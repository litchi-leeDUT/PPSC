// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

interface IERC20Minimal {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
}

interface IPpscCommitteeRegistry {
    function committees(bytes32 committeeId)
        external
        view
        returns (
            uint64 epoch,
            uint16 threshold,
            bytes32 seed,
            bytes32 memberRoot,
            bytes32 selectionEvidenceHash,
            bool active
        );

    function isCommitteeMember(bytes32 committeeId, address member) external view returns (bool);
}

/// @title Public ERC-20 to confidential balance gateway
/// @notice Locks public tokens and advances an off-chain confidential ledger by committee attestation.
/// @dev Deposit/withdraw amounts are public. Confidential accounts and balances remain off chain.
contract ConfidentialTokenSwap {
    enum DepositStatus {
        None,
        Pending,
        Finalized,
        Cancelled
    }

    enum WithdrawalStatus {
        None,
        Pending,
        Finalized,
        Cancelled
    }

    struct TokenConfig {
        bool enabled;
        uint128 minimumDeposit;
        uint16 withdrawalFeeBps;
    }

    struct Deposit {
        address token;
        address depositor;
        uint256 amount;
        bytes32 privateAccountCommitment;
        uint64 createdAt;
        DepositStatus status;
    }

    struct DepositSettlement {
        bytes32 expectedOldStateRoot;
        bytes32 newStateRoot;
        bytes32 encryptedBalanceDataId;
        bytes32 transcriptRoot;
    }

    struct Withdrawal {
        address token;
        address recipient;
        uint256 grossAmount;
        bytes32 nullifier;
        bytes32 expectedOldStateRoot;
        bytes32 newStateRoot;
        bytes32 transcriptRoot;
        uint64 expiry;
    }

    struct WithdrawalRequest {
        address token;
        address requester;
        address recipient;
        uint256 grossAmount;
        bytes32 privateAccountCommitment;
        uint64 expiry;
        WithdrawalStatus status;
    }

    struct WithdrawalSettlement {
        bytes32 nullifier;
        bytes32 expectedOldStateRoot;
        bytes32 newStateRoot;
        bytes32 encryptedBalanceDataId;
        bytes32 transcriptRoot;
    }

    error Unauthorized();
    error Paused();
    error InvalidArgument();
    error InvalidState();
    error InvalidThreshold();
    error InvalidSignature();
    error TokenTransferFailed();
    error UnsupportedTokenBehavior();
    error AlreadySpent();
    error DeadlineExpired();

    event TokenConfigured(
        address indexed token, bool enabled, uint128 minimumDeposit, uint16 withdrawalFeeBps
    );
    event CommitteeChanged(bytes32 indexed oldCommitteeId, bytes32 indexed newCommitteeId);
    event DepositRequested(
        bytes32 indexed depositId,
        address indexed token,
        address indexed depositor,
        uint256 amount,
        bytes32 privateAccountCommitment
    );
    event DepositFinalized(
        bytes32 indexed depositId,
        address indexed token,
        bytes32 encryptedBalanceDataId,
        bytes32 newStateRoot,
        bytes32 transcriptRoot
    );
    event DepositCancelled(bytes32 indexed depositId, address indexed depositor, uint256 amount);
    event WithdrawalFinalized(
        bytes32 indexed nullifier,
        address indexed token,
        address indexed recipient,
        uint256 grossAmount,
        uint256 fee,
        uint256 payout,
        bytes32 newStateRoot,
        bytes32 transcriptRoot
    );
    event WithdrawalRequested(
        bytes32 indexed withdrawalId,
        address indexed token,
        address indexed requester,
        address recipient,
        uint256 grossAmount,
        bytes32 privateAccountCommitment,
        uint64 expiry
    );
    event ConfidentialWithdrawalFinalized(
        bytes32 indexed withdrawalId,
        bytes32 indexed nullifier,
        address indexed token,
        address recipient,
        uint256 payout,
        bytes32 encryptedBalanceDataId,
        bytes32 newStateRoot
    );
    event WithdrawalCancelled(bytes32 indexed withdrawalId, address indexed requester);
    event FeesCollected(address indexed token, address indexed recipient, uint256 amount);
    event PauseChanged(bool paused);

    uint16 public constant MAX_FEE_BPS = 1_000;
    uint64 public constant MIN_REFUND_DELAY = 1 hours;

    address public immutable admin;
    IPpscCommitteeRegistry public immutable committeeRegistry;
    bytes32 public activeCommitteeId;
    uint64 public refundDelay;
    bool public paused;

    mapping(address => TokenConfig) public tokenConfigs;
    mapping(address => bytes32) public privateStateRoots;
    mapping(address => uint256) public privateLiabilities;
    mapping(address => uint256) public accountedBalances;
    mapping(address => uint256) public accruedFees;
    mapping(address => mapping(uint64 => bool)) public depositNonceUsed;
    mapping(address => mapping(uint64 => bool)) public withdrawalNonceUsed;
    mapping(bytes32 => Deposit) public deposits;
    mapping(bytes32 => WithdrawalRequest) public withdrawalRequests;
    mapping(bytes32 => bool) public spentNullifiers;

    uint256 private _reentrancyLock = 1;

    constructor(
        address admin_,
        IPpscCommitteeRegistry committeeRegistry_,
        bytes32 activeCommitteeId_,
        uint64 refundDelay_
    ) {
        if (
            admin_ == address(0) || address(committeeRegistry_) == address(0)
                || activeCommitteeId_ == bytes32(0) || refundDelay_ < MIN_REFUND_DELAY
        ) revert InvalidArgument();
        admin = admin_;
        committeeRegistry = committeeRegistry_;
        activeCommitteeId = activeCommitteeId_;
        refundDelay = refundDelay_;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert Paused();
        _;
    }

    modifier nonReentrant() {
        if (_reentrancyLock != 1) revert InvalidState();
        _reentrancyLock = 2;
        _;
        _reentrancyLock = 1;
    }

    function configureToken(
        address token,
        bool enabled,
        uint128 minimumDeposit,
        uint16 withdrawalFeeBps
    ) external onlyAdmin {
        if (token == address(0) || minimumDeposit == 0 || withdrawalFeeBps > MAX_FEE_BPS) revert InvalidArgument();
        tokenConfigs[token] = TokenConfig({
            enabled: enabled, minimumDeposit: minimumDeposit, withdrawalFeeBps: withdrawalFeeBps
        });
        emit TokenConfigured(token, enabled, minimumDeposit, withdrawalFeeBps);
    }

    function setActiveCommittee(bytes32 nextCommitteeId) external onlyAdmin {
        if (nextCommitteeId == bytes32(0)) revert InvalidArgument();
        (,,,,, bool active) = committeeRegistry.committees(nextCommitteeId);
        if (!active) revert InvalidArgument();
        bytes32 oldCommitteeId = activeCommitteeId;
        activeCommitteeId = nextCommitteeId;
        emit CommitteeChanged(oldCommitteeId, nextCommitteeId);
    }

    function setPaused(bool nextPaused) external onlyAdmin {
        paused = nextPaused;
        emit PauseChanged(nextPaused);
    }

    function deposit(address token, uint256 amount, bytes32 privateAccountCommitment, uint64 nonce)
        external
        whenNotPaused
        nonReentrant
        returns (bytes32 depositId)
    {
        TokenConfig memory config = tokenConfigs[token];
        if (
            !config.enabled || amount < config.minimumDeposit
                || privateAccountCommitment == bytes32(0)
        ) {
            revert InvalidArgument();
        }
        if (depositNonceUsed[msg.sender][nonce]) revert InvalidState();
        depositNonceUsed[msg.sender][nonce] = true;

        depositId = keccak256(
            abi.encode(
                "PPSC_PUBLIC_TO_PRIVATE_V1",
                block.chainid,
                address(this),
                token,
                msg.sender,
                amount,
                privateAccountCommitment,
                nonce
            )
        );
        if (deposits[depositId].status != DepositStatus.None) revert InvalidState();

        uint256 balanceBefore = IERC20Minimal(token).balanceOf(address(this));
        _safeTransferFrom(token, msg.sender, address(this), amount);
        uint256 received = IERC20Minimal(token).balanceOf(address(this)) - balanceBefore;
        if (received != amount) revert UnsupportedTokenBehavior();

        deposits[depositId] = Deposit({
            token: token,
            depositor: msg.sender,
            amount: amount,
            privateAccountCommitment: privateAccountCommitment,
            createdAt: uint64(block.timestamp),
            status: DepositStatus.Pending
        });
        accountedBalances[token] += amount;
        emit DepositRequested(depositId, token, msg.sender, amount, privateAccountCommitment);
    }

    function depositDigest(bytes32 depositId, DepositSettlement calldata settlement)
        public
        view
        returns (bytes32)
    {
        Deposit storage target = deposits[depositId];
        return _ethSigned(
            keccak256(
                abi.encode(
                    "PPSC_DEPOSIT_SETTLEMENT_V1",
                    block.chainid,
                    address(this),
                    activeCommitteeId,
                    depositId,
                    target.token,
                    target.depositor,
                    target.amount,
                    target.privateAccountCommitment,
                    settlement
                )
            )
        );
    }

    function finalizeDeposit(
        bytes32 depositId,
        DepositSettlement calldata settlement,
        bytes[] calldata signatures
    ) external whenNotPaused {
        Deposit storage target = deposits[depositId];
        if (target.status != DepositStatus.Pending) revert InvalidState();
        if (
            settlement.newStateRoot == bytes32(0) || settlement.encryptedBalanceDataId == bytes32(0)
                || settlement.transcriptRoot == bytes32(0)
                || privateStateRoots[target.token] != settlement.expectedOldStateRoot
        ) revert InvalidArgument();

        _verifyThreshold(depositDigest(depositId, settlement), signatures);
        privateStateRoots[target.token] = settlement.newStateRoot;
        privateLiabilities[target.token] += target.amount;
        target.status = DepositStatus.Finalized;
        emit DepositFinalized(
            depositId,
            target.token,
            settlement.encryptedBalanceDataId,
            settlement.newStateRoot,
            settlement.transcriptRoot
        );
    }

    function cancelDeposit(bytes32 depositId) external nonReentrant {
        Deposit storage target = deposits[depositId];
        if (target.status != DepositStatus.Pending || msg.sender != target.depositor) {
            revert InvalidState();
        }
        if (block.timestamp < uint256(target.createdAt) + refundDelay) revert DeadlineExpired();
        target.status = DepositStatus.Cancelled;
        accountedBalances[target.token] -= target.amount;
        _safeTransfer(target.token, target.depositor, target.amount);
        emit DepositCancelled(depositId, target.depositor, target.amount);
    }

    function withdrawalDigest(Withdrawal calldata withdrawal) public view returns (bytes32) {
        return _ethSigned(
            keccak256(
                abi.encode(
                    "PPSC_PRIVATE_TO_PUBLIC_V1",
                    block.chainid,
                    address(this),
                    activeCommitteeId,
                    withdrawal
                )
            )
        );
    }

    /// @notice Creates an on-chain task that asks Runtime to verify and debit a confidential balance.
    /// @dev The amount is intentionally public. The commitment identifies the off-chain account
    /// without publishing its balance or ciphertext.
    function requestWithdrawal(
        address token,
        uint256 grossAmount,
        bytes32 privateAccountCommitment,
        address recipient,
        uint64 nonce,
        uint64 expiry
    ) external whenNotPaused returns (bytes32 withdrawalId) {
        TokenConfig memory config = tokenConfigs[token];
        if (
            !config.enabled || grossAmount == 0 || privateAccountCommitment == bytes32(0)
                || recipient == address(0) || expiry <= block.timestamp
        ) revert InvalidArgument();
        if (withdrawalNonceUsed[msg.sender][nonce]) revert InvalidState();
        withdrawalNonceUsed[msg.sender][nonce] = true;
        withdrawalId = keccak256(
            abi.encode(
                "PPSC_WITHDRAWAL_REQUEST_V1",
                block.chainid,
                address(this),
                token,
                msg.sender,
                recipient,
                grossAmount,
                privateAccountCommitment,
                nonce,
                expiry
            )
        );
        if (withdrawalRequests[withdrawalId].status != WithdrawalStatus.None) {
            revert InvalidState();
        }
        withdrawalRequests[withdrawalId] = WithdrawalRequest({
            token: token,
            requester: msg.sender,
            recipient: recipient,
            grossAmount: grossAmount,
            privateAccountCommitment: privateAccountCommitment,
            expiry: expiry,
            status: WithdrawalStatus.Pending
        });
        emit WithdrawalRequested(
            withdrawalId,
            token,
            msg.sender,
            recipient,
            grossAmount,
            privateAccountCommitment,
            expiry
        );
    }

    function withdrawalSettlementDigest(
        bytes32 withdrawalId,
        WithdrawalSettlement calldata settlement
    ) public view returns (bytes32) {
        WithdrawalRequest storage request = withdrawalRequests[withdrawalId];
        return _ethSigned(
            keccak256(
                abi.encode(
                    "PPSC_WITHDRAWAL_SETTLEMENT_V1",
                    block.chainid,
                    address(this),
                    activeCommitteeId,
                    withdrawalId,
                    request.token,
                    request.requester,
                    request.recipient,
                    request.grossAmount,
                    request.privateAccountCommitment,
                    request.expiry,
                    settlement
                )
            )
        );
    }

    /// @notice Releases public tokens only after Runtime has debited the confidential balance and
    /// the selected committee attests to the resulting ciphertext/state root.
    function finalizeWithdrawal(
        bytes32 withdrawalId,
        WithdrawalSettlement calldata settlement,
        bytes[] calldata signatures
    ) external whenNotPaused nonReentrant {
        WithdrawalRequest storage request = withdrawalRequests[withdrawalId];
        if (request.status != WithdrawalStatus.Pending) revert InvalidState();
        if (block.timestamp > request.expiry) revert DeadlineExpired();
        if (
            settlement.nullifier == bytes32(0) || settlement.newStateRoot == bytes32(0)
                || settlement.encryptedBalanceDataId == bytes32(0)
                || settlement.transcriptRoot == bytes32(0)
                || settlement.expectedOldStateRoot != privateStateRoots[request.token]
        ) revert InvalidArgument();
        if (spentNullifiers[settlement.nullifier]) revert AlreadySpent();
        if (privateLiabilities[request.token] < request.grossAmount) revert InvalidState();

        _verifyThreshold(withdrawalSettlementDigest(withdrawalId, settlement), signatures);
        spentNullifiers[settlement.nullifier] = true;
        request.status = WithdrawalStatus.Finalized;
        privateStateRoots[request.token] = settlement.newStateRoot;
        privateLiabilities[request.token] -= request.grossAmount;

        TokenConfig memory config = tokenConfigs[request.token];
        uint256 fee = request.grossAmount * config.withdrawalFeeBps / 10_000;
        uint256 payout = request.grossAmount - fee;
        accruedFees[request.token] += fee;
        accountedBalances[request.token] -= payout;
        _safeTransfer(request.token, request.recipient, payout);
        emit ConfidentialWithdrawalFinalized(
            withdrawalId,
            settlement.nullifier,
            request.token,
            request.recipient,
            payout,
            settlement.encryptedBalanceDataId,
            settlement.newStateRoot
        );
    }

    /// @notice Cancels an expired request. No public funds were reserved by the request itself.
    function cancelWithdrawal(bytes32 withdrawalId) external {
        WithdrawalRequest storage request = withdrawalRequests[withdrawalId];
        if (
            request.status != WithdrawalStatus.Pending || request.requester != msg.sender
                || block.timestamp <= request.expiry
        ) revert InvalidState();
        request.status = WithdrawalStatus.Cancelled;
        emit WithdrawalCancelled(withdrawalId, msg.sender);
    }

    function withdraw(Withdrawal calldata withdrawal, bytes[] calldata signatures)
        external
        whenNotPaused
        nonReentrant
    {
        TokenConfig memory config = tokenConfigs[withdrawal.token];
        if (
            !config.enabled || withdrawal.recipient == address(0) || withdrawal.grossAmount == 0
                || withdrawal.nullifier == bytes32(0) || withdrawal.newStateRoot == bytes32(0)
                || withdrawal.transcriptRoot == bytes32(0)
                || withdrawal.expectedOldStateRoot != privateStateRoots[withdrawal.token]
        ) revert InvalidArgument();
        if (block.timestamp > withdrawal.expiry) revert DeadlineExpired();
        if (spentNullifiers[withdrawal.nullifier]) revert AlreadySpent();
        if (privateLiabilities[withdrawal.token] < withdrawal.grossAmount) revert InvalidState();

        _verifyThreshold(withdrawalDigest(withdrawal), signatures);
        spentNullifiers[withdrawal.nullifier] = true;
        privateStateRoots[withdrawal.token] = withdrawal.newStateRoot;
        privateLiabilities[withdrawal.token] -= withdrawal.grossAmount;

        uint256 fee = withdrawal.grossAmount * config.withdrawalFeeBps / 10_000;
        uint256 payout = withdrawal.grossAmount - fee;
        accruedFees[withdrawal.token] += fee;
        accountedBalances[withdrawal.token] -= payout;
        _safeTransfer(withdrawal.token, withdrawal.recipient, payout);
        emit WithdrawalFinalized(
            withdrawal.nullifier,
            withdrawal.token,
            withdrawal.recipient,
            withdrawal.grossAmount,
            fee,
            payout,
            withdrawal.newStateRoot,
            withdrawal.transcriptRoot
        );
    }

    function collectFees(address token, address recipient, uint256 amount)
        external
        onlyAdmin
        nonReentrant
    {
        if (recipient == address(0) || amount == 0 || amount > accruedFees[token]) {
            revert InvalidArgument();
        }
        accruedFees[token] -= amount;
        accountedBalances[token] -= amount;
        _safeTransfer(token, recipient, amount);
        emit FeesCollected(token, recipient, amount);
    }

    function reserveIsSolvent(address token) external view returns (bool) {
        uint256 balance = IERC20Minimal(token).balanceOf(address(this));
        return balance >= accountedBalances[token] && balance >= privateLiabilities[token];
    }

    function _verifyThreshold(bytes32 digest, bytes[] calldata signatures) private view {
        (, uint16 threshold,,,, bool active) = committeeRegistry.committees(activeCommitteeId);
        if (!active || threshold == 0 || signatures.length < threshold) revert InvalidThreshold();
        address previous;
        for (uint256 i; i < signatures.length; ++i) {
            address signer = _recover(digest, signatures[i]);
            if (
                signer <= previous
                    || !committeeRegistry.isCommitteeMember(activeCommitteeId, signer)
            ) revert InvalidSignature();
            previous = signer;
        }
    }

    function _safeTransfer(address token, address recipient, uint256 amount) private {
        (bool success, bytes memory result) =
            token.call(abi.encodeCall(IERC20Minimal.transfer, (recipient, amount)));
        if (!success || (result.length != 0 && !abi.decode(result, (bool)))) {
            revert TokenTransferFailed();
        }
    }

    function _safeTransferFrom(address token, address sender, address recipient, uint256 amount)
        private
    {
        (bool success, bytes memory result) =
            token.call(abi.encodeCall(IERC20Minimal.transferFrom, (sender, recipient, amount)));
        if (!success || (result.length != 0 && !abi.decode(result, (bool)))) {
            revert TokenTransferFailed();
        }
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) revert InvalidSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        if (
            uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
                || (v != 27 && v != 28)
        ) revert InvalidSignature();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
        return signer;
    }

    function _ethSigned(bytes32 payload) private pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payload));
    }
}
