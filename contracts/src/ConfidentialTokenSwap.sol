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

    enum TransferStatus {
        None,
        Pending,
        Finalized,
        Cancelled
    }

    enum OpeningStatus {
        None,
        Pending,
        Fulfilled
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

    struct ConfidentialTransferRequest {
        address token;
        address requester;
        bytes32 senderAccountCommitment;
        bytes32 receiverAccountCommitment;
        uint256 amount;
        uint64 expiry;
        TransferStatus status;
    }

    struct ConfidentialTransferSettlement {
        bytes32 expectedOldStateRoot;
        bytes32 newStateRoot;
        bytes32 senderBalanceDataId;
        bytes32 receiverBalanceDataId;
        bytes32 transcriptRoot;
    }

    struct BalanceOpeningRequest {
        address token;
        address requester;
        bytes32 privateAccountCommitment;
        bytes32 recipientEncryptionKey;
        uint64 expiry;
        OpeningStatus status;
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
    event CommitteeHandoffStarted(
        bytes32 indexed oldCommitteeId, bytes32 indexed nextCommitteeId, bytes32 handoffRoot
    );
    event CommitteeHandoffFinalized(
        bytes32 indexed oldCommitteeId, bytes32 indexed newCommitteeId, bytes32 handoffRoot
    );
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
    event ConfidentialTransferRequested(
        bytes32 indexed transferId,
        address indexed token,
        address indexed requester,
        bytes32 senderAccountCommitment,
        bytes32 receiverAccountCommitment,
        uint256 amount,
        uint64 expiry
    );
    event ConfidentialTransferFinalized(
        bytes32 indexed transferId,
        address indexed token,
        bytes32 senderBalanceDataId,
        bytes32 receiverBalanceDataId,
        bytes32 newStateRoot
    );
    event FeesCollected(address indexed token, address indexed recipient, uint256 amount);
    event PauseChanged(bool paused);
    event TaskGasFunded(bytes32 indexed taskId, address indexed payer, uint256 amount);
    event GasRefundCredited(bytes32 indexed taskId, address indexed submitter, uint256 amount);
    event GasRefundClaimed(address indexed submitter, address indexed recipient, uint256 amount);
    event BalanceOpeningRequested(
        bytes32 indexed requestId,
        address indexed token,
        address indexed requester,
        bytes32 privateAccountCommitment,
        bytes32 recipientEncryptionKey,
        uint64 expiry
    );
    event BalanceOpeningFulfilled(bytes32 indexed requestId, bytes encryptedResult);

    uint16 public constant MAX_FEE_BPS = 1_000;
    uint64 public constant MIN_REFUND_DELAY = 1 hours;

    address public immutable admin;
    IPpscCommitteeRegistry public immutable committeeRegistry;
    bytes32 public activeCommitteeId;
    bytes32 public pendingCommitteeId;
    bytes32 public pendingHandoffRoot;
    uint64 public refundDelay;
    bool public paused;

    mapping(address => TokenConfig) public tokenConfigs;
    mapping(address => bytes32) public privateStateRoots;
    mapping(address => uint256) public privateLiabilities;
    mapping(address => uint256) public accountedBalances;
    mapping(address => uint256) public accruedFees;
    mapping(address => mapping(uint64 => bool)) public depositNonceUsed;
    mapping(address => mapping(uint64 => bool)) public withdrawalNonceUsed;
    mapping(address => mapping(uint64 => bool)) public transferNonceUsed;
    mapping(address => mapping(uint64 => bool)) public openingNonceUsed;
    mapping(bytes32 => Deposit) public deposits;
    mapping(bytes32 => WithdrawalRequest) public withdrawalRequests;
    mapping(bytes32 => ConfidentialTransferRequest) public confidentialTransferRequests;
    mapping(bytes32 => BalanceOpeningRequest) public balanceOpeningRequests;
    mapping(bytes32 => bytes) public balanceOpeningResults;
    mapping(bytes32 => bool) public spentNullifiers;
    mapping(bytes32 => uint256) public taskGasEscrow;
    mapping(address => uint256) public gasRefundCredits;
    mapping(bytes32 => address) public confidentialAccountControllers;
    bytes32[] public depositTaskIds;
    bytes32[] public transferTaskIds;
    bytes32[] public withdrawalTaskIds;
    bytes32[] public openingTaskIds;

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

    function beginCommitteeHandoff(bytes32 nextCommitteeId, bytes32 handoffRoot)
        external
        onlyAdmin
    {
        if (nextCommitteeId == bytes32(0) || handoffRoot == bytes32(0)) {
            revert InvalidArgument();
        }
        (,,,,, bool active) = committeeRegistry.committees(nextCommitteeId);
        if (!active || pendingCommitteeId != bytes32(0)) revert InvalidState();
        pendingCommitteeId = nextCommitteeId;
        pendingHandoffRoot = handoffRoot;
        emit CommitteeHandoffStarted(activeCommitteeId, nextCommitteeId, handoffRoot);
    }

    function committeeHandoffDigest() public view returns (bytes32) {
        return _ethSigned(
            keccak256(
                abi.encode(
                    "PPSC_SWAP_COMMITTEE_HANDOFF_V1",
                    block.chainid,
                    address(this),
                    activeCommitteeId,
                    pendingCommitteeId,
                    pendingHandoffRoot
                )
            )
        );
    }

    function finalizeCommitteeHandoff(
        bytes[] calldata oldCommitteeSignatures,
        bytes[] calldata newCommitteeSignatures
    ) external {
        bytes32 nextCommitteeId = pendingCommitteeId;
        if (nextCommitteeId == bytes32(0)) revert InvalidState();
        bytes32 digest = committeeHandoffDigest();
        _verifyCommitteeThreshold(activeCommitteeId, digest, oldCommitteeSignatures);
        _verifyCommitteeThreshold(nextCommitteeId, digest, newCommitteeSignatures);
        bytes32 oldCommitteeId = activeCommitteeId;
        bytes32 handoffRoot = pendingHandoffRoot;
        activeCommitteeId = nextCommitteeId;
        pendingCommitteeId = bytes32(0);
        pendingHandoffRoot = bytes32(0);
        emit CommitteeHandoffFinalized(oldCommitteeId, nextCommitteeId, handoffRoot);
        emit CommitteeChanged(oldCommitteeId, nextCommitteeId);
    }

    function setPaused(bool nextPaused) external onlyAdmin {
        paused = nextPaused;
        emit PauseChanged(nextPaused);
    }

    function deposit(address token, uint256 amount, bytes32 privateAccountCommitment, uint64 nonce)
        external
        payable
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
        address controller = confidentialAccountControllers[privateAccountCommitment];
        if (controller != address(0) && controller != msg.sender) revert Unauthorized();
        confidentialAccountControllers[privateAccountCommitment] = msg.sender;
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
        depositTaskIds.push(depositId);
        taskGasEscrow[depositId] = msg.value;
        emit TaskGasFunded(depositId, msg.sender, msg.value);
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
        _creditTaskGas(depositId, msg.sender);
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
        _returnTaskGas(depositId, target.depositor);
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

    function requestConfidentialTransfer(
        address token,
        bytes32 senderAccountCommitment,
        bytes32 receiverAccountCommitment,
        uint256 amount,
        uint64 nonce,
        uint64 expiry
    ) external payable whenNotPaused returns (bytes32 transferId) {
        if (
            !tokenConfigs[token].enabled || senderAccountCommitment == bytes32(0)
                || receiverAccountCommitment == bytes32(0)
                || senderAccountCommitment == receiverAccountCommitment || amount == 0
                || expiry <= block.timestamp
        ) revert InvalidArgument();
        if (
            confidentialAccountControllers[senderAccountCommitment] != msg.sender
                || confidentialAccountControllers[receiverAccountCommitment] == address(0)
        ) revert Unauthorized();
        if (transferNonceUsed[msg.sender][nonce]) revert InvalidState();
        transferNonceUsed[msg.sender][nonce] = true;
        transferId = keccak256(
            abi.encode(
                "PPSC_CONFIDENTIAL_TRANSFER_REQUEST_V1",
                block.chainid,
                address(this),
                token,
                msg.sender,
                senderAccountCommitment,
                receiverAccountCommitment,
                amount,
                nonce,
                expiry
            )
        );
        confidentialTransferRequests[transferId] = ConfidentialTransferRequest({
            token: token,
            requester: msg.sender,
            senderAccountCommitment: senderAccountCommitment,
            receiverAccountCommitment: receiverAccountCommitment,
            amount: amount,
            expiry: expiry,
            status: TransferStatus.Pending
        });
        transferTaskIds.push(transferId);
        taskGasEscrow[transferId] = msg.value;
        emit TaskGasFunded(transferId, msg.sender, msg.value);
        emit ConfidentialTransferRequested(
            transferId,
            token,
            msg.sender,
            senderAccountCommitment,
            receiverAccountCommitment,
            amount,
            expiry
        );
    }

    function confidentialTransferDigest(
        bytes32 transferId,
        ConfidentialTransferSettlement calldata settlement
    ) public view returns (bytes32) {
        ConfidentialTransferRequest storage request = confidentialTransferRequests[transferId];
        return _ethSigned(
            keccak256(
                abi.encode(
                    "PPSC_CONFIDENTIAL_TRANSFER_SETTLEMENT_V1",
                    block.chainid,
                    address(this),
                    activeCommitteeId,
                    transferId,
                    request.token,
                    request.requester,
                    request.senderAccountCommitment,
                    request.receiverAccountCommitment,
                    request.amount,
                    request.expiry,
                    settlement
                )
            )
        );
    }

    function finalizeConfidentialTransfer(
        bytes32 transferId,
        ConfidentialTransferSettlement calldata settlement,
        bytes[] calldata signatures
    ) external whenNotPaused {
        ConfidentialTransferRequest storage request = confidentialTransferRequests[transferId];
        if (request.status != TransferStatus.Pending) revert InvalidState();
        if (block.timestamp > request.expiry) revert DeadlineExpired();
        if (
            settlement.expectedOldStateRoot != privateStateRoots[request.token]
                || settlement.newStateRoot == bytes32(0)
                || settlement.senderBalanceDataId == bytes32(0)
                || settlement.receiverBalanceDataId == bytes32(0)
                || settlement.transcriptRoot == bytes32(0)
        ) revert InvalidArgument();
        _verifyThreshold(confidentialTransferDigest(transferId, settlement), signatures);
        request.status = TransferStatus.Finalized;
        _creditTaskGas(transferId, msg.sender);
        privateStateRoots[request.token] = settlement.newStateRoot;
        emit ConfidentialTransferFinalized(
            transferId,
            request.token,
            settlement.senderBalanceDataId,
            settlement.receiverBalanceDataId,
            settlement.newStateRoot
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
    ) external payable whenNotPaused returns (bytes32 withdrawalId) {
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
        withdrawalTaskIds.push(withdrawalId);
        taskGasEscrow[withdrawalId] = msg.value;
        emit TaskGasFunded(withdrawalId, msg.sender, msg.value);
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
        _creditTaskGas(withdrawalId, msg.sender);
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
        _returnTaskGas(withdrawalId, msg.sender);
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

    function requestBalanceOpening(
        address token,
        bytes32 privateAccountCommitment,
        bytes32 recipientEncryptionKey,
        uint64 nonce,
        uint64 expiry
    ) external payable whenNotPaused returns (bytes32 requestId) {
        if (
            !tokenConfigs[token].enabled || privateAccountCommitment == bytes32(0)
                || recipientEncryptionKey == bytes32(0) || expiry <= block.timestamp
                || openingNonceUsed[msg.sender][nonce]
        ) revert InvalidArgument();
        if (confidentialAccountControllers[privateAccountCommitment] != msg.sender) {
            revert Unauthorized();
        }
        openingNonceUsed[msg.sender][nonce] = true;
        requestId = keccak256(
            abi.encode(
                "PPSC_BALANCE_OPENING_REQUEST_V1",
                block.chainid,
                address(this),
                token,
                msg.sender,
                privateAccountCommitment,
                recipientEncryptionKey,
                nonce,
                expiry
            )
        );
        balanceOpeningRequests[requestId] = BalanceOpeningRequest({
            token: token,
            requester: msg.sender,
            privateAccountCommitment: privateAccountCommitment,
            recipientEncryptionKey: recipientEncryptionKey,
            expiry: expiry,
            status: OpeningStatus.Pending
        });
        openingTaskIds.push(requestId);
        taskGasEscrow[requestId] = msg.value;
        emit TaskGasFunded(requestId, msg.sender, msg.value);
        emit BalanceOpeningRequested(
            requestId, token, msg.sender, privateAccountCommitment, recipientEncryptionKey, expiry
        );
    }

    function registerConfidentialAccount(bytes32 privateAccountCommitment) external {
        if (privateAccountCommitment == bytes32(0)) revert InvalidArgument();
        address controller = confidentialAccountControllers[privateAccountCommitment];
        if (controller != address(0) && controller != msg.sender) revert Unauthorized();
        confidentialAccountControllers[privateAccountCommitment] = msg.sender;
    }

    function balanceOpeningDigest(bytes32 requestId, bytes calldata encryptedResult)
        public
        view
        returns (bytes32)
    {
        BalanceOpeningRequest storage request = balanceOpeningRequests[requestId];
        return _ethSigned(
            keccak256(
                abi.encode(
                    "PPSC_BALANCE_OPENING_RESULT_V1",
                    block.chainid,
                    address(this),
                    activeCommitteeId,
                    requestId,
                    request.token,
                    request.requester,
                    request.privateAccountCommitment,
                    request.recipientEncryptionKey,
                    request.expiry,
                    keccak256(encryptedResult)
                )
            )
        );
    }

    function fulfillBalanceOpening(
        bytes32 requestId,
        bytes calldata encryptedResult,
        bytes[] calldata signatures
    ) external {
        BalanceOpeningRequest storage request = balanceOpeningRequests[requestId];
        if (
            request.status != OpeningStatus.Pending || block.timestamp > request.expiry
                || encryptedResult.length == 0
        ) revert InvalidState();
        _verifyThreshold(balanceOpeningDigest(requestId, encryptedResult), signatures);
        request.status = OpeningStatus.Fulfilled;
        balanceOpeningResults[requestId] = encryptedResult;
        _creditTaskGas(requestId, msg.sender);
        emit BalanceOpeningFulfilled(requestId, encryptedResult);
    }

    function reserveIsSolvent(address token) external view returns (bool) {
        uint256 balance = IERC20Minimal(token).balanceOf(address(this));
        return balance >= accountedBalances[token] && balance >= privateLiabilities[token];
    }

    function claimGasRefund(address payable recipient) external nonReentrant {
        uint256 amount = gasRefundCredits[msg.sender];
        if (recipient == address(0) || amount == 0) revert InvalidArgument();
        gasRefundCredits[msg.sender] = 0;
        (bool success,) = recipient.call{ value: amount }("");
        if (!success) revert TokenTransferFailed();
        emit GasRefundClaimed(msg.sender, recipient, amount);
    }

    function _creditTaskGas(bytes32 taskId, address submitter) private {
        uint256 amount = taskGasEscrow[taskId];
        if (amount == 0) return;
        taskGasEscrow[taskId] = 0;
        gasRefundCredits[submitter] += amount;
        emit GasRefundCredited(taskId, submitter, amount);
    }

    function _returnTaskGas(bytes32 taskId, address payer) private {
        uint256 amount = taskGasEscrow[taskId];
        if (amount == 0) return;
        taskGasEscrow[taskId] = 0;
        gasRefundCredits[payer] += amount;
        emit GasRefundCredited(taskId, payer, amount);
    }

    function taskCounts()
        external
        view
        returns (
            uint256 depositsCount,
            uint256 transfersCount,
            uint256 withdrawalsCount,
            uint256 openingsCount
        )
    {
        return (
            depositTaskIds.length,
            transferTaskIds.length,
            withdrawalTaskIds.length,
            openingTaskIds.length
        );
    }

    function _verifyThreshold(bytes32 digest, bytes[] calldata signatures) private view {
        _verifyCommitteeThreshold(activeCommitteeId, digest, signatures);
    }

    function _verifyCommitteeThreshold(
        bytes32 committeeId,
        bytes32 digest,
        bytes[] calldata signatures
    ) private view {
        (, uint16 threshold,,,, bool active) = committeeRegistry.committees(committeeId);
        if (!active || threshold == 0 || signatures.length < threshold) revert InvalidThreshold();
        address previous;
        for (uint256 i; i < signatures.length; ++i) {
            address signer = _recover(digest, signatures[i]);
            if (signer <= previous || !committeeRegistry.isCommitteeMember(committeeId, signer)) {
                revert InvalidSignature();
            }
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
