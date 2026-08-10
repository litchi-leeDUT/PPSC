// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import { ConfidentialTokenSwap, IPpscCommitteeRegistry } from "../src/ConfidentialTokenSwap.sol";
import { PpscControlPlane } from "../src/PpscControlPlane.sol";
import { ISortitionVerifier } from "../src/interfaces/ISortitionVerifier.sol";
import { MockERC20 } from "./mocks/MockERC20.sol";

interface SwapVm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address sender) external;
    function warp(uint256 timestamp) external;
    function deal(address account, uint256 balance) external;
    function expectRevert(bytes4 selector) external;
}

contract AcceptAllSortitionVerifier is ISortitionVerifier {
    function verifySelection(bytes32, uint64, bytes32, address[] calldata, bytes calldata)
        external
        pure
        returns (bool)
    {
        return true;
    }
}

contract ConfidentialTokenSwapTest {
    SwapVm private constant vm = SwapVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 private constant MEMBER_KEY_1 = 0xB0B;
    uint256 private constant MEMBER_KEY_2 = 0xCAFE;
    uint256 private constant MEMBER_KEY_3 = 0xD00D;
    uint256 private constant USER_KEY = 0xA11CE;

    PpscControlPlane private control;
    ConfidentialTokenSwap private swap;
    MockERC20 private token;
    bytes32 private committeeId = keccak256("swap-committee");
    address private user;

    function setUp() public {
        user = vm.addr(USER_KEY);
        AcceptAllSortitionVerifier verifier = new AcceptAllSortitionVerifier();
        control = new PpscControlPlane(address(this), address(this), verifier);
        (address[] memory members,) = _sortedMembersAndKeys();
        control.finalizeCommittee(committeeId, keccak256("swap-seed"), 1, members, 2, hex"01");

        swap = new ConfidentialTokenSwap(
            address(this), IPpscCommitteeRegistry(address(control)), committeeId, 1 days
        );
        token = new MockERC20();
        swap.configureToken(address(token), true, 1 ether, 100);
        token.mint(user, 1_000 ether);
        vm.prank(user);
        token.approve(address(swap), type(uint256).max);
        vm.deal(user, 10 ether);
    }

    function testPublicDepositThenPrivateWithdrawal() public {
        bytes32 privateAccount = keccak256("alice-private-account");
        vm.prank(user);
        bytes32 depositId = swap.deposit(address(token), 100 ether, privateAccount, 1);

        require(token.balanceOf(address(swap)) == 100 ether, "deposit not escrowed");
        require(swap.accountedBalances(address(token)) == 100 ether, "accounting mismatch");

        ConfidentialTokenSwap.DepositSettlement memory settlement =
            ConfidentialTokenSwap.DepositSettlement({
                expectedOldStateRoot: bytes32(0),
                newStateRoot: keccak256("private-state-1"),
                encryptedBalanceDataId: keccak256("alice-encrypted-balance"),
                transcriptRoot: keccak256("deposit-transcript")
            });
        bytes32 depositDigest = swap.depositDigest(depositId, settlement);
        swap.finalizeDeposit(depositId, settlement, _memberSignatures(depositDigest));

        require(swap.privateLiabilities(address(token)) == 100 ether, "mint not accounted");
        require(
            swap.privateStateRoots(address(token)) == settlement.newStateRoot,
            "deposit state not advanced"
        );

        vm.prank(user);
        bytes32 withdrawalId = swap.requestWithdrawal(
            address(token), 40 ether, privateAccount, user, 7, uint64(block.timestamp + 1 hours)
        );
        ConfidentialTokenSwap.WithdrawalSettlement memory withdrawal =
            ConfidentialTokenSwap.WithdrawalSettlement({
                nullifier: keccak256("private-burn-nullifier"),
                expectedOldStateRoot: settlement.newStateRoot,
                newStateRoot: keccak256("private-state-2"),
                encryptedBalanceDataId: keccak256("alice-encrypted-balance-after-withdrawal"),
                transcriptRoot: keccak256("withdraw-transcript")
            });
        bytes32 withdrawalDigest = swap.withdrawalSettlementDigest(withdrawalId, withdrawal);
        swap.finalizeWithdrawal(withdrawalId, withdrawal, _memberSignatures(withdrawalDigest));

        require(token.balanceOf(user) == 939.6 ether, "wrong public payout");
        require(token.balanceOf(address(swap)) == 60.4 ether, "wrong reserve balance");
        require(swap.privateLiabilities(address(token)) == 60 ether, "wrong liability");
        require(swap.accruedFees(address(token)) == 0.4 ether, "wrong fee");
        require(swap.spentNullifiers(withdrawal.nullifier), "nullifier not spent");
        require(swap.reserveIsSolvent(address(token)), "reserve insolvent");

        vm.expectRevert(ConfidentialTokenSwap.InvalidState.selector);
        swap.finalizeWithdrawal(withdrawalId, withdrawal, new bytes[](0));
    }

    function testPendingDepositCanBeRefundedAfterDelay() public {
        vm.prank(user);
        bytes32 depositId = swap.deposit(address(token), 25 ether, keccak256("refund-account"), 2);

        vm.expectRevert(ConfidentialTokenSwap.DeadlineExpired.selector);
        vm.prank(user);
        swap.cancelDeposit(depositId);

        vm.warp(block.timestamp + 1 days);
        vm.prank(user);
        swap.cancelDeposit(depositId);

        require(token.balanceOf(user) == 1_000 ether, "refund missing");
        require(token.balanceOf(address(swap)) == 0, "escrow not released");
        require(swap.accountedBalances(address(token)) == 0, "accounting not released");
    }

    function testRejectsInsufficientCommitteeSignatures() public {
        vm.prank(user);
        bytes32 depositId = swap.deposit(address(token), 10 ether, keccak256("private-account"), 3);
        ConfidentialTokenSwap.DepositSettlement memory settlement =
            ConfidentialTokenSwap.DepositSettlement({
                expectedOldStateRoot: bytes32(0),
                newStateRoot: keccak256("state"),
                encryptedBalanceDataId: keccak256("ciphertext"),
                transcriptRoot: keccak256("transcript")
            });
        bytes32 digest = swap.depositDigest(depositId, settlement);
        bytes[] memory signatures = new bytes[](1);
        (, uint256[] memory keys) = _sortedMembersAndKeys();
        signatures[0] = _sign(keys[0], digest);

        vm.expectRevert(ConfidentialTokenSwap.InvalidThreshold.selector);
        swap.finalizeDeposit(depositId, settlement, signatures);
    }

    function testUserPrepaidGasIsCreditedOnlyAfterValidSettlement() public {
        vm.prank(user);
        bytes32 depositId = swap.deposit{ value: 0.01 ether }(
            address(token), 10 ether, keccak256("gas-funded-account"), 44
        );
        require(swap.taskGasEscrow(depositId) == 0.01 ether, "escrow missing");
        ConfidentialTokenSwap.DepositSettlement memory settlement =
            ConfidentialTokenSwap.DepositSettlement({
                expectedOldStateRoot: bytes32(0),
                newStateRoot: keccak256("gas-state"),
                encryptedBalanceDataId: keccak256("gas-ciphertext"),
                transcriptRoot: keccak256("gas-transcript")
            });
        swap.finalizeDeposit(
            depositId, settlement, _memberSignatures(swap.depositDigest(depositId, settlement))
        );
        require(swap.taskGasEscrow(depositId) == 0, "escrow not consumed");
        require(swap.gasRefundCredits(address(this)) == 0.01 ether, "submitter not credited");
    }

    function testConfidentialTransferAdvancesRootWithoutChangingLiability() public {
        bytes32 senderAccount = keccak256("sender-private-account");
        bytes32 receiverAccount = keccak256("receiver-private-account");
        vm.prank(user);
        bytes32 depositId = swap.deposit(address(token), 100 ether, senderAccount, 9);
        ConfidentialTokenSwap.DepositSettlement memory depositSettlement =
            ConfidentialTokenSwap.DepositSettlement({
                expectedOldStateRoot: bytes32(0),
                newStateRoot: keccak256("deposit-root"),
                encryptedBalanceDataId: keccak256("sender-ciphertext"),
                transcriptRoot: keccak256("deposit-transcript")
            });
        swap.finalizeDeposit(
            depositId,
            depositSettlement,
            _memberSignatures(swap.depositDigest(depositId, depositSettlement))
        );
        vm.prank(user);
        swap.registerConfidentialAccount(receiverAccount);
        vm.prank(user);
        bytes32 transferId = swap.requestConfidentialTransfer(
            address(token),
            senderAccount,
            receiverAccount,
            30 ether,
            1,
            uint64(block.timestamp + 1 hours)
        );
        ConfidentialTokenSwap.ConfidentialTransferSettlement memory transferSettlement =
            ConfidentialTokenSwap.ConfidentialTransferSettlement({
                expectedOldStateRoot: depositSettlement.newStateRoot,
                newStateRoot: keccak256("transfer-root"),
                senderBalanceDataId: keccak256("sender-after"),
                receiverBalanceDataId: keccak256("receiver-after"),
                transcriptRoot: keccak256("transfer-transcript")
            });
        swap.finalizeConfidentialTransfer(
            transferId,
            transferSettlement,
            _memberSignatures(swap.confidentialTransferDigest(transferId, transferSettlement))
        );
        require(swap.privateLiabilities(address(token)) == 100 ether, "liability changed");
        require(
            swap.privateStateRoots(address(token)) == transferSettlement.newStateRoot,
            "transfer root not applied"
        );
    }

    function _memberSignatures(bytes32 digest) private returns (bytes[] memory signatures) {
        (, uint256[] memory keys) = _sortedMembersAndKeys();
        signatures = new bytes[](2);
        signatures[0] = _sign(keys[0], digest);
        signatures[1] = _sign(keys[1], digest);
    }

    function _sortedMembersAndKeys()
        private
        returns (address[] memory members, uint256[] memory keys)
    {
        members = new address[](3);
        keys = new uint256[](3);
        keys[0] = MEMBER_KEY_1;
        keys[1] = MEMBER_KEY_2;
        keys[2] = MEMBER_KEY_3;
        members[0] = vm.addr(keys[0]);
        members[1] = vm.addr(keys[1]);
        members[2] = vm.addr(keys[2]);
        for (uint256 i; i < members.length; ++i) {
            for (uint256 j = i + 1; j < members.length; ++j) {
                if (members[j] < members[i]) {
                    (members[i], members[j]) = (members[j], members[i]);
                    (keys[i], keys[j]) = (keys[j], keys[i]);
                }
            }
        }
    }

    function _sign(uint256 privateKey, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
