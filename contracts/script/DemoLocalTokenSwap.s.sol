// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import { ConfidentialTokenSwap, IPpscCommitteeRegistry } from "../src/ConfidentialTokenSwap.sol";
import { PpscControlPlane } from "../src/PpscControlPlane.sol";
import { ISortitionVerifier } from "../src/interfaces/ISortitionVerifier.sol";
import { MockERC20 } from "../test/mocks/MockERC20.sol";

interface SwapDemoVm {
    function envUint(string calldata name) external returns (uint256);
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
}

contract DemoAcceptAllSortition is ISortitionVerifier {
    function verifySelection(bytes32, uint64, bytes32, address[] calldata, bytes calldata)
        external
        pure
        returns (bool)
    {
        return true;
    }
}

contract DemoLocalTokenSwap {
    SwapDemoVm private constant vm =
        SwapDemoVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 private constant MEMBER_KEY_1 = 0xB0B;
    uint256 private constant MEMBER_KEY_2 = 0xCAFE;
    uint256 private constant MEMBER_KEY_3 = 0xD00D;

    function run()
        external
        returns (
            PpscControlPlane control,
            MockERC20 token,
            ConfidentialTokenSwap swap,
            bytes32 depositId
        )
    {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address user = vm.addr(deployerKey);
        bytes32 committeeId = keccak256("local-swap-committee");
        (address[] memory members,) = _sortedMembersAndKeys();

        vm.startBroadcast(deployerKey);
        DemoAcceptAllSortition verifier = new DemoAcceptAllSortition();
        control = new PpscControlPlane(user, user, verifier);
        control.finalizeCommittee(committeeId, keccak256("local-swap-seed"), 1, members, 2, hex"01");
        token = new MockERC20();
        swap = new ConfidentialTokenSwap(
            user, IPpscCommitteeRegistry(address(control)), committeeId, 1 days
        );
        swap.configureToken(address(token), true, 1 ether, 100);
        token.mint(user, 1_000 ether);
        token.approve(address(swap), type(uint256).max);
        depositId = swap.deposit(address(token), 100 ether, keccak256("demo-private-account"), 1);
        vm.stopBroadcast();

        ConfidentialTokenSwap.DepositSettlement memory settlement =
            ConfidentialTokenSwap.DepositSettlement({
                expectedOldStateRoot: bytes32(0),
                newStateRoot: keccak256("demo-private-state-1"),
                encryptedBalanceDataId: keccak256("demo-encrypted-balance"),
                transcriptRoot: keccak256("demo-deposit-transcript")
            });
        bytes[] memory depositSignatures =
            _memberSignatures(swap.depositDigest(depositId, settlement));

        vm.startBroadcast(deployerKey);
        swap.finalizeDeposit(depositId, settlement, depositSignatures);
        vm.stopBroadcast();

        ConfidentialTokenSwap.Withdrawal memory withdrawal = ConfidentialTokenSwap.Withdrawal({
            token: address(token),
            recipient: user,
            grossAmount: 40 ether,
            nullifier: keccak256("demo-withdraw-nullifier"),
            expectedOldStateRoot: settlement.newStateRoot,
            newStateRoot: keccak256("demo-private-state-2"),
            transcriptRoot: keccak256("demo-withdraw-transcript"),
            expiry: uint64(block.timestamp + 1 hours)
        });
        bytes[] memory withdrawalSignatures = _memberSignatures(swap.withdrawalDigest(withdrawal));

        vm.startBroadcast(deployerKey);
        swap.withdraw(withdrawal, withdrawalSignatures);
        vm.stopBroadcast();

        require(token.balanceOf(user) == 939.6 ether, "unexpected user balance");
        require(token.balanceOf(address(swap)) == 60.4 ether, "unexpected reserve");
        require(swap.privateLiabilities(address(token)) == 60 ether, "unexpected liability");
        require(swap.reserveIsSolvent(address(token)), "insolvent reserve");
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

