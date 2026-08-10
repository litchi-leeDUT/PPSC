// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import { ConfidentialTokenSwap, IPpscCommitteeRegistry } from "../src/ConfidentialTokenSwap.sol";
import { PpscControlPlane } from "../src/PpscControlPlane.sol";
import { ISortitionVerifier } from "../src/interfaces/ISortitionVerifier.sol";
import { MockERC20 } from "../test/mocks/MockERC20.sol";

interface InteractiveVm {
    function envUint(string calldata name) external returns (uint256);
    function addr(uint256 privateKey) external returns (address);
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
}

contract InteractiveAcceptAllSortition is ISortitionVerifier {
    function verifySelection(bytes32, uint64, bytes32, address[] calldata, bytes calldata)
        external
        pure
        returns (bool)
    {
        return true;
    }
}

/// @notice Deploys only the infrastructure. User actions are sent later by the
/// interactive shell, so every balance change can be observed independently.
contract DeployInteractiveSwap {
    InteractiveVm private constant vm =
        InteractiveVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 private constant MEMBER_KEY_1 = 0xB0B;
    uint256 private constant MEMBER_KEY_2 = 0xCAFE;
    uint256 private constant MEMBER_KEY_3 = 0xD00D;

    function run()
        external
        returns (PpscControlPlane control, MockERC20 token, ConfidentialTokenSwap swap)
    {
        uint256 userKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address user = vm.addr(userKey);
        bytes32 committeeId = keccak256("interactive-swap-committee");
        address[] memory members = _sortedMembers();

        vm.startBroadcast(userKey);
        InteractiveAcceptAllSortition verifier = new InteractiveAcceptAllSortition();
        control = new PpscControlPlane(user, user, verifier);
        control.finalizeCommittee(
            committeeId, keccak256("interactive-swap-seed"), 1, members, 2, hex"01"
        );
        token = new MockERC20();
        swap = new ConfidentialTokenSwap(
            user, IPpscCommitteeRegistry(address(control)), committeeId, 1 days
        );
        swap.configureToken(address(token), true, 1 ether, 100);
        token.mint(user, 1_000 ether);
        vm.stopBroadcast();
    }

    function _sortedMembers() private returns (address[] memory members) {
        members = new address[](3);
        members[0] = vm.addr(MEMBER_KEY_1);
        members[1] = vm.addr(MEMBER_KEY_2);
        members[2] = vm.addr(MEMBER_KEY_3);
        for (uint256 i; i < members.length; ++i) {
            for (uint256 j = i + 1; j < members.length; ++j) {
                if (members[j] < members[i]) {
                    (members[i], members[j]) = (members[j], members[i]);
                }
            }
        }
    }
}
