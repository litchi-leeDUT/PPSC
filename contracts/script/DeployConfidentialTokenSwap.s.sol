// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import { ConfidentialTokenSwap, IPpscCommitteeRegistry } from "../src/ConfidentialTokenSwap.sol";

interface SwapDeployVm {
    function envUint(string calldata name) external returns (uint256);
    function envAddress(string calldata name) external returns (address);
    function envBytes32(string calldata name) external returns (bytes32);
    function addr(uint256 privateKey) external returns (address);
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
}

contract DeployConfidentialTokenSwap {
    SwapDeployVm private constant vm =
        SwapDeployVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external returns (ConfidentialTokenSwap swap) {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);
        address controlPlane = vm.envAddress("CONTROL_PLANE_ADDRESS");
        address publicToken = vm.envAddress("PUBLIC_TOKEN_ADDRESS");
        bytes32 committeeId = vm.envBytes32("ACTIVE_COMMITTEE_ID");
        uint256 minimumDeposit = vm.envUint("MINIMUM_DEPOSIT");
        uint256 withdrawalFeeBps = vm.envUint("WITHDRAWAL_FEE_BPS");
        uint256 refundDelay = vm.envUint("REFUND_DELAY_SECONDS");
        require(minimumDeposit <= type(uint128).max, "minimum overflow");
        require(withdrawalFeeBps <= type(uint16).max, "fee overflow");
        require(refundDelay <= type(uint64).max, "delay overflow");

        vm.startBroadcast(deployerKey);
        swap = new ConfidentialTokenSwap(
            deployer, IPpscCommitteeRegistry(controlPlane), committeeId, uint64(refundDelay)
        );
        swap.configureToken(publicToken, true, uint128(minimumDeposit), uint16(withdrawalFeeBps));
        vm.stopBroadcast();
    }
}

