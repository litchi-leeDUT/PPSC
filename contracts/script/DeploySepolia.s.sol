// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import { PpscControlPlane } from "../src/PpscControlPlane.sol";
import { EcdsaSortitionVerifier } from "../src/EcdsaSortitionVerifier.sol";

interface VmScript {
    function envUint(string calldata name) external returns (uint256);
    function addr(uint256 privateKey) external returns (address);
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
}

contract DeploySepolia {
    VmScript private constant vm =
        VmScript(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external returns (EcdsaSortitionVerifier verifier, PpscControlPlane control) {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        vm.startBroadcast(deployerKey);
        verifier = new EcdsaSortitionVerifier(deployer);
        control = new PpscControlPlane(deployer, deployer, verifier);
        vm.stopBroadcast();
    }
}

