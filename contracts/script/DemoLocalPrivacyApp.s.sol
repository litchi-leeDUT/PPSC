// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import { PpscControlPlane } from "../src/PpscControlPlane.sol";
import { EcdsaSortitionVerifier } from "../src/EcdsaSortitionVerifier.sol";
import { PrivateBalanceApp } from "../src/examples/PrivateBalanceApp.sol";

interface DemoVmScript {
    function envUint(string calldata name) external returns (uint256);
    function addr(uint256 privateKey) external returns (address);
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
}

contract DemoLocalPrivacyApp {
    DemoVmScript private constant vm =
        DemoVmScript(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run()
        external
        returns (EcdsaSortitionVerifier verifier, PpscControlPlane control, PrivateBalanceApp app)
    {
        uint256 userKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address user = vm.addr(userKey);

        vm.startBroadcast(userKey);
        verifier = new EcdsaSortitionVerifier(user);
        control = new PpscControlPlane(user, user, verifier);
        app = new PrivateBalanceApp(
            control,
            user,
            keccak256("local-user-private-balance"),
            keccak256("private-balance-manifest-v1"),
            keccak256("ppsc-runtime-v1"),
            keccak256("initial-encrypted-balances-root")
        );
        vm.stopBroadcast();
    }
}
