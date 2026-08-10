// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import { PpscControlPlane } from "../src/PpscControlPlane.sol";
import { EcdsaSortitionVerifier } from "../src/EcdsaSortitionVerifier.sol";
import { PrivateBalanceApp } from "../src/examples/PrivateBalanceApp.sol";

interface UserVm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address sender) external;
    function expectRevert(bytes4 selector) external;
}

contract PrivateBalanceAppTest {
    UserVm private constant vm = UserVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant AUTHORITY_KEY = 0xA11CE;
    uint256 private constant MEMBER_KEY_1 = 0xB0B;
    uint256 private constant MEMBER_KEY_2 = 0xCAFE;
    uint256 private constant MEMBER_KEY_3 = 0xD00D;

    PpscControlPlane private control;
    PrivateBalanceApp private app;
    address private user;
    address private receiver;
    bytes32 private senderVariable;
    bytes32 private receiverVariable;

    function setUp() public {
        user = vm.addr(AUTHORITY_KEY);
        receiver = vm.addr(0xBEEF);
        EcdsaSortitionVerifier verifier = new EcdsaSortitionVerifier(user);
        control = new PpscControlPlane(address(this), address(this), verifier);
        vm.prank(user);
        app = new PrivateBalanceApp(
            control,
            user,
            keccak256("user-deployment-salt"),
            keccak256("private-balance-manifest"),
            keccak256("ppsc-runtime-v1"),
            keccak256("encrypted-balances-v1")
        );
        _registerAndDeclareVariables();
    }

    function testRuntimeControlsVariablesAndAuthorizedBalanceQueriesSurroundComputation() public {
        require(app.privateTransferPublished(), "program not atomically published");
        PpscControlPlane.FunctionDefinition memory definition = control.functionDefinition(
            app.confidentialContractId(), app.PRIVATE_TRANSFER_SELECTOR()
        );
        require(definition.exists, "program missing");

        vm.prank(user);
        bytes32 beforePick = app.requestMyBalance(
            keccak256("user-opening-key"), 10, uint64(block.timestamp + 1 hours)
        );
        require(control.pickRequestExists(beforePick), "pre-compute query missing");

        vm.prank(user);
        bytes32 executionId =
            app.conditionalTransfer(receiver, 1, uint64(block.timestamp + 1 hours));
        require(
            control.executionStatus(executionId) == PpscControlPlane.ExecutionStatus.Requested,
            "execution not requested"
        );

        bytes32 committeeId = keccak256("private-transfer-committee");
        _finalizeCommittee(committeeId);
        control.assignCommittee(executionId, committeeId);
        control.markRunning(executionId);
        PpscControlPlane.ResultSubmission memory result = _result();
        control.submitResult(
            executionId, result, _memberSignatures(control.resultDigest(executionId, result))
        );

        PpscControlPlane.VariableUpdate[] memory updates = new PpscControlPlane.VariableUpdate[](2);
        updates[0] =
            PpscControlPlane.VariableUpdate({ variableAddress: senderVariable, outputSlot: 0 });
        updates[1] =
            PpscControlPlane.VariableUpdate({ variableAddress: receiverVariable, outputSlot: 1 });
        control.updateStateVariablesAfterResult(
            executionId,
            updates,
            _memberSignatures(control.variableUpdateDigest(executionId, updates))
        );

        _assertVariable(senderVariable, result.outputId, 0);
        _assertVariable(receiverVariable, result.outputId, 1);
        require(app.privateStateRoot() == result.newStateRoot, "state root not advanced");

        vm.prank(user);
        bytes32 afterPick = app.requestMyBalance(
            keccak256("user-opening-key"), 11, uint64(block.timestamp + 1 hours)
        );
        require(control.pickRequestExists(afterPick), "post-compute query missing");
    }

    function testNonOwnerCannotInvokeOrQueryBalance() public {
        address attacker = vm.addr(0xBAD);
        vm.expectRevert(PrivateBalanceApp.Unauthorized.selector);
        vm.prank(attacker);
        app.conditionalTransfer(receiver, 9, uint64(block.timestamp + 1 hours));

        vm.expectRevert(PrivateBalanceApp.Unauthorized.selector);
        vm.prank(attacker);
        app.requestMyBalance(keccak256("attacker-key"), 1, uint64(block.timestamp + 1 hours));
    }

    function _registerAndDeclareVariables() private {
        bytes32 senderId = keccak256("sender-balance-100");
        bytes32 receiverId = keccak256("receiver-balance-20");
        bytes32 minimumId = keccak256("minimum-balance-50");
        bytes32 amountId = keccak256("transfer-amount-30");
        _registerInput(user, senderId, keccak256("sender-commitment"));
        _registerInput(receiver, receiverId, keccak256("receiver-commitment"));
        _registerInput(user, minimumId, keccak256("minimum-commitment"));
        _registerInput(user, amountId, keccak256("amount-commitment"));
        bytes32 contractId = app.confidentialContractId();
        senderVariable = app.balanceVariable(user);
        receiverVariable = app.balanceVariable(receiver);
        control.declareStateVariable(contractId, senderVariable, senderId, 0);
        control.declareStateVariable(contractId, receiverVariable, receiverId, 0);
        control.declareStateVariable(contractId, app.minimumBalanceVariable(), minimumId, 0);
        control.declareStateVariable(contractId, app.transferAmountVariable(), amountId, 0);
    }

    function _registerInput(address dataOwner, bytes32 dataId, bytes32 commitment) private {
        control.registerDataFor(
            dataOwner,
            dataId,
            commitment,
            keccak256("public-key-set"),
            keccak256("storage-set"),
            bytes32(0),
            PpscControlPlane.Representation.SecretSharing,
            2,
            1,
            1
        );
    }

    function _result() private pure returns (PpscControlPlane.ResultSubmission memory) {
        return PpscControlPlane.ResultSubmission({
            outputId: keccak256("private-transfer-output"),
            outputCommitment: keccak256("commit-ss-sender-70-receiver-50"),
            outputPublicKeySetRoot: keccak256("output-public-key-set"),
            outputStorageSetRoot: keccak256("output-storage-set"),
            outputFheKeyId: bytes32(0),
            outputRepresentation: PpscControlPlane.Representation.SecretSharing,
            outputThreshold: 2,
            outputVersion: 2,
            newStateRoot: keccak256("encrypted-balances-sender-70-receiver-50"),
            transcriptRoot: keccak256("C2S-MPC-gt-conditional-sub-add-S2C")
        });
    }

    function _assertVariable(bytes32 variableAddress, bytes32 dataId, uint32 slot) private view {
        PpscControlPlane.StateVariable memory variableRef =
            control.stateVariableReference(variableAddress);
        require(variableRef.dataId == dataId, "wrong variable data");
        require(variableRef.slot == slot, "wrong variable slot");
        require(variableRef.version == 2, "wrong variable version");
    }

    function _finalizeCommittee(bytes32 committeeId) private {
        (address[] memory members,) = _sortedMembersAndKeys();
        bytes32 seed = keccak256("private-transfer-seed");
        EcdsaSortitionVerifier verifier =
            EcdsaSortitionVerifier(address(control.sortitionVerifier()));
        bytes32 digest = verifier.selectionDigest(seed, 1, committeeId, members);
        control.finalizeCommittee(committeeId, seed, 1, members, 2, _sign(AUTHORITY_KEY, digest));
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
