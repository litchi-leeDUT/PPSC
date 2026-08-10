// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import { PpscControlPlane } from "../src/PpscControlPlane.sol";
import { EcdsaSortitionVerifier } from "../src/EcdsaSortitionVerifier.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);
    function expectRevert(bytes4 selector) external;
}

contract PpscControlPlaneTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 private constant AUTHORITY_KEY = 0xA11CE;
    uint256 private constant MEMBER_KEY_1 = 0xB0B;
    uint256 private constant MEMBER_KEY_2 = 0xCAFE;
    uint256 private constant MEMBER_KEY_3 = 0xD00D;

    EcdsaSortitionVerifier private verifier;
    PpscControlPlane private control;

    bytes32 private contractId;
    bytes32 private committeeId;
    bytes32 private keyDataId = keccak256("key-data");
    bytes32 private inputDataId = keccak256("input-data");
    bytes4 private constant SELECTOR = bytes4(keccak256("privateTransfer(bytes32)"));

    function setUp() public {
        verifier = new EcdsaSortitionVerifier(vm.addr(AUTHORITY_KEY));
        control = new PpscControlPlane(address(this), address(this), verifier);

        contractId = control.publishContract(
            keccak256("contract-salt"),
            keccak256("manifest"),
            keccak256("runtime"),
            keccak256("initial-state")
        );
        control.publishFunction(
            contractId,
            SELECTOR,
            keccak256("program"),
            keccak256("operator-sequence"),
            keccak256("abi"),
            "ipfs://program-cid",
            100_000
        );

        control.registerData(
            keyDataId,
            keccak256("key-commitment"),
            keccak256("key-pk-set"),
            keccak256("key-storage-set"),
            bytes32(0),
            PpscControlPlane.Representation.SecretSharing,
            1,
            1,
            1
        );
        control.registerData(
            inputDataId,
            keccak256("ciphertext"),
            keccak256("cipher-pk-set"),
            keccak256("cipher-storage-set"),
            keyDataId,
            PpscControlPlane.Representation.Fhe,
            0,
            1,
            1
        );

        committeeId = keccak256("committee-1");
        _finalizeCommittee(committeeId, keccak256("seed-1"), 1);
    }

    function testEndToEndExecutionAndPick() public {
        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = inputDataId;
        bytes32 executionId =
            control.invoke(contractId, SELECTOR, inputs, 1, uint64(block.timestamp + 1 days));

        control.assignCommittee(executionId, committeeId);
        control.markRunning(executionId);

        bytes32 outputId = keccak256("output");
        bytes32 newStateRoot = keccak256("new-state");
        PpscControlPlane.ResultSubmission memory result = PpscControlPlane.ResultSubmission({
            outputId: outputId,
            outputCommitment: keccak256("output-commitment"),
            outputPublicKeySetRoot: keccak256("output-pk-set"),
            outputStorageSetRoot: keccak256("output-storage-set"),
            outputFheKeyId: bytes32(0),
            outputRepresentation: PpscControlPlane.Representation.SecretSharing,
            outputThreshold: 1,
            outputVersion: 1,
            newStateRoot: newStateRoot,
            transcriptRoot: keccak256("transcript")
        });
        bytes32 digest = control.resultDigest(executionId, result);
        bytes[] memory signatures = _memberSignatures(digest);
        control.submitResult(executionId, result, signatures);

        require(
            control.executionStatus(executionId) == PpscControlPlane.ExecutionStatus.Completed,
            "execution not completed"
        );
        require(control.contractStateRoot(contractId) == newStateRoot, "state root not updated");
        require(
            control.dataStatus(outputId) == PpscControlPlane.DataStatus.Available,
            "output not registered"
        );

        bytes32 pickId = control.requestPick(
            outputId, keccak256("recipient-encryption-key"), 7, uint64(block.timestamp + 1 hours)
        );
        require(control.pickRequestExists(pickId), "pick not registered");
    }

    function testRejectsFheDataWithoutKeyReference() public {
        vm.expectRevert(PpscControlPlane.InvalidThreshold.selector);
        control.registerData(
            keccak256("bad-data"),
            keccak256("bad-commitment"),
            keccak256("pk-set"),
            keccak256("storage-set"),
            bytes32(0),
            PpscControlPlane.Representation.Fhe,
            0,
            1,
            1
        );
    }

    function testRejectsDuplicateInvocationNonce() public {
        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = inputDataId;
        control.invoke(contractId, SELECTOR, inputs, 99, uint64(block.timestamp + 1 days));
        vm.expectRevert(PpscControlPlane.NonceAlreadyUsed.selector);
        control.invoke(contractId, SELECTOR, inputs, 99, uint64(block.timestamp + 1 days));
    }

    function testCommitteeHandoffRequiresIncomingThreshold() public {
        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = inputDataId;
        bytes32 executionId =
            control.invoke(contractId, SELECTOR, inputs, 2, uint64(block.timestamp + 1 days));
        control.assignCommittee(executionId, committeeId);
        control.markRunning(executionId);

        bytes32 nextCommitteeId = keccak256("committee-2");
        _finalizeCommittee(nextCommitteeId, keccak256("seed-2"), 2);
        control.beginHandoff(executionId, nextCommitteeId, keccak256("epoch-state-root"));

        bytes32 digest = control.handoffDigest(executionId);
        bytes[] memory signatures = _memberSignatures(digest);
        control.finalizeHandoff(executionId, signatures);

        require(control.executionCommittee(executionId) == nextCommitteeId, "committee not rotated");
        require(
            control.executionStatus(executionId) == PpscControlPlane.ExecutionStatus.Running,
            "execution not resumed"
        );
    }

    function testDataLocationsMoveToSelectedCommittee() public {
        (address[] memory initialNodes,) = _sortedMembersAndKeys();
        bytes32 locatedDataId = keccak256("located-ss-data");
        control.registerData(
            locatedDataId,
            keccak256("located-data-commitment"),
            keccak256("initial-public-key-set"),
            keccak256(abi.encode(initialNodes)),
            bytes32(0),
            PpscControlPlane.Representation.SecretSharing,
            1,
            1,
            1
        );
        control.registerDataLocations(locatedDataId, initialNodes);

        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = locatedDataId;
        bytes32 executionId =
            control.invoke(contractId, SELECTOR, inputs, 3, uint64(block.timestamp + 1 days));
        control.assignCommittee(executionId, committeeId);
        control.markRunning(executionId);

        bytes32 nextCommitteeId = keccak256("storage-committee-2");
        _finalizeCommittee(nextCommitteeId, keccak256("storage-seed-2"), 2);
        control.beginHandoff(executionId, nextCommitteeId, keccak256("complete-epoch-state"));
        control.finalizeHandoff(executionId, _memberSignatures(control.handoffDigest(executionId)));

        address[] memory nextNodes = new address[](2);
        nextNodes[0] = initialNodes[0];
        nextNodes[1] = initialNodes[1];
        bytes32 newStorageRoot = keccak256(abi.encode(nextNodes));
        bytes32 newPublicKeyRoot = keccak256("next-public-key-set");
        bytes32 digest = control.dataHandoffDigest(
            locatedDataId, executionId, newStorageRoot, newPublicKeyRoot, 2, 2
        );
        control.updateDataLocationsAfterHandoff(
            locatedDataId, executionId, nextNodes, newPublicKeyRoot, _memberSignatures(digest)
        );

        address[] memory storedNodes = control.dataStorageNodes(locatedDataId);
        require(storedNodes.length == 2, "wrong storage-node count");
        require(storedNodes[0] == nextNodes[0], "first node not updated");
        require(storedNodes[1] == nextNodes[1], "second node not updated");
        require(control.dataVersion(locatedDataId) == 2, "data version not advanced");
    }

    function _finalizeCommittee(bytes32 id, bytes32 seed, uint64 epoch) private {
        (address[] memory members,) = _sortedMembersAndKeys();
        bytes32 digest = verifier.selectionDigest(seed, epoch, id, members);
        bytes memory evidence = _sign(AUTHORITY_KEY, digest);
        control.finalizeCommittee(id, seed, epoch, members, 2, evidence);
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
