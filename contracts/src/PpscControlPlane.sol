// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import { ISortitionVerifier } from "./interfaces/ISortitionVerifier.sol";

/// @title PPSC on-chain control plane
/// @notice Stores only public programs, handles, commitments and protocol attestations.
/// @dev Never put plaintexts, local shares, FHE secret-key shares or preprocessing secrets here.
contract PpscControlPlane {
    enum Representation {
        SecretSharing,
        Fhe
    }

    enum DataStatus {
        None,
        Available,
        Locked,
        Superseded,
        Expired
    }

    enum ExecutionStatus {
        None,
        Requested,
        CommitteeAssigned,
        Running,
        Handoff,
        ResultPending,
        Completed,
        Failed,
        Cancelled
    }

    struct ConfidentialContract {
        address owner;
        bytes32 manifestHash;
        bytes32 runtimeHash;
        bytes32 stateRoot;
        uint64 version;
        bool active;
    }

    struct FunctionDefinition {
        bytes32 programHash;
        bytes32 operatorSequenceHash;
        bytes32 abiHash;
        string codeLocation;
        uint64 maxSteps;
        bool exists;
    }

    struct DataReference {
        address owner;
        bytes32 commitment;
        bytes32 publicKeySetRoot;
        bytes32 storageSetRoot;
        bytes32 fheKeyId;
        Representation representation;
        DataStatus status;
        uint16 threshold;
        uint64 version;
        uint64 epoch;
    }

    struct Committee {
        uint64 epoch;
        uint16 threshold;
        bytes32 seed;
        bytes32 memberRoot;
        bytes32 selectionEvidenceHash;
        bool active;
    }

    struct Execution {
        bytes32 contractId;
        bytes32 functionId;
        bytes32 inputRoot;
        bytes32 oldStateRoot;
        bytes32 outputId;
        bytes32 currentCommitteeId;
        bytes32 nextCommitteeId;
        bytes32 transcriptRoot;
        address requester;
        uint64 nonce;
        uint64 deadline;
        uint32 round;
        ExecutionStatus status;
    }

    struct ResultSubmission {
        bytes32 outputId;
        bytes32 outputCommitment;
        bytes32 outputPublicKeySetRoot;
        bytes32 outputStorageSetRoot;
        bytes32 outputFheKeyId;
        Representation outputRepresentation;
        uint16 outputThreshold;
        uint64 outputVersion;
        bytes32 newStateRoot;
        bytes32 transcriptRoot;
    }

    struct StateVariable {
        bytes32 contractId;
        bytes32 dataId;
        Representation representation;
        uint32 slot;
        uint64 version;
        bool exists;
    }

    struct VariableUpdate {
        bytes32 variableAddress;
        uint32 outputSlot;
    }

    error Unauthorized();
    error AlreadyExists();
    error NotFound();
    error InvalidArgument();
    error InvalidState();
    error InvalidThreshold();
    error InvalidSelection();
    error InvalidSignature();
    error DeadlineExpired();
    error NonceAlreadyUsed();

    event ContractPublished(
        bytes32 indexed contractId, address indexed owner, bytes32 manifestHash, bytes32 runtimeHash
    );
    event FunctionPublished(
        bytes32 indexed contractId,
        bytes4 indexed selector,
        bytes32 programHash,
        bytes32 operatorSequenceHash,
        string codeLocation
    );
    event DataRegistered(
        bytes32 indexed dataId,
        address indexed owner,
        Representation representation,
        bytes32 commitment,
        bytes32 storageSetRoot
    );
    event DataLocationsRegistered(
        bytes32 indexed dataId, bytes32 indexed storageSetRoot, address[] storageNodes
    );
    event DataHandoffFinalized(
        bytes32 indexed dataId,
        bytes32 indexed executionId,
        bytes32 indexed committeeId,
        bytes32 oldStorageSetRoot,
        bytes32 newStorageSetRoot,
        uint64 epoch,
        uint64 version
    );
    event CommitteeFinalized(
        bytes32 indexed committeeId,
        uint64 indexed epoch,
        bytes32 seed,
        bytes32 memberRoot,
        uint16 threshold
    );
    event ExecutionRequested(
        bytes32 indexed executionId,
        bytes32 indexed contractId,
        bytes4 indexed selector,
        address requester,
        bytes32 inputRoot
    );
    event CommitteeAssigned(bytes32 indexed executionId, bytes32 indexed committeeId);
    event HandoffStarted(
        bytes32 indexed executionId,
        bytes32 indexed oldCommitteeId,
        bytes32 indexed nextCommitteeId,
        bytes32 epochStateRoot
    );
    event HandoffFinalized(bytes32 indexed executionId, bytes32 indexed committeeId);
    event ResultFinalized(
        bytes32 indexed executionId,
        bytes32 indexed outputId,
        bytes32 newStateRoot,
        bytes32 transcriptRoot
    );
    event StateVariableDeclared(
        bytes32 indexed variableAddress,
        bytes32 indexed contractId,
        bytes32 indexed dataId,
        uint32 slot,
        uint64 version
    );
    event StateVariableUpdated(
        bytes32 indexed variableAddress,
        bytes32 indexed executionId,
        bytes32 indexed dataId,
        uint32 slot,
        uint64 version
    );
    event VariablePickRequested(
        bytes32 indexed requestId,
        bytes32 indexed variableAddress,
        bytes32 indexed dataId,
        uint32 slot,
        uint64 version,
        bytes32 recipient
    );
    event PickRequested(
        bytes32 indexed requestId,
        bytes32 indexed dataId,
        address indexed owner,
        bytes32 recipient,
        uint64 nonce,
        uint64 expiry
    );

    address public admin;
    address public runtime;
    ISortitionVerifier public sortitionVerifier;

    mapping(bytes32 => ConfidentialContract) public contracts;
    mapping(bytes32 => FunctionDefinition) private _functions;
    mapping(bytes32 => DataReference) public dataReferences;
    mapping(bytes32 => address[]) private _dataStorageNodes;
    mapping(bytes32 => Committee) public committees;
    mapping(bytes32 => address[]) private _committeeMembers;
    mapping(bytes32 => mapping(address => bool)) public isCommitteeMember;
    mapping(bytes32 => Execution) public executions;
    mapping(bytes32 => StateVariable) public stateVariables;
    mapping(bytes32 => bool) public executionVariableUpdatesFinalized;
    mapping(address => mapping(uint64 => bool)) public invocationNonceUsed;
    mapping(bytes32 => bool) public pickRequestExists;

    constructor(address admin_, address runtime_, ISortitionVerifier sortitionVerifier_) {
        if (
            admin_ == address(0) || runtime_ == address(0)
                || address(sortitionVerifier_) == address(0)
        ) revert InvalidArgument();
        admin = admin_;
        runtime = runtime_;
        sortitionVerifier = sortitionVerifier_;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }

    modifier onlyRuntime() {
        if (msg.sender != runtime) revert Unauthorized();
        _;
    }

    function setRuntime(address nextRuntime) external onlyAdmin {
        if (nextRuntime == address(0)) revert InvalidArgument();
        runtime = nextRuntime;
    }

    function setSortitionVerifier(ISortitionVerifier nextVerifier) external onlyAdmin {
        if (address(nextVerifier) == address(0)) revert InvalidArgument();
        sortitionVerifier = nextVerifier;
    }

    function publishContract(
        bytes32 salt,
        bytes32 manifestHash,
        bytes32 runtimeHash,
        bytes32 initialStateRoot
    ) external returns (bytes32 contractId) {
        if (manifestHash == bytes32(0) || runtimeHash == bytes32(0)) {
            revert InvalidArgument();
        }
        contractId = keccak256(
            abi.encode("PPSC_CONTRACT_V1", block.chainid, address(this), msg.sender, salt)
        );
        if (contracts[contractId].owner != address(0)) revert AlreadyExists();
        contracts[contractId] = ConfidentialContract({
            owner: msg.sender,
            manifestHash: manifestHash,
            runtimeHash: runtimeHash,
            stateRoot: initialStateRoot,
            version: 1,
            active: true
        });
        emit ContractPublished(contractId, msg.sender, manifestHash, runtimeHash);
    }

    function publishFunction(
        bytes32 contractId,
        bytes4 selector,
        bytes32 programHash,
        bytes32 operatorSequenceHash,
        bytes32 abiHash,
        string calldata codeLocation,
        uint64 maxSteps
    ) external {
        ConfidentialContract storage target = contracts[contractId];
        if (target.owner == address(0)) revert NotFound();
        if (msg.sender != target.owner) revert Unauthorized();
        if (
            selector == bytes4(0) || programHash == bytes32(0) || operatorSequenceHash == bytes32(0)
                || bytes(codeLocation).length == 0 || maxSteps == 0
        ) revert InvalidArgument();
        bytes32 functionId = _functionId(contractId, selector);
        if (_functions[functionId].exists) revert AlreadyExists();
        _functions[functionId] = FunctionDefinition({
            programHash: programHash,
            operatorSequenceHash: operatorSequenceHash,
            abiHash: abiHash,
            codeLocation: codeLocation,
            maxSteps: maxSteps,
            exists: true
        });
        emit FunctionPublished(
            contractId, selector, programHash, operatorSequenceHash, codeLocation
        );
    }

    function functionDefinition(bytes32 contractId, bytes4 selector)
        external
        view
        returns (FunctionDefinition memory)
    {
        return _functions[_functionId(contractId, selector)];
    }

    function registerData(
        bytes32 dataId,
        bytes32 commitment,
        bytes32 publicKeySetRoot,
        bytes32 storageSetRoot,
        bytes32 fheKeyId,
        Representation representation,
        uint16 threshold,
        uint64 version,
        uint64 epoch
    ) external {
        _registerData(
            msg.sender,
            dataId,
            commitment,
            publicKeySetRoot,
            storageSetRoot,
            fheKeyId,
            representation,
            threshold,
            version,
            epoch
        );
    }

    /// @notice Runtime registers ciphertext/shares uploaded for an end user.
    function registerDataFor(
        address dataOwner,
        bytes32 dataId,
        bytes32 commitment,
        bytes32 publicKeySetRoot,
        bytes32 storageSetRoot,
        bytes32 fheKeyId,
        Representation representation,
        uint16 threshold,
        uint64 version,
        uint64 epoch
    ) external onlyRuntime {
        if (dataOwner == address(0)) revert InvalidArgument();
        _registerData(
            dataOwner,
            dataId,
            commitment,
            publicKeySetRoot,
            storageSetRoot,
            fheKeyId,
            representation,
            threshold,
            version,
            epoch
        );
    }

    function _registerData(
        address dataOwner,
        bytes32 dataId,
        bytes32 commitment,
        bytes32 publicKeySetRoot,
        bytes32 storageSetRoot,
        bytes32 fheKeyId,
        Representation representation,
        uint16 threshold,
        uint64 version,
        uint64 epoch
    ) private {
        if (
            dataId == bytes32(0) || commitment == bytes32(0) || publicKeySetRoot == bytes32(0)
                || storageSetRoot == bytes32(0) || version == 0
        ) revert InvalidArgument();
        if (dataReferences[dataId].status != DataStatus.None) revert AlreadyExists();
        if (representation == Representation.SecretSharing) {
            if (threshold == 0 || fheKeyId != bytes32(0)) revert InvalidThreshold();
        } else {
            if (threshold != 0 || fheKeyId == bytes32(0)) revert InvalidThreshold();
            DataReference storage keyRef = dataReferences[fheKeyId];
            if (
                keyRef.status != DataStatus.Available
                    || keyRef.representation != Representation.SecretSharing
                    || keyRef.owner != dataOwner
            ) revert InvalidArgument();
        }
        dataReferences[dataId] = DataReference({
            owner: dataOwner,
            commitment: commitment,
            publicKeySetRoot: publicKeySetRoot,
            storageSetRoot: storageSetRoot,
            fheKeyId: fheKeyId,
            representation: representation,
            status: DataStatus.Available,
            threshold: threshold,
            version: version,
            epoch: epoch
        });
        emit DataRegistered(dataId, dataOwner, representation, commitment, storageSetRoot);
    }

    /// @notice Publishes the explicit storage-node list whose hash is already bound by registerData.
    function registerDataLocations(bytes32 dataId, address[] calldata storageNodes) external {
        DataReference storage dataRef = dataReferences[dataId];
        if (dataRef.status != DataStatus.Available) revert NotFound();
        if (dataRef.owner != msg.sender && msg.sender != runtime) revert Unauthorized();
        if (_dataStorageNodes[dataId].length != 0) revert AlreadyExists();
        bytes32 storageSetRoot = _validateAndHashNodes(storageNodes);
        if (storageSetRoot != dataRef.storageSetRoot) revert InvalidArgument();
        for (uint256 i; i < storageNodes.length; ++i) {
            _dataStorageNodes[dataId].push(storageNodes[i]);
        }
        emit DataLocationsRegistered(dataId, storageSetRoot, storageNodes);
    }

    function dataStorageNodes(bytes32 dataId) external view returns (address[] memory) {
        return _dataStorageNodes[dataId];
    }

    /// @notice Runtime declares the authoritative binding for a logical variable.
    function declareStateVariable(
        bytes32 contractId,
        bytes32 variableAddress,
        bytes32 dataId,
        uint32 slot
    ) external onlyRuntime {
        if (contracts[contractId].owner == address(0)) revert NotFound();
        DataReference storage dataRef = dataReferences[dataId];
        if (variableAddress == bytes32(0) || dataRef.status != DataStatus.Available) {
            revert InvalidArgument();
        }
        if (stateVariables[variableAddress].exists) revert AlreadyExists();
        stateVariables[variableAddress] = StateVariable({
            contractId: contractId,
            dataId: dataId,
            representation: dataRef.representation,
            slot: slot,
            version: dataRef.version,
            exists: true
        });
        emit StateVariableDeclared(variableAddress, contractId, dataId, slot, dataRef.version);
    }

    function finalizeCommittee(
        bytes32 committeeId,
        bytes32 seed,
        uint64 epoch,
        address[] calldata members,
        uint16 threshold,
        bytes calldata selectionEvidence
    ) external onlyRuntime {
        if (committeeId == bytes32(0) || seed == bytes32(0) || members.length == 0) {
            revert InvalidArgument();
        }
        if (committees[committeeId].active) revert AlreadyExists();
        if (threshold == 0 || threshold > members.length) revert InvalidThreshold();
        address previous;
        for (uint256 i; i < members.length; ++i) {
            if (members[i] == address(0) || members[i] <= previous) revert InvalidArgument();
            previous = members[i];
        }
        if (!sortitionVerifier.verifySelection(
                seed, epoch, committeeId, members, selectionEvidence
            )) revert InvalidSelection();

        bytes32 memberRoot = keccak256(abi.encode(members));
        committees[committeeId] = Committee({
            epoch: epoch,
            threshold: threshold,
            seed: seed,
            memberRoot: memberRoot,
            selectionEvidenceHash: keccak256(selectionEvidence),
            active: true
        });
        for (uint256 i; i < members.length; ++i) {
            _committeeMembers[committeeId].push(members[i]);
            isCommitteeMember[committeeId][members[i]] = true;
        }
        emit CommitteeFinalized(committeeId, epoch, seed, memberRoot, threshold);
    }

    function committeeMembers(bytes32 committeeId) external view returns (address[] memory) {
        return _committeeMembers[committeeId];
    }

    function invoke(
        bytes32 contractId,
        bytes4 selector,
        bytes32[] calldata inputIds,
        uint64 nonce,
        uint64 deadline
    ) external returns (bytes32 executionId) {
        return _invoke(contractId, selector, inputIds, msg.sender, nonce, deadline);
    }

    /// @notice Lets the published application contract preserve the end-user as
    /// execution requester while still exposing an application-level ABI.
    function invokeFor(
        bytes32 contractId,
        bytes4 selector,
        bytes32[] calldata inputIds,
        address requester,
        uint64 nonce,
        uint64 deadline
    ) external returns (bytes32 executionId) {
        ConfidentialContract storage target = contracts[contractId];
        if (target.owner != msg.sender) revert Unauthorized();
        if (requester == address(0)) revert InvalidArgument();
        return _invoke(contractId, selector, inputIds, requester, nonce, deadline);
    }

    function _invoke(
        bytes32 contractId,
        bytes4 selector,
        bytes32[] calldata inputIds,
        address requester,
        uint64 nonce,
        uint64 deadline
    ) private returns (bytes32 executionId) {
        ConfidentialContract storage target = contracts[contractId];
        if (!target.active || !_functions[_functionId(contractId, selector)].exists) {
            revert NotFound();
        }
        if (deadline <= block.timestamp) revert DeadlineExpired();
        if (invocationNonceUsed[requester][nonce]) revert NonceAlreadyUsed();
        invocationNonceUsed[requester][nonce] = true;
        for (uint256 i; i < inputIds.length; ++i) {
            if (dataReferences[inputIds[i]].status != DataStatus.Available) revert InvalidState();
        }
        bytes32 inputRoot = keccak256(abi.encode(inputIds));
        executionId = keccak256(
            abi.encode(
                "PPSC_EXECUTION_V1",
                block.chainid,
                address(this),
                requester,
                contractId,
                selector,
                inputRoot,
                nonce
            )
        );
        if (executions[executionId].status != ExecutionStatus.None) revert AlreadyExists();
        executions[executionId] = Execution({
            contractId: contractId,
            functionId: _functionId(contractId, selector),
            inputRoot: inputRoot,
            oldStateRoot: target.stateRoot,
            outputId: bytes32(0),
            currentCommitteeId: bytes32(0),
            nextCommitteeId: bytes32(0),
            transcriptRoot: bytes32(0),
            requester: requester,
            nonce: nonce,
            deadline: deadline,
            round: 0,
            status: ExecutionStatus.Requested
        });
        emit ExecutionRequested(executionId, contractId, selector, requester, inputRoot);
    }

    function assignCommittee(bytes32 executionId, bytes32 committeeId) external onlyRuntime {
        Execution storage execution = executions[executionId];
        if (execution.status != ExecutionStatus.Requested) revert InvalidState();
        if (!committees[committeeId].active) revert NotFound();
        execution.currentCommitteeId = committeeId;
        execution.status = ExecutionStatus.CommitteeAssigned;
        emit CommitteeAssigned(executionId, committeeId);
    }

    function markRunning(bytes32 executionId) external onlyRuntime {
        Execution storage execution = executions[executionId];
        if (execution.status != ExecutionStatus.CommitteeAssigned) revert InvalidState();
        execution.status = ExecutionStatus.Running;
    }

    function beginHandoff(bytes32 executionId, bytes32 nextCommitteeId, bytes32 epochStateRoot)
        external
        onlyRuntime
    {
        Execution storage execution = executions[executionId];
        if (execution.status != ExecutionStatus.Running || epochStateRoot == bytes32(0)) {
            revert InvalidState();
        }
        if (!committees[nextCommitteeId].active) revert NotFound();
        execution.nextCommitteeId = nextCommitteeId;
        execution.transcriptRoot = epochStateRoot;
        execution.status = ExecutionStatus.Handoff;
        emit HandoffStarted(
            executionId, execution.currentCommitteeId, nextCommitteeId, epochStateRoot
        );
    }

    function finalizeHandoff(bytes32 executionId, bytes[] calldata signatures)
        external
        onlyRuntime
    {
        Execution storage execution = executions[executionId];
        if (execution.status != ExecutionStatus.Handoff) revert InvalidState();
        bytes32 digest = handoffDigest(executionId);
        _verifyThreshold(execution.nextCommitteeId, digest, signatures);
        execution.currentCommitteeId = execution.nextCommitteeId;
        execution.nextCommitteeId = bytes32(0);
        execution.round += 1;
        execution.status = ExecutionStatus.Running;
        emit HandoffFinalized(executionId, execution.currentCommitteeId);
    }

    /// @notice Updates a data reference after the bytes/shares have been handed to the active committee.
    function updateDataLocationsAfterHandoff(
        bytes32 dataId,
        bytes32 executionId,
        address[] calldata newStorageNodes,
        bytes32 newPublicKeySetRoot,
        bytes[] calldata signatures
    ) external onlyRuntime {
        DataReference storage dataRef = dataReferences[dataId];
        Execution storage execution = executions[executionId];
        if (dataRef.status != DataStatus.Available || execution.status != ExecutionStatus.Running) {
            revert InvalidState();
        }
        if (newPublicKeySetRoot == bytes32(0)) revert InvalidArgument();
        bytes32 committeeId = execution.currentCommitteeId;
        Committee storage committee = committees[committeeId];
        if (!committee.active) revert InvalidState();
        bytes32 newStorageSetRoot = _validateAndHashNodes(newStorageNodes);
        for (uint256 i; i < newStorageNodes.length; ++i) {
            if (!isCommitteeMember[committeeId][newStorageNodes[i]]) revert Unauthorized();
        }
        bytes32 digest = dataHandoffDigest(
            dataId,
            executionId,
            newStorageSetRoot,
            newPublicKeySetRoot,
            committee.epoch,
            dataRef.version + 1
        );
        _verifyThreshold(committeeId, digest, signatures);

        bytes32 oldStorageSetRoot = dataRef.storageSetRoot;
        _replaceDataStorageNodes(dataId, newStorageNodes);
        dataRef.storageSetRoot = newStorageSetRoot;
        dataRef.publicKeySetRoot = newPublicKeySetRoot;
        dataRef.epoch = committee.epoch;
        dataRef.version += 1;
        emit DataHandoffFinalized(
            dataId,
            executionId,
            committeeId,
            oldStorageSetRoot,
            newStorageSetRoot,
            committee.epoch,
            dataRef.version
        );
    }

    function dataHandoffDigest(
        bytes32 dataId,
        bytes32 executionId,
        bytes32 newStorageSetRoot,
        bytes32 newPublicKeySetRoot,
        uint64 newEpoch,
        uint64 newVersion
    ) public view returns (bytes32) {
        DataReference storage dataRef = dataReferences[dataId];
        return _ethSigned(
            keccak256(
                abi.encode(
                    "PPSC_DATA_HANDOFF_V1",
                    block.chainid,
                    address(this),
                    dataId,
                    executionId,
                    executions[executionId].currentCommitteeId,
                    dataRef.storageSetRoot,
                    newStorageSetRoot,
                    dataRef.publicKeySetRoot,
                    newPublicKeySetRoot,
                    newEpoch,
                    newVersion
                )
            )
        );
    }

    function handoffDigest(bytes32 executionId) public view returns (bytes32) {
        Execution storage execution = executions[executionId];
        return _ethSigned(
            keccak256(
                abi.encode(
                    "PPSC_HANDOFF_V1",
                    block.chainid,
                    address(this),
                    executionId,
                    execution.currentCommitteeId,
                    execution.nextCommitteeId,
                    execution.transcriptRoot
                )
            )
        );
    }

    function submitResult(
        bytes32 executionId,
        ResultSubmission calldata result,
        bytes[] calldata signatures
    ) external onlyRuntime {
        Execution storage execution = executions[executionId];
        if (execution.status != ExecutionStatus.Running) revert InvalidState();
        if (block.timestamp > execution.deadline) revert DeadlineExpired();
        if (
            result.outputId == bytes32(0) || result.outputCommitment == bytes32(0)
                || result.outputPublicKeySetRoot == bytes32(0)
                || result.outputStorageSetRoot == bytes32(0) || result.outputVersion == 0
                || result.newStateRoot == bytes32(0) || result.transcriptRoot == bytes32(0)
        ) revert InvalidArgument();
        if (dataReferences[result.outputId].status != DataStatus.None) revert AlreadyExists();
        if (result.outputRepresentation == Representation.SecretSharing) {
            if (result.outputThreshold == 0 || result.outputFheKeyId != bytes32(0)) {
                revert InvalidThreshold();
            }
        } else {
            if (result.outputThreshold != 0 || result.outputFheKeyId == bytes32(0)) {
                revert InvalidThreshold();
            }
            DataReference storage outputKeyRef = dataReferences[result.outputFheKeyId];
            if (
                outputKeyRef.status != DataStatus.Available
                    || outputKeyRef.representation != Representation.SecretSharing
                    || outputKeyRef.owner != execution.requester
            ) revert InvalidArgument();
        }
        bytes32 digest = resultDigest(executionId, result);
        _verifyThreshold(execution.currentCommitteeId, digest, signatures);

        ConfidentialContract storage target = contracts[execution.contractId];
        if (target.stateRoot != execution.oldStateRoot) revert InvalidState();
        target.stateRoot = result.newStateRoot;
        target.version += 1;
        dataReferences[result.outputId] = DataReference({
            owner: execution.requester,
            commitment: result.outputCommitment,
            publicKeySetRoot: result.outputPublicKeySetRoot,
            storageSetRoot: result.outputStorageSetRoot,
            fheKeyId: result.outputFheKeyId,
            representation: result.outputRepresentation,
            status: DataStatus.Available,
            threshold: result.outputThreshold,
            version: result.outputVersion,
            epoch: committees[execution.currentCommitteeId].epoch
        });
        execution.outputId = result.outputId;
        execution.transcriptRoot = result.transcriptRoot;
        execution.status = ExecutionStatus.Completed;
        emit DataRegistered(
            result.outputId,
            execution.requester,
            result.outputRepresentation,
            result.outputCommitment,
            result.outputStorageSetRoot
        );
        emit ResultFinalized(
            executionId, result.outputId, result.newStateRoot, result.transcriptRoot
        );
    }

    function resultDigest(bytes32 executionId, ResultSubmission calldata result)
        public
        view
        returns (bytes32)
    {
        return _ethSigned(
            keccak256(
                abi.encode(
                    "PPSC_RESULT_V1",
                    block.chainid,
                    address(this),
                    executionId,
                    executions[executionId].currentCommitteeId,
                    executions[executionId].oldStateRoot,
                    result
                )
            )
        );
    }

    /// @notice Committee-authorized variable advancement after an accepted result.
    /// Users cannot choose or mutate these bindings.
    function updateStateVariablesAfterResult(
        bytes32 executionId,
        VariableUpdate[] calldata updates,
        bytes[] calldata signatures
    ) external onlyRuntime {
        Execution storage execution = executions[executionId];
        if (
            execution.status != ExecutionStatus.Completed
                || executionVariableUpdatesFinalized[executionId] || updates.length == 0
        ) revert InvalidState();
        bytes32 digest = variableUpdateDigest(executionId, updates);
        _verifyThreshold(execution.currentCommitteeId, digest, signatures);
        DataReference storage output = dataReferences[execution.outputId];
        for (uint256 i; i < updates.length; ++i) {
            StateVariable storage variableRef = stateVariables[updates[i].variableAddress];
            if (!variableRef.exists || variableRef.contractId != execution.contractId) {
                revert InvalidArgument();
            }
            variableRef.dataId = execution.outputId;
            variableRef.representation = output.representation;
            variableRef.slot = updates[i].outputSlot;
            variableRef.version = output.version;
            emit StateVariableUpdated(
                updates[i].variableAddress,
                executionId,
                execution.outputId,
                updates[i].outputSlot,
                output.version
            );
        }
        executionVariableUpdatesFinalized[executionId] = true;
    }

    function variableUpdateDigest(bytes32 executionId, VariableUpdate[] calldata updates)
        public
        view
        returns (bytes32)
    {
        Execution storage execution = executions[executionId];
        return _ethSigned(
            keccak256(
                abi.encode(
                    "PPSC_VARIABLE_UPDATE_V1",
                    block.chainid,
                    address(this),
                    executionId,
                    execution.contractId,
                    execution.outputId,
                    keccak256(abi.encode(updates))
                )
            )
        );
    }

    function requestVariablePickFor(
        bytes32 variableAddress,
        address requester,
        bytes32 recipient,
        uint64 nonce,
        uint64 expiry
    ) external returns (bytes32 requestId) {
        StateVariable storage variableRef = stateVariables[variableAddress];
        if (!variableRef.exists) revert NotFound();
        if (contracts[variableRef.contractId].owner != msg.sender) revert Unauthorized();
        if (requester == address(0) || recipient == bytes32(0) || expiry <= block.timestamp) {
            revert InvalidArgument();
        }
        requestId = keccak256(
            abi.encode(
                "PPSC_VARIABLE_PICK_V1",
                block.chainid,
                address(this),
                variableAddress,
                variableRef.dataId,
                variableRef.slot,
                variableRef.version,
                requester,
                recipient,
                nonce,
                expiry
            )
        );
        if (pickRequestExists[requestId]) revert NonceAlreadyUsed();
        pickRequestExists[requestId] = true;
        emit VariablePickRequested(
            requestId,
            variableAddress,
            variableRef.dataId,
            variableRef.slot,
            variableRef.version,
            recipient
        );
    }

    function requestPick(bytes32 dataId, bytes32 recipient, uint64 nonce, uint64 expiry)
        external
        returns (bytes32 requestId)
    {
        DataReference storage dataRef = dataReferences[dataId];
        if (dataRef.status != DataStatus.Available) revert NotFound();
        if (msg.sender != dataRef.owner) revert Unauthorized();
        if (recipient == bytes32(0) || expiry <= block.timestamp) revert InvalidArgument();
        requestId = keccak256(
            abi.encode(
                "PPSC_PICK_V1",
                block.chainid,
                address(this),
                dataId,
                msg.sender,
                recipient,
                nonce,
                expiry
            )
        );
        if (pickRequestExists[requestId]) revert NonceAlreadyUsed();
        pickRequestExists[requestId] = true;
        emit PickRequested(requestId, dataId, msg.sender, recipient, nonce, expiry);
    }

    function executionStatus(bytes32 executionId) external view returns (ExecutionStatus) {
        return executions[executionId].status;
    }

    function executionCommittee(bytes32 executionId) external view returns (bytes32) {
        return executions[executionId].currentCommitteeId;
    }

    function contractStateRoot(bytes32 contractId) external view returns (bytes32) {
        return contracts[contractId].stateRoot;
    }

    function dataStatus(bytes32 dataId) external view returns (DataStatus) {
        return dataReferences[dataId].status;
    }

    function dataVersion(bytes32 dataId) external view returns (uint64) {
        return dataReferences[dataId].version;
    }

    function dataRepresentation(bytes32 dataId) external view returns (Representation) {
        if (dataReferences[dataId].status == DataStatus.None) revert NotFound();
        return dataReferences[dataId].representation;
    }

    function executionOutput(bytes32 executionId) external view returns (bytes32) {
        return executions[executionId].outputId;
    }

    function executionContract(bytes32 executionId) external view returns (bytes32) {
        return executions[executionId].contractId;
    }

    function stateVariableReference(bytes32 variableAddress)
        external
        view
        returns (StateVariable memory)
    {
        StateVariable memory variableRef = stateVariables[variableAddress];
        if (!variableRef.exists) revert NotFound();
        return variableRef;
    }

    function _verifyThreshold(bytes32 committeeId, bytes32 digest, bytes[] calldata signatures)
        private
        view
    {
        Committee storage committee = committees[committeeId];
        if (!committee.active || signatures.length < committee.threshold) {
            revert InvalidThreshold();
        }
        address previous;
        for (uint256 i; i < signatures.length; ++i) {
            address signer = _recover(digest, signatures[i]);
            if (signer <= previous || !isCommitteeMember[committeeId][signer]) {
                revert InvalidSignature();
            }
            previous = signer;
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
        // EIP-2 lower-half-order check prevents signature malleability.
        if (
            uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
                || (v != 27 && v != 28)
        ) revert InvalidSignature();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
        return signer;
    }

    function _functionId(bytes32 contractId, bytes4 selector) private pure returns (bytes32) {
        return keccak256(abi.encode(contractId, selector));
    }

    function _validateAndHashNodes(address[] calldata nodes) private pure returns (bytes32) {
        if (nodes.length == 0) revert InvalidArgument();
        address previous;
        for (uint256 i; i < nodes.length; ++i) {
            if (nodes[i] == address(0) || nodes[i] <= previous) revert InvalidArgument();
            previous = nodes[i];
        }
        return keccak256(abi.encode(nodes));
    }

    function _replaceDataStorageNodes(bytes32 dataId, address[] calldata nodes) private {
        delete _dataStorageNodes[dataId];
        for (uint256 i; i < nodes.length; ++i) {
            _dataStorageNodes[dataId].push(nodes[i]);
        }
    }

    function _ethSigned(bytes32 payload) private pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payload));
    }
}
