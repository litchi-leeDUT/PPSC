// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import { PpscControlPlane } from "../PpscControlPlane.sol";

/// @notice User-facing application for ControlPlane-owned confidential variables.
contract PrivateBalanceApp {
    error Unauthorized();

    bytes4 public constant PRIVATE_TRANSFER_SELECTOR =
        bytes4(keccak256("conditionalTransfer(bytes32,bytes32,bytes32,bytes32)"));

    PpscControlPlane public immutable controlPlane;
    address public immutable owner;
    bytes32 public immutable confidentialContractId;

    event ConditionalTransferRequested(
        bytes32 indexed executionId,
        address indexed sender,
        address indexed receiver,
        bytes32 senderBalanceVariable,
        bytes32 receiverBalanceVariable
    );
    event BalanceOpeningRequested(
        bytes32 indexed requestId,
        address indexed account,
        bytes32 indexed balanceVariable,
        bytes32 recipientEncryptionKey
    );

    constructor(
        PpscControlPlane controlPlane_,
        address owner_,
        bytes32 deploymentSalt,
        bytes32 manifestHash,
        bytes32 runtimeHash,
        bytes32 initialPrivateStateRoot
    ) {
        if (address(controlPlane_) == address(0) || owner_ == address(0)) {
            revert Unauthorized();
        }
        controlPlane = controlPlane_;
        owner = owner_;
        confidentialContractId = controlPlane_.publishContract(
            deploymentSalt, manifestHash, runtimeHash, initialPrivateStateRoot
        );
        // The fixed application program is registered atomically at deployment.
        controlPlane_.publishFunction(
            confidentialContractId,
            PRIVATE_TRANSFER_SELECTOR,
            keccak256("conditional-private-transfer-program-v2"),
            keccak256("C2S->MPC(gt,conditional_sub_add)->S2C"),
            keccak256("conditionalTransfer(bytes32,bytes32,bytes32,bytes32)"),
            "ipfs://ppsc/conditional-private-transfer-v2",
            250_000
        );
    }

    function privateTransferPublished() external pure returns (bool) {
        return true;
    }

    function balanceVariable(address account) public view returns (bytes32) {
        return keccak256(abi.encode("PPSC_BALANCE_VARIABLE_V1", confidentialContractId, account));
    }

    function minimumBalanceVariable() public view returns (bytes32) {
        return keccak256(abi.encode("PPSC_MINIMUM_BALANCE_VARIABLE_V1", confidentialContractId));
    }

    function transferAmountVariable() public view returns (bytes32) {
        return keccak256(abi.encode("PPSC_TRANSFER_AMOUNT_VARIABLE_V1", confidentialContractId));
    }

    function balanceReference(address account)
        external
        view
        returns (PpscControlPlane.StateVariable memory)
    {
        return controlPlane.stateVariableReference(balanceVariable(account));
    }

    /// @notice Users provide an account, not arbitrary variable/data addresses.
    /// The application resolves ControlPlane-owned current bindings.
    function conditionalTransfer(address receiver, uint64 nonce, uint64 deadline)
        external
        returns (bytes32 executionId)
    {
        if (msg.sender != owner || receiver == address(0)) revert Unauthorized();
        bytes32 senderVariable = balanceVariable(msg.sender);
        bytes32 receiverVariable = balanceVariable(receiver);
        PpscControlPlane.StateVariable memory sender =
            controlPlane.stateVariableReference(senderVariable);
        PpscControlPlane.StateVariable memory receiverBalance =
            controlPlane.stateVariableReference(receiverVariable);
        PpscControlPlane.StateVariable memory minimum =
            controlPlane.stateVariableReference(minimumBalanceVariable());
        PpscControlPlane.StateVariable memory amount =
            controlPlane.stateVariableReference(transferAmountVariable());
        bytes32[] memory inputs = new bytes32[](4);
        inputs[0] = sender.dataId;
        inputs[1] = receiverBalance.dataId;
        inputs[2] = minimum.dataId;
        inputs[3] = amount.dataId;
        executionId = controlPlane.invokeFor(
            confidentialContractId, PRIVATE_TRANSFER_SELECTOR, inputs, msg.sender, nonce, deadline
        );
        emit ConditionalTransferRequested(
            executionId, msg.sender, receiver, senderVariable, receiverVariable
        );
    }

    /// @notice Emits an authorized request. Runtime returns an encrypted opening
    /// for the current dataId/slot/version to `recipientEncryptionKey`.
    function requestMyBalance(bytes32 recipientEncryptionKey, uint64 nonce, uint64 expiry)
        external
        returns (bytes32 requestId)
    {
        if (msg.sender != owner) revert Unauthorized();
        bytes32 variableAddress = balanceVariable(msg.sender);
        requestId = controlPlane.requestVariablePickFor(
            variableAddress, msg.sender, recipientEncryptionKey, nonce, expiry
        );
        emit BalanceOpeningRequested(requestId, msg.sender, variableAddress, recipientEncryptionKey);
    }

    function privateStateRoot() external view returns (bytes32) {
        return controlPlane.contractStateRoot(confidentialContractId);
    }
}
