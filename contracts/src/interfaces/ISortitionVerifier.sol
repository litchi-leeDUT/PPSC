// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

interface ISortitionVerifier {
    function verifySelection(
        bytes32 seed,
        uint64 epoch,
        bytes32 committeeId,
        address[] calldata members,
        bytes calldata evidence
    ) external view returns (bool);
}

