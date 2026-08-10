// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import { ISortitionVerifier } from "./interfaces/ISortitionVerifier.sol";

/// @notice Testnet verifier. A configured authority attests the externally computed sortition.
/// @dev Replace this contract with a VRF/random-beacon verifier before production use.
contract EcdsaSortitionVerifier is ISortitionVerifier {
    error InvalidAuthority();

    address public immutable authority;

    constructor(address authority_) {
        if (authority_ == address(0)) revert InvalidAuthority();
        authority = authority_;
    }

    function selectionDigest(
        bytes32 seed,
        uint64 epoch,
        bytes32 committeeId,
        address[] calldata members
    ) public view returns (bytes32) {
        bytes32 payload = keccak256(
            abi.encode(
                "PPSC_SORTITION_V1",
                block.chainid,
                address(this),
                seed,
                epoch,
                committeeId,
                keccak256(abi.encode(members))
            )
        );
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payload));
    }

    function verifySelection(
        bytes32 seed,
        uint64 epoch,
        bytes32 committeeId,
        address[] calldata members,
        bytes calldata evidence
    ) external view returns (bool) {
        if (evidence.length != 65) return false;
        bytes32 digest = selectionDigest(seed, epoch, committeeId, members);
        (bytes32 r, bytes32 s, uint8 v) = _split(evidence);
        return ecrecover(digest, v, r, s) == authority;
    }

    function _split(bytes calldata signature) private pure returns (bytes32 r, bytes32 s, uint8 v) {
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
    }
}

