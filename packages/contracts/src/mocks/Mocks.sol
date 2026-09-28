// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IProofVerifier} from "../zk/ProofVerifier.sol";
import {IBLS} from "../interfaces/IDecryptionGate.sol";

/// @notice Deterministic STARK verifier stand-in for local devnet and unit tests.
/// @dev The real verifier is a Winterfell-wasm / Stone-prover service addressed in
///      `NetworkParams`. This mock accepts any proof that starts with the magic prefix, so
///      the orchestration logic (escrow, epochs, disputes, channels, settlement) can be
///      tested end to end without a proving system in the loop. Integration tests that
///      exercise the real AIR live in `test/ProofVerifier.spec.ts` and must run against a
///      deployed verifier.
contract MockStarkVerifier is IProofVerifier {
    bytes4 internal constant MAGIC = 0x53544152; // "STAR"
    uint256 public immutable maxProofBytes;

    mapping(bytes32 => bool) public consumed;
    uint256 public verifiedCount;
    uint256 public rejectedCount;

    error NotMagic(bytes4 got);
    error Replayed(bytes32 transcript);

    constructor(uint256 maxProofBytes_) {
        maxProofBytes = maxProofBytes_;
    }

    function verifyProof(bytes calldata publicInput, bytes calldata proof) external view returns (bool) {
        if (proof.length < 4 || bytes4(proof[0:4]) != MAGIC) return false;
        return !consumed[transcriptOf(publicInput)];
    }

    /// @notice Segmented proof: the payload is a 32-byte Merkle root over the per-segment STARKs.
    /// @dev The real verifier re-checks the root binding plus one sampled segment; the mock can
    ///      only check the shape, so it additionally requires the root to be non-zero to keep the
    ///      "empty proof" case from silently passing.
    function verifyProofSegmented(bytes calldata publicInput, bytes calldata proof) external view returns (bool) {
        if (proof.length != 32) return false;
        if (bytes32(proof) == bytes32(0)) return false;
        return !consumed[transcriptOf(publicInput)];
    }

    /// @notice Replay protection is keyed on the transcript hash, which `CipherTask` puts in
    ///         word 0 of the public input. Keying on `keccak256(publicInput)` instead would make
    ///         `consume(transcript)` unable to ever mark anything consumed, silently disabling the
    ///         replay test.
    function transcriptOf(bytes calldata publicInput) public pure returns (bytes32) {
        if (publicInput.length < 32) return bytes32(0);
        bytes32 w;
        assembly {
            w := calldataload(publicInput.offset)
        }
        return w;
    }

    /// @notice Mark a transcript as used. Kept separate from the `view` verify so the mock
    ///         honours the replay-protection semantics the real verifier has internally.
    function consume(bytes32 transcript) external {
        if (consumed[transcript]) revert Replayed(transcript);
        consumed[transcript] = true;
        verifiedCount++;
    }

    function fail(bytes32 transcript) external {
        rejectedCount++;
        transcript;
    }
}

/// @notice BLS verifier stand-in. Accepts a signature whose first 32 bytes equal a hash the
///         test registered as "signed by the committee".
contract MockBLS is IBLS {
    mapping(bytes32 => bool) public approvedMessages;
    uint256 public verifyCount;

    function approve(bytes32 message) external {
        approvedMessages[message] = true;
    }

    function verifyAggregate(bytes32 message, bytes calldata, bytes calldata) external view returns (bool) {
        return approvedMessages[message];
    }

    function verify(bytes32 message) external returns (bool) {
        verifyCount++;
        return approvedMessages[message];
    }
}
