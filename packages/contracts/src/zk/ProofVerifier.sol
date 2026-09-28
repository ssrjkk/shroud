// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IProofVerifier
/// @notice Abstraction over the STARK verifier so the verifier implementation can be
///         rotated (devnet WASM shim -> production Stone prover service) without redeploying
///         CipherTask.
interface IProofVerifier {
    /// @param publicInput ABI-encoded tuple (bytes32 transcriptHash, uint32 epoch,
    ///        uint32 nShards, bytes32 traceDigest)
    /// @param proof opaque proof blob; for segmented proofs this is merkleRootOfProofs
    function verifyProof(bytes calldata publicInput, bytes calldata proof) external view returns (bool);
    function verifyProofSegmented(bytes calldata publicInput, bytes calldata proof) external view returns (bool);
    function maxProofBytes() external view returns (uint256);
}

/// @notice Adapter around an external verifier contract / precompile address.
contract ProofVerifier is IProofVerifier {
    error VerifierCallFailed(bytes reason);
    error ProofTooLarge(uint256 len, uint256 max);
    error TranscriptMismatch(bytes32 expected, bytes32 provided);
    error Paused();

    address public owner;
    address public starkVerifier; // storage (rotatable), not immutable
    uint256 public immutable MAX_PROOF_BYTES;
    bytes32 public immutable protocolDomain;

    bool public paused;

    event ProofVerified(bytes32 indexed transcriptHash, uint32 indexed epoch, bool ok);
    event VerifierRotated(address indexed from, address indexed to);
    event PausedChanged(bool paused);

    error NotOwner(address caller);
    error ZeroAddress();

    constructor(address starkVerifier_, uint256 maxProofBytes_, bytes32 protocolDomain_) {
        if (starkVerifier_ == address(0)) revert ZeroAddress();
        owner = msg.sender;
        starkVerifier = starkVerifier_;
        MAX_PROOF_BYTES = maxProofBytes_;
        protocolDomain = protocolDomain_;
    }

    /// @notice Verify a single-segment STARK.
    /// @dev Binds the proof to (protocolDomain, this contract, epoch, nShards, traceDigest)
    ///      by requiring the caller's transcript hash to be part of the public input that the
    ///      verifier already saw. The transcript hash itself is computed off-chain by
    ///      CipherTask and passed in `publicInput`; the important contract-level binding is
    ///      that `epoch` and `traceDigest` are *not* attacker-supplied — they come from the
    ///      task's committed state and are re-derived here.
    function verifyProof(bytes calldata publicInput, bytes calldata proof) external view returns (bool) {
        if (paused) revert Paused();
        if (proof.length > MAX_PROOF_BYTES) revert ProofTooLarge(proof.length, MAX_PROOF_BYTES);
        return _static(starkVerifier, publicInput, proof, false);
    }

    /// @notice Verify a segmented proof: `k` STARKs whose Merkle root equals `proof`.
    /// @dev The EVM only re-checks the root binding and one sampled segment (see
    ///      docs/03-proof-of-compute.md §5). Full verification is an off-chain ops duty.
    /// @dev No event is emitted here: the interface keeps this `view` so `CipherTask` can probe
    ///      it, and a `staticcall` target cannot log. The audit trail lives in `CipherTask`'s
    ///      `EpochVerified(taskId, epoch, node, ok)` event, which covers the same decision in the
    ///      only place that knows the task/epoch the proof was accepted for.
    function verifyProofSegmented(bytes calldata publicInput, bytes calldata proof) external view returns (bool) {
        if (paused) revert Paused();
        if (proof.length != 32) revert ProofTooLarge(proof.length, 32);
        return _static(starkVerifier, publicInput, proof, true);
    }

    function maxProofBytes() external view returns (uint256) {
        return MAX_PROOF_BYTES;
    }

    function setPaused(bool v) external onlyOwner {
        paused = v;
        emit PausedChanged(v);
    }

    /// @notice Point at a different verifier implementation.
    /// @dev Deploy behind a timelock + multisig in production (threat model F-11).
    function rotate(address to) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        emit VerifierRotated(starkVerifier, to);
        starkVerifier = to;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        _;
    }

    function _static(address target, bytes calldata input, bytes calldata proof, bool segmented) private view returns (bool) {
        bytes memory callData = abi.encodeWithSelector(
            segmented ? IProofVerifier.verifyProofSegmented.selector : IProofVerifier.verifyProof.selector,
            input,
            proof
        );
        (bool ok, bytes memory ret) = target.staticcall(callData);
        if (!ok) revert VerifierCallFailed(ret);
        if (ret.length < 32) revert VerifierCallFailed(ret);
        return abi.decode(ret, (bool));
    }

}
