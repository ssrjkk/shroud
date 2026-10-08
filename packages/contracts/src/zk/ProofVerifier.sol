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

    /// @dev Delay a verifier rotation must sit in the queue before it can be executed. Seven days
    ///      matches `NetworkParams`' rotation timelock so both halves of the protocol's trust
    ///      surface move on the same schedule.
    uint256 public constant ROTATION_TIMELOCK = 7 days;

    address public pendingVerifier;
    uint64 public pendingVerifierAt;

    bool public paused;

    event ProofVerified(bytes32 indexed transcriptHash, uint32 indexed epoch, bool ok);
    event VerifierRotated(address indexed from, address indexed to);
    event VerifierRotationProposed(address indexed from, address indexed to, uint64 executableAt);
    event VerifierRotationCancelled(address indexed verifier);
    event PausedChanged(bool paused);

    error NotOwner(address caller);
    error ZeroAddress();
    error NoPendingRotation();
    error TooEarly(uint64 executableAt);

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
/// @dev Behind a mandatory timelock, because this contract gates every payout in the protocol: a
///      verifier that accepts anything is a verifier that pays fraudsters. This used to be a
///      single-call `onlyOwner` swap, so a compromised owner key could install a permissive
///      verifier in one transaction with no window for anyone to notice. The window is the
///      mitigation, and it has to be enforced on-chain to be worth anything — an off-chain
///      promise in a runbook is not. `NetworkParams` already does this for key rotation; the two
///      should not have had different strength.
function proposeRotation(address to) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        pendingVerifier = to;
        pendingVerifierAt = uint64(block.timestamp + ROTATION_TIMELOCK);
        emit VerifierRotationProposed(starkVerifier, to, pendingVerifierAt);
    }

    /// @notice Cancel a queued rotation. Owner-only: the owner must be able to stop a rotation it
    ///         no longer wants, including one queued by a compromised key before the timelock
    ///         elapses. This is the owner's only lever once a rotation is queued.
    function cancelRotation() external onlyOwner {
        if (pendingVerifier == address(0)) revert NoPendingRotation();
        emit VerifierRotationCancelled(pendingVerifier);
        pendingVerifier = address(0);
        pendingVerifierAt = 0;
    }

    /// @notice Install the queued verifier once its timelock has elapsed.
    /// @dev Permissionless on purpose. If only the owner could execute, then "the owner is
    ///      compromised" would also mean "the rotation can be frozen forever" — the owner could
    ///      simply never call this. Letting anyone execute means a queued rotation either happens
    ///      at or after the announced time or gets cancelled, and an observer can rely on that.
    function executeRotation() external {
        if (pendingVerifier == address(0)) revert NoPendingRotation();
        if (block.timestamp < pendingVerifierAt) revert TooEarly(pendingVerifierAt);
        address from = starkVerifier;
        address to = pendingVerifier;
        pendingVerifier = address(0);
        pendingVerifierAt = 0;
        starkVerifier = to;
        emit VerifierRotated(from, to);
    }

    /// @notice The rotation queued for execution, if any.
    function pendingRotation() external view returns (address verifier, uint64 executableAt) {
        return (pendingVerifier, pendingVerifierAt);
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
