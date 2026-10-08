// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "./libraries/Guard.sol";

/// @title NetworkParams
/// @notice Publishes the network-wide parameters that every participant must agree on, and
///         pins them on chain so a key-swap attack is detectable (threat model A7/F-08).
///
/// @dev The pin is the whole point. A malicious sequencer could publish a different FHE public
///      key, encrypt its own probe rows under it, and learn everything submitted after the
///      swap. With `fhePublicKeyHash` pinned, the SDK refuses mismatched params, compute
///      nodes refuse to start, and a swap becomes an availability failure instead of a
///      confidentiality failure. That is the difference we are buying, and it is why the
///      rotation path is timelocked and multi-sig.
contract NetworkParams is ReentrancyGuard {
    struct Params {
        uint64 chainId;
        uint64 keyVersion;
        bytes32 fhePublicKeyHash; // keccak256(abi.encode(s_pub))
        bytes32 committeeAggregateKey; // BLS G2 aggregate
        uint16 committeeThreshold; // t of n
        uint16 committeeSize; // n
        uint32 maxProofBytes;
        uint32 maxCiphertextBytes;
        uint32 maxFeatures;
        uint64 activatedAt;
        bool active;
    }

    struct Rotation {
        uint64 scheduledAt; // when the new params become active
        bytes32 expectedHash; // hash the incoming rotation must match
        address proposer;
        address approver;
        bool executed;
        bool cancelled;
    }

    bytes32 public constant NETWORK_TYPEHASH =
        keccak256("Params(uint64 keyVersion,bytes32 fhePublicKeyHash,bytes32 committeeAggregateKey,uint16 committeeThreshold,uint16 committeeSize,uint32 maxProofBytes,uint32 maxCiphertextBytes,uint32 maxFeatures)");

    address public owner;
    address public pendingOwner;
    address public approver;

    Params public current;
    Rotation public pending;

    error NotOwner(address caller);
    error NotApprover(address caller);
    error NoPendingRotation();
    error RotationCancelled();
    error RotationAlreadyExecuted();
    error HashMismatch(bytes32 expected, bytes32 provided);
    error TooEarly(uint64 scheduledAt);
    error InvalidParams(string reason);
    error ZeroAddress();

    event Initialized(Params params);
    event RotationProposed(bytes32 expectedHash, uint64 scheduledAt, address indexed proposer, Params candidate);
    event RotationApproved(address indexed approver, bytes32 expectedHash);
    event RotationCancelledEvent(uint64 indexed scheduledAt);
    event RotationExecuted(uint64 keyVersion, bytes32 fhePublicKeyHash);
    event OwnershipTransferStarted(address indexed from, address indexed to);
    event OwnershipTransferred(address indexed from, address indexed to);
    event ApproverChanged(address indexed from, address indexed to);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        _;
    }

    modifier onlyApprover() {
        if (msg.sender != approver) revert NotApprover(msg.sender);
        _;
    }

    constructor(address approver_) {
        if (approver_ == address(0)) revert ZeroAddress();
        owner = msg.sender;
        approver = approver_;
        emit OwnershipTransferred(address(0), msg.sender);
        emit ApproverChanged(address(0), approver_);
    }

    /// @notice One-shot initialisation. Retrying with different values is deliberately blocked:
    ///         a mutable genesis would let an attacker negotiate a key they control.
    function initialize(Params calldata p) external onlyOwner {
        if (current.active) revert InvalidParams("already initialized");
        if (p.keyVersion != 1) revert InvalidParams("genesis keyVersion must be 1");
        if (p.fhePublicKeyHash == bytes32(0)) revert InvalidParams("fhePublicKeyHash");
        if (p.committeeThreshold == 0 || p.committeeThreshold > p.committeeSize) revert InvalidParams("threshold");
        if (p.committeeSize < 3) revert InvalidParams("committeeSize");
        if (p.maxProofBytes < 1_024 || p.maxProofBytes > 131_072) revert InvalidParams("maxProofBytes");
        if (p.maxFeatures == 0) revert InvalidParams("maxFeatures");

        current = Params({
            chainId: uint64(block.chainid),
            keyVersion: p.keyVersion,
            fhePublicKeyHash: p.fhePublicKeyHash,
            committeeAggregateKey: p.committeeAggregateKey,
            committeeThreshold: p.committeeThreshold,
            committeeSize: p.committeeSize,
            maxProofBytes: p.maxProofBytes,
            maxCiphertextBytes: p.maxCiphertextBytes,
            maxFeatures: p.maxFeatures,
            activatedAt: uint64(block.timestamp),
            active: true
        });
        emit Initialized(current);
    }

    /// @notice Shared validation for a rotating parameter set.
    /// @dev Applied at *both* ends of the rotation, not just when proposing. `proposeRotation`
    ///      used to validate its `candidate` argument and then throw it away, storing only the
    ///      caller-supplied `expectedHash` — which was never checked against `candidate`. The
    ///      struct that actually reaches `current` is the one handed to `approveRotation` and
    ///      `executeRotation`, and that one was never validated at all. So a rotation could install
    ///      `committeeThreshold = 0`, `committeeSize = 0`, `maxProofBytes = 0`, or a `keyVersion`
    ///      that does not increment — the last being precisely the invariant that exists to stop a
    ///      replayed or reordered key from being mistaken for a new one.
    function _validateCandidate(Params memory c) private view {
        if (c.keyVersion != current.keyVersion + 1) revert InvalidParams("keyVersion must increment by 1");
        if (c.fhePublicKeyHash == current.fhePublicKeyHash) revert InvalidParams("hash unchanged");
        if (c.fhePublicKeyHash == bytes32(0)) revert InvalidParams("fhePublicKeyHash");
        if (c.committeeThreshold == 0 || c.committeeThreshold > c.committeeSize) {
            revert InvalidParams("threshold");
        }
        if (c.committeeSize < 3) revert InvalidParams("committeeSize");
        if (c.maxProofBytes < 1_024 || c.maxProofBytes > 131_072) revert InvalidParams("maxProofBytes");
        if (c.maxCiphertextBytes == 0) revert InvalidParams("maxCiphertextBytes");
        if (c.maxFeatures == 0) revert InvalidParams("maxFeatures");
    }

    /// @notice Propose the next parameter set, effective after `timelock`.
    /// @dev `expectedHash` must be `keccak256(abi.encode(candidate, chainId, approver))`. Requiring
    ///      that here — rather than only checking the hash at approval time — is what makes the
    ///      struct that was *validated* provably the same struct that will be *installed*. The
    ///      approver is already known (`approver` is state, not chosen per-rotation), so this
    ///      costs the proposer nothing and removes the possibility of proposing a valid-looking
    ///      candidate while actually queueing a different one for the approver to sign.
    function proposeRotation(Params calldata candidate, bytes32 expectedHash, uint64 timelock) external onlyOwner returns (uint64 scheduledAt) {
        if (!current.active) revert InvalidParams("not initialized");
        if (pending.scheduledAt != 0 && !pending.executed && !pending.cancelled) revert NoPendingRotation();
        _validateCandidate(candidate);
        if (timelock < 7 days) revert InvalidParams("timelock too short");
        bytes32 h = keccak256(abi.encode(candidate, block.chainid, approver));
        if (h != expectedHash) revert HashMismatch(expectedHash, h);

        scheduledAt = uint64(block.timestamp) + timelock;
        pending = Rotation({
            scheduledAt: scheduledAt,
            expectedHash: expectedHash,
            proposer: msg.sender,
            approver: address(0),
            executed: false,
            cancelled: false
        });
        emit RotationProposed(expectedHash, scheduledAt, msg.sender, candidate);
    }

    function approveRotation(Params calldata candidate) external onlyApprover {
        if (pending.scheduledAt == 0 || pending.executed) revert NoPendingRotation();
        if (pending.cancelled) revert RotationCancelled();
        if (candidate.chainId != block.chainid) revert InvalidParams("chainId mismatch");
        bytes32 h = keccak256(abi.encode(candidate, block.chainid, msg.sender));
        if (h != pending.expectedHash) revert HashMismatch(pending.expectedHash, h);
        pending.approver = msg.sender;
        emit RotationApproved(msg.sender, pending.expectedHash);
    }

    function cancelRotation() external onlyOwner {
        if (pending.scheduledAt == 0) revert NoPendingRotation();
        pending.cancelled = true;
        pending.scheduledAt = 0;
        emit RotationCancelledEvent(uint64(block.timestamp));
    }

    /// @notice Execute an approved rotation whose timelock has elapsed.
    function executeRotation(Params calldata candidate) external nonReentrant {
        if (pending.scheduledAt == 0) revert NoPendingRotation();
        if (pending.executed) revert RotationAlreadyExecuted();
        if (pending.cancelled) revert RotationCancelled();
        if (block.timestamp < pending.scheduledAt) revert TooEarly(pending.scheduledAt);
        if (pending.approver == address(0)) revert NotApprover(pending.approver);
        if (candidate.chainId != block.chainid) revert InvalidParams("chainId mismatch");

        bytes32 h = keccak256(abi.encode(candidate, block.chainid, pending.approver));
        if (h != pending.expectedHash) revert HashMismatch(pending.expectedHash, h);
        // Re-validated here even though `proposeRotation` already did it, so that no future change
        // to the proposal path can weaken what reaches `current`. Clients pin these values to decide
        // whether a submission is acceptable, so an invalid set installed here would be trusted.
        _validateCandidate(candidate);

        current.keyVersion = candidate.keyVersion;
        current.fhePublicKeyHash = candidate.fhePublicKeyHash;
        current.committeeAggregateKey = candidate.committeeAggregateKey;
        current.committeeThreshold = candidate.committeeThreshold;
        current.committeeSize = candidate.committeeSize;
        current.maxProofBytes = candidate.maxProofBytes;
        current.maxCiphertextBytes = candidate.maxCiphertextBytes;
        current.maxFeatures = candidate.maxFeatures;
        current.activatedAt = uint64(block.timestamp);

        pending = Rotation(0, bytes32(0), address(0), address(0), false, false);
        emit RotationExecuted(current.keyVersion, current.fhePublicKeyHash);
    }

    function transferOwnership(address to) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        emit OwnershipTransferStarted(owner, to);
        pendingOwner = to;
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotOwner(msg.sender);
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    function setApprover(address to) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        emit ApproverChanged(approver, to);
        approver = to;
    }

    /* ------------------------------------------------------------------ */
    /*                                views                                */
    /* ------------------------------------------------------------------ */

    function isCurrentKey(bytes32 sPubHash) external view returns (bool) {
        return current.active && current.fhePublicKeyHash == sPubHash;
    }

    function rotationPending() external view returns (bool) {
        return pending.scheduledAt != 0 && !pending.executed && !pending.cancelled;
    }
}
