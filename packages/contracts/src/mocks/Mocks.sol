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

    address public owner;

    mapping(bytes32 => bool) public consumed;
    uint256 public verifiedCount;
    uint256 public rejectedCount;

    error NotMagic(bytes4 got);
    error Replayed(bytes32 transcript);

    constructor(uint256 maxProofBytes_) {
        owner = msg.sender;
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
/// @dev Owner-only. `deploy.ts` installs this contract as the devnet's *real* `ProofVerifier`, so
    ///      an unrestricted `consume` was not a test-only sloppiness: any address could mark a
    ///      transcript spent and permanently invalidate the honest node's proof for that
    ///      (task, epoch) pair, since `consumed` is keyed on the transcript and never cleared.
    function consume(bytes32 transcript) external onlyOwner {
        if (consumed[transcript]) revert Replayed(transcript);
        consumed[transcript] = true;
        verifiedCount++;
    }

    function fail(bytes32 transcript) external onlyOwner {
        rejectedCount++;
        transcript;
    }

    error NotOwner(address caller);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        _;
    }
}

/// @notice Reentrancy probe: an ERC-20 whose `transferFrom` calls back into an arbitrary target
///         once, in the middle of the victim's token transfer.
///
///         This is the only honest way to test a reentrancy guard, because the callback has to
///         land *inside* the victim's function body while its flag is set. Probing from the
///         outside only proves the guard was clear before and after the call, which is the
///         trivial half. `PaymentVault.fundTask` is the chosen victim: it is `nonReentrant` and
///         pulls tokens, so `transferFrom` is the exact point a real attacker's token would fire.
contract ReentrantTokenMock {
    address public reentryTarget;
    bytes public reentry;
    bool public tried;
    bytes public lastRevert;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    error ReentrancyStillPossible();

    function mint(address to, uint256 v) external {
        totalSupply += v;
        balanceOf[to] += v;
    }

    /// @param reentry_ calldata to fire at `target_` during the first `transferFrom`; empty to
    ///        disable the callback. Both are settable afterwards because a vault under test has to
    ///        be deployed *after* the token it pulls, so the token cannot know its address in the
    ///        constructor.
    constructor(address target_, bytes memory reentry_) {
        reentryTarget = target_;
        reentry = reentry_;
    }

    function setTarget(address target_) external {
        reentryTarget = target_;
    }

    function setReentry(bytes calldata reentry_) external {
        reentry = reentry_;
    }

    function approve(address spender, uint256 v) external returns (bool) {
        allowance[msg.sender][spender] = v;
        return true;
    }

    function transfer(address to, uint256 v) external returns (bool) {
        balanceOf[msg.sender] -= v;
        balanceOf[to] += v;
        return true;
    }

    function transferFrom(address from, address to, uint256 v) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        if (a != type(uint256).max) allowance[from][msg.sender] = a - v;
        balanceOf[from] -= v;
        balanceOf[to] += v;

        if (!tried) {
            tried = true;
            bytes memory cd = reentry;
            if (cd.length > 0) {
                (bool ok, bytes memory ret) = reentryTarget.call(cd);
                if (!ok) lastRevert = ret;
            }
        }
        return true;
    }
}

/// @notice BLS verifier stand-in. Accepts a signature whose first 32 bytes equal a hash the
///         test registered as "signed by the committee".
/// @dev `approve` is owner-only for the same reason `MockStarkVerifier.consume` is: `deploy.ts`
///      installs this as the devnet's real `IBLS`, and an unrestricted `approve` would let any
///      address forge the committee's aggregate signature and open a reveal for a task it has no
///      business touching — defeating the entire point of the threshold gate.
contract MockBLS is IBLS {
    mapping(bytes32 => bool) public approvedMessages;
    uint256 public verifyCount;

    address public owner;

    error NotOwner(address caller);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        _;
    }

    function approve(bytes32 message) external onlyOwner {
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
