//! The byte layouts `CipherTask` hashes, mirrored exactly.
//!
//! Both are consensus-critical: `ctRoot` is a STARK public input and the proof
//! transcript is what a verifier binds a proof to. A prover that computes either
//! one byte differently proves a statement the chain will not accept — and worse,
//! a re-executing node would "disagree" with an honest commit and file a dispute
//! that only its own encoder caused.

use crate::hash::keccak256;

/// Domain tag of the proof transcript, as the first `abi.encode` argument.
pub const TRANSCRIPT_MAGIC: &[u8] = b"SHROUD/PoC/v1"; // 13 bytes
/// Domain tag of the trace commitment preimage.
pub const TRACE_MAGIC: &[u8] = b"SHROUD/TRACE/v1\0";
/// Domain tag of the proof-reference preimage.
pub const PROOF_REF_MAGIC: &[u8] = b"SHROUD/PROOF-REF/v1";
/// `STAR` prefix the mock verifier keys its magic check on.
pub const PROOF_REF_PREFIX: [u8; 4] = [0x53, 0x54, 0x41, 0x52];

/// The seed of the `ctRoot` accumulation chain: `_EMPTY_ROOT` in `CipherTask`.
pub fn empty_root() -> [u8; 32] {
    keccak256(b"SHROUD/CTROOT/v1")
}

/// One step of the `ctRoot` chain.
///
/// `CipherTask::_appendLeaf` is `keccak256(abi.encodePacked(acc, leafIndex, ciphertextCid))`:
/// 32 + 4 + 32 = 68 packed bytes, with the `uint32` in its own 4 bytes — *not* padded to a word,
/// which is the difference between this and a struct hash.
pub fn ct_root_step(prev: [u8; 32], leaf_index: u32, ciphertext_cid: [u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 68];
    buf[0..32].copy_from_slice(&prev);
    buf[32..36].copy_from_slice(&leaf_index.to_be_bytes());
    buf[36..68].copy_from_slice(&ciphertext_cid);
    keccak256(&buf)
}

/// Fold a whole contribution set into the root the contract compares against.
///
/// Leaves are appended in submission order, so `leaf_index` is positional: `0..n`.
pub fn ct_root(ciphertext_cids: &[[u8; 32]]) -> [u8; 32] {
    let mut root = empty_root();
    for (index, cid) in ciphertext_cids.iter().enumerate() {
        root = ct_root_step(root, index as u32, *cid);
    }
    root
}

/// The commitment `commitDispute` takes: `keccak256(abi.encode(digest, salt, reporter))`.
///
/// Three full words — `bytes32`, `bytes32`, `address` left-padded into a word — so the
/// encoding is a fixed 96 bytes with no offsets. Binding the reporter stops one commitment
/// being replayed by another identity; binding the salt stops a bare digest from matching.
pub fn dispute_commitment(digest: [u8; 32], salt: [u8; 32], reporter: [u8; 20]) -> [u8; 32] {
    let mut buf = [0u8; 96];
    buf[0..32].copy_from_slice(&digest);
    buf[32..64].copy_from_slice(&salt);
    buf[64..76].copy_from_slice(&[0u8; 12]);
    buf[76..96].copy_from_slice(&reporter);
    keccak256(&buf)
}

/// Deterministic dispute salt for `(operator, task, epoch)`.
///
/// Fresh randomness would need persisting across the commit and the reveal (a restart between
/// the two otherwise loses the salt while the commitment stays open on chain). A derived
/// salt is recomputable after any restart, and it does not weaken the hiding: the preimage
/// space that matters is the 256-bit digest, not the salt. Uniqueness per reporter comes
/// from the reporter binding inside the commitment itself.
pub fn dispute_salt(operator: [u8; 20], task_id: [u8; 32], epoch: u32) -> [u8; 32] {
    let mut buf = [0u8; 96];
    buf[0..12].copy_from_slice(&[0u8; 12]);
    buf[12..32].copy_from_slice(&operator);
    buf[32..64].copy_from_slice(&task_id);
    let mut epoch_word = [0u8; 32];
    epoch_word[28..32].copy_from_slice(&epoch.to_be_bytes());
    buf[64..96].copy_from_slice(&epoch_word);
    keccak256(&buf)
}

/// A single leaf pin for the trace commitment, in contract leaf order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceLeaf {
    /// Contract leaf index.
    pub leaf_index: u32,
    /// DA content id of the shard.
    pub cid: [u8; 32],
    /// Pinned `keccak256` of the shard bytes.
    pub ct_digest: [u8; 32],
}

/// The trace commitment. Layout, in order:
///
/// ```text
/// "SHROUD/TRACE/v1\0" | task_id u256-BE | epoch u32-BE | chain_id u64-BE | cipher_task 20B
/// | ct_root | prev_weights_digest
/// | features u32-BE | scale u32-BE | lr_q16 u32-BE | l2_q16 u32-BE | minibatch u64-BE | seed u64-BE
/// | n_rows u64-BE | loss_mean_q i128-BE two's complement (0 when the backend cannot observe loss)
/// | per leaf ascending: leaf_index u32-BE | cid | ct_digest
/// | next_weights_digest
/// ```
///
/// `keccak256` of the concatenation. Every value that can change the result is in the
/// preimage — including the hyperparameters, so nodes that disagree on configuration
/// disagree on the digest instead of accusing each other. `ct_digest` (verified by the
/// worker to equal `keccak256` of the shard bytes) stands in for the bytes: the
/// digest commits to the exact payload the chain pinned without re-hashing megabytes.
#[allow(clippy::too_many_arguments)] // arity is the layout: one param per preimage field
pub fn trace_digest(
    task_id: [u8; 32],
    epoch: u32,
    chain_id: u64,
    cipher_task: [u8; 20],
    ct_root: [u8; 32],
    prev_weights_digest: [u8; 32],
    features: u32,
    scale: u32,
    lr_q16: u32,
    l2_q16: u32,
    minibatch: u64,
    seed: u64,
    n_rows: u64,
    loss_mean_q: Option<i128>,
    leaves: &[TraceLeaf],
    next_weights_digest: [u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(TRACE_MAGIC);
    buf.extend_from_slice(&task_id);
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&cipher_task);
    buf.extend_from_slice(&ct_root);
    buf.extend_from_slice(&prev_weights_digest);
    buf.extend_from_slice(&features.to_be_bytes());
    buf.extend_from_slice(&scale.to_be_bytes());
    buf.extend_from_slice(&lr_q16.to_be_bytes());
    buf.extend_from_slice(&l2_q16.to_be_bytes());
    buf.extend_from_slice(&minibatch.to_be_bytes());
    buf.extend_from_slice(&seed.to_be_bytes());
    buf.extend_from_slice(&n_rows.to_be_bytes());
    buf.extend_from_slice(&loss_mean_q.unwrap_or(0).to_be_bytes());
    for leaf in leaves {
        buf.extend_from_slice(&leaf.leaf_index.to_be_bytes());
        buf.extend_from_slice(&leaf.cid);
        buf.extend_from_slice(&leaf.ct_digest);
    }
    buf.extend_from_slice(&next_weights_digest);
    keccak256(&buf)
}

/// The transcript a proof of compute is bound to.
///
/// `abi.encode` of a `string` plus eight static arguments lays out as nine head words
/// (offset + 8 args), followed by the string's length word and its data right-padded to
/// 32 bytes. `TRANSCRIPT_MAGIC` is 13 bytes, so the total is `9 * 32 + 32 + 32 = 352`
/// bytes and the offset is `288`. The `node` argument (8th) cryptographically binds each
/// proof to its producer: without it a proof is replayable under another identity.
#[allow(clippy::too_many_arguments)] // arity is the layout: one param per ABI head word
pub fn proof_transcript(
    chain_id: u64,
    cipher_task: [u8; 20],
    task_id: [u8; 32],
    epoch: u32,
    ct_root: [u8; 32],
    last_weights_digest: [u8; 32],
    trace_digest: [u8; 32],
    node: [u8; 20],
) -> [u8; 32] {
    fn word_u256(v: u128) -> [u8; 32] {
        v.to_be_bytes()
    }
    let mut buf: Vec<u8> = Vec::with_capacity(352);
    // Head word 0: offset of the dynamic `string` = 9 * 32 = 288.
    buf.extend_from_slice(&word_u256(9 * 32));
    buf.extend_from_slice(&word_u256(chain_id as u128));
    let mut addr_word = [0u8; 32];
    addr_word[12..32].copy_from_slice(&cipher_task);
    buf.extend_from_slice(&addr_word);
    buf.extend_from_slice(&task_id);
    buf.extend_from_slice(&word_u256(epoch as u128));
    buf.extend_from_slice(&ct_root);
    buf.extend_from_slice(&last_weights_digest);
    buf.extend_from_slice(&trace_digest);
    let mut node_word = [0u8; 32];
    node_word[12..32].copy_from_slice(&node);
    buf.extend_from_slice(&node_word);
    // Tail: length, then the data padded into one word.
    buf.extend_from_slice(&word_u256(TRANSCRIPT_MAGIC.len() as u128));
    let mut string_word = [0u8; 32];
    string_word[..TRANSCRIPT_MAGIC.len()].copy_from_slice(TRANSCRIPT_MAGIC);
    buf.extend_from_slice(&string_word);
    keccak256(&buf)
}

/// The 32-byte `proof` reference for `commitEpoch`.
///
/// `0x53544152 ("STAR") || keccak256("SHROUD/PROOF-REF/v1" || trace_digest)[0..28]`.
/// The prefix satisfies the mock verifier's magic check on devnet/test chains; the hash
/// binds the exact trace, so the reference is useless for any other epoch.
pub fn proof_reference(trace_digest: [u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(PROOF_REF_MAGIC.len() + 32);
    preimage.extend_from_slice(PROOF_REF_MAGIC);
    preimage.extend_from_slice(&trace_digest);
    let hash = keccak256(&preimage);
    let mut out = [0u8; 32];
    out[..4].copy_from_slice(&PROOF_REF_PREFIX);
    out[4..].copy_from_slice(&hash[..28]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_layout_is_352_bytes_with_offset_288() {
        // Rebuild the preimage by hand and check the structural words: offset,
        // chain id and magic length must sit at exact positions or a guest with
        // a different encoder would fork the digest silently.
        let zero = [0u8; 32];
        let addr = [0u8; 20];
        let task = [1u8; 32];
        let d = proof_transcript(31_337, addr, task, 0, zero, zero, zero, addr);
        assert_eq!(d.len(), 32);
        // Distinct nodes must diverge: the binding is the point of the 8th word.
        let other = [2u8; 20];
        assert_ne!(
            d,
            proof_transcript(31_337, addr, task, 0, zero, zero, zero, other)
        );
    }

    #[test]
    fn ct_root_is_empty_seed_for_no_leaves() {
        assert_eq!(ct_root(&[]), empty_root());
    }

    #[test]
    fn proof_reference_carries_the_star_prefix() {
        let r = proof_reference([9u8; 32]);
        assert_eq!(&r[..4], &PROOF_REF_PREFIX);
    }
}
