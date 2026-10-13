//! The two byte layouts `CipherTask` hashes, mirrored exactly.
//!
//! Both are consensus-critical: `ctRoot` is a STARK public input and `proofTranscript` is what a
//! verifier binds a proof to. A node that computes either one byte differently proves a statement
//! the chain will not accept — and worse, a re-executing node would "disagree" with an honest
//! commit and file a dispute that only its own encoder caused. So the layouts here are pinned by
//! tests against values captured from a real hardhat deployment of these contracts, not against a
//! hand-computed hash.

use alloy::primitives::{keccak256, Address, B256, U256};

/// Domain tag of the proof transcript, as the first `abi.encode` argument.
const TRANSCRIPT_MAGIC: &[u8] = b"SHROUD/PoC/v1"; // 13 bytes

/// The seed of the `ctRoot` accumulation chain: `_EMPTY_ROOT` in `CipherTask`.
pub fn empty_root() -> B256 {
    keccak256(b"SHROUD/CTROOT/v1")
}

/// One step of the `ctRoot` chain.
///
/// `CipherTask::_appendLeaf` is `keccak256(abi.encodePacked(acc, leafIndex, ciphertextCid))`:
/// 32 + 4 + 32 = 68 packed bytes, with the `uint32` in its own 4 bytes — *not* padded to a word,
/// which is the difference between this and a struct hash.
pub fn ct_root_step(prev: B256, leaf_index: u32, ciphertext_cid: B256) -> B256 {
    let mut buf = [0u8; 68];
    buf[0..32].copy_from_slice(prev.as_slice());
    buf[32..36].copy_from_slice(&leaf_index.to_be_bytes());
    buf[36..68].copy_from_slice(ciphertext_cid.as_slice());
    keccak256(buf)
}

/// Fold a whole contribution set into the root the contract compares against.
///
/// Leaves are appended in submission order, so `leaf_index` is positional: `0..n`.
pub fn ct_root(ciphertext_cids: &[B256]) -> B256 {
    let mut root = empty_root();
    for (index, cid) in ciphertext_cids.iter().enumerate() {
        root = ct_root_step(root, index as u32, *cid);
    }
    root
}

/// The transcript a proof of compute is bound to:
/// `CipherTask::proofTranscript(taskId, epoch, traceDigest)`.
///
/// `abi.encode` of a `string` plus seven static arguments lays out as eight head words — the
/// string's head being its offset from the start of the encoding — followed by the string's
/// length word and its data right-padded to 32 bytes. `TRANSCRIPT_MAGIC` is 13 bytes, so the
/// total is `8 * 32 + 32 + 32 = 320` bytes and the offset is `256`.
pub fn proof_transcript(
    chain_id: u64,
    cipher_task: Address,
    task_id: U256,
    epoch: u32,
    ct_root: B256,
    last_weights_digest: B256,
    trace_digest: B256,
) -> B256 {
    let mut buf: Vec<u8> = Vec::with_capacity(320);
    // Head word 0: offset of the dynamic `string`.
    buf.extend_from_slice(&U256::from(8 * 32).to_be_bytes::<32>());
    buf.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    let mut addr_word = [0u8; 32];
    addr_word[12..32].copy_from_slice(cipher_task.as_slice());
    buf.extend_from_slice(&addr_word);
    buf.extend_from_slice(&task_id.to_be_bytes::<32>());
    buf.extend_from_slice(&U256::from(epoch).to_be_bytes::<32>());
    buf.extend_from_slice(ct_root.as_slice());
    buf.extend_from_slice(last_weights_digest.as_slice());
    buf.extend_from_slice(trace_digest.as_slice());
    // Tail: length, then the data padded into one word.
    buf.extend_from_slice(&U256::from(TRANSCRIPT_MAGIC.len()).to_be_bytes::<32>());
    let mut string_word = [0u8; 32];
    string_word[..TRANSCRIPT_MAGIC.len()].copy_from_slice(TRANSCRIPT_MAGIC);
    buf.extend_from_slice(&string_word);
    keccak256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b256(s: &str) -> B256 {
        s.parse().expect("32-byte hex")
    }

    /// Deployed `CipherTask` of the hardhat run the vectors come from.
    const TASK_ADDRESS: &str = "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318";
    const CHAIN_ID: u64 = 31_337;

    #[test]
    fn the_empty_root_is_the_contracts_seed() {
        assert_eq!(
            empty_root(),
            b256("0x863737be8f430ace1a1b64da126e38a94c776d0ccefa95785ea4eaeb113b9cf3")
        );
    }

    #[test]
    fn ct_root_steps_match_the_chain() {
        // Three `submitContribution` calls, each followed by a read of `ctRootOf(taskId)`.
        let chain = [
            (
                0u32,
                "0x7cb28e2fbd63cc4d4a519f09950cf70541ff7d13878e887d59fb1341ac17890c",
                "0x801459d04349d20b5e2f880112503d0f17b1183937397bdcb66efa502fe4fde8",
            ),
            (
                1,
                "0x444d61d4497174c690bdb4fd4bbcac1a652b91a47223a97074a78dbd5496f6e3",
                "0xb719daf526966b94fd548fd4de7c9659c119d4b006beaf12759e5c94da10dd14",
            ),
            (
                2,
                "0x4780e827121b4e535b1661f87ed03f1ea1c3845f7c059087f524423d53238403",
                "0xa3d7329343c8b278393d3e6d990e99e514d3474f8d4f4df834630ecbdf9d0827",
            ),
        ];

        let mut acc = empty_root();
        for (leaf, cid, expected) in chain {
            acc = ct_root_step(acc, leaf, b256(cid));
            assert_eq!(acc, b256(expected), "leaf {leaf}");
        }
        assert_eq!(
            ct_root(
                &chain
                    .iter()
                    .map(|(_, cid, _)| b256(cid))
                    .collect::<Vec<_>>()
            ),
            acc,
            "the folded root must equal the last incremental step"
        );
    }

    #[test]
    fn an_empty_contribution_set_is_the_seed() {
        assert_eq!(ct_root(&[]), empty_root());
    }

    #[test]
    fn the_transcript_matches_the_contract_view() {
        // `task.proofTranscript(1, 0, traceDigest)` after the third contribution and an
        // `openEpoch` whose `weightsDigest` is the one below.
        let got = proof_transcript(
            CHAIN_ID,
            TASK_ADDRESS.parse().expect("address"),
            U256::from(1),
            0,
            b256("0xa3d7329343c8b278393d3e6d990e99e514d3474f8d4f4df834630ecbdf9d0827"),
            b256("0xa68765884cb666d6f6f1673b17cd9d3d23bc01d171acdf0f77bcd5c0ae88544f"),
            b256("0x01c8a3e3937be1c605ffbdfd93fa4c7b1a68ef7dd87913adf52d6c0739ee7f62"),
        );
        assert_eq!(
            got,
            b256("0x4abdca8df798a87c70c8d71e451d62074a9769cca624cedb289f9d579702d27c")
        );
    }

    #[test]
    fn every_public_input_changes_the_transcript() {
        let task: Address = TASK_ADDRESS.parse().expect("address");
        let (ct, w, tr) = (B256::repeat_byte(1), B256::repeat_byte(2), B256::repeat_byte(3));
        let base = || proof_transcript(CHAIN_ID, task, U256::from(1), 0, ct, w, tr);
        let mut seen = vec![base()];
        for (chain_id, task_id, epoch, root, weights, trace) in [
            (CHAIN_ID + 1, U256::from(1), 0, ct, w, tr),
            (CHAIN_ID, U256::from(2), 0, ct, w, tr),
            (CHAIN_ID, U256::from(1), 1, ct, w, tr),
            (CHAIN_ID, U256::from(1), 0, B256::repeat_byte(9), w, tr),
            (CHAIN_ID, U256::from(1), 0, ct, B256::repeat_byte(9), tr),
            (CHAIN_ID, U256::from(1), 0, ct, w, B256::repeat_byte(9)),
        ] {
            let got = proof_transcript(chain_id, task, task_id, epoch, root, weights, trace);
            assert_ne!(got, base(), "a changed public input must change the transcript");
            seen.push(got);
        }
        let before = seen.len();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), before, "two distinct input sets collided");
    }

    #[test]
    fn a_replayed_proof_is_bound_to_the_contract_that_emitted_it() {
        let addr: Address = TASK_ADDRESS.parse().expect("address");
        let other: Address = "0x0000000000000000000000000000000000000001"
            .parse()
            .expect("address");
        assert_ne!(
            proof_transcript(CHAIN_ID, addr, U256::from(1), 0, B256::ZERO, B256::ZERO, B256::ZERO),
            proof_transcript(CHAIN_ID, other, U256::from(1), 0, B256::ZERO, B256::ZERO, B256::ZERO),
        );
    }
}
