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

/// The commitment `commitDispute` takes: `keccak256(abi.encode(digest, salt, reporter))`.
///
/// Three full words — `bytes32`, `bytes32`, `address` left-padded into a word — so the
/// encoding is a fixed 96 bytes with no offsets. Binding the reporter stops one commitment
/// being replayed by another identity; binding the salt stops a bare digest from matching.
pub fn dispute_commitment(digest: B256, salt: B256, reporter: Address) -> B256 {
    let mut buf = [0u8; 96];
    buf[0..32].copy_from_slice(digest.as_slice());
    buf[32..64].copy_from_slice(salt.as_slice());
    buf[64..76].copy_from_slice(&[0u8; 12]);
    buf[76..96].copy_from_slice(reporter.as_slice());
    keccak256(buf)
}

/// Deterministic dispute salt for `(operator, task, epoch)`.
///
/// Fresh randomness would need persisting across the commit and the reveal (a restart between
/// the two otherwise loses the salt while the commitment stays open on chain). A derived
/// salt is recomputable after any restart, and it does not weaken the hiding: the preimage
/// space that matters is the 256-bit digest, not the salt. Uniqueness per reporter comes
/// from the reporter binding inside the commitment itself.
pub fn dispute_salt(operator: Address, task_id: U256, epoch: u32) -> B256 {
    let mut buf = [0u8; 96];
    buf[0..12].copy_from_slice(&[0u8; 12]);
    buf[12..32].copy_from_slice(operator.as_slice());
    buf[32..64].copy_from_slice(&task_id.to_be_bytes::<32>());
    let mut epoch_word = [0u8; 32];
    epoch_word[28..32].copy_from_slice(&epoch.to_be_bytes());
    buf[64..96].copy_from_slice(&epoch_word);
    keccak256(buf)
}

/// The transcript a proof of compute is bound to:
/// `CipherTask::proofTranscript(taskId, epoch, traceDigest, node)`.
///
/// H2 fix: the `node` parameter is the 8th static argument. This cryptographically binds
/// each STARK proof to the node that produced it, so a proof cannot be replayed under a
/// different node's identity. Previously the proof was replayable because only the digest
/// was in the transcript — any node could adopt another node's trace digest and win the
/// tie-break without doing the compute.
///
/// `abi.encode` of a `string` plus eight static arguments lays out as nine head words
/// (offset + 8 args), followed by the string's length word and its data right-padded to
/// 32 bytes. `TRANSCRIPT_MAGIC` is 13 bytes, so the total is `9 * 32 + 32 + 32 = 352`
/// bytes and the offset is `288`.
pub fn proof_transcript(
    chain_id: u64,
    cipher_task: Address,
    task_id: U256,
    epoch: u32,
    ct_root: B256,
    last_weights_digest: B256,
    trace_digest: B256,
    node: Address, // H2 fix: bind proof to node
) -> B256 {
    let mut buf: Vec<u8> = Vec::with_capacity(352);
    // Head word 0: offset of the dynamic `string` = 9 * 32 = 288.
    buf.extend_from_slice(&U256::from(9 * 32).to_be_bytes::<32>());
    buf.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    let mut addr_word = [0u8; 32];
    addr_word[12..32].copy_from_slice(cipher_task.as_slice());
    buf.extend_from_slice(&addr_word);
    buf.extend_from_slice(&task_id.to_be_bytes::<32>());
    buf.extend_from_slice(&U256::from(epoch).to_be_bytes::<32>());
    buf.extend_from_slice(ct_root.as_slice());
    buf.extend_from_slice(last_weights_digest.as_slice());
    buf.extend_from_slice(trace_digest.as_slice());
    // H2 fix: node address padded to 32 bytes.
    let mut node_word = [0u8; 32];
    node_word[12..32].copy_from_slice(node.as_slice());
    buf.extend_from_slice(&node_word);
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
    use alloy::primitives::address;

    fn b256(s: &str) -> B256 {
        s.parse().expect("32-byte hex")
    }

    /// Deployed `CipherTask` of the hardhat run the vectors come from.
    const TASK_ADDRESS: &str = "0x959922bE3CAee4b8Cd9a407cc3ac1C251C2007B1";
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

    // H2 fix: node parameter added to proof_transcript.
    // Used only in tests; production call sites are updated separately in EpochLib.sol.
    // Pinned to the Hardhat default signer used as `node` in `test-vectors/vectors.spec.ts`,
    // so this test and the chain vectors agree byte for byte.
    const TEST_NODE: Address = address!("0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc");

    #[test]
    fn the_transcript_matches_the_contract_view() {
        // `task.proofTranscript(1, 0, traceDigest, TEST_NODE)` after the third contribution.
        // Pinned against the `test-vectors/vectors.spec.ts` deployment (TRANSCRIPT.expected):
        // both sides bind the same node, so the digests must agree byte for byte.
        let got = proof_transcript(
            CHAIN_ID,
            TASK_ADDRESS.parse().expect("address"),
            U256::from(1),
            0,
            b256("0xa3d7329343c8b278393d3e6d990e99e514d3474f8d4f4df834630ecbdf9d0827"),
            b256("0xa68765884cb666d6f6f1673b17cd9d3d23bc01d171acdf0f77bcd5c0ae88544f"),
            b256("0x01c8a3e3937be1c605ffbdfd93fa4c7b1a68ef7dd87913adf52d6c0739ee7f62"),
            TEST_NODE, // H2 fix
        );
        assert_eq!(
            got,
            b256("0x0454f70057b5b5de290d04ff8a8e93e2f6ec4fa9d063a1a0eb95d73681cd99f9")
        );
    }

    #[test]
    fn every_public_input_changes_the_transcript() {
        let task: Address = TASK_ADDRESS.parse().expect("address");
        let (ct, w, tr) = (
            B256::repeat_byte(1),
            B256::repeat_byte(2),
            B256::repeat_byte(3),
        );
        let base = || proof_transcript(CHAIN_ID, task, U256::from(1), 0, ct, w, tr, TEST_NODE);
        let mut seen = vec![base()];
        for (chain_id, task_id, epoch, root, weights, trace) in [
            (CHAIN_ID + 1, U256::from(1), 0, ct, w, tr),
            (CHAIN_ID, U256::from(2), 0, ct, w, tr),
            (CHAIN_ID, U256::from(1), 1, ct, w, tr),
            (CHAIN_ID, U256::from(1), 0, B256::repeat_byte(9), w, tr),
            (CHAIN_ID, U256::from(1), 0, ct, B256::repeat_byte(9), tr),
            (CHAIN_ID, U256::from(1), 0, ct, w, B256::repeat_byte(9)),
        ] {
            let got = proof_transcript(
                chain_id, task, task_id, epoch, root, weights, trace, TEST_NODE,
            );
            assert_ne!(
                got,
                base(),
                "a changed public input must change the transcript"
            );
            seen.push(got);
        }
        let before = seen.len();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), before, "two distinct input sets collided");
        // H2 fix: the node is a public input. Same computation under a different node
        // must produce a different transcript; otherwise proofs are replayable.
        assert_ne!(
            proof_transcript(CHAIN_ID, task, U256::from(1), 0, ct, w, tr, TEST_NODE),
            proof_transcript(
                CHAIN_ID,
                task,
                U256::from(1),
                0,
                ct,
                w,
                tr,
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .parse()
                    .expect("address")
            ),
            "node must change the transcript"
        );
    }

    #[test]
    fn the_dispute_commitment_matches_abi_encode() {
        // `ethers.keccak256(abi.encode(["bytes32","bytes32","address"], [0x11*32, 0x22*32, 0xaa*20]))`,
        // computed against the SDK's encoder so the node and the contract agree byte for byte.
        let digest = B256::repeat_byte(0x11);
        let salt = B256::repeat_byte(0x22);
        let reporter: Address = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .expect("address");
        assert_eq!(
            dispute_commitment(digest, salt, reporter),
            b256("0xcfd5d0c50c4ee315105146571d644a56cfe517efa50a3d1f9010e78948106e97")
        );
    }

    #[test]
    fn the_dispute_commitment_binds_every_word() {
        let digest = B256::repeat_byte(0x11);
        let salt = B256::repeat_byte(0x22);
        let reporter: Address = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .expect("address");
        let base = dispute_commitment(digest, salt, reporter);
        assert_ne!(
            dispute_commitment(B256::repeat_byte(0x12), salt, reporter),
            base
        );
        assert_ne!(
            dispute_commitment(digest, B256::repeat_byte(0x23), reporter),
            base
        );
        let other: Address = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .parse()
            .expect("address");
        assert_ne!(dispute_commitment(digest, salt, other), base);
    }

    #[test]
    fn the_dispute_salt_is_deterministic_and_scoped() {
        let operator: Address = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .parse()
            .expect("address");
        // `keccak256(0x00*12 || 0xbb*20 || u256(7) || u256(3))` from the SDK encoder.
        assert_eq!(
            dispute_salt(operator, U256::from(7), 3),
            b256("0x193369e50097a1b3e8b1486f5f36d750c4c184785a17edec4539b3f4f03b5eb0")
        );
        assert_eq!(
            dispute_salt(operator, U256::from(7), 3),
            dispute_salt(operator, U256::from(7), 3),
            "a restart between commit and reveal must recompute the same salt"
        );
        assert_ne!(
            dispute_salt(operator, U256::from(8), 3),
            dispute_salt(operator, U256::from(7), 3)
        );
    }

    #[test]
    fn a_replayed_proof_is_bound_to_the_contract_that_emitted_it() {
        let addr: Address = TASK_ADDRESS.parse().expect("address");
        let other: Address = "0x0000000000000000000000000000000000000001"
            .parse()
            .expect("address");
        assert_ne!(
            proof_transcript(
                CHAIN_ID,
                addr,
                U256::from(1),
                0,
                B256::ZERO,
                B256::ZERO,
                B256::ZERO,
                TEST_NODE
            ),
            proof_transcript(
                CHAIN_ID,
                other,
                U256::from(1),
                0,
                B256::ZERO,
                B256::ZERO,
                B256::ZERO,
                TEST_NODE
            ),
        );
    }
}
