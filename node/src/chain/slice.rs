//! The ERC-1271 reward-slice blob a `CipherTask` channel is redeemed with.
//!
//! `PaymentVault.redeem` authenticates `signature` against the channel's streamer. When the
//! streamer is the orchestrator (every Shroud reward channel), `_authorize` dispatches to
//! `CipherTask.isValidSignature`, which expects **96 bytes**: `abi.encode(uint256 channelId,
//! uint256 sliceIndex, uint128 amount)` with the deadline fixed to `type(uint256).max`
//! (`CipherTask::_decodeSliceFull`). It is not a signature at all — the authorisation already
//! happened on chain when `_authorizedSlice[channelId][0] = reward` was written, and the blob is
//! simply the key the orchestrator looks that authorisation up under.
//!
//! Three consequences the node must respect, all verified by replaying a real `redeem` against a
//! hardhat chain built from this repository's contracts rather than read off a comment:
//!
//! * Only `sliceIndex == 0` is ever authorised, at exactly the channel's `maxCumulative`. A
//!   second slice for the same channel has no authorisation to be checked against, so a channel
//!   is collected in one `redeem`, not streamed.
//! * The blob is *not* an EOA signature. A 65-byte ECDSA signature is only accepted when the
//!   streamer is an EOA, so streamer-signed slices belong to EOA channels only.
//! * The `uint128` and `uint64` casts the contract applies to the words truncate, so an
//!   over-wide word is refused locally instead of being read as a different amount than the
//!   chain will pay.

use alloy::primitives::U256;

/// Bytes of `abi.encode(uint256,uint256,uint128)` — three 32-byte words, no tail.
pub const BLOB_BYTES: usize = 96;

/// The only slice index `CipherTask` ever authorises.
pub const SLICE_INDEX: u64 = 0;

/// `CipherTask::_decodeSliceFull` hardcodes the deadline to `type(uint256).max`, so the value
/// that goes into the redeem call — and therefore into the EIP-712 digest the vault recomputes —
/// is this, not a wall-clock deadline.
pub const SLICE_DEADLINE: U256 = U256::MAX;

/// One authorised slice, as the orchestrator records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slice {
    pub channel_id: U256,
    pub index: u64,
    /// Cumulative amount, matching `redeem`'s `uint128 amount` semantics.
    pub amount: u128,
}

impl Slice {
    /// The canonical epoch reward slice: index 0 at the channel's full authorisation.
    pub fn epoch_reward(channel_id: U256, amount: u128) -> Self {
        Self {
            channel_id,
            index: SLICE_INDEX,
            amount,
        }
    }
}

/// Encode the blob `redeem`'s `signature` argument must carry for an orchestrator-streamed
/// channel.
pub fn encode(slice: &Slice) -> [u8; BLOB_BYTES] {
    let mut out = [0u8; BLOB_BYTES];
    out[0..32].copy_from_slice(&slice.channel_id.to_be_bytes::<32>());
    out[32..64].copy_from_slice(&U256::from(slice.index).to_be_bytes::<32>());
    out[64..96].copy_from_slice(&U256::from(slice.amount).to_be_bytes::<32>());
    out
}

/// Read a blob back, rejecting anything the contract would have to truncate.
pub fn decode(blob: &[u8]) -> Option<Slice> {
    if blob.len() != BLOB_BYTES {
        return None;
    }
    if blob[32..56] != [0u8; 24] {
        return None;
    }
    if blob[64..80] != [0u8; 16] {
        return None;
    }
    Some(Slice {
        channel_id: U256::from_be_slice(&blob[0..32]),
        index: u64::from_be_slice(&blob[56..64]),
        amount: u128::from_be_slice(&blob[80..96]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `channelId = 1`, `sliceIndex = 0`, `amount = 50_000_000` (50 CMUSD at 6 decimals) — the
    /// blob a real `PaymentVault.redeem` accepted on a hardhat chain deployed from this
    /// repository's contracts.
    const CHAIN_BLOB: &str = concat!(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000002faf080",
    );

    fn bytes32_words(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn the_encoding_matches_the_blob_the_chain_accepted() {
        let slice = Slice::epoch_reward(U256::from(1), 50_000_000);
        assert_eq!(encode(&slice).to_vec(), bytes32_words(CHAIN_BLOB));
    }

    #[test]
    fn decode_reads_the_chain_blob_back() {
        assert_eq!(
            decode(&bytes32_words(CHAIN_BLOB)).expect("decodes"),
            Slice {
                channel_id: U256::from(1),
                index: 0,
                amount: 50_000_000,
            }
        );
    }

    #[test]
    fn encode_decode_round_trips() {
        for (channel, amount) in [
            (U256::ZERO, 0u128),
            (U256::from(7), 1),
            (U256::MAX, u128::MAX),
        ] {
            let slice = Slice::epoch_reward(channel, amount);
            assert_eq!(decode(&encode(&slice)).expect("round trip"), slice);
        }
    }

    #[test]
    fn a_blob_of_the_wrong_length_is_not_a_slice() {
        assert!(decode(&[]).is_none());
        assert!(decode(&[0u8; 95]).is_none());
        assert!(decode(&[0u8; 97]).is_none());
        assert!(
            decode(&[0u8; 65]).is_none(),
            "a 65-byte ECDSA signature is not a slice blob"
        );
    }

    #[test]
    fn an_over_wide_word_is_refused_rather_than_truncated() {
        let mut blob = encode(&Slice::epoch_reward(U256::from(1), 10));
        blob[64] = 0x01; // bit 128 of the `uint128` slot: `uint128(bytes32)` would drop it
        assert!(decode(&blob).is_none());

        let mut blob = encode(&Slice::epoch_reward(U256::from(1), 10));
        blob[32] = 0x01; // bit 64 of the slice-index slot: `uint64(...)` would drop it
        assert!(decode(&blob).is_none());
    }

    #[test]
    fn the_deadline_is_the_contracts_sentinel_not_a_timestamp() {
        assert_eq!(SLICE_DEADLINE, U256::MAX);
    }
}
