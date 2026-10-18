//! The `shroud/noop/v1` development shard envelope.
//!
//! Row convention: the first `features - 1` lanes are inputs, the last lane is the
//! label. Values arrive as little-endian `f64` and are quantised on decode, so a
//! shard quantised at any other scale trains on different numbers than the
//! contributor approved — the scale is a parameter here, never a default.

use crate::{
    error::{CoreError, Result},
    fixed::quantize,
};

/// Magic prefix of every development shard.
pub const NOOP_SHARD_MAGIC: &[u8] = b"shroud/noop/v1\0";
/// Magic prefix of `tfhe-rs` ciphertext shards (handled by the tfhe backend).
pub const TFHE_SHARD_MAGIC: &[u8] = b"shroud/tfhe/v1\0";

/// Decoded development shard: quantised row-major values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardRows {
    pub features: u32,
    pub rows: u32,
    pub values: Vec<u64>,
}

/// Decode a `shroud/noop/v1` shard payload into quantised rows.
///
/// `expected_features` is the task's on-chain `features` and `scale` is the task's
/// quantisation scale: a shard quantised at any other scale trains on different
/// numbers than the contributor approved, so the scale is a parameter here,
/// never a default.
pub fn decode_noop_shard(bytes: &[u8], expected_features: u32, scale: u32) -> Result<ShardRows> {
    let malformed = |offset: usize, reason: String| CoreError::Malformed { offset, reason };
    if bytes.len() < NOOP_SHARD_MAGIC.len() {
        return Err(malformed(
            0,
            "shard is shorter than the envelope magic".into(),
        ));
    }
    if &bytes[..NOOP_SHARD_MAGIC.len()] != NOOP_SHARD_MAGIC {
        // Anything else here is either corruption or a handle-based (relayer) or tfhe
        // shard, which the reference backend cannot decrypt. Say which, loudly:
        // attempting to train on handle bytes as floats would produce a digest no
        // honest node reproduces.
        if bytes.len() >= TFHE_SHARD_MAGIC.len()
            && &bytes[..TFHE_SHARD_MAGIC.len()] == TFHE_SHARD_MAGIC
        {
            return Err(CoreError::Backend(
                "shard holds tfhe-rs ciphertexts: the reference engine cannot decrypt them; \
                 run a tfhe backend with the network server key (fhe.backend + fhe.server_key_path)"
                    .into(),
            ));
        }
        return Err(malformed(
            0,
            "bad shard magic: not a shroud/noop/v1 payload".into(),
        ));
    }
    let mut pos = NOOP_SHARD_MAGIC.len();
    let mut number = |what: &str| -> Result<u32> {
        let start = pos;
        while pos < bytes.len() && bytes[pos] != 0 {
            if !bytes[pos].is_ascii_digit() {
                return Err(malformed(start, format!("non-decimal byte in {what}")));
            }
            pos += 1;
        }
        if pos >= bytes.len() {
            return Err(malformed(start, format!("unterminated {what}")));
        }
        let text = std::str::from_utf8(&bytes[start..pos])
            .map_err(|_| malformed(start, format!("{what} is not UTF-8")))?;
        pos += 1; // the NUL
        text.parse::<u32>()
            .map_err(|_| malformed(start, format!("{what} {text:?} is not a u32")))
    };
    let features = number("features")?;
    let rows = number("rows")?;
    if features != expected_features {
        return Err(CoreError::ShapeMismatch {
            got_rows: rows as usize,
            got_cols: features as usize,
            want_rows: rows as usize,
            want_cols: expected_features as usize,
        });
    }
    let lanes = (rows as usize)
        .checked_mul(features as usize)
        .ok_or_else(|| {
            malformed(
                pos,
                "row count overflows the address space; the header is hostile or corrupt".into(),
            )
        })?;
    let want = lanes
        .checked_mul(8)
        .and_then(|body| pos.checked_add(body))
        .ok_or_else(|| {
            malformed(
                pos,
                "row count overflows the address space; the header is hostile or corrupt".into(),
            )
        })?;
    if bytes.len() != want {
        return Err(malformed(
            pos,
            format!(
                "shard is {} bytes, expected {want} for {rows} rows x {features} features",
                bytes.len()
            ),
        ));
    }
    let mut values = Vec::with_capacity(lanes);
    for i in 0..lanes {
        let word: [u8; 8] = bytes[pos + i * 8..pos + i * 8 + 8]
            .try_into()
            .expect("length checked");
        values.push(quantize(f64::from_le_bytes(word), scale, i)?);
    }
    Ok(ShardRows {
        features,
        rows,
        values,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shard_bytes(features: u32, rows: &[[f64; 2]]) -> Vec<u8> {
        let mut b = Vec::from(NOOP_SHARD_MAGIC);
        b.extend_from_slice(format!("{features}\0").as_bytes());
        b.extend_from_slice(format!("{}\0", rows.len()).as_bytes());
        for r in rows {
            for v in r {
                b.extend_from_slice(&v.to_le_bytes());
            }
        }
        b
    }

    #[test]
    fn decodes_a_well_formed_shard() {
        let s = decode_noop_shard(&shard_bytes(2, &[[2.0, 3.0]]), 2, 10_000).unwrap();
        assert_eq!((s.features, s.rows), (2, 1));
        assert_eq!(s.values, vec![20_000, 30_000]);
    }

    #[test]
    fn rejects_foreign_envelopes_loudly() {
        assert!(decode_noop_shard(b"nope", 2, 10_000).is_err());
        let mut tfhe = Vec::from(TFHE_SHARD_MAGIC);
        tfhe.extend_from_slice(&[0u8; 8]);
        assert!(matches!(
            decode_noop_shard(&tfhe, 2, 10_000),
            Err(CoreError::Backend(_))
        ));
    }
}
