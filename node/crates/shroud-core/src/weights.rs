//! The `shroud/weights/v1` file format: magic, features, lane count, `u32` lanes.
//!
//! A weight vector. Lanes are `i32` two's complement stored in `u32` words: linear models
//! legitimately go negative, and a `u32` lane width cannot express that any other way.
//! `lanes.len()` always equals `features`; the last lane is the bias.

use crate::{
    error::{CoreError, Result},
    hash::keccak256,
};

/// Magic prefix of every weight file.
pub const WEIGHTS_MAGIC: &[u8] = b"shroud/weights/v1\0";

/// A weight vector. `lanes.len()` always equals `features`; the last lane is the bias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Weights {
    pub features: u32,
    pub lanes: Vec<u32>,
}

impl Weights {
    /// All-zero vector (genesis weights when a task pins no seed).
    pub fn zeros(features: u32) -> Result<Self> {
        if features < 2 {
            return Err(CoreError::ShapeMismatch {
                got_rows: 0,
                got_cols: 0,
                want_rows: 0,
                want_cols: 2,
            });
        }
        Ok(Self {
            features,
            lanes: vec![0u32; features as usize],
        })
    }

    /// Lanes reinterpreted as signed (engine use: the optimiser trains on `i64`).
    pub fn signed(&self) -> Vec<i64> {
        self.lanes.iter().map(|w| (*w as i32) as i64).collect()
    }

    /// `keccak256` over the lane words, little-endian. This is the `weightsDigest`
    /// `commitEpoch` stores; the next epoch binds it as `lastWeightsDigest`.
    pub fn digest(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(self.lanes.len() * 4);
        for lane in &self.lanes {
            buf.extend_from_slice(&lane.to_le_bytes());
        }
        keccak256(&buf)
    }

    /// Encode to the [`WEIGHTS_MAGIC`] file format for the content-addressed store.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WEIGHTS_MAGIC.len() + 8 + self.lanes.len() * 4);
        out.extend_from_slice(WEIGHTS_MAGIC);
        out.extend_from_slice(&self.features.to_le_bytes());
        out.extend_from_slice(&(self.lanes.len() as u32).to_le_bytes());
        for lane in &self.lanes {
            out.extend_from_slice(&lane.to_le_bytes());
        }
        out
    }

    /// Decode and validate a weight file. `expected_features` is the task's `features`;
    /// anything else is a shape error, never a silent reinterpretation.
    pub fn decode(bytes: &[u8], expected_features: u32) -> Result<Self> {
        let fail = |reason: String| CoreError::Malformed { offset: 0, reason };
        if bytes.len() < WEIGHTS_MAGIC.len() + 8 {
            return Err(fail(format!(
                "weight object is {} bytes, shorter than the header",
                bytes.len()
            )));
        }
        if &bytes[..WEIGHTS_MAGIC.len()] != WEIGHTS_MAGIC {
            return Err(fail("bad weights magic".into()));
        }
        let r = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().expect("sliced"));
        let features = r(WEIGHTS_MAGIC.len());
        let count = r(WEIGHTS_MAGIC.len() + 4);
        if features != expected_features {
            return Err(CoreError::ShapeMismatch {
                got_rows: 0,
                got_cols: features as usize,
                want_rows: 0,
                want_cols: expected_features as usize,
            });
        }
        if count != features {
            return Err(fail(format!(
                "weight file holds {count} lanes for {features} features"
            )));
        }
        let want = WEIGHTS_MAGIC.len() + 8 + count as usize * 4;
        if bytes.len() != want {
            return Err(fail(format!(
                "weight object is {} bytes, expected {want} for {count} lanes",
                bytes.len()
            )));
        }
        let mut lanes = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            lanes.push(r(WEIGHTS_MAGIC.len() + 8 + i * 4));
        }
        Ok(Self { features, lanes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_preserves_lanes() {
        let w = Weights {
            features: 3,
            lanes: vec![1, u32::MAX, 42],
        };
        assert_eq!(Weights::decode(&w.encode(), 3).unwrap(), w);
        assert!(Weights::decode(&w.encode(), 2).is_err());
        assert!(Weights::zeros(1).is_err());
    }

    #[test]
    fn digest_is_stable() {
        let a = Weights::zeros(2).unwrap().digest();
        let b = Weights::zeros(2).unwrap().digest();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }
}
