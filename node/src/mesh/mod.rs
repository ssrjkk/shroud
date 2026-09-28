//! gRPC peer mesh.
//!
//! The generated protobuf types are `include!`d rather than gated, because `build.rs` runs
//! before feature resolution is visible to it and a missing module is a much worse error than a
//! little unused code. [`proto`] is the generated code; the hand-written logic lives in the
//! sibling modules.

/// Generated from `proto/mesh.proto` by `build.rs`.
pub mod proto {
    #![allow(clippy::all)]
    #![allow(missing_docs)]
    tonic::include_proto!("ciphermesh.mesh.v1");
}

pub use proto::{mesh_client, mesh_server};

use alloy::primitives::U256;
use thiserror::Error;

/// A `uint256` carried as a decimal string over protobuf.
///
/// proto3 has no 256-bit integer, and the obvious "fixes" are both silent: `uint64` truncates,
/// and `double` loses precision above 2^53. The contracts use `uint256` for `taskId` and
/// `channelId`, so those two fields are strings on the wire and parsed here, where a failure is
/// a loud error rather than a wrong-but-plausible number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecimalU256(pub U256);

impl std::str::FromStr for DecimalU256 {
    type Err = ParseIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ParseIdError::Empty);
        }
        // Reject anything that is not plain decimal, including `+1`, ` 1` and `0x1`. Being
        // strict here means a malformed peer cannot make us and another peer disagree about
        // which task is being discussed.
        if !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ParseIdError::NotDecimal(s.to_string()));
        }
        U256::from_str_radix(s, 10).map(DecimalU256).map_err(ParseIdError::Overflow)
    }
}

impl std::fmt::Display for DecimalU256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<DecimalU256> for U256 {
    fn from(v: DecimalU256) -> U256 {
        v.0
    }
}

#[derive(Debug, Error)]
pub enum ParseIdError {
    #[error("empty task/channel id")]
    Empty,
    #[error("`{0}` is not a plain decimal integer")]
    NotDecimal(String),
    #[error("`0` overflows uint256: {0}")]
    Overflow(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_normal_id_round_trips() {
        let v: DecimalU256 = "42".parse().expect("parses");
        assert_eq!(v.0, U256::from(42));
        assert_eq!(v.to_string(), "42");
    }

    #[test]
    fn a_uint256_max_id_round_trips() {
        // The case a uint64 or double field would silently corrupt.
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        let v: DecimalU256 = max.parse().expect("parses");
        assert_eq!(v.to_string(), max);
    }

    #[test]
    fn hex_and_whitespace_are_rejected() {
        for bad in ["0x2a", " 2", "2 ", "+2", "-2", "2.0"] {
            assert!(bad.parse::<DecimalU256>().is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn empty_is_rejected() {
        assert!("".parse::<DecimalU256>().is_err());
    }

    #[test]
    fn overflow_is_rejected_rather_than_wrapping() {
        let too_big = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        assert!(too_big.parse::<DecimalU256>().is_err());
    }

    #[test]
    fn leading_zeros_are_accepted() {
        assert_eq!("007".parse::<DecimalU256>().unwrap().0, U256::from(7));
    }
}
