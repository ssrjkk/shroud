//! Fixed-point primitives shared by the node, the lab and future guests.
//!
//! The canonical versions of what `web/assets/crypto.js` mirrors: any change here
//! must be ported there (and vice versa) or `equiv.mjs` goes red.

use crate::error::{CoreError, Result};

/// Clamp an `i128` accumulator into an `i64` lane. Clamp, never wrap: a step that
/// does not fit is reported by the `i32` range check at the end of the epoch.
pub fn clamp_i64(v: i128) -> i64 {
    v.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// Quantise one row value exactly the way the SDK does (`round(v * scale)`),
/// rejecting anything TFHE cannot represent rather than coercing it: a wrapped
/// negative would train on a huge positive with no error anywhere downstream.
pub fn quantize(value: f64, scale: u32, index: usize) -> Result<u64> {
    let malformed = |reason: String| CoreError::Malformed {
        offset: index,
        reason,
    };
    if !value.is_finite() {
        return Err(malformed(format!(
            "row value at index {index} is not finite"
        )));
    }
    if value < 0.0 {
        return Err(malformed(format!(
            "row value at index {index} is negative ({value}): TFHE encrypts unsigned integers"
        )));
    }
    let q = (value * f64::from(scale)).round();
    // `as u64` saturates, so the boundary itself must be rejected: a value that rounds
    // to exactly 2^64 would otherwise become u64::MAX silently.
    if q >= 18_446_744_073_709_551_616.0 {
        return Err(malformed(format!(
            "row value at index {index} overflows uint64 at scale {scale}"
        )));
    }
    Ok(q as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantize_rounds_like_the_sdk() {
        assert_eq!(quantize(1.5, 10_000, 0).unwrap(), 15_000);
        assert_eq!(quantize(0.0, 10_000, 0).unwrap(), 0);
    }

    #[test]
    fn quantize_rejects_the_unrepresentable() {
        assert!(quantize(f64::NAN, 10_000, 0).is_err());
        assert!(quantize(f64::INFINITY, 10_000, 0).is_err());
        assert!(quantize(-0.5, 10_000, 3).is_err());
        assert!(quantize(2e15, 10_000, 0).is_err());
    }

    #[test]
    fn clamp_holds_the_i64_edges() {
        assert_eq!(clamp_i64(i64::MIN as i128 - 1), i64::MIN);
        assert_eq!(clamp_i64(i64::MAX as i128 + 1), i64::MAX);
        assert_eq!(clamp_i64(42), 42);
    }
}
