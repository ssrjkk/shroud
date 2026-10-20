//! Deterministic fixed-point SGD for linear regression over quantised rows.
//!
//! Row convention: the first `features - 1` lanes are inputs, the last lane is the
//! label (`labelBits` on chain describes its width). The weight vector has `features`
//! lanes, the last being the bias — the weight on the constant 1.0 input, quantised
//! as `S`, so its gradient accumulator lives in the same S² domain as every other
//! lane and the shared update rule applies to it unchanged. All arithmetic is
//! checked `i128`; anything that does not fit is an error, never a wrap: two nodes
//! must compute the same digest, and wrapping would make that depend on build details.
//!
//! Update per minibatch of `m` rows, with `S = scale`, `Q = 2^16`:
//! `w -= (lr_q16 * Σ(err * x)) / (Q * S * m)`, then L2 once per epoch:
//! `w -= (l2_q16 * w) / Q`. Division truncates toward zero — deterministic on every
//! platform, which is the only property the dispute protocol needs from it.

use crate::{
    error::{CoreError, Result},
    fixed::clamp_i64,
};

/// Hyperparameters for one epoch. All three scales must be non-zero; the caller
/// (node engine assembly) enforces that before calling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SgdParams {
    /// Quantisation scale `S`.
    pub scale: u32,
    /// Learning rate in Q16.16.
    pub lr_q16: u32,
    /// L2 shrinkage in Q16.16 (0 disables).
    pub l2_q16: u32,
    /// Rows per gradient-accumulation batch.
    pub minibatch: usize,
}

/// One decoded shard view: `rows * features` quantised lanes, row-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardView<'a> {
    /// Row count in this shard.
    pub rows: u32,
    /// `rows * features` quantised values, row-major.
    pub values: &'a [u64],
}

/// The epoch result the caller commits: updated weights, mean loss, row count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SgdOutput {
    /// Updated weight vector (`features` lanes, bias last).
    pub weights: Vec<i64>,
    /// Mean quantised squared error (`loss / n_rows`).
    pub loss_mean_q: i128,
    /// Total rows consumed.
    pub n_rows: u64,
}

/// One minibatch step: `w -= (lr_q16 * acc) / (2^16 * S * m)`, accumulators cleared.
///
/// The conversions clamp rather than wrap: a step that does not fit is reported by
/// the `i32` range check at the end of the epoch, never silently folded.
pub fn apply_update(w: &mut [i64], grad: &mut [i128], m: u64, lr_q16: u32, s: i128) -> Result<()> {
    let overflow = |stage: &'static str| CoreError::Overflow { stage };
    // The denominator is checked like everything else here, and a zero denominator (a zero
    // scale, or an empty batch) is an error rather than a division by zero.
    let denom = 65_536i128
        .checked_mul(s)
        .and_then(|d| d.checked_mul(i128::from(m)))
        .ok_or_else(|| overflow("update denominator"))?;
    if denom == 0 {
        return Err(overflow("update denominator"));
    }
    for (lane, acc) in w.iter_mut().zip(grad.iter_mut()) {
        // `lr_q16 * acc` is the one product that can leave `i128`: the accumulator holds a
        // sum of `err * x` over the batch and the learning rate multiplies it on top. The
        // loss check only bounds `err * err`, not `err * x`, so the product can exceed the
        // range on inputs the rest of the epoch accepted. A wrap here would make the update
        // depend on build details - exactly what this module exists to prevent - so it is
        // an error instead.
        let scaled = i128::from(lr_q16)
            .checked_mul(*acc)
            .ok_or_else(|| overflow("update"))?;
        let delta = scaled / denom;
        *lane = clamp_i64(
            i128::from(*lane)
                .checked_sub(delta)
                .ok_or_else(|| overflow("update"))?,
        );
        *acc = 0;
    }
    Ok(())
}

/// Run one full epoch over already-decoded shards.
///
/// `features` includes the label lane (so `features >= 2`) and must match
/// `prev_w.len()`; an epoch with zero rows is a shape error, never a silent
/// no-op that would commit a digest of nothing.
pub fn run_epoch(
    params: &SgdParams,
    features: usize,
    prev_w: &[i64],
    shards: &[ShardView<'_>],
) -> Result<SgdOutput> {
    let s = i128::from(params.scale);
    let mut w: Vec<i64> = prev_w.to_vec();
    let mut grad = vec![0i128; features];
    let mut in_batch: u64 = 0;
    let mut n_rows: u64 = 0;
    let mut loss: i128 = 0;

    let overflow = |stage: &'static str| CoreError::Overflow { stage };

    for shard in shards {
        for r in 0..shard.rows as usize {
            let base = r * features;
            // Prediction in quantised units: Σ w·x / S + bias.
            let mut dot: i128 = 0;
            for (j, wj) in w.iter().enumerate().take(features - 1) {
                dot = dot
                    .checked_add(
                        i128::from(*wj)
                            .checked_mul(i128::from(shard.values[base + j]))
                            .ok_or_else(|| overflow("dot product"))?,
                    )
                    .ok_or_else(|| overflow("dot product"))?;
            }
            let pred = dot / s + i128::from(w[features - 1]);
            let err = pred - i128::from(shard.values[base + features - 1]);
            loss = loss
                .checked_add(err.checked_mul(err).ok_or_else(|| overflow("loss"))?)
                .ok_or_else(|| overflow("loss"))?;
            for (j, gj) in grad.iter_mut().enumerate().take(features - 1) {
                *gj = (*gj)
                    .checked_add(
                        err.checked_mul(i128::from(shard.values[base + j]))
                            .ok_or_else(|| overflow("gradient"))?,
                    )
                    .ok_or_else(|| overflow("gradient"))?;
            }
            // The bias is the weight on the constant input 1.0, quantised as `S`:
            // its accumulator lives in the same S² domain as every other lane, so
            // the shared update rule applies to it unchanged.
            grad[features - 1] = grad[features - 1]
                .checked_add(err.checked_mul(s).ok_or_else(|| overflow("gradient"))?)
                .ok_or_else(|| overflow("gradient"))?;
            in_batch += 1;
            n_rows += 1;
            if in_batch as usize >= params.minibatch {
                apply_update(&mut w, &mut grad, in_batch, params.lr_q16, s)?;
                in_batch = 0;
            }
        }
    }
    if n_rows == 0 {
        return Err(CoreError::ShapeMismatch {
            got_rows: 0,
            got_cols: features,
            want_rows: 1,
            want_cols: features,
        });
    }
    if in_batch > 0 {
        apply_update(&mut w, &mut grad, in_batch, params.lr_q16, s)?;
    }
    // L2 shrinkage, once per epoch. Clamped into i64: the final i32
    // range check below turns an out-of-lane result into an error.
    if params.l2_q16 != 0 {
        for lane in w.iter_mut() {
            let shrink = i128::from(params.l2_q16)
                .checked_mul(i128::from(*lane))
                .ok_or_else(|| overflow("l2 shrinkage"))?
                / 65_536;
            *lane = clamp_i64(
                i128::from(*lane)
                    .checked_sub(shrink)
                    .ok_or_else(|| overflow("l2 shrinkage"))?,
            );
        }
    }
    let loss_mean = loss / i128::from(n_rows);
    Ok(SgdOutput {
        weights: w,
        loss_mean_q: loss_mean,
        n_rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> SgdParams {
        SgdParams {
            scale: 10_000,
            lr_q16: 327,
            l2_q16: 0,
            minibatch: 4,
        }
    }

    #[test]
    fn learns_downhill_on_a_toy_shard() {
        // y = 2x through the origin-ish: the bias absorbs the offset, the slope
        // must move toward 2.0 (20000 quantised) from a zero start.
        let values = vec![10_000u64, 20_000, 20_000, 40_000];
        let shards = [ShardView {
            rows: 2,
            values: &values,
        }];
        let out = run_epoch(&params(), 2, &[0, 0], &shards).unwrap();
        assert_eq!(out.n_rows, 2);
        assert!(out.weights[0] > 0, "slope must move positive");
    }

    #[test]
    fn a_step_that_does_not_fit_is_an_error_not_a_wrap() {
        // `lr_q16 * acc` is the product that can leave `i128`: the accumulator holds a sum of
        // `err * x` and the learning rate multiplies it on top. The loss check bounds `err *
        // err`, not `err * x`, so an accumulator that the epoch accepted can still overflow
        // here. A wrap would make the update depend on build details - the one thing this
        // module exists to prevent - so it is an error.
        let mut w = vec![0i64];
        let mut grad = vec![i128::MAX];
        let out = apply_update(&mut w, &mut grad, 1, u32::MAX, 10_000);
        assert!(
            matches!(out, Err(CoreError::Overflow { .. })),
            "an update that does not fit must be an error, got {out:?}"
        );
    }

    #[test]
    fn a_zero_scale_is_an_error_not_a_division_by_zero() {
        let mut w = vec![1i64];
        let mut grad = vec![1i128];
        let out = apply_update(&mut w, &mut grad, 1, 327, 0);
        assert!(
            matches!(out, Err(CoreError::Overflow { .. })),
            "a zero denominator must be an error, got {out:?}"
        );
    }

    #[test]
    fn empty_input_is_a_shape_error_not_a_silent_noop() {
        let out = run_epoch(&params(), 2, &[0, 0], &[]);
        assert!(matches!(
            out,
            Err(CoreError::ShapeMismatch { want_rows: 1, .. })
        ));
    }

    #[test]
    fn exploding_values_overflow_instead_of_wrapping() {
        let values = vec![u64::MAX / 2, u64::MAX / 2];
        let shards = [ShardView {
            rows: 1,
            values: &values,
        }];
        assert!(run_epoch(&params(), 2, &[i64::MAX / 2, 0], &shards).is_err());
    }
}
