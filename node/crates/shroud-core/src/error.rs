//! Error type for the portable core.
//!
//! Deliberately dependency-free: callers map these to their own errors. The node
//! maps each variant to the identical `shroud-node` error (same fields, same
//! message strings), so moving logic here changes no observable behaviour.

/// What can go wrong in pure compute. No I/O variants exist on purpose: nothing
/// in this crate touches the network, the chain or the clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// An `i128` accumulator exceeded its range at the named stage.
    Overflow { stage: &'static str },
    /// A shape assertion failed (features/rows/lanes).
    ShapeMismatch {
        got_rows: usize,
        got_cols: usize,
        want_rows: usize,
        want_cols: usize,
    },
    /// A byte payload failed validation. `reason` is pre-formatted by the
    /// function that raised it, so callers wrap it verbatim and messages stay
    /// identical across the node/guest/wasm builds.
    Malformed { offset: usize, reason: String },
    /// Backend-specific failure, reported with its message intact (e.g. a shard
    /// envelope this backend cannot decrypt). The message is part of the error
    /// contract: it is formatted once, in core, and wrapped verbatim by callers.
    Backend(String),
    /// A final lane did not fit `i32` (reported as its unsigned magnitude).
    LaneOverflow(u64),
}

/// Fallible core computation.
pub type Result<T> = std::result::Result<T, CoreError>;
