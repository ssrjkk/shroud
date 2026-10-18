// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Dividend
/// @notice Pro-rata distribution of the contributor pool with liveness multiplier,
///         plus deterministic remainder handling.
/// @dev Linear weights (w = rows * liveness): splitting a dataset across N addresses earns
///      exactly the same as one address with all N rows, so sybil has no economic advantage
///      beyond the per-address gas cost. The liveness multiplier (1.0 → 0.25) still rewards
///      early commitment. Anti-sybil enforcement is handled by minRowsPerShard, gas costs,
///      and the optional contribution bond (BondLib), not by weight distortion.
///
///      The three entry points are `external` so their bodies link out of `CipherTask`: they are
///      stateless pure math, and `shareOf` runs once per contributor inside a paged settlement
///      loop, so inlining it bought `CipherTask` bytecode it does not need. `Hardhat`'s
///      `deployContract` resolves the links; see `scripts/deploy.ts`.
library Dividend {
    uint256 public constant Q16 = 1 << 16;

    /// @notice Contribution weight: `rows * liveness`, in Q16.16.
    /// @param rows number of accepted rows in the contribution
    /// @param livenessQ16 Q16.16 factor in (0, 1]; 1.0 == contributed at task creation,
    ///        0.25 == contributed at/after the window deadline.
    /// @dev H3 fix: changed from sqrt(rows) to linear. The original sqrt was claimed to damp
    ///      sybil but actually gives massive advantage to large sybil rings (400 rows split
    ///      as 400×1 earns 400 vs honest sqrt(400)=20 — a 20x disadvantage for honest).
    ///      Linear weight makes splitting neutral; real sybil deterrence comes from minRows
    ///      and bonds.
    function weight(uint32 rows, uint256 livenessQ16) external pure returns (uint256) {
        if (rows == 0) return 0;
        return uint256(rows) * livenessQ16; // linear: split has no advantage, no disadvantage
    }

    /// @notice Liveness multiplier: linear decay from 1.0 to 0.25 across the contribution
    ///         window. Rewards early commitment (capital lock) and damps end-of-window spam.
    function liveness(uint64 createdAt, uint64 windowEnd, uint64 submittedAt) external pure returns (uint256) {
        if (windowEnd <= createdAt) return Q16; // degenerate window: no penalty
        if (submittedAt <= createdAt) return Q16;
        if (submittedAt >= windowEnd) return Q16 / 4;
        uint256 span = windowEnd - createdAt;
        uint256 offset = submittedAt - createdAt;
        return Q16 - (offset * (3 * Q16)) / (4 * span);
    }

    /// @notice Pro-rata payout of `pool` for `weightQ16` out of `totalWeightQ16`.
    function shareOf(uint128 pool, uint96 weightQ16, uint256 totalWeightQ16) external pure returns (uint128) {
        if (totalWeightQ16 == 0) return 0;
        return uint128((uint256(pool) * uint256(weightQ16)) / totalWeightQ16);
    }

    /// @notice Largest integer square root (Babylonian). Reverts-safe for 2^256-1.
    function _isqrt(uint256 x) internal pure returns (uint256 y) {
        if (x == 0) return 0;
        y = x;
        uint256 z = (x >> 1) + 1;
        unchecked {
            while (z < y) {
                y = z;
                z = (x / z + z) >> 1;
            }
        }
    }
}
