// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Dividend
/// @notice Pro-rata distribution of the contributor pool with sqrt-damping and a liveness
///         multiplier, plus deterministic remainder handling.
/// @dev Why sqrt-damping: if the weight were linear in `rows`, splitting one dataset across
///      400 sybil addresses would earn 400x a single honest address. With `w = sqrt(rows)`
///      the split earns `400 * 1 = 400` while the honest address earns `sqrt(400) = 20`,
///      i.e. 20x more. The weight is computed and frozen in Q16.16 at submission time
///      (see `Contribution.weightQ16`) so settlement is a single pass and liveness cannot be
///      gamed by ordering.
library Dividend {
    uint256 internal constant Q16 = 1 << 16;

    /// @notice Contribution weight: `sqrt(rows) * liveness`, in Q16.16.
    /// @param rows number of accepted rows in the contribution
    /// @param livenessQ16 Q16.16 factor in (0, 1]; 1.0 == contributed at task creation,
    ///        0.25 == contributed at/after the window deadline.
    function weight(uint32 rows, uint256 livenessQ16) internal pure returns (uint256) {
        if (rows == 0) return 0;
        return (_isqrt(uint256(rows) << 32) * livenessQ16) >> 16;
    }

    /// @notice Liveness multiplier: linear decay from 1.0 to 0.25 across the contribution
    ///         window. Rewards early commitment (capital lock) and damps end-of-window spam.
    function liveness(uint64 createdAt, uint64 windowEnd, uint64 submittedAt) internal pure returns (uint256) {
        if (windowEnd <= createdAt) return Q16; // degenerate window: no penalty
        if (submittedAt <= createdAt) return Q16;
        if (submittedAt >= windowEnd) return Q16 / 4;
        uint256 span = windowEnd - createdAt;
        uint256 offset = submittedAt - createdAt;
        return Q16 - (offset * (3 * Q16)) / (4 * span);
    }

    /// @notice Pro-rata payout of `pool` for `weightQ16` out of `totalWeightQ16`.
    function shareOf(uint128 pool, uint96 weightQ16, uint256 totalWeightQ16) internal pure returns (uint128) {
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
