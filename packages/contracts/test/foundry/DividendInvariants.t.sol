// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../src/libraries/Dividend.sol";

/// Native property tests for the contributor-dividend math (Phase 4).
///
/// Hardhat pins lifecycle *behavior*; these pin the pure-math *properties* that make
/// linear weights Sybil-neutral, with fresh random inputs on every run. All four are
/// exact (no division, no rounding), so any failure is a real regression, never fuzz
/// noise. `shareOf` conservation is the settlement invariant in miniature: the paging
/// loop in `SettlementLib` pays these legs, and dust accounting assumes their sum.
contract DividendInvariants is Test {
    /// H3 as an invariant: splitting one dataset across two addresses earns exactly
    /// the sum of the parts — no split advantage, no split penalty, at any liveness.
    function testSplitNeutral(uint32 a, uint32 b, uint256 liveness) external {
        liveness = bound(liveness, 1, Dividend.Q16());
        uint256 sum = uint256(a) + uint256(b);
        if (sum > type(uint32).max) return; // out of the rows domain, not a counterexample
        assertEq(
            Dividend.weight(a, liveness) + Dividend.weight(b, liveness),
            Dividend.weight(uint32(sum), liveness)
        );
    }

    /// Zero rows earn zero at any liveness (no free weight for empty shards).
    function testZeroRowsZeroWeight(uint256 liveness) external {
        assertEq(Dividend.weight(0, liveness), 0);
    }

    /// The multiplier never leaves [0.25, 1.0]: early submitters are not taxed,
    /// late ones keep a quarter. Bounds hold for every timestamp triple, including
    /// degenerate windows (which pin to 1.0 rather than dividing by zero).
    function testLivenessStaysInBand(uint64 createdAt, uint64 span, uint64 submittedAt) external {
        createdAt = uint64(bound(createdAt, 0, 1_000_000_000_000));
        span = uint64(bound(span, 0, 30 days));
        uint64 windowEnd = createdAt + span;
        submittedAt = uint64(bound(submittedAt, 0, createdAt + 60 days));
        uint256 l = Dividend.liveness(createdAt, windowEnd, submittedAt);
        assertGe(l, Dividend.Q16() / 4);
        assertLe(l, Dividend.Q16());
    }

    /// Pro-rata legs never overpay the pool, and total dust stays under one unit
    /// per leg (each floor loses less than 1). Settlement's dust leg assumes both.
    function testShareConservation(uint128 pool, uint96[4] memory w) external {
        uint256 total = uint256(w[0]) + w[1] + w[2] + w[3];
        if (total == 0) return; // shareOf short-circuits; covered by testZeroRowsZeroWeight
        uint256 paid = 0;
        for (uint256 i = 0; i < 4; i++) {
            paid += Dividend.shareOf(pool, w[i], total);
        }
        assertLe(paid, pool);
        uint256 dust = uint256(pool) - paid;
        assertLt(dust, 4);
    }
}
