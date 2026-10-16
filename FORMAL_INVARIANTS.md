# Formal invariants

Money and state properties the suite pins on every run. Each row names the
property, where it is enforced, and the test that fails if it breaks. Counts
live in CI; this file maps properties to proof.

## Vault conservation

- `totalLocked == subBalances + channelLocks` after every vault movement.
  Enforced in `PaymentVault` (`accountedLocked` reconciliation); asserted by the
  `PaymentVault` spec and every settlement/abort/reclaim test's closing balance check.
- No recipient can block another: all payouts are pull-based credits
  (`creditFromTask` + `claim`/`redeem`), never pushed transfers.

## Settlement integrity

- Contributor and committee pools are reserved: `reclaim` computes
  `available - (userPool + committeePool)` and returns nothing when only those remain
  (`SettlementLib.reclaim`; `reclaimUnspentEpochs` specs).
- `abort` reverts once every epoch ran (`SettleReady`, `UnwindLib`); settled tasks
  never unwind (`AlreadySettled`/`SettlementBegun` guards).
- Paging pays each contributor exactly once: frozen `userPool`, cursor continuity
  (`SettleCursorMismatch`), double-settle refused (`SettleScaling.spec.ts`).
- The final page waits for reward-channel maturity (`ChannelsImmature`); committee
  and buyer legs are never paid from an incomplete balance.

## Epoch and dispute integrity

- One shard per address per task; CIDs unique per task (`DuplicateShard`).
- Proof transcript binds chain/task/epoch/dataset/prior weights
  (`proofTranscript`; `vectors.spec.ts` pins the layout the node decodes).
- First verified commit keeps the winner seat; a late copy cannot displace it.
- A report counts only from an address holding a verified commit for that epoch,
  for a digest that differs from the claim (`DisputeWithoutVerifiedCommit`,
  `DisputeAgreesWithClaim`, `DisputeDigestMismatch`).
- Quorum rejects the epoch: reporters paid from the lock, winner unpaid, winner
  bond slashed into the refund; task continues (rejected ≠ aborted).

## DA integrity

- Every fetched object re-hashed locally against the on-chain pin (`getVerified`);
  the store's own addressing is never trusted for the integrity decision.
- Size caps enforced while streaming (declared pre-check + running total with
  early cancel); range pulls require `content-range` on every `206`.
- ShardStore addresses by keccak-256 — the same digest the chain pins
  (`keccak.test.mjs` differential proofs + the empty-string spec vector).

## What is deliberately NOT an invariant

- Dispute liveness under Sybil reporters (flat quorum of 3, bonds returned).
- Owner honesty (single-key pause/treasury/abort/slash).
- Committee non-collusion at threshold.
- TFHE-branch cross-node determinism (single-executor only).

These are `TRUST_ASSUMPTIONS.md` rows, not gaps in the suite: the tests prove the
mechanism works as specified, not that the specification survives adversaries it
names as out of scope.
