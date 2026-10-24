# Dispute economics

What an attack costs, what it pays, and why the current design prices grief
instead of preventing it. All parameters are protocol constants or task params
validated on chain — see `CipherTask.sol`, `TaskParamsLib.sol`, `PaymentVault.sol`.

## Parameters (code pins)

- `DISPUTE_QUORUM = 3` — distinct reporters with verified competing commits.
- `MAX_REEXECUTION_BPS = 5000` — reporter bounty up to 50% of the epoch lock.
- `REGISTRATION_BOND = 10_000_000` (10 units at 6 dp) per node per task, locked
  for the task's life, returned after terminality unless slashed.
- Winner bond slashed into the refund on quorum reject; reporters keep theirs.

## The grief ring (the attack the design admits)

1. Attacker registers 3 addresses (3 × bond locked, BLS keys fresh — key
   generation is free, uniqueness is enforced so accidentals, not Sybils, are stopped).
2. Each commits a verified proof with a digest disagreeing with the honest claim
   (re-execution work is real: a report needs the reporter's own verified commit).
3. Quorum reached → epoch rejected: honest winner loses the epoch reward AND its
   bond; ring collects `reexecutionBps` of the lock via normal redeemable channels.

Cost: 3 bonds locked for the task duration + gas for 3 registrations, 3 commits,
3 reports. At `reexecutionBps = 5000` (buyer-set, attacker reads it on chain and
hunts high values), revenue reaches half an epoch lock per griefed epoch.
Capital returns afterwards: the grief is rentable, not burnable.

## What does NOT work for the attacker

- Copying a proof to steal the winner seat: first verified commit keeps it
  (`CommitLib`), and a report must differ from the claim.
- Copying a digest to free-ride the bounty: the report must match the reporter's
  own verified commit (`DisputeDigestMismatch`).
- Draining contributor/committee pools: settlement reserves them; `abort` reverts
  once every epoch ran (`SettleReady`).
- Inflating the reporter set to DoS finalization: registration capped
  (`MAX_NODES = 200`); settlement pages.

## What would change the model (not implemented)

Stake-weighted reporters, reporter bonds slashed on false reports, lockups that
survive terminality, random challenger selection, challenge windows. Each is a
product decision with simulations attached — not a patch. Until then: griefing
is an accepted, priced residual (F-04), and high-`reexecutionBps` tasks should
expect rings.

## Contributor weight (rows are self-declared)

`weight = rows × liveness` prices declared rows, not proven bytes — Groth16 is
not verified on-chain. Deterrence layers, in order of strength:

1. `setContributionBondPerRow`: each claimed row locks `perRow` base units
   (returned unless slashed). Lying about 100k rows locks 100k× the rate.
2. `setWeightByBond` (secure mode): weight ignores `rows` entirely
   (`effectiveRows = 1`, liveness only). No gain from inflating the claim.
3. `slashContributionBond` (buyer/manager/owner, attested): burns the bond and
   zeroes the weight share. Off-chain verification (DA bytes vs claim) is the
   buyer's duty before slashing; the chain enforces custody, not truth.
