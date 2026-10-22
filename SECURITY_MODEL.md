# Security model

What this protocol protects, from whom, and under which assumptions. Every claim
here traces to `docs/04-threat-model.md` (findings F-01…F-39), `docs/05-honest-limitations.md`,
or the test suite — nothing here is new, it is the enforceable subset in one place.

## Assets

| Asset | Where it lives | Protection |
|---|---|---|
| Buyer escrow (USDC) | `PaymentVault` sub-balances | `totalLocked == subBalances + channelLocks` asserted on every movement; pull-based payouts (a reverting recipient cannot block others) |
| Contributor rewards | Vault credits via `SettlementLib.payPage` | Pro-rata over frozen `totalWeight`; paged settlement (`SETTLE_PAGE_SIZE = 200`) so no task is unsettleable |
| Node rewards | EIP-712 reward channels (`PaymentVault`) | Monotonic slices, contract-streamer auth, maturity-gated final page (`ChannelsImmature`) |
| Committee share + buyer refund | Last settlement page | Paid only after every channel matured; dust accounted, never stranded |
| Shard plaintext | Contributor device → (FHE) → committee | Confidentiality **only** on the production path (`@shroud/sdk/relayer` + pinned key); the reference/dev path carries open bytes by design |
| Epoch integrity | `ctRoot`, `lastWeightsDigest`, `traceDigest`, STARK transcript | `proofTranscript` binds chain/task/epoch/dataset/prior weights; first verified commit keeps the winner seat; disputes via re-execution quorum (flat 3, priced — not Sybil-proof) |

## Trust boundaries

1. **Chain ↔ off-chain.** The contracts never see plaintext and never trust DA bytes:
   only `keccak256` digests cross the boundary (`ctDigest`, commitments). Anything the DA
   returns is re-hashed locally (`getVerified`) and size/time-bounded before buffering.
2. **Buyer ↔ contributors/nodes.** Money moves only through escrowed pools with fixed
   shares. The buyer cannot take contributor/committee pools (`reclaim` reserves them;
   `abort` reverts once every epoch ran — `SettleReady`).
3. **Claimant ↔ re-executors.** A commit is a claim, not a proof (mock verifier). Three
   independently verified disagreements reject the epoch; the winner's bond slashes into
   the refund. Copying a proof cannot steal the seat (first-wins) and cannot report
   (a report must differ from the claim and match the reporter's own commit).
4. **Operator ↔ machine.** The node never holds buyer funds; the operator key only pays
   gas, registers, commits and redeems its own channels. Vault approvals are exact-amount,
   never max (contributor bonds) — except the node registration bond approval, which is
   documented as one-per-lifetime because the vault can only pull `REGISTRATION_BOND`.

## What is explicitly NOT covered

- A t-of-n committee colluding off-chain (residual F-10): rows decryptable by design.
- A Sybil dispute quorum (flat 3, bonds returned): griefing is priced, not prevented.
- A malicious/complacent contract owner: single-key pause/abort (no multisig). The treasury
  moves only through a 7-day rotation (F-61) and the shape-proof requirement cannot be loosened
  at all (F-62), so the money and the dataset's integrity are not one keystroke away.
- TFHE-branch determinism across nodes: single-executor only today.
- The live `commitEpoch` from this node on production: has not happened yet.

See `TRUST_ASSUMPTIONS.md` for the assumption list and `docs/05-honest-limitations.md` §8
for the node state.
