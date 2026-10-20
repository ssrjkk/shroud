# Audit scope

What an external auditor is asked to review, which invariants must hold, and which
questions are already open. Frozen per release: this file describes the tree at the
tagged commit, not `main` in motion.

## In scope

- `packages/contracts/src/` — `CipherTask` (state machine, escrow, epochs, disputes,
  settlement, bonds, abort/reclaim), `payments/PaymentVault` (channels, EIP-712 slices,
  reclaims, bond custody), `DecryptionGate` (threshold reveal), `NetworkParams`
  (rotation timelock), libraries (`EpochLib`, `SettlementLib`, `BondLib`, `DisputeLib`,
  `Dividend`, `TaskParamsLib`), `zk/` verifier shims.
- `packages/sdk/src/` — encryption bindings, `uploadAndMonetize` ordering, DA client
  (`da.ts`: caps, retries, digest verification, range semantics), EIP-712 helpers,
  key-pin checks, relayer binding.
- `node/src/` — chain follower (reorg handling), executor determinism (`fhe.rs`
  fixed-point engine vs `tfhe-rs` backend), worker lifecycle, gRPC mesh throttle,
  DA client budgets, key management.
- `infra/shardstore/` — auth, range semantics, capacity/DoS budgets, addressing
  (`keccak.mjs` vs chain pin).
- `bot/src/` — allowlist auth, abuse guard, command dispatch, send queue bounds.

## Invariants the suite already pins (verify, don't re-derive)

- `totalLocked == subBalances + channelLocks` on every vault movement.
- Pull-based payouts; no recipient can block another.
- Settlement reserves contributor/committee pools (`reclaim` never touches them).
- `abort` reverts once every epoch ran; settled tasks never unwind.
- First verified commit keeps the winner seat; reports must differ from the claim.
- DA bytes re-hashed locally against the on-chain pin; caps enforced while streaming.
- Shard CIDs unique per task; one shard per address.

## Known open risks (not findings — decision points)

1. Dispute quorum is flat-3 with returned bonds: griefing priced, not prevented.
2. Contract owner is a single key (pause/treasury/abort/slash paths).
3. TFHE backend is non-deterministic across nodes: single-executor only.
4. Committee collusion at threshold decrypts rows (residual by design).
5. `node.enforce_key_pin` is on by default (a node without `fhe.public_key_hash` +
   `contracts.network_params` refuses to boot; devnet opts out explicitly). The check is at
   startup, not per epoch, so a mid-epoch rotation is caught only at the next restart.
6. One dismissed Dependabot advisory, `elliptic<=6.6.1`, a dev-toolchain transitive of
   Hardhat 2 with no patched version (see `docs/05` §7b). The other 29 were closed by
   pinned `overrides`; the open count is zero.

## Questions for auditors

1. Is there any path where `abort`, `reclaim`, `settle` or `sweepTaskChannels` pays the
   same entitlement twice or strands funds permanently?
2. Can a second verified commit (same or lower address) take another node's winner seat
   or bounty after the first-wins change?
3. Can a reporter collect `reexecutionBps` without doing the re-execution work?
4. Does any mesh/DA/gossip path admit unthrottled, unbounded, or unauthenticated work?
5. Does any SDK default let a caller commit to the wrong chain, key, task, or digest
   without a hard error?

## Deliverable expected

Findings with severity, affected commit hash, fix verification, and a residual-risk
list. Findings against documented `TRUST_ASSUMPTIONS.md` rows are out of scope unless
the code contradicts the row.
