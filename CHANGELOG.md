# Changelog

All notable changes. Counts live in CI — this file records behaviour, not test numbers.
No tags or releases are published yet; entries below are merge-PR scoped until the
first tagged release.

## Unreleased

### Security hardening (merged as #14–#19)

- Contracts (#14): `abort` reverts once every epoch ran (`SettleReady` — buyer rug
  closed); duplicate `ciphertextCid` rejected per task (`DuplicateShard`); node
  registration capped (`MAX_NODES = 200`, `nodeCount`); winner seat follows the first
  verified commit (mempool proof-copy cannot steal it); SDK ABI re-exported.
- SDK + ShardStore (#15): store addresses by real keccak-256 (was SHA3-256);
  download caps enforced while streaming with early cancel; `206` always requires
  `content-range`; relayer proofs require a `CipherTask` binding (no `ZeroAddress`);
  `getVerified` memo (bounded FIFO, copies in/out).
- Bot (#16): command dispatch uses the guard's single parse; replies go through the
  bounded send queue (`droppedSends` stays honest).
- Node (#17): full-table throttle evicts the stalest bucket (was fail-open admit);
  `mesh.max_throttle_peers` configurable (default 10000, fail-closed validation).
- Site (#18): source links track HEAD; FHE claims reframed as goal/production-path;
  lab button assembles shards; EN findings count corrected to 39; equiv fuzzes
  non-zero lanes (incl. i32 edges) and weights rejections.
- Guards (#19): `--locked` cargo builds; `links.yml` (lychee + no-pinned-`/main/`
  guard); pre-push checklist in `CONTRIBUTING.md`.
- Docs (#20): hardcoded test counts replaced with CI links.
- Trust docs (#21): `SECURITY_MODEL.md`, `TRUST_ASSUMPTIONS.md`, `CHANGELOG.md`,
  advisory triage (§7b), CodeQL for JS/TS.
- Trust round 2 (#22): README research banner, honest titles, ShardStore ETags,
  `AUDIT_SCOPE.md`.
- Release hygiene (#23): `VERSIONING.md`, `RELEASE_PROCESS.md`, evidence-pack script.
- SDK batch reads (#24): `getManyVerified` (bounded parallelism, order-preserving).
- Site honesty (#25): download buttons name the actual demo files.

### Prior base (pre-split, PR #12 lineage)

- Phase 2 execution engine wired into the worker (reference-cpu + tfhe-rs behind
  `prover`); two-node devnet agreement check in CI.
- Ubuntu 24.04 pinned across workflows; `Cargo.lock` committed.
- Contribution bonds (opt-in), commit-reveal disputes, segmented commits, settlement
  maturity gating, BLS proof-of-possession on registration.
