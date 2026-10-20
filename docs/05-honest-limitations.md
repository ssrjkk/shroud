# Honest Limitations — read before promising anything to an investor or a buyer

This file is the counterweight to the marketing docs. Everything here is true as of the MVP
in this repo.

## 1. The FHE throughput number is the whole ballgame

| Claim people want | Reality on the MVP |
|---|---|
| "trains any model on encrypted data" | Trains **linear / logistic regression over ≤ 33 tabular features**, minibatch-8 with gradient accumulation. |
| "seconds per epoch" | ~41 s per epoch for 1 000 rows × 33 features on 8 AVX2 cores. Deeper nets are **hours to days**. |
| "production scale" | 10^3–10^4 rows. 10^6 rows × 100 features is out of reach for the u32 TFHE path by roughly 3–4 orders of magnitude. |

If Shroud is going to serve real workloads, the roadmap is: (a) GPU bootstrapping
(CUDA `cuFHE`/HPU), (b) amortised SIMD with lane reuse across features instead of batch, (c) a
**hybrid** protocol where the FHE path handles the sensitive core and cleartext handles the
rest. (c) is what production FHE-ML actually does and this repo does not implement it.

## 2. What the STARK does not prove

It does **not** prove the FHE arithmetic was correct. It proves:
- the shards were consumed in the order committed under `ctRoot`;
- the linear map over the shard digests equals the committed trace.

The FHE layer's honesty comes from the **dispute re-execution quorum**, which is economic +
deterministic-recomputation, not cryptography. A full "verify TFHE bootstraps inside a ZKVM"
design is a research project (see AUs 2024/2025 work on verifiable FHE); it is not in this repo.

## 2a. The re-executor set is unweighted; the bond prices Sybils without stopping them

`registerNode(taskId, blsPubKey)` pulls a flat `REGISTRATION_BOND` into vault custody, rejects
zero and reused BLS keys per task, and a dispute quorum slashes the *winner's* bond into the
buyer refund. `reportDispute` still accepts any registered address and the quorum is still a
flat count of 3 — there is no seeded or stake-weighted re-executor assignment.

Consequences, stated plainly:
- A ring of 3 addresses now locks 3× the bond for the task's life, plus gas and one verified
  commit each. It cannot *steal* the payout — the winner is still chosen by STARK validity —
  but it can deny a node its reward and burn the honest winner's bond with it, at the cost of
  three bonds locked and three commits computed.
- Copying a bare dispute from the mempool no longer works unmodified: disputes are filed
  commit-reveal (`commitDispute` → `reportDisputeWithSalt`, salt bound to the reporter), and
  the node files them that way. A ring must re-execute to produce its own digests.
- Conversely, an honest node cannot exclude Sybil reporters, and locked capital returns to the
  attacker after terminality: the bond is a spam price, not a burn.

Making it economically unattractive still requires real work: stake-weighted or seeded
re-executor assignment. Until that lands, treat the quorum as a liveness check against a single
bad claimant backed by a priced identity, not as a Sybil-resistant economic guarantee.

## 3. On-chain proof verification is sampled, not complete

The EVM cannot verify a 2^20 STARK in one call. MVP: the contract verifies the transcript
binding, the aggregate proof digest, and a *sampled* segment; full verification happens
off-chain in the ops path. Both entry points exist on chain now (`commitEpoch` and
`commitEpochSegmented`, the latter reaching the previously unreachable segmented verifier).
Production still needs recursive proof aggregation (recursive STARK → one Groth16) so that
"the chain verified the proof" is literally true. This is the single most important missing
piece before mainnet — and no prover exists in this repo at all (mock verifier on devnet),
so the missing half is cryptography, not plumbing.

## 4. Committee majority can decrypt rows

Documented as F-10 in the threat model. Not mitigated, only bounded and auditable. Protocol
designs that claim otherwise are usually assuming a single trusted KMS, which is worse.

## 5. Revealability is a real trade-off, not a bug

The buyer *must* be able to see the weights, otherwise they cannot use them. So the boundary
is: inputs never revealed, outputs revealed post-settlement. A determined buyer can still
memorise-infer information about individuals from the weights of a tiny dataset. Dataset
minimums (`minRowsPerShard`, `minContributors`) exist to make single-row inference hard and
are the practical mitigation. Shroud does not claim membership-inference resistance.

## 6. Sequencer trust

Encrypted mempool hides contents, not the fact that a tx exists. Censorship and reordering are
mitigated, not solved. Single devnet sequencer in this repo.

## 7. Audit status

Nothing here has been externally audited. The Solidity has a Hardhat suite (lifecycle,
dispute commit-reveal, contribution bonds, segmented commits, settlement maturity, stateful fuzz,
gas snapshot, admin controls, byte-layout vectors — counts live in CI) and the node has unit tests
including the state fold (counts live in CI), but "tested" ≠ "audited". Do not deploy with real value.

## 7b. Dependency advisories are dev-tooling transitives pinned by overrides

Triaged 2026-10-16: 30 open Dependabot alerts, all in the Hardhat 2 dev toolchain
(`undici`, `adm-zip`, `@fastify/busboy`, `tmp`, `serialize-javascript`, `uuid`,
`diff`, `elliptic`, `cookie`; 1 older `pbkdf2` item already fixed). Production trees
were and are clean — `npm audit --omit=dev` in `packages/sdk` reports zero, the bot ships only
`ethers`, and contracts deploy bytecode, not `node_modules`. Code scanning runs as
`codeql.yml` (javascript-typescript, zero open; Rust is covered by
`clippy -D warnings`, Solidity by the Hardhat suite + fuzz). Secret scanning is
clean (zero alerts).

Re-checked 2026-10-20: **zero open Dependabot advisories**, one dismissed (the
`elliptic` item below). `npm audit` in `packages/contracts` reports 16 low and
nothing above it — all of them in the same Hardhat 2 dev toolchain.

Resolved 2026-10-17: 29 of the 30 via flat `overrides` in
`packages/contracts/package.json` (`cookie 0.7.0`, `tmp 0.2.7`,
`undici 6.28.1`, `diff 8.0.3`, `serialize-javascript 7.0.5`, `uuid 11.1.1`,
`adm-zip 0.6.1`, `@fastify/busboy 3.2.2`) — Dependabot shows them `fixed`, and
`npm audit` reports 0 high/moderate. The remaining `elliptic<=6.6.1`
(GHSA-848j-6mx2-7j84, low, no patched version) is dismissed as tolerable risk:
dev-only via Hardhat 2, removable only by a Hardhat 3 migration that the pinned
`@fhevm/hardhat-plugin` (`hardhat: ^2.0.0`, no Hardhat-3-compatible release)
does not support. Full rationale lives in `SECURITY.md` ("Dependency security").

A note on the method, because an earlier revision of this section forbade it:
forcing newer transitives under Hardhat 2 was accepted only after verification —
`hardhat compile` clean, the full Hardhat suite green, devnet deploy + E2E green,
and the Rust `devnet-live` followers green, all in CI. The overrides use flat
keys (`"undici": "6.28.1"`, not range keys), because range keys break `npm ci`
on the npm 10 shipped with Node 22. The `contracts` CI job additionally gates on
`npm audit --audit-level=high`, so a new high/critical advisory fails the build
instead of waiting for the weekly Dependabot scan.

`npm audit` / Dependabot report advisories against transitive dependencies of the Hardhat 2
toolchain (`undici`, `adm-zip`, `@fastify/busboy`, `tmp`, `cookie`, `elliptic`, …). They are
real CVEs but they live in the *test runner*, not in deployed code: no advisory dependency ships
in any contract bytecode or in the SDK/runtime paths that touch funds.

What remains open-ended: the `elliptic` dismissal above and the Hardhat 3 migration
behind it. When Zama ships a Hardhat-3-compatible `@fhevm/hardhat-plugin`, migrate
(`hardhat`, `hardhat-ethers`, `hardhat-chai-matchers`, `typechain`), drop the
`overrides` that the new major absorbs, and un-dismiss the `elliptic` alert —
a rescan closes it for real once the dependency is gone from the tree.

## 7a. The devnet deploys through `--network localhost` — nothing else works

`docker compose up devnet` deploys the full contract set to a standalone `hardhat node` with
the mock coprocessor etched into it, and `scripts/devnet-e2e-check.ts` drives create → contribute
→ seal → registerNode-with-bond against that deployment. Two selection details are load-bearing,
and both have bitten before:

- The plugin recognises a standalone node **only under the `localhost` network name** (port
  8545, chainId forced 31337). A custom `devnet:` network entry resolves to provider type
  `Unknown`, on which mock setup refuses — so there is deliberately no `devnet` network in
  `hardhat.config.ts`, and `deploy:devnet` passes `--network localhost` explicitly.
- `hardhat run` without `--network` targets the ephemeral in-process network, where no mocks
  are installed and `CipherTask`'s constructor reverts with no reason string. `deploy.ts`
  asserts mock presence up front (`assertFheMocksPresent`) so that mis-selection fails with a
  diagnosis instead of a bare revert.

`infra/devnet/addresses.{json,env}` (gitignored) carry the deployment to operators and to
`CM_TASK_ADDRESS` / `CM_VAULT_ADDRESS`. The contracts workflow runs the same deploy + E2E
against a background node, so a regression here fails CI rather than surprising an operator.

What this does not give you: the verifier and BLS contracts on devnet are **mocks**
(`MockStarkVerifier` checks a magic prefix, `MockBLS` is an owner allowlist) and the chain is a
single-node EDR with unlocked accounts. What it *does* give you, proven on every push: the real
SDK uploads a real contribution to a real deployed task (`devnet:sdk` in the contracts
workflow), and the real node binary follows a real deployed chain, approves, registers and
bonds (`devnet-live` in the rust workflow). The FHE execution and STARK proving legs remain
unstubbed only in unit tests — see §8.

## 8. The Rust node builds and tests green on CI — and now executes epochs

`node/` builds and passes its suite on GitHub Actions (`cargo check` all-features and
no-default-features, `fmt --check`, `clippy -D warnings`, `cargo test` both feature sets,
`cargo build --release`). The old alloy API drift (`Filter::selectors`,
`PendingTransactionBuilder::block_id`, `BoxedProvider`, figment 0.10) is fixed, and the
three `state.rs` logic bugs fixed by inspection are covered by tests that run green
(`our_own_commit_queues_only_the_finalize`, the dispute/claim tests, the `ctRoot` round-trip
tests).

`Work::Execute` / `Work::Reexecute` are implemented, not stubbed: `node/src/fhe.rs` holds
a deterministic fixed-point SGD engine (`reference-cpu`, golden-tested against a
hand-computed gradient step) plus a `tfhe-rs` backend behind `--features prover`;
`node/src/da.rs` is the content-addressed shard/weights store (local first, `s3://` /
`gs://` / `https://` behind `--features da`); the worker verifies every payload against
its chain pin, publishes the artefacts, and commits through the double-gated
`commitEpoch` path. The 32-byte `proof` committed alongside is a `STAR`-prefixed
reference that verifies on mock-verifier chains only — a real proving system is still
Phase 3, and the reference engine trains on development (`NoopEncryptor`) shards, not
on encrypted data. Neither property is hidden: both are in the module docs.

What remains true:

- The build needs `--cfg relaxed_coherence`, and that was not committed: `alloy-signer-local`
  2.5.0 uses a `From<GenericArray<T, N>> for [T; N]` impl that `generic-array` gates behind
  that cfg (the impl is an orphan-rule violation, so the crate offers `Into` instead). The
  flag lived in one shell on 2026-10-18 and in no committed file, so `cargo check --locked
  --all-features` could not build the crate at all — and the error names a trait bound
  inside `alloy-signer-local`, never mentioning `generic-array`, which is what makes it
  hard to read. It now lives in `node/.cargo/config.toml` and in the CI `RUSTFLAGS`, and
  `infra/node/Dockerfile` copies the config into its dependency-cache stage.
- The sandbox this was developed in cannot *link* Rust (`link.exe` is absent and
  Smart App Control blocks freshly compiled DLLs), so `cargo check`/`cargo test` run on CI,
  never locally — `cargo fmt --check` (parse + layout) is the one Rust gate that runs in the
  sandbox. If CI is red, the tree is unverified — treat it as such.
- Nothing here has run against a live chain beyond the devnet-live CI job, which is
  wired to go further than register + bond (a two-node execution agreement check on a
  task with real pins) but has not reported green on that leg yet: the execution legs
  are otherwise covered by unit tests with captured fixtures, and the first
  *production* `commitEpoch` from this node is still ahead of us.
- Settlement now waits for reward maturity on its final page (`ChannelsImmature`): the node
  re-arms settlement at the earliest channel `unlockAt` instead of burning gas on the revert.
  Operator-visible consequence — committee/buyer legs land up to one reward window after the
  last epoch.
- `node.strict_weights` is on by default: the genesis-zeros fallback is a hard error for
  deployments whose buyers always publish SDK-encoded seed files. Deployments that knowingly
  serve non-file pins (devnet mocks) opt out explicitly with `strict_weights = false`.

## 9. What is genuinely finished in this repo

- `CipherTask.sol`: complete state machine, escrow, dividend, staged withdrawal, fraud window,
  opt-in contribution bonds, commit-reveal disputes, segmented commits. Covered by the Hardhat
  suite (counts live in CI), including the `test-vectors/`
  byte-layout vectors and the `Hardening` spec for the mechanisms in this paragraph.
- `PaymentVault.sol`: EIP-712 signed streaming channel with monotonic slices and reclaims, plus an
  O(1) `totalLocked == subBalances + channelLocks` invariant asserted on every balance movement.
  The reentrancy guard has its own test driven by a hostile token that calls back mid-transfer.
- `DecryptionGate.sol`: BLS-gated, contract-restricted partial decryption. `withdraw` on the
  orchestrator requires the gate to actually have reached threshold, so `Disclosed` is evidence
  rather than a self-declared status.
- `packages/sdk`: `uploadAndMonetize()` — local encryption, DA upload, digest pinning, on-chain
  submission. It now refuses to upload through an encryptor that does not encrypt, verifies the
  pinned FHE public key against `NetworkParams` when configured, refuses to sign against a chain
  that disagrees with `chainId`, and pre-validates every condition `submitContribution` enforces.
  Real encryption lives in `@shroud/sdk/relayer` (`src/relayer-encryptor.ts`, node-only):
  quantization, `{handles, inputProof}` envelope codec and row commitment are covered by the
  hermetic smoke suite, while actual TFHE encryption runs only in the gated live test
  (`test/live-relayer.test.ts`, `SHROUD_LIVE_RELAYER=1`, CI job `relayer-live`) — it has never
  passed in this sandbox (no route to the Sepolia relayer), so treat the live leg as
  CI-verified, not locally verified. Seed-weight files (`shroud/weights/v1`, `src/weights.ts`) are byte-pinned against the node's golden vector.
  Still stubbed: the default `Encryptor` is `NoopEncryptor` (there is no FHEWasm/browser
  implementation in this repo), the default `ShardStore` is in-memory, and the reference DA server
  has no authentication — it is a development service and is published on `127.0.0.1` only.

- `infra/shardstore`: a real, running service (content-addressed, size-capped, `Range`-capable,
  optionally persistent), with bearer-token writes (`AUTH_TOKEN`, reads stay open by design),
  optional TLS termination (`TLS_CERT`/`TLS_KEY`), LRU-evicting catalogue (`MAX_OBJECTS`, disk
  copies go with the entry), boot index rebuild from `DATA_DIR`, and a `DELETE` endpoint — covered
  by `server.test.mjs` in its own CI job. It addresses objects by keccak-256
  (`infra/shardstore/keccak.mjs`, differentially tested against `web/assets/crypto.js`),
  the same digest the chain pins — `PUT` returns a `digest` a third-party client can commit
  on-chain directly. `HttpShardStore.getVerified` still re-hashes locally instead of trusting
  the CID. No GC beyond LRU eviction: objects can still only be deleted explicitly or
  evicted, never expired by age.
- `node/`: chain follower, epoch executor and payment agent — reorg-safe log watcher,
  shard store with byte budget and remote backends, deterministic reference fixed-point
  engine plus `tfhe-rs` backend behind `prover`, `FheEngine`-trait execution wired into
  `Work::Execute`/`Work::Reexecute` with duplicate-commit and taint gates, gRPC peer
  mesh (per-IP inbound throttle, stream cap) with EIP-712 slice signer, commit-reveal
  disputes, settlement that waits for reward maturity. **Builds and tests green on CI,
  but the first live `commitEpoch` from this node has not happened yet — see §8.** The
  `proof` it commits verifies on mock-verifier chains only; the STARK prover is still
  Phase 3. Config refuses dead flags (`shard.aead_transport`) and zero mesh caps instead
  of silently misconfiguring.
