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
- Conversely, an honest node cannot exclude Sybil reporters, and locked capital returns to the
  attacker after terminality: the bond is a spam price, not a burn.

Making it economically unattractive still requires real work: stake-weighted or seeded
re-executor assignment. Until that lands, treat the quorum as a liveness check against a single
bad claimant backed by a priced identity, not as a Sybil-resistant economic guarantee.

## 3. On-chain proof verification is sampled, not complete

The EVM cannot verify a 2^20 STARK in one call. MVP: the contract verifies the transcript
binding, the aggregate proof digest, and a *sampled* segment; full verification happens
off-chain in the ops path. Production needs recursive proof aggregation (recursive STARK →
one Groth16) so that "the chain verified the proof" is literally true. This is the single
most important missing piece before mainnet.

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

Nothing here has been externally audited. The Solidity has a Hardhat suite (102 tests plus the
`test-vectors/` byte-layout vectors) and the node has 165 unit tests including the state fold,
but "tested" ≠ "audited". Do not deploy with real value.

## 7b. Dependency advisories are dev-tooling transitives blocked on upstream majors

`npm audit` / Dependabot report advisories against transitive dependencies of the Hardhat 2
toolchain (`undici`, `adm-zip`, `@fastify/busboy`, `tmp`, `cookie`, `elliptic`, …). They are
real CVEs but they live in the *test runner*, not in deployed code: no advisory dependency ships
in any contract bytecode or in the SDK/runtime paths that touch funds.

Fixing them within semver (`npm update`) is done whenever it resolves; the remainder require
major bumps of the toolchain itself — Hardhat 2 → 3 (`hardhat`, `hardhat-ethers`,
`hardhat-chai-matchers`, `typechain`) — which the pinned `@fhevm/hardhat-plugin` does not
support (its latest line peers `hardhat: ^2.0.0`, and no Hardhat-3-compatible plugin release
exists). So the advisories stay open until Zama ships one, at which point the Hardhat 3
migration unblocks the whole family at once. Do not "fix" them with `overrides` pinning
transitives outside their parents' ranges: forcing a newer `undici` under Hardhat 2 risks the
test runner's HTTP layer in ways the suite cannot meaningfully cover.

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

## 8. The Rust node now builds and tests green on CI — with caveats

`node/` builds and passes its suite on GitHub Actions (`cargo check` all-features and
no-default-features, `fmt --check`, `clippy -D warnings`, `cargo test` both feature sets,
`cargo build --release`): 160 tests, all passing. The old alloy API drift (`Filter::selectors`,
`PendingTransactionBuilder::block_id`, `BoxedProvider`, figment 0.10) is fixed, and the three
`state.rs` logic bugs fixed by inspection are now covered by tests that run green
(`our_own_commit_queues_only_the_finalize`, the dispute/claim tests, the `ctRoot` round-trip
tests).

What remains true:

- The machine this was developed on has **no Rust toolchain at all** (no `cargo`, no `rustc`),
  and Windows + MinGW-w64 cannot link `cargo test` (`tfhe` and `alloy-transport` fail with
  `E0463: can't find crate` for proc-macro deps `strum`, `auto_impl`). So every Rust change
  here is verified by CI, never locally. If CI is red, the tree is unverified — treat it as
  such.
- Nothing here has run against a live chain: the fold, watcher, worker and mesh server are
  exercised by unit tests with captured fixtures, not by a node following a real CipherTask
  (§7a explains why no such deployment exists in this repo).

## 9. What is genuinely finished in this repo

- `CipherTask.sol`: complete state machine, escrow, dividend, staged withdrawal, fraud window.
  Covered by the Hardhat suite (96 tests across the contracts, including the `test-vectors/`
  byte-layout vectors).
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
  Still stubbed: the default `Encryptor` is `NoopEncryptor` (there is no FHEWasm/relayer
  implementation in this repo, so the FHE half of the SDK is an interface with no
  implementation behind it), the default `ShardStore` is in-memory, and the reference DA server
  has no authentication — it is a development service and is published on `127.0.0.1` only.

- `infra/shardstore`: a real, running service (content-addressed, size-capped, `Range`-capable,
  optionally persistent), with bearer-token writes (`AUTH_TOKEN`, reads stay open by design),
  optional TLS termination (`TLS_CERT`/`TLS_KEY`), LRU-evicting catalogue (`MAX_OBJECTS`, disk
  copies go with the entry), boot index rebuild from `DATA_DIR`, and a `DELETE` endpoint — covered
  by `server.test.mjs` (8 tests) in its own CI job. Its addressing is Node's SHA3-256 while the
  on-chain pin is keccak-256, which is why `HttpShardStore.getVerified` re-hashes locally instead
  of trusting the CID. No GC beyond LRU eviction: objects can still only be deleted explicitly or
  evicted, never expired by age.
- `node/`: complete service skeleton — reorg-safe log watcher, shard store with byte budget,
  FHE engine behind a `FheEngine` trait (u32 TFHE adapter + reference CPU adapter for tests),
  Winterfell PoC circuit + prover, gRPC peer mesh, EIP-712 slice signer, dispute gossip.
  **Builds and tests green on CI (160 tests), but nothing here has run against a live chain —
  see §8.**
