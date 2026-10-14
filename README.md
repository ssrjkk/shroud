# Shroud — Private, programmable ML with verifiable compute and streaming payouts

[![contracts](https://github.com/ssrjkk/shroud/actions/workflows/contracts.yml/badge.svg)](https://github.com/ssrjkk/shroud/actions/workflows/contracts.yml)
[![sdk](https://github.com/ssrjkk/shroud/actions/workflows/sdk.yml/badge.svg)](https://github.com/ssrjkk/shroud/actions/workflows/sdk.yml)
[![rust](https://github.com/ssrjkk/shroud/actions/workflows/rust.yml/badge.svg)](https://github.com/ssrjkk/shroud/actions/workflows/rust.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

**Train a model over other people's encrypted data — without ever seeing it. Sell the model /
your data's value without revealing either.**

Shroud is an fhEVM (Fully Homomorphic Encryption) app chain where data never leaves its
owner's device in cleartext. Buyers escrow a budget, nodes execute training over ciphertext,
prove the work with a STARK, and settle via streaming payment channels.

```
plaintext ──► FHEWasm ──► ciphertext ──► DA ──► node (FHE execute) ──► STARK proof
                                                                        │
buyer ──► CipherTask (escrow + FSM + payment channels) ◄──────────────┘
```

## Why this matters (2027 lens: AI × Privacy)

- **Compute on encrypted data** — the natural successor to "compute on public data". ZK proved
  *what was computed*; FHE removes the need to reveal *the input* at all.
- **Data DAOs / private data marketplaces** — sell the *value* of data and models without
  selling (or leaking) the data.
- **Agent economies** — privacy-preserving inference and model licensing are infrastructure
  they all lean on.

Shroud is the plumbing for the highest-value version of that: **train and sell a model over
private data, with settlement gated on a verified proof of compute.** Read
[`docs/05-honest-limitations.md`](docs/05-honest-limitations.md) before believing any of it —
several parts are stubbed and are called out there explicitly.

## Core properties

- **FHE end-to-end**: input rows are encrypted client-side (FHEWasm) and never decrypted; the
  final weights are committee-revealed after settlement.
- **Proof of compute**: each epoch's execution is pinned by a STARK public input binding the
  chain, task, dataset root, and prior weights. A registered node can dispute by re-executing and
  reporting a different digest; a quorum of 3 distinct reporters rejects the epoch and pays nobody
  (see the caveat in [Security status](#security-status) — this quorum is *not* Sybil-resistant).
- **Streaming payments**: `PaymentVault` settles in slices (EIP-1271) so contributors and nodes are
  paid as epochs complete. A node that has not redeemed by the end of its reward window can
  `reclaim` the remainder itself; whatever is still locked when the task settles or aborts is
  swept back into the task sub-balance and ultimately refunded to the buyer.
- **Explicit budgets**: `createTask(budget, params)` escrows exactly what the buyer names.
- **Settlement always completes**: paying every contributor in one call measured at ~584M gas
  against a 30M block limit, so a task at the contributor cap could finish every epoch and become
  permanently unsettleable — contributors' funds stuck in the vault with no route out.
  `settleFrom(taskId, cursor)` pays `SETTLE_PAGE_SIZE` (200) contributors per call; the final page
  also pays the committee and refunds the buyer.
- **Disclosure is attested, not self-declared**: a task only reaches `Disclosed` once the
  decryption committee has actually submitted `threshold` distinct partial decryptions. The buyer
  cannot shortcut the ceremony to obtain the status.

## Repository

| path | what |
|------|------|
| `packages/contracts/` | fhEVM Solidity: `CipherTask`, `PaymentVault`, `DecryptionGate`, `NetworkParams`, `ProofVerifier` + Hardhat suite (106 tests incl. fuzz, gas snapshot and byte-layout vectors) |
| `packages/sdk/` | `@shroud/sdk` — `uploadAndMonetize(data, taskId)`, EIP-712 binding, hardened DA client, on-chain key-pin check, weight files (36 tests) |
| `node/` | Rust compute node: chain follower + epoch executor (reference fixed-point engine, `tfhe-rs` behind `prover`), tonic gRPC mesh, alloy JSON-RPC, content-addressed DA (`da` feature for remote) — see the note below |
| `bot/` | Telegram ops bot: task pool, disputes, **network key rotation alerts** (35 tests, incl. stub-RPC read coverage) |
| `web/` | Project site — landing page and the full honest security posture |
| `infra/` | docker-compose devnet: fhEVM node, ShardStore (DA, size-capped + range-pull), 3 nodes |
| `docs/` | architecture, cryptography, proof-of-compute, threat model, honest limitations |

## Build & test

```sh
# contracts — the only fully working path
cd packages/contracts
npm ci && npx hardhat compile && npx hardhat test && npx tsc --noEmit   # 106 + 2 passing

# sdk
cd packages/sdk
npm ci && npm test                                                       # 36 passing

# ops bot (no token and no chain needed for the tests)
cd bot
npm ci && npm test                                                       # 35 passing
npm start                                                                # needs bot/.env

# node — needs protoc and a C toolchain (MSVC build tools or MinGW-w64)
cd node
cargo check --all-features

# site — any static server
cd web && python -m http.server 4173

# DA only (chain + DA)
cd infra
docker compose up -d --build shardstore
```

> **The `devnet` service deploys through `--network localhost`.** The fhevm plugin instruments
> a standalone node only under the `localhost` name (port 8545, chainId 31337); any other network
> name — including a custom `devnet:` entry — resolves to provider type `Unknown` and the mock
> coprocessor is never installed, so `CipherTask`'s constructor reverts with no reason.
> `deploy:devnet` passes the flag explicitly, `deploy.ts` asserts mock presence up front, and the
> contracts workflow re-runs the deploy plus a lifecycle smoke on every push. The contracts are
> also fully exercised by `hardhat test`; see [`docs/05-honest-limitations.md`](docs/05-honest-limitations.md) §7a.

> **Note on the Rust node:** `node/` executes epochs for real now. `Work::Execute`
> gathers the sealed dataset (leaf CIDs and digests as contract views, bytes from the
> content-addressed store, every payload re-hashed against its pin), runs the
> `reference-cpu` fixed-point SGD engine (`node/src/fhe.rs`) on a blocking thread,
> publishes the weight and metrics artefacts back to the store, and commits the digests
> with `commitEpoch` behind the usual double gate plus a duplicate-commit check.
> `Work::Reexecute` recomputes the same digest and re-arms the commit race on a
> mismatch, so the fold files `reportDispute` from this node's own commit. The `tfhe-rs`
> backend (`--features prover`, homomorphic SGD over `FheUint32` under a provisioned
> `CompressedServerKey`) and remote DA (`s3://`/`gs://`/`https://` via `--features da`)
> are implemented alongside, with their genuine constraints documented in the module
> docs (u32 wrapping, PBS randomness vs. cross-node byte equality).
> >
> > Historical note: the crate previously only typechecked — `cargo check --all-features`
> > was clean after fixing real API drift (`BoxedProvider` → `DynProvider`,
> > `Filter::selectors` removal, figment 0.10, the `TaskStatus::None` shadowing and the
> > reorg-taint double borrow), but `cargo test` could not link on Windows + MinGW-w64
> > (`E0463` for proc-macro deps of `tfhe`/`alloy-transport`).
> >
> > Local verification status is unchanged in kind: this sandbox's Smart App Control
> > policy blocks loading freshly compiled DLLs, so `cargo check`/`cargo test` cannot run
> > here at all (not even for `proc-macro2`). Every Rust change in this tree — including
> > the execution engine above — is verified by the `rust` CI job on Linux, never locally.
> > `cargo fmt` (parse-only) is the one Rust gate that runs in this sandbox, and it is
> > green. See [`docs/05-honest-limitations.md`](docs/05-honest-limitations.md) §8.
> >
> > Building still needs a C toolchain and `protoc` (tonic's codegen shells out).

## Security status

**This code moves funds and has not been externally audited. Do not deploy it with real value.**

What is actually enforced on chain today, and what is not:

| claim | status |
|---|---|
| Escrow accounting is internally consistent | **Enforced.** `PaymentVault` asserts `totalLocked == subBalancesTotal + channelLocksTotal` on every balance movement, and the check is O(1). |
| A reentrancy guard covers the money path | **Enforced and tested** with a hostile token that calls back mid-`transferFrom`. |
| Buyers cannot take funds owed to contributors or the committee | **Enforced.** `settle` and `reclaimUnspentEpochs` draw from disjoint pools, and reclaim reserves the contributor and committee shares. |
| Nothing is stranded by `abort` | **Enforced.** The retained work-in-progress slice is only withheld when a node actually verified an epoch, and it is paid as a redeemable channel. |
| The winner's digest is the dispute target | **Enforced.** A losing committer cannot redirect the dispute and get an honest epoch rejected for free. |
| Re-executors are paid, so disputing is rational | **Enforced.** `reexecutionBps` of the disputed lock is split between the reporters. |
| `Disclosed` means the committee decrypted the output | **Enforced.** `withdraw` requires the gate to have reached threshold. |
| A substituted FHE public key is detected before upload | **Enforced in the SDK when configured.** Pass `networkParams` + `fhePublicKeyHash` and `uploadAndMonetize` refuses on `isCurrentKey === false`. The node's twin, `enforce_key_pin` (with `fhe.public_key_hash`), compares the on-chain key hash at startup — but it is off by default. |
| The SDK cannot upload cleartext by omission | **Enforced.** `Encryptor.providesConfidentiality` is required, and the `NoopEncryptor` default is refused unless `allowUnencrypted` is set. |
| The SDK checks the chain it signs against | **Enforced.** A configured `chainId` that disagrees with the provider is a hard error. |
| The DA client treats CIDs and responses as hostile | **Enforced.** CIDs are validated before entering a request path (they come from on-chain data any contributor controls), responses are size-capped, timed out, and the store's address and digest are never trusted — `getVerified` re-hashes the bytes with keccak256 against the on-chain `ctDigest`. |
| The surface doesn't imply guarantees that don't exist | **Enforced.** Unreachable declarations that implied missing mechanisms (a slashable contribution bond, a rejected-contribution event, a finalize step that never ran) were removed rather than left to be misread. See threat model F-34. |
| Parameter rotation installs exactly what it validated | **Enforced.** `NetworkParams` binds the candidate to its hash at proposal time and re-validates at execution, so a struct that was checked is the struct that reaches `current`. |
| The verifier that gates all payouts can be swapped instantly | **Enforced.** `ProofVerifier` rotation is propose → 7-day wait → execute, and execution is permissionless so a queued rotation cannot be frozen by a compromised owner. |
| The dispute quorum is Sybil-resistant | **NOT enforced — priced, not prevented.** `registerNode` pulls a `REGISTRATION_BOND` (vault custody) and rejects reused BLS keys, and a quorum slashes the winner's bond — but locked capital returns after terminality, the quorum is still a flat count of 3, and a ring can deny a reward *and* burn an honest winner's bond. See [`docs/05-honest-limitations.md`](docs/05-honest-limitations.md) §2a. |
| A slashable contribution bond deters fake rows | **NOT implemented.** `contributionBond` does not exist anywhere in the tree. Sybil farming is mitigated only by `sqrt(rows)` weighting plus one-shard-per-address. F-01 in the threat model previously claimed otherwise and has been corrected. |
| The chain fully verifies the STARK | **NOT implemented.** Verification is sampled on chain and completed off-chain. See §3 of the limitations doc. |
| Committee majority cannot decrypt user rows | **NOT mitigated, by design.** Documented as residual F-10. |
| Participants detect a substituted FHE public key | **NOT enforced by default.** `NetworkParams` pins the key correctly on chain, and the SDK check runs only when the caller passes the pin fields. The node check (`enforce_key_pin = true` + `fhe.public_key_hash`) exists but is off unless an operator turns it on, and even then it runs once at startup. A malicious sequencer can swap the key and harvest ciphertexts undetected. The on-chain history allows *forensic* detection after the fact. See F-08. |

`docs/05-honest-limitations.md` is the document to read before trusting any of this.

## Docs

- [`docs/01-architecture.md`](docs/01-architecture.md) — system design and lifecycle
- [`docs/02-cryptography.md`](docs/02-cryptography.md) — TFHE, quantization, DKG, threshold reveal
- [`docs/03-proof-of-compute.md`](docs/03-proof-of-compute.md) — STARK + dispute protocol
- [`docs/04-threat-model.md`](docs/04-threat-model.md) — security analysis
- [`docs/05-honest-limitations.md`](docs/05-honest-limitations.md) — honest MVP scope

## Roadmap

### Phase 1: Protocol Core, SDK & Ops Skeleton (Done — see `docs/05-honest-limitations.md`)

- [x] **fhEVM contracts:** `CipherTask` FSM + escrow, `PaymentVault` streaming channels
  (EIP-712 slices, `settleFrom` paging), `DecryptionGate` threshold reveal,
  `NetworkParams` + `ProofVerifier` rotation timelocks. Hardhat suite: **102 passing**.
- [x] **Dispute path (economic, not ZK):** `registerNode` bond + flat quorum of 3 distinct
  reporters, winner-bond slash into buyer refund. Sampled on-chain check
  (`verifyProofSegmented`), full verification off-chain. NOT Sybil-resistant (§2a).
- [x] **TS SDK:** `uploadAndMonetize()`, DA client with CID validation + `getVerified`
  re-hash, key-pin and `chainId` checks. **34 passing** (incl. relayer quantize/codec/
  commitment). Real TFHE encryption in `@shroud/sdk/relayer` (node-only, Sepolia relayer);
  live leg gated behind `SHROUD_LIVE_RELAYER=1` (CI job `relayer-live`), unverified from
  this sandbox. Gap: default `Encryptor` is still `NoopEncryptor`, no browser FHEWasm build.
- [x] **Rust node skeleton (not a compute node yet):** reorg-safe watcher, state fold,
  worker (finalize/settle/dispute/redeem/reclaim/claim), gRPC mesh, local shard cache.
  `cargo check --all-features` clean, **~160–165 tests green on CI**, never run against a
  live chain. `lib.rs`/`worker.rs`: **no FHE engine and no STARK prover compiled in**
  (`tfhe`/`winterfell`/`object_store` are optional, unimported deps).
- [x] **DA service:** `infra/shardstore` content-addressed, size-capped, `Range`-capable,
  bearer-token writes, LRU catalogue. 8 tests. On-chain pin is keccak-256, store
  addresses SHA3-256 — SDK re-hashes instead of trusting CID.
- [x] **Ops:** Telegram bot (35 tests), static `web/` site, `infra/` compose devnet
  (`--network localhost` only, mock verifier/BLS).

### Phase 2: Real FHE Compute in `node/` (Execution wired; tfhe + remote DA implemented)

- [x] **`FheEngine` trait + `reference-cpu` engine (`node/src/fhe.rs`):** deterministic
  fixed-point SGD (`Enc(W)·Enc(X)+Enc(B)` structure over quantised development shards,
  gradient, `W_{t+1}`), exact integer arithmetic, golden-tested against a hand-computed
  step; `trace_digest` layout documented and sensitivity-tested.
- [x] **`Work::Execute` / `Work::Reexecute` (`node/src/worker.rs`):** sealed-input
  gathering (leaf contributors/digests as contract views, bytes verified against pins),
  `spawn_blocking` execution, DA publication, double-gated `commitEpoch` with
  duplicate-commit check; mismatch re-arms the commit race for the dispute path.
- [x] **Local DA (`node/src/da.rs`):** atomic content-addressed writes, budget
  enforcement, digest verification; same layout the mesh serves.
- [x] **`tfhe` backend (`--features prover`):** real `tfhe-rs` homomorphic SGD over
  `FheUint32` (server key via `safe_serialize`d `CompressedServerKey`, shift-scaled
  public learning rate, framed envelopes). Constraints documented in code: u32 wrapping,
  power-of-two scale, PBS randomness vs. cross-node byte equality (single-executor
  tasks until deterministic parameter sets land).
- [x] **Remote DA (`--features da`):** `object_store` fetch/store for `s3://`, `gs://`,
  `https://` with cache populate-through; loud refusal without the feature.
- [ ] **Live `commitEpoch` from this node against devnet** (operator procedure + CI
  assertion in `devnet-live`): `scripts/devnet-execute-check.ts` drives it — two live
  nodes must independently commit the same verified digest — but no green CI run has
  proven the loop yet.
- [x] **Buyer-side `shroud/weights/v1` seed publishing** (SDK `src/weights.ts`, byte-pinned
  against the node's golden vector): epoch 0 still falls back to genesis zeros with a
  warning when the pinned seed is a foreign convention.

### Phase 3: Verifiable FHE via STARKs

- [ ] **Prover + AIR:** no prover/AIR in tree today (`docs/03` §1: statement unbaked,
  `nodeId`/`n_shards`/`lr`/`w_{e+1}` unbound). Implement trace → Winterfell/SP1/RISC Zero
  circuit with the 8-field transcript (`SHROUD/PoC/v1`, chainid, CipherTask, taskId,
  epoch, ctRoot, lastWeightsDigest, traceDigest) byte-for-byte (`transcript.rs` + test-vectors).
- [ ] **Full on-chain verification:** replace sampled-segment check with recursive
  aggregation (STARK → Groth16) so "chain verified the proof" is literally true.
- [ ] **Benchmarks:** epoch latency, ciphertext expansion, gas per verify on CPU/GPU runners.

### Phase 4: Cryptoeconomic Hardening & Threshold KMS

- [ ] **Commit-reveal reports:** `commitReport(keccak(digest,salt))` → `revealReport`
  to stop mempool copy-paste by the 2nd/3rd reporter.
- [ ] **Stake-weighted re-executors:** replace flat-count-3 with seeded/staked assignment;
  slash winner on valid dispute, slash reporters on failed dispute (today: flat bond,
  priced not prevented).
- [ ] **Threshold re-encryption:** replace mock reveal with fhEVM Gateway KMS async
  re-encryption of final weights under buyer key (ECIES/NaCl box).
- [x] **Stateful invariant fuzz (`test/LifecycleFuzz.spec.ts`):** deterministic PRNG
  (3 seeds × 200 steps) over every money-moving entry point — create, contribute, seal,
  open, register, honest/divergent commits, disputes, finalize, paged settlement, bond
  release, aborts, time travel — asserting `totalLocked == accountedLocked()` and vault
  solvency after every step, success or revert, plus a terminal settle sweep. Arithmetic
  panics fail the run; ordinary reverts are coverage data (tallied per action).
- [ ] **Foundry stateful fuzz** (native `forge` invariants over the same properties,
  once a foundry toolchain is available to verify them).

## Contributing & security

- [CONTRIBUTING.md](CONTRIBUTING.md) — how to build, test and contribute.
- [SECURITY.md](SECURITY.md) — how to report a vulnerability (this protocol moves funds).

## License

MIT — see [LICENSE](LICENSE).
