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

## 2a. The re-executor set is unweighted and unbonded

The threat model's F-04 cost argument ("a ring must bond stake, so the attack costs
`≥ 0.6 × epochBudget`") describes a design that is **not** what the contracts implement.
`registerNode(taskId, blsPubKey)` is permissionless and takes no stake, and `reportDispute`
accepts any registered address; the quorum is a flat count of 3. `BLS` keys are recorded but
never checked for uniqueness or stake behind them.

Consequences, stated plainly:
- A ring of 3 cheap addresses can reach quorum and reject a valid epoch. It cannot *steal* the
  payout — the winner is still chosen by STARK validity, not by the dispute outcome — but it can
  deny a node its reward, repeatedly, at the cost of three `registerNode` calls.
- Conversely, an honest node cannot exclude Sybil reporters.

F-15 removes the version of this where the attack is *free* (a losing node redirecting the
dispute target). Making it economically unattractive still requires real work: a bond per
registered node, stake-weighted or seeded re-executor assignment, and BLS-key uniqueness. Until
that lands, treat the quorum as a liveness check against a single bad claimant, not as a
Sybil-resistant economic guarantee.

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

Nothing here has been externally audited. The Solidity has a Hardhat suite (69 tests) and the node
has property tests for the AIR, but "tested" ≠ "audited". Do not deploy with real value.

## 7a. The devnet cannot deploy the contracts

`docker compose up devnet` is broken with the pinned `@fhevm/hardhat-plugin@0.4.2`, in two
independent ways:

- `hardhat run` on the in-process network does not install the FHE mock coprocessor, so
  `CipherTask`'s constructor reverts inside `FHE.asEuint32` with no reason string.
- `hardhat run --network devnet` against a standalone `hardhat node` fails with
  `FhevmError: Provider type mismatch`.

The plugin installs the mocks only through the Hardhat subtask `fhevm:install-solidity`, which
Hardhat refuses to run from the CLI (HH312), which `hre.run` cannot resolve, and which is
restricted to the in-process network. It is reachable only through undocumented plugin internals
(`setupMockUsingHostContractsArtifacts(mockProvider, addresses, signers, paths)`), whose signature
is not part of any public API — calling it directly would trade a clear failure for a fragile one
that breaks on the next plugin bump.

What this does and does not block: the contracts are fully exercised by `hardhat test` (55 tests,
where the mock *is* installed), so the money-handling logic is verified. What is **not** available
is any deployed chain: the SDK and Rust node have never been exercised against a live CipherTask,
because no deployment of one exists in this repo. Every claim about the end-to-end path is
therefore untested.

`deploy.ts` now checks for code at the Coprocessor address up front and fails with the diagnosis,
the pinned version, and both workarounds, rather than a bare revert. Fixing this properly means
changing the plugin version; the upgrade path is real work, not a config tweak.

## 8. The Rust node does not compile, and its fold logic is unverified

`node/` does not build. `build.rs` needs `protoc` (for `tonic-prost-build`), and the crate also
needs a working C toolchain for its `aws-lc-rs`/`ring` TLS backends. Beyond that, `src/chain/`
contains hand-written alloy bindings that target APIs which do not match any released alloy
version (e.g. `Filter::selectors`, `PendingTransactionBuilder::block_id`), and `client.rs`
references a `CommitIntent` type and a `PrivateKeySigner` import that are never defined. The CI
job in `.github/workflows/rust.yml` is expected to be red for this reason.

Three logic bugs in `state.rs` were fixed by inspection — a scheduler condition inverted so the
node only offered to execute an epoch *after* somebody else had already committed, a
cross-epoch digest consensus compared against a single epoch's claim, and a self-assignment that
silently pinned `opened_at` to zero. **These fixes are unverified**: they could not be compiled or
run here. The inversion has one piece of corroborating evidence — the pre-existing unit test
`task_sealed_for_a_registered_node_produces_execute_work` asserts the correct behaviour and would
have failed against the old code, which is consistent with the crate never having been built. That
is not a substitute for `cargo test`.

`node/` should be read as a design document, not as working software.

## 9. What is genuinely finished in this repo

- `CipherTask.sol`: complete state machine, escrow, dividend, staged withdrawal, fraud window.
  Covered by 48 Hardhat tests.
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
  optionally persistent), but **no authentication, no TLS, and no garbage collection** — objects
  are never deleted, so the store only grows. Its addressing is Node's SHA3-256 while the on-chain
  pin is keccak-256, which is why `HttpShardStore.getVerified` re-hashes locally instead of trusting
  the CID. There is no test harness for this file; its behaviour was verified by running it.
- `node/`: complete service skeleton — reorg-safe log watcher, shard store with byte budget,
  FHE engine behind a `FheEngine` trait (u32 TFHE adapter + reference CPU adapter for tests),
  Winterfell PoC circuit + prover, gRPC peer mesh, EIP-712 slice signer, dispute gossip.
  **Skeleton only — does not compile, see §8.**
