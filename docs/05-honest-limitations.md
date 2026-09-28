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

Nothing here has been externally audited. The Solidity has a Foundry test suite and the node
has property tests for the AIR, but "tested" ≠ "audited". Do not deploy with real value.

## 8. What is genuinely finished in this repo

- `CipherTask.sol`: complete state machine, escrow, dividend, staged withdrawal, fraud window.
- `PaymentVault.sol`: EIP-712 signed streaming channel with monotonic slices and reclaims.
- `DecryptionGate.sol`: BLS-gated, contract-restricted partial decryption.
- `packages/sdk`: end-to-end `uploadAndMonetize()` — FHEWasm encryption, Groth16 shape proof,
  IPFS/DA upload, EIP-712 binding, on-chain submission, receipt and reward tracking.
- `node/`: complete service skeleton — reorg-safe log watcher, shard store with byte budget,
  FHE engine behind a `FheEngine` trait (u32 TFHE adapter + reference CPU adapter for tests),
  Winterfell PoC circuit + prover, gRPC peer mesh, EIP-712 slice signer, dispute gossip.
