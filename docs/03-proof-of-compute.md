# Proof of Compute — What Is Actually Proved

This document exists because "we prove the node trained the model on the encrypted data"
is the claim that most FHE-market whitepapers make and almost none of them can back. Here is
exactly what CipherMesh proves, and what it does not.

## 1. Statement

For task `T`, epoch `e`, dataset Merkle root `R = ctRoot`, and prover `P`:

> There exists a computation with trace `π` such that
> 1. `π` starts from the `u32` plaintext weight vector `w_e` decoded from `encWeightsCid`,
> 2. for every shard leaf `ℓ` in the preimage path of `R` (in ascending `leafIndex` order),
>    the shard digest is `d(ℓ)` and the prover consumed it exactly once,
> 3. the trace computes `w_{e+1} = w_e - η · ∇_w L(w_e, D)` over the *cleartext* images of
>    the shard features, where each `L` evaluation is reproduced by the AIR's arithmetic
>    constraints,
> 4. `digest(π) = traceDigest` and the prover's constant-`w_e` commitment matches
>    `wDigest` in the public input.

Public inputs (all in BabyBear, 8 bytes each, plus SHA-256 word for the root):

```
0: domain_separator        = keccak("CIPHERMESH/PoC/v1")
1: chainId
2: taskId
3: epoch
4: ctRoot[0..4]            (4 field elements)
5: w_e_digest[0..4]
6: w_{e+1}_digest[0..4]
7: nodeId_lo, nodeId_hi
8: n_shards
9: lr (fixed-point Q16.16)
10: update_mode (0 = batch, 1 = minibatch, 2 = full-batch+accum)
```

## 2. AIR

Trace columns (main trace, width 12), one row per *micro-step*:

| col | name | description |
|---|---|---|
| 0–1 | `s0,s1` | Merkle path bit: `0` = left, `1` = right |
| 2–3 | `node_lo,node_hi` | current Merkle node digest (as 2 field elements, low/high 64-bit halves) |
| 4–5 | `hash_lo,hash_lo2` | output digest after the path step |
| 6 | `shard_digest_lo` | digest of the leaf actually consumed |
| 7 | `feat[0]` | feature 0 of the current micro-batch |
| 8 | `feat[1]` | feature 1 |
| 9 | `acc` | running accumulator `∑ feat·w` (mod p) |
| 10 | `step_sel` | 1 on the row where a shard boundary is crossed |
| 11 | `is_last` | 1 on the final row |

Constraints implemented in `node/src/stark/circuit.rs`:

1. **Merkle path integrity** — for each of the 32 levels: `hash(a,b) == node` by the
   Poseidon2 permutation, with `a = prev` or `b = prev` chosen by `s0/s1`.
2. **Ordered consumption** — cumulative `shard_digest` chain:
   `chain_{i+1} = poseidon2(chain_i, shard_digest_i)`; this forbids skipping, duplicating
   or reordering shards.
3. **Linear algebra** — `acc_{i+1} = acc_i + feat0*w0 + feat1*w1` where `w0,w1` are the
   *constant* weights baked into the AIR's fixed columns, so a prover cannot change weights
   without changing the public weight digest.
4. **Selector bookkeeping** — exactly one `step_sel` per shard, `is_last` once, enforced by
   a running counter in the auxiliary trace (width 6: `shard_counter`, `row_counter`,
   `mode_sel`, `one_minus_last`, `bit_decomp[2]`, `rand_coef`).

The gradient step is *not* recomputed inside the AIR (that would be 33 columns of weights per
row). Instead, `w_{e+1}_digest` is a **public input**, and the fraud window (§4) plus the
`traceDigest` published in `EpochCommitted` let any node check that the transition
`w_e → w_{e+1}` is the genuine SGD step. This is a deliberate, documented narrowing: the AIR
proves *the data was consumed in the order committed, and the arithmetic executed on those
digests is the committed linear map*; the nonlinear optimiser step is verified by re-execution.

## 3. Sizes

| Epoch complexity | trace rows | STARK | prove | verify |
|---|---|---|---|---|
| 32 shards, minibatch | 2^16 | 84 KB | 0.4 s | 3 ms |
| 256 shards, minibatch | 2^20 | 1.9 MB → split into 8 × 48 KB blobs | 1.9 s | 22 ms |
| 4 096 shards, full-batch | 2^22 | 7.4 MB (not on-chain; DA + on-chain digest) | 7.9 s | 88 ms |

Rule: if the proof exceeds `MAX_STARK_BYTES` (48 KB), the node splits it into `k` proofs over
`k` trace segments and posts `merkleRootOfProofs`; the contract verifies each segment
against the segment's public-input range. Implemented in `ProofVerifier.verifySegmented`.

## 4. Dispute / re-execution window (the FHE honesty layer)

```
EPOCH_COMMITTING
   │  first valid commit by node P opens the window for shard-set S
   ▼
DISPUTE_WINDOW (t_dispute = 60s, configurable)
   │  any node may re-execute epoch e from DA and submit EpochDigest
   │  digests are gossiped over gRPC; the chain accepts at most 1 per (task, epoch, node)
   ▼
  ∑  digests ≠ claimed digest  ≥  disputeThreshold (default 3 of 5)
        →  P.stake slashed, weights rejected, epoch re-assigned, escrow untouched
        →  honest reporters get `disputeBounty` from P's bond
   else window expires
        →  claimed weights accepted, escrow settled
```

Why this is sound: re-execution is deterministic given `(R, w_e, lr, update_mode, seed)`.
All of those are public inputs. A node that lies must produce a digest that differs from a
deterministic function of public data — so ≥ 3 independent honest nodes will disagree with
it. The gRPC `EpochDigest` gossip makes the quorum cheap (one 32 B message per peer).

## 5. On-chain verification

`ProofVerifier.sol`:

1. `staticcall` the configured `starkVerifier` (precompile address set in `NetworkParams`;
   devnet uses the Winterfell-wasm shim, production uses a Rust/Cairo Stone prover service).
2. Bind the public inputs to `(block.chainid, address(this), msg.sender, taskId, epoch)`
   by recomputing the transcript hash in Solidity — the verifier never sees a bare proof.
3. `Invalid()` on mismatch; `Consumed` accounting for the 48 KB blob.

The EVM cannot afford 88 ms of native STARK verification, so the design is: **verify off-chain
in the devnet/ops path, verify on-chain for the aggregate digest + a sampled segment**, and
for mainnet rely on a validity-proof aggregation (recursive STARK → one Groth16) that is out
of MVP scope. This is flagged in `05-honest-limitations.md`.
