# Proof of Compute — What Is Actually Proved

This document exists because "we prove the node trained the model on the encrypted data"
is the claim that most FHE-market whitepapers make and almost none of them can back. Here is
exactly what Shroud proves, and what it does not.

## 1. Statement

For task `T`, epoch `e`, dataset commitment `R = ctRoot`, and prover `P`:

> There exists a computation with trace `π` such that
> 1. `π` starts from the `u32` plaintext weight vector `w_e` decoded from `encWeightsCid`,
> 2. for every shard leaf `ℓ` of the chain that folds to `R` (in ascending `leafIndex` order),
>    the shard digest is `d(ℓ)` and the prover consumed it exactly once,
> 3. the trace computes `w_{e+1} = w_e - η · ∇_w L(w_e, D)` over the *cleartext* images of
>    the shard features, where each `L` evaluation is reproduced by the AIR's arithmetic
>    constraints,
> 4. `digest(π) = traceDigest` and the prover's constant-`w_e` commitment matches
>    `wDigest` in the public input.

### What the chain actually binds

`CipherTask.proofTranscript(taskId, epoch, traceDigest)` — and therefore `StarkVerifier` — takes
exactly these values, in this `abi.encode` order (the layout `node/src/chain/transcript.rs`
reproduces byte for byte, and `packages/contracts/test-vectors/vectors.spec.ts` re-derives from a
live deployment of these contracts):

```
0: "SHROUD/PoC/v1"          (the string head, length and padded data)
1: chainid
2: address(this)            (the CipherTask instance)
3: taskId
4: epoch
5: ctRoot                   (leaf chain over the sealed dataset)
6: lastWeightsDigest        (w_e)
7: traceDigest              (digest of the trace)
```

### What the circuit would additionally bind

`nodeId`, `n_shards`, `lr`, `update_mode` and `w_{e+1}` belong to the intended statement, but the
contract cannot check them: they are not in the list above, and **no prover and no AIR for this
statement are implemented in this repository** (see `docs/05-honest-limitations.md`). A proof
verified today therefore attests to those eight values and nothing else; binding the rest means
either extending the transcript or committing them inside the proof's public-input vector and
checking that commitment on chain.

## 2. AIR

Trace columns (main trace, width 12), one row per *micro-step*:

| col | name | description |
|---|---|---|
| 0–1 | `s0,s1` | leaf-fold selector: which words of the 68-byte `_appendLeaf` preimage this row advances |
| 2–3 | `node_lo,node_hi` | current chain value `prev` (as 2 field elements, low/high 64-bit halves) |
| 4–5 | `hash_lo,hash_lo2` | output digest after the fold step |
| 6 | `shard_digest_lo` | digest of the leaf being folded in |
| 7 | `feat[0]` | feature 0 of the current micro-batch |
| 8 | `feat[1]` | feature 1 |
| 9 | `acc` | running accumulator `∑ feat·w` (mod p) |
| 10 | `step_sel` | 1 on the row where a shard boundary is crossed |
| 11 | `is_last` | 1 on the final row |

Constraints of the AIR **as designed** — no prover and no circuit for them exist in this
repository (see `docs/05-honest-limitations.md`); this section is the specification the
`nodeId`-binding decision in §1 refers back to, not a description of running code:

1. **Leaf-fold integrity** — for each folded leaf: `keccak(prev ‖ leafIndex ‖ cid)`, the same
   68-byte preimage `CipherTask._appendLeaf` hashes on chain, with the leaf's words selected by
   `s0/s1` as the row advances the chain.
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
against the segment's public-input range.

> **Not implemented.** `IProofVerifier.verifyProofSegmented` and a `ProofVerifier` implementation
> of it exist, but `CipherTask.commitEpoch` calls `verifyProof` and only `verifyProof`, so this path
> is unreachable from the only entry point that submits proofs. A 32-byte segmented Merkle root
> submitted through `commitEpoch` would in any case be sent to the single-segment verifier and
> rejected. There is also no STARK prover in this repo, so there is nothing today that could produce
> either proof shape. Treat the paragraph above as the design intent, not as shipped behaviour;
> see `05-honest-limitations.md` and threat model F-33.

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
