# Benchmarks

Measured numbers, not projections. Every figure names its fixture; re-run to
refresh — nothing here is a promise about other machines or inputs.

## On-chain gas (Hardhat, 2 contributors, 1 epoch)

From `GasSnapshot.spec.ts` (`npx hardhat test test/GasSnapshot.spec.ts`):

| call | gas |
|---|---:|
| createTask | 602,429 |
| submitContribution | 295,091 |
| submitContribution #2 | 239,115 |
| sealTask | 55,787 |
| registerNode | 154,281 |
| registerNode #2 | 137,193 |
| openEpoch | 488,273 |
| commitEpoch | 240,217 |
| commitEpoch #2 | 193,028 |
| finalizeEpoch | 360,803 |
| settle | 460,246 |
| releaseBond | 89,256 |

Why paging exists: at ~117k gas per contributor, a 5000-contributor `settle` needs
~584M gas against a 30M block limit — hence `settleFrom` pages of 200
(`SettlementLib`, `SettleScaling.spec.ts` proves every page fits).

## ShardStore addressing (this machine, Node 24)

`infra/shardstore/keccak.mjs` (dependency-free port): **~10 MB/s** for 1 MiB
buffers × 20 iterations. A 64 MiB max-size object hashes in ~6 s on this box —
relevant because `PUT` addresses before storing and `getVerified` re-hashes
before trusting. Node 24, Windows, single thread; CI runners differ.
Operator consequence: the hash runs synchronously in the PUT handler, so one
max-size PUT stalls the whole event loop (all GETs/healthz) for those ~6 s.
Mitigations in place: per-connection and global in-flight budgets shed with 503,
empty objects are rejected before hashing, and idempotency replays verify by hash
instead of re-storing. For production DA, lower `MAX_OBJECT_BYTES` (e.g. 8 MiB)
and/or front with ≥2 instances.

## Not measured here (pending key material / scale)

- TFHE encrypt/execute latency, ciphertext expansion, accuracy vs plaintext,
  quantization error at scale: need a prover build (`--features prover`) plus
  network key material — none present in this repo's CI.
- Multi-epoch, multi-contributor gas: scales linearly per the table above;
  dispute-path gas (quorum `finalizeEpoch` with N reporters) grows with N
  reporter channels — capped in practice by `MAX_NODES = 200`.
