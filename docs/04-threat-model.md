# Threat Model

Scope: CipherMesh MVP (L3 AppChain + FHE compute + ZK proof of compute + escrow).
Out of scope: side-channel resistance of the FHE library (audited separately), L1 finality
guarantees, wallet security, the buyer's own model IP.

## 1. Adversaries

| ID | Adversary | Capability |
|---|---|---|
| ADV1 | Malicious user | submits fake/poison/duplicate/copied rows, sybil-farms rewards, downloads others' ciphertexts |
| ADV2 | Malicious compute node | returns wrong weights, fake proofs, trained on a different dataset, withholds commits for payment |
| ADV3 | Sybil node ring | k colluding compute nodes sign mutually consistent lies |
| ADV4 | Greedy buyer | aborts mid-task, steals weights without paying, changes model spec mid-run |
| ADV5 | Sequencer | reorders, censors, substitutes `s_pub`, front-runs contributions |
| ADV6 | Committee minority | ≤ t-1 members try to decrypt user rows |
| ADV7 | Committee majority | ≥ t members collude to decrypt user rows |
| ADV8 | External observer | reads DA, observes chain, tries to deanonymise contributors |

## 2. Findings

### F-01 — Sybil contribution farming (ADV1) — **Mitigated**
Contributions are 1:1 per address per task (`Task.contributorOf`), each contribution carries a
Groth16 proof of knowledge of a valid row against the buyer's `shapeRoot`, and the reward
weight is `sqrt(rows)·liveness` rather than linear, so splitting one row into 400 sybil
addresses yields `400·sqrt(1) << sqrt(400)`. A deposit of `contributionBond` is slashable on a
fraud quorum. Residual: a funded adversary with many *genuinely distinct* rows is not
preventable by any of this and is not a vulnerability — that is a bulk data purchase.

### F-02 — Proof replay across tasks (ADV2) — **Mitigated**
STARK public inputs include `chainId`, `taskId`, `epoch`, `nodeId` and `address(this)`.
`ProofVerifier` recomputes the transcript binding in Solidity. A proof lifted from another task
fails binding.

### F-03 — Trained-on-wrong-dataset (ADV2) — **Mitigated**
`ctRoot` is a public input and the AIR enforces ordered, single-consumption Merkle traversal
over shard digests. Disagreement requires ≥ 3 of 5 re-executors, who are staked nodes chosen
by the contract, not by the claimant.

### F-04 — Sybil node ring defeating the dispute quorum (ADV3) — **Partially mitigated**
`disputeReexecutors` is assigned by the contract from the staked set with a deterministic
seed `keccak(taskId, epoch, salt)`, weighted by stake, and the quorum counts *distinct
operators with distinct BLS keys*. A ring still needs to control ≥ 3/5 of the assigned
re-executors. If stake is Sybil-ed the ring also has to bond that stake, so the attack cost is
`≥ 0.6 × epochBudget` and the reward is `≤ 0.15 × epochBudget`. Not profitable, but not
proved — see F-11.

### F-05 — Weight theft without payment (ADV4) — **Mitigated**
Weights are ciphertext on DA until `requestReveal` succeeds, and `requestReveal` requires
`status == SETTLING` (all epochs settled) and a valid BLS aggregate from the committee. The
committee's `DecryptionGate` check rejects any request whose output CIDs are not in the
settled task's committed set, so there is no way to request the reveal before paying.

### F-06 — Mid-task spec change (ADV4) — **Mitigated**
`TaskParams` are frozen at creation; the spec hash is a public input to every epoch's STARK.
Changes require a new task. Reusing already-settled epochs across tasks is impossible because
`taskId` is bound.

### F-07 — Censorship by the sequencer (ADV5) — **Accepted**
An encrypted mempool plus forced inclusion windows reduces but does not eliminate censorship.
Contributors whose shards are censored lose `liveness` credit and their reward share; the
`maxContributors`/`windowEnd` bounds cap the damage. Full censorship resistance needs
fair-ordering L3s (e.g. based encrypted sequencing) — post-MVP.

### F-08 — `s_pub` substitution (ADV5) — **Mitigated**
`NetworkParams.sPubHash` is on-chain; the SDK refuses to encrypt with params whose hash
mismatches; compute nodes refuse to start. Post-substitution rows are simply unusable
(confidentiality holds, liveness lost) — the failure mode is availability, not disclosure.

### F-09 — Committee minority decryption (ADV6) — **Mitigated**
Shamir t-of-n. `DecryptionGate` additionally restricts *what* may be decrypted: a member's
`partialDecrypt` call carries the output CID and is rejected unless that CID is registered by
a settled task, so a minority cannot even meaningfully co-process user shards.

### F-10 — Committee majority decryption (ADV7) — **RESIDUAL, documented**
If `t` committee members collude they can compute the decryption of *any* ciphertext under
`s_pub`, including individual user rows. CipherMesh does not claim to prevent this. Mitigations
in place: (a) requests are contract-gated, so collusion needs `t` members to *publish* an
off-protocol request, which is publicly auditable; (b) members are bonded and their identity is
on-chain, so it is slashable/forensic; (c) the honest-majority assumption is stated in the
protocol docs so integrators can choose a different committee (see `CipherTask.committee` being
set at network init). The only cryptographic cure is FHE with access control / proxy re-encryption
with a per-recipient key (FHE-RAMP), which is a research dependency, not an MVP item.

### F-11 — Verifier availability / soundness under a bad verifier (ADV5, ADV3) — **Accepted**
`ProofVerifier.starkVerifier` is a precompile-style address. A compromised verifier accepts
anything. Mitigation is the dispute window (which does not depend on the verifier) plus
monitoring of `ProofVerified` vs off-chain re-execution disagreements. Production should
deploy a multisig-owned rotating verifier with a timelock, which is in `infra/` but flagged as
TODO in the config.

### F-12 — Deanonymisation of contributors (ADV8) — **Accepted**
Anyone can read the chain and see "address X contributed to task T for buyer B". The row
itself stays encrypted, so the leak is the *participation graph*, not the data. `liveness`
weighting increases this (early contributors are more visible). If a deployment needs
unlinkability, front contributions through a relayer or use a shielded pool — out of MVP scope,
documented rather than hidden.

### F-13 — Encrypted-output tampering in DA (ADV8) — **Mitigated**
`encWeightsCid` is a SHA-256 pin in the contract and its digest is a STARK public input. A
swapped object fails the digest check before it is ever loaded.

### F-14 — Malleability of the EIP-712 payment slices (ADV4) — **Mitigated**
Slice permits are `Permit`-style with `deadline`, `channelId`, monotonically increasing
`sliceIndex`, and a `MAX_CUMULATIVE` cap. The contract rejects `sliceIndex <= consumed` and
`amount > remainingChannel`. Re-signing an old slice is worthless. Signature malleability is
handled by using the low-s form and an explicit `s` bound check in `PaymentVault`.

## 3. Explicitly out of scope

- Padding-oracle / timing side channels inside the fhEVM coprocessor.
- Wallet compromise, key-phishing, malicious browser extensions.
- The buyer's model IP: a determined buyer can *infer* things about the dataset from the
  trained weights. This is inherent to the product, and the buyer-facing docs must say so.
- L1↔L2 data availability sampling (the MVP trusts the L3 sequencer + the DA layer for
  availability, and the STARK for correctness).
