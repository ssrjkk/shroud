# Threat Model

Scope: Shroud MVP (L3 AppChain + FHE compute + ZK proof of compute + escrow).
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

### F-01 — Sybil contribution farming (ADV1) — **Partially mitigated**
Contributions are 1:1 per address per task (`Task.contributorOf`), each contribution carries a
Groth16 proof of knowledge of a valid row against the buyer's `shapeRoot`, and the reward weight
is `sqrt(rows)·liveness` rather than linear, so splitting one row into 400 sybil addresses yields
`400·sqrt(1) << sqrt(400)`. Residual: a funded adversary with many *genuinely distinct* rows is not
preventable by any of this and is not a vulnerability — that is a bulk data purchase.

*Update:* an opt-in bond now exists where none did. `setContributionBondRequirement` (buyer or
update manager, only while the window is open, capped at `MAX_CONTRIBUTION_BOND`) makes every
`submitContribution` pull that bond into the orchestrator's custody; `releaseContributionBond`
returns it once the task can no longer slash it, and `slashContributionBond` forfeits it to the
treasury — never to the buyer, so slashing cannot become a revenue stream — while marking the
contribution `slashed` so `settle` skips its reward share. The slash path closes once the task is
settled or terminal, so post-hoc burns of honest contributors' unreleased bonds revert. The default requirement is zero, so
tasks created before this mechanism behave exactly as before. What the bond does **not** do is
prove fraud on chain: there is no on-chain test for "this shard is poison", so the slash is an
attested operator action with an event trail, not a fraud proof.

### F-02 — Proof replay across tasks (ADV2) — **Mitigated**
The STARK transcript (`CipherTask.proofTranscript`) is bound to `chainId`, `address(this)`,
`taskId`, `epoch`, `ctRoot`, `lastWeightsDigest` and the trace digest itself. `ProofVerifier`
recomputes that binding in Solidity, so a proof lifted from another task fails binding. The
committing node's identity is *not* one of the bound values: whoever holds a valid proof for
these inputs can be its committer, which the dispute protocol has to absorb instead of the
binding.

### F-03 — Trained-on-wrong-dataset (ADV2) — **Partially mitigated**
`ctRoot` is bound into the transcript, so an epoch proved against a different dataset fails the
binding check. What does **not** exist is the AIR constraint that re-folds the shard digests in
`leafIndex` order: the chain verifies a transcript, not a fold, and the ordered re-fold lives in
`node/src/chain/transcript.rs`, which nothing on chain checks. Reaching the dispute quorum
rejects the epoch and pays nobody, so a wrong-dataset epoch is recoverable, but only by
re-execution — see §3 of the limitations doc for the sampled-verification caveat.

*Known deviation from the original design:* re-executors are **not** assigned from a staked set
with a seeded, stake-weighted selection. `reportDispute` accepts any node that called
`registerNode` for the task, and the quorum is a fixed count of 3 distinct such addresses. So the
"≥ 3/5 of contract-assigned re-executors" cost argument in F-04 does **not** hold on this
implementation, and a Sybil ring that registers N addresses and runs them cheaply is materially
cheaper than the analysis there assumes. F-15 removes the free griefing path, but stake-weighted
assignment and a bond are still genuinely missing and are called out in
`05-honest-limitations.md` rather than papered over here.

### F-04 — Sybil node ring defeating the dispute quorum (ADV3) — **Partially mitigated**
*Corrected:* this finding previously described stake-weighted, contract-assigned re-executors
(`keccak(taskId, epoch, salt)` selection, a bond, "≥ 3/5 of the assigned re-executors", attack
cost `≥ 0.6 × epochBudget`). **The assignment half is still not implemented.** What the contracts
now do about the cost half:

- `registerNode(taskId, blsPubKey)` pulls `REGISTRATION_BOND` (10 CMUSD at 6 dp, vault custody
  as its own invariant term) and rejects zero and already-used BLS keys for the task.
- A dispute quorum slashes the *winner's* bond into the task sub-balance (buyer refund);
  reporters keep theirs.
- `reportDispute` still accepts any registered address, and the quorum is still a flat
  `_disputeCount >= 3` over distinct registered addresses.

So a ring of three addresses now locks 3× the bond for the task's whole life *plus* gas and
compute (each reporter still needs its own verified commit), and a lying winner additionally
forfeits its bond on rejection. What the bond does **not** do: it is locked capital, not burned
capital — an attacker gets it back after terminality. It prices grief; it does not prevent it.
A ring can still deny an honest node its reward, and now also burn the honest winner's bond
alongside the reward (the chain cannot tell a lying winner from a lying quorum). Seeded or
stake-weighted re-executor assignment is still genuinely missing and is called out in
`05-honest-limitations.md` rather than papered over here.

*Update — narrower without changing the count:* `commitDispute` + `reportDisputeWithSalt`
hide the digest until the reveal, so a bare `reportDispute` in the mempool can no longer be
copied by a ring that never re-executed (the salt is bound to the reporter; the bare path
closes while a commitment is open). `registerNodeWithPop` binds the BLS key to a live signer
(EIP-191 ECDSA over task, key, node, chain, contract), which at least proves one live signer
per identity and ends key-theft repudiation for adopters. Neither changes the flat quorum of 3.

F-15 removes the variant where the attack is free.

### F-15 — Dispute-target hijack by a losing committer (ADV2) — **Mitigated**
`_claimedDigest` is the digest the dispute window is measured against, and it must therefore be
the *winner's* digest. It was previously written by every committer, so the **last** commit won
the slot regardless of who actually won the epoch. A losing node could then submit a valid STARK
carrying a different `traceDigest` and move the dispute target onto its own value. Because epoch
execution is deterministic, every honest re-executor reproduces the *winner's* digest; they would
all file what the contract read as disagreements, reach quorum, and get an honest epoch rejected —
for free, since the liar commits no extra gas. `_claimedDigest` is now written only inside the
branch that installs a new winner. Regression: *"does not let a losing committer redirect the
dispute away from the winner"*.

### F-16 — Buyer drains the contributor pool via `reclaimUnspentEpochs` (ADV4) — **Mitigated**
The early-refund path returned the task's whole sub-balance. After the last epoch that balance is
*mostly* the contributor and committee pools (they are only distributed in `settle`), so a buyer
could call `reclaimUnspentEpochs` and take 100% of the escrow, leaving `settle` to distribute
nothing — contributors who supplied the data would be paid zero from a task that completed
normally. The function now reserves `userPool + committeePool` and returns only the unspent node
pool, and is a no-op when nothing above that line remains. Regression: two cases in
*"governance recovery"*, including one that then settles and asserts everyone is paid in full.

### F-17 — Stranded escrow on abort (ADV4, ADV2) — **Mitigated**
`abort` withheld `ABORT_LOCK_BPS` (20%) of the open epoch's lock "for a node that may have been
working" but never paid it to anyone, and `abort` is terminal — no later call can move that
balance. Every abort therefore burned 20% of the epoch lock. Retention is now conditional on an
actual *verified* commit existing for the epoch, and the retained slice is opened as a normal
redeemable reward channel. An abort with no commit refunds the buyer in full. Regression:
*"strands nothing when aborted with an open but uncommitted epoch"* and
*"retains a redeemable slice for a node that verified an epoch before the abort"*.

### F-18 — Unpaid re-executors (ADV2 economics) — **Mitigated**
`finalizeEpoch` documented that "reporters are paid out of the lock so that reporting is
rational", but no reporter was ever paid and `reexecutionBps` was dead configuration. Reporting
costs real gas plus a full re-execution, so the only rational strategy was to accept every claim
unchallenged, which collapses the dispute window to nothing. Reporters now receive
`reexecutionBps` of the disputed lock, split equally with the division remainder to the first
reporter, as ordinary ERC-1271 redeemable channels. Bounty channels deliberately do **not** write
`_epochChannel[epoch]`, so an indexer cannot mistake a bounty recipient for the epoch winner.
Regression: *"pays reporters a bounty from the disputed lock, and nobody is paid as winner"*.

### F-19 — Committee bootstrap with duplicate members (ADV6) — **Mitigated**
`DecryptionGate.initialize` accepted repeated addresses in `members`, so `threshold` could be
satisfied by fewer than `t` *distinct* members — or the gate could become impossible to complete
at all, since `hasSubmitted` blocks a member from submitting twice. `initialize` is one-shot and
gates every past and future reveal, so a bad bootstrap is not recoverable in place. Duplicate
members are now rejected.

### F-20 — Unrestricted grant of encrypted-state decryption (ADV8) — **Mitigated**
`grantStateAccess(account)` had **no access control whatsoever**. Any address could hand any
other address a decryption grant over the four orchestration handles, including `_encState` — the
buyer's encrypted loss curve, remaining noise budget and epoch checkpoint. That is not the model
weights and not any contributor's rows, so it is not a key-compromise-class break, but it is
unprivileged access to buyer telemetry. The signature is now `grantStateAccess(taskId, account)`
and the grant is restricted on the **target**: it must be the buyer, the update manager, the
owner, or a node registered for that task. Restricting the target rather than only the caller is
deliberate — otherwise the buyer could widen the ACL to an arbitrary third party, which is the
same leak by another route. Regression: *"refuses to grant decryption of the orchestration state
to an unrelated address"*.

### F-21 — Buyer can skip the threshold-decryption ceremony (ADV4) — **Mitigated**
`CipherTask.withdraw` checked only `status == Revealing`, which `requestReveal` sets as soon as a
valid committee BLS signature is presented. The buyer could therefore call `withdraw` immediately
and reach `Disclosed` with **zero** partial decryptions submitted. The plaintext weights are
delivered off-chain, so the buyer could only shoot themselves in the foot — but `Disclosed` is the
protocol's on-chain attestation that the committee decrypted this output, and skipping the
ceremony made that status worthless as evidence while leaving no on-chain record that a threshold
was ever met. `withdraw` now requires `DecryptionGate.revealCompleted(taskId)`, which is true only
once `threshold` *distinct* members have submitted and the combine was recorded. This also
un-deaded `canFinalize`, whose `&& !combined` guard contradicted the auto-combine in
`submitPartialDecryption`. Regression: *"withdraw is blocked while the gate has not reached
threshold"*, which asserts that not even the owner can shortcut it.

### F-22 — Contributors shortchanged by un-redeemed reward channels (ADV2) — **Mitigated**
`sweepTaskChannels` deliberately leaves a channel open until its 7-day reward window matures, so
that a node which delivered a valid proof is not paid nothing merely because settlement ran first.
The final settlement page now *waits* for that maturity instead of paying the committee/buyer
legs from an incomplete balance: `settleFrom` reverts `ChannelsImmature(taskId)` on the last page
while any channel of the task is still redeemable, and succeeds once the window passes (the sweep
at the top of the page then recovers everything). Earlier pages are unaffected — contributor
shares come from the pool frozen by the first page, which node locks can never eat into — so
settlement still progresses while it waits; only the terminal legs defer. Operators and the node
itself treat this as a scheduled wait, not a failure: the node re-arms settlement at the earliest
maturity instead of burning gas on the revert, and `settleToCompletion` explains the remedy.

The one behavioural cost is stated plainly: a task's committee cut and buyer refund now land up
to one reward window after the last epoch. The money was never lost (it sat in redeemable
channels), but it is deferred, and this makes the deferral explicit and bounded rather than a
silent haircut.

### F-23 — SDK could upload cleartext rows by omission (ADV1) — **Mitigated**
`ShroudSdk` defaulted `encryptor` to `NoopEncryptor`, which serialises the plaintext `f64`s
straight into the payload. Nothing in the payload marks it as unencrypted, and the resulting CID
is committed on chain exactly like a real ciphertext — so a caller who simply forgot to pass an
encryptor would publish a contributor's rows in cleartext with no downstream signal at all. The
`Encryptor` interface now requires `providesConfidentiality: boolean`, and `uploadAndMonetize`
refuses to run when it is false unless the caller passes `allowUnencrypted: true`. The refusal
happens before any network call, so a misconfiguration cannot leak data even when the task itself
is invalid. Regression: *"ShroudSdk refuses to upload through an encryptor that does not encrypt"*.

### F-24 — Client could sign against the wrong chain (ADV4) — **Mitigated**
`SdkConfig.chainId` was accepted, stored, and then ignored, and the private `ensureChainId()` that
would have read it was never called — dead code from the start. `SdkConfig.provider` was likewise
accepted and never stored. So nothing ever compared the configured chain against the one the
provider was serving. The escrow amount, the task-id space and every EIP-712 slice digest are
chain-specific, so a mismatch yields transactions that look valid and land on the wrong network —
especially dangerous on a devnet that shares contract addresses with a real deployment.
`ensureChainId()` is now called on every upload, memoises the resolved id, honours `cfg.provider`
as the fallback, and throws when a configured `chainId` disagrees with the provider. Regression:
*"ShroudSdk refuses a mismatched chainId"*.

### F-26 — Attacker-controlled `cid` reached the DA request path unvalidated (ADV8) — **Mitigated**
`HttpShardStore.get` interpolated `cid` straight into the URL path, and `ciphertextCid` originates
from on-chain state that **any contributor controls**. A crafted CID could therefore rewrite the
request path (`../`, `//host/x`, `a?b`, `a#f`) and send the node somewhere the DA was never asked
to point at. Impact is bounded by the DA being a dumb blob store, but the client is exactly the
component that must not treat on-chain strings as trusted input. All CIDs are now validated
(`assertSafeCid`) against a charset that admits hex and base58 while excluding path separators,
query/fragment markers and relative-path tokens, and the store's *returned* CID is validated too
before it can be committed. Regression: `"assertSafeCid rejects path traversal and URL injection"`.

### F-27 — DA responses trusted for size, address and integrity (ADV8) — **Mitigated**
Three separate problems in the same client, all from treating the store as honest:

- *Size.* Neither `put` nor `get` bounded the payload. A malicious or broken store could stream an
  unbounded body and OOM the node, which has an epoch deadline to meet. There is now a
  `maxObjectBytes` cap on upload, on the declared `Content-Length` before buffering, and on the
  buffered result.
- *Address.* `put` returned whatever `cid` the store sent, to be committed on-chain unexamined.
- *Integrity.* The docs told re-executors to re-verify `ctDigest` over fetched bytes but the SDK
  provided no way to do it, and `get` did not check anything. `put` now derives `digest` locally
  from the payload instead of echoing the server's value, and `getVerified(cid, ctDigest)`
  re-hashes the fetched bytes with keccak256 and refuses a mismatch. This is the property the
  whole proof-of-compute path depends on.

Also added: per-request `AbortController` timeout (an epoch has a deadline), optional bearer
`authToken`, and `getRange` so the documented "range-pull" claim is actually implementable against
this store. Regressions cover traversal, unusable returned CID, size caps, and a store that lies
about its digest.

### F-28 — Reference DA server was unbounded, lossy and unauthenticated (ADV8) — **Mitigated**
`infra/shardstore/server.mjs` accumulated bodies in an in-memory `Map` with no size limit (a single
request could OOM the process, taking the DA down for every node at once), lost every shard on
restart, accepted any CID string as a map key, and advertised "range-pull" while implementing no
`Range` support at all. It now enforces a body cap while streaming (413), persists to `DATA_DIR`
when set, validates CIDs, answers `Range` with `206`/`416`, binds `127.0.0.1` by default, and warns
on startup when bound to all interfaces without auth. `docker-compose` mounts a named volume and
publishes it on `127.0.0.1` only.

*Verified by running it*, not by inspection: `PUT 201`, `GET 200`, `Range 206` with
`content-range: bytes 2-5/16`, out-of-range `416`, missing `404`, traversal `400`, oversized `413`.
That live run caught a bug in the hardening itself — the CID pattern initially rejected the `0x`
prefix the client actually sends, so every `GET` returned 400. A unit test would not have caught
it; there is no test harness for this file.

### F-29 — Verifier rotation had no on-chain timelock (ADV5) — **Mitigated**
`ProofVerifier.rotate(address)` was a single-call `onlyOwner` swap. This contract gates every
payout in the protocol: a verifier that accepts anything is a verifier that pays fraudsters, so
the owner's key here is as sensitive as the escrow itself. A compromised owner could install a
permissive verifier in one transaction with no window in which a second party could notice. F-11
acknowledged the gap but pointed at a timelock "in `infra/`" — there is none in `infra/`.

Rotation is now propose → wait → execute, with a 7-day delay matching `NetworkParams`' own
rotation window so both halves of the trust surface move on one schedule. `executeRotation` is
**permissionless**: if only the owner could execute, "the owner is compromised" would also mean
"the rotation can be frozen forever", so a queued rotation is guaranteed to happen at or after its
announced time unless the owner cancels it. Regressions cover the delay, permissionless execution,
owner-only cancellation, and a cancelled rotation never taking effect.

### F-30 — Devnet mocks were open to any address, and are the real verifiers there (ADV2) — **Mitigated**
`deploy.ts` installs `MockStarkVerifier` as the chain's actual `ProofVerifier` and `MockBLS` as the
actual committee-key verifier. Both had unrestricted helpers, which made them devnet attack surface
rather than test-only conveniences:

- `MockStarkVerifier.consume(transcript)` was callable by anyone. `consumed` is keyed on the
  proof transcript and never cleared, so any address could permanently invalidate the honest
  node's proof for a given `(task, epoch)` pair.
- `MockBLS.approve(message)` was callable by anyone, so any address could forge the committee's
  aggregate signature and open a reveal for a task it has no business touching — defeating the
  point of the threshold gate.

Both are owner-only now, and `deploy.ts` marks the mocks in `addresses.json` and prints a warning.

### F-31 — Devnet deployment path (ADV5) — **Mitigated**
`docker compose up devnet` deploys the contracts to a standalone `hardhat node` today, on the
`@fhevm` 0.13 line (hardhat-plugin 0.13.0, solidity 0.13.4). The two failure modes documented here
turned out to share one root cause: network *selection*, not the plugin version.

1. `hardhat run` without `--network` targets the ephemeral in-process network, where no mocks
   are installed — so `CipherTask`'s constructor reverts inside `FHE.asEuint64` with no reason
   string.
2. A custom `devnet:` network entry resolves to provider type `Unknown` in the plugin's
   `__guessDefaultProvider`, on which mock setup refuses. The plugin recognises a standalone
   node only under the `localhost` name (port 8545, chainId forced 31337) and etches the mocks
   into it through its `hardhat_node` provider hook.

So there is deliberately no `devnet` network in `hardhat.config.ts`, `deploy:devnet` passes
`--network localhost` explicitly, and `deploy.ts` asserts mock presence up front
(`assertFheMocksPresent`) so a mis-selection fails with a diagnosis instead of a bare revert.
`scripts/devnet-e2e-check.ts` drives create → contribute → seal → registerNode-with-bond against
the deployment, and the contracts workflow re-runs deploy + E2E on every push. Verified
end-to-end against a local node; `infra/devnet/addresses.{json,env}` (gitignored) carry the
deployment to operators.

### F-32 — `settle` could be un-executable at the advertised contributor cap (ADV1, ADV4) — **Mitigated**
`settle` looped over every accepted contributor and made an external call into the vault for each,
so its cost is O(contributors). `MAX_CONTRIBUTORS` was 5 000. **Measured**, not estimated:
`tests/SettleScaling.spec.ts` builds tasks of varying size and reads `estimateGas`, giving ~117k gas
per contributor. Extrapolated to the cap, settling one task needed **~584M gas against a 30M block
limit — about 19x over.**

This was not a performance nit. `settle` is the *only* call that distributes the contributor pool,
so a task that accepted many contributors could finish every epoch, reach `EpochSettled`, and then
be **permanently unable to settle**: every contributor's share would sit in the vault with no
on-chain route out, and the buyer's refund and the committee's cut with them. The failure mode is a
silent, permanent loss of funds for exactly the participants the protocol claims to pay — and it
triggers at a contributor count well inside the documented limit, so a task could be created that was
guaranteed to become unsettleable.

Settlement is now paged. `settleFrom(taskId, cursor)` pays at most `SETTLE_PAGE_SIZE` (200)
contributors per call, tracked by `_settleCursor` / `_settleDistributed` / `_settleDustRecipient`;
the last page additionally pays the dust, the committee and the buyer refund and sets `_settled`.
`settle(taskId)` remains as the cursor-0 shorthand, so existing callers are unchanged.

Two properties make paging safe rather than a new way to lose money:

- *Per-contributor amounts are page-invariant.* `userPool` derives from `t.budget` and
  `totalWeight` from `_totalWeight`, both frozen once the contribution window closes, so every page
  computes identical amounts. Nothing is underpaid by being in a later page.
- *A page cannot skip ahead.* `cursor` must equal the recorded `_settleCursor`. Without that check
  a caller could jump to the end, trigger the final page, set `_settled`, and strand every
  contributor before the cursor — permissionless paging would then be a way to steal the pool
  rather than distribute it.

Paging is permissionless by design: it only ever moves funds to addresses the task already
committed to paying, with amounts derived from frozen state, so the caller has no discretion.
`CipherTaskClient.settleToCompletion` drives the loop for SDK users.

Two bugs in the paging itself were found by re-reading the diff rather than by a test, and both
are now fixed and covered:

- *The pool was not actually frozen.* Each page recomputed `userPool` and clamped it to the vault's
  current `taskBalance` — a balance that *shrinks* as pages pay contributors. If the clamp ever
  bound, a later page would compute a smaller pool and pay its contributors a smaller share of a
  smaller pie, so amounts would depend on which page a contributor landed in. In practice
  `available >= userPool + committeePool` always holds (node rewards can only consume the node
  pool, and the shares sum to 100%), so the clamp never bound — but that is a non-obvious invariant
  the code did not state, and the docstring asserted an invariant the code did not enforce. The pool
  is now frozen by the first page in `_settleUserPool` and reused verbatim, which makes the
  property hold by construction instead of by arithmetic coincidence.
- *`abort` stayed available mid-pagination.* Because the status during paging is still
  `EpochSettled`, a buyer could run one page — paying contributors in list order at their full
  pro-rata share — then `abort` and recover everything the remaining contributors were owed. That
  turns contributor ordering, which is only submission order, into a selective-payment lever: pay
  the addresses you like, claw back the rest. `abort` now reverts once any page has run. Freezing
  it cannot strand funds, because settlement is permissionless, every page is independently
  callable, and the total credited can never exceed the frozen pool — so finishing is always
  possible.

### F-34 — Unreachable surface that implied mechanisms which do not exist (ADV8) — **Removed**
Seven declarations were reachable only by inspection and each implied a capability the protocol
does not have. In a contract that moves funds this is worse than no code at all: an auditor or
integrator reads the surface and concludes a guarantee exists.

Removed, because nothing called them:

- `ICipherTask.ContributionRejected` (event) — never emitted. There is no contribution rejection
  path; `submitContribution` reverts instead.
- `ICipherTask.BondInsufficient` (error) — never thrown, and tied to the bond that does not exist
  (F-01).
- `PaymentVault.refundFromTask` — superseded by `creditFromTask` + `claim`. `CipherTask.abort`'s
  comment explicitly records choosing the pull-based path instead, so this was the abandoned
  alternative left in place.
- `PaymentVault.closeTaskChannel` and `unwindTask` — both `onlyTaskManager`, never called. Kept
  alive by a comment describing an end-of-task flow that `sweepTaskChannels` actually implements.
- `DecryptionGate.finalizeReveal` — unreachable, because `submitPartialDecryption` combines as
  soon as the threshold is met. It read as the function that completes a reveal when it never
  could.
- `DecryptionGate.canDecrypt` — declared in the interface, implemented, called by nothing.

Also dropped the state variables and errors that became orphans once the above went:
`PaymentVault.totalReturned` (never incremented), `PaymentVault.TaskRefunded`,
`PaymentVault.ChannelNotInTask`, and `DecryptionGate.NotEnoughPartials`.

`PaymentVault`'s ABI went from 70 entries to 64. All of these were `onlyTaskManager` or pure
declarations, so removal is not a breaking change for any live caller.

**Kept deliberately:** `Contribution.slashed`. `settle` reads it and adding slashing later should
not have to change the payout path, so it stays — but it is now documented in the struct as always
false with a pointer to F-01, rather than left to look like an active mechanism.

### F-35 — Parameter rotation validated one struct and installed another (ADV5) — **Mitigated**
`NetworkParams.proposeRotation(candidate, expectedHash, timelock)` validated its `candidate`
argument — key version increments, hash changes, threshold sane — and then **discarded it**,
storing only the caller-supplied `expectedHash`, which was never checked against `candidate`. The
struct that actually reached `current` is the one handed to `approveRotation` and `executeRotation`,
and that struct had **never been validated by anything**.

So the sequence was:

1. Owner calls `proposeRotation(validCandidate, expectedHash = keccak(invalidCandidate, chainId, approver), 7 days)`.
   Every check in the function passes, because it is checking `validCandidate`.
2. Approver signs `invalidCandidate`. Its hash matches `expectedHash`, so `approveRotation` accepts it.
3. Anyone calls `executeRotation(invalidCandidate)` after the timelock. Its only checks are the hash
   and "the hash changed" — both satisfied.

`invalidCandidate` may carry `committeeThreshold = 0`, `committeeSize = 0`, `maxProofBytes = 0`,
`maxFeatures = 0`, or a `keyVersion` that does **not** increment. That last one matters most: the
monotonic key version is exactly the invariant that stops a replayed or reordered key from being
mistaken for a new one, and this path let it be bypassed. Because these values are what clients pin
to decide whether a submission is acceptable, a wrong set installed here is silently trusted — this
contract is the one place where a mistake does not revert.

Two independent fixes, because either alone leaves a gap:

- **Bind at proposal time.** `proposeRotation` now requires
  `expectedHash == keccak256(abi.encode(candidate, chainId, approver))`. The approver is already
  known (`approver` is state, not chosen per rotation), so this costs the proposer nothing, and it
  makes it impossible to validate one struct while queueing another.
- **Re-validate at execution.** `executeRotation` runs the same `_validateCandidate` checks before
  touching `current`, so no future weakening of the proposal path can install an invalid set.

Verified by reverting the first fix and confirming the regression test fails without it.
`NetworkParams.spec.ts` is new: rotation previously had **no test coverage at all** — `initialize`
was the only thing exercised — and it now has eight cases covering a clean rotation, the mismatch,
six invalid parameter sets, timelock enforcement, single execution, cancellation, role separation,
and the live-rotation guard.

### F-33 — Segmented proofs were documented as implemented but are unreachable (ADV2) — **Mitigated**
`IProofVerifier.verifyProofSegmented` and the `ProofVerifier` implementation exist, and
`docs/03-proof-of-compute.md` §5 states the contract "verifies each segment against the segment's
public-input range. Implemented in `ProofVerifier.verifySegmented`". The segmented path *was*
unreachable: `CipherTask.commitEpoch` called `verifyProof` and only `verifyProof`, so no caller
could ever reach it.

`commitEpochSegmented` now routes the same bindings and winner logic through
`verifyProofSegmented`, so the path is reachable and covered. What is still honestly missing is
the prover itself: there is no working STARK prover in this repo (mock verifier on devnet), so
segmented verification is exercised against the mock's shape check, not a real AIR. The
cryptographic half stays in `05-honest-limitations.md` as missing work.

### F-25 — SDK pre-validation was documented but absent (ADV1) — **Mitigated**
`uploadAndMonetize`'s docstring promised it pre-validates "task status, per-address contribution
cap, minimum rows, and shape-proof presence". Only three of those four existed. The per-address cap
was never checked, so a second contribution from the same address was discovered solely as an
`AlreadyContributed` revert — the exact gas burn the docstring claimed to avoid. `ShardTooLarge`,
the contribution-window deadline and the `maxContributors` cap were not checked either. All of
them are now checked locally against on-chain state before the payload is built, and the docstring
matches the code again. The contract remains the authority and still reverts if anything slips.

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

### F-08 — `s_pub` substitution (ADV5) — **Mitigated at boot by default, not mid-epoch**
*Corrected, and this one matters:* this finding was marked **Mitigated** on the strength of
"the SDK refuses to encrypt with params whose hash mismatches; compute nodes refuse to start".
**Neither check existed by default — both do now, at boot.**

What is real: `NetworkParams` does publish and pin the parameters correctly. `initialize` is
one-shot, and `proposeRotation` → `approveRotation` → `executeRotation` enforces a ≥ 7-day
timelock plus a distinct approver, with the key version forced to increment and the hash forced
to change. That part is genuinely well built, and it means a key swap is *visible after the fact*.

What is missing: continuous checking. The SDK only refuses to encrypt when the caller
passes `networkParams` + `fhePublicKeyHash`; without them the check is skipped, not failed.
The node checks at startup whenever `enforce_key_pin = true`, which is now the default —
a node without pins refuses to boot — but the check still happens once, at startup.

Consequence: a malicious sequencer substituting `s_pub` is **not** detected by anything that is
on by default. It is not an availability failure, which is what this finding used to claim —
there is no participant that would notice. The sequencer can publish its own key, harvest the
ciphertexts submitted under it, and decrypt them, and every participant will treat the result as
normal. The on-chain pin still gives you *forensic* detection after the fact (the old hash is
preserved in history), which is worth something, but it is detection, not prevention, and it
requires someone to go and look.

Closing this needs a `NetworkParams` client in the SDK that refuses to encrypt on a hash mismatch
before upload, and a real key-pin check at node startup. **The SDK half is now done and
fail-closed:** `NetworkParamsClient` plus `SdkConfig.networkParams` / `fhePublicKeyHash` make
`uploadAndMonetize` verify `isCurrentKey` before it builds a payload, and a client whose
encryptor actually encrypts under a declared key now *refuses to construct* without
`networkParams` (unless `allowUnpinnedKey` is set for deployments that pin out of band) — the
old silent skip is gone. **The node half now exists but is opt-in:** with `node.enforce_key_pin
= true` (plus `fhe.public_key_hash` and `contracts.network_params`) the node compares the
on-chain key hash at startup and refuses to run on a mismatch, and the startup log is a `warn`,
not an `info`, when the check is off — an operator who never sees the warning is not looking.
It defaults to off — the devnet config sets neither field — and it is a startup check, not a
continuous one: a rotation that lands mid-epoch is not caught until the next restart. So the
finding stands as **not mitigated for any default configuration**, but the unsafe defaults are
now loud on both sides instead of silent.

### F-09 — Committee minority decryption (ADV6) — **Mitigated**
Shamir t-of-n. `DecryptionGate` additionally restricts *what* may be decrypted: a member's
`partialDecrypt` call carries the output CID and is rejected unless that CID is registered by
a settled task, so a minority cannot even meaningfully co-process user shards.

### F-10 — Committee majority decryption (ADV7) — **RESIDUAL, documented**
If `t` committee members collude they can compute the decryption of *any* ciphertext under
`s_pub`, including individual user rows. Shroud does not claim to prevent this. Mitigations
in place: (a) requests are contract-gated, so collusion needs `t` members to *publish* an
off-protocol request, which is publicly auditable; (b) member identities are on-chain
(`isCommitteeMember`), so collusion is attributable and a member can be ejected by deploying a
replacement gate; (c) the honest-majority assumption is stated in the protocol docs so integrators
can choose a different committee.

*Corrected:* this finding previously also claimed members "are bonded", making them
"slashable/forensic". **There is no bond for committee members** — `initialize` only writes a
boolean per address, and `DecryptionGate` holds no stake accounting at all. Attribution without
economic consequence is a much weaker guarantee than the text implied, and a colluding majority
keeps its decryption ability until the whole gate is redeployed.

### F-11 — Verifier availability / soundness under a bad verifier (ADV5, ADV3) — **Accepted**
`ProofVerifier.starkVerifier` is a precompile-style address. A compromised verifier accepts
anything. Mitigation is the dispute window (which does not depend on the verifier) plus
monitoring of `ProofVerified` vs off-chain re-execution disagreements. Verifier rotation
behind a timelock is implemented and tested (`NetworkParams` rotation specs); multisig
ownership of the rotation is still open — a single owner key proposes, approves and cancels.

### F-12 — Deanonymisation of contributors (ADV8) — **Accepted**
Anyone can read the chain and see "address X contributed to task T for buyer B". The row
itself stays encrypted, so the leak is the *participation graph*, not the data. `liveness`
weighting increases this (early contributors are more visible). If a deployment needs
unlinkability, front contributions through a relayer or use a shielded pool — out of MVP scope,
documented rather than hidden.

### F-13 — Encrypted-output tampering in DA (ADV8) — **Mitigated**
`encWeightsCid` is a keccak256 pin in the contract and its digest is a STARK public input. A
swapped object fails the digest check before it is ever loaded.

### F-14 — Malleability of the EIP-712 payment slices (ADV4) — **Mitigated**
Slice permits are `Permit`-style with `deadline`, `channelId`, monotonically increasing
`sliceIndex`, and a `MAX_CUMULATIVE` cap. The contract rejects `sliceIndex <= consumed` and
`amount > remainingChannel`. Re-signing an old slice is worthless. Signature malleability is
handled by using the low-s form and an explicit `s` bound check in `PaymentVault`.

### F-36 — Fee-on-transfer tokens broke escrow accounting (ADV4) — **Mitigated (fail-closed)**
`fundTask` and `takeBond` recorded the *requested* amount while the token could deliver less, so
a fee-taking escrow token silently under-collateralised the task (or the bond price F-04
assumes). Both paths now ledger the balance diff actually received. A shortfall fails closed —
`EscrowMismatch` on creation, `BondInsufficient` on registration — rather than recording money
that never arrived. Fee-on-transfer tokens are therefore rejected with a diagnosis, not
mis-accounted; plain and no-return (USDT-style) tokens work as before.

### F-37 — Transient-only reentrancy guard (pre-Cancun chains) — **Mitigated**
The guard used `TLOAD`/`TSTORE` (EIP-1153), which do not exist pre-Cancun: on such a chain every
guarded call misbehaves instead of merely costing more gas. The guard is now a storage flag —
slightly more expensive on Cancun+, correct everywhere the bytecode can execute.

### F-38 — Task-manager rotation overwrite (ADV5) — **Mitigated**
`proposeTaskManager` silently overwrote a live rotation, including its `eta`: observers watching
the first proposal could be switched to a different candidate mid-timelock. A live proposal must
now be cancelled (itself an event) before a new one is queued.

### F-39 — `openEpoch`/`reclaim` authority creep (ADV4) — **Mitigated**
`openEpoch` accepted the contract owner alongside the buyer/update manager, handing a third key
quiet control of the training trajectory; only the buyer and update manager may open epochs now
(the owner's emergency lever remains `emergencyUnwind`, rate-limited by deadline + window).
`reclaimUnspentEpochs` was buyer-only, stranding the refund behind a key the task may no longer
use; the update manager — which already controls the epoch loop — may call it too.

## 3. Explicitly out of scope

- Padding-oracle / timing side channels inside the fhEVM coprocessor.
- Wallet compromise, key-phishing, malicious browser extensions.
- The buyer's model IP: a determined buyer can *infer* things about the dataset from the
  trained weights. This is inherent to the product, and the buyer-facing docs must say so.
- L1↔L2 data availability sampling (the MVP trusts the L3 sequencer + the DA layer for
  availability, and the STARK for correctness).
