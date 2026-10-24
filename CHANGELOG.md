# Changelog

All notable changes. Counts live in CI — this file records behaviour, not test numbers.
No tags or releases are published yet; entries below are merge-PR scoped until the
first tagged release.

## Unreleased

### SDK: `openEpoch` opens and pins hyperparams in one call (M5 closed)

- New `CipherTaskClient.openEpoch(taskId, { encWeightsCid, weightsDigest,
  encStateHandle, encStateProof, hyperparams })`: validates hyperparams locally,
  opens the epoch, then pins `scale/lrQ16/l2Q16/minibatch/seed` on the epoch it
  just opened (`nextEpoch` only advances on `finalizeEpoch`, so the pin cannot
  drift; a failed pin leaves the epoch open and nodes fall back to local config
  with a warning). New `validateHyperparams` mirrors the on-chain gate, plus
  buyer-side `setContributionBondRequirement` / `setContributionBondPerRow` /
  `setWeightByBond`. Re-exported from the SDK entrypoint; `devnet-execute-check`
  pins the node defaults after opening epoch 0; buyer flow documented in
  `USER_GUIDE.md`.

### Devnet: the compose stack starts as documented, and the shots re-render

- `shardstore` no longer crash-loops on a default `up`: the server is
  fail-closed (exits without `AUTH_TOKEN`), so compose now defaults to
  `ALLOW_UNAUTHENTICATED=1` for localhost dev and documents the production
  `SHARDSTORE_AUTH_TOKEN` + `=0` pair. The stale "empty keeps the open
  behaviour" comment is corrected.
- Nodes were unstartable as composed: empty task/vault addresses (clap parse
  error, not the clean `Missing`), no BLS keys, one shared operator key across
  three nodes (registration collision), and `enforce_key_pin`/`strict_weights`
  defaulting true with no env override. Fixed without touching Rust: a shared
  read-only `infra/node/shroud-devnet.toml` (devnet opt-outs + compose
  endpoints via `CM_CONFIG`), `env_file: ./devnet/addresses.env` from the deploy
  (no hand-copying), distinct hardhat keys (#1/#2/#0) and throwaway BLS
  identities, per-node peer lists without self-peers, per-node data volumes
  (the follower cursor cannot be shared), localhost-bound devnet RPC, and a
  shardstore `/healthz` healthcheck.
- New `web/scripts/render-shots.mjs` re-renders `docs/shots/*.png`
  deterministically (pinned RU/ink/newcomer, desktop + mobile viewports,
  scroll-through for intersection-rendered sections); all four shots refreshed
  from the current site.

### Contracts: continuity, priced rows, pinned hyperparams, paged settlement

- `finalizeEpoch` promotes the winner's `encWeightsCid`/`weightsDigest` into
  `lastWeights*`, and `openEpoch` enforces continuity against them from epoch 1
  (`WeightPinMismatch`): an epoch can no longer train from silently replaced
  weights. `abort` is refused while an epoch is committing; `ProofVerifier`
  rotation cannot be overwritten while pending; `disputeQuorum` reads the
  terminal epoch correctly.
- Contributor weight no longer trusts self-declared `rows` for free: optional
  per-row bond surcharge prices each claimed row, and `setWeightByBond` switches
  the task to secure mode (`effectiveRows = 1`, liveness only). Consensus
  hyperparams pin per epoch (`pinEpochHyperparams`, buyer/manager only) so chain
  truth wins over per-node config; first dispute action pins `(seed, total)`.
- Settlement scales: `sweepTaskChannelsPaged` with an `openChannelCount` counter
  and `SWEEP_PAGE` keeps every page under the block limit (`ChannelsImmature`
  until channels mature). `CipherTask` stays deployable at 24_291/24_576 bytes
  with 285 bytes of slack; `PaymentVault` at 12_875.

### Bot: speaks Russian, has a front door, and explains itself simply or fully

- New /start with role guides (buyer/contributor/node/watcher), RU/EN with
  auto-detect from the Telegram client, and simple/pro depth modes; mode and
  language buttons re-render the same screen in place. Alerts render per chat
  in its language. Historical default (EN, pro) is unchanged until a chat
  opts in via /start, /pro, /simple or /lang.
- Fixed a startup crash: `connect()` called a nonexistent `log`, so the bot
  died against a healthy chain; covered by a connect-against-stub test.
- Ops hub and geek track: `/menu` hub, `/how` pipeline, `/protocol` geek spec,
  `/settings` one-screen prefs; mode labels are simple/geek (stored value stays
  `pro`). RU command aliases, bare-id input (`12` → `/task 12`), RU role args.
  Full key-rotation lifecycle alerts (approve/cancel), ProofVerifier rotation
  alerts with `/status` queue state, escrow-decimal money scaling (6-decimal
  USDC no longer renders as "0"), first/last pool page jumps, dead-key i18n
  guard, dead-end keyboards on every confirmation screen.
- Harsh-review hardening pass: per-stage scan isolation with cursor hold and
  loud retry (no more silent alert loss on transient RPC failures), reorg
  rewind covers the rewritten head block, `/watch 007` canonicalizes to task 7,
  `Revealing` no longer mislabeled as payouts and `None` no longer as "open",
  honest dust (`<0.0001`) instead of `"0"`, bounded watchlist and read-error
  rendering (no more 400-truncated dead screens), `/pool` distinguishes
  unreadable from empty, GUARD: stale/error toasts and mode buttons speak the
  chat's language, alert queue sheds the oldest waiting alert first.

### Tests: stateful vault invariants in Foundry (roadmap: Foundry-инварианты)

- The roadmap lists Foundry invariants; only the Dividend math had them. New
  `test/foundry/VaultInvariants.t.sol` fuzzes interleavings of the manager-side
  operations (fund, bond, top-up, open, sweep, credit, claim, warp) and asserts
  after every sequence what `_assertInvariant` cannot see from inside: real token
  solvency alongside `totalLocked == accountedLocked`. Test-only, no bytecode change.

### Site: the footers quoted an old finding count, and the gate did not look there

- The footers said "threats 39" while the model carries 63 — the same drift the long
  quotes once had, in a format `findings.mjs` did not check. All six spots now say 63,
  and the gate checks every `threats N` in the dictionary and every page, proven
  against a deliberate mismatch.

### Site: the blueprint looks like a blueprint now

- Millimeter grid across the sheet, registration marks on the hero, the schemes and
  the license sheet, finer grid inside scheme bodies, tabular figures wherever numbers
  sit, and the footer base reframed as a title block. Plus a print stylesheet, so the
  spec sheets land on paper as a clean light document. CSS only, no new copy —
  accessibility stays at 1.00 everywhere.

### Docs and lab: the reward weight is linear, not sqrt (H3 aftermath)

- The contract pays `rows·liveness` since the H3 fix — sqrt backfired by rewarding
  splits — but the site, the lab preview and the bot still said sqrt, and the bot
  also claimed there was no slashable contribution bond while the opt-in bond
  exists. All of it now matches the code: linear weight, split-neutral, deterrence
  by minRows, gas and the bond. (`docs/01-architecture.md` still shows the old
  formula; it is frozen by agreement, so this entry records the divergence instead
  of editing it.)

### Threat model: the settlement sweep has a measured channel bound (F-63)

- `taskChannels` only grows and the sweep walks all of it on every settlement page:
  ~11.5k gas to close a channel, ~4.8k to skip a closed one, so one page bricks at
  ~2,600 mature unclosed (or ~6,300 closed) channels. The sortition keeps the realistic
  worst case near ~8 channels per epoch, which is why this is recorded, not fixed —
  the fix does not fit the deployment headroom. A new tripwire test pins the two
  per-channel numbers so a storage change cannot silently eat the margin.

### Docs: a slashed winner bond never reaches the treasury

- Seven places said the treasury receives "every slashed bond". It does not: slashed
  contribution bonds go to the treasury, but a slashed winner bond rejoins the task
  balance and refunds to the buyer at settlement. The docstring, the threat model,
  the bot text and the spec header now say exactly that.

### Site: the settlement card tells the truth about the dust

- The SETTLE card said "treasury = the remainder" and "all division remainders go to
  the largest address". The code says otherwise: the treasury gets the fixed committee
  leg, contributor-pool dust goes to the highest address, and the epoch-lock remainder
  plus everything unclaimed is refunded to the buyer. The card now says exactly that,
  in both languages.

### Paper theme: code and journal headings were unreadable

- In the light theme the keyword color and the journal headings rendered dark-on-dark
  (contrast 1.27 — the text was there, but only the DOM could see it). Both now use a
  pale screen accent, verified against the computed styles in both themes.
- The 404 page promised three ways out and linked two; the protocol button is there now.
- Commit messages and comments stay short from here: explain the why, not the what.

### Node: stop filing disputes the sortition did not pick

- `reportDispute` counts a report only from an address the epoch's sortition drew, and the
  first dispute action fixes the seed. The node's `dispute_gate` mirrored the standing checks
  — verified commit, matching digest, claim not ours — but not the draw, so a node that had
  committed honestly and disagreed would send a transaction the contract rejects with
  `NotCommitteeMember`, paying for it and logging a failure that reads like a bug. A new
  `committee_gate` reads `committeeSeed`/`isCommitteeEligible` first and skips with "not drawn
  into this epoch's dispute committee". A zero seed means nobody has fixed it yet, and that
  case is deliberately let through: the seed is derived from the first reporter's own block,
  so refusing there would make the initial report impossible rather than cheaper.
- `ICipherTaskView` gains `committeeSeed` and `isCommitteeEligible`, so the node reads the
  draw from the contract instead of re-deriving it.

### Site: the front door is readable by assistive tech

- Every page except the landing one opened with `h2` — the document had no `h1` at all.
  The first section title is now the `h1`, the headings under it moved down one level,
  and the footer's `h5` column titles (a `h2 → h5` jump on every page) are `h2`. `card`,
  `plain-card`, `perm-grid` and `ledger` headings keep their look through grouped
  selectors, and the new levels were checked against the computed styles.
- The lab's fourteen fields had a `<label>` *next to* them, not associated with them:
  a screen reader announced "edit text, blank" and nothing else. Each label now carries
  `for=`. The journal's section headings are `h2` (they were `h4` under an `h1`).
- New `web/tests/a11y.mjs` (in the `site` workflow and the CONTRIBUTING pre-push list):
  one `h1` and no downward level jumps per page, every field has an accessible name,
  every image has `alt`, every link and button has text, every document has `lang`.
  It was run against six deliberate regressions — each one fails the gate.
- Lighthouse on all pages: accessibility 1.00 (was 0.98 on six pages and 0.87 on the
  lab), best practices 1.00, SEO 1.00. The 404 page was checked at `/shroud/`, where
  GitHub Pages serves it, so its absolute asset paths are exercised too.
- CONTRIBUTING's pre-push list gained `findings.mjs` (it was in CI but not in the list)
  and `a11y.mjs`.

### Devnet: the owner controls are exercised on a live deployment

- The unit suite proves the treasury rotation and the proof-requirement ratchet in
  isolation. `scripts/devnet-admin-check.ts` proves them through the artifact that
  actually lands on chain: it queues a treasury change, watches an early execute get
  refused, moves the clock a week, and lets a **non-owner** execute it — then checks
  that the requirement holds and that the switch which used to weaken it is not in the
  ABI at all. The contracts workflow runs it between the lifecycle smoke and the SDK
  check, so "the interface works in a fixture" cannot drift away from "the deployed
  thing works" again.
- The README quickstart no longer sends you to Docker first: a plain `npx hardhat node`
  is enough for the contracts and SDK legs. Docker is what the DA and compute nodes
  need, and the quickstart now says so.

### Ops: the bot watches the treasury rotation

- A timelock is only as good as the monitoring around it. The bot already
  watched the network-key rotation; it now watches `TreasuryProposed`,
  `TreasuryChanged` and `TreasuryRotationCancelled` on the orchestrator.
- The **proposal** is the alert that matters, because it is the only moment when
  an operator can still say no — once the change is executed, the money is
  already pointed somewhere else. `ALERT_TREASURY` (on by default) delivers it,
  with a `/alerts` per-chat toggle like the other flags.

### Design: the owner can no longer move the money or drop the proof requirement in one transaction

- The treasury receives every slashed bond and every committee leg, and
  `setTreasury` was a single `onlyOwner` call: one transaction repointed every
  future fee flow to an address of the owner's choosing, with no window in which
  anyone could notice. The treasury now moves through a rotation —
  `proposeTreasury` queues the candidate and the time it becomes executable,
  `executeTreasury` installs it once `TREASURY_DELAY` (seven days, the same
  window the verifier and the task-manager rotations use) has elapsed, and
  `cancelTreasury` lets the owner drop a change it no longer wants. A live
  candidate cannot be swapped, so the address watchers saw is the address that
  lands, and anyone may execute, so a queued rotation is not hostage to a lost
  owner key. **F-61.**
- Each contribution carries a Groth16 proof that its rows match the buyer's
  shape, and that proof is the only thing keeping rows of the wrong shape out of
  the dataset. `setShapeProofsRequired(false)` removed the requirement in one
  call. The requirement is now a **ratchet**: `requireShapeProofs` turns it on and
  there is no entry point that turns it off at all — a deployment decides at
  construction, the owner may tighten it later, nobody may loosen it. A delay
  would have been the weaker version of the same fix: it would still leave a
  window in which the requirement could lapse. **F-62.**
- ABI change: `setTreasury`/`setShapeProofsRequired` are gone, the rotation
  functions are new, and the shape-proof requirement is decided per deployment.
  `DISPUTE_QUORUM` is no longer a public constant — `disputeQuorum(taskId)` still
  reports it. The SDK's ABI is regenerated from the artifact.

### Design: the dispute committee is no longer the sequencer's to pick

- The committee that may report a dispute for an epoch is drawn by a weighted
  lottery, so a Sybil ring cannot count arbitrary identities toward quorum. But
  the draw needs a seed, and the seed was the block's randomness alone. On a
  chain whose sequencer proposes the blocks — this protocol's own L3 — that is a
  handful of hashes to search until the seed draws the sequencer's own
  identities and excludes the honest one: **the sequencer picked the committee,
  for free**, while every bond in the design is priced.
- The seed now also commits to the registered node set, and that set is fixed by
  the registrations — each of which posts a bond. The sequencer can no longer
  choose the committee, and a Sybil cannot buy its way in either: it cannot see
  the seed before it registers, and every identity it adds costs a bond. The
  chain's randomness still enters, so the draw stays uniform for a fixed set.
- No ABI change: the commitment is a running hash over the registrations, kept
  in one new public mapping, and the seed derivation moved into the dispute
  library where the lottery already lived. **F-59.**

### Design: a task whose dispute could never be checked is refused

- A dispute is only worth filing if a re-execution can finish inside the dispute
  window, and a re-execution takes about as long as the epoch does. A task whose
  dispute window is shorter than the training time has an **unreachable
  dispute**: the committee cannot check the claim, and the epoch settles on the
  claimant's word alone — the one thing the dispute protocol exists to prevent.
- The contract cannot know how long a re-execution takes, so the guard lives in
  the node, which does: it refuses such an epoch loudly instead of taking part
  in a mechanism that cannot work. The node's own `min_epoch_window` is the
  yardstick, so an operator who knows their training time sets it once.
  **F-60.**

### Gates: the threat model's regression references must name a real test

- Every finding fixed in this pass carries the test that pins it, and that
  reference is the difference between a finding and a claim: an auditor who
  cannot find the test has to take the finding on trust. The references were
  checked by eye — and four of them were paraphrases rather than the tests' own
  names, so a renamed test would have left a reference that pointed at nothing
  while looking exactly as authoritative. `scripts/regression-refs.mjs` now
  checks that the named file exists and contains the quoted name, and the four
  paraphrases are the tests' verbatim names (two of the ShardStore's tests are
  named in Russian, and the citation now quotes them as they are).
- The gate was verified to fail on a renamed test and to pass again afterwards.

### Gates: the digest of a negative weight lane is pinned too

- A weight lane is an `i32` in `u32` clothing — linear models legitimately go
  negative — and the digest `commitEpoch` stores is over the `u32` words. The
  SDK and the node agreed on that, but the *digest* of a negative lane was
  pinned on neither side: the existing goldens only carried positive lanes. A
  divergence would not have failed loudly; the node would have compared the seed
  it downloaded against a digest the buyer computed differently and fallen back
  to genesis zeros with a warning in the log. Both sides now pin the same
  value for the same negative lanes.

### The fee-on-transfer refusal was a claim, not a test

- F-36 says the escrow and the registration bond now fail closed on a
  fee-taking token, and that is what the code does — but nothing tested it. The
  claim "fail closed" was a claim about the code, and a change to
  `_pull`/`takeBond` would have silently restored the silent
  under-collateralisation it was written to prevent.
- A `FeeOnTransferTokenMock` (a token that takes a cut and burns it) and a spec
  now prove both refusals: the escrow at the orchestrator's `EscrowMismatch`,
  the bond at `BondInsufficient`, with the vault's books still balancing after
  the refused pull. The mock's cut is switchable, because the escrow is checked
  at task creation — with the cut already on, the task cannot exist and the
  bond path is unreachable.
- The finding's status did not change: the fix was already in the code, and it
  is now pinned.

### Gates: more of the threat model's findings cite the test that pins them

- The regression-reference gate started at the thirteen findings fixed in this
  pass. The older findings cited their regressions in prose — "two cases in
  *governance recovery*", "the file had no test harness" — which no machine can
  check and which had already gone stale in one place (F-28 still claimed the
  shard store had no test harness; it has had one for a while). The citations
  are now in the checkable form, and **52 of the 58 findings name a file and a
  test**. The six that do not are the ones with no test to name: four accepted
  or residual risks, a removal, and the devnet deployment path.

### Node: the provider's key no longer reaches the log

- A managed RPC URL carries the provider's API key in its path. The node
  printed that URL in its start-up line, and a transport error quotes the URL it
  failed to reach — so a node whose RPC hiccupped wrote the key into its log,
  **on every failed poll**. A configuration error quoted the offending value
  the same way, before the node had even started.
- The endpoint now stays visible in a redacted form (the host and the API
  version), while every path segment that is not an API version, the query
  string, the fragment and the URL's own credentials are masked. The secret is
  registered before the configuration is loaded, so even a configuration error
  is scrubbed. A storage endpoint is a location rather than a credential, so its
  path stays visible — but a presigned query signature does not.
- This is F-58 in the threat model; the site's finding count follows — 58.

### Docs: three dead references, one false claim, and a gate that keeps them dead

- The architecture's mitigation table pointed at `shard_store.rs` — a file that
  does not exist; the shard store is `node/src/da.rs`.
- The cryptography document attributed its performance figures to
  `node/benches/epoch.rs` — a benchmark that is not in this tree. The figures are
  derived from the scaling guard's arithmetic, and the document now says so: a
  number that looks measured but is not is worse than a number that says where
  it came from.
- The release process pointed at a `RELEASE_NOTES.md` that nobody had written;
  it now says the file is written for the tag.
- `node/Cargo.toml` described the `prover` feature as a reserved dependency
  stack that "nothing in this crate imports" — the tfhe backend has been behind
  that feature all along, and the `--all-features` CI run compiles *and tests*
  it. The comment described a plan, not the code.
- `scripts/doc-refs.mjs` now checks that every file the documentation names
  exists, and a new `doc-refs` workflow runs it — on the sources as well as on
  the prose, because a file can be renamed without touching a document, and that
  is exactly when a reference goes stale. Runtime artifacts (the bot's
  watchlist, the operator's config, the evidence pack's output) are listed
  explicitly, so the exceptions are visible rather than implicit.

### Node: a network blip no longer costs the node an epoch

- Before it either requeues an epoch or drops it, the node sorts a failure into
  "may resolve on its own" and "permanent". The chain's **transport** errors were
  in the permanent group: a timeout, a dropped connection or a 502 while the
  epoch's inputs were being collected was read as "this epoch has no executable
  inputs", and the node dropped the epoch — no commit, no opinion, and the
  window closed without it. The transport is a retryable failure now, and the
  epoch window bounds the wait, which is what the code's own documentation
  always said it did.
- The local DA cache is checked by `stat` before the object is read, the way
  the remote path already did with `head` before `get`. Shards are fetched with
  a bounded concurrency, so a cache holding objects larger than the current
  budget was read in full — several at a time — before the check rejected it.
- This is F-56 in the threat model; the site's finding count follows — 57.

### SDK: the relayer encryptor no longer remembers a failure forever

- The relayer encryptor builds its live instance once and reuses it. The
  *rejection* was reused too: a momentary outage — the relayer restarting, the
  RPC hiccupping — left the encryptor permanently broken, because every later
  call returned the same cached rejection and only a process restart could
  recover. A failed attempt is not remembered now; the next call builds a new
  one. The memo is a named helper (`onceAsync`) with a test of its own.
- The SDK's dispute commitment is now pinned to the node's golden, so the two
  encoders cannot drift apart — a divergence would surface as a dispute that can
  never be revealed.
- This is F-57 in the threat model.

### Dependabot: version updates off, security updates on

- Dependabot was scheduled weekly on seven ecosystems, so every Monday it re-created the
  branch-and-pull-request mess this repository is deliberately kept out of. Version updates
  are now switched off (`open-pull-requests-limit: 0`); vulnerability alerts and security
  updates keep working, and every JavaScript CI job gates on `npm audit --audit-level=high`,
  so a new high or critical advisory fails the build rather than waiting for a scan.
- The trade is recorded in `docs/05` §7b: routine version bumps no longer arrive on their
  own and have to be taken by hand.

### Bot: the client aborted its own long poll

- The Telegram client's request deadline (15 s) was shorter than the long-poll
  window it asked for (30 s). Telegram holds a `getUpdates` request open until it
  has an update or the window ends, so every *idle* poll was aborted by the
  client's own deadline: the bot logged "command poll failed", slept two seconds
  and polled again — on every quiet minute, forever. Updates still arrived
  (Telegram answers as soon as it has one), so the bot was not blind, but the log
  said "failed" continuously, and a log that always says "failed" tells an
  operator nothing. The deadline now clears the poll window plus the round trip.
- This is F-55 in the threat model: the site's finding count follows — 55.

### Threat model: the map now carries every defect that was fixed

- F-40…F-46 covered the seven defects of the last pass. The fixes of the pass
  before that were not in the map either, and the map is what an auditor reads
  first: the shard store's per-request catch, the SDK's range pull that buffered
  the whole object, the SDK's file store that deleted a live temp file, the
  bot's watchlists that two chats could lose between them, the bot's watch
  buttons that were priced like the cheap command, the bot's alert cursor that
  was rewritten in place, the provider's API key that could reach the log and
  the chat, and the lab that taught a digest convention no node commits. They are
  now F-47…F-54, each with the failure it allowed and the regression that pins
  it. The site's finding count follows: 54.

### The provider's key: the redaction had two holes, and the errors were never scrubbed

- The RPC URL is printed so the operator can see *which* endpoint is
  misconfigured — and a managed RPC URL carries the provider's API key in it.
  The redaction masked the **last** path segment only, so a key in any other
  position (a gateway that puts something after it), in the query string, in the
  fragment, or in the URL's own credentials was printed in full. Every path
  segment that is not an API-version token is masked now, and the query, the
  fragment and the credentials are dropped.
- The messages the bot prints and sends were never scrubbed at all: an error
  that quoted the RPC URL carried the key into the log and into the chat, where
  it stays in the chat's history. Every error the bot logs or returns is now
  scrubbed of the key, including the read errors `/status` surfaces.

### The shard store's last-resort net is now a tested invariant

- A request whose handler rejected took the server down with it: the rejection
  surfaced as an unhandled rejection, which Node treats as fatal. The net is now
  a library primitive (`guardedRequest`) rather than a `try`/`catch` buried in
  the request path, so the invariant is pinned by a unit test instead of by
  reading the server.

### Threat model: seven fixed defects enter the map as F-40–F-46

- The threat model carried F-01…F-39 and none of the seven defects fixed in this
  pass was in it — so the map an auditor reads did not describe the tree. They are
  now F-40…F-46, each with the failure it allowed and the regression that pins it:
  an aborted task that could be re-sealed (reopening the slash path), a gate that
  could be opened behind the orchestrator's back (bricking the task), a DA that
  could silently discard an honest upload, a DA whose memory guard did not guard
  memory, a node that read the epoch claim by a rule the contract does not have
  (so an honest node never disputed), an SGD update that could wrap, and a tfhe
  backend that could not run an epoch at all.
- The site's finding count follows: it quoted 39 findings, and the model now
  carries 46.

### Gates: the SDK's shard layout is pinned, and advisories fail the SDK and the bot

- The SDK's `noop` shard encoder was never checked against the node's decoder, so
  a change on either side that the other did not follow would produce a shard
  that uploads cleanly and then fails in every node's decoder — or worse, decodes
  into different rows. The SDK now pins its bytes against the node's golden (the
  same vector the site's equivalence gate and the node's own test use).
- `npm audit --audit-level=high` gated the contracts job only. The SDK is a
  published package and the bot runs on a server with the operator's token, so a
  new high-severity advisory in either tree passed the build and waited for the
  weekly Dependabot scan. Both jobs run the gate now.

### Gates: the SDK's EIP-712 pins now cover the typehash and the slice blob

- The redeem typehash is written down in three places: the contract's public
  constant, the contracts' off-chain copy, and the SDK's. A change to one of
  them alone would make every signature that side produces fail at the vault —
  and neither suite would notice on its own, because each compared the string
  only with itself. The vault's own constant is now compared against the
  contracts' copy, and the SDK pins the same bytes.
- The ERC-1271 slice blob is three big-endian words, and the SDK's round-trip
  test only proved that the SDK agreed with itself. It now also pins the bytes
  the chain accepted — the node's golden, replayed against a real
  `PaymentVault.redeem`.
- The node-registration proof-of-possession message was the same story: the
  contract, the contracts' suite and the SDK each wrote it down, and each
  compared it only with itself. The message is now a named function on both
  off-chain sides (`popDigest`) and the two are pinned to one golden — a change
  to one of them alone would otherwise make every registration the SDK submits
  fail with `InvalidPopSignature`.

### Gates: the SDK's domain separator is pinned to the vault's

- The SDK recomputes the vault's EIP-712 domain separator locally and submits the
  digest to `PaymentVault.redeem`, which checks it against the separator the vault
  computed in its constructor. A divergence would make every slice redemption the
  SDK submits fail with `InvalidSignature` — and nothing in the repo would notice:
  the contracts' suite computes its own separator, and the SDK's only test checked
  that its own was stable. Both sides now pin the same golden value, and the
  live redeem in the contracts' suite ties that value to the contract's own
  behaviour.

### Gates: the site's finding count can no longer drift from the threat model

- The site tells the reader that the threat model carries "N findings", and the
  number was written by hand. It had already drifted twice — findings were added
  to the model and the site kept quoting the old count, so the page understated
  the model's coverage. `web/tests/findings.mjs` now counts the findings in
  `docs/04-threat-model.md`, checks that the numbering is contiguous (a hole
  means a finding was deleted without renumbering the rest), checks that every
  finding carries a status, and checks that every number the site quotes equals
  the model's. The site workflow runs it, and a change to the threat model now
  triggers that workflow — otherwise the check would be skipped exactly when the
  drift happens.

### ShardStore: an honest upload could be silently discarded

- The "bot-timing" heuristic scored any client with a regular PUT cadence as a bot
  (a fixed interval has a coefficient of variation of zero, which is the definition
  of the anomaly it looks for), and a `HIGH` score answered the write with a
  plausible `201` and stored **nothing**. The client was told the shard was stored,
  the contract pinned its digest, and the encrypted rows were unrecoverable - the
  upload looked successful at every layer. A regular cadence is what the SDK's own
  upload loop produces, so it is not evidence of an attack. The honeypot now needs
  a *hard* signal as well (a failed auth, a rate hit, a duplicate payload, range
  abuse); timing alone no longer shadows a write.
- The in-flight byte budget was checked once, on admission, and a body without
  `Content-Length` reserved **zero** bytes - so the check passed and was never
  re-applied while the body arrived. N such connections held N x 64 MiB with a
  512 MiB budget: the memory guard did not guard memory, and the DA died under
  every node that had to publish a shard. The budget is now re-checked as the body
  arrives, and the excess is shed as backpressure (a retryable 503), not as a
  silent drop.
- A request whose handler rejected took the whole server down with it (the
  rejection surfaced as an unhandled rejection, which the process treats as fatal).
  The rejection is now caught per request and answered as a 500.

### SDK: three ways to lose a shard that was already accepted

- `FileShardStore` swept every `*.tmp` in its directory when it opened, so a second
  process opening the store deleted the temp file the first one was about to
  rename. The rename then failed and the shard was never stored - in a store
  documented for multi-process use ("SDK uploads next to a node reading the same
  dir"). The sweep now takes only orphans (older than an hour) and leaves a temp
  that is still in flight alone.
- Two processes putting the same content-addressed bytes for the first time both
  passed the "does it exist" check, and the second rename over the existing file
  threw on Windows. The content is identical by construction, so the store now
  treats "the file is already there" as success.
- A range pull was bounded by the *object* cap (64 MiB) instead of the requested
  window, so a store that ignored `Range` made the client buffer the whole object
  - twice that in the copy - for a window that may be a kilobyte. The
  `Content-Range` header is now checked before the body is read, and the read
  itself is bounded by the window.

### Bot: state could be lost, a button could write "undefined", and the RPC key leaked

- Every watchlist save used one temp path per process, so two chats saved at the
  same time (the dispatcher runs handlers concurrently) landed in one file, and the
  rename published a mixture of the two snapshots. The next start read that as
  corruption, moved it aside and started empty - every chat lost its watchlist and
  its alert overrides over one interleaved save. The writes are now atomic and
  serialised per file.
- A handler that failed answers with a plain string, and the inline-keyboard path
  read `reply.text` off it - `undefined` - so a failed "refresh" press edited the
  user's message to the literal text "undefined". The reply is now unwrapped the
  same way the message path does it.
- The watch and unwatch buttons render the full task view, which is `/task`-sized
  work, but they were priced like the cheap `/watch` command. A chat could buy
  five times the intended RPC amplification - exactly what the per-chat budget
  exists to stop. The price now comes from what the press does.
- The alert cursor was rewritten in place on every poll cycle, so a crash left a
  truncated file; a truncated cursor reads as "no cursor", which restarts the scan
  with an empty seen-set and an empty digest map - a duplicate-alert storm over the
  whole window, and the loss of every remembered commit digest. It is written
  atomically now.
- The RPC URL was printed in the clear, and a managed RPC URL carries the
  provider's API key in its path. The endpoint stays visible; the secret does not.

### Site: the lab's trace digest was not the one a node commits

- The leaf the node puts into the trace digest comes from the chain's contribution
  record: the transport address the contributor submitted (`sha256` of the payload)
  and the on-chain pin (`keccak256` of the payload). The lab and the golden
  harness used the row commitment and `keccak(payload)` in those two slots, so the
  digest the lab printed was not a digest any node would commit - and nothing in
  the repo noticed, because the lab and the harness agreed with each other and
  both disagreed with the node.
- The goldens now model the real contribution: the transport address, the on-chain
  pin, and the chain's own running `ctRoot`
  (`keccak256(_EMPTY_ROOT || u32be(leafIndex) || ciphertextCid)`). The node's own
  test confirms the new digests, the site reproduces them, and the lab now builds
  the leaf the way the node does. The site grew a SHA-256 for the transport
  address, cross-checked against `ethers` in CI.

### Contracts: an aborted task could be re-sealed, reopening the slash path

- `sealTask` gated on `isSealed` alone, and `abort` leaves `isSealed` false — the task was
  never sealed. So once the contribution window had expired, **anyone** could seal an aborted
  task, which moved it out of `Aborted`. That reopened the two things the abort deliberately
  closed: `slashContributionBond` (whose `AlreadyTerminal` guard no longer trips, so a
  buyer could burn an honest contributor's bond into the treasury) and
  `releaseContributionBond` (the bond is no longer releasable, and the task cannot be
  re-aborted either — `abort` on a `Sealed` task is refused by the same guard, so the tokens
  sit in the contract with no way out). `sealTask` now refuses a terminal task.

### Contracts: the gate could be opened behind the orchestrator's back, bricking the task

- `DecryptionGate.requestReveal` was callable by anyone holding a committee signature. The
  gate's `open` flag and the task's `Settling -> Revealing` transition are one state
  machine, and opening the gate directly took the flag while the task was still `Settling`.
  The buyer's own `CipherTask.requestReveal` then hit the gate's `AlreadyOpen` guard and
  reverted — rolling the status transition back with it. The task could never reach
  `Disclosed` and `withdraw` was unreachable for good, with no way to reset the gate.
- The gate is now opened by the orchestrator and by nothing else, which is what its own
  documentation already claimed ("contract-restricted"). The SDK's reveal entry point moves
  with it: `CipherTaskClient.requestReveal` asks the task (which pins the output CID and
  asks the gate), and `DecryptionGateClient` keeps the reads and the committee member's
  partial submission.

### Node: the fold read the epoch's claim by the wrong rule, so an honest node stayed quiet

- The claim the contract holds is the **first** committer's digest: `commitEpoch` writes
  `claimed[taskId][epoch]` exactly once, and the first verified commit takes the winner
  seat and keeps it ("ties resolve by commit order, not by address"). The node read it as
  the *lowest-address* committer's digest — a rule that does not exist in the contract, and
  which the node's own comment described as if it did.
- The consequence cost money: a peer that committed first and this node second left the
  node believing the claim was its own, so it filed no dispute — while the peer kept the
  reward for an epoch this node had honestly computed. The fold now tracks the claim as the
  first commit it folded, and reports an unknown claim as unknown rather than guessing it.
  The worker's own check (which reads the winner from the chain) was always right; the
  decision to file a dispute at all was not.

### Node: the SGD update could wrap, and the tfhe backend could not run at all

- `apply_update` multiplied `lr_q16 * acc` unchecked, in the one module whose contract is
  "all arithmetic is checked `i128`; anything that does not fit is an error, never a
  wrap". The loss check bounds `err * err`, not `err * x`, so an accumulator the epoch
  accepted could still overflow the product: debug builds panicked, release builds wrapped
  silently and produced a weight update no other node reproduces — the build-dependent
  divergence the module exists to prevent. The update is checked now, and an update that
  does not fit is an error.
- The tfhe weights envelope was written with the *lane* count where its own decoder reads a
  *row* count, and with one frame per lane where the decoder expects `rows * features`
  frames. Every tfhe epoch therefore failed to load its own previous weights ("truncated
  ciphertext length"): the backend could never start an epoch, never commit, never dispute.
  The framing now agrees on both sides - the row count is derived from the lane count, and
  the header and the frame count are pinned by tests on both sides of the contract (the
  framing test needs no FHE stack at all, so it runs in every build).
- The tfhe L2 shrinkage was derived from the *gradient* step, which divides by the
  quantisation scale and the minibatch. The reference engine shrinks by
  `l2_q16 * w / 2^16` and nothing else, so the tfhe backend's regularisation was `S` times
  weaker than configured — at the default scale of 10 000, no regularisation at all. The L2
  step has its own derivation, and the two backends now shrink by the same amount. The
  derivations moved out of the `prover`-gated module, so they are compiled and tested in
  every build rather than only in the ones that pull in the FHE stack.

### SDK: the configured and the declared key were compared case-sensitively

- Hex is case-insensitive, and the on-chain comparison goes through the ABI, which does not
  care about case — but the constructor's own check did, so a caller passing an EIP-55
  checksum-cased hash for the key their encryptor already declares was refused with "the
  pin check would attest to a key the shard is not encrypted under". The comparison is
  case-insensitive now, like the SDK's three other hash comparisons.

### Release tooling: the evidence pack did not produce what the release process promised

- `RELEASE_PROCESS.md` lists `ci.txt` (the CI run IDs covering the tagged commit) and
  per-suite exit codes among the evidence pack's artifacts. `scripts/evidence-pack.sh`
  produced neither: no `ci.txt`, and the exit code was only printed to the terminal,
  where it vanished with the shell. A tag whose evidence cannot name the runs that
  cleared it, or the exit code of the suite that ran, is not auditable.
- The pack now writes `ci.txt` (via `gh run list --commit`; it says so plainly when
  `gh` is unavailable rather than skipping the file) and `exit-codes.txt` with one
  `name=code` line per suite. The suite logs stay unedited, which is what the release
  process says they are.
- The pack recorded `hardhat --version` under the label `solc`, so the evidence named
  Hardhat's version (2.29.1) as the compiler version. The two are different: the
  contracts are compiled with solc 0.8.24, and the pack now reads that from the
  build-info (`hardhat` and `solc` are recorded separately, and before the first
  compile the pack says "NOT COMPILED" rather than recording a wrong number).
- `evidence/` was not in `.gitignore`, although the script's own header says its
  output is not committed — running the release tool dirtied the working tree with
  untracked output. It is ignored now.

### Repository: one branch, no open PRs, green CI

- The default branch is now `main` (renamed from `master`), and the eight workflows
  follow it. The rename left two gaps, both closed here: `site.yml`'s deploy job still
  gated on `refs/heads/master`, so a push to `main` would never have deployed the site,
  and the release documentation still named `master` as the branch a release is cut from.
- `fix/unified` is merged into the mainline (fast-forward, no conflicts). It carries the
  node build fix, the documentation that matches the fail-closed defaults, the node/web/SDK
  corrections, and the regenerated SDK ABI snapshots.
- The SDK ABI snapshots had drifted from the compiled contracts:
  `committeeSeed`, `isCommitteeEligible`, `committeeSize`, `NotCommitteeMember`,
  `taskBondTotal`, `topUpNodeBond` and `NodeBondToppedUp` were missing after #40
  added them. `sdk.yml` never caught it because its `paths` filter only covered
  `packages/sdk/**` — a Solidity change could not fail the ABI-drift test. The
  filter now includes `packages/contracts/src/**`, and the snapshots are
  regenerated to match.
- Every open PR is closed and every branch other than `main` is deleted
  (local and remote). The Dependabot branches go with their PRs; Dependabot will
  re-propose on its next weekly run, against a `main` that now builds.
- `feat/tg-bot-ux` was deleted rather than merged: it is the earlier version of
  the inline-keyboard/watchlist feature that is already on the mainline and was
  reworked there (`watchlist.js` 227 lines against 130, `keyboards.js` 154
  against 112, `index.js` 921 against 597, and longer versions of all three
  test files). `fix/rust-ci` was already contained in the mainline.

### CI: the link check raced the Pages deployment

- `links.yml` ran lychee over `README.md`, which links to the live Pages site
  (`ssrjkk.github.io/shroud/pipeline.html`, `.../use.html`, ...). Pages deploys
  asynchronously, so on any push that adds a page the deployment still serves
  the old tree and every one of those self-links 404s. The check therefore
  failed on the very push that introduced the pages it complained about — a race
  between two workflows, not a broken link, and one a re-run would "fix".
- Self-links are now verified against the repository: every
  `ssrjkk.github.io/shroud/...` reference must point at a file that exists in
  `web/`. That is deterministic and states the same property the old check was
  meant to establish. lychee keeps checking every external link and skips our
  own host.

### CI: one global concurrency group made every concurrent PR report red

- `site.yml` used a single `concurrency: group: pages` for every ref. GitHub keeps one
  job per group, so when several PRs were open at once, each new run **cancelled**
  the others — and a cancelled job is reported as a failed check. A batch of
  Dependabot PRs therefore showed `package static site` and `deploy to GitHub Pages`
  as red even though the site itself builds fine, which made it look like the site
  was broken when nothing was wrong with it. The group is now per-ref
  (`pages-${{ github.ref }}`): a new push to main still cancels the older main
  deploy, and unrelated PRs no longer cancel each other.
- The red was not the whole story, and the distinction matters: PR #43 failed for a
  real reason (the SDK's embedded ABI snapshot did not match the compiled
  `CipherTask` artifact) and PR #46 for another (`hardhat-ethers` 4.x conflicts with
  the `^3.1.3` peer range `@fhevm/hardhat-plugin` requires). Those are dependency
  problems, not CI problems, and are closed as such.

### Node: the build needed a flag nobody set — CI could not compile the crate

- `alloy-signer-local` 2.5.0 calls `<[u8; 32]>::from(self.to_field_bytes())`, and the
  `From<GenericArray<T, N>> for [T; N]` impl that requires is an orphan-rule violation,
  so `generic-array` gates it behind `--cfg relaxed_coherence` and offers `Into`
  instead. The flag was set in one developer's shell on 2026-10-18 and nowhere else:
  **CI compiled with `RUSTFLAGS: "-D warnings"` only, so `cargo check --locked
  --all-features` could not build the crate at all** — the failure is a trait error
  inside a dependency that never mentions `generic-array`, which is what makes it
  hard to read.
- The flag now lives in the repository, in two places that must agree: `node/.cargo/config.toml`
  (for every local build) and the CI `RUSTFLAGS` (the environment variable *replaces*
  `build.rustflags` rather than extending it). `--check-cfg cfg(relaxed_coherence)`
  comes with it: `--cfg` for a name the crate does not declare trips `unexpected_cfgs`,
  and CI compiles with `-D warnings`.
- `infra/node/Dockerfile` needed the same fix: its dependency-cache stage copied only
  `Cargo.toml` / `Cargo.lock` / `build.rs` / `proto`, so the image build would have
  failed the same way before the real source was even copied. It now copies
  `node/.cargo` as well.
- Verified: `cargo check --locked --all-targets --all-features` and `cargo fmt --all -- --check`
  pass with the flag; without it the crate does not compile. `cargo clippy` is clean on both
  feature sets (with `--all-targets`, which the CI invocation does not lint), and the suites
  run green: 174 node tests and 14 `shroud-core` tests.

### Node: key-pin and weight checks are on by default, config fails closed at load

- `node.enforce_key_pin` and `node.strict_weights` default to **true**. A node with the
  pin check on but no `fhe.public_key_hash` / `contracts.network_params` refuses to boot
  instead of running unpinned, and an epoch whose seed weights are not a decodable
  `shroud/weights/v1` file is a hard error instead of a silent fallback to genesis zeros.
  Devnet opts out explicitly, per field.
- `Config::validate` now rejects the configurations that parse but make the node useless:
  an empty `chain.rpc_url` or `shard.da_endpoint`, a `da_endpoint` scheme nothing serves
  (`s33://`), whitespace around the endpoint, a zero `shard.max_ciphertext_bytes` /
  `stark.max_proof_bytes` / `payment.redeem_gas_limit`, and a zero `chain.poll_interval`
  or `mesh.announce_interval` (those two busy-loop instead of polling).
- A node that refuses to boot now says why. `ConfigError::Missing` carries an optional
  reason, and the two pin checks use it: with `enforce_key_pin` on by default, "missing
  required field `fhe.public_key_hash`" was a dead end — the message now names the
  opt-out (`node.enforce_key_pin = false`) as well as the two fields to set instead.
- F-08 in `docs/04-threat-model.md` is re-graded from "not mitigated" to **"mitigated at
  boot, not mid-epoch"** — the node-side check is on by default, but it still runs once,
  at startup, and the SDK half is still skipped when the caller does not pass a pin.
- Every place that still described the old behaviour was corrected to match the code:
  `README.md`, `OPERATOR_RUNBOOK.md`, `USER_GUIDE.md`, `infra/README.md`,
  `AUDIT_SCOPE.md`, `TRUST_ASSUMPTIONS.md`, `docs/01-architecture.md`,
  `docs/05-honest-limitations.md`, `bot/README.md`, and the F-08 rows of
  `web/security.html` + `web/protocol.html` (RU and EN in lockstep).
- Robustness on hot paths: the watcher drops pending logs that carry no block number
  instead of folding them as block 0 (which would reorder a commit against its
  settlement); the TFHE backend returns a typed error on a truncated header instead of
  panicking; the mesh throttle and the epoch lookup fail closed instead of `expect`ing;
  a closed shard-fetch semaphore surfaces as an error rather than a task panic.
- `hostile_headers_are_errors_never_panics` was not testing what its comment said.
  The header it builds is `b"4294967295\04294967295\0"`, and `\042` is the *octal*
  escape 0o42 (a quote) — not a NUL followed by "42" — so the decoder rejected the
  header one step earlier, on the non-digit, and the overflow the test is named after
  was never reached. Rewritten with `\x00`, which is unambiguous, and it now exercises
  the `rows × features` overflow it claims to.

### Site: mobile matrix — 7 devices, 3 real fixes

- Ran the site through emulated devices over CDP (iPhone SE/14, Pixel 7,
  Galaxy S8, 320px small, landscape, iPad — viewport, DPR, touch, mobile UA):
  49 combinations measured for document overflow, tiny tap targets, burger
  menu and section-bar visibility.
- `security.html` overflowed the document on every portrait phone: the report
  notice holds the unbreakable advisories URL (485px at 320–412px viewports).
  `.notice` now wraps long words; document width equals the viewport on all
  devices, verified by re-running the matrix.
- Footer links were 14–16px tap targets; they now have vertical padding
  (33px, above the 24px minimum), measured live.
- The section bar hid at 900px, so landscape phones lost it; the breakpoint
  is 700px now, verified shown on 844px landscape and hidden on small
  portraits.

### Contracts/SDK: VRF-committee ABI drift fixed, CI hole closed

- `packages/sdk` was failing its own gate: 2 of 60 smoke tests red
  ("CipherTask/PaymentVault ABI matches the compiled artifact"). The SDK's
  embedded ABIs predated PR #38 and missed the whole VRF dispute committee
  (`NotCommitteeMember`, `committeeSeed`, `committeeSize`, `isCommitteeEligible`).
  Nothing extraneous — a pure lag. Re-ran the repo's own
  `scripts/export-abi.cjs` (+150/−1 lines across the two JSONs, the single
  deletion is the JSON tail) and the suite is green again.
- Why CI didn't catch it: `sdk.yml` only watched `packages/sdk/**`, while the
  drift came from `packages/contracts/src/**` in #38 — and `contracts.yml`
  never runs the SDK suite. `sdk.yml` paths now include
  `packages/contracts/src/**`, so a Solidity change with a stale `src/abi/`
  snapshot fails there even when the SDK itself is untouched.
- Verified around the fix: contracts `hardhat test` 136 passing + vectors 2
  passing, bot 117/117, `cargo fmt --check` clean (compile itself still needs
  the full toolchain per `docs/05-honest-limitations.md` §8), both touched
  workflows parse as YAML.

### Site: pool shares labelled as the devnet example, not constants

- `8000 / 1500 / 500` were shown as protocol constants (home `03 / PRO`,
  protocol `pro.stxp`), but `TaskParamsLib.requireShares` only enforces that
  the three per-task shares sum to BPS — the numbers are the devnet-script and
  docs example. Both strings now say so in RU and EN; the formulas keep the
  concrete numbers, now introduced as the example.

### Site: honest lab guards and a copy fallback that always answers

- The lab's "calculate payouts" bench reported success on empty state:
  `doSettle()` is a pure function of the budget and had no guards, so clicking
  it first thing printed "matches CipherTask._settle" over zeroes. It now
  refuses with the existing `lab.m.noepoch` message until at least one epoch
  ran — same for `doProof()`, whose old `prevLanes.length` check could never
  fire (lanes are zero-initialised, never empty). Both verified live: refusal
  on empty state, success after `runAll`, refusal again after epoch reset.
- The copy button could leave the user with no feedback at all: if
  `clipboard.writeText` neither resolves nor rejects (a hanging permission),
  the label never flipped. It now races the promise against a 1.5s timer that
  falls back to the textarea + `execCommand` path. Verified with an async
  probe: label flips to the confirmation and restores itself.

### Site: menu announces the current page, theme tooltip follows the language

- The active menu item now carries `aria-current="page"`. The `active` class
  was visible to sighted users but silent to screen readers; `nav.mjs` rule 3
  asserts it sits on exactly one link per page and points at that page
  (verified against a copy with the attribute removed — fails as expected).
- The theme button's tooltip was hardcoded English (`title="Theme"`) on Russian
  pages while its `aria-label` translated fine. `app.js` now sets the title
  from the same `theme.toggle` key on load and on every language switch
  (RU "Переключить тему" / EN "Toggle theme", verified live).

### Site: the reading-mode switch is now reachable

- The site has advertised newcomer / pro modes from the start, but the buttons
  existed only inside the lab: `data-mode-btn` appeared in `playground.html` and
  nowhere else. Landing straight on the home page meant `03 / PRO` — the
  constants table — was simply unreachable, and there was no way to leave pro
  mode either. The switch now sits in the masthead of the four pages whose
  content actually changes with it (home, protocol, security, license) and
  shares the existing `shroud-mode` key in localStorage, so the choice follows
  the visitor across the site. Pipeline and practice deliberately have no
  switch: nothing on them is gated by the mode, and a dead control is worse
  than none.
- Masthead spacing tightened (segment padding 10→8px, gaps 12→10 and 6→4) so
  brand + seven menu items + theme + language + mode still fit on one row at
  1280px: measured 1084px of the 1132px available in the worst case (Russian),
  939px in English.
- `aria-label` on the language and mode groups was hardcoded English
  ("language", "mode") on Russian pages; both are translated now.
- `nav.mjs` gained the invariant that made this class of bug visible: a page with
  `only-new` / `only-pro` blocks must have a mode switch, and a page with a mode
  switch must have such blocks. Verified in both directions on a throwaway copy.

### Site: motion and small tools (no new dependencies, no build step)

- **Animations**, all of them decorative and reversible: hero elements rise in
  sequence once on load; every section header draws a short accent tick when it
  enters the viewport; the arrows in Diagram A flow along their own direction;
  the status ticker now actually scrolls (seamless, pauses on hover); cards lift
  and light up their border on hover/focus; menu underlines grow from the left.
- **Small tools**: an auto-built section bar under the masthead with a scroll-spy
  (pages with 3+ sections: home, security, protocol) — every section
  also gets a stable `id`, so `#sec-3` style deep links work and respect the
  existing `scroll-margin-top`; a copy button on every `pre.code` block (labels
  follow the language, hidden on touch devices where hover does not exist); a
  2px scroll-progress line and a "back to top" button.
- The section bar is `sticky` and sits in the flow right after the masthead
  rather than being `fixed`. Fixed positioning put it *under* the header: the
  header does not start at the top of the viewport (`.topbar` is above it) and
  it covers the bar with its own background, which left an empty frame on
  screen. Found by rendering the site and looking at the result.
- `prefers-reduced-motion` is honoured in both directions: CSS kills the motion,
  and JS skips ticker duplication and reveal observers entirely.
- Progress and "back to top" write styles straight from the scroll handler (no
  `requestAnimationFrame`), so they keep working when frames are throttled.
- 4 new i18n keys (`ui.copy`, `ui.copied`, `ui.toc`, `ui.top`), RU/EN symmetric
  at 563 keys each. No claim, number or guarantee was added or softened.
- New `web/tests/i18n.mjs` (wired into the `site` workflow and the CONTRIBUTING
  pre-push list): ru/en key-set symmetry, every `data-i18n*` key in the markup
  resolving in both languages, and keys that nothing references — markup or JS.
  It caught one leftover (`idx.more`) from the section that moved to
  `security.html`, which was removed.
- New `web/tests/nav.mjs` (same two places): every page present in the menu,
  identical menu order on all seven pages, exactly one `active` item pointing
  at its own page, live `#anchors`, skip link present, every page reachable
  from the home. With seven hand-copied menus this was the regression most
  likely to happen; the test was itself verified against five deliberate
  breakages (missing menu item, lost `active`, extra page, dead anchor,
  unreachable page) and caught all five.
- Section ids are numbered without gaps now, so `#sec-3` is the third section
  of the page on every page.
- `docs/shots/*.png` re-rendered from the current site: `home.png` showed the
  pre-split single-page home, `mobile.png` and `protocol.png` still had the
  five-item menu. Captured with headless Chrome at the same sizes as before
  (1440×960, 1440×2600, 1440×2400, 500×1000).

### Site: one page per topic (home stops being a single scroll)

- `web/index.html` is now a hub: hero + the three plain-language steps + a
  "where to go" card grid (6 links) + repository table + the pro constants block.
  It went from 192 to 129 lines; the four long sections moved to pages of their own.
- New `web/pipeline.html` (data-and-money diagram, the FHE/PROOF/MONEY cards, the
  ticker) and new `web/use.html` (lab cycle, four roles, devnet quickstart). Each has
  its own title, meta description, topbar status and `nav` active item.
- The home page's `03 ENFORCED` / `04 NOT YET` sections were **folded into the existing
  tables on `security.html`** instead of being copied there: the three gaps already
  exist as `01 / GAPS` rows (F-04, F-01, §3, F-10), and the three unique rows survive
  as a new `sec.g6` gap (end-to-end FHE, still a goal) plus `sec.e13` / `sec.e14`
  (explicit budgets, paged settlement). No security claim was dropped.
- i18n: keys re-prefixed per page (`pip.*`, `use.*`, `sec.*`), 19 duplicated keys
  removed, 27 added — `ru` and `en` stay symmetric at 560 keys each, all 497 keys
  used in markup resolve in both languages.
- Nav is identical on all seven pages (home, pipeline, practice, lab, protocol,
  security, license); `active` moved per page; no JS added.

### Security hardening (merged as #14–#19)

- Contracts (#14): `abort` reverts once every epoch ran (`SettleReady` — buyer rug
  closed); duplicate `ciphertextCid` rejected per task (`DuplicateShard`); node
  registration capped (`MAX_NODES = 200`, `nodeCount`); winner seat follows the first
  verified commit (mempool proof-copy cannot steal it); SDK ABI re-exported.
- SDK + ShardStore (#15): store addresses by real keccak-256 (was SHA3-256);
  download caps enforced while streaming with early cancel; `206` always requires
  `content-range`; relayer proofs require a `CipherTask` binding (no `ZeroAddress`);
  `getVerified` memo (bounded FIFO, copies in/out).
- Bot (#16): command dispatch uses the guard's single parse; replies go through the
  bounded send queue (`droppedSends` stays honest).
- Node (#17): full-table throttle evicts the stalest bucket (was fail-open admit);
  `mesh.max_throttle_peers` configurable (default 10000, fail-closed validation).
- Site (#18): source links track HEAD; FHE claims reframed as goal/production-path;
  lab button assembles shards; EN findings count corrected to 39; equiv fuzzes
  non-zero lanes (incl. i32 edges) and weights rejections.
- Guards (#19): `--locked` cargo builds; `links.yml` (lychee + no-pinned-`/main/`
  guard); pre-push checklist in `CONTRIBUTING.md`.
- Docs (#20): hardcoded test counts replaced with CI links.
- Trust docs (#21): `SECURITY_MODEL.md`, `TRUST_ASSUMPTIONS.md`, `CHANGELOG.md`,
  advisory triage (§7b), CodeQL for JS/TS.
- Trust round 2 (#22): README research banner, honest titles, ShardStore ETags,
  `AUDIT_SCOPE.md`.
- Release hygiene (#23): `VERSIONING.md`, `RELEASE_PROCESS.md`, evidence-pack script.
- SDK batch reads (#24): `getManyVerified` (bounded parallelism, order-preserving).
- Site honesty (#25): download buttons name the actual demo files.

### Prior base (pre-split, PR #12 lineage)

- Phase 2 execution engine wired into the worker (reference-cpu + tfhe-rs behind
  `prover`); two-node devnet agreement check in CI.
- Ubuntu 24.04 pinned across workflows; `Cargo.lock` committed.
- Contribution bonds (opt-in), commit-reveal disputes, segmented commits, settlement
  maturity gating, BLS proof-of-possession on registration.
