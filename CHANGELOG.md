# Changelog

All notable changes. Counts live in CI — this file records behaviour, not test numbers.
No tags or releases are published yet; entries below are merge-PR scoped until the
first tagged release.

## Unreleased

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
  The encoder writes a row count now, and a round-trip test covers it.
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

- `fix/unified` is merged into `master` (fast-forward, no conflicts). `master` now
  carries the node build fix, the documentation that matches the fail-closed
  defaults, the node/web/SDK corrections, and the regenerated SDK ABI snapshots.
- The SDK ABI snapshots on `master` had drifted from the compiled contracts:
  `committeeSeed`, `isCommitteeEligible`, `committeeSize`, `NotCommitteeMember`,
  `taskBondTotal`, `topUpNodeBond` and `NodeBondToppedUp` were missing after #40
  added them. `sdk.yml` never caught it because its `paths` filter only covered
  `packages/sdk/**` — a Solidity change could not fail the ABI-drift test. The
  filter now includes `packages/contracts/src/**`, and the snapshots are
  regenerated to match.
- Every open PR is closed and every branch other than `master` is deleted
  (local and remote). The Dependabot branches go with their PRs; Dependabot will
  re-propose on its next weekly run, against a `master` that now builds.
- `feat/tg-bot-ux` was deleted rather than merged: it is the earlier version of
  the inline-keyboard/watchlist feature that is already in `master` and was
  reworked there (`watchlist.js` 227 lines against 130, `keyboards.js` 154
  against 112, `index.js` 921 against 597, and longer versions of all three
  test files). `fix/rust-ci` was already contained in `master`.

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
  (`pages-${{ github.ref }}`): a new push to master still cancels the older master
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
