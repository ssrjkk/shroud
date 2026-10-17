# Shroud Telegram bot

An operations bot for a Shroud deployment: task pool, disputes, and — the reason
it exists — **network key rotation alerts**.

Read-only by construction. It holds no private key and has no code path that signs
or sends a transaction. Everything it reports comes from an `eth_call` or an
`eth_getLogs` against an RPC URL you already control.

```
npm install
cp .env.example .env      # then edit it — see below
npm start
```

## Why the key-rotation alert is the important one

`docs/05-honest-limitations.md` records a gap that no default configuration covers: participants
**cannot** detect a substituted FHE public key at submission time. `NetworkParams`
pins the key correctly on chain, but nothing reads it by default — the SDK checks only when
the caller passes `networkParams` + `fhePublicKeyHash`, and the node's `enforce_key_pin`
check is opt-in (and runs once, at startup). A malicious sequencer can swap the key and
harvest ciphertexts, and the only detection is forensic, after the fact.

So the bot watches `RotationProposed` and `RotationExecuted` and says so loudly.
If a rotation appears that you did not initiate, the correct response is to stop,
not to keep uploading.

## Commands

| command | what it answers |
|---|---|
| `/status` | chain, head, pinned FHE key hash, committee threshold, **pending rotation** |
| `/pool [page]` | the most recent tasks with status, budget and contributor count, 12 per page |
| `/task <id>` | one task, plus that epoch's commits — and whether they disagree |
| `/watch <id>` | narrow this chat's task alerts to a task (repeat per task) |
| `/unwatch <id>` | stop watching a task |
| `/watchlist` | tasks this chat watches — empty means everything |
| `/alerts` | per-chat alert flags with tap-to-toggle buttons |
| `/limits` | what this deployment does *not* protect against |
| `/help` | the list above |

Every reply carries inline buttons that do the same as the commands: pool
pages (`‹ prev` / `next ›`, task shortcuts), task refresh / watch / neighbour
navigation, status refresh, and alert toggles. Buttons edit the message
in place; a press on a stale button (older bot version) answers with a hint
instead of firing RPC. Button traffic is priced through the same per-chat
abuse budget as typing (`/pool`-equivalent presses cost 15, `/task` 5,
`/status` 4, local-only presses 1).

## Watchlist and per-chat alerts

`state/watchlist.json` holds, per chat id, the watched task ids (max 200)
and alert-flag overrides. Writes are atomic (tmp file + rename); a corrupt
file is moved aside to `watchlist.corrupt-<timestamp>.json` and replaced
with an empty state, so one bad byte never bricks the bot.

Semantics, deliberately conservative:

- Empty watchlist (default) = every task-scoped alert, exactly as before.
- Non-empty watchlist = commit-mismatch and dispute alerts only for watched
  tasks. Key-rotation alerts are global and ignore the watchlist.
- Per-chat flags (`/alerts`, toggles `mismatch` / `disputes` / `rotation`)
  override the global `ALERT_*` `.env` flags when set, inherit them when unset.

Task-scoped alerts carry a `view task #id` button; rotation alerts carry a
`view status` button.

## Alerts

Configurable in `.env`, all off-by-default-risk since they only *add* output:

| variable | default | alerts on |
|---|---|---|
| `ALERT_COMMIT_MISMATCH` | on | one node committing twice for the same epoch with different digests |
| `ALERT_DISPUTES` | on | disputes, epoch rejections, settlements, status changes |
| `ALERT_KEY_ROTATION` | on | any network parameter rotation |

`ALERT_COMMIT_MISMATCH` watches for the *same* node committing two different
digests for one epoch. On chain that cannot happen — the contract rejects it — so
it means a non-deterministic executor or a node bug. `/task` separately flags
*different* nodes disagreeing about an epoch, which is the condition a dispute
exists for and is not itself a bug.

Dispute alerts now also cover `DisputeCommitted` — the commit-reveal front half of a
dispute. A commitment with no follow-up reveal is a stuck reporter or someone probing
the quorum, and it is worth knowing about before the reveal lands.

## Anti-abuse (per-chat throttling)

One command costs up to ~15 RPC calls (`/pool`), so a compromised allowlisted chat
is an amplification vector onto the RPC node. `src/abuse.mjs` prices commands in
RPC-load units (`/pool` 15, `/task` 5, `/status` 4, `/help` 1) against a per-chat
sliding-window budget; over-budget chats get a retry-after reply, floods of
identical commands raise a decay-scored risk, greylisted chats are tarpitted and
spammers are shadowbanned — a plausible reply with zero RPC behind it. Every
handler additionally runs under `ABUSE_HANDLER_TIMEOUT_MS`, and the RPC provider
itself carries `RPC_TIMEOUT_MS`, so a dead node fails commands in milliseconds
instead of stalling both poll loops. All knobs are env (`ABUSE_*`, see
`.env.example`); the guard is fail-open (better an extra RPC than a dead bot).

## Setup

### 1. Create the bot

Message [@BotFather](https://t.me/BotFather), `/newbot`, and keep the token.

### 2. Find your Telegram id

Message your bot, then open:

```
https://api.telegram.org/bot<TOKEN>/getUpdates
```

and read `messages[0].from.id`.

### 3. Fill in `.env`

Two values are mandatory and the process **refuses to start without them**:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_ALLOWED_IDS`

The allowlist is the only thing between an open bot and a full read of task
budgets, operator addresses and dispute activity. A `@username` in that field is
rejected rather than ignored, because a username would never match a numeric id
and the failure would look like "the bot is down".

Leave a contract address unset and the matching command says *not configured*
rather than reporting an empty pool — a bot that reports "no tasks" when it is
simply pointed at the wrong address is worse than one that admits it does not
know.

## Tests

```
npm test
```

103 tests, no bot token and no chain required. They cover the parts that fail
quietly in production:

- HTML escaping of chain-derived values, so on-chain data cannot inject markup
  into a chat
- `not configured` vs `unreadable` vs `read` as three distinct states
- the commit-mismatch condition actually being detected
- chain reads against a stub JSON-RPC server with ABI-encoded responses — this is
  what caught `new <Interface instance>` (every read threw, every read caught, so
  the bot reported empty pools forever) and `Number()` of the dispute-quorum pair
  (always `NaN`)
- log identity for the alert loop: decoded logs carry `transactionHash` + `index`
  (this caught `#decode` reading `log.hash`, which does not exist on an ethers v6
  `Log` — every rendered "tx …" was `undefined`), and `eventUid`/`dedupeEvents`
  suppress re-alerts across restarts and reorg rewinds
- config validation, including that a missing or non-numeric allowlist stops
  the bot rather than opening it
- per-chat abuse quotas (heavy commands cost more), input sanitization, flood →
  shadowban escalation, handler deadlines, and the RPC timeout failing fast
- bounded Telegram send queue (over-cap alerts shed newest-first with a counter,
  broadcasts never grow memory without limit)
- inline keyboards: callback payloads parse total (garbage in, null out, never
  a throw), every emitted payload fits the 64-byte cap, pool pages clamp,
  watch/unwatch flip state with a toast, alert toggles resolve against globals
- watchlist persistence: atomic tmp+rename writes, corrupt-file backup with an
  empty start, empty-means-everything filtering, file-store mutation contract
- delivery routing: flag source × watchlist × alert scope matrix, unknown keys
  dropped rather than broadcast
- transport: callback ack/edit payloads, toast truncation, explicit 4096-cut
  that always fits, stale-edit fallback contract

## Honest limits of the bot itself

- **Long polling, not webhooks.** An ops bot runs on your machine behind NAT with
  no public URL, so a webhook would need infrastructure this does not have.
  Trade-off: Telegram caps long polling at ~25 updates/s, which is irrelevant
  here but would be for a busy public bot.
- **At-least-once alerts with duplicate suppression, not exactly-once.** Every
  observed log is remembered by `transactionHash:logIndex` (persisted, capped at
  2000) and skipped on rescan, and a reorg below the cursor rewinds instead of
  skipping the range. What remains: a crash between sending and persisting still
  re-alerts (a duplicate is noise; a loss would be an incident, so this is the
  right bias), and a log the RPC never returns is never alerted on.
- **It reports what the chain says, not whether the chain is honest.** Every
  caveat in `/limits` applies to the bot too: it is a better way to notice a key
  rotation, not a way to prove one did not happen.
- **It has never been run against a live deployment.** Reads are pinned against a
  stub JSON-RPC server returning ABI-encoded responses, not against running
  contracts. Formatting, config and access control are tested.