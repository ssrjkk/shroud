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
| `/pool [page]` | the most recent tasks with status, budget and contributor count, 8 per page |
| `/task <id>` | one task, plus that epoch's commits — and whether they disagree |
| `/watch <id>` | alert this chat about one task (toggle) |
| `/unwatch <id\|all>` | stop following |
| `/watchlist` | what this chat follows |
| `/alerts` | per-chat alert switches |
| `/limits` | what this deployment does *not* protect against |
| `/help` | the list above |

Almost every screen carries inline buttons underneath: pool pages, prev/next
task, refresh (which rewrites the message in place instead of stacking new
ones), watch toggles, and alert switches. Tapping a button does the same thing
as typing the command — `/pool 2`, `t:7`, `w:7` are just the typed spellings of
the same verbs, so nothing is reachable *only* by button or *only* by typing.

## Per-chat state

Two things are remembered per chat, in `state/watchlist.json` (atomic write,
corrupt file degrades to empty rather than crashing):

- **watchlist** — task ids this chat follows. A chat that watches nothing gets
  every task alert (the old broadcast); a chat watching `#5` gets only `#5`
  plus key rotations, which always reach everyone.
- **alert overrides** — each family (`mismatch`, `disputes`, `key rotation`)
  can be forced on/off per chat via `/alerts`; unset means "follow `.env`".
  The env flags stay a global kill switch with one exception: a chat that
  explicitly switched a family *on* still receives it when the env has it
  *off* — otherwise the switch would be a lie.

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

53 tests, no bot token and no chain required. They cover the parts that fail
quietly in production:

- HTML escaping of chain-derived values, so on-chain data cannot inject markup
  into a chat
- `not configured` vs `unreadable` vs `read` as three distinct states
- the commit-mismatch condition actually being detected
- chain reads against a stub JSON-RPC server with ABI-encoded responses — this is
  what caught `new <Interface instance>` (every read threw, every read caught, so
  the bot reported empty pools forever) and `Number()` of the dispute-quorum pair
  (always `NaN`)
- config validation, including that a missing or non-numeric allowlist stops
  the bot rather than opening it
- every callback button parses back into a known verb (unknown data fails
  loudly), payloads fit the 64-byte cap, and paging never offers a missing page
- watchlist routing (empty = broadcast, rotations always global) and the
  alert-override cycle, against an ephemeral store — no token, no chain

## Honest limits of the bot itself

- **Long polling, not webhooks.** An ops bot runs on your machine behind NAT with
  no public URL, so a webhook would need infrastructure this does not have.
  Trade-off: Telegram caps long polling at ~25 updates/s, which is irrelevant
  here but would be for a busy public bot.
- **The alert cursor is per-block, not per-event.** A crash between the RPC read
  and the cursor save re-alerts on that window. Cursor saves are written after
  each scan, so the window is one poll interval.
- **It reports what the chain says, not whether the chain is honest.** Every
  caveat in `/limits` applies to the bot too: it is a better way to notice a key
  rotation, not a way to prove one did not happen.
- **It has never been run against a live deployment.** Reads are pinned against a
  stub JSON-RPC server returning ABI-encoded responses, not against running
  contracts. Formatting, config and access control are tested.