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

`docs/05-honest-limitations.md` records a gap that no test covers: participants
**cannot** detect a substituted FHE public key at submission time. `NetworkParams`
pins the key correctly on chain, but nothing reads it — the SDK has no reference
to `s_pub`, and the node's `enforce_key_pin` flag is dead code. A malicious
sequencer can swap the key and harvest ciphertexts, and the only detection is
forensic, after the fact.

So the bot watches `RotationProposed` and `RotationExecuted` and says so loudly.
If a rotation appears that you did not initiate, the correct response is to stop,
not to keep uploading.

## Commands

| command | what it answers |
|---|---|
| `/status` | chain, head, pinned FHE key hash, committee threshold, **pending rotation** |
| `/pool` | the most recent tasks with status, budget and contributor count |
| `/task <id>` | one task, plus that epoch's commits — and whether they disagree |
| `/limits` | what this deployment does *not* protect against |
| `/help` | the list above |

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

22 tests, no bot token and no chain required. They cover the parts that fail
quietly in production:

- HTML escaping of chain-derived values, so on-chain data cannot inject markup
  into a chat
- `not configured` vs `unreadable` vs `read` as three distinct states
- the commit-mismatch condition actually being detected
- config validation, including that a missing or non-numeric allowlist stops
  the bot rather than opening it

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
- **It has never been run against a live deployment.** The devnet does not
  currently deploy (threat model F-31), so the chain path is verified against the
  compiled ABIs and a real unreachable-RPC failure, not against running
  contracts. Formatting, config and access control are tested.