/**
 * Shroud operations bot.
 *
 * Read-only by construction: it holds no private key and has no code path that
 * signs or sends a transaction. Everything it reports comes from an `eth_call`
 * or an `eth_getLogs` against a chain URL the operator already controls.
 *
 * Two independent loops:
 *   1. Telegram long polling for commands.
 *   2. A block scanner for alerts, with a persisted cursor so a restart resumes
 *      instead of replaying the whole chain or skipping the gap.
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";

import { loadConfig, configuredContracts, ConfigError, ROOT } from "./config.js";
import { TelegramBot } from "./telegram.js";
import { ChatAbuseGuard, loadAbuseConfig } from "./abuse.mjs";
import { ChainReader, makeInterfaces, poolIds, shortId, shortAddr } from "./chain.js";
import {
  renderStatus,
  renderPool,
  renderTask,
  renderCommitMismatch,
  renderDispute,
  renderRotation,
  renderLimits,
  renderHelp,
} from "./format.js";

const CURSOR_FILE = resolve(ROOT, "state", "cursor.json");

const COMMANDS = [
  { command: "status", description: "chain, key pin and pending rotation" },
  { command: "pool", description: "recent tasks" },
  { command: "task", description: "<id> — one task with its epoch commits" },
  { command: "limits", description: "what this deployment does not protect against" },
  { command: "help", description: "this list" },
];

/**
 * Curried logger: `log("info", config)("message", detail)`.
 *
 * Returns a function rather than printing directly so that every call site reads
 * the same way and the level check happens in one place.
 */
function log(level, config) {
  const order = { error: 0, warn: 1, info: 2, debug: 3 };
  const threshold = order[config?.logLevel] ?? order.info;
  return (...parts) => {
    if ((order[level] ?? 2) > threshold) return;
    const line = `[${new Date().toISOString()}] ${level.toUpperCase()} ${parts
      .map((p) => (typeof p === "string" ? p : JSON.stringify(p)))
      .join(" ")}`;
    (level === "error" ? console.error : console.log)(line);
  };
}

/**
 * Load the alert cursor, or start from `catchupBlocks` behind the head.
 *
 * Starting at the head would silently skip whatever happened while the bot was
 * down; starting at zero would re-alert on the entire history. A bounded
 * catch-up window is the honest middle, and the value is configurable because
 * "how far back" depends entirely on how long the bot is expected to be off.
 *
 * The cursor also carries the identities of the events already alerted on
 * (`txHash:logIndex`, capped), so a restart or a reorg rewind does not re-alert
 * on the same logs: at-least-once delivery with duplicate suppression, rather
 * than the previous at-most-once `save-before-send`.
 */
async function loadCursor(startBlock, catchupBlocks) {
  try {
    const raw = JSON.parse(await readFile(CURSOR_FILE, "utf8"));
    if (Number.isInteger(raw.cursor) && raw.cursor >= 0) {
      const seen = Array.isArray(raw.seen) ? raw.seen.filter((s) => typeof s === "string") : [];
      return { cursor: raw.cursor, seen: new Set(seen) };
    }
  } catch {
    // No cursor yet, or unreadable: fall through to a fresh window.
  }
  return { cursor: Math.max(0, startBlock - catchupBlocks), seen: new Set() };
}

/** Cap on remembered event identities: enough for weeks of alerts, small on disk. */
export const MAX_SEEN_EVENTS = 2000;

async function saveCursor(cursor, seen) {
  try {
    await mkdir(dirname(CURSOR_FILE), { recursive: true });
    const arr = [...seen].slice(-MAX_SEEN_EVENTS);
    await writeFile(CURSOR_FILE, JSON.stringify({ cursor, at: Date.now(), seen: arr }, null, 2));
  } catch (err) {
    // A cursor we cannot persist only costs us alert continuity on the next
    // start; it must not take the bot down.
    console.warn("could not persist cursor:", err.message);
  }
}

/**
 * Stable identity of a decoded log, or `null` when the log carries none.
 *
 * `txHash:logIndex` survives reorgs (a reorged log has a different hash) and restarts.
 * Logs without either field cannot be deduplicated and are always surfaced: for an ops
 * bot a duplicate alert is noise, a lost one is an incident.
 */
export function eventUid(ev) {
  if (typeof ev?.txHash === "string" && Number.isInteger(ev?.logIndex)) {
    return `${ev.txHash}:${ev.logIndex}`;
  }
  return null;
}

/**
 * Split `events` into unseen ones, recording everything observed.
 *
 * Pure so the rewind/dedupe behaviour is pinned by a test rather than by inspection:
 * identity-less events always pass through (see `eventUid`), seen events are dropped,
 * and every identity observed is remembered for the next scan.
 */
export function dedupeEvents(events, seen) {
  const fresh = [];
  for (const ev of events) {
    const uid = eventUid(ev);
    if (uid === null) {
      fresh.push(ev);
      continue;
    }
    if (seen.has(uid)) continue;
    seen.add(uid);
    fresh.push(ev);
  }
  return fresh;
}

/**
 * Arguments for the commit-mismatch alert from a re-commit event and the digest
 * previously seen for the same (task, epoch, node).
 *
 * Pure so the mapping is pinned by a test: an earlier revision passed the previous
 * digest as `winnerDigest` (which the renderer ignores) and omitted `previousDigest`,
 * so every alert read "previously —".
 */
export function mismatchArgs(ev, prev) {
  return {
    taskId: ev.args.taskId,
    epoch: ev.args.epoch,
    challenger: ev.args.node,
    challengerDigest: ev.args.traceDigest,
    previousDigest: prev,
  };
}

/**
 * Command handlers over an already-resolved chain reader.
 *
 * Exported for tests: `main` wires the real reader, tests hand a stub whose calls
 * are recorded, which is what pins the pool window and the /task composition
 * (commits/winner/quorum for the running epoch) without a chain.
 */
export function createHandlers(chain, config, ops = {}) {
  return {
    async help() {
      return renderHelp();
    },
    async limits() {
      return renderLimits();
    },
    async status() {
      const chainIdNow = await chain.chainId();
      const np = await chain.networkParams();
      const pending = np ? await chain.pendingRotation() : null;
      const out = renderStatus(
        { chainId: chainIdNow, blockNumber: await chain.blockNumber(), networkParams: np, pendingRotation: pending },
        config
      );
      // Shed alerts are invisible by design (the queue drops newest-first overflow) —
      // surfacing the counter here is the only way an operator learns alerts were lost.
      const dropped = typeof ops.droppedSends === "function" ? ops.droppedSends() : 0;
      if (dropped > 0) {
        return out + `\n\n${"⚠️"} <b>${dropped} alert(s) shed by the send queue</b> — ` +
          `the bot dropped outbound messages faster than Telegram drained them. ` +
          `Treat recent silence as data loss, not as calm.`;
      }
      return out;
    },
    async pool() {
      const count = await chain.taskCount();
      const items = [];
      for (const id of poolIds(count, 12)) {
        items.push(await chain.task(id));
      }
      return renderPool(items);
    },
    async task(args) {
      if (!args.length) return "usage: /task &lt;id&gt;";
      // Санитизация до RPC: id — короткий decimal. Длинная строка здесь — либо мусор,
      // либо попытка заставить ноду жевать BigInt из килобайта цифр.
      if (!/^\d{1,20}$/.test(args[0])) return "task ids are decimal integers. Try /pool.";
      const id = BigInt(args[0]);
      const t = await chain.task(id);
      const commits = t ? await chain.commitsForEpoch(id, t.nextEpoch) : [];
      const winner = t ? await chain.epochWinner(id, t.nextEpoch) : null;
      const quorum = t ? await chain.disputeQuorum(id) : null;
      return renderTask({ task: t, commits, winner, quorum }, id);
    },
  };
}

async function main() {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) {
      console.error(`\nCannot start: ${err.message}\n`);
      process.exit(2);
    }
    throw err;
  }

  log("info", config)("configuration accepted; allowed chats:", [
    ...config.allowedChatIds,
  ].join(", "));

  // Identities are loaded before the chain so a misconfigured path fails before
  // anything starts polling.
  let interfaces;
  try {
    interfaces = makeInterfaces();
  } catch (err) {
    console.error(`\nCannot start: ${err.message}\n`);
    process.exit(2);
  }

  let chain;
  try {
    chain = await ChainReader.connect(config, interfaces);
  } catch (err) {
    console.error(`\nCannot reach the chain: ${err.message}\n`);
    console.error(`Check RPC_URL (currently ${config.rpcUrl}) and that the node is running.\n`);
    process.exit(2);
  }

  const chainId = await chain.chainId();
  log("info", config)(`connected to chain ${chainId} at ${config.rpcUrl}`);

  const missing = configuredContracts(config).filter((c) => !c.configured);
  if (missing.length) {
    // Not fatal: /status and /limits still work, and every chain command
    // reports the address as unconfigured instead of showing an empty pool.
    log("warn", config)(
      `no address configured for: ${missing.map((m) => m.name).join(", ")} — chain commands will say so rather than report empty`
    );
  }

  const bot = new TelegramBot(config.telegramToken, { log: console });
  const me = await bot.getMe();
  log("info", config)(`telegram connected as @${me.username}`);

  try {
    await bot.setCommands(COMMANDS);
  } catch (err) {
    log("warn", config)("could not publish command list:", err.message);
  }

  // --- access control ------------------------------------------------------
  //
  // Group chats report the chat id, not the sender's id. Using the chat id for
  // groups is intentional (the allowlist then authorises a conversation rather
  // than a person), but a *private* chat must match the sender, or anyone who
  // learns the bot's username could impersonate an allowlisted id by having the
  // allowlisted user forward them a message.

  function isAuthorised(msg) {
    const chatId = msg.chat?.id;
    const fromId = msg.from?.id;
    if (chatId === undefined) return false;
    if (config.allowedChatIds.has(chatId)) return true;
    if (msg.chat?.type === "private") {
      return typeof fromId === "number" && config.allowedChatIds.has(fromId);
    }
    return false;
  }

  function send(text, { html = config.html } = {}) {
    return Promise.all(
      [...config.allowedChatIds].map((id) =>
        bot.sendQueued(id, text, html ? { parse_mode: "HTML" } : {}).catch((err) => {
          log("error", config)(`send to ${id} failed:`, err.message);
        })
      )
    );
  }

  // --- commands ------------------------------------------------------------
  //
  // Built by a factory, not inline, so the composition (which ids the pool reads,
  // which epoch's commits /task shows) is unit-testable without a chain: handlers
  // take an already-resolved chain reader, and the tests hand them a stub.

  const handlers = createHandlers(chain, config, { droppedSends: () => bot.droppedSends });

  // Анти-абьюз: квоты в единицах RPC-нагрузки (/pool стоит 15), флуд-детект, tarpit
  // для greylisted и shadowban для спамеров — правдоподобный ответ без единого RPC.
  // Хендлеры сверх этого идут с жёстким дедлайном (runHandler).
  const abuseGuard = new ChatAbuseGuard(loadAbuseConfig(process.env));

  async function handleCommand(msg) {
    const text = msg.text ?? "";
    let verdict;
    try {
      verdict = await abuseGuard.guardChat(msg.chat?.id ?? "unknown", text);
    } catch {
      verdict = { action: "pass" }; // fail-open охраны: лучше лишний RPC, чем мёртвый бот
    }
    if (verdict.action === "deny-usage" || verdict.action === "deny-rate" || verdict.action === "shadow") {
      return verdict.reply;
    }
    try {
      return await abuseGuard.runHandler(msg.chat?.id ?? "unknown", async () => {
        const [rawName, ...args] = text.split(/\s+/);
        const name = rawName.split("@")[0].replace(/^\//, "").toLowerCase();
        const handler = handlers[name];
        if (!handler) {
          return renderHelp();
        }
        try {
          return await handler(args);
        } catch (err) {
          // A failing command must not kill the process: an ops bot that crashes on
          // one bad RPC read is worse than one that says "that failed".
          return `could not complete /${name}: ${err.message}`;
        }
      });
    } catch (err) {
      // A failing command must not kill the process: an ops bot that crashes on
      // one bad RPC read is worse than one that says "that failed".
      return `could not complete: ${err.message}`;
    }
  }

  async function pollCommands() {
    let offset = 0;
    for (;;) {
      try {
        const { updates, nextOffset } = await bot.getUpdates(offset, 30);
        offset = nextOffset;

        for (const update of updates) {
          const msg = update.message;
          if (!msg?.text) continue;

          if (!isAuthorised(msg)) {
            log("warn", config)(
              `rejected message from chat ${msg.chat?.id} / user ${msg.from?.id}: not in allowlist`
            );
            // A refusal in a group is visible to everyone, which is itself a
            // small disclosure of who is allowed. Reply only in private.
            if (msg.chat?.type === "private") {
              await bot
                .sendMessage(msg.chat.id, "not authorised. Add your Telegram id to TELEGRAM_ALLOWED_IDS.", {})
                .catch(() => {});
            }
            continue;
          }

          const reply = await handleCommand(msg);
          if (reply) {
            await bot.sendMessage(msg.chat.id, reply, config.html ? { parse_mode: "HTML" } : {});
          }
        }
      } catch (err) {
        log("error", config)("command poll failed:", err.message);
        await sleep(2000);
      }
    }
  }

  // --- alert scanner -------------------------------------------------------

  async function scanOnce(cursor, seen) {
    let head = await chain.blockNumber();
    if (head < cursor) {
      // Reorg below the cursor: block numbers now repeat with different contents.
      // Rewind instead of skipping the range forever; the seen-set suppresses the
      // logs that did not actually change.
      log("warn", config)(`head ${head} is below cursor ${cursor} (reorg); rewinding`);
      cursor = head;
    }
    if (head <= cursor) return { cursor, alerts: [], seen };

    const alerts = [];
    const alertsCfg = config.alerts;

    // Commits, so a same-epoch digest disagreement can be detected. The bot
    // keeps the last-seen digest per (task, epoch, node) to spot a second,
    // differing commit by the same node.
    const seenDigest = scanOnce.seenDigest ?? new Map();
    scanOnce.seenDigest = seenDigest;

    if (config.cipherTask) {
      const commits = dedupeEvents(await chain.commitEvents(cursor + 1, head), seen);
      for (const ev of commits) {
        const key = `${ev.args.taskId}/${ev.args.epoch}/${ev.args.node}`;
        const prev = seenDigest.get(key);
        seenDigest.set(key, ev.args.traceDigest);
        if (alertsCfg.commitMismatch && prev && prev !== ev.args.traceDigest) {
          alerts.push(renderCommitMismatch(mismatchArgs(ev, prev)));
        }
      }
    }

    if (config.cipherTask && alertsCfg.disputes) {
      const events = dedupeEvents(await chain.disputeEvents(cursor + 1, head), seen);
      for (const ev of events) {
        const rendered = renderDispute(ev);
        if (rendered) alerts.push(rendered);
      }
    }

    if (config.networkParams && alertsCfg.keyRotation) {
      const { executed, proposed } = await chain.rotationEvents(cursor + 1, head);
      for (const ev of dedupeEvents(proposed, seen)) {
        alerts.push(
          renderRotation("proposed", {
            proposer: ev.args.proposer,
            expectedHash: ev.args.expectedHash,
            scheduledAt: ev.args.scheduledAt,
          })
        );
      }
      for (const ev of dedupeEvents(executed, seen)) {
        alerts.push(
          renderRotation("executed", {
            keyVersion: ev.args.keyVersion,
            fhePublicKeyHash: ev.args.fhePublicKeyHash,
          })
        );
      }
    }

    return { cursor: head, alerts, seen };
  }

  async function pollAlerts() {
    const start = await loadCursor(await chain.blockNumber(), config.catchupBlocks);
    let cursor = start.cursor;
    const seen = start.seen;
    log("info", config)(`alert scanner starting at block ${cursor} (${seen.size} events remembered)`);

    for (;;) {
      try {
        // `seen` is mutated in place by the scan (every observed identity is remembered);
        // persisting it after sending is what suppresses re-alerts across restarts.
        const { cursor: next, alerts } = await scanOnce(cursor, seen);
        cursor = next;
        // At-least-once: send first, persist after. A crash between the two re-alerts
        // (the seen-set was not saved yet); a crash before sending loses nothing, because
        // the cursor did not move either. For security alerts a duplicate is noise and a
        // loss is an incident, so this is the right bias.
        for (const a of alerts) {
          await send(a);
        }
        await saveCursor(cursor, seen);
      } catch (err) {
        log("error", config)("alert scan failed:", err.message);
      }
      await sleep(config.pollIntervalMs);
    }
  }

  // --- start ---------------------------------------------------------------

  log("info", config)("ready. /help lists commands.");
  await send(
    `🕶 <b>Shroud bot online</b>\n\nchain ${chainId} · head ${await chain.blockNumber()}\n` +
      `alerts: commit mismatch ${config.alerts.commitMismatch ? "on" : "off"}, ` +
      `disputes ${config.alerts.disputes ? "on" : "off"}, ` +
      `key rotation ${config.alerts.keyRotation ? "on" : "off"}`
  );

  await Promise.all([pollCommands(), pollAlerts()]);
}

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  main().catch((err) => {
    console.error("fatal:", err);
    process.exit(1);
  });
}