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
import { setTimeout as sleep } from "node:timers/promises";

import { loadConfig, configuredContracts, ConfigError, ROOT } from "./config.js";
import { TelegramBot } from "./telegram.js";
import { ChainReader, makeInterfaces, shortId, shortAddr } from "./chain.js";
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
 */
async function loadCursor(startBlock, catchupBlocks) {
  try {
    const raw = JSON.parse(await readFile(CURSOR_FILE, "utf8"));
    if (Number.isInteger(raw.cursor) && raw.cursor >= 0) return raw.cursor;
  } catch {
    // No cursor yet, or unreadable: fall through to a fresh window.
  }
  return Math.max(0, startBlock - catchupBlocks);
}

async function saveCursor(cursor) {
  try {
    await mkdir(dirname(CURSOR_FILE), { recursive: true });
    await writeFile(CURSOR_FILE, JSON.stringify({ cursor, at: Date.now() }, null, 2));
  } catch (err) {
    // A cursor we cannot persist only costs us alert continuity on the next
    // start; it must not take the bot down.
    console.warn("could not persist cursor:", err.message);
  }
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

  const handlers = {
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
      return renderStatus(
        { chainId: chainIdNow, blockNumber: await chain.blockNumber(), networkParams: np, pendingRotation: pending },
        config
      );
    },
    async pool() {
      const count = await chain.taskCount();
      const items = [];
      const shown = Math.min(count, 12);
      for (let i = count - 1; i >= Math.max(0, count - shown); i--) {
        const t = await chain.task(BigInt(i));
        items.push(t);
      }
      return renderPool(items);
    },
    async task(args) {
      if (!args.length) return "usage: /task &lt;id&gt;";
      if (!/^\d+$/.test(args[0])) return "task ids are decimal integers. Try /pool.";
      const id = BigInt(args[0]);
      const t = await chain.task(id);
      const commits = t ? await chain.commitsForEpoch(id, t.nextEpoch) : [];
      const winner = t ? await chain.epochWinner(id, t.nextEpoch) : null;
      const quorum = t ? await chain.disputeQuorum(id) : null;
      return renderTask({ task: t, commits, winner, quorum }, id);
    },
  };

  async function handleCommand(msg) {
    const text = msg.text ?? "";
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

  async function scanOnce(cursor) {
    const head = await chain.blockNumber();
    if (head <= cursor) return { cursor, alerts: [] };

    const alerts = [];
    const alertsCfg = config.alerts;

    // Commits, so a same-epoch digest disagreement can be detected. The bot
    // keeps the last-seen digest per (task, epoch, node) to spot a second,
    // differing commit by the same node.
    const seenDigest = scanOnce.seenDigest ?? new Map();
    scanOnce.seenDigest = seenDigest;

    if (config.cipherTask) {
      const commits = await chain.commitEvents(cursor + 1, head);
      for (const ev of commits) {
        const key = `${ev.args.taskId}/${ev.args.epoch}/${ev.args.node}`;
        const prev = seenDigest.get(key);
        seenDigest.set(key, ev.args.traceDigest);
        if (alertsCfg.commitMismatch && prev && prev !== ev.args.traceDigest) {
          alerts.push(
            renderCommitMismatch({
              taskId: ev.args.taskId,
              epoch: ev.args.epoch,
              winner: ev.args.node,
              winnerDigest: prev,
              challenger: ev.args.node,
              challengerDigest: ev.args.traceDigest,
            })
          );
        }
      }
    }

    if (config.cipherTask && alertsCfg.disputes) {
      const events = await chain.disputeEvents(cursor + 1, head);
      for (const ev of events) {
        const rendered = renderDispute(ev);
        if (rendered) alerts.push(rendered);
      }
    }

    if (config.networkParams && alertsCfg.keyRotation) {
      const { executed, proposed } = await chain.rotationEvents(cursor + 1, head);
      for (const ev of proposed) {
        alerts.push(
          renderRotation("proposed", {
            proposer: ev.args.proposer,
            expectedHash: ev.args.expectedHash,
            scheduledAt: ev.args.scheduledAt,
          })
        );
      }
      for (const ev of executed) {
        alerts.push(
          renderRotation("executed", {
            keyVersion: ev.args.keyVersion,
            fhePublicKeyHash: ev.args.fhePublicKeyHash,
          })
        );
      }
    }

    return { cursor: head, alerts };
  }

  async function pollAlerts() {
    let cursor = await loadCursor(await chain.blockNumber(), config.catchupBlocks);
    log("info", config)(`alert scanner starting at block ${cursor}`);

    for (;;) {
      try {
        const { cursor: next, alerts } = await scanOnce(cursor);
        cursor = next;
        await saveCursor(cursor);
        for (const a of alerts) {
          await send(a);
        }
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

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});