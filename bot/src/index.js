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
  renderWatchlist,
  renderAlerts,
} from "./format.js";
import {
  ALERT_KEYS,
  parseCallback,
  poolKeyboard,
  taskKeyboard,
  statusKeyboard,
  alertsKeyboard,
  openTaskKeyboard,
  openStatusKeyboard,
  watchlistKeyboard,
} from "./keyboards.js";
import { WatchStore, targetChats } from "./watchlist.js";

const CURSOR_FILE = resolve(ROOT, "state", "cursor.json");

const COMMANDS = [
  { command: "status", description: "chain, key pin and pending rotation" },
  { command: "pool", description: "recent tasks, newest first" },
  { command: "task", description: "<id> — one task with its epoch commits" },
  { command: "watch", description: "<id> — alert me about this task" },
  { command: "unwatch", description: "<id|all> — stop following" },
  { command: "watchlist", description: "what this chat follows" },
  { command: "alerts", description: "per-chat alert switches" },
  { command: "limits", description: "what this deployment does not protect against" },
  { command: "help", description: "this list" },
];

/** Tasks per pool page. Small enough that the button list stays tappable. */
export const POOL_PAGE_SIZE = 8;

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
 * Command handlers over an already-resolved chain reader and watch store.
 *
 * Every handler returns `{ text, keyboard? }`: the text is what the tests
 * assert on, the keyboard is what makes it tappable. Handlers never touch
 * Telegram directly, so the whole conversation (including callbacks) is
 * unit-testable without a chain: tests hand a stub reader and an ephemeral
 * store. `store` may be null in tests — watching then behaves as "off".
 *
 * Exported for tests: `main` wires the real reader, tests hand a stub whose calls
 * are recorded, which is what pins the pool window and the /task composition
 * (commits/winner/quorum for the running epoch) without a chain.
 */
export function createHandlers(chain, config, store = null) {
  async function isWatched(chatId, id) {
    if (chatId == null || !store) return false;
    return store.watched(chatId).includes(String(id));
  }

  return {
    async help() {
      return { text: renderHelp() };
    },
    async limits() {
      return { text: renderLimits() };
    },
    async status() {
      const chainIdNow = await chain.chainId();
      const np = await chain.networkParams();
      const pending = np ? await chain.pendingRotation() : null;
      return {
        text: renderStatus(
          { chainId: chainIdNow, blockNumber: await chain.blockNumber(), networkParams: np, pendingRotation: pending },
          config
        ),
        keyboard: statusKeyboard(),
      };
    },
    async pool(args = []) {
      let page = 0;
      if (args.length) {
        if (!/^\d+$/.test(args[0]) || Number(args[0]) < 1) {
          return { text: "usage: /pool [page] — pages start at 1." };
        }
        page = Number(args[0]) - 1;
      }
      const count = await chain.taskCount();
      const pages = Math.max(1, Math.ceil(count / POOL_PAGE_SIZE));
      page = Math.min(page, pages - 1);
      const ids = poolIds(count, (page + 1) * POOL_PAGE_SIZE).slice(page * POOL_PAGE_SIZE);
      const items = [];
      for (const id of ids) {
        items.push(await chain.task(id));
      }
      return {
        text: renderPool(items.filter(Boolean), count),
        keyboard: poolKeyboard({
          ids: items.filter(Boolean).map((t) => ({ id: String(t.taskId), label: t.statusName })),
          page,
          pages,
        }),
      };
    },
    async task(args = [], chatId = null) {
      if (!args.length) return { text: "usage: /task &lt;id&gt;" };
      if (!/^\d+$/.test(args[0])) return { text: "task ids are decimal integers. Try /pool." };
      const id = BigInt(args[0]);
      const t = await chain.task(id);
      const commits = t ? await chain.commitsForEpoch(id, t.nextEpoch) : [];
      const winner = t ? await chain.epochWinner(id, t.nextEpoch) : null;
      const quorum = t ? await chain.disputeQuorum(id) : null;
      return {
        text: renderTask({ task: t, commits, winner, quorum }, id),
        keyboard: t ? taskKeyboard({ id: String(t.taskId), watched: await isWatched(chatId, t.taskId) }) : undefined,
      };
    },
    async watch(args = [], chatId = null) {
      if (!args.length || !/^\d+$/.test(args[0])) {
        return { text: "usage: /watch &lt;id&gt; — alert this chat about one task." };
      }
      if (!store) return { text: "watching is unavailable (no state dir)." };
      const on = await store.toggleWatch(chatId, args[0]);
      const id = String(BigInt(args[0]));
      return {
        text: on
          ? `watching task ${id}. Task alerts for this chat now cover #${id} (plus key rotations, always).`
          : `stopped watching task ${id}.`,
        keyboard: taskKeyboard({ id, watched: on }),
      };
    },
    async unwatch(args = [], chatId = null) {
      if (!store) return { text: "watching is unavailable (no state dir)." };
      if (args[0] === "all") {
        for (const id of store.watched(chatId)) await store.toggleWatch(chatId, id);
        return { text: "watchlist cleared — this chat follows everything again." };
      }
      if (!args.length || !/^\d+$/.test(args[0])) {
        return { text: "usage: /unwatch &lt;id&gt; or /unwatch all." };
      }
      const id = String(BigInt(args[0]));
      if (store.watched(chatId).includes(id)) await store.toggleWatch(chatId, id);
      return { text: `stopped watching task ${id}.` };
    },
    async watchlist(args = [], chatId = null) {
      const watched = store ? store.watched(chatId) : [];
      return { text: renderWatchlist(watched), keyboard: watchlistKeyboard(watched) };
    },
    async alerts(args = [], chatId = null) {
      const overrides = store
        ? { commitMismatch: null, disputes: null, keyRotation: null, ...store.snapshot(chatId).alerts }
        : { commitMismatch: null, disputes: null, keyRotation: null };
      return { text: renderAlerts(config.alerts, overrides), keyboard: alertsKeyboard(overrides) };
    },
  };
}

/**
 * Route one callback query to a screen. Pure orchestration over handlers and
 * the watch store: returns `{ text, keyboard?, toast? }` or `{ error }`.
 * The caller (pollCommands) decides between editing the tapped message and
 * sending a fresh one.
 */
export async function handleCallback(data, { handlers, store, chatId }) {
  const cb = parseCallback(data);
  if (!cb) return { error: "unknown button — try /help." };
  try {
    switch (cb.kind) {
      case "pool": {
        const view = await handlers.pool([String(cb.page + 1)]);
        return { ...view };
      }
      case "task": {
        const view = await handlers.task([cb.id], chatId);
        return { ...view };
      }
      case "refresh": {
        if (cb.view === "s") return { ...(await handlers.status()) };
        const [kind, arg] = cb.view.split(":");
        if (kind === "p") return { ...(await handlers.pool([String(Number(arg) + 1)])) };
        return { ...(await handlers.task([arg], chatId)) };
      }
      case "watch": {
        if (!store) return { error: "watching is unavailable (no state dir)." };
        const on = await store.toggleWatch(chatId, cb.id);
        const view = await handlers.task([cb.id], chatId);
        return { ...view, toast: on ? `watching #${cb.id}` : `unwatched #${cb.id}` };
      }
      case "alerts": {
        if (!store) return { error: "watching is unavailable (no state dir)." };
        const family = ALERT_KEYS[cb.key];
        const snap = store.snapshot(chatId);
        const cur = snap.alerts[family];
        // null (env) → false → true → null: two taps return to env.
        const next = cur === null || cur === undefined ? false : cur === false ? true : null;
        await store.setAlert(chatId, family, next);
        const view = await handlers.alerts([], chatId);
        const label = next === null ? "following env" : next ? "on" : "off";
        return { ...view, toast: `${family}: ${label}` };
      }
      default:
        return { error: "unknown button — try /help." };
    }
  } catch (err) {
    return { error: `could not complete that tap: ${err.message}` };
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

  // Per-chat state (watchlists, alert overrides). Best-effort persistence:
  // an unreadable state dir only costs preferences, never uptime.
  const store = await WatchStore.open(resolve(ROOT, "state"));

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

  const handlers = createHandlers(chain, config, store);

  async function handleCommand(msg) {
    const text = msg.text ?? "";
    const [rawName, ...args] = text.split(/\s+/);
    const name = rawName.split("@")[0].replace(/^\//, "").toLowerCase();
    const handler = handlers[name];
    if (!handler) {
      return { text: renderHelp() };
    }
    try {
      return await handler(args, msg.chat?.id ?? null);
    } catch (err) {
      // A failing command must not kill the process: an ops bot that crashes on
      // one bad RPC read is worse than one that says "that failed".
      return { text: `could not complete /${name}: ${err.message}` };
    }
  }

  function sendOptions(keyboard) {
    const extra = config.html ? { parse_mode: "HTML" } : {};
    if (keyboard) extra.reply_markup = keyboard;
    return extra;
  }

  /** One alert to exactly the chats that asked for it (see targetChats). */
  async function sendAlert(view, targets) {
    await Promise.all(
      targets.map((id) =>
        bot.sendQueued(id, view.text, sendOptions(view.keyboard)).catch((err) => {
          log("error", config)(`send to ${id} failed:`, err.message);
        })
      )
    );
  }

  function authQuery(query) {
    // Callbacks carry no message text; authorise the same way as messages:
    // the chat when allowlisted, else the private sender.
    const chat = query.message?.chat;
    const probe = { chat: chat ?? { id: query.from?.id, type: "private" }, from: query.from };
    return isAuthorised(probe) ? (chat?.id ?? query.from?.id ?? null) : null;
  }

  async function pollCommands() {
    let offset = 0;
    for (;;) {
      try {
        const { updates, nextOffset } = await bot.getUpdates(offset, 30);
        offset = nextOffset;

        for (const update of updates) {
          if (update.callback_query) {
            const query = update.callback_query;
            const chatId = authQuery(query);
            if (chatId === null) {
              await bot.answerCallbackQuery(query.id, "not authorised.");
              continue;
            }
            const out = await handleCallback(query.data, {
              handlers,
              store,
              chatId,
            });
            if (out.toast || out.error) {
              await bot.answerCallbackQuery(query.id, out.toast ?? out.error);
            } else {
              await bot.answerCallbackQuery(query.id);
            }
            if (out.error) continue;
            // Prefer editing the tapped message: paging and refreshes then read
            // as one living screen instead of a growing stack of stale ones.
            const mid = query.message?.message_id;
            if (mid !== undefined) {
              try {
                await bot.editMessageText(chatId, mid, out.text, sendOptions(out.keyboard));
                continue;
              } catch {
                // Falls through to a fresh message (e.g. the tap came from an
                // alert whose layout changed shape).
              }
            }
            await bot
              .sendMessage(chatId, out.text, sendOptions(out.keyboard))
              .catch(() => {});
            continue;
          }

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
            await bot.sendMessage(msg.chat.id, reply.text, sendOptions(reply.keyboard));
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

    // The env flags are a global kill switch; a per-chat override can still
    // re-enable a family for that chat, so the scan runs when anyone — env
    // or override — could receive the alert. targetChats filters per chat.
    function familyWanted(family) {
      if (config.alerts[family]) return true;
      for (const id of config.allowedChatIds) {
        if (store.snapshot(id).alerts[family] === true) return true;
      }
      return false;
    }

    // Alerts carry their own routing: which task they are about (null for
    // chain-wide ones like key rotation) and which per-chat families gate
    // them. pollAlerts resolves chat targets from the watch store.
    const alerts = [];

    // Commits, so a same-epoch digest disagreement can be detected. The bot
    // keeps the last-seen digest per (task, epoch, node) to spot a second,
    // differing commit by the same node.
    const seenDigest = scanOnce.seenDigest ?? new Map();
    scanOnce.seenDigest = seenDigest;

    if (config.cipherTask && familyWanted("commitMismatch")) {
      const commits = await chain.commitEvents(cursor + 1, head);
      for (const ev of commits) {
        const key = `${ev.args.taskId}/${ev.args.epoch}/${ev.args.node}`;
        const prev = seenDigest.get(key);
        seenDigest.set(key, ev.args.traceDigest);
        if (config.alerts.commitMismatch && prev && prev !== ev.args.traceDigest) {
          const taskId = String(ev.args.taskId);
          alerts.push({
            text: renderCommitMismatch(mismatchArgs(ev, prev)),
            keyboard: openTaskKeyboard(taskId),
            taskId,
            families: ["commitMismatch"],
          });
        }
      }
    }

    if (config.cipherTask && familyWanted("disputes")) {
      const events = await chain.disputeEvents(cursor + 1, head);
      for (const ev of events) {
        const rendered = renderDispute(ev);
        if (rendered) {
          const taskId = ev.args?.taskId === undefined ? null : String(ev.args.taskId);
          alerts.push({
            text: rendered,
            keyboard: taskId === null ? undefined : openTaskKeyboard(taskId),
            taskId,
            families: ["disputes"],
          });
        }
      }
    }

    if (config.networkParams && familyWanted("keyRotation")) {
      const { executed, proposed } = await chain.rotationEvents(cursor + 1, head);
      for (const ev of proposed) {
        alerts.push({
          text: renderRotation("proposed", {
            proposer: ev.args.proposer,
            expectedHash: ev.args.expectedHash,
            scheduledAt: ev.args.scheduledAt,
          }),
          keyboard: openStatusKeyboard(),
          taskId: null,
          families: ["keyRotation"],
        });
      }
      for (const ev of executed) {
        alerts.push({
          text: renderRotation("executed", {
            keyVersion: ev.args.keyVersion,
            fhePublicKeyHash: ev.args.fhePublicKeyHash,
          }),
          keyboard: openStatusKeyboard(),
          taskId: null,
          families: ["keyRotation"],
        });
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
          const targets = targetChats({
            allowedIds: [...config.allowedChatIds],
            store,
            env: config.alerts,
            taskId: a.taskId,
            families: a.families,
          });
          await sendAlert(a, targets);
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
      `key rotation ${config.alerts.keyRotation ? "on" : "off"}\n` +
      `per-chat: /watch, /alerts`
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