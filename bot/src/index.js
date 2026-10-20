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

import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";

import { writeAtomic } from "./atomic-write.js";

import { loadConfig, configuredContracts, ConfigError, ROOT } from "./config.js";
import { TelegramBot } from "./telegram.js";
import { ChatAbuseGuard, loadAbuseConfig } from "./abuse.mjs";
import { ChainReader, makeInterfaces, poolPage } from "./chain.js";
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
  htmlEscape,
} from "./format.js";
import {
  parseCallback,
  poolKeyboard,
  taskKeyboard,
  statusKeyboard,
  alertsKeyboard,
  taskLinkKeyboard,
  rotationKeyboard,
  isTaskId,
  callbackCost,
} from "./keyboards.js";
import {
  createFileStore,
  loadWatchlist,
  effectiveAlerts,
  passesWatchlist,
  ALERT_KEYS,
} from "./watchlist.js";

const CURSOR_FILE = resolve(ROOT, "state", "cursor.json");

const COMMANDS = [
  { command: "status", description: "chain, key pin and pending rotation" },
  { command: "pool", description: "recent tasks" },
  { command: "task", description: "<id> — one task with its epoch commits" },
  { command: "watch", description: "<id> — alert only on this task" },
  { command: "unwatch", description: "<id> — stop watching a task" },
  { command: "watchlist", description: "tasks this chat watches" },
  { command: "alerts", description: "per-chat alert flags" },
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
 *
 * It also carries the last-seen digest per (task, epoch, node) (capped): the
 * commit-mismatch detector compares each commit against the previous one for
 * the same key, and without persistence a restart between the two commits
 * would miss the mismatch — the single most useful signal in the system.
 * Files written before digests existed load with an empty map.
 */
export async function loadCursor(startBlock, catchupBlocks, file = CURSOR_FILE) {
  try {
    const raw = JSON.parse(await readFile(file, "utf8"));
    if (Number.isInteger(raw.cursor) && raw.cursor >= 0) {
      const seen = Array.isArray(raw.seen) ? raw.seen.filter((s) => typeof s === "string") : [];
      const digests = new Map();
      if (raw.digests && typeof raw.digests === "object") {
        for (const [k, v] of Object.entries(raw.digests)) {
          if (typeof k === "string" && typeof v === "string") digests.set(k, v);
        }
      }
      return { cursor: raw.cursor, seen: new Set(seen), digests };
    }
  } catch {
    // No cursor yet, or unreadable: fall through to a fresh window.
  }
  return { cursor: Math.max(0, startBlock - catchupBlocks), seen: new Set(), digests: new Map() };
}

/** Cap on remembered event identities: enough for weeks of alerts, small on disk. */
export const MAX_SEEN_EVENTS = 2000;

/**
 * The RPC endpoint without its secret.
 *
 * Managed RPC URLs carry the provider's API key in the path (`…/v2/<key>`), so
 * printing the URL as it is writes the key into stdout and into whatever collects it.
 * The host and the path shape stay visible - the operator still sees *which*
 * endpoint - and only the last path segment is masked.
 */
export function redactRpcUrl(url) {
  try {
    const u = new URL(url);
    const segments = u.pathname.split("/").filter(Boolean);
    if (segments.length === 0) return `${u.protocol}//${u.host}`;
    const last = segments[segments.length - 1];
    const masked = last.length > 4 ? `${last.slice(0, 2)}…${last.slice(-2)}` : "…";
    segments[segments.length - 1] = masked;
    u.pathname = `/${segments.join("/")}`;
    u.search = "";
    u.username = "";
    u.password = "";
    return u.toString();
  } catch {
    // Not a URL we can parse: show only the shape, never the tail.
    return "<rpc url>";
  }
}

/** Cap on remembered commit digests: keys are short, values are 32-byte hashes. */
export const MAX_SEEN_DIGESTS = 5000;

export async function saveCursor(cursor, seen, digests = new Map(), file = CURSOR_FILE) {
  try {
    const arr = [...seen].slice(-MAX_SEEN_EVENTS);
    const entries = [...digests.entries()].slice(-MAX_SEEN_DIGESTS);
    // Temp + rename, serialised per file (see `atomic-write.js`): the cursor is rewritten
    // on every poll cycle, so a crash in the middle of a plain write leaves a truncated
    // file - and a truncated cursor reads as "no cursor", which restarts the scan from
    // the catchup window with an empty seen-set and an empty digest map. That is a
    // duplicate-alert storm over the whole window and the loss of every remembered
    // commit digest.
    await writeAtomic(
      file,
      JSON.stringify({ cursor, at: Date.now(), seen: arr, digests: Object.fromEntries(entries) }, null, 2)
    );
  } catch (err) {
    // A cursor we cannot persist only costs us alert continuity on the next
    // start; it must not take the bot down.
    console.warn("could not persist cursor:", err.message);
  }
}

/**
 * Whether a scanned alert reaches a chat.
 *
 * Pure routing behind the broadcast loop: the effective flag (per-chat
 * override wins, otherwise global) decides first, then the watchlist (empty
 * means everything; task-scoped alerts only for watched tasks; global
 * rotation alerts carry no task and skip the filter). Exported so the matrix
 * is pinned by tests instead of by reading the poll loop.
 */
export function shouldDeliverAlert(alert, globalAlerts, state, chatId) {
  const eff = effectiveAlerts(globalAlerts ?? {}, state, chatId);
  if (!eff[alert.key]) return false;
  return passesWatchlist(state, chatId, alert.taskId);
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
 * Resolve the command to dispatch: the abuse guard's single parse wins, raw text is only
 * re-parsed when the guard failed open (its verdict then carries no name).
 *
 * Two parsers on the same text drifted before: the guard trims, the handler did not, so
 * `"  /pool"` was accounted as the 15-cost `pool` but dispatched as `` (help). One parse,
 * one accounting, one dispatch.
 */
export function commandFromVerdict(verdict, text) {
  if (verdict && typeof verdict.name === "string") {
    return { name: verdict.name, args: Array.isArray(verdict.args) ? verdict.args : [] };
  }
  const [rawName, ...args] = text.split(/\s+/);
  const name = rawName.split("@")[0].replace(/^\//, "").toLowerCase();
  return { name, args };
}

/**
 * Bounded-concurrency dispatcher for poll-loop updates.
 *
 * Long polling used to handle updates strictly one at a time: one tarpit
 * sleep (up to 3s) or one slow RPC (up to the 20s handler deadline) stalled
 * every chat behind it, including keyboard presses that should feel instant.
 * The dispatcher caps in-flight handlers (default 4) while isolating
 * failures — a rejected job rejects its own `dispatch` promise and never
 * touches the others. Replies for the same chat may arrive out of order;
 * updates are independent status questions, so that is acceptable.
 */
export function createDispatcher({ maxInFlight = 4 } = {}) {
  if (!Number.isInteger(maxInFlight) || maxInFlight < 1) {
    throw new Error("dispatcher maxInFlight must be a positive integer");
  }
  const flying = new Set();
  // Admission mutex: waiters proceed one at a time, each only after the
  // previous waiter has taken its slot. Without it, N waiters woken by one
  // settling job all observe the same free slot and overshoot the cap
  // together (check-then-act race).
  let admission = Promise.resolve();
  // Settlement-only view of a job: waiters must not inherit its outcome — a
  // rejected job would otherwise fail an innocent waiter sharing the race.
  // The sentinel is a non-promise on purpose: resolving with `p` itself would
  // re-adopt its rejection.
  const settled = (p) => p.then(
    () => null,
    () => null
  );
  return {
    get inFlight() {
      return flying.size;
    },
    async dispatch(job) {
      const prev = admission;
      let release = () => {};
      admission = new Promise((r) => {
        release = r;
      });
      await prev;
      try {
        while (flying.size >= maxInFlight) await Promise.race([...flying].map(settled));
      } finally {
        release();
      }
      const p = (async () => job())();
      flying.add(p);
      try {
        return await p;
      } finally {
        flying.delete(p);
      }
    },
  };
}

/**
 * Reply to a command through the bounded send queue, never past it.
 *
 * `pollCommands` used raw `sendMessage`: a reply storm bypassed the queue cap, the
 * `droppedSends` counter and the /status shed warning — the one path exempt from the
 * accounting every other send goes through. Returns true when Telegram accepted the
 * reply, false when the queue shed it under load (the operator sees the shed count
 * in /status; silence under load is data loss only if it is invisible).
 *
 * `reply` is a string (legacy callers, tests) or `{ text, markup }` as returned
 * by the command handlers; `markup` becomes the message `reply_markup`.
 */
export async function sendReply(bot, chatId, reply, html, extra = {}) {
  const text = typeof reply === "string" ? reply : reply.text;
  const markup = typeof reply === "string" ? {} : reply.markup ? { reply_markup: reply.markup } : {};
  const out = await bot.sendQueued(chatId, text, {
    ...(html ? { parse_mode: "HTML" } : {}),
    ...markup,
    ...extra,
  });
  return out?.dropped !== true;
}

/** Unwrap a handler reply to its text (tests and callers that ignore keyboards). */
export function replyText(reply) {
  return typeof reply === "string" ? reply : reply.text;
}

/**
 * Command handlers over an already-resolved chain reader.
 *
 * Exported for tests: `main` wires the real reader, tests hand a stub whose calls
 * are recorded, which is what pins the pool window and the /task composition
 * (commits/winner/quorum for the running epoch) without a chain.
 *
 * Every handler returns `{ text, markup }` (`markup` may be undefined): the
 * caller decides between a fresh message and an in-place edit. `ops.store` is
 * the watchlist store (file-backed in production, memory in tests); handlers
 * that need it degrade to an explanatory reply when it is absent rather than
 * throwing. `ctx` carries the originating `{ chatId }` for per-chat state.
 */
export function createHandlers(chain, config, ops = {}) {
  const store = ops.store ?? null;

  async function renderPoolPage(page) {
    const count = await chain.taskCount();
    const { ids, page: p, pages, total } = poolPage(count, page);
    // One RPC per task, all in flight at once: the sequential loop made /pool the
    // slowest command (12 round trips serialized). Promise.all preserves input order,
    // so newest-first output is unchanged.
    const items = await Promise.all(ids.map((id) => chain.task(id)));
    return {
      text: renderPool(items, total, { page: p, pages }),
      markup: poolKeyboard(ids.map(String), p, pages),
    };
  }

  async function renderTaskView(id, chatId) {
    const t = await chain.task(id);
    // Independent reads once the task (and its running epoch) is known.
    const [commits, winner, quorum] = t
      ? await Promise.all([
          chain.commitsForEpoch(id, t.nextEpoch),
          chain.epochWinner(id, t.nextEpoch),
          chain.disputeQuorum(id),
        ])
      : [[], null, null];
    const watched =
      store && chatId !== undefined ? store.listWatched(chatId).includes(String(id)) : false;
    // Neighbour navigation needs the pool top: one extra eth_call, skipped when
    // the task does not exist (nothing to navigate from) or the reader has no
    // taskCount (unit stubs) — navigation degrades to pool-only either way.
    let prevId = null;
    let nextId = null;
    if (t && typeof chain.taskCount === "function") {
      const count = Number(await chain.taskCount().catch(() => 0n));
      const n = BigInt(id);
      if (n > 1n) prevId = String(n - 1n);
      if (count && n < BigInt(count)) nextId = String(n + 1n);
    }
    return {
      text: renderTask({ task: t, commits, winner, quorum }, id),
      markup: t ? taskKeyboard(String(id), { watched, prevId, nextId }) : undefined,
    };
  }

  return {
    async help() {
      return { text: renderHelp(), markup: undefined };
    },
    async limits() {
      return { text: renderLimits(), markup: undefined };
    },
    async status() {
      const [chainIdNow, blockNumber] = await Promise.all([chain.chainId(), chain.blockNumber()]);
      const np = await chain.networkParams();
      const pending = np ? await chain.pendingRotation() : null;
      const out = renderStatus(
        { chainId: chainIdNow, blockNumber, networkParams: np, pendingRotation: pending },
        config
      );
      // Shed alerts are invisible by design (the queue drops newest-first overflow) —
      // surfacing the counter here is the only way an operator learns alerts were lost.
      const dropped = typeof ops.droppedSends === "function" ? ops.droppedSends() : 0;
      // Same for a stalled queue: sends are serialised, so one hung Telegram call
      // delays everything behind it. Past 10s the delay itself is the incident.
      const queueWait = typeof ops.queueDelayMs === "function" ? ops.queueDelayMs() : 0;
      // Same for read failures: readers fail soft (null/[]), so without this line an
      // operator cannot tell "empty pool" from "RPC dead".
      const readError = typeof chain.lastReadError === "function" ? chain.lastReadError() : null;
      let text = out;
      if (readError) {
        // Error text comes from the RPC layer (proxies answer with HTML bodies);
        // it is content, never markup.
        text += `\n\n${"⚠️"} <b>chain reads failing:</b> ${htmlEscape(readError)}`;
      } else if (queueWait > 10_000) {
        text += `\n\n${"⚠️"} <b>slowest queued send waited ${Math.round(queueWait / 1000)}s</b> — ` +
          `Telegram is answering slowly and alerts are delayed behind it. ` +
          `Treat recent silence as backlog, not as calm.`;
      } else if (dropped > 0) {
        text += `\n\n${"⚠️"} <b>${dropped} alert(s) shed by the send queue</b> — ` +
          `the bot dropped outbound messages faster than Telegram drained them. ` +
          `Treat recent silence as data loss, not as calm.`;
      }
      return { text, markup: statusKeyboard() };
    },
    async pool(args = []) {
      // `/pool 3` — page 3 of the newest-first window. Non-numeric input falls
      // back to page 1 (the abuse guard already rejected hostile charsets; a
      // plain word here is a typo, not an attack, and deserves the first page).
      const page = args.length && /^\d{1,4}$/.test(args[0]) ? Number(args[0]) : 1;
      return renderPoolPage(page);
    },
    async task(args, ctx = {}) {
      if (!args.length) return { text: "usage: /task &lt;id&gt;", markup: undefined };
      // Санитизация до RPC: id — короткий decimal. Длинная строка здесь — либо мусор,
      // либо попытка заставить ноду жевать BigInt из килобайта цифр.
      if (!isTaskId(args[0])) return { text: "task ids are decimal integers. Try /pool.", markup: undefined };
      return renderTaskView(BigInt(args[0]), ctx.chatId);
    },
    async watch(args, ctx = {}) {
      if (ctx.chatId === undefined || !store) {
        return { text: "watchlist unavailable in this context.", markup: undefined };
      }
      if (!args.length || !isTaskId(args[0])) {
        return { text: "usage: /watch &lt;id&gt;", markup: undefined };
      }
      const res = await store.addWatch(ctx.chatId, args[0]);
      const list = store.listWatched(ctx.chatId);
      return {
        text: `${htmlEscape(res.reason)}\n\n${renderWatchlist(list)}`,
        markup: taskLinkKeyboard(args[0]),
      };
    },
    async unwatch(args, ctx = {}) {
      if (ctx.chatId === undefined || !store) {
        return { text: "watchlist unavailable in this context.", markup: undefined };
      }
      if (!args.length || !isTaskId(args[0])) {
        return { text: "usage: /unwatch &lt;id&gt;", markup: undefined };
      }
      const res = await store.removeWatch(ctx.chatId, args[0]);
      const list = store.listWatched(ctx.chatId);
      return { text: `${htmlEscape(res.reason)}\n\n${renderWatchlist(list)}`, markup: undefined };
    },
    async watchlist(args, ctx = {}) {
      if (ctx.chatId === undefined || !store) {
        return { text: "watchlist unavailable in this context.", markup: undefined };
      }
      return { text: renderWatchlist(store.listWatched(ctx.chatId)), markup: undefined };
    },
    async alerts(args, ctx = {}) {
      if (ctx.chatId === undefined || !store) {
        return { text: "per-chat alerts unavailable in this context.", markup: undefined };
      }
      const eff = effectiveAlerts(config.alerts ?? {}, store.state(), ctx.chatId);
      const inherited = {};
      const override = store.state().chats[String(ctx.chatId)]?.alerts ?? {};
      for (const key of ALERT_KEYS) inherited[key] = override[key] !== true && override[key] !== false;
      return { text: renderAlerts(eff, inherited), markup: alertsKeyboard(eff) };
    },
    // Test seam: shared renderers for the callback router below.
    renderPoolPage,
    renderTaskView,
  };
}

/**
 * Route an inline-keyboard press to a fresh `{ text, markup }` reply.
 *
 * Exported for tests: `main` wires the live poll loop around it, tests hand a
 * stub chain and a memory store. Unknown or stale payloads (older bot version)
 * resolve to a hint, never to an RPC call. Toggle actions (`w`/`u`/`a`)
 * answer with a toast via `onToast` and re-render the underlying view so the
 * button flips in place.
 */
export async function routeCallback(parsed, { chain, config, store, chatId, onToast }) {
  const toast = onToast ?? (async () => {});
  const say = async (t) => toast(t);
  switch (parsed.op) {
    case "p": {
      const handlers = createHandlers(chain, config, { store });
      return handlers.renderPoolPage(Number(parsed.arg));
    }
    case "t": {
      const handlers = createHandlers(chain, config, { store });
      return handlers.renderTaskView(BigInt(parsed.arg), chatId);
    }
    case "w": {
      if (!store || chatId === undefined) return { text: "watchlist unavailable.", markup: undefined };
      const res = await store.addWatch(chatId, parsed.arg);
      await say(res.added ? `watching #${parsed.arg}` : res.reason);
      const handlers = createHandlers(chain, config, { store });
      return handlers.renderTaskView(BigInt(parsed.arg), chatId);
    }
    case "u": {
      if (!store || chatId === undefined) return { text: "watchlist unavailable.", markup: undefined };
      const res = await store.removeWatch(chatId, parsed.arg);
      await say(res.removed ? `unwatched #${parsed.arg}` : res.reason);
      const handlers = createHandlers(chain, config, { store });
      return handlers.renderTaskView(BigInt(parsed.arg), chatId);
    }
    case "s": {
      const handlers = createHandlers(chain, config, { store });
      return handlers.status();
    }
    case "a": {
      if (!store || chatId === undefined) return { text: "per-chat alerts unavailable.", markup: undefined };
      const eff = effectiveAlerts(config.alerts ?? {}, store.state(), chatId);
      const next = !eff[parsed.arg];
      await store.setAlert(chatId, parsed.arg, next);
      const after = effectiveAlerts(config.alerts ?? {}, store.state(), chatId);
      const override = store.state().chats[String(chatId)]?.alerts ?? {};
      const inherited = {};
      for (const key of ALERT_KEYS) inherited[key] = override[key] !== true && override[key] !== false;
      const names = { mm: "mismatch", disp: "disputes", rot: "rotation" };
      await say(`${names[parsed.arg]} ${next ? "on" : "off"} for this chat`);
      return { text: renderAlerts(after, inherited), markup: alertsKeyboard(after) };
    }
    default:
      return { text: "that button is from an older bot — send the command again.", markup: undefined };
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
    // The RPC URL often carries the provider's API key in its path, so it is not printed
    // as it is: the operator needs to know *which* endpoint, not its secret.
    console.error(`Check RPC_URL (currently ${redactRpcUrl(config.rpcUrl)}) and that the node is running.\n`);
    process.exit(2);
  }

  const chainId = await chain.chainId();
  log("info", config)(`connected to chain ${chainId} at ${redactRpcUrl(config.rpcUrl)}`);

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

  // Per-chat state: watchlist + alert overrides, loaded once at startup.
  // Mutations persist best-effort inside the store; a store that cannot read
  // starts empty rather than stopping the bot.
  const watchStore = createFileStore();
  try {
    watchStore.replaceState(await loadWatchlist());
  } catch {
    // loadWatchlist never throws; this is belt and suspenders.
  }
  const handlers = createHandlers(
    chain,
    config,
    {
      droppedSends: () => bot.droppedSends,
      queueDelayMs: () => bot.maxQueueWaitMs(),
      store: watchStore,
    }
  );

  // Анти-абьюз: квоты в единицах RPC-нагрузки (/pool стоит 15), флуд-детект, tarpit
  // для greylisted и shadowban для спамеров — правдоподобный ответ без единого RPC.
  // Хендлеры сверх этого идут с жёстким дедлайном (runHandler).
  const abuseGuard = new ChatAbuseGuard(loadAbuseConfig(process.env));

  async function handleCommand(msg, chatId) {
    const text = msg.text ?? "";
    let verdict;
    try {
      verdict = await abuseGuard.guardChat(chatId ?? msg.chat?.id ?? "unknown", text);
    } catch {
      verdict = { action: "pass" }; // fail-open охраны: лучше лишний RPC, чем мёртвый бот
    }
    if (verdict.action === "deny-usage" || verdict.action === "deny-rate" || verdict.action === "shadow") {
      return { text: verdict.reply, markup: undefined };
    }
    try {
      return await abuseGuard.runHandler(chatId ?? msg.chat?.id ?? "unknown", async () => {
        const { name, args } = commandFromVerdict(verdict, text);
        const handler = handlers[name];
        if (!handler || typeof handler !== "function") {
          return handlers.help();
        }
        try {
          return await handler(args, { chatId });
        } catch (err) {
          // A failing command must not kill the process: an ops bot that crashes on
          // one bad RPC read is worse than one that says "that failed".
          // err.message is escaped: replies go out with parse_mode HTML and a raw
          // "<" from an RPC/proxy error would make Telegram reject the send (400).
          return { text: `could not complete /${name}: ${htmlEscape(err.message)}`, markup: undefined };
        }
      });
    } catch (err) {
      // A failing command must not kill the process: an ops bot that crashes on
      // one bad RPC read is worse than one that says "that failed".
      return { text: `could not complete: ${htmlEscape(err.message)}`, markup: undefined };
    }
  }

  /**
   * Handle an inline-keyboard press.
   *
   * Authorisation mirrors messages (chat id, or sender in private chats); an
   * unauthorised press gets a toast and nothing else — no edit, no state
   * change, no disclosure of what the button would have shown. The press is
   * priced through the same abuse guard as its command equivalent (synthetic
   * text), so refresh-spam costs RPC budget like retyping the command.
   */
  const CALLBACK_TEXT = { p: "/pool", t: "/task x", w: "/watch x", u: "/watch x", s: "/status", a: "/alerts" };

  async function handleCallback(query) {
    const data = query.data ?? "";
    const chatId = query.message?.chat?.id;
    const fromId = query.from?.id;
    const authorised = (() => {
      if (chatId === undefined) return false;
      if (config.allowedChatIds.has(chatId)) return true;
      if (query.message?.chat?.type === "private") {
        return typeof fromId === "number" && config.allowedChatIds.has(fromId);
      }
      return false;
    })();
    if (!authorised) {
      await bot.answerCallbackQuery(query.id, "not authorised");
      log("warn", config)(`rejected callback from chat ${chatId} / user ${fromId}: not in allowlist`);
      return;
    }
    const parsed = parseCallback(data);
    if (!parsed) {
      await bot.answerCallbackQuery(query.id, "that button is stale — send the command again");
      return;
    }
    let verdict;
    try {
      // The press is priced by what it does, not by the command it resembles: the watch
      // buttons render the full task view, which is `/task`-sized work.
      verdict = await abuseGuard.guardChat(
        chatId,
        CALLBACK_TEXT[parsed.op] ?? "/help",
        callbackCost(parsed)
      );
    } catch {
      verdict = { action: "pass" };
    }
    if (verdict.action === "deny-rate" || verdict.action === "shadow" || verdict.action === "deny-usage") {
      await bot.answerCallbackQuery(query.id, verdict.reply ?? "slow down");
      return;
    }
    let reply;
    try {
      reply = await abuseGuard.runHandler(chatId, async () =>
        routeCallback(parsed, {
          chain,
          config,
          store: watchStore,
          chatId,
          onToast: (t) => bot.answerCallbackQuery(query.id, t),
        })
      );
    } catch (err) {
      await bot.answerCallbackQuery(query.id, "that failed — try again");
      log("error", config)("callback failed:", err.message);
      return;
    }
    // In-place edit keeps the chat tidy; when Telegram rejects the edit
    // (identical content, message too old) fall back to a fresh reply and
    // always ack the query so the spinner stops.
    const messageId = query.message?.message_id;
    const extra = {
      ...(config.html ? { parse_mode: "HTML" } : {}),
      ...(reply.markup ? { reply_markup: reply.markup } : {}),
    };
    let edited = null;
    if (messageId !== undefined) {
      // `runHandler` answers with a plain string when the handler failed, so the reply is
      // unwrapped rather than read as an object: `reply.text` on a string is undefined, and
      // editing the user's message to the literal text "undefined" is worse than useless.
      edited = await bot.editMessage(chatId, messageId, replyText(reply), extra);
    }
    if (!edited) {
      await sendReply(bot, chatId, reply, config.html);
    }
    await bot.answerCallbackQuery(query.id);
  }

  // At most a few updates in flight: commands are independent status
  // questions, so strict ordering buys nothing and costs head-of-line stalls.
  const dispatcher = createDispatcher({ maxInFlight: 4 });

  async function handleUpdate(update) {
    // Inline-keyboard presses share the poll loop with messages.
    if (update.callback_query) {
      await handleCallback(update.callback_query);
      return;
    }
    const msg = update.message;
    if (!msg?.text) return;

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
      return;
    }

    const reply = await handleCommand(msg, msg.chat.id);
    if (reply) {
      await sendReply(bot, msg.chat.id, reply, config.html);
    }
  }

  async function pollCommands() {
    let offset = 0;
    for (;;) {
      try {
        const { updates, nextOffset } = await bot.getUpdates(offset, 30);
        offset = nextOffset;

        for (const update of updates) {
          // Fire-and-forget under the cap: the offset already advanced, so a
          // slow handler delays only its own reply, never the next update.
          // Rejections are isolated per update (see createDispatcher).
          dispatcher.dispatch(() => handleUpdate(update)).catch((err) => {
            log("error", config)("update failed:", err.message);
          });
        }
      } catch (err) {
        log("error", config)("command poll failed:", err.message);
        await sleep(2000);
      }
    }
  }

  // --- alert scanner -------------------------------------------------------
  //
  // Alerts are `{ text, taskId, key, markup }`: `taskId` scopes watchlist
  // filtering (`null` for global rotation alerts), `key` selects the per-chat
  // flag (`mm` | `disp` | `rot`), and `markup` carries the deep-link button.

  async function scanOnce(cursor, seen, digests = new Map()) {
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

    // Commits, so a same-epoch digest disagreement can be detected. `digests`
    // holds the last-seen digest per (task, epoch, node) and is persisted with
    // the cursor: a static in-memory map here once missed every mismatch whose
    // two commits straddled a restart.

    // Note: no global-flag gate here. Delivery is decided per chat in
    // pollAlerts (override wins, otherwise global): collecting always keeps
    // the digest/dedupe tracking correct even while a flag is off, so
    // toggling it on later does not replay history.
    if (config.cipherTask) {
      const commits = dedupeEvents(await chain.commitEvents(cursor + 1, head), seen);
      for (const ev of commits) {
        const key = `${ev.args.taskId}/${ev.args.epoch}/${ev.args.node}`;
        const prev = digests.get(key);
        // Delete-before-set: re-setting an existing Map key does NOT refresh its
        // insertion order, so without this the saveCursor slice evicts by first-seen
        // instead of last-updated and a hot key can push out live entries.
        digests.delete(key);
        digests.set(key, ev.args.traceDigest);
        if (prev && prev !== ev.args.traceDigest) {
          const args = mismatchArgs(ev, prev);
          alerts.push({
            text: renderCommitMismatch(args),
            taskId: String(args.taskId),
            key: "mm",
            markup: taskLinkKeyboard(String(args.taskId)),
          });
        }
      }
    }

    if (config.cipherTask) {
      const events = dedupeEvents(await chain.disputeEvents(cursor + 1, head), seen);
      for (const ev of events) {
        const rendered = renderDispute(ev);
        if (rendered) {
          const taskId = ev.args?.taskId !== undefined ? String(ev.args.taskId) : null;
          alerts.push({
            text: rendered,
            taskId,
            key: "disp",
            markup: taskId !== null ? taskLinkKeyboard(taskId) : undefined,
          });
        }
      }
    }

    if (config.networkParams) {
      const { executed, proposed } = await chain.rotationEvents(cursor + 1, head);
      for (const ev of dedupeEvents(proposed, seen)) {
        alerts.push({
          text: renderRotation("proposed", {
            proposer: ev.args.proposer,
            expectedHash: ev.args.expectedHash,
            scheduledAt: ev.args.scheduledAt,
          }),
          taskId: null,
          key: "rot",
          markup: rotationKeyboard(),
        });
      }
      for (const ev of dedupeEvents(executed, seen)) {
        alerts.push({
          text: renderRotation("executed", {
            keyVersion: ev.args.keyVersion,
            fhePublicKeyHash: ev.args.fhePublicKeyHash,
          }),
          taskId: null,
          key: "rot",
          markup: rotationKeyboard(),
        });
      }
    }

    return { cursor: head, alerts, seen };
  }

  /**
   * Deliver one scanned alert to every chat that wants it (see
   * `shouldDeliverAlert` for the routing matrix, pinned by tests).
   */
  function deliverAlert(alert) {
    const jobs = [];
    for (const chatId of config.allowedChatIds) {
      if (!shouldDeliverAlert(alert, config.alerts, watchStore.state(), chatId)) continue;
      jobs.push(
        bot
          .sendQueued(chatId, alert.text, {
            ...(config.html ? { parse_mode: "HTML" } : {}),
            ...(alert.markup ? { reply_markup: alert.markup } : {}),
          })
          .catch((err) => {
            log("error", config)(`send to ${chatId} failed:`, err.message);
          })
      );
    }
    return Promise.all(jobs);
  }

  async function pollAlerts() {
    const start = await loadCursor(await chain.blockNumber(), config.catchupBlocks);
    let cursor = start.cursor;
    const seen = start.seen;
    const digests = start.digests;
    log("info", config)(`alert scanner starting at block ${cursor} (${seen.size} events, ${digests.size} digests remembered)`);

    for (;;) {
      try {
        // `seen` and `digests` are mutated in place by the scan (every observed
        // identity and digest is remembered); persisting them after sending is
        // what suppresses re-alerts across restarts.
        const { cursor: next, alerts } = await scanOnce(cursor, seen, digests);
        cursor = next;
        // At-least-once: send first, persist after. A crash between the two re-alerts
        // (the seen-set was not saved yet); a crash before sending loses nothing, because
        // the cursor did not move either. For security alerts a duplicate is noise and a
        // loss is an incident, so this is the right bias.
        for (const a of alerts) {
          await deliverAlert(a);
        }
        await saveCursor(cursor, seen, digests);
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