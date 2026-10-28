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

import { loadConfig, configuredContracts, isOwnerId, ConfigError, ROOT } from "./config.js";
import { TelegramBot } from "./telegram.js";
import { ChatAbuseGuard, loadAbuseConfig } from "./abuse.mjs";
import { ChainReader, makeInterfaces, poolPage } from "./chain.js";
import { redactRpcUrl, scrubRpcSecret } from "./redact.js";
import { t, pickLang, isLang } from "./i18n.js";
import { renderRole, isRole, ROLE_ALIASES } from "./roles.js";
import {
  renderStatus,
  renderPool,
  renderTask,
  renderCommitMismatch,
  renderDispute,
  renderRotation,
  renderTreasury,
  renderLimits,
  renderHelp,
  renderWatchlist,
  renderAlerts,
  renderStart,
  renderMenu,
  renderHow,
  renderProtocol,
  renderSettings,
  renderAlert,
  renderAdmin,
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
  startKeyboard,
  menuKeyboard,
  howKeyboard,
  protoKeyboard,
  settingsKeyboard,
  hubLinkKeyboard,
  navRow,
  roleKeyboard,
  isTaskId,
  callbackCost,
} from "./keyboards.js";
import {
  createFileStore,
  loadWatchlist,
  effectiveAlerts,
  passesWatchlist,
  getPrefs,
  setPref,
  ALERT_KEYS,
} from "./watchlist.js";

const CURSOR_FILE = resolve(ROOT, "state", "cursor.json");
const TG_OFFSET_FILE = resolve(ROOT, "state", "tg-offset.json");

const COMMANDS = [
  { command: "menu", description: "hub: status, tasks, guides, trust" },
  { command: "start", description: "hub + onboarding: simple or geek" },
  { command: "status", description: "chain, key pin and pending rotation" },
  { command: "pool", description: "recent tasks" },
  { command: "task", description: "<id> — one task with its epoch commits" },
  { command: "how", description: "how Shroud works in 60 seconds" },
  { command: "protocol", description: "geek spec: binding, disputes, money, keys" },
  { command: "role", description: "<buyer|contributor|node|watcher> — guided path" },
  { command: "settings", description: "language, depth and alert flags" },
  { command: "pro", description: "geek mode: every digest and quorum" },
  { command: "simple", description: "plain-words mode" },
  { command: "lang", description: "ru|en — switch language" },
  { command: "watch", description: "<id> — alert only on this task" },
  { command: "unwatch", description: "<id> — stop watching a task" },
  { command: "watchlist", description: "tasks this chat watches" },
  { command: "alerts", description: "per-chat alert flags" },
  { command: "limits", description: "what this deployment does not protect against" },
  { command: "admin", description: "owner-only deployment diagnostics" },
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
 * The RPC endpoint without its secret, and the scrubber for any text that quotes
 * it.
 *
 * Re-exported from `redact.js` so the public surface of this module does not
 * change: the operator-facing helpers live in one place, and the bot's entry
 * point still hands them out.
 */
export { redactRpcUrl, scrubRpcSecret };

/** Cap on remembered commit digests: keys are short, values are 32-byte hashes. */
export const MAX_SEEN_DIGESTS = 5000;

/** Telegram `getUpdates` offset, persisted so a restart resumes instead of replaying. */
export async function loadTgOffset(file = TG_OFFSET_FILE) {
  try {
    const raw = JSON.parse(await readFile(file, "utf8"));
    if (Number.isInteger(raw.offset) && raw.offset >= 0) return raw.offset;
  } catch {
    // No offset yet, or unreadable: fall through to a fresh poll.
  }
  return 0;
}

export async function saveTgOffset(offset, file = TG_OFFSET_FILE) {
  try {
    await writeAtomic(file, JSON.stringify({ offset, at: Date.now() }));
  } catch (err) {
    console.warn("could not persist tg offset:", err.message);
  }
}

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
 * Display language for a chat: stored pref wins, otherwise the Telegram
 * client locale (RU stays RU, everything else is EN). Extracted so the
 * failure paths (which must also be localized) share the one rule — and so
 * a test can pin it without reaching into `main`.
 */
export function resolveChatLang(store, chatId, langCode) {
  const stored = store ? getPrefs(store.state(), chatId) : {};
  if (isLang(stored.lang)) return stored.lang;
  return pickLang(langCode);
}

/**
 * User-input normalization: RU aliases, plurals and bare ids.
 *
 * Lets a RU chat type `/статус`, `/пул`, `/таск 12` or just `12` and land on
 * the same handler as the English command. Runs *before* the abuse guard so
 * accounting (pool=15, task=5) matches dispatch. Unknown names pass through
 * untouched and fall back to /help downstream — never to an RPC.
 */
const ALIAS_GROUPS = {
  menu: ["menu", "меню"],
  start: ["start", "старт"],
  status: ["status", "статус"],
  pool: ["pool", "пул", "tasks", "таски"],
  task: ["task", "таск", "задача"],
  how: ["how", "как"],
  protocol: ["protocol", "proto", "протокол", "спека"],
  role: ["role", "роль", "гайд", "гайды", "guide", "guides"],
  settings: ["settings", "setting", "настройки", "параметры"],
  pro: ["pro", "гик", "профи", "geek"],
  simple: ["simple", "просто"],
  lang: ["lang", "язык"],
  watch: ["watch", "следить", "вотч", "подписаться"],
  unwatch: ["unwatch", "отписаться"],
  watchlist: ["watchlist", "вотчлист", "подписки"],
  alerts: ["alerts", "алерты", "уведомления"],
  limits: ["limits", "лимиты", "честность"],
  admin: ["admin", "админ", "админка"],
  help: ["help", "помощь", "хелп"],
};

const REVERSE_ALIAS = Object.fromEntries(
  Object.entries(ALIAS_GROUPS).flatMap(([canon, variants]) => variants.map((v) => [v, canon]))
);

/** Russian role names → English handler args. Applied in normalizeInput so the
 *  abuse guard only ever sees Latin args (its charset gate stays untouched). */
const ROLE_ARG_ALIAS = {
  "покупатель": "buyer",
  "контрибьютор": "contrib",
  "узел": "node",
  "нода": "node",
  "наблюдатель": "watch",
};

export function normalizeInput(text) {
  if (typeof text !== "string") return "";
  const trimmed = text.trim();
  if (!trimmed) return "";
  if (/^\/?\d{1,20}$/.test(trimmed)) {
    return `/task ${trimmed.replace(/^\//, "")}`;
  }
  const parts = trimmed.split(/\s+/);
  const raw = parts[0].split("@")[0].replace(/^\//, "").toLowerCase();
  const canon = REVERSE_ALIAS[raw] ?? raw;
  let rest = parts.slice(1).join(" ");
  if (canon === "role" && rest) {
    const [first, ...tail] = rest.split(/\s+/);
    const mapped = ROLE_ARG_ALIAS[first.toLowerCase()] ?? first;
    rest = tail.length ? `${mapped} ${tail.join(" ")}` : mapped;
  }
  return rest ? `/${canon} ${rest}` : `/${canon}`;
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
 * Escrow-token scale for money displays, fail-soft to 18.
 *
 * Old readers and unit stubs have no `escrowDecimals()`; a throwing reader
 * (dead RPC mid-command) must not take the reply down with it. A wrong scale
 * is a display bug, a thrown command is an outage — so this never throws.
 */
export async function escrowScale(chain) {
  try {
    if (chain && typeof chain.escrowDecimals === "function") {
      const d = await chain.escrowDecimals();
      if (Number.isInteger(d) && d >= 0 && d <= 77) return d;
    }
  } catch {
    // Fail-soft below.
  }
  return 18;
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

  /**
   * Resolve display language and depth for a chat. Stored prefs win; without
   * them the language is auto-detected from the Telegram client (RU stays RU,
   * everything else is EN) and depth defaults to pro — the historical
   * behaviour, so existing chats see exactly what they always saw until they
   * tap /start, /pro, /simple or /lang.
   */
  const prefsOf = (ctx = {}) => {
    const stored = store ? getPrefs(store.state(), ctx.chatId) : {};
    const lang = stored.lang || (ctx.langCode ? pickLang(ctx.langCode) : "en");
    const mode = stored.mode || "pro";
    return { lang: isLang(lang) ? lang : "en", mode: mode === "simple" ? "simple" : "pro" };
  };

  async function renderPoolPage(page, ctx = {}) {
    const { lang, mode } = prefsOf(ctx);
    const count = await chain.taskCount();
    const { ids, page: p, pages, total } = poolPage(count, page);
    // One RPC per task, all in flight at once: the sequential loop made /pool the
    // slowest command (12 round trips serialized). Promise.all preserves input order,
    // so newest-first output is unchanged.
    const [items, decimals] = await Promise.all([
      Promise.all(ids.map((id) => chain.task(id))),
      escrowScale(chain),
    ]);
    return {
      text: renderPool(items, total, { page: p, pages }, lang, mode, decimals),
      // Empty pool has no task buttons, so the keyboard would be undefined:
      // fall back to a hub row so the screen is never a dead end.
      markup: poolKeyboard(ids.map(String), p, pages, lang, mode) ?? navRow(lang),
    };
  }

  async function renderTaskView(id, chatId, ctx = {}) {
    const { lang, mode } = prefsOf({ ...ctx, chatId });
    const t = await chain.task(id);
    // Independent reads once the task (and its running epoch) is known.
    const [commits, winner, quorum, decimals] = t
      ? await Promise.all([
          chain.commitsForEpoch(id, t.nextEpoch),
          chain.epochWinner(id, t.nextEpoch),
          chain.disputeQuorum(id),
          escrowScale(chain),
        ])
      : [[], null, null, 18];
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
      text: renderTask({ task: t, commits, winner, quorum }, id, lang, mode, decimals),
      markup: t ? taskKeyboard(String(id), { watched, prevId, nextId, lang, mode }) : navRow(lang),
    };
  }

  return {
    async start(args, ctx = {}) {
      const chatId = ctx.chatId;
      let lang = pickLang(ctx.langCode);
      let mode = "simple";
      if (store && chatId !== undefined) {
        // Onboarding writes once: a chat that already chose keeps its choice,
        // a fresh chat gets the detected language and the plain-words mode.
        const cur = getPrefs(store.state(), chatId);
        lang = cur.lang || lang;
        mode = cur.mode || "simple";
        if (!cur.lang && ctx.langCode) await store.setPref(chatId, "lang", lang);
        if (!cur.mode) await store.setPref(chatId, "mode", "simple");
      }
      if (!isLang(lang)) lang = "en";
      return { text: renderStart(lang, mode), markup: startKeyboard(lang, mode) };
    },
    async menu(args, ctx = {}) {
      const { lang, mode } = prefsOf(ctx);
      // The hub is the front door: a chat that never chose a depth gets the
      // welcoming mode rather than the historical pro default. An explicit
      // stored choice always wins; nothing is written here (unlike /start).
      const stored = store ? getPrefs(store.state(), ctx.chatId) : {};
      const m = stored.mode === "pro" || stored.mode === "simple" ? mode : "simple";
      return { text: renderMenu(lang, m), markup: menuKeyboard(lang, m) };
    },
    async how(args, ctx = {}) {
      const { lang, mode } = prefsOf(ctx);
      return { text: renderHow(lang, mode), markup: howKeyboard(lang, mode) };
    },
    async protocol(args, ctx = {}) {
      const { lang, mode } = prefsOf(ctx);
      return { text: renderProtocol(lang), markup: protoKeyboard(lang, mode) };
    },
    async settings(args, ctx = {}) {
      const { lang, mode } = prefsOf(ctx);
      if (ctx.chatId === undefined || !store) {
        return { text: t(lang, "common.noAlerts"), markup: undefined };
      }
      const eff = effectiveAlerts(config.alerts ?? {}, store.state(), ctx.chatId);
      const inherited = {};
      const override = store.state().chats[String(ctx.chatId)]?.alerts ?? {};
      for (const key of ALERT_KEYS) inherited[key] = override[key] !== true && override[key] !== false;
      return { text: renderSettings(eff, inherited, lang, mode), markup: settingsKeyboard(eff, lang, mode) };
    },
    async role(args, ctx = {}) {
      const { lang, mode } = prefsOf(ctx);
      const key = String(args[0] || "").toLowerCase();
      const r = ROLE_ALIASES[key];
      if (!r) {
        return { text: t(lang, "role.pick"), markup: roleKeyboard(lang, mode, "buyer") };
      }
      return { text: renderRole(r, lang, mode), markup: roleKeyboard(lang, mode, r) };
    },
    async pro(args, ctx = {}) {
      const { lang } = prefsOf(ctx);
      if (!store || ctx.chatId === undefined) return { text: t(lang, "common.unavailable"), markup: undefined };
      await store.setPref(ctx.chatId, "mode", "pro");
      return { text: t(lang, "status.modeLine", { mode: t(lang, "common.modePro"), lang }), markup: navRow(lang) };
    },
    async simple(args, ctx = {}) {
      const { lang } = prefsOf(ctx);
      if (!store || ctx.chatId === undefined) return { text: t(lang, "common.unavailable"), markup: undefined };
      await store.setPref(ctx.chatId, "mode", "simple");
      return { text: t(lang, "status.modeLine", { mode: t(lang, "common.modeSimple"), lang }), markup: navRow(lang) };
    },
    async lang(args, ctx = {}) {
      const { lang: cur, mode } = prefsOf(ctx);
      const want = String(args[0] || "").toLowerCase();
      if (want !== "ru" && want !== "en") {
        return { text: t(cur, "status.modeLine", { mode: t(cur, mode === "simple" ? "common.modeSimple" : "common.modePro"), lang: cur }), markup: navRow(cur) };
      }
      if (store && ctx.chatId !== undefined) await store.setPref(ctx.chatId, "lang", want);
      const upd = prefsOf({ ...ctx });
      return { text: t(want, "status.modeLine", { mode: t(want, upd.mode === "simple" ? "common.modeSimple" : "common.modePro"), lang: want }), markup: navRow(want) };
    },
    async help(args, ctx = {}) {
      const { lang, mode } = prefsOf(ctx);
      // The owner panel is advertised only to its audience of one: listing
      // /admin to every chat would teach scanners exactly which command to
      // hammer (it denies them, but why hand out the address).
      const extra = isOwnerId(config, ctx.chatId)
        ? `\n<code>/admin</code>  ${t(lang, "help.admin")}`
        : "";
      return { text: renderHelp(lang) + extra, markup: hubLinkKeyboard(lang, mode, "help") };
    },
    async limits(args, ctx = {}) {
      const { lang, mode } = prefsOf(ctx);
      return { text: renderLimits(lang), markup: hubLinkKeyboard(lang, mode, "lim") };
    },
    async admin(args, ctx = {}) {
      const { lang, mode } = prefsOf(ctx);
      // Owner gate first, before any read: a non-owner learns nothing — not
      // even whether the chain is up — and costs the deployment zero RPC.
      if (!isOwnerId(config, ctx.chatId)) {
        return { text: t(lang, "admin.denied"), markup: navRow(lang) };
      }
      // Fail-soft reads: the panel reports "unreadable", never throws. A
      // throwing admin screen during an RPC outage would hide exactly the
      // outage the owner opened it to see.
      const [chainId, taskCount] = await Promise.all([
        typeof chain.chainId === "function" ? chain.chainId().catch(() => null) : Promise.resolve(null),
        typeof chain.taskCount === "function"
          ? chain.taskCount().then((n) => n.toString()).catch(() => null)
          : Promise.resolve(null),
      ]);
      const chats = store ? Object.keys(store.state().chats ?? {}) : null;
      const watchers =
        store && chats
          ? Object.values(store.state().chats).reduce(
              (n, e) => n + (Array.isArray(e?.watched) ? e.watched.length : 0),
              0
            )
          : null;
      return {
        text: renderAdmin(
          {
            chainId,
            taskCount,
            rpc: config.rpcUrl,
            contracts: configuredContracts(config),
            dropped: typeof ops.droppedSends === "function" ? ops.droppedSends() : null,
            maxWaitMs: typeof ops.queueDelayMs === "function" ? ops.queueDelayMs() : null,
            chats: chats === null ? null : chats.length,
            watchers,
            ownerId: config.ownerId,
          },
          lang
        ),
        markup: hubLinkKeyboard(lang, mode, "help"),
      };
    },
    async status(args, ctx = {}) {
      const { lang, mode } = prefsOf(ctx);
      const [chainIdNow, blockNumber] = await Promise.all([chain.chainId(), chain.blockNumber()]);
      const np = await chain.networkParams();
      const pending = np ? await chain.pendingRotation() : null;
      // The verifier slot is optional (devnet points it at a mock): old stubs
      // and unconfigured deployments simply report nothing here.
      const pendingVerifier =
        config.verifier && typeof chain.pendingVerifierRotation === "function"
          ? await chain.pendingVerifierRotation()
          : null;
      const out = renderStatus(
        { chainId: chainIdNow, blockNumber, networkParams: np, pendingRotation: pending, pendingVerifier },
        config,
        lang,
        mode
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
        // it is content, never markup. Cap it first: a multi-KB body wrapped
        // in <b> would push /status past 4096 and Telegram would 400 the one
        // screen that explains the outage.
        const short = readError.length > 300 ? `${readError.slice(0, 300)}…` : readError;
        text += `\n\n${"⚠️"} <b>${t(lang, "status.errReads", { err: htmlEscape(short) })}</b>`;
      } else if (queueWait > 10_000) {
        text += `\n\n${"⚠️"} <b>${t(lang, "status.errSlow", { s: Math.round(queueWait / 1000) })}</b>`;
      } else if (dropped > 0) {
        text += `\n\n${"⚠️"} <b>${t(lang, "status.errDrop", { n: dropped })}</b>`;
      }
      return { text, markup: statusKeyboard(lang, mode) };
    },
    async pool(args = [], ctx = {}) {
      const { lang, mode } = prefsOf(ctx);
      // `/pool 3` — page 3 of the newest-first window. Non-numeric input falls
      // back to page 1 (the abuse guard already rejected hostile charsets; a
      // plain word here is a typo, not an attack, and deserves the first page).
      const page = args.length && /^\d{1,4}$/.test(args[0]) ? Number(args[0]) : 1;
      return renderPoolPage(page, ctx);
    },
    async task(args, ctx = {}) {
      const { lang } = prefsOf(ctx);
      if (!args.length) return { text: t(lang, "common.usageTask"), markup: navRow(lang) };
      // Санитизация до RPC: id — короткий decimal. Длинная строка здесь — либо мусор,
      // либо попытка заставить ноду жевать BigInt из килобайта цифр.
      if (!isTaskId(args[0])) return { text: t(lang, "common.badId"), markup: navRow(lang) };
      return renderTaskView(BigInt(args[0]), ctx.chatId, ctx);
    },
    async watch(args, ctx = {}) {
      const { lang } = prefsOf(ctx);
      if (ctx.chatId === undefined || !store) {
        return { text: t(lang, "common.noWatch"), markup: undefined };
      }
      if (!args.length || !isTaskId(args[0])) {
        return { text: t(lang, "common.usageWatch"), markup: navRow(lang) };
      }
      const res = await store.addWatch(ctx.chatId, args[0]);
      const list = store.listWatched(ctx.chatId);
      return {
        text: `${htmlEscape(res.reason)}\n\n${renderWatchlist(list, lang)}`,
        markup: taskLinkKeyboard(args[0], lang),
      };
    },
    async unwatch(args, ctx = {}) {
      const { lang } = prefsOf(ctx);
      if (ctx.chatId === undefined || !store) {
        return { text: t(lang, "common.noWatch"), markup: undefined };
      }
      if (!args.length || !isTaskId(args[0])) {
        return { text: t(lang, "common.usageUnwatch"), markup: navRow(lang) };
      }
      const res = await store.removeWatch(ctx.chatId, args[0]);
      const list = store.listWatched(ctx.chatId);
      return { text: `${htmlEscape(res.reason)}\n\n${renderWatchlist(list, lang)}`, markup: navRow(lang) };
    },
    async watchlist(args, ctx = {}) {
      const { lang } = prefsOf(ctx);
      if (ctx.chatId === undefined || !store) {
        return { text: t(lang, "common.noWatch"), markup: undefined };
      }
      return { text: renderWatchlist(store.listWatched(ctx.chatId), lang), markup: navRow(lang) };
    },
    async alerts(args, ctx = {}) {
      const { lang, mode } = prefsOf(ctx);
      if (ctx.chatId === undefined || !store) {
        return { text: t(lang, "common.noAlerts"), markup: undefined };
      }
      const eff = effectiveAlerts(config.alerts ?? {}, store.state(), ctx.chatId);
      const inherited = {};
      const override = store.state().chats[String(ctx.chatId)]?.alerts ?? {};
      for (const key of ALERT_KEYS) inherited[key] = override[key] !== true && override[key] !== false;
      return { text: renderAlerts(eff, inherited, lang), markup: alertsKeyboard(eff, lang, mode) };
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
export async function routeCallback(parsed, { chain, config, store, chatId, onToast, langCode }) {
  const toast = onToast ?? (async () => {});
  const say = async (t) => toast(t);
  // Display prefs for re-renders: stored win, the pressing chat's client is
  // the fallback. No stored prefs and no language hint means English pro —
  // the historical default.
  const prefs = () => {
    const stored = store ? getPrefs(store.state(), chatId) : {};
    const lang = stored.lang || (langCode ? pickLang(langCode) : "en");
    const mode = stored.mode || "pro";
    return { lang: isLang(lang) ? lang : "en", mode: mode === "simple" ? "simple" : "pro" };
  };
  const handlers = () => createHandlers(chain, config, { store });
  // Re-render any screen by target descriptor (see keyboards.isTarget): used
  // by the mode/language toggles so the reader never leaves their context.
  const renderTarget = async (target) => {
    const [head, ...rest] = target.split(":");
    const { lang, mode } = prefs();
    if (head === "s") return handlers().status([], { chatId, langCode });
    if (head === "h" || head === "menu") return handlers().menu([], { chatId, langCode });
    if (head === "how") return { text: renderHow(lang, mode), markup: howKeyboard(lang, mode) };
    if (head === "proto") return { text: renderProtocol(lang), markup: protoKeyboard(lang, mode) };
    if (head === "set") return handlers().settings([], { chatId, langCode });
    if (head === "a") return handlers().alerts([], { chatId, langCode });
    if (head === "lim") return handlers().limits([], { chatId, langCode });
    if (head === "help") return handlers().help([], { chatId, langCode });
    if (head === "r") {
      const role = rest[0];
      if (!isRole(role)) return { text: t(lang, "role.pick"), markup: roleKeyboard(lang, mode, "buyer") };
      return { text: renderRole(role, lang, mode), markup: roleKeyboard(lang, mode, role) };
    }
    if (head === "p") return handlers().renderPoolPage(Number(rest[0]), { chatId, langCode });
    if (head === "t") return handlers().renderTaskView(BigInt(rest[0]), chatId, { chatId, langCode });
    return { text: t(lang, "common.unavailable"), markup: navRow(lang) };
  };
  // Shared toggle body: lowercase "a" lands on the alerts screen, uppercase
  // "A" (settings keyboard) stays in settings. The toast confirms the flip
  // either way.
  const toggleAlert = async (key, target) => {
    if (!store || chatId === undefined) {
      const { lang } = prefs();
      return { text: t(lang, "common.noAlerts"), markup: undefined };
    }
    const eff = effectiveAlerts(config.alerts ?? {}, store.state(), chatId);
    const next = !eff[key];
    await store.setAlert(chatId, key, next);
    const { lang } = prefs();
    const names = { mm: t(lang, "alerts.mm"), disp: t(lang, "alerts.disp"), rot: t(lang, "alerts.rot"), tre: t(lang, "alerts.tre"), ver: t(lang, "alerts.ver") };
    await say(`${names[key] ?? key} ${next ? t(lang, "common.onState") : t(lang, "common.offState")}`);
    return renderTarget(target);
  };
  switch (parsed.op) {
    case "p": {
      return renderTarget(`p:${parsed.arg}`);
    }
    case "t": {
      return renderTarget(`t:${parsed.arg}`);
    }
    case "w": {
      if (!store || chatId === undefined) {
        const { lang } = prefs();
        return { text: t(lang, "common.noWatch"), markup: undefined };
      }
      const res = await store.addWatch(chatId, parsed.arg);
      await say(res.added ? t(prefs().lang, "toast.watching", { id: parsed.arg }) : res.reason);
      return renderTarget(`t:${parsed.arg}`);
    }
    case "u": {
      if (!store || chatId === undefined) {
        const { lang } = prefs();
        return { text: t(lang, "common.noWatch"), markup: undefined };
      }
      const res = await store.removeWatch(chatId, parsed.arg);
      await say(res.removed ? t(prefs().lang, "toast.unwatched", { id: parsed.arg }) : res.reason);
      return renderTarget(`t:${parsed.arg}`);
    }
    case "s": {
      return renderTarget("s");
    }
    case "h":
    case "menu": {
      return handlers().menu([], { chatId, langCode });
    }
    case "how": {
      return renderTarget("how");
    }
    case "proto": {
      return renderTarget("proto");
    }
    case "set": {
      return renderTarget("set");
    }
    case "lim": {
      return renderTarget("lim");
    }
    case "help": {
      return renderTarget("help");
    }
    case "a": {
      if (!parsed.arg) return renderTarget("a");
      return toggleAlert(parsed.arg, "a");
    }
    case "A": {
      return toggleAlert(parsed.arg, "set");
    }
    case "r": {
      if (!isRole(parsed.arg)) return { text: t(prefs().lang, "role.pick"), markup: roleKeyboard(prefs().lang, prefs().mode, "buyer") };
      const { lang, mode } = prefs();
      return { text: renderRole(parsed.arg, lang, mode), markup: roleKeyboard(lang, mode, parsed.arg) };
    }
    case "m": {
      // Flip whatever the chat currently sees (stored or default pro), then
      // re-render in place. Toggling from the raw stored value alone would make
      // the first press a no-op for chats that never chose: no stored mode
      // reads as pro, and "not pro" flipped naively stays pro.
      if (store && chatId !== undefined) {
        const cur = prefs().mode;
        await store.setPref(chatId, "mode", cur === "pro" ? "simple" : "pro");
      }
      return renderTarget(parsed.arg);
    }
    case "l": {
      // Set the language (validated by parseCallback), then re-render.
      const j = parsed.arg.indexOf(":");
      const lang = parsed.arg.slice(0, j);
      const target = parsed.arg.slice(j + 1);
      if (store && chatId !== undefined) await store.setPref(chatId, "lang", lang);
      return renderTarget(target);
    }
    default: {
      // Stale buttons used to strand the chat (no keyboard to get back with);
      // keep the hub one tap away instead.
      const { lang } = prefs();
      return { text: t(lang, "toast.oldBot"), markup: navRow(lang) };
    }
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
    console.error(`\nCannot reach the chain: ${scrubRpcSecret(err.message, config.rpcUrl)}\n`);
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
    const text = normalizeInput(msg.text ?? "");
    const langCode = msg.from?.language_code;
    let verdict;
    try {
      verdict = await abuseGuard.guardChat(chatId ?? msg.chat?.id ?? "unknown", text);
    } catch {
      verdict = { action: "pass" }; // fail-open охраны: лучше лишний RPC, чем мёртвый бот
    }
    if (verdict.action === "deny-usage" || verdict.action === "deny-rate" || verdict.action === "shadow") {
      return { text: verdict.reply, markup: undefined };
    }
    // NOTE: the store is called `watchStore` in this scope (`store` lives
    // only inside createHandlers/routeCallback). A bare `store` here throws
    // ReferenceError and would replace the real handler error with itself.
    const guessLang = () => resolveChatLang(watchStore, chatId ?? msg.chat?.id, langCode);
    try {
      return await abuseGuard.runHandler(chatId ?? msg.chat?.id ?? "unknown", async () => {
        const { name, args } = commandFromVerdict(verdict, text);
        const handler = handlers[name];
        if (!handler || typeof handler !== "function") {
          return handlers.help([], { chatId, langCode });
        }
        try {
          return await handler(args, { chatId, langCode });
        } catch (err) {
          // A failing command must not kill the process: an ops bot that crashes on
          // one bad RPC read is worse than one that says "that failed".
          // err.message is escaped: replies go out with parse_mode HTML and a raw
          // "<" from an RPC/proxy error would make Telegram reject the send (400).
          // It is scrubbed too: the reply lands in a chat, and an error that quotes
          // the RPC URL would put the provider's key in the chat's history.
          const message = htmlEscape(scrubRpcSecret(err.message, config.rpcUrl));
          const lang = guessLang();
          return { text: t(lang, "common.failed", { name, err: message }), markup: navRow(lang) };
        }
      });
    } catch (err) {
      // A failing command must not kill the process: an ops bot that crashes on
      // one bad RPC read is worse than one that says "that failed".
      const message = htmlEscape(scrubRpcSecret(err.message, config.rpcUrl));
      const lang = guessLang();
      return { text: t(lang, "common.failedNoName", { err: message }), markup: navRow(lang) };
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
  const CALLBACK_TEXT = { p: "/pool", t: "/task x", w: "/watch x", u: "/watch x", s: "/status", a: "/alerts", A: "/alerts", h: "/help", r: "/role", m: "/pro", l: "/lang", menu: "/help", how: "/help", proto: "/help", set: "/alerts", lim: "/limits", help: "/help" };

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
    // Toast language: stored prefs win, else the pressing client's locale.
    // (The guard replies and the "not authorised" refusal stay English on
    // purpose: the former has no chat context, the latter must not leak it.)
    const storedPrefs = getPrefs(watchStore.state(), chatId);
    const toastLang = isLang(storedPrefs.lang) ? storedPrefs.lang : pickLang(query.from?.language_code);
    const parsed = parseCallback(data);
    if (!parsed) {
      await bot.answerCallbackQuery(query.id, t(toastLang, "toast.stale"));
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
          langCode: query.from?.language_code,
          onToast: (t) => bot.answerCallbackQuery(query.id, t),
        })
      );
    } catch (err) {
      await bot.answerCallbackQuery(query.id, t(toastLang, "toast.failed"));
      log("error", config)("callback failed:", scrubRpcSecret(err.message, config.rpcUrl));
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
    let offset = await loadTgOffset();
    for (;;) {
      try {
        const { updates, nextOffset } = await bot.getUpdates(offset, 30);
        if (nextOffset !== offset) {
          offset = nextOffset;
          // Persist before dispatch: a crash between poll and persist replays one
          // batch (deduped by #seen), while persist-after-dispatch risks skipping.
          // Fire-and-forget is fine — worst case is one replayed batch.
          void saveTgOffset(offset);
        }

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
  // filtering (`null` for global rotation/treasury/verifier alerts, which
  // always bypass it), `key` selects the per-chat flag
  // (`mm` | `disp` | `rot` | `tre` | `ver`), and `markup` carries the
  // deep-link button.

  async function scanOnce(cursor, seen, digests = new Map()) {
    let head = await chain.blockNumber();
    if (head < cursor) {
      // Reorg below the cursor: block numbers now repeat with different contents.
      // Rewind one block *before* the new head, not to it: the rewritten head
      // block itself is never rescanned otherwise, and a rotation landing
      // exactly there would be missed. The seen-set suppresses the logs that
      // did not actually change, so the overlap is free.
      log("warn", config)(`head ${head} is below cursor ${cursor} (reorg); rewinding`);
      cursor = Math.max(0, head - 1);
    }
    if (head <= cursor) return { cursor, alerts: [], seen };

    const alerts = [];
    // A failed block holds the cursor: the next poll rescans the same range
    // and the seen-set dedupes what already alerted. That turns a transient
    // RPC failure into a quiet retry instead of a silent loss — at the price
    // of one repeated window, never a duplicate alert.
    let nextCursor = head;
    const failBlock = (name, err) => {
      log("error", config)(`alert scan (${name}) failed, will retry range:`, scrubRpcSecret(err.message, config.rpcUrl));
      nextCursor = cursor;
    };

    // Commits, so a same-epoch digest disagreement can be detected. `digests`
    // holds the last-seen digest per (task, epoch, node) and is persisted with
    // the cursor: a static in-memory map here once missed every mismatch whose
    // two commits straddled a restart.

    // Note: no global-flag gate here. Delivery is decided per chat in
    // pollAlerts (override wins, otherwise global): collecting always keeps
    // the digest/dedupe tracking correct even while a flag is off, so
    // toggling it on later does not replay history.
    try {
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
            kind: "mismatch",
            taskId: String(args.taskId),
            key: "mm",
            link: { type: "task", id: String(args.taskId) },
            payload: args,
          });
        }
      }
    }
    } catch (err) { failBlock("commitments", err); }

    try {
    if (config.cipherTask) {
      const events = dedupeEvents(await chain.disputeEvents(cursor + 1, head), seen);
      // Settlement amounts render at delivery; the scale is read once per scan
      // (cached in the reader afterwards) and travels on the alert itself.
      const decimals = events.length ? await escrowScale(chain) : 18;
      for (const ev of events) {
        // Rendered at delivery, per chat language — see deliverAlert. Unknown
        // event shapes stay silent rather than push an empty message.
        if (!ev.args) continue;
        const taskId = ev.args.taskId !== undefined ? String(ev.args.taskId) : null;
        alerts.push({
          kind: "dispute",
          taskId,
          key: "disp",
          decimals,
          link: taskId !== null ? { type: "task", id: taskId } : null,
          payload: ev,
        });
      }
    }
    } catch (err) { failBlock("disputes", err); }

    try {
    if (config.networkParams) {
      const { executed, proposed, approved = [], cancelled = [] } = await chain.rotationEvents(cursor + 1, head);
      for (const ev of dedupeEvents(proposed, seen)) {
        alerts.push({
          kind: "rotation",
          taskId: null,
          key: "rot",
          link: { type: "status" },
          payload: {
            variant: "proposed",
            args: {
              proposer: ev.args.proposer,
              expectedHash: ev.args.expectedHash,
              scheduledAt: ev.args.scheduledAt,
            },
          },
        });
      }
      // Approval is the point of no return: after the timelock anyone can
      // execute, so an unexpected approval deserves the same noise as a proposal.
      for (const ev of dedupeEvents(approved, seen)) {
        alerts.push({
          kind: "rotation",
          taskId: null,
          key: "rot",
          link: { type: "status" },
          payload: {
            variant: "approved",
            args: {
              approver: ev.args.approver,
              expectedHash: ev.args.expectedHash,
            },
          },
        });
      }
      // A cancellation closes the story: the queued key will never activate.
      // Also fires when an approver rotation drops an unapproved queue.
      for (const ev of dedupeEvents(cancelled, seen)) {
        alerts.push({
          kind: "rotation",
          taskId: null,
          key: "rot",
          link: { type: "status" },
          payload: {
            variant: "cancelled",
            args: {
              scheduledAt: ev.args.scheduledAt,
            },
          },
        });
      }
      for (const ev of dedupeEvents(executed, seen)) {
        alerts.push({
          kind: "rotation",
          taskId: null,
          key: "rot",
          link: { type: "status" },
          payload: {
            variant: "executed",
            args: {
              keyVersion: ev.args.keyVersion,
              fhePublicKeyHash: ev.args.fhePublicKeyHash,
            },
          },
        });
      }
    }
    } catch (err) { failBlock("key-rotation", err); }

    try {
    if (config.cipherTask) {
      // The treasury rotation is the one rotation whose window is the whole point:
      // the money only moves if nobody objects during it. So the proposal is
      // reported on its own, not only the moment it lands.
      for (const ev of dedupeEvents(await chain.treasuryEvents(cursor + 1, head), seen)) {
        const name = ev.name ?? "";
        let variant = null;
        let args = null;
        if (name === "TreasuryProposed") {
          variant = "proposed";
          args = { to: ev.args?.to, eta: ev.args?.eta };
        } else if (name === "TreasuryChanged") {
          variant = "executed";
          args = { from: ev.args?.from, to: ev.args?.to };
        } else if (name === "TreasuryRotationCancelled") {
          variant = "cancelled";
          args = { dropped: ev.args?.dropped };
        }
        if (variant) {
          alerts.push({
            kind: "treasury",
            taskId: null,
            key: "tre",
            link: { type: "status" },
            payload: { variant, args },
          });
        }
      }
    }
    } catch (err) { failBlock("treasury", err); }

    try {
    if (config.verifier) {
      // The verifier gates every payout, so its rotation is money rotation:
      // propose (owner) → 7-day timelock → execute (anyone) or cancel (owner).
      // No approver step here, unlike the key rotation.
      const { rotated, proposed, cancelled } = await chain.verifierEvents(cursor + 1, head);
      for (const ev of dedupeEvents(proposed, seen)) {
        alerts.push({
          kind: "verifier",
          taskId: null,
          key: "ver",
          link: { type: "status" },
          payload: {
            variant: "proposed",
            args: { to: ev.args.to, executableAt: ev.args.executableAt },
          },
        });
      }
      for (const ev of dedupeEvents(cancelled, seen)) {
        alerts.push({
          kind: "verifier",
          taskId: null,
          key: "ver",
          link: { type: "status" },
          payload: {
            variant: "cancelled",
            args: { dropped: ev.args.verifier },
          },
        });
      }
      for (const ev of dedupeEvents(rotated, seen)) {
        alerts.push({
          kind: "verifier",
          taskId: null,
          key: "ver",
          link: { type: "status" },
          payload: {
            variant: "executed",
            args: { from: ev.args.from, to: ev.args.to },
          },
        });
      }
    }
    } catch (err) { failBlock("verifier-rotation", err); }

    return { cursor: nextCursor, alerts, seen };
  }

  /**
   * Deliver one scanned alert to every chat that wants it (see
   * `shouldDeliverAlert` for the routing matrix, pinned by tests). Text and
   * buttons render per chat in its language: the stored prefs win, otherwise
   * English — alerts fired before any /start are in the historical language.
   */
  function deliverAlert(alert) {
    const jobs = [];
    for (const chatId of config.allowedChatIds) {
      if (!shouldDeliverAlert(alert, config.alerts, watchStore.state(), chatId)) continue;
      const stored = watchStore ? getPrefs(watchStore.state(), chatId) : {};
      const lang = stored.lang || "en";
      const text = renderAlert(alert, lang, alert.decimals ?? 18);
      if (!text) continue; // unknown event shape: never push an empty message
      const markup =
        alert.link?.type === "task"
          ? taskLinkKeyboard(alert.link.id, lang)
          : rotationKeyboard(lang);
      jobs.push(
        bot
          .sendQueued(chatId, text, {
            ...(config.html ? { parse_mode: "HTML" } : {}),
            ...(markup ? { reply_markup: markup } : {}),
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
        // loss is an incident, so this is the right bias. Known boundary: an alert
        // whose Telegram send keeps failing is logged and skipped while the cursor
        // still advances — a total Telegram outage can lose, never duplicate.
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
      `key rotation ${config.alerts.keyRotation ? "on" : "off"}, ` +
      `treasury ${config.alerts.treasury ? "on" : "off"}, ` +
      `verifier ${config.alerts.verifierRotation ? "on" : "off"}`
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