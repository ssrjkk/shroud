/**
 * Inline keyboards and callback payloads.
 *
 * Every bot reply that can be refreshed or navigated carries an inline
 * keyboard; every button press arrives back as a `callback_query` update whose
 * `data` must be parsed without trusting Telegram (or anyone who learned the
 * bot's shape) — a malformed payload answers with a hint, never with an RPC
 * call or a crash.
 *
 * `callback_data` is capped by Telegram at 64 bytes, so the encoding is
 * single-letter opcodes with positional arguments:
 *
 *   p:<page>        pool page (1-based)
 *   t:<id>          task view
 *   w:<id>          watch task
 *   u:<id>          unwatch task
 *   s               status refresh
 *   h | menu        hub (h is the legacy start-screen opcode)
 *   how             how-it-works screen
 *   proto           geek protocol spec
 *   set             settings screen
 *   a               alerts screen
 *   a:<key>         toggle a per-chat alert flag (mm | disp | rot | tre)
 *   r:<role>        role guide (buyer | contrib | node | watcher)
 *   m:<target>      flip simple/geek and re-render the target screen
 *   l:<lang>:<target>  set language and re-render the target screen
 *   lim             limits screen (honest limitations)
 *   help            help screen (command map)
 *   A:<key>         toggle a per-chat alert flag and stay in settings
 *
 * A <target> names the screen to re-render: s, h, menu, how, proto, set, a,
 * lim, help, r:<role>, p:<page>, t:<id>. Everything stays far under the cap:
 * the longest payload, a 20-digit task re-render in the other language
 * (`l:en:t:` + 20 digits), is 27 bytes of the 64 allowed.
 *
 * Builders return `{ text, reply_markup }`-ready `reply_markup` objects only;
 * rendering stays in format.js so keyboards never interpolate chain data
 * themselves (markup injection would render as broken buttons).
 */

import { t } from "./i18n.js";
import { isRole } from "./roles.js";

export const CALLBACK_LIMIT = 64;

/** Task ids are short decimals everywhere (/task gate, watchlist, callbacks). */
export function isTaskId(s) {
  return typeof s === "string" && /^\d{1,20}$/.test(s);
}

/**
 * Encode a callback payload. Returns `null` when the payload would exceed
 * Telegram's 64-byte cap rather than producing a button that silently fails.
 */
export function encodeCallback(op, arg = "") {
  const data = arg === "" ? op : `${op}:${arg}`;
  if (data.length > CALLBACK_LIMIT) return null;
  return data;
}

/**
 * Parse a callback payload back into `{ op, arg }`.
 *
 * Total: anything outside the known opcode/argument shape is `null` — the
 * caller answers the query with a hint and moves on. Callback data is
 * attacker-controlled input (anyone can POST a crafted update if they reach
 * long polling is impossible, but stale buttons from an older bot version are
 * real), so this never throws.
 */
export function parseCallback(data) {
  if (typeof data !== "string" || data.length === 0 || data.length > CALLBACK_LIMIT) {
    return null;
  }
  if (data === "s") return { op: "s", arg: "" };
  if (data === "h") return { op: "h", arg: "" };
  if (data === "menu") return { op: "menu", arg: "" };
  if (data === "how") return { op: "how", arg: "" };
  if (data === "proto") return { op: "proto", arg: "" };
  if (data === "set") return { op: "set", arg: "" };
  if (data === "a") return { op: "a", arg: "" };
  if (data === "lim") return { op: "lim", arg: "" };
  if (data === "help") return { op: "help", arg: "" };
  const i = data.indexOf(":");
  if (i === -1) return null;
  const op = data.slice(0, i);
  const arg = data.slice(i + 1);
  // No global arg-length cap: each opcode validates its own shape below
  // (fixed enums, isTaskId's 20 decimals, the 1..1000 page range), and the
  // whole payload is already capped at 64 bytes above. A global cap here used
  // to silently kill mode/language toggles on tasks with 16+ digit ids while
  // the task buttons themselves parsed fine.
  if (arg.length === 0) return null;
  switch (op) {
    case "p":
      // Pool page: positive integer, bounded so a crafted button cannot ask
      // the node to walk an unbounded range (each page costs ~12 RPC calls).
      if (!/^\d{1,4}$/.test(arg)) return null;
      if (Number(arg) < 1 || Number(arg) > 1000) return null;
      return { op, arg };
    case "t":
    case "w":
    case "u":
      if (!isTaskId(arg)) return null;
      return { op, arg };
    case "a":
    case "A":
      // Lowercase toggles land on the alerts screen, uppercase ones stay in
      // settings — same flags, different return address.
      if (arg !== "mm" && arg !== "disp" && arg !== "rot" && arg !== "tre" && arg !== "ver") return null;
      return { op, arg };
    case "r":
      if (!isRole(arg)) return null;
      return { op, arg };
    case "m": {
      // Re-render target after flipping simple/pro: s, h, a, r:<role>,
      // p:<page>, t:<id>. Same grammar as a target, checked twice — once
      // here, once where it is rendered.
      if (!isTarget(arg)) return null;
      return { op, arg };
    }
    case "l": {
      // Language switch with a re-render target: "<lang>:<target>".
      const j = arg.indexOf(":");
      if (j === -1) return null;
      const lang = arg.slice(0, j);
      const target = arg.slice(j + 1);
      if (lang !== "ru" && lang !== "en") return null;
      if (!isTarget(target)) return null;
      return { op, arg };
    }
    default:
      return null;
  }
}

/**
 * Re-render target grammar shared by `m:` and `l:` payloads: every bare
 * screen plus r:<role> (guide), p:<page> (pool page), t:<id> (task).
 * Anything else is not a screen and cannot be re-rendered.
 */
export function isTarget(s) {
  if (
    s === "s" || s === "h" || s === "a" || s === "menu" || s === "how" ||
    s === "proto" || s === "set" || s === "lim" || s === "help"
  ) return true;
  const i = s.indexOf(":");
  if (i === -1) return false;
  const op = s.slice(0, i);
  const arg = s.slice(i + 1);
  if (op === "r") return isRole(arg);
  if (op === "p") return /^\d{1,4}$/.test(arg) && Number(arg) >= 1 && Number(arg) <= 1000;
  if (op === "t") return isTaskId(arg);
  return false;
}

/** Map a parsed callback to the abuse-guard cost of the work it triggers. */
export function callbackCost(parsed) {
  if (!parsed) return 1;
  switch (parsed.op) {
    case "p":
      return 15; // same as /pool: one page of task reads
    case "t":
      return 5; // same as /task
    case "s":
      return 4; // same as /status
    case "w":
    case "u":
      // The watch buttons are not free: they toggle the watchlist and then render the
      // *full task view* (task + contributors + commits per contributor + winner +
      // quorum), which is the work `/task` does. Pricing them like the cheap `/watch`
      // command (1) let a chat buy five times the intended RPC amplification - exactly
      // what the per-chat budget exists to stop.
      return 5;
    case "m":
    case "l": {
      // A mode/language flip re-renders its target, so it costs what the
      // target screen costs: pool pages are the only expensive ones.
      const target = parsed.op === "m" ? parsed.arg : parsed.arg.slice(parsed.arg.indexOf(":") + 1);
      const top = target.split(":")[0];
      if (top === "p") return 15;
      if (top === "t") return 5;
      if (top === "s") return 4;
      return 1;
    }
    case "h":
    case "r":
    case "menu":
    case "how":
    case "proto":
    case "set":
    case "lim":
    case "help":
      return 1; // static screens: no RPC at all
    case "A":
      return 1; // settings toggle: local state only, like "a"
    default:
      return 1; // the alert toggles touch local state only
  }
}

const button = (text, callback_data) => ({ text, callback_data });

/**
 * Pool keyboard: up to 4 task buttons per row (short ids stay readable),
 * plus a pager row, first/last jump buttons on deep pools, and a hub row.
 * `page` is 1-based; `pages` is the total page count. The last row flips
 * simple/geek and RU/EN in place (`origin` re-renders this same page).
 */
export function poolKeyboard(ids, page, pages, lang = "en", mode = "pro") {
  const rows = [];
  for (let i = 0; i < ids.length; i += 4) {
    rows.push(ids.slice(i, i + 4).map((id) => button(`#${String(id)}`, encodeCallback("t", String(id)))));
  }
  const nav = [];
  if (page > 1) nav.push(button(t(lang, "btn.prev"), encodeCallback("p", String(page - 1))));
  if (page < pages) nav.push(button(t(lang, "btn.next"), encodeCallback("p", String(page + 1))));
  if (nav.length) rows.push(nav);
  // Deep pools: walking ‹ prev / next › one page at a time is tedious, so
  // offer direct jumps — but only when they skip at least one page, otherwise
  // they duplicate prev/next. Labels are plain numbers, same in both languages.
  const jumps = [];
  if (page > 2) jumps.push(button(`« 1`, encodeCallback("p", "1")));
  if (page < pages - 1) jumps.push(button(`${pages} »`, encodeCallback("p", String(pages))));
  if (jumps.length) rows.push(jumps);
  if (rows.length) rows.push([button(t(lang, "btn.menu"), "menu"), button(t(lang, "btn.how"), "how")]);
  if (rows.length) rows.push(prefsRow(lang, mode, `p:${page}`));
  return rows.length ? { inline_keyboard: rows } : undefined;
}

/**
 * Task keyboard: refresh, watch/unwatch toggle, neighbours for prev/next
 * navigation (prev/next may be null at the pool edges), then the mode/language
 * row so the reader can switch depth without leaving the task.
 */
export function taskKeyboard(taskId, { watched, prevId = null, nextId = null, lang = "en", mode = "pro" } = {}) {
  const id = String(taskId);
  const rows = [
    [
      button(t(lang, "btn.refresh"), encodeCallback("t", id)),
      watched
        ? button(t(lang, "btn.unwatch"), encodeCallback("u", id))
        : button(t(lang, "btn.watch"), encodeCallback("w", id)),
    ],
  ];
  const nav = [];
  if (prevId !== null) nav.push(button(t(lang, "btn.prev"), encodeCallback("t", String(prevId))));
  nav.push(button(t(lang, "btn.pool"), encodeCallback("p", "1")));
  if (nextId !== null) nav.push(button(t(lang, "btn.next"), encodeCallback("t", String(nextId))));
  rows.push(nav);
  rows.push([button(t(lang, "btn.menu"), "menu"), button(t(lang, "btn.how"), "how")]);
  rows.push(prefsRow(lang, mode, `t:${id}`));
  return { inline_keyboard: rows };
}

/** Status keyboard: refresh, hub links, plus the mode/language row. */
export function statusKeyboard(lang = "en", mode = "pro") {
  return {
    inline_keyboard: [
      [button(t(lang, "btn.refresh"), "s")],
      [button(t(lang, "btn.menu"), "menu"), button(t(lang, "btn.how"), "how")],
      prefsRow(lang, mode, "s"),
    ],
  };
}

const ALERT_LABELS = { mm: "alerts.mm", disp: "alerts.disp", rot: "alerts.rot", tre: "alerts.tre", ver: "alerts.ver" };

/**
 * Alert-override keyboard: one toggle button per flag showing its effective
 * state, plus a refresh back to /status. `effective` maps mm/disp/rot/tre/ver
 * to booleans already resolved against the global config. Five toggles ride
 * in 3+2 rows — five across would shrink every button to tap-target noise.
 */
export function alertsKeyboard(effective, lang = "en", mode = "pro") {
  const all = Object.entries(ALERT_LABELS).map(([key, labelKey]) =>
    button(`${effective[key] ? "✅" : "❌"} ${t(lang, labelKey)}`, encodeCallback("a", key))
  );
  const rows = [all.slice(0, 3), all.slice(3)];
  rows.push([button(t(lang, "btn.status"), "s")]);
  rows.push([button(t(lang, "btn.menu"), "menu"), button(t(lang, "btn.settings"), "set")]);
  rows.push(prefsRow(lang, mode, "a"));
  return { inline_keyboard: rows };
}

/** Deep link from a task-scoped alert back to the task view. */
export function taskLinkKeyboard(taskId, lang = "en") {
  const id = String(taskId);
  return { inline_keyboard: [[button(t(lang, "btn.viewTask", { id }), encodeCallback("t", id))]] };
}

/** Deep link from a rotation alert back to /status. */
export function rotationKeyboard(lang = "en") {
  return { inline_keyboard: [[button(t(lang, "btn.viewStatus"), "s")]] };
}

/**
 * One row that flips simple/geek and RU/EN in place. Both buttons name the
 * TARGET, never the current state: tapping "mode: geek" always lands in geek
 * mode, like tapping "EN" always lands in English. `origin` names the screen
 * to re-render (s, h, a, r:<role>, p:<n>, t:<id>), so the toggle never kicks
 * the reader out of context.
 */
export function prefsRow(lang, mode, origin) {
  const other = lang === "ru" ? "en" : "ru";
  return [
    button(t(lang, mode === "simple" ? "btn.modePro" : "btn.modeSimple"), `m:${origin}`),
    button(other === "ru" ? "RU" : "EN", `l:${other}:${origin}`),
  ];
}

/**
 * Start / menu screen: the hub.
 *
 * First two rows jump to live data (status, pool) and to explainers
 * (how, protocol). Then trust (limits, alerts) and the four role guides.
 * Last row flips simple/geek + RU/EN in place. Extended rows never break
 * old tests — they only assert `includes` for roles and prefs.
 */
export function startKeyboard(lang = "en", mode = "pro") {
  return {
    inline_keyboard: [
      [
        button(t(lang, "btn.statusLong"), "s"),
        button(t(lang, "btn.poolLong"), "p:1"),
      ],
      [
        button(t(lang, "btn.how"), "how"),
        button(t(lang, "btn.proto"), "proto"),
      ],
      [
        button(t(lang, "btn.alertsLong"), "a"),
        button(t(lang, "btn.limits"), "lim"),
      ],
      [
        button(t(lang, "btn.roleBuyer"), "r:buyer"),
        button(t(lang, "btn.roleContrib"), "r:contrib"),
      ],
      [
        button(t(lang, "btn.roleNode"), "r:node"),
        button(t(lang, "btn.roleWatcher"), "r:watch"),
      ],
      prefsRow(lang, mode, "h"),
    ],
  };
}

/** Alias: /menu renders the same hub as /start (without touching prefs). */
export function menuKeyboard(lang = "en", mode = "pro") {
  return startKeyboard(lang, mode);
}

/** How-it-works screen: next steps + back to hub. */
export function howKeyboard(lang = "en", mode = "pro") {
  return {
    inline_keyboard: [
      [
        button(t(lang, "btn.proto"), "proto"),
        button(t(lang, "btn.poolLong"), "p:1"),
      ],
      [
        button(t(lang, "btn.menu"), "menu"),
        button(t(lang, "btn.limits"), "lim"),
      ],
      prefsRow(lang, mode, "how"),
    ],
  };
}

/** Protocol (geek) screen. */
export function protoKeyboard(lang = "en", mode = "pro") {
  return {
    inline_keyboard: [
      [
        button(t(lang, "btn.how"), "how"),
        button(t(lang, "btn.limits"), "lim"),
      ],
      [
        button(t(lang, "btn.statusLong"), "s"),
        button(t(lang, "btn.menu"), "menu"),
      ],
      prefsRow(lang, mode, "proto"),
    ],
  };
}

/** Settings screen: alert toggles + hub links + prefs row. */
export function settingsKeyboard(effective, lang = "en", mode = "pro") {
  // Uppercase "A" toggles: the flip stays in settings instead of jumping to
  // the alerts screen (see routeCallback). Same flags, same cost.
  const names = { mm: t(lang, "alerts.mm"), disp: t(lang, "alerts.disp"), rot: t(lang, "alerts.rot"), tre: t(lang, "alerts.tre"), ver: t(lang, "alerts.ver") };
  return {
    inline_keyboard: [
      [
        button(`${effective?.mm ? "✅" : "❌"} ${names.mm}`, encodeCallback("A", "mm")),
        button(`${effective?.disp ? "✅" : "❌"} ${names.disp}`, encodeCallback("A", "disp")),
        button(`${effective?.rot ? "✅" : "❌"} ${names.rot}`, encodeCallback("A", "rot")),
      ],
      [
        button(`${effective?.tre ? "✅" : "❌"} ${names.tre}`, encodeCallback("A", "tre")),
        button(`${effective?.ver ? "✅" : "❌"} ${names.ver}`, encodeCallback("A", "ver")),
      ],
      [
        button(t(lang, "btn.menu"), "menu"),
        button(t(lang, "btn.statusLong"), "s"),
      ],
      prefsRow(lang, mode, "set"),
    ],
  };
}

/**
 * Minimal hub row for terminal screens (confirmations, empty states): just a
 * way back, no prefs row — there is no screen context worth preserving.
 */
export function navRow(lang = "en") {
  return {
    inline_keyboard: [
      [button(t(lang, "btn.menu"), "menu"), button(t(lang, "btn.how"), "how")],
    ],
  };
}

/** Small hub-link row for help / limits screens. */
export function hubLinkKeyboard(lang = "en", mode = "pro", origin = "h") {
  return {
    inline_keyboard: [
      [
        button(t(lang, "btn.menu"), "menu"),
        button(t(lang, "btn.how"), "how"),
      ],
      prefsRow(lang, mode, origin),
    ],
  };
}

/** Role guide screen: switch guides in place, plus hub + mode/language rows. */
export function roleKeyboard(lang = "en", mode = "pro", role = "buyer") {
  return {
    inline_keyboard: [
      [
        button(t(lang, "btn.roleBuyer"), "r:buyer"),
        button(t(lang, "btn.roleContrib"), "r:contrib"),
      ],
      [
        button(t(lang, "btn.roleNode"), "r:node"),
        button(t(lang, "btn.roleWatcher"), "r:watch"),
      ],
      [
        button(t(lang, "btn.menu"), "menu"),
        button(t(lang, "btn.how"), "how"),
      ],
      prefsRow(lang, mode, `r:${role}`),
    ],
  };
}
