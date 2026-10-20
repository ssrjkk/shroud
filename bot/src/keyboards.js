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
 *   a:<key>         toggle a per-chat alert flag (mm | disp | rot)
 *
 * Builders return `{ text, reply_markup }`-ready `reply_markup` objects only;
 * rendering stays in format.js so keyboards never interpolate chain data
 * themselves (markup injection would render as broken buttons).
 */

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
  const i = data.indexOf(":");
  if (i === -1) return null;
  const op = data.slice(0, i);
  const arg = data.slice(i + 1);
  if (arg.length === 0 || arg.length > 20) return null;
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
      if (arg !== "mm" && arg !== "disp" && arg !== "rot") return null;
      return { op, arg };
    default:
      return null;
  }
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
    default:
      return 1; // the alert toggles touch local state only
  }
}

const button = (text, callback_data) => ({ text, callback_data });

/**
 * Pool keyboard: up to 4 task buttons per row (short ids stay readable),
 * plus a pager row. `page` is 1-based; `pages` is the total page count.
 */
export function poolKeyboard(ids, page, pages) {
  const rows = [];
  for (let i = 0; i < ids.length; i += 4) {
    rows.push(ids.slice(i, i + 4).map((id) => button(`#${String(id)}`, encodeCallback("t", String(id)))));
  }
  const nav = [];
  if (page > 1) nav.push(button("‹ prev", encodeCallback("p", String(page - 1))));
  if (page < pages) nav.push(button("next ›", encodeCallback("p", String(page + 1))));
  if (nav.length) rows.push(nav);
  return rows.length ? { inline_keyboard: rows } : undefined;
}

/**
 * Task keyboard: refresh, watch/unwatch toggle, and neighbours for
 * prev/next navigation (prev/next may be null at the pool edges).
 */
export function taskKeyboard(taskId, { watched, prevId = null, nextId = null } = {}) {
  const id = String(taskId);
  const rows = [
    [
      button("⟳ refresh", encodeCallback("t", id)),
      watched
        ? button("★ unwatch", encodeCallback("u", id))
        : button("☆ watch", encodeCallback("w", id)),
    ],
  ];
  const nav = [];
  if (prevId !== null) nav.push(button("‹ prev", encodeCallback("t", String(prevId))));
  nav.push(button("pool", encodeCallback("p", "1")));
  if (nextId !== null) nav.push(button("next ›", encodeCallback("t", String(nextId))));
  rows.push(nav);
  return { inline_keyboard: rows };
}

/** Status keyboard: refresh only. Everything else on /status is a snapshot. */
export function statusKeyboard() {
  return { inline_keyboard: [[button("⟳ refresh", "s")]] };
}

const ALERT_LABELS = { mm: "mismatch", disp: "disputes", rot: "rotation" };

/**
 * Alert-override keyboard: one toggle button per flag showing its effective
 * state, plus a refresh back to /status. `effective` maps mm/disp/rot to
 * booleans already resolved against the global config.
 */
export function alertsKeyboard(effective) {
  const rows = [
    Object.entries(ALERT_LABELS).map(([key, label]) =>
      button(`${effective[key] ? "✅" : "❌"} ${label}`, encodeCallback("a", key))
    ),
  ];
  rows.push([button("status", "s")]);
  return { inline_keyboard: rows };
}

/** Deep link from a task-scoped alert back to the task view. */
export function taskLinkKeyboard(taskId) {
  const id = String(taskId);
  return { inline_keyboard: [[button(`view task #${id}`, encodeCallback("t", id))]] };
}

/** Deep link from a rotation alert back to /status. */
export function rotationKeyboard() {
  return { inline_keyboard: [[button("view status", "s")]] };
}
