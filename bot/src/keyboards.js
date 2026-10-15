/**
 * Inline keyboards and the callback protocol.
 *
 * Every button the bot ever shows is built here, from plain data, with no
 * chain access — so the layout (labels, rows, limits) is unit-testable and a
 * redesign never risks an RPC call. Handlers in `index.js` only attach the
 * markup these builders return.
 *
 * Callback data is deliberately terse: Telegram caps it at 64 bytes, and a
 * task id plus a one-letter verb must always fit with room to spare.
 *
 * Protocol (`parseCallback` understands exactly this):
 *   p:{page}     pool page (0-based)
 *   t:{id}       open task {id}
 *   r:{view}     re-render: `s`, `p:{page}` or `t:{id}` (refresh / navigation)
 *   w:{id}       toggle watch on task {id} for this chat
 *   a:{key}       toggle per-chat alert override (`m`, `d`, `k`)
 *
 * Labels stay short and stable: buttons are tapped, not read, and a label
 * that wraps to two lines on a phone makes the whole keyboard feel broken.
 */

export const ALERT_KEYS = { m: "commitMismatch", d: "disputes", k: "keyRotation" };

/**
 * Parse callback data. Returns a plain verb object, or `null` when the data
 * is not ours (forwarded/foreign buttons must never crash the router).
 */
export function parseCallback(data) {
  if (typeof data !== "string") return null;
  let m = /^p:(\d+)$/.exec(data);
  if (m) return { kind: "pool", page: Number(m[1]) };
  m = /^t:(\d+)$/.exec(data);
  if (m) return { kind: "task", id: m[1] };
  m = /^r:(s|p:\d+|t:\d+)$/.exec(data);
  if (m) return { kind: "refresh", view: m[1] };
  m = /^w:(\d+)$/.exec(data);
  if (m) return { kind: "watch", id: m[1] };
  m = /^a:([mdk])$/.exec(data);
  if (m) return { kind: "alerts", key: m[1] };
  return null;
}

const row = (...buttons) => buttons;
const btn = (text, data) => ({ text, callback_data: data });

const fits = (data) => {
  if (data.length > 64) throw new Error(`callback data too long: ${JSON.stringify(data)}`);
  return data;
};

/** Pool screen: one button per task, then page navigation, then refresh. */
export function poolKeyboard({ ids, page, pages }) {
  const rows = [];
  for (let i = 0; i < ids.length; i += 2) {
    rows.push(
      row(
        ...ids
          .slice(i, i + 2)
          .map((t) => btn(`#${t.id} · ${t.label}`, fits(`t:${t.id}`)))
      )
    );
  }
  if (pages > 1) {
    const nav = [];
    if (page > 0) nav.push(btn("‹ prev", fits(`p:${page - 1}`)));
    nav.push(btn(`${page + 1}/${pages}`, fits(`p:${page}`)));
    if (page < pages - 1) nav.push(btn("next ›", fits(`p:${page + 1}`)));
    rows.push(row(...nav));
  }
  rows.push(row(btn("↻ refresh", fits(`r:p:${page}`))));
  return { inline_keyboard: rows };
}

/** Task screen: refresh, neighbours, watch toggle. */
export function taskKeyboard({ id, watched }) {
  const n = Number(id);
  const nav = [btn("↻ refresh", fits(`r:t:${id}`))];
  if (Number.isInteger(n) && n > 1) nav.push(btn("‹ prev", fits(`t:${n - 1}`)));
  if (Number.isInteger(n)) nav.push(btn("next ›", fits(`t:${n + 1}`)));
  return {
    inline_keyboard: [
      row(...nav),
      row(btn(watched ? `★ unwatch #${id}` : `☆ watch #${id}`, fits(`w:${id}`))),
    ],
  };
}

/** Status screen: a single refresh. Everything else is already on screen. */
export function statusKeyboard() {
  return { inline_keyboard: [[btn("↻ refresh", fits("r:s"))]] };
}

/** Per-chat alert toggles. `state` maps m/d/k to true/false/null (null = env). */
export function alertsKeyboard(state) {
  const names = { m: "mismatch", d: "disputes", k: "key rotation" };
  const rows = Object.keys(names).map((key) => {
    const v = state[key];
    const label = v === null || v === undefined ? "env" : v ? "on" : "off";
    return row(btn(`${names[key]}: ${label}`, fits(`a:${key}`)));
  });
  return { inline_keyboard: rows };
}

/** One-tap jump from an alert message into the task screen. */
export function openTaskKeyboard(taskId) {
  return { inline_keyboard: [[btn(`open task #${taskId}`, fits(`t:${taskId}`))]] };
}

/** One-tap jump from a rotation alert into the status screen. */
export function openStatusKeyboard() {
  return { inline_keyboard: [[btn("check status", fits("r:s"))]] };
}

/** Watchlist screen: one tap drops a task. Empty list needs no buttons. */
export function watchlistKeyboard(ids) {
  if (!ids.length) return undefined;
  const rows = [];
  for (let i = 0; i < ids.length; i += 2) {
    rows.push(row(...ids.slice(i, i + 2).map((id) => btn(`✕ #${id}`, fits(`w:${id}`)))));
  }
  return { inline_keyboard: rows };
}
