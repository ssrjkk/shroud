/**
 * Per-chat watchlist and alert overrides.
 *
 * A chat with an empty watchlist gets every task-scoped alert (the historical
 * behaviour). A chat with a non-empty watchlist gets task-scoped alerts
 * (commit mismatches, disputes) only for watched tasks; key-rotation alerts
 * are global and always follow the alert flags. Per-chat alert flags override
 * the global `.env` flags when set, and inherit them when unset.
 *
 * Persistence is `state/watchlist.json`, written atomically (tmp file +
 * rename) and read corrupt-safe: a half-written or hand-edited file is moved
 * aside to `watchlist.corrupt-<timestamp>.json` and replaced with an empty
 * state, so one bad byte never bricks the bot. Like the alert cursor, a store
 * that cannot persist only costs continuity, never liveness.
 */

import { readFile, rename } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { ROOT } from "./config.js";
import { isTaskId } from "./keyboards.js";
import { writeAtomic } from "./atomic-write.js";

export const WATCHLIST_FILE = resolve(ROOT, "state", "watchlist.json");

/** Bound: a watchlist is a filter, not a database. */
export const MAX_WATCHED_PER_CHAT = 200;

/**
 * Bound on chats holding state. Writers are allowlisted chats only, so this is
 * unreachable in practice — it exists so one misbehaving integration cannot
 * grow the state file without limit. Mirrors the ABUSE_MAX_CHATS default.
 */
export const MAX_CHATS_WITH_STATE = 10_000;

/** Alert flag keys shared with keyboards.js (`a:<key>` toggle payloads). */
export const ALERT_KEYS = ["mm", "disp", "rot", "tre", "ver"];

/** Preference keys a chat may override. `lang`: "ru" | "en" | null (auto).
 * `mode`: "simple" | "pro" | null (simple for onboarded chats, pro otherwise). */
export const PREF_KEYS = ["lang", "mode"];
export const PREF_VALUES = {
  lang: ["ru", "en"],
  mode: ["simple", "pro"],
};

/** Map alert keys to the global config flag names in config.js. */
export function globalFlagFor(key) {
  switch (key) {
    case "mm":
      return "commitMismatch";
    case "disp":
      return "disputes";
    case "rot":
      return "keyRotation";
    case "tre":
      return "treasury";
    case "ver":
      return "verifierRotation";
    default:
      return null;
  }
}

export function emptyState() {
  return { version: 1, chats: {} };
}

function chatEntry(state, chatId) {
  const key = String(chatId);
  if (!state.chats[key]) state.chats[key] = { watched: [], alerts: {} };
  const entry = state.chats[key];
  if (!Array.isArray(entry.watched)) entry.watched = [];
  if (!entry.alerts || typeof entry.alerts !== "object") entry.alerts = {};
  if (!entry.prefs || typeof entry.prefs !== "object") entry.prefs = {};
  return entry;
}

/**
 * Canonical task id: strip leading zeros so "007" and "7" are one filter.
 * Without this, `/watch 007` silently watches nothing — the scanner compares
 * canonical `String(BigInt)` ids and the watchlist would never match.
 */
function canonTaskId(id) {
  const s = String(id);
  if (!isTaskId(s)) return s;
  try {
    return String(BigInt(s));
  } catch {
    return s;
  }
}

/**
 * Normalise a loaded document: drop non-string ids, non-object alerts, and
 * unknown alert keys. A state file survives bot upgrades only if loading is
 * liberal here and strict nowhere else.
 */
export function normaliseState(raw) {
  const state = emptyState();
  const chats = raw?.chats;
  if (!chats || typeof chats !== "object") return state;
  for (const [chatId, entry] of Object.entries(chats)) {
    if (!/^-?\d+$/.test(chatId)) continue;
    if (!entry || typeof entry !== "object") continue;
    const watched = Array.isArray(entry.watched)
      ? [...new Set(entry.watched.filter(isTaskId).map(canonTaskId))].slice(0, MAX_WATCHED_PER_CHAT)
      : [];
    const alerts = {};
    if (entry.alerts && typeof entry.alerts === "object") {
      for (const key of ALERT_KEYS) {
        if (entry.alerts[key] === true || entry.alerts[key] === false) {
          alerts[key] = entry.alerts[key];
        }
      }
    }
    const prefs = {};
    if (entry.prefs && typeof entry.prefs === "object") {
      for (const key of PREF_KEYS) {
        if (PREF_VALUES[key].includes(entry.prefs[key])) prefs[key] = entry.prefs[key];
      }
    }
    state.chats[chatId] = { watched, alerts, prefs };
  }
  return state;
}

/**
 * Load the watchlist, corrupt-safe. Never throws: missing file means empty,
 * corrupt file means backup + empty.
 */
export async function loadWatchlist(file = WATCHLIST_FILE) {
  try {
    const raw = JSON.parse(await readFile(file, "utf8"));
    return normaliseState(raw);
  } catch (err) {
    if (err?.code !== "ENOENT") {
      // Preserve the evidence: the operator may want to know what was lost.
      try {
        await rename(file, `${file}.corrupt-${Date.now()}.json`);
      } catch {
        // Best effort only; the empty state below is what matters.
      }
    }
    if (err?.code !== "ENOENT" && err instanceof SyntaxError) {
      console.warn(`watchlist ${file} is corrupt; backed it up and starting empty`);
    }
    return emptyState();
  }
}

/**
 * Atomic save: temp file + rename, so a crash mid-write never leaves half JSON.
 *
 * The write is serialised per file (see `atomic-write.js`): two chats can be saved at
 * the same time (the dispatcher runs handlers concurrently), and a shared temp path
 * means both writes land in one file - the second rename then publishes a mixture of
 * the two snapshots, which is not valid JSON. The next start reads that as corruption,
 * moves it aside and starts empty, so *every* chat loses its watchlist and its alert
 * overrides over one interleaved save.
 */
export async function saveWatchlist(state, file = WATCHLIST_FILE) {
  try {
    await writeAtomic(file, JSON.stringify(state, null, 2));
  } catch (err) {
    // Persistence loss costs per-chat continuity only; the in-memory state
    // keeps serving for the rest of this run.
    console.warn("could not persist watchlist:", err.message);
  }
}

/** In-memory store for tests and for callers that manage persistence themselves. */
export function createMemoryStore(initial = emptyState()) {
  let state = normaliseState(initial);
  return {
    state: () => state,
    listWatched: (chatId) => [...(state.chats[String(chatId)]?.watched ?? [])],
    addWatch: (chatId, taskId) => addWatch(state, chatId, taskId),
    removeWatch: (chatId, taskId) => removeWatch(state, chatId, taskId),
    setAlert: (chatId, key, value) => setAlertOverride(state, chatId, key, value),
    getPrefs: (chatId) => getPrefs(state, chatId),
    setPref: (chatId, key, value) => setPref(state, chatId, key, value),
    save: async () => {},
  };
}

/** File-backed store for production: mutations persist (best-effort). */
export function createFileStore(file = WATCHLIST_FILE, initial = emptyState()) {
  let state = normaliseState(initial);
  const persist = () => saveWatchlist(state, file);
  return {
    state: () => state,
    replaceState: (next) => {
      state = normaliseState(next);
    },
    listWatched: (chatId) => [...(state.chats[String(chatId)]?.watched ?? [])],
    addWatch: async (chatId, taskId) => {
      const res = addWatch(state, chatId, taskId);
      if (res.added) await persist();
      return res;
    },
    removeWatch: async (chatId, taskId) => {
      const res = removeWatch(state, chatId, taskId);
      if (res.removed) await persist();
      return res;
    },
    setAlert: async (chatId, key, value) => {
      const res = setAlertOverride(state, chatId, key, value);
      await persist();
      return res;
    },
    getPrefs: (chatId) => getPrefs(state, chatId),
    setPref: async (chatId, key, value) => {
      const res = setPref(state, chatId, key, value);
      if (res.ok) await persist();
      return res;
    },
    save: persist,
  };
}

/**
 * Add a task to a chat's watchlist. Pure on `state`; persistence is the
 * store's job. Returns `{ added, reason }` — the caller renders the reason,
 * this never throws on user input.
 */
export function addWatch(state, chatId, taskId) {
  if (!isTaskId(String(taskId))) return { added: false, reason: "task ids are decimal integers. Try /pool." };
  if (!state.chats[String(chatId)] && Object.keys(state.chats).length >= MAX_CHATS_WITH_STATE) {
    return { added: false, reason: "too many chats hold state; contact the operator." };
  }
  const entry = chatEntry(state, chatId);
  const id = canonTaskId(taskId);
  if (entry.watched.includes(id)) return { added: false, reason: `task #${id} is already watched.` };
  if (entry.watched.length >= MAX_WATCHED_PER_CHAT) {
    return { added: false, reason: `watchlist is full (${MAX_WATCHED_PER_CHAT} tasks). Unwatch something first.` };
  }
  entry.watched.push(id);
  return { added: true, reason: `watching task #${id}.` };
}

export function removeWatch(state, chatId, taskId) {
  // Read-only lookup on purpose: removing what was never watched must not
  // create a chat entry as a side effect (unbounded state growth on typos).
  const entry = state.chats[String(chatId)];
  const id = canonTaskId(String(taskId));
  const i = Array.isArray(entry?.watched) ? entry.watched.indexOf(id) : -1;
  if (i === -1) return { removed: false, reason: `task #${id} is not watched.` };
  entry.watched.splice(i, 1);
  return { removed: true, reason: `stopped watching task #${id}.` };
}

/**
 * Set (`true`/`false`) or clear (`null`) a per-chat alert override.
 * Unknown keys are rejected, never stored.
 */
export function setAlertOverride(state, chatId, key, value) {
  if (!ALERT_KEYS.includes(key)) return { ok: false, reason: `unknown alert ${JSON.stringify(String(key))}.` };
  if (value !== true && value !== false && value !== null) {
    return { ok: false, reason: "alert value must be on, off, or default." };
  }
  if (!state.chats[String(chatId)] && Object.keys(state.chats).length >= MAX_CHATS_WITH_STATE) {
    return { ok: false, reason: "too many chats hold state; contact the operator." };
  }
  const entry = chatEntry(state, chatId);
  if (value === null) delete entry.alerts[key];
  else entry.alerts[key] = value;
  return { ok: true, reason: "" };
}

/** Resolve per-chat effective flags: override wins, otherwise global. */
export function effectiveAlerts(global, state, chatId) {
  const override = state.chats[String(chatId)]?.alerts ?? {};
  const pick = (key, globalValue) =>
    override[key] === true || override[key] === false ? override[key] : Boolean(globalValue);
  return {
    mm: pick("mm", global.commitMismatch),
    disp: pick("disp", global.disputes),
    rot: pick("rot", global.keyRotation),
    tre: pick("tre", global.treasury),
    ver: pick("ver", global.verifierRotation),
  };
}

/**
 * Read a chat's prefs. Unknown chats get `{}` — callers apply their own
 * defaults (autodetect language, simple mode for onboarded chats).
 */
export function getPrefs(state, chatId) {
  const prefs = state.chats[String(chatId)]?.prefs;
  return prefs && typeof prefs === "object" ? { ...prefs } : {};
}

/**
 * Set one pref (`lang` | `mode`), validated against PREF_VALUES. Unknown keys
 * and values are rejected, never stored. `null` clears back to default.
 */
export function setPref(state, chatId, key, value) {
  if (!PREF_KEYS.includes(key)) return { ok: false };
  if (value !== null && !PREF_VALUES[key].includes(value)) return { ok: false };
  if (!state.chats[String(chatId)] && Object.keys(state.chats).length >= MAX_CHATS_WITH_STATE) {
    return { ok: false };
  }
  const entry = chatEntry(state, chatId);
  if (value === null) delete entry.prefs[key];
  else entry.prefs[key] = value;
  return { ok: true };
}

/**
 * Whether a task-scoped alert for `taskId` reaches `chatId`.
 *
 * Empty watchlist means "everything" (the historical behaviour); a non-empty
 * one filters to watched tasks. Rotation/global alerts pass `taskId = null`
 * and are never filtered here — flags alone decide those.
 */
export function passesWatchlist(state, chatId, taskId) {
  if (taskId === null || taskId === undefined) return true;
  const watched = state.chats[String(chatId)]?.watched ?? [];
  if (watched.length === 0) return true;
  return watched.includes(String(taskId));
}
