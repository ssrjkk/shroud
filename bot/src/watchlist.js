/**
 * Per-chat operator state: watched tasks and alert overrides.
 *
 * Two different needs live here, and both are per chat rather than global:
 *
 * - a watchlist: chats that name tasks only want task-scoped alerts about
 *   those tasks (a chat watching nothing gets everything, exactly as before);
 * - alert overrides: a chat can force one alert family on or off regardless
 *   of the `.env` defaults (`null` means "follow the env").
 *
 * Persisted as one JSON file with an atomic write (tmp + rename), next to
 * the alert cursor in `state/`. A corrupt or missing file is an empty store,
 * never a crash: losing preferences is annoying, refusing to start is worse.
 */

import { readFile, writeFile, mkdir, rename } from "node:fs/promises";
import { dirname, resolve } from "node:path";

export const ALERT_FAMILIES = ["commitMismatch", "disputes", "keyRotation"];

function blankChat() {
  return { watched: [], alerts: { commitMismatch: null, disputes: null, keyRotation: null } };
}

function sanitize(raw) {
  const chats = {};
  if (raw && typeof raw === "object" && raw.chats && typeof raw.chats === "object") {
    for (const [chatId, c] of Object.entries(raw.chats)) {
      if (!/^-?\d+$/.test(chatId)) continue;
      const watched = Array.isArray(c?.watched)
        ? [...new Set(c.watched.map(String).filter((v) => /^\d+$/.test(v)))]
        : [];
      const alerts = {};
      for (const f of ALERT_FAMILIES) {
        const v = c?.alerts?.[f];
        alerts[f] = v === true || v === false ? v : null;
      }
      chats[chatId] = { watched, alerts };
    }
  }
  return { chats };
}

export class WatchStore {
  #file;
  #state = { chats: {} };

  constructor(file) {
    this.#file = file;
  }

  static async open(dir) {
    const store = new WatchStore(resolve(dir, "watchlist.json"));
    await store.#load();
    return store;
  }

  async #load() {
    try {
      this.#state = sanitize(JSON.parse(await readFile(this.#file, "utf8")));
    } catch {
      this.#state = { chats: {} };
    }
  }

  async #save() {
    try {
      await mkdir(dirname(this.#file), { recursive: true });
      const tmp = `${this.#file}.${process.pid}.tmp`;
      await writeFile(tmp, JSON.stringify(this.#state, null, 2));
      await rename(tmp, this.#file);
    } catch {
      // Preferences are best-effort: the bot must keep answering even when
      // the disk is read-only.
    }
  }

  #chat(chatId) {
    const key = String(chatId);
    if (!this.#state.chats[key]) this.#state.chats[key] = blankChat();
    return this.#state.chats[key];
  }

  /** Ids this chat watches, as strings. */
  watched(chatId) {
    return [...(this.#state.chats[String(chatId)]?.watched ?? [])];
  }

  /** Toggle-watch; returns true when the task is watched afterwards. */
  async toggleWatch(chatId, taskId) {
    const id = String(taskId);
    if (!/^\d+$/.test(id)) throw new Error("task ids are decimal integers");
    const chat = this.#chat(chatId);
    const at = chat.watched.indexOf(id);
    if (at === -1) chat.watched.push(id);
    else chat.watched.splice(at, 1);
    chat.watched.sort((a, b) => Number(a) - Number(b));
    await this.#save();
    return at === -1;
  }

  /** Per-chat alert override; `value` true/false/null(null = follow env). */
  async setAlert(chatId, family, value) {
    if (!ALERT_FAMILIES.includes(family)) throw new Error(`unknown alert family ${family}`);
    if (value !== true && value !== false && value !== null) {
      throw new Error("alert value must be true, false or null");
    }
    this.#chat(chatId).alerts[family] = value;
    await this.#save();
  }

  /** Effective on/off for one family: chat override wins, env is the default. */
  effective(chatId, family, envDefault) {
    const v = this.#state.chats[String(chatId)]?.alerts?.[family];
    return v === null || v === undefined ? Boolean(envDefault) : v;
  }

  snapshot(chatId) {
    const c = this.#state.chats[String(chatId)];
    return c
      ? { watched: [...c.watched], alerts: { ...c.alerts } }
      : { watched: [], alerts: { commitMismatch: null, disputes: null, keyRotation: null } };
  }
}

/**
 * Which chats should receive an alert.
 *
 * - key-rotation alerts go to every chat (subject to their own override);
 * - task-scoped alerts go to chats with an empty watchlist (the old
 *   broadcast behaviour) plus chats watching that task.
 * Each family is additionally gated by its per-chat override in `decide`.
 */
export function targetChats({ allowedIds, store, env, taskId, families }) {
  const out = [];
  for (const id of allowedIds) {
    if (!families.every((f) => store.effective(id, f, env[f]))) continue;
    const watched = store.watched(id);
    if (taskId === null || taskId === undefined) {
      out.push(id);
    } else if (watched.length === 0 || watched.includes(String(taskId))) {
      out.push(id);
    }
  }
  return out;
}
