/**
 * Minimal Telegram Bot API client.
 *
 * Only the methods this bot actually uses. No dependency, because the surface
 * needed is `sendMessage`, `getUpdates`, `setMyCommands` and `getMe` — four
 * calls, and wrapping them in a library would add more code than it saves.
 *
 * Long polling is used rather than webhooks on purpose: an ops bot runs on the
 * operator's machine, behind NAT, with no public URL and no TLS certificate.
 * A webhook would need all three.
 */

import { setTimeout as sleep } from "node:timers/promises";

export class TelegramError extends Error {
  constructor(method, description, errorCode) {
    super(`Telegram ${method} failed: ${description}`);
    this.name = "TelegramError";
    this.method = method;
    this.description = description;
    this.errorCode = errorCode;
  }

  /** 429 means "you are going too fast", which is worth retrying. */
  get isRateLimit() {
    return this.errorCode === 429;
  }
}

export class TelegramBot {
  #token;
  #base;
  /** Serialises all writes. Telegram is unhappy with concurrent sends. */
  #writeChain = Promise.resolve();
  /** offsets of updates already handled, per chat id. */
  #seen = new Set();

  constructor(token, { log = console } = {}) {
    if (!token) throw new Error("TelegramBot needs a token");
    this.#token = token;
    this.#base = `https://api.telegram.org/bot${token}`;
    this.log = log;
  }

  async #call(method, payload = {}, { retries = 3 } = {}) {
    const url = `${this.#base}/${method}`;

    for (let attempt = 0; ; attempt++) {
      let response;
      try {
        response = await fetch(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(payload),
        });
      } catch (cause) {
        // Network-level failure: DNS, offline, TLS. Retrying is safe here
        // because every method used by this bot is either a read or a send
        // that Telegram deduplicates by update id.
        if (attempt >= retries) {
          throw new Error(`Telegram ${method}: network failure (${cause.message})`, { cause });
        }
        await sleep(500 * 2 ** attempt);
        continue;
      }

      let body;
      try {
        body = await response.json();
      } catch {
        if (attempt >= retries) {
          throw new Error(`Telegram ${method}: non-JSON response ${response.status}`);
        }
        await sleep(500 * 2 ** attempt);
        continue;
      }

      if (body.ok) return body.result;

      const err = new TelegramError(method, body.description ?? "unknown", body.error_code);
      if (err.isRateLimit && attempt < retries) {
        // `parameters.retry_after` is in seconds and must be respected exactly.
        const wait = body.parameters?.retry_after ?? 1;
        this.log.warn?.(`rate limited on ${method}; waiting ${wait}s`);
        await sleep(wait * 1000);
        continue;
      }
      throw err;
    }
  }

  /** Verify the token works and learn the bot's own username. */
  async getMe() {
    return this.#call("getMe");
  }

  async sendMessage(chatId, text, extra = {}) {
    // Cap at 4096: Telegram silently truncates past that, and a truncated
    // security alert is worse than a shorter one.
    const body = {
      chat_id: chatId,
      text: text.length > 4096 ? `${text.slice(0, 4090)}\n…(truncated)` : text,
      disable_web_page_preview: true,
      ...extra,
    };
    return this.#call("sendMessage", body);
  }

  /** Sends are serialised so a burst of alerts cannot trip the rate limiter. */
  sendQueued(chatId, text, extra = {}) {
    const next = this.#writeChain
      .catch(() => {})
      .then(() => this.sendMessage(chatId, text, extra));
    this.#writeChain = next.catch(() => {});
    return next;
  }

  /** Publish the command list so Telegram shows a menu instead of a blank bar. */
  async setCommands(commands) {
    return this.#call("setMyCommands", { commands });
  }

  /**
   * Long-poll for updates, returning only ones we have not seen.
   *
   * Dedup is kept in memory on purpose: Telegram only guarantees `offset`
   * semantics within a single run, and the alternative — persisting every
   * update id to disk — is not worth it for a bot whose updates are
   * ephemeral status questions.
   */
  async getUpdates(offset, timeoutSeconds = 30) {
    const updates = await this.#call("getUpdates", {
      offset,
      timeout: timeoutSeconds,
      allowed_updates: ["message", "command"],
    });
    const fresh = updates.filter((u) => !this.#seen.has(u.update_id));
    for (const u of updates) this.#seen.add(u.update_id);
    // Bound the dedup set: this bot is long-lived and update ids grow forever.
    if (this.#seen.size > 5000) {
      const keep = new Set(updates.map((u) => u.update_id));
      this.#seen = keep;
    }
    return { updates: fresh, nextOffset: updates.length ? updates.at(-1).update_id + 1 : offset };
  }
}