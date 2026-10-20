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

/** Telegram silently truncates past 4096; a truncated security alert is worse
 * than a shorter one, so the cut is explicit and the result always fits. */
export const TELEGRAM_TEXT_LIMIT = 4096;
const TRUNC_SUFFIX = "\n…(truncated)";

/**
 * How much longer than the long-poll window the request deadline is.
 *
 * Telegram holds a `getUpdates` request open until it has an update or the
 * window ends, so the deadline has to clear the window plus the round trip -
 * otherwise the client aborts its own poll (see `getUpdates`).
 */
const LONG_POLL_SLACK_MS = 10_000;

export function truncateText(text) {
  const s = String(text);
  if (s.length <= TELEGRAM_TEXT_LIMIT) return s;
  return `${s.slice(0, TELEGRAM_TEXT_LIMIT - TRUNC_SUFFIX.length)}${TRUNC_SUFFIX}`;
}

export class TelegramBot {
  #token;
  #base;
  /** Serialises all writes. Telegram is unhappy with concurrent sends. */
  #writeChain = Promise.resolve();
  /** In-flight + queued sends. Bounded: an alert storm must not grow memory without limit. */
  #queued = 0;
  #maxQueued;
  /** Enqueue timestamps parallel to #queued: the oldest bounds the queue's stall. */
  #waitSince = [];
  #timeoutMs;
  /** Alerts dropped by the queue cap since boot. Polled by /status operators, never reset. */
  droppedSends = 0;
  /** offsets of updates already handled, per chat id. */
  #seen = new Set();

  constructor(token, { log = console, maxQueued = 100, timeoutMs = 15_000 } = {}) {
    if (!token) throw new Error("TelegramBot needs a token");
    if (!Number.isInteger(maxQueued) || maxQueued < 1) {
      throw new Error("TelegramBot maxQueued must be a positive integer");
    }
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1) {
      throw new Error("TelegramBot timeoutMs must be a positive integer");
    }
    this.#token = token;
    this.#base = `https://api.telegram.org/bot${token}`;
    this.#maxQueued = maxQueued;
    this.#timeoutMs = timeoutMs;
    this.log = log;
  }

  /**
   * Longest time any accepted send has waited unsent, in ms (0 when idle).
   *
   * Sends are serialised, so one stalled Telegram call delays everything
   * behind it; the counter alone cannot show that. /status surfaces this when
   * it passes the warning threshold, same as shed sends.
   */
  maxQueueWaitMs() {
    if (!this.#waitSince.length) return 0;
    return Date.now() - this.#waitSince[0];
  }

  async #call(method, payload = {}, { retries = 3, timeoutMs = this.#timeoutMs } = {}) {
    const url = `${this.#base}/${method}`;

    for (let attempt = 0; ; attempt++) {
      let response;
      // A hung Telegram must not wedge the serialised write chain forever:
      // abort this attempt and fail fast (no retry — retrying a stall just
      // re-stalls the queue behind it).
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), timeoutMs);
      try {
        response = await fetch(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(payload),
          signal: ac.signal,
        });
      } catch (cause) {
        if (cause?.name === "AbortError") {
          throw new Error(`Telegram ${method}: timed out after ${timeoutMs}ms`);
        }
        // Network-level failure: DNS, offline, TLS. Retrying is safe here
        // because every method used by this bot is either a read or a send
        // that Telegram deduplicates by update id.
        if (attempt >= retries) {
          throw new Error(`Telegram ${method}: network failure (${cause.message})`, { cause });
        }
        await sleep(500 * 2 ** attempt);
        continue;
      } finally {
        clearTimeout(timer);
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
      text: truncateText(text),
      disable_web_page_preview: true,
      ...extra,
    };
    return this.#call("sendMessage", body);
  }

  /**
   * Sends are serialised so a burst of alerts cannot trip the rate limiter, and
   * bounded so a burst of alerts cannot grow memory without limit: past the cap
   * the oldest unsent alert is shed in favour of the newest (an ops channel wants
   * the latest state, not a backlog), counted in `droppedSends` and logged.
   * Dropping resolves `{ dropped: true }` rather than rejecting, so broadcast loops
   * (`Promise.all` over chats) are unaffected.
   */
  sendQueued(chatId, text, extra = {}) {
    if (this.#queued >= this.#maxQueued) {
      this.droppedSends++;
      this.log.warn?.(`send queue full (${this.#queued}/${this.#maxQueued}); dropping alert for ${chatId}`);
      return Promise.resolve({ dropped: true });
    }
    this.#queued++;
    this.#waitSince.push(Date.now());
    const next = this.#writeChain
      .catch(() => {})
      .then(() => this.sendMessage(chatId, text, extra))
      .finally(() => {
        this.#queued--;
        this.#waitSince.shift();
      });
    this.#writeChain = next.catch(() => {});
    return next;
  }

  /** Publish the command list so Telegram shows a menu instead of a blank bar. */
  async setCommands(commands) {
    return this.#call("setMyCommands", { commands });
  }

  /**
   * Acknowledge a callback query, dismissing the client's loading spinner.
   * `text` shows as a transient toast; kept short because Telegram truncates
   * it at ~200 characters. Best-effort: a failed ack must not fail the action
   * the button already triggered.
   */
  async answerCallbackQuery(callbackQueryId, text = "") {
    try {
      return await this.#call("answerCallbackQuery", {
        callback_query_id: callbackQueryId,
        ...(text ? { text: text.slice(0, 190) } : {}),
      });
    } catch (err) {
      this.log.warn?.(`answerCallbackQuery failed: ${err.message}`);
      return null;
    }
  }

  /**
   * In-place edit of a message the bot sent (keyboard refreshes, toggles).
   * Falls back to `null` when Telegram rejects the edit (message too old,
   * content identical) so the caller can send a fresh message instead.
   */
  async editMessage(chatId, messageId, text, extra = {}) {
    try {
      return await this.#call("editMessageText", {
        chat_id: chatId,
        message_id: messageId,
        text: truncateText(text),
        disable_web_page_preview: true,
        ...extra,
      });
    } catch (err) {
      this.log.warn?.(`editMessage ${chatId}:${messageId} failed: ${err.message}`);
      return null;
    }
  }

  /**
   * Long-poll for updates, returning only ones we have not seen.
   *
   * Dedup is kept in memory on purpose: Telegram only guarantees `offset`
   * semantics within a single run, and the alternative — persisting every
   * update id to disk — is not worth it for a bot whose updates are
   * ephemeral status questions. `callback_query` is subscribed alongside
   * `message` so inline-keyboard presses arrive on the same poll loop.
   */
  async getUpdates(offset, timeoutSeconds = 30) {
    // A long poll holds the connection open for `timeoutSeconds` and answers only
    // when an update arrives. The request deadline has to be *longer* than that
    // window: with the ordinary deadline (15s) shorter than the poll (30s), the
    // client aborted its own poll before Telegram answered, so every idle poll
    // ended in a timeout error and a two-second sleep. Updates still arrived -
    // Telegram answers as soon as it has one - but the bot was permanently
    // reporting a failure that was its own doing.
    const deadlineMs = Math.max(this.#timeoutMs, timeoutSeconds * 1000 + LONG_POLL_SLACK_MS);
    const updates = await this.#call(
      "getUpdates",
      {
        offset,
        timeout: timeoutSeconds,
        allowed_updates: ["message", "callback_query"],
      },
      { timeoutMs: deadlineMs }
    );
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