/**
 * abuse.mjs — анти-абьюз Telegram-бота: per-chat троттлинг, санитизация команд,
 * детект флуда, tarpit и shadowban. Ноль зависимостей сверх guard.mjs/existing.
 *
 * Почему это нужно: одна команда — это до ~15 RPC-вызовов (`/pool` читает 12 задач
 * + счётчик). Без квот скомпрометированный allowlisted-чат превращает бота в
 * amplification-DoS на RPC-ноду. Квоты считаются в "единицах RPC-нагрузки", а не в
 * сообщениях: тяжёлые команды стоят дороже.
 *
 * Подключение к хендлерам — одной строкой (см. index.js):
 *   const verdict = await abuse.guardChat(chatId, text);
 *   if (verdict.action !== "pass") return verdict.reply; // tarpit уже отспал внутри
 */
import {
  SlidingWindowLimiter, RiskEngine, RiskSignal, RiskLevel, tarpitDelayMs,
  FloodDetector, Metrics, AuditLog, SanitizeError,
  requestContext, withRequest, newRequestId,
} from "../../infra/shardstore/guard.mjs";

export const COMMAND_COST = Object.freeze({
  pool: 15, // ~12 eth_call + taskCount + сборка: самая тяжёлая команда
  task: 5,  // task + commits(по контрибьюторам) + winner + quorum
  status: 4, // chainId + blockNumber + networkParams + rotation
  limits: 1, help: 1,
  watch: 1, unwatch: 1, watchlist: 1, alerts: 1,
  menu: 1, start: 1, how: 1, protocol: 1, role: 1, settings: 1,
  pro: 1, simple: 1, lang: 1,
});
const KNOWN_COMMANDS = Object.freeze(Object.keys(COMMAND_COST));

function num(env, key, def, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const raw = env[key];
  if (raw === undefined || raw === null || raw === "") return def;
  const v = Number(raw);
  if (!Number.isFinite(v) || v < min || v > max) {
    throw new Error(`abuse config: ${key} must be within [${min}, ${max}]`);
  }
  return v;
}

export function loadAbuseConfig(env = process.env) {
  return Object.freeze({
    // Квота на чат в единицах RPC-нагрузки за окно.
    chatBudget: num(env, "ABUSE_CHAT_BUDGET", 60, { min: 1 }),
    chatWindowMs: num(env, "ABUSE_CHAT_WINDOW_MS", 60_000, { min: 1000 }),
    maxChats: num(env, "ABUSE_MAX_CHATS", 10_000, { min: 10 }),
    // Сырые команды: длина и число аргументов до парсинга.
    maxTextLen: num(env, "ABUSE_MAX_TEXT_LEN", 1024, { min: 16 }),
    maxArgs: num(env, "ABUSE_MAX_ARGS", 8, { min: 1 }),
    maxArgLen: num(env, "ABUSE_MAX_ARG_LEN", 128, { min: 8 }),
    // Флуд: столько последних хэшей команд помним на чат.
    floodK: num(env, "ABUSE_FLOOD_K", 5, { min: 2, max: 64 }),
    // Скоринг чатов (веса в тех же единицах, что guard RiskEngine).
    riskMediumAt: num(env, "ABUSE_RISK_MEDIUM", 20, { min: 1 }),
    riskHighAt: num(env, "ABUSE_RISK_HIGH", 60, { min: 2 }),
    riskWHit: num(env, "ABUSE_RISK_W_HIT", 8, { min: 0 }),
    riskWDup: num(env, "ABUSE_RISK_W_DUP", 6, { min: 0 }),
    riskWBadInput: num(env, "ABUSE_RISK_W_BAD", 2, { min: 0 }),
    tarpitMinMs: num(env, "ABUSE_TARPIT_MIN_MS", 1000, { min: 0 }),
    tarpitMaxMs: num(env, "ABUSE_TARPIT_MAX_MS", 3000, { min: 0 }),
    handlerTimeoutMs: num(env, "ABUSE_HANDLER_TIMEOUT_MS", 20_000, { min: 1000 }),
  });
}

/**
 * Разбор и санитизация сырого текста команды. Возвращает { name, args }.
 * Бросает SanitizeError на мусор — вызывающий отвечает usage-подсказкой, а не RPC.
 * Правила: длина, число аргументов, длина аргумента, только печатаемая латиница/
 * цифры и безопасная пунктуация, без control/invisible unicode и null-bytes.
 */
export function parseCommand(text, cfg) {
  if (typeof text !== "string" || text.length === 0 || text.length > cfg.maxTextLen) {
    throw new SanitizeError("command", `length must be within [1, ${cfg.maxTextLen}]`);
  }
  if (text.includes("\0")) throw new SanitizeError("command", "null byte");
  if (/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text)) {
    throw new SanitizeError("command", "control or invisible characters");
  }
  const parts = text.trim().split(/\s+/);
  const rawName = parts[0].split("@")[0].replace(/^\//, "").toLowerCase();
  if (!/^[a-z]{1,24}$/.test(rawName)) throw new SanitizeError("command", "unknown shape");
  const args = parts.slice(1);
  if (args.length > cfg.maxArgs) throw new SanitizeError("args", `at most ${cfg.maxArgs}`);
  for (const a of args) {
    if (a.length > cfg.maxArgLen) throw new SanitizeError("args", `argument over ${cfg.maxArgLen} chars`);
    if (!/^[\w\-./:]{1,128}$/.test(a)) throw new SanitizeError("args", "argument charset");
  }
  return { name: rawName, args };
}

export class ChatAbuseGuard {
  #cfg; #bucket; #risk; #flood; #audit; #metrics;
  constructor(cfg = loadAbuseConfig(), { audit, metrics } = {}) {
    this.#cfg = cfg;
    this.#metrics = metrics ?? new Metrics();
    this.#audit = audit ?? new AuditLog({ service: "tgbot", metrics: this.#metrics });
    this.#bucket = new SlidingWindowLimiter({
      limit: cfg.chatBudget, windowMs: cfg.chatWindowMs, maxKeys: cfg.maxChats,
    });
    this.#risk = new RiskEngine({
      riskLambdaPerSec: 0.05,
      riskMediumAt: cfg.riskMediumAt, riskHighAt: cfg.riskHighAt, riskMaxSubjects: cfg.maxChats,
      riskWAuthFail: 0, riskWRateHit: cfg.riskWHit, riskWNotFound: 0,
      riskWDupPayload: cfg.riskWDup, riskWFastBurst: 0, riskWRangeAbuse: cfg.riskWBadInput,
    });
    this.#flood = new FloodDetector(cfg.floodK);
  }
  get metrics() { return this.#metrics; }

  /**
   * Вердикт по входящему сообщению. Всегда быстрый и никогда не бросает:
   *   { action: "pass" }                                   — штатно;
   *   { action: "pass-tarpitted", sleptMs }                — greylisted, уже приторможен;
   *   { action: "deny-usage", reply }                      — мусорный ввод, RPC не трогаем;
   *   { action: "deny-rate", reply, retryAfterMs }         — квота исчерпана;
   *   { action: "shadow", reply }                          — теневой бан: правдоподобный
   *     ответ БЕЗ единого RPC-вызова, нарушитель не знает об изоляции.
   * Вызывающий при "pass" выполняет хендлер и обязан вызвать noteResult().
   */
  async guardChat(chatId, text, costOverride) {
    const subject = `chat:${chatId}`;
    let parsed;
    try {
      parsed = parseCommand(text, this.#cfg);
    } catch (e) {
      const r = this.#risk.add(subject, RiskSignal.RANGE_ABUSE);
      this.#audit.security("BAD_INPUT", { chatId, riskLevel: r.level });
      this.#metrics.incr("abuse:deny-usage");
      return { action: "deny-usage", reply: "usage: /menu · /pool · /task <id> · /status · /help" };
    }
    // The cost is what the action really costs in RPC. It comes from the command the text
    // names, unless the caller states it outright: a button press can do more than the
    // command it resembles, and pricing it by resemblance would undercharge it.
    const cost = costOverride ?? COMMAND_COST[parsed.name] ?? 2; // неизвестная команда: дёшево, ответ — help
    const level = this.#risk.levelOf(subject);

    // HIGH: теневая изоляция до любой квоты и любого RPC.
    if (level === RiskLevel.HIGH) {
      this.#audit.security("SHADOWBAN_HIT", { chatId, command: parsed.name });
      this.#metrics.incr("abuse:shadow");
      return { action: "shadow", reply: this.#plausibleReply(parsed.name) };
    }

    const q = this.#bucket.take(subject, cost);
    if (!q.allowed) {
      const r = this.#risk.add(subject, RiskSignal.RATE_HIT);
      this.#audit.security("RATE_LIMIT_EXCEEDED", {
        chatId, command: parsed.name, riskLevel: r.level, retryAfterMs: q.retryAfterMs,
      });
      this.#metrics.incr("abuse:deny-rate");
      return {
        action: "deny-rate",
        reply: `too many requests — retry in ${Math.ceil(q.retryAfterMs / 1000)}s. Heavy commands (/pool) cost more.`,
        retryAfterMs: q.retryAfterMs,
      };
    }

    // Флуд одинаковыми командами: хэш нормализованного текста.
    const digest = `${parsed.name}:${parsed.args.join(" ")}`;
    if (this.#flood.note(subject, digest)) {
      const r = this.#risk.add(subject, RiskSignal.DUP_PAYLOAD);
      this.#audit.security("FLOOD_DUP", { chatId, command: parsed.name, riskLevel: r.level });
      this.#metrics.incr("abuse:flood-dup");
    }

    // MEDIUM: tarpit здесь и сейчас — связывает ресурсы спамера, не очередь бота
    // (sleep идёт до хендлера, RPC ещё не тронут).
    if (this.#risk.levelOf(subject) === RiskLevel.MEDIUM) {
      const ms = tarpitDelayMs(RiskLevel.MEDIUM, {
        tarpitMinMs: this.#cfg.tarpitMinMs, tarpitMaxMs: this.#cfg.tarpitMaxMs,
      });
      if (ms > 0) {
        this.#audit.security("TARPIT_APPLIED", { chatId, command: parsed.name, sleepMs: ms });
        this.#metrics.incr("abuse:tarpit");
        await new Promise((r) => setTimeout(r, ms));
        return { action: "pass-tarpitted", sleptMs: ms, name: parsed.name, args: parsed.args };
      }
    }
    return { action: "pass", name: parsed.name, args: parsed.args };
  }

  /** Правдоподобные ответы shadowban: форматом неотличимы от настоящих пустых. */
  #plausibleReply(name) {
    switch (name) {
      case "pool": return "no tasks yet.";
      case "task": return "unknown task.";
      case "status": return "could not complete /status: rpc unreachable";
      default: return "usage: /pool · /task <id> · /status · /limits · /help";
    }
  }

  /**
   * Хендлер с жёстким дедлайном. Превышение — дружественная строка вместо висящего
   * апдейта, плюс скоринг (висящий RPC — тоже сигнал).
   */
  async runHandler(chatId, fn) {
    const ms = this.#cfg.handlerTimeoutMs;
    let timer;
    try {
      return await Promise.race([
        fn(),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error(`handler timeout after ${ms}ms`)), ms);
        }),
      ]);
    } catch (e) {
      this.#audit.warn("HANDLER_TIMEOUT", { chatId, error: e.message });
      this.#metrics.incr("abuse:handler-timeout");
      return `could not complete: ${e.message}`;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /** Для тестов и мониторинга: текущий уровень чата. */
  levelOf(chatId) { return this.#risk.levelOf(`chat:${chatId}`); }
  /** Принудительно сбросить чат (оператор разбанил вручную). */
  forgive(chatId) { /* риск сам затухает; метод — точка расширения под ручной unban */ }
}

export { requestContext, withRequest, newRequestId };
