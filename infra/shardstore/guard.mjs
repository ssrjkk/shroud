/**
 * guard.mjs — охрана периметра ShardStore: антифрод, троттлинг, идемпотентность,
 * санитизация, аудит, Circuit Breaker. Ноль зависимостей (только node builtins).
 *
 * Модель конкурентности Node.js: синхронные секции атомарны относительно event loop,
 * гонки возможны только на границах `await`. Поэтому:
 *  - все мутации счётчиков — в синхронных методах (атомарно по построению);
 *  - дедупликация параллельных одинаковых работ — через singleflight (разделяемый
 *    Promise), а не через "проверь-потом-сделай".
 *
 * Память строго ограничена: у каждого хранилища есть cap + TTL-eviction через sweep().
 * Вызывай startSweeper() один раз на процесс (см. server.mjs).
 *
 * Redis-адаптер: реализуй StoreAdapter (get/set/del/incrWithTtl) — и передай его в
 * конструкторы вместо MemoryStore. Сигнатуры не меняются.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import { keccak256Hex } from "./keccak.mjs";

/* ------------------------------------------------------------------ */
/* 0. Конфиг: ни одного магического числа в движках ниже               */
/* ------------------------------------------------------------------ */

export const DEFAULTS = Object.freeze({
  // Глобальный предохранитель (load shedding): весь сервис.
  globalRps: 800, globalBurst: 1600, globalWindowMs: 1000,
  // Per-IP квоты раздельно: чтение дёшево, запись дорога.
  readRps: 200, readBurst: 400, readWindowMs: 1000,
  writeRps: 20, writeBurst: 40, writeWindowMs: 1000,
  // Penalty box: повторные нарушения подряд → блок base*2^k до max.
  penaltyBaseMs: 5_000, penaltyMaxMs: 300_000, penaltyWindowMs: 60_000, penaltyMaxKeys: 20_000,
  // Первые N нарушений в окне — только счёт (fail-open к легитимным опечаткам токеном);
  // блок начинается с N+1.
  penaltyFreeAttempts: 4,
  // Риск: веса сигналов, скорость затухания, пороги.
  riskLambdaPerSec: 0.05, riskMediumAt: 30, riskHighAt: 80, riskMaxSubjects: 50_000,
  riskWAuthFail: 10, riskWRateHit: 10, riskWNotFound: 1, riskWDupPayload: 3,
  riskWFastBurst: 20, riskWRangeAbuse: 8,
  // Bot-timing: ≥5 интервалов между PUT с коэффициентом вариации ниже — бот.
  riskMinIntervals: 5, riskMaxCv: 0.15,
  // Tarpit для MEDIUM: равномерный sleep. Применяется к запросам, которые уже несут
  // нарушение (401/400/416), а не ко всем подряд — легитимный трафик с greylisted IP
  // не тормозится, атакующий связывает свои ресурсы.
  tarpitMinMs: 1000, tarpitMaxMs: 3000,
  // Идемпотентность.
  idempotencyTtlMs: 10 * 60_000, idempotencyMaxEntries: 5_000, idempotencyKeyMaxLen: 64,
  // Санитизация.
  maxPathLen: 256,
  // Circuit breaker для исходящих/внешних интеграций (диск, апстримы).
  cbFailureThreshold: 5, cbOpenMs: 30_000, cbHalfOpenMax: 1,
  // Очереди и таймауты.
  handlerTimeoutMs: 15_000, requestTimeoutMs: 30_000,
  maxInflightBytes: 512 * 1024 * 1024,
  sweeperIntervalMs: 30_000,
});

function num(env, key, def, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const raw = env[key];
  if (raw === undefined || raw === null || raw === "") return def;
  const v = Number(raw);
  if (!Number.isFinite(v)) throw new ConfigError(`${key} must be a number, got ${JSON.stringify(raw)}`);
  if (v < min || v > max) throw new ConfigError(`${key} must be within [${min}, ${max}], got ${v}`);
  return v;
}

export class ConfigError extends Error {
  constructor(message) { super(`guard config: ${message}`); this.name = "ConfigError"; }
}

/** Типизированный конфиг из env. Бросает ConfigError на первом же невалидном значении. */
export function loadGuardConfig(env = process.env) {
  const cfg = {
    globalRps: num(env, "GUARD_GLOBAL_RPS", DEFAULTS.globalRps, { min: 1 }),
    globalBurst: num(env, "GUARD_GLOBAL_BURST", DEFAULTS.globalBurst, { min: 1 }),
    globalWindowMs: num(env, "GUARD_GLOBAL_WINDOW_MS", DEFAULTS.globalWindowMs, { min: 100 }),
    readRps: num(env, "GUARD_READ_RPS", DEFAULTS.readRps, { min: 1 }),
    readBurst: num(env, "GUARD_READ_BURST", DEFAULTS.readBurst, { min: 1 }),
    readWindowMs: num(env, "GUARD_READ_WINDOW_MS", DEFAULTS.readWindowMs, { min: 100 }),
    writeRps: num(env, "GUARD_WRITE_RPS", DEFAULTS.writeRps, { min: 1 }),
    writeBurst: num(env, "GUARD_WRITE_BURST", DEFAULTS.writeBurst, { min: 1 }),
    writeWindowMs: num(env, "GUARD_WRITE_WINDOW_MS", DEFAULTS.writeWindowMs, { min: 100 }),
    penaltyBaseMs: num(env, "GUARD_PENALTY_BASE_MS", DEFAULTS.penaltyBaseMs, { min: 100 }),
    penaltyMaxMs: num(env, "GUARD_PENALTY_MAX_MS", DEFAULTS.penaltyMaxMs, { min: 1000 }),
    penaltyWindowMs: num(env, "GUARD_PENALTY_WINDOW_MS", DEFAULTS.penaltyWindowMs, { min: 1000 }),
    penaltyMaxKeys: num(env, "GUARD_PENALTY_MAX_KEYS", DEFAULTS.penaltyMaxKeys, { min: 100 }),
    penaltyFreeAttempts: num(env, "GUARD_PENALTY_FREE", DEFAULTS.penaltyFreeAttempts, { min: 0, max: 100 }),
    riskLambdaPerSec: num(env, "GUARD_RISK_LAMBDA", DEFAULTS.riskLambdaPerSec, { min: 0.001, max: 10 }),
    riskMediumAt: num(env, "GUARD_RISK_MEDIUM", DEFAULTS.riskMediumAt, { min: 1 }),
    riskHighAt: num(env, "GUARD_RISK_HIGH", DEFAULTS.riskHighAt, { min: 2 }),
    riskMaxSubjects: num(env, "GUARD_RISK_MAX_SUBJECTS", DEFAULTS.riskMaxSubjects, { min: 100 }),
    riskWAuthFail: num(env, "GUARD_RISK_W_AUTH_FAIL", DEFAULTS.riskWAuthFail, { min: 0 }),
    riskWRateHit: num(env, "GUARD_RISK_W_RATE_HIT", DEFAULTS.riskWRateHit, { min: 0 }),
    riskWNotFound: num(env, "GUARD_RISK_W_NOT_FOUND", DEFAULTS.riskWNotFound, { min: 0 }),
    riskWDupPayload: num(env, "GUARD_RISK_W_DUP", DEFAULTS.riskWDupPayload, { min: 0 }),
    riskWFastBurst: num(env, "GUARD_RISK_W_FAST_BURST", DEFAULTS.riskWFastBurst, { min: 0 }),
    riskWRangeAbuse: num(env, "GUARD_RISK_W_RANGE", DEFAULTS.riskWRangeAbuse, { min: 0 }),
    riskMinIntervals: num(env, "GUARD_RISK_MIN_INTERVALS", DEFAULTS.riskMinIntervals, { min: 3, max: 50 }),
    riskMaxCv: num(env, "GUARD_RISK_MAX_CV", DEFAULTS.riskMaxCv, { min: 0.01, max: 2 }),
    tarpitMinMs: num(env, "GUARD_TARPIT_MIN_MS", DEFAULTS.tarpitMinMs, { min: 0 }),
    tarpitMaxMs: num(env, "GUARD_TARPIT_MAX_MS", DEFAULTS.tarpitMaxMs, { min: 0 }),
    idempotencyTtlMs: num(env, "GUARD_IDEMPOTENCY_TTL_MS", DEFAULTS.idempotencyTtlMs, { min: 1000 }),
    idempotencyMaxEntries: num(env, "GUARD_IDEMPOTENCY_MAX", DEFAULTS.idempotencyMaxEntries, { min: 10 }),
    idempotencyKeyMaxLen: num(env, "GUARD_IDEMPOTENCY_KEY_MAX", DEFAULTS.idempotencyKeyMaxLen, { min: 8, max: 256 }),
    maxPathLen: num(env, "GUARD_MAX_PATH_LEN", DEFAULTS.maxPathLen, { min: 32 }),
    cbFailureThreshold: num(env, "GUARD_CB_FAILURES", DEFAULTS.cbFailureThreshold, { min: 1 }),
    cbOpenMs: num(env, "GUARD_CB_OPEN_MS", DEFAULTS.cbOpenMs, { min: 1000 }),
    cbHalfOpenMax: num(env, "GUARD_CB_HALF_OPEN_MAX", DEFAULTS.cbHalfOpenMax, { min: 1 }),
    handlerTimeoutMs: num(env, "GUARD_HANDLER_TIMEOUT_MS", DEFAULTS.handlerTimeoutMs, { min: 1000 }),
    requestTimeoutMs: num(env, "GUARD_REQUEST_TIMEOUT_MS", DEFAULTS.requestTimeoutMs, { min: 1000 }),
    maxInflightBytes: num(env, "GUARD_MAX_INFLIGHT_BYTES", DEFAULTS.maxInflightBytes, { min: 1024 }),
    sweeperIntervalMs: num(env, "GUARD_SWEEPER_MS", DEFAULTS.sweeperIntervalMs, { min: 1000 }),
  };
  if (cfg.riskHighAt <= cfg.riskMediumAt) throw new ConfigError("GUARD_RISK_HIGH must exceed GUARD_RISK_MEDIUM");
  if (cfg.tarpitMaxMs < cfg.tarpitMinMs) throw new ConfigError("GUARD_TARPIT_MAX_MS must be >= GUARD_TARPIT_MIN_MS");
  if (cfg.penaltyMaxMs < cfg.penaltyBaseMs) throw new ConfigError("GUARD_PENALTY_MAX_MS must be >= GUARD_PENALTY_BASE_MS");
  return Object.freeze(cfg);
}

/* ------------------------------------------------------------------ */
/* 1. StoreAdapter: контракт под будущий Redis. Сейчас — память.        */
/* ------------------------------------------------------------------ */

/**
 * Минимальный контракт распределённого KV с TTL. MemoryStore — реализация по
 * умолчанию; RedisStore должен реализовать те же 4 метода — замена в одном месте
 * (конструкторы движков принимают `store`).
 */
export class MemoryStore {
  #data = new Map(); // key -> { value, expiresAt }
  #now;
  constructor({ now = () => Date.now() } = {}) { this.#now = now; }
  get(key) {
    const e = this.#data.get(key);
    if (!e) return undefined;
    if (e.expiresAt <= this.#now()) { this.#data.delete(key); return undefined; }
    return e.value;
  }
  set(key, value, ttlMs) {
    this.#data.set(key, { value, expiresAt: this.#now() + ttlMs });
    return true;
  }
  del(key) { return this.#data.delete(key); }
  size() { return this.#data.size; }
  /** Фоновая сборка мусора: удаляет протухшее. Возвращает число удалённых. */
  sweep() {
    const now = this.#now();
    let n = 0;
    for (const [k, e] of this.#data) {
      if (e.expiresAt <= now) { this.#data.delete(k); n++; }
    }
    return n;
  }
}

/* ------------------------------------------------------------------ */
/* 2. Sliding-window rate limiter (точные границы окна, не бакет)       */
/* ------------------------------------------------------------------ */

export class SlidingWindowLimiter {
  #hits = new Map(); // key -> number[] (метки в мс, только внутри окна)
  #limit; #windowMs; #now; #maxKeys;
  constructor({ limit, windowMs, maxKeys = 100_000, now = () => Date.now() }) {
    if (!(limit >= 1)) throw new ConfigError("limiter limit must be >= 1");
    if (!(windowMs >= 1)) throw new ConfigError("limiter window must be >= 1ms");
    this.#limit = limit; this.#windowMs = windowMs; this.#now = now; this.#maxKeys = maxKeys;
  }
  /**
   * Атомарно: синхронный метод, race между проверкой и занятием невозможен.
   * cost>1 — ужесточение квоты для greylisted (MEDIUM съедает N токенов за запрос).
   */
  take(key, cost = 1) {
    const now = this.#now();
    let arr = this.#hits.get(key);
    if (!arr) {
      if (this.#hits.size >= this.#maxKeys) {
        const oldest = this.#hits.keys().next();
        if (!oldest.done) this.#hits.delete(oldest.value);
      }
      arr = [];
      this.#hits.set(key, arr);
    }
    while (arr.length > 0 && arr[0] <= now - this.#windowMs) arr.shift();
    if (arr.length + cost > this.#limit) {
      // Fresh key (or fully-expired window) with cost > limit: arr is empty and arr[0]
      // is undefined — without the guard below retryAfterMs is NaN and the caller
      // emits a garbage Retry-After header while denying a client that can never pass.
      const oldestHit = arr.length > 0 ? arr[0] : now;
      return { allowed: false, remaining: 0, retryAfterMs: Math.max(1, oldestHit + this.#windowMs - now) };
    }
    for (let i = 0; i < cost; i++) arr.push(now);
    return { allowed: true, remaining: Math.max(0, this.#limit - arr.length), retryAfterMs: 0 };
  }
  /** Сколько разных ключей сейчас отслеживается (для метрик/лимитов памяти). */
  size() { return this.#hits.size; }
  sweep() {
    const now = this.#now();
    let n = 0;
    for (const [k, arr] of this.#hits) {
      while (arr.length > 0 && arr[0] <= now - this.#windowMs) arr.shift();
      if (arr.length === 0) { this.#hits.delete(k); n++; }
    }
    return n;
  }
}

/* ------------------------------------------------------------------ */
/* 3. PenaltyBox: t*2^k за серии нарушений подряд                       */
/* ------------------------------------------------------------------ */

export class PenaltyBox {
  #state = new Map(); // key -> { streak, blockedUntil, lastAt }
  #baseMs; #maxMs; #windowMs; #maxKeys; #free; #now;
  constructor({ baseMs, maxMs, windowMs, maxKeys = 20_000, freeAttempts = 4, now = () => Date.now() }) {
    this.#baseMs = baseMs; this.#maxMs = maxMs; this.#windowMs = windowMs;
    this.#maxKeys = maxKeys; this.#free = freeAttempts; this.#now = now;
  }
  blockedMs(key, now = this.#now()) {
    const s = this.#state.get(key);
    if (!s) return 0;
    return s.blockedUntil > now ? s.blockedUntil - now : 0;
  }
  /**
   * Зафиксировать нарушение. Серия сбрасывается, если с прошлого прошло > windowMs.
   * Первые freeAttempts нарушений в серии — только счёт, блок с freeAttempts+1,
   * длительностью base*2^(streak-free) до max. Возвращает { streak, blockedMs }.
   */
  violate(key, now = this.#now()) {
    let s = this.#state.get(key);
    if (!s) {
      if (this.#state.size >= this.#maxKeys) {
        const oldest = this.#state.keys().next();
        if (!oldest.done) this.#state.delete(oldest.value);
      }
      s = { streak: 0, blockedUntil: 0, lastAt: 0 };
      this.#state.set(key, s);
    }
    s.streak = now - s.lastAt > this.#windowMs ? 1 : s.streak + 1;
    s.lastAt = now;
    if (s.streak <= this.#free) return { streak: s.streak, blockedMs: 0 };
    // k=0 на первом блокирующем нарушении: base, 2·base, 4·base, … до max.
    const k = Math.min(s.streak - this.#free - 1, 20);
    const blockMs = Math.min(this.#baseMs * 2 ** k, this.#maxMs);
    s.blockedUntil = now + blockMs;
    return { streak: s.streak, blockedMs: blockMs };
  }
  forgive(key) { this.#state.delete(key); }
  sweep(now = this.#now()) {
    let n = 0;
    for (const [k, s] of this.#state) {
      if (s.blockedUntil <= now && now - s.lastAt > this.#windowMs) { this.#state.delete(k); n++; }
    }
    return n;
  }
}

/* ------------------------------------------------------------------ */
/* 4. RiskEngine: decay-скоринг + детектор bot-timing                   */
/* ------------------------------------------------------------------ */

export const RiskSignal = Object.freeze({
  AUTH_FAIL: "auth_fail", RATE_HIT: "rate_hit", NOT_FOUND: "not_found",
  DUP_PAYLOAD: "dup_payload", FAST_BURST: "fast_burst", RANGE_ABUSE: "range_abuse",
});
export const RiskLevel = Object.freeze({ LOW: "low", MEDIUM: "medium", HIGH: "high" });

export class RiskEngine {
  #scores = new Map(); // subject -> { score, updatedAt, hard }
  #intervals = new Map(); // subject+action -> number[] последних меток
  #cfg; #now;
  constructor(cfg, { now = () => Date.now() } = {}) { this.#cfg = cfg; this.#now = now; }
  #weight(signal) {
    switch (signal) {
      case RiskSignal.AUTH_FAIL: return this.#cfg.riskWAuthFail;
      case RiskSignal.RATE_HIT: return this.#cfg.riskWRateHit;
      case RiskSignal.NOT_FOUND: return this.#cfg.riskWNotFound;
      case RiskSignal.DUP_PAYLOAD: return this.#cfg.riskWDupPayload;
      case RiskSignal.FAST_BURST: return this.#cfg.riskWFastBurst;
      case RiskSignal.RANGE_ABUSE: return this.#cfg.riskWRangeAbuse;
      default: return 0;
    }
  }
  /** score(t) = score * e^(-λΔt) + w. Возвращает { score, level }. */
  add(subject, signal, at = this.#now()) {
    let s = this.#scores.get(subject);
    if (!s) {
      if (this.#scores.size >= this.#cfg.riskMaxSubjects) {
        const oldest = this.#scores.keys().next();
        if (!oldest.done) this.#scores.delete(oldest.value);
      }
      s = { score: 0, updatedAt: at, hard: 0 };
      this.#scores.set(subject, s);
    }
    const dt = Math.max(0, (at - s.updatedAt) / 1000);
    s.score = s.score * Math.exp(-this.#cfg.riskLambdaPerSec * dt) + this.#weight(signal);
    s.updatedAt = at;
    // Timing regularity is weak evidence: a fixed upload cadence is what the SDK's own
    // loop produces. Only a real violation counts as a hard signal, and the shadowban
    // needs one (see `hasHardSignal`).
    if (signal !== RiskSignal.FAST_BURST) s.hard = (s.hard ?? 0) + 1;
    return { score: s.score, level: this.#levelOf(s.score) };
  }
  /**
   * Whether this subject has shown a signal other than its timing.
   *
   * The honeypot answers a write with a plausible `201` and stores nothing, so a
   * legitimate client that trips it loses data silently: the contract pins a digest
   * for a shard that was never stored, and the encrypted rows are unrecoverable. A
   * regular cadence is not evidence of that - an automated uploader looks exactly
   * like a bot on the timing signal alone - so the shadowban waits for a hard signal
   * (a failed auth, a rate hit, a duplicate payload, range abuse) to stand on.
   */
  hasHardSignal(subject) {
    const s = this.#scores.get(subject);
    return !!s && (s.hard ?? 0) > 0;
  }
  levelOf(subject, at = this.#now()) {
    const s = this.#scores.get(subject);
    if (!s) return RiskLevel.LOW;
    const dt = Math.max(0, (at - s.updatedAt) / 1000);
    return this.#levelOf(s.score * Math.exp(-this.#cfg.riskLambdaPerSec * dt));
  }
  #levelOf(score) {
    if (score >= this.#cfg.riskHighAt) return RiskLevel.HIGH;
    if (score >= this.#cfg.riskMediumAt) return RiskLevel.MEDIUM;
    return RiskLevel.LOW;
  }
  /**
   * Bot-timing: интервалы между действиями субъекта. Если последних N интервалов
   * имеют коэффициент вариации (σ/μ) ниже порога — это машина с фиксированным слипом,
   * начисляется FAST_BURST. Живые клиенты так не ходят.
   */
  noteInterval(subject, action, at = this.#now()) {
    const key = `${subject}\n${action}`;
    let arr = this.#intervals.get(key);
    if (!arr) {
      // Bounded like #scores: with a spoofable subject source (XFF behind TRUST_PROXY) an
      // unbounded interval map is a memory leak. Same cap, stalest-first eviction.
      if (this.#intervals.size >= this.#cfg.riskMaxSubjects) {
        const oldest = this.#intervals.keys().next();
        if (!oldest.done) this.#intervals.delete(oldest.value);
      }
      arr = []; this.#intervals.set(key, arr);
    }
    const prev = arr.length ? arr[arr.length - 1] : null;
    arr.push(at);
    const keep = this.#cfg.riskMinIntervals + 1;
    if (arr.length > keep) arr.splice(0, arr.length - keep);
    if (prev === null || arr.length < keep) return { anomaly: false };
    const gaps = [];
    for (let i = 1; i < arr.length; i++) gaps.push(arr[i] - arr[i - 1]);
    const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    if (mean <= 0) return { anomaly: true, cv: 0, mean };
    const variance = gaps.reduce((a, g) => a + (g - mean) ** 2, 0) / gaps.length;
    const cv = Math.sqrt(variance) / mean;
    if (cv < this.#cfg.riskMaxCv) {
      const r = this.add(subject, RiskSignal.FAST_BURST, at);
      return { anomaly: true, cv, mean, score: r.score, level: r.level };
    }
    return { anomaly: false, cv, mean };
  }
  sweep(at = this.#now()) {
    // Субъект с затухшим скором ниже 0.01 — мёртвый груз (float-хвосты не живут вечно).
    let n = 0;
    for (const [k, s] of this.#scores) {
      const dt = Math.max(0, (at - s.updatedAt) / 1000);
      if (s.score * Math.exp(-this.#cfg.riskLambdaPerSec * dt) < 0.01) { this.#scores.delete(k); n++; }
    }
    for (const [k, arr] of this.#intervals) {
      if (arr.length === 0 || at - arr[arr.length - 1] > 3_600_000) { this.#intervals.delete(k); n++; }
    }
    return n;
  }
  subjectCount() { return this.#scores.size; }
}

/** Задержка tarpit для MEDIUM: равномерная [min, max]. LOW/HIGH → 0 (HIGH изолируется иначе). */
export function tarpitDelayMs(level, cfg, rand = Math.random) {
  if (level !== RiskLevel.MEDIUM) return 0;
  return Math.floor(cfg.tarpitMinMs + rand() * (cfg.tarpitMaxMs - cfg.tarpitMinMs + 1));
}

/**
 * Honeypot-ответ для HIGH-субъекта на авторизованную запись: правдоподобный 201
 * с корректным cid, но БЕЗ записи в каталог. Атакующий не отличает изоляцию от успеха;
 * последующий GET отдаст 404 ("evicted" — правдоподобно при LRU).
 */
export function honeypotPut(payload) {
  const cid = keccak256Hex(payload);
  return { status: 201, body: { cid, digest: cid } };
}

/* ------------------------------------------------------------------ */
/* 5. IdempotencyStore: singleflight + TTL + LRU-cap (anti-race)        */
/* ------------------------------------------------------------------ */

export class IdempotencyStore {
  #done = new Map(); // key -> { result, bodyHash, expiresAt } (insertion order = LRU)
  #flights = new Map(); // key -> Promise (вычисляется прямо сейчас)
  #ttlMs; #maxEntries; #now;
  constructor({ ttlMs, maxEntries, now = () => Date.now() }) {
    this.#ttlMs = ttlMs; this.#maxEntries = maxEntries; this.#now = now;
  }
  /** Store (result, bodyHash, expiresAt) for a key. bodyHash enables replay verification. */
  #put(key, result, bodyHash) {
    if (this.#done.size >= this.#maxEntries) {
      const oldest = this.#done.keys().next();
      if (!oldest.done) this.#done.delete(oldest.value);
    }
    const entry = { result, bodyHash: bodyHash ?? null, expiresAt: this.#now() + this.#ttlMs };
    this.#done.set(key, entry);
  }
  /** Return the cached body-hash for a key, or null if not found/expired. */
  getBodyHash(key) {
    const hit = this.#done.get(key);
    if (!hit || hit.expiresAt <= this.#now()) { this.#done.delete(key); return null; }
    return hit.bodyHash;
  }
  /**
   * Выполнить fn() не более одного раза на ключ: параллельные вызовы с тем же ключом
   * ждут тот же Promise (singleflight), повтор после завершения — из кэша до TTL.
   * Именно это закрывает гонку "два запроса в одну миллисекунду дважды списывают".
   *
   * bodyHash: if provided, stored alongside the result so replay can verify the body matched.
   */
  async run(key, fn, bodyHash = null) {
    const now = this.#now();
    const hit = this.#done.get(key);
    if (hit) {
      if (hit.expiresAt > now) {
        this.#done.delete(key); this.#done.set(key, hit); // LRU-touch
        return { result: hit.result, replayed: true };
      }
      this.#done.delete(key);
    }
    let flight = this.#flights.get(key);
    if (!flight) {
      // Bound in-flight singleflight entries: distinct keys with slow bodies would otherwise
      // grow #flights without limit. Past the cap the call runs untracked (correct, just not
      // deduplicated) instead of evicting somebody else's in-flight work.
      if (this.#flights.size >= this.#maxEntries) {
        const result = await fn();
        return { result, replayed: false };
      }
      flight = (async () => {
        try {
          const result = await fn();
          // Adopt the worker's own bodyHash when the caller did not pass one: doPut
          // returns { status, body, bodyHash }, and dropping it here is what made
          // getBodyHash always null — same-key/different-body replays then looked
          // identical to legitimate replays and got a silent 201 instead of 422.
          this.#put(key, result, bodyHash ?? result?.bodyHash ?? null);
          return { result, replayed: false };
        } finally {
          this.#flights.delete(key);
        }
      })();
      this.#flights.set(key, flight);
    }
    return flight;
  }
  /** Drop one cached result (e.g. after DELETE so a stale replay cannot resurrect a ghost). */
  forget(key) {
    return this.#done.delete(key);
  }
  sweep(now = this.#now()) {
    let n = 0;
    for (const [k, e] of this.#done) {
      if (e.expiresAt <= now) { this.#done.delete(k); n++; }
    }
    return n;
  }
  size() { return this.#done.size + this.#flights.size; }
}

/* ------------------------------------------------------------------ */
/* 6. Sanitizer: всё textual проверяется ДО тяжёлой работы              */
/* ------------------------------------------------------------------ */

const CID_RE = /^0x[0-9a-f]{64}$/;
const PRINTABLE_ASCII = /^[\x21-\x7e]+$/;
const IDEMPOTENCY_KEY_RE = /^[A-Za-z0-9/_+=-]+$/;
// Все регэкспы линейные, без вложенных квантификаторов — ReDoS невозможен по построению.

export class SanitizeError extends Error {
  constructor(field, reason) {
    super(`invalid ${field}: ${reason}`);
    this.name = "SanitizeError"; this.field = field;
  }
}

export function assertCid(cid) {
  if (typeof cid !== "string" || !CID_RE.test(cid)) throw new SanitizeError("cid", "must be 0x + 64 lowercase hex");
  return cid;
}
export function assertPath(pathname, maxLen) {
  if (typeof pathname !== "string" || pathname.length === 0 || pathname.length > maxLen) {
    throw new SanitizeError("path", `length must be within [1, ${maxLen}]`);
  }
  if (pathname.includes("\0")) throw new SanitizeError("path", "null byte");
  // WHATWG URL нормализует буквальные `..`, но не %2e — декодируем один раз и проверяем.
  let decoded = pathname;
  try { decoded = decodeURIComponent(pathname); } catch { throw new SanitizeError("path", "bad percent-encoding"); }
  if (decoded.includes("\0")) throw new SanitizeError("path", "null byte after decode");
  if (/(^|\/)(\.\.?)(\/|$)/.test(decoded)) throw new SanitizeError("path", "dot-segment");
  // Невидимый Unicode (bidi, zero-width): в путях/ключах им делать нечего.
  if (/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/.test(decoded)) {
    throw new SanitizeError("path", "invisible unicode");
  }
  return pathname;
}
/** Single-range `bytes=a-b` or suffix `bytes=-N`. null (нет), окно или бросок (→416/400). */
export function parseRangeHeader(value, maxBytes) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" || value.length > 64) throw new SanitizeError("range", "malformed");
  if (value.includes(",")) throw new SanitizeError("range", "multi-range not supported");
  const m = /^bytes=(\d*)-(\d*)$/.exec(value.trim());
  if (!m) throw new SanitizeError("range", "malformed");
  if (m[1] === "") {
    // Суффикс: последние N байт. N=0 — пустое окно, невыполнимо (→416 у вызывающего).
    if (m[2] === "") throw new SanitizeError("range", "empty suffix");
    const n = Number(m[2]);
    if (!Number.isSafeInteger(n) || n < 0) throw new SanitizeError("range", "bad suffix");
    if (n === 0) throw new SanitizeError("range", "empty suffix");
    if (n > maxBytes) throw new SanitizeError("range", "window exceeds object cap");
    return { suffix: n };
  }
  const start = Number(m[1]);
  const end = m[2] === "" ? start + maxBytes - 1 : Number(m[2]);
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start) {
    throw new SanitizeError("range", "bad bounds");
  }
  if (end - start + 1 > maxBytes) throw new SanitizeError("range", "window exceeds object cap");
  return { start, end };
}
export function assertDeclaredLength(value, cap) {
  if (value === undefined || value === null || value === "") return null;
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) throw new SanitizeError("content-length", "not a non-negative integer");
  if (n > cap) throw new SanitizeError("content-length", `declares ${n} bytes over the ${cap} cap`);
  return n;
}
export function assertBearerToken(header) {
  if (typeof header !== "string" || !header.startsWith("Bearer ")) throw new SanitizeError("authorization", "missing scheme");
  const token = header.slice("Bearer ".length);
  if (token.length === 0 || token.length > 512 || !PRINTABLE_ASCII.test(token)) {
    throw new SanitizeError("authorization", "malformed credential");
  }
  return token;
}
export function assertIdempotencyKey(value, maxLen) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" || value.length > maxLen || !IDEMPOTENCY_KEY_RE.test(value)) {
    throw new SanitizeError("idempotency-key", `must match [A-Za-z0-9/_+=-]{1,${maxLen}}`);
  }
  return value;
}
/** Детектор флуда одинаковыми пейлоадами: последние K хэшей субъекта (кольцевой буфер). */
export class FloodDetector {
  #recent = new Map(); // subject -> string[] (cap K, shift)
  #k;
  constructor(k = 8) { this.#k = k; }
  /** true, если такой хэш уже видели в окне (дубль). Всегда записывает. */
  note(subject, hash) {
    let arr = this.#recent.get(subject);
    if (!arr) { arr = []; this.#recent.set(subject, arr); }
    const dup = arr.includes(hash);
    arr.push(hash);
    if (arr.length > this.#k) arr.splice(0, arr.length - this.#k);
    if (this.#recent.size > 50_000) {
      const oldest = this.#recent.keys().next();
      if (!oldest.done) this.#recent.delete(oldest.value);
    }
    return dup;
  }
}

/* ------------------------------------------------------------------ */
/* 7. Observability: request_id, маскирование, метрики                 */
/* ------------------------------------------------------------------ */

export const requestContext = new AsyncLocalStorage();

export function newRequestId() { return randomUUID(); }
export function withRequest(id, fn) { return requestContext.run({ requestId: id ?? newRequestId() }, fn); }
export function currentRequestId() { return requestContext.getStore()?.requestId ?? null; }

const SECRET_KEY_RE = /(authorization|cookie|set-cookie|token|api[-_]?key|secret|password|passwd|private[-_]?key|seed|mnemonic|bearer)/i;

export function maskSecrets(value, seen = new Set()) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map((v) => maskSecrets(v, seen));
  if (value && typeof value === "object") {
    if (seen.has(value)) return "[circular]";
    seen.add(value);
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SECRET_KEY_RE.test(k) ? "***" : maskSecrets(v, seen);
    }
    return out;
  }
  return value;
}

export class Metrics {
  #counters = new Map();
  #timings = new Map(); // name -> { count, sum, max }
  incr(name, by = 1) { this.#counters.set(name, (this.#counters.get(name) ?? 0) + by); }
  observe(name, ms) {
    let t = this.#timings.get(name);
    if (!t) { t = { count: 0, sum: 0, max: 0 }; this.#timings.set(name, t); }
    t.count++; t.sum += ms; if (ms > t.max) t.max = ms;
  }
  snapshot() {
    const timings = {};
    for (const [k, t] of this.#timings) timings[k] = { count: t.count, avgMs: t.count ? t.sum / t.count : 0, maxMs: t.max };
    return { counters: Object.fromEntries(this.#counters), timings };
  }
}

export class AuditLog {
  #sink; #service; #metrics;
  constructor({ sink = process.stderr, service = "guard", metrics = new Metrics() } = {}) {
    this.#sink = sink; this.#service = service; this.#metrics = metrics;
  }
  get metrics() { return this.#metrics; }
  #write(level, type, fields = {}) {
    // Явные параметры побеждают поля: fields.level/type никогда не должны маскировать
    // severity события (иначе MEDIUM-спам выглядел бы как level:"medium", а не security).
    const line = JSON.stringify({
      ...maskSecrets(fields),
      ts: new Date().toISOString(), level, type, service: this.#service,
      requestId: currentRequestId(),
    });
    this.#sink.write(line + "\n");
  }
  info(type, fields) { this.#write("info", type, fields); }
  warn(type, fields) { this.#write("warn", type, fields); this.#metrics.incr(`warn:${type}`); }
  security(type, fields) { this.#write("security", type, fields); this.#metrics.incr(`security:${type}`); }
  critical(type, fields) { this.#write("critical", type, fields); this.#metrics.incr(`critical:${type}`); }
}

/* ------------------------------------------------------------------ */
/* 8. Fail-open обёртка + Circuit Breaker                              */
/* ------------------------------------------------------------------ */

/**
 * Fail-open: охрана никогда не роняет сервис. Любой сбой внутри fn — CRITICAL в
 * аудит и синхронный fallback. Возвращает { ok, value }.
 */
export async function withResilience(name, fn, { fallback, audit }) {
  try {
    return { ok: true, value: await fn() };
  } catch (e) {
    audit?.critical("GUARD_FALLBACK", { guard: name, error: e?.message ?? String(e) });
    return { ok: false, value: typeof fallback === "function" ? await fallback() : fallback };
  }
}

export const CbState = Object.freeze({ CLOSED: "closed", OPEN: "open", HALF_OPEN: "half-open" });

export class CircuitBreaker {
  #state = CbState.CLOSED; #failures = 0; #openedAt = 0; #probes = 0;
  #threshold; #openMs; #halfOpenMax; #now; #onState;
  constructor({ failureThreshold, openMs, halfOpenMax = 1, now = () => Date.now(), onState } = {}) {
    this.#threshold = failureThreshold; this.#openMs = openMs;
    this.#halfOpenMax = halfOpenMax; this.#now = now; this.#onState = onState;
  }
  get state() {
    if (this.#state === CbState.OPEN && this.#now() - this.#openedAt >= this.#openMs) {
      this.#set(CbState.HALF_OPEN); this.#probes = 0;
    }
    return this.#state;
  }
  #set(s) { this.#state = s; this.#onState?.(s); }
  /**
   * Выполнить fn. В OPEN — сразу fallback (или бросок, если его нет): никакого
   * ожидания таймаута мёртвого апстрима. В HALF_OPEN — не более halfOpenMax проб
   * одновременно, остальные — в fallback.
   */
  async exec(fn, { fallback } = {}) {
    const st = this.state;
    if (st === CbState.OPEN) {
      if (fallback === undefined) throw new Error("circuit open and no fallback");
      return fallback();
    }
    if (st === CbState.HALF_OPEN) {
      if (this.#probes >= this.#halfOpenMax) {
        if (fallback === undefined) throw new Error("circuit half-open probe in flight and no fallback");
        return fallback();
      }
      this.#probes++;
    }
    try {
      const v = await fn();
      this.#failures = 0; this.#probes = 0;
      if (this.#state !== CbState.CLOSED) this.#set(CbState.CLOSED);
      return v;
    } catch (e) {
      this.#failures++;
      if (this.#state === CbState.HALF_OPEN || this.#failures >= this.#threshold) {
        this.#openedAt = this.#now(); this.#probes = 0; this.#set(CbState.OPEN);
      }
      if (fallback === undefined) throw e;
      return fallback();
    }
  }
}

/* ------------------------------------------------------------------ */
/* 9. Фоновый sweeper: одна точка сборки мусора на процесс              */
/* ------------------------------------------------------------------ */

export function startSweeper(sweepables, intervalMs) {
  const timer = setInterval(() => {
    for (const s of sweepables) {
      try { s.sweep?.(); } catch { /* сборщик мусора не имеет права падать */ }
    }
  }, intervalMs);
  if (typeof timer.unref === "function") timer.unref();
  return () => clearInterval(timer);
}
