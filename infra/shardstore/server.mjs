/**
 * ShardStore - content-addressed DA for Shroud, hardened.
 *
 * API (без изменений, обратно совместимо):
 *   PUT /objects            body = raw bytes      -> { cid, digest } (201)
 *   GET /objects/:cid                             -> raw bytes (200/404/400)
 *   GET /objects/:cid  Range: bytes=a-b          -> 206 Partial Content (416)
 *   DELETE /objects/:cid                          -> { deleted: true } (200/404)
 *   GET /healthz                                  -> { ok, objects, ... } (расширено метриками)
 *
 * Охрана периметра (см. guard.mjs) — порядок на каждый запрос:
 *   request_id → global load-shed (503) → penalty box (429) → per-IP quota,
 *   read/write раздельно (429) → санитизация пути → auth (401 + скоринг) →
 *   risk-уровень: HIGH+авторизованная запись → honeypot-изоляция (правдоподобный 201
 *   без записи); нарушение + MEDIUM → tarpit → бизнес-логика с таймаутом.
 *
 * Отказоустойчивость: сокет-таймауты, глобальный бюджет in-flight байт, атомарная
 * запись (tmp+rename — битых объектов не бывает), Circuit Breaker на persist
 * (fallback: memory-only + degraded + DLQ), graceful shutdown с дедлайном.
 * Охрана fail-open: сбой движка охраны = CRITICAL в аудит + локальный пропуск,
 * никогда 500 из-за guard.
 *
 * Run: `node server.mjs`
 *   (PORT=8080, DATA_DIR=./data, MAX_OBJECT_BYTES=67108864, MAX_OBJECTS=4096,
 *    MAX_TOTAL_BYTES=1073741824, SHUTDOWN_TIMEOUT_MS=10000, DLQ_DIR=<DATA_DIR>/dlq, TRUST_PROXY=0, GUARD_* — см. guard.mjs)
 */
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { timingSafeEqual, randomBytes } from "node:crypto";
import { mkdir, writeFile, readFile, stat, unlink, readdir, rename } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import {
  loadGuardConfig, ConfigError, SlidingWindowLimiter, PenaltyBox, RiskEngine, RiskSignal, RiskLevel,
  tarpitDelayMs, honeypotPut, IdempotencyStore, FloodDetector, SanitizeError,
  assertCid, assertPath, parseRangeHeader, assertDeclaredLength, assertBearerToken,
  assertIdempotencyKey, Metrics, AuditLog, CircuitBreaker, withResilience,
  requestContext, newRequestId, currentRequestId, startSweeper,
} from "./guard.mjs";
import { keccak256Hex } from "./keccak.mjs";

const PORT = Number(process.env.PORT ?? 8080);
const HOST = process.env.HOST ?? "127.0.0.1";
const DATA_DIR = process.env.DATA_DIR || null;
const MAX_OBJECT_BYTES = Number(process.env.MAX_OBJECT_BYTES ?? 64 * 1024 * 1024);
if (!Number.isSafeInteger(MAX_OBJECT_BYTES) || MAX_OBJECT_BYTES < 1) {
  console.error("shardstore: MAX_OBJECT_BYTES must be a positive integer number of bytes");
  process.exit(1);
}
const MAX_OBJECTS = Number(process.env.MAX_OBJECTS ?? 4096);
if (!Number.isSafeInteger(MAX_OBJECTS) || MAX_OBJECTS < 1) {
  console.error("shardstore: MAX_OBJECTS must be a positive integer");
  process.exit(1);
}
/**
 * Cap on all catalogued bytes (count cap is secondary). 4096 objects × 64 MiB
 * would otherwise pin up to 256 GiB of RAM — and `rebuildIndex` would load it
 * all at startup. One GiB holds ~16k average shards with headroom; per-object
 * and in-flight caps still apply underneath.
 */
const MAX_TOTAL_BYTES = Number(process.env.MAX_TOTAL_BYTES ?? 1024 * 1024 * 1024);
if (!Number.isFinite(MAX_TOTAL_BYTES) || MAX_TOTAL_BYTES < 1) {
  console.error("shardstore: MAX_TOTAL_BYTES must be a positive number of bytes");
  process.exit(1);
}
const AUTH_TOKEN = process.env.AUTH_TOKEN || null;
const TLS_CERT = process.env.TLS_CERT || null;
const TLS_KEY = process.env.TLS_KEY || null;
const SHUTDOWN_TIMEOUT_MS = Number(process.env.SHUTDOWN_TIMEOUT_MS ?? 10_000);
const DLQ_DIR = process.env.DLQ_DIR || (DATA_DIR ? join(DATA_DIR, "..", "dlq") : null);
const TRUST_PROXY = process.env.TRUST_PROXY === "1";

let guard;
try {
  guard = loadGuardConfig(process.env);
} catch (e) {
  console.error(`shardstore: ${e.message}`);
  process.exit(1);
}

if ((TLS_CERT === null) !== (TLS_KEY === null)) {
  console.error("shardstore: TLS_CERT and TLS_KEY must be set together");
  process.exit(1);
}

const CID_RE = /^0x[0-9a-f]{64}$/;
const FILE_RE = /^[0-9a-f]{64}$/;

/** Insertion-ordered catalogue: хвост — самый свежий, голова вытесняется первой. */
const objects = new Map();
/** Bytes currently catalogued (parallel to `objects`; single source of truth for the budget). */
let objectsBytes = 0;

const metrics = new Metrics();
const audit = new AuditLog({ service: "shardstore", metrics });
const globalLimiter = new SlidingWindowLimiter({ limit: guard.globalBurst, windowMs: guard.globalWindowMs });
const readLimiter = new SlidingWindowLimiter({ limit: guard.readBurst, windowMs: guard.readWindowMs });
const writeLimiter = new SlidingWindowLimiter({ limit: guard.writeBurst, windowMs: guard.writeWindowMs });
const penalty = new PenaltyBox({
  baseMs: guard.penaltyBaseMs, maxMs: guard.penaltyMaxMs, windowMs: guard.penaltyWindowMs,
  maxKeys: guard.penaltyMaxKeys, freeAttempts: guard.penaltyFreeAttempts,
});
const risk = new RiskEngine(guard);
const idempotency = new IdempotencyStore({ ttlMs: guard.idempotencyTtlMs, maxEntries: guard.idempotencyMaxEntries });
const flood = new FloodDetector(8);
const stopSweeper = startSweeper([globalLimiter, readLimiter, writeLimiter, penalty, risk, idempotency], guard.sweeperIntervalMs);

let degraded = false;
/** Глобальный бюджет одновременно принимаемых байт (защита от OOM при веере PUT). */
let inflightBytes = 0;
/** Открытые сокеты — для graceful shutdown с дедлайном. */
const sockets = new Set();
let shuttingDown = false;

const persistBreaker = new CircuitBreaker({
  failureThreshold: guard.cbFailureThreshold,
  openMs: guard.cbOpenMs,
  halfOpenMax: guard.cbHalfOpenMax,
  onState: (s) => {
    degraded = s !== "closed";
    audit.warn("PERSIST_BREAKER", { state: s, degraded });
  },
});

function keccak(buf) {
  // The digest the chain pins (ethers.keccak256): any store answering a different
  // hash breaks every third-party client that commits the returned `digest` on-chain.
  return keccak256Hex(buf);
}

function send(res, code, body, type = "application/json", extraHeaders = {}) {
  if (res.headersSent || res.destroyed) return false;
  res.writeHead(code, { "content-type": type, "x-request-id": currentRequestId() ?? "", ...extraHeaders });
  res.end(type === "application/json" ? JSON.stringify(body) : body);
  return true;
}

function retryAfter(ms) {
  return { "retry-after": String(Math.max(1, Math.ceil(ms / 1000))) };
}

/**
 * Consume-and-discard a request body unless already complete. Two paths answer
 * without running the body read — an idempotent replay and a singleflight
 * follower sharing the leader's in-flight PUT — and replying with the body
 * still on the socket desyncs the keep-alive connection behind it (the unread
 * bytes parse as the next request). Never rejects; the socket timeout bounds
 * slow senders.
 */
function drainRequest(req) {
  // `req.complete` alone is NOT enough to skip: a fully-arrived but unread body still
  // sits in the buffer, and leaving it there desynchronizes the next pipelined request
  // (it would parse leftover body bytes as HTTP). Skip only when the stream already
  // ended, or when it is complete with an empty buffer — which means the bytes were
  // consumed elsewhere and waiting for another 'end' would hang forever.
  if (req.readableEnded) return Promise.resolve();
  if (req.complete && req.readableLength === 0) return Promise.resolve();
  return new Promise((resolve) => {
    req.on("data", () => {});
    req.on("end", resolve);
    req.on("error", () => resolve());
    req.on("aborted", () => resolve());
    // `aborted` deprecated/never fires on some Node versions; `close` always does.
    req.on("close", () => resolve());
    req.resume();
  });
}

/**
 * Drain the body while hashing it (keccak256 over raw bytes). Used on the idempotent-replay
 * path: the cached result is only valid for the same bytes. Returns the hex digest, or null
 * when the body could not be fully consumed (aborted socket, or over the byte cap — caller
 * must then NOT trust a replay-or-mismatch verdict and falls back to draining).
 */
function drainAndHash(req, cap) {
  // Same skip rule as drainRequest, but resolving null (unverifiable) instead of just
  // returning: when the body was already consumed (singleflight share) there is nothing
  // to hash, and when it is over the cap the hash is unknowable. The caller must then
  // NOT treat the replay as verified — it falls back to a plain replay or re-execution.
  if (req.readableEnded) return Promise.resolve(null);
  if (req.complete && req.readableLength === 0) return Promise.resolve(null);
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    let overCap = false;
    let failed = false;
    req.on("data", (c) => {
      if (overCap || failed) return;
      size += c.length;
      if (size > cap) {
        // Oversized replay body: keep draining (discard) so keep-alive survives, but the
        // hash is unknowable — signal unverifiable rather than buffering an attack.
        overCap = true;
        chunks.length = 0;
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (failed || overCap) return resolve(null);
      try {
        resolve(keccak(Buffer.concat(chunks)));
      } catch {
        resolve(null);
      }
    });
    req.on("error", () => { failed = true; resolve(null); });
    req.on("aborted", () => { failed = true; resolve(null); });
    // `aborted` deprecated/never fires on some Node versions; `close` always does.
    req.on("close", () => resolve(null));
    req.resume();
  });
}

/** IP клиента. X-Forwarded-For — только при явном TRUST_PROXY=1, иначе это спуфинг. */
function clientIp(req) {
  if (TRUST_PROXY) {
    const xff = (req.headers["x-forwarded-for"] ?? "").split(",")[0].trim();
    if (/^[0-9a-fA-F:.]{3,45}$/.test(xff)) return xff;
  }
  return req.socket?.remoteAddress ?? "unknown";
}

function authorised(req) {
  if (AUTH_TOKEN === null) return true;
  let token;
  try {
    token = assertBearerToken(req.headers.authorization);
  } catch {
    return false;
  }
  const presented = Buffer.from(token);
  const expected = Buffer.from(AUTH_TOKEN);
  return presented.length === expected.length && timingSafeEqual(presented, expected);
}

/** Tarpit для запроса, который уже нарушил (401/400/416) и чей субъект greylisted. */
async function maybeTarpit(ip, violated) {
  if (!violated) return;
  const level = risk.levelOf(ip);
  const ms = tarpitDelayMs(level, guard);
  if (ms > 0) {
    metrics.incr("tarpit:applied");
    audit.security("TARPIT_APPLIED", { ip, level, sleepMs: ms });
    await sleep(ms);
  }
}

function storePath(cid) {
  return DATA_DIR ? join(DATA_DIR, cid.slice(2)) : null;
}

/** Атомарная запись: tmp + rename. Наблюдатель никогда не видит половину объекта. */
async function persistAtomic(cid, payload) {
  const dest = storePath(cid);
  if (!dest) return;
  const tmp = `${dest}.part-${randomBytes(8).toString("hex")}`;
  await mkdir(DATA_DIR, { recursive: true });
  await writeFile(tmp, payload);
  await rename(tmp, dest);
}

/** Best-effort сброс в DLQ для ручного разбора/повтора. Никогда не бросает. */
const MAX_DLQ_FILES = Number(process.env.MAX_DLQ_FILES ?? 100);
async function dlqWrite(cid, payload, reason) {
  if (!DLQ_DIR) return false;
  try {
    await mkdir(DLQ_DIR, { recursive: true });
    // Cap: every persist failure writes a full payload copy, so an unbounded DLQ turns a full
    // disk into a faster-full disk. Oldest files are NOT rotated away automatically (evidence),
    // new writes are shed with a warning instead.
    try {
      const existing = await readdir(DLQ_DIR);
      if (existing.length >= (Number.isSafeInteger(MAX_DLQ_FILES) ? MAX_DLQ_FILES : 100)) {
        audit.warn("DLQ_FULL", { cid, reason });
        metrics.incr("persist:dlq-shed");
        return false;
      }
    } catch {
      // Cannot list: try the write anyway, it may still succeed.
    }
    await writeFile(join(DLQ_DIR, `${cid.slice(2)}.${Date.now()}.failed`), payload);
    audit.critical("DLQ_WRITE", { cid, reason });
    return true;
  } catch (e) {
    audit.critical("DLQ_FAILED", { cid, reason, error: e.message });
    return false;
  }
}

/** Drop the least-recently-used entries until the catalogue fits the count AND
 * byte caps, disk copies included. Stops at one entry: a lone object above the
 * byte budget is still bounded by MAX_OBJECT_BYTES, and evicting it would turn
 * every read into a miss (the same thrash guard the SDK cache uses). */
async function enforceCapacity() {
  while ((objects.size > MAX_OBJECTS || objectsBytes > MAX_TOTAL_BYTES) && objects.size > 1) {
    const oldest = objects.keys().next();
    if (oldest.done) return;
    const cid = oldest.value;
    const victim = objects.get(cid);
    objects.delete(cid);
    objectsBytes = Math.max(0, objectsBytes - (victim?.length ?? 0));
    if (DATA_DIR) {
      try {
        await unlink(storePath(cid));
      } catch {
        // Already gone or never persisted: the catalogue is authoritative either way.
      }
    }
  }
}

/**
 * Rebuild the catalogue from files, newest first, within the count AND byte
 * caps: peak memory is bounded, not "all files on disk". Selected newest-first,
 * inserted oldest-first so the live eviction order (head = oldest) holds from
 * boot. A lone survivor may exceed the byte budget — same rule as live PUTs.
 */
async function rebuildIndex() {
  if (!DATA_DIR) return;
  let names;
  try {
    names = await readdir(DATA_DIR);
  } catch {
    return; // nothing persisted yet
  }
  const entries = [];
  for (const name of names) {
    if (!FILE_RE.test(name)) continue;
    try {
      const info = await stat(join(DATA_DIR, name));
      if (info.isFile() && info.size <= MAX_OBJECT_BYTES) entries.push({ name, mtime: info.mtimeMs, size: info.size });
    } catch {
      // Vanished between listing and stat: not ours to serve.
    }
  }
  entries.sort((a, b) => b.mtime - a.mtime);
  const selected = [];
  let selectedBytes = 0;
  for (const e of entries) {
    if (selected.length >= MAX_OBJECTS) break;
    if (selected.length > 0 && selectedBytes + e.size > MAX_TOTAL_BYTES) continue;
    selected.push(e);
    selectedBytes += e.size;
  }
  objectsBytes = 0;
  const selectedNames = new Set(selected.map((e) => e.name));
  for (let i = selected.length - 1; i >= 0; i--) {
    try {
      const data = await readFile(join(DATA_DIR, selected[i].name));
      objects.set(`0x${selected[i].name}`, data);
      objectsBytes += data.length;
    } catch {
      // Unreadable now: skip rather than serve half an object later.
    }
  }
  // Orphans: files that fit neither the count nor the byte budget would otherwise sit on disk
  // forever, invisible to the catalogue but eating the volume. Best-effort delete.
  for (const e of entries) {
    if (selectedNames.has(e.name)) continue;
    try {
      await unlink(join(DATA_DIR, e.name));
      metrics.incr("rebuild:orphan-removed");
    } catch {
      // Already gone or unwritable: memory catalogue stays authoritative.
    }
  }
}

/* ------------------------------- routes ------------------------------- */

async function routeHealth(req, res) {
  metrics.incr("route:healthz");
  return send(res, 200, {
    ok: true,
    objects: objects.size,
    objectsBytes,
    maxObjects: MAX_OBJECTS,
    maxTotalBytes: MAX_TOTAL_BYTES,
    degraded,
    uptimeSec: Math.floor(process.uptime()),
    inflightBytes,
    guard: metrics.snapshot(),
  });
}

async function routePut(req, res, url, ip) {
  // 0. Квота записи. MEDIUM-субъект платит 5 токенов: ужесточение без отдельного кода.
  const level0 = risk.levelOf(ip);
  const quota = writeLimiter.take(ip, level0 === RiskLevel.MEDIUM ? 5 : 1);
  if (!quota.allowed) {
    const r = risk.add(ip, RiskSignal.RATE_HIT);
    penalty.violate(ip);
    audit.security("RATE_LIMIT_EXCEEDED", { ip, op: "put", riskLevel: r.level, retryAfterMs: quota.retryAfterMs });
    await maybeTarpit(ip, true);
    metrics.incr("route:put:429");
    return send(res, 429, { error: "rate limited" }, "application/json", retryAfter(quota.retryAfterMs));
  }
  // 1. Путь и заявленный размер — до чтения тела.
  try {
    assertPath(url.pathname, guard.maxPathLen);
    if (url.pathname !== "/objects") return send(res, 404, { error: "not found" });
  } catch (e) {
    if (e instanceof SanitizeError) { await maybeTarpit(ip, true); return send(res, 400, { error: e.message }); }
    throw e;
  }
  let declared;
  try {
    declared = assertDeclaredLength(req.headers["content-length"], MAX_OBJECT_BYTES);
  } catch (e) {
    if (e instanceof SanitizeError) {
      risk.add(ip, RiskSignal.RANGE_ABUSE);
      await maybeTarpit(ip, true);
      return send(res, 413, { error: e.message });
    }
    throw e;
  }
  // 2. Резерв глобального бюджета. Неизвестная длина стартует с нуля, а учитывается
  // по мере прихода чанков в doPut: резерв под полный кап на каждое соединение без
  // Content-Length позволяет горстке медленных тел выбрать весь бюджет (8 x 64 МБ).
  let accounted = declared ?? 0;
  if (inflightBytes + accounted > guard.maxInflightBytes) {
    audit.warn("BACKPRESSURE_SHED", { ip, op: "put", inflightBytes, reserve: accounted });
    metrics.incr("route:put:503");
    return send(res, 503, { error: "server busy" }, "application/json", retryAfter(1000));
  }
  inflightBytes += accounted;
  let settled = false;
  const release = () => { if (!settled) { settled = true; inflightBytes = Math.max(0, inflightBytes - accounted); } };
  res.on("close", release);

  // 3. Ключ идемпотентности (400 на мусор — до дорогой работы).
  let idemKey = null;
  try {
    idemKey = assertIdempotencyKey(req.headers["idempotency-key"], guard.idempotencyKeyMaxLen);
  } catch (e) {
    if (e instanceof SanitizeError) { release(); await maybeTarpit(ip, true); return send(res, 400, { error: e.message }); }
    release(); throw e;
  }

  // 4. Auth. Провал = скоринг + penalty; tarpit только если субъект уже greylisted.
  if (!authorised(req)) {
    const r = risk.add(ip, RiskSignal.AUTH_FAIL);
    const pen = penalty.violate(ip);
    audit.security("AUTH_FAIL", { ip, op: "put", riskLevel: r.level, streak: pen.streak });
    metrics.incr("route:put:401");
    release();
    await maybeTarpit(ip, true);
    return send(res, 401, { error: "unauthorised" });
  }

  // 5. HIGH + авторизованная запись → honeypot: правдоподобный 201, записи нет.
  // Только при наличии «жёсткого» сигнала (см. `hasHardSignal`): honeypot отвечает 201 и
  // ничего не пишет, поэтому честный клиент, попавший под тайминг-сигнал, потерял бы
  // данные молча — контракт закрепил бы пинит несуществующего шарда, а зашифрованные
  // строки восстановить было бы нельзя. Регулярная cadence — это ровно то, что делает
  // собственный цикл загрузки SDK, а не признак злоумышленника.
  const level = risk.levelOf(ip);
  const shadowed = level === RiskLevel.HIGH && risk.hasHardSignal(ip);

  // 6. Bot-timing по фактическим PUT.
  risk.noteInterval(ip, "put");

  const doPut = async () => {
    const chunks = [];
    let size = 0;
    let aborted = false;
    const payload = await new Promise((resolve, reject) => {
      req.on("data", (c) => {
        if (aborted) return;
        size += c.length;
        if (declared == null) {
          // Тело без заявленной длины: бюджет учитываем по факту, а не резервом.
          // `accounted` захвачен замыканием `release` ниже, так что освобождение
          // вернёт ровно столько, сколько пришло (включая обрыв по 413).
          accounted += c.length;
          inflightBytes += c.length;
          // Бюджет проверяется и здесь, а не только на входе: тело без Content-Length
          // резервировало 0, поэтому проверка на входе проходила всегда, и N таких
          // соединений держали в памяти N x 64 МБ — при бюджете 512 МБ это OOM и
          // остановка всех нод, которым нужно опубликовать или прочитать шард.
          // Превышение — это backpressure: 503 с ретраем, а не потеря данных.
          if (inflightBytes > guard.maxInflightBytes) {
            aborted = true;
            metrics.incr("route:put:503");
            audit.warn("BACKPRESSURE_SHED", { ip, op: "put", inflightBytes, reserve: accounted });
            send(res, 503, { error: "server busy" }, "application/json", retryAfter(1000));
            req.destroy();
            reject(new Error("server busy"));
            return;
          }
        }
        if (size > MAX_OBJECT_BYTES) {
          aborted = true;
          metrics.incr("route:put:413");
          send(res, 413, { error: "object too large" });
          req.destroy();
          reject(new Error("object too large"));
          return;
        }
        chunks.push(c);
      });
      req.on("end", () => { if (!aborted) resolve(Buffer.concat(chunks)); });
      req.on("error", (e) => { if (!aborted) { aborted = true; reject(e); } });
      req.on("aborted", () => { if (!aborted) { aborted = true; reject(new Error("client aborted")); } });
    }).finally(release);

    // Compute bodyHash alongside the CID: both are derived from the same payload.
    const cid = keccak(payload);
    const bodyHash = cid; // same keccak computation, stored for replay verification

    if (shadowed) {
      const hp = honeypotPut(payload);
      audit.security("SHADOWBAN_PUT", { ip, bytes: payload.length, cid: hp.body.cid });
      metrics.incr("shadowban:put");
      return { status: hp.status, body: hp.body, bodyHash };
    }

    if (flood.note(ip, cid)) {
      const r = risk.add(ip, RiskSignal.DUP_PAYLOAD);
      audit.security("DUP_PAYLOAD", { ip, cid, riskLevel: r.level });
    }
    // LRU-touch with byte accounting: a re-PUT replaces, never double-counts.
    const prev = objects.get(cid);
    objects.delete(cid);
    objects.set(cid, payload);
    objectsBytes += payload.length - (prev?.length ?? 0);
    if (DATA_DIR) {
      // Fail-open persist: диск лёг — memory-only + degraded + DLQ, сервис жив.
      // exec с fallback не бросает: успех → "ok", открытый контур → "degraded".
      const outcome = await persistBreaker.exec(() => persistAtomic(cid, payload).then(() => "ok"), {
        fallback: async () => {
          audit.critical("PERSIST_FALLBACK", { cid });
          metrics.incr("persist:degraded");
          await dlqWrite(cid, payload, "persist-breaker-open");
          return "degraded";
        },
      });
      if (outcome !== "ok" && outcome !== "degraded") {
        console.error(`shardstore: persist ${cid} failed: unexpected outcome`);
        return { status: 500, body: { error: "persist failed" } };
      }
    }
    await enforceCapacity();
    return { status: 201, body: { cid, digest: cid }, bodyHash };
  };

  try {
    let out;
    if (idemKey) {
      const key = `put:${ip}:${idemKey}`;
      // NOTE: we do NOT call drainAndHash here before idempotency.run.
      // doPut reads the body and computes bodyHash, which is stored in the cache.
      // On replay (r.replayed), we use the stored bodyHash to verify.
      const r = await idempotency.run(key, doPut);
      if (r.replayed) {
        // Stale-cache check FIRST, before touching the body: if the cached 201 names
        // an object that is gone (deleted after caching), forget and re-execute so
        // doPut reads the intact body itself. Draining first would leave doPut with
        // an empty stream that never ends — the request then hangs until the handler
        // timeout answers 503.
        const replayCid = typeof r.result?.body?.cid === "string" ? r.result.body.cid : null;
        if (replayCid && r.result.status === 201 && !objects.has(replayCid)) {
          idempotency.forget(key);
          metrics.incr("idempotency:stale-replay-reexecuted");
          audit.info("IDEMPOTENT_STALE_REEXEC", { ip, key: `${ip}:***` });
          out = await doPut();
        } else {
          // Live replay: the cached result is only valid for the same bytes. Drain the
          // body to hash it and compare against the stored bodyHash from the original
          // request — this detects the same idempotency key reused with different bytes.
          const storedHash = idempotency.getBodyHash(key);
          const currentHash = await drainAndHash(req, MAX_OBJECT_BYTES);
          if (storedHash !== null && currentHash !== null && storedHash.toLowerCase() !== currentHash.toLowerCase()) {
            metrics.incr("idempotency:mismatch");
            audit.security("IDEMPOTENCY_MISMATCH", { ip, key: `${ip}:***` });
            return send(res, 422, { error: "idempotency key was already used with different bytes" });
          }
          metrics.incr("idempotency:replay");
          audit.info("IDEMPOTENT_REPLAY", { ip, key: `${ip}:***` });
          out = r.result;
          // Even on replay we must consume the body so the connection stays usable.
          await drainRequest(req);
        }
      } else {
        // First call (or cache miss): doPut ran and the cache adopted its bodyHash.
        // Singleflight subtlety: when our call shared another request's in-flight
        // execution, the winner consumed ITS body while ours sits unread in our
        // socket. Verify ours against the winner's hash before accepting the shared
        // result — otherwise a concurrent same-key/different-body PUT silently gets
        // a cid it cannot commit (must be 422, same as the replay path). When we won
        // the race our body is already consumed, the hash comes back null, and the
        // check is skipped. Either way the body ends consumed (drained here, or by
        // doPut) so the connection stays usable.
        const sharedHash = r.result?.bodyHash ?? null;
        const ourHash = await drainAndHash(req, MAX_OBJECT_BYTES);
        if (sharedHash !== null && ourHash !== null && sharedHash.toLowerCase() !== ourHash.toLowerCase()) {
          metrics.incr("idempotency:mismatch");
          audit.security("IDEMPOTENCY_MISMATCH", { ip, key: `${ip}:***` });
          return send(res, 422, { error: "idempotency key was already used with different bytes" });
        }
        out = r.result;
      }
    } else {
      out = await doPut();
      // doPut consumed the body; a replay or a shared singleflight result did
      // not. Drain whatever is left so the connection stays usable even on
      // runtimes/proxies that do not discard unread bodies themselves.
      await drainRequest(req);
    }
    metrics.incr(`route:put:${out.status}`);
    return send(res, out.status, out.body);
  } catch (e) {
    // Обрыв клиента после destroy: ответ уже ушёл (413) или сокет мёртв — не 500.
    if (res.headersSent || res.destroyed || /too large|aborted/i.test(e.message)) return false;
    audit.critical("PUT_FAILED", { ip, error: e.message });
    metrics.incr("route:put:500");
    return send(res, 500, { error: "put failed" });
  }
}

async function routeDelete(req, res, url, ip) {
  const quota = writeLimiter.take(ip);
  if (!quota.allowed) {
    risk.add(ip, RiskSignal.RATE_HIT);
    penalty.violate(ip);
    audit.security("RATE_LIMIT_EXCEEDED", { ip, op: "delete", retryAfterMs: quota.retryAfterMs });
    await maybeTarpit(ip, true);
    return send(res, 429, { error: "rate limited" }, "application/json", retryAfter(quota.retryAfterMs));
  }
  let cid;
  try {
    assertPath(url.pathname, guard.maxPathLen);
    cid = assertCid(url.pathname.slice("/objects/".length).toLowerCase());
  } catch (e) {
    if (e instanceof SanitizeError) { await maybeTarpit(ip, true); return send(res, 400, { error: e.message }); }
    throw e;
  }
  if (!authorised(req)) {
    const r = risk.add(ip, RiskSignal.AUTH_FAIL);
    penalty.violate(ip);
    audit.security("AUTH_FAIL", { ip, op: "delete", riskLevel: r.level });
    await maybeTarpit(ip, true);
    return send(res, 401, { error: "unauthorised" });
  }
  if (!objects.has(cid)) return send(res, 404, { error: "not found" });
  const removed = objects.get(cid);
  objects.delete(cid);
  // Byte accounting is parallel to the catalogue: a delete that forgets it leaks the budget
  // until the next restart (premature evictions + a lying healthz).
  objectsBytes = Math.max(0, objectsBytes - (removed?.length ?? 0));
  // NOTE: a stale idempotency replay for this cid is handled on the PUT path — a replayed
  // 201 whose object is gone is re-executed instead of served from cache (see routePut).
  if (DATA_DIR) {
    try {
      await unlink(storePath(cid));
    } catch {
      // Memory is authoritative; a missing file changes nothing.
    }
  }
  metrics.incr("route:delete:200");
  return send(res, 200, { deleted: true });
}

async function routeGet(req, res, url, ip) {
  const quota = readLimiter.take(ip);
  if (!quota.allowed) {
    risk.add(ip, RiskSignal.RATE_HIT);
    penalty.violate(ip);
    audit.security("RATE_LIMIT_EXCEEDED", { ip, op: "get", retryAfterMs: quota.retryAfterMs });
    await maybeTarpit(ip, true);
    return send(res, 429, { error: "rate limited" }, "application/json", retryAfter(quota.retryAfterMs));
  }
  let cid;
  try {
    assertPath(url.pathname, guard.maxPathLen);
    cid = assertCid(url.pathname.slice("/objects/".length).toLowerCase());
  } catch (e) {
    if (e instanceof SanitizeError) { await maybeTarpit(ip, true); return send(res, 400, { error: e.message }); }
    throw e;
  }

  let payload = objects.get(cid);
  if (payload) {
    objects.delete(cid);
    objects.set(cid, payload);
  }
  if (!payload && DATA_DIR) {
    try {
      const p = storePath(cid);
      const info = await stat(p);
      if (info.size <= MAX_OBJECT_BYTES) payload = await readFile(p);
    } catch {
      payload = undefined;
    }
  }
  if (!payload) {
    risk.add(ip, RiskSignal.NOT_FOUND);
    metrics.incr("route:get:404");
    return send(res, 404, { error: "not found" });
  }

  // Conditional read: a client holding the ETag revalidates without a second download.
  // The ETag is always the keccak cid, and CIDs are content addresses, so a match means
  // byte-identical content — no weak-comparison pitfalls. `*` matches any representation.
  const inm = req.headers["if-none-match"];
  if (typeof inm === "string") {
    const tags = inm.split(",").map((s) => s.trim());
    if (tags.includes("*") || tags.includes(`"${cid}"`)) {
      metrics.incr("route:get:304");
      res.writeHead(304, {
        etag: `"${cid}"`,
        "accept-ranges": "bytes",
        "x-request-id": currentRequestId() ?? "",
      });
      return Boolean(res.end());
    }
  }

  let range = null;
  try {
    range = parseRangeHeader(req.headers.range, MAX_OBJECT_BYTES);
  } catch (e) {
    if (e instanceof SanitizeError) {
      risk.add(ip, RiskSignal.RANGE_ABUSE);
      audit.security("RANGE_ABUSE", { ip, cid, reason: e.message });
      await maybeTarpit(ip, true);
      res.writeHead(416, { "content-range": `bytes */${payload.length}` });
      return Boolean(res.end());
    }
    throw e;
  }
  if (range) {
    // Суффикс резолвится против реальной длины: последние N байт (или весь объект).
    const start = range.suffix !== undefined ? Math.max(0, payload.length - range.suffix) : range.start;
    const end = Math.min(range.end ?? payload.length - 1, payload.length - 1);
    if (start > end) {
      res.writeHead(416, { "content-range": `bytes */${payload.length}` });
      return Boolean(res.end());
    }
    const slice = payload.subarray(start, end + 1);
    metrics.incr("route:get:206");
    res.writeHead(206, {
      "content-type": "application/octet-stream",
      "content-range": `bytes ${start}-${end}/${payload.length}`,
      "content-length": String(slice.length),
      "accept-ranges": "bytes",
      "etag": `"${cid}"`,
      "x-request-id": currentRequestId() ?? "",
    });
    return Boolean(res.end(slice));
  }

  metrics.incr("route:get:200");
  res.writeHead(200, {
    "content-type": "application/octet-stream",
    "content-length": String(payload.length),
    "accept-ranges": "bytes",
    "etag": `"${cid}"`,
    "x-request-id": currentRequestId() ?? "",
  });
  return Boolean(res.end(payload));
}

/* ------------------------------- server ------------------------------- */

const server = (TLS_CERT ? createHttpsServer : createHttpServer)(
  ...(TLS_CERT ? [{ cert: readFileSync(TLS_CERT), key: readFileSync(TLS_KEY) }] : []),
  (req, res) => {
    // Каждый запрос — в своём request-контексте: request_id во всех логах и ответах.
    // Реджект ловится здесь, а не всплывает как unhandledRejection: падение одного
    // запроса не должно убивать весь DA-сервис (обработчик ниже выходит с кодом 1).
    requestContext.run({ requestId: newRequestId() }, () => {
      handle(req, res).catch((e) => {
        const msg = e instanceof Error ? e.message : String(e);
        audit.critical("HANDLER_REJECTED", { error: msg });
        if (!res.headersSent) send(res, 500, { error: "internal error" });
      });
    });
  }
);

server.on("connection", (socket) => {
  sockets.add(socket);
  socket.on("close", () => sockets.delete(socket));
});

// Ошибка listen (EADDRINUSE при быстром рестарте, EACCES) — это не рабочий процесс:
// громкий не-нулевой выход, а не маскировка под graceful shutdown через uncaughtException.
server.on("error", (e) => {
  audit.critical("LISTEN_FAILED", { error: e.message });
  console.error(`shardstore: listen failed: ${e.message}`);
  stopSweeper();
  process.exit(1);
});

async function handle(req, res) {
  const t0 = Date.now();
  const ip = clientIp(req);
  req.setTimeout(guard.requestTimeoutMs, () => {
    audit.warn("REQUEST_TIMEOUT", { ip, method: req.method, url: req.url });
    metrics.incr("request:timeout");
    if (!res.headersSent) send(res, 408, { error: "request timeout" });
    req.destroy();
  });
  req.on("error", (e) => {
    audit.warn("REQUEST_ERROR", { ip, error: e.message });
    try { req.destroy(); } catch { /* уже мёртв */ }
  });

  // Fail-open входного каскада: сбой охраны = пропуск с CRITICAL, не 500.
  const gate = await withResilience("ingress", async () => {
    if (shuttingDown) return { action: "unavailable" };
    const g = globalLimiter.take("global");
    if (!g.allowed) {
      audit.security("RATE_LIMIT_EXCEEDED", { ip, op: "global", retryAfterMs: g.retryAfterMs });
      return { action: "deny", status: 503, retryAfterMs: g.retryAfterMs };
    }
    const blocked = penalty.blockedMs(ip);
    if (blocked > 0) {
      audit.security("PENALTY_BLOCK", { ip, blockedMs: blocked });
      return { action: "deny", status: 429, retryAfterMs: blocked };
    }
    return { action: "pass" };
  }, { fallback: { action: "pass" }, audit });
  const decision = gate.value;
  if (decision.action === "unavailable") return send(res, 503, { error: "shutting down" });
  if (decision.action === "deny") {
    metrics.incr(`ingress:${decision.status}`);
    return send(res, decision.status, { error: decision.status === 503 ? "server busy" : "blocked" },
      "application/json", retryAfter(decision.retryAfterMs ?? 1000));
  }

  let url;
  try {
    url = new URL(req.url, `http://${req.headers.host ?? "localhost"}`);
  } catch {
    await maybeTarpit(ip, true);
    return send(res, 400, { error: "bad request" });
  }

  try {
    // Жёсткий дедлайн хендлера: зависший маршрут не держит сокет вечно.
    const done = (async () => {
      if (req.method === "GET" && url.pathname === "/healthz") return routeHealth(req, res);
      if (req.method === "PUT" && url.pathname === "/objects") return routePut(req, res, url, ip);
      if (req.method === "DELETE" && url.pathname.startsWith("/objects/")) return routeDelete(req, res, url, ip);
      if (req.method === "GET" && url.pathname.startsWith("/objects/")) return routeGet(req, res, url, ip);
      // Неизвестный маршрут — тоже через санитайзер (троллинг путями).
      try { assertPath(url.pathname, guard.maxPathLen); } catch { return send(res, 404, { error: "not found" }); }
      return send(res, 404, { error: "not found" });
    })();
    const timeout = sleep(guard.handlerTimeoutMs).then(() => "timeout");
    const winner = await Promise.race([done.then(() => "done"), timeout]);
    if (winner === "timeout") {
      audit.warn("HANDLER_TIMEOUT", { ip, method: req.method, path: url.pathname });
      metrics.incr("handler:timeout");
      send(res, 503, { error: "handler timeout" });
      try { req.destroy(); } catch { /* уже мёртв */ }
    }
  } catch (e) {
    audit.critical("HANDLER_FAILED", { ip, method: req.method, error: e.message });
    metrics.incr("handler:500");
    send(res, 500, { error: "internal error" });
  } finally {
    const ms = Date.now() - t0;
    metrics.observe("handler:ms", ms);
    audit.info("REQUEST", { ip, method: req.method, path: url.pathname, ms, risk: risk.levelOf(ip) });
  }
}

function shutdown(signal, code = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  audit.critical("SHUTDOWN_BEGIN", { signal });
  server.close(() => {
    audit.critical("SHUTDOWN_DRAINED", {});
    stopSweeper();
    process.exit(code);
  });
  // Дедлайн: зависшие соединения рвём, иначе SIGTERM висит вечно.
  setTimeout(() => {
    audit.critical("SHUTDOWN_FORCE", { openSockets: sockets.size });
    for (const s of sockets) {
      try { s.destroy(); } catch { /* уже мёртв */ }
    }
    stopSweeper();
    process.exit(code);
  }, SHUTDOWN_TIMEOUT_MS).unref();
}

process.on("SIGINT", () => shutdown("SIGINT", 0));
process.on("SIGTERM", () => shutdown("SIGTERM", 0));
process.on("uncaughtException", (e) => {
  // Крах — не graceful shutdown: не-нулевой код, иначе оркестратор решит, что всё штатно.
  audit.critical("UNCAUGHT", { error: e.message });
  shutdown("uncaughtException", 1);
});
process.on("unhandledRejection", (reason) => {
  // Async-обработчики вызваны как void handle(): вылетевший реджект иначе умирает молча.
  const msg = reason instanceof Error ? reason.message : String(reason);
  audit.critical("UNHANDLED_REJECTION", { error: msg });
  shutdown("unhandledRejection", 1);
});

await rebuildIndex();
server.listen(PORT, HOST, () => {
  const bound = server.address();
  const port = typeof bound === "object" && bound !== null ? bound.port : PORT;
  console.log(`shardstore listening on ${HOST}:${port}`);
  if (!DATA_DIR) console.log("shardstore: DATA_DIR unset, objects are memory-only and lost on restart");
  if (AUTH_TOKEN === null) console.log("shardstore: AUTH_TOKEN unset, writes are unauthenticated");
  if (HOST === "0.0.0.0" && AUTH_TOKEN === null) {
    console.log("shardstore: WARNING bound to all interfaces with no authentication");
  }
  audit.info("STARTUP", { host: HOST, port, dataDir: DATA_DIR ?? null, auth: AUTH_TOKEN !== null });
});
