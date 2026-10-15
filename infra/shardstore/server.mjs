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
 *    SHUTDOWN_TIMEOUT_MS=10000, DLQ_DIR=<DATA_DIR>/dlq, TRUST_PROXY=0, GUARD_* — см. guard.mjs)
 */
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { createHash, timingSafeEqual, randomBytes } from "node:crypto";
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

const PORT = Number(process.env.PORT ?? 8080);
const HOST = process.env.HOST ?? "127.0.0.1";
const DATA_DIR = process.env.DATA_DIR || null;
const MAX_OBJECT_BYTES = Number(process.env.MAX_OBJECT_BYTES ?? 64 * 1024 * 1024);
const MAX_OBJECTS = Number(process.env.MAX_OBJECTS ?? 4096);
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
  // Имя — под то, что SDK сравнивает. Это SHA3-256, не keccak-256; см. addressing.
  return "0x" + createHash("sha3-256").update(buf).digest("hex");
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
async function dlqWrite(cid, payload, reason) {
  if (!DLQ_DIR) return false;
  try {
    await mkdir(DLQ_DIR, { recursive: true });
    await writeFile(join(DLQ_DIR, `${cid.slice(2)}.${Date.now()}.failed`), payload);
    audit.critical("DLQ_WRITE", { cid, reason });
    return true;
  } catch (e) {
    audit.critical("DLQ_FAILED", { cid, reason, error: e.message });
    return false;
  }
}

/** Drop the least-recently-used entries until the catalogue fits the cap, disk copies included. */
async function enforceCapacity() {
  while (objects.size > MAX_OBJECTS) {
    const oldest = objects.keys().next();
    if (oldest.done) return;
    const cid = oldest.value;
    objects.delete(cid);
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
 * Rebuild the catalogue from files, newest first, не более MAX_OBJECTS файлов:
 * пик памяти ограничен, а не "все файлы диска".
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
      if (info.isFile() && info.size <= MAX_OBJECT_BYTES) entries.push({ name, mtime: info.mtimeMs });
    } catch {
      // Vanished between listing and stat: not ours to serve.
    }
  }
  entries.sort((a, b) => b.mtime - a.mtime);
  for (const { name } of entries.slice(0, MAX_OBJECTS)) {
    try {
      objects.set(`0x${name}`, await readFile(join(DATA_DIR, name)));
    } catch {
      // Unreadable now: skip rather than serve half an object later.
    }
  }
}

/* ------------------------------- routes ------------------------------- */

async function routeHealth(req, res) {
  metrics.incr("route:healthz");
  return send(res, 200, {
    ok: true,
    objects: objects.size,
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
  // 2. Резерв глобального бюджета. Неизвестная длина = резерв под полный кап.
  const reserve = declared ?? MAX_OBJECT_BYTES;
  if (inflightBytes + reserve > guard.maxInflightBytes) {
    audit.warn("BACKPRESSURE_SHED", { ip, op: "put", inflightBytes, reserve });
    metrics.incr("route:put:503");
    return send(res, 503, { error: "server busy" }, "application/json", retryAfter(1000));
  }
  inflightBytes += reserve;
  let settled = false;
  const release = () => { if (!settled) { settled = true; inflightBytes = Math.max(0, inflightBytes - reserve); } };
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
  const level = risk.levelOf(ip);
  const shadowed = level === RiskLevel.HIGH;

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

    if (shadowed) {
      const hp = honeypotPut(payload);
      audit.security("SHADOWBAN_PUT", { ip, bytes: payload.length, cid: hp.body.cid });
      metrics.incr("shadowban:put");
      return { status: hp.status, body: hp.body };
    }

    const cid = keccak(payload);
    if (flood.note(ip, cid)) {
      const r = risk.add(ip, RiskSignal.DUP_PAYLOAD);
      audit.security("DUP_PAYLOAD", { ip, cid, riskLevel: r.level });
    }
    objects.delete(cid);
    objects.set(cid, payload);
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
    return { status: 201, body: { cid, digest: cid } };
  };

  try {
    let out;
    if (idemKey) {
      const key = `put:${ip}:${idemKey}`;
      const r = await idempotency.run(key, doPut);
      if (r.replayed) {
        metrics.incr("idempotency:replay");
        audit.info("IDEMPOTENT_REPLAY", { ip, key: `${ip}:***` });
      }
      out = r.result;
    } else {
      out = await doPut();
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
  objects.delete(cid);
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
      "x-request-id": currentRequestId() ?? "",
    });
    return Boolean(res.end(slice));
  }

  metrics.incr("route:get:200");
  res.writeHead(200, {
    "content-type": "application/octet-stream",
    "content-length": String(payload.length),
    "x-request-id": currentRequestId() ?? "",
  });
  return Boolean(res.end(payload));
}

/* ------------------------------- server ------------------------------- */

const server = (TLS_CERT ? createHttpsServer : createHttpServer)(
  ...(TLS_CERT ? [{ cert: readFileSync(TLS_CERT), key: readFileSync(TLS_KEY) }] : []),
  (req, res) => {
    // Каждый запрос — в своём request-контексте: request_id во всех логах и ответах.
    requestContext.run({ requestId: newRequestId() }, () => void handle(req, res));
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

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  audit.critical("SHUTDOWN_BEGIN", { signal });
  server.close(() => {
    audit.critical("SHUTDOWN_DRAINED", {});
    stopSweeper();
    process.exit(0);
  });
  // Дедлайн: зависшие соединения рвём, иначе SIGTERM висит вечно.
  setTimeout(() => {
    audit.critical("SHUTDOWN_FORCE", { openSockets: sockets.size });
    for (const s of sockets) {
      try { s.destroy(); } catch { /* уже мёртв */ }
    }
    stopSweeper();
    process.exit(0);
  }, SHUTDOWN_TIMEOUT_MS).unref();
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("uncaughtException", (e) => {
  // Последний рубеж: логируем и гасим по протоколу, а не падаем с dump посреди PUT.
  audit.critical("UNCAUGHT", { error: e.message });
  shutdown("uncaughtException");
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
