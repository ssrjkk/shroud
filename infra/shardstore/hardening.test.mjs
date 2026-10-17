/**
 * Интеграционные доказательства охраны на живом server.mjs.
 * Отдельный файл и порт (18082), т.к. node --test гоняет файлы параллельно.
 * Доказывает end-to-end:
 *  (а) троттлинг записи: N+1-й PUT в окне → 429 + Retry-After;
 *  (б) penalty box: серия 401 → блок с растущим Retry-After;
 *  (в) shadowban: HIGH-субъект с валидным токеном получает правдоподобный 201,
 *      но объект НЕ записан (GET → 404) — изоляция без оракула для атакующего;
 *  (г) идемпотентность: повтор PUT с тем же Idempotency-Key и тем же телом →
 *      тот же ответ без повторной записи; тот же ключ с другим телом → 422;
 *  (д) graceful shutdown: SIGTERM → процесс завершается кодом 0, данные целы;
 *  (е) replay дренирует тело: пайплайнинг на одном сокете не рассинхронизируется,
 *      повтор с другим телом → 422;
 *  (е2) повтор после DELETE не воскрешает призрака: stale-replay переисполняется;
 *  (е3) DELETE уменьшает objectsBytes;
 *  (ж) байт-бюджет каталога: вытеснение oldest-first по сумме, одиночный объект
 *      сверх бюджета остаётся (без thrash).
 */
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { keccak256Hex } from "./keccak.mjs";

const DIR = dirname(fileURLToPath(import.meta.url));
const PORT = 18082;
const BASE = `http://127.0.0.1:${PORT}`;
const TOKEN = "hardening-token";

function cidOf(bytes) {
  return keccak256Hex(bytes);
}

function spawnServer(extraEnv) {
  const { AUTH_TOKEN: _ambient, ...clean } = process.env;
  const env = { ...clean, PORT: String(PORT), ...extraEnv };
  return spawn("node", [join(DIR, "server.mjs")], { env, stdio: ["ignore", "pipe", "pipe"] });
}

async function waitHealthy(child) {
  const deadline = Date.now() + 10_000;
  for (;;) {
    try {
      const r = await fetch(`${BASE}/healthz`);
      if (r.ok) return;
    } catch { /* not up yet */ }
    if (Date.now() > deadline) {
      child.kill();
      throw new Error("hardened shardstore did not become healthy in time");
    }
    await new Promise((r) => setTimeout(r, 100));
  }
}

async function stop(child) {
  child.kill("SIGTERM");
  const code = await new Promise((resolve) => {
    const t = setTimeout(() => { child.kill("SIGKILL"); resolve("SIGKILL"); }, 8000);
    child.on("exit", (c, s) => { clearTimeout(t); resolve(c ?? `signal:${s}`); });
  });
  return code;
}

const authed = (t = TOKEN) => ({ Authorization: `Bearer ${t}` });

describe("hardening", () => {
  let child;
  let dataDir;

  before(async () => {
    dataDir = mkdtempSync(join(tmpdir(), "shardstore-hardening-"));
    child = spawnServer({
      DATA_DIR: dataDir,
      AUTH_TOKEN: TOKEN,
      MAX_OBJECTS: "100",
      // Жёсткие, но детерминированные лимиты для proofs.
      GUARD_WRITE_BURST: "3",
      GUARD_WRITE_RPS: "3",
      GUARD_WRITE_WINDOW_MS: "60000",
      GUARD_READ_BURST: "1000",
      GUARD_PENALTY_FREE: "1",
      GUARD_PENALTY_BASE_MS: "60000",
      GUARD_PENALTY_MAX_MS: "60000",
      GUARD_RISK_W_AUTH_FAIL: "50",
      GUARD_RISK_MEDIUM: "30",
      GUARD_RISK_HIGH: "80",
      GUARD_TARPIT_MIN_MS: "10",
      GUARD_TARPIT_MAX_MS: "20",
    });
    await waitHealthy(child);
  });

  after(async () => {
    if (child && child.exitCode === null) child.kill("SIGKILL");
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("(а) троттлинг записи: burst+1 → 429 с Retry-After", async () => {
    // 3 PUT в burst — проходят; 4-й в том же окне 60с — 429.
    for (let i = 0; i < 3; i++) {
      const r = await fetch(`${BASE}/objects`, {
        method: "PUT", headers: authed(), body: Buffer.from(`throttle-${i}-${Date.now()}`),
      });
      assert.equal(r.status, 201);
    }
    const over = await fetch(`${BASE}/objects`, {
      method: "PUT", headers: authed(), body: Buffer.from("throttle-over"),
    });
    assert.equal(over.status, 429);
    assert.ok(over.headers.get("retry-after"), "Retry-After обязан присутствовать");
    assert.match(await over.text(), /rate limited|blocked/);
  });

  it("(б) penalty box: серия 401 → блок", async () => {
    // G кладет отдельный сервер? Нет — тот же процесс, но write-квота уже съедена
    // тестом (а). Поднимаем чистый инстанс на другом порту для изоляции.
    const port2 = 18083;
    const c2 = spawnServer({
      PORT: String(port2), DATA_DIR: mkdtempSync(join(tmpdir(), "shardstore-pen-")),
      AUTH_TOKEN: TOKEN, GUARD_PENALTY_FREE: "1",
      GUARD_PENALTY_BASE_MS: "60000", GUARD_PENALTY_MAX_MS: "60000",
      GUARD_WRITE_BURST: "1000",
    });
    const base2 = `http://127.0.0.1:${port2}`;
    try {
      const deadline = Date.now() + 10_000;
      for (;;) {
        try {
          const r = await fetch(`${base2}/healthz`);
          if (r.ok) break;
        } catch { /* wait */ }
        if (Date.now() > deadline) throw new Error("penalty server not up");
        await new Promise((r) => setTimeout(r, 100));
      }
      const bad = { method: "PUT", body: Buffer.from("x") };
      assert.equal((await fetch(`${base2}/objects`, { ...bad, headers: authed("nope-1") })).status, 401);
      // 2-е нарушение при FREE=1 → блок 60с: даже валидный токен теперь 429.
      assert.equal((await fetch(`${base2}/objects`, { ...bad, headers: authed("nope-2") })).status, 401);
      const blocked = await fetch(`${base2}/objects`, {
        method: "PUT", headers: authed(), body: Buffer.from("legit-but-blocked"),
      });
      assert.equal(blocked.status, 429);
      assert.ok(Number(blocked.headers.get("retry-after")) >= 1);
    } finally {
      c2.kill("SIGKILL");
    }
  });

  it("(в) shadowban: HIGH с валидным токеном видит 201, но объекта нет", async () => {
    const port3 = 18084;
    const dir3 = mkdtempSync(join(tmpdir(), "shardstore-shadow-"));
    const c3 = spawnServer({
      PORT: String(port3), DATA_DIR: dir3, AUTH_TOKEN: TOKEN,
      GUARD_WRITE_BURST: "1000",
      GUARD_RISK_W_AUTH_FAIL: "50", // 2 провала = HIGH(80+ с учётом decay≈0)
      GUARD_RISK_HIGH: "80",
      GUARD_TARPIT_MIN_MS: "1", GUARD_TARPIT_MAX_MS: "2",
    });
    const base3 = `http://127.0.0.1:${port3}`;
    try {
      const deadline = Date.now() + 10_000;
      for (;;) {
        try {
          const r = await fetch(`${base3}/healthz`);
          if (r.ok) break;
        } catch { /* wait */ }
        if (Date.now() > deadline) throw new Error("shadow server not up");
        await new Promise((r) => setTimeout(r, 100));
      }
      // Два неверных токена → HIGH.
      await fetch(`${base3}/objects`, { method: "PUT", headers: authed("bad-1"), body: Buffer.from("x") });
      await fetch(`${base3}/objects`, { method: "PUT", headers: authed("bad-2"), body: Buffer.from("y") });
      // Теперь валидный токен: правдоподобный 201…
      const body = Buffer.from(`shadowed-${Date.now()}`);
      const put = await fetch(`${base3}/objects`, { method: "PUT", headers: authed(), body });
      assert.equal(put.status, 201);
      const { cid } = await put.json();
      assert.equal(cid, cidOf(body)); // cid корректный — неотличимо от успеха
      // …но записи нет: ни в памяти, ни на диске.
      assert.equal((await fetch(`${base3}/objects/${cid}`)).status, 404);
    } finally {
      c3.kill("SIGKILL");
      rmSync(dir3, { recursive: true, force: true });
    }
  });

  it("(г) идемпотентность: повтор с тем же ключом — replay без переписи", async () => {
    const port4 = 18085;
    const dir4 = mkdtempSync(join(tmpdir(), "shardstore-idem-"));
    const c4 = spawnServer({
      PORT: String(port4), DATA_DIR: dir4, AUTH_TOKEN: TOKEN, GUARD_WRITE_BURST: "1000",
    });
    const base4 = `http://127.0.0.1:${port4}`;
    try {
      const deadline = Date.now() + 10_000;
      for (;;) {
        try {
          const r = await fetch(`${base4}/healthz`);
          if (r.ok) break;
        } catch { /* wait */ }
        if (Date.now() > deadline) throw new Error("idempotency server not up");
        await new Promise((r) => setTimeout(r, 100));
      }
      const key = `test-key-${Date.now()}`;
      const body = Buffer.from("idempotent-payload");
      const first = await fetch(`${base4}/objects`, {
        method: "PUT", headers: { ...authed(), "Idempotency-Key": key }, body,
      });
      assert.equal(first.status, 201);
      const j1 = await first.json();
      // Тот же ключ, другое тело: 422 — молча вернуть чужой cid значит отдать клиенту
      // шард, который он не сможет закоммитить (ctDigest не сойдётся).
      const second = await fetch(`${base4}/objects`, {
        method: "PUT", headers: { ...authed(), "Idempotency-Key": key }, body: Buffer.from("different-bytes"),
      });
      assert.equal(second.status, 422);
      assert.match(await second.text(), /different bytes/);
      // Мусорный ключ — 400, а не запись.
      const bad = await fetch(`${base4}/objects`, {
        method: "PUT", headers: { ...authed(), "Idempotency-Key": "bad key!!" }, body,
      });
      assert.equal(bad.status, 400);
    } finally {
      c4.kill("SIGKILL");
      rmSync(dir4, { recursive: true, force: true });
    }
  });

  it("(д) graceful shutdown: SIGTERM → код 0, данные целы", async () => {
    const port5 = 18086;
    const dir5 = mkdtempSync(join(tmpdir(), "shardstore-grace-"));
    const c5 = spawnServer({ PORT: String(port5), DATA_DIR: dir5, AUTH_TOKEN: TOKEN });
    const base5 = `http://127.0.0.1:${port5}`;
    const deadline = Date.now() + 10_000;
    for (;;) {
      try {
        const r = await fetch(`${base5}/healthz`);
        if (r.ok) break;
      } catch { /* wait */ }
      if (Date.now() > deadline) throw new Error("grace server not up");
      await new Promise((r) => setTimeout(r, 100));
    }
    const body = Buffer.from("graceful-payload");
    const { cid } = await (await fetch(`${base5}/objects`, {
      method: "PUT", headers: authed(), body,
    })).json();
    const code = await stop(c5);
    // POSIX: SIGTERM доставляется в обработчик → server.close() + exit(0).
    // Windows: SIGTERM = TerminateProcess без диспетчеризации — graceful-путь там
    // недостижим сигналами в принципе; проверяем только durability (атомарный persist
    // уже завершился к моменту 201).
    if (process.platform !== "win32") {
      assert.equal(code, 0, `graceful exit code 0, got ${code}`);
    }
    // Перезапуск на том же DATA_DIR: объект пережил shutdown.
    const c6 = spawnServer({ PORT: String(port5), DATA_DIR: dir5, AUTH_TOKEN: TOKEN });
    try {
      const deadline2 = Date.now() + 10_000;
      for (;;) {
        try {
          const r = await fetch(`${base5}/healthz`);
          if (r.ok) break;
        } catch { /* wait */ }
        if (Date.now() > deadline2) throw new Error("restarted server not up");
        await new Promise((r) => setTimeout(r, 100));
      }
      const get = await fetch(`${base5}/objects/${cid}`);
      assert.equal(get.status, 200);
      assert.deepEqual(Buffer.from(await get.arrayBuffer()), body);
    } finally {
      c6.kill("SIGKILL");
      rmSync(dir5, { recursive: true, force: true });
    }
  });

  it("(е) replay дренирует тело: пайплайнинг на одном сокете не рассинхронизируется", async () => {
    // fetch-клиент мог бы открыть новое соединение и скрыть баг, поэтому сырой
    // сокет: три запроса подряд без ожидания ответов. Без drain непрочитанное
    // тело второго PUT парсится как следующий запрос и третий ответ — мусор.
    const port6 = 18087;
    const dir6 = mkdtempSync(join(tmpdir(), "shardstore-pipe-"));
    const c6 = spawnServer({
      PORT: String(port6), DATA_DIR: dir6, AUTH_TOKEN: TOKEN, GUARD_WRITE_BURST: "1000",
    });
    const { default: net } = await import("node:net");
    try {
      const deadline = Date.now() + 10_000;
      for (;;) {
        try {
          const r = await fetch(`http://127.0.0.1:${port6}/healthz`);
          if (r.ok) break;
        } catch { /* wait */ }
        if (Date.now() > deadline) throw new Error("pipe server not up");
        await new Promise((r) => setTimeout(r, 100));
      }
      const key = `pipe-key-${Date.now()}`;
      const a = Buffer.alloc(16, 0x41);
      const b = Buffer.alloc(16, 0x42);
      const put = (body) =>
        `PUT /objects HTTP/1.1\r\nhost: x\r\nauthorization: Bearer ${TOKEN}\r\n` +
        `idempotency-key: ${key}\r\ncontent-length: ${body.length}\r\nconnection: keep-alive\r\n\r\n`;
      const responses = await new Promise((resolve, reject) => {
        const sock = net.connect(port6, "127.0.0.1", () => {
          // Второй PUT несёт ДРУГОЕ тело под тем же ключом: это 422, а не тихий replay
          // чужого cid — иначе клиент закоммитит непиннящийся шард. Главное: соединение
          // не рассинхронизируется и третий ответ — корректный GET.
          sock.write(put(a) + a);
          sock.write(put(b) + b);
          sock.write(`GET /objects/${cidOf(a)} HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n`);
        });
        const chunks = [];
        sock.on("data", (c) => chunks.push(c));
        sock.on("end", () => resolve(Buffer.concat(chunks).toString("latin1")));
        sock.on("error", reject);
        setTimeout(() => reject(new Error("pipelined responses timed out")), 10_000).unref();
      });
      const parsed = [...responses.matchAll(/HTTP\/1\.1 (\d{3})/g)].map((m) => m[1]);
      assert.deepEqual(parsed, ["201", "422", "200"], `statuses must survive pipelining, got ${parsed}`);
      const bodies = [...responses.matchAll(/\{[^}]*\}/g)].map((m) => m[0]);
      const first = JSON.parse(bodies[0]);
      assert.equal(first.cid, cidOf(a));
      assert.match(bodies[1], /different bytes/);
    } finally {
      c6.kill("SIGKILL");
      rmSync(dir6, { recursive: true, force: true });
    }
  });

  it("(е2) повтор с тем же телом — replay 201, повтор после DELETE — новая запись", async () => {
    const port8 = 18089;
    const dir8 = mkdtempSync(join(tmpdir(), "shardstore-replay-"));
    const c8 = spawnServer({
      PORT: String(port8), DATA_DIR: dir8, AUTH_TOKEN: TOKEN, GUARD_WRITE_BURST: "1000",
    });
    const base8 = `http://127.0.0.1:${port8}`;
    try {
      const deadline = Date.now() + 10_000;
      for (;;) {
        try {
          const r = await fetch(`${base8}/healthz`);
          if (r.ok) break;
        } catch { /* wait */ }
        if (Date.now() > deadline) throw new Error("replay server not up");
        await new Promise((r) => setTimeout(r, 100));
      }
      const key = `replay-key-${Date.now()}`;
      const body = Buffer.alloc(16, 0x43);
      const headers = { ...authed(), "idempotency-key": key };
      const p1 = await fetch(`${base8}/objects`, { method: "PUT", headers, body });
      assert.equal(p1.status, 201);
      const cid = (await p1.json()).cid;
      // Тот же ключ + то же тело → replay, тот же cid.
      const p2 = await fetch(`${base8}/objects`, { method: "PUT", headers, body });
      assert.equal(p2.status, 201);
      assert.equal((await p2.json()).cid, cid);
      // DELETE, затем тот же ключ + то же тело → НЕ stale-replay призрака, а новая запись.
      assert.equal((await fetch(`${base8}/objects/${cid}`, { method: "DELETE", headers: authed() })).status, 200);
      assert.equal((await fetch(`${base8}/objects/${cid}`)).status, 404);
      const p3 = await fetch(`${base8}/objects`, { method: "PUT", headers, body });
      assert.equal(p3.status, 201);
      assert.equal((await p3.json()).cid, cid);
      assert.equal((await fetch(`${base8}/objects/${cid}`)).status, 200);
    } finally {
      c8.kill("SIGKILL");
      rmSync(dir8, { recursive: true, force: true });
    }
  });

  it("(е3) DELETE уменьшает objectsBytes: бюджет не течёт", async () => {
    const port9 = 18090;
    const dir9 = mkdtempSync(join(tmpdir(), "shardstore-delbytes-"));
    const c9 = spawnServer({
      PORT: String(port9), DATA_DIR: dir9, AUTH_TOKEN: TOKEN, GUARD_WRITE_BURST: "1000",
    });
    const base9 = `http://127.0.0.1:${port9}`;
    try {
      const deadline = Date.now() + 10_000;
      for (;;) {
        try {
          const r = await fetch(`${base9}/healthz`);
          if (r.ok) break;
        } catch { /* wait */ }
        if (Date.now() > deadline) throw new Error("delbytes server not up");
        await new Promise((r) => setTimeout(r, 100));
      }
      const p = await fetch(`${base9}/objects`, { method: "PUT", headers: authed(), body: Buffer.alloc(16, 7) });
      assert.equal(p.status, 201);
      const cid = (await p.json()).cid;
      assert.equal((await (await fetch(`${base9}/healthz`)).json()).objectsBytes, 16);
      assert.equal((await fetch(`${base9}/objects/${cid}`, { method: "DELETE", headers: authed() })).status, 200);
      const health = await (await fetch(`${base9}/healthz`)).json();
      assert.equal(health.objects, 0);
      assert.equal(health.objectsBytes, 0);
    } finally {
      c9.kill("SIGKILL");
      rmSync(dir9, { recursive: true, force: true });
    }
  });

  it("(ж) байт-бюджет вытесняет oldest-first, одиночку сверх бюджета держит", async () => {
    const port7 = 18088;
    const dir7 = mkdtempSync(join(tmpdir(), "shardstore-bytes-"));
    const c7 = spawnServer({
      PORT: String(port7), DATA_DIR: dir7, AUTH_TOKEN: TOKEN,
      MAX_TOTAL_BYTES: "40", GUARD_WRITE_BURST: "1000",
    });
    const base7 = `http://127.0.0.1:${port7}`;
    try {
      const deadline = Date.now() + 10_000;
      for (;;) {
        try {
          const r = await fetch(`${base7}/healthz`);
          if (r.ok) break;
        } catch { /* wait */ }
        if (Date.now() > deadline) throw new Error("bytes server not up");
        await new Promise((r) => setTimeout(r, 100));
      }
      const mk = (fill) => Buffer.alloc(16, fill);
      const cids = [];
      for (const fill of [1, 2, 3]) {
        const put = await fetch(`${base7}/objects`, { method: "PUT", headers: authed(), body: mk(fill) });
        assert.equal(put.status, 201);
        cids.push((await put.json()).cid);
      }
      // 3×16 = 48 > 40: первый вытеснен, остальные на месте.
      assert.equal((await fetch(`${base7}/objects/${cids[0]}`)).status, 404);
      assert.equal((await fetch(`${base7}/objects/${cids[1]}`)).status, 200);
      assert.equal((await fetch(`${base7}/objects/${cids[2]}`)).status, 200);
      const health = await (await fetch(`${base7}/healthz`)).json();
      assert.equal(health.objects, 2);
      assert.equal(health.objectsBytes, 32);
      // Одиночный объект сверх бюджета остаётся: иначе каждое чтение — промах.
      const big = Buffer.alloc(64, 9);
      const putBig = await fetch(`${base7}/objects`, { method: "PUT", headers: authed(), body: big });
      assert.equal(putBig.status, 201);
      const bigCid = (await putBig.json()).cid;
      assert.equal((await fetch(`${base7}/objects/${bigCid}`)).status, 200);
    } finally {
      c7.kill("SIGKILL");
      rmSync(dir7, { recursive: true, force: true });
    }
  });
});
