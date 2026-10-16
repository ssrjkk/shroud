/**
 * Интеграционные доказательства охраны на живом server.mjs.
 * Отдельный файл и порт (18082), т.к. node --test гоняет файлы параллельно.
 * Доказывает end-to-end:
 *  (а) троттлинг записи: N+1-й PUT в окне → 429 + Retry-After;
 *  (б) penalty box: серия 401 → блок с растущим Retry-After;
 *  (в) shadowban: HIGH-субъект с валидным токеном получает правдоподобный 201,
 *      но объект НЕ записан (GET → 404) — изоляция без оракула для атакующего;
 *  (г) идемпотентность: повтор PUT с тем же Idempotency-Key → тот же ответ без
 *      повторной записи (401 без ключа vs 201 с ключом не проверяем — проверяем replay);
 *  (д) graceful shutdown: SIGTERM → процесс завершается кодом 0, данные целы.
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
      // Тот же ключ, другое тело: сервер обязан вернуть ПЕРВЫЙ результат, не писать второе.
      const second = await fetch(`${base4}/objects`, {
        method: "PUT", headers: { ...authed(), "Idempotency-Key": key }, body: Buffer.from("different-bytes"),
      });
      assert.equal(second.status, 201);
      const j2 = await second.json();
      assert.deepEqual(j2, j1);
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
});
