import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { keccak256Hex } from "./keccak.mjs";

const DIR = dirname(fileURLToPath(import.meta.url));
const PORT = 18081;
const BASE = `http://127.0.0.1:${PORT}`;
const TOKEN = "test-token-abc";

function cidOf(bytes) {
  return keccak256Hex(bytes);
}

async function waitHealthy(extraEnv = {}) {
  const { AUTH_TOKEN: _ambient, ...clean } = process.env;
  const env = { ...clean, PORT: String(PORT), ...extraEnv };
  const child = spawn("node", [join(DIR, "server.mjs")], { env, stdio: ["ignore", "pipe", "pipe"] });
  const deadline = Date.now() + 10_000;
  for (;;) {
    try {
      const r = await fetch(`${BASE}/healthz`);
      if (r.ok) return child;
    } catch {
      // not up yet
    }
    if (Date.now() > deadline) {
      child.kill();
      throw new Error("shardstore did not become healthy in time");
    }
    await new Promise((r) => setTimeout(r, 100));
  }
}

function authed(token = TOKEN) {
  return { Authorization: `Bearer ${token}` };
}

describe("shardstore", () => {
  let child;
  let dataDir;

  before(async () => {
    dataDir = mkdtempSync(join(tmpdir(), "shardstore-test-"));
    child = await waitHealthy({ DATA_DIR: dataDir, AUTH_TOKEN: TOKEN, MAX_OBJECTS: "3" });
  });

  after(() => {
    child?.kill();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("round-trips PUT then GET with matching digest", async () => {
    const body = Buffer.from("hello-shard");
    const put = await fetch(`${BASE}/objects`, { method: "PUT", headers: authed(), body });
    assert.equal(put.status, 201);
    const { cid, digest } = await put.json();
    assert.equal(cid, cidOf(body));
    assert.equal(digest, cid);

    const get = await fetch(`${BASE}/objects/${cid}`);
    assert.equal(get.status, 200);
    assert.deepEqual(Buffer.from(await get.arrayBuffer()), body);
  });

  it("rejects empty objects: they would pollute the LRU catalogue", async () => {
    // keccak256("") is 0xc5d2... but empty PUTs are rejected — 4096 empties would
    // otherwise evict legit shards. The digest function itself is covered in keccak.test.mjs.
    const empty = await fetch(`${BASE}/objects`, { method: "PUT", headers: authed(), body: Buffer.alloc(0) });
    assert.equal(empty.status, 400);
  });

  it("reads without a token: the cid is the capability", async () => {
    const body = Buffer.from("open-read");
    const cid = cidOf(body);
    await fetch(`${BASE}/objects`, { method: "PUT", headers: authed(), body });
    const get = await fetch(`${BASE}/objects/${cid}`);
    assert.equal(get.status, 200);
  });

  it("rejects writes without or with a wrong token", async () => {
    const body = Buffer.from("nope");
    const cid = cidOf(body);
    assert.equal((await fetch(`${BASE}/objects`, { method: "PUT", body })).status, 401);
    assert.equal((await fetch(`${BASE}/objects`, { method: "PUT", headers: authed("wrong"), body })).status, 401);
    assert.equal((await fetch(`${BASE}/objects/${cid}`, { method: "DELETE" })).status, 401);
    assert.equal((await fetch(`${BASE}/objects/${cid}`)).status, 404);
  });

  it("rejects malformed cids and misses with 400/404", async () => {
    assert.equal((await fetch(`${BASE}/objects/xyz`)).status, 400);
    assert.equal((await fetch(`${BASE}/objects/0xab`)).status, 400);
    assert.equal((await fetch(`${BASE}/objects/${cidOf(Buffer.from("absent"))}`)).status, 404);
  });

  it("serves byte ranges and 416s the unusable ones", async () => {
    const body = Buffer.from("0123456789");
    const put = await fetch(`${BASE}/objects`, { method: "PUT", headers: authed(), body });
    const { cid } = await put.json();
    const part = await fetch(`${BASE}/objects/${cid}`, { headers: { Range: "bytes=2-5" } });
    assert.equal(part.status, 206);
    assert.equal(part.headers.get("content-range"), `bytes 2-5/${body.length}`);
    assert.equal(await part.text(), "2345");
    const bad = await fetch(`${BASE}/objects/${cid}`, { headers: { Range: "bytes=99-100" } });
    assert.equal(bad.status, 416);
  });

  it("advertises range support and a content-derived ETag on 200 and 206", async () => {
    // A client can only resume/revalidate when the server says it speaks ranges and
    // names a validator. The ETag is the keccak cid itself: content-addressed objects
    // never change under one address, so it is trivially strong.
    const body = Buffer.from("etag-fixture");
    const { cid } = await (await fetch(`${BASE}/objects`, { method: "PUT", headers: authed(), body })).json();
    const full = await fetch(`${BASE}/objects/${cid}`);
    assert.equal(full.status, 200);
    assert.equal(full.headers.get("accept-ranges"), "bytes");
    assert.equal(full.headers.get("etag"), `"${cid}"`);
    await full.arrayBuffer();
    const part = await fetch(`${BASE}/objects/${cid}`, { headers: { Range: "bytes=0-3" } });
    assert.equal(part.status, 206);
    assert.equal(part.headers.get("accept-ranges"), "bytes");
    assert.equal(part.headers.get("etag"), `"${cid}"`);
    assert.equal(part.headers.get("content-range"), `bytes 0-3/${body.length}`);
    await part.arrayBuffer();
  });

  it("answers 304 when the client already holds the ETag", async () => {
    // Conditional GET saves a re-download: a matching If-None-Match (or *) returns
    // no body. A stale tag still gets the bytes. CIDs are content addresses, so a
    // match always means identical bytes — no weak-comparison pitfalls.
    const body = Buffer.from("etag-revalidate");
    const { cid } = await (await fetch(`${BASE}/objects`, { method: "PUT", headers: authed(), body })).json();
    const fresh = await fetch(`${BASE}/objects/${cid}`, { headers: { "If-None-Match": `"${cid}"` } });
    assert.equal(fresh.status, 304);
    assert.equal(fresh.headers.get("etag"), `"${cid}"`);
    assert.equal((await fresh.arrayBuffer()).byteLength, 0);
    const star = await fetch(`${BASE}/objects/${cid}`, { headers: { "If-None-Match": "*" } });
    assert.equal(star.status, 304);
    await star.arrayBuffer();
    const stale = await fetch(`${BASE}/objects/${cid}`, {
      headers: { "If-None-Match": '"0x0000000000000000000000000000000000000000000000000000000000000000"' },
    });
    assert.equal(stale.status, 200);
    assert.deepEqual(Buffer.from(await stale.arrayBuffer()), body);
  });

  it("serves suffix ranges per RFC 9110", async () => {
    const body = Buffer.from("0123456789");
    const put = await fetch(`${BASE}/objects`, { method: "PUT", headers: authed(), body });
    const { cid } = await put.json();
    const tail = await fetch(`${BASE}/objects/${cid}`, { headers: { Range: "bytes=-4" } });
    assert.equal(tail.status, 206);
    assert.equal(tail.headers.get("content-range"), `bytes 6-9/${body.length}`);
    assert.equal(await tail.text(), "6789");
    // Суффикс длиннее объекта — весь объект; пустой суффикс — 416.
    const whole = await fetch(`${BASE}/objects/${cid}`, { headers: { Range: "bytes=-100" } });
    assert.equal(whole.status, 206);
    assert.equal(await whole.text(), "0123456789");
    assert.equal((await fetch(`${BASE}/objects/${cid}`, { headers: { Range: "bytes=-0" } })).status, 416);
  });

  it("deletes objects and their disk copies", async () => {
    const body = Buffer.from("ephemeral");
    const { cid } = await (
      await fetch(`${BASE}/objects`, { method: "PUT", headers: authed(), body })
    ).json();
    const del = await fetch(`${BASE}/objects/${cid}`, { method: "DELETE", headers: authed() });
    assert.equal(del.status, 200);
    assert.equal((await fetch(`${BASE}/objects/${cid}`)).status, 404);
    assert.equal((await fetch(`${BASE}/objects/${cid}`, { method: "DELETE", headers: authed() })).status, 404);
  });

  it("evicts least-recently-used entries past MAX_OBJECTS", async () => {
    // MAX_OBJECTS=3 for this server; earlier tests already hold entries, so push past the cap
    // and confirm the catalogue (and health count) stays bounded.
    for (let i = 0; i < 5; i++) {
      await fetch(`${BASE}/objects`, { method: "PUT", headers: authed(), body: Buffer.from(`gc-${i}`) });
    }
    const health = await (await fetch(`${BASE}/healthz`)).json();
    assert.equal(health.ok, true);
    assert.ok(health.objects <= 3, `catalogue bounded, got ${health.objects}`);
    assert.equal((await fetch(`${BASE}/objects/${cidOf(Buffer.from("gc-0"))}`)).status, 404);
  });

  it("rebuilds the index from disk across a restart", async () => {
    const body = Buffer.from("survives-restart");
    const { cid } = await (
      await fetch(`${BASE}/objects`, { method: "PUT", headers: authed(), body })
    ).json();
    child.kill();
    child = await waitHealthy({ DATA_DIR: dataDir, AUTH_TOKEN: TOKEN, MAX_OBJECTS: "3" });
    const get = await fetch(`${BASE}/objects/${cid}`);
    assert.equal(get.status, 200);
    assert.deepEqual(Buffer.from(await get.arrayBuffer()), body);
  });
});
