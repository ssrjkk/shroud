/**
 * ShardStore - content-addressed DA for Shroud.
 *
 * A minimal HTTP service implementing the contract the SDK's `HttpShardStore` speaks:
 *
 *   PUT /objects            body = raw bytes      -> { cid, digest }
 *   GET /objects/:cid                             -> raw bytes (404 if absent)
 *   GET /objects/:cid  Range: bytes=a-b          -> 206 Partial Content
 *   DELETE /objects/:cid                          -> { deleted: true } (404 if absent)
 *   GET /healthz                                  -> { ok: true, objects: n }
 *
 * Addressing: the CID here is the store's *transport* address (Node's sha3-256). The on-chain
 * pin is a different identifier - `ctDigest`, keccak256(payload), computed by the SDK client -
 * because Ethereum's keccak-256 differs from NIST SHA3-256 in padding and Node's crypto does not
 * expose the former. A re-executing node must therefore recompute keccak256 over the fetched
 * bytes and compare against the on-chain `ctDigest`; `HttpShardStore.getVerified` does exactly
 * that. The DA's cid only needs to be stable.
 *
 * Run: `node server.mjs`
 *   (PORT=8080, DATA_DIR=./data, MAX_OBJECT_BYTES=67108864, MAX_OBJECTS=4096)
 *
 * Authentication is a shared bearer token (`AUTH_TOKEN`). When set, every `PUT` and `DELETE`
 * requires `Authorization: Bearer <token>`; `GET` stays open because objects are
 * content-addressed (the cid is the capability) and readers must never depend on a credential
 * the writers rotate. When unset, writes are open: bind to loopback (the default) and do not
 * expose the port.
 *
 * Memory is bounded (`MAX_OBJECTS`, LRU-evicted, disk copy removed with the entry), and with
 * `DATA_DIR` set the index is rebuilt from disk on boot, so a restart keeps serving what was
 * persisted. Objects evicted from memory are gone even if their file somehow survives: the
 * memory index is the catalogue, the directory is just the backing.
 *
 * TLS is `TLS_CERT` + `TLS_KEY` (PEM paths). Both or neither; without them the server speaks
 * plain HTTP and must sit behind loopback or a terminating proxy.
 */
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { createHash, timingSafeEqual } from "node:crypto";
import { mkdir, writeFile, readFile, stat, unlink, readdir } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const PORT = Number(process.env.PORT ?? 8080);
const HOST = process.env.HOST ?? "127.0.0.1";
// Empty string counts as unset: compose interpolates an absent `.env` entry as `KEY=`, and an
// empty DATA_DIR must mean memory-only, not "a directory named nothing".
const DATA_DIR = process.env.DATA_DIR || null;
const MAX_OBJECT_BYTES = Number(process.env.MAX_OBJECT_BYTES ?? 64 * 1024 * 1024);
const MAX_OBJECTS = Number(process.env.MAX_OBJECTS ?? 4096);
const AUTH_TOKEN = process.env.AUTH_TOKEN || null;
const TLS_CERT = process.env.TLS_CERT || null;
const TLS_KEY = process.env.TLS_KEY || null;

if ((TLS_CERT === null) !== (TLS_KEY === null)) {
  console.error("shardstore: TLS_CERT and TLS_KEY must be set together");
  process.exit(1);
}

/**
 * Objects are addressed by content, so the name is a pure function of the bytes. Restricting the
 * alphabet keeps a name from escaping the directory and keeps `GET /objects/:cid` from being
 * walked with `..`. The `0x` prefix is required because that is exactly what `keccak()` emits and
 * what the SDK sends; accepting a bare hash here would mean two spellings of one object.
 */
const CID_RE = /^0x[0-9a-f]{64}$/;
const FILE_RE = /^[0-9a-f]{64}$/;

/** Insertion-ordered catalogue: the tail is the most recently used, the head is evicted first. */
const objects = new Map();

function keccak(buf) {
  // Named for what the SDK expects to be compared against. This is SHA3-256, not keccak-256;
  // see the addressing note above.
  return "0x" + createHash("sha3-256").update(buf).digest("hex");
}

function send(res, code, body, type = "application/json") {
  res.writeHead(code, { "content-type": type });
  res.end(type === "application/json" ? JSON.stringify(body) : body);
}

/** Writes need the bearer token when one is configured; reads never do (see header). */
function authorised(req) {
  if (AUTH_TOKEN === null) return true;
  const header = req.headers.authorization ?? "";
  const prefix = "Bearer ";
  if (!header.startsWith(prefix)) return false;
  const presented = Buffer.from(header.slice(prefix.length));
  const expected = Buffer.from(AUTH_TOKEN);
  return presented.length === expected.length && timingSafeEqual(presented, expected);
}

/** Parse a single-range `Range: bytes=a-b` header. Returns null when absent or malformed. */
function parseRange(header) {
  if (!header) return null;
  const m = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!m) return undefined; // present but unusable -> caller answers 416
  const [, rawStart, rawEnd] = m;
  if (rawStart === "") return undefined; // suffix ranges are not supported
  const start = Number(rawStart);
  const end = rawEnd === "" ? Number.MAX_SAFE_INTEGER : Number(rawEnd);
  if (!Number.isSafeInteger(start) || start < 0) return undefined;
  return { start, end: Math.min(end, start + MAX_OBJECT_BYTES - 1) };
}

function storePath(cid) {
  return DATA_DIR ? join(DATA_DIR, cid.slice(2)) : null;
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

/** Rebuild the catalogue from files written by earlier runs, oldest first (LRU order). */
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
  entries.sort((a, b) => a.mtime - b.mtime);
  for (const { name } of entries) {
    try {
      objects.set(`0x${name}`, await readFile(join(DATA_DIR, name)));
    } catch {
      // Unreadable now: skip rather than serve half an object later.
    }
  }
  await enforceCapacity();
}

const server = (TLS_CERT ? createHttpsServer : createHttpServer)(
  ...(TLS_CERT ? [{ cert: readFileSync(TLS_CERT), key: readFileSync(TLS_KEY) }] : []),
  async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host ?? "localhost"}`);

    if (req.method === "GET" && url.pathname === "/healthz") {
      return send(res, 200, { ok: true, objects: objects.size });
    }

    if (req.method === "PUT" && url.pathname === "/objects") {
      if (!authorised(req)) return send(res, 401, { error: "unauthorised" });
      const chunks = [];
      let size = 0;
      let aborted = false;

      req.on("data", (c) => {
        if (aborted) return;
        size += c.length;
        // Bound the body as it arrives. Without this the process grows until it is OOM-killed,
        // which takes the DA down for every node at once.
        if (size > MAX_OBJECT_BYTES) {
          aborted = true;
          send(res, 413, { error: "object too large" });
          req.destroy();
          return;
        }
        chunks.push(c);
      });

      req.on("end", async () => {
        if (aborted) return;
        const payload = Buffer.concat(chunks);
        const cid = keccak(payload);
        // Refresh LRU position on rewrite: a re-put object is hot by definition.
        objects.delete(cid);
        objects.set(cid, payload);
        if (DATA_DIR) {
          try {
            await mkdir(DATA_DIR, { recursive: true });
            await writeFile(storePath(cid), payload);
          } catch (e) {
            // In-memory put already succeeded; surface the durability failure rather than pretend
            // the object is safely stored, because it will vanish on restart.
            console.error(`shardstore: persist ${cid} failed: ${e.message}`);
            return send(res, 500, { error: "persist failed" });
          }
        }
        await enforceCapacity();
        send(res, 201, { cid, digest: cid });
      });
      return;
    }

    if (req.method === "DELETE" && url.pathname.startsWith("/objects/")) {
      if (!authorised(req)) return send(res, 401, { error: "unauthorised" });
      const cid = url.pathname.slice("/objects/".length).toLowerCase();
      if (!CID_RE.test(cid)) return send(res, 400, { error: "bad cid" });
      if (!objects.has(cid)) return send(res, 404, { error: "not found" });
      objects.delete(cid);
      if (DATA_DIR) {
        try {
          await unlink(storePath(cid));
        } catch {
          // Memory is authoritative; a missing file changes nothing.
        }
      }
      send(res, 200, { deleted: true });
      return;
    }

    if (req.method === "GET" && url.pathname.startsWith("/objects/")) {
      const cid = url.pathname.slice("/objects/".length).toLowerCase();
      if (!CID_RE.test(cid)) return send(res, 400, { error: "bad cid" });

      const serve = async () => {
        let payload = objects.get(cid);
        // Refresh LRU position on read: hot objects must not be evicted under cold ones.
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
        if (!payload) return send(res, 404, { error: "not found" });

        const range = parseRange(req.headers.range);
        if (range === undefined) {
          res.writeHead(416, { "content-range": `bytes */${payload.length}` });
          return res.end();
        }
        if (range) {
          const end = Math.min(range.end, payload.length - 1);
          if (range.start > end) {
            res.writeHead(416, { "content-range": `bytes */${payload.length}` });
            return res.end();
          }
          const slice = payload.subarray(range.start, end + 1);
          res.writeHead(206, {
            "content-type": "application/octet-stream",
            "content-range": `bytes ${range.start}-${end}/${payload.length}`,
            "content-length": String(slice.length),
          });
          return res.end(slice);
        }

        res.writeHead(200, {
          "content-type": "application/octet-stream",
          "content-length": String(payload.length),
        });
        res.end(payload);
      };

      serve().catch((e) => {
        console.error(`shardstore: read failed: ${e.message}`);
        if (!res.headersSent) send(res, 500, { error: "read failed" });
      });
      return;
    }

    send(res, 404, { error: "not found" });
  }
);

await rebuildIndex();
server.listen(PORT, HOST, () => {
  const bound = server.address();
  const port = typeof bound === "object" && bound !== null ? bound.port : PORT;
  console.log(`shardstore listening on ${HOST}:${port}`);
  if (!DATA_DIR) console.log("shardstore: DATA_DIR unset, objects are memory-only and lost on restart");
  if (AUTH_TOKEN === null) console.log("shardstore: AUTH_TOKEN unset, writes are unauthenticated");
  if (HOST === "0.0.0.0" && AUTH_TOKEN === null)
    console.log("shardstore: WARNING bound to all interfaces with no authentication");
});
