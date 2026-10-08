/**
 * ShardStore - content-addressed DA for Shroud.
 *
 * A minimal HTTP service implementing the contract the SDK's `HttpShardStore` speaks:
 *
 *   PUT /objects            body = raw bytes      -> { cid, digest }
 *   GET /objects/:cid                             -> raw bytes (404 if absent)
 *   GET /objects/:cid  Range: bytes=a-b          -> 206 Partial Content
 *
 * Addressing: the CID here is the store's *transport* address (Node's sha3-256). The on-chain
 * pin is a different identifier - `ctDigest`, keccak256(payload), computed by the SDK client -
 * because Ethereum's keccak-256 differs from NIST SHA3-256 in padding and Node's crypto does not
 * expose the former. A re-executing node must therefore recompute keccak256 over the fetched
 * bytes and compare against the on-chain `ctDigest`; `HttpShardStore.getVerified` does exactly
 * that. The DA's cid only needs to be stable.
 *
 * Run: `node server.mjs`  (PORT=8080, DATA_DIR=./data, MAX_OBJECT_BYTES=67108864)
 *
 * This is a development service. It is single-process and holds objects in memory, so restarting
 * it loses every shard; it enforces no authentication. It must not be exposed to an untrusted
 * network — see docs/05.
 */
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { mkdir, writeFile, readFile, stat } from "node:fs/promises";
import { join } from "node:path";

const PORT = Number(process.env.PORT ?? 8080);
const HOST = process.env.HOST ?? "127.0.0.1";
const DATA_DIR = process.env.DATA_DIR ?? null;
const MAX_OBJECT_BYTES = Number(process.env.MAX_OBJECT_BYTES ?? 64 * 1024 * 1024);

/**
 * Objects are addressed by content, so the name is a pure function of the bytes. Restricting the
 * alphabet keeps a name from escaping the directory and keeps `GET /objects/:cid` from being
 * walked with `..`. The `0x` prefix is required because that is exactly what `keccak()` emits and
 * what the SDK sends; accepting a bare hash here would mean two spellings of one object.
 */
const CID_RE = /^0x[0-9a-f]{64}$/;

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

const server = createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host ?? "localhost"}`);

  if (req.method === "PUT" && url.pathname === "/objects") {
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
      send(res, 201, { cid, digest: cid });
    });
    return;
  }

  if (req.method === "GET" && url.pathname.startsWith("/objects/")) {
    const cid = url.pathname.slice("/objects/".length).toLowerCase();
    if (!CID_RE.test(cid)) return send(res, 400, { error: "bad cid" });

    const serve = async () => {
      let payload = objects.get(cid);

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
});

server.listen(PORT, HOST, () => {
  console.log(`shardstore listening on ${HOST}:${PORT}`);
  if (!DATA_DIR) console.log("shardstore: DATA_DIR unset, objects are memory-only and lost on restart");
  if (HOST === "0.0.0.0") console.log("shardstore: WARNING bound to all interfaces with no authentication");
});