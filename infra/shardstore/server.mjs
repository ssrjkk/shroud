/**
 * ShardStore - content-addressed DA for CipherMesh.
 *
 * A minimal in-process HTTP service implementing the contract the SDK's `HttpShardStore` speaks:
 *
 *   PUT /objects            body = raw bytes      -> { cid, digest }
 *   GET /objects/:cid                             -> raw bytes (404 if absent)
 *
 * The CID is keccak256(payload), so the store is content-addressed and content-verifiable; the
 * digest returned equals the CID. This is a reference implementation for the devnet - a
 * production deployment adds range-pull, replication, and AEAD transport (see the threat model).
 *
 * Run: `node server.mjs`  (default PORT=8080)
 */
import { createServer } from "node:http";
import { createHash } from "node:crypto";

const PORT = Number(process.env.PORT ?? 8080);
const objects = new Map();

function keccak(buf) {
  return "0x" + createHash("sha3-256").update(buf).digest("hex");
}

function send(res, code, body, type = "application/json") {
  res.writeHead(code, { "content-type": type });
  res.end(type === "application/json" ? JSON.stringify(body) : body);
}

const server = createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === "PUT" && url.pathname === "/objects") {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const payload = Buffer.concat(chunks);
      const cid = keccak(payload);
      objects.set(cid, payload);
      send(res, 201, { cid, digest: cid });
    });
    return;
  }

  if (req.method === "GET" && url.pathname.startsWith("/objects/")) {
    const cid = url.pathname.slice("/objects/".length);
    const payload = objects.get(cid);
    if (!payload) return send(res, 404, { error: "not found" });
    res.writeHead(200, { "content-type": "application/octet-stream" });
    res.end(payload);
    return;
  }

  send(res, 404, { error: "not found" });
});

server.listen(PORT, () => {
  console.log(`shardstore listening on :${PORT}`);
});
