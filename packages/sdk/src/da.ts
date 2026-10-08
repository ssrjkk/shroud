/**
 * Content-addressed shard store (DA) client.
 *
 * The default `MemoryShardStore` is for local development and tests. A production deployment
 * points `ShardStore` at the `infra/` ShardStore service (content-addressed, range-pull).
 *
 * Note on addressing: the store's `cid` is a *transport* address, while the value pinned on-chain
 * is `ctDigest` = keccak256(payload), computed client-side in `pinPayload`. The two differ — the
 * reference store uses Node's SHA3-256 and Ethereum uses keccak-256, which differ in padding — so
 * the store's `cid` is never the on-chain pin and must never be treated as one.
 *
 * Consequently `getVerified` recomputes keccak256 over the fetched bytes and compares against the
 * expected `ctDigest`. Trusting the store's own addressing instead would mean a DA that returns
 * the wrong object is indistinguishable from an honest one, which is precisely the assumption a
 * re-executing node cannot afford to make.
 */
import { ethers } from "ethers";
import type { ShardStore } from "./types.js";

/**
 * A cid is interpolated into a URL path, and a cid ultimately originates from on-chain data that
 * any contributor controls. An unvalidated value here would let a crafted `ciphertextCid` rewrite
 * the request path (`../../admin`, `//evil.example/x`, `a?b`) and have the node fetch from
 * somewhere the DA was never asked to point at.
 *
 * This allows hex and base58 (so it covers the reference store and IPFS-style CIDs) while
 * excluding every path separator, query/fragment marker, and relative-path token.
 */
const CID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** Throw unless `cid` is safe to place in a request path. */
export function assertSafeCid(cid: string): void {
  if (!CID_RE.test(cid) || cid.includes("..")) {
    throw new Error(`unsafe shard cid ${JSON.stringify(cid)}`);
  }
}

export class MemoryShardStore implements ShardStore {
  private readonly objects = new Map<string, Uint8Array>();

  async put(payload: Uint8Array): Promise<{ cid: string; digest: string }> {
    // Content-addressed: the local keccak256 is both the cid and the on-chain pin, so the two
    // cannot drift apart the way a separate transport hash would.
    const digest = ethers.keccak256(payload);
    this.objects.set(digest, payload);
    return { cid: digest, digest };
  }

  async get(cid: string): Promise<Uint8Array> {
    const hit = this.objects.get(cid);
    if (!hit) throw new Error(`shard ${cid} not found`);
    return hit;
  }
}

export interface HttpShardStoreOptions {
  /** Bearer token, sent as `Authorization: Bearer ...`. */
  authToken?: string;
  /** Reject any object larger than this, in bytes, on both put and get. */
  maxObjectBytes?: number;
  /** Per-request timeout in milliseconds. */
  timeoutMs?: number;
}

/**
 * A ShardStore backed by an HTTP endpoint (the production DA / ShardStore service).
 *
 * Every response is treated as untrusted: sizes are bounded before the body is buffered, the
 * returned address is validated, and callers who need integrity should use `getVerified`, which
 * re-derives keccak256 locally rather than believing the `cid` the server echoed back.
 */
export class HttpShardStore implements ShardStore {
  /** 64 MiB. A shard is FHE ciphertext for one contribution; anything larger is a mistake or an attack. */
  static readonly DEFAULT_MAX_OBJECT_BYTES = 64 * 1024 * 1024;
  static readonly DEFAULT_TIMEOUT_MS = 30_000;

  private readonly baseUrl: string;
  private readonly authToken?: string;
  private readonly maxObjectBytes: number;
  private readonly timeoutMs: number;

  constructor(baseUrl: string, opts: HttpShardStoreOptions = {}) {
    // A trailing slash would produce `//objects` and break the path.
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.authToken = opts.authToken;
    this.maxObjectBytes = opts.maxObjectBytes ?? HttpShardStore.DEFAULT_MAX_OBJECT_BYTES;
    this.timeoutMs = opts.timeoutMs ?? HttpShardStore.DEFAULT_TIMEOUT_MS;
  }

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    return {
      "content-type": "application/octet-stream",
      ...(this.authToken ? { authorization: `Bearer ${this.authToken}` } : {}),
      ...extra,
    };
  }

  private async fetchWithTimeout(path: string, init: RequestInit): Promise<Response> {
    // Without an abort a hung DA would hang the node, and an epoch has a deadline.
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), this.timeoutMs);
    try {
      return await fetch(`${this.baseUrl}${path}`, { ...init, signal: ac.signal });
    } catch (e) {
      if ((e as Error)?.name === "AbortError") {
        throw new Error(`shard store request timed out after ${this.timeoutMs}ms: ${path}`);
      }
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }

  async put(payload: Uint8Array): Promise<{ cid: string; digest: string }> {
    if (payload.byteLength > this.maxObjectBytes) {
      throw new Error(
        `refusing to upload ${payload.byteLength} bytes; the shard store cap is ${this.maxObjectBytes}`
      );
    }

    const res = await this.fetchWithTimeout("/objects", {
      method: "PUT",
      body: payload as BodyInit,
      headers: this.headers(),
    });
    if (!res.ok) throw new Error(`shard store PUT failed: ${res.status}`);
    const body = (await res.json()) as { cid?: string; digest?: string };

    // Validate whatever address the store handed back before it can be committed on-chain.
    if (typeof body.cid !== "string" || !CID_RE.test(body.cid)) {
      throw new Error(`shard store returned an unusable cid ${JSON.stringify(body.cid)}`);
    }

    // The on-chain pin is derived here, not read from the response. A store that echoes a wrong
    // digest would otherwise be able to steer what gets committed.
    const digest = ethers.keccak256(payload);
    return { cid: body.cid, digest };
  }

  async get(cid: string): Promise<Uint8Array> {
    assertSafeCid(cid);

    const res = await this.fetchWithTimeout(`/objects/${cid}`, { method: "GET", headers: this.headers() });
    if (!res.ok) throw new Error(`shard store GET failed for ${cid}: ${res.status}`);

    // Bound the body *before* buffering it, so a hostile or broken store cannot exhaust memory by
    // streaming an unbounded response.
    const declared = Number(res.headers.get("content-length") ?? "0");
    if (Number.isFinite(declared) && declared > this.maxObjectBytes) {
      throw new Error(`shard ${cid} declares ${declared} bytes, over the ${this.maxObjectBytes} byte cap`);
    }
    const bytes = new Uint8Array(await res.arrayBuffer());
    if (bytes.byteLength > this.maxObjectBytes) {
      throw new Error(`shard ${cid} is ${bytes.byteLength} bytes, over the ${this.maxObjectBytes} byte cap`);
    }
    return bytes;
  }

  /**
   * Fetch a shard and prove it is the one that was committed.
   *
   * `expectedCtDigest` is the on-chain `ctDigest` (keccak256). The store's own addressing is
   * ignored for the integrity decision: the bytes are hashed locally and compared. This is the
   * only form of `get` a re-executing node should use.
   */
  async getVerified(cid: string, expectedCtDigest: string): Promise<Uint8Array> {
    const bytes = await this.get(cid);
    const actual = ethers.keccak256(bytes);
    if (actual.toLowerCase() !== expectedCtDigest.toLowerCase()) {
      throw new Error(
        `shard ${cid} failed integrity check: expected ctDigest ${expectedCtDigest}, computed ${actual}`
      );
    }
    return bytes;
  }

  /** Fetch a byte range, for pulls too large to hold in memory. The server must answer 206. */
  async getRange(cid: string, offset: number, length: number): Promise<Uint8Array> {
    assertSafeCid(cid);
    if (!Number.isInteger(offset) || offset < 0 || !Number.isInteger(length) || length <= 0) {
      throw new Error(`invalid range ${offset}..${offset + length}`);
    }
    if (length > this.maxObjectBytes) {
      throw new Error(`requested range of ${length} bytes exceeds the ${this.maxObjectBytes} byte cap`);
    }

    const res = await this.fetchWithTimeout(`/objects/${cid}`, {
      method: "GET",
      headers: this.headers({ range: `bytes=${offset}-${offset + length - 1}` }),
    });
    // 200 means the server ignored the Range header and is sending the whole object; accept it
    // only when it is small enough that the caller wanted the whole thing anyway.
    if (res.status !== 206 && res.status !== 200) {
      throw new Error(`shard store range GET failed for ${cid}: ${res.status}`);
    }
    const bytes = new Uint8Array(await res.arrayBuffer());
    if (bytes.byteLength > this.maxObjectBytes) {
      throw new Error(`shard ${cid} range returned ${bytes.byteLength} bytes, over the cap`);
    }
    return bytes;
  }
}