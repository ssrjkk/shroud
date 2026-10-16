/**
 * Content-addressed shard store (DA) client.
 *
 * The default `MemoryShardStore` is for local development and tests. A production deployment
 * points `ShardStore` at the `infra/` ShardStore service (content-addressed, range-pull).
 *
 * Note on addressing: a store's `cid` is a *transport* address and may be anything the store
 * chooses to call an object, while the value pinned on chain is `ctDigest` = keccak256(payload),
 * computed client-side in `pinPayload`. The development stores below mirror the production
 * split on purpose: `cid` = sha256(payload) (the transport address), `digest` =
 * keccak256(payload) (the on-chain pin, which is also what the reference service returns).
 * They are different identifiers for the same bytes — and a store's `cid` must never be
 * treated as the pin. An earlier revision used keccak256 for both, which hid exactly the
 * confusion production punishes: code that compared `cid` against `ctDigest` passed in dev
 * and failed live.
 *
 * Consequently `getVerified` recomputes keccak256 over the fetched bytes and compares against the
 * expected `ctDigest`. Trusting the store's own addressing instead would mean a DA that returns
 * the wrong object is indistinguishable from an honest one, which is precisely the assumption a
 * re-executing node cannot afford to make. It is part of the `ShardStore` interface rather than an
 * extra on the HTTP client, because verifying is the one thing a node always has to do.
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

/** Throw unless `bytes` are the object `expectedCtDigest` pins, naming the address that failed. */
function assertDigest(bytes: Uint8Array, expectedCtDigest: string, cid: string): void {
  const actual = ethers.keccak256(bytes);
  if (actual.toLowerCase() !== expectedCtDigest.toLowerCase()) {
    throw new Error(
      `shard ${cid} failed integrity check: expected ctDigest ${expectedCtDigest}, computed ${actual}`
    );
  }
}

export class MemoryShardStore implements ShardStore {
  private readonly objects = new Map<string, Uint8Array>();

  async put(payload: Uint8Array): Promise<{ cid: string; digest: string }> {
    // Content-addressed, with the production split: the transport address is sha256, the
    // on-chain pin is keccak256. Using keccak256 for both here once hid cid/digest confusion
    // that only failed live.
    // Copied on the way in and on the way out (see FileShardStore): the caller keeps a live
    // reference otherwise, and mutating it afterwards would corrupt every later read —
    // including another party's `getVerified` in the same process.
    const bytes = Uint8Array.from(payload);
    const cid = ethers.sha256(bytes);
    const digest = ethers.keccak256(bytes);
    this.objects.set(cid, bytes);
    return { cid, digest };
  }

  async get(cid: string): Promise<Uint8Array> {
    const hit = this.objects.get(cid);
    if (!hit) throw new Error(`shard ${cid} not found`);
    return Uint8Array.from(hit);
  }

  async getVerified(cid: string, expectedCtDigest: string): Promise<Uint8Array> {
    const bytes = await this.get(cid);
    // Checked rather than assumed: an in-process store is used in tests alongside a forged or
    // mistyped commit, and the node code under test must see the same behaviour here as it does
    // against the HTTP store.
    assertDigest(bytes, expectedCtDigest, cid);
    return bytes;
  }
}

export interface HttpShardStoreOptions {
  /** Bearer token, sent as `Authorization: Bearer ...`. */
  authToken?: string;
  /** Reject any object larger than this, in bytes, on both put and get. */
  maxObjectBytes?: number;
  /** Per-request timeout in milliseconds. */
  timeoutMs?: number;
  /**
   * Retries after the first attempt (default 3). Retried: network-level failures,
   * timeouts, HTTP 429 and 5xx. Never retried: 4xx (other than 429), size caps,
   * digest mismatches, assertion failures. Retrying a PUT is safe: the store is
   * content-addressed, so re-sending the same bytes addresses the same object.
   */
  maxRetries?: number;
  /** Base backoff in milliseconds (default 200): sleep before attempt n is
   * `rand() * base * 2^(n-1)` — exponential backoff with full jitter, so a fleet
   * of nodes does not re-hit a recovering DA in lockstep. */
  retryBaseMs?: number;
}

/**
 * Retryable iff the failure might pass on its own: a dead socket, an expired timeout,
 * an overloaded store (429/5xx). Anything the store decided deliberately (400/404/size
 * caps) or that failed locally (digest mismatch, assertions) is permanent.
 */
function isRetryableFetchError(e: unknown): boolean {
  // Undici/network-level: DNS, refused, reset, aborted.
  if (e instanceof TypeError) return true;
  const m = e instanceof Error ? e.message : String(e);
  if (/timed out after \d+ms/.test(m)) return true;
  return /: (429|5\d\d)\b/.test(m);
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
  private readonly maxRetries: number;
  private readonly retryBaseMs: number;

  constructor(baseUrl: string, opts: HttpShardStoreOptions = {}) {
    // A trailing slash would produce `//objects` and break the path.
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.authToken = opts.authToken;
    this.maxObjectBytes = opts.maxObjectBytes ?? HttpShardStore.DEFAULT_MAX_OBJECT_BYTES;
    this.timeoutMs = opts.timeoutMs ?? HttpShardStore.DEFAULT_TIMEOUT_MS;
    this.maxRetries = opts.maxRetries ?? 3;
    this.retryBaseMs = opts.retryBaseMs ?? 200;
  }

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    return {
      "content-type": "application/octet-stream",
      ...(this.authToken ? { authorization: `Bearer ${this.authToken}` } : {}),
      ...extra,
    };
  }

  /**
   * One request with retries. The attempt budget is attempts, not time: with the defaults
   * (3 retries, 200ms base) the worst case sleeps ~200+400+800ms of jittered backoff, which
   * is what keeps an epoch with a deadline from waiting on a DA that will never answer.
   */
  private async request<T>(
    path: string,
    init: RequestInit,
    consume: (res: Response) => Promise<T>
  ): Promise<T> {
    let last: unknown;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        const backoff = Math.random() * this.retryBaseMs * 2 ** (attempt - 1);
        await new Promise((r) => setTimeout(r, backoff));
      }
      try {
        return await this.withTimeout(path, init, consume);
      } catch (e) {
        last = e;
        if (!isRetryableFetchError(e)) throw e;
      }
    }
    throw last;
  }

  /**
   * Request `path` and consume its response inside the timeout window.
   *
   * The body read has to be inside the window, not just the header exchange: an epoch has a
   * deadline, and a DA that sends a `content-length` and then stalls mid-body would otherwise hang
   * the node forever with the abort timer already cleared.
   */
  private async withTimeout<T>(
    path: string,
    init: RequestInit,
    consume: (res: Response) => Promise<T>
  ): Promise<T> {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), this.timeoutMs);
    try {
      const res = await fetch(`${this.baseUrl}${path}`, { ...init, signal: ac.signal });
      return await consume(res);
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

    const body = await this.request("/objects", {
      method: "PUT",
      body: payload as BodyInit,
      headers: this.headers(),
    }, async (res) => {
      if (!res.ok) throw new Error(`shard store PUT failed: ${res.status}`);
      return (await res.json()) as { cid?: string; digest?: string };
    });

    // Validate whatever address the store handed back before it can be committed on-chain.
    // `assertSafeCid`, not a bare regex: the regex alone admits "a.." (dots are legal
    // inside), which `get` would then refuse — a store could hand back a CID that commits
    // fine and never reads back. One validator for both directions, no drift.
    if (typeof body.cid !== "string") {
      throw new Error(`shard store returned an unusable cid ${JSON.stringify(body.cid)}`);
    }
    assertSafeCid(body.cid);

    // The on-chain pin is derived here, not read from the response. A store that echoes a wrong
    // digest would otherwise be able to steer what gets committed.
    const digest = ethers.keccak256(payload);
    return { cid: body.cid, digest };
  }

  async get(cid: string): Promise<Uint8Array> {
    assertSafeCid(cid);

    return this.request(
      `/objects/${cid}`,
      { method: "GET", headers: this.headers() },
      async (res) => {
        if (!res.ok) throw new Error(`shard store GET failed for ${cid}: ${res.status}`);

        // Bound the body *before* buffering it, so a hostile or broken store cannot exhaust memory
        // by streaming an unbounded response.
        const declared = Number(res.headers.get("content-length") ?? "0");
        if (Number.isFinite(declared) && declared > this.maxObjectBytes) {
          throw new Error(`shard ${cid} declares ${declared} bytes, over the ${this.maxObjectBytes} byte cap`);
        }
        // The declared length is the store's own claim and may be absent or a lie: enforce the
        // cap while pulling, chunk by chunk, and cancel the stream the moment it fires instead
        // of buffering the attacker's whole body first and checking afterwards.
        return this.readCapped(res, this.maxObjectBytes, `shard ${cid}`);
      }
    );
  }

  /**
   * Pull a response body without ever holding more than `cap` bytes.
   *
   * Reads the stream chunk by chunk and cancels it as soon as the running total passes the
   * cap, so a store that declares 100 bytes and then streams gigabytes costs us `cap` bytes
   * of memory, not gigabytes. Without the cancel the producer would keep flowing into the
   * socket buffer after the cap already fired.
   */
  private async readCapped(res: Response, cap: number, what: string): Promise<Uint8Array> {
    const body = res.body;
    if (!body) return new Uint8Array(await res.arrayBuffer());
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done || !value) break;
        size += value.byteLength;
        if (size > cap) {
          throw new Error(`${what} is over the ${cap} byte cap (stopped pulling after ${size} streamed bytes)`);
        }
        chunks.push(value);
      }
    } finally {
      try {
        await reader.cancel();
      } catch {
        // Already closed or errored: nothing left to stop.
      }
      reader.releaseLock();
    }
    const out = new Uint8Array(size);
    let off = 0;
    for (const c of chunks) {
      out.set(c, off);
      off += c.byteLength;
    }
    return out;
  }

  /**
   * Fetch a shard and prove it is the one that was committed.
   *
   * `expectedCtDigest` is the on-chain `ctDigest` (keccak256). The store's own addressing is
   * ignored for the integrity decision: the bytes are hashed locally and compared.
   */
  async getVerified(cid: string, expectedCtDigest: string): Promise<Uint8Array> {
    const bytes = await this.get(cid);
    assertDigest(bytes, expectedCtDigest, cid);
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

    const bytes = await this.request(
      `/objects/${cid}`,
      { method: "GET", headers: this.headers({ range: `bytes=${offset}-${offset + length - 1}` }) },
      async (res) => {
        if (res.status !== 200 && res.status !== 206) {
          throw new Error(`shard store range GET failed for ${cid}: ${res.status}`);
        }
        // Bounded like every other read: a range pull that ignored the cap would let one
        // malicious chunk eat memory proportional to the stream, not to the window.
        const body = await this.readCapped(
          res,
          this.maxObjectBytes,
          `range ${offset}..${offset + length - 1} of ${cid}`
        );

        // A `200` means the server ignored `Range` and sent the whole object, which is only the
        // answer to this request when the window *is* the object from its start. Accepting anything
        // else would let a chunked pull reassemble the object's first bytes at every offset: a
        // shard of the right length, whose CID resolves, whose contents are wrong.
        if (res.status === 200) {
          if (offset !== 0 || body.byteLength > length) {
            throw new Error(
              `shard store sent ${body.byteLength} bytes with status 200 for range ` +
                `${offset}..${offset + length - 1} of ${cid}; it ignored the Range header`
            );
          }
          return body;
        }

        // On a 206 the header is what proves the bytes belong at this offset. A short final chunk
        // is normal, so the length alone cannot tell an honest tail from an ignored Range — and a
        // 206 without the header cannot tell a truncated honest chunk from a hostile prefix
        // served at the wrong offset. RFC 9110 requires Content-Range on every 206, and the
        // reference server always sends it, so a missing header is a hard failure, not leniency.
        const contentRange = res.headers.get("content-range");
        if (!contentRange) {
          throw new Error(
            `shard store answered 206 for range ${offset}..${offset + length - 1} of ${cid} ` +
              `without a content-range header`
          );
        }
        {
          const matched = /^bytes (\d+)-(\d+)\/(?:\d+|\*)$/.exec(contentRange);
          const start = matched ? Number(matched[1]) : Number.NaN;
          const end = matched ? Number(matched[2]) : Number.NaN;
          if (start !== offset || end - start + 1 !== body.byteLength) {
            throw new Error(
              `shard store answered content-range ${JSON.stringify(contentRange)} for range ` +
                `${offset}..${offset + length - 1} of ${cid}`
            );
          }
        }
        return body;
      }
    );
    return bytes;
  }
}