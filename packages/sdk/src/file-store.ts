/**
 * File-backed shard store (DA) client.
 *
 * Node-only: this module imports `node:fs` and is therefore a separate entry point
 * (`@shroud/sdk/file-store`), not part of the browser-safe `index.js`. Same `ShardStore`
 * interface as `MemoryShardStore`, but objects survive restarts: each payload is a file named
 * by its keccak256 digest under `dir`, written atomically (temp + rename) so a crash never
 * leaves a torn object behind.
 *
 * Like `MemoryShardStore`, the cid *is* the keccak256 digest here, so cid and on-chain pin
 * cannot drift apart. Unlike the memory store, `get` re-reads from disk every time: the
 * directory is the authority, which keeps multi-process use (SDK uploads next to a node
 * reading the same dir) coherent without any cache-invalidation protocol.
 */
import { mkdirSync, readFileSync, renameSync, writeFileSync, existsSync } from "node:fs";
import { join, sep } from "node:path";
import { ethers } from "ethers";
import type { ShardStore } from "./types.js";

export interface FileShardStoreOptions {
  /** Refuse to store or serve objects larger than this, in bytes. */
  maxObjectBytes?: number;
}

export class FileShardStore implements ShardStore {
  /** 64 MiB, mirroring the reference service: anything larger is a mistake or an attack. */
  static readonly DEFAULT_MAX_OBJECT_BYTES = 64 * 1024 * 1024;

  private readonly dir: string;
  private readonly maxObjectBytes: number;

  constructor(dir: string, opts: FileShardStoreOptions = {}) {
    if (!dir || dir.includes("\0")) throw new Error(`invalid shard directory ${JSON.stringify(dir)}`);
    this.dir = dir;
    this.maxObjectBytes = opts.maxObjectBytes ?? FileShardStore.DEFAULT_MAX_OBJECT_BYTES;
    mkdirSync(dir, { recursive: true });
  }

  private pathFor(digest: string): string {
    // `digest` is always a `0x`-prefixed 32-byte hex string this class computed itself (see
    // `put`), never a caller-supplied path — but `get` takes arbitrary cids, so validate here
    // rather than trusting either call site.
    if (!/^0x[0-9a-fA-F]{64}$/.test(digest) || digest.includes(sep) || digest.includes("..")) {
      throw new Error(`unsafe shard digest ${JSON.stringify(digest)}`);
    }
    return join(this.dir, digest.slice(2));
  }

  async put(payload: Uint8Array): Promise<{ cid: string; digest: string }> {
    if (payload.byteLength > this.maxObjectBytes) {
      throw new Error(
        `refusing to store ${payload.byteLength} bytes; the shard cap is ${this.maxObjectBytes}`
      );
    }
    const digest = ethers.keccak256(payload);
    const path = this.pathFor(digest);
    if (!existsSync(path)) {
      // Temp + rename: a concurrent reader either sees the old state (absent) or the complete
      // new file, never a half-written one.
      const tmp = `${path}.${process.pid}.tmp`;
      writeFileSync(tmp, payload);
      renameSync(tmp, path);
    }
    return { cid: digest, digest };
  }

  async get(cid: string): Promise<Uint8Array> {
    // Validated outside the try: a hostile cid must fail as hostile, never be relabelled
    // "not found" by the read-error handler below.
    const path = this.pathFor(cid);
    let bytes: Buffer;
    try {
      bytes = readFileSync(path);
    } catch {
      throw new Error(`shard ${cid} not found`);
    }
    if (bytes.byteLength > this.maxObjectBytes) {
      throw new Error(`shard ${cid} is ${bytes.byteLength} bytes, over the ${this.maxObjectBytes} byte cap`);
    }
    // A copy, not a view: `new Uint8Array(buffer)` would alias Node's 8 KiB pool past the
    // object's own bytes, and callers comparing or hashing the result would read garbage.
    return Uint8Array.from(bytes);
  }

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
}
