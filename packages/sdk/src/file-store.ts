/**
 * File-backed shard store (DA) client.
 *
 * Node-only: this module imports `node:fs` and is therefore a separate entry point
 * (`@shroud/sdk/file-store`), not part of the browser-safe `index.js`. Same `ShardStore`
 * interface as `MemoryShardStore`, but objects survive restarts: each payload is a file
 * named by its transport cid (sha256, see `put`) under `dir`, written atomically
 * (temp + rename) so a crash never leaves a torn object behind.
 *
 * Like `MemoryShardStore`, the cid (sha256) and the on-chain pin (keccak256) differ by
 * design, mirroring the production service. Files written by the old keccak-named layout
 * are ignored, not migrated: this store is development-only, and silent aliasing of two
 * addressing schemes would be worse than a clean break.
 *
 * Unlike the memory store, `get` re-reads from disk every time: the
 * directory is the authority, which keeps multi-process use (SDK uploads next to a node
 * reading the same dir) coherent without any cache-invalidation protocol.
 */
import { mkdirSync, readFileSync, readdirSync, renameSync, statSync, unlinkSync, writeFileSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
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

  /**
   * How old a `.tmp` file has to be before it is treated as an orphan.
   *
   * A crash between temp-write and rename leaves `<cid>.<pid>.<rand>.tmp` behind. Temp
   * files are never complete objects, so sweeping them at open is safe - but only the
   * orphans: a temp file that another process is writing *right now* carries the same
   * suffix, and deleting it makes that writer's rename fail with ENOENT. The shard is
   * then never stored and the caller sees a spurious failure, so the sweep skips
   * anything young enough to still be in flight.
   */
  static readonly ORPHAN_TEMP_AGE_MS = 60 * 60_000;

  private readonly dir: string;
  private readonly maxObjectBytes: number;

  constructor(dir: string, opts: FileShardStoreOptions = {}) {
    if (!dir || dir.includes("\0")) throw new Error(`invalid shard directory ${JSON.stringify(dir)}`);
    this.dir = dir;
    this.maxObjectBytes = opts.maxObjectBytes ?? FileShardStore.DEFAULT_MAX_OBJECT_BYTES;
    mkdirSync(dir, { recursive: true });
    const cutoff = Date.now() - FileShardStore.ORPHAN_TEMP_AGE_MS;
    for (const name of readdirSync(dir)) {
      if (!name.endsWith(".tmp")) continue;
      try {
        if (statSync(join(dir, name)).mtimeMs > cutoff) continue; // живой temp
        unlinkSync(join(dir, name));
      } catch {
        // Raced with a live writer or another sweeper: harmless either way.
      }
    }
  }

  private pathFor(cid: string): string {
    // `cid` is always a `0x`-prefixed 32-byte hex string this class computed itself (see
    // `put`), never a caller-supplied path — but `get` takes arbitrary cids, so validate here
    // rather than trusting either call site.
    if (!/^0x[0-9a-fA-F]{64}$/.test(cid) || cid.includes(sep) || cid.includes("..")) {
      throw new Error(`unsafe shard cid ${JSON.stringify(cid)}`);
    }
    return join(this.dir, cid.slice(2));
  }

  async put(payload: Uint8Array): Promise<{ cid: string; digest: string }> {
    if (payload.byteLength > this.maxObjectBytes) {
      throw new Error(
        `refusing to store ${payload.byteLength} bytes; the shard cap is ${this.maxObjectBytes}`
      );
    }
    // Transport address (sha256) vs on-chain pin (keccak256): see the header note.
    const cid = ethers.sha256(payload);
    const digest = ethers.keccak256(payload);
    const path = this.pathFor(cid);
    if (!existsSync(path)) {
      // Temp + rename: a concurrent reader either sees the old state (absent) or the complete
      // new file, never a half-written one. The temp name is unique per attempt (pid + 128-bit
      // nonce): two concurrent puts of the same content-addressed bytes must not share one
      // temp path — on Windows the second rename over an existing file throws.
      const tmp = `${path}.${process.pid}.${randomBytes(16).toString("hex")}.tmp`;
      writeFileSync(tmp, payload);
      try {
        renameSync(tmp, path);
      } catch (e) {
        // Another process stored the same content-addressed bytes first. The name is the
        // hash of the bytes, so the file that is there is the file we wanted - and on
        // Windows the rename over an existing file throws, which is not a failure.
        if (!existsSync(path)) throw e;
        try {
          unlinkSync(tmp);
        } catch {
          // The temp is already gone: the other writer's rename took it.
        }
      }
    }
    return { cid, digest };
  }

  async get(cid: string): Promise<Uint8Array> {
    // Validated outside the try: a hostile cid must fail as hostile, never be relabelled
    // "not found" by the read-error handler below.
    const path = this.pathFor(cid);
    // Bound before buffering: a file planted in the shared directory (multi-process use
    // is documented) must not be fully loaded only to be rejected afterwards.
    let size: number;
    try {
      size = statSync(path).size;
    } catch {
      throw new Error(`shard ${cid} not found`);
    }
    if (size > this.maxObjectBytes) {
      throw new Error(`shard ${cid} is ${size} bytes, over the ${this.maxObjectBytes} byte cap`);
    }
    let bytes: Buffer;
    try {
      bytes = readFileSync(path);
    } catch {
      throw new Error(`shard ${cid} not found`);
    }
    // Re-check after the read: the file may have grown between stat and read.
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
