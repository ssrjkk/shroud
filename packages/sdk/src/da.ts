/**
 * Content-addressed shard store (DA) client.
 *
 * The default `MemoryShardStore` is for local development and tests. A production deployment
 * points `ShardStore` at the `infra/` ShardStore service (content-addressed, range-pull).
 */
import { ethers } from "ethers";
import type { ShardStore } from "./types.js";

export class MemoryShardStore implements ShardStore {
  private readonly objects = new Map<string, Uint8Array>();

  async put(payload: Uint8Array): Promise<{ cid: string; digest: string }> {
    const cid = ethers.keccak256(payload);
    this.objects.set(cid, payload);
    return { cid, digest: cid };
  }

  async get(cid: string): Promise<Uint8Array | undefined> {
    return this.objects.get(cid);
  }
}

/** A ShardStore backed by an HTTP endpoint (the production DA / ShardStore service). */
export class HttpShardStore implements ShardStore {
  constructor(private readonly baseUrl: string) {}

  async put(payload: Uint8Array): Promise<{ cid: string; digest: string }> {
    const res = await fetch(`${this.baseUrl}/objects`, {
      method: "PUT",
      body: payload as BodyInit,
      headers: { "content-type": "application/octet-stream" },
    });
    if (!res.ok) throw new Error(`shard store PUT failed: ${res.status}`);
    const body = (await res.json()) as { cid: string; digest: string };
    return body;
  }

  async get(cid: string): Promise<Uint8Array> {
    const res = await fetch(`${this.baseUrl}/objects/${cid}`);
    if (!res.ok) throw new Error(`shard store GET failed: ${res.status}`);
    return new Uint8Array(await res.arrayBuffer());
  }
}
