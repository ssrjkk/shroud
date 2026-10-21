/**
 * Real FHE encryption for `@shroud/sdk`, via `@zama-fhe/relayer-sdk` (TFHE, Sepolia testnet).
 *
 * Node-only entry point (`@shroud/sdk/relayer`), like `file-store`: the relayer SDK pulls
 * native WASM (`tfhe`, `node-tfhe`) that has no business in a browser bundle. Import it
 * directly; `index.js` stays browser-safe.
 *
 * What it does, end to end: fetch the network TFHE public key from the relayer, quantize each
 * `float64` row to an unsigned 64-bit integer (`round(v * scale)`), encrypt every integer with
 * `add64` under the network key, and pack `{handles, inputProof}` into one DA payload the node
 * can verify against `ctDigest`. `providesConfidentiality` is true, so uploads through this
 * encryptor need no `allowUnencrypted` escape hatch.
 *
 * Three interop contracts a caller must respect (all asserted, never silently defaulted past):
 *
 * 1. **Quantization scale.** The Rust node denoises in fixed point with its own `scale`
 *    (default 10_000); a shard quantized at any other scale decrypts to garbage weights. The
 *    default here matches the node default, and any other scale must be agreed out of band.
 * 2. **Domain.** TFHE encrypts unsigned integers. Negative, non-finite or overflowing values
 *    throw here rather than wrap: a wrapped negative would train on a huge positive with no
 *    error anywhere.
 * 3. **Key pin.** `publicKeyHash` is `keccak256(abi.encode(tfheKeyBytes))` of the exact key the
 *    ciphertexts were produced under, so the existing `ShroudSdk` pin check (constructor +
 *    `NetworkParams.isCurrentKey`) attests to the real key, not a string someone typed.
 *
 * `rowCommitment` commits to the *quantized integers* that were encrypted
 * (`keccak256("shroud/relayer-row/v1" || le64...)`). Like every plaintext commitment it is
 * brute-forceable over tiny domains — that is inherent to the protocol's dispute design (a
 * re-execution must compare decrypted rows against *something*), not to this encryptor.
 */
import { ethers } from "ethers";
import { createInstance, SepoliaConfig } from "@zama-fhe/relayer-sdk/node";
import type { FhevmInstance } from "@zama-fhe/relayer-sdk/node";
import type { Encryptor } from "./types.js";
import { onceAsync } from "./memo.js";

/** Magic + version of the DA payload envelope (see `encodeRelayerPayload`). */
export const RELAYER_PAYLOAD_MAGIC = "shroud/relayer/v1";
/** Fixed-point scale matching the Rust node's default (`fhe.scale`). See contract 1 above. */
export const DEFAULT_QUANTIZE_SCALE = 10_000;

export interface RelayerEncryptorOptions {
  /** JSON-RPC URL of the chain the relayer serves (e.g. a Sepolia endpoint). Required. */
  network: string;
  /** Relayer base URL. Defaults to the Sepolia testnet relayer. */
  relayerUrl?: string;
  /** Chain id of `network`. Defaults to Sepolia (11155111). */
  chainId?: number;
  /** Fixed-point scale. Defaults to {@link DEFAULT_QUANTIZE_SCALE}. */
  scale?: number;
  /**
   * CipherTask address the input proof is bound to. Required: a proof created against
   * the zero address (or any other contract) verifies independently of the task, so the
   * same handles/proof would replay on every task. Fail-closed at config time.
   */
  contractAddress?: string;
  /** User address the input is bound to (defaults to the zero address: binding-neutral). */
  userAddress?: string;
}

/**
 * Validate the `createEncryptedInput` binding before any network call.
 *
 * The contract address is required and must be a real (non-zero) address: without it the
 * input proof is bound to nothing and replays across tasks. The user address may stay
 * neutral (zero) for callers that bind the contributor elsewhere.
 */
export function assertInputBinding(
  contractAddress?: string,
  userAddress?: string
): { contractAddress: string; userAddress: string } {
  if (!contractAddress || !ethers.isAddress(contractAddress) || contractAddress === ethers.ZeroAddress) {
    throw new Error(
      "RelayerEncryptor needs opts.contractAddress (the CipherTask): a binding-neutral proof replays on every task"
    );
  }
  if (userAddress !== undefined && !ethers.isAddress(userAddress)) {
    throw new Error(`RelayerEncryptor got an invalid userAddress ${JSON.stringify(userAddress)}`);
  }
  return { contractAddress, userAddress: userAddress ?? ethers.ZeroAddress };
}

interface RelayerShard {
  handles: Uint8Array[];
  inputProof: Uint8Array;
}

/**
 * Quantize one row-major matrix to unsigned 64-bit integers.
 *
 * Pure (no network), so it is unit-tested without a relayer. Throws on anything TFHE cannot
 * represent rather than coercing it: silent coercion here would train on different numbers than
 * the contributor approved.
 */
export function quantizeRows(data: Float64Array | number[], features: number, scale: number): bigint[] {
  if (!Number.isInteger(features) || features <= 0) throw new Error(`features must be positive, got ${features}`);
  if (!Number.isInteger(scale) || scale <= 0) throw new Error(`scale must be positive, got ${scale}`);
  const n = data.length;
  if (n % features !== 0) throw new Error(`data length ${n} is not a multiple of features ${features}`);
  const out = new Array<bigint>(n);
  for (let i = 0; i < n; i++) {
    const v = data[i];
    if (!Number.isFinite(v)) throw new Error(`row value at index ${i} is not finite`);
    if (v < 0) throw new Error(`row value at index ${i} is negative (${v}): TFHE encrypts unsigned integers`);
    const scaled = v * scale;
    // `v` is finite but `v * scale` may not be (1e308 at scale 10000): without this,
    // `BigInt(Infinity)` below throws a bare RangeError with no index, value or scale.
    // Precision past 2^53 is the caller's responsibility — f64 cannot hold more — but an
    // infinite intermediate must never reach the encoder.
    if (!Number.isFinite(scaled)) {
      throw new Error(`row value at index ${i} overflows float64 at scale ${scale}`);
    }
    const q = BigInt(Math.round(scaled));
    if (q > 18446744073709551615n) {
      throw new Error(`row value at index ${i} overflows uint64 at scale ${scale}`);
    }
    out[i] = q;
  }
  return out;
}

/** Commitment over the quantized integers (see header). Pure, unit-tested. */
export function relayerRowCommitment(quantized: bigint[]): string {
  const buf = new Uint8Array(22 + quantized.length * 8);
  new TextEncoder().encodeInto("shroud/relayer-row/v1\0", buf);
  const view = new DataView(buf.buffer);
  for (let i = 0; i < quantized.length; i++) view.setBigUint64(22 + i * 8, quantized[i], true);
  return ethers.keccak256(buf);
}

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

/**
 * Pack `{handles, inputProof}` into one DA payload. Self-describing (per-item lengths), so a
 * future handle size never silently misaligns the parse.
 */
export function encodeRelayerPayload(shard: RelayerShard): Uint8Array {
  const head = new TextEncoder().encode(`${RELAYER_PAYLOAD_MAGIC}\0`);
  let len = head.length + 4;
  for (const h of shard.handles) len += 4 + h.length;
  len += 4 + shard.inputProof.length;
  const out = new Uint8Array(len);
  let o = 0;
  out.set(head, o);
  o += head.length;
  const w = new DataView(out.buffer);
  w.setUint32(o, shard.handles.length, false);
  o += 4;
  for (const h of shard.handles) {
    w.setUint32(o, h.length, false);
    o += 4;
    out.set(h, o);
    o += h.length;
  }
  w.setUint32(o, shard.inputProof.length, false);
  o += 4;
  out.set(shard.inputProof, o);
  return out;
}

/** Inverse of {@link encodeRelayerPayload}. Throws on truncation or a wrong magic. */
export function decodeRelayerPayload(payload: Uint8Array): RelayerShard {
  const head = new TextEncoder().encode(`${RELAYER_PAYLOAD_MAGIC}\0`);
  const fail = (why: string): never => {
    throw new Error(`invalid relayer payload: ${why}`);
  };
  if (payload.length < head.length + 4) fail("shorter than header");
  for (let i = 0; i < head.length; i++) if (payload[i] !== head[i]) fail("bad magic");
  const r = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  let o = head.length;
  const readU32 = (): number => {
    if (o + 4 > payload.length) fail("truncated length");
    const v = r.getUint32(o, false);
    o += 4;
    return v;
  };
  const readBytes = (n: number): Uint8Array => {
    if (n < 0 || o + n > payload.length) fail("truncated item");
    const b = payload.slice(o, o + n);
    o += n;
    return b;
  };
  const nHandles = readU32();
  if (nHandles > 1_000_000) fail(`absurd handle count ${nHandles}`);
  const handles: Uint8Array[] = [];
  for (let i = 0; i < nHandles; i++) handles.push(readBytes(readU32()));
  const proof = readBytes(readU32());
  if (o !== payload.length) fail("trailing bytes");
  return { handles, inputProof: proof };
}

export class RelayerEncryptor implements Encryptor {
  readonly providesConfidentiality = true;
  readonly publicKeyHash?: string;
  readonly publicKeyId?: string;

  private readonly opts: Required<
    Pick<RelayerEncryptorOptions, "network" | "relayerUrl" | "chainId" | "scale">
  > &
    Required<Pick<RelayerEncryptorOptions, "contractAddress" | "userAddress">>;
  private instance?: FhevmInstance;

  private constructor(
    opts: RelayerEncryptorOptions,
    publicKeyHash: string,
    publicKeyId: string
  ) {
    if (!opts.network) throw new Error("RelayerEncryptor needs opts.network (chain RPC URL)");
    const binding = assertInputBinding(opts.contractAddress, opts.userAddress);
    this.opts = {
      network: opts.network,
      relayerUrl: opts.relayerUrl ?? SepoliaConfig.relayerUrl,
      chainId: opts.chainId ?? 11155111,
      scale: opts.scale ?? DEFAULT_QUANTIZE_SCALE,
      contractAddress: binding.contractAddress,
      userAddress: binding.userAddress,
    };
    if (!Number.isInteger(this.opts.scale) || this.opts.scale <= 0) {
      throw new Error(`scale must be positive, got ${opts.scale}`);
    }
    this.publicKeyHash = publicKeyHash;
    this.publicKeyId = publicKeyId;
  }

  /**
   * Build an encryptor against a live relayer: fetches the network TFHE public key, derives
   * the pin hash from its exact bytes, and keeps the instance for `encryptRows`.
   *
   * The hash derivation is `keccak256(abi.encode(keyBytes))`, byte-for-byte what the
   * `NetworkParams.fhePublicKeyHash` pin means on chain — so the `ShroudSdk` constructor and
   * `isCurrentKey` checks below compare the key the ciphertexts actually use.
   */
  static async create(opts: RelayerEncryptorOptions): Promise<RelayerEncryptor> {
    // Fail fast on a binding-neutral config before spending a network round-trip.
    const binding = assertInputBinding(opts.contractAddress, opts.userAddress);
    const draft: RelayerEncryptorOptions = {
      network: opts.network,
      relayerUrl: opts.relayerUrl ?? SepoliaConfig.relayerUrl,
      chainId: opts.chainId ?? 11155111,
      scale: opts.scale ?? DEFAULT_QUANTIZE_SCALE,
      contractAddress: binding.contractAddress,
      userAddress: binding.userAddress,
    };
    const instance = await createInstance({
      ...SepoliaConfig,
      relayerUrl: draft.relayerUrl!,
      network: draft.network!,
      chainId: draft.chainId!,
    });
    const key = instance.getPublicKey();
    if (!key) throw new Error("relayer returned no TFHE public key");
    const hash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(["bytes"], [key.publicKey])
    );
    const enc = new RelayerEncryptor(draft, hash, key.publicKeyId);
    enc.instance = instance;
    return enc;
  }

  async encryptRows(
    data: Float64Array | number[],
    features: number
  ): Promise<{ ciphertext: Uint8Array; rowCommitment: string }> {
    const quantized = quantizeRows(data, features, this.opts.scale);
    const instance = await this.ready();
    const input = instance.createEncryptedInput(this.opts.contractAddress, this.opts.userAddress);
    for (const q of quantized) input.add64(q);
    const { handles, inputProof } = await input.encrypt();
    if (!handles.length) throw new Error("relayer returned no handles");
    return {
      ciphertext: encodeRelayerPayload({ handles, inputProof }),
      rowCommitment: relayerRowCommitment(quantized),
    };
  }

  private async ready(): Promise<FhevmInstance> {
    if (this.instance) return this.instance;
    return this.instanceOnce();
  }

  /**
   * The live instance, built at most once.
   *
   * A failed attempt is not remembered: the relayer or the RPC may be down for a
   * moment, and a cached rejection would leave the encryptor permanently broken
   * until the process is restarted.
   */
  private readonly instanceOnce = onceAsync(async () => {
    const opts = this.opts;
    const instance = await createInstance({
      ...SepoliaConfig,
      relayerUrl: opts.relayerUrl,
      network: opts.network,
      chainId: opts.chainId,
    });
    this.instance = instance;
    return instance;
  });
}
