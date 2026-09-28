/**
 * @ciphermesh/sdk — client-side orchestration for CipherMesh.
 *
 * The primary entry point is `CipherMeshSdk.uploadAndMonetize(data, taskId, opts)`, which
 * encrypts the buyer's rows locally, uploads the shard to the DA, and commits it to the task
 * with the buyer's escrow already in place.
 */
import type { Signer, Provider } from "ethers";
import { ethers } from "ethers";
import { CipherTaskClient, PaymentVaultClient } from "./cipher.js";
import type { Encryptor, ShardStore, TaskParams, UploadResult, PreparedShard } from "./types.js";
import { NoopEncryptor, pinPayload } from "./encrypt.js";
import { MemoryShardStore } from "./da.js";
import type { Hex } from "./types.js";

export * from "./types.js";
export * from "./eip712.js";
export * from "./encrypt.js";
export * from "./da.js";
export { CipherTaskClient, PaymentVaultClient };

export interface SdkConfig {
  cipherTask: string;
  paymentVault: string;
  signer: Signer;
  provider: Provider;
  /** Shard store (DA). Defaults to an in-memory store for development. */
  shardStore?: ShardStore;
  /** Local FHE encryptor. Defaults to the noop (development-only) encryptor. */
  encryptor?: Encryptor;
  /** chain id; if omitted it is read from the provider. */
  chainId?: bigint;
}

export interface UploadOptions {
  /** Exact escrow budget (base units) when creating a new task. */
  budget?: bigint;
  /** Task parameters used when `createIfMissing` is true. */
  params?: TaskParams;
  /** Number of features per row. */
  features: number;
  /** If true, create the task when `taskId` does not yet exist. */
  createIfMissing?: boolean;
  /** Optional shape proof over the shard (a real Groth16 proof in production). */
  shapeProof?: Hex;
}

export class CipherMeshSdk {
  readonly cipherTask: CipherTaskClient;
  readonly paymentVault: PaymentVaultClient;
  readonly encryptor: Encryptor;
  readonly shardStore: ShardStore;
  private readonly chainId: bigint;
  private readonly signer: Signer;

  constructor(cfg: SdkConfig) {
    this.signer = cfg.signer;
    this.cipherTask = new CipherTaskClient(cfg.cipherTask, cfg.signer);
    this.paymentVault = new PaymentVaultClient(cfg.paymentVault, cfg.signer);
    this.encryptor = cfg.encryptor ?? new NoopEncryptor();
    this.shardStore = cfg.shardStore ?? new MemoryShardStore();
    this.chainId = cfg.chainId ?? 0n;
  }

  private async ensureChainId(): Promise<bigint> {
    if (this.chainId !== 0n) return this.chainId;
    const net = await this.signer.provider?.getNetwork();
    return net?.chainId ?? 0n;
  }

  /**
   * Encrypt `data`, upload it to the DA, and commit it as a contribution to `taskId`.
   *
   * `data` is a flat `Float64Array` (or `number[]`) of `rows * features` values.
   *
   * If `opts.createIfMissing` is true and the task does not exist yet, the buyer creates it with
   * `opts.budget` first, so the escrow is in place before the shard lands.
   */
  async uploadAndMonetize(
    data: Float64Array | number[],
    taskId: bigint,
    opts: UploadOptions
  ): Promise<UploadResult> {
    if (opts.features <= 0) throw new Error("features must be positive");
    if (data.length % opts.features !== 0) {
      throw new Error(`data length ${data.length} is not a multiple of features ${opts.features}`);
    }
    const rows = data.length / opts.features;

    const resolvedId = await this.resolveTask(taskId, opts);

    // 1. Encrypt locally - plaintext never leaves the client.
    const payload = await this.encryptor.encryptRows(data, opts.features);

    // 2. Upload the shard to the DA.
    const { cid } = await this.shardStore.put(payload);
    const { ctDigest, rowCommitment } = pinPayload(payload);

    // 3. Commit the shard to the task.
    const shard: PreparedShard = {
      ciphertextCid: cid,
      ctDigest,
      shapeProof: opts.shapeProof ?? ethers.ZeroHash,
      rowCommitment,
      rows,
    };
    const contributionTx = await this.cipherTask.submitContribution(resolvedId, shard);

    return { taskId: resolvedId, ...shard, contributionTx };
  }

  private async resolveTask(taskId: bigint, opts: UploadOptions): Promise<bigint> {
    const count = await this.cipherTask.taskCount();
    const exists = taskId > 0n && taskId <= count;
    if (exists) return taskId;
    if (!opts.createIfMissing) {
      throw new Error(`task ${taskId} does not exist and createIfMissing is not set`);
    }
    if (opts.budget === undefined) throw new Error("budget is required when createIfMissing is true");
    if (opts.params === undefined) throw new Error("params are required when createIfMissing is true");
    const created = await this.cipherTask.createTask(opts.budget, opts.params);
    return created.taskId;
  }
}
