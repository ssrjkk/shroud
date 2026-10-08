/**
 * @shroud/sdk — client-side orchestration for Shroud.
 *
 * The primary entry point is `ShroudSdk.uploadAndMonetize(data, taskId, opts)`, which
 * encrypts the buyer's rows locally, uploads the shard to the DA, and commits it to the task
 * with the buyer's escrow already in place.
 */
import type { Signer, Provider } from "ethers";
import { ethers } from "ethers";
import { CipherTaskClient, NetworkParamsClient, PaymentVaultClient } from "./cipher.js";
import type { Encryptor, ShardStore, TaskParams, UploadResult, PreparedShard } from "./types.js";
import { NoopEncryptor, pinPayload } from "./encrypt.js";
import { MemoryShardStore } from "./da.js";
import type { Hex } from "./types.js";

export * from "./types.js";
export * from "./eip712.js";
export * from "./encrypt.js";
export * from "./da.js";
export { CipherTaskClient, NetworkParamsClient, PaymentVaultClient };

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
  /**
   * The `fhePublicKeyHash` this client will encrypt under (`keccak256(abi.encode(s_pub))`).
   *
   * When supplied together with `networkParams`, the SDK verifies against the on-chain pin before
   * every upload and refuses to submit on a mismatch. See `NetworkParamsClient`.
   */
  fhePublicKeyHash?: Hex;
  /** Address of the on-chain `NetworkParams` pin. Enables the key-substitution check. */
  networkParams?: string;
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
  /**
   * Allow submitting a shard produced by an encryptor that does not actually encrypt.
   *
   * Development-only escape hatch for the `NoopEncryptor` default. Without it the SDK refuses to
   * upload, because the alternative is silently committing a contributor's plaintext rows to a
   * public chain under a CID that looks exactly like a real ciphertext.
   */
  allowUnencrypted?: boolean;
}

/**
 * `CipherTask.MAX_ROWS_PER_SHARD`.
 *
 * Mirrored here so the SDK can reject an oversized shard without spending gas. If the contract
 * constant changes this must change with it; the contract remains the authority and will still
 * revert.
 */
export const MAX_ROWS_PER_SHARD = 100_000;

export class ShroudSdk {
  readonly cipherTask: CipherTaskClient;
  readonly paymentVault: PaymentVaultClient;
  readonly encryptor: Encryptor;
  readonly shardStore: ShardStore;
  readonly networkParams?: NetworkParamsClient;
  private readonly configuredChainId?: bigint;
  private readonly fhePublicKeyHash?: Hex;
  private resolvedChainId?: bigint;
  private readonly signer: Signer;

  constructor(cfg: SdkConfig) {
    this.signer = cfg.signer;
    // `cfg.provider` was accepted and then never read, so a client built with a signer that
    // exposes no provider of its own could not resolve its chain id at all. It is the documented
    // fallback, so honour it here rather than only via `withProvider`.
    this.providerFallback = cfg.provider;
    this.cipherTask = new CipherTaskClient(cfg.cipherTask, cfg.signer);
    this.paymentVault = new PaymentVaultClient(cfg.paymentVault, cfg.signer);
    this.encryptor = cfg.encryptor ?? new NoopEncryptor();
    this.shardStore = cfg.shardStore ?? new MemoryShardStore();
    this.configuredChainId = cfg.chainId;
    this.fhePublicKeyHash = cfg.fhePublicKeyHash;
    if (cfg.networkParams) {
      if (!cfg.fhePublicKeyHash) {
        throw new Error(
          "networkParams was provided without fhePublicKeyHash; the pin check would have nothing to compare against"
        );
      }
      this.networkParams = new NetworkParamsClient(cfg.networkParams, cfg.signer);
    }
  }

  /**
   * Resolve the chain id once and pin it for the life of the client.
   *
   * This used to be dead code: `chainId` was stored from the config and `ensureChainId` was
   * defined but never called, so a configured `chainId` was silently ignored. That matters more
   * than it looks — the escrow amount, the task id space, and every EIP-712 slice digest are
   * chain-specific, so signing against the wrong network produces transactions that look valid
   * and land nowhere (or, worse, on a devnet with the same contract addresses).
   */
  private async ensureChainId(): Promise<bigint> {
    if (this.resolvedChainId !== undefined) return this.resolvedChainId;
    const net = await (this.signer.provider ?? this.providerFallback)?.getNetwork();
    const actual = net?.chainId;
    if (actual === undefined) {
      throw new Error("could not determine the chain id from the provider; pass cfg.chainId explicitly");
    }
    if (this.configuredChainId !== undefined && this.configuredChainId !== actual) {
      throw new Error(
        `configured chainId ${this.configuredChainId} but the provider is on ${actual}; refusing to sign against the wrong chain`
      );
    }
    this.resolvedChainId = actual;
    return actual;
  }

  private providerFallback?: Provider;

  /** Attach a provider explicitly when the signer exposes none. */
  withProvider(provider: Provider): this {
    this.providerFallback = provider;
    return this;
  }

  /**
   * Verify the configured `fhePublicKeyHash` against the on-chain pin (threat model F-08).
   *
   * Skipped when `networkParams`/`fhePublicKeyHash` were not configured, because a client with no
   * key hash has nothing to compare. That is a real gap and is why the absence of configuration is
   * itself worth noticing: `NetworkParams` exists to make a key swap *detectable*, and a client
   * that never reads it cannot detect anything.
   */
  private async assertKeyPin(): Promise<void> {
    if (!this.networkParams || !this.fhePublicKeyHash) return;
    if (await this.networkParams.isCurrentKey(this.fhePublicKeyHash)) return;

    const onChain = await this.networkParams.snapshot().catch(() => undefined);
    const pending = await this.networkParams.rotationPending().catch(() => false);
    throw new Error(
      `the FHE public key this client would encrypt under (${this.fhePublicKeyHash}) is not the key ` +
        `pinned on chain${onChain ? ` (${onChain.fhePublicKeyHash}, keyVersion ${onChain.keyVersion})` : ""}` +
        `${pending ? "; a rotation is currently pending, so refresh your parameters first" : ""}. ` +
        `Refusing to upload: under a substituted key the ciphertexts would be readable by whoever ` +
        `published it, and nothing downstream would detect that.`
    );
  }

  /**
   * Encrypt `data`, upload it to the DA, and commit it as a contribution to `taskId`.
   *
   * `data` is a flat `Float64Array` (or `number[]`) of `rows * features` values.
   *
   * If `opts.createIfMissing` is true and the task does not exist yet, the buyer creates it with
   * `opts.budget` first, so the escrow is in place before the shard lands.
   *
   * Every condition the contract would revert on is checked locally first — task status, shard
   * size bounds, the contributor cap, the contribution window, one-shard-per-address, and
   * shape-proof presence — so a misconfigured call fails with an actionable message instead of
   * burning gas. The list below is exhaustive against `submitContribution`; the contract remains
   * the authority and still reverts if anything slips through.
   */
  async uploadAndMonetize(
    data: Float64Array | number[],
    taskId: bigint,
    opts: UploadOptions
  ): Promise<UploadResult> {
    // Refuse to build a payload we already know must not be uploaded. This is checked before any
    // network call so a misconfiguration cannot leak data even if the task turns out to be
    // invalid.
    if (!this.encryptor.providesConfidentiality && !opts.allowUnencrypted) {
      throw new Error(
        "refusing to upload: the configured Encryptor does not encrypt (providesConfidentiality = false). " +
          "Pass a real FHEWasm/relayer encryptor, or set opts.allowUnencrypted = true in development " +
          "to submit plaintext on purpose."
      );
    }

    await this.ensureChainId();
    await this.assertKeyPin();

    if (opts.features <= 0) throw new Error("features must be positive");
    if (data.length % opts.features !== 0) {
      throw new Error(`data length ${data.length} is not a multiple of features ${opts.features}`);
    }
    const rows = data.length / opts.features;

    const resolvedId = await this.resolveTask(taskId, opts);

    const t = await this.cipherTask.task(resolvedId);
    const opening = 1n; // TaskStatus.Opening
    const collecting = 2n; // TaskStatus.Collecting
    if (t.status !== opening && t.status !== collecting) {
      throw new Error(
        `task ${resolvedId} does not accept shards (status ${t.status}); contribution is only possible while Opening(1) or Collecting(2)`
      );
    }

    // `submitContribution` -> ShardTooSmall / ShardTooLarge.
    const minRows = Number(t.params.minRowsPerShard);
    if (rows < minRows) {
      throw new Error(`shard has ${rows} rows, below the task minimum of ${minRows}`);
    }
    if (rows > MAX_ROWS_PER_SHARD) {
      throw new Error(`shard has ${rows} rows, over CipherTask.MAX_ROWS_PER_SHARD (${MAX_ROWS_PER_SHARD})`);
    }

    // `submitContribution` -> ContributionWindowClosed. `windowEnd` is fixed at task creation.
    const windowEnd = BigInt(t.windowEnd ?? 0);
    if (windowEnd > 0n && BigInt(Math.floor(Date.now() / 1000)) > windowEnd) {
      throw new Error(
        `the contribution window for task ${resolvedId} closed at ${windowEnd}; anyone can now seal it instead`
      );
    }

    // `submitContribution` -> CapReached.
    const maxContributors = Number(t.params.maxContributors);
    if (BigInt(t.contributors ?? 0) >= BigInt(maxContributors)) {
      throw new Error(`task ${resolvedId} already has ${t.contributors}/${maxContributors} contributors`);
    }

    // `submitContribution` -> AlreadyContributed. This is the check the previous docstring claimed
    // and did not perform, so a repeat contribution was discovered only as a revert.
    const me = await this.signer.getAddress();
    const existing = await this.cipherTask.contribution(resolvedId, me);
    if (existing.accepted) {
      throw new Error(
        `address ${me} already contributed ${existing.rows} rows to task ${resolvedId}; ` +
          `the contract allows exactly one shard per address per task (AlreadyContributed)`
      );
    }

    if (await this.cipherTask.shapeProofsRequired()) {
      if (!opts.shapeProof || opts.shapeProof === ethers.ZeroHash) {
        throw new Error(
          "this task requires a Groth16 shape proof; pass opts.shapeProof (an empty proof reverts on-chain with ShapeProofInvalid)"
        );
      }
    }

    // 1. Encrypt locally - plaintext never leaves the client.
    const payload = await this.encryptor.encryptRows(data, opts.features);

    // 2. Upload the shard to the DA.
    const { cid } = await this.shardStore.put(payload);
    const { ctDigest, rowCommitment } = pinPayload(payload);

    // 3. Commit the shard to the task.
    const shard: PreparedShard = {
      ciphertextCid: cid,
      ctDigest,
      shapeProof: opts.shapeProof as Hex,
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
