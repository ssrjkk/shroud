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
import { encodeWeights, weightsDigest } from "./weights.js";
import { MemoryShardStore } from "./da.js";
import type { Hex } from "./types.js";

export * from "./types.js";
export * from "./eip712.js";
export * from "./encrypt.js";
export * from "./da.js";
export * from "./weights.js";
export * from "./gate.js";
export { CipherTaskClient, NetworkParamsClient, NETWORK_PARAMS_ABI, PaymentVaultClient, taskIdFromReceipt, validateHyperparams } from "./cipher.js";
export type { EpochHyperparams } from "./cipher.js";

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
   * The `keccak256(abi.encode(s_pub))` this client encrypts under.
   *
   * Optional when the configured `encryptor` declares its own `publicKeyHash`, which is the case
   * that actually matters: a key the caller *believes* is in use can be compared against the chain,
   * while a key the encryptor holds can be substituted without the client noticing. See
   * `Encryptor.publicKeyHash` and `NetworkParamsClient`.
   */
  fhePublicKeyHash?: Hex;
  /** Address of the on-chain `NetworkParams` pin. Enables the key-substitution check. */
  networkParams?: string;
  /**
   * Allow a confidential encryptor with no on-chain pin to compare against.
   *
   * By default a client whose encryptor actually encrypts (`providesConfidentiality`) and
   * declares the key it encrypts under refuses to run without `networkParams`: without the
   * pin there is nothing that would notice a substituted `s_pub` (threat model F-08), and a
   * silent default here would turn an explicit SDK guarantee into a configuration accident.
   * Set this to `true` only for deployments that pin the key out of band.
   */
  allowUnpinnedKey?: boolean;
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

/**
 * Normalize a configured chain id. The field is typed `bigint`, but JavaScript callers
 * pass numbers: `11155111 !== 11155111n`, so a strict comparison later would cry wolf
 * on the correct chain. Floats and garbage fail fast here instead of deep in a signing path.
 */
function normalizeChainId(v: unknown): bigint | undefined {
  if (v === undefined) return undefined;
  if (typeof v === "bigint") return v;
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new Error(`cfg.chainId must be an integer chain id, got ${v}`);
    return BigInt(v);
  }
  if (typeof v === "string" && /^\d+$/.test(v)) return BigInt(v);
  throw new Error(`cfg.chainId must be an integer chain id, got ${JSON.stringify(v)}`);
}

/** Minimal ERC-20 surface the SDK needs for bond approvals. Never add transfer here:
 *  the SDK moves no funds of its own; approvals are the only token writes it performs.
 *  `increaseAllowance` is preferred over `approve` for tokens like USDT that require
 *  zero-first (they revert on non-zero-to-nonzero approve). */
const ERC20_MIN_ABI = [
  "function approve(address spender, uint256 amount) returns (bool)",
  "function increaseAllowance(address spender, uint256 addedValue) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function balanceOf(address account) view returns (uint256)",
] as const;

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
    this.configuredChainId = normalizeChainId(cfg.chainId);
    // The key the client is *told* it uses and the key the encryptor *actually* uses have to agree
    // before either is compared with the chain, otherwise the pin check verifies a string that is
    // not the one the ciphertext depends on. Hex is case-insensitive - the same bytes32 written
    // with EIP-55 casing is the same key - and the on-chain comparison goes through the ABI,
    // which does not care about case, so this comparison must not care either. A checksum-cased
    // hash for the key the encryptor already declares is the same key, not a different one.
    const declared = this.encryptor.publicKeyHash;
    if (cfg.fhePublicKeyHash && declared && cfg.fhePublicKeyHash.toLowerCase() !== declared.toLowerCase()) {
      throw new Error(
        `cfg.fhePublicKeyHash is ${cfg.fhePublicKeyHash} but the configured encryptor encrypts under ` +
          `${declared}; the pin check would attest to a key the shard is not encrypted under`
      );
    }
    this.fhePublicKeyHash = cfg.fhePublicKeyHash ?? declared;
    if (cfg.networkParams) {
      if (!this.fhePublicKeyHash) {
        throw new Error(
          "networkParams was provided without fhePublicKeyHash, and the encryptor declares no " +
            "publicKeyHash; the pin check would have nothing to compare against"
        );
      }
      this.networkParams = new NetworkParamsClient(cfg.networkParams, cfg.signer);
    } else if (this.encryptor.providesConfidentiality && this.fhePublicKeyHash && !cfg.allowUnpinnedKey) {
      // F-08, fail-closed: an encryptor that produces real ciphertext under a known key, with
      // no on-chain pin to compare it to, is exactly the configuration a key-substitution
      // attack needs — every upload would succeed and nobody would notice. The old default
      // skipped the check silently; refusing to construct is the only safe default.
      throw new Error(
        "this encryptor produces real ciphertext under a declared key, but no networkParams " +
          "pin was configured, so a substituted s_pub would go undetected. Pass " +
          "cfg.networkParams (the on-chain NetworkParams address), or set " +
          "cfg.allowUnpinnedKey = true if this deployment pins the key out of band."
      );
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
    // An explicitly attached provider wins over whatever the signer happens to carry:
    // otherwise `withProvider` could never actually switch networks, and a signer with
    // a stale default would silently override deliberate configuration.
    const net = await (this.providerFallback ?? this.signer.provider)?.getNetwork();
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

  /**
   * The provider reads go through. `cfg.provider` wins when set (see the constructor);
   * otherwise the signer's own provider is used. Fails closed when neither exists —
   * every `provider.*` call below is a consensus read (chain id, block time) or a
   * preflight simulation, and silently running those against `undefined` is how
   * wrong-chain signatures and phantom submissions happen.
   */
  private activeProvider(): Provider {
    const p = this.providerFallback ?? this.signer.provider;
    if (!p) {
      throw new Error(
        "no provider available: pass cfg.provider or construct the SDK with a signer that carries one"
      );
    }
    return p;
  }

  /** Attach a provider explicitly when the signer exposes none. */
  withProvider(provider: Provider): this {
    // The resolved chain id is pinned per client: swapping the provider without
    // forgetting it would keep signing against the old network after this call.
    // The fallback also takes precedence over the signer's own provider (see
    // `ensureChainId`), so this call actually switches networks instead of
    // decorating a signer that keeps answering for the old one.
    this.providerFallback = provider;
    this.resolvedChainId = undefined;
    return this;
  }

  /**
   * Verify the key this client encrypts under against the on-chain pin (threat model F-08).
   *
   * The key is `cfg.fhePublicKeyHash`, or what the encryptor declares when the caller did not
   * configure one — the constructor refuses a client where the two disagree.
   *
   * Skipped when `networkParams` was not configured, because a client with no pin to read has
   * nothing to compare. That is a real gap and is why the absence of configuration is itself worth
   * noticing: `NetworkParams` exists to make a key swap *detectable*, and a client that never reads
   * it cannot detect anything.
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
   * size bounds, the contributor cap, the contribution window, one-shard-per-address, shape-proof
   * presence, the contribution bond (approved up front when missing), and the encryptor's own outputs (a non-empty ciphertext, a row commitment, and a
   * content address short enough to be a `bytes32`) — so a misconfigured call fails with an
   * actionable message instead of burning gas. The list below is exhaustive against
   * `submitContribution`; the contract remains the authority and still reverts if anything slips
   * through.
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

    if (!Number.isInteger(opts.features) || opts.features <= 0) throw new Error(`features must be a positive integer, got ${String(opts.features)}`);
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

    // No on-chain check anywhere (`ContributeLib.submit` never reads `features`), so a
    // mismatch here fails silently: wrong `features` means wrong `rows`, which means a
    // wrong reward weight (unless `weightByBond`) and a wrong per-row bond — with zero
    // reverts to catch it. Fail loudly against the task's own spec instead.
    const wantFeatures = Number(t.params.features);
    if (opts.features !== wantFeatures) {
      throw new Error(
        `features ${opts.features} does not match task ${resolvedId} (expects ${wantFeatures}); ` +
          `re-encode the shard with the task's feature count`
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
    // Use block timestamp, not Date.now(), to avoid false positives/negatives from clock skew.
    const windowEnd = BigInt(t.windowEnd ?? 0);
    if (windowEnd > 0n) {
      const block = await this.activeProvider().getBlock("latest");
      // `Block.timestamp` is a number; the comparison below is against a bigint, and
      // mixing the two throws, so normalize first. Chain time, not wall-clock: see above.
      const nowSec = BigInt(block?.timestamp ?? Math.floor(Date.now() / 1000));
      if (nowSec > windowEnd) {
        throw new Error(
          `the contribution window for task ${resolvedId} closed at ${windowEnd}; anyone can now seal it instead`
        );
      }
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

    // `submitContribution` -> BondInsufficient. The bond is pulled by the orchestrator
    // itself, so without an approval the submission burns gas on a revert that was
    // knowable locally. Approved up front, for exactly the requirement — never a max
    // approval, and only after every free check above passed. The approval deliberately
    // precedes encrypt/upload: a dangling exact-amount approval is consumed by the next
    // successful submit, while an uploaded-but-unsubmitted shard would pollute the DA.
    await this.ensureContributionBond(resolvedId, me, rows);

    // 1. Encrypt locally — plaintext never leaves the client.
    const { ciphertext, rowCommitment } = await this.encryptor.encryptRows(data, opts.features);

    // The two values the contract will not accept empty or malformed, checked before the upload so
    // a broken encryptor cannot leave a shard in the DA that is then unpinnable.
    if (ciphertext.length === 0) {
      throw new Error("the encryptor returned an empty ciphertext; there is nothing to upload");
    }
    if (!rowCommitment || rowCommitment === ethers.ZeroHash) {
      throw new Error(
        "the encryptor returned no rowCommitment. It commits to the plaintext rows, so it can only " +
          "come from the encryptor - CipherTask rejects a zero commitment with RowCommitmentInvalid, " +
          "and a re-execution compares it against the rows it decrypts"
      );
    }

    // 2. Commit the shard to the task — dry-run FIRST, upload second.
    // Every dry-run input is already local (ciphertext bytes, rowCommitment, rows,
    // locally-derived digests), so there is no reason to touch the DA before knowing
    // the submit simulates cleanly. The old order (upload, then simulate) left an
    // orphan object in the DA on every revert — with `allowUnencrypted` that orphan
    // is plaintext on a store the task then refuses.
    const { ctDigest } = pinPayload(ciphertext);
    // Transport address, same convention the stores use (`sha256`, while the on-chain
    // pin is `keccak256`). Recomputed by `put` below; a mismatch means a lying store
    // and aborts before any transaction.
    const localCid = ethers.sha256(ciphertext) as Hex;
    if (ethers.dataLength(localCid) !== 32) {
      throw new Error(
        `computed a ${ethers.dataLength(localCid)}-byte cid (${localCid}); the on-chain ` +
          `ciphertextCid is a bytes32, so only a 32-byte content address can be committed to it`
      );
    }

    // An omitted shape proof is empty bytes: the contract only rejects those when it
    // requires proofs (checked above), and passing `undefined` through would die inside
    // ethers' ABI encoder with an obscure BytesLike error instead of uploading.
    const shard: PreparedShard = {
      ciphertextCid: localCid,
      ctDigest,
      shapeProof: (opts.shapeProof ?? "0x") as Hex,
      rowCommitment,
      rows,
    };

    // TOCTOU guard: simulate the call before sending so a task that was sealed or filled
    // between the preflight checks (lines 288-335) and now surfaces as a revert rather
    // than burning gas on an obviously failing transaction. `from: me` matters: the real
    // transaction runs as the contributor (bond pull included), so simulating from the
    // zero address would false-positive on every bonded task.
    const taskContract = this.cipherTask.contract;
    const submitData = taskContract.interface.encodeFunctionData("submitContribution", [
      resolvedId, shard.ciphertextCid, shard.ctDigest, shard.shapeProof, shard.rowCommitment, shard.rows,
    ]);
    try {
      await this.activeProvider().call({ to: taskContract.target, from: me, data: submitData });
    } catch (simError: any) {
      const revertReason = simError?.reason ?? simError?.message ?? String(simError);
      throw new Error(
        `submitContribution dry-run reverted for task ${resolvedId}: ${revertReason}. ` +
          `The task state may have changed (sealed/filled/closed) since the preflight checks.`
      );
    }

    // 3. Upload the shard to the DA — only after the submit is known to simulate.
    const { cid } = await this.shardStore.put(ciphertext);
    if (cid.toLowerCase() !== localCid.toLowerCase()) {
      throw new Error(
        `the shard store echoed cid ${cid} for bytes addressing ${localCid}; refusing to submit ` +
          `a contribution the store itself cannot serve back`
      );
    }

    const contributionTx = await this.cipherTask.submitContribution(resolvedId, { ...shard, ciphertextCid: cid });

    return { taskId: resolvedId, ...shard, ciphertextCid: cid, contributionTx };
  }

  /**
   * Publish a genesis seed-weight file for `openEpoch`.
   *
   * Buyer-side helper around `@shroud/sdk/weights`: encodes `lanes` (length `features`)
   * as a `shroud/weights/v1` file, uploads it to the DA, and returns both pins the
   * epoch opening needs — `cid` (`encWeightsCid`) and `weightsDigest` (`weightsDigest`).
   * The node decodes the same layout (`node/src/fhe.rs`), so a digest mismatch here
   * would only surface as a genesis-zeros fallback with a warning in the node's logs.
   */
  async publishWeights(
    features: number,
    lanes: number[]
  ): Promise<{ cid: Hex; weightsDigest: Hex }> {
    const bytes = encodeWeights(features, lanes);
    const { cid } = await this.shardStore.put(bytes);
    return { cid, weightsDigest: weightsDigest(lanes) };
  }

  /**
   * Approve the contribution bond the task requires, if any is still missing.
   *
   * Reads, never guesses: the requirement and what this address already posted come from
   * the chain, the token address from the orchestrator itself. The requirement is the
   * full pull amount — flat plus per-row surcharge times this shard's rows
   * (`BondLib.pull` charges `flat + perRow*rows`, so approving the flat part alone
   * would revert post-upload with `BondInsufficient`). A shortfall with no funds
   * is a local error naming the exact figures; an approval covers exactly the requirement
   * (the pull takes the full requirement or reverts, so a partial approval would still
   * burn gas — approve the whole thing or fail loudly here).
   */
  private async ensureContributionBond(taskId: bigint, contributor: string, rows: number): Promise<void> {
    const flat = await this.cipherTask.contributionBondRequired(taskId);
    const perRow = await this.cipherTask.contributionBondPerRow(taskId);
    const required = flat + perRow * BigInt(rows);
    if (required === 0n) return;
    const posted = await this.cipherTask.contributionBondOf(taskId, contributor);
    if (posted >= required) return;
    const taskAddr = this.cipherTask.contract.target as string;
    const token = new ethers.Contract(await this.cipherTask.escrowToken(), ERC20_MIN_ABI, this.signer);
    const balance = BigInt(await token.balanceOf(contributor));
    if (balance < required) {
      throw new Error(
        `task ${taskId} requires a contribution bond of ${required}, but ${contributor} holds ` +
          `only ${balance}; fund the bond first (an on-chain submit would revert BondInsufficient)`
      );
    }
    const allowance = BigInt(await token.allowance(contributor, taskAddr));
    if (allowance < required) {
      // `increaseAllowance` adds to the existing allowance, so topping up by the full
      // requirement would over-approve by whatever is already granted — despite the
      // "exactly the requirement" rule above. Top up by the shortfall only.
      const shortfall = required - allowance;
      // USDT pattern: no `increaseAllowance`, and `approve(nonZero→nonZero)` reverts.
      // Try increaseAllowance first; on failure (revert or bad receipt) fall back to
      // zero-first approve(0)+approve(required). Never leave a misleading error.
      let ok = false;
      try {
        const tx = await (token as any)["increaseAllowance"](taskAddr, shortfall);
        const receipt = await tx.wait();
        ok = !!receipt && receipt.status === 1;
      } catch {
        ok = false;
      }
      if (!ok) {
        const zeroTx = await token.approve(taskAddr, 0n);
        const zeroReceipt = await zeroTx.wait();
        if (!zeroReceipt || zeroReceipt.status !== 1) {
          throw new Error(`bond approval zero-first reset failed (status ${zeroReceipt?.status})`);
        }
        const tx = await token.approve(taskAddr, required);
        const receipt = await tx.wait();
        if (!receipt || receipt.status !== 1) {
          throw new Error(`bond approval transaction failed (status ${receipt?.status})`);
        }
      }
    }
  }

  private async resolveTask(taskId: bigint, opts: UploadOptions): Promise<bigint> {
    // Runtime gate for JavaScript callers: the type says bigint, but `1.5 > 0n` is true,
    // so without this a fractional id sails past the existence check and dies obscurely
    // inside an ABI encoder. Fail here with the actual value in hand.
    if (typeof taskId !== "bigint" || taskId <= 0n) {
      throw new Error(`task id must be a positive integer, got ${String(taskId)}`);
    }
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
