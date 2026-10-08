/**
 * Thin ethers v6 wrapper around `CipherTask` and `PaymentVault`.
 *
 * The ABIs are the compiled artifacts, embedded in `src/abi/*.json` so the SDK is self-contained
 * when published and always selects the same functions as the on-chain contracts. Regenerate
 * them with `scripts/export-abi.cjs` whenever the Solidity changes.
 */
import { Contract, ethers, type Signer, type Provider } from "ethers";
import CipherTaskAbi from "./abi/CipherTask.json" with { type: "json" };
import PaymentVaultAbi from "./abi/PaymentVault.json" with { type: "json" };
import type { Hex, PreparedShard, TaskParams, RedeemSlice } from "./types.js";
import { domainSeparator, redeemDigest, signRedeemSlice } from "./eip712.js";

export class CipherTaskClient {
  readonly contract: Contract;

  constructor(address: string, signerOrProvider: Signer | Provider) {
    this.contract = new Contract(address, CipherTaskAbi, signerOrProvider);
  }

  async createTask(budget: bigint, params: TaskParams): Promise<{ taskId: bigint; tx: string }> {
    const tx = await this.contract.createTask(budget, params);
    const receipt = await tx.wait();
    if (!receipt) throw new Error("no receipt for createTask");
    const taskId = await this.contract.taskCount();
    return { taskId: BigInt(taskId), tx: tx.hash };
  }

  async submitContribution(taskId: bigint, shard: PreparedShard): Promise<string> {
    const tx = await this.contract.submitContribution(
      taskId,
      shard.ciphertextCid,
      shard.ctDigest,
      shard.shapeProof,
      shard.rowCommitment,
      shard.rows
    );
    const receipt = await tx.wait();
    if (!receipt) throw new Error("no receipt for submitContribution");
    return tx.hash;
  }

  async task(taskId: bigint) {
    return this.contract.tasks(taskId);
  }

  /**
   * Settle the next page of contributors.
   *
   * Settlement is paged because paying the whole pool in one call is O(contributors) in gas with
   * an external call each, which at the orchestrator's cap is far past a block gas limit. Call this
   * repeatedly with the returned cursor until `isFullySettled` is true; the final page also pays
   * the committee and refunds the buyer. Paging is permissionless — it only ever pays the
   * addresses the task already committed to.
   */
  async settle(taskId: bigint, cursor = 0n): Promise<string> {
    const tx = cursor === 0n ? await this.contract.settle(taskId) : await this.contract.settleFrom(taskId, cursor);
    const receipt = await tx.wait();
    if (!receipt) throw new Error("no receipt for settle");
    return tx.hash;
  }

  /** Index of the first contributor not yet paid. */
  async settleCursor(taskId: bigint): Promise<bigint> {
    return BigInt(await this.contract.settleCursor(taskId));
  }

  /** Whether the final settlement page has run. */
  async isFullySettled(taskId: bigint): Promise<boolean> {
    return this.contract.isFullySettled(taskId);
  }

  /** Contributors paid per settlement call. */
  async settlePageSize(): Promise<bigint> {
    return BigInt(await this.contract.SETTLE_PAGE_SIZE());
  }

  /** The contributor pool frozen by the first settlement page, for monitoring. */
  async settleUserPool(taskId: bigint): Promise<bigint> {
    return BigInt(await this.contract.settleUserPool(taskId));
  }

  /**
   * Drive settlement to completion.
   *
   * Safe to call repeatedly and from any account: each page is independent and idempotent in the
   * sense that an already-settled task reverts rather than paying anyone twice, which is why the
   * loop re-reads `isFullySettled` rather than trusting its own count.
   */
  async settleToCompletion(taskId: bigint, maxPages = 100): Promise<number> {
    let pages = 0;
    while (pages < maxPages) {
      if (await this.isFullySettled(taskId)) return pages;
      const cursor = await this.settleCursor(taskId);
      await this.settle(taskId, cursor);
      pages++;
    }
    throw new Error(`settlement did not complete within ${maxPages} pages for task ${taskId}`);
  }

  async taskCount(): Promise<bigint> {
    return BigInt(await this.contract.taskCount());
  }

  /** Whether the orchestrator requires a non-empty shape proof on every shard. */
  async shapeProofsRequired(): Promise<boolean> {
    return this.contract.shapeProofsRequired();
  }

  /**
   * A single contribution record, or `undefined` if this address never contributed.
   *
   * Exists so `ShroudSdk` can check the one-shard-per-address rule before paying gas. The
   * contract enforces it as `AlreadyContributed`; catching it here turns a revert into a local,
   * actionable error.
   */
  async contribution(taskId: bigint, contributor: string) {
    const c = await this.contract.contributions(taskId, contributor);
    return {
      accepted: Boolean(c.accepted),
      slashed: Boolean(c.slashed),
      rows: Number(c.rows),
      ciphertextCid: String(c.ciphertextCid),
    };
  }

  async epochChannel(taskId: bigint, epoch: number): Promise<bigint> {
    return BigInt(await this.contract.epochChannel(taskId, epoch));
  }

  async pendingPayout(account: string): Promise<bigint> {
    return BigInt(await this.contract.pendingPayout(account));
  }
}

export class PaymentVaultClient {
  readonly contract: Contract;

  constructor(address: string, signerOrProvider: Signer | Provider) {
    this.contract = new Contract(address, PaymentVaultAbi, signerOrProvider);
  }

  /** Redeem a slice; `sig` must be an EIP-712 signature by the streamer (see `signRedeemSlice`). */
  async redeem(slice: RedeemSlice, sliceIndex: number, amount: bigint, signature: Hex): Promise<string> {
    const tx = await this.contract.redeem(
      slice.channelId,
      sliceIndex,
      amount,
      slice.deadline,
      signature
    );
    const receipt = await tx.wait();
    if (!receipt) throw new Error("no receipt for redeem");
    return tx.hash;
  }

  async channelInfo(channelId: bigint) {
    return this.contract.channelInfo(channelId);
  }

  /** Build the digest the vault expects for a slice, then have the streamer sign it. */
  async authorizeSlice(
    streamer: Signer,
    slice: RedeemSlice,
    chainId: bigint
  ): Promise<{ digest: Hex; signature: Hex }> {
    const ds = domainSeparator(this.contract.target as string, chainId);
    const digest = redeemDigest(slice, ds);
    const signature = await signRedeemSlice(streamer, slice, this.contract.target as string, chainId);
    return { digest, signature };
  }

  async claim(claimer: Signer): Promise<void> {
    const claimerContract = new Contract(this.contract.target as string, PaymentVaultAbi, claimer);
    const tx = await claimerContract.claim();
    const receipt = await tx.wait();
    if (!receipt) throw new Error("no receipt for claim");
  }

  async pendingWithdrawal(account: string): Promise<bigint> {
    return BigInt(await this.contract.pendingWithdrawal(account));
  }
}

/**
 * Read-only client for the on-chain `NetworkParams` pin.
 *
 * This exists to close the `s_pub` substitution hole (threat model F-08). `NetworkParams` pins
 * `fhePublicKeyHash` correctly and rotates it only behind a timelock plus a second approver — but
 * until now nothing read it. A malicious sequencer could publish its own public key, collect the
 * ciphertexts submitted under it, and decrypt them, and no participant would notice.
 *
 * The pin is still a *detection* control, not a prevention one: a swap that already happened is
 * only visible afterwards. What it does guarantee is that a client refuses to encrypt under a key
 * the network has not blessed, so a swap becomes a loud, blocking failure instead of a silent
 * confidentiality loss.
 *
 * A minimal ABI is embedded rather than pulled from the artifact pipeline because this client only
 * needs two view functions; `NetworkParams.isCurrentKey` is a pure comparison against
 * `current.fhePublicKeyHash` and cannot be misread if kept to exactly these two entries.
 */
const NETWORK_PARAMS_ABI = [
  "function isCurrentKey(bytes32 sPubHash) view returns (bool)",
  "function current() view returns (tuple(uint64 chainId, uint64 keyVersion, bytes32 fhePublicKeyHash, bytes32 committeeAggregateKey, uint16 committeeThreshold, uint16 committeeSize, uint32 maxProofBytes, uint32 maxCiphertextBytes, uint32 maxFeatures, uint64 activatedAt, bool active))",
  "function rotationPending() view returns (bool)",
] as const;

export interface NetworkParamsSnapshot {
  chainId: bigint;
  keyVersion: bigint;
  fhePublicKeyHash: string;
  committeeThreshold: number;
  committeeSize: number;
  maxCiphertextBytes: number;
  maxFeatures: number;
  activatedAt: bigint;
  active: boolean;
}

export class NetworkParamsClient {
  readonly contract: Contract;

  constructor(address: string, signerOrProvider: Signer | Provider) {
    this.contract = new Contract(address, NETWORK_PARAMS_ABI as unknown as string[], signerOrProvider);
  }

  async snapshot(): Promise<NetworkParamsSnapshot> {
    const c = await this.contract.current();
    return {
      chainId: BigInt(c.chainId),
      keyVersion: BigInt(c.keyVersion),
      fhePublicKeyHash: String(c.fhePublicKeyHash),
      committeeThreshold: Number(c.committeeThreshold),
      committeeSize: Number(c.committeeSize),
      maxCiphertextBytes: Number(c.maxCiphertextBytes),
      maxFeatures: Number(c.maxFeatures),
      activatedAt: BigInt(c.activatedAt),
      active: Boolean(c.active),
    };
  }

  /** Whether `sPubHash` is the currently pinned network public key. */
  async isCurrentKey(sPubHash: string): Promise<boolean> {
    return this.contract.isCurrentKey(sPubHash);
  }

  /** Whether a rotation is queued but not yet executed (i.e. a key change is imminent). */
  async rotationPending(): Promise<boolean> {
    return this.contract.rotationPending();
  }
}

export { ethers };
