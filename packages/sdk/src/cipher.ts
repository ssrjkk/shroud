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
    await tx.wait();
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
    await tx.wait();
    return tx.hash;
  }

  async task(taskId: bigint) {
    return this.contract.tasks(taskId);
  }

  async taskCount(): Promise<bigint> {
    return BigInt(await this.contract.taskCount());
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
    await tx.wait();
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
    await tx.wait();
  }

  async pendingWithdrawal(account: string): Promise<bigint> {
    return BigInt(await this.contract.pendingWithdrawal(account));
  }
}

export { ethers };
