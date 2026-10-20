/**
 * Thin ethers v6 wrapper around `CipherTask` and `PaymentVault`.
 *
 * The ABIs are the compiled artifacts, embedded in `src/abi/*.json` so the SDK is self-contained
 * when published and always selects the same functions as the on-chain contracts. Compile the
 * contracts and regenerate the copies with `npm run export-abi` in `packages/sdk` whenever the
 * Solidity changes; the SDK's smoke suite fails on any drift between a copy and its artifact.
 */
import { Contract, ethers, type Interface, type Signer, type Provider } from "ethers";
import CipherTaskAbi from "./abi/CipherTask.json" with { type: "json" };
import PaymentVaultAbi from "./abi/PaymentVault.json" with { type: "json" };
import type { Hex, PreparedShard, TaskParams, RedeemSlice } from "./types.js";
import { domainSeparator, encodeSliceSignature, redeemDigest, signRedeemSlice, SLICE_DEADLINE, SLICE_INDEX } from "./eip712.js";

/**
 * The task id a mined `createTask` produced, read from its `TaskCreated` event.
 *
 * Reading `taskCount()` back after the transaction was a race: a task created by anyone else in the
 * same block makes it return an id this transaction did not create, and the caller then contributes
 * to, monitors and pays escrow for the wrong task — with a budget that is not its own.
 * `TaskCreated` carries the id this call minted, indexed, so the receipt is the only authority
 * needed, and a receipt without the event is an error rather than a guess.
 */
export function taskIdFromReceipt(
  logs: readonly { topics: readonly string[]; data: string }[],
  iface: Interface
): bigint | undefined {
  for (const log of logs) {
    // `parseLog` returns null for a topic0 this ABI does not declare, which is every log from a
    // contract the task manager called into — the DA, the verifier, the vault.
    const parsed = iface.parseLog(log);
    if (parsed?.name === "TaskCreated") return BigInt(parsed.args["taskId"]);
  }
  return undefined;
}

/**
 * Normalize an integer identifier (task id, chain id): accept bigint and integral
 * numbers/decimal strings, reject everything else up front. The ABI encoder accepts
 * several shapes but fails obscurely on fractional ones (`1.5 > 0n` is true, so a bare
 * range check would wave it through to die inside `encode`).
 */
function normalizeUint(v: unknown, name: string): bigint {
  if (typeof v === "bigint") {
    if (v > 0n) return v;
  } else if (typeof v === "number") {
    if (Number.isInteger(v) && v > 0) return BigInt(v);
  } else if (typeof v === "string" && /^[1-9]\d*$/.test(v)) {
    return BigInt(v);
  }
  throw new Error(`${name} must be a positive integer, got ${String(v)}`);
}

export class CipherTaskClient {
  readonly contract: Contract;

  constructor(address: string, signerOrProvider: Signer | Provider) {
    this.contract = new Contract(address, CipherTaskAbi, signerOrProvider);
  }

  async createTask(budget: bigint, params: TaskParams): Promise<{ taskId: bigint; tx: string }> {
    const tx = await this.contract.createTask(budget, params);
    const receipt = await tx.wait();
    if (!receipt) throw new Error("no receipt for createTask");
    const taskId = taskIdFromReceipt(receipt.logs, this.contract.interface);
    if (taskId === undefined) {
      throw new Error(
        `createTask was mined in ${tx.hash} but its receipt carries no TaskCreated event; ` +
          `refusing to guess the task id`
      );
    }
    return { taskId, tx: tx.hash };
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
   *
   * If the final page is not yet runnable because reward channels have not matured
   * (`ChannelsImmature`, threat model F-22), the revert is rethrown with the remedy attached:
   * wait out the reward window and call again — the pages that already ran keep their effect.
   */
  async settleToCompletion(taskId: bigint, maxPages = 100): Promise<number> {
    let pages = 0;
    while (pages < maxPages) {
      if (await this.isFullySettled(taskId)) return pages;
      const cursor = await this.settleCursor(taskId);
      try {
        await this.settle(taskId, cursor);
      } catch (e) {
        if (e instanceof Error && /ChannelsImmature/.test(e.message)) {
          throw new Error(
            `settlement of task ${taskId} paid ${pages} page(s) and is now waiting for reward ` +
              `channels to mature; retry after the reward window (CipherTask.rewardChannelWindow). ` +
              `Caused by: ${e.message}`
          );
        }
        throw e;
      }
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

  /**
   * Register with proof-of-possession of the caller's key over its BLS key.
   *
   * Signs the EIP-191 message the contract reconstructs
   * (`keccak(taskId, blsPubKey, node, chainId, cipherTask)`), so the BLS key is bound to a
   * live signer instead of being self-declared. Prefer this over `registerNode` whenever the
   * caller holds its own key.
   */
  async registerNodeWithPop(taskId: bigint, blsPubKey: Hex, signer: Signer, chainId: bigint): Promise<string> {
    // Fail fast on shapes the contract would reject with an opaque revert after a
    // signature round trip — or, for a fractional task id, inside the ABI encoder.
    const tid = normalizeUint(taskId, "task id");
    if (!ethers.isHexString(blsPubKey, 32)) {
      throw new Error(`blsPubKey must be a bytes32 hex string, got ${JSON.stringify(blsPubKey)}`);
    }
    const chain = normalizeUint(chainId, "chainId");
    const node = await signer.getAddress();
    const target = this.contract.target as string;
    const inner = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "bytes32", "address", "uint256", "address"],
        [tid, blsPubKey, node, chain, target]
      )
    );
    const sig = await signer.signMessage(ethers.getBytes(inner));
    const contract = this.contract.connect(signer) as Contract;
    const tx = await contract.registerNodeWithPop(tid, blsPubKey, sig);
    const receipt = await tx.wait();
    if (!receipt) throw new Error("no receipt for registerNodeWithPop");
    return tx.hash;
  }

  /** Commit to a dispute digest before revealing it (front-run resistance). */
  async commitDispute(taskId: bigint, epoch: number, commitment: Hex): Promise<string> {
    const tx = await this.contract.commitDispute(taskId, epoch, commitment);
    const receipt = await tx.wait();
    if (!receipt) throw new Error("no receipt for commitDispute");
    return tx.hash;
  }

  /** Reveal a committed dispute digest. */
  async reportDisputeWithSalt(taskId: bigint, epoch: number, digest: Hex, salt: Hex): Promise<string> {
    const tx = await this.contract.reportDisputeWithSalt(taskId, epoch, digest, salt);
    const receipt = await tx.wait();
    if (!receipt) throw new Error("no receipt for reportDisputeWithSalt");
    return tx.hash;
  }

  /** Commitment for `keccak(digest, salt, reporter)` — what `commitDispute` must be given. */
  disputeCommitment(digest: Hex, salt: Hex, reporter: string): Hex {
    return ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32", "address"], [digest, salt, reporter])
    );
  }

  /** Submit a segmented-STARK root for `epoch` (see `commitEpochSegmented`). */
  async commitEpochSegmented(
    taskId: bigint,
    epoch: number,
    segmentedRoot: Hex,
    encWeightsCid: Hex,
    weightsDigest: Hex,
    metricsCid: Hex,
    traceDigest: Hex
  ): Promise<string> {
    const tx = await this.contract.commitEpochSegmented(
      taskId,
      epoch,
      segmentedRoot,
      encWeightsCid,
      weightsDigest,
      metricsCid,
      traceDigest
    );
    const receipt = await tx.wait();
    if (!receipt) throw new Error("no receipt for commitEpochSegmented");
    return tx.hash;
  }

  /** Bond currently required of new contributions to `taskId` (0 = none). */
  async contributionBondRequired(taskId: bigint): Promise<bigint> {
    return BigInt(await this.contract.contributionBondRequired(taskId));
  }

  /** Bond currently posted by `contributor` on `taskId`. */
  async contributionBondOf(taskId: bigint, contributor: string): Promise<bigint> {
    return BigInt(await this.contract.contributionBondOf(taskId, contributor));
  }

  /** The ERC-20 token the orchestrator pulls contribution bonds (and escrow) in. */
  async escrowToken(): Promise<string> {
    return String(await this.contract.escrowToken());
  }

  /**
   * Ask the committee to open the reveal window for a settled task.
   *
   * The reveal is requested here, on the orchestrator, and not on the gate: the gate may only
   * be opened by the orchestrator, because the task's `Settling -> Revealing` transition and
   * the gate's `open` flag are one state machine. Opening the gate directly would take the
   * flag while the task was still `Settling`, and this call would then revert - leaving the
   * task unable to reach `Disclosed` and its buyer unable to withdraw.
   *
   * The orchestrator pins the output CID itself, so the caller only supplies the committee's
   * aggregate signature over that task and that CID.
   */
  async requestReveal(taskId: bigint, blsAggregateSig: Hex): Promise<string> {
    const tx = await this.contract.requestReveal(taskId, blsAggregateSig);
    const receipt = await tx.wait();
    if (!receipt) throw new Error("no receipt for requestReveal");
    return tx.hash;
  }
}

export class PaymentVaultClient {
  readonly contract: Contract;

  constructor(address: string, signerOrProvider: Signer | Provider) {
    this.contract = new Contract(address, PaymentVaultAbi, signerOrProvider);
  }

  /**
   * Redeem slice `sliceIndex` of `slice.channelId`.
   *
   * `signature` is whatever authenticates the channel's streamer, and which one that is depends on
   * the streamer, not on the caller's preference:
   * — a contract streamer (`CipherTask`, i.e. every node reward channel) takes the 96-byte slice
   *   blob from `encodeSliceSignature`;
   * — an EOA streamer takes a 65-byte ECDSA signature over the EIP-712 digest (`signRedeemSlice`).
   *
   * Passing the wrong kind is `InvalidSignature`, and for the common case `authorizedSlice` below
   * produces the right one from on-chain data.
   */
  async redeem(slice: RedeemSlice, sliceIndex: number, amount: bigint, signature: Hex): Promise<string> {
    if (!Number.isInteger(sliceIndex) || sliceIndex < 0) {
      throw new Error(`sliceIndex must be a non-negative integer, got ${sliceIndex}`);
    }
    // `PaymentVault` bounds the index so that `uint64(sliceIndex)` cannot truncate a larger value
    // back onto a consumed index, and `redeem` is `onlyNode`, so a wrong argument here is a revert
    // the caller pays for rather than a mistake the chain catches for free.
    if (BigInt(sliceIndex) >= 1n << 64n) {
      throw new Error(`sliceIndex ${sliceIndex} is outside uint64 and reverts with SliceIndexOutOfRange`);
    }
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

  /**
   * The slice `CipherTask` authorised for a reward channel, plus its signature.
   *
   * There is no private key involved: `finalizeEpoch` writes exactly one authorised slice per node
   * channel — index 0, amount equal to the channel cap — and the vault accepts that triple encoded
   * as the ERC-1271 "signature" (see `encodeSliceSignature`). Everything needed to redeem is
   * therefore readable from the channel itself, which is also why a node cannot redeem more than it
   * earned: the cap is on chain, and `withdrawn` only ever grows.
   *
   * `redeem` is callable only by the channel's node, so that is checked locally before spending gas.
   */
  async authorizedSlice(channelId: bigint): Promise<{ slice: RedeemSlice; signature: Hex }> {
    const ch = await this.channelInfo(channelId);
    const node = String(ch.node);
    if (node === ethers.ZeroAddress) {
      throw new Error(`channel ${channelId} does not exist (its node is the zero address)`);
    }
    const me = await this.signerAddress();
    if (me && me.toLowerCase() !== node.toLowerCase()) {
      throw new Error(
        `channel ${channelId} belongs to node ${node}; this client is ${me} and ` +
          `PaymentVault.redeem is onlyNode`
      );
    }
    const slice: RedeemSlice = {
      channelId,
      streamer: String(ch.streamer),
      node,
      maxCumulative: BigInt(ch.maxCumulative),
      unlockAt: BigInt(ch.unlockAt),
      deadline: SLICE_DEADLINE,
    };
    return {
      slice,
      signature: encodeSliceSignature(channelId, SLICE_INDEX, slice.maxCumulative),
    };
  }

  /** Read a channel's authorised slice and redeem it, in one call. */
  async redeemAuthorizedSlice(channelId: bigint): Promise<string> {
    const { slice, signature } = await this.authorizedSlice(channelId);
    return this.redeem(slice, Number(SLICE_INDEX), slice.maxCumulative, signature);
  }

  /**
   * The address this client sends from, or `undefined` for a read-only client.
   *
   * A `Provider` runner has no address; callers that gate on it must treat `undefined` as "cannot
   * check locally", not as "not authorised", or a monitoring client built on a provider would be
   * told it cannot read its own channels.
   */
  private async signerAddress(): Promise<string | undefined> {
    const runner = this.contract.runner as { getAddress?: () => Promise<string> };
    return runner?.getAddress?.();
  }

  /**
   * Build the digest the vault expects for a slice and have an EOA streamer sign it.
   *
   * Only correct when the channel's streamer is a wallet. For a contract streamer this produces
   * bytes the vault will reject, because the contract authenticates the recorded slice blob, not a
   * signature over a digest; use `authorizedSlice` there.
   */
  async signSliceAsStreamer(
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

  /** Whether `taskId` still has an open reward channel whose window has not matured. */
  async hasImmatureChannels(taskId: bigint): Promise<boolean> {
    return this.contract.hasImmatureChannels(taskId);
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
 * needs three view functions. Being hand-written it is the one ABI the generated copies cannot
 * keep honest, so the SDK suite compares each fragment — inputs *and* outputs — against the
 * compiled `NetworkParams` artifact.
 */
export const NETWORK_PARAMS_ABI = [
  "function isCurrentKey(bytes32 sPubHash) view returns (bool)",
  // `Params public current;` is a public struct, so solc's auto-getter returns its *flattened*
  // members rather than a tuple. Declaring this as a tuple compiles fine against ethers and fails
  // at runtime, because every named output reads `undefined`.
  "function current() view returns (uint64 chainId, uint64 keyVersion, bytes32 fhePublicKeyHash, bytes32 committeeAggregateKey, uint16 committeeThreshold, uint16 committeeSize, uint32 maxProofBytes, uint32 maxCiphertextBytes, uint32 maxFeatures, uint64 activatedAt, bool active)",
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
