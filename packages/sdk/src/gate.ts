/**
 * Read/write client for the on-chain `DecryptionGate` (threshold reveal of task outputs).
 *
 * The SDK historically exported the gate ABI but wrapped nothing: reveal monitoring had to
 * use raw contract calls, so integrators could not tell a "reveal in flight" task from a
 * "reveal combinable" one without reading storage. Every method here is a thin, named read
 * over the committed output CID, plus the write a committee member needs.
 *
 * Opening the reveal window is *not* one of them: the gate may only be opened by the
 * orchestrator, because the task's status and the gate's `open` flag are one state machine.
 * Ask for the reveal through `CipherTaskClient.requestReveal` (the buyer, update manager or
 * contract owner calls the task, which pins the output CID and asks the gate), and use this
 * client to watch the window and to submit partial decryptions as a committee member.
 */
import { Contract, ethers, type Signer, type Provider } from "ethers";
import DecryptionGateAbi from "./abi/DecryptionGate.json" with { type: "json" };
import type { Hex } from "./types.js";

export interface GateInfo {
  open: boolean;
  combined: boolean;
  required: number;
  members: string[];
}

export class DecryptionGateClient {
  readonly contract: Contract;

  constructor(address: string, signerOrProvider: Signer | Provider) {
    if (!ethers.isAddress(address) || address === ethers.ZeroAddress) {
      throw new Error(
        `DecryptionGateClient needs a gate address (got ${JSON.stringify(address)}): ` +
          `reveal transactions against the zero address always revert, against a typo'd ` +
          `one they bind the wrong contract`
      );
    }
    this.contract = new Contract(address, DecryptionGateAbi, signerOrProvider);
  }

  /** Domain-separated message the committee BLS-signs to open a reveal. */
  async revealMessage(taskId: bigint, weightsCid: Hex): Promise<Hex> {
    return this.contract.revealMessage(taskId, weightsCid);
  }

  /** Whether the threshold has been met and the reveal combined. */
  async revealCompleted(taskId: bigint): Promise<boolean> {
    return this.contract.revealCompleted(taskId);
  }

  /** Open/combined state plus the members that already submitted partials. */
  async gateInfo(taskId: bigint): Promise<GateInfo> {
    const [open, combined, required, members] = await this.contract.gateInfo(taskId);
    return { open, combined, required: Number(required), members: [...members] as string[] };
  }

  /** Number of partial decryptions submitted for `taskId`. */
  async partialCount(taskId: bigint): Promise<bigint> {
    return BigInt(await this.contract.partialCount(taskId));
  }

  /** Whether `account` is a committee member that may submit partials. */
  async isCommitteeMember(account: string): Promise<boolean> {
    return this.contract.isCommitteeMember(account);
  }

  /**
   * Submit this member's partial decryption commitment for `taskId`.
   */
  async submitPartialDecryption(taskId: bigint, partialDecryption: Hex): Promise<string> {
    const tx = await this.contract.submitPartialDecryption(taskId, partialDecryption);
    const receipt = await tx.wait();
    if (!receipt) throw new Error("no receipt for submitPartialDecryption");
    return tx.hash;
  }

  /**
   * Wait until the reveal completes or `timeoutMs` elapses, polling `revealCompleted`.
   *
   * Rejections carry the partial count so an operator can see whether the ceremony is
   * stalled (no new partials) or merely slow.
   */
  async waitForReveal(taskId: bigint, opts: { timeoutMs?: number; pollMs?: number } = {}): Promise<void> {
    const timeoutMs = opts.timeoutMs ?? 10 * 60_000;
    const pollMs = opts.pollMs ?? 5_000;
    const started = Date.now();
    for (;;) {
      try {
        if (await this.revealCompleted(taskId)) return;
      } catch (e) {
        // One RPC blip must not kill a 10-minute wait — retry until timeout.
        if (Date.now() - started > timeoutMs) throw e;
      }
      if (Date.now() - started > timeoutMs) {
        const partials = await this.partialCount(taskId).catch(() => -1n);
        throw new Error(`reveal for task ${taskId} did not complete within ${timeoutMs}ms (${partials} partials submitted)`);
      }
      await new Promise((r) => setTimeout(r, pollMs));
    }
  }
}
