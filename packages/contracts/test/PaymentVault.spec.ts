import { time } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import type { Signer } from "ethers";
import { ethers } from "hardhat";

import { PaymentVault, TestToken } from "../typechain-types";
import { redeemDigest, sliceDomain } from "./helpers";

/**
 * `PaymentVault` governance and the EOA-streamer redemption path.
 *
 * The vault holds every task's escrow and can move any of it on one instruction from `taskManager`.
 * These tests pin who may change that address, how fast the change takes effect, what happens to
 * tokens that were never escrowed, and the redemption branch only an EOA manager can reach.
 */
describe("PaymentVault", () => {
  async function fixture() {
    const [owner, stranger, earner] = await ethers.getSigners();
    const token: TestToken = await ethers.deployContract("TestToken");
    const vault: PaymentVault = await ethers.deployContract("PaymentVault", [await token.getAddress()]);
    const chainId = (await ethers.provider.getNetwork()).chainId;
    return { token, vault, owner, stranger, earner, chainId };
  }

  /**
   * Put `amount` of escrow under `taskId`, pulled from `owner`.
   *
   * `fundTask` is `onlyTaskManager` but takes the token holder as a separate argument, so `payer`
   * (who signs) and the source of the tokens (`owner`, who approves) are not the same thing.
   */
  async function fund(fx: Awaited<ReturnType<typeof fixture>>, taskId: bigint, amount: bigint, payer?: Signer) {
    const { token, vault, owner } = fx;
    await token.mint(owner.address, amount);
    await token.connect(owner).approve(await vault.getAddress(), amount);
    await vault.connect(payer ?? owner).fundTask(taskId, amount, owner.address);
  }

  describe("task manager authority", () => {
    it("installs the manager once and refuses a second direct swap", async () => {
      const fx = await fixture();
      const { vault, owner, stranger } = fx;
      await vault.setTaskManager(stranger.address);
      expect(await vault.taskManager()).to.equal(stranger.address);

      // The slot is occupied, so the only way to move it is the timelock below. Without this, one
      // owner transaction could repoint the manager, and `onlyTaskManager` covers `creditFromTask`,
      // `openTaskChannel` and `sweepTaskChannels` together: the whole vault.
      await expect(vault.setTaskManager(owner.address)).to.be.revertedWithCustomError(vault, "TaskManagerAlreadySet");
      // `staticCall` rather than a sent transaction: `@fhevm/hardhat-plugin` replaces a revert that
      // arrives with calldata an `address` argument in it with its own assertion error, so the sent
      // form hides which check actually failed. The simulation runs the same modifier.
      await expect(vault.connect(stranger).setTaskManager.staticCall(owner.address)).to.be.revertedWithCustomError(vault, "NotOwner");
      await expect(vault.setTaskManager(ethers.ZeroAddress)).to.be.revertedWithCustomError(vault, "ZeroAddress");
    });

    it("cannot rotate to the address that already holds the role", async () => {
      const fx = await fixture();
      const { vault, stranger } = fx;
      await vault.setTaskManager(stranger.address);
      await expect(vault.proposeTaskManager(stranger.address)).to.be.revertedWithCustomError(vault, "TaskManagerUnchanged");
      await expect(vault.proposeTaskManager(ethers.ZeroAddress)).to.be.revertedWithCustomError(vault, "ZeroAddress");
      await expect(vault.connect(stranger).proposeTaskManager.staticCall(fx.earner.address)).to.be.revertedWithCustomError(vault, "NotOwner");
      // Queuing is not installing: the announcement is what the week is for.
      expect(await vault.taskManager()).to.equal(stranger.address);
      expect(await vault.proposedTaskManager()).to.equal(ethers.ZeroAddress);
    });

    it("holds a rotation for the full delay, then lets anyone execute it", async () => {
      const fx = await fixture();
      const { vault, owner, stranger } = fx;
      await vault.setTaskManager(owner.address);
      await vault.proposeTaskManager(stranger.address);
      expect(await vault.taskManager()).to.equal(owner.address);

      await expect(vault.executeTaskManager()).to.be.revertedWithCustomError(vault, "TaskManagerNotReady");

      await time.increase(await vault.TASK_MANAGER_DELAY());
      // Executed by an unrelated account: the owner must not be able to hold an announced rotation
      // hostage by simply never calling this.
      const tx = await vault.connect(stranger).executeTaskManager();
      await expect(tx).to.emit(vault, "TaskManagerChanged").withArgs(owner.address, stranger.address);
      expect(await vault.taskManager()).to.equal(stranger.address);
      expect(await vault.proposedTaskManager()).to.equal(ethers.ZeroAddress);
      await expect(vault.executeTaskManager()).to.be.revertedWithCustomError(vault, "NoPendingTaskManager");
    });

    it("cancels a queued rotation without touching the installed manager", async () => {
      const fx = await fixture();
      const { vault, owner, stranger, earner } = fx;
      await vault.setTaskManager(owner.address);
      await vault.proposeTaskManager(stranger.address);
      await expect(vault.connect(stranger).cancelTaskManager()).to.be.revertedWithCustomError(vault, "NotOwner");

      const tx = await vault.cancelTaskManager();
      await expect(tx).to.emit(vault, "TaskManagerRotationCancelled").withArgs(stranger.address);
      expect(await vault.taskManager()).to.equal(owner.address);
      expect(await vault.proposedTaskManager()).to.equal(ethers.ZeroAddress);
      await expect(vault.cancelTaskManager()).to.be.revertedWithCustomError(vault, "NoPendingTaskManager");
      void earner;
    });

    it("keeps a rotated-in manager powerless while the vault is paused", async () => {
      // The delay is only worth having if pausing blocks what a hostile manager could do.
      const fx = await fixture();
      const { vault, token, owner, stranger } = fx;
      await vault.setTaskManager(owner.address);
      await fund(fx, 1n, 500_000n);
      await vault.proposeTaskManager(stranger.address);
      await vault.setPaused(true);
      // The rotation itself is not paused: `executeTaskManager` moves a role, never money, and
      // blocking it would let a pause freeze an announced rotation forever.
      await time.increase(await vault.TASK_MANAGER_DELAY());
      await vault.executeTaskManager();
      expect(await vault.taskManager()).to.equal(stranger.address);

      // Every function that can move escrow is gated, one at a time so a single failure names the
      // call that slipped through.
      // Simulated (see the note on `NotOwner` above) but from the rotated-in manager, so this is
      // exactly the account the pause has to hold.
      await expect(vault.connect(stranger).creditFromTask.staticCall(1n, stranger.address, 100n)).to.be.revertedWithCustomError(vault, "Paused");
      await expect(vault.connect(stranger).openTaskChannel.staticCall(1n, stranger.address, 100n, 0)).to.be.revertedWithCustomError(vault, "Paused");
      await expect(vault.connect(stranger).sweepTaskChannels.staticCall(1n)).to.be.revertedWithCustomError(vault, "Paused");
      await expect(vault.connect(stranger).fundTask.staticCall(2n, 100n, owner.address)).to.be.revertedWithCustomError(vault, "Paused");
      expect(await token.balanceOf(await vault.getAddress())).to.equal(500_000n);
    });
  });

  describe("ownership", () => {
    it("transfers only when the recipient accepts", async () => {
      const fx = await fixture();
      const { vault, owner, stranger } = fx;
      const tx = await vault.transferOwnership(stranger.address);
      await expect(tx).to.emit(vault, "OwnershipTransferStarted").withArgs(owner.address, stranger.address);
      // A typo in `to` used to be final: the old owner lost the key and nothing could undo it.
      expect(await vault.owner()).to.equal(owner.address);
      expect(await vault.pendingOwner()).to.equal(stranger.address);

      await expect(vault.connect(owner).acceptOwnership()).to.be.revertedWithCustomError(vault, "NotOwner");
      await vault.connect(stranger).acceptOwnership();
      expect(await vault.owner()).to.equal(stranger.address);
      expect(await vault.pendingOwner()).to.equal(ethers.ZeroAddress);

      // The new owner holds the levers; the old one holds none.
      await expect(vault.connect(owner).setPaused(true)).to.be.revertedWithCustomError(vault, "NotOwner");
      await vault.connect(stranger).setPaused(true);
    });

    it("refuses a handover to the zero address", async () => {
      const { vault } = await fixture();
      await expect(vault.transferOwnership(ethers.ZeroAddress)).to.be.revertedWithCustomError(vault, "ZeroAddress");
    });

    it("names its first owner in the deployment log", async () => {
      const fx = await fixture();
      // The two-step handover only means something if genesis is auditable: without this event the
      // first owner is a storage slot with no record of when it was set.
      const vault: PaymentVault = await ethers.deployContract("PaymentVault", [await fx.token.getAddress()]);
      await expect(vault.deploymentTransaction()).to.emit(vault, "OwnershipTransferred").withArgs(ethers.ZeroAddress, fx.owner.address);
      expect(await vault.owner()).to.equal(fx.owner.address);
      expect(await vault.pendingOwner()).to.equal(ethers.ZeroAddress);
    });
  });

  describe("stray tokens", () => {
    it("returns a mistaken direct transfer to the owner", async () => {
      const fx = await fixture();
      const { vault, token, owner, stranger } = fx;
      await token.mint(stranger.address, 250_000n);
      // Not `fundTask`: this never entered anyone's escrow, it just landed on the address.
      await token.connect(stranger).transfer(await vault.getAddress(), 250_000n);
      expect(await vault.totalLocked()).to.equal(0n);

      const tx = await vault.rescueStrayTokens();
      await expect(tx).to.emit(vault, "StrayTokensRescued").withArgs(owner.address, 250_000n);
      expect(await token.balanceOf(owner.address)).to.equal(250_000n);
      await expect(vault.rescueStrayTokens()).to.be.revertedWithCustomError(vault, "NothingToRescue");
    });

    it("rescues nothing that is escrowed or owed", async () => {
      const fx = await fixture();
      const { vault, token, owner, stranger, earner } = fx;
      await vault.setTaskManager(owner.address);
      await fund(fx, 1n, 500_000n);
      await expect(vault.rescueStrayTokens()).to.be.revertedWithCustomError(vault, "NothingToRescue");

      // A credited-but-unclaimed amount has already left `totalLocked` while its tokens are still
      // in the vault, so `pendingTotal` is what keeps it out of the rescue.
      await vault.creditFromTask(1n, earner.address, 200_000n);
      expect(await vault.totalLocked()).to.equal(300_000n);
      expect(await vault.pendingTotal()).to.equal(200_000n);
      await expect(vault.rescueStrayTokens()).to.be.revertedWithCustomError(vault, "NothingToRescue");

      await vault.connect(earner).claim();
      expect(await vault.pendingTotal()).to.equal(0n);
      expect(await token.balanceOf(earner.address)).to.equal(200_000n);
      await expect(vault.rescueStrayTokens()).to.be.revertedWithCustomError(vault, "NothingToRescue");

      // Only a genuine over-deposit becomes rescuable, and only the escrow stays behind.
      await token.mint(stranger.address, 123n);
      await token.connect(stranger).transfer(await vault.getAddress(), 123n);
      await vault.rescueStrayTokens();
      expect(await token.balanceOf(owner.address)).to.equal(123n);
      expect(await vault.taskBalance(1n)).to.equal(300_000n);
    });

    it("is owner-only", async () => {
      const fx = await fixture();
      const { vault, token, stranger } = fx;
      await token.mint(stranger.address, 10n);
      await token.connect(stranger).transfer(await vault.getAddress(), 10n);
      await expect(vault.connect(stranger).rescueStrayTokens()).to.be.revertedWithCustomError(vault, "NotOwner");
    });
  });

  describe("EOA streamer", () => {
    it("computes the domain separator the SDK pins", () => {
      // The SDK recomputes this separator locally and hands the digest to the vault, so
      // the two must agree byte for byte. The live redeem below signs with this helper's
      // value and the vault accepts it, which pins the formula; this pins the value, which
      // is what ties the SDK's copy to it. If either side changed, one of the two tests
      // would fail - and a divergence would show up in production as every slice
      // redemption rejected with InvalidSignature.
      expect(
        sliceDomain("0x0000000000000000000000000000000000000001", 31337n).domainSeparator
      ).to.equal("0x7daba0f7c50d1c8fd8026e05236fc6a200ce2bacc02f5c91de5630ce317cc423");
    });

    /**
     * A channel's streamer is always whoever called `openTaskChannel`, i.e. the task manager. With
     * `CipherTask` in that role the slice is an ERC-1271 blob (covered in `CipherTask.spec.ts`);
     * with an EOA manager the same `redeem` takes a 65-byte ECDSA signature instead. That branch
     * existed with no test on it, which is how a code path can be both documented and unreachable.
     */
    async function eoaFixture(maxCumulative: bigint) {
      const fx = await fixture();
      const manager = ethers.Wallet.createRandom().connect(ethers.provider);
      await fx.owner.sendTransaction({ to: manager.address, value: ethers.parseEther("1") });
      await fx.vault.setTaskManager(manager.address);
      // `fundTask` is `onlyTaskManager`, so the escrow now has to come in through the wallet that
      // holds the role; the tokens still belong to `owner`, who approves them.
      await fund(fx, 1n, maxCumulative, manager);

      const unlockAt = BigInt((await time.latest()) + 3600);
      const tx = await fx.vault.connect(manager).openTaskChannel(1n, fx.earner.address, maxCumulative, unlockAt);
      await tx.wait();
      const channelId = await fx.vault.channelNonce();
      const ch = await fx.vault.channelInfo(channelId);
      return { ...fx, manager, taskId: 1n, channelId, ch, unlockAt };
    }

    type EoaFx = Awaited<ReturnType<typeof eoaFixture>>;

    /** Sign, or deliberately mis-sign, the digest `redeem` checks. */
    function sliceSignature(fx: EoaFx, tamper?: "malleable" | "badV") {
      const domain = sliceDomain(fx.vault.target as string, fx.chainId);
      const digest = redeemDigest({
        domainSeparator: domain.domainSeparator,
        channelId: fx.channelId,
        streamer: fx.manager.address,
        node: fx.earner.address,
        maxCumulative: fx.ch.maxCumulative,
        unlockAt: fx.unlockAt,
        deadline: ethers.MaxUint256
      });
      const sig = new ethers.SigningKey(fx.manager.privateKey as string).sign(digest);
      if (tamper === undefined) return sig.serialized;
      if (tamper === "badV") return ethers.concat([sig.r, sig.s, ethers.toBeHex(sig.v === 27 ? 26 : 29, 1)]);
      // The malleable twin: s' = n - s with v flipped. `Signature.from` refuses to build a
      // non-canonical s, so the 65 bytes (r || s || v) are assembled directly.
      const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
      return ethers.concat([sig.r, ethers.zeroPadValue("0x" + (n - BigInt(sig.s)).toString(16), 32), ethers.toBeHex(sig.v === 27 ? 28 : 27, 1)]);
    }

    it("opens with the manager as streamer and redeems a slice it signed", async () => {
      const fx = await eoaFixture(400_000n);
      expect(fx.ch.streamer).to.equal(fx.manager.address);
      expect(fx.ch.node).to.equal(fx.earner.address);

      await fx.vault.connect(fx.earner).redeem(fx.channelId, 0, 150_000n, ethers.MaxUint256, sliceSignature(fx));
      expect(await fx.token.balanceOf(fx.earner.address)).to.equal(150_000n);
      expect(await fx.vault.totalLocked()).to.equal(await fx.vault.accountedLocked());
    });

    it("rejects the malleable twin of an otherwise valid signature", async () => {
      const fx = await eoaFixture(400_000n);
      await expect(
        fx.vault.connect(fx.earner).redeem(fx.channelId, 0, 150_000n, ethers.MaxUint256, sliceSignature(fx, "malleable"))
      ).to.be.revertedWithCustomError(fx.vault, "InvalidSignature");
    });

    it("rejects a recovery id outside 27 and 28", async () => {
      const fx = await eoaFixture(400_000n);
      await expect(
        fx.vault.connect(fx.earner).redeem(fx.channelId, 0, 150_000n, ethers.MaxUint256, sliceSignature(fx, "badV"))
      ).to.be.revertedWithCustomError(fx.vault, "InvalidSignature");
    });

    it("authenticates before consuming a slice index, even when the slice pays nothing", async () => {
      const fx = await eoaFixture(400_000n);
      const { vault, earner } = fx;

      // Pay slice 0 properly first, so the zero-payment path below is reachable.
      await vault.connect(earner).redeem(fx.channelId, 0, 150_000n, ethers.MaxUint256, sliceSignature(fx));
      expect((await vault.channelInfo(fx.channelId)).consumed).to.equal(1n);

      // Slice 1 at the same cumulative amount pays nothing. That path used to bump `consumed`
      // before checking the signature at all, so the replay counter advanced on unauthenticated
      // input. A garbage signature must now revert and leave the counter where it was.
      const junk = ethers.concat([ethers.ZeroHash, ethers.ZeroHash, ethers.toBeHex(27, 1)]);
      await expect(vault.connect(earner).redeem(fx.channelId, 1, 150_000n, ethers.MaxUint256, junk)).to.be.revertedWithCustomError(
        vault,
        "InvalidSignature"
      );
      expect((await vault.channelInfo(fx.channelId)).consumed).to.equal(1n);

      // Authenticated, the same call is accepted and still pays nothing: `redeem` consumes the
      // index and returns without touching the money, and it emits nothing because no value moved.
      await vault.connect(earner).redeem(fx.channelId, 1, 150_000n, ethers.MaxUint256, sliceSignature(fx));
      expect((await vault.channelInfo(fx.channelId)).consumed).to.equal(2n);
      expect((await vault.channelInfo(fx.channelId)).withdrawn).to.equal(150_000n);
      expect(await fx.token.balanceOf(earner.address)).to.equal(150_000n);
    });

    it("lets the EOA streamer close its own channel and return the remainder to the task", async () => {
      const fx = await eoaFixture(400_000n);
      await expect(fx.vault.connect(fx.stranger).closeChannel(fx.channelId)).to.be.revertedWithCustomError(fx.vault, "NotStreamer");

      const tx = await fx.vault.connect(fx.manager).closeChannel(fx.channelId);
      await expect(tx).to.emit(fx.vault, "ChannelClosedByStreamer").withArgs(fx.channelId, 400_000n, fx.taskId);
      expect(await fx.vault.taskBalance(fx.taskId)).to.equal(400_000n);
      expect(await fx.vault.totalLocked()).to.equal(await fx.vault.accountedLocked());
    });
  });
});
