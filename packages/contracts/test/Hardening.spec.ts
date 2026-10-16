import { time } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";

import { CipherTask, DecryptionGate, MockBLS, MockStarkVerifier, PaymentVault, TestToken } from "../typechain-types";
import { bytes32Of, externalUint64, matureRewardWindows, params, proofFor, proofRef } from "./helpers";
import { deployLinked } from "../scripts/libraries";

/**
 * Regression coverage for the hardening pass:
 * - contribution anti-spam bonds (F-01): requirement, pull, release, slash-to-treasury
 * - dispute commit-reveal (mempool front-run resistance)
 * - node registration proof-of-possession over the BLS key
 * - segmented-proof commit path (F-33: previously unreachable)
 * - final-page settlement gate on immature reward channels (F-22)
 * - task-manager rotation anti-overwrite
 * - `openEpoch` no longer callable by the contract owner
 */
describe("Hardening", () => {
  type Fx = Awaited<ReturnType<typeof deployFixture>>;

  async function deployFixture() {
    const [owner, buyer, alice, bob, node, node2, node3, outsider, treasury] = await ethers.getSigners();
    const token: TestToken = await ethers.deployContract("TestToken");
    const vault: PaymentVault = await ethers.deployContract("PaymentVault", [await token.getAddress()]);
    const verifier: MockStarkVerifier = await ethers.deployContract("MockStarkVerifier", [48_576]);
    const bls: MockBLS = await ethers.deployContract("MockBLS");
    const gate: DecryptionGate = await ethers.deployContract("DecryptionGate", [
      await bls.getAddress(),
      bytes32Of("bls-agg"),
      1,
    ]);
    const task: CipherTask = await deployLinked("CipherTask", [
      await token.getAddress(),
      await vault.getAddress(),
      await verifier.getAddress(),
      await gate.getAddress(),
      treasury.address,
      false,
    ]);
    await vault.setTaskManager(await task.getAddress());
    await gate.setCipherTask(await task.getAddress());
    await gate.initialize(owner.address, [owner.address]);

    const escrow = 1_000_000_000n;
    await token.mint(buyer.address, escrow);
    await token.connect(buyer).approve(await vault.getAddress(), ethers.MaxUint256);
    const bond = await vault.REGISTRATION_BOND();
    for (const n of [node, node2, node3]) {
      await token.mint(n.address, bond);
      await token.connect(n).approve(await vault.getAddress(), ethers.MaxUint256);
    }
    return { token, vault, verifier, bls, gate, task, escrow, owner, buyer, alice, bob, node, node2, node3, outsider, treasury };
  }

  async function fullTask(fx: Fx, contributors: { signer: typeof fx.alice; rows: number }[]) {
    const { task, buyer } = fx;
    await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 1, epochs: 1 }));
    const id = await task.taskCount();
    let i = 0;
    for (const c of contributors) {
      await task
        .connect(c.signer)
        .submitContribution(id, bytes32Of(100 + i), bytes32Of(200 + i), proofFor(i), bytes32Of(300 + i), c.rows);
      i++;
    }
    return id;
  }

  async function runEpoch(fx: Fx, id: bigint, node: typeof fx.node) {
    const { task, buyer } = fx;
    await task.connect(buyer).sealTask(id);
    await task.connect(node).registerNode(id, bytes32Of(9000 + Number(id)));
    const st = await externalUint64(await task.getAddress(), buyer.address, 0n);
    await task.connect(buyer).openEpoch(id, bytes32Of(101), bytes32Of(102), st.handle, st.proof);
    await task
      .connect(node)
      .commitEpoch(id, 0, proofRef(7), bytes32Of(301), bytes32Of(401), bytes32Of(501), bytes32Of(999));
    await time.increase(3600 + 600 + 1);
    await task.finalizeEpoch(id, 0);
  }

  describe("contribution bonds (F-01)", () => {
    it("only the buyer/manager sets the requirement, capped and before seal", async () => {
      const fx = await deployFixture();
      const { task, buyer, outsider } = fx;
      await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 1, epochs: 1 }));
      const id = await task.taskCount();

      await expect(task.connect(outsider).setContributionBondRequirement(id, 1_000_000n)).to.be.revertedWithCustomError(
        task,
        "NotUpdateManagerOrOwner"
      );
      const cap = await task.MAX_CONTRIBUTION_BOND();
      await expect(task.connect(buyer).setContributionBondRequirement(id, cap + 1n)).to.be.revertedWithCustomError(
        task,
        "BondRequirementInvalid"
      );
      await expect(task.connect(buyer).setContributionBondRequirement(id, 1_000_000n)).to.emit(
        task,
        "ContributionBondRequirementSet"
      );
      expect(await task.contributionBondRequired(id)).to.equal(1_000_000n);

      await fx.token.mint(fx.alice.address, 1_000_000n);
      await fx.token.connect(fx.alice).approve(await task.getAddress(), 1_000_000n);
      await task.connect(fx.alice).submitContribution(id, bytes32Of(1), bytes32Of(2), proofFor(3), bytes32Of(4), 1_000);
      await task.connect(buyer).sealTask(id);
      await expect(task.connect(buyer).setContributionBondRequirement(id, 0n)).to.be.revertedWithCustomError(
        task,
        "InvalidTaskStatus"
      );
    });

    it("submit pulls the bond; release works only once settleable; slash pays the treasury", async () => {
      const fx = await deployFixture();
      const { task, token, vault, buyer, alice, bob, treasury } = fx;
      const bondReq = 1_000_000n;
      await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 1, epochs: 1 }));
      const id = await task.taskCount();
      await task.connect(buyer).setContributionBondRequirement(id, bondReq);

      // Without approving the task, submission reverts instead of recording a bond never posted.
      await expect(
        task.connect(alice).submitContribution(id, bytes32Of(1), bytes32Of(2), proofFor(3), bytes32Of(4), 1_000)
      ).to.be.reverted;
      await token.mint(alice.address, bondReq);
      await token.connect(alice).approve(await task.getAddress(), bondReq);
      await token.mint(bob.address, bondReq);
      await token.connect(bob).approve(await task.getAddress(), bondReq);
      await task.connect(alice).submitContribution(id, bytes32Of(1), bytes32Of(2), proofFor(3), bytes32Of(4), 1_000);
      await task.connect(bob).submitContribution(id, bytes32Of(5), bytes32Of(6), proofFor(7), bytes32Of(8), 1_000);
      expect(await task.contributionBondOf(id, alice.address)).to.equal(bondReq);

      // Release before the task is settleable reverts; slash sends to the treasury, not the buyer.
      await expect(task.releaseContributionBond(id, alice.address)).to.be.revertedWithCustomError(task, "BondNotReleasable");
      const treasuryBefore = await token.balanceOf(treasury.address);
      await expect(task.connect(buyer).slashContributionBond(id, alice.address)).to.emit(task, "ContributionBondSlashed");
      expect(await token.balanceOf(treasury.address)).to.equal(treasuryBefore + bondReq);
      expect((await task.contributions(id, alice.address)).slashed).to.equal(true);
      await expect(task.releaseContributionBond(id, alice.address)).to.be.revertedWithCustomError(task, "NoBondToRelease");

      // Settle: the slashed contribution earns nothing.
      await runEpochOnly(fx, id);
      await matureRewardWindows();
      await task.settle(id);
      expect(await task.pendingPayout(alice.address)).to.equal(0n);
      expect(await task.pendingPayout(bob.address)).to.be.greaterThan(0n);

      // After settlement the slash path is closed (anti-grief cutoff): post-hoc burns
      // of honest contributors' unreleased bonds revert, while release still works.
      await expect(task.connect(buyer).slashContributionBond(id, bob.address)).to.be.revertedWithCustomError(
        task,
        "AlreadySettled"
      );

      // The honest bond releases to its contributor.
      const bobBefore = await token.balanceOf(bob.address);
      await task.releaseContributionBond(id, bob.address);
      expect(await token.balanceOf(bob.address)).to.equal(bobBefore + bondReq);
      void vault;
    });

    it("tasks without a requirement behave exactly as before (bond defaults to zero)", async () => {
      const fx = await deployFixture();
      const { task, buyer, alice } = fx;
      const id = await fullTask(fx, [{ signer: alice, rows: 1_000 }]);
      expect(await task.contributionBondRequired(id)).to.equal(0n);
      expect(await task.contributionBondOf(id, alice.address)).to.equal(0n);
      void buyer;
    });
  });

  /** Seal+register+open+commit+finalize for a task whose contributions already landed. */
  async function runEpochOnly(fx: Fx, id: bigint) {
    const { task, buyer, node } = fx;
    await task.connect(buyer).sealTask(id);
    await task.connect(node).registerNode(id, bytes32Of(4242));
    const st = await externalUint64(await task.getAddress(), buyer.address, 0n);
    await task.connect(buyer).openEpoch(id, bytes32Of(101), bytes32Of(102), st.handle, st.proof);
    await task
      .connect(node)
      .commitEpoch(id, 0, proofRef(7), bytes32Of(301), bytes32Of(401), bytes32Of(501), bytes32Of(999));
    await time.increase(3600 + 600 + 1);
    await task.finalizeEpoch(id, 0);
  }

  describe("dispute commit-reveal", () => {
    it("commit then reveal counts; bare report is closed while committed; wrong salt fails", async () => {
      const fx = await deployFixture();
      const { task, buyer, node, node2 } = fx;
      await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 1, epochs: 1 }));
      const id = await task.taskCount();
      await task.connect(fx.alice).submitContribution(id, bytes32Of(1), bytes32Of(2), proofFor(3), bytes32Of(4), 1_000);
      await task.connect(buyer).sealTask(id);
      await task.connect(node).registerNode(id, bytes32Of(5001));
      await task.connect(node2).registerNode(id, bytes32Of(5002));
      const st = await externalUint64(await task.getAddress(), buyer.address, 0n);
      await task.connect(buyer).openEpoch(id, bytes32Of(101), bytes32Of(102), st.handle, st.proof);
      const digestA = bytes32Of("digest-a");
      const digestB = bytes32Of("digest-b");
      await task.connect(node).commitEpoch(id, 0, proofRef(11), bytes32Of(311), bytes32Of(411), bytes32Of(511), digestA);
      await task.connect(node2).commitEpoch(id, 0, proofRef(12), bytes32Of(312), bytes32Of(412), bytes32Of(512), digestB);
      const winner = await task.epochWinner(id, 0);
      const challenger = winner === node.address ? node2 : node;
      const challengerDigest = challenger === node ? digestA : digestB;

      const salt = bytes32Of("salt-1");
      const commitment = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32", "address"], [challengerDigest, salt, challenger.address])
      );
      await expect(task.connect(challenger).commitDispute(id, 0, commitment)).to.emit(task, "DisputeCommitted");
      await expect(task.connect(challenger).reportDispute(id, 0, challengerDigest)).to.be.revertedWithCustomError(
        task,
        "CommitmentPending"
      );
      await expect(
        task.connect(challenger).reportDisputeWithSalt(id, 0, challengerDigest, bytes32Of("wrong-salt"))
      ).to.be.revertedWithCustomError(task, "CommitmentMismatch");
      await expect(task.connect(challenger).reportDisputeWithSalt(id, 0, challengerDigest, salt)).to.emit(
        task,
        "DisputeReported"
      );
    });
  });

  describe("node registration proof-of-possession", () => {
    async function popSig(
      fx: Fx,
      id: bigint,
      blsKey: string,
      signer: typeof fx.node
    ): Promise<string> {
      const net = await ethers.provider.getNetwork();
      const inner = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["uint256", "bytes32", "address", "uint256", "address"],
          [id, blsKey, signer.address, net.chainId, await fx.task.getAddress()]
        )
      );
      return signer.signMessage(ethers.getBytes(inner));
    }

    it("registers with a valid possession signature and rejects forgeries", async () => {
      const fx = await deployFixture();
      const { task, buyer, node, outsider } = fx;
      await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 1, epochs: 1 }));
      const id = await task.taskCount();
      const key = bytes32Of("node-bls-key");
      await expect(task.connect(node).registerNodeWithPop(id, key, await popSig(fx, id, key, node))).to.emit(
        task,
        "NodeRegistered"
      );
      expect(await task.nodeRegistered(id, node.address)).to.equal(true);

      // Another key needs its own signature; replaying no signature at all fails.
      await expect(task.connect(outsider).registerNodeWithPop(id, bytes32Of("other"), "0x")).to.be.revertedWithCustomError(
        task,
        "InvalidPopSignature"
      );
      // A signature by the wrong signer fails even for a fresh key.
      const forged = await popSig(fx, id, bytes32Of("forged"), outsider);
      await expect(task.connect(node).registerNodeWithPop(id, bytes32Of("forged"), forged)).to.be.revertedWithCustomError(
        task,
        "InvalidPopSignature"
      );
    });
  });

  describe("segmented commits (F-33)", () => {
    it("accepts a segmented root through the segmented path and settles the epoch", async () => {
      const fx = await deployFixture();
      const { task, buyer, node } = fx;
      await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 1, epochs: 1 }));
      const id = await task.taskCount();
      await task.connect(fx.alice).submitContribution(id, bytes32Of(1), bytes32Of(2), proofFor(3), bytes32Of(4), 1_000);
      await task.connect(buyer).sealTask(id);
      await task.connect(node).registerNode(id, bytes32Of(777));
      const st = await externalUint64(await task.getAddress(), buyer.address, 0n);
      await task.connect(buyer).openEpoch(id, bytes32Of(101), bytes32Of(102), st.handle, st.proof);
      await expect(
        task.connect(node).commitEpochSegmented(id, 0, proofRef(77), bytes32Of(301), bytes32Of(401), bytes32Of(501), bytes32Of(999))
      ).to.emit(task, "EpochCommitted");
      await time.increase(3600 + 600 + 1);
      await task.finalizeEpoch(id, 0);
      expect(await task.epochWinner(id, 0)).to.equal(node.address);
    });
  });

  describe("settlement waits for reward maturity (F-22)", () => {
    it("reverts ChannelsImmature on the final page until the window passes", async () => {
      const fx = await deployFixture();
      const { task, buyer } = fx;
      await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 1, epochs: 1 }));
      const id = await task.taskCount();
      await task.connect(fx.alice).submitContribution(id, bytes32Of(1), bytes32Of(2), proofFor(3), bytes32Of(4), 1_000);
      await runEpochOnly(fx, id);
      await expect(task.settle(id)).to.be.revertedWithCustomError(task, "ChannelsImmature");
      await matureRewardWindows();
      await expect(task.settle(id)).to.emit(task, "EscrowSettled");
    });

    it("a reverted settlement page changes nothing: bonds still slash afterwards", async () => {
      // Revert rolls the whole page back — including `started` — so a ChannelsImmature
      // revert leaves slash/reclaim exactly as legitimate as before the attempt. The
      // SettlementBegun guards only fire after a page actually succeeded (multi-page
      // tasks), which needs more contributors than test chains provide.
      const fx = await deployFixture();
      const { task, buyer, token, vault, treasury } = fx;
      const bondReq = 1_000_000n;
      await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 1, epochs: 1 }));
      const id = await task.taskCount();
      await task.connect(buyer).setContributionBondRequirement(id, bondReq);
      await token.mint(fx.alice.address, bondReq);
      await token.connect(fx.alice).approve(await task.getAddress(), bondReq);
      await task.connect(fx.alice).submitContribution(id, bytes32Of(1), bytes32Of(2), proofFor(3), bytes32Of(4), 1_000);
      await runEpochOnly(fx, id);
      await expect(task.settle(id)).to.be.revertedWithCustomError(task, "ChannelsImmature");
      await expect(task.connect(buyer).slashContributionBond(id, fx.alice.address))
        .to.emit(task, "ContributionBondSlashed");
      expect((await task.contributions(id, fx.alice.address)).slashed).to.equal(true);
      await matureRewardWindows();
      await task.settle(id);
      expect(await task.pendingPayout(fx.alice.address)).to.equal(0n);
      expect(await task.pendingPayout(treasury.address)).to.be.greaterThan(0n);
      void vault;
    });

    it("a reverted settlement page changes nothing: reclaim still works afterwards", async () => {
      // The winner's channel is immature (not expired), so there is nothing reclaimable
      // yet — but the call must succeed as a no-op, proving the reverted page left no
      // half-written settlement state behind.
      const fx = await deployFixture();
      const { task, buyer, vault } = fx;
      await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 1, epochs: 1 }));
      const id = await task.taskCount();
      await task.connect(fx.alice).submitContribution(id, bytes32Of(1), bytes32Of(2), proofFor(3), bytes32Of(4), 1_000);
      await runEpochOnly(fx, id);
      await expect(task.settle(id)).to.be.revertedWithCustomError(task, "ChannelsImmature");
      await task.connect(buyer).reclaimUnspentEpochs(id);
      expect(await vault.taskBalance(id)).to.equal(850_000_000n);
    });

    it("reports the actually-paid committee leg in EscrowSettled, not the nominal pool", async () => {
      const fx = await deployFixture();
      const { task, buyer, vault, treasury } = fx;
      await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 1, epochs: 1 }));
      const id = await task.taskCount();
      await task.connect(fx.alice).submitContribution(id, bytes32Of(1), bytes32Of(2), proofFor(3), bytes32Of(4), 1_000);
      await runEpochOnly(fx, id);
      await matureRewardWindows();
      const tx = await task.settle(id);
      const rcpt = await tx.wait();
      expect(rcpt, "settle receipt").to.not.equal(null);
      const evt = rcpt!.logs
        .map((l) => {
          try {
            return task.interface.parseLog(l);
          } catch {
            return null;
          }
        })
        .find((e) => e?.name === "EscrowSettled");
      expect(evt, "EscrowSettled emitted").to.not.equal(null);
      // Pull-based legs: the treasury's credit is the paid amount by construction.
      expect(evt!.args[2]).to.equal(await task.pendingPayout(treasury.address));
      void vault;
    });
  });

  describe("governance hardening", () => {
    it("refuses to overwrite a live task-manager rotation; cancel then propose works", async () => {
      const fx = await deployFixture();
      const { vault, owner, outsider } = fx;
      await vault.connect(owner).proposeTaskManager(outsider.address);
      await expect(vault.connect(owner).proposeTaskManager(owner.address)).to.be.revertedWithCustomError(
        vault,
        "PendingRotationExists"
      );
      await vault.connect(owner).cancelTaskManager();
      await vault.connect(owner).proposeTaskManager(owner.address);
    });

    it("the contract owner cannot publish epochs", async () => {
      const fx = await deployFixture();
      const { task, buyer, owner } = fx;
      await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 1, epochs: 1 }));
      const id = await task.taskCount();
      await task.connect(fx.alice).submitContribution(id, bytes32Of(1), bytes32Of(2), proofFor(3), bytes32Of(4), 1_000);
      await task.connect(buyer).sealTask(id);
      const st = await externalUint64(await task.getAddress(), buyer.address, 0n);
      await expect(
        task.connect(owner).openEpoch(id, bytes32Of(101), bytes32Of(102), st.handle, st.proof)
      ).to.be.revertedWithCustomError(task, "NotUpdateManagerOrOwner");
    });
  });
});
