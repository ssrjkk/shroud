import { expect } from "chai";
import { artifacts, ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

import { deployLinked } from "../scripts/libraries";
import { bytes32Of, params } from "./helpers";

/**
 * Owner-gated switches on the orchestrator.
 *
 * The treasury decides where every slashed bond and every committee leg goes, and the
 * shape-proof requirement decides whether a contribution has to prove that its rows
 * match the buyer's shape. Both used to be single-call switches: one transaction moved
 * the money, or dropped the proof requirement, with no window in which anybody could
 * notice. The treasury now waits behind a rotation delay, and the proof requirement is
 * a ratchet — it can be tightened, never loosened.
 *
 * Each behaviour is pinned here: who may act, what it rejects, and when the change
 * actually lands.
 */
describe("AdminControls", () => {
  async function fixture() {
    const [owner, buyer, alice, outsider] = await ethers.getSigners();
    const token = await ethers.deployContract("TestToken");
    const vault = await ethers.deployContract("PaymentVault", [await token.getAddress()]);
    const verifier = await ethers.deployContract("MockStarkVerifier", [48_576]);
    const bls = await ethers.deployContract("MockBLS");
    const gate = await ethers.deployContract("DecryptionGate", [
      await bls.getAddress(),
      bytes32Of("bls-agg"),
      1,
    ]);
    const task = await deployLinked("CipherTask", [
      await token.getAddress(),
      await vault.getAddress(),
      await verifier.getAddress(),
      await gate.getAddress(),
      buyer.address,
      true,
    ]);
    await vault.setTaskManager(await task.getAddress());
    const escrow = 1_000_000_000n;
    await token.mint(buyer.address, escrow);
    await token.connect(buyer).approve(await vault.getAddress(), ethers.MaxUint256);
    return { token, vault, task, owner, buyer, alice, outsider, escrow };
  }

  describe("treasury rotation", () => {
    it("queues the change instead of moving the treasury, and says when it lands", async () => {
      const fx = await fixture();
      const { task, owner, outsider } = fx;
      const to = outsider.address;

      await expect(task.connect(owner).proposeTreasury(to)).to.emit(task, "TreasuryProposed");

      // The money has not moved: only the delay separates the proposal from the move.
      expect(await task.treasury()).to.equal(fx.buyer.address);
      // The window is a protocol parameter, not a deployment accident.
      expect(await task.TREASURY_DELAY()).to.equal(7n * 24n * 60n * 60n);
    });

    it("refuses to execute before the delay, and executes for anyone after it", async () => {
      const fx = await fixture();
      const { task, owner, outsider } = fx;
      const to = outsider.address;
      await task.connect(owner).proposeTreasury(to);

      await expect(task.connect(owner).executeTreasury()).to.be.revertedWithCustomError(
        task,
        "TreasuryNotReady",
      );
      expect(await task.treasury()).to.equal(fx.buyer.address);

      await time.increase(Number(await task.TREASURY_DELAY()) + 1);

      // Anyone may execute: a queued change must not be hostage to a lost owner key.
      await expect(task.connect(outsider).executeTreasury())
        .to.emit(task, "TreasuryChanged")
        .withArgs(fx.buyer.address, to);
      expect(await task.treasury()).to.equal(to);
    });

    it("keeps the queued candidate stable: a live change cannot be swapped", async () => {
      const fx = await fixture();
      const { task, owner, outsider, alice } = fx;
      await task.connect(owner).proposeTreasury(outsider.address);
      await expect(task.connect(owner).proposeTreasury(alice.address)).to.be.revertedWithCustomError(
        task,
        "PendingRotationExists",
      );

      // The candidate that lands is the first one: the refused proposal changed nothing.
      await time.increase(Number(await task.TREASURY_DELAY()) + 1);
      await task.connect(owner).executeTreasury();
      expect(await task.treasury()).to.equal(outsider.address);
    });

    it("lets the owner cancel a queued change, and only the owner", async () => {
      const fx = await fixture();
      const { task, owner, outsider } = fx;
      await task.connect(owner).proposeTreasury(outsider.address);

      await expect(task.connect(outsider).cancelTreasury.staticCall()).to.be.revertedWithCustomError(
        task,
        "NotOwner",
      );

      await expect(task.connect(owner).cancelTreasury())
        .to.emit(task, "TreasuryRotationCancelled")
        .withArgs(outsider.address);
      await expect(task.connect(owner).executeTreasury()).to.be.revertedWithCustomError(
        task,
        "NoPendingTreasury",
      );
      expect(await task.treasury()).to.equal(fx.buyer.address);
    });

    it("refuses a non-owner proposal and the zero address", async () => {
      const fx = await fixture();
      const { task, owner, outsider } = fx;
      // Simulated, not sent: the fhevm plugin replaces a revert arriving with an
      // `address` argument in it with its own assertion error (see the `NotOwner`
      // note in PaymentVault.spec), hiding which check failed. The simulation runs
      // the same `onlyOwner` modifier and address validation.
      await expect(
        task.connect(outsider).proposeTreasury.staticCall(outsider.address),
      ).to.be.revertedWithCustomError(task, "NotOwner");
      await expect(
        task.connect(owner).proposeTreasury.staticCall(ethers.ZeroAddress),
      ).to.be.revertedWithCustomError(task, "ZeroAddress");
      // Neither attempt moved it.
      expect(await task.treasury()).to.equal(fx.buyer.address);
    });
  });

  describe("shape-proof requirement", () => {
    it("is on by default and rejects empty proofs while on", async () => {
      const fx = await fixture();
      const { task, buyer, alice } = fx;
      expect(await task.shapeProofsRequired()).to.equal(true);
      await task.connect(buyer).createTask(1_000_000_000n, params(buyer.address));
      const id = await task.taskCount();
      await expect(
        task.connect(alice).submitContribution(id, bytes32Of(1), bytes32Of(11), "0x", bytes32Of(7), 100),
      ).to.be.revertedWithCustomError(task, "ShapeProofInvalid");
    });

    it("can be tightened by the owner, and only by the owner", async () => {
      const fx = await fixture();
      const { task, owner, outsider } = fx;
      await expect(task.connect(owner).requireShapeProofs())
        .to.emit(task, "ShapeProofsRequiredChanged")
        .withArgs(true);
      expect(await task.shapeProofsRequired()).to.equal(true);
      await expect(
        task.connect(outsider).requireShapeProofs.staticCall(),
      ).to.be.revertedWithCustomError(task, "NotOwner");
    });

    it("cannot be loosened: there is no switch that turns the requirement off", async () => {
      const fx = await fixture();
      const { task } = fx;
      // The weakening direction has no entry point at all, so there is nothing to
      // call, nothing to delay and nothing for a compromised key to race. This is a
      // pin on the ABI: if a "set the requirement to false" entry point comes back,
      // this test fails.
      const artifact = await artifacts.readArtifact("CipherTask");
      const names = artifact.abi
        .filter((f) => f.type === "function")
        .map((f) => f.name);
      expect(names).to.not.include("setShapeProofsRequired");
      expect(names).to.include("requireShapeProofs");
    });

    it("lets a contribution through once the requirement does not hold", async () => {
      const fx = await fixture();
      const { task, buyer, alice } = fx;
      // A deployment that starts without the requirement accepts an empty proof.
      const token = await ethers.deployContract("TestToken");
      const vault = await ethers.deployContract("PaymentVault", [await token.getAddress()]);
      const verifier = await ethers.deployContract("MockStarkVerifier", [48_576]);
      const bls = await ethers.deployContract("MockBLS");
      const gate = await ethers.deployContract("DecryptionGate", [
        await bls.getAddress(),
        bytes32Of("bls-agg"),
        1,
      ]);
      const open = await deployLinked("CipherTask", [
        await token.getAddress(),
        await vault.getAddress(),
        await verifier.getAddress(),
        await gate.getAddress(),
        buyer.address,
        false,
      ]);
      await vault.setTaskManager(await open.getAddress());
      await token.mint(buyer.address, 1_000_000_000n);
      await token.connect(buyer).approve(await vault.getAddress(), ethers.MaxUint256);

      await open.connect(buyer).createTask(1_000_000_000n, params(buyer.address));
      const id = await open.taskCount();
      await open
        .connect(alice)
        .submitContribution(id, bytes32Of(1), bytes32Of(11), "0x", bytes32Of(7), 100);
      expect((await open.contributorsOf(id)).length).to.equal(1);
      expect(await task.shapeProofsRequired()).to.equal(true);
    });
  });
});
