import { expect } from "chai";
import { ethers } from "hardhat";

import { deployLinked } from "../scripts/libraries";
import { bytes32Of, params } from "./helpers";

/**
 * Owner-gated switches on the orchestrator.
 *
 * `setTreasury` redirects every future fee flow and `setShapeProofsRequired` changes
 * what counts as a valid contribution, yet neither had a single test: an access-control
 * regression on either would be silent until real value moved. Each switch is pinned
 * here for who may flip it, what it rejects, and — for the proof flag — what changes
 * on the contribution path.
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

  describe("setTreasury", () => {
    it("moves the treasury with an event, and only the owner moves it", async () => {
      const fx = await fixture();
      const { task, owner, outsider } = fx;
      const to = outsider.address;
      await expect(task.connect(owner).setTreasury(to))
        .to.emit(task, "TreasuryChanged")
        .withArgs(fx.buyer.address, to);
      expect(await task.treasury()).to.equal(to);
    });

    it("refuses a non-owner and the zero address", async () => {
      const fx = await fixture();
      const { task, owner, outsider } = fx;
      // Simulated, not sent: the fhevm plugin replaces a revert arriving with an
      // `address` argument in it with its own assertion error (see the `NotOwner`
      // note in PaymentVault.spec), hiding which check failed. The simulation runs
      // the same `onlyOwner` modifier and address validation.
      await expect(
        task.connect(outsider).setTreasury.staticCall(outsider.address)
      ).to.be.revertedWithCustomError(task, "NotOwner");
      await expect(
        task.connect(owner).setTreasury.staticCall(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(task, "ZeroAddress");
      // Neither attempt moved it.
      expect(await task.treasury()).to.equal(fx.buyer.address);
    });
  });

  describe("setShapeProofsRequired", () => {
    it("is on by default and rejects empty proofs while on", async () => {
      const fx = await fixture();
      const { task, buyer, alice } = fx;
      expect(await task.shapeProofsRequired()).to.equal(true);
      await task.connect(buyer).createTask(1_000_000_000n, params(buyer.address));
      const id = await task.taskCount();
      await expect(
        task.connect(alice).submitContribution(id, bytes32Of(1), bytes32Of(11), "0x", bytes32Of(7), 100)
      ).to.be.revertedWithCustomError(task, "ShapeProofInvalid");
    });

    it("lets the owner switch it off, and only the owner", async () => {
      const fx = await fixture();
      const { task, owner, buyer, alice, outsider } = fx;
      await expect(task.connect(owner).setShapeProofsRequired(false))
        .to.emit(task, "ShapeProofsRequiredChanged")
        .withArgs(false);
      expect(await task.shapeProofsRequired()).to.equal(false);
      await expect(
        task.connect(outsider).setShapeProofsRequired(true)
      ).to.be.revertedWithCustomError(task, "NotOwner");

      // With the flag off, the same empty proof the previous test refused now lands.
      await task.connect(buyer).createTask(1_000_000_000n, params(buyer.address));
      const id = await task.taskCount();
      await task.connect(alice).submitContribution(id, bytes32Of(1), bytes32Of(11), "0x", bytes32Of(7), 100);
      expect((await task.contributorsOf(id)).length).to.equal(1);
    });
  });
});
