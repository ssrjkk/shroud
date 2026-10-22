import { expect } from "chai";
import { ethers } from "hardhat";

import { CipherTask } from "../typechain-types";
import { DecryptionGate, MockBLS, MockStarkVerifier, PaymentVault, FeeOnTransferTokenMock } from "../typechain-types";
import { bytes32Of, params } from "./helpers";
import { deployLinked } from "../scripts/libraries";

/**
 * Fee-on-transfer tokens must fail closed, not be mis-accounted.
 *
 * Threat model F-36: `fundTask` and `takeBond` used to record the *requested* amount while
 * the token delivered less, so a fee-taking escrow token silently under-collateralised the
 * task - the ledger said the task held the budget while the vault held less, and the
 * shortfall surfaced only when a payout could not be made.
 *
 * Both paths now ledger the balance diff that actually arrived, and both refuse to
 * continue when it is short: the escrow at the orchestrator's `EscrowMismatch`, the bond
 * at `BondInsufficient`. These are the tests that prove the refusal - without them the
 * claim "fail closed" was a claim about the code, not about the behaviour.
 */
describe("fee-on-transfer tokens", () => {
  type Fx = Awaited<ReturnType<typeof deployFixture>>;

  async function deployFixture() {
    const [owner, buyer, node, committee, treasury] = await ethers.getSigners();

    // 1% on every transfer.
    const token: FeeOnTransferTokenMock = await ethers.deployContract("FeeOnTransferTokenMock", [100]);
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
      true,
    ]);
    await vault.setTaskManager(await task.getAddress());
    await gate.setCipherTask(await task.getAddress());
    await gate.initialize(committee.address, [committee.address]);

    const escrow = 1_000_000_000n;
    await token.mint(buyer.address, escrow);
    await token.connect(buyer).approve(await vault.getAddress(), ethers.MaxUint256);

    const bond = await vault.REGISTRATION_BOND();
    await token.mint(node.address, bond * 2n);
    await token.connect(node).approve(await vault.getAddress(), ethers.MaxUint256);

    return { token, vault, task, escrow, bond, owner, buyer, node, committee, treasury };
  }

  it("the escrow fails closed when the token takes a cut", async () => {
    const fx = await deployFixture();
    const { task, buyer, escrow } = fx;

    // The task is created with the budget it names, but the vault receives 1% less.
    // The orchestrator compares what arrived with what was asked for and refuses.
    await expect(
      task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 1 }))
    ).to.be.revertedWithCustomError(task, "EscrowMismatch");

    // Nothing was created: the counter did not move, so a retry cannot double-count.
    expect(await task.taskCount()).to.equal(0n);
  });

  it("the registration bond fails closed when the token takes a cut", async () => {
    const fx = await deployFixture();
    const { task, token, vault, buyer, node, bond } = fx;

    // The escrow is checked at creation, so the task has to exist before the cut is
    // turned on - otherwise the creation would fail first and the bond path would
    // never be reached.
    await token.setFeeBps(0);
    await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 1 }));
    const id = await task.taskCount();
    await token.setFeeBps(100);

    // The bond is pulled in full, but 1% of it never arrives. A node that registered
    // anyway would carry a quorum price the contract never received, so the bond is
    // refused rather than recorded.
    await expect(task.connect(node).registerNode(id, bytes32Of(42))).to.be.revertedWithCustomError(
      task,
      "BondInsufficient"
    );
    expect(await task.nodeRegistered(id, node.address)).to.equal(false);
    expect(await vault.nodeBond(id, node.address)).to.equal(0n);
    // The vault's books still balance after the refused pull.
    expect(await vault.totalLocked()).to.equal(await vault.accountedLocked());
    void bond;
  });
});
