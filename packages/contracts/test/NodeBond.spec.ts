import { time } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";

import { CipherTask } from "../typechain-types";
import { DecryptionGate, MockBLS, MockStarkVerifier, PaymentVault, TestToken } from "../typechain-types";
import { bytes32Of, externalUint64, matureRewardWindows, params, proofFor, proofRef } from "./helpers";
import { deployLinked } from "../scripts/libraries";

/**
 * Registration bonds: the Sybil price for node identities (threat model F-04, limitations §2a).
 *
 * A node locks `REGISTRATION_BOND` (vault custody, its own invariant term — never sub-balance
 * money) to register. A dispute quorum slashes the *winner's* bond into the task sub-balance;
 * reporters keep theirs. The bond is released once the task can no longer slash it.
 */
describe("node registration bonds", () => {
  type Fx = Awaited<ReturnType<typeof deployFixture>>;

  async function deployFixture() {
    const [owner, buyer, alice, bob, node, node2, node3, node4, committee, outsider, treasury] =
      await ethers.getSigners();

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
      true,
    ]);
    await vault.setTaskManager(await task.getAddress());
    await gate.setCipherTask(await task.getAddress());
    await gate.initialize(committee.address, [committee.address]);

    const escrow = 1_000_000_000n;
    await token.mint(buyer.address, escrow);
    await token.connect(buyer).approve(await vault.getAddress(), ethers.MaxUint256);

    const bond = await vault.REGISTRATION_BOND();
    for (const n of [node, node2, node3, node4]) {
      await token.mint(n.address, bond);
      await token.connect(n).approve(await vault.getAddress(), ethers.MaxUint256);
    }

    return { token, vault, task, escrow, bond, owner, buyer, alice, bob, node, node2, node3, node4, committee, outsider, treasury };
  }

  /** A sealed 2-contributor task with `nodes` registered under distinct BLS keys. */
  async function sealed(fx: Fx, nodes: Fx["node"][]) {
    const { task, buyer, alice, bob } = fx;
    await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 2, epochs: 2 }));
    const id = await task.taskCount();
    await task.connect(alice).submitContribution(id, bytes32Of(1), bytes32Of(11), proofFor(1), bytes32Of(7), 1_000);
    await task.connect(bob).submitContribution(id, bytes32Of(2), bytes32Of(12), proofFor(2), bytes32Of(8), 1_000);
    await task.connect(buyer).sealTask(id);
    for (const [i, n] of nodes.entries()) await task.connect(n).registerNode(id, bytes32Of(5000 + i));
    return id;
  }

  async function openEpochAs(fx: Fx, id: bigint, cid: string, digest: string) {
    const st = await externalUint64(await fx.task.getAddress(), await fx.buyer.getAddress(), 0n);
    return fx.task.connect(fx.buyer).openEpoch(id, cid, digest, st.handle, st.proof);
  }

  it("pulls the bond into the vault ledger on registration", async () => {
    const fx = await deployFixture();
    const { task, token, vault, buyer, node, bond } = fx;
    await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 1 }));
    const id = await task.taskCount();

    await expect(task.connect(node).registerNode(id, bytes32Of(42)))
      .to.emit(task, "NodeRegistered")
      .withArgs(id, node.address, bytes32Of(42));
    expect(await vault.nodeBond(id, node.address)).to.equal(bond);
    expect(await token.balanceOf(node.address)).to.equal(0n);
    // The bond is custodied, not spent: the invariant counts it as its own term.
    expect(await vault.bondTotal()).to.equal(bond);
    expect(await vault.totalLocked()).to.equal(await vault.accountedLocked());
    expect(await vault.taskBalance(id)).to.equal(fx.escrow);
  });

  it("reverts registration without an approval", async () => {
    const fx = await deployFixture();
    const { task, buyer, outsider, bond } = fx;
    await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 1 }));
    const id = await task.taskCount();
    await expect(task.connect(outsider).registerNode(id, bytes32Of(43))).to.be.revertedWithCustomError(
      task,
      "BondInsufficient"
    ).withArgs(id, outsider.address, bond);
    expect(await task.nodeRegistered(id, outsider.address)).to.equal(false);
  });

  it("rejects a reused BLS key", async () => {
    const fx = await deployFixture();
    const { task, node, node2 } = fx;
    const id = await sealed(fx, [node]);
    await expect(task.connect(node2).registerNode(id, bytes32Of(5000))).to.be.revertedWithCustomError(
      task,
      "BlsKeyAlreadyUsed"
    );
    expect(await task.nodeRegistered(id, node2.address)).to.equal(false);
  });

  it("rejects a zero BLS key", async () => {
    const fx = await deployFixture();
    const { task, node } = fx;
    const id = await sealed(fx, []);
    await expect(task.connect(node).registerNode(id, ethers.ZeroHash)).to.be.revertedWithCustomError(
      task,
      "ZeroBlsKey"
    );
  });

  it("charges the bond exactly once on double registration", async () => {
    const fx = await deployFixture();
    const { task, token, vault, node, bond } = fx;
    const id = await sealed(fx, [node]);
    await expect(task.connect(node).registerNode(id, bytes32Of(5001))).to.be.revertedWithCustomError(
      task,
      "NodeAlreadyRegistered"
    );
    expect(await vault.nodeBond(id, node.address)).to.equal(bond);
    expect(await token.balanceOf(node.address)).to.equal(0n);
  });

  it("locks the bond until the task is terminal, then returns it", async () => {
    const fx = await deployFixture();
    const { task, token, vault, buyer, node, bond } = fx;
    const id = await sealed(fx, [node]);

    await expect(vault.connect(node).releaseBond(id, node.address)).to.be.revertedWithCustomError(
      task,
      "BondNotReleasable"
    );

    await task.connect(buyer).abort(id, "0x656d556e");
    await expect(vault.connect(node).releaseBond(id, node.address))
      .to.emit(vault, "NodeBondWithdrawn")
      .withArgs(id, node.address, bond);
    expect(await token.balanceOf(node.address)).to.equal(bond);
    expect(await vault.nodeBond(id, node.address)).to.equal(0n);
    expect(await vault.totalLocked()).to.equal(await vault.accountedLocked());
  });

  it("releases the bond after full settlement", async () => {
    const fx = await deployFixture();
    const { task, token, vault, buyer, node, bond } = fx;
    await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 1, epochs: 1 }));
    const id = await task.taskCount();
    await task.connect(fx.alice).submitContribution(id, bytes32Of(1), bytes32Of(11), proofFor(1), bytes32Of(7), 1_000);
    await task.connect(buyer).sealTask(id);
    await task.connect(node).registerNode(id, bytes32Of(42));
    await openEpochAs(fx, id, bytes32Of(100), bytes32Of(101));
    await task
      .connect(node)
      .commitEpoch(id, 0, proofRef(1), bytes32Of(301), bytes32Of(401), bytes32Of(501), bytes32Of(999));
    await time.increase(3600 + 600);
    await task.finalizeEpoch(id, 0);
    await matureRewardWindows();
    await task.settle(id);

    await expect(vault.connect(node).releaseBond(id, node.address))
      .to.emit(vault, "NodeBondWithdrawn")
      .withArgs(id, node.address, bond);
    expect(await token.balanceOf(node.address)).to.equal(bond);
  });

  it("slashes the winner bond on quorum reject and spares the reporters", async () => {
    const fx = await deployFixture();
    const { task, token, vault, buyer, node, node2, node3, node4, bond } = fx;
    const id = await sealed(fx, [node, node2, node3, node4]);
    await openEpochAs(fx, id, bytes32Of(100), bytes32Of(101));

    // Four verified commits; the lowest address claims, three others disagree.
    const order = [node, node2, node3, node4].sort((a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1));
    const [claimant, ...challengers] = order;
    await task
      .connect(claimant)
      .commitEpoch(id, 0, proofRef(1), bytes32Of(301), bytes32Of(401), bytes32Of(501), bytes32Of(999));
    const digests = [bytes32Of(2001), bytes32Of(2002), bytes32Of(2003)];
    for (const [i, c] of challengers.entries()) {
      await task
        .connect(c)
        .commitEpoch(id, 0, proofRef(10 + i), bytes32Of(601 + i), bytes32Of(701 + i), bytes32Of(801 + i), digests[i]);
      await task.connect(c).reportDispute(id, 0, digests[i]);
    }

    const tx = await task.finalizeEpoch(id, 0);
    await expect(tx).to.emit(task, "EpochRejected");
    await expect(tx).to.emit(vault, "NodeBondSlashed").withArgs(id, 0, claimant.address, bond);

    // The winner's bond is gone into the sub-balance; reporters keep theirs.
    expect(await vault.nodeBond(id, claimant.address)).to.equal(0n);
    for (const c of challengers) expect(await vault.nodeBond(id, c.address)).to.equal(bond);
    // Bounty 1.5e6 out to reporter channels, slashed bond 1e7 back in: 1e9 - 1.5e6 + 1e7.
    expect(await vault.taskBalance(id)).to.equal(1_008_500_000n);
    expect(await vault.totalLocked()).to.equal(await vault.accountedLocked());

    // Reporters exit whole after terminal: honest disputes are not punished.
    await task.connect(buyer).abort(id, "0x656d556e");
    for (const c of challengers) {
      await vault.connect(c).releaseBond(id, c.address);
      expect(await token.balanceOf(c.address)).to.equal(bond);
    }
  });
});
