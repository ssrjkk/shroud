import { expect } from "chai";
import { ethers } from "hardhat";

import { CipherTask, DecryptionGate, DisputeLib, MockBLS, MockStarkVerifier, PaymentVault, TestToken } from "../typechain-types";
import { bytes32Of, params } from "./helpers";
import { deployLinked } from "../scripts/libraries";

/**
 * The dispute sortition: who may report a dispute for an epoch.
 *
 * Threat model F-04. The committee is drawn by a weighted lottery - each registered
 * node is eligible with probability `COMMITTEE_SIZE * weight / total` - so a Sybil
 * ring cannot count arbitrary identities toward quorum. The draw needs a seed, and
 * the seed used to be the block's randomness alone. On a chain whose sequencer
 * proposes the blocks, that is a handful of hashes to search until the seed draws
 * the sequencer's own Sybil identities and excludes the honest one: the sequencer
 * picks the committee, for free, and every bond in the design is priced while this
 * lever is not.
 *
 * The seed therefore also commits to the registered node set, which is fixed by the
 * registrations - each of which posts a bond. The sequencer can no longer choose
 * the committee, and a Sybil cannot buy its way in either, because it cannot see
 * the seed before it registers.
 */
describe("dispute sortition", () => {
  it("the epoch's seed commits to the registered node set", async () => {
    const lib: DisputeLib = await deployLinked("DisputeLib");
    const a = await lib.epochSeed(bytes32Of("node-set-a"), 12345n, 1n, 0);
    const b = await lib.epochSeed(bytes32Of("node-set-b"), 12345n, 1n, 0);
    // Same block randomness, same task, same epoch: only the node set differs - and
    // the seed differs, so the sequencer cannot pick the committee by searching.
    expect(a).to.not.equal(b);
  });

  it("the seed still binds the chain's randomness, the task and the epoch", async () => {
    const lib: DisputeLib = await deployLinked("DisputeLib");
    const set = bytes32Of("node-set");
    const base = await lib.epochSeed(set, 12345n, 1n, 0);
    // The randomness still enters, so a Sybil cannot grind its identity against a
    // seed it could otherwise predict.
    expect(await lib.epochSeed(set, 54321n, 1n, 0)).to.not.equal(base);
    // And the epoch and the task do.
    expect(await lib.epochSeed(set, 12345n, 1n, 1)).to.not.equal(base);
    expect(await lib.epochSeed(set, 12345n, 2n, 0)).to.not.equal(base);
    // Deterministic for the same inputs.
    expect(await lib.epochSeed(set, 12345n, 1n, 0)).to.equal(base);
  });

  it("registering a node changes the task's node set commitment", async () => {
    const [owner, buyer, node, committee, treasury] = await ethers.getSigners();
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

    const escrow = 1_000_000_000n;
    await token.mint(buyer.address, escrow);
    await token.connect(buyer).approve(await vault.getAddress(), ethers.MaxUint256);
    await task.connect(buyer).createTask(escrow, params(buyer.address, { minContributors: 1 }));
    const id = await task.taskCount();

    // No node has registered: the set is empty, and the commitment is zero.
    expect(await task.nodeSetHash(id)).to.equal(ethers.ZeroHash);

    const bond = await vault.REGISTRATION_BOND();
    await token.mint(node.address, bond);
    await token.connect(node).approve(await vault.getAddress(), ethers.MaxUint256);
    await task.connect(node).registerNode(id, bytes32Of("node-bls-key"));

    // Now the set commits to the registration.
    expect(await task.nodeSetHash(id)).to.not.equal(ethers.ZeroHash);
    void owner;
    void committee;
  });
});
