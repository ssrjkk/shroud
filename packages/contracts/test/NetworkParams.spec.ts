import { time } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";

import { NetworkParams } from "../typechain-types";
import type { NetworkParams as NetworkParamsNamespace } from "../typechain-types";
import { bytes32Of } from "./helpers";

/** The generated struct type; typechain requires exactly this shape at the call sites. */
type ParamsStruct = NetworkParamsNamespace.ParamsStruct;

/**
 * `NetworkParams` rotation.
 *
 * The rotation path carries the FHE public-key pin, so it is the one place where a mistake does
 * not revert but silently changes what every client in the network is willing to accept. It is also
 * the least tested contract in the repo: until this file the only coverage was `initialize`.
 *
 * The central property is that **the struct which was validated is the struct which is installed**.
 * `proposeRotation` used to validate its `candidate` argument and then discard it, keeping only a
 * caller-supplied `expectedHash`; the struct reaching `current` was whatever hashed to that value
 * and had never been checked at all.
 */
describe("NetworkParams rotation", () => {
  /** Timelock as seconds for `time.increase`, and as a `uint64` for the contract. */
  const TIMELOCK = 7 * 86_400;
  const TIMELOCK_U64 = BigInt(TIMELOCK);

  function candidate(overrides: Partial<ParamsStruct> = {}): ParamsStruct {
    return {
      chainId: 0,
      keyVersion: 2,
      fhePublicKeyHash: bytes32Of("s_pub-v2"),
      committeeAggregateKey: bytes32Of("bls-v2"),
      committeeThreshold: 3,
      committeeSize: 7,
      maxProofBytes: 48_576,
      maxCiphertextBytes: 1 << 20,
      maxFeatures: 512,
      activatedAt: 0,
      active: true,
      ...overrides,
    } as ParamsStruct;
  }

  /** Substitute the real chainId, which is what the contract hashes over. */
  async function withChainId(c: ParamsStruct): Promise<ParamsStruct> {
    const chainId = (await ethers.provider.getNetwork()).chainId;
    return { ...c, chainId };
  }

  /** The hash `proposeRotation` requires: `keccak256(abi.encode(candidate, chainId, approver))`. */
  async function hashOf(net: NetworkParams, c: ParamsStruct): Promise<string> {
    // The tuple needs named components: `abi.encode` over a struct hashes its fields positionally,
    // and ethers refuses an object against the bare `bytes32` placeholders in a type string.
    const struct =
      "tuple(uint64 chainId,uint64 keyVersion,bytes32 fhePublicKeyHash,bytes32 committeeAggregateKey," +
      "uint16 committeeThreshold,uint16 committeeSize,uint32 maxProofBytes,uint32 maxCiphertextBytes," +
      "uint32 maxFeatures,uint64 activatedAt,bool active)";
    return ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        [struct, "uint256", "address"],
        [c, (await ethers.provider.getNetwork()).chainId, await net.approver()]
      )
    );
  }

  async function deploy() {
    const [owner, approver, outsider] = await ethers.getSigners();
    const net: NetworkParams = await ethers.deployContract("NetworkParams", [approver.address]);
    await net.initialize(
      await withChainId(candidate({ keyVersion: 1, fhePublicKeyHash: bytes32Of("s_pub-v1") }))
    );
    return { net, owner, approver, outsider };
  }

  /** Propose -> approve -> wait out the timelock, computing the expected hash correctly. */
  async function queue(net: NetworkParams, owner: any, approver: any, c: ParamsStruct) {
    const cand = await withChainId(c);
    await net.connect(owner).proposeRotation(cand, await hashOf(net, cand), TIMELOCK_U64);
    await net.connect(approver).approveRotation(cand);
    return cand;
  }

  it("installs a valid rotation after the timelock", async () => {
    const { net, owner, approver } = await deploy();
    const cand = await queue(net, owner, approver, candidate());
    await time.increase(TIMELOCK);
    await expect(net.executeRotation(cand)).to.emit(net, "RotationExecuted");

    const cur = await net.current();
    expect(cur.keyVersion).to.equal(2n);
    expect(cur.fhePublicKeyHash).to.equal(bytes32Of("s_pub-v2"));
    expect(cur.committeeThreshold).to.equal(3n);
    // The pin really moved, which is the entire point of the rotation.
    expect(await net.isCurrentKey(bytes32Of("s_pub-v1"))).to.equal(false);
    expect(await net.isCurrentKey(bytes32Of("s_pub-v2"))).to.equal(true);
  });

  it("refuses to queue a hash that does not describe the proposed candidate", async () => {
    // The bug this guards: `expectedHash` used to be taken on trust, so an owner could validate a
    // perfectly good candidate in the same transaction that queues a *different* struct for the
    // approver to sign — one that never passed any validation at all.
    const { net, owner } = await deploy();
    const good = await withChainId(candidate());
    const bad = await withChainId(candidate({ committeeThreshold: 0 }));

    // Proposing the *good* candidate while supplying the hash of the *bad* one must fail.
    await expect(net.connect(owner).proposeRotation(good, await hashOf(net, bad), TIMELOCK_U64))
      .to.be.revertedWithCustomError(net, "HashMismatch");
  });

  it("refuses to queue parameters that are invalid in their own right", async () => {
    // Defence in depth: execute re-validates, so even a weakened proposal path cannot install a
    // parameter set that clients would pin against.
    const { net, owner } = await deploy();
    for (const bad of [
      candidate({ committeeThreshold: 0 }),
      candidate({ committeeSize: 1, committeeThreshold: 1 }),
      candidate({ maxProofBytes: 0 }),
      candidate({ maxFeatures: 0 }),
      candidate({ keyVersion: 5 }),
      candidate({ fhePublicKeyHash: bytes32Of("s_pub-v1") }),
    ]) {
      const cand = await withChainId(bad);
      await expect(
        net.connect(owner).proposeRotation(cand, await hashOf(net, cand), TIMELOCK_U64)
      ).to.be.revertedWithCustomError(net, "InvalidParams");
    }
  });

  it("will not execute before the timelock, and executes exactly once", async () => {
    const { net, owner, approver } = await deploy();
    const cand = await queue(net, owner, approver, candidate());

    await expect(net.executeRotation(cand)).to.be.revertedWithCustomError(net, "TooEarly");
    await time.increase(TIMELOCK);
    await expect(net.executeRotation(cand)).to.emit(net, "RotationExecuted");
    // A second attempt finds nothing pending.
    await expect(net.executeRotation(cand)).to.be.revertedWithCustomError(net, "NoPendingRotation");
  });

  it("lets the owner cancel, and a cancelled rotation cannot execute", async () => {
    const { net, owner, approver } = await deploy();
    const cand = await queue(net, owner, approver, candidate());
    await net.connect(owner).cancelRotation();
    await time.increase(TIMELOCK);
    await expect(net.executeRotation(cand)).to.be.revertedWithCustomError(net, "NoPendingRotation");
    // The pin did not move.
    expect(await net.isCurrentKey(bytes32Of("s_pub-v1"))).to.equal(true);
  });

  it("restricts proposal and approval to their roles", async () => {
    const { net, owner, approver, outsider } = await deploy();
    const cand = await withChainId(candidate());
    const h = await hashOf(net, cand);
    await expect(net.connect(outsider).proposeRotation(cand, h, TIMELOCK_U64)).to.be.revertedWithCustomError(
      net,
      "NotOwner"
    );
    await net.connect(owner).proposeRotation(cand, h, TIMELOCK_U64);
    await expect(net.connect(outsider).approveRotation(cand)).to.be.revertedWithCustomError(net, "NotApprover");
    // The owner is not implicitly the approver; the two roles are separate.
    await expect(net.connect(owner).approveRotation(cand)).to.be.revertedWithCustomError(net, "NotApprover");
    void approver;
  });

  it("rejects a short timelock", async () => {
    const { net, owner } = await deploy();
    const cand = await withChainId(candidate());
    await expect(net.connect(owner).proposeRotation(cand, await hashOf(net, cand), 86_400n))
      .to.be.revertedWithCustomError(net, "InvalidParams")
      .withArgs("timelock too short");
  });

  it("does not allow a second rotation to be queued over a live one", async () => {
    const { net, owner } = await deploy();
    const a = await withChainId(candidate());
    await net.connect(owner).proposeRotation(a, await hashOf(net, a), TIMELOCK_U64);
    const b = await withChainId(candidate({ fhePublicKeyHash: bytes32Of("s_pub-v3") }));
    await expect(net.connect(owner).proposeRotation(b, await hashOf(net, b), TIMELOCK_U64))
      .to.be.revertedWithCustomError(net, "NoPendingRotation");
  });
  it("applies the rotation rules at genesis too", async () => {
    // `initialize` used to run a shorter list than `_validateCandidate`, so the very first parameter
    // set of the network could pin `committeeAggregateKey` to zero or `maxCiphertextBytes` to zero:
    // values a rotation is refused for. Every client pins whatever genesis installs.
    const [owner] = await ethers.getSigners();
    const net: NetworkParams = await ethers.deployContract("NetworkParams", [owner.address]);

    for (const [label, bad] of [
      ["committeeAggregateKey", candidate({ keyVersion: 1, committeeAggregateKey: ethers.ZeroHash })],
      ["maxCiphertextBytes", candidate({ keyVersion: 1, maxCiphertextBytes: 0 })],
      ["fhePublicKeyHash", candidate({ keyVersion: 1, fhePublicKeyHash: ethers.ZeroHash })],
      ["maxProofBytes", candidate({ keyVersion: 1, maxProofBytes: 512 })],
      ["threshold above size", candidate({ keyVersion: 1, committeeThreshold: 8, committeeSize: 7 })],
      ["committeeSize", candidate({ keyVersion: 1, committeeSize: 2, committeeThreshold: 1 })],
      ["keyVersion must start at 1", candidate({ keyVersion: 2 })]
    ] as [string, ParamsStruct][]) {
      await expect(net.initialize(await withChainId(bad)), label).to.be.revertedWithCustomError(net, "InvalidParams");
    }

    // Nothing partial was installed by the rejected attempts.
    expect((await net.current()).active).to.equal(false);

    await expect(net.initialize(await withChainId(candidate({ keyVersion: 1, fhePublicKeyHash: bytes32Of("s_pub-v1") })))).to.emit(net, "Initialized");
    expect(await net.isCurrentKey(bytes32Of("s_pub-v1"))).to.equal(true);

    // Genesis is a one-shot: re-initializing would replace the pin every client already trusts.
    await expect(net.initialize(await withChainId(candidate()))).to.be.revertedWithCustomError(net, "InvalidParams");
  });

  it("voids an unapproved rotation when the approver changes, and keeps an approved one", async () => {
    // `approveRotation` binds the stored hash to the approver that signed it, so replacing the
    // approver has two different consequences depending on whether anyone had approved yet. It used
    // to leave a proposal queued against an approver that no longer holds the role, which then
    // reverted forever in `executeRotation`: one owner call could wedge the rotation path.
    const { net, owner, approver, outsider } = await deploy();

    // (a) Proposed, never approved: changing the approver voids it.
    const unapproved = await withChainId(candidate({ fhePublicKeyHash: bytes32Of("s_pub-v2") }));
    await net.connect(owner).proposeRotation(unapproved, await hashOf(net, unapproved), TIMELOCK_U64);
    await expect(net.connect(owner).setApprover(outsider.address)).to.emit(net, "RotationCancelledEvent");
    await time.increase(TIMELOCK);
    await expect(net.executeRotation(unapproved)).to.be.revertedWithCustomError(net, "NoPendingRotation");
    expect((await net.current()).fhePublicKeyHash).to.equal(bytes32Of("s_pub-v1"));

    // (b) Approved by the old approver: the rotation is owed, and changing the key afterwards cannot
    // un-sign a decision the approver already made.
    await net.connect(owner).setApprover(approver.address);
    const approved = await withChainId(candidate({ fhePublicKeyHash: bytes32Of("s_pub-v3") }));
    await net.connect(owner).proposeRotation(approved, await hashOf(net, approved), TIMELOCK_U64);
    await net.connect(approver).approveRotation(approved);
    await net.connect(owner).setApprover(outsider.address);
    await time.increase(TIMELOCK);
    await expect(net.executeRotation(approved)).to.emit(net, "RotationExecuted");
    expect(await net.isCurrentKey(bytes32Of("s_pub-v3"))).to.equal(true);
  });
});
