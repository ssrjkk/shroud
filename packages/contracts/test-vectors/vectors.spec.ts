import { time } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import type { EventFragment } from "ethers";

import type { CipherTask, NetworkParams, PaymentVault, TestToken } from "../typechain-types";
import { MockBLS, MockStarkVerifier } from "../typechain-types";
import { bytes32Of, externalUint64, params, proofFor, proofRef } from "../test/helpers";
import { deployLinked } from "../scripts/libraries";

/**
 * The byte layouts the Rust node mirrors, asserted against the chain that defines them.
 *
 * `node/src/chain/transcript.rs`, `node/src/chain/slice.rs` and the captured-log table of
 * `node/src/chain/watcher.rs` each pin a constant, and those constants were read off a deployment
 * of *these* contracts. This file is what stops them from rotting: it drives the scenario, reads
 * the value back from the deployed contract, recomputes it from the encoding the Rust side
 * implements, and asserts the three agree. Change a layout in Solidity and this fails in one run
 * of `npm test` — rather than in a node that has already paid gas for an epoch the chain will not
 * accept.
 *
 * The pinned addresses are the deterministic CREATE addresses of the deploy order in
 * `deployFixture` below. Reordering the deployments changes them, and the Rust vectors have to be
 * re-captured together with it; they will not silently disagree, because the transcript digest
 * takes `address(this)` as a public input.
 *
 * This file lives outside `test/` on purpose. Those addresses are a function of the deployer
 * account *and its nonce*, so they only reproduce on a chain whose first transaction is the first
 * deployment — and `hardhat test` runs every spec against one shared chain, in filename order.
 * `npm test` therefore runs the suite and then this file as a separate process; a fresh chain is
 * what makes the pinned numbers meaningful. Re-seeding the chain mid-suite is not an option:
 * `hardhat_reset` also drops the FHEVM runtime the fixtures deploy into, so `createTask` reverts
 * without a reason.
 */

/** `CipherTask._EMPTY_ROOT` and `node::chain::transcript::empty_root`. */
const CT_ROOT_TAG = "SHROUD/CTROOT/v1";
const EMPTY_ROOT = "0x863737be8f430ace1a1b64da126e38a94c776d0ccefa95785ea4eaeb113b9cf3";

/**
 * Three `submitContribution` calls: the leaf's `ciphertextCid`, and `ctRootOf(taskId)` read back
 * from the chain after it. `node::chain::transcript::ct_root_step` reproduces each step from
 * `keccak256(abi.encodePacked(acc, leafIndex, ciphertextCid))`, starting at `EMPTY_ROOT` — the
 * accumulator *is* `Task.ctRoot`, seeded by `createTask`, so leaf 0 folds the tagged empty root
 * rather than `bytes32(0)`.
 */
const CT_STEPS = [
  { leaf: 0, cid: "0x7cb28e2fbd63cc4d4a519f09950cf70541ff7d13878e887d59fb1341ac17890c", root: "0x801459d04349d20b5e2f880112503d0f17b1183937397bdcb66efa502fe4fde8" },
  { leaf: 1, cid: "0x444d61d4497174c690bdb4fd4bbcac1a652b91a47223a97074a78dbd5496f6e3", root: "0xb719daf526966b94fd548fd4de7c9659c119d4b006beaf12759e5c94da10dd14" },
  { leaf: 2, cid: "0x4780e827121b4e535b1661f87ed03f1ea1c3845f7c059087f524423d53238403", root: "0xa3d7329343c8b278393d3e6d990e99e514d3474f8d4f4df834630ecbdf9d0827" },
];

/** `CipherTask.proofTranscript(1, 0, traceDigest)` under the parameters below. */
const TRANSCRIPT_MAGIC = "SHROUD/PoC/v1";
const TRANSCRIPT = {
  epoch: 0,
  traceDigest: "0x01c8a3e3937be1c605ffbdfd93fa4c7b1a68ef7dd87913adf52d6c0739ee7f62",
  weightsDigest: "0xa68765884cb666d6f6f1673b17cd9d3d23bc01d171acdf0f77bcd5c0ae88544f",
  encWeightsCid: "0x3678b6346b5d7438951ee3fd450cfe307d900e56e2fbb316aca2dc85423e8bbd",
  ctRoot: "0xa3d7329343c8b278393d3e6d990e99e514d3474f8d4f4df834630ecbdf9d0827",
  expected: "0x4abdca8df798a87c70c8d71e451d62074a9769cca624cedb289f9d579702d27c",
};

/**
 * The 96-byte ERC-1271 blob `PaymentVault.redeem` accepts for channel 1 of this scenario:
 * `abi.encode(uint256 channelId, uint256 sliceIndex, uint128 amount)` with the epoch reward of
 * `1e9 * 1500bps / 3 epochs = 5e7`. `node::chain::slice::encode` produces these exact bytes.
 */
const SLICE_BLOB =
  "0x0000000000000000000000000000000000000000000000000000000000000001" +
  "0000000000000000000000000000000000000000000000000000000000000000" +
  "0000000000000000000000000000000000000000000000000000000002faf080";
const ERC1271_MAGIC = "0x1626ba7e";
const NOT_MAGIC = "0xffffffff";

/**
 * The shape of every event the node folds: `event signature`, its `topic0`, how many arguments are
 * `indexed` and how many land in `data`. The watcher decodes by position, so a reordered or
 * mis-indexed argument is a wrong value rather than a failed call — which is why this is checked
 * against the interface the compiler emitted, and why the topic0 words are the ones the node
 * subscribes to.
 */
const PINNED_SHAPE: [string, number, number, string][] = [
  ["ContributionSubmitted(uint256,address,uint32,bytes32,uint32)", 3, 2, "0xc37fa11865d20db8c2f9f36ef55d1f99c41a0ee1f98fd66fcad5c3e82cae8ef3"],
  ["DisputeReported(uint256,uint32,address,bytes32)", 3, 1, "0x56c6da7aeff81fba1958ad3eddabcec10d01fa5edbe133afd962121e89b9acf9"],
  ["EpochCommitted(uint256,uint32,address,bytes32)", 3, 1, "0xbe1c0401080fba30020b1609c22d6c3de654f750279eb2c12daac731b9c5f668"],
  ["EpochOpened(uint256,uint32,bytes32,bytes32)", 2, 2, "0x7e3cb4c8395e586b6b675ae99ac10bb09551b19d95aeae90a896aead64caab2b"],
  ["EpochRejected(uint256,uint32,uint256)", 2, 1, "0x8ef810f8e72a2aced85333b1f2a81efc7ee1e964b7b6e12eac2e49eb288900cc"],
  ["EpochSettled(uint256,uint32,address,uint128)", 3, 1, "0x9c7e9f71dff59cfde2bb5e38de2a9baecc65bbaaa779209751a12c1c28355610"],
  ["EpochVerified(uint256,uint32,address,bool)", 3, 1, "0xde1a096b42a741da9abd8e171b97e821d67b222feddb8d4e6efdfd642df44091"],
  ["NodeRewardChannelOpened(uint256,uint32,address,uint256,uint128,uint64,uint128)", 3, 4, "0x2226c20f431901d82fc48febfeab68c3b8b46423aae620f73d8b0b3c2b407053"],
  ["TaskAborted(uint256,bytes4)", 1, 1, "0xe445d9d031ef936fdcc51bb3f78ad934dc35d6a085ab35864de6329a6e9f65c8"],
  ["TaskSealed(uint256,bytes32,uint32,uint32)", 1, 3, "0x99bf7cc8880bbbcd95ba1c122c314cb230e1607837b7aed2ea1957185b28c41b"],
  ["TaskSettled(uint256,uint128,uint128,uint128)", 1, 3, "0x64b9379e52477e67cef49489615cca11e9f6343f94879ddc0c0f50ba19a4be65"],
  ["ChannelOpened(uint256,uint256,address,address,uint128,uint64)", 3, 3, "0x70d39e0205cc39a51528f1c53832da8ccc0820ec76bec1d321bfa6c864c829cf"],
  ["SliceRedeemed(uint256,address,uint128,uint128,uint256)", 2, 3, "0x107845e530b551b1ff303785868633c9e6e01096d45d483f669269e4b5995a69"],
  ["ChannelReclaimed(uint256,address,uint128)", 2, 1, "0x97c9fd82973dc049001bdce58b00498bb0ed44ee59212ca45dbe5f1e8201ba84"],
];

/** The vault's three events; every other pinned event comes from `CipherTask`. */
const VAULT_EVENTS = new Set(["ChannelOpened", "SliceRedeemed", "ChannelReclaimed"]);

/** Logs this scenario emits byte-for-byte as the rows the node decodes in its capture table. */
const PINNED_LOGS = [
  {
    name: "ContributionSubmitted",
    topic0: "0xc37fa11865d20db8c2f9f36ef55d1f99c41a0ee1f98fd66fcad5c3e82cae8ef3",
    address: "0x8a791620dd6260079bf849dc5567adc3f2fdc318",
    topics: [
      "0xc37fa11865d20db8c2f9f36ef55d1f99c41a0ee1f98fd66fcad5c3e82cae8ef3",
      "0x0000000000000000000000000000000000000000000000000000000000000001",
      "0x0000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
    ],
    data:
      "0x7cb28e2fbd63cc4d4a519f09950cf70541ff7d13878e887d59fb1341ac17890c" +
      "00000000000000000000000000000000000000000000000000000000000003e8",
  },
  {
    name: "EpochCommitted",
    topic0: "0xbe1c0401080fba30020b1609c22d6c3de654f750279eb2c12daac731b9c5f668",
    address: "0x8a791620dd6260079bf849dc5567adc3f2fdc318",
    topics: [
      "0xbe1c0401080fba30020b1609c22d6c3de654f750279eb2c12daac731b9c5f668",
      "0x0000000000000000000000000000000000000000000000000000000000000001",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000009965507d1a55bcc2695c58ba16fb37d819b0a4dc",
    ],
    data: "0x01c8a3e3937be1c605ffbdfd93fa4c7b1a68ef7dd87913adf52d6c0739ee7f62",
  },
  {
    name: "EpochVerified",
    topic0: "0xde1a096b42a741da9abd8e171b97e821d67b222feddb8d4e6efdfd642df44091",
    address: "0x8a791620dd6260079bf849dc5567adc3f2fdc318",
    topics: [
      "0xde1a096b42a741da9abd8e171b97e821d67b222feddb8d4e6efdfd642df44091",
      "0x0000000000000000000000000000000000000000000000000000000000000001",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000009965507d1a55bcc2695c58ba16fb37d819b0a4dc",
    ],
    data: "0x0000000000000000000000000000000000000000000000000000000000000001",
  },
  {
    // The seal is the event whose first data word is the `ctRoot` the node re-derives, so this row
    // is what ties the accumulation chain to the log the watcher folds.
    name: "TaskSealed",
    topic0: "0x99bf7cc8880bbbcd95ba1c122c314cb230e1607837b7aed2ea1957185b28c41b",
    address: "0x8a791620dd6260079bf849dc5567adc3f2fdc318",
    topics: [
      "0x99bf7cc8880bbbcd95ba1c122c314cb230e1607837b7aed2ea1957185b28c41b",
      "0x0000000000000000000000000000000000000000000000000000000000000001",
    ],
    data:
      "0xa3d7329343c8b278393d3e6d990e99e514d3474f8d4f4df834630ecbdf9d0827" +
      "0000000000000000000000000000000000000000000000000000000000000003" +
      "0000000000000000000000000000000000000000000000000000000000000003",
  },
  {
    name: "EpochOpened",
    topic0: "0x7e3cb4c8395e586b6b675ae99ac10bb09551b19d95aeae90a896aead64caab2b",
    address: "0x8a791620dd6260079bf849dc5567adc3f2fdc318",
    topics: [
      "0x7e3cb4c8395e586b6b675ae99ac10bb09551b19d95aeae90a896aead64caab2b",
      "0x0000000000000000000000000000000000000000000000000000000000000001",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
    ],
    data:
      "0x3678b6346b5d7438951ee3fd450cfe307d900e56e2fbb316aca2dc85423e8bbd" +
      "a68765884cb666d6f6f1673b17cd9d3d23bc01d171acdf0f77bcd5c0ae88544f",
  },
];

describe("chain vectors", () => {
  async function deployFixture() {
    const [owner, buyer, alice, bob, carol, node, committee, treasury] = await ethers.getSigners();

    const token: TestToken = await ethers.deployContract("TestToken");
    const vault: PaymentVault = await ethers.deployContract("PaymentVault", [await token.getAddress()]);
    const verifier: MockStarkVerifier = await ethers.deployContract("MockStarkVerifier", [48_576]);
    const bls: MockBLS = await ethers.deployContract("MockBLS");
    const gate = await ethers.deployContract("DecryptionGate", [await bls.getAddress(), bytes32Of("bls-agg"), 1]);

    const task: CipherTask = await deployLinked("CipherTask", [
      await token.getAddress(),
      await vault.getAddress(),
      await verifier.getAddress(),
      await gate.getAddress(),
      treasury.address,
      true
    ]);

    await vault.setTaskManager(await task.getAddress());
    await gate.setCipherTask(await task.getAddress());
    await gate.initialize(committee.address, [committee.address]);

    const net: NetworkParams = await ethers.deployContract("NetworkParams", [owner.address]);
    await net.initialize({
      chainId: 0,
      keyVersion: 1,
      fhePublicKeyHash: bytes32Of("s_pub-v1"),
      committeeAggregateKey: bytes32Of("bls-agg"),
      committeeThreshold: 1,
      committeeSize: 7,
      maxProofBytes: 48_576,
      maxCiphertextBytes: 1 << 20,
      maxFeatures: 512,
      activatedAt: 0,
      active: true
    });

    const escrow = 1_000_000_000n;
    await token.mint(buyer.address, escrow);
    await token.connect(buyer).approve(await vault.getAddress(), ethers.MaxUint256);
    // Registration pulls a bond from the node via the vault (no new deployments, so the pinned
    // CREATE addresses below are unaffected).
    await token.mint(node.address, await vault.REGISTRATION_BOND());
    await token.connect(node).approve(await vault.getAddress(), ethers.MaxUint256);

    return { token, vault, task, net, escrow, owner, buyer, alice, bob, carol, node, committee };
  }

  /**
   * Every log written by the scenario, keyed by `topic0`. Scoped to the task address and to the
   * block the scenario started at: `fromBlock: 0` would also collect the logs of every other spec
   * file in the run, and a stray match is indistinguishable from a layout that changed.
   */
  async function captured(
    provider: typeof ethers.provider,
    address: string,
    fromBlock: number
  ): Promise<Map<string, { address: string; topics: string[]; data: string }[]>> {
    const byTopic = new Map<string, { address: string; topics: string[]; data: string }[]>();
    const logs = await provider.getLogs({ address, fromBlock, toBlock: await provider.getBlockNumber() });
    for (const log of logs) {
      const key = log.topics[0].toLowerCase();
      const row = {
        address: log.address.toLowerCase(),
        topics: log.topics.map((t) => t.toLowerCase()),
        data: log.data.toLowerCase(),
      };
      byTopic.set(key, [...(byTopic.get(key) ?? []), row]);
    }
    return byTopic;
  }

  it("drives the money path the vectors are read from", async () => {
    const fx = await deployFixture();
    const { task, vault, buyer, alice, bob, carol, node } = fx;
    const chainId = (await ethers.provider.getNetwork()).chainId;

    expect(chainId).to.equal(31_337);
    expect(await task.getAddress()).to.equal("0x8A791620dd6260079BF849Dc5567aDC3F2FdC318");
    expect(await vault.getAddress()).to.equal("0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512");

    // --- ctRoot ------------------------------------------------------------------------
    expect(ethers.keccak256(ethers.toUtf8Bytes(CT_ROOT_TAG))).to.equal(EMPTY_ROOT);

    const startBlock = await ethers.provider.getBlockNumber();
    await task.connect(buyer).createTask(fx.escrow, params(buyer.address, { minContributors: 2 }));
    const id = await task.taskCount();
    expect(id).to.equal(1n);
    expect(await task.ctRootOf(id)).to.equal(EMPTY_ROOT);

    const cids = CT_STEPS.map((s) => s.cid);
    const signers = [alice, bob, carol];
    let acc = EMPTY_ROOT;
    for (let i = 0; i < signers.length; i++) {
      await task.connect(signers[i]).submitContribution(id, cids[i], cids[i], proofFor(i + 1), bytes32Of(100 + i), 1_000);
      // `CipherTask._appendLeaf` packs 32 + 4 + 32 bytes; `leafIndex` keeps its own 4 bytes.
      acc = ethers.keccak256(ethers.solidityPacked(["bytes32", "uint32", "bytes32"], [acc, CT_STEPS[i].leaf, CT_STEPS[i].cid]));
      expect(acc).to.equal(CT_STEPS[i].root, `leaf ${i} root`);
      expect(await task.ctRootOf(id)).to.equal(CT_STEPS[i].root, `chain root after leaf ${i}`);
    }

    await task.connect(buyer).sealTask(id);
    expect(await task.ctRootOf(id)).to.equal(CT_STEPS[2].root, "sealing must not move the root");

    // --- proofTranscript ---------------------------------------------------------------
    await task.connect(node).registerNode(id, bytes32Of(42));
    const st = await externalUint64(await task.getAddress(), buyer.address, 0n);
    await task.connect(buyer).openEpoch(id, TRANSCRIPT.encWeightsCid, TRANSCRIPT.weightsDigest, st.handle, st.proof);

    const live = await task.tasks(id);
    expect(live.ctRoot).to.equal(TRANSCRIPT.ctRoot);

    const onChain = await task.proofTranscript(id, TRANSCRIPT.epoch, TRANSCRIPT.traceDigest);
    expect(onChain).to.equal(TRANSCRIPT.expected);
    // The same eight head words `node::chain::transcript::proof_transcript` writes by hand.
    const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
      ["string", "uint256", "address", "uint256", "uint32", "bytes32", "bytes32", "bytes32"],
      [TRANSCRIPT_MAGIC, chainId, await task.getAddress(), id, TRANSCRIPT.epoch, TRANSCRIPT.ctRoot, TRANSCRIPT.weightsDigest, TRANSCRIPT.traceDigest]
    );
    expect(ethers.keccak256(encoded)).to.equal(TRANSCRIPT.expected);

    // --- commit, settle, redeem --------------------------------------------------------
    await task
      .connect(node)
      .commitEpoch(id, TRANSCRIPT.epoch, proofRef(0), bytes32Of(300), bytes32Of(400), bytes32Of(500), TRANSCRIPT.traceDigest);
    await time.increase(3600 + 600 + 1);
    await task.finalizeEpoch(id, TRANSCRIPT.epoch);

    const channelId = await task.epochChannel(id, TRANSCRIPT.epoch);
    const ch = await vault.channelInfo(channelId);
    expect(channelId).to.equal(1n);
    expect(ch.streamer).to.equal(await task.getAddress(), "an orchestrator-streamed channel is what the 96-byte blob signs for");
    expect(ch.maxCumulative).to.equal(50_000_000n);

    const blob = ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256", "uint128"], [channelId, 0n, ch.maxCumulative]);
    expect(blob).to.equal(SLICE_BLOB);

    const digest = await vault.redeemDigest(channelId, ch.streamer, ch.node, ch.maxCumulative, ch.unlockAt, ethers.MaxUint256);
    expect(await task.isValidSignature(digest, blob)).to.equal(ERC1271_MAGIC);

    // Only `sliceIndex == 0` is ever authorised, so a second slice has nothing to be checked
    // against — which is why `node::chain::slice` documents a channel as collected in one redeem.
    const second = ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256", "uint128"], [channelId, 1n, ch.maxCumulative]);
    expect(await task.isValidSignature(digest, second)).to.equal(NOT_MAGIC);
    // And the deadline is not carried by the blob: `_decodeSliceFull` fixes it at `type(uint256).max`,
    // so the same bytes cannot authorise a digest built on any other deadline.
    const otherDeadline = await vault.redeemDigest(channelId, ch.streamer, ch.node, ch.maxCumulative, ch.unlockAt, ch.unlockAt + 1n);
    expect(await task.isValidSignature(otherDeadline, blob)).to.equal(NOT_MAGIC);

    await vault.connect(node).redeem(channelId, 0n, ch.maxCumulative, ethers.MaxUint256, blob);
    expect((await vault.channelInfo(channelId)).withdrawn).to.equal(50_000_000n);

    // --- the captured logs themselves --------------------------------------------------
    const logs = await captured(ethers.provider, await task.getAddress(), startBlock);
    for (const pinned of PINNED_LOGS) {
      const hits = logs.get(pinned.topic0) ?? [];
      expect(hits.length, `${pinned.name} was not emitted`).to.be.greaterThan(0);
      // Shaped exactly like a captured row: chai's `deep.include` compares array elements by
      // full equality, so an extra key here would make a correct log look like a changed one.
      const want = { address: pinned.address, topics: pinned.topics, data: pinned.data };
      expect(hits, `${pinned.name} log differs from the node's capture table`).to.deep.include(want);
    }
  });

  it("pins the event layout the node decodes by position", async () => {
    const fx = await deployFixture();
    const { task, vault } = fx;

    for (const [signature, indexed, words, topic0] of PINNED_SHAPE) {
      const name = signature.slice(0, signature.indexOf("("));
      const iface = VAULT_EVENTS.has(name) ? vault.interface : task.interface;
      // `getEvent` is overloaded per emitted event by the TypeChain bindings, so a `string`
      // would have to be a literal union. `topic0` is asserted against `ethers.id(signature)`
      // a line below, so the cast only widens the lookup key, never the checked facts.
      const fragment = (iface.getEvent as (name: string) => EventFragment)(name);
      expect(ethers.id(signature), `topic0 of ${name}`).to.equal(topic0);
      expect(fragment.inputs.filter((i) => i.indexed).length, `indexed arguments of ${name}`).to.equal(indexed);
      expect(fragment.inputs.filter((i) => !i.indexed).length, `data words of ${name}`).to.equal(words);
    }
  });
});
