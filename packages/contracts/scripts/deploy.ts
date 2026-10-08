/**
 * Deploy the Shroud devnet contracts and write their addresses to
 * `infra/devnet/addresses.json` so the sequencer, SDK and Rust nodes can find them.
 *
 * Run against the hardhat network:
 *   npx hardhat run scripts/deploy.ts
 *
 * The devnet uses the in-process FHE mock coprocessor (the `@fhevm/hardhat-plugin` devnet), so
 * no external KMS is required. In production the same bytecode runs against the Zama coprocessor
 * with a KMS back end.
 */
import { ethers, network } from "hardhat";
import { writeFileSync, mkdirSync, readFileSync } from "fs";
import { join } from "path";

const OUT = join(__dirname, "../../../infra/devnet/addresses.json");

function h(s: string): string {
  return ethers.id(`Shroud/devnet/${s}`);
}

/**
 * `ZamaConfig._getLocalConfig().CoprocessorAddress` for chainId 31337, inlined because a
 * `.sol` import is not loadable from a TypeScript script. Duplicated from
 * `node_modules/@fhevm/solidity/config/ZamaConfig.sol`; if that constant moves, this must too.
 */
const LOCAL_COPROCESSOR_ADDRESS = "0xe3a9105a3a932253A70F126eb1E3b589C643dD24";

/**
 * Fail early, and legibly, if the FHE mock coprocessor is not present.
 *
 * `@fhevm/hardhat-plugin@0.4.2` installs the mocks only through a Hardhat *subtask*
 * (`fhevm:install-solidity`), which Hardhat refuses to run from the CLI (HH312) and `hre.run`
 * cannot resolve. It is also restricted to the in-process network: running against a standalone
 * `hardhat node` fails with "Provider type mismatch". `hardhat run` on the in-process network does
 * not install the mocks either, so `CipherTask`'s constructor reverts inside `FHE.asEuint32` with
 * no reason string, because the Coprocessor address `ZamaConfig` points at has no code.
 *
 * This check turns that opaque revert into an actionable message. It does *not* install anything:
 * the installer is not reachable from a script without depending on plugin internals that change
 * between releases, which is a worse trade than a clear error.
 *
 * Consequence: the contracts are fully exercised by `hardhat test` (which does install the
 * mocks), but `docker compose up devnet` cannot deploy them with the pinned plugin version. See
 * docs/05.
 */
async function assertFheMocksPresent(): Promise<void> {
  const coprocessor = LOCAL_COPROCESSOR_ADDRESS;
  const code = await ethers.provider.getCode(coprocessor);
  if (code === "0x") {
    throw new Error(
      `the FHE mock coprocessor is not installed at ${coprocessor} (chainId ${network.config.chainId}).\n` +
        `  @fhevm/hardhat-plugin@${pluginVersion()} only installs it via the 'fhevm:install-solidity' subtask,\n` +
        `  which Hardhat will not run from the CLI and which refuses any network but 'hardhat'.\n` +
        `  Workarounds: run the contracts through 'npx hardhat test' (the mock is installed there),\n` +
        `  or change the @fhevm/hardhat-plugin version before deploying to a standalone node.`
    );
  }
}

function pluginVersion(): string {
  try {
    // Read the file directly: the plugin's package.json is not in its `exports` map, so
    // `require("@fhevm/hardhat-plugin/package.json")` fails. `scripts/` sits next to
    // `node_modules/`, so it is one level up, not two.
    const pkg = join(__dirname, "../node_modules/@fhevm/hardhat-plugin/package.json");
    return JSON.parse(readFileSync(pkg, "utf8")).version as string;
  } catch {
    return "unknown";
  }
}

async function main() {
  await assertFheMocksPresent();

  const [owner, buyer, committeeA, committeeB, committeeC, treasury] = await ethers.getSigners();

  const token = await ethers.deployContract("TestToken");
  const vault = await ethers.deployContract("PaymentVault", [await token.getAddress()]);
  const verifier = await ethers.deployContract("MockStarkVerifier", [48_576]);
  const bls = await ethers.deployContract("MockBLS");
  // 2-of-3 rather than 1-of-1: with a single member and threshold 1 the gate cannot distinguish
  // "the committee decrypted this" from "one key holder clicked approve", so the devnet would
  // exercise none of the t-of-n logic it exists to demonstrate. Three members also means a
  // single misconfigured or compromised member cannot open a reveal on its own.
  const committee = [committeeA.address, committeeB.address, committeeC.address];
  const gate = await ethers.deployContract("DecryptionGate", [await bls.getAddress(), h("bls-agg"), 2]);
  const net = await ethers.deployContract("NetworkParams", [owner.address]);
  const task = await ethers.deployContract("CipherTask", [
    await token.getAddress(),
    await vault.getAddress(),
    await verifier.getAddress(),
    await gate.getAddress(),
    treasury.address,
    true,
  ]);

  await vault.setTaskManager(await task.getAddress());
  await gate.setCipherTask(await task.getAddress());
  await gate.initialize(committeeA.address, committee);

  await net.initialize({
    chainId: 0,
    keyVersion: 1,
    fhePublicKeyHash: h("s_pub-v1"),
    committeeAggregateKey: h("bls-agg"),
    // Keep these consistent with the gate actually deployed above: `NetworkParams` publishes
    // them for clients to pin, and a client that trusts the pin while the gate disagrees gets
    // the wrong answer.
    committeeThreshold: 2,
    committeeSize: 3,
    maxProofBytes: 48_576,
    maxCiphertextBytes: 1 << 20,
    maxFeatures: 512,
    activatedAt: 0,
    active: true,
  });

  const chainId = (await ethers.provider.getNetwork()).chainId;
  const addresses = {
    chainId: Number(chainId),
    token: await token.getAddress(),
    vault: await vault.getAddress(),
    verifier: await verifier.getAddress(),
    bls: await bls.getAddress(),
    gate: await gate.getAddress(),
    networkParams: await net.getAddress(),
    cipherTask: await task.getAddress(),
    owner: owner.address,
    buyer: buyer.address,
    committee: committeeA.address,
    committeeMembers: committee,
    committeeThreshold: 2,
    treasury: treasury.address,
    /** The verifier and BLS contracts here are MOCKS. Do not treat devnet proofs or committee
     *  signatures as meaningful: the STARK is a magic-prefix check and the BLS check is an
     *  owner-curated allowlist. */
    mocks: { verifier: true, bls: true },
  };

  mkdirSync(join(__dirname, "../../../infra/devnet"), { recursive: true });
  writeFileSync(OUT, JSON.stringify(addresses, null, 2));
  console.log(`deployed Shroud devnet contracts; addresses written to ${OUT}`);
  console.warn("WARNING: MockStarkVerifier and MockBLS are installed as the real verifiers.");
  console.warn("         Proofs are not verified and committee signatures are owner-approved.");
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
