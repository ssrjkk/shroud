/**
 * SDK-against-devnet smoke: drives the real `ShroudSdk.uploadAndMonetize` (NoopEncryptor with
 * the explicit dev-only `allowUnencrypted` flag, in-memory DA) against a standalone node that
 * `deploy:devnet` populated, then verifies the contribution landed on chain.
 *
 * Run after the contracts deploy, against the same chain:
 *   npx hardhat node --hostname 127.0.0.1 --port 8545 &
 *   npm run deploy:devnet
 *   npm run devnet:sdk   (in packages/sdk, after `npm run build`)
 *
 * Uses hardhat#0 as both funder and buyer (unlocked dev key, already the deployer). Nothing here
 * is meaningful with real value: plaintext rows, mock verifier, single-node chain.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import { ShroudSdk, MemoryShardStore, NoopEncryptor } from "../dist/index.js";

const ADDRESSES = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "infra", "devnet", "addresses.json"), "utf8")
);
const RPC = process.env.CM_RPC_URL ?? "http://127.0.0.1:8545";
// hardhat#5, unused by any other script on a fresh devnet. Dev-only: a dedicated buyer keeps
// this script's nonce slate clean no matter what the deployer (hardhat#0) did before — sharing
// one account across scripts races ethers' local nonce tracking against automining.
const BUYER_KEY = process.env.CM_BUYER_KEY ?? "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba";

const TOKEN_ABI = [
  "function mint(address to, uint256 amount)",
  "function approve(address spender, uint256 amount) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function balanceOf(address) view returns (uint256)",
];

/**
 * A Wallet that numbers every send from a process-local counter instead of asking the chain.
 *
 * Two compounding reasons, both observed against automining Hardhat rather than theorised:
 *
 * 1. Ethers' provider caches identical requests for 250ms (`#performCache`): two
 *    `eth_getTransactionCount` calls 100ms apart return the SAME promise, so the second send
 *    reuses the first send's nonce and dies with `NONCE_EXPIRED`. On a 12-second chain that
 *    window never matters; on automine (every send mines instantly) sequential sends always
 *    land inside it. Raw `provider.send` bypasses the cache, but a local counter needs no
 *    reads at all.
 * 2. Ethers fetches nonces against the `pending` block, and on automine `pending` lags
 *    `latest` by exactly the last mined transaction (proven: `latest` 9, `pending` 8 right
 *    after mining). The counter starts from one raw `latest` read and only moves forward.
 *
 * Correct exactly when every send from this key goes through this one object, sequentially —
 * which is how this script and the SDK use it (single buyer, awaited sends). It is wrong for
 * concurrent senders sharing a key; devnet scripts must stay single-flight.
 */
function serialSigner(key, provider, firstNonce) {
  const wallet = new ethers.Wallet(key, provider);
  let next = firstNonce;
  const orig = wallet.sendTransaction.bind(wallet);
  wallet.sendTransaction = async (tx) => {
    const nonce = next++;
    const data = typeof tx.data === "string" ? tx.data.slice(0, 10) : "?";
    console.error(`[send] to=${tx.to} nonce=${nonce} data=${data}`);
    const res = await orig({ ...tx, nonce });
    const rc = await res.wait();
    console.error(`[mined] nonce=${nonce} block=${rc.blockNumber}`);
    return res;
  };
  return wallet;
}

/** Uncached chain truth: raw `send` skips the provider's 250ms request cache. */
async function chainNonce(provider, addr) {
  return BigInt(await provider.send("eth_getTransactionCount", [addr, "latest"]));
}

function b32(label) {
  return ethers.keccak256(ethers.toUtf8Bytes(`Shroud/devnet-sdk/${label}`));
}

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC);
  const buyerAddr = await new ethers.Wallet(BUYER_KEY, provider).getAddress();
  const startNonce = await chainNonce(provider, buyerAddr);
  const buyer = serialSigner(BUYER_KEY, provider, startNonce);

  // Idempotent funding: top up only the shortfall and approve only when short, so reruns
  // (and a previously half-finished run) converge instead of double-spending.
  const token = new ethers.Contract(ADDRESSES.token, TOKEN_ABI, buyer);
  const escrow = 1_000_000_000n;
  const have = await token.balanceOf(buyerAddr);
  if (have < escrow) await (await token.mint(buyerAddr, escrow - have)).wait();
  const allowed = await token.allowance(buyerAddr, ADDRESSES.vault);
  if (allowed < escrow) await (await token.approve(ADDRESSES.vault, ethers.MaxUint256)).wait();

  const sdk = new ShroudSdk({
    cipherTask: ADDRESSES.cipherTask,
    paymentVault: ADDRESSES.vault,
    signer: buyer,
    provider,
    shardStore: new MemoryShardStore(),
    encryptor: new NoopEncryptor(),
    chainId: BigInt(ADDRESSES.chainId),
  });

  // 2 features x 4 rows. minRowsPerShard below is 2, so this passes the local gate.
  const data = new Float64Array([1, 2, 3, 4, 5, 6, 7, 8]);
  const out = await sdk.uploadAndMonetize(data, 99999n, {
    features: 2,
    createIfMissing: true,
    budget: escrow,
    params: {
      buyer: buyerAddr,
      updateManager: ethers.ZeroAddress,
      epochs: 1,
      minContributors: 1,
      maxContributors: 100,
      minRowsPerShard: 2,
      features: 2,
      labelBits: 8,
      contributionWindow: 86400,
      epochDuration: 3600,
      disputeWindow: 600,
      pricePerRow: 1000,
      userShareBps: 8000,
      nodeShareBps: 1500,
      committeeShareBps: 500,
      reexecutionBps: 200,
      modelSpecCid: b32("model"),
      shapeRoot: b32("shape"),
      updateMode: 1,
    },
    allowUnencrypted: true,
    // Non-empty dummy: the devnet deploys with `shapeProofsRequired = true`, and the mock chain
    // accepts any non-empty proof (only `length == 0` reverts). A real deployment needs the
    // Groth16 proof the SDK's `shapeProof` option carries; the mock cannot check one.
    shapeProof: "0x1234",
  });
  console.log("uploaded task", out.taskId.toString(), "cid", out.ciphertextCid);

  // Independent on-chain verification through the SDK's own view client.
  const contrib = await sdk.cipherTask.contribution(out.taskId, buyerAddr);
  if (!contrib.accepted) throw new Error("contribution not accepted on chain");
  if (contrib.rows !== 4) throw new Error(`expected 4 rows, got ${contrib.rows}`);
  const task = await sdk.cipherTask.task(out.taskId);
  if (task.ctRoot === ethers.ZeroHash) throw new Error("ctRoot did not move");
  console.log("DEVNET SDK E2E OK");
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
