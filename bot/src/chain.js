/**
 * Chain reads.
 *
 * Scope is deliberately small and read-only: this bot reports what the chain
 * says, and never signs. It has no key material and no way to obtain any, which
 * is the property that makes it safe to point at a live deployment.
 *
 * ABI is loaded from the SDK's own JSON rather than hand-copied. If the
 * contracts change, the SDK ABI changes, and the bot fails loudly at load time
 * instead of silently decoding the wrong event field — the classic way a log
 * watcher ends up reporting zeros.
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { Interface, JsonRpcProvider, FetchRequest, Contract, id as keccakId, getAddress } from "ethers";
import { ROOT } from "./config.js";
import { scrubRpcSecret } from "./redact.js";

const ABI_DIR = resolve(ROOT, "..", "packages", "sdk", "src", "abi");

/**
 * The SDK ships ABIs for the two contracts it talks to. `NetworkParams` is not
 * among them, so its ABI is read straight from the compiled Hardhat artifact,
 * which is the source of truth.
 */
function loadArtifact(name, { contract }) {
  const candidates = [
    resolve(ABI_DIR, `${name}.json`),
    resolve(ROOT, "..", "packages", "contracts", "artifacts", "src", `${contract}.sol`, `${contract}.json`),
  ];
  for (const path of candidates) {
    if (!existsSync(path)) continue;
    const raw = JSON.parse(readFileSync(path, "utf8"));
    // Hardhat artifacts nest the ABI; the SDK's are the bare array.
    const abi = Array.isArray(raw) ? raw : raw.abi;
    if (Array.isArray(abi) && abi.length) return abi;
  }
  throw new Error(
    `No ABI found for ${name}. Looked in:\n  ${candidates.join("\n  ")}\n` +
      `Run \`npm run compile\` in packages/contracts first.`
  );
}

export function makeInterfaces() {
  return {
    cipherTask: new Interface(loadArtifact("CipherTask", { contract: "CipherTask" })),
    paymentVault: new Interface(loadArtifact("PaymentVault", { contract: "PaymentVault" })),
    networkParams: new Interface(loadArtifact("NetworkParams", { contract: "NetworkParams" })),
  };
}

/**
 * Formats a task id the way the explorer and the contracts display it.
 *
 * Total by design: a formatter that throws takes the bot down, and this runs
 * inside message rendering where a crash means a silent channel. Task ids are
 * numeric in practice, but a formatter fed something unexpected should show
 * that something, not abort the reply.
 */
export const shortId = (v) => {
  const s = String(v);
  let n;
  try {
    n = BigInt(s).toString();
  } catch {
    // Not a number. Still truncate, so a hostile or malformed value cannot be
    // used to inject an unbounded string into a message.
    return s.length <= 16 ? s : `${s.slice(0, 12)}…`;
  }
  return n.length <= 12 ? n : `${n.slice(0, 6)}…${n.slice(-4)}`;
};

export const shortAddr = (a) => {
  // Total like shortId: a formatter that throws takes the whole reply down, and chain
  // structs occasionally carry non-strings where an address belongs.
  if (!a) return "—";
  const s = String(a);
  return `${s.slice(0, 8)}…${s.slice(-6)}`;
};

/** Decimals cache for ERC20 tokens, keyed by token address. */
const tokenDecimalsCache = new Map();

/** ERC20 minimal ABI for reading decimals. */
const ERC20_DECIMALS_ABI = ["function decimals() view returns (uint8)"];

/**
 * Fetch and cache token decimals. Uses the chain provider from the ChainReader instance.
 * @param {string} tokenAddress - ERC20 token address
 * @param {import("ethers").JsonRpcProvider} provider - RPC provider
 * @returns {Promise<number>} token decimals (defaults to 18 if read fails)
 */
async function getTokenDecimals(tokenAddress, provider) {
  if (!tokenAddress || tokenAddress === "0x0000000000000000000000000000000000000000") {
    return 18; // Default for ETH or invalid token
  }
  const cached = tokenDecimalsCache.get(tokenAddress.toLowerCase());
  if (cached !== undefined) return cached;

  try {
    const tokenContract = new Contract(tokenAddress, ERC20_DECIMALS_ABI, provider);
    const decimals = Number(await tokenContract.decimals());
    tokenDecimalsCache.set(tokenAddress.toLowerCase(), decimals);
    return decimals;
  } catch {
    tokenDecimalsCache.set(tokenAddress.toLowerCase(), 18);
    return 18; // Default to 18 if read fails
  }
}

/** 1e18-scaled token amount as a plain decimal string with 4dp. */
export function fmtEth(wei, decimals = 4, tokenDecimals = 18n) {
  try {
    const v = BigInt(wei);
    const d = BigInt(tokenDecimals);
    const scale = 10n ** d;
    const whole = v / scale;
    const frac = v % scale;
    const fracStr = frac.toString().padStart(Number(d), "0").slice(0, decimals);
    return fracStr.replace(/0+$/, "") === ""
      ? whole.toString()
      : `${whole}.${fracStr.replace(/0+$/, "")}`;
  } catch {
    return String(wei);
  }
}

export class ChainReader {
  #provider;
  #ifaces;
  #config;
  /** Memoized `ethers.Contract` instances, keyed by role. Constructing one is cheap
   *  but not free (ABI parsing + runner binding), and readers run every poll — nine
   *  call sites sharing three instances instead of rebuilding them per read. */
  #contracts = new Map();

  constructor(provider, interfaces, config) {
    this.#provider = provider;
    this.#ifaces = interfaces;
    this.#config = config;
  }

  /**
   * Cached contract handle, or null when unconfigured. Addresses are fixed for the
   * life of the reader, so one instance per role is enough; callers keep their
   * existing `if (!... ) return <default>` guards unchanged.
   */
  #contract(role, address, iface) {
    if (!address) return null;
    let c = this.#contracts.get(role);
    if (!c) {
      c = new Contract(address, iface, this.#provider);
      this.#contracts.set(role, c);
    }
    return c;
  }

  static async connect(config, ifaces) {
    // `staticNetwork` requires knowing the chain id up front. Passing
    // `chainId: 0` or `null` makes ethers reject the network object itself, which
    // would mask the real problem (an unreachable RPC) behind a validation
    // error about names. So a custom network is only supplied when the operator
    // actually configured one.
    const network = config.chainId
      ? { chainId: config.chainId, name: `shroud-${config.chainId}` }
      : undefined;

    // Bounded RPC: a dead node must fail reads in milliseconds, not hang the poll loops
    // forever. FetchRequest carries the timeout; JsonRpcProvider honors it per request.
    // Batching is on (up to 12 calls per round trip): readers fan independent reads out
    // with Promise.all, and batching folds the overlap into one HTTP request. A provider
    // that cannot do batches answers each call alone — slower, never wrong.
    const request = new FetchRequest(config.rpcUrl);
    request.timeout = config.rpcTimeoutMs ?? 15_000;
    const provider = new JsonRpcProvider(request, network, {
      staticNetwork: Boolean(network),
      batchMaxCount: 12,
    });

    // `getNetwork()` alone is not a liveness check: with `staticNetwork` set,
    // ethers returns the configured id without ever contacting the node. That
    // would let the bot start happily against a dead RPC and only fail later,
    // per poll. `getBlockNumber()` genuinely round-trips, so it is called
    // explicitly for that reason.
    const head = await provider.getBlockNumber();

    // Also report the chain the RPC actually serves, so a config pointing at the
    // wrong chain is caught before the bot says anything about it.
    const seen = await provider.getNetwork();
    if (config.chainId && Number(seen.chainId) !== config.chainId) {
      throw new Error(
        `RPC_URL serves chain ${seen.chainId}, but CHAIN_ID is ${config.chainId}. Refusing to report state from the wrong chain.`
      );
    }
    log(`connected to chain ${seen.chainId}, head block ${head}`);
    return new ChainReader(provider, ifaces, config);
  }

  get provider() {
    return this.#provider;
  }

  #lastReadError = null;

  /**
   * Latest read failure (`where: message`), or null when no recent read failed.
   *
   * Reads fail soft (null/[]) so one bad RPC never kills a reply — but then an
   * operator cannot tell "no commits" from "RPC dead". /status surfaces this, so
   * the two stay distinguishable. Entries expire after `maxAgeMs` (default 5 min):
   * readers poll continuously, and a stale blip must not cry outage forever.
   */
  lastReadError(maxAgeMs = 5 * 60_000) {
    const e = this.#lastReadError;
    if (!e) return null;
    if (Date.now() - e.at > maxAgeMs) {
      this.#lastReadError = null;
      return null;
    }
    return `${e.where}: ${e.message}`;
  }

  #noteReadError(where, err) {
    this.#lastReadError = {
      where,
      // Scrubbed: this message is surfaced to the operator by /status, and an error
      // that quotes the RPC URL would put the provider's key into a chat.
      message: scrubRpcSecret(err?.message ?? String(err), this.#config.rpcUrl),
      at: Date.now(),
    };
  }

  get interfaces() {
    return this.#ifaces;
  }

  async chainId() {
    return Number((await this.#provider.getNetwork()).chainId);
  }

  async blockNumber() {
    return this.#provider.getBlockNumber();
  }

  async balanceOf(address) {
    return this.#provider.getBalance(getAddress(address));
  }

  /**
   * Fetch logs for an event across a block range.
   *
   * The range is walked in windows because a devnet node will refuse a wide
   * `eth_getLogs`, and the failure mode of a single huge query is a hard
   * error rather than a partial answer — so it is done in bounded slices here.
   */
  async #queryLogs(iface, eventName, address, fromBlock, toBlock, { window = 2000 } = {}) {
    if (!address) return [];
    const topic = iface.getEvent(eventName).topicHash;
    const out = [];
    for (let start = fromBlock; start <= toBlock; start += window) {
      const end = Math.min(start + window - 1, toBlock);
      const logs = await this.#provider.getLogs({
        address: getAddress(address),
        fromBlock: start,
        toBlock: end,
        topics: [topic],
      });
      out.push(...logs);
    }
    return out;
  }

  #decode(iface, eventName, logs) {
    const parsed = [];
    for (const log of logs) {
      try {
        const item = iface.parseLog({
          topics: log.topics,
          data: log.data,
        });
        // Identity, not just position: `transactionHash` + `index` is what lets the alert
        // loop deduplicate across restarts and rewinds. (This used to read `log.hash`, which
        // does not exist on an ethers v6 `Log` — every rendered "tx …" was `undefined`.)
        if (item) {
          parsed.push({
            ...item,
            blockNumber: log.blockNumber,
            txHash: log.transactionHash,
            logIndex: log.index,
          });
        }
      } catch {
        // A log we cannot decode is skipped rather than fatal: a contract
        // upgrade should not stop the bot from reporting everything else.
      }
    }
    return parsed;
  }

  // --- CipherTask ----------------------------------------------------------

  /** Every `TaskCreated` in range, newest last. */
  async tasksCreated(fromBlock, toBlock) {
    const logs = await this.#queryLogs(
      this.#ifaces.cipherTask,
      "TaskCreated",
      this.#config.cipherTask,
      fromBlock,
      toBlock
    );
    return this.#decode(this.#ifaces.cipherTask, "TaskCreated", logs);
  }

  /** Number of tasks the contract knows about. */
  async taskCount() {
    if (!this.#config.cipherTask) return 0;
    const c = this.#contract("cipherTask", this.#config.cipherTask, this.#ifaces.cipherTask);
    return Number(await c.taskCount());
  }

  /**
   * Full on-chain state for one task.
   *
   * `tasks(uint256)` returns one flat struct (params nested, budget and status
   * alongside it) and a non-existent id reverts rather than returning zeros, so
   * "unknown task" is reported as such instead of as a task with a zero budget.
   */
  async task(taskId) {
    if (!this.#config.cipherTask) return null;
    // Optimistic clear: a success below leaves the flag null; the catch re-sets it
    // on failure. Without this a one-second RPC blip warns for the full 5-minute TTL.
    this.#lastReadError = null;
    const c = this.#contract("cipherTask", this.#config.cipherTask, this.#ifaces.cipherTask);
    try {
      const t = await c.tasks(taskId);
      if (!t) return null;
      const status = Number(t.status);
      return {
        taskId: BigInt(taskId).toString(),
        status,
        statusName: taskStatusName(status),
        budget: t.budget,
        locked: t.locked,
        contributors: Number(t.contributors),
        shards: Number(t.shards),
        nextEpoch: Number(t.nextEpoch),
        ctRoot: t.ctRoot,
        ctRootSet: t.ctRoot !== "0x" + "0".repeat(64),
        isSealed: Boolean(t.isSealed),
        params: t.params
          ? {
              epochs: Number(t.params.epochs),
              labelBits: Number(t.params.labelBits),
              features: Number(t.params.features),
              contributionWindow: Number(t.params.contributionWindow),
              disputeWindow: Number(t.params.disputeWindow),
              pricePerRow: t.params.pricePerRow,
            }
          : null,
      };
    } catch (e) {
      this.#noteReadError("task", e);
      return null;
    }
  }

  async statusOf(taskId) {
    if (!this.#config.cipherTask) return null;
    this.#lastReadError = null;
    const c = this.#contract("cipherTask", this.#config.cipherTask, this.#ifaces.cipherTask);
    try {
      return Number(await c.statusOf(taskId));
    } catch (e) {
      this.#noteReadError("statusOf", e);
      return null;
    }
  }

  /**
   * The contributor set for a task.
   *
   * There is no `allCommits`: the contract stores commits per
   * (task, epoch, node), so the set of nodes worth asking about comes from
   * `contributorsOf`. Asking for an arbitrary address would return a zeroed
   * struct for every node that never committed, which is exactly the kind of
   * "empty but successful" read that makes a bot report a clean epoch when
   * nobody actually committed.
   */
  async contributors(taskId) {
    if (!this.#config.cipherTask) return [];
    this.#lastReadError = null;
    const c = this.#contract("cipherTask", this.#config.cipherTask, this.#ifaces.cipherTask);
    try {
      return [...(await c.contributorsOf(taskId))];
    } catch (e) {
      this.#noteReadError("contributors", e);
      return [];
    }
  }

  /** Commits for one epoch, across the task's contributor set. */
  async commitsForEpoch(taskId, epoch) {
    const nodes = await this.contributors(taskId);
    if (!nodes.length) return [];
    const c = this.#contract("cipherTask", this.#config.cipherTask, this.#ifaces.cipherTask);
    // All reads in flight at once: the sequential loop paid a full RPC round trip per
    // node. Order is the contributor-list order either way (Promise.all preserves it).
    const settled = await Promise.all(
      nodes.map(async (node) => {
        try {
          const r = await c.commits(taskId, epoch, node);
          // A node that did not commit reads back as an all-zero struct; its
          // digest is zero, which is filtered out rather than shown as a commit.
          if (!r || r.traceDigest === "0x" + "0".repeat(64)) return null;
          return {
            node,
            traceDigest: r.traceDigest,
            verified: Boolean(r.verified),
            // The 32-byte proof reference as committed (STAR-prefixed on mock-verifier
            // chains); rendered by /task so operators can eyeball it, never interpreted.
            proof: r.proof,
          };
        } catch {
          // Read failure for one node must not hide the others.
          return null;
        }
      })
    );
    return settled.filter((x) => x !== null);
  }

  async epochWinner(taskId, epoch) {
    if (!this.#config.cipherTask) return null;
    this.#lastReadError = null;
    const c = this.#contract("cipherTask", this.#config.cipherTask, this.#ifaces.cipherTask);
    try {
      return await c.epochWinner(taskId, epoch);
    } catch (e) {
      this.#noteReadError("epochWinner", e);
      return null;
    }
  }

  /**
   * Dispute quorum progress: how many distinct reporters have filed (`have`) out of
   * the quorum the contract requires (`need`).
   *
   * The contract returns a pair, not a scalar — an earlier revision wrapped the pair
   * in `Number()`, which is `NaN` for any task, and every /task screen showed
   * "NaN on record" forever.
   */
  async disputeQuorum(taskId) {
    if (!this.#config.cipherTask) return null;
    this.#lastReadError = null;
    const c = this.#contract("cipherTask", this.#config.cipherTask, this.#ifaces.cipherTask);
    try {
      const [need, have] = await c.disputeQuorum(taskId);
      return { need: Number(need), have: Number(have) };
    } catch (e) {
      this.#noteReadError("disputeQuorum", e);
      return null;
    }
  }

  /** `EpochCommitted` logs in a range, decoded and ready to alert on. */
  async commitEvents(fromBlock, toBlock) {
    const logs = await this.#queryLogs(
      this.#ifaces.cipherTask,
      "EpochCommitted",
      this.#config.cipherTask,
      fromBlock,
      toBlock
    );
    return this.#decode(this.#ifaces.cipherTask, "EpochCommitted", logs);
  }

  async disputeEvents(fromBlock, toBlock) {
    // Only events that actually exist in the ABI are queried. There is no
    // `DisputeRejected`; a rejection surfaces as `EpochVerified(ok=false)`.
    // `DisputeCommitted` is the commit-reveal front half of a dispute: worth watching
    // because a commitment with no follow-up reveal is either a stuck reporter or a
    // ring testing the quorum.
    const names = ["DisputeCommitted", "DisputeReported", "EpochVerified", "TaskSettled", "TaskStatusChanged"];
    const out = [];
    for (const name of names) {
      try {
        const logs = await this.#queryLogs(
          this.#ifaces.cipherTask,
          name,
          this.#config.cipherTask,
          fromBlock,
          toBlock
        );
        out.push(...this.#decode(this.#ifaces.cipherTask, name, logs));
      } catch {
        // Not every build emits every event; absence is not an error.
      }
    }
    // `NodeBondSlashed` is emitted by the vault, not the orchestrator: same topic the
    // interface declares, different emitting address, so it needs its own query.
    try {
      const logs = await this.#queryLogs(
        this.#ifaces.paymentVault,
        "NodeBondSlashed",
        this.#config.paymentVault,
        fromBlock,
        toBlock
      );
      out.push(...this.#decode(this.#ifaces.paymentVault, "NodeBondSlashed", logs));
    } catch {
      // Not every build emits every event; absence is not an error.
    }
    return out.sort((a, b) => (a.blockNumber ?? 0) - (b.blockNumber ?? 0));
  }

  // --- NetworkParams -------------------------------------------------------

  /**
   * Turn a positional `Result` from a multi-return call into a named object.
   *
   * `current()` and `pending()` return flat value lists, not structs, so the
   * shape has to be rebuilt by position. Taking the names from the ABI rather
   * than hardcoding them means a contract change that reorders the outputs
   * fails here instead of silently reporting `chainId` as `keyVersion`.
   */
  #named(iface, fn, result) {
    const outputs = iface.getFunction(fn).outputs ?? [];
    if (!outputs.length || !outputs.every((o) => o.name)) {
      throw new Error(`${fn}() has unnamed outputs; cannot map them safely.`);
    }
    const out = {};
    outputs.forEach((o, i) => {
      out[o.name] = result[i];
    });
    return out;
  }

  /** Current network parameters, including the pinned FHE key hash. */
  async networkParams() {
    if (!this.#config.networkParams) return null;
    this.#lastReadError = null;
    const c = this.#contract("networkParams", this.#config.networkParams, this.#ifaces.networkParams);
    try {
      const n = this.#named(this.#ifaces.networkParams, "current", await c.current());
      return {
        chainId: Number(n.chainId),
        keyVersion: Number(n.keyVersion),
        fhePublicKeyHash: n.fhePublicKeyHash,
        committeeThreshold: Number(n.committeeThreshold),
        committeeSize: Number(n.committeeSize),
        maxProofBytes: Number(n.maxProofBytes),
        maxCiphertextBytes: Number(n.maxCiphertextBytes),
        maxFeatures: Number(n.maxFeatures),
        activatedAt: Number(n.activatedAt),
        active: Boolean(n.active),
      };
    } catch (e) {
      this.#noteReadError("networkParams", e);
      return null;
    }
  }

  /** The queued rotation, or `null` when none is pending. */
  async pendingRotation() {
    if (!this.#config.networkParams) return null;
    const c = this.#contract("networkParams", this.#config.networkParams, this.#ifaces.networkParams);
    try {
      if (!(await c.rotationPending())) return null;
      const r = this.#named(this.#ifaces.networkParams, "pending", await c.pending());
      return {
        scheduledAt: Number(r.scheduledAt),
        expectedHash: r.expectedHash,
        proposer: r.proposer,
        approver: r.approver,
      };
    } catch {
      return null;
    }
  }

  async rotationEvents(fromBlock, toBlock) {
const grab = async (name) =>
      this.#decode(
        this.#ifaces.networkParams,
        name,
        await this.#queryLogs(
          this.#ifaces.networkParams,
          name,
          this.#config.networkParams,
          fromBlock,
          toBlock
        )
      );
    const executed = await grab("RotationExecuted");
    const proposed = await grab("RotationProposed");
    return { executed, proposed, pending: await this.pendingRotation() };
  }
}

/**
 * Task ids for the pool screen, newest first.
 *
 * On-chain ids start at 1 and `taskCount()` is the newest id, so the window is
 * `(count-shown, count]` — not `[count-shown, count)`. The old loop started at
 * `count - 1`: it never showed the newest task and always queried id 0, which
 * reverts. Pure, so the off-by-one is pinned by a test instead of a chat log.
 */
export function poolIds(count, shown) {
  const n = Math.max(0, Math.floor(Number(count) || 0));
  const s = Math.max(0, Math.floor(Number(shown) || 0));
  const ids = [];
  for (let i = n; i > Math.max(0, n - s); i--) ids.push(BigInt(i));
  return ids;
}

/**
 * One page of the pool window, newest first.
 *
 * Page 1 is the newest `perPage` tasks; later pages walk backwards. Pure like
 * `poolIds` so the bounds are pinned by tests: a page past the end clamps to
 * the last non-empty page, and an empty pool reports one page of nothing
 * rather than page 0 of 0 (keyboards render `page/pages` unconditionally).
 */
export const POOL_PAGE_SIZE = 12;

export function poolPage(count, page, perPage = POOL_PAGE_SIZE) {
  const total = Math.max(0, Math.floor(Number(count) || 0));
  const size = Math.max(1, Math.floor(Number(perPage) || POOL_PAGE_SIZE));
  const pages = Math.max(1, Math.ceil(total / size));
  const p = Math.min(Math.max(1, Math.floor(Number(page) || 1)), pages);
  const ids = [];
  for (let i = total - (p - 1) * size; i > Math.max(0, total - p * size); i--) {
    ids.push(BigInt(i));
  }
  return { ids, page: p, pages, total };
}

/** Mirrors `ICipherTask.TaskStatus` so the bot never invents a status name. */
export function taskStatusName(status) {
  return (
    {
      0: "None",
      1: "Opening",
      2: "Collecting",
      3: "Sealed",
      4: "EpochOpen",
      5: "EpochCommitting",
      6: "EpochSettled",
      7: "Settling",
      8: "Revealing",
      9: "Disclosed",
      10: "Aborted",
      11: "Paused",
    }[status] ?? `Unknown(${status})`
  );
}

export { keccakId };
