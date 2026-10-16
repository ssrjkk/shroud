# User guide

End-to-end usage for every role: buyer, contributor, node operator, committee,
watcher (Telegram bot), and the in-browser lab. Research prototype — see the
banner in `README.md` before putting anything real through this.

## 0. Prerequisites

- Docker (devnet, ShardStore, nodes), Node 22 (`npm ci` everywhere), Rust toolchain
  with `protoc` (node only), a Sepolia RPC URL + relayer access for real encryption.
- No real funds, no real private data. Devnet uses faucet keys printed in the logs.

## 1. Devnet up

```sh
cd infra
docker compose up -d --build devnet shardstore   # chain :8545 + DA :8080
docker compose build node-a                        # tags shroud-node:dev
docker compose up -d node-a node-b node-c          # attach 3 nodes
```

Deployed addresses land in `infra/devnet/addresses.json` (also `.env` shell form).
Health: `devnet` has a healthcheck (up to 60×5s for cold compile+deploy);
ShardStore: `GET http://127.0.0.1:8080/healthz`.

## 2. Buyer — fund a task and get weights back

```ts
import { ShroudSdk, NoopEncryptor } from "@shroud/sdk"; // dev only: NoopEncryptor is plaintext
import { ethers } from "ethers";

const signer = new ethers.Wallet(process.env.CM_OPERATOR_KEY!, provider);
const sdk = new ShroudSdk({
  cipherTask: "0x…",          // from addresses.json
  paymentVault: "0x…",
  signer,
  provider,                   // explicit provider wins over the signer's own
  chainId: 31337n,            // numbers/decimal strings are normalized; mismatch throws
  encryptor: new NoopEncryptor(),
  shardStore: new HttpShardStore("http://127.0.0.1:8080", { authToken: process.env.SHARDSTORE_AUTH_TOKEN }),
});
// Contributor side (same call): encrypt → DA → submitContribution, with every
// revert reason pre-checked locally (shape, window, cap, bond, duplicate).
const { taskId, ciphertextCid } = await sdk.uploadAndMonetize(rows, 0n, {
  features: 3,
  budget: 1_000_000_000n,                       // base units; escrowed in full
  params: { epochs: 3, minContributors: 1, /* …see TaskParams */ },
  createIfMissing: true,
  allowUnencrypted: true,                       // dev ONLY: NoopEncryptor is plaintext
});
```

Production encryption instead of the noop path:

```ts
import { RelayerEncryptor } from "@shroud/sdk/relayer";
const encryptor = await RelayerEncryptor.create({
  network: process.env.SEPOLIA_RPC!,            // chain RPC the relayer serves
  contractAddress: "0x…CipherTask…",             // REQUIRED: binds the input proof
  userAddress: await signer.getAddress(),
});
// uploads through this encryptor need no allowUnencrypted escape hatch
```

Task lifecycle (buyer or `updateManager`): `openEpoch` per epoch →
nodes `commitEpoch` → `finalizeEpoch` after the dispute window (or quorum reject)
→ `settle`/`settleFrom(cursor)` paged at 200 → `requestReveal` (committee BLS
aggregate) → partials → `withdraw` → `Disclosed`. Buyer refund and channel claims
are pull-based: `PaymentVault.claim()` / `redeem(...)`.

Money rules that bite: escrow is total and up-front; contributor/committee pools
are reserved (reclaim/abort cannot touch them); `abort` reverts once every epoch
ran (`SettleReady`) — settle instead; reward channels mature 7 days before the
final page pays (`ChannelsImmature` until then).

## 3. Contributor — shard requirements

- One shard per address per task (`AlreadyContributed`, `DuplicateShard` on copy).
- `rows >= minRowsPerShard`, `rows <= 100_000`, `features >= 1` on chain
  (SDK mirrors the cap client-side).
- Optional per-task bond (`setContributionBondRequirement`, capped): pulled on
  submit, slashed to treasury on `slashContributionBond`, released when terminal
  or settled. Default requirement is zero.
- `shapeProof` (Groth16 bytes) required iff the task demands it.

## 4. Node operator

Config lives in `shroud.toml` (annotated example: `infra/README.md` §3). Essentials:

```toml
[chain]
rpc_url = "http://127.0.0.1:8545"
chain_id = 31337
[contracts]
cipher_task = "0x…"      # from addresses.json
payment_vault = "0x…"
[node]
operator_key = "0x…"     # pays gas + registration bond (10 token units at 6 dp/task)
data_dir = "./data"
# enforce_key_pin = false  # dev default; set true + fhe.public_key_hash + contracts.network_params anywhere real
[shard]
da_endpoint = "file://./data/da"
[mesh]
listen = "127.0.0.1:17331"
# max_throttle_peers = 10000
```

Run: `shroud-node --config shroud.toml`. The node registers (bond pulled),
executes open epochs (reference-cpu by default; `tfhe-rs` needs `--features prover`
plus `fhe.server_key_path`), commits, re-executes rivals for disputes
(commit-reveal recommended), finalizes, redeems channels, releases its bond when
the task can no longer slash it. A loud warning is logged while key-pin
enforcement is off. Mesh without all three `mtls_*` paths serves plaintext (WARN).

## 5. Committee + reveal

`requestReveal(taskId, blsAggregateSig)` (buyer/manager/owner) → members
`submitPartialDecryption` → `withdraw(taskId)` once `revealCompleted` (threshold).
`DecryptionGateClient` (`@shroud/sdk` `gate.ts`) wraps reads
(`revealMessage`, `revealCompleted`, `gateInfo`, `partialCount`) and the two
writes, plus `waitForReveal` with timeout. Threshold and members come from the
gate; collusion at threshold is a documented residual (F-10), not a bug.

## 6. Watcher bot

```sh
cp bot/.env.example bot/.env   # fill TELEGRAM_BOT_TOKEN + TELEGRAM_ALLOWED_IDS
cd bot && npm ci && npm start
```

Commands: `/pool`, `/task <id>`, `/status`, `/limits`, `/help`.
`/status` also reports shed alerts and recent chain-read failures, so "empty
pool" vs "RPC dead" stay distinguishable. Heavy commands cost budget
(`/pool` 15/min-ish pool); over-quota chats get rate replies, then tarpit, then
plausible shadowban answers without RPC. Replies go through the
bounded send queue; `droppedSends` is visible in `/status`.

## 7. Browser lab

Open `web/playground.html` (or the deployed site): pick a preset → parse CSV →
assemble shard → run epoch → trace digest → report → settle math → downloads
(`shard-demo.hex`, `weights-demo.hex`, `shroud-report.json` — demo bytes).
CSV cells are strict decimals (hex/binary/Infinity rejected). Default lr 0.05
yields lrQ16 3277 while golden vectors pin 3276 — compare against goldens at
the same lrQ16 (see the lab honesty note).

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ChannelsImmature` on settle | Winner channel inside the 7-day window | Wait it out, settle again; `settleFrom` resumes at cursor |
| `SettleReady` on abort | All epochs ran — abort is closed | `settle` (+ `reclaimUnspentEpochs` before it if node pool unspent) |
| `BondInsufficient` on submit | No/revoked bond approval | Approve the exact requirement; retry (allowance is exact, never max) |
| `wrong chain` from SDK | `chainId` vs provider mismatch | Align config with the RPC network |
| `is not the key pinned on chain` | `s_pub` rotated or misconfigured | Update `fhePublicKeyHash` / wait rotation; never `allowUnpinnedKey` blindly |
| Bot "not configured" | Zero/missing contract address | Fill `*_ADDRESS` in `bot/.env` |
| Bot "chain reads failing" in /status | RPC down or wrong chain | Check `RPC_URL`/`CHAIN_ID`, node logs |
| DA `413`/`503` | Object over cap / in-flight budget shed | Smaller shards; retry with backoff (SDK retries 429/5xx) |
| `DuplicateShard` / `AlreadyContributed` | Same bytes or same address twice | New bytes, new address |
| Node "key is NOT checked" warning | `enforce_key_pin` off | Expected on devnet; enable with pin + NetworkParams elsewhere |
| `NoEpochOpened` on emergencyUnwind | No epoch ever opened | Buyer `abort` is the recovery path there |
