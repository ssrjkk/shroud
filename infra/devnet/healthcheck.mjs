// Healthcheck for the devnet container: the JSON-RPC answers AND the deploy finished
// (addresses.json written). Gating on the file as well as the port is what lets the compute
// nodes wait for contracts rather than for an empty chain: with `depends_on:
// condition: service_healthy` they start only after this passes.
import { readFileSync, existsSync } from "node:fs";

try {
  const r = await fetch("http://127.0.0.1:8545", {
    method: "post",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", method: "eth_blockNumber", params: [], id: 1 }),
  });
  if (!r.ok) process.exit(1);
  const out = "/infra/devnet/addresses.json";
  if (!existsSync(out)) process.exit(1);
  const addrs = JSON.parse(readFileSync(out, "utf8"));
  if (!addrs.cipherTask || !addrs.vault) process.exit(1);
  process.exit(0);
} catch {
  process.exit(1);
}
