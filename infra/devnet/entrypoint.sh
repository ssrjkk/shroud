#!/bin/sh
# fhEVM devnet entrypoint: start hardhat, wait for RPC, deploy contracts, keep serving.
set -e

npx hardhat node --hostname 0.0.0.0 --port 8545 &
NODE_PID=$!

# Wait until the JSON-RPC answers before deploying against it.
until node -e "
fetch('http://127.0.0.1:8545', {
  method: 'post',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ jsonrpc: '2.0', method: 'eth_blockNumber', params: [], id: 1 })
}).then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))
" 2>/dev/null; do
  sleep 1
done

npm run deploy:devnet || { echo "deploy failed"; exit 1; }

# Keep the RPC alive; propagate SIGTERM so `docker compose stop` is clean.
trap 'kill -TERM $NODE_PID' TERM INT
wait $NODE_PID
