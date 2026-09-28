// Healthcheck for the devnet container: is the JSON-RPC answering?
node -e "
fetch('http://127.0.0.1:8545', {
  method: 'post',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ jsonrpc: '2.0', method: 'eth_blockNumber', params: [], id: 1 })
}).then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))
"
