# fhEVM devnet: a hardhat node with the CipherMesh contracts deployed.
#
# The `@fhevm/hardhat-plugin` installs the in-process mock coprocessor, so no external KMS is
# needed - the same bytecode runs against the Zama coprocessor in production.
FROM node:20

WORKDIR /app
COPY packages/contracts/package.json packages/contracts/package-lock.json* ./
RUN npm ci
COPY packages/contracts/ .

# Start the hardhat node, wait for it, deploy the contracts (writes infra/devnet/addresses.json),
# then keep serving RPC.
CMD ["sh", "-c", "npx hardhat node --hostname 0.0.0.0 --port 8545 & node -e \"setTimeout(async()=>{try{await fetch('http://localhost:8545',{method:'post',body:'{\\\"jsonrpc\\\":\\\"2.0\\\",\\\"method\\\":\\\"eth_chainId\\\",\\\"params\\\":[],\\\"id\\\":1}',headers:{'content-type':'application/json'}})}catch{process.exit(1)}}.then(()=>process.exit(0)).catch(()=>process.exit(1)),0)\" ; sleep 1 ; while ! node -e \"fetch('http://localhost:8545',{method:'post',body:JSON.stringify({jsonrpc:'2.0',method:'eth_blockNumber',params:[],id:1}),headers:{'content-type':'application/json'}}).then(r=>r.ok?process.exit(0):process.exit(1)).catch(()=>process.exit(1))\" ; do sleep 1 ; done ; npm run deploy:devnet ; tail -f /dev/null"]
