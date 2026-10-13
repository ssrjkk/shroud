# fhEVM devnet: a hardhat node with the Shroud contracts deployed.
#
# The `@fhevm/hardhat-plugin` etches the mock coprocessor into the standalone node at startup
# (its `hardhat_node` provider hook), so no external KMS is needed - the same bytecode runs
# against the Zama coprocessor in production.
FROM node:26

WORKDIR /app
COPY packages/contracts/package.json packages/contracts/package-lock.json* ./
RUN npm ci
COPY packages/contracts/ .
COPY infra/devnet/entrypoint.sh /entrypoint.sh
COPY infra/devnet/healthcheck.mjs /healthcheck.mjs
RUN chmod +x /entrypoint.sh
# Compile at build time: fails fast on broken code and warms the cache, so the entrypoint's
# deploy starts from artifacts rather than a cold multi-minute compile (the healthcheck only
# waits ~5 minutes for the whole deploy).
RUN npx hardhat compile

EXPOSE 8545
ENTRYPOINT ["/entrypoint.sh"]
