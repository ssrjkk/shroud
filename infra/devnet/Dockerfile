# fhEVM devnet: a hardhat node with the Shroud contracts deployed.
#
# The `@fhevm/hardhat-plugin` installs the in-process mock coprocessor, so no external KMS is
# needed - the same bytecode runs against the Zama coprocessor in production.
FROM node:20

WORKDIR /app
COPY packages/contracts/package.json packages/contracts/package-lock.json* ./
RUN npm ci
COPY packages/contracts/ .
COPY infra/devnet/entrypoint.sh /entrypoint.sh
COPY infra/devnet/healthcheck.mjs /healthcheck.mjs
RUN chmod +x /entrypoint.sh

EXPOSE 8545
ENTRYPOINT ["/entrypoint.sh"]
