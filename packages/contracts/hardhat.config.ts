import "@nomicfoundation/hardhat-ethers";
import "@nomicfoundation/hardhat-chai-matchers";
// Installs the in-process mock coprocessor. Without it the `FHE` library's gateway calls
// (trivialEncrypt, allow, add, ...) hit unimplemented precompiles and every deploy reverts.
import "@fhevm/hardhat-plugin";
import "@typechain/hardhat";
import { HardhatUserConfig } from "hardhat/config";

/**
 * fhEVM compile configuration.
 *
 * `@fhevm/solidity` ships `lib/FHE.sol` (the `FHE` library) and the ciphertext value types
 * live in `encrypted-types/EncryptedTypes.sol`. Both are plain npm packages, so Hardhat's
 * default node_modules resolution handles `import {FHE} from "@fhevm/solidity/lib/FHE.sol"`.
 *
 * Cancun EVM semantics are required: `ReentrancyGuard` uses EIP-1153 transient storage, and
 * the fhEVM coprocessor expects Cancun.
 */

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 100 },
      viaIR: true,
      evmVersion: "cancun",
      metadata: { bytecodeHash: "none" }
    }
  },
  networks: {
    hardhat: {
      // `allowUnlimitedContractSize` is deliberately absent. With it set, an over-sized contract
      // compiles with a warning and deploys in tests, then fails on any real chain at the
      // 24,576-byte Spurious Dragon limit; without it, the test suite *is* the deployability check.
      blockGasLimit: 300_000_000,
      chainId: 31_337
    },
    // No named devnet network on purpose. The fhevm plugin recognises exactly three local
    // shapes - in-process 'hardhat', a standalone node reached as 'localhost' (port 8545,
    // chainId forced 31337), and 'anvil' - and any other network name resolves to provider
    // type Unknown, on which mock setup refuses. A 'devnet:' entry with its own URL/chainId
    // therefore deploys against a chain the plugin cannot instrument, and the constructor
    // reverts on the missing mock coprocessor. Deploy to a standalone node with '--network
    // localhost' (see 'deploy:devnet'); Hardhat's built-in 'localhost' network needs no
    // configuration.
  },
  paths: {
    sources: "./src",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  },
  typechain: {
    outDir: "./typechain-types",
    target: "ethers-v6"
  },
  mocha: {
    timeout: 120_000
  }
};

export default config;
