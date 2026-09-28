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
      allowUnlimitedContractSize: true,
      blockGasLimit: 300_000_000,
      chainId: 31_337
    },
    devnet: {
      url: process.env.CM_RPC_URL ?? "http://127.0.0.1:8545",
      chainId: Number(process.env.CM_CHAIN_ID ?? 31338),
      accounts: process.env.CM_DEPLOYER_KEY ? [process.env.CM_DEPLOYER_KEY] : []
    }
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
