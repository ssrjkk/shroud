/**
 * Regenerate the SDK's embedded ABIs from the compiled contract artifacts.
 *
 * The SDK ships a copy of the compiled ABIs (`src/abi/*.json`) so it is self-contained and
 * selects the exact same functions as the on-chain contracts. Re-run this whenever the Solidity
 * changes, before committing:
 *
 *   cd packages/contracts && npx hardhat compile
 *   node packages/sdk/scripts/export-abi.cjs
 */
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "../../contracts/artifacts/src");
const out = path.resolve(__dirname, "../src/abi");

const contracts = [
  ["CipherTask", "CipherTask.sol/CipherTask"],
  ["PaymentVault", "payments/PaymentVault.sol/PaymentVault"],
  ["DecryptionGate", "DecryptionGate.sol/DecryptionGate"],
];

fs.mkdirSync(out, { recursive: true });
for (const [name, file] of contracts) {
  const abi = JSON.parse(fs.readFileSync(path.join(root, `${file}.json`), "utf8")).abi;
  fs.writeFileSync(path.join(out, `${name}.json`), JSON.stringify(abi, null, 2));
  console.log(`wrote src/abi/${name}.json (${abi.length} entries)`);
}
