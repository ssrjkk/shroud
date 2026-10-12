import { expect } from "chai";
import { artifacts } from "hardhat";

/** EIP-170: the largest deployed bytecode any account may hold since Spurious Dragon. */
const DEPLOYMENT_LIMIT = 24_576;

/**
 * Bytecode budget gate.
 *
 * `CipherTask` was 29,592 bytes, which no public chain will accept, and the failure was invisible
 * locally: the suite ran with `allowUnlimitedContractSize`, so an undeployable contract still
 * passed 71 tests. That flag is off now, which catches the problem for contracts the suite
 * actually deploys and only at deploy time. This test checks every artifact instead, so a contract
 * that grows past the limit fails with its measured size rather than with a cryptic deploy revert.
 *
 * The budget is not a style preference. Leaving headroom is what makes the next feature additive;
 * at 24,563 bytes the only way to add code was to move code out, which is why settlement lives in
 * `SettlementLib`.
 */
describe("deployability", function () {
  it("keeps every contract inside the 24,576-byte deployment limit", async function () {
    const over: string[] = [];
    const rows: Array<[string, number]> = [];

    for (const fqn of await artifacts.getAllFullyQualifiedNames()) {
      const artifact = await artifacts.readArtifact(fqn);
      const code = artifact.deployedBytecode;
      if (code.length <= 2) continue; // interface or abstract, nothing to deploy
      const size = (code.length - 2) / 2;
      rows.push([fqn, size]);
      if (size > DEPLOYMENT_LIMIT) over.push(`${fqn} = ${size} bytes`);
    }

    expect(over, `contracts over the EIP-170 limit: ${over.join(", ")}`).to.deep.equal([]);
    // The suite is only meaningful if it measured the real thing.
    expect(rows.length).to.be.greaterThan(0);
  });

  it("leaves room to add a feature to CipherTask", async function () {
    const artifact = await artifacts.readArtifact("src/CipherTask.sol:CipherTask");
    const size = (artifact.deployedBytecode.length - 2) / 2;
    // A hard limit is not a target: at 200 bytes of slack the next guard or event would breach
    // EIP-170 again, so the budget itself is the thing under test.
    expect(DEPLOYMENT_LIMIT - size, `CipherTask is ${size} bytes`).to.be.greaterThan(250);
  });
});
