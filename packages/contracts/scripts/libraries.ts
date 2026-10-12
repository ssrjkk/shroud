import { artifacts, ethers } from "hardhat";

/**
 * Library linking for the contracts that are compiled against `external` libraries.
 *
 * `CipherTask` keeps its large, self-contained subtrees (validation, dividend math, state ACLs,
 * settlement) in `external` libraries so solc emits a `DELEGATECALL` instead of inlining them. That
 * is the only mechanism here that brings the contract under the 24,576-byte deployment limit:
 * `viaIR` inlines `internal` library functions, so moving code to a library as `internal` saves
 * nothing, and the optimizer's `runs` setting was measured to be irrelevant (29,592 bytes at
 * `runs: 100`, 29,645 at `runs: 1`).
 *
 * Because the calls are external, the deployed bytecode carries *link references* that must be
 * patched before deployment, and `ethers.deployContract` has no way to pass a link map. The
 * references are therefore read from the artifact itself, so adding or removing a library on a
 * contract never requires a matching edit here.
 *
 * @dev A library is deployed once per process and reused. The delegatecall'd code executes in the
 *      host's context, so libraries must never be swapped at runtime: the linked address is part of
 *      the deployed contract's trust boundary.
 */
const deployed = new Map<string, string>();

async function libraryAddress(name: string): Promise<string> {
  const cached = deployed.get(name);
  if (cached) return cached;
  // A library can itself call one (e.g. `SettlementLib` -> `Dividend`), so its own link references
  // must be resolved before it can be deployed; the recursion terminates because the dependency
  // graph is acyclic, which Solidity requires of `external` library calls anyway.
  const factory = await ethers.getContractFactory(name, { libraries: await linkLibrariesFor(name) });
  const instance = await factory.deploy();
  await instance.waitForDeployment();
  const address = await instance.getAddress();
  deployed.set(name, address);
  return address;
}

/** The `{ LibraryName: address }` map `name` was compiled to expect, or `{}` if it links nothing. */
export async function linkLibrariesFor(name: string): Promise<Record<string, string>> {
  const artifact = await artifacts.readArtifact(name);
  const links: Record<string, string> = {};
  for (const references of Object.values(artifact.linkReferences ?? {})) {
    for (const library of Object.keys(references)) links[library] = await libraryAddress(library);
  }
  return links;
}

/**
 * Deploy `name` with its libraries linked.
 *
 * `args` is the constructor argument list, exactly as `ethers.deployContract` takes it. The return
 * type is the typechain-generated contract type for `name`, which callers narrow with a type
 * annotation (`const task: CipherTask = await deployLinked(...)`).
 */
export async function deployLinked(name: string, args: unknown[] = []): Promise<any> {
  const factory = await ethers.getContractFactory(name, { libraries: await linkLibrariesFor(name) });
  const instance = await factory.deploy(...(args as Parameters<typeof factory.deploy>));
  await instance.waitForDeployment();
  return instance;
}

/** Forget the cached library addresses, for tests that reset the EVM state. */
export function resetLibraryCache(): void {
  deployed.clear();
}
