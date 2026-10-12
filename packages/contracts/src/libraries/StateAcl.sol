// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Impl} from "@fhevm/solidity/lib/Impl.sol";
import "encrypted-types/EncryptedTypes.sol";

/// @title StateAcl
/// @notice Batch ACL grants for `CipherTask`'s encrypted state handle.
/// @dev Every fhEVM handle a task owns must be granted to the buyer, the update manager and the
///      contract itself before the next FHE operation on it, and `CipherTask` does that on every
///      `createTask` and `openEpoch`, plus once per reader in `grantStateAccess`. Inlined, each
///      grant is a storage read of the coprocessor config plus a checked external call to the ACL
///      contract, about 100 bytes of bytecode each: when `CipherTask` carried four handles and
///      twenty-odd grants, those grants alone were a large part of what pushed it past the
///      24 576-byte deployment limit. Linking them out keeps one copy of that code.
///
///      `Impl.allow` is called directly rather than through `FHE.allow`: the typed wrapper first
///      materialises an uninitialised handle with `asEuint32(0)` (a coprocessor round trip), and
///      every handle this library touches has just been created by the calling task.
library StateAcl {
    /// @notice Grant `h` to `buyer`, `manager` and `self`.
    /// @dev `self` is passed, not read as `address(this)`: a library body linked by `DELEGATECALL`
    ///      would evaluate `address(this)` as the caller, but an inlined one would evaluate it as
    ///      the library, and the ACL entry would then be useless. The explicit argument removes the
    ///      ambiguity.
    function grant64(euint64 h, address buyer, address manager, address self) external {
        bytes32 u = euint64.unwrap(h);
        Impl.allow(u, buyer);
        Impl.allow(u, manager);
        Impl.allow(u, self);
    }

    /// @notice Grant one additional reader access to `h`.
    /// @dev This is `grantStateAccess`'s body: a node that registers for a task must be able to
    ///      read the encrypted state accumulator it is about to be handed.
    function allow64(euint64 h, address reader) external {
        Impl.allow(euint64.unwrap(h), reader);
    }
}
