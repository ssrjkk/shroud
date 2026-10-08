// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ReentrancyGuard (transient storage, Solidity >=0.8.24)
/// @dev Hand-rolled instead of OZ so the package compiles without external deps.
///      Uses TSTORE/TLOAD (EIP-1153), available on the fhEVM L3 and on Cancun+.
///
///      Transient storage slot 0 is the only one used. It is per-transaction rather than
///      per-frame, which is exactly what a reentrancy flag wants: the flag is always cleared
///      before the guarded function returns, so no later call in the same transaction can
///      inherit a stale `_ENTERED` from an earlier one. solc's EIP-1153 warning names this
///      pattern as the safe one.
///
///      Only the flag read/write is inlined. The revert stays in Solidity rather than a
///      hand-encoded `mstore`/`revert` pair, so the `Reentrancy()` selector can never drift
///      out of sync with the declaration above — a raw 4-byte constant here is exactly the kind
///      of silent mismatch that turns a reentrancy attempt into an opaque failure.
abstract contract ReentrancyGuard {
    error Reentrancy();

    modifier nonReentrant() {
        bool locked;
        assembly {
            locked := tload(0)
        }
        if (locked) revert Reentrancy();
        assembly {
            tstore(0, 1)
        }
        _;
        assembly {
            tstore(0, 0)
        }
    }
}

/// @title Pausable
abstract contract Pausable {
    bool private _paused;

    error Paused();

    event PausedChanged(bool paused);

    modifier whenNotPaused() {
        if (_paused) revert Paused();
        _;
    }

    function paused() external view returns (bool) {
        return _paused;
    }

    function _setPaused(bool v) internal {
        _paused = v;
        emit PausedChanged(v);
    }
}
