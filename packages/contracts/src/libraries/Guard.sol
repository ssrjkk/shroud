// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ReentrancyGuard (storage flag, all EVM versions)
/// @dev Hand-rolled instead of OZ so the package compiles without external deps.
///
///      A single storage flag, not transient storage (EIP-1153/TSTORE). Transient is
///      cheaper on Cancun+, but these contracts — `PaymentVault` in particular, which is
///      plain Solidity with no FHE precompiles — must remain safe on any EVM that can
///      execute them. On a pre-Cancun chain `TLOAD`/`TSTORE` are not defined opcodes,
///      so a transient guard would either revert every guarded call or, worse, silently
///      not guard, depending on the client. A storage flag costs one extra cold slot
///      access and is correct everywhere.
abstract contract ReentrancyGuard {
    error Reentrancy();

    uint256 private _entered;

    modifier nonReentrant() {
        if (_entered != 0) revert Reentrancy();
        _entered = 1;
        _;
        _entered = 0;
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
