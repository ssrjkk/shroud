// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ReentrancyGuard (transient storage, Solidity >=0.8.24)
/// @dev Hand-rolled instead of OZ so the package compiles without external deps.
///      Uses TSTORE/TLOAD (EIP-1153), available on the fhEVM L3 and on Cancun+.
abstract contract ReentrancyGuard {
    error Reentrancy();

    bytes32 private constant _NOT_ENTERED = bytes32(uint256(1));
    bytes32 private constant _ENTERED = bytes32(uint256(2));

    bytes32 private _reentrancyState = _NOT_ENTERED;

    modifier nonReentrant() {
        if (_reentrancyState == _ENTERED) revert Reentrancy();
        _reentrancyState = _ENTERED;
        _;
        _reentrancyState = _NOT_ENTERED;
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
