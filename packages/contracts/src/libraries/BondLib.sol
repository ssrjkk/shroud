// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICipherTask} from "../interfaces/ICipherTask.sol";
import {IERC20} from "../interfaces/IERC20.sol";

/// @title BondLib
/// @notice Opt-in per-contributor anti-spam bonds for `CipherTask` (threat model F-01).
///
/// @dev External library on purpose (see `DisputeLib`/`SettlementLib`): every byte here would
///      otherwise sit in the host past the 24,576-byte deployment limit. Runs by DELEGATECALL
///      as the host.
///
///      Design notes, because money custody invites misreading:
///      - Bonds are contributor money, never task escrow: they are held by the host contract
///        directly, outside the vault's sub-balance accounting (a bond swept into a buyer
///        refund would pay the buyer with the contributor's money — the same reason node
///        bonds live outside sub-balances in the vault).
///      - Slashes go to the treasury, never to the buyer: the buyer must gain nothing from
///        slashing, or slashing becomes a revenue stream over every contributor.
///      - Slashing also marks the contribution slashed, so `settle` skips its reward share —
///        fraud forfeits both the bond and the payout.
///      - The requirement is settable only while the window is open and capped, so a malicious
///        buyer cannot censor the window shut with a prohibitive bond after shards landed.
library BondLib {
    /// @notice Bond state. Owned by the host, passed by pointer.
    struct State {
        /// @dev Per-task bond required of new contributions. Zero (default) = none.
        mapping(uint256 => uint128) required;
        /// @dev Bonds posted, keyed by task then contributor.
        mapping(uint256 => mapping(address => uint128)) posted;
    }

    // Redeclared from the host (delegatecall logs from the host's address).
    event ContributionBondRequirementSet(uint256 indexed taskId, uint128 amount);
    event ContributionBondReleased(uint256 indexed taskId, address indexed contributor, uint128 amount);
    event ContributionBondSlashed(uint256 indexed taskId, address indexed contributor, uint128 amount);

    /// @notice Pull the required bond (if any) from `from`. Fail-closed on fee-on-transfer
    ///         tokens: a shortfall reverts instead of recording a bond never posted.
    function pull(State storage s, IERC20 token, uint256 taskId, address from) external {
        uint128 req = s.required[taskId];
        if (req == 0) return;
        uint256 before = token.balanceOf(address(this));
        (bool ok, bytes memory ret) =
            address(token).call(abi.encodeCall(IERC20.transferFrom, (from, address(this), req)));
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) {
            revert ICipherTask.BondInsufficient(taskId, from, req);
        }
        if (token.balanceOf(address(this)) - before != req) {
            revert ICipherTask.BondInsufficient(taskId, from, req);
        }
        s.posted[taskId][from] = req;
    }

    /// @notice Release a contributor's bond to them. The host decides releasability (terminal
    ///         or fully settled) and passes it in; the money can only go to the contributor.
    function release(State storage s, IERC20 token, uint256 taskId, address contributor, bool releasable) external {
        uint128 bond = s.posted[taskId][contributor];
        if (bond == 0) revert ICipherTask.NoBondToRelease(taskId, contributor);
        if (!releasable) revert ICipherTask.BondNotReleasable(taskId, contributor);
        s.posted[taskId][contributor] = 0;
        (bool ok, bytes memory ret) = address(token).call(abi.encodeCall(IERC20.transfer, (contributor, bond)));
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) {
            revert ICipherTask.TransferFailed(address(token), contributor, bond);
        }
        emit ContributionBondReleased(taskId, contributor, bond);
    }

    /// @notice Slash a contributor's bond to `treasury` and mark the contribution slashed.
    function slash(
        State storage s,
        mapping(uint256 => mapping(address => ICipherTask.Contribution)) storage contributions,
        IERC20 token,
        address treasury,
        uint256 taskId,
        address contributor
    ) external {
        uint128 bond = s.posted[taskId][contributor];
        if (bond == 0) revert ICipherTask.NoBondToRelease(taskId, contributor);
        s.posted[taskId][contributor] = 0;
        if (contributions[taskId][contributor].accepted) {
            contributions[taskId][contributor].slashed = true;
        }
        (bool ok, bytes memory ret) = address(token).call(abi.encodeCall(IERC20.transfer, (treasury, bond)));
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) {
            revert ICipherTask.TransferFailed(address(token), treasury, bond);
        }
        emit ContributionBondSlashed(taskId, contributor, bond);
    }
}

/// @title PopLib
/// @notice Proof-of-possession check for node BLS keys (external so the host stays small).
/// @dev `sig` must be a 65-byte EIP-191 personal-message ECDSA signature by `node` over
///      `keccak256(abi.encode(taskId, blsPubKey, node, chainId, host))`. BLS keys are otherwise
///      self-declared: uniqueness only stops lazy reuse. Binding the BLS key to the node's EOA
///      proves one live signer per identity and makes key-theft repudiation impossible.
library PopLib {
    // secp256k1 `n`-half: reject malleable `s` (same bound `PaymentVault` uses, F-14).
    bytes32 private constant _UPPER_S =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    function verify(
        uint256 taskId,
        bytes32 blsPubKey,
        address node,
        uint256 chainId,
        address host,
        bytes calldata sig
    ) external pure {
        if (sig.length != 65) revert ICipherTask.InvalidPopSignature(taskId, node);
        bytes32 inner = keccak256(abi.encode(taskId, blsPubKey, node, chainId, host));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 0x20))
            v := byte(0, calldataload(add(sig.offset, 0x40)))
        }
        if (v != 27 && v != 28) revert ICipherTask.InvalidPopSignature(taskId, node);
        if (s > _UPPER_S) revert ICipherTask.InvalidPopSignature(taskId, node);
        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0) || recovered != node) revert ICipherTask.InvalidPopSignature(taskId, node);
    }
}
