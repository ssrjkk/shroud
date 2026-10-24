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
        /// @dev Per-row surcharge: rows are self-declared (H2), so a flat bond prices a
        ///      100k-row lie the same as an honest 1k-row shard. perRow*rows makes large
        ///      claims expensive to lie about. Zero (default) = flat only, backward compat.
        mapping(uint256 => uint128) perRow;
        /// @dev Secure weight mode (H2 full close): when true, weight ignores claimed rows
        ///      (`effectiveRows = 1`, liveness only). Default false = legacy rows weight.
        mapping(uint256 => bool) weightByBond;
        /// @dev Bonds posted, keyed by task then contributor.
        mapping(uint256 => mapping(address => uint128)) posted;
    }

    // Redeclared from the host (delegatecall logs from the host's address).
    event ContributionBondRequirementSet(uint256 indexed taskId, uint128 amount);
    event ContributionBondReleased(uint256 indexed taskId, address indexed contributor, uint128 amount);
    event ContributionBondSlashed(uint256 indexed taskId, address indexed contributor, uint128 amount);

    uint128 private constant _MAX_BOND = 1_000_000_000;
    uint128 private constant _MAX_PER_ROW = 10_000;

    /// @notice Set flat bond requirement (external so the host stays small).
    function setFlat(
        State storage s,
        ICipherTask.Task storage t,
        uint256 taskId,
        address caller,
        uint128 amount
    ) external {
        if (t.status == ICipherTask.TaskStatus.None) revert ICipherTask.UnknownTask(taskId);
        if (caller != t.params.buyer && caller != t.params.updateManager) {
            revert ICipherTask.NotUpdateManagerOrOwner(taskId, caller);
        }
        if (t.status != ICipherTask.TaskStatus.Opening) {
            revert ICipherTask.InvalidTaskStatus(taskId, t.status, ICipherTask.TaskStatus.Opening);
        }
        if (amount > _MAX_BOND) revert ICipherTask.BondRequirementInvalid(taskId, amount);
        s.required[taskId] = amount;
        emit ContributionBondRequirementSet(taskId, amount);
    }

    /// @notice Set per-row surcharge (external so the host stays small).
    function setPerRow(
        State storage s,
        ICipherTask.Task storage t,
        uint256 taskId,
        address caller,
        uint128 amount
    ) external {
        if (t.status == ICipherTask.TaskStatus.None) revert ICipherTask.UnknownTask(taskId);
        if (caller != t.params.buyer && caller != t.params.updateManager) {
            revert ICipherTask.NotUpdateManagerOrOwner(taskId, caller);
        }
        if (t.status != ICipherTask.TaskStatus.Opening) {
            revert ICipherTask.InvalidTaskStatus(taskId, t.status, ICipherTask.TaskStatus.Opening);
        }
        if (amount > _MAX_PER_ROW) revert ICipherTask.BondRequirementInvalid(taskId, amount);
        s.perRow[taskId] = amount;
        emit ContributionBondRequirementSet(taskId, amount);
    }

    /// @notice Enable/disable secure weight mode (external so the host stays small).
    /// @dev H2 full close opt-in: weight ignores claimed rows (effectiveRows = 1).
    function setWeightMode(
        State storage s,
        ICipherTask.Task storage t,
        uint256 taskId,
        address caller,
        bool byBond
    ) external {
        if (t.status == ICipherTask.TaskStatus.None) revert ICipherTask.UnknownTask(taskId);
        if (caller != t.params.buyer && caller != t.params.updateManager) {
            revert ICipherTask.NotUpdateManagerOrOwner(taskId, caller);
        }
        if (t.status != ICipherTask.TaskStatus.Opening) {
            revert ICipherTask.InvalidTaskStatus(taskId, t.status, ICipherTask.TaskStatus.Opening);
        }
        s.weightByBond[taskId] = byBond;
        emit ContributionBondRequirementSet(taskId, byBond ? uint128(1) : uint128(0));
    }

    /// @notice Pull the required bond (if any) from `from`. Fail-closed on fee-on-transfer
    ///         tokens: a shortfall reverts instead of recording a bond never posted.
    /// @dev Total = flat + perRow*rows (H2: self-declared rows must cost to claim).
    function pull(State storage s, IERC20 token, uint256 taskId, address from, uint32 rows) external {
        uint128 req = s.required[taskId];
        uint128 pr = s.perRow[taskId];
        if (pr != 0 && rows != 0) {
            req = req + uint128(uint256(pr) * uint256(rows));
        }
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
    /// @dev The slashed weight leaves the settlement denominator with the share: without
    ///      this, a slashed Sybil's weight would keep diluting honest contributors while its
    ///      forfeited share pooled into dust for the highest-address contributor — an
    ///      address the attacker picks — letting a slashed weight earn through the back
    ///      door. Decrementing here keeps honest payouts exactly pro-rata with dust
    ///      reduced to rounding. Underflow is impossible: weight is added once at
    ///      submission and this branch runs at most once per contribution (the bond is
    ///      zeroed, so a second slash reverts before reaching it), and only for
    ///      accepted contributions whose weight was actually added.
    function slash(
        State storage s,
        mapping(uint256 => mapping(address => ICipherTask.Contribution)) storage contributions,
        mapping(uint256 => uint256) storage totalWeight,
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
            totalWeight[taskId] -= contributions[taskId][contributor].weightQ16;
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
