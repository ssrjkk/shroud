// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../src/payments/PaymentVault.sol";
import "../../src/mocks/TestToken.sol";

/// Fuzzed driver for the vault-accounting invariants. Every function here is a
/// manager-side operation forge may call in any order with any arguments; the
/// bounds keep inputs inside the valid domain (a reverting handler call fails
/// the run, so out-of-domain inputs are skipped, not sent).
contract VaultHandler is Test {
    PaymentVault public vault;
    TestToken public token;

    uint256 public keyNonce;
    bytes32[] public bondedKeys;
    mapping(bytes32 => bool) public bonded;

    struct BondRef {
        uint256 taskId;
        address node;
    }

    mapping(bytes32 => BondRef) public bondRefs;

    constructor(PaymentVault _vault, TestToken _token) {
        vault = _vault;
        token = _token;
    }

    function _task(uint256 seed) internal pure returns (uint256) {
        return bound(seed, 0, 2);
    }

    function _node(uint256 seed) internal pure returns (address) {
        return address(uint160(bound(seed, 1, 10)));
    }

    /// Fund a task sub-balance from this handler (mints first: the token is a test mock).
    function fund(uint256 taskSeed, uint256 amount) external {
        uint256 taskId = _task(taskSeed);
        amount = bound(amount, 1, 1_000_000_000_000);
        token.mint(address(this), amount);
        token.approve(address(vault), amount);
        vault.fundTask(taskId, amount, address(this));
    }

    /// Post a registration bond for a node (fresh BLS key every time: keys are
    /// single-use per task). Funded through the node itself, exactly like production.
    function bond(uint256 taskSeed, uint256 nodeSeed) external {
        uint256 taskId = _task(taskSeed);
        address node = _node(nodeSeed);
        bytes32 key = keccak256(abi.encode("shroud-test-key", keyNonce++));
        deal(address(token), node, vault.REGISTRATION_BOND());
        vm.startPrank(node);
        token.approve(address(vault), vault.REGISTRATION_BOND());
        vault.takeBond(taskId, node, key);
        vm.stopPrank();
        bytes32 id = keccak256(abi.encode(taskId, node));
        if (!bonded[id]) {
            bonded[id] = true;
            bondedKeys.push(id);
            bondRefs[id] = BondRef(taskId, node);
        }
    }

    /// Top up a bond this handler previously posted. Only the bond owner may top up
    /// their own position, so the whole call happens as the node.
    function topUp(uint256 keySeed, uint128 amount) external {
        if (bondedKeys.length == 0) return;
        bytes32 id = bondedKeys[bound(keySeed, 0, bondedKeys.length - 1)];
        BondRef storage ref = bondRefs[id];
        amount = uint128(bound(amount, 1, 1_000_000));
        deal(address(token), ref.node, amount);
        vm.startPrank(ref.node);
        token.approve(address(vault), amount);
        vault.topUpNodeBond(ref.taskId, amount);
        vm.stopPrank();
    }

    /// Open a reward channel as task manager, capped by what the task actually holds
    /// (opening past the balance reverts, and a reverting handler call fails the run).
    function open(uint256 taskSeed, uint256 nodeSeed, uint256 lock, uint64 window) external {
        uint256 taskId = _task(taskSeed);
        uint256 balance = vault.taskBalance(taskId);
        if (balance == 0) return;
        uint256 cap = balance > type(uint128).max ? uint256(type(uint128).max) : balance;
        lock = bound(lock, 1, cap);
        window = uint64(bound(window, 1, 7 days));
        vault.openTaskChannel(taskId, _node(nodeSeed), uint128(lock), window);
    }

    /// Sweep matured locks back to the sub-balance.
    function sweep(uint256 taskSeed) external {
        vault.sweepTaskChannels(_task(taskSeed));
    }

    /// Credit a share out of a task sub-balance (to this handler, who can claim it,
    /// or to a stranger, whose pending piles up exactly like unclaimed rewards do).
    function credit(uint256 taskSeed, uint256 toSeed, uint256 amount) external {
        uint256 taskId = _task(taskSeed);
        uint256 balance = vault.taskBalance(taskId);
        if (balance == 0) return;
        uint256 cap = balance > type(uint128).max ? uint256(type(uint128).max) : balance;
        amount = bound(amount, 1, cap);
        address to = toSeed % 2 == 0 ? address(this) : _node(toSeed);
        vault.creditFromTask(taskId, to, uint128(amount));
    }

    /// Claim whatever this handler was credited (skips when there is nothing: `claim`
    /// reverts on zero, and an empty claim is not a counterexample).
    function claimSelf() external {
        if (vault.pendingWithdrawal(address(this)) == 0) return;
        vault.claim();
    }

    /// Move time forward so channels mature (bounded: the all-immature case must also
    /// be hit, and the fuzzer gets there on its own).
    function warp(uint64 dt) external {
        vm.warp(block.timestamp + bound(dt, 0, 30 days));
    }
}

/// Stateful vault-accounting invariants.
///
/// Hardhat pins lifecycle *behavior* (open → redeem → sweep → settle pays out); this
/// fuzzes *interleavings* of the manager-side operations with fresh random sequences on
/// every run. Two properties, both exact:
///  1. `totalLocked == accountedLocked`: the vault's own bookkeeping identity.
///  2. Solvency: the token balance covers everything the vault owes (`totalLocked`
///     plus credited-but-unclaimed `pendingTotal`). No sequence of manager calls may
///     strand escrow or conjure claims beyond the backing tokens.
contract VaultInvariants is Test {
    VaultHandler public handler;
    PaymentVault public vault;
    TestToken public token;

    function setUp() external {
        token = new TestToken();
        vault = new PaymentVault(address(token));
        handler = new VaultHandler(vault, token);
        vault.setTaskManager(address(handler));
        targetContract(address(handler));
    }

    /// The vault's bookkeeping identity holds after every fuzzed sequence.
    function invariant_accounting() external view {
        assertEq(vault.totalLocked(), vault.accountedLocked());
    }

    /// The vault always holds at least what it owes.
    function invariant_solvency() external view {
        assertGe(token.balanceOf(address(vault)), vault.totalLocked() + vault.pendingTotal());
    }
}
