// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../src/payments/PaymentVault.sol";
import "../../src/mocks/TestToken.sol";

/// Fuzzed driver for the vault-accounting invariants. Every function here is a
/// manager- or owner-side operation forge may call in any order with any arguments; the
/// bounds keep inputs inside the valid domain (a reverting handler call fails
/// the run, so out-of-domain inputs are skipped, not sent).
contract VaultHandler is Test {
    PaymentVault public vault;
    TestToken public token;

    uint256 public keyNonce;

    /// Calls that completed without reverting, per operation. `afterInvariant`
    /// asserts every operation ran at least once: a green run that never posted
    /// a bond (or never swept) proves nothing about that path, and raw revert
    /// counts cannot tell a dead path from a healthy one.
    uint256 public fundsPosted;
    uint256 public bondsPosted;
    uint256 public topUpsPosted;
    uint256 public channelsOpened;
    uint256 public sweepsRun;
    uint256 public creditsPosted;
    uint256 public claimsMade;
    uint256 public warpsDone;
    uint256 public redeemsDone;
    uint256 public reclaimsDone;
    uint256 public closesDone;
    uint256 public straysDone;
    uint256 public rescuesDone;

    /// Every channel this handler opened (it is the streamer of all of them, so
    /// `closeChannel` works on any entry, unlike redeem/reclaim which need the
    /// earner).
    uint256[] public allIds;

    /// Tokens minted straight to the vault, bypassing `fundTask`: the only money
    /// the accounting does not know about, and exactly what `rescueStrayTokens`
    /// must return. `invariant_strayAccounts` pins the identity.
    uint256 public strayOwed;

    /// Slice indices per channel, so every redeem moves strictly forward.
    mapping(uint256 => uint64) public nextSlice;

    /// The newest channel this handler earns from. Picks by lottery almost never
    /// land on an open handler-owned channel once the array fills with closed
    /// ones, so redeem/reclaim drive this slot instead of rolling dice.
    uint256 public lastHandlerChannel;
    bool public hasHandlerChannel;

    /// Set while the handler presents a slice to `redeem`: the EIP-1271 hook
    /// below answers the vault's staticcall, so only a slice the handler is
    /// actively redeeming ever validates — never a standing approval.
    bool internal _authNow;

    constructor(PaymentVault _vault, TestToken _token) {
        vault = _vault;
        token = _token;
    }

    /// Accept the vault's ownership (two-step handover, called once from setUp).
    /// Guarded: any later fuzz call finds nothing pending and skips instead of
    /// reverting the run.
    function acceptVaultOwnership() external {
        if (vault.pendingOwner() != address(this)) return;
        vault.acceptOwnership();
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
        fundsPosted++;
    }

    /// Post a registration bond for this handler on a task. The handler bonds
    /// *itself*: no `deal`, no `prank` — mint, approve and post all happen as one
    /// identity, so there is no cross-identity plumbing that can silently fail
    /// and brick the whole bond path (which is exactly what happened with a
    /// `deal` + `prank` setup: every post reverted and the fuzzer never touched
    /// bonds while reporting green).
    function bond(uint256 taskSeed) external {
        uint256 taskId = _task(taskSeed);
        _bondSelf(taskId);
        bondsPosted++;
    }

    function _bondSelf(uint256 taskId) internal {
        if (vault.nodeBond(taskId, address(this)) != 0) return;
        bytes32 key = keccak256(abi.encode("shroud-test-key", keyNonce++));
        token.mint(address(this), vault.REGISTRATION_BOND());
        token.approve(address(vault), vault.REGISTRATION_BOND());
        vault.takeBond(taskId, address(this), key);
    }

    /// Top up this handler's own bond. Same identity throughout, like `bond`.
    function topUp(uint256 taskSeed, uint128 amount) external {
        uint256 taskId = _task(taskSeed);
        _bondSelf(taskId);
        amount = uint128(bound(amount, 1, 1_000_000));
        token.mint(address(this), amount);
        token.approve(address(vault), amount);
        vault.topUpNodeBond(taskId, amount);
        topUpsPosted++;
    }

    /// EIP-1271 for the vault's streamer check: this handler *is* the streamer of
    /// the channels it opens, and it authorises exactly the slice it is redeeming.
    /// Signature content is intentionally unchecked — authorization, not
    /// cryptography, is what the accounting invariants exercise (auth itself is
    /// pinned by the Hardhat EIP-712 suite).
    function isValidSignature(bytes32, bytes calldata) external view returns (bytes4) {
        return _authNow ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }

    /// Open a reward channel as task manager, capped by what the task actually holds
    /// (opening past the balance reverts, and a reverting handler call fails the run).
    function open(uint256 taskSeed, uint256 nodeSeed, uint256 lock, uint64 window) external {
        uint256 taskId = _task(taskSeed);
        uint256 balance = vault.taskBalance(taskId);
        if (balance == 0) return;
        uint256 cap = balance > type(uint128).max ? uint256(type(uint128).max) : balance;
        lock = bound(lock, 1, cap);
        // `unlockAt` is absolute, not a duration: passing the window raw would
        // mature every channel at birth (1970) and the sweep would close it before
        // any redeem could run — the exact dead path this harness must not have.
        uint64 unlockAt = uint64(block.timestamp) + uint64(bound(window, 1, 7 days));
        // Every third channel names this handler as the earner so `reclaim` has
        // something to close; the rest go to arbitrary nodes like production's.
        address node = nodeSeed % 3 == 0 ? address(this) : _node(nodeSeed);
        vault.openTaskChannel(taskId, node, uint128(lock), unlockAt);
        uint256[] memory ids = vault.channelIds(taskId);
        uint256 id = ids[ids.length - 1];
        allIds.push(id);
        if (node == address(this)) {
            lastHandlerChannel = id;
            hasHandlerChannel = true;
        }
        channelsOpened++;
    }

    /// Sweep matured locks back to the sub-balance.
    function sweep(uint256 taskSeed) external {
        vault.sweepTaskChannels(_task(taskSeed));
        sweepsRun++;
    }

    /// Close any open channel as its streamer. Unlike sweep/reclaim this needs no
    /// maturity: the streamer may pull its own lock back at any time.
    function closeChannel(uint256 channelSeed) external {
        if (allIds.length == 0) return;
        uint256 id = allIds[bound(channelSeed, 0, allIds.length - 1)];
        if (vault.channelInfo(id).closed) return;
        vault.closeChannel(id);
        closesDone++;
    }

    /// Mint tokens straight to the vault, bypassing every ledger entry.
    function stray(uint256 amount) external {
        amount = bound(amount, 1, 1_000_000);
        token.mint(address(vault), amount);
        strayOwed += amount;
        straysDone++;
    }

    /// Rescue exactly the stray — no more (escrow is untouchable), no less
    /// (dust must not accumulate). The equality is the test: `rescueStrayTokens`
    /// computes `balance - owed` independently of this handler's bookkeeping.
    function rescue() external {
        if (strayOwed == 0) return;
        uint256 got = vault.rescueStrayTokens();
        assertEq(got, strayOwed);
        strayOwed = 0;
        rescuesDone++;
    }

    /// Redeem the next slice of this handler's newest channel. Slice indices must
    /// strictly increase and the amount is cumulative, so the handler tracks both
    /// per channel and only ever moves forward — a reverted redeem is a harness
    /// bug, not fuzz noise.
    function redeem(uint256 amount, uint64 inDays) external {
        if (!hasHandlerChannel) return;
        uint256 id = lastHandlerChannel;
        PaymentVault.Channel memory ch = vault.channelInfo(id);
        if (ch.closed) return;
        amount = bound(amount, 1, ch.maxCumulative);
        uint64 slice = nextSlice[id];
        nextSlice[id] = slice + 1;
        uint256 deadline = block.timestamp + bound(inDays, 1, 30 days);
        _authNow = true;
        vault.redeem(id, slice, uint128(amount), deadline, hex"00");
        _authNow = false;
        redeemsDone++;
    }

    /// Deterministic reclaim: open for this handler, mature past its own window,
    /// reclaim — all in one call. The organic `reclaim` above depends on winning
    /// a race with `sweep`/`closeChannel` after a warp, which the fuzzer wins
    /// too rarely to assert on; this proves the path while the fuzzer still
    /// interleaves the organic one.
    function openMatureReclaim(uint256 taskSeed, uint256 lock, uint64 window) external {
        uint256 taskId = _task(taskSeed);
        uint256 balance = vault.taskBalance(taskId);
        if (balance == 0) {
            uint256 fund = bound(lock, 1, 1_000_000_000_000);
            token.mint(address(this), fund);
            token.approve(address(vault), fund);
            vault.fundTask(taskId, fund, address(this));
            fundsPosted++;
            balance = vault.taskBalance(taskId);
        }
        lock = bound(lock, 1, balance > type(uint128).max ? uint256(type(uint128).max) : balance);
        window = uint64(bound(window, 1, 7 days));
        vault.openTaskChannel(taskId, address(this), uint128(lock), uint64(block.timestamp) + window);
        uint256[] memory ids = vault.channelIds(taskId);
        uint256 id = ids[ids.length - 1];
        channelsOpened++;
        lastHandlerChannel = id;
        hasHandlerChannel = true;
        vm.warp(uint64(block.timestamp) + window + 1);
        warpsDone++;
        vault.reclaim(id);
        reclaimsDone++;
    }

    /// Reclaim this handler's newest channel once matured. Closed or immature
    /// channels are skipped, not forced: warp drives maturity on its own schedule.
    function reclaim() external {
        if (!hasHandlerChannel) return;
        uint256 id = lastHandlerChannel;
        PaymentVault.Channel memory ch = vault.channelInfo(id);
        if (ch.closed) return;
        if (block.timestamp < ch.unlockAt) return;
        vault.reclaim(id);
        reclaimsDone++;
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
        creditsPosted++;
    }

    /// Claim whatever this handler was credited (skips when there is nothing: `claim`
    /// reverts on zero, and an empty claim is not a counterexample).
    function claimSelf() external {
        if (vault.pendingWithdrawal(address(this)) == 0) return;
        vault.claim();
        claimsMade++;
    }

    /// Move time forward so channels mature (bounded: the all-immature case must also
    /// be hit, and the fuzzer gets there on its own).
    function warp(uint64 dt) external {
        vm.warp(block.timestamp + bound(dt, 0, 30 days));
        warpsDone++;
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
        // The handler also owns the vault so `rescue` is reachable; acceptance
        // runs through the handler's guarded entry point, exactly once.
        vault.transferOwnership(address(handler));
        handler.acceptVaultOwnership();
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

    /// Stray accounting: the only money outside the books is what `stray` minted
    /// and `rescue` has not yet taken back.
    function invariant_strayAccounts() external view {
        uint256 bal = token.balanceOf(address(vault));
        uint256 owed = vault.totalLocked() + vault.pendingTotal();
        assertGe(bal, owed);
        assertEq(bal - owed, handler.strayOwed());
    }

    /// Coverage proof: every handler operation completed at least once across the
    /// campaign. A green run that never posted a bond would prove nothing about the
    /// bond paths; this fails loudly instead of letting that pass silently.
    function afterInvariant() external view {
        assertGt(handler.fundsPosted(), 0, "fund never ran");
        assertGt(handler.bondsPosted(), 0, "bond never ran");
        assertGt(handler.topUpsPosted(), 0, "topUp never ran");
        assertGt(handler.channelsOpened(), 0, "open never ran");
        assertGt(handler.sweepsRun(), 0, "sweep never ran");
        assertGt(handler.creditsPosted(), 0, "credit never ran");
        assertGt(handler.claimsMade(), 0, "claim never ran");
        assertGt(handler.warpsDone(), 0, "warp never ran");
        assertGt(handler.redeemsDone(), 0, "redeem never ran");
        assertGt(handler.reclaimsDone(), 0, "reclaim never ran");
        assertGt(handler.closesDone(), 0, "closeChannel never ran");
        assertGt(handler.straysDone(), 0, "stray never ran");
        assertGt(handler.rescuesDone(), 0, "rescue never ran");
    }
}
