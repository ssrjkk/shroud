// SPDX-License-Identifier: ERC-20
pragma solidity ^0.8.24;

import {IERC20} from "../interfaces/IERC20.sol";

/// @notice Minimal, correctly-behaved ERC-20 for tests. Deliberately *not* a "returns nothing"
///         token: `PaymentVault` is written to tolerate both standards, and that tolerance is
///         covered by `NoReturnTokenMock` instead.
contract TestToken is IERC20 {
    string public name = "Shroud USD";
    string public symbol = "SHD";
    uint8 public immutable decimals = 6;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    error InsufficientBalance(address from, uint256 balance, uint256 needed);
    error InsufficientAllowance(address owner, address spender, uint256 allowed, uint256 needed);

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _move(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            if (allowed < value) revert InsufficientAllowance(from, msg.sender, allowed, value);
            unchecked {
                allowance[from][msg.sender] = allowed - value;
            }
        }
        _move(from, to, value);
        return true;
    }

    function _move(address from, address to, uint256 value) private {
        uint256 balance = balanceOf[from];
        if (balance < value) revert InsufficientBalance(from, balance, value);
        unchecked {
            balanceOf[from] = balance - value;
        }
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }
}

/// @notice A token that takes a cut on every transfer: the recipient receives less than
///         the sender asked for, and the difference never reaches anyone.
/// @dev Fee-on-transfer tokens are the classic way to break escrow accounting. A contract
///      that records the *requested* amount has silently under-collateralised the task:
///      the ledger says the task holds the budget while the vault holds less, and the
///      shortfall is discovered when a payout cannot be made. `PaymentVault` and
///      `BondLib` ledger the balance diff that actually arrived and fail closed instead,
///      and this mock is what proves they do.
contract FeeOnTransferTokenMock is IERC20 {
    string public name = "Fee USD";
    string public symbol = "FEE";
    uint8 public immutable decimals = 6;

    address public owner;

    /// The cut, in basis points: 100 = 1% of every transfer.
    uint256 public feeBps;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    error InsufficientBalance(address from, uint256 balance, uint256 needed);
    error InsufficientAllowance(address owner, address spender, uint256 allowed, uint256 needed);
    error NotOwner(address caller);

    constructor(uint256 feeBps_) {
        owner = msg.sender;
        feeBps = feeBps_;
    }

    /// @notice Turn the cut on or off. Owner-only.
    /// @dev The escrow and the registration bond live in the same task, and the escrow
    ///      fails closed at creation - so with the cut already on, the task can never
    ///      exist and the bond path is unreachable. Switching the fee lets a test reach
    ///      both paths: create the task with no cut, then turn it on and pull a bond.
    function setFeeBps(uint256 feeBps_) external {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        feeBps = feeBps_;
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _move(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            if (allowed < value) revert InsufficientAllowance(from, msg.sender, allowed, value);
            unchecked {
                allowance[from][msg.sender] = allowed - value;
            }
        }
        _move(from, to, value);
        return true;
    }

    /// Move `value` and burn the cut: the recipient is credited with less than the
    /// sender's balance fell by.
    function _move(address from, address to, uint256 value) private {
        uint256 balance = balanceOf[from];
        if (balance < value) revert InsufficientBalance(from, balance, value);
        uint256 fee = (value * feeBps) / 10_000;
        uint256 received = value - fee;
        unchecked {
            balanceOf[from] = balance - value;
        }
        balanceOf[to] += received;
        totalSupply -= fee;
        emit Transfer(from, to, received);
    }
}

/// @notice USDT-style token: `transfer`/`transferFrom` return no data, and balances still move.
///         `PaymentVault._pull`/`_push` are written for exactly this case, so this mock is the
///         regression test for the `ret.length != 0` guards.
contract NoReturnTokenMock is IERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    function name() external pure returns (string memory) {
        return "NoReturn USDT";
    }

    function symbol() external pure returns (string memory) {
        return "USDT";
    }

    function decimals() external pure returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        return true;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _move(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= value, "allowance");
            unchecked {
                allowance[from][msg.sender] = allowed - value;
            }
        }
        _move(from, to, value);
        return true;
    }

    function _move(address from, address to, uint256 value) private {
        uint256 balance = balanceOf[from];
        require(balance >= value, "balance");
        unchecked {
            balanceOf[from] = balance - value;
        }
        balanceOf[to] += value;
    }
}
