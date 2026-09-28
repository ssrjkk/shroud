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
