// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title `DexPuller` (CTR-DEX-22): the only holder of user allowances for outside tokens. Deployed by its DEX's
///        `initialize` (a clone has no constructor, CTR-DEX-24); only that DEX may call `pull`, which moves exactly
///        `amount` from `from` to the DEX.
/// @notice Holders of an outside token approve the puller, never the DEX: an exchange-path interaction runs as the DEX,
///         so an allowance held by the DEX could be spent by a crafted `transferFrom`.
contract DexPuller {
    using SafeERC20 for IERC20;

    address public immutable dex;

    error NotDex(address caller);

    constructor() {
        dex = msg.sender;
    }

    function pull(address token, address from, uint256 amount) external {
        if (msg.sender != dex) revert NotDex(msg.sender);
        IERC20(token).safeTransferFrom(from, dex, amount);
    }
}
