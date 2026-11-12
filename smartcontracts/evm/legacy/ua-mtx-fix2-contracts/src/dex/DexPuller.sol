// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {TokenCall} from "./TokenCall.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title `DexPuller` (CTR-DEX-22): the only holder of user allowances for outside tokens. Deployed by its DEX's
///        `initialize` (a clone has no constructor, CTR-DEX-24); only that DEX may call `pull`, which moves exactly
///        `amount` from `from` to the DEX.
/// @notice Holders of an outside token approve the puller, never the DEX: an exchange-path interaction runs as the DEX,
///         so an allowance held by the DEX could be spent by a crafted `transferFrom`.
contract DexPuller {
    using SafeERC20 for IERC20;

    address public immutable dex;
    /// @notice `DexConfig.rescueTo` (spec §6.2, CTR-GOV-06): immutable; 0 = no rescue.
    address public immutable rescueTo;

    event Rescued(address indexed asset, address indexed to, uint256 amount);

    error NotDex(address caller);
    error RescueOff();

    constructor(address rescueTo_) {
        dex = msg.sender;
        rescueTo = rescueTo_;
    }

    /// @notice Anyone: the puller's whole balance of `token` to `rescueTo`. It holds no user's funds, only allowances, and
    ///         calls only `balanceOf` and `transfer`, so no allowance is spent (R-16).
    function rescue(address token) external {
        address to = rescueTo;
        if (to == address(0)) revert RescueOff();
        uint256 amount = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransfer(to, amount);
        emit Rescued(token, to, amount);
    }

    function pull(address token, address from, uint256 amount) external {
        if (msg.sender != dex) revert NotDex(msg.sender);
        // the token's own revert data never reaches the DEX (W-O: it could forge a starvation error); no data (out of
        // gas) stays empty, the node's `out_of_gas` (as `SCaaSDex._tokenFailed`)
        if (!TokenCall.ok(token, abi.encodeCall(IERC20.transferFrom, (from, dex, amount)))) {
            assembly ("memory-safe") {
                if iszero(returndatasize()) { revert(0, 0) }
            }
            revert SafeERC20.SafeERC20FailedOperation(token);
        }
    }
}
