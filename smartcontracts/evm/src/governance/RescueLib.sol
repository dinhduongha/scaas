// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {IRescuable} from "./IRescuable.sol";

/// @title The rescue destination and send (CTR-GOV-06, CTR-GOV-25): one constant, one send, shared by every contract
///        that takes a `rescue`.
library RescueLib {
    using SafeERC20 for IERC20;

    /// @notice CTR-GOV-25 (owner 2026-11-12): the destination when a stored `rescueTo` is 0. A plain EOA, the same on
    ///         every chain.
    address internal constant SCAAS_DEV_RESCUE = 0x0389f77E846ff687d44db57bcC9DCB55dd6f4131;

    /// @notice The effective destination: `stored`, or `SCAAS_DEV_RESCUE` for 0.
    function to(address stored) internal pure returns (address) {
        return stored == address(0) ? SCAAS_DEV_RESCUE : stored;
    }

    /// @dev The native coin (`address(0)`) by value, refused to a designator as `WrappedLib.payOut` refuses it; an ERC-20
    ///      by `safeTransfer`.
    function send(address asset, address dest, uint256 amount) internal {
        if (asset == address(0)) {
            if (SigCheck.isDesignator(dest)) revert IRescuable.RescueAssetInvalid(asset);
            Address.sendValue(payable(dest), amount);
        } else {
            IERC20(asset).safeTransfer(dest, amount);
        }
    }
}
