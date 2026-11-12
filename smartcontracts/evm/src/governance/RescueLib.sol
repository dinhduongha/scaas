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

    /// @notice CTR-GOV-25 (owner 2026-11-12): the destination when a stored `rescueTo` is 0, the same on every chain: the
    ///         `RescueVault` (first owner the dev EOA `0x0389f77E846ff687d44db57bcC9DCB55dd6f4131`) at its CREATE2 address
    ///         through `0x4e59b44847b379578588920ca78fbf26c0b4956c`, salt `keccak256("scaas.rescue-vault.v1")`
    ///         (`test/governance/RescueVault.t.sol` `test_addressIsTheConstant`).
    address internal constant SCAAS_DEV_RESCUE = 0xc564b98ad818d5C870f4B2058C95435259D126cf;

    /// @notice The effective destination: `stored`, or `SCAAS_DEV_RESCUE` for 0.
    function to(address stored) internal pure returns (address) {
        return stored == address(0) ? SCAAS_DEV_RESCUE : stored;
    }

    /// @notice The whole balance of `asset` (`address(0)`: the native coin) to `dest`, `IRescuable.Rescued`.
    function all(address asset, address dest) internal {
        uint256 amount = asset == address(0) ? address(this).balance : IERC20(asset).balanceOf(address(this));
        send(asset, dest, amount);
        emit IRescuable.Rescued(asset, dest, amount);
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
