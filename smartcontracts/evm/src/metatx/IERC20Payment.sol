// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {IERC20MetaTx} from "./IERC20MetaTx.sol";
import {FeeMode} from "../common/FeePolicy.sol";

/// @title Payments on a SCaaS token (metatx.md, Interfaces; CTR-MTX-01).
interface IERC20Payment is IERC20MetaTx {
    event PaymentSettled(address indexed from, address indexed to, uint256 amount, uint256 feeAmount,
                         address feeRecipient, bytes32 indexed entryRef);

    /// @notice `msg.sender` pays `amount` to `to`, the fee on top (CTR-MTX-08: never to the payee).
    function payWithFee(address to, uint256 amount, FeeMode feeMode, uint256 fee, address feeRecipient,
                        bytes32 entryRef) external returns (bool);
}
