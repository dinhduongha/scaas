// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";

/// @title The meta-transaction surface of every SCaaS token: `ERC20MetaTx` (metatx.md, Interfaces).
interface IERC20MetaTx is IERC20, IMetaTx {
    error MetaTxInsufficientForFee(uint256 needed, uint256 available);
    error PayToZero();
    error TransferToSelf();
    error FeeRecipientIsPayee();
    error SpenderNotContract(address spender);   // allowance rule (CTR-TOK-01)
    error CallerNotContract(address caller);     // allowance rule (CTR-TOK-01)

    function mtxTransferDigest(MetaTxLib.MetaTransfer calldata t) external view returns (bytes32);
    function mtxExecuteTransfer(MetaTxLib.MetaTransfer calldata t, bytes calldata signature) external returns (bool);
    function mtxBatchTransfer(MetaTxLib.MetaTransfer[] calldata ts, bytes[] calldata signatures)
        external returns (bool);
}
