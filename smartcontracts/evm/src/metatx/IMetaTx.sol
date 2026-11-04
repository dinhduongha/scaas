// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxLib} from "../common/MetaTxLib.sol";

/// @title The meta-transaction core of every SCaaS contract on `MetaTxBase` (metatx.md, Interfaces; ua-mtx-merge MD-1): the
///        wallets add the address entries (`IMetaTxAddress`), tokens and the router the `bytes32` ones (`UAMetaTxBase`).
interface IMetaTx {
    event MetaTransactionExecuted(address indexed from, address indexed relayer, uint256 indexed batch,
                                  uint256 nonce, bytes32 digest, address feeRecipient, uint256 fee);
    event MetaNonceCancelled(address indexed from, uint256 indexed batch, uint256 newNonce);

    error MetaTxExpired(uint256 validUntil, uint256 nowTs);
    error MetaTxBadNonce(uint256 expected, uint256 got);
    error MetaTxBadSignature();
    error MetaTxUnauthorizedRelayer(address allowed, address caller);
    error MetaTxUnknownMode(uint32 mode);
    error MtxSelectorNotAllowed(bytes4 selector);
    error MtxDataShape(bytes4 selector);
    error MtxFeeClass(bytes4 selector, uint32 mode);
    error Reentrancy();
    error SelfSender();
    error MtxBatchEmpty();
    /// @notice The selector may not run inside `mtxBatch` (the PQZ ops, CTR-PQZ-21).
    error MtxNotBatchable(bytes4 selector);
    error MtxBatchLengthMismatch();

    function executeMetaTransaction(MetaTxLib.MetaTransaction calldata m, bytes calldata signature)
        external returns (bool success);
    function mtxSelectors()
        external view returns (bytes4[] memory selectors, uint8[] memory feeClass, uint8[] memory amountArg);
    function chainUid() external view returns (bytes32);
    function supportedModes() external view returns (uint32);   // 0xF3 on tokens, 0x03 elsewhere
    function cancelNonce(uint256 batch) external;
}
