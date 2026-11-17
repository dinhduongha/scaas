// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title The UA ledger of every SCaaS token (accounts.md CTR-UA-18, CTR-UA-19, CTR-UA-26): balances of derived UAs by
///        `bytes32` id, shown to ERC-20 observers as the one holder `UA_POOL`, and the `ua*` meta-transactions whose
///        `from` (and `to`) is a native id (address zero-padded) or a registered SIGNING UA.
/// @notice Reported by ERC-165 only while `registry()` is not 0 (a derived side then reverts `UALedgerOff`). The generic
///         signed entries on ids (`mtxExecute`, `mtxBatch`, `mtxCancelNonce`, `UAMetaTxBase`), their views
///         (`IUALedgerViews`) and the typed path (`mtxExecuteTransfer`, `mtxBatchTransfer`, `mtxTransferDigest`,
///         `mtxRelayFee`, `IERC20MetaTx`) are not here: they run for a native id with no registry (ua-mtx-merge C, R9).
interface IUALedger {
    /// @notice Every movement with a derived side (a burn under a UA has `to = 0`).
    event UATransfer(bytes32 indexed from, bytes32 indexed to, uint256 value);
    /// @notice Per executed `UAMetaTransaction` / `UAMetaTransfer`; `digest` is the mesh `intent_id`.
    event UAMetaTransactionExecuted(bytes32 indexed from, address indexed relayer, uint256 indexed batch, uint256 nonce,
                                    bytes32 digest, address feeRecipient, uint256 fee);
    /// @notice A `UAMetaTransfer` with `entryRef ≠ 0` (the UA ledger's `PaymentSettled`).
    event UAPaymentSettled(bytes32 indexed from, bytes32 indexed to, uint256 amount, uint256 feeAmount,
                           address feeRecipient, bytes32 indexed entryRef);
    event UANonceCancelled(bytes32 indexed ua, uint256 indexed batch, uint256 newNonce);

    error UALedgerOff();
    error UARegistryChainUid(bytes32 registryUid, bytes32 tokenUid);
    error UAPoolNotPayable();
    /// @notice D19 (CTR-ZTH-51): `SHIELD_POOL` is neither a payee nor a spender; only a shielding layer moves it.
    error ShieldPoolNotPayable();
    error UANotRegistered(bytes32 ua);
    error UAKindNotAccepted(bytes32 ua, uint16 kind);
    error UAInsufficientBalance(bytes32 ua, uint256 balance, uint256 needed);
    /// @notice The unordered `uaCancelNonce` only (legacy/ua-mtx-merge/); no built entry reverts with it.
    error UACancelUsed();
    error MetaTxUnknownOp(bytes4 selector);
    /// @notice A leg or receive token that is not a SCaaS token with its UA ledger on (accounts.md CTR-UA-27); on
    ///         `mtxWrapOrder`, also a leg with no `mtxTrade` for any holder.
    error UALegNotLedger(address token);

    function registry() external view returns (address);
    function balanceOfUA(bytes32 ua) external view returns (uint256);

    function transferToUA(bytes32 to, uint256 amount) external returns (bool);
}
