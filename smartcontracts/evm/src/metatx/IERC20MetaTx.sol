// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title The meta-transaction surface of every SCaaS token: `ERC20MetaTx` (metatx.md, Interfaces).
interface IERC20MetaTx is IERC20, IMetaTx {
    error MetaTxInsufficientForFee(uint256 needed, uint256 available);
    error PayToZero();
    error TransferToSelf();
    error FeeRecipientIsPayee();
    error SpenderNotContract(address spender);   // allowance rule (CTR-TOK-01)
    error CallerNotContract(address caller);     // allowance rule (CTR-TOK-01)
    // Raised only inside `MtxPipelineLib` (metatx split R4), declared here so every kind's ABI decodes them.
    error ModeFeeInvalid(uint32 mode);                     // MetaTxLib.feeModeOf
    error SigCheckGasStarved(uint256 cap, uint256 gasLeft); // SigCheck: ERC-1271 cap not forwarded

    // The typed path on ids (ua-mtx-merge T2, R4, R28): one form for a native id (an address zero-padded, signing with
    // its own key, no registry needed) and a derived UA (through the registry). Here, not in `IUALedger`: they run
    // with the ledger off for native ids (C, R9). The address `MetaTransfer` forms are in legacy/ua-mtx-merge/.
    function mtxTransferDigest(MetaTxLib.UAMetaTransfer calldata t) external view returns (bytes32);
    function mtxExecuteTransfer(MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata auth)
        external returns (bool);
    function mtxBatchTransfer(MetaTxLib.UAMetaTransfer[] calldata ts, IUARegistry.UASig[] calldata auths)
        external returns (bool);
    /// @notice The relay-fee payment (CTR-MTX-27, TS-D19; pay-meta-tax spec §4): `from` signed `UARelayFee{…, batch,
    ///         nonce, validUntil, relayer}` under `metatx`, `relayer` read as `msg.sender`. Pays `value` to `payee` on the
    ///         payer's lane `(from, batch)` at `nonce`, fee `NONE`, `ref` = `RelayFeeRouter.relayRef`.
    function mtxRelayFee(bytes32 from, address target, bytes32 callDataHash, bytes32 payee, uint256 value, uint256 batch,
        uint256 nonce, uint256 validUntil, IUARegistry.UASig calldata auth) external;
}
