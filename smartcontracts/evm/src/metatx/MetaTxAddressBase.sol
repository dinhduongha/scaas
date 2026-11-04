// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxBase} from "./MetaTxBase.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {IMetaTxAddress} from "./IMetaTxAddress.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {MtxPipelineLib} from "./MtxPipelineLib.sol";

/// @title The address generic path of `MetaTxBase` (ua-mtx-merge MD-1, R26): inherited by `WalletExecute` only, so
///        `SmartKeyAccount` keeps `mtxNonce`, `mtxDigest`, `mtxExecute`, `mtxBatch` and `mtxCancelNonce` with `address
///        from`. The bodies are `MetaTxBase`'s as they stood at `ref/pre-ua-mtx-merge`, unchanged. Tokens and the router
///        have the `bytes32` set (`UAMetaTxBase`) and keep only `executeMetaTransaction` of this path (R3); the mandate
///        wallets (T3b, Q6) have the `bytes32` set and refuse `executeMetaTransaction`.
abstract contract MetaTxAddressBase is MetaTxBase, IMetaTxAddress {
    bytes32 private constant _CANCEL_NONCE_TYPEHASH = keccak256(
        "CancelNonce(address from,uint256 lane,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );

    constructor(string memory domainName, bytes32 chainUid_) MetaTxBase(domainName, chainUid_) {}

    function mtxNonce(address from, uint256 batch) public view returns (uint256) {
        return _nonce(MetaTxLib.pad(from), batch);
    }

    function mtxDigest(MetaTxLib.MetaTransaction calldata m) external view virtual returns (bytes32) {
        return _hashTypedDataV4(MtxPipelineLib._structHash(MetaTxLib.METATX_TYPEHASH, _envelopeOf(m)));
    }

    function mtxExecute(MetaTxLib.MetaTransaction calldata m, bytes calldata signature)
        external nonReentrant returns (bytes memory)
    {
        return _execute(m, signature);
    }

    /// @notice Atomic: items run in order, each with a fresh ticket; any failure reverts all (CTR-MTX-11).
    function mtxBatch(MetaTxLib.MetaTransaction[] calldata ms, bytes[] calldata signatures)
        external nonReentrant returns (bool)
    {
        uint256 n = ms.length;
        if (n == 0) revert MtxBatchEmpty();
        if (n != signatures.length) revert MtxBatchLengthMismatch();
        for (uint256 i; i < n; ++i) {
            _requireBatchable(bytes4(ms[i].data));
            _execute(ms[i], signatures[i]);
        }
        return true;
    }

    /// @notice The signed `cancelNonce(lane)` (TS-D14): `lane` is cancelled, `e.batch` is the lane of the cancel itself.
    function mtxCancelNonce(MetaTxLib.Envelope calldata e, uint256 lane, bytes calldata sig)
        external nonReentrant returns (bytes memory)
    {
        return _named(_CANCEL_NONCE_TYPEHASH, IMetaTx.cancelNonce.selector, e, abi.encode(lane), sig);
    }
}
