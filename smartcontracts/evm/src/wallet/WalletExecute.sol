// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxAddressBase} from "../metatx/MetaTxAddressBase.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {MtxPipelineLib} from "../metatx/MtxPipelineLib.sol";

/// @title The named `Execute` entry of `SmartKeyAccount` (TS-D14; the mandate wallets' is `UAExecute` on
///        `UAMetaTxBase` since ua-mtx-merge T3b, Q6).
/// @dev `Execute` is the one wallet op with a dynamic argument: its struct hashes `data`, its self-call carries it, so it
///      cannot take `MetaTxBase._named`, whose `args` are both. It runs the same pipeline, `_run`, over its own struct.
abstract contract WalletExecute is MetaTxAddressBase {
    bytes32 private constant _EXECUTE_TYPEHASH = keccak256(
        "Execute(address from,address target,uint256 value,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes4 private constant _EXECUTE = bytes4(keccak256("execute(address,uint256,bytes)"));

    constructor(string memory domainName, bytes32 chainUid_) MetaTxAddressBase(domainName, chainUid_) {}

    function _namedExecute(MetaTxLib.Envelope calldata e, address target, uint256 value, bytes calldata data, bytes calldata sig)
        internal returns (bytes memory)
    {
        MetaTxLib.MetaTransaction memory m = _metaOf(e, abi.encodeWithSelector(_EXECUTE, target, value, data));
        return _run(m, _hashTypedDataV4(MtxPipelineLib._namedHash(
            _EXECUTE_TYPEHASH, _envelopeOf(m, 0), abi.encode(target, value, keccak256(data)))), sig);
    }
}
