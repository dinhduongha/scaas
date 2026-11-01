// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxBase} from "../metatx/MetaTxBase.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {MtxPipelineLib} from "../metatx/MtxPipelineLib.sol";

/// @title The named `Execute` entry of `MandateWallet` and `SmartKeyAccount` (TS-D14).
/// @dev `Execute` is the one wallet op with a dynamic argument: its struct hashes `data`, its self-call carries it, so it
///      cannot take `MetaTxBase._named`, whose `args` are both. This is the steps of CTR-MTX-17 over the struct `Execute`, the
///      base's own step functions in the base's order.
abstract contract WalletExecute is MetaTxBase {
    bytes32 private constant _EXECUTE_TYPEHASH = keccak256(
        "Execute(address from,address target,uint256 value,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes4 private constant _EXECUTE = bytes4(keccak256("execute(address,uint256,bytes)"));

    constructor(string memory domainName, bytes32 chainUid_) MetaTxBase(domainName, chainUid_) {}

    function _namedExecute(MetaTxLib.Envelope calldata e, address target, uint256 value, bytes calldata data, bytes calldata sig)
        internal returns (bytes memory)
    {
        MetaTxLib.MetaTransaction memory m = _metaOf(e, abi.encodeWithSelector(_EXECUTE, target, value, data));
        return _steps(m, _hashTypedDataV4(MtxPipelineLib._namedHash(
            _EXECUTE_TYPEHASH, _envelopeOf(m, 0), abi.encode(target, value, keccak256(data)))), sig);
    }

    // ponytail: `MetaTxBase._run`'s order written again, `_run` is private there; goes when the base takes a dynamic named op.
    function _steps(MetaTxLib.MetaTransaction memory m, bytes32 digest, bytes calldata sig) private returns (bytes memory ret) {
        _checkEnvelope(MetaTxLib.pad(m.from), m.batch, m.nonce, m.validUntil, m.mode, m.relayer); // 1
        _requireValidSignature(m.from, digest, sig);                                  // 2
        uint256 basis = _checkCall(m.data, m.mode);                                   // 3
        _useNonce(MetaTxLib.pad(m.from), m.batch);                                    // 4
        ret = _selfCall(MetaTxLib.pad(m.from), m.data, _envelopeBinding(m));          // 5
        uint256 fee = _chargeFee(m.from, basis, m);                                   // 6
        emit MetaTransactionExecuted(m.from, msg.sender, m.batch, m.nonce, digest, _feeRecipientOf(m), fee); // 7
    }
}
