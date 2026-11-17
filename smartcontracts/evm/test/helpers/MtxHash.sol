// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {MtxPipelineLib} from "../../src/metatx/MtxPipelineLib.sol";

/// The EIP-712 struct hashes a test reproduces, through the copy every contract uses (`MtxPipelineLib._structHash`), not a
/// second copy of the byte rule (Fable B P3-3: `MetaTxLib.hashStruct` moved to legacy/ua-mtx-fix-contracts/).
library MtxHash {
    function hashStruct(MetaTxLib.MetaTransaction memory m) internal pure returns (bytes32) {
        return MtxPipelineLib._structHash(MetaTxLib.METATX_TYPEHASH, MtxPipelineLib.Envelope(MetaTxLib.pad(m.from),
            keccak256(m.data), m.batch, m.nonce, m.validUntil, m.mode, m.relayer, m.fee, m.feeRecipient));
    }

    function hashStruct(MetaTxLib.UAMetaTransaction memory m) internal pure returns (bytes32) {
        return MtxPipelineLib._structHash(MetaTxLib.UAMETATX_TYPEHASH, MtxPipelineLib.Envelope(m.from, keccak256(m.data),
            m.batch, m.nonce, m.validUntil, m.mode, m.relayer, m.fee, m.feeRecipient));
    }

    function hashStruct(MetaTxLib.UAMetaTransfer memory t) internal pure returns (bytes32) {
        return MtxPipelineLib._structHash(t);
    }
}
