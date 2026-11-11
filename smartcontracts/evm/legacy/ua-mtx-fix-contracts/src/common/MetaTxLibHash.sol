// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

// Backup, not built (Fable review B P3-3, branch ua-mtx-fix-contracts): the four functions of `src/common/MetaTxLib.sol`
// that no contract called. Every contract hashes through `MtxPipelineLib._structHash` / `_namedHash` and checks the mode in
// `MtxPipelineLib._checkEnvelope`; two copies of one byte rule drift apart silently. As they stood in `library MetaTxLib`, names qualified.

import {MetaTxLib} from "../../../../src/common/MetaTxLib.sol";

library MetaTxLibHash {
    function hashStruct(MetaTxLib.MetaTransaction memory m) internal pure returns (bytes32) {
        (address r, address f) = MetaTxLib.canon(m);
        return keccak256(abi.encode(
            MetaTxLib.METATX_TYPEHASH, m.from, keccak256(m.data), m.batch, m.nonce, m.validUntil, m.mode, r, m.fee, f
        ));
    }

    function hashStruct(MetaTxLib.UAMetaTransaction memory m) internal pure returns (bytes32) {
        address r = (m.mode & MetaTxLib.MODE_RESTRICT_RELAYER) != 0 ? m.relayer : address(0);
        address f = (m.mode & MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT) != 0 ? m.feeRecipient : address(0);
        return keccak256(abi.encode(
            MetaTxLib.UAMETATX_TYPEHASH, m.from, keccak256(m.data), m.batch, m.nonce, m.validUntil, m.mode, r, m.fee, f
        ));
    }

    function hashStruct(MetaTxLib.UAMetaTransfer memory t) internal pure returns (bytes32) {
        address r = (t.mode & MetaTxLib.MODE_RESTRICT_RELAYER) != 0 ? t.relayer : address(0);
        address f = (t.mode & MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT) != 0 ? t.feeRecipient : address(0);
        return keccak256(abi.encode(
            MetaTxLib.UAMETATRANSFER_TYPEHASH, t.from, t.to, t.value, t.entryRef, t.batch, t.nonce, t.validUntil, t.mode, r, t.fee, f
        ));
    }

    /// @notice Từ chối mọi bit không hiểu. Gọi ở bước 3 của §04.6.1, TRƯỚC verify chữ ký.
    /// @dev Hai kiểm tra khác nhau, vì hai nửa byte có bản chất khác nhau:
    ///      nửa đầu là cờ nên chỉ cần bit lạ = 0; nửa sau là giá trị liệt kê nên
    ///      `0x30`–`0xF0` là bit hợp lệ nhưng giá trị vô nghĩa, và phải revert.
    ///      Chấp nhận bit/giá trị không hiểu nghĩa là khoá chết ngữ nghĩa tương lai.
    function validateMode(uint32 mode) internal pure {
        if (mode & ~MetaTxLib.MODE_KNOWN_MASK != 0) revert MetaTxLib.ModeUnknownBits(mode);
        MetaTxLib.feeModeOf(mode);  // revert ModeFeeInvalid nếu nửa byte sau > 2
    }
}
