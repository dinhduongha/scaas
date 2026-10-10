// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20MetaTxV1} from "../metatx/IERC20MetaTxV1.sol";
import {HederaAccountAuth} from "./HederaAccountAuth.sol";

/// @title Chữ ký HIP-632 cho mọi tầng v2 trên Hedera (R63, R144) — như `HederaMetaToken` v1.
/// @notice Chữ ký 64 byte từ một địa chỉ KHÔNG có code (tài khoản Hedera khoá ED25519, `0.0.N`) đi qua
///         `isAuthorizedRaw`: precompile đọc khoá của tài khoản trong state Hedera, khoá client gửi không bao giờ là
///         căn cứ. Mọi thứ khác (EOA ECDSA 65 byte, ERC-1271) đi đường EVM của `MetaTxCore`.
///         Thư viện, không phải mixin `is MetaTxCore`: mixin đó tạo một kim cương với tầng (Single/Multi đều
///         `is MetaTxCore`) và bắt mỗi con ghi đè lại bảy hàm chỉ để chọn bên; ở đây mỗi con ghi đè đúng một hàm.
library HederaSig {
    function requireValid(address from, bytes32 digest, bytes calldata sig) internal view {
        if (!HederaAccountAuth.asView()(from, digest, sig)) revert IERC20MetaTxV1.MetaTxBadSignature();
    }
}

/// @title Kiểm underlying HTS lúc init, FAIL-CLOSED (TW2 §11, review M5).
/// @notice 1. `isToken(u)` ≠ SUCCESS ⇒ `HtsQueryFailed`. 2. Nếu là HTS: `getTokenCustomFees(u)` ≠ SUCCESS hoặc không
///         giải mã được ⇒ `HtsQueryFailed`; có bất kỳ phí fixed/fractional/royalty nào ⇒ người gọi từ chối
///         (`UnderlyingInvalid`). 3. Nếu là HTS: `associateToken(this, u)` ≠ SUCCESS/ALREADY ⇒ `AssociateFailed`.
///         Precompile vắng mặt (lời gọi "thành công" với returndata rỗng) cũng là `HtsQueryFailed(u, -1)`.
///         Một fee-schedule key vẫn thêm được phí về sau: không chặn on-chain, ví và wizard cảnh báo (§6.6).
library HederaHts {
    address internal constant HTS = address(0x167);
    int64 internal constant SUCCESS = 22;
    int64 internal constant ALREADY_ASSOCIATED = 194; // TOKEN_ALREADY_ASSOCIATED_TO_ACCOUNT

    error HtsQueryFailed(address u, int64 responseCode);
    error AssociateFailed(int64 responseCode);

    /// @return feeFree `false` nếu `u` là token HTS có custom fee.
    function checkAndAssociate(address u) internal returns (bool feeFree) {
        bytes memory ret = _query(u, abi.encodeWithSignature("isToken(address)", u), 64);
        if (_word(ret, 32) == 0) return true; // ERC-20 thường trên EVM của Hedera: không phí HTS, không associate
        ret = _query(u, abi.encodeWithSignature("getTokenCustomFees(address)", u), 128);
        // (int64, FixedFee[], FractionalFee[], RoyaltyFee[]): mỗi độ dài mảng phải nằm trong returndata.
        for (uint256 i = 1; i <= 3; ++i) {
            uint256 off = _word(ret, 32 * i);
            if (off > ret.length || ret.length - off < 32) revert HtsQueryFailed(u, SUCCESS);
            if (_word(ret, off) != 0) return false;
        }
        (bool ok, bytes memory r) =
            HTS.call(abi.encodeWithSignature("associateToken(address,address)", address(this), u));
        int64 rc = ok && r.length == 32 ? _rc(r) : int64(-1);
        if (rc != SUCCESS && rc != ALREADY_ASSOCIATED) revert AssociateFailed(rc);
        return true;
    }

    /// @dev Gọi HTS; `rc ≠ SUCCESS` (kể cả không trả lời: `-1`) hoặc returndata ngắn hơn `minLen` ⇒ `HtsQueryFailed`.
    function _query(address u, bytes memory call, uint256 minLen) private returns (bytes memory ret) {
        bool ok;
        (ok, ret) = HTS.call(call);
        int64 rc = ok && ret.length >= 32 ? _rc(ret) : int64(-1);
        if (rc != SUCCESS || ret.length < minLen) revert HtsQueryFailed(u, rc);
    }

    function _rc(bytes memory ret) private pure returns (int64) {
        return int64(int256(_word(ret, 0)));
    }

    function _word(bytes memory b, uint256 off) private pure returns (uint256 w) {
        assembly ("memory-safe") { w := mload(add(add(b, 32), off)) }
    }
}
