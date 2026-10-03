// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {MetaToken} from "../metatx/MetaToken.sol";
import {HederaAccountAuth} from "./HederaAccountAuth.sol";

/// @title MetaToken trên Hedera (HSCS) — R63.
/// @notice Giống hệt `MetaToken` (cùng domain EIP-712, cùng chín bước), thêm hai điều riêng Hedera:
///         1. Tài khoản Hedera khoá ED25519 (`from` = địa chỉ long-zero `0.0.N`) ký digest EIP-712 bằng ed25519;
///            chữ ký 64 byte từ địa chỉ KHÔNG có code đi qua HIP-632 — precompile đọc khoá của tài khoản trong
///            state Hedera, nên khoá công khai client gửi không bao giờ là căn cứ (R6-2).
///         2. Wrapper tầng 2 trên token HTS phải associate token đó trước khi nhận (R6-5).
///         64 byte không mơ hồ: OZ 5.2 `ECDSA.tryRecover(bytes)` chỉ nhận 65 byte, nên một chữ ký compact
///         EIP-2098 chưa bao giờ hợp lệ trong hệ, và ở đây nó tới precompile — nơi tài khoản ECDSA bị từ chối.
contract HederaMetaToken is MetaToken {
    address internal constant HTS = address(0x167);
    int64 internal constant HTS_SUCCESS = 22;
    int64 internal constant HTS_ALREADY_ASSOCIATED = 194; // TOKEN_ALREADY_ASSOCIATED_TO_ACCOUNT

    error AssociateFailed(int64 responseCode);

    constructor(address factory_) MetaToken(factory_) {}

    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view override {
        if (sig.length == 64 && !_isContract(from)) {
            if (!HederaAccountAuth.isAuthorizedRaw(from, digest, sig)) revert MetaTxBadSignature();
            return;
        }
        super._requireValidSignature(from, digest, sig);
    }

    /// @notice Không cần quyền, gọi lại bao nhiêu lần cũng được: chỉ cho phép contract này NHẬN `underlying`.
    function associateUnderlying() external {
        address u = underlying;
        if (u == address(0)) revert NotAWrapper();
        (bool ok, bytes memory ret) =
            HTS.call(abi.encodeWithSignature("associateToken(address,address)", address(this), u));
        int64 rc = ok && ret.length == 32 ? int64(int256(uint256(bytes32(ret)))) : int64(-1);
        if (rc != HTS_SUCCESS && rc != HTS_ALREADY_ASSOCIATED) revert AssociateFailed(rc);
    }
}
