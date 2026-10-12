// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {NoUnderlyingToken} from "../metatx/NoUnderlyingToken.sol";
import {SingleUnderlyingToken} from "../metatx/SingleUnderlyingToken.sol";
import {MultiUnderlyingToken} from "../metatx/MultiUnderlyingToken.sol";
import {HederaSig, HederaHts} from "./HederaV2Lib.sol";

/// @title Ba tầng v2 trên Hedera (HSCS, TW2 §11, R144): thừa kế toàn bộ tầng EVM, thêm HIP-632.
/// @notice Không SubjectAccount trên Hedera ⇒ `SUBJECT_ACCOUNT_IMPL = 0`: mọi ví hợp đồng giữ trần 50k cho ERC-1271.
///         Tầng wrapper kiểm mọi underlying lúc `initialize`, fail-closed (`HederaHts`), và associate từng chân HTS:
///         không có hàm `associateUnderlying` — một token mà chân không associate được thì không bao giờ ra đời.
///         Domain, ABI, event là của EVM.
contract HederaNoUnderlyingToken is NoUnderlyingToken {
    constructor(address factory_) NoUnderlyingToken(factory_, address(0)) {}

    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view override {
        if (sig.length == 64 && !_isContract(from)) return HederaSig.requireValid(from, digest, sig);
        super._requireValidSignature(from, digest, sig);
    }
}

contract HederaSingleUnderlyingToken is SingleUnderlyingToken {
    constructor(address factory_) SingleUnderlyingToken(factory_, address(0)) {}

    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view override {
        if (sig.length == 64 && !_isContract(from)) return HederaSig.requireValid(from, digest, sig);
        super._requireValidSignature(from, digest, sig);
    }

    function _checkUnderlying(address u) internal override {
        super._checkUnderlying(u);
        if (!HederaHts.checkAndAssociate(u)) revert UnderlyingInvalid(u);
    }
}

contract HederaMultiUnderlyingToken is MultiUnderlyingToken {
    constructor(address factory_) MultiUnderlyingToken(factory_, address(0)) {}

    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view override {
        if (sig.length == 64 && !_isContract(from)) return HederaSig.requireValid(from, digest, sig);
        super._requireValidSignature(from, digest, sig);
    }

    function _checkUnderlying(address u) internal override {
        super._checkUnderlying(u);
        if (!HederaHts.checkAndAssociate(u)) revert UnderlyingInvalid(u);
    }
}
