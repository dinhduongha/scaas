// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {SingleUnderlyingToken} from "../metatx/SingleUnderlyingToken.sol";
import {MultiUnderlyingToken} from "../metatx/MultiUnderlyingToken.sol";
import {HederaLib} from "./HederaLib.sol";

/// @title Transitional Hedera wrapper tiers (CTR-TOK-23): `IS_HEDERA = true` gives them HIP-632 signatures from
///        `MetaTokenBase`; what is left here is the fail-closed HTS check and association of every leg at init
///        (`HederaLib.checkAndAssociate`), which moves into `UnderlyingLib` with `UnderlyingToken` in P1d. Kind `NONE`
///        on Hedera is a `NoUnderlyingToken` deployed with `isHedera_ = true`. No SmartKeyAccount on Hedera:
///        `SMART_KEY_ACCOUNT_IMPL = 0`, every contract wallet keeps the 50k ERC-1271 cap.
contract HederaSingleUnderlyingToken is SingleUnderlyingToken {
    constructor(address factory_, bytes32 chainUid_) SingleUnderlyingToken(factory_, address(0), chainUid_, true) {}

    function _checkUnderlying(address u) internal override {
        super._checkUnderlying(u);
        if (!HederaLib.checkAndAssociate(u)) revert UnderlyingInvalid(u);
    }
}

contract HederaMultiUnderlyingToken is MultiUnderlyingToken {
    constructor(address factory_, bytes32 chainUid_) MultiUnderlyingToken(factory_, address(0), chainUid_, true) {}

    function _checkUnderlying(address u) internal override {
        super._checkUnderlying(u);
        if (!HederaLib.checkAndAssociate(u)) revert UnderlyingInvalid(u);
    }
}
