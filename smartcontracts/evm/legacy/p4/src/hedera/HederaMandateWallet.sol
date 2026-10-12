// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

import {MandateWallet} from "../wallet/MandateWallet.sol";
import {HederaAccountAuth} from "./HederaAccountAuth.sol";

/// @title MandateWallet trên Hedera — R25 + R63.
/// @notice Delegate vẫn là khoá custody secp256k1 của platform (ECDSA, không đổi). Owner là tài khoản Hedera
///         khoá ED25519 thì `executeAsOwner` (ECDSA) không dùng được; `executeAsOwnerRaw` kiểm owner qua
///         HIP-632 trên CÙNG digest `OwnerCall` và CÙNG `ownerNonce` — hai đường không replay chéo được.
contract HederaMandateWallet is MandateWallet {
    constructor(address owner_) MandateWallet(owner_) {}

    function executeAsOwnerRaw(bytes calldata data, uint256 nonce, uint256 validUntil, bytes calldata sig)
        external returns (bytes memory)
    {
        if (block.timestamp > validUntil) revert SignatureExpired();
        if (nonce != ownerNonce) revert BadNonce();
        if (!HederaAccountAuth.isAuthorizedRaw(owner, ownerCallDigest(data, nonce, validUntil), sig)) {
            revert BadSignature();
        }
        ownerNonce = nonce + 1;
        (bool ok, bytes memory ret) = address(this).call(data);
        if (!ok) revert CallFailed(ret);
        return ret;
    }
}
