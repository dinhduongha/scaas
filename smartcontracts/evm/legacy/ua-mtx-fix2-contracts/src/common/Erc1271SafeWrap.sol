// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

// Backup, not built (Fable review B P3-2, branch ua-mtx-fix2-contracts, commit be8d0772): the Safe-style one-level ERC-1271
// wrap of `SmartKeyAccount` and `MandateWallet`, superseded by ERC-7739 (owner 2026-11-12: "only ERC-7739, back the Safe
// wrap up to legacy"; a wallet shows only `hash: 0x…` for this wrap, ERC-7739 keeps the app's fields readable). As it
// stood: the typehash in `library MetaTxLib`, the view and the `isValidSignature` body in each wallet.

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

library Erc1271SafeWrap {
    /// was `MetaTxLib.ERC1271_MESSAGE_TYPEHASH` (0xff8bbe299de1266e571c68af5b71b4e716412184ca1bd495927110f9581950cb)
    bytes32 internal constant ERC1271_MESSAGE_TYPEHASH = keccak256("ERC1271Message(bytes32 hash)");

    /// was `SmartKeyAccount.erc1271Digest` / `MandateWallet.erc1271Digest` (public views):
    /// `_hashTypedDataV4(keccak256(abi.encode(ERC1271_MESSAGE_TYPEHASH, hash)))` in the wallet's own salted domain.
    function erc1271Digest(bytes32 walletSeparator, bytes32 hash) internal pure returns (bytes32 d) {
        bytes32 sh = keccak256(abi.encode(ERC1271_MESSAGE_TYPEHASH, hash));
        d = keccak256(abi.encodePacked(hex"1901", walletSeparator, sh));
    }

    /// was `SmartKeyAccount.isValidSignature`: `_isValid(erc1271Digest(hash), signature) ? 0x1626ba7e : 0xffffffff`.
    /// was `MandateWallet.isValidSignature` (native owner): ECDSA by the owner's address over `erc1271Digest(hash)`.
    function mandateOwnerValid(bytes32 walletSeparator, address owner, bytes32 hash, bytes memory sig)
        internal pure returns (bool)
    {
        (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(erc1271Digest(walletSeparator, hash), sig);
        return err == ECDSA.RecoverError.NoError && rec == owner;
    }
}
