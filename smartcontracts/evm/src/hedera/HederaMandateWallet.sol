// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MandateWallet} from "../wallet/MandateWallet.sol";

/// @title `MandateWallet` on Hedera (NET-HED-03).
/// @notice `IS_HEDERA` is set: on the native branch of every entry a 64-byte signature from an address without code (a
///         native ED25519 account) is checked by HIP-632 `isAuthorizedRaw` over the entry's digest, on the same lanes
///         (CTR-TOK-23's rule for tokens, through `UAMetaTxBase`); every other signature takes the EVM path. An ED25519
///         owner pays by hand through `mtxExecute`: `isValidSignature` (ERC-1271, under STATICCALL where HIP-632 halts)
///         stays ECDSA, so a payment with `from = wallet` works for ECDSA owners only.
contract HederaMandateWallet is MandateWallet {
    constructor(bytes32 owner_, bytes32 chainUid_, address registry_) MandateWallet(owner_, chainUid_, registry_, true) {}
}
