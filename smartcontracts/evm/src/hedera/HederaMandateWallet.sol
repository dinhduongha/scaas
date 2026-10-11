// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MandateWallet} from "../wallet/MandateWallet.sol";
import {HederaAccountAuth} from "./HederaAccountAuth.sol";
import {SigCheck} from "../common/SigCheck.sol";

/// @title `MandateWallet` on Hedera (NET-HED-03).
/// @notice A 64-byte signature from an address without code (a native ED25519 account) is checked by HIP-632
///         `isAuthorizedRaw` over the same `MetaTransaction` digest, on the same lane nonces (CTR-TOK-23's rule for
///         tokens); every other signature takes the EVM path. So an ED25519 owner signs its owner calls
///         (`mtxExecuteAsOwnerRaw`, the spec's name for them, or `mtxExecuteAsOwner` / `mtxExecute`), and an owner
///         call `execute(token, payWithFee…)` is how it pays by hand: `isValidSignature` (ERC-1271, under STATICCALL
///         where HIP-632 halts) stays ECDSA, so a meta-transaction with `from = wallet` works for ECDSA owners only.
contract HederaMandateWallet is MandateWallet {
    constructor(address owner_, bytes32 chainUid_) MandateWallet(owner_, chainUid_) {}

    /// @notice `mtxExecuteAsOwner` under its Hedera name: the owner's `MetaTransaction` on lane 0, any signature kind.
    function mtxExecuteAsOwnerRaw(bytes calldata data, uint256 nonce, uint256 validUntil, bytes calldata sig)
        external nonReentrant returns (bytes memory)
    {
        return _named(owner, data, 0, nonce, validUntil, sig);
    }

    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view override {
        if (sig.length == 64 && !SigCheck.isContract(from)) {
            if (!HederaAccountAuth.asView()(from, digest, sig)) revert MetaTxBadSignature();
            return;
        }
        super._requireValidSignature(from, digest, sig);
    }
}
