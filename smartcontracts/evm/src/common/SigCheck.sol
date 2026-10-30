// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/// @title The one signature check of every SCaaS contract (CTR-MTX-25).
/// @notice EOA ⇒ OpenZeppelin `ECDSA.tryRecover` (65 bytes, low-s, CTR-MTX-14). Contract ⇒ ERC-1271
///         `isValidSignature` by `staticcall` with a per-signer gas cap (50 000 by default; 400 000 only for
///         `SmartKeyAccount` clones, CTR-ACC-05), at most 32 bytes of returndata read, and the EIP-150 rule of
///         CTR-DEX-08: the caller must hold `cap·64/63 + GAS_MARGIN` gas, so a relayer cannot starve the call to
///         turn a valid signature into an invalid one. An EIP-7702 delegated EOA (code exactly `0xef0100‖address`)
///         is an EOA (accounts.md CTR-UA-24, owner ruling 2026-10-30, superseding 2026-10-28): ECDSA by its own key
///         only, never ERC-1271 (its delegate's code never authorises), and never an authorised direct caller
///         (`requireNotDelegated`, `CallerDelegated`).
/// @dev HIP-632 hook (P1c, CTR-TOK-23): `isValid` gains a `bool hedera` argument (the implementation's
///      `IS_HEDERA`); when it is set, `sig.length == 64` and `signer` has no code, the answer is HIP-632
///      `isAuthorizedRaw(signer, digest, sig)` (built: `HederaAccountAuth.asView()`; moved into `HederaLib` in
///      P1c) and nothing below runs. Every other signature on Hedera takes the EVM path unchanged. P1a has no
///      Hedera path: the built Hedera children keep their `_requireValidSignature` overrides until P1b/P1c.
library SigCheck {
    uint256 internal constant ERC1271_GAS = 50_000;
    uint256 internal constant GAS_MARGIN = 5_000;

    /// @notice The caller holds too little gas to give an ERC-1271 wallet its cap (EIP-150, CTR-DEX-08).
    error SigCheckGasStarved(uint256 cap, uint256 gasLeft);
    /// @notice An EIP-7702 delegated EOA called directly where the caller is authority: its delegate's code is running
    ///         as the EOA, and an EOA must not run code (owner ruling 2026-10-30). Use a relayed, key-signed `mtx*`
    ///         (fee may be 0) or clear the delegation.
    error CallerDelegated(address caller);

    /// @notice Code exactly `0xef0100 ‖ address` (23 bytes): an EIP-7702 delegation designator (EIP-3541: no deployed
    ///         contract starts with `0xef`). Never true on Hedera today (no designators there).
    function isDesignator(address a) internal view returns (bool d) {
        assembly ("memory-safe") {
            if eq(extcodesize(a), 23) {
                extcodecopy(a, 0, 0, 3)
                d := eq(shr(232, mload(0)), 0xef0100)
            }
        }
    }

    /// @notice Real code: not empty and not a designator (a designator account is an EOA).
    function isContract(address a) internal view returns (bool) {
        uint256 len = a.code.length;
        return len != 0 && (len != 23 || !isDesignator(a));
    }

    /// @notice The one "an EOA must not run code" check of a direct caller that is authority (owner ruling 2026-10-30,
    ///         D2): a designator reverts `CallerDelegated`; a contract or a code-less EOA passes.
    function requireNotDelegated(address caller) internal view {
        if (isDesignator(caller)) revert CallerDelegated(caller);
    }

    /// @notice accounts.md CTR-UA-24, one rule for the address and the UA paths (owner ruling 2026-10-30, D1): no code
    ///         or the 23-byte EIP-7702 designator ⇒ ECDSA by the address's own key only (the delegate is never asked);
    ///         other code ⇒ ERC-1271 only.
    function isValid(address signer, bytes32 digest, bytes memory sig, uint256 cap1271)
        internal view returns (bool)
    {
        if (!isContract(signer)) return _ecdsa(signer, digest, sig);
        return _erc1271(signer, digest, sig, cap1271);
    }

    function _ecdsa(address signer, bytes32 digest, bytes memory sig) private pure returns (bool) {
        (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
        return err == ECDSA.RecoverError.NoError && rec == signer;
    }

    function _erc1271(address signer, bytes32 digest, bytes memory sig, uint256 cap1271)
        private view returns (bool ok)
    {
        bytes memory payload = abi.encodeCall(IERC1271.isValidSignature, (digest, sig));
        uint256 left = gasleft();
        if (left < cap1271 * 64 / 63 + GAS_MARGIN) revert SigCheckGasStarved(cap1271, left);
        bytes4 magic = IERC1271.isValidSignature.selector;
        assembly ("memory-safe") {
            mstore(0, 0)
            let success := staticcall(cap1271, signer, add(payload, 0x20), mload(payload), 0, 0x20)
            ok := and(and(success, eq(returndatasize(), 0x20)), eq(mload(0), magic))
        }
    }
}
