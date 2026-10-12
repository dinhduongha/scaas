// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/// @title The one signature check of every SCaaS contract (CTR-MTX-25).
/// @notice EOA ⇒ OpenZeppelin `ECDSA.tryRecover` (65 bytes, low-s, CTR-MTX-14). Contract ⇒ ERC-1271
///         `isValidSignature` by `staticcall` with a per-signer gas cap (50 000 by default; 400 000 only for
///         `SmartKeyAccount` clones, CTR-ACC-05), at most 32 bytes of returndata read, and the EIP-150 rule of
///         CTR-DEX-08: the caller must hold `cap·64/63 + GAS_MARGIN` gas, so a relayer cannot starve the call to
///         turn a valid signature into an invalid one. "Contract" excludes an EIP-7702 delegated EOA
///         (`0xef0100‖address`): its key still signs.
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

    function isContract(address a) internal view returns (bool) {
        uint256 len = a.code.length;
        if (len == 0) return false;
        if (len == 23) {
            bytes memory c = a.code;
            if (c[0] == 0xef && c[1] == 0x01 && c[2] == 0x00) return false;
        }
        return true;
    }

    function isValid(address signer, bytes32 digest, bytes memory sig, uint256 cap1271)
        internal view returns (bool ok)
    {
        if (!isContract(signer)) {
            (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
            return err == ECDSA.RecoverError.NoError && rec == signer;
        }
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
