// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title One gas-capped ERC-20 call (C6-1).
/// @notice A listed hook token, or a hostile / upgradeable outside token, can burn every gas it is given; uncapped,
///         63/64 of a settlement's gas is gone and a later capped verify (ERC-1271, an ML-DSA leg) starves. Every call
///         the DEX or its puller makes into an outside token is forwarded at most `TOKEN_GAS`; out of gas inside it is
///         an ordinary failure (empty return data). 500 k: a transfer into a fresh account is ~130 k, a hook token
///         needs room above that; the bound, not the exact figure, is what keeps a verify funded. `SafeERC20.trySafeTransfer*` semantics otherwise: success means
///         the call succeeded and returned nothing from an account with code, or returned exactly `true`.
library TokenCall {
    uint256 internal constant TOKEN_GAS = 500_000;

    function ok(address token, bytes memory data) internal returns (bool good) {
        assembly ("memory-safe") {
            let g := gas()
            if gt(g, TOKEN_GAS) { g := TOKEN_GAS }
            let s := call(g, token, 0, add(data, 0x20), mload(data), 0, 0x20)
            switch returndatasize()
            case 0 { good := and(s, iszero(iszero(extcodesize(token)))) }
            default { good := and(s, and(gt(returndatasize(), 0x1f), eq(mload(0), 1))) }
        }
    }
}
