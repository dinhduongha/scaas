// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

// legacy/typed-signing: NOT COMPILED. The flat `uaUnwrap(bytes32 from, …)` as it stood in src/metatx/MetaTokenBase.sol
// (declared in IMetaTokenV2) before the typed-signing C2 review: it duplicated the named
// `uaUnwrap(UAEnvelope, …, UASig)` / `uaUnwrapLeg` (owner 2026-11-01). Reference only.

abstract contract FlatUaUnwrap {
    /// @notice The single-leg-or-any `unwrap` that `uaUnwrap` builds (accounts.md CTR-UA-26).
    bytes4 internal constant SEL_UA_UNWRAP = bytes4(keccak256("unwrap(address,uint256,address,uint256)"));

    /// @notice `uaExecute(UAMetaTransaction{from, unwrap(underlying, wrapped, recipient, minOut), …, fee 0})`: the
    ///         gasless unwrap of a UA (CTR-MTX-12); fee `NONE` (as `mtxTransfer`). Only on kinds whose UA allowlist
    ///         has that `unwrap` (else `MetaTxUnknownOp`).
    function uaUnwrap(
        bytes32 from, address underlying, uint256 wrapped, address recipient, uint256 minOut,
        uint256 batch, uint256 nonce, uint256 validUntil, uint32 mode, address relayer, bytes calldata auth
    ) external nonReentrant returns (bytes memory) {
        if (mode & ~MetaTxLib.MODE_RESTRICT_RELAYER != 0) revert MtxModeShape(mode);
        MetaTxLib.UAMetaTransaction memory m;
        m.from = from;
        m.data = abi.encodeWithSelector(SEL_UA_UNWRAP, underlying, wrapped, recipient, minOut);
        m.batch = batch;
        m.nonce = nonce;
        m.validUntil = validUntil;
        m.mode = mode;
        m.relayer = relayer;
        return _uaExecute(m, auth);
    }
}
