// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {UnderlyingToken} from "../metatx/UnderlyingToken.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {MetaTxBase} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {AdminLib} from "../metatx/AdminLib.sol";
import {UnderlyingLib} from "../metatx/UnderlyingLib.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {ITransferDisclosure} from "./ITransferDisclosure.sol";
import {ZetherTypes} from "./ZetherTypes.sol";
import {ZetherLayer} from "./ZetherLayer.sol";
import {ZetherLib} from "./ZetherLib.sol";

/// @title Kind `UNDERLYING_ZETHER` (CTR-TOK-21): the wrapper of 1–8 legs with the Zether layer (CTR-ZTH-44).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Dev chains only. The legs, rates, reserves, `wrap`/`unwrap`,
///         `mtxWrap` and the rate and guardian roles are `UnderlyingToken`'s (`UnderlyingLib`); the layer adds
///         `zetherWrapShield` (a leg's underlying straight into a shielded balance, nothing minted) and
///         `zetherUnshieldUnwrap` (a shielded balance straight out to a leg's underlying, nothing minted). Reserve
///         invariant: `Σ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply() + totalShielded·shieldScale`, by construction (a wrap-shield
///         credits `minted / shieldScale` with `minted` a multiple of the scale, an unshield-unwrap pays
///         `⌊amount·shieldScale·den/num⌋`, worth at most what it removes), and `executeRate` checks it with the shielded
///         part. Flags: `PAYABLE`, `RATE_ADJUSTABLE`, `WRAP_DISABLEABLE` (CTR-ZTH-47). Never on Hedera.
contract UnderlyingZetherToken is UnderlyingToken, ZetherLayer {
    constructor(address factory_, address smartKeyAccountImpl_, bytes32 chainUid_, address registry_,
        ITransferDisclosure disclosure_)
        UnderlyingToken(factory_, smartKeyAccountImpl_, chainUid_, registry_, false)
        ZetherLayer(disclosure_)
    {}

    function kind() public pure override(UnderlyingToken, MetaTokenBase) returns (uint8) {
        return AdminLib.KIND_UNDERLYING_ZETHER;
    }

    function _init(TokenConfig calldata cfg) internal override(UnderlyingToken, MetaTokenBase) {
        _requireUnused(cfg, true, false, false, false);
        UnderlyingLib.initToken(cfg, false, AdminLib.KIND_UNDERLYING_ZETHER);
        ZetherLib.init(cfg.conf);
    }

    // ------------------------------------------------------------------ wrap-shield / unshield-unwrap (CTR-ZTH-45)

    /// @notice Pulls `amountIn` of leg `u` (native: `msg.value`) and credits the public-equivalent `minted` (the leg's
    ///         rate on the measured delta) as `minted / shieldScale` shielded units to `ua`, minting nothing;
    ///         `minted % shieldScale ≠ 0` ⇒ `AmountNotScaled` (the client sends an exact amount).
    function zetherWrapShield(address u, uint256 amountIn, ZetherTypes.UA ua) external payable nonReentrant {
        (,, uint256 minted) = UnderlyingLib.wrap(UnderlyingLib.indexOf(u), amountIn, _msgSender(), msg.value);
        uint256 scale = ZetherLib.$().shieldScale;
        if (minted % scale != 0) revert AmountNotScaled(minted, scale);
        ZetherLib.shield(ua, minted / scale, _REGISTRY);
    }

    /// @notice The unshield proof (amount and `recipient` in the statement; a direct call also binds `u` and `minOut`),
    ///         then leg `u` pays `⌊amount·shieldScale·den/num⌋ ≥ minOut` from its reserve to `recipient`, minting nothing.
    function zetherUnshieldUnwrap(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary,
        address u,
        address recipient,
        uint256 amount,
        uint256 minOut
    ) external nonReentrant {
        _unshieldUnwrap(payload, proof, authSig, beneficiary, Unwrap(u, recipient, amount, minOut));
    }

    struct Unwrap {
        address u;
        address recipient;
        uint256 amount;
        uint256 minOut;
    }

    /// @dev The leg first (cheap), the proof and the debit, then the payout from the leg's reserve (CEI: the debit
    ///      before the one outside call).
    function _unshieldUnwrap(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary,
        Unwrap memory x
    ) private {
        uint256 i = UnderlyingLib.indexOf(x.u);
        ZetherLib.unshield(payload, proof, authSig, beneficiary, x.amount, x.recipient, _envUnwrap(x.u, x.minOut));
        (uint256 out,) = UnderlyingLib.quoteUnwrap(i, x.amount * ZetherLib.$().shieldScale, x.recipient, x.minOut);
        UnderlyingLib.payOut(i, x.recipient, out);
    }

    /// @notice As `UnderlyingToken` (also cancels a pending rate change, CTR-TOK-06); restated for the second base.
    function disableFeature(uint8 bit) external override(UnderlyingToken, MetaTokenBase) {
        AdminLib.disableFeature(bit, _msgSender());
        if (bit == AdminLib.RATE_ADJUSTABLE) UnderlyingLib.dropPending();
    }

    /// @notice The collateral check of a rate change counts the shielded value too.
    function executeRate() external override {
        UnderlyingLib.executeRate(_msgSender(), totalSupply() + ZetherLib.$().totalShielded * ZetherLib.$().shieldScale);
    }

    // ------------------------------------------------------------------ the layer's hooks

    function _domainName() internal pure override(ERC20MetaTx, ZetherLayer) returns (string memory) {
        return ZetherLayer._domainName();
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m)
        internal view override(MetaTxBase, ZetherLayer) returns (bytes32)
    {
        return ZetherLayer._envelopeBinding(m);
    }

    /// @dev Relayed: the envelope binding (the signature covers `data`, the leg and `minOut` with it); direct: the leg
    ///      and `minOut` (`ZetherLib.unwrapBinding`) under `ZTX_V1_DIRECT`.
    function _envUnwrap(address u, uint256 minOut) private view returns (ZetherLib.Env memory) {
        bytes32 b = _ticketBinding();
        if (b != bytes32(0)) return ZetherLib.Env(_REGISTRY, CHAIN_UID, ZetherLib.TAG_RELAYED, b);
        return ZetherLib.Env(_REGISTRY, CHAIN_UID, ZetherLib.TAG_DIRECT, ZetherLib.unwrapBinding(u, minOut));
    }

    // ------------------------------------------------------------------ allowlist (CTR-MTX-19, CTR-ZTH-34)

    /// @notice `UnderlyingToken`'s six, then the Zether ops and the two underlying paths, each `ABSOLUTE`.
    function mtxSelectors()
        public pure override(UnderlyingToken, IMetaTx, MetaTxBase)
        returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](14);
        c = new uint8[](14);
        a = new uint8[](14);
        (s[0], c[0]) = (this.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (SEL_WRAP, FEE_CLASS_ABSOLUTE);
        (s[2], c[2]) = (SEL_UNWRAP_MIN, FEE_CLASS_AMOUNT);
        (s[3], c[3]) = (SEL_WRAP_LEG, FEE_CLASS_ABSOLUTE);
        (s[4], c[4], a[4]) = (SEL_UNWRAP_LEG, FEE_CLASS_AMOUNT, 1);
        (s[5], c[5]) = (SEL_ADD_RESERVE, FEE_CLASS_ABSOLUTE);
        (s[6], c[6]) = (this.zetherShield.selector, FEE_CLASS_ABSOLUTE);
        (s[7], c[7]) = (this.zetherTransfer.selector, FEE_CLASS_ABSOLUTE);
        (s[8], c[8]) = (this.zetherTransferCompact.selector, FEE_CLASS_ABSOLUTE);
        (s[9], c[9]) = (this.zetherTransferNoBundle.selector, FEE_CLASS_ABSOLUTE);
        (s[10], c[10]) = (this.zetherTransferSingle.selector, FEE_CLASS_ABSOLUTE);
        (s[11], c[11]) = (this.zetherUnshield.selector, FEE_CLASS_ABSOLUTE);
        (s[12], c[12]) = (this.zetherWrapShield.selector, FEE_CLASS_ABSOLUTE);
        (s[13], c[13]) = (this.zetherUnshieldUnwrap.selector, FEE_CLASS_ABSOLUTE);
    }

    function _mtxRule(bytes4 sel) internal view override(UnderlyingToken, MetaTxBase) returns (MtxRule memory) {
        if (_isZetherOp(sel) || sel == this.zetherUnshieldUnwrap.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);
        if (sel == this.zetherWrapShield.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 100);
        return UnderlyingToken._mtxRule(sel);
    }

    function _uaAllowed(bytes4 sel) internal view override(UnderlyingToken, ERC20MetaTx) returns (bool) {
        return UnderlyingToken._uaAllowed(sel);
    }
}
