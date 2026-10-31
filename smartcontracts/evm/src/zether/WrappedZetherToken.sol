// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {WrappedToken} from "../metatx/WrappedToken.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {MetaTxBase} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {AdminLib} from "../metatx/AdminLib.sol";
import {WrappedLib} from "../metatx/WrappedLib.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {ITransferDisclosure} from "./ITransferDisclosure.sol";
import {ZetherTypes} from "./ZetherTypes.sol";
import {ZetherLayer} from "./ZetherLayer.sol";
import {ZetherLib} from "./ZetherLib.sol";
import {IConfidentialWrappedToken} from "../confidential/IConfidentialToken.sol";
import {UAKinds} from "../ua/UAKinds.sol";

/// @title Kind `WRAPPED_ZETHER` (CTR-TOK-21): the wrapper of 1–8 legs with the Zether layer (CTR-ZTH-44).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Any chain with EIP-2537 (BLS12-381). The legs, rates, reserves, `wrap`/`unwrap`,
///         `mtxWrap` and the rate and guardian roles are `WrappedToken`'s (`WrappedLib`); the layer adds
///         `mtxWrapShield` (a leg's underlying straight into a shielded balance, minted to the pool) and
///         `mtxUnshieldUnwrap` (a shielded balance straight out to a leg's underlying, burnt from the pool; to an
///         address or, through a SCaaS ledger leg, a UA). Reserve
///         invariant: `Σ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply()` (the shielded value is public units in `SHIELD_POOL`, D19), by
///         construction (a wrap-shield mints `minted`, a multiple of the scale, to the pool, an unshield-unwrap burns
///         `amount·shieldScale` from it and pays `⌊amount·shieldScale·den/num⌋`, worth at most what it removes), and
///         `executeRate` checks it. Flags: `PAYABLE`, `RATE_ADJUSTABLE`, `WRAP_DISABLEABLE` (CTR-ZTH-47). Never on Hedera.
contract WrappedZetherToken is WrappedToken, ZetherLayer, IConfidentialWrappedToken {
    /// @dev The factory's append (`OpenFactory.deployImplementation`, plan 5g-Z2): the release's `Env` (Hedera off: `ZetherLayer`
    ///      refuses a Hedera env); no `implArgs`.
    constructor(uint16 envVersion, Env memory env, bytes memory implArgs)
        WrappedToken(envVersion, env, implArgs)
        ZetherLayer(env)
    {}

    /// @dev The legs (`WrappedToken`), restated for the second base.
    function underlyings() public view override(WrappedToken, MetaTokenBase) returns (address[] memory) {
        return super.underlyings();
    }

    function kind() public pure override(WrappedToken, MetaTokenBase) returns (uint8) {
        return AdminLib.KIND_WRAPPED_ZETHER;
    }

    function _init(TokenConfig memory cfg) internal override(WrappedToken, MetaTokenBase) {
        _requireUnused(cfg, true, false, false, false);
        WrappedLib.initToken(cfg, false, AdminLib.KIND_WRAPPED_ZETHER);
        ZetherLib.init(cfg.conf, TRANSFER_VERIFIER);
    }

    // ------------------------------------------------------------------ wrap-shield / unshield-unwrap (CTR-ZTH-45)

    /// @notice Pulls `amountIn` of leg `underlying` (native: `msg.value`) and credits the public-equivalent `minted`
    ///         (the leg's rate on the measured delta) as `minted / shieldScale` shielded units to `toUA`, minting `minted`
    ///         to `SHIELD_POOL`; `minted % shieldScale ≠ 0` ⇒ `AmountNotScaled` (the client sends an exact amount).
    function mtxWrapShield(address underlying, uint256 amountIn, bytes32 toUA) external payable nonReentrant {
        address m = _msgSender();
        (,, uint256 minted) = WrappedLib.wrap(WrappedLib.indexOf(underlying), amountIn, m, msg.value);
        uint256 scale = ZetherLib.$().shieldScale;
        if (minted % scale != 0) revert AmountNotScaled(minted, scale);
        ZetherLib.shield(ZetherTypes.UA.wrap(toUA), minted / scale, _REGISTRY, m);
        _poolMove(bytes32(0), MetaTxLib.pad(MetaTxLib.SHIELD_POOL), minted); // D19: minted to the pool
    }

    /// @notice The unshield proof (`x.amount` and `x.recipient` in the statement; a direct call also binds
    ///         `x.underlying` and `x.minOut`), then leg `x.underlying` pays `⌊amount·shieldScale·den/num⌋ ≥ minOut` from
    ///         its reserve to `x.recipient` — an address, or a derived UA through the leg's `transferToUA`
    ///         (`UALegNotLedger` otherwise, CTR-ZTH-51) — burning `amount·shieldScale` from `SHIELD_POOL`.
    function mtxUnshieldUnwrap(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata auth,
        bytes32 beneficiary,
        bytes calldata accHint,
        Unwrap calldata x
    ) external nonReentrant {
        _noAuth(auth, accHint);
        _unshieldUnwrap(payload, proof, ZetherTypes.UA.wrap(beneficiary), x);
    }

    /// @dev The leg first (cheap), the proof and the debit, then the payout from the leg's reserve (CEI: the debit
    ///      before the one outside call).
    function _unshieldUnwrap(
        bytes calldata payload,
        bytes calldata proof,
        ZetherTypes.UA beneficiary,
        Unwrap calldata x
    ) private {
        uint256 i = WrappedLib.indexOf(x.underlying);
        // a derived recipient: the leg's `transferToUA` checks it
        if (UAKinds.inNativeSpace(x.recipient)) _requirePayee(address(uint160(uint256(x.recipient))));
        uint256 fee = ZetherLib.unshield(payload, proof, beneficiary, x.amount, x.recipient, _envUnwrap(x.underlying, x.minOut));
        uint256 wrapped = x.amount * ZetherLib.$().shieldScale;
        _poolMove(MetaTxLib.pad(MetaTxLib.SHIELD_POOL), bytes32(0), wrapped); // D19: burn from the pool
        _fromPool(beneficiary, fee);
        WrappedLib.payOutTo(i, x.recipient, wrapped, x.minOut);
    }

    /// @notice As `WrappedToken` (also cancels a pending rate change, CTR-TOK-06); restated for the second base.
    function disableFeature(uint8 bit) external override(WrappedToken, MetaTokenBase) nonReentrant {
        AdminLib.disableFeature(bit, _msgSender());
        if (bit == AdminLib.RATE_ADJUSTABLE) WrappedLib.dropPending();
    }

    /// @notice The collateral check of a rate change counts the shielded value too.
    function executeRate() external override nonReentrant {
        WrappedLib.executeRate(_msgSender(), totalSupply()); // the shielded value sits in SHIELD_POOL (D19)
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

    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view override(ERC20MetaTx, ZetherLayer) returns (bytes32)
    {
        return ZetherLayer._uaEnvelopeBinding(m);
    }

    /// @dev Relayed: the envelope binding (the signature covers `data`, the leg and `minOut` with it); direct: the leg
    ///      and `minOut` (`ZetherLib.unwrapBinding`) under `ZTX_V1_DIRECT`.
    function _envUnwrap(address u, uint256 minOut) private view returns (ZetherLib.Env memory) {
        bytes32 b = _ticketBinding();
        if (b != bytes32(0)) return ZetherLib.Env(_REGISTRY, CHAIN_UID, ZetherLib.TAG_RELAYED, b, BURN_VERIFIER);
        return ZetherLib.Env(
            _REGISTRY, CHAIN_UID, ZetherLib.TAG_DIRECT, ZetherLib.unwrapBinding(u, minOut), BURN_VERIFIER
        );
    }

    // ------------------------------------------------------------------ allowlist (CTR-MTX-19, CTR-ZTH-34)

    /// @notice `WrappedToken`'s first six, then the Zether ops and the two underlying paths, each `ABSOLUTE`, then
    ///         `WrappedToken`'s UA-5a two (`wrapToUA` `ABSOLUTE`, `unwrapToUA` `AMOUNT(1)`, CTR-UA-28).
    function mtxSelectors()
        public pure override(WrappedToken, IMetaTx, MetaTxBase)
        returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](19);
        c = new uint8[](19);
        a = new uint8[](19);
        (s[0], c[0]) = (this.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (SEL_WRAP, FEE_CLASS_ABSOLUTE);
        (s[2], c[2]) = (SEL_UNWRAP_MIN, FEE_CLASS_AMOUNT);
        (s[3], c[3]) = (SEL_WRAP_LEG, FEE_CLASS_ABSOLUTE);
        (s[4], c[4], a[4]) = (SEL_UNWRAP_LEG, FEE_CLASS_AMOUNT, 1);
        (s[5], c[5]) = (SEL_ADD_RESERVE, FEE_CLASS_ABSOLUTE);
        (s[6], c[6]) = (this.mtxShield.selector, FEE_CLASS_ABSOLUTE);
        (s[7], c[7]) = (this.mtxConfidentialTransfer.selector, FEE_CLASS_ABSOLUTE);
        (s[8], c[8]) = (this.mtxConfidentialTransferCompact.selector, FEE_CLASS_ABSOLUTE);
        (s[9], c[9]) = (this.mtxConfidentialTransferSingle.selector, FEE_CLASS_ABSOLUTE);
        (s[10], c[10]) = (this.mtxUnshield.selector, FEE_CLASS_ABSOLUTE);
        (s[11], c[11]) = (this.mtxWrapShield.selector, FEE_CLASS_ABSOLUTE);
        (s[12], c[12]) = (this.mtxUnshieldUnwrap.selector, FEE_CLASS_ABSOLUTE);
        (s[13], c[13]) = (SEL_WRAP_TO_UA, FEE_CLASS_ABSOLUTE);
        (s[14], c[14], a[14]) = (SEL_UNWRAP_TO_UA, FEE_CLASS_AMOUNT, 1);
        (s[15], c[15]) = (this.mtxRollOver.selector, FEE_CLASS_ABSOLUTE);
        (s[16], c[16]) = (this.mtxRollOverBatch.selector, FEE_CLASS_ABSOLUTE);
        (s[17], c[17]) = (this.mtxRollOverSigned.selector, FEE_CLASS_ABSOLUTE);
        (s[18], c[18]) = (this.mtxSetRollOverMode.selector, FEE_CLASS_ABSOLUTE);
    }

    function _mtxRule(bytes4 sel) internal view override(WrappedToken, MetaTxBase) returns (MtxRule memory) {
        if (_isZetherOp(sel) || sel == this.mtxUnshieldUnwrap.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);
        if (sel == this.mtxWrapShield.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 100);
        return WrappedToken._mtxRule(sel);
    }

    /// @notice `WrappedToken`'s UA allowlist, the Zether ops and `mtxUnshieldUnwrap` (CTR-ZTH-51, UA-5c, as
    ///         `NormalZetherToken`); not `mtxWrapShield` (a UA wrap-shields in two signed steps, `uaWrap` then
    ///         `mtxShield`).
    function _uaAllowed(bytes4 sel) internal view override(WrappedToken, ERC20MetaTx) returns (bool) {
        return _isZetherOp(sel) || sel == this.mtxUnshieldUnwrap.selector || WrappedToken._uaAllowed(sel);
    }
}
