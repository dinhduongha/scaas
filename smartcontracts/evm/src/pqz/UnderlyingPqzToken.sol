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
import {PqzLayer} from "./PqzLayer.sol";
import {PqzCore} from "./PqzCore.sol";
import {PqzBurnLib} from "./PqzBurnLib.sol";
import {PqzStateLib} from "./PqzStateLib.sol";
import {PqzViewLib} from "./PqzViewLib.sol";

/// @title Kind `UNDERLYING_PQZ` (CTR-TOK-21, CTR-PQZ-22): the wrapper of 1–8 legs with the PQZ layer (P6g plan D1).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Chains 31337 / 1337 / 7622 only. Legs, rates, reserves,
///         `wrap` / `unwrap` and the roles are `UnderlyingToken`'s; the layer adds `pqzWrapShield` (a leg's underlying
///         straight into a TRIVIAL pending entry, nothing minted; plan 5h D18) and `pqzUnshieldUnwrap` (a burn paid straight out of a leg's
///         reserve, nothing minted), as `zetherWrapShield` / `zetherUnshieldUnwrap`. Reserve invariant
///         `Σ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply() + totalShielded·shieldScale`; `executeRate` counts the shielded part.
contract UnderlyingPqzToken is UnderlyingToken, PqzLayer {
    /// @notice A burn paid from leg `u`: `amount` shielded units to `recipient`, at least `minOut` of the leg.
    struct Unwrap {
        address u;
        address recipient;
        uint256 amount;
        uint256 minOut;
    }

    /// @dev The factory's append (`OpenFactory.deployImplementation`, plan 5g-Z2): the release's `Env`, whose
    ///      `deps[ENV_PQZ_VERIFIER]` is the release's `UAPqzVerifier` (CTR-ZTH-20 / CTR-PQZ-10); no `implArgs`.
    constructor(uint16 envVersion, Env memory env, bytes memory implArgs)
        UnderlyingToken(envVersion, env, implArgs)
        PqzLayer(env)
    {
        if (env.registry.code.length == 0) revert BadInit();
    }

    /// @dev The legs (`UnderlyingToken`), restated for the second base.
    function underlyings() public view override(UnderlyingToken, MetaTokenBase) returns (address[] memory) {
        return super.underlyings();
    }

    function kind() public pure override(UnderlyingToken, MetaTokenBase) returns (uint8) {
        return AdminLib.KIND_UNDERLYING_PQZ;
    }

    function _init(TokenConfig memory cfg) internal override(UnderlyingToken, MetaTokenBase) {
        _requireUnused(cfg, true, false, false, false);
        UnderlyingLib.initToken(cfg, false, AdminLib.KIND_UNDERLYING_PQZ);
        PqzStateLib.init(cfg.conf, _REGISTRY, PQZ_VERIFIER);
    }

    // ------------------------------------------------------------------ wrap-shield / unshield-unwrap (CTR-PQZ-22)

    /// @notice Pulls `amountIn` of leg `u` (native: `msg.value`); the minted public-equivalent, a multiple of
    ///         `shieldScale` (`AmountNotScaled`), becomes a TRIVIAL entry of `minted / shieldScale` for `ua`.
    function pqzWrapShield(address u, uint256 amountIn, bytes32 ua) external payable nonReentrant {
        (,, uint256 minted) = UnderlyingLib.wrap(UnderlyingLib.indexOf(u), amountIn, _msgSender(), msg.value);
        uint256 scale = PqzCore.$().shieldScale;
        if (minted % scale != 0) revert AmountNotScaled(minted, scale);
        PqzStateLib.shield(ua, minted / scale, _REGISTRY);
    }

    /// @notice The burn of `x.amount` (statement: `amount`, `recipient`; direct, `envelopeBinding` binds `x.u` and
    ///         `x.minOut`, P6g D12), then leg `x.u` pays `⌊amount·shieldScale·den/num⌋ ≥ minOut` to `x.recipient`.
    function pqzUnshieldUnwrap(bytes calldata payload, bytes calldata accHint, Unwrap calldata x,
        bytes calldata proof, bytes calldata authSig) external nonReentrant
    {
        PqzBurnLib.unshield(_envUnwrap(x), payload, accHint, proof, authSig);
        _shieldIn(payload);
        _payUnwrap(x);
    }

    function _payUnwrap(Unwrap calldata x) private {
        uint256 i = UnderlyingLib.indexOf(x.u);
        (uint256 out,) = UnderlyingLib.quoteUnwrap(i, x.amount * PqzCore.$().shieldScale, x.recipient, x.minOut);
        UnderlyingLib.payOut(i, x.recipient, out);
    }

    /// @notice The `envelopeBinding` word of a direct `pqzUnshieldUnwrap` (P6g plan D12).
    function unwrapBinding(address u, uint256 minOut) public pure returns (bytes32) {
        return keccak256(abi.encode(PqzCore.TAG_UNWRAP, u, minOut));
    }

    /// @notice The burn statement of `pqzUnshieldUnwrap` (the binding as the call would use it, direct or `binding`).
    function unshieldUnwrapStatement(bytes calldata payload, Unwrap calldata x, bytes32 binding)
        external view returns (bytes memory)
    {
        PqzCore.Env memory e = _envOf(binding == 0 ? unwrapBinding(x.u, x.minOut) : binding);
        (e.amount, e.recipient) = (x.amount, x.recipient);
        return PqzViewLib.statementOf(2, e, payload);
    }

    function _envUnwrap(Unwrap calldata x) private view returns (PqzCore.Env memory e) {
        bytes32 b = _ticketBinding();
        e = _envOf(b != 0 ? b : unwrapBinding(x.u, x.minOut));
        (e.amount, e.recipient) = (x.amount, x.recipient);
    }

    /// @notice As `UnderlyingToken` (also cancels a pending rate change, CTR-TOK-06); restated for the second base.
    function disableFeature(uint8 bit) external override(UnderlyingToken, MetaTokenBase) nonReentrant {
        AdminLib.disableFeature(bit, _msgSender());
        if (bit == AdminLib.RATE_ADJUSTABLE) UnderlyingLib.dropPending();
    }

    /// @notice The collateral check of a rate change counts the shielded value too.
    function executeRate() external override nonReentrant {
        UnderlyingLib.executeRate(_msgSender(), totalSupply() + PqzCore.$().totalShielded * PqzCore.$().shieldScale);
    }

    // ------------------------------------------------------------------ the layer's hooks

    function _domainName() internal pure override(ERC20MetaTx, PqzLayer) returns (string memory) {
        return PqzLayer._domainName();
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m)
        internal view override(MetaTxBase, PqzLayer) returns (bytes32)
    {
        return PqzLayer._envelopeBinding(m);
    }

    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view override(ERC20MetaTx, PqzLayer) returns (bytes32)
    {
        return PqzLayer._uaEnvelopeBinding(m);
    }

    function _isPqzOp(bytes4 sel) internal pure override returns (bool) {
        return PqzLayer._isPqzOp(sel) || sel == this.pqzWrapShield.selector || sel == this.pqzUnshieldUnwrap.selector;
    }

    function _batchable(bytes4 sel) internal view override(MetaTxBase, PqzLayer) returns (bool) {
        return PqzLayer._batchable(sel);
    }

    // ------------------------------------------------------------------ allowlist (CTR-MTX-19, CTR-PQZ-21)

    /// @notice `UnderlyingToken`'s eight, then the PQZ ops and the two leg paths, each `ABSOLUTE`.
    function mtxSelectors()
        public pure override(UnderlyingToken, IMetaTx, MetaTxBase)
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
        (s[6], c[6]) = (SEL_WRAP_TO_UA, FEE_CLASS_ABSOLUTE);
        (s[7], c[7], a[7]) = (SEL_UNWRAP_TO_UA, FEE_CLASS_AMOUNT, 1);
        (s[8], c[8]) = (this.pqzShield.selector, FEE_CLASS_ABSOLUTE);
        (s[9], c[9]) = (this.pqzTransfer.selector, FEE_CLASS_ABSOLUTE);
        (s[10], c[10]) = (this.pqzTransferCompact.selector, FEE_CLASS_ABSOLUTE);
        (s[11], c[11]) = (this.pqzTransferNoBundle.selector, FEE_CLASS_ABSOLUTE);
        (s[12], c[12]) = (this.pqzUnshield.selector, FEE_CLASS_ABSOLUTE);
        (s[13], c[13]) = (this.pqzRollOver.selector, FEE_CLASS_ABSOLUTE);
        (s[14], c[14]) = (this.pqzWrapShield.selector, FEE_CLASS_ABSOLUTE);
        (s[15], c[15]) = (this.pqzUnshieldUnwrap.selector, FEE_CLASS_ABSOLUTE);
        (s[16], c[16]) = (this.pqzTransferSingle.selector, FEE_CLASS_ABSOLUTE);
        (s[17], c[17]) = (this.pqzTransferSingleCompact.selector, FEE_CLASS_ABSOLUTE);
        (s[18], c[18]) = (this.pqzTransferSingleNoBundle.selector, FEE_CLASS_ABSOLUTE);
    }

    function _mtxRule(bytes4 sel) internal view override(UnderlyingToken, MetaTxBase) returns (MtxRule memory) {
        if (sel == this.pqzWrapShield.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 100);
        if (_isPqzOp(sel)) return _pqzRule(sel);
        return UnderlyingToken._mtxRule(sel);
    }

    /// @notice The leg paths of `UnderlyingToken` and the PQZ ops; not `pqzWrapShield` (the pool holds no leg).
    function _uaAllowed(bytes4 sel) internal view override(UnderlyingToken, ERC20MetaTx) returns (bool) {
        return (_isPqzOp(sel) && sel != this.pqzWrapShield.selector) || UnderlyingToken._uaAllowed(sel);
    }
}
