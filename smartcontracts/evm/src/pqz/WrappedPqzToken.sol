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
import {SigCheck} from "../common/SigCheck.sol";
import {PqzLayer} from "./PqzLayer.sol";
import {PqzCore} from "./PqzCore.sol";
import {PqzBurnLib} from "./PqzBurnLib.sol";
import {PqzStateLib} from "./PqzStateLib.sol";
import {PqzViewLib} from "./PqzViewLib.sol";
import {IConfidentialWrappedToken} from "../confidential/IConfidentialToken.sol";

/// @title Kind `WRAPPED_PQZ` (CTR-TOK-21, CTR-PQZ-22): the wrapper of 1–8 legs with the PQZ layer (P6g plan D1).
/// @notice **UNAUDITED.** Chains 31337 / 1337 / 7622 only. Legs, rates, reserves,
///         `wrap` / `unwrap` and the roles are `WrappedToken`'s; the layer adds `mtxWrapShield` (a leg's underlying
///         into a TRIVIAL pending entry, the public-equivalent minted to `SHIELD_POOL`; plan 5h D18, D19) and
///         `mtxUnshieldUnwrap` (a burn: `amount · shieldScale` burnt from `SHIELD_POOL`, then paid out of a leg's
///         reserve to an address or, through a SCaaS ledger leg, to a UA), as on `WRAPPED_ZETHER`. Reserve invariant
///         `Σ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply()` (the shielded value is the pool's public units).
contract WrappedPqzToken is WrappedToken, PqzLayer, IConfidentialWrappedToken {
    /// @dev The factory's append (`OpenFactory.deployImplementation`, plan 5g-Z2): the release's `Env`, whose
    ///      `deps[ENV_PQZ_VERIFIER]` is the release's `UAPqzVerifier` (CTR-ZTH-20 / CTR-PQZ-10); no `implArgs`.
    constructor(uint16 envVersion, Env memory env, bytes memory implArgs)
        WrappedToken(envVersion, env, implArgs)
        PqzLayer(env)
    {
        if (!SigCheck.isContract(env.registry)) revert BadInit();
    }

    /// @dev The legs (`WrappedToken`), restated for the second base.
    function underlyings() public view override(WrappedToken, MetaTokenBase) returns (address[] memory) {
        return super.underlyings();
    }

    function kind() public pure override(WrappedToken, MetaTokenBase) returns (uint8) {
        return AdminLib.KIND_WRAPPED_PQZ;
    }

    function _init(TokenConfig memory cfg) internal override(WrappedToken, MetaTokenBase) {
        _requireUnused(cfg, true, false, false, false);
        WrappedLib.initToken(cfg, false, AdminLib.KIND_WRAPPED_PQZ);
        PqzStateLib.init(cfg.conf, _REGISTRY, PQZ_VERIFIER);
    }

    // ------------------------------------------------------------------ wrap-shield / unshield-unwrap (CTR-PQZ-22)

    /// @notice Pulls `amountIn` of leg `underlying` (native: `msg.value`); the public-equivalent `minted`, a multiple of
    ///         `shieldScale` (`AmountNotScaled`), is minted to `SHIELD_POOL` (D19) and becomes a TRIVIAL entry of
    ///         `minted / shieldScale` for `toUA`.
    function mtxWrapShield(address underlying, uint256 amountIn, bytes32 toUA) external payable nonReentrant {
        address m = _msgSender();
        (,, uint256 minted) = WrappedLib.wrap(WrappedLib.indexOf(underlying), amountIn, m, msg.value);
        uint256 scale = PqzCore.$().shieldScale;
        if (minted % scale != 0) revert AmountNotScaled(minted, scale);
        PqzStateLib.shield(toUA, minted / scale, m, _REGISTRY);
        _poolMove(bytes32(0), MetaTxLib.pad(MetaTxLib.SHIELD_POOL), minted);
    }

    /// @notice The burn of `x.amount` (statement: `amount`, `recipient`; `envelopeBinding` binds `x.underlying` and
    ///         `x.minOut`, direct P6g D12, relayed folded with the envelope's D15), `amount · shieldScale` burnt from
    ///         `SHIELD_POOL`, txFee to the beneficiary, then leg `x.underlying` pays `⌊amount·shieldScale·den/num⌋ ≥
    ///         minOut` to `x.recipient`: an address, or a derived UA through the leg's `transferToUA` (`UALegNotLedger`
    ///         otherwise).
    function mtxUnshieldUnwrap(bytes calldata payload, bytes calldata proof, bytes calldata auth, bytes32 beneficiary,
        bytes calldata accHint, Unwrap calldata x) external nonReentrant
    {
        _ben(payload, 128, beneficiary);
        _burn(_envUnwrap(x, _ticketBinding()), payload, proof, auth, accHint);
        uint256 wrapped = x.amount * PqzCore.$().shieldScale;
        _poolMove(MetaTxLib.pad(MetaTxLib.SHIELD_POOL), bytes32(0), wrapped);
        WrappedLib.payOutTo(WrappedLib.indexOf(x.underlying), x.recipient, wrapped, x.minOut);
    }

    /// @notice The `envelopeBinding` word of a direct `mtxUnshieldUnwrap` (P6g plan D12).
    function unwrapBinding(address u, uint256 minOut) public pure returns (bytes32) {
        return keccak256(abi.encode(PqzCore.TAG_UNWRAP, u, minOut));
    }

    /// @notice The burn statement of `mtxUnshieldUnwrap` (`binding` 0 = direct, else the relayed call's envelope binding).
    function unshieldUnwrapStatement(bytes calldata payload, Unwrap calldata x, bytes32 binding)
        external view returns (bytes memory)
    {
        return PqzViewLib.statementOf(2, _envUnwrap(x, binding), payload);
    }

    /// @dev The binding word: `unwrapBinding(u, minOut)` direct, `keccak256(abi.encode(envelope, unwrapBinding(u,
    ///      minOut)))` relayed (plan 5h D15).
    function _envUnwrap(Unwrap calldata x, bytes32 b) private view returns (PqzCore.Env memory e) {
        bytes32 w = unwrapBinding(x.underlying, x.minOut);
        e = _envOf(b == 0 ? w : keccak256(abi.encode(b, w)));
        (e.amount, e.recipient) = (x.amount, x.recipient);
    }

    /// @notice As `WrappedToken` (also cancels a pending rate change, CTR-TOK-06); restated for the second base.
    function disableFeature(uint8 bit) external override(WrappedToken, MetaTokenBase) nonReentrant {
        AdminLib.disableFeature(bit, _msgSender());
        if (bit == AdminLib.RATE_ADJUSTABLE) WrappedLib.dropPending();
    }

    /// @notice The collateral check of a rate change: `totalSupply()` (the shielded value sits in `SHIELD_POOL`, D19).
    function executeRate() external override nonReentrant {
        WrappedLib.executeRate(_msgSender(), totalSupply());
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
        return PqzLayer._isPqzOp(sel) || sel == this.mtxWrapShield.selector || sel == this.mtxUnshieldUnwrap.selector;
    }

    function _batchable(bytes4 sel) internal view override(MetaTxBase, PqzLayer) returns (bool) {
        return PqzLayer._batchable(sel);
    }

    // ------------------------------------------------------------------ allowlist (CTR-MTX-19, CTR-PQZ-21)

    /// @notice `WrappedToken`'s eight, then the PQZ ops and the two leg paths, each `ABSOLUTE` (incl. the rollover
    ///         and `mtxPrepareAcc`).
    function mtxSelectors()
        public pure override(WrappedToken, IMetaTx, MetaTxBase)
        returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](18);
        c = new uint8[](18);
        a = new uint8[](18);
        (s[0], c[0]) = (this.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (SEL_WRAP, FEE_CLASS_ABSOLUTE);
        (s[2], c[2]) = (SEL_UNWRAP_MIN, FEE_CLASS_AMOUNT);
        (s[3], c[3]) = (SEL_WRAP_LEG, FEE_CLASS_ABSOLUTE);
        (s[4], c[4], a[4]) = (SEL_UNWRAP_LEG, FEE_CLASS_AMOUNT, 1);
        (s[5], c[5]) = (SEL_ADD_RESERVE, FEE_CLASS_ABSOLUTE);
        (s[6], c[6]) = (SEL_WRAP_TO_UA, FEE_CLASS_ABSOLUTE);
        (s[7], c[7], a[7]) = (SEL_UNWRAP_TO_UA, FEE_CLASS_AMOUNT, 1);
        (s[8], c[8]) = (this.mtxShield.selector, FEE_CLASS_ABSOLUTE);
        (s[9], c[9]) = (this.mtxConfidentialTransfer.selector, FEE_CLASS_ABSOLUTE);
        (s[10], c[10]) = (this.mtxConfidentialTransferCompact.selector, FEE_CLASS_ABSOLUTE);
        (s[11], c[11]) = (this.mtxUnshield.selector, FEE_CLASS_ABSOLUTE);
        (s[12], c[12]) = (this.mtxWrapShield.selector, FEE_CLASS_ABSOLUTE);
        (s[13], c[13]) = (this.mtxUnshieldUnwrap.selector, FEE_CLASS_ABSOLUTE);
        (s[14], c[14]) = (this.mtxConfidentialTransferSingle.selector, FEE_CLASS_ABSOLUTE);
        (s[15], c[15]) = (this.mtxConfidentialTransferSingleCompact.selector, FEE_CLASS_ABSOLUTE);
        (s[16], c[16]) = (this.mtxRollOver.selector, FEE_CLASS_ABSOLUTE);
        (s[17], c[17]) = (this.mtxPrepareAcc.selector, FEE_CLASS_ABSOLUTE);
    }

    function _mtxRule(bytes4 sel) internal view override(WrappedToken, MetaTxBase) returns (MtxRule memory) {
        if (sel == this.mtxWrapShield.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 100);
        if (_isPqzOp(sel)) return _pqzRule(sel);
        return WrappedToken._mtxRule(sel);
    }

    /// @notice The leg paths of `WrappedToken` and the PQZ ops; not `mtxWrapShield` (the pool holds no leg).
    function _uaAllowed(bytes4 sel) internal view override(WrappedToken, ERC20MetaTx) returns (bool) {
        return (_isPqzOp(sel) && sel != this.mtxWrapShield.selector) || WrappedToken._uaAllowed(sel);
    }
}
