// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MetaTokenBase} from "./MetaTokenBase.sol";
import {AdminLib} from "./AdminLib.sol";
import {UnderlyingLib} from "./UnderlyingLib.sol";
import {IUnderlyingToken} from "./IUnderlyingToken.sol";
import {MetaTxBase} from "./MetaTxBase.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {IOpenFactoryV2} from "../common/IOpenFactoryV2.sol";

/// @title Kind `UNDERLYING` (CTR-TOK-21): a wrapper of 1–8 legs, each an ERC-20 or the native coin (CTR-TOK-26), at
///        per-leg rates `num/den`, with internal per-leg reserves; the logic is in `UnderlyingLib`.
/// @notice Any-of (CTR-TOK-07): wrap one chosen leg, unwrap into one chosen leg, bounded by that leg's reserve. The
///         single-asset ABI (`wrap(amount)`, `unwrap(amount, recipient[, minOut])`) works only with exactly one leg
///         (`UnderlyingRequired`). Flags (CTR-TOK-22): `PAYABLE`, `RATE_ADJUSTABLE` (role rateAdmin, a contract:
///         timelocked rate changes), `WRAP_DISABLEABLE` (role guardian: one-way `disableWrap`). Built by the factory
///         through `initialize(creator, underlyings, version, abi.encode(UnderlyingInit))`; P1e switches to
///         `TokenConfig`.
contract UnderlyingToken is MetaTokenBase, IUnderlyingToken {
    uint256 public constant RATE_WINDOW = UnderlyingLib.RATE_WINDOW;

    bytes4 internal constant SEL_WRAP = bytes4(keccak256("wrap(uint256)"));
    bytes4 internal constant SEL_UNWRAP_MIN = bytes4(keccak256("unwrap(uint256,address,uint256)"));
    bytes4 internal constant SEL_WRAP_LEG = bytes4(keccak256("wrap(address,uint256)"));
    bytes4 internal constant SEL_UNWRAP_LEG = bytes4(keccak256("unwrap(address,uint256,address,uint256)"));
    bytes4 internal constant SEL_ADD_RESERVE = bytes4(keccak256("addReserve(address,uint256)"));

    constructor(address factory_, address smartKeyAccountImpl_, bytes32 chainUid_, bool isHedera_)
        MetaTokenBase(factory_, smartKeyAccountImpl_, chainUid_, isHedera_)
    {}

    /// @dev Transitional: factory v2's `META_SINGLE` takes 1–8 legs (P1e replaces the enum).
    function tokenKind() external pure override returns (IOpenFactoryV2.TokenKind) {
        return IOpenFactoryV2.TokenKind.META_SINGLE;
    }

    /// @param initData `abi.encode(UnderlyingInit)`; decoded and checked in `UnderlyingLib.initToken`.
    function _init(address, address[] calldata us, bytes calldata initData) internal override {
        UnderlyingLib.initToken(us, initData, IS_HEDERA);
    }

    // ------------------------------------------------------------------ wrap / unwrap / reserve

    /// @notice Single-asset ABI. Mints the MEASURED amount received at the leg's rate, rounded down.
    function wrap(uint256 amount) external payable nonReentrant returns (uint256) {
        return _wrap(UnderlyingLib.sole(), amount);
    }

    function wrap(address u, uint256 amount) external payable nonReentrant returns (uint256) {
        return _wrap(UnderlyingLib.indexOf(u), amount);
    }

    /// @notice Single-asset ABI, `minOut = 0`; not allowlisted.
    function unwrap(uint256 wrapped, address recipient) external nonReentrant returns (uint256 out) {
        (out,) = _unwrap(UnderlyingLib.sole(), wrapped, recipient, 0);
    }

    function unwrap(uint256 wrapped, address recipient, uint256 minOut) external nonReentrant returns (uint256 out) {
        (out,) = _unwrap(UnderlyingLib.sole(), wrapped, recipient, minOut);
    }

    function unwrap(address u, uint256 wrapped, address recipient, uint256 minOut)
        external nonReentrant returns (uint256 out, uint256 burned)
    {
        return _unwrap(UnderlyingLib.indexOf(u), wrapped, recipient, minOut);
    }

    /// @notice Anyone; no mint. Over-collateralises before a rate decrease; otherwise a donation to every holder.
    function addReserve(address u, uint256 amount) external payable nonReentrant {
        address from = _msgSender();
        emit ReserveAdded(from, u, UnderlyingLib.addReserve(UnderlyingLib.indexOf(u), amount, from, msg.value));
    }

    function _wrap(uint256 i, uint256 amount) private returns (uint256 minted) {
        address account = _msgSender();
        (address u, uint256 received, uint256 m) = UnderlyingLib.wrap(i, amount, account, msg.value);
        minted = m;
        _mint(account, minted);
        emit Wrapped(account, u, received, minted);
    }

    /// @dev Burn before the one outside call (CEI), under the contract-wide guard.
    function _unwrap(uint256 i, uint256 wrapped, address recipient, uint256 minOut)
        private returns (uint256 out, uint256 burned)
    {
        (out, burned) = UnderlyingLib.quoteUnwrap(i, wrapped, recipient, minOut);
        address from = _msgSender();
        _burn(from, burned);
        address u = UnderlyingLib.payOut(i, recipient, out);
        emit Unwrapped(from, u, recipient, burned, out);
    }

    // ------------------------------------------------------------------ roles: guardian, rate admin

    function disableWrap(address u, bytes32 reason) external {
        UnderlyingLib.disableWrap(u, reason, _msgSender());
    }

    function proposeRate(address u, uint96 num, uint96 den) external {
        UnderlyingLib.proposeRate(u, num, den, _msgSender());
    }

    function cancelRate() external {
        UnderlyingLib.cancelRate(_msgSender());
    }

    function executeRate() external {
        UnderlyingLib.executeRate(_msgSender(), totalSupply());
    }

    /// @notice `disableFeature(RATE_ADJUSTABLE)` also cancels a pending rate change (CTR-TOK-06).
    function disableFeature(uint8 bit) external override {
        AdminLib.disableFeature(bit, _msgSender());
        if (bit == AdminLib.RATE_ADJUSTABLE) UnderlyingLib.dropPending();
    }

    // ------------------------------------------------------------------ allowlist (CTR-MTX-19)

    /// @notice `cancelNonce` (base); `wrap(uint256)`, `wrap(address,uint256)`, `addReserve` `ABSOLUTE` (fee from the
    ///         minted units or the caller's balance); `unwrap(uint256,address,uint256)` `AMOUNT(0)`,
    ///         `unwrap(address,uint256,address,uint256)` `AMOUNT(1)` (gasless unwrap, CTR-MTX-12). The two-argument
    ///         `unwrap` is not listed (same intent, second digest, no `minOut`).
    function mtxSelectors()
        public pure override(IMetaTx, MetaTxBase) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](6);
        c = new uint8[](6);
        a = new uint8[](6);
        (s[0], c[0]) = (this.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (SEL_WRAP, FEE_CLASS_ABSOLUTE);
        (s[2], c[2]) = (SEL_UNWRAP_MIN, FEE_CLASS_AMOUNT);
        (s[3], c[3]) = (SEL_WRAP_LEG, FEE_CLASS_ABSOLUTE);
        (s[4], c[4], a[4]) = (SEL_UNWRAP_LEG, FEE_CLASS_AMOUNT, 1);
        (s[5], c[5]) = (SEL_ADD_RESERVE, FEE_CLASS_ABSOLUTE);
    }

    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
        if (sel == SEL_WRAP) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 36);
        if (sel == SEL_UNWRAP_MIN) return MtxRule(FEE_CLASS_AMOUNT, 0, 100);
        if (sel == SEL_WRAP_LEG) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 68);
        if (sel == SEL_UNWRAP_LEG) return MtxRule(FEE_CLASS_AMOUNT, 1, 132);
        if (sel == SEL_ADD_RESERVE) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 68);
        return super._mtxRule(sel);
    }

    // ------------------------------------------------------------------ views

    /// @notice The one underlying of a one-leg token (`address(0)` for the native coin); `address(0)` with more legs.
    function underlying() external view returns (address) {
        UnderlyingLib.UnderlyingStorage storage s = UnderlyingLib.$();
        return s.legCount == 1 ? s.legs[0].token : address(0);
    }

    function underlyings() external view returns (address[] memory us) {
        UnderlyingLib.UnderlyingStorage storage s = UnderlyingLib.$();
        uint256 n = s.legCount;
        us = new address[](n);
        for (uint256 i; i < n; ++i) us[i] = s.legs[i].token;
    }

    function legOf(address u)
        external view returns (uint96 num, uint96 den, uint256 reserve, uint8 decimals_, bool wrapEnabled)
    {
        UnderlyingLib.Leg storage L = UnderlyingLib.$().legs[UnderlyingLib.indexOf(u)];
        return (L.num, L.den, L.reserve, L.decimals, L.wrapEnabled);
    }

    /// @notice `Σ⌊reserve_i·num_i/den_i⌋`, saturating at `type(uint256).max` instead of overflowing.
    function collateralValue() external view returns (uint256) {
        return UnderlyingLib.collateralValue();
    }

    /// @notice `(⌊amount·q⌋, ⌈minted/q⌉)`: clients round `amount` down to `used` so no dust stays in the reserve.
    ///         Ignores fee-on-transfer (assumes `received == amount`).
    function previewWrap(address u, uint256 amount) external view returns (uint256 minted, uint256 used) {
        return UnderlyingLib.previewWrap(u, amount);
    }

    function previewUnwrap(address u, uint256 wrapped) external view returns (uint256 out, uint256 burned) {
        return UnderlyingLib.previewUnwrap(u, wrapped);
    }

    function rateAdjustable() external view returns (bool) {
        return AdminLib.hasFeature(AdminLib.RATE_ADJUSTABLE);
    }

    function rateDelay() external view returns (uint32) {
        return UnderlyingLib.$().rateDelay;
    }

    function maxRateStepBps() external view returns (uint16) {
        return UnderlyingLib.$().maxRateStepBps;
    }

    /// @notice All zero when nothing is pending or the pending change has expired.
    function pendingRate() external view returns (address u, uint96 num, uint96 den, uint64 eta) {
        if (!UnderlyingLib.isPending()) return (address(0), 0, 0, 0);
        UnderlyingLib.UnderlyingStorage storage s = UnderlyingLib.$();
        UnderlyingLib.PendingRate memory p = s.pending;
        return (s.legs[p.leg].token, p.num, p.den, p.eta);
    }
}
