// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTokenBase} from "./MetaTokenBase.sol";
import {AdminLib} from "./AdminLib.sol";
import {WrappedLib} from "./WrappedLib.sol";
import {IWrappedToken} from "./IWrappedToken.sol";
import {MetaTxBase} from "./MetaTxBase.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {UAKinds} from "../ua/UAKinds.sol";

/// @title Kind `WRAPPED` (CTR-TOK-21): a wrapper of 1–8 legs, each an ERC-20 or the native coin (CTR-TOK-26), at
///        per-leg rates `num/den`, with internal per-leg reserves; the logic is in `WrappedLib`.
/// @notice Any-of (CTR-TOK-07): wrap one chosen leg, unwrap into one chosen leg, bounded by that leg's reserve. The
///         single-asset ABI (`wrap(amount)`, `unwrap(amount, recipient[, minOut])`) works only with exactly one leg
///         (`UnderlyingRequired`). Flags (CTR-TOK-22): `PAYABLE`, `RATE_ADJUSTABLE` (role rateAdmin, a contract:
///         timelocked rate changes), `WRAP_DISABLEABLE` (role guardian: one-way `disableWrap`). Built by
///         `OpenFactory.createToken` (CTR-TOK-25) from `legs` and `rate`; `initialSupply`, `initialHolder`, `conf`
///         must be empty.
contract WrappedToken is MetaTokenBase, IWrappedToken {
    uint256 public constant RATE_WINDOW = WrappedLib.RATE_WINDOW;

    bytes4 internal constant SEL_WRAP = bytes4(keccak256("wrap(uint256)"));
    bytes4 internal constant SEL_UNWRAP_MIN = bytes4(keccak256("unwrap(uint256,address,uint256)"));
    bytes4 internal constant SEL_WRAP_LEG = bytes4(keccak256("wrap(address,uint256)"));
    bytes4 internal constant SEL_UNWRAP_LEG = bytes4(keccak256("unwrap(address,uint256,address,uint256)"));
    bytes4 internal constant SEL_ADD_RESERVE = bytes4(keccak256("addReserve(address,uint256)"));
    bytes4 internal constant SEL_WRAP_TO_UA = bytes4(keccak256("wrapToUA(address,uint256,bytes32)"));
    bytes4 internal constant SEL_UNWRAP_TO_UA = bytes4(keccak256("unwrapToUA(address,uint256,bytes32,uint256)"));

    /// @dev The factory's append (`OpenFactory.deployImplementation`, plan 5g-Z2): the release's `Env`; this kind takes
    ///      no `implArgs`.
    constructor(uint16, Env memory env, bytes memory) MetaTokenBase(env) {}

    function kind() public pure virtual override returns (uint8) {
        return AdminLib.KIND_WRAPPED;
    }

    /// @dev `initialSupply`, `initialHolder`, `conf` must be empty; legs and rate are checked in `WrappedLib`.
    function _init(TokenConfig memory cfg) internal virtual override {
        _requireUnused(cfg, true, false, false, true);
        WrappedLib.initToken(cfg, IS_HEDERA, AdminLib.KIND_WRAPPED);
    }

    // ------------------------------------------------------------------ wrap / unwrap / reserve

    /// @notice Single-asset ABI. Mints the MEASURED amount received at the leg's rate, rounded down.
    function wrap(uint256 amount) external payable nonReentrant returns (uint256) {
        return _wrap(WrappedLib.sole(), amount, 0);
    }

    function wrap(address u, uint256 amount) external payable nonReentrant returns (uint256) {
        return _wrap(WrappedLib.indexOf(u), amount, 0);
    }

    /// @notice `wrap(u, amount)` minted into the registered SIGNING UA `to` (CTR-UA-28), the receiver checked first.
    ///         Address allowlist `ABSOLUTE`: relayed, the native leg reverts (no coin in a self-call).
    function wrapToUA(address u, uint256 amount, bytes32 to) external payable nonReentrant returns (uint256) {
        _requireDerivedReceiver(to);
        return _wrap(WrappedLib.indexOf(u), amount, to);
    }

    /// @notice Single-asset ABI, `minOut = 0`; not allowlisted.
    function unwrap(uint256 wrapped, address recipient) external nonReentrant returns (uint256 out) {
        (out,) = _unwrap(WrappedLib.sole(), wrapped, recipient, 0);
    }

    function unwrap(uint256 wrapped, address recipient, uint256 minOut) external nonReentrant returns (uint256 out) {
        (out,) = _unwrap(WrappedLib.sole(), wrapped, recipient, minOut);
    }

    function unwrap(address u, uint256 wrapped, address recipient, uint256 minOut)
        external nonReentrant returns (uint256 out, uint256 burned)
    {
        return _unwrap(WrappedLib.indexOf(u), wrapped, recipient, minOut);
    }

    /// @notice `unwrap(u, …)` paid into `to` in leg `u`'s UA ledger (CTR-UA-28): burns from the subject (a native, or a
    ///         UA through `UA_POOL` under `uaExecute`) before the one outside call, the leg's `transferToUA`.
    function unwrapToUA(address u, uint256 wrapped, bytes32 to, uint256 minOut)
        external nonReentrant returns (uint256 out, uint256 burned)
    {
        uint256 i = WrappedLib.indexOf(u);
        (out, burned) = WrappedLib.quoteUnwrapToUA(i, wrapped, minOut);
        address from = _msgSender();
        _burn(from, burned);
        WrappedLib.payOutToUA(i, to, out);
        emit UnwrappedToUA(from, u, to, burned, out);
    }

    /// @notice Anyone; no mint. Over-collateralises before a rate decrease; otherwise a donation to every holder.
    function addReserve(address u, uint256 amount) external payable nonReentrant {
        address from = _msgSender();
        emit ReserveAdded(from, u, WrappedLib.addReserve(WrappedLib.indexOf(u), amount, from, msg.value));
    }

    /// @notice Signature wrap of a SCaaS underlying (CTR-TOK-20): mints `minted − fee` to `o.destination` (or
    ///         `o.from`) and `fee` to the submitter. Not allowlisted: a direct read of the caller (the submitter).
    function mtxWrap(address u, TradeOrder calldata o, bytes calldata sig)
        external nonReentrant returns (uint256 minted)
    {
        uint256 received;
        uint256 fee;
        (received, minted, fee) = WrappedLib.wrapBySig(u, o, sig, msg.sender);
        address to = o.destination == address(0) ? o.from : o.destination;
        _mint(to, minted - fee);
        if (fee != 0) _mint(msg.sender, fee);
        emit Wrapped(to, u, received, minted - fee);
    }

    /// @notice `mtxWrap` for a `UATradeOrder` (CTR-TOK-20, UA-5b): the underlying's `uaTrade` checks the holder (a
    ///         derived id under purpose `trade`, a native id itself); `minted − fee` goes to `o.destination` (0 ⇒
    ///         `o.from`) — a derived id by `_uaMint` (registered SIGNING), a native one by `_mint` — and `fee` to the
    ///         submitter. Not allowlisted: a direct read of the caller.
    function uaWrap(address u, UATradeOrder calldata o, bytes calldata auth)
        external nonReentrant returns (uint256 minted)
    {
        uint256 received;
        uint256 fee;
        (received, minted, fee) = WrappedLib.wrapBySigUA(u, o, auth, msg.sender);
        bytes32 to = o.destination == 0 ? o.from : o.destination;
        if (UAKinds.inNativeSpace(to)) _mint(address(uint160(uint256(to))), minted - fee);
        else _uaMint(to, minted - fee);
        if (fee != 0) _mint(msg.sender, fee);
        emit UAWrapped(to, u, received, minted - fee);
    }

    /// @dev `to == 0` is a sentinel, "mint to the caller", not a receiver; any other `to` is minted into that derived UA
    ///      as a move from 0, unchecked here: a caller passing a `to` must validate it first (`wrapToUA`:
    ///      `_requireDerivedReceiver`, which also refuses 0 as a native id).
    function _wrap(uint256 i, uint256 amount, bytes32 to) private returns (uint256 minted) {
        address account = _msgSender();
        (address u, uint256 received, uint256 m) = WrappedLib.wrap(i, amount, account, msg.value);
        minted = m;
        if (to == 0) _mint(account, minted);
        else _uaMove(0, to, minted);
        emit Wrapped(account, u, received, minted);
    }

    /// @dev Burn before the one outside call (CEI), under the contract-wide guard.
    function _unwrap(uint256 i, uint256 wrapped, address recipient, uint256 minOut)
        private returns (uint256 out, uint256 burned)
    {
        (out, burned) = WrappedLib.quoteUnwrap(i, wrapped, recipient, minOut);
        address from = _msgSender();
        _burn(from, burned);
        address u = WrappedLib.payOut(i, recipient, out);
        emit Unwrapped(from, u, recipient, burned, out);
    }

    // ------------------------------------------------------------------ roles: guardian, rate admin

    function disableWrap(address u, bytes32 reason) external nonReentrant {
        WrappedLib.disableWrap(u, reason, _msgSender());
    }

    function proposeRate(address u, uint96 num, uint96 den) external nonReentrant {
        WrappedLib.proposeRate(u, num, den, _msgSender());
    }

    function cancelRate() external nonReentrant {
        WrappedLib.cancelRate(_msgSender());
    }

    function executeRate() external virtual nonReentrant {
        WrappedLib.executeRate(_msgSender(), totalSupply());
    }

    /// @notice `disableFeature(RATE_ADJUSTABLE)` also cancels a pending rate change (CTR-TOK-06).
    function disableFeature(uint8 bit) external virtual override nonReentrant {
        AdminLib.disableFeature(bit, _msgSender());
        if (bit == AdminLib.RATE_ADJUSTABLE) WrappedLib.dropPending();
    }

    // ------------------------------------------------------------------ allowlist (CTR-MTX-19)

    /// @notice `cancelNonce` (base); `wrap(uint256)`, `wrap(address,uint256)`, `addReserve` `ABSOLUTE` (fee from the
    ///         minted units or the caller's balance); `unwrap(uint256,address,uint256)` `AMOUNT(0)`,
    ///         `unwrap(address,uint256,address,uint256)` `AMOUNT(1)` (gasless unwrap, CTR-MTX-12); UA-5a (CTR-UA-28)
    ///         `wrapToUA` `ABSOLUTE`, `unwrapToUA` `AMOUNT(1)`. The two-argument `unwrap` is not listed (same intent,
    ///         second digest, no `minOut`).
    function mtxSelectors()
        public pure virtual override(IMetaTx, MetaTxBase) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](8);
        c = new uint8[](8);
        a = new uint8[](8);
        (s[0], c[0]) = (this.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (SEL_WRAP, FEE_CLASS_ABSOLUTE);
        (s[2], c[2]) = (SEL_UNWRAP_MIN, FEE_CLASS_AMOUNT);
        (s[3], c[3]) = (SEL_WRAP_LEG, FEE_CLASS_ABSOLUTE);
        (s[4], c[4], a[4]) = (SEL_UNWRAP_LEG, FEE_CLASS_AMOUNT, 1);
        (s[5], c[5]) = (SEL_ADD_RESERVE, FEE_CLASS_ABSOLUTE);
        (s[6], c[6]) = (SEL_WRAP_TO_UA, FEE_CLASS_ABSOLUTE);
        (s[7], c[7], a[7]) = (SEL_UNWRAP_TO_UA, FEE_CLASS_AMOUNT, 1);
    }

    /// @notice The UA allowlist (CTR-UA-26): the two `unwrap`s with `minOut` and `unwrapToUA` (a derived signer burns
    ///         its UA balance).
    function _uaAllowed(bytes4 sel) internal view virtual override returns (bool) {
        return sel == SEL_UNWRAP_MIN || sel == SEL_UNWRAP_LEG || sel == SEL_UNWRAP_TO_UA;
    }

    function _mtxRule(bytes4 sel) internal view virtual override returns (MtxRule memory) {
        if (sel == SEL_WRAP) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 36);
        if (sel == SEL_UNWRAP_MIN) return MtxRule(FEE_CLASS_AMOUNT, 0, 100);
        if (sel == SEL_WRAP_LEG) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 68);
        if (sel == SEL_UNWRAP_LEG) return MtxRule(FEE_CLASS_AMOUNT, 1, 132);
        if (sel == SEL_ADD_RESERVE) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 68);
        if (sel == SEL_WRAP_TO_UA) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 100);
        if (sel == SEL_UNWRAP_TO_UA) return MtxRule(FEE_CLASS_AMOUNT, 1, 132);
        return super._mtxRule(sel);
    }

    // ------------------------------------------------------------------ views

    /// @notice The one underlying of a one-leg token (`address(0)` for the native coin); `address(0)` with more legs.
    function underlying() external view returns (address) {
        WrappedLib.WrappedStorage storage s = WrappedLib.$();
        return s.legCount == 1 ? s.legs[0].token : address(0);
    }

    function underlyings() public view virtual override(IWrappedToken, MetaTokenBase) returns (address[] memory us) {
        WrappedLib.WrappedStorage storage s = WrappedLib.$();
        uint256 n = s.legCount;
        us = new address[](n);
        for (uint256 i; i < n; ++i) us[i] = s.legs[i].token;
    }

    function legOf(address u)
        external view returns (uint96 num, uint96 den, uint256 reserve, uint8 decimals_, bool wrapEnabled)
    {
        WrappedLib.Leg storage L = WrappedLib.$().legs[WrappedLib.indexOf(u)];
        return (L.num, L.den, L.reserve, L.decimals, L.wrapEnabled);
    }

    /// @notice `Σ⌊reserve_i·num_i/den_i⌋`, saturating at `type(uint256).max` instead of overflowing.
    function collateralValue() external view returns (uint256) {
        return WrappedLib.collateralValue();
    }

    /// @notice `(⌊amount·q⌋, ⌈minted/q⌉)`: clients round `amount` down to `used` so no dust stays in the reserve.
    ///         Ignores fee-on-transfer (assumes `received == amount`).
    function previewWrap(address u, uint256 amount) external view returns (uint256 minted, uint256 used) {
        return WrappedLib.previewWrap(u, amount);
    }

    function previewUnwrap(address u, uint256 wrapped) external view returns (uint256 out, uint256 burned) {
        return WrappedLib.previewUnwrap(u, wrapped);
    }

    function rateAdjustable() external view returns (bool) {
        return AdminLib.hasFeature(AdminLib.RATE_ADJUSTABLE);
    }

    function rateDelay() external view returns (uint32) {
        return WrappedLib.$().rateDelay;
    }

    function maxRateStepBps() external view returns (uint16) {
        return WrappedLib.$().maxRateStepBps;
    }

    /// @notice All zero when nothing is pending or the pending change has expired.
    function pendingRate() external view returns (address u, uint96 num, uint96 den, uint64 eta) {
        if (!WrappedLib.isPending()) return (address(0), 0, 0, 0);
        WrappedLib.WrappedStorage storage s = WrappedLib.$();
        WrappedLib.PendingRate memory p = s.pending;
        return (s.legs[p.leg].token, p.num, p.den, p.eta);
    }
}
