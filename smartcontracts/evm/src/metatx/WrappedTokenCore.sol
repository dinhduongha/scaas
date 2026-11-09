// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;
import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {ITradeToken} from "../trade/ITradeToken.sol";

import {MetaTokenBase} from "./MetaTokenBase.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceUse} from "../governance/GovernanceBase.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {TokenStore} from "./TokenStore.sol";
import {WrappedLib} from "./WrappedLib.sol";
import {IWrappedToken} from "./IWrappedToken.sol";
import {MetaTxBase, MetaTxBaseCore} from "./MetaTxBase.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title Kind `WRAPPED` (CTR-TOK-21): a wrapper of 1–8 legs, each an ERC-20 or the native coin (CTR-TOK-26), at
///        per-leg rates `num/den`, with internal per-leg reserves; the logic is in `WrappedLib`.
/// @notice Any-of (CTR-TOK-07): wrap one chosen leg, unwrap into one chosen leg, bounded by that leg's reserve. The
///         single-asset ABI (`wrap(amount)`, `unwrap(amount, recipient[, minOut])`) works only with exactly one leg
///         (`UnderlyingRequired`). Flags (CTR-TOK-22): `PAYABLE`, `RATE_ADJUSTABLE` (role rateAdmin, a contract:
///         timelocked rate changes), `WRAP_DISABLEABLE` (role guardian: one-way `disableWrap`). Built by
///         `OpenFactory.createToken` (CTR-TOK-25) from `legs` and `rate`; `initialSupply`, `initialHolder`, `conf`
///         must be empty.
abstract contract WrappedTokenCore is MetaTokenBase {
    uint256 public constant RATE_WINDOW = WrappedLib.RATE_WINDOW;

    bytes4 internal constant SEL_WRAP = bytes4(keccak256("wrap(uint256)"));
    bytes4 internal constant SEL_UNWRAP_MIN = bytes4(keccak256("unwrap(uint256,address,uint256)"));
    bytes4 internal constant SEL_WRAP_LEG = bytes4(keccak256("wrap(address,uint256)"));
    bytes4 internal constant SEL_UNWRAP_LEG = bytes4(keccak256("unwrap(address,uint256,address,uint256)"));
    bytes4 internal constant SEL_ADD_RESERVE = bytes4(keccak256("addReserve(address,uint256)"));
    bytes4 internal constant SEL_WRAP_TO_UA = bytes4(keccak256("wrapToUA(address,uint256,bytes32)"));
    bytes4 internal constant SEL_UNWRAP_TO_UA = bytes4(keccak256("unwrapToUA(address,uint256,bytes32,uint256)"));


    bytes32 internal constant WRAP_TYPEHASH = keccak256(
        "Wrap(address from,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 internal constant WRAP_LEG_TYPEHASH = keccak256(
        "WrapLeg(address from,address underlying,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 internal constant UA_UNWRAP_TYPEHASH = keccak256(
        "UAUnwrap(bytes32 from,uint256 wrapped,address recipient,uint256 minOut,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 internal constant UA_UNWRAP_LEG_TYPEHASH = keccak256(
        "UAUnwrapLeg(bytes32 from,address underlying,uint256 wrapped,address recipient,uint256 minOut,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 internal constant ADD_RESERVE_TYPEHASH = keccak256(
        "AddReserve(address from,address underlying,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 internal constant WRAP_TO_UA_TYPEHASH = keccak256(
        "WrapToUA(address from,address underlying,uint256 amount,bytes32 to,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 internal constant UA_UNWRAP_TO_UA_TYPEHASH = keccak256(
        "UAUnwrapToUA(bytes32 from,address underlying,uint256 wrapped,bytes32 to,uint256 minOut,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );

    /// @dev The factory's append (`OpenFactory.deployImplementation`, chain-neutral spec §2.1): its address; this kind
    ///      takes no `implArgs`.
    constructor(address factory_, bytes memory) MetaTokenBase(factory_) {}

    function kind() public pure virtual override returns (uint8) {
        return TokenStore.KIND_WRAPPED;
    }

    /// @dev `initialSupply`, `initialHolder`, `conf` must be empty; legs and rate are checked in `WrappedLib`.
    function _validBits() internal pure virtual override returns (uint256) {
        return GovernanceBits.WRAPPED_BITS;
    }

    /// @dev The `WRAPPED*` masks (spec §1.2): roles 1, 3, 4; bit 3 contract-only.
    function _roleBits() internal pure virtual override returns (uint256) { return GovernanceBits.WRAPPED_ROLES; }
    function _contractOnlyBits() internal pure virtual override returns (uint256) { return GovernanceBits.WRAPPED_CONTRACT_ONLY; }

    /// @dev 5-9 are not in the kind's mask: `init` refuses each with `FeatureInvalidForKind` (regulated-kinds spec Q3).
    function _init(IFactoryToken.TokenConfig memory cfg) internal virtual override {
        _requireUnused(cfg, true, false, false, true);
        WrappedLib.initToken(cfg, _hedera(), TokenStore.KIND_WRAPPED, _validBits(), _roleBits(), _contractOnlyBits(),
            _registry());
    }

    // ------------------------------------------------------------------ wrap / unwrap / reserve

    /// @notice Single-asset ABI. Mints the MEASURED amount received at the leg's rate, rounded down.
    function _wrapBody(uint256 amount) internal returns (uint256) {
        return _wrap(WrappedLib.sole(), amount, 0);
    }

    function _wrapBody(address u, uint256 amount) internal returns (uint256) {
        return _wrap(WrappedLib.indexOf(u), amount, 0);
    }

    /// @notice `wrap(u, amount)` minted into the registered SIGNING UA `to` (CTR-UA-28), the receiver checked first.
    ///         Address allowlist `ABSOLUTE`: relayed, the native leg reverts (no coin in a self-call).
    function _wrapToUABody(address u, uint256 amount, bytes32 to) internal returns (uint256) {
        _requireDerivedReceiver(to);
        return _wrap(WrappedLib.indexOf(u), amount, to);
    }

    /// @notice Single-asset ABI, `minOut = 0`; not allowlisted.
    function _unwrapBody(uint256 wrapped, address recipient) internal returns (uint256 out) {
        (out,) = _unwrap(WrappedLib.sole(), wrapped, recipient, 0);
    }

    function _unwrapBody(uint256 wrapped, address recipient, uint256 minOut) internal returns (uint256 out) {
        (out,) = _unwrap(WrappedLib.sole(), wrapped, recipient, minOut);
    }

    function _unwrapBody(address u, uint256 wrapped, address recipient, uint256 minOut) internal returns (uint256 out, uint256 burned)
    {
        return _unwrap(WrappedLib.indexOf(u), wrapped, recipient, minOut);
    }

    /// @notice `unwrap(u, …)` paid into `to` in leg `u`'s UA ledger (CTR-UA-28): burns from the subject (a native, or a
    ///         UA through `UA_POOL` under `mtxExecute`) before the one outside call, the leg's `transferToUA`.
    function _unwrapToUABody(address u, uint256 wrapped, bytes32 to, uint256 minOut) internal returns (uint256 out, uint256 burned)
    {
        uint256 i = WrappedLib.indexOf(u);
        (out, burned) = WrappedLib.quoteUnwrapToUA(i, wrapped, minOut);
        address from = _msgSender();
        _burn(from, burned);
        WrappedLib.payOutToUA(i, to, out);
        emit IWrappedToken.UnwrappedToUA(from, u, to, burned, out);
    }

    /// @notice Anyone; no mint. Over-collateralises before a rate decrease; otherwise a donation to every holder.
    function _addReserveBody(address u, uint256 amount) internal {
        address from = _msgSender();
        emit IWrappedToken.ReserveAdded(from, u, WrappedLib.addReserve(WrappedLib.indexOf(u), amount, from, msg.value));
    }

    // ------------------------------------------------------------------ named typed entries (TS-D14)

    /// @notice The signed `wrap(amount)`, `ABSOLUTE` as on the generic path, like every wrap and `addReserve` below.
    function _mtxWrapBody(MetaTxLib.Envelope calldata e, uint256 amount, bytes calldata sig) internal returns (bytes memory)
    {
        return _named(WRAP_TYPEHASH, SEL_WRAP, e, abi.encode(amount), sig);
    }

    function _mtxWrapLegBody(MetaTxLib.Envelope calldata e, address u, uint256 amount, bytes calldata sig) internal returns (bytes memory)
    {
        return _named(WRAP_LEG_TYPEHASH, SEL_WRAP_LEG, e, abi.encode(u, amount), sig);
    }

    function _mtxWrapToUABody(MetaTxLib.Envelope calldata e, address u, uint256 amount, bytes32 to, bytes calldata sig) internal returns (bytes memory)
    {
        return _named(WRAP_TO_UA_TYPEHASH, SEL_WRAP_TO_UA, e, abi.encode(u, amount, to), sig);
    }

    function _mtxAddReserveBody(MetaTxLib.Envelope calldata e, address u, uint256 amount, bytes calldata sig) internal returns (bytes memory)
    {
        return _named(ADD_RESERVE_TYPEHASH, SEL_ADD_RESERVE, e, abi.encode(u, amount), sig);
    }

    /// @notice The signed `unwrap(wrapped, recipient, minOut)`, `AMOUNT(0)` as on the generic path; the other unwraps
    ///         `AMOUNT(1)`, the basis `wrapped`. ua-mtx-merge R23: today's `ua*` bodies under the `mtx*` names, for native
    ///         and derived ids (a native one by its own key, no registry; a derived UA through the registry).
    function _mtxUnwrapBody(MetaTxLib.UAEnvelope calldata e, uint256 wrapped, address recipient, uint256 minOut,
        IUARegistry.UASig calldata auth) internal returns (bytes memory)
    {
        return _namedUA(UA_UNWRAP_TYPEHASH, SEL_UNWRAP_MIN, e, abi.encode(wrapped, recipient, minOut), auth);
    }

    function _mtxUnwrapLegBody(MetaTxLib.UAEnvelope calldata e, address u, uint256 wrapped, address recipient, uint256 minOut,
        IUARegistry.UASig calldata auth) internal returns (bytes memory)
    {
        return _namedUA(UA_UNWRAP_LEG_TYPEHASH, SEL_UNWRAP_LEG, e, abi.encode(u, wrapped, recipient, minOut), auth);
    }

    function _mtxUnwrapToUABody(MetaTxLib.UAEnvelope calldata e, address u, uint256 wrapped, bytes32 to, uint256 minOut,
        IUARegistry.UASig calldata auth) internal returns (bytes memory)
    {
        return _namedUA(UA_UNWRAP_TO_UA_TYPEHASH, SEL_UNWRAP_TO_UA, e, abi.encode(u, wrapped, to, minOut), auth);
    }

    /// @notice Signature wrap of a SCaaS underlying by a `UAWrapOrder` (CTR-TOK-20, UA-5b; ua-mtx-merge R39: today's
    ///         `uaWrapOrder` under this name): the underlying's `mtxTrade` checks the holder (a derived id under purpose
    ///         `trade`, a native id itself); `minted − fee` goes to `o.destination` (0 ⇒ `o.from`) — a derived id by
    ///         `_uaMint` (registered SIGNING), a native one by `_mint` — and `fee` to the submitter. Not allowlisted: a
    ///         direct read of the caller.
    function _mtxWrapOrderBody(address u, ITradeToken.UAWrapOrder calldata o, IUARegistry.UASig calldata auth) internal returns (uint256 minted)
    {
        if (o.destination != 0 && o.destination != o.from) _regSender(o.from);
        uint256 received;
        uint256 fee;
        (received, minted, fee) = WrappedLib.wrapBySigUA(u, o, auth, msg.sender, totalSupply());
        _regFeeTo(MetaTxLib.pad(msg.sender), fee);
        bytes32 to = o.destination == 0 ? o.from : o.destination;
        if (UAKinds.inNativeSpace(to)) _mint(address(uint160(uint256(to))), minted - fee);
        else _uaMint(to, minted - fee);
        if (fee != 0) _mint(msg.sender, fee);
        emit IWrappedToken.UAWrapped(to, u, received, minted - fee);
    }

    /// @dev `to == 0` is a sentinel, "mint to the caller", not a receiver; any other `to` is minted into that derived UA
    ///      as a move from 0, unchecked here: a caller passing a `to` must validate it first (`wrapToUA`:
    ///      `_requireDerivedReceiver`, which also refuses 0 as a native id).
    function _wrap(uint256 i, uint256 amount, bytes32 to) private returns (uint256 minted) {
        if (to != 0) _regPayer();
        address account = _msgSender();
        (address u, uint256 received, uint256 m) = WrappedLib.wrap(i, amount, account, msg.value, totalSupply());
        minted = m;
        if (to == 0) _mint(account, minted);
        else _uaMove(0, to, minted);
        emit IWrappedToken.Wrapped(account, u, received, minted);
    }

    /// @dev Burn before the one outside call (CEI), under the contract-wide guard.
    function _unwrap(uint256 i, uint256 wrapped, address recipient, uint256 minOut)
        private returns (uint256 out, uint256 burned)
    {
        (out, burned) = WrappedLib.quoteUnwrap(i, wrapped, recipient, minOut);
        address from = _msgSender();
        _burn(from, burned);
        address u = WrappedLib.payOut(i, recipient, out);
        emit IWrappedToken.Unwrapped(from, u, recipient, burned, out);
    }

    // ------------------------------------------------------------------ the hybrid's issuer (spec §5.2, CTR-GOV-12)

    /// @notice `MINTABLE` and the `minter` role, under `maxSupply`, into a public balance; no reserve moves. Never
    ///         allowlisted, as `NormalToken.mint`.
    function _mintBody(address to, uint256 amount) internal {
        GovernanceUse.use(GovernanceBits.MINTABLE, _govSubject(), amount);
        WrappedLib.checkMint(totalSupply(), amount);
        _mint(to, amount);
    }

    /// @notice `mint` into the registered SIGNING UA `to` (CTR-UA-28), its public UA balance.
    function _mintToUABody(bytes32 to, uint256 amount) internal {
        GovernanceUse.use(GovernanceBits.MINTABLE, _govSubject(), amount);
        WrappedLib.checkMint(totalSupply(), amount);
        _uaMint(to, amount);
    }

    /// @notice Spec §6.2 on `WRAPPED*`: a leg's surplus over its reserve, a foreign asset whole (`WrappedLib.rescue`).
    function _rescueBody(address asset) internal virtual override {
        WrappedLib.rescue(asset);
    }

    // ------------------------------------------------------------------ roles: guardian, rate admin

    function _disableWrapBody(address u, bytes32 reason) internal {
        WrappedLib.disableWrap(u, reason, _govSubject());
    }

    function _proposeRateBody(address u, uint96 num, uint96 den) internal {
        WrappedLib.proposeRate(u, num, den, _govSubject());
    }

    function _cancelRateBody() internal {
        WrappedLib.cancelRate(_govSubject());
    }

    function _executeRateBody() internal virtual {
        WrappedLib.executeRate(_govSubject(), totalSupply());
    }

    /// @notice `disableFeature(RATE_ADJUSTABLE)` also cancels a pending rate change (CTR-TOK-06), once the disable applied.
    function _disableFeatureBody(uint8 bit) internal virtual override {
        bool applied = GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits());
        if (applied && bit == GovernanceBits.RATE_ADJUSTABLE) WrappedLib.dropPending();
    }

    // ------------------------------------------------------------------ allowlist (CTR-MTX-19)

    /// @notice `cancelNonce` (base); `wrap(uint256)`, `wrap(address,uint256)`, `addReserve` `ABSOLUTE` (fee from the
    ///         minted units or the caller's balance); `unwrap(uint256,address,uint256)` `AMOUNT(0)`,
    ///         `unwrap(address,uint256,address,uint256)` `AMOUNT(1)` (gasless unwrap, CTR-MTX-12); UA-5a (CTR-UA-28)
    ///         `wrapToUA` `ABSOLUTE`, `unwrapToUA` `AMOUNT(1)`. The two-argument `unwrap` is not listed (same intent,
    ///         second digest, no `minOut`).
    function _mtxSelectorsBody() internal pure virtual override returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](8);
        c = new uint8[](8);
        a = new uint8[](8);
        (s[0], c[0]) = (IMetaTx.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
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
    function _underlyingBody() internal view returns (address) {
        WrappedLib.WrappedStorage storage s = WrappedLib.$();
        return s.legCount == 1 ? s.legs[0].token : address(0);
    }

    function _underlyingsBody() internal view virtual override returns (address[] memory us) {
        WrappedLib.WrappedStorage storage s = WrappedLib.$();
        uint256 n = s.legCount;
        us = new address[](n);
        for (uint256 i; i < n; ++i) us[i] = s.legs[i].token;
    }

    function _legOfBody(address u) internal view returns (uint96 num, uint96 den, uint256 reserve, uint8 decimals_, bool wrapEnabled)
    {
        WrappedLib.Leg storage L = WrappedLib.$().legs[WrappedLib.indexOf(u)];
        return (L.num, L.den, L.reserve, L.decimals, L.wrapEnabled);
    }

    /// @notice `Σ⌊reserve_i·num_i/den_i⌋`, saturating at `type(uint256).max` instead of overflowing.
    function _collateralValueBody() internal view returns (uint256) {
        return WrappedLib.collateralValue();
    }

    function _maxSupplyBody() internal view returns (uint256) {
        return WrappedLib.$().maxSupply;
    }

    /// @notice `(⌊amount·q⌋, ⌈minted/q⌉)`: clients round `amount` down to `used` so no dust stays in the reserve.
    ///         Ignores fee-on-transfer (assumes `received == amount`).
    function _previewWrapBody(address u, uint256 amount) internal view returns (uint256 minted, uint256 used) {
        return WrappedLib.previewWrap(u, amount);
    }

    function _previewUnwrapBody(address u, uint256 wrapped) internal view returns (uint256 out, uint256 burned) {
        return WrappedLib.previewUnwrap(u, wrapped);
    }

    function _rateAdjustableBody() internal view returns (bool) {
        return GovernanceLib.hasFeature(GovernanceBits.RATE_ADJUSTABLE);
    }

    function _rateDelayBody() internal view returns (uint32) {
        return WrappedLib.$().rateDelay;
    }

    function _maxRateStepBpsBody() internal view returns (uint16) {
        return WrappedLib.$().maxRateStepBps;
    }

    /// @notice All zero when nothing is pending or the pending change has expired.
    function _pendingRateBody() internal view returns (address u, uint96 num, uint96 den, uint64 eta) {
        if (!WrappedLib.isPending()) return (address(0), 0, 0, 0);
        WrappedLib.WrappedStorage storage s = WrappedLib.$();
        WrappedLib.PendingRate memory p = s.pending;
        return (s.legs[p.leg].token, p.num, p.den, p.eta);
    }
}
