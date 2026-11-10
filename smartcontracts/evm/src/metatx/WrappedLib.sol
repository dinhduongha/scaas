// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {IWrappedToken} from "./IWrappedToken.sol";
import {IUALedger} from "./IUALedger.sol";
import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {IOpenFactory} from "../factory/IOpenFactory.sol";
import {IGovernance} from "../governance/IGovernance.sol";
import {IRescuable} from "../governance/IRescuable.sol";
import {ITradeToken} from "../trade/ITradeToken.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceUse} from "../governance/GovernanceBase.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {TokenStore} from "./TokenStore.sol";
import {MetaTokenBase} from "./MetaTokenBase.sol";
import {HederaLib} from "../hedera/HederaLib.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title Legs, reserve and rates of kind `WRAPPED` (CTR-TOK-24), in the ERC-7201 namespace `scaas.underlying`.
/// @notice External library: the core of wrap and unwrap **without a destination** (pull, rate, reserve; pay out),
///         rate changes with timelock, `disableWrap`, the hybrid's cap. The token mints and burns (ERC-20 stays inline)
///         and emits `Wrapped`/`Unwrapped`/`ReserveAdded`.
///
///         Rate `q = num/den` = wrapped raw units per underlying raw unit (CTR-TOK-04); every output rounds DOWN:
///         `minted = ⌊in·q⌋`, `out = ⌊w/q⌋`, unwrap burns only `⌈out·q⌉ ≤ w`. Invariant (CTR-TOK-05):
///         `Σ⌊reserve_i·q_i⌋ ≥ totalSupply()`, not claimed on a hybrid (`maxSupply != 0`, spec §5.3, CTR-GOV-12), whose
///         invariant is `totalSupply() ≤ maxSupply`; `reserve` changes only through wrap, unwrap, `addReserve`; the raw
///         balance never prices anything. The native leg (`address(0)`, CTR-TOK-26) reads `address(this).balance`
///         where an ERC-20 leg reads `balanceOf(this)`.
library WrappedLib {
    using SafeERC20 for IERC20;

    /// @dev slot a: token ‖ decimals ‖ wrapEnabled ‖ adjustable ‖ capped ‖ ctl (copies, so a fixed-rate wrap reads no
    ///      config, a non-hybrid wrap no `maxSupply` and a wrap or unwrap of a token without the wrap limits nothing new;
    ///      `ctl`: group 3l, `CTL_*`); slot b: num ‖ den; slot c: reserve.
    struct Leg {
        address token;
        uint8 decimals;
        bool wrapEnabled;
        bool adjustable;
        bool capped;
        uint8 ctl;
        uint96 num;
        uint96 den;
        uint256 reserve;
    }

    /// @dev One slot; `eta == 0` ⇒ none.
    struct PendingRate {
        uint8 leg;
        uint96 num;
        uint96 den;
        uint56 eta;
    }

    /// @custom:storage-location erc7201:scaas.underlying
    struct WrappedStorage {
        mapping(uint256 => Leg) legs;
        mapping(address => uint256) legIndex; // index + 1
        PendingRate pending;
        uint8 legCount;
        uint32 rateDelay;
        uint16 maxRateStepBps;
        uint256 maxSupply; // spec §5.2: the hybrid's cap, 0 = not a hybrid; immutable
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.underlying")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0x38d6f7edefffa65376a58a6aced8a2c86698d3a0b5d15a785f69ed89d0cd1000;

    address internal constant NATIVE = address(0);
    uint256 internal constant MAX_LEGS = 8;
    uint256 internal constant MAX_RATE = type(uint96).max;
    /// @notice Execution window after `eta`; past it the change counts as none everywhere.
    uint256 internal constant RATE_WINDOW = 7 days;

    function $() internal pure returns (WrappedStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    // ------------------------------------------------------------------ group 3l: the wrap limits' storage (spec §5)

    /// @dev `Leg.ctl`, written on every leg by each applied configuration (spec §5): `TRACK` bit 25 held and the first
    ///      configuration written (`base` and `startMin` move on every wrap and unwrap), `NET` the net rule, `WLIST` /
    ///      `ULIST` the lists. 0: a wrap or an unwrap reads nothing new.
    uint8 internal constant CTL_TRACK = 1;
    uint8 internal constant CTL_NET = 2;
    uint8 internal constant CTL_WLIST = 4;
    uint8 internal constant CTL_ULIST = 8;

    /// @dev Two slots per leg, slot 0 the wrap side and slot 1 the unwrap side, each two limits of 112 bits (`perUser` 24,
    ///      `tokenWide` 64, `periodMin` 24) then `unitExp` (bit 224) and `decayDays` (bit 232): the code reads each side as
    ///      one word at these offsets, which `Layout.t.sol` pins against this declaration. A struct member never nests (a
    ///      nested struct starts a new slot).
    struct LegConfig {
        uint24 wrapShortPerUser;
        uint64 wrapShortTokenWide;
        uint24 wrapShortPeriodMin;
        uint24 wrapLongPerUser;
        uint64 wrapLongTokenWide;
        uint24 wrapLongPeriodMin;
        uint8 unitExp;
        uint16 decayDays;
        uint24 unwrapShortPerUser;
        uint64 unwrapShortTokenWide;
        uint24 unwrapShortPeriodMin;
        uint24 unwrapLongPerUser;
        uint64 unwrapLongTokenWide;
        uint24 unwrapLongPeriodMin;
        uint8 unitExpCopy;
        uint16 decayDaysCopy;
    }

    /// @dev The token-wide windows, slot 0 the wrap side and slot 1 the unwrap side, each two of 88 bits (start 24, minutes on
    ///      the 21-bit circle of the quota word; used 64).
    struct TokenWindows {
        uint24 wrapShortStart;
        uint64 wrapShortUsed;
        uint24 wrapLongStart;
        uint64 wrapLongUsed;
        uint24 unwrapShortStart;
        uint64 unwrapShortUsed;
        uint24 unwrapLongStart;
        uint64 unwrapLongUsed;
    }

    /// @custom:storage-location erc7201:scaas.wraplimit
    struct WrapLimitStorage {
        mapping(uint256 leg => LegConfig) config;
        mapping(uint256 leg => TokenWindows) total;
        /// @dev One word per id and leg (R7, R26; spec §5): by limit id `l` the window start (minutes mod 2^21) at bit 21·l,
        ///      its used quanta (19 bits) at 84 + 19·l; `base` (`b`, quanta, saturating, 32 bits) at 160; `startMin` (`s`, the
        ///      weighted start, an absolute minute, 64 bits) at 192. Not byte-aligned, so a word; `Layout.t.sol` pins it.
        mapping(bytes32 account => mapping(uint256 leg => uint256)) quota;
        mapping(bytes32 account => uint8) member; // bit 0 canWrap, bit 1 canUnwrap
        bytes32 pendingCommit;
        uint64 pendingEta;
        uint32 pendingGeneration; // the owner generation at the proposal
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.wraplimit")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _WRAPLIMIT = 0x8338ae7a3cc0bfc024cc8dc02945ad44a577ebed1c8a715e7136501207e79700;

    /// @dev The window circle (R26): starts and elapsed minutes mod 2^21, `period ≤ 2^20 − 1` minutes (half the circle);
    ///      per-user used counts of 19 bits.
    uint256 private constant _CIRCLE = 1 << 21;
    uint256 private constant _MAX_PERIOD_MIN = (1 << 20) - 1;
    uint256 private constant _MAX_PER_USER = (1 << 19) - 1;
    /// @dev A side word's two `tokenWide` fields, and every field but `unitExp`.
    uint256 private constant _TW = (uint256(type(uint64).max) << 24) | (uint256(type(uint64).max) << 136);
    uint256 private constant _NOT_UNIT = ~(uint256(0xff) << 224);

    function wl() internal pure returns (WrapLimitStorage storage w) {
        assembly ("memory-safe") { w.slot := _WRAPLIMIT }
    }

    // ------------------------------------------------------------------ init

    /// @notice The token's `_init`: legs 1–8 (the factory's index reads the same `legs`), the metadata, the
    ///         flags/owner/roles of `kind` (`GovernanceLib.init` with the kind's masks, spec §1.2), the rate config, then
    ///         the legs in their given order (never changes).
    function initToken(IFactoryToken.TokenConfig memory c, bool isHedera, uint8 kind, uint256 valid, uint256 roleBits,
        uint256 contractOnly, address uaRegistry) public
    {
        uint256 n = c.legs.length;
        if (n == 0 || n > MAX_LEGS) revert MetaTokenBase.UnderlyingCountInvalid(n);
        { // scoped: `init` below takes ten words (stack)
            TokenStore.TokenStorage storage t = TokenStore.$();
            t.name = c.name;
            t.symbol = c.symbol;
            t.decimals = c.decimals;
            t.kind = kind;
        }
        // spec §5.2: a hybrid is `maxSupply != 0`, and `MINTABLE` is set at creation iff it is one
        if ((c.maxSupply != 0) != (c.features & (uint256(1) << GovernanceBits.MINTABLE) != 0)) {
            revert IWrappedToken.MaxSupplyInvalid();
        }
        // group 3l (R12): the wrap controls only on a hybrid, read from the config before `init` writes it
        uint256 wc = c.features & GovernanceBits.WRAP_CONTROLS;
        if (c.maxSupply == 0 && wc != 0) {
            revert IWrappedToken.WrapControlNeedsHybrid(wc & (uint256(1) << GovernanceBits.WRAP_LIMIT) != 0
                ? GovernanceBits.WRAP_LIMIT : wc & (uint256(1) << GovernanceBits.WRAP_LIST) != 0
                ? GovernanceBits.WRAP_LIST : GovernanceBits.REDEEMER);
        }
        GovernanceLib.init(c.features, c.lockedFeatures, c.owner, c.grantDelay, c.rescueTo, c.roles, valid, roleBits,
            contractOnly, uaRegistry);
        bool adjustable = GovernanceLib.hasFeature(GovernanceBits.RATE_ADJUSTABLE);
        WrappedStorage storage s = $();
        IFactoryToken.RateConfig memory rate = c.rate;
        if (!adjustable) {
            if (rate.rateDelay != 0 || rate.maxRateStepBps != 0) revert IWrappedToken.RateConfigInvalid();
        } else {
            if (rate.rateDelay < 2 days || rate.rateDelay > 30 days || rate.maxRateStepBps == 0
                || rate.maxRateStepBps > 1000) revert IWrappedToken.RateConfigInvalid();
            s.rateDelay = rate.rateDelay;
            s.maxRateStepBps = rate.maxRateStepBps;
        }
        s.maxSupply = c.maxSupply;
        for (uint256 i; i < n; ++i) _addLeg(s, c.legs[i], adjustable, isHedera);
    }

    function _addLeg(WrappedStorage storage s, IFactoryToken.Leg memory l, bool adjustable, bool isHedera)
        private
    {
        address u = l.underlying;
        uint8 d;
        if (u == NATIVE) {
            d = isHedera ? 8 : 18; // Hedera's EVM counts the native coin in tinybars
        } else {
            if (u == address(this) || !SigCheck.isContract(u)) revert IWrappedToken.UnderlyingInvalid(u);
            if (isHedera && !HederaLib.checkAndAssociate(u)) revert IWrappedToken.UnderlyingInvalid(u);
            // CTR-GOV-05 (spec §6.1, B-15): a leg this factory registered must not carry FORCE or MODERATE. `msg.sender` is
            // the factory (`initialize` checked it; DELEGATECALL keeps it, GD-20). `isRegisteredToken`, never `isToken`: an
            // unregistered leg or a second factory's token is an outside leg, never read. Features only lose bits.
            if (IOpenFactory(msg.sender).isRegisteredToken(u) && IGovernance(u).features()
                & ((uint256(1) << GovernanceBits.FORCE) | (uint256(1) << GovernanceBits.MODERATE)) != 0) {
                revert IWrappedToken.UnderlyingInvalid(u);
            }
            (bool ok, bytes memory ret) = u.staticcall(abi.encodeCall(IERC20Metadata.decimals, ()));
            if (!ok || ret.length != 32 || uint256(bytes32(ret)) > type(uint8).max) {
                revert IWrappedToken.DecimalsUnreadable(u);
            }
            d = uint8(uint256(bytes32(ret)));
        }
        (uint256 num, uint256 den) = (l.num, l.den);
        if (num == 0 || den == 0 || num > MAX_RATE || den > MAX_RATE) revert IWrappedToken.RateInvalid(num, den);
        if (s.legIndex[u] != 0) revert IWrappedToken.DuplicateUnderlying(u);
        uint256 i = s.legCount;
        s.legs[i] = Leg({
            token: u, decimals: d, wrapEnabled: true, adjustable: adjustable, capped: s.maxSupply != 0, ctl: 0,
            num: uint96(num), den: uint96(den), reserve: 0
        });
        s.legIndex[u] = i + 1;
        s.legCount = uint8(i + 1);
    }

    // ------------------------------------------------------------------ wrap / reserve / unwrap

    /// @notice Pull `amount` from `from` (or take `value` on the native leg), price the measured delta; on a hybrid,
    ///         `supply + minted ≤ maxSupply` (`supply`: the token's `totalSupply()`, read only when capped). Group 3l
    ///         (spec §4): the wrapper list on the payer `from` before the pull, the four limits on the payer and the net
    ///         credit to `receiver` (0: the payer) on the measured `received` after it.
    function wrap(uint256 i, uint256 amount, address from, uint256 value, uint256 supply, bytes32 receiver)
        public returns (address u, uint256 received, uint256 minted)
    {
        WrappedStorage storage s = $();
        Leg storage L = s.legs[i];
        u = L.token;
        if (!L.wrapEnabled) revert IWrappedToken.WrapDisabledFor(u);
        if (L.adjustable && _isPending(s)) revert IWrappedToken.WrapPausedForRateChange(u);
        uint8 ctl = L.ctl;
        if (ctl & CTL_WLIST != 0) _listed(MetaTxLib.pad(from), 1);
        received = _pull(L, amount, from, value);
        minted = Math.mulDiv(received, L.num, L.den);
        if (minted == 0) revert IWrappedToken.WrapTooSmall();
        if (L.capped) _cap(supply, minted);
        if (ctl & CTL_TRACK != 0) _wrapCount(i, u, MetaTxLib.pad(from), receiver, received);
    }

    /// @notice A hybrid's mint (spec §5.2): the same cap as a wrap; the token checked bit 1 and its holder before.
    function checkMint(uint256 supply, uint256 amount) public view {
        _cap(supply, amount);
    }

    /// @dev The one cap (spec §5.2, CTR-GOV-12): every path that raises `totalSupply()` on a hybrid; shielded value counts,
    ///      the pool's units being in `totalSupply()`. `MaxSupplyExceeded` names the supply the call would reach.
    function _cap(uint256 supply, uint256 added) private view {
        uint256 max = $().maxSupply;
        uint256 next = Math.saturatingAdd(supply, added);
        if (next > max) revert IWrappedToken.MaxSupplyExceeded(next, max);
    }

    /// @notice Anyone; no mint. Refused on a leg whose wrap is disabled.
    function addReserve(uint256 i, uint256 amount, address from, uint256 value) public returns (uint256 received) {
        Leg storage L = $().legs[i];
        if (!L.wrapEnabled) revert IWrappedToken.WrapDisabledFor(L.token);
        received = _pull(L, amount, from, value);
    }

    /// @dev One balance read before serves both the shortfall check (no wrap or top-up while `balance < reserve`)
    ///      and the measurement. Native: the balance already holds `value`, which is the measured delta.
    function _pull(Leg storage L, uint256 amount, address from, uint256 value) private returns (uint256 received) {
        address u = L.token;
        uint256 reserve = L.reserve;
        if (u == NATIVE) {
            if (value != amount) revert IWrappedToken.NativeValueMismatch(value, amount);
            uint256 before = address(this).balance - value;
            if (before < reserve) revert IWrappedToken.ReserveShortfall(u, before, reserve);
            received = value;
        } else {
            if (value != 0) revert IWrappedToken.NativeValueMismatch(value, 0);
            uint256 before = IERC20(u).balanceOf(address(this));
            if (before < reserve) revert IWrappedToken.ReserveShortfall(u, before, reserve);
            IERC20(u).safeTransferFrom(from, address(this), amount);
            received = IERC20(u).balanceOf(address(this)) - before;
        }
        L.reserve = reserve + received;
    }

    /// @notice `mtxWrapOrder` (CTR-TOK-20, UA-5b, R39): the leg must accept a wrap (enabled, no pending change, no
    ///         shortfall); the underlying's `mtxTrade` takes the holder's `UAWrapOrder` as the `UATradeOrder` with
    ///         `dex == receiveToken == wrappedToken`: it checks the holder, that this token is the puller, the price
    ///         (`minMinted <= minted`), the relayer (`submitter`) and the fee bound, and moves `o.amount` here. A ledger
    ///         is asked of the underlying (`IUALedger` by ERC-165, as `payOutToUA`) only for a derived holder (C). A leg
    ///         with no `mtxTrade` (an outside ERC-20) fails closed by name: a leg call that reverts without data is
    ///         `UALegNotLedger` (ua-mtx-merge T6; a native holder asks no registry), any other revert is the leg's own.
    /// @return received the measured delta (must be `o.amount`)
    /// @return minted `⌊o.amount·num/den⌋`
    /// @return fee `⌈minted·o.fee/10⁶⌉`, the submitter's part of `minted`
    function wrapBySigUA(address u, ITradeToken.UAWrapOrder calldata o, IUARegistry.UASig calldata auth, address submitter,
        uint256 supply) public returns (uint256 received, uint256 minted, uint256 fee)
    {
        (Leg storage L, uint256 i) = _wrapLeg(u, o.wrappedToken);
        if (!UAKinds.inNativeSpace(o.from) && !ERC165Checker.supportsInterface(u, type(IUALedger).interfaceId)) {
            revert IUALedger.UALegNotLedger(u);
        }
        if (L.ctl & CTL_WLIST != 0) _listed(o.from, 1); // group 3l: the order's signer is the payer (R14)
        (minted, fee) = _sigQuote(L, o.amount, o.fee, supply);
        // group 3l (spec §4): the limits on `o.from` and the net credit to the destination at `o.amount` (= received)
        if (L.ctl & CTL_TRACK != 0) _wrapCount(i, u, o.from, o.destination, o.amount);
        received = _sigBefore(L); // the balance before, in the return slot (stack)
        try ITradeToken(u).mtxTrade(_order(o), auth, ITradeToken.TradeFill(o.amount, minted, fee, submitter)) {}
        catch (bytes memory r) {
            // ponytail: an empty revert is read as "no `mtxTrade`"; a leg that ran out of gas inside gets the same name
            // (the submitter's simulation shows it); probe the leg's code if a finer verdict is ever needed
            if (r.length == 0) revert IUALedger.UALegNotLedger(u);
            assembly ("memory-safe") { revert(add(r, 0x20), mload(r)) }
        }
        received = _sigReceived(L, received, o.amount);
    }

    /// @dev The order the underlying checks: a wrap order is the `UATradeOrder` with `dex == receiveToken == wrappedToken`
    ///      (TS-D19).
    function _order(ITradeToken.UAWrapOrder memory w) private pure returns (ITradeToken.UATradeOrder memory c) {
        c.from = w.from;
        c.receiveToken = w.wrappedToken;
        c.amount = w.amount;
        c.receiveAmount = w.minMinted;
        c.minFill = w.minFill;
        c.fee = w.fee;
        c.relayer = w.relayer;
        c.dex = w.wrappedToken;
        c.destination = w.destination;
        c.flags = w.flags;
        c.batch = w.batch;
        c.nonce = w.nonce;
        c.validUntil = w.validUntil;
    }

    function _wrapLeg(address u, address receiveToken) private view returns (Leg storage L, uint256 i) {
        if (u == NATIVE) revert IWrappedToken.NativeNotGasless();
        WrappedStorage storage s = $();
        i = indexOf(u);
        L = s.legs[i];
        if (!L.wrapEnabled) revert IWrappedToken.WrapDisabledFor(u);
        if (L.adjustable && _isPending(s)) revert IWrappedToken.WrapPausedForRateChange(u);
        if (receiveToken != address(this)) revert IWrappedToken.WrapOrderInvalid(receiveToken);
    }

    /// @dev `minted = ⌊amount·num/den⌋`, the submitter's `fee = ⌈minted·feePpm/10⁶⌉`; a hybrid's cap on `minted` (the fee is
    ///      minted too).
    function _sigQuote(Leg storage L, uint256 amount, uint256 feePpm, uint256 supply)
        private view returns (uint256 minted, uint256 fee)
    {
        minted = Math.mulDiv(amount, L.num, L.den);
        if (minted == 0) revert IWrappedToken.WrapTooSmall();
        if (L.capped) _cap(supply, minted);
        fee = Math.mulDiv(minted, feePpm, 1_000_000, Math.Rounding.Ceil);
    }

    /// @dev One balance read before serves the shortfall check and the measurement, as in `_pull`.
    function _sigBefore(Leg storage L) private view returns (uint256 before) {
        uint256 reserve = L.reserve;
        before = IERC20(L.token).balanceOf(address(this));
        if (before < reserve) revert IWrappedToken.ReserveShortfall(L.token, before, reserve);
    }

    function _sigReceived(Leg storage L, uint256 before, uint256 amount) private returns (uint256 received) {
        received = IERC20(L.token).balanceOf(address(this)) - before;
        if (received != amount) revert IWrappedToken.WrapReceivedMismatch(amount, received);
        L.reserve += received;
    }

    /// @notice Every check before any effect: recipient, `0 < out`, `out ≥ minOut`, `out ≤ reserve`; group 3l (spec §4):
    ///         the unwrapper list, the four limits and the entitlement of `holder` on `out`, checked, not written.
    function quoteUnwrap(uint256 i, uint256 wrapped, address recipient, uint256 minOut, bytes32 holder)
        public view returns (uint256 out, uint256 burned)
    {
        if (recipient == address(0) || recipient == address(this) || recipient == MetaTxLib.UA_POOL
            || recipient == MetaTxLib.SHIELD_POOL) { // C5-4
            revert IWrappedToken.UnwrapRecipientInvalid(recipient);
        }
        return _quote(i, wrapped, minOut, holder);
    }

    /// @notice `unwrapToUA` (CTR-UA-28): the checks of `quoteUnwrap` but the recipient's (the leg's `transferToUA`
    ///         checks `to`).
    function quoteUnwrapToUA(uint256 i, uint256 wrapped, uint256 minOut, bytes32 holder)
        public view returns (uint256 out, uint256 burned)
    {
        return _quote(i, wrapped, minOut, holder);
    }

    function _quote(uint256 i, uint256 wrapped, uint256 minOut, bytes32 holder)
        private view returns (uint256 out, uint256 burned)
    {
        Leg storage L = $().legs[i];
        (uint256 num, uint256 den) = (L.num, L.den);
        out = Math.mulDiv(wrapped, den, num);
        if (out == 0) revert IWrappedToken.UnwrapTooSmall();
        if (out < minOut) revert IWrappedToken.UnwrapBelowMin(out, minOut);
        uint256 reserve = L.reserve;
        if (out > reserve) revert IWrappedToken.InsufficientReserve(L.token, out, reserve);
        burned = Math.mulDiv(out, num, den, Math.Rounding.Ceil);
        uint8 ctl = L.ctl;
        if (ctl != 0) _unwrapNext(ctl, i, holder, out, L.token);
    }

    /// @notice After the token burned: `reserve -= out`, then the one outside call, under the token's guard (CEI).
    ///         The balance must drop by EXACTLY `out` (a sender-pays fee reverts, CTR-TOK-11). The native coin goes
    ///         with all gas; a recipient that refuses it reverts the unwrap, and an EIP-7702 designator recipient is
    ///         refused (`UnwrapRecipientInvalid`: an EOA must not run code, owner ruling 2026-10-30, D4).
    ///         Group 3l (spec §4 step 6): `holder`'s count, checked again and written, before `reserve -= out`.
    function payOut(uint256 i, address recipient, uint256 out, bytes32 holder) public returns (address u) {
        Leg storage L = $().legs[i];
        u = L.token;
        _unwrapCount(L, i, holder, out);
        L.reserve -= out;
        uint256 before = _balance(u);
        if (u == NATIVE) {
            if (SigCheck.isDesignator(recipient)) revert IWrappedToken.UnwrapRecipientInvalid(recipient);
            Address.sendValue(payable(recipient), out);
        }
        else IERC20(u).safeTransfer(recipient, out);
        uint256 after_ = _balance(u);
        uint256 sent = before > after_ ? before - after_ : 0;
        if (sent != out) revert IWrappedToken.UnderlyingTransferMismatch(u, out, sent);
    }

    /// @notice `payOut` into a derived UA (CTR-UA-28): leg `u` pays `to` in its own UA ledger,
    ///         `IUALedger(u).transferToUA(to, out)`, which checks `to`. A leg that does not report `IUALedger` by ERC-165
    ///         (the native coin, an outside ERC-20 or HTS token, a SCaaS token with the ledger off) reverts
    ///         `UALegNotLedger` before the reserve or the leg moves; the caller's burn before it is unwound by the
    ///         revert, atomically. The balance must drop by EXACTLY `out`, as in `payOut`.
    function payOutToUA(uint256 i, bytes32 to, uint256 out, bytes32 holder) public returns (address u) {
        Leg storage L = $().legs[i];
        u = L.token;
        // `u == NATIVE` only skips the probe: `supportsInterface(address(0), …)` is false, so the error is the same
        if (u == NATIVE || !ERC165Checker.supportsInterface(u, type(IUALedger).interfaceId)) {
            revert IUALedger.UALegNotLedger(u);
        }
        _unwrapCount(L, i, holder, out);
        L.reserve -= out;
        uint256 before = IERC20(u).balanceOf(address(this));
        IUALedger(u).transferToUA(to, out);
        uint256 after_ = IERC20(u).balanceOf(address(this));
        uint256 sent = before > after_ ? before - after_ : 0;
        if (sent != out) revert IWrappedToken.UnderlyingTransferMismatch(u, out, sent);
    }

    /// @notice The quote `payOutTo` runs, alone: a native id by `quoteUnwrap`, a derived UA by `quoteUnwrapToUA`. An
    ///         unshield-unwrap runs it before its proof (spec §5.4), so a short reserve, or a wrap limit (group 3l, the proof's
    ///         sender `holder`), costs the relayer the cheap prefix.
    function quoteTo(uint256 i, bytes32 recipient, uint256 wrapped, uint256 minOut, bytes32 holder)
        public view returns (uint256 out)
    {
        if (UAKinds.inNativeSpace(recipient)) {
            (out,) = quoteUnwrap(i, wrapped, address(uint160(uint256(recipient))), minOut, holder);
        } else {
            (out,) = quoteUnwrapToUA(i, wrapped, minOut, holder);
        }
    }

    /// @notice The leg payout of an unshield-unwrap (CTR-ZTH-51, UA-5c) to a recipient id, after the caller burnt
    ///         `wrapped`: a native id (its address) by `quoteUnwrap` + `payOut`, a derived UA in leg `i`'s own UA ledger
    ///         by `quoteUnwrapToUA` + `payOutToUA` (`UALegNotLedger` for an outside leg).
    function payOutTo(uint256 i, bytes32 recipient, uint256 wrapped, uint256 minOut, bytes32 holder)
        public returns (uint256 out)
    {
        out = quoteTo(i, recipient, wrapped, minOut, holder);
        if (UAKinds.inNativeSpace(recipient)) payOut(i, address(uint160(uint256(recipient))), out, holder);
        else payOutToUA(i, recipient, out, holder);
    }

    // ------------------------------------------------------------------ rescue (CTR-GOV-06, spec §6.2)

    /// @notice `WRAPPED*`: a leg (the native one included) pays only `balance − reserve`, checked before and after the
    ///         transfer (`ReserveShortfall`, never a panic); a foreign asset its whole balance. Either way every other leg's
    ///         balance is unchanged across the call (`RescueTouchedLeg`, at most `MAX_LEGS` reads): a foreign alias of a leg
    ///         (A16), or a second leg over the same ledger, whose reserve the first leg's surplus would hold (review
    ///         2026-11-04 M-1); a short leg traps no other rescue. The caller's guard is the token's `nonReentrant`.
    function rescue(address asset) public {
        address to = GovernanceLib.rescueOpen(asset);
        WrappedStorage storage s = $();
        uint256 x = s.legIndex[asset]; // the leg's index + 1, 0 for a foreign asset
        uint256 n = s.legCount;
        uint256[] memory before = new uint256[](n);
        for (uint256 i; i < n; ++i) if (i + 1 != x) before[i] = _balance(s.legs[i].token);
        uint256 amount;
        if (x != 0) {
            uint256 r = s.legs[x - 1].reserve;
            uint256 bal = _balance(asset);
            if (bal < r) revert IWrappedToken.ReserveShortfall(asset, bal, r);
            amount = bal - r;
            GovernanceLib.rescueSend(asset, to, amount);
            bal = _balance(asset);
            if (bal < r) revert IWrappedToken.ReserveShortfall(asset, bal, r);
        } else {
            amount = _balance(asset);
            GovernanceLib.rescueSend(asset, to, amount);
        }
        for (uint256 i; i < n; ++i) {
            address leg = s.legs[i].token;
            if (i + 1 != x && _balance(leg) != before[i]) revert IRescuable.RescueTouchedLeg(leg);
        }
        emit IRescuable.Rescued(asset, to, amount);
    }

    // ------------------------------------------------------------------ guardian (WRAP_DISABLEABLE)

    /// @notice One-way: no re-enable (a compromised guardian reopening a depegged inflow would drain the good legs).
    function disableWrap(address u, bytes32 reason, bytes32 caller) public {
        if (!GovernanceLib.hasFeature(GovernanceBits.WRAP_DISABLEABLE) || !GovernanceLib.hasRole(GovernanceBits.WRAP_DISABLEABLE, caller)) {
            revert IWrappedToken.NotGuardian();
        }
        GovernanceUse.use(GovernanceBits.WRAP_DISABLEABLE, caller, 0); // a limited holder's grant binds it
        Leg storage L = $().legs[indexOf(u)];
        if (!L.wrapEnabled) revert IWrappedToken.WrapDisabledFor(u);
        L.wrapEnabled = false;
        emit IWrappedToken.WrapDisabled(u, caller, reason);
    }

    // ------------------------------------------------------------------ rates (CTR-TOK-06, CTR-TOK-13)

    function _onlyRateAdmin(bytes32 caller) private {
        if (!GovernanceLib.hasFeature(GovernanceBits.RATE_ADJUSTABLE)) revert IWrappedToken.RateFixed();
        if (!GovernanceLib.hasRole(GovernanceBits.RATE_ADJUSTABLE, caller)) revert IWrappedToken.NotRateAdmin();
        GovernanceUse.use(GovernanceBits.RATE_ADJUSTABLE, caller, 0); // a limited holder's grant binds it
    }

    /// @notice The step is checked ONCE, here, against the current rate (which cannot change while pending).
    function proposeRate(address u, uint96 num, uint96 den, bytes32 caller) public {
        _onlyRateAdmin(caller);
        WrappedStorage storage s = $();
        if (_isPending(s)) revert IWrappedToken.RateChangePending();
        uint256 i = indexOf(u);
        if (num == 0 || den == 0) revert IWrappedToken.RateInvalid(num, den);
        Leg storage L = s.legs[i];
        (uint96 n0, uint96 d0) = (L.num, L.den);
        // |num'·den − num·den'|·10⁴ ≤ num·den'·bps — exact in integers, every product < 2^207.
        uint256 a = uint256(num) * d0;
        uint256 b = uint256(n0) * den;
        if ((a > b ? a - b : b - a) * 10_000 > b * s.maxRateStepBps) revert IWrappedToken.RateStepTooLarge();
        uint64 eta = uint64(block.timestamp + s.rateDelay);
        s.pending = PendingRate({leg: uint8(i), num: num, den: den, eta: uint56(eta)});
        emit IWrappedToken.RateChangeProposed(u, n0, d0, num, den, eta);
    }

    function cancelRate(bytes32 caller) public {
        _onlyRateAdmin(caller);
        WrappedStorage storage s = $();
        if (!_isPending(s)) revert IWrappedToken.NoRateChangePending();
        _drop(s);
    }

    /// @notice `disableFeature(RATE_ADJUSTABLE)` fixes the rate and cancels a pending change (CTR-TOK-06).
    function dropPending() public {
        WrappedStorage storage s = $();
        if (_isPending(s)) _drop(s);
        else delete s.pending;
    }

    function _drop(WrappedStorage storage s) private {
        address u = s.legs[s.pending.leg].token;
        delete s.pending;
        emit IWrappedToken.RateChangeCancelled(u);
    }

    /// @notice Only the rate admin executes: a third party cannot bundle the execution with its own wraps.
    function executeRate(bytes32 caller, uint256 supply) public {
        _onlyRateAdmin(caller);
        WrappedStorage storage s = $();
        PendingRate memory p = s.pending;
        if (p.eta == 0) revert IWrappedToken.NoRateChangePending();
        if (block.timestamp < p.eta) revert IWrappedToken.RateChangeNotReady(p.eta);
        if (block.timestamp > uint256(p.eta) + RATE_WINDOW) revert IWrappedToken.RateChangeExpired(p.eta);
        bool anyDisabled = _requireCollateral(s, p, supply);
        Leg storage T = s.legs[p.leg];
        (uint96 n0, uint96 d0) = (T.num, T.den);
        if (anyDisabled && uint256(p.num) * d0 < uint256(n0) * p.den) {
            revert IWrappedToken.RateDecreaseWithDisabledLeg();
        }
        T.num = p.num;
        T.den = p.den;
        delete s.pending;
        emit IWrappedToken.RateChanged(T.token, n0, d0, p.num, p.den);
    }

    /// @dev Every leg: `balance ≥ reserve` (no phantom reserve); then `C' ≥ supply` with the new rate, summing with an
    ///      early exit once covered but still checking every leg's balance. Returns "some leg has wrap disabled". On a
    ///      hybrid (`capped`) no `C' ≥ supply`: a rate fall needs no `addReserve` (spec §5.3, C1, CTR-GOV-12).
    function _requireCollateral(WrappedStorage storage s, PendingRate memory p, uint256 supply)
        private view returns (bool anyDisabled)
    {
        uint256 c;
        uint256 n = s.legCount;
        for (uint256 i; i < n; ++i) {
            Leg storage L = s.legs[i];
            if (L.capped) supply = 0; // every leg carries the same copy
            uint256 r = L.reserve;
            uint256 bal = _balance(L.token);
            if (bal < r) revert IWrappedToken.ReserveShortfall(L.token, bal, r);
            if (!L.wrapEnabled) anyDisabled = true;
            if (c < supply) {
                c = Math.saturatingAdd(c, i == p.leg ? _value(r, p.num, p.den) : _value(r, L.num, L.den));
            }
        }
        if (c < supply) revert IWrappedToken.RateChangeUndercollateralized(c, supply);
    }

    // ------------------------------------------------------------------ views

    function collateralValue() public view returns (uint256 c) {
        WrappedStorage storage s = $();
        uint256 n = s.legCount;
        for (uint256 i; i < n; ++i) {
            Leg storage L = s.legs[i];
            c = Math.saturatingAdd(c, _value(L.reserve, L.num, L.den));
        }
    }

    function previewWrap(address u, uint256 amount) public view returns (uint256 minted, uint256 used) {
        Leg storage L = $().legs[indexOf(u)];
        minted = Math.mulDiv(amount, L.num, L.den);
        used = Math.mulDiv(minted, L.den, L.num, Math.Rounding.Ceil);
    }

    function previewUnwrap(address u, uint256 wrapped) public view returns (uint256 out, uint256 burned) {
        Leg storage L = $().legs[indexOf(u)];
        out = Math.mulDiv(wrapped, L.den, L.num);
        burned = Math.mulDiv(out, L.num, L.den, Math.Rounding.Ceil);
    }

    // ------------------------------------------------------------------ group 3l: wrap / unwrap limits (spec 2026-11-10)
    // Hybrids of the wrapped kinds only (R12). Amounts in quanta of `10^unitExp` raw units of the leg (R22); windows fixed,
    // in minutes (R2); per id, plus an optional token-wide cap, per leg (R3, R15); the net-wrapped entitlement, plain or
    // decaying linearly over `decayDays` from a weighted-average start in absolute minutes (R4, R11, R23, R24, R26). UNAUDITED.

    /// @dev The two limits of one side (`side` 0 wrap, 1 unwrap) on `x` raw units: per-user parts in `qw` (the id's quota
    ///      word), token-wide parts in `tw` (the side's `TokenWindows` word); `q = ⌈x/unit⌉` (spec §2, "A use").
    function _side(uint256 cfg, uint256 qw, uint256 tw, uint256 side, Use memory c)
        private pure returns (uint256, uint256)
    {
        c.unit = 10 ** uint8(cfg >> 224);
        c.q = Math.ceilDiv(c.x, c.unit);
        for (uint256 j; j < 2; ++j) {
            uint256 part = cfg >> (112 * j);
            uint256 l = 2 * side + j;
            if (uint24(part) != 0) qw = _userPart(c, qw, part, l);
            if (uint64(part >> 24) != 0) tw = _totalPart(c, tw, part, l, j);
        }
        return (qw, tw);
    }

    function _use(uint256 x, bytes32 id, address u) private view returns (Use memory) {
        return Use(x, 0, 0, (block.timestamp / 60) % _CIRCLE, id, u);
    }

    /// @dev One use: the raw amount, its quanta, the unit, the minute on the circle, the subject, the leg.
    struct Use {
        uint256 x;
        uint256 q;
        uint256 unit;
        uint256 nowMin;
        bytes32 id;
        address u;
    }

    function _userPart(Use memory c, uint256 qw, uint256 part, uint256 l) private pure returns (uint256) {
        uint256 cap = uint24(part);
        (uint256 ns, uint256 nu, uint256 left) =
            _window(_get(qw, 21 * l, 21), _get(qw, 84 + 19 * l, 19), uint24(part >> 88), c.q, cap, c.nowMin);
        if (nu > cap) revert IWrappedToken.WrapLimitExceeded(c.u, uint8(l), c.id, c.x, left * c.unit);
        return _put(_put(qw, 21 * l, 21, ns), 84 + 19 * l, 19, nu);
    }

    function _totalPart(Use memory c, uint256 tw, uint256 part, uint256 l, uint256 j) private pure returns (uint256) {
        uint256 cap = uint64(part >> 24);
        (uint256 ns, uint256 nu, uint256 left) =
            _window(uint24(tw >> (88 * j)), uint64(tw >> (88 * j + 24)), uint24(part >> 88), c.q, cap, c.nowMin);
        if (nu > cap) revert IWrappedToken.WrapCapExceeded(c.u, uint8(l), c.x, left * c.unit);
        return _put(_put(tw, 88 * j, 24, ns), 88 * j + 24, 64, nu);
    }

    /// @dev A fixed window (R2): active while `used ≠ 0` and at most `p` whole minutes have passed since its start, the
    ///      elapsed minutes on the 2^21 circle, never a checked subtraction (spec §5, Fable P1-4); a new window starts at this
    ///      use. `nu > cap` is the caller's refusal.
    function _window(uint256 start, uint256 used, uint256 p, uint256 q, uint256 cap, uint256 nowMin)
        private pure returns (uint256 ns, uint256 nu, uint256 left)
    {
        bool active = used != 0 && (nowMin + _CIRCLE - start) % _CIRCLE <= p;
        uint256 base = active ? used : 0;
        (ns, nu) = (active ? start : nowMin, base + q);
        left = base < cap ? cap - base : 0;
    }

    /// @dev The entitlement `E` of a base `b` started at minute `s` (§2.1) and the age `g` in minutes, clamped to `H`
    ///      (`decayDays · 1,440`) when the decay is on; `decayDays == 0`: `E = b`, `g` the plain age (the clock kept while the
    ///      decay is off). `s > now` (never produced) reads as age 0, so nothing underflows.
    function _ent(uint256 b, uint256 s, uint256 decayDays) private view returns (uint256 e, uint256 g, uint256 h) {
        uint256 nowMin = block.timestamp / 60;
        g = nowMin > s ? nowMin - s : 0;
        if (decayDays == 0) return (b, g, 0);
        h = decayDays * 1440;
        if (g > h) g = h;
        e = b * (h - g) / h;
    }

    /// @dev A wrap's net credit of `a = ⌊x/unit⌋` quanta (§2.1): the age weighted by value and rounded older, the base
    ///      rescaled so the value now is exact, `b' ≤ b + a`, saturating at `2^32 − 1`; `a == 0` changes nothing.
    function _credit(uint256 qw, uint256 a, uint256 decayDays) private view returns (uint256) {
        if (a == 0) return qw;
        uint256 b = _get(qw, 160, 32);
        (uint256 e, uint256 g, uint256 h) = _ent(b, qw >> 192, decayDays);
        uint256 g2 = Math.ceilDiv(e * g, e + a);
        uint256 b2 = b + a;
        if (h != 0) b2 = Math.min(b2, (e + a) * h / (h - g2));
        return _put(_put(qw, 160, 32, Math.min(b2, type(uint32).max)), 192, 64, block.timestamp / 60 - g2);
    }

    /// @dev The wrap side's count (spec §4 step 7): the payer's limits, then the net credit to `receiver` (0: the payer),
    ///      one load and one write when they are the same id. Issuer mints never come here (R12).
    function _wrapCount(uint256 i, address u, bytes32 payer, bytes32 receiver, uint256 x) private {
        if (receiver == 0) receiver = payer;
        uint256 cfg = _ld(_slot(wl().config[i]));
        uint256 ps = _qslot(wl(), payer, i);
        uint256 qw = _wrapSide(cfg, i, ps, x, payer, u);
        uint256 a = x / 10 ** uint8(cfg >> 224);
        if (receiver == payer) {
            _st(ps, _credit(qw, a, uint16(cfg >> 232)));
        } else {
            _st(ps, qw);
            uint256 rs = _qslot(wl(), receiver, i);
            _st(rs, _credit(_ld(rs), a, uint16(cfg >> 232)));
        }
    }

    /// @dev The wrap side's limits on the payer's word `ps`; the token-wide word written when a part of it is on.
    function _wrapSide(uint256 cfg, uint256 i, uint256 ps, uint256 x, bytes32 payer, address u) private returns (uint256 qw) {
        (uint256 ts, uint256 tw) = _total(wl(), cfg, i, 0);
        (qw, tw) = _side(cfg, _ld(ps), tw, 0, _use(x, payer, u));
        if (ts != 0) _st(ts, tw);
    }

    /// @dev The side's token-wide word, read only when a token-wide part of the side is on: its slot (0 = none) and word.
    function _total(WrapLimitStorage storage w, uint256 cfg, uint256 i, uint256 side) private view returns (uint256 ts, uint256 tw) {
        if (cfg & _TW == 0) return (0, 0);
        ts = _slot(w.total[i]) + side;
        tw = _ld(ts);
    }

    /// @dev The unwrap side's check (spec §4 step 4, §2): the subject (never 0), the unwrapper list, then, tracked, the
    ///      limits and the entitlement rule on `q = ⌈out/unit⌉`; the new words returned, not written. `excess` > 0: a
    ///      redeemer's exemption used, the raw units above the entitlement (R27).
    function _unwrapNext(uint8 ctl, uint256 i, bytes32 holder, uint256 x, address u)
        private view returns (uint256 qw, uint256 ts, uint256 tw, uint256 excess)
    {
        if (holder == 0) revert IWrappedToken.WrapSubjectZero();
        if (ctl & CTL_ULIST != 0) _listed(holder, 2);
        if (ctl & CTL_TRACK == 0) return (0, 0, 0, 0);
        uint256 cfg = _ld(_slot(wl().config[i]) + 1);
        (ts, tw) = _total(wl(), cfg, i, 1);
        (qw, tw) = _side(cfg, _ld(_qslot(wl(), holder, i)), tw, 1, _use(x, holder, u));
        (qw, excess) = _debit(cfg, qw, ctl, x, holder, u);
    }

    /// @dev The entitlement rule (§2 table: `NET`, or the decay on) and the debit (§2.1): `q ≥ E` ⇒ `b' = 0` first (no
    ///      division at `E = 0`, Fable P1-3), else `b' = ⌊b·(E − q)/E⌋`, which is `b − q` without the decay; the start kept.
    ///      A would-be refusal reads the redeemer role (R9), and only then.
    function _debit(uint256 cfg, uint256 qw, uint8 ctl, uint256 x, bytes32 holder, address u)
        private view returns (uint256, uint256 excess)
    {
        uint256 unit = 10 ** uint8(cfg >> 224);
        uint256 decayDays = uint16(cfg >> 232);
        uint256 q = Math.ceilDiv(x, unit);
        uint256 b = _get(qw, 160, 32);
        (uint256 e,,) = _ent(b, qw >> 192, decayDays);
        if ((ctl & CTL_NET != 0 || decayDays != 0) && q > e) {
            if (!GovernanceLib.hasRole(GovernanceBits.REDEEMER, holder)) {
                revert IWrappedToken.UnwrapAboveNetWrapped(u, holder, x, e * unit);
            }
            excess = x - e * unit; // q > e ⇒ x > e·unit
        }
        return (_put(qw, 160, 32, q >= e ? 0 : b * (e - q) / e), excess);
    }

    /// @dev The unwrap side's count (spec §4 step 6): checked again (warm), written; a redeemer's exemption is a use of
    ///      the scalar power (R27: expiry, uses, budget, window, a revoked grantor's leaves).
    function _unwrapCount(Leg storage L, uint256 i, bytes32 holder, uint256 x) private {
        uint8 ctl = L.ctl;
        if (ctl == 0) return;
        (uint256 qw, uint256 ts, uint256 tw, uint256 excess) = _unwrapNext(ctl, i, holder, x, L.token);
        if (ctl & CTL_TRACK != 0) _st(_qslot(wl(), holder, i), qw);
        if (ts != 0) _st(ts, tw);
        if (excess != 0) GovernanceUse.use(GovernanceBits.REDEEMER, holder, excess);
    }

    function _listed(bytes32 id, uint8 bit) private view {
        if (wl().member[id] & bit != 0) return;
        if (bit == 1) revert IWrappedToken.WrapperNotListed(id);
        revert IWrappedToken.UnwrapperNotListed(id);
    }

    // ----- the owner's configuration (spec §6)

    /// @notice The owner's limits (R6, R13, R21): `legs` in leg order, each naming its underlying. A wrap-side relaxation
    ///         or an unwrap-side tightening waits `noticePeriod()` of `factory` in two calls (`_delayedRelaxBits`'s
    ///         shape): the first proposes, the same call again by the owner in `[eta, eta + delay]` under the same owner
    ///         generation applies; anything else applies at once and clears a pending. The first configuration on a bit-25
    ///         token fixes every leg's `unitExp` and starts the tracking.
    function setWrapLimits(IWrappedToken.WrapLegLimits[] calldata legs, bool netUnwrap, bool wrapList, bool unwrapList,
        bytes32 caller, address factory) public
    {
        (bool slow, uint8 ctl) = _classify(legs, netUnwrap, wrapList, unwrapList, caller);
        if (slow && !_due(keccak256(abi.encode(legs, netUnwrap, wrapList, unwrapList)), caller,
            GovernanceLib.$().ownerGeneration, IOpenFactory(factory).noticePeriod(), legs, netUnwrap, wrapList, unwrapList)) {
            return;
        }
        _apply(legs, ctl);
        emit IWrappedToken.WrapLimitsSet(caller, legs, netUnwrap, wrapList, unwrapList);
    }

    /// @dev The owner, the leg count, the bits, every leg's checks; `slow`: R6 / R13, the wrap side looser or the unwrap side
    ///      tighter (the lists and the net rule included); `ctl` the copy the configuration writes.
    function _classify(IWrappedToken.WrapLegLimits[] calldata legs, bool netUnwrap, bool wrapList, bool unwrapList,
        bytes32 caller) private view returns (bool slow, uint8 ctl)
    {
        bool has25 = _ownerAndBits(legs.length, netUnwrap, wrapList, unwrapList, caller);
        uint8 old = $().legs[0].ctl;
        slow = (old & CTL_WLIST != 0 && !wrapList) || (old & CTL_ULIST == 0 && unwrapList) || (old & CTL_NET == 0 && netUnwrap);
        slow = _legsSlow(legs, has25, old & CTL_TRACK != 0) || slow;
        ctl = (has25 ? CTL_TRACK : 0) | (netUnwrap ? CTL_NET : 0) | (wrapList ? CTL_WLIST : 0) | (unwrapList ? CTL_ULIST : 0);
    }

    /// @dev The owner, the leg count, the bits a field needs: 25 the limits, `unitExp`, the decay and the net rule, 26 the lists.
    function _ownerAndBits(uint256 n, bool netUnwrap, bool wrapList, bool unwrapList, bytes32 caller)
        private view returns (bool has25)
    {
        GovernanceLib.GovernanceStorage storage g = GovernanceLib.$();
        if (caller == 0 || caller != g.owner) revert IGovernance.NotOwner(caller);
        if (n != $().legCount) revert IWrappedToken.WrapLegMismatch(n, address(0));
        has25 = g.features & (uint256(1) << GovernanceBits.WRAP_LIMIT) != 0;
        if (netUnwrap && !has25) revert IGovernance.FeatureNotSet(GovernanceBits.WRAP_LIMIT);
        if ((wrapList || unwrapList) && g.features & (uint256(1) << GovernanceBits.WRAP_LIST) == 0) {
            revert IGovernance.FeatureNotSet(GovernanceBits.WRAP_LIST);
        }
    }

    function _legsSlow(IWrappedToken.WrapLegLimits[] calldata legs, bool has25, bool tracked) private view returns (bool slow) {
        WrappedStorage storage s = $();
        for (uint256 i; i < legs.length; ++i) if (_legSlow(s, i, legs[i], has25, tracked)) slow = true;
    }

    /// @dev The configuration written: every leg's two words and `ctl` (the hot-path copy), the pending cleared.
    function _apply(IWrappedToken.WrapLegLimits[] calldata legs, uint8 ctl) private {
        WrapLimitStorage storage w = wl();
        WrappedStorage storage s = $();
        (w.pendingCommit, w.pendingEta, w.pendingGeneration) = (0, 0, 0);
        for (uint256 i; i < legs.length; ++i) {
            (uint256 w0, uint256 w1) = _words(legs[i], address(0));
            uint256 c = _slot(w.config[i]);
            _st(c, w0);
            _st(c + 1, w1);
            s.legs[i].ctl = ctl;
        }
    }

    /// @dev One leg's checks and its classification against the configuration in force (§6's table): true when its wrap
    ///      side is looser or its unwrap side (the decay included) is tighter.
    function _legSlow(WrappedStorage storage s, uint256 i, IWrappedToken.WrapLegLimits calldata l, bool has25, bool tracked)
        private view returns (bool)
    {
        address u = s.legs[i].token;
        if (l.underlying != u) revert IWrappedToken.WrapLegMismatch(i, l.underlying);
        (uint256 w0, uint256 w1) = _words(l, u);
        if (!has25 && (w0 | w1) != 0) revert IGovernance.FeatureNotSet(GovernanceBits.WRAP_LIMIT);
        uint256 c = _slot(wl().config[i]);
        uint256 o0 = _ld(c);
        uint256 o1 = _ld(c + 1);
        if (l.unitExp > 36 || (tracked && l.unitExp != uint8(o0 >> 224))) revert IWrappedToken.WrapUnitInvalid(u, l.unitExp);
        (, bool loose) = _cmp(o0, w0);
        (bool tight,) = _cmp(o1, w1);
        (bool t,) = _amt(uint16(o1 >> 232), uint16(w1 >> 232));
        return loose || tight || t;
    }

    /// @dev A side's two limits, old `o` against new `w`, each part `eff(0) = ∞`, the period when the limit is on in both.
    function _cmp(uint256 o, uint256 w) private pure returns (bool tight, bool loose) {
        for (uint256 j; j < 2; ++j) {
            (uint256 po, uint256 pw) = (o >> (112 * j), w >> (112 * j));
            (bool t, bool l) = _amt(uint24(po), uint24(pw));
            (bool t2, bool l2) = _amt(uint64(po >> 24), uint64(pw >> 24));
            (tight, loose) = (tight || t || t2, loose || l || l2);
            if (uint88(po) != 0 && uint88(pw) != 0) {
                (uint256 a, uint256 b) = (uint24(po >> 88), uint24(pw >> 88));
                (tight, loose) = (tight || b > a, loose || b < a);
            }
        }
    }

    /// @dev An amount with 0 = no limit, old `a`, new `b`: strictly tighter, strictly looser.
    function _amt(uint256 a, uint256 b) private pure returns (bool tight, bool loose) {
        tight = b != 0 && (a == 0 || b < a);
        loose = a != 0 && (b == 0 || b > a);
    }

    /// @dev The two side words of a leg's configuration; each limit's rule (§2, R26: `perUser ≤ 2^19 − 1`, `period` a whole
    ///      number of minutes in `[1, 2^20 − 1]` when a part is on, else 0) checked when `u != 0`.
    function _words(IWrappedToken.WrapLegLimits calldata l, address u) private pure returns (uint256 w0, uint256 w1) {
        uint256 tail = (uint256(l.unitExp) << 224) | (uint256(l.decayDays) << 232);
        w0 = _part(l.wrapShort, u, 0) | (_part(l.wrapLong, u, 1) << 112) | tail;
        w1 = _part(l.unwrapShort, u, 2) | (_part(l.unwrapLong, u, 3) << 112) | tail;
    }

    function _part(IWrappedToken.WrapLimit calldata x, address u, uint8 id) private pure returns (uint256) {
        uint256 p = x.period;
        bool bad = x.perUser > _MAX_PER_USER || (x.perUser != 0 || x.tokenWide != 0
            ? p % 60 != 0 || p < 60 || p > _MAX_PERIOD_MIN * 60 : p != 0);
        if (bad && u != address(0)) revert IWrappedToken.WrapLimitInvalid(u, id);
        return uint256(x.perUser) | (uint256(x.tokenWide) << 24) | ((p / 60) << 88);
    }

    /// @dev The two-call shape (governance spec §1.6, `GovernanceLib._due`): a live pending of the same commitment, at or
    ///      after `eta`, applies (true); before `eta` `GrantNotReady(25, 0, eta)`; anything else proposes (false), replacing
    ///      any pending. A delay of 0 applies at once.
    function _due(bytes32 commit, bytes32 caller, uint32 gen, uint64 delay, IWrappedToken.WrapLegLimits[] calldata legs,
        bool netUnwrap, bool wrapList, bool unwrapList) private returns (bool)
    {
        if (delay == 0) return true;
        WrapLimitStorage storage w = wl();
        uint64 eta = w.pendingEta;
        if (_live(w, gen, delay) && w.pendingCommit == commit) {
            if (block.timestamp < eta) revert IGovernance.GrantNotReady(GovernanceBits.WRAP_LIMIT, 0, eta);
            return true;
        }
        eta = uint64(block.timestamp) + delay;
        (w.pendingCommit, w.pendingEta, w.pendingGeneration) = (commit, eta, gen);
        emit IWrappedToken.WrapLimitsProposed(caller, eta, legs, netUnwrap, wrapList, unwrapList);
        return false;
    }

    function _live(WrapLimitStorage storage w, uint32 gen, uint64 delay) private view returns (bool) {
        uint256 eta = w.pendingEta;
        return eta != 0 && w.pendingGeneration == gen && block.timestamp <= eta + delay;
    }

    /// @notice Bit 26's holder (`GovernanceUse.use`: a power, no scalar, no scope), at once both ways; a caller without the
    ///         role is refused by name first (`MissingRole`, as `disableWrap` names its guardian).
    function setWrapMember(bytes32 account, bool canWrap, bool canUnwrap, bytes32 caller) public {
        if (!GovernanceLib.hasRole(GovernanceBits.WRAP_LIST, caller)) revert IGovernance.MissingRole(GovernanceBits.WRAP_LIST, caller);
        GovernanceUse.use(GovernanceBits.WRAP_LIST, caller, 0);
        wl().member[account] = (canWrap ? 1 : 0) | (canUnwrap ? 2 : 0);
        emit IWrappedToken.WrapMemberSet(account, caller, canWrap, canUnwrap);
    }

    /// @notice `disableFeature` of bit 25, 26 or 27 (spec §2): refused while a control under it is on (25: a limit, the
    ///         decay or the net rule on any leg; 26: a list on; 27: a holder), so a relaxation cannot skip §6's delay; a
    ///         disabled 25 stops the tracking. The caller runs it before the disable (atomic).
    function controlsOff(uint8 bit) public {
        if (bit == GovernanceBits.REDEEMER) {
            if (GovernanceLib.$().counts[bit].holders != 0) revert IWrappedToken.WrapControlActive(bit);
            return;
        }
        WrappedStorage storage s = $();
        uint256 n = s.legCount;
        bool limit = bit == GovernanceBits.WRAP_LIMIT;
        for (uint256 i; i < n; ++i) {
            Leg storage L = s.legs[i];
            uint8 ctl = L.ctl;
            if (ctl & (limit ? CTL_NET : CTL_WLIST | CTL_ULIST) != 0) revert IWrappedToken.WrapControlActive(bit);
            if (limit) {
                uint256 c = _slot(wl().config[i]);
                if ((_ld(c) | _ld(c + 1)) & _NOT_UNIT != 0) revert IWrappedToken.WrapControlActive(bit);
                L.ctl = ctl & ~CTL_TRACK;
            }
        }
    }

    // ----- views (spec §7)

    /// @notice The configuration in force (zeros before the first), the pending one (`pendingLive` under `factory`'s
    ///         `noticePeriod()`) and that delay (Fable P2-3).
    function wrapLimits(address factory) public view returns (IWrappedToken.WrapLegLimits[] memory legs, bool netUnwrap,
        bool wrapList, bool unwrapList, bytes32 pendingCommit, uint64 pendingEta, bool pendingLive, uint64 delay)
    {
        legs = _legLimits();
        uint8 ctl = $().legs[0].ctl;
        (netUnwrap, wrapList, unwrapList) = (ctl & CTL_NET != 0, ctl & CTL_WLIST != 0, ctl & CTL_ULIST != 0);
        WrapLimitStorage storage w = wl();
        (pendingCommit, pendingEta, delay) = (w.pendingCommit, w.pendingEta, IOpenFactory(factory).noticePeriod());
        pendingLive = _live(w, GovernanceLib.$().ownerGeneration, delay);
    }

    function _legLimits() private view returns (IWrappedToken.WrapLegLimits[] memory legs) {
        WrappedStorage storage s = $();
        uint256 n = s.legCount;
        legs = new IWrappedToken.WrapLegLimits[](n);
        for (uint256 i; i < n; ++i) {
            uint256 c = _slot(wl().config[i]);
            (uint256 w0, uint256 w1) = (_ld(c), _ld(c + 1));
            legs[i] = IWrappedToken.WrapLegLimits(s.legs[i].token, uint8(w0 >> 224), uint16(w0 >> 232), _lim(w0), _lim(w0 >> 112),
                _lim(w1), _lim(w1 >> 112));
        }
    }

    function _lim(uint256 p) private pure returns (IWrappedToken.WrapLimit memory) {
        return IWrappedToken.WrapLimit(uint24(p), uint64(p >> 24), uint32(uint24(p >> 88)) * 60);
    }

    /// @notice `account`'s quota on leg `u` (§7).
    function wrapQuotaOf(bytes32 account, address u) public view returns (IWrappedToken.WrapQuota memory r) {
        uint256 i = indexOf(u);
        uint256 c = _slot(wl().config[i]);
        uint256 qw = _ld(_qslot(wl(), account, i));
        uint256 cfg = _ld(c + 1);
        uint256 unit = 10 ** uint8(cfg >> 224);
        r.wrapShort = _userView(_ld(c), qw, 0, unit);
        r.wrapLong = _userView(_ld(c), qw, 1, unit);
        r.unwrapShort = _userView(cfg, qw, 2, unit);
        r.unwrapLong = _userView(cfg, qw, 3, unit);
        _netView(r, account, $().legs[i].ctl, qw, cfg);
    }

    /// @dev The net line, the entitlement, the lists and the role of `wrapQuotaOf`.
    function _netView(IWrappedToken.WrapQuota memory r, bytes32 account, uint8 ctl, uint256 qw, uint256 cfg) private view {
        uint256 unit = 10 ** uint8(cfg >> 224);
        uint256 b = _get(qw, 160, 32);
        r.netWrapped = b * unit;
        (uint256 e,, uint256 h) = _ent(b, qw >> 192, uint16(cfg >> 232));
        r.redeemer = GovernanceLib.hasRole(GovernanceBits.REDEEMER, account);
        r.entitlement = (ctl & CTL_NET == 0 && h == 0) || r.redeemer ? type(uint256).max : e * unit;
        if (h != 0 && b != 0) r.entitlementZeroAt = uint64(((qw >> 192) + h) * 60);
        uint8 m = wl().member[account];
        (r.canWrap, r.canUnwrap) = (ctl & CTL_WLIST == 0 || m & 1 != 0, ctl & CTL_ULIST == 0 || m & 2 != 0);
    }

    /// @notice The token-wide windows of leg `u` (§7, named fields).
    function wrapQuotaTotal(address u) public view returns (IWrappedToken.WrapQuotaTotal memory r) {
        uint256 i = indexOf(u);
        r.wrapShort = _totalView(i, 0);
        r.wrapLong = _totalView(i, 1);
        r.unwrapShort = _totalView(i, 2);
        r.unwrapLong = _totalView(i, 3);
    }

    function _totalView(uint256 i, uint256 l) private view returns (IWrappedToken.WindowView memory) {
        WrapLimitStorage storage w = wl();
        uint256 cfg = _ld(_slot(w.config[i]) + l / 2);
        uint256 tw = _ld(_slot(w.total[i]) + l / 2) >> (88 * (l % 2));
        uint256 part = cfg >> (112 * (l % 2));
        return _wv(uint64(part >> 24), uint24(tw), uint64(tw >> 24), uint24(part >> 88), 10 ** uint8(cfg >> 224));
    }

    function _userView(uint256 cfg, uint256 qw, uint256 l, uint256 unit) private view returns (IWrappedToken.WindowView memory) {
        uint256 part = cfg >> (112 * (l % 2));
        return _wv(uint24(part), _get(qw, 21 * l, 21), _get(qw, 84 + 19 * l, 19), uint24(part >> 88), unit);
    }

    /// @dev `left` raw units (`max` when the part is off), `resetAt` the active window's end (its last minute + 1).
    function _wv(uint256 cap, uint256 start, uint256 used, uint256 p, uint256 unit)
        private view returns (IWrappedToken.WindowView memory v)
    {
        if (cap == 0) return IWrappedToken.WindowView(type(uint256).max, 0);
        uint256 nowMin = block.timestamp / 60;
        uint256 elapsed = (nowMin % _CIRCLE + _CIRCLE - start) % _CIRCLE;
        if (used == 0 || elapsed > p) return IWrappedToken.WindowView(cap * unit, 0);
        v.left = (used < cap ? cap - used : 0) * unit;
        v.resetAt = uint64((nowMin - elapsed + p + 1) * 60);
    }

    // ----- raw words at the declared layout

    function _slot(LegConfig storage x) private pure returns (uint256 p) {
        assembly ("memory-safe") { p := x.slot }
    }

    function _slot(TokenWindows storage x) private pure returns (uint256 p) {
        assembly ("memory-safe") { p := x.slot }
    }

    function _qslot(WrapLimitStorage storage w, bytes32 id, uint256 i) private view returns (uint256 p) {
        mapping(uint256 => uint256) storage m = w.quota[id];
        assembly ("memory-safe") {
            mstore(0, i)
            mstore(0x20, m.slot)
            p := keccak256(0, 0x40)
        }
    }

    function _ld(uint256 p) private view returns (uint256 v) {
        assembly ("memory-safe") { v := sload(p) }
    }

    function _st(uint256 p, uint256 v) private {
        assembly ("memory-safe") { sstore(p, v) }
    }

    function _get(uint256 word, uint256 pos, uint256 width) private pure returns (uint256) {
        return (word >> pos) & ((uint256(1) << width) - 1);
    }

    /// @dev `word` with its `width`-bit field at bit `pos` set to `v` (`v` fits: every caller bounds it).
    function _put(uint256 word, uint256 pos, uint256 width, uint256 v) private pure returns (uint256) {
        uint256 m = ((uint256(1) << width) - 1) << pos;
        return (word & ~m) | ((v << pos) & m);
    }

    // ------------------------------------------------------------------ internal helpers (inlined in the token)

    function indexOf(address u) internal view returns (uint256) {
        uint256 x = $().legIndex[u];
        if (x == 0) revert IWrappedToken.UnknownUnderlying(u);
        return x - 1;
    }

    /// @dev The single-asset ABI works only with exactly one leg.
    function sole() internal view returns (uint256) {
        if ($().legCount != 1) revert IWrappedToken.UnderlyingRequired();
        return 0;
    }

    function isPending() internal view returns (bool) {
        return _isPending($());
    }

    function _isPending(WrappedStorage storage s) private view returns (bool) {
        uint256 eta = s.pending.eta;
        return eta != 0 && block.timestamp <= eta + RATE_WINDOW;
    }

    function _balance(address u) private view returns (uint256) {
        return u == NATIVE ? address(this).balance : IERC20(u).balanceOf(address(this));
    }

    /// @dev `⌊r·num/den⌋`, saturating where the result exceeds 256 bits (`mulDiv` would revert).
    function _value(uint256 r, uint256 num, uint256 den) private pure returns (uint256) {
        (uint256 hi,) = Math.mul512(r, num);
        return hi >= den ? type(uint256).max : Math.mulDiv(r, num, den);
    }
}
