// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IUnderlyingToken} from "./IUnderlyingToken.sol";
import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {AdminLib} from "./AdminLib.sol";
import {MetaTokenBase} from "./MetaTokenBase.sol";
import {HederaLib} from "../hedera/HederaLib.sol";

/// @title Legs, reserve and rates of kind `UNDERLYING` (CTR-TOK-24), in the ERC-7201 namespace `scaas.underlying`.
/// @notice External library: the core of wrap and unwrap **without a destination** (pull, rate, reserve; pay out),
///         rate changes with timelock, `disableWrap`. The token mints and burns (ERC-20 stays inline) and emits
///         `Wrapped`/`Unwrapped`/`ReserveAdded`.
///
///         Rate `q = num/den` = wrapped raw units per underlying raw unit (CTR-TOK-04); every output rounds DOWN:
///         `minted = ⌊in·q⌋`, `out = ⌊w/q⌋`, unwrap burns only `⌈out·q⌉ ≤ w`. Invariant (CTR-TOK-05):
///         `Σ⌊reserve_i·q_i⌋ ≥ totalSupply()`; `reserve` changes only through wrap, unwrap, `addReserve`; the raw
///         balance never prices anything. The native leg (`address(0)`, CTR-TOK-26) reads `address(this).balance`
///         where an ERC-20 leg reads `balanceOf(this)`.
library UnderlyingLib {
    using SafeERC20 for IERC20;

    /// @dev slot a: token ‖ decimals ‖ wrapEnabled ‖ adjustable (copy, so a fixed-rate wrap reads no config);
    ///      slot b: num ‖ den; slot c: reserve.
    struct Leg {
        address token;
        uint8 decimals;
        bool wrapEnabled;
        bool adjustable;
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
    struct UnderlyingStorage {
        mapping(uint256 => Leg) legs;
        mapping(address => uint256) legIndex; // index + 1
        PendingRate pending;
        uint8 legCount;
        uint32 rateDelay;
        uint16 maxRateStepBps;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.underlying")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0x38d6f7edefffa65376a58a6aced8a2c86698d3a0b5d15a785f69ed89d0cd1000;

    address internal constant NATIVE = address(0);
    uint256 internal constant MAX_LEGS = 8;
    uint256 internal constant MAX_RATE = type(uint96).max;
    /// @notice Execution window after `eta`; past it the change counts as none everywhere.
    uint256 internal constant RATE_WINDOW = 7 days;

    function $() internal pure returns (UnderlyingStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    // ------------------------------------------------------------------ init

    /// @notice The token's `_init`: legs 1–8 (the factory's index reads the same `legs`), the metadata, the
    ///         flags/owner/roles (`AdminLib.init`), the rate config, then the legs in their given order (never changes).
    function initToken(IFactoryToken.TokenConfig calldata c, bool isHedera) public {
        uint256 n = c.legs.length;
        if (n == 0 || n > MAX_LEGS) revert MetaTokenBase.UnderlyingCountInvalid(n);
        AdminLib.TokenStorage storage t = AdminLib.$();
        t.name = c.name;
        t.symbol = c.symbol;
        t.decimals = c.decimals;
        AdminLib.init(AdminLib.KIND_UNDERLYING, c.features, c.lockedFeatures, c.owner, c.roles);
        bool adjustable = AdminLib.hasFeature(AdminLib.RATE_ADJUSTABLE);
        UnderlyingStorage storage s = $();
        IFactoryToken.RateConfig calldata rate = c.rate;
        if (!adjustable) {
            if (rate.rateDelay != 0 || rate.maxRateStepBps != 0) revert IUnderlyingToken.RateConfigInvalid();
        } else {
            if (rate.rateDelay < 2 days || rate.rateDelay > 30 days || rate.maxRateStepBps == 0
                || rate.maxRateStepBps > 1000) revert IUnderlyingToken.RateConfigInvalid();
            s.rateDelay = rate.rateDelay;
            s.maxRateStepBps = rate.maxRateStepBps;
        }
        for (uint256 i; i < n; ++i) _addLeg(s, c.legs[i], adjustable, isHedera);
    }

    function _addLeg(UnderlyingStorage storage s, IFactoryToken.Leg calldata l, bool adjustable, bool isHedera)
        private
    {
        address u = l.underlying;
        uint8 d;
        if (u == NATIVE) {
            d = isHedera ? 8 : 18; // Hedera's EVM counts the native coin in tinybars
        } else {
            if (u == address(this) || u.code.length == 0) revert IUnderlyingToken.UnderlyingInvalid(u);
            if (isHedera && !HederaLib.checkAndAssociate(u)) revert IUnderlyingToken.UnderlyingInvalid(u);
            (bool ok, bytes memory ret) = u.staticcall(abi.encodeCall(IERC20Metadata.decimals, ()));
            if (!ok || ret.length != 32 || uint256(bytes32(ret)) > type(uint8).max) {
                revert IUnderlyingToken.DecimalsUnreadable(u);
            }
            d = uint8(uint256(bytes32(ret)));
        }
        (uint256 num, uint256 den) = (l.num, l.den);
        if (num == 0 || den == 0 || num > MAX_RATE || den > MAX_RATE) revert IUnderlyingToken.RateInvalid(num, den);
        if (s.legIndex[u] != 0) revert IUnderlyingToken.DuplicateUnderlying(u);
        uint256 i = s.legCount;
        s.legs[i] = Leg({
            token: u, decimals: d, wrapEnabled: true, adjustable: adjustable,
            num: uint96(num), den: uint96(den), reserve: 0
        });
        s.legIndex[u] = i + 1;
        s.legCount = uint8(i + 1);
    }

    // ------------------------------------------------------------------ wrap / reserve / unwrap

    /// @notice Pull `amount` from `from` (or take `value` on the native leg), price the measured delta.
    function wrap(uint256 i, uint256 amount, address from, uint256 value)
        public returns (address u, uint256 received, uint256 minted)
    {
        UnderlyingStorage storage s = $();
        Leg storage L = s.legs[i];
        u = L.token;
        if (!L.wrapEnabled) revert IUnderlyingToken.WrapDisabledFor(u);
        if (L.adjustable && _isPending(s)) revert IUnderlyingToken.WrapPausedForRateChange(u);
        received = _pull(L, amount, from, value);
        minted = Math.mulDiv(received, L.num, L.den);
        if (minted == 0) revert IUnderlyingToken.WrapTooSmall();
    }

    /// @notice Anyone; no mint. Refused on a leg whose wrap is disabled.
    function addReserve(uint256 i, uint256 amount, address from, uint256 value) public returns (uint256 received) {
        Leg storage L = $().legs[i];
        if (!L.wrapEnabled) revert IUnderlyingToken.WrapDisabledFor(L.token);
        received = _pull(L, amount, from, value);
    }

    /// @dev One balance read before serves both the shortfall check (no wrap or top-up while `balance < reserve`)
    ///      and the measurement. Native: the balance already holds `value`, which is the measured delta.
    function _pull(Leg storage L, uint256 amount, address from, uint256 value) private returns (uint256 received) {
        address u = L.token;
        uint256 reserve = L.reserve;
        if (u == NATIVE) {
            if (value != amount) revert IUnderlyingToken.NativeValueMismatch(value, amount);
            uint256 before = address(this).balance - value;
            if (before < reserve) revert IUnderlyingToken.ReserveShortfall(u, before, reserve);
            received = value;
        } else {
            if (value != 0) revert IUnderlyingToken.NativeValueMismatch(value, 0);
            uint256 before = IERC20(u).balanceOf(address(this));
            if (before < reserve) revert IUnderlyingToken.ReserveShortfall(u, before, reserve);
            IERC20(u).safeTransferFrom(from, address(this), amount);
            received = IERC20(u).balanceOf(address(this)) - before;
        }
        L.reserve = reserve + received;
    }

    /// @notice Every check before any effect: recipient, `0 < out`, `out ≥ minOut`, `out ≤ reserve`.
    function quoteUnwrap(uint256 i, uint256 wrapped, address recipient, uint256 minOut)
        public view returns (uint256 out, uint256 burned)
    {
        if (recipient == address(0) || recipient == address(this)) {
            revert IUnderlyingToken.UnwrapRecipientInvalid(recipient);
        }
        Leg storage L = $().legs[i];
        (uint256 num, uint256 den) = (L.num, L.den);
        out = Math.mulDiv(wrapped, den, num);
        if (out == 0) revert IUnderlyingToken.UnwrapTooSmall();
        if (out < minOut) revert IUnderlyingToken.UnwrapBelowMin(out, minOut);
        uint256 reserve = L.reserve;
        if (out > reserve) revert IUnderlyingToken.InsufficientReserve(L.token, out, reserve);
        burned = Math.mulDiv(out, num, den, Math.Rounding.Ceil);
    }

    /// @notice After the token burned: `reserve -= out`, then the one outside call, under the token's guard (CEI).
    ///         The balance must drop by EXACTLY `out` (a sender-pays fee reverts, CTR-TOK-11). The native coin goes
    ///         with all gas; a recipient that refuses it reverts the unwrap.
    function payOut(uint256 i, address recipient, uint256 out) public returns (address u) {
        Leg storage L = $().legs[i];
        L.reserve -= out;
        u = L.token;
        uint256 before = _balance(u);
        if (u == NATIVE) Address.sendValue(payable(recipient), out);
        else IERC20(u).safeTransfer(recipient, out);
        uint256 after_ = _balance(u);
        uint256 sent = before > after_ ? before - after_ : 0;
        if (sent != out) revert IUnderlyingToken.UnderlyingTransferMismatch(u, out, sent);
    }

    // ------------------------------------------------------------------ guardian (WRAP_DISABLEABLE)

    /// @notice One-way: no re-enable (a compromised guardian reopening a depegged inflow would drain the good legs).
    function disableWrap(address u, bytes32 reason, address caller) public {
        if (!AdminLib.hasFeature(AdminLib.WRAP_DISABLEABLE) || !AdminLib.hasRole(AdminLib.WRAP_DISABLEABLE, caller)) {
            revert IUnderlyingToken.NotGuardian();
        }
        Leg storage L = $().legs[indexOf(u)];
        if (!L.wrapEnabled) revert IUnderlyingToken.WrapDisabledFor(u);
        L.wrapEnabled = false;
        emit IUnderlyingToken.WrapDisabled(u, caller, reason);
    }

    // ------------------------------------------------------------------ rates (CTR-TOK-06, CTR-TOK-13)

    function _onlyRateAdmin(address caller) private view {
        if (!AdminLib.hasFeature(AdminLib.RATE_ADJUSTABLE)) revert IUnderlyingToken.RateFixed();
        if (!AdminLib.hasRole(AdminLib.RATE_ADJUSTABLE, caller)) revert IUnderlyingToken.NotRateAdmin();
    }

    /// @notice The step is checked ONCE, here, against the current rate (which cannot change while pending).
    function proposeRate(address u, uint96 num, uint96 den, address caller) public {
        _onlyRateAdmin(caller);
        UnderlyingStorage storage s = $();
        if (_isPending(s)) revert IUnderlyingToken.RateChangePending();
        uint256 i = indexOf(u);
        if (num == 0 || den == 0) revert IUnderlyingToken.RateInvalid(num, den);
        Leg storage L = s.legs[i];
        (uint96 n0, uint96 d0) = (L.num, L.den);
        // |num'·den − num·den'|·10⁴ ≤ num·den'·bps — exact in integers, every product < 2^207.
        uint256 a = uint256(num) * d0;
        uint256 b = uint256(n0) * den;
        if ((a > b ? a - b : b - a) * 10_000 > b * s.maxRateStepBps) revert IUnderlyingToken.RateStepTooLarge();
        uint64 eta = uint64(block.timestamp + s.rateDelay);
        s.pending = PendingRate({leg: uint8(i), num: num, den: den, eta: uint56(eta)});
        emit IUnderlyingToken.RateChangeProposed(u, n0, d0, num, den, eta);
    }

    function cancelRate(address caller) public {
        _onlyRateAdmin(caller);
        UnderlyingStorage storage s = $();
        if (!_isPending(s)) revert IUnderlyingToken.NoRateChangePending();
        _drop(s);
    }

    /// @notice `disableFeature(RATE_ADJUSTABLE)` fixes the rate and cancels a pending change (CTR-TOK-06).
    function dropPending() public {
        UnderlyingStorage storage s = $();
        if (_isPending(s)) _drop(s);
        else delete s.pending;
    }

    function _drop(UnderlyingStorage storage s) private {
        address u = s.legs[s.pending.leg].token;
        delete s.pending;
        emit IUnderlyingToken.RateChangeCancelled(u);
    }

    /// @notice Only the rate admin executes: a third party cannot bundle the execution with its own wraps.
    function executeRate(address caller, uint256 supply) public {
        _onlyRateAdmin(caller);
        UnderlyingStorage storage s = $();
        PendingRate memory p = s.pending;
        if (p.eta == 0) revert IUnderlyingToken.NoRateChangePending();
        if (block.timestamp < p.eta) revert IUnderlyingToken.RateChangeNotReady(p.eta);
        if (block.timestamp > uint256(p.eta) + RATE_WINDOW) revert IUnderlyingToken.RateChangeExpired(p.eta);
        bool anyDisabled = _requireCollateral(s, p, supply);
        Leg storage T = s.legs[p.leg];
        (uint96 n0, uint96 d0) = (T.num, T.den);
        if (anyDisabled && uint256(p.num) * d0 < uint256(n0) * p.den) {
            revert IUnderlyingToken.RateDecreaseWithDisabledLeg();
        }
        T.num = p.num;
        T.den = p.den;
        delete s.pending;
        emit IUnderlyingToken.RateChanged(T.token, n0, d0, p.num, p.den);
    }

    /// @dev Every leg: `balance ≥ reserve` (no phantom reserve); then `C' ≥ supply` with the new rate, summing with an
    ///      early exit once covered but still checking every leg's balance. Returns "some leg has wrap disabled".
    function _requireCollateral(UnderlyingStorage storage s, PendingRate memory p, uint256 supply)
        private view returns (bool anyDisabled)
    {
        uint256 c;
        uint256 n = s.legCount;
        for (uint256 i; i < n; ++i) {
            Leg storage L = s.legs[i];
            uint256 r = L.reserve;
            uint256 bal = _balance(L.token);
            if (bal < r) revert IUnderlyingToken.ReserveShortfall(L.token, bal, r);
            if (!L.wrapEnabled) anyDisabled = true;
            if (c < supply) {
                c = Math.saturatingAdd(c, i == p.leg ? _value(r, p.num, p.den) : _value(r, L.num, L.den));
            }
        }
        if (c < supply) revert IUnderlyingToken.RateChangeUndercollateralized(c, supply);
    }

    // ------------------------------------------------------------------ views

    function collateralValue() public view returns (uint256 c) {
        UnderlyingStorage storage s = $();
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

    // ------------------------------------------------------------------ internal helpers (inlined in the token)

    function indexOf(address u) internal view returns (uint256) {
        uint256 x = $().legIndex[u];
        if (x == 0) revert IUnderlyingToken.UnknownUnderlying(u);
        return x - 1;
    }

    /// @dev The single-asset ABI works only with exactly one leg.
    function sole() internal view returns (uint256) {
        if ($().legCount != 1) revert IUnderlyingToken.UnderlyingRequired();
        return 0;
    }

    function isPending() internal view returns (bool) {
        return _isPending($());
    }

    function _isPending(UnderlyingStorage storage s) private view returns (bool) {
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
