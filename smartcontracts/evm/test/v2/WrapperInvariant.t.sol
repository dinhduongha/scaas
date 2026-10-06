// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {V2Fixture} from "./helpers/V2Fixture.sol";
import {MockERC20, FeeOnTransferERC20} from "../helpers/Mocks.sol";
import {SlashableERC20, RateAdminForwarder} from "./helpers/V2Mocks.sol";
import {SingleUnderlyingToken} from "../../src/metatx/SingleUnderlyingToken.sol";
import {MultiUnderlyingToken} from "../../src/metatx/MultiUnderlyingToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// @notice Handler cho `MultiUnderlyingToken` ba chân (thường / phí-chuyển / chịu sốc âm), tỉ lệ điều chỉnh được,
///         có guardian (TW2 §10.4, review M6). Mọi revert CÓ CHỦ ĐÍCH được bắt và phân loại; revert ngoài danh sách
///         ghi vào `unexpected`, nên `fail_on_revert` không bao giờ nuốt một lỗi thật.
contract WrapperHandler is Test {
    MultiUnderlyingToken public t;
    MockERC20[3] public legs;
    RateAdminForwarder public adm;
    uint256[3] public pks = [uint256(0xA1), 0xB2, 0xC3];
    address public attacker = address(0xA77AC);
    address public feeTaker = address(0xFEE);
    address public relayer = address(0xBEEF);
    address public donor = address(0xD0D0);
    address public outsider = address(0x0D7);
    uint256 public seq;

    uint256[3] public ghostReserve;
    bool[3] public disabled;
    bool public shocked;
    uint256 public lastSlack;
    bool public slackDecreased;
    bool public attackerProfited;
    bool public badExecution;
    bool public wrapWhilePending;
    bytes public unexpected;
    uint256 public calls;

    // the pending change as proposed
    uint256 public proposedAt;
    uint96 public pOldNum;
    uint96 public pOldDen;

    constructor() {
        adm = new RateAdminForwarder();
    }

    function init(MultiUnderlyingToken t_, MockERC20[3] memory legs_) external {
        t = t_;
        legs = legs_;
        lastSlack = _slack();
    }

    function actor(uint256 i) public view returns (address) { return vm.addr(pks[i % 3]); }

    // ------------------------------------------------------------------ bookkeeping

    function _slack() internal view returns (uint256) {
        uint256 c = t.collateralValue();
        uint256 s = t.totalSupply();
        return c >= s ? c - s : 0;
    }

    /// Slack `C − S` không bao giờ giảm, trừ một lần thực thi tỉ lệ (§10.4).
    modifier tracked(bool rateExecution) {
        _;
        uint256 now_ = _slack();
        if (!rateExecution && now_ < lastSlack) slackDecreased = true;
        lastSlack = now_;
        ++calls;
    }

    function _expect(bytes memory err, bytes4[] memory ok) internal {
        bytes4 sel = err.length >= 4 ? bytes4(err) : bytes4(0);
        for (uint256 i; i < ok.length; ++i) if (sel == ok[i]) return;
        if (unexpected.length == 0) unexpected = err.length == 0 ? bytes("empty revert") : err;
    }

    /// Chỗ trống trong danh sách lỗi mong đợi. Không phải `bytes4(0)`: revert rỗng không bao giờ được coi là mong đợi.
    bytes4 constant NONE = 0xffffffff;

    function _sels(bytes4 a, bytes4 b, bytes4 c, bytes4 d, bytes4 e) internal pure returns (bytes4[] memory s) {
        s = new bytes4[](5);
        (s[0], s[1], s[2], s[3], s[4]) = (a, b, c, d, e);
    }

    function _pending() internal view returns (bool) {
        (,,, uint64 eta) = t.pendingRate();
        return eta != 0;
    }

    function _rate(uint256 i) internal view returns (uint256 num, uint256 den) {
        (uint96 n, uint96 d,,,) = t.legOf(address(legs[i]));
        return (n, d);
    }

    /// `a·b ≤ c·d` trong 512 bit.
    function _le(uint256 a, uint256 b, uint256 c, uint256 d) internal pure returns (bool) {
        (uint256 h1, uint256 l1) = Math.mul512(a, b);
        (uint256 h2, uint256 l2) = Math.mul512(c, d);
        return h1 < h2 || (h1 == h2 && l1 <= l2);
    }

    // ------------------------------------------------------------------ wrap / unwrap / reserve

    /// Biến cục bộ của một thao tác, trong memory (solc không via-IR hết stack).
    struct Ctx {
        uint256 i;
        address w;
        MockERC20 u;
        uint256 num;
        uint256 den;
        uint256 balBefore; // wrapper's underlying balance
        uint256 uBefore;   // actor's underlying balance
        uint256 wBefore;   // actor's wrapped balance
    }

    function _ctx(uint256 who, uint256 leg, bool attackerToo) internal view returns (Ctx memory c) {
        c.i = leg % 3;
        c.w = attackerToo && who % 4 == 3 ? attacker : actor(who);
        c.u = legs[c.i];
        (c.num, c.den) = _rate(c.i);
        c.balBefore = c.u.balanceOf(address(t));
        c.uBefore = c.u.balanceOf(c.w);
        c.wBefore = t.balanceOf(c.w);
    }

    function wrap(uint256 who, uint256 leg, uint256 amount) external tracked(false) {
        amount = bound(amount, 0, 1e30);
        legs[leg % 3].mint(who % 4 == 3 ? attacker : actor(who), amount);
        Ctx memory c = _ctx(who, leg, true);
        bool pending = _pending();
        vm.startPrank(c.w);
        c.u.approve(address(t), amount);
        try t.wrap(address(c.u), amount) returns (uint256) {
            vm.stopPrank();
            if (pending) wrapWhilePending = true;
            ghostReserve[c.i] += c.u.balanceOf(address(t)) - c.balBefore;
            // profit oracle: minted·den ≤ amount·num (value at the current, nominal rate never rises)
            if (c.w == attacker && !_le(t.balanceOf(c.w) - c.wBefore, c.den, amount, c.num)) attackerProfited = true;
        } catch (bytes memory err) {
            vm.stopPrank();
            _expect(err, _sels(SingleUnderlyingToken.WrapTooSmall.selector,
                SingleUnderlyingToken.WrapPausedForRateChange.selector, SingleUnderlyingToken.WrapDisabledFor.selector,
                SingleUnderlyingToken.ReserveShortfall.selector, NONE));
        }
    }

    function unwrap(uint256 who, uint256 leg, uint256 frac, uint256 minOutSeed, uint256 recipientSeed)
        external tracked(false)
    {
        Ctx memory c = _ctx(who, leg, true);
        uint256 wrapped = bound(frac, 0, c.wBefore);
        address r = recipientSeed % 5 == 0 ? address(t) : c.w; // recipient = self is refused
        (uint256 quote,) = t.previewUnwrap(address(c.u), wrapped);
        vm.prank(c.w);
        try t.unwrap(address(c.u), wrapped, r, minOutSeed % 2 == 0 ? 0 : quote) returns (uint256 out, uint256) {
            ghostReserve[c.i] -= out;
            if (c.balBefore - c.u.balanceOf(address(t)) != out) badExecution = true;
            // profit oracle: received·num ≤ burned·den
            if (c.w == attacker && !_le(c.u.balanceOf(c.w) - c.uBefore, c.num, c.wBefore - t.balanceOf(c.w), c.den)) {
                attackerProfited = true;
            }
        } catch (bytes memory err) {
            _expect(err, _sels(SingleUnderlyingToken.UnwrapTooSmall.selector,
                SingleUnderlyingToken.InsufficientReserve.selector, SingleUnderlyingToken.UnwrapRecipientInvalid.selector,
                IERC20Errors.ERC20InsufficientBalance.selector, NONE));
        }
    }

    /// R148: gasless unwrap qua op, phí theo phần trăm cho `feeTaker`.
    function unwrapOp(uint256 who, uint256 leg, uint256 frac, uint256 feePpm, uint256 recipientSeed)
        external tracked(false)
    {
        Ctx memory c = _ctx(who, leg, false);
        address r = recipientSeed % 5 == 0 ? address(t) : (recipientSeed % 5 == 1 ? outsider : c.w);
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: c.w, to: r, value: bound(frac, 0, c.wBefore / 2),
            data: abi.encodeWithSelector(bytes4(keccak256("unwrap(address,address,uint256)")), address(c.u), r,
                uint256(0)),
            batch: ++seq, nonce: 0, validUntil: block.timestamp + 1, mode: MetaTxLib.MODE_RESTRICT_RELAYER
                | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT | MetaTxLib.MODE_FEE_PERCENT,
            relayer: relayer, fee: bound(feePpm, 0, 10_000), feeRecipient: feeTaker
        });
        bytes memory sig = _sign(pks[who % 3], m);
        vm.prank(relayer);
        try t.executeMetaTransaction(m, sig) {
            ghostReserve[c.i] -= c.balBefore - c.u.balanceOf(address(t));
        } catch (bytes memory err) {
            _expect(err, _sels(SingleUnderlyingToken.UnwrapTooSmall.selector,
                SingleUnderlyingToken.InsufficientReserve.selector, SingleUnderlyingToken.UnwrapRecipientInvalid.selector,
                IERC20Errors.ERC20InsufficientBalance.selector, NONE));
        }
    }

    function _sign(uint256 pk, MetaTxLib.MetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, t.metaTxDigest(m));
        return abi.encodePacked(r, s, v);
    }

    function addReserve(uint256 leg, uint256 amount) external tracked(false) {
        uint256 i = leg % 3;
        amount = bound(amount, 0, 1e24);
        MockERC20 u = legs[i];
        u.mint(donor, amount);
        uint256 balBefore = u.balanceOf(address(t));
        vm.startPrank(donor);
        u.approve(address(t), amount);
        try t.addReserve(address(u), amount) {
            ghostReserve[i] += u.balanceOf(address(t)) - balBefore;
        } catch (bytes memory err) {
            _expect(err, _sels(SingleUnderlyingToken.WrapDisabledFor.selector,
                SingleUnderlyingToken.ReserveShortfall.selector, NONE, NONE, NONE));
        }
        vm.stopPrank();
    }

    /// Quà tặng bằng chuyển thường: ngoài reserve, không định giá gì.
    function donate(uint256 leg, uint256 amount) external tracked(false) {
        legs[leg % 3].mint(address(t), bound(amount, 0, 1e24));
    }

    /// Sốc âm trên chân 2: tịch thu từ wrapper.
    function shock(uint256 amount) external tracked(false) {
        SlashableERC20 u = SlashableERC20(address(legs[2]));
        uint256 bal = u.balanceOf(address(t));
        if (bal == 0) return;
        u.slash(address(t), bound(amount, 1, bal));
        shocked = true;
    }

    function transferMeta(uint256 from, uint256 to, uint256 frac, uint256 feePpm) external tracked(false) {
        uint256 pk = pks[from % 3];
        address f = vm.addr(pk);
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: f, to: actor(to), value: bound(frac, 0, t.balanceOf(f) / 2), data: "", batch: ++seq, nonce: 0,
            validUntil: block.timestamp + 1, mode: MetaTxLib.MODE_FEE_PERCENT | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT,
            relayer: address(0), fee: bound(feePpm, 0, 10_000), feeRecipient: feeTaker
        });
        bytes memory sig = _sign(pk, m);
        vm.prank(relayer);
        try t.executeMetaTransaction(m, sig) {} catch (bytes memory err) {
            _expect(err, new bytes4[](0));
        }
    }

    // ------------------------------------------------------------------ rates, guardian

    function propose(uint256 leg, uint256 stepSeed, bool up) external tracked(false) {
        if (_pending()) return;
        uint256 i = leg % 3;
        (uint256 n, uint256 d) = _rate(i);
        (uint256 n2, uint256 d2) = _candidate(n, d, bound(stepSeed, 0, t.maxRateStepBps()), up);
        if (n2 == 0 || d2 == 0 || n2 > type(uint96).max || d2 > type(uint96).max) return;
        if (!_withinStep(n, d, n2, d2)) return; // outside the bound: not this handler's business
        adm.exec(address(t), abi.encodeCall(SingleUnderlyingToken.proposeRate, (address(legs[i]), uint96(n2), uint96(d2))));
        proposedAt = block.timestamp;
        (pOldNum, pOldDen) = (uint96(n), uint96(d));
    }

    /// Một tỉ lệ cách `n/d` khoảng `step` bps: nhân cả hai với 10⁴ khi còn vừa uint96, nếu không thì dịch số lớn hơn.
    function _candidate(uint256 n, uint256 d, uint256 step, bool up) internal pure returns (uint256, uint256) {
        if (n * (10_000 + step) <= type(uint96).max && d * 10_000 <= type(uint96).max) {
            return (up ? n * (10_000 + step) : n * (10_000 - step), d * 10_000);
        }
        if (n >= d) return (up ? n + n * step / 10_000 : n - n * step / 10_000, d);
        return (n, up ? d - d * step / 20_000 : d + d * step / 20_000);
    }

    function _withinStep(uint256 n, uint256 d, uint256 n2, uint256 d2) internal view returns (bool) {
        uint256 a = n2 * d;
        uint256 b = n * d2;
        return (a > b ? a - b : b - a) * 10_000 <= b * t.maxRateStepBps();
    }

    function cancel() external tracked(false) {
        try adm.exec(address(t), abi.encodeCall(SingleUnderlyingToken.cancelRate, ())) {} catch (bytes memory err) {
            _expect(err, _sels(SingleUnderlyingToken.NoRateChangePending.selector, NONE, NONE, NONE, NONE));
        }
    }

    function execute() external tracked(true) {
        (address u, uint96 num, uint96 den, uint64 eta) = t.pendingRate();
        bool shortfall; // M1: no execution on phantom reserve
        for (uint256 i; i < 3; ++i) {
            (,, uint256 r,,) = t.legOf(address(legs[i]));
            if (legs[i].balanceOf(address(t)) < r) shortfall = true;
        }
        // only the admin executes
        vm.prank(attacker);
        try t.executeRate() { badExecution = true; } catch {}
        try adm.exec(address(t), abi.encodeCall(SingleUnderlyingToken.executeRate, ())) {
            if (u == address(0) || shortfall || block.timestamp < eta || eta != proposedAt + t.rateDelay()) {
                badExecution = true;
            }
            if (!_withinStep(pOldNum, pOldDen, num, den)) badExecution = true;
        } catch (bytes memory err) {
            _expect(err, _sels(SingleUnderlyingToken.NoRateChangePending.selector,
                SingleUnderlyingToken.RateChangeNotReady.selector, SingleUnderlyingToken.RateChangeUndercollateralized.selector,
                SingleUnderlyingToken.ReserveShortfall.selector, SingleUnderlyingToken.RateDecreaseWithDisabledLeg.selector));
        }
    }

    /// Nhảy ĐÚNG tới `eta` hoặc `eta + 7 ngày` (hai biên của cửa sổ), hoặc trôi một chút khi không có gì chờ.
    function warpToEta(bool windowEnd, uint256 drift) external tracked(false) {
        (,,, uint64 eta) = t.pendingRate();
        if (eta == 0) {
            vm.warp(block.timestamp + bound(drift, 0, 3 days));
            return;
        }
        uint256 target = windowEnd ? uint256(eta) + 7 days : eta;
        if (target > block.timestamp) vm.warp(target);
    }

    function disable(uint256 leg) external tracked(false) {
        uint256 i = leg % 3;
        if (disabled[i]) {
            try t.disableWrap(address(legs[i]), "again") { badExecution = true; } catch {}
            return;
        }
        t.disableWrap(address(legs[i]), "depeg");
        disabled[i] = true;
    }
}

/// @notice Một hợp đồng bất biến cho mỗi cấu hình tỉ lệ (§10.4): `1:1`, `10¹²:1`, `1:10⁴`, `(2⁹⁶−1):1`, `1:(2⁹⁶−1)`,
///         `3:7` — cả ba chân cùng tỉ lệ ban đầu.
abstract contract WrapperInvariantBase is StdInvariant, V2Fixture {
    WrapperHandler h;
    MultiUnderlyingToken t;
    MockERC20[3] legs;

    function _rate() internal pure virtual returns (uint256 num, uint256 den);

    function setUp() public {
        vm.warp(1_800_000_000);
        h = new WrapperHandler();
        legs[0] = new MockERC20("Plain", "PLN", 6);
        legs[1] = MockERC20(address(new FeeOnTransferERC20()));
        legs[2] = MockERC20(address(new SlashableERC20(6)));
        address[] memory us = new address[](3);
        uint256[] memory nums = new uint256[](3);
        uint256[] memory dens = new uint256[](3);
        (uint256 num, uint256 den) = _rate();
        for (uint256 i; i < 3; ++i) (us[i], nums[i], dens[i]) = (address(legs[i]), num, den);
        t = _multi(us, nums, dens, _adjustable(address(h.adm())), address(h));
        h.init(t, legs);
        targetContract(address(h));
        bytes4[] memory sels = new bytes4[](13);
        (sels[0], sels[1], sels[2], sels[3], sels[4]) = (h.wrap.selector, h.unwrap.selector, h.unwrapOp.selector,
            h.addReserve.selector, h.donate.selector);
        (sels[5], sels[6], sels[7], sels[8], sels[9]) = (h.shock.selector, h.transferMeta.selector, h.propose.selector,
            h.cancel.selector, h.execute.selector);
        // execute listed twice: rate executions are the rarest path to reach (pending + window + collateral)
        (sels[10], sels[11], sels[12]) = (h.warpToEta.selector, h.disable.selector, h.execute.selector);
        targetSelector(FuzzSelector({addr: address(h), selectors: sels}));
    }

    function _holdersSum() internal view returns (uint256 s) {
        for (uint256 i; i < 3; ++i) s += t.balanceOf(h.actor(i));
        s += t.balanceOf(h.attacker()) + t.balanceOf(h.feeTaker()) + t.balanceOf(h.relayer());
    }

    function invariant_solventAndBalancesSumToSupply() public view {
        assertGe(t.collateralValue(), t.totalSupply());
        assertEq(_holdersSum(), t.totalSupply());
    }

    function invariant_slackNeverDecreasesAndNoProfit() public view {
        assertFalse(h.slackDecreased(), "slack decreased outside a rate execution");
        assertFalse(h.attackerProfited(), "wrap/unwrap attacker gained value at par");
    }

    function invariant_perLegConservation() public view {
        for (uint256 i; i < 3; ++i) {
            (,, uint256 reserve,,) = t.legOf(address(legs[i]));
            assertEq(reserve, h.ghostReserve(i));
            if (i < 2) assertGe(legs[i].balanceOf(address(t)), reserve); // well-behaved legs
        }
    }

    function invariant_rateAndGuardianRules() public view {
        assertFalse(h.badExecution(), "unlawful rate execution or guardian action");
        assertFalse(h.wrapWhilePending(), "a wrap succeeded while a rate change was pending");
        for (uint256 i; i < 3; ++i) {
            (,,,, bool enabled) = t.legOf(address(legs[i]));
            if (h.disabled(i)) assertFalse(enabled, "a disabled leg was re-enabled");
        }
        assertEq(h.unexpected(), bytes(""), "unexpected revert");
    }
}

contract WrapperInvariant_1_1 is WrapperInvariantBase {
    function _rate() internal pure override returns (uint256, uint256) { return (1, 1); }
}

contract WrapperInvariant_1e12_1 is WrapperInvariantBase {
    function _rate() internal pure override returns (uint256, uint256) { return (1e12, 1); }
}

contract WrapperInvariant_1_1e4 is WrapperInvariantBase {
    function _rate() internal pure override returns (uint256, uint256) { return (1, 1e4); }
}

contract WrapperInvariant_max_1 is WrapperInvariantBase {
    function _rate() internal pure override returns (uint256, uint256) { return (type(uint96).max, 1); }
}

contract WrapperInvariant_1_max is WrapperInvariantBase {
    function _rate() internal pure override returns (uint256, uint256) { return (1, type(uint96).max); }
}

contract WrapperInvariant_3_7 is WrapperInvariantBase {
    function _rate() internal pure override returns (uint256, uint256) { return (3, 7); }
}
