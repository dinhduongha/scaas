// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs} from "../../script/KindModules.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {WrappedLib} from "../../src/metatx/WrappedLib.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {DexLegs} from "../helpers/DexLegs.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {UACall} from "../ua/UACall.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {WrapLimitsBase} from "./WrapLimitsBase.sol";

/// Group 3l, kind `WRAPPED` (spec 2026-11-10-wrap-limits.md §11 rows 1-11, 13-23, 26-35, 37, 38; R26, R27): each refusal
/// beside its positive control, one change at a time. UNAUDITED.
contract WrapLimitsTest is WrapLimitsBase {
    uint32 constant DAY = 1 days;
    uint256 constant T0 = 1_800_000_000; // UALedgerBase's start: a whole minute

    function _overId(uint8 limit, bytes32 id, uint256 amount, uint256 left) internal view returns (bytes memory) {
        return abi.encodeWithSelector(IWrappedToken.WrapLimitExceeded.selector, u, limit, id, amount, left);
    }

    /// A derived UA's unwrap through `mtxExecute` (the generic path; the subject is the ticket's UA, never `UA_POOL`).
    function _uaUnwrap(WrappedToken w, bytes32 ua, uint256 wrapped, bytes memory err) internal {
        MetaTxLib.UAMetaTransaction memory m =
            _m(address(w), ua, abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", u, wrapped, bob, 0));
        bytes memory a = _authM(address(w), m);
        if (err.length != 0) vm.expectRevert(err);
        vm.prank(RELAYER);
        w.mtxExecute(m, UACall.auth(m.from, a));
    }

    // ------------------------------------------------------------------ row 1, 2: the lists

    function test_r1_wrapperListReadsThePayerBeforeThePull() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 0, OFF(), OFF(), OFF(), OFF()), false, true, false);
        _wrapRev(w, bob, 10, abi.encodeWithSelector(IWrappedToken.WrapperNotListed.selector, _pad(bob)));
        assertEq(und.balanceOf(address(w)), 0, "nothing pulled");
        _grant(w, WLIST, LISTER);
        vm.prank(LISTER);
        w.setWrapMember(_pad(bob), true, false);
        _wrap(w, bob, 10); // positive control
        // the payer, never the receiver: an unlisted payer into a listed UA is refused
        vm.prank(LISTER);
        w.setWrapMember(uaP, true, true);
        _fundW(w, alice, 10);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapperNotListed.selector, _pad(alice)));
        vm.prank(alice);
        w.wrapToUA(u, 10, uaP);
        // before the pull: an unlisted payer with no allowance gets the list's name, not the pull's
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapperNotListed.selector, _pad(address(0xC0))));
        vm.prank(address(0xC0));
        w.wrap(u, 10);
    }

    function test_r2_unwrapperListReadsTheHolder() public {
        WrappedToken w = _hyb();
        _wrap(w, alice, 100);
        _set(w, _cfg1(0, 0, OFF(), OFF(), OFF(), OFF()), false, false, true);
        _unwrapRev(w, alice, 10, abi.encodeWithSelector(IWrappedToken.UnwrapperNotListed.selector, _pad(alice)));
        _grant(w, WLIST, LISTER);
        vm.prank(LISTER);
        w.setWrapMember(_pad(bob), false, true);
        // a listed recipient does not help
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.UnwrapperNotListed.selector, _pad(alice)));
        vm.prank(alice);
        w.unwrap(u, 10, bob, 0);
        vm.prank(LISTER);
        w.setWrapMember(_pad(alice), false, true);
        _unwrap(w, alice, 10); // positive control
        // a derived UA is read as itself
        vm.prank(alice);
        w.transferToUA(uaP, 50);
        _uaUnwrap(w, uaP, 10, abi.encodeWithSelector(IWrappedToken.UnwrapperNotListed.selector, uaP));
        vm.prank(LISTER);
        w.setWrapMember(uaP, false, true);
        _uaUnwrap(w, uaP, 10, "");
        assertEq(und.balanceOf(bob), 10);
    }

    // ------------------------------------------------------------------ rows 3-6: the windows

    function test_r3_perUserWrapShortAndLong() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 0, L(100, 0, DAY), L(150, 0, 7 * DAY), OFF(), OFF()), false, false, false);
        _wrap(w, alice, 100); // at the short cap
        _wrapRev(w, alice, 1, _over(0, alice, 1, 0));
        vm.warp(T0 + DAY + 60); // the short window over, the long one not
        _wrap(w, alice, 50);
        _wrapRev(w, alice, 1, _over(1, alice, 1, 0));
        _wrap(w, bob, 100); // another id, its own windows
    }

    function test_r3_quantaRoundUp() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(1, 0, L(10, 0, DAY), OFF(), OFF(), OFF()), false, false, false);
        _wrap(w, alice, 91); // ⌈91/10⌉ = 10 quanta: the cap
        _wrapRev(w, alice, 9, _over(0, alice, 9, 0)); // ⌈9/10⌉ = 1
    }

    function test_r4_unwrapCountsTheUnderlyingOut() public {
        WrappedToken w = _hybWith(1 | (uint256(1) << GovernanceBits.MINTABLE) | CONTROLS, u, 2); // 2 units per raw unit
        _wrap(w, alice, 200); // 400 units
        _set(w, _cfg1(0, 0, OFF(), OFF(), L(100, 0, DAY), OFF()), false, false, false);
        _unwrap(w, alice, 200); // out 100: at the cap (burned 200 would be over)
        _unwrapRev(w, alice, 2, _over(2, alice, 1, 0));
        assertEq(_q(w, alice).unwrapShort.left, 0);
    }

    function test_r5_tokenWideCap() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 0, L(100, 150, DAY), OFF(), OFF(), OFF()), false, false, false);
        _wrap(w, alice, 100);
        _wrap(w, bob, 50);
        _wrapRev(w, bob, 1, _capOver(0, 1, 0));
        _wrapRev(w, alice, 1, _over(0, alice, 1, 0)); // the per-user part first
        vm.warp(T0 + DAY + 60);
        _wrap(w, bob, 1); // positive control: the next window
    }

    /// Row 35 (Fable P2-2, accepted and pinned): one id can use up a token-wide unwrap cap; the others wait for the window.
    function test_r35_tokenWideCapIsFirstCome() public {
        WrappedToken w = _hyb();
        _wrap(w, alice, 100);
        _wrap(w, bob, 100);
        _set(w, _cfg1(0, 0, OFF(), OFF(), L(0, 100, DAY), OFF()), false, false, false);
        _unwrap(w, alice, 100);
        _unwrapRev(w, bob, 1, _capOver(2, 1, 0));
        vm.warp(T0 + DAY + 60);
        _unwrap(w, bob, 1);
    }

    function test_r6_fixedWindowInMinutes() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 0, L(10, 0, 3600), OFF(), OFF(), OFF()), false, false, false);
        _wrap(w, alice, 10);
        vm.warp(T0 + 3659); // 60 whole minutes elapsed: still the window
        _wrapRev(w, alice, 1, _over(0, alice, 1, 0));
        vm.warp(T0 + 3660);
        _wrap(w, alice, 1);
    }

    function test_r6_startNotResetByAUse() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 0, L(10, 0, 3600), OFF(), OFF(), OFF()), false, false, false);
        _wrap(w, alice, 5);
        vm.warp(T0 + 1800);
        _wrap(w, alice, 5);
        vm.warp(T0 + 3660); // the window started at T0 is over, whatever the later use
        _wrap(w, alice, 10);
    }

    function _invalid(WrappedToken w, IWrappedToken.WrapLimit memory x, uint8 limit) internal {
        IWrappedToken.WrapLegLimits[] memory a = _cfg1(0, 0, OFF(), OFF(), OFF(), OFF());
        if (limit == 0) a[0].wrapShort = x;
        else a[0].unwrapLong = x;
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapLimitInvalid.selector, u, limit));
        vm.prank(OWNER);
        w.setWrapLimits(a, false, false, false);
    }

    /// Row 6, row 32 (R26's bounds): a period of whole minutes in [1, 2^20 − 1] when a part is on, else 0; `perUser ≤ 2^19 − 1`.
    function test_r6_r32_limitShape() public {
        WrappedToken w = _hyb();
        _invalid(w, L(10, 0, 3601), 0);
        _invalid(w, L(10, 0, 0), 0);
        _invalid(w, L(0, 10, 0), 3);
        _invalid(w, L(0, 0, 60), 0);
        _invalid(w, L(10, 0, uint32(1 << 20) * 60), 0);
        _invalid(w, L(uint24(1 << 19), 0, 60), 3);
        _set(w, _cfg1(0, 0, L(uint24((1 << 19) - 1), type(uint64).max, uint32((1 << 20) - 1) * 60), OFF(), OFF(),
            L(uint24((1 << 19) - 1), 0, 60)), false, false, false); // the largest pass
        (IWrappedToken.WrapLegLimits[] memory legs,,,,,,,) = w.wrapLimits();
        assertEq(legs[0].wrapShort.period, uint32((1 << 20) - 1) * 60);
        assertEq(legs[0].wrapShort.perUser, (1 << 19) - 1);
    }

    // ------------------------------------------------------------------ row 7: the minute circle (P1-4)

    function _straddle(uint256 t) internal {
        vm.warp(t - 120); // two minutes before the 2^21 circle wraps
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 0, L(10, 0, 600), OFF(), OFF(), OFF()), false, false, false);
        _wrap(w, alice, 10);
        vm.warp(t + 300); // across the wrap, 7 minutes in: still the window, no panic
        _wrapRev(w, alice, 1, _over(0, alice, 1, 0));
        vm.warp(t + 540); // 11 minutes: over
        _wrap(w, alice, 10); // a window opened after the wrap
        vm.warp(t + 540 + 600);
        _wrapRev(w, alice, 1, _over(0, alice, 1, 0));
        vm.warp(t + 540 + 660);
        _wrap(w, alice, 1);
    }

    function test_r7_circleWraps2029() public {
        _straddle(1_887_436_800); // 15 · 2^21 minutes: 2029-10-23 05:20 UTC
    }

    function test_r7_circleWraps2033() public {
        _straddle(2_013_265_920); // 2^25 minutes: 2033-10-18 16:32 UTC, where a checked 24-bit subtraction would panic
    }

    function test_r7_aliasedStaleWindowOnlyRefuses() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 0, L(10, 0, DAY), OFF(), OFF(), OFF()), false, false, false);
        _wrap(w, alice, 10);
        vm.warp(T0 + (uint256(1) << 21) * 60); // one whole circle idle: the stale window reads as active
        _wrapRev(w, alice, 1, _over(0, alice, 1, 0));
        vm.warp(T0 + (uint256(1) << 21) * 60 + DAY + 60);
        _wrap(w, alice, 10);
    }

    // ------------------------------------------------------------------ rows 8, 9, 13: the net rule and the tracking

    function test_r8_plainNetRule() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 0, OFF(), OFF(), OFF(), OFF()), true, false, false);
        _wrap(w, alice, 100);
        vm.prank(alice);
        w.transfer(bob, 100);
        _unwrapRev(w, bob, 1, _aboveNet(bob, 1, 0)); // received by transfer
        _wrap(w, alice, 100);
        _unwrap(w, alice, 100); // own wraps pass
        // `wrapToUA` credits the receiver, never the payer
        _fundW(w, alice, 50);
        vm.prank(alice);
        w.wrapToUA(u, 50, uaP);
        assertEq(_q(w, alice).netWrapped, 100, "the payer's line unmoved (200 wrapped, 100 unwrapped)");
        assertEq(w.wrapQuotaOf(uaP, u).netWrapped, 50);
        _uaUnwrap(w, uaP, 50, "");
    }

    function test_r8_debitRoundsUp() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(1, 0, OFF(), OFF(), OFF(), OFF()), true, false, false);
        _wrap(w, alice, 15); // ⌊15/10⌋ = 1 quantum
        assertEq(_q(w, alice).netWrapped, 10);
        _unwrap(w, alice, 10); // ⌈10/10⌉ = 1
        _wrap(w, alice, 15);
        _unwrapRev(w, alice, 11, _aboveNet(alice, 11, 10)); // ⌈11/10⌉ = 2 > 1
    }

    function test_r9_trackedWhileOff() public {
        WrappedToken w = _hyb();
        _track(w);
        _wrap(w, alice, 100);
        vm.prank(alice);
        w.transfer(bob, 60);
        _unwrap(w, bob, 10); // the rule off: transferred units unwrap
        _set(w, _cfg1(0, 0, OFF(), OFF(), OFF(), OFF()), true, false, false);
        _unwrapRev(w, bob, 1, _aboveNet(bob, 1, 0));
        _unwrap(w, alice, 40); // b = 100 counted while the rule was off
    }

    function test_r9_decayCountsTheRealAge() public {
        WrappedToken w = _hyb();
        _track(w);
        _wrap(w, alice, 1000);
        vm.warp(T0 + 365 days);
        _set(w, _cfg1(0, 730, OFF(), OFF(), OFF(), OFF()), false, false, false); // the clock was kept while off
        assertEq(_q(w, alice).entitlement, 500);
        _unwrapRev(w, alice, 501, _aboveNet(alice, 501, 500));
        _unwrap(w, alice, 500);
        // two wraps while the decay is off: the start is their weighted average, not the last wrap
        w = _hyb();
        _track(w);
        _wrap(w, alice, 1000);
        vm.warp(block.timestamp + 200 days);
        _wrap(w, alice, 1000); // the start moves to 100 days after the first wrap
        vm.warp(block.timestamp + 165 days);
        _set(w, _cfg1(0, 730, OFF(), OFF(), OFF(), OFF()), false, false, false);
        assertEq(_q(w, alice).entitlement, uint256(2000 * 465) / 730, "the age is 265 days");
    }

    function test_r13_mintNotCounted() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 0, L(10, 0, DAY), OFF(), OFF(), OFF()), true, false, false);
        _wrap(w, bob, 10); // a reserve to unwrap from
        vm.prank(MINTER);
        w.mint(alice, 100);
        IWrappedToken.WrapQuota memory q = _q(w, alice);
        assertEq(q.netWrapped, 0);
        assertEq(q.wrapShort.left, 10);
        assertEq(_word(w, _pad(alice), 0), 0, "no slot written");
        _unwrapRev(w, alice, 1, _aboveNet(alice, 1, 0));
    }

    // ------------------------------------------------------------------ rows 10, 11, 38: subjects

    function _wrapDigest(WrappedToken w, MetaTxLib.Envelope memory e, uint256 amount) internal view returns (bytes32) {
        return MtxDigest.typed(address(w), keccak256(abi.encode(keccak256("Wrap(address from,uint256 amount,uint256 batch,"
            "uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), e.from, amount,
            e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
    }

    function test_r10_namedWrapCountsTheSigner() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 0, L(10, 0, DAY), OFF(), OFF(), OFF()), false, false, false);
        _fundW(w, alice, 20);
        MetaTxLib.Envelope memory e =
            MetaTxLib.Envelope(alice, 1, w.mtxNonce(_pad(alice), 1), block.timestamp + 300, 0, address(0), 0, address(0));
        bytes memory sig = _ecdsa(ALICE_PK, _wrapDigest(w, e, 10));
        vm.prank(RELAYER);
        w.mtxWrap(e, 10, sig);
        assertEq(_q(w, alice).wrapShort.left, 0);
        assertEq(_q(w, RELAYER).wrapShort.left, 10, "never the submitter");
        _wrapRev(w, alice, 1, _over(0, alice, 1, 0));
    }

    function test_r10_batchItemCounted() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 0, L(10, 0, DAY), OFF(), OFF(), OFF()), false, false, false);
        _fundW(w, alice, 20);
        bytes memory d = abi.encodeWithSignature("wrap(address,uint256)", u, 6);
        MetaTxLib.UAMetaTransaction[] memory ms = new MetaTxLib.UAMetaTransaction[](2);
        IUARegistry.UASig[] memory as_ = new IUARegistry.UASig[](2);
        ms[0] = _m(address(w), _pad(alice), d);
        ms[1] = _m(address(w), _pad(alice), d);
        ms[1].nonce = ms[0].nonce + 1;
        for (uint256 i; i < 2; ++i) as_[i] = UACall.auth(ms[i].from, _authM(address(w), ms[i]));
        vm.expectRevert(_over(0, alice, 6, 4)); // the second item: 6 + 6 > 10
        vm.prank(RELAYER);
        w.mtxBatch(ms, as_);
        ms = new MetaTxLib.UAMetaTransaction[](1);
        ms[0] = _m(address(w), _pad(alice), d);
        IUARegistry.UASig[] memory one = new IUARegistry.UASig[](1);
        one[0] = UACall.auth(ms[0].from, _authM(address(w), ms[0]));
        vm.prank(RELAYER);
        w.mtxBatch(ms, one); // positive control: one item
        assertEq(_q(w, alice).wrapShort.left, 4);
    }

    function test_r10_derivedUnwrapCountsTheUA() public {
        WrappedToken w = _hyb();
        _wrap(w, alice, 100);
        _set(w, _cfg1(0, 0, OFF(), OFF(), L(10, 0, DAY), OFF()), false, false, false);
        vm.startPrank(alice);
        w.transferToUA(uaP, 50);
        w.transferToUA(uaB, 50);
        vm.stopPrank();
        _uaUnwrap(w, uaP, 10, "");
        _uaUnwrap(w, uaP, 1, _overId(2, uaP, 1, 0));
        _uaUnwrap(w, uaB, 10, ""); // another UA, its own window (never one `UA_POOL` quota)
        assertEq(w.wrapQuotaOf(MetaTxLib.pad(MetaTxLib.UA_POOL), u).unwrapShort.left, 10);
    }

    function _order(WrappedToken w, uint256 amount, uint256 nonce, bytes32 dest) internal view returns (ITradeToken.UAWrapOrder memory o) {
        (o.from, o.wrappedToken, o.amount, o.minMinted, o.minFill) = (_pad(alice), address(w), amount, amount, amount);
        (o.relayer, o.batch, o.nonce, o.validUntil, o.destination) = (RELAYER, 1, nonce, block.timestamp + 300, dest);
    }

    function _fill(WrappedToken w, ITradeToken.UAWrapOrder memory o, bytes memory err) internal {
        bytes memory sig = _ecdsa(ALICE_PK, tok.tradeOrderDigest(DexLegs.asTrade(o)));
        if (err.length != 0) vm.expectRevert(err);
        vm.prank(RELAYER);
        w.mtxWrapOrder(address(tok), o, UACall.auth(o.from, sig));
    }

    function test_r11_wrapOrderCountsTheSigner() public {
        WrappedToken w = _hybWith(1 | (uint256(1) << GovernanceBits.MINTABLE) | CONTROLS, address(tok), 1);
        _set(w, _legs1(_leg(address(tok), 0, 0, L(10, 0, DAY), OFF(), OFF(), OFF())), false, false, false);
        _fill(w, _order(w, 10, 1, 0), "");
        assertEq(w.wrapQuotaOf(_pad(alice), address(tok)).wrapShort.left, 0);
        assertEq(w.wrapQuotaOf(_pad(RELAYER), address(tok)).wrapShort.left, 10, "never the submitter");
        _fill(w, _order(w, 1, 2, 0), abi.encodeWithSelector(IWrappedToken.WrapLimitExceeded.selector, address(tok), uint8(0),
            _pad(alice), 1, 0));
    }

    /// Rows 11, 38: the credit goes to the destination; with `destination == from` the windows and the credit share one word.
    function test_r11_r38_orderCreditsTheDestination() public {
        WrappedToken w = _hybWith(1 | (uint256(1) << GovernanceBits.MINTABLE) | CONTROLS, address(tok), 1);
        _set(w, _legs1(_leg(address(tok), 0, 0, L(100, 0, DAY), OFF(), OFF(), OFF())), false, false, false);
        _fill(w, _order(w, 30, 1, uaP), "");
        assertEq(w.wrapQuotaOf(uaP, address(tok)).netWrapped, 30);
        assertEq(w.wrapQuotaOf(_pad(alice), address(tok)).netWrapped, 0);
        _fill(w, _order(w, 60, 2, _pad(alice)), "");
        IWrappedToken.WrapQuota memory q = w.wrapQuotaOf(_pad(alice), address(tok));
        assertEq(q.wrapShort.left, 10, "both windows uses");
        assertEq(q.netWrapped, 60, "and the credit, in one word");
    }

    // ------------------------------------------------------------------ rows 14-16: tighter and looser (R6, R13)

    function _pending(WrappedToken w) internal view returns (uint64 eta, bool live) {
        (,,,,, eta, live,) = w.wrapLimits();
    }

    function _perUser(WrappedToken w, uint256 limit) internal view returns (uint24) {
        (IWrappedToken.WrapLegLimits[] memory legs,,,,,,,) = w.wrapLimits();
        if (limit == 0) return legs[0].wrapShort.perUser;
        return legs[0].unwrapShort.perUser;
    }

    function _ws(WrappedToken w, IWrappedToken.WrapLimit memory x) internal {
        _set(w, _cfg1(0, 0, x, OFF(), OFF(), OFF()), false, false, false);
    }

    function test_r14_wrapSideTighterAtOnce() public {
        notice = 7 days;
        WrappedToken w = _hyb();
        _ws(w, L(100, 0, DAY)); // off -> on
        assertEq(_perUser(w, 0), 100);
        _ws(w, L(50, 0, DAY));
        _ws(w, L(50, 0, 2 * DAY)); // a longer period
        _ws(w, L(50, 500, 2 * DAY)); // a token-wide part on
        _set(w, _cfg1(0, 0, L(50, 500, 2 * DAY), OFF(), OFF(), OFF()), false, true, false); // the wrapper list on
        assertEq(_perUser(w, 0), 50);
        (uint64 eta,) = _pending(w);
        assertEq(eta, 0, "nothing waited");
        _ws(w, L(0, 500, 2 * DAY)); // positive control: 50 -> 0 (off) is looser and waits (the list off too)
        assertEq(_perUser(w, 0), 50);
        (eta,) = _pending(w);
        assertEq(eta, block.timestamp + 7 days);
    }

    function test_r15_wrapSideLooserWaits() public {
        notice = 7 days;
        WrappedToken w = _hyb();
        _ws(w, L(50, 0, 2 * DAY));
        _ws(w, L(100, 0, 2 * DAY)); // proposed
        assertEq(_perUser(w, 0), 50);
        (uint64 eta, bool live) = _pending(w);
        assertTrue(live);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotReady.selector, WL, bytes32(0), eta));
        vm.prank(OWNER);
        w.setWrapLimits(_cfg1(0, 0, L(100, 0, 2 * DAY), OFF(), OFF(), OFF()), false, false, false);
        vm.warp(eta);
        _ws(w, L(100, 0, 2 * DAY)); // confirmed
        assertEq(_perUser(w, 0), 100);
        (eta,) = _pending(w);
        assertEq(eta, 0);
        // dead after its window: the same call proposes again
        _ws(w, L(200, 0, 2 * DAY));
        (eta,) = _pending(w);
        vm.warp(uint256(eta) + 7 days + 1);
        (, live) = _pending(w);
        assertFalse(live);
        _ws(w, L(200, 0, 2 * DAY));
        assertEq(_perUser(w, 0), 100);
        // a shorter period is looser
        _ws(w, L(100, 0, DAY));
        (eta,) = _pending(w);
        assertEq(eta, block.timestamp + 7 days);
        // a new proposal replaces the old: the old one does not apply at its eta
        _ws(w, L(300, 0, 2 * DAY));
        vm.warp(eta);
        _ws(w, L(100, 0, DAY));
        assertEq(_perUser(w, 0), 100);
    }

    function test_r15_ownerChangeKillsThePending() public {
        notice = 7 days;
        WrappedToken w = _hyb();
        _ws(w, L(50, 0, DAY));
        _ws(w, L(100, 0, DAY));
        (uint64 eta,) = _pending(w);
        address next = address(0x0B);
        vm.prank(OWNER);
        w.transferAdmin(_pad(next), EnvKit.codeUidOf(address(w)));
        vm.prank(next);
        w.acceptAdmin();
        vm.warp(eta);
        vm.prank(next);
        w.setWrapLimits(_cfg1(0, 0, L(100, 0, DAY), OFF(), OFF(), OFF()), false, false, false);
        assertEq(_perUser(w, 0), 50, "proposed again under the new generation, not applied");
    }

    function test_r15_mixedCallWaits() public {
        notice = 7 days;
        WrappedToken w = _hyb();
        _ws(w, L(50, 500, DAY));
        _ws(w, L(100, 400, DAY)); // the cap tighter, the per-user part looser
        assertEq(_perUser(w, 0), 50);
    }

    function _us(WrappedToken w, IWrappedToken.WrapLimit memory x, uint16 decay, bool net, bool ul) internal {
        _set(w, _cfg1(0, decay, OFF(), OFF(), x, OFF()), net, false, ul);
    }

    function _waits(WrappedToken w) internal view returns (bool) {
        (uint64 eta,) = _pending(w);
        return eta != 0;
    }

    function _confirm(WrappedToken w, IWrappedToken.WrapLimit memory x, uint16 decay, bool net, bool ul) internal {
        (uint64 eta,) = _pending(w);
        vm.warp(eta);
        _us(w, x, decay, net, ul);
        assertFalse(_waits(w));
    }

    function test_r16_unwrapSideTighterWaitsLooserAtOnce() public {
        notice = 7 days;
        WrappedToken w = _hyb();
        _track(w);
        _us(w, L(100, 0, DAY), 0, false, false); // a part on: waits
        assertTrue(_waits(w));
        assertEq(_perUser(w, 2), 0);
        _confirm(w, L(100, 0, DAY), 0, false, false);
        _us(w, L(200, 0, DAY), 0, false, false); // looser: at once
        assertFalse(_waits(w));
        assertEq(_perUser(w, 2), 200);
        _us(w, L(200, 0, DAY), 0, false, true); // the list on: waits
        assertTrue(_waits(w));
        _confirm(w, L(200, 0, DAY), 0, false, true);
        _us(w, L(200, 0, DAY), 0, true, true); // the net rule on: waits
        assertTrue(_waits(w));
        _confirm(w, L(200, 0, DAY), 0, true, true);
        _us(w, L(200, 0, DAY), 730, true, true); // the decay on: waits
        assertTrue(_waits(w));
        _confirm(w, L(200, 0, DAY), 730, true, true);
        _us(w, L(200, 0, DAY), 365, true, true); // a shorter horizon: waits
        assertTrue(_waits(w));
        _confirm(w, L(200, 0, DAY), 365, true, true);
        _us(w, L(200, 0, DAY), 730, true, true); // a longer one: at once
        assertFalse(_waits(w));
        _us(w, L(200, 0, DAY), 0, false, false); // everything off: at once
        assertFalse(_waits(w));
        (, bool net, , bool ul,,,,) = w.wrapLimits();
        assertFalse(net || ul);
    }

    function test_r16_unwrapTighterAndWrapLooserWaitOnce() public {
        notice = 7 days;
        WrappedToken w = _hyb();
        _ws(w, L(50, 0, DAY));
        IWrappedToken.WrapLegLimits[] memory a = _cfg1(0, 0, L(100, 0, DAY), OFF(), L(10, 0, DAY), OFF());
        _set(w, a, false, false, false);
        (uint64 eta,) = _pending(w);
        assertEq(eta, block.timestamp + 7 days);
        vm.warp(eta);
        _set(w, a, false, false, false);
        assertEq(_perUser(w, 0), 100);
        assertEq(_perUser(w, 2), 10);
    }

    // ------------------------------------------------------------------ rows 17-21: the setter's other rules

    function test_r17_unitWriteOnce() public {
        WrappedToken w = _hyb();
        IWrappedToken.WrapLegLimits[] memory a = _cfg1(37, 0, OFF(), OFF(), OFF(), OFF());
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapUnitInvalid.selector, u, uint8(37)));
        vm.prank(OWNER);
        w.setWrapLimits(a, false, false, false);
        _set(w, _cfg1(2, 0, OFF(), OFF(), OFF(), OFF()), false, false, false);
        a = _cfg1(3, 0, OFF(), OFF(), OFF(), OFF());
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapUnitInvalid.selector, u, uint8(3)));
        vm.prank(OWNER);
        w.setWrapLimits(a, false, false, false);
        _set(w, _cfg1(2, 0, L(1, 0, DAY), OFF(), OFF(), OFF()), false, false, false); // the same unit passes
    }

    function _disable(WrappedToken w, uint8 bit, bytes memory err) internal {
        if (err.length != 0) vm.expectRevert(err);
        vm.prank(OWNER);
        w.disableFeature(bit);
    }

    function _active(uint8 bit) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IWrappedToken.WrapControlActive.selector, bit);
    }

    function _ctl(WrappedToken w, uint256 i) internal view returns (uint8) {
        return uint8(uint256(vm.load(address(w), keccak256(abi.encode(i, UNS)))) >> 192);
    }

    function test_r18_disableRefusedWhileOn() public {
        WrappedToken w = _hyb();
        _ws(w, L(10, 0, DAY));
        _disable(w, WL, _active(WL));
        _set(w, _cfg1(0, 0, OFF(), OFF(), OFF(), OFF()), true, false, false);
        _disable(w, WL, _active(WL)); // the net rule
        _set(w, _cfg1(0, 9, OFF(), OFF(), OFF(), OFF()), false, false, false);
        _disable(w, WL, _active(WL)); // the decay
        _set(w, _cfg1(0, 0, OFF(), OFF(), OFF(), OFF()), false, true, false);
        _disable(w, WLIST, _active(WLIST));
        _set(w, _cfg1(0, 0, OFF(), OFF(), OFF(), OFF()), false, false, false);
        assertEq(_ctl(w, 0), WrappedLib.CTL_TRACK);
        _disable(w, WL, "");
        assertEq(_ctl(w, 0), 0, "the tracking stops");
        _disable(w, WLIST, "");
        _grant(w, RED, MERCHANT);
        _disable(w, RED, _active(RED));
        vm.prank(OWNER);
        w.revokeRole(RED, _pad(MERCHANT));
        _disable(w, RED, "");
    }

    function test_r19_setterNeedsTheBits() public {
        WrappedToken w = _hybWith(1 | (uint256(1) << GovernanceBits.MINTABLE) | (uint256(1) << WLIST), u, 1);
        IWrappedToken.WrapLegLimits[] memory a = _cfg1(0, 0, L(1, 0, DAY), OFF(), OFF(), OFF());
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, WL));
        vm.prank(OWNER);
        w.setWrapLimits(a, false, false, false);
        a = _cfg1(0, 0, OFF(), OFF(), OFF(), OFF());
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, WL));
        vm.prank(OWNER);
        w.setWrapLimits(a, true, false, false);
        _set(w, a, false, true, false); // positive control: the list alone
        assertEq(_ctl(w, 0), WrappedLib.CTL_WLIST, "no tracking without bit 25");
        w = _hybWith(1 | (uint256(1) << GovernanceBits.MINTABLE) | (uint256(1) << WL), u, 1);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, WLIST));
        vm.prank(OWNER);
        w.setWrapLimits(a, false, false, true);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, WLIST, _pad(OWNER)));
        vm.prank(OWNER);
        w.setWrapMember(_pad(bob), true, true); // no holder of bit 26 can exist without it
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, _pad(bob)));
        vm.prank(bob);
        w.setWrapLimits(a, false, false, false);
    }

    /// Row 19: the normal kind refuses the three bits (kind 0 here; the confidential and regulated kinds in WrapLimitsKinds).
    function test_r19_normalKindRefusesTheBits() public {
        address n = address(new NormalToken(address(this), kindArgs(0, address(this), "")));
        for (uint8 bit = WL; bit <= RED; ++bit) {
            NormalToken t = NormalToken(EnvKit.clone(n, EnvKit.env(chainUidA, REG_L, address(0), false)));
            IFactoryToken.TokenConfig memory c = normalInit("N", "N", 6, 0, address(0), address(0));
            c.features |= uint256(1) << bit;
            vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, bit));
            t.initialize(nid(address(this)), 1, abi.encode(c));
        }
    }

    function _twoLegs(MockERC20 b) internal returns (WrappedToken) {
        address[] memory l = new address[](2);
        uint256[] memory n = new uint256[](2);
        (l[0], l[1], n[0], n[1]) = (u, address(b), 1, 1);
        return _make(_cfg(l, n, 1 | (uint256(1) << GovernanceBits.MINTABLE) | CONTROLS));
    }

    function test_r20_perLeg() public {
        MockERC20 und2 = new MockERC20("U2", "U2", 6);
        WrappedToken w = _twoLegs(und2);
        IWrappedToken.WrapLegLimits[] memory a = new IWrappedToken.WrapLegLimits[](2);
        a[0] = _leg(u, 0, 0, L(10, 0, DAY), OFF(), OFF(), OFF());
        a[1] = _leg(address(und2), 0, 0, OFF(), OFF(), OFF(), OFF());
        _set(w, a, true, false, false);
        _wrap(w, alice, 10);
        _wrapRev(w, alice, 1, _over(0, alice, 1, 0));
        und2.mint(alice, 100);
        vm.startPrank(alice);
        und2.approve(address(w), 100);
        w.wrap(address(und2), 100); // leg B: no limit
        vm.stopPrank();
        _wrap(w, bob, 10); // reserve on leg A beyond alice's own
        _unwrapRev(w, alice, 11, _aboveNet(alice, 11, 10)); // b per leg: 10 on A
        vm.prank(alice);
        w.unwrap(address(und2), 11, alice, 0); // 100 on B
        // the leg order and its underlying are checked
        a[0].underlying = address(und2);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapLegMismatch.selector, 0, address(und2)));
        vm.prank(OWNER);
        w.setWrapLimits(a, true, false, false);
    }

    function test_r21_copiesOnEveryLeg() public {
        MockERC20 und2 = new MockERC20("U2", "U2", 6);
        WrappedToken w = _twoLegs(und2);
        IWrappedToken.WrapLegLimits[] memory a = new IWrappedToken.WrapLegLimits[](2);
        a[0] = _leg(u, 3, 100, OFF(), OFF(), OFF(), OFF());
        a[1] = _leg(address(und2), 4, 200, OFF(), OFF(), OFF(), OFF());
        _set(w, a, true, true, false);
        for (uint256 i; i < 2; ++i) {
            bytes32 c = keccak256(abi.encode(i, WLNS));
            uint256 w0 = uint256(vm.load(address(w), c));
            uint256 w1 = uint256(vm.load(address(w), bytes32(uint256(c) + 1)));
            assertEq(uint8(w0 >> 224), 3 + i, "unitExp");
            assertEq(uint8(w1 >> 224), 3 + i, "unitExpCopy");
            assertEq(uint16(w0 >> 232), 100 * (i + 1), "decayDays");
            assertEq(uint16(w1 >> 232), 100 * (i + 1), "decayDaysCopy");
            assertEq(_ctl(w, i), WrappedLib.CTL_TRACK | WrappedLib.CTL_NET | WrappedLib.CTL_WLIST, "ctl");
        }
    }

    /// Spec §5, R26: the quota word's bit offsets, written by a wrap through the library and read with `vm.load`: by limit id
    /// `l` the start (21 bits) at 21·l and its used count (19 bits) at 84 + 19·l, `base` at 160, `startMin` at 192.
    function test_quotaWordOffsetsArePinned() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 0, OFF(), L(500, 0, DAY), OFF(), OFF()), false, false, false); // limit 1, wrapLong
        _wrap(w, alice, 100);
        uint256 m = T0 / 60;
        uint256 want = ((m % (1 << 21)) << 21) | (uint256(100) << (84 + 19)) | (uint256(100) << 160) | (m << 192);
        assertEq(_word(w, _pad(alice), 0), want);
    }

    // ------------------------------------------------------------------ row 22: +0 off (spec §5 `ctl`)

    function _reads(WrappedToken w) internal returns (uint256 nw, uint256 nu, bool touched) {
        _fundW(w, alice, 100);
        vm.record();
        vm.prank(alice);
        w.wrap(u, 100);
        (bytes32[] memory r,) = vm.accesses(address(w));
        nw = r.length;
        touched = _wl(r);
        vm.record();
        _unwrap(w, alice, 50);
        (r,) = vm.accesses(address(w));
        nu = r.length;
        touched = touched || _wl(r);
    }

    /// Any slot of the namespace a tracked use would touch: leg 0's config words, alice's quota word, her member byte.
    function _wl(bytes32[] memory r) internal view returns (bool) {
        bytes32 c = keccak256(abi.encode(uint256(0), WLNS));
        bytes32 q = keccak256(abi.encode(uint256(0), keccak256(abi.encode(_pad(alice), uint256(WLNS) + 2))));
        bytes32 m = keccak256(abi.encode(_pad(alice), uint256(WLNS) + 3));
        for (uint256 i; i < r.length; ++i) {
            if (r[i] == c || r[i] == bytes32(uint256(c) + 1) || r[i] == q || r[i] == m) return true;
        }
        return false;
    }

    function test_r22_plusZeroWhenOff() public {
        (uint256 nw0, uint256 nu0, bool t0) = _reads(_hybWith(1 | (uint256(1) << GovernanceBits.MINTABLE), u, 1));
        (uint256 nw1, uint256 nu1, bool t1) = _reads(_hyb()); // the bits, never configured
        assertFalse(t0 || t1, "a wrap-limit slot read");
        assertEq(nw1, nw0, "wrap");
        assertEq(nu1, nu0, "unwrap");
        WrappedToken w = _hyb();
        _track(w);
        (,, bool t2) = _reads(w);
        assertTrue(t2, "positive control: tracked, the slots are read");
    }

    // ------------------------------------------------------------------ row 23: the views

    function test_r23_viewsMatchWhatPasses() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 0, L(100, 300, DAY), OFF(), L(50, 0, DAY), OFF()), true, false, false);
        _wrap(w, alice, 60);
        IWrappedToken.WrapQuota memory q = _q(w, alice);
        assertEq(q.wrapShort.left, 40);
        assertEq(q.wrapShort.resetAt, T0 + 1441 * 60);
        assertEq(q.wrapLong.left, type(uint256).max, "a part off");
        assertEq(q.unwrapShort.left, 50);
        assertEq(q.unwrapShort.resetAt, 0, "no window yet");
        assertEq(q.netWrapped, 60);
        assertEq(q.entitlement, 60);
        assertTrue(q.canWrap && q.canUnwrap && !q.redeemer);
        IWrappedToken.WrapQuotaTotal memory t = w.wrapQuotaTotal(u);
        assertEq(t.wrapShort.left, 240);
        assertEq(t.wrapShort.resetAt, T0 + 1441 * 60);
        assertEq(t.unwrapShort.left, type(uint256).max);
        _wrap(w, alice, 40); // exactly `left`
        _wrapRev(w, alice, 1, _over(0, alice, 1, 0));
        vm.warp(q.wrapShort.resetAt - 1);
        _wrapRev(w, alice, 1, _over(0, alice, 1, 0));
        vm.warp(q.wrapShort.resetAt);
        _wrap(w, alice, 1); // `resetAt` is the refusal's lift
        _unwrap(w, alice, 50);
        assertEq(_q(w, alice).unwrapShort.left, 0);
        assertEq(_q(w, alice).entitlement, 51);
    }

    // ------------------------------------------------------------------ rows 26-33: the decay (§2.1, R26)

    function _decayed(bool net) internal returns (WrappedToken w) {
        w = _hyb();
        _set(w, _cfg1(0, 730, OFF(), OFF(), OFF(), OFF()), net, false, false);
        _wrap(w, alice, 1000);
    }

    function test_r26_decayAtZeroHalfAndFull() public {
        WrappedToken w = _decayed(true);
        assertEq(_q(w, alice).entitlement, 1000);
        assertEq(_q(w, alice).entitlementZeroAt, T0 + 730 days);
        vm.warp(T0 + 365 days);
        assertEq(_q(w, alice).entitlement, 500);
        _unwrapRev(w, alice, 501, _aboveNet(alice, 501, 500));
        _unwrap(w, alice, 500);
        w = _decayed(true);
        vm.warp(block.timestamp + 730 days);
        assertEq(_q(w, alice).entitlement, 0);
        _unwrapRev(w, alice, 1, _aboveNet(alice, 1, 0));
        vm.warp(block.timestamp + 1000 days);
        _unwrapRev(w, alice, 1, _aboveNet(alice, 1, 0));
    }

    /// Row 26b (Fable P2-6): the decay applies with the net rule off.
    function test_r26b_decayWithoutTheNetRule() public {
        WrappedToken w = _decayed(false);
        vm.warp(T0 + 365 days);
        _unwrapRev(w, alice, 501, _aboveNet(alice, 501, 500));
        _unwrap(w, alice, 500);
    }

    function _age(WrappedToken w, address who) internal view returns (uint256) {
        return block.timestamp / 60 - (_word(w, _pad(who), 0) >> 192);
    }

    function _base(WrappedToken w, address who) internal view returns (uint256) {
        return uint32(_word(w, _pad(who), 0) >> 160);
    }

    function test_r27_r28_weightedStart() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(2, 730, OFF(), OFF(), OFF(), OFF()), true, false, false);
        _wrap(w, alice, 100_000); // 1000 quanta of 100
        vm.warp(T0 + 100 days);
        uint256 before = _word(w, _pad(alice), 0);
        _wrap(w, alice, 50); // below one unit: nothing moves
        assertEq(_word(w, _pad(alice), 0), before, "dust");
        uint256 e = _q(w, alice).entitlement / 100;
        assertEq(e, 863);
        _wrap(w, alice, 100); // one quantum: the age moves by its weight, rounded older
        assertEq(_age(w, alice), 143_834, "g' = ceil(863 * 144000 / 864)");
        uint256 e2 = _q(w, alice).entitlement / 100;
        uint256 h = 730 * 1440;
        assertLe(e2, e + 1, "row 28: never above E + a");
        assertGe(e2 + (1001 + h - 1) / h + 1, e + 1, "row 28: at most one minute's decay below");
        assertLe(_base(w, alice), 1001, "b' <= b + a");
        assertGe(e2, e, "a wrap never lowers E");
        // a wrap as large as the entitlement halves the age
        w = _hyb();
        _set(w, _cfg1(2, 730, OFF(), OFF(), OFF(), OFF()), true, false, false);
        _wrap(w, alice, 100_000);
        vm.warp(block.timestamp + 100 days);
        _wrap(w, alice, 86_300);
        assertEq(_age(w, alice), 72_000);
        assertLe(_q(w, alice).entitlement / 100, 863 + 863, "rescaled: never above E + a");
    }

    /// Row 28: the `b + a` clamp binds when a large top-up meets a young line (the age's round-up by one minute would put the
    /// rescaled base 133 quanta above `b + a`); found by T99's mutant `base-clamp-missing`, which survived the rows above.
    function test_r28_clampBindsOnALargeTopUp() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 730, OFF(), OFF(), OFF(), OFF()), true, false, false);
        _wrap(w, alice, 7_260_627);
        vm.warp(T0 + 4416 * 60);
        _wrap(w, alice, 818_492_002);
        assertEq(_base(w, alice), 7_260_627 + 818_492_002, "b' = b + a, not the rescaled 825,752,762");
        assertEq(_age(w, alice), 39, "g' = ceil(7230125 * 4416 / 825722127)");
    }

    function test_r29_unwrapUnderTheDecay() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(2, 730, OFF(), OFF(), OFF(), OFF()), true, false, false);
        _wrap(w, alice, 100_000);
        vm.warp(T0 + 100 days);
        uint256 e = _q(w, alice).entitlement / 100; // 863
        _unwrap(w, alice, 10_000); // 100 quanta
        uint256 e2 = _q(w, alice).entitlement / 100;
        assertTrue(e2 == e - 100 || e2 == e - 101, "E drops by q or q + 1");
        uint256 sum = 100;
        while (true) {
            uint256 left = _q(w, alice).entitlement;
            if (left < 10_000) break;
            _unwrap(w, alice, 10_000);
            sum += 100;
        }
        assertLe(sum, e, "repeated unwraps never sum past E");
    }

    function test_r31_decayOnOffOn() public {
        WrappedToken w = _decayed(true);
        vm.warp(T0 + 365 days);
        assertEq(_q(w, alice).entitlement, 500);
        _set(w, _cfg1(0, 0, OFF(), OFF(), OFF(), OFF()), true, false, false); // off: at once
        assertEq(_q(w, alice).entitlement, 1000, "back to b, never above the plain net");
        _set(w, _cfg1(0, 730, OFF(), OFF(), OFF(), OFF()), true, false, false); // on again (notice 0)
        assertEq(_q(w, alice).entitlement, 500, "the kept clock");
    }

    function test_r32_baseSaturates() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 65_535, OFF(), OFF(), OFF(), OFF()), true, false, false);
        _wrap(w, alice, (uint256(1) << 32) + 7);
        assertEq(_base(w, alice), type(uint32).max);
        _wrap(w, alice, 5);
        assertEq(_base(w, alice), type(uint32).max, "saturated: only refuses more");
        vm.warp(T0 + 65_000 days); // the largest products
        assertLt(_q(w, alice).entitlement, type(uint32).max);
    }

    /// Row 33 (R25, accepted and disclosed): a wrap of `a` then an unwrap of `a` leaves `E` and makes the start younger by
    /// `g·a/(E + a)`, pinned so a change is seen.
    function test_r33_roundTripRejuvenates() public {
        WrappedToken w = _decayed(true);
        vm.warp(T0 + 365 days);
        _wrap(w, alice, 500);
        assertEq(_q(w, alice).entitlement, 999, "E + a, one quantum to the rounding");
        _unwrap(w, alice, 500);
        assertEq(_q(w, alice).entitlement, 498, "E back where it was, less q + 1's rounding (wraplimits.json)");
        assertEq(_age(w, alice), 262_800, "365 days halved: ceil(500 * 525600 / 1000)");
    }

    // ------------------------------------------------------------------ row 30: the redeemer (R9, R27)

    function _toMerchant(WrappedToken w, uint256 amount) internal {
        _wrap(w, alice, amount);
        vm.prank(alice);
        w.transfer(MERCHANT, amount);
    }

    function _terms(uint128 total, uint64 validUntil, bool delegable) internal pure returns (IGovernance.GrantTerms memory t) {
        (t.max, t.total, t.validUntil, t.delegable) = (type(uint128).max, total, validUntil, delegable);
    }

    function test_r30_redeemerPastTheEntitlement() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 0, OFF(), OFF(), L(50, 0, DAY), OFF()), true, false, false);
        _toMerchant(w, 100);
        _unwrapRev(w, MERCHANT, 40, _aboveNet(MERCHANT, 40, 0));
        _grant(w, RED, MERCHANT);
        assertTrue(_q(w, MERCHANT).redeemer);
        assertEq(_q(w, MERCHANT).entitlement, type(uint256).max);
        _unwrap(w, MERCHANT, 40); // b = 0, E = 0: no division (P1-3)
        _unwrapRev(w, MERCHANT, 11, _over(2, MERCHANT, 11, 10)); // still bound by the windows
        vm.prank(OWNER);
        w.revokeRole(RED, _pad(MERCHANT));
        vm.warp(T0 + DAY + 60);
        _unwrapRev(w, MERCHANT, 1, _aboveNet(MERCHANT, 1, 0)); // revoked: at once
    }

    function test_r30_redeemerBudgetIsTheExcess() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 0, OFF(), OFF(), OFF(), OFF()), true, false, false);
        _toMerchant(w, 100);
        _wrap(w, MERCHANT, 10); // its own E = 10
        vm.prank(OWNER);
        w.setGrant(RED, _pad(MERCHANT), _terms(20, 0, false));
        _unwrap(w, MERCHANT, 30); // 0 < E < q: the excess 20 spends the budget
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExhausted.selector, uint8(2)));
        vm.prank(MERCHANT);
        w.unwrap(u, 1, MERCHANT, 0);
    }

    function test_r30_expiredGrantRefused() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 0, OFF(), OFF(), OFF(), OFF()), true, false, false);
        _toMerchant(w, 100);
        vm.prank(OWNER);
        w.setGrant(RED, _pad(MERCHANT), _terms(0, uint64(T0 + DAY), false));
        _unwrap(w, MERCHANT, 10); // positive control: in time
        vm.warp(T0 + 2 * DAY);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExpired.selector, RED, _pad(MERCHANT)));
        vm.prank(MERCHANT);
        w.unwrap(u, 10, MERCHANT, 0);
    }

    function test_r30_leafOfARevokedGrantorRefused() public {
        WrappedToken w = _hyb();
        _set(w, _cfg1(0, 0, OFF(), OFF(), OFF(), OFF()), true, false, false);
        address leaf = address(0x1EAF);
        _wrap(w, alice, 100);
        vm.prank(alice);
        w.transfer(leaf, 100);
        vm.prank(OWNER);
        w.setGrant(RED, _pad(MERCHANT), _terms(1000, 0, true));
        vm.prank(MERCHANT);
        w.setGrant(RED, _pad(leaf), _terms(500, 0, false));
        _unwrap(w, leaf, 10); // positive control
        vm.prank(OWNER);
        w.revokeRole(RED, _pad(MERCHANT));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExhausted.selector, uint8(7)));
        vm.prank(leaf);
        w.unwrap(u, 10, leaf, 0);
    }

    /// R27: bit 27 binds a scalar, bit 26 does not.
    function test_r30_bit27IsScalar() public {
        WrappedToken w = _hyb();
        vm.prank(OWNER);
        w.setGrant(RED, _pad(MERCHANT), _terms(20, 0, false));
        vm.expectRevert();
        vm.prank(OWNER);
        w.setGrant(WLIST, _pad(LISTER), _terms(20, 0, false));
    }

    // ------------------------------------------------------------------ row 34: hybrid only (R12), kind 1

    function test_r34_pureWrapRefusesTheBits() public {
        for (uint8 bit = WL; bit <= RED; ++bit) {
            (address[] memory l, uint256[] memory n) = _one(u);
            IFactoryToken.TokenConfig memory c = _cfg(l, n, 1 | (uint256(1) << bit));
            WrappedToken w = _clone();
            vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapControlNeedsHybrid.selector, bit));
            w.initialize(nid(address(this)), 1, abi.encode(c));
            _hybWith(1 | (uint256(1) << GovernanceBits.MINTABLE) | (uint256(1) << bit), u, 1); // the same hybrid passes
        }
    }

    // ------------------------------------------------------------------ row 37: subject 0 (P2-8)

    function test_r37_subjectZeroRefused() public {
        SubjectZeroHarness hz = new SubjectZeroHarness();
        vm.expectRevert(IWrappedToken.WrapSubjectZero.selector);
        hz.quote(bytes32(0));
        hz.quote(_pad(alice)); // positive control
    }

    // ------------------------------------------------------------------ row 32: the fuzz invariants

    /// `E ≤ b ≤ plain net` after every step, and a wrap never lowers `E`, over random wraps, unwraps and times.
    function testFuzz_r32_invariants(uint256 seed) public {
        WrappedToken w = _hyb();
        uint16 d = uint16(bound(seed, 1, 900));
        _set(w, _cfg1(1, d, OFF(), OFF(), OFF(), OFF()), true, false, false);
        uint256 plain; // quanta
        for (uint256 k; k < 12; ++k) {
            seed = uint256(keccak256(abi.encode(seed, k)));
            uint256 e = _q(w, alice).entitlement;
            uint256 op = seed % 3;
            if (op == 0) {
                uint256 x = bound(seed >> 8, 1, 1e9);
                _wrap(w, alice, x);
                plain += x / 10;
                assertGe(_q(w, alice).entitlement, e, "a wrap never lowers E");
            } else if (op == 1 && e >= 10) {
                uint256 x = bound(seed >> 8, 1, e);
                _unwrap(w, alice, x);
                uint256 q = (x + 9) / 10;
                plain = plain > q ? plain - q : 0;
            } else {
                vm.warp(block.timestamp + bound(seed >> 8, 1, 400 days));
            }
            IWrappedToken.WrapQuota memory r = _q(w, alice);
            assertLe(r.entitlement, r.netWrapped, "E <= b");
            assertLe(r.netWrapped, plain * 10, "b <= plain net");
        }
    }
}

/// A token-free caller of `WrappedLib`'s unwrap quote, for row 37: a leg with the unwrapper list on.
contract SubjectZeroHarness {
    constructor() {
        WrappedLib.WrappedStorage storage s = WrappedLib.$();
        (s.legs[0].token, s.legs[0].num, s.legs[0].den, s.legs[0].reserve, s.legs[0].ctl) =
            (address(0xD), 1, 1, 100, WrappedLib.CTL_ULIST);
        WrappedLib.wl().member[bytes32(uint256(uint160(0xA11CE)))] = 2;
        s.legCount = 1;
    }

    function quote(bytes32 holder) external view {
        if (holder != 0) holder = bytes32(uint256(uint160(0xA11CE)));
        WrappedLib.quoteUnwrap(0, 10, address(0xBEEF), 0, holder);
    }
}
