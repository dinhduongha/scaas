// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {DexLegs} from "../helpers/DexLegs.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {UACall} from "../ua/UACall.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {WrapLimitsBase} from "./WrapLimitsBase.sol";

/// A leg whose `mtxTrade` delivers `amount` to `o.dex` and records what the wrapper's views read from inside the leg's call
/// (spec §3.4, S-5: `totalWrapped()` must never run ahead of `totalSupply()` there).
contract ReaderLeg {
    mapping(address => uint256) public balanceOf;
    uint256 public seenWrapped;
    uint256 public seenSupply;

    function decimals() external pure returns (uint8) { return 0; }

    function mtxTrade(ITradeToken.UATradeOrder calldata o, IUARegistry.UASig calldata, ITradeToken.TradeFill calldata)
        external
    {
        seenWrapped = IWrappedToken(msg.sender).totalWrapped();
        seenSupply = WrappedToken(payable(msg.sender)).totalSupply();
        balanceOf[o.dex] += o.amount;
    }

    function transfer(address to, uint256 v) external returns (bool) {
        balanceOf[msg.sender] -= v;
        balanceOf[to] += v;
        return true;
    }
}

/// A leg whose `mtxTrade` re-enters the wrapper (Fable F-4): a second wrap, an unwrap and the cap setter from inside a
/// signature wrap, each recorded by its revert selector; then it delivers `amount`.
contract ReenterLeg {
    mapping(address => uint256) public balanceOf;
    bytes4[] public errs;
    address public u;

    function decimals() external pure returns (uint8) { return 0; }

    function setU(address u_) external { u = u_; }

    function n() external view returns (uint256) { return errs.length; }

    function mtxTrade(ITradeToken.UATradeOrder calldata o, IUARegistry.UASig calldata, ITradeToken.TradeFill calldata)
        external
    {
        WrappedToken w = WrappedToken(payable(msg.sender));
        try w.wrap(u, 1) { errs.push(0); } catch (bytes memory r) { errs.push(bytes4(r)); }
        try w.unwrap(u, 1, address(this), 0) { errs.push(0); } catch (bytes memory r) { errs.push(bytes4(r)); }
        try w.setMaxWrapSupply(0, bytes32(0)) { errs.push(0); } catch (bytes memory r) { errs.push(bytes4(r)); }
        balanceOf[o.dex] += o.amount;
    }
}

/// Round 3zc (spec 2026-11-13-burner-wrap-caps.md §3, §6; CTR-GOV-30), kind `WRAPPED` (the library every wrapped kind
/// shares): the counter `totalWrapped` on every wrap and unwrap path of this kind (exact deltas on a 3:1 leg, where the
/// units an unwrap burns differ from those it names), the wrap cap `maxWrapSupply`, the two delayed setters under bit 31
/// with their floors at the apply, and the views. The confidential and regulated kinds: `SupplyCapsKinds.t.sol`. UNAUDITED.
contract SupplyCapsTest is WrapLimitsBase {
    uint8 internal constant SCA = GovernanceBits.SUPPLY_CAP_ADJUSTABLE;
    uint256 internal constant HYB = 1 | (uint256(1) << GovernanceBits.MINTABLE);
    bytes32 internal constant SIB = bytes32(uint256(0x5B));

    // ------------------------------------------------------------------ fixtures

    /// A token over `leg` at `num`:1, `features`, `maxSupply` (hybrid: `CAP`), `maxWrapSupply`, `grantDelay`.
    function _tok(uint256 features, address leg, uint256 num, uint256 maxWrap, uint64 delay) internal returns (WrappedToken) {
        (address[] memory l, uint256[] memory n) = _one(leg);
        n[0] = num;
        IFactoryToken.TokenConfig memory c = _cfg(l, n, features);
        (c.maxWrapSupply, c.grantDelay) = (maxWrap, delay);
        return _make(c);
    }

    function _uid(WrappedToken w) internal view returns (bytes32) {
        return EnvKit.codeUidOf(address(w));
    }

    function _setMS(WrappedToken w, uint256 v) internal {
        vm.prank(OWNER);
        w.setMaxSupply(v, _uid(w));
    }

    function _setMW(WrappedToken w, uint256 v) internal {
        vm.prank(OWNER);
        w.setMaxWrapSupply(v, _uid(w));
    }

    function _mintBy(WrappedToken w, address to, uint256 v) internal {
        vm.prank(MINTER);
        w.mint(to, v, _uid(w));
    }

    function _overCap(uint256 next, uint256 cap) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IWrappedToken.MaxWrapSupplyExceeded.selector, next, cap);
    }

    function _wrapDigest(WrappedToken w, MetaTxLib.Envelope memory e, uint256 amount) internal view returns (bytes32) {
        return MtxDigest.typed(address(w), keccak256(abi.encode(keccak256("Wrap(address from,uint256 amount,uint256 batch,"
            "uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"), e.from, amount,
            e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
    }

    /// `mtxWrap(amount)` signed by alice, relayed.
    function _mtxWrap(WrappedToken w, uint256 amount, bytes memory err) internal {
        _fundW(w, alice, amount);
        MetaTxLib.Envelope memory e =
            MetaTxLib.Envelope(alice, 1, w.mtxNonce(_pad(alice), 1), block.timestamp + 300, 0, address(0), 0, address(0));
        bytes memory sig = _ecdsa(ALICE_PK, _wrapDigest(w, e, amount));
        if (err.length != 0) vm.expectRevert(err);
        vm.prank(RELAYER);
        w.mtxWrap(e, amount, sig);
    }

    function _wrapToUA(WrappedToken w, bytes32 to, uint256 amount, bytes memory err) internal {
        _fundW(w, alice, amount);
        if (err.length != 0) vm.expectRevert(err);
        vm.prank(alice);
        w.wrapToUA(u, amount, to);
    }

    /// A derived UA's generic `mtxExecute` of `unwrap(u, wrapped, bob, 0)`.
    function _uaUnwrap(WrappedToken w, bytes32 ua, uint256 wrapped) internal {
        MetaTxLib.UAMetaTransaction memory m =
            _m(address(w), ua, abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", u, wrapped, bob, 0));
        bytes memory a = _authM(address(w), m);
        vm.prank(RELAYER);
        w.mtxExecute(m, UACall.auth(m.from, a));
    }

    /// A signature wrap of `tok` (a SCaaS ledger leg) by alice, nonce `nonce`.
    function _order(WrappedToken w, uint256 amount, uint256 nonce) internal view returns (ITradeToken.UAWrapOrder memory o) {
        (o.from, o.wrappedToken, o.amount, o.minMinted, o.minFill) = (_pad(alice), address(w), amount, 1, amount);
        (o.relayer, o.batch, o.nonce, o.validUntil) = (RELAYER, 1, nonce, block.timestamp + 300);
    }

    function _fill(WrappedToken w, ITradeToken.UAWrapOrder memory o, bytes memory err) internal {
        bytes memory sig = _ecdsa(ALICE_PK, tok.tradeOrderDigest(DexLegs.asTrade(o)));
        if (err.length != 0) vm.expectRevert(err);
        vm.prank(RELAYER);
        w.mtxWrapOrder(address(tok), o, UACall.auth(o.from, sig));
    }

    // ------------------------------------------------------------------ the counter, each path (spec §3.3), a 3:1 leg

    function test_counter_wrapDirect() public {
        WrappedToken w = _tok(HYB, u, 3, 0, 0);
        _wrap(w, bob, 7); // wrap(u, amount)
        assertEq(w.totalWrapped(), 21);
        _fundW(w, bob, 5);
        vm.prank(bob);
        w.wrap(5); // wrap(amount)
        assertEq(w.totalWrapped(), 36);
        assertEq(w.totalWrapped(), w.totalSupply());
    }

    function test_counter_wrapToUA() public {
        WrappedToken w = _tok(HYB, u, 3, 0, 0);
        _wrapToUA(w, uaP, 4, "");
        assertEq(w.totalWrapped(), 12);
    }

    function test_counter_mtxWrap() public {
        WrappedToken w = _tok(HYB, u, 3, 0, 0);
        _mtxWrap(w, 6, "");
        assertEq(w.totalWrapped(), 18);
    }

    /// The submitter's fee part is minted by the wrap too and counted.
    function test_counter_wrapOrder() public {
        WrappedToken w = _tok(HYB, address(tok), 3, 0, 0);
        ITradeToken.UAWrapOrder memory o = _order(w, 10, 1);
        o.fee = 10_000; // 1 %
        _fill(w, o, "");
        assertEq(w.totalWrapped(), 30);
        assertEq(w.totalSupply(), 30);
    }

    /// `unwrap(u, wrapped, to, minOut)`: 10 named, out 3, burned 9 (`⌈out·q⌉`): the counter falls by the units burnt.
    function test_counter_unwrapLeg() public {
        WrappedToken w = _tok(HYB, u, 3, 0, 0);
        _wrap(w, bob, 10); // 30
        (uint256 out, uint256 burned) = w.previewUnwrap(u, 10);
        assertEq(out, 3);
        assertEq(burned, 9, "burned != named: the 'pass out' / 'pass wrapped' mutants are visible");
        _unwrap(w, bob, 10);
        assertEq(w.totalWrapped(), 21);
        assertEq(w.totalWrapped(), w.totalSupply());
    }

    function test_counter_unwrapSole() public {
        WrappedToken w = _tok(HYB, u, 3, 0, 0);
        _wrap(w, bob, 10);
        vm.prank(bob);
        w.unwrap(10, bob); // unwrap(uint256, address)
        assertEq(w.totalWrapped(), 21);
        vm.prank(bob);
        w.unwrap(10, bob, 0); // unwrap(uint256, address, uint256)
        assertEq(w.totalWrapped(), 12);
    }

    function test_counter_genericUnwrapByDerivedUA() public {
        WrappedToken w = _tok(HYB, u, 3, 0, 0);
        _wrap(w, alice, 10);
        vm.prank(alice);
        w.transferToUA(uaP, 30);
        _uaUnwrap(w, uaP, 10);
        assertEq(w.totalWrapped(), 21);
    }

    /// `unwrapToUA` pays in the leg's UA ledger (a SCaaS ledger leg `tok`).
    function test_counter_unwrapToUA() public {
        WrappedToken w = _tok(HYB, address(tok), 3, 0, 0);
        _fill(w, _order(w, 10, 1), ""); // 30 to alice
        vm.prank(alice);
        w.unwrapToUA(address(tok), 10, uaP, 0);
        assertEq(w.totalWrapped(), 21);
        assertEq(w.totalWrapped(), w.totalSupply());
    }

    /// No move: the minter's mint, `addReserve`, transfers.
    function test_counter_notMovedByMintReserveTransfer() public {
        WrappedToken w = _tok(HYB, u, 3, 0, 0);
        _wrap(w, bob, 10);
        _mintBy(w, alice, 500);
        _fundW(w, alice, 50);
        vm.prank(alice);
        w.addReserve(u, 50);
        vm.prank(alice);
        w.transfer(bob, 100);
        assertEq(w.totalWrapped(), 30);
    }

    /// Saturation: a hybrid's unwrap of minter-minted units below the counter leaves it at 0, never a revert.
    function test_counter_saturatesAtZero() public {
        WrappedToken w = _tok(HYB, u, 3, 0, 0);
        _wrap(w, alice, 10); // 30 counted
        _fundW(w, alice, 100);
        vm.prank(alice);
        w.addReserve(u, 100);
        _mintBy(w, bob, 150);
        _unwrap(w, bob, 150); // out 50, burned 150 > 30
        assertEq(w.totalWrapped(), 0);
        assertEq(w.totalSupply(), 30);
    }

    /// A pure wrap: every unit is born by a wrap and dies by an unwrap, so `totalWrapped == totalSupply` exactly.
    function testFuzz_pureWrapCounterIsSupply(uint96 a, uint96 b, uint96 c) public {
        WrappedToken w = _tok(1, u, 3, 0, 0);
        uint256 x = bound(a, 1, 1e24);
        _wrap(w, bob, x);
        _wrap(w, alice, bound(b, 1, 1e24));
        uint256 y = bound(c, 0, w.balanceOf(bob));
        if (y >= 3) _unwrap(w, bob, y);
        assertEq(w.totalWrapped(), w.totalSupply());
    }

    /// A hybrid: `totalWrapped <= totalSupply` whatever the mix.
    function testFuzz_hybridCounterBelowSupply(uint96 a, uint96 m, uint96 c) public {
        WrappedToken w = _tok(HYB, u, 3, 0, 0);
        _wrap(w, bob, bound(a, 1, 1e24));
        _mintBy(w, bob, bound(m, 0, 1e24));
        uint256 y = bound(c, 0, w.balanceOf(bob));
        (uint256 out,) = w.previewUnwrap(u, y);
        (,, uint256 reserve,,) = w.legOf(u);
        if (out != 0 && out <= reserve) _unwrap(w, bob, y);
        assertLe(w.totalWrapped(), w.totalSupply());
    }

    // ------------------------------------------------------------------ the cap (spec §3.4)

    function test_cap_atTheCapPassesOneOverRefused() public {
        WrappedToken w = _tok(1, u, 1, 100, 0);
        assertEq(w.maxWrapSupply(), 100);
        _wrap(w, bob, 100);
        _wrapRev(w, bob, 1, _overCap(101, 100));
        _unwrap(w, bob, 1);
        _wrap(w, bob, 1); // room again after an unwrap
    }

    function test_cap_everyWrapPath() public {
        WrappedToken w = _tok(1, u, 1, 10, 0);
        _wrapToUA(w, uaP, 11, _overCap(11, 10));
        _mtxWrap(w, 11, _overCap(11, 10));
        _fundW(w, bob, 11);
        vm.expectRevert(_overCap(11, 10));
        vm.prank(bob);
        w.wrap(11);
        WrappedToken o = _tok(1, address(tok), 1, 10, 0);
        _fill(o, _order(o, 11, 1), _overCap(11, 10));
        _fill(o, _order(o, 10, 1), ""); // the control
        assertEq(o.totalWrapped(), 10);
    }

    function test_cap_zeroIsNoCap() public {
        WrappedToken w = _tok(1, u, 1, 0, 0);
        _wrap(w, bob, 1e30);
        assertEq(w.totalWrapped(), 1e30);
    }

    /// The hybrid's `maxSupply` binds first (order of refusals), then the wrap cap.
    function test_cap_maxSupplyFirst() public {
        WrappedToken w = _tok(HYB, u, 1, 50, 0);
        _mintBy(w, alice, CAP - 10);
        _wrapRev(w, bob, 60, abi.encodeWithSelector(IWrappedToken.MaxSupplyExceeded.selector, CAP + 50, CAP));
    }

    /// The minter's mint ignores `maxWrapSupply`.
    function test_cap_mintIgnoresTheWrapCap() public {
        WrappedToken w = _tok(HYB, u, 1, 10, 0);
        _mintBy(w, alice, 1_000);
        assertEq(w.totalSupply(), 1_000);
        _wrap(w, bob, 10);
        _wrapRev(w, bob, 1, _overCap(11, 10));
    }

    /// Both the cap and the wrap-limit window bind, each alone refusing.
    function test_cap_andWrapLimitBothBind() public {
        WrappedToken w = _tok(HYB | CONTROLS, u, 1, 100, 0);
        _set(w, _cfg1(0, 0, L(30, 0, 1 days), OFF(), OFF(), OFF()), false, false, false);
        _wrap(w, bob, 30);
        _wrapRev(w, bob, 1, _over(0, bob, 1, 0)); // the window refuses, the cap would pass
        _wrap(w, alice, 30);
        _wrap(w, address(0xC4), 30);
        _wrapRev(w, address(0xC5), 11, _overCap(101, 100)); // the cap refuses, the window would pass
    }

    /// S-5: inside the leg's `mtxTrade` of a signature wrap, the counter has not run ahead of the supply.
    function test_cap_sigWrapCounterWrittenAfterTheLeg() public {
        ReaderLeg leg = new ReaderLeg();
        WrappedToken w = _tok(1, address(leg), 1, 100, 0);
        ITradeToken.UAWrapOrder memory o = _order(w, 40, 1);
        o.relayer = address(0); // any submitter: the leg checks nothing
        IUARegistry.UASig memory none;
        w.mtxWrapOrder(address(leg), o, none);
        assertEq(leg.seenWrapped(), 0, "not yet written inside the leg");
        assertLe(leg.seenWrapped(), leg.seenSupply());
        assertEq(w.totalWrapped(), 40);
        o = _order(w, 61, 2);
        o.relayer = address(0);
        vm.expectRevert(_overCap(101, 100));
        w.mtxWrapOrder(address(leg), o, none);
    }

    function test_cap_creationAboveMaxSupplyRefused() public {
        (address[] memory l, uint256[] memory n) = _one(u);
        IFactoryToken.TokenConfig memory c = _cfg(l, n, HYB);
        c.maxWrapSupply = CAP + 1;
        WrappedToken w = _clone();
        vm.expectRevert(IWrappedToken.MaxWrapSupplyInvalid.selector);
        w.initialize(nid(address(this)), 1, abi.encode(c));
        c.maxWrapSupply = CAP;
        _make(c); // the control: equal passes
    }

    // ------------------------------------------------------------------ the setters (spec §3.5)

    function test_set_adminThenWordBeforeAnyWrite() public {
        WrappedToken w = _tok(HYB | (uint256(1) << SCA), u, 1, 0, 1 hours);
        bytes memory na = abi.encodeWithSelector(IAdmin.NotAdmin.selector, _pad(bob));
        bytes memory mm = abi.encodeWithSelector(IAdmin.ChainUidMismatch.selector, _uid(w), SIB);
        vm.startPrank(bob);
        vm.expectRevert(na);
        w.setMaxSupply(CAP + 1, SIB);
        vm.expectRevert(na);
        w.setMaxWrapSupply(5, SIB);
        vm.stopPrank();
        vm.startPrank(OWNER);
        vm.expectRevert(mm);
        w.setMaxSupply(CAP + 1, SIB);
        vm.expectRevert(mm);
        w.setMaxWrapSupply(5, SIB);
        vm.stopPrank();
        (, uint64 e1, bool l1,, uint64 e2, bool l2) = w.pendingSupplyCaps();
        assertTrue(e1 == 0 && e2 == 0 && !l1 && !l2, "nothing proposed");
        assertEq(w.lastProposedAt(), 0);
        _setMS(w, CAP + 1); // the control: proposes
        (, e1, l1,,,) = w.pendingSupplyCaps();
        assertTrue(l1 && e1 == block.timestamp + 1 hours);
    }

    function test_set_featureNotSet() public {
        WrappedToken w = _tok(HYB, u, 1, 0, 0);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, SCA));
        _setMS(w, CAP + 1);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, SCA));
        _setMW(w, 5);
        WrappedToken d = _tok(HYB | (uint256(1) << SCA), u, 1, 0, 0);
        _setMW(d, 5); // the control
        assertEq(d.maxWrapSupply(), 5);
        vm.prank(OWNER);
        d.disableFeature(SCA, _uid(d));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, SCA));
        _setMW(d, 6);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, SCA));
        _setMS(d, CAP + 1);
    }

    function test_set_noDelayAppliesAtOnce() public {
        WrappedToken w = _tok(HYB | (uint256(1) << SCA), u, 1, 0, 0);
        vm.expectEmit(address(w));
        emit IWrappedToken.MaxSupplySet(_pad(OWNER), CAP, CAP / 2);
        _setMS(w, CAP / 2);
        assertEq(w.maxSupply(), CAP / 2);
        vm.expectEmit(address(w));
        emit IWrappedToken.MaxWrapSupplySet(_pad(OWNER), 0, 1000);
        _setMW(w, 1000);
        assertEq(w.maxWrapSupply(), 1000);
        _setMW(w, 0); // 0 removes the wrap cap
        assertEq(w.maxWrapSupply(), 0);
        assertEq(w.lastProposedAt(), 0, "no proposal without a delay");
    }

    function test_set_delayedProposeNotReadyApply() public {
        WrappedToken w = _tok(HYB | (uint256(1) << SCA), u, 1, 0, 1 hours);
        vm.warp(block.timestamp + 10);
        vm.expectEmit(address(w));
        emit IWrappedToken.MaxSupplyProposed(_pad(OWNER), CAP * 2, uint64(block.timestamp + 1 hours));
        _setMS(w, CAP * 2);
        assertEq(w.maxSupply(), CAP, "not yet");
        assertEq(w.lastProposedAt(), block.timestamp, "the pending signal");
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotReady.selector, SCA, bytes32(0),
            uint64(block.timestamp + 1 hours)));
        _setMS(w, CAP * 2);
        vm.warp(block.timestamp + 1 hours);
        _setMS(w, CAP * 2);
        assertEq(w.maxSupply(), CAP * 2, "applied in the window");
        (, uint64 eta, bool live,,,) = w.pendingSupplyCaps();
        assertTrue(eta == 0 && !live, "the pending is deleted");
        // the wrap cap the same, a decrease delayed too
        _setMW(w, 500);
        assertEq(w.maxWrapSupply(), 0);
        vm.warp(block.timestamp + 1 hours);
        _setMW(w, 500);
        assertEq(w.maxWrapSupply(), 500);
        _setMW(w, 100);
        vm.warp(block.timestamp + 1 hours);
        _setMW(w, 100);
        assertEq(w.maxWrapSupply(), 100, "a decrease is delayed alike");
    }

    function test_set_deadAfterTheWindowProposesAgain() public {
        WrappedToken w = _tok(HYB | (uint256(1) << SCA), u, 1, 0, 1 hours);
        _setMS(w, CAP * 2);
        vm.warp(block.timestamp + 2 hours + 1);
        (,, bool live,,,) = w.pendingSupplyCaps();
        assertFalse(live, "dead past eta + grantDelay");
        _setMS(w, CAP * 2); // proposes again, no revert
        assertEq(w.maxSupply(), CAP);
        (, uint64 eta, bool live2,,,) = w.pendingSupplyCaps();
        assertTrue(live2 && eta == block.timestamp + 1 hours);
    }

    function test_set_deadAfterAnAdminChange() public {
        WrappedToken w = _tok(HYB | (uint256(1) << SCA), u, 1, 0, 1 hours);
        _setMW(w, 500);
        vm.prank(OWNER);
        w.transferAdmin(_pad(bob), _uid(w));
        vm.prank(bob);
        w.acceptAdmin();
        (,,,,, bool live) = w.pendingSupplyCaps();
        assertFalse(live, "a new admin generation");
        vm.warp(block.timestamp + 1 hours);
        vm.prank(bob);
        w.setMaxWrapSupply(500, _uid(w)); // proposes again
        assertEq(w.maxWrapSupply(), 0);
    }

    function test_set_replacedByAnotherValue() public {
        WrappedToken w = _tok(HYB | (uint256(1) << SCA), u, 1, 0, 1 hours);
        _setMW(w, 500);
        vm.warp(block.timestamp + 30 minutes);
        _setMW(w, 600); // replaces, the clock restarts
        vm.warp(block.timestamp + 40 minutes);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotReady.selector, SCA, bytes32(0),
            uint64(block.timestamp + 20 minutes)));
        _setMW(w, 600);
        _setMW(w, 500); // 500 is no longer pending: proposes
        assertEq(w.maxWrapSupply(), 0);
    }

    /// The floors run at the apply against the state then: supply raised during the delay blocks a lower cap (S-1, O4).
    function test_set_floorsAtApply() public {
        WrappedToken w = _tok(HYB | (uint256(1) << SCA), u, 1, 0, 1 hours);
        _setMS(w, 1000); // propose a lower cap; supply is 0
        _wrap(w, bob, 1500); // binds nothing before the apply
        vm.warp(block.timestamp + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.MaxSupplyBelowSupply.selector, 1000, 1500));
        _setMS(w, 1000);
        // maxWrapSupply: below the counter, above maxSupply
        _setMW(w, 1000);
        vm.warp(block.timestamp + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.MaxWrapSupplyBelowWrapped.selector, 1000, 1500));
        _setMW(w, 1000);
        _setMW(w, CAP + 1);
        vm.warp(block.timestamp + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.MaxWrapSupplyAboveMaxSupply.selector, CAP + 1, CAP));
        _setMW(w, CAP + 1);
    }

    /// The floors are not read at the proposal (spec §3.5 item 4): a cap below today's supply may be proposed, and applies once
    /// supply has fallen under it by the apply.
    function test_set_proposeBelowSupplyThenApply() public {
        WrappedToken w = _tok(HYB | (uint256(1) << SCA), u, 1, 0, 1 hours);
        _wrap(w, bob, 1500);
        vm.expectEmit(address(w));
        emit IWrappedToken.MaxSupplyProposed(_pad(OWNER), 1000, uint64(block.timestamp + 1 hours));
        _setMS(w, 1000); // below today's supply: proposed, not refused
        _setMW(w, 900); // below today's counter: proposed, not refused
        _unwrap(w, bob, 700);
        vm.warp(block.timestamp + 1 hours);
        _setMW(w, 900);
        _setMS(w, 1000);
        assertEq(w.maxWrapSupply(), 900);
        assertEq(w.maxSupply(), 1000);
    }

    /// The floor against the wrap cap; lower the wrap cap first, both pending together.
    function test_set_maxSupplyBelowWrapCapThenInOrder() public {
        WrappedToken w = _tok(HYB | (uint256(1) << SCA), u, 1, 5000, 0);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.MaxSupplyBelowWrapCap.selector, 4000, 5000));
        _setMS(w, 4000);
        _setMW(w, 3000);
        _setMS(w, 4000); // in order
        assertEq(w.maxSupply(), 4000);
    }

    /// A joint raise proposed together and applied `maxSupply` first; the other order refuses the wrap cap's apply.
    function test_set_jointRaiseInOrder() public {
        (address[] memory l, uint256[] memory n) = _one(u);
        IFactoryToken.TokenConfig memory c = _cfg(l, n, HYB | (uint256(1) << SCA));
        (c.maxSupply, c.maxWrapSupply, c.grantDelay) = (1000, 1000, 1 hours);
        WrappedToken w = _make(c);
        _setMS(w, 2000);
        _setMW(w, 2000);
        vm.warp(block.timestamp + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.MaxWrapSupplyAboveMaxSupply.selector, 2000, 1000));
        _setMW(w, 2000);
        _setMS(w, 2000);
        _setMW(w, 2000);
        assertEq(w.maxSupply(), 2000);
        assertEq(w.maxWrapSupply(), 2000);
    }

    function test_set_maxSupplyShape() public {
        WrappedToken p = _tok(1 | (uint256(1) << SCA), u, 1, 0, 0); // a pure wrap
        vm.expectRevert(IWrappedToken.MaxSupplyInvalid.selector);
        _setMS(p, 100);
        _setMW(p, 100); // its wrap cap is adjustable
        assertEq(p.maxWrapSupply(), 100);
        WrappedToken h = _tok(HYB | (uint256(1) << SCA), u, 1, 0, 0);
        vm.expectRevert(IWrappedToken.MaxSupplyInvalid.selector);
        _setMS(h, 0); // a hybrid stays a hybrid
    }

    // ------------------------------------------------------------------ views

    function test_views() public {
        WrappedToken w = _tok(HYB | (uint256(1) << SCA), u, 3, 0, 1 hours);
        _wrap(w, bob, 10);
        _fundW(w, alice, 7);
        vm.prank(alice);
        w.addReserve(u, 7);
        assertEq(w.reserveValue(), w.collateralValue());
        assertEq(w.reserveValue(), 51);
        _setMS(w, CAP * 2);
        _setMW(w, 99);
        (uint256 a, uint64 ea, bool la, uint256 b, uint64 eb, bool lb) = w.pendingSupplyCaps();
        assertTrue(a == CAP * 2 && b == 99 && la && lb && ea == eb && ea != 0);
        vm.prank(OWNER);
        w.disableFeature(SCA, _uid(w));
        (,, la,,, lb) = w.pendingSupplyCaps();
        assertTrue(!la && !lb, "not live once bit 31 is off");
    }

    // ------------------------------------------------------------------ setWrapLimits carries the word (O5, spec §3.8)

    /// A stranger `NotAdmin` whatever the word (the admin check first); the admin with a sibling's word
    /// `ChainUidMismatch`, nothing written and no pending; the own word applies (no notice period here).
    function test_setWrapLimits_word() public {
        WrappedToken w = _hyb();
        IWrappedToken.WrapLegLimits[] memory a = _cfg1(0, 0, L(10, 0, 1 days), OFF(), OFF(), OFF());
        bytes memory na = abi.encodeWithSelector(IAdmin.NotAdmin.selector, _pad(bob));
        vm.startPrank(bob);
        vm.expectRevert(na);
        w.setWrapLimits(a, false, false, false, SIB);
        vm.expectRevert(na);
        w.setWrapLimits(a, false, false, false, _uid(w));
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSelector(IAdmin.ChainUidMismatch.selector, _uid(w), SIB));
        vm.prank(OWNER);
        w.setWrapLimits(a, false, false, false, SIB);
        (IWrappedToken.WrapLegLimits[] memory got,,,,, uint64 eta,,) = w.wrapLimits();
        assertTrue(got.length == 0 || got[0].wrapShort.perUser == 0, "nothing written");
        assertEq(eta, 0, "no pending");
        _set(w, a, false, false, false); // the control, the own word
        (got,,,,,,,) = w.wrapLimits();
        assertEq(got[0].wrapShort.perUser, 10);
    }

    // ------------------------------------------------------------------ Fable review fixes (F-4, F-11)

    /// F-4: the token's guard refuses a wrap, an unwrap and the cap setter from inside a signature wrap's leg call, so the
    /// counter written after the leg (spec §3.4) never misses an in-flight wrap; the counter stays within the cap.
    function test_sigWrapLegCannotReenter() public {
        ReenterLeg leg = new ReenterLeg();
        WrappedToken w = _tok(1, address(leg), 1, 100, 0);
        leg.setU(address(leg));
        ITradeToken.UAWrapOrder memory o = _order(w, 60, 1);
        o.relayer = address(0);
        IUARegistry.UASig memory none;
        w.mtxWrapOrder(address(leg), o, none);
        assertEq(leg.n(), 3);
        for (uint256 i; i < 3; ++i) assertEq(leg.errs(i), IMetaTx.Reentrancy.selector, "the guard, inside the leg");
        assertEq(w.totalWrapped(), 60);
        assertLe(w.totalWrapped(), w.maxWrapSupply());
    }

    /// F-11 (a): a pending applies at exactly `eta + grantDelay` and is dead one second later.
    function test_set_windowBoundary() public {
        WrappedToken w = _tok(HYB | (uint256(1) << SCA), u, 1, 0, 1 hours);
        _setMW(w, 500);
        uint256 t0 = block.timestamp;
        vm.warp(t0 + 2 hours); // eta + grantDelay exactly
        _setMW(w, 500);
        assertEq(w.maxWrapSupply(), 500, "applied at the last second of the window");
        _setMW(w, 400);
        vm.warp(block.timestamp + 2 hours + 1);
        _setMW(w, 400); // past the window: proposes again
        assertEq(w.maxWrapSupply(), 500);
    }

    /// F-11 (b): with both the wrap cap and a wrap-limit window refusing, the cap is named first (spec §3.4's order).
    function test_cap_beforeTheWindow() public {
        WrappedToken w = _tok(HYB | CONTROLS, u, 1, 10, 0);
        _set(w, _cfg1(0, 0, L(5, 0, 1 days), OFF(), OFF(), OFF()), false, false, false);
        _wrapRev(w, bob, 11, _overCap(11, 10)); // over the window (5) and over the cap (10)
    }
}

