// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {V2Fixture, Rate} from "./helpers/V2Fixture.sol";
import {RateAdminForwarder} from "./helpers/V2Mocks.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {IUnderlyingToken} from "../../src/metatx/IUnderlyingToken.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {MockERC20} from "../helpers/Mocks.sol";

/// Signature wrap of a SCaaS underlying (CTR-TOK-20): the holder signs a `TradeOrder` in the underlying's domain with
/// `dex` = `receiveToken` = the wrapper; no allowance anywhere.
contract MtxWrapTest is V2Fixture {
    uint256 constant ALICE_PK = 0xA11CE;
    address alice = vm.addr(ALICE_PK);
    address bob = address(0xB0B);
    NoUnderlyingToken u;
    UnderlyingToken w;

    function setUp() public {
        u = _none(alice, 1_000_000, address(0)); // decimals 0
        w = _single(address(u), 0, 3, 1, _fixedRate()); // 1 u -> 3 w
    }

    function _order(uint256 amount, uint256 minOut, uint256 fee) internal view returns (ITradeToken.TradeOrder memory o) {
        o.from = alice;
        o.receiveToken = address(w);
        o.amount = amount;
        o.receiveAmount = minOut;
        o.minFill = amount;
        o.fee = fee;
        o.dex = address(w);
        o.batch = 7;
        o.nonce = 1;
        o.validUntil = block.timestamp + 300;
    }

    function _sig(ITradeToken.TradeOrder memory o) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, u.tradeOrderDigest(o));
        return abi.encodePacked(r, s, v);
    }

    function test_mtxWrap_mintsAtTheRate_feeToTheSubmitter() public {
        ITradeToken.TradeOrder memory o = _order(1000, 3000, 1_000); // 0.1 % of 3000 = 3
        bytes memory sig = _sig(o); // before the prank: an external call would consume it
        vm.expectEmit(address(w));
        emit IUnderlyingToken.Wrapped(alice, address(u), 1000, 3000);
        vm.prank(relayer);
        assertEq(w.mtxWrap(address(u), o, sig), 3000);
        assertEq(w.balanceOf(alice), 2997);
        assertEq(w.balanceOf(relayer), 3);
        assertEq(u.balanceOf(address(w)), 1000);
        (,, uint256 reserve,,) = w.legOf(address(u));
        assertEq(reserve, 1000);
        assertEq(u.allowance(alice, address(w)), 0);
        assertEq(u.pulled(u.tradeOrderDigest(o)), 1000);
    }

    function test_mtxWrap_toDestination() public {
        ITradeToken.TradeOrder memory o = _order(1000, 3000, 0);
        o.destination = bob;
        bytes memory sig = _sig(o);
        vm.prank(relayer);
        w.mtxWrap(address(u), o, sig);
        assertEq(w.balanceOf(bob), 3000);
        assertEq(w.balanceOf(alice), 0);
    }

    function test_mtxWrap_signedMinimumIsThePrice() public {
        ITradeToken.TradeOrder memory o = _order(1000, 3001, 0);
        bytes memory sig = _sig(o);
        bytes32 h = u.tradeOrderDigest(o);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.PriceLimit.selector, h));
        w.mtxWrap(address(u), o, sig);
    }

    function test_mtxWrap_relayerBinding() public {
        ITradeToken.TradeOrder memory o = _order(1000, 3000, 0);
        o.relayer = bob;
        bytes memory sig = _sig(o);
        bytes32 h = u.tradeOrderDigest(o);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.WrongRelayer.selector, h, relayer));
        w.mtxWrap(address(u), o, sig);
        vm.prank(bob);
        w.mtxWrap(address(u), o, sig);
    }

    function test_mtxWrap_refusals() public {
        ITradeToken.TradeOrder memory o = _order(1000, 3000, 0);
        bytes memory sig = _sig(o);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.UnknownUnderlying.selector, address(0xDEAD)));
        w.mtxWrap(address(0xDEAD), o, sig);
        o.receiveToken = address(u);
        sig = _sig(o);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.WrapOrderInvalid.selector, address(u)));
        w.mtxWrap(address(u), o, sig);
        // the order names another dex: the underlying refuses the wrapper as caller
        o = _order(1000, 3000, 0);
        o.dex = address(this);
        sig = _sig(o);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.NotDex.selector, address(w)));
        w.mtxWrap(address(u), o, sig);
    }

    function test_mtxWrap_nativeLegIsNotGasless() public {
        UnderlyingToken n = _single(address(0), 18, 1, 1, _fixedRate());
        ITradeToken.TradeOrder memory o = _order(1000, 1000, 0);
        o.receiveToken = address(n);
        o.dex = address(n);
        vm.expectRevert(IUnderlyingToken.NativeNotGasless.selector);
        n.mtxWrap(address(0), o, "");
    }

    function test_mtxWrap_pausedDuringARateChange() public {
        RateAdminForwarder adm = new RateAdminForwarder();
        UnderlyingToken a = _single(address(u), 0, 3, 1, _adjustable(address(adm)));
        adm.exec(address(a), abi.encodeCall(a.proposeRate, (address(u), 301, 100)));
        ITradeToken.TradeOrder memory o = _order(1000, 3000, 0);
        o.receiveToken = address(a);
        o.dex = address(a);
        bytes memory sig = _sig(o);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.WrapPausedForRateChange.selector, address(u)));
        a.mtxWrap(address(u), o, sig);
    }

    function test_mtxWrap_anOutsideLegHasNoMtxTrade() public {
        MockERC20 usdc = new MockERC20("USD Coin", "USDC", 6);
        UnderlyingToken x = _single(address(usdc), 6, 1, 1, _fixedRate());
        ITradeToken.TradeOrder memory o = _order(1000, 1000, 0);
        o.receiveToken = address(x);
        o.dex = address(x);
        vm.expectRevert();
        x.mtxWrap(address(usdc), o, "");
    }

    function test_mtxWrap_isNotAllowlisted() public view {
        (bytes4[] memory s,,) = w.mtxSelectors();
        for (uint256 i; i < s.length; ++i) assertTrue(s[i] != w.mtxWrap.selector);
    }
}
