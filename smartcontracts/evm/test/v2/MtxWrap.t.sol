// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {V2Fixture, Rate} from "./helpers/V2Fixture.sol";
import {RateAdminForwarder} from "./helpers/V2Mocks.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {IUnderlyingToken} from "../../src/metatx/IUnderlyingToken.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";

/// A leg whose `mtxTrade` delivers `amount + skew` to `o.dex` (no signature, no checks): a lying underlying.
contract SkewLeg {
    mapping(address => uint256) public balanceOf;
    int256 public skew;

    function decimals() external pure returns (uint8) { return 0; }

    function setSkew(int256 s) external { skew = s; }

    function setBalance(address a, uint256 v) external { balanceOf[a] = v; }

    function mtxTrade(ITradeToken.TradeOrder calldata o, bytes calldata, ITradeToken.TradeFill calldata) external {
        balanceOf[o.dex] = uint256(int256(balanceOf[o.dex] + o.amount) + skew);
    }
}

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
        emit IUnderlyingToken.Wrapped(alice, address(u), 1000, 2997); // net of the fee (W-Q)
        vm.prank(relayer);
        assertEq(w.mtxWrap(address(u), o, sig), 3000);
        assertEq(w.balanceOf(alice), 2997);
        assertEq(w.balanceOf(relayer), 3);
        assertEq(u.balanceOf(address(w)), 1000);
        (,, uint256 reserve,,) = w.legOf(address(u));
        assertEq(reserve, 1000);
        assertEq(u.allowance(alice, address(w)), 0);
        assertEq(u.pulled(u.tradeOrderDigest(o)), 1000);
        assertGe(w.collateralValue(), w.totalSupply());
    }

    function test_mtxWrap_toDestination() public {
        ITradeToken.TradeOrder memory o = _order(1000, 3000, 0);
        o.destination = bob;
        bytes memory sig = _sig(o);
        vm.expectEmit(address(w));
        emit IUnderlyingToken.Wrapped(bob, address(u), 1000, 3000); // the credited party (W-Q)
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

    // ------------------------------------------------------------------ more refusals

    function test_mtxWrap_feeIsRoundedUp() public {
        UnderlyingToken x = _single(address(u), 0, 2999, 1000, _fixedRate()); // 1000 u -> 2999 x
        ITradeToken.TradeOrder memory o = _order(1000, 2999, 1_000); // 0.1 % of 2999 = 2.999 -> 3 (floor: 2)
        o.receiveToken = address(x);
        o.dex = address(x);
        bytes memory sig = _sig(o);
        vm.prank(relayer);
        assertEq(x.mtxWrap(address(u), o, sig), 2999);
        assertEq(x.balanceOf(relayer), 3);
        assertEq(x.balanceOf(alice), 2996);
    }

    function test_mtxWrap_disabledLegIsRefused() public {
        address guardian = address(0x6A2D);
        UnderlyingToken g = _multi(_one(address(u)), _oneU(3), _oneU(1), _fixedRate(), guardian);
        vm.prank(guardian);
        g.disableWrap(address(u), "depeg");
        ITradeToken.TradeOrder memory o = _order(1000, 3000, 0);
        o.receiveToken = address(g);
        o.dex = address(g);
        bytes memory sig = _sig(o);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.WrapDisabledFor.selector, address(u)));
        g.mtxWrap(address(u), o, sig);
    }

    function test_mtxWrap_tooSmallToMint() public {
        UnderlyingToken x = _single(address(u), 0, 1, 1000, _fixedRate()); // 999 u -> 0 x
        ITradeToken.TradeOrder memory o = _order(999, 1, 0);
        o.receiveToken = address(x);
        o.dex = address(x);
        bytes memory sig = _sig(o);
        vm.expectRevert(IUnderlyingToken.WrapTooSmall.selector);
        x.mtxWrap(address(u), o, sig);
    }

    function test_mtxWrap_escrowFlagIsRefusedByTheUnderlying() public {
        ITradeToken.TradeOrder memory o = _order(1000, 3000, 0);
        o.flags = 3; // IOC | ESCROW: Path B wants a (amount, 0, 0) fill, the wrapper passes the price
        bytes memory sig = _sig(o);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.EscrowFillShape.selector, u.tradeOrderDigest(o)));
        w.mtxWrap(address(u), o, sig);
    }

    function _skewWrapper() internal returns (SkewLeg leg, UnderlyingToken x, ITradeToken.TradeOrder memory o) {
        leg = new SkewLeg();
        x = _single(address(leg), 0, 1, 1, _fixedRate());
        o = _order(1000, 1000, 0);
        o.receiveToken = address(x);
        o.dex = address(x);
    }

    function test_mtxWrap_deliveredLessOrMoreThanSignedIsRefused() public {
        (SkewLeg leg, UnderlyingToken x, ITradeToken.TradeOrder memory o) = _skewWrapper();
        for (uint256 k; k < 2; ++k) {
            leg.setSkew(k == 0 ? -1 : int256(1));
            vm.expectRevert(abi.encodeWithSelector(
                IUnderlyingToken.WrapReceivedMismatch.selector, 1000, k == 0 ? 999 : 1001));
            x.mtxWrap(address(leg), o, "");
            assertEq(x.totalSupply(), 0);
            (,, uint256 reserve,,) = x.legOf(address(leg));
            assertEq(reserve, 0);
        }
    }

    function test_mtxWrap_reserveShortfallIsRefused() public {
        (SkewLeg leg, UnderlyingToken x, ITradeToken.TradeOrder memory o) = _skewWrapper();
        x.mtxWrap(address(leg), o, "");
        assertGe(x.collateralValue(), x.totalSupply());
        leg.setBalance(address(x), 999); // below the reserve of 1000
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.ReserveShortfall.selector, address(leg), 999, 1000));
        x.mtxWrap(address(leg), o, "");
    }

    function test_mtxWrap_throughMtxExecuteIsNotAllowlisted() public {
        ITradeToken.TradeOrder memory o = _order(1000, 3000, 0);
        bytes memory data = abi.encodeCall(w.mtxWrap, (address(u), o, _sig(o)));
        MetaTxLib.MetaTransaction memory m = _call(alice, data, 1, RR);
        bytes memory sig = _signCall(ALICE_PK, address(w), m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, w.mtxWrap.selector));
        MetaTokenBase(address(w)).mtxExecute(m, sig);
    }
}
