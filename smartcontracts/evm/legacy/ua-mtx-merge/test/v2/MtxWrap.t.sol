// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {V2Fixture, Rate} from "./helpers/V2Fixture.sol";
import {RateAdminForwarder} from "./helpers/V2Mocks.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {DexLegs} from "../helpers/DexLegs.sol";
import {OrderJson} from "../helpers/OrderJson.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";
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

/// Signature wrap of a SCaaS underlying (CTR-TOK-20): the holder signs a `WrapOrder` in the underlying's domain, the wrapper
/// pulling for itself; no allowance anywhere.
contract MtxWrapTest is V2Fixture {
    uint256 constant ALICE_PK = 0xA11CE;
    address alice = vm.addr(ALICE_PK);
    address bob = address(0xB0B);
    NormalToken u;
    WrappedToken w;

    function setUp() public {
        u = _normal(alice, 1_000_000, address(0)); // decimals 0
        w = _single(address(u), 0, 3, 1, _fixedRate()); // 1 u -> 3 w
    }

    function _order(uint256 amount, uint256 minOut, uint256 fee) internal view returns (ITradeToken.WrapOrder memory o) {
        o.from = alice;
        o.wrappedToken = address(w);
        o.amount = amount;
        o.minMinted = minOut;
        o.minFill = amount;
        o.fee = fee;
        o.batch = 7;
        o.nonce = 1;
        o.validUntil = block.timestamp + 300;
    }

    function _sig(ITradeToken.WrapOrder memory o) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, u.tradeOrderDigest(DexLegs.asTrade(o)));
        return abi.encodePacked(r, s, v);
    }

    function test_mtxWrapOrder_mintsAtTheRate_feeToTheSubmitter() public {
        ITradeToken.WrapOrder memory o = _order(1000, 3000, 1_000); // 0.1 % of 3000 = 3
        bytes memory sig = _sig(o); // before the prank: an external call would consume it
        vm.expectEmit(address(w));
        emit IWrappedToken.Wrapped(alice, address(u), 1000, 2997); // net of the fee (W-Q)
        vm.prank(relayer);
        assertEq(w.mtxWrapOrder(address(u), o, sig), 3000);
        assertEq(w.balanceOf(alice), 2997);
        assertEq(w.balanceOf(relayer), 3);
        assertEq(u.balanceOf(address(w)), 1000);
        (,, uint256 reserve,,) = w.legOf(address(u));
        assertEq(reserve, 1000);
        assertEq(u.allowance(alice, address(w)), 0);
        assertEq(u.pulled(u.tradeOrderDigest(DexLegs.asTrade(o))), 1000);
        assertGe(w.collateralValue(), w.totalSupply());
    }

    /// TS-D16: the wrap-by-signature entry is `mtxWrapOrder`; `mtxWrap` is the named entry of `wrap(uint256)`. The old
    /// `mtxWrap(address, TradeOrder, bytes)`, the only change being the selector and the order's form, has no entry.
    function test_mtxWrapOrderRenamed() public {
        ITradeToken.WrapOrder memory o = _order(1000, 3000, 0);
        bytes memory sig = _sig(o);
        assertEq(IWrappedToken.mtxWrapOrder.selector, bytes4(0x423d548d), "the row's selector");
        bytes4 old = bytes4(keccak256("mtxWrap(address,(address,address,uint256,uint256,uint256,uint256,address,address,address,uint8,uint256,uint256,uint256),bytes)"));
        (bool ok, bytes memory ret) = address(w).call(abi.encodePacked(old, abi.encode(address(u), DexLegs.asTrade(o), sig)));
        assertFalse(ok);
        assertEq(ret.length, 0, "no such function");
        vm.prank(relayer);
        assertEq(w.mtxWrapOrder(address(u), o, sig), 3000);
    }

    /// The wallet's `WrapOrder` JSON, in the underlying's domain, wraps through the wrapper.
    function test_mtxWrapOrder_walletJson() public {
        ITradeToken.WrapOrder memory o = _order(1000, 3000, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, OrderJson.wrap(address(u), TradeLib.core(DexLegs.asTrade(o)), false));
        vm.prank(relayer);
        assertEq(w.mtxWrapOrder(address(u), o, abi.encodePacked(r, s, v)), 3000);
    }

    function test_mtxWrapOrder_toDestination() public {
        ITradeToken.WrapOrder memory o = _order(1000, 3000, 0);
        o.destination = bob;
        bytes memory sig = _sig(o);
        vm.expectEmit(address(w));
        emit IWrappedToken.Wrapped(bob, address(u), 1000, 3000); // the credited party (W-Q)
        vm.prank(relayer);
        w.mtxWrapOrder(address(u), o, sig);
        assertEq(w.balanceOf(bob), 3000);
        assertEq(w.balanceOf(alice), 0);
    }

    function test_mtxWrapOrder_signedMinimumIsThePrice() public {
        ITradeToken.WrapOrder memory o = _order(1000, 3001, 0);
        bytes memory sig = _sig(o);
        bytes32 h = u.tradeOrderDigest(DexLegs.asTrade(o));
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.PriceLimit.selector, h));
        w.mtxWrapOrder(address(u), o, sig);
    }

    function test_mtxWrapOrder_relayerBinding() public {
        ITradeToken.WrapOrder memory o = _order(1000, 3000, 0);
        o.relayer = bob;
        bytes memory sig = _sig(o);
        bytes32 h = u.tradeOrderDigest(DexLegs.asTrade(o));
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.WrongRelayer.selector, h, relayer));
        w.mtxWrapOrder(address(u), o, sig);
        vm.prank(bob);
        w.mtxWrapOrder(address(u), o, sig);
    }

    function test_mtxWrapOrder_refusals() public {
        ITradeToken.WrapOrder memory o = _order(1000, 3000, 0);
        bytes memory sig = _sig(o);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.UnknownUnderlying.selector, address(0xDEAD)));
        w.mtxWrapOrder(address(0xDEAD), o, sig);
        o.wrappedToken = address(u);
        sig = _sig(o);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapOrderInvalid.selector, address(u)));
        w.mtxWrapOrder(address(u), o, sig);
    }

    function test_mtxWrapOrder_nativeLegIsNotGasless() public {
        WrappedToken n = _single(address(0), 18, 1, 1, _fixedRate());
        ITradeToken.WrapOrder memory o = _order(1000, 1000, 0);
        o.wrappedToken = address(n);
        vm.expectRevert(IWrappedToken.NativeNotGasless.selector);
        n.mtxWrapOrder(address(0), o, "");
    }

    function test_mtxWrapOrder_pausedDuringARateChange() public {
        RateAdminForwarder adm = new RateAdminForwarder();
        WrappedToken a = _single(address(u), 0, 3, 1, _adjustable(address(adm)));
        adm.exec(address(a), abi.encodeCall(a.proposeRate, (address(u), 301, 100)));
        ITradeToken.WrapOrder memory o = _order(1000, 3000, 0);
        o.wrappedToken = address(a);
        bytes memory sig = _sig(o);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapPausedForRateChange.selector, address(u)));
        a.mtxWrapOrder(address(u), o, sig);
    }

    function test_mtxWrapOrder_anOutsideLegHasNoMtxTrade() public {
        MockERC20 usdc = new MockERC20("USD Coin", "USDC", 6);
        WrappedToken x = _single(address(usdc), 6, 1, 1, _fixedRate());
        ITradeToken.WrapOrder memory o = _order(1000, 1000, 0);
        o.wrappedToken = address(x);
        vm.expectRevert();
        x.mtxWrapOrder(address(usdc), o, "");
    }

    function test_mtxWrapOrder_isNotAllowlisted() public view {
        (bytes4[] memory s,,) = w.mtxSelectors();
        for (uint256 i; i < s.length; ++i) assertTrue(s[i] != IWrappedToken.mtxWrapOrder.selector);
    }

    // ------------------------------------------------------------------ more refusals

    function test_mtxWrapOrder_feeIsRoundedUp() public {
        WrappedToken x = _single(address(u), 0, 2999, 1000, _fixedRate()); // 1000 u -> 2999 x
        ITradeToken.WrapOrder memory o = _order(1000, 2999, 1_000); // 0.1 % of 2999 = 2.999 -> 3 (floor: 2)
        o.wrappedToken = address(x);
        bytes memory sig = _sig(o);
        vm.prank(relayer);
        assertEq(x.mtxWrapOrder(address(u), o, sig), 2999);
        assertEq(x.balanceOf(relayer), 3);
        assertEq(x.balanceOf(alice), 2996);
    }

    function test_mtxWrapOrder_disabledLegIsRefused() public {
        address guardian = address(0x6A2D);
        WrappedToken g = _multi(_one(address(u)), _oneU(3), _oneU(1), _fixedRate(), guardian);
        vm.prank(guardian);
        g.disableWrap(address(u), "depeg");
        ITradeToken.WrapOrder memory o = _order(1000, 3000, 0);
        o.wrappedToken = address(g);
        bytes memory sig = _sig(o);
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapDisabledFor.selector, address(u)));
        g.mtxWrapOrder(address(u), o, sig);
    }

    function test_mtxWrapOrder_tooSmallToMint() public {
        WrappedToken x = _single(address(u), 0, 1, 1000, _fixedRate()); // 999 u -> 0 x
        ITradeToken.WrapOrder memory o = _order(999, 1, 0);
        o.wrappedToken = address(x);
        bytes memory sig = _sig(o);
        vm.expectRevert(IWrappedToken.WrapTooSmall.selector);
        x.mtxWrapOrder(address(u), o, sig);
    }

    function test_mtxWrapOrder_escrowFlagIsRefusedByTheUnderlying() public {
        ITradeToken.WrapOrder memory o = _order(1000, 3000, 0);
        o.flags = 3; // IOC | ESCROW: Path B wants a (amount, 0, 0) fill, the wrapper passes the price
        bytes memory sig = _sig(o);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.EscrowFillShape.selector, u.tradeOrderDigest(DexLegs.asTrade(o))));
        w.mtxWrapOrder(address(u), o, sig);
    }

    function _skewWrapper() internal returns (SkewLeg leg, WrappedToken x, ITradeToken.WrapOrder memory o) {
        leg = new SkewLeg();
        x = _single(address(leg), 0, 1, 1, _fixedRate());
        o = _order(1000, 1000, 0);
        o.wrappedToken = address(x);
    }

    function test_mtxWrapOrder_deliveredLessOrMoreThanSignedIsRefused() public {
        (SkewLeg leg, WrappedToken x, ITradeToken.WrapOrder memory o) = _skewWrapper();
        for (uint256 k; k < 2; ++k) {
            leg.setSkew(k == 0 ? -1 : int256(1));
            vm.expectRevert(abi.encodeWithSelector(
                IWrappedToken.WrapReceivedMismatch.selector, 1000, k == 0 ? 999 : 1001));
            x.mtxWrapOrder(address(leg), o, "");
            assertEq(x.totalSupply(), 0);
            (,, uint256 reserve,,) = x.legOf(address(leg));
            assertEq(reserve, 0);
        }
    }

    function test_mtxWrapOrder_reserveShortfallIsRefused() public {
        (SkewLeg leg, WrappedToken x, ITradeToken.WrapOrder memory o) = _skewWrapper();
        x.mtxWrapOrder(address(leg), o, "");
        assertGe(x.collateralValue(), x.totalSupply());
        leg.setBalance(address(x), 999); // below the reserve of 1000
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.ReserveShortfall.selector, address(leg), 999, 1000));
        x.mtxWrapOrder(address(leg), o, "");
    }

    function test_mtxWrapOrder_throughMtxExecuteIsNotAllowlisted() public {
        ITradeToken.WrapOrder memory o = _order(1000, 3000, 0);
        bytes memory data = abi.encodeCall(IWrappedToken.mtxWrapOrder, (address(u), o, _sig(o)));
        MetaTxLib.MetaTransaction memory m = _call(alice, data, 1, RR);
        bytes memory sig = _signCall(ALICE_PK, address(w), m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, IWrappedToken.mtxWrapOrder.selector));
        MetaTokenBase(address(w)).mtxExecute(m, sig);
    }
}
