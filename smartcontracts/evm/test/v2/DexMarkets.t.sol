// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {DexLegs} from "../helpers/DexLegs.sol";
import {FeeOnTransferERC20, MockERC20} from "../helpers/Mocks.sol";
import {nid} from "../helpers/Ids.sol";
import {UADexBase} from "../ua/UADex.t.sol";
import {MockRouter} from "./DexExchange.t.sol";

/// fix2-dex (owner 2026-11-12). Bit 29 `CLOSED_MARKETS`: off by default, any pair settles on `mtxSettle` / the hybrids and
/// any token trades on the exchange path; on (set at creation), listed pairs and known tokens only. The SCaaS kind is the
/// factory's at use ("made from a registered release"), so an unlisted pair needs no record. The DEX never reads a
/// release's deprecation (owner 2026-11-12, closing Fable recheck2 P3-2): a deprecated release's token still settles
/// through its own verify, and a bad signature still fails at the token.
contract DexMarketsTest is UADexBase {
    uint256 constant CLOSED = 1 << GovernanceBits.CLOSED_MARKETS;
    MockRouter router;
    uint256 made;

    function setUp() public override {
        super.setUp();
        router = new MockRouter();
        vm.startPrank(bob);
        B.transfer(address(router), 100_000);
        vm.stopPrank();
    }

    // ------------------------------------------------------------------ helpers

    /// A new DEX with `features` and `locked` and no market; `dex` is it from here on (the orders name it).
    function _fresh(uint256 features, uint256 locked) internal {
        dex = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(address(this)), 200_000, TREASURY, false, 0,
            address(0), features, locked)), bytes32(++made)));
    }

    /// Alice sells 1000 A for >= 1900 B (0.3 %); Bob sells 2000 B for 1000 A (0.1 %); both shape 1, native signers.
    function _book() internal view returns (ISCaaSDex.Settlement[] memory) {
        return _s(_uaLeg(address(A), _ua(_pad(alice), address(B), 1000, 1900, 3_000), 1000),
            _uaLeg(address(B), _ua(_pad(bob), address(A), 2000, 1000, 1_000), 2000));
    }

    /// Alice sells 1000 A for >= 1900 B through the router (1000 A -> 2000 B).
    function _plan() internal view returns (ISCaaSDex.ExchangePlan memory p) {
        p.ref = "x";
        p.legs = new ISCaaSDex.ExchangeLeg[](1);
        p.legs[0] = DexLegs.exchange(_uaLeg(address(A), _ua(_pad(alice), address(B), 1000, 1900, 3_000), 0), 1000, 1900);
    }

    /// Alice sells 1000 A for >= 1800 B: Bob's 800 B at his price (400 A), 600 A outside for >= 1080 B.
    function _hybridPlan() internal view returns (ISCaaSDex.HybridPlan memory p) {
        p.ref = "hy";
        p.taker = _uaLeg(address(A), _ua(_pad(alice), address(B), 1000, 1800, 3_000), 1000);
        p.makers = new ISCaaSDex.DexLeg[](1);
        p.makers[0] = _uaLeg(address(B), _ua(_pad(bob), address(A), 2000, 1000, 1_000), 800);
        (p.outsideSell, p.outsideFloor) = (600, 1080);
    }

    function _swap(address tIn, address tOut, uint256 amountIn, uint256 amountOut)
        internal view returns (ISCaaSDex.Interaction[] memory xs)
    {
        xs = new ISCaaSDex.Interaction[](2);
        xs[0] = ISCaaSDex.Interaction(tIn, abi.encodeCall(IERC20.approve, (address(router), amountIn)));
        xs[1] = ISCaaSDex.Interaction(address(router),
            abi.encodeCall(MockRouter.swap, (tIn, tOut, amountIn, amountOut, address(dex))));
    }

    function _exchange(ISCaaSDex.ExchangePlan memory p, ISCaaSDex.Interaction[] memory xs, bytes memory err) internal {
        vm.prank(RELAYER);
        if (err.length != 0) vm.expectRevert(err);
        dex.mtxExchange(p, xs);
    }

    function _hybrid(ISCaaSDex.HybridPlan memory p, ISCaaSDex.Interaction[] memory xs, bytes memory err) internal {
        vm.prank(RELAYER);
        if (err.length != 0) vm.expectRevert(err);
        dex.mtxHybrid(p, xs);
    }

    function _deprecate(uint64 version) internal {
        f.deprecateToken(IOpenFactory.TokenKind.NORMAL, version, f.chainUid(), "x");
    }

    // ------------------------------------------------------------------ CLOSED_MARKETS

    /// Off by default: a pair never listed settles on `mtxSettle`; nothing was recorded for it.
    function test_open_settlesAPairNeverListed() public {
        _fresh(0, 0);
        assertEq(dex.features(), GovernanceBits.DEX_BITS);
        assertFalse(dex.listedOnly());
        assertFalse(dex.marketListed(address(A), address(B)));
        assertTrue(_settle(_book()));
        assertEq(B.balanceOf(alice), 1994);
        assertEq(A.balanceOf(bob), 999);
        assertEq(dex.tokenKind(address(A)), 0);
    }

    /// On (set at creation): the unlisted pair is refused `MarketNotListed`; listed, the same settlement settles.
    function test_closed_refusesAnUnlistedPair() public {
        _fresh(CLOSED, 0);
        assertEq(dex.features(), GovernanceBits.DEX_BITS | CLOSED);
        ISCaaSDex.Settlement[] memory ss = _book();
        _expectOne(ss, abi.encodeWithSelector(ISCaaSDex.MarketNotListed.selector, address(A), address(B)));
        dex.setMarket(address(A), address(B), true);
        assertTrue(_settle(ss));
    }

    /// The normal feature-bit rules: the admin's `disableFeature(29)` opens the markets for good; a bit locked at creation
    /// stays; a lock needs the bit set; the bit has no holder.
    function test_closed_disableOpens_lockHolds() public {
        _fresh(CLOSED, 0);
        dex.disableFeature(GovernanceBits.CLOSED_MARKETS);
        assertEq(dex.features(), GovernanceBits.DEX_BITS);
        assertTrue(_settle(_book()));
        _fresh(CLOSED, CLOSED);
        assertEq(dex.lockedFeatures(), CLOSED);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureLocked.selector, GovernanceBits.CLOSED_MARKETS));
        dex.disableFeature(GovernanceBits.CLOSED_MARKETS);
        vm.expectRevert(IGovernance.LockedNotSubset.selector);
        this.freshFor(0, CLOSED);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, uint8(30)));
        this.freshFor(1 << 30, 0);
        assertFalse(dex.hasRole(GovernanceBits.CLOSED_MARKETS, nid(address(this))));
    }

    function freshFor(uint256 features, uint256 locked) external { _fresh(features, locked); }

    /// The exchange path is open too: unknown tokens trade by default; on a closed DEX `TokenNotKnown`. The hybrid follows
    /// `mtxSettle`: any pair by default, `MarketNotListed` when closed.
    function test_exchangeAndHybrid_openByDefault_closedRefuse() public {
        _fresh(0, 0);
        _exchange(_plan(), _swap(address(A), address(B), 1000, 2000), "");
        assertEq(B.balanceOf(alice), 2000 - 6);
        _fresh(0, 0);
        _hybrid(_hybridPlan(), _swap(address(A), address(B), 600, 1150), "");
        _fresh(CLOSED, 0);
        _exchange(_plan(), _swap(address(A), address(B), 1000, 2000),
            abi.encodeWithSelector(ISCaaSDex.TokenNotKnown.selector, address(A)));
        _hybrid(_hybridPlan(), _swap(address(A), address(B), 600, 1150),
            abi.encodeWithSelector(ISCaaSDex.MarketNotListed.selector, address(A), address(B)));
    }

    /// With open markets the guard against a token that credits less is conservation: a fee-on-transfer outside maker
    /// on a pair never listed fails closed (no balance to pay from: nothing settles; with a stray balance:
    /// `ConservationBroken`).
    function test_open_feeOnTransfer_conservationCatchesIt() public {
        _fresh(0, 0);
        FeeOnTransferERC20 fot = new FeeOnTransferERC20();
        fot.mint(dave, 1e6);
        address p = dex.puller();
        vm.prank(dave);
        fot.approve(p, type(uint256).max);
        ITradeToken.TradeOrder memory m = _nat(dave, address(A), 2000, 1000, 0);
        ISCaaSDex.Settlement[] memory ss = _s(_uaLeg(address(A), _ua(_pad(alice), address(fot), 1000, 2000, 0), 1000),
            DexLegs.leg0(address(fot), m, _ecdsa(DAVE_PK, dex.dexOrderDigest(address(fot), m)), 2000));
        vm.prank(RELAYER);
        vm.expectRevert(ISCaaSDex.NothingSettled.selector);
        dex.mtxSettle(ss);
        fot.mint(address(dex), 10_000);
        _expectOne(ss, abi.encodeWithSelector(ISCaaSDex.ConservationBroken.selector, address(fot)));
    }

    // ------------------------------------------------------------------ the kind at use, never deprecation

    /// A derived receiver of a SCaaS ledger token on a pair never listed is paid (the ledger rule reads the factory at use).
    function test_open_derivedReceiverOfAnUnlistedToken() public {
        _fresh(0, 0);
        ISCaaSDex.ExchangePlan memory p = _plan();
        ITradeToken.UATradeOrder memory o = _ua(_pad(alice), address(B), 1000, 1900, 0);
        o.destination = uaB;
        p.legs[0] = DexLegs.exchange(_uaLeg(address(A), o, 0), 1000, 1900);
        _exchange(p, _swap(address(A), address(B), 1000, 2000), "");
        assertEq(B.balanceOfUA(uaB), 100_000 + 2000);
    }

    /// Settle, exchange and hybrid after A's and B's release is deprecated: each settles through the tokens' own verify (a
    /// shape-1 leg, the kind unchanged), and a bad taker signature fails at the token (`MetaTxBadSignature`), not the DEX.
    function test_deprecatedRelease_settlesThroughTheTokensVerify() public {
        _deprecate(1);
        assertEq(dex.tokenKind(address(A)), 1);
        ISCaaSDex.Settlement[] memory ss = _book();
        ss[0].taker.auth.signature = _ecdsa(BOB_PK, A.tradeOrderDigest(ss[0].taker.uaOrder));
        _expectOne(ss, abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector));
        assertTrue(_settle(_book())); // the control
        _fresh(0, 0);
        _exchange(_plan(), _swap(address(A), address(B), 1000, 2000), "");
        _fresh(0, 0);
        _hybrid(_hybridPlan(), _swap(address(A), address(B), 600, 1150), "");
    }

    // ------------------------------------------------------------------ the recipient's delta (owner 2026-11-12, C6-4)

    /// A receive-only outside token on an open DEX: alice sells 1000 A for >= 1900 of `t` through the router, which pays
    /// `out` of `t` to the DEX. Returns the plan.
    function _toOutside(address t) internal view returns (ISCaaSDex.ExchangePlan memory p) {
        p.ref = "x";
        p.legs = new ISCaaSDex.ExchangeLeg[](1);
        p.legs[0] = DexLegs.exchange(_uaLeg(address(A), _ua(_pad(alice), t, 1000, 1900, 0), 0), 1000, 1900);
    }

    /// The same receive-only plan with an exact token (the control) and with a 1 % fee-on-transfer token, one change at a
    /// time: the route pays 1920, the DEX receives 1901 (floor 1900, conservation balances) and pays it all to alice, who
    /// is credited 1882 < 1900: `InsufficientOutput`. With room (the route pays 2000) the fee token settles: the check is
    /// on what alice is credited, not on the token.
    function test_exchange_receiveOnlyFeeToken_recipientDelta() public {
        _fresh(0, 0);
        MockERC20 ex = new MockERC20("Exact", "EX", 18);
        FeeOnTransferERC20 fot = new FeeOnTransferERC20();
        ex.mint(address(router), 1e6);
        fot.mint(address(router), 1e6);
        _exchange(_toOutside(address(ex)), _swap(address(A), address(ex), 1000, 1920), ""); // the control
        assertEq(ex.balanceOf(alice), 1920);
        _fresh(0, 0);
        _exchange(_toOutside(address(fot)), _swap(address(A), address(fot), 1000, 1920),
            abi.encodeWithSelector(ISCaaSDex.InsufficientOutput.selector, address(fot)));
        _exchange(_toOutside(address(fot)), _swap(address(A), address(fot), 1000, 2000), "");
        assertGe(fot.balanceOf(alice), 1900);
    }

    /// The hybrid's taker (its exchange leg; no maker here): the same receive-only fee token, the same control.
    function test_hybrid_receiveOnlyFeeToken_recipientDelta() public {
        MockERC20 ex = new MockERC20("Exact", "EX", 18);
        FeeOnTransferERC20 fot = new FeeOnTransferERC20();
        ex.mint(address(router), 1e6);
        fot.mint(address(router), 1e6);
        ISCaaSDex.HybridPlan memory p;
        p.ref = "hy";
        p.makers = new ISCaaSDex.DexLeg[](0);
        (p.outsideSell, p.outsideFloor) = (1000, 1900);
        _fresh(0, 0);
        p.taker = _uaLeg(address(A), _ua(_pad(alice), address(ex), 1000, 1900, 0), 1000);
        _hybrid(p, _swap(address(A), address(ex), 1000, 1920), ""); // the control
        assertEq(ex.balanceOf(alice), 1920);
        _fresh(0, 0);
        p.taker = _uaLeg(address(A), _ua(_pad(alice), address(fot), 1000, 1900, 0), 1000);
        _hybrid(p, _swap(address(A), address(fot), 1000, 1920),
            abi.encodeWithSelector(ISCaaSDex.InsufficientOutput.selector, address(fot)));
    }

    /// The minimum is net of the DEX fee: alice signs 0.3 % and the route pays exactly the floor (1900, surplus 0); she is
    /// credited 1900 − ⌈5.7⌉ = 1894, which settles.
    function test_exchange_recipientDelta_netOfTheFee() public {
        _fresh(0, 0);
        MockERC20 ex = new MockERC20("Exact", "EX", 18);
        ex.mint(address(router), 1e6);
        ISCaaSDex.ExchangePlan memory p = _toOutside(address(ex));
        p.legs[0] = DexLegs.exchange(_uaLeg(address(A), _ua(_pad(alice), address(ex), 1000, 1900, 3_000), 0), 1000, 1900);
        _exchange(p, _swap(address(A), address(ex), 1000, 1900), "");
        assertEq(ex.balanceOf(alice), 1894);
    }
}
