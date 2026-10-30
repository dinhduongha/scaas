// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {UALedgerBase} from "./UALedgerBase.sol";
import {plainEnv, Catalogue} from "../helpers/Catalogue.sol";

/// Pulls `amountIn` of `tIn` from the caller under its allowance and pays `amountOut` of `tOut` to `to`.
contract UARouter {
    function swap(address tIn, address tOut, uint256 amountIn, uint256 amountOut, address to) external {
        IERC20(tIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20(tOut).transfer(to, amountOut);
    }
}

/// The SCaaSDex fixture with UA ledgers on (CTR-DEX-26): a factory on context A whose `NORMAL` implementation is bound to
/// the UA registry `REG_L`; `A` (alice 1e6) and `B` (bob 1e6) listed, the outside `usdc` (dave, approved to the puller)
/// listed against `A`, `C` a SCaaS token with the ledger off listed against `A`. `uaP` holds 100 k A, `uaB` 100 k B.
abstract contract UADexBase is UALedgerBase {
    uint256 internal constant DAVE_PK = 0xDA7E;
    address internal constant TREASURY = address(0x7EA5);
    address internal dave;
    OpenFactory internal f;
    SCaaSDex internal dex;
    NormalToken internal A;
    NormalToken internal B;
    NormalToken internal C;
    MockERC20 internal usdc;

    function setUp() public virtual override {
        super.setUp();
        dave = vm.addr(DAVE_PK);
        f = new OpenFactory(address(this), chainUidA, 0);
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, REG_L, address(0), false);
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 2, type(NormalToken).creationCode, address(0), address(0), false);
        Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0));
        A = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(normalInit("A", "A", 0, 1e6, alice, address(0))), "A"));
        B = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(normalInit("B", "B", 0, 1e6, bob, address(0))), "B"));
        C = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 2, abi.encode(normalInit("C", "C", 0, 1e6, bob, address(0))), "C"));
        dex = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(address(this), 200_000, TREASURY, false)), "dex"));
        usdc = new MockERC20("USD Coin", "USDC", 6);
        usdc.mint(dave, 1e6);
        address puller = dex.puller();
        vm.prank(dave);
        usdc.approve(puller, type(uint256).max);
        dex.setMarket(address(A), address(B), true);
        dex.setMarket(address(A), address(usdc), true);
        dex.setMarket(address(A), address(C), true);
        vm.prank(alice);
        A.transferToUA(uaP, 100_000);
        vm.prank(bob);
        B.transferToUA(uaB, 100_000);
    }

    // ----- orders -----

    function _ua(bytes32 from, address receiveToken, uint256 amount, uint256 receiveAmount, uint256 fee)
        internal view returns (ITradeToken.UATradeOrder memory o)
    {
        o.from = from;
        o.receiveToken = receiveToken;
        o.amount = amount;
        o.receiveAmount = receiveAmount;
        o.fee = fee;
        o.dex = address(dex);
        o.batch = 1;
        o.nonce = 1;
        o.validUntil = block.timestamp + 300;
    }

    function _nat(address from, address receiveToken, uint256 amount, uint256 receiveAmount, uint256 fee)
        internal view returns (ITradeToken.TradeOrder memory o)
    {
        o.from = from;
        o.receiveToken = receiveToken;
        o.amount = amount;
        o.receiveAmount = receiveAmount;
        o.fee = fee;
        o.dex = address(dex);
        o.batch = 1;
        o.nonce = 1;
        o.validUntil = block.timestamp + 300;
    }

    function _pk(address a) internal view returns (uint256) {
        if (a == alice) return ALICE_PK;
        if (a == bob) return BOB_PK;
        return DAVE_PK;
    }

    /// A shape-1 leg: a derived signer through the registry under `trade`, a padded native by its own signature.
    function _uaLeg(address sell, ITradeToken.UATradeOrder memory o, uint256 fill)
        internal view returns (ISCaaSDex.Leg memory)
    {
        bytes32 h = ITradeToken(sell).uaTradeOrderDigest(o);
        bytes memory auth = UAKinds.inNativeSpace(o.from)
            ? _ecdsa(_pk(address(uint160(uint256(o.from)))), h)
            : _auth(lreg, lreg.kindOf(o.from), _key(lreg.kindOf(o.from)), UAKinds.PURPOSE_TRADE, h);
        return ISCaaSDex.Leg(sell, 1, abi.encode(o), auth, fill);
    }

    /// A shape-0 leg (a SCaaS token's `TradeOrder`, or an outside token's `DexOrder`).
    function _natLeg(address sell, ITradeToken.TradeOrder memory o, uint256 fill)
        internal view returns (ISCaaSDex.Leg memory)
    {
        bytes32 h = sell == address(usdc) ? dex.dexOrderDigest(sell, o) : ITradeToken(sell).tradeOrderDigest(o);
        return ISCaaSDex.Leg(sell, 0, abi.encode(o), _ecdsa(_pk(o.from), h), fill);
    }

    function _s(ISCaaSDex.Leg memory taker, ISCaaSDex.Leg memory maker)
        internal pure returns (ISCaaSDex.Settlement[] memory ss)
    {
        ss = new ISCaaSDex.Settlement[](1);
        ss[0].ref = "ua";
        ss[0].taker = taker;
        ss[0].makers = new ISCaaSDex.Leg[](1);
        ss[0].makers[0] = maker;
    }

    function _settle(ISCaaSDex.Settlement[] memory ss) internal returns (bool) {
        vm.prank(RELAYER);
        return dex.mtxSettle(ss)[0];
    }

    /// The settlement fails alone with `err` (run through `settleOne` as the DEX).
    function _expectOne(ISCaaSDex.Settlement[] memory ss, bytes memory err) internal {
        vm.prank(address(dex));
        vm.expectRevert(err);
        dex.settleOne(ss[0], RELAYER);
    }

    function _uaLegSettled(Vm.Log[] memory logs, bytes32 from) internal pure returns (bytes32 h, uint256[7] memory v) {
        for (uint256 k; k < logs.length; ++k) {
            if (logs[k].topics[0] != ISCaaSDex.UALegSettled.selector || logs[k].topics[3] != from) continue;
            h = logs[k].topics[2];
            (bytes32 dest, uint256 a, uint256 b, uint256 c, uint256 d, uint256 e, uint256 g) =
                abi.decode(logs[k].data, (bytes32, uint256, uint256, uint256, uint256, uint256, uint256));
            v = [uint256(dest), a, b, c, d, e, g];
            return (h, v);
        }
        revert("no UALegSettled");
    }
}

/// dex.md CTR-DEX-26 (UA-5b): tagged legs in one book — UA and native orders match each other; a UA leg sells a SCaaS
/// ledger token through `uaTrade`; derived parties are paid and refunded by `transferToUA`; self-trade over ids;
/// `UAVerifyGas` reverts the whole call; `uaTrade` is refused in interactions; conservation unchanged.
contract UADexTest is UADexBase {
    /// uaP (shape 1) sells 1000 A for >= 1900 B (0.3 %); bob (shape 0) sells 2000 B for 1000 A (0.1 %).
    function test_uaTaker_nativeMaker() public {
        ITradeToken.UATradeOrder memory t = _ua(uaP, address(B), 1000, 1900, 3_000);
        ITradeToken.TradeOrder memory m = _nat(bob, address(A), 2000, 1000, 1_000);
        ISCaaSDex.Settlement[] memory ss = _s(_uaLeg(address(A), t, 1000), _natLeg(address(B), m, 2000));
        uint256 poolA = A.balanceOf(POOL);
        vm.recordLogs();
        assertTrue(_settle(ss));
        // taker: 2000 B gross, fee ⌈6⌉ → 1994 into uaP's B ledger; relayer 20 % of 6 = 1, treasury 5
        assertEq(B.balanceOfUA(uaP), 1994);
        assertEq(B.balanceOf(POOL), 100_000 + 1994);
        assertEq(A.balanceOfUA(uaP), 100_000 - 1000);
        assertEq(A.balanceOf(POOL), poolA - 1000);
        // maker: 1000 A gross, fee 1 → 999
        assertEq(A.balanceOf(bob), 999);
        assertEq(B.balanceOf(RELAYER), 1);
        assertEq(B.balanceOf(TREASURY), 5);
        assertEq(A.balanceOf(TREASURY), 1);
        assertEq(A.balanceOf(address(dex)), 0);
        assertEq(B.balanceOf(address(dex)), 0);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        (bytes32 h, uint256[7] memory v) = _uaLegSettled(logs, uaP);
        assertEq(h, A.uaTradeOrderDigest(t));
        assertEq(abi.encode(v), abi.encode([uint256(uaP), 1000, 1994, 6, 0, 1, 5]));
        uint256 native;
        for (uint256 k; k < logs.length; ++k) if (logs[k].topics[0] == ISCaaSDex.LegSettled.selector) ++native;
        assertEq(native, 1);
    }

    /// alice (shape 0) takes uaB's resting order (shape 1, its proceeds to uaP).
    function test_nativeTaker_uaMaker_derivedDestination() public {
        ITradeToken.TradeOrder memory t = _nat(alice, address(B), 1000, 1900, 0);
        ITradeToken.UATradeOrder memory m = _ua(uaB, address(A), 2000, 1000, 0);
        m.destination = uaP;
        assertTrue(_settle(_s(_natLeg(address(A), t, 1000), _uaLeg(address(B), m, 2000))));
        assertEq(B.balanceOf(alice), 2000);
        assertEq(B.balanceOfUA(uaB), 100_000 - 2000);
        assertEq(A.balanceOfUA(uaP), 100_000 + 1000);
        assertEq(A.balanceOfUA(uaB), 0);
    }

    function test_uaVsUa_and_aSecondFillVerifiesNothing() public {
        ITradeToken.UATradeOrder memory t = _ua(uaP, address(B), 500, 1000, 0);
        ITradeToken.UATradeOrder memory m = _ua(uaB, address(A), 2000, 1000, 0);
        ISCaaSDex.Leg memory ml = _uaLeg(address(B), m, 1000);
        assertTrue(_settle(_s(_uaLeg(address(A), t, 500), ml)));
        assertEq(B.balanceOfUA(uaP), 1000);
        assertEq(A.balanceOfUA(uaB), 500);
        // the maker rests; its second fill carries no valid auth: pulled[h] ≠ 0 (CTR-DEX-15 step 4)
        t.nonce = 2;
        ml.sig = hex"00";
        assertTrue(_settle(_s(_uaLeg(address(A), t, 500), ml)));
        assertEq(B.balanceOfUA(uaP), 2000);
        assertEq(B.pulled(B.uaTradeOrderDigest(m)), 2000);
    }

    /// A native id signs a `UATradeOrder` to name a UA destination; it sells its ERC-20 balance.
    function test_nativeShape1_paysAUA() public {
        ITradeToken.UATradeOrder memory t = _ua(_pad(alice), address(B), 1000, 2000, 0);
        t.destination = uaP;
        ITradeToken.TradeOrder memory m = _nat(bob, address(A), 2000, 1000, 0);
        uint256 a0 = A.balanceOf(alice);
        assertTrue(_settle(_s(_uaLeg(address(A), t, 1000), _natLeg(address(B), m, 2000))));
        assertEq(A.balanceOf(alice), a0 - 1000);
        assertEq(B.balanceOfUA(uaP), 2000);
        assertEq(A.balanceOf(bob), 1000);
    }

    /// Over ids: alice's `TradeOrder` and her padded `UATradeOrder` are one party.
    function test_selfTrade_byId() public {
        ITradeToken.TradeOrder memory t = _nat(alice, address(B), 1000, 2000, 0);
        ITradeToken.UATradeOrder memory m = _ua(_pad(alice), address(A), 2000, 1000, 0);
        _expectOne(_s(_natLeg(address(A), t, 1000), _uaLeg(address(B), m, 2000)),
            abi.encodeWithSelector(ISCaaSDex.SelfTrade.selector, _pad(alice)));
        ITradeToken.UATradeOrder memory u = _ua(uaB, address(B), 1000, 2000, 0);
        ITradeToken.UATradeOrder memory v = _ua(uaB, address(A), 2000, 1000, 0);
        _expectOne(_s(_uaLeg(address(A), u, 1000), _uaLeg(address(B), v, 2000)),
            abi.encodeWithSelector(ISCaaSDex.SelfTrade.selector, uaB));
    }

    /// Path B on a UA leg: the token pulls the whole amount; the DEX refunds the unmatched part into the UA's ledger.
    function test_pathB_refundToAUA() public {
        ITradeToken.UATradeOrder memory t = _ua(uaP, address(B), 1000, 1200, 0);
        t.flags = 3; // IOC | ESCROW
        ITradeToken.TradeOrder memory m = _nat(bob, address(A), 1200, 600, 0); // 1200 B for 600 A
        vm.recordLogs();
        assertTrue(_settle(_s(_uaLeg(address(A), t, 600), _natLeg(address(B), m, 1200))));
        assertEq(A.balanceOfUA(uaP), 100_000 - 600);
        assertEq(B.balanceOfUA(uaP), 1200);
        assertEq(A.balanceOf(address(dex)), 0);
        (, uint256[7] memory v) = _uaLegSettled(vm.getRecordedLogs(), uaP);
        assertEq(abi.encode(v), abi.encode([uint256(uaP), 600, 1200, 0, 400, 0, 0]));
    }

    function test_legKindAndShapeErrors() public {
        ITradeToken.TradeOrder memory m = _nat(bob, address(A), 2000, 1000, 0);
        // a shape-1 leg in a ledger-off SCaaS token, and in an outside token
        ITradeToken.UATradeOrder memory tc = _ua(_pad(bob), address(A), 1000, 1000, 0);
        _expectOne(_s(_uaLeg(address(C), tc, 1000), _natLeg(address(A), _nat(alice, address(C), 1000, 1000, 0), 1000)),
            abi.encodeWithSelector(ISCaaSDex.UALegNotLedger.selector, address(C)));
        ITradeToken.UATradeOrder memory tu = _ua(_pad(dave), address(A), 1000, 1000, 0);
        ISCaaSDex.Leg memory lu = ISCaaSDex.Leg(address(usdc), 1, abi.encode(tu), hex"00", 1000); // usdc has no digest
        _expectOne(_s(lu, _natLeg(address(A), _nat(alice, address(usdc), 1000, 1000, 0), 1000)),
            abi.encodeWithSelector(ISCaaSDex.UALegNotLedger.selector, address(usdc)));
        // an unknown tag
        ISCaaSDex.Settlement[] memory ss =
            _s(_uaLeg(address(A), _ua(uaP, address(B), 1000, 2000, 0), 1000), _natLeg(address(B), m, 2000));
        ss[0].taker.shape = 2;
        _expectOne(ss, abi.encodeWithSelector(ISCaaSDex.LegShapeUnknown.selector, uint8(2)));
    }

    /// A derived payout in a token without a UA ledger, or to an unregistered id, fails that settlement.
    function test_payoutErrors() public {
        // uaP's proceeds in the outside usdc (dave's outside maker order)
        ITradeToken.UATradeOrder memory t = _ua(uaP, address(usdc), 1000, 2000, 0);
        ITradeToken.TradeOrder memory d = _nat(dave, address(A), 2000, 1000, 0);
        _expectOne(_s(_uaLeg(address(A), t, 1000), _natLeg(address(usdc), d, 2000)),
            abi.encodeWithSelector(ISCaaSDex.UAReceiveNotLedger.selector, address(usdc)));
        // a padded native in C (ledger off) with a derived destination
        ITradeToken.UATradeOrder memory tc = _ua(_pad(alice), address(C), 1000, 1000, 0);
        tc.destination = uaB;
        _expectOne(_s(_uaLeg(address(A), tc, 1000), _natLeg(address(C), _nat(bob, address(A), 1000, 1000, 0), 1000)),
            abi.encodeWithSelector(ISCaaSDex.UAReceiveNotLedger.selector, address(C)));
        // an unregistered derived destination: the receive token's transferToUA refuses it
        ITradeToken.UATradeOrder memory tx_ = _ua(uaP, address(B), 1000, 2000, 0);
        tx_.destination = bytes32(uint256(keccak256("nobody")));
        ITradeToken.TradeOrder memory m = _nat(bob, address(A), 2000, 1000, 0);
        _expectOne(_s(_uaLeg(address(A), tx_, 1000), _natLeg(address(B), m, 2000)),
            abi.encodeWithSelector(IUALedger.UANotRegistered.selector, tx_.destination));
        // through mtxSettle that is one MatchFailed, the call itself does not revert when another settlement works
        ISCaaSDex.Settlement[] memory two = new ISCaaSDex.Settlement[](2);
        two[0] = _s(_uaLeg(address(A), tx_, 1000), _natLeg(address(B), m, 2000))[0];
        ITradeToken.UATradeOrder memory ok = _ua(uaP, address(B), 1000, 2000, 0);
        ok.nonce = 2;
        ITradeToken.TradeOrder memory m2 = _nat(bob, address(A), 2000, 1000, 0);
        m2.nonce = 2;
        two[1] = _s(_uaLeg(address(A), ok, 1000), _natLeg(address(B), m2, 2000))[0];
        vm.prank(RELAYER);
        bool[] memory r = dex.mtxSettle(two);
        assertFalse(r[0]);
        assertTrue(r[1]);
    }

    /// A UA leg whose verify cannot get its cap reverts the whole call (`UAVerifyGas`), never `MatchFailed`; with the
    /// gas it settles.
    function test_uaVerifyGas_revertsTheWholeCall() public {
        ITradeToken.UATradeOrder memory t = _ua(uaP, address(B), 1000, 2000, 0); // p256: cap 400 k
        ITradeToken.TradeOrder memory m = _nat(bob, address(A), 2000, 1000, 0);
        ISCaaSDex.Settlement[] memory ss = _s(_uaLeg(address(A), t, 1000), _natLeg(address(B), m, 2000));
        vm.prank(RELAYER);
        vm.expectRevert(UAKinds.UAVerifyGas.selector);
        dex.mtxSettle{gas: 380_000}(ss);
        assertTrue(_settle(ss));
    }

    /// Logged (cold, one state snapshot per pair): the same native parties as shape-0 legs and as padded shape-1 legs
    /// (ECDSA either way), and a derived `p256` taker (stand-in verifier) — what the tag and the UA ledger cost.
    function test_gas_legShapes() public {
        ITradeToken.TradeOrder memory t0 = _nat(alice, address(B), 1000, 2000, 3_000);
        ITradeToken.TradeOrder memory m0 = _nat(bob, address(A), 2000, 1000, 3_000);
        ISCaaSDex.Settlement[] memory s00 = _s(_natLeg(address(A), t0, 1000), _natLeg(address(B), m0, 2000));
        ISCaaSDex.Settlement[] memory s11 = _s(_uaLeg(address(A), _ua(_pad(alice), address(B), 1000, 2000, 3_000), 1000),
            _uaLeg(address(B), _ua(_pad(bob), address(A), 2000, 1000, 3_000), 2000));
        ISCaaSDex.Settlement[] memory sP1 = _s(_uaLeg(address(A), _ua(uaP, address(B), 1000, 2000, 3_000), 1000),
            _uaLeg(address(B), _ua(_pad(bob), address(A), 2000, 1000, 3_000), 2000));
        string[3] memory names = ["native x native, shape 0 x 0", "native x native, shape 1 x 1 (padded ids)",
            "p256 UA (stand-in) x native, shape 1 x 1"];
        ISCaaSDex.Settlement[][3] memory all = [s00, s11, sP1];
        for (uint256 i; i < 3; ++i) {
            uint256 snap = vm.snapshotState();
            vm.prank(RELAYER);
            uint256 g = gasleft();
            assertTrue(dex.mtxSettle(all[i])[0]);
            emit log_named_uint(string.concat("mtxSettle ", names[i]), g - gasleft());
            vm.revertToState(snap);
        }
    }

    function test_exchange_uaLegGetsTheSurplus_and_uaTradeIsNoInteraction() public {
        UARouter router = new UARouter();
        vm.prank(bob);
        B.transfer(address(router), 10_000);
        ITradeToken.UATradeOrder memory o = _ua(uaP, address(B), 1000, 1900, 3_000);
        ISCaaSDex.ExchangePlan memory p;
        p.ref = "x";
        p.legs = new ISCaaSDex.ExchangeLeg[](1);
        ISCaaSDex.Leg memory l = _uaLeg(address(A), o, 1000);
        p.legs[0] = ISCaaSDex.ExchangeLeg(address(A), 1, l.order, l.sig, 1000, 1900);
        // `uaTrade` is never an interaction (the DEX is `o.dex` of every order)
        ISCaaSDex.Interaction[] memory bad = new ISCaaSDex.Interaction[](1);
        bad[0] = ISCaaSDex.Interaction(address(A),
            abi.encodeCall(ITradeToken.uaTrade, (o, l.sig, ITradeToken.TradeFill(1, 2, 0, RELAYER))));
        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.ForbiddenSelector.selector, address(A), ITradeToken.uaTrade.selector));
        dex.mtxExchange(p, bad);
        // 1000 A → 2000 B through the router: floor 1900, fee ⌈5.7⌉ = 6, surplus 100
        ISCaaSDex.Interaction[] memory xs = new ISCaaSDex.Interaction[](2);
        xs[0] = ISCaaSDex.Interaction(address(A), abi.encodeCall(IERC20.approve, (address(router), 1000)));
        xs[1] = ISCaaSDex.Interaction(address(router),
            abi.encodeCall(UARouter.swap, (address(A), address(B), 1000, 2000, address(dex))));
        vm.recordLogs();
        vm.prank(RELAYER);
        dex.mtxExchange(p, xs);
        assertEq(B.balanceOfUA(uaP), 1900 - 6 + 100);
        assertEq(A.balanceOfUA(uaP), 100_000 - 1000);
        assertEq(A.balanceOf(address(dex)), 0);
        assertEq(B.balanceOf(address(dex)), 0);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 n;
        for (uint256 k; k < logs.length; ++k) {
            if (logs[k].topics[0] != ISCaaSDex.UAExchangeLegSettled.selector) continue;
            assertEq(logs[k].topics[3], uaP);
            assertEq(logs[k].data, abi.encode(uaP, uint256(1000), uint256(1900), uint256(100), uint256(6), uint256(0),
                uint256(1900)));
            ++n;
        }
        assertEq(n, 1);
    }
}
