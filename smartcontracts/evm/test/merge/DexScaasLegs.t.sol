// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {DexLegs} from "../helpers/DexLegs.sol";
import {OrderJson} from "../helpers/OrderJson.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {UACall} from "../ua/UACall.sol";
import {UADexBase, UARouter} from "../ua/UADex.t.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";

/// The token's trade side after ua-mtx-merge T6 (R12, R38), called by selector: this file compiles on the tree before T6
/// too, so each test is red there on its own (plan T6 step 3).
interface IMergedT6 {
    function mtxTrade(ITradeToken.UATradeOrder calldata o, IUARegistry.UASig calldata auth,
        ITradeToken.TradeFill calldata f) external;
    function mtxCancelOrder(ITradeToken.UATradeOrder calldata o, IUARegistry.UASig calldata auth) external;
    function mtxInvalidateNonces(bytes32 from, uint256 batch, uint256 newMin, IUARegistry.UASig calldata auth) external;
    function tradeOrderDigest(ITradeToken.UATradeOrder calldata o) external view returns (bytes32);
    function cancelOrderDigest(ITradeToken.UATradeOrder calldata o) external view returns (bytes32);
    function invalidateNoncesDigest(bytes32 from, uint256 batch, uint256 newMin) external view returns (bytes32);
    function minNonce(bytes32 from, uint256 batch) external view returns (uint256);
    function pulled(bytes32 orderHash) external view returns (uint256);
    function mtxCancelNonce(MetaTxLib.UAEnvelope calldata e, uint256 lane, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function mtxNonce(bytes32 from, uint256 batch) external view returns (uint256);
}

/// The token's retired trade forms (invariant 3): the address `TradeOrder` side and the `ua*` names.
interface IOldT6 {
    function mtxTrade(ITradeToken.TradeOrder calldata o, bytes calldata sig, ITradeToken.TradeFill calldata f) external;
    function mtxCancelOrder(ITradeToken.TradeOrder calldata o, bytes calldata sig) external;
    function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes calldata sig) external;
    function restorePulled(ITradeToken.TradeOrder calldata o, uint256 amount) external;
    function tradeOrderDigest(ITradeToken.TradeOrder calldata o) external view returns (bytes32);
    function cancelOrderDigest(ITradeToken.TradeOrder calldata o) external view returns (bytes32);
    function invalidateNoncesDigest(address from, uint256 batch, uint256 newMin) external view returns (bytes32);
    function minNonce(address from, uint256 batch) external view returns (uint256);
    function uaTrade(ITradeToken.UATradeOrder calldata o, IUARegistry.UASig calldata auth,
        ITradeToken.TradeFill calldata f) external;
    function uaCancelOrder(ITradeToken.UATradeOrder calldata o, IUARegistry.UASig calldata auth) external;
    function uaInvalidateNonces(bytes32 from, uint256 batch, uint256 newMin, IUARegistry.UASig calldata auth) external;
    function uaTradeOrderDigest(ITradeToken.UATradeOrder calldata o) external view returns (bytes32);
    function cancelUAOrderDigest(ITradeToken.UATradeOrder calldata o) external view returns (bytes32);
    function uaInvalidateNoncesDigest(bytes32 from, uint256 batch, uint256 newMin) external view returns (bytes32);
    function uaMinNonce(bytes32 from, uint256 batch) external view returns (uint256);
}

interface IWrapOrderT6 {
    function mtxWrapOrder(address u, ITradeToken.UAWrapOrder calldata o, IUARegistry.UASig calldata auth)
        external returns (uint256);
}

/// T6: a SCaaS token leg is a `UATradeOrder` (CTR-DEX-26 shape 1), native or derived, through the token's merged
/// `mtxTrade`; `TradeOrder` stays for outside legs (`DexOrder`, shape 0); a registry only for a derived seller (C, R9).
/// The `UADexBase` book plus `D`, a SCaaS token with no registry (alice 1e6), listed against `C` (no registry, bob 1e6).
contract DexScaasLegsTest is UADexBase {
    NormalToken internal D;

    function setUp() public override {
        super.setUp();
        D = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 2,
            abi.encode(normalInit("D", "D", 0, 1e6, alice, address(0))), "D"));
        dex.setMarket(address(C), address(D), true);
        assertEq(C.registry(), address(0));
        assertEq(D.registry(), address(0));
    }

    function _sigOf(uint256 pk, bytes32 d) internal pure returns (IUARegistry.UASig memory a) {
        a.signature = _ecdsa(pk, d);
    }

    function _count(Vm.Log[] memory logs, bytes32 topic) internal pure returns (uint256 k) {
        for (uint256 i; i < logs.length; ++i) if (logs[i].topics[0] == topic) ++k;
    }

    /// R12: a `TradeOrder` (shape 0) selling a SCaaS token is refused by name, before any pull; the same trade as
    /// `UATradeOrder`s (shape 1) settles.
    function test_scaasLegShapeZeroRefused() public {
        ITradeToken.TradeOrder memory t = _nat(alice, address(B), 1000, 1900, 0);
        ITradeToken.UATradeOrder memory m = _ua(_pad(bob), address(A), 2000, 1000, 0);
        ISCaaSDex.DexLeg memory shape0 = DexLegs.leg0(address(A), t, _ecdsa(ALICE_PK, keccak256("any digest")), 1000);
        _expectOne(_s(shape0, _uaLeg(address(B), m, 2000)),
            abi.encodeWithSelector(ISCaaSDex.LegShapeUnknown.selector, uint8(0)));
        // positive control: alice's order as a `UATradeOrder` (her address zero-padded, her own key)
        ITradeToken.UATradeOrder memory u = _ua(_pad(alice), address(B), 1000, 1900, 0);
        assertTrue(_settle(_s(_uaLeg(address(A), u, 1000), _uaLeg(address(B), m, 2000))));
        assertEq(B.balanceOf(alice), 2000);
        assertEq(A.balanceOf(bob), 1000);
    }

    /// R9 (C): an all-native trade on two SCaaS tokens with no registry settles, each EOA by its own key, no registry
    /// call at all.
    function test_scaasLegUATradeOrder_eoaNoRegistry() public {
        ITradeToken.UATradeOrder memory t = _ua(_pad(alice), address(C), 1000, 1900, 3_000);
        ITradeToken.UATradeOrder memory m = _ua(_pad(bob), address(D), 2000, 1000, 1_000);
        ISCaaSDex.Settlement[] memory ss = _s(_uaLeg(address(D), t, 1000), _uaLeg(address(C), m, 2000));
        vm.expectCall(REG_L, bytes(""), 0);
        assertTrue(_settle(ss));
        // taker: 2000 C gross, fee ⌈6⌉ → 1994; maker: 1000 D gross, fee 1 → 999
        assertEq(C.balanceOf(alice), 1994);
        assertEq(D.balanceOf(bob), 999);
        assertEq(D.balanceOf(alice), 1e6 - 1000);
        assertEq(C.balanceOf(bob), 1e6 - 2000);
        assertEq(C.balanceOf(address(dex)), 0);
        assertEq(D.balanceOf(address(dex)), 0);
        assertEq(IMergedT6(address(D)).pulled(IMergedT6(address(D)).tradeOrderDigest(t)), 1000);
    }

    /// C: a derived seller needs its token's registry. The DEX refuses the leg by name before any pull
    /// (`UALegNotLedger`); the token's own guard on every trade entry is `UALedgerOff` by name.
    function test_derivedSellerNeedsLedger() public {
        ITradeToken.UATradeOrder memory t = _ua(_pad(alice), address(C), 1000, 2000, 0);
        ITradeToken.UATradeOrder memory d = _ua(uaB, address(D), 2000, 1000, 0);
        IUARegistry.UASig memory any = UACall.auth(uaB, hex"00");
        _expectOne(_s(_uaLeg(address(D), t, 1000), DexLegs.uaLeg(address(C), d, any, 2000)),
            abi.encodeWithSelector(IUALedger.UALegNotLedger.selector, address(C)));
        IMergedT6 c = IMergedT6(address(C));
        vm.prank(address(dex));
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        c.mtxTrade(d, any, ITradeToken.TradeFill(2000, 1000, 0, RELAYER));
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        c.mtxCancelOrder(d, any);
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        c.mtxInvalidateNonces(uaB, 1, 2, any);
        // positive control: the same derived seller on `B` (registry on) is pulled
        ITradeToken.UATradeOrder memory dB = _ua(uaB, address(A), 2000, 1000, 0);
        ITradeToken.UATradeOrder memory tA = _ua(_pad(alice), address(B), 1000, 2000, 0);
        assertTrue(_settle(_s(_uaLeg(address(A), tA, 1000), _uaLeg(address(B), dB, 2000))));
        assertEq(B.balanceOfUA(uaB), 100_000 - 2000);
    }

    /// R12, R37: an outside token's leg stays a `TradeOrder` signed as `DexOrder` (shape 0) and emits the address
    /// `LegSettled`; the SCaaS leg it meets emits `UALegSettled`; shape 1 on the outside token is refused by name.
    function test_outsideLegKeepsTradeOrder() public {
        ITradeToken.UATradeOrder memory t = _ua(_pad(alice), address(usdc), 1000, 500, 0);
        ITradeToken.TradeOrder memory m = _nat(dave, address(A), 500, 1000, 0);
        vm.recordLogs();
        assertTrue(_settle(_s(_uaLeg(address(A), t, 1000), _natLeg(address(usdc), m, 500))));
        assertEq(usdc.balanceOf(alice), 500);
        assertEq(A.balanceOf(dave), 1000);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 outside;
        for (uint256 k; k < logs.length; ++k) {
            if (logs[k].topics[0] != ISCaaSDex.LegSettled.selector) continue;
            ++outside;
            assertEq(logs[k].topics[2], dex.dexOrderDigest(address(usdc), m));
            assertEq(logs[k].topics[3], bytes32(uint256(uint160(dave))));
        }
        assertEq(outside, 1);
        assertEq(_count(logs, ISCaaSDex.UALegSettled.selector), 1);
        ITradeToken.UATradeOrder memory mu = _ua(_pad(dave), address(A), 500, 1000, 0);
        _expectOne(_s(_uaLeg(address(A), t, 1000), DexLegs.uaLeg(address(usdc), mu, UACall.auth(mu.from, hex"00"), 500)),
            abi.encodeWithSelector(IUALedger.UALegNotLedger.selector, address(usdc)));
    }

    /// R18: a SCaaS leg emits `UALegSettled` (the native signer zero-padded) and the token `UATradeFilled`; no address
    /// `LegSettled` / `TradeFilled` for a SCaaS leg (here two EOAs on tokens with no registry).
    function test_scaasLegEmitsUALegSettled() public {
        ITradeToken.UATradeOrder memory t = _ua(_pad(alice), address(C), 1000, 2000, 0);
        ITradeToken.UATradeOrder memory m = _ua(_pad(bob), address(D), 2000, 1000, 0);
        vm.recordLogs();
        assertTrue(_settle(_s(_uaLeg(address(D), t, 1000), _uaLeg(address(C), m, 2000))));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(_count(logs, ISCaaSDex.LegSettled.selector), 0);
        assertEq(_count(logs, ITradeToken.TradeFilled.selector), 0);
        assertEq(_count(logs, ISCaaSDex.UALegSettled.selector), 2);
        assertEq(_count(logs, ITradeToken.UATradeFilled.selector), 2);
        (bytes32 h, uint256[7] memory v) = _uaLegSettled(logs, _pad(alice));
        assertEq(h, IMergedT6(address(D)).tradeOrderDigest(t));
        assertEq(abi.encode(v), abi.encode([uint256(_pad(alice)), 1000, 2000, 0, 0, 0, 0]));
    }

    /// Separate stores: the signed meta-tx cancel (`mtxCancelNonce`) bumps a meta-tx lane, never a trade lane's
    /// `minNonce`; `mtxInvalidateNonces` raises the trade floor, never a meta-tx nonce.
    function test_metaTxCancelDoesNotCancelTradeOrders() public {
        IMergedT6 a = IMergedT6(address(A));
        bytes32 me = _pad(alice);
        MetaTxLib.UAEnvelope memory e;
        (e.from, e.batch, e.nonce, e.validUntil) = (me, 7, 0, block.timestamp + 600);
        bytes32 cd = MtxDigest.typed(address(A), keccak256(abi.encode(MetaTxLib.UA_CANCEL_NONCE_TYPEHASH, me, uint256(1),
            e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
        vm.prank(RELAYER);
        a.mtxCancelNonce(e, 1, _sigOf(ALICE_PK, cd));
        assertEq(a.mtxNonce(me, 1), 1);
        assertEq(a.minNonce(me, 1), 0);
        ITradeToken.UATradeOrder memory t = _ua(me, address(B), 1000, 1900, 0); // batch 1, nonce 1
        ITradeToken.UATradeOrder memory m = _ua(_pad(bob), address(A), 2000, 1000, 0);
        assertTrue(_settle(_s(_uaLeg(address(A), t, 1000), _uaLeg(address(B), m, 2000))));
        assertEq(a.pulled(a.tradeOrderDigest(t)), 1000);
        a.mtxInvalidateNonces(me, 1, 5, _sigOf(ALICE_PK, a.invalidateNoncesDigest(me, 1, 5)));
        assertEq(a.minNonce(me, 1), 5);
        assertEq(a.mtxNonce(me, 1), 1);
    }

    /// `_interact` refuses the merged `mtxTrade` (the DEX is `o.dex` of every order), and still the retired selectors.
    function test_interactRefusesMergedTradeSelector() public {
        UARouter router = new UARouter();
        vm.prank(bob);
        B.transfer(address(router), 10_000);
        ITradeToken.UATradeOrder memory o = _ua(_pad(alice), address(B), 1000, 1900, 0);
        ISCaaSDex.DexLeg memory l = _uaLeg(address(A), o, 1000);
        ISCaaSDex.ExchangePlan memory p;
        p.ref = "x";
        p.legs = new ISCaaSDex.ExchangeLeg[](1);
        p.legs[0] = DexLegs.exchange(l, 1000, 1900);
        bytes4[3] memory sels = [IMergedT6.mtxTrade.selector, IOldT6.mtxTrade.selector, IOldT6.uaTrade.selector];
        assertEq(sels[0], bytes4(0x874ab327));
        for (uint256 i; i < 3; ++i) {
            ISCaaSDex.Interaction[] memory bad = new ISCaaSDex.Interaction[](1);
            bad[0] = ISCaaSDex.Interaction(address(A), abi.encodePacked(sels[i], abi.encode(o, l.auth,
                ITradeToken.TradeFill(1, 2, 0, RELAYER))));
            vm.prank(RELAYER);
            vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.ForbiddenSelector.selector, address(A), sels[i]));
            dex.mtxExchange(p, bad);
        }
    }

    /// R12: a SCaaS maker signs `bytes32 destination` (the wallet's `UATradeOrder` JSON is the token's digest), the
    /// proceeds go where it signed, and a destination changed after signing is refused.
    function test_tradeOrderDestinationIsBytes32Signed() public {
        ITradeToken.UATradeOrder memory o = _ua(_pad(alice), address(B), 1000, 1900, 0);
        o.destination = uaP;
        IMergedT6 a = IMergedT6(address(A));
        bytes32 h = a.tradeOrderDigest(o);
        assertEq(h, OrderJson.trade(address(A), o, true));
        ITradeToken.UATradeOrder memory o2 = _ua(_pad(alice), address(B), 1000, 1900, 0);
        o2.destination = _pad(bob);
        assertTrue(a.tradeOrderDigest(o2) != h);
        ITradeToken.UATradeOrder memory m = _ua(_pad(bob), address(A), 2000, 1000, 0);
        ISCaaSDex.DexLeg memory l = _uaLeg(address(A), _ua(_pad(alice), address(B), 1000, 1900, 0), 1000);
        l.uaOrder.destination = uaP; // signed with destination 0, swapped after signing
        _expectOne(_s(l, _uaLeg(address(B), m, 2000)), abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector));
        uint256 before = B.balanceOfUA(uaP);
        assertTrue(_settle(_s(_uaLeg(address(A), o, 1000), _uaLeg(address(B), m, 2000))));
        assertEq(B.balanceOfUA(uaP), before + 2000);
        assertEq(B.balanceOf(alice), 0);
    }

    /// Carried from T3 (rule C): an EOA cancels and invalidates on a token with no registry, by its own key, no
    /// registry call; a wrong signer is refused.
    function test_eoaCancelAndInvalidate_noRegistry() public {
        IMergedT6 d = IMergedT6(address(D));
        bytes32 me = _pad(alice);
        ITradeToken.UATradeOrder memory o = _ua(me, address(C), 1000, 1900, 0);
        bytes32 h = d.tradeOrderDigest(o);
        bytes32 cd = d.cancelOrderDigest(o);
        bytes32 id = d.invalidateNoncesDigest(me, 1, 5);
        vm.expectCall(REG_L, bytes(""), 0);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        d.mtxCancelOrder(o, _sigOf(BOB_PK, cd));
        vm.expectEmit(true, true, false, true, address(D));
        emit ITradeToken.UAOrderCancelled(h, me);
        d.mtxCancelOrder(o, _sigOf(ALICE_PK, cd));
        assertEq(d.pulled(h), 1000);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        d.mtxInvalidateNonces(me, 1, 5, _sigOf(BOB_PK, id));
        vm.expectEmit(true, true, false, true, address(D));
        emit ITradeToken.UANoncesInvalidated(me, 1, 5);
        d.mtxInvalidateNonces(me, 1, 5, _sigOf(ALICE_PK, id));
        assertEq(d.minNonce(me, 1), 5);
    }

    /// Carried from T3: the address `TradeOrder` side of the token (its `WrapOrder` / `CancelWrapOrder` /
    /// `CancelOrder` / `InvalidateNonces` forms) and the `ua*` names have no entry; a wrap-shaped order
    /// (`dex == receiveToken`) is signed as `UAWrapOrder`, its cancel as `CancelUAWrapOrder`.
    function test_addressTradeFormsHaveNoEntry() public {
        ITradeToken.TradeOrder memory t = _nat(alice, address(B), 1000, 1900, 0);
        ITradeToken.UATradeOrder memory u = _ua(_pad(alice), address(B), 1000, 1900, 0);
        IUARegistry.UASig memory s;
        ITradeToken.TradeFill memory fill = ITradeToken.TradeFill(1, 2, 0, RELAYER);
        bytes[15] memory cds = [
            abi.encodeCall(IOldT6.mtxTrade, (t, "", fill)),
            abi.encodeCall(IOldT6.mtxCancelOrder, (t, "")),
            abi.encodeCall(IOldT6.mtxInvalidateNonces, (alice, 1, 2, "")),
            abi.encodeCall(IOldT6.restorePulled, (t, 1)),
            abi.encodeCall(IOldT6.tradeOrderDigest, (t)),
            abi.encodeCall(IOldT6.cancelOrderDigest, (t)),
            abi.encodeCall(IOldT6.invalidateNoncesDigest, (alice, 1, 2)),
            abi.encodeCall(IOldT6.minNonce, (alice, 1)),
            abi.encodeCall(IOldT6.uaTrade, (u, s, fill)),
            abi.encodeCall(IOldT6.uaCancelOrder, (u, s)),
            abi.encodeCall(IOldT6.uaInvalidateNonces, (_pad(alice), 1, 2, s)),
            abi.encodeCall(IOldT6.uaTradeOrderDigest, (u)),
            abi.encodeCall(IOldT6.cancelUAOrderDigest, (u)),
            abi.encodeCall(IOldT6.uaInvalidateNoncesDigest, (_pad(alice), 1, 2)),
            abi.encodeCall(IOldT6.uaMinNonce, (_pad(alice), 1))
        ];
        for (uint256 i; i < cds.length; ++i) {
            (bool ok, bytes memory ret) = address(A).call(cds[i]);
            assertFalse(ok, vm.toString(i));
            assertEq(ret.length, 0, vm.toString(i));
        }
        // positive control: the id forms answer, a wrap-shaped order in the UA wrap structs
        ITradeToken.UATradeOrder memory w = _ua(_pad(alice), address(B), 1000, 1900, 0);
        w.dex = address(B);
        IMergedT6 a = IMergedT6(address(A));
        assertEq(a.tradeOrderDigest(w), OrderJson.wrap(address(A), w, true));
        assertEq(a.cancelOrderDigest(w), OrderJson.cancelWrap(address(A), w, true));
        assertEq(a.cancelOrderDigest(u), OrderJson.cancelTrade(address(A), u, true));
        assertEq(a.invalidateNoncesDigest(_pad(alice), 1, 2), MtxDigest.typed(address(A),
            keccak256(abi.encode(keccak256("UAInvalidateNonces(bytes32 from,uint256 batch,uint256 minNonce)"),
            _pad(alice), uint256(1), uint256(2)))));
    }

    /// Carried from T3: an EOA's wrap order over a leg that is no SCaaS token (no `mtxTrade`: here an outside ERC-20)
    /// fails closed by name, `UALegNotLedger`, with no registry call; over a SCaaS leg it wraps (positive control).
    function test_wrapOrderOutsideLegNamedError() public {
        ITradeToken.UAWrapOrder memory w;
        (w.from, w.wrappedToken, w.amount, w.minMinted, w.batch, w.nonce, w.validUntil) =
            (_pad(alice), address(wrp), 100, 100, 3, 1, block.timestamp + 300);
        und.mint(alice, 100);
        vm.expectCall(REG_L, bytes(""), 0);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.UALegNotLedger.selector, address(und)));
        IWrapOrderT6(address(wrp)).mtxWrapOrder(address(und), w, _sigOf(ALICE_PK, keccak256("no domain")));
        // positive control: the same EOA's order over `tok` (a SCaaS leg) into `wrpL`
        _wrapL(bob, 1); // the leg is live
        w.wrappedToken = address(wrpL);
        bytes32 h = IMergedT6(address(tok)).tradeOrderDigest(DexLegs.asTrade(w));
        uint256 got = IWrapOrderT6(address(wrpL)).mtxWrapOrder(address(tok), w, _sigOf(ALICE_PK, h));
        assertEq(got, 100);
        assertEq(wrpL.balanceOf(alice), 100);
    }
}
