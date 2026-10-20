// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {V2Fixture, UID_} from "./helpers/V2Fixture.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";

/// The sell token's side of a `TradeOrder` (CTR-DEX-15, -14, -04, -05, -02). This test contract plays the DEX: it is
/// a contract and it is `o.dex`.
contract TradeTest is V2Fixture {
    uint256 constant ALICE_PK = 0xA11CE;
    address alice = vm.addr(ALICE_PK);
    address other = address(0x07E5);
    NoUnderlyingToken t;
    NoUnderlyingToken t2;

    function setUp() public {
        t = _none(alice, 1_000_000, address(0));
        t2 = _none(alice, 1_000_000, address(0));
    }

    function _order(uint256 amount, uint256 receiveAmount) internal view returns (ITradeToken.TradeOrder memory o) {
        o.from = alice;
        o.receiveToken = address(t2);
        o.amount = amount;
        o.receiveAmount = receiveAmount;
        o.dex = address(this);
        o.batch = 1;
        o.nonce = 1;
        o.validUntil = block.timestamp + 300;
    }

    function _sign(NoUnderlyingToken tok, ITradeToken.TradeOrder memory o) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, tok.tradeOrderDigest(o));
        return abi.encodePacked(r, s, v);
    }

    function _fill(uint256 sell, uint256 recv, uint256 fee) internal view returns (ITradeToken.TradeFill memory) {
        return ITradeToken.TradeFill(sell, recv, fee, relayer);
    }

    function _trade(ITradeToken.TradeOrder memory o, ITradeToken.TradeFill memory f) internal {
        t.mtxTrade(o, _sign(t, o), f);
    }

    function _expect(bytes4 sel, ITradeToken.TradeOrder memory o, ITradeToken.TradeFill memory f) internal {
        bytes memory sig = _sign(t, o);
        vm.expectRevert(abi.encodeWithSelector(sel, t.tradeOrderDigest(o)));
        t.mtxTrade(o, sig, f);
    }

    // ------------------------------------------------------------------ Path A

    function test_pathA_partialFillsToTheDex_thenTheRemainderCloses() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        bytes32 h = t.tradeOrderDigest(o);
        vm.expectEmit(address(t));
        emit ITradeToken.TradeFilled(h, alice, 600, 1200, 0);
        _trade(o, _fill(600, 1200, 0));
        assertEq(t.balanceOf(address(this)), 600);
        assertEq(t.pulled(h), 600);
        _trade(o, _fill(400, 800, 0)); // the remainder may close below the minimum
        assertEq(t.pulled(h), 1000);
        _expect(ITradeToken.OrderClosed.selector, o, _fill(1, 2, 0));
    }

    function test_pathA_bounds() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        _expect(ITradeToken.ZeroFill.selector, o, _fill(0, 0, 0));
        _expect(ITradeToken.Overfill.selector, o, _fill(1001, 2002, 0));
        _expect(ITradeToken.BelowMinFill.selector, o, _fill(499, 998, 0)); // 50 % floor
        _expect(ITradeToken.PriceLimit.selector, o, _fill(600, 1199, 0));
        _expect(ITradeToken.FeeAboveSigned.selector, o, _fill(600, 1200, 1)); // fee 0 signed
        o.fee = 3_000; // 0.3 % of 1200 = 3.6 -> 4 (rounded up)
        _trade(o, _fill(600, 1200, 4));
        ITradeToken.TradeOrder memory o2 = _order(1000, 2000);
        o2.nonce = 2;
        o2.fee = 3_000;
        _expect(ITradeToken.FeeAboveSigned.selector, o2, _fill(600, 1200, 5));
    }

    /// SOL-02 (review W-S, 2026-10-19): the price limit of amounts whose products pass 2^256 is a verdict, not a panic.
    function test_pathA_priceLimit_hugeAmounts() public {
        ITradeToken.TradeOrder memory o = _order(1 << 200, 1 << 100);
        _expect(ITradeToken.PriceLimit.selector, o, _fill(1 << 200, (1 << 100) - 1, 0));
    }

    /// CHAIN-03 (review T2, 2026-10-19): the signed fee bound of a huge receiveFill is `mulDiv`, not a product past 2^256;
    /// the bound is exactly ceil(2^250 · 1 %).
    function test_pathA_feeBound_hugeReceiveFill() public {
        ITradeToken.TradeOrder memory o = _order(1000, 1 << 250);
        o.fee = 10_000;
        uint256 cap = (uint256(1) << 250) / 100 + 1; // 2^250 is not a multiple of 100: ceil = floor + 1
        _expect(ITradeToken.FeeAboveSigned.selector, o, _fill(1000, 1 << 250, cap + 1));
        _trade(o, _fill(1000, 1 << 250, cap));
        assertEq(t.pulled(t.tradeOrderDigest(o)), 1000);
    }

    /// `mulGt` is exactly `a·b > c·d` wherever the products fit, and ordered past 2^256.
    function testFuzz_mulGt(uint128 a, uint128 b, uint128 c, uint128 d) public pure {
        assertEq(TradeLib.mulGt(a, b, c, d), uint256(a) * b > uint256(c) * d);
    }

    function test_mulGt_past2pow256() public pure {
        uint256 m = type(uint256).max;
        assertTrue(TradeLib.mulGt(m, 2, m, 1));
        assertFalse(TradeLib.mulGt(m, 1, m, 2));
        assertFalse(TradeLib.mulGt(m, m, m, m));
        assertTrue(TradeLib.mulGt(1 << 200, 1 << 100, (1 << 100) - 1, 1 << 200));
        assertFalse(TradeLib.mulGt(1 << 200, 1 << 100, 1 << 100, 1 << 200));
    }

    function test_minFill_signerAboveTheFloor_andFillOrKill() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        o.minFill = 800;
        _expect(ITradeToken.BelowMinFill.selector, o, _fill(700, 1400, 0));
        o.minFill = 1000; // fill-or-kill
        _expect(ITradeToken.BelowMinFill.selector, o, _fill(999, 1998, 0));
        _trade(o, _fill(1000, 2000, 0));
        o.minFill = 1001;
        o.nonce = 2;
        _expect(ITradeToken.BadMinFill.selector, o, _fill(1000, 2000, 0));
    }

    function test_ioc_closesAtItsSinglePull() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        o.flags = 1; // IOC
        _trade(o, _fill(600, 1200, 0));
        assertEq(t.pulled(t.tradeOrderDigest(o)), 1000);
        _expect(ITradeToken.OrderClosed.selector, o, _fill(400, 800, 0));
    }

    // ------------------------------------------------------------------ Path B

    function test_pathB_escrowPullsTheWholeAmountOnce() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        o.flags = 3; // IOC | ESCROW
        _expect(ITradeToken.EscrowFillShape.selector, o, _fill(999, 0, 0));
        _expect(ITradeToken.EscrowFillShape.selector, o, _fill(1000, 2000, 0));
        _expect(ITradeToken.EscrowFillShape.selector, o, _fill(1000, 0, 1)); // no DEX fee on an escrow
        bytes32 h = t.tradeOrderDigest(o);
        vm.expectEmit(address(t));
        emit ITradeToken.TradeFilled(h, alice, 1000, 0, 0);
        _trade(o, _fill(1000, 0, 0));
        assertEq(t.pulled(h), 1000);
        assertEq(t.balanceOf(address(this)), 1000);
        _expect(ITradeToken.OrderClosed.selector, o, _fill(1000, 0, 0));
        o.flags = 2; // ESCROW without IOC
        o.nonce = 2;
        _expect(ITradeToken.BadFlags.selector, o, _fill(1000, 0, 0));
        o.flags = 8; // unknown bit
        _expect(ITradeToken.BadFlags.selector, o, _fill(1000, 0, 0));
    }

    // ------------------------------------------------------------------ caller, identities, shape

    function test_onlyTheNamedDex_andItMustBeAContract() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        bytes memory sig = _sign(t, o);
        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.NotDex.selector, other));
        t.mtxTrade(o, sig, _fill(600, 1200, 0));
        o.dex = other; // an EOA
        sig = _sign(t, o);
        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.DexNotContract.selector, other));
        t.mtxTrade(o, sig, _fill(600, 1200, 0));
    }

    function test_selfOrder_relayer_expiry_shape() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        o.relayer = address(0x5E1);
        bytes memory sig = _sign(t, o);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.WrongRelayer.selector, t.tradeOrderDigest(o), relayer));
        t.mtxTrade(o, sig, _fill(600, 1200, 0));
        o = _order(1000, 2000);
        o.validUntil = block.timestamp - 1;
        _expect(ITradeToken.OrderExpired.selector, o, _fill(600, 1200, 0));
        o = _order(0, 2000);
        _expect(ITradeToken.ZeroAmount.selector, o, _fill(600, 1200, 0));
        o = _order(1000, 0);
        _expect(ITradeToken.ZeroAmount.selector, o, _fill(600, 1200, 0));
        o = _order(1000, 2000);
        o.fee = 10_001;
        _expect(ITradeToken.FeeAboveCap.selector, o, _fill(600, 1200, 0));
        o = _order(1000, 2000);
        o.receiveToken = address(t); // a cycle order X -> X is allowed by the token
        _trade(o, _fill(600, 1200, 0));
    }

    function test_badSignature_andReplayOnAnotherToken() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        bytes memory sigOnT2 = _sign(t2, o); // signed in t2's domain
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxTrade(o, sigOnT2, _fill(600, 1200, 0));
    }

    function test_erc1271Signer() public {
        Mock1271Wallet w = new Mock1271Wallet(alice);
        vm.prank(alice);
        t.transfer(address(w), 1000);
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        o.from = address(w);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, t.tradeOrderDigest(o));
        t.mtxTrade(o, abi.encodePacked(r, s, v), _fill(600, 1200, 0));
        assertEq(t.balanceOf(address(this)), 600);
    }

    // ------------------------------------------------------------------ cancel (CTR-DEX-02)

    function test_cancel_closesForever_replayIsANoOp() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        bytes32 h = t.tradeOrderDigest(o);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, t.cancelOrderDigest(h));
        bytes memory c = abi.encodePacked(r, s, v);
        vm.expectEmit(address(t));
        emit ITradeToken.OrderCancelled(h, alice);
        vm.prank(other); // anyone submits
        t.mtxCancelOrder(o, c);
        assertEq(t.pulled(h), 1000);
        vm.recordLogs();
        t.mtxCancelOrder(o, c);
        assertEq(vm.getRecordedLogs().length, 0);
        _expect(ITradeToken.OrderClosed.selector, o, _fill(600, 1200, 0));
        (v, r, s) = vm.sign(0xBAD, t.cancelOrderDigest(h));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxCancelOrder(o, abi.encodePacked(r, s, v));
    }

    function test_invalidateNonces_strictlyIncreasing_capped() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, t.invalidateNoncesDigest(alice, 1, 2));
        vm.expectEmit(address(t));
        emit ITradeToken.NoncesInvalidated(alice, 1, 2);
        t.mtxInvalidateNonces(alice, 1, 2, abi.encodePacked(r, s, v));
        assertEq(t.minNonce(alice, 1), 2);
        _expect(ITradeToken.NonceInvalidated.selector, o, _fill(600, 1200, 0)); // nonce 1 < 2
        bytes memory again = abi.encodePacked(r, s, v);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.MinNonceNotIncreasing.selector, 2, 2));
        t.mtxInvalidateNonces(alice, 1, 2, again);
        uint256 big = 2 ** 128 + 1;
        (v, r, s) = vm.sign(ALICE_PK, t.invalidateNoncesDigest(alice, 1, big));
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.MinNonceAboveCap.selector, big));
        t.mtxInvalidateNonces(alice, 1, big, abi.encodePacked(r, s, v));
        o.batch = 2; // another lane is untouched
        _trade(o, _fill(600, 1200, 0));
    }

    // ------------------------------------------------------------------ never gasless

    function test_tradeEntriesAreNotAllowlisted() public {
        bytes4[3] memory sels = [t.mtxTrade.selector, t.mtxCancelOrder.selector, t.mtxInvalidateNonces.selector];
        (bytes4[] memory s,,) = t.mtxSelectors();
        for (uint256 i; i < sels.length; ++i) {
            for (uint256 j; j < s.length; ++j) assertTrue(s[j] != sels[i]);
        }
    }

    function _domainSep() internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS MetaToken"), keccak256("1"), block.chainid, address(t), UID_));
    }

    function _typed(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", _domainSep(), structHash));
    }

    function _orderStruct(bytes32 typeHash, ITradeToken.TradeOrder memory o) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            typeHash, o.from, o.receiveToken, o.amount, o.receiveAmount, o.minFill, o.fee, o.relayer, o.dex,
            o.destination, o.flags, o.batch, o.nonce, o.validUntil));
    }

    /// The three type strings of CTR-DEX-13 / CTR-DEX-02, hashed here, are what the library and the token digests use.
    function test_typehashesArePinned() public view {
        bytes32 order = keccak256(
            "TradeOrder(address from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,"
            "uint256 fee,address relayer,address dex,address destination,uint8 flags,uint256 batch,uint256 nonce,"
            "uint256 validUntil)");
        bytes32 cancel = keccak256("CancelOrder(bytes32 orderHash)");
        bytes32 inv = keccak256("InvalidateNonces(address from,uint256 batch,uint256 minNonce)");
        assertEq(TradeLib.TRADE_ORDER_TYPEHASH, order);
        assertEq(TradeLib.CANCEL_ORDER_TYPEHASH, cancel);
        assertEq(TradeLib.INVALIDATE_NONCES_TYPEHASH, inv);
        assertEq(order, 0xffe350903bdef674d7c33448fa7ce9b1cd306aa838f3ce1bbdd82aca46773f5d);
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        assertEq(t.tradeOrderDigest(o), _typed(_orderStruct(order, o)));
        assertEq(t.cancelOrderDigest(bytes32(uint256(5))), _typed(keccak256(abi.encode(cancel, uint256(5)))));
        assertEq(t.invalidateNoncesDigest(alice, 3, 4), _typed(keccak256(abi.encode(inv, alice, uint256(3), uint256(4)))));
    }

    // ------------------------------------------------------------------ more bounds and edges

    function test_selfOrder_fromOrDexIsTheToken() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        o.from = address(t);
        bytes32 h = t.tradeOrderDigest(o);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.SelfOrder.selector, h));
        t.mtxTrade(o, "", _fill(600, 1200, 0));
        o = _order(1000, 2000);
        o.dex = address(t);
        h = t.tradeOrderDigest(o);
        vm.prank(address(t));
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.SelfOrder.selector, h));
        t.mtxTrade(o, "", _fill(600, 1200, 0));
    }

    function test_minFill_oddAmountRoundsTheHalfUp() public {
        // half of 1001 = 500.5 -> 501; receiveAmount 2000 keeps the received side (>= 1000) out of play
        ITradeToken.TradeOrder memory o = _order(1001, 2000);
        _expect(ITradeToken.BelowMinFill.selector, o, _fill(500, 1000, 0));
        _trade(o, _fill(501, 1001, 0));
        assertEq(t.pulled(t.tradeOrderDigest(o)), 501);
    }

    function test_hugeAmount_partFillDoesNotOverflow() public {
        NoUnderlyingToken big = _none(alice, type(uint256).max, address(0));
        ITradeToken.TradeOrder memory o = _order(type(uint256).max, 1);
        uint256 sell = o.amount - o.amount / 2;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, big.tradeOrderDigest(o));
        big.mtxTrade(o, abi.encodePacked(r, s, v), _fill(sell, 1, 0));
        assertEq(big.balanceOf(address(this)), sell);
        assertEq(big.pulled(big.tradeOrderDigest(o)), sell);
    }

    function test_edges_minNonceCap_relayerIsSubmitter_validUntilIsNow() public {
        bytes32 d = t.invalidateNoncesDigest(alice, 1, 2 ** 128);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, d);
        t.mtxInvalidateNonces(alice, 1, 2 ** 128, abi.encodePacked(r, s, v));
        assertEq(t.minNonce(alice, 1), 2 ** 128);
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        o.batch = 2;
        o.relayer = relayer; // the fill's submitter is `relayer`
        o.validUntil = block.timestamp; // the last valid second
        _trade(o, _fill(600, 1200, 0));
        assertEq(t.balanceOf(address(this)), 600);
    }

    function test_replayOnAnotherChain_andCancelSignedOnAnotherToken() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        bytes memory sig = _sign(t, o);
        bytes32 h = t.tradeOrderDigest(o);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, t2.cancelOrderDigest(h));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxCancelOrder(o, abi.encodePacked(r, s, v));
        vm.chainId(block.chainid + 1);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxTrade(o, sig, _fill(600, 1200, 0));
    }

    function test_tradeEntriesThroughMtxExecuteAreNotAllowlisted() public {
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        bytes[3] memory data = [
            abi.encodeCall(t.mtxTrade, (o, _sign(t, o), _fill(600, 1200, 0))),
            abi.encodeCall(t.mtxCancelOrder, (o, _sign(t, o))),
            abi.encodeCall(t.mtxInvalidateNonces, (alice, 1, 2, _sign(t, o)))];
        for (uint256 i; i < 3; ++i) {
            MetaTxLib.MetaTransaction memory m = _call(alice, data[i], i + 1, RR);
            bytes memory sig = _signCall(ALICE_PK, address(t), m);
            vm.prank(relayer);
            vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(data[i])));
            MetaTokenBase(address(t)).mtxExecute(m, sig);
        }
    }

    function test_minFillPpm_halvingEncodesIt() public pure {
        // TradeLib.record writes ceil(x * MIN_FILL_PPM / PPM) as x - x / 2; that is only right while this holds
        assertEq(2 * TradeLib.MIN_FILL_PPM, TradeLib.PPM);
    }

    function test_tradeNamespace_pulledSlot_andBaseNamespacesUntouched() public {
        bytes32 nsTrade = 0x2c9c6bfc4d8563261a812845f5cbef41fd06d0e8f173455fd0e077ab420e2f00;
        bytes32 nsToken = 0x83083067f3d1caf66741d4eeefa9d3f4f0e5b0793677731d6fee7e67b774ac00;
        bytes32 nsMeta = 0x06b01547c739946503c06c80685cc72ae2fec5074fd602f84cd2fa888722ac00;
        bytes32[12] memory before_;
        for (uint256 i; i < 12; i++) before_[i] = vm.load(address(t), bytes32(uint256(nsToken) + i));
        bytes32 metaBefore = vm.load(address(t), nsMeta);
        ITradeToken.TradeOrder memory o = _order(1000, 2000);
        bytes32 h = t.tradeOrderDigest(o);
        _trade(o, _fill(600, 1200, 0));
        assertEq(uint256(vm.load(address(t), keccak256(abi.encode(h, nsTrade)))), 600);
        for (uint256 i; i < 12; i++) {
            assertEq(vm.load(address(t), bytes32(uint256(nsToken) + i)), before_[i], "scaas.token slot moved");
        }
        assertEq(vm.load(address(t), nsMeta), metaBefore, "scaas.metatx slot moved");
    }
}
