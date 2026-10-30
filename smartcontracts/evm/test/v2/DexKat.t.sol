// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {DexLegs} from "../helpers/DexLegs.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {UID_, normalInit} from "./helpers/V2Fixture.sol";
import {plainEnv, Catalogue} from "../helpers/Catalogue.sol";

/// KAT of the DEX side (CTR-DEX-16, -18, -02) on a real `SCaaSDex` clone on chain 7622 with its real `chain_uid`:
/// `dex_order_kat.json` holds an outside-token maker order as a `DexOrder` in the DEX domain "SCaaS Dex", a SCaaS taker
/// order in its token's domain, the `mtxSettle` calldata of one settlement between them, and the DEX-side
/// `mtxCancelOrders` / `mtxInvalidateNonces` digests and calldata. Every calldata is executed here, so the node
/// (`dex.rs`) and clientkeys encode what the contracts accept, byte for byte.
/// `WRITE_KAT=true forge test --match-contract DexKatTest` rewrites the file.
contract DexKatTest is Test {
    uint256 constant ALICE_PK = 0xA11CE;
    uint256 constant DAVE_PK = 0xDA7E;
    address constant RELAYER = address(0xBEEF);
    address constant TREASURY = address(0x7EA5);
    string constant OUT = "./test/vectors/dex_order_kat.json";
    address alice = vm.addr(ALICE_PK);
    address dave = vm.addr(DAVE_PK);
    NormalToken a;
    MockERC20 usdc;
    SCaaSDex dex;

    function setUp() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        OpenFactory f = new OpenFactory(address(this), UID_, 0);
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, address(0), address(0), false);
        Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0));
        a = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(normalInit("A", "A", 6, 1e9, alice, address(0))), "a"));
        dex = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(address(this), 500_000, TREASURY, false)), "dex"));
        usdc = new MockERC20("USD Coin", "USDC", 6);
        dex.setMarket(address(a), address(usdc), true);
        usdc.mint(dave, 1e9);
        address p = dex.puller();
        vm.prank(dave);
        usdc.approve(p, type(uint256).max);
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _domainSep() internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS Dex"), keccak256("1"), uint256(7622), address(dex), UID_));
    }

    function _tradeStruct(ITradeToken.TradeOrder memory o) internal pure returns (bytes32) {
        return keccak256(abi.encode(TradeLib.TRADE_ORDER_TYPEHASH, o.from, o.receiveToken, o.amount, o.receiveAmount,
            o.minFill, o.fee, o.relayer, o.dex, o.destination, o.flags, o.batch, o.nonce, o.validUntil));
    }

    /// Dave (maker, outside token) sells 2000 USDC for >= 1000 A; Alice (taker, SCaaS) sells 500 A for >= 1000 USDC.
    function _orders() internal view returns (ITradeToken.TradeOrder memory m, ITradeToken.TradeOrder memory t) {
        m = ITradeToken.TradeOrder({
            from: dave, receiveToken: address(a), amount: 2000e6, receiveAmount: 1000e6, minFill: 0, fee: 3_000,
            relayer: RELAYER, dex: address(dex), destination: address(0), flags: 0, batch: 1, nonce: 3,
            validUntil: 1_800_000_300
        });
        t = ITradeToken.TradeOrder({
            from: alice, receiveToken: address(usdc), amount: 500e6, receiveAmount: 1000e6, minFill: 0, fee: 3_000,
            relayer: RELAYER, dex: address(dex), destination: address(0x5E11), flags: 1, batch: 2, nonce: 9,
            validUntil: 1_800_000_300
        });
    }

    /// One settlement: Dave fills half (1000 USDC, receives ceil(1000 * 1000 / 2000) = 500 A), Alice all of hers.
    function _settle(string memory k, ITradeToken.TradeOrder memory m, ITradeToken.TradeOrder memory t, bytes32 hm)
        internal
    {
        DexLegs.Settlement[] memory ss = new DexLegs.Settlement[](1);
        ss[0].ref = keccak256("scaas.kat.settlement");
        ss[0].taker = DexLegs.Leg(address(a), t, _sign(ALICE_PK, a.tradeOrderDigest(t)), 500e6);
        ss[0].makers = new DexLegs.Leg[](1);
        ss[0].makers[0] = DexLegs.Leg(address(usdc), m, _sign(DAVE_PK, hm), 1000e6);
        bytes memory settleData = abi.encodeCall(ISCaaSDex.mtxSettle, (DexLegs.wire(ss)));
        vm.prank(RELAYER);
        (bool ok, bytes memory ret) = address(dex).call(settleData);   // the vectors really execute
        assertTrue(ok);
        assertTrue(abi.decode(ret, (bool[]))[0]);
        assertEq(usdc.balanceOf(address(0x5E11)), 1000e6 - 3e6);         // fee ceil(1000e6 * 3000 / 1e6)
        assertEq(a.balanceOf(dave), 500e6 - 1.5e6);
        assertEq(dex.pulled(hm), 1000e6);
        vm.serializeString(k, "settle_calldata", vm.toString(settleData));
    }

    /// The DEX-side cancel closes Dave's remainder; the DEX-side invalidate raises his lane 1 to 5.
    function _cancels(string memory k, ITradeToken.TradeOrder memory m, bytes32 hm, bytes32 domainSep) internal {
        bytes32 cancelDigest = dex.cancelOrderDigest(hm);
        assertEq(cancelDigest, keccak256(abi.encodePacked(hex"1901", domainSep,
            keccak256(abi.encode(TradeLib.CANCEL_ORDER_TYPEHASH, hm)))));
        ISCaaSDex.DexOrder[] memory os = new ISCaaSDex.DexOrder[](1);
        os[0] = ISCaaSDex.DexOrder(address(usdc), m);
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(DAVE_PK, cancelDigest);
        bytes memory cancelData = abi.encodeCall(ISCaaSDex.mtxCancelOrders, (os, sigs));
        (bool ok,) = address(dex).call(cancelData);
        assertTrue(ok);
        assertEq(dex.pulled(hm), m.amount);
        bytes32 invDigest = dex.invalidateNoncesDigest(dave, 1, 5);
        assertEq(invDigest, keccak256(abi.encodePacked(hex"1901", domainSep,
            keccak256(abi.encode(TradeLib.INVALIDATE_NONCES_TYPEHASH, dave, uint256(1), uint256(5))))));
        bytes memory invData = abi.encodeCall(ISCaaSDex.mtxInvalidateNonces, (dave, 1, 5, _sign(DAVE_PK, invDigest)));
        (ok,) = address(dex).call(invData);
        assertTrue(ok);
        assertEq(dex.minNonce(dave, 1), 5);
        vm.serializeString(k, "cancel_digest", vm.toString(cancelDigest));
        vm.serializeString(k, "cancel_orders_calldata", vm.toString(cancelData));
        vm.serializeString(k, "invalidate_digest", vm.toString(invDigest));
        vm.serializeString(k, "invalidate_calldata", vm.toString(invData));
    }

    /// The fixed exchange plan: the two settlement orders as tagged `ExchangeLeg`s (shape 0), one extra token.
    function _plan(ITradeToken.TradeOrder memory m, ITradeToken.TradeOrder memory t, bytes32 hm)
        internal view returns (ISCaaSDex.ExchangePlan memory p)
    {
        p.ref = keccak256("scaas.kat.exchange");
        p.legs = new ISCaaSDex.ExchangeLeg[](2);
        p.legs[0] = ISCaaSDex.ExchangeLeg(address(usdc), 0, abi.encode(m), _sign(DAVE_PK, hm), 1000e6, 500e6);
        p.legs[1] = ISCaaSDex.ExchangeLeg(address(a), 0, abi.encode(t), _sign(ALICE_PK, a.tradeOrderDigest(t)), 500e6, 1000e6);
        p.extraTokens = new address[](1);
        p.extraTokens[0] = address(0xE7A);
    }

    function _interactions() internal pure returns (ISCaaSDex.Interaction[] memory xs) {
        xs = new ISCaaSDex.Interaction[](1);
        xs[0] = ISCaaSDex.Interaction(address(0xA11), hex"deadbeef");
    }

    /// `mtxExchange` / `mtxExchangeVia` / `mtxExchangeBatch` calldata for one fixed plan (review C6-2): the two
    /// settlement orders as tagged `ExchangeLeg`s (shape 0), one extra token, one interaction. ENCODING ONLY (not
    /// executed here: the exchange paths run in the exchange tests); the node pins its call table and its ABI structs
    /// against these bytes.
    function _exchange(string memory k, ITradeToken.TradeOrder memory m, ITradeToken.TradeOrder memory t, bytes32 hm)
        internal
    {
        ISCaaSDex.ExchangePlan memory p = _plan(m, t, hm);
        vm.serializeString(k, "exchange_calldata", vm.toString(abi.encodeCall(ISCaaSDex.mtxExchange, (p, _interactions()))));
        vm.serializeString(k, "exchange_via_calldata",
            vm.toString(abi.encodeCall(ISCaaSDex.mtxExchangeVia, (p, address(0xE7EC), hex"c0ffee"))));
        ISCaaSDex.ExchangePlan[] memory ps = new ISCaaSDex.ExchangePlan[](1);
        ps[0] = p;
        ISCaaSDex.Interaction[][] memory xss = new ISCaaSDex.Interaction[][](1);
        xss[0] = _interactions();
        vm.serializeString(k, "exchange_batch_calldata", vm.toString(abi.encodeCall(ISCaaSDex.mtxExchangeBatch, (ps, xss))));
    }

    /// `mtxHybrid` / `mtxHybridVia` calldata for one fixed plan: Alice's order as the taker (shape 0), Dave's as the
    /// one maker, 100 of the taker's sell routed outside for at least 200, one extra token. ENCODING ONLY, as `_exchange`.
    function _hybrid(string memory k, ITradeToken.TradeOrder memory m, ITradeToken.TradeOrder memory t, bytes32 hm)
        internal
    {
        ISCaaSDex.HybridPlan memory p;
        p.ref = keccak256("scaas.kat.hybrid");
        p.taker = ISCaaSDex.Leg(address(a), 0, abi.encode(t), _sign(ALICE_PK, a.tradeOrderDigest(t)), 500e6);
        p.makers = new ISCaaSDex.Leg[](1);
        p.makers[0] = ISCaaSDex.Leg(address(usdc), 0, abi.encode(m), _sign(DAVE_PK, hm), 1000e6);
        p.outsideSell = 100e6;
        p.outsideFloor = 200e6;
        p.extraTokens = new address[](1);
        p.extraTokens[0] = address(0xE7A);
        vm.serializeString(k, "hybrid_calldata", vm.toString(abi.encodeCall(ISCaaSDex.mtxHybrid, (p, _interactions()))));
        vm.serializeString(k, "hybrid_via_calldata",
            vm.toString(abi.encodeCall(ISCaaSDex.mtxHybridVia, (p, address(0xE7EC), hex"c0ffee"))));
    }

    function tail(bytes calldata d) external pure returns (bytes memory) {
        return d[4:];
    }

    function _kat(string memory key) internal view returns (bytes memory) {
        return vm.parseBytes(vm.parseJsonString(vm.readFile(OUT), string.concat(".", key)));
    }

    function _rtHybrid() internal view {
        bytes memory c = _kat("hybrid_calldata");
        assertEq(bytes4(c), ISCaaSDex.mtxHybrid.selector);
        (ISCaaSDex.HybridPlan memory p, ISCaaSDex.Interaction[] memory xs) =
            abi.decode(this.tail(c), (ISCaaSDex.HybridPlan, ISCaaSDex.Interaction[]));
        assertEq(abi.encodeCall(ISCaaSDex.mtxHybrid, (p, xs)), c);
    }

    function _rtHybridVia() internal view {
        bytes memory c = _kat("hybrid_via_calldata");
        assertEq(bytes4(c), ISCaaSDex.mtxHybridVia.selector);
        (ISCaaSDex.HybridPlan memory p, address ex, bytes memory data) =
            abi.decode(this.tail(c), (ISCaaSDex.HybridPlan, address, bytes));
        assertEq(abi.encodeCall(ISCaaSDex.mtxHybridVia, (p, ex, data)), c);
    }

    /// Same selector as `ISCaaSDex.mtxExchangeBatch`, so the calldata is decoded by the compiler's calldata decoder
    /// (the memory `abi.decode` of this nested shape is stack-too-deep without `via_ir`) and re-encoded.
    function mtxExchangeBatch(ISCaaSDex.ExchangePlan[] calldata ps, ISCaaSDex.Interaction[][] calldata xs)
        external pure returns (bytes memory)
    {
        return abi.encodeCall(ISCaaSDex.mtxExchangeBatch, (ps, xs));
    }

    function _rtBatch() internal view {
        bytes memory c = _kat("exchange_batch_calldata");
        assertEq(bytes4(c), ISCaaSDex.mtxExchangeBatch.selector);
        (bool ok, bytes memory r) = address(this).staticcall(c);
        assertTrue(ok);
        assertEq(abi.decode(r, (bytes)), c);
    }

    /// The three encoding-only entries decode and re-encode to the same bytes, under `ISCaaSDex`'s selectors.
    function test_dexKat_newEntriesRoundTrip() public view {
        _rtHybrid();
        _rtHybridVia();
        _rtBatch();
    }

    function test_dexKat() public {
        (ITradeToken.TradeOrder memory m, ITradeToken.TradeOrder memory t) = _orders();
        bytes32 domainSep = _domainSep();
        bytes32 dexOrderStruct = keccak256(abi.encode(
            keccak256("DexOrder(address sellToken,TradeOrder order)TradeOrder(address from,address receiveToken,"
                "uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,"
                "address destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)"),
            address(usdc), _tradeStruct(m)));
        bytes32 hm = keccak256(abi.encodePacked(hex"1901", domainSep, dexOrderStruct));
        assertEq(hm, dex.dexOrderDigest(address(usdc), m));

        string memory k = "dex";
        vm.serializeString(k, "chain_id", "7622");
        vm.serializeString(k, "salt", vm.toString(UID_));
        vm.serializeString(k, "dex", vm.toString(address(dex)));
        vm.serializeString(k, "dex_domain_separator", vm.toString(domainSep));
        vm.serializeString(k, "token", vm.toString(address(a)));
        vm.serializeString(k, "outside_token", vm.toString(address(usdc)));
        vm.serializeString(k, "maker_order_abi", vm.toString(abi.encode(m)));
        vm.serializeString(k, "dex_order_struct_hash", vm.toString(dexOrderStruct));
        vm.serializeString(k, "dex_order_hash", vm.toString(hm));
        vm.serializeString(k, "taker_order_abi", vm.toString(abi.encode(t)));
        vm.serializeString(k, "taker_order_hash", vm.toString(a.tradeOrderDigest(t)));
        _settle(k, m, t, hm);
        _cancels(k, m, hm, domainSep);
        _exchange(k, m, t, hm);
        _hybrid(k, m, t, hm);
        string memory out = vm.serializeString(k, "relayer", vm.toString(RELAYER));
        if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, OUT);

        string memory onDisk = vm.readFile(OUT);
        string[] memory keys = vm.parseJsonKeys(out, "$");
        assertEq(vm.parseJsonKeys(onDisk, "$").length, keys.length);
        assertEq(keys.length, 22);
        for (uint256 i; i < keys.length; ++i) {
            assertEq(
                vm.parseJsonString(onDisk, string.concat(".", keys[i])),
                vm.parseJsonString(out, string.concat(".", keys[i])), keys[i]);
        }
    }
}
