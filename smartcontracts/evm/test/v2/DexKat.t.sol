// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {UID_, noneInit} from "./helpers/V2Fixture.sol";

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
    NoUnderlyingToken a;
    MockERC20 usdc;
    SCaaSDex dex;

    function setUp() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        OpenFactory f = new OpenFactory(address(this), UID_);
        f.registerImplementation(IOpenFactory.TokenKind.NONE, 1,
            address(new NoUnderlyingToken(address(f), address(0), UID_, address(0), false)));
        f.registerDexImplementation(1, address(new SCaaSDex(address(f), UID_, address(0))));
        a = NoUnderlyingToken(f.createToken(IOpenFactory.TokenKind.NONE, 1,
            noneInit("A", "A", 6, 1e9, alice, address(0)), "a"));
        dex = SCaaSDex(f.createDex(1, ISCaaSDex.DexConfig(address(this), 500_000, TREASURY, false), "dex"));
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
        ISCaaSDex.Settlement[] memory ss = new ISCaaSDex.Settlement[](1);
        ss[0].ref = keccak256("scaas.kat.settlement");
        ss[0].taker = ISCaaSDex.Leg(address(a), t, _sign(ALICE_PK, a.tradeOrderDigest(t)), 500e6);
        ss[0].makers = new ISCaaSDex.Leg[](1);
        ss[0].makers[0] = ISCaaSDex.Leg(address(usdc), m, _sign(DAVE_PK, hm), 1000e6);
        bytes memory settleData = abi.encodeCall(ISCaaSDex.mtxSettle, (ss));
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
        string memory out = vm.serializeString(k, "relayer", vm.toString(RELAYER));
        if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, OUT);

        string memory onDisk = vm.readFile(OUT);
        string[] memory keys = vm.parseJsonKeys(out, "$");
        assertEq(vm.parseJsonKeys(onDisk, "$").length, keys.length);
        assertEq(keys.length, 17);
        for (uint256 i; i < keys.length; ++i) {
            assertEq(
                vm.parseJsonString(onDisk, string.concat(".", keys[i])),
                vm.parseJsonString(out, string.concat(".", keys[i])), keys[i]);
        }
    }
}
