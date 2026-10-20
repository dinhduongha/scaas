// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";
import {noneInit} from "../v2/helpers/V2Fixture.sol";
import {plainEnv} from "../helpers/Catalogue.sol";

/// KATs of the token-side DEX structs (CTR-DEX-13, CTR-DEX-02) on a real token: `trade_kat.json` holds a
/// `TradeOrder`, its `CancelOrder` and an `InvalidateNonces`, in the token domain "SCaaS MetaToken" of a
/// `NoUnderlyingToken` clone on chain 7622 with its real `chain_uid`, with the relayed `mtxCancelOrder` and
/// `mtxInvalidateNonces` calldata (both executed here). The DEX-domain `DexOrder` is `dex_order_kat.json` (DexKat.t.sol).
/// `WRITE_KAT=true forge test --match-contract TradeKatTest` rewrites the file.
contract TradeKatTest is Test {
    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    uint256 internal constant ALICE_PK = 0xA11CE;
    string internal constant OUT = "./test/vectors/trade_kat.json";
    NoUnderlyingToken internal tok;

    function setUp() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        tok = NoUnderlyingToken(Clones.clone(address(new NoUnderlyingToken(1, plainEnv(address(this), address(0), UID, address(0), false), ""))));
        tok.initialize(address(this), 1, abi.encode(noneInit("Points", "PTS", 6, 0, address(this), address(this))));
    }

    function _domainSep() internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS MetaToken"), keccak256("1"), uint256(7622), address(tok), UID));
    }

    function _sign(bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    /// The relayed calldata of the cancel and the invalidate, executed (a separate frame: stack depth).
    function _relayed(string memory k, ITradeToken.TradeOrder memory o, bytes32 h, bytes32 cancelDigest,
        bytes32 invDigest) internal
    {
        bytes memory cancelData = abi.encodeCall(ITradeToken.mtxCancelOrder, (o, _sign(cancelDigest)));
        bytes memory invData = abi.encodeCall(ITradeToken.mtxInvalidateNonces, (o.from, 7, 43, _sign(invDigest)));
        (bool ok,) = address(tok).call(cancelData);
        assertTrue(ok);
        assertEq(tok.pulled(h), o.amount);
        (ok,) = address(tok).call(invData);
        assertTrue(ok);
        assertEq(tok.minNonce(o.from, 7), 43);
        vm.serializeString(k, "cancel_calldata", vm.toString(cancelData));
        vm.serializeString(k, "invalidate_calldata", vm.toString(invData));
    }

    function test_tradeKat() public {
        ITradeToken.TradeOrder memory o = ITradeToken.TradeOrder({
            from: vm.addr(ALICE_PK), receiveToken: address(0x7E57), amount: 1_000e6, receiveAmount: 2_000e6,
            minFill: 600e6, fee: 3_000, relayer: address(0xBEEF), dex: address(0xDE7), destination: address(0),
            flags: 1, batch: 7, nonce: 42, validUntil: 1_800_000_300
        });
        bytes32 domainSep = _domainSep();
        bytes32 structHash = keccak256(abi.encode(
            TradeLib.TRADE_ORDER_TYPEHASH, o.from, o.receiveToken, o.amount, o.receiveAmount, o.minFill, o.fee,
            o.relayer, o.dex, o.destination, o.flags, o.batch, o.nonce, o.validUntil));
        bytes32 h = keccak256(abi.encodePacked(hex"1901", domainSep, structHash));
        assertEq(h, tok.tradeOrderDigest(o));
        bytes32 cancelStruct = keccak256(abi.encode(TradeLib.CANCEL_ORDER_TYPEHASH, h));
        bytes32 cancelDigest = keccak256(abi.encodePacked(hex"1901", domainSep, cancelStruct));
        assertEq(cancelDigest, tok.cancelOrderDigest(h));
        bytes32 invStruct = keccak256(abi.encode(TradeLib.INVALIDATE_NONCES_TYPEHASH, o.from, uint256(7), uint256(43)));
        bytes32 invDigest = keccak256(abi.encodePacked(hex"1901", domainSep, invStruct));
        assertEq(invDigest, tok.invalidateNoncesDigest(o.from, 7, 43));

        string memory k = "trade";
        vm.serializeString(k, "domain_name", "SCaaS MetaToken");
        vm.serializeString(k, "domain_version", "1");
        vm.serializeString(k, "chain_id", "7622");
        vm.serializeString(k, "verifying_contract", vm.toString(address(tok)));
        vm.serializeString(k, "salt", vm.toString(UID));
        vm.serializeString(k, "domain_separator", vm.toString(domainSep));
        vm.serializeString(k, "signer", vm.toString(o.from));
        vm.serializeString(k, "order_abi", vm.toString(abi.encode(o)));
        vm.serializeString(k, "trade_order_type_hash", vm.toString(TradeLib.TRADE_ORDER_TYPEHASH));
        vm.serializeString(k, "trade_order_struct_hash", vm.toString(structHash));
        vm.serializeString(k, "order_hash", vm.toString(h));
        vm.serializeString(k, "order_signature", vm.toString(_sign(h)));
        vm.serializeString(k, "cancel_type_hash", vm.toString(TradeLib.CANCEL_ORDER_TYPEHASH));
        vm.serializeString(k, "cancel_digest", vm.toString(cancelDigest));
        vm.serializeString(k, "cancel_signature", vm.toString(_sign(cancelDigest)));
        vm.serializeString(k, "invalidate_type_hash", vm.toString(TradeLib.INVALIDATE_NONCES_TYPEHASH));
        vm.serializeString(k, "invalidate_batch", "7");
        vm.serializeString(k, "invalidate_min_nonce", "43");
        vm.serializeString(k, "invalidate_digest", vm.toString(invDigest));
        _relayed(k, o, h, cancelDigest, invDigest);
        string memory out = vm.serializeString(k, "invalidate_signature", vm.toString(_sign(invDigest)));
        if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, OUT);

        // every field of the file on disk is the freshly built one (and no field is missing or extra)
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
