// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {plainEnv} from "../helpers/Catalogue.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

/// KATs of the token-side DEX structs (CTR-DEX-13, CTR-DEX-02, CTR-DEX-25) on a real token. ua-mtx-merge T6 (R12,
/// R38): a SCaaS token's order is a `UATradeOrder`, so this suite reads the native signer's row of
/// `smartcontracts/vectors/ua/uatrade_kat.json` (written by `clients/clientkeys/scripts/ua-sig-vectors.mjs`, rows
/// unchanged) instead of the address `trade_kat.json` (now `test/vectors/legacy/ua-mtx-merge/`): the struct hash, the
/// order digest, the `CancelUAOrder` and `UAInvalidateNonces` digests recomputed here from the type strings and the
/// salted domain, and the relayed merged `mtxCancelOrder` / `mtxInvalidateNonces` executed on a `NormalToken` clone at
/// the vector's token address with no registry (a native signer needs none, C). The DEX-domain `DexOrder` is `dex_order_kat.json`
/// (DexKat.t.sol).
contract TradeKatTest is Test {
    string internal vj;
    NormalToken internal tok;

    function setUp() public {
        vj = vm.readFile("../vectors/ua/uatrade_kat.json");
        vm.chainId(vm.parseJsonUint(vj, ".chainId"));
        vm.warp(1_800_000_000);
        address at = vm.parseJsonAddress(vj, ".tokenA");
        // no registry: a native signer's row needs none (C), and the domain does not name it
        address impl = address(new NormalToken(address(this), ""));
        vm.etch(at, EnvKit.runtime(impl, EnvKit.env(vm.parseJsonBytes32(vj, ".chainUid"), address(0), address(0), false)));
        tok = NormalToken(at);
        tok.initialize(nid(address(this)), 1, abi.encode(normalInit("T", "T", 6, 0, address(this), address(this))));
    }

    function _order(string memory p) internal view returns (ITradeToken.UATradeOrder memory o) {
        o.from = vm.parseJsonBytes32(vj, string.concat(p, "from"));
        o.receiveToken = vm.parseJsonAddress(vj, string.concat(p, "receiveToken"));
        o.amount = vm.parseJsonUint(vj, string.concat(p, "amount"));
        o.receiveAmount = vm.parseJsonUint(vj, string.concat(p, "receiveAmount"));
        o.minFill = vm.parseJsonUint(vj, string.concat(p, "minFill"));
        o.fee = vm.parseJsonUint(vj, string.concat(p, "fee"));
        o.relayer = vm.parseJsonAddress(vj, string.concat(p, "relayer"));
        o.dex = vm.parseJsonAddress(vj, string.concat(p, "dex"));
        o.destination = vm.parseJsonBytes32(vj, string.concat(p, "destination"));
        o.flags = uint8(vm.parseJsonUint(vj, string.concat(p, "flags")));
        o.batch = vm.parseJsonUint(vj, string.concat(p, "batch"));
        o.nonce = vm.parseJsonUint(vj, string.concat(p, "nonce"));
        o.validUntil = vm.parseJsonUint(vj, string.concat(p, "validUntil"));
    }

    function _sig(string memory key) internal view returns (IUARegistry.UASig memory a) {
        a.signature = vm.parseJsonBytes(vj, string.concat(".rows[0].", key));
    }

    function test_tradeKat() public {
        assertEq(vm.parseJsonString(vj, ".rows[0].name"), "native");
        ITradeToken.UATradeOrder memory o = _order(".rows[0].order.message.");
        bytes32 domainSep = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS MetaToken"), keccak256("1"), block.chainid, address(tok), vm.parseJsonBytes32(vj, ".chainUid")));
        assertEq(domainSep, vm.parseJsonBytes32(vj, ".domainSeparatorA"));
        bytes32 structHash = keccak256(abi.encode(
            TradeLib.UA_TRADE_ORDER_TYPEHASH, o.from, o.receiveToken, o.amount, o.receiveAmount, o.minFill, o.fee,
            o.relayer, o.dex, o.destination, o.flags, o.batch, o.nonce, o.validUntil));
        assertEq(structHash, vm.parseJsonBytes32(vj, ".rows[0].structHash"));
        bytes32 h = keccak256(abi.encodePacked(hex"1901", domainSep, structHash));
        assertEq(h, vm.parseJsonBytes32(vj, ".rows[0].orderHash"));
        assertEq(h, tok.tradeOrderDigest(o));
        bytes32 cancelDigest = keccak256(abi.encodePacked(hex"1901", domainSep,
            keccak256(abi.encode(TradeLib.CANCEL_UA_ORDER_TYPEHASH, structHash))));
        assertEq(cancelDigest, vm.parseJsonBytes32(vj, ".rows[0].cancelDigest"));
        assertEq(cancelDigest, tok.cancelOrderDigest(o));
        bytes32 invDigest = keccak256(abi.encodePacked(hex"1901", domainSep,
            keccak256(abi.encode(TradeLib.UA_INVALIDATE_NONCES_TYPEHASH, o.from, uint256(1), uint256(5)))));
        assertEq(invDigest, vm.parseJsonBytes32(vj, ".rows[0].invalidateDigest"));
        assertEq(invDigest, tok.invalidateNoncesDigest(o.from, 1, 5));

        // the relayed merged entries, executed (anyone submits a cancel, CTR-DEX-02)
        bytes memory cancelData = abi.encodeCall(ITradeToken.mtxCancelOrder, (o, _sig("cancelAuth")));
        bytes memory invData = abi.encodeCall(ITradeToken.mtxInvalidateNonces, (o.from, 1, 5, _sig("invalidateAuth")));
        assertEq(bytes4(cancelData), bytes4(0x8f50a845));
        assertEq(bytes4(invData), bytes4(0xcf2d8d70));
        (bool ok,) = address(tok).call(cancelData);
        assertTrue(ok);
        assertEq(tok.pulled(h), o.amount);
        (ok,) = address(tok).call(invData);
        assertTrue(ok);
        assertEq(tok.minNonce(o.from, 1), 5);
    }
}
