// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {stdJson} from "forge-std/StdJson.sol";
import {V2Fixture, BaseHarness} from "./helpers/V2Fixture.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {SingleUnderlyingToken} from "../../src/metatx/SingleUnderlyingToken.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// @title KAT v2 (TW2 §10.4): `test/vectors/metatx_v2_kat.json`.
/// @notice Vector gốc = ĐÚNG struct của `metatx_kat.json` v1 (cùng `struct_hash`), digest mới vì domain version
///         "2". Thêm `mtxpay` (lane `payLane(payId)`, nonce 0) và `mtxunwrap` (T2). Python (Odoo `lib/eip712.py`)
///         và Rust (node) đọc cùng file; đổi typehash, `canon` hay domain là họ đỏ.
contract BaseKatTest is V2Fixture {
    using MetaTxLib for MetaTxLib.MetaTransaction;
    using stdJson for string;

    uint256 constant PK = 0xA11CE;

    function _domainSep(address vc) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("SCaaS MetaToken"), keccak256("2"), uint256(9000), vc));
    }

    function _vector(string memory k, address vc, MetaTxLib.MetaTransaction memory m)
        internal returns (string memory out)
    {
        bytes32 structHash = m.hashStruct();
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", _domainSep(vc), structHash));
        assertEq(digest, IERC20MetaTx(vc).metaTxDigest(m));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, digest);
        vm.serializeString(k, "domain_name", "SCaaS MetaToken");
        vm.serializeString(k, "domain_version", "2");
        vm.serializeString(k, "chain_id", "9000");
        vm.serializeString(k, "verifying_contract", vm.toString(vc));
        vm.serializeString(k, "from", vm.toString(m.from));
        vm.serializeString(k, "to", vm.toString(m.to));
        vm.serializeString(k, "value", vm.toString(m.value));
        vm.serializeString(k, "data", vm.toString(m.data));
        vm.serializeString(k, "batch", vm.toString(m.batch));
        vm.serializeString(k, "nonce", vm.toString(m.nonce));
        vm.serializeString(k, "valid_until", vm.toString(m.validUntil));
        vm.serializeString(k, "mode", vm.toString(uint256(m.mode)));
        vm.serializeString(k, "relayer", vm.toString(m.relayer));
        vm.serializeString(k, "fee", vm.toString(m.fee));
        vm.serializeString(k, "fee_recipient", vm.toString(m.feeRecipient));
        vm.serializeString(k, "struct_hash", vm.toString(structHash));
        vm.serializeString(k, "digest", vm.toString(digest));
        vm.serializeString(k, "signer", vm.toString(m.from));
        out = vm.serializeString(k, "signature", vm.toString(abi.encodePacked(r, s, v)));
    }

    function test_writeV2Kat() public {
        vm.chainId(9000);
        vm.warp(1_800_000_000);
        BaseHarness tok = _harness(address(this), 0);
        address from = vm.addr(PK);
        tok.mint(from, 1_000e6);

        // 1. the v1 struct, unchanged
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: from, to: address(0x5409), value: 250e6,
            data: _payData(bytes32(uint256(0x42))), batch: uint256(keccak256("scaas.pay.lane")),
            nonce: 0, validUntil: 1_800_000_300, mode: RR, relayer: relayer, fee: 0, feeRecipient: address(0xFEE)
        });
        string memory v1 = vm.readFile("./test/vectors/metatx_kat.json");
        assertEq(m.hashStruct(), v1.readBytes32(".struct_hash"));
        string memory base = _vector("v2kat", address(tok), m);

        // 2. mtxPay: lane on chain, nonce 0, a bound percent fee
        bytes32 payId = bytes32(uint256(0x42));
        MetaTxLib.MetaTransaction memory p = MetaTxLib.MetaTransaction({
            from: from, to: address(0x5409), value: 250e6, data: _payData(payId), batch: tok.payLane(payId),
            nonce: 0, validUntil: 1_800_000_300, mode: RR | RF | PCT, relayer: relayer, fee: 2_500,
            feeRecipient: address(0xFEE)
        });
        string memory pj = _vector("mtxpay", address(tok), p);
        pj = vm.serializeString("mtxpay", "pay_id", vm.toString(payId));
        vm.expectEmit(address(tok));
        emit IERC20MetaTx.MetaTransactionExecuted(from, relayer, p.batch, 0, tok.metaTxDigest(p), address(0xFEE), 625_000);
        vm.prank(relayer);
        tok.mtxPay(from, p.to, p.value, payId, p.validUntil, p.mode, relayer, p.fee, p.feeRecipient,
            vm.parseJsonBytes(pj, ".signature"));

        base = vm.serializeString("v2kat", "mtxpay", pj);

        // 3. mtxUnwrap on a 1:1 single-underlying clone (R148)
        MockERC20 u = new MockERC20("USD Coin", "USDC", 6);
        SingleUnderlyingToken w = _single(address(u), 6, 1, 1, _fixedRate());
        u.mint(from, 100e6);
        vm.startPrank(from);
        u.approve(address(w), 100e6);
        w.wrap(100e6);
        vm.stopPrank();
        MetaTxLib.MetaTransaction memory x = MetaTxLib.MetaTransaction({
            from: from, to: address(0x5409), value: 40e6, data: _unwrapData(address(u), address(0x5409), 40e6),
            batch: 7, nonce: 0, validUntil: 1_800_000_300, mode: RR, relayer: relayer, fee: 0, feeRecipient: address(0)
        });
        string memory uj = _vector("mtxunwrap", address(w), x);
        vm.serializeString("mtxunwrap", "underlying", vm.toString(address(u)));
        uj = vm.serializeString("mtxunwrap", "min_out", vm.toString(uint256(40e6)));
        vm.expectEmit(address(w));
        emit IERC20MetaTx.MetaTransactionExecuted(from, relayer, 7, 0, w.metaTxDigest(x), relayer, 0);
        vm.prank(relayer);
        w.mtxUnwrap(from, address(u), 40e6, x.to, 40e6, 7, 0, x.validUntil, RR, relayer,
            vm.parseJsonBytes(uj, ".signature"));
        assertEq(u.balanceOf(x.to), 40e6);
        base = vm.serializeString("v2kat", "mtxunwrap", uj);
        vm.writeJson(base, "./test/vectors/metatx_v2_kat.json");
    }
}
