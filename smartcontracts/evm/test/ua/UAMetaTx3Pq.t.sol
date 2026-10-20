// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UAMldsaVerifier} from "../../src/ua/MlDsa.sol";
import {UAFndsaVerifier} from "../../src/ua/FnDsa.sol";
import {UASlhdsaVerifier} from "../../src/ua/SlhDsa.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {noneInit} from "../v2/helpers/V2Fixture.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {plainEnv} from "../helpers/Catalogue.sol";

/// The UA ledger with PQ signers (P6c; accounts.md CTR-UA-26, §1.16): pq_signatures.json's `metatx3` rows — the
/// metatx3.json structs and domain, one row per PQ kind — on a `NONE` clone at the vector token address, context A,
/// the real PQ verifiers (ML-DSA on its cached expanded key). Every digest is recomputed by the token, every auth passes
/// `requireAuthorized` under `metatx`, every `UAMetaTransfer` row executes. Gas of `uaExecuteTransfer` per kind is logged.
/// UA-5a (metatx.md, the `uaPayReceiverFee` paragraph): receiver-pays with an `mldsa65` payer and an `mldsa65` payee
/// (two PQ verifies) fits one 16,777,216-gas transaction (EIP-7825), intrinsic and calldata included.
contract UAMetaTx3PqTest is UARegistryBase {
    NoUnderlyingToken internal tok;

    function _pj() internal view returns (string memory) {
        return vm.readFile("../vectors/ua/pq_signatures.json");
    }

    function setUp() public override {
        super.setUp();
        string memory pj = _pj();
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](4);
        c[0] = UARegistry.KindConfig(0x0130, address(new UAMldsaVerifier(0x0130, address(0), "", "")), 4_250_000);
        c[1] = UARegistry.KindConfig(0x0131, address(new UAMldsaVerifier(0x0131, address(0), "", "")), 5_950_000);
        c[2] = UARegistry.KindConfig(0x0132, address(new UAFndsaVerifier()), 2_500_000);
        c[3] = UARegistry.KindConfig(0x0133, address(new UASlhdsaVerifier()), 1_400_000);
        reg = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, c);
        for (uint256 i; i < 4; ++i) {
            string memory k = string.concat(".kinds[", vm.toString(i), "].");
            uint16 kind = uint16(vm.parseJsonUint(pj, string.concat(k, "kind")));
            bytes memory pk = vm.parseJsonBytes(pj, string.concat(k, "keyData"));
            for (uint256 p; kind <= 0x0131 && p < (kind == 0x0130 ? 1 : 2); ++p) reg.cacheExpandedKey(kind, pk, p);
            reg.register(kind, pk, vm.parseJsonBytes(pj, string.concat(k, "pop.sig")), 0, "");
        }
        // the receiverFee payee: mldsa65 index 1 (extraKeys[0]), its expanded key cached as the payer's
        bytes memory pk1 = vm.parseJsonBytes(pj, ".extraKeys[0].keyData");
        for (uint256 p; p < 2; ++p) reg.cacheExpandedKey(0x0131, pk1, p);
        reg.register(0x0131, pk1, vm.parseJsonBytes(pj, ".extraKeys[0].pop.sig"), 0, "");
        address token = vm.parseJsonAddress(pj, ".metatx3.token");
        address impl = address(new NoUnderlyingToken(1, plainEnv(address(this), address(0), chainUidA, REG_A, false), ""));
        vm.etch(token, abi.encodePacked(hex"363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91602b57fd5bf3"));
        tok = NoUnderlyingToken(token);
        tok.initialize(address(this), 1, abi.encode(noneInit("Points", "PTS", 6, 0, address(0), address(this))));
        vm.warp(1_800_000_000);
    }

    function _f(string memory row, string memory field) internal pure returns (string memory) {
        return string.concat(row, "typedData.message.", field);
    }

    function _call(string memory pj, string memory r) internal pure returns (MetaTxLib.UAMetaTransaction memory m) {
        m.from = vm.parseJsonBytes32(pj, _f(r, "from"));
        m.data = vm.parseJsonBytes(pj, _f(r, "data"));
        m.batch = vm.parseJsonUint(pj, _f(r, "batch"));
        m.nonce = vm.parseJsonUint(pj, _f(r, "nonce"));
        m.validUntil = vm.parseJsonUint(pj, _f(r, "validUntil"));
        m.mode = uint32(vm.parseJsonUint(pj, _f(r, "mode")));
        m.relayer = vm.parseJsonAddress(pj, _f(r, "relayer"));
        m.fee = vm.parseJsonUint(pj, _f(r, "fee"));
        m.feeRecipient = vm.parseJsonAddress(pj, _f(r, "feeRecipient"));
    }

    function _transfer(string memory pj, string memory r) internal pure returns (MetaTxLib.UAMetaTransfer memory) {
        return _transferAt(pj, string.concat(r, "typedData.message."));
    }

    /// A `UAMetaTransfer` from the message at path prefix `p`.
    function _transferAt(string memory pj, string memory p) internal pure returns (MetaTxLib.UAMetaTransfer memory t) {
        t.from = vm.parseJsonBytes32(pj, string.concat(p, "from"));
        t.to = vm.parseJsonBytes32(pj, string.concat(p, "to"));
        t.value = vm.parseJsonUint(pj, string.concat(p, "value"));
        t.entryRef = vm.parseJsonBytes32(pj, string.concat(p, "entryRef"));
        t.batch = vm.parseJsonUint(pj, string.concat(p, "batch"));
        t.nonce = vm.parseJsonUint(pj, string.concat(p, "nonce"));
        t.validUntil = vm.parseJsonUint(pj, string.concat(p, "validUntil"));
        t.mode = uint32(vm.parseJsonUint(pj, string.concat(p, "mode")));
        t.relayer = vm.parseJsonAddress(pj, string.concat(p, "relayer"));
        t.fee = vm.parseJsonUint(pj, string.concat(p, "fee"));
        t.feeRecipient = vm.parseJsonAddress(pj, string.concat(p, "feeRecipient"));
    }

    /// `UAMetaTransaction` rows: digest and auth (the `unwrap` itself is not on the `NONE` kind's allowlist).
    function test_callRows() public view {
        string memory pj = _pj();
        uint256 n;
        for (uint256 i; vm.keyExistsJson(pj, string.concat(".metatx3.call[", vm.toString(i), "]")); ++i) {
            string memory r = string.concat(".metatx3.call[", vm.toString(i), "].");
            MetaTxLib.UAMetaTransaction memory m = _call(pj, r);
            bytes32 digest = vm.parseJsonBytes32(pj, string.concat(r, "digest"));
            assertEq(MetaTxLib.hashStruct(m), vm.parseJsonBytes32(pj, string.concat(r, "structHash")));
            assertEq(tok.uaDigest(m), digest);
            reg.requireAuthorized(m.from, UAKinds.PURPOSE_METATX, digest, vm.parseJsonBytes(pj, string.concat(r, "auth")));
            ++n;
        }
        assertEq(n, 4);
    }

    /// `UAMetaTransfer` rows: a payment with a FIXED fee from each PQ UA to a native payee, executed.
    function test_transferRows() public {
        string memory pj = _pj();
        uint256 n;
        for (uint256 i; vm.keyExistsJson(pj, string.concat(".metatx3.transfer[", vm.toString(i), "]")); ++i) {
            string memory r = string.concat(".metatx3.transfer[", vm.toString(i), "].");
            MetaTxLib.UAMetaTransfer memory t = _transfer(pj, r);
            bytes32 digest = vm.parseJsonBytes32(pj, string.concat(r, "digest"));
            assertEq(MetaTxLib.hashStruct(t), vm.parseJsonBytes32(pj, string.concat(r, "structHash")));
            assertEq(tok.uaTransferDigest(t), digest);
            bytes memory auth = vm.parseJsonBytes(pj, string.concat(r, "auth"));
            tok.mint(address(this), t.value + t.fee);
            tok.transferToUA(t.from, t.value + t.fee);
            vm.prank(t.relayer);
            uint256 g = gasleft();
            tok.uaExecuteTransfer(t, auth);
            g -= gasleft();
            emit log_named_uint(string.concat("uaExecuteTransfer ", vm.parseJsonString(pj, string.concat(r, "name"))), g);
            assertEq(tok.balanceOfUA(t.from), 0);
            ++n;
        }
        assertEq(n, 4);
        assertEq(tok.balanceOf(address(0x5409)), 4 * 100_000_000);
        assertEq(tok.balanceOf(address(0xFEE)), 4 * 100_000);
        assertEq(tok.balanceOf(MetaTxLib.UA_POOL), 0);
    }

    uint256 internal constant TX_GAS_CAP = 16_777_216; // EIP-7825; chain 7622's block gas limit is the same

    /// `uaPayReceiverFee` with two `mldsa65` signatures (payer and payee) runs inside one capped transaction: the call
    /// is given exactly `TX_GAS_CAP − 21,000 − calldata` (the registry holds each verify's full cap first), and the
    /// transaction's gas — 21,000 + max(calldata + execution, the EIP-7623 floor) — stays under the cap (logged).
    function test_receiverFee_twoMldsa65_underCap() public {
        (MetaTxLib.UAMetaTransfer memory t, uint256 fee, bytes memory cd) = _receiverFeeRow(_pj(), ".metatx3.receiverFee[0].");
        tok.mint(address(this), t.value);
        tok.transferToUA(t.from, t.value);
        (uint256 std, uint256 floor) = _calldataGas(cd);
        vm.prank(t.relayer);
        uint256 g = gasleft();
        (bool ok, bytes memory ret) = address(tok).call{gas: TX_GAS_CAP - 21_000 - std}(cd);
        g -= gasleft();
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        uint256 txGas = 21_000 + (std + g > floor ? std + g : floor);
        emit log_named_uint("calldata bytes", cd.length);
        emit log_named_uint("calldata gas (EIP-2028)", std);
        emit log_named_uint("execution gas", g);
        emit log_named_uint("transaction gas", txGas);
        assertLt(txGas, TX_GAS_CAP);
        assertEq(tok.balanceOfUA(t.to), t.value - fee);
    }

    /// The row's payment (digest checked), its fee, and the `uaPayReceiverFee` calldata (`ReceiverFee` digest checked).
    function _receiverFeeRow(string memory pj, string memory r)
        internal view returns (MetaTxLib.UAMetaTransfer memory t, uint256 fee, bytes memory cd)
    {
        t = _transferAt(pj, string.concat(r, "transfer.message."));
        bytes32 d = vm.parseJsonBytes32(pj, string.concat(r, "paymentDigest"));
        assertEq(tok.uaTransferDigest(t), d);
        (uint256 f, address feeTo, uint256 until) = _rfFields(pj, r);
        assertEq(tok.receiverFeeDigest(d, f, feeTo, until), vm.parseJsonBytes32(pj, string.concat(r, "receiverFeeDigest")));
        return (t, f, _rfCalldata(pj, r, t));
    }

    function _rfFields(string memory pj, string memory r) internal pure returns (uint256, address, uint256) {
        return (vm.parseJsonUint(pj, string.concat(r, "receiverFee.message.fee")),
            vm.parseJsonAddress(pj, string.concat(r, "receiverFee.message.feeRecipient")),
            vm.parseJsonUint(pj, string.concat(r, "receiverFee.message.validUntil")));
    }

    function _rfCalldata(string memory pj, string memory r, MetaTxLib.UAMetaTransfer memory t)
        internal view returns (bytes memory)
    {
        bytes memory payerAuth = vm.parseJsonBytes(pj, string.concat(r, "payerAuth"));
        bytes memory payeeAuth = vm.parseJsonBytes(pj, string.concat(r, "payeeAuth"));
        (uint256 fee, address feeTo, uint256 until) = _rfFields(pj, r);
        return abi.encodeCall(tok.uaPayReceiverFee, (t, payerAuth, fee, feeTo, until, payeeAuth));
    }

    /// EIP-2028 calldata gas (4 per zero byte, 16 otherwise) and the EIP-7623 floor (10 per token, 4 tokens per non-zero byte).
    function _calldataGas(bytes memory cd) internal pure returns (uint256 std, uint256 floor) {
        uint256 zeros;
        for (uint256 i; i < cd.length; ++i) if (cd[i] == 0) ++zeros;
        std = 4 * zeros + 16 * (cd.length - zeros);
        floor = 10 * (zeros + 4 * (cd.length - zeros));
    }
}
