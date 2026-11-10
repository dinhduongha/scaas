// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs} from "../../script/KindModules.sol";

import {PayMetaKit} from "../helpers/PayMetaKit.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {MldsaVerifier} from "../../src/ua/MlDsa.sol";
import {FndsaVerifier} from "../../src/ua/FnDsa.sol";
import {SlhdsaVerifier} from "../../src/ua/SlhDsa.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {plainEnv} from "../helpers/Catalogue.sol";
import {UACall} from "./UACall.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {Eip8355Allowed} from "./UARegistryPq.t.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

/// The UA ledger with PQ signers (P6c; accounts.md CTR-UA-26, §1.16): pq_signatures.json's `metatx3` rows — the
/// metatx3.json structs and domain, one row per PQ kind — on a `NORMAL` clone at the vector token address, context A,
/// the real PQ verifiers (ML-DSA on its cached expanded key). Every digest is recomputed by the token, every auth passes
/// `requireAuthorized` under `metatx`, every `UAMetaTransfer` row executes. Gas of `mtxExecuteTransfer` per kind is logged.
/// UA-5a (metatx.md, the `mtxPayReceiverFee` paragraph): receiver-pays with an `mldsa65` payer and an `mldsa65` payee
/// (two PQ verifies) fits one 16,777,216-gas transaction (EIP-7825), intrinsic and calldata included.
contract UAMetaTx3PqTest is UARegistryBase {
    NormalToken internal tok;

    function _pj() internal view returns (string memory) {
        return vm.readFile("../vectors/ua/pq_signatures.json");
    }

    function setUp() public override {
        super.setUp();
        string memory pj = _pj();
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](6);
        c[0] = UARegistry.KindConfig(0x0130, address(new MldsaVerifier(0x0130, address(0), "", "")), 4_250_000);
        c[1] = UARegistry.KindConfig(0x0131, address(new MldsaVerifier(0x0131, address(0), "", "")), 5_950_000);
        c[2] = UARegistry.KindConfig(0x0132, address(new FndsaVerifier(0x0132)), 2_500_000);
        c[3] = UARegistry.KindConfig(0x0133, address(new SlhdsaVerifier()), 1_400_000);
        c[4] = UARegistry.KindConfig(0x0134, _ml87(pj), 250_000); // CTR-UA-39: precompile only, the cap a provisional estimate
        c[5] = UARegistry.KindConfig(0x0135, address(new FndsaVerifier(0x0135)), 5_250_000); // CTR-UA-40, provisional cap
        reg = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, c);
        for (uint256 i; i < 6; ++i) {
            string memory k = string.concat(".kinds[", vm.toString(i), "].");
            uint16 kind = uint16(vm.parseJsonUint(pj, string.concat(k, "kind")));
            bytes memory pk = vm.parseJsonBytes(pj, string.concat(k, "keyData"));
            if (kind == 0x0134) ml87.allow(_in87(pk, vm.parseJsonBytes(pj, string.concat(k, "pop.sig")), vm.parseJsonBytes32(pj, string.concat(k, "pop.message"))));
            for (uint256 p; kind <= 0x0131 && p < (kind == 0x0130 ? 1 : 2); ++p) reg.cacheExpandedKey(kind, pk, p);
            UACall.register(reg, kind, pk, _none(), vm.parseJsonBytes(pj, string.concat(k, "pop.sig")), "");
        }
        // the receiverFee payee: mldsa65 index 1 (extraKeys[0]), its expanded key cached as the payer's
        bytes memory pk1 = vm.parseJsonBytes(pj, ".extraKeys[0].keyData");
        for (uint256 p; p < 2; ++p) reg.cacheExpandedKey(0x0131, pk1, p);
        UACall.register(reg, 0x0131, pk1, _none(), vm.parseJsonBytes(pj, ".extraKeys[0].pop.sig"), "");
        address token = vm.parseJsonAddress(pj, ".metatx3.token");
        address impl = address(new NormalToken(address(this), kindArgs(0, address(this), "")));
        vm.etch(token, EnvKit.runtime(impl, EnvKit.env(chainUidA, REG_A, address(0), false)));
        tok = NormalToken(token);
        tok.initialize(nid(address(this)), 1, abi.encode(normalInit("Points", "PTS", 6, 0, address(0), address(this))));
        vm.warp(1_800_000_000);
    }

    Eip8355Allowed internal ml87;

    /// The `mldsa87` verifier on a stand-in precompile that answers 1 to the inputs allowed here: the vectors' own valid
    /// signatures (noble's verdict; `MlDsa.t`'s emulator verifies the KAT row in Solidity), so the rows run through the
    /// registry and the token as on a chain with `MLDSA87`.
    function _ml87(string memory pj) internal returns (address) {
        ml87 = new Eip8355Allowed();
        string memory kat = vm.readFile("../vectors/ua/pq_kat.json");
        bytes memory valid = vm.parseJsonBytes(kat, ".kinds.mldsa87.eip8355_probe_valid");
        ml87.allow(keccak256(valid));
        for (uint256 t; t < 2; ++t) {
            string memory set = t == 0 ? ".metatx3.call[" : ".metatx3.transfer[";
            for (uint256 i; vm.keyExistsJson(pj, string.concat(set, vm.toString(i), "]")); ++i) {
                string memory r = string.concat(set, vm.toString(i), "].");
                if (vm.parseJsonUint(pj, string.concat(r, "kind")) != 0x0134) continue;
                (, bytes memory sig) = abi.decode(vm.parseJsonBytes(pj, string.concat(r, "auth")), (bytes, bytes));
                bytes32 m = UAKinds.uaMessage(0x0134, UAKinds.PURPOSE_METATX, vm.parseJsonBytes32(pj, string.concat(r, "digest")));
                ml87.allow(_in87(vm.parseJsonBytes(pj, ".kinds[4].keyData"), sig, m));
            }
        }
        return address(new MldsaVerifier(0x0134, address(ml87), valid, vm.parseJsonBytes(kat, ".kinds.mldsa87.eip8355_probe_invalid")));
    }

    function _in87(bytes memory pk, bytes memory sig, bytes32 uaMsg) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(pk, sig, PqUA.pqMessage(PqUA.tag(0x0134), uaMsg)));
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

    /// `UAMetaTransaction` rows: digest and auth (the `unwrap` itself is not on the `NORMAL` kind's allowlist).
    function test_callRows() public view {
        string memory pj = _pj();
        uint256 n;
        for (uint256 i; vm.keyExistsJson(pj, string.concat(".metatx3.call[", vm.toString(i), "]")); ++i) {
            string memory r = string.concat(".metatx3.call[", vm.toString(i), "].");
            MetaTxLib.UAMetaTransaction memory m = _call(pj, r);
            bytes32 digest = vm.parseJsonBytes32(pj, string.concat(r, "digest"));
            assertEq(MetaTxLib.hashStruct(m), vm.parseJsonBytes32(pj, string.concat(r, "structHash")));
            assertEq(tok.mtxDigest(m), digest);
            reg.requireAuthorized(m.from, UAKinds.PURPOSE_METATX, digest, UACall.auth(m.from, vm.parseJsonBytes(pj, string.concat(r, "auth"))));
            ++n;
        }
        assertEq(n, 6); // + fndsa1024 (CTR-UA-40)
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
            assertEq(tok.mtxTransferDigest(t), digest);
            bytes memory auth = vm.parseJsonBytes(pj, string.concat(r, "auth"));
            tok.mint(address(this), t.value + t.fee);
            tok.transferToUA(t.from, t.value + t.fee);
            vm.prank(t.relayer);
            uint256 g = gasleft();
            tok.mtxExecuteTransfer(t, UACall.auth(t.from, auth));
            g -= gasleft();
            emit log_named_uint(string.concat("mtxExecuteTransfer ", vm.parseJsonString(pj, string.concat(r, "name"))), g);
            assertEq(tok.balanceOfUA(t.from), 0);
            ++n;
        }
        assertEq(n, 6); // + fndsa1024 (CTR-UA-40)
        assertEq(tok.balanceOf(address(0x5409)), 6 * 100_000_000);
        assertEq(tok.balanceOf(address(0xFEE)), 6 * 100_000);
        assertEq(tok.balanceOf(MetaTxLib.UA_POOL), 0);
    }

    uint256 internal constant TX_GAS_CAP = 16_777_216; // EIP-7825; chain 7622's block gas limit is the same

    /// `mtxPayReceiverFee` with two `mldsa65` signatures (payer and payee) runs inside one capped transaction: the call
    /// is given exactly `TX_GAS_CAP − 21,000 − calldata` (the registry holds each verify's full cap first), and the
    /// transaction's gas — 21,000 + max(calldata + execution, the EIP-7623 floor) — stays under the cap (logged).
    /// pay-meta-tax T41: the row carries its `PayMeta` (the entry's last parameter; `entryRef` its commitment).
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

    /// The row's payment (digest checked), its fee, and the `mtxPayReceiverFee` calldata (`ReceiverFee` digest checked).
    function _receiverFeeRow(string memory pj, string memory r)
        internal view returns (MetaTxLib.UAMetaTransfer memory t, uint256 fee, bytes memory cd)
    {
        t = _transferAt(pj, string.concat(r, "transfer.message."));
        bytes32 d = vm.parseJsonBytes32(pj, string.concat(r, "paymentDigest"));
        assertEq(tok.mtxTransferDigest(t), d);
        (uint256 f, address feeTo, uint256 until) = _rfFields(pj, r);
        assertEq(tok.receiverFeeDigest(t, f, feeTo, until), vm.parseJsonBytes32(pj, string.concat(r, "receiverFeeDigest")));
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
        RfArgs memory a;
        a.meta = _rowMeta(pj, string.concat(r, "meta."), t.entryRef);
        a.payer = UACall.auth(t.from, vm.parseJsonBytes(pj, string.concat(r, "payerAuth")));
        a.payee = UACall.auth(t.to, vm.parseJsonBytes(pj, string.concat(r, "payeeAuth")));
        (a.fee, a.feeTo, a.until) = _rfFields(pj, r);
        return abi.encodeCall(tok.mtxPayReceiverFee, (t, a.payer, a.fee, a.feeTo, a.until, a.payee, a.meta));
    }

    /// The receiver-fee call's arguments in one memory struct (the legacy decoder's stack).
    struct RfArgs {
        IUARegistry.UASig payer;
        IUARegistry.UASig payee;
        uint256 fee;
        address feeTo;
        uint256 until;
        MetaTxLib.PayMeta meta;
    }

    /// The row's `PayMeta` (pay-meta-tax T41), its commitment checked against the payment's `entryRef`.
    function _rowMeta(string memory pj, string memory p, bytes32 entryRef) internal pure returns (MetaTxLib.PayMeta memory m) {
        m = MetaTxLib.PayMeta(vm.parseJsonBytes32(pj, string.concat(p, "salt")), vm.parseJsonBytes32(pj, string.concat(p, "payNo")),
            vm.parseJsonBool(pj, string.concat(p, "save")), uint16(vm.parseJsonUint(pj, string.concat(p, "schema"))),
            vm.parseJsonBytes(pj, string.concat(p, "body")));
        assertEq(PayMetaKit.id(m), entryRef, "the row's entryRef commits to its PayMeta");
    }

    /// EIP-2028 calldata gas (4 per zero byte, 16 otherwise) and the EIP-7623 floor (10 per token, 4 tokens per non-zero byte).
    function _calldataGas(bytes memory cd) internal pure returns (uint256 std, uint256 floor) {
        uint256 zeros;
        for (uint256 i; i < cd.length; ++i) if (cd[i] == 0) ++zeros;
        std = 4 * zeros + 16 * (cd.length - zeros);
        floor = 10 * (zeros + 4 * (cd.length - zeros));
    }
}
