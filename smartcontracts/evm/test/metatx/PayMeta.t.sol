// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalToken} from "../../src/metatx/NormalToken.sol";

import {UACall} from "../ua/UACall.sol";
import {Test, Vm} from "forge-std/Test.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {FeeMode} from "../../src/common/FeePolicy.sol";
import {IRig, PlainRig, PqzRig, ZetherRig} from "./helpers/KindRigs.sol";
import {PayMetaKit} from "../helpers/PayMetaKit.sol";

/// The tokens of the parity rigs (`NORMAL`, `WRAPPED`, `NORMAL` with the ledger off, both PQZ and both Zether kinds) and the
/// pay helpers of `PayMeta.t` and `PayLanes.t`. The signer `0xA11CE` is an EOA that signs `UAMetaTransfer` with its own
/// key and is funded on every rig.
abstract contract PayRigBase is Test {
    uint256 internal constant PK = 0xA11CE;
    address internal constant REL = address(0x7E1A);
    address internal constant PAYEE = address(0xB0B5);
    address internal constant FEE_TO = address(0xFEE5);
    uint32 internal constant MODE = MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT
        | MetaTxLib.MODE_FEE_FIXED;
    uint256 internal constant FEE = 5;
    uint256 internal constant AMOUNT = 1_000;
    // GovernanceLib's ERC-7201 `scaas.governance`: slot 0 of `GovernanceStorage` is `features`
    bytes32 internal constant GOV_STORAGE = 0x0a3a361961b35589cdb03530b6f9e23a4db6ca9a0dad5ddf5d7761c7fabc8700;

    address internal signer = vm.addr(PK);
    string[] internal kinds;
    address[] internal toks;

    function setUp() public virtual {
        IRig[3] memory rigs;
        PlainRig plain = new PlainRig();
        plain.init();
        rigs[0] = IRig(address(plain));
        PqzRig pqz = new PqzRig();
        pqz.init();
        rigs[1] = IRig(address(pqz));
        ZetherRig zeth = new ZetherRig();
        zeth.init();
        rigs[2] = IRig(address(zeth));
        for (uint256 r; r < 3; ++r) {
            (string[] memory k, address[] memory t,) = rigs[r].setup();
            for (uint256 i; i < t.length; ++i) {
                kinds.push(k[i]);
                toks.push(t[i]);
            }
        }
        assertEq(toks.length, 7, "six kinds and NORMAL with the ledger off");
    }

    function _ecdsa(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    /// A UUIDv7 (`019a6e3c-5f00-7a3b-8c4d-5e6f708192a3` + `i`), right-aligned: the recommended `payNo` (plan T83).
    function _uuid(uint256 i) internal pure returns (bytes32) {
        return bytes32(uint256(0x019a6e3c5f007a3b8c4d5e6f708192a3) + i);
    }

    /// A schema 1 `PayMeta` (a note) with a `payNo` (`save` off), its salt from `i`.
    function _meta(uint256 i) internal pure returns (MetaTxLib.PayMeta memory m) {
        m.salt = keccak256(abi.encode("paymeta.test.salt", i));
        m.payNo = _uuid(i);
        m.schema = 1;
        m.body = bytes(string.concat("note ", vm.toString(i)));
    }

    /// The payment of `entryRef` on lane `(batch, nonce)`, relayer `REL`, fee `FEE` to `FEE_TO`.
    function _ut(bytes32 entryRef, uint256 batch, uint256 nonce) internal view returns (MetaTxLib.UAMetaTransfer memory) {
        return MetaTxLib.UAMetaTransfer(MetaTxLib.pad(signer), MetaTxLib.pad(PAYEE), AMOUNT, entryRef, batch, nonce,
            block.timestamp + 300, MODE, REL, FEE, FEE_TO);
    }

    function _sigOf(address t, MetaTxLib.UAMetaTransfer memory x) internal view returns (IUARegistry.UASig memory) {
        return UACall.auth(x.from, _ecdsa(PK, NormalToken(t).mtxTransferDigest(x)));
    }

    /// `mtxPay(x, sig, m)` from `REL`.
    function _pay(address t, MetaTxLib.UAMetaTransfer memory x, MetaTxLib.PayMeta memory m) internal {
        IUARegistry.UASig memory a = _sigOf(t, x);
        vm.prank(REL);
        NormalToken(t).mtxPay(x, a, m);
    }

    /// The index of the first log of `t` with `topic0` from `start`; reverts when there is none.
    function _find(Vm.Log[] memory logs, address t, bytes32 topic0, uint256 start) internal pure returns (uint256) {
        for (uint256 i = start; i < logs.length; ++i) if (logs[i].emitter == t && logs[i].topics[0] == topic0) return i;
        revert("event not emitted");
    }

    function _count(Vm.Log[] memory logs, address t, bytes32 topic0) internal pure returns (uint256 n) {
        for (uint256 i; i < logs.length; ++i) if (logs[i].emitter == t && logs[i].topics[0] == topic0) ++n;
    }
}

/// @notice Pay-meta-tax spec §3 (T37; CTR-MTX-26 Change, PT-2) as plan T83 changes it (owner 2026-11-09): `PayMeta { salt,
///         payNo, save, schema, body }` is the required last parameter of every pay entry; a non-zero salt; schema 0 iff the
///         body is empty; `payNo` a `bytes32`, never parsed (0 = none, recommended a right-aligned UUIDv7); no `save` without
///         a `payNo`; `entryRef == metaPayId(meta)` under `scaas.pay.meta.v3`; `PaymentMeta(payId, payNo, save, schema,
///         body)` always emitted, before the payment's events. Run on a clone of every kind of the parity rigs.
///         `test_payMetaVectors` writes (`PAYMETA_WRITE=1`) or checks `../vectors/metatx/paymeta.json`, the vectors
///         `clientkeys`, `ua-rs` and the node read (the v2 rows, `payNo` a string, in `../vectors/metatx/legacy/ua-mtx-merge/
///         t83/`; the old formula's file, for the families still on it, in `../vectors/metatx/legacy/ua-mtx-merge/`).
contract PayMetaTest is PayRigBase {
    string internal constant FILE = "../vectors/metatx/paymeta.json";

    /// Each kind: the control `m` lands; `bad` (with `entryRef = id(bad)`, one field changed) is refused with `err`.
    function _controlThenRefused(MetaTxLib.PayMeta memory m, MetaTxLib.PayMeta memory bad, bytes memory err) internal {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            uint256 snap = vm.snapshotState();
            _pay(t, _ut(PayMetaKit.id(m), 7, 0), m);
            assertEq(NormalToken(t).balanceOf(PAYEE), AMOUNT, kinds[i]);
            vm.revertToState(snap);
            MetaTxLib.UAMetaTransfer memory x = _ut(PayMetaKit.id(bad), 7, 0);
            IUARegistry.UASig memory a = _sigOf(t, x);
            vm.prank(REL);
            vm.expectRevert(err);
            NormalToken(t).mtxPay(x, a, bad);
        }
    }

    function test_payMeta_saltZeroRefused() public {
        MetaTxLib.PayMeta memory m = _meta(1);
        MetaTxLib.PayMeta memory bad = _meta(1);
        bad.salt = 0;
        _controlThenRefused(m, bad, abi.encodeWithSelector(IMetaTokenV2.PayMetaShape.selector));
    }

    function test_payMeta_schemaZeroWithBody() public {
        MetaTxLib.PayMeta memory m = _meta(2);
        (m.schema, m.body) = (0, "");
        MetaTxLib.PayMeta memory bad = _meta(2);
        (bad.schema, bad.body) = (0, "x");
        _controlThenRefused(m, bad, abi.encodeWithSelector(IMetaTokenV2.PayMetaShape.selector));
    }

    function test_payMeta_schemaWithEmptyBody() public {
        MetaTxLib.PayMeta memory m = _meta(3);
        MetaTxLib.PayMeta memory bad = _meta(3);
        bad.body = "";
        _controlThenRefused(m, bad, abi.encodeWithSelector(IMetaTokenV2.PayMetaShape.selector));
    }

    /// Plan T83: any 32-byte `payNo` is accepted and never parsed (here every byte set, no UUID), indexed in `PaymentMeta`.
    function test_payMeta_anyPayNoIndexed() public {
        MetaTxLib.PayMeta memory m = _meta(4);
        m.payNo = keccak256("scaas.paymeta.test.any32");
        for (uint256 i; i < toks.length; ++i) {
            vm.recordLogs();
            _pay(toks[i], _ut(PayMetaKit.id(m), 7, 0), m);
            Vm.Log[] memory logs = vm.getRecordedLogs();
            uint256 pm = _find(logs, toks[i], IMetaTokenV2.PaymentMeta.selector, 0);
            assertEq(logs[pm].topics[2], m.payNo, kinds[i]);
            assertEq(logs[pm].data, abi.encode(false, m.schema, m.body), kinds[i]);
        }
    }

    /// Plan T83: `save` with `payNo == 0` is a shape error (the control saves under a `payNo`).
    function test_payMeta_saveWithoutPayNoRefused() public {
        MetaTxLib.PayMeta memory m = _meta(5);
        m.save = true;
        MetaTxLib.PayMeta memory bad = _meta(5);
        (bad.payNo, bad.save) = (0, true);
        _controlThenRefused(m, bad, abi.encodeWithSelector(IMetaTokenV2.PayMetaShape.selector));
    }

    /// Plan T83: `save` is inside the commitment: an `entryRef` over `save = false` refuses the call with `save = true`, and
    /// the other way round.
    function test_payMeta_saveInCommitment() public {
        for (uint256 k; k < 2; ++k) {
            MetaTxLib.PayMeta memory signed = _meta(8 + k);
            signed.save = k == 1;
            MetaTxLib.PayMeta memory sent = _meta(8 + k);
            sent.save = k == 0;
            for (uint256 i; i < toks.length; ++i) {
                address t = toks[i];
                MetaTxLib.UAMetaTransfer memory x = _ut(PayMetaKit.id(signed), 7, k);
                IUARegistry.UASig memory s = _sigOf(t, x);
                vm.prank(REL);
                vm.expectRevert(abi.encodeWithSelector(IMetaTokenV2.PayMetaMismatch.selector, x.entryRef,
                    PayMetaKit.id(sent)));
                NormalToken(t).mtxPay(x, s, sent);
                _pay(t, x, signed); // control
            }
        }
    }

    /// The commitment over `payNo` "A", the call with "B" (same salt, save, schema, body).
    function test_payMeta_otherPayNoMismatch() public {
        MetaTxLib.PayMeta memory a = _meta(6);
        a.payNo = bytes32("A");
        MetaTxLib.PayMeta memory b = _meta(6);
        b.payNo = bytes32("B");
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            MetaTxLib.UAMetaTransfer memory x = _ut(PayMetaKit.id(a), 7, 0);
            IUARegistry.UASig memory s = _sigOf(t, x);
            vm.prank(REL);
            vm.expectRevert(abi.encodeWithSelector(IMetaTokenV2.PayMetaMismatch.selector, x.entryRef, PayMetaKit.id(b)));
            NormalToken(t).mtxPay(x, s, b);
            _pay(t, x, a); // control
        }
    }

    /// An `entryRef` under an old tag over the same bytes is refused by name: `scaas.pay.meta` (C1, Codex #8) and
    /// `scaas.pay.meta.v2` (plan T83: the type changed, so the tag did), each over the v3 encoding.
    function test_payMeta_oldTagRefused() public {
        MetaTxLib.PayMeta memory m = _meta(7);
        m.save = true;
        bytes32 inner = keccak256(abi.encode(m.payNo, m.save, m.schema, m.body));
        bytes32[2] memory old = [keccak256(abi.encodePacked("scaas.pay.meta", m.salt, inner)),
            keccak256(abi.encodePacked("scaas.pay.meta.v2", m.salt, inner))];
        for (uint256 j; j < 2; ++j) {
            assertTrue(old[j] != PayMetaKit.id(m));
            for (uint256 i; i < toks.length; ++i) {
                address t = toks[i];
                MetaTxLib.UAMetaTransfer memory x = _ut(old[j], 7, 0);
                IUARegistry.UASig memory s = _sigOf(t, x);
                vm.prank(REL);
                vm.expectRevert(abi.encodeWithSelector(IMetaTokenV2.PayMetaMismatch.selector, old[j], PayMetaKit.id(m)));
                NormalToken(t).mtxPay(x, s, m);
                assertEq(NormalToken(t).metaPayId(m), PayMetaKit.id(m), kinds[i]);
            }
        }
    }

    /// `PaymentMeta(payId, payNo, save, schema, body)` with its fields, before `UAPaymentSettled` and the executed event.
    function test_payMeta_emittedBeforeSettled() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            MetaTxLib.PayMeta memory m = _meta(100 + i);
            MetaTxLib.UAMetaTransfer memory x = _ut(PayMetaKit.id(m), 9, 0);
            bytes32 d = NormalToken(t).mtxTransferDigest(x);
            vm.recordLogs();
            _pay(t, x, m);
            Vm.Log[] memory logs = vm.getRecordedLogs();
            uint256 pm = _find(logs, t, IMetaTokenV2.PaymentMeta.selector, 0);
            assertEq(logs[pm].topics[1], x.entryRef, kinds[i]);
            assertEq(logs[pm].topics[2], m.payNo, kinds[i]);
            assertEq(logs[pm].data, abi.encode(m.save, m.schema, m.body), kinds[i]);
            uint256 ps = _find(logs, t, IUALedger.UAPaymentSettled.selector, 0);
            uint256 ex = _find(logs, t, IUALedger.UAMetaTransactionExecuted.selector, 0);
            assertLt(pm, ps, string.concat(kinds[i], ": PaymentMeta before UAPaymentSettled"));
            assertLt(ps, ex, kinds[i]);
            assertEq(logs[ps].topics[logs[ps].topics.length - 1], x.entryRef, kinds[i]);
            (uint256 nonce, bytes32 digest,,) = abi.decode(logs[ex].data, (uint256, bytes32, address, uint256));
            assertEq(uint256(logs[ex].topics[3]), 9, kinds[i]);
            assertEq(nonce, 0, kinds[i]);
            assertEq(digest, d, kinds[i]);
            assertEq(NormalToken(t).balanceOf(FEE_TO), FEE, kinds[i]);
        }
    }

    /// `PAYABLE` gates `mtxPay` (CTR-TOK-22); the bit is always locked, so it is cleared in storage.
    function test_mtxPay_requiresPayable() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            uint256 f = uint256(vm.load(t, GOV_STORAGE));
            assertEq(f & (1 << GovernanceBits.PAYABLE), 1 << GovernanceBits.PAYABLE, kinds[i]);
            vm.store(t, GOV_STORAGE, bytes32(f & ~uint256(1 << GovernanceBits.PAYABLE)));
            MetaTxLib.PayMeta memory m = _meta(400 + i);
            MetaTxLib.UAMetaTransfer memory x = _ut(PayMetaKit.id(m), 7, 0);
            IUARegistry.UASig memory s = _sigOf(t, x);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, GovernanceBits.PAYABLE));
            NormalToken(t).mtxPay(x, s, m);
        }
    }

    /// The direct entry: `entryRef = 0` is refused (`PayMetaMismatch(0, id)`), the commitment lands.
    function test_payWithFee_entryRefZeroRefused() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            MetaTxLib.PayMeta memory m = _meta(500 + i);
            vm.prank(signer);
            vm.expectRevert(abi.encodeWithSelector(IMetaTokenV2.PayMetaMismatch.selector, bytes32(0), PayMetaKit.id(m)));
            NormalToken(t).payWithFee(PAYEE, AMOUNT, FeeMode.NONE, 0, address(0), bytes32(0), m);
            vm.recordLogs();
            vm.prank(signer);
            NormalToken(t).payWithFee(PAYEE, AMOUNT, FeeMode.NONE, 0, address(0), PayMetaKit.id(m), m);
            assertEq(NormalToken(t).balanceOf(PAYEE), AMOUNT, kinds[i]);
            Vm.Log[] memory logs = vm.getRecordedLogs();
            assertEq(_count(logs, t, IMetaTokenV2.PaymentMeta.selector), 1, kinds[i]);
        }
    }

    // ------------------------------------------------------------------ the shared vectors

    /// The UUIDv7 of the vector rows (`019a6e3c-5f00-7a3b-8c4d-5e6f708192a3`), right-aligned.
    bytes32 internal constant ROW_UUID = bytes32(uint256(0x019a6e3c5f007a3b8c4d5e6f708192a3));
    string internal constant ROW_UUID_TEXT = "019a6e3c-5f00-7a3b-8c4d-5e6f708192a3";

    /// Rows `{name, salt, payNo, save, schema, body, payId, accepted}` (spec §7.3, plan T83): salt only; a right-aligned
    /// UUIDv7 `payNo` (with `payNoUuid`, its text) without and with `save` (`saveOffPayId`: the same fields with `save` off
    /// differ); a 32-byte `payNo` that is no UUID, saved; `save` without a `payNo` (refused `PayMetaShape`); each schema
    /// 1-4 (schema 2 is `abi.encode(string creditorRef, uint64 dueDate)`, no `invoiceNo`); a row with `v2TagPayId`, the v2
    /// tag's hash over the same bytes (C1). The schema 4 body is illustrative filler.
    function _rows() internal pure returns (string[] memory names, MetaTxLib.PayMeta[] memory ms) {
        uint256 n = 9;
        names = new string[](n);
        ms = new MetaTxLib.PayMeta[](n);
        bytes32 any32 = keccak256("scaas.paymeta.v3.vector.any32");
        (names[0], ms[0]) = ("salt_only", _m(0, false, 0, ""));
        (names[1], ms[1]) = ("payno_uuidv7", _m(ROW_UUID, false, 0, ""));
        (names[2], ms[2]) = ("payno_uuidv7_save", _m(ROW_UUID, true, 0, ""));
        (names[3], ms[3]) = ("payno_any32_save", _m(any32, true, 0, ""));
        (names[4], ms[4]) = ("save_without_payno_refused", _m(0, true, 0, ""));
        (names[5], ms[5]) = ("note_utf8", _m(0, false, 1, bytes(unicode"Hóa đơn 2026-0042 — cảm ơn")));
        (names[6], ms[6]) = ("structured_reference", _m(ROW_UUID, true, 2, abi.encode("RF18539007547034", uint64(1_830_297_600))));
        (names[7], ms[7]) = ("bound_call", _m(0, false, 3, abi.encode(uint256(7622),
            bytes32(uint256(uint160(address(0xC0FFEE)))), keccak256("scaas.paymeta.vector.call"))));
        (names[8], ms[8]) = ("encrypted_illustrative", _m(ROW_UUID, false, 4, _filler(96, 0x04)));
        for (uint256 i; i < n; ++i) ms[i].salt = keccak256(abi.encode("scaas.paymeta.v3.vector", names[i]));
    }

    function _m(bytes32 payNo, bool save, uint16 schema, bytes memory body) internal pure returns (MetaTxLib.PayMeta memory m) {
        (m.payNo, m.save, m.schema, m.body) = (payNo, save, schema, body);
    }

    function _filler(uint256 n, uint8 seed) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; ++i) b[i] = bytes1(uint8(uint256(keccak256(abi.encode(seed, i / 32))) >> (8 * (i % 32))));
    }

    function _accepted(MetaTxLib.PayMeta memory m) internal pure returns (bool) {
        return !(m.save && m.payNo == 0);
    }

    function _rowJson(string memory name, MetaTxLib.PayMeta memory m) internal pure returns (string memory) {
        string memory head = string.concat('  {"name":"', name, '","salt":"', vm.toString(m.salt), '","payNo":"',
            vm.toString(m.payNo), '","save":', m.save ? "true" : "false", ',"schema":', vm.toString(m.schema));
        string memory tail = string.concat(',"body":"', vm.toString(m.body), '","payId":"', vm.toString(PayMetaKit.id(m)),
            '","accepted":', _accepted(m) ? "true" : "false");
        if (m.payNo == ROW_UUID) tail = string.concat(tail, ',"payNoUuid":"', ROW_UUID_TEXT, '"');
        if (keccak256(bytes(name)) == keccak256("payno_uuidv7")) {
            tail = string.concat(tail, ',"v2TagPayId":"', vm.toString(keccak256(abi.encodePacked("scaas.pay.meta.v2",
                m.salt, keccak256(abi.encode(m.payNo, m.save, m.schema, m.body))))), '"');
        }
        if (keccak256(bytes(name)) == keccak256("payno_uuidv7_save")) {
            MetaTxLib.PayMeta memory off = _m(m.payNo, false, m.schema, m.body);
            off.salt = m.salt;
            tail = string.concat(tail, ',"saveOffPayId":"', vm.toString(PayMetaKit.id(off)), '"');
        }
        return string.concat(head, tail, "}");
    }

    function test_payMetaVectors() public {
        if (vm.envOr("PAYMETA_WRITE", false)) {
            (string[] memory names, MetaTxLib.PayMeta[] memory ms) = _rows();
            string memory j = "[\n";
            for (uint256 i; i < names.length; ++i) j = string.concat(j, i == 0 ? "" : ",\n", _rowJson(names[i], ms[i]));
            vm.writeFile(FILE, string.concat(j, "\n]\n"));
        }
        string memory f = vm.readFile(FILE);
        uint256 rows;
        while (vm.keyExistsJson(f, string.concat("[", vm.toString(rows), "]"))) ++rows;
        assertEq(rows, 9, "rows");
        address t = toks[0];
        for (uint256 i; i < rows; ++i) {
            string memory p = string.concat("[", vm.toString(i), "]");
            MetaTxLib.PayMeta memory m = MetaTxLib.PayMeta(vm.parseJsonBytes32(f, string.concat(p, ".salt")),
                vm.parseJsonBytes32(f, string.concat(p, ".payNo")), vm.parseJsonBool(f, string.concat(p, ".save")),
                uint16(vm.parseJsonUint(f, string.concat(p, ".schema"))), vm.parseJsonBytes(f, string.concat(p, ".body")));
            bytes32 payId = vm.parseJsonBytes32(f, string.concat(p, ".payId"));
            assertEq(payId, PayMetaKit.id(m), "payId formula");
            assertEq(vm.parseJsonBool(f, string.concat(p, ".accepted")), _accepted(m), "accepted");
            for (uint256 k; k < toks.length; ++k) assertEq(NormalToken(toks[k]).metaPayId(m), payId, kinds[k]);
            // each row submitted: an accepted row lands with its `PaymentMeta` (and its record when saved), the refused one
            // by name
            MetaTxLib.UAMetaTransfer memory x = _ut(payId, 11, i);
            IUARegistry.UASig memory s = _sigOf(t, x);
            uint256 before = NormalToken(t).paymentCount(m.payNo);
            if (!_accepted(m)) {
                vm.expectRevert(abi.encodeWithSelector(IMetaTokenV2.PayMetaShape.selector));
                vm.prank(REL);
                NormalToken(t).mtxPay(x, s, m);
                vm.prank(REL);
                NormalToken(t).mtxExecuteTransfer(x, s); // the refused row consumed nothing: nonce `i` still free
            } else {
                vm.prank(REL);
                NormalToken(t).mtxPay(x, s, m);
            }
            assertEq(NormalToken(t).paymentCount(m.payNo), before + (m.save && _accepted(m) ? 1 : 0), "record");
            if (vm.keyExistsJson(f, string.concat(p, ".payNoUuid"))) {
                assertEq(m.payNo, ROW_UUID, "the UUIDv7 right-aligned");
                assertEq(vm.parseJsonString(f, string.concat(p, ".payNoUuid")), ROW_UUID_TEXT, "its text");
            }
            if (vm.keyExistsJson(f, string.concat(p, ".v2TagPayId"))) {
                assertTrue(vm.parseJsonBytes32(f, string.concat(p, ".v2TagPayId")) != payId, "C1: the tags disagree");
            }
            if (vm.keyExistsJson(f, string.concat(p, ".saveOffPayId"))) {
                m.save = false;
                assertEq(vm.parseJsonBytes32(f, string.concat(p, ".saveOffPayId")), PayMetaKit.id(m), "save off");
                assertTrue(PayMetaKit.id(m) != payId, "save is committed");
            }
        }
    }
}
