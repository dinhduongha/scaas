// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

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

    /// A schema 1 `PayMeta` (a note) with a `payNo`, its salt from `i`.
    function _meta(uint256 i) internal pure returns (MetaTxLib.PayMeta memory m) {
        m.salt = keccak256(abi.encode("paymeta.test.salt", i));
        m.payNo = string.concat("INV-", vm.toString(i));
        m.schema = 1;
        m.body = bytes(string.concat("note ", vm.toString(i)));
    }

    /// The payment of `entryRef` on lane `(batch, nonce)`, relayer `REL`, fee `FEE` to `FEE_TO`.
    function _ut(bytes32 entryRef, uint256 batch, uint256 nonce) internal view returns (MetaTxLib.UAMetaTransfer memory) {
        return MetaTxLib.UAMetaTransfer(MetaTxLib.pad(signer), MetaTxLib.pad(PAYEE), AMOUNT, entryRef, batch, nonce,
            block.timestamp + 300, MODE, REL, FEE, FEE_TO);
    }

    function _sigOf(address t, MetaTxLib.UAMetaTransfer memory x) internal view returns (IUARegistry.UASig memory) {
        return UACall.auth(x.from, _ecdsa(PK, MetaTokenBase(t).mtxTransferDigest(x)));
    }

    /// `mtxPay(x, sig, m)` from `REL`.
    function _pay(address t, MetaTxLib.UAMetaTransfer memory x, MetaTxLib.PayMeta memory m) internal {
        IUARegistry.UASig memory a = _sigOf(t, x);
        vm.prank(REL);
        MetaTokenBase(t).mtxPay(x, a, m);
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

/// @notice Pay-meta-tax spec §3 (T37; CTR-MTX-26 Change, PT-2): `PayMeta { salt, payNo, schema, body }` is the required
///         last parameter of every pay entry; a non-zero salt; schema 0 iff the body is empty; `payNo` at most 256 bytes;
///         `entryRef == metaPayId(meta)` under `scaas.pay.meta.v2`; `PaymentMeta(payId, payNo, schema, body)` always
///         emitted, before the payment's events. Run on a clone of every kind of the parity rigs. `test_payMetaVectors`
///         writes (`PAYMETA_WRITE=1`) or checks `../vectors/metatx/paymeta.json`, the vectors `clientkeys`, `ua-rs` and the
///         node read (the old formula's file, for the families still on it, is in `../vectors/metatx/legacy/ua-mtx-merge/`).
contract PayMetaTest is PayRigBase {
    string internal constant FILE = "../vectors/metatx/paymeta.json";

    /// Each kind: the control `m` lands; `bad` (with `entryRef = id(bad)`, one field changed) is refused with `err`.
    function _controlThenRefused(MetaTxLib.PayMeta memory m, MetaTxLib.PayMeta memory bad, bytes memory err) internal {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            uint256 snap = vm.snapshotState();
            _pay(t, _ut(PayMetaKit.id(m), 7, 0), m);
            assertEq(MetaTokenBase(t).balanceOf(PAYEE), AMOUNT, kinds[i]);
            vm.revertToState(snap);
            MetaTxLib.UAMetaTransfer memory x = _ut(PayMetaKit.id(bad), 7, 0);
            IUARegistry.UASig memory a = _sigOf(t, x);
            vm.prank(REL);
            vm.expectRevert(err);
            MetaTokenBase(t).mtxPay(x, a, bad);
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

    function _payNo(uint256 n) internal pure returns (string memory) {
        bytes memory b = new bytes(n);
        for (uint256 i; i < n; ++i) b[i] = bytes1(uint8(0x41 + i % 26));
        return string(b);
    }

    function test_payMeta_payNo256Passes() public {
        MetaTxLib.PayMeta memory m = _meta(4);
        m.payNo = _payNo(256);
        for (uint256 i; i < toks.length; ++i) {
            vm.recordLogs();
            _pay(toks[i], _ut(PayMetaKit.id(m), 7, 0), m);
            Vm.Log[] memory logs = vm.getRecordedLogs();
            uint256 pm = _find(logs, toks[i], IMetaTokenV2.PaymentMeta.selector, 0);
            (string memory payNo,,) = abi.decode(logs[pm].data, (string, uint16, bytes));
            assertEq(bytes(payNo).length, 256, kinds[i]);
        }
    }

    function test_payMeta_payNo257Refused() public {
        MetaTxLib.PayMeta memory m = _meta(5);
        m.payNo = _payNo(256);
        MetaTxLib.PayMeta memory bad = _meta(5);
        bad.payNo = _payNo(257);
        _controlThenRefused(m, bad, abi.encodeWithSelector(IMetaTokenV2.PayNoTooLong.selector, 257));
    }

    /// The commitment over `payNo` "A", the call with "B" (same salt, schema, body).
    function test_payMeta_otherPayNoMismatch() public {
        MetaTxLib.PayMeta memory a = _meta(6);
        a.payNo = "A";
        MetaTxLib.PayMeta memory b = _meta(6);
        b.payNo = "B";
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            MetaTxLib.UAMetaTransfer memory x = _ut(PayMetaKit.id(a), 7, 0);
            IUARegistry.UASig memory s = _sigOf(t, x);
            vm.prank(REL);
            vm.expectRevert(abi.encodeWithSelector(IMetaTokenV2.PayMetaMismatch.selector, x.entryRef, PayMetaKit.id(b)));
            MetaTokenBase(t).mtxPay(x, s, b);
            _pay(t, x, a); // control
        }
    }

    /// An `entryRef` under the old tag `scaas.pay.meta` over the same bytes is refused by name (C1, Codex #8).
    function test_payMeta_oldTagRefused() public {
        MetaTxLib.PayMeta memory m = _meta(7);
        bytes32 old = keccak256(abi.encodePacked("scaas.pay.meta", m.salt, keccak256(abi.encode(m.payNo, m.schema, m.body))));
        assertTrue(old != PayMetaKit.id(m));
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            MetaTxLib.UAMetaTransfer memory x = _ut(old, 7, 0);
            IUARegistry.UASig memory s = _sigOf(t, x);
            vm.prank(REL);
            vm.expectRevert(abi.encodeWithSelector(IMetaTokenV2.PayMetaMismatch.selector, old, PayMetaKit.id(m)));
            MetaTokenBase(t).mtxPay(x, s, m);
            assertEq(MetaTokenBase(t).metaPayId(m), PayMetaKit.id(m), kinds[i]);
        }
    }

    /// `PaymentMeta(payId, payNo, schema, body)` with its fields, before `UAPaymentSettled` and the executed event.
    function test_payMeta_emittedBeforeSettled() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            MetaTxLib.PayMeta memory m = _meta(100 + i);
            MetaTxLib.UAMetaTransfer memory x = _ut(PayMetaKit.id(m), 9, 0);
            bytes32 d = MetaTokenBase(t).mtxTransferDigest(x);
            vm.recordLogs();
            _pay(t, x, m);
            Vm.Log[] memory logs = vm.getRecordedLogs();
            uint256 pm = _find(logs, t, IMetaTokenV2.PaymentMeta.selector, 0);
            assertEq(logs[pm].topics[1], x.entryRef, kinds[i]);
            assertEq(logs[pm].data, abi.encode(m.payNo, m.schema, m.body), kinds[i]);
            uint256 ps = _find(logs, t, IUALedger.UAPaymentSettled.selector, 0);
            uint256 ex = _find(logs, t, IUALedger.UAMetaTransactionExecuted.selector, 0);
            assertLt(pm, ps, string.concat(kinds[i], ": PaymentMeta before UAPaymentSettled"));
            assertLt(ps, ex, kinds[i]);
            assertEq(logs[ps].topics[logs[ps].topics.length - 1], x.entryRef, kinds[i]);
            (uint256 nonce, bytes32 digest,,) = abi.decode(logs[ex].data, (uint256, bytes32, address, uint256));
            assertEq(uint256(logs[ex].topics[3]), 9, kinds[i]);
            assertEq(nonce, 0, kinds[i]);
            assertEq(digest, d, kinds[i]);
            assertEq(MetaTokenBase(t).balanceOf(FEE_TO), FEE, kinds[i]);
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
            MetaTokenBase(t).mtxPay(x, s, m);
        }
    }

    /// The direct entry: `entryRef = 0` is refused (`PayMetaMismatch(0, id)`), the commitment lands.
    function test_payWithFee_entryRefZeroRefused() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            MetaTxLib.PayMeta memory m = _meta(500 + i);
            vm.prank(signer);
            vm.expectRevert(abi.encodeWithSelector(IMetaTokenV2.PayMetaMismatch.selector, bytes32(0), PayMetaKit.id(m)));
            MetaTokenBase(t).payWithFee(PAYEE, AMOUNT, FeeMode.NONE, 0, address(0), bytes32(0), m);
            vm.recordLogs();
            vm.prank(signer);
            MetaTokenBase(t).payWithFee(PAYEE, AMOUNT, FeeMode.NONE, 0, address(0), PayMetaKit.id(m), m);
            assertEq(MetaTokenBase(t).balanceOf(PAYEE), AMOUNT, kinds[i]);
            Vm.Log[] memory logs = vm.getRecordedLogs();
            assertEq(_count(logs, t, IMetaTokenV2.PaymentMeta.selector), 1, kinds[i]);
        }
    }

    // ------------------------------------------------------------------ the shared vectors

    /// Rows `{name, salt, payNo, schema, body, payId, accepted}` (spec §7.3): salt only; `payNo` only; `payNo` of 256
    /// bytes (accepted) and of 257 (refused `PayNoTooLong`); a multi-byte UTF-8 `payNo` ending at the bound; each schema
    /// 1-4 (schema 2 is `abi.encode(string creditorRef, uint64 dueDate)`, no `invoiceNo`); a row with `oldTagPayId`, the
    /// old tag's hash over the same bytes (C1). The schema 4 body is illustrative filler.
    function _rows() internal pure returns (string[] memory names, string[] memory payNos, uint16[] memory schemas,
        bytes[] memory bodies)
    {
        uint256 n = 9;
        names = new string[](n);
        payNos = new string[](n);
        schemas = new uint16[](n);
        bodies = new bytes[](n);
        (names[0], payNos[0], schemas[0], bodies[0]) = ("salt_only", "", 0, "");
        (names[1], payNos[1], schemas[1], bodies[1]) = ("payno_only", "INV-2026-0042", 0, "");
        (names[2], payNos[2], schemas[2], bodies[2]) = ("payno_256", _payNo(256), 0, "");
        (names[3], payNos[3], schemas[3], bodies[3]) = ("payno_257_refused", _payNo(257), 0, "");
        (names[4], payNos[4], schemas[4], bodies[4]) = ("payno_utf8_256", _euro(), 0, "");
        (names[5], payNos[5], schemas[5], bodies[5]) =
            ("note_utf8", "", 1, bytes(unicode"Hóa đơn 2026-0042 — cảm ơn"));
        (names[6], payNos[6], schemas[6], bodies[6]) =
            ("structured_reference", "INV-2026-0042", 2, abi.encode("RF18539007547034", uint64(1_830_297_600)));
        (names[7], payNos[7], schemas[7], bodies[7]) = ("bound_call", "", 3, abi.encode(uint256(7622),
            bytes32(uint256(uint160(address(0xC0FFEE)))), keccak256("scaas.paymeta.vector.call")));
        (names[8], payNos[8], schemas[8], bodies[8]) = ("encrypted_illustrative", "", 4, _filler(96, 0x04));
    }

    /// "A" and 85 times "€" (3 bytes each): 256 bytes, the last character multi-byte.
    function _euro() internal pure returns (string memory s) {
        s = "A";
        for (uint256 i; i < 85; ++i) s = string.concat(s, unicode"€");
    }

    function _filler(uint256 n, uint8 seed) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; ++i) b[i] = bytes1(uint8(uint256(keccak256(abi.encode(seed, i / 32))) >> (8 * (i % 32))));
    }

    function _rowJson(string memory name, MetaTxLib.PayMeta memory m) internal pure returns (string memory) {
        string memory head = string.concat('  {"name":"', name, '","salt":"', vm.toString(m.salt), '","payNo":"', m.payNo,
            '","schema":', vm.toString(m.schema), ',"body":"', vm.toString(m.body));
        string memory tail = string.concat('","payId":"', vm.toString(PayMetaKit.id(m)), '","accepted":',
            bytes(m.payNo).length <= 256 ? "true" : "false");
        if (keccak256(bytes(name)) == keccak256("payno_only")) {
            tail = string.concat(tail, ',"oldTagPayId":"', vm.toString(keccak256(abi.encodePacked("scaas.pay.meta",
                m.salt, keccak256(abi.encode(m.payNo, m.schema, m.body))))), '"');
        }
        return string.concat(head, tail, "}");
    }

    function test_payMetaVectors() public {
        if (vm.envOr("PAYMETA_WRITE", false)) {
            (string[] memory names, string[] memory payNos, uint16[] memory schemas, bytes[] memory bodies) = _rows();
            string memory j = "[\n";
            for (uint256 i; i < names.length; ++i) {
                MetaTxLib.PayMeta memory m = MetaTxLib.PayMeta(keccak256(abi.encode("scaas.paymeta.v2.vector", names[i])),
                    payNos[i], schemas[i], bodies[i]);
                j = string.concat(j, i == 0 ? "" : ",\n", _rowJson(names[i], m));
            }
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
                vm.parseJsonString(f, string.concat(p, ".payNo")), uint16(vm.parseJsonUint(f, string.concat(p, ".schema"))),
                vm.parseJsonBytes(f, string.concat(p, ".body")));
            bytes32 payId = vm.parseJsonBytes32(f, string.concat(p, ".payId"));
            assertEq(payId, PayMetaKit.id(m), "payId formula");
            for (uint256 k; k < toks.length; ++k) assertEq(MetaTokenBase(toks[k]).metaPayId(m), payId, kinds[k]);
            // each row submitted: an accepted row lands with its `PaymentMeta`, the refused one by name
            MetaTxLib.UAMetaTransfer memory x = _ut(payId, 11, i);
            IUARegistry.UASig memory s = _sigOf(t, x);
            if (!vm.parseJsonBool(f, string.concat(p, ".accepted"))) {
                vm.expectRevert(abi.encodeWithSelector(IMetaTokenV2.PayNoTooLong.selector, bytes(m.payNo).length));
                vm.prank(REL);
                MetaTokenBase(t).mtxPay(x, s, m);
                x.nonce = i; // the lane's next nonce stays `i`: the refused row consumed nothing
                vm.prank(REL);
                MetaTokenBase(t).mtxExecuteTransfer(x, s);
            } else {
                vm.prank(REL);
                MetaTokenBase(t).mtxPay(x, s, m);
            }
            if (vm.keyExistsJson(f, string.concat(p, ".oldTagPayId"))) {
                assertTrue(vm.parseJsonBytes32(f, string.concat(p, ".oldTagPayId")) != payId, "C1: the tags disagree");
            }
        }
    }
}
