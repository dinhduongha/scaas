// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20Payment} from "../../src/metatx/IERC20Payment.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IRig, PlainRig, PqzRig, ZetherRig} from "./MetaTxParity.t.sol";

/// @notice CTR-MTX-26 (metatx split T7, spec §6.1, R11): `mtxPayMeta` / `uaPayMeta` are `mtxPay` / `uaPay` with
///         `payId = metaPayId(salt, meta)` — the same digest, lane `payLane(payId)`, nonce 0 — and emit
///         `PaymentMeta(payId, meta)` before `PaymentSettled`. Run on a clone of every token kind (the parity rigs:
///         `NORMAL`, `WRAPPED`, `NORMAL` with the ledger off, both PQZ and both Zether kinds; the signer of every rig is
///         `0xA11CE`). `test_payMetaVectors` writes (`PAYMETA_WRITE=1`) or checks `../vectors/metatx/paymeta.json`, the
///         vectors every other family and `clientkeys` read.
contract PayMetaTest is Test {
    uint256 internal constant PK = 0xA11CE;
    address internal constant REL = address(0x7E1A);
    address internal constant PAYEE = address(0xB0B5);
    address internal constant FEE_TO = address(0xFEE5);
    uint32 internal constant MODE = MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT
        | MetaTxLib.MODE_FEE_FIXED;
    uint256 internal constant FEE = 5;
    uint256 internal constant AMOUNT = 1_000;
    // AdminLib's ERC-7201 `scaas.token`: slot 0 of `TokenStorage` is `features`
    bytes32 internal constant TOKEN_STORAGE = 0x83083067f3d1caf66741d4eeefa9d3f4f0e5b0793677731d6fee7e67b774ac00;
    string internal constant FILE = "../vectors/metatx/paymeta.json";

    address internal signer = vm.addr(PK);
    string[] internal kinds;
    address[] internal toks;

    function setUp() public {
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

    // ------------------------------------------------------------------ helpers

    function _ecdsa(bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, d);
        return abi.encodePacked(r, s, v);
    }

    function _meta(uint256 i) internal pure returns (bytes32 salt, bytes memory meta) {
        salt = keccak256(abi.encode("paymeta.test.salt", i));
        meta = abi.encode(uint16(1), bytes(string.concat("invoice ", vm.toString(i))));
    }

    function _payId(bytes32 salt, bytes memory meta) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("scaas.pay.meta", salt, keccak256(meta)));
    }

    function _tr(address t, bytes32 payId) internal view returns (MetaTxLib.MetaTransfer memory) {
        return MetaTxLib.MetaTransfer(signer, PAYEE, AMOUNT, payId, MetaTokenBase(t).payLane(payId), 0,
            block.timestamp + 300, MODE, REL, FEE, FEE_TO);
    }

    function _ut(address t, bytes32 payId) internal view returns (MetaTxLib.UAMetaTransfer memory) {
        return MetaTxLib.UAMetaTransfer(MetaTxLib.pad(signer), MetaTxLib.pad(PAYEE), AMOUNT, payId,
            MetaTokenBase(t).payLane(payId), 0, block.timestamp + 300, MODE, REL, FEE, FEE_TO);
    }

    function _payMeta(address t, bytes32 salt, bytes memory meta, uint256 vu, bytes memory sig) internal {
        vm.prank(REL);
        MetaTokenBase(t).mtxPayMeta(signer, PAYEE, AMOUNT, salt, meta, vu, MODE, REL, FEE, FEE_TO, sig);
    }

    function _uaPayMeta(address t, bytes32 salt, bytes memory meta, uint256 vu, bytes memory auth) internal {
        vm.prank(REL);
        MetaTokenBase(t).uaPayMeta(MetaTxLib.pad(signer), MetaTxLib.pad(PAYEE), AMOUNT, salt, meta, vu, MODE, REL,
            FEE, FEE_TO, auth);
    }

    function _hasLedger(address t) internal view returns (bool) {
        return IERC165(t).supportsInterface(type(IUALedger).interfaceId);
    }

    /// The index of the first log of `t` with `topic0`; reverts when there is none.
    function _find(Vm.Log[] memory logs, address t, bytes32 topic0) internal pure returns (uint256) {
        for (uint256 i; i < logs.length; ++i) if (logs[i].emitter == t && logs[i].topics[0] == topic0) return i;
        revert("event not emitted");
    }

    /// `PaymentMeta(payId, meta)` emitted, before `settled`; the executed event carries lane `lane`, nonce 0, digest `d`.
    function _checkLogs(address t, bytes32 payId, bytes memory meta, bool ua, uint256 lane, bytes32 d, uint256 i)
        internal
    {
        string memory kind = kinds[i];
        bytes32 settled = ua ? IUALedger.UAPaymentSettled.selector : IERC20Payment.PaymentSettled.selector;
        bytes32 executed = ua ? IUALedger.UAMetaTransactionExecuted.selector : IMetaTx.MetaTransactionExecuted.selector;
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 pm = _find(logs, t, IMetaTokenV2.PaymentMeta.selector);
        assertEq(logs[pm].topics[1], payId, kind);
        assertEq(logs[pm].data, abi.encode(meta), kind);
        uint256 ps = _find(logs, t, settled);
        assertLt(pm, ps, string.concat(kind, ": PaymentMeta before PaymentSettled"));
        assertEq(logs[ps].topics[logs[ps].topics.length - 1], payId, string.concat(kind, ": entryRef = payId"));
        uint256 ex = _find(logs, t, executed);
        assertEq(uint256(logs[ex].topics[3]), lane, string.concat(kind, ": lane payLane(payId)"));
        (uint256 nonce, bytes32 digest,,) = abi.decode(logs[ex].data, (uint256, bytes32, address, uint256));
        assertEq(nonce, 0, string.concat(kind, ": nonce 0"));
        assertEq(digest, d, string.concat(kind, ": the mtxPay digest"));
    }

    // ------------------------------------------------------------------ the entries

    /// The `mtxPay` signature over `payId = metaPayId(salt, meta)` settles through `mtxPayMeta` (and, in a snapshot,
    /// through `mtxPay` itself): one digest, lane `payLane(payId)`, nonce 0.
    function test_payMeta_settlesLikeMtxPay() public {
        for (uint256 i; i < toks.length; ++i) _settles(i);
    }

    function _settles(uint256 i) internal {
        address t = toks[i];
        (bytes32 salt, bytes memory meta) = _meta(i);
        MetaTxLib.MetaTransfer memory x = _tr(t, _payId(salt, meta));
        assertEq(MetaTokenBase(t).metaPayId(salt, meta), x.entryRef, kinds[i]);
        bytes32 d = MetaTokenBase(t).mtxTransferDigest(x);
        uint256 snap = vm.snapshotState();
        vm.prank(REL);
        MetaTokenBase(t).mtxPay(signer, PAYEE, AMOUNT, x.entryRef, x.validUntil, MODE, REL, FEE, FEE_TO, _ecdsa(d));
        vm.revertToState(snap);
        vm.recordLogs();
        _payMeta(t, salt, meta, x.validUntil, _ecdsa(d));
        _checkLogs(t, x.entryRef, meta, false, x.batch, d, i);
        assertEq(MetaTokenBase(t).mtxNonce(signer, x.batch), 1, kinds[i]);
        assertEq(MetaTokenBase(t).balanceOf(PAYEE), AMOUNT, kinds[i]);
        assertEq(MetaTokenBase(t).balanceOf(FEE_TO), FEE, kinds[i]);
    }

    function test_uaPayMeta_settlesLikeUaPay() public {
        uint256 n;
        for (uint256 i; i < toks.length; ++i) {
            if (!_hasLedger(toks[i])) continue;
            ++n;
            _uaSettles(i);
        }
        assertEq(n, 6, "every kind with its ledger on");
    }

    function _uaSettles(uint256 i) internal {
        address t = toks[i];
        (bytes32 salt, bytes memory meta) = _meta(100 + i);
        MetaTxLib.UAMetaTransfer memory x = _ut(t, _payId(salt, meta));
        bytes32 d = MetaTokenBase(t).uaTransferDigest(x);
        uint256 snap = vm.snapshotState();
        vm.prank(REL);
        MetaTokenBase(t).uaPay(x.from, x.to, AMOUNT, x.entryRef, x.validUntil, MODE, REL, FEE, FEE_TO, _ecdsa(d));
        vm.revertToState(snap);
        vm.recordLogs();
        _uaPayMeta(t, salt, meta, x.validUntil, _ecdsa(d));
        _checkLogs(t, x.entryRef, meta, true, x.batch, d, i);
        assertEq(MetaTokenBase(t).uaNonce(x.from, x.batch), 1, kinds[i]);
        assertEq(MetaTokenBase(t).balanceOf(PAYEE), AMOUNT, kinds[i]);
        assertEq(MetaTokenBase(t).balanceOf(FEE_TO), FEE, kinds[i]);
    }

    /// A signature over another `payId` is refused; a second pay-meta of the same `(from, payId)` finds nonce 1.
    function test_payMeta_mismatchAndReplayRefused() public {
        for (uint256 i; i < toks.length; ++i) {
            _mismatch(i);
            if (_hasLedger(toks[i])) _uaMismatch(i);
        }
    }

    bytes internal constant OTHER = abi.encode(uint16(1), bytes("another invoice"));

    function _mismatch(uint256 i) internal {
        address t = toks[i];
        (bytes32 salt, bytes memory meta) = _meta(200 + i);
        uint256 vu = block.timestamp + 300;
        bytes memory bad = _ecdsa(MetaTokenBase(t).mtxTransferDigest(_tr(t, _payId(salt, OTHER))));
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        MetaTokenBase(t).mtxPayMeta(signer, PAYEE, AMOUNT, salt, meta, vu, MODE, REL, FEE, FEE_TO, bad);
        bytes memory sig = _ecdsa(MetaTokenBase(t).mtxTransferDigest(_tr(t, _payId(salt, meta))));
        // the valid signature with another salt: another payId
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        MetaTokenBase(t).mtxPayMeta(signer, PAYEE, AMOUNT, ~salt, meta, vu, MODE, REL, FEE, FEE_TO, sig);
        _payMeta(t, salt, meta, vu, sig);
        vm.prank(REL);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        MetaTokenBase(t).mtxPayMeta(signer, PAYEE, AMOUNT, salt, meta, vu, MODE, REL, FEE, FEE_TO, sig);
        // nor through plain `mtxPay`: one lane
        vm.prank(REL);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        MetaTokenBase(t).mtxPay(signer, PAYEE, AMOUNT, _payId(salt, meta), vu, MODE, REL, FEE, FEE_TO, sig);
    }

    function _uaMismatch(uint256 i) internal {
        address t = toks[i];
        (bytes32 salt, bytes memory meta) = _meta(300 + i);
        uint256 vu = block.timestamp + 300;
        bytes memory bad = _ecdsa(MetaTokenBase(t).uaTransferDigest(_ut(t, _payId(salt, OTHER))));
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        MetaTokenBase(t).uaPayMeta(MetaTxLib.pad(signer), MetaTxLib.pad(PAYEE), AMOUNT, salt, meta, vu, MODE, REL,
            FEE, FEE_TO, bad);
        bytes memory auth = _ecdsa(MetaTokenBase(t).uaTransferDigest(_ut(t, _payId(salt, meta))));
        vm.prank(REL);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        MetaTokenBase(t).uaPayMeta(MetaTxLib.pad(signer), MetaTxLib.pad(PAYEE), AMOUNT, ~salt, meta, vu, MODE, REL,
            FEE, FEE_TO, auth);
        _uaPayMeta(t, salt, meta, vu, auth);
        vm.prank(REL);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        MetaTokenBase(t).uaPayMeta(MetaTxLib.pad(signer), MetaTxLib.pad(PAYEE), AMOUNT, salt, meta, vu, MODE, REL,
            FEE, FEE_TO, auth);
    }

    /// Pay, so `PAYABLE` gates both (CTR-TOK-22). `PAYABLE` is always locked, so the bit is cleared in storage.
    function test_payMeta_requiresPayable() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            uint256 f = uint256(vm.load(t, TOKEN_STORAGE));
            assertEq(f & (1 << AdminLib.PAYABLE), 1 << AdminLib.PAYABLE, kinds[i]);
            vm.store(t, TOKEN_STORAGE, bytes32(f & ~uint256(1 << AdminLib.PAYABLE)));
            (bytes32 salt, bytes memory meta) = _meta(400 + i);
            bytes memory err = abi.encodeWithSelector(ITokenAdmin.FeatureNotSet.selector, AdminLib.PAYABLE);
            vm.expectRevert(err);
            MetaTokenBase(t).mtxPayMeta(signer, PAYEE, AMOUNT, salt, meta, block.timestamp + 1, MODE, REL, FEE, FEE_TO, "");
            vm.expectRevert(err);
            MetaTokenBase(t).uaPayMeta(MetaTxLib.pad(signer), MetaTxLib.pad(PAYEE), AMOUNT, salt, meta,
                block.timestamp + 1, MODE, REL, FEE, FEE_TO, "");
        }
    }

    // ------------------------------------------------------------------ the shared vectors

    /// `(name, schema, salt, meta, payId, payLane)`; `meta = abi.encode(uint16 schema, bytes body)`, the body in the
    /// encoding of its schema as docs/contracts/metatx.md CTR-MTX-26 fixes it (the contract never parses it). The
    /// schema 4 bodies are illustrative filler; `long_body_4096` is a hash vector only, never submitted on chain.
    function _rows() internal pure returns (string[] memory names, uint16[] memory schemas, bytes[] memory bodies) {
        names = new string[](6);
        schemas = new uint16[](6);
        bodies = new bytes[](6);
        (names[0], schemas[0], bodies[0]) = ("note_utf8", 1, bytes(unicode"Hóa đơn 2026-0042 — cảm ơn"));
        (names[1], schemas[1], bodies[1]) =
            ("structured_reference", 2, abi.encode("RF18539007547034", "INV-2026-0042", uint64(1_830_297_600)));
        (names[2], schemas[2], bodies[2]) =
            ("bound_call", 3, abi.encode(uint256(7622), bytes32(uint256(uint160(address(0xC0FFEE)))),
                keccak256(abi.encodeCall(IMetaTx.cancelNonce, (7)))));
        (names[3], schemas[3], bodies[3]) = ("encrypted_illustrative", 4, _filler(96, 0x04));
        (names[4], schemas[4], bodies[4]) = ("empty_body", 1, bytes(""));
        (names[5], schemas[5], bodies[5]) = ("long_body_4096", 4, _filler(4096, 0x45));
    }

    function _filler(uint256 n, uint8 seed) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; ++i) b[i] = bytes1(uint8(uint256(keccak256(abi.encode(seed, i / 32))) >> (8 * (i % 32))));
    }

    function _row(MetaTokenBase t0, string memory name, uint16 schema, bytes32 salt, bytes memory meta)
        internal view returns (string memory)
    {
        bytes32 payId = t0.metaPayId(salt, meta);
        string memory head = string.concat('  {"name":"', name, '","schema":', vm.toString(schema), ',"salt":"',
            vm.toString(salt), '","meta":"', vm.toString(meta));
        return string.concat(head, '","payId":"', vm.toString(payId), '","payLane":"',
            vm.toString(bytes32(t0.payLane(payId))), '"}');
    }

    function test_payMetaVectors() public {
        MetaTokenBase t0 = MetaTokenBase(toks[0]);
        if (vm.envOr("PAYMETA_WRITE", false)) {
            (string[] memory names, uint16[] memory schemas, bytes[] memory bodies) = _rows();
            string memory j = "[\n";
            for (uint256 i; i < names.length; ++i) {
                bytes32 salt = keccak256(abi.encode("scaas.paymeta.vector", names[i]));
                bytes memory meta = abi.encode(schemas[i], bodies[i]);
                j = string.concat(j, i == 0 ? "" : ",\n", _row(t0, names[i], schemas[i], salt, meta));
            }
            vm.writeFile(FILE, string.concat(j, "\n]\n"));
        }
        string memory f = vm.readFile(FILE);
        uint256 rows;
        while (vm.keyExistsJson(f, string.concat("[", vm.toString(rows), "]"))) ++rows;
        assertEq(rows, 6, "rows");
        for (uint256 i; i < rows; ++i) {
            string memory p = string.concat("[", vm.toString(i), "]");
            bytes32 salt = vm.parseJsonBytes32(f, string.concat(p, ".salt"));
            bytes memory meta = vm.parseJsonBytes(f, string.concat(p, ".meta"));
            bytes32 payId = vm.parseJsonBytes32(f, string.concat(p, ".payId"));
            (uint16 schema,) = abi.decode(meta, (uint16, bytes));
            assertEq(schema, vm.parseJsonUint(f, string.concat(p, ".schema")), "schema");
            assertEq(payId, _payId(salt, meta), "payId formula");
            for (uint256 k; k < toks.length; ++k) {
                assertEq(MetaTokenBase(toks[k]).metaPayId(salt, meta), payId, kinds[k]);
                assertEq(bytes32(MetaTokenBase(toks[k]).payLane(payId)),
                    vm.parseJsonBytes32(f, string.concat(p, ".payLane")), kinds[k]);
            }
        }
    }
}
