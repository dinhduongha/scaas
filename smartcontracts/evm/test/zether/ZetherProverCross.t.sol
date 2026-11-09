// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalZetherToken} from "../../src/zether/NormalZetherToken.sol";

import {MtxDigest} from "../helpers/MtxDigest.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ZetherFixture} from "./helpers/ZetherFixture.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";

/// @notice The Rust prover against real tokens (final review P3b m3): `zether-cli` through ffi builds the transfer, the
///         token's statement builder (`ZetherStatements`, the same `ZetherLib` code the token runs) returns the
///         prover's `statement` byte for byte, the prover's calldata settles, the stored form is the prover's and the
///         sender recovers `R` and `s` from storage alone. One cell per stored form, disclosure mode, auditor mode and
///         binding, on BLS12-381 (the bn254 suite is in `legacy/ua6/`). Skipped without the binary (CI's `zether-prover` job has it):
///         `cargo build --release --features hazmat --bin zether-cli` (ARCH-POS-13: the raw commands are test-only) (clients/zether-prover), then
///         `ZETHER_CLI=<path>/zether-cli forge test --ffi --match-path test/zether/ZetherProverCross.t.sol`.
abstract contract ZetherProverCrossSuite is ZetherFixture {
    using stdJson for string;

    uint256 internal constant B = 5000;
    uint256 internal constant PAYER_PK = 0x9A7E5;
    User[3] internal rs;
    uint256[3] internal amts = [uint256(1200), 0, 77];
    uint256 internal dFee; // the per-leg decoyFee of the request (owner 2026-10-20)

    function setUp() public {
        vm.skip(bytes(vm.envOr("ZETHER_CLI", string(""))).length == 0);
        _stack();
        _users();
        for (uint256 i; i < 3; ++i) rs[i] = _user(0xD00 + i, address(uint160(0xE00 + i)));
    }

    function _cli(string memory cmd, string memory req) internal returns (string memory out) {
        string[] memory a = new string[](6);
        (a[0], a[1], a[2]) = ("bash", "-c", "printf '%s' \"$2\" | \"$0\" \"$1\"");
        (a[3], a[4], a[5]) = (vm.envString("ZETHER_CLI"), cmd, req);
        out = string(vm.ffi(a));
        require(bytes(out).length != 0, string.concat(cmd, " failed"));
    }

    function _q(string memory k, string memory v) internal pure returns (string memory) {
        return string.concat('"', k, '":"', v, '"');
    }

    /// @dev curve, alice's key, chainId, chainUid, token.
    function _base(NormalZetherToken t) internal view returns (string memory) {
        return string.concat(
            "{", _q("curve", bls ? "bls12381" : "bn254"), ',"key":{', _q("x", vm.toString(bytes32(alice.x))), '},"chainId":',
            vm.toString(block.chainid), ",", _q("chainUid", vm.toString(t.chainUid())), ",", _q("token", vm.toString(address(t)))
        );
    }

    function _token(uint8 d, uint8 a, bool auditor, bytes32 name) internal returns (NormalZetherToken t) {
        (dMode, aMode) = (d, a);
        t = _newToken(auditor, name);
        _fund(t, alice, B);
        t.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
    }

    /// @dev The prove request: alice's state, the fee to carol, the modes, `yAud` (null = left out), `extra` fields.
    function _req(NormalZetherToken t, string memory dm, string memory am, bool aud, string memory extra)
        internal view returns (string memory)
    {
        IZetherToken.AccountState memory st = t.accountState(alice.ua);
        string memory r = string.concat(
            _base(t), ',"sendCounter":', vm.toString(st.sendCounter), ',"accSeq":', vm.toString(st.accSeq), ",",
            _q("validUntilBlock", vm.toString(vub)), ',"acc":{',
            _q("C", vm.toString(st.accC)), ",", _q("D", vm.toString(st.accD)), '},"balance":', vm.toString(B), ',"fee":',
            vm.toString(FEE), ",", _q("beneficiary", vm.toString(ZetherTypes.UA.unwrap(carol.ua)))
        );
        return string.concat(r, ",", _q("disclosureMode", dm), ",", _q("auditorMode", am), ',"yAud":',
            aud ? string.concat('"', vm.toString(t.auditorKey()), '"') : "null", ',"includeWitness":true', extra, "}");
    }

    function _recipients() internal view returns (string memory r) {
        r = ',"recipients":[';
        for (uint256 j; j < 3; ++j) {
            r = string.concat(r, j == 0 ? "{" : ",{", _q("yTo", vm.toString(rs[j].y)), ',"amount":', vm.toString(amts[j]), "}");
        }
        r = string.concat(r, "]");
    }

    function _mode(string memory m) internal pure returns (ZetherTypes.TransferMode) {
        bytes32 h = keccak256(bytes(m));
        if (h == keccak256("compact")) return ZetherTypes.TransferMode.HASH;
        if (h == keccak256("bundle")) return ZetherTypes.TransferMode.BUNDLE;
        revert("unknown form");
    }

    /// @dev Multi-recipient, direct: statement bytes, settlement, stored form, recovery.
    function _multi(NormalZetherToken t, string memory dm, string memory am, bool aud, string memory extra) internal {
        string memory out = _cli("proveTransferMulti", _req(t, dm, am, aud, string.concat(extra, _recipients())));
        ZetherTypes.TransferMode tm = _mode(out.readString(".mode"));
        assertEq(stm.transferStatement(address(t), _zMulti(out.readBytes(".payload"), carol.ua), tm, 0), out.readBytes(".statement"),
            "statement bytes");
        (bool ok, bytes memory ret) = address(t).call(out.readBytes(".directCalldata"));
        assertTrue(ok, "settles");
        _settled(t, out, abi.decode(ret, (bytes32)), tm);
    }

    function _settled(NormalZetherToken t, string memory out, bytes32 ref, ZetherTypes.TransferMode tm) internal {
        assertEq(ref, out.readBytes32(".entryRef"), "entryRef");
        for (uint256 j; j < 3; ++j) assertTrue(_holds(t, rs[j], amts[j], false), "recipient pending");
        assertTrue(_holds(t, alice, B - 1277 - FEE - 3 * dFee, true), "sender acc");
        for (uint256 j; j < 3; ++j) assertEq(t.balanceOfUA(ZetherTypes.UA.unwrap(rs[j].ua)), dFee * SCALE, "decoyFee per leg");
        bytes memory e = t.transferEntry(ref);
        bytes memory r = out.readBytes(".bundles");
        assertEq(e, r, "stored R (inline or SSTORE2: always from state)");
        if (tm == ZetherTypes.TransferMode.HASH) assertEq(t.transferMemo(ref), out.readBytes(".memo"), "the sender memo");
        string memory rec = _recover(t, ref, e, tm);
        assertEq(rec.readBytes(".bundles"), r, "recovered R");
        assertEq(rec.readBytes32(".s"), out.readBytes32(".witness.s"), "recovered s");
    }

    /// @dev From storage only: the record `R` (`transferEntry`) and, for commit-reveal, the memo (`transferMemo`):
    ///      openMemo (the auditor flag) → recoverTransfer.
    function _recover(NormalZetherToken t, bytes32 ref, bytes memory e, ZetherTypes.TransferMode tm) internal returns (string memory) {
        string memory q = string.concat(_base(t), ',"sendCounter":0,"tableBits":18,"boundBits":24,', _q("entry", vm.toString(e)));
        string memory ya = t.auditorKey().length == 0 ? "null" : string.concat('"', vm.toString(t.auditorKey()), '"');
        if (tm == ZetherTypes.TransferMode.BUNDLE) return _cli("recoverTransfer", string.concat(q, ',"yAud":', ya, "}"));
        q = string.concat(q, ",", _q("memo", vm.toString(t.transferMemo(ref))));
        string memory memo = _cli("openMemo", string.concat(q, "}"));
        for (uint256 j; j < 3; ++j) {
            assertEq(memo.readBytes32(string.concat(".legs[", vm.toString(j), "].toUA")), ZetherTypes.UA.unwrap(rs[j].ua), "legs.toUA");
        }
        if (!memo.readBool(".auditorIncluded")) ya = "null";
        return _cli("recoverTransfer", string.concat(q, ',"yAud":', ya, "}"));
    }

    function test_bundleOptional_default() public {
        _multi(_token(0, 2, true, "b-opt"), "bundle", "optional", true, "");
    }

    /// A decoy fee of 3 per leg on a `minDecoyFee = 2` token: the prover's payload word and fee word are the token's.
    function test_bundleOptional_decoyFee() public {
        minDecoy = 2;
        dFee = 3;
        _multi(_token(0, 2, true, "b-dec"), "bundle", "optional", true, ',"decoyFee":3,"minDecoyFee":2');
    }

    function test_bundleNone_auditorOff() public {
        _multi(_token(0, 0, false, "b-none"), "bundle", "none", false, "");
    }

    function test_bundleFull_compact() public {
        _multi(_token(0, 1, true, "b-full"), "bundle", "full", true, ',"mode":"compact"');
    }

    /// @dev COMPACT/OPTIONAL, auditor left out, relayed: the statement with the envelope binding, settled by `mtxExecute`.
    function test_compactOptional_relayed_optOut() public {
        NormalZetherToken t = _token(1, 2, true, "c-opt");
        _public(t, vm.addr(PAYER_PK), 1000);
        MetaTxLib.MetaTransaction memory mt = MetaTxLib.MetaTransaction({
            from: vm.addr(PAYER_PK), data: "", batch: 7, nonce: t.mtxNonce(MetaTxLib.pad(vm.addr(PAYER_PK)), 7),
            validUntil: block.timestamp + 300, mode: MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_FEE_FIXED,
            relayer: relayer, fee: 3, feeRecipient: address(0)
        });
        bytes32 binding = _addrBinding(t, mt);
        string memory out = _cli("proveTransferMulti", _req(t, "compact", "optional", false,
            string.concat(",", _q("envelopeBinding", vm.toString(binding)), ',"uaSigner":"ecdsa"', _recipients())));
        assertEq(stm.transferStatement(address(t), _zMulti(out.readBytes(".payload"), carol.ua), ZetherTypes.TransferMode.HASH, binding),
            out.readBytes(".statement"), "relayed statement bytes");
        mt.data = out.readBytes(".directCalldata");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PAYER_PK, MtxDigest.metaTx(address(t), mt));
        vm.prank(relayer);
        // ua-mtx-merge T1, meaning: `executeMetaTransaction` (R3) returns `true`, not the self-call's entryRef; the
        // prover's ref is checked against the contract's storage there (`_settled` reads `transferEntry(ref)`)
        assertTrue(t.executeMetaTransaction(mt, abi.encodePacked(r, s, v)));
        _settled(t, out, out.readBytes32(".entryRef"), ZetherTypes.TransferMode.HASH);
    }

    // ------------------------------------------------------------------ the prover's `namedCall` settles on the merged entries

    /// @dev The `UAEnvelope` fields of the next relayed op of `from` (the `data` filled by the caller).
    function _envMt(bytes32 from, NormalZetherToken t, uint32 mode, uint256 fee) internal view returns (MetaTxLib.UAMetaTransaction memory) {
        return MetaTxLib.UAMetaTransaction({
            from: from, data: "", batch: 7, nonce: t.mtxNonce(from, 7), validUntil: block.timestamp + 300, mode: mode,
            relayer: relayer, fee: fee, feeRecipient: address(0)
        });
    }

    /// @dev The payer EOA's envelope: relayer bound, a fixed fee of 3.
    function _payerMt(NormalZetherToken t) internal view returns (MetaTxLib.UAMetaTransaction memory) {
        return _envMt(MetaTxLib.pad(vm.addr(PAYER_PK)), t, MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_FEE_FIXED, 3);
    }

    function _n(string memory k, uint256 v) private pure returns (string memory) {
        return string.concat('"', k, '":"', vm.toString(v), '"');
    }

    function _envJson(MetaTxLib.UAMetaTransaction memory m) private pure returns (string memory) {
        return string.concat(
            '"env":{', _q("from", vm.toString(m.from)), ",", _n("batch", m.batch), ",", _n("nonce", m.nonce), ",", _n("validUntil", m.validUntil),
            ",", _n("mode", m.mode), ",", _q("relayer", vm.toString(m.relayer)), ",", _n("fee", m.fee), ",",
            _q("feeRecipient", vm.toString(m.feeRecipient)), "}"
        );
    }

    /// @dev The prover's `uaEnvelope` of `m` (R35): its binding equals the token's `envelopeBinding` view and its digest the
    ///      token's `mtxDigest`; returned as the `envelopeBinding` field of a prove request.
    function _uaBinding(NormalZetherToken t, MetaTxLib.UAMetaTransaction memory m) internal returns (string memory) {
        string memory out = string.concat(
            '{"chainId":', vm.toString(block.chainid), ",", _q("chainUid", vm.toString(t.chainUid())), ",", _q("token", vm.toString(address(t))),
            ',"meta":{', _q("from", vm.toString(m.from)), ",", _q("data", vm.toString(m.data)), ",", _q("batch", vm.toString(bytes32(m.batch))));
        out = string.concat(out, ',"nonce":', vm.toString(m.nonce), ',"validUntil":', vm.toString(m.validUntil), ',"mode":', vm.toString(m.mode), ",",
            _q("relayer", vm.toString(m.relayer)), ',"fee":', vm.toString(m.fee));
        out = _cli("uaEnvelope", string.concat(out, ",", _q("feeRecipient", vm.toString(m.feeRecipient)), "}}"));
        bytes32 b = out.readBytes32(".binding");
        assertEq(b, t.envelopeBinding(m), "the prover's UA binding is the token's envelopeBinding");
        assertEq(out.readBytes32(".digest"), t.mtxDigest(m), "the prover's UAMetaTransaction digest is the token's mtxDigest");
        return string.concat(",", _q("envelopeBinding", vm.toString(b)));
    }

    function _namedReq(NormalZetherToken t, string memory op, MetaTxLib.UAMetaTransaction memory m, string memory out, string memory extra)
        private view returns (string memory)
    {
        string memory head = string.concat(
            '{"op":"', op, '","chainId":', vm.toString(block.chainid), ",", _q("chainUid", vm.toString(t.chainUid())), ",",
            _q("token", vm.toString(address(t))), ",", _envJson(m)
        );
        return string.concat(
            head, ",", _q("payload", vm.toString(out.readBytes(".payload"))), ",", _q("proof", vm.toString(out.readBytes(".proof"))), ",",
            _q("beneficiary", vm.toString(ZetherTypes.UA.unwrap(carol.ua))), extra
        );
    }

    /// @dev `namedCall` through the real binary: the digest it returns, signed by the payer's EOA here (`sig` raw: `UASig{signature}`),
    ///      then the merged entry's calldata.
    function _named(NormalZetherToken t, string memory op, MetaTxLib.UAMetaTransaction memory m, string memory out, string memory extra)
        internal returns (bytes memory)
    {
        string memory q = _namedReq(t, op, m, out, extra);
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(PAYER_PK, _cli("namedCall", string.concat(q, "}")).readBytes32(".digest"));
        return _cli("namedCall", string.concat(q, ',"sig":"', vm.toString(abi.encodePacked(r, sg, v)), '"}')).readBytes(".calldata");
    }

    /// @dev One changed byte in a signed field (the `validUntil` word of the envelope) is refused (`MetaTxBadSignature` for a native
    ///      payer); the good call then settles, the nonce of `from` consumed.
    function _settleNamed(NormalZetherToken t, bytes memory cd, bytes32 from, bytes4 refusal) internal returns (bytes memory ret) {
        bytes memory bad = abi.encodePacked(cd);
        bad[4 + 32 * 3 + 31] = bytes1(uint8(bad[4 + 32 * 3 + 31]) ^ 1);
        vm.prank(relayer);
        if (refusal != bytes4(0)) vm.expectRevert(refusal);
        (bool badOk,) = address(t).call(bad);
        if (refusal == bytes4(0)) assertFalse(badOk, "a changed signed field is refused");
        assertEq(t.mtxNonce(from, 7), 0, "nothing consumed by the refusal");
        vm.prank(relayer);
        bool ok;
        (ok, ret) = address(t).call(cd);
        assertTrue(ok, "the good call settles");
        assertEq(t.mtxNonce(from, 7), 1, "nonce consumed");
    }

    function _settlePayer(NormalZetherToken t, bytes memory cd) internal returns (bytes memory ret) {
        address payer = vm.addr(PAYER_PK);
        ret = _settleNamed(t, cd, MetaTxLib.pad(payer), IMetaTx.MetaTxBadSignature.selector);
        assertEq(t.balanceOf(payer), 1000 - 3, "relay fee paid");
    }

    /// @dev ua-mtx-merge T12 (R35): the prover's UA binding and `UAMetaTransaction` digest equal the token's views for a native
    ///      (padded) and a derived subject; the address binding of `executeMetaTransaction` is another word.
    function test_uaEnvelopeEqualsTheToken() public {
        NormalZetherToken t = _token(0, 2, true, "u-env");
        MetaTxLib.UAMetaTransaction memory m = _payerMt(t);
        m.data = hex"deadbeef";
        _uaBinding(t, m);
        MetaTxLib.MetaTransaction memory a = MetaTxLib.MetaTransaction(vm.addr(PAYER_PK), m.data, m.batch, m.nonce, m.validUntil,
            m.mode, m.relayer, m.fee, m.feeRecipient);
        assertTrue(_addrBinding(t, a) != t.envelopeBinding(m), "the address tag is not the UA tag");
        m = _envMt(ZetherTypes.UA.unwrap(alice.ua), t, 0, 0);
        m.data = hex"beef";
        _uaBinding(t, m);
    }

    /// @dev Relayed `mtxConfidentialTransferCompact(UAEnvelope, …, UASig)` (multi, commit-reveal) on a COMPACT token.
    function test_named_multi_relayed() public {
        NormalZetherToken t = _token(1, 2, true, "n-multi");
        _public(t, vm.addr(PAYER_PK), 1000);
        MetaTxLib.UAMetaTransaction memory m = _payerMt(t);
        string memory out = _cli("proveTransferMulti", _req(t, "compact", "optional", false,
            string.concat(_uaBinding(t, m), ',"uaSigner":"ecdsa"', _recipients())));
        bytes memory ret = _settlePayer(t, _named(t, "UAZetherTransferCompact", m, out, ""));
        _settled(t, out, abi.decode(ret, (bytes32)), ZetherTypes.TransferMode.HASH);
    }

    /// @dev Relayed `mtxConfidentialTransferSingle(UAEnvelope, …, UASig)` (BUNDLE / FULL): balances and the stored record.
    function test_named_single_relayed() public {
        NormalZetherToken t = _token(0, 1, true, "n-single");
        _public(t, vm.addr(PAYER_PK), 1000);
        MetaTxLib.UAMetaTransaction memory m = _payerMt(t);
        string memory out = _cli("proveTransfer", _req(t, "bundle", "full", true, string.concat(
            _uaBinding(t, m), ',"uaSigner":"ecdsa",', _q("yTo", vm.toString(rs[0].y)), ',"amount":1200')));
        bytes32 ref = abi.decode(_settlePayer(t, _named(t, "UAZetherTransferSingle", m, out, "")), (bytes32));
        assertEq(ref, out.readBytes32(".entryRef"), "entryRef");
        assertEq(t.transferEntry(ref), out.readBytes(".record"), "single record");
        assertTrue(_holds(t, rs[0], 1200, false), "recipient pending");
    }

    /// @dev Relayed `mtxUnshield(UAEnvelope, …, UASig)`: the recipient is credited `amount * shieldScale` public units.
    function test_named_unshield_relayed() public {
        NormalZetherToken t = _token(0, 2, true, "n-unshield");
        address to = address(0xAB1E);
        _public(t, vm.addr(PAYER_PK), 1000);
        MetaTxLib.UAMetaTransaction memory m = _payerMt(t);
        string memory out = _cli("proveBurn", _req(t, "bundle", "optional", false, string.concat(
            _uaBinding(t, m), ',"amount":100,', _q("recipient", vm.toString(to)))));
        _settlePayer(t, _named(t, "UAZetherUnshield", m, out, string.concat(
            ',"amount":100,', _q("recipient", vm.toString(MetaTxLib.pad(to))))));
        assertEq(t.balanceOf(to), 100 * SCALE, "recipient credited");
    }

    /// @dev A derived subject (R35): alice's Zether UA relays her own single transfer, fee 0, signed through the prover (`uaSig`,
    ///      purpose `metatx`: the registry's `requireAuthorized` message), `sig` as the explicit `UASig` object.
    function test_named_single_relayed_derived() public {
        NormalZetherToken t = _token(0, 1, true, "n-derived");
        bytes32 a = ZetherTypes.UA.unwrap(alice.ua);
        MetaTxLib.UAMetaTransaction memory m = _envMt(a, t, 0, 0);
        string memory out = _cli("proveTransfer", _req(t, "bundle", "full", true, string.concat(
            _uaBinding(t, m), ',"uaSigner":"ecdsa",', _q("yTo", vm.toString(rs[0].y)), ',"amount":1200')));
        string memory q = _namedReq(t, "UAZetherTransferSingle", m, out, "");
        bytes32 d = _cli("namedCall", string.concat(q, "}")).readBytes32(".digest");
        string memory sig = _cli("uaSig", string.concat('{"curve":"bls12381","key":{', _q("x", vm.toString(bytes32(alice.x))), "},",
            _q("purpose", "metatx"), ",", _q("digest", vm.toString(d)), "}")).readString(".sig");
        bytes memory cd = _cli("namedCall", string.concat(q, ',"sig":{', _q("keyData", "0x"), ",", _q("signature", sig), ',"members":[]}}'))
            .readBytes(".calldata");
        bytes32 ref = abi.decode(_settleNamed(t, cd, a, bytes4(0)), (bytes32));
        assertEq(ref, out.readBytes32(".entryRef"), "entryRef");
        assertTrue(_holds(t, rs[0], 1200, false), "recipient pending");
    }

    /// @dev Typed-signing C3 review T3: the token's builder from the explicit struct against the prover, for every recipient count that
    ///      changes the statement's shape, every auditor setting and both forms; bytes only (`_settled` knows three legs). M stops at 7,
    ///      the most every cell can send: the prover refuses M = 8 in the dearest form (EIP-7825 cap, `check_gas`).
    function test_statementDifferential() public {
        NormalZetherToken none = _token(0, 0, false, "d-none");
        NormalZetherToken opt = _token(0, 2, true, "d-opt");
        NormalZetherToken full = _token(0, 1, true, "d-full");
        uint256[5] memory ms = [uint256(1), 2, 3, 4, 7];
        string memory r = ',"recipients":[';
        uint256 done;
        for (uint256 k; k < ms.length; ++k) {
            for (; done < ms[k]; ++done) {
                User memory u = _user(0xE00 + done, address(uint160(0xF00 + done)));
                r = string.concat(r, done == 0 ? "{" : ",{", _q("yTo", vm.toString(u.y)), ',"amount":1}');
            }
            string memory legs = string.concat(r, "]");
            _statement(none, "none", false, legs);
            _statement(opt, "optional", false, legs);
            _statement(opt, "optional", true, legs);
            _statement(full, "full", true, legs);
        }
    }

    function _statement(NormalZetherToken t, string memory am, bool aud, string memory legs) internal {
        string[2] memory forms = ["bundle", "compact"];
        for (uint256 f; f < 2; ++f) {
            string memory out = _cli("proveTransferMulti", _req(t, "bundle", am, aud, string.concat(",", _q("mode", forms[f]), legs)));
            assertEq(out.readString(".mode"), forms[f], "form");
            assertEq(stm.transferStatement(address(t), _zMulti(out.readBytes(".payload"), carol.ua), _mode(forms[f]), 0),
                out.readBytes(".statement"), string.concat("statement ", am, " ", forms[f]));
        }
    }

    /// @dev The single format (BUNDLE/FULL): `transferStatementSingle`, the stored record.
    function test_single_bundleFull() public {
        NormalZetherToken t = _token(0, 1, true, "s-full");
        string memory out = _cli("proveTransfer", _req(t, "bundle", "full", true,
            string.concat(",", _q("yTo", vm.toString(rs[0].y)), ',"amount":1200')));
        assertEq(stm.transferStatementSingle(address(t), _zSingle(out.readBytes(".payload"), carol.ua), 0), out.readBytes(".statement"),
            "single statement bytes");
        (bool ok, bytes memory ret) = address(t).call(out.readBytes(".directCalldata"));
        assertTrue(ok, "settles");
        bytes32 ref = abi.decode(ret, (bytes32));
        assertEq(ref, out.readBytes32(".entryRef"));
        assertEq(t.transferEntry(ref), out.readBytes(".record"), "single record");
        assertTrue(_holds(t, rs[0], 1200, false));
        assertEq(_recover(t, ref, t.transferEntry(ref), ZetherTypes.TransferMode.BUNDLE).readBytes32(".s"),
            out.readBytes32(".witness.s"));
    }
}

contract ZetherProverCrossBls12381Test is ZetherProverCrossSuite {}
