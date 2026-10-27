// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {stdJson} from "forge-std/StdJson.sol";
import {ZetherFixture} from "./helpers/ZetherFixture.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// @notice The Rust prover against real tokens (final review P3b m3): `zether-cli` through ffi builds the transfer, the
///         token's statement builder (`ZetherStatements`, the same `ZetherLib` code the token runs) returns the
///         prover's `statement` byte for byte, the prover's calldata settles, the stored form is the prover's and the
///         sender recovers `R` and `s` from storage alone. One cell per stored form, disclosure mode, auditor mode and
///         binding, on BLS12-381 (the bn254 suite is in `legacy/ua6/`). Opt-in, it needs the binary:
///         `cargo build --release --bin zether-cli` (clients/zether-prover), then
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
    function _base(ZetherLayer t) internal view returns (string memory) {
        return string.concat(
            "{", _q("curve", bls ? "bls12381" : "bn254"), ',"key":{', _q("x", vm.toString(bytes32(alice.x))), '},"chainId":',
            vm.toString(block.chainid), ",", _q("chainUid", vm.toString(t.chainUid())), ",", _q("token", vm.toString(address(t)))
        );
    }

    function _token(uint8 d, uint8 a, bool auditor, bytes32 name) internal returns (ZetherLayer t) {
        (dMode, aMode) = (d, a);
        t = _newToken(auditor, name);
        _fund(t, alice, B);
        t.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
    }

    /// @dev The prove request: alice's state, the fee to carol, the modes, `yAud` (null = left out), `extra` fields.
    function _req(ZetherLayer t, string memory dm, string memory am, bool aud, string memory extra)
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
    function _multi(ZetherLayer t, string memory dm, string memory am, bool aud, string memory extra) internal {
        string memory out = _cli("proveTransferMulti", _req(t, dm, am, aud, string.concat(extra, _recipients())));
        ZetherTypes.TransferMode tm = _mode(out.readString(".mode"));
        assertEq(stm.transferStatement(address(t), out.readBytes(".payload"), carol.ua, tm, 0), out.readBytes(".statement"),
            "statement bytes");
        (bool ok, bytes memory ret) = address(t).call(out.readBytes(".directCalldata"));
        assertTrue(ok, "settles");
        _settled(t, out, abi.decode(ret, (bytes32)), tm);
    }

    function _settled(ZetherLayer t, string memory out, bytes32 ref, ZetherTypes.TransferMode tm) internal {
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
    function _recover(ZetherLayer t, bytes32 ref, bytes memory e, ZetherTypes.TransferMode tm) internal returns (string memory) {
        string memory q = string.concat(_base(t), ',"sendCounter":0,"tableBits":18,"boundBits":24,', _q("entry", vm.toString(e)));
        string memory ya = t.auditorKey().length == 0 ? "null" : string.concat('"', vm.toString(t.auditorKey()), '"');
        if (tm == ZetherTypes.TransferMode.BUNDLE) return _cli("recoverTransfer", string.concat(q, ',"yAud":', ya, "}"));
        q = string.concat(q, ",", _q("memo", vm.toString(t.transferMemo(ref))));
        string memory memo = _cli("openMemo", string.concat(q, "}"));
        bytes32[] memory need = memo.readBytes32Array(".needKeys");
        for (uint256 j; j < need.length; ++j) assertEq(need[j], ZetherTypes.UA.unwrap(rs[j].ua), "needKeys");
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
        ZetherLayer t = _token(1, 2, true, "c-opt");
        _public(t, vm.addr(PAYER_PK), 1000);
        MetaTxLib.MetaTransaction memory mt = MetaTxLib.MetaTransaction({
            from: vm.addr(PAYER_PK), data: "", batch: 7, nonce: t.mtxNonce(vm.addr(PAYER_PK), 7),
            validUntil: block.timestamp + 300, mode: MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_FEE_FIXED,
            relayer: relayer, fee: 3, feeRecipient: address(0)
        });
        bytes32 binding = t.envelopeBinding(mt);
        string memory out = _cli("proveTransferMulti", _req(t, "compact", "optional", false,
            string.concat(",", _q("envelopeBinding", vm.toString(binding)), _recipients())));
        assertEq(stm.transferStatement(address(t), out.readBytes(".payload"), carol.ua, ZetherTypes.TransferMode.HASH, binding),
            out.readBytes(".statement"), "relayed statement bytes");
        mt.data = out.readBytes(".directCalldata");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PAYER_PK, t.mtxDigest(mt));
        vm.prank(relayer);
        bytes memory ret = t.mtxExecute(mt, abi.encodePacked(r, s, v));
        _settled(t, out, abi.decode(ret, (bytes32)), ZetherTypes.TransferMode.HASH);
    }

    /// @dev The single format (BUNDLE/FULL): `transferStatementSingle`, the stored record.
    function test_single_bundleFull() public {
        ZetherLayer t = _token(0, 1, true, "s-full");
        string memory out = _cli("proveTransfer", _req(t, "bundle", "full", true,
            string.concat(",", _q("yTo", vm.toString(rs[0].y)), ',"amount":1200')));
        assertEq(stm.transferStatementSingle(address(t), out.readBytes(".payload"), carol.ua, 0), out.readBytes(".statement"),
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
