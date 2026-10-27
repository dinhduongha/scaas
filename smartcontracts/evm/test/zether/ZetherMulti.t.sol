// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2, Vm} from "forge-std/Test.sol";
import {IConfidentialToken} from "../../src/confidential/IConfidentialToken.sol";
import {ZetherFixture} from "./helpers/ZetherFixture.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ITransferDisclosure} from "../../src/zether/ITransferDisclosure.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {ZetherProver} from "./helpers/ZetherProver.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";

/// @notice Multi-recipient transfers (CTR-ZTH-37/38) on a `NONE_ZETHER` token: effects, refusals, disclosure in the
///         three modes and the gas table M ∈ {1, 2, 4, 8} × {HASH, BUNDLE, NONE}, on BLS12-381 (the bn254 suite is in `legacy/ua6/`).
abstract contract ZetherMultiSuite is ZetherFixture {
    User[8] internal rs;

    function setUp() public {
        _deploy(true);
        for (uint256 i; i < 8; ++i) rs[i] = _user(0xD00 + i, address(uint160(0xE00 + i)));
    }

    // ------------------------------------------------------------------ tiện ích

    function _to(uint256 m) internal view returns (User[] memory to) {
        to = new User[](m);
        for (uint256 j; j < m; ++j) to[j] = rs[j];
    }

    function _send(ZetherLayer t, ZetherTypes.TransferMode mode, Tx memory x, ZetherTypes.UA ben) internal returns (bytes32) {
        if (mode == ZetherTypes.TransferMode.HASH) return t.mtxConfidentialTransferCompact(x.payload, x.proof, "", ZetherTypes.UA.unwrap(ben), "");
        return t.mtxConfidentialTransfer(x.payload, x.proof, "", ZetherTypes.UA.unwrap(ben), "");
    }

    function _selector(ZetherTypes.TransferMode mode) internal pure returns (bytes4) {
        if (mode == ZetherTypes.TransferMode.HASH) return ZetherLayer.mtxConfidentialTransferCompact.selector;
        return ZetherLayer.mtxConfidentialTransfer.selector;
    }

    function _modeName(ZetherTypes.TransferMode mode) internal pure returns (string memory) {
        return mode == ZetherTypes.TransferMode.HASH ? "HASH" : "BUNDLE";
    }

    function _cut(bytes memory a, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) out[i] = a[off + i];
    }

    /// @dev `R = salt ‖ B_1 ‖ … ‖ B_M` dựng lại từ payload (đúng thứ một client đọc được từ calldata).
    function _bundlesOf(bytes memory payload) internal view returns (bytes memory b) {
        uint256 p = ver.g1EncodedBytes();
        uint256 m = uint256(bytes32(_cut(payload, 112, 32)));
        bytes memory dOut = _cut(payload, 176 + p, p);
        b = _cut(payload, 96, 16);
        for (uint256 j; j < m; ++j) {
            uint256 o = _legAt(j);
            b = bytes.concat(b, _cut(payload, o, 2 * p), dOut, _cut(payload, o + 2 * p, 2 * p)); // Y_t C_out D_out C_aud D_aud
        }
    }

    /// @dev Where leg `j` (`Y_tj ‖ C_out_j ‖ C_aud_j ‖ D_aud_j`) starts in a multi-recipient payload.
    function _legAt(uint256 j) internal view returns (uint256) {
        uint256 p = ver.g1EncodedBytes();
        return 176 + 3 * p + 4 * p * j;
    }

    function _replacePoint(bytes memory payload, uint256 off) internal view returns (bytes memory out) {
        uint256 p = ver.g1EncodedBytes();
        out = bytes.concat(payload);
        bytes memory np = ver.g1Add(_cut(payload, off, p), ver.g1MulBase(1));
        for (uint256 i; i < p; ++i) out[off + i] = np[i];
    }

    function _funded(uint256 amount) internal {
        _fund(tok, alice, amount);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
    }

    // ------------------------------------------------------------------ gas (spec §7)

    /// @dev Trạng thái mới cho mỗi ô (người nhận và beneficiary nhận credit lần đầu), như số đo của bản một người nhận.
    function _gasRun(uint256 m, ZetherTypes.TransferMode mode) internal {
        uint256 b = 1_000_000;
        _funded(b);
        uint256[] memory vs = new uint256[](m);
        vs[m / 2] = 1000; // một người nhận thật, còn lại là mồi nhận 0
        Tx memory t = _proveMulti(tok, alice, _to(m), vs, b, carol.ua, mode);
        uint256 cd = abi.encodeWithSelector(_selector(mode), t.payload, t.proof, bytes(""), ZetherTypes.UA.unwrap(carol.ua), bytes("")).length;
        uint256 g0 = gasleft();
        _send(tok, mode, t, carol.ua);
        uint256 used = g0 - gasleft();
        Vm.Gas memory lg = vm.lastCallGas(); // the isolated transaction: REGULAR gas, and EIP-8037 STATE gas apart
        console2.log(string.concat(
            bls ? "bls12-381" : "bn254", " mtxConfidentialTransfer M=", vm.toString(m), " ", _modeName(mode),
            audOut ? " auditor-out" : "", " gas ", vm.toString(used), " calldata ", vm.toString(cd),
            " regular ", vm.toString(lg.gasTotalUsed), " state ", vm.toString(uint256(int256(lg.gasStateUsed)))
        ));
        assertTrue(_holds(tok, alice, b - 1000 - FEE, true), "sender acc = b - sum(v) - fee");
    }

    /// @dev Như `_gasRun`, định dạng một người nhận.
    function _gasSingle() internal {
        uint256 b = 1_000_000;
        _funded(b);
        Tx memory t = _proveTransfer(tok, alice, rs[0], 1000, b, carol.ua, 0);
        uint256 cd = abi.encodeCall(ZetherLayer.mtxConfidentialTransferSingle, (t.payload, t.proof, bytes(""), ZetherTypes.UA.unwrap(carol.ua), bytes(""))).length;
        uint256 g0 = gasleft();
        _direct(tok, t, carol.ua);
        uint256 used = g0 - gasleft();
        console2.log(string.concat(
            bls ? "bls12-381" : "bn254", " mtxConfidentialTransferSingle", audOut ? " auditor-out" : "",
            " gas ", vm.toString(used), " calldata ", vm.toString(cd)
        ));
        assertTrue(_holds(tok, alice, b - 1000 - FEE, true), "sender acc = b - v - fee");
    }

    function test_gasSingle() public { _gasSingle(); }
    function test_gasOutSingle() public { audOut = true; _gasSingle(); }

    function test_gasM1Hash() public { _gasRun(1, ZetherTypes.TransferMode.HASH); }
    function test_gasM1Bundle() public { _gasRun(1, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasM2Hash() public { _gasRun(2, ZetherTypes.TransferMode.HASH); }
    function test_gasM2Bundle() public { _gasRun(2, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasM4Hash() public { _gasRun(4, ZetherTypes.TransferMode.HASH); }
    function test_gasM4Bundle() public { _gasRun(4, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasM8Hash() public { _gasRun(8, ZetherTypes.TransferMode.HASH); }
    function test_gasM8Bundle() public { _gasRun(8, ZetherTypes.TransferMode.BUNDLE); }
    // Z12: token có auditor, người gửi bỏ auditor (mọi C_aud = O)
    function test_gasOutM1Hash() public { audOut = true; _gasRun(1, ZetherTypes.TransferMode.HASH); }
    function test_gasOutM1Bundle() public { audOut = true; _gasRun(1, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasOutM2Hash() public { audOut = true; _gasRun(2, ZetherTypes.TransferMode.HASH); }
    function test_gasOutM2Bundle() public { audOut = true; _gasRun(2, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasOutM4Hash() public { audOut = true; _gasRun(4, ZetherTypes.TransferMode.HASH); }
    function test_gasOutM4Bundle() public { audOut = true; _gasRun(4, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasOutM8Hash() public { audOut = true; _gasRun(8, ZetherTypes.TransferMode.HASH); }
    function test_gasOutM8Bundle() public { audOut = true; _gasRun(8, ZetherTypes.TransferMode.BUNDLE); }

    // ------------------------------------------------------------------ hiệu lực

    function test_effectsDecoysAndConservation() public {
        _funded(1000);
        uint256[] memory vs = new uint256[](4);
        (vs[0], vs[1], vs[2], vs[3]) = (0, 300, 0, 50);
        uint256 seq = tok.accountState(rs[1].ua).pendingSeq;
        Tx memory t = _proveMulti(tok, alice, _to(4), vs, 1000, carol.ua, ZetherTypes.TransferMode.HASH);
        bytes32[] memory uas = new bytes32[](4);
        for (uint256 j; j < 4; ++j) uas[j] = ZetherTypes.UA.unwrap(rs[j].ua);
        bytes32 expected = _ref(tok, alice, 0);
        vm.expectEmit(true, true, true, true, address(tok));
        emit IConfidentialToken.ConfidentialTransferMulti(expected, ZetherTypes.UA.unwrap(alice.ua),
            ZetherTypes.UA.unwrap(carol.ua), FEE, 0, uas, uint8(ZetherTypes.TransferMode.HASH), address(0));
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.HASH, t, carol.ua);
        assertEq(ref, _ref(tok, alice, 0), "entryRef carries chainUid (CTR-ZTH-36)");
        assertTrue(_holds(tok, alice, 1000 - 350 - FEE, true), "sender debited sum + fee");
        for (uint256 j; j < 4; ++j) {
            assertTrue(_holds(tok, rs[j], vs[j], false), "recipient pending = its v (decoys 0)");
        }
        assertEq(tok.accountState(rs[1].ua).pendingSeq, seq + 1, "every recipient gets a credit");
        assertEq(tok.accountState(rs[0].ua).pendingSeq, 1, "decoys too");
        assertEq(tok.balanceOfUA(ZetherTypes.UA.unwrap(carol.ua)), FEE * SCALE, "beneficiary public balance");
        assertEq(tok.accountState(carol.ua).pendingSeq, 0, "no pend_ben credit (D19)");
        assertEq(tok.sendCounter(alice.ua), 1);
        assertEq(tok.totalShielded(), 1000 - FEE, "only the fee left the shielded set (D19)");
    }

    function test_auditorOffToken() public {
        tok = _newToken(false, "noaud");
        _funded(500);
        uint256[] memory vs = new uint256[](2);
        (vs[0], vs[1]) = (0, 40);
        Tx memory t = _proveMulti(tok, alice, _to(2), vs, 500, _none(), ZetherTypes.TransferMode.BUNDLE);
        _send(tok, ZetherTypes.TransferMode.BUNDLE, t, _none());
        assertTrue(_holds(tok, rs[1], 40, false));
        assertTrue(_holds(tok, alice, 460, true));
    }

    // ------------------------------------------------------------------ chặn

    function test_rejectsBadShapes() public {
        _funded(1000);
        uint256[] memory vs = new uint256[](2);
        (vs[0], vs[1]) = (5, 6);
        Tx memory t = _proveMulti(tok, alice, _to(2), vs, 1000, _none(), ZetherTypes.TransferMode.HASH);
        uint256 p = ver.g1EncodedBytes();
        // M = 0 and M = 17
        bytes memory pl = bytes.concat(t.payload);
        pl[143] = bytes1(0);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadRecipientCount.selector, 0));
        tok.mtxConfidentialTransferCompact(pl, t.proof, "", bytes32(0), "");
        pl[143] = bytes1(uint8(17));
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadRecipientCount.selector, 17));
        tok.mtxConfidentialTransferCompact(pl, t.proof, "", bytes32(0), "");
        // M = 3 with two legs: length
        pl[143] = bytes1(uint8(3));
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadPayload.selector, t.payload.length));
        tok.mtxConfidentialTransferCompact(pl, t.proof, "", bytes32(0), "");
        // duplicate recipient, self, unregistered
        User[] memory dup = _to(2);
        dup[1] = dup[0];
        Tx memory d = _proveMultiUnchecked(dup, vs);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.DuplicateRecipient.selector, rs[0].ua));
        tok.mtxConfidentialTransferCompact(d.payload, t.proof, "", bytes32(0), "");
        User[] memory self = _to(2);
        self[1] = alice;
        d = _proveMultiUnchecked(self, vs);
        vm.expectRevert(IZetherToken.SelfTransfer.selector);
        tok.mtxConfidentialTransferCompact(d.payload, t.proof, "", bytes32(0), "");
        User[] memory stranger = _to(2);
        stranger[1].y = _pubOf(0x5757);
        stranger[1].ua = ZetherTypes.toUA(stranger[1].y);
        d = _proveMultiUnchecked(stranger, vs);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, stranger[1].ua));
        tok.mtxConfidentialTransferCompact(d.payload, t.proof, "", bytes32(0), "");
        // tampered C_deb, C_out_2, C_aud_1, D_aud_2 (review C0-1: E6′_j binds it)
        uint256[4] memory offs = [176 + 2 * p, _legAt(1) + p, _legAt(0) + 2 * p, _legAt(1) + 3 * p];
        for (uint256 i; i < 4; ++i) {
            bytes memory tampered = _replacePoint(t.payload, offs[i]);
            vm.expectRevert(IZetherToken.ProofRejected.selector);
            tok.mtxConfidentialTransferCompact(tampered, t.proof, "", bytes32(0), "");
        }
        // a HASH proof under another form (`mtxConfidentialTransfer` stores R on this BUNDLE token): with its memo the payload
        // has the wrong shape for that form, without it the statement (opTag, memoHash) is another one
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadPayload.selector, t.payload.length));
        tok.mtxConfidentialTransfer(t.payload, t.proof, "", bytes32(0), "");
        bytes memory bare = _cut(t.payload, 0, t.payload.length - 17 - 40 * 2);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.mtxConfidentialTransfer(bare, t.proof, "", bytes32(0), "");
        // valid, then replay
        tok.mtxConfidentialTransferCompact(t.payload, t.proof, "", bytes32(0), "");
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.StaleSendCounter.selector, 1, 0));
        tok.mtxConfidentialTransferCompact(t.payload, t.proof, "", bytes32(0), "");
    }

    /// @dev Payload thôi (chưa proof) — các phép kiểm hình dạng chạy trước verify.
    function _proveMultiUnchecked(User[] memory to, uint256[] memory vs) internal view returns (Tx memory r) {
        r.payload = _multiPayload(tok, alice, to, vs, 7, tok.accountState(alice.ua));
    }

    function _pubOf(uint256 x) internal view returns (bytes memory) {
        return ver.g1MulBase(x);
    }

    // ------------------------------------------------------------------ tiết lộ theo mode

    /// @dev Opening Chaum-Pedersen leg `j`: SENDER_CP trên cơ sở `Y_tj` bằng `s`, AUDITOR trên `D_aud_j` (review C0-1),
    ///      RECEIVER_X trên `D_out`.
    function _cp(uint256 x, bytes32 ref, uint256 j, uint256 amount, ITransferDisclosure.OpeningKind kind, bytes memory payload)
        internal view returns (bytes memory)
    {
        uint256 p = ver.g1EncodedBytes();
        bytes memory base = kind == ITransferDisclosure.OpeningKind.SENDER_CP ? _cut(payload, _legAt(j), p)
            : kind == ITransferDisclosure.OpeningKind.AUDITOR ? _cut(payload, _legAt(j) + 3 * p, p)
            : _cut(payload, 176 + p, p);
        return _cpOpening(tok, x, ref, j, amount, kind, base);
    }

    function test_disclosureHashMode() public {
        _funded(500);
        uint256[] memory vs = new uint256[](3);
        vs[1] = 77;
        Tx memory t = _proveMulti(tok, alice, _to(3), vs, 500, _none(), ZetherTypes.TransferMode.HASH);
        bytes memory bundles = _bundlesOf(t.payload);
        bytes32 expected = _ref(tok, alice, 0);
        vm.expectEmit(true, false, false, true, address(tok));
        emit IZetherToken.TransferBundles(expected, bundles);
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.HASH, t, _none());
        // HASH keeps R in state by SSTORE2 (CTR-ZTH-38, review C0-3): `entryPtrs[ref]` holds the pointer, nothing under
        // `entries[ref]`, the memo next to it
        uint256 ns = 0xd1eef6cbeb7b383e0a92b3cb723053d5c39c76707d89da6b14ff91b83198ce00;
        address ptr = address(uint160(uint256(vm.load(address(tok), keccak256(abi.encode(ref, ns + 10))))));
        assertTrue(ptr != address(0) && ptr.code.length == bundles.length + 1, "the pointer: 0x00 || R");
        assertEq(vm.load(address(tok), keccak256(abi.encode(ref, ns + 9))), bytes32(0));
        assertEq(vm.load(address(tok), keccak256(abi.encode(ref, ns + 11))), bytes32(uint256(_memo(3).length * 2 + 1)),
            "the memo next to it (a long `bytes`: 2 * len + 1)");
        assertEq(tok.transferEntry(ref), bundles, "R itself, from state");
        assertEq(tok.transferMemo(ref), _memo(3), "the sender memo");
        _discloseAll(ref, t);
    }

    /// @dev Review C0-3: disclosure reads `R` from the token's state, with no `bundles` argument (the event is not needed).
    function test_disclosure_readsRecordFromState() public {
        _funded(500);
        uint256[] memory vs = new uint256[](3);
        vs[1] = 77;
        Tx memory t = _proveMulti(tok, alice, _to(3), vs, 500, _none(), ZetherTypes.TransferMode.HASH);
        vm.recordLogs();
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.HASH, t, _none());
        vm.getRecordedLogs(); // the event is dropped: the opening still verifies
        assertTrue(_vta(tok, ref, 1, 77, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s)));
        assertFalse(_vta(tok, ref, 1, 78, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s)));
    }

    /// @dev Review C0-3: the stored bytes hash to the commitment `keccak256(R)` the event's `R` gives, so an off-chain
    ///      indexer that keeps the old hash stays consistent.
    function test_hashRecordMatchesR() public {
        _funded(500);
        uint256[] memory vs = new uint256[](3);
        vs[1] = 77;
        Tx memory t = _proveMulti(tok, alice, _to(3), vs, 500, _none(), ZetherTypes.TransferMode.HASH);
        vm.recordLogs();
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.HASH, t, _none());
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes memory r;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == IZetherToken.TransferBundles.selector && logs[i].topics[1] == ref) r = abi.decode(logs[i].data, (bytes));
        }
        assertGt(r.length, 0, "event R");
        assertEq(keccak256(tok.transferEntry(ref)), keccak256(r), "state R hashes to the event's commitment");
        assertEq(r, _bundlesOf(t.payload));
    }

    /// @dev Review C0-3: the old `mtxConfidentialTransferNoBundle` selector is gone: a call to it hits the token's
    ///      unknown-selector path and reverts (and no allow-list entry names it).
    function test_noBundleRetired() public {
        bytes4 old = bytes4(keccak256("mtxConfidentialTransferNoBundle(bytes,bytes,bytes,bytes32,bytes)"));
        (bool ok, bytes memory ret) = address(tok).call(abi.encodeWithSelector(old, bytes(""), bytes(""), bytes(""), bytes32(0), bytes("")));
        assertFalse(ok, "retired");
        assertEq(ret.length, 0, "the plain fallback revert (no function by that selector)");
        (bytes4[] memory s,,) = tok.mtxSelectors();
        for (uint256 i; i < s.length; ++i) assertTrue(s[i] != old, "off the allow-list");
        // relayed: the envelope is refused at the allow-list, not forwarded to the fallback
        uint256 pk = 0x9A7E5;
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: vm.addr(pk), data: abi.encodeWithSelector(old, bytes(""), bytes(""), bytes(""), bytes32(0), bytes("")),
            batch: 1, nonce: tok.mtxNonce(vm.addr(pk), 1), validUntil: block.timestamp + 300,
            mode: MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_FEE_FIXED, relayer: relayer, fee: 0, feeRecipient: address(0)
        });
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(pk, tok.mtxDigest(m));
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, old));
        tok.mtxExecute(m, abi.encodePacked(r, sg, v));
    }

    /// @dev A foreign token's entry that is not a record length: `RecordMalformed`.
    function test_disclosureBundleMode() public {
        _funded(500);
        uint256[] memory vs = new uint256[](3);
        vs[1] = 77;
        Tx memory t = _proveMulti(tok, alice, _to(3), vs, 500, _none(), ZetherTypes.TransferMode.BUNDLE);
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.BUNDLE, t, _none());
        _discloseAll(ref, t);
    }

    /// @dev Cả bốn opening trên leg thật, `s` mở cả leg mồi (owner Z3), opening không chuyển leg, chỉ số ngoài khoảng.
    function _discloseAll(bytes32 ref, Tx memory t) internal {
        _discloseCp(ref, t);
        ITransferDisclosure.OpeningKind S = ITransferDisclosure.OpeningKind.SENDER_S;
        ITransferDisclosure.OpeningKind RX = ITransferDisclosure.OpeningKind.RECEIVER_X;
        assertTrue(_vta(tok, ref, 1, 77, S, abi.encode(t.s)), "sender opens the real leg");
        assertFalse(_vta(tok, ref, 1, 78, S, abi.encode(t.s)));
        assertTrue(_vta(tok, ref, 0, 0, S, abi.encode(t.s)), "s also opens a decoy (Z3)");
        bytes memory rx = _cp(rs[1].x, ref, 1, 77, RX, t.payload);
        assertTrue(_vta(tok, ref, 1, 77, RX, rx));
        assertFalse(_vta(tok, ref, 2, 77, RX, rx), "an opening does not move to another leg");
        bytes memory au = _cp(X_AUD, ref, 1, 77, ITransferDisclosure.OpeningKind.AUDITOR, t.payload);
        assertEq(_vta(tok, ref, 1, 77, ITransferDisclosure.OpeningKind.AUDITOR, au), !audOut,
            "auditor opens unless left out (Z12)");
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.BadRecipientIndex.selector, 3));
        _vta(tok, ref, 3, 0, S, abi.encode(t.s));
        (bytes memory ct, bytes memory yTo) = dis.transferCiphertext(address(tok), ref, 1);
        assertEq(yTo, rs[1].y);
        assertEq(ct.length, 4 * ver.g1EncodedBytes(), "C_out D_out C_aud D_aud");
    }

    /// @dev SENDER_CP (Z10): chỉ leg j mở, challenge ràng j.
    function _discloseCp(bytes32 ref, Tx memory t) internal view {
        ITransferDisclosure.OpeningKind CP = ITransferDisclosure.OpeningKind.SENDER_CP;
        bytes memory cp = _cp(t.s, ref, 1, 77, CP, t.payload);
        assertTrue(_vta(tok, ref, 1, 77, CP, cp), "sender CP opens leg 1");
        assertFalse(_vta(tok, ref, 1, 78, CP, cp), "wrong amount");
        assertFalse(_vta(tok, ref, 0, 77, CP, cp), "wrong leg");
        assertFalse(_vta(tok, ref, 0, 0, CP, cp), "a proof for leg 1 does not open leg 0");
        assertFalse(_vta(tok, ref, 1, 77, ITransferDisclosure.OpeningKind.RECEIVER_X, cp), "kind is bound");
        bytes memory cp0 = _cp(t.s, ref, 0, 0, CP, t.payload);
        assertTrue(_vta(tok, ref, 0, 0, CP, cp0), "decoy opens with its own proof");
        assertFalse(_vta(tok, ref, 1, 0, CP, cp0));
    }

    // ------------------------------------------------------------------ bỏ auditor theo transfer (Z12)

    function test_auditorOptOut() public {
        _funded(500);
        uint256[] memory vs = new uint256[](3);
        vs[1] = 77;
        audOut = true;
        Tx memory t = _proveMulti(tok, alice, _to(3), vs, 500, _none(), ZetherTypes.TransferMode.BUNDLE);
        audOut = false;
        Tx memory on = _proveMulti(tok, alice, _to(3), vs, 500, _none(), ZetherTypes.TransferMode.BUNDLE);
        // Y_a nằm trong statement: proof của lựa chọn này không qua dưới lựa chọn kia
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.mtxConfidentialTransfer(t.payload, on.proof, "", bytes32(0), "");
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.mtxConfidentialTransfer(on.payload, t.proof, "", bytes32(0), "");
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.BUNDLE, t, _none());
        assertTrue(_holds(tok, rs[1], 77, false));
        assertTrue(_holds(tok, alice, 423, true));
        audOut = true;
        _discloseAll(ref, t);
    }

    function test_auditorLegsMixedReverts() public {
        _funded(500);
        uint256[] memory vs = new uint256[](2);
        vs[1] = 9;
        Tx memory t = _proveMulti(tok, alice, _to(2), vs, 500, _none(), ZetherTypes.TransferMode.HASH);
        uint256 p = ver.g1EncodedBytes();
        bytes memory pl = bytes.concat(t.payload);
        for (uint256 i; i < p; ++i) pl[_legAt(0) + 2 * p + i] = 0; // C_aud_1 = O, C_aud_2 ≠ O
        vm.expectRevert(IZetherToken.AuditorLegsMixed.selector);
        tok.mtxConfidentialTransferCompact(pl, t.proof, "", bytes32(0), "");
        vm.expectRevert(IZetherToken.AuditorLegsMixed.selector);
        stm.transferStatement(address(tok), pl, _none(), ZetherTypes.TransferMode.HASH, 0);
    }

    /// Token không có auditor (`NONE`): C_aud ≠ O không "bật" được auditor — bị từ chối trước verify, statement cũng vậy.
    function test_auditorOffTokenRejectsCAud() public {
        tok = _newToken(false, "noaud2");
        _funded(500);
        uint256[] memory vs = new uint256[](1);
        vs[0] = 5;
        Tx memory t = _proveMulti(tok, alice, _to(1), vs, 500, _none(), ZetherTypes.TransferMode.HASH);
        bytes memory pl = _replacePoint(t.payload, _legAt(0) + 2 * ver.g1EncodedBytes());
        vm.expectRevert(IZetherToken.AuditorForbidden.selector);
        tok.mtxConfidentialTransferCompact(pl, t.proof, "", bytes32(0), "");
        vm.expectRevert(IZetherToken.AuditorForbidden.selector);
        stm.transferStatement(address(tok), pl, _none(), ZetherTypes.TransferMode.HASH, 0);
    }

    // ------------------------------------------------------------------ review C0-1: per-leg auditor randomness

    /// @dev The stored record of `ref` (BUNDLE): `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j ‖ D_aud_j`, point `k` of leg `j`.
    function _recPt(bytes memory rec, uint256 j, uint256 k) internal view returns (bytes memory) {
        uint256 p = ver.g1EncodedBytes();
        return _cut(rec, 16 + 5 * p * j + k * p, p);
    }

    /// Two decoys (`v = 0`) and a real leg, auditor on: every `C_aud_j` and `D_aud_j` differs, and no small public
    /// combination cancels the mask: `h_k·C_aud_j − h_j·C_aud_k ≠ O` (two decoys) and `≠ [h_k·v_j − h_j·v_k]G` — what one
    /// shared `s`, with or without public per-leg coefficients (option (i)), gave away.
    function test_multiAudited_decoysDistinct() public {
        _funded(500);
        uint256[] memory vs = new uint256[](3);
        vs[1] = 77;
        Tx memory t = _proveMulti(tok, alice, _to(3), vs, 500, _none(), ZetherTypes.TransferMode.BUNDLE);
        bytes memory rec = tok.transferEntry(_send(tok, ZetherTypes.TransferMode.BUNDLE, t, _none()));
        uint256 p = ver.g1EncodedBytes();
        assertEq(rec.length, 16 + 3 * 5 * p, "5 points per leg");
        for (uint256 j; j < 3; ++j) {
            for (uint256 k; k < 3; ++k) {
                if (j == k) continue;
                assertNotEq(_recPt(rec, j, 3), _recPt(rec, k, 3), "C_aud_j == C_aud_k");
                assertNotEq(_recPt(rec, j, 4), _recPt(rec, k, 4), "D_aud_j == D_aud_k");
                for (uint256 h = 0; h < 9; ++h) _noCancel(_recPt(rec, j, 3), _recPt(rec, k, 3), vs[j], vs[k], 1 + h / 3, 1 + h % 3);
            }
        }
        _reusedTRefused();
    }

    /// @dev Two decoys under one reused `t` (legs 0 and 2 byte-identical `C_aud`, `D_aud`), proven honestly for that
    ///      statement: the verifier refuses it (`ProofRejected`), the token's statement builder takes it as given.
    function _reusedTRefused() internal {
        uint256[] memory vs = new uint256[](3);
        vs[1] = 33;
        Tx memory t = _proveMulti(tok, alice, _to(3), vs, 423, _none(), ZetherTypes.TransferMode.BUNDLE);
        uint256 p = ver.g1EncodedBytes();
        bytes memory pl = bytes.concat(t.payload);
        for (uint256 i; i < 2 * p; ++i) pl[_legAt(2) + 2 * p + i] = pl[_legAt(0) + 2 * p + i];
        ZetherProver.MultiWitness memory w = _multiWitness(alice.x, t.s, vs, 423);
        w.t[2] = w.t[0];
        bytes memory st = stm.transferStatement(address(tok), pl, _none(), ZetherTypes.TransferMode.BUNDLE, 0);
        bytes memory pr = prover.proveTransferMulti(ver, st, w);
        assertFalse(ver.verifyTransferMulti(st, pr), "a reused t_j verifies");
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.mtxConfidentialTransfer(pl, pr, "", bytes32(0), "");
    }

    /// @dev `h_k·C_j − h_j·C_k` is neither `O` nor `[h_k·v_j − h_j·v_k]G`.
    function _noCancel(bytes memory cj, bytes memory ck, uint256 vj, uint256 vk, uint256 hj, uint256 hk) internal view {
        uint256 r = ver.groupOrder();
        uint256[] memory sc = new uint256[](2);
        (sc[0], sc[1]) = (hk, r - hj);
        bytes memory lin = ver.g1Msm(bytes.concat(cj, ck), sc);
        assertNotEq(lin, ver.identity(), "h_k C_aud_j - h_j C_aud_k = O");
        assertNotEq(lin, ver.g1MulBase(addmod(mulmod(hk, vj, r), r - mulmod(hj, vk, r), r)), "the auditor mask cancels");
    }

    /// The auditor decrypts every leg as `C_aud_j − [x_a]D_aud_j` (decoys 0), and its `AUDITOR` opening of a multi leg is
    /// over `D_aud_j`: one built on `D_out` (the pre-fix base) is refused.
    function test_multiAudited_auditorDecryptsEachLeg() public {
        _funded(500);
        uint256[] memory vs = new uint256[](4);
        (vs[0], vs[1], vs[2], vs[3]) = (0, 41, 0, 9);
        Tx memory t = _proveMulti(tok, alice, _to(4), vs, 500, _none(), ZetherTypes.TransferMode.BUNDLE);
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.BUNDLE, t, _none());
        bytes memory rec = tok.transferEntry(ref);
        for (uint256 j; j < 4; ++j) {
            assertEq(_decrypt(_recPt(rec, j, 3), _recPt(rec, j, 4), X_AUD, 100), vs[j], "auditor reads leg j");
            assertEq(_recPt(rec, j, 4), ver.g1MulBase(_tAud(t.s, j)), "D_aud_j = [t_j]G");
            bytes memory au = _cp(X_AUD, ref, j, vs[j], ITransferDisclosure.OpeningKind.AUDITOR, t.payload);
            assertTrue(_vta(tok, ref, j, vs[j], ITransferDisclosure.OpeningKind.AUDITOR, au), "AUDITOR opens leg j");
            assertFalse(_vta(tok, ref, j, vs[j] + 1, ITransferDisclosure.OpeningKind.AUDITOR, au));
        }
        bytes memory onDOut = _cpOpening(tok, X_AUD, ref, 1, 41, ITransferDisclosure.OpeningKind.AUDITOR,
            _cut(t.payload, 176 + ver.g1EncodedBytes(), ver.g1EncodedBytes()));
        assertFalse(_vta(tok, ref, 1, 41, ITransferDisclosure.OpeningKind.AUDITOR, onDOut), "not over D_out");
        (bytes memory ct,) = dis.transferCiphertext(address(tok), ref, 3);
        uint256 p = ver.g1EncodedBytes();
        assertEq(_cut(ct, 3 * p, p), _recPt(rec, 3, 4), "transferCiphertext ends with D_aud_j");
    }

    /// With the auditor on, the auditor key as a recipient or as the sender reverts `AuditorKeyAsParty` (both formats,
    /// before verification, and in the statement views); with the auditor left out it is an ordinary account.
    function test_auditorKeyAsParty() public {
        User memory au = _user(X_AUD, address(0xA0D));
        _funded(500);
        uint256[] memory vs = new uint256[](2);
        vs[1] = 5;
        User[] memory to = _to(2);
        to[0] = au;
        Tx memory t;
        t.payload = _multiPayload(tok, alice, to, vs, 7, tok.accountState(alice.ua));
        vm.expectRevert(IZetherToken.AuditorKeyAsParty.selector);
        tok.mtxConfidentialTransfer(t.payload, "", "", bytes32(0), "");
        vm.expectRevert(IZetherToken.AuditorKeyAsParty.selector);
        stm.transferStatement(address(tok), t.payload, _none(), ZetherTypes.TransferMode.BUNDLE, 0);
        bytes memory single = _payload(tok, alice, au, 5, 7, tok.accountState(alice.ua));
        vm.expectRevert(IZetherToken.AuditorKeyAsParty.selector);
        tok.mtxConfidentialTransferSingle(single, "", "", bytes32(0), "");
        vm.expectRevert(IZetherToken.AuditorKeyAsParty.selector);
        stm.transferStatementSingle(address(tok), single, _none(), 0);
        // the auditor key as the sender
        bytes memory fromAud = _multiPayload(tok, au, _to(2), vs, 7, tok.accountState(au.ua));
        vm.expectRevert(IZetherToken.AuditorKeyAsParty.selector);
        tok.mtxConfidentialTransfer(fromAud, "", "", bytes32(0), "");
        bytes memory singleFromAud = _payload(tok, au, bob, 5, 7, tok.accountState(au.ua));
        vm.expectRevert(IZetherToken.AuditorKeyAsParty.selector);
        tok.mtxConfidentialTransferSingle(singleFromAud, "", "", bytes32(0), "");
        // auditor left out (OPTIONAL): an ordinary recipient
        audOut = true;
        t = _proveMulti(tok, alice, to, vs, 500, _none(), ZetherTypes.TransferMode.BUNDLE);
        _send(tok, ZetherTypes.TransferMode.BUNDLE, t, _none());
        assertTrue(_holds(tok, rs[1], 5, false));
        assertTrue(_holds(tok, au, 0, false), "the auditor's own account, a decoy");
    }

    /// Review C0-9: `block.number > validUntilBlock` reverts `TransferExpired` on every debit, direct and in the views;
    /// `block.number == validUntilBlock` settles. The word is in the statement, so a relayer cannot extend it.
    function test_directTransferExpired() public {
        _funded(1000);
        vm.roll(99);
        vub = 99; // proved at block 99, sent at 100
        Tx memory t = _proveTransfer(tok, alice, bob, 10, 1000, _none(), 0);
        uint256[] memory vs = new uint256[](2);
        vs[0] = 10;
        Tx memory m = _proveMulti(tok, alice, _to(2), vs, 1000, _none(), ZetherTypes.TransferMode.BUNDLE);
        (bytes memory pl, bytes memory pr) = _proveUnshield(tok, alice, 10, 1000, address(0xB0C), _none(), 0);
        vm.roll(100);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.TransferExpired.selector, 99));
        _direct(tok, t, _none());
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.TransferExpired.selector, 99));
        stm.transferStatementSingle(address(tok), t.payload, _none(), 0);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.TransferExpired.selector, 99));
        _send(tok, ZetherTypes.TransferMode.BUNDLE, m, _none());
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.TransferExpired.selector, 99));
        tok.mtxUnshield(pl, pr, "", bytes32(0), "", 10, bytes32(uint256(uint160(address(0xB0C)))));
        // the proof binds the word: the same proof with a later validUntilBlock is rejected
        bytes memory later = bytes.concat(t.payload);
        later[95] = bytes1(uint8(200));
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        _direct(tok, Tx(later, t.proof, t.s), _none());
        // at the last block it settles
        vub = 100;
        t = _proveTransfer(tok, alice, bob, 10, 1000, _none(), 0);
        _direct(tok, t, _none());
        assertTrue(_holds(tok, bob, 10, false));
    }

    // ------------------------------------------------------------------ bên thứ ba on-chain

    function test_thirdPartyContractVerifiesOnChain() public {
        _funded(500);
        uint256[] memory vs = new uint256[](2);
        vs[0] = 31;
        Tx memory t = _proveMulti(tok, alice, _to(2), vs, 500, _none(), ZetherTypes.TransferMode.BUNDLE);
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.BUNDLE, t, _none());
        Escrow3P esc = new Escrow3P();
        bytes memory cp = _cp(t.s, ref, 0, 31, ITransferDisclosure.OpeningKind.SENDER_CP, t.payload);
        assertTrue(esc.release(IZetherToken(address(tok)), ref, 0, 31, cp));
        assertEq(esc.released(ref), 31);
        vm.expectRevert(bytes("not proven"));
        esc.release(IZetherToken(address(tok)), ref, 0, 32, cp);
    }

    // ------------------------------------------------------------------ gas tiết lộ (spec §7 b)

    /// @dev Gas on-chain của `verifyTransferAmount` gọi từ một contract (`Escrow3P.measure`), token/disclosure
    ///      làm nguội trước mỗi lần đo (như một giao dịch mới: account và slot bundle lạnh).
    function _measure(Escrow3P esc, bytes32 ref, uint256 j, uint256 k, bytes memory o)
        internal returns (uint256)
    {
        vm.cool(address(tok));
        vm.cool(address(dis));
        vm.cool(address(ver));
        return esc.measure(IZetherToken(address(tok)), ref, j, 1000, ITransferDisclosure.OpeningKind(k), o);
    }

    function _gasKinds(string memory tag, bytes32 ref, uint256 j, bytes[4] memory o) internal {
        Escrow3P esc = new Escrow3P();
        string[4] memory names = ["SENDER_S", "RECEIVER_X", "AUDITOR", "SENDER_CP"];
        for (uint256 k; k < 4; ++k) {
            console2.log(string.concat(
                bls ? "bls12-381" : "bn254", " disclose ", tag, " ", names[k], " gas ",
                vm.toString(_measure(esc, ref, j, k, o[k]))
            ));
        }
    }

    /// @dev Leg thật là leg cuối (`j = M − 1`).
    function _gasDisclose(uint256 m, ZetherTypes.TransferMode mode) internal {
        _funded(1_000_000);
        uint256[] memory vs = new uint256[](m);
        uint256 j = m - 1;
        vs[j] = 1000;
        Tx memory t = _proveMulti(tok, alice, _to(m), vs, 1_000_000, _none(), mode);
        bytes32 ref = _send(tok, mode, t, _none());
        bytes[4] memory o = [
            abi.encode(t.s),
            _cp(rs[j].x, ref, j, 1000, ITransferDisclosure.OpeningKind.RECEIVER_X, t.payload),
            _cp(X_AUD, ref, j, 1000, ITransferDisclosure.OpeningKind.AUDITOR, t.payload),
            _cp(t.s, ref, j, 1000, ITransferDisclosure.OpeningKind.SENDER_CP, t.payload)
        ];
        _gasKinds(string.concat("M=", vm.toString(m), " ", _modeName(mode)), ref, j, o);
    }

    function test_gasDiscloseM1Bundle() public { _gasDisclose(1, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasDiscloseM8Bundle() public { _gasDisclose(8, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasDiscloseM1Hash() public { _gasDisclose(1, ZetherTypes.TransferMode.HASH); }
    function test_gasDiscloseM8Hash() public { _gasDisclose(8, ZetherTypes.TransferMode.HASH); }

    function test_gasDiscloseSingle() public {
        _funded(1_000_000);
        Tx memory t = _proveTransfer(tok, alice, rs[0], 1000, 1_000_000, _none(), 0);
        bytes32 ref = _direct(tok, t, _none());
        bytes memory dOut = _cut(t.payload, 112 + 3 * ver.g1EncodedBytes(), ver.g1EncodedBytes()); // salt Y_f Y_t C_out D_out …
        bytes[4] memory o = [
            abi.encode(t.s),
            _cpOpening(tok, rs[0].x, ref, 0, 1000, ITransferDisclosure.OpeningKind.RECEIVER_X, dOut),
            _cpOpening(tok, X_AUD, ref, 0, 1000, ITransferDisclosure.OpeningKind.AUDITOR, dOut),
            _cpOpening(tok, t.s, ref, 0, 1000, ITransferDisclosure.OpeningKind.SENDER_CP, rs[0].y)
        ];
        _gasKinds("Single", ref, 0, o);
    }
}

/// @notice A third-party contract: finds the canonical `ZetherDisclosure` from the token and checks on chain. No
///         attestation (CTR-ZTH-39): whoever needs an on-chain trace records it, as `released` here.
contract Escrow3P {
    mapping(bytes32 => uint256) public released;

    function release(IZetherToken token, bytes32 ref, uint256 j, uint256 amount, bytes calldata opening)
        external returns (bool)
    {
        bool ok = token.disclosure().verifyTransferAmount(
            address(token), ref, j, amount, ITransferDisclosure.OpeningKind.SENDER_CP, opening);
        require(ok, "not proven");
        released[ref] = amount;
        return true;
    }

    /// @dev `gasleft()` quanh đúng lời gọi `verifyTransferAmount`; phải trả true.
    function measure(
        IZetherToken token,
        bytes32 ref,
        uint256 j,
        uint256 amount,
        ITransferDisclosure.OpeningKind kind,
        bytes calldata opening
    ) external view returns (uint256 used) {
        ITransferDisclosure d = token.disclosure();
        uint256 g0 = gasleft();
        bool ok = d.verifyTransferAmount(address(token), ref, j, amount, kind, opening);
        used = g0 - gasleft();
        require(ok, "not proven");
    }
}

contract ZetherMultiBls12381Test is ZetherMultiSuite {}
