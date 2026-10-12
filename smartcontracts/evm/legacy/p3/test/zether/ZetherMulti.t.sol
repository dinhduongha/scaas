// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {console2} from "forge-std/Test.sol";
import {ZetherFixture} from "./helpers/ZetherFixture.sol";
import {ZetherToken} from "../../src/zether/ZetherToken.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ITransferDisclosure} from "../../src/zether/ITransferDisclosure.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";

/// @notice Transfer nhiều người nhận (spec 2026-10-08-zether-multi-recipient): hiệu lực, chặn, tiết lộ theo ba
///         mode và bảng gas M ∈ {1, 2, 4, 8} × {HASH, BUNDLE, NONE}, cho cả hai đường cong.
abstract contract ZetherMultiSuite is ZetherFixture {
    User[8] internal rs;

    function _curve() internal pure virtual returns (bool);

    function setUp() public {
        _deploy(_curve(), true);
        for (uint256 i; i < 8; ++i) rs[i] = _user(0xD00 + i, address(uint160(0xE00 + i)));
    }

    // ------------------------------------------------------------------ tiện ích

    function _to(uint256 m) internal view returns (User[] memory to) {
        to = new User[](m);
        for (uint256 j; j < m; ++j) to[j] = rs[j];
    }

    function _send(ZetherToken t, ZetherTypes.TransferMode mode, Tx memory x, ZetherTypes.UA ben) internal returns (bytes32) {
        if (mode == ZetherTypes.TransferMode.HASH) return t.transferConfidential(x.payload, x.proof, "", ben);
        if (mode == ZetherTypes.TransferMode.BUNDLE) return t.transferConfidentialBundle(x.payload, x.proof, "", ben);
        return t.transferConfidentialNoBundle(x.payload, x.proof, "", ben);
    }

    function _selector(ZetherTypes.TransferMode mode) internal pure returns (bytes4) {
        if (mode == ZetherTypes.TransferMode.HASH) return ZetherToken.transferConfidential.selector;
        if (mode == ZetherTypes.TransferMode.BUNDLE) return ZetherToken.transferConfidentialBundle.selector;
        return ZetherToken.transferConfidentialNoBundle.selector;
    }

    function _modeName(ZetherTypes.TransferMode mode) internal pure returns (string memory) {
        return mode == ZetherTypes.TransferMode.HASH ? "HASH" : mode == ZetherTypes.TransferMode.BUNDLE ? "BUNDLE" : "NONE";
    }

    function _cut(bytes memory a, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) out[i] = a[off + i];
    }

    /// @dev `B_1 ‖ … ‖ B_M` dựng lại từ payload (đúng thứ một client đọc được từ calldata).
    function _bundlesOf(bytes memory payload) internal view returns (bytes memory b) {
        uint256 p = ver.g1EncodedBytes();
        uint256 m = (payload.length - 96 - 3 * p) / (3 * p);
        bytes memory dOut = _cut(payload, 96 + p, p);
        for (uint256 j; j < m; ++j) {
            uint256 o = 96 + 3 * p + 3 * p * j;
            b = bytes.concat(b, _cut(payload, o, 2 * p), dOut, _cut(payload, o + 2 * p, p));
        }
    }

    function _replacePoint(bytes memory payload, uint256 off) internal view returns (bytes memory out) {
        uint256 p = ver.g1EncodedBytes();
        out = bytes.concat(payload);
        bytes memory np = ver.g1Add(_cut(payload, off, p), ver.g1MulBase(1));
        for (uint256 i; i < p; ++i) out[off + i] = np[i];
    }

    function _funded(uint256 amount) internal {
        _fund(tok, alice, amount);
        tok.rollOverPublic(alice.ua);
    }

    // ------------------------------------------------------------------ gas (spec §7)

    /// @dev Trạng thái mới cho mỗi ô (người nhận và beneficiary nhận credit lần đầu), như số đo của bản một người nhận.
    function _gasRun(uint256 m, ZetherTypes.TransferMode mode) internal {
        uint256 b = 1_000_000;
        _funded(b);
        uint256[] memory vs = new uint256[](m);
        vs[m / 2] = 1000; // một người nhận thật, còn lại là mồi nhận 0
        Tx memory t = _proveMulti(tok, alice, _to(m), vs, b, carol.ua, mode);
        uint256 cd = abi.encodeWithSelector(_selector(mode), t.payload, t.proof, bytes(""), carol.ua).length;
        uint256 g0 = gasleft();
        _send(tok, mode, t, carol.ua);
        uint256 used = g0 - gasleft();
        console2.log(string.concat(
            bls ? "bls12-381" : "bn254", " transferConfidential M=", vm.toString(m), " ", _modeName(mode),
            audOut ? " auditor-out" : "", " gas ", vm.toString(used), " calldata ", vm.toString(cd)
        ));
        assertTrue(_holds(tok, alice, b - 1000 - FEE, true), "sender acc = b - sum(v) - fee");
    }

    /// @dev Như `_gasRun`, định dạng một người nhận.
    function _gasSingle() internal {
        uint256 b = 1_000_000;
        _funded(b);
        Tx memory t = _proveTransfer(tok, alice, rs[0], 1000, b, carol.ua, 0);
        uint256 cd = abi.encodeCall(ZetherToken.transferConfidentialSingle, (t.payload, t.proof, bytes(""), carol.ua)).length;
        uint256 g0 = gasleft();
        _direct(tok, t, carol.ua);
        uint256 used = g0 - gasleft();
        console2.log(string.concat(
            bls ? "bls12-381" : "bn254", " transferConfidentialSingle", audOut ? " auditor-out" : "",
            " gas ", vm.toString(used), " calldata ", vm.toString(cd)
        ));
        assertTrue(_holds(tok, alice, b - 1000 - FEE, true), "sender acc = b - v - fee");
    }

    function test_gasSingle() public { _gasSingle(); }
    function test_gasOutSingle() public { audOut = true; _gasSingle(); }

    function test_gasM1Hash() public { _gasRun(1, ZetherTypes.TransferMode.HASH); }
    function test_gasM1Bundle() public { _gasRun(1, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasM1None() public { _gasRun(1, ZetherTypes.TransferMode.NONE); }
    function test_gasM2Hash() public { _gasRun(2, ZetherTypes.TransferMode.HASH); }
    function test_gasM2Bundle() public { _gasRun(2, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasM2None() public { _gasRun(2, ZetherTypes.TransferMode.NONE); }
    function test_gasM4Hash() public { _gasRun(4, ZetherTypes.TransferMode.HASH); }
    function test_gasM4Bundle() public { _gasRun(4, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasM4None() public { _gasRun(4, ZetherTypes.TransferMode.NONE); }
    function test_gasM8Hash() public { _gasRun(8, ZetherTypes.TransferMode.HASH); }
    function test_gasM8Bundle() public { _gasRun(8, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasM8None() public { _gasRun(8, ZetherTypes.TransferMode.NONE); }
    // Z12: token có auditor, người gửi bỏ auditor (mọi C_aud = O)
    function test_gasOutM1Hash() public { audOut = true; _gasRun(1, ZetherTypes.TransferMode.HASH); }
    function test_gasOutM1Bundle() public { audOut = true; _gasRun(1, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasOutM1None() public { audOut = true; _gasRun(1, ZetherTypes.TransferMode.NONE); }
    function test_gasOutM2Hash() public { audOut = true; _gasRun(2, ZetherTypes.TransferMode.HASH); }
    function test_gasOutM2Bundle() public { audOut = true; _gasRun(2, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasOutM2None() public { audOut = true; _gasRun(2, ZetherTypes.TransferMode.NONE); }
    function test_gasOutM4Hash() public { audOut = true; _gasRun(4, ZetherTypes.TransferMode.HASH); }
    function test_gasOutM4Bundle() public { audOut = true; _gasRun(4, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasOutM4None() public { audOut = true; _gasRun(4, ZetherTypes.TransferMode.NONE); }
    function test_gasOutM8Hash() public { audOut = true; _gasRun(8, ZetherTypes.TransferMode.HASH); }
    function test_gasOutM8Bundle() public { audOut = true; _gasRun(8, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasOutM8None() public { audOut = true; _gasRun(8, ZetherTypes.TransferMode.NONE); }

    // ------------------------------------------------------------------ hiệu lực

    function test_effectsDecoysAndConservation() public {
        _funded(1000);
        uint256[] memory vs = new uint256[](4);
        (vs[0], vs[1], vs[2], vs[3]) = (0, 300, 0, 50);
        uint256 seq = tok.accountState(rs[1].ua).pendingSeq;
        Tx memory t = _proveMulti(tok, alice, _to(4), vs, 1000, carol.ua, ZetherTypes.TransferMode.HASH);
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.HASH, t, carol.ua);
        assertEq(ref, keccak256(abi.encode(
            keccak256("SCAAS-ZETHER-ENTRY-V1"), block.chainid, address(tok), alice.ua, uint256(0)
        )));
        assertTrue(_holds(tok, alice, 1000 - 350 - FEE, true), "sender debited sum + fee");
        for (uint256 j; j < 4; ++j) {
            assertTrue(_holds(tok, rs[j], vs[j], false), "recipient pending = its v (decoys 0)");
        }
        assertEq(tok.accountState(rs[1].ua).pendingSeq, seq + 1, "every recipient gets a credit");
        assertEq(tok.accountState(rs[0].ua).pendingSeq, 1, "decoys too");
        assertTrue(_holds(tok, carol, FEE, false), "beneficiary");
        assertEq(tok.sendCounter(alice.ua), 1);
        assertEq(tok.totalShielded(), 1000, "nothing created or destroyed");
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
        pl[95] = bytes1(0);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadRecipientCount.selector, 0));
        tok.transferConfidential(pl, t.proof, "", _none());
        pl[95] = bytes1(uint8(17));
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadRecipientCount.selector, 17));
        tok.transferConfidential(pl, t.proof, "", _none());
        // M = 3 with two legs: length
        pl[95] = bytes1(uint8(3));
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadPayload.selector, t.payload.length));
        tok.transferConfidential(pl, t.proof, "", _none());
        // duplicate recipient, self, unregistered
        User[] memory dup = _to(2);
        dup[1] = dup[0];
        Tx memory d = _proveMultiUnchecked(dup, vs);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.DuplicateRecipient.selector, rs[0].ua));
        tok.transferConfidential(d.payload, t.proof, "", _none());
        User[] memory self = _to(2);
        self[1] = alice;
        d = _proveMultiUnchecked(self, vs);
        vm.expectRevert(IZetherToken.SelfTransfer.selector);
        tok.transferConfidential(d.payload, t.proof, "", _none());
        User[] memory stranger = _to(2);
        stranger[1].y = _pubOf(0x5757);
        stranger[1].ua = ZetherTypes.toUA(stranger[1].y);
        d = _proveMultiUnchecked(stranger, vs);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, stranger[1].ua));
        tok.transferConfidential(d.payload, t.proof, "", _none());
        // tampered C_deb, C_out_2, C_aud_1
        uint256[3] memory offs = [96 + 2 * p, 96 + 3 * p + 3 * p + p, 96 + 3 * p + 2 * p];
        for (uint256 i; i < 3; ++i) {
            bytes memory tampered = _replacePoint(t.payload, offs[i]);
            vm.expectRevert(IZetherToken.ProofRejected.selector);
            tok.transferConfidential(tampered, t.proof, "", _none());
        }
        // a HASH proof under another mode
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.transferConfidentialBundle(t.payload, t.proof, "", _none());
        // valid, then replay
        tok.transferConfidential(t.payload, t.proof, "", _none());
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.StaleSendCounter.selector, 1, 0));
        tok.transferConfidential(t.payload, t.proof, "", _none());
    }

    /// @dev Payload thôi (chưa proof) — các phép kiểm hình dạng chạy trước verify.
    function _proveMultiUnchecked(User[] memory to, uint256[] memory vs) internal view returns (Tx memory r) {
        r.payload = _multiPayload(tok, alice, to, vs, 7, tok.accountState(alice.ua));
    }

    function _pubOf(uint256 x) internal view returns (bytes memory) {
        return ver.g1MulBase(x);
    }

    // ------------------------------------------------------------------ tiết lộ theo mode

    /// @dev Opening Chaum-Pedersen leg `j`: SENDER_CP trên cơ sở `Y_tj` bằng `s`, còn lại trên `D_out`.
    function _cp(uint256 x, bytes32 ref, uint256 j, uint256 amount, ITransferDisclosure.OpeningKind kind, bytes memory payload)
        internal view returns (bytes memory)
    {
        uint256 p = ver.g1EncodedBytes();
        bytes memory base = kind == ITransferDisclosure.OpeningKind.SENDER_CP
            ? _cut(payload, 96 + 3 * p + 3 * p * j, p)
            : _cut(payload, 96 + p, p);
        return _cpOpening(tok, x, ref, j, amount, kind, base);
    }

    function test_disclosureHashMode() public {
        _funded(500);
        uint256[] memory vs = new uint256[](3);
        vs[1] = 77;
        Tx memory t = _proveMulti(tok, alice, _to(3), vs, 500, _none(), ZetherTypes.TransferMode.HASH);
        bytes memory bundles = _bundlesOf(t.payload);
        bytes32 expected = keccak256(abi.encode(keccak256("SCAAS-ZETHER-ENTRY-V1"), block.chainid, address(tok), alice.ua, uint256(0)));
        vm.expectEmit(true, false, false, true, address(tok));
        emit IZetherToken.TransferBundles(expected, bundles);
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.HASH, t, _none());
        _discloseAll(ref, t, bundles);
        // bundles that do not match the stored hash
        bytes memory wrong = bytes.concat(bundles);
        wrong[0] = bytes1(uint8(wrong[0]) ^ 1);
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.BundlesMismatch.selector, ref));
        _vta(tok, ref, 1, 77, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s), wrong);
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.BundlesMismatch.selector, ref));
        _vta(tok, ref, 1, 77, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s), "");
    }

    function test_disclosureBundleMode() public {
        _funded(500);
        uint256[] memory vs = new uint256[](3);
        vs[1] = 77;
        Tx memory t = _proveMulti(tok, alice, _to(3), vs, 500, _none(), ZetherTypes.TransferMode.BUNDLE);
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.BUNDLE, t, _none());
        _discloseAll(ref, t, ""); // stored: no bundles needed
    }

    function test_disclosureNoBundleModeIsOffChainOnly() public {
        _funded(500);
        uint256[] memory vs = new uint256[](3);
        vs[1] = 77;
        Tx memory t = _proveMulti(tok, alice, _to(3), vs, 500, _none(), ZetherTypes.TransferMode.NONE);
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.NONE, t, _none());
        bytes memory bundles = _bundlesOf(t.payload);
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.UnknownEntry.selector, ref));
        _vta(tok, ref, 1, 77, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s), bundles);
        // off chain: the sender's s opens the leg read from calldata
        bytes memory b1 = _cut(_bundlesOf(t.payload), 4 * ver.g1EncodedBytes(), 4 * ver.g1EncodedBytes());
        uint256 p = ver.g1EncodedBytes();
        assertEq(ver.g1MulBase(t.s), _cut(b1, 2 * p, p), "D_out = [s]G");
        assertEq(ver.g1Add(ver.g1MulBase(77), ver.g1Mul(rs[1].y, t.s)), _cut(b1, p, p), "C_out = [v]G + [s]Y_t");
    }

    /// @dev Cả bốn opening trên leg thật, `s` mở cả leg mồi (owner Z3), opening không chuyển leg, chỉ số ngoài khoảng.
    function _discloseAll(bytes32 ref, Tx memory t, bytes memory bundles) internal {
        _discloseCp(ref, t, bundles);
        ITransferDisclosure.OpeningKind S = ITransferDisclosure.OpeningKind.SENDER_S;
        ITransferDisclosure.OpeningKind RX = ITransferDisclosure.OpeningKind.RECEIVER_X;
        assertTrue(_vta(tok, ref, 1, 77, S, abi.encode(t.s), bundles), "sender opens the real leg");
        assertFalse(_vta(tok, ref, 1, 78, S, abi.encode(t.s), bundles));
        assertTrue(_vta(tok, ref, 0, 0, S, abi.encode(t.s), bundles), "s also opens a decoy (Z3)");
        bytes memory rx = _cp(rs[1].x, ref, 1, 77, RX, t.payload);
        assertTrue(_vta(tok, ref, 1, 77, RX, rx, bundles));
        assertFalse(_vta(tok, ref, 2, 77, RX, rx, bundles), "an opening does not move to another leg");
        bytes memory au = _cp(X_AUD, ref, 1, 77, ITransferDisclosure.OpeningKind.AUDITOR, t.payload);
        assertEq(_vta(tok, ref, 1, 77, ITransferDisclosure.OpeningKind.AUDITOR, au, bundles), !audOut,
            "auditor opens unless left out (Z12)");
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.BadRecipientIndex.selector, 3));
        _vta(tok, ref, 3, 0, S, abi.encode(t.s), bundles);
        (bytes memory ct, bytes memory yTo) = dis.transferCiphertext(address(tok), ref, 1, bundles);
        assertEq(yTo, rs[1].y);
        assertEq(ct.length, 3 * ver.g1EncodedBytes());
    }

    /// @dev SENDER_CP (Z10): chỉ leg j mở, challenge ràng j.
    function _discloseCp(bytes32 ref, Tx memory t, bytes memory bundles) internal view {
        ITransferDisclosure.OpeningKind CP = ITransferDisclosure.OpeningKind.SENDER_CP;
        bytes memory cp = _cp(t.s, ref, 1, 77, CP, t.payload);
        assertTrue(_vta(tok, ref, 1, 77, CP, cp, bundles), "sender CP opens leg 1");
        assertFalse(_vta(tok, ref, 1, 78, CP, cp, bundles), "wrong amount");
        assertFalse(_vta(tok, ref, 0, 77, CP, cp, bundles), "wrong leg");
        assertFalse(_vta(tok, ref, 0, 0, CP, cp, bundles), "a proof for leg 1 does not open leg 0");
        assertFalse(_vta(tok, ref, 1, 77, ITransferDisclosure.OpeningKind.RECEIVER_X, cp, bundles), "kind is bound");
        bytes memory cp0 = _cp(t.s, ref, 0, 0, CP, t.payload);
        assertTrue(_vta(tok, ref, 0, 0, CP, cp0, bundles), "decoy opens with its own proof");
        assertFalse(_vta(tok, ref, 1, 0, CP, cp0, bundles));
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
        tok.transferConfidentialBundle(t.payload, on.proof, "", _none());
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.transferConfidentialBundle(on.payload, t.proof, "", _none());
        bytes32 ref = _send(tok, ZetherTypes.TransferMode.BUNDLE, t, _none());
        assertTrue(_holds(tok, rs[1], 77, false));
        assertTrue(_holds(tok, alice, 423, true));
        audOut = true;
        _discloseAll(ref, t, "");
    }

    function test_auditorLegsMixedReverts() public {
        _funded(500);
        uint256[] memory vs = new uint256[](2);
        vs[1] = 9;
        Tx memory t = _proveMulti(tok, alice, _to(2), vs, 500, _none(), ZetherTypes.TransferMode.HASH);
        uint256 p = ver.g1EncodedBytes();
        bytes memory pl = bytes.concat(t.payload);
        for (uint256 i; i < p; ++i) pl[96 + 5 * p + i] = 0; // C_aud_1 = O, C_aud_2 ≠ O
        vm.expectRevert(IZetherToken.AuditorLegsMixed.selector);
        tok.transferConfidential(pl, t.proof, "", _none());
        vm.expectRevert(IZetherToken.AuditorLegsMixed.selector);
        tok.transferStatement(pl, _none(), ZetherTypes.TransferMode.HASH);
    }

    /// Token không có auditor: C_aud ≠ O không "bật" được auditor — statement giữ Y_a = O, verifier từ chối.
    function test_auditorOffTokenRejectsCAud() public {
        tok = _newToken(false, "noaud2");
        _funded(500);
        uint256[] memory vs = new uint256[](1);
        vs[0] = 5;
        Tx memory t = _proveMulti(tok, alice, _to(1), vs, 500, _none(), ZetherTypes.TransferMode.HASH);
        bytes memory pl = _replacePoint(t.payload, 96 + 5 * ver.g1EncodedBytes());
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.transferConfidential(pl, t.proof, "", _none());
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
    function _measure(Escrow3P esc, bytes32 ref, uint256 j, uint256 k, bytes memory o, bytes memory bundles)
        internal returns (uint256)
    {
        vm.cool(address(tok));
        vm.cool(address(dis));
        vm.cool(address(ver));
        return esc.measure(IZetherToken(address(tok)), ref, j, 1000, ITransferDisclosure.OpeningKind(k), o, bundles);
    }

    function _gasKinds(string memory tag, bytes32 ref, uint256 j, bytes[4] memory o, bytes memory bundles) internal {
        Escrow3P esc = new Escrow3P();
        string[4] memory names = ["SENDER_S", "RECEIVER_X", "AUDITOR", "SENDER_CP"];
        for (uint256 k; k < 4; ++k) {
            console2.log(string.concat(
                bls ? "bls12-381" : "bn254", " disclose ", tag, " ", names[k], " gas ",
                vm.toString(_measure(esc, ref, j, k, o[k], bundles)), " bundles ", vm.toString(bundles.length)
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
        bytes memory bundles = mode == ZetherTypes.TransferMode.HASH ? _bundlesOf(t.payload) : bytes("");
        bytes[4] memory o = [
            abi.encode(t.s),
            _cp(rs[j].x, ref, j, 1000, ITransferDisclosure.OpeningKind.RECEIVER_X, t.payload),
            _cp(X_AUD, ref, j, 1000, ITransferDisclosure.OpeningKind.AUDITOR, t.payload),
            _cp(t.s, ref, j, 1000, ITransferDisclosure.OpeningKind.SENDER_CP, t.payload)
        ];
        _gasKinds(string.concat("M=", vm.toString(m), " ", _modeName(mode)), ref, j, o, bundles);
    }

    function test_gasDiscloseM1Bundle() public { _gasDisclose(1, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasDiscloseM8Bundle() public { _gasDisclose(8, ZetherTypes.TransferMode.BUNDLE); }
    function test_gasDiscloseM1Hash() public { _gasDisclose(1, ZetherTypes.TransferMode.HASH); }
    function test_gasDiscloseM8Hash() public { _gasDisclose(8, ZetherTypes.TransferMode.HASH); }

    function test_gasDiscloseSingle() public {
        _funded(1_000_000);
        Tx memory t = _proveTransfer(tok, alice, rs[0], 1000, 1_000_000, _none(), 0);
        bytes32 ref = _direct(tok, t, _none());
        bytes memory dOut = _cut(t.payload, 64 + 3 * ver.g1EncodedBytes(), ver.g1EncodedBytes()); // Y_f Y_t C_out D_out …
        bytes[4] memory o = [
            abi.encode(t.s),
            _cpOpening(tok, rs[0].x, ref, 0, 1000, ITransferDisclosure.OpeningKind.RECEIVER_X, dOut),
            _cpOpening(tok, X_AUD, ref, 0, 1000, ITransferDisclosure.OpeningKind.AUDITOR, dOut),
            _cpOpening(tok, t.s, ref, 0, 1000, ITransferDisclosure.OpeningKind.SENDER_CP, rs[0].y)
        ];
        _gasKinds("Single", ref, 0, o, "");
    }
}

/// @notice Contract bên thứ ba: tìm `ZetherDisclosure` chuẩn từ token và kiểm on-chain. Không còn attestation
///         (Z9): ai cần vết on-chain thì tự ghi, như `released` ở đây.
contract Escrow3P {
    mapping(bytes32 => uint256) public released;

    function release(IZetherToken token, bytes32 ref, uint256 j, uint256 amount, bytes calldata opening)
        external returns (bool)
    {
        bool ok = token.disclosure().verifyTransferAmount(
            address(token), ref, j, amount, ITransferDisclosure.OpeningKind.SENDER_CP, opening, ""
        );
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
        bytes calldata opening,
        bytes calldata bundles
    ) external view returns (uint256 used) {
        ITransferDisclosure d = token.disclosure();
        uint256 g0 = gasleft();
        bool ok = d.verifyTransferAmount(address(token), ref, j, amount, kind, opening, bundles);
        used = g0 - gasleft();
        require(ok, "not proven");
    }
}

contract ZetherMultiBn254Test is ZetherMultiSuite {
    function _curve() internal pure override returns (bool) { return false; }
}

contract ZetherMultiBls12381Test is ZetherMultiSuite {
    function _curve() internal pure override returns (bool) { return true; }
}
