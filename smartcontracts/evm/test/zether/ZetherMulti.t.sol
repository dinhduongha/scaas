// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {console2} from "forge-std/Test.sol";
import {ZetherFixture} from "./helpers/ZetherFixture.sol";
import {ZetherToken} from "../../src/zether/ZetherToken.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ITransferDisclosure} from "../../src/zether/ITransferDisclosure.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {ZetherTranscript} from "../../src/zether/ZetherTranscript.sol";

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
            " gas ", vm.toString(used), " calldata ", vm.toString(cd)
        ));
        assertTrue(_holds(tok, alice, b - 1000 - FEE, true), "sender acc = b - sum(v) - fee");
    }

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

    function _cp(uint256 x, bytes32 ref, uint256 amount, ITransferDisclosure.OpeningKind kind, bytes memory dOut)
        internal view returns (bytes memory)
    {
        uint256 r = ver.groupOrder();
        uint256 k = uint256(keccak256(abi.encode("cp", x, ref, amount))) % r;
        bytes memory a1a2 = bytes.concat(ver.g1MulBase(k), ver.g1Mul(dOut, k));
        uint256 e = ZetherTranscript.hashToScalar(keccak256(bytes.concat(
            abi.encodePacked("SCAAS-ZETHER-DISCLOSE-V1", block.chainid, address(tok)),
            abi.encodePacked(ref, amount, uint8(kind), a1a2)
        )), r);
        uint256 p = ver.g1EncodedBytes();
        return abi.encode(_cut(a1a2, 0, p), _cut(a1a2, p, p), addmod(k, mulmod(e, x, r), r));
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
        tok.verifyTransferAmount(ref, 1, 77, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s), wrong);
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.BundlesMismatch.selector, ref));
        tok.verifyTransferAmount(ref, 1, 77, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s), "");
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
        tok.verifyTransferAmount(ref, 1, 77, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s), bundles);
        // off chain: the sender's s opens the leg read from calldata
        bytes memory b1 = _cut(_bundlesOf(t.payload), 4 * ver.g1EncodedBytes(), 4 * ver.g1EncodedBytes());
        uint256 p = ver.g1EncodedBytes();
        assertEq(ver.g1MulBase(t.s), _cut(b1, 2 * p, p), "D_out = [s]G");
        assertEq(ver.g1Add(ver.g1MulBase(77), ver.g1Mul(rs[1].y, t.s)), _cut(b1, p, p), "C_out = [v]G + [s]Y_t");
    }

    /// @dev Cả ba opening trên leg thật, `s` mở cả leg mồi (owner Z3), chỉ số ngoài khoảng, attestation.
    function _discloseAll(bytes32 ref, Tx memory t, bytes memory bundles) internal {
        uint256 p = ver.g1EncodedBytes();
        bytes memory dOut = _cut(t.payload, 96 + p, p);
        ITransferDisclosure.OpeningKind S = ITransferDisclosure.OpeningKind.SENDER_S;
        assertTrue(tok.verifyTransferAmount(ref, 1, 77, S, abi.encode(t.s), bundles), "sender opens the real leg");
        assertFalse(tok.verifyTransferAmount(ref, 1, 78, S, abi.encode(t.s), bundles));
        assertTrue(tok.verifyTransferAmount(ref, 0, 0, S, abi.encode(t.s), bundles), "s also opens a decoy (Z3)");
        bytes memory rx = _cp(rs[1].x, ref, 77, ITransferDisclosure.OpeningKind.RECEIVER_X, dOut);
        assertTrue(tok.verifyTransferAmount(ref, 1, 77, ITransferDisclosure.OpeningKind.RECEIVER_X, rx, bundles));
        assertFalse(tok.verifyTransferAmount(ref, 2, 77, ITransferDisclosure.OpeningKind.RECEIVER_X, rx, bundles),
            "an opening does not move to another leg");
        bytes memory au = _cp(X_AUD, ref, 77, ITransferDisclosure.OpeningKind.AUDITOR, dOut);
        assertTrue(tok.verifyTransferAmount(ref, 1, 77, ITransferDisclosure.OpeningKind.AUDITOR, au, bundles));
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.BadRecipientIndex.selector, 3));
        tok.verifyTransferAmount(ref, 3, 0, S, abi.encode(t.s), bundles);
        (bytes memory ct, bytes memory yTo) = tok.transferCiphertext(ref, 1, bundles);
        assertEq(yTo, rs[1].y);
        assertEq(ct.length, 3 * p);
        vm.expectEmit(true, true, false, true, address(tok));
        emit ITransferDisclosure.AmountAttested(ref, 1, 77, ITransferDisclosure.OpeningKind.RECEIVER_X, address(this), block.timestamp);
        tok.attestTransferAmount(ref, 1, 77, ITransferDisclosure.OpeningKind.RECEIVER_X, rx, bundles);
    }
}

contract ZetherMultiBn254Test is ZetherMultiSuite {
    function _curve() internal pure override returns (bool) { return false; }
}

contract ZetherMultiBls12381Test is ZetherMultiSuite {
    function _curve() internal pure override returns (bool) { return true; }
}
