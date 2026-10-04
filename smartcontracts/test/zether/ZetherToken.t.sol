// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {console2} from "forge-std/Test.sol";
import {ZetherFixture} from "./helpers/ZetherFixture.sol";
import {ZetherToken} from "../../src/zether/ZetherToken.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ITransferDisclosure} from "../../src/zether/ITransferDisclosure.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {ZetherTranscript} from "../../src/zether/ZetherTranscript.sol";
import {ZetherKeys} from "./helpers/ZetherKeys.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeeMode, FeePolicy} from "../../src/common/FeePolicy.sol";

/// @notice Vòng đời đầy đủ trên token thật (clone qua factory, verifier thật, proof thật từ prover test),
///         chạy cho CẢ HAI đường cong qua hai contract con ở cuối file.
abstract contract ZetherTokenSuite is ZetherFixture {
    function _curve() internal pure virtual returns (bool);

    function setUp() public {
        _deploy(_curve(), true);
    }

    function _bal(User memory u) internal view returns (uint256 a, uint256 p) {
        return _balances(tok, u, 1100);
    }

    // ------------------------------------------------------------------ vòng đời + bảo toàn

    function _vta(bytes32 ref, uint256 amount, ITransferDisclosure.OpeningKind kind, bytes memory opening)
        internal view returns (bool)
    {
        (bool ok, bytes memory ret) = address(tok).staticcall(
            abi.encodeWithSelector(ITransferDisclosure.verifyTransferAmount.selector, ref, amount, uint8(kind), opening)
        );
        if (!ok) assembly { revert(add(ret, 32), mload(ret)) }
        return abi.decode(ret, (bool));
    }

    function _ata(bytes32 ref, uint256 amount, ITransferDisclosure.OpeningKind kind, bytes memory opening) internal {
        (bool ok, bytes memory ret) = address(tok).call(
            abi.encodeWithSelector(ITransferDisclosure.attestTransferAmount.selector, ref, amount, uint8(kind), opening)
        );
        if (!ok) assembly { revert(add(ret, 32), mload(ret)) }
    }

    function test_lifecycleFundTransferRollOverBurn() public {
        _fund(tok, alice, 1000);
        _assertConservation(tok, 1100);
        (uint256 a, uint256 p) = _bal(alice);
        assertEq(a, 0);
        assertEq(p, 1000, "fund lands in pending");

        tok.rollOverPublic(alice.ua);
        (a, p) = _bal(alice);
        assertEq(a, 1000);
        assertEq(p, 0);
        assertEq(tok.accountState(alice.ua).accSeq, 1);

        // alice → bob 300, phí tầng trong FEE cho carol (public scalar)
        Tx memory t1 = _proveTransfer(tok, alice, bob, 300, 1000, carol.ua, 0);
        uint256 g0 = gasleft();
        bytes32 ref = _direct(tok, t1, carol.ua);
        console2.log(bls ? "bls12-381" : "bn254", "transferConfidential (direct, auditor, fee) gas", g0 - gasleft());
        (a,) = _bal(alice);
        assertEq(a, 1000 - 300 - FEE, "sender acc debited v + fee");
        (, p) = _bal(bob);
        assertEq(p, 300, "receiver pending credited");
        (, p) = _bal(carol);
        assertEq(p, FEE, "beneficiary pending credited [fee]G");
        assertEq(tok.sendCounter(alice.ua), 1);
        assertTrue(ref != bytes32(0));
        _assertConservation(tok, 1100);

        // bob tiêu tiền vừa nhận: rollOver (PUBLIC, không chữ ký) rồi chuyển lại 100
        tok.rollOverPublic(bob.ua);
        _direct(tok, _proveTransfer(tok, bob, alice, 100, 300, _none(), 0), _none());
        _assertConservation(tok, 1100);

        // bob rút 50 ra underlying công khai
        (bytes memory pl, bytes memory pr) = _proveBurn(tok, bob, 50, 200, address(0xD00D), _none(), 0);
        g0 = gasleft();
        tok.burn(pl, 50, address(0xD00D), _none(), pr, "");
        console2.log(bls ? "bls12-381" : "bn254", "burn gas", g0 - gasleft());
        assertEq(usd.balanceOf(address(0xD00D)), 50 * SCALE);
        (a,) = _bal(bob);
        assertEq(a, 150);

        // alice gộp 100 vừa nhận rồi rút 700 kèm phí cho carol
        tok.rollOverPublic(alice.ua);
        (pl, pr) = _proveBurn(tok, alice, 700, 798, address(0xD00D), carol.ua, 0);
        tok.burn(pl, 700, address(0xD00D), carol.ua, pr, "");
        (a,) = _bal(alice);
        assertEq(a, 798 - 700 - FEE);
        (, p) = _bal(carol);
        assertEq(p, 2 * FEE);
        assertEq(tok.totalShielded(), 1000 - 750);
        _assertConservation(tok, 1100);
    }

    function test_fundAndRollOverGas() public {
        usd.mint(address(this), 1000 * SCALE);
        usd.approve(address(tok), 1000 * SCALE);
        uint256 g0 = gasleft();
        tok.fund(alice.y, 500);
        console2.log(bls ? "bls12-381" : "bn254", "fund (first credit) gas", g0 - gasleft());
        g0 = gasleft();
        tok.fund(alice.y, 500);
        console2.log(bls ? "bls12-381" : "bn254", "fund (warm) gas", g0 - gasleft());
        g0 = gasleft();
        tok.rollOverPublic(alice.ua);
        console2.log(bls ? "bls12-381" : "bn254", "rollOverPublic gas", g0 - gasleft());
        g0 = gasleft();
        tok.rollOverPublic(alice.ua);
        console2.log(bls ? "bls12-381" : "bn254", "rollOverPublic no-op gas", g0 - gasleft());
    }

    // ------------------------------------------------------------------ rollOver: hai chế độ

    function test_rollOverPublicIsNoOpWithoutNewCredit() public {
        _fund(tok, alice, 10);
        tok.rollOverPublic(alice.ua);
        tok.rollOverPublic(alice.ua); // không revert, không bump
        assertEq(tok.accountState(alice.ua).accSeq, 1);
        ZetherTypes.UA[] memory batch = new ZetherTypes.UA[](2);
        (batch[0], batch[1]) = (alice.ua, bob.ua);
        tok.rollOverBatch(batch);
        assertEq(tok.accountState(alice.ua).accSeq, 1);
    }

    function _modeSig(User memory u, ZetherTypes.RollOverMode mode, uint64 nonce, uint64 until)
        internal view returns (bytes memory)
    {
        bytes32 d = keccak256(bytes.concat(
            abi.encode(keccak256("ZETHER_SET_ROLLOVER_MODE_V1"), block.chainid, address(tok)),
            abi.encode(u.ua, uint8(mode), nonce, until)
        ));
        return abi.encode(u.y, ZetherKeys.schnorr(u.x, d, bls));
    }

    function _rollSig(User memory u, uint64 accSeq, uint64 pendSeq, uint64 until) internal view returns (bytes memory) {
        bytes32 d = keccak256(bytes.concat(
            abi.encode(keccak256("ZETHER_ROLLOVER_V1"), block.chainid, address(tok)),
            abi.encode(u.ua, accSeq, pendSeq, until)
        ));
        return abi.encode(u.y, ZetherKeys.schnorr(u.x, d, bls));
    }

    /// Kẻ grief số dư 0 chèn transfer v=0 trước `rollOverSigned`: pendingSeq tiến nhưng rollOver của chủ vẫn
    /// chạy (gộp luôn credit mới); chữ ký không phát lại được vì `accSeq` đã tiến.
    function test_rollOverSignedSurvivesFrontRunCredit() public {
        uint64 until = uint64(block.number + 50);
        tok.setRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until,
            _modeSig(alice, ZetherTypes.RollOverMode.OWNER_ONLY, 0, until));
        _fund(tok, alice, 10);
        bytes memory rs = _rollSig(alice, 0, 1, until);
        _direct(tok, _proveTransfer(tok, bob, alice, 0, 0, _none(), 0), _none());
        assertEq(tok.accountState(alice.ua).pendingSeq, 2);
        tok.rollOverSigned(alice.ua, 1, until, rs);
        (uint256 a,) = _bal(alice);
        assertEq(a, 10);
        _fund(tok, alice, 5);
        // phát lại bị chặn ngay ở cổng credit-mới (1 ≤ lastRolled = 2), trước cả chữ ký (accSeq đã tiến)
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.PendingSeqMismatch.selector, 1, 3));
        tok.rollOverSigned(alice.ua, 1, until, rs);
    }

    /// Chữ ký rollOver không nêu credit mới (expected ≤ lastRolled) là no-op nên không tăng `accSeq`; với `≥`
    /// nó thành vé để bất kỳ ai ép rollOver khi credit sau đến, giết proof đang bay của chủ `OWNER_ONLY`.
    function test_rollOverSignedWithoutNewCreditIsRejected() public {
        uint64 until = uint64(block.number + 50);
        tok.setRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until,
            _modeSig(alice, ZetherTypes.RollOverMode.OWNER_ONLY, 0, until));
        _fund(tok, alice, 10);
        tok.rollOverSigned(alice.ua, 1, until, _rollSig(alice, 0, 1, until));
        bytes memory stale = _rollSig(alice, 1, 1, until);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.PendingSeqMismatch.selector, 1, 1));
        tok.rollOverSigned(alice.ua, 1, until, stale);
        _fund(tok, alice, 5);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.PendingSeqMismatch.selector, 1, 2));
        tok.rollOverSigned(alice.ua, 1, until, stale);
        assertEq(tok.accountState(alice.ua).accSeq, 1);
    }

    function test_setRollOverModeExpired() public {
        uint64 until = uint64(block.number + 5);
        bytes memory sig = _modeSig(alice, ZetherTypes.RollOverMode.OWNER_ONLY, 0, until);
        vm.roll(until + 1);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.RollOverExpired.selector, until));
        tok.setRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, sig);
    }

    function test_ownerOnlyRollOver() public {
        uint64 until = uint64(block.number + 50);
        bytes memory sig = _modeSig(alice, ZetherTypes.RollOverMode.OWNER_ONLY, 0, until);
        tok.setRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, sig);
        vm.expectRevert(); // phát lại chữ ký cũ: modeNonce đã tiến
        tok.setRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, sig);
        _fund(tok, alice, 10);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.RollOverOwnerOnly.selector, alice.ua));
        tok.rollOverPublic(alice.ua);
        ZetherTypes.UA[] memory batch = new ZetherTypes.UA[](1);
        batch[0] = alice.ua;
        tok.rollOverBatch(batch); // bỏ qua, không revert
        assertEq(tok.accountState(alice.ua).accSeq, 0);

        bytes memory rs = _rollSig(alice, 0, 1, until);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.PendingSeqMismatch.selector, 2, 1));
        tok.rollOverSigned(alice.ua, 2, until, rs);
        uint256 g0 = gasleft();
        tok.rollOverSigned(alice.ua, 1, until, rs);
        console2.log(bls ? "bls12-381" : "bn254", "rollOverSigned (Schnorr) gas", g0 - gasleft());
        assertEq(tok.accountState(alice.ua).accSeq, 1);
        (uint256 a,) = _bal(alice);
        assertEq(a, 10);

        // chữ ký rollOver hết hạn: tấn công "giữ blob" bị chặn bởi validUntilBlock
        _fund(tok, alice, 5);
        bytes memory late = _rollSig(alice, 1, 2, until);
        vm.roll(until + 1);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.RollOverExpired.selector, until));
        tok.rollOverSigned(alice.ua, 2, until, late);
    }

    function test_rollOverSignedRejectsForeignSignature() public {
        uint64 until = uint64(block.number + 50);
        _fund(tok, alice, 10);
        bytes memory forged = _rollSig(bob, 0, 1, until); // bob ký thay alice
        vm.expectRevert();
        tok.rollOverSigned(alice.ua, 1, until, forged);
    }

    // ------------------------------------------------------------------ race acc/pending (SRS §7.6–7.7)

    /// Credit đến giữa lúc prove và lúc gửi chỉ đổi pending: proof vẫn sống.
    function test_incomingCreditDoesNotKillInFlightProof() public {
        _fund(tok, alice, 500);
        tok.rollOverPublic(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        _fund(tok, alice, 7); // ai đó gửi bụi cho alice
        _direct(tok, t, _none());
        (uint256 a, uint256 p) = _bal(alice);
        assertEq(a, 400);
        assertEq(p, 7);
    }

    /// rollOver chen ngang làm `accSeq` tiến ⇒ proof cũ bị từ chối RẺ, trước verify.
    function test_rollOverBetweenProveAndSubmitRejectsCheaply() public {
        _fund(tok, alice, 500);
        tok.rollOverPublic(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        _fund(tok, alice, 7);
        tok.rollOverPublic(alice.ua);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.StaleAccSeq.selector, 2, 1));
        _direct(tok, t, _none());
    }

    // ------------------------------------------------------------------ replay

    function test_replaySameProofRejected() public {
        _fund(tok, alice, 500);
        tok.rollOverPublic(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        _direct(tok, t, _none());
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.StaleSendCounter.selector, 1, 0));
        _direct(tok, t, _none());
    }

    /// Cùng verifier, cùng registry, cùng accSeq/sendCounter trên token khác: header (token) khác ⇒ fail.
    function test_replayAcrossTokensRejected() public {
        ZetherToken other = _newToken(true, "zusd-2");
        _fund(tok, alice, 500);
        _fund(other, alice, 500);
        tok.rollOverPublic(alice.ua);
        other.rollOverPublic(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        _direct(other, t, _none());
        _direct(tok, t, _none()); // đúng token thì qua
    }

    function test_replayAcrossChainsRejected() public {
        _fund(tok, alice, 500);
        tok.rollOverPublic(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        vm.chainId(1337); // chain dev khác, cùng state
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        _direct(tok, t, _none());
    }

    // ------------------------------------------------------------------ phong bì meta-tx + phí

    uint256 constant PAYER_PK = 0x9A7E5;

    function _relayedSetup() internal returns (address payer) {
        payer = vm.addr(PAYER_PK);
        usd.mint(payer, 1000);
        vm.startPrank(payer);
        usd.approve(address(tok), 1000);
        tok.wrap(1000); // số dư công khai để trả phí ngoài
        vm.stopPrank();
        _fund(tok, alice, 500);
        tok.rollOverPublic(alice.ua);
    }

    function _zData(Tx memory t, ZetherTypes.UA ben) internal view returns (bytes memory) {
        return abi.encodePacked(tok.OP_ZTRANSFER(), abi.encode(t.payload, t.proof, bytes(""), ZetherTypes.UA.unwrap(ben)));
    }

    /// Proof ràng `envelopeBinding` ⇒ dựng statement RELAYED trước, rồi mới ký phong bì chứa proof.
    function _relayedTx(uint256 batch, uint256 fee) internal view returns (MetaTxLib.MetaTransaction memory m, Tx memory t) {
        m = _mt(vm.addr(PAYER_PK), "", batch, MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_FEE_FIXED, fee);
        t = _proveTransfer(tok, alice, bob, 100, 500, carol.ua, tok.envelopeBinding(m));
        m.data = _zData(t, carol.ua);
    }

    function test_relayedTransferChargesOuterAndInnerFees() public {
        address payer = _relayedSetup();
        (MetaTxLib.MetaTransaction memory m,) = _relayedTx(uint256(keccak256("lane-1")), 25);
        bytes memory sig = _sign(PAYER_PK, tok, m);
        vm.prank(relayer);
        uint256 g0 = gasleft();
        tok.executeMetaTransaction(m, sig);
        console2.log(bls ? "bls12-381" : "bn254", "relayed transferConfidential gas", g0 - gasleft());
        assertEq(tok.balanceOf(relayer), 25, "outer fee: public ERC-20 to relayer");
        assertEq(tok.balanceOf(payer), 975);
        (, uint256 p) = _bal(carol);
        assertEq(p, FEE, "inner fee: [fee]G into beneficiary pending");
        (uint256 a,) = _bal(alice);
        assertEq(a, 500 - 100 - FEE);
        assertEq(tok.metaNonce(payer, m.batch), 1);
        _assertConservation(tok, 1100);
    }

    function test_proofLiftedOutOfEnvelopeRejected() public {
        _relayedSetup();
        (, Tx memory t) = _relayedTx(7, 25);
        vm.expectRevert(IZetherToken.ProofRejected.selector); // statement DIRECT ≠ RELAYED
        tok.transferConfidential(t.payload, t.proof, "", carol.ua);
    }

    function test_proofMovedToAnotherEnvelopeRejected() public {
        _relayedSetup();
        (MetaTxLib.MetaTransaction memory m,) = _relayedTx(7, 25);
        m.batch = 8; // phong bì khác (khác lane), cùng data ⇒ binding khác
        bytes memory sig = _sign(PAYER_PK, tok, m);
        vm.prank(relayer);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.executeMetaTransaction(m, sig);
    }

    function test_relayedPercentFeeForbidden() public {
        _relayedSetup();
        (MetaTxLib.MetaTransaction memory m,) = _relayedTx(7, 25);
        m.mode = MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_FEE_PERCENT;
        bytes memory sig = _sign(PAYER_PK, tok, m);
        vm.prank(relayer);
        vm.expectRevert(FeePolicy.PercentFeeForbiddenOnConfidential.selector);
        tok.executeMetaTransaction(m, sig);
    }

    /// Phong bì không đủ phí ngoài revert TRƯỚC mọi precompile (relayer không đốt ~2M gas).
    function test_relayedInsufficientFeeFailsBeforeVerify() public {
        _relayedSetup();
        (MetaTxLib.MetaTransaction memory m,) = _relayedTx(7, 5000);
        bytes memory sig = _sign(PAYER_PK, tok, m);
        vm.prank(relayer);
        uint256 g0 = gasleft();
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("MetaTxInsufficientForFee(uint256,uint256)")), 5000, 1000));
        tok.executeMetaTransaction(m, sig);
        assertLt(g0 - gasleft(), 200_000, "fail-fast");
    }

    function test_relayedBurn() public {
        address payer = _relayedSetup();
        MetaTxLib.MetaTransaction memory m =
            _mt(payer, "", 11, MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_FEE_FIXED, 9);
        (bytes memory pl, bytes memory pr) = _proveBurn(tok, alice, 60, 500, address(0xB0C), carol.ua, tok.envelopeBinding(m));
        m.data = abi.encodePacked(tok.OP_ZBURN(), abi.encode(pl, uint256(60), address(0xB0C), ZetherTypes.UA.unwrap(carol.ua), pr, bytes("")));
        // bóc proof ra gọi thẳng: statement DIRECT ⇒ từ chối
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.burn(pl, 60, address(0xB0C), carol.ua, pr, "");
        bytes memory sig = _sign(PAYER_PK, tok, m);
        vm.prank(relayer);
        tok.executeMetaTransaction(m, sig);
        assertEq(usd.balanceOf(address(0xB0C)), 60 * SCALE);
        assertEq(tok.balanceOf(relayer), 9);
        (uint256 a,) = _bal(alice);
        assertEq(a, 500 - 60 - FEE);
        _assertConservation(tok, 1100);
    }

    function test_publicMetaTransferStillWorks() public {
        address payer = _relayedSetup();
        MetaTxLib.MetaTransaction memory m = _mt(payer, "", 1, MetaTxLib.MODE_FEE_PERCENT, 10_000);
        m.to = address(0x7777);
        m.value = 500;
        bytes memory sig = _sign(PAYER_PK, tok, m);
        vm.prank(relayer);
        tok.executeMetaTransaction(m, sig);
        assertEq(tok.balanceOf(address(0x7777)), 500);
        assertEq(tok.balanceOf(relayer), 5); // 1% của 500
    }

    // ------------------------------------------------------------------ tiết lộ (ITransferDisclosure)

    function _cpOpening(uint256 x, bytes32 ref, uint256 amount, ITransferDisclosure.OpeningKind kind)
        internal view returns (bytes memory)
    {
        uint256 r = ver.groupOrder();
        uint256 k = uint256(keccak256(abi.encode("cp", x, ref))) % r;
        bytes memory a1a2 = bytes.concat(ver.g1MulBase(k), ver.g1Mul(_dOut(ref), k));
        uint256 e = ZetherTranscript.hashToScalar(keccak256(bytes.concat(
            abi.encodePacked("BAMBOO-ZETHER-DISCLOSE-V1", block.chainid, address(tok)),
            abi.encodePacked(ref, amount, uint8(kind), a1a2)
        )), r);
        uint256 p = ver.g1EncodedBytes();
        return abi.encode(_cut(a1a2, 0, p), _cut(a1a2, p, p), addmod(k, mulmod(e, x, r), r));
    }

    function _dOut(bytes32 ref) internal view returns (bytes memory) {
        (bytes memory ct,) = tok.transferCiphertext(ref);
        return _cut(ct, ver.g1EncodedBytes(), ver.g1EncodedBytes());
    }

    function _cut(bytes memory a, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) out[i] = a[off + i];
    }

    function test_disclosureThreeOpenings() public {
        _fund(tok, alice, 500);
        tok.rollOverPublic(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 123, 500, _none(), 0);
        bytes32 ref = _direct(tok, t, _none());
        // người gửi mở bằng s
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s)));
        assertFalse(_vta(ref, 124, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s)));
        // người nhận mở bằng x_to, không cần người gửi
        bytes memory rx = _cpOpening(bob.x, ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X);
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X, rx));
        assertFalse(_vta(ref, 122, ITransferDisclosure.OpeningKind.RECEIVER_X, rx));
        bytes memory wrong = _cpOpening(alice.x, ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X);
        assertFalse(_vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X, wrong));
        // auditor mở C_aud
        bytes memory au = _cpOpening(X_AUD, ref, 123, ITransferDisclosure.OpeningKind.AUDITOR);
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.AUDITOR, au));
        // bí danh mod r và vượt n_v bị từ chối
        assertFalse(_vta(ref, 123 + ver.groupOrder(), ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s)));
        assertFalse(_vta(ref, 1 << 64, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s)));
        // attestation có dấu thời gian
        vm.expectEmit(true, true, false, true, address(tok));
        emit ITransferDisclosure.AmountAttested(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X, address(this), block.timestamp);
        _ata(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X, rx);
        vm.expectRevert(ITransferDisclosure.OpeningMalformed.selector);
        _ata(ref, 99, ITransferDisclosure.OpeningKind.RECEIVER_X, rx);
        // opening sai khuôn: s không đủ 32 byte, A1 sai độ dài, z ≥ r
        vm.expectRevert(ITransferDisclosure.OpeningMalformed.selector);
        _vta(ref, 123, ITransferDisclosure.OpeningKind.SENDER_S, new bytes(31));
        (bytes memory a1, bytes memory a2, uint256 z) = abi.decode(rx, (bytes, bytes, uint256));
        vm.expectRevert(ITransferDisclosure.OpeningMalformed.selector);
        _vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X, abi.encode(new bytes(1), a2, z));
        bytes memory zBig = abi.encode(a1, a2, ver.groupOrder());
        vm.expectRevert(ITransferDisclosure.OpeningMalformed.selector);
        _vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X, zBig);
        (bytes memory ct, bytes memory yTo) = tok.transferCiphertext(ref);
        assertEq(yTo, bob.y);
        assertEq(ct.length, 3 * ver.g1EncodedBytes());
    }

    /// limits D1/D5: một transfer > 2^32 đơn vị, số dư > 2^44 được giữ, chi (cả số dư trong một transfer)
    /// và rút; tiết lộ một khoản > 2^32 bằng cả ba opening. Số dư kiểm bằng `_holds` (check_balance).
    function test_largeValuesNv64() public {
        tok = _newToken(true, "big", uint256(1) << 54);
        uint256 b0 = (uint256(1) << 44) + 12_345;
        _fund(tok, alice, b0);
        tok.rollOverPublic(alice.ua);
        assertTrue(_holds(tok, alice, b0, true), "acc holds > 2^44");
        uint256 v = (uint256(1) << 33) + 7;
        Tx memory t = _proveTransfer(tok, alice, bob, v, b0, carol.ua, 0);
        uint256 g0 = gasleft();
        bytes32 ref = _direct(tok, t, carol.ua);
        console2.log(bls ? "bls12-381" : "bn254", "transferConfidential v > 2^32 (direct, auditor, fee) gas", g0 - gasleft());
        uint256 b1 = b0 - v - FEE;
        assertTrue(_holds(tok, alice, b1, true), "sender acc = b - v - fee");
        assertTrue(_holds(tok, bob, v, false), "receiver pending = v");
        assertTrue(_holds(tok, carol, FEE, false), "beneficiary pending = fee");
        _discloseLarge(ref, v, t.s);
        _spendAllAndBurn(b1, v);
    }

    /// Tiết lộ khoản > 2^32 bằng cả ba opening (D6: bundle không đổi); ≥ 2^n_v bị từ chối.
    function _discloseLarge(bytes32 ref, uint256 v, uint256 s) internal view {
        assertTrue(_vta(ref, v, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(s)));
        bytes memory rx = _cpOpening(bob.x, ref, v, ITransferDisclosure.OpeningKind.RECEIVER_X);
        assertTrue(_vta(ref, v, ITransferDisclosure.OpeningKind.RECEIVER_X, rx));
        assertTrue(_vta(ref, v, ITransferDisclosure.OpeningKind.AUDITOR,
            _cpOpening(X_AUD, ref, v, ITransferDisclosure.OpeningKind.AUDITOR)));
        assertFalse(_vta(ref, v - (uint256(1) << 32), ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(s)));
        assertFalse(_vta(ref, uint256(1) << 64, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(s)));
    }

    /// Cả số dư còn lại (> 2^44) trong MỘT transfer, rồi người nhận rút hết.
    function _spendAllAndBurn(uint256 b1, uint256 v) internal {
        _direct(tok, _proveTransfer(tok, alice, bob, b1, b1, _none(), 0), _none());
        assertTrue(_holds(tok, alice, 0, true), "sender emptied");
        tok.rollOverPublic(bob.ua);
        uint256 bb = v + b1;
        assertTrue(_holds(tok, bob, bb, true), "receiver acc = v + b1");
        (bytes memory pl, bytes memory pr) = _proveBurn(tok, bob, bb, bb, address(0xD00D), _none(), 0);
        tok.burn(pl, bb, address(0xD00D), _none(), pr, "");
        assertEq(usd.balanceOf(address(0xD00D)), bb * SCALE);
        assertEq(tok.totalShielded(), FEE, "only carol's fee left shielded");
    }

    /// Auditor giải mã ĐÚNG khoản được tiết lộ, không giải mã được số dư của ai.
    function test_auditorSeesTransferButNoBalance() public {
        _fund(tok, alice, 500);
        tok.rollOverPublic(alice.ua);
        bytes32 ref = _direct(tok, _proveTransfer(tok, alice, bob, 321, 500, _none(), 0), _none());
        (bytes memory ct,) = tok.transferCiphertext(ref);
        uint256 p = ver.g1EncodedBytes();
        bytes memory dOut = new bytes(p);
        bytes memory cAud = new bytes(p);
        for (uint256 i; i < p; ++i) {
            dOut[i] = ct[p + i];
            cAud[i] = ct[2 * p + i];
        }
        assertEq(_decrypt(cAud, dOut, X_AUD, 400), 321, "auditor reads C_aud");
        IZetherToken.AccountState memory s = tok.accountState(alice.ua);
        vm.expectRevert(bytes("decrypt: out of range"));
        this.decryptExt(s.accC, s.accD, X_AUD, 1100); // số dư 179 của alice: auditor không đọc được
        assertEq(_decrypt(s.accC, s.accD, alice.x, 1100), 179);
    }

    function decryptExt(bytes memory c, bytes memory d, uint256 x, uint256 max) external view returns (uint256) {
        return _decrypt(c, d, x, max);
    }
}

contract ZetherTokenBn254Test is ZetherTokenSuite {
    function _curve() internal pure override returns (bool) { return false; }
}

contract ZetherTokenBls12381Test is ZetherTokenSuite {
    function _curve() internal pure override returns (bool) { return true; }
}
