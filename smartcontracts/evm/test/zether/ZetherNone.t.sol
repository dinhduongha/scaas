// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {ZetherFixture, ZUID} from "./helpers/ZetherFixture.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ITransferDisclosure} from "../../src/zether/ITransferDisclosure.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {ZetherKeys} from "./helpers/ZetherKeys.sol";

/// @notice The whole life of a `NONE_ZETHER` token (a factory clone, the real verifier, real proofs from the test
///         prover), on BOTH curves through the two contracts at the end: shield from the public balance, transfer,
///         roll-over, unshield into public units; replay protection; `chainUid` in every digest (CTR-ZTH-36);
///         disclosure.
abstract contract ZetherNoneSuite is ZetherFixture {
    function _curve() internal pure virtual returns (bool);

    function setUp() public {
        _deploy(_curve(), true);
    }

    function _bal(User memory u) internal view returns (uint256 a, uint256 p) {
        return _balances(tok, u, 1100);
    }

    function _vta(bytes32 ref, uint256 amount, ITransferDisclosure.OpeningKind kind, bytes memory opening)
        internal view returns (bool)
    {
        return _vta(tok, ref, 0, amount, kind, opening, "");
    }

    // ------------------------------------------------------------------ life cycle and conservation

    function test_lifecycleShieldTransferRollOverUnshield() public {
        _fund(tok, alice, 1000);
        _assertConservation(tok, 1100);
        (uint256 a, uint256 p) = _bal(alice);
        assertEq(a, 0);
        assertEq(p, 1000, "shield lands in pending");
        assertEq(tok.balanceOf(address(this)), 0, "the public units were burnt");

        tok.zetherRollOver(alice.ua);
        (a, p) = _bal(alice);
        assertEq(a, 1000);
        assertEq(p, 0);
        assertEq(tok.accountState(alice.ua).accSeq, 1);

        // alice → bob 300, inner fee FEE to carol (a public scalar)
        Tx memory t1 = _proveTransfer(tok, alice, bob, 300, 1000, carol.ua, 0);
        uint256 g0 = gasleft();
        bytes32 ref = _direct(tok, t1, carol.ua);
        console2.log(bls ? "bls12-381" : "bn254", "zetherTransferSingle (direct, auditor, fee) gas", g0 - gasleft());
        (a,) = _bal(alice);
        assertEq(a, 1000 - 300 - FEE, "sender acc debited v + fee");
        (, p) = _bal(bob);
        assertEq(p, 300, "receiver pending credited");
        (, p) = _bal(carol);
        assertEq(p, FEE, "beneficiary pending credited [fee]G");
        assertEq(tok.sendCounter(alice.ua), 1);
        assertEq(ref, _ref(tok, alice, 0), "entryRef carries chainUid");
        _assertConservation(tok, 1100);

        // bob spends what he received: roll-over (PUBLIC, no signature), then 100 back
        tok.zetherRollOver(bob.ua);
        _direct(tok, _proveTransfer(tok, bob, alice, 100, 300, _none(), 0), _none());
        _assertConservation(tok, 1100);

        // bob unshields 50 into public units
        (bytes memory pl, bytes memory pr) = _proveUnshield(tok, bob, 50, 200, address(0xD00D), _none(), 0);
        g0 = gasleft();
        tok.zetherUnshield(pl, pr, "", _none(), address(0xD00D), 50);
        console2.log(bls ? "bls12-381" : "bn254", "zetherUnshield gas", g0 - gasleft());
        assertEq(tok.balanceOf(address(0xD00D)), 50 * SCALE);
        (a,) = _bal(bob);
        assertEq(a, 150);

        // alice rolls the 100 over, then unshields 700 with a fee to carol
        tok.zetherRollOver(alice.ua);
        (pl, pr) = _proveUnshield(tok, alice, 700, 798, address(0xD00D), carol.ua, 0);
        tok.zetherUnshield(pl, pr, "", carol.ua, address(0xD00D), 700);
        (a,) = _bal(alice);
        assertEq(a, 798 - 700 - FEE);
        (, p) = _bal(carol);
        assertEq(p, 2 * FEE);
        assertEq(tok.totalShielded(), 1000 - 750);
        assertEq(tok.balanceOf(address(0xD00D)), 750 * SCALE);
        _assertConservation(tok, 1100);
    }

    function test_shieldAndRollOverGas() public {
        _public(tok, address(this), 1000 * SCALE);
        uint256 g0 = gasleft();
        tok.zetherShield(alice.y, 500);
        console2.log(bls ? "bls12-381" : "bn254", "zetherShield (first credit) gas", g0 - gasleft());
        g0 = gasleft();
        tok.zetherShield(alice.y, 500);
        console2.log(bls ? "bls12-381" : "bn254", "zetherShield (warm) gas", g0 - gasleft());
        g0 = gasleft();
        tok.zetherRollOver(alice.ua);
        console2.log(bls ? "bls12-381" : "bn254", "zetherRollOver gas", g0 - gasleft());
        g0 = gasleft();
        tok.zetherRollOver(alice.ua);
        console2.log(bls ? "bls12-381" : "bn254", "zetherRollOver no-op gas", g0 - gasleft());
    }

    /// CTR-ZTH-35: the caller's public units, exactly `amount · shieldScale`; shield to anyone registered; the cap.
    function test_shieldBurnsTheCallersPublicUnits() public {
        _public(tok, address(this), 30 * SCALE + 1);
        vm.expectEmit(true, false, false, true, address(tok));
        emit IZetherToken.ZetherShielded(bob.ua, 30);
        tok.zetherShield(bob.y, 30); // to someone else's account
        assertEq(tok.balanceOf(address(this)), 1, "30 x scale burnt, the rest kept");
        assertEq(tok.totalShielded(), 30);
        assertEq(tok.totalSupply(), 1);
        assertTrue(_holds(tok, bob, 30, false));
        assertEq(tok.accountState(bob.ua).pendingSeq, 1);
        bytes memory err = abi.encodeWithSignature("ERC20InsufficientBalance(address,uint256,uint256)", address(this), 1, SCALE);
        vm.expectRevert(err);
        tok.zetherShield(bob.y, 1);
        // the cap counts every account: room = max − totalShielded
        ZetherLayer small = _newToken(false, "small", 100);
        _public(small, address(this), 101 * SCALE);
        small.zetherShield(alice.y, 60);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, 41, 40));
        small.zetherShield(bob.y, 41);
        small.zetherShield(bob.y, 40);
        assertEq(small.totalShielded(), 100);
    }

    // ------------------------------------------------------------------ the statement (zether.md §7)

    /// The token's statement carries the 15-word header with `chainUid` at word 3 (CTR-ZTH-36), the token, the
    /// binding tag, the salt at word 13 (CTR-ZTH-30) and `memoHash` at word 14 (0 off commit-reveal and on an unshield,
    /// CTR-ZTH-50); the view and the token build the very same bytes (a proof of the view's statement passes); a salt
    /// changed after proving is refused.
    function test_statementHeaderCarriesChainUid() public {
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, carol.ua, 0);
        bytes memory st = stm.transferStatementSingle(address(tok), t.payload, carol.ua, 0);
        bytes memory head = new bytes(480);
        for (uint256 i; i < 480; ++i) head[i] = st[i];
        bytes memory expected = bytes.concat(
            abi.encode(keccak256("SCAAS-ZETHER-OP-TRANSFER-V1"), ver.proofSystemId(), block.chainid, ZUID, address(tok),
                keccak256("ZTX_V1_DIRECT"), bytes32(0)),
            abi.encode(uint256(0), uint256(1), FEE, carol.ua, uint256(0), address(0), uint256(uint128(salt)), bytes32(0))
        );
        assertEq(head, expected);
        assertEq(tok.chainUid(), ZUID);
        // unshield: amount and recipient at words 11 and 12
        (bytes memory pl,) = _proveUnshield(tok, alice, 7, 500, address(0xD00D), _none(), 0);
        st = stm.unshieldStatement(address(tok), pl, 7, address(0xD00D), _none(), 0);
        (uint256 amount, address rcp) = abi.decode(_cut(st, 352, 64), (uint256, address));
        assertEq(amount, 7);
        assertEq(rcp, address(0xD00D));
        assertEq(bytes32(_cut(st, 0, 32)), keccak256("SCAAS-ZETHER-OP-BURN-V1"));
        assertEq(bytes32(_cut(st, 96, 32)), ZUID);
        assertEq(_cut(st, 416, 64), new bytes(64), "no salt, no memo on an unshield");
        bytes memory tampered = bytes.concat(t.payload);
        tampered[70] ^= 0x01; // the salt
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.zetherTransferSingle(tampered, t.proof, "", carol.ua);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadPayload.selector, t.payload.length - 1));
        tok.zetherTransferSingle(_cut(t.payload, 0, t.payload.length - 1), t.proof, "", carol.ua);
        bytes32 ref = _ref(tok, alice, 0);
        vm.expectEmit(true, true, true, true, address(tok));
        emit IZetherToken.ZetherTransfer(alice.ua, bob.ua, carol.ua, FEE, 0, ref);
        _direct(tok, t, carol.ua);
    }

    // ------------------------------------------------------------------ roll-over, two modes

    function test_rollOverIsNoOpWithoutNewCredit() public {
        _fund(tok, alice, 10);
        tok.zetherRollOver(alice.ua);
        tok.zetherRollOver(alice.ua); // no revert, no bump
        assertEq(tok.accountState(alice.ua).accSeq, 1);
        ZetherTypes.UA[] memory batch = new ZetherTypes.UA[](2);
        (batch[0], batch[1]) = (alice.ua, bob.ua);
        tok.zetherRollOverBatch(batch);
        assertEq(tok.accountState(alice.ua).accSeq, 1);
    }

    function _modeSig(User memory u, ZetherTypes.RollOverMode mode, uint64 nonce, uint64 until)
        internal view returns (bytes memory)
    {
        bytes32 d = keccak256(bytes.concat(
            abi.encode(keccak256("ZETHER_SET_ROLLOVER_MODE_V1"), block.chainid, ZUID, address(tok)),
            abi.encode(u.ua, uint8(mode), nonce, until)
        ));
        return abi.encode(u.y, ZetherKeys.schnorr(u.x, d, bls));
    }

    function _rollSig(User memory u, uint64 accSeq, uint64 pendSeq, uint64 until) internal view returns (bytes memory) {
        bytes32 d = keccak256(bytes.concat(
            abi.encode(keccak256("ZETHER_ROLLOVER_V1"), block.chainid, ZUID, address(tok)),
            abi.encode(u.ua, accSeq, pendSeq, until)
        ));
        return abi.encode(u.y, ZetherKeys.schnorr(u.x, d, bls));
    }

    /// CTR-ZTH-36: a mode or roll-over signature over the digest without `chainUid` (a captured signature from a
    /// re-created chain, whose counters restarted) is refused.
    function test_rollOverAndModeDigestsCarryChainUid() public {
        uint64 until = uint64(block.number + 50);
        bytes32 noUid = keccak256(bytes.concat(
            abi.encode(keccak256("ZETHER_SET_ROLLOVER_MODE_V1"), block.chainid, address(tok)),
            abi.encode(alice.ua, uint8(ZetherTypes.RollOverMode.OWNER_ONLY), uint64(0), until)
        ));
        bytes memory bad = abi.encode(alice.y, ZetherKeys.schnorr(alice.x, noUid, bls));
        vm.expectRevert();
        tok.zetherSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, bad);
        _fund(tok, alice, 10);
        bytes32 rollNoUid = keccak256(bytes.concat(
            abi.encode(keccak256("ZETHER_ROLLOVER_V1"), block.chainid, address(tok)),
            abi.encode(alice.ua, uint64(0), uint64(1), until)
        ));
        bad = abi.encode(alice.y, ZetherKeys.schnorr(alice.x, rollNoUid, bls));
        vm.expectRevert();
        tok.zetherRollOverSigned(alice.ua, 1, until, bad);
        tok.zetherRollOverSigned(alice.ua, 1, until, _rollSig(alice, 0, 1, until));
        assertEq(tok.accountState(alice.ua).accSeq, 1);
    }

    /// A griefer with balance 0 slips a `v = 0` transfer before `zetherRollOverSigned`: `pendingSeq` moves on but the
    /// owner's roll-over still runs (merging the new credit too); the signature cannot replay (`accSeq` moved).
    function test_rollOverSignedSurvivesFrontRunCredit() public {
        uint64 until = uint64(block.number + 50);
        tok.zetherSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until,
            _modeSig(alice, ZetherTypes.RollOverMode.OWNER_ONLY, 0, until));
        _fund(tok, alice, 10);
        bytes memory rs = _rollSig(alice, 0, 1, until);
        _direct(tok, _proveTransfer(tok, bob, alice, 0, 0, _none(), 0), _none());
        assertEq(tok.accountState(alice.ua).pendingSeq, 2);
        tok.zetherRollOverSigned(alice.ua, 1, until, rs);
        (uint256 a,) = _bal(alice);
        assertEq(a, 10);
        _fund(tok, alice, 5);
        // the replay stops at the new-credit gate (1 ≤ lastRolled = 2), before the signature (accSeq moved too)
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.PendingSeqMismatch.selector, 1, 3));
        tok.zetherRollOverSigned(alice.ua, 1, until, rs);
    }

    /// CTR-ZTH-17: a signature that names no new credit is refused (it would be a reusable no-op ticket).
    function test_rollOverSignedWithoutNewCreditIsRejected() public {
        uint64 until = uint64(block.number + 50);
        tok.zetherSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until,
            _modeSig(alice, ZetherTypes.RollOverMode.OWNER_ONLY, 0, until));
        _fund(tok, alice, 10);
        tok.zetherRollOverSigned(alice.ua, 1, until, _rollSig(alice, 0, 1, until));
        bytes memory stale = _rollSig(alice, 1, 1, until);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.PendingSeqMismatch.selector, 1, 1));
        tok.zetherRollOverSigned(alice.ua, 1, until, stale);
        _fund(tok, alice, 5);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.PendingSeqMismatch.selector, 1, 2));
        tok.zetherRollOverSigned(alice.ua, 1, until, stale);
        assertEq(tok.accountState(alice.ua).accSeq, 1);
    }

    function test_setRollOverModeExpired() public {
        uint64 until = uint64(block.number + 5);
        bytes memory sig = _modeSig(alice, ZetherTypes.RollOverMode.OWNER_ONLY, 0, until);
        vm.roll(until + 1);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.RollOverExpired.selector, until));
        tok.zetherSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, sig);
    }

    function test_ownerOnlyRollOver() public {
        uint64 until = uint64(block.number + 50);
        bytes memory sig = _modeSig(alice, ZetherTypes.RollOverMode.OWNER_ONLY, 0, until);
        vm.expectEmit(true, false, false, true, address(tok));
        emit IZetherToken.RollOverModeChanged(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY);
        tok.zetherSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, sig);
        assertEq(tok.accountState(alice.ua).modeNonce, 1);
        vm.expectRevert(); // the old signature again: modeNonce moved
        tok.zetherSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, sig);
        _fund(tok, alice, 10);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.RollOverOwnerOnly.selector, alice.ua));
        tok.zetherRollOver(alice.ua);
        ZetherTypes.UA[] memory batch = new ZetherTypes.UA[](1);
        batch[0] = alice.ua;
        tok.zetherRollOverBatch(batch); // skipped, no revert
        assertEq(tok.accountState(alice.ua).accSeq, 0);

        bytes memory rs = _rollSig(alice, 0, 1, until);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.PendingSeqMismatch.selector, 2, 1));
        tok.zetherRollOverSigned(alice.ua, 2, until, rs);
        uint256 g0 = gasleft();
        tok.zetherRollOverSigned(alice.ua, 1, until, rs);
        console2.log(bls ? "bls12-381" : "bn254", "zetherRollOverSigned (Schnorr) gas", g0 - gasleft());
        assertEq(tok.accountState(alice.ua).accSeq, 1);
        (uint256 a,) = _bal(alice);
        assertEq(a, 10);

        // an expired roll-over signature: "hold the blob" blocked by validUntilBlock
        _fund(tok, alice, 5);
        bytes memory late = _rollSig(alice, 1, 2, until);
        vm.roll(until + 1);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.RollOverExpired.selector, until));
        tok.zetherRollOverSigned(alice.ua, 2, until, late);
    }

    function test_rollOverSignedRejectsForeignSignature() public {
        uint64 until = uint64(block.number + 50);
        _fund(tok, alice, 10);
        bytes memory forged = _rollSig(bob, 0, 1, until); // bob signs for alice
        vm.expectRevert();
        tok.zetherRollOverSigned(alice.ua, 1, until, forged);
    }

    // ------------------------------------------------------------------ acc/pending race

    /// A credit that arrives between proving and submitting changes only pending: the proof stays valid.
    function test_incomingCreditDoesNotKillInFlightProof() public {
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        _fund(tok, alice, 7); // someone sends alice dust
        _direct(tok, t, _none());
        (uint256 a, uint256 p) = _bal(alice);
        assertEq(a, 400);
        assertEq(p, 7);
    }

    /// A roll-over in between moves `accSeq`: the old proof is refused cheaply, before verification.
    function test_rollOverBetweenProveAndSubmitRejectsCheaply() public {
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        _fund(tok, alice, 7);
        tok.zetherRollOver(alice.ua);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.StaleAccSeq.selector, 2, 1));
        _direct(tok, t, _none());
    }

    // ------------------------------------------------------------------ replay

    function test_replaySameProofRejected() public {
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        _direct(tok, t, _none());
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.StaleSendCounter.selector, 1, 0));
        _direct(tok, t, _none());
    }

    /// Same verifier, registry, accSeq/sendCounter on another token: the header (token) differs ⇒ refused.
    function test_replayAcrossTokensRejected() public {
        ZetherLayer other = _newToken(true, "zusd-2");
        _fund(tok, alice, 500);
        _fund(other, alice, 500);
        tok.zetherRollOver(alice.ua);
        other.zetherRollOver(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        _direct(other, t, _none());
        _direct(tok, t, _none()); // on the right token it passes
    }

    function test_replayAcrossChainsRejected() public {
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        vm.chainId(1337); // another dev chain, same state
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        _direct(tok, t, _none());
    }

    // ------------------------------------------------------------------ disclosure (ITransferDisclosure)

    /// @dev Chaum-Pedersen opening of leg 0: RECEIVER_X/AUDITOR on base `D_out`, SENDER_CP on `Y_t` (key `s`).
    function _cpOpening(uint256 x, bytes32 ref, uint256 amount, ITransferDisclosure.OpeningKind kind)
        internal view returns (bytes memory)
    {
        (bytes memory ct, bytes memory yt) = dis.transferCiphertext(address(tok), ref, 0, "");
        bytes memory base = kind == ITransferDisclosure.OpeningKind.SENDER_CP ? yt : _cut(ct, ver.g1EncodedBytes(), ver.g1EncodedBytes());
        return _cpOpening(tok, x, ref, 0, amount, kind, base);
    }

    function _cut(bytes memory a, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) out[i] = a[off + i];
    }

    function test_disclosureFourOpenings() public {
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 123, 500, _none(), 0);
        bytes32 ref = _direct(tok, t, _none());
        // the sender opens with s
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s)));
        assertFalse(_vta(ref, 124, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s)));
        // the recipient opens with x_to, without the sender
        bytes memory rx = _cpOpening(bob.x, ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X);
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X, rx));
        assertFalse(_vta(ref, 122, ITransferDisclosure.OpeningKind.RECEIVER_X, rx));
        bytes memory wrong = _cpOpening(alice.x, ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X);
        assertFalse(_vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X, wrong));
        // the auditor opens C_aud
        bytes memory au = _cpOpening(X_AUD, ref, 123, ITransferDisclosure.OpeningKind.AUDITOR);
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.AUDITOR, au));
        // the sender opens the leg by Chaum-Pedersen on `s`, without handing `s` over (CTR-ZTH-40)
        bytes memory cp = _cpOpening(t.s, ref, 123, ITransferDisclosure.OpeningKind.SENDER_CP);
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.SENDER_CP, cp));
        assertFalse(_vta(ref, 124, ITransferDisclosure.OpeningKind.SENDER_CP, cp));
        assertFalse(_vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X, cp), "kind is bound");
        // aliases mod r and values past n_v are refused
        assertFalse(_vta(ref, 123 + ver.groupOrder(), ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s)));
        assertFalse(_vta(ref, 1 << 64, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s)));
        // malformed openings: s not 32 bytes, A1 of the wrong length, z ≥ r
        vm.expectRevert(ITransferDisclosure.OpeningMalformed.selector);
        _vta(ref, 123, ITransferDisclosure.OpeningKind.SENDER_S, new bytes(31));
        (bytes memory a1, bytes memory a2, uint256 z) = abi.decode(rx, (bytes, bytes, uint256));
        vm.expectRevert(ITransferDisclosure.OpeningMalformed.selector);
        _vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X, abi.encode(new bytes(1), a2, z));
        bytes memory zBig = abi.encode(a1, a2, ver.groupOrder());
        vm.expectRevert(ITransferDisclosure.OpeningMalformed.selector);
        _vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X, zBig);
        (bytes memory ct, bytes memory yTo) = dis.transferCiphertext(address(tok), ref, 0, "");
        assertEq(yTo, bob.y);
        assertEq(ct.length, 3 * ver.g1EncodedBytes());
        assertEq(address(tok.disclosure()), address(dis), "canonical disclosure from the token");
    }

    /// CTR-ZTH-36: the disclosure challenge carries `chainUid`; an opening made without it fails.
    function test_disclosureChallengeCarriesChainUid() public {
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 123, 500, _none(), 0);
        bytes32 ref = _direct(tok, t, _none());
        (bytes memory ct,) = dis.transferCiphertext(address(tok), ref, 0, "");
        bytes memory dOut = _cut(ct, ver.g1EncodedBytes(), ver.g1EncodedBytes());
        uint256 r = ver.groupOrder();
        uint256 k = 0x5151;
        bytes memory a1 = ver.g1MulBase(k);
        bytes memory a2 = ver.g1Mul(dOut, k);
        uint256 e = uint256(keccak256(bytes.concat(
            abi.encodePacked("SCAAS-ZETHER-DISCLOSE-V1", block.chainid, address(tok)),
            abi.encodePacked(ref, uint256(0), uint256(123), uint8(1), a1, a2)
        )));
        e = _h2s(e, r);
        bytes memory noUid = abi.encode(a1, a2, addmod(k, mulmod(e, bob.x, r), r));
        assertFalse(_vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X, noUid));
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X,
            _cpOpening(bob.x, ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X)));
    }

    function _h2s(uint256 seed, uint256 r) internal pure returns (uint256) {
        uint256 hi = uint256(keccak256(abi.encodePacked(bytes32(seed), uint8(2))));
        uint256 lo = uint256(keccak256(abi.encodePacked(bytes32(seed), uint8(3))));
        return addmod(mulmod(hi, (type(uint256).max % r) + 1, r), lo, r);
    }

    /// CTR-ZTH-42, single format: the token has an auditor, the sender leaves it out (`C_aud = O`, statement `Y_a = O`).
    function test_singleAuditorOptOut() public {
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        audOut = true;
        Tx memory t = _proveTransfer(tok, alice, bob, 123, 500, _none(), 0);
        audOut = false;
        Tx memory on = _proveTransfer(tok, alice, bob, 123, 500, _none(), 0);
        // a proof of one choice does not pass under the other (Y_a is in the statement)
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.zetherTransferSingle(t.payload, on.proof, "", _none());
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.zetherTransferSingle(on.payload, t.proof, "", _none());
        bytes32 ref = _direct(tok, t, _none());
        assertTrue(_holds(tok, bob, 123, false));
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(t.s)));
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X,
            _cpOpening(bob.x, ref, 123, ITransferDisclosure.OpeningKind.RECEIVER_X)));
        assertTrue(_vta(ref, 123, ITransferDisclosure.OpeningKind.SENDER_CP,
            _cpOpening(t.s, ref, 123, ITransferDisclosure.OpeningKind.SENDER_CP)));
        assertFalse(_vta(ref, 123, ITransferDisclosure.OpeningKind.AUDITOR,
            _cpOpening(X_AUD, ref, 123, ITransferDisclosure.OpeningKind.AUDITOR)), "auditor reads nothing");
        assertFalse(_vta(ref, 0, ITransferDisclosure.OpeningKind.AUDITOR,
            _cpOpening(X_AUD, ref, 0, ITransferDisclosure.OpeningKind.AUDITOR)));
    }

    /// n_v = 64: a transfer > 2^32 units, a balance > 2^44 held, spent (the whole balance in one transfer) and
    /// unshielded; a disclosure of an amount > 2^32 with every opening. Balances checked by `_holds`.
    function test_largeValuesNv64() public {
        tok = _newToken(true, "big", uint256(1) << 54);
        uint256 b0 = (uint256(1) << 44) + 12_345;
        _fund(tok, alice, b0);
        tok.zetherRollOver(alice.ua);
        assertTrue(_holds(tok, alice, b0, true), "acc holds > 2^44");
        uint256 v = (uint256(1) << 33) + 7;
        Tx memory t = _proveTransfer(tok, alice, bob, v, b0, carol.ua, 0);
        uint256 g0 = gasleft();
        bytes32 ref = _direct(tok, t, carol.ua);
        console2.log(bls ? "bls12-381" : "bn254", "zetherTransferSingle v > 2^32 (direct, auditor, fee) gas", g0 - gasleft());
        uint256 b1 = b0 - v - FEE;
        assertTrue(_holds(tok, alice, b1, true), "sender acc = b - v - fee");
        assertTrue(_holds(tok, bob, v, false), "receiver pending = v");
        assertTrue(_holds(tok, carol, FEE, false), "beneficiary pending = fee");
        _discloseLarge(ref, v, t.s);
        _spendAllAndUnshield(b1, v);
    }

    function _discloseLarge(bytes32 ref, uint256 v, uint256 s) internal view {
        assertTrue(_vta(ref, v, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(s)));
        bytes memory rx = _cpOpening(bob.x, ref, v, ITransferDisclosure.OpeningKind.RECEIVER_X);
        assertTrue(_vta(ref, v, ITransferDisclosure.OpeningKind.RECEIVER_X, rx));
        assertTrue(_vta(ref, v, ITransferDisclosure.OpeningKind.AUDITOR,
            _cpOpening(X_AUD, ref, v, ITransferDisclosure.OpeningKind.AUDITOR)));
        assertTrue(_vta(ref, v, ITransferDisclosure.OpeningKind.SENDER_CP,
            _cpOpening(s, ref, v, ITransferDisclosure.OpeningKind.SENDER_CP)));
        assertFalse(_vta(ref, v - (uint256(1) << 32), ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(s)));
        assertFalse(_vta(ref, uint256(1) << 64, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(s)));
    }

    function _spendAllAndUnshield(uint256 b1, uint256 v) internal {
        _direct(tok, _proveTransfer(tok, alice, bob, b1, b1, _none(), 0), _none());
        assertTrue(_holds(tok, alice, 0, true), "sender emptied");
        tok.zetherRollOver(bob.ua);
        uint256 bb = v + b1;
        assertTrue(_holds(tok, bob, bb, true), "receiver acc = v + b1");
        (bytes memory pl, bytes memory pr) = _proveUnshield(tok, bob, bb, bb, address(0xD00D), _none(), 0);
        tok.zetherUnshield(pl, pr, "", _none(), address(0xD00D), bb);
        assertEq(tok.balanceOf(address(0xD00D)), bb * SCALE);
        assertEq(tok.totalShielded(), FEE, "only carol's fee left shielded");
    }

    /// The auditor decrypts the disclosed transfer, nobody's balance.
    function test_auditorSeesTransferButNoBalance() public {
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        bytes32 ref = _direct(tok, _proveTransfer(tok, alice, bob, 321, 500, _none(), 0), _none());
        (bytes memory ct,) = dis.transferCiphertext(address(tok), ref, 0, "");
        uint256 p = ver.g1EncodedBytes();
        assertEq(_decrypt(_cut(ct, 2 * p, p), _cut(ct, p, p), X_AUD, 400), 321, "auditor reads C_aud");
        IZetherToken.AccountState memory s = tok.accountState(alice.ua);
        vm.expectRevert(bytes("decrypt: out of range"));
        this.decryptExt(s.accC, s.accD, X_AUD, 1100); // alice's 179: the auditor cannot read it
        assertEq(_decrypt(s.accC, s.accD, alice.x, 1100), 179);
    }

    function decryptExt(bytes memory c, bytes memory d, uint256 x, uint256 max) external view returns (uint256) {
        return _decrypt(c, d, x, max);
    }
}

contract ZetherNoneBn254Test is ZetherNoneSuite {
    function _curve() internal pure override returns (bool) { return false; }
}

contract ZetherNoneBls12381Test is ZetherNoneSuite {
    function _curve() internal pure override returns (bool) { return true; }
}
