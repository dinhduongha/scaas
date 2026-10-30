// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {IConfidentialToken} from "../../src/confidential/IConfidentialToken.sol";
import {ZetherFixture, ZUID} from "./helpers/ZetherFixture.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ITransferDisclosure} from "../../src/zether/ITransferDisclosure.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {ZetherKeys} from "./helpers/ZetherKeys.sol";
import {ZetherTranscript} from "../../src/zether/ZetherTranscript.sol";
import {SigCheck} from "../../src/common/SigCheck.sol";

/// @notice The whole life of a `NORMAL_ZETHER` token (a factory clone, the real verifier, real proofs from the test
///         prover), on BLS12-381 (the only classical Zether curve since UA-6): shield from the public balance, transfer,
///         roll-over, unshield into public units; replay protection; `chainUid` in every digest (CTR-ZTH-36);
///         disclosure.
abstract contract ZetherNormalSuite is ZetherFixture {

    function setUp() public {
        _deploy(true);
    }

    function _bal(User memory u) internal view returns (uint256 a, uint256 p) {
        return _balances(tok, u, 1100);
    }

    function _vta(bytes32 ref, uint256 amount, ITransferDisclosure.OpeningKind kind, bytes memory opening)
        internal view returns (bool)
    {
        return _vta(tok, ref, 0, amount, kind, opening);
    }

    // ------------------------------------------------------------------ life cycle and conservation

    function test_lifecycleShieldTransferRollOverUnshield() public {
        _fund(tok, alice, 1000);
        _assertConservation(tok, 1100);
        (uint256 a, uint256 p) = _bal(alice);
        assertEq(a, 0);
        assertEq(p, 1000, "shield lands in pending");
        assertEq(tok.balanceOf(address(this)), 0, "the public units were burnt");

        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        (a, p) = _bal(alice);
        assertEq(a, 1000);
        assertEq(p, 0);
        assertEq(tok.accountState(alice.ua).accSeq, 1);

        // alice → bob 300, inner fee FEE to carol (a public scalar)
        Tx memory t1 = _proveTransfer(tok, alice, bob, 300, 1000, carol.ua, 0);
        uint256 g0 = gasleft();
        bytes32 ref = _direct(tok, t1, carol.ua);
        console2.log(bls ? "bls12-381" : "bn254", "mtxConfidentialTransferSingle (direct, auditor, fee) gas", g0 - gasleft());
        (a,) = _bal(alice);
        assertEq(a, 1000 - 300 - FEE, "sender acc debited v + fee");
        (, p) = _bal(bob);
        assertEq(p, 300, "receiver pending credited");
        assertEq(tok.balanceOfUA(ZetherTypes.UA.unwrap(carol.ua)), FEE * SCALE, "beneficiary: fee x scale public units from the pool");
        assertEq(tok.accountState(carol.ua).pendingSeq, 0, "no pend_ben credit (D19)");
        assertEq(tok.sendCounter(alice.ua), 1);
        assertEq(ref, _ref(tok, alice, 0), "entryRef carries chainUid");
        _assertConservation(tok, 1100);

        // bob spends what he received: roll-over (PUBLIC, no signature), then 100 back
        tok.mtxRollOver(ZetherTypes.UA.unwrap(bob.ua), 1);
        _direct(tok, _proveTransfer(tok, bob, alice, 100, 300, _none(), 0), _none());
        _assertConservation(tok, 1100);

        // bob unshields 50 into public units
        (bytes memory pl, bytes memory pr) = _proveUnshield(tok, bob, 50, 200, address(0xD00D), _none(), 0);
        g0 = gasleft();
        tok.mtxUnshield(pl, pr, "", bytes32(0), "", 50, bytes32(uint256(uint160(address(0xD00D)))));
        console2.log(bls ? "bls12-381" : "bn254", "mtxUnshield gas", g0 - gasleft());
        assertEq(tok.balanceOf(address(0xD00D)), 50 * SCALE);
        (a,) = _bal(bob);
        assertEq(a, 150);

        // alice rolls the 100 over, then unshields 700 with a fee to carol
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        (pl, pr) = _proveUnshield(tok, alice, 700, 798, address(0xD00D), carol.ua, 0);
        tok.mtxUnshield(pl, pr, "", ZetherTypes.UA.unwrap(carol.ua), "", 700, bytes32(uint256(uint160(address(0xD00D)))));
        (a,) = _bal(alice);
        assertEq(a, 798 - 700 - FEE);
        assertEq(tok.balanceOfUA(ZetherTypes.UA.unwrap(carol.ua)), 2 * FEE * SCALE, "both fees, public units");
        assertEq(tok.totalShielded(), 1000 - 750 - 2 * FEE, "the fees left the shielded set (D19)");
        assertEq(tok.balanceOf(address(0xD00D)), 750 * SCALE);
        _assertConservation(tok, 1100);
    }

    function test_shieldAndRollOverGas() public {
        _public(tok, address(this), 1000 * SCALE);
        uint256 g0 = gasleft();
        tok.mtxShield(ZetherTypes.UA.unwrap(alice.ua), 500);
        console2.log(bls ? "bls12-381" : "bn254", "mtxShield (first credit) gas", g0 - gasleft());
        g0 = gasleft();
        tok.mtxShield(ZetherTypes.UA.unwrap(alice.ua), 500);
        console2.log(bls ? "bls12-381" : "bn254", "mtxShield (warm) gas", g0 - gasleft());
        g0 = gasleft();
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        console2.log(bls ? "bls12-381" : "bn254", "mtxRollOver gas", g0 - gasleft());
        g0 = gasleft();
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        console2.log(bls ? "bls12-381" : "bn254", "mtxRollOver no-op gas", g0 - gasleft());
    }

    /// CTR-ZTH-35: the caller's public units, exactly `amount · shieldScale`; shield to anyone registered; the cap.
    /// D19 (CTR-ZTH-51): `SHIELD_POOL` is neither a payee nor a spender; no external path reaches it.
    function test_shieldPool_neitherPayeeNorSpender() public {
        _fund(tok, alice, 5); // the pool now holds 5 x scale
        _public(tok, address(this), 3 * SCALE);
        bytes memory err = abi.encodeWithSignature("ShieldPoolNotPayable()");
        vm.expectRevert(err);
        tok.transfer(SHIELD_POOL_, 1);
        vm.expectRevert(err); // an unshield payee
        tok.mtxUnshield("", "", "", bytes32(0), "", 1, bytes32(uint256(uint160(SHIELD_POOL_))));
        vm.prank(SHIELD_POOL_);
        vm.expectRevert(err); // a spender
        tok.transfer(address(this), 1);
        assertEq(tok.balanceOf(SHIELD_POOL_), 5 * SCALE, "untouched");
    }

    /// Owner ruling 2026-10-30 (D2): a holder with an EIP-7702 designator (a sweeper's code calling as it) cannot shield
    /// its public units away.
    function test_shield_delegatedCallerRefused() public {
        address v = address(0xD7702);
        _public(tok, v, 30 * SCALE);
        vm.etch(v, abi.encodePacked(hex"ef0100", address(this)));
        vm.prank(v);
        vm.expectRevert(abi.encodeWithSelector(SigCheck.CallerDelegated.selector, v));
        tok.mtxShield(ZetherTypes.UA.unwrap(bob.ua), 30);
        assertEq(tok.balanceOf(v), 30 * SCALE);
    }

    function test_shieldMovesTheCallersPublicUnitsToThePool() public {
        _public(tok, address(this), 30 * SCALE + 1);
        uint64 seq = tok.accountState(bob.ua).pendingSeq + 1;
        vm.expectEmit(true, true, false, true, address(tok));
        emit IConfidentialToken.Shielded(ZetherTypes.UA.unwrap(bob.ua), address(this), 30, seq);
        tok.mtxShield(ZetherTypes.UA.unwrap(bob.ua), 30); // to someone else's account
        assertEq(tok.balanceOf(address(this)), 1, "30 x scale moved, the rest kept");
        assertEq(tok.totalShielded(), 30);
        assertEq(tok.totalSupply(), 30 * SCALE + 1, "D19: nothing burnt");
        assertEq(tok.balanceOf(SHIELD_POOL_), 30 * SCALE);
        assertTrue(_holds(tok, bob, 30, false));
        assertEq(tok.accountState(bob.ua).pendingSeq, 1);
        bytes memory err = abi.encodeWithSignature("ERC20InsufficientBalance(address,uint256,uint256)", address(this), 1, SCALE);
        vm.expectRevert(err);
        tok.mtxShield(ZetherTypes.UA.unwrap(bob.ua), 1);
        // the cap counts every account: room = max − totalShielded
        ZetherLayer small = _newToken(false, "small", 100);
        _public(small, address(this), 101 * SCALE);
        small.mtxShield(ZetherTypes.UA.unwrap(alice.ua), 60);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, 41, 40));
        small.mtxShield(ZetherTypes.UA.unwrap(bob.ua), 41);
        small.mtxShield(ZetherTypes.UA.unwrap(bob.ua), 40);
        assertEq(small.totalShielded(), 100);
    }

    // ------------------------------------------------------------------ the statement (zether.md §7)

    /// The token's statement carries the 15-word header with `chainUid` at word 3 (CTR-ZTH-36), the token, the
    /// binding tag, the salt at word 13 (CTR-ZTH-30) and `memoHash` at word 14 (0 off commit-reveal and on an unshield,
    /// CTR-ZTH-50); the view and the token build the very same bytes (a proof of the view's statement passes); a salt
    /// changed after proving is refused.
    function test_statementHeaderCarriesChainUid() public {
        _fund(tok, alice, 500);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, carol.ua, 0);
        bytes memory st = stm.transferStatementSingle(address(tok), t.payload, carol.ua, 0);
        bytes memory head = new bytes(512);
        for (uint256 i; i < 512; ++i) head[i] = st[i];
        bytes memory expected = bytes.concat(
            abi.encode(keccak256("SCAAS-ZETHER-OP-TRANSFER-V1"), ver.proofSystemId(), block.chainid, ZUID, address(tok),
                keccak256("ZTX_V1_DIRECT"), bytes32(0)),
            abi.encode(uint256(0), uint256(1), FEE, carol.ua, uint256(0), address(0), uint256(uint128(salt)), bytes32(0)),
            abi.encode(vub) // word 15: validUntilBlock (review C0-9)
        );
        assertEq(head, expected);
        assertEq(tok.chainUid(), ZUID);
        // unshield: amount and recipient at words 11 and 12
        (bytes memory pl,) = _proveUnshield(tok, alice, 7, 500, address(0xD00D), _none(), 0);
        st = stm.unshieldStatement(address(tok), pl, 7, bytes32(uint256(uint160(address(0xD00D)))), _none(), 0);
        (uint256 amount, address rcp) = abi.decode(_cut(st, 352, 64), (uint256, address));
        assertEq(amount, 7);
        assertEq(rcp, address(0xD00D));
        assertEq(bytes32(_cut(st, 0, 32)), keccak256("SCAAS-ZETHER-OP-BURN-V1"));
        assertEq(bytes32(_cut(st, 96, 32)), ZUID);
        assertEq(_cut(st, 416, 64), new bytes(64), "no salt, no memo on an unshield");
        bytes memory tampered = bytes.concat(t.payload);
        tampered[102] ^= 0x01; // the salt
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.mtxConfidentialTransferSingle(tampered, t.proof, "", ZetherTypes.UA.unwrap(carol.ua), "");
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadPayload.selector, t.payload.length - 1));
        tok.mtxConfidentialTransferSingle(_cut(t.payload, 0, t.payload.length - 1), t.proof, "", ZetherTypes.UA.unwrap(carol.ua), "");
        bytes32 ref = _ref(tok, alice, 0);
        vm.expectEmit(true, true, true, true, address(tok));
        emit IConfidentialToken.ConfidentialTransfer(ref, ZetherTypes.UA.unwrap(alice.ua), ZetherTypes.UA.unwrap(bob.ua),
            ZetherTypes.UA.unwrap(carol.ua), FEE, 0, address(0));
        _direct(tok, t, carol.ua);
    }

    // ------------------------------------------------------------------ roll-over, two modes

    function test_rollOverIsNoOpWithoutNewCredit() public {
        _fund(tok, alice, 10);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1); // no revert, no bump
        assertEq(tok.accountState(alice.ua).accSeq, 1);
        ZetherTypes.UA[] memory batch = new ZetherTypes.UA[](2);
        (batch[0], batch[1]) = (alice.ua, bob.ua);
        tok.mtxRollOverBatch(batch);
        assertEq(tok.accountState(alice.ua).accSeq, 1);
    }

    function _modeSig(User memory u, ZetherTypes.RollOverMode mode, uint64 nonce, uint64 until)
        internal view returns (bytes memory)
    {
        bytes32 d = keccak256(bytes.concat(
            abi.encode(keccak256("ZETHER_SET_ROLLOVER_MODE_V1"), block.chainid, ZUID, address(tok)),
            abi.encode(u.ua, uint8(mode), nonce, until)
        ));
        return _ownerAuth(u, d);
    }

    function _rollSig(User memory u, uint64 accSeq, uint64 pendSeq, uint64 until) internal view returns (bytes memory) {
        bytes32 d = keccak256(bytes.concat(
            abi.encode(keccak256("ZETHER_ROLLOVER_V1"), block.chainid, ZUID, address(tok)),
            abi.encode(u.ua, accSeq, pendSeq, until)
        ));
        return _ownerAuth(u, d);
    }

    /// CTR-ZTH-36: a mode or roll-over signature over the digest without `chainUid` (a captured signature from a
    /// re-created chain, whose counters restarted) is refused.
    function test_rollOverAndModeDigestsCarryChainUid() public {
        uint64 until = uint64(block.number + 50);
        bytes32 noUid = keccak256(bytes.concat(
            abi.encode(keccak256("ZETHER_SET_ROLLOVER_MODE_V1"), block.chainid, address(tok)),
            abi.encode(alice.ua, uint8(ZetherTypes.RollOverMode.OWNER_ONLY), uint64(0), until)
        ));
        bytes memory bad = _ownerAuth(alice, noUid);
        vm.expectRevert();
        tok.mtxSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, bad);
        _fund(tok, alice, 10);
        bytes32 rollNoUid = keccak256(bytes.concat(
            abi.encode(keccak256("ZETHER_ROLLOVER_V1"), block.chainid, address(tok)),
            abi.encode(alice.ua, uint64(0), uint64(1), until)
        ));
        bad = _ownerAuth(alice, rollNoUid);
        vm.expectRevert();
        tok.mtxRollOverSigned(alice.ua, 1, until, bad);
        tok.mtxRollOverSigned(alice.ua, 1, until, _rollSig(alice, 0, 1, until));
        assertEq(tok.accountState(alice.ua).accSeq, 1);
    }

    /// A griefer with balance 0 slips a `v = 0` transfer before `mtxRollOverSigned`: `pendingSeq` moves on but the
    /// owner's roll-over still runs (merging the new credit too); the signature cannot replay (`accSeq` moved).
    function test_rollOverSignedSurvivesFrontRunCredit() public {
        uint64 until = uint64(block.number + 50);
        tok.mtxSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until,
            _modeSig(alice, ZetherTypes.RollOverMode.OWNER_ONLY, 0, until));
        _fund(tok, alice, 10);
        bytes memory rs = _rollSig(alice, 0, 1, until);
        _direct(tok, _proveTransfer(tok, bob, alice, 0, 0, _none(), 0), _none());
        assertEq(tok.accountState(alice.ua).pendingSeq, 2);
        tok.mtxRollOverSigned(alice.ua, 1, until, rs);
        (uint256 a,) = _bal(alice);
        assertEq(a, 10);
        _fund(tok, alice, 5);
        // the replay stops at the new-credit gate (1 ≤ lastRolled = 2), before the signature (accSeq moved too)
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.PendingSeqMismatch.selector, 1, 3));
        tok.mtxRollOverSigned(alice.ua, 1, until, rs);
    }

    /// CTR-ZTH-17: a signature that names no new credit is refused (it would be a reusable no-op ticket).
    function test_rollOverSignedWithoutNewCreditIsRejected() public {
        uint64 until = uint64(block.number + 50);
        tok.mtxSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until,
            _modeSig(alice, ZetherTypes.RollOverMode.OWNER_ONLY, 0, until));
        _fund(tok, alice, 10);
        tok.mtxRollOverSigned(alice.ua, 1, until, _rollSig(alice, 0, 1, until));
        bytes memory stale = _rollSig(alice, 1, 1, until);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.PendingSeqMismatch.selector, 1, 1));
        tok.mtxRollOverSigned(alice.ua, 1, until, stale);
        _fund(tok, alice, 5);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.PendingSeqMismatch.selector, 1, 2));
        tok.mtxRollOverSigned(alice.ua, 1, until, stale);
        assertEq(tok.accountState(alice.ua).accSeq, 1);
    }

    function test_setRollOverModeExpired() public {
        uint64 until = uint64(block.number + 5);
        bytes memory sig = _modeSig(alice, ZetherTypes.RollOverMode.OWNER_ONLY, 0, until);
        vm.roll(until + 1);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.RollOverExpired.selector, until));
        tok.mtxSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, sig);
    }

    function test_ownerOnlyRollOver() public {
        uint64 until = uint64(block.number + 50);
        bytes memory sig = _modeSig(alice, ZetherTypes.RollOverMode.OWNER_ONLY, 0, until);
        vm.expectEmit(true, false, false, true, address(tok));
        emit IZetherToken.RollOverModeChanged(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY);
        tok.mtxSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, sig);
        assertEq(tok.accountState(alice.ua).modeNonce, 1);
        vm.expectRevert(); // the old signature again: modeNonce moved
        tok.mtxSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, sig);
        _fund(tok, alice, 10);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.RollOverOwnerOnly.selector, alice.ua));
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        ZetherTypes.UA[] memory batch = new ZetherTypes.UA[](1);
        batch[0] = alice.ua;
        tok.mtxRollOverBatch(batch); // skipped, no revert
        assertEq(tok.accountState(alice.ua).accSeq, 0);

        bytes memory rs = _rollSig(alice, 0, 1, until);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.PendingSeqMismatch.selector, 2, 1));
        tok.mtxRollOverSigned(alice.ua, 2, until, rs);
        uint256 g0 = gasleft();
        tok.mtxRollOverSigned(alice.ua, 1, until, rs);
        console2.log(bls ? "bls12-381" : "bn254", "mtxRollOverSigned (Schnorr) gas", g0 - gasleft());
        assertEq(tok.accountState(alice.ua).accSeq, 1);
        (uint256 a,) = _bal(alice);
        assertEq(a, 10);

        // an expired roll-over signature: "hold the blob" blocked by validUntilBlock
        _fund(tok, alice, 5);
        bytes memory late = _rollSig(alice, 1, 2, until);
        vm.roll(until + 1);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.RollOverExpired.selector, until));
        tok.mtxRollOverSigned(alice.ua, 2, until, late);
    }

    function test_rollOverSignedRejectsForeignSignature() public {
        uint64 until = uint64(block.number + 50);
        _fund(tok, alice, 10);
        bytes memory forged = _rollSig(bob, 0, 1, until); // bob signs for alice
        vm.expectRevert();
        tok.mtxRollOverSigned(alice.ua, 1, until, forged);
    }

    // ------------------------------------------------------------------ acc/pending race

    /// A credit that arrives between proving and submitting changes only pending: the proof stays valid.
    function test_incomingCreditDoesNotKillInFlightProof() public {
        _fund(tok, alice, 500);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
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
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        _fund(tok, alice, 7);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.StaleAccSeq.selector, 2, 1));
        _direct(tok, t, _none());
    }

    // ------------------------------------------------------------------ replay

    function test_replaySameProofRejected() public {
        _fund(tok, alice, 500);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
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
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        other.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        Tx memory t = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        _direct(other, t, _none());
        _direct(tok, t, _none()); // on the right token it passes
    }

    function test_replayAcrossChainsRejected() public {
        _fund(tok, alice, 500);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
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
        (bytes memory ct, bytes memory yt) = dis.transferCiphertext(address(tok), ref, 0);
        bytes memory base = kind == ITransferDisclosure.OpeningKind.SENDER_CP ? yt : _cut(ct, ver.g1EncodedBytes(), ver.g1EncodedBytes());
        return _cpOpening(tok, x, ref, 0, amount, kind, base);
    }

    function _cut(bytes memory a, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i; i < len; ++i) out[i] = a[off + i];
    }

    function _modInv(uint256 a, uint256 r) internal view returns (uint256 out) {
        (, bytes memory o) = address(5).staticcall(abi.encode(uint256(32), uint256(32), uint256(32), a, r - 2, r));
        out = abi.decode(o, (uint256));
    }

    /// @dev The pre-C0-4 verifier's two equations: `[z]G = A1 + [e]Y_t` and `[z]D = A2 + [e](C − [a]G)`.
    function _oldAccepts(bytes32 ref, uint256 a, uint256 e, bytes memory opening) internal view returns (bool) {
        (bytes memory a1, bytes memory a2, uint256 z) = abi.decode(opening, (bytes, bytes, uint256));
        (bytes memory ct,) = dis.transferCiphertext(address(tok), ref, 0);
        uint256 p = ver.g1EncodedBytes();
        bytes memory cm = ver.g1Sub(_cut(ct, 0, p), ver.g1MulBase(a));
        return keccak256(ver.g1MulBase(z)) == keccak256(ver.g1Add(a1, ver.g1Mul(bob.y, e)))
            && keccak256(ver.g1Mul(_cut(ct, p, p), z)) == keccak256(ver.g1Add(a2, ver.g1Mul(cm, e)));
    }

    /// @dev Review C0-4. The OLD challenge `H(pre ‖ A1 ‖ A2)` carried no statement point and `entryRef` is known before the
    ///      transfer, so a sender with the key holder picks `k1, k2`, computes `e`, then `s = k1⁻¹(k2 + e(v − a))` and sends an
    ///      honest transfer of `v`; `z = k1 + e·x_t` opens the false amount `a`. The new challenge absorbs `G ‖ K ‖ B ‖ M`,
    ///      which depend on `s`, so the forged opening is refused (and the honest one is accepted).
    function test_disclosure_lateS_noFalseOpening() public {
        _fund(tok, alice, 500);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        bytes32 ref = _ref(tok, alice, tok.accountState(alice.ua).sendCounter);
        (uint256 eOld, uint256 s) = _lateS(ref, 100, 5);
        forceS = s;
        assertEq(_direct(tok, _proveTransfer(tok, alice, bob, 100, 500, _none(), 0), _none()), ref, "predicted entryRef");
        bytes memory forged = _forged(eOld);
        assertTrue(_oldAccepts(ref, 5, eOld, forged), "the OLD verifier opens the false amount 5");
        assertFalse(_vta(ref, 5, ITransferDisclosure.OpeningKind.RECEIVER_X, forged), "no false opening");
        assertTrue(_vta(ref, 100, ITransferDisclosure.OpeningKind.RECEIVER_X,
            _cpOpening(bob.x, ref, 100, ITransferDisclosure.OpeningKind.RECEIVER_X)), "honest opening of v");
    }

    uint256 constant K1 = 0x1111;
    uint256 constant K2 = 0x2222;

    /// @dev The old `e` for `A1 = [K1]G, A2 = [K2]G` and amount `a`, and `s = K1⁻¹(K2 + e(v − a))`.
    function _lateS(bytes32 ref, uint256 v, uint256 a) internal view returns (uint256 e, uint256 s) {
        uint256 r = ver.groupOrder();
        e = ZetherTranscript.hashToScalar(keccak256(bytes.concat(
            abi.encodePacked("SCAAS-ZETHER-DISCLOSE-V2", block.chainid, tok.chainUid(), address(tok)),
            abi.encodePacked(ref, uint256(0), a, uint8(ITransferDisclosure.OpeningKind.RECEIVER_X)),
            ver.g1MulBase(K1), ver.g1MulBase(K2)
        )), r);
        s = mulmod(_modInv(K1, r), addmod(K2, mulmod(e, addmod(v, r - a, r), r), r), r);
    }

    function _forged(uint256 e) internal view returns (bytes memory) {
        uint256 r = ver.groupOrder();
        return abi.encode(ver.g1MulBase(K1), ver.g1MulBase(K2), addmod(K1, mulmod(e, bob.x, r), r));
    }

    function test_disclosureFourOpenings() public {
        _fund(tok, alice, 500);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
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
        (bytes memory ct, bytes memory yTo) = dis.transferCiphertext(address(tok), ref, 0);
        assertEq(yTo, bob.y);
        assertEq(ct.length, 4 * ver.g1EncodedBytes(), "C_out D_out C_aud D_aud (= D_out on the single format)");
        assertEq(address(tok.disclosure()), address(dis), "canonical disclosure from the token");
    }

    /// CTR-ZTH-36: the disclosure challenge carries `chainUid`; an opening made without it fails.
    function test_disclosureChallengeCarriesChainUid() public {
        _fund(tok, alice, 500);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        Tx memory t = _proveTransfer(tok, alice, bob, 123, 500, _none(), 0);
        bytes32 ref = _direct(tok, t, _none());
        (bytes memory ct,) = dis.transferCiphertext(address(tok), ref, 0);
        bytes memory dOut = _cut(ct, ver.g1EncodedBytes(), ver.g1EncodedBytes());
        uint256 r = ver.groupOrder();
        uint256 k = 0x5151;
        bytes memory a1 = ver.g1MulBase(k);
        bytes memory a2 = ver.g1Mul(dOut, k);
        // the full new preimage (G ‖ K ‖ B ‖ M) minus chainUid: chainUid is the only difference from the honest one
        uint256 e = uint256(keccak256(bytes.concat(
            abi.encodePacked("SCAAS-ZETHER-DISCLOSE-V2", block.chainid, address(tok)),
            abi.encodePacked(ref, uint256(0), uint256(123), uint8(1)),
            ver.g1MulBase(1), bob.y, dOut, _cut(ct, 0, ver.g1EncodedBytes()), a1, a2
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
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        audOut = true;
        Tx memory t = _proveTransfer(tok, alice, bob, 123, 500, _none(), 0);
        audOut = false;
        Tx memory on = _proveTransfer(tok, alice, bob, 123, 500, _none(), 0);
        // a proof of one choice does not pass under the other (Y_a is in the statement)
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.mtxConfidentialTransferSingle(t.payload, on.proof, "", bytes32(0), "");
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.mtxConfidentialTransferSingle(on.payload, t.proof, "", bytes32(0), "");
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
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        assertTrue(_holds(tok, alice, b0, true), "acc holds > 2^44");
        uint256 v = (uint256(1) << 33) + 7;
        Tx memory t = _proveTransfer(tok, alice, bob, v, b0, carol.ua, 0);
        uint256 g0 = gasleft();
        bytes32 ref = _direct(tok, t, carol.ua);
        console2.log(bls ? "bls12-381" : "bn254", "mtxConfidentialTransferSingle v > 2^32 (direct, auditor, fee) gas", g0 - gasleft());
        uint256 b1 = b0 - v - FEE;
        assertTrue(_holds(tok, alice, b1, true), "sender acc = b - v - fee");
        assertTrue(_holds(tok, bob, v, false), "receiver pending = v");
        assertEq(tok.balanceOfUA(ZetherTypes.UA.unwrap(carol.ua)), FEE * SCALE, "beneficiary public balance = fee x scale");
        assertEq(tok.accountState(carol.ua).pendingSeq, 0, "no pend_ben credit (D19)");
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
        tok.mtxRollOver(ZetherTypes.UA.unwrap(bob.ua), 1);
        uint256 bb = v + b1;
        assertTrue(_holds(tok, bob, bb, true), "receiver acc = v + b1");
        (bytes memory pl, bytes memory pr) = _proveUnshield(tok, bob, bb, bb, address(0xD00D), _none(), 0);
        tok.mtxUnshield(pl, pr, "", bytes32(0), "", bb, bytes32(uint256(uint160(address(0xD00D)))));
        assertEq(tok.balanceOf(address(0xD00D)), bb * SCALE);
        assertEq(tok.totalShielded(), 0, "the fee left the shielded set (D19)");
    }

    /// The auditor decrypts the disclosed transfer, nobody's balance.
    function test_auditorSeesTransferButNoBalance() public {
        _fund(tok, alice, 500);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        bytes32 ref = _direct(tok, _proveTransfer(tok, alice, bob, 321, 500, _none(), 0), _none());
        (bytes memory ct,) = dis.transferCiphertext(address(tok), ref, 0);
        uint256 p = ver.g1EncodedBytes();
        assertEq(_decrypt(_cut(ct, 2 * p, p), _cut(ct, p, p), X_AUD, 400), 321, "auditor reads C_aud");
        IZetherToken.AccountState memory s = tok.accountState(alice.ua);
        vm.expectRevert(bytes("decrypt: out of range"));
        this.decryptExt(s.accC, s.accD, X_AUD, 1100); // alice's 179: the auditor cannot read it
        assertEq(_decrypt(s.accC, s.accD, alice.x, 1100), 179);
    }

    // ------------------------------------------------------------------ UA-6 (U8, U9): the Zether key is the UA

    /// U9: a spend is authorized by the proof alone: no registry authorization call (only `kindOf`), no `authSig`.
    function test_UA6_spendWithoutAuthSig() public {
        _fund(tok, alice, 100);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
        Tx memory t1 = _proveTransfer(tok, alice, bob, 30, 100, _none(), 0);
        bytes4 legacyAuth = bytes4(keccak256("requireZetherAuthorized(bytes32,bytes32,bytes,bool)"));
        vm.expectCall(address(reg), abi.encodeWithSelector(legacyAuth), 0);
        vm.expectCall(address(reg), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector), 0);
        tok.mtxConfidentialTransferSingle(t1.payload, t1.proof, "", bytes32(0), "");
        (bytes memory pl, bytes memory pr) = _proveUnshield(tok, alice, 20, 70, address(0xD00D), _none(), 0);
        tok.mtxUnshield(pl, pr, "", bytes32(0), "", 20, bytes32(uint256(uint160(address(0xD00D)))));
        (uint256 a,) = _bal(alice);
        assertEq(a, 50);
        assertEq(tok.balanceOf(address(0xD00D)), 20 * SCALE);
    }

    /// U9: the owner ops go through `requireAuthorized(ua, zether-owner, digest, abi.encode("", Schnorr by x))`; a
    /// signature under another purpose is refused.
    function test_UA6_ownerOpsThroughRequireAuthorized() public {
        uint64 until = uint64(block.number + 50);
        bytes32 ua = ZetherTypes.UA.unwrap(alice.ua);
        bytes32 d = keccak256(bytes.concat(
            abi.encode(keccak256("ZETHER_SET_ROLLOVER_MODE_V1"), block.chainid, ZUID, address(tok)),
            abi.encode(alice.ua, uint8(ZetherTypes.RollOverMode.OWNER_ONLY), uint64(0), until)
        ));
        bytes memory wrong = _uaAuth(alice, UAKinds.PURPOSE_METATX, d);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        tok.mtxSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, wrong);
        bytes memory sig = _ownerAuth(alice, d);
        vm.expectCall(address(reg), abi.encodeCall(IUARegistry.requireAuthorized, (ua, UAKinds.PURPOSE_ZETHER_OWNER, d, sig)));
        tok.mtxSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, sig);
        _fund(tok, alice, 10);
        d = keccak256(bytes.concat(
            abi.encode(keccak256("ZETHER_ROLLOVER_V1"), block.chainid, ZUID, address(tok)),
            abi.encode(alice.ua, uint64(0), uint64(1), until)
        ));
        sig = _ownerAuth(alice, d);
        vm.expectCall(address(reg), abi.encodeCall(IUARegistry.requireAuthorized, (ua, UAKinds.PURPOSE_ZETHER_OWNER, d, sig)));
        tok.mtxRollOverSigned(alice.ua, 1, until, sig);
        assertEq(tok.accountState(alice.ua).accSeq, 1);
    }

    /// Owner ruling 2026-10-20: the owner ops accept a registered Zether UA only. A `schnorr-bn254` UA (same
    /// key, valid Schnorr under `zether-owner`) and an unregistered id are refused with `AccountNotRegistered`.
    function test_ownerOpsZetherUaOnly() public {
        uint256 x = 0xBEEF1;
        bytes memory y = ZetherKeys.pub(x, false);
        bytes32 other = reg.uaOf(UAKinds.SCHNORR_BN254, y);
        bytes32 pd = UAKinds.registrationDigest(UAKinds.portablePopDigest(other, 0, 0), 0); // UA-8: portable
        vm.prank(address(0xB0B));
        reg.register(
            UAKinds.SCHNORR_BN254,
            y,
            IUARegistry.UAAttrs("", 0, 0, ""),
            ZetherKeys.sign("scaas.ua.schnorr.v1", x, reg.uaMessage(UAKinds.SCHNORR_BN254, UAKinds.PURPOSE_POP_V2, pd), false),
            ""
        );
        _refusedOwnerOps(other, x);
        _refusedOwnerOps(keccak256("unregistered"), x);
    }

    function _refusedOwnerOps(bytes32 raw, uint256 x) internal {
        uint64 until = uint64(block.number + 50);
        ZetherTypes.UA id = ZetherTypes.UA.wrap(raw);
        bytes32 d = keccak256(abi.encode(
            keccak256("ZETHER_SET_ROLLOVER_MODE_V1"), block.chainid, ZUID, address(tok), id,
            uint8(ZetherTypes.RollOverMode.OWNER_ONLY), uint64(0), until
        ));
        bytes memory sig = _otherSig(x, d);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, id));
        tok.mtxSetRollOverMode(id, ZetherTypes.RollOverMode.OWNER_ONLY, until, sig);
        d = keccak256(abi.encode(
            keccak256("ZETHER_ROLLOVER_V1"), block.chainid, ZUID, address(tok), id, uint64(0), uint64(1), until
        ));
        sig = _otherSig(x, d);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, id));
        tok.mtxRollOverSigned(id, 1, until, sig);
    }

    function _otherSig(uint256 x, bytes32 d) internal view returns (bytes memory) {
        return abi.encode(bytes(""), ZetherKeys.sign("scaas.ua.schnorr.v1", x, reg.uaMessage(UAKinds.SCHNORR_BN254, UAKinds.PURPOSE_ZETHER_OWNER, d), false));
    }

    /// U8 (CTR-UA-30 (2), CTR-ZTH-51): the Zether UA's public balance lives on the UA ledger under the same id: it
    /// receives by `transferToUA` and by a UA transfer, signs a `UAMetaTransfer`, and shields its own public units with
    /// `uaExecute(mtxShield)` (Schnorr by `x` under `metatx`).
    function test_UA6_zetherUaSignsMetaTxAndShields() public {
        bytes32 a = ZetherTypes.UA.unwrap(alice.ua);
        bytes32 b = ZetherTypes.UA.unwrap(bob.ua);
        _public(tok, address(this), 100 * SCALE);
        tok.transferToUA(a, 100 * SCALE);
        assertEq(tok.balanceOfUA(a), 100 * SCALE);
        MetaTxLib.UAMetaTransfer memory t = MetaTxLib.UAMetaTransfer({
            from: a, to: b, value: 10 * SCALE, entryRef: 0, batch: 1, nonce: tok.uaNonce(a, 1),
            validUntil: block.timestamp + 300, mode: MetaTxLib.MODE_RESTRICT_RELAYER, relayer: relayer, fee: 0,
            feeRecipient: address(0)
        });
        bytes memory auth = _uaAuth(alice, UAKinds.PURPOSE_METATX, tok.uaTransferDigest(t));
        vm.prank(relayer);
        tok.uaExecuteTransfer(t, auth);
        assertEq(tok.balanceOfUA(b), 10 * SCALE);
        MetaTxLib.UAMetaTransaction memory m = MetaTxLib.UAMetaTransaction({
            from: a, data: abi.encodeCall(ZetherLayer.mtxShield, (ZetherTypes.UA.unwrap(alice.ua), 40)), batch: 1, nonce: tok.uaNonce(a, 1),
            validUntil: block.timestamp + 300, mode: MetaTxLib.MODE_RESTRICT_RELAYER, relayer: relayer, fee: 0,
            feeRecipient: address(0)
        });
        auth = _uaAuth(bob, UAKinds.PURPOSE_METATX, tok.uaDigest(m)); // another key
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, a));
        vm.prank(relayer);
        tok.uaExecute(m, auth);
        auth = _uaAuth(alice, UAKinds.PURPOSE_METATX, tok.uaDigest(m));
        vm.prank(relayer);
        tok.uaExecute(m, auth);
        assertEq(tok.balanceOfUA(a), 50 * SCALE);
        (, uint256 p) = _bal(alice);
        assertEq(p, 40, "the Zether UA shielded its own public units");
        assertEq(tok.totalShielded(), 40);
        assertEq(tok.totalSupply(), minted[address(tok)]);
        assertEq(tok.balanceOf(SHIELD_POOL_), 40 * SCALE);
    }

    /// The Zether UA's signature through `requireAuthorized` (stored kind: no key data).
    function _uaAuth(User memory u, bytes32 purpose, bytes32 digest) internal view returns (bytes memory) {
        return abi.encode(bytes(""), ZetherKeys.schnorr(u.x, reg.uaMessage(_zkind(), purpose, digest), bls));
    }

    function decryptExt(bytes memory c, bytes memory d, uint256 x, uint256 max) external view returns (uint256) {
        return _decrypt(c, d, x, max);
    }
}

contract ZetherNormalBls12381Test is ZetherNormalSuite {}
