// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {PqzOffchainBase, VerdictOutOfGas} from "./helpers/PqzOffchainBase.sol";
import {noVerdict} from "./helpers/PqzVerdicts.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {PqzSafety} from "../../src/pqz/PqzSafety.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {SSTORE2} from "../../src/common/SSTORE2.sol";
import {UACall} from "../ua/UACall.sol";
import {Catalogue, pqzEnv} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {PQZ_UID} from "./helpers/PqzRegistryBase.sol";

/// Group 3f, T44 (PQZ verifier mode spec §3, §5, §6; CTR-PQZ-27, -29, -30 drafts): the `OFFCHAIN` core. Positive control
/// first, then one change at a time: the verdict's binding (token, chain, `proofSystemId`, statement, proof, epoch,
/// `validUntil`, the domain, the signer, starvation), revocation and shape, the mode at init, the zero-dep release, the
/// key rule of each mode (KV-12) and the 3g items moved here (owner 2026-11-07: 3g before 3f). UNAUDITED.
contract PqzOffchainCoreTest is PqzOffchainBase {
    PqzLayer internal off;

    function setUp() public {
        _offStack();
        tok = _newToken("pqz-precompile");
        off = _offToken("pqz-offchain", vA, false);
        _shieldOn(off, alice, 100);
        _shieldOn(tok, alice, 100);
    }

    function _mismatch(uint8 f) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IPqzToken.PqzVerdictMismatch.selector, f);
    }

    /// The op 1 of the control and its statement.
    function _op() internal view returns (IPqzToken.PqzTransferArgs memory a, bytes memory st) {
        return _op1Of(off, alice, bob, 5, true);
    }

    // ------------------------------------------------------------------ the binding (spec §5.2, §5.3)

    function test_pqzVerdict_positiveControl() public {
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op();
        IPqzToken.PqzSignedVerdict memory sv = _sv(off, st);
        vm.expectCall(PQZ, bytes(""), 0);
        vm.expectEmit(address(off));
        emit IPqzToken.PqzVerified(keccak256(st), keccak256(VPROOF), vA, 0);
        bytes32 ref = off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
        assertTrue(off.pqzEntryBlob(ref).length != 0, "the entry is stored");
        assertEq(off.pqzAccount(bob, 0).pendingCount, 1, "bob credited");
    }

    function test_pqzVerdict_wrongToken() public {
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op();
        IPqzToken.PqzVerdict memory v = _verdict(off, st, VPROOF);
        v.token = address(tok);
        IPqzToken.PqzSignedVerdict memory sv = _sign(off, VKEY, v);
        vm.expectRevert(_mismatch(0));
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
        // the right fields, signed in another token's domain
        sv = _signAt(address(tok), VKEY, _verdict(off, st, VPROOF));
        vm.expectRevert(IPqzToken.PqzVerdictRejected.selector);
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
    }

    function test_pqzVerdict_wrongChain() public {
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op();
        IPqzToken.PqzVerdict memory v = _verdict(off, st, VPROOF);
        v.chainId = block.chainid + 1;
        IPqzToken.PqzSignedVerdict memory sv = _sign(off, VKEY, v);
        vm.expectRevert(_mismatch(1));
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
    }

    function test_pqzVerdict_wrongPsid() public {
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op();
        assertEq(off.proofSystemId(), PqzSet.PQZL_ID, "OFFCHAIN: the build's PQZL id");
        IPqzToken.PqzVerdict memory v = _verdict(off, st, VPROOF);
        v.proofSystemId = keccak256("another proof system");
        IPqzToken.PqzSignedVerdict memory sv = _sign(off, VKEY, v);
        vm.expectRevert(_mismatch(2));
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
    }

    /// A verdict over S1 while the op builds S2 (another salt), and over a statement with a replaced key.
    function test_pqzVerdict_wrongStatement() public {
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op();
        IPqzToken.PqzSignedVerdict memory sv = _sv(off, st);
        a.salt = bytes16(uint128(0x5A18));
        vm.expectRevert(_mismatch(3));
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
        (a,) = _op();
        a.beneficiaryUA = carol;
        vm.expectRevert(_mismatch(3));
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
    }

    function test_pqzVerdict_wrongProof() public {
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op();
        IPqzToken.PqzSignedVerdict memory sv = _sv(off, st);
        vm.expectRevert(_mismatch(4));
        off.mtxConfidentialTransferSingle(a, hex"c0df", _pqAuth(), "", sv);
    }

    function test_pqzVerdict_wrongEpoch() public {
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op();
        IPqzToken.PqzVerdict memory v = _verdict(off, st, VPROOF);
        v.pqzVerifierEpoch = 1;
        IPqzToken.PqzSignedVerdict memory sv = _sign(off, VKEY, v);
        vm.expectRevert(_mismatch(5));
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
    }

    /// `validUntil = now - 1` refused, `now` passes.
    function test_pqzVerdict_expired() public {
        vm.warp(1_000_000);
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op();
        IPqzToken.PqzVerdict memory v = _verdict(off, st, VPROOF);
        v.validUntil = uint64(block.timestamp - 1);
        IPqzToken.PqzSignedVerdict memory sv = _sign(off, VKEY, v);
        vm.expectRevert(_mismatch(6));
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
        v.validUntil = uint64(block.timestamp);
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sign(off, VKEY, v));
    }

    function test_pqzVerdict_rejectedSignature() public {
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op();
        IPqzToken.PqzSignedVerdict memory sv = _sign(off, VKEY2, _verdict(off, st, VPROOF));
        vm.expectRevert(IPqzToken.PqzVerdictRejected.selector);
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
        sv.sig.signature = ""; // the right fields, no signature
        sv.pqzVerdict = _verdict(off, st, VPROOF);
        vm.expectRevert(IPqzToken.PqzVerdictRejected.selector);
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
    }

    /// The verifier's signature check out of gas is `UAVerifyGas`, never `PqzVerdictRejected` (the auth check before it is
    /// let through: its own `requireAuthorized` call is the holder's, `PURPOSE_ZETHER_AUTH`).
    function test_pqzVerdict_starvedIsUAVerifyGas() public {
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op();
        IPqzToken.PqzSignedVerdict memory sv = _sv(off, st);
        vm.mockFunction(address(reg), address(new VerdictOutOfGas()), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector));
        vm.expectRevert(UAKinds.UAVerifyGas.selector);
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
        // the registry's own `UAVerifyGas`
        vm.clearMockedCalls();
        _mockMlDsa();
        vm.mockCallRevert(address(reg), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector, vA),
            abi.encodeWithSelector(UAKinds.UAVerifyGas.selector));
        vm.expectRevert(UAKinds.UAVerifyGas.selector);
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
    }

    /// A -> B -> A (notice 0: each transfer applies at once): A's withheld epoch-0 signature is refused at epoch 2.
    function test_pqzVerdict_epochABA() public {
        PqzLayer t = _owned(vA, false);
        _shieldOn(t, alice, 10);
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op1Of(t, alice, bob, 5, true);
        IPqzToken.PqzSignedVerdict memory old = _sv(t, st);
        t.pqzSetVerifier(vB);
        t.pqzSetVerifier(vA);
        assertEq(t.pqzVerifyConfig().pqzVerifierEpoch, 2);
        assertEq(t.pqzVerifyConfig().verifier, vA);
        vm.expectRevert(_mismatch(5));
        t.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", old);
        t.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sv(t, st)); // a fresh epoch-2 verdict
    }

    function test_pqzVerdict_revokedRefuses() public {
        PqzLayer t = _owned(vA, false);
        _shieldOn(t, alice, 10);
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op1Of(t, alice, bob, 5, true);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        t.pqzRevokeVerifier();
        vm.expectRevert(IPqzToken.PqzVerifierRevoked.selector);
        t.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
    }

    /// A native verifier that gains code: every proof refuses `PqzVerifierChanged`.
    function test_pqzVerdict_shapeChanged_nativeCode() public {
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op();
        IPqzToken.PqzSignedVerdict memory sv = _sv(off, st);
        uint256 snap = vm.snapshotState();
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
        vm.revertToState(snap);
        vm.deal(address(uint160(uint256(vA))), 1 ether); // an account that exists but holds no code: the same shape
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
        vm.revertToState(snap);
        vm.etch(address(uint160(uint256(vA))), hex"00");
        vm.expectRevert(IPqzToken.PqzVerifierChanged.selector);
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
    }

    // ------------------------------------------------------------------ the mode (spec §3)

    /// The mode is written by init only: no entry or op moves byte 22 of slot 0 (I1 at large: the invariant suite).
    function test_mode_immutable() public {
        bytes32 root = PqzCore._STORAGE;
        assertEq(uint8(uint256(vm.load(address(off), root)) >> 176), 1, "OFFCHAIN at byte 22");
        assertEq(uint8(uint256(vm.load(address(tok), root)) >> 176), 0, "PRECOMPILE");
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op();
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sv(off, st));
        (IPqzToken.PqzBurnArgs memory b, bytes memory bst) = _burnOf(off, alice, 0, 0, 9);
        off.mtxUnshield(b, 0, 0, VPROOF, _pqAuth(), "", _sv(off, bst));
        assertEq(uint8(uint256(vm.load(address(off), root)) >> 176), 1, "still OFFCHAIN");
        assertEq(off.pqzVerifyConfig().pqzVerifyMode, 1);
        assertEq(tok.pqzVerifyConfig().pqzVerifyMode, 0);
    }

    function _create(uint8 mode, bytes32 v, bool fixed_) internal returns (address) {
        (vMode, vUA, vFixed) = (mode, v, fixed_);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        (vMode, vUA, vFixed) = (0, bytes32(0), false);
        return factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), keccak256(abi.encode(mode, v, fixed_)));
    }

    function test_mode_configInvalid() public {
        vm.expectRevert(IPqzToken.PqzVerifyConfigInvalid.selector);
        _create(0, vA, false); // PRECOMPILE with a verifier
        vm.expectRevert(IPqzToken.PqzVerifyConfigInvalid.selector);
        _create(0, 0, true); // PRECOMPILE fixed
        vm.expectRevert(IPqzToken.PqzVerifyConfigInvalid.selector);
        _create(1, 0, false); // OFFCHAIN without one
        vm.expectRevert(IPqzToken.PqzVerifyConfigInvalid.selector);
        _create(1, 0, true);
        _create(1, vA, true); // controls
        _create(0, 0, false);
    }

    function test_mode_valueInvalid() public {
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PqzVerifyModeInvalid.selector, uint8(2)));
        _create(2, vA, false);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PqzVerifyModeInvalid.selector, uint8(255)));
        _create(255, 0, false);
    }

    // ------------------------------------------------------------------ the zero-dep release (spec §3, C6)

    /// A release with `deps = [0]` on a second factory (the release passes `validateEnv`).
    function _zeroDepFactory() internal returns (OpenFactory f) {
        f = new OpenFactory(registrar);
        EnvKit.configure(f, PQZ_UID, 0, address(0));
        Catalogue.release(f, IOpenFactory.TokenKind.NORMAL_PQZ, 1, pqzEnv(address(f), PQZ_UID, address(reg), address(0)),
            type(NormalPqzToken).creationCode);
        vm.prank(registrar);
        f.setKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true);
    }

    /// PRECOMPILE on it: `SelfTestFailed(address(0))` before any call (the auditor's key is not even read).
    function test_release_zeroDep_precompileRefused() public {
        OpenFactory f = _zeroDepFactory();
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        vm.expectCall(address(reg), abi.encodeWithSelector(IUARegistry.pqzKeyOf.selector), 0);
        vm.expectRevert(abi.encodeWithSelector(PqzSafety.SelfTestFailed.selector, address(0)));
        f.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), "zero-dep-pre");
    }

    /// OFFCHAIN on it initialises and runs a transfer; the precompile is never called (an absent one: no mock answers).
    function test_release_zeroDep_offchainInits() public {
        OpenFactory f = _zeroDepFactory();
        (vMode, vUA, vFixed) = (1, vA, false);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        (vMode, vUA, vFixed) = (0, bytes32(0), false);
        PqzLayer t = PqzLayer(f.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), "zero-dep-off"));
        assertEq(t.verifier(), address(0));
        assertEq(t.precompile(), address(0));
        assertEq(t.proofSystemId(), PqzSet.PQZL_ID);
        _shieldOn(t, alice, 10);
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op1Of(t, alice, bob, 5, true);
        vm.clearMockedCalls();
        _mockMlDsa();
        vm.etch(PQZ, hex"fe"); // a precompile that would revert
        vm.expectCall(PQZ, bytes(""), 0);
        t.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sv(t, st));
    }

    /// I5: transfer, burn, refresh of an OFFCHAIN token never call `0x…5caa0f01`.
    function test_offchain_neverCallsPrecompile() public {
        vm.expectCall(PQZ, bytes(""), 0);
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op();
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sv(off, st));
        (IPqzToken.PqzBurnArgs memory b, bytes memory bst) = _burnOf(off, alice, 3, bytes32(uint256(0xD00D)), 9);
        off.mtxUnshield(b, 3, bytes32(uint256(0xD00D)), VPROOF, _pqAuth(), "", _sv(off, bst));
        (b, bst) = _burnOf(off, alice, 0, 0, 10);
        off.mtxUnshield(b, 0, 0, VPROOF, _pqAuth(), "", _sv(off, bst));
    }

    /// I5: a PRECOMPILE token never reads the verdict: a garbage one changes nothing, and the precompile decides.
    function test_precompile_ignoresPqzVerdict() public {
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op1Of(tok, alice, bob, 5, true);
        IPqzToken.PqzSignedVerdict memory g = _sv(off, st);
        g.pqzVerdict.token = address(0xBAD);
        g.sig.signature = hex"deadbeef";
        vm.mockCallRevert(address(reg), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector, vA,
            UAKinds.PURPOSE_PQZ_VERDICT), "never asked");
        uint256 snap = vm.snapshotState();
        tok.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", g);
        vm.revertToState(snap);
        _mockOp(1, 0);
        IPqzToken.PqzSignedVerdict memory good = _sv(tok, st);
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", good);
    }

    // ------------------------------------------------------------------ keys (spec §6, KV-12)

    /// A UA whose version-0 key is stored without its proof (the `0x0142` verifier never checked it).
    function _unprovenUA(bytes memory pk, uint8 seed) internal returns (bytes32 ua) {
        ua = UACall.register(reg, UAKinds.MLDSA65, _mlPk(seed), _pqzAttrs(pk), new bytes(ML65_SIG), "");
        (,,, bool proven) = reg.pqzKeyOf(ua);
        assertFalse(proven, "unproven");
    }

    function test_keys_unproven_offchainAccepts() public {
        bytes32 dan = _unprovenUA(_pk(41), 41);
        _shieldOn(off, dan, 5); // a credit (TRIVIAL)
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op1Of(off, alice, dan, 5, true);
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sv(off, st)); // a credit by a transfer
        (a, st) = _op1Of(off, dan, bob, 6, true);
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sv(off, st)); // a debit
    }

    function test_keys_unproven_precompileRefuses() public {
        bytes32 dan = _unprovenUA(_pk(41), 41);
        _public(tok, address(this), 5 * SCALE);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, dan));
        tok.mtxShield(dan, 5);
        (IPqzToken.PqzTransferArgs memory a,) = _op1Of(tok, alice, bob, 5, true);
        a.toUA = dan;
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, dan));
        tok.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", noVerdict());
    }

    /// A key of another set's length: refused in both modes.
    function test_keys_unproven_wrongLength() public {
        bytes memory other = new bytes(PqzCt.PK == 16_384 ? 18_432 : 16_384);
        other[7] = 0x2a;
        bytes32 dan = _unprovenUA(other, 42);
        _public(off, address(this), 5 * SCALE);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, dan));
        off.mtxShield(dan, 5);
        _public(tok, address(this), 5 * SCALE);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, dan));
        tok.mtxShield(dan, 5);
    }

    /// An unproven auditor at init: OFFCHAIN passes, PRECOMPILE refused.
    function test_auditor_unproven_offchain() public {
        aud = _unprovenUA(_pk(43), 43);
        PqzLayer t = _offToken("aud-unproven-off", vA, false);
        assertEq(t.auditorUA(), aud);
    }

    function test_auditor_unproven_precompile() public {
        aud = _unprovenUA(_pk(43), 43);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, aud));
        _newToken("aud-unproven-pre");
    }

    // ------------------------------------------------------------------ I4: the ciphertexts in both modes

    /// The same op 1 on a PRECOMPILE and an OFFCHAIN token from the same state: the op blob, the entry, the credit and the
    /// account are identical (never lose ciphertext, CTR-PQZ-07).
    function test_ciphertexts_sameInBothModes() public {
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op();
        (IPqzToken.PqzTransferArgs memory a2,) = _op1Of(tok, alice, bob, 5, true);
        bytes32 r1 = tok.mtxConfidentialTransferSingle(a2, VPROOF, _pqAuth(), "", noVerdict());
        bytes32 r2 = off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sv(off, st));
        assertEq(tok.pqzEntryBlob(r1), off.pqzEntryBlob(r2), "op blob");
        assertEq(tok.transferCiphertextHash(r1), off.transferCiphertextHash(r2));
        assertEq(tok.pqzPendingCt(bob, 0, 0), off.pqzPendingCt(bob, 0, 0), "the credit");
        assertEq(tok.pqzAcc(alice, 0), off.pqzAcc(alice, 0), "the sender's acc");
        assertEq(tok.totalShielded(), off.totalShielded());
        (IPqzToken.PqzBurnArgs memory b, bytes memory bst) = _burnOf(off, alice, 0, 0, 9);
        (IPqzToken.PqzBurnArgs memory b2,) = _burnOf(tok, alice, 0, 0, 9);
        tok.mtxUnshield(b2, 0, 0, VPROOF, _pqAuth(), "", noVerdict());
        off.mtxUnshield(b, 0, 0, VPROOF, _pqAuth(), "", _sv(off, bst));
        assertEq(tok.pqzAcc(alice, 0), off.pqzAcc(alice, 0), "refresh: acc");
    }

    function test_PqzVerdictTypehashIsPinned() public pure {
        assertEq(PqzCore.VERDICT_TYPEHASH, keccak256(
            "PqzVerdict(address token,uint256 chainId,bytes32 proofSystemId,bytes32 statementHash,bytes32 proofHash,uint32 pqzVerifierEpoch,uint64 validUntil)"));
        assertEq(PqzCore.VERDICT_TYPEHASH, 0x18a510364af2f51c138ef32b05cda5a4ebabb81bc0a964b911044a3983d1ff88, "the pin");
        assertEq(UAKinds.PURPOSE_PQZ_VERDICT, keccak256("scaas.ua.purpose.pqz-verdict.v1"));
    }

    // ------------------------------------------------------------------ moved from 3g (KV-12, owner 2026-11-07)

    /// A verdict issued for a receiver before its rotation and submitted after it: `PqzVerdictMismatch(statementHash)`
    /// (liveness only). Control: before the rotation it lands.
    function test_inflight_offchain_refused() public {
        (IPqzToken.PqzTransferArgs memory a, bytes memory st) = _op();
        IPqzToken.PqzSignedVerdict memory sv = _sv(off, st);
        uint256 snap = vm.snapshotState();
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
        vm.revertToState(snap);
        reg.setPqzKey(bob, 1, _pk(31), keccak256("v1"), UACall.sig(new bytes(ML65_SIG)));
        reg.storePqzPop(bob, 1, "v1");
        vm.expectRevert(_mismatch(3));
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
    }

    /// On a registry with the verifier an OFFCHAIN token credits the highest PROVEN version (registry KV-3).
    function test_offchain_currentProvenOnVerifier() public {
        reg.setPqzKey(bob, 1, _pk(31), keccak256("v1"), UACall.sig(new bytes(ML65_SIG))); // stored, not proven
        _shieldOn(off, bob, 3);
        assertEq(off.pqzAccount(bob, 0).pendingCount, 1, "version 0, the proven one");
        reg.storePqzPop(bob, 1, "v1");
        _shieldOn(off, bob, 3);
        assertEq(off.pqzAccount(bob, 1).pendingCount, 1, "version 1 once proven");
    }

    /// Version 0 unproven while none is proven: current, and an OFFCHAIN token credits it.
    function test_offchain_v0UnprovenWhileNoneProven() public {
        bytes32 dan = _unprovenUA(_pk(44), 44);
        (uint64 cur,,,) = reg.pqzKeyOf(dan);
        assertEq(cur, 0);
        _shieldOn(off, dan, 2);
        assertEq(off.pqzAccount(dan, 0).pendingCount, 1);
    }

    /// On a registry without the verifier a version becomes current only once its proof bytes are stored.
    function test_offchain_noVerifierNeedsBytes() public {
        (PqzLayer t, UARegistry r2) = _noVerifierToken(vA);
        bytes32 dan = UACall.register(r2, UAKinds.MLDSA65, _mlPk(45), _pqzAttrs(_pk(45)), new bytes(ML65_SIG), hex"aa");
        _shieldOn(t, dan, 1);
        r2.setPqzKey(dan, 1, _pk(46), keccak256("b1"), UACall.sig(new bytes(ML65_SIG)));
        vm.roll(block.number + 1); // a new block: a TRIVIAL entry of this block would merge into the tail
        _shieldOn(t, dan, 1);
        assertEq(t.pqzAccount(dan, 0).pendingCount, 2, "v1 without its bytes is not current");
        r2.storePqzPop(dan, 1, "b1");
        vm.roll(block.number + 1);
        _shieldOn(t, dan, 1);
        assertEq(t.pqzAccount(dan, 1).pendingCount, 1, "v1 current once its bytes are stored");
    }

    /// A burn verdict for version 0 cannot be retargeted to version 1 by changing `keyVersion`: stale refused, retargeted
    /// the statement (version 1's key) differs and the verdict mismatches.
    function test_offchain_outstanding_notRetargetable() public {
        (IPqzToken.PqzBurnArgs memory b,) = _burnOf(off, alice, 10, bytes32(uint256(0xD00D)), 9);
        b.p = 0; // at p 0 both versions' accounts are empty: only the key differs once retargeted
        IPqzToken.PqzSignedVerdict memory sv = _sv(off, off.burnStatement(b, 10, bytes32(uint256(0xD00D)), 0));
        reg.setPqzKey(alice, 1, _pk(34), keccak256("a1"), UACall.sig(new bytes(ML65_SIG)));
        reg.storePqzPop(alice, 1, "a1");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.StaleKeyVersion.selector, alice, uint64(0), uint64(1)));
        off.mtxUnshield(b, 10, bytes32(uint256(0xD00D)), VPROOF, _pqAuth(), "", sv);
        b.keyVersion = 1;
        vm.expectRevert(_mismatch(3));
        off.mtxUnshield(b, 10, bytes32(uint256(0xD00D)), VPROOF, _pqAuth(), "", sv);
    }

    /// Two UAs that stored one key on a registry without the verifier (unproven: no `keyOwner` refusal to rely on), both
    /// legs of an op 7 of an OFFCHAIN token: `KeyReused` (KV-9, M-T6). Control: distinct keys land.
    function test_keyReused_legs_offchain() public {
        (PqzLayer t, UARegistry r2) = _noVerifierToken(vA);
        bytes32 s1 = UACall.register(r2, UAKinds.MLDSA65, _mlPk(51), _pqzAttrs(_pk(51)), new bytes(ML65_SIG), hex"aa");
        bytes32 l1 = UACall.register(r2, UAKinds.MLDSA65, _mlPk(52), _pqzAttrs(_pk(52)), new bytes(ML65_SIG), hex"aa");
        bytes32 l2 = UACall.register(r2, UAKinds.MLDSA65, _mlPk(53), _pqzAttrs(_pk(52)), new bytes(ML65_SIG), hex"aa");
        bytes32 l3 = UACall.register(r2, UAKinds.MLDSA65, _mlPk(54), _pqzAttrs(_pk(54)), new bytes(ML65_SIG), hex"aa");
        _shieldOn(t, s1, 10);
        bytes32[] memory legs = new bytes32[](2);
        (legs[0], legs[1]) = (l1, l3);
        IPqzToken.PqzMultiArgs memory m = _ms(_mpayload(1, 0, s1, bytes32(0), legs, _blob(6, _outLen(2, false)), ""));
        t.mtxConfidentialTransfer(m, VPROOF, _pqAuth(), "", _sv(t, t.transferStatement(m, 0)));
        legs[1] = l2;
        m = _ms(_mpayload(2, 0, s1, bytes32(0), legs, _blob(7, _outLen(2, false)), ""));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.KeyReused.selector, l2));
        t.transferStatement(m, 0);
    }

    /// A leg's key equal to the auditor's on an OFFCHAIN token: `KeyReused`.
    function test_keyReused_auditor_offchain() public {
        (IPqzToken.PqzTransferArgs memory a,) = _op();
        (uint64 v, address p, bytes32 ph, bool pr) = reg.pqzKeyOf(aud);
        vm.mockCall(address(reg), abi.encodeCall(IUARegistry.pqzKeyOf, (bob)), abi.encode(v, p, ph, pr));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.KeyReused.selector, aud));
        off.transferSingleStatement(a, 0);
    }

    /// A migration whose two versions hold one key, on an OFFCHAIN token: `KeyReused`.
    function test_keyReused_migration_offchain() public {
        reg.setPqzKey(alice, 1, _pk(34), keccak256("a1"), UACall.sig(new bytes(ML65_SIG)));
        reg.storePqzPop(alice, 1, "a1");
        (, address p, bytes32 ph, bool pr) = reg.pqzKeyOf(alice);
        vm.mockCall(address(reg), abi.encodeCall(IUARegistry.pqzKeyAt, (alice, uint64(0))), abi.encode(p, ph, pr));
        IPqzToken.PqzTransferArgs memory a = _ts(_payload(1, 0, alice, alice, bytes32(0), _out(5, false), ""));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.KeyReused.selector, alice));
        off.transferSingleStatement(a, 0);
    }

    // ------------------------------------------------------------------ helpers

    /// An OFFCHAIN token with this test as its owner (the governance entries' caller) on the fixture's factory (notice 0).
    function _owned(bytes32 v, bool fixed_) internal returns (PqzLayer t) {
        (vMode, vUA, vFixed) = (PqzCore.OFFCHAIN, v, fixed_);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        (vMode, vUA, vFixed) = (0, bytes32(0), false);
        c.owner = bytes32(uint256(uint160(address(this))));
        t = PqzLayer(factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), keccak256(abi.encode(v, fixed_,
            gasleft()))));
    }
}
