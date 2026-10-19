// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {ZetherFixture} from "./helpers/ZetherFixture.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {UnderlyingZetherToken} from "../../src/zether/UnderlyingZetherToken.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ITransferDisclosure} from "../../src/zether/ITransferDisclosure.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {ZetherKeys} from "./helpers/ZetherKeys.sol";
import {ZUID} from "./helpers/ZetherFixture.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// @notice The two modes fixed at `initialize` (CTR-ZTH-48, CTR-ZTH-49), every pair on a kind: `disclosureMode`
///         `BUNDLE` (`zetherTransfer` stores `R = salt ‖ B_1 ‖ … ‖ B_M`, `zetherTransferCompact` commits, `…NoBundle`
///         stores nothing, single stores `R`) or `COMPACT` (`zetherTransfer` and `…Compact` commit with the sender memo,
///         no-bundle and single refused); `auditorMode` `NONE` (every `C_aud = O`), `FULL` (every `C_aud ≠ O`) or
///         `OPTIONAL` (the sender's choice, all or nothing). Every stored form opens with the four openings; a
///         commit-reveal transfer opens with `R` from its event and with the `R` the sender rebuilds from `s` and the
///         values (CTR-ZTH-38, CTR-ZTH-42, CTR-ZTH-50).
abstract contract ZetherModesSuite is ZetherFixture {
    uint8 constant BUNDLE = 0;
    uint8 constant COMPACT = 1;
    uint8 constant NONE = 0;
    uint8 constant FULL = 1;
    uint8 constant OPTIONAL = 2;

    ITransferDisclosure.OpeningKind constant S = ITransferDisclosure.OpeningKind.SENDER_S;
    ITransferDisclosure.OpeningKind constant RX = ITransferDisclosure.OpeningKind.RECEIVER_X;
    ITransferDisclosure.OpeningKind constant AUD = ITransferDisclosure.OpeningKind.AUDITOR;
    ITransferDisclosure.OpeningKind constant CP = ITransferDisclosure.OpeningKind.SENDER_CP;

    /// @dev Alice's acc balance (plaintext), the transfers' source.
    uint256 internal bal;

    function _kind() internal pure virtual returns (IOpenFactory.TokenKind);

    /// @dev The kind's config: `_cfg` (`dMode`, `aMode`) plus the kind's own fields.
    function _kindCfg(bool auditor) internal view virtual returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(auditor, uint256(1) << 40);
    }

    function _newToken(bool auditor, bytes32 salt_, uint256) internal virtual override returns (ZetherLayer) {
        return ZetherLayer(factory.createToken(_kind(), 1, _kindCfg(auditor), salt_));
    }

    // ------------------------------------------------------------------ the matrix

    function test_bundleNone() public { _pair(BUNDLE, NONE); }
    function test_bundleFull() public { _pair(BUNDLE, FULL); }
    function test_bundleOptional() public { _pair(BUNDLE, OPTIONAL); }
    function test_compactNone() public { _pair(COMPACT, NONE); }
    function test_compactFull() public { _pair(COMPACT, FULL); }
    function test_compactOptional() public { _pair(COMPACT, OPTIONAL); }

    function _pair(uint8 d, uint8 a) internal {
        (dMode, aMode) = (d, a);
        tok = _newToken(a != NONE, bytes32(uint256(16 * d + a + 1)), 0);
        assertEq(uint8(tok.disclosureMode()), d, "disclosureMode");
        assertEq(uint8(tok.auditorMode()), a, "auditorMode");
        assertEq(tok.auditorKey().length != 0, a != NONE, "a key exactly when the auditor is on");
        _fund(tok, alice, 1000);
        tok.zetherRollOver(alice.ua);
        bal = 1000;
        _auditorRule(d, a);
        if (d == BUNDLE) _bundleForms(a);
        else _compactForms(a);
        _assertConservation(tok, 1000);
    }

    /// @dev `NONE` refuses an auditor leg, `FULL` an opt-out, both before the verifier and in the statement views (the
    ///      single format on a BUNDLE token too); `OPTIONAL` takes the opt-out (the AUDITOR opening then fails).
    function _auditorRule(uint8 d, uint8 a) internal {
        if (a == OPTIONAL) {
            audOut = true;
            (bytes32 ref, Tx memory t) = _multi(ZetherTypes.TransferMode.HASH, ZetherLayer.zetherTransferCompact.selector, 5);
            _openAll(ref, t.s, 5, _rebuild(_two(), _vs(5), t.s), false);
            audOut = false;
            return;
        }
        bytes4 err = a == NONE ? IZetherToken.AuditorForbidden.selector : IZetherToken.AuditorRequired.selector;
        (audForce, audOut) = (a == NONE, a == FULL);
        bytes memory multi = bytes.concat(_multiPayload(tok, alice, _two(), _vs(5), 7, tok.accountState(alice.ua)), _memo(2));
        bytes memory single = _payload(tok, alice, bob, 5, 7, tok.accountState(alice.ua));
        (audForce, audOut) = (false, false);
        vm.expectRevert(err);
        tok.zetherTransferCompact(multi, "", "", _none());
        vm.expectRevert(err);
        stm.transferStatement(address(tok), multi, _none(), ZetherTypes.TransferMode.HASH, 0);
        if (d == COMPACT) return;
        vm.expectRevert(err);
        tok.zetherTransferSingle(single, "", "", _none());
        vm.expectRevert(err);
        stm.transferStatementSingle(address(tok), single, _none(), 0);
    }

    /// @dev `BUNDLE`: `zetherTransfer` stores `R`, `zetherTransferCompact` commits, `zetherTransferNoBundle` stores
    ///      nothing, the single format stores `R` with its one leg.
    function _bundleForms(uint8 a) internal {
        bool audIn = a != NONE;
        (bytes32 ref, Tx memory t) = _multi(ZetherTypes.TransferMode.BUNDLE, ZetherLayer.zetherTransfer.selector, 11);
        bytes memory r = _rebuild(_two(), _vs(11), t.s);
        assertEq(tok.transferEntry(ref), r, "zetherTransfer on BUNDLE: R, the salt first");
        _openAll(ref, t.s, 11, "", audIn);
        _hashForm(audIn, ZetherLayer.zetherTransferCompact.selector);
        (ref, t) = _multi(ZetherTypes.TransferMode.NONE, ZetherLayer.zetherTransferNoBundle.selector, 13);
        assertEq(tok.transferEntry(ref).length, 0, "NONE: nothing stored");
        r = _rebuild(_two(), _vs(13), t.s); // before `expectRevert`: it calls out
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.UnknownEntry.selector, ref));
        _vta(tok, ref, 0, 13, S, abi.encode(t.s), r);
        t = _proveTransfer(tok, alice, bob, 14, bal, _none(), 0);
        ref = _direct(tok, t, _none());
        bal -= 14;
        assertEq(tok.transferEntry(ref), _rebuild(_one(), _vs1(14), t.s), "single: R with its one leg");
        _openAll(ref, t.s, 14, "", audIn);
    }

    /// @dev `COMPACT`: `zetherTransfer` and `zetherTransferCompact` both commit; the no-bundle entry, the single format
    ///      and every form but HASH are refused (token and statement views).
    function _compactForms(uint8 a) internal {
        bool audIn = a != NONE;
        bytes memory dis_ = abi.encodeWithSelector(IZetherToken.TransferEntryDisabled.selector, COMPACT);
        bytes memory pl = _multiPayload(tok, alice, _two(), _vs(11), 7, tok.accountState(alice.ua));
        bytes memory single = _payload(tok, alice, bob, 5, 7, tok.accountState(alice.ua));
        vm.expectRevert(dis_);
        tok.zetherTransferNoBundle(pl, "", "", _none());
        vm.expectRevert(dis_);
        stm.transferStatement(address(tok), pl, _none(), ZetherTypes.TransferMode.BUNDLE, 0);
        vm.expectRevert(dis_);
        stm.transferStatement(address(tok), pl, _none(), ZetherTypes.TransferMode.NONE, 0);
        vm.expectRevert(dis_);
        tok.zetherTransferSingle(single, "", "", _none());
        vm.expectRevert(dis_);
        stm.transferStatementSingle(address(tok), single, _none(), 0);
        _hashForm(audIn, ZetherLayer.zetherTransfer.selector);
        _hashForm(audIn, ZetherLayer.zetherTransferCompact.selector);
    }

    /// @dev Commit-reveal through `sel`: `keccak256(R)` in one slot and the memo next to it (`transferEntry` = both),
    ///      `R` in the event; the openings take the event's `R` and the sender's rebuilt one (the same bytes), and refuse
    ///      others.
    function _hashForm(bool audIn, bytes4 sel) internal {
        vm.recordLogs();
        (bytes32 ref, Tx memory t) = _multi(ZetherTypes.TransferMode.HASH, sel, 12);
        bytes memory r = _eventBundles(ref);
        assertEq(_rebuild(_two(), _vs(12), t.s), r, "the sender rebuilds R from s and the values");
        assertEq(tok.transferEntry(ref), abi.encodePacked(keccak256(r), _memo(2)), "keccak256(R) then the memo");
        _openAll(ref, t.s, 12, r, audIn);
        r[20] = bytes1(uint8(r[20]) ^ 1);
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.BundlesMismatch.selector, ref));
        _vta(tok, ref, 0, 12, S, abi.encode(t.s), r);
    }

    // ------------------------------------------------------------------ the memo and the salt are signed

    /// The memo's hash (header word 14) and the salt (word 13) are in the statement: a relayer that changes either after
    /// proving is refused; the memo has exactly `17 + 40·M` bytes on commit-reveal and none elsewhere, and starts with
    /// the payload's salt (`MemoSaltMismatch`, CTR-ZTH-50).
    function test_memoAndSaltBoundByTheProof() public {
        tok = _newToken(true, "memo", 0);
        _fund(tok, alice, 100);
        tok.zetherRollOver(alice.ua);
        Tx memory t = _proveMulti(tok, alice, _two(), _vs(9), 100, _none(), ZetherTypes.TransferMode.HASH);
        bytes memory memo1 = bytes.concat(t.payload);
        memo1[memo1.length - 1] ^= 0x01;
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.zetherTransferCompact(memo1, t.proof, "", _none());
        bytes memory salt1 = bytes.concat(t.payload);
        salt1[70] ^= 0x01;
        // review T2 m2: the memo's clear salt must be the payload's, before the proof (and in the statement view)
        vm.expectRevert(IZetherToken.MemoSaltMismatch.selector);
        tok.zetherTransferCompact(salt1, t.proof, "", _none());
        vm.expectRevert(IZetherToken.MemoSaltMismatch.selector);
        stm.transferStatement(address(tok), salt1, _none(), ZetherTypes.TransferMode.HASH, 0);
        salt1[salt1.length - 97 + 6] ^= 0x01; // the same flip in the memo: the proof refuses it
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.zetherTransferCompact(salt1, t.proof, "", _none());
        bytes memory short = new bytes(t.payload.length - 1);
        for (uint256 i; i < short.length; ++i) short[i] = t.payload[i];
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadPayload.selector, short.length));
        tok.zetherTransferCompact(short, t.proof, "", _none());
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadPayload.selector, t.payload.length));
        tok.zetherTransfer(t.payload, t.proof, "", _none()); // a memo on the BUNDLE form
        tok.zetherTransferCompact(t.payload, t.proof, "", _none());
        assertTrue(_holds(tok, bob, 9, false));
    }

    // ------------------------------------------------------------------ mixed legs, the storage slot

    /// FULL refuses a mix (one leg left out) with `AuditorRequired`, NONE a mix (one leg with an auditor ciphertext) with
    /// `AuditorForbidden`, direct, relayed and in the statement view (OPTIONAL: `AuditorLegsMixed`, `ZetherMulti.t`).
    function test_mixedLegsByMode() public {
        uint256 p = ver.g1EncodedBytes();
        (dMode, aMode) = (BUNDLE, FULL);
        tok = _newToken(true, "mixFull", 0);
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        bytes memory pl = bytes.concat(_multiPayload(tok, alice, _two(), _vs(9), 7, tok.accountState(alice.ua)), _memo(2));
        for (uint256 i; i < p; ++i) pl[112 + 5 * p + i] = 0; // leg 1: C_aud = O, leg 2 ≠ O
        vm.expectRevert(IZetherToken.AuditorRequired.selector);
        tok.zetherTransferCompact(pl, "", "", _none());
        vm.expectRevert(IZetherToken.AuditorRequired.selector);
        stm.transferStatement(address(tok), pl, _none(), ZetherTypes.TransferMode.HASH, 0);
        (dMode, aMode) = (BUNDLE, NONE);
        tok = _newToken(false, "mixNone", 0);
        _fund(tok, alice, 500);
        tok.zetherRollOver(alice.ua);
        audForce = true;
        pl = _multiPayload(tok, alice, _two(), _vs(9), 7, tok.accountState(alice.ua));
        audForce = false;
        for (uint256 i; i < p; ++i) pl[112 + 5 * p + i] = 0;
        vm.expectRevert(IZetherToken.AuditorForbidden.selector);
        tok.zetherTransfer(pl, "", "", _none());
        vm.expectRevert(IZetherToken.AuditorForbidden.selector);
        stm.transferStatement(address(tok), pl, _none(), ZetherTypes.TransferMode.NONE, 0);
        uint256 pk = 0x9A7E5;
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: vm.addr(pk), data: abi.encodeCall(ZetherLayer.zetherTransferNoBundle, (pl, bytes(""), bytes(""), _none())),
            batch: 3, nonce: 0, validUntil: block.timestamp + 300, mode: MetaTxLib.MODE_RESTRICT_RELAYER, relayer: relayer,
            fee: 0, feeRecipient: address(0)
        });
        (uint8 v, bytes32 r, bytes32 s_) = vm.sign(pk, tok.mtxDigest(m));
        vm.prank(relayer);
        vm.expectRevert(IZetherToken.AuditorForbidden.selector);
        tok.mtxExecute(m, abi.encodePacked(r, s_, v));
    }

    /// M3 (review T2 m5): `disclosureMode` at byte 20 and `auditorMode` at byte 21 of the verifier's slot (`ns`), nothing
    /// above; the scale still at `ns + 1`.
    function test_modesPackedInTheVerifierSlot() public {
        (dMode, aMode) = (COMPACT, OPTIONAL);
        tok = _newToken(true, "pack", 0);
        bytes32 ns = 0xd1eef6cbeb7b383e0a92b3cb723053d5c39c76707d89da6b14ff91b83198ce00;
        uint256 w = uint256(vm.load(address(tok), ns));
        assertEq(address(uint160(w)), address(ver));
        assertEq((w >> 160) & 0xff, COMPACT, "disclosureMode, byte 20");
        assertEq((w >> 168) & 0xff, OPTIONAL, "auditorMode, byte 21");
        assertEq(w >> 176, 0);
        assertEq(uint256(vm.load(address(tok), bytes32(uint256(ns) + 1))), SCALE);
    }

    // ------------------------------------------------------------------ invalid configs (both kinds)

    /// `FULL` / `OPTIONAL` need a key, `NONE` refuses one, an unknown mode is refused (`BadAuditorMode`,
    /// `BadDisclosureMode`).
    function test_invalidModesRefused() public {
        IFactoryToken.TokenConfig[6] memory bad;
        (bad[0], bad[1], bad[2], bad[3], bad[4], bad[5]) =
            (_kindCfg(false), _kindCfg(false), _kindCfg(true), _kindCfg(false), _kindCfg(false), _kindCfg(true));
        bad[0].conf.auditorMode = FULL;
        bad[1].conf.auditorMode = OPTIONAL;
        bad[2].conf.auditorMode = NONE;
        bad[3].conf.disclosureMode = 2;
        bad[4].conf.auditorMode = 3;
        bad[5].conf.auditorMode = 3; // with a key: only the bound refuses it
        bytes[6] memory errs = [
            abi.encodeWithSelector(IZetherToken.BadAuditorMode.selector, FULL),
            abi.encodeWithSelector(IZetherToken.BadAuditorMode.selector, OPTIONAL),
            abi.encodeWithSelector(IZetherToken.BadAuditorMode.selector, NONE),
            abi.encodeWithSelector(IZetherToken.BadDisclosureMode.selector, uint8(2)),
            abi.encodeWithSelector(IZetherToken.BadAuditorMode.selector, uint8(3)),
            abi.encodeWithSelector(IZetherToken.BadAuditorMode.selector, uint8(3))
        ];
        for (uint256 i; i < bad.length; ++i) {
            vm.expectRevert(errs[i]);
            factory.createToken(_kind(), 1, bad[i], bytes32(i + 200));
        }
        IFactoryToken.TokenConfig memory ok = _kindCfg(true);
        ok.conf.auditorMode = FULL;
        ok.conf.disclosureMode = COMPACT;
        ZetherLayer t = ZetherLayer(factory.createToken(_kind(), 1, ok, "ok"));
        assertEq(uint8(t.auditorMode()), FULL);
        assertEq(uint8(t.disclosureMode()), COMPACT);
    }

    // ------------------------------------------------------------------ helpers

    function _two() internal view returns (User[] memory to) {
        to = new User[](2);
        (to[0], to[1]) = (bob, carol);
    }

    function _one() internal view returns (User[] memory to) {
        to = new User[](1);
        to[0] = bob;
    }

    /// @dev Bob gets `v`, carol is a decoy.
    function _vs(uint256 v) internal pure returns (uint256[] memory vs) {
        vs = new uint256[](2);
        vs[0] = v;
    }

    function _vs1(uint256 v) internal pure returns (uint256[] memory vs) {
        vs = new uint256[](1);
        vs[0] = v;
    }

    /// @dev A transfer proved for the stored form `mode`, sent through the entry `sel`.
    function _multi(ZetherTypes.TransferMode mode, bytes4 sel, uint256 v) internal returns (bytes32 ref, Tx memory t) {
        t = _proveMulti(tok, alice, _two(), _vs(v), bal, _none(), mode);
        (bool ok, bytes memory r) = address(tok).call(abi.encodeWithSelector(sel, t.payload, t.proof, bytes(""), _none()));
        if (!ok) assembly ("memory-safe") { revert(add(r, 32), mload(r)) }
        ref = abi.decode(r, (bytes32));
        bal -= v;
    }

    /// @dev What a sender rebuilds off chain from the salt, `s`, the values, the recipients' keys and the token's auditor
    ///      key: `R = salt ‖ B_1 ‖ … ‖ B_M`, `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j` (the client's `recoverTransfer`
    ///      does it from the memo and the registry's `keyOf`).
    function _rebuild(User[] memory to, uint256[] memory vs, uint256 s) internal view returns (bytes memory b) {
        bytes memory aud = _aud(tok);
        b = abi.encodePacked(salt);
        for (uint256 j; j < to.length; ++j) {
            (bytes memory cOut, bytes memory dOut,, bytes memory cAud) = prover.ciphertexts(ver, alice.y, to[j].y, aud, vs[j], s);
            b = bytes.concat(b, to[j].y, cOut, dOut, cAud);
        }
    }

    function _eventBundles(bytes32 ref) internal returns (bytes memory) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == IZetherToken.TransferBundles.selector && logs[i].topics[1] == ref) {
                return abi.decode(logs[i].data, (bytes));
            }
        }
        revert("no TransferBundles");
    }

    /// @dev The four openings of bob's leg (index 0); AUDITOR opens only with the auditor in.
    function _openAll(bytes32 ref, uint256 s, uint256 v, bytes memory bundles, bool audIn) internal view {
        bytes memory dOut = ver.g1MulBase(s);
        assertTrue(_vta(tok, ref, 0, v, S, abi.encode(s), bundles), "SENDER_S");
        assertFalse(_vta(tok, ref, 0, v + 1, S, abi.encode(s), bundles), "SENDER_S wrong amount");
        assertTrue(_vta(tok, ref, 0, v, RX, _cpOpening(tok, bob.x, ref, 0, v, RX, dOut), bundles), "RECEIVER_X");
        assertEq(_vta(tok, ref, 0, v, AUD, _cpOpening(tok, X_AUD, ref, 0, v, AUD, dOut), bundles), audIn, "AUDITOR");
        assertTrue(_vta(tok, ref, 0, v, CP, _cpOpening(tok, s, ref, 0, v, CP, bob.y), bundles), "SENDER_CP");
    }
}

contract ZetherModesNoneTest is ZetherModesSuite {
    function setUp() public {
        _stack(false);
        _users();
    }

    function _kind() internal pure override returns (IOpenFactory.TokenKind) {
        return IOpenFactory.TokenKind.NONE_ZETHER;
    }
}

/// @notice The same suite on BLS12-381 (review T2 m6): the 480-byte header and the modes end to end through a token.
contract ZetherModesBlsTest is ZetherModesSuite {
    function setUp() public {
        _stack(true);
        _users();
    }

    function _kind() internal pure override returns (IOpenFactory.TokenKind) {
        return IOpenFactory.TokenKind.NONE_ZETHER;
    }
}

contract ZetherModesUnderlyingTest is ZetherModesSuite {
    MockERC20 internal usd = new MockERC20("USD", "USD", 6);

    function setUp() public {
        _stack(false);
        UnderlyingZetherToken impl = new UnderlyingZetherToken(address(factory), address(0), ZUID, address(reg), dis, ver, burnVer);
        vm.prank(registrar);
        factory.registerImplementation(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, address(impl));
        _users();
    }

    function _kind() internal pure override returns (IOpenFactory.TokenKind) {
        return IOpenFactory.TokenKind.UNDERLYING_ZETHER;
    }

    /// @dev One USD leg 1:1, `PAYABLE` only.
    function _kindCfg(bool auditor) internal view override returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(auditor, uint256(1) << 40);
        c.features = 1 << AdminLib.PAYABLE;
        c.roles.minter = address(0);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
    }

    /// @dev Public units by a USD wrap.
    function _public(ZetherLayer t, address to, uint256 units) internal override {
        usd.mint(address(this), units);
        usd.approve(address(t), units);
        UnderlyingToken(payable(address(t))).wrap(address(usd), units);
        if (to != address(this)) t.transfer(to, units);
        minted[address(t)] += units;
    }
}
