// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {PqzFixture} from "./helpers/PqzFixture.sol";
import {PQZ_UID, PQZL_ID} from "./helpers/PqzRegistryBase.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzLib} from "../../src/pqz/PqzLib.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";

/// The `NONE_PQZ` token (P6g plan Task 5): life cycle, statements against the P6e vectors, every §7.4–§7.6 check,
/// entries and disclosure. The precompile is mocked (`PqzFixture`); the arithmetic, the registry and the token are real.
contract PqzNoneTest is PqzFixture {
    uint256 internal constant OUT_ON = 16_768;

    function setUp() public {
        _stack();
        tok = _newToken("pqz");
    }

    // ------------------------------------------------------------------ life cycle

    function test_lifecycle() public {
        _fund(tok, alice, 1000);
        assertEq(tok.balanceOf(address(this)), 0, "public units burnt");
        IPqzToken.AccountState memory a = tok.accountState(alice);
        assertEq(a.plainPending, 1000);
        assertEq(a.accHash, PqzCt.ZERO_HASH, "a new acc is Trivial(0)");
        assertEq(tok.totalShielded(), 1000);
        _assertConservation(tok);

        uint256 g = gasleft();
        (bytes32 ref, bytes memory out) = _transfer(tok, alice, bob, carol, 1, true);
        console2.log("pqzTransfer (BUNDLE, auditor, fee, mocked proof) gas", g - gasleft());
        a = tok.accountState(alice);
        assertEq(a.accHash, keccak256(accOf[alice]), "acc = u || v_f");
        assertEq(a.plainPending, 0);
        assertEq(a.sendCounter, 1);
        assertEq(a.accUnits, 1);
        assertEq(tok.accountState(bob).pendingCount, 1);
        assertEq(tok.pendingHash(bob, 0), keccak256(_cut(out, 0, PqzCt.CT)));
        assertEq(tok.accountState(carol).plainPending, FEE);
        assertEq(ref, keccak256(abi.encode(keccak256("SCAAS-PQZ-ENTRY-V1"), block.chainid, PQZ_UID, address(tok), alice,
            uint256(0))), "entryRef");
        bytes memory r = bytes.concat(salt, _cut(out, 0, PqzCt.CT), _cut(out, 16_640, 128), bob);
        assertEq(tok.transferEntry(ref), r, "BUNDLE stores R");
        assertEq(tok.transferCiphertextHash(ref), keccak256(r));

        g = gasleft();
        _roll(tok, bob, 1);
        console2.log("pqzRollOver (1 credit) gas", g - gasleft());
        assertEq(tok.accountState(bob).accHash, keccak256(accOf[bob]));
        assertEq(tok.accountState(bob).accUnits, 1);
        _transfer(tok, bob, alice, bytes32(0), 2, false);
        assertEq(tok.accountState(alice).pendingCount, 1);
        _assertConservation(tok);

        // burn 100 from alice's pending credit (p = 1 ≥ rolled 0: one inline credit)
        bytes memory nb = _blob(9, PqzCt.CT);
        bytes memory pl = bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), alice, carol), nb);
        bytes[] memory inl = _inline(tok, alice, 1);
        assertEq(inl.length, 1);
        g = gasleft();
        tok.pqzUnshield(pl, _acc(alice), inl, 100, address(0xD00D), hex"c0de", _mlAuth());
        console2.log("pqzUnshield (1 inline, fee, mocked proof) gas", g - gasleft());
        accOf[alice] = nb;
        assertEq(tok.balanceOf(address(0xD00D)), 100 * SCALE);
        assertEq(tok.totalShielded(), 900);
        assertEq(tok.accountState(carol).plainPending, 2 * FEE);
        assertEq(tok.accountState(alice).rolled, 1);
        assertEq(tok.accountState(alice).sendCounter, 2);
        _assertConservation(tok);

        // refresh: amount 0, recipient 0
        bytes memory nr = _blob(10, PqzCt.CT);
        pl = bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), alice, bytes32(0)), nr);
        tok.pqzUnshield(pl, _acc(alice), new bytes[](0), 0, address(0), hex"c0de", _mlAuth());
        assertEq(tok.accountState(alice).accHash, keccak256(nr));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RefreshRecipient.selector, address(1)));
        tok.pqzUnshield(pl, _acc(alice), new bytes[](0), 0, address(1), hex"c0de", _mlAuth());
        _assertConservation(tok);
    }

    // ------------------------------------------------------------------ statements against the vectors

    /// alice holds the vector's `Enc_F(1,000,000)` as `acc` and 1,000 plain: her transfer statement body is the vector's
    /// byte for byte; the header is §7.7 word by word; the precompile input is exactly `01 ‖ be32(83,072) ‖ stmt ‖ proof`.
    function test_transferStatementMatchesVector() public {
        bytes memory e = _subTrivial(_cut(txStmt, 49_792, PqzCt.CT), 1000);
        bytes memory carrier = bytes.concat(e, _blob(5, 256));
        bytes memory pl = _payload(0, 0, bob, alice, bytes32(0), carrier, "");
        tok.pqzTransfer(pl, _acc(bob), new bytes[](0), hex"01", _mlAuth());
        pend[alice].push(e);
        _roll(tok, alice, 1);
        _fund(tok, alice, 1000);
        bytes memory out = _cut(txStmt, 66_304, OUT_ON);
        pl = _payload(1, 1000, alice, bob, carol, out, "");
        bytes memory st = tok.transferStatement(pl, _acc(alice), new bytes[](0), 0);
        assertEq(st.length, 83_072);
        assertEq(_cut(st, 640, 83_072 - 640), _cut(txStmt, 640, 83_072 - 640), "body = vector body");
        bytes memory head = bytes.concat(
            abi.encode(PqzLib.OP_TRANSFER, PQZL_ID, block.chainid, address(tok), address(reg), alice, bob, carol, FEE,
                uint256(0)),
            abi.encode(uint256(0), uint256(0), uint256(1), block.number + 100, uint256(1), uint256(1000), PQZ_UID,
                bytes32(0), uint256(uint128(salt)), bytes32(0))
        );
        assertEq(_cut(st, 0, 640), head, "header");
        bytes memory proof = hex"0102030405";
        vm.expectCall(PQZ, abi.encodePacked(uint8(1), uint32(83_072), st, proof));
        uint256 g = gasleft();
        tok.pqzTransfer(pl, _acc(alice), new bytes[](0), proof, _mlAuth());
        console2.log("pqzTransfer of the vector statement (83,072 B, mocked proof) gas", g - gasleft());
        // the auth digest the registry saw is over this statement (a changed salt changes it, hence the proof)
        assertEq(tok.accountState(alice).sendCounter, 1);
    }

    function test_burnStatementLayout() public {
        _fund(tok, alice, 50);
        bytes memory nb = _blob(11, PqzCt.CT);
        bytes memory pl = bytes.concat(abi.encode(uint256(0), block.number + 5, uint256(50), alice, bytes32(0)), nb);
        bytes memory st = tok.burnStatement(pl, _acc(alice), new bytes[](0), 7, address(0xD00D), keccak256("b"));
        assertEq(st.length, 50_048);
        assertEq(bytes32(_cut(st, 0, 32)), PqzLib.OP_BURN);
        assertEq(uint256(bytes32(_cut(st, 288, 32))), 7, "amount");
        assertEq(address(uint160(uint256(bytes32(_cut(st, 320, 32))))), address(0xD00D), "recipient");
        assertEq(bytes32(_cut(st, 544, 32)), keccak256("b"), "envelopeBinding");
        assertEq(_cut(st, 640, PqzCt.PK), _cut(txStmt, 640, PqzCt.PK), "pk_f");
        bytes memory t = new bytes(PqzCt.CT);
        assertEq(_cut(st, 17_024, PqzCt.CT), ct.sum(t, new bytes[](0), new bytes[](0), 50), "T = 0 + Trivial(50)");
        assertEq(_cut(st, 33_536, PqzCt.CT), nb, "u' || v_f");
        st = tok.burnStatement(pl, _acc(alice), new bytes[](0), 0, address(0), 0);
        assertEq(bytes32(_cut(st, 0, 32)), PqzLib.OP_REFRESH);
    }

    // ------------------------------------------------------------------ inline credits on both sides of `rolled`

    function _credits(bytes32 ua, uint256 n) internal {
        for (uint256 i; i < n; ++i) _transfer(tok, carol, ua, bytes32(0), 100 + i, false);
    }

    function test_inlineAboveRolled() public {
        _credits(alice, 3);
        (, bytes memory out) = _transfer(tok, alice, bob, bytes32(0), 50, true); // p = 3, inline = pending[0..3)
        IPqzToken.AccountState memory a = tok.accountState(alice);
        assertEq(a.rolled, 3);
        assertEq(a.floor, 3);
        assertEq(a.cleared, 3);
        assertEq(a.accUnits, 1);
        assertEq(tok.pendingHash(alice, 0), bytes32(0), "dead slots deleted");
        assertEq(a.accHash, keccak256(bytes.concat(_cut(out, 0, PqzCt.PK), _cut(out, PqzCt.CT, 128))));
    }

    function test_inlineBelowRolled() public {
        _credits(alice, 3);
        _roll(tok, alice, 3);
        // prove at p = 1 < rolled 3: T = acc − pending[1] − pending[2]; those two stay inside the new acc
        bytes memory out = _out(51, true);
        bytes memory pl = _payload(1, 0, alice, bob, bytes32(0), out, "");
        bytes[] memory inl = _inline(tok, alice, 1);
        assertEq(inl.length, 2);
        bytes memory st = tok.transferStatement(pl, _acc(alice), inl, 0);
        bytes[] memory none = new bytes[](0);
        bytes memory t = ct.sum(_acc(alice), none, inl, 0);
        assertEq(_cut(st, 49_792, PqzCt.CT), t, "T = acc - inline");
        tok.pqzTransfer(pl, _acc(alice), inl, hex"01", _mlAuth());
        IPqzToken.AccountState memory a = tok.accountState(alice);
        bytes memory kept = ct.sum(bytes.concat(_cut(out, 0, PqzCt.PK), _cut(out, PqzCt.CT, 128)), inl, none, 0);
        assertEq(a.accHash, keccak256(kept), "acc = (u, v_f) + kept credits");
        assertEq(a.accUnits, 3);
        assertEq(a.rolled, 3);
        assertEq(a.floor, 1);
        assertEq(a.cleared, 1);
        // a later debit below floor is refused
        pl = _payload(0, 0, alice, bob, bytes32(0), _out(52, true), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PendingRange.selector, 0, 1, 3));
        tok.pqzTransfer(pl, kept, new bytes[](0), hex"01", _mlAuth());
    }

    function test_rollover() public {
        _credits(bob, 17);
        bytes[] memory cts = new bytes[](17);
        for (uint256 i; i < 17; ++i) cts[i] = pend[bob][i];
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollOverRange.selector, 17));
        tok.pqzRollOver(bob, _acc(bob), cts);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollOverRange.selector, 0));
        tok.pqzRollOver(bob, _acc(bob), new bytes[](0));
        bytes[] memory two = new bytes[](2);
        (two[0], two[1]) = (pend[bob][1], pend[bob][0]);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.InlineMismatch.selector, 0));
        tok.pqzRollOver(bob, _acc(bob), two);
        vm.expectRevert(IPqzToken.AccMismatch.selector);
        tok.pqzRollOver(bob, _blob(1, PqzCt.CT), two);
        uint256 g = gasleft();
        _roll(tok, bob, 16);
        console2.log("pqzRollOver (16 credits) gas", g - gasleft());
        IPqzToken.AccountState memory a = tok.accountState(bob);
        assertEq(a.rolled, 16);
        assertEq(a.accUnits, 16);
        assertEq(a.accHash, keccak256(accOf[bob]));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollOverRange.selector, 2));
        tok.pqzRollOver(bob, _acc(bob), two);
    }

    // ------------------------------------------------------------------ the checks of §7.4

    function test_transferChecks() public {
        _credits(alice, 1);
        bytes memory out = _out(60, true);
        bytes memory accA = _acc(alice);
        bytes[] memory one = _inline(tok, alice, 1);
        bytes[] memory none = new bytes[](0);
        // expired
        bytes memory pl = bytes.concat(abi.encode(uint256(1), block.number - 1, 0, alice, bob, bytes32(0)), salt, out);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.Expired.selector, block.number - 1));
        tok.pqzTransfer(pl, accA, one, hex"01", _mlAuth());
        // self, unregistered receiver and beneficiary
        vm.expectRevert(IPqzToken.SelfTransfer.selector);
        tok.pqzTransfer(_payload(1, 0, alice, alice, bytes32(0), out, ""), accA, one, hex"01", _mlAuth());
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, bytes32(uint256(5))));
        tok.pqzTransfer(_payload(1, 0, alice, bytes32(uint256(5)), bytes32(0), out, ""), accA, one, hex"01", _mlAuth());
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, bytes32(uint256(6))));
        tok.pqzTransfer(_payload(1, 0, alice, bob, bytes32(uint256(6)), out, ""), accA, one, hex"01", _mlAuth());
        // plain overdraw, acc mismatch, range
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PlainOverdraw.selector, 1, 0));
        tok.pqzTransfer(_payload(1, 1, alice, bob, bytes32(0), out, ""), accA, one, hex"01", _mlAuth());
        vm.expectRevert(IPqzToken.AccMismatch.selector);
        tok.pqzTransfer(_payload(1, 0, alice, bob, bytes32(0), out, ""), _blob(3, PqzCt.CT), one, hex"01", _mlAuth());
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PendingRange.selector, 2, 0, 1));
        tok.pqzTransfer(_payload(2, 0, alice, bob, bytes32(0), out, ""), accA, one, hex"01", _mlAuth());
        // inline: missing, extra, wrong
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.InlineMismatch.selector, 0));
        tok.pqzTransfer(_payload(1, 0, alice, bob, bytes32(0), out, ""), accA, none, hex"01", _mlAuth());
        bytes[] memory two = new bytes[](2);
        (two[0], two[1]) = (one[0], one[0]);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.InlineMismatch.selector, 2));
        tok.pqzTransfer(_payload(1, 0, alice, bob, bytes32(0), out, ""), accA, two, hex"01", _mlAuth());
        bytes[] memory bad = new bytes[](1);
        bad[0] = _blob(4, PqzCt.CT);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.InlineMismatch.selector, 0));
        tok.pqzTransfer(_payload(1, 0, alice, bob, bytes32(0), out, ""), accA, bad, hex"01", _mlAuth());
        // non-canonical out, bad length
        bytes memory nc = bytes.concat(out);
        nc[0] = 0xff;
        vm.expectRevert(IPqzToken.NonCanonical.selector);
        tok.pqzTransfer(_payload(1, 0, alice, bob, bytes32(0), nc, ""), accA, one, hex"01", _mlAuth());
        pl = _payload(1, 0, alice, bob, bytes32(0), _cut(out, 0, 16_700), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, pl.length));
        tok.pqzTransfer(pl, accA, one, hex"01", _mlAuth());
        // proof and authority
        pl = _payload(1, 0, alice, bob, bytes32(0), out, "");
        _mockOp(1, 0);
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.pqzTransfer(pl, accA, one, hex"01", _mlAuth());
        _mockOp(1, 1);
        vm.expectRevert(IPqzToken.AuthRejected.selector);
        tok.pqzTransfer(pl, accA, one, hex"01", abi.encode(bytes("x"), new bytes(3309)));
        vm.mockCall(ML65, bytes(""), abi.encode(uint256(0)));
        vm.expectRevert(IPqzToken.AuthRejected.selector);
        tok.pqzTransfer(pl, accA, one, hex"01", _mlAuth());
        vm.mockCall(ML65, bytes(""), abi.encode(uint256(1)));
        tok.pqzTransfer(pl, accA, one, hex"01", _mlAuth());
        // replay: the counter moved, the acc changed
        vm.expectRevert(IPqzToken.AccMismatch.selector);
        tok.pqzTransfer(pl, accA, one, hex"01", _mlAuth());
    }

    function test_inlineTooFarAndCreditCap() public {
        _credits(alice, 17);
        bytes memory pl = _payload(17, 0, alice, bob, bytes32(0), _out(70, true), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.InlineTooFar.selector, 17));
        tok.pqzTransfer(pl, _acc(alice), new bytes[](0), hex"01", _mlAuth());
        // the receiver's cap: accUnits + unrolled + 2 > K_MAX ⇒ RefreshRequired (accUnits written directly)
        bytes32 slot = bytes32(uint256(keccak256(abi.encode(bob, uint256(0xda865ec17214f25b93cdb133d719c79392c290a4b9089fd0bba156256c521500) + 8))) + 1);
        vm.store(address(tok), slot, bytes32(uint256(1023)));
        assertEq(tok.accountState(bob).accUnits, 1023);
        bytes memory pc = _payloadFor(tok, carol, bob, bytes32(0), _out(71, false));
        bytes memory accC = _acc(carol);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RefreshRequired.selector, bob));
        tok.pqzTransfer(pc, accC, new bytes[](0), hex"01", _mlAuth());
        vm.store(address(tok), slot, bytes32(uint256(1022))); // 1022 + 0 + 2 = K_MAX: still allowed
        _transfer(tok, carol, bob, bytes32(0), 72, false);
    }

    // ------------------------------------------------------------------ modes (CTR-PQZ-23 / -24)

    function test_auditorModes() public {
        aMode = uint8(ZetherTypes.AuditorMode.FULL);
        PqzLayer full = _newToken("full");
        bytes memory off = _payload(0, 0, alice, bob, bytes32(0), _out(80, false), "");
        vm.expectRevert(IPqzToken.AuditorRequired.selector);
        full.pqzTransfer(off, _acc(alice), new bytes[](0), hex"01", _mlAuth());
        aMode = uint8(ZetherTypes.AuditorMode.NONE);
        PqzLayer none = _newToken("none");
        bytes memory on = _payload(0, 0, alice, bob, bytes32(0), _out(81, true), "");
        vm.expectRevert(IPqzToken.AuditorForbidden.selector);
        none.pqzTransfer(on, _acc(alice), new bytes[](0), hex"01", _mlAuth());
        bytes memory st = none.transferStatement(off, _acc(alice), new bytes[](0), 0);
        assertEq(st.length, 66_560, "R_TX0");
        assertEq(uint256(bytes32(_cut(st, 448, 32))), 0, "auditorOn 0");
        none.pqzTransfer(off, _acc(alice), new bytes[](0), hex"01", _mlAuth());
        // OPTIONAL (the default token) takes both
        st = tok.transferStatement(on, _acc(alice), new bytes[](0), 0);
        assertEq(st.length, 83_072);
        assertEq(_cut(st, 33_408, PqzCt.PK), _cut(txStmt, 33_408, PqzCt.PK), "pk_a from the registry");
        // config refusals
        IFactoryToken.TokenConfig memory c = _cfg(1 << 40);
        c.conf.auditorMode = uint8(ZetherTypes.AuditorMode.FULL);
        c.conf.auditorKey = "";
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadAuditorMode.selector, 1));
        factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, c, "x1");
        c.conf.auditorKey = abi.encode(bytes32(uint256(9)));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, bytes32(uint256(9))));
        factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, c, "x2");
        c = _cfg((1 << 62) + 1);
        vm.expectRevert(IPqzToken.BadInit.selector);
        factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, c, "x3");
    }

    function test_compactAndNoBundle() public {
        dMode = uint8(ZetherTypes.DisclosureMode.COMPACT);
        PqzLayer cpt = _newToken("compact");
        bytes memory out = _out(90, true);
        bytes memory pl = _payload(0, 0, alice, bob, bytes32(0), out, "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.TransferEntryDisabled.selector, 1));
        cpt.pqzTransferNoBundle(pl, _acc(alice), new bytes[](0), hex"01", _mlAuth());
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, pl.length));
        cpt.pqzTransfer(pl, _acc(alice), new bytes[](0), hex"01", _mlAuth()); // no memo
        bytes memory memo = _memo();
        bytes memory badMemo = bytes.concat(memo);
        badMemo[0] ^= 0x01;
        vm.expectRevert(IPqzToken.MemoSaltMismatch.selector);
        cpt.pqzTransfer(_payload(0, 0, alice, bob, bytes32(0), out, badMemo), _acc(alice), new bytes[](0), hex"01", _mlAuth());
        pl = _payload(0, 0, alice, bob, bytes32(0), out, memo);
        bytes memory st = cpt.transferStatement(pl, _acc(alice), new bytes[](0), 0);
        assertEq(bytes32(_cut(st, 608, 32)), keccak256(memo), "memoHash");
        bytes32 ref = cpt.pqzTransfer(pl, _acc(alice), new bytes[](0), hex"01", _mlAuth());
        bytes memory r = bytes.concat(salt, _cut(out, 0, PqzCt.CT), _cut(out, 16_640, 128), bob);
        assertEq(cpt.transferEntry(ref), bytes.concat(keccak256(r), memo), "hash || memo");
        assertEq(cpt.transferCiphertextHash(ref), keccak256(r));
        // BUNDLE token: compact and no-bundle forms
        ref = tok.pqzTransferNoBundle(pl = _payload(0, 0, alice, bob, bytes32(0), out, ""), _acc(alice), new bytes[](0),
            hex"01", _mlAuth());
        assertEq(tok.transferCiphertextHash(ref), bytes32(0));
        accOf[alice] = bytes.concat(_cut(out, 0, PqzCt.PK), _cut(out, PqzCt.CT, 128));
        ref = tok.pqzTransferCompact(_payload(0, 0, alice, bob, bytes32(0), out, memo), _acc(alice), new bytes[](0),
            hex"01", _mlAuth());
        assertEq(tok.transferCiphertextHash(ref), keccak256(r));
    }

    // ------------------------------------------------------------------ disclosure (§7.9, P6g D11)

    function test_disclosure() public {
        (bytes32 ref, bytes memory out) = _transfer(tok, alice, bob, bytes32(0), 95, true);
        bytes memory r = bytes.concat(salt, _cut(out, 0, PqzCt.CT), _cut(out, 16_640, 128), bob);
        bytes memory st = tok.disclosureStatement(ref, 123, 1, r);
        assertEq(st.length, 33_184);
        assertEq(_cut(st, 0, 288), abi.encode(PqzLib.OP_DR, PQZL_ID, block.chainid, PQZ_UID, address(tok), address(reg),
            ref, uint256(123), uint256(1)));
        assertEq(_cut(st, 288, PqzCt.PK), _cut(txStmt, 17_024, PqzCt.PK), "pk_t (bob)");
        assertEq(_cut(st, 16_672, PqzCt.PK + 128), _cut(out, 0, PqzCt.CT), "u || v_t");
        st = tok.disclosureStatement(ref, 123, 2, r);
        assertEq(_cut(st, 288, PqzCt.PK), _cut(txStmt, 33_408, PqzCt.PK), "pk_a");
        assertEq(_cut(st, 33_056, 128), _cut(out, 16_640, 128), "v_a");
        assertEq(bytes32(_cut(st, 0, 32)), PqzLib.OP_DA);
        bytes memory opening = abi.encode(r, hex"0a0b");
        vm.expectCall(PQZ, abi.encodePacked(uint8(5), uint32(33_184), st, hex"0a0b"));
        assertTrue(tok.verifyTransferAmount(ref, 123, 2, opening));
        assertTrue(tok.verifyTransferAmount(ref, 123, 0, opening), "SENDER_S (op 4)");
        _mockOp(5, 0);
        assertFalse(tok.verifyTransferAmount(ref, 123, 1, opening), "the precompile says no");
        assertTrue(tok.verifyTransferAmount(ref, 123, 0, opening));
        assertFalse(tok.verifyTransferAmount(ref, 123, 3, opening), "SENDER_CP / unknown kind");
        assertFalse(tok.verifyTransferAmount(ref, 1 << 64, 0, opening), "amount >= 2^64");
        assertFalse(tok.verifyTransferAmount(keccak256("x"), 123, 0, opening), "unknown entry");
        bytes memory other = bytes.concat(r);
        other[20] ^= 0x01;
        assertFalse(tok.verifyTransferAmount(ref, 123, 0, abi.encode(other, hex"0a0b")), "not the stored bundle");
        assertFalse(tok.verifyTransferAmount(ref, 123, 0, bytes.concat(opening, bytes32(0))), "non-canonical opening");
    }

    // ------------------------------------------------------------------ the factory gate (P6g D1, D2)

    function test_factoryGate() public {
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.KindReserved.selector, IOpenFactory.TokenKind.NONE_ZETHER_PQZ));
        factory.registerImplementation(IOpenFactory.TokenKind.NONE_ZETHER_PQZ, 1, address(noneImpl));
        IFactoryToken.TokenConfig memory c = _cfg(1 << 40);
        c.conf.verifier = address(0);
        vm.expectRevert(IOpenFactory.VerifierRequiredForPqz.selector);
        factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, c, "g1");
        c.conf.verifier = address(reg);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.PqzVerifierUnsupported.selector, address(reg)));
        factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, c, "g2");
        // the self-test failing now: refused at creation and at setPqzEnabled(true)
        vm.mockCall(PQZ, hex"0600000000", abi.encode(bytes32(0)));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.PqzVerifierUnsupported.selector, address(pqv)));
        factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, _cfg(1 << 40), "g3");
        vm.prank(registrar);
        vm.expectRevert();
        factory.setPqzEnabled(true);
        vm.prank(registrar);
        factory.setPqzEnabled(false);
        vm.expectRevert(IOpenFactory.PqzDisabled.selector);
        factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, _cfg(1 << 40), "g4");
        assertEq(tok.kind(), 4);
        assertEq(tok.proofSystemId(), PQZL_ID);
        assertEq(tok.precompile(), PQZ);
    }

    function test_shieldChecks() public {
        _public(tok, address(this), 10 * SCALE);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, bytes32(uint256(1))));
        tok.pqzShield(bytes32(uint256(1)), 1);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AmountOutOfRange.selector, 0, (uint256(1) << 40)));
        tok.pqzShield(alice, 0);
        bytes memory err = abi.encodeWithSignature("ERC20InsufficientBalance(address,uint256,uint256)", address(this),
            10 * SCALE, 11 * SCALE);
        vm.expectRevert(err);
        tok.pqzShield(alice, 11);
        uint256 g = gasleft();
        tok.pqzShield(bob, 10);
        console2.log("pqzShield gas", g - gasleft());
        assertEq(tok.accountState(bob).plainPending, 10);
    }

    // ------------------------------------------------------------------ helpers

    /// `− Trivial(m)`: v[i] −= Δ·digit_i mod q.
    function _subTrivial(bytes memory c, uint256 m) internal pure returns (bytes memory r) {
        r = bytes.concat(c);
        for (uint256 i; i < 16; ++i) {
            uint256 o = PqzCt.PK + 8 * i;
            uint256 x;
            for (uint256 k; k < 8; ++k) x = (x << 8) | uint8(r[o + k]);
            x = (x + PqzCt.Q - (PqzCt.DELTA * ((m >> (4 * i)) & 15)) % PqzCt.Q) % PqzCt.Q;
            for (uint256 k; k < 8; ++k) r[o + k] = bytes1(uint8(x >> (8 * (7 - k))));
        }
    }
}
