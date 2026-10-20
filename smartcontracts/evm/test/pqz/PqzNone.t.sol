// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {PqzFixture} from "./helpers/PqzFixture.sol";
import {PQZ_UID, PQZL_ID} from "./helpers/PqzRegistryBase.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {PqzSafety} from "../../src/pqz/PqzSafety.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {NoUnderlyingPqzToken} from "../../src/pqz/NoUnderlyingPqzToken.sol";
import {Catalogue, pqzEnv} from "../helpers/Catalogue.sol";

/// A verifier that claims any precompile and proof system and says "supported" (review W-B).
contract FakePqzVerifier {
    address public immutable PRECOMPILE;
    bytes32 public immutable PROOF_SYSTEM_ID;

    constructor(address p, bytes32 id) {
        (PRECOMPILE, PROOF_SYSTEM_ID) = (p, id);
    }

    function isSupportedOnThisChain() external pure returns (bool) {
        return true;
    }
}

/// The `NONE_PQZ` token (P6g plan Task 5): life cycle, statements against the P6e vectors, every §7.4–§7.6 check,
/// entries and disclosure. The precompile is mocked (`PqzFixture`); the arithmetic, the registry and the token are real.
contract PqzNoneTest is PqzFixture {
    uint256 internal constant OUT_ON = 16_768;

    function setUp() public {
        _stack();
        tok = _newToken("pqz");
    }

    // ------------------------------------------------------------------ life cycle

    function _amt(PqzLayer t, bytes32 ua, uint64 i) internal view returns (uint256) {
        return (t.pqzPending(ua, i) >> 96) & type(uint64).max;
    }

    function test_lifecycle() public {
        _fund(tok, alice, 1000);
        assertEq(tok.balanceOf(address(this)), 0, "public units burnt");
        IPqzToken.AccountState memory a = tok.accountState(alice);
        assertEq(a.pendingCount, 1, "a TRIVIAL entry");
        assertEq(_amt(tok, alice, 0), 1000);
        assertEq(tok.pqzAcc(alice), new bytes(PqzCt.CT), "a new acc is Trivial(0)");
        assertEq(tok.totalShielded(), 1000);
        _assertConservation(tok);

        uint256 g = gasleft();
        (bytes32 ref, bytes memory out) = _transfer(tok, alice, bob, carol, 1, true);
        console2.log("pqzTransfer (BUNDLE, auditor, fee, 1 inline TRIVIAL, mocked proof) gas", g - gasleft());
        a = tok.accountState(alice);
        assertEq(tok.pqzAcc(alice), accOf[alice], "acc = u || v_f");
        assertEq(a.sendCounter, 1);
        assertEq(a.accUnits, 1);
        assertEq(a.rolled, 1);
        assertEq(tok.accountState(bob).pendingCount, 1);
        assertEq(tok.pqzPendingCt(bob, 0), _cut(out, 0, PqzCt.CT));
        assertEq(_amt(tok, carol, 0), FEE, "the fee: a TRIVIAL entry of the beneficiary");
        assertEq(ref, keccak256(abi.encode(keccak256("SCAAS-PQZ-ENTRY-V1"), block.chainid, PQZ_UID, address(tok), alice,
            uint256(0))), "entryRef");
        bytes memory r = bytes.concat(salt, _cut(out, 0, PqzCt.CT), _cut(out, 16_640, 128), bob);
        assertEq(tok.transferEntry(ref), r, "BUNDLE stores R");
        assertEq(tok.transferCiphertextHash(ref), keccak256(r));

        g = gasleft();
        _roll(tok, bob, 1);
        console2.log("pqzRollOver (1 credit, first after prepare) gas", g - gasleft());
        assertEq(tok.pqzAcc(bob), accOf[bob]);
        assertEq(tok.accountState(bob).accUnits, 1);
        _transfer(tok, bob, alice, bytes32(0), 2, false);
        assertEq(tok.accountState(alice).pendingCount, 2);
        _assertConservation(tok);

        // burn 100 from alice's pending credit (p = 2 ≥ rolled 1: one inline credit)
        bytes memory nb = _blob(9, PqzCt.CT);
        bytes memory pl = bytes.concat(abi.encode(uint256(2), block.number + 5, uint256(0), alice, carol), nb);
        g = gasleft();
        tok.pqzUnshield(pl, "", 100, address(0xD00D), hex"c0de", _mlAuth());
        console2.log("pqzUnshield (1 inline, fee, mocked proof) gas", g - gasleft());
        accOf[alice] = nb;
        assertEq(tok.balanceOf(address(0xD00D)), 100 * SCALE);
        assertEq(tok.totalShielded(), 900);
        assertEq(tok.accountState(carol).pendingCount, 2, "a later block: the fee appended");
        assertEq(_amt(tok, carol, 1), FEE);
        assertEq(tok.accountState(alice).rolled, 2);
        assertEq(tok.accountState(alice).sendCounter, 2);
        assertEq(tok.pqzAcc(alice), nb, "acc = the burn's blob");
        _assertConservation(tok);

        // refresh: amount 0, recipient 0
        bytes memory nr = _blob(10, PqzCt.CT);
        pl = bytes.concat(abi.encode(uint256(2), block.number + 5, uint256(0), alice, bytes32(0)), nr);
        tok.pqzUnshield(pl, "", 0, address(0), hex"c0de", _mlAuth());
        assertEq(tok.pqzAcc(alice), nr);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RefreshRecipient.selector, address(1)));
        tok.pqzUnshield(pl, "", 0, address(1), hex"c0de", _mlAuth());
        _assertConservation(tok);
    }

    // ------------------------------------------------------------------ statements against the vectors

    /// alice holds the vector's `Enc_F(1,000,000)` minus `Trivial(1000)` as `acc` (a credit, rolled from state) and tops
    /// up 1,000 with `shieldIn`: her transfer statement body is the vector's byte for byte; the header is §7.7 word by
    /// word (word 480 `shieldIn`); the precompile input is exactly `01 ‖ be32(83,072) ‖ stmt ‖ proof`.
    function test_transferStatementMatchesVector() public {
        bytes memory e = _subTrivial(_cut(txStmt, 49_792, PqzCt.CT), 1000);
        bytes memory carrier = bytes.concat(e, _blob(5, 256));
        bytes memory pl = _payload(0, 0, bob, alice, bytes32(0), carrier, "");
        tok.pqzTransferSingle(pl, "", hex"01", _mlAuth());
        pend[alice].push(e);
        _roll(tok, alice, 1);
        assertEq(tok.pqzAcc(alice), e);
        _public(tok, address(this), 1000 * SCALE);
        bytes memory out = _cut(txStmt, 66_304, OUT_ON);
        pl = _payload(1, 1000, alice, bob, carol, out, "");
        bytes memory st = tok.transferSingleStatement(pl, 0);
        assertEq(st.length, 83_072);
        assertEq(_cut(st, 640, 83_072 - 640), _cut(txStmt, 640, 83_072 - 640), "body = vector body");
        bytes memory head = bytes.concat(
            abi.encode(PqzCore.OP_TRANSFER, PQZL_ID, block.chainid, address(tok), address(reg), alice, bob, carol, FEE,
                uint256(0)),
            abi.encode(uint256(0), uint256(0), uint256(1), block.number + 100, uint256(1), uint256(1000), PQZ_UID,
                _direct(ZetherTypes.TransferMode.BUNDLE), uint256(uint128(salt)), bytes32(0))
        );
        assertEq(_cut(st, 0, 640), head, "header");
        bytes memory proof = hex"0102030405";
        vm.expectCall(PQZ, abi.encodePacked(uint8(1), uint32(83_072), st, proof));
        uint256 g = gasleft();
        tok.pqzTransferSingle(pl, "", proof, _mlAuth());
        console2.log("pqzTransfer of the vector statement (83,072 B, mocked proof) gas", g - gasleft());
        // the auth digest the registry saw is over this statement (a changed salt changes it, hence the proof)
        assertEq(tok.accountState(alice).sendCounter, 1);
        assertEq(tok.balanceOf(address(this)), 0, "shieldIn taken from the signer");
        _assertConservation(tok);
    }

    function test_burnStatementLayout() public {
        _fund(tok, alice, 50);
        bytes memory nb = _blob(11, PqzCt.CT);
        bytes memory pl = bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), alice, bytes32(0)), nb);
        bytes memory st = tok.burnStatement(pl, 7, address(0xD00D), keccak256("b"));
        assertEq(st.length, 50_048);
        assertEq(bytes32(_cut(st, 0, 32)), PqzCore.OP_BURN);
        assertEq(uint256(bytes32(_cut(st, 288, 32))), 7, "amount");
        assertEq(address(uint160(uint256(bytes32(_cut(st, 320, 32))))), address(0xD00D), "recipient");
        assertEq(bytes32(_cut(st, 544, 32)), keccak256("b"), "envelopeBinding");
        assertEq(_cut(st, 640, PqzCt.PK), _cut(txStmt, 640, PqzCt.PK), "pk_f");
        bytes memory t = new bytes(PqzCt.CT);
        assertEq(_cut(st, 17_024, PqzCt.CT), ct.sum(t, new bytes[](0), new bytes[](0), 50), "T = 0 + Trivial(50)");
        assertEq(_cut(st, 33_536, PqzCt.CT), nb, "u' || v_f");
        st = tok.burnStatement(pl, 0, address(0), 0);
        assertEq(bytes32(_cut(st, 0, 32)), PqzCore.OP_REFRESH);
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
        assertEq(tok.pqzPending(alice, 0), 0, "dead slots deleted");
        assertEq(tok.pqzAcc(alice), bytes.concat(_cut(out, 0, PqzCt.PK), _cut(out, PqzCt.CT, 128)));
    }

    /// Plan 5h D4: a debit at `p < rolled` un-rolls `[p, rolled)`; `acc` is the fresh `(u, v_f)` alone.
    function test_inlineBelowRolled() public {
        _credits(alice, 3);
        _roll(tok, alice, 3);
        // prove at p = 1 < rolled 3: T = acc − pending[1] − pending[2]; those two are pending again
        bytes memory out = _out(51, true);
        bytes memory pl = _payload(1, 0, alice, bob, bytes32(0), out, "");
        bytes[] memory inl = _range(alice, 1, 3);
        bytes memory st = tok.transferSingleStatement(pl, 0);
        bytes[] memory none = new bytes[](0);
        bytes memory t = ct.sum(_acc(alice), none, inl, 0);
        assertEq(_cut(st, 49_792, PqzCt.CT), t, "T = acc - inline");
        tok.pqzTransferSingle(pl, "", hex"01", _mlAuth());
        IPqzToken.AccountState memory a = tok.accountState(alice);
        assertEq(tok.pqzAcc(alice), bytes.concat(_cut(out, 0, PqzCt.PK), _cut(out, PqzCt.CT, 128)), "acc = (u, v_f)");
        assertEq(a.accUnits, 1);
        assertEq(a.rolled, 1, "un-rolled");
        assertEq(a.floor, 1);
        assertEq(a.cleared, 1);
        assertEq(tok.pqzPendingCt(alice, 2), pend[alice][2], "pending again");
        // a later debit below floor is refused
        pl = _payload(0, 0, alice, bob, bytes32(0), _out(52, true), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PendingRange.selector, 0, 1, 3));
        tok.pqzTransferSingle(pl, "", hex"01", _mlAuth());
    }

    function test_rollover() public {
        _credits(bob, 17);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollOverRange.selector, PqzCore.ROLL_MAX + 1));
        tok.pqzRollOver(bob, PqzCore.ROLL_MAX + 1);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollOverRange.selector, 0));
        tok.pqzRollOver(bob, 0);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccNotPrepared.selector, bob));
        tok.pqzRollOver(bob, 1);
        _prepare(tok, bob);
        vm.roll(block.number + ROLL_AGE);
        uint256 g = gasleft();
        _roll(tok, bob, 16);
        console2.log("pqzRollOver (16 credits, first materialisation after prepare) gas", g - gasleft());
        IPqzToken.AccountState memory a = tok.accountState(bob);
        assertEq(a.rolled, 16);
        assertEq(a.accUnits, 16);
        assertEq(a.accHash, keccak256(accOf[bob]));
        assertEq(tok.pqzAcc(bob), accOf[bob]);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollOverRange.selector, 2));
        tok.pqzRollOver(bob, 2);
    }

    // ------------------------------------------------------------------ the checks of §7.4

    function test_transferChecks() public {
        _credits(alice, 1);
        bytes memory out = _out(60, true);
        // expired
        bytes memory pl = bytes.concat(abi.encode(uint256(1), block.number - 1, 0, alice, bob, bytes32(0)), salt, out);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.Expired.selector, block.number - 1));
        tok.pqzTransferSingle(pl, "", hex"01", _mlAuth());
        // self, unregistered receiver and beneficiary
        vm.expectRevert(IPqzToken.SelfTransfer.selector);
        tok.pqzTransferSingle(_payload(1, 0, alice, alice, bytes32(0), out, ""), "", hex"01", _mlAuth());
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, bytes32(uint256(5))));
        tok.pqzTransferSingle(_payload(1, 0, alice, bytes32(uint256(5)), bytes32(0), out, ""), "", hex"01", _mlAuth());
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, bytes32(uint256(6))));
        tok.pqzTransferSingle(_payload(1, 0, alice, bob, bytes32(uint256(6)), out, ""), "", hex"01", _mlAuth());
        // shieldIn over the balance, range
        vm.expectRevert();
        tok.pqzTransferSingle(_payload(1, 1, alice, bob, bytes32(0), out, ""), "", hex"01", _mlAuth());
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PendingRange.selector, 2, 0, 1));
        tok.pqzTransferSingle(_payload(2, 0, alice, bob, bytes32(0), out, ""), "", hex"01", _mlAuth());
        // non-canonical out, bad length
        bytes memory nc = bytes.concat(out);
        nc[0] = 0xff;
        vm.expectRevert(IPqzToken.NonCanonical.selector);
        tok.pqzTransferSingle(_payload(1, 0, alice, bob, bytes32(0), nc, ""), "", hex"01", _mlAuth());
        pl = _payload(1, 0, alice, bob, bytes32(0), _cut(out, 0, 16_700), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, pl.length));
        tok.pqzTransferSingle(pl, "", hex"01", _mlAuth());
        // proof and authority
        pl = _payload(1, 0, alice, bob, bytes32(0), out, "");
        _mockOp(1, 0);
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.pqzTransferSingle(pl, "", hex"01", _mlAuth());
        _mockOp(1, 1);
        vm.expectRevert(IPqzToken.AuthRejected.selector);
        tok.pqzTransferSingle(pl, "", hex"01", abi.encode(bytes("x"), new bytes(3309)));
        vm.mockCall(ML65, bytes(""), abi.encode(uint256(0)));
        vm.expectRevert(IPqzToken.AuthRejected.selector);
        tok.pqzTransferSingle(pl, "", hex"01", _mlAuth());
        vm.mockCall(ML65, bytes(""), abi.encode(uint256(1)));
        bytes memory st = tok.transferSingleStatement(pl, 0);
        _mockOp(1, 0);
        vm.mockCall(PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, hex"01"), abi.encode(uint256(1)));
        tok.pqzTransferSingle(pl, "", hex"01", _mlAuth());
        // replay: the counter and the acc moved, so the statement differs and the proof fails
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.pqzTransferSingle(pl, "", hex"01", _mlAuth());
    }

    function test_inlineTooFar() public {
        _credits(alice, 17);
        bytes memory pl = _payload(17, 0, alice, bob, bytes32(0), _out(70, true), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.InlineTooFar.selector, 17));
        tok.pqzTransferSingle(pl, "", hex"01", _mlAuth());
        pl = _payload(16, 0, alice, bob, bytes32(0), _out(70, true), "");
        tok.pqzTransferSingle(pl, "", hex"01", _mlAuth());
        assertEq(tok.accountState(alice).rolled, 16);
    }

    // ------------------------------------------------------------------ modes (CTR-PQZ-23 / -24)

    function test_auditorModes() public {
        aMode = uint8(ZetherTypes.AuditorMode.FULL);
        PqzLayer full = _newToken("full");
        bytes memory off = _payload(0, 0, alice, bob, bytes32(0), _out(80, false), "");
        vm.expectRevert(IPqzToken.AuditorRequired.selector);
        full.pqzTransferSingle(off, "", hex"01", _mlAuth());
        aMode = uint8(ZetherTypes.AuditorMode.NONE);
        PqzLayer none = _newToken("none");
        bytes memory on = _payload(0, 0, alice, bob, bytes32(0), _out(81, true), "");
        vm.expectRevert(IPqzToken.AuditorForbidden.selector);
        none.pqzTransferSingle(on, "", hex"01", _mlAuth());
        bytes memory st = none.transferSingleStatement(off, 0);
        assertEq(st.length, 66_560, "R_TX0");
        assertEq(uint256(bytes32(_cut(st, 448, 32))), 0, "auditorOn 0");
        none.pqzTransferSingle(off, "", hex"01", _mlAuth());
        // OPTIONAL (the default token) takes both
        st = tok.transferSingleStatement(on, 0);
        assertEq(st.length, 83_072);
        assertEq(_cut(st, 33_408, PqzCt.PK), _cut(txStmt, 33_408, PqzCt.PK), "pk_a from the registry");
        // config refusals
        IFactoryToken.TokenConfig memory c = _cfg(1 << 40);
        c.conf.auditorMode = uint8(ZetherTypes.AuditorMode.FULL);
        c.conf.auditorKey = "";
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadAuditorMode.selector, 1));
        factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, abi.encode(c), "x1");
        c.conf.auditorKey = abi.encode(bytes32(uint256(9)));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, bytes32(uint256(9))));
        factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, abi.encode(c), "x2");
        c = _cfg((1 << 62) + 1);
        vm.expectRevert(IPqzToken.BadInit.selector);
        factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, abi.encode(c), "x3");
    }

    function test_compactAndNoBundle() public {
        dMode = uint8(ZetherTypes.DisclosureMode.COMPACT);
        PqzLayer cpt = _newToken("compact");
        bytes memory out = _out(90, true);
        bytes memory pl = _payload(0, 0, alice, bob, bytes32(0), out, "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.TransferEntryDisabled.selector, 1));
        cpt.pqzTransferSingleNoBundle(pl, "", hex"01", _mlAuth());
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, pl.length));
        cpt.pqzTransferSingle(pl, "", hex"01", _mlAuth()); // no memo
        bytes memory memo = _memo();
        bytes memory badMemo = bytes.concat(memo);
        badMemo[0] ^= 0x01;
        vm.expectRevert(IPqzToken.MemoSaltMismatch.selector);
        cpt.pqzTransferSingle(_payload(0, 0, alice, bob, bytes32(0), out, badMemo), "", hex"01", _mlAuth());
        pl = _payload(0, 0, alice, bob, bytes32(0), out, memo);
        bytes memory st = cpt.transferSingleStatement(pl, 0);
        assertEq(bytes32(_cut(st, 608, 32)), keccak256(memo), "memoHash");
        assertEq(bytes32(_cut(st, 544, 32)), _direct(ZetherTypes.TransferMode.HASH), "direct commit-reveal binding");
        bytes32 ref = cpt.pqzTransferSingle(pl, "", hex"01", _mlAuth());
        bytes memory r = bytes.concat(salt, _cut(out, 0, PqzCt.CT), _cut(out, 16_640, 128), bob);
        assertEq(cpt.transferEntry(ref), bytes.concat(keccak256(r), memo), "hash || memo");
        assertEq(cpt.transferCiphertextHash(ref), keccak256(r));
        // BUNDLE token: compact and no-bundle forms
        ref = tok.pqzTransferSingleNoBundle(pl = _payload(0, 0, alice, bob, bytes32(0), out, ""), "", hex"01", _mlAuth());
        assertEq(tok.transferCiphertextHash(ref), bytes32(0));
        ref = tok.pqzTransferSingleCompact(_payload(0, 0, alice, bob, bytes32(0), out, memo), "", hex"01", _mlAuth());
        assertEq(tok.transferCiphertextHash(ref), keccak256(r));
    }

    // ------------------------------------------------------------------ disclosure (§7.9, P6g D11)

    function test_disclosure() public {
        (bytes32 ref, bytes memory out) = _transfer(tok, alice, bob, bytes32(0), 95, true);
        bytes memory r = bytes.concat(salt, _cut(out, 0, PqzCt.CT), _cut(out, 16_640, 128), bob);
        bytes memory st = tok.disclosureStatement(ref, 0, 123, 1, r);
        assertEq(st.length, 33_184);
        assertEq(_cut(st, 0, 288), abi.encode(PqzCore.OP_DR, PQZL_ID, block.chainid, PQZ_UID, address(tok), address(reg),
            ref, uint256(123), uint256(1)));
        assertEq(_cut(st, 288, PqzCt.PK), _cut(txStmt, 17_024, PqzCt.PK), "pk_t (bob)");
        assertEq(_cut(st, 16_672, PqzCt.PK + 128), _cut(out, 0, PqzCt.CT), "u || v_t");
        st = tok.disclosureStatement(ref, 0, 123, 2, r);
        assertEq(_cut(st, 288, PqzCt.PK), _cut(txStmt, 33_408, PqzCt.PK), "pk_a");
        assertEq(_cut(st, 33_056, 128), _cut(out, 16_640, 128), "v_a");
        assertEq(bytes32(_cut(st, 0, 32)), PqzCore.OP_DA);
        bytes memory opening = abi.encode(r, hex"0a0b");
        vm.expectCall(PQZ, abi.encodePacked(uint8(5), uint32(33_184), st, hex"0a0b"));
        assertTrue(tok.verifyTransferAmount(ref, 0, 123, 2, opening));
        assertTrue(tok.verifyTransferAmount(ref, 0, 123, 0, opening), "SENDER_S (op 4)");
        _mockOp(5, 0);
        assertFalse(tok.verifyTransferAmount(ref, 0, 123, 1, opening), "the precompile says no");
        assertTrue(tok.verifyTransferAmount(ref, 0, 123, 0, opening));
        assertFalse(tok.verifyTransferAmount(ref, 0, 123, 3, opening), "SENDER_CP / unknown kind");
        assertFalse(tok.verifyTransferAmount(ref, 0, 1 << 64, 0, opening), "amount >= 2^64");
        assertFalse(tok.verifyTransferAmount(keccak256("x"), 0, 123, 0, opening), "unknown entry");
        bytes memory other = bytes.concat(r);
        other[20] ^= 0x01;
        assertFalse(tok.verifyTransferAmount(ref, 0, 123, 0, abi.encode(other, hex"0a0b")), "not the stored bundle");
        assertFalse(tok.verifyTransferAmount(ref, 0, 123, 0, bytes.concat(opening, bytes32(0))), "non-canonical opening");
    }

    // ------------------------------------------------------------------ the factory gate (P6g D1, D2)

    function test_factoryGate() public {
        bytes memory code = type(NoUnderlyingPqzToken).creationCode;
        vm.prank(registrar);
        (bool ok,) = address(factory).call(abi.encodeWithSelector(factory.deployImplementation.selector, uint8(6), 1, 1, code, ""));
        assertFalse(ok, "kind 6 (dropped, D21) fails ABI decoding");
        // an unregistered PQZ implementation cannot be cloned at all (owner 2026-10-19)
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.UnregisteredConfidentialKind.selector,
            IOpenFactory.TokenKind.NONE_PQZ));
        factory.createTokenUnregistered(IOpenFactory.TokenKind.NONE_PQZ, address(noneImpl), abi.encode(_cfg(1 << 40)), "g2");
        // the self-test failing now: the token's initialize refuses (plan 5g-Z2: the chain gates are the implementation's)
        vm.mockCall(PQZ, hex"0600000000", abi.encode(bytes32(0)));
        vm.expectRevert(abi.encodeWithSelector(PqzSafety.SelfTestFailed.selector, PQZ));
        factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, abi.encode(_cfg(1 << 40)), "g3");
        _mockSelfTest();
        // the factory's generic gate: the kind disabled
        vm.prank(registrar);
        factory.setKindEnabled(IOpenFactory.TokenKind.NONE_PQZ, false);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.KindDisabled.selector, IOpenFactory.TokenKind.NONE_PQZ));
        factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, abi.encode(_cfg(1 << 40)), "g4");
        assertEq(tok.kind(), 4);
        assertEq(tok.proofSystemId(), PQZL_ID);
        assertEq(tok.precompile(), PQZ);
    }

    /// Review 5g-Z2 P2-3: the release env (`deps = [UAPqzVerifier]` with code, never Hedera) is checked by the
    /// constructor, bubbled through `deployImplementation`.
    function test_constructorChecksTheEnv() public {
        bytes memory code = type(NoUnderlyingPqzToken).creationCode;
        IFactoryToken.Env[4] memory bad;
        for (uint256 i; i < bad.length; ++i) bad[i] = pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv));
        bad[0].deps = new address[](0);                                  // no verifier
        bad[1].deps = new address[](2);                                  // two
        (bad[1].deps[0], bad[1].deps[1]) = (address(pqv), address(pqv));
        bad[2].hedera = true;                                            // never on Hedera
        bad[3].deps[0] = address(0x1234);                                // a verifier without code
        for (uint256 i; i < bad.length; ++i) {
            uint16 ev = Catalogue.env(factory, IOpenFactory.TokenKind.NONE_PQZ, bad[i]);
            vm.prank(registrar);
            vm.expectRevert(IPqzToken.BadInit.selector);
            factory.deployImplementation(IOpenFactory.TokenKind.NONE_PQZ, 2, ev, code, "");
        }
    }

    /// Review 5g-Z2 P2-3 (controller proposal 2): the kind enabled, but on a chain outside PQZ's allowlist (22776, the
    /// mainnet) every `createToken` reverts with the implementation's gate.
    function test_createToken_enabledKindOnAForbiddenChain_reverts() public {
        assertTrue(factory.kindEnabled(IOpenFactory.TokenKind.NONE_PQZ));
        vm.chainId(22776);
        vm.expectRevert(abi.encodeWithSelector(PqzSafety.NotAllowedChain.selector, 22776));
        factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, abi.encode(_cfg(1 << 40)), "mainnet");
    }

    /// UA-6 (RF6): a registered `mldsa65` UA without a PQZ key is no PQZ account: as sender, leg, beneficiary,
    /// shield target and auditor alike (`AccountNotRegistered`).
    function test_keylessUAIsNoPqzAccount() public {
        bytes32 k = _mldsaUA(20);
        bytes memory out = _out(60, true);
        bytes memory err = abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, k);
        _credits(alice, 1);
        bytes memory pl = _payload(1, 0, alice, k, bytes32(0), out, "");
        vm.expectRevert(err); // recipient leg
        tok.pqzTransferSingle(pl, "", hex"01", _mlAuth());
        pl = _payload(1, 0, alice, bob, k, out, "");
        vm.expectRevert(err); // beneficiary
        tok.pqzTransferSingle(pl, "", hex"01", _mlAuth());
        pl = _payload(1, 0, k, bob, bytes32(0), out, "");
        vm.expectRevert(err); // sender
        tok.pqzTransferSingle(pl, "", hex"01", _mlAuth());
        _public(tok, address(this), SCALE);
        vm.expectRevert(err); // shield target
        tok.pqzShield(k, 1);
        IFactoryToken.TokenConfig memory c = _cfg(1 << 40);
        c.conf.auditorMode = uint8(ZetherTypes.AuditorMode.FULL);
        c.conf.auditorKey = abi.encode(k);
        vm.expectRevert(err); // auditor
        factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, abi.encode(c), "keyless");
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
        assertEq(_amt(tok, bob, 0), 10, "a TRIVIAL entry");
    }

    // ------------------------------------------------------------------ review 2026-10-19 (plan Task 5g)

    /// W-A: a direct transfer's statement names its mode (`envelopeBinding` word), so a front-runner cannot replay a
    /// BUNDLE call through `…NoBundle` (no entry stored) or the reverse: the proof and `authSig` are for one entry point.
    function test_directModeBound_single() public {
        bytes memory pl = _payload(0, 0, alice, bob, bytes32(0), _out(97, true), "");
        bytes memory st = tok.transferSingleStatement(pl, 0);
        assertEq(bytes32(_cut(st, 544, 32)), _direct(ZetherTypes.TransferMode.BUNDLE));
        bytes memory stN = tok.transferSingleStatement(pl, _direct(ZetherTypes.TransferMode.NONE));
        assertEq(bytes32(_cut(stN, 544, 32)), _direct(ZetherTypes.TransferMode.NONE));
        assertEq(_cut(stN, 0, 544), _cut(st, 0, 544));
        assertEq(_cut(stN, 576, st.length - 576), _cut(st, 576, st.length - 576), "only the binding differs");
        bytes memory proof = hex"b0b0";
        _mockOp(1, 0); // the precompile accepts exactly the BUNDLE statement with this proof
        vm.mockCall(PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, proof), abi.encode(uint256(1)));
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.pqzTransferSingleNoBundle(pl, "", proof, _mlAuth());
        bytes32 ref = tok.pqzTransferSingle(pl, "", proof, _mlAuth());
        assertTrue(tok.transferCiphertextHash(ref) != 0, "the bundle stored");
        // the reverse: a NoBundle proof does not pass as a BUNDLE call
        pl = _payload(0, 0, alice, bob, bytes32(0), _out(98, true), "");
        stN = tok.transferSingleStatement(pl, _direct(ZetherTypes.TransferMode.NONE));
        vm.mockCall(PQZ, abi.encodePacked(uint8(1), uint32(stN.length), stN, proof), abi.encode(uint256(1)));
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.pqzTransferSingle(pl, "", proof, _mlAuth());
        ref = tok.pqzTransferSingleNoBundle(pl, "", proof, _mlAuth());
        assertEq(tok.transferCiphertextHash(ref), bytes32(0));
    }

    /// W-B / CTR-ZTH-20: the verifier is the release env's (plan 5g-Z2); even an env whose registrar listed a fake
    /// verifier gets tokens whose verdicts come from `PqzSafety.PQZ` only, for PQZL or PQZH only, after the self-test
    /// (the init check is the second line).
    function test_initPinsThePrecompile() public {
        assertEq(factory.envOf(IOpenFactory.TokenKind.NONE_PQZ, 1).deps[0], address(pqv));
        address fake = address(0xFA4E);
        bytes32 other = keccak256("another proof system");
        address[3] memory pre = [fake, PQZ, PQZ];
        bytes32[3] memory ids = [PQZL_ID, other, PQZL_ID];
        for (uint256 i; i < 3; ++i) {
            address fv = address(new FakePqzVerifier(pre[i], ids[i]));
            OpenFactory g = new OpenFactory(registrar, PQZ_UID, 0);
            Catalogue.release(g, IOpenFactory.TokenKind.NONE_PQZ, 1, pqzEnv(address(g), PQZ_UID, address(reg), fv),
                type(NoUnderlyingPqzToken).creationCode);
            vm.prank(registrar);
            g.setKindEnabled(IOpenFactory.TokenKind.NONE_PQZ, true);
            if (i == 2) vm.mockCall(PQZ, hex"0600000000", abi.encode(bytes32(0))); // the real pair, self-test failing
            vm.expectRevert(i == 2 ? abi.encodeWithSelector(PqzSafety.SelfTestFailed.selector, PQZ)
                : abi.encodeWithSelector(PqzSafety.NotPqz.selector, pre[i], ids[i]));
            g.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, abi.encode(_cfg(1 << 40)), "w");
        }
        _mockSelfTest();
        assertEq(tok.precompile(), PQZ);
        assertEq(tok.verifier(), address(pqv), "the release's verifier");
        assertTrue(factory.isRegisteredToken(address(tok)));
    }

    // The W-E race tests (a debit on the base) live on as "a rollover between prove and submit still settles" in
    // PqzState.t.sol (plan 5h D6: the base is gone, `T` is read from state).

    /// W-I: an opening that does not decode reverts (as documented); a non-canonical one is false.
    function test_verifyTransferAmount_undecodableOpeningReverts() public {
        (bytes32 ref,) = _transfer(tok, alice, bob, bytes32(0), 95, true);
        vm.expectRevert();
        tok.verifyTransferAmount(ref, 0, 1, 0, hex"0102");
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
