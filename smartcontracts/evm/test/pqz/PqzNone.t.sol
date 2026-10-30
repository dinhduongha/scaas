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
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {UAPqzVerifier} from "../../src/pqz/UAPqzVerifier.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {NoUnderlyingPqzToken} from "../../src/pqz/NoUnderlyingPqzToken.sol";
import {Catalogue, pqzEnv} from "../helpers/Catalogue.sol";
import {SigCheck} from "../../src/common/SigCheck.sol";

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
    uint256 internal constant OUT_ON = PqzCore.OUT_ON;

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
        assertEq(tok.balanceOf(address(this)), 0, "public units moved to the pool");
        IPqzToken.AccountState memory a = tok.pqzAccount(alice);
        assertEq(a.pendingCount, 1, "a TRIVIAL entry");
        assertEq(_amt(tok, alice, 0), 1000);
        assertEq(tok.pqzAcc(alice), new bytes(PqzCt.CT), "a new acc is Trivial(0)");
        assertEq(tok.totalShielded(), 1000);
        _assertConservation(tok);

        uint256 g = gasleft();
        (bytes32 ref, bytes memory out) = _transfer(tok, alice, bob, carol, 1, true);
        console2.log("mtxConfidentialTransfer (BUNDLE, auditor, fee, 1 inline TRIVIAL, mocked proof) gas", g - gasleft());
        a = tok.pqzAccount(alice);
        assertEq(tok.pqzAcc(alice), accOf[alice], "acc = u || v_f");
        assertEq(a.sendCounter, 1);
        assertEq(a.accUnits, 1);
        assertEq(a.rolled, 1);
        assertEq(tok.pqzAccount(bob).pendingCount, 1);
        assertEq(tok.pqzPendingCt(bob, 0), _cut(out, 0, PqzCt.CT));
        assertEq(tok.balanceOfUA(carol), FEE * SCALE, "txFee: the beneficiary's public balance (D19)");
        assertEq(tok.pqzAccount(carol).pendingCount, 0, "no TRIVIAL fee entry");
        assertEq(ref, keccak256(abi.encode(keccak256("SCAAS-PQZ-ENTRY-V1"), block.chainid, PQZ_UID, address(tok), alice,
            uint256(0))), "entryRef");
        bytes memory r = _rOf(out, bob);
        assertEq(tok.transferEntry(ref), r, "BUNDLE stores R");
        assertEq(tok.transferCiphertextHash(ref), keccak256(r));

        g = gasleft();
        _roll(tok, bob, 1);
        console2.log("mtxRollOver (1 credit, first after prepare) gas", g - gasleft());
        assertEq(tok.pqzAcc(bob), accOf[bob]);
        assertEq(tok.pqzAccount(bob).accUnits, 1);
        _transfer(tok, bob, alice, bytes32(0), 2, false);
        assertEq(tok.pqzAccount(alice).pendingCount, 2);
        _assertConservation(tok);

        // burn 100 from alice's pending credit (p = 2 ≥ rolled 1: one inline credit)
        bytes memory nb = _blob(9, PqzCt.CT);
        bytes memory pl = bytes.concat(abi.encode(uint256(2), block.number + 5, uint256(0), alice, carol), nb);
        g = gasleft();
        tok.mtxUnshield(pl, hex"c0de", _mlAuth(), _benM(pl), "", 100, bytes32(uint256(uint160(address(0xD00D)))));
        console2.log("mtxUnshield (1 inline, fee, mocked proof) gas", g - gasleft());
        accOf[alice] = nb;
        assertEq(tok.balanceOf(address(0xD00D)), 100 * SCALE);
        assertEq(tok.totalShielded(), 900 - 2 * FEE, "the burn and both fees left the pool");
        assertEq(tok.balanceOfUA(carol), 2 * FEE * SCALE, "the burn's txFee too");
        assertEq(tok.pqzAccount(alice).rolled, 2);
        assertEq(tok.pqzAccount(alice).sendCounter, 2);
        assertEq(tok.pqzAcc(alice), nb, "acc = the burn's blob");
        _assertConservation(tok);

        // refresh: amount 0, recipient 0
        bytes memory nr = _blob(10, PqzCt.CT);
        pl = bytes.concat(abi.encode(uint256(2), block.number + 5, uint256(0), alice, bytes32(0)), nr);
        tok.mtxUnshield(pl, hex"c0de", _mlAuth(), _benM(pl), "", 0, bytes32(0));
        assertEq(tok.pqzAcc(alice), nr);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RefreshRecipient.selector, address(1)));
        tok.mtxUnshield(pl, hex"c0de", _mlAuth(), _benM(pl), "", 0, bytes32(uint256(uint160(address(1)))));
        _assertConservation(tok);
    }

    // ------------------------------------------------------------------ statements against the vectors

    /// alice holds the vector's `Enc_F(1,000,000)` minus `Trivial(1000)` as `acc` (a credit, rolled from state) and tops
    /// up 1,000 with `shieldIn`: her transfer statement body is the vector's byte for byte; the header is §7.7 word by
    /// word (word 480 `shieldIn`); the precompile input is exactly `01 ‖ be32(83,072) ‖ stmt ‖ proof`.
    function test_transferStatementMatchesVector() public {
        bytes memory e = _subTrivial(_cut(txStmt, O_T, PqzCt.CT), 1000);
        bytes memory carrier = bytes.concat(e, _blob(5, 256));
        bytes memory pl = _payload(0, 0, bob, alice, bytes32(0), carrier, "");
        tok.mtxConfidentialTransferSingle(pl, hex"01", _mlAuth(), _benT(pl), "");
        pend[alice].push(e);
        _roll(tok, alice, 1);
        assertEq(tok.pqzAcc(alice), e);
        _public(tok, address(this), 1000 * SCALE);
        bytes memory out = _cut(txStmt, O_OUT, OUT_ON);
        pl = _payload(1, 1000, alice, bob, carol, out, "");
        bytes memory st = tok.transferSingleStatement(pl, 0);
        assertEq(st.length, ST_TX);
        assertEq(_cut(st, 640, ST_TX - 640), _cut(txStmt, 640, ST_TX - 640), "body = vector body");
        bytes memory head = bytes.concat(
            abi.encode(PqzCore.OP_TRANSFER, PQZL_ID, block.chainid, address(tok), address(reg), alice, bob, carol, FEE,
                uint256(0)),
            abi.encode(uint256(0), uint256(0), uint256(1), block.number + 100, uint256(1), uint256(1000), PQZ_UID,
                _direct(ZetherTypes.TransferMode.BUNDLE), uint256(uint128(salt)), bytes32(0))
        );
        assertEq(_cut(st, 0, 640), head, "header");
        bytes memory proof = hex"0102030405";
        vm.expectCall(PQZ, abi.encodePacked(uint8(1), uint32(ST_TX), st, proof));
        uint256 g = gasleft();
        tok.mtxConfidentialTransferSingle(pl, proof, _mlAuth(), _benT(pl), "");
        console2.log("mtxConfidentialTransfer of the vector statement (83,072 B, mocked proof) gas", g - gasleft());
        // the auth digest the registry saw is over this statement (a changed salt changes it, hence the proof)
        assertEq(tok.pqzAccount(alice).sendCounter, 1);
        assertEq(tok.balanceOf(address(this)), 0, "shieldIn taken from the signer");
        _assertConservation(tok);
    }

    function test_burnStatementLayout() public {
        _fund(tok, alice, 50);
        bytes memory nb = _blob(11, PqzCt.CT);
        bytes memory pl = bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), alice, bytes32(0)), nb);
        bytes memory st = tok.burnStatement(pl, 7, bytes32(uint256(uint160(address(0xD00D)))), keccak256("b"));
        assertEq(st.length, ST_BURN);
        assertEq(bytes32(_cut(st, 0, 32)), PqzCore.OP_BURN);
        assertEq(uint256(bytes32(_cut(st, 288, 32))), 7, "amount");
        assertEq(address(uint160(uint256(bytes32(_cut(st, 320, 32))))), address(0xD00D), "recipient");
        assertEq(bytes32(_cut(st, 544, 32)), keccak256("b"), "envelopeBinding");
        assertEq(_cut(st, 640, PqzCt.PK), _cut(txStmt, 640, PqzCt.PK), "pk_f");
        bytes memory t = new bytes(PqzCt.CT);
        assertEq(_cut(st, O_PK1, PqzCt.CT), ct.sum(t, new bytes[](0), new bytes[](0), 50), "T = 0 + Trivial(50)");
        assertEq(_cut(st, O_BOUT, PqzCt.CT), nb, "u' || v_f");
        st = tok.burnStatement(pl, 0, bytes32(0), 0);
        assertEq(bytes32(_cut(st, 0, 32)), PqzCore.OP_REFRESH);
    }

    // ------------------------------------------------------------------ inline credits on both sides of `rolled`

    function _credits(bytes32 ua, uint256 n) internal {
        for (uint256 i; i < n; ++i) _transfer(tok, carol, ua, bytes32(0), 100 + i, false);
    }

    function test_inlineAboveRolled() public {
        _credits(alice, 3);
        (, bytes memory out) = _transfer(tok, alice, bob, bytes32(0), 50, true); // p = 3, inline = pending[0..3)
        IPqzToken.AccountState memory a = tok.pqzAccount(alice);
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
        assertEq(_cut(st, O_T, PqzCt.CT), t, "T = acc - inline");
        tok.mtxConfidentialTransferSingle(pl, hex"01", _mlAuth(), _benT(pl), "");
        IPqzToken.AccountState memory a = tok.pqzAccount(alice);
        assertEq(tok.pqzAcc(alice), bytes.concat(_cut(out, 0, PqzCt.PK), _cut(out, PqzCt.CT, 128)), "acc = (u, v_f)");
        assertEq(a.accUnits, 1);
        assertEq(a.rolled, 1, "un-rolled");
        assertEq(a.floor, 1);
        assertEq(a.cleared, 1);
        assertEq(tok.pqzPendingCt(alice, 2), pend[alice][2], "pending again");
        // a later debit below floor is refused
        pl = _payload(0, 0, alice, bob, bytes32(0), _out(52, true), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PendingRange.selector, 0, 1, 3));
        tok.mtxConfidentialTransferSingle(pl, hex"01", _mlAuth(), _benT(pl), "");
    }

    function test_rollover() public {
        _credits(bob, 17);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollOverRange.selector, PqzCore.ROLL_MAX + 1));
        tok.mtxRollOver(bob, PqzCore.ROLL_MAX + 1);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollOverRange.selector, 0));
        tok.mtxRollOver(bob, 0);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccNotPrepared.selector, bob));
        tok.mtxRollOver(bob, 1);
        _prepare(tok, bob);
        vm.roll(block.number + ROLL_AGE);
        uint256 g = gasleft();
        _roll(tok, bob, 16);
        console2.log("mtxRollOver (16 credits, first materialisation after prepare) gas", g - gasleft());
        IPqzToken.AccountState memory a = tok.pqzAccount(bob);
        assertEq(a.rolled, 16);
        assertEq(a.accUnits, 16);
        assertEq(a.accHash, keccak256(_packed(accOf[bob])), "accHash: the packed acc (P46)");
        assertEq(tok.pqzAcc(bob), accOf[bob]);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollOverRange.selector, 2));
        tok.mtxRollOver(bob, 2);
    }

    // ------------------------------------------------------------------ the checks of §7.4

    function test_transferChecks() public {
        _credits(alice, 1);
        bytes memory out = _out(60, true);
        // expired
        bytes memory pl = bytes.concat(abi.encode(uint256(1), block.number - 1, 0, alice, bob, bytes32(0)), salt, out);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.Expired.selector, block.number - 1));
        tok.mtxConfidentialTransferSingle(pl, hex"01", _mlAuth(), _benT(pl), "");
        // self, unregistered receiver and beneficiary
        vm.expectRevert(IPqzToken.SelfTransfer.selector);
        tok.mtxConfidentialTransferSingle(_payload(1, 0, alice, alice, bytes32(0), out, ""), hex"01", _mlAuth(), bytes32(0), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, bytes32(uint256(5))));
        tok.mtxConfidentialTransferSingle(_payload(1, 0, alice, bytes32(uint256(5)), bytes32(0), out, ""), hex"01", _mlAuth(), bytes32(0), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, bytes32(uint256(6))));
        tok.mtxConfidentialTransferSingle(_payload(1, 0, alice, bob, bytes32(uint256(6)), out, ""), hex"01", _mlAuth(), bytes32(uint256(6)), "");
        // shieldIn over the balance, range
        vm.expectRevert();
        tok.mtxConfidentialTransferSingle(_payload(1, 1, alice, bob, bytes32(0), out, ""), hex"01", _mlAuth(), bytes32(0), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PendingRange.selector, 2, 0, 1));
        tok.mtxConfidentialTransferSingle(_payload(2, 0, alice, bob, bytes32(0), out, ""), hex"01", _mlAuth(), bytes32(0), "");
        // non-canonical out, bad length
        bytes memory nc = bytes.concat(out);
        nc[0] = 0xff;
        vm.expectRevert(IPqzToken.NonCanonical.selector);
        tok.mtxConfidentialTransferSingle(_payload(1, 0, alice, bob, bytes32(0), nc, ""), hex"01", _mlAuth(), bytes32(0), "");
        pl = _payload(1, 0, alice, bob, bytes32(0), _cut(out, 0, 16_700), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, pl.length));
        tok.mtxConfidentialTransferSingle(pl, hex"01", _mlAuth(), _benT(pl), "");
        // proof and authority
        pl = _payload(1, 0, alice, bob, bytes32(0), out, "");
        _mockOp(1, 0);
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.mtxConfidentialTransferSingle(pl, hex"01", _mlAuth(), _benT(pl), "");
        _mockOp(1, 1);
        vm.expectRevert(IPqzToken.AuthRejected.selector);
        tok.mtxConfidentialTransferSingle(pl, hex"01", abi.encode(bytes("x"), new bytes(3309)), _benT(pl), "");
        vm.mockCall(ML65, bytes(""), abi.encode(uint256(0)));
        vm.expectRevert(IPqzToken.AuthRejected.selector);
        tok.mtxConfidentialTransferSingle(pl, hex"01", _mlAuth(), _benT(pl), "");
        vm.mockCall(ML65, bytes(""), abi.encode(uint256(1)));
        bytes memory st = tok.transferSingleStatement(pl, 0);
        _mockOp(1, 0);
        vm.mockCall(PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, hex"01"), abi.encode(uint256(1)));
        tok.mtxConfidentialTransferSingle(pl, hex"01", _mlAuth(), _benT(pl), "");
        // replay: the counter and the acc moved, so the statement differs and the proof fails
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.mtxConfidentialTransferSingle(pl, hex"01", _mlAuth(), _benT(pl), "");
    }

    function test_inlineTooFar() public {
        _credits(alice, 17);
        bytes memory pl = _payload(17, 0, alice, bob, bytes32(0), _out(70, true), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.InlineTooFar.selector, 17));
        tok.mtxConfidentialTransferSingle(pl, hex"01", _mlAuth(), _benT(pl), "");
        pl = _payload(16, 0, alice, bob, bytes32(0), _out(70, true), "");
        tok.mtxConfidentialTransferSingle(pl, hex"01", _mlAuth(), _benT(pl), "");
        assertEq(tok.pqzAccount(alice).rolled, 16);
    }

    // ------------------------------------------------------------------ modes (CTR-PQZ-23 / -24)

    function test_auditorModes() public {
        aMode = uint8(ZetherTypes.AuditorMode.FULL);
        PqzLayer full = _newToken("full");
        bytes memory off = _payload(0, 0, alice, bob, bytes32(0), _out(80, false), "");
        vm.expectRevert(IPqzToken.AuditorRequired.selector);
        full.mtxConfidentialTransferSingle(off, hex"01", _mlAuth(), _benT(off), "");
        aMode = uint8(ZetherTypes.AuditorMode.NONE);
        PqzLayer none = _newToken("none");
        bytes memory on = _payload(0, 0, alice, bob, bytes32(0), _out(81, true), "");
        vm.expectRevert(IPqzToken.AuditorForbidden.selector);
        none.mtxConfidentialTransferSingle(on, hex"01", _mlAuth(), _benT(on), "");
        bytes memory st = none.transferSingleStatement(off, 0);
        assertEq(st.length, ST_TX0, "R_TX0");
        assertEq(uint256(bytes32(_cut(st, 448, 32))), 0, "auditorOn 0");
        none.mtxConfidentialTransferSingle(off, hex"01", _mlAuth(), _benT(off), "");
        // OPTIONAL (the default token) takes both
        st = tok.transferSingleStatement(on, 0);
        assertEq(st.length, ST_TX);
        assertEq(_cut(st, O_PK2, PqzCt.PK), _cut(txStmt, O_PK2, PqzCt.PK), "pk_a from the registry");
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

    /// D11: NONE retired; a COMPACT entry is the op blob plus the memo (no stored hash): `transferEntry` =
    /// `keccak256(R) ‖ memo`, `transferCiphertextHash` = `keccak256(R)`, `pqzEntryBlob` = `R ‖ v_f` (`R`, `v_f` packed, P46).
    function test_compactAndNoneRetired() public {
        dMode = uint8(ZetherTypes.DisclosureMode.COMPACT);
        PqzLayer cpt = _newToken("compact");
        bytes memory out = _out(90, true);
        bytes memory pl = _payload(0, 0, alice, bob, bytes32(0), out, "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, pl.length));
        cpt.mtxConfidentialTransferSingle(pl, hex"01", _mlAuth(), _benT(pl), ""); // no memo
        bytes memory memo = _memo();
        bytes memory badMemo = bytes.concat(memo);
        badMemo[0] ^= 0x01;
        vm.expectRevert(IPqzToken.MemoSaltMismatch.selector);
        cpt.mtxConfidentialTransferSingle(_payload(0, 0, alice, bob, bytes32(0), out, badMemo), hex"01", _mlAuth(), bytes32(0), "");
        pl = _payload(0, 0, alice, bob, bytes32(0), out, memo);
        bytes memory st = cpt.transferSingleStatement(pl, 0);
        assertEq(bytes32(_cut(st, 608, 32)), keccak256(memo), "memoHash");
        assertEq(bytes32(_cut(st, 544, 32)), _direct(ZetherTypes.TransferMode.HASH), "direct commit-reveal binding");
        bytes32 ref = cpt.mtxConfidentialTransferSingle(pl, hex"01", _mlAuth(), _benT(pl), "");
        bytes memory r = _rOf(out, bob);
        assertEq(cpt.transferEntry(ref), bytes.concat(keccak256(r), memo), "hash || memo");
        assertEq(cpt.transferCiphertextHash(ref), keccak256(r));
        assertEq(cpt.pqzEntryBlob(ref), bytes.concat(r, _packed(_cut(out, PqzCt.CT, 128))), "the op blob: R || P(v_f)");
        // disclosure of a COMPACT entry reads R from the blob: no bundle argument
        assertEq(_cut(cpt.disclosureStatement(ref, 0, 5, 1), O_DU, PqzCt.CT), _cut(out, 0, PqzCt.CT), "u || v_t");
        // BUNDLE token: the commit-reveal form, same hash
        ref = tok.mtxConfidentialTransferSingleCompact(_payload(0, 0, alice, bob, bytes32(0), out, memo), hex"01", _mlAuth(), bytes32(0), "");
        assertEq(tok.transferCiphertextHash(ref), keccak256(r));
        // the NONE entry points are gone
        bytes memory d = abi.encodeWithSignature("mtxConfidentialTransferSingleNoBundle(bytes,bytes,bytes,bytes32,bytes)",
            _payload(1, 0, alice, bob, bytes32(0), out, ""), hex"01", _mlAuth(), bytes32(0), bytes(""));
        (bool ok,) = address(tok).call(d);
        assertFalse(ok, "no single no-bundle entry on PQZ");
        (ok,) = address(tok).call(abi.encodeWithSignature("mtxConfidentialTransferNoBundle(bytes,bytes,bytes,bytes32,bytes)",
            bytes(""), bytes(""), bytes(""), bytes32(0), bytes("")));
        assertFalse(ok, "mtxConfidentialTransferNoBundle is Zether-only (PQZ NONE retired)");
        assertEq(tok.pqzEntryBlob(keccak256("unknown")), "", "no entry: empty");
    }

    // ------------------------------------------------------------------ disclosure (§7.9, P6g D11)

    /// Disclosure reads `R` from the op blob (D11): `disclosureStatement(ref, leg, amount, kind)`, the opening is the
    /// proof alone.
    function test_disclosure() public {
        (bytes32 ref, bytes memory out) = _transfer(tok, alice, bob, bytes32(0), 95, true);
        bytes memory st = tok.disclosureStatement(ref, 0, 123, 1);
        assertEq(st.length, ST_DISC);
        assertEq(_cut(st, 0, 288), abi.encode(PqzCore.OP_DR, PQZL_ID, block.chainid, PQZ_UID, address(tok), address(reg),
            ref, uint256(123), uint256(1)));
        assertEq(_cut(st, 288, PqzCt.PK), _cut(txStmt, O_PK1, PqzCt.PK), "pk_t (bob)");
        assertEq(_cut(st, O_DU, PqzCt.PK + 128), _cut(out, 0, PqzCt.CT), "u || v_t");
        st = tok.disclosureStatement(ref, 0, 123, 2);
        assertEq(_cut(st, 288, PqzCt.PK), _cut(txStmt, O_PK2, PqzCt.PK), "pk_a");
        assertEq(_cut(st, O_DV, 128), _cut(out, PqzCore.OUT_OFF, 128), "v_a");
        assertEq(bytes32(_cut(st, 0, 32)), PqzCore.OP_DA);
        bytes memory proof = hex"0a0b";
        vm.expectCall(PQZ, abi.encodePacked(uint8(5), uint32(ST_DISC), st, proof));
        assertTrue(tok.verifyTransferAmount(ref, 0, 123, 2, proof));
        assertTrue(tok.verifyTransferAmount(ref, 0, 123, 0, proof), "SENDER_S (op 4)");
        _mockOp(5, 0);
        assertFalse(tok.verifyTransferAmount(ref, 0, 123, 1, proof), "the precompile says no");
        assertTrue(tok.verifyTransferAmount(ref, 0, 123, 0, proof));
        assertFalse(tok.verifyTransferAmount(ref, 0, 123, 3, proof), "SENDER_CP / unknown kind");
        assertFalse(tok.verifyTransferAmount(ref, 0, 1 << 64, 0, proof), "amount >= 2^64");
        assertFalse(tok.verifyTransferAmount(keccak256("x"), 0, 123, 0, proof), "unknown entry");
        assertFalse(tok.verifyTransferAmount(ref, 0, 123, 0, ""), "empty proof");
        assertFalse(tok.verifyTransferAmount(ref, 1, 123, 0, proof), "no leg 1");
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

    /// Plan 5h Task 8d part 2 (D23 [Z2]): a new `UAPqzVerifier` (a new set or id) reaches tokens only through the next
    /// `Env` version of the kind and a new release on it; tokens of the old release keep their verifier, the old release
    /// keeps its env, and the new release's tokens run on the new instance.
    function test_newVerifierNewEnvNewRelease() public {
        UAPqzVerifier old = pqv;
        UAPqzVerifier fresh = _newPqzVerifier(PQZL_ID);
        assertTrue(address(fresh) != address(old));
        uint16 v1 = factory.latestEnvVersion(IOpenFactory.TokenKind.NONE_PQZ);
        address impl2 = Catalogue.release(factory, IOpenFactory.TokenKind.NONE_PQZ, 2,
            pqzEnv(address(factory), PQZ_UID, address(reg), address(fresh)), type(NoUnderlyingPqzToken).creationCode);
        assertEq(factory.latestEnvVersion(IOpenFactory.TokenKind.NONE_PQZ), v1 + 1, "the next env version");
        assertEq(factory.releaseOf(IOpenFactory.TokenKind.NONE_PQZ, 2).envVersion, v1 + 1);
        assertEq(factory.releaseOf(IOpenFactory.TokenKind.NONE_PQZ, 1).envVersion, v1, "release 1 keeps its env");
        PqzLayer t2 = PqzLayer(factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 2, abi.encode(_cfg(1 << 40)), "r2"));
        assertEq(t2.verifier(), address(fresh));
        assertEq(NoUnderlyingPqzToken(impl2).verifier(), address(fresh));
        assertEq(tok.verifier(), address(old), "release 1's tokens keep theirs");
        assertEq(t2.proofSystemId(), PqzSet.PQZL_ID);
        _fund(t2, alice, 10);
        _transfer(t2, alice, bob, bytes32(0), 1, true);
        assertEq(t2.pqzAccount(bob).pendingCount, 1, "the new release works");
    }

    /// Review 5g-Z2 P2-3: the release env (`deps = [UAPqzVerifier]` with code, never Hedera) is checked by the
    /// constructor, bubbled through `deployImplementation`.
    function test_constructorChecksTheEnv() public {
        bytes memory code = type(NoUnderlyingPqzToken).creationCode;
        IFactoryToken.Env[6] memory bad;
        for (uint256 i; i < bad.length; ++i) bad[i] = pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv));
        // owner ruling 2026-10-30 (D5): an EIP-7702 designator is not a dependency, even one delegating to the real one
        (address dVer, address dReg) = (address(0xD7702), address(0xD7703));
        vm.etch(dVer, abi.encodePacked(hex"ef0100", address(pqv)));
        vm.etch(dReg, abi.encodePacked(hex"ef0100", address(reg)));
        bad[4].deps[0] = dVer;                                           // a designator verifier
        bad[5].registry = dReg;                                          // a designator registry
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

    /// UA-6 (RF6): a registered `mldsa65` UA without a PQZ key is no PQZ account: as sender, leg,
    /// shield target and auditor alike (`AccountNotRegistered`); not as the fee beneficiary, which needs only a registered
    /// UA (C0-7, owner 2026-10-27: `PqzGuards.t.sol` test_beneficiary_anyRegisteredUA).
    function test_keylessUAIsNoPqzAccount() public {
        bytes32 k = _mldsaUA(20);
        bytes memory out = _out(60, true);
        bytes memory err = abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, k);
        _credits(alice, 1);
        bytes memory pl = _payload(1, 0, alice, k, bytes32(0), out, "");
        vm.expectRevert(err); // recipient leg
        tok.mtxConfidentialTransferSingle(pl, hex"01", _mlAuth(), _benT(pl), "");
        pl = _payload(1, 0, k, bob, bytes32(0), out, "");
        vm.expectRevert(err); // sender
        tok.mtxConfidentialTransferSingle(pl, hex"01", _mlAuth(), _benT(pl), "");
        _public(tok, address(this), SCALE);
        vm.expectRevert(err); // shield target
        tok.mtxShield(k, 1);
        IFactoryToken.TokenConfig memory c = _cfg(1 << 40);
        c.conf.auditorMode = uint8(ZetherTypes.AuditorMode.FULL);
        c.conf.auditorKey = abi.encode(k);
        vm.expectRevert(err); // auditor
        factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, abi.encode(c), "keyless");
    }

    /// Owner ruling 2026-10-30 (D2): a holder with an EIP-7702 designator (a sweeper's code calling as it) cannot shield
    /// its public units away.
    function test_shield_delegatedCallerRefused() public {
        address v = address(0xD7702);
        _public(tok, v, 10 * SCALE);
        vm.etch(v, abi.encodePacked(hex"ef0100", address(this)));
        vm.prank(v);
        vm.expectRevert(abi.encodeWithSelector(SigCheck.CallerDelegated.selector, v));
        tok.mtxShield(alice, 1);
        assertEq(tok.balanceOf(v), 10 * SCALE);
    }

    /// no7702 review m1: the submitter of a UA-authorised PQZ op is an open role (CTR-UA-24, D3); only a `shieldIn` pull
    /// makes it authority (its own public units move). A relayer with an EIP-7702 designator submits a transfer with
    /// `shieldIn = 0`; with a pull it is refused `CallerDelegated`.
    function test_transfer_delegatedSubmitterOnlyRefusedOnAPull() public {
        _fund(tok, alice, 1000);
        address r = address(0xD7702);
        _public(tok, r, 10 * SCALE);
        vm.etch(r, abi.encodePacked(hex"ef0100", address(this)));
        bytes memory out = _out(61, false);
        bytes memory auth = _mlAuth();
        bytes memory pl = _payload(1, 1, alice, bob, bytes32(0), out, "");
        bytes32 ben = _benT(pl);
        vm.prank(r);
        vm.expectRevert(abi.encodeWithSelector(SigCheck.CallerDelegated.selector, r));
        tok.mtxConfidentialTransferSingle(pl, hex"01", auth, ben, "");
        pl = _payloadFor(tok, alice, bob, bytes32(0), out);
        ben = _benT(pl);
        vm.prank(r);
        tok.mtxConfidentialTransferSingle(pl, hex"01", auth, ben, "");
        assertEq(tok.pqzAccount(alice).sendCounter, 1);
        assertEq(tok.balanceOf(r), 10 * SCALE, "nothing pulled from the relayer");
    }

    function test_shieldChecks() public {
        _public(tok, address(this), 10 * SCALE);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, bytes32(uint256(1))));
        tok.mtxShield(bytes32(uint256(1)), 1);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AmountOutOfRange.selector, 0, (uint256(1) << 40)));
        tok.mtxShield(alice, 0);
        bytes memory err = abi.encodeWithSignature("ERC20InsufficientBalance(address,uint256,uint256)", address(this),
            10 * SCALE, 11 * SCALE);
        vm.expectRevert(err);
        tok.mtxShield(alice, 11);
        uint256 g = gasleft();
        tok.mtxShield(bob, 10);
        console2.log("mtxShield gas", g - gasleft());
        assertEq(_amt(tok, bob, 0), 10, "a TRIVIAL entry");
    }

    // ------------------------------------------------------------------ review 2026-10-19 (plan Task 5g)

    /// W-A: a direct transfer's statement names its mode (`envelopeBinding` word): a proof bound to another mode (a
    /// retired `…NoBundle` one) does not pass as a BUNDLE call.
    function test_directModeBound_single() public {
        bytes memory pl = _payload(0, 0, alice, bob, bytes32(0), _out(97, true), "");
        bytes memory st = tok.transferSingleStatement(pl, 0);
        assertEq(bytes32(_cut(st, 544, 32)), _direct(ZetherTypes.TransferMode.BUNDLE));
        bytes memory stN = tok.transferSingleStatement(pl, 0);
        bytes32 nb = _direct(ZetherTypes.TransferMode.HASH);
        assembly ("memory-safe") { mstore(add(stN, 576), nb) } // word 544: another mode's binding
        bytes memory proof = hex"b0b0";
        _mockOp(1, 0); // the precompile accepts exactly the other mode's statement
        vm.mockCall(PQZ, abi.encodePacked(uint8(1), uint32(stN.length), stN, proof), abi.encode(uint256(1)));
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.mtxConfidentialTransferSingle(pl, proof, _mlAuth(), _benT(pl), "");
        vm.mockCall(PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, proof), abi.encode(uint256(1)));
        bytes32 ref = tok.mtxConfidentialTransferSingle(pl, proof, _mlAuth(), _benT(pl), "");
        assertTrue(tok.transferCiphertextHash(ref) != 0, "the bundle stored");
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
