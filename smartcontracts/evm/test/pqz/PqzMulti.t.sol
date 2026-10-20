// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {PqzFixture} from "./helpers/PqzFixture.sol";
import {PQZ_UID, PQZL_ID, PQZH_ID} from "./helpers/PqzRegistryBase.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {NoUnderlyingPqzToken} from "../../src/pqz/NoUnderlyingPqzToken.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {Catalogue, pqzEnv} from "../helpers/Catalogue.sol";

/// Op 7, the multi-recipient transfer (CTR-PQZ-25 / -26; P6g op 7): `pqzTransfer*` with `M` legs (decoys included),
/// the statement against pq-zero-knowledge.md §8.1 op 7, the effects per leg, the bundle (for `M = 1` the single
/// transfer's), disclosure by leg, `decoyFee`, the PQZH limits. The precompile is mocked; the rest is real.
contract PqzMultiTest is PqzFixture {
    bytes32[8] internal xs; // extra pqz-mlwe UAs (keys `_pk(20 + i)`)

    function setUp() public {
        _stack();
        _mockOp(7, 1);
        for (uint8 i; i < 8; ++i) xs[i] = _pqzUA(_pk(20 + i), 10 + i);
        tok = _newToken("pqz");
    }

    // ------------------------------------------------------------------ helpers

    function _legsOf(uint256 m) internal view returns (bytes32[] memory r) {
        r = new bytes32[](m);
        r[0] = bob;
        for (uint256 j = 1; j < m; ++j) r[j] = xs[j - 1];
    }

    function _mmemo(uint256 m) internal view returns (bytes memory) {
        return bytes.concat(salt, _slice(_blob(0x3e31, 352), 0, 2 + 40 * m));
    }

    /// A direct op 7 transfer at `p = pendingCount`, `shieldIn = 0`; the client's mirror.
    function _multi(PqzLayer t, bytes32 from, bytes32 ben, bytes32[] memory rec, uint256 seed, bool aud)
        internal returns (bytes32 ref, bytes memory out)
    {
        out = _blob(seed, _outLen(rec.length, aud));
        ref = t.pqzTransfer(_mplFor(t, from, ben, rec, out), "", hex"c0de", _mlAuth());
        _mirror(from, rec, out);
    }

    /// The client's payload: `p = pendingCount`, `shieldIn = 0`, the memo on a COMPACT token.
    function _mplFor(PqzLayer t, bytes32 from, bytes32 ben, bytes32[] memory rec, bytes memory out)
        internal view returns (bytes memory)
    {
        bytes memory memo = t.disclosureMode() == ZetherTypes.DisclosureMode.COMPACT ? _mmemo(rec.length) : bytes("");
        return _mpayload(t.pqzAccount(from).pendingCount, 0, from, ben, rec, out, memo);
    }

    function _mirror(bytes32 from, bytes32[] memory rec, bytes memory out) internal {
        uint256 m = rec.length;
        uint256 us = PqzCt.PK * ((m + 3) / 4);
        _afterDebit(from, _cut(out, 0, PqzCt.PK), _cut(out, us + PqzCt.V * m, PqzCt.V));
        for (uint256 j; j < m; ++j) {
            pend[rec[j]].push(bytes.concat(_cut(out, PqzCt.PK * (j / 4), PqzCt.PK), _cut(out, us + PqzCt.V * j, PqzCt.V)));
        }
    }

    /// The §8.1 op 7 layout of alice's M = 4 statement with the auditor and carol as beneficiary.
    function _checkLayout(bytes memory st, bytes32[] memory rec, bytes memory out) internal view {
        bytes memory head = bytes.concat(
            abi.encode(PqzCore.OP_TRANSFER_MULTI, PQZL_ID, block.chainid, address(tok), address(reg), alice,
                keccak256(abi.encodePacked(rec)), carol, FEE, uint256(0)),
            abi.encode(uint256(4), uint256(0), uint256(0), block.number + 100, uint256(1), uint256(1000), PQZ_UID,
                _direct(ZetherTypes.TransferMode.BUNDLE), uint256(uint128(salt)), bytes32(0))
        );
        assertEq(_cut(st, 0, 640), head, "header: word 192 recipientsHash, 320 M");
        assertEq(_cut(st, 640, PqzCt.PK), _keyOf(alice), "pk_f");
        for (uint256 j; j < 4; ++j) assertEq(_cut(st, 17_024 + PqzCt.PK * j, PqzCt.PK), _keyOf(rec[j]), "pk_j");
        assertEq(_cut(st, 17_024 + PqzCt.PK * 4, PqzCt.PK), _keyOf(aud), "pk_a");
        assertEq(_cut(st, 17_024 + PqzCt.PK * 5 + PqzCt.CT, out.length), out, "out after T");
    }

    /// `R` of a one-group transfer with the auditor.
    function _bundleOn(bytes memory out, bytes32[] memory rec) internal view returns (bytes memory r) {
        uint256 m = rec.length;
        r = bytes.concat(salt, _cut(out, 0, PqzCt.PK));
        for (uint256 j; j < m; ++j) {
            r = bytes.concat(r, _cut(out, PqzCt.PK + PqzCt.V * j, PqzCt.V),
                _cut(out, PqzCt.PK + PqzCt.V * (m + 1 + j), PqzCt.V), rec[j]);
        }
    }

    /// The PQZ key of a holder (UA-6: `recordOf`'s pointer, SSTORE2 code after its leading STOP byte).
    function _keyOf(bytes32 ua) internal view returns (bytes memory) {
        (, address ptr) = reg.recordOf(ua);
        return _slice(ptr.code, 1, ptr.code.length - 1);
    }

    // ------------------------------------------------------------------ statement and effects

    /// M = 4 with the auditor: the precompile input is `07 ‖ be32(len) ‖ stmt ‖ proof` with the §8.1 op 7 layout —
    /// header word 192 `recipientsHash`, 320 `M`, keys in leg order, `T`, `out`; every leg credited `(u_0, v_j)`.
    function test_multi_statementAndEffects() public {
        _public(tok, address(this), 1000 * SCALE); // topped up with `shieldIn`
        bytes32[] memory rec = _legsOf(4);
        bytes memory out = _blob(7, _outLen(4, true));
        bytes memory pl = _mpayload(0, 1000, alice, carol, rec, out, "");
        bytes memory st = tok.transferStatement(pl, 0);
        assertEq(st.length, 50_048 + 16_640 * 4 + 16_384, "len(M = 4, A = 1)");
        _checkLayout(st, rec, out);

        bytes memory proof = hex"0a0b0c";
        vm.expectCall(PQZ, abi.encodePacked(uint8(7), uint32(st.length), st, proof));
        for (uint256 j; j < 4; ++j) {
            vm.expectEmit(true, true, false, true, address(tok));
            emit IPqzToken.PqzCredit(rec[j], 0, keccak256(abi.encode(keccak256("SCAAS-PQZ-ENTRY-V1"), block.chainid, PQZ_UID,
                address(tok), alice, uint256(0))));
        }
        uint256 g = gasleft();
        bytes32 ref = tok.pqzTransfer(pl, "", proof, _mlAuth());
        console2.log("pqzTransfer op 7 M = 4 (BUNDLE, auditor, fee, mocked proof) gas", g - gasleft());
        _mirror(alice, rec, out);

        IPqzToken.AccountState memory a = tok.pqzAccount(alice);
        assertEq(tok.pqzAcc(alice), accOf[alice], "acc = u_0 || v_f");
        assertEq(a.sendCounter, 1);
        assertEq(a.accUnits, 1);
        for (uint256 j; j < 4; ++j) {
            assertEq(tok.pqzAccount(rec[j]).pendingCount, 1);
            assertEq(tok.pqzPendingCt(rec[j], 0), pend[rec[j]][0], "credit (u_0, v_j)");
        }
        assertEq(tok.balanceOfUA(carol), FEE * SCALE, "txFee once, to the beneficiary's public balance");
        assertEq(tok.pqzAccount(carol).pendingCount, 0, "no TRIVIAL fee entry");
        assertEq(tok.totalShielded(), 1000 - FEE, "the fee left the pool");
        assertEq(tok.transferEntry(ref), _bundleOn(out, rec), "BUNDLE stores R = salt || u_0 || (v_j || v_aj || UA_j)_j");
        _roll(tok, bob, 1);
        _assertConservation(tok);
    }

    /// M = 8 (two groups): legs 4..7 are credited with `u_1`; without the auditor; then a leg spends.
    function test_multi_M8_twoGroups() public {
        _fund(tok, alice, 1000);
        bytes32[] memory rec = _legsOf(8);
        uint256 g = gasleft();
        (bytes32 ref, bytes memory out) = _multi(tok, alice, bytes32(0), rec, 9, false);
        console2.log("pqzTransfer op 7 M = 8 (BUNDLE, no auditor, mocked proof) gas", g - gasleft());
        for (uint256 j; j < 8; ++j) assertEq(tok.pqzPendingCt(rec[j], 0), pend[rec[j]][0]);
        assertEq(_cut(pend[rec[5]][0], 0, PqzCt.PK), _cut(out, PqzCt.PK, PqzCt.PK), "leg 5 uses u_1");
        assertEq(tok.transferEntry(ref).length, 16 + 2 * PqzCt.PK + 160 * 8);
        _roll(tok, rec[7], 1);
        bytes32[] memory back = new bytes32[](1);
        back[0] = alice;
        _multi(tok, rec[7], bytes32(0), back, 10, false);
        assertEq(tok.pqzAccount(alice).pendingCount, 2, "the shield's TRIVIAL entry and the credit");
    }

    /// For `M = 1` the multi bundle is the single transfer's bundle byte for byte, so disclosure reads both alike.
    function test_multi_M1_bundleIsTheSingleBundle() public {
        _fund(tok, alice, 1000);
        bytes32[] memory rec = _legsOf(1);
        (bytes32 ref, bytes memory out) = _multi(tok, alice, bytes32(0), rec, 11, true);
        bytes memory single = bytes.concat(salt, _cut(out, 0, PqzCt.CT), _cut(out, 16_640, 128), bob);
        assertEq(tok.transferEntry(ref), single);
    }

    // ------------------------------------------------------------------ checks

    function test_multi_checks() public {
        _fund(tok, alice, 1000);
        bytes32[] memory rec = _legsOf(2);
        bytes memory out = _blob(3, _outLen(2, false));

        bytes32[] memory three = _legsOf(3);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadRecipientCount.selector, 3));
        tok.pqzTransfer(_mpayload(0, 0, alice, 0, three, _blob(3, _outLen(3, false)), ""), "", hex"01", _mlAuth());
        bytes32[] memory zero = new bytes32[](0);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadRecipientCount.selector, 0));
        tok.pqzTransfer(_mpayload(0, 0, alice, 0, zero, out, ""), "", hex"01", _mlAuth());

        bytes32[] memory dup = _legsOf(2);
        dup[1] = bob;
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.DuplicateRecipient.selector, bob));
        tok.pqzTransfer(_mpayload(0, 0, alice, 0, dup, out, ""), "", hex"01", _mlAuth());

        bytes32[] memory self = _legsOf(2);
        self[1] = alice;
        vm.expectRevert(IPqzToken.SelfTransfer.selector);
        tok.pqzTransfer(_mpayload(0, 0, alice, 0, self, out, ""), "", hex"01", _mlAuth());

        bytes32[] memory unknown = _legsOf(2);
        unknown[1] = bytes32(uint256(5));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, bytes32(uint256(5))));
        tok.pqzTransfer(_mpayload(0, 0, alice, 0, unknown, out, ""), "", hex"01", _mlAuth());

        bytes memory pl = _mpayload(0, 0, alice, 0, rec, bytes.concat(out, bytes32(0)), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, pl.length));
        tok.pqzTransfer(pl, "", hex"01", _mlAuth());
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, 100));
        tok.pqzTransfer(new bytes(100), "", hex"01", _mlAuth());

        bytes memory nc = bytes.concat(out);
        nc[0] = 0xff;
        vm.expectRevert(IPqzToken.NonCanonical.selector);
        tok.pqzTransfer(_mpayload(0, 0, alice, 0, rec, nc, ""), "", hex"01", _mlAuth());

        _mockOp(7, 0);
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.pqzTransfer(_mpayload(0, 0, alice, 0, rec, out, ""), "", hex"01", _mlAuth());
        _mockOp(7, 1);
        tok.pqzTransfer(_mpayload(0, 0, alice, 0, rec, out, ""), "", hex"01", _mlAuth());
    }

    /// The auditor mode binds `auditorOn` (read from the length for the given `M`), and a COMPACT token takes only
    /// commit-reveal with the `18 + 40·M`-byte memo of the payload's salt.
    function test_multi_modes() public {
        aMode = uint8(ZetherTypes.AuditorMode.FULL);
        PqzLayer full = _newToken("full");
        bytes32[] memory rec = _legsOf(2);
        vm.expectRevert(IPqzToken.AuditorRequired.selector);
        full.pqzTransfer(_mpayload(0, 0, alice, 0, rec, _blob(1, _outLen(2, false)), ""), "", hex"01", _mlAuth());
        aMode = uint8(ZetherTypes.AuditorMode.NONE);
        PqzLayer noAud = _newToken("noaud");
        vm.expectRevert(IPqzToken.AuditorForbidden.selector);
        noAud.pqzTransfer(_mpayload(0, 0, alice, 0, rec, _blob(1, _outLen(2, true)), ""), "", hex"01", _mlAuth());

        aMode = uint8(ZetherTypes.AuditorMode.OPTIONAL);
        dMode = uint8(ZetherTypes.DisclosureMode.COMPACT);
        PqzLayer cpt = _newToken("compact");
        bytes memory out = _blob(2, _outLen(2, true));
        bytes memory noMemo = _mpayload(0, 0, alice, 0, rec, out, "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, noMemo.length));
        cpt.pqzTransfer(noMemo, "", hex"01", _mlAuth());
        bytes memory badMemo = bytes.concat(bytes16(0), _slice(_mmemo(2), 16, 82));
        vm.expectRevert(IPqzToken.MemoSaltMismatch.selector);
        cpt.pqzTransfer(_mpayload(0, 0, alice, 0, rec, out, badMemo), "", hex"01", _mlAuth());
        bytes memory memo = _mmemo(2);
        bytes memory pl = _mpayload(0, 0, alice, 0, rec, out, memo);
        bytes memory st = cpt.transferStatement(pl, 0);
        assertEq(bytes32(_cut(st, 608, 32)), keccak256(memo), "memoHash");
        bytes32 ref = cpt.pqzTransfer(pl, "", hex"01", _mlAuth());
        bytes memory e = cpt.transferEntry(ref);
        assertEq(_cut(e, 32, e.length - 32), memo, "the memo stored");
        assertEq(bytes32(_cut(e, 0, 32)), cpt.transferCiphertextHash(ref));
    }

    // ------------------------------------------------------------------ disclosure by leg

    function test_multi_disclosureByLeg() public {
        _fund(tok, alice, 1000);
        bytes32[] memory rec = _legsOf(8);
        (bytes32 ref, bytes memory out) = _multi(tok, alice, bytes32(0), rec, 13, true);
        uint256 us = 2 * PqzCt.PK;
        for (uint256 j = 3; j < 6; ++j) {
            bytes memory st = tok.disclosureStatement(ref, j, 77, 1);
            assertEq(st.length, 33_184);
            assertEq(_cut(st, 288, PqzCt.PK), _keyOf(rec[j]), "the leg's key");
            assertEq(_cut(st, 16_672, PqzCt.PK), _cut(out, PqzCt.PK * (j / 4), PqzCt.PK), "u of the leg's group");
            assertEq(_cut(st, 33_056, 128), _cut(out, us + PqzCt.V * j, PqzCt.V), "v_j");
            st = tok.disclosureStatement(ref, j, 77, 2);
            assertEq(_cut(st, 288, PqzCt.PK), _keyOf(aud), "the auditor's key");
            assertEq(_cut(st, 33_056, 128), _cut(out, us + PqzCt.V * (9 + j), PqzCt.V), "v_aj");
        }
        bytes memory opening = hex"0a0b"; // the proof: `R` is read from the op blob (D11)
        assertTrue(tok.verifyTransferAmount(ref, 5, 77, 1, opening));
        assertFalse(tok.verifyTransferAmount(ref, 8, 77, 1, opening), "no leg 8");
        _mockOp(5, 0);
        assertFalse(tok.verifyTransferAmount(ref, 5, 77, 1, opening), "the precompile says no");
    }

    // ------------------------------------------------------------------ decoyFee (owner 2026-10-20) and PQZH

    /// Op 7: the sender's `decoyFee d ≥ minDecoyFee` to EVERY leg's public balance (the real recipient too), txFee to
    /// the beneficiary; the statement's fee word is `txFee + M·d`, so `d` is bound by the proof; all out of the pool.
    function test_decoyFee_perLegUniform() public {
        minDecoy = 2;
        PqzLayer t = _newToken("decoy");
        assertEq(t.minDecoyFee(), 2);
        _fund(t, alice, 1000);
        bytes32[] memory rec = _legsOf(4);
        decoy = 5;
        bytes memory pl = _mpayload(1, 0, alice, carol, rec, _blob(4, _outLen(4, true)), "");
        bytes memory st = t.transferStatement(pl, 0);
        assertEq(uint256(bytes32(_cut(st, 256, 32))), FEE + 4 * 5, "fee word = txFee + M * decoyFee");
        _mockOp(7, 0);
        vm.mockCall(PQZ, abi.encodePacked(uint8(7), uint32(st.length), st, hex"01"), abi.encode(uint256(1)));
        t.pqzTransfer(pl, "", hex"01", _mlAuth());
        _mockOp(7, 1);
        assertEq(t.balanceOfUA(carol), FEE * SCALE, "txFee to the beneficiary");
        for (uint256 j; j < 4; ++j) {
            assertEq(t.balanceOfUA(rec[j]), 5 * SCALE, "decoyFee to every leg, real recipient included");
            assertEq(t.pqzAccount(rec[j]).pendingCount, 1, "the credit only, no TRIVIAL fee entry");
        }
        assertEq(t.totalShielded(), 1000 - FEE - 20);
        _assertConservation(t);
        // no beneficiary: the fee word is M * decoyFee alone
        rec[0] = alice;
        decoy = 2;
        pl = _mpayload(0, 0, carol, 0, rec, _blob(5, _outLen(4, true)), "");
        assertEq(uint256(bytes32(_cut(t.transferStatement(pl, 0), 256, 32))), 8);
        // the op 1 path never pays it
        pl = _payload(0, 0, bob, alice, bytes32(0), _out(6, true), "");
        assertEq(uint256(bytes32(_cut(t.transferSingleStatement(pl, 0), 256, 32))), 0);
        uint256 before = t.balanceOfUA(alice);
        t.pqzTransferSingle(pl, "", hex"01", _mlAuth());
        assertEq(t.balanceOfUA(alice), before, "op 1: no decoyFee");
    }

    /// `d < minDecoyFee` and `d ≥ 2^64` are refused; `minDecoyFee = 0` takes `d = 0` (no payment).
    function test_decoyFee_bounds() public {
        minDecoy = 2;
        PqzLayer t = _newToken("decoy");
        bytes32[] memory rec = _legsOf(2);
        decoy = 1;
        bytes memory pl = _mpayload(0, 0, alice, 0, rec, _blob(4, _outLen(2, true)), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.DecoyFeeOutOfRange.selector, 1, 2));
        t.pqzTransfer(pl, "", hex"01", _mlAuth());
        decoy = uint256(1) << 64;
        pl = _mpayload(0, 0, alice, 0, rec, _blob(4, _outLen(2, true)), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.DecoyFeeOutOfRange.selector, uint256(1) << 64, 2));
        t.pqzTransfer(pl, "", hex"01", _mlAuth());
        decoy = 0;
        _fund(tok, alice, 10);
        tok.pqzTransfer(_mpayload(1, 0, alice, 0, rec, _blob(5, _outLen(2, true)), ""), "", hex"01", _mlAuth());
        assertEq(tok.balanceOfUA(bob), 0);
    }

    function test_minDecoyFee_initBounds() public {
        minDecoy = (uint256(1) << 61); // confidentialFee + 8 · minDecoyFee ≥ 2^64
        vm.expectRevert();
        _newToken("big");
    }

    /// Review W-I: a payload shorter than its legs and memo is `BadPayload`, not an arithmetic panic.
    function test_multi_shortPayloadIsBadPayload() public {
        bytes memory pl = bytes.concat(new bytes(160), bytes32(uint256(1)), bytes32(0), bytes16(0)); // M = 1, no leg
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, uint256(240)));
        tok.pqzTransfer(pl, "", hex"01", _mlAuth());
    }

    /// A PQZH token: M = 8 is not built; at most 10 inline credits on op 7 (16 on op 1).
    function test_multi_pqzh() public {
        // a PQZH release: its verifier is the env's, an immutable (CTR-ZTH-20)
        pqv = _newPqzVerifier(PQZH_ID);
        factory = new OpenFactory(registrar, PQZ_UID, 0);
        Catalogue.release(factory, IOpenFactory.TokenKind.NONE_PQZ, 1,
            pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv)), type(NoUnderlyingPqzToken).creationCode);
        vm.prank(registrar);
        factory.setKindEnabled(IOpenFactory.TokenKind.NONE_PQZ, true);
        PqzLayer h = _newToken("pqzh");
        assertEq(h.proofSystemId(), PQZH_ID);
        bytes32[] memory rec = _legsOf(8);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadRecipientCount.selector, 8));
        h.pqzTransfer(_mpayload(0, 0, alice, 0, rec, _blob(1, _outLen(8, true)), ""), "", hex"01", _mlAuth());
        // 11 credits to alice, then a debit at p = 11 needs 11 inline credits: refused on op 7, accepted on op 1
        _fund(h, bob, 1000);
        for (uint256 i; i < 11; ++i) _transferOn(h, bob, alice, 100 + i);
        assertEq(h.pqzAccount(alice).pendingCount, 11);
        bytes32[] memory one = new bytes32[](1);
        one[0] = carol;
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.InlineTooFar.selector, 11));
        h.pqzTransfer(_mpayload(11, 0, alice, 0, one, _blob(2, _outLen(1, true)), ""), "", hex"01", _mlAuth());
        h.pqzTransferSingle(_payload(11, 0, alice, carol, bytes32(0), _out(3, true), ""), "", hex"01", _mlAuth());
    }

    function _transferOn(PqzLayer t, bytes32 from, bytes32 to, uint256 seed) internal {
        _transfer(t, from, to, bytes32(0), seed, true);
    }

    // ------------------------------------------------------------------ relaying

    /// The four transfer selectors are allowlisted `ABSOLUTE` on the relaying paths; the NONE ones are gone (D11).
    function test_multi_allowlisted() public view {
        (bytes4[] memory s,,) = NoUnderlyingPqzToken(address(tok)).mtxSelectors();
        bytes4[4] memory want = [PqzLayer.pqzTransfer.selector, PqzLayer.pqzTransferCompact.selector,
            PqzLayer.pqzTransferSingle.selector, PqzLayer.pqzTransferSingleCompact.selector];
        for (uint256 i; i < 4; ++i) {
            bool found;
            for (uint256 k; k < s.length; ++k) found = found || s[k] == want[i];
            assertTrue(found);
        }
        bytes4[2] memory gone = [bytes4(keccak256("pqzTransferNoBundle(bytes,bytes,bytes,bytes)")),
            bytes4(keccak256("pqzTransferSingleNoBundle(bytes,bytes,bytes,bytes)"))];
        for (uint256 k; k < s.length; ++k) assertTrue(s[k] != gone[0] && s[k] != gone[1], "NONE retired");
    }
}
