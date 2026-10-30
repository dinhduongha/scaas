// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {PqzFixture} from "./helpers/PqzFixture.sol";
import {PQZ_UID, PQZL_ID, PQZH_ID} from "./helpers/PqzRegistryBase.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {Catalogue, pqzEnv} from "../helpers/Catalogue.sol";

/// Op 7, the multi-recipient transfer (CTR-PQZ-25 / -26; P6g op 7): `mtxConfidentialTransfer*` with `M` legs (decoys included),
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
        ref = t.mtxConfidentialTransfer(_mplFor(t, from, ben, rec, out), hex"c0de", _mlAuth(), ben, "");
        _mirror(from, rec, out, aud);
    }

    /// The client's payload: `p = pendingCount`, `shieldIn = 0`, the memo on a COMPACT token.
    function _mplFor(PqzLayer t, bytes32 from, bytes32 ben, bytes32[] memory rec, bytes memory out)
        internal view returns (bytes memory)
    {
        bytes memory memo = t.disclosureMode() == ZetherTypes.DisclosureMode.COMPACT ? _mmemo(rec.length) : bytes("");
        return _mpayload(t.pqzAccount(from).pendingCount, 0, from, ben, rec, out, memo);
    }

    /// The client's mirror of an op 7: leg `j` credited `(u_{g(j)}, v_j)`, `g` by the auditor flag (R0-1).
    function _mirror(bytes32 from, bytes32[] memory rec, bytes memory out, bool withAud) internal {
        uint256 m = rec.length;
        uint256 us = PqzCt.PK * _groups(m, withAud);
        _afterDebit(from, _cut(out, 0, PqzCt.PK), _cut(out, us + PqzCt.V * m, PqzCt.V));
        for (uint256 j; j < m; ++j) {
            pend[rec[j]].push(bytes.concat(_cut(out, PqzCt.PK * _groupOf(j, withAud), PqzCt.PK),
                _cut(out, us + PqzCt.V * j, PqzCt.V)));
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
        for (uint256 j; j < 4; ++j) assertEq(_cut(st, O_PK1 + PqzCt.PK * j, PqzCt.PK), _keyOf(rec[j]), "pk_j");
        assertEq(_cut(st, O_PK1 + PqzCt.PK * 4, PqzCt.PK), _keyOf(aud), "pk_a");
        assertEq(_cut(st, O_PK1 + PqzCt.PK * 5 + PqzCt.CT, out.length), out, "out after T");
    }

    /// `R = salt ‖ P(u_0 … u_{G−1}) ‖ (P(v_j) ‖ P(v_{a,j}) ‖ UA_j)_j` with the auditor (P46: `u`, `v` packed;
    /// G = ⌈M / S_AUD⌉).
    function _bundleOn(bytes memory out, bytes32[] memory rec) internal view returns (bytes memory r) {
        uint256 m = rec.length;
        uint256 us = PqzCt.PK * _groups(m, true);
        r = bytes.concat(salt, _packed(_cut(out, 0, us)));
        for (uint256 j; j < m; ++j) {
            r = bytes.concat(r, _packed(_cut(out, us + PqzCt.V * j, PqzCt.V)),
                _packed(_cut(out, us + PqzCt.V * (m + 1 + j), PqzCt.V)), rec[j]);
        }
    }

    /// The PQZ key of a holder (UA-6: `recordOf`'s pointer, SSTORE2 code after its leading STOP byte).
    function _keyOf(bytes32 ua) internal view returns (bytes memory) {
        (, address ptr) = reg.recordOf(ua);
        return _slice(ptr.code, 1, ptr.code.length - 1);
    }

    // ------------------------------------------------------------------ statement and effects

    /// M = 4 with the auditor: the precompile input is `07 ‖ be32(len) ‖ stmt ‖ proof` with the §8.1 op 7 layout —
    /// header word 192 `recipientsHash`, 320 `M`, keys in leg order, `T`, `out`; every leg credited `(u_{g(j)}, v_j)`
    /// (G = ⌈4 / S_AUD⌉: two groups at n2048-kmax1024 / n2304-kmax4096).
    function test_multi_statementAndEffects() public {
        _public(tok, address(this), 1000 * SCALE); // topped up with `shieldIn`
        bytes32[] memory rec = _legsOf(4);
        bytes memory out = _blob(7, _outLen(4, true));
        bytes memory pl = _mpayload(0, 1000, alice, carol, rec, out, "");
        bytes memory st = tok.transferStatement(pl, 0);
        assertEq(st.length, PqzSet.multiLen(4, true), "len(M = 4, A = 1)");
        _checkLayout(st, rec, out);

        bytes memory proof = hex"0a0b0c";
        vm.expectCall(PQZ, abi.encodePacked(uint8(7), uint32(st.length), st, proof));
        for (uint256 j; j < 4; ++j) {
            vm.expectEmit(true, true, false, true, address(tok));
            emit IPqzToken.Credited(rec[j], 0, keccak256(abi.encode(keccak256("SCAAS-PQZ-ENTRY-V1"), block.chainid, PQZ_UID,
                address(tok), alice, uint256(0))));
        }
        uint256 g = gasleft();
        bytes32 ref = tok.mtxConfidentialTransfer(pl, proof, _mlAuth(), _benM(pl), "");
        console2.log("mtxConfidentialTransfer op 7 M = 4 (BUNDLE, auditor, fee, mocked proof) gas", g - gasleft());
        _mirror(alice, rec, out, true);

        IPqzToken.AccountState memory a = tok.pqzAccount(alice);
        assertEq(tok.pqzAcc(alice), accOf[alice], "acc = u_0 || v_f");
        assertEq(a.sendCounter, 1);
        assertEq(a.accUnits, 1);
        for (uint256 j; j < 4; ++j) {
            assertEq(tok.pqzAccount(rec[j]).pendingCount, 1);
            assertEq(tok.pqzPendingCt(rec[j], 0), pend[rec[j]][0], "credit (u_g(j), v_j)");
        }
        assertEq(tok.balanceOfUA(carol), FEE * SCALE, "txFee once, to the beneficiary's public balance");
        assertEq(tok.pqzAccount(carol).pendingCount, 0, "no TRIVIAL fee entry");
        assertEq(tok.totalShielded(), 1000 - FEE, "the fee left the pool");
        assertEq(tok.transferEntry(ref), _bundleOn(out, rec), "BUNDLE stores R = salt || u_0..u_G-1 || (v_j || v_aj || UA_j)_j");
        _roll(tok, bob, 1);
        _assertConservation(tok);
    }

    /// M = 8 (two groups): legs 4..7 are credited with `u_1`; without the auditor; then a leg spends.
    function test_multi_M8_twoGroups() public {
        _fund(tok, alice, 1000);
        bytes32[] memory rec = _legsOf(8);
        uint256 g = gasleft();
        (bytes32 ref, bytes memory out) = _multi(tok, alice, bytes32(0), rec, 9, false);
        console2.log("mtxConfidentialTransfer op 7 M = 8 (BUNDLE, no auditor, mocked proof) gas", g - gasleft());
        for (uint256 j; j < 8; ++j) assertEq(tok.pqzPendingCt(rec[j], 0), pend[rec[j]][0]);
        assertEq(_cut(pend[rec[5]][0], 0, PqzCt.PK), _cut(out, PqzCt.PK, PqzCt.PK), "leg 5 uses u_1");
        assertEq(tok.transferEntry(ref).length, 16 + 2 * PqzCt.PKP + (PqzCt.VP + 32) * 8, "R of M = 8, no auditor (packed)");
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
        bytes memory single = _rOf(out, bob);
        assertEq(tok.transferEntry(ref), single);
    }

    // ------------------------------------------------------------------ checks

    function test_multi_checks() public {
        _fund(tok, alice, 1000);
        bytes32[] memory rec = _legsOf(2);
        bytes memory out = _blob(3, _outLen(2, false));

        bytes32[] memory three = _legsOf(3);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadRecipientCount.selector, 3));
        tok.mtxConfidentialTransfer(_mpayload(0, 0, alice, 0, three, _blob(3, _outLen(3, false)), ""), hex"01", _mlAuth(), bytes32(0), "");
        bytes32[] memory zero = new bytes32[](0);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadRecipientCount.selector, 0));
        tok.mtxConfidentialTransfer(_mpayload(0, 0, alice, 0, zero, out, ""), hex"01", _mlAuth(), bytes32(0), "");

        bytes32[] memory dup = _legsOf(2);
        dup[1] = bob;
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.DuplicateRecipient.selector, bob));
        tok.mtxConfidentialTransfer(_mpayload(0, 0, alice, 0, dup, out, ""), hex"01", _mlAuth(), bytes32(0), "");

        bytes32[] memory self = _legsOf(2);
        self[1] = alice;
        vm.expectRevert(IPqzToken.SelfTransfer.selector);
        tok.mtxConfidentialTransfer(_mpayload(0, 0, alice, 0, self, out, ""), hex"01", _mlAuth(), bytes32(0), "");

        bytes32[] memory unknown = _legsOf(2);
        unknown[1] = bytes32(uint256(5));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, bytes32(uint256(5))));
        tok.mtxConfidentialTransfer(_mpayload(0, 0, alice, 0, unknown, out, ""), hex"01", _mlAuth(), bytes32(0), "");

        bytes memory pl = _mpayload(0, 0, alice, 0, rec, bytes.concat(out, bytes32(0)), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, pl.length));
        tok.mtxConfidentialTransfer(pl, hex"01", _mlAuth(), _benM(pl), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, 100));
        tok.mtxConfidentialTransfer(new bytes(100), hex"01", _mlAuth(), _benM(new bytes(100)), "");

        bytes memory nc = bytes.concat(out);
        nc[0] = 0xff;
        vm.expectRevert(IPqzToken.NonCanonical.selector);
        tok.mtxConfidentialTransfer(_mpayload(0, 0, alice, 0, rec, nc, ""), hex"01", _mlAuth(), bytes32(0), "");

        _mockOp(7, 0);
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.mtxConfidentialTransfer(_mpayload(0, 0, alice, 0, rec, out, ""), hex"01", _mlAuth(), bytes32(0), "");
        _mockOp(7, 1);
        tok.mtxConfidentialTransfer(_mpayload(0, 0, alice, 0, rec, out, ""), hex"01", _mlAuth(), bytes32(0), "");
    }

    /// The auditor mode binds `auditorOn` (read from the length for the given `M`), and a COMPACT token takes only
    /// commit-reveal with the `18 + 40·M`-byte memo of the payload's salt.
    function test_multi_modes() public {
        aMode = uint8(ZetherTypes.AuditorMode.FULL);
        PqzLayer full = _newToken("full");
        bytes32[] memory rec = _legsOf(2);
        vm.expectRevert(IPqzToken.AuditorRequired.selector);
        full.mtxConfidentialTransfer(_mpayload(0, 0, alice, 0, rec, _blob(1, _outLen(2, false)), ""), hex"01", _mlAuth(), bytes32(0), "");
        aMode = uint8(ZetherTypes.AuditorMode.NONE);
        PqzLayer noAud = _newToken("noaud");
        vm.expectRevert(IPqzToken.AuditorForbidden.selector);
        noAud.mtxConfidentialTransfer(_mpayload(0, 0, alice, 0, rec, _blob(1, _outLen(2, true)), ""), hex"01", _mlAuth(), bytes32(0), "");

        aMode = uint8(ZetherTypes.AuditorMode.OPTIONAL);
        dMode = uint8(ZetherTypes.DisclosureMode.COMPACT);
        PqzLayer cpt = _newToken("compact");
        bytes memory out = _blob(2, _outLen(2, true));
        bytes memory noMemo = _mpayload(0, 0, alice, 0, rec, out, "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, noMemo.length));
        cpt.mtxConfidentialTransfer(noMemo, hex"01", _mlAuth(), _benM(noMemo), "");
        bytes memory badMemo = bytes.concat(bytes16(0), _slice(_mmemo(2), 16, 82));
        vm.expectRevert(IPqzToken.MemoSaltMismatch.selector);
        cpt.mtxConfidentialTransfer(_mpayload(0, 0, alice, 0, rec, out, badMemo), hex"01", _mlAuth(), bytes32(0), "");
        bytes memory memo = _mmemo(2);
        bytes memory pl = _mpayload(0, 0, alice, 0, rec, out, memo);
        bytes memory st = cpt.transferStatement(pl, 0);
        assertEq(bytes32(_cut(st, 608, 32)), keccak256(memo), "memoHash");
        bytes32 ref = cpt.mtxConfidentialTransfer(pl, hex"01", _mlAuth(), _benM(pl), "");
        bytes memory e = cpt.transferEntry(ref);
        assertEq(_cut(e, 32, e.length - 32), memo, "the memo stored");
        assertEq(bytes32(_cut(e, 0, 32)), cpt.transferCiphertextHash(ref));
    }

    // ------------------------------------------------------------------ disclosure by leg

    /// Every leg of an audited M = 8: `u` of the leg's group `⌊j / S_AUD⌋`, `v_j` / `v_{a,j}`, and the kind word
    /// `OpeningKind + 256·(j mod S_AUD)` for AUDITOR (R0-1; `OpeningKind` alone for RECEIVER_X).
    function test_multi_disclosureByLeg() public {
        _fund(tok, alice, 1000);
        bytes32[] memory rec = _legsOf(8);
        (bytes32 ref, bytes memory out) = _multi(tok, alice, bytes32(0), rec, 13, true);
        uint256 us = _groups(8, true) * PqzCt.PK;
        for (uint256 j; j < 8; ++j) {
            bytes memory st = tok.disclosureStatement(ref, j, 77, 1);
            assertEq(st.length, ST_DISC);
            assertEq(uint256(bytes32(_cut(st, 256, 32))), 1, "RECEIVER_X kind word: w = 0");
            assertEq(_cut(st, 288, PqzCt.PK), _keyOf(rec[j]), "the leg's key");
            assertEq(_cut(st, O_DU, PqzCt.PK), _cut(out, PqzCt.PK * (j / PqzSet.S_AUD), PqzCt.PK), "u of the leg's group");
            assertEq(_cut(st, O_DV, 128), _cut(out, us + PqzCt.V * j, PqzCt.V), "v_j");
            st = tok.disclosureStatement(ref, j, 77, 2);
            assertEq(uint256(bytes32(_cut(st, 256, 32))), 2 + 256 * (j % PqzSet.S_AUD), "AUDITOR kind word: w = j mod S_AUD");
            assertEq(_cut(st, 288, PqzCt.PK), _keyOf(aud), "the auditor's key");
            assertEq(_cut(st, O_DU, PqzCt.PK), _cut(out, PqzCt.PK * (j / PqzSet.S_AUD), PqzCt.PK), "u of the leg's group");
            assertEq(_cut(st, O_DV, 128), _cut(out, us + PqzCt.V * (9 + j), PqzCt.V), "v_aj");
        }
        // without the auditor: groups of 4, and no AUDITOR disclosure
        (bytes32 ref0, bytes memory out0) = _multi(tok, alice, bytes32(0), rec, 14, false);
        for (uint256 j; j < 8; ++j) {
            bytes memory st = tok.disclosureStatement(ref0, j, 77, 1);
            assertEq(_cut(st, O_DU, PqzCt.PK), _cut(out0, PqzCt.PK * (j / 4), PqzCt.PK), "off: u of group j / 4");
        }
        vm.expectRevert();
        tok.disclosureStatement(ref0, 0, 77, 2);
        bytes memory opening = hex"0a0b"; // the proof: `R` is read from the op blob (D11)
        assertTrue(tok.verifyTransferAmount(ref, 5, 77, 1, opening));
        assertFalse(tok.verifyTransferAmount(ref, 8, 77, 1, opening), "no leg 8");
        _mockOp(5, 0);
        assertFalse(tok.verifyTransferAmount(ref, 5, 77, 1, opening), "the precompile says no");
    }

    /// The vectors' op 7 disclosures as the oracle (`disclosures` of the set's `statement_transfer_multi.json`, the head
    /// words extracted to `test/vectors/pqz-disclosures/<set>.json`: the 3.5 MB file exceeds forge's memory gas): the
    /// token's statement of the same leg and kind has the vectors' opTag, amount and kind word (`OpeningKind + 256·w`,
    /// byte-identical to pqz-stmt's R_DR / R_DA statement).
    function test_multi_disclosureKindWord_vectors() public {
        _fund(tok, alice, 1000);
        string memory j = vm.readFile(string.concat(vm.projectRoot(), "/test/vectors/pqz-disclosures/", PqzSet.NAME, ".json"));
        for (uint256 i; i < 4; ++i) {
            string memory r = string.concat(".rows[", vm.toString(i), "]");
            uint256 m = vm.parseJsonUint(j, string.concat(r, ".legs"));
            uint256 leg = vm.parseJsonUint(j, string.concat(r, ".leg"));
            bytes memory head = vm.parseBytes(string.concat("0x", vm.parseJsonString(j, string.concat(r, ".head"))));
            uint256 word = uint256(bytes32(_cut(head, 256, 32)));
            (bytes32 ref,) = _multi(tok, alice, bytes32(0), _legsOf(m), 40 + i, true);
            bytes memory st = tok.disclosureStatement(ref, leg, uint256(bytes32(_cut(head, 224, 32))), uint8(word & 0xff));
            assertEq(_cut(st, 0, 32), _cut(head, 0, 32), "opTag");
            assertEq(_cut(st, 224, 64), _cut(head, 224, 64), "amount and kind words as the vector");
            if (word & 0xff == 2) assertEq(word >> 8, leg % PqzSet.S_AUD, "AUDITOR: w = leg mod S_AUD");
        }
    }

    /// `_bundleShape`: the length of `R` fixes (G, M, auditorOn) for every M ≤ 8 (owner rule R0-1: G = ⌈M / S_AUD⌉ with
    /// the auditor, ⌈M / 4⌉ without). Through the library code at the build's set; all 16 lengths round-trip, so they
    /// are distinct. The other sets: the same test through `script/pqz/at-set.sh <set>` (review of fix part b, M-5).
    function test_bundleShape_unique() public {
        BundleShapeHarness h = new BundleShapeHarness();
        for (uint256 m = 1; m <= 8; ++m) {
            for (uint256 a; a < 2; ++a) {
                uint256 g = _groups(m, a == 1);
                (uint256 g2, uint256 m2, uint256 a2) = h.shape(16 + PqzCt.PKP * g + (32 + PqzCt.VP * (1 + a)) * m);
                assertEq(abi.encode(g2, m2, a2), abi.encode(g, m, a), "the shape from the length");
            }
        }
    }

    /// F-4 (R0 review): with the auditor copies on, the auditor UA is neither the sender nor a leg (op 7 and op 1);
    /// without them it may be either.
    function test_auditorAsParty_refused() public {
        _fund(tok, alice, 1000);
        bytes32[] memory rec = _legsOf(2);
        rec[1] = aud;
        bytes memory out = _blob(3, _outLen(2, true));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AuditorAsParty.selector, aud));
        tok.mtxConfidentialTransfer(_mpayload(0, 0, alice, 0, rec, out, ""), hex"01", _mlAuth(), bytes32(0), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AuditorAsParty.selector, aud));
        tok.transferStatement(_mpayload(0, 0, alice, 0, rec, out, ""), 0);
        _fund(tok, aud, 1000);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AuditorAsParty.selector, aud));
        tok.mtxConfidentialTransfer(_mpayload(0, 0, aud, 0, _legsOf(2), out, ""), hex"01", _mlAuth(), bytes32(0), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AuditorAsParty.selector, aud));
        tok.mtxConfidentialTransferSingle(_payload(0, 0, aud, bob, bytes32(0), _out(4, true), ""), hex"01", _mlAuth(), bytes32(0), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AuditorAsParty.selector, aud));
        tok.mtxConfidentialTransferSingle(_payload(0, 0, alice, aud, bytes32(0), _out(5, true), ""), hex"01", _mlAuth(), bytes32(0), "");
        // auditor off: no copies, no collision
        tok.mtxConfidentialTransfer(_mpayload(0, 0, alice, 0, rec, _blob(6, _outLen(2, false)), ""), hex"01", _mlAuth(), bytes32(0), "");
        tok.mtxConfidentialTransferSingle(_payload(0, 0, aud, bob, bytes32(0), _out(7, false), ""), hex"01", _mlAuth(), bytes32(0), "");
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
        t.mtxConfidentialTransfer(pl, hex"01", _mlAuth(), _benM(pl), "");
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
        t.mtxConfidentialTransferSingle(pl, hex"01", _mlAuth(), _benT(pl), "");
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
        t.mtxConfidentialTransfer(pl, hex"01", _mlAuth(), _benM(pl), "");
        decoy = uint256(1) << 64;
        pl = _mpayload(0, 0, alice, 0, rec, _blob(4, _outLen(2, true)), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.DecoyFeeOutOfRange.selector, uint256(1) << 64, 2));
        t.mtxConfidentialTransfer(pl, hex"01", _mlAuth(), _benM(pl), "");
        decoy = 0;
        _fund(tok, alice, 10);
        tok.mtxConfidentialTransfer(_mpayload(1, 0, alice, 0, rec, _blob(5, _outLen(2, true)), ""), hex"01", _mlAuth(), bytes32(0), "");
        assertEq(tok.balanceOfUA(bob), 0);
    }

    function test_minDecoyFee_initBounds() public {
        minDecoy = (uint256(1) << 61); // confidentialFee + 8 · minDecoyFee ≥ 2^64
        vm.expectRevert(IPqzToken.BadInit.selector);
        _newToken("big");
    }

    /// Review W-I: a payload shorter than its legs and memo is `BadPayload`, not an arithmetic panic.
    function test_multi_shortPayloadIsBadPayload() public {
        bytes memory pl = bytes.concat(new bytes(160), bytes32(uint256(1)), bytes32(0), bytes16(0)); // M = 1, no leg
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, uint256(240)));
        tok.mtxConfidentialTransfer(pl, hex"01", _mlAuth(), _benM(pl), "");
    }

    /// A PQZH token: M = 8 is not built; at most 10 inline credits on op 7 (16 on op 1).
    function test_multi_pqzh() public {
        if (!PqzSet.PQZH_VALUE) return; // no PQZH value token at this set (init refuses it: PqzGuards test_init_pqzhRefusedWithoutValueSets)
        // a PQZH release: its verifier is the env's, an immutable (CTR-ZTH-20)
        pqv = _newPqzVerifier(PQZH_ID);
        factory = new OpenFactory(registrar, PQZ_UID, 0);
        Catalogue.release(factory, IOpenFactory.TokenKind.NORMAL_PQZ, 1,
            pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv)), type(NormalPqzToken).creationCode);
        vm.prank(registrar);
        factory.setKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true);
        PqzLayer h = _newToken("pqzh");
        assertEq(h.proofSystemId(), PQZH_ID);
        bytes32[] memory rec = _legsOf(8);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadRecipientCount.selector, 8));
        h.mtxConfidentialTransfer(_mpayload(0, 0, alice, 0, rec, _blob(1, _outLen(8, true)), ""), hex"01", _mlAuth(), bytes32(0), "");
        // 11 credits to alice, then a debit at p = 11 needs 11 inline credits: refused on op 7, accepted on op 1
        _fund(h, bob, 1000);
        for (uint256 i; i < 11; ++i) _transferOn(h, bob, alice, 100 + i);
        assertEq(h.pqzAccount(alice).pendingCount, 11);
        bytes32[] memory one = new bytes32[](1);
        one[0] = carol;
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.InlineTooFar.selector, 11));
        h.mtxConfidentialTransfer(_mpayload(11, 0, alice, 0, one, _blob(2, _outLen(1, true)), ""), hex"01", _mlAuth(), bytes32(0), "");
        h.mtxConfidentialTransferSingle(_payload(11, 0, alice, carol, bytes32(0), _out(3, true), ""), hex"01", _mlAuth(), bytes32(0), "");
    }

    function _transferOn(PqzLayer t, bytes32 from, bytes32 to, uint256 seed) internal {
        _transfer(t, from, to, bytes32(0), seed, true);
    }

    // ------------------------------------------------------------------ relaying

    /// The four transfer selectors are allowlisted `ABSOLUTE` on the relaying paths; the NONE ones are gone (D11).
    function test_multi_allowlisted() public view {
        (bytes4[] memory s,,) = NormalPqzToken(address(tok)).mtxSelectors();
        bytes4[4] memory want = [PqzLayer.mtxConfidentialTransfer.selector, PqzLayer.mtxConfidentialTransferCompact.selector,
            PqzLayer.mtxConfidentialTransferSingle.selector, PqzLayer.mtxConfidentialTransferSingleCompact.selector];
        for (uint256 i; i < 4; ++i) {
            bool found;
            for (uint256 k; k < s.length; ++k) found = found || s[k] == want[i];
            assertTrue(found);
        }
        bytes4[2] memory gone = [bytes4(keccak256("mtxConfidentialTransferNoBundle(bytes,bytes,bytes,bytes32,bytes)")),
            bytes4(keccak256("mtxConfidentialTransferSingleNoBundle(bytes,bytes,bytes,bytes32,bytes)"))];
        for (uint256 k; k < s.length; ++k) assertTrue(s[k] != gone[0] && s[k] != gone[1], "NONE retired");
    }
}

/// `PqzCore._bundleShape` (internal) for `test_bundleShape_unique`.
contract BundleShapeHarness {
    function shape(uint256 bl) external pure returns (uint256, uint256, uint256) {
        return PqzCore._bundleShape(bl);
    }
}
