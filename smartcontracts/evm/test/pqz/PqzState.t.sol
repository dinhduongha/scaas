// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {PqzFixture} from "./helpers/PqzFixture.sol";
import {PqzCtHarness} from "./helpers/PqzCtHarness.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {NoUnderlyingPqzToken} from "../../src/pqz/NoUnderlyingPqzToken.sol";
import {PqzSafety} from "../../src/pqz/PqzSafety.sol";

/// Storage helpers over the ERC-7201 namespace `scaas.pqz` (plan 5h D2 / D3 layout).
abstract contract PqzSlots is PqzFixture {
    uint256 internal constant BASE = 0xda865ec17214f25b93cdb133d719c79392c290a4b9089fd0bba156256c521500;

    function _acctSlot(bytes32 ua) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(ua, BASE + 8)));
    }

    function _pendingSlot(bytes32 ua, uint256 i) internal pure returns (bytes32) {
        return keccak256(abi.encode(uint256(i), _acctSlot(ua) + 4));
    }

    /// `accUnits` (bits 192..224 of the account's slot 1) written directly.
    function _setUnits(PqzLayer t, bytes32 ua, uint256 units) internal {
        bytes32 k = bytes32(_acctSlot(ua) + 1);
        uint256 w = uint256(vm.load(address(t), k));
        w = (w & ~(uint256(type(uint32).max) << 192)) | (units << 192);
        vm.store(address(t), k, bytes32(w));
        assertEq(t.pqzAccount(ua).accUnits, units);
    }

    /// `T` of an op 1 statement (`pk_f ‖ pk_t ‖ [pk_a]` before it).
    function _tOf(bytes memory st, bool aud) internal pure returns (bytes memory) {
        return _slice(st, 640 + (aud ? 3 : 2) * PqzCt.PK, PqzCt.CT);
    }

    /// The expected `T` of a debit: the last debit's `(u, v_f)` plus every entry in `[lastP, p)` (D4 / D5).
    function _expectT(bytes32 ua, bytes memory ref, uint256 lastP, uint256 p, uint256 shieldIn)
        internal view returns (bytes memory)
    {
        return _sumRange(ref, ua, lastP, p, shieldIn);
    }

    function _flags(PqzLayer t, bytes32 ua) internal view returns (uint8) {
        return t.pqzAccount(ua).flags;
    }
}

/// Plan 5h Task 2 (D1–D9, D18, D24): ciphertexts in state, B (credits never refused, ordered rollovers, the cap clamp),
/// the proof-free TRIVIAL shield, the hint, `ROLL_AGE`, CHAIN-01, restore from state. Proofs mocked, the rest real.
contract PqzStateTest is PqzSlots {
    bytes[] internal none;

    function setUp() public {
        _stack();
        tok = _newToken("pqz");
    }

    function _pl(uint256 p, bytes32 from, bytes32 to, uint256 seed, bool aud) internal view returns (bytes memory) {
        return _payload(p, 0, from, to, bytes32(0), _out(seed, aud), "");
    }

    function _send(bytes memory pl, bytes memory hint) internal {
        tok.mtxConfidentialTransferSingle(pl, hex"c0de", _mlAuth(), _benT(pl), hint);
    }

    /// The client's mirror of a direct op 1 debit of `pl` (out at 208).
    function _mirrorDebit(bytes32 from, bytes32 to, bytes memory pl) internal {
        bytes memory out = _slice(pl, PqzCore.T_OUT, pl.length - PqzCore.T_OUT);
        _afterDebit(from, _cut(out, 0, PqzCt.PK), _cut(out, PqzCt.CT, PqzCt.V));
        pend[to].push(_cut(out, 0, PqzCt.CT));
    }

    // ------------------------------------------------------------------ B: credits, the cap, ordered rollovers (D7, D8)

    /// D7: an `acc` at the old cap (`accUnits + unrolled + 2 > K_MAX` was `RefreshRequired`) still takes op 1 and op 7
    /// credits and shields; the queue just grows.
    function test_creditsBeyondTheOldCapAccepted() public {
        _setUnits(tok, bob, PqzCore.K_MAX - 1);
        _transfer(tok, carol, bob, bytes32(0), 1, false);
        _fund(tok, bob, 5);
        bytes32[] memory legs = new bytes32[](1);
        legs[0] = bob;
        bytes memory out = _blob(2, PqzCt.PK + 2 * PqzCt.V);
        bytes memory pl = bytes.concat(abi.encode(uint256(0), block.number + 100, uint256(0), alice, bytes32(0),
            uint256(1), uint256(0)), salt, legs[0], out);
        _mockOp(7, 1);
        tok.mtxConfidentialTransfer(pl, hex"c0de", _mlAuth(), _benM(pl), "");
        assertEq(tok.pqzAccount(bob).pendingCount, 3);
        assertEq(tok.pqzAccount(bob).accUnits, PqzCore.K_MAX - 1);
    }

    /// D8: a rollover is strictly `[rolled, rolled + n')`, `n' = min(n, K_MAX − 1 − accUnits)`; `CapReached` at the
    /// cap; a refresh at `p = rolled` (units `K_MAX`) resets `accUnits` to 1 and rollovers continue; the debit's
    /// `unitsOf(T)` check stays (a TRIVIAL entry counts one).
    function test_capClampCapReachedAndRefresh() public {
        for (uint256 i; i < 10; ++i) {
            _fund(tok, alice, 1 + i);
            vm.roll(block.number + 1);
        }
        _prepare(tok, alice);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollOverRange.selector, 0));
        tok.mtxRollOver(alice, 0);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollOverRange.selector, PqzCore.ROLL_MAX + 1));
        tok.mtxRollOver(alice, PqzCore.ROLL_MAX + 1);
        _setUnits(tok, alice, PqzCore.K_MAX - 4);
        vm.roll(block.number + ROLL_AGE);
        tok.mtxRollOver(alice, 10);
        IPqzToken.AccountState memory a = tok.pqzAccount(alice);
        assertEq(a.rolled, 3, "clamped to K_MAX - 1 - accUnits = 3");
        assertEq(a.accUnits, PqzCore.K_MAX - 1);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.CapReached.selector, alice));
        tok.mtxRollOver(alice, 1);
        // a debit past rolled at the cap: unitsOf(T) = K_MAX − 1 + 1 + 1 > K_MAX
        vm.expectRevert(IPqzToken.UnitsInvariant.selector);
        tok.transferSingleStatement(_pl(4, alice, bob, 1, false), 0);
        // the refresh at p = rolled: units K_MAX
        bytes memory pl = bytes.concat(abi.encode(uint256(3), block.number + 5, uint256(0), alice, bytes32(0)),
            _blob(9, PqzCt.CT));
        tok.mtxUnshield(pl, hex"c0de", _mlAuth(), _benM(pl), "", 0, bytes32(0));
        a = tok.pqzAccount(alice);
        assertEq(a.accUnits, 1, "refresh resets");
        assertEq(a.rolled, 3);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollOverRange.selector, 100));
        tok.mtxRollOver(alice, 100); // only 7 left: never a partial or skipping roll
        tok.mtxRollOver(alice, 7);
        assertEq(tok.pqzAccount(alice).rolled, 10);
        assertEq(tok.pqzAccount(alice).accUnits, 8);
    }

    /// The over-long rollover reverts `RollOverRange` (nothing is skipped or partially taken).
    function test_rolloverPastTheQueueReverts() public {
        _fund(tok, alice, 1);
        _prepare(tok, alice);
        vm.roll(block.number + ROLL_AGE);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollOverRange.selector, 2));
        tok.mtxRollOver(alice, 2);
        tok.mtxRollOver(alice, 1);
        assertEq(tok.pqzAccount(alice).rolled, 1);
    }

    /// D8: `AccNotPrepared` until both halves; `mtxPrepareAcc` is idempotent and keyed to a PQZ holder.
    function test_prepareAcc() public {
        _fund(tok, alice, 1);
        vm.roll(block.number + ROLL_AGE);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccNotPrepared.selector, alice));
        tok.mtxRollOver(alice, 1);
        tok.mtxPrepareAcc(alice, 0);
        assertEq(_flags(tok, alice), 2);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccNotPrepared.selector, alice));
        tok.mtxRollOver(alice, 1);
        tok.mtxPrepareAcc(alice, 1);
        tok.mtxPrepareAcc(alice, 1); // idempotent
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, 2));
        tok.mtxPrepareAcc(alice, 2);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, bytes32(uint256(5))));
        tok.mtxPrepareAcc(bytes32(uint256(5)), 0);
        tok.mtxRollOver(alice, 1);
        assertEq(_flags(tok, alice), 7, "materialised, both halves");
        assertEq(tok.pqzAcc(alice), _trivCt(1));
        tok.mtxPrepareAcc(alice, 0); // a no-op on a materialised acc
        assertEq(tok.pqzAcc(alice), _trivCt(1));
    }

    // ------------------------------------------------------------------ Review Focus 1: un-roll at the inline edge

    /// A rollover of `ROLL_MAX` entries, then a debit at exactly `p = rolled − INLINE_MAX` whose un-rolled window holds
    /// TRIVIAL entries and credits; the un-rolled entries are pending again, nothing lost, and roll again.
    function test_unrollAtTheInlineEdgeAfterRollMax() public {
        uint256 total = PqzCore.ROLL_MAX + 16;
        for (uint256 i; i < total; ++i) {
            if (i == 241 || i == 247 || i == 262) _transfer(tok, carol, alice, bytes32(0), 300 + i, false);
            else _fund(tok, alice, 1 + i);
            vm.roll(block.number + 1);
        }
        _roll(tok, alice, PqzCore.ROLL_MAX);
        IPqzToken.AccountState memory a = tok.pqzAccount(alice);
        uint256 r = PqzCore.ROLL_MAX;
        assertEq(a.rolled, r);
        assertEq(a.accUnits, r);
        assertEq(a.cleared, r - 16, "slots below rolled - INLINE_MAX deleted");
        assertEq(a.floor, r - 16);
        assertEq(tok.pqzPending(alice, uint64(r - 17)), 0);
        assertTrue(tok.pqzPending(alice, uint64(r - 16)) != 0);
        assertEq(tok.pqzAcc(alice), accOf[alice], "acc materialised = sum of the entries");
        // below the edge: refused
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PendingRange.selector, r - 17, r - 16, total));
        tok.transferSingleStatement(_pl(r - 17, alice, bob, 1, false), 0);
        // at the edge: T = acc − Σ pending[240 .. 256)
        bytes memory pl = _pl(r - 16, alice, bob, 2, false);
        bytes memory want = ct.sum(accOf[alice], none, _range(alice, r - 16, r), 0);
        assertEq(want, _expectT(alice, new bytes(PqzCt.CT), 0, r - 16, 0), "= sum [0, p)");
        assertEq(_tOf(tok.transferSingleStatement(pl, 0), false), want);
        _send(pl, "");
        _mirrorDebit(alice, bob, pl);
        a = tok.pqzAccount(alice);
        assertEq(a.rolled, r - 16, "un-rolled");
        assertEq(a.floor, r - 16);
        assertEq(a.accUnits, 1);
        for (uint256 i = r - 16; i < total; ++i) assertEq(tok.pqzPendingCt(alice, uint64(i)), _entCt(alice, i), "pending again");
        _roll(tok, alice, 32);
        assertEq(tok.pqzAccount(alice).rolled, total);
        assertEq(tok.pqzAcc(alice), accOf[alice], "rolled again, nothing lost");
    }

    // ------------------------------------------------------------------ Review Focus 2: the hint

    /// The hint never decides `T`: a stale hint (a rollover in between), a hint equal to the old materialised `acc`
    /// after a debit cleared the flag (its `accHash` still stored), and a malformed hint are ignored; a fresh hint is
    /// used, with the same `T`.
    function test_hint_staleFreshAndAfterDebit() public {
        for (uint256 i; i < 4; ++i) {
            _fund(tok, alice, 10 + i);
            vm.roll(block.number + 1);
        }
        _roll(tok, alice, 3);
        bytes memory h1 = tok.pqzAcc(alice);
        assertEq(h1, accOf[alice]);
        bytes memory pl = _pl(4, alice, bob, 1, false);
        bytes memory st = tok.transferSingleStatement(pl, 0);
        assertEq(_tOf(st, false), _expectT(alice, new bytes(PqzCt.CT), 0, 4, 0));
        _roll(tok, alice, 1); // anyone: h1 is stale now
        bytes memory h2 = tok.pqzAcc(alice); // the materialised acc the debit below replaces
        assertEq(keccak256(h2), tok.pqzAccount(alice).accHash);
        assertEq(tok.transferSingleStatement(pl, 0), st, "same T after the rollover");
        vm.expectCall(PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, hex"c0de"));
        _send(pl, h1);
        _mirrorDebit(alice, bob, pl);
        // after the debit the flag is clear but `accHash` still hashes h2: a hint of h2 must be ignored (the MAT check
        // is what keeps a spent acc from being reused: a double spend otherwise)
        IPqzToken.AccountState memory a = tok.pqzAccount(alice);
        assertEq(a.flags & 1, 0, "MATERIALISED cleared");
        assertEq(keccak256(h2), a.accHash, "the stale accHash still matches h2");
        assertEq(tok.pqzAcc(alice), accOf[alice], "fresh reference");
        bytes memory pl2 = _pl(4, alice, bob, 2, false);
        st = tok.transferSingleStatement(pl2, 0);
        assertEq(_tOf(st, false), accOf[alice], "T = the reference (p = rolled)");
        assertTrue(keccak256(_tOf(st, false)) != keccak256(h2), "h2 would give another T");
        vm.expectCall(PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, hex"c0de"));
        _send(pl2, h2);
        _mirrorDebit(alice, bob, pl2);
        // a materialised acc with its fresh hint, and with a malformed one: the same statement
        _fund(tok, alice, 7);
        _roll(tok, alice, 1);
        bytes memory h3 = tok.pqzAcc(alice);
        bytes memory pl3 = _pl(5, alice, bob, 3, false);
        st = tok.transferSingleStatement(pl3, 0);
        vm.expectCall(PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, hex"c0de"));
        uint256 g = gasleft();
        _send(pl3, h3);
        console2.log("op 1 with a valid hint (materialised acc) gas", g - gasleft());
        assertEq(_tOf(st, false), h3, "T = acc (p = rolled)");
        _mirrorDebit(alice, bob, pl3);
        bytes memory bad = bytes.concat(h3);
        bad[3] ^= 0x01;
        _fund(tok, alice, 8);
        _roll(tok, alice, 1);
        bytes memory pl4 = _pl(6, alice, bob, 4, false);
        st = tok.transferSingleStatement(pl4, 0);
        vm.expectCall(PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, hex"c0de"));
        _send(pl4, bad);
    }

    // ------------------------------------------------------------------ Review Focus 3: ROLL_AGE

    /// D6: a rollover takes entry `i` only at `block_i + ROLL_AGE`; the owner's own debit may take young entries inline.
    function test_rollTooYoungAndYoungInline() public {
        _fund(tok, alice, 5);
        _prepare(tok, alice);
        uint256 b0 = block.number;
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollTooYoung.selector, 0));
        tok.mtxRollOver(alice, 1);
        vm.roll(b0 + ROLL_AGE - 1);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollTooYoung.selector, 0));
        tok.mtxRollOver(alice, 1);
        vm.roll(b0 + ROLL_AGE);
        _fund(tok, alice, 6); // young entry 1
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.RollTooYoung.selector, 1));
        tok.mtxRollOver(alice, 2);
        tok.mtxRollOver(alice, 1);
        accOf[alice] = _trivCt(5);
        // the owner's debit takes the young entry inline in its own block
        bytes memory pl = _pl(2, alice, bob, 1, false);
        assertEq(_tOf(tok.transferSingleStatement(pl, 0), false), ct.sum(_trivCt(5), _range(alice, 1, 2), none, 0));
        _send(pl, "");
        assertEq(tok.pqzAccount(alice).rolled, 2);
    }

    // ------------------------------------------------------------------ the W-E races, now "a rollover between prove and submit still settles"

    /// `p ≥ rolled` at proving; anyone rolls up to `p` before the submit.
    function test_rollRace_rolloverUpToP() public {
        _transfer(tok, carol, alice, bytes32(0), 1, false);
        _fund(tok, alice, 3);
        vm.roll(block.number + 1);
        _transfer(tok, carol, alice, bytes32(0), 2, true);
        vm.roll(block.number + ROLL_AGE);
        bytes memory pl = _pl(3, alice, bob, 4, true);
        bytes memory st = tok.transferSingleStatement(pl, 0);
        _roll(tok, alice, 2);
        assertEq(tok.transferSingleStatement(pl, 0), st, "same T");
        vm.expectCall(PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, hex"c0de"));
        _send(pl, tok.pqzAcc(alice));
        IPqzToken.AccountState memory a = tok.pqzAccount(alice);
        assertEq(a.rolled, 3);
        assertEq(a.floor, 3);
        assertEq(a.accUnits, 1);
    }

    /// `p < rolled` at proving (an un-roll); anyone rolls further before the submit; the un-rolled entries roll again.
    function test_rollRace_unrollThenRollover() public {
        for (uint256 i; i < 3; ++i) _transfer(tok, carol, alice, bytes32(0), 10 + i, false);
        _roll(tok, alice, 3);
        bytes memory p1 = _pl(1, alice, bob, 20, false);
        _send(p1, "");
        _mirrorDebit(alice, bob, p1); // rolled 1: entries 1, 2 pending again
        assertEq(tok.pqzAccount(alice).rolled, 1);
        _fund(tok, alice, 9);
        _transfer(tok, carol, alice, bytes32(0), 13, false);
        vm.roll(block.number + ROLL_AGE);
        bytes memory pl = _pl(2, alice, bob, 21, false);
        bytes memory st = tok.transferSingleStatement(pl, 0);
        _roll(tok, alice, 4); // rolled 5
        assertEq(tok.pqzAccount(alice).rolled, 5);
        assertEq(tok.transferSingleStatement(pl, 0), st, "same T");
        vm.expectCall(PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, hex"c0de"));
        _send(pl, "");
        _mirrorDebit(alice, bob, pl);
        assertEq(tok.pqzAccount(alice).rolled, 2, "un-rolled to p");
        _roll(tok, alice, 3);
        assertEq(tok.pqzAcc(alice), accOf[alice]);
        assertEq(tok.pqzAccount(alice).accUnits, 4);
    }

    /// `p > rolled` at proving; after `ROLL_AGE` anyone rolls past `p`; the debit still settles and un-rolls.
    function test_rollRace_rolloverPastP() public {
        for (uint256 i; i < 5; ++i) _transfer(tok, carol, alice, bytes32(0), 30 + i, false);
        vm.roll(block.number + ROLL_AGE);
        bytes memory pl = _pl(2, alice, bob, 40, true);
        bytes memory st = tok.transferSingleStatement(pl, 0);
        _roll(tok, alice, 4);
        assertEq(tok.transferSingleStatement(pl, 0), st, "same T");
        vm.expectCall(PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, hex"c0de"));
        _send(pl, "");
        _mirrorDebit(alice, bob, pl);
        IPqzToken.AccountState memory a = tok.pqzAccount(alice);
        assertEq(a.rolled, 2, "rolled back to p");
        assertEq(a.accUnits, 1);
        assertEq(a.floor, 2);
        _roll(tok, alice, 3);
        assertEq(tok.pqzAccount(alice).rolled, 5);
        assertEq(tok.pqzAcc(alice), accOf[alice]);
    }

    // ------------------------------------------------------------------ Review Focus 9: TRIVIAL entries (D18)

    function test_trivial_mergeAndAppend() public {
        _fund(tok, alice, 5);
        _fund(tok, alice, 7); // same block: merged
        assertEq(tok.pqzAccount(alice).pendingCount, 1);
        uint256 e = tok.pqzPending(alice, 0);
        assertEq(e >> 160, 0, "blob field 0: TRIVIAL");
        assertEq((e >> 96) & type(uint64).max, 12, "amount");
        assertEq(uint64(e), block.number, "block");
        assertEq(tok.pqzPendingCt(alice, 0), _trivCt(12));
        vm.roll(block.number + 1);
        _fund(tok, alice, 1); // next block: appended
        assertEq(tok.pqzAccount(alice).pendingCount, 2);
        _transfer(tok, carol, alice, bytes32(0), 1, false); // a credit tail
        _fund(tok, alice, 2); // the tail is a credit: appended
        assertEq(tok.pqzAccount(alice).pendingCount, 4);
        assertEq(tok.totalShielded(), 15);
        _assertConservation(tok);
    }

    /// Never merge into a tail a same-block debit already spent (index < max(floor, rolled)).
    function test_trivial_noMergeIntoASpentTail() public {
        _fund(tok, alice, 5);
        bytes memory pl = _pl(1, alice, bob, 1, false);
        _send(pl, ""); // spends entry 0 inline, same block
        _fund(tok, alice, 4);
        assertEq(tok.pqzAccount(alice).pendingCount, 2, "appended, not merged into the spent entry");
        assertEq(tok.pqzPending(alice, 0), 0, "the spent entry deleted by the debit");
        assertEq((tok.pqzPending(alice, 1) >> 96) & type(uint64).max, 4);
    }

    /// A third-party shield between prove (state of an earlier block) and submit appends after `p`: the debit's `T`
    /// is unchanged and it settles; the shielded amount stays pending.
    function test_trivial_thirdPartyShieldBetweenProveAndSubmit() public {
        _fund(tok, alice, 5);
        vm.roll(block.number + 1);
        bytes memory pl = _pl(1, alice, bob, 1, false);
        bytes memory st = tok.transferSingleStatement(pl, 0);
        address mallory = address(0xBAD);
        _public(tok, mallory, 3 * SCALE);
        vm.prank(mallory);
        tok.mtxShield(alice, 3);
        assertEq(tok.pqzAccount(alice).pendingCount, 2, "appended (the tail is of an earlier block)");
        assertEq(tok.transferSingleStatement(pl, 0), st, "same T");
        vm.expectCall(PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, hex"c0de"));
        _send(pl, "");
        assertEq((tok.pqzPending(alice, 1) >> 96) & type(uint64).max, 3, "still pending");
        assertEq(tok.pqzAccount(alice).rolled, 1);
    }

    /// The documented residual of spec §5.9 (pinned, intentional): a debit whose window holds an entry of its own block
    /// (its submitter predicted it, e.g. shield and debit bundled into one block) can be made to revert by a
    /// third-party merge into that entry before it; wallets use the same-call `shieldIn` for "shield and spend now".
    function test_trivial_sameBlockResidual() public {
        _fund(tok, alice, 5); // entry 0, this block
        bytes memory pl = _pl(1, alice, bob, 1, false); // its window holds entry 0
        bytes memory st = tok.transferSingleStatement(pl, 0);
        _mockOp(1, 0);
        vm.mockCall(PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, hex"c0de"), abi.encode(uint256(1)));
        address mallory = address(0xBAD);
        _public(tok, mallory, SCALE);
        vm.prank(mallory);
        tok.mtxShield(alice, 1); // merged into entry 0: T changes
        assertEq(tok.pqzAccount(alice).pendingCount, 1, "merged");
        assertTrue(keccak256(tok.transferSingleStatement(pl, 0)) != keccak256(st));
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        _send(pl, "");
        // re-proven in the next block: a later shield appends after `p` and the debit settles
        vm.roll(block.number + 1);
        st = tok.transferSingleStatement(pl, 0);
        vm.mockCall(PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, hex"c0de"), abi.encode(uint256(1)));
        _public(tok, mallory, SCALE);
        vm.prank(mallory);
        tok.mtxShield(alice, 1);
        assertEq(tok.pqzAccount(alice).pendingCount, 2, "appended");
        _send(pl, "");
        assertEq(tok.pqzAccount(alice).rolled, 1);
    }

    /// TRIVIAL entries on both sides of `p` in an un-roll: `T` is exact; `unitsOf` counts each entry.
    function test_trivial_bothSidesOfPAndUnits() public {
        for (uint256 i; i < 6; ++i) {
            _fund(tok, alice, 100 + i);
            vm.roll(block.number + 1);
        }
        _roll(tok, alice, 6);
        bytes memory pl = _pl(3, alice, bob, 1, false);
        assertEq(_tOf(tok.transferSingleStatement(pl, 0), false), _expectT(alice, new bytes(PqzCt.CT), 0, 3, 0));
        _send(pl, "");
        _mirrorDebit(alice, bob, pl);
        // 3 pending again + accUnits 1 + 1: units 5
        _setUnits(tok, alice, PqzCore.K_MAX - 4);
        tok.transferSingleStatement(_pl(6, alice, bob, 2, false), 0); // K_MAX − 4 + 3 + 1 = K_MAX
        _fund(tok, alice, 1);
        vm.expectRevert(IPqzToken.UnitsInvariant.selector);
        tok.transferSingleStatement(_pl(7, alice, bob, 2, false), 0);
    }

    /// `shieldIn`: the same-call top-up from the signer's public balance, one `Trivial(digits(shieldIn))` term.
    function test_shieldIn() public {
        _fund(tok, alice, 5);
        _public(tok, address(this), 40 * SCALE);
        bytes memory pl = _payload(1, 40, alice, bob, bytes32(0), _out(1, false), "");
        bytes memory st = tok.transferSingleStatement(pl, 0);
        assertEq(uint256(bytes32(_cut(st, 480, 32))), 40, "header word 480 = shieldIn");
        assertEq(_tOf(st, false), _expectT(alice, new bytes(PqzCt.CT), 0, 1, 40));
        _send(pl, "");
        assertEq(tok.balanceOf(address(this)), 0, "taken from the signer");
        assertEq(tok.totalShielded(), 45);
        _assertConservation(tok);
        // over the cap or over the balance
        pl = _payload(1, 1 << 41, alice, bob, bytes32(0), _out(2, false), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AmountOutOfRange.selector, uint256(1) << 41,
            (uint256(1) << 40) - 45));
        _send(pl, "");
        vm.expectRevert();
        _send(_payload(1, 1, alice, bob, bytes32(0), _out(2, false), ""), "");
    }

    // ------------------------------------------------------------------ Review Focus 12: CHAIN-01 (D24)

    function test_zeroURefused() public {
        bytes memory out = _out(1, true);
        for (uint256 i; i < PqzCt.PK; ++i) out[i] = 0;
        vm.expectRevert(IPqzToken.ZeroU.selector);
        _send(_payload(0, 0, alice, bob, bytes32(0), out, ""), "");
        // op 7, M = 8: either group's u all zero
        _mockOp(7, 1);
        bytes32[] memory legs = new bytes32[](8);
        legs[0] = bob;
        legs[1] = carol;
        for (uint256 j = 2; j < 8; ++j) legs[j] = _pqzUA(_pk(uint8(40 + j)), uint8(40 + j));
        for (uint256 g; g < 2; ++g) {
            bytes memory o7 = _blob(2, 2 * PqzCt.PK + 9 * PqzCt.V);
            for (uint256 i; i < PqzCt.PK; ++i) o7[g * PqzCt.PK + i] = 0;
            bytes memory pl = bytes.concat(abi.encode(uint256(0), block.number + 100, uint256(0), alice, bytes32(0),
                uint256(8), uint256(0)), salt, abi.encodePacked(legs), o7);
            vm.expectRevert(IPqzToken.ZeroU.selector);
            tok.mtxConfidentialTransfer(pl, hex"c0de", _mlAuth(), _benM(pl), "");
        }
        // burn and refresh: u' all zero
        bytes memory nb = _blob(3, PqzCt.CT);
        for (uint256 i; i < PqzCt.PK; ++i) nb[i] = 0;
        bytes memory bp = bytes.concat(abi.encode(uint256(0), block.number + 5, uint256(0), alice, bytes32(0)), nb);
        vm.expectRevert(IPqzToken.ZeroU.selector);
        tok.mtxUnshield(bp, hex"c0de", _mlAuth(), _benM(bp), "", 1, bytes32(uint256(uint160(address(0xD00D)))));
        vm.expectRevert(IPqzToken.ZeroU.selector);
        tok.mtxUnshield(bp, hex"c0de", _mlAuth(), _benM(bp), "", 0, bytes32(0));
        // one non-zero coefficient is enough
        out[PqzCt.PK - 1] = 0x01;
        _send(_payload(0, 0, alice, bob, bytes32(0), out, ""), "");
    }

    // ------------------------------------------------------------------ restore from state (R-state, D13)

    /// A wallet rebuilds `acc` and every pending ciphertext from the views alone, through credits, merged shields, a
    /// rollover, a debit (the blob reference), an un-roll; burns and op 7 credits included.
    function test_restoreFromState() public {
        _transfer(tok, carol, alice, bytes32(0), 1, true);
        _fund(tok, alice, 3);
        _fund(tok, alice, 4);
        vm.roll(block.number + 1);
        _mockOp(7, 1);
        bytes32[] memory legs = new bytes32[](2);
        (legs[0], legs[1]) = (bob, alice);
        bytes memory o7 = _blob(5, PqzCt.PK + 3 * PqzCt.V + 2 * PqzCt.V);
        tok.mtxConfidentialTransfer(bytes.concat(abi.encode(uint256(0), block.number + 100, uint256(0), carol, bytes32(0),
            uint256(2), uint256(0)), salt, abi.encodePacked(legs), o7), hex"c0de", _mlAuth(), bytes32(0), "");
        pend[bob].push(bytes.concat(_cut(o7, 0, PqzCt.PK), _cut(o7, PqzCt.PK, PqzCt.V)));
        pend[alice].push(bytes.concat(_cut(o7, 0, PqzCt.PK), _cut(o7, PqzCt.PK + PqzCt.V, PqzCt.V)));
        _restoreCheck(alice);
        _roll(tok, alice, 2);
        _restoreCheck(alice);
        bytes memory nb = _blob(6, PqzCt.CT);
        bytes memory bp = bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), alice, bytes32(0)), nb);
        tok.mtxUnshield(bp, hex"c0de", _mlAuth(), _benM(bp), "", 2, bytes32(uint256(uint160(address(0xD00D)))));
        accOf[alice] = nb;
        _restoreCheck(alice);
        _restoreCheck(bob);
        _roll(tok, alice, 2);
        _restoreCheck(alice);
    }

    function _restoreCheck(bytes32 ua) internal view {
        IPqzToken.AccountState memory a = tok.pqzAccount(ua);
        assertEq(tok.pqzAcc(ua), _acc(ua), "acc from state");
        for (uint256 i = a.rolled; i < a.pendingCount; ++i) assertEq(tok.pqzPendingCt(ua, uint64(i)), _entCt(ua, i), "pending ct");
        if (a.flags & 1 != 0) assertEq(a.accHash, keccak256(tok.pqzAcc(ua)), "accHash of the materialised acc");
    }

    // ------------------------------------------------------------------ D1: the op blob is the bundle

    /// BUNDLE: `entryPtr` is the op blob (`R ‖ v_f`): no second SSTORE2, `transferEntry` = `R`, the hash unchanged.
    function test_opBlobIsTheBundle() public {
        (bytes32 ref, bytes memory out) = _transfer(tok, alice, bob, bytes32(0), 7, true);
        bytes memory r = bytes.concat(salt, _cut(out, 0, PqzCt.CT), _cut(out, 16_640, 128), bob);
        assertEq(tok.transferEntry(ref), r);
        assertEq(tok.transferCiphertextHash(ref), keccak256(r));
        IPqzToken.AccountState memory a = tok.pqzAccount(alice);
        assertEq(a.accBlob.code.length, 1 + r.length + PqzCt.V, "STOP, R, v_f");
        uint256 e = tok.pqzPending(bob, 0);
        assertEq(address(uint160(e >> 96)), a.accBlob, "the credit points into the sender's blob");
    }
}

/// The forge invariant of D4 / D5 (plan 5h Task 2): every entry below a debit's `p` is in exactly one of the spent
/// `T` (`[.., lastP)`), `acc` (`[lastP, rolled)`, with the last debit's `(u, v_f)`) or pending (`[rolled, pendingCount)`).
/// The handler checks each debit's `T` against `ref + Σ [lastP, p)`; the invariant checks `acc` and the pending
/// ciphertexts against the mirror.
contract PqzStateHandler is Test {
    PqzLayer internal tok;
    PqzCtHarness internal ct;
    bytes32 internal alice;
    bytes32 internal bob;
    bytes32 internal carol;
    bytes internal auth;
    bytes[] internal none;

    bytes public ref; // the last debit's (u, v_f) (zero before any)
    uint256 public lastP;
    bytes[] internal ents; // a credit's ct, or "" for a TRIVIAL entry (amount in `amts`)
    uint256[] internal amts;
    uint256[] internal blks; // the block each entry was appended in
    bytes internal lastMat; // the last materialised acc seen (a stale hint once a debit or rollover replaced it)
    uint256 internal seed;
    uint256 public debits;
    uint256 public rolls;

    constructor(PqzLayer t, PqzCtHarness c, bytes32 a, bytes32 b, bytes32 cr, bytes memory au) {
        (tok, ct, alice, bob, carol, auth) = (t, c, a, b, cr, au);
        ref = new bytes(PqzCt.CT);
    }

    function entCount() external view returns (uint256) {
        return ents.length;
    }

    function entAt(uint256 i) public view returns (bytes memory) {
        return ents[i].length != 0 ? ents[i] : _triv(amts[i]);
    }

    function _blob(uint256 s, uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; i += 32) {
            uint256 w = uint256(keccak256(abi.encode(s, i))) & 0x000000ffffffffff000000ffffffffff000000ffffffffff000000ffffffffff;
            assembly ("memory-safe") { mstore(add(add(b, 32), i), w) }
        }
    }

    function _triv(uint256 a) internal view returns (bytes memory) {
        return ct.sum(new bytes(PqzCt.CT), none, none, a);
    }

    function credit() external {
        bytes memory out = _blob(++seed, 16_640);
        bytes memory pl = bytes.concat(abi.encode(tok.pqzAccount(carol).pendingCount, block.number + 100, uint256(0),
            carol, alice, bytes32(0)), bytes16(uint128(seed)), out);
        tok.mtxConfidentialTransferSingle(pl, hex"c0de", auth, bytes32(0), "");
        bytes memory u = new bytes(PqzCt.CT);
        assembly ("memory-safe") { mcopy(add(u, 32), add(out, 32), 16512) }
        ents.push(u);
        amts.push(0);
        blks.push(block.number);
    }

    function shield(uint256 amount) external {
        amount = bound(amount, 1, 1000);
        IPqzToken.AccountState memory a = tok.pqzAccount(alice);
        uint256 n = ents.length;
        uint256 lo = a.floor > a.rolled ? a.floor : a.rolled;
        tok.mtxShield(alice, amount);
        if (n != 0 && ents[n - 1].length == 0 && blks[n - 1] == block.number && n - 1 >= lo) {
            amts[n - 1] += amount; // the mirror's own merge rule (D18)
        } else {
            ents.push("");
            amts.push(amount);
            blks.push(block.number);
        }
        assertEq(tok.pqzAccount(alice).pendingCount, ents.length, "mirror: merge / append");
    }

    function advance(uint256 k) external {
        vm.roll(block.number + bound(k, 1, 8));
    }

    /// Anyone's rollover after `ROLL_AGE` blocks (a keeper), of 1 .. all pending entries.
    function roll(uint256 n) external {
        IPqzToken.AccountState memory a = tok.pqzAccount(alice);
        if (a.pendingCount == a.rolled) return;
        vm.roll(block.number + 5);
        tok.mtxRollOver(alice, bound(n, 1, a.pendingCount - a.rolled));
        lastMat = tok.pqzAcc(alice);
        ++rolls;
    }

    /// `hint`: 0 none, 1 the current `pqzAcc` (a reference after a debit), 2 the last materialised `acc` (stale after
    /// a debit or a later rollover; its keccak may still be the stored `accHash`): `T` must be the state's every time.
    function debit(uint256 sel, uint8 hint) external {
        IPqzToken.AccountState memory a = tok.pqzAccount(alice);
        uint256 lo = a.rolled > 16 ? a.rolled - 16 : 0;
        if (lo < a.floor) lo = a.floor;
        uint256 hi = a.rolled + 16 < a.pendingCount ? a.rolled + 16 : a.pendingCount;
        if (hi < lo) return;
        uint256 p = bound(sel, lo, hi);
        bytes memory out = _blob(++seed, 16_640);
        bytes memory pl = bytes.concat(abi.encode(p, block.number + 100, uint256(0), alice, bob, bytes32(0)),
            bytes16(uint128(seed)), out);
        bytes memory st = tok.transferSingleStatement(pl, 0);
        bytes[] memory win = new bytes[](p - lastP);
        for (uint256 i; i < win.length; ++i) win[i] = entAt(lastP + i);
        bytes memory want = ct.sum(ref, win, none, 0);
        bytes memory got = new bytes(PqzCt.CT);
        assembly ("memory-safe") { mcopy(add(got, 32), add(add(st, 32), 33408), 16512) }
        assertEq(got, want, "T = ref + sum [lastP, p)");
        hint %= 3;
        bytes memory h = hint == 1 ? tok.pqzAcc(alice) : hint == 2 ? lastMat : bytes("");
        // the precompile accepts exactly the state's statement: a hint that changed `T` would be `ProofRejected`
        vm.mockCall(PqzSafety.PQZ, abi.encodePacked(uint8(1)), abi.encode(uint256(0)));
        vm.mockCall(PqzSafety.PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, hex"c0de"), abi.encode(uint256(1)));
        tok.mtxConfidentialTransferSingle(pl, hex"c0de", auth, bytes32(0), h);
        vm.mockCall(PqzSafety.PQZ, abi.encodePacked(uint8(1)), abi.encode(uint256(1)));
        bytes memory r = new bytes(PqzCt.CT);
        assembly ("memory-safe") {
            mcopy(add(r, 32), add(out, 32), 16384)
            mcopy(add(r, 16416), add(out, 16544), 128)
        }
        ref = r;
        lastP = p;
        ++debits;
    }
}

contract PqzStateInvariantTest is PqzFixture {
    PqzStateHandler internal h;

    function setUp() public {
        _stack();
        tok = _newToken("pqz");
        h = new PqzStateHandler(tok, ct, alice, bob, carol, _mlAuth());
        _public(tok, address(h), 1 << 38);
        tok.mtxPrepareAcc(alice, 0);
        tok.mtxPrepareAcc(alice, 1);
        targetContract(address(h));
        bytes4[] memory sel = new bytes4[](5);
        (sel[0], sel[1], sel[2]) = (PqzStateHandler.credit.selector, PqzStateHandler.shield.selector,
            PqzStateHandler.advance.selector);
        (sel[3], sel[4]) = (PqzStateHandler.roll.selector, PqzStateHandler.debit.selector);
        targetSelector(FuzzSelector(address(h), sel));
    }

    /// forge-config: default.invariant.runs = 16
    /// forge-config: default.invariant.depth = 32
    function invariant_everyEntryInExactlyOnePlace() public view {
        IPqzToken.AccountState memory a = tok.pqzAccount(alice);
        assertLe(a.cleared, a.floor);
        assertLe(a.floor, a.rolled);
        assertLe(a.rolled, a.pendingCount);
        assertEq(a.pendingCount, h.entCount());
        assertLe(h.lastP(), a.rolled);
        bytes[] memory acc = new bytes[](a.rolled - h.lastP());
        for (uint256 i; i < acc.length; ++i) acc[i] = h.entAt(h.lastP() + i);
        assertEq(tok.pqzAcc(alice), ct.sum(h.ref(), acc, new bytes[](0), 0), "acc = ref + sum [lastP, rolled)");
        for (uint256 i = a.rolled; i < a.pendingCount; ++i) assertEq(tok.pqzPendingCt(alice, uint64(i)), h.entAt(i));
    }

    function afterInvariant() external view {
        console2.log("debits / rolls", h.debits(), h.rolls());
    }
}
