// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {PqzFixture} from "./helpers/PqzFixture.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {SSTORE2} from "../../src/common/SSTORE2.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {UACall} from "../ua/UACall.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";

/// Group 3g, T52 (spec 2026-11-06-pqz-key-versions §3, §14 token rows; CTR-PQZ-31 draft): PQZ state per `(ua, version)`,
/// `sendCounter` per UA, credits to `current` read once, debits naming `keyVersion` (captured once), a stale version only
/// migrates (op 1 to itself) or refreshes, the keys of a statement pairwise distinct, rollover and prepare per version. The
/// PQZ precompile is mocked (`PqzFixture`); where a test needs "the proof of one exact statement" it answers 1 for exactly
/// that input and 0 for every other input of the op, so a statement that changes is a `ProofRejected`. UNAUDITED.
contract PqzKeyVersionsTokenTest is PqzFixture {
    bytes internal constant PROOF = hex"c0de";
    bytes32 internal constant D00D = bytes32(uint256(uint160(address(0xD00D))));

    function setUp() public {
        _stack();
        _mockOp(7, 1); // op 7 (R_TXM), as ops 1-5 in the fixture
        tok = _newToken("pqzver");
    }

    // ----- fixtures -----

    /// `ua` (a fixture `mldsa65` UA) adds PQZ key version `v` = `pk` and proves it: current becomes `v`. The consent is the
    /// mocked ML-DSA-65 precompile's, `R_REG` the mocked op 3's: the registry paths are real.
    function _rotate(bytes32 ua, uint64 v, bytes memory pk) internal {
        _addVersion(ua, v, pk);
        reg.storePqzPop(ua, v, abi.encodePacked("pqzver", ua, v));
        (uint64 cur,,,) = reg.pqzKeyOf(ua);
        assertEq(cur, v, "rotated");
    }

    /// Version `v` = `pk` stored, not proven (not current).
    function _addVersion(bytes32 ua, uint64 v, bytes memory pk) internal {
        reg.setPqzKey(ua, v, pk, keccak256(abi.encodePacked("pqzver", ua, v)), UACall.sig(new bytes(ML65_SIG)));
    }

    /// The precompile answers 1 for exactly `op ‖ len ‖ st ‖ PROOF`, 0 for any other input of `op`.
    function _exactOnly(uint8 op, bytes memory st) internal {
        vm.mockCall(PQZ, abi.encodePacked(op), abi.encode(uint256(0)));
        vm.mockCall(PQZ, abi.encodePacked(op, uint32(st.length), st, PROOF), abi.encode(uint256(1)));
    }

    function _keyAt(bytes32 ua, uint64 v) internal view returns (bytes memory) {
        (address p,,) = reg.pqzKeyAt(ua, v);
        return SSTORE2.read(p);
    }

    /// An op 1 of `from` (debit version `kv`) to `to` at `p`, no fee, no auditor copies.
    function _op1(bytes32 from, uint64 kv, bytes32 to, uint64 p, uint256 seed)
        internal view returns (IPqzToken.PqzTransferArgs memory t)
    {
        t = _ts(_payload(p, 0, from, to, bytes32(0), _out(seed, false), ""));
        t.keyVersion = kv;
    }

    /// An op 7 of `from` (version `kv`) to `legs`, no auditor copies.
    function _op7(bytes32 from, uint64 kv, bytes32[] memory legs, uint64 p, uint256 seed)
        internal view returns (IPqzToken.PqzMultiArgs memory t)
    {
        t = _ms(_mpayload(p, 0, from, bytes32(0), legs, _blob(seed, _outLen(legs.length, false)), ""));
        t.keyVersion = kv;
    }

    /// A burn (refresh with `amount` 0) of `from` (version `kv`) at `p`.
    function _burnArgs(bytes32 from, uint64 kv, uint64 p, uint256 seed) internal view returns (IPqzToken.PqzBurnArgs memory b) {
        b = _bs(bytes.concat(abi.encode(uint256(p), block.number + 50, uint256(0), from, bytes32(0)), _blob(seed, PqzCt.CT)));
        b.keyVersion = kv;
    }

    function _two(bytes32 a, bytes32 b) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](2);
        (l[0], l[1]) = (a, b);
    }

    function _staleErr(bytes32 ua, uint64 kv, uint64 cur) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IPqzToken.StaleKeyVersion.selector, ua, kv, cur);
    }

    function _pending(bytes32 ua, uint64 v) internal view returns (uint64) {
        return tok.pqzAccount(ua, v).pendingCount;
    }

    /// Shield `amount` into `ua`'s current version (a TRIVIAL entry).
    function _shield(bytes32 ua, uint256 amount) internal {
        _public(tok, address(this), amount * SCALE);
        tok.mtxShield(ua, amount);
    }

    // ----- the allow-lists (KV-10, §10 row 21) -----

    function _hasSel(address t, bytes4 sel) internal view returns (bool found) {
        (bytes4[] memory s,,) = IMetaTx(t).mtxSelectors();
        for (uint256 i; i < s.length; ++i) if (s[i] == sel) found = true;
    }

    function _selectors(address t) internal view {
        assertTrue(_hasSel(t, IPqzToken.mtxRollOver.selector), "mtxRollOver(bytes32,uint64,uint256)");
        assertTrue(_hasSel(t, IPqzToken.mtxPrepareAcc.selector), "mtxPrepareAcc(bytes32,uint64,uint256)");
        assertFalse(_hasSel(t, bytes4(keccak256("mtxRollOver(bytes32,uint256)"))), "no two-argument rollover");
        assertFalse(_hasSel(t, bytes4(keccak256("mtxPrepareAcc(bytes32,uint256)"))), "no two-argument prepare");
    }

    function test_mtxSelectors_pqzver_4() public view {
        _selectors(address(tok));
    }

    function test_mtxSelectors_pqzver_5() public {
        _releaseWrapped();
        _selectors(address(_newWrapped("pqzver-w")));
    }

    // ----- credits go to current (KV-7) -----

    /// After bob's rotation a credit lands in `(bob, 1)`, with the version in `Credited`; `(bob, 0)` is untouched.
    function test_credit_afterRotation_lands_vPlus1() public {
        _shield(alice, 100);
        _shield(bob, 7); // (bob, 0) has one TRIVIAL entry
        _rotate(bob, 1, _pk(31));
        _addVersion(bob, 2, _pk(35)); // the latest stored version, not current: no credit goes there (M-T1)
        vm.recordLogs();
        tok.mtxConfidentialTransferSingle(_op1(alice, 0, bob, 1, 5), PROOF, _pqAuth(), "");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool seen;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] != IPqzToken.Credited.selector) continue;
            assertEq(logs[i].topics[1], bob);
            (uint64 kv,) = abi.decode(logs[i].data, (uint64, bytes32));
            assertEq(kv, 1, "Credited names the version");
            seen = true;
        }
        assertTrue(seen);
        assertEq(_pending(bob, 1), 1, "the credit lands in (bob, 1)");
        assertEq(_pending(bob, 0), 1, "(bob, 0) untouched");
        assertEq(_pending(bob, 2), 0, "nothing in the latest, unproven version");
        // a shield too
        _shield(bob, 3);
        assertEq(_pending(bob, 1), 2);
    }

    /// J5 / M-T3: the receiver's key and version are read once (one `pqzKeyOf` of bob in the call).
    function test_credit_readOnce() public {
        _shield(alice, 100);
        _rotate(bob, 1, _pk(31));
        vm.expectCall(address(reg), abi.encodeCall(IUARegistry.pqzKeyOf, (bob)), 1);
        tok.mtxConfidentialTransferSingle(_op1(alice, 0, bob, 1, 5), PROOF, _pqAuth(), "");
    }

    /// Decoy legs to a rotated UA land on its current version (op 7).
    function test_decoys_landOnCurrent() public {
        _shield(alice, 100);
        _rotate(carol, 1, _pk(32));
        tok.mtxConfidentialTransfer(_op7(alice, 0, _two(bob, carol), 1, 6), PROOF, _pqAuth(), "");
        assertEq(_pending(carol, 1), 1);
        assertEq(_pending(carol, 0), 0);
        assertEq(_pending(bob, 0), 1);
    }

    /// A proof built against bob's version 0 and submitted after bob's rotation fails (`ProofRejected`): the statement now
    /// names bob's new key. Liveness only: nothing moves. Control: the same submission before the rotation lands.
    function test_inflight_precompile_refused() public {
        _shield(alice, 100);
        IPqzToken.PqzTransferArgs memory t = _op1(alice, 0, bob, 1, 5);
        _exactOnly(1, tok.transferSingleStatement(t, 0));
        uint256 snap = vm.snapshotState();
        tok.mtxConfidentialTransferSingle(t, PROOF, _pqAuth(), "");
        vm.revertToState(snap);
        _rotate(bob, 1, _pk(31));
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.mtxConfidentialTransferSingle(t, PROOF, _pqAuth(), "");
    }

    /// An auditor rotation: new copies go under the auditor's new key; a debit proven with the old copies is refused.
    function test_auditorRotation() public {
        _shield(alice, 100);
        IPqzToken.PqzTransferArgs memory t = _ts(_payload(1, 0, alice, bob, bytes32(0), _out(8, true), ""));
        bytes memory st = tok.transferSingleStatement(t, 0);
        assertEq(_slice(st, 640 + 2 * PqzCt.PK, PqzCt.PK), _keyAt(aud, 0), "pk_a: the auditor's version 0");
        _exactOnly(1, st);
        _rotate(aud, 1, _pk(33));
        assertEq(_slice(tok.transferSingleStatement(t, 0), 640 + 2 * PqzCt.PK, PqzCt.PK), _pk(33), "pk_a: version 1");
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.mtxConfidentialTransferSingle(t, PROOF, _pqAuth(), "");
    }

    // ----- debits name their version; a stale version only migrates or refreshes (KV-8) -----

    /// A burn issued for version 0 cannot be retargeted to version 1 by changing `keyVersion` (Codex #1): stale it is
    /// refused, retargeted the statement names version 1's key (equal `T`: both accounts empty at `p` 0) and the proof fails.
    function test_burn_v0_notRetargetable() public {
        _shield(alice, 100);
        IPqzToken.PqzBurnArgs memory b = _burnArgs(alice, 0, 0, 9);
        bytes memory st = tok.burnStatement(b, 10, D00D, 0);
        _exactOnly(2, st);
        _rotate(alice, 1, _pk(34));
        vm.expectRevert(_staleErr(alice, 0, 1));
        tok.mtxUnshield(b, 10, D00D, PROOF, _pqAuth(), "");
        b.keyVersion = 1;
        bytes memory st1 = tok.burnStatement(b, 10, D00D, 0);
        assertEq(_slice(st1, 640 + PqzCt.PK, PqzCt.CT), _slice(st, 640 + PqzCt.PK, PqzCt.CT), "the same T");
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.mtxUnshield(b, 10, D00D, PROOF, _pqAuth(), "");
    }

    function test_stale_payment_refused() public {
        _shield(alice, 100);
        _rotate(alice, 1, _pk(34));
        vm.expectRevert(_staleErr(alice, 0, 1));
        tok.mtxConfidentialTransferSingle(_op1(alice, 0, bob, 1, 5), PROOF, _pqAuth(), "");
        tok.mtxConfidentialTransferSingle(_op1(alice, 1, bob, 0, 5), PROOF, _pqAuth(), ""); // control: the current version
    }

    function test_stale_op7_refused() public {
        _shield(alice, 100);
        _rotate(alice, 1, _pk(34));
        vm.expectRevert(_staleErr(alice, 0, 1));
        tok.mtxConfidentialTransfer(_op7(alice, 0, _two(bob, carol), 1, 6), PROOF, _pqAuth(), "");
    }

    function test_stale_burnAmount_refused() public {
        _shield(alice, 100);
        _rotate(alice, 1, _pk(34));
        vm.expectRevert(_staleErr(alice, 0, 1));
        tok.mtxUnshield(_burnArgs(alice, 0, 1, 9), 10, D00D, PROOF, _pqAuth(), "");
    }

    /// A refresh (amount 0, no recipient) of a stale version works and settles that version.
    function test_stale_refresh_ok() public {
        _shield(alice, 100);
        _rotate(alice, 1, _pk(34));
        tok.mtxUnshield(_burnArgs(alice, 0, 1, 9), 0, bytes32(0), PROOF, _pqAuth(), "");
        assertEq(tok.pqzAccount(alice, 0).rolled, 1);
        assertEq(tok.pqzAcc(alice, 0), _blob(9, PqzCt.CT), "acc = the refresh's blob");
        assertEq(tok.pqzAccount(alice, 1).rolled, 0);
    }

    /// The migration: op 1 from `(alice, 0)` to alice herself, the credit in `(alice, 1)`; the books (J6) unchanged.
    function test_stale_migration_ok() public {
        _shield(alice, 100);
        _rotate(alice, 1, _pk(34));
        uint256 total = tok.totalShielded();
        tok.mtxConfidentialTransferSingle(_op1(alice, 0, alice, 1, 5), PROOF, _pqAuth(), "");
        assertEq(_pending(alice, 1), 1, "credited to (alice, 1)");
        assertEq(tok.pqzAccount(alice, 0).rolled, 1, "debited (alice, 0)");
        assertEq(tok.totalShielded(), total, "nothing left the pool");
        _assertConservation(tok);
    }

    /// `from == to` at the current version, and `from` as an op 7 leg at any version: `SelfTransfer` as today.
    function test_selfTransfer_current_refused() public {
        _shield(alice, 100);
        vm.expectRevert(IPqzToken.SelfTransfer.selector);
        tok.mtxConfidentialTransferSingle(_op1(alice, 0, alice, 1, 5), PROOF, _pqAuth(), "");
        _rotate(alice, 1, _pk(34));
        vm.expectRevert(IPqzToken.SelfTransfer.selector);
        tok.mtxConfidentialTransferSingle(_op1(alice, 1, alice, 0, 5), PROOF, _pqAuth(), "");
    }

    function test_selfTransfer_op7Leg_refused() public {
        _shield(alice, 100);
        vm.expectRevert(IPqzToken.SelfTransfer.selector);
        tok.mtxConfidentialTransfer(_op7(alice, 0, _two(bob, alice), 1, 6), PROOF, _pqAuth(), "");
        _rotate(alice, 1, _pk(34));
        vm.expectRevert(IPqzToken.SelfTransfer.selector);
        tok.mtxConfidentialTransfer(_op7(alice, 0, _two(bob, alice), 1, 6), PROOF, _pqAuth(), "");
    }

    /// `keyVersion` above current: `KeyVersionUnknown`; a stale version that never passed the key check: refused.
    function test_keyVersion_above_refused() public {
        _shield(alice, 100);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.KeyVersionUnknown.selector, alice, uint64(1)));
        tok.mtxConfidentialTransferSingle(_op1(alice, 1, bob, 1, 5), PROOF, _pqAuth(), "");
        _addVersion(alice, 1, _pk(34)); // stored, not proven: not current
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.KeyVersionUnknown.selector, alice, uint64(1)));
        tok.mtxConfidentialTransferSingle(_op1(alice, 1, bob, 1, 5), PROOF, _pqAuth(), "");
    }

    function test_keyVersion_unprovenStale_refused() public {
        bytes32 u = _mldsaUA(9);
        _addVersion(u, 0, _pk(40)); // version 0 unproven
        _rotate(u, 1, _pk(41));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, u));
        tok.mtxUnshield(_burnArgs(u, 0, 0, 9), 0, bytes32(0), PROOF, _pqAuth(), "");
    }

    /// M-T5's control (Codex #3): two versions with equal TRIVIAL balances; a debit on version 0 names version 0's key,
    /// builds `T` from `(alice, 0)` and settles `(alice, 0)`, and nothing of `(alice, 1)` changes.
    function test_equalTrivial_accountSettled() public {
        _shield(alice, 5);
        _rotate(alice, 1, _pk(34));
        _shield(alice, 5);
        IPqzToken.AccountState memory before = tok.pqzAccount(alice, 1);
        IPqzToken.PqzBurnArgs memory b = _burnArgs(alice, 0, 1, 9);
        bytes memory st = tok.burnStatement(b, 0, 0, 0);
        assertEq(_slice(st, 640, PqzCt.PK), _keyAt(alice, 0), "pk_f: version 0's key");
        assertEq(_slice(st, 640 + PqzCt.PK, PqzCt.CT), _trivCt(5), "T: (alice, 0)'s");
        tok.mtxUnshield(b, 0, bytes32(0), PROOF, _pqAuth(), "");
        IPqzToken.AccountState memory a0 = tok.pqzAccount(alice, 0);
        assertEq(abi.encode(a0.rolled, a0.floor, a0.cleared), abi.encode(uint64(1), uint64(1), uint64(1)), "(alice, 0) settled");
        IPqzToken.AccountState memory a1 = tok.pqzAccount(alice, 1);
        assertEq(abi.encode(a1.pendingCount, a1.rolled, a1.floor, a1.cleared, a1.accBlob, a1.accUnits, a1.flags, a1.accHash),
            abi.encode(before.pendingCount, before.rolled, before.floor, before.cleared, before.accBlob, before.accUnits,
                before.flags, before.accHash), "(alice, 1) untouched");
        assertEq(tok.pqzPending(alice, 1, 0) >> 96 & type(uint64).max, 5, "(alice, 1)'s entry still pending");
    }

    /// A replay of the migration after it landed is refused: the counter moved, the statement differs.
    function test_replay_afterMigration_refused() public {
        _shield(alice, 100);
        _rotate(alice, 1, _pk(34));
        IPqzToken.PqzTransferArgs memory t = _op1(alice, 0, alice, 1, 5);
        _exactOnly(1, tok.transferSingleStatement(t, 0));
        tok.mtxConfidentialTransferSingle(t, PROOF, _pqAuth(), "");
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.mtxConfidentialTransferSingle(t, PROOF, _pqAuth(), "");
    }

    /// One counter per UA across versions: debits on version 0 and version 1 get counters 0 and 1 and distinct entryRefs
    /// (J2; a counter per version would collide them).
    function test_counter_sharedAcrossVersions() public {
        _shield(alice, 100);
        _rotate(alice, 1, _pk(34));
        bytes32 r0 = tok.mtxConfidentialTransferSingle(_op1(alice, 0, alice, 1, 5), PROOF, _pqAuth(), "");
        vm.recordLogs();
        bytes32 r1 = tok.mtxConfidentialTransferSingle(_op1(alice, 1, bob, 1, 6), PROOF, _pqAuth(), "");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool seen;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] != IPqzToken.Debited.selector) continue;
            (uint64 kv,,,) = abi.decode(logs[i].data, (uint64, uint64, uint64, address));
            assertEq(kv, 1, "Debited names the version (M-T8)");
            seen = true;
        }
        assertTrue(seen);
        assertTrue(r0 != r1);
        assertEq(tok.pqzAccount(alice, 0).sendCounter, 2);
        assertEq(tok.pqzAccount(alice, 1).sendCounter, 2);
        assertTrue(tok.pqzEntryBlob(r0).length != 0 && tok.pqzEntryBlob(r1).length != 0);
    }

    // ----- the keys of a statement pairwise distinct (KV-9) -----

    /// Two legs of two UAs that stored one key (a registry without `keyOwner`; mocked here): `KeyReused`. Control: distinct.
    function test_keyReused_legs() public {
        _shield(alice, 100);
        IPqzToken.PqzMultiArgs memory t = _op7(alice, 0, _two(bob, carol), 1, 6);
        uint256 snap = vm.snapshotState();
        tok.mtxConfidentialTransfer(t, PROOF, _pqAuth(), "");
        vm.revertToState(snap);
        (uint64 v, address p, bytes32 ph, bool pr) = reg.pqzKeyOf(bob);
        vm.mockCall(address(reg), abi.encodeCall(IUARegistry.pqzKeyOf, (carol)), abi.encode(v, p, ph, pr));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.KeyReused.selector, carol));
        tok.mtxConfidentialTransfer(t, PROOF, _pqAuth(), "");
    }

    /// A leg equal to the auditor's key: `KeyReused`.
    function test_keyReused_auditor() public {
        _shield(alice, 100);
        IPqzToken.PqzTransferArgs memory t = _ts(_payload(1, 0, alice, bob, bytes32(0), _out(8, true), ""));
        (uint64 v, address p, bytes32 ph, bool pr) = reg.pqzKeyOf(aud);
        vm.mockCall(address(reg), abi.encodeCall(IUARegistry.pqzKeyOf, (bob)), abi.encode(v, p, ph, pr));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.KeyReused.selector, aud));
        tok.mtxConfidentialTransferSingle(t, PROOF, _pqAuth(), "");
    }

    /// A migration whose two versions hold one key (refused at storage by the registry; mocked here): `KeyReused`.
    function test_keyReused_migration() public {
        _shield(alice, 100);
        _rotate(alice, 1, _pk(34));
        (, address p, bytes32 ph, bool pr) = reg.pqzKeyOf(alice);
        vm.mockCall(address(reg), abi.encodeCall(IUARegistry.pqzKeyAt, (alice, uint64(0))), abi.encode(p, ph, pr));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.KeyReused.selector, alice));
        tok.mtxConfidentialTransferSingle(_op1(alice, 0, alice, 1, 5), PROOF, _pqAuth(), "");
    }

    // ----- rollover, prepare, views (KV-10) -----

    /// A stale version's queue drains by rollovers on that version.
    function test_rollover_stale() public {
        _shield(alice, 5);
        _rotate(alice, 1, _pk(34));
        tok.mtxPrepareAcc(alice, 0, 0);
        tok.mtxPrepareAcc(alice, 0, 1);
        vm.roll(block.number + ROLL_AGE);
        vm.expectEmit(address(tok));
        emit IPqzToken.PqzRolledOver(alice, 0, 1, 1, keccak256(_packed(_trivCt(5))));
        tok.mtxRollOver(alice, 0, 1);
        assertEq(tok.pqzAccount(alice, 0).rolled, 1);
        assertEq(tok.pqzAccount(alice, 1).rolled, 0);
    }

    /// A version that never passed the key check (stored, unproven): rollover and prepare refused.
    function test_rollover_neverChecked() public {
        _addVersion(alice, 1, _pk(34));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, alice));
        tok.mtxPrepareAcc(alice, 1, 0);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, alice));
        tok.mtxRollOver(alice, 1, 1);
    }

    /// Restore from state alone over two versions (§3.5): per version `pqzAccount`, `pqzAcc`, `pqzPendingCt`; the
    /// balance is the sum over versions.
    function test_restore_twoVersions() public {
        _shield(alice, 5);
        _rotate(alice, 1, _pk(34));
        _shield(alice, 7);
        uint256 total;
        for (uint64 v; v <= reg.pqzKeyLatest(alice); ++v) {
            IPqzToken.AccountState memory a = tok.pqzAccount(alice, v);
            assertEq(tok.pqzAcc(alice, v), new bytes(PqzCt.CT));
            for (uint64 i = a.rolled; i < a.pendingCount; ++i) {
                bytes memory c = tok.pqzPendingCt(alice, v, i);
                assertEq(c, _trivCt(v == 0 ? 5 : 7));
                total += v == 0 ? 5 : 7;
            }
        }
        assertEq(total, 12);
    }
}
