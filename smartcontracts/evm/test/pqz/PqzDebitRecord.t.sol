// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {stdJson} from "forge-std/StdJson.sol";
import {noVerdict} from "./helpers/PqzVerdicts.sol";
import {PqzFixture} from "./helpers/PqzFixture.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {UACall} from "../ua/UACall.sol";

/// Group 3h, T58 (spec 2026-11-06-pqz-proof-path §2, §11.1; CTR-PQZ-33 draft): every pending slot kept for good (PP-1), one
/// debit record per debit (PP-2). The PQZ precompile is mocked (`PqzFixture`). UNAUDITED.
contract PqzDebitRecordTest is PqzFixture {
    using stdJson for string;

    bytes internal constant PROOF = hex"c0de";
    bytes32 internal constant D00D = bytes32(uint256(uint160(address(0xD00D))));
    /// `debitRec`'s slot in `scaas.pqz` (test/v2/layout/namespaces.json; `test_layout_scaasPqz` reads the pin)
    uint256 internal constant REC_SLOT = 19;

    function setUp() public {
        _stack();
        _mockOp(7, 1);
        tok = _newToken("dr");
    }

    // ----- fixtures -----

    function _shield(bytes32 ua, uint256 amount) internal {
        _public(tok, address(this), amount * SCALE);
        tok.mtxShield(ua, amount);
    }

    /// `n` TRIVIAL entries into `ua`, one block apart (no same-block merge), `amount` `1 + i`.
    function _entries(bytes32 ua, uint256 n) internal {
        for (uint256 i; i < n; ++i) {
            _shield(ua, 1 + i);
            vm.roll(block.number + 1);
        }
    }

    /// An op 1 of `from` (version `kv`) to `to` at `p`, `shieldIn` topped up from the test's public balance.
    function _op1(bytes32 from, uint64 kv, bytes32 to, uint64 p, uint256 shieldIn, uint256 seed)
        internal returns (IPqzToken.PqzTransferArgs memory t)
    {
        if (shieldIn != 0) _public(tok, address(this), shieldIn * SCALE);
        t = _ts(_payload(p, shieldIn, from, to, bytes32(0), _out(seed, false), ""));
        t.keyVersion = kv;
    }

    function _send1(bytes32 from, uint64 kv, bytes32 to, uint64 p, uint256 shieldIn, uint256 seed) internal {
        tok.mtxConfidentialTransferSingle(_op1(from, kv, to, p, shieldIn, seed), PROOF, _pqAuth(), "", noVerdict());
    }

    /// A refresh (`amount` 0) or burn of `from` (version `kv`) at `p`.
    function _burnArgs(bytes32 from, uint64 kv, uint64 p, uint256 shieldIn, uint256 seed)
        internal returns (IPqzToken.PqzBurnArgs memory b)
    {
        if (shieldIn != 0) _public(tok, address(this), shieldIn * SCALE);
        b = _bs(bytes.concat(abi.encode(uint256(p), block.number + 50, shieldIn, from, bytes32(0)), _blob(seed, PqzCt.CT)));
        b.keyVersion = kv;
    }

    function _refresh(bytes32 from, uint64 kv, uint64 p, uint256 seed) internal {
        tok.mtxUnshield(_burnArgs(from, kv, p, 0, seed), 0, bytes32(0), PROOF, _pqAuth(), "", noVerdict());
    }

    /// Prepare both halves and roll `n` entries of `(ua, v)` after `ROLL_AGE` blocks, in rollovers of at most `ROLL_MAX` (32 at
    /// n2816-kmax65536).
    function _rollN(bytes32 ua, uint64 v, uint256 n) internal {
        uint8 f = tok.pqzAccount(ua, v).flags;
        if (f & 2 == 0) tok.mtxPrepareAcc(ua, v, 0);
        if (f & 4 == 0) tok.mtxPrepareAcc(ua, v, 1);
        vm.roll(block.number + ROLL_AGE);
        for (uint256 k; k < n; k += PqzCore.ROLL_MAX) tok.mtxRollOver(ua, v, n - k < PqzCore.ROLL_MAX ? n - k : PqzCore.ROLL_MAX);
    }

    function _slots(bytes32 ua, uint64 v, uint256 n) internal view returns (uint256[] memory s) {
        s = new uint256[](n);
        for (uint256 i; i < n; ++i) s[i] = tok.pqzPending(ua, v, uint64(i));
    }

    // ----- PP-1: pending slots kept -----

    /// A debit at `p` keeps every slot below `p` (the deletion of `[cleared, p)` is gone); `cleared` still moves to `p`.
    /// Control: the code before 3h deleted them.
    function test_debit_keepsPendingSlots() public {
        _entries(alice, 3);
        uint256[] memory before = _slots(alice, 0, 3);
        _send1(alice, 0, bob, 3, 0, 5);
        IPqzToken.AccountState memory a = tok.pqzAccount(alice, 0);
        assertEq(abi.encode(a.rolled, a.floor, a.cleared), abi.encode(uint64(3), uint64(3), uint64(3)), "the counters as before");
        for (uint256 i; i < 3; ++i) {
            assertTrue(before[i] != 0, "written");
            assertEq(tok.pqzPending(alice, 0, uint64(i)), before[i], "kept, unchanged");
        }
    }

    /// A rollover keeps every slot below `rolled - INLINE_MAX` (the deletion is gone); `cleared` and `floor` still follow
    /// `rolled - INLINE_MAX`. Control: the code before 3h deleted them.
    function test_rollover_keepsPendingSlots() public {
        _entries(alice, 40);
        uint256[] memory before = _slots(alice, 0, 40);
        _rollN(alice, 0, 40);
        IPqzToken.AccountState memory a = tok.pqzAccount(alice, 0);
        assertEq(abi.encode(a.rolled, a.floor, a.cleared), abi.encode(uint64(40), uint64(24), uint64(24)), "40 rolled, 24 below the window");
        for (uint256 i; i < 40; ++i) assertEq(tok.pqzPending(alice, 0, uint64(i)), before[i], "kept, unchanged");
    }

    /// `pqzPendingCt` below `cleared`: a credit's `u ‖ v` from its blob, a TRIVIAL entry `Trivial(digits(amount))`, as above it.
    function test_pendingCt_belowCleared() public {
        _shield(alice, 7);
        vm.roll(block.number + 1);
        bytes memory out = _out(11, false);
        tok.mtxConfidentialTransferSingle(_ts(_payload(0, 0, bob, alice, bytes32(0), out, "")), PROOF, _pqAuth(), "", noVerdict());
        _send1(alice, 0, carol, 2, 0, 5);
        assertEq(tok.pqzAccount(alice, 0).cleared, 2, "both below cleared");
        assertEq(tok.pqzPendingCt(alice, 0, 0), _trivCt(7), "the TRIVIAL entry");
        assertEq(tok.pqzPendingCt(alice, 0, 1), _cut(out, 0, PqzCt.CT), "the credit's u || v_t");
    }

    // ----- PP-2: the record -----

    /// Version `v` = `pk` of `ua`, stored and proven: current becomes `v` (as `PqzKeyVersionsTokenTest._rotate`).
    function _rotate(bytes32 ua, uint64 v, bytes memory pk) internal {
        reg.setPqzKey(ua, v, pk, keccak256(abi.encodePacked("pqzver", ua, v)), UACall.sig(new bytes(ML65_SIG)));
        reg.storePqzPop(ua, v, abi.encodePacked("pqzver", ua, v));
    }

    function _recSlot(bytes32 ua, uint64 k) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(uint256(k), keccak256(abi.encode(ua, uint256(PqzCore._STORAGE) + REC_SLOT)))));
    }

    function _rec(address prevBlob, uint64 p, uint16 dp, uint64 shieldIn, uint64 kv, uint64 prevCounter, bool hasPrev)
        internal pure returns (IPqzToken.DebitRecordView memory)
    {
        return IPqzToken.DebitRecordView(prevBlob, p, dp, 0, shieldIn, kv, prevCounter, hasPrev);
    }

    /// The view against `want`, and the two words in state against spec §2.2's layout: `w0 = prevBlob(160) ‖ p(64) ‖ Δp(16) ‖
    /// proofStore(8) ‖ flags(8)` (RECORD 1, WIDE 2), `w1 = shieldIn(64) ‖ keyVersion(64) ‖ prevCounter(64) ‖ 0` exactly when
    /// `shieldIn ≠ 0`, `keyVersion ≠ 0` or the predecessor is not `k − 1` (R1), else the slot never written.
    function _expect(bytes32 ua, uint64 k, IPqzToken.DebitRecordView memory w, string memory what) internal view {
        assertEq(abi.encode(tok.pqzDebitRecord(ua, k)), abi.encode(w), what);
        uint256 s = _recSlot(ua, k);
        bool wide = w.shieldIn != 0 || w.keyVersion != 0 || (w.hasPrev && w.prevCounter + 1 != k);
        assertEq(uint256(vm.load(address(tok), bytes32(s))), uint256(uint160(w.prevBlob)) << 96 | uint256(w.p) << 32
            | uint256(w.deltaP) << 16 | uint256(w.proofStore) << 8 | (wide ? 3 : 1), string.concat(what, ": w0"));
        assertEq(uint256(vm.load(address(tok), bytes32(s + 1))),
            wide ? uint256(w.shieldIn) << 192 | uint256(w.keyVersion) << 128 | uint256(w.prevCounter) << 64 : 0,
            string.concat(what, ": w1"));
    }

    function _blobOf(bytes32 ua, uint64 v) internal view returns (address) {
        return tok.pqzAccount(ua, v).accBlob;
    }

    function test_record_op1() public {
        _entries(alice, 2);
        _send1(alice, 0, bob, 2, 0, 5);
        address b0 = _blobOf(alice, 0);
        _expect(alice, 0, _rec(address(0), 2, 2, 0, 0, 0, false), "op 1, the first debit");
        assertEq(tok.pqzAccount(alice, 0).lastDebit, 1, "lastDebit = k + 1");
        _entries(alice, 1);
        _send1(alice, 0, bob, 3, 0, 6);
        _expect(alice, 1, _rec(b0, 3, 1, 0, 0, 0, true), "op 1 after op 1: narrow, prevCounter k - 1");
        assertEq(tok.pqzAccount(alice, 0).lastDebit, 2);
    }

    function test_record_op7() public {
        _entries(alice, 1);
        bytes32[] memory legs = new bytes32[](2);
        (legs[0], legs[1]) = (bob, carol);
        IPqzToken.PqzMultiArgs memory t = _ms(_mpayload(1, 0, alice, bytes32(0), legs, _blob(5, _outLen(2, false)), ""));
        tok.mtxConfidentialTransfer(t, PROOF, _pqAuth(), "", noVerdict());
        _expect(alice, 0, _rec(address(0), 1, 1, 0, 0, 0, false), "op 7");
        assertEq(tok.pqzAccount(alice, 0).lastDebit, 1);
    }

    function test_record_burn() public {
        _entries(alice, 2);
        tok.mtxUnshield(_burnArgs(alice, 0, 2, 0, 9), 2, D00D, PROOF, _pqAuth(), "", noVerdict());
        _expect(alice, 0, _rec(address(0), 2, 2, 0, 0, 0, false), "burn");
    }

    function test_record_refresh() public {
        _entries(alice, 1);
        _refresh(alice, 0, 1, 9);
        _expect(alice, 0, _rec(address(0), 1, 1, 0, 0, 0, false), "refresh");
    }

    /// Kind 5's `mtxUnshieldUnwrap` is the burn debit: one record.
    function test_record_unwrap() public {
        _releaseWrapped();
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.features = (1 << GovernanceBits.PAYABLE);
        (c.lockedFeatures, c.roles.minter) = (0, 0);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        WrappedPqzToken w = WrappedPqzToken(payable(factory.createToken(IOpenFactory.TokenKind.WRAPPED_PQZ, 1, abi.encode(c), "drw")));
        tok = PqzLayer(address(w));
        usd.mint(address(this), 10 * SCALE);
        usd.approve(address(w), type(uint256).max);
        w.mtxWrapShield(address(usd), 10 * SCALE, alice);
        IConfidentialWrappedToken.Unwrap memory x = IConfidentialWrappedToken.Unwrap(address(usd), D00D, 4, 4 * SCALE);
        w.mtxUnshieldUnwrap(_burnArgs(alice, 0, 1, 0, 9), x, PROOF, _pqAuth(), "", noVerdict());
        _expect(alice, 0, _rec(address(0), 1, 1, 0, 0, 0, false), "unwrap");
    }

    /// A 3g migration (op 1 from a stale version to the holder itself) records the version it debited.
    function test_record_migration() public {
        _entries(alice, 1);
        _rotate(alice, 1, _pk(34));
        _send1(alice, 0, alice, 1, 0, 5);
        _expect(alice, 0, _rec(address(0), 1, 1, 0, 0, 0, false), "the migration debits version 0");
        assertEq(tok.pqzAccount(alice, 0).lastDebit, 1);
        assertEq(tok.pqzAccount(alice, 1).lastDebit, 0, "the credited version has no debit");
    }

    function test_record_wide_shieldIn() public {
        _send1(alice, 0, bob, 0, 3, 5);
        _expect(alice, 0, _rec(address(0), 0, 0, 3, 0, 0, false), "shieldIn alone: wide (M18)");
    }

    function test_record_wide_keyVersion() public {
        _rotate(alice, 1, _pk(34));
        _shield(alice, 5);
        _send1(alice, 1, bob, 1, 0, 5);
        _expect(alice, 0, _rec(address(0), 1, 1, 0, 1, 0, false), "keyVersion alone: wide (R1, M5)");
    }

    /// Version 0 at k 0, version 1 at k 1, version 0 again at k 2: its predecessor is k 0, not k − 1.
    function test_record_wide_prevNotPrevious() public {
        _entries(alice, 1);
        _send1(alice, 0, bob, 1, 0, 5);
        address b0 = _blobOf(alice, 0);
        _rotate(alice, 1, _pk(34));
        _shield(alice, 5);
        _send1(alice, 1, bob, 1, 0, 6);
        _refresh(alice, 0, 1, 7);
        _expect(alice, 2, _rec(b0, 1, 0, 0, 0, 0, true), "the predecessor k 0: wide");
    }

    /// A narrow record writes `w0` and never touches `w1`'s slot.
    function test_record_narrow() public {
        _entries(alice, 1);
        _send1(alice, 0, bob, 1, 0, 5);
        address b0 = _blobOf(alice, 0);
        _entries(alice, 1);
        IPqzToken.PqzTransferArgs memory t = _op1(alice, 0, bob, 2, 0, 6);
        uint256 s = _recSlot(alice, 1);
        vm.record();
        tok.mtxConfidentialTransferSingle(t, PROOF, _pqAuth(), "", noVerdict());
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tok));
        (bool w0, bool w1) = (false, false);
        for (uint256 i; i < writes.length; ++i) {
            if (uint256(writes[i]) == s) w0 = true;
            if (uint256(writes[i]) == s + 1) w1 = true;
        }
        for (uint256 i; i < reads.length; ++i) if (uint256(reads[i]) == s + 1) w1 = true;
        assertTrue(w0, "w0 written");
        assertFalse(w1, "w1's slot not touched");
        _expect(alice, 1, _rec(b0, 2, 1, 0, 0, 0, true), "narrow");
    }

    function test_record_deltaP_first() public {
        _entries(alice, 3);
        _send1(alice, 0, bob, 3, 0, 5);
        _expect(alice, 0, _rec(address(0), 3, 3, 0, 0, 0, false), "the first debit: dp = p");
    }

    /// `Δp` is from the previous debit's `p`, not from `floor` (M21): the rollover moved `floor` to `rolled − INLINE_MAX`.
    function test_record_deltaP_afterRollover() public {
        _entries(alice, 1);
        _send1(alice, 0, bob, 1, 0, 5);
        address b0 = _blobOf(alice, 0);
        _entries(alice, 40);
        _rollN(alice, 0, 40);
        assertEq(tok.pqzAccount(alice, 0).floor, 25, "floor moved");
        _send1(alice, 0, bob, 41, 0, 6);
        _expect(alice, 1, _rec(b0, 41, 40, 0, 0, 0, true), "dp 41 - 1");
    }

    /// An un-roll (`p < rolled`): `Δp = p − p_prev`.
    function test_record_deltaP_unroll() public {
        _entries(alice, 1);
        _send1(alice, 0, bob, 1, 0, 5);
        address b0 = _blobOf(alice, 0);
        _entries(alice, 10);
        _rollN(alice, 0, 10);
        assertEq(tok.pqzAccount(alice, 0).rolled, 11);
        _send1(alice, 0, bob, 5, 0, 6);
        _expect(alice, 1, _rec(b0, 5, 4, 0, 0, 0, true), "un-rolled: dp 5 - 1");
    }

    /// A rollover leaves `accBlob` alone: the next debit's `prevBlob` is the previous debit's blob (C2).
    function test_record_prevBlob_afterRollover() public {
        _entries(alice, 1);
        _send1(alice, 0, bob, 1, 0, 5);
        address b0 = _blobOf(alice, 0);
        _entries(alice, 20);
        _rollN(alice, 0, 20);
        assertEq(_blobOf(alice, 0), b0, "the rollover kept accBlob");
        _send1(alice, 0, bob, 21, 0, 6);
        assertEq(tok.pqzDebitRecord(alice, 1).prevBlob, b0, "prevBlob: the previous debit's blob (M4)");
        assertTrue(_blobOf(alice, 0) != b0, "the new blob");
    }

    /// A rollover never lowers `floor`: below `cleared` it changes nothing (M17).
    function test_rollover_floorOnlyRises() public {
        _entries(alice, 16);
        _send1(alice, 0, bob, 16, 0, 5);
        _entries(alice, 4);
        _rollN(alice, 0, 4); // rolled 20: 20 − INLINE_MAX = 4 is below cleared 16
        IPqzToken.AccountState memory a = tok.pqzAccount(alice, 0);
        assertEq(abi.encode(a.rolled, a.floor, a.cleared), abi.encode(uint64(20), uint64(16), uint64(16)), "floor kept at the debit's p");
    }

    function test_lastDebit_perVersion() public {
        _entries(alice, 1);
        _send1(alice, 0, bob, 1, 0, 5);
        _rotate(alice, 1, _pk(34));
        assertEq(abi.encode(tok.pqzAccount(alice, 0).lastDebit, tok.pqzAccount(alice, 1).lastDebit), abi.encode(uint64(1), uint64(0)));
        _shield(alice, 5);
        _send1(alice, 1, bob, 1, 0, 6);
        assertEq(abi.encode(tok.pqzAccount(alice, 0).lastDebit, tok.pqzAccount(alice, 1).lastDebit), abi.encode(uint64(1), uint64(2)));
    }

    /// Each version's chain `lastDebit → prevCounter → …` across interleaved debits (Codex C6).
    function test_lastDebit_interleaved() public {
        _entries(alice, 1);
        _send1(alice, 0, bob, 1, 0, 5); // k 0, version 0
        address b0 = _blobOf(alice, 0);
        _rotate(alice, 1, _pk(34));
        _shield(alice, 5);
        _send1(alice, 1, bob, 1, 0, 6); // k 1, version 1
        address b1 = _blobOf(alice, 1);
        _refresh(alice, 0, 1, 7); // k 2, version 0
        address b2 = _blobOf(alice, 0);
        _refresh(alice, 1, 1, 8); // k 3, version 1
        assertEq(abi.encode(tok.pqzAccount(alice, 0).lastDebit, tok.pqzAccount(alice, 1).lastDebit), abi.encode(uint64(3), uint64(4)));
        _expect(alice, 3, _rec(b1, 1, 0, 0, 1, 1, true), "version 1's second debit: prevCounter 1");
        _expect(alice, 2, _rec(b0, 1, 0, 0, 0, 0, true), "version 0's second debit: prevCounter 0");
        _expect(alice, 1, _rec(address(0), 1, 1, 0, 1, 0, false), "version 1's first debit");
        _expect(alice, 0, _rec(address(0), 1, 1, 0, 0, 0, false), "version 0's first debit");
        assertTrue(b2 != b0, "a new blob");
    }

    /// No record before a debit or past the last; a first debit at `p` 0 is `w0 = RECORD` alone, never the zero word (C1, M6).
    function test_record_unknown_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.DebitRecordUnknown.selector, alice, uint64(0)));
        tok.pqzDebitRecord(alice, 0);
        _refresh(alice, 0, 0, 5);
        _expect(alice, 0, _rec(address(0), 0, 0, 0, 0, 0, false), "w0 = RECORD alone");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.DebitRecordUnknown.selector, alice, uint64(1)));
        tok.pqzDebitRecord(alice, 1);
    }

    /// The `Δp` field holds every debit's `p − p_prev` at this set: a first debit's `p ≤ K_MAX − 1` by the units rule, so
    /// the build's `PqzSet.DELTA_P_MAX` (a `uint16` literal from `gen_set.py`) is `K_MAX − 1`.
    function test_deltaP_fitsTheSet() public pure {
        assertEq(uint256(PqzSet.DELTA_P_MAX), PqzSet.K_MAX - 1);
    }

    // ----- spec §2.3: `T` of any debit from its one record and state (invariant P2's unit form) -----

    /// `(uOff, vOff)` of an op blob from its length: a burn's `u' ‖ v_f` is `CTP` bytes, a transfer's `salt ‖ u ‖ … ‖ v_f`.
    function _uv(address blob) internal view returns (uint256, uint256) {
        uint256 n = blob.code.length - 1;
        return n == PqzCt.CTP ? (0, PqzCt.PKP) : (16, n - PqzCt.VP);
    }

    /// `T_k` rebuilt from the record alone: `prevBlob`'s `(u, v_f)` + `Σ pending[p − Δp, p)` + `Trivial(digits(shieldIn))`.
    function _tOf(bytes32 ua, uint64 k) internal view returns (bytes memory) {
        IPqzToken.DebitRecordView memory r = tok.pqzDebitRecord(ua, k);
        bytes memory c = new bytes(PqzCt.CT);
        if (r.prevBlob != address(0)) {
            (uint256 uo, uint256 vo) = _uv(r.prevBlob);
            PqzCt.loadBlob(r.prevBlob, uo, vo, c);
        }
        bytes[] memory plus = new bytes[](r.deltaP);
        for (uint256 i; i < r.deltaP; ++i) plus[i] = tok.pqzPendingCt(ua, r.keyVersion, r.p - r.deltaP + uint64(i));
        return ct.sum(c, plus, new bytes[](0), r.shieldIn);
    }

    /// Random runs: shields (same-block merges included), credits, rollovers, and every debit form at a `p` up or down
    /// (un-rolls); each debit's `T`, read from its statement before it lands, equals `T` rebuilt from its record afterwards.
    /// forge-config: default.fuzz.runs = 12
    function test_T_fromOneRecord_equalsStatement(uint256 seed) public {
        for (uint256 step; step < 14; ++step) {
            uint256 r = uint256(keccak256(abi.encode(seed, step)));
            uint256 a = r % 7;
            IPqzToken.AccountState memory s = tok.pqzAccount(alice, 0);
            if (a == 0) {
                _shield(alice, 1 + (r >> 8) % 5);
                if ((r >> 16) & 1 == 1) _shield(alice, 2); // the same block: merged into the tail when it may be
                vm.roll(block.number + 1);
            } else if (a == 1) {
                tok.mtxConfidentialTransferSingle(_ts(_payload(0, 0, bob, alice, bytes32(0), _out(r, false), "")), PROOF,
                    _pqAuth(), "", noVerdict());
                vm.roll(block.number + 1);
            } else if (a == 2) {
                if (s.pendingCount > s.rolled) _rollN(alice, 0, 1 + (r >> 8) % (s.pendingCount - s.rolled));
            } else {
                _debitRandom(a, r, s);
            }
        }
    }

    function _debitRandom(uint256 a, uint256 r, IPqzToken.AccountState memory s) internal {
        uint256 lo = s.rolled > 16 && s.rolled - 16 > s.floor ? s.rolled - 16 : s.floor;
        uint256 hi = s.rolled + 16 < s.pendingCount ? s.rolled + 16 : s.pendingCount;
        uint64 p = uint64(lo + (r >> 8) % (hi - lo + 1));
        uint256 sIn = (r >> 24) % 3;
        bytes memory t = a == 3 ? _randomOp1(p, sIn, r) : a == 4 ? _randomOp7(p, sIn, r) : _randomBurn(a, p, sIn, r);
        assertEq(_tOf(alice, s.sendCounter), t, "T from the record = the statement's T");
        assertEq(tok.pqzDebitRecord(alice, s.sendCounter).p, p);
    }

    /// Each form: its statement's `T`, read before the debit lands.
    function _randomOp1(uint64 p, uint256 sIn, uint256 r) internal returns (bytes memory t) {
        IPqzToken.PqzTransferArgs memory x = _op1(alice, 0, carol, p, sIn, r);
        t = _cut(tok.transferSingleStatement(x, 0), 640 + 2 * PqzCt.PK, PqzCt.CT);
        tok.mtxConfidentialTransferSingle(x, PROOF, _pqAuth(), "", noVerdict());
    }

    function _randomOp7(uint64 p, uint256 sIn, uint256 r) internal returns (bytes memory t) {
        if (sIn != 0) _public(tok, address(this), sIn * SCALE);
        bytes32[] memory legs = new bytes32[](1);
        legs[0] = carol;
        IPqzToken.PqzMultiArgs memory x = _ms(_mpayload(p, sIn, alice, bytes32(0), legs, _blob(r, _outLen(1, false)), ""));
        t = _cut(tok.transferStatement(x, 0), 640 + 2 * PqzCt.PK, PqzCt.CT);
        tok.mtxConfidentialTransfer(x, PROOF, _pqAuth(), "", noVerdict());
    }

    /// `a` 5: a burn of 1 when the pool has it, else a refresh; `a` 6: a refresh.
    function _randomBurn(uint256 a, uint64 p, uint256 sIn, uint256 r) internal returns (bytes memory t) {
        uint256 amount = a == 5 && tok.totalShielded() + sIn > 0 ? 1 : 0;
        IPqzToken.PqzBurnArgs memory b = _burnArgs(alice, 0, p, sIn, r);
        bytes32 to = amount == 0 ? bytes32(0) : D00D;
        t = _cut(tok.burnStatement(b, amount, to, 0), 640 + PqzCt.PK, PqzCt.CT);
        tok.mtxUnshield(b, amount, to, PROOF, _pqAuth(), "", noVerdict());
    }

    // ----- the pin -----

    /// `scaas.pqz`'s new rows, read from test/v2/layout/namespaces.json, against a real debit's writes: `lastDebit` in the
    /// account slot `sendCounter` left in 3g, `debitRec[ua][k].w0` / `.w1` appended.
    function test_layout_scaasPqz() public {
        _send1(alice, 0, bob, 0, 3, 5); // k 0, wide (shieldIn 3)
        IPqzToken.DebitRecordView memory r = tok.pqzDebitRecord(alice, 0);
        string memory pin = vm.readFile("./test/v2/layout/namespaces.json");
        string[] memory labels = pin.readStringArray(".pqz.labels");
        uint256[] memory slots = pin.readUintArray(".pqz.slots");
        uint256[] memory inner = pin.readUintArray(".pqz.inner");
        uint256[] memory at = pin.readUintArray(".pqz.bytes");
        uint256[] memory widths = pin.readUintArray(".pqz.widths");
        string[3] memory want = ["acct[U][7].lastDebit", "debitRec[U][7].w0", "debitRec[U][7].w1"];
        assertEq(r.prevBlob, address(0), "a first debit");
        uint256[3] memory value = [uint256(1), 3, uint256(3) << 192]; // lastDebit k + 1; w0 RECORD | WIDE; w1 shieldIn 3
        uint256 found;
        for (uint256 i; i < labels.length; ++i) {
            for (uint256 j; j < 3; ++j) {
                if (keccak256(bytes(labels[i])) != keccak256(bytes(want[j]))) continue;
                uint256 sl = uint256(keccak256(abi.encode(uint256(0), keccak256(abi.encode(alice, uint256(PqzCore._STORAGE) + slots[i])))));
                uint256 word = uint256(vm.load(address(tok), bytes32(sl + inner[i])));
                uint256 mask = widths[i] == 32 ? type(uint256).max : (uint256(1) << (8 * widths[i])) - 1;
                assertEq((word >> (8 * at[i])) & mask, value[j], want[j]);
                ++found;
            }
        }
        assertEq(found, 3, "the three rows pinned");
        assertEq(slots[labels.length - 1], REC_SLOT, "debitRec appended last");
    }
}
