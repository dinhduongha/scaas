// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {PqzSlots} from "./PqzState.t.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";

/// Plan 5h Task 2 gas (Review Focus 5, 6; spec §5.3 / §5.4) on the real token: `ROLL_MAX` and the `mtxPrepareAcc` halves
/// pinned under `0.75 · 2^24`, the shield (append, merge) and the per-op table. Each test is one transaction after
/// `setUp` (a slot written in `setUp` is clean and cold in the test, as on chain; `PqzStateSteadyGasTest*` of the
/// prototype). Every rollover entry is a credit from its own op blob (distinct cold accounts, every coefficient `q − 1`).
/// Numbers are execution gas of the token call as it counts against the 2^24 cap: refunds not subtracted, calldata
/// and the 21,000 intrinsic not included, the precompile and the ML-DSA verification mocked.
/// Run: `../../scripts/capped forge test --match-contract PqzStatePinGasTest -vv` (log: runs/2026-10-20-5h-b-gas.txt).
contract PqzStatePinGasTest is PqzSlots {
    uint256 internal constant CAP = (uint256(1) << 24) * 3 / 4; // 12,582,912
    uint256 internal constant PRE = 16; // entries rolled in setUp (acc materialised)
    uint256 internal constant QM1 = PqzCt.Q - 1;

    bytes32 internal dave; // a second rolling account (the slope of ROLL_MAX)
    bytes32 internal eve; // never prepared
    bytes32 internal frank; // a TRIVIAL tail of the current block
    bytes32[8] internal xs;
    uint256 internal nextBlob = 0x5EED0000;

    function setUp() public {
        _stack();
        _mockOp(7, 1);
        tok = _newToken("gas");
        dave = _pqzUA(_pk(9), 9);
        eve = _pqzUA(_pk(10), 10);
        frank = _pqzUA(_pk(11), 11);
        for (uint8 i; i < 8; ++i) xs[i] = _pqzUA(_pk(20 + i), 20 + i);
        bytes memory code = _blobCode();
        _seed(alice, PRE + PqzCore.ROLL_MAX, code);
        _seed(dave, PRE + 128, code);
        vm.roll(block.number + 100);
        for (uint256 k; k < 2; ++k) {
            bytes32 ua = k == 0 ? alice : dave;
            tok.mtxPrepareAcc(ua, 0);
            tok.mtxPrepareAcc(ua, 1);
            tok.mtxRollOver(ua, PRE); // the first materialisation; the measured rollovers rewrite
        }
        _transfer(tok, carol, bob, bytes32(0), 1, true); // carol's acc: a fresh blob reference
        _fund(tok, bob, 1); // bob: an entry of an earlier block
        vm.roll(block.number + 1);
        _fund(tok, frank, 1); // frank: a TRIVIAL tail of the test's block
        _public(tok, address(this), 1000 * SCALE);
        _fund(tok, _pqzUA(_pk(12), 12), 100); // D19: the pool holds the fees the measured debits pay out
    }

    /// `STOP ‖ salt(16) ‖ u ‖ v_t ‖ toUA ‖ v_f`, every coefficient `q − 1` (the lane-overflow worst case).
    function _blobCode() internal pure returns (bytes memory c) {
        c = new bytes(1 + 16 + PqzCt.PK + 128 + 32 + 128);
        uint256 w = QM1 << 192 | QM1 << 128 | QM1 << 64 | QM1;
        for (uint256 o = 17; o < 17 + PqzCt.CT; o += 32) {
            assembly ("memory-safe") { mstore(add(add(c, 32), o), w) }
        }
    }

    /// `k` credits of `ua`, each pointing into its own etched blob (block 1, so old enough after `setUp`'s roll).
    function _seed(bytes32 ua, uint256 k, bytes memory code) internal {
        for (uint256 i; i < k; ++i) {
            address b = address(uint160(++nextBlob));
            vm.etch(b, code);
            uint256 e = uint256(uint160(b)) << 96 | uint256(16) << 80 | uint256(16 + PqzCt.PK) << 64 | 1;
            vm.store(address(tok), _pendingSlot(ua, i), bytes32(e));
        }
        vm.store(address(tok), bytes32(_acctSlot(ua)), bytes32(k));
    }

    function _gas(bytes memory data) internal returns (uint256 used) {
        uint256 g0 = gasleft();
        (bool ok, bytes memory ret) = address(tok).call(data);
        used = g0 - gasleft();
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
    }

    function _log(string memory what, uint256 g) internal pure {
        console2.log(string.concat(what, " gas"), g);
    }

    // ------------------------------------------------------------------ ROLL_MAX and prepare (Review Focus 5, 6)

    /// `ROLL_MAX` = the largest multiple of 16 under `0.75 · 2^24`: `ROLL_MAX` fits, `ROLL_MAX + 16` (the linear fit
    /// through a 128-entry rollover of another account) would not. The 128-entry call runs first under a snapshot that
    /// is reverted (`vm.revertToState` restores cold access too: `gMax` equals its value as the test's only call), so
    /// both are measured cold, as `test_gas_roll128` alone. Then the lanes: `acc` holds `16 (q − 1)`, the rollover adds
    /// `ROLL_MAX` entries of `q − 1`: every coefficient is `q − 272`.
    function test_gas_rollMax() public {
        uint256 snap = vm.snapshotState();
        uint256 g128 = _gas(abi.encodeCall(tok.mtxRollOver, (dave, 128)));
        vm.revertToState(snap);
        uint256 gMax = _gas(abi.encodeCall(tok.mtxRollOver, (alice, PqzCore.ROLL_MAX)));
        uint256 next = gMax + (gMax - g128) * 16 / (PqzCore.ROLL_MAX - 128);
        _log("mtxRollOver 128 (steady, distinct cold blobs)", g128);
        _log("mtxRollOver ROLL_MAX = 256 (steady, distinct cold blobs)", gMax);
        _log("mtxRollOver 272 (linear fit)", next);
        console2.log("per entry / fixed (fit)", (gMax - g128) / 128, gMax - (gMax - g128) * 2);
        assertLe(gMax, CAP, "ROLL_MAX under 0.75 * 2^24");
        assertGt(next, CAP, "ROLL_MAX + 16 over it");
        bytes memory acc = tok.pqzAcc(alice);
        uint256 want = PqzCt.Q - (PRE + PqzCore.ROLL_MAX);
        want = want << 192 | want << 128 | want << 64 | want;
        for (uint256 o; o < PqzCt.CT; o += 32) {
            uint256 w;
            assembly ("memory-safe") { w := mload(add(add(acc, 32), o)) }
            assertEq(w, want);
        }
    }

    function test_gas_roll128() public {
        _log("mtxRollOver 128 (steady, distinct cold blobs)", _gas(abi.encodeCall(tok.mtxRollOver, (dave, 128))));
    }

    function test_gas_roll_1() public {
        _log("mtxRollOver 1 (steady)", _gas(abi.encodeCall(tok.mtxRollOver, (alice, 1))));
    }

    function test_gas_roll_16() public {
        _log("mtxRollOver 16 (steady)", _gas(abi.encodeCall(tok.mtxRollOver, (alice, 16))));
    }

    /// Each half of the first materialisation in a transaction of its own (D8; spec §5.3).
    function test_gas_prepareAcc_half0() public {
        uint256 g = _gas(abi.encodeCall(tok.mtxPrepareAcc, (eve, 0)));
        _log("mtxPrepareAcc half 0", g);
        assertLe(g, CAP);
    }

    function test_gas_prepareAcc_half1() public {
        uint256 g = _gas(abi.encodeCall(tok.mtxPrepareAcc, (eve, 1)));
        _log("mtxPrepareAcc half 1", g);
        assertLe(g, CAP);
    }

    // ------------------------------------------------------------------ the shield (D18)

    function test_gas_shield_firstEntry() public {
        _log("mtxShield, the account's first entry (append)", _gas(abi.encodeCall(tok.mtxShield, (eve, 5))));
    }

    function test_gas_shield_append() public {
        _log("mtxShield, append (tail of an earlier block)", _gas(abi.encodeCall(tok.mtxShield, (bob, 5))));
    }

    function test_gas_shield_merge() public {
        uint256 g = _gas(abi.encodeCall(tok.mtxShield, (frank, 5)));
        assertEq(tok.pqzAccount(frank).pendingCount, 1, "merged");
        _log("mtxShield, merge (TRIVIAL tail of this block)", g);
    }

    // ------------------------------------------------------------------ debits (spec §5.4)

    function _op1(bytes32 from, uint256 p, bool aud, bytes memory hint) internal view returns (bytes memory) {
        return abi.encodeCall(tok.mtxConfidentialTransferSingle,
            (_payload(p, 0, from, bob, carol, _out(77, aud), ""), hex"c0de", _mlAuth(), carol, hint));
    }

    function test_gas_op1_bundle_freshRef() public {
        _log("op 1 BUNDLE, auditor, fee, p = rolled, acc = blob reference", _gas(_op1(carol, 0, true, "")));
    }

    function test_gas_op1_bundle_materialised_hint() public {
        bytes memory h = tok.pqzAcc(alice);
        _log("op 1 BUNDLE, auditor, fee, p = rolled, materialised acc, hint", _gas(_op1(alice, PRE, true, h)));
    }

    function test_gas_op1_bundle_materialised_noHint() public {
        _log("op 1 BUNDLE, auditor, fee, p = rolled, materialised acc, no hint", _gas(_op1(alice, PRE, true, "")));
    }

    function test_gas_op1_bundle_16inline() public {
        bytes memory h = tok.pqzAcc(alice);
        _log("op 1 BUNDLE, auditor, fee, 16 inline credits (cold blobs), hint", _gas(_op1(alice, PRE + 16, true, h)));
    }

    function test_gas_op1_compact() public {
        bytes memory d = abi.encodeCall(tok.mtxConfidentialTransferSingleCompact,
            (_payload(0, 0, carol, bob, alice, _out(78, true), _memo()), hex"c0de", _mlAuth(), alice, ""));
        _log("op 1 COMPACT (HASH), auditor, fee, fresh ref", _gas(d));
    }

    function test_gas_op1_shieldIn() public {
        bytes memory d = abi.encodeCall(tok.mtxConfidentialTransferSingle,
            (_payload(0, 100, carol, bob, alice, _out(80, true), ""), hex"c0de", _mlAuth(), alice, ""));
        _log("op 1 BUNDLE, auditor, fee, shieldIn 100, fresh ref", _gas(d));
    }

    function _op7(uint256 m) internal view returns (bytes memory) {
        bytes memory r;
        for (uint256 j; j < m; ++j) r = bytes.concat(r, xs[j]);
        uint256 g = (m + 3) / 4;
        bytes memory out = _blob(81 + m, PqzCt.PK * g + PqzCt.V * (m + 1) + PqzCt.V * m);
        return abi.encodeCall(tok.mtxConfidentialTransfer, (bytes.concat(abi.encode(uint256(0), block.number + 100, uint256(0),
            carol, alice, m, uint256(0)), salt, r, out), hex"c0de", _mlAuth(), alice, ""));
    }

    function test_gas_op7_M4() public {
        _log("op 7 M = 4 BUNDLE, auditor, fee, fresh ref (4 first credits)", _gas(_op7(4)));
    }

    function test_gas_op7_M8() public {
        _log("op 7 M = 8 BUNDLE, auditor, fee, fresh ref (8 first credits)", _gas(_op7(8)));
    }

    function _burn(uint256 amount, address to) internal view returns (bytes memory) {
        bytes memory pl = bytes.concat(abi.encode(uint256(0), block.number + 5, uint256(0), carol, alice), _blob(5, PqzCt.CT));
        return abi.encodeCall(tok.mtxUnshield, (pl, hex"c0de", _mlAuth(), _benM(pl), "", amount, bytes32(uint256(uint160(to)))));
    }

    function test_gas_refresh() public {
        _log("refresh, fee, fresh ref", _gas(_burn(0, address(0))));
    }

    function test_gas_burn() public {
        _log("burn 1 to an address, fee, fresh ref", _gas(_burn(1, address(0xD00D))));
    }
}

/// Final review I1 (D3 "the `acc` slots are never zeroed"): a shield-only account's first rollover sums TRIVIAL entries
/// only, so every `u` coefficient of its `acc` is 0. Each stored word carries a marker bit, so no slot goes back to zero
/// and the next rollover of `ROLL_MAX` cold credits still rewrites (2,900 gas a word), not re-creates (22,100), and
/// fits `0.75 · 2^24`. Each test is one transaction after `setUp`.
contract PqzStateTrivialRollGasTest is PqzSlots {
    uint256 internal constant CAP = (uint256(1) << 24) * 3 / 4;
    uint256 internal constant QM1 = PqzCt.Q - 1;
    uint256 internal constant TRIV = 4; // TRIVIAL entries rolled in setUp
    uint256 internal nextBlob = 0x5EED0000;
    bytes32 internal gina;

    function _blobCode() internal pure returns (bytes memory c) {
        c = new bytes(1 + 16 + PqzCt.PK + 128 + 32 + 128);
        uint256 w = QM1 << 192 | QM1 << 128 | QM1 << 64 | QM1;
        for (uint256 o = 17; o < 17 + PqzCt.CT; o += 32) {
            assembly ("memory-safe") { mstore(add(add(c, 32), o), w) }
        }
    }

    function _gas(bytes memory data) internal returns (uint256 used) {
        uint256 g0 = gasleft();
        (bool ok, bytes memory ret) = address(tok).call(data);
        used = g0 - gasleft();
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
    }

    function setUp() public {
        _stack();
        _mockOp(7, 1);
        tok = _newToken("gas");
        gina = _pqzUA(_pk(13), 13);
        tok.mtxPrepareAcc(gina, 0);
        tok.mtxPrepareAcc(gina, 1);
        _public(tok, address(this), TRIV * SCALE);
        for (uint256 i; i < TRIV; ++i) {
            tok.mtxShield(gina, 1);
            vm.roll(block.number + 1);
        }
        vm.roll(block.number + 30);
        tok.mtxRollOver(gina, TRIV); // acc = Trivial(4): every u coefficient 0
        // ROLL_MAX credits after the TRIVIAL entries, each from its own cold blob, every coefficient q − 1
        bytes memory code = _blobCode();
        for (uint256 i; i < PqzCore.ROLL_MAX; ++i) {
            address b = address(uint160(++nextBlob));
            vm.etch(b, code);
            uint256 e = uint256(uint160(b)) << 96 | uint256(16) << 80 | uint256(16 + PqzCt.PK) << 64 | 1;
            vm.store(address(tok), _pendingSlot(gina, TRIV + i), bytes32(e));
        }
        bytes32 k = bytes32(_acctSlot(gina));
        uint256 w = uint256(vm.load(address(tok), k));
        vm.store(address(tok), k, bytes32((w & ~uint256(type(uint64).max)) | (TRIV + PqzCore.ROLL_MAX)));
    }

    /// No `acc` slot is zero after the TRIVIAL-only rollover (D3), and the `u` half still reads as zero.
    function test_trivialRoll_noZeroSlot() public view {
        for (uint256 i; i < PqzCt.CT / 32; ++i) {
            assertTrue(vm.load(address(tok), bytes32(_acctSlot(gina) + 5 + i)) != 0, "acc slot zeroed");
        }
        bytes memory acc = tok.pqzAcc(gina);
        for (uint256 o; o < PqzCt.PK; o += 32) {
            uint256 x;
            assembly ("memory-safe") { x := mload(add(add(acc, 32), o)) }
            assertEq(x, 0, "u of Trivial(4)");
        }
        assertEq(keccak256(acc), tok.pqzAccount(gina).accHash, "accHash over the unmarked bytes");
    }

    /// The regression pin: `ROLL_MAX` cold credits after the TRIVIAL-only rollover fit `0.75 · 2^24` (10.6 M for
    /// n = 1 and 20.9 M for `ROLL_MAX` when the slots were zeroed), and every `u` coefficient is `256 (q − 1) mod q`.
    function test_gas_rollMax_afterTrivialRoll() public {
        uint256 g = _gas(abi.encodeCall(tok.mtxRollOver, (gina, PqzCore.ROLL_MAX)));
        console2.log("mtxRollOver ROLL_MAX after a TRIVIAL-only rollover gas", g);
        assertLe(g, CAP, "ROLL_MAX under 0.75 * 2^24");
        bytes memory acc = tok.pqzAcc(gina);
        uint256 want = PqzCt.Q - PqzCore.ROLL_MAX;
        want = want << 192 | want << 128 | want << 64 | want;
        for (uint256 o; o < PqzCt.PK; o += 32) {
            uint256 x;
            assembly ("memory-safe") { x := mload(add(add(acc, 32), o)) }
            assertEq(x, want);
        }
        assertEq(keccak256(acc), tok.pqzAccount(gina).accHash);
    }
}
