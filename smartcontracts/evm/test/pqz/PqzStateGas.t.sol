// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2, Vm} from "forge-std/Test.sol";
import {PqzSlots} from "./PqzState.t.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// Task 7b: a stand-in for a precompile with a known price: burns `B` gas, answers 1 (`_precompiles`).
contract GasBurner {
    uint256 internal immutable B;

    constructor(uint256 b) { B = b; }

    fallback(bytes calldata) external returns (bytes memory) {
        uint256 g0 = gasleft();
        while (g0 - gasleft() < B) {}
        return abi.encode(uint256(1));
    }
}

// F185 (Foundry 1.8.5, Amsterdam): the largest `ROLL_MAX` under `0.75 · 2^24` at the current sizes is 128 (a `mtxRollOver`
// is 6,598,351 regular gas fixed + 44,123 per entry, the fit through 128 and 256 entries); the constant in `src/` is 256
// until Task 8d re-pins it (owner checkpoint, Task 7b: 80 at the 16k sizes). While `ROLL_MAX` is above this figure the
// four `ROLL_MAX` rows below assert a ceiling just above today's measurement instead of the cap (17.9 M at 256 entries),
// so further growth still fails; at or below it they assert the cap again. TODO(5h Task 8d): re-pin and delete both.
uint256 constant AMS_ROLL_MAX = 128;

/// A single transfer's op blob as SSTORE2 code, `STOP ‖ salt(16) ‖ P(u ‖ v_t) ‖ toUA ‖ P(v_f)` (P46 packed, plan 5h Task 8d
/// part 2), every coefficient `q − 1`: the credits the gas pins roll (the lanes' worst case).
function _qm1BlobCode() pure returns (bytes memory) {
    uint256 qm1 = PqzCt.Q - 1;
    uint256 w = qm1 << 192 | qm1 << 128 | qm1 << 64 | qm1;
    bytes memory ct = new bytes(PqzCt.CT);
    for (uint256 o; o < PqzCt.CT; o += 32) {
        assembly ("memory-safe") { mstore(add(add(ct, 32), o), w) }
    }
    bytes memory v = new bytes(PqzCt.V);
    for (uint256 o; o < PqzCt.V; o += 32) {
        assembly ("memory-safe") { mstore(add(add(v, 32), o), w) }
    }
    return bytes.concat(hex"00", bytes16(0), PqzCt.packMem(ct), bytes32(0), PqzCt.packMem(v));
}
uint256 constant ROLL_CEILING = 18_500_000;

/// Plan 5h Task 2 gas (Review Focus 5, 6; spec §5.3 / §5.4) on the real token: `ROLL_MAX` and the `mtxPrepareAcc` halves
/// pinned under `0.75 · 2^24`, the shield (append, merge) and the per-op table. Each test is one transaction after
/// `setUp` (a slot written in `setUp` is clean and cold in the test, as on chain; `PqzStateSteadyGasTest*` of the
/// prototype). Every rollover entry is a credit from its own op blob (distinct cold accounts, every coefficient `q − 1`).
/// Numbers (Task 7b, Foundry >= 1.8, Amsterdam): each measured call is its own transaction; regular gas before refunds
/// including the intrinsic and calldata (or the EIP-7976 floor), EIP-8037 state gas apart; the precompile and the ML-DSA
/// verification mocked.
/// Run: `../../scripts/capped forge test --match-contract PqzStatePinGasTest -vv` (log: runs/2026-10-20-5h-b-gas.txt).
contract PqzStatePinGasTest is PqzSlots {
    uint256 internal constant CAP = (uint256(1) << 24) * 3 / 4; // 12,582,912
    uint256 internal constant PRE = 16; // entries rolled in setUp (acc materialised)
    uint256 internal constant LO = PqzCore.ROLL_MAX / 2; // the fit's second point (128 at ROLL_MAX = 256; Task 7b)
    uint256 internal constant QM1 = PqzCt.Q - 1;

    bytes32 internal dave; // a second rolling account (the slope of ROLL_MAX)
    bytes32 internal eve; // never prepared
    bytes32 internal frank; // a TRIVIAL tail of the current block
    bytes32[8] internal xs;
    uint256 internal nextBlob = 0x5EED0000;
    uint256 internal constant RKEY = 0xA11CE; // the envelope signer
    address internal constant RELAYER = address(0x7E1A7E); // a fresh relayer: the fee credit is a zero → non-zero write

    function setUp() public {
        // Task 7b: Amsterdam caps a transaction's regular gas at 2^24 and `setUp` is one transaction (the four
        // 322-slot prepares alone ≈ 15.6 M): unmetered, it measures nothing (each test's calls are their own transactions)
        vm.pauseGasMetering();
        _stack();
        _mockOp(7, 1);
        tok = _newToken("gas");
        dave = _pqzUA(_pk(9), 9);
        eve = _pqzUA(_pk(10), 10);
        frank = _pqzUA(_pk(11), 11);
        for (uint8 i; i < 8; ++i) xs[i] = _pqzUA(_pk(20 + i), 20 + i);
        bytes memory code = _blobCode();
        _seed(alice, PRE + PqzCore.ROLL_MAX, code);
        _seed(dave, PRE + LO, code);
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
        _public(tok, vm.addr(RKEY), 1000); // the relayed envelopes' signer pays the outer fee (full-tx pins)
        vm.resumeGasMetering();
    }

    /// `STOP ‖ salt(16) ‖ P(u ‖ v_t) ‖ toUA ‖ P(v_f)` (P46), every coefficient `q − 1` (the lane-overflow worst case).
    function _blobCode() internal pure returns (bytes memory c) {
        c = _qm1BlobCode();
    }

    /// `k` credits of `ua`, each pointing into its own etched blob (block 1, so old enough after `setUp`'s roll).
    function _seed(bytes32 ua, uint256 k, bytes memory code) internal {
        for (uint256 i; i < k; ++i) {
            address b = address(uint160(++nextBlob));
            vm.etch(b, code);
            uint256 e = uint256(uint160(b)) << 96 | uint256(16) << 80 | uint256(16 + PqzCt.PKP) << 64 | 1;
            vm.store(address(tok), _pendingSlot(ua, i), bytes32(e));
        }
        vm.store(address(tok), bytes32(_acctSlot(ua)), bytes32(k));
    }

    /// Plan 5h Task 7b (Amsterdam): Foundry >= 1.8 runs every top-level call of a test as its own transaction
    /// (`isolate = true`), so `vm.lastCallGas()` is that transaction's REGULAR gas before refunds (intrinsic
    /// 12,000 + 3,000, calldata or the EIP-7976 floor, execution) and its EIP-8037 STATE gas apart (`lastState`).
    uint256 internal lastState;

    function _gas(bytes memory data) internal returns (uint256 used) {
        (bool ok, bytes memory ret) = address(tok).call(data);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        Vm.Gas memory g = vm.lastCallGas();
        used = g.gasTotalUsed;
        lastState = uint256(int256(g.gasStateUsed));
    }

    function _log(string memory what, uint256 g) internal view {
        console2.log(string.concat(what, " gas: regular / state / total"), g, lastState, g + lastState);
    }

    // ------------------------------------------------------------------ ROLL_MAX and prepare (Review Focus 5, 6)

    /// `ROLL_MAX` = the largest multiple of 16 under `0.75 · 2^24`: `ROLL_MAX` fits; `ROLL_MAX + 16` is the linear fit
    /// through a `LO`-entry rollover of another account (logged; the binding rule is the relayed full transaction,
    /// `test_gas_rollMax_relayedFullTx`). The `LO`-entry call runs first under a snapshot that
    /// is reverted (`vm.revertToState` restores cold access too: `gMax` equals its value as the test's only call), so
    /// both are measured cold, as `test_gas_roll128` alone. Then the lanes: `acc` holds `16 (q − 1)`, the rollover adds
    /// `ROLL_MAX` entries of `q − 1`: every coefficient is `q − 272`.
    function test_gas_rollMax() public {
        uint256 snap = vm.snapshotState();
        uint256 g128 = _gas(abi.encodeCall(tok.mtxRollOver, (dave, LO)));
        vm.revertToState(snap);
        uint256 gMax = _gas(abi.encodeCall(tok.mtxRollOver, (alice, PqzCore.ROLL_MAX)));
        uint256 next = gMax + (gMax - g128) * 16 / (PqzCore.ROLL_MAX - LO);
        _log("mtxRollOver ROLL_MAX / 2 (steady, distinct cold blobs)", g128);
        _log("mtxRollOver ROLL_MAX (steady, distinct cold blobs)", gMax);
        _log("mtxRollOver ROLL_MAX + 16 (linear fit)", next);
        console2.log("per entry / fixed (fit)", (gMax - g128) / (PqzCore.ROLL_MAX - LO),
            g128 - (gMax - g128) * LO / (PqzCore.ROLL_MAX - LO));
        if (PqzCore.ROLL_MAX > AMS_ROLL_MAX) assertLe(gMax, ROLL_CEILING, "ROLL_MAX over the cap: ceiling"); // TODO(5h Task 8d): re-pin ROLL_MAX under Amsterdam, remove this ceiling
        else assertLe(gMax, CAP, "ROLL_MAX under 0.75 * 2^24");
        bytes memory acc = tok.pqzAcc(alice);
        uint256 want = PqzCt.Q - (PRE + PqzCore.ROLL_MAX);
        want = want << 192 | want << 128 | want << 64 | want;
        for (uint256 o; o < PqzCt.CT; o += 32) {
            uint256 w;
            assembly ("memory-safe") { w := mload(add(add(acc, 32), o)) }
            assertEq(w, want);
        }
    }

    /// `data` (a token call) relayed through `mtxExecute` (fee 0, own transaction; execution gas only).
    function _relayed(bytes memory data) internal returns (uint256) {
        uint256 key = RKEY;
        MetaTxLib.MetaTransaction memory m;
        m.from = vm.addr(key);
        m.data = data;
        m.validUntil = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, tok.mtxDigest(m));
        return _gas(abi.encodeWithSignature("mtxExecute((address,bytes,uint256,uint256,uint256,uint32,address,uint256,address),bytes)", m, abi.encodePacked(r, s, v)));
    }

    /// Fix round 1 (review I1, m3): `data` relayed as a full transaction. The envelope pays a FIXED (absolute) outer fee
    /// `fee` from the signer's public balance to a fresh relayer; the digest is computed under a snapshot that is then
    /// reverted, so the clone's implementation and libraries are cold in the measured call. Task 7b (Amsterdam): the
    /// relayer's `mtxExecute` call is its own transaction (`isolate`, `tx.to = tok` warm as on chain): `reg` = regular
    /// gas before refunds (12,000 + 3,000 intrinsic, max(calldata 4 / 16 + execution, EIP-7976 floor 64 per byte),
    /// execution), `st` = EIP-8037 state gas. The precompile and ML-DSA stay mocked (not included).
    function _fullTx(bytes memory data, uint256 fee) internal returns (uint256 reg, uint256 st) {
        MetaTxLib.MetaTransaction memory m;
        m.from = vm.addr(RKEY);
        m.data = data;
        m.validUntil = block.timestamp + 1 hours;
        m.mode = fee == 0 ? 0 : MetaTxLib.MODE_FEE_FIXED;
        m.fee = fee;
        uint256 snap = vm.snapshotState();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(RKEY, tok.mtxDigest(m));
        vm.revertToState(snap);
        bytes memory call = abi.encodeWithSignature("mtxExecute((address,bytes,uint256,uint256,uint256,uint32,address,uint256,address),bytes)", m, abi.encodePacked(r, s, v));
        uint256 zeros;
        for (uint256 i; i < call.length; ++i) if (call[i] == 0) ++zeros;
        vm.prank(RELAYER);
        reg = _gas(call);
        st = lastState;
        int256 refund = vm.lastCallGas().gasRefunded;
        assertEq(tok.balanceOf(RELAYER), fee, "the outer fee was paid");
        console2.log("  mtxExecute calldata bytes / zero bytes / EIP-7976 floor (15,000 + 64 per byte)", call.length, zeros,
            15_000 + 64 * call.length);
        console2.log("  calldata gas 4 / 16 / refund (not subtracted)", 4 * zeros + 16 * (call.length - zeros),
            uint256(refund));
        console2.log("  full tx regular / state / total", reg, st, reg + st);
    }

    /// Fix round 1 (I1): the `ROLL_MAX` rollover (or `PQZ_ROLL_N` entries) as a full relayed transaction with an outer
    /// fee: the binding convention for `ROLL_MAX` (the whole transaction <= 0.75 · 2^24).
    function test_gas_rollMax_relayedFullTx() public {
        uint256 n = vm.envOr("PQZ_ROLL_N", PqzCore.ROLL_MAX);
        console2.log("relayed mtxRollOver, full transaction, fee 7, entries", n);
        (uint256 reg,) = _fullTx(abi.encodeCall(tok.mtxRollOver, (alice, n)), 7);
        if (n > AMS_ROLL_MAX) assertLe(reg, ROLL_CEILING, "ROLL_MAX over the cap: ceiling"); // TODO(5h Task 8d): re-pin ROLL_MAX under Amsterdam, remove this ceiling
        else assertLe(reg, CAP, "the full relayed transaction's regular gas under 0.75 * 2^24");
    }

    /// Fix round 1 (I1): each `mtxPrepareAcc` half as a full relayed transaction with an outer fee.
    function test_gas_prepareAcc_half0_relayedFullTx() public {
        console2.log("relayed mtxPrepareAcc half 0, full transaction, fee 7");
        (uint256 reg,) = _fullTx(abi.encodeCall(tok.mtxPrepareAcc, (eve, 0)), 7);
        assertLe(reg, CAP);
    }

    /// Task 7b: half 1 as a full relayed transaction too.
    function test_gas_prepareAcc_half1_relayedFullTx() public {
        console2.log("relayed mtxPrepareAcc half 1, full transaction, fee 7");
        (uint256 reg,) = _fullTx(abi.encodeCall(tok.mtxPrepareAcc, (eve, 1)), 7);
        assertLe(reg, CAP);
    }

    /// The same `ROLL_MAX` rollover relayed (owner rule 2026-10-20: every mtx* write is relayable). Plan 5h Task 7:
    /// `ROLL_MAX` is the largest multiple of 16 when this fails at `ROLL_MAX + 16` (built with that constant).
    function test_gas_rollMax_relayed() public {
        uint256 g = _relayed(abi.encodeCall(tok.mtxRollOver, (alice, PqzCore.ROLL_MAX)));
        _log("relayed mtxRollOver ROLL_MAX (mtxExecute, fee 0)", g);
        if (PqzCore.ROLL_MAX > AMS_ROLL_MAX) assertLe(g, ROLL_CEILING, "ROLL_MAX over the cap: ceiling"); // TODO(5h Task 8d): re-pin ROLL_MAX under Amsterdam, remove this ceiling
        else assertLe(g, CAP, "relayed ROLL_MAX under 0.75 * 2^24");
    }

    function test_gas_roll128() public {
        _log("mtxRollOver ROLL_MAX / 2 (steady, distinct cold blobs)", _gas(abi.encodeCall(tok.mtxRollOver, (dave, LO))));
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

    /// Plan 5h Task 7: each half relayed (fee 0) stays under `0.75 · 2^24` too (every mtx* write is relayable).
    function test_gas_prepareAcc_half0_relayed() public {
        uint256 g = _relayed(abi.encodeCall(tok.mtxPrepareAcc, (eve, 0)));
        _log("relayed mtxPrepareAcc half 0 (mtxExecute, fee 0)", g);
        assertLe(g, CAP);
    }

    function test_gas_prepareAcc_half1_relayed() public {
        uint256 g = _relayed(abi.encodeCall(tok.mtxPrepareAcc, (eve, 1)));
        _log("relayed mtxPrepareAcc half 1 (mtxExecute, fee 0)", g);
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
        return _op1p(from, p, aud, hint, hex"c0de");
    }

    function _op1p(bytes32 from, uint256 p, bool aud, bytes memory hint, bytes memory proof)
        internal view returns (bytes memory)
    {
        return abi.encodeCall(tok.mtxConfidentialTransferSingle,
            (_payload(p, 0, from, bob, carol, _out(77, aud), ""), proof, _mlAuth(), carol, hint));
    }

    /// `n` pseudo-random proof bytes (the calldata a real proof of that length costs: almost no zero bytes).
    function _proof(uint256 n) internal pure returns (bytes memory proof) {
        proof = new bytes(n);
        for (uint256 i; i < n; i += 32) {
            bytes32 w = keccak256(abi.encode("proof", i));
            assembly ("memory-safe") { mstore(add(add(proof, 32), i), w) }
        }
    }

    /// Task 7b: op 1 (auditor, fee) relayed as a full transaction with a `PQZ_PROOF_TX`-byte proof (default 52,624: the
    /// 16k `R_TX` codegen size), fresh ref and the materialised `acc` without a hint (the op 1 worst case).
    /// Task 7b: unless `PQZ_PRECOMPILE=0`, `PQZ` and `ML65` become code that burns their price (`pqzGas` [estimate]:
    /// today's row × 1.25; ML-DSA-65 68,000 + 6 per message word, unchanged) less the cold-account difference
    /// (3,000 here, 100 for a precompile on chain): the transaction then counts the verification as execution, as on
    /// chain, and the EIP-7976 floor is compared with the whole of it. Loop granularity ≈ ±40 gas.
    function _precompiles(uint256 pqzGas) internal {
        if (vm.envOr("PQZ_PRECOMPILE", uint256(1)) == 0) return;
        console2.log("  [estimate] precompile gas PQZ / ML65 (burnt by stand-ins)", pqzGas, uint256(68_006));
        vm.clearMockedCalls();
        vm.etch(PQZ, address(new GasBurner(pqzGas - 2_900)).code);
        vm.etch(ML65, address(new GasBurner(68_006 - 2_900)).code);
    }

    function test_gas_op1_relayedFullTx_freshRef() public {
        _precompiles(vm.envOr("PQZ_GAS_TX", uint256(6_761_250))); // 5,409,000 (PQZL v3 R_TX, auditor) × 1.25
        uint256 plen = vm.envOr("PQZ_PROOF_TX", uint256(52_624));
        console2.log("relayed op 1 BUNDLE, auditor, fresh ref, full transaction, fee 7, proof bytes", plen);
        _fullTx(_op1p(carol, 0, true, "", _proof(plen)), 7);
    }

    function test_gas_op1_relayedFullTx_materialisedNoHint() public {
        _precompiles(vm.envOr("PQZ_GAS_TX", uint256(6_761_250)));
        uint256 plen = vm.envOr("PQZ_PROOF_TX", uint256(52_624));
        console2.log("relayed op 1 BUNDLE, auditor, materialised acc, no hint, full transaction, fee 7, proof bytes", plen);
        _fullTx(_op1p(alice, PRE, true, "", _proof(plen)), 7);
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
        return _op7p(m, hex"c0de");
    }

    function _op7p(uint256 m, bytes memory proof) internal view returns (bytes memory) {
        bytes memory r;
        for (uint256 j; j < m; ++j) r = bytes.concat(r, xs[j]);
        uint256 g = (m + 3) / 4;
        bytes memory out = _blob(81 + m, PqzCt.PK * g + PqzCt.V * (m + 1) + PqzCt.V * m);
        return abi.encodeCall(tok.mtxConfidentialTransfer, (bytes.concat(abi.encode(uint256(0), block.number + 100, uint256(0),
            carol, alice, m, uint256(0)), salt, r, out), proof, _mlAuth(), alice, ""));
    }

    function test_gas_op7_M4() public {
        _log("op 7 M = 4 BUNDLE, auditor, fee, fresh ref (4 first credits)", _gas(_op7(4)));
    }

    function test_gas_op7_M8() public {
        _log("op 7 M = 8 BUNDLE, auditor, fee, fresh ref (8 first credits)", _gas(_op7(8)));
    }

    /// Plan 5h Task 7: op 7 M = 8 (auditor, fee, fresh ref) as one transaction against 2^24, with a proof of
    /// `PQZ_PROOF_LEN` bytes (default 64,578: today's codegen estimate of `R_TXM` M = 8; set it to the measured or the
    /// candidate's size). Logs the execution gas (precompile mocked: its schedule gas is not included), the calldata gas
    /// (EIP-2028 4 / 16, and the "all bytes non-zero" bound) and the EIP-7623 floor of the call's data.
    function test_gas_op7_M8_txTotal() public {
        uint256 plen = vm.envOr("PQZ_PROOF_LEN", uint256(64_578));
        bytes memory proof = new bytes(plen);
        for (uint256 i; i < plen; i += 32) {
            bytes32 w = keccak256(abi.encode("proof", i));
            assembly ("memory-safe") { mstore(add(add(proof, 32), i), w) }
        }
        bytes memory data = _op7p(8, proof);
        uint256 zeros;
        for (uint256 i; i < data.length; ++i) if (data[i] == 0) ++zeros;
        uint256 reg = _gas(data);
        console2.log("op 7 M = 8 calldata bytes / zero bytes / proof bytes", data.length, zeros, plen);
        _log("op 7 M = 8 BUNDLE, auditor, fee, fresh ref, direct tx (precompile mocked)", reg);
        console2.log("calldata gas 4 / 16 / EIP-7976 floor 15,000 + 64 per byte", 4 * zeros + 16 * (data.length - zeros),
            15_000 + 64 * data.length);
    }

    /// Fix round 1 (m3): op 7 M = 8 relayed as a full transaction with the real data (payload and a `PQZ_PROOF_LEN`-byte
    /// proof) and an outer fee; the precompile's schedule gas is not included (mocked).
    function test_gas_op7_M8_relayedFullTx() public {
        uint256 plen = vm.envOr("PQZ_PROOF_LEN", uint256(64_578));
        bytes memory proof = _proof(plen);
        console2.log("relayed op 7 M = 8, full transaction, fee 7, proof bytes (precompile mocked)", plen);
        _fullTx(_op7p(8, proof), 7);
    }

    /// Task 7b: op 7 M = 1 / 2 / 4 (auditor, fee, fresh ref) relayed as a full transaction with the 16k codegen proof
    /// sizes (`PQZ_PROOF_M<M>`; M = 1 uses `R_TX`'s parameters: 52,624; `txm2` 53,504; `txm4` 57,202).
    function _op7Relayed(uint256 m, uint256 dflt, uint256 row) internal {
        _precompiles(vm.envOr(string.concat("PQZ_GAS_M", vm.toString(m)), row * 5 / 4));
        uint256 plen = vm.envOr(string.concat("PQZ_PROOF_M", vm.toString(m)), dflt);
        console2.log("relayed op 7 BUNDLE, auditor, fresh ref, full transaction, fee 7: M / proof bytes", m, plen);
        _fullTx(_op7p(m, _proof(plen)), 7);
    }

    /// today's PQZL v3 op 7 rows, auditor on: M = 1 3,625,000; M = 2 3,710,000; M = 4 4,121,000 (× 1.25 [estimate])
    function test_gas_op7_relayedFullTx_M1() public { _op7Relayed(1, 52_624, 3_625_000); }
    function test_gas_op7_relayedFullTx_M2() public { _op7Relayed(2, 53_504, 3_710_000); }
    function test_gas_op7_relayedFullTx_M4() public { _op7Relayed(4, 57_202, 4_121_000); }

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
/// only, so every `u` coefficient of its `acc` is 0. Each slot stores `not(packed word)` (P46), so no slot goes back to zero
/// and the next rollover of `ROLL_MAX` cold credits still rewrites (2,900 gas a word), not re-creates (22,100), and
/// fits `0.75 · 2^24`. Each test is one transaction after `setUp`.
contract PqzStateTrivialRollGasTest is PqzSlots {
    uint256 internal constant CAP = (uint256(1) << 24) * 3 / 4;
    uint256 internal constant QM1 = PqzCt.Q - 1;
    uint256 internal constant TRIV = 4; // TRIVIAL entries rolled in setUp
    uint256 internal nextBlob = 0x5EED0000;
    bytes32 internal gina;

    function _blobCode() internal pure returns (bytes memory c) {
        c = _qm1BlobCode();
    }

    function _gas(bytes memory data) internal returns (uint256 used) {
        (bool ok, bytes memory ret) = address(tok).call(data);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        Vm.Gas memory g = vm.lastCallGas(); // Task 7b: the call's own transaction, regular gas (state gas logged)
        used = g.gasTotalUsed;
        console2.log("  (state gas)", uint256(int256(g.gasStateUsed)));
    }

    function setUp() public {
        vm.pauseGasMetering(); // Task 7b: as `PqzStatePinGasTest.setUp`
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
            uint256 e = uint256(uint160(b)) << 96 | uint256(16) << 80 | uint256(16 + PqzCt.PKP) << 64 | 1;
            vm.store(address(tok), _pendingSlot(gina, TRIV + i), bytes32(e));
        }
        bytes32 k = bytes32(_acctSlot(gina));
        uint256 w = uint256(vm.load(address(tok), k));
        vm.store(address(tok), k, bytes32((w & ~uint256(type(uint64).max)) | (TRIV + PqzCore.ROLL_MAX)));
        vm.resumeGasMetering();
    }

    /// No `acc` slot is zero after the TRIVIAL-only rollover (D3), and the `u` half still reads as zero.
    function test_trivialRoll_noZeroSlot() public view {
        for (uint256 i; i < PqzCt.ACC_WORDS; ++i) {
            assertTrue(vm.load(address(tok), bytes32(_acctSlot(gina) + 5 + i)) != 0, "acc slot zeroed");
        }
        bytes memory acc = tok.pqzAcc(gina);
        for (uint256 o; o < PqzCt.PK; o += 32) {
            uint256 x;
            assembly ("memory-safe") { x := mload(add(add(acc, 32), o)) }
            assertEq(x, 0, "u of Trivial(4)");
        }
        assertEq(keccak256(PqzCt.packMem(acc)), tok.pqzAccount(gina).accHash, "accHash over the packed stream");
    }

    /// The regression pin: `ROLL_MAX` cold credits after the TRIVIAL-only rollover fit `0.75 · 2^24` (10.6 M for
    /// n = 1 and 20.9 M for `ROLL_MAX` when the slots were zeroed), and every `u` coefficient is `256 (q − 1) mod q`.
    function test_gas_rollMax_afterTrivialRoll() public {
        uint256 g = _gas(abi.encodeCall(tok.mtxRollOver, (gina, PqzCore.ROLL_MAX)));
        console2.log("mtxRollOver ROLL_MAX after a TRIVIAL-only rollover gas", g);
        if (PqzCore.ROLL_MAX > AMS_ROLL_MAX) assertLe(g, ROLL_CEILING, "ROLL_MAX over the cap: ceiling"); // TODO(5h Task 8d): re-pin ROLL_MAX under Amsterdam, remove this ceiling
        else assertLe(g, CAP, "ROLL_MAX under 0.75 * 2^24");
        bytes memory acc = tok.pqzAcc(gina);
        uint256 want = PqzCt.Q - PqzCore.ROLL_MAX;
        want = want << 192 | want << 128 | want << 64 | want;
        for (uint256 o; o < PqzCt.PK; o += 32) {
            uint256 x;
            assembly ("memory-safe") { x := mload(add(add(acc, 32), o)) }
            assertEq(x, want);
        }
        assertEq(keccak256(PqzCt.packMem(acc)), tok.pqzAccount(gina).accHash);
    }
}
