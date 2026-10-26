// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2, Vm} from "forge-std/Test.sol";
import {PqzSlots} from "./PqzState.t.sol";
import {PQZ_UID} from "./helpers/PqzRegistryBase.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UAPqzVerifier} from "../../src/pqz/UAPqzVerifier.sol";
import {NoUnderlyingPqzToken} from "../../src/pqz/NoUnderlyingPqzToken.sol";

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

/// Plan 5h Task 8d part 2b: the `PQZ` precompile at a schedule row's price, `row + 3 · ⌈len / 32⌉` (CTR-PQZ-11), less
/// 2,900 (this stand-in is a cold account, 3,000 gas; a precompile is warm, 100): answers 1.
contract RowBurner {
    uint256 internal immutable ROW;

    constructor(uint256 r) { ROW = r; }

    fallback(bytes calldata d) external returns (bytes memory) {
        uint256 b = ROW + 3 * ((d.length + 31) / 32) - 2_900;
        uint256 g0 = gasleft();
        while (g0 - gasleft() < b) {}
        return abi.encode(uint256(1));
    }
}

/// Plan 5h Task 8d part 2b: the execution gas of one call, without the transaction's intrinsic gas and calldata (what
/// the EIP-7976 floor hides when it binds). The call data is in memory before the first `gasleft`, so the meter's own
/// copy is not counted; the callee is a cold account here (3,000), the transaction's `to` on chain (warm, 100). The
/// call's EIP-8037 state gas is included (forge's `gasleft` pays it): subtract the transaction's `gasStateUsed`.
contract GasMeter {
    function measure(address t, bytes calldata d) external returns (uint256 used) {
        bytes memory m = d;
        bool ok;
        uint256 g0 = gasleft();
        assembly ("memory-safe") { ok := call(gas(), t, 0, add(m, 32), mload(m), 0, 0) }
        used = g0 - gasleft();
        if (!ok) assembly ("memory-safe") { returndatacopy(0, 0, returndatasize()) revert(0, returndatasize()) }
    }
}

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
    uint256 internal constant LO = PqzCore.ROLL_MAX / 2; // the fit's second point
    uint256 internal constant QM1 = PqzCt.Q - 1;

    bytes32 internal dave; // a second rolling account (the slope of ROLL_MAX)
    bytes32 internal eve; // never prepared
    bytes32 internal frank; // a TRIVIAL tail of the current block
    bytes32[8] internal xs;
    uint256 internal nextBlob = 0x5EED0000;
    uint256 internal constant RKEY = 0xA11CE; // the envelope signer
    address internal constant RELAYER = address(0x7E1A7E); // a fresh relayer: the fee credit is a zero → non-zero write
    uint256 internal feeSigLen = ML65_SIG; // the fee UA's signature bytes (an `slhdsa128s` fee UA: 7,856)
    bytes32 internal feeUA; // the `uaExecute` envelopes' signer: an `mldsa65` UA paying the outer fee from its ledger

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
        (discRef,) = _transfer(tok, carol, bob, bytes32(0), 1, true); // carol's acc: a fresh blob reference
        _fund(tok, bob, 1); // bob: an entry of an earlier block
        vm.roll(block.number + 1);
        _fund(tok, frank, 1); // frank: a TRIVIAL tail of the test's block
        _public(tok, address(this), 1000 * SCALE);
        _fund(tok, _pqzUA(_pk(12), 12), 100); // D19: the pool holds the fees the measured debits pay out
        _public(tok, vm.addr(RKEY), 1000); // the relayed envelopes' signer pays the outer fee (full-tx pins)
        feeUA = _mldsaUA(50); // the ML-DSA relay path's signer (8d2b fix round, review I1 / I2)
        NoUnderlyingPqzToken(address(tok)).mintToUA(feeUA, 1000);
        minted += 1000;
        _tableSetUp();
        vm.resumeGasMetering();
    }

    /// The gas table's state (plan 5h Task 8d part 2b), on accounts no other test uses: an op 7 M = 8 entry (auditor) to
    /// disclose, the meter, and registries whose PQZ verify cap (12 M) does not cut the register row. The PQZH verifier's
    /// probe re-mocks op 3, so it comes after every registration and op 3 is mocked to 1 again.
    function _tableSetUp() internal {
        gus = _pqzUA(_pk(40), 40);
        for (uint8 i; i < 8; ++i) ys[i] = _pqzUA(_pk(41 + i), 41 + i);
        bytes memory r;
        for (uint256 j; j < 8; ++j) r = bytes.concat(r, ys[j]);
        discRef7 = tok.mtxConfidentialTransfer(bytes.concat(abi.encode(uint256(0), block.number + 100, uint256(0), gus,
            alice, uint256(8), uint256(0)), salt, r, _blob(99, _outLen(8, true))), hex"c0de", _mlAuth(), alice, "");
        meter = new GasMeter();
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](2);
        k[0] = UARegistry.KindConfig(UAKinds.MLDSA65, address(mlv), 100_000);
        k[1] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(pqv), 12_000_000);
        regL = new UARegistry(PQZ_UID, address(0), false, 12_000_000, address(0), true, k);
        verL = pqv;
        if (PqzSet.HAS_PQZH) {
            verH = _newPqzVerifier(PqzSet.PQZH_ID);
            k[1] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(verH), 12_000_000);
            regH = new UARegistry(PQZ_UID, address(0), false, 12_000_000, address(0), true, k);
            vm.mockCall(PQZ, abi.encodePacked(uint8(3)), abi.encode(uint256(1)));
        }
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
        used = _gasTo(address(tok), data);
    }

    function _gasTo(address t, bytes memory data) internal returns (uint256 used) {
        (bool ok, bytes memory ret) = t.call(data);
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
        assertLe(gMax, CAP, "ROLL_MAX under 0.75 * 2^24");
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
        return _fullTxVia(false, data, fee);
    }

    /// Plan 5h Task 8d part 2b fix round (review I1): `_fullTx` on either relay path, `ua` = `uaExecute` (`_envelopeVia`),
    /// with ML-DSA-65 at 68,006 [estimate] (`GasBurner`, as the gas table): its mocks are cleared, so the precompile is
    /// not available in the call (a rollover or a prepare does not use it).
    function _fullTxVia(bool ua, bytes memory data, uint256 fee) internal returns (uint256 reg, uint256 st) {
        if (ua) {
            vm.clearMockedCalls();
            vm.etch(ML65, address(new GasBurner(68_006 - 2_900)).code);
        }
        bytes memory call = _envelopeVia(ua, data, fee);
        uint256 zeros;
        for (uint256 i; i < call.length; ++i) if (call[i] == 0) ++zeros;
        vm.prank(RELAYER);
        reg = _gas(call);
        st = lastState;
        int256 refund = vm.lastCallGas().gasRefunded;
        assertEq(tok.balanceOf(RELAYER), fee, "the outer fee was paid");
        console2.log(string.concat(ua ? "  uaExecute" : "  mtxExecute",
            " calldata bytes / zero bytes / EIP-7976 floor (15,000 + 64 per byte)"), call.length, zeros,
            15_000 + 64 * call.length);
        console2.log("  calldata gas 4 / 16 / refund (not subtracted)", 4 * zeros + 16 * (call.length - zeros),
            uint256(refund));
        console2.log("  full tx regular / state / total", reg, st, reg + st);
    }

    /// `data` in a signed `mtxExecute` envelope with a FIXED outer fee `fee` (0: none); the digest under a snapshot that
    /// is reverted (the clone's implementation and libraries stay cold for the measured call).
    function _envelope(bytes memory data, uint256 fee) internal returns (bytes memory) {
        return _envelopeVia(false, data, fee);
    }

    /// `_envelope` on either relay path. `ua`: a `uaExecute` envelope of `feeUA` (the ML-DSA-65 fee UA, the outer fee
    /// FIXED from its ledger to `msg.sender`) with a pseudo-random 3,309-byte signature (a real signature's calldata).
    function _envelopeVia(bool ua, bytes memory data, uint256 fee) internal returns (bytes memory) {
        if (ua) {
            MetaTxLib.UAMetaTransaction memory u;
            u.from = feeUA;
            u.data = data;
            u.validUntil = block.timestamp + 1 hours;
            u.mode = fee == 0 ? 0 : MetaTxLib.MODE_FEE_FIXED;
            u.fee = fee;
            return abi.encodeCall(tok.uaExecute, (u, abi.encode(bytes(""), _proof(feeSigLen))));
        }
        MetaTxLib.MetaTransaction memory m;
        m.from = vm.addr(RKEY);
        m.data = data;
        m.validUntil = block.timestamp + 1 hours;
        m.mode = fee == 0 ? 0 : MetaTxLib.MODE_FEE_FIXED;
        m.fee = fee;
        uint256 snap = vm.snapshotState();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(RKEY, tok.mtxDigest(m));
        vm.revertToState(snap);
        return abi.encodeWithSignature("mtxExecute((address,bytes,uint256,uint256,uint256,uint32,address,uint256,address),bytes)", m, abi.encodePacked(r, s, v));
    }

    /// Fix round 1 (I1): the `ROLL_MAX` rollover as a full relayed transaction with an outer fee: the binding convention
    /// for `ROLL_MAX` (the whole transaction <= 0.75 · 2^24). Plan 5h Task 8d part 2b: and `ROLL_MAX` is the LARGEST such
    /// multiple of 16 — `ROLL_MAX + 16` (the linear fit through a `LO`-entry relayed rollover of `dave`, measured cold
    /// under a snapshot first) is over the cap. The token refuses `n > ROLL_MAX`, so `ROLL_MAX + 16` itself is measured
    /// by a build with a larger constant (`test/research/PqzPackGas.t.sol` `test_pack_scanRoll`,
    /// `runs/2026-10-26-t8d2b-fix-rollscan-<set>.txt`: per-entry steps equal within 0.01 %, so the fit is exact enough).
    /// 8d2b fix round (review I1): on BOTH relay paths, `mtxExecute` (ECDSA) and `uaExecute` (the ML-DSA-65 fee UA):
    /// `ROLL_MAX` fits on each, and `ROLL_MAX + 16` is over the cap on the costlier one.
    function test_gas_rollMax_relayedFullTx() public {
        (uint256 e, uint256 en) = _rollMaxVia(false);
        (uint256 u, uint256 un) = _rollMaxVia(true);
        assertLe(e, CAP, "mtxExecute: the full relayed transaction's regular gas under 0.75 * 2^24");
        assertLe(u, CAP, "uaExecute: the full relayed transaction's regular gas under 0.75 * 2^24");
        assertGt(en > un ? en : un, CAP, "ROLL_MAX + 16 would fit too: ROLL_MAX is not the largest multiple of 16");
    }

    /// The `ROLL_MAX` relayed rollover on one path and its `ROLL_MAX + 16` fit (state restored afterwards).
    function _rollMaxVia(bool ua) internal returns (uint256 reg, uint256 next) {
        string memory p = ua ? "uaExecute" : "mtxExecute";
        uint256 snap = vm.snapshotState();
        console2.log(string.concat("relayed mtxRollOver (", p, "), full transaction, fee 7, entries (fit point)"), LO);
        (uint256 lo,) = _fullTxVia(ua, abi.encodeCall(tok.mtxRollOver, (dave, LO)), 7);
        vm.revertToState(snap);
        console2.log(string.concat("relayed mtxRollOver (", p, "), full transaction, fee 7, entries"), PqzCore.ROLL_MAX);
        (reg,) = _fullTxVia(ua, abi.encodeCall(tok.mtxRollOver, (alice, PqzCore.ROLL_MAX)), 7);
        vm.revertToState(snap);
        next = reg + (reg - lo) * 16 / (PqzCore.ROLL_MAX - LO);
        console2.log(string.concat("ROLL_MAX + 16, relayed full transaction (", p, ", linear fit) / per entry"), next,
            (reg - lo) / (PqzCore.ROLL_MAX - LO));
    }

    /// Fix round 1 (I1): each `mtxPrepareAcc` half as a full relayed transaction with an outer fee, on both relay paths
    /// (8d2b fix round, review I1).
    function test_gas_prepareAcc_half0_relayedFullTx() public {
        _prepareVia(0);
    }

    /// Task 7b: half 1 as a full relayed transaction too.
    function test_gas_prepareAcc_half1_relayedFullTx() public {
        _prepareVia(1);
    }

    function _prepareVia(uint256 half) internal {
        uint256 snap = vm.snapshotState();
        console2.log("relayed mtxPrepareAcc (mtxExecute), full transaction, fee 7, half", half);
        (uint256 e,) = _fullTxVia(false, abi.encodeCall(tok.mtxPrepareAcc, (eve, half)), 7);
        vm.revertToState(snap);
        console2.log("relayed mtxPrepareAcc (uaExecute), full transaction, fee 7, half", half);
        (uint256 u,) = _fullTxVia(true, abi.encodeCall(tok.mtxPrepareAcc, (eve, half)), 7);
        assertLe(e, CAP, "mtxExecute");
        assertLe(u, CAP, "uaExecute");
    }

    /// The same `ROLL_MAX` rollover relayed (owner rule 2026-10-20: every mtx* write is relayable). Plan 5h Task 7:
    /// `ROLL_MAX` is the largest multiple of 16 when this fails at `ROLL_MAX + 16` (built with that constant).
    function test_gas_rollMax_relayed() public {
        uint256 g = _relayed(abi.encodeCall(tok.mtxRollOver, (alice, PqzCore.ROLL_MAX)));
        _log("relayed mtxRollOver ROLL_MAX (mtxExecute, fee 0)", g);
        assertLe(g, CAP, "relayed ROLL_MAX under 0.75 * 2^24");
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

    /// The hint path (plan 5h D5) under P46 (Task 8d part 2b, open item 2): the hint is the packed stream
    /// (`pack(pqzAcc)`, `PqzCt.CTP` bytes) and replaces the `ACC_WORDS` cold slot reads, so the debit's EXECUTION is
    /// cheaper with it (`GasMeter`, each cold under a snapshot); an unpacked hint is ignored (state read). The
    /// transaction's regular gas is another matter: the hint adds `CTP` calldata bytes, 64 gas each under the EIP-7976
    /// floor (853,760 at n2304, against 417 × 2,100 = 875,700 for the reads), so it saves gas only when the transaction is
    /// not floor-bound (PQZL with its precompile price: yes, the gas table; this test's 2-byte proof: no).
    function test_gas_op1_bundle_materialised_hint() public {
        bytes memory h = _packed(tok.pqzAcc(alice));
        assertEq(h.length, PqzCt.CTP);
        uint256 snap = vm.snapshotState();
        uint256 e0 = meter.measure(address(tok), _op1(alice, PRE, true, ""));
        vm.revertToState(snap);
        uint256 eu = meter.measure(address(tok), _op1(alice, PRE, true, tok.pqzAcc(alice)));
        vm.revertToState(snap);
        uint256 eh = meter.measure(address(tok), _op1(alice, PRE, true, h));
        vm.revertToState(snap);
        uint256 g = _gas(_op1(alice, PRE, true, h));
        _log("op 1 BUNDLE, auditor, fee, p = rolled, materialised acc, hint", g);
        console2.log("  execution with the hint / without / with the unpacked (ignored) hint", eh, e0, eu);
        assertLt(eh + PqzCt.ACC_WORDS * 1_000, e0, "the hint replaces the cold slot reads");
        assertGe(eu, e0, "an unpacked hint is ignored");
    }

    function test_gas_op1_bundle_materialised_noHint() public {
        _log("op 1 BUNDLE, auditor, fee, p = rolled, materialised acc, no hint", _gas(_op1(alice, PRE, true, "")));
    }

    function test_gas_op1_bundle_16inline() public {
        bytes memory h = _packed(tok.pqzAcc(alice));
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
        return _op7a(m, true, proof);
    }

    function _op7a(uint256 m, bool aud, bytes memory proof) internal view returns (bytes memory) {
        bytes memory r;
        for (uint256 j; j < m; ++j) r = bytes.concat(r, xs[j]);
        bytes memory out = _blob(81 + m, _outLen(m, aud));
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
        return _burnP(amount, to, hex"c0de");
    }

    function _burnP(uint256 amount, address to, bytes memory proof) internal view returns (bytes memory) {
        bytes memory pl = bytes.concat(abi.encode(uint256(0), block.number + 5, uint256(0), carol, alice), _blob(5, PqzCt.CT));
        return abi.encodeCall(tok.mtxUnshield, (pl, proof, _mlAuth(), _benM(pl), "", amount, bytes32(uint256(uint160(to)))));
    }

    function test_gas_refresh() public {
        _log("refresh, fee, fresh ref", _gas(_burn(0, address(0))));
    }

    function test_gas_burn() public {
        _log("burn 1 to an address, fee, fresh ref", _gas(_burn(1, address(0xD00D))));
    }

    // ------------------------------------------------------------------ the gas table (plan 5h Task 8d part 2b)

    uint256 internal constant TX_CAP = 1 << 24; // EIP-7825: regular gas per transaction
    GasMeter internal meter;
    bytes32 internal discRef; // setUp's op 1 (carol → bob, auditor): the op 1 disclosure rows
    bytes32 internal discRef7; // _tableSetUp's op 7 M = 8 (gus, auditor): the op 7 disclosure rows
    bytes32 internal gus;
    bytes32[8] internal ys;
    UARegistry internal regL; // the register rows: PQZ verify cap 12 M, the PQZL / PQZH verifier
    UARegistry internal regH;
    UAPqzVerifier internal verL;
    UAPqzVerifier internal verH;
    string internal gj; // test/vectors/pqz-gas/<set>.json (script/pqz/gas-inputs.py)

    /// One row per relation and form at the build's set and proof system, each its own transaction after `setUp` under
    /// a snapshot that is reverted (cold state per row): the relayed full transaction (`mtxExecute` from a fresh relayer,
    /// outer fee 7) for every `mtx*` write, a direct call for `UARegistry.register`, the verifier's `verifyPop` and the
    /// disclosure view (an `eth_call`, priced as a transaction). The proof is pseudo-random bytes of the set's length
    /// (`test/vectors/pqz-gas/<set>.json`: PQZL the vector proof, PQZH its bound); the `PQZ` precompile burns its
    /// provisional row + 3 · ⌈input / 32⌉ (`RowBurner`, `chain/engine-pqz-provisional-<n>.json`), ML-DSA-65 68,006
    /// ([estimate], `GasBurner`). Columns: calldata bytes (zero bytes), standard calldata gas (4 / 16), the EIP-7976 floor
    /// (15,000 + 64 per byte), the precompile, execution (`GasMeter`: the call less the precompile and the state gas, the
    /// callee warm as a transaction's `to`; ML-DSA included), the transaction's regular gas (forge: max(15,000 + calldata + execution +
    /// precompile, floor); "model" is that maximum from the columns) and EIP-8037 state gas. PQZL: every row fits 2^24
    /// (asserted; D20 builds only what fits); PQZH: logged (the calldata-cap question of part 2b).
    /// Run: `script/pqz/at-set.sh <set> test --match-test test_gasTable -vv` (logs `runs/2026-10-26-t8d2b-gas-<set>.txt`).
    function test_gasTable_pqzl() public {
        _gasTable("pqzl");
    }

    function test_gasTable_pqzh() public {
        vm.skip(!PqzSet.HAS_PQZH);
        _gasTable("pqzh");
    }

    /// 8d2b fix round (review I2): the same tables with every `mtx*` row relayed through `uaExecute` (the ML-DSA-65 fee
    /// UA, `_envelopeVia`); logged as system `pqzl-ua` / `pqzh-ua`.
    bool internal viaUA;

    function test_gasTable_pqzl_ua() public {
        viaUA = true;
        _gasTable("pqzl");
    }

    function test_gasTable_pqzh_ua() public {
        vm.skip(!PqzSet.HAS_PQZH);
        viaUA = true;
        _gasTable("pqzh");
    }

    function _pf(string memory sys, string memory key) internal view returns (bytes memory) {
        return _proof(vm.parseJsonUint(gj, string.concat(".", sys, "['", key, "'].proof")));
    }

    function _gasTable(string memory sys) internal {
        gj = vm.readFile(string.concat(vm.projectRoot(), "/test/vectors/pqz-gas/", PqzSet.NAME, ".json"));
        bool h = keccak256(bytes(sys)) == keccak256("pqzh");
        bytes memory hint = _packed(tok.pqzAcc(alice));
        address t = address(tok);
        _row(sys, "TRANSFER", "op 1, auditor, fresh ref", t, _op1p(carol, 0, true, "", _pf(sys, "TRANSFER")), true);
        _row(sys, "TRANSFER0", "op 1, no auditor, fresh ref", t, _op1p(carol, 0, false, "", _pf(sys, "TRANSFER0")), true);
        _row(sys, "TRANSFER", "op 1, auditor, materialised acc, no hint", t,
            _op1p(alice, PRE, true, "", _pf(sys, "TRANSFER")), true);
        _row(sys, "TRANSFER", "op 1, auditor, materialised acc, hint", t,
            _op1p(alice, PRE, true, hint, _pf(sys, "TRANSFER")), true);
        for (uint256 m = 1; m <= (h ? 4 : 8); m *= 2) {
            for (uint256 a; a < 2; ++a) {
                string memory key = string.concat("M", vm.toString(m), a == 0 ? "-on" : "-off");
                _row(sys, key, string.concat("op 7 M = ", vm.toString(m), a == 0 ? ", auditor" : ", no auditor", ", fresh ref"),
                    t, _op7a(m, a == 0, _pf(sys, key)), true);
            }
        }
        _row(sys, "BURN", "burn 1 to an address, fresh ref", t, _burnP(1, address(0xD00D), _pf(sys, "BURN")), true);
        _row(sys, "REFRESH", "refresh, fresh ref", t, _burnP(0, address(0), _pf(sys, "REFRESH")), true);
        _registerRows(sys, h);
        _discRow(sys, 0, discRef, 0, "op 1 entry");
        _discRow(sys, 1, discRef, 0, "op 1 entry");
        _discRow(sys, 2, discRef, 0, "op 1 entry");
        _discRow(sys, 1, discRef7, 5, "op 7 M = 8 entry leg 5");
        _discRow(sys, 2, discRef7, 5, "op 7 M = 8 entry leg 5");
    }

    // ------------------------------------------------------------------ holder / fee-UA rows (review2 T2, C0-2 / C0-5)

    /// An n-of-n `mldsa65` `msig` PQZ holder (weights 1; the registry's PQZL rule admits it) and its debit auth.
    function _msigHolder(uint8 n, uint8 seed0) internal returns (bytes32 ua, bytes memory auth) {
        bytes32[] memory ids = new bytes32[](n);
        for (uint8 i; i < n; ++i) ids[i] = _mldsaUA(seed0 + i);
        for (uint256 i = 1; i < n; ++i) for (uint256 j = i; j > 0 && ids[j - 1] > ids[j]; --j) (ids[j - 1], ids[j]) = (ids[j], ids[j - 1]);
        bytes memory d = abi.encodePacked(uint16(n), uint16(n));
        UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](n);
        for (uint16 i; i < n; ++i) {
            d = abi.encodePacked(d, UAKinds.MLDSA65, ids[i], uint16(1));
            s[i] = UARegistry.MemberSig(i, "", new bytes(ML65_SIG));
        }
        ua = reg.uaOf(UAKinds.MSIG, d);
        bytes memory pqz = _pk(seed0 + 50);
        bytes32 h = UAKinds.keyHashOf(UAKinds.PQZ_MLWE, pqz);
        reg.register(UAKinds.MSIG, d, abi.encode(s), pqz, hex"aa"); // m-of-n PoP: filler signatures, ML65 mocked
        auth = abi.encode(d, abi.encode(s));
        assertEq(reg.keyOwner(h), ua);
    }

    function _burnH(bytes32 from, bytes memory auth, bytes memory proof) internal view returns (bytes memory) {
        bytes memory pl = bytes.concat(abi.encode(uint256(0), block.number + 5, uint256(0), from, alice), _blob(5, PqzCt.CT));
        return abi.encodeCall(tok.mtxUnshield, (pl, proof, auth, _benM(pl), "", 1, bytes32(uint256(uint160(0xD00D)))));
    }

    /// The cheapest debit (burn 1) of a 2-of-2 / 3-of-3 `mldsa65` `msig` holder on both relay paths, and of the
    /// `mldsa65` holder `carol` with an `slhdsa128s` fee UA (`uaExecute`; `mtxExecute`'s signer is an address). At
    /// n2048-kmax1024 PQZH (the one PQZH value-token set) the verdicts of README row C0-2: 2-of-2 fits `mtxExecute` only,
    /// 3-of-3 neither path, the `slhdsa128s` fee UA is over `uaExecute`. PQZL fits every row at every set.
    function test_gasTable_holderRows() public {
        (hm[0], ha[0]) = _msigHolder(2, 150);
        (hm[1], ha[1]) = _msigHolder(3, 160);
        slhFee = reg.register(UAKinds.SLHDSA128S, abi.encodePacked(keccak256("slh fee")), new bytes(7_856), "", "");
        NoUnderlyingPqzToken(address(tok)).mintToUA(slhFee, 1000);
        minted += 1000;
        gj = vm.readFile(string.concat(vm.projectRoot(), "/test/vectors/pqz-gas/", PqzSet.NAME, ".json"));
        _holderSys("pqzl", false);
        if (PqzSet.HAS_PQZH) _holderSys("pqzh", PqzSet.PQZH_VALUE);
    }

    bytes32[2] internal hm; // the 2-of-2 / 3-of-3 holders
    bytes[2] internal ha; // their debit auths
    bytes32 internal slhFee;

    function _holderSys(string memory sys, bool verdicts) internal {
        bytes memory pf = _pf(sys, "BURN");
        for (uint256 h; h < 2; ++h) {
            for (uint256 k; k < 2; ++k) {
                viaUA = k == 1;
                uint256 g = _row(sys, "BURN", string.concat("burn 1, ", h == 0 ? "2-of-2" : "3-of-3", " mldsa65 msig holder, ",
                    k == 1 ? "uaExecute" : "mtxExecute"), address(tok), _burnH(hm[h], ha[h], pf), true);
                // 2-of-2 fits mtxExecute only; 3-of-3 neither path
                if (verdicts) assertEq(g <= TX_CAP, h == 0 && k == 0, "PQZH n2048 holder verdict");
            }
        }
        viaUA = true;
        _feeMl = feeUA;
        feeUA = slhFee;
        feeSigLen = 7_856;
        uint256 gs = _row(sys, "BURN", "burn 1, mldsa65 holder, slhdsa128s fee UA, uaExecute", address(tok),
            _burnP(1, address(0xD00D), pf), true);
        if (verdicts) assertGt(gs, TX_CAP, "PQZH n2048: an slhdsa128s fee UA is over uaExecute");
        feeSigLen = ML65_SIG;
        feeUA = _feeMl;
    }

    bytes32 internal _feeMl;

    function _discRow(string memory sys, uint8 kd, bytes32 ref, uint256 leg, string memory entry) internal {
        string memory kn = kd == 0 ? "SENDER" : kd == 1 ? "RECEIVER" : "AUDITOR";
        string memory key = string.concat("DISCLOSE-", kn);
        bytes memory d = abi.encodeCall(tok.verifyTransferAmount, (ref, leg, 1, kd, _pf(sys, key)));
        _row(sys, key, string.concat("disclosure ", kn, ", ", entry, " (verifyTransferAmount)"), address(tok), d, false);
    }

    function _registerRows(string memory sys, bool h) internal {
        bytes memory proof = _pf(sys, "REGISTER");
        UARegistry r = h ? regH : regL;
        bytes memory d = abi.encodeCall(r.register, (UAKinds.MLDSA65, _mlPk(60), new bytes(ML65_SIG), _pk(60), proof));
        _row(sys, "REGISTER", "register (UARegistry.register: mldsa65 UA with a PQZ key)", address(r), d, false);
        UAPqzVerifier v = h ? verH : verL;
        d = abi.encodeCall(v.verifyPop, (_pk(60), bytes32(uint256(1)), proof));
        _row(sys, "REGISTER", "register: the R_REG verifyPop call alone (what the PQZ_MLWE cap must cover)", address(v), d, false);
    }

    function _row(string memory sys, string memory key, string memory what, address to, bytes memory data, bool relay)
        internal returns (uint256)
    {
        string memory k = string.concat(".", sys, "['", key, "']");
        uint256 row = vm.parseJsonUint(gj, string.concat(k, ".row"));
        uint256 pqzGas = row + 3 * ((vm.parseJsonUint(gj, string.concat(k, ".input")) + 31) / 32);
        vm.clearMockedCalls();
        vm.etch(PQZ, address(new RowBurner(row)).code);
        vm.etch(ML65, address(new GasBurner(68_006 - 2_900)).code);
        if (relay) data = _envelopeVia(viaUA, data, 7);
        uint256 snap = vm.snapshotState();
        vm.prank(RELAYER);
        uint256 reg = _gasTo(to, data);
        uint256 st = lastState;
        vm.revertToState(snap);
        uint256 inner = meter.measure(to, data);
        vm.revertToState(snap);
        // the meter's frame pays the EIP-8037 state gas out of its gas too (forge's reservoir is not visible to `gasleft`)
        uint256 off = pqzGas + 2_900 + st;
        _rowLog(sys, what, data, pqzGas, inner > off ? inner - off : 0, reg, st);
        return reg;
    }

    function _rowLog(string memory sys, string memory what, bytes memory data, uint256 pqzGas, uint256 exec, uint256 reg,
        uint256 st) internal view
    {
        uint256 n = data.length;
        uint256 z;
        for (uint256 i; i < n; ++i) if (data[i] == 0) ++z;
        uint256 std = 4 * z + 16 * (n - z);
        uint256 floor = 15_000 + 64 * n;
        uint256 model = 15_000 + std + exec + pqzGas;
        console2.log(string.concat("GAS ", PqzSet.NAME, " ", sys, viaUA ? "-ua" : "", " | ", what, " | calldata ", vm.toString(n), " (zero ",
            vm.toString(z), ") | std ", vm.toString(std), " | floor ", vm.toString(floor)));
        console2.log(string.concat("  | pqz ", vm.toString(pqzGas), " | exec ", vm.toString(exec), " | regular ",
            vm.toString(reg), " (model ", vm.toString(model > floor ? model : floor), ") | state ", vm.toString(st),
            " | fits 2^24 ", reg <= TX_CAP ? "yes" : "NO"));
        if (keccak256(bytes(sys)) == keccak256("pqzl")) assertLe(reg, TX_CAP, string.concat("PQZL ", what, ": over 2^24"));
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
        assertLe(g, CAP, "ROLL_MAX under 0.75 * 2^24");
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
