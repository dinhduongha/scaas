// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IZetherVerifier, IZetherBurnVerifier, IZetherInnerProductVerifier} from "../../src/zether/IZetherVerifier.sol";
import {ZetherMsmCorpus} from "./helpers/ZetherMsmCorpus.sol";
import {ZetherProver} from "./helpers/ZetherProver.sol";
import {G1Bls12381} from "../../src/zether/ZetherCurves.sol";
import {ZetherTranscript as T} from "../../src/zether/ZetherTranscript.sol";
import {
    ZetherInnerProductVerifierBls12381,
    ZetherTransferVerifierBls12381,
    ZetherBurnVerifierBls12381,
    ZetherCurve,
    ZetherBls12381Curve
} from "../../src/zether/ZetherVerifier.sol";

/// @dev The inner-product verifier with its one MSM reported instead of judged: reverts with the sum and the point count.
contract FoldProbe is ZetherInnerProductVerifierBls12381 {
    error Folded(bytes sum, uint256 points);

    function _msm(bytes memory pts, uint256[] memory sc)
        internal view override(ZetherCurve, ZetherBls12381Curve) returns (bytes memory)
    {
        revert Folded(super._msm(pts, sc), sc.length);
    }
}

/// @notice The merged check (zether.md §9.1, CTR-ZTH-53): every equation of every form folded into one MSM under the powers
///         of a `ρ` that hashes the whole proof. Each equation is broken alone by a cheating prover (`ZetherProver`
///         tamper hooks) and refused; fixed-weight cancelling pairs, low-order and off-curve points are refused.
contract ZetherMsmTest is ZetherMsmCorpus {
    uint256 constant GAS = 100_000_000; // a failing precompile burns all it is sent: every call that may fail there is capped

    IZetherVerifier pv;
    IZetherBurnVerifier pb;
    IZetherInnerProductVerifier ip;

    function setUp() public {
        _corpus();
        FoldProbe probe = new FoldProbe();
        pv = IZetherVerifier(address(new ZetherTransferVerifierBls12381(probe)));
        pb = IZetherBurnVerifier(address(new ZetherBurnVerifierBls12381(probe)));
        ip = new ZetherInnerProductVerifierBls12381();
    }

    /// @dev The verdict of `op` (0 transfer, 1 multi, 2 burn) on the canonical verifiers; a revert is a refusal.
    function _ok(uint8 op, bytes memory st, bytes memory pr) internal view returns (bool) {
        try this.call_{gas: GAS}(op, st, pr) returns (bool ok) { return ok; } catch { return false; }
    }

    function call_(uint8 op, bytes memory st, bytes memory pr) external view returns (bool) {
        return op == 0 ? v.verifyTransfer(st, pr) : op == 1 ? v.verifyTransferMulti(st, pr) : vb.verifyBurn(st, pr);
    }

    /// @dev The fold's sum and point count, through the probe.
    function _fold(uint8 op, bytes memory st, bytes memory pr) internal view returns (bytes memory sum, uint256 points) {
        try this.probe_(op, st, pr) { revert("no fold"); } catch (bytes memory e) {
            require(bytes4(e) == FoldProbe.Folded.selector, "not a fold");
            bytes memory args = new bytes(e.length - 4);
            for (uint256 i; i < args.length; ++i) args[i] = e[4 + i];
            (sum, points) = abi.decode(args, (bytes, uint256));
        }
    }

    function probe_(uint8 op, bytes memory st, bytes memory pr) external view {
        if (op == 0) pv.verifyTransfer(st, pr);
        else if (op == 1) pv.verifyTransferMulti(st, pr);
        else pb.verifyBurn(st, pr);
    }

    function _invR(uint256 a) internal pure returns (uint256 acc) {
        acc = 1;
        (uint256 b, uint256 e) = (a, R - 2);
        for (; e > 0; e >>= 1) {
            if (e & 1 == 1) acc = mulmod(acc, b, R);
            b = mulmod(b, b, R);
        }
    }

    function _pow(uint256 a, uint256 e) internal pure returns (uint256 acc) {
        acc = 1;
        for (uint256 i; i < e; ++i) acc = mulmod(acc, a, R);
    }

    // ------------------------------------------------------------------ one MSM, its size

    function test_eachFormIsOneMsm() public {
        (bytes memory st, bytes memory pr) = _transfer(true);
        (bytes memory stM, bytes memory prM) = _multi(2, true);
        (bytes memory stB, bytes memory prB) = _burn();
        vm.expectCall(address(0x0c), bytes(""), 3);
        assertTrue(v.verifyTransfer(st, pr));
        assertTrue(v.verifyTransferMulti(stM, prM));
        assertTrue(vb.verifyBurn(stB, prB));
    }

    function test_pointCountPerForm() public view {
        (bytes memory st, bytes memory pr) = _transfer(true);
        (bytes memory sum, uint256 n) = _fold(0, st, pr);
        assertEq(n, 182, "transfer, 131 + 19 + 2 x 16");
        assertEq(sum, new bytes(P), "honest: O");
        (st, pr) = _transfer(false);
        (, n) = _fold(0, st, pr);
        assertEq(n, 182, "the auditor-off O points keep their slots");
        (st, pr) = _burn();
        (, n) = _fold(2, st, pr);
        assertEq(n, 154, "burn, 131 + 7 + 16");
        for (uint256 m = 1; m <= 3; ++m) {
            (st, pr) = _multi(m, true);
            (sum, n) = _fold(1, st, pr);
            assertEq(n, 159 + 25 * m, "multi, 131 + 12 + 16 + 25M");
            assertEq(sum, new bytes(P), "honest multi: O");
        }
    }

    // ------------------------------------------------------------------ each equation alone

    /// @dev Σ point `i` offset by `[1]G` (`rid` = 0, else `T1` of range proof `rid`): only its equation, the `eq`-th of the
    ///      fold, fails. The verifier refuses, and the sum is `[−ρ^eq]G`: that equation's weight and nothing else.
    function _broken(uint8 op, uint256 i, uint256 rid, uint256 eq, bytes memory st, uint256 sigmaLen) internal {
        prover.setTamper(i, rid);
        bytes memory bad = _reprove(op, st);
        prover.setTamper(0, 0);
        assertFalse(_ok(op, st, bad), "one broken equation accepted");
        (bytes memory sum,) = _fold(op, st, bad);
        assertEq(sum, _residual(rid != 0, eq, st, bad, sigmaLen), "the fold is not rho^eq times the residual");
    }

    function _reprove(uint8 op, bytes memory st) internal view returns (bytes memory pr) {
        if (op == 0) return _proveTransfer(Case(B, 300, 300, FEE, true), st);
        if (op == 2) return _proveBurn(st, XF, B - 400 - FEE);
        (, pr) = _multi(multiM, true);
    }

    /// @dev The state after `sigma.c` and `ρ` of a proof, as zether.md §9.1 derives them.
    function _rho(bytes memory st, bytes memory pr, uint256 sigmaLen) internal pure returns (bytes32 s1, uint256 rho) {
        (s1,) = T.challenge(T.absorb(T.absorb(T.init(), "statement", st), "sigma.commit", _head(pr, sigmaLen)), "sigma.c", R);
        (, rho) = T.challenge(T.absorb(s1, "fold.proof", pr), "fold.rho", R);
    }

    /// @dev `[−ρ^eq]G` for a broken Σ commitment; `[−ρ^eq · x]G` for `T1` of a range proof, which BP-1 reads times `−x`.
    function _residual(bool bp, uint256 eq, bytes memory st, bytes memory pr, uint256 sigmaLen)
        internal view returns (bytes memory)
    {
        (bytes32 s1, uint256 rho) = _rho(st, pr, sigmaLen);
        uint256 w = _pow(rho, eq);
        if (bp) w = mulmod(w, _x(s1, pr, sigmaLen + (st.length == HEADER + 9 * P ? 192 : 96)), R);
        return v.g1MulBase(R - w);
    }

    /// @dev The `x` of the range proof at `off`, the first one on the transcript after `sigma.c`.
    function _x(bytes32 st, bytes memory pr, uint256 off) internal pure returns (uint256 x) {
        st = T.absorb(st, "bp.AS", abi.encodePacked(uint32(64), _at(pr, off, 2 * P)));
        (st,) = T.challenge(st, "bp.y", R);
        (st,) = T.challenge(st, "bp.z", R);
        st = T.absorb(st, "bp.T", _at(pr, off + 2 * P, 2 * P));
        (, x) = T.challenge(st, "bp.x", R);
    }

    uint256 multiM; // the leg count `_reprove` proves

    function test_eachTransferEquationAloneRefused() public {
        (bytes memory st, bytes memory pr) = _transfer(true);
        // A_y A_D A_out A_deb A_bal A_aud A_Vv A_Vb: E1 .. E8
        for (uint256 i; i < 8; ++i) _broken(0, 3 + i, 0, i, st, 10 * P);
    }

    function test_eachTransferEquationAloneRefused_noAuditor() public {
        (bytes memory st, bytes memory pr) = _transfer(false);
        _broken(0, 3, 0, 0, st, 10 * P); // E1
        _broken(0, 7, 0, 4, st, 10 * P); // E5
        _broken(0, 9, 0, 5, st, 10 * P); // E7: E6 is not in the fold
        _broken(0, 10, 0, 6, st, 10 * P); // E8
    }

    function test_firstBpOneAloneRefused() public {
        (bytes memory st, bytes memory pr) = _transfer(true);
        _broken(0, 0, 32, 8, st, 10 * P); // BP-1 of BP(v), the rid of `proveTransfer`
    }

    /// Bytes `a` and `b` are absorbed by no challenge and read by no other equation: BP-2 of one proof alone fails.
    function test_eachBpTwoAloneRefused() public view {
        (bytes memory st, bytes memory pr) = _transfer(true);
        for (uint256 k; k < 2; ++k) {
            uint256 at = 10 * P + 192 + k * BP_LEN + 16 * P + 96; // a of BP k
            bytes memory t = bytes.concat(pr);
            _setWord(t, at, addmod(_word(t, at), 1, R));
            assertFalse(_ok(0, st, t), "a");
            t = bytes.concat(pr);
            _setWord(t, at + 32, addmod(_word(t, at + 32), 1, R));
            assertFalse(_ok(0, st, t), "b");
        }
    }

    function test_secondBpOneAloneRefused() public {
        (bytes memory st,) = _transfer(true);
        prover.setTamper(0, 64); // BP(b')
        bytes memory bad = _reprove(0, st);
        prover.setTamper(0, 0);
        assertFalse(_ok(0, st, bad));
    }

    function test_eachBurnEquationAloneRefused() public {
        (bytes memory st, bytes memory pr) = _burn();
        _broken(2, 2, 0, 0, st, 4 * P); // A_y, E1
        _broken(2, 3, 0, 1, st, 4 * P); // A_bal, E5
        _broken(2, 4, 0, 2, st, 4 * P); // A_Vb, E8
        _broken(2, 0, 64, 3, st, 4 * P); // BP-1
        assertTrue(_ok(2, st, pr));
        _setWord(pr, pr.length - 32, addmod(_word(pr, pr.length - 32), 1, R)); // b: BP-2
        assertFalse(_ok(2, st, pr));
    }

    /// Fold order on the multi-recipient form: E1 E2, per leg E3_j E6_j E6′_j E7_j, then E4 E5 E8.
    function test_eachMultiEquationAloneRefused() public {
        multiM = 2;
        (bytes memory st, bytes memory pr) = _multi(2, true);
        uint256 sig = (6 + 5 * 2) * P;
        _broken(1, 2, 0, 0, st, sig); // A_y, E1
        _broken(1, 3, 0, 1, st, sig); // A_D, E2
        for (uint256 j; j < 2; ++j) {
            uint256 e = 2 + 4 * j;
            _broken(1, 6 + 5 * j + 2, 0, e, st, sig);     // A_out_j, E3_j
            _broken(1, 6 + 5 * j + 3, 0, e + 1, st, sig); // A_aud_j, E6_j
            _broken(1, 6 + 5 * j + 4, 0, e + 2, st, sig); // A_Daud_j, E6′_j
            _broken(1, 6 + 5 * j + 5, 0, e + 3, st, sig); // A_Vvj, E7_j
        }
        _broken(1, 4, 0, 10, st, sig); // A_deb, E4
        _broken(1, 5, 0, 11, st, sig); // A_bal, E5
        _broken(1, 6, 0, 12, st, sig); // A_Vb, E8
    }

    // ------------------------------------------------------------------ the weights

    /// @dev `z_gv + δ` breaks E7 by `[δ]Hb`, `z_gb − δ/ρ` breaks E8 by the opposite under weights `ρ^6`, `ρ^7`: the two
    ///      cancel in the fold if the verifier's weight is `rho`.
    function _cancelling(bytes memory pr, uint256 rho) internal pure returns (bytes memory t) {
        t = bytes.concat(pr);
        uint256 d = 0xD00D;
        uint256 zgv = 10 * P + 4 * 32;
        uint256 zgb = 10 * P + 5 * 32;
        _setWord(t, zgv, addmod(_word(t, zgv), d, R));
        _setWord(t, zgb, addmod(_word(t, zgb), R - mulmod(d, _invR(rho), R), R));
    }

    /// Requirement 1 of §9.1. The proof scalars are in no challenge, so a weight that does not hash them could be read
    /// first and the pair built to it. Each guess below is the weight of a verifier that gets it wrong: equal weights;
    /// `ρ` of the transcript without the proof; `ρ` of the untouched proof, which the pair itself must move.
    function test_cancellingPairRefused() public view {
        (bytes memory st, bytes memory pr) = _transfer(true);
        (bytes32 s1, uint256 honest) = _rho(st, pr, 10 * P);
        (, uint256 unbound) = T.challenge(T.absorb(s1, "fold.proof", ""), "fold.rho", R);
        assertFalse(_ok(0, st, _cancelling(pr, 1)), "equal weights");
        assertFalse(_ok(0, st, _cancelling(pr, unbound)), "a weight that misses the proof scalars");
        assertFalse(_ok(0, st, _cancelling(pr, honest)), "the honest proof's weight");
    }

    /// `ρ = 0` would keep only the first equation: refused by the check, not by luck. BP-1 alone holds on this proof.
    function test_zeroRhoRefused() public view {
        (bytes memory st, bytes memory pr) = _transfer(true);
        (bytes32 s1,) = _rho(st, pr, 10 * P);
        uint256[] memory at = new uint256[](1);
        at[0] = 131;
        bytes memory bp = _at(pr, 10 * P + 192, BP_LEN);
        _setWord(bp, BP_LEN - 32, addmod(_word(bp, BP_LEN - 32), 1, R)); // BP-2 broken
        assertFalse(ip.verifyFold(s1, IZetherInnerProductVerifier.SigmaFold(0, 1, _point(pr, 0), new uint256[](132), at), bp));
    }

    /// Requirement 4: every shared slot starts at `r − 1`, its `+1` a copy of the generator in the caller's points. The range
    /// proof's terms then wrap past `r` on every one of them; the sum still cancels only if each stays exact mod `r`.
    function test_sharedGeneratorsAddModR() public view {
        (bytes memory st, bytes memory pr) = _transfer(true);
        (bytes32 s1,) = _rho(st, pr, 10 * P);
        bytes memory bp = _at(pr, 10 * P + 192, BP_LEN);
        bytes memory pts = bytes.concat(v.g1MulBase(1), v.generators(), _point(pr, 0));
        uint256[] memory sc = new uint256[](131 + 132);
        for (uint256 i; i < 131; ++i) (sc[i], sc[131 + i]) = (R - 1, 1);
        uint256[] memory at = new uint256[](1);
        at[0] = 131 + 131;
        IZetherInnerProductVerifier.SigmaFold memory f = IZetherInnerProductVerifier.SigmaFold(0xABCDEF, 0xFEDCBA, pts, sc, at);
        assertTrue(ip.verifyFold(s1, f, bp), "shared slots near r");
        _setWord(bp, BP_LEN - 32, addmod(_word(bp, BP_LEN - 32), 1, R));
        assertFalse(ip.verifyFold(s1, f, bp), "a broken proof stays broken");
    }

    // ------------------------------------------------------------------ the standalone range proof

    function test_verifyRangeHonestAndTampered() public view {
        (bytes memory st, bytes memory pr) = _transfer(true);
        (bytes32 s1,) = _rho(st, pr, 10 * P);
        bytes memory bp = _at(pr, 10 * P + 192, BP_LEN);
        (bool ok, bytes32 s2) = ip.verifyRange(s1, _point(pr, 0), bp);
        assertTrue(ok);
        (bool ok2,) = ip.verifyRange(s2, _point(pr, P), _at(pr, 10 * P + 192 + BP_LEN, BP_LEN));
        assertTrue(ok2, "the returned state carries on to the next proof");
        _setWord(bp, BP_LEN - 32, addmod(_word(bp, BP_LEN - 32), 1, R));
        (ok,) = ip.verifyRange(s1, _point(pr, 0), bp);
        assertFalse(ok);
    }

    // ------------------------------------------------------------------ the points (zether.md §9.1, requirement 3)

    /// G1ADD takes the order-3 point, G1MSM refuses it, whatever the scalar.
    function test_precompilesOnTheLowOrderPoint() public view {
        bytes memory t = _lowOrder();
        bytes memory g = G1Bls12381.generator();
        (bool ok, bytes memory out) = address(0x0b).staticcall{gas: GAS}(bytes.concat(t, t));
        assertTrue(ok, "G1ADD has no subgroup check");
        assertEq(out.length, P);
        (ok, out) = address(0x0b).staticcall{gas: GAS}(bytes.concat(out, t));
        assertEq(out, new bytes(P), "order 3");
        for (uint256 k; k < 4; ++k) {
            (ok,) = address(0x0c).staticcall{gas: GAS}(abi.encodePacked(t, k));
            assertFalse(ok, "G1MSM checks the subgroup, a zero scalar too");
        }
        (ok,) = address(0x0c).staticcall{gas: GAS}(abi.encodePacked(g, uint256(1), t, uint256(0)));
        assertFalse(ok, "at any position of the input");
        (ok,) = address(0x0c).staticcall{gas: GAS}(abi.encodePacked(uint256(0), uint256(1), uint256(0), uint256(1), uint256(0)));
        assertFalse(ok, "off the curve, scalar 0");
    }

    /// Each of `n` points at `off`: moved out of the subgroup by the order-3 point, it must reach G1MSM and revert.
    function _everyPointReachesMsm(uint8 op, bytes memory st, bytes memory pr, bool inStatement, uint256 off, uint256 n) internal {
        for (uint256 i; i < n; ++i) {
            (bytes memory a, bytes memory b) = (bytes.concat(st), bytes.concat(pr));
            _outOfSubgroup(inStatement ? a : b, off + i * P);
            vm.expectRevert(G1Bls12381.BadPoint.selector);
            this.call_{gas: GAS}(op, a, b);
        }
    }

    function _outOfSubgroup(bytes memory t, uint256 at) internal view {
        _setPoint(t, at, G1Bls12381.add(_point(t, at), _lowOrder()));
    }

    function test_everyTransferPointReachesTheMsm() public {
        (bytes memory st, bytes memory pr) = _transfer(true);
        _everyPointReachesMsm(0, st, pr, true, HEADER, 9);
        _everyPointReachesMsm(0, st, pr, false, 0, 10);
        for (uint256 k; k < 2; ++k) _everyPointReachesMsm(0, st, pr, false, 10 * P + 192 + k * BP_LEN, 16);
    }

    function test_everyBurnPointReachesTheMsm() public {
        (bytes memory st, bytes memory pr) = _burn();
        _everyPointReachesMsm(2, st, pr, true, HEADER, 3);
        _everyPointReachesMsm(2, st, pr, false, 0, 4);
        _everyPointReachesMsm(2, st, pr, false, 4 * P + 96, 16);
    }

    function test_everyMultiPointReachesTheMsm() public {
        uint256 m = 2;
        (bytes memory st, bytes memory pr) = _multi(m, true);
        _everyPointReachesMsm(1, st, pr, true, HEADER, 6);
        _everyPointReachesMsm(1, st, pr, true, HEADER + 6 * P + 32, 4 * m);
        _everyPointReachesMsm(1, st, pr, false, 0, 6 + 5 * m);
        uint256 off = (6 + 5 * m) * P + (4 + 3 * m) * 32;
        for (uint256 k; k <= m; ++k) _everyPointReachesMsm(1, st, pr, false, off + k * BP_LEN, 16);
    }

    /// `T` on one equation and `−T` on another would sum to `O` under equal weights: never reaches a sum.
    function test_lowOrderPairAcrossEquationsRefused() public {
        (bytes memory st, bytes memory pr) = _transfer(true);
        _outOfSubgroup(pr, 8 * P);
        _setPoint(pr, 9 * P, G1Bls12381.add(_point(pr, 9 * P), G1Bls12381.neg(_lowOrder())));
        vm.expectRevert(G1Bls12381.BadPoint.selector);
        this.call_{gas: GAS}(0, st, pr);
    }

    /// A prover-chosen `z_x = 0` gives `D_acc` the scalar 0 in the sum: its slot stays, so its subgroup check does too.
    function test_zeroScalarSlotStillChecked() public {
        (bytes memory st, bytes memory pr) = _transfer(true);
        _setWord(pr, 10 * P, 0);
        _outOfSubgroup(st, HEADER + 4 * P);
        vm.expectRevert(G1Bls12381.BadPoint.selector);
        this.call_{gas: GAS}(0, st, pr);
    }
}
