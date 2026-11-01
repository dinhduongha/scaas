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
    FoldProbe probe;

    function setUp() public {
        _corpus();
        probe = new FoldProbe();
        pv = IZetherVerifier(address(new ZetherTransferVerifierBls12381(probe)));
        pb = IZetherBurnVerifier(address(new ZetherBurnVerifierBls12381(probe)));
        ip = new ZetherInnerProductVerifierBls12381();
    }

    /// @dev The verdict of `op` (0 transfer, 1 multi, 2 burn) on the canonical verifiers. A revert is a refusal only as
    ///      `BadPoint`: out of gas or a `Panic` must not read as one.
    function _ok(uint8 op, bytes memory st, bytes memory pr) internal view returns (bool) {
        try this.call_{gas: GAS}(op, st, pr) returns (bool ok) { return ok; } catch (bytes memory e) {
            assertTrue(e.length == 4 && bytes4(e) == G1Bls12381.BadPoint.selector, "a revert other than BadPoint");
            return false;
        }
    }

    function call_(uint8 op, bytes memory st, bytes memory pr) external view returns (bool) {
        return op == 0 ? v.verifyTransfer(st, pr) : op == 1 ? v.verifyTransferMulti(st, pr) : vb.verifyBurn(st, pr);
    }

    /// @dev The fold's sum and point count, through the probe.
    function _fold(uint8 op, bytes memory st, bytes memory pr) internal view returns (bytes memory sum, uint256 points) {
        try this.probe_(op, st, pr) { revert("no fold"); } catch (bytes memory e) { return _folded(e); }
    }

    function _folded(bytes memory e) internal pure returns (bytes memory sum, uint256 points) {
        require(bytes4(e) == FoldProbe.Folded.selector, "not a fold");
        bytes memory args = new bytes(e.length - 4);
        for (uint256 i; i < args.length; ++i) args[i] = e[4 + i];
        (sum, points) = abi.decode(args, (bytes, uint256));
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

    /// @dev Σ point `i` offset by `[1]G`: only its equation, the `eq`-th of the fold, fails. The verifier refuses, and the sum
    ///      is `[−ρ^eq]G`: that equation's weight and nothing else.
    function _broken(uint8 op, uint256 i, uint256 eq, bytes memory st, uint256 sigmaLen) internal {
        prover.setTamper(i, 0, 0);
        bytes memory bad = _reprove(op, st);
        prover.setTamper(0, 0, 0);
        assertFalse(_ok(op, st, bad), "one broken equation accepted");
        (bytes memory sum,) = _fold(op, st, bad);
        (, uint256 rho) = _rho(st, bad, sigmaLen);
        assertEq(sum, v.g1MulBase(R - _pow(rho, eq)), "the fold is not rho^eq times the residual");
    }

    function _reprove(uint8 op, bytes memory st) internal view returns (bytes memory pr) {
        if (op == 0) return _proveTransfer(Case(B, 300, 300, FEE, true), st);
        if (op == 2) return _proveBurn(st, XF, B - 400 - FEE);
        (, pr) = _multi(multiM, !multiNoAud);
    }

    /// @dev The state after `sigma.c` and `ρ` of a proof, as zether.md §9.1 derives them.
    function _rho(bytes memory st, bytes memory pr, uint256 sigmaLen) internal pure returns (bytes32 s1, uint256 rho) {
        (s1,) = T.challenge(T.absorb(T.absorb(T.init(), "statement", st), "sigma.commit", _head(pr, sigmaLen)), "sigma.c", R);
        (, rho) = T.challenge(T.absorb(s1, "fold.proof", pr), "fold.rho", R);
    }

    /// @dev A form, for the range-proof pins: `zLen` the bytes of Σ scalars after the `sigmaLen` bytes of Σ points, `eqs` the
    ///      number of Σ equations, so proof `k` holds equations `eqs + 2k` (BP-1) and `eqs + 2k + 1` (BP-2).
    struct Form {
        uint8 op;
        bytes st;
        uint256 sigmaLen;
        uint256 zLen;
        uint256 eqs;
    }

    /// @dev Requirement 2 for each range proof. `T1 + [1]G` breaks BP-1 alone, by `−[x]G`; `A + [1]G` breaks BP-2 alone, by
    ///      `[1]G`. The sum then shows each equation's own weight, so the powers cannot repeat or skip across proofs.
    function _rangePin(Form memory f, uint256 k, uint256 rid) internal {
        _pinBp1(f, k, rid);
        _pinBp2(f, k, rid);
    }

    function _pinBp1(Form memory f, uint256 k, uint256 rid) internal {
        prover.setTamper(0, rid, 0);
        bytes memory bad = _reprove(f.op, f.st);
        prover.setTamper(0, 0, 0);
        assertFalse(_ok(f.op, f.st, bad), "BP-1 alone accepted");
        (bytes memory sum,) = _fold(f.op, f.st, bad);
        assertEq(sum, _bp1Sum(f, k, bad), "BP-1 weight");
    }

    /// @dev `[−ρ^eq · x_k]G`: BP-1 reads the offset of `T1` times `−x`.
    function _bp1Sum(Form memory f, uint256 k, bytes memory bad) internal view returns (bytes memory) {
        (bytes32 s1, uint256 rho) = _rho(f.st, bad, f.sigmaLen);
        return v.g1MulBase(R - mulmod(_pow(rho, f.eqs + 2 * k), _x(s1, bad, f.sigmaLen + f.zLen, k), R));
    }

    function _pinBp2(Form memory f, uint256 k, uint256 rid) internal {
        prover.setTamper(0, 0, rid);
        bytes memory bad = _reprove(f.op, f.st);
        prover.setTamper(0, 0, 0);
        assertFalse(_ok(f.op, f.st, bad), "BP-2 alone accepted");
        (bytes memory sum,) = _fold(f.op, f.st, bad);
        (, uint256 rho) = _rho(f.st, bad, f.sigmaLen);
        assertEq(sum, v.g1MulBase(_pow(rho, f.eqs + 2 * k + 1)), "BP-2 weight");
    }

    /// @dev The `x` of range proof `k`, the transcript walked from `st` through the `k` before it.
    function _x(bytes32 st, bytes memory pr, uint256 off, uint256 k) internal pure returns (uint256 x) {
        for (uint256 i; i <= k; ++i) {
            uint256 at = off + i * BP_LEN;
            st = T.absorb(st, "bp.AS", abi.encodePacked(uint32(64), _at(pr, at, 2 * P)));
            (st,) = T.challenge(st, "bp.y", R);
            (st,) = T.challenge(st, "bp.z", R);
            st = T.absorb(st, "bp.T", _at(pr, at + 2 * P, 2 * P));
            (st, x) = T.challenge(st, "bp.x", R);
            st = T.absorb(st, "bp.t", _at(pr, at + 16 * P, 96));
            (st,) = T.challenge(st, "bp.w", R);
            for (uint256 j; j < 6; ++j) {
                st = T.absorb(st, "ipa.LR", _at(pr, at + (4 + 2 * j) * P, 2 * P));
                (st,) = T.challenge(st, "ipa.u", R);
            }
        }
    }

    uint256 multiM; // the leg count `_reprove` proves
    bool multiNoAud;

    function test_eachTransferEquationAloneRefused() public {
        (bytes memory st,) = _transfer(true);
        // A_y A_D A_out A_deb A_bal A_aud A_Vv A_Vb: E1 .. E8
        for (uint256 i; i < 8; ++i) _broken(0, 3 + i, i, st, 10 * P);
    }

    function test_eachTransferEquationAloneRefused_noAuditor() public {
        (bytes memory st,) = _transfer(false);
        _broken(0, 3, 0, st, 10 * P); // E1
        _broken(0, 7, 4, st, 10 * P); // E5
        _broken(0, 9, 5, st, 10 * P); // E7: E6 is not in the fold
        _broken(0, 10, 6, st, 10 * P); // E8
    }

    function test_rangeEquationsAloneRefused_transfer() public {
        (bytes memory st,) = _transfer(true);
        Form memory f = Form(0, st, 10 * P, 192, 8);
        _rangePin(f, 0, 32); // BP(v), the rid of `proveTransfer`
        _rangePin(f, 1, 64); // BP(b')
    }

    function test_rangeEquationsAloneRefused_multi() public {
        multiM = 2;
        (bytes memory st,) = _multi(2, true);
        Form memory f = Form(1, st, (6 + 5 * 2) * P, (4 + 3 * 2) * 32, 13);
        _rangePin(f, 0, 100); // BP(v_1)
        _rangePin(f, 1, 101); // BP(v_2)
        _rangePin(f, 2, 64);  // BP(b')
    }

    function test_rangeEquationsAloneRefused_burn() public {
        (bytes memory st,) = _burn();
        _rangePin(Form(2, st, 4 * P, 96, 3), 0, 64);
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

    function test_eachBurnEquationAloneRefused() public {
        (bytes memory st, bytes memory pr) = _burn();
        _broken(2, 2, 0, st, 4 * P); // A_y, E1
        _broken(2, 3, 1, st, 4 * P); // A_bal, E5
        _broken(2, 4, 2, st, 4 * P); // A_Vb, E8
        assertTrue(_ok(2, st, pr));
        _setWord(pr, pr.length - 32, addmod(_word(pr, pr.length - 32), 1, R)); // b: BP-2
        assertFalse(_ok(2, st, pr));
    }

    /// Fold order on the multi-recipient form: E1 E2, per leg E3_j E6_j E6′_j E7_j, then E4 E5 E8.
    function test_eachMultiEquationAloneRefused() public {
        multiM = 2;
        (bytes memory st,) = _multi(2, true);
        uint256 sig = (6 + 5 * 2) * P;
        _broken(1, 2, 0, st, sig); // A_y, E1
        _broken(1, 3, 1, st, sig); // A_D, E2
        for (uint256 j; j < 2; ++j) {
            uint256 e = 2 + 4 * j;
            _broken(1, 6 + 5 * j + 2, e, st, sig);     // A_out_j, E3_j
            _broken(1, 6 + 5 * j + 3, e + 1, st, sig); // A_aud_j, E6_j
            _broken(1, 6 + 5 * j + 4, e + 2, st, sig); // A_Daud_j, E6′_j
            _broken(1, 6 + 5 * j + 5, e + 3, st, sig); // A_Vvj, E7_j
        }
        _broken(1, 4, 10, st, sig); // A_deb, E4
        _broken(1, 5, 11, st, sig); // A_bal, E5
        _broken(1, 6, 12, st, sig); // A_Vb, E8
    }

    // ------------------------------------------------------------------ the largest form, M = 16

    /// @dev 559 points, honest `O`, then the last two range proofs each broken alone: `eqs` Σ equations before them.
    function _m16(bool aud, uint256 eqs) internal returns (bytes memory st) {
        multiM = 16;
        multiNoAud = !aud;
        bytes memory pr;
        (st, pr) = _multi(16, aud);
        assertTrue(_ok(1, st, pr), "honest");
        (bytes memory sum, uint256 n) = _fold(1, st, pr);
        assertEq(n, 559, "131 + 12 + 16 + 25 x 16");
        assertEq(sum, new bytes(P), "honest: O");
        Form memory f = Form(1, st, (6 + 5 * 16) * P, (4 + 3 * 16) * 32, eqs);
        _rangePin(f, 15, 115); // BP(v_16)
        _rangePin(f, 16, 64);  // BP(b'), the last two of the `e` equations
    }

    /// `e` = 103: E1 E2, 4 × 16 leg equations, E4 E5 E8, 2 × 17 range equations.
    function test_m16_auditorOn() public {
        bytes memory st = _m16(true, 69);
        uint256 sig = (6 + 5 * 16) * P;
        _broken(1, 6 + 5 * 15 + 2, 62, st, sig); // A_out_16, E3
        _broken(1, 6 + 5 * 15 + 3, 63, st, sig); // A_aud_16, E6
        _broken(1, 6 + 5 * 15 + 4, 64, st, sig); // A_Daud_16, E6′
        _broken(1, 6 + 5 * 15 + 5, 65, st, sig); // A_Vv16, E7
        _broken(1, 4, 66, st, sig);              // A_deb, E4
        _broken(1, 6, 68, st, sig);              // A_Vb, E8
    }

    /// `e` = 71: no E6, no E6′.
    function test_m16_auditorOff() public {
        bytes memory st = _m16(false, 37);
        uint256 sig = (6 + 5 * 16) * P;
        _broken(1, 6 + 5 * 15 + 2, 32, st, sig); // A_out_16, E3
        _broken(1, 6 + 5 * 15 + 5, 33, st, sig); // A_Vv16, E7
        _broken(1, 5, 35, st, sig);              // A_bal, E5
    }

    // ------------------------------------------------------------------ auditor off: the fields no equation reads

    /// With the auditor off no equation reads these, so a tampered copy of an honest row proves nothing: it moves `c` and
    /// another equation refuses. Each row here is proved for the junk it carries, so every equation holds and the `O` check
    /// alone refuses.
    function test_auditorOffFieldsRefused() public {
        (bytes memory st, bytes memory pr) = _transfer(false);
        assertTrue(_ok(0, st, pr), "the row without junk");
        bytes memory t = bytes.concat(st);
        _setPoint(t, HEADER + 8 * P, v.g1MulBase(42));
        assertFalse(_ok(0, t, _reprove(0, t)), "C_aud");
        prover.setTamper(8, 0, 0); // A_aud
        bytes memory bad = _reprove(0, st);
        prover.setTamper(0, 0, 0);
        assertFalse(_ok(0, st, bad), "A_aud");
    }

    function _multiLegJunk(bytes memory st, uint256[] memory vs, uint256 total, uint256 at) internal view {
        bytes memory t = bytes.concat(st);
        _setPoint(t, at, v.g1MulBase(42));
        assertFalse(_ok(1, t, _proveMulti(t, vs, total, 0)), "statement field");
    }

    function _multiCommitJunk(bytes memory st, uint256[] memory vs, uint256 total, uint256 i) internal {
        prover.setTamper(i, 0, 0);
        bytes memory bad = _proveMulti(st, vs, total, 0);
        prover.setTamper(0, 0, 0);
        assertFalse(_ok(1, st, bad), "proof field");
    }

    function test_auditorOffLegFieldsRefused() public {
        uint256 m = 2;
        uint256[] memory vs = new uint256[](m);
        (bytes memory st, uint256 total) = _multiSt(m, vs, false);
        bytes memory pr = _proveMulti(st, vs, total, 0);
        assertTrue(_ok(1, st, pr), "the row without junk");
        for (uint256 j; j < m; ++j) {
            uint256 leg = HEADER + 6 * P + 32 + 4 * P * j;
            _multiLegJunk(st, vs, total, leg + 2 * P);             // C_aud_j
            _multiLegJunk(st, vs, total, leg + 3 * P);             // D_aud_j
            _multiCommitJunk(st, vs, total, 6 + 5 * j + 3);        // A_aud_j
            _multiCommitJunk(st, vs, total, 6 + 5 * j + 4);        // A_Daud_j
            bytes memory t = bytes.concat(pr);
            _setWord(t, (6 + 5 * m) * P + (6 + 3 * j) * 32, 1);    // z_tj, in no equation and no challenge
            assertFalse(_ok(1, st, t), "z_tj");
        }
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

    /// @dev `verifyFold` on a range proof whose BP-2 is false and whose BP-1 holds, with no Σ terms.
    function _foldBroken(uint256 rho, uint256 weight) internal view returns (bool) {
        (bytes memory st, bytes memory pr) = _transfer(true);
        (bytes32 s1,) = _rho(st, pr, 10 * P);
        uint256[] memory at = new uint256[](1);
        at[0] = 131;
        bytes memory bp = _at(pr, 10 * P + 192, BP_LEN);
        _setWord(bp, BP_LEN - 32, addmod(_word(bp, BP_LEN - 32), 1, R));
        return ip.verifyFold(s1, IZetherInnerProductVerifier.SigmaFold(rho, weight, _point(pr, 0), new uint256[](132), at), bp);
    }

    /// `ρ ≡ 0` would keep only the first range equation: refused by the check, not by luck, in both spellings.
    function test_zeroRhoRefused() public view {
        assertFalse(_foldBroken(0, 1), "rho 0");
    }

    function test_rhoEqualToOrderRefused() public view {
        assertFalse(_foldBroken(R, 1), "rho r");
    }

    /// Weight `≡ 0` switches every range equation off, so any range proof would pass. The token cannot reach it (`ρ^e ≠ 0`);
    /// `verifyFold` is public and refuses it anyway.
    function test_zeroWeightRefused() public view {
        assertFalse(_foldBroken(5, 0), "weight 0");
    }

    function test_weightEqualToOrderRefused() public view {
        assertFalse(_foldBroken(5, R), "weight r");
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

    /// Requirement 1 on the standalone entry: `A + [1]G` breaks BP-2 alone, at weight `ρ`, so the sum is `[ρ]G` and shows the
    /// `ρ` in use. It must hash the commitment and the proof, both.
    function test_verifyRangeRhoHashesCommitmentAndProof() public {
        (bytes memory st,) = _transfer(true);
        prover.setTamper(0, 0, 32);
        bytes memory bad = _reprove(0, st);
        prover.setTamper(0, 0, 0);
        (bytes32 s1,) = _rho(st, bad, 10 * P);
        bytes memory V = _point(bad, 0);
        bytes memory bp = _at(bad, 10 * P + 192, BP_LEN);
        (, uint256 rho) = T.challenge(T.absorb(s1, "fold.proof", bytes.concat(V, bp)), "fold.rho", R);
        try probe.verifyRange(s1, V, bp) { revert("no fold"); } catch (bytes memory e) {
            (bytes memory sum,) = _folded(e);
            assertEq(sum, v.g1MulBase(rho));
        }
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

    /// @dev `isSupportedOnThisChain` on a chain whose G1MSM answers `input` with `out` instead of refusing it.
    function _supportedWhenAccepted(bytes memory input, bytes memory out) internal returns (bool ok) {
        vm.mockCall(address(0x0c), input, out);
        ok = v.isSupportedOnThisChain();
        vm.clearMockedCalls();
    }

    /// The probe holds the fold's precondition (requirement 3): a G1MSM that skips the subgroup check, alone or on a zero-scalar
    /// term, is refused, and each probe does it alone. `[1]T = T` and `[1]G + [0]T = G` are what such a chain would answer.
    function test_supportProbeRefusesMsmWithoutSubgroupCheck() public {
        bytes memory t = _lowOrder();
        bytes memory g = G1Bls12381.generator();
        assertTrue(v.isSupportedOnThisChain(), "a compliant chain");
        assertFalse(_supportedWhenAccepted(abi.encodePacked(t, uint256(1)), t), "G1MSM(T, 1) accepted");
        assertFalse(_supportedWhenAccepted(abi.encodePacked(g, uint256(1), t, uint256(0)), g), "G1MSM(G, 1, T, 0) accepted");
        assertTrue(v.isSupportedOnThisChain(), "compliant again");
    }

    /// Both probes fail by design on a compliant chain, and a failed precompile burns all it is sent. `ZetherLib.init` reads
    /// an out-of-gas probe as an unsupported chain, so an uncapped probe would refuse the chains it must accept.
    function test_supportProbeIsCapped() public view {
        (bool ok, bytes memory out) = address(v).staticcall{gas: 500_000}(abi.encodeCall(v.isSupportedOnThisChain, ()));
        assertTrue(ok && out.length == 32 && abi.decode(out, (uint256)) == 1, "the probe spent the call's gas");
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
