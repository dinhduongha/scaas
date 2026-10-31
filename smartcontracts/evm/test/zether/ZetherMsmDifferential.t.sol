// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {IZetherVerifier, IZetherBurnVerifier, IZetherInnerProductVerifier} from "../../src/zether/IZetherVerifier.sol";
import {G1Bls12381} from "../../src/zether/ZetherCurves.sol";
import {ZetherTranscript as T} from "../../src/zether/ZetherTranscript.sol";
import {ZetherMsmCorpus} from "./helpers/ZetherMsmCorpus.sol";
import {ZetherLegacyVerifiers} from "./helpers/ZetherLegacyVerifiers.sol";

interface IInnerProductOf {
    function innerProduct() external view returns (IZetherInnerProductVerifier);
}

/// @notice The per-equation verifier of `legacy/zether-msm/` and the merged one on the same rows: the Rust prover's S3
///         vectors, the Solidity prover's valid and cheating rows, and every point, scalar, header word and length of
///         each mutated (requirement 5 of zether.md §9.1). They must agree on accept or refuse. A revert is a refusal; the tally
///         prints how the two refuse, which differs by design: all points reach the one MSM, so a bad point reverts
///         where the old verifier may answer false at an earlier equation.
contract ZetherMsmDifferentialTest is ZetherMsmCorpus {
    using stdJson for string;

    uint256 constant GAS = 20_000_000; // a bad point burns all it is sent; M ≤ 3 verifies well inside this
    uint8 constant TRANSFER = 0;
    uint8 constant MULTI = 1;
    uint8 constant BURN = 2;
    uint8 constant NO = 0;
    uint8 constant YES = 1;
    uint8 constant REVERT = 2;
    string constant DIR = "test/vectors/zether/s3/";

    IZetherVerifier oldT;
    IZetherBurnVerifier oldB;
    uint256[3][3] tally; // tally[old][new]

    /// @dev Where a form keeps its points and scalars.
    struct Shape {
        uint8 op;
        uint256 sigmaPts;  // Σ points at the head of the proof
        uint256 zs;        // Σ scalars after them
        uint256 bps;       // range proofs after those
        uint256 stPts;     // points after the statement header
        uint256 legPts;    // the multi-recipient leg points, after `be32(M)`
    }

    function setUp() public {
        _corpus();
        (oldT, oldB) = ZetherLegacyVerifiers.deploy();
    }

    function _shape(uint8 op, uint256 m) internal pure returns (Shape memory) {
        if (op == TRANSFER) return Shape(op, 10, 6, 2, 9, 0);
        if (op == BURN) return Shape(op, 4, 3, 1, 3, 0);
        return Shape(op, 6 + 5 * m, 4 + 3 * m, m + 1, 6, 4 * m);
    }

    function verify(IZetherVerifier t, IZetherBurnVerifier b, uint8 op, bytes memory st, bytes memory pr)
        external view returns (bool)
    {
        return op == TRANSFER ? t.verifyTransfer(st, pr) : op == MULTI ? t.verifyTransferMulti(st, pr) : b.verifyBurn(st, pr);
    }

    function _verdict(IZetherVerifier t, IZetherBurnVerifier b, uint8 op, bytes memory st, bytes memory pr)
        internal view returns (uint8)
    {
        try this.verify{gas: GAS}(t, b, op, st, pr) returns (bool ok) { return ok ? YES : NO; } catch { return REVERT; }
    }

    /// @dev One row through both; returns the shared verdict.
    function _same(uint8 op, bytes memory st, bytes memory pr) internal returns (bool) {
        uint8 o = _verdict(oldT, oldB, op, st, pr);
        uint8 n = _verdict(v, vb, op, st, pr);
        assertEq(o == YES, n == YES, "old and new disagree");
        ++tally[o][n];
        return n == YES;
    }

    function _report() internal view {
        console2.log("rows old accept / new accept", tally[YES][YES]);
        console2.log("rows old false / new false", tally[NO][NO]);
        console2.log("rows old false / new revert", tally[NO][REVERT]);
        console2.log("rows old revert / new false", tally[REVERT][NO]);
        console2.log("rows old revert / new revert", tally[REVERT][REVERT]);
    }

    // ------------------------------------------------------------------ mutations

    function _pointRows(Shape memory h, bytes memory st, bytes memory pr, bool inSt, uint256 off, uint256 n) internal {
        for (uint256 i; i < n; ++i) {
            for (uint256 kind; kind < 4; ++kind) {
                (bytes memory a, bytes memory b) = (bytes.concat(st), bytes.concat(pr));
                _mutatePoint(inSt ? a : b, off + i * P, kind);
                _different(h.op, a, b, st, pr);
            }
        }
    }

    function _mutatePoint(bytes memory t, uint256 at, uint256 kind) internal view {
        if (kind == 0) _setPoint(t, at, new bytes(P));                                   // O
        else if (kind == 1) _setPoint(t, at, G1Bls12381.generator());                    // another subgroup point
        else if (kind == 2) _setPoint(t, at, G1Bls12381.add(_point(t, at), _lowOrder())); // out of the subgroup
        else t[at + P - 1] ^= 0x01;                                                      // off the curve, or not O any more
    }

    /// @dev A row that changed nothing (O on an auditor-off point) proves nothing and is skipped.
    function _different(uint8 op, bytes memory a, bytes memory b, bytes memory st, bytes memory pr) internal {
        if (keccak256(a) == keccak256(st) && keccak256(b) == keccak256(pr)) return;
        assertFalse(_same(op, a, b), "a mutated row accepted");
    }

    function _scalarRows(uint8 op, bytes memory st, bytes memory pr, uint256 off, uint256 n) internal {
        for (uint256 i; i < n; ++i) {
            uint256 at = off + 32 * i;
            uint256 w = _word(pr, at);
            bytes memory b = bytes.concat(pr);
            _setWord(b, at, addmod(w, 1, R));
            _different(op, st, b, st, pr);
            _setWord(b, at, w + R); // the same point, another encoding
            _different(op, st, b, st, pr);
        }
    }

    function _headerRows(uint8 op, bytes memory st, bytes memory pr) internal {
        for (uint256 i; i < HEADER / 32; ++i) {
            bytes memory a = bytes.concat(st);
            a[32 * i + 31] ^= 0x01;
            _different(op, a, pr, st, pr);
        }
    }

    function _lengthRows(uint8 op, bytes memory st, bytes memory pr) internal {
        _different(op, bytes.concat(st, new bytes(32)), pr, st, pr);
        _different(op, st, bytes.concat(pr, new bytes(32)), st, pr);
        _different(op, _head(st, st.length - 32), pr, st, pr);
        _different(op, st, _head(pr, pr.length - 32), st, pr);
    }

    /// @dev The first two range proofs swapped, and with them their commitments on the single form.
    function _swapRows(Shape memory h, bytes memory st, bytes memory pr) internal {
        if (h.bps < 2) return;
        uint256 off = h.sigmaPts * P + h.zs * 32;
        bytes memory b = bytes.concat(pr);
        for (uint256 i; i < BP_LEN; i += 32) {
            _setWord(b, off + i, _word(pr, off + BP_LEN + i));
            _setWord(b, off + BP_LEN + i, _word(pr, off + i));
        }
        _different(h.op, st, b, st, pr);
        if (h.op != TRANSFER) return;
        _setPoint(b, 0, _point(pr, P));
        _setPoint(b, P, _point(pr, 0));
        _different(h.op, st, b, st, pr);
    }

    function _sigmaAndStatementRows(Shape memory h, bytes memory st, bytes memory pr) internal {
        _pointRows(h, st, pr, false, 0, h.sigmaPts);
        _scalarRows(h.op, st, pr, h.sigmaPts * P, h.zs);
        _pointRows(h, st, pr, true, HEADER, h.stPts);
        _pointRows(h, st, pr, true, HEADER + h.stPts * P + 32, h.legPts);
        _headerRows(h.op, st, pr);
        _lengthRows(h.op, st, pr);
        _swapRows(h, st, pr);
    }

    function _rangeRows(Shape memory h, bytes memory st, bytes memory pr) internal {
        uint256 off = h.sigmaPts * P + h.zs * 32;
        for (uint256 k; k < h.bps; ++k) {
            _pointRows(h, st, pr, false, off + k * BP_LEN, 16);
            _scalarRows(h.op, st, pr, off + k * BP_LEN + 16 * P, 5);
        }
    }

    function _vector(string memory file) internal view returns (bytes memory st, bytes memory pr) {
        string memory j = vm.readFile(string.concat(DIR, file));
        (st, pr) = (j.readBytes(".statement"), j.readBytes(".proof"));
        assertTrue(j.readBool(".expect"));
    }

    function _legsOf(bytes memory st) internal pure returns (uint256) {
        return _word(st, HEADER + 6 * P);
    }

    function _s3(string memory file, uint8 op, bool ranges) internal {
        (bytes memory st, bytes memory pr) = _vector(file);
        assertTrue(_same(op, st, pr), "S3 vector");
        Shape memory h = _shape(op, op == MULTI ? _legsOf(st) : 0);
        if (ranges) _rangeRows(h, st, pr);
        else _sigmaAndStatementRows(h, st, pr);
        _report();
    }

    // ------------------------------------------------------------------ the Rust prover's vectors, mutated

    function test_s3TransferSigma() public { _s3("transfer_bls12381.json", TRANSFER, false); }
    function test_s3TransferRanges() public { _s3("transfer_bls12381.json", TRANSFER, true); }
    function test_s3TransferNoAuditorSigma() public { _s3("transfer_noaud_bls12381.json", TRANSFER, false); }
    function test_s3TransferNoAuditorRanges() public { _s3("transfer_noaud_bls12381.json", TRANSFER, true); }
    function test_s3BurnSigma() public { _s3("burn_bls12381.json", BURN, false); }
    function test_s3BurnRanges() public { _s3("burn_bls12381.json", BURN, true); }
    function test_s3MultiSigma() public { _s3("transfer_multi_bls12381.json", MULTI, false); }
    function test_s3MultiRanges() public { _s3("transfer_multi_bls12381.json", MULTI, true); }
    function test_s3MultiNoAuditorSigma() public { _s3("transfer_multi_noaud_bls12381.json", MULTI, false); }
    function test_s3MultiNoAuditorRanges() public { _s3("transfer_multi_noaud_bls12381.json", MULTI, true); }

    /// The refused generations of vectors: statements under the old ids, and the weak Fiat-Shamir forgeries.
    function test_refusedVectorGenerations() public {
        string[3] memory files = ["v2/transfer_bls12381.json", "v2/burn_bls12381.json", "v2/transfer_multi_bls12381.json"];
        uint8[3] memory ops = [TRANSFER, BURN, MULTI];
        for (uint256 i; i < 3; ++i) {
            string memory j = vm.readFile(string.concat(DIR, files[i]));
            assertFalse(_same(ops[i], j.readBytes(".statement"), j.readBytes(".proof")));
        }
        _report();
    }

    function test_multiMWord() public {
        (bytes memory st, bytes memory pr) = _multi(2, true);
        assertTrue(_same(MULTI, st, pr));
        uint256[4] memory ms = [uint256(0), 1, 3, 17];
        for (uint256 i; i < 4; ++i) {
            bytes memory a = bytes.concat(st);
            _setWord(a, HEADER + 6 * P, ms[i]);
            assertFalse(_same(MULTI, a, pr));
        }
    }

    // ------------------------------------------------------------------ the Solidity prover's rows

    function _cases(uint256 i) internal pure returns (Case memory) {
        if (i == 0) return Case(1000, 300, 300, 5, false);
        if (i == 1) return Case(1000, 300, 300, 5, true);
        if (i == 2) return Case(1000, 1000, 1000, 0, true);             // the whole balance, no fee
        if (i == 3) return Case(2 ** 64 + 6, 2 ** 64 - 1, 2 ** 64 - 1, 7, false); // v at the top, b' = 0
        if (i == 4) return Case(2 ** 54, 2 ** 44 + 3, 2 ** 44 + 3, 7, false);
        return Case(2 ** 64, 1, 1, 2 ** 64 - 1, false);                 // the largest fee
    }

    function test_validTransfers() public {
        for (uint256 i; i < 6; ++i) {
            (bytes memory st, bytes memory pr) = _transfer(_cases(i));
            assertTrue(_same(TRANSFER, st, pr), "valid");
        }
    }

    function test_cheatingTransfers() public {
        Case[4] memory bad = [
            Case(1000, 1001, 1001, 0, false),            // overspent: b' = −1
            Case(1000, 998, 998, 5, false),              // overspent by the fee
            Case(2 ** 64 + 10, 2 ** 64, 2 ** 64, 0, false), // v = 2^64
            Case(1000, 900, 100, 0, false)               // the ciphertext says 900, the witness 100
        ];
        for (uint256 i; i < 4; ++i) {
            (bytes memory st, bytes memory pr) = _transfer(bad[i]);
            assertFalse(_same(TRANSFER, st, pr), "cheating");
        }
    }

    function test_burns() public {
        bytes memory st = _burnSt(1000, 400, 5);
        assertTrue(_same(BURN, st, _proveBurn(st, XF, 595)), "valid");
        assertFalse(_same(BURN, st, _proveBurn(st, XF, 596)), "wrong balance");
        assertFalse(_same(BURN, st, _proveBurn(st, XT, 595)), "wrong key");
        st = _burnSt(1000, 996, 5);
        assertFalse(_same(BURN, st, _proveBurn(st, XF, addmod(1000, R - 1001, R))), "overspent");
    }

    function test_multis() public {
        for (uint256 m = 1; m <= 3; ++m) {
            (bytes memory st, bytes memory pr) = _multi(m, true);
            assertTrue(_same(MULTI, st, pr), "valid, auditor");
            (st, pr) = _multi(m, false);
            assertTrue(_same(MULTI, st, pr), "valid, no auditor");
            (st, pr) = _multi(m, true, 1);
            assertFalse(_same(MULTI, st, pr), "cheating balance");
        }
    }

    function test_mutatedSolidityRows() public {
        (bytes memory st, bytes memory pr) = _multi(1, true);
        _sigmaAndStatementRows(_shape(MULTI, 1), st, pr);
        _rangeRows(_shape(MULTI, 1), st, pr);
        _report();
    }

    // ------------------------------------------------------------------ the standalone range proof

    /// `verifyRange` keeps its answer and its returned state, a proof's mutated rows included.
    function test_verifyRangeAgrees() public view {
        (bytes memory st, bytes memory pr) = _transfer(true);
        (bytes32 s,) = T.challenge(T.absorb(T.absorb(T.init(), "statement", st), "sigma.commit", _head(pr, 10 * P)), "sigma.c", R);
        bytes memory bp = _at(pr, 10 * P + 192, BP_LEN);
        bytes memory V = _point(pr, 0);
        for (uint256 i; i <= 21; ++i) {
            bytes memory t = bytes.concat(bp);
            if (i > 0 && i <= 16) t[(i - 1) * P + P - 1] ^= 0x01;
            else if (i > 16) t[16 * P + (i - 17) * 32 + 31] ^= 0x01;
            (bool ok, bytes32 s2) = _range(v, s, V, t);
            (bool okOld, bytes32 s2Old) = _range(oldT, s, V, t);
            assertEq(ok, okOld, "verdict");
            assertEq(ok, i == 0, "only the honest proof");
            if (i == 0) assertEq(s2, s2Old, "state");
        }
    }

    function _range(IZetherVerifier t, bytes32 s, bytes memory V, bytes memory bp) internal view returns (bool, bytes32) {
        try this.range{gas: GAS}(t, s, V, bp) returns (bool ok, bytes32 out) { return (ok, out); } catch { return (false, s); }
    }

    function range(IZetherVerifier t, bytes32 s, bytes memory V, bytes memory bp) external view returns (bool, bytes32) {
        return IInnerProductOf(address(t)).innerProduct().verifyRange(s, V, bp);
    }
}
