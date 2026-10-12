// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ZetherVerifierBn254, ZetherVerifierBls12381, ZetherVerifierBase} from "../../src/zether/ZetherVerifier.sol";
import {IZetherVerifier} from "../../src/zether/IZetherVerifier.sol";
import {ZetherTranscript as T} from "../../src/zether/ZetherTranscript.sol";
import {G1Bn254, G1Bls12381} from "../../src/zether/ZetherCurves.sol";

/// @notice Ghim Solidity vào vector do `kat.py` (Python + py_ecc, viết độc lập từ đặc tả §3, §4, §11.1)
///         sinh ra. Generator, transcript, hash-to-scalar sai một byte là mọi proof của S3 fail — nên phải
///         bị bắt ở đây chứ không phải lúc tích hợp.
contract ZetherKatTest is Test {
    using stdJson for string;

    string constant DIR = "test/vectors/zether/";
    ZetherVerifierBn254 bn;
    ZetherVerifierBls12381 bls;

    function setUp() public {
        bn = new ZetherVerifierBn254();
        bls = new ZetherVerifierBls12381();
    }

    function _checkGenerators(IZetherVerifier v, string memory file) internal view {
        string memory j = vm.readFile(string.concat(DIR, file));
        uint256 p = v.g1EncodedBytes();
        bytes memory blob = v.generators();
        assertEq(blob.length, 130 * p, "blob length");
        assertEq(keccak256(blob), j.readBytes32(".blobKeccak"), "blob keccak");
        assertEq(v.proofSystemId(), j.readBytes32(".proofSystemId"), "proofSystemId");
        assertEq(_at(blob, 0, p), j.readBytes(".h"), "h");
        assertEq(_at(blob, 1, p), j.readBytes(".U"), "U");
        bytes[] memory G = j.readBytesArray(".G");
        bytes[] memory H = j.readBytesArray(".H");
        for (uint256 i; i < 64; ++i) {
            assertEq(_at(blob, 2 + i, p), G[i], "G_i");
            assertEq(_at(blob, 66 + i, p), H[i], "H_i");
        }
    }

    function _at(bytes memory blob, uint256 i, uint256 p) internal pure returns (bytes memory out) {
        out = new bytes(p);
        for (uint256 k; k < p; ++k) out[k] = blob[i * p + k];
    }

    function test_generatorsBn254MatchIndependentReference() public view {
        _checkGenerators(bn, "generators_bn254.json");
    }

    function test_generatorsBls12381MatchIndependentReference() public view {
        _checkGenerators(bls, "generators_bls12381.json");
    }

    function test_transcriptMatchesReference() public view {
        string memory j = vm.readFile(string.concat(DIR, "transcript.json"));
        for (uint256 c; c < 2; ++c) {
            string memory pre = string.concat(".cases[", vm.toString(c), "]");
            uint256 r = c == 0 ? G1Bn254.R : G1Bls12381.R;
            assertEq(T.init(), j.readBytes32(string.concat(pre, ".init")));
            bytes32[] memory states = j.readBytes32Array(string.concat(pre, ".states"));
            bytes32[] memory chals = j.readBytes32Array(string.concat(pre, ".challenges"));
            bytes32 st = T.init();
            uint256 ci;
            for (uint256 i; i < states.length; ++i) {
                string memory op = string.concat(pre, ".ops[", vm.toString(i), "]");
                if (vm.keyExistsJson(j, string.concat(op, ".absorb"))) {
                    st = T.absorb(st, j.readString(string.concat(op, ".absorb")), j.readBytes(string.concat(op, ".data")));
                } else {
                    uint256 ch;
                    (st, ch) = T.challenge(st, j.readString(string.concat(op, ".challenge")), r);
                    assertEq(bytes32(ch), chals[ci++], "challenge");
                }
                assertEq(st, states[i], "state");
            }
        }
    }

    function test_hashToScalarMatchesReference() public view {
        string memory j = vm.readFile(string.concat(DIR, "transcript.json"));
        for (uint256 i; i < 3; ++i) {
            string memory pre = string.concat(".hashToScalar[", vm.toString(i), "]");
            bytes32 seed = j.readBytes32(string.concat(pre, ".seed"));
            assertEq(T.hashToScalar(seed, G1Bn254.R), uint256(j.readBytes32(string.concat(pre, ".bn254"))));
            assertEq(T.hashToScalar(seed, G1Bls12381.R), uint256(j.readBytes32(string.concat(pre, ".bls12381"))));
        }
    }

    function _checkSchnorr(IZetherVerifier v, string memory file) internal view {
        string memory j = vm.readFile(string.concat(DIR, file));
        uint256 x = uint256(j.readBytes32(".x"));
        bytes memory Y = j.readBytes(".Y");
        bytes memory R = j.readBytes(".R");
        assertEq(v.g1MulBase(x), Y, "Y = [x]G");
        assertEq(v.g1MulBase(uint256(j.readBytes32(".k"))), R, "R = [k]G");
        uint256 e = T.hashToScalar(keccak256(abi.encodePacked("SCAAS-ZETHER-SCHNORR-V1", R, Y, j.readBytes32(".msg"))), v.groupOrder());
        assertEq(e, uint256(j.readBytes32(".e")), "e");
        // [z]G == R + [e]Y
        assertEq(v.g1MulBase(uint256(j.readBytes32(".z"))), v.g1Add(R, v.g1Mul(Y, e)), "schnorr eq");
    }

    function test_schnorrBn254MatchesReference() public view { _checkSchnorr(bn, "schnorr_bn254.json"); }
    function test_schnorrBls12381MatchesReference() public view { _checkSchnorr(bls, "schnorr_bls12381.json"); }

    // --------------------------------------------------------------- phép nhóm

    function _groupLaws(IZetherVerifier v) internal view {
        bytes memory g2 = v.g1MulBase(2);
        bytes memory g3 = v.g1MulBase(3);
        bytes memory g5 = v.g1MulBase(5);
        assertEq(v.g1Add(g2, g3), g5, "2G+3G");
        assertEq(v.g1Sub(g5, g3), g2, "5G-3G");
        assertEq(v.g1Sub(g3, g3), v.identity(), "P-P = O");
        assertEq(v.g1Add(g3, v.identity()), g3, "P+O");
        assertEq(v.g1Mul(g2, v.groupOrder() - 1), v.g1Sub(v.identity(), g2), "[r-1]P = -P");
        uint256[] memory sc = new uint256[](3);
        (sc[0], sc[1], sc[2]) = (7, 11, v.groupOrder() - 13);
        assertEq(v.g1Msm(bytes.concat(g2, g3, g5), sc), v.g1MulBase(v.groupOrder() - 18), "msm");
        assertTrue(v.isValidPoint(g5));
        assertTrue(v.isValidPoint(v.identity()));
        assertTrue(v.isSupportedOnThisChain());
        assertEq(v.ringSize(), 2);
    }

    function test_groupLawsBn254() public view { _groupLaws(bn); }
    function test_groupLawsBls12381() public view { _groupLaws(bls); }

    function test_bn254RejectsOffCurve() public {
        bytes memory bad = abi.encodePacked(uint256(1), uint256(3));
        assertFalse(bn.isValidPoint(bad));
        bytes memory g = bn.g1MulBase(1);
        vm.expectRevert(G1Bn254.BadPoint.selector);
        bn.g1Add(bad, g);
        assertFalse(bn.isValidPoint(abi.encodePacked(uint256(1), G1Bn254.P + 2))); // không chính tắc
        assertFalse(bn.isValidPoint(new bytes(63)));
    }

    function test_blsRejectsNonSubgroupAndOffCurve() public {
        string memory j = vm.readFile(string.concat(DIR, "curve_misc.json"));
        bytes memory ns = j.readBytes(".blsNonSubgroup");
        assertFalse(bls.isValidPoint(ns), "subgroup");
        uint256[] memory one = new uint256[](1);
        one[0] = 1;
        vm.expectRevert(G1Bls12381.BadPoint.selector);
        bls.g1Msm(ns, one);
        bytes memory off = bls.g1MulBase(1);
        off[127] = bytes1(uint8(off[127]) ^ 1);
        assertFalse(bls.isValidPoint(off), "on-curve");
        assertFalse(bls.isValidPoint(new bytes(64)));
    }

    function test_blsNegMatchesSubtraction() public view {
        bytes memory a = bls.g1MulBase(123456789);
        assertEq(bls.g1Add(a, G1Bls12381.neg(a)), bls.identity());
        assertEq(G1Bls12381.neg(bls.identity()), bls.identity());
    }

    function test_blsAddNegRejectBadInput() public {
        bytes memory g = bls.g1MulBase(1);
        vm.expectRevert(abi.encodeWithSelector(G1Bls12381.BadLength.selector, 127));
        bls.g1Add(new bytes(127), g);
        vm.expectRevert(abi.encodeWithSelector(G1Bls12381.BadLength.selector, 127));
        bls.g1Sub(g, new bytes(127)); // neg
        bytes memory off = bls.g1MulBase(1);
        off[127] = off[127] ^ 0x01;
        vm.expectRevert(G1Bls12381.BadPoint.selector); // G1ADD kiểm on-curve
        bls.g1Add(off, g);
    }

    function test_emptyMsmRevertsOnBls() public {
        vm.expectRevert(abi.encodeWithSelector(G1Bls12381.BadLength.selector, 0));
        bls.g1Msm("", new uint256[](0));
    }
}
