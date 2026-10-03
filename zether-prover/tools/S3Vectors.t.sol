// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ZetherVerifierBn254, ZetherVerifierBls12381} from "../../src/zether/ZetherVerifier.sol";
import {IZetherVerifier} from "../../src/zether/IZetherVerifier.sol";

/// S3 (Rust prover) vectors through S2's Solidity verifier. Scratch-only harness.
contract S3VectorsTest is Test {
    ZetherVerifierBn254 bn;
    ZetherVerifierBls12381 bls;

    function setUp() public {
        bn = new ZetherVerifierBn254();
        bls = new ZetherVerifierBls12381();
    }

    function callVerify(IZetherVerifier v, bytes memory st, bytes memory pr, bool transfer) external view returns (bool) {
        return transfer ? v.verifyTransfer(st, pr) : v.verifyBurn(st, pr);
    }

    function _ok(IZetherVerifier v, bytes memory st, bytes memory pr, bool transfer) internal view returns (bool) {
        try this.callVerify(v, st, pr, transfer) returns (bool ok) { return ok; } catch { return false; }
    }

    function _run(IZetherVerifier v, string memory file, bool transfer) internal {
        string memory j = vm.readFile(string.concat("test/vectors/zether/s3/", file));
        bytes memory st = vm.parseJsonBytes(j, ".statement");
        bytes memory pr = vm.parseJsonBytes(j, ".proof");
        uint256 g0 = gasleft();
        assertTrue(_ok(v, st, pr, transfer), string.concat(file, ": valid vector rejected"));
        emit log_named_uint(string.concat(file, " verify gas"), g0 - gasleft());
        // flip one bit in the last scalar of the proof and in the statement's accSeq word
        bytes memory pr2 = bytes.concat(pr);
        pr2[pr2.length - 1] ^= 0x01;
        assertFalse(_ok(v, st, pr2, transfer), string.concat(file, ": flipped proof accepted"));
        bytes memory st2 = bytes.concat(st);
        st2[255] ^= 0x01;
        assertFalse(_ok(v, st2, pr, transfer), string.concat(file, ": flipped statement accepted"));
    }

    function test_s3_vectors_bn254() public {
        _run(bn, "transfer_bn254.json", true);
        _run(bn, "transfer_noaud_bn254.json", true);
        _run(bn, "burn_bn254.json", false);
    }

    function test_s3_vectors_bls12381() public {
        _run(bls, "transfer_bls12381.json", true);
        _run(bls, "transfer_noaud_bls12381.json", true);
        _run(bls, "burn_bls12381.json", false);
    }
}
