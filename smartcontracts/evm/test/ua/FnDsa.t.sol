// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PqVectors} from "./PqVectors.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {Shake} from "../../src/ua/Shake.sol";
import {Falcon512, UAFndsaVerifier} from "../../src/ua/FnDsa.sol";

contract FnHarness {
    function verify(bytes calldata pk, bytes calldata m, bytes calldata sig) external pure returns (bool) {
        Shake.reserve();
        return Falcon512.verify(pk, m, sig);
    }

    function shake(uint256 rate, bytes calldata input, uint256 outLen) external pure returns (bytes memory out) {
        Shake.reserve();
        bytes memory inp = input;
        out = new bytes(outLen + 200); // whole blocks are written
        uint256 p;
        uint256 o;
        assembly {
            p := add(inp, 32)
            o := add(out, 32)
        }
        Shake.hash(rate, p, input.length, o, outLen);
        assembly {
            mstore(out, outLen)
        }
    }
}

/// `fndsa512` (CTR-UA-23): SHAKE (FIPS 202), the NTT table, the NIST Falcon-512 KATs published with EIP-8052 rebuilt
/// as padded signatures, the SCaaS UA vector, malformed encodings.
contract FnDsaTest is PqVectors {
    function test_shake_knownAnswers() public {
        FnHarness h = new FnHarness();
        // SHAKE128("") and SHAKE256("") (FIPS 202 examples), and a 200-byte input spanning a SHAKE256 block (noble)
        assertEq(h.shake(168, "", 32), hex"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        assertEq(h.shake(136, "", 64),
            hex"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
        bytes memory long = new bytes(200);
        for (uint256 i; i < 200; ++i) long[i] = bytes1(uint8(i));
        assertEq(h.shake(136, long, 32), _b(_kat(), ".shake256_200"));
    }

    function test_zetaTable_falcon() public pure {
        _zetas(Falcon512.ZETAS, 2, 512, 12289, 10302);
    }

    function test_kat_fndsa512() public {
        _uaVector("fndsa512", address(new UAFndsaVerifier()), PqUA.FNDSA512);
    }

    function test_falcon_nistKat() public {
        vm.pauseGasMetering();
        string memory ext = _ext();
        FnHarness h = new FnHarness();
        assertEq(_cases(ext, "falcon_kat"), 10);
        for (uint256 i; i < 10; ++i) {
            string memory c = _case("falcon_kat", i);
            bytes memory pk = _b(ext, string.concat(c, ".pk"));
            bytes memory m = _b(ext, string.concat(c, ".msg"));
            bytes memory sig = _b(ext, string.concat(c, ".sig"));
            assertTrue(h.verify(pk, m, sig));
            sig[665] = 0x01; // non-zero padding
            assertFalse(h.verify(pk, m, sig));
        }
    }

    /// Malformed inputs are refused, never reduced: a coefficient ≥ q, the headers, the lengths.
    function test_malformed_fndsa() public {
        string memory kat = _kat();
        UAFndsaVerifier v = new UAFndsaVerifier();
        bytes memory pk = _k(kat, "fndsa512", "pk");
        bytes memory sig = _k(kat, "fndsa512", "sig");
        bytes32 m = bytes32(_k(kat, "fndsa512", "ua_msg"));
        assertTrue(v.verify(pk, m, sig));
        bytes memory bad = bytes.concat(pk);
        bad[1] = 0xff; // first 14-bit coefficient ≥ 0x3fc0 > q
        assertFalse(v.verify(bad, m, sig));
        bad = bytes.concat(pk);
        bad[0] = 0x0a; // logn header
        assertFalse(v.verify(bad, m, sig));
        bad = bytes.concat(sig);
        bad[0] = 0x29; // the unpadded (NIST API) header
        assertFalse(v.verify(pk, m, bad));
        assertFalse(v.verify(pk, m, bytes.concat(sig, hex"00")));
    }
}
