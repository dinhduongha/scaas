// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
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

    /// Misuse: no `Shake.reserve()` first.
    function verifyUnreserved(bytes calldata pk, bytes calldata m, bytes calldata sig) external pure returns (bool) {
        return Falcon512.verify(pk, m, sig);
    }

    function decompress(bytes calldata comp) external pure returns (bool ok) {
        (ok,) = Falcon512._decompress(comp);
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
        uint256 negZeros;
        uint256 unusedBits;
        for (uint256 i; i < 10; ++i) {
            string memory c = _case("falcon_kat", i);
            bytes memory pk = _b(ext, string.concat(c, ".pk"));
            bytes memory m = _b(ext, string.concat(c, ".msg"));
            bytes memory sig = _b(ext, string.concat(c, ".sig"));
            assertTrue(h.verify(pk, m, sig));
            (bool negZero, bool unused) = _pinChecks(h, pk, m, sig);
            if (negZero) ++negZeros;
            if (unused) ++unusedBits;
            sig[665] = 0x01; // non-zero padding
            assertFalse(h.verify(pk, m, sig));
        }
        assertEq(negZeros, 9); // cases 0–6, 8, 9 have a zero coefficient
        assertGt(unusedBits, 0);
    }

    /// Malformed inputs are refused, never reduced: the headers, the lengths, and (`_pinChecks`) a pk coefficient `h_i + q`,
    /// a 898-byte pk, "−0", a set unused bit, the unpadded form.
    function test_malformed_fndsa() public {
        string memory kat = _kat();
        UAFndsaVerifier v = new UAFndsaVerifier();
        bytes memory pk = _k(kat, "fndsa512", "pk");
        bytes memory sig = _k(kat, "fndsa512", "sig");
        bytes32 m = bytes32(_k(kat, "fndsa512", "ua_msg"));
        assertTrue(v.verify(pk, m, sig));
        bytes memory bad = bytes.concat(pk);
        bad[1] = 0xff; // first 14-bit coefficient ≥ 0x3fc0 > q (also a different h: `h_i + q` below pins the range check)
        assertFalse(v.verify(bad, m, sig));
        bad = bytes.concat(pk);
        bad[0] = 0x0a; // logn header
        assertFalse(v.verify(bad, m, sig));
        bad = bytes.concat(sig);
        bad[0] = 0x29; // the unpadded (NIST API) header
        assertFalse(v.verify(pk, m, bad));
        assertFalse(v.verify(pk, m, bytes.concat(sig, hex"00")));
        (bool negZero, bool unused) = _pinChecks(new FnHarness(), pk, abi.encodePacked(m), sig);
        assertTrue(negZero && unused);
    }

    /// `|s2_i| ≤ 2047` (not observable through `verify`: changing a coefficient changes `s1`): 2047 decodes, 2048 does not.
    function test_decode_s2Bound() public {
        FnHarness h = new FnHarness();
        assertTrue(h.decompress(_comp(2047)));
        assertFalse(h.decompress(_comp(2048)));
    }

    /// `Shake` without `reserve()` reverts instead of overwriting the caller's memory.
    function test_shake_requiresReserve() public {
        string memory kat = _kat();
        FnHarness h = new FnHarness();
        bytes memory m = _k(kat, "fndsa512", "ua_msg");
        vm.expectRevert(Shake.ShakeMemory.selector);
        h.verifyUnreserved(_k(kat, "fndsa512", "pk"), m, _k(kat, "fndsa512", "sig"));
    }

    /// The checks a valid signature does not reach: each mutant below verifies iff its check is removed from FnDsa.sol.
    /// Returns whether the vector has a zero coefficient (for "−0") and unused bits in its last s2 byte.
    function _pinChecks(FnHarness h, bytes memory pk, bytes memory m, bytes memory sig)
        internal pure returns (bool negZero, bool unused)
    {
        assertFalse(h.verify(bytes.concat(pk, hex"00"), m, sig), "pk length 898");
        bytes memory bad = bytes.concat(pk);
        uint256 i;
        while (_bits(bad, 8 + 14 * i, 14) >= 16384 - 12289) ++i;
        _setBits(bad, 8 + 14 * i, 14, _bits(bad, 8 + 14 * i, 14) + 12289);
        assertFalse(h.verify(bad, m, sig), "h_i + q");
        // walk the compressed s2 (bit 0 = first bit after the salt): sign, 7 low bits, unary high part
        uint256 pos = 328;
        uint256 zeroAt;
        for (i = 0; i < 512; ++i) {
            if (zeroAt == 0 && _bits(sig, pos, 9) == 1) zeroAt = pos; // 0x00 then the unary stop bit: the value 0
            pos += 8;
            while (_bits(sig, pos, 1) == 0) ++pos;
            ++pos;
        }
        assertFalse(h.verify(pk, m, _slice(sig, (pos + 7) / 8)), "unpadded behind 0x39");
        if (zeroAt != 0) {
            negZero = true;
            bad = bytes.concat(sig);
            _setBits(bad, zeroAt, 1, 1); // the sign bit
            assertFalse(h.verify(pk, m, bad), "-0");
        }
        if (pos % 8 != 0) {
            unused = true;
            bad = bytes.concat(sig);
            _setBits(bad, pos, 1, 1);
            assertFalse(h.verify(pk, m, bad), "unused bit of the last s2 byte");
        }
    }

    /// One s2 encoding: coefficient 0 = `v0`, the other 511 zero (sign 0, 7 low bits, unary high part, stop bit 1).
    function _comp(uint256 v0) internal pure returns (bytes memory c) {
        c = new bytes(625);
        uint256 p;
        for (uint256 i; i < 512; ++i) {
            uint256 v = i == 0 ? v0 : 0;
            _setBits(c, p, 8, v & 127);
            p += 8 + (v >> 7);
            _setBits(c, p, 1, 1);
            ++p;
        }
    }

    /// `n` bits of `b` at bit position `p`, most significant bit first.
    function _bits(bytes memory b, uint256 p, uint256 n) internal pure returns (uint256 v) {
        for (uint256 i = p; i < p + n; ++i) v = (v << 1) | ((uint8(b[i / 8]) >> (7 - i % 8)) & 1);
    }

    function _setBits(bytes memory b, uint256 p, uint256 n, uint256 v) internal pure {
        for (uint256 i; i < n; ++i) {
            uint256 bit = p + i;
            uint8 mask = uint8(128 / 2 ** (bit % 8));
            uint8 cur = uint8(b[bit / 8]) & ~mask;
            b[bit / 8] = bytes1((v >> (n - 1 - i)) & 1 == 1 ? cur | mask : cur);
        }
    }

    function _slice(bytes memory b, uint256 len) internal pure returns (bytes memory s) {
        s = new bytes(len);
        for (uint256 i; i < len; ++i) s[i] = b[i];
    }
}
