// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqVectors} from "./PqVectors.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {Shake} from "../../src/ua/Shake.sol";
import {Falcon, UAFndsaVerifier} from "../../src/ua/FnDsa.sol";

/// `Falcon` at one `logn` (9: Falcon-512, 10: Falcon-1024).
contract FnHarness {
    uint256 public immutable logn;
    uint256 public immutable n;

    constructor(uint256 logn_) {
        (logn, n) = (logn_, 1 << logn_);
    }

    function verify(bytes calldata pk, bytes calldata m, bytes calldata sig) external view returns (bool) {
        Shake.reserve();
        return Falcon.verify(logn, pk, m, sig);
    }

    /// Misuse: no `Shake.reserve()` first.
    function verifyUnreserved(bytes calldata pk, bytes calldata m, bytes calldata sig) external view returns (bool) {
        return Falcon.verify(logn, pk, m, sig);
    }

    function decompress(bytes calldata comp) external view returns (bool ok) {
        (ok,) = Falcon._decompress(comp, n);
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

/// `fndsa512` (CTR-UA-23) and `fndsa1024` (CTR-UA-40): SHAKE (FIPS 202), the shared NTT table, the NIST round-3 Falcon-512 KATs
/// published with EIP-8052 and the NIST round-3 Falcon-1024 KATs, rebuilt as padded signatures, the SCaaS UA vectors, malformed
/// encodings, the verifier's kind.
contract FnDsaTest is PqVectors {
    function test_shake_knownAnswers() public {
        FnHarness h = new FnHarness(9);
        // SHAKE128("") and SHAKE256("") (FIPS 202 examples), and a 200-byte input spanning a SHAKE256 block (noble)
        assertEq(h.shake(168, "", 32), hex"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        assertEq(h.shake(136, "", 64),
            hex"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
        bytes memory long = new bytes(200);
        for (uint256 i; i < 200; ++i) long[i] = bytes1(uint8(i));
        assertEq(h.shake(136, long, 32), _b(_kat(), ".shake256_200"));
    }

    /// One table: `1945^brv10(k)` for n = 1,024, whose first 512 entries are Falcon-512's `10302^brv9(k)` (n = 512 reads those).
    function test_zetaTable_falcon() public pure {
        _zetas(Falcon.ZETAS, 2, 1024, 12289, 1945);
        _zetas(_slice(Falcon.ZETAS, 1024), 2, 512, 12289, 10302);
    }

    function test_kat_fndsa512() public {
        _uaVector("fndsa512", address(new UAFndsaVerifier(PqUA.FNDSA512)), PqUA.FNDSA512);
    }

    /// CTR-UA-40: the `fndsa1024` row of pq_kat.json (clientkeys, noble 0.7.1) and its mutations through the verifier.
    function test_kat_fndsa1024() public {
        _uaVector("fndsa1024", address(new UAFndsaVerifier(PqUA.FNDSA1024)), PqUA.FNDSA1024);
    }

    /// The verifier's kind picks its parameters: one deployment per Falcon kind; any other kind is refused at construction, and
    /// neither size accepts the other's key or signature.
    function test_fndsaVerifier_kind() public {
        string memory kat = _kat();
        UAFndsaVerifier v512 = new UAFndsaVerifier(PqUA.FNDSA512);
        UAFndsaVerifier v1024 = new UAFndsaVerifier(PqUA.FNDSA1024);
        assertEq(v512.KIND(), PqUA.FNDSA512);
        assertEq(v1024.KIND(), PqUA.FNDSA1024);
        uint16[4] memory others = [uint16(0x0131), 0x0133, 0x0134, 0x0136];
        for (uint256 i; i < 4; ++i) {
            vm.expectRevert(abi.encodeWithSelector(UAFndsaVerifier.UAFndsaKind.selector, others[i]));
            new UAFndsaVerifier(others[i]);
        }
        string[2] memory names = ["fndsa512", "fndsa1024"];
        UAFndsaVerifier[2] memory vs = [v512, v1024];
        for (uint256 i; i < 2; ++i) {
            bytes memory pk = _k(kat, names[i], "pk");
            bytes memory sig = _k(kat, names[i], "sig");
            bytes32 m = bytes32(_k(kat, names[i], "ua_msg"));
            assertTrue(vs[i].verify(pk, m, sig));
            assertFalse(vs[1 - i].verify(pk, m, sig), "the other size");
        }
    }

    function test_falcon_nistKat() public {
        vm.pauseGasMetering();
        string memory ext = _ext();
        FnHarness h = new FnHarness(9);
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

    /// CTR-UA-40: the NIST round-3 Falcon-1024 KATs (falcon1024-KAT.rsp of Falcon-Round3.zip, both SHA-256 pinned by
    /// pq-external.mjs) rebuilt as padded 1,280-byte signatures; the rows whose compressed s2 exceeds 1,239 B have no padded form
    /// (count 82). Every pinned check, a set padding byte, the Falcon-512 header and the Falcon-512 verifier refuse.
    function test_falcon1024_nistKat() public {
        vm.pauseGasMetering();
        string memory ext = _ext();
        FnHarness h = new FnHarness(10);
        FnHarness h512 = new FnHarness(9);
        assertEq(_cases(ext, "falcon1024_kat"), 10);
        assertEq(vm.parseJsonUintArray(ext, ".falcon1024_kat.rows_over_1239"), _one(82));
        uint256 negZeros;
        uint256 unusedBits;
        for (uint256 i; i < 10; ++i) {
            string memory c = _case("falcon1024_kat", i);
            bytes memory pk = _b(ext, string.concat(c, ".pk"));
            bytes memory m = _b(ext, string.concat(c, ".msg"));
            bytes memory sig = _b(ext, string.concat(c, ".sig"));
            assertTrue(h.verify(pk, m, sig));
            assertFalse(h512.verify(pk, m, sig), "Falcon-512 parameters");
            (bool negZero, bool unused) = _pinChecks(h, pk, m, sig);
            if (negZero) ++negZeros;
            if (unused) ++unusedBits;
            bytes memory bad = bytes.concat(sig);
            bad[1279] = 0x01; // non-zero padding
            assertFalse(h.verify(pk, m, bad));
            bad = bytes.concat(sig);
            bad[0] = 0x39; // the Falcon-512 signature header
            assertFalse(h.verify(pk, m, bad));
        }
        assertGt(negZeros, 0);
        assertGt(unusedBits, 0);
    }

    function _one(uint256 v) internal pure returns (uint256[] memory a) {
        a = new uint256[](1);
        a[0] = v;
    }

    /// Malformed inputs are refused, never reduced: the headers, the lengths, and (`_pinChecks`) a pk coefficient `h_i + q`,
    /// a 898-byte pk, "−0", a set unused bit, the unpadded form.
    function test_malformed_fndsa() public {
        string memory kat = _kat();
        UAFndsaVerifier v = new UAFndsaVerifier(PqUA.FNDSA512);
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
        (bool negZero, bool unused) = _pinChecks(new FnHarness(9), pk, abi.encodePacked(m), sig);
        assertTrue(negZero && unused);
    }

    /// The same for `fndsa1024` (pq_kat.json's row): headers `0x0A` / `0x3A`, 1,793 / 1,280 B, every pinned check.
    function test_malformed_fndsa1024() public {
        string memory kat = _kat();
        UAFndsaVerifier v = new UAFndsaVerifier(PqUA.FNDSA1024);
        bytes memory pk = _k(kat, "fndsa1024", "pk");
        bytes memory sig = _k(kat, "fndsa1024", "sig");
        bytes32 m = bytes32(_k(kat, "fndsa1024", "ua_msg"));
        assertTrue(v.verify(pk, m, sig));
        assertTrue(v.verifyPop(pk, m, sig));
        bytes memory bad = bytes.concat(pk);
        bad[0] = 0x09; // the Falcon-512 key header
        assertFalse(v.verify(bad, m, sig));
        bad = bytes.concat(sig);
        bad[0] = 0x2a; // the unpadded (NIST API) header
        assertFalse(v.verify(pk, m, bad));
        assertFalse(v.verify(pk, m, bytes.concat(sig, hex"00")), "1,281 B");
        bad = new bytes(1279);
        for (uint256 i; i < 1279; ++i) bad[i] = sig[i];
        assertFalse(v.verify(pk, m, bad), "1,279 B");
        (bool negZero, bool unused) = _pinChecks(new FnHarness(10), pk, abi.encodePacked(m), sig);
        assertTrue(negZero || unused);
    }

    /// `|s2_i| ≤ 2047` (not observable through `verify`: changing a coefficient changes `s1`): 2047 decodes, 2048 does not,
    /// at n = 512 (625 B after the salt) and n = 1,024 (1,239 B).
    function test_decode_s2Bound() public {
        FnHarness h = new FnHarness(9);
        assertTrue(h.decompress(_comp(2047, 512, 625)));
        assertFalse(h.decompress(_comp(2048, 512, 625)));
        h = new FnHarness(10);
        assertTrue(h.decompress(_comp(2047, 1024, 1239)));
        assertFalse(h.decompress(_comp(2048, 1024, 1239)));
        assertFalse(h.decompress(_comp(0, 512, 1239)), "512 coefficients and zeros: the 1,024-th is missing");
    }

    /// `Shake` without `reserve()` reverts instead of overwriting the caller's memory.
    function test_shake_requiresReserve() public {
        string memory kat = _kat();
        FnHarness h = new FnHarness(9);
        bytes memory m = _k(kat, "fndsa512", "ua_msg");
        vm.expectRevert(Shake.ShakeMemory.selector);
        h.verifyUnreserved(_k(kat, "fndsa512", "pk"), m, _k(kat, "fndsa512", "sig"));
    }

    /// The checks a valid signature does not reach: each mutant below verifies iff its check is removed from FnDsa.sol.
    /// Returns whether the vector has a zero coefficient (for "−0") and unused bits in its last s2 byte.
    function _pinChecks(FnHarness h, bytes memory pk, bytes memory m, bytes memory sig)
        internal view returns (bool negZero, bool unused)
    {
        assertFalse(h.verify(bytes.concat(pk, hex"00"), m, sig), "pk length + 1");
        bytes memory bad = bytes.concat(pk);
        uint256 i;
        while (_bits(bad, 8 + 14 * i, 14) >= 16384 - 12289) ++i;
        _setBits(bad, 8 + 14 * i, 14, _bits(bad, 8 + 14 * i, 14) + 12289);
        assertFalse(h.verify(bad, m, sig), "h_i + q");
        // walk the compressed s2 (bit 0 = first bit after the salt): sign, 7 low bits, unary high part
        uint256 pos = 328;
        uint256 zeroAt;
        for (i = 0; i < h.n(); ++i) {
            if (zeroAt == 0 && _bits(sig, pos, 9) == 1) zeroAt = pos; // 0x00 then the unary stop bit: the value 0
            pos += 8;
            while (_bits(sig, pos, 1) == 0) ++pos;
            ++pos;
        }
        assertFalse(h.verify(pk, m, _slice(sig, (pos + 7) / 8)), "unpadded behind the padded header");
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

    /// One s2 encoding of `bytes_` bytes: coefficient 0 = `v0`, the other `n − 1` zero (sign 0, 7 low bits, unary high part, stop
    /// bit 1), then zero bits.
    function _comp(uint256 v0, uint256 n, uint256 bytes_) internal pure returns (bytes memory c) {
        c = new bytes(bytes_);
        uint256 p;
        for (uint256 i; i < n; ++i) {
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
