// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {Pqzh, PqzhSkeleton} from "./Pqzh.sol";
import {Shake} from "../../src/ua/Shake.sol";

/// Harness: every component on the reference vectors (results returned) and in loops (gas per operation =
/// (gas(n) - gas(0)) / n, loop overhead included, as the skeleton pays it).
contract PqzhBench {
    using Pqzh for uint256;

    function fp(uint256 a, uint256 b) external pure returns (uint256, uint256, uint256, uint256) {
        return (mulmod(a, b, Pqzh.P), addmod(a, b, Pqzh.P), addmod(a, Pqzh.P - b, Pqzh.P), Pqzh.inv(a));
    }

    function ext(uint256 a, uint256 b, uint256 E) external pure returns (uint256, uint256) {
        return (a.emul(b, E), a.einv(E));
    }

    function loopMul(uint256 n, uint256 a) external pure returns (uint256) {
        for (uint256 i; i < n; ++i) a = mulmod(a, a, Pqzh.P);
        return a;
    }

    function loopInv(uint256 n, uint256 a) external pure returns (uint256) {
        for (uint256 i; i < n; ++i) a = Pqzh.inv(a);
        return a;
    }

    function loopEmul(uint256 n, uint256 a, uint256 E) external pure returns (uint256) {
        for (uint256 i; i < n; ++i) a = a.emul(a, E);
        return a;
    }

    function loopEinv(uint256 n, uint256 a, uint256 E) external pure returns (uint256) {
        for (uint256 i; i < n; ++i) a = a.einv(E);
        return a;
    }

    function loopEscaleAdd(uint256 n, uint256 a, uint256 s) external pure returns (uint256) {
        for (uint256 i; i < n; ++i) a = a.eadd(a.escale(s));
        return a;
    }

    /// Mixed-height opening (Pqzh.walk): groups (10, 24 values) and (7, 6 values) as ref.py's merkle vector, the
    /// injected row right after the leaf row in `rows`.
    function merkle(uint256 n, bytes calldata rows, uint256 index, bytes calldata path) external pure returns (bytes32 root) {
        uint256[] memory lh = new uint256[](2);
        uint256[] memory w = new uint256[](2);
        (lh[0], lh[1], w[0], w[1]) = (10, 7, 24, 6);
        for (uint256 i; i < n; ++i) root = Pqzh.walk(lh, w, index, Pqzh.off(rows), Pqzh.off(path));
    }

    /// Goldilocks^5 (x^5 = 3) multiplication, unrolled, fixed memory buffers (no allocation per step), n times: c_k = sum_{i+j=k} a_i b_j + 3 sum_{i+j=k+5}.
    function loopEmul5(uint256 n, uint256[5] memory a) external pure returns (uint256[5] memory r) {
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                mstore(add(r, 0), mod(add(mul(mload(add(a, 0)), mload(add(a, 0))), mul(3, mod(add(add(add(mul(mload(add(a, 32)), mload(add(a, 128))), mul(mload(add(a, 64)), mload(add(a, 96)))), mul(mload(add(a, 96)), mload(add(a, 64)))), mul(mload(add(a, 128)), mload(add(a, 32)))), 0xffffffff00000001))), 0xffffffff00000001))
                mstore(add(r, 32), mod(add(add(mul(mload(add(a, 0)), mload(add(a, 32))), mul(mload(add(a, 32)), mload(add(a, 0)))), mul(3, mod(add(add(mul(mload(add(a, 64)), mload(add(a, 128))), mul(mload(add(a, 96)), mload(add(a, 96)))), mul(mload(add(a, 128)), mload(add(a, 64)))), 0xffffffff00000001))), 0xffffffff00000001))
                mstore(add(r, 64), mod(add(add(add(mul(mload(add(a, 0)), mload(add(a, 64))), mul(mload(add(a, 32)), mload(add(a, 32)))), mul(mload(add(a, 64)), mload(add(a, 0)))), mul(3, mod(add(mul(mload(add(a, 96)), mload(add(a, 128))), mul(mload(add(a, 128)), mload(add(a, 96)))), 0xffffffff00000001))), 0xffffffff00000001))
                mstore(add(r, 96), mod(add(add(add(add(mul(mload(add(a, 0)), mload(add(a, 96))), mul(mload(add(a, 32)), mload(add(a, 64)))), mul(mload(add(a, 64)), mload(add(a, 32)))), mul(mload(add(a, 96)), mload(add(a, 0)))), mul(3, mod(mul(mload(add(a, 128)), mload(add(a, 128))), 0xffffffff00000001))), 0xffffffff00000001))
                mstore(add(r, 128), mod(add(add(add(add(mul(mload(add(a, 0)), mload(add(a, 128))), mul(mload(add(a, 32)), mload(add(a, 96)))), mul(mload(add(a, 64)), mload(add(a, 64)))), mul(mload(add(a, 96)), mload(add(a, 32)))), mul(mload(add(a, 128)), mload(add(a, 0)))), 0xffffffff00000001))
                mcopy(a, r, 160)
            }
        }
    }

    function mul5(uint256[5] memory a, uint256[5] memory b) public pure returns (uint256[5] memory r) {
        assembly ("memory-safe") {
            mstore(add(r, 0), mod(add(mul(mload(add(a, 0)), mload(add(b, 0))), mul(3, mod(add(add(add(mul(mload(add(a, 32)), mload(add(b, 128))), mul(mload(add(a, 64)), mload(add(b, 96)))), mul(mload(add(a, 96)), mload(add(b, 64)))), mul(mload(add(a, 128)), mload(add(b, 32)))), 0xffffffff00000001))), 0xffffffff00000001))
            mstore(add(r, 32), mod(add(add(mul(mload(add(a, 0)), mload(add(b, 32))), mul(mload(add(a, 32)), mload(add(b, 0)))), mul(3, mod(add(add(mul(mload(add(a, 64)), mload(add(b, 128))), mul(mload(add(a, 96)), mload(add(b, 96)))), mul(mload(add(a, 128)), mload(add(b, 64)))), 0xffffffff00000001))), 0xffffffff00000001))
            mstore(add(r, 64), mod(add(add(add(mul(mload(add(a, 0)), mload(add(b, 64))), mul(mload(add(a, 32)), mload(add(b, 32)))), mul(mload(add(a, 64)), mload(add(b, 0)))), mul(3, mod(add(mul(mload(add(a, 96)), mload(add(b, 128))), mul(mload(add(a, 128)), mload(add(b, 96)))), 0xffffffff00000001))), 0xffffffff00000001))
            mstore(add(r, 96), mod(add(add(add(add(mul(mload(add(a, 0)), mload(add(b, 96))), mul(mload(add(a, 32)), mload(add(b, 64)))), mul(mload(add(a, 64)), mload(add(b, 32)))), mul(mload(add(a, 96)), mload(add(b, 0)))), mul(3, mod(mul(mload(add(a, 128)), mload(add(b, 128))), 0xffffffff00000001))), 0xffffffff00000001))
            mstore(add(r, 128), mod(add(add(add(add(mul(mload(add(a, 0)), mload(add(b, 128))), mul(mload(add(a, 32)), mload(add(b, 96)))), mul(mload(add(a, 64)), mload(add(b, 64)))), mul(mload(add(a, 96)), mload(add(b, 32)))), mul(mload(add(a, 128)), mload(add(b, 0)))), 0xffffffff00000001))
        }
    }

    /// Plain path of `depth` levels (one keccak per level), n times.
    function path(uint256 n, bytes32 leaf, uint256 index, uint256 depth, bytes calldata sib) external pure returns (bytes32 r) {
        for (uint256 i; i < n; ++i) r = Pqzh.merkle(leaf, index, depth, Pqzh.off(sib));
    }

    /// keccak of `len` calldata bytes, n times (leaf hashing of opened rows).
    function leaf(uint256 n, bytes calldata row) external pure returns (bytes32 r) {
        for (uint256 i; i < n; ++i) r = Pqzh.hashCd(Pqzh.off(row), row.length);
    }

    function fold(uint256 n, uint256 index, uint256 lh, uint256 a, uint256 beta, uint256[] calldata ev, uint256 E)
        external
        pure
        returns (uint256 r)
    {
        uint256[64] memory t = Pqzh.tables();
        uint256[] memory buf = new uint256[](ev.length);
        uint256 sInv = Pqzh.pw(t, index, lh, 63 - a);
        for (uint256 i; i < n; ++i) {
            for (uint256 j; j < ev.length; ++j) buf[j] = ev[j];
            r = Pqzh.fold(buf, a, beta, sInv, E, t);
        }
    }

    function logup(uint256[] calldata keys, uint256[] calldata mults, uint256 beta, uint256 E) external pure returns (uint256) {
        return Pqzh.logup(keys, mults, beta, E);
    }

    function horner(bytes calldata c, uint256 gamma, uint256 E) external pure returns (uint256 r, bool ok) {
        return Pqzh.horner(Pqzh.off(c), Pqzh.off(c) + c.length, gamma, E);
    }

    function rowsum(uint256 n, bytes calldata row, uint256 E) external pure returns (uint256 r) {
        uint256 w = row.length / 8;
        uint256[] memory apow = new uint256[](w * E);
        for (uint256 i; i < w * E; ++i) apow[i] = i + 1;
        for (uint256 i; i < n; ++i) (r,) = Pqzh.rowsum(Pqzh.off(row), w, apow, E);
    }
}

/// SHAKE256 over calldata with src/ua/Shake.sol (Keccak-f[1600] in Solidity) against the keccak256 opcode.
contract PqzhHash {
    function shake256(bytes calldata m) external pure returns (bytes32 r) {
        Shake.reserve();
        uint256 mp;
        uint256 out;
        assembly ("memory-safe") {
            mp := mload(0x40)
            calldatacopy(mp, m.offset, m.length)
            out := add(mp, add(m.length, 32))
            mstore(0x40, add(out, 256))
        }
        Shake.hash(Shake.SHAKE256, mp, m.length, out, 32);
        assembly ("memory-safe") {
            r := mload(out)
        }
    }

    function keccak(bytes calldata m) external pure returns (bytes32) {
        return keccak256(m);
    }
}

/// PQZH Solidity verifier gas study (docs/research/pqzh-solidity-verifier.md): component values against
/// pqz-core/pqzh/sol/ref.py, component gas, and the end-to-end skeleton on the shapes of model.py E2E.
/// `forge test --match-contract PqzhTest -vv` prints the numbers. Test-only, nothing here is deployed.
contract PqzhTest is Test {
    PqzhBench internal b;
    string internal json;

    function setUp() public {
        b = new PqzhBench();
        json = vm.readFile("test/vectors/pqzh/components.json");
    }

    function _wd(bytes memory v, uint256 i) internal pure returns (uint256 x) {
        assembly ("memory-safe") {
            x := mload(add(v, add(32, shl(5, i))))
        }
    }

    // ------------------------------------------------------------ values

    function test_fp_vectors() public view {
        bytes memory v = vm.parseJsonBytes(json, ".fp");
        for (uint256 i; i < 8; ++i) {
            (uint256 m, uint256 s, uint256 d, uint256 iv) = b.fp(_wd(v, 6 * i), _wd(v, 6 * i + 1));
            assertEq(m, _wd(v, 6 * i + 2));
            assertEq(s, _wd(v, 6 * i + 3));
            assertEq(d, _wd(v, 6 * i + 4));
            assertEq(iv, _wd(v, 6 * i + 5));
        }
    }

    function test_fp5_vector() public view {
        bytes memory v = vm.parseJsonBytes(json, ".fp5");
        for (uint256 i; i < 4; ++i) {
            uint256[5] memory a;
            uint256[5] memory c;
            for (uint256 j; j < 5; ++j) (a[j], c[j]) = (_wd(v, 15 * i + j), _wd(v, 15 * i + 5 + j));
            uint256[5] memory r = b.mul5(a, c);
            for (uint256 j; j < 5; ++j) assertEq(r[j], _wd(v, 15 * i + 10 + j));
        }
    }

    function test_ext_vectors() public view {
        for (uint256 E = 2; E <= 3; ++E) {
            bytes memory v = vm.parseJsonBytes(json, E == 2 ? ".fp2" : ".fp3");
            for (uint256 i; i < 8; ++i) {
                (uint256 m, uint256 iv) = b.ext(_wd(v, 4 * i), _wd(v, 4 * i + 1), E);
                assertEq(m, _wd(v, 4 * i + 2));
                assertEq(iv, _wd(v, 4 * i + 3));
            }
        }
    }

    function test_merkle_vector() public view {
        bytes memory rows = vm.parseJsonBytes(json, ".merkle.rows");
        bytes memory inj = vm.parseJsonBytes(json, ".merkle.inj");
        bytes memory path = vm.parseJsonBytes(json, ".merkle.path");
        uint256 index = vm.parseJsonUint(json, ".merkle.index");
        bytes32 root = bytes32(vm.parseJsonBytes(json, ".merkle.root"));
        bytes memory both = bytes.concat(rows, inj);
        assertEq(b.merkle(1, both, index, path), root);
        path[100] ^= 0x01;
        assertTrue(b.merkle(1, both, index, path) != root, "tampered sibling must change the root");
    }

    function test_fold_vectors() public view {
        string[6] memory k = [".fold2_2", ".fold2_8", ".fold2_16", ".fold3_2", ".fold3_8", ".fold3_16"];
        for (uint256 i; i < 6; ++i) {
            bytes memory v = vm.parseJsonBytes(json, k[i]);
            uint256 a = _wd(v, 2);
            uint256[] memory ev = new uint256[](1 << a);
            for (uint256 j; j < ev.length; ++j) ev[j] = _wd(v, 5 + j);
            assertEq(b.fold(1, _wd(v, 0), _wd(v, 1), a, _wd(v, 3), ev, i < 3 ? 2 : 3), _wd(v, 4), k[i]);
        }
    }

    function test_logup_horner_vectors() public view {
        for (uint256 E = 2; E <= 3; ++E) {
            bytes memory v = vm.parseJsonBytes(json, E == 2 ? ".logup2" : ".logup3");
            uint256 n = _wd(v, 0);
            uint256[] memory keys = new uint256[](n);
            uint256[] memory mults = new uint256[](n);
            for (uint256 i; i < n; ++i) (keys[i], mults[i]) = (_wd(v, 3 + i), _wd(v, 3 + n + i));
            assertEq(b.logup(keys, mults, _wd(v, 1), E), _wd(v, 2));
            string memory h = E == 2 ? ".horner2" : ".horner3";
            (uint256 r, bool ok) =
                b.horner(vm.parseJsonBytes(json, string.concat(h, ".coeffs")), vm.parseJsonUint(json, string.concat(h, ".gamma")), E);
            assertTrue(ok);
            assertEq(r, vm.parseJsonUint(json, string.concat(h, ".result")));
        }
    }

    function test_shake_vector() public {
        PqzhHash hsh = new PqzhHash();
        bytes memory m = vm.parseJsonBytes(json, ".shake.msg");
        assertEq(hsh.shake256(m), bytes32(vm.parseJsonBytes(json, ".shake.shake256")));
        assertEq(hsh.keccak(m), bytes32(vm.parseJsonBytes(json, ".shake.keccak256")));
    }

    // ------------------------------------------------------------ gas per component

    function _perOp(bytes memory call0, bytes memory callN, uint256 n) internal returns (uint256) {
        uint256 g0 = gasleft();
        (bool ok0,) = address(b).staticcall(call0);
        uint256 g1 = gasleft();
        (bool ok1,) = address(b).staticcall(callN);
        uint256 g2 = gasleft();
        require(ok0 && ok1, "bench call");
        return ((g1 - g2) - (g0 - g1)) / n;
    }

    uint256 internal constant X = 0x123456789abcdef;
    uint256 internal constant X2 = X | (0xfedcba987654321 << 64);
    uint256 internal constant X3 = X2 | (0x0f1e2d3c4b5a6978 << 128);

    function test_gas_field() public {
        (uint256 x, uint256 x2, uint256 x3, uint256 n) = (X, X2, X3, 200);
        console2.log("fp mul (mulmod + loop)", _perOp(abi.encodeCall(b.loopMul, (0, x)), abi.encodeCall(b.loopMul, (n, x)), n));
        console2.log("fp inv", _perOp(abi.encodeCall(b.loopInv, (0, x)), abi.encodeCall(b.loopInv, (20, x)), 20));
        console2.log("fp2 mul", _perOp(abi.encodeCall(b.loopEmul, (0, x2, 2)), abi.encodeCall(b.loopEmul, (n, x2, 2)), n));
        console2.log("fp3 mul", _perOp(abi.encodeCall(b.loopEmul, (0, x3, 3)), abi.encodeCall(b.loopEmul, (n, x3, 3)), n));
        console2.log("fp2 inv", _perOp(abi.encodeCall(b.loopEinv, (0, x2, 2)), abi.encodeCall(b.loopEinv, (20, x2, 2)), 20));
        console2.log("fp3 inv", _perOp(abi.encodeCall(b.loopEinv, (0, x3, 3)), abi.encodeCall(b.loopEinv, (20, x3, 3)), 20));
        uint256[5] memory a5 = [x, x2 >> 64, x3 >> 128, uint256(5), uint256(11)];
        console2.log("fp5 mul (memory)", _perOp(abi.encodeCall(b.loopEmul5, (0, a5)), abi.encodeCall(b.loopEmul5, (n, a5)), n));
        console2.log("ext scale+add", _perOp(abi.encodeCall(b.loopEscaleAdd, (0, x3, x)), abi.encodeCall(b.loopEscaleAdd, (n, x3, x)), n));
    }

    function test_gas_merkle() public {
        // Merkle: depth-10 mixed-height opening (one leaf of 24 values, one injected row of 6), and plain levels
        bytes memory rows = vm.parseJsonBytes(json, ".merkle.rows");
        bytes memory inj = vm.parseJsonBytes(json, ".merkle.inj");
        bytes memory path = vm.parseJsonBytes(json, ".merkle.path");
        uint256 index = vm.parseJsonUint(json, ".merkle.index");
        bytes memory both = bytes.concat(rows, inj);
        uint256 walk = _perOp(abi.encodeCall(b.merkle, (0, both, index, path)), abi.encodeCall(b.merkle, (10, both, index, path)), 10);
        console2.log("merkle depth-10 mixed-height opening (24 + 6 values)", walk);
        uint256 lvl = _perOp(abi.encodeCall(b.path, (0, bytes32(0), index, 10, path)), abi.encodeCall(b.path, (10, bytes32(0), index, 10, path)), 10);
        console2.log("merkle path, 10 levels (keccak opcode)", lvl);
        bytes memory row = new bytes(8 * 116);
        console2.log("leaf hash, 116 values (928 B)", _perOp(abi.encodeCall(b.leaf, (0, row)), abi.encodeCall(b.leaf, (20, row)), 20));
        console2.log("row combination, 116 values, E=2", _perOp(abi.encodeCall(b.rowsum, (0, row, 2)), abi.encodeCall(b.rowsum, (20, row, 2)), 20));
        console2.log("row combination, 116 values, E=3", _perOp(abi.encodeCall(b.rowsum, (0, row, 3)), abi.encodeCall(b.rowsum, (20, row, 3)), 20));
    }

    function test_gas_fold() public {
        string[6] memory k = [".fold2_2", ".fold2_8", ".fold2_16", ".fold3_2", ".fold3_8", ".fold3_16"];
        for (uint256 i; i < 6; ++i) {
            bytes memory v = vm.parseJsonBytes(json, k[i]);
            uint256 a = _wd(v, 2);
            uint256[] memory ev = new uint256[](1 << a);
            for (uint256 j; j < ev.length; ++j) ev[j] = _wd(v, 5 + j);
            uint256 E = i < 3 ? 2 : 3;
            uint256 g = _perOp(abi.encodeCall(b.fold, (0, _wd(v, 0), _wd(v, 1), a, _wd(v, 3), ev, E)),
                abi.encodeCall(b.fold, (10, _wd(v, 0), _wd(v, 1), a, _wd(v, 3), ev, E)), 10);
            console2.log(string.concat("FRI fold ", k[i]), g);
        }
    }

    function test_gas_logup_horner() public {
        uint256 x3 = X3;
        // LogUp public sum vs Horner fingerprint, per term
        for (uint256 E = 2; E <= 3; ++E) {
            uint256[] memory ks = new uint256[](256);
            uint256[] memory ms = new uint256[](256);
            uint256[] memory k1 = new uint256[](1);
            uint256[] memory m1 = new uint256[](1);
            for (uint256 i; i < 256; ++i) (ks[i], ms[i]) = (i, 1);
            uint256 lg = _perOp(abi.encodeCall(b.logup, (k1, m1, x3, E)), abi.encodeCall(b.logup, (ks, ms, x3, E)), 255);
            console2.log(E == 2 ? "LogUp public term, E=2" : "LogUp public term, E=3", lg);
            bytes memory c1 = new bytes(8);
            bytes memory cN = new bytes(8 * 1001);
            uint256 hn = _perOp(abi.encodeCall(b.horner, (c1, x3, E)), abi.encodeCall(b.horner, (cN, x3, E)), 1000);
            console2.log(E == 2 ? "Horner per statement coefficient, E=2" : "Horner per statement coefficient, E=3", hn);
        }
    }

    /// Transcript seed over the R_TX statement (83,072 B + 29 B of tag, op, length): SHAKE256 in Solidity against
    /// the keccak256 opcode.
    function test_gas_transcript_seed() public {
        PqzhHash hsh = new PqzhHash();
        bytes memory m = new bytes(83_101);
        for (uint256 i; i < m.length; i += 97) m[i] = bytes1(uint8(i));
        uint256 g0 = gasleft();
        hsh.shake256(m);
        uint256 g1 = gasleft();
        hsh.keccak(m);
        uint256 g2 = gasleft();
        console2.log("SHAKE256 (Solidity Keccak-f) over 83,101 B", g0 - g1);
        console2.log("keccak256 opcode over 83,101 B", g1 - g2);
        assertGt(g0 - g1, 20 * (g1 - g2));
    }

    // ------------------------------------------------------------ end to end

    function _e2e(string memory name) internal returns (uint256 gasUsed, uint256 proofLen) {
        bytes memory blob = vm.readFileBinary(string.concat("test/vectors/pqzh/", name, ".bin"));
        uint256 ls = uint32(bytes4(_slice(blob, 0, 4)));
        uint256 lt = uint32(bytes4(_slice(blob, 4, 4)));
        uint256 lp = uint32(bytes4(_slice(blob, 8, 4)));
        bytes memory shape = _slice(blob, 12, ls);
        bytes memory stmt = _slice(blob, 12 + ls, lt);
        bytes memory proof = _slice(blob, 12 + ls + lt, lp);
        PqzhSkeleton s = new PqzhSkeleton();
        uint256 g = gasleft();
        s.verify(shape, stmt, proof);
        gasUsed = g - gasleft();
        proofLen = lp;
        uint256[12] memory pf = s.profile(shape, stmt, proof);
        string[12] memory nm = ["  seed (keccak opcode)", "  roots, challenges, OOD, FRI roots, PoW", "  Horner fingerprint",
            "  DEEP precomputation", "  constraint stand-in", "  opened rows (DEEP numerators)", "  trace Merkle openings",
            "  DEEP inversions", "  FRI rows + Merkle paths", "  FRI folds", "  final poly + query loop rest", "  total (inside)"];
        for (uint256 i; i < 12; ++i) console2.log(nm[i], pf[i]);
        // a flipped byte in the last Merkle sibling of the proof must be caught
        proof[lp - 5] ^= 0x01;
        vm.expectRevert();
        s.verify(shape, stmt, proof);
    }

    function _slice(bytes memory b_, uint256 o, uint256 n) internal pure returns (bytes memory r) {
        r = new bytes(n);
        for (uint256 i; i < n; ++i) r[i] = b_[o + i];
    }

    function test_gas_e2e_tx_b16_a8_conj() public {
        (uint256 g, uint256 n) = _e2e("e2e_tx_b16_a8_conj");
        console2.log("e2e R_TX blowup 16, arity 8, conjectured, Fp2, 28 queries: verify gas", g);
        console2.log("  skeleton proof bytes (unpruned Merkle paths)", n);
        console2.log(g < 16_777_216 ? "  under the 16,777,216 cap" : "  OVER the 16,777,216 cap");
    }

    function test_gas_e2e_tx_b16_a8_johnson() public {
        (uint256 g, uint256 n) = _e2e("e2e_tx_b16_a8_johnson");
        console2.log("e2e R_TX blowup 16, arity 8, Johnson, Fp3, 56 queries: verify gas", g);
        console2.log("  skeleton proof bytes (unpruned Merkle paths)", n);
        console2.log(g < 16_777_216 ? "  under the 16,777,216 cap" : "  OVER the 16,777,216 cap");
    }

    function test_gas_e2e_tx_b8_a2_conj() public {
        (uint256 g, uint256 n) = _e2e("e2e_tx_b8_a2_conj");
        console2.log("e2e R_TX blowup 8, arity 2, conjectured, Fp2, 38 queries: verify gas", g);
        console2.log("  skeleton proof bytes (unpruned Merkle paths)", n);
        console2.log(g < 16_777_216 ? "  under the 16,777,216 cap" : "  OVER the 16,777,216 cap");
    }
}
