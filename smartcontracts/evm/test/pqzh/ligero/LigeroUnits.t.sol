// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {LigeroVerifier} from "./LigeroVerifier.sol";

/// The verifier's components in isolation (gas inside, gasleft deltas): per element = (gas(n2) - gas(n1)) / (n2 - n1).
/// Inputs for the gas model pqz-core/pqzh/ligero/evm_model.py (docs/research/pqzh-ligero.md §11).
contract LigeroUnits is LigeroVerifier {
    constructor() LigeroVerifier(new address[](0)) {}

    function fill(uint256 n, uint256 seed, bool packed) internal pure returns (uint256[] memory a) {
        a = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            uint256 r = uint256(keccak256(abi.encode(seed, i)));
            a[i] = packed ? (r & 0x000003ffffffffff000003ffffffffff000003ffffffffff000003ffffffffff) % (1 << 255) : r % Q;
        }
    }

    function gRowEval(uint256 n) external view returns (uint256 g) {
        uint256[] memory own = fill(n, 1, true);
        uint256[] memory lc = fill(n, 2, false);
        g = gasleft();
        rowEval(own, 0, lc, n);
        g -= gasleft();
    }

    /// the same lazy MAC, 8x unrolled, pointer increments (a tuned-Yul reference)
    function gTunedMac(uint256 n) external view returns (uint256 g, uint256 r) {
        uint256[] memory own = fill(n, 1, true);
        uint256[] memory lc = fill(n, 2, false);
        g = gasleft();
        assembly {
            let p := add(own, 32)
            let q := add(lc, 32)
            let e := add(p, mul(n, 32))
            let a02 := 0
            let a13 := 0
            for {} lt(p, e) { p := add(p, 256) q := add(q, 256) } {
                let x := mload(q)
                let w := mload(p)
                a02 := add(a02, mul(and(w, 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff), x))
                a13 := add(a13, mul(and(shr(64, w), 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff), x))
                x := mload(add(q, 32))
                w := mload(add(p, 32))
                a02 := add(a02, mul(and(w, 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff), x))
                a13 := add(a13, mul(and(shr(64, w), 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff), x))
                x := mload(add(q, 64))
                w := mload(add(p, 64))
                a02 := add(a02, mul(and(w, 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff), x))
                a13 := add(a13, mul(and(shr(64, w), 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff), x))
                x := mload(add(q, 96))
                w := mload(add(p, 96))
                a02 := add(a02, mul(and(w, 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff), x))
                a13 := add(a13, mul(and(shr(64, w), 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff), x))
                x := mload(add(q, 128))
                w := mload(add(p, 128))
                a02 := add(a02, mul(and(w, 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff), x))
                a13 := add(a13, mul(and(shr(64, w), 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff), x))
                x := mload(add(q, 160))
                w := mload(add(p, 160))
                a02 := add(a02, mul(and(w, 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff), x))
                a13 := add(a13, mul(and(shr(64, w), 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff), x))
                x := mload(add(q, 192))
                w := mload(add(p, 192))
                a02 := add(a02, mul(and(w, 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff), x))
                a13 := add(a13, mul(and(shr(64, w), 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff), x))
                x := mload(add(q, 224))
                w := mload(add(p, 224))
                a02 := add(a02, mul(and(w, 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff), x))
                a13 := add(a13, mul(and(shr(64, w), 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff), x))
            }
            r := xor(a02, a13)
        }
        g -= gasleft();
    }

    function gEvalP(bytes calldata poly, uint256 n) external view returns (uint256 g) {
        uint256[] memory xp = new uint256[](n);
        powers(xp, 12345);
        uint256 o = pOffOf(poly);
        g = gasleft();
        evalP(o, n, xp);
        g -= gasleft();
    }

    function gPowers(uint256 n) external view returns (uint256 g) {
        uint256[] memory xp = new uint256[](n);
        g = gasleft();
        powers(xp, 12345);
        g -= gasleft();
    }

    function gLagrange(uint256 n) external view returns (uint256 g) {
        uint256[] memory om = fill(n, 3, false);
        uint256[] memory lc = new uint256[](n);
        uint256[] memory pre = new uint256[](n);
        g = gasleft();
        lagrange(lc, pre, om, 777, 999);
        g -= gasleft();
    }

    function gDotU(bytes calldata col, uint256 m) external view returns (uint256 g) {
        uint256[] memory c = fill(m, 4, true);
        uint256 o = pOffOf(col);
        g = gasleft();
        dotU(c, o, m);
        g -= gasleft();
    }

    function gQuad(bytes calldata col, uint256 nt) external view returns (uint256 g) {
        V memory v;
        v.tri = new uint256[](nt);
        for (uint256 i; i < nt; ++i) v.tri[i] = (i % 100) | ((i * 7) % 100) << 32 | ((i * 13) % 100) << 64;
        v.rq = fill(nt, 5, true);
        uint256 o = pOffOf(col);
        g = gasleft();
        quad(v, o);
        g -= gasleft();
    }

    function gEm(uint256 n) external view returns (uint256 g) {
        uint256 a = 0x0000012345678901000002345678901200000345678901230000045678901234;
        g = gasleft();
        for (uint256 i; i < n; ++i) a = em(a, a);
        g -= gasleft();
        a;
    }

    function gEaEs(uint256 n) external view returns (uint256 g) {
        uint256 a = 0x0000012345678901000002345678901200000345678901230000045678901234;
        uint256 b = 0x0000022345678901000003345678901200000445678901230000015678901234;
        g = gasleft();
        for (uint256 i; i < n; ++i) a = es(ea(a, b), b);
        g -= gasleft();
        a;
    }

    /// one A pass block (j fixed): 32 x 64 terms
    function gAPass() external view returns (uint256 g) {
        uint256[] memory am = fill(393_216 / 32 + 1, 6, false);
        uint256[] memory gam = fill(32, 7, true);
        uint256[] memory a = new uint256[](64);
        g = gasleft();
        aPass(am, gam, 5, false, a);
        g -= gasleft();
    }

    /// one ringJ (64 recurrence steps + own updates), K = 64
    function gRingJ() external view returns (uint256 g) {
        V memory v;
        v.rho = 0x0000012345678901000002345678901200000345678901230000045678901234;
        v.rp = fill(65, 8, true);
        v.own = new uint256[](64);
        uint256[] memory a = fill(64, 9, true);
        g = gasleft();
        ringJ(v, a, 64, 0);
        g -= gasleft();
    }
}

contract LigeroUnitsTest is Test {
    LigeroUnits internal u;

    function setUp() public {
        u = new LigeroUnits();
    }

    function per(uint256 g1, uint256 g2, uint256 n1, uint256 n2) internal pure returns (string memory) {
        uint256 x100 = (g2 - g1) * 100 / (n2 - n1);
        return string.concat(vm.toString(x100 / 100), ".", x100 % 100 < 10 ? "0" : "", vm.toString(x100 % 100));
    }

    function test_units() public view {
        bytes memory big = new bytes(24 * 4096 + 32);
        for (uint256 i; i < big.length; i += 32) {
            bytes32 r = keccak256(abi.encode(i)) & 0x000003ffffffffff000003ffffffffff000003ffffffffff000003ffffffffff;
            assembly {
                mstore(add(add(big, 32), i), r)
            }
        }
        (uint256 t1,) = u.gTunedMac(1024);
        (uint256 t2,) = u.gTunedMac(4096);
        console2.log(string.concat('{"unit": "own_mac_this_code", "gas": ', per(u.gRowEval(1024), u.gRowEval(4096), 1024, 4096), "}"));
        console2.log(string.concat('{"unit": "own_mac_tuned_8x", "gas": ', per(t1, t2, 1024, 4096), "}"));
        console2.log(string.concat('{"unit": "poly_coeff_eval", "gas": ', per(u.gEvalP(big, 1024), u.gEvalP(big, 4096), 1024, 4096), "}"));
        console2.log(string.concat('{"unit": "power", "gas": ', per(u.gPowers(1024), u.gPowers(4096), 1024, 4096), "}"));
        console2.log(string.concat('{"unit": "lagrange_slot", "gas": ', per(u.gLagrange(256), u.gLagrange(1024), 256, 1024), "}"));
        console2.log(string.concat('{"unit": "dotU_row", "gas": ', per(u.gDotU(big, 64), u.gDotU(big, 512), 64, 512), "}"));
        console2.log(string.concat('{"unit": "quad_triple", "gas": ', per(u.gQuad(big, 64), u.gQuad(big, 512), 64, 512), "}"));
        console2.log(string.concat('{"unit": "ext_mul", "gas": ', per(u.gEm(16), u.gEm(256), 16, 256), "}"));
        console2.log(string.concat('{"unit": "ext_add_sub_pair", "gas": ', per(u.gEaEs(16), u.gEaEs(256), 16, 256), "}"));
        console2.log(string.concat('{"unit": "a_pass_term", "gas": ', per(0, u.gAPass(), 0, 2048), "}"));
        console2.log(string.concat('{"unit": "ring_step_k64", "gas": ', per(0, u.gRingJ(), 0, 64), "}"));
    }
}
