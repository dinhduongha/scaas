// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {HashToCurve} from "../common/HashToCurve.sol";

/// @title Phép nhóm G1 của bn254 qua precompile EIP-196 (0x06 add, 0x07 mul).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Điểm là `bytes` 64 byte `x ‖ y`, vô cực = 64 byte 0
///         (đặc tả `2026-10-03-zether-design.md` §2). Cofactor 1: on-curve là đủ, và precompile tự từ
///         chối điểm sai/không chính tắc, nên mọi hàm ở đây revert `BadPoint` thay vì trả rác.
library G1Bn254 {
    uint256 internal constant P = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 internal constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant POINT_BYTES = 64;

    error BadPoint();
    error BadLength(uint256 got);
    error ModexpFailed();

    function generator() internal pure returns (bytes memory) {
        return abi.encodePacked(uint256(1), uint256(2));
    }

    function identity() internal pure returns (bytes memory) {
        return new bytes(64);
    }

    function add(bytes memory a, bytes memory b) internal view returns (bytes memory c) {
        if (a.length != 64 || b.length != 64) revert BadLength(a.length);
        c = new bytes(64);
        bool ok;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, mload(add(a, 32)))
            mstore(add(m, 32), mload(add(a, 64)))
            mstore(add(m, 64), mload(add(b, 32)))
            mstore(add(m, 96), mload(add(b, 64)))
            ok := staticcall(gas(), 0x06, m, 128, add(c, 32), 64)
        }
        if (!ok) revert BadPoint();
    }

    function neg(bytes memory a) internal pure returns (bytes memory) {
        if (a.length != 64) revert BadLength(a.length);
        (uint256 x, uint256 y) = abi.decode(a, (uint256, uint256));
        if (x == 0 && y == 0) return a;
        return abi.encodePacked(x, y == 0 ? 0 : P - (y % P));
    }

    function sub(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        return add(a, neg(b));
    }

    function mulBase(uint256 k) internal view returns (bytes memory) {
        return mul(generator(), k);
    }

    function mul(bytes memory a, uint256 k) internal view returns (bytes memory c) {
        if (a.length != 64) revert BadLength(a.length);
        c = new bytes(64);
        bool ok;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, mload(add(a, 32)))
            mstore(add(m, 32), mload(add(a, 64)))
            mstore(add(m, 64), k)
            ok := staticcall(gas(), 0x07, m, 96, add(c, 32), 64)
        }
        if (!ok) revert BadPoint();
    }

    /// @notice `Σ [sc[i]] pts[i]`, `pts` = các điểm nối liền. Không có MSM precompile cho bn254:
    ///         mỗi số hạng một `ecMul` + một `ecAdd` (research §3.3.3).
    function msm(bytes memory pts, uint256[] memory sc) internal view returns (bytes memory out) {
        uint256 k = sc.length;
        if (pts.length != k * 64) revert BadLength(pts.length);
        out = new bytes(64);
        bool ok = true;
        assembly ("memory-safe") {
            let m := mload(0x40)            // [0,64) acc, [64,128) term, [128,224) mul input
            mstore(m, 0)
            mstore(add(m, 32), 0)
            for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                let s := mload(add(add(sc, 32), mul(i, 32)))
                let pp := add(add(pts, 32), mul(i, 64))
                mstore(add(m, 128), mload(pp))
                mstore(add(m, 160), mload(add(pp, 32)))
                mstore(add(m, 192), s)
                ok := and(ok, staticcall(gas(), 0x07, add(m, 128), 96, add(m, 64), 64))
                ok := and(ok, staticcall(gas(), 0x06, m, 128, m, 64))
            }
            mstore(add(out, 32), mload(m))
            mstore(add(out, 64), mload(add(m, 32)))
        }
        if (!ok) revert BadPoint();
    }

    /// @notice Điểm hợp lệ (trên đường cong, toạ độ chính tắc) hoặc vô cực.
    function isValid(bytes memory a) internal view returns (bool ok) {
        if (a.length != 64) return false;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, mload(add(a, 32)))
            mstore(add(m, 32), mload(add(a, 64)))
            mstore(add(m, 64), 0)
            mstore(add(m, 96), 0)
            ok := staticcall(gas(), 0x06, m, 128, m, 64)
        }
    }

    function isIdentity(bytes memory a) internal pure returns (bool) {
        return a.length == 64 && keccak256(a) == keccak256(new bytes(64));
    }

    /// @notice Try-and-increment (§3.1). Đầu vào công khai nên không cần constant-time.
    function mapToG1(bytes memory prefix) internal view returns (bytes memory) {
        for (uint32 ctr = 0; ; ++ctr) {
            uint256 x = uint256(keccak256(abi.encodePacked(prefix, ctr))) % P;
            uint256 rhs = addmod(mulmod(mulmod(x, x, P), x, P), 3, P);
            uint256 y = _modexp(rhs, (P + 1) / 4);
            if (mulmod(y, y, P) == rhs) {
                if (y & 1 == 1) y = P - y;
                return abi.encodePacked(x, y);
            }
        }
        revert BadPoint(); // không bao giờ tới
    }

    function _modexp(uint256 b, uint256 e) private view returns (uint256 r) {
        bool ok;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, 32)
            mstore(add(m, 32), 32)
            mstore(add(m, 64), 32)
            mstore(add(m, 96), b)
            mstore(add(m, 128), e)
            mstore(add(m, 160), P)
            ok := staticcall(gas(), 0x05, m, 192, m, 32)
            r := mload(m)
        }
        if (!ok) revert ModexpFailed();
    }
}

/// @title Phép nhóm G1 của BLS12-381 qua EIP-2537 (0x0b G1ADD, 0x0c G1MSM).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Điểm 128 byte (mỗi Fp 64 byte, 16 byte 0 đầu).
///         G1ADD chỉ kiểm on-curve; **G1MSM kiểm subgroup** — nên `isValid`, `msm` đều đi qua 0x0c.
library G1Bls12381 {
    uint256 internal constant R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
    uint256 internal constant POINT_BYTES = 128;
    // p = 0x1a0111ea…aaab, chia hai word theo bố cục 64 byte của EIP-2537
    uint256 internal constant P_HI = 0x1a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 internal constant P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    error BadPoint();
    error BadLength(uint256 got);

    function generator() internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes16(0), hex"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            bytes16(0), hex"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
        );
    }

    function identity() internal pure returns (bytes memory) {
        return new bytes(128);
    }

    function add(bytes memory a, bytes memory b) internal view returns (bytes memory c) {
        if (a.length != 128 || b.length != 128) revert BadLength(a.length);
        bool ok;
        (ok, c) = address(0x0b).staticcall(bytes.concat(a, b));
        if (!ok || c.length != 128) revert BadPoint();
    }

    function neg(bytes memory a) internal pure returns (bytes memory c) {
        if (a.length != 128) revert BadLength(a.length);
        if (isIdentity(a)) return a;
        c = new bytes(128);
        assembly ("memory-safe") {
            mstore(add(c, 32), mload(add(a, 32)))
            mstore(add(c, 64), mload(add(a, 64)))
            let yHi := mload(add(a, 96))
            let yLo := mload(add(a, 128))
            let borrow := lt(P_LO, yLo)
            mstore(add(c, 128), sub(P_LO, yLo))
            mstore(add(c, 96), sub(sub(P_HI, yHi), borrow))
        }
    }

    function sub(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        return add(a, neg(b));
    }

    function mulBase(uint256 k) internal view returns (bytes memory) {
        return mul(generator(), k);
    }

    function mul(bytes memory a, uint256 k) internal view returns (bytes memory c) {
        if (a.length != 128) revert BadLength(a.length);
        bool ok;
        (ok, c) = address(0x0c).staticcall(abi.encodePacked(a, k));
        if (!ok || c.length != 128) revert BadPoint();
    }

    function msm(bytes memory pts, uint256[] memory sc) internal view returns (bytes memory c) {
        uint256 k = sc.length;
        if (k == 0 || pts.length != k * 128) revert BadLength(pts.length);
        bytes memory input = new bytes(k * 160);
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                let src := add(add(pts, 32), mul(i, 128))
                let dst := add(add(input, 32), mul(i, 160))
                mstore(dst, mload(src))
                mstore(add(dst, 32), mload(add(src, 32)))
                mstore(add(dst, 64), mload(add(src, 64)))
                mstore(add(dst, 96), mload(add(src, 96)))
                mstore(add(dst, 128), mload(add(add(sc, 32), mul(i, 32))))
            }
        }
        bool ok;
        (ok, c) = address(0x0c).staticcall(input);
        if (!ok || c.length != 128) revert BadPoint();
    }

    /// @notice Trên đường cong, chính tắc, TRONG SUBGROUP (G1MSM k=1), hoặc vô cực.
    function isValid(bytes memory a) internal view returns (bool) {
        if (a.length != 128) return false;
        (bool ok, bytes memory c) = address(0x0c).staticcall(abi.encodePacked(a, uint256(1)));
        return ok && c.length == 128;
    }

    function isIdentity(bytes memory a) internal pure returns (bool) {
        return a.length == 128 && keccak256(a) == keccak256(new bytes(128));
    }

    /// @notice RFC 9380 `BLS12381G1_XMD:SHA-256_SSWU_RO_` (§3.2).
    function hashToG1(bytes memory message, bytes memory dst) internal view returns (bytes memory) {
        return HashToCurve.hashToG1(message, dst);
    }
}
