// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IZetherVerifier} from "./IZetherVerifier.sol";
import {ZetherTranscript as T} from "./ZetherTranscript.sol";
import {ZetherSafety} from "./ZetherSafety.sol";
import {G1Bn254, G1Bls12381} from "./ZetherCurves.sol";

/// @title Verifier Σ-Bullets cho Zether, độc lập đường cong (đặc tả §6–§9).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Một Σ-protocol (R1 khoá, R2–R4 ciphertext cùng `s`,
///         R5 số dư, R9 auditor shared-`s`, liên kết Σ-Bullets) và đúng hai Bulletproof (`n_v = 64`,
///         `n_b = 64`, ruling RS-NV64-1) trên **một** transcript. Mọi phương trình là một MSM phải bằng `O`; trên BLS12-381
///         MSM đi qua 0x0c nên mọi điểm đầu vào được kiểm subgroup ngầm.
///
///         Generator NUMS tính trong constructor theo §3 rồi ghi vào một data contract (SSTORE2): ai
///         cũng tính lại được, không có hằng số nào để tin.
abstract contract ZetherVerifierBase is IZetherVerifier {
    bytes32 internal constant OP_TRANSFER = keccak256("SCAAS-ZETHER-OP-TRANSFER-V1");
    bytes32 internal constant OP_BURN = keccak256("SCAAS-ZETHER-OP-BURN-V1");
    uint256 internal constant NV = 64; // limits D1 (RS-NV64-1)
    uint256 internal constant NB = 64;
    uint256 internal constant HEADER = 384;
    uint256 internal constant NGEN = 130; // h, U, G_0..63, H_0..63

    address public immutable generatorStore;

    error GeneratorStoreFailed();

    constructor() {
        ZetherSafety.requireDevChain();
        uint256 p = _pointBytes();
        bytes memory blob = new bytes(NGEN * p);
        _put(blob, 0, _gen("h", 0), p);
        _put(blob, 1, _gen("U", 0), p);
        for (uint32 i = 0; i < 64; ++i) {
            _put(blob, 2 + i, _gen("G", i), p);
            _put(blob, 66 + i, _gen("H", i), p);
        }
        // SSTORE2: runtime = 0x00 (STOP) ‖ blob, để không ai "gọi" được data contract.
        bytes memory init = abi.encodePacked(
            hex"61", uint16(blob.length + 1), hex"80600c6000396000f3", hex"00", blob
        );
        address store;
        assembly ("memory-safe") { store := create(0, add(init, 32), mload(init)) }
        if (store == address(0)) revert GeneratorStoreFailed();
        generatorStore = store;
    }

    // ------------------------------------------------------------------ móc theo đường cong

    function proofSystemId() public pure virtual returns (bytes32);
    function _pointBytes() internal pure virtual returns (uint256);
    function _order() internal pure virtual returns (uint256);
    function _gen(string memory label, uint32 index) internal view virtual returns (bytes memory);
    function _base() internal pure virtual returns (bytes memory);
    function _msm(bytes memory pts, uint256[] memory sc) internal view virtual returns (bytes memory);
    function _add(bytes memory a, bytes memory b) internal view virtual returns (bytes memory);
    function _neg(bytes memory a) internal pure virtual returns (bytes memory);
    function _valid(bytes memory a) internal view virtual returns (bool);

    // ------------------------------------------------------------------ IZetherVerifier: phép nhóm

    function groupOrder() external pure returns (uint256) { return _order(); }
    function ringSize() external pure returns (uint256) { return 2; }
    function g1EncodedBytes() external pure returns (uint256) { return _pointBytes(); }
    function identity() external pure returns (bytes memory) { return new bytes(_pointBytes()); }
    function isValidPoint(bytes calldata a) external view returns (bool) { return _valid(a); }
    function g1Add(bytes calldata a, bytes calldata b) external view returns (bytes memory) { return _add(a, b); }
    function g1Sub(bytes calldata a, bytes calldata b) external view returns (bytes memory) {
        return _add(a, _neg(b));
    }
    function g1Mul(bytes calldata a, uint256 k) external view returns (bytes memory) {
        uint256[] memory sc = new uint256[](1);
        sc[0] = k;
        return _msm(a, sc);
    }
    function g1MulBase(uint256 k) external view returns (bytes memory) {
        uint256[] memory sc = new uint256[](1);
        sc[0] = k;
        return _msm(_base(), sc);
    }
    function g1Msm(bytes calldata pts, uint256[] calldata scalars) external view returns (bytes memory) {
        return _msm(pts, scalars);
    }

    function generators() public view returns (bytes memory blob) {
        uint256 len = NGEN * _pointBytes();
        address store = generatorStore;
        blob = new bytes(len);
        assembly ("memory-safe") { extcodecopy(store, add(blob, 32), 1, len) }
    }

    // ------------------------------------------------------------------ verify

    function verifyTransfer(bytes calldata statement, bytes calldata proof) external view returns (bool) {
        uint256 p = _pointBytes();
        // Σ 10P + 192 ‖ BP(64) 16P + 160 ‖ BP(64) 16P + 160
        if (statement.length != HEADER + 9 * p || proof.length != 42 * p + 512) return false;
        if (bytes32(statement[0:32]) != OP_TRANSFER || bytes32(statement[32:64]) != proofSystemId()) return false;
        Ctx memory x = _ctx(statement, proof, 10 * p);
        if (x.c == 0 || !_sigmaTransfer(x)) return false;
        uint256 off1 = 10 * p + 192;
        bool ok;
        (ok, x.st) = _bulletproof(x, NV, _pf(x, 0), off1);
        if (!ok) return false;
        (ok, x.st) = _bulletproof(x, NB, _pf(x, 1), off1 + 16 * p + 160);
        return ok;
    }

    function verifyBurn(bytes calldata statement, bytes calldata proof) external view returns (bool) {
        uint256 p = _pointBytes();
        if (statement.length != HEADER + 3 * p || proof.length != 20 * p + 256) return false;
        if (bytes32(statement[0:32]) != OP_BURN || bytes32(statement[32:64]) != proofSystemId()) return false;
        Ctx memory x = _ctx(statement, proof, 4 * p);
        if (x.c == 0 || !_sigmaBurn(x)) return false;
        bool ok;
        (ok, x.st) = _bulletproof(x, NB, _pf(x, 0), 4 * p + 96);
        return ok;
    }

    struct Ctx {
        uint256 p;
        uint256 r;
        uint256 c;
        bytes32 st;
        bytes gens;
        bytes s;   // statement
        bytes pr;  // proof
    }

    /// @dev Hấp thụ statement và `sigmaLen` byte đầu của proof, rút challenge `c` (§7).
    function _ctx(bytes calldata statement, bytes calldata proof, uint256 sigmaLen)
        private view returns (Ctx memory x)
    {
        x.p = _pointBytes();
        x.r = _order();
        x.gens = generators();
        x.s = statement;
        x.pr = proof;
        x.st = T.absorb(T.init(), "statement", x.s);
        x.st = T.absorb(x.st, "sigma.commit", proof[0:sigmaLen]);
        (x.st, x.c) = T.challenge(x.st, "sigma.c", x.r);
    }

    /// @dev Điểm thứ `i` của phần điểm statement (sau header 384 byte).
    function _sp(Ctx memory x, uint256 i) private pure returns (bytes memory) {
        return _slice(x.s, HEADER + i * x.p, x.p);
    }

    /// @dev Điểm thứ `i` của proof.
    function _pf(Ctx memory x, uint256 i) private pure returns (bytes memory) {
        return _slice(x.pr, i * x.p, x.p);
    }

    /// @dev Scalar thứ `i` sau `nPts` điểm đầu của proof; `>= r` ⇒ proof không chính tắc.
    function _ps(Ctx memory x, uint256 nPts, uint256 i) private pure returns (uint256 v, bool ok) {
        v = _word(x.pr, nPts * x.p + 32 * i);
        ok = v < x.r;
    }

    /// @dev E1–E8 (§7.1). Statement: Y_f Y_t Y_a C_acc D_acc C_out D_out C_deb C_aud.
    ///      Proof: V_v V_b A_y A_D A_out A_deb A_bal A_aud A_Vv A_Vb z_x z_v z_s z_b z_gv z_gb.
    function _sigmaTransfer(Ctx memory x) private view returns (bool) {
        uint256[6] memory z;
        for (uint256 i; i < 6; ++i) {
            bool ok;
            (z[i], ok) = _ps(x, 10, i);
            if (!ok) return false;
        }
        if (_isZero(_sp(x, 6)) || _isZero(_sp(x, 0)) || _isZero(_sp(x, 1))
            || keccak256(_sp(x, 0)) == keccak256(_sp(x, 1))) return false;
        uint256 r = x.r;
        uint256 nc = r - x.c;
        bytes memory g = _base();
        // E1  [z_x]G − [c]Y_f − A_y
        if (!_z3([g, _sp(x, 0), _pf(x, 2)], [z[0], nc, r - 1])) return false;
        // E2  [z_s]G − [c]D_out − A_D
        if (!_z3([g, _sp(x, 6), _pf(x, 3)], [z[2], nc, r - 1])) return false;
        // E3  [z_v]G + [z_s]Y_t − [c]C_out − A_out
        if (!_z4([g, _sp(x, 1), _sp(x, 5), _pf(x, 4)], [z[1], z[2], nc, r - 1])) return false;
        // E4  [z_v]G + [z_s]Y_f − [c]C_deb − A_deb
        if (!_z4([g, _sp(x, 0), _sp(x, 7), _pf(x, 5)], [z[1], z[2], nc, r - 1])) return false;
        // E5  [z_b + c·fee]G + [z_x]D_acc − [z_x]D_out − [c]C_acc + [c]C_deb − A_bal
        {
            uint256[] memory sc = new uint256[](6);
            sc[0] = addmod(z[3], mulmod(x.c, _word(x.s, 256), r), r);
            sc[1] = z[0];
            sc[2] = _negS(z[0], r);
            sc[3] = nc;
            sc[4] = x.c;
            sc[5] = r - 1;
            bytes memory pts = bytes.concat(g, _sp(x, 4), _sp(x, 6), _sp(x, 3), _sp(x, 7), _pf(x, 6));
            if (!_isZero(_msm(pts, sc))) return false;
        }
        // E6  auditor bật ⇒ [z_v]G + [z_s]Y_a − [c]C_aud − A_aud; tắt ⇒ C_aud = A_aud = O
        if (_isZero(_sp(x, 2))) {
            if (!_isZero(_sp(x, 8)) || !_isZero(_pf(x, 7))) return false;
        } else if (!_z4([g, _sp(x, 2), _sp(x, 8), _pf(x, 7)], [z[1], z[2], nc, r - 1])) {
            return false;
        }
        bytes memory hb = _slice(x.gens, 0, x.p);
        // E7  [z_v]G + [z_gv]Hb − [c]V_v − A_Vv
        if (!_z4([g, hb, _pf(x, 0), _pf(x, 8)], [z[1], z[4], nc, r - 1])) return false;
        // E8  [z_b]G + [z_gb]Hb − [c]V_b − A_Vb
        return _z4([g, hb, _pf(x, 1), _pf(x, 9)], [z[3], z[5], nc, r - 1]);
    }

    /// @dev §7.2. Statement: Y_f C_acc D_acc. Proof: V_b A_y A_bal A_Vb z_x z_b z_gb.
    function _sigmaBurn(Ctx memory x) private view returns (bool) {
        uint256[3] memory z;
        for (uint256 i; i < 3; ++i) {
            bool ok;
            (z[i], ok) = _ps(x, 4, i);
            if (!ok) return false;
        }
        if (_isZero(_sp(x, 0))) return false;
        uint256 r = x.r;
        uint256 nc = r - x.c;
        bytes memory g = _base();
        // E1  [z_x]G − [c]Y_f − A_y
        if (!_z3([g, _sp(x, 0), _pf(x, 1)], [z[0], nc, r - 1])) return false;
        // E5  [z_b + c·(amount + fee)]G + [z_x]D_acc − [c]C_acc − A_bal
        uint256 debit = addmod(_word(x.s, 320), _word(x.s, 256), r);
        if (!_z4([g, _sp(x, 2), _sp(x, 1), _pf(x, 2)], [addmod(z[1], mulmod(x.c, debit, r), r), z[0], nc, r - 1])) {
            return false;
        }
        // E8  [z_b]G + [z_gb]Hb − [c]V_b − A_Vb
        return _z4([g, _slice(x.gens, 0, x.p), _pf(x, 0), _pf(x, 3)], [z[1], z[2], nc, r - 1]);
    }

    /// @dev Bulletproof một giá trị, `n` bit, proof tại `off` (§8.2). Trả trạng thái transcript mới.
    function _bulletproof(Ctx memory x, uint256 n, bytes memory V, uint256 off)
        private view returns (bool, bytes32)
    {
        BP memory b;
        bytes memory pr = x.pr;
        b.p = x.p;
        b.r = x.r;
        b.n = n;
        if (n != 64) return (false, x.st); // NV = NB = 64 ⇒ k = 6; n khác là lỗi lập trình, không phải proof
        b.k = 6;
        b.off = off;
        b.sOff = off + (4 + 2 * b.k) * b.p;
        for (uint256 i; i < 5; ++i) {
            b.sc[i] = _word(pr, b.sOff + 32 * i); // τ_x μ t̂ a b
            if (b.sc[i] >= b.r) return (false, x.st);
        }
        bytes32 st = T.absorb(x.st, "bp.AS", abi.encodePacked(uint32(n), _slice(pr, off, 2 * b.p)));
        (st, b.y) = T.challenge(st, "bp.y", b.r);
        (st, b.z) = T.challenge(st, "bp.z", b.r);
        st = T.absorb(st, "bp.T", _slice(pr, off + 2 * b.p, 2 * b.p));
        (st, b.x) = T.challenge(st, "bp.x", b.r);
        st = T.absorb(st, "bp.t", _slice(pr, b.sOff, 96));
        (st, b.w) = T.challenge(st, "bp.w", b.r);
        if (b.y == 0 || b.z == 0 || b.x == 0 || b.w == 0) return (false, st);
        b.u = new uint256[](b.k);
        for (uint256 j; j < b.k; ++j) {
            st = T.absorb(st, "ipa.LR", _slice(pr, off + (4 + 2 * j) * b.p, 2 * b.p));
            (st, b.u[j]) = T.challenge(st, "ipa.u", b.r);
            if (b.u[j] == 0) return (false, st);
        }
        if (!_bp1(x, b, V, pr)) return (false, st);
        return (_bp2(x, b, pr), st);
    }

    struct BP {
        uint256 p;
        uint256 r;
        uint256 n;
        uint256 k;
        uint256 off;
        uint256 sOff;
        uint256[5] sc; // τ_x μ t̂ a b
        uint256 y;
        uint256 z;
        uint256 x;
        uint256 w;
        uint256[] u;
        uint256[] uInv;
    }

    /// @dev BP-1: [t̂ − δ]G + [τ_x]Hb − [z²]V − [x]T1 − [x²]T2 == O.
    function _bp1(Ctx memory x, BP memory b, bytes memory V, bytes memory pr) private view returns (bool) {
        uint256 r = b.r;
        uint256 z2 = mulmod(b.z, b.z, r);
        uint256 sumY;
        uint256 yi = 1;
        for (uint256 i; i < b.n; ++i) {
            sumY = addmod(sumY, yi, r);
            yi = mulmod(yi, b.y, r);
        }
        // δ = (z − z²)·Σy^i − z³·(2^n − 1)
        uint256 delta = addmod(
            mulmod(addmod(b.z, r - z2, r), sumY, r),
            r - mulmod(mulmod(z2, b.z, r), ((1 << b.n) - 1) % r, r),
            r
        );
        bytes memory pts = bytes.concat(
            _base(), _slice(x.gens, 0, b.p), V, _slice(pr, b.off + 2 * b.p, 2 * b.p)
        );
        uint256[] memory sc = new uint256[](5);
        sc[0] = addmod(b.sc[2], r - delta, r);
        sc[1] = b.sc[0];
        sc[2] = _negS(z2, r);
        sc[3] = _negS(b.x, r);
        sc[4] = _negS(mulmod(b.x, b.x, r), r);
        return _isZero(_msm(pts, sc));
    }

    /// @dev BP-2 (§8.2), một MSM `2n + 2k + 4` số hạng:
    ///      A + [x]S + Σ[−z − a·s_i]G_i + Σ[z + y^{-i}(z²2^i − b·s_i⁻¹)]H_i − [μ]Hb + [w(t̂ − ab)]U
    ///        + Σ[u_j²]L_j + Σ[u_j⁻²]R_j
    function _bp2(Ctx memory x, BP memory b, bytes memory pr) private view returns (bool) {
        uint256 n = b.n;
        uint256 p = b.p;
        uint256 m = 2 * n + 2 * b.k + 4;
        bytes memory pts = new bytes(m * p);
        uint256[] memory sc = new uint256[](m);
        _copy(pts, 0, pr, b.off, 2 * p);                 // A, S
        _copy(pts, 2 * p, x.gens, 2 * p, n * p);         // G_0..G_{n-1}
        _copy(pts, (2 + n) * p, x.gens, 66 * p, n * p);  // H_0..H_{n-1}
        _copy(pts, (2 + 2 * n) * p, x.gens, 0, 2 * p);   // Hb, U
        sc[0] = 1;
        sc[1] = b.x;
        _bpVectorScalars(b, sc);
        sc[2 + 2 * n] = _negS(b.sc[1], b.r);
        sc[3 + 2 * n] = mulmod(b.w, addmod(b.sc[2], b.r - mulmod(b.sc[3], b.sc[4], b.r), b.r), b.r);
        for (uint256 j; j < b.k; ++j) {
            uint256 at = 4 + 2 * n + 2 * j;
            _copy(pts, at * p, pr, b.off + (4 + 2 * j) * p, 2 * p); // L_j, R_j
            sc[at] = mulmod(b.u[j], b.u[j], b.r);
            sc[at + 1] = mulmod(b.uInv[j], b.uInv[j], b.r);
        }
        return _isZero(_msm(pts, sc));
    }

    /// @dev Hệ số của G_i (ô 2..n+1) và H_i (ô n+2..2n+1).
    function _bpVectorScalars(BP memory b, uint256[] memory sc) private view {
        uint256 r = b.r;
        uint256 n = b.n;
        uint256[] memory s = _sVector(b);
        uint256 z2 = mulmod(b.z, b.z, r);
        uint256 yInv = _inv(b.y, r);
        uint256 yInvI = 1;
        uint256 twoI = 1;
        for (uint256 i; i < n; ++i) {
            sc[2 + i] = _negS(addmod(b.z, mulmod(b.sc[3], s[i], r), r), r);
            // s_i⁻¹ = s_{n−1−i}: phần bù bit đảo dấu mọi số mũ
            uint256 inner = addmod(mulmod(z2, twoI, r), r - mulmod(b.sc[4], s[n - 1 - i], r), r);
            sc[2 + n + i] = addmod(b.z, mulmod(yInvI, inner, r), r);
            yInvI = mulmod(yInvI, yInv, r);
            twoI = addmod(twoI, twoI, r);
        }
    }

    /// @dev s_0 = Π u_j⁻¹, s_i = s_{i − 2^lg} · u_{k−1−lg}² (lg = bit cao nhất của i). Ghi `b.uInv`.
    function _sVector(BP memory b) private view returns (uint256[] memory s) {
        uint256 r = b.r;
        s = new uint256[](b.n);
        b.uInv = new uint256[](b.k);
        s[0] = 1;
        for (uint256 j; j < b.k; ++j) {
            b.uInv[j] = _inv(b.u[j], r);
            s[0] = mulmod(s[0], b.uInv[j], r);
        }
        for (uint256 i = 1; i < b.n; ++i) {
            uint256 lg = _log2(i);
            uint256 uj = b.u[b.k - 1 - lg];
            s[i] = mulmod(s[i - (1 << lg)], mulmod(uj, uj, r), r);
        }
    }

    // ------------------------------------------------------------------ tiện ích

    function _z3(bytes[3] memory pts, uint256[3] memory s) private view returns (bool) {
        uint256[] memory sc = new uint256[](3);
        (sc[0], sc[1], sc[2]) = (s[0], s[1], s[2]);
        return _isZero(_msm(bytes.concat(pts[0], pts[1], pts[2]), sc));
    }

    function _z4(bytes[4] memory pts, uint256[4] memory s) private view returns (bool) {
        uint256[] memory sc = new uint256[](4);
        (sc[0], sc[1], sc[2], sc[3]) = (s[0], s[1], s[2], s[3]);
        return _isZero(_msm(bytes.concat(pts[0], pts[1], pts[2], pts[3]), sc));
    }

    function _negS(uint256 a, uint256 r) private pure returns (uint256) {
        return a == 0 ? 0 : r - a;
    }

    function _isZero(bytes memory a) private pure returns (bool z) {
        z = true;
        for (uint256 i; i < a.length; i += 32) {
            if (_word(a, i) != 0) return false;
        }
    }

    function _log2(uint256 v) private pure returns (uint256 l) {
        while (v > 1) {
            v >>= 1;
            ++l;
        }
    }

    function _inv(uint256 a, uint256 r) private view returns (uint256 out) {
        bool ok;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, 32)
            mstore(add(m, 32), 32)
            mstore(add(m, 64), 32)
            mstore(add(m, 96), a)
            mstore(add(m, 128), sub(r, 2))
            mstore(add(m, 160), r)
            ok := staticcall(gas(), 0x05, m, 192, m, 32)
            out := mload(m)
        }
        require(ok);
    }

    function _word(bytes memory a, uint256 off) internal pure returns (uint256 w) {
        assembly ("memory-safe") { w := mload(add(add(a, 32), off)) }
    }

    function _slice(bytes memory a, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        _copy(out, 0, a, off, len);
    }

    /// @dev Chép `len` byte (bội của 32) từ `src[srcOff..]` sang `dst[dstOff..]`.
    function _copy(bytes memory dst, uint256 dstOff, bytes memory src, uint256 srcOff, uint256 len) internal pure {
        assembly ("memory-safe") {
            let d := add(add(dst, 32), dstOff)
            let s := add(add(src, 32), srcOff)
            for { let i := 0 } lt(i, len) { i := add(i, 32) } { mstore(add(d, i), mload(add(s, i))) }
        }
    }

    function _put(bytes memory blob, uint256 idx, bytes memory pt, uint256 p) private pure {
        _copy(blob, idx * p, pt, 0, p);
    }

    /// @dev Nhãn generator §3: `u8(len(label)) ‖ label ‖ be4(index)`.
    function _genMsg(string memory label, uint32 index) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(bytes(label).length), label, index);
    }
}

/// @title Verifier Zether trên bn254 (precompile 0x05–0x07, có từ Byzantium).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** ~100 bit sau exTNFS (canon C6.1): mọi số tiền
///         confidential trên public chain phải được giả định giải mã được trong khoảng 2035–2045.
contract ZetherVerifierBn254 is ZetherVerifierBase {
    function proofSystemId() public pure override returns (bytes32) {
        return keccak256("scaas/zether/sigma-bullets/bn254/n64-n64/v1");
    }

    function curveName() external pure returns (string memory) { return "bn254"; }

    /// @dev Probe: G + G phải đúng bằng [2]G (vector cố định). Rỗng/sai ⇒ false.
    function isSupportedOnThisChain() external view returns (bool) {
        (bool ok, bytes memory out) = address(0x06).staticcall(abi.encodePacked(uint256(1), uint256(2), uint256(1), uint256(2)));
        if (!ok || out.length != 64) return false;
        (bool ok2, bytes memory out2) = address(0x07).staticcall(abi.encodePacked(uint256(1), uint256(2), uint256(2)));
        return ok2 && out2.length == 64 && keccak256(out) == keccak256(out2)
            && keccak256(out) == keccak256(abi.encodePacked(
                uint256(0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3),
                uint256(0x15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4)));
    }

    function _pointBytes() internal pure override returns (uint256) { return 64; }
    function _order() internal pure override returns (uint256) { return G1Bn254.R; }
    function _base() internal pure override returns (bytes memory) { return G1Bn254.generator(); }

    function _gen(string memory label, uint32 index) internal view override returns (bytes memory) {
        return G1Bn254.mapToG1(abi.encodePacked("SCAAS-ZETHER-GEN-BN254-V1", _genMsg(label, index)));
    }

    function _msm(bytes memory pts, uint256[] memory sc) internal view override returns (bytes memory) {
        return G1Bn254.msm(pts, sc);
    }

    function _add(bytes memory a, bytes memory b) internal view override returns (bytes memory) {
        return G1Bn254.add(a, b);
    }

    function _neg(bytes memory a) internal pure override returns (bytes memory) { return G1Bn254.neg(a); }
    function _valid(bytes memory a) internal view override returns (bool) { return G1Bn254.isValid(a); }
}

/// @title Verifier Zether trên BLS12-381 (EIP-2537, cần Prague).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** 117–126 bit; điểm 128 byte; subgroup check nằm
///         trong mọi G1MSM.
contract ZetherVerifierBls12381 is ZetherVerifierBase {
    bytes internal constant GEN_DST = "SCAAS-ZETHER-GEN-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_";

    function proofSystemId() public pure override returns (bytes32) {
        return keccak256("scaas/zether/sigma-bullets/bls12-381/n64-n64/v1");
    }

    function curveName() external pure returns (string memory) { return "bls12-381"; }

    /// @dev Probe cả G1ADD và G1MSM: G + G == [2]G. Precompile vắng mặt trả 0 byte ⇒ false.
    function isSupportedOnThisChain() external view returns (bool) {
        bytes memory g = G1Bls12381.generator();
        (bool ok, bytes memory sum) = address(0x0b).staticcall(bytes.concat(g, g));
        if (!ok || sum.length != 128) return false;
        (bool ok2, bytes memory dbl) = address(0x0c).staticcall(abi.encodePacked(g, uint256(2)));
        return ok2 && dbl.length == 128 && keccak256(sum) == keccak256(dbl) && !G1Bls12381.isIdentity(sum);
    }

    function _pointBytes() internal pure override returns (uint256) { return 128; }
    function _order() internal pure override returns (uint256) { return G1Bls12381.R; }
    function _base() internal pure override returns (bytes memory) { return G1Bls12381.generator(); }

    function _gen(string memory label, uint32 index) internal view override returns (bytes memory) {
        return G1Bls12381.hashToG1(_genMsg(label, index), GEN_DST);
    }

    function _msm(bytes memory pts, uint256[] memory sc) internal view override returns (bytes memory) {
        return G1Bls12381.msm(pts, sc);
    }

    function _add(bytes memory a, bytes memory b) internal view override returns (bytes memory) {
        return G1Bls12381.add(a, b);
    }

    function _neg(bytes memory a) internal pure override returns (bytes memory) { return G1Bls12381.neg(a); }
    function _valid(bytes memory a) internal view override returns (bool) { return G1Bls12381.isValid(a); }
}
