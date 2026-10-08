// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IZetherVerifier} from "../../../src/zether/IZetherVerifier.sol";
import {ZetherTranscript as T} from "../../../src/zether/ZetherTranscript.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @notice Prover THAM CHIẾU CHỈ CHO TEST, viết thẳng từ đặc tả §7–§9, chạy trong EVM qua phép nhóm của
///         verifier. Không bao giờ dùng ngoài test: nonce dẫn xuất tất định từ `seed` (không hedged), và
///         witness nằm trong calldata. Prover thật là luồng S3 (Rust/WASM); vector của nó được kiểm riêng.
///
///         Là một contract riêng để bộ nhớ của mỗi lần prove được giải phóng khi lời gọi trả về.
contract ZetherProver {
    struct Env {
        IZetherVerifier v;
        uint256 r;
        uint256 p;
        bytes gens;
        bytes g;
        bytes32 seed;
        uint256 rid; // nhãn nonce của Bulletproof đang dựng (hai BP cùng n = 64 phải khác nonce)
    }

    struct TransferWitness {
        uint256 x;
        uint256 v;
        uint256 s;
        uint256 bPrime;
        uint256 gammaV;
        uint256 gammaB;
        bytes32 seed;
    }

    uint256 constant HEADER = 384;

    function _env(IZetherVerifier v, bytes32 seed) internal view returns (Env memory e) {
        e.v = v;
        e.r = v.groupOrder();
        e.p = v.g1EncodedBytes();
        e.gens = v.generators();
        e.g = v.g1MulBase(1);
        e.seed = seed;
    }

    function _rand(Env memory e, string memory tag, uint256 i) internal pure returns (uint256) {
        return T.hashToScalar(keccak256(abi.encode(e.seed, tag, i)), e.r);
    }

    // ------------------------------------------------------------------ ciphertext tiện ích

    /// @notice `(C_out, D_out, C_deb, C_aud)` cho chuyển `v` với randomness `s` (§7.1).
    function ciphertexts(IZetherVerifier v, bytes memory yf, bytes memory yt, bytes memory ya, uint256 amount, uint256 s)
        external view returns (bytes memory cOut, bytes memory dOut, bytes memory cDeb, bytes memory cAud)
    {
        bytes memory g = v.g1MulBase(1);
        cOut = _m2(v, g, amount, yt, s);
        dOut = v.g1MulBase(s);
        cDeb = _m2(v, g, amount, yf, s);
        cAud = _isZero(ya) ? ya : _m2(v, g, amount, ya, s);
    }

    function _m2(IZetherVerifier v, bytes memory a, uint256 sa, bytes memory b, uint256 sb)
        internal view returns (bytes memory)
    {
        uint256[] memory sc = new uint256[](2);
        (sc[0], sc[1]) = (sa, sb);
        return v.g1Msm(bytes.concat(a, b), sc);
    }

    // ------------------------------------------------------------------ Σ + BP

    function proveTransfer(IZetherVerifier v, bytes calldata statement, TransferWitness calldata w)
        external view returns (bytes memory)
    {
        Env memory e = _env(v, w.seed);
        bytes memory s = statement;
        uint256[6] memory k;
        for (uint256 i; i < 6; ++i) k[i] = _rand(e, "sigma.k", i); // k_x k_v k_s k_b k_gv k_gb
        bytes memory commits = _transferCommits(e, s, w, k);
        bytes32 st = T.absorb(T.init(), "statement", s);
        st = T.absorb(st, "sigma.commit", commits);
        uint256 c;
        (st, c) = T.challenge(st, "sigma.c", e.r);
        bytes memory zs = _responses(e.r, c, k, [w.x, w.v, w.s, w.bPrime, w.gammaV, w.gammaB]);
        bytes memory bp1;
        bytes memory bp2;
        // n_v = n_b = 64 (limits D1); `e.rid` tách nonce của hai Bulletproof (cùng n thì cùng nhãn).
        e.rid = 32;
        (bp1, st) = _proveRange(e, st, 64, w.v, w.gammaV);
        e.rid = 64;
        (bp2, st) = _proveRange(e, st, 64, w.bPrime, w.gammaB);
        return bytes.concat(commits, zs, bp1, bp2);
    }

    function _responses(uint256 r, uint256 c, uint256[6] memory k, uint256[6] memory wit)
        internal pure returns (bytes memory out)
    {
        for (uint256 i; i < 6; ++i) out = bytes.concat(out, abi.encodePacked(addmod(k[i], mulmod(c, wit[i], r), r)));
    }

    function _transferCommits(Env memory e, bytes memory s, TransferWitness calldata w, uint256[6] memory k)
        internal view returns (bytes memory commits)
    {
        IZetherVerifier v = e.v;
        bytes memory hb = _slice(e.gens, 0, e.p);
        commits = bytes.concat(
            _m2(v, e.g, w.v, hb, w.gammaV),                          // V_v
            _m2(v, e.g, w.bPrime, hb, w.gammaB),                     // V_b
            v.g1MulBase(k[0]),                                       // A_y
            v.g1MulBase(k[2]),                                       // A_D
            _m2(v, e.g, k[1], _sp(e, s, 1), k[2])                    // A_out
        );
        commits = bytes.concat(
            commits,
            _m2(v, e.g, k[1], _sp(e, s, 0), k[2]),                   // A_deb
            _abal(e, s, k[3], k[0]),                                 // A_bal
            _isZero(_sp(e, s, 2)) ? new bytes(e.p) : _m2(v, e.g, k[1], _sp(e, s, 2), k[2]), // A_aud
            _m2(v, e.g, k[1], hb, k[4]),                             // A_Vv
            _m2(v, e.g, k[3], hb, k[5])                              // A_Vb
        );
    }

    function _abal(Env memory e, bytes memory s, uint256 kb, uint256 kx) internal view returns (bytes memory) {
        uint256[] memory sc = new uint256[](3);
        (sc[0], sc[1], sc[2]) = (kb, kx, kx == 0 ? 0 : e.r - kx);
        return e.v.g1Msm(bytes.concat(e.g, _sp(e, s, 4), _sp(e, s, 6)), sc); // [k_b]G + [k_x](D_acc − D_out)
    }

    // ------------------------------------------------------------------ nhiều người nhận

    struct MultiWitness {
        uint256 x;
        uint256 s;
        uint256[] v;
        uint256 bPrime;
        uint256[] gammaV;
        uint256 gammaB;
        bytes32 seed;
    }

    /// @notice Σ (E1–E8, E3/E6/E7 theo từng người nhận) + BP(v_j) cho từng người + BP(b') trên một transcript.
    function proveTransferMulti(IZetherVerifier v, bytes calldata statement, MultiWitness calldata w)
        external view returns (bytes memory)
    {
        Env memory e = _env(v, w.seed);
        uint256 m = w.v.length;
        uint256[] memory k = new uint256[](4 + 2 * m); // k_x k_s k_b k_gb (k_vj k_gvj)_j
        for (uint256 i; i < k.length; ++i) k[i] = _rand(e, "multi.k", i);
        bytes memory commits = _multiCommits(e, statement, w, k);
        bytes32 st = T.absorb(T.init(), "statement", statement);
        st = T.absorb(st, "sigma.commit", commits);
        uint256 c;
        (st, c) = T.challenge(st, "sigma.c", e.r);
        bytes memory out = bytes.concat(commits, _multiResponses(e.r, c, k, w));
        for (uint256 j; j < m; ++j) {
            e.rid = 100 + j;
            bytes memory bp;
            (bp, st) = _proveRange(e, st, 64, w.v[j], w.gammaV[j]);
            out = bytes.concat(out, bp);
        }
        e.rid = 64;
        bytes memory bpB;
        (bpB, st) = _proveRange(e, st, 64, w.bPrime, w.gammaB);
        return bytes.concat(out, bpB);
    }

    function _multiResponses(uint256 r, uint256 c, uint256[] memory k, MultiWitness calldata w)
        internal pure returns (bytes memory out)
    {
        out = abi.encodePacked(
            addmod(k[0], mulmod(c, w.x, r), r), addmod(k[1], mulmod(c, w.s, r), r),
            addmod(k[2], mulmod(c, w.bPrime, r), r), addmod(k[3], mulmod(c, w.gammaB, r), r)
        );
        for (uint256 j; j < w.v.length; ++j) {
            out = bytes.concat(out, abi.encodePacked(
                addmod(k[4 + 2 * j], mulmod(c, w.v[j], r), r), addmod(k[5 + 2 * j], mulmod(c, w.gammaV[j], r), r)
            ));
        }
    }

    /// @dev Statement: Y_f Y_a C_acc D_acc D_out C_deb be32(M) (Y_tj C_out_j C_aud_j)_j.
    function _multiCommits(Env memory e, bytes memory s, MultiWitness calldata w, uint256[] memory k)
        internal view returns (bytes memory commits)
    {
        uint256 kvSum;
        for (uint256 j; j < w.v.length; ++j) kvSum = addmod(kvSum, k[4 + 2 * j], e.r);
        commits = _multiHead(e, s, w.bPrime, w.gammaB, k, kvSum);
        for (uint256 j; j < w.v.length; ++j) {
            commits = bytes.concat(commits, _multiLeg(e, s, j, w.v[j], w.gammaV[j], k));
        }
    }

    /// @dev V_b A_y A_D A_deb A_bal A_Vb (k = k_x k_s k_b k_gb …).
    function _multiHead(Env memory e, bytes memory s, uint256 bPrime, uint256 gammaB, uint256[] memory k, uint256 kvSum)
        internal view returns (bytes memory head)
    {
        bytes memory hb = _slice(e.gens, 0, e.p);
        head = bytes.concat(
            _m2(e.v, e.g, bPrime, hb, gammaB),               // V_b
            e.v.g1MulBase(k[0]),                             // A_y
            e.v.g1MulBase(k[1]),                             // A_D
            _m2(e.v, e.g, kvSum, _sp(e, s, 0), k[1])         // A_deb
        );
        uint256[] memory sc = new uint256[](3);
        (sc[0], sc[1], sc[2]) = (k[2], k[0], k[0] == 0 ? 0 : e.r - k[0]);
        head = bytes.concat(
            head,
            e.v.g1Msm(bytes.concat(e.g, _sp(e, s, 3), _sp(e, s, 4)), sc), // A_bal = [k_b]G + [k_x](D_acc − D_out)
            _m2(e.v, e.g, k[2], hb, k[3])                                  // A_Vb
        );
    }

    /// @dev V_vj A_out_j A_aud_j A_Vvj.
    function _multiLeg(Env memory e, bytes memory s, uint256 j, uint256 v, uint256 gammaV, uint256[] memory k)
        internal view returns (bytes memory leg)
    {
        bytes memory hb = _slice(e.gens, 0, e.p);
        leg = bytes.concat(
            _m2(e.v, e.g, v, hb, gammaV),                                // V_vj
            _m2(e.v, e.g, k[4 + 2 * j], _lp(e, s, j), k[1])              // A_out_j
        );
        bytes memory ya = _sp(e, s, 1);
        leg = bytes.concat(
            leg,
            _isZero(ya) ? new bytes(e.p) : _m2(e.v, e.g, k[4 + 2 * j], ya, k[1]), // A_aud_j
            _m2(e.v, e.g, k[4 + 2 * j], hb, k[5 + 2 * j])                         // A_Vvj
        );
    }

    function _lp(Env memory e, bytes memory s, uint256 j) internal pure returns (bytes memory) {
        return _slice(s, HEADER + 6 * e.p + 32 + 3 * j * e.p, e.p);
    }

    struct BurnWitness {
        uint256 x;
        uint256 bPrime;
        uint256 gammaB;
        bytes32 seed;
    }

    function proveBurn(IZetherVerifier v, bytes calldata statement, BurnWitness calldata w)
        external view returns (bytes memory)
    {
        Env memory e = _env(v, w.seed);
        uint256[6] memory k;
        for (uint256 i; i < 3; ++i) k[i] = _rand(e, "burn.k", i); // k_x k_b k_gb
        bytes memory commits = _burnCommits(e, statement, w.bPrime, w.gammaB, k);
        bytes32 st = T.absorb(T.init(), "statement", statement);
        st = T.absorb(st, "sigma.commit", commits);
        uint256 c;
        (st, c) = T.challenge(st, "sigma.c", e.r);
        bytes memory zs = _responses(e.r, c, k, [w.x, w.bPrime, w.gammaB, 0, 0, 0]);
        bytes memory bp;
        e.rid = 64;
        (bp, st) = _proveRange(e, st, 64, w.bPrime, w.gammaB);
        return bytes.concat(commits, _slice(zs, 0, 96), bp);
    }

    function _burnCommits(Env memory e, bytes memory s, uint256 bPrime, uint256 gammaB, uint256[6] memory k)
        internal view returns (bytes memory)
    {
        bytes memory hb = _slice(e.gens, 0, e.p);
        return bytes.concat(
            _m2(e.v, e.g, bPrime, hb, gammaB),          // V_b
            e.v.g1MulBase(k[0]),                        // A_y
            _m2(e.v, e.g, k[1], _sp(e, s, 2), k[0]),    // A_bal = [k_b]G + [k_x]D_acc
            _m2(e.v, e.g, k[1], hb, k[2])               // A_Vb
        );
    }

    // ------------------------------------------------------------------ Bulletproof (§8.1)

    struct RP {
        uint256 n;
        uint256 y;
        uint256 z;
        uint256 x;
        uint256 w;
        uint256 alpha;
        uint256 rho;
        uint256 tau1;
        uint256 tau2;
        uint256 gamma;
        uint256 that;
        uint256[] aL;
        uint256[] aR;
        uint256[] sL;
        uint256[] sR;
        uint256[] l;
        uint256[] rv;
        bytes AS;
        bytes T12;
        bytes tvals;
    }

    function _proveRange(Env memory e, bytes32 st, uint256 n, uint256 value, uint256 gamma)
        internal view returns (bytes memory out, bytes32)
    {
        RP memory q = _rpInit(e, n, value, gamma);
        st = T.absorb(st, "bp.AS", abi.encodePacked(uint32(n), q.AS));
        (st, q.y) = T.challenge(st, "bp.y", e.r);
        (st, q.z) = T.challenge(st, "bp.z", e.r);
        _polys(e, q);
        st = T.absorb(st, "bp.T", q.T12);
        (st, q.x) = T.challenge(st, "bp.x", e.r);
        _evalAt(e.r, q);
        st = T.absorb(st, "bp.t", q.tvals);
        (st, q.w) = T.challenge(st, "bp.w", e.r);
        bytes memory LR;
        uint256 a;
        uint256 b;
        (LR, a, b, st) = _ipa(e, st, q, q.l, q.rv);
        out = bytes.concat(q.AS, q.T12, LR, q.tvals, abi.encodePacked(a, b));
        return (out, st);
    }

    function _rpInit(Env memory e, uint256 n, uint256 value, uint256 gamma) internal view returns (RP memory q) {
        uint256 id = e.rid;
        uint256 r = e.r;
        q.n = n;
        q.gamma = gamma;
        q.aL = new uint256[](n);
        q.aR = new uint256[](n);
        q.sL = new uint256[](n);
        q.sR = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            q.aL[i] = (value >> i) & 1;
            q.aR[i] = q.aL[i] == 1 ? 0 : r - 1;
            q.sL[i] = _rand(e, string.concat("sL", _n(id)), i);
            q.sR[i] = _rand(e, string.concat("sR", _n(id)), i);
        }
        q.alpha = _rand(e, "alpha", id);
        q.rho = _rand(e, "rho", id);
        q.tau1 = _rand(e, "tau1", id);
        q.tau2 = _rand(e, "tau2", id);
        q.AS = bytes.concat(_vecCommit(e, q.alpha, q.aL, q.aR), _vecCommit(e, q.rho, q.sL, q.sR));
    }

    /// @dev l = l0 + x·s_L, r = r0 + x·(y^n∘s_R), t̂ = <l,r>, τ_x, μ.
    function _evalAt(uint256 r, RP memory q) internal pure {
        uint256 yi = 1;
        for (uint256 i; i < q.n; ++i) {
            q.l[i] = addmod(q.l[i], mulmod(q.x, q.sL[i], r), r);
            q.rv[i] = addmod(q.rv[i], mulmod(q.x, mulmod(yi, q.sR[i], r), r), r);
            q.that = addmod(q.that, mulmod(q.l[i], q.rv[i], r), r);
            yi = mulmod(yi, q.y, r);
        }
        uint256 taux = addmod(mulmod(q.tau2, mulmod(q.x, q.x, r), r), mulmod(q.tau1, q.x, r), r);
        taux = addmod(taux, mulmod(mulmod(q.z, q.z, r), q.gamma, r), r);
        q.tvals = abi.encodePacked(taux, addmod(q.alpha, mulmod(q.rho, q.x, r), r), q.that);
    }

    function _n(uint256 n) internal pure returns (string memory) {
        return Strings.toString(n);
    }

    /// @dev l0 = a_L − z, r0 = y^n∘(a_R + z) + z²2^n; T1, T2 với t1 = <l0,r1> + <l1,r0>, t2 = <l1,r1>.
    function _polys(Env memory e, RP memory q) internal view {
        uint256 r = e.r;
        q.l = new uint256[](q.n);
        q.rv = new uint256[](q.n);
        uint256 z2 = mulmod(q.z, q.z, r);
        uint256 yi = 1;
        uint256 twoI = 1;
        uint256 t1;
        uint256 t2;
        for (uint256 i; i < q.n; ++i) {
            q.l[i] = addmod(q.aL[i], r - q.z, r);
            q.rv[i] = addmod(mulmod(yi, addmod(q.aR[i], q.z, r), r), mulmod(z2, twoI, r), r);
            uint256 r1 = mulmod(yi, q.sR[i], r);
            t1 = addmod(t1, addmod(mulmod(q.l[i], r1, r), mulmod(q.sL[i], q.rv[i], r), r), r);
            t2 = addmod(t2, mulmod(q.sL[i], r1, r), r);
            yi = mulmod(yi, q.y, r);
            twoI = addmod(twoI, twoI, r);
        }
        bytes memory hb = _slice(e.gens, 0, e.p);
        q.T12 = bytes.concat(_m2(e.v, e.g, t1, hb, q.tau1), _m2(e.v, e.g, t2, hb, q.tau2));
    }

    function _vecCommit(Env memory e, uint256 blind, uint256[] memory av, uint256[] memory bv)
        internal view returns (bytes memory)
    {
        uint256 n = av.length;
        uint256[] memory sc = new uint256[](1 + 2 * n);
        sc[0] = blind;
        for (uint256 i; i < n; ++i) {
            sc[1 + i] = av[i];
            sc[1 + n + i] = bv[i];
        }
        bytes memory pts = bytes.concat(
            _slice(e.gens, 0, e.p), _slice(e.gens, 2 * e.p, n * e.p), _slice(e.gens, 66 * e.p, n * e.p)
        );
        return e.v.g1Msm(pts, sc);
    }

    struct IPA {
        uint256 m;
        uint256 h;
        uint256 u;
        uint256 uInv;
        bytes G;
        bytes H;
        bytes Q;
    }

    function _ipa(Env memory e, bytes32 st, RP memory q, uint256[] memory a, uint256[] memory b)
        internal view returns (bytes memory LR, uint256, uint256, bytes32)
    {
        IPA memory s = _ipaSetup(e, q);
        while (s.m > 1) {
            s.h = s.m / 2;
            bytes memory lr = bytes.concat(_lr(e, s, a, b, true), _lr(e, s, a, b, false));
            LR = bytes.concat(LR, lr);
            st = T.absorb(st, "ipa.LR", lr);
            (st, s.u) = T.challenge(st, "ipa.u", e.r);
            s.uInv = _inv(s.u, e.r);
            _fold(e, s, a, b);
            s.m = s.h;
        }
        return (LR, a[0], b[0], st);
    }

    function _ipaSetup(Env memory e, RP memory q) internal view returns (IPA memory s) {
        uint256 p = e.p;
        s.m = q.n;
        s.G = _slice(e.gens, 2 * p, q.n * p);
        s.H = new bytes(q.n * p);
        uint256 yInv = _inv(q.y, e.r);
        uint256 yi = 1;
        for (uint256 i; i < q.n; ++i) {
            _copy(s.H, i * p, e.v.g1Mul(_slice(e.gens, (66 + i) * p, p), yi), 0, p); // H'_i = [y^{-i}]H_i
            yi = mulmod(yi, yInv, e.r);
        }
        s.Q = e.v.g1Mul(_slice(e.gens, p, p), q.w);
    }

    /// @dev a' = a_lo·u + a_hi·u⁻¹, b' = b_lo·u⁻¹ + b_hi·u, G' = [u⁻¹]G_lo + [u]G_hi, H' = [u]H_lo + [u⁻¹]H_hi.
    function _fold(Env memory e, IPA memory s, uint256[] memory a, uint256[] memory b) internal view {
        uint256 r = e.r;
        for (uint256 i; i < s.h; ++i) {
            a[i] = addmod(mulmod(a[i], s.u, r), mulmod(a[s.h + i], s.uInv, r), r);
            b[i] = addmod(mulmod(b[i], s.uInv, r), mulmod(b[s.h + i], s.u, r), r);
            _foldPoint(e, s.G, i, s.h, s.uInv, s.u);
            _foldPoint(e, s.H, i, s.h, s.u, s.uInv);
        }
    }

    /// @dev vec[i] = [lo]vec[i] + [hi]vec[h+i]
    function _foldPoint(Env memory e, bytes memory vec, uint256 i, uint256 h, uint256 lo, uint256 hi) internal view {
        uint256 p = e.p;
        _copy(vec, i * p, _m2(e.v, _slice(vec, i * p, p), lo, _slice(vec, (h + i) * p, p), hi), 0, p);
    }

    /// @dev L = Σ[a_lo]G_hi + Σ[b_hi]H'_lo + [<a_lo,b_hi>]Q ; R = Σ[a_hi]G_lo + Σ[b_lo]H'_hi + [<a_hi,b_lo>]Q.
    function _lr(Env memory e, IPA memory s, uint256[] memory a, uint256[] memory b, bool left)
        internal view returns (bytes memory)
    {
        uint256 h = s.h;
        uint256 p = e.p;
        uint256[] memory sc = new uint256[](2 * h + 1);
        uint256 cross;
        for (uint256 i; i < h; ++i) {
            uint256 ai = left ? a[i] : a[h + i];
            uint256 bi = left ? b[h + i] : b[i];
            sc[i] = ai;
            sc[h + i] = bi;
            cross = addmod(cross, mulmod(ai, bi, e.r), e.r);
        }
        sc[2 * h] = cross;
        bytes memory pts = bytes.concat(
            _slice(s.G, (left ? h : 0) * p, h * p), _slice(s.H, (left ? 0 : h) * p, h * p), s.Q
        );
        return e.v.g1Msm(pts, sc);
    }

    // ------------------------------------------------------------------ tiện ích

    function _sp(Env memory e, bytes memory s, uint256 i) internal pure returns (bytes memory) {
        return _slice(s, HEADER + i * e.p, e.p);
    }

    function _pow(uint256 b, uint256 ex, uint256 r) internal pure returns (uint256 acc) {
        acc = 1;
        while (ex > 0) {
            if (ex & 1 == 1) acc = mulmod(acc, b, r);
            b = mulmod(b, b, r);
            ex >>= 1;
        }
    }

    function _inv(uint256 a, uint256 r) internal pure returns (uint256) {
        return _pow(a, r - 2, r);
    }

    function _isZero(bytes memory a) internal pure returns (bool) {
        return keccak256(a) == keccak256(new bytes(a.length));
    }

    function _slice(bytes memory a, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        _copy(out, 0, a, off, len);
    }

    function _copy(bytes memory dst, uint256 dstOff, bytes memory src, uint256 srcOff, uint256 len) internal pure {
        assembly ("memory-safe") {
            let d := add(add(dst, 32), dstOff)
            let s := add(add(src, 32), srcOff)
            for { let i := 0 } lt(i, len) { i := add(i, 32) } { mstore(add(d, i), mload(add(s, i))) }
        }
    }
}
