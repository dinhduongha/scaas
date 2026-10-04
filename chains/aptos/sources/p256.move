/// ECDSA secp256r1 (P-256) viết bằng Move — **UNAUDITED**. Aptos chưa có native verify P-256 gọi được từ Move
/// (`aptos_std::secp256r1` chỉ có kiểu khoá; P-256 chỉ được kiểm ở tầng transaction authenticator, AIP-66), nên
/// passkey trong đường contract dùng module này (owner OQ1 → B). Tách riêng để thay bằng native khi Aptos có:
/// chỉ `verify` là API.
///
/// Số học: Montgomery R = 2^256 trên u256 (tích 512 bit dựng từ bốn tích 128×128), một hàm cho cả mod p và mod n.
/// Điểm: Jacobian, a = −3, cộng hỗn hợp (affine) + Shamir u1·G + u2·Q với G+Q chuẩn hoá về affine một lần.
/// Quy tắc: khoá 65 byte không nén `0x04‖x‖y` nằm trên đường cong; `0 < r < n`, `0 < s ≤ n/2` (low-s — một chữ
/// ký một dạng); `hash` 32 byte (SHA-256 của thông điệp, rút gọn mod n). Vector: Wycheproof P1363 + WebAuthn thật.
module bamboo::p256 {
    const MAX: u256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    const M128: u256 = 0xffffffffffffffffffffffffffffffff;

    const P: u256 = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
    const P_NEG_INV: u256 = 0xffffffff00000002000000000000000000000001000000000000000000000001;
    const P_R2: u256 = 0x4fffffffdfffffffffffffffefffffffbffffffff0000000000000003;
    const P_ONE: u256 = 0xfffffffeffffffffffffffffffffffff000000000000000000000001;
    const N: u256 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
    const N_NEG_INV: u256 = 0x60d06633a9d6281c50fe77ecc588c6f648c944087d74d2e4ccd1c8aaee00bc4f;
    const N_R2: u256 = 0x66e12d94f3d956202845b2392b6bec594699799c49bd6fa683244c95be79eea2;
    const N_ONE: u256 = 0xffffffff00000000000000004319055258e8617b0c46353d039cdaaf;
    const HALF_N: u256 = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;
    /// b, Gx, Gy, 3 ở dạng Montgomery mod p.
    const B_M: u256 = 0xdc30061d04874834e5a220abf7212ed6acf005cd78843090d89cdf6229c4bddf;
    const GX_M: u256 = 0x18905f76a53755c679fb732b7762251075ba95fc5fedb60179e730d418a9143c;
    const GY_M: u256 = 0x8571ff1825885d85d2e88688dd21f3258b4ab8e4ba19e45cddf25357ce95560a;
    const THREE_M: u256 = 0x2fffffffcfffffffffffffffffffffffd000000000000000000000003;

    /// `true` chỉ khi chữ ký hợp lệ theo mọi quy tắc ở đầu module. Không abort với đầu vào xấu.
    public fun verify(pk: &vector<u8>, hash: &vector<u8>, sig: &vector<u8>): bool {
        if (pk.length() != 65 || pk[0] != 4 || hash.length() != 32 || sig.length() != 64) return false;
        let (qx, qy, r, s) = (be(pk, 1), be(pk, 33), be(sig, 0), be(sig, 32));
        if (r == 0 || r >= N || s == 0 || s > HALF_N || qx >= P || qy >= P) return false;
        let (qxm, qym) = (fmul(qx, P_R2), fmul(qy, P_R2));
        // y² = x³ − 3x + b
        let rhs = fadd(fsub(fmul(fmul(qxm, qxm), qxm), fmul(THREE_M, qxm)), B_M);
        if (fmul(qym, qym) != rhs) return false;
        let e = be(hash, 0);
        if (e >= N) e -= N;
        // w = s⁻¹·R (Montgomery mod n, Fermat); u = x·w·R⁻¹ = x·s⁻¹ ở dạng thường.
        let w = nexp(nmul(s, N_R2), N - 2);
        let (u1, u2) = (nmul(e, w), nmul(r, w));
        let (sx, sy, sz) = madd(GX_M, GY_M, P_ONE, qxm, qym);
        let (gqx, gqy) = (0, 0);
        if (sz != 0) {
            let zi = fexp(sz, P - 2);
            let zi2 = fmul(zi, zi);
            gqx = fmul(sx, zi2);
            gqy = fmul(sy, fmul(zi2, zi));
        };
        let (x, y, z) = (0, 0, 0);
        let i = top_bit(u1 | u2);
        while (i > 0) {
            i -= 1;
            (x, y, z) = dbl(x, y, z);
            let (b1, b2) = ((u1 >> (i as u8)) & 1, (u2 >> (i as u8)) & 1);
            if (b1 == 1 && b2 == 1) {
                if (sz != 0) (x, y, z) = madd(x, y, z, gqx, gqy);
            } else if (b1 == 1) {
                (x, y, z) = madd(x, y, z, GX_M, GY_M);
            } else if (b2 == 1) {
                (x, y, z) = madd(x, y, z, qxm, qym);
            };
        };
        if (z == 0) return false;
        // x(R) mod n == r ⇔ r·Z² ≡ X (mod p) hoặc (r+n)·Z² ≡ X khi r+n < p — không cần nghịch đảo.
        let z2 = fmul(z, z);
        if (fmul(fmul(r, P_R2), z2) == x) return true;
        r < P - N && fmul(fmul(r + N, P_R2), z2) == x
    }

    /// Số bit của `v` (0 cho 0) — bỏ các vòng nhân đôi điểm vô cực ở đầu.
    fun top_bit(v: u256): u64 {
        let n = 0;
        while (v != 0) {
            v >>= 1;
            n += 1;
        };
        n
    }

    /// 32 byte big-endian từ `off`.
    fun be(b: &vector<u8>, off: u64): u256 {
        let (v, i) = (0u256, 0);
        while (i < 32) {
            v = (v << 8) | (b[off + i] as u256);
            i += 1;
        };
        v
    }

    // ------------------------------------------------------------------ điểm (Jacobian, Montgomery mod p)

    /// dbl-2001-b (a = −3). Z = 0 là điểm vô cực.
    fun dbl(x: u256, y: u256, z: u256): (u256, u256, u256) {
        if (z == 0 || y == 0) return (0, 0, 0);
        let delta = fmul(z, z);
        let gamma = fmul(y, y);
        let beta = fmul(x, gamma);
        let t = fmul(fsub(x, delta), fadd(x, delta));
        let alpha = fadd(fadd(t, t), t);
        let beta4 = fadd(beta, beta);
        beta4 = fadd(beta4, beta4);
        let x3 = fsub(fmul(alpha, alpha), fadd(beta4, beta4));
        let yz = fadd(y, z);
        let z3 = fsub(fsub(fmul(yz, yz), gamma), delta);
        let g8 = fmul(gamma, gamma);
        g8 = fadd(g8, g8);
        g8 = fadd(g8, g8);
        g8 = fadd(g8, g8);
        (x3, fsub(fmul(alpha, fsub(beta4, x3)), g8), z3)
    }

    /// madd-2007-bl: (x1,y1,z1) Jacobian + (x2,y2) affine.
    fun madd(x1: u256, y1: u256, z1: u256, x2: u256, y2: u256): (u256, u256, u256) {
        if (z1 == 0) return (x2, y2, P_ONE);
        let z1z1 = fmul(z1, z1);
        let h = fsub(fmul(x2, z1z1), x1);
        let rr = fsub(fmul(y2, fmul(z1, z1z1)), y1);
        if (h == 0) {
            if (rr == 0) return dbl(x2, y2, P_ONE);
            return (0, 0, 0)
        };
        rr = fadd(rr, rr);
        let hh = fmul(h, h);
        let i = fadd(hh, hh);
        i = fadd(i, i);
        let j = fmul(h, i);
        let v = fmul(x1, i);
        let x3 = fsub(fsub(fmul(rr, rr), j), fadd(v, v));
        let y1j = fmul(y1, j);
        let y3 = fsub(fmul(rr, fsub(v, x3)), fadd(y1j, y1j));
        let zh = fadd(z1, h);
        (x3, y3, fsub(fsub(fmul(zh, zh), z1z1), hh))
    }

    // ------------------------------------------------------------------ trường

    fun fmul(a: u256, b: u256): u256 { mont_mul(a, b, P, P_NEG_INV) }

    fun nmul(a: u256, b: u256): u256 { mont_mul(a, b, N, N_NEG_INV) }

    fun fadd(a: u256, b: u256): u256 { if (a >= P - b) a - (P - b) else a + b }

    fun fsub(a: u256, b: u256): u256 { if (a >= b) a - b else P - (b - a) }

    fun fexp(b: u256, e: u256): u256 {
        let (acc, i) = (P_ONE, 256);
        while (i > 0) {
            i -= 1;
            acc = fmul(acc, acc);
            if ((e >> (i as u8)) & 1 == 1) acc = fmul(acc, b);
        };
        acc
    }

    fun nexp(b: u256, e: u256): u256 {
        let (acc, i) = (N_ONE, 256);
        while (i > 0) {
            i -= 1;
            acc = nmul(acc, acc);
            if ((e >> (i as u8)) & 1 == 1) acc = nmul(acc, b);
        };
        acc
    }

    /// REDC(a·b) = a·b·2⁻²⁵⁶ mod m với a, b < m, m lẻ, `neg_inv` = −m⁻¹ mod 2²⁵⁶.
    fun mont_mul(a: u256, b: u256, m: u256, neg_inv: u256): u256 {
        let (th, tl) = mul_wide(a, b);
        let (uh, _) = mul_wide(mul_lo(tl, neg_inv), m);
        // tl + ul ≡ 0 (mod 2²⁵⁶): có nhớ đúng khi tl ≠ 0. th, uh < m ⇒ th + uh + 1 < 2m.
        let r = if (tl != 0) th + 1 else th;
        if (r > MAX - uh) return r - (m - uh);
        let s = r + uh;
        if (s >= m) s - m else s
    }

    /// Tích đầy đủ 512 bit (hi, lo).
    fun mul_wide(a: u256, b: u256): (u256, u256) {
        let (a0, a1, b0, b1) = (a & M128, a >> 128, b & M128, b >> 128);
        let (mid, c1) = add_c(a0 * b1, a1 * b0);
        let (lo, c2) = add_c(a0 * b0, mid << 128);
        (a1 * b1 + (mid >> 128) + (c1 << 128) + c2, lo)
    }

    /// a·b mod 2²⁵⁶.
    fun mul_lo(a: u256, b: u256): u256 {
        let (a0, a1, b0, b1) = (a & M128, a >> 128, b & M128, b >> 128);
        let cross = ((((a0 * b1) & M128) + ((a1 * b0) & M128)) & M128) << 128;
        let (lo, _) = add_c(a0 * b0, cross);
        lo
    }

    /// (a + b mod 2²⁵⁶, nhớ).
    fun add_c(a: u256, b: u256): (u256, u256) {
        if (a > MAX - b) (a - (MAX - b) - 1, 1) else (a + b, 0)
    }

    #[test]
    fun montgomery_round_trips() {
        let x = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        assert!(fmul(fmul(x, P_R2), 1) == x % P, 0);
        assert!(nmul(nmul(x % N, N_R2), 1) == x % N, 1);
        // (P−1)² ≡ 1
        let pm = fmul(P - 1, P_R2);
        assert!(fmul(fmul(pm, pm), 1) == 1, 2);
        // inverse: 7 · 7⁻¹ ≡ 1 (mod n)
        let s = nmul(7, N_R2);
        assert!(nmul(nmul(s, nexp(s, N - 2)), 1) == 1, 3);
    }
}
