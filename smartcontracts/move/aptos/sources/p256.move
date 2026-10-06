/// ECDSA secp256r1 (P-256) viết bằng Move — **UNAUDITED**. Aptos chưa có native verify P-256 gọi được từ Move
/// (`aptos_std::secp256r1` chỉ có kiểu khoá; P-256 chỉ được kiểm ở tầng transaction authenticator, AIP-66), nên
/// passkey trong đường contract dùng module này (owner OQ1 → B). Tách riêng để thay bằng native khi Aptos có:
/// chỉ `verify` là API.
///
/// Số học: Montgomery R = 2^256 trên u256 (tích 512 bit dựng từ bốn tích 128×128), một hàm cho cả mod p và mod n.
/// Điểm: Jacobian, a = −3, cộng hỗn hợp (affine). u1·G + u2·Q xen kẽ (Strauss) bằng wNAF: G cửa sổ 7 với bảng
/// hằng 32 bội lẻ, Q cửa sổ 5 với 8 bội lẻ tính lúc chạy rồi chuẩn hoá affine chung một nghịch đảo (Montgomery trick).
/// Gas (localnet, `scripts/gas_probe.py`, spec §16): bảng của khoá lưu sẵn (`table`, lúc đăng ký) ⇒ `verify_with`
/// dưới một nửa trần execution gas, để một lệnh DEX khớp hai passkey vừa một tx.
/// Quy tắc: khoá 65 byte không nén `0x04‖x‖y` nằm trên đường cong; `0 < r < n`, `0 < s ≤ n/2` (low-s — một chữ
/// ký một dạng); `hash` 32 byte (SHA-256 của thông điệp, rút gọn mod n). Vector: Wycheproof P1363 + WebAuthn thật.
module scaas::p256 {
    const M128: u256 = 0xffffffffffffffffffffffffffffffff;

    const P: u256 = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
    const P_R2: u256 = 0x4fffffffdfffffffffffffffefffffffbffffffff0000000000000003;
    const P_ONE: u256 = 0xfffffffeffffffffffffffffffffffff000000000000000000000001;
    const N: u256 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
    const N_R2: u256 = 0x66e12d94f3d956202845b2392b6bec594699799c49bd6fa683244c95be79eea2;
    const N_ONE: u256 = 0xffffffff00000000000000004319055258e8617b0c46353d039cdaaf;
    /// Nửa thấp/cao 128 bit của p, n và −m⁻¹ (bớt phép tách trong `mont_mul`).
    const P_LO: u256 = 0xffffffffffffffffffffffff;
    const P_HI: u256 = 0xffffffff000000010000000000000000;
    const PNI_LO: u256 = 0x1000000000000000000000001;
    const PNI_HI: u256 = 0xffffffff000000020000000000000000;
    const N_LO: u256 = 0xbce6faada7179e84f3b9cac2fc632551;
    const N_HI: u256 = 0xffffffff00000000ffffffffffffffff;
    const NNI_LO: u256 = 0x48c944087d74d2e4ccd1c8aaee00bc4f;
    const NNI_HI: u256 = 0x60d06633a9d6281c50fe77ecc588c6f6;
    const HALF_N: u256 = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;
    /// b, 3 ở dạng Montgomery mod p.
    const B_M: u256 = 0xdc30061d04874834e5a220abf7212ed6acf005cd78843090d89cdf6229c4bddf;
    const THREE_M: u256 = 0x2fffffffcfffffffffffffffffffffffd000000000000000000000003;
    /// (2k+1)·G, k = 0..31, affine Montgomery mod p (sinh bằng Python, kiểm bởi vector Wycheproof).
    const GX_T: vector<u256> = vector[0x18905f76a53755c679fb732b7762251075ba95fc5fedb60179e730d418a9143c, 0x26936a3fb6ff747e66ad77dd87cbbc98b027f84a087d81fbffac3f904eebc127, 0xc9079605890523c8941cb5aad076c20c90ec649a94b9537dbe1b8aaec45c61f5, 0x13ba5119c3123e03f43eaab50c23bb082bd20213d23c00f70746354ea0173b4f, 0xe05b3080f0c4e16b2cc09c0444c8eb00abe6bfed59a7a84175c96e8f264e20e8, 0x3e7090f1649c90731ff3a4158dac1ab59de407956e7fdfe0ea7d260a6245e404, 0x738477ac5395b759bcbcd43f559e98110e356769856fd30dccc425634b2ed709, 0xe2aa0e430ad3da09ee337424e481937003cc23ee56e27e4b72bcd8b7bc60055b, 0xc1a35c0a6c7a574eb0f139752cfe2dfff17624b6ac0a177b97091dcbd53c5c9d, 0xfe545c282897c3fcb8842277752c41ac68363aba25e1a16efea912baa5659ae8, 0xecead9f4c16762fc6d2a506c5a3f3b3074e1b2654783f47d562e4cecc135b208, 0xaf2cea7c1727bf42d0825fa2a358406937c7a7e89e2e1f6ef4f876532de45068, 0x966742eb65432a2ee395993332f1f3af6fc1b49eed6b67b0a4a319acd837879f, 0x9f8aa54b2ef7c76a49d2c9eb084ffdd7d36a42d7aebf7313042c2af497e2feb4, 0xe266f95948603d48944a70270317b9e2f1be963a0d9258805e5db46acb66e132, 0x948dc4f8b1fc87b48ef5689d3cf7600ddd3cf7e7473017e6e2f73c696755ff89, 0x33ec6868f044b10cac09c4ae65578ab985ceae7c4b68f103871514560f664534, 0xca640b8642a3e5210b8e4134efc2b4c8742ee464233e76b7fd16847fdec67ef5, 0x2763a387dfa394ebc5748baea677d806b636458c7f178d5500467bc58cce08b5, 0x5853e4c4363186ac068f237d16fb36646f5ae714ff0b9346a9d89488a059c142, 0x98100a4fdb01614feeca111539ce22716fdfe0b56f072822624d60492ed22e91, 0x179c85db3db01994b7d9ad900574598180c5bfb4878873fa4ff23ffd248a7d06, 0xe94f7d346d8232781b1e8ae057477f580032940b946c6e181ee426ccd5cd79bf, 0x4b969974eba78bfd6b20afec715af2c70a624fa936c83906283c7513caa76097, 0xabdbe6084fb7db2bff4cd0b228766127ffe7048453dc690921950b421ff6acd3, 0xd20ebe0d5c3fa443da1deb852f4318d4e20bc0ba1e5edf3f508cec1c3b3f64c9, 0xec3a318d306634b0912e8beda8c8acd95f9c3fc492f2467997359638546c4d8d, 0x5cee8449a7b730dd0deb0e4a46c814c131eea5bf07ef5be6258bbbf9e7305683, 0xc13298306acf8ccc068212e3fd1eaf381bfeea57c7385b293ec832e77acaca28, 0x4c2bab1b8add53b7cb9727eaa2d17c362100d5d3a8d063d169d44ed65c46aa8e, 0x994a44a69b8335fa71cdf6537eceb50a59556621a9404f843667eb1a7f4c04cc, 0x0763a43482fc568d95c376329182cb26039c4800f0518eedb8d3d9319ff91fe5];
    const GY_T: vector<u256> = vector[0x8571ff1825885d85d2e88688dd21f3258b4ab8e4ba19e45cddf25357ce95560a, 0xd5f06a29e587cc07788208311a2ee98e583e47ad0861fe1ab04c5c1fc983a7eb, 0x73a076bb2dd1e9163540a9877e7a1f6873c568efe5eb882beb309b4ae7ba4f10, 0xeaedd9156e240867ef933bdc77c941956742f2f25da67bdd2847d0303f5b9d4d, 0x086659cdfd835f9b2b6e019a88b12f1a56af7bedce5d45e31eb7777aa45f3314, 0x68930023e125b88e0c0daa891ead643d250f939ee57f61c81a7685612b944e88, 0xfbc08769c9e7b7977cd06422bd1f5bc168748390742ed2e335752b90c00ee17f, 0x2042170a7079adf464efa6de778a4797d766355442a41b2540b8524f6383c45d, 0xebd512263274c3d02f4e247f0d1883bb0575bf30e89cb80e227d314693e79987, 0xf720ee256d12597b85665e9be39508c15806244afba977c52d36e9e7dc4c696b, 0xc086d5f1c9477fa37a75023e7fac29a41b0fadc083bb3c61f29dd4b2e286e5b9, 0x83d0687b9077666f48068e1371ac2f71e5fda49c27299f4a0360a4fb9e4785a9, 0x7b948dc356f7996812068859c9b731ee96cc631243f439504b8dc9feb4966228, 0x2d431068d84bde312d97d10878eb4cbb3bd0c66fddb7fb589200b7ba09895e70, 0x3798142a2a3be21b8a966939777c619f90472447a2fb18a398db66735c208899, 0xf38ae8914d7b4745faecedfd0c9803fc2d921ca298eb6028d9e9fe814ea53299, 0xb16c4303c32f63c4f909604f763f15745509d1285847d5ef6ac4832b3a8ec1f1, 0x2ba901628bb47af824e4ab126b237af7313c300c547852d5653a01908ceb6aa9, 0x58b36143620088a8f63ebce51558462ce7adda3e6f20d850a12b448a7d3cebb6, 0x0c0bc0e56919240847b864fae14e7b1c2ec4a76681828876e2d87d2363c52f98, 0xf70bfeec03884a7bc67732591d57d9ceb6f94d2ec87e9a47b6b0daa2a35c628f, 0x47795f4f95b2dda09e91cd3ba5e6a3184d82d052eadce5a8ba41b06261a6966c, 0xd73acbfe2cd9e6b5772ef6dec7f80c81c5254469f72b33a5c747cb96782ba21a, 0x9bbff86e6dddfd2704819d515ded93d49b944e107baeca13220755ccd921d60e, 0xd394077ef247fa364d78f592f7818ed826147d27f4645b5a837c92285e1109e8, 0xd731e383a2f54c2d99a5e23d82681c6261f1511c5e1a5f65370b4ea773241ea3, 0xfba1da5943465283b155bcd2dcafe1973db82f6f522113f280167f41c31cb264, 0x25e8013ff14cf3f4c2cf6a6880e518caee759f879e27a6b4eab495c5a0182bde, 0xda44c6c600017626c5ab2632c79b7a015748060db661782ab909f2db2aac9e59, 0xa062499846fb7a8b6651f7017ce477f8778afcd3a837ebeaa084e90c15426704, 0x0d1bc780872bdbf3b6658466da44bba2473c5680eed4350dd7faf819dbeb9b69, 0x90876a0140959b7092bf7c8f91230de0ac98b930824e8197707c04d5383e76ba];

    /// `true` chỉ khi chữ ký hợp lệ theo mọi quy tắc ở đầu module. Không abort với đầu vào xấu.
    public fun verify(pk: &vector<u8>, hash: &vector<u8>, sig: &vector<u8>): bool {
        let t = table(pk);
        !t.is_empty() && verify_with(&t, hash, sig)
    }

    /// Bảng 8 bội lẻ Q, 3Q, …, 15Q (affine Montgomery: 8 x rồi 8 y) của khoá 65 byte không nén nằm trên đường cong;
    /// rỗng nếu khoá không hợp lệ. Lưu kèm khoá passkey lúc đăng ký thì mỗi lần kiểm chữ ký bớt ~400 gas.
    public fun table(pk: &vector<u8>): vector<u256> {
        if (pk.length() != 65 || pk[0] != 4) return vector[];
        let (qx, qy) = (be(pk, 1), be(pk, 33));
        if (qx >= P || qy >= P) return vector[];
        let (qxm, qym) = (fmul(qx, P_R2), fmul(qy, P_R2));
        // y² = x³ − 3x + b
        let rhs = fadd(fsub(fmul(fmul(qxm, qxm), qxm), fmul(THREE_M, qxm)), B_M);
        if (fmul(qym, qym) != rhs) return vector[];
        q_table(qxm, qym)
    }

    /// Kiểm với bảng của `table(pk)` (bảng phải do `table` tính — module gọi giữ nó trong state của mình). `package`:
    /// module ngoài truyền bảng không tin cậy sẽ thành "kiểm theo Q mà bảng mã hoá" (review I1).
    package fun verify_with(t: &vector<u256>, hash: &vector<u8>, sig: &vector<u8>): bool {
        if (t.length() != 16 || hash.length() != 32 || sig.length() != 64) return false;
        let (r, s) = (be(sig, 0), be(sig, 32));
        if (r == 0 || r >= N || s == 0 || s > HALF_N) return false;
        let e = be(hash, 0);
        if (e >= N) e -= N;
        // w = s⁻¹·R (Montgomery mod n); u = x·w·R⁻¹ = x·s⁻¹ ở dạng thường.
        let w = ninv_m(s);
        let (u1, u2) = (nmul(e, w), nmul(r, w));
        let (d1, d2) = (wnaf(u1, 7), wnaf(u2, 5));
        let (gtx, gty) = (GX_T, GY_T);
        let (x, y, z) = (0, 0, 0);
        let i = if (d1.length() > d2.length()) d1.length() else d2.length();
        while (i > 0) {
            i -= 1;
            (x, y, z) = dbl(x, y, z);
            if (i < d1.length() && d1[i] != 0) (x, y, z) = add_digit(x, y, z, d1[i], &gtx, 0, &gty, 0);
            if (i < d2.length() && d2[i] != 0) (x, y, z) = add_digit(x, y, z, d2[i], t, 0, t, 8);
        };
        if (z == 0) return false;
        // x(R) mod n == r ⇔ r·Z² ≡ X (mod p) hoặc (r+n)·Z² ≡ X khi r+n < p — không cần nghịch đảo.
        let z2 = fmul(z, z);
        if (fmul(fmul(r, P_R2), z2) == x) return true;
        r < P - N && fmul(fmul(r + N, P_R2), z2) == x
    }

    /// wNAF cửa sổ `w` của k (bit thấp trước). Chữ số mã hoá 0 = không, ngược lại `1 + 2·chỉ số + âm` với
    /// |chữ số| = 2·chỉ số + 1.
    fun wnaf(k: u256, w: u8): vector<u64> {
        let (out, full) = (vector[], 1u256 << w);
        let half = full >> 1;
        while (k != 0) {
            if (k & 1 == 1) {
                let d = k & (full - 1);
                if (d >= half) {
                    let m = full - d; // chữ số âm d − 2^w; k < n nên k + m không tràn
                    k += m;
                    out.push_back(2 + ((((m as u64) - 1) >> 1) << 1));
                } else {
                    k -= d;
                    out.push_back(1 + ((((d as u64) - 1) >> 1) << 1));
                };
            } else out.push_back(0);
            k >>= 1;
        };
        out
    }

    /// Cộng (±) bội lẻ thứ `idx` của bảng affine (x ở `tx[ox + idx]`, y ở `ty[oy + idx]`) vào điểm Jacobian.
    inline fun add_digit(
        x: u256, y: u256, z: u256, enc: u64, tx: &vector<u256>, ox: u64, ty: &vector<u256>, oy: u64,
    ): (u256, u256, u256) {
        let idx = (enc - 1) >> 1;
        let py = ty[oy + idx];
        if ((enc - 1) & 1 == 1 && py != 0) py = P - py;
        madd(x, y, z, tx[ox + idx], py)
    }

    /// Q, 3Q, …, 15Q affine (Montgomery), 8 x rồi 8 y; rỗng nếu gặp điểm vô cực (không xảy ra với khoá hợp lệ).
    fun q_table(qx: u256, qy: u256): vector<u256> {
        let (x2, y2, z2) = dbl(qx, qy, P_ONE);
        if (z2 == 0) return vector[];
        let zi = finv(z2);
        let zi2 = fmul(zi, zi);
        let (tx, ty) = (fmul(x2, zi2), fmul(y2, fmul(zi2, zi)));
        let (xs, ys, zs) = (vector[qx], vector[qy], vector[P_ONE]);
        let (x, y, z) = (qx, qy, P_ONE);
        let k = 1;
        while (k < 8) {
            (x, y, z) = madd(x, y, z, tx, ty);
            if (z == 0) return vector[];
            xs.push_back(x);
            ys.push_back(y);
            zs.push_back(z);
            k += 1;
        };
        // Montgomery trick: c[i] = z0·…·zi, một nghịch đảo, rồi lùi.
        let c = vector[P_ONE];
        k = 1;
        while (k < 8) {
            let prev = c[k - 1];
            c.push_back(fmul(prev, zs[k]));
            k += 1;
        };
        let inv = finv(c[7]);
        while (k > 1) {
            k -= 1;
            let zinv = fmul(inv, c[k - 1]);
            inv = fmul(inv, zs[k]);
            let zinv2 = fmul(zinv, zinv);
            *xs.borrow_mut(k) = fmul(xs[k], zinv2);
            *ys.borrow_mut(k) = fmul(ys[k], fmul(zinv2, zinv));
        };
        xs.append(ys);
        xs
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
        let delta = fmul_i(z, z);
        let gamma = fmul_i(y, y);
        let beta = fmul_i(x, gamma);
        let t = fmul_i(fsub(x, delta), fadd(x, delta));
        let alpha = fadd(fadd(t, t), t);
        let beta4 = fadd(beta, beta);
        beta4 = fadd(beta4, beta4);
        let x3 = fsub(fmul_i(alpha, alpha), fadd(beta4, beta4));
        let yz = fadd(y, z);
        let z3 = fsub(fsub(fmul_i(yz, yz), gamma), delta);
        let g8 = fmul_i(gamma, gamma);
        g8 = fadd(g8, g8);
        g8 = fadd(g8, g8);
        g8 = fadd(g8, g8);
        (x3, fsub(fmul_i(alpha, fsub(beta4, x3)), g8), z3)
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
    // Gas (đo trên localnet, `smartcontracts/move/aptos/scripts/gas_probe.py`): một lời gọi hàm tốn hơn cả phép nhân, nên mọi
    // thứ bên trong `fmul`/`nmul` là `inline` (bản gọi hàm vượt trần execution gas của một tx); `fmul`/`nmul` giữ là
    // hàm thường để module không vượt 60 KB.

    fun fmul(a: u256, b: u256): u256 { fmul_i(a, b) }

    /// Bản inline cho `dbl` (vòng nóng: 256 lần nhân đôi, ~2/3 số phép nhân), bản gọi hàm cho phần còn lại — inline cả
    /// `madd` đẩy package quá 60 KB.
    inline fun fmul_i(a: u256, b: u256): u256 { mont_mul(a, b, P, P_LO, P_HI, PNI_LO, PNI_HI) }

    fun nmul(a: u256, b: u256): u256 { mont_mul(a, b, N, N_LO, N_HI, NNI_LO, NNI_HI) }

    inline fun fadd(a: u256, b: u256): u256 { if (a >= P - b) a - (P - b) else a + b }

    inline fun fsub(a: u256, b: u256): u256 { if (a >= b) a - b else P - (b - a) }

    /// a⁻¹·R mod p từ a ở dạng Montgomery (a·R): nghịch đảo thường của a·R là a⁻¹·R⁻¹, nhân R³ ⇒ a⁻¹·R.
    fun finv(a: u256): u256 { fmul(fmul(inv_mod(a, P), P_R2), P_R2) }

    /// a⁻¹·R mod n từ a ở dạng THƯỜNG (Montgomery của a⁻¹ = a⁻¹·R).
    fun ninv_m(a: u256): u256 { nmul(inv_mod(a, N), N_R2) }

    /// a⁻¹ mod m (m lẻ, 0 < a < m) — Euclid nhị phân; rẻ hơn Fermat ~10 lần về gas.
    fun inv_mod(a: u256, m: u256): u256 {
        let (u, v, x1, x2) = (a, m, 1u256, 0u256);
        while (u != 1 && v != 1) {
            while (u & 1 == 0) {
                u >>= 1;
                x1 = half_mod(x1, m);
            };
            while (v & 1 == 0) {
                v >>= 1;
                x2 = half_mod(x2, m);
            };
            if (u >= v) {
                u -= v;
                x1 = if (x1 >= x2) x1 - x2 else m - (x2 - x1);
            } else {
                v -= u;
                x2 = if (x2 >= x1) x2 - x1 else m - (x1 - x2);
            };
        };
        if (u == 1) x1 else x2
    }

    /// x/2 mod m (m lẻ): x chẵn ⇒ x>>1; lẻ ⇒ (x+m)/2 = (x>>1) + (m>>1) + 1, không tràn.
    inline fun half_mod(x: u256, m: u256): u256 { if (x & 1 == 0) x >> 1 else (x >> 1) + (m >> 1) + 1 }

    /// REDC(a·b) = a·b·2⁻²⁵⁶ mod m với a, b < m, m lẻ; `m_lo/m_hi`, `ni_lo/ni_hi` = nửa 128 bit của m và −m⁻¹ mod 2²⁵⁶.
    inline fun mont_mul(a: u256, b: u256, m: u256, m_lo: u256, m_hi: u256, ni_lo: u256, ni_hi: u256): u256 {
        let (th, tl) = mul_wide(a & M128, a >> 128, b & M128, b >> 128);
        let (t0, t1) = (tl & M128, tl >> 128);
        // q = tl·(−m⁻¹) mod 2²⁵⁶
        let q00 = t0 * ni_lo;
        let qt = (q00 >> 128) + ((t0 * ni_hi) & M128) + ((t1 * ni_lo) & M128);
        let q = (q00 & M128) | ((qt & M128) << 128);
        let (uh, _ul) = mul_wide(q & M128, q >> 128, m_lo, m_hi);
        // tl + ul ≡ 0 (mod 2²⁵⁶): có nhớ đúng khi tl ≠ 0. th, uh < m ⇒ kết quả < 2m, trừ m tối đa một lần.
        let s = if (tl != 0) th + 1 else th;
        if (s >= m - uh) s - (m - uh) else s + uh
    }

    /// Tích đầy đủ 512 bit (hi, lo) của (a1·2¹²⁸ + a0)(b1·2¹²⁸ + b0) — không nhánh, không tràn.
    inline fun mul_wide(a0: u256, a1: u256, b0: u256, b1: u256): (u256, u256) {
        let (p00, p01, p10) = (a0 * b0, a0 * b1, a1 * b0);
        let t = (p00 >> 128) + (p01 & M128) + (p10 & M128);
        (a1 * b1 + (p01 >> 128) + (p10 >> 128) + (t >> 128), (p00 & M128) | ((t & M128) << 128))
    }

    #[test]
    fun montgomery_round_trips() {
        let x = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        assert!(fmul(fmul(x, P_R2), 1) == x % P, 0);
        assert!(nmul(nmul(x % N, N_R2), 1) == x % N, 1);
        // (P−1)² ≡ 1
        let pm = fmul(P - 1, P_R2);
        assert!(fmul(fmul(pm, pm), 1) == 1, 2);
        // inverses: 7 · 7⁻¹ ≡ 1 (mod n), x · x⁻¹ ≡ 1 (mod p) in Montgomery form
        assert!(nmul(7, ninv_m(7)) == 1, 3);
        let xm = fmul(x % P, P_R2);
        assert!(fmul(fmul(xm, finv(xm)), 1) == 1, 4);
        assert!(inv_mod(P - 1, P) == P - 1 && inv_mod(1, N) == 1, 5);
    }
}
