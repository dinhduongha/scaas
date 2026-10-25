//! Test entry points (`#[doc(hidden)]`, not API): the arithmetic KAT of `pqzl/kat/lazer_dump.c` for the `kat_dump`
//! binary, KeyGen / Enc with lowered norm thresholds for the `keys_kat` binary, and the Rust halves of the C-oracle
//! tests (`tests/oracle_arith.rs`), whose C halves are in `tests/oracle_shim.c`.
//! Plain data in and out, so the crate's internal types stay internal.
use crate::arith::int::Int;
use crate::arith::ntt::{self, D, Q};
use crate::arith::poly::{Poly, RING_Q};
use crate::arith::polymat::{Pm, PolyMat};
use crate::arith::polyvec::{self, PolyVec};
use crate::params::tx::pqz_tx_dcomp;
use crate::rand::rng::Rng;
use alloc::string::String;
use core::fmt::Write;

/// `pqz_ntt_fwd`
pub fn ntt_fwd(c: &mut [u64; 64]) {
    ntt::fwd(c);
}

/// `pqz_ntt_inv`
pub fn ntt_inv(c: &mut [u64; 64]) {
    ntt::inv(c);
}

/// `pqz_ntt_basemul`
pub fn ntt_basemul(a: &[u64; 64], b: &[u64; 64]) -> [u64; 64] {
    ntt::basemul(a, b)
}

/// `pqz_keygen` with lowered norm thresholds (the C core's PQZ_TEST_HOOKS knobs `pqz_test_bs` / `pqz_test_be`): the
/// keys KAT pins the resample path and the counter-64 error with them; with `ctx` as `Ctx::keygen` (its cached A)
pub fn keygen_lowered(ctx: Option<&mut crate::Ctx>, seed32: &[u8; 32], bs: i64, be: i64) -> Result<crate::Key, crate::Error> {
    crate::keys::keygen(ctx.map_or(&mut None, |c| &mut c.a), seed32, bs, be)
}

/// `pqz_enc_seed` with lowered norm thresholds (`pqz_test_bs` / `_be` / `_b2`); with `ctx` as `Ctx::enc_seed`
pub fn enc_seed_lowered(
    ctx: Option<&mut crate::Ctx>,
    pks: &[&[u8; crate::POLYVEC_BYTES]],
    msgs: &[[u8; 16]],
    seed_enc: &[u8; 32],
    bs: i64,
    be: i64,
    b2: i64,
) -> Result<crate::Enc, crate::Error> {
    crate::keys::enc_seed(ctx.map_or(&mut None, |c| &mut c.a), pks, None, msgs, seed_enc, (bs, be, b2))
}

/// `print_int`: up to two limbs as a decimal (a zero of either sign is `0`), else `"overflow"`
fn put_int(o: &mut String, a: &Int) {
    if a.limbs()[2.min(a.n)..].iter().any(|&x| x != 0) {
        o.push_str("\"overflow\"");
        return;
    }
    let m = a.l[0] as u128 | if a.n > 1 { (a.l[1] as u128) << 64 } else { 0 };
    if m != 0 && a.neg != 0 {
        o.push('-');
    }
    let _ = write!(o, "{m}");
}

/// `print_poly`: centres the poly in place (`poly_redc (p, p)`, which also moves it to the coefficient domain)
fn put_poly(o: &mut String, p: &mut Poly) {
    *p = Poly::redc(p);
    o.push('[');
    for j in 0..D {
        if j > 0 {
            o.push(',');
        }
        put_int(o, &p.get_coeff(j));
    }
    o.push(']');
}

fn begin_case(o: &mut String, first: &mut bool, name: &str) {
    let _ = write!(o, "{}\n  \"{name}\": ", if *first { "" } else { "," });
    *first = false;
}

/// `lazer_dump.c`'s 19 cases on the same inputs, in its JSON shape (`meta.backend = "pqzl-rust"`); compare with
/// `kat/check.py`
pub fn kat_json() -> Result<String, crate::Error> {
    const NP: usize = 24;
    const H: i64 = ((Q - 1) / 2) as i64;
    let mut xs: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut rnd = move || {
        xs ^= xs >> 12;
        xs ^= xs << 25;
        xs ^= xs >> 27;
        xs.wrapping_mul(2_685_821_657_736_338_717)
    };
    let mut fill = |kind: usize| {
        let mut p = Poly::ZERO;
        for j in 0..D {
            let v = match kind {
                0 => (rnd() % Q) as i64 - H,
                1 => H,
                2 => -H,
                3 => [-H, H][j & 1],
                4 => (rnd() % 3) as i64 - 1,
                _ => (rnd() % 1_000_001) as i64 - 500_000,
            };
            p.set_coeff(j, &Int::from_i64(1, v));
        }
        p
    };
    let mut a = PolyVec::new(NP)?;
    let mut b = PolyVec::new(NP)?;
    for i in 0..NP {
        a[i] = fill(if i < 4 { i + 1 } else if i < 8 { 4 } else if i < 12 { 5 } else { 0 });
        b[i] = fill(if i < 4 { (i + 1) % 4 + 1 } else if i % 3 == 0 { 4 } else { 0 });
    }

    let mut o = String::new();
    let _ = write!(
        o,
        "{{\n  \"meta\": {{\"backend\": \"pqzl-rust\", \"lazer_commit\": \"3330e487228f633eceb322807b13a596b516770f\", \
         \"build\": \"rust\", \"compiler\": \"rustc\", \"cpu_avx512f\": 0, \"cpu_avx512ifma\": 0, \
         \"ring\": \"Z_q[X]/(X^64+1), q = {} (set {})\"}},\n  \"cases\": {{",
        crate::params::set::Q,
        crate::params::set::SET_NAME
    );
    let mut first = true;
    for (name, v) in [("inputs_a", &mut a), ("inputs_b", &mut b)] {
        begin_case(&mut o, &mut first, name);
        o.push('[');
        for i in 0..NP {
            o.push_str(if i > 0 { "," } else { "" });
            put_poly(&mut o, &mut v[i]);
        }
        o.push(']');
    }

    let j = |i: usize| (i + 1) % NP;
    per_pair(&mut o, &mut first, "mul", &mut a, &mut b, &|i, a, b| Ok(Poly::mul(&mut a[i], &mut b[i])))?;
    per_pair(&mut o, &mut first, "add", &mut a, &mut b, &|i, a, b| Ok(Poly::add(&mut a[i], &mut b[i], false)))?;
    per_pair(&mut o, &mut first, "sub", &mut a, &mut b, &|i, a, b| Ok(Poly::sub(&mut a[i], &mut b[i], false)))?;
    per_pair(&mut o, &mut first, "neg", &mut a, &mut b, &|i, a, _| Ok(Poly::neg(&mut a[i])))?;
    per_pair(&mut o, &mut first, "scale", &mut a, &mut b, &|i, _, b| {
        let sc = Int::from_i64(1, ((i as u64).wrapping_mul(1_234_567_891) % Q) as i64 - H);
        Ok(Poly::scale(&sc, &mut b[i]))
    })?;
    per_pair(&mut o, &mut first, "auto", &mut a, &mut b, &|i, a, _| Ok(Poly::auto(&mut a[i])))?;
    per_pair(&mut o, &mut first, "mul_add_crt", &mut a, &mut b, &|i, a, b| {
        let mut r = Poly::mul(&mut a[i], &mut b[i]);
        let (bi, bj) = pair(b, i, j(i));
        r.add_assign(&mut Poly::mul(bi, bj), true);
        Ok(r)
    })?;
    per_pair(&mut o, &mut first, "mul_sub_crt", &mut a, &mut b, &|i, a, b| {
        let mut r = Poly::mul(&mut a[i], &mut b[i]);
        let (ai, aj) = pair(a, i, j(i));
        r.sub_assign(&mut Poly::mul(ai, aj), true);
        Ok(r)
    })?;

    begin_case(&mut o, &mut first, "l2sqr_linf");
    o.push('[');
    for i in 0..NP {
        let (l2, li) = (a[i].l2sqr(), a[i].linf());
        o.push_str(if i > 0 { ",[" } else { "[" });
        put_int(&mut o, &l2);
        o.push(',');
        put_int(&mut o, &li);
        o.push(']');
    }
    o.push(']');

    // polymat (4 x 8) times polyvec (8), a row's dot product, a vector's l2^2
    let mut am = PolyMat::new(4, 8)?;
    let mut x = PolyVec::new(8)?;
    let mut y = PolyVec::new(4)?;
    for i in 0..4 {
        for jj in 0..8 {
            am.at(i, jj).clone_from(&a[(8 * i + jj) % NP]);
        }
    }
    for jj in 0..8 {
        x[jj].clone_from(&b[(3 * jj + 1) % NP]);
    }
    polyvec::mul(&mut y, &mut am, &mut x);
    polyvec::fromcrt(&mut y);
    begin_case(&mut o, &mut first, "matvec");
    o.push('[');
    for i in 0..4 {
        o.push_str(if i > 0 { "," } else { "" });
        put_poly(&mut o, &mut y[i]);
    }
    o.push(']');
    let mut r = polyvec::dot(&mut am.row(1), &mut x);
    begin_case(&mut o, &mut first, "dot");
    put_poly(&mut o, &mut r);
    begin_case(&mut o, &mut first, "vec_l2sqr");
    put_int(&mut o, &polyvec::l2sqr(&mut x));

    begin_case(&mut o, &mut first, "decompose");
    o.push('[');
    for i in 0..NP {
        let (mut r1, mut r0) = Poly::decompose(&mut a[i], &pqz_tx_dcomp);
        o.push_str(if i > 0 { ",[" } else { "[" });
        put_poly(&mut o, &mut r1);
        o.push(',');
        put_poly(&mut o, &mut r0);
        o.push(']');
    }
    o.push(']');
    per_pair(&mut o, &mut first, "power2round", &mut a, &mut b, &|i, a, _| Ok(Poly::power2round(&mut a[i], &pqz_tx_dcomp)))?;

    // the library PRNG and the samplers driven by it
    let seed: [u8; 32] = core::array::from_fn(|i| (i * 7 + 1) as u8);
    let mut out = [0u8; 1024];
    let mut st = Rng::new(&seed, 5);
    st.urandom(&mut out[..1000])?; // odd length: the C core's block cache
    st.urandom(&mut out[1000..])?;
    begin_case(&mut o, &mut first, "aes256ctr_stream_hex");
    o.push('"');
    for x in out {
        let _ = write!(o, "{x:02x}");
    }
    o.push('"');
    per_pair(&mut o, &mut first, "urandom", &mut a, &mut b, &|i, _, _| Poly::urandom(&RING_Q, crate::arith::poly::LOG2Q, &seed, i as u64))?;
    per_pair(&mut o, &mut first, "brandom", &mut a, &mut b, &|i, _, _| Poly::brandom(2, &seed, i as u64))?;
    o.push_str("\n  }\n}\n");
    Ok(o)
}

type PairFn<'a> = &'a dyn Fn(usize, &mut PolyVec, &mut PolyVec) -> Result<Poly, crate::Error>;

/// `PER_PAIR (name, stmt)`: r = f(i) for every i, printed (and centred)
fn per_pair(o: &mut String, first: &mut bool, name: &str, a: &mut PolyVec, b: &mut PolyVec, f: PairFn)
            -> Result<(), crate::Error> {
    begin_case(o, first, name);
    o.push('[');
    for i in 0..a.len() {
        o.push_str(if i > 0 { "," } else { "" });
        let mut r = f(i, a, b)?;
        put_poly(o, &mut r);
    }
    o.push(']');
    Ok(())
}

/// two distinct elements, mutably
fn pair(v: &mut [Poly], i: usize, j: usize) -> (&mut Poly, &mut Poly) {
    assert!(i != j);
    if i < j {
        let (l, h) = v.split_at_mut(j);
        (&mut l[i], &mut h[0])
    } else {
        let (l, h) = v.split_at_mut(i);
        (&mut h[0], &mut l[j])
    }
}

/// input words of [`polyvec_ops`]: 31 polys (A 3x4, x 4, y 4, z 3, c, 3 sparse-vector and 4 sparse-matrix entries) and
/// a scalar
#[cfg(feature = "c-oracle")]
pub const OPS_IN: usize = 31 * 64 + 1;

#[cfg(feature = "c-oracle")]
fn dump(o: &mut alloc::vec::Vec<u64>, p: &Poly) {
    o.push(p.crt as u64);
    o.push(if p.crt { 0 } else { p.neg });
    o.extend_from_slice(&p.v);
}

#[cfg(feature = "c-oracle")]
fn dump_int(o: &mut alloc::vec::Vec<u64>, a: &Int) {
    o.extend_from_slice(&[a.n as u64, a.neg, a.l[0], if a.n > 1 { a.l[1] } else { 0 }]);
}

/// a fixed sequence of vector / matrix / sparse operations and the states they leave (`pqz_shim_polyvec_ops` in
/// tests/oracle_shim.c, step for step): every output poly and, at the end, every operand
#[cfg(feature = "c-oracle")]
pub fn polyvec_ops(inp: &[i64]) -> Result<alloc::vec::Vec<u64>, crate::Error> {
    use crate::arith::polymat;
    use crate::arith::spoly::Sparse;
    let mut o = alloc::vec::Vec::new();
    let mut k = 0;
    let mut next = || {
        let mut p = Poly::ZERO;
        p.set_i64(&inp[64 * k..64 * k + 64]);
        k += 1;
        p
    };
    let mut am = PolyMat::new(3, 4)?;
    for i in 0..3 {
        for j in 0..4 {
            *am.at(i, j) = next();
        }
    }
    let mut x = PolyVec(core::iter::repeat_with(&mut next).take(4).collect());
    let mut y = PolyVec(core::iter::repeat_with(&mut next).take(4).collect());
    let mut z = PolyVec(core::iter::repeat_with(&mut next).take(3).collect());
    let mut c = next();
    let svp: [Poly; 3] = core::array::from_fn(|_| next());
    let smp: [Poly; 4] = core::array::from_fn(|_| next());
    let s = Int::from_i64(1, inp[64 * 31]);
    let (mut r3, mut r4, mut t4) = (PolyVec::new(3)?, PolyVec::new(4)?, PolyVec::new(4)?);
    let dv = |o: &mut alloc::vec::Vec<u64>, v: &PolyVec| v.iter().for_each(|p| dump(o, p));

    y[1].tocrt();
    z[0].tocrt();
    polyvec::mul(&mut r3, &mut am, &mut x);
    dv(&mut o, &r3);
    polyvec::add(&mut r4, &mut x, &mut y, false);
    dv(&mut o, &r4);
    polyvec::sub(&mut t4, &mut x, &mut y, true);
    dv(&mut o, &t4);
    polyvec::addmul(&mut r3, &mut am, &mut y, false);
    dv(&mut o, &r3);
    polyvec::mul2(&mut r4, &mut z, &mut am);
    dv(&mut o, &r4);
    polyvec::scale(&mut t4, &s, &mut y);
    dv(&mut o, &t4);
    polyvec::scale2(&mut r4, &mut c, &mut x);
    dv(&mut o, &r4);
    let mut d = polyvec::dot(&mut x, &mut y);
    dump(&mut o, &d);
    polyvec::auto(&mut t4, &mut x);
    dv(&mut o, &t4);
    polyvec::lrot(&mut r4, &mut y, 5);
    dv(&mut o, &r4);
    polyvec::redp(&mut t4, &mut y);
    polyvec::mod_(&mut r4, &mut x);
    dv(&mut o, &t4);
    dv(&mut o, &r4);
    let (l2, li) = (polyvec::l2sqr(&mut y), polyvec::linf(&mut x));
    dump_int(&mut o, &l2);
    dump_int(&mut o, &li);

    let mut sv = Sparse::new_vec(4);
    for (p, e) in svp.iter().zip([3, 0, 2]) {
        sv.insert_elem(e)?.clone_from(p);
    }
    sv.sort()?;
    d = polyvec::dot2(&mut sv, &mut x);
    dump(&mut o, &d);

    let mut sm = Sparse::new_mat(3, 4, 6);
    for (p, (r, cc)) in smp.iter().zip([(2, 1), (0, 3), (0, 0), (1, 2)]) {
        sm.insert_rc(r, cc)?.clone_from(p);
    }
    sm.sort()?;
    polyvec::mulsparse(&mut r3, &mut sm, &mut y);
    dv(&mut o, &r3);

    polyvec::subscale2(&mut r3, &mut c, &mut z, true);
    dv(&mut o, &r3);
    polyvec::addscale(&mut r4, &s, &mut x, false);
    dv(&mut o, &r4);
    d = Poly::tracemap(&mut c);
    dump(&mut o, &d);
    polyvec::neg_self(&mut x);
    dv(&mut o, &x);

    let mut sm2 = Sparse::new_mat(3, 4, 6);
    Sparse::set(&mut sm2, &sm)?;
    let mut sm3 = Sparse::new_mat(3, 4, 10);
    Sparse::add(&mut sm3, &mut sm, &mut sm2, false)?;
    polyvec::mulsparse(&mut r3, &mut sm3, &mut x);
    dv(&mut o, &r3);

    polyvec::redc(&mut t4, &mut x);
    dv(&mut o, &t4);
    polyvec::sublshift(&mut r4, &mut t4, 3);
    dv(&mut o, &r4);

    d.auto_self();
    dump(&mut o, &d);
    // poly_auto_self in the NTT domain (e = c x[0] is in it)
    let mut e = Poly::mul(&mut c, &mut x[0]);
    e.auto_self();
    dump(&mut o, &e);

    let mut bm = PolyMat::new(3, 4)?;
    polymat::auto(&mut bm, &mut am);
    (0..12).for_each(|i| dump(&mut o, bm.at(i / 4, i % 4)));
    polymat::lrot(&mut bm, &mut am, 7);
    (0..12).for_each(|i| dump(&mut o, bm.at(i / 4, i % 4)));
    o.push(polymat::is_upperdiag(&mut bm) as u64);

    let mut sv2 = Sparse::new_vec(4);
    Sparse::lrot(&mut sv2, &mut sv, 9)?;
    let mut sv3 = Sparse::new_vec(8);
    Sparse::add(&mut sv3, &mut sv, &mut sv2, true)?;
    d = polyvec::dot2(&mut sv3, &mut y);
    dump(&mut o, &d);
    Sparse::scale2(&mut sv2, &mut c, &mut sv)?;
    d = polyvec::dot2(&mut sv2, &mut x);
    dump(&mut o, &d);
    Sparse::mod_(&mut sv2, &mut sv)?;
    d = polyvec::dot2(&mut sv2, &mut y);
    dump(&mut o, &d);
    Sparse::scale(&mut sv2, &s, &mut sv)?;
    d = polyvec::dot2(&mut sv2, &mut x);
    dump(&mut o, &d);

    (0..12).for_each(|i| dump(&mut o, am.at(i / 4, i % 4)));
    dv(&mut o, &x);
    dv(&mut o, &y);
    dv(&mut o, &z);
    dump(&mut o, &c);
    (0..sv.nelems()).for_each(|i| dump(&mut o, sv.get_elem(i)));
    (0..sm.nelems()).for_each(|i| dump(&mut o, sm.get_elem(i)));
    Ok(o)
}

#[cfg(feature = "c-oracle")]
fn dump_intn(o: &mut alloc::vec::Vec<u64>, a: &Int) {
    o.extend_from_slice(&[a.n as u64, a.neg]);
    o.extend_from_slice(a.limbs());
}

/// input words of [`int_ops`]
#[cfg(feature = "c-oracle")]
pub const INT_OPS_IN: usize = 18;

/// multi-limb int and int-vector operations (`pqz_shim_int_ops` in tests/oracle_shim.c, step for step)
#[cfg(feature = "c-oracle")]
pub fn int_ops(inp: &[u64; INT_OPS_IN]) -> Result<alloc::vec::Vec<u64>, crate::Error> {
    use crate::arith::int::{int_div, IntVec};
    let mut o = alloc::vec::Vec::new();
    let a = Int::from_limbs(&[inp[0], inp[1]], inp[2] & 1);
    let b = Int::from_limbs(&[inp[3], inp[4]], inp[5] & 1);
    let m = Int::from_limbs(&[inp[6], inp[7] | 1], 0);
    let k = Int::from_limbs(&[inp[8] | 1], 0);
    let sh = (inp[9] % 140) as u32;
    let (mut v, mut w) = (IntVec::new(4, 1)?, IntVec::new(4, 1)?);
    for i in 0..4 {
        v.set_elem_i64(i, inp[10 + i] as i64);
        w.set_elem_i64(i, inp[14 + i] as i64);
    }
    let (mut r1, mut r2, mut r4, mut q3) = (Int::new(1), Int::new(2), Int::new(4), Int::new(3));

    r2.add(&a, &b);
    dump_intn(&mut o, &r2);
    r2.sub(&a, &b);
    dump_intn(&mut o, &r2);
    r4.mul(&a, &b);
    dump_intn(&mut o, &r4);
    r2.mod_(&r4, &m);
    dump_intn(&mut o, &r2);
    r1.mod_(&a, &k);
    dump_intn(&mut o, &r1);
    int_div(&mut q3, &mut r2, &r4, &m);
    dump_intn(&mut o, &q3);
    dump_intn(&mut o, &r2);
    r2.rshift(&a, sh);
    dump_intn(&mut o, &r2);
    r2.lshift(&a, sh);
    dump_intn(&mut o, &r2);
    r4.lshift(&a, sh);
    dump_intn(&mut o, &r4);
    r2.redc(&a, &m);
    dump_intn(&mut o, &r2);
    r2.redp(&a, &m);
    dump_intn(&mut o, &r2);
    r1.set(&a);
    dump_intn(&mut o, &r1);
    r4.set(&b);
    r4.addmul(&a, &b);
    dump_intn(&mut o, &r4);
    r4.submul(&b, &b);
    dump_intn(&mut o, &r4);
    r4.subsqr(&a);
    dump_intn(&mut o, &r4);
    r2.set(&a);
    r2.mul_sgn_self(-1);
    dump_intn(&mut o, &r2);
    let f = [a.eq(&b), a.lt(&b), a.le(&b), a.gt(&b), a.ge(&b), a.abslt(&b), a.absle(&b), a.absgt(&b), a.absge(&b),
             a.abseq(&b)];
    let bits = f.iter().enumerate().fold(0u64, |x, (i, &t)| x | (t as u64) << i);
    o.push(bits | ((a.sgn() + 1) as u64) << 10 | (a.eqzero() as u64) << 12);
    o.push(a.get_i64() as u64);

    IntVec::dot(&mut r2, &v, &w);
    dump_intn(&mut o, &r2);
    v.l2sqr(&mut r2);
    dump_intn(&mut o, &r2);
    w.linf(&mut r1);
    dump_intn(&mut o, &r1);
    o.push(v.lt(&k) as u64 | (v.ge(&k) as u64) << 1 | (w.le(&k) as u64) << 2 | (w.gt(&k) as u64) << 3
           | (v.eq(&w) as u64) << 4);
    v.add_assign(&w);
    v.mod_self(&k);
    w.redc_self(&k);
    v.sub_assign(&w);
    w.redp_self(&k);
    v.rshift_self(3);
    w.lshift_self(5);
    v.mul_sgn_self(-1);
    w.neg_self();
    for i in 0..4 {
        dump_intn(&mut o, &v.get(i));
        dump_intn(&mut o, &w.get(i));
    }
    Ok(o)
}

// ---------------------------------------------------------------- hashing, rng, samplers (tests/oracle_rand.rs)

/// CBD_eta samples `n` of the keys' bit stream over the SHAKE256 input `input`, from bit `bit_offset`
#[cfg(feature = "c-oracle")]
pub fn rand_cbd(input: &[u8], eta: u32, bit_offset: usize, n: usize) -> alloc::vec::Vec<i32> {
    use crate::rand::shake::{cbd, Stream};
    let mut s = Stream::new(&[input]);
    (0..bit_offset).for_each(|_| {
        s.bit();
    });
    (0..n).map(|_| cbd(eta, &mut s)).collect()
}

/// `pqz_shim_rng`: the `Rng (seed, dom)` stream read in pieces of `lens` bytes
#[cfg(feature = "c-oracle")]
pub fn rand_rng(seed: &[u8; 32], dom: u64, lens: &[u32]) -> Result<alloc::vec::Vec<u8>, crate::Error> {
    let mut out = alloc::vec![0u8; lens.iter().map(|&l| l as usize).sum()];
    let mut st = Rng::new(seed, dom);
    let mut o = &mut out[..];
    for &l in lens {
        let (a, b) = o.split_at_mut(l as usize);
        st.urandom(a)?;
        o = b;
    }
    Ok(out)
}

/// `pqz_shim_shake`: SHAKE128 (`which` = 128) or SHAKE256 of `input` (absorbed in pieces `alens`), squeezed in
/// pieces `slens`
#[cfg(feature = "c-oracle")]
pub fn rand_shake(which: u32, input: &[u8], alens: &[u32], slens: &[u32]) -> alloc::vec::Vec<u8> {
    use crate::rand::shake::{shake128, shake256};
    let mut parts = alloc::vec::Vec::new();
    let mut rest = input;
    for &l in alens {
        let (a, b) = rest.split_at(l as usize);
        parts.push(a);
        rest = b;
    }
    let mut out = alloc::vec![0u8; slens.iter().map(|&l| l as usize).sum()];
    let (mut x128, mut x256) = (shake128(&parts), shake256(&parts));
    let mut o = &mut out[..];
    for &l in slens {
        let (a, b) = o.split_at_mut(l as usize);
        if which == 128 {
            x128.squeeze(a);
        } else {
            x256.squeeze(a);
        }
        o = b;
    }
    out
}

/// `pqz_shim_grandom`: `_intvec_grandom` of `n` elements, then `polyvec_grandom` of 2 polys
#[cfg(feature = "c-oracle")]
pub fn rand_grandom(seed: &[u8; 32], dom: u32, log2o: u32, n: u32) -> Result<alloc::vec::Vec<i64>, crate::Error> {
    use crate::rand::grandom::{grandom, polyvec_grandom};
    let mut out = alloc::vec![0i64; n as usize];
    grandom(&mut out, log2o, seed, dom as u64)?;
    let mut pv = PolyVec::new(2)?;
    polyvec_grandom(&mut *pv, log2o, seed, dom)?;
    for p in pv.iter() {
        out.extend((0..D).map(|j| p.c(j).get_i64()));
    }
    Ok(out)
}

/// one-limb int vector from values
#[cfg(feature = "c-oracle")]
fn intvec_of(v: &[i64]) -> Result<crate::arith::int::IntVec, crate::Error> {
    let mut r = crate::arith::int::IntVec::new(v.len(), 1)?;
    r.set_i64(v);
    Ok(r)
}

/// `pqz_shim_rej`: `rej_standard` / `rej_bimodal` on the `Rng (seed, dom)` stream: (reject, the next 8 stream bytes)
#[cfg(feature = "c-oracle")]
pub fn rand_rej(bimodal: bool, seed: &[u8; 32], dom: u64, z: &[i64], v: &[i64], scm: &[u64; 3], s2: &[u64; 2])
                -> Result<(bool, [u8; 8]), crate::Error> {
    use crate::rand::rejection::{rej_bimodal, rej_standard};
    let (z, v) = (intvec_of(z)?, intvec_of(v)?);
    let (scm, s2) = (Int::from_limbs(scm, 0), Int::from_limbs(s2, 0));
    let mut st = Rng::new(seed, dom);
    let rej = if bimodal { rej_bimodal(&mut st, &z, &v, &scm, &s2)? } else { rej_standard(&mut st, &z, &v, &scm, &s2)? };
    Ok((rej, st.u64().to_le_bytes()))
}

/// `pqz_shim_rej_limbs`: [`rand_rej`] on elements of `nl` limbs then the sign ((nl + 1) words each)
#[cfg(feature = "c-oracle")]
#[allow(clippy::too_many_arguments)]
pub fn rand_rej_limbs(bimodal: bool, seed: &[u8; 32], dom: u64, z: &[u64], v: &[u64], nl: u32, scm: &[u64; 3],
                      s2: &[u64; 2]) -> Result<(bool, [u8; 8]), crate::Error> {
    use crate::rand::rejection::{rej_bimodal, rej_standard};
    let w = nl as usize + 1;
    let vec = |x: &[u64]| -> Result<crate::arith::int::IntVec, crate::Error> {
        let mut r = crate::arith::int::IntVec::new(x.len() / w, nl as usize)?;
        for (i, e) in x.chunks_exact(w).enumerate() {
            r.set_elem(i, &Int::from_limbs(&e[..nl as usize], e[nl as usize] & 1));
        }
        Ok(r)
    };
    let (z, v) = (vec(z)?, vec(v)?);
    let (scm, s2) = (Int::from_limbs(scm, 0), Int::from_limbs(s2, 0));
    let mut st = Rng::new(seed, dom);
    let rej = if bimodal { rej_bimodal(&mut st, &z, &v, &scm, &s2)? } else { rej_standard(&mut st, &z, &v, &scm, &s2)? };
    Ok((rej, st.u64().to_le_bytes()))
}

/// an int from 5 words: limbs[0..3), sign, nlimbs
#[cfg(feature = "c-oracle")]
fn int_of(w: &[u64; 5]) -> Int {
    Int::from_limbs(&w[..w[4] as usize], w[3] & 1)
}

#[cfg(feature = "c-oracle")]
fn dump_intvec(o: &mut alloc::vec::Vec<u64>, r: &crate::arith::int::IntVec) {
    for i in 0..r.len() {
        let e = r.get(i);
        o.extend_from_slice(e.limbs());
        o.push(e.neg);
    }
}

#[cfg(feature = "c-oracle")]
fn dump_coeffs(o: &mut alloc::vec::Vec<u64>, p: &Poly) {
    o.extend((0..D).map(|j| p.c(j).get_i64() as u64));
}

/// `pqz_shim_urandom`: `intvec_urandom` (n elements of nl limbs), then `polymat_urandom` (2 x 2)
#[cfg(feature = "c-oracle")]
pub fn rand_urandom(seed: &[u8; 32], dom: u32, n: u32, nl: u32, m: &[u64; 5], log2mod: u32)
                    -> Result<alloc::vec::Vec<u64>, crate::Error> {
    use crate::arith::polymat::PmRef;
    use crate::rand::urandom::{polymat_urandom, urandom};
    let m = int_of(m);
    let mut r = crate::arith::int::IntVec::new(n as usize, nl as usize)?;
    urandom(&mut r, &m, log2mod, seed, dom as u64)?;
    let mut o = alloc::vec::Vec::new();
    dump_intvec(&mut o, &r);
    let mut pm = PolyMat::new(2, 2)?;
    polymat_urandom(&mut pm, &m, log2mod, seed, dom)?;
    for i in 0..2 {
        for j in 0..2 {
            dump_coeffs(&mut o, pm.get(i, j));
        }
    }
    Ok(o)
}

/// `pqz_shim_urandom_bnd`: `intvec_urandom_bnd` (n elements of nl limbs), then for one-limb lo and hi
/// `polyvec_urandom_bnd` (2 polys)
#[cfg(feature = "c-oracle")]
pub fn rand_urandom_bnd(seed: &[u8; 32], dom: u32, n: u32, nl: u32, lo: &[u64; 5], hi: &[u64; 5])
                        -> Result<alloc::vec::Vec<u64>, crate::Error> {
    use crate::rand::urandom::{polyvec_urandom_bnd, urandom_bnd};
    let one_limb = lo[4] == 1 && hi[4] == 1;
    let (lo, hi) = (int_of(lo), int_of(hi));
    let mut r = crate::arith::int::IntVec::new(n as usize, nl as usize)?;
    urandom_bnd(&mut r, &lo, &hi, seed, dom as u64)?;
    let mut o = alloc::vec::Vec::new();
    dump_intvec(&mut o, &r);
    if one_limb {
        let mut pv = PolyVec::new(2)?;
        polyvec_urandom_bnd(&mut *pv, &lo, &hi, seed, dom)?;
        pv.iter().for_each(|p| dump_coeffs(&mut o, p));
    }
    Ok(o)
}

/// `pqz_shim_autostable`: `poly_urandom_autostable`
#[cfg(feature = "c-oracle")]
pub fn rand_autostable(seed: &[u8; 32], dom: u32, bnd: i64, log2: u32) -> Result<alloc::vec::Vec<u64>, crate::Error> {
    let p = Poly::urandom_autostable(bnd, log2, seed, dom as u64)?;
    let mut o = alloc::vec::Vec::new();
    dump_coeffs(&mut o, &p);
    Ok(o)
}

/// every relation's parameters in `pqz_shim_params`'s order (tests/oracle_shim.c's `P`)
#[cfg(feature = "c-oracle")]
fn rels() -> alloc::vec::Vec<(&'static str, &'static crate::params::Tbox)> {
    // the relation table without the R_TXM M = 1 entries, which reuse R_TX's / R_TX0's parameters
    crate::rel::RELS.iter().filter(|r| r.op != crate::OP_TRANSFER_MULTI || r.legs > 1).map(|r| (r.name, r.p)).collect()
}

/// Every relation's parameters (src/params, generated from pqzl/params/pqz_*_params.h) as one word stream each, in
/// `pqz_shim_params`'s order and layout (tests/oracle_shim.c): the whole `lnp_tbox_params_t`, pointers followed
#[cfg(feature = "c-oracle")]
pub fn params_words() -> alloc::vec::Vec<(&'static str, alloc::vec::Vec<u64>)> {
    use crate::params::*;
    fn int(o: &mut alloc::vec::Vec<u64>, a: &Int) {
        o.extend_from_slice(&[a.n as u64, a.neg]);
        o.extend_from_slice(&a.l[..a.n]);
    }
    fn abdlop(o: &mut alloc::vec::Vec<u64>, a: &Abdlop) {
        let (r, d) = (a.ring, a.dcompress);
        int(o, &r.q);
        o.extend_from_slice(&[r.d as u64, r.log2q as u64, r.log2d as u64, 0, r.nmoduli as u64]); // 0: moduli NULL
        int(o, &r.pmodq);
        r.ppmodq.iter().for_each(|x| int(o, x));
        int(o, &r.inv2);
        for x in [&d.q, &d.qminus1, &d.m, &d.mby2, &d.gamma, &d.gammaby2, &d.pow2d, &d.pow2dby2] {
            int(o, x);
        }
        o.extend_from_slice(&[d.d as u64, d.m_odd as u64, d.log2m as u64]);
        o.extend_from_slice(&[a.m1, a.m2, a.l, a.lext, a.kmsis].map(u64::from));
        int(o, &a.bsqr);
        o.extend_from_slice(&[a.nu as u64, a.omega as u64, a.log2omega as u64, a.eta, a.rej1 as u64, a.log2stdev1 as u64]);
        int(o, &a.scm1);
        int(o, &a.stdev1sqr);
        o.extend_from_slice(&[a.rej2 as u64, a.log2stdev2 as u64]);
        int(o, &a.scm2);
        int(o, &a.stdev2sqr);
    }
    rels()
        .iter()
        .map(|&(name, p)| {
            let mut o = alloc::vec::Vec::new();
            abdlop(&mut o, p.tbox);
            abdlop(&mut o, p.quad_eval.quad_eval);
            abdlop(&mut o, p.quad_eval.quad_many);
            o.extend_from_slice(&[p.quad_eval.lambda, p.nbin, p.z].map(u64::from));
            o.extend(p.n.iter().map(|&x| x as u64));
            o.extend_from_slice(&[p.nprime as u64, p.nex as u64, p.rej3 as u64, p.log2stdev3 as u64]);
            int(&mut o, &p.scm3);
            int(&mut o, &p.stdev3sqr);
            o.extend_from_slice(&[p.rej4 as u64, p.log2stdev4 as u64]);
            for x in [&p.scm4, &p.stdev4sqr, &p.bz3sqr, &p.bz4] {
                int(&mut o, x);
            }
            p.l2bsqr.iter().for_each(|x| int(&mut o, x));
            int(&mut o, &p.inv4);
            o.push(p.prooflen);
            (name, o)
        })
        .collect()
}

/// relation i's (`params_words` order) quad_many dcompress `(gamma, m)`; `None` past the last relation
#[cfg(feature = "c-oracle")]
pub fn dcomp_gamma_m(i: usize) -> Option<(i64, i64)> {
    let d = rels().get(i)?.1.quad_eval.quad_many.dcompress;
    Some((d.gamma.get_i64(), d.m.get_i64()))
}

/// `pqz_shim_ghint`'s output for relation i: `Poly::use_ghint (y, r)` and `Poly::make_ghint (z, r)` of `inp` = y, z,
/// r; `None` past the last relation
#[cfg(feature = "c-oracle")]
pub fn ghint(i: usize, inp: &[i64; 192]) -> Option<alloc::vec::Vec<u64>> {
    let d = rels().get(i)?.1.quad_eval.quad_many.dcompress;
    let poly = |k: usize| {
        let mut p = Poly::ZERO;
        p.set_i64(&inp[64 * k..64 * k + 64]);
        p
    };
    let (mut y, mut z, mut r) = (poly(0), poly(1), poly(2));
    let mut o = alloc::vec::Vec::new();
    dump(&mut o, &Poly::use_ghint(&mut y, &mut r, d));
    dump(&mut o, &Poly::make_ghint(&mut z, &mut r, d));
    Some(o)
}

/// A random proof of relation `code`'s shape, as long as an honest one (tB, h uniform below q, tA1 below
/// 2^(log2q - D), c in [-8, 8], one hint in 8 in [-3, 3] and the rest 0, the Gaussian parts in [-2^(l+1), 2^(l+1))
/// for stdev 1.55 * 2^l), encoded by the codec: decodable input for the relations without a frozen vector (the
/// oversize shapes); `None` for an unknown code or an encoding over MAX_PROOF.
#[cfg(feature = "c-oracle")]
pub fn synthetic_proof(code: u8, seed: u64) -> Option<alloc::vec::Vec<u8>> {
    use crate::coder::{encode_proof, ProofParts};
    use crate::rel::tbox_by_code;
    let p = tbox_by_code(code)?;
    let mut f = ProofParts::new(p).ok()?;
    let mut s = seed | 1;
    let mut rnd = move || {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        s.wrapping_mul(2_685_821_657_736_338_717)
    };
    let mt = p.tbox.ring.log2q - p.quad_eval.quad_many.dcompress.d;
    let mut fill = |v: &mut [Poly], g: &mut dyn FnMut(u64) -> i64| {
        for x in v {
            x.set_i64(&core::array::from_fn::<i64, D, _>(|_| g(rnd())));
        }
    };
    fill(&mut f.t_b, &mut |r| (r % Q) as i64);
    fill(&mut f.h, &mut |r| (r % Q) as i64);
    fill(&mut f.t_a1, &mut |r| (r >> (64 - mt)) as i64);
    fill(core::slice::from_mut(&mut f.c), &mut |r| (r % 17) as i64 - 8);
    fill(&mut f.hint, &mut |r| if r % 8 == 0 { ((r >> 3) % 7) as i64 - 3 } else { 0 });
    let qm = p.quad_eval.quad_many;
    for (v, l) in [(&mut f.z1, qm.log2stdev1), (&mut f.z21, qm.log2stdev2), (&mut f.z3, p.log2stdev3), (&mut f.z4, p.log2stdev4)] {
        fill(v, &mut |r| (r % (1 << (l + 2))) as i64 - (1 << (l + 1)));
    }
    encode_proof(&f, crate::MAX_PROOF).ok()
}

/// Where relation `code`'s challenge c sits in its proof encoding: (bit offset of coefficient 0, bits per
/// coefficient, omega; the codec refuses a value >= 2 omega + 1). `None` for an unknown code.
pub fn proof_c_field(code: u8) -> Option<(usize, u32, i64)> {
    let p = crate::rel::tbox_by_code(code)?;
    let (tb, qm) = (p.tbox, p.quad_eval.quad_many);
    let log2q = tb.ring.log2q as usize;
    let fixed = (tb.l + tb.lext + p.quad_eval.lambda / 2) as usize * log2q + tb.kmsis as usize * (log2q - qm.dcompress.d as usize);
    Some((64 * fixed, qm.log2omega, qm.omega))
}
