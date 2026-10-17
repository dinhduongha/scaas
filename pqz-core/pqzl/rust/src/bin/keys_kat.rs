//! The keys KAT of `pqzl/test/pqz_keys_kat.c` from the Rust port: the same JSON lines, so the same independent check
//! serves both:
//!   cargo run --release --bin keys_kat 1000 > k.jsonl
//!   python3 -I smartcontracts/vectors/pqz/pqz_kat.py --c-keys k.jsonl
//!
//! In C's section numbers and order: 1. SHAKE256 on 10 inputs, absorbed and squeezed in two parts; 2. KeyGen on 20
//! seeds, Enc of two values to recipients i and i + 1, Dec by both, the R_TXM group seeds; 4. the resample path and
//! the counter-64 error with lowered thresholds (`testkit::*_lowered`); 3. the Dec(Enc(m)) = m round trip on n seeds
//! and the non-canonical inputs. C's section 5 (every keys entry point before `pqz_init` returns PQZ_ERR_INTERNAL)
//! has no counterpart: there is no init here, so its `before_init_rejected` line is not printed. Where C prints a
//! buffer an error left alone, the same buffer is kept here (for section 4's KeyGen `pk`, an uninitialised stack
//! array in C, that is the previous iteration's `pk`, as the compiled C prints; the check ignores it). Apart from the
//! `before_init_rejected` line, the output equals the C binary's byte for byte.
use pqzl::testkit::{enc_seed_lowered, keygen_lowered};
use pqzl::{dec, enc_group_seed, enc_seed, keygen, Error, CT_BYTES, POLYVEC_BYTES, V_BYTES};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use std::fmt::Write;

const NK: usize = 20;
const B_FRESH: i64 = 11_872;

fn hex(p: &[u8]) -> String {
    p.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// SHAKE256 of the parts, `out.len()` bytes squeezed in two pieces split at `cut`
fn shake256(parts: &[&[u8]], out: &mut [u8], cut: usize) {
    let mut h = Shake256::default();
    parts.iter().for_each(|p| h.update(p));
    let mut r = h.finalize_xof();
    let (a, b) = out.split_at_mut(cut);
    r.read(a);
    r.read(b);
}

fn sh256(p: &[u8]) -> String {
    let mut h = [0u8; 32];
    shake256(&[p], &mut h, 0);
    hex(&h)
}

fn digits(x: u64) -> [u8; 16] {
    core::array::from_fn(|i| ((x >> (4 * i)) & 15) as u8)
}

/// splitmix64
fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

fn ints(v: &[i64]) -> String {
    v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", ")
}

/// the C return code
fn rc<T>(r: &Result<T, Error>) -> i32 {
    match r {
        Ok(_) => 0,
        Err(Error::Internal) => 1,
        Err(Error::Memory) => 2,
        Err(Error::Input) => 3,
        Err(Error::Reject) => 4,
    }
}

fn main() {
    let nrt: usize = std::env::args().nth(1).map_or(1000, |a| a.parse().expect("n_roundtrip"));
    let mut fails = 0;
    // C's static buffers: an error leaves them as they were
    let mut u = vec![0u8; POLYVEC_BYTES];
    let mut vs = [[0u8; V_BYTES]; 2];
    let mut ct = vec![0u8; CT_BYTES];
    let mut m = [[0u8; 16]; 2];
    let mut se = [0u8; 32];
    let keep = |c: &pqzl::Enc, u: &mut Vec<u8>, vs: &mut [[u8; V_BYTES]; 2]| {
        u.copy_from_slice(&c.u[..]);
        vs[..c.vs.len()].copy_from_slice(&c.vs);
    };
    let ctv = |ct: &mut Vec<u8>, u: &[u8], v: &[u8]| {
        ct[..POLYVEC_BYTES].copy_from_slice(u);
        ct[POLYVEC_BYTES..].copy_from_slice(v);
    };
    let as_ct = |ct: &[u8]| -> Box<[u8; CT_BYTES]> { ct.to_vec().into_boxed_slice().try_into().unwrap() };

    // 1. SHAKE256
    const IL: [usize; 10] = [0, 1, 31, 135, 136, 137, 271, 272, 1000, 4999];
    const OL: [usize; 10] = [32, 64, 135, 136, 137, 272, 300, 500, 32, 1000];
    for c in 0..10 {
        let inp: Vec<u8> = (0..IL[c]).map(|i| (i * 7 + c) as u8).collect();
        let (mut out, mut out2) = (vec![0u8; OL[c]], [0u8; 32]);
        shake256(&[&inp[..IL[c] / 3], &inp[IL[c] / 3..]], &mut out, OL[c] / 2);
        shake256(&[&inp], &mut out2, 0); // one-shot: the first 32 bytes must agree
        fails += (out[..32] != out2) as i32;
        println!("{{\"shake256\": {{\"in\": \"{}\", \"outlen\": {}, \"out\": \"{}\"}}}}", hex(&inp), OL[c], hex(&out));
    }

    // 2. KeyGen, Enc, Dec on 20 seeds
    let seed: Vec<[u8; 32]> = (0..NK).map(|i| core::array::from_fn(|j| (31 * i + j) as u8)).collect();
    let mut keys = Vec::new();
    for sd in &seed {
        let k = keygen(sd);
        fails += (rc(&k) != 0) as i32;
        let k = k.expect("keygen");
        let (sd, ctr, h) = (hex(sd), k.ctr, sh256(&k.pk[..]));
        println!("{{\"keygen\": {{\"seed\": \"{sd}\", \"ctr\": {ctr}, \"rc\": 0, \"pk_shake256\": \"{h}\"}}}}");
        keys.push(k);
    }
    for i in 0..NK {
        let t = (i + 1) % NK;
        let v = [mix(i as u64), if i == 0 { !0 } else { mix(i as u64) >> (i % 64) }];
        se = core::array::from_fn(|j| (17 * i + j + 1) as u8);
        m = [digits(v[0]), digits(v[1])];
        let c = enc_seed(&[&*keys[i].pk, &*keys[t].pk], &m, &se);
        let mut r = rc(&c);
        let ctr = c.as_ref().map_or(0, |c| c.ctr);
        if let Ok(c) = &c {
            keep(c, &mut u, &mut vs);
        }
        let mut d = Vec::new();
        for j in 0..2 {
            ctv(&mut ct, &u, &vs[j]);
            let x = dec(&keys[if j == 1 { t } else { i }].s, &as_ct(&ct));
            r |= rc(&x);
            let (mm, nn) = x.unwrap_or(([0; 16], [0; 16]));
            fails += (0..16).filter(|&k| mm[k] != m[j][k] as i64).count() as i32;
            d.push(format!("{{\"M\": [{}], \"noise\": [{}]}}", ints(&mm), ints(&nn)));
        }
        fails += (r != 0) as i32;
        let (se, r0, r1, uh, v0, v1, d) =
            (hex(&se), hex(&seed[i]), hex(&seed[t]), sh256(&u), hex(&vs[0]), hex(&vs[1]), d.join(", "));
        println!(
            "{{\"enc\": {{\"seed_enc\": \"{se}\", \"recipients\": [\"{r0}\", \"{r1}\"], \"values\": [{}, {}], \"ctr\": \
             {ctr}, \"rc\": {r}, \"u_shake256\": \"{uh}\", \"v\": [\"{v0}\", \"{v1}\"], \"dec\": [{d}]}}}}",
            v[0], v[1]
        );
    }
    // 2b. R_TXM group seeds: seed_enc_i (as in 2), g = 0 .. 3 (g = 0 is seed_enc itself)
    for i in 0..4 {
        for g in 0..4u32 {
            se = core::array::from_fn(|j| (17 * i + j + 1) as u8);
            let gs = enc_group_seed(&se, g);
            fails += (g == 0 && gs != se) as i32;
            let (se, gs) = (hex(&se), hex(&gs));
            println!("{{\"enc_group_seed\": {{\"seed_enc\": \"{se}\", \"g\": {g}, \"out\": \"{gs}\"}}}}");
        }
    }

    // 4. lowered thresholds: KeyGen ||s|| <= 32, ||e|| <= 143 (each passes about half the time), Enc also ||e2_j|| <=
    // 12; then a threshold no sample meets (0): the counter-64 error
    const LS: [[i64; 4]; 6] = [[32, 143, 64, 0], [32, 143, 64, 1], [32, 143, 64, 2], [32, 143, 12, 3], [0, 164, 64, 4],
                               [36, 164, 0, 5]];
    let (mut resampled_k, mut resampled_e, mut err64) = (0, 0, 0);
    let mut kp = vec![0u8; POLYVEC_BYTES];
    for (c, l) in LS.iter().enumerate() {
        let sd = &seed[l[3] as usize];
        let k = keygen_lowered(sd, l[0], l[1]);
        let (bs, be, b2) = (if l[0] != 0 { l[0] } else { 36 }, l[1], l[2]);
        se = core::array::from_fn(|j| (101 * c + j) as u8);
        let mv = [mix(c as u64), mix(c as u64 + 50)];
        m = [digits(mv[0]), digits(mv[1])];
        let e = enc_seed_lowered(&[&*keys[0].pk, &*keys[1].pk], &m, &se, bs, be, b2);
        let (rk, re) = (rc(&k), rc(&e));
        let ck = k.as_ref().map_or(-1, |k| k.ctr as i64);
        let ce = e.as_ref().map_or(-1, |e| e.ctr as i64);
        resampled_k += (rk == 0 && ck >= 1) as i32;
        resampled_e += (re == 0 && ce >= 1) as i32;
        err64 += (c == 4 && rk == 4) as i32 + (c == 5 && re == 4) as i32;
        if let Ok(e) = &e {
            keep(e, &mut u, &mut vs);
        }
        if let Ok(k) = &k {
            kp.copy_from_slice(&k.pk[..]);
        }
        let kh = sh256(&kp);
        println!("{{\"keygen_lowered\": {{\"seed\": \"{}\", \"bs\": {}, \"be\": {}, \"ctr\": {ck}, \"rc\": {rk}, \
                  \"pk_shake256\": \"{kh}\"}}}}", hex(sd), l[0], l[1]);
        let (se, r0, r1, uh, v0, v1) = (hex(&se), hex(&seed[0]), hex(&seed[1]), sh256(&u), hex(&vs[0]), hex(&vs[1]));
        println!(
            "{{\"enc_lowered\": {{\"seed_enc\": \"{se}\", \"bs\": {bs}, \"be\": {be}, \"b2\": {b2}, \"recipients\": \
             [\"{r0}\", \"{r1}\"], \"values\": [{}, {}], \"ctr\": {ce}, \"rc\": {re}, \"u_shake256\": \"{uh}\", \"v\": \
             [\"{v0}\", \"{v1}\"]}}}}",
            mv[0], mv[1]
        );
    }
    fails += (resampled_k == 0 || resampled_e == 0 || err64 != 2) as i32;
    println!("{{\"lowered\": {{\"keygen_resampled\": {resampled_k}, \"enc_resampled\": {resampled_e}, \
              \"ctr64_errors\": {err64}}}}}");

    // 3. round trip; non-canonical inputs rejected
    let (mut maxn, mut maxctr) = (0i64, 0u32);
    let mut s0 = keys[0].s.clone(); // C's s[0]: each round trip's key overwrites it
    for i in 0..nrt {
        let mut sd = [0u8; 32];
        for j in 0..4 {
            let x = mix((i * 4 + j + 1000) as u64);
            sd[8 * j..8 * j + 8].copy_from_slice(&x.to_le_bytes());
            se[8 * j..8 * j + 8].copy_from_slice(&mix(x).to_le_bytes());
        }
        let (mut c1, mut c2) = (0, 0);
        let mut bad = false;
        m[0] = digits(mix(i as u64));
        match keygen(&sd) {
            Ok(k) => {
                (c1, s0) = (k.ctr, k.s);
                match enc_seed(&[&*k.pk], &m[..1], &se) {
                    Ok(c) => {
                        c2 = c.ctr;
                        ctv(&mut ct, &c.u[..], &c.vs[0]);
                        match dec(&s0, &as_ct(&ct)) {
                            Ok((mm, nn)) => {
                                for k in 0..16 {
                                    bad |= mm[k] != m[0][k] as i64 || nn[k] > B_FRESH || nn[k] < -B_FRESH;
                                    maxn = maxn.max(nn[k].abs());
                                }
                            }
                            Err(_) => bad = true,
                        }
                    }
                    Err(_) => bad = true,
                }
            }
            Err(_) => bad = true,
        }
        maxctr = if c1 > maxctr { c1 } else if c2 > maxctr { c2 } else { maxctr };
        fails += bad as i32;
    }
    ct[POLYVEC_BYTES - 8..POLYVEC_BYTES].fill(0xff); // a u coefficient >= q
    let mut nc = dec(&s0, &as_ct(&ct)).is_err() as i32;
    let mut pkx = keys[0].pk.clone();
    pkx[..8].fill(0xff); // a pk coefficient >= q
    nc += enc_seed(&[&*pkx], &m[..1], &se).is_err() as i32;
    m[0][3] = 16; // a digit >= 16
    nc += enc_seed(&[&*keys[1].pk], &m[..1], &se).is_err() as i32;
    fails += (nc != 3) as i32;
    println!("{{\"roundtrip\": {nrt}, \"max_abs_noise\": {maxn}, \"bound\": {B_FRESH}, \"max_ctr\": {maxctr}, \
              \"noncanonical_rejected\": {nc}, \"fails\": {fails}}}");
    std::process::exit((fails != 0) as i32);
}
