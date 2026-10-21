//! The proof codec against the C core (features `c-oracle`, `test-hooks`): `pqz_test_mutate` (decode, change one
//! field, re-encode) = `test_mutate` on the frozen proofs of every relation code (Review Focus 1: Rust rejects
//! exactly where C rejects, and re-encodes to the same bytes where C accepts), malformed encodings, and the hint
//! functions of `dcompress.c` (`use_ghint` / `make_ghint`) through `tests/oracle_shim.c`.
use pqzl::c_oracle::{c_ghint, c_test_mutate};
use pqzl::test_mutate;
use pqzl::testkit::{dcomp_gamma_m, ghint, synthetic_proof};
use serde_json::Value;
use std::path::PathBuf;

const Q: u64 = pqzl::Q;
const MAX_PROOF: usize = pqzl::MAX_PROOF;

/// xorshift64*
struct Rnd(u64);

impl Rnd {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(2_685_821_657_736_338_717)
    }

    /// uniform in [lo, hi]
    fn range(&mut self, lo: i64, hi: i64) -> i64 {
        lo + (self.next() % (hi - lo + 1) as u64) as i64
    }
}

fn hex(s: &Value) -> Vec<u8> {
    let s = s.as_str().expect("hex string").as_bytes();
    s.chunks(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).expect("hex")).collect()
}

/// the relation code of a proof_pqzl.json row (pqz_int.h: an op, PQZ_REL_TX0, PQZ_REL_TXM (log2 M, auditorOn))
fn rel_code(r: &Value) -> u8 {
    match r["form"].as_str().unwrap() {
        "TRANSFER0" => 0x81,
        "TRANSFER-MULTI" => {
            let case = r["statement"]["case"].as_str().unwrap(); // M<m>-<on|off>[-...]
            let mut it = case[1..].split('-');
            let m: u8 = it.next().unwrap().parse().unwrap();
            0x70 | ((it.next() == Some("on")) as u8) << 3 | m.trailing_zeros() as u8
        }
        _ => r["op"].as_u64().unwrap() as u8,
    }
}

/// one frozen proof per relation code (the first row of each), in file order
fn proofs() -> Vec<(u8, Vec<u8>)> {
    // the vectors of this build's parameter set (v3 at the canonical path, another set below it)
    let b = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../smartcontracts/vectors/pqz");
    let p = if pqzl::SET == "n2048-kmax1024" { b } else { b.join(pqzl::SET) }.join("proof_pqzl.json");
    let j: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let mut out: Vec<(u8, Vec<u8>)> = Vec::new();
    for r in j["rows"].as_array().unwrap() {
        let code = rel_code(r);
        if !out.iter().any(|(c, _)| *c == code) {
            out.push((code, hex(&r["proof"])));
        }
    }
    let mut codes: Vec<u8> = out.iter().map(|(c, _)| *c).collect();
    codes.sort();
    assert_eq!(codes, [1, 2, 3, 4, 5, 0x70, 0x71, 0x72, 0x73, 0x78, 0x79, 0x7a, 0x7b, 0x81], "six forms + eight R_TXM");
    if cfg!(feature = "oversize") {
        for code in [0x74, 0x7c] {
            out.push((code, synthetic_proof(code, 1).expect("synthetic proof")));
        }
    }
    out
}

fn len(x: &Option<Vec<u8>>) -> Option<usize> {
    x.as_ref().map(Vec::len)
}

/// kinds 0..15 x 200 (r1, r2) seeds x every relation code: Rust = C. Within a seed the kinds chain (kind k mutates
/// kind k - 1's output when there is one), so the decoders also meet what the mutations produce (long hints, large z).
#[test]
fn test_mutate_eq_c() {
    let mut g = Rnd(0x5EED_C0DE);
    for (code, proof) in proofs() {
        let mut some = [0u32; 16];
        for s in 0..200 {
            let mut cur = proof.clone();
            for kind in 0..16u32 {
                let (r1, r2) = (g.next(), g.next());
                let r = test_mutate(code, &cur, kind, r1, r2).expect("Rust test_mutate error");
                let c = c_test_mutate(code, &cur, kind, r1, r2);
                assert!(r == c, "code {code:#x} seed {s} kind {kind} (r1 {r1:#x} r2 {r2:#x}): Rust {:?} C {:?}", len(&r), len(&c));
                if let Some(o) = r {
                    some[kind as usize] += 1;
                    cur = o;
                }
            }
        }
        println!("code {code:#04x}: re-encoded per kind {some:?} of 200");
        assert!(some.iter().all(|&n| n > 0), "code {code:#x}: a kind never re-encodes {some:?}");
    }
}

/// re-encode only (kind 14) of malformed encodings: every one Rust = C, and the ones C must refuse are refused
#[test]
fn malformed_eq_c() {
    let all = proofs();
    let mut g = Rnd(0xBAD_C0DE);
    for (code, proof) in &all {
        let n = proof.len();
        let mut v: Vec<(String, Vec<u8>, bool)> = Vec::new(); // (name, bytes, C must refuse)
        v.push(("honest".into(), proof.clone(), false));
        for k in [0, 1, n / 2, n - 1] {
            v.push((format!("truncated to {k}"), proof[..k].to_vec(), true));
        }
        for tail in [0u8, 1, 0x80] {
            v.push((format!("trailing byte {tail:#x}"), [&proof[..], &[tail]].concat(), true));
        }
        let mut x = proof.clone();
        x[n - 1] = 0; // the pad one gone
        v.push(("no pad".into(), x, true));
        let mut x = proof.clone();
        x[n - 1] |= 0x80; // a one after the pad
        let must = x[n - 1] != proof[n - 1];
        v.push(("bit after pad".into(), x, must));
        // tB[0][0]: the first LOG2Q bits, LSB first (the coder's width of a value mod q; v3: 42)
        let l = 64 - (Q - 1).leading_zeros() as usize;
        let put = |x: &mut [u8], v: u64| {
            for b in 0..l {
                x[b / 8] = (x[b / 8] & !(1 << (b % 8))) | ((((v >> b) & 1) as u8) << (b % 8));
            }
        };
        let mut x = proof.clone();
        put(&mut x, (1 << l) - 1); // 2^LOG2Q - 1 >= q
        v.push(("tB coefficient >= q".into(), x, true));
        let mut x = proof.clone();
        put(&mut x, Q); // q exactly
        v.push(("tB coefficient = q".into(), x, true));
        let mut x = proof.clone();
        x.resize(MAX_PROOF + 1, 0);
        v.push(("over MAX_PROOF".into(), x, true));
        for t in 0..64 {
            let mut x = proof.clone();
            let b = (g.next() % (8 * n as u64)) as usize;
            x[b / 8] ^= 1 << (b % 8);
            v.push((format!("bit flip {t} at {b}"), x, false));
        }
        for (other, p) in &all {
            if other != code {
                v.push((format!("proof of {other:#x}"), p.clone(), false));
            }
        }
        let (mut flips, mut foreign) = (0, 0); // refused
        for (name, x, must) in &v {
            let r = test_mutate(*code, x, 99, 0, 0).expect("Rust test_mutate error");
            let c = c_test_mutate(*code, x, 99, 0, 0);
            assert!(r == c, "code {code:#x} {name}: Rust {:?} C {:?}", len(&r), len(&c));
            assert!(!must || c.is_none(), "code {code:#x} {name}: C accepts");
            flips += (c.is_none() && name.starts_with("bit flip")) as u32;
            foreign += (c.is_none() && name.starts_with("proof of")) as u32;
            if name == "honest" {
                assert_eq!(c.as_ref(), Some(proof), "code {code:#x}: C does not re-encode its own proof");
            }
        }
        println!("code {code:#04x}: refused {flips} of 64 bit flips, {foreign} of {} foreign proofs", all.len() - 1);
    }
    assert_eq!(test_mutate(0x42, &all[0].1, 99, 0, 0), Ok(None), "unknown relation code");
    assert_eq!(c_test_mutate(0x42, &all[0].1, 99, 0, 0), None);
}

/// `use_ghint (y, r)` and `make_ghint (z, r)` of every relation's dcompress: 2,000 inputs each in their domains
/// (r in [-(q-1)/2, (q-1)/2], every 4th poly in (-q, q) for use_ghint; y in (-m/2, m/2]; z in [-gamma/2, gamma/2]) with
/// the edges (multiples of gamma +-1, +-(q-1)/2, +-gamma/2, the r1 = (q-1)/gamma wrap), Rust = C word for word
#[test]
fn ghint_eq_c() {
    let h = ((Q - 1) / 2) as i64;
    let mut g = Rnd(0x6417_0001);
    let mut i = 0;
    while let Some((gamma, m)) = dcomp_gamma_m(i) {
        for t in 0..2000 {
            let mut inp = [0i64; 192];
            for k in 0..64 {
                inp[k] = g.range(-(m - 1) / 2, m / 2);
                inp[64 + k] = g.range(-gamma / 2, gamma / 2);
                inp[128 + k] = match (t + k) % 8 {
                    0 if t % 4 == 0 => g.range(-(Q as i64 - 1), Q as i64 - 1),
                    1 => g.range(-(m - 1), m - 1) * gamma + g.range(-1, 1),
                    2 => [h, -h, gamma / 2, -gamma / 2, 0, h - gamma / 2][g.range(0, 5) as usize],
                    _ => g.range(-h, h),
                };
            }
            if t % 16 == 0 {
                inp[64..128].fill([gamma / 2, -gamma / 2][t / 16 % 2]);
            }
            assert_eq!(ghint(i, &inp), c_ghint(i as u32, &inp), "relation {i} input {t}");
        }
        i += 1;
    }
    assert_eq!(i, if cfg!(feature = "oversize") { 14 } else { 12 });
    assert_eq!(c_ghint(i as u32, &[0; 192]), None, "C has more relations");
}
