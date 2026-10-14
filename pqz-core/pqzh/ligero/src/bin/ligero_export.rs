//! Fixtures for the EVM verifier (smartcontracts/evm/test/pqzh/ligero/): the same bytes the Rust verifier takes.
//!   ligero_export <dir> [preset ...]      presets: proven (radix 431), conj (radix 431), johnson, conj-n<N>-k<K> (any n, k)
//! Writes a.bin (A as 32 x 32 x 64 canonical F_q, 6 bytes big-endian, order (i, j, coefficient)), and per relation
//! and preset: <rel>-<preset>.stmt / .proof / .other (a valid proof of the statement with byte 64 flipped, a hashed-only header byte) / .params
//! (n, k, l, t, grinding bits: five 32-byte big-endian words). neg-<case>.stmt / .proof: invalid witnesses proved without the honest prover's checks
//! (conjectured preset), each must be rejected. A JSON line per file on stdout.

use pqzh_ligero::client::{Tweak, digits, setup, setup_with};
use pqzh_ligero::ring::{Q, a_matrix};
use pqzh_ligero::{OP_REGISTER, OP_TRANSFER, Params, prove, prove_unchecked, verify};

fn put(dir: &str, name: &str, b: &[u8]) {
    std::fs::write(format!("{dir}/{name}"), b).unwrap();
    println!("{{\"file\": \"{name}\", \"bytes\": {}}}", b.len());
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let dir = a.get(1).expect("usage: ligero_export <dir> [preset ...]").clone();
    std::fs::create_dir_all(&dir).unwrap();
    let presets: Vec<String> = if a.len() > 2 { a[2..].to_vec() } else { vec!["proven".into(), "conj".into()] };

    let mut am = Vec::with_capacity(32 * 32 * 64 * 6);
    for p in a_matrix() {
        for &c in p {
            am.extend_from_slice(&(c.rem_euclid(Q as i64) as u64).to_be_bytes()[2..]);
        }
    }
    put(&dir, "a.bin", &am);

    let s = setup();
    for pre in &presets {
        for (op, rel, st, w) in [(OP_REGISTER, "reg", &s.reg_stmt, &s.reg_wit), (OP_TRANSFER, "tx", &s.tx_stmt, &s.tx_wit)] {
            let p = match pre.as_str() {
                "proven" => Params::preset(op, true, true),
                "conj" => Params::preset(op, false, true),
                "johnson" => Params::johnson_preset(),
                x => {
                    let nk: Vec<usize> = x.trim_start_matches("conj-n").split("-k").map(|v| v.parse().unwrap()).collect();
                    Params::new(nk[0], nk[1], false)
                }
            };
            let pf = prove(op, st, w, [1; 32], &p).unwrap();
            assert!(verify(op, st, &pf, &p));
            let mut st2 = st.clone();
            st2[64] ^= 0x80;
            let other = prove(op, &st2, w, [9; 32], &p).unwrap();
            put(&dir, &format!("{rel}-{pre}.stmt"), st);
            put(&dir, &format!("{rel}-{pre}.proof"), &pf);
            put(&dir, &format!("{rel}-{pre}.other"), &other);
            // n, k, l, t, grinding bits as five big-endian 32-byte words (abi.decode in the forge test)
            let mut pw = Vec::new();
            for x in [p.n, p.k, p.ell, p.t, p.pow_bits as usize] {
                pw.extend_from_slice(&[0u8; 24]);
                pw.extend_from_slice(&(x as u64).to_be_bytes());
            }
            put(&dir, &format!("{rel}-{pre}.params"), &pw);
        }
    }

    // invalid witnesses (pqzh/tests/attacks.rs and ligero tests/attacks.rs), conjectured preset
    let mut sv = vec![0i64; 2048];
    for k in 0..1300 {
        sv[k] = if k % 2 == 0 { 1 } else { -1 };
    }
    let norm = setup_with(&Tweak { s_f: Some(sv), ..Default::default() });
    let mut sv = vec![0i64; 2048];
    sv[5] = 100;
    let coef = setup_with(&Tweak { s_f: Some(sv), ..Default::default() });
    let mut d = digits(123_456);
    d[0] += 16;
    d[1] -= 1;
    let digit = setup_with(&Tweak { d: Some(d), ..Default::default() });
    let mut e = vec![0i64; 16];
    e[0] = 65;
    let e2 = setup_with(&Tweak { e2_t: Some(e), ..Default::default() });
    let mut over = s.tx_wit.clone();
    for i in 0..16 {
        over[12400 + i] = 15;
    }
    let mut ring = s.tx_wit.clone();
    ring[8192] = ring[8192].wrapping_add(1);
    let cases: Vec<(&str, u8, &[u8], &[u8])> = vec![
        ("reg-norm", OP_REGISTER, &norm.reg_stmt, &norm.reg_wit),
        ("reg-coef", OP_REGISTER, &coef.reg_stmt, &coef.reg_wit),
        ("tx-norm", OP_TRANSFER, &norm.tx_stmt, &norm.tx_wit),
        ("tx-digit", OP_TRANSFER, &digit.tx_stmt, &digit.tx_wit),
        ("tx-e2", OP_TRANSFER, &e2.tx_stmt, &e2.tx_wit),
        ("tx-overspend", OP_TRANSFER, &s.tx_stmt, &over),
        ("tx-ring", OP_TRANSFER, &s.tx_stmt, &ring),
    ];
    for (name, op, st, w) in cases {
        let p = Params::preset(op, false, true);
        let pf = prove_unchecked(op, st, w, [5; 32], &p).unwrap();
        assert!(!verify(op, st, &pf, &p), "{name} accepted natively");
        put(&dir, &format!("neg-{name}.stmt"), st);
        put(&dir, &format!("neg-{name}.proof"), &pf);
    }
}
