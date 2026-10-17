//! The prover against the C core (feature `c-oracle`): `Ctx::prove` = `pqz_prove` (the same bytes, or the same error
//! code) per relation code on the honest witness, a short one, and witnesses with one byte changed (at 0, 2048 and
//! the last byte): inconsistent witnesses reach every refusal the prover has (the parsers' Input, the norm-bound
//! Input, the invariant checks' Internal) or give a proof C gives too (a broken R_q-linear row is not checked by
//! either prover). Rust proves on a second thread while C proves on its own.
use pqzl::c_oracle::c_prove;
use pqzl::{Ctx, Error};

mod common;

fn both(ctx: &mut Ctx, r: &common::Row, wit: &[u8]) -> (Result<Vec<u8>, Error>, Result<Vec<u8>, Error>) {
    std::thread::scope(|s| {
        let rust = s.spawn(|| ctx.prove(r.op, &r.stmt, wit, &r.rnd32));
        let c = c_prove(r.op, &r.stmt, wit, &r.rnd32);
        (rust.join().unwrap(), c)
    })
}

#[test]
fn prove_eq_c() {
    let mut ctx = Ctx::new();
    let mut seen = Vec::new();
    let mut outcomes = std::collections::BTreeMap::new();
    for r in common::pqzl_rows() {
        if seen.contains(&r.code) {
            continue;
        }
        seen.push(r.code);
        let n = r.wit.len();
        let mut cases = vec![("honest", r.wit.clone()), ("short", r.wit[..n - 1].to_vec())];
        for at in [0, 2048, n - 1] {
            let mut w = r.wit.clone();
            w[at] = w[at].wrapping_add(1);
            cases.push((["byte 0", "byte 2048", "last byte"][(at > 0) as usize + (at == n - 1) as usize], w));
        }
        for (case, w) in cases {
            let (rust, c) = both(&mut ctx, &r, &w);
            assert!(rust == c, "{} {case}: Rust {:?}, C {:?}", r.name, rust.as_ref().map(Vec::len), c.as_ref().map(Vec::len));
            if case == "honest" {
                assert!(rust.as_ref() == Ok(&r.proof), "{}: the vector's proof", r.name);
            }
            *outcomes.entry(format!("{case}: {:?}", rust.map(|_| "proof"))).or_insert(0) += 1;
        }
    }
    assert_eq!(seen.len(), 14);
    eprintln!("prove_eq_c: 14 relation codes, Rust = C on every case; outcomes {outcomes:?}");
}
