//! The constant-time check of the PQZH prover under valgrind memcheck (ctgrind; review P-B, the method of PQZL fix E,
//! pqzl/rust/src/bin/ct.rs): `ct [rels] [nprove]` proves with the witness and rnd32 marked secret (`ct::secret`) at
//! THE preset; memcheck reports every branch or address that depends on them, after the declassification points
//! (`ct::public` / the verdicts in the crate). `rels`: bit i = RELS[i] (0..6: R_REG, R_TX, R_BURN, R_DS, R_DR, R_TX0),
//! then the op 7 shapes of `multi_rels()` (bits 6..12); default 4095 = all twelve. Proof j uses rnd32 = [j; 32], the
//! seeds of ligero_bench's `fnv_by_seed`. Every proof must verify. Run by `runs/ct.sh` (feature `ctgrind`, x86-64).
use pqzh_ligero::client::{inputs, rel_name, setup};
use pqzh_ligero::{Params, RELS, Rel, ct, multi_rels, prove, verify};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let arg = |i: usize, d: u32| a.get(i).map_or(d, |s| s.parse().expect("a number"));
    let (rels, np) = (arg(1, 4095), arg(2, 1));
    let s = setup();
    let all: Vec<Rel> = RELS.iter().map(|&f| Rel::Form(f)).chain(multi_rels()).collect();
    let p = Params::proven();
    let mut fails = 0;
    for (_, &r) in all.iter().enumerate().filter(|&(i, _)| rels >> i & 1 == 1) {
        let (st, w) = inputs(&s, r);
        for j in 0..np {
            let rnd = [j as u8; 32];
            ct::secret(&w[..]);
            ct::secret(&rnd);
            let pf = prove(r.op(), &st, &w, rnd, &p);
            let ok = pf.as_ref().is_ok_and(|pf| verify(r.op(), &st, pf, &p));
            let fnv = pf.as_ref().map_or(0, |pf| pf.iter().fold(2166136261u32, |h, &b| (h ^ b as u32).wrapping_mul(16777619)));
            let len = pf.as_ref().map(|pf| pf.len());
            println!("{{\"rel\": \"{}\", \"run\": {j}, \"prove\": \"{len:?}\", \"verify\": {ok}, \"fnv\": \"{fnv:08x}\"}}", rel_name(r));
            fails += !ok as u32;
        }
    }
    println!("{{\"fails\": {fails}}}");
    std::process::exit((fails != 0) as i32);
}
