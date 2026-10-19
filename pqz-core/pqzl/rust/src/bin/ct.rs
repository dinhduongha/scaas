//! The constant-time check of the prover under valgrind memcheck (ctgrind; review fix E, pqzl/test/ct.sh's Rust
//! twin): `ct [rels] [nprove]` proves with the witness and rnd32 marked secret (`Bench::prove_ct`); memcheck reports
//! every branch or address that depends on them. Run by `pqzl/test/ct.sh` (feature `ctgrind`, x86-64 only).
use pqzl::bench::{Bench, NAMES, NREL};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let arg = |i: usize, d: u32| a.get(i).map_or(d, |s| s.parse().expect("a number"));
    let (rels, np) = (arg(1, 1), arg(2, 1));
    let mut b = Bench::new().expect("init");
    let mut fails = 0;
    for tx in (0..NREL).filter(|&t| rels >> t & 1 == 1) {
        for i in 0..np {
            let rc = b.prove_ct(tx, i);
            let ok = rc.is_ok() && b.verify(tx);
            println!("{{\"rel\": \"{}\", \"run\": {i}, \"prove\": \"{rc:?}\", \"verify\": {ok}, \"fnv\": \"{:08x}\"}}", NAMES[tx], b.hash(tx));
            fails += !ok as u32;
        }
    }
    println!("{{\"fails\": {fails}}}");
    std::process::exit((fails != 0) as i32);
}
