//! Dump client::setup()'s statements and witnesses (all six forms) for the byte cross-check with pqz-core
//! (../xcheck/ligero.sh, which patches pqz_bench.c's statements to the same opTag, PQZH id (D3) and auditorOn):
//! `cargo run --release --example dump_setup -- DIR`.
use pqzh_ligero::RELS;
use pqzh_ligero::client::{rel_name, setup};

fn main() {
    let dir = std::env::args().nth(1).expect("DIR");
    let s = setup();
    for f in RELS {
        let n = rel_name(f)[2..].to_lowercase();
        let (st, w) = s.rel(f);
        std::fs::write(format!("{dir}/{n}_stmt.bin"), st).unwrap();
        std::fs::write(format!("{dir}/{n}_wit.bin"), w).unwrap();
    }
}
