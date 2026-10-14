//! Dump client::setup()'s statements and witnesses (all five relations) for the byte cross-check with pqz-core
//! (../xcheck/ligero.sh): `cargo run --release --example dump_setup -- DIR`.
use pqzh_ligero::client::{Tweak, rel_name, setup_with};
use pqzh_ligero::{OPS, stmt::PQZL_PROOF_SYSTEM_ID};

fn main() {
    let dir = std::env::args().nth(1).expect("DIR");
    // PQZL's proofSystemId, as pqz_bench.c writes it; PQZH statements differ only in bytes 32..63
    let s = setup_with(&Tweak { psid: Some(PQZL_PROOF_SYSTEM_ID), ..Default::default() });
    for op in OPS {
        let n = rel_name(op)[2..].to_lowercase();
        let (st, w) = s.rel(op);
        std::fs::write(format!("{dir}/{n}_stmt.bin"), st).unwrap();
        std::fs::write(format!("{dir}/{n}_wit.bin"), w).unwrap();
    }
}
