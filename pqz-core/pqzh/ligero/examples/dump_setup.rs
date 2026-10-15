//! Dump client::setup()'s statements and witnesses (all six forms) for the byte cross-check with pqz-core
//! (../xcheck/ligero.sh, which patches pqz_bench.c's statements to the same opTag, PQZH id (D3) and auditorOn):
//! `cargo run --release --example dump_setup -- DIR`. Also every op 7 `R_TXM` shape (`txm<M>[_0]_stmt.bin`,
//! `_wit.bin`), which pqz-core does not have yet: xcheck/kat_multi.py checks those against pqz_kat.py.
use pqzh_ligero::client::{MultiTweak, rel_name, setup, setup_multi};
use pqzh_ligero::{RELS, Rel, multi_rels};

fn main() {
    let dir = std::env::args().nth(1).expect("DIR");
    let s = setup();
    for f in RELS {
        let n = rel_name(f)[2..].to_lowercase();
        let (st, w) = s.rel(f);
        std::fs::write(format!("{dir}/{n}_stmt.bin"), st).unwrap();
        std::fs::write(format!("{dir}/{n}_wit.bin"), w).unwrap();
    }
    // the default shapes, plus fee 0 with all-decoy legs and two real legs (M >= 2)
    for r in multi_rels() {
        let Rel::Multi { m, aud } = r else { unreachable!() };
        let n = rel_name(r)[2..].to_lowercase();
        let mut two = vec![0; m];
        two[0] = 5;
        two[m - 1] += 1_000;
        for (sfx, tw) in [
            ("", MultiTweak::default()),
            ("_fee0", MultiTweak { fee: Some(0), amounts: Some(vec![0; m]), ..Default::default() }),
            ("_two", MultiTweak { amounts: Some(two), ..Default::default() }),
        ] {
            let (st, w) = setup_multi(m, aud, &tw);
            std::fs::write(format!("{dir}/{n}{sfx}_stmt.bin"), st).unwrap();
            std::fs::write(format!("{dir}/{n}{sfx}_wit.bin"), w).unwrap();
        }
    }
}
