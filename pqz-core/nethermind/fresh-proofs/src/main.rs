//! `pqz-fresh-proofs <n>`: JSON lines {"id", "form", "op", "input"} — n fresh proofs (rnd32 = i ‖ 0x7f…) of every
//! fixture form and every built op 7 shape of both ids, each checked valid through the precompile.
use pqz_ffi::*;

fn main() {
    let n: u8 = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(20);
    for (name, id) in [("pqzl", PQZL_ID), ("pqzh", PQZH_ID)] {
        for c in fixture::cases(&id).unwrap() {
            for i in 0..n {
                let mut rnd = [0x7fu8; 32];
                rnd[0] = i;
                let proof = prove(c.op(), &c.stmt, &c.wit, &rnd).expect("prove");
                let input = stmt::input(c.op(), &c.stmt, &proof);
                assert_eq!(precompile(&input), Ok(VALID), "{name} {:?} #{i}", c.form);
                let hex: String = input.iter().map(|b| format!("{b:02x}")).collect();
                println!("{{\"id\": \"{name}\", \"form\": \"{:?}\", \"op\": {}, \"input\": \"{hex}\"}}", c.form, c.op());
            }
            eprintln!("{name} {:?}: {n} fresh proofs", c.form);
        }
        // op 7 (P6-ANON S8): every built (M, auditorOn) of the id
        for c in fixture::multi_cases(&id, 8).unwrap() {
            for i in 0..n {
                let mut rnd = [0x7fu8; 32];
                rnd[0] = i;
                let proof = prove(c.op(), &c.stmt, &c.wit, &rnd).expect("prove");
                let input = stmt::input(c.op(), &c.stmt, &proof);
                assert_eq!(precompile(&input), Ok(VALID), "{name} {} #{i}", c.name());
                let hex: String = input.iter().map(|b| format!("{b:02x}")).collect();
                println!("{{\"id\": \"{name}\", \"form\": \"{}\", \"op\": {}, \"input\": \"{hex}\"}}", c.name(), c.op());
            }
            eprintln!("{name} {}: {n} fresh proofs", c.name());
        }
    }
}
