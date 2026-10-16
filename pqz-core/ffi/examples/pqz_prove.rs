//! P6g e2e helper (plan D7): proofs for statements the PQZ contracts built on chain 7622.
//!
//! Reads jobs from stdin, one per line, until EOF; answers one line each on stdout:
//!   `prove <op> <stmt hex> <wit hex> <rnd32 hex>`  →  the proof as hex (`ERR <reason>` on failure)
//!   `verify <op> <stmt hex> <proof hex>`           →  the precompile's word as hex (`pqz_ffi::precompile`)
//! The proof system is the statement's `proofSystemId` (bytes 32..63). Build: `cargo build --release --offline
//! --features prove --example pqz_prove`. Nothing else in pqz-ffi depends on it.

#[cfg(not(feature = "prove"))]
fn main() {
    eprintln!("pqz_prove needs --features prove");
    std::process::exit(2);
}

#[cfg(feature = "prove")]
fn main() {
    use std::io::{BufRead, Write};

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex")).collect()
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        let f: Vec<&str> = line.split_whitespace().collect();
        let reply = match f.as_slice() {
            ["prove", op, stmt, wit, rnd] => {
                let r: [u8; 32] = unhex(rnd).try_into().expect("rnd32");
                match pqz_ffi::prove(op.parse().expect("op"), &unhex(stmt), &unhex(wit), &r) {
                    Ok(p) => hex(&p),
                    Err(e) => format!("ERR {e:?}"),
                }
            }
            ["verify", op, stmt, proof] => {
                let s = unhex(stmt);
                let mut input = vec![op.parse::<u8>().expect("op")];
                input.extend_from_slice(&(s.len() as u32).to_be_bytes());
                input.extend_from_slice(&s);
                input.extend_from_slice(&unhex(proof));
                match pqz_ffi::precompile(&input) {
                    Ok(w) => hex(&w),
                    Err(e) => format!("ERR {e:?}"),
                }
            }
            _ => "ERR job".to_string(),
        };
        writeln!(out, "{reply}").expect("stdout");
        out.flush().expect("stdout");
    }
}
