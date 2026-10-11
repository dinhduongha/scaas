//! zether-cli — emit calldata / proofs / vectors for tests and e2e. UNAUDITED.
//!
//!   zether-cli vectors <dir>      write the deterministic vector files
//!   zether-cli <command>          JSON request on stdin, JSON result on stdout
//!
//! Commands: keygen, encrypt, decrypt, proveTransfer, verifyTransfer, proveTransferMulti, verifyTransferMulti,
//! proveBurn, verifyBurn, recoverTransfer, pop, shieldCalldata, envelope (see `zether_prover::api`).

use std::io::Read;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("vectors") => {
            let dir = std::path::Path::new(args.get(2).map(String::as_str).unwrap_or("vectors"));
            for (name, v) in zether_prover::vectors::generate() {
                let path = dir.join(&name);
                std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap() + "\n").expect("write vector");
                println!("{}", path.display());
            }
            ExitCode::SUCCESS
        }
        Some(cmd) => {
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input).expect("stdin");
            match zether_prover::api::call(cmd, &input) {
                Ok(out) => {
                    println!("{out}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        None => {
            eprintln!("usage: zether-cli vectors <dir> | zether-cli <command> < request.json");
            ExitCode::FAILURE
        }
    }
}
