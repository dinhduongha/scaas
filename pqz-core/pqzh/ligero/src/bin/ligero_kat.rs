//! Deterministic proof fingerprints (no timing; plan 5h Task 8c): the byte-identity check of a field / set change.
//!   ligero_kat setup     every relation of `client::inputs` (the six forms, the built op 7 shapes) at THE preset, seeds
//!                        [0; 32] and [1; 32]: one JSON line each {set, rel, seed, proof_bytes, keccak, fnv, verify}
//!   ligero_kat replay    stdin lines "op stmt_hex wit_hex rnd32_hex proof_hex" (runs/replay_vectors.py builds them
//!                        from smartcontracts/vectors/pqz/proof_pqzh.json): the keccak of a fresh proof and the verdict
//!                        on the stored proof, one JSON line per input
//! wasm/fnv_wasm.mjs prints the same `setup` lines from the wasm32 build (native = wasm32).

use std::io::BufRead;

use pqzh_ligero::client::{inputs, rel_name, setup};
use pqzh_ligero::merkle::keccak;
use pqzh_ligero::{Params, RELS, Rel, multi_rels, prove, verify};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn fnv(b: &[u8]) -> u32 {
    b.iter().fold(2166136261u32, |h, &x| (h ^ x as u32).wrapping_mul(16777619))
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let p = Params::proven();
    match mode.as_str() {
        "setup" => {
            let s = setup();
            for r in RELS.iter().map(|&f| Rel::Form(f)).chain(multi_rels()) {
                let (st, w) = inputs(&s, r);
                for seed in [0u8, 1] {
                    let pf = prove(r.op(), &st, &w, [seed; 32], &p).expect("prove");
                    println!(
                        "{{\"set\": \"{}\", \"rel\": \"{}\", \"seed\": {seed}, \"proof_bytes\": {}, \"keccak\": \"{}\", \"fnv\": \"{:08x}\", \"verify\": {}}}",
                        "baseline-HEAD-756713a2",
                        rel_name(r),
                        pf.len(),
                        hex(&keccak(&[&pf])),
                        fnv(&pf),
                        verify(r.op(), &st, &pf, &p)
                    );
                }
            }
        }
        "replay" => {
            for line in std::io::stdin().lock().lines() {
                let line = line.expect("stdin");
                let f: Vec<&str> = line.split_whitespace().collect();
                let op: u8 = f[0].parse().expect("op");
                let (st, w, rnd, stored) = (unhex(f[1]), unhex(f[2]), unhex(f[3]), unhex(f[4]));
                let pf = prove(op, &st, &w, rnd.try_into().expect("rnd32"), &p).expect("prove");
                println!(
                    "{{\"op\": {op}, \"proof_bytes\": {}, \"keccak\": \"{}\", \"verify_stored\": {}}}",
                    pf.len(),
                    hex(&keccak(&[&pf])),
                    verify(op, &st, &stored, &p)
                );
            }
        }
        _ => panic!("usage: ligero_kat setup | replay"),
    }
}
