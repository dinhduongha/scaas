//! Verify times through the FFI against the verifiers called directly, and the verify-only arena peak (P6e Task 7).
//!   cargo run --release --offline --features prove --example ffi_bench [n]      JSON lines on stdout
//! Per honest form of both ids: `direct` = `pqz_verify_fast` on the caller's thread (the lock only, no worker hop) /
//! `pqzh::verify`; `rust` =
//! `precompile` (decode, dispatch, catch_unwind); `c_abi` = `pqz_precompile`; `adversarial` = `pqz_precompile` on the
//! honest input with one proof bit flipped in the middle. Then `decode` alone, and the arena: a fresh core on the
//! big arena that only runs the precompile path (all six PQZL forms, the self-test) and its peak.
use std::time::Instant;

use pqz_ffi::*;

fn stats(mut v: Vec<f64>) -> String {
    v.sort_by(|a, b| a.total_cmp(b));
    let q = |p: f64| v[((v.len() - 1) as f64 * p).round() as usize];
    format!("{{\"n\": {}, \"p50_ms\": {:.3}, \"p99_ms\": {:.3}, \"max_ms\": {:.3}}}", v.len(), q(0.5), q(0.99), q(1.0))
}

fn time(n: usize, mut f: impl FnMut()) -> Vec<f64> {
    (0..n)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_secs_f64() * 1e3
        })
        .collect()
}

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(200);
    let rnd = [0x33u8; 32];
    let mut pqzl_inputs = Vec::new();
    for id in [PQZL_ID, PQZH_ID] {
        let sys = if id == PQZL_ID { "PQZL" } else { "PQZH" };
        for c in fixture::cases(&id).unwrap() {
            let Ok(proof) = prove(c.op(), &c.stmt, &c.wit, &rnd) else {
                println!("{{\"sys\": \"{sys}\", \"form\": \"{:?}\", \"skipped\": \"no prover\"}}", c.form);
                continue;
            };
            let input = stmt::input(c.op(), &c.stmt, &proof);
            let mut adv = input.clone();
            let m = 5 + c.stmt.len() + proof.len() / 2;
            adv[m] ^= 4;
            assert_eq!(precompile(&input), Ok(VALID));
            let direct = |s: &[u8], p: &[u8]| {
                if id == PQZL_ID { pqzl::verify_fast_on_caller(c.op(), s, p) } else { pqzh::verify(c.op(), s, p) }
            };
            assert!(verify_input(&input)); // warm on the worker (relation keys, SV tables)
            let mut out = [0u8; 32];
            let row = [
                ("direct", time(n, || assert!(direct(&c.stmt, &proof)))),
                ("rust", time(n, || assert_eq!(precompile(&input), Ok(VALID)))),
                ("c_abi", time(n, || unsafe {
                    assert_eq!(pqz_precompile(input.as_ptr(), input.len(), out.as_mut_ptr(), 32), PQZ_FFI_OK);
                })),
                ("adversarial", time(n, || assert_eq!(precompile(&adv), Ok(INVALID)))),
                ("decode", time(n, || assert!(decode(&input).is_ok()))),
            ];
            let body: Vec<String> = row.into_iter().map(|(k, v)| format!("\"{k}\": {}", stats(v))).collect();
            println!(
                "{{\"sys\": \"{sys}\", \"form\": \"{:?}\", \"proof_bytes\": {}, {}}}",
                c.form,
                proof.len(),
                body.join(", ")
            );
            if id == PQZL_ID {
                pqzl_inputs.push(input);
            }
        }
    }
    // verify-only arena: a core that has never proved, every PQZL form's keys and tables kept, plus the self-test
    assert!(pqzl::reinit(pqzl::ARENA_BIG));
    let t = Instant::now();
    let st = selftest::report().unwrap();
    let st_ms = t.elapsed().as_secs_f64() * 1e3;
    for i in &pqzl_inputs {
        assert_eq!(precompile(i), Ok(VALID));
    }
    let peak = pqzl::arena_peak();
    println!(
        "{{\"arena\": \"verify-only\", \"peak_bytes\": {peak}, \"x1.5_mib\": {}, \"ARENA_SMALL_mib\": {}, \"selftest_cold_ms\": {st_ms:.1}, \"selftest_results\": {:?}}}",
        (peak * 3 / 2).div_ceil(1 << 20),
        pqzl::ARENA_SMALL >> 20,
        st.results
    );
    // and the precompile path on a fresh ARENA_SMALL core
    assert!(pqzl::reinit(pqzl::ARENA_SMALL));
    let ok = pqzl_inputs.iter().all(|i| precompile(i) == Ok(VALID)) && selftest::report().unwrap().hash == st.hash;
    println!("{{\"arena\": \"ARENA_SMALL\", \"all_valid\": {ok}, \"peak_bytes\": {}}}", pqzl::arena_peak());
}
