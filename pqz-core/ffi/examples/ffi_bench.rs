//! Verify times through the FFI against the verifiers called directly, and the verify-only arena peak (P6e Task 7).
//!   cargo run --release --offline --features prove --example ffi_bench [n]      JSON lines on stdout
//! Per honest form of both ids: `direct` = `pqz_verify_fast` on the caller's thread (the lock only, no worker hop) /
//! `pqzh::verify`; `rust` =
//! `precompile` (decode, dispatch, catch_unwind); `c_abi` = `pqz_precompile`; `adversarial` = `pqz_precompile` on the
//! honest input with one proof bit flipped in the middle. Then `decode` alone, and the arena: a fresh core on the
//! big arena that only runs the precompile path (all six PQZL forms, every op 7 shape, the self-test) and its peak.
//! Op 7 (P6-ANON S3): every built `(M, auditorOn)` of both ids after the forms, with the statement / input bytes, the
//! worst-case input (PQZL `MAX_PROOF`, PQZH Ligero's exact bound) and one prove's time; and the prove arena's peak
//! with every relation loaded (the core that proved everything, `ARENA_BIG`).
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
        let forms = fixture::cases(&id).unwrap().into_iter().map(|c| (format!("{:?}", c.form), c.op(), c.stmt, c.wit, None));
        let multi = fixture::multi_cases(&id, usize::MAX).unwrap().into_iter().map(|c| (c.name(), c.op(), c.stmt, c.wit, Some((c.m, c.aud))));
        for (name, op, st, wit, shape) in forms.chain(multi) {
            let t = Instant::now();
            let Ok(proof) = prove(op, &st, &wit, &rnd) else {
                println!("{{\"sys\": \"{sys}\", \"form\": \"{name}\", \"skipped\": \"no prover\"}}");
                continue;
            };
            let prove_ms = t.elapsed().as_secs_f64() * 1e3;
            let input = stmt::input(op, &st, &proof);
            let mut adv = input.clone();
            let m = 5 + st.len() + proof.len() / 2;
            adv[m] ^= 4;
            assert_eq!(precompile(&input), Ok(VALID));
            let direct = |s: &[u8], p: &[u8]| {
                if id == PQZL_ID { pqzl::verify_fast_on_caller(op, s, p) } else { pqzh::verify(op, s, p) }
            };
            assert!(verify_input(&input).unwrap()); // warm on the worker (relation keys, SV tables)
            let mut out = [0u8; 32];
            let row = [
                ("direct", time(n, || assert!(direct(&st, &proof)))),
                ("rust", time(n, || assert_eq!(precompile(&input), Ok(VALID)))),
                ("c_abi", time(n, || unsafe {
                    assert_eq!(pqz_precompile(input.as_ptr(), input.len(), out.as_mut_ptr(), 32), PQZ_FFI_OK);
                })),
                ("adversarial", time(n, || assert_eq!(precompile(&adv), Ok(INVALID)))),
                ("decode", time(n, || assert!(decode(&input).is_ok()))),
            ];
            let body: Vec<String> = row.into_iter().map(|(k, v)| format!("\"{k}\": {}", stats(v))).collect();
            let multi = shape.map_or(String::new(), |(m, aud)| {
                let bound = if id == PQZL_ID { stmt::MAX_PROOF_PQZL } else { pqzh::PARAMS.max_proof_len(pqzh_ligero::Rel::Multi { m, aud }) };
                format!(
                    "\"m\": {m}, \"auditor\": {aud}, \"stmt_bytes\": {}, \"input_bytes\": {}, \"proof_bound\": {bound}, \"worst_input_bytes\": {}, \"prove_ms\": {prove_ms:.0}, ",
                    st.len(),
                    input.len(),
                    5 + st.len() + bound
                )
            });
            println!("{{\"sys\": \"{sys}\", \"form\": \"{name}\", {multi}\"proof_bytes\": {}, {}}}", proof.len(), body.join(", "));
            if id == PQZL_ID {
                pqzl_inputs.push(input);
            }
        }
    }
    // the prove arena: the core that proved every form and op 7 shape (every relation's keys loaded), since its init
    let prove_peak = pqzl::arena_peak();
    println!(
        "{{\"arena\": \"prove, every relation loaded\", \"peak_bytes\": {prove_peak}, \"ARENA_BIG_mib\": {}, \"margin\": {:.2}}}",
        pqzl::ARENA_BIG >> 20,
        pqzl::ARENA_BIG as f64 / prove_peak as f64
    );
    // verify-only arena: a core that has never proved, every PQZL form's and op 7 shape's keys and tables kept, plus
    // the self-test
    assert!(pqzl::reinit(pqzl::ARENA_BIG));
    let t = Instant::now();
    let st = selftest::report().unwrap();
    let st_ms = t.elapsed().as_secs_f64() * 1e3;
    for i in &pqzl_inputs {
        assert_eq!(precompile(i), Ok(VALID));
    }
    let peak = pqzl::arena_peak();
    println!(
        "{{\"arena\": \"verify-only\", \"peak_bytes\": {peak}, \"x1.5_mib\": {}, \"ARENA_SMALL_mib\": {}, \"margin\": {:.2}, \"selftest_cold_ms\": {st_ms:.1}, \"selftest_results\": {:?}}}",
        (peak * 3 / 2).div_ceil(1 << 20),
        pqzl::ARENA_SMALL >> 20,
        pqzl::ARENA_SMALL as f64 / peak as f64,
        st.results
    );
    // and the precompile path on a fresh ARENA_SMALL core
    assert!(pqzl::reinit(pqzl::ARENA_SMALL));
    let ok = pqzl_inputs.iter().all(|i| precompile(i) == Ok(VALID)) && selftest::report().unwrap().hash == st.hash;
    println!("{{\"arena\": \"ARENA_SMALL\", \"all_valid\": {ok}, \"peak_bytes\": {}}}", pqzl::arena_peak());
}
