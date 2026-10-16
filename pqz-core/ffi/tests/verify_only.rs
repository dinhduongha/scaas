//! The precompile in its production configuration (review of p6e-a3, controller 2026-10-14): a fresh process whose
//! core has never proved, on the verify-only arena (`ARENA_SMALL`, 512 MiB since P6-ANON S3). The honest inputs (every
//! form and every built op 7 shape of both ids) are proved by a child process
//! (`child_task`), so this process only verifies.
//!
//! `verify_only_arena`: the full adversarial corpus (every decoder rejection and framing case, the 10,240-input
//! abort-freedom generator) serial, from 8 threads and on a 1 MiB caller-stack thread, then 5,000 repeated mixed calls;
//! the arena never moves: `arena_used()` after every call and `arena_peak()` at the end equal their values after the
//! warm-up pass (no growth, nothing left below the base mark), the arena stays `ARENA_SMALL`, and its peak leaves a margin of at least 1.5×.
//!
//! `fill_determinism`: child processes fill every arena with 0x00, 0xA5 or 0x5A before `pqz_init` and write the
//! digest lines (fixtures, proofs of every form, verdicts, self-test) and the result of every corpus input; all three
//! files must be identical (the core never reads arena bytes it did not write).
mod common;

use std::sync::atomic::Ordering::Relaxed;

use common::*;
use pqz_ffi::*;

const N_GEN: usize = 10_240;

fn tmp(name: &str) -> String {
    format!("{}/{name}", env!("CARGO_TARGET_TMPDIR"))
}

fn corpus(hs: &[Honest], n_gen: usize) -> Vec<Vec<u8>> {
    let mut c: Vec<Vec<u8>> = hs.iter().flat_map(|h| negatives(h).into_iter().map(|x| x.1)).collect();
    c.extend(framing(hs).into_iter().map(|x| x.1));
    c.extend(hs.iter().map(|h| h.input()));
    c.push(vec![6, 0, 0, 0, 0]);
    c.extend((0..n_gen).map(|i| gen(hs, i)));
    c
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Child entry (no-op unless `PQZ_FFI_CHILD` is set): `gen:<file>` proves every form of both ids and writes the
/// inputs; `fill:<byte>:<inputs>:<out>` runs the fill-pattern pass.
#[test]
fn child_task() {
    let Ok(arg) = std::env::var("PQZ_FFI_CHILD") else { return };
    let a: Vec<&str> = arg.split(':').collect();
    match a[0] {
        "gen" => std::fs::write(a[1], to_bytes(&prove_all())).unwrap(),
        "fill" => {
            let b = u8::from_str_radix(a[1], 16).unwrap();
            pqzl::TEST_ARENA_FILL.store(0x100 | b as u32, Relaxed);
            let hs = from_bytes(&std::fs::read(a[2]).unwrap());
            let mut s = fixture::digest_lines(&PQZL_ID) + &fixture::digest_lines(&PQZH_ID) + &fixture::selftest_line();
            assert!(pqzl::reinit(pqzl::ARENA_SMALL));
            for inp in corpus(&hs, 2048) {
                let (rc, w) = call(&inp);
                s += &format!("{rc} {}\n", hex(&w));
            }
            std::fs::write(a[3], s).unwrap();
        }
        _ => panic!("{arg}"),
    }
}

#[test]
fn verify_only_arena() {
    if std::env::var("PQZ_FFI_CHILD").is_ok() {
        return;
    }
    let f = tmp("verify_only_inputs.bin");
    child("child_task", &format!("gen:{f}"));
    let hs = from_bytes(&std::fs::read(&f).unwrap());
    assert_eq!(hs.len(), 16 + 14);
    let honest: Vec<Vec<u8>> = hs.iter().map(|h| h.input()).collect();
    let c = corpus(&hs, N_GEN);
    let gen_from = c.len() - N_GEN;
    assert_eq!(pqzl::arena_bytes(), 0, "no core before the first call");

    // warm-up pass: every relation's keys and tables get built
    let t = std::time::Instant::now();
    let r1: Vec<(i32, Word)> = c.iter().map(|i| call(i)).collect();
    let warm_s = t.elapsed().as_secs_f64();
    assert_eq!(pqzl::arena_bytes(), pqzl::ARENA_SMALL);
    let (used0, peak0) = (pqzl::arena_used(), pqzl::arena_peak());
    let mut valid = 0;
    for (i, (rc, w)) in r1.iter().enumerate() {
        assert_eq!(*rc, PQZ_FFI_OK, "input {i}");
        if c[i] == [6, 0, 0, 0, 0] {
            continue;
        }
        let ok = honest.contains(&c[i]);
        assert_eq!(*w, word(ok), "input {i}");
        valid += ok as usize;
    }

    // the generator part again: 8 threads, and a thread with a 1 MiB stack, equal to the warm-up pass
    let par: Vec<(i32, Word)> = std::thread::scope(|s| {
        let js: Vec<_> = (0..8)
            .map(|t| {
                let c = &c;
                s.spawn(move || (gen_from + t..c.len()).step_by(8).map(|i| (i, call(&c[i]))).collect::<Vec<_>>())
            })
            .collect();
        let mut all: Vec<(usize, (i32, Word))> = js.into_iter().flat_map(|h| h.join().unwrap()).collect();
        all.sort_by_key(|x| x.0);
        all.into_iter().map(|x| x.1).collect()
    });
    assert_eq!(par, r1[gen_from..], "8 threads = serial");
    let small: Vec<(i32, Word)> = std::thread::scope(|s| {
        std::thread::Builder::new()
            .stack_size(1 << 20)
            .spawn_scoped(s, || c[gen_from..].iter().map(|i| call(i)).collect())
            .unwrap()
            .join()
            .unwrap()
    });
    assert_eq!(small, r1[gen_from..], "1 MiB caller stack = serial");

    // repeated mixed calls; the arena in use between calls never moves
    for k in 0..5_000usize {
        let i = (k * 7919) % c.len();
        assert_eq!(call(&c[i]), r1[i], "mixed call {k}");
        assert_eq!(pqzl::arena_used(), used0, "arena in use after mixed call {k}");
    }
    let peak1 = pqzl::arena_peak();
    assert_eq!(peak1, peak0, "arena peak grew");
    assert_eq!(pqzl::arena_bytes(), pqzl::ARENA_SMALL);
    let lp = pqzh_ligero::ligero::VERIFY_PANICS.load(Relaxed);
    eprintln!(
        "verify-only {} MiB: {} honest inputs, corpus {} inputs ({} generator), warm-up {warm_s:.1} s, {valid} valid (= the unedited honest \
         ones), status 3 / 4: 0; generator again from 8 threads and on a 1 MiB stack: equal; 5,000 mixed calls: equal; \
         arena used {used0} B after every call, peak {peak0} B = {:.2} of the arena (margin {:.2}x), Ligero panics caught {lp}",
        pqzl::ARENA_SMALL >> 20,
        hs.len(),
        c.len(),
        N_GEN,
        peak0 as f64 / pqzl::ARENA_SMALL as f64,
        pqzl::ARENA_SMALL as f64 / peak0 as f64
    );
    assert_eq!(lp, 0);
    assert!(2 * pqzl::ARENA_SMALL >= 3 * peak0, "arena margin under 1.5x");
}

#[test]
fn fill_determinism() {
    if std::env::var("PQZ_FFI_CHILD").is_ok() {
        return;
    }
    let f = tmp("fill_inputs.bin");
    child("child_task", &format!("gen:{f}"));
    let outs: Vec<String> = ["00", "a5", "5a"]
        .iter()
        .map(|b| {
            let o = tmp(&format!("fill_{b}.txt"));
            child("child_task", &format!("fill:{b}:{f}:{o}"));
            std::fs::read_to_string(o).unwrap()
        })
        .collect();
    assert_eq!(outs[0], outs[1], "0x00 vs 0xA5");
    assert_eq!(outs[0], outs[2], "0x00 vs 0x5A");
    let lines = outs[0].lines().count();
    let valid = outs[0].matches("\"valid\": true").count();
    assert_eq!(valid, 2 * (8 + 6));
    if let Ok(p) = std::env::var("PQZ_FFI_FILL_OUT") {
        std::fs::write(p, &outs[0]).unwrap();
    }
    eprintln!("fill determinism: arenas filled 0x00 / 0xA5 / 0x5A before pqz_init: {lines} result lines identical (digest lines of 16 forms and 12 op 7 shapes incl. proofs, self-test, {} corpus results)", lines - 29);
}
