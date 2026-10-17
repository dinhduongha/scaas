//! `pqzl/test/pqz_bench.c`'s main: `bench [n_prove] [n_verify] [rel]` (defaults 10 100 63; rel the C bench's bit
//! mask: 1 R_REG, 2 R_TX, 4 R_BURN, 8 R_DS, 16 R_DR, 32 R_TX0, 64 << t R_TXM shape t), JSON lines: per relation the
//! prove timings, `proofs_fnv` (FNV-1a over the per-proof FNV-1a hashes, seeds 0 .. n_prove - 1: equal to the C
//! bench's for the same arguments), honest and adversarial verify timings; `{"fails": n}` last, exit 1 if n > 0.
//! Not ported: the arena figures (no arena), `rej_tries_mean`, the hedge / auditor / txm checks, PQZ_VERIFY=fast.
use pqzl::bench::{Bench, NAMES, NKIND, NREL};
use std::time::Instant;

/// microseconds as milliseconds with three decimals (integers only: no float in the crate)
fn ms(us: u128) -> String {
    format!("{}.{:03}", us / 1000, us % 1000)
}

fn stats(name: &str, v: &mut [u128]) {
    if v.is_empty() {
        return;
    }
    v.sort_unstable();
    let n = v.len();
    let s: u128 = v.iter().sum();
    println!(
        "{{\"timing\": \"{name}\", \"n\": {n}, \"mean_ms\": {}, \"p50_ms\": {}, \"p99_ms\": {}, \"max_ms\": {}}}",
        ms(s / n as u128),
        ms(v[n / 2]),
        ms(v[99 * (n - 1) / 100]),
        ms(v[n - 1])
    );
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let arg = |i: usize, d: u32| a.get(i).map_or(d, |s| s.parse().expect("a number"));
    let (np, nv, rels) = (arg(1, 10), arg(2, 100), arg(3, 63));
    let t0 = Instant::now();
    let mut b = match Bench::new() {
        Ok(b) => b,
        Err(e) => {
            println!("{{\"error\": \"init {e:?}\"}}");
            std::process::exit(1);
        }
    };
    println!("{{\"init_ms\": {}, \"verify\": \"generic\"}}", ms(t0.elapsed().as_micros()));
    let mut fails = 0;
    for tx in (0..NREL).filter(|&t| rels >> t & 1 == 1) {
        let rel = NAMES[tx];
        let (mut tp, mut maxlen, mut hall) = (Vec::new(), 0, 2166136261u32);
        for i in 0..np {
            let t0 = Instant::now();
            let rc = b.prove(tx, i);
            tp.push(t0.elapsed().as_micros());
            if let Err(e) = rc {
                println!("{{\"rel\": \"{rel}\", \"prove_rc\": \"{e:?}\"}}");
                fails += 1;
                continue;
            }
            maxlen = maxlen.max(b.len(tx));
            hall = (hall ^ b.hash(tx)).wrapping_mul(16777619);
            if !b.verify(tx) {
                println!("{{\"rel\": \"{rel}\", \"verify_honest\": 0, \"run\": {i}}}");
                fails += 1;
            }
        }
        stats(&format!("{rel} prove"), &mut tp);
        println!(
            "{{\"rel\": \"{rel}\", \"proof_bytes_last\": {}, \"proof_bytes_max\": {maxlen}, \"proofs_fnv\": \"{hall:08x}\"}}",
            b.len(tx)
        );
        let mut tv = Vec::new();
        for _ in 0..nv {
            let t0 = Instant::now();
            fails += !b.verify(tx) as u32;
            tv.push(t0.elapsed().as_micros());
        }
        stats(&format!("{rel} verify valid"), &mut tv);
        let mut ta = Vec::new();
        for kind in 0..NKIND * (nv > 0) as u32 {
            for i in 0..nv / 5 + 1 {
                let t0 = Instant::now();
                let ok = b.verify_bad(tx, kind, i * 7 + kind);
                ta.push(t0.elapsed().as_micros());
                if ok {
                    println!("{{\"rel\": \"{rel}\", \"accepted_bad_kind\": {kind}}}");
                    fails += 1;
                }
            }
        }
        stats(&format!("{rel} verify adversarial"), &mut ta);
    }
    println!("{{\"fails\": {fails}}}");
    std::process::exit((fails != 0) as i32);
}
