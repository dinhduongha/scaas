//! Research spike A (plan 5h Task 8c spike, 2026-10-22; throwaway, kept as the record): a prover limit of
//! MAX_PROOF_PQZH (262,144) below the verifier's bound at set (a). Per debit form, N honest proofs with distinct rnd32
//! (threads share the seeds), each proved with `spike_prove_attempts(limit)`: every attempt's length, the attempts per
//! proof, the accepted proof verified, and every attempt's length checked against `spike_len_of(query indices)` (the
//! length is a function of the transcript's query indices alone). Then a Monte Carlo of the same length function over
//! uniform index sets. No timing: prover runs are counted.
//!   spike_retry <N per form> <threads> <monte carlo samples>      (build with --features set-n2304-kmax4096)

use pqzh_ligero::client::{inputs, rel_name, setup};
use pqzh_ligero::ligero::{spike_len_of, spike_prove_attempts, spike_query_indices};
use pqzh_ligero::pqz_stmt::MAX_PROOF_PQZH;
use pqzh_ligero::{Form, Params, Rel, verify};

fn stats(v: &mut [usize]) -> String {
    v.sort_unstable();
    format!("{{\"min\": {}, \"median\": {}, \"max\": {}}}", v[0], v[v.len() / 2], v[v.len() - 1])
}

fn main() {
    let a: Vec<usize> = std::env::args().skip(1).map(|x| x.parse().expect("number")).collect();
    let (n, threads, mc) = (a[0], a[1], a[2]);
    let p = Params::proven();
    let s = setup();
    let rels = [
        Rel::Form(Form::Transfer),
        Rel::Form(Form::Transfer0),
        Rel::Form(Form::Burn),
        Rel::Multi { m: 2, aud: true },
        Rel::Multi { m: 2, aud: false },
        Rel::Multi { m: 4, aud: true },
        Rel::Multi { m: 4, aud: false },
    ];
    println!(
        "{{\"set\": \"{}\", \"limit\": {MAX_PROOF_PQZH}, \"n\": {}, \"k\": {}, \"t\": {}, \"proofs_per_form\": {n}, \"threads\": {threads}}}",
        pqzh_ligero::set::NAME,
        p.n,
        p.k,
        p.t
    );
    for &r in &rels {
        let (st, w) = inputs(&s, r);
        // per proof: (attempt lengths, accepted verified, attempts whose length = spike_len_of(indices))
        let res: Vec<(Vec<usize>, bool, usize)> = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..threads)
                .map(|th| {
                    let (st, w) = (&st, &w);
                    sc.spawn(move || {
                        (th..n)
                            .step_by(threads)
                            .map(|i| {
                                let mut rnd = [0xA5u8; 32];
                                rnd[..8].copy_from_slice(&(i as u64).to_le_bytes());
                                let at = spike_prove_attempts(r.op(), st, w, rnd, &p, MAX_PROOF_PQZH).expect("prove");
                                let lens: Vec<usize> = at.iter().map(|x| x.len()).collect();
                                let same = at.iter().filter(|x| spike_len_of(r, &spike_query_indices(r.op(), st, x, &p), &p) == x.len()).count();
                                let ok = verify(r.op(), st, at.last().unwrap(), &p);
                                (lens, ok, same)
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
        });
        let mut first: Vec<usize> = res.iter().map(|x| x.0[0]).collect();
        let mut fin: Vec<usize> = res.iter().map(|x| *x.0.last().unwrap()).collect();
        let runs: usize = res.iter().map(|x| x.0.len()).sum();
        let over = first.iter().filter(|&&l| l > MAX_PROOF_PQZH).count();
        let maxa = res.iter().map(|x| x.0.len()).max().unwrap();
        let verified = res.iter().filter(|x| x.1).count();
        let same: usize = res.iter().map(|x| x.2).sum();
        println!(
            "{{\"rel\": \"{}\", \"proofs\": {}, \"prover_runs\": {runs}, \"first_attempt_bytes\": {}, \"first_over_limit\": {over}, \"max_attempts\": {maxa}, \"accepted_bytes\": {}, \"accepted_verified\": {verified}, \"len_equals_len_of_indices\": \"{same} / {runs}\", \"bound\": {}}}",
            rel_name(r),
            res.len(),
            stats(&mut first),
            stats(&mut fin),
            p.max_proof_len(r)
        );
    }
    // Monte Carlo: t uniform indices in [0, n) (the transcript's draws in the random-oracle model), the same length
    // function per form
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let mut over = vec![0usize; rels.len()];
    let mut hist = std::collections::BTreeMap::new();
    for _ in 0..mc {
        let mut idx: Vec<usize> = (0..p.t)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x % p.n as u64) as usize
            })
            .collect();
        idx.sort_unstable();
        idx.dedup();
        for (i, &r) in rels.iter().enumerate() {
            let l = spike_len_of(r, &idx, &p);
            over[i] += (l > MAX_PROOF_PQZH) as usize;
            if i == 5 {
                *hist.entry(l / 256 * 256).or_insert(0usize) += 1;
            }
        }
    }
    for (i, &r) in rels.iter().enumerate() {
        println!(
            "{{\"monte_carlo\": \"{}\", \"samples\": {mc}, \"over_limit\": {}, \"p_over\": {:.6}, \"expected_attempts\": {:.6}}}",
            rel_name(r),
            over[i],
            over[i] as f64 / mc as f64,
            1.0 / (1.0 - over[i] as f64 / mc as f64)
        );
    }
    let h: Vec<String> = hist.iter().map(|(k, v)| format!("\"{k}\": {v}")).collect();
    println!("{{\"monte_carlo_hist_R_TXM4_bytes_per_256\": {{{}}}}}", h.join(", "));
}
