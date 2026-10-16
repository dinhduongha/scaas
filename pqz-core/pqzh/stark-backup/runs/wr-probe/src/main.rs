//! PROBE (docs/research/pqzh-zk-whir.md §10, re-examination of 2026-10-14). Not part of the PQZH build.
//!
//!   [WR_LEVEL=debug] wr-probe tx  one ZK WHIR R_TX proof (WhirParams::DEFAULT, Goldilocks^5): prove time with tracing
//!                               span timings on stderr, verify time, and the proof's bytes field by field (JSON)
//!   wr-probe report             p3-whir's hiding base-case security report (Debug) for the R_TX main-round shape
//!   wr-probe micro N C [C2 ..]  HidingWhirPcs alone on a random 2^N polynomial: commit, the per-claim evaluations
//!                               that HidingWhirPcs::open does before proving, open, verify, for C claims each
//!
//! Run under scripts/capped, alone (runs/wr-probe.sh).

use std::time::Instant;

use p3_batch_stark::BatchProof;
use p3_commit::MultilinearPcs;
use p3_keccak::Keccak256Hash;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_whir::{
    FoldingFactor, HidingWhirPcs, ProtocolParameters, QueryOpenings, SecurityAssumption, ZkParameters, ZkWhirConfig,
    ZkWhirProof,
};
use pqzh::config::{BeChallenger, BeKeccak, Challenge5, Compress, HidingValMmcs, WhirParams, Whir5Config};
use pqzh::ring::F;
use pqzh::whirpcs::WDft;
use pqzh::{OP_TRANSFER, Params, client, enc};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

type EF = Challenge5;

fn sz<T: serde::Serialize + ?Sized>(t: &T) -> usize {
    enc::to_vec(t).map(|v| v.len()).unwrap_or(0)
}

fn q<P: serde::Serialize>(o: &QueryOpenings<F, EF, P>) -> (usize, usize, usize) {
    match o {
        QueryOpenings::Base(s) => (s.rows.len(), sz(&s.rows), sz(&s.proof)),
        QueryOpenings::Extension(s) => (s.rows.len(), sz(&s.rows), sz(&s.proof)),
    }
}

fn opening_json(w: &ZkWhirProof<F, EF, HidingValMmcs>) -> String {
    let mut o = vec![
        format!("\"total\": {}", sz(w)),
        format!("\"evals\": {}", sz(&w.evals)),
        format!("\"sumchecks\": {}", sz(&w.sumchecks)),
        format!("\"sumcheck_mask_commitments\": {}", sz(&w.sumcheck_mask_commitments)),
    ];
    for (i, r) in w.rounds.iter().enumerate() {
        let (n, rows, proof) = q(&r.openings);
        o.push(format!(
            "\"round{i}\": {{\"total\": {}, \"commitments\": {}, \"ood\": {}, \"queries\": {n}, \"query_rows\": {rows}, \"query_merkle\": {proof}}}",
            sz(r),
            sz(&r.commitment) + sz(&r.mask_commitment),
            sz(&r.ood_answers)
        ));
    }
    let b = &w.base_case;
    let (sn, srows, sproof) = q(&b.source_openings);
    let bm_msg: usize = b.blinded_masks.iter().map(|m| sz(&m.message)).sum();
    let bm_rnd: usize = b.blinded_masks.iter().map(|m| sz(&m.randomness)).sum();
    let bm_len: Vec<String> = b.blinded_masks.iter().map(|m| format!("[{}, {}]", m.message.len(), m.randomness.len())).collect();
    let groups: Vec<String> = b
        .mask_openings
        .iter()
        .map(|p| {
            format!(
                "{{\"positions\": {}, \"width\": {}, \"carried_rows\": {}, \"carried_merkle\": {}, \"fresh_rows\": {}, \"fresh_merkle\": {}}}",
                p.carried.rows.len(),
                p.carried.rows.first().map_or(0, |r| r.len()),
                sz(&p.carried.rows),
                sz(&p.carried.proof),
                sz(&p.fresh.rows),
                sz(&p.fresh.proof)
            )
        })
        .collect();
    let mo_rows: usize = b.mask_openings.iter().map(|p| sz(&p.carried.rows) + sz(&p.fresh.rows)).sum();
    let mo_merkle: usize = b.mask_openings.iter().map(|p| sz(&p.carried.proof) + sz(&p.fresh.proof)).sum();
    o.push(format!(
        "\"base_case\": {{\"total\": {}, \"commitments\": {}, \"blinded_source\": {}, \"blinded_source_len\": [{}, {}], \"blinded_masks_message\": {bm_msg}, \"blinded_masks_randomness\": {bm_rnd}, \"blinded_masks_lens\": [{}], \"source_queries\": {sn}, \"source_rows\": {srows}, \"source_merkle\": {sproof}, \"fresh_main_rows\": {}, \"fresh_main_merkle\": {}, \"mask_openings_rows\": {mo_rows}, \"mask_openings_merkle\": {mo_merkle}, \"mask_groups\": [{}]}}",
        sz(b),
        sz(&b.fresh_main_commitment) + sz(&b.fresh_mask_commitments),
        sz(&b.blinded_message) + sz(&b.blinded_randomness),
        b.blinded_message.len(),
        b.blinded_randomness.len(),
        bm_len.join(", "),
        sz(&b.fresh_main_openings.rows),
        sz(&b.fresh_main_openings.proof),
        groups.join(", ")
    ));
    format!("{{{}}}", o.join(", "))
}

fn tx() {
    tracing_subscriber::fmt()
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .with_max_level(if std::env::var("WR_LEVEL").as_deref() == Ok("debug") {
            tracing_subscriber::filter::LevelFilter::DEBUG
        } else {
            tracing_subscriber::filter::LevelFilter::INFO
        })
        .with_writer(std::io::stderr)
        .init();
    let mut p = Params::DEFAULT;
    p.zk = true;
    p.ext5 = true;
    p.whir = Some(WhirParams::DEFAULT);
    p.max_proof = 100_000_000;
    let s = client::setup();
    let t = Instant::now();
    let pf = pqzh::prove(OP_TRANSFER, &s.tx_stmt, &s.tx_wit, [1; 32], &p).expect("prove");
    let prove_ms = t.elapsed().as_secs_f64() * 1e3;
    let t = Instant::now();
    let ok = pqzh::verify(OP_TRANSFER, &s.tx_stmt, &pf, &p);
    let verify_ms = t.elapsed().as_secs_f64() * 1e3;
    let (bp, _) = enc::take_from_bytes::<BatchProof<Whir5Config>>(&pf).expect("decode");
    println!(
        "{{\"rel\": \"R_TX\", \"whir\": \"{:?}\", \"proof_bytes\": {}, \"fnv\": \"{:08x}\", \"prove_ms\": {prove_ms:.0}, \"verify_ms\": {verify_ms:.1}, \"verified\": {ok}, \"commitments\": {}, \"opened_values\": {}, \"lookup_terminals\": {}}}",
        WhirParams::DEFAULT,
        pf.len(),
        pf.iter().fold(2166136261u32, |h, &b| (h ^ b as u32).wrapping_mul(16777619)),
        sz(&bp.commitments),
        sz(&bp.opened_values),
        sz(&bp.lookup_terminals)
    );
    for (i, w) in bp.opening_proof.iter().enumerate() {
        println!("{{\"opening\": {i}, \"claims\": {}, \"parts\": {}}}", w.evals.len(), opening_json(w));
    }
}

fn micro(n: usize, claims: &[usize]) {
    let w = WhirParams::DEFAULT;
    let mk = |seed: u8| {
        let params = ProtocolParameters {
            security_level: w.target,
            pow_bits: w.pow,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(w.fold),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: w.rate,
        };
        let cfg = ZkWhirConfig::new(n, params, ZkParameters { ell_zk: w.ell_zk, mask_log_inv_rate: w.mask_rate }).unwrap();
        let mut rng = StdRng::from_seed([seed; 32]);
        let mmcs = HidingValMmcs::new(BeKeccak, Compress::new(Keccak256Hash {}), 0, StdRng::from_rng(&mut rng));
        HidingWhirPcs::<EF, F, WDft, HidingValMmcs, BeChallenger, StdRng>::new(cfg, WDft::default(), mmcs, rng)
    };
    let mut r = StdRng::from_seed([7; 32]);
    let msg: Vec<F> = (0..1usize << n).map(|_| r.random()).collect();
    for &c in claims {
        let pcs = mk(1);
        let t = Instant::now();
        let (cm, data) = pcs.commit(Poly::new(msg.clone()), &mut BeChallenger::new(&[0; 32])).unwrap();
        let commit_ms = t.elapsed().as_secs_f64() * 1e3;
        let pts: Vec<Point<EF>> = (0..c).map(|_| Point::new((0..n).map(|_| r.random::<EF>()).collect())).collect();
        // the evaluations HidingWhirPcs::open computes (prover_data.message.eval_base, one per claim) before proving
        let poly = Poly::new(msg.clone());
        let t = Instant::now();
        for p in &pts {
            let _ = std::hint::black_box(poly.eval_base(p));
        }
        let evals_ms = t.elapsed().as_secs_f64() * 1e3;
        let mut ch = BeChallenger::new(&[1; 32]);
        pcs.observe_commitment(&cm, &mut ch);
        let t = Instant::now();
        let pf = pcs.open(data, pts.clone(), &mut ch).unwrap();
        let open_ms = t.elapsed().as_secs_f64() * 1e3;
        let v = mk(2);
        let t = Instant::now();
        let ok = v.verify(&cm, &pf, &mut BeChallenger::new(&[1; 32]), pts).is_ok();
        let verify_ms = t.elapsed().as_secs_f64() * 1e3;
        println!(
            "{{\"vars\": {n}, \"claims\": {c}, \"commit_ms\": {commit_ms:.0}, \"claim_evals_ms\": {evals_ms:.0}, \"open_ms_incl_claim_evals\": {open_ms:.0}, \"verify_ms\": {verify_ms:.1}, \"verified\": {ok}, \"bytes\": {}, \"parts\": {}}}",
            sz(&pf),
            opening_json(&pf)
        );
    }
}

/// p3-whir's own base-case security report (Debug) for one opening of `n` variables, mask code rate 1/2^m
fn report<E>(name: &str, n: usize, target: usize, pow: usize, m: usize)
where
    E: p3_field::ExtensionField<F> + p3_field::TwoAdicField,
{
    let w = WhirParams::DEFAULT;
    let params = ProtocolParameters {
        security_level: target,
        pow_bits: pow,
        round_log_inv_rates: vec![],
        folding_factor: FoldingFactor::Constant(w.fold),
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate: w.rate,
    };
    match ZkWhirConfig::<E, F, BeChallenger>::new(n, params, ZkParameters { ell_zk: w.ell_zk, mask_log_inv_rate: m }) {
        Ok(c) => println!(
            "=== {name} vars {n} target {target} pow {pow} mask_rate 1/2^{m}: mask_queries {} groups {:?}\n{:#?}",
            c.mask_queries(),
            c.mask_groups(),
            c.hiding_base_case_security_report()
        ),
        Err(e) => println!("=== {name} vars {n} target {target} pow {pow} mask_rate 1/2^{m}: config error {e}"),
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(|s| s.as_str()) {
        Some("tx") => tx(),
        Some("micro") => {
            let n = a[2].parse().unwrap();
            let c: Vec<usize> = a[3..].iter().map(|x| x.parse().unwrap()).collect();
            micro(n, &c)
        }
        Some("report") => {
            report::<EF>("ext5", 22, 128, 16, 4);
            report::<pqzh::config::Challenge>("ext2", 22, 96, 16, 4);
            report::<pqzh::config::Challenge>("ext2", 22, 96, 16, 1);
        }
        _ => eprintln!("usage: wr-probe tx | micro N C [C ..] | report"),
    }
}
