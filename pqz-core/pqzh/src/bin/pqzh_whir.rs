//! PQZH R_REG / R_TX with a WHIR commitment (Plonky3 0.9.0-rc.1): the same AIRs proved by p3-multi-stark (the
//! multilinear SuperSpartan-style STARK, the only Plonky3 prover that takes a multilinear PCS such as WHIR) with
//! `WhirProver` (non-hiding). **Not zero-knowledge**: p3-multi-stark masks no sumcheck message ("Nothing this backend
//! accepts hides anything", p3-multi-stark src/contract/mod.rs), and the hiding `HidingWhirPcs` plugs into neither it
//! nor the uni/batch STARK (pqzh-zk-ext5.md §7). Measurement only: proof bytes, prove / verify time, peak heap, bits.
//!   pqzh_whir [--ext 2|5] [--rate R] [--fold K] [--pow B] [--target T] [--assume johnson|unique|capacity]
//!             [--np N] [--nv N] [--nadv N] [--rel reg|tx|both]
//! Prints JSON lines. Run under scripts/capped.

use std::alloc::{GlobalAlloc, Layout as AllocLayout, System};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::time::Instant;

use p3_dft::Radix2DFTSmallBatch;
use p3_field::extension::BinomialExtensionField;
use p3_multi_stark::config::MultiStarkConfig;
use p3_multi_stark::{
    MultiStarkProof, ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, prove, security_report, setup,
    verify,
};
use p3_sumcheck::layout::{Layout, PrefixProver, Table, TableShape, Witness, plan_stacked_layout};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver, WhirProverData};

use pqzh::air::PqzhAir;
use pqzh::client::{KINDS, R, mutate};
use pqzh::config::{BeChallenger, ValMmcs, mmcs};
use pqzh::ring::F;
use pqzh::{OP_REGISTER, OP_TRANSFER, client, enc, rel};

struct Track;
static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);
unsafe impl GlobalAlloc for Track {
    unsafe fn alloc(&self, l: AllocLayout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() && ARMED.load(Ordering::Relaxed) {
            let v = LIVE.fetch_add(l.size() as isize, Ordering::Relaxed) + l.size() as isize;
            if v > 0 {
                PEAK.fetch_max(v as usize, Ordering::Relaxed);
            }
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: AllocLayout) {
        if ARMED.load(Ordering::Relaxed) {
            LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        }
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static G: Track = Track;

type Dft = Radix2DFTSmallBatch<F>;
type L<EF> = PrefixProver<F, EF>;
type Pcs<EF> = WhirProver<EF, F, Dft, ValMmcs, BeChallenger, L<EF>>;

/// first-round folding factor = per-table padding floor (as in p3-multi-stark's WHIR tests)
struct WCfg<EF: p3_field::ExtensionField<F>> {
    pcs: Pcs<EF>,
    pre: Pcs<EF>,
    fold: usize,
}

macro_rules! wcfg {
    ($ef:ty) => {
        impl MultiStarkConfig for WCfg<$ef> {
            type Val = F;
            type Challenge = $ef;
            type Challenger = BeChallenger;
            type Pcs = Pcs<$ef>;
            fn pcs(&self) -> &Pcs<$ef> {
                &self.pcs
            }
            fn preprocessed_pcs(&self) -> &Pcs<$ef> {
                &self.pre
            }
            fn collision_resistance_bits(&self) -> Option<usize> {
                Some(128) // Keccak-256
            }
            fn min_num_variables(&self) -> usize {
                self.fold
            }
            fn build_witness(&self, tables: Vec<Table<F>>) -> Witness<F> {
                L::<$ef>::new_witness(tables, self.fold)
            }
            fn committed_table<'a>(&self, d: &'a WhirProverData<F, $ef, ValMmcs, L<$ef>>, i: usize) -> &'a Table<F> {
                d.table(i)
            }
        }
    };
}
wcfg!(BinomialExtensionField<F, 2>);
wcfg!(BinomialExtensionField<F, 5>);

#[derive(Clone, Copy)]
struct Opt {
    rate: usize,
    fold: usize,
    pow: usize,
    target: usize,
    assume: SecurityAssumption,
}

/// rates of the codewords committed after each round: +(fold - 1) per round (p3-multi-stark's WHIR tests)
fn rates(nv: usize, ff: &FoldingFactor, start: usize) -> Vec<usize> {
    let s = ff.compute_folding_schedule(nv).expect("folding schedule");
    let mut r = start;
    s.iter().take(s.len() - 1).map(|&f| {
        r += f - 1;
        r
    }).collect()
}

fn pcs_for<EF: p3_field::ExtensionField<F> + p3_field::TwoAdicField>(shapes: &[TableShape], o: &Opt) -> Pcs<EF>
where
    Pcs<EF>: Sized,
{
    let (nv, _) = plan_stacked_layout(shapes);
    let ff = FoldingFactor::Constant(o.fold);
    let params = ProtocolParameters {
        security_level: o.target,
        pow_bits: o.pow,
        round_log_inv_rates: rates(nv, &ff, o.rate),
        folding_factor: ff,
        soundness_type: o.assume,
        starting_log_inv_rate: o.rate,
    };
    Pcs::<EF>::new(WhirConfig::new(nv, params).expect("WHIR config"), Dft::default(), mmcs(0))
}

fn stats(v: &mut [f64]) -> String {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n == 0 {
        return "null".into();
    }
    format!("{{\"n\": {n}, \"p50_ms\": {:.3}, \"p99_ms\": {:.3}, \"max_ms\": {:.3}}}", v[n / 2], v[((n - 1) as f64 * 0.99) as usize], v[n - 1])
}

macro_rules! run {
    ($ef:ty, $o:expr, $op:expr, $name:expr, $st:expr, $w:expr, $np:expr, $nv:expr, $nadv:expr) => {{
        let (o, op, name, st, w): (Opt, u8, &str, &[u8], &[u8]) = ($o, $op, $name, $st, $w);
        let mut p = pqzh::Params::DEFAULT;
        p.max_proof = usize::MAX;
        let b = rel::build(op, st, Some(w), true, &p).expect("build");
        let airs: Vec<&PqzhAir> = b.airs.iter().collect();
        let traces = b.traces.as_ref().unwrap();
        let logh: Vec<usize> = traces.iter().map(|t| t.height().trailing_zeros() as usize).collect();
        use p3_air::BaseAir;
        use p3_matrix::Matrix;
        let main: Vec<TableShape> = b.airs.iter().zip(&logh).map(|(a, &h)| TableShape::new(h, BaseAir::<F>::width(a))).collect();
        let pre: Vec<TableShape> = b
            .airs
            .iter()
            .zip(&logh)
            .filter(|(a, _)| BaseAir::<F>::preprocessed_width(*a) > 0)
            .map(|(a, &h)| TableShape::new(h, BaseAir::<F>::preprocessed_width(a)))
            .collect();
        let cfg = WCfg::<$ef> { pcs: pcs_for::<$ef>(&main, &o), pre: pcs_for::<$ef>(&pre, &o), fold: o.fold };
        let (pk, vk) = setup(&cfg, &airs, &mut BeChallenger::new(&[0; 32])).expect("setup");
        let seed = rel::stmt_digest(op, st);
        let vi = VerifierInstances::new(b.airs.iter().zip(&logh).map(|(a, &h)| VerifierInstance::new(a, &vk, h, &[])).collect());
        let rep = security_report(&cfg, &vi).expect("security report");
        let mut terms: Vec<(String, f64)> = rep.terms().iter().map(|t| (format!("{}{}", t.label, t.component.map(|c| format!(" / {c}")).unwrap_or_default()), t.bits.bits())).collect();
        terms.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        let bits = rep.security_bits();
        let mut pf = Vec::new();
        let mut tp = Vec::new();
        let mut peak = 0;
        for _ in 0..$np.max(1) {
            let inst = ProverInstances::new(
                b.airs.iter().zip(traces).map(|(a, t)| ProverInstance::new(a, Table::new(t.clone().transpose()), &pk, &[])).collect(),
            );
            LIVE.store(0, Ordering::Relaxed);
            PEAK.store(0, Ordering::Relaxed);
            ARMED.store(true, Ordering::Relaxed);
            let t0 = Instant::now();
            let proof = prove(&cfg, inst, o.pow, &mut BeChallenger::new(&seed)).expect("prove");
            tp.push(t0.elapsed().as_secs_f64() * 1e3);
            ARMED.store(false, Ordering::Relaxed);
            peak = peak.max(PEAK.load(Ordering::Relaxed));
            pf = enc::to_vec(&proof).expect("encode");
        }
        let check = |s: &[u8], bytes: &[u8]| -> bool {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let Ok(bb) = rel::build(op, s, None, false, &p) else { return false };
                let Ok((proof, rest)) = enc::take_from_bytes::<MultiStarkProof<WCfg<$ef>>>(bytes) else { return false };
                let vi = VerifierInstances::new(bb.airs.iter().zip(&logh).map(|(a, &h)| VerifierInstance::new(a, &vk, h, &[])).collect());
                rest.is_empty() && verify(&cfg, vi, &proof, o.pow, &mut BeChallenger::new(&rel::stmt_digest(op, s))).is_ok()
            }))
            .unwrap_or(false)
        };
        let mut tv = Vec::new();
        for _ in 0..$nv {
            let t0 = Instant::now();
            assert!(check(st, &pf), "honest verify");
            tv.push(t0.elapsed().as_secs_f64() * 1e3);
        }
        let mut r = R(0x9E3779B97F4A7C15 ^ op as u64);
        let (mut acc, mut ta) = (0, Vec::new());
        for k in 0..KINDS.len() {
            for _ in 0..$nadv {
                // "other_proof": the honest proof of the same statement with a flipped byte stands in (no second proof)
                let (ms, mp) = mutate(k, op, st, &pf, &pf[..pf.len() / 2], &mut r);
                let t0 = Instant::now();
                acc += check(&ms, &mp) as usize;
                ta.push(t0.elapsed().as_secs_f64() * 1e3);
            }
        }
        println!(
            "{{\"rel\": \"{name}\", \"ext\": {}, \"rate\": {}, \"fold\": {}, \"pow\": {}, \"target\": {}, \"assume\": \"{:?}\", \"bits\": {:?}, \"binding\": {:?}, \"terms\": {:?}, \"stacked_vars\": {}, \"proof_bytes\": {}, \"prove\": {}, \"peak_heap_mb\": {:.1}, \"verify_honest\": {}, \"verify_adversarial\": {}, \"adv_cases\": {}, \"accepted\": {acc}}}",
            <$ef as p3_field::BasedVectorSpace<F>>::DIMENSION, o.rate, o.fold, o.pow, o.target, o.assume, bits, terms.first(), &terms[..terms.len().min(6)],
            plan_stacked_layout(&main).0, pf.len(), stats(&mut tp), peak as f64 / 1048576.0, stats(&mut tv), stats(&mut ta), ta.len()
        );
    }};
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let get = |k: &str| a.iter().position(|x| x == k).and_then(|i| a.get(i + 1)).map(|s| s.as_str());
    let num = |k: &str, d: usize| get(k).map_or(d, |s| s.parse().unwrap());
    let o = Opt {
        rate: num("--rate", 1),
        fold: num("--fold", 4),
        pow: num("--pow", 16),
        target: num("--target", 128),
        assume: match get("--assume").unwrap_or("johnson") {
            "unique" => SecurityAssumption::UniqueDecoding,
            "capacity" => SecurityAssumption::CapacityBound,
            _ => SecurityAssumption::JohnsonBound,
        },
    };
    let ext = num("--ext", 5);
    let (np, nv, nadv) = (num("--np", 2), num("--nv", 50), num("--nadv", 4));
    let s = client::setup();
    let rels: Vec<(u8, &str, &[u8], &[u8])> = match get("--rel").unwrap_or("both") {
        "reg" => vec![(OP_REGISTER, "R_REG", &s.reg_stmt, &s.reg_wit)],
        "tx" => vec![(OP_TRANSFER, "R_TX", &s.tx_stmt, &s.tx_wit)],
        _ => vec![(OP_REGISTER, "R_REG", &s.reg_stmt, &s.reg_wit), (OP_TRANSFER, "R_TX", &s.tx_stmt, &s.tx_wit)],
    };
    for (op, name, st, w) in rels {
        if ext == 2 {
            run!(BinomialExtensionField<F, 2>, o, op, name, st, w, np, nv, nadv);
        } else {
            run!(BinomialExtensionField<F, 5>, o, op, name, st, w, np, nv, nadv);
        }
    }
}
