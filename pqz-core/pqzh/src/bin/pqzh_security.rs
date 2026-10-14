//! PQZH soundness sweep (p3-security 0.8.0): proven (unique-decoding / Johnson list-decoding) and conjectured
//! (random-words, ePrint 2025/2010) bits of the R_REG / R_TX batch STARKs over blowup x FRI arity x queries, from the
//! real AIR shapes (constraints, degrees, quotient chunks, batched openings, LogUp interactions); then, with
//! --measure, the proof bytes at the smallest query count reaching the target in each regime.
//!   pqzh_security [--target 128] [--pow 16] [--ext 2|5] [--zk] [--measure] [--batch-pow B] [--ood-pow B] [--lookup-pow B]
//! --ext 5: Goldilocks^5 challenge field (Params::ext5; plain mode). Prints JSON lines. Run under scripts/capped.
//!   pqzh_security --whir --ext 2|5 --rate R [--fold K] [--pow B] [--target T] [--unique] [--ell L] [--mask-rate M]
//! With --vars N --claims C: the terms of one HVZK-WHIR opening of that shape only (no proof).
//! ZK WHIR (src/whirpcs.rs): proves each relation once to read the openings' shapes, then prints every soundness
//! term (bits) and their union bound (docs/research/pqzh-zk-whir.md §5.5).

use p3_air::BaseAir;
use p3_air::symbolic::AirLayout;
use p3_batch_stark::ProverData;
use p3_batch_stark::num_batched_openings;
use p3_batch_stark::symbolic::{get_log_num_quotient_chunks_for_domain, get_max_constraint_degree, get_symbolic_constraints};
use p3_field::PrimeCharacteristicRing;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_lookup::LogUpGadget;
use p3_security::fri::FriRegime;
use p3_security::grinding::GrindingSites;
use p3_security::logup::{LogUpAir, security_term};
use p3_security::shape::{InstanceShape, StarkAirParams};
use p3_security::stark::{conjectured_security_report, proven_security_report};
use p3_uni_stark::{OpeningShape, StarkGenericConfig};

use pqzh::config::Challenge;
use pqzh::ring::F;
use pqzh::{OP_REGISTER, OP_TRANSFER, Params, client, prove, rel};

struct Shape {
    air: StarkAirParams,
    log_n: usize,
    batched: usize,
    logup: LogUpAir,
    widths: Vec<usize>,
}

/// AIR shape of one relation as the batch prover lays it out (same calls as ProverData / prove_batch).
fn shape(op: u8, stmt: &[u8], p: &Params, ext: usize) -> Shape {
    let b = rel::build(op, stmt, None, false, p).unwrap();
    let zk = p.zk as usize;
    let deg = rel::degrees(&b, p.zk);
    let cfg = p.plain(&[0; 32]);
    // lookups only (the plain config: trace degrees without the ZK bit)
    let pd = ProverData::from_airs_and_degrees(&cfg, &b.airs, &deg.iter().map(|d| d - zk).collect::<Vec<_>>()).unwrap();
    let gadget = LogUpGadget::new();
    let opening = if p.zk { OpeningShape::hiding(p.random_codewords()) } else { OpeningShape::new() };
    let (mut ncons, mut maxdeg, mut chunks, mut batched, mut width) = (0, 0, 0, 0, 0);
    let mut denoms = 0f64; // sum over AIRs of interactions * rows
    let mut widths = vec![];
    for (i, air) in b.airs.iter().enumerate() {
        let lk = &pd.common.lookups[i];
        let layout = AirLayout::from_air(air);
        let n = 1usize << (deg[i] - zk);
        let (bc, ec) = get_symbolic_constraints::<F, Challenge, _, _>(air, layout, lk, &gadget);
        ncons += bc.len() + ec.len();
        maxdeg = maxdeg.max(get_max_constraint_degree::<F, Challenge, _, _>(air, layout, n, lk, &gadget));
        let dom = TwoAdicMultiplicativeCoset::new(F::ONE, deg[i] - zk).unwrap(); // TwoAdicFriPcs::natural_domain_for_degree
        let lc = get_log_num_quotient_chunks_for_domain::<F, Challenge, _, _>(air, layout, dom, lk, zk, &gadget);
        let c = 1 << (lc + zk);
        chunks = usize::max(chunks, c);
        let next = !air.main_next_row_columns().is_empty();
        batched += num_batched_openings(air.width(), next, air.preprocessed_width(), false, c, lk.len(), ext, opening);
        let inter: usize = lk.iter().map(|l| l.elements.len()).sum();
        width = lk.iter().flat_map(|l| l.elements.iter().map(|e| e.len())).fold(width, usize::max);
        denoms += inter as f64 * (1u64 << deg[i]) as f64;
        widths.push(air.width());
    }
    let log_n = *deg.iter().max().unwrap();
    Shape {
        air: StarkAirParams { num_constraints: ncons, max_constraint_degree: maxdeg, num_quotient_chunks: chunks, max_combo: 2 },
        log_n,
        batched,
        logup: LogUpAir { num_interactions: (denoms / (1u64 << log_n) as f64).ceil() as usize, max_message_width: width },
        widths,
    }
}

/// (bits, binding term) for the proven (best of unique / list decoding) and the conjectured regime
fn reports(s: &Shape, ext: usize, lb: usize, arity: usize, q: usize, pow: usize, g: &GrindingSites) -> [(f64, &'static str); 2] {
    let regime = FriRegime { log_blowup: lb, num_queries: q, log_final_poly_len: 3, max_log_arity: arity, commit_pow_bits: 0, query_pow_bits: pow };
    let inst = InstanceShape { log_trace_length: s.log_n, modulus_bits: 64 * ext, collision_resistance: 128, num_batched_functions: s.batched };
    let lt: Vec<_> = security_term(&s.logup, &inst, g).into_iter().collect();
    let pr = proven_security_report(&regime, &s.air, &inst, &lt, g);
    let cr = conjectured_security_report(&regime, &s.air, &inst, &lt, g);
    [(pr.security_bits(), pr.binding().1.label), (cr.security_bits(), cr.binding().label)]
}

/// ZK WHIR bits per term, union-composed: STARK terms (ALI, DEEP, LogUp) as Schwartz-Zippel over the extracted
/// polynomials (list size 1: the WHIR openings carry the decoding regime, as a PCS-compiled PIOP), the claim batching
/// β, each HVZK-WHIR opening (`WhirUniPcs::opening_terms`), Keccak-256 collision.
fn whir_bits<EF: p3_field::ExtensionField<F> + p3_field::TwoAdicField>(p: &Params, ext: usize)
where
    rand::distr::StandardUniform: rand::distr::Distribution<EF>,
{
    use p3_security::air::composition_error;
    use p3_security::deep::deep_ali_error;

    use pqzh::whirpcs::{LAST_OPENINGS, union_bits};
    let fb = EF::bits() - 1;
    let cfg = p.whir_ext::<EF>(&[0; 32], [0; 32]);
    let s = client::setup();
    for (op, name, st, w) in [(OP_REGISTER, "R_REG", &s.reg_stmt, &s.reg_wit), (OP_TRANSFER, "R_TX", &s.tx_stmt, &s.tx_wit)] {
        let sh = shape(op, st, p, ext);
        prove(op, st, w, [1; 32], p).expect("prove");
        let opens = LAST_OPENINGS.lock().unwrap().clone();
        let inst = InstanceShape { log_trace_length: sh.log_n, modulus_bits: fb, collision_resistance: 128, num_batched_functions: 1 };
        let mut terms: Vec<(String, f64)> = vec![
            ("ali".into(), composition_error(sh.air.num_constraints, 1.0, fb).bits()),
            ("deep".into(), deep_ali_error(&sh.air, &inst, 1.0).bits()),
            ("collision".into(), 128.0),
        ];
        if let Some(t) = security_term(&sh.logup, &inst, &GrindingSites::NONE) {
            terms.push(("logup".into(), t.bits.bits()));
        }
        let values: usize = opens.iter().map(|o| o.2).sum();
        terms.push(("claim-beta".into(), fb as f64 - (values as f64).log2()));
        let mut rows = vec![];
        for (i, &(n, claims, _)) in opens.iter().enumerate() {
            let t = cfg.pcs().opening_terms(n, claims).expect("terms");
            let u = union_bits(t.iter().map(|x| x.1));
            let mut tt: Vec<_> = t.iter().filter(|x| x.1.is_finite()).cloned().collect();
            tt.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
            rows.push(format!("{{\"round\": {i}, \"vars\": {n}, \"claims\": {claims}, \"bits\": {u:.2}, \"weakest\": {:?}, \"{}\": 0}}", &tt[..tt.len().min(4)], t.iter().find(|x| !x.1.is_finite()).unwrap().0));
            terms.push((format!("whir-opening-{i}"), u));
        }
        let total = union_bits(terms.iter().map(|x| x.1));
        terms.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        println!(
            "{{\"rel\": \"{name}\", \"ext\": {ext}, \"whir\": \"{:?}\", \"bits_composed\": {total:.2}, \"terms\": {:?}, \"openings\": [{}]}}",
            p.whir.unwrap(), terms.iter().map(|(k, v)| (k.as_str(), (v * 100.0).round() / 100.0)).collect::<Vec<_>>(), rows.join(", ")
        );
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.iter().any(|x| x == "--whir") {
        let get = |k: &str| a.iter().position(|x| x == k).and_then(|i| a.get(i + 1)).map(|s| s.parse::<usize>().unwrap());
        let d = pqzh::config::WhirParams::DEFAULT;
        let mut p = Params::DEFAULT;
        let ext = get("--ext").unwrap_or(5);
        (p.zk, p.ext5, p.max_proof) = (true, ext == 5, usize::MAX);
        p.whir = Some(pqzh::config::WhirParams {
            rate: get("--rate").unwrap_or(d.rate),
            fold: get("--fold").unwrap_or(d.fold),
            pow: get("--pow").unwrap_or(d.pow),
            target: get("--target").unwrap_or(d.target),
            unique: a.iter().any(|x| x == "--unique"),
            ell_zk: get("--ell").unwrap_or(d.ell_zk),
            mask_rate: get("--mask-rate").unwrap_or(d.mask_rate),
        });
        // one opening's terms only (no proof): --vars N --claims C
        if let (Some(n), Some(c)) = (get("--vars"), get("--claims")) {
            let t = if ext == 5 {
                p.whir_ext::<pqzh::config::Challenge5>(&[0; 32], [0; 32]).pcs().opening_terms(n, c)
            } else {
                p.whir_ext::<Challenge>(&[0; 32], [0; 32]).pcs().opening_terms(n, c)
            };
            match t {
                Ok(t) => println!(
                    "{{\"ext\": {ext}, \"whir\": \"{:?}\", \"vars\": {n}, \"claims\": {c}, \"bits\": {:.2}, \"terms\": {:?}}}",
                    p.whir.unwrap(),
                    pqzh::whirpcs::union_bits(t.iter().map(|x| x.1)),
                    t
                ),
                Err(e) => println!("{{\"ext\": {ext}, \"whir\": \"{:?}\", \"vars\": {n}, \"error\": {e:?}}}", p.whir.unwrap()),
            }
            return;
        }
        if ext == 5 { whir_bits::<pqzh::config::Challenge5>(&p, 5) } else { whir_bits::<Challenge>(&p, 2) }
        return;
    }
    let get = |k: &str| a.iter().position(|x| x == k).and_then(|i| a.get(i + 1)).map(|s| s.parse::<usize>().unwrap());
    let target = get("--target").unwrap_or(128) as f64;
    let pow = get("--pow").unwrap_or(16);
    let ext = get("--ext").unwrap_or(2);
    let measure = a.iter().any(|x| x == "--measure");
    // model-only grinding at the STARK's own sites (the prototype config grinds none of them)
    let g = GrindingSites {
        batch_combination: get("--batch-pow").unwrap_or(0),
        out_of_domain: get("--ood-pow").unwrap_or(0),
        lookup_challenge: get("--lookup-pow").unwrap_or(0),
        ..GrindingSites::NONE
    };
    assert!(!(measure && g != GrindingSites::NONE), "--measure: the prototype grinds only before the FRI queries");
    assert!(ext == 2 || ext == 5, "--ext 2 or 5");
    let mut p = Params::DEFAULT;
    p.zk = a.iter().any(|x| x == "--zk");
    p.query_pow_bits = pow;
    p.ext5 = ext == 5;
    let s = client::setup();
    for (op, name, st, w) in [(OP_REGISTER, "R_REG", &s.reg_stmt, &s.reg_wit), (OP_TRANSFER, "R_TX", &s.tx_stmt, &s.tx_wit)] {
        let sh = shape(op, st, &p, ext);
        println!(
            "{{\"rel\": \"{name}\", \"ext\": {ext}, \"zk\": {}, \"grinding\": \"{g:?}\", \"shape\": {{\"num_constraints\": {}, \"max_constraint_degree\": {}, \"max_quotient_chunks\": {}, \"log_trace\": {}, \"batched_functions\": {}, \"logup_interactions_per_row\": {}, \"logup_width\": {}, \"air_widths\": {:?}}}}}",
            p.zk, sh.air.num_constraints, sh.air.max_constraint_degree, sh.air.num_quotient_chunks, sh.log_n, sh.batched, sh.logup.num_interactions, sh.logup.max_message_width, sh.widths
        );
        // blowup 2 needs constraint degree <= 3; the quotient must fit: chunks <= blowup
        for lb in 1..=5usize {
            if sh.air.num_quotient_chunks > 1 << lb {
                continue;
            }
            for arity in [1usize, 2, 3, 4] {
                // best bits at a large query count = the field / batching / logup ceiling of the regime
                let [pc, cc] = reports(&sh, ext, lb, arity, 1000, pow, &g);
                let mut row = format!("{{\"rel\": \"{name}\", \"ext\": {ext}, \"zk\": {}, \"log_blowup\": {lb}, \"log_arity\": {arity}, \"pow\": {pow}", p.zk);
                row += &format!(
                    ", \"ceiling_proven\": {:.1}, \"ceiling_proven_binding\": \"{}\", \"ceiling_conjectured\": {:.1}, \"ceiling_conjectured_binding\": \"{}\"",
                    pc.0, pc.1, cc.0, cc.1
                );
                let mut need = [None, None];
                for q in 1..=400usize {
                    for (k, (bits, lab)) in reports(&sh, ext, lb, arity, q, pow, &g).into_iter().enumerate() {
                        if need[k].is_none() && bits >= target {
                            need[k] = Some((q, bits, lab));
                        }
                    }
                }
                for (k, tag) in ["proven", "conjectured"].into_iter().enumerate() {
                    match need[k] {
                        Some((q, bits, lab)) => {
                            row += &format!(", \"q_{tag}\": {q}, \"bits_{tag}\": {bits:.1}, \"binding_{tag}\": \"{lab}\"");
                            if measure {
                                let mut pm = p;
                                (pm.log_blowup, pm.max_log_arity, pm.num_queries) = (lb, arity, q);
                                let pf = prove(op, st, w, [1; 32], &pm).unwrap();
                                row += &format!(", \"bytes_{tag}\": {}", pf.len());
                            }
                        }
                        None => row += &format!(", \"q_{tag}\": null"),
                    }
                }
                // the prototype default (28 queries) at this setting
                let [pr, cr] = reports(&sh, ext, lb, arity, p.num_queries, pow, &g);
                row += &format!(", \"at_q{}\": {{\"proven\": {:.1}, \"conjectured\": {:.1}}}}}", p.num_queries, pr.0, cr.0);
                println!("{row}");
            }
        }
    }
}
