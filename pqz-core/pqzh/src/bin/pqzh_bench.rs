//! PQZH bench: proof bytes and breakdown, prove time, honest and adversarial verify p50 / p99, peak heap.
//!   pqzh_bench [--rel reg|tx|both] [--np N] [--nv N] [--nadv N] [--blowup L] [--queries Q] [--arity A]
//!              [--final F] [--pow B] [--cap H] [--mvw W] [--zk] [--ext5] [--max-proof N] [--sizes-only] [--dump DIR]
//! Prints JSON lines. Run under scripts/capped.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::time::Instant;

use pqzh::client::{KINDS, R, mutate};
use pqzh::{OP_REGISTER, OP_TRANSFER, Params, client, prove, rel, verify};

struct Track;
static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);
unsafe impl GlobalAlloc for Track {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() && ARMED.load(Ordering::Relaxed) {
            let v = LIVE.fetch_add(l.size() as isize, Ordering::Relaxed) + l.size() as isize;
            if v > 0 {
                PEAK.fetch_max(v as usize, Ordering::Relaxed);
            }
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if ARMED.load(Ordering::Relaxed) {
            LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        }
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static G: Track = Track;
fn arm() {
    LIVE.store(0, Ordering::Relaxed);
    PEAK.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
}
fn disarm() -> usize {
    ARMED.store(false, Ordering::Relaxed);
    PEAK.load(Ordering::Relaxed)
}

fn stats(v: &mut [f64]) -> String {
    if v.is_empty() {
        return "null".into();
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    let mean = v.iter().sum::<f64>() / n as f64;
    format!(
        "{{\"n\": {n}, \"mean_ms\": {mean:.3}, \"p50_ms\": {:.3}, \"p99_ms\": {:.3}, \"max_ms\": {:.3}}}",
        v[n / 2],
        v[((n - 1) as f64 * 0.99) as usize],
        v[n - 1]
    )
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let get = |k: &str| a.iter().position(|x| x == k).and_then(|i| a.get(i + 1)).map(|s| s.as_str());
    let num = |k: &str, d: usize| get(k).map_or(d, |s| s.parse().unwrap());
    let mut p = Params::DEFAULT;
    p.log_blowup = num("--blowup", p.log_blowup);
    p.num_queries = num("--queries", p.num_queries);
    p.max_log_arity = num("--arity", p.max_log_arity);
    p.log_final_poly_len = num("--final", p.log_final_poly_len);
    p.query_pow_bits = num("--pow", p.query_pow_bits);
    p.cap_height = num("--cap", p.cap_height);
    p.mv_width = num("--mvw", p.mv_width);
    p.zk = a.iter().any(|x| x == "--zk");
    p.ext5 = a.iter().any(|x| x == "--ext5");
    p.max_proof = num("--max-proof", p.max_proof); // measurement only: verify proofs above the 160 KB limit
    let sizes_only = a.iter().any(|x| x == "--sizes-only");
    let (np, nv, nadv) = (num("--np", 3), num("--nv", 50), num("--nadv", 4));
    let rels: Vec<(u8, &str)> = match get("--rel").unwrap_or("both") {
        "reg" => vec![(OP_REGISTER, "R_REG")],
        "tx" => vec![(OP_TRANSFER, "R_TX")],
        _ => vec![(OP_REGISTER, "R_REG"), (OP_TRANSFER, "R_TX")],
    };
    println!(
        "{{\"params\": {{\"log_blowup\": {}, \"queries\": {}, \"max_log_arity\": {}, \"log_final_poly_len\": {}, \"query_pow_bits\": {}, \"cap_height\": {}, \"mv_width\": {}, \"zk\": {}, \"ext5\": {}}}}}",
        p.log_blowup, p.num_queries, p.max_log_arity, p.log_final_poly_len, p.query_pow_bits, p.cap_height, p.mv_width, p.zk, p.ext5
    );
    std::panic::set_hook(Box::new(|_| {})); // verify counts caught panics; keep stderr quiet
    let s = client::setup();
    // a second statement of each relation for "other_proof": another key (R_REG) / another salt-free prefix (R_TX)
    for (op, name) in rels {
        let (st, w) = if op == OP_REGISTER { (&s.reg_stmt, &s.reg_wit) } else { (&s.tx_stmt, &s.tx_wit) };
        let mut st2 = st.clone();
        st2[0] ^= 0x80; // same witness, other statement prefix: a valid proof of a different statement
        let mut pt = Vec::new();
        let mut tp = Vec::new();
        let mut peak_p = 0;
        for i in 0..np.max(1) {
            arm();
            let t = Instant::now();
            pt = prove(op, st, w, [i as u8; 32], &p).expect("prove");
            tp.push(t.elapsed().as_secs_f64() * 1e3);
            peak_p = peak_p.max(disarm());
        }
        let bd: Vec<String> = rel::breakdown(&pt, &p).iter().map(|(k, v)| format!("\"{k}\": {v}")).collect();
        println!(
            "{{\"rel\": \"{name}\", \"proof_bytes\": {}, \"fnv_last\": \"{:08x}\", \"within_max_proof\": {}, \"breakdown\": {{{}}}}}",
            pt.len(),
            pt.iter().fold(2166136261u32, |h, &b| (h ^ b as u32).wrapping_mul(16777619)),
            pt.len() <= rel::MAX_PROOF,
            bd.join(", ")
        );
        println!("{{\"rel\": \"{name}\", \"timing\": \"prove\", \"stats\": {}, \"peak_heap_mb\": {:.1}}}", stats(&mut tp), peak_p as f64 / 1048576.0);
        if sizes_only {
            continue;
        }
        let ok_size = pt.len() <= p.max_proof;
        let other = prove(op, &st2, w, [9; 32], &p).expect("prove other");
        if let Some(d) = get("--dump") {
            // proofs for the wasm verifier (wasm/run_wasm.mjs verify-only mode)
            std::fs::write(format!("{d}/{name}.proof"), &pt).unwrap();
            std::fs::write(format!("{d}/{name}.other"), &other).unwrap();
        }
        let mut tv = Vec::new();
        arm();
        for _ in 0..nv {
            let t = Instant::now();
            let ok = verify(op, st, &pt, &p);
            tv.push(t.elapsed().as_secs_f64() * 1e3);
            assert_eq!(ok, ok_size, "honest verify");
        }
        let peak_v = disarm();
        println!("{{\"rel\": \"{name}\", \"timing\": \"verify_honest\", \"stats\": {}, \"peak_heap_mb\": {:.1}}}", stats(&mut tv), peak_v as f64 / 1048576.0);
        let mut r = R(0x9E3779B97F4A7C15 ^ op as u64);
        let mut tall = Vec::new();
        for k in 0..KINDS.len() {
            let mut tk = Vec::new();
            let mut acc = 0;
            let p0 = rel::VERIFY_PANICS.load(Ordering::Relaxed);
            for _ in 0..nadv {
                let (ms, mp) = mutate(k, op, st, &pt, &other, &mut r);
                let t = Instant::now();
                acc += verify(op, &ms, &mp, &p) as usize;
                tk.push(t.elapsed().as_secs_f64() * 1e3);
            }
            tall.extend_from_slice(&tk);
            println!("{{\"rel\": \"{name}\", \"kind\": \"{}\", \"cases\": {nadv}, \"accepted\": {acc}, \"panics\": {}, \"stats\": {}}}", KINDS[k], rel::VERIFY_PANICS.load(Ordering::Relaxed) - p0, stats(&mut tk));
            assert_eq!(acc, 0, "mutated input accepted");
        }
        println!("{{\"rel\": \"{name}\", \"timing\": \"verify_adversarial\", \"stats\": {}}}", stats(&mut tall));
    }
}
