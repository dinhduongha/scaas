//! PQZH bench: proof bytes and breakdown, prove time, honest and adversarial verify p50 / p99, peak heap.
//!   pqzh_bench [--rel reg|tx|both] [--np N] [--nv N] [--nadv N] [--blowup L] [--queries Q] [--arity A]
//!              [--final F] [--pow B] [--cap H] [--mvw W] [--zk] [--sizes-only]
//! Prints JSON lines. Run under scripts/capped.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::time::Instant;

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

/// xorshift for mutations (independent of the setup stream)
struct R(u64);
impl R {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

const KINDS: [&str; 12] = [
    "bitflip", "byte_set", "random_bytes", "truncate", "extend", "stmt_coeff", "stmt_oob", "stmt_prefix",
    "stmt_tail", "other_proof", "field_noncanon", "empty",
];

/// mutated (statement, proof) of kind k
fn mutate(k: usize, op: u8, st: &[u8], pf: &[u8], other: &[u8], r: &mut R) -> (Vec<u8>, Vec<u8>) {
    let (mut s, mut p) = (st.to_vec(), pf.to_vec());
    let body = rel::PREFIX + if op == OP_REGISTER { 32 } else { 0 };
    let ncoef = (s.len() - body - if op == OP_TRANSFER { 8 } else { 0 }) / 8;
    match KINDS[k] {
        "bitflip" => {
            let b = (r.next() % (8 * p.len() as u64)) as usize;
            p[b / 8] ^= 1 << (b % 8);
        }
        "byte_set" => {
            let i = (r.next() % p.len() as u64) as usize;
            p[i] = p[i].wrapping_add(1 + (r.next() % 255) as u8);
        }
        "random_bytes" => p.iter_mut().for_each(|b| *b = r.next() as u8),
        "truncate" => p.truncate(p.len() - 1 - (r.next() % 64) as usize),
        "extend" => p.extend((0..1 + r.next() % 64).map(|_| r.next() as u8)),
        "stmt_coeff" => {
            // +1 mod q on one coefficient (stays canonical)
            let o = body + 8 * (r.next() as usize % ncoef);
            let v = u64::from_be_bytes(s[o..o + 8].try_into().unwrap());
            s[o..o + 8].copy_from_slice(&((v + 1) % pqzh::ring::Q).to_be_bytes());
        }
        "stmt_oob" => {
            let o = body + 8 * (r.next() as usize % ncoef);
            let v = u64::from_be_bytes(s[o..o + 8].try_into().unwrap());
            s[o..o + 8].copy_from_slice(&(v + pqzh::ring::Q).to_be_bytes());
        }
        "stmt_prefix" => s[(r.next() % rel::PREFIX as u64) as usize] ^= 1 << (r.next() % 8),
        "stmt_tail" => {
            // R_REG: message byte; R_TX: fee
            let i = if op == OP_REGISTER { rel::PREFIX + (r.next() % 32) as usize } else { s.len() - 1 - (r.next() % 8) as usize };
            s[i] ^= 1 << (r.next() % 8);
        }
        "other_proof" => p = other.to_vec(),
        "field_noncanon" => {
            // add p to one 8-byte-aligned little-endian word near the end (a field element of the FRI final poly)
            let i = p.len() - 8 * (1 + (r.next() % 16) as usize);
            let w = u64::from_le_bytes(p[i..i + 8].try_into().unwrap());
            p[i..i + 8].copy_from_slice(&w.wrapping_add(0xFFFF_FFFF_0000_0001).to_le_bytes());
        }
        _ => p.clear(),
    }
    (s, p)
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
    let sizes_only = a.iter().any(|x| x == "--sizes-only");
    let (np, nv, nadv) = (num("--np", 3), num("--nv", 50), num("--nadv", 4));
    let rels: Vec<(u8, &str)> = match get("--rel").unwrap_or("both") {
        "reg" => vec![(OP_REGISTER, "R_REG")],
        "tx" => vec![(OP_TRANSFER, "R_TX")],
        _ => vec![(OP_REGISTER, "R_REG"), (OP_TRANSFER, "R_TX")],
    };
    println!(
        "{{\"params\": {{\"log_blowup\": {}, \"queries\": {}, \"max_log_arity\": {}, \"log_final_poly_len\": {}, \"query_pow_bits\": {}, \"cap_height\": {}, \"mv_width\": {}, \"zk\": {}}}}}",
        p.log_blowup, p.num_queries, p.max_log_arity, p.log_final_poly_len, p.query_pow_bits, p.cap_height, p.mv_width, p.zk
    );
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
        let bd: Vec<String> = rel::breakdown(&pt).iter().map(|(k, v)| format!("\"{k}\": {v}")).collect();
        println!(
            "{{\"rel\": \"{name}\", \"proof_bytes\": {}, \"within_max_proof\": {}, \"breakdown\": {{{}}}}}",
            pt.len(),
            pt.len() <= rel::MAX_PROOF,
            bd.join(", ")
        );
        println!("{{\"rel\": \"{name}\", \"timing\": \"prove\", \"stats\": {}, \"peak_heap_mb\": {:.1}}}", stats(&mut tp), peak_p as f64 / 1048576.0);
        if sizes_only {
            continue;
        }
        let ok_size = pt.len() <= rel::MAX_PROOF;
        let other = prove(op, &st2, w, [9; 32], &p).expect("prove other");
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
            for _ in 0..nadv {
                let (ms, mp) = mutate(k, op, st, &pt, &other, &mut r);
                let t = Instant::now();
                acc += verify(op, &ms, &mp, &p) as usize;
                tk.push(t.elapsed().as_secs_f64() * 1e3);
            }
            tall.extend_from_slice(&tk);
            println!("{{\"rel\": \"{name}\", \"kind\": \"{}\", \"cases\": {nadv}, \"accepted\": {acc}, \"stats\": {}}}", KINDS[k], stats(&mut tk));
            assert_eq!(acc, 0, "mutated input accepted");
        }
        println!("{{\"rel\": \"{name}\", \"timing\": \"verify_adversarial\", \"stats\": {}}}", stats(&mut tall));
    }
}
