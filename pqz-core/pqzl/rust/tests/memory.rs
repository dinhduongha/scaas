//! Memory (plan D2, D6, Review Focus 3): a test-only counting allocator (this test binary's global allocator; the
//! crate has none) measures the peak heap per operation, and caps or denies allocations to show that exhaustion is
//! an error, never a panic or an abort: `prove`, `try_verify` and `try_verify_fast` = `Error::Memory` (never a
//! verdict false for the vector's proof), `verify` / `verify_fast` = false, and the `Ctx` stays usable (the next
//! uncapped call gives the honest result).
//!
//! Accounting is per thread (thread-locals, const-initialised: no allocation inside the allocator), so the test
//! harness's other threads do not disturb a measurement. `PQZL_MEM_TRACE=all` (or `=<bytes>`) prints a backtrace at
//! every denied allocation (of that size): an abort after the last one names an infallible allocation.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use pqzl::{Ctx, Error};

mod common;
use common::Row;

struct Counting;

thread_local! {
    /// bytes live on this thread (allocations minus frees; may go negative after freeing older memory)
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
    /// allocations made while counting
    static COUNT: Cell<u64> = const { Cell::new(0) };
    /// deny an allocation that would take LIVE above CAP
    static CAP: Cell<isize> = const { Cell::new(isize::MAX) };
    /// deny allocation number DENY (1-based; 0 = none)
    static DENY: Cell<u64> = const { Cell::new(0) };
    static DENIED: Cell<u64> = const { Cell::new(0) };
    /// inside the trace printer (its own allocations pass)
    static BUSY: Cell<bool> = const { Cell::new(false) };
}

/// may `n` more bytes (a block of `size` bytes) be allocated on this thread? (counts it if so)
fn admit(n: isize, size: usize) -> bool {
    let busy = BUSY.try_with(Cell::get).unwrap_or(true);
    if busy {
        return true;
    }
    let (live, cap) = (LIVE.with(Cell::get) + n, CAP.with(Cell::get));
    let k = COUNT.with(|c| {
        c.set(c.get() + 1);
        c.get()
    });
    if live > cap || k == DENY.with(Cell::get) {
        DENIED.with(|d| d.set(d.get() + 1));
        // BUSY first: reading the variable allocates, which must pass uncounted
        BUSY.with(|b| b.set(true));
        if std::env::var("PQZL_MEM_TRACE").is_ok_and(|v| v.parse() == Ok(size) || v == "all") {
            eprintln!("denied {size} B (+{n} B, allocation {k}):\n{}", std::backtrace::Backtrace::force_capture());
        }
        BUSY.with(|b| b.set(false));
        return false;
    }
    LIVE.with(|c| c.set(live));
    PEAK.with(|p| p.set(p.get().max(live)));
    true
}

fn release(n: isize) {
    if !BUSY.try_with(Cell::get).unwrap_or(true) {
        LIVE.with(|c| c.set(c.get() - n));
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if !admit(l.size() as isize, l.size()) {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        if !admit(l.size() as isize, l.size()) {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        release(l.size() as isize);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        if !admit(new as isize - l.size() as isize, new) {
            return std::ptr::null_mut();
        }
        let r = unsafe { System.realloc(p, l, new) };
        if r.is_null() {
            release(new as isize - l.size() as isize);
        }
        r
    }
}

#[global_allocator]
static A: Counting = Counting;

/// run `f` under a cap of `cap` bytes above the current live count and / or denying allocation `deny` (counted
/// from the start of `f`); (result, peak above the start, allocations, denials)
fn measure<R>(cap: Option<usize>, deny: u64, f: impl FnOnce() -> R) -> (R, usize, u64, u64) {
    let base = LIVE.with(Cell::get);
    PEAK.with(|p| p.set(base));
    COUNT.with(|c| c.set(0));
    DENIED.with(|d| d.set(0));
    DENY.with(|d| d.set(deny));
    CAP.with(|c| c.set(cap.map_or(isize::MAX, |n| base + n as isize)));
    let r = f();
    CAP.with(|c| c.set(isize::MAX));
    DENY.with(|d| d.set(0));
    let peak = (PEAK.with(Cell::get) - base) as usize;
    (r, peak, COUNT.with(Cell::get), DENIED.with(Cell::get))
}

/// one row per relation code (14), the first of the vectors
fn rows() -> Vec<Row> {
    let mut v: Vec<Row> = Vec::new();
    for r in common::pqzl_rows() {
        if !v.iter().any(|x| x.code == r.code) {
            v.push(r);
        }
    }
    v
}

const MIB: usize = 1 << 20;
/// the C core's arena peak for R_TX prove (research/pqzl-measure `layout-*` relfix run)
const C_TX_PROVE_PEAK: usize = 312_151_904;

/// peak heap per relation: prove / verify / verify_fast on a fresh `Ctx` (cold: the caches are built inside the
/// call) and again on the same `Ctx` (warm); R_TX prove (cold) within 2x the C arena peak (D6: informational up
/// to that)
#[test]
fn peak_per_op() {
    println!("size_of::<Ctx>() = {} B (the specialised verifier's fixed tables inline, the rest on the heap)", std::mem::size_of::<Ctx>());
    println!("peak_per_op (bytes; cold = fresh Ctx, the call builds A / keys / SV tables; warm = second call)");
    println!("{:<28} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12} {:>9}", "row", "prove cold", "prove warm",
             "verify cold", "verify warm", "fast cold", "fast warm", "allocs");
    let mut tx = 0;
    for r in rows() {
        let mut c = Ctx::new();
        let (p, pc, n, _) = measure(None, 0, || c.prove(r.op, &r.stmt, &r.wit, &r.rnd32));
        assert_eq!(p.as_deref(), Ok(&r.proof[..]), "{}", r.name);
        let (_, pw, _, _) = measure(None, 0, || c.prove(r.op, &r.stmt, &r.wit, &r.rnd32));
        let mut c = Ctx::new();
        let (ok, vc, _, _) = measure(None, 0, || c.verify(r.op, &r.stmt, &r.proof));
        assert!(ok, "{}", r.name);
        let (_, vw, _, _) = measure(None, 0, || c.verify(r.op, &r.stmt, &r.proof));
        let mut c = Ctx::new();
        let (ok, fc, _, _) = measure(None, 0, || c.verify_fast(r.op, &r.stmt, &r.proof));
        assert!(ok, "{}", r.name);
        let (_, fw, _, _) = measure(None, 0, || c.verify_fast(r.op, &r.stmt, &r.proof));
        println!("{:<28} {pc:>12} {pw:>12} {vc:>12} {vw:>12} {fc:>12} {fw:>12} {n:>9}", r.name);
        if r.code == 1 {
            tx = pc;
        }
    }
    println!("R_TX prove (cold) {tx} B = {}.{:02} x the C arena peak {C_TX_PROVE_PEAK} B (target <= 1.1, fails > 2)",
             tx / C_TX_PROVE_PEAK, tx % C_TX_PROVE_PEAK * 100 / C_TX_PROVE_PEAK);
    assert!(tx > 0 && tx <= 2 * C_TX_PROVE_PEAK);
}

/// the operation: Some(output = the honest one), None = out of memory (`Error::Memory`; the verifiers through
/// `try_verify` / `try_verify_fast`, where out of memory must never come back as the verdict false)
fn run(c: &mut Ctx, r: &Row, which: u8) -> Option<bool> {
    let out = match which {
        0 => c.prove(r.op, &r.stmt, &r.wit, &r.rnd32).map(|p| p == r.proof),
        1 => c.try_verify(r.op, &r.stmt, &r.proof),
        _ => c.try_verify_fast(r.op, &r.stmt, &r.proof),
    };
    match out {
        Ok(true) => Some(true),
        Err(Error::Memory) => None,
        Ok(false) => panic!("{} {}: not the honest result (an out-of-memory folded into the verdict?)", r.name, OPS[which as usize]),
        Err(e) => panic!("{} {}: {e:?}", r.name, OPS[which as usize]),
    }
}

/// the operation on `c` under `cap` / `deny`, then (if it ran out of memory) again without: (it gave the honest
/// result or the out-of-memory one, and the retry the honest one; allocations denied)
fn op(c: &mut Ctx, r: &Row, which: u8, cap: Option<usize>, deny: u64) -> (bool, u64) {
    let (out, _, _, denied) = measure(cap, deny, || run(c, r, which));
    (out.unwrap_or_else(|| run(c, r, which) == Some(true)), denied)
}

/// keygen, keypair_from_secret, enc_seed (two recipients), encrypt, through `c`'s methods or the free functions
type Keys = (pqzl::Key, pqzl::Key, Box<[u8; pqzl::POLYVEC_BYTES]>, pqzl::Enc, pqzl::Enc);

fn keys_all(mut c: Option<&mut Ctx>) -> Result<Keys, Error> {
    let (s1, s2) = ([5u8; 32], [6u8; 32]);
    let mut kg = |s: &[u8; 32]| c.as_mut().map_or_else(|| pqzl::keygen(s), |c| c.keygen(s));
    let (k1, k2) = (kg(&s1)?, kg(&s2)?);
    let pks = [&*k1.pk, &*k2.pk];
    let msgs = [[3u8; 16], [9u8; 16]];
    let (pk, e, x) = match c {
        Some(c) => {
            let pk = c.keypair_from_secret(&k1.s, &k1.e)?;
            let e = c.enc_seed(&pks, &msgs, &s1)?;
            let x = c.encrypt(&pks, &msgs, &e.r, &e.e1, &e.e2)?;
            (pk, e, x)
        }
        None => {
            let pk = pqzl::keypair_from_secret(&k1.s, &k1.e)?;
            let e = pqzl::enc_seed(&pks, &msgs, &s1)?;
            let x = pqzl::encrypt(&pks, &msgs, &e.r, &e.e1, &e.e2)?;
            (pk, e, x)
        }
    };
    Ok((k1, k2, pk, e, x))
}

/// the outputs as bytes (outside any measurement)
fn flat(r: Result<Keys, Error>) -> Result<Vec<u8>, Error> {
    let (k1, k2, pk, e, x) = r?;
    let mut out = [&k1.pk[..], &k2.pk[..], &pk[..], &e.u[..], &x.u[..]].concat();
    e.vs.iter().chain(&x.vs).for_each(|v| out.extend_from_slice(v));
    Ok(out)
}

const OPS: [&str; 3] = ["prove", "verify", "verify_fast"];

/// Review Focus 3. The brief's 64 MiB cap is above the Rust prover's R_TX peak (60 MiB cold, `peak_per_op`; the C
/// arena's is 298 MiB): under it R_TX prove succeeds with the vector's bytes and R_TXM8 (110 MiB) is
/// `Error::Memory`; under 32 MiB R_TX prove is `Error::Memory`; R_TX verify and verify_fast under half their peak
/// (at most 64 MiB) are `Error::Memory` through `try_verify` / `try_verify_fast` and false through the bool API;
/// after each failure the same `Ctx` gives the honest result. Then for every relation,
/// operation, cold and warm `Ctx`: caps at k / (C + 1) of the measured peak (k = 1 .. C) and the denial of single
/// allocations (each of the first F, then S spread over the rest) give the honest result or `Error::Memory` (the
/// verifiers: never false for the vector's proof), never a panic or an abort, and the same `Ctx` gives the honest result afterwards. C, F, S: 7, 16, 16
/// for verify / verify_fast, 3, 4, 4 for prove (`PQZL_MEM_SWEEP=C,F,S` for both); `PQZL_MEM_THREADS` workers
/// (default 6; accounting is per thread); `PQZL_MEM_ONLY=<text>[,<text>..]` only the items whose name contains one;
/// `PQZL_MEM_SWEEP=0,1000000000,0` denies every allocation in turn (exhaustive).
#[test]
fn exhaustion_is_error() {
    // the log names the settings it ran with (review round 2: the port's exhaustive logs did not)
    let set: Vec<String> = std::env::vars().filter(|(k, _)| k.starts_with("PQZL_MEM_")).map(|(k, v)| format!("{k}={v}")).collect();
    println!("PQZL_MEM_* settings: {}", if set.is_empty() { "none (the defaults)".to_string() } else { set.join(" ") });
    let rs = rows();
    let tx = rs.iter().find(|r| r.code == 1).unwrap();
    let m8 = rs.iter().find(|r| r.name == "M8-on").unwrap();
    // the caps: the brief's 64 / 32 MiB for the v3 set; for another set the R_TX prove's cold peak rounded up + 4 MiB
    // and half that (the same roles: R_TX fits, R_TXM8 and half the cap do not)
    let (hi, lo) = if pqzl::SET == "n2048-kmax1024" {
        (64, 32)
    } else {
        let (_, p, _, _) = measure(None, 0, || run(&mut Ctx::new(), tx, 0));
        let hi = p.div_ceil(MIB) + 4;
        println!("R_TX prove cold peak {p} B: caps {hi} / {} MiB", hi / 2);
        (hi, hi / 2)
    };
    for (r, cap, want_mem) in [(tx, hi, false), (m8, hi, true), (tx, lo, true)] {
        let mut c = Ctx::new();
        let (out, _, _, d) = measure(Some(cap * MIB), 0, || run(&mut c, r, 0));
        assert_eq!((out, d > 0), if want_mem { (None, true) } else { (Some(true), false) }, "{} prove, {cap} MiB", r.name);
        assert_eq!(run(&mut c, r, 0), Some(true));
        println!("{} prove cold under {cap} MiB: {}; the same Ctx then proves", r.name,
                 if want_mem { "Error::Memory" } else { "the vector's proof" });
    }
    for which in 1..3 {
        let (out, peak, _, _) = measure(None, 0, || run(&mut Ctx::new(), tx, which));
        assert_eq!(out, Some(true));
        let cap = (peak / 2).min(64 * MIB);
        let mut c = Ctx::new();
        let (out, _, _, d) = measure(Some(cap), 0, || run(&mut c, tx, which));
        assert!(out.is_none() && d > 0, "R_TX {} under {cap} B (peak {peak} B)", OPS[which as usize]);
        assert_eq!(run(&mut c, tx, which), Some(true));
        // the bool API under the same cap: false (and the Ctx accepts afterwards)
        let mut c = Ctx::new();
        let bool_api = |c: &mut Ctx| if which == 1 { c.verify(tx.op, &tx.stmt, &tx.proof) } else { c.verify_fast(tx.op, &tx.stmt, &tx.proof) };
        let (b, _, _, d) = measure(Some(cap), 0, || bool_api(&mut c));
        assert!(!b && d > 0);
        assert!(bool_api(&mut c));
        println!("R_TX {} cold under {cap} B (half its peak {peak} B): try_ = Error::Memory, bool = false; the same Ctx then accepts", OPS[which as usize]);
    }

    // the keys, free functions and Ctx methods (cold and warm Ctx): every allocation denied in turn
    for mode in 0..3 {
        let fresh = || {
            let mut c = Ctx::new();
            if mode == 2 {
                keys_all(Some(&mut c)).map(|_| ()).unwrap();
            }
            c
        };
        fn ctx(c: &mut Ctx, mode: usize) -> Option<&mut Ctx> {
            (mode > 0).then_some(c)
        }
        let want = flat(keys_all(None)).unwrap();
        let mut c = fresh();
        let (out, _, n, _) = measure(None, 0, || keys_all(ctx(&mut c, mode)));
        assert_eq!(flat(out).as_ref(), Ok(&want));
        for k in 1..=n {
            let mut c = fresh();
            let (out, _, _, d) = measure(None, k, || keys_all(ctx(&mut c, mode)));
            let out = flat(out);
            assert!(d == 1 && (out == Err(Error::Memory) || out.as_ref() == Ok(&want)), "keys mode {mode}: allocation {k}");
            assert_eq!(flat(keys_all(ctx(&mut c, mode))).as_ref(), Ok(&want));
        }
        println!("keys ({}): each of the {n} allocations denied in turn: Error::Memory, then the same outputs",
                 ["free functions", "Ctx methods, cold", "Ctx methods, warm"][mode]);
    }

    let env = |k: &str| std::env::var(k).ok();
    let sweep: Option<Vec<u64>> = env("PQZL_MEM_SWEEP").map(|s| s.split(',').map(|x| x.parse().expect("C,F,S")).collect());
    let only = env("PQZL_MEM_ONLY");
    let nthreads: usize = env("PQZL_MEM_THREADS").map_or(6, |s| s.parse().expect("PQZL_MEM_THREADS"));
    let mut work = Vec::new();
    for r in &rs {
        for which in 0..3u8 {
            for warm in [false, true] {
                work.push((r, which, warm));
            }
        }
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let done = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|sc| {
        for _ in 0..nthreads {
            sc.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(&(r, which, warm)) = work.get(i) else { break };
                let name = format!("{} {} {}", r.name, OPS[which as usize], if warm { "warm" } else { "cold" });
                if only.as_ref().is_some_and(|o| !o.split(',').any(|o| name.contains(o))) {
                    done.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    continue;
                }
                let (nc, nf, ns) = match (&sweep, which) {
                    (Some(v), _) => (v[0], v[1], v[2]),
                    (None, 0) => (3, 4, 4),
                    _ => (7, 16, 16),
                };
                let t0 = std::time::Instant::now();
                let fresh = || {
                    let mut c = Ctx::new();
                    if warm {
                        assert_eq!(run(&mut c, r, which), Some(true));
                    }
                    c
                };
                let mut c = fresh();
                let (out, peak, n, _) = measure(None, 0, || run(&mut c, r, which));
                assert_eq!(out, Some(true), "{}", r.name);
                let (mut runs, mut hit) = (0, 0);
                let caps = (1..=nc).map(|k| (Some(peak * k as usize / (nc as usize + 1)), 0));
                let stride = n.saturating_sub(nf).div_ceil(ns.max(1)).max(1) as usize;
                let denies = (1..=nf.min(n)).chain((nf + 1..=n).step_by(stride)).map(|k| (None, k));
                for (cap, deny) in caps.chain(denies) {
                    let (good, d) = op(&mut fresh(), r, which, cap, deny);
                    assert!(good, "{name}: cap {cap:?} B of peak {peak} B, allocation {deny} of {n} denied");
                    runs += 1;
                    hit += (d > 0) as u32;
                }
                println!("{name:<28}: peak {peak:>10} B, {n:>6} allocations, {runs:>3} capped runs ({hit:>3} out of memory): \
                          each the honest result or out of memory, the Ctx usable after ({} s)", t0.elapsed().as_secs());
                done.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            });
        }
    });
    assert_eq!(done.into_inner(), work.len());
}
