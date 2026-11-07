// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T17: the reference bench, through ua-rs's public API in a release build with no test feature: PQZ `R_TX` prove
//! (`proveTransfer` with the auditor, the release words path; PQZL, and PQZH where the set has it), scrypt at `N = 2^17` (opening
//! a seed vault), Falcon-1024 and SLH-DSA keygen per handle. One JSON line per item; the first line names machine, load, commit,
//! profile and set: no figure is quoted without it. The command: `runs/2026-11-07-ua-rs-sign-t17.md`.
//!
//! `ua_bench [prove runs, default 21] [other runs, default 21]`. `heap_peak_mib`: the process's Rust heap during the item (this
//! binary's counting allocator; stacks and C allocations not counted); `heap_added_mib`: the part above what was live when the
//! item started; `vm_hwm_mib`: the kernel's high-water mark so far (Linux, Android), the whole process since its start, so it
//! reads for the first item only. Every prove's words come from `tests/pqz_chain` (a token's storage as the contract writes it);
//! the last proof of each system is checked after its item: an `R_TX` statement, valid through pqz-ffi's precompile. UNAUDITED.
use pqz_ffi::stmt::{self as st, Form, Stmt, Word, PQZH_ID, PQZL_ID};
use scaas_ua::facade::pqz::pqz_set;
use scaas_ua::wallet::{Unlock, Wallet};
use serde_json::{json, Value};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

#[path = "../tests/pqz_chain/mod.rs"]
mod pqz_chain;
use pqz_chain::{h, hx, merge, Chain};

const WORDS: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const PIN: &str = "bench passphrase 1";
const FROM: Word = [0xA1; 32];
const TO: Word = [0xB0; 32];
const AUDITOR: Word = [0xA3; 32];
const MIB: f64 = (1 << 20) as f64;

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(n: usize) {
    PEAK.fetch_max(LIVE.fetch_add(n, Relaxed) + n, Relaxed);
}

// SAFETY: every call forwards to `System` with the caller's arguments; the counters allocate nothing.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        grew(l.size());
        System.alloc(l)
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        grew(l.size());
        System.alloc_zeroed(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Relaxed);
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        LIVE.fetch_sub(l.size(), Relaxed);
        grew(new);
        System.realloc(p, l, new)
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// The value after `key:` on the first line of `file` that starts with `key`.
fn proc_line(file: &str, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(file).ok()?;
    let line = text.lines().find(|l| l.starts_with(key))?;
    Some(line.split_once(':')?.1.trim().to_owned())
}

/// `n` runs of `f(i)`: one JSON line. CTR-PQZ-18's budgets are p95, so the line has it beside p50.
fn item(name: &str, n: usize, mut f: impl FnMut(usize)) {
    let start = LIVE.load(Relaxed);
    PEAK.store(start, Relaxed);
    let mut ms: Vec<f64> = (0..n)
        .map(|i| {
            let t = Instant::now();
            f(i);
            t.elapsed().as_secs_f64() * 1e3
        })
        .collect();
    let peak = PEAK.load(Relaxed);
    let first = ms[0];
    ms.sort_by(f64::total_cmp);
    let q = |p: f64| ms[((n - 1) as f64 * p).round() as usize];
    let round = |x: f64| (x * 10.0).round() / 10.0;
    let hwm = proc_line("/proc/self/status", "VmHWM").and_then(|s| s.split(' ').next()?.parse::<f64>().ok()).map(|kb| round(kb / 1024.0));
    println!(
        "{}",
        json!({"item": name, "n": n, "first_ms": round(first), "p50_ms": round(q(0.5)), "p95_ms": round(q(0.95)), "max_ms": round(q(1.0)),
            "heap_peak_mib": round(peak as f64 / MIB), "heap_added_mib": round((peak - start) as f64 / MIB), "vm_hwm_mib": hwm})
    );
}

fn r_tx(w: &Wallet, name: &str, id: &Word, n: usize) {
    let (from, to, auditor) = (w.pqz_key(0, 0).unwrap(), w.pqz_key(1, 0).unwrap(), w.pqz_key(2, 0).unwrap());
    let mut c = Chain::new();
    c.register(FROM, &from.pk());
    c.register(TO, &to.pk());
    c.register(AUDITOR, &auditor.pk());
    c.auditor = Some(AUDITOR);
    c.shield(&FROM, 1000);
    let extra = json!({"psid": hx(id), "toUA": hx(&TO), "pkT": hx(&to.pk()), "pkA": hx(&auditor.pk()), "amount": 1, "mode": "BUNDLE"});
    let req = merge(merge(c.own(&FROM, 16), c.debit_fields()), extra).to_string();
    let mut last = String::new();
    item(name, n, |_| last = from.call("proveTransfer", req.as_bytes()).unwrap());
    let p: Value = serde_json::from_str(&last).unwrap();
    let (stmt, proof) = (h(&p["stmt"]), h(&p["proof"]));
    let Stmt::Debit(d) = st::parse(1, &stmt).unwrap() else { panic!("{name}: not a debit") };
    assert_eq!(d.form, Form::Transfer, "{name}: R_TX, with the auditor");
    assert_eq!(pqz_ffi::precompile(&st::input(1, &stmt, &proof)), Ok(pqz_ffi::VALID), "{name}: the proof verifies");
}

fn main() {
    if cfg!(debug_assertions) {
        eprintln!("ua_bench: a release build only (--release)");
        std::process::exit(2);
    }
    let arg = |i: usize, default: usize| std::env::args().nth(i).map_or(default, |a| a.parse().expect("runs: a number"));
    let (prove_runs, other_runs) = (arg(1, 21), arg(2, 21));
    println!(
        "{}",
        json!({"machine": proc_line("/proc/cpuinfo", "model name"), "mem_total": proc_line("/proc/meminfo", "MemTotal"),
            "cpus": std::thread::available_parallelism().map_or(0, |c| c.get()), "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
            "loadavg": std::fs::read_to_string("/proc/loadavg").ok().map(|s| s.trim().to_owned()),
            "commit": option_env!("SCAAS_BENCH_COMMIT").unwrap_or("unknown"), "profile": "release", "set": pqz_set().name})
    );
    let w = Wallet::from_mnemonic(WORDS, "").unwrap();
    r_tx(&w, "pqz_r_tx_prove_pqzl", &PQZL_ID, prove_runs);
    if pqz_ffi::PQZH {
        r_tx(&w, "pqz_r_tx_prove_pqzh", &PQZH_ID, prove_runs);
    }
    let vault = w.seal_vault(PIN, None).unwrap();
    assert!(!vault.needs_rewrap(), "a new envelope is N = 2^17, r = 8, p = 1");
    item("scrypt_n17_open_vault", other_runs, |_| drop(Wallet::open_vault(&vault, Unlock::VaultPassphrase(PIN), "").unwrap()));
    // a new index every run: `ua_key` caches a handle's secret by kind, account and index
    for (name, kind) in [("falcon1024_keygen_per_handle", 0x0135u16), ("slhdsa128s_keygen_per_handle", 0x0133)] {
        item(name, other_runs, |i| drop(w.ua_key(kind, 0, i as u32).unwrap()));
    }
}
