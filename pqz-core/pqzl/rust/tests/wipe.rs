// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! T-06 / review 3w-delta U1h-1 and 3zh Fable F-10 (feature `test-hooks`): every heap buffer the prover holds in
//! `Wiped` (a rejection try's z3 / z4 = `y + beta R s` and R s3 / R' s4, the witness images and their copies, the
//! masks and their products, the rejection steps' copies, s1 / m / s2 / tA2, the digits) is cleared before it is
//! freed, a rejected try's included. The prover names each such buffer (`pqzl::set_secret_buf_hook`); this test
//! binary's global allocator checks the named block's bytes when it is freed. Cheat mode 4 rejects each prove's first
//! try (then an honest proof, verified), so the retry path runs on every prove; mode 0 is the control. Rows: R_REG
//! (the vectors) and R_TXS (the split transfer fixture, tests/common/split_fx.rs).
//! Same best-effort boundary as `pqzl::wipe` (heap buffers; stack copies and register spills are not seen here).
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use pqzl::Ctx;

mod common;
#[path = "common/split_fx.rs"]
mod split_fx;

const SLOTS: usize = 1024;

struct Watch;

thread_local! {
    /// the named blocks not yet freed (0 = empty slot); a fixed array: no allocation inside the allocator
    static LIVE: [Cell<usize>; SLOTS] = const { [const { Cell::new(0) }; SLOTS] };
    /// blocks named, named blocks freed, of which still held a nonzero byte, names dropped (no free slot)
    static NAMED: Cell<u64> = const { Cell::new(0) };
    static FREED: Cell<u64> = const { Cell::new(0) };
    static DIRTY: Cell<u64> = const { Cell::new(0) };
    static LOST: Cell<u64> = const { Cell::new(0) };
}

fn bump(c: &'static std::thread::LocalKey<Cell<u64>>) {
    let _ = c.try_with(|c| c.set(c.get() + 1));
}

fn named(p: usize) {
    bump(&NAMED);
    let ok = LIVE.with(|l| l.iter().find(|s| s.get() == 0 || s.get() == p).map(|s| s.set(p)).is_some());
    if !ok {
        bump(&LOST);
    }
}

unsafe impl GlobalAlloc for Watch {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        let hit = LIVE.try_with(|v| v.iter().find(|s| s.get() == p as usize).map(|s| s.set(0)).is_some()).unwrap_or(false);
        if hit {
            // SAFETY: p is a live block of l.size() bytes until System.dealloc below
            let dirty = unsafe { std::slice::from_raw_parts(p, l.size()) }.iter().any(|&b| b != 0);
            bump(&FREED);
            if dirty {
                bump(&DIRTY);
            }
        }
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static A: Watch = Watch;

/// (cheat mode, buffers named, z3 / z4 tries) per prove of `(op, stmt, wit)`, each verified, every named buffer freed
/// and clean
fn run(name: &str, op: u8, stmt: &[u8], wit: &[u8], rnd32: &[u8; 32]) -> Vec<(u32, u64, u64)> {
    let mut ctx = Ctx::new();
    let mut named_per_prove = Vec::new();
    pqzl::set_secret_buf_hook(Some(named));
    for (k, mode) in [(0u8, 0u32), (1, 0), (0, 4), (1, 4), (2, 4)] {
        let mut rnd = *rnd32;
        rnd[0] ^= k;
        for c in [&NAMED, &FREED, &DIRTY, &LOST] {
            c.with(|c| c.set(0));
        }
        let _ = pqzl::take_z34_tries();
        pqzl::set_cheat(mode);
        let p = ctx.prove(op, stmt, wit, &rnd);
        pqzl::set_cheat(0);
        let tries = pqzl::take_z34_tries();
        let p = p.unwrap_or_else(|e| panic!("{name}: honest prove {e:?}"));
        let (n, f, d, lost) = (NAMED.with(Cell::get), FREED.with(Cell::get), DIRTY.with(Cell::get), LOST.with(Cell::get));
        assert!(ctx.verify(op, stmt, &p), "{name} rnd {k} mode {mode}: honest proof rejected");
        assert_eq!((lost, f), (0, n), "{name} rnd {k} mode {mode}: every named block tracked and freed");
        assert_eq!(d, 0, "{name} rnd {k} mode {mode}: {d} of {f} secret buffers freed without being cleared");
        named_per_prove.push((mode, n, tries));
    }
    pqzl::set_secret_buf_hook(None);
    println!("{name}: (cheat mode, secret buffers named, z3 / z4 tries) per prove: {named_per_prove:?}");
    named_per_prove
}

#[test]
fn rejected_z34_cleared_before_free() {
    let r = common::pqzl_rows().into_iter().find(|r| r.code == 3).expect("an R_REG row");
    let n = run("R_REG", r.op, &r.stmt, &r.wit, &r.rnd32);
    // the retry path, counted directly (owner 2026-11-16: the buffer-count margin `mode 4 >= mode 0 + 10` failed at
    // n2560-kmax16384, mode 0 61 / mode 4 57, as honest proves retry on their own): every mode-4 prove made a rejected
    // try (2 or more tries), and every prove named its buffers; the rejected tries' buffers are in the clean asserts above
    assert!(n.iter().all(|x| x.1 >= 20 && x.2 >= 1), "{n:?}");
    assert!(n.iter().filter(|x| x.0 == 4).all(|x| x.2 >= 2), "the retry path was not exercised: {n:?}");
}

/// the same on a split transfer (R_TXS, the auditor on): its second randomness group and v_f's rows
#[test]
fn split_row_cleared_before_free() {
    let x = split_fx::tx();
    let (st, w) = (split_fx::honest_stmt(&x, true), split_fx::wit(&x, true, &x.own));
    // (the counts vary with the lower protocol's own retries; the forced compute_z34 retry is asserted on R_REG)
    let n = run("R_TXS", split_fx::OP_TRANSFER, &st, &w, &[9; 32]);
    assert!(n.iter().all(|x| x.1 >= 20 && x.2 >= 1), "{n:?}");
}
