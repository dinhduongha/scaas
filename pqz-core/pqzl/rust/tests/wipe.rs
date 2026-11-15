// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! T-06 / review 3w-delta U1h-1 (feature `test-hooks`): every heap buffer of a rejection try's secret z3 / z4 (`y +
//! beta R s`: the mask plus a linear image of the witness) and R s3 / R' s4 is cleared before it is freed, a rejected
//! try's included. The prover names each such buffer when it fills it (`pqzl::set_secret_buf_hook`); this test
//! binary's global allocator checks the named block's bytes when it is freed. Cheat mode 4 rejects each prove's first
//! try (then an honest proof, verified), so the retry path runs on every prove; mode 0 is the control.
//! Same best-effort boundary as `pqzl::wipe` (heap buffers; stack copies and register spills are not seen here).
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use pqzl::Ctx;

mod common;

const SLOTS: usize = 64;

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

#[test]
fn rejected_z34_cleared_before_free() {
    let r = common::pqzl_rows().into_iter().find(|r| r.code == 3).expect("an R_REG row");
    let mut ctx = Ctx::new();
    let mut named_per_prove = Vec::new();
    pqzl::set_secret_buf_hook(Some(named));
    for (k, mode) in [(0u8, 0u32), (1, 0), (0, 4), (1, 4), (2, 4)] {
        let mut rnd = r.rnd32;
        rnd[0] ^= k;
        for c in [&NAMED, &FREED, &DIRTY, &LOST] {
            c.with(|c| c.set(0));
        }
        pqzl::set_cheat(mode);
        let p = ctx.prove(r.op, &r.stmt, &r.wit, &rnd);
        pqzl::set_cheat(0);
        let p = p.expect("honest prove");
        let (n, f, d, lost) = (NAMED.with(Cell::get), FREED.with(Cell::get), DIRTY.with(Cell::get), LOST.with(Cell::get));
        assert!(ctx.verify(r.op, &r.stmt, &p), "rnd {k} mode {mode}: honest proof rejected");
        assert_eq!((lost, f), (0, n), "rnd {k} mode {mode}: every named block tracked and freed");
        assert_eq!(d, 0, "rnd {k} mode {mode}: {d} of {f} secret z3 / z4 / R s blocks freed without being cleared");
        named_per_prove.push((mode, n));
    }
    pqzl::set_secret_buf_hook(None);
    println!("(cheat mode, secret z3 / z4 / R s buffers named) per prove, 4 per try: {named_per_prove:?}");
    assert!(named_per_prove.iter().all(|&(m, n)| n % 4 == 0 && n >= if m == 4 { 8 } else { 4 }), "the retry path was not exercised");
}
