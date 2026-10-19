//! Review P-D: when one of the verifier's buffers cannot be reserved, `try_verify` reports `Err(Oom)` (pqz-ffi:
//! `NodeFault`) instead of aborting the process, and never a verdict. A global allocator that refuses every allocation
//! of at least LIMIT bytes while armed; the limits stay above the largest allocation `try_verify` leaves infallible (a
//! decoded public-key vector, 16 KiB).
#![cfg(feature = "bench")]
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use pqzh_ligero::client::setup;
use pqzh_ligero::{Form, Oom, Params, prove, try_verify};

struct Cap;
static LIMIT: AtomicUsize = AtomicUsize::new(usize::MAX);

unsafe impl GlobalAlloc for Cap {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if l.size() >= LIMIT.load(Ordering::SeqCst) {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static A: Cap = Cap;

#[test]
fn verifier_out_of_memory_is_a_fault() {
    let s = setup();
    let p = Params::proven();
    for f in [Form::Register, Form::Transfer] {
        let (st, w) = s.rel(f);
        let pf = prove(f.op(), st, w, [1; 32], &p).unwrap();
        assert_eq!(try_verify(f.op(), st, &pf, &p), Ok(true));
        // 1 MiB: nothing refused; 200 kB: the domain H_n (262 kB); 50 kB: the decoded w (52 kB); 20 kB: the same
        let r: Vec<_> = [1 << 20, 200_000, 50_000, 20_000]
            .map(|limit| {
                LIMIT.store(limit, Ordering::SeqCst);
                let r = try_verify(f.op(), st, &pf, &p);
                LIMIT.store(usize::MAX, Ordering::SeqCst);
                r
            })
            .to_vec();
        assert_eq!(r, [Ok(true), Err(Oom), Err(Oom), Err(Oom)], "{f:?}");
    }
}
