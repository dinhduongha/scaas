// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! T21 L75: a FROST session's two serialized nonces are wiped before their buffers are freed. A recording global allocator
//! copies each 32-byte buffer this thread frees while recording is on; none may equal a half of the session's arena slot
//! (`hiding ‖ binding`, read through the `vectors` probe). Positive control: the recorder sees a buffer the test fills and
//! frees itself. Its own test binary: the allocator is the whole process's. UNAUDITED.
#![cfg(feature = "vectors")]
use scaas_ua::frost::{dkg, id, Secp256K1Sha256};
use scaas_ua::wallet::Wallet;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Mutex;

const N: usize = 4096;
static FREED: Mutex<([[u8; 32]; N], usize)> = Mutex::new(([[0; 32]; N], 0));
thread_local! { static ON: Cell<bool> = const { Cell::new(false) }; }

struct Recorder;

unsafe impl GlobalAlloc for Recorder {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if l.size() == 32 && ON.try_with(Cell::get).unwrap_or(false) {
            // `try_lock`: never waits inside the allocator
            if let Ok(mut g) = FREED.try_lock() {
                let (bufs, n) = &mut *g;
                if *n < N {
                    bufs[*n].copy_from_slice(unsafe { std::slice::from_raw_parts(p, 32) });
                    *n += 1;
                }
            }
        }
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static A: Recorder = Recorder;

/// The freed 32-byte buffers recorded while `f` ran on this thread.
fn freed_during<R>(f: impl FnOnce() -> R) -> (R, Vec<[u8; 32]>) {
    FREED.lock().unwrap().1 = 0;
    ON.with(|c| c.set(true));
    let r = f();
    ON.with(|c| c.set(false));
    let g = FREED.lock().unwrap();
    (r, g.0[..g.1].to_vec())
}

#[test]
fn frost_nonce_copies_are_wiped_before_they_are_freed() {
    use rand_chacha::rand_core::SeedableRng;
    let (_, control) = freed_during(|| drop(std::hint::black_box(vec![0xa5u8; 32])));
    assert!(control.contains(&[0xa5; 32]), "control: the recorder sees a freed buffer");
    let w = Wallet::from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "").unwrap();
    let g = dkg::<Secp256K1Sha256, _>(2, 2, &mut rand_chacha::ChaCha20Rng::seed_from_u64(9)).unwrap();
    let (s, freed) = freed_during(|| w.frost_session(&g.keys[&id::<Secp256K1Sha256>(1)]).unwrap());
    let slot = s.vectors_nonce_probe().unwrap().bytes().unwrap();
    assert_eq!(slot.len(), 64);
    let (h, b) = slot.split_at(32);
    assert!(h.iter().chain(b).any(|x| *x != 0), "control: the slot holds the nonces");
    assert!(!freed.iter().any(|f| f[..] == *h || f[..] == *b), "a freed buffer held a nonce");
}
