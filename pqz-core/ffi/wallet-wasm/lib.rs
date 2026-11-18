// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The browser wallet's K3-7 holder check (CLI-SGN-51; TODO 3zf): [`pqz_ffi::opening::check_recipient`] and
//! [`pqz_ffi::opening::check_auditor`] behind wasm32 exports that a buggy caller cannot break. UNAUDITED.
//!
//! The module owns its buffers: one input of [`INPUT_CAP`] bytes (`input_ptr`, `input_cap`) and one 16-byte output
//! (`out_ptr`). The caller writes a frame of `n` bytes into the input and calls `check_recipient(n)` or
//! `check_auditor(n)`. No export takes a caller's pointer, and the crate has no `unsafe` code.
//!
//! The frame: every field `be4(len) ‖ bytes`, in this order, nothing after it (depth 1: one optional party):
//!
//! ```text
//! openKemSeed(96) chainUid(32) token(20) u(PK_BYTES)
//! recipient: ua(32) keyVersion(8, big-endian) pk(PK_BYTES) kemPk(1601 in state) v(128) opening(1648 in state)
//! auditorOn(1: 0 or 1)  [auditor: the same six fields]
//! ```
//!
//! Every fixed field's length must be its exact length. `kemPk` and `opening` are slices in the Rust API ([`Party`]): any
//! length inside the frame, and the Rust API decides (a wrong one fails there). Every length must lie inside `n`, and `n`
//! is at most [`INPUT_CAP`] (`SLACK` bytes above the largest frame of exact lengths). A frame that is not exactly this is
//! the outcome of a failed check: skip, or unreadable (also for a frame above the cap, where the Rust API given such an
//! over-long slice could still say recipient-unreadable; state never holds one).
//!
//! Outcomes, one per failure as the Rust API: `check_recipient` 0 skip, 1 accepted; `check_auditor` 0 unreadable, 1 read,
//! 2 recipient-unreadable. On 1 the output holds the 16 digits, else zeros. Every call zeroes the output first and the
//! whole input after (it held the opening KEM seed). No error detail, no step number leaves (ARCH-POS-13). A panic traps
//! (wasm32 aborts); the loader then drops the instance.
use std::cell::RefCell;

use pqz_ffi::opening::{self as op, AuditorOutcome, Credit, Party};
use pqz_ffi::pqzl::PK_BYTES;

const SEED: usize = 96;
const PARTY: usize = 6 * 4 + 32 + 8 + PK_BYTES + op::KEM_PK + 128 + op::OPENING;
/// Room for an over-long `kemPk` / `opening` (state never holds one: the blob's layout fixes both).
const SLACK: usize = 4096;
/// The largest frame: seed, chainUid, token, `u`, the flag, two parties, the slack.
pub const INPUT_CAP: usize = 5 * 4 + SEED + 32 + 20 + PK_BYTES + 1 + 2 * PARTY + SLACK;

thread_local! {
    static INPUT: RefCell<Vec<u8>> = RefCell::new(vec![0; INPUT_CAP]);
    static OUT: RefCell<[u8; 16]> = const { RefCell::new([0; 16]) };
}

/// The frame's reader: each `take` checks the length word and the bytes left.
struct Frame<'a>(&'a [u8]);

impl<'a> Frame<'a> {
    fn take<const L: usize>(&mut self) -> Option<&'a [u8; L]> {
        let (len, rest) = self.0.split_first_chunk::<4>()?;
        if u32::from_be_bytes(*len) as usize != L {
            return None;
        }
        let (f, rest) = rest.split_first_chunk::<L>()?;
        self.0 = rest;
        Some(f)
    }

    /// A field of any length that lies inside the frame.
    fn slice(&mut self) -> Option<&'a [u8]> {
        let (len, rest) = self.0.split_first_chunk::<4>()?;
        let len = u32::from_be_bytes(*len) as usize;
        let f = rest.get(..len)?;
        self.0 = &rest[len..];
        Some(f)
    }

    fn party(&mut self) -> Option<Party<'a>> {
        Some(Party {
            ua: self.take()?,
            key_version: u64::from_be_bytes(*self.take::<8>()?),
            pk: self.take()?,
            kem_pk: self.slice()?,
            v: self.take()?,
            opening: self.slice()?,
        })
    }
}

fn parse(b: &[u8]) -> Option<(&[u8; SEED], Credit<'_>)> {
    let mut f = Frame(b);
    let seed = f.take()?;
    let (chain_uid, token, u) = (f.take()?, f.take()?, f.take()?);
    let to = f.party()?;
    let auditor = match f.take::<1>()? {
        [0] => None,
        [1] => Some(f.party()?),
        _ => return None,
    };
    f.0.is_empty().then_some((
        seed,
        Credit {
            chain_uid,
            token,
            u,
            to,
            auditor,
        },
    ))
}

/// Runs `check` on the frame of `n` bytes, `none` for a malformed frame; zeroes the output before and the input after.
fn with_frame(n: u32, none: u32, check: impl FnOnce(&[u8; SEED], &Credit) -> u32) -> u32 {
    OUT.with(|o| *o.borrow_mut() = [0; 16]);
    INPUT.with(|i| {
        let mut buf = i.borrow_mut();
        let r = match buf.get(..n as usize).and_then(parse) {
            Some((seed, c)) => check(seed, &c),
            None => none,
        };
        buf.fill(0);
        r
    })
}

fn put(d: [u8; 16]) {
    OUT.with(|o| *o.borrow_mut() = d);
}

/// The input buffer the caller writes a frame into (owned by the module, [`INPUT_CAP`] bytes, never moved).
#[no_mangle]
pub extern "C" fn input_ptr() -> *mut u8 {
    INPUT.with(|i| i.borrow_mut().as_mut_ptr())
}

#[no_mangle]
pub extern "C" fn input_cap() -> u32 {
    INPUT_CAP as u32
}

/// The 16 digits of the last accepted / read credit, zeros otherwise.
#[no_mangle]
pub extern "C" fn out_ptr() -> *const u8 {
    OUT.with(|o| o.borrow().as_ptr())
}

/// The set's `PK_BYTES` (the `u` and `pk` length): a module is built for one parameter set.
#[no_mangle]
pub extern "C" fn pk_bytes() -> u32 {
    PK_BYTES as u32
}

/// K3-7 for the recipient: 1 accepted (the digits in `out_ptr`), 0 skip.
#[no_mangle]
pub extern "C" fn check_recipient(n: u32) -> u32 {
    with_frame(n, 0, |seed, c| match op::check_recipient(seed, c) {
        Some(d) => {
            put(d);
            1
        }
        None => 0,
    })
}

/// K3-7 for the auditor: 1 read (the digits in `out_ptr`), 2 recipient-unreadable, 0 unreadable.
#[no_mangle]
pub extern "C" fn check_auditor(n: u32) -> u32 {
    with_frame(n, 0, |seed, c| match op::check_auditor(seed, c) {
        AuditorOutcome::Read(d) => {
            put(d);
            1
        }
        AuditorOutcome::RecipientUnreadable => 2,
        AuditorOutcome::Unreadable => 0,
    })
}
