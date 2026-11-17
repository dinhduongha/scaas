// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! [`SecretBytes`] (scaas-sdk spec §5, §23.1 item 8; lifted from ua-dart-frb): a secret in Rust-owned memory, the one type every
//! secret parameter of a binding has. Its bytes are whole 16 KiB page-aligned blocks of its own, allocated once at their final
//! size and never moved, locked in RAM and no-dump best effort ([`super::protect`], feature `mlock`), zeroed on [`dispose`] or
//! drop. Neither `Clone` nor `Debug`:
//!
//! ```compile_fail
//! let s = scaas_ua::wallet::SecretBytes::new(1).unwrap();
//! let _ = s.clone();
//! ```
//! ```compile_fail
//! let s = scaas_ua::wallet::SecretBytes::new(1).unwrap();
//! println!("{s:?}");
//! ```
//!
//! A binding names a secret by its [`SecretBytes::id`] and moves bytes only through the two copy calls [`secret_write`] and
//! [`secret_read`] under the registry's lock, and frees it with [`secret_dispose`]: no pointer reaches a garbage-collected
//! language and no generator codec holds the bytes (CLI-UAL-05's rule). [`SecretBytes::addr`] is the one exception, for
//! ua-dart-frb's in-place write (its `dart:ffi` view), which keeps its own rule. UNAUDITED.
//!
//! [`dispose`]: SecretBytes::dispose
use super::{protect, Error, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use zeroize::{Zeroize, Zeroizing};

/// A block: 16 KiB, page-aligned (the largest page of a listed target).
pub(crate) const BLOCK: usize = 16384;
/// The largest secret: 16 MiB.
pub const SECRET_MAX: usize = 1 << 24;

#[repr(C, align(16384))]
struct Block([u8; BLOCK]);

/// The blocks of one secret and its length.
struct Blocks {
    mem: Box<[Block]>,
    len: usize,
    locked: bool,
    no_dump: bool,
}

impl Blocks {
    fn new(len: usize) -> Result<Blocks> {
        if len > SECRET_MAX {
            return Err(Error::Argument);
        }
        let mut mem: Box<[Block]> = (0..len.div_ceil(BLOCK).max(1)).map(|_| Block([0; BLOCK])).collect();
        let (locked, no_dump) = protect::on(mem.as_mut_ptr().cast(), mem.len() * BLOCK);
        Ok(Blocks { mem, len, locked, no_dump })
    }
    fn get(&self) -> &[u8] {
        // SAFETY: `mem` is `mem.len() * BLOCK` contiguous initialised bytes (`Block` is `repr(C)`, its size its alignment), and
        // `len` is at most that
        unsafe { std::slice::from_raw_parts(self.mem.as_ptr().cast::<u8>(), self.len) }
    }
    fn get_mut(&mut self) -> &mut [u8] {
        // SAFETY: as in `get`, borrowed mutably through `self`
        unsafe { std::slice::from_raw_parts_mut(self.mem.as_mut_ptr().cast::<u8>(), self.len) }
    }
}

impl Drop for Blocks {
    fn drop(&mut self) {
        self.mem.iter_mut().for_each(|b| b.0.zeroize());
        #[cfg(test)]
        tests::released(&self.mem);
        protect::off(self.mem.as_mut_ptr().cast(), self.mem.len() * BLOCK, self.locked, self.no_dump);
    }
}

type Cell = Arc<Mutex<Option<Blocks>>>;

fn registry() -> MutexGuard<'static, HashMap<u64, Cell>> {
    static R: OnceLock<Mutex<HashMap<u64, Cell>>> = OnceLock::new();
    R.get_or_init(Default::default).lock().unwrap_or_else(PoisonError::into_inner)
}

fn cell(c: &Cell) -> MutexGuard<'_, Option<Blocks>> {
    c.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A secret: its blocks, under an id in the process's registry until [`SecretBytes::dispose`] or drop.
pub struct SecretBytes {
    id: u64,
    cell: Cell,
}

impl SecretBytes {
    /// A new secret of `len` zero bytes (`Argument` above [`SECRET_MAX`]), registered under a fresh id.
    pub fn new(len: usize) -> Result<SecretBytes> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let cell: Cell = Arc::new(Mutex::new(Some(Blocks::new(len)?)));
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        registry().insert(id, cell.clone());
        Ok(SecretBytes { id, cell })
    }

    /// A secret holding `src` (a Rust caller's); `src` wipes itself.
    pub fn from_zeroizing(src: Zeroizing<Vec<u8>>) -> Result<SecretBytes> {
        let s = SecretBytes::new(src.len())?;
        s.with_mut(|b| b.copy_from_slice(&src));
        Ok(s)
    }

    /// The registry id a binding names this secret by.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The length in bytes (0 once disposed).
    pub fn len(&self) -> usize {
        cell(&self.cell).as_ref().map_or(0, |b| b.len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `f` over the bytes, under this secret's lock (empty once disposed).
    pub fn with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        let g = cell(&self.cell);
        f(g.as_ref().map_or(&[][..], Blocks::get))
    }

    /// `f` over the bytes to write them, under this secret's lock (empty once disposed).
    pub fn with_mut<R>(&self, f: impl FnOnce(&mut [u8]) -> R) -> R {
        let mut g = cell(&self.cell);
        f(g.as_mut().map_or(&mut [][..], Blocks::get_mut))
    }

    /// The address of the first byte, the same for the secret's life (0 once disposed): for ua-dart-frb's in-place write only.
    pub fn addr(&self) -> usize {
        cell(&self.cell).as_mut().map_or(0, |b| b.mem.as_mut_ptr() as usize)
    }

    /// Zeroes and frees the blocks and leaves the registry; later reads see nothing, later copy calls are `Argument`.
    pub fn dispose(&self) {
        registry().remove(&self.id);
        cell(&self.cell).take();
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.dispose();
    }
}

fn lookup(id: u64) -> Result<Cell> {
    registry().get(&id).cloned().ok_or(Error::Argument)
}

/// Copies `src` into secret `id`: `Argument` for an unknown or disposed id or a length other than the secret's.
pub fn secret_write(id: u64, src: &[u8]) -> Result<()> {
    let c = lookup(id)?;
    let mut g = cell(&c);
    let dst = g.as_mut().map(Blocks::get_mut).ok_or(Error::Argument)?;
    if dst.len() != src.len() {
        return Err(Error::Argument);
    }
    dst.copy_from_slice(src);
    Ok(())
}

/// Copies secret `id` into the start of `dst` and returns its length: `Argument` for an unknown or disposed id or a `dst` shorter
/// than the secret.
pub fn secret_read(id: u64, dst: &mut [u8]) -> Result<usize> {
    let c = lookup(id)?;
    let g = cell(&c);
    let src = g.as_ref().map(Blocks::get).ok_or(Error::Argument)?;
    dst.get_mut(..src.len()).ok_or(Error::Argument)?.copy_from_slice(src);
    Ok(src.len())
}

/// Disposes of secret `id` (zeroed, freed); `false` for an unknown or already disposed id.
pub fn secret_dispose(id: u64) -> bool {
    match registry().remove(&id) {
        Some(c) => {
            cell(&c).take();
            true
        }
        None => false,
    }
}

/// The number of secrets registered now (a binding's leak check).
pub fn secrets_live() -> usize {
    registry().len()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::cell::Cell as StdCell;

    thread_local! {
        /// Blocks released on this thread, and those released with a non-zero byte.
        static RELEASED: StdCell<(usize, usize)> = const { StdCell::new((0, 0)) };
    }
    pub(super) fn released(mem: &[Block]) {
        let nonzero = mem.iter().any(|b| b.0.iter().any(|x| *x != 0));
        RELEASED.with(|r| r.set((r.get().0 + 1, r.get().1 + usize::from(nonzero))));
    }

    /// ua-dart-frb's `secret_fixed_locked_and_zeroed_on_drop`, moved with the implementation (plan T2a).
    #[test]
    fn secret_bytes_zeroed_on_dispose() {
        let s = SecretBytes::new(100).unwrap();
        let p = s.addr();
        assert_eq!((p % BLOCK, s.len()), (0, 100));
        // an in-place write (ua-dart-frb's) and a copy call
        // SAFETY: `p` is the first of `s`'s 100 bytes, `s` alive and not borrowed
        unsafe { std::ptr::write_bytes(p as *mut u8, 0xa5, 100) };
        assert!(s.with(|b| b == [0xa5; 100]));
        assert_eq!(s.addr(), p, "never moved");
        assert_eq!(cell(&s.cell).as_ref().map(|b| (b.locked, b.mem.len())), Some((cfg!(all(unix, feature = "mlock")), 1)));
        let before = RELEASED.with(StdCell::get);
        s.dispose();
        assert_eq!(RELEASED.with(StdCell::get), (before.0 + 1, before.1), "released once, every byte zero");
        assert_eq!((s.len(), s.addr()), (0, 0));
        drop(s);
        assert_eq!(RELEASED.with(StdCell::get), (before.0 + 1, before.1), "a disposed secret is not released twice");
        // a positive control: the hook sees a non-zero block
        released(&[Block([1; BLOCK])]);
        assert_eq!(RELEASED.with(StdCell::get), (before.0 + 2, before.1 + 1));
        // drop without dispose zeroes too
        let t = SecretBytes::from_zeroizing(Zeroizing::new(vec![7; 3])).unwrap();
        drop(t);
        assert_eq!(RELEASED.with(StdCell::get), (before.0 + 3, before.1 + 1));
    }

    /// ua-dart-frb's `secret_sizes_and_outputs`, moved with the implementation.
    #[test]
    fn secret_sizes() {
        let e = SecretBytes::new(0).unwrap();
        assert_eq!((e.len(), cell(&e.cell).as_ref().map(|b| b.mem.len())), (0, Some(1)), "an empty secret: one block");
        let big = SecretBytes::new(BLOCK + 1).unwrap();
        assert_eq!(cell(&big.cell).as_ref().map(|b| b.mem.len()), Some(2));
        assert_eq!(SecretBytes::new(SECRET_MAX + 1).err(), Some(Error::Argument));
        assert!(SecretBytes::new(SECRET_MAX).is_ok());
    }
}
