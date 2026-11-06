// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The wallet's secret store (spec §8.2, C-02, C-09): one per wallet, shared by `Arc`, a read-write lock over the generation
//! and the arena. The arena is page-aligned chunks that never move or grow (a new chunk when one is full); every secret lives
//! in it as bytes. A handle holds the `Arc`, the generation at its creation and its slot: no secret bytes. Every secret
//! operation runs under the read guard and refuses `KeyRevoked` when its generation is not the store's; `lock` takes the
//! write lock (it waits for every operation in flight), wipes the arena and raises the generation, so no earlier handle works
//! again; `open` builds a new arena at the raised generation. The store also holds the wallet's public manifest (spec §8.3),
//! outside the arena: `lock` keeps it. Memory protection (T10, feature `mlock`, best effort): each chunk is locked in RAM
//! (`mlock`) and, on Linux and Android, excluded from core dumps (`MADV_DONTDUMP`) at allocation; at release it is wiped,
//! unmarked and unlocked. A refused call is counted in [`MemoryProtection`], never an error. Outside that coverage: the crates'
//! key types rebuilt per operation and their temporaries, the scrypt work buffer, the caller's buffers, every target without
//! `mlock` (wasm32: compiled out, nothing is locked; Windows: no `VirtualLock` in this build, reported as not locked). The
//! process-wide `PR_SET_DUMPABLE` is never set: a host app that wants it sets it itself. UNAUDITED.
// the readers of secrets (`Handle::with`, the entropy for the vault) are the signers (T3a–T3d) and the vault (T9)
#![cfg_attr(not(feature = "vectors"), allow(dead_code))]
use super::manifest::Manifest;
use super::{Error, KeyId, Result};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use zeroize::{Zeroize, Zeroizing};

/// The chunk size and alignment: the largest page of a listed target (16 KiB on Apple aarch64 and 16 KiB Android), so a
/// chunk never shares a page with other data. A secret is at most one chunk (the largest planned: an ML-DSA-87 expanded key,
/// 4,896 B).
pub(crate) const PAGE: usize = 16384;

#[repr(C, align(16384))]
struct Page([u8; PAGE]);

/// What protection a wallet's arena has now (spec §8.2): counts of its chunks. All zero while the wallet is locked; `locked`
/// and `no_dump` zero without feature `mlock` (and on wasm32). Best effort: a refused lock lowers a count and fails nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryProtection {
    /// The arena's chunks (16 KiB each).
    pub chunks: usize,
    /// Chunks locked in RAM (`mlock`): never written to swap.
    pub locked: usize,
    /// Chunks excluded from core dumps (`MADV_DONTDUMP`, Linux and Android).
    pub no_dump: usize,
}

/// `mlock` and `MADV_DONTDUMP` of a chunk (feature `mlock`, Unix).
#[cfg(all(feature = "mlock", unix))]
mod protect {
    use libc::c_void;

    /// Whether `[p, p + len)` is whole pages of this system (a 64 KiB-page kernel: no, so nothing is locked or marked; an
    /// unlock there would also release a neighbouring chunk sharing the page).
    fn whole_pages(p: *mut u8, len: usize) -> bool {
        // SAFETY: sysconf reads a constant of the system
        let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(ps).is_ok_and(|ps| ps > 0 && (p as usize).is_multiple_of(ps) && len.is_multiple_of(ps))
    }

    /// `(locked, no_dump)`: whether `mlock` and `MADV_DONTDUMP` took on the chunk at `p`.
    pub(super) fn on(p: *mut u8, len: usize) -> (bool, bool) {
        if !whole_pages(p, len) {
            return (false, false);
        }
        // SAFETY: `[p, p + len)` is one live allocation (a chunk) of whole pages; neither call reads or writes its bytes
        let locked = unsafe { libc::mlock(p as *const c_void, len) } == 0;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        // SAFETY: as above; MADV_DONTDUMP changes only the mapping's dump flag
        let no_dump = unsafe { libc::madvise(p as *mut c_void, len, libc::MADV_DONTDUMP) } == 0;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let no_dump = false;
        (locked, no_dump)
    }

    /// Undoes `on` for the chunk at `p` (already wiped).
    pub(super) fn off(p: *mut u8, len: usize, locked: bool, no_dump: bool) {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if no_dump {
            // SAFETY: as in `on`; the chunk is still allocated
            unsafe { libc::madvise(p as *mut c_void, len, libc::MADV_DODUMP) };
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let _ = no_dump;
        if locked {
            // SAFETY: as in `on`
            unsafe { libc::munlock(p as *const c_void, len) };
        }
    }
}

/// Without feature `mlock`, or off Unix (wasm32, Windows): nothing is locked or marked.
#[cfg(not(all(feature = "mlock", unix)))]
mod protect {
    pub(super) fn on(_: *mut u8, _: usize) -> (bool, bool) {
        (false, false)
    }
    pub(super) fn off(_: *mut u8, _: usize, _: bool, _: bool) {}
}

/// One arena chunk: a page-aligned block that never moves, locked and marked no-dump from allocation (feature `mlock`), and at
/// release wiped first, then unmarked and unlocked.
struct Chunk {
    page: Box<Page>,
    locked: bool,
    no_dump: bool,
}

impl Chunk {
    fn new() -> Chunk {
        let mut page = Box::new(Page([0; PAGE]));
        let (locked, no_dump) = protect::on(page.0.as_mut_ptr(), PAGE);
        Chunk { page, locked, no_dump }
    }
}

impl Drop for Chunk {
    fn drop(&mut self) {
        self.page.0.zeroize();
        #[cfg(feature = "vectors")]
        vectors::released(&self.page.0);
        protect::off(self.page.0.as_mut_ptr(), PAGE, self.locked, self.no_dump);
    }
}

/// Test-only (feature `vectors`): every chunk released in this process, and those released with a non-zero byte.
#[cfg(feature = "vectors")]
pub(crate) mod vectors {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static RELEASED: AtomicUsize = AtomicUsize::new(0);
    static NONZERO: AtomicUsize = AtomicUsize::new(0);

    pub(super) fn released(bytes: &[u8]) {
        RELEASED.fetch_add(1, Ordering::SeqCst);
        if bytes.iter().any(|b| *b != 0) {
            NONZERO.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// `(released, released non-zero)`.
    pub fn chunks_released() -> (usize, usize) {
        (RELEASED.load(Ordering::SeqCst), NONZERO.load(Ordering::SeqCst))
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Slot {
    chunk: usize,
    start: usize,
    len: usize,
}

pub(crate) struct Arena {
    chunks: Vec<Chunk>,
    used: usize, // bytes used in the last chunk
    total: usize, // bytes written, every chunk
    entropy: Slot,
    seed: Slot,
    keys: HashMap<KeyId, (Slot, Vec<u8>)>, // a derived key: its slot and its public key data
    tested: HashSet<KeyId>,                // the keys whose self-test ran in this store (a KEM key: FIPS 203 §7.3)
    self_tests: usize,                     // self-tests run in this store
}

impl Arena {
    /// An arena with no entropy and no seed (an ephemeral key's store).
    fn empty() -> Arena {
        let empty = Slot { chunk: 0, start: 0, len: 0 };
        let (keys, tested) = (HashMap::new(), HashSet::new());
        Arena { chunks: Vec::new(), used: 0, total: 0, entropy: empty, seed: empty, keys, tested, self_tests: 0 }
    }

    fn new(entropy: &[u8], seed: &[u8; 64]) -> Result<Arena> {
        let mut a = Arena::empty();
        a.entropy = a.put(entropy)?;
        a.seed = a.put(seed)?;
        Ok(a)
    }

    fn put(&mut self, bytes: &[u8]) -> Result<Slot> {
        if bytes.len() > PAGE {
            return Err(Error::Argument);
        }
        if self.chunks.is_empty() || PAGE - self.used < bytes.len() {
            self.chunks.push(Chunk::new());
            self.used = 0;
        }
        let slot = Slot { chunk: self.chunks.len() - 1, start: self.used, len: bytes.len() };
        let dst = self.chunks.last_mut().and_then(|c| c.page.0.get_mut(slot.start..slot.start + slot.len)).ok_or(Error::Argument)?;
        dst.copy_from_slice(bytes);
        self.used += bytes.len();
        self.total += bytes.len();
        Ok(slot)
    }

    fn get(&self, s: Slot) -> Result<&[u8]> {
        self.chunks.get(s.chunk).and_then(|c| c.page.0.get(s.start..s.start + s.len)).ok_or(Error::KeyRevoked)
    }

    fn get_mut(&mut self, s: Slot) -> Result<&mut [u8]> {
        self.chunks.get_mut(s.chunk).and_then(|c| c.page.0.get_mut(s.start..s.start + s.len)).ok_or(Error::KeyRevoked)
    }

    pub(crate) fn entropy(&self) -> Result<&[u8]> {
        self.get(self.entropy)
    }

    /// The secret of key `id`, if the arena holds it.
    pub(crate) fn secret(&self, id: KeyId) -> Option<&[u8]> {
        self.get(self.keys.get(&id)?.0).ok()
    }

    /// `secret` (and its public key data) as key `id`, a key not derived from the seed (an imported key).
    pub(crate) fn insert(&mut self, id: KeyId, secret: &[u8], public: Vec<u8>) -> Result<()> {
        let slot = self.put(secret)?;
        self.keys.insert(id, (slot, public));
        Ok(())
    }
}

struct Inner {
    generation: u64,
    arena: Option<Arena>,
    manifest: Manifest,
}

pub(crate) struct SecretStore(RwLock<Inner>);

/// A secret's place in a store: what a key handle holds instead of its bytes.
pub(crate) struct Handle {
    store: Arc<SecretStore>,
    generation: u64,
    slot: Slot,
}

impl SecretStore {
    pub(crate) fn new() -> Arc<SecretStore> {
        Arc::new(SecretStore(RwLock::new(Inner { generation: 0, arena: None, manifest: Manifest::default() })))
    }

    // a panic under the lock cannot leave a half-written arena that a reader would trust: every write path below either
    // completes or returns before it touches the arena, so a poisoned lock is taken as it is
    fn read(&self) -> RwLockReadGuard<'_, Inner> {
        self.0.read().unwrap_or_else(PoisonError::into_inner)
    }
    fn write(&self) -> RwLockWriteGuard<'_, Inner> {
        self.0.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// The arena from the entropy and its seed, at the current generation; `Argument` while one is open (a second arena would
    /// move the slots of live handles).
    pub(crate) fn open(&self, entropy: &[u8], seed: &[u8; 64]) -> Result<()> {
        let mut g = self.write();
        if g.arena.is_some() {
            return Err(Error::Argument);
        }
        g.arena = Some(Arena::new(entropy, seed)?);
        Ok(())
    }

    /// Waits for every operation in flight (the write lock), wipes the arena, raises the generation.
    pub(crate) fn lock(&self) {
        let mut g = self.write();
        g.arena = None;
        g.generation += 1;
    }

    /// The handle of key `id`: its slot if the store has it, else `derive(seed)` → (secret, public key data), the secret
    /// copied into the arena. `WalletLocked` while locked. Derivation runs under the write lock.
    // ponytail: one write lock per derivation (an SLH-DSA keygen blocks signing for its milliseconds); a per-key lock if
    // that shows up in T17's numbers.
    pub(crate) fn key(
        self: &Arc<Self>,
        id: KeyId,
        derive: impl FnOnce(&[u8; 64]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)>,
    ) -> Result<(Handle, Vec<u8>)> {
        let mut g = self.write();
        let generation = g.generation;
        let arena = g.arena.as_mut().ok_or(Error::WalletLocked)?;
        self.key_in(arena, generation, id, derive)
    }

    fn key_in(
        self: &Arc<Self>,
        arena: &mut Arena,
        generation: u64,
        id: KeyId,
        derive: impl FnOnce(&[u8; 64]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)>,
    ) -> Result<(Handle, Vec<u8>)> {
        let (slot, public) = match arena.keys.get(&id) {
            Some((slot, public)) => (*slot, public.clone()),
            None => {
                let seed: Zeroizing<[u8; 64]> = Zeroizing::new(arena.get(arena.seed)?.try_into().map_err(|_| Error::Argument)?);
                let (secret, public) = derive(&seed)?;
                let slot = arena.put(&secret)?;
                arena.keys.insert(id, (slot, public.clone()));
                (slot, public)
            }
        };
        Ok((Handle { store: self.clone(), generation, slot }, public))
    }

    /// A store of its own holding only `secret` (an ephemeral KEM key, spec §8.2), and the secret's handle.
    pub(crate) fn single(secret: &[u8]) -> Result<Handle> {
        let mut arena = Arena::empty();
        let slot = arena.put(secret)?;
        let inner = Inner { generation: 0, arena: Some(arena), manifest: Manifest::default() };
        Ok(Handle { store: Arc::new(SecretStore(RwLock::new(inner))), generation: 0, slot })
    }

    /// `f` over the open arena under the read guard; `WalletLocked` while locked.
    pub(crate) fn with_arena<R>(&self, f: impl FnOnce(&Arena) -> Result<R>) -> Result<R> {
        f(self.read().arena.as_ref().ok_or(Error::WalletLocked)?)
    }

    /// `f` over the seed under the read guard (a derivation that stores nothing: discovery); `WalletLocked` while locked.
    pub(crate) fn with_seed<R>(&self, f: impl FnOnce(&[u8; 64]) -> Result<R>) -> Result<R> {
        self.with_arena(|a| f(&Zeroizing::new(a.get(a.seed)?.try_into().map_err(|_| Error::Argument)?)))
    }

    /// `f` over the open arena and the manifest under the write lock; `WalletLocked` while locked.
    pub(crate) fn with_all<R>(&self, f: impl FnOnce(&mut Arena, &mut Manifest) -> Result<R>) -> Result<R> {
        let mut g = self.write();
        let Inner { arena, manifest, .. } = &mut *g;
        f(arena.as_mut().ok_or(Error::WalletLocked)?, manifest)
    }

    /// The open arena's protection; all zero while locked.
    pub(crate) fn memory_protection(&self) -> MemoryProtection {
        self.read().arena.as_ref().map_or_else(MemoryProtection::default, |a| MemoryProtection {
            chunks: a.chunks.len(),
            locked: a.chunks.iter().filter(|c| c.locked).count(),
            no_dump: a.chunks.iter().filter(|c| c.no_dump).count(),
        })
    }

    /// The manifest (public; kept by `lock`).
    pub(crate) fn manifest(&self) -> Manifest {
        self.read().manifest.clone()
    }

    /// `f` over the manifest under the write lock, locked or not.
    pub(crate) fn note(&self, f: impl FnOnce(&mut Manifest)) {
        f(&mut self.write().manifest);
    }

    #[cfg(feature = "vectors")]
    pub(crate) fn seed(&self) -> Result<Zeroizing<[u8; 64]>> {
        self.with_arena(|a| Ok(Zeroizing::new(a.get(a.seed)?.try_into().map_err(|_| Error::Argument)?)))
    }

    #[cfg(feature = "vectors")]
    pub(crate) fn used(&self) -> Result<usize> {
        self.with_arena(|a| Ok(a.total))
    }

    #[cfg(feature = "vectors")]
    pub(crate) fn self_tests(&self) -> Result<usize> {
        self.with_arena(|a| Ok(a.self_tests))
    }
}

impl Handle {
    /// A second handle of the same secret (a session keeps its key's), for the crate only: handles are not `Clone`.
    pub(crate) fn dup(&self) -> Handle {
        Handle { store: self.store.clone(), generation: self.generation, slot: self.slot }
    }

    /// Whether this handle is of store `s` (a backup's sender key of the wallet that seals).
    pub(crate) fn of_store(&self, s: &Arc<SecretStore>) -> bool {
        Arc::ptr_eq(&self.store, s)
    }

    /// `f` over this handle's store's manifest (a KEM key written at its first use).
    pub(crate) fn note(&self, f: impl FnOnce(&mut Manifest)) {
        self.store.note(f);
    }

    /// Locks this handle's store (wipes it, revokes every handle of it): an ephemeral key's own store only.
    pub(crate) fn revoke_store(&self) {
        self.store.lock();
    }

    /// The handle of key `id` derived from this handle's own store's seed, as [`SecretStore::key`]: `KeyRevoked` once the
    /// store's generation moved (a KEM key of a UA key, spec §6.1: no other wallet can be named).
    pub(crate) fn derive(
        &self,
        id: KeyId,
        derive: impl FnOnce(&[u8; 64]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)>,
    ) -> Result<(Handle, Vec<u8>)> {
        let mut g = self.store.write();
        if g.generation != self.generation {
            return Err(Error::KeyRevoked);
        }
        let arena = g.arena.as_mut().ok_or(Error::KeyRevoked)?;
        self.store.key_in(arena, self.generation, id, derive)
    }

    /// `test` over the secret once per store for key `id`, under the write lock; the record is the store's (wiped with its
    /// arena). A failed test records nothing and is returned.
    pub(crate) fn self_test(&self, id: KeyId, test: impl FnOnce(&[u8]) -> Result<()>) -> Result<()> {
        let mut g = self.store.write();
        if g.generation != self.generation {
            return Err(Error::KeyRevoked);
        }
        let arena = g.arena.as_mut().ok_or(Error::KeyRevoked)?;
        if !arena.tested.contains(&id) {
            test(arena.get(self.slot)?)?;
            arena.tested.insert(id);
            arena.self_tests += 1;
        }
        Ok(())
    }

    /// A one-use secret (a group session's secret nonce, spec §8.2) put into this handle's store, under the write lock:
    /// `KeyRevoked` once the generation moved.
    // ponytail: a taken slot is wiped, not reused; the arena grows by one nonce per session until `lock()`.
    pub(crate) fn put(&self, bytes: &[u8]) -> Result<Handle> {
        let mut g = self.store.write();
        if g.generation != self.generation {
            return Err(Error::KeyRevoked);
        }
        let slot = g.arena.as_mut().ok_or(Error::KeyRevoked)?.put(bytes)?;
        Ok(Handle { store: self.store.clone(), generation: self.generation, slot })
    }

    /// The secret's bytes, wiped in the arena as they are read (under the write lock): a one-use secret's only read.
    pub(crate) fn take(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut g = self.store.write();
        if g.generation != self.generation {
            return Err(Error::KeyRevoked);
        }
        let s = g.arena.as_mut().ok_or(Error::KeyRevoked)?.get_mut(self.slot)?;
        let out = Zeroizing::new(s.to_vec());
        s.zeroize();
        Ok(out)
    }

    /// `f` over the secret's bytes, under the store's read guard: `KeyRevoked` once the store's generation moved.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R> {
        let g = self.store.read();
        if g.generation != self.generation {
            return Err(Error::KeyRevoked);
        }
        Ok(f(g.arena.as_ref().ok_or(Error::KeyRevoked)?.get(self.slot)?))
    }

    /// Whether the bytes [`Handle::with`] gives lie inside one of the arena's chunks and outside `owner` (the handle's own
    /// allocation, address and size).
    #[cfg(feature = "vectors")]
    pub(crate) fn in_arena(&self, owner: (usize, usize)) -> Result<bool> {
        let p = self.with(|s| s.as_ptr() as usize)?;
        let g = self.store.read();
        let a = g.arena.as_ref().ok_or(Error::KeyRevoked)?;
        let in_chunk = a.chunks.iter().any(|c| (c.page.0.as_ptr() as usize..c.page.0.as_ptr() as usize + PAGE).contains(&p));
        Ok(in_chunk && !(owner.0..owner.0 + owner.1).contains(&p))
    }
}
