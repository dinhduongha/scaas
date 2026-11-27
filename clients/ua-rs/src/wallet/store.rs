// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The wallet's secret store (spec §8.2, C-02, C-09): one per wallet, shared by `Arc`, a read-write lock over the generation
//! and the arena. The arena is page-aligned chunks that never move or grow (a new chunk when one is full); every secret lives
//! in it as bytes. A handle holds the `Arc`, the generation at its creation and its slot: no secret bytes. Every secret
//! operation runs under the read guard and refuses `KeyRevoked` when its generation is not the store's; `lock` takes the
//! write lock (it waits for every operation in flight), wipes the arena and raises the generation, so no earlier handle works
//! again; `open` builds a new arena at the raised generation. An operation that copies a secret out of the arena and uses the
//! copy after the guard is gone (a vault's scrypt and AEAD, a seal's KDF and AEAD after decapsulation, a backup's split and
//! seals, a group round 2) holds a read lease ([`Lease`]) for the copy's whole use: leases never wait for each other, and
//! `lock` waits until none is in flight before it wipes (T21 L82, owner 2026-11-16). Lock order: a lease is
//! taken before any guard of its store, never while one is held; `lock` holds the lease count from the moment it is zero
//! until the arena is wiped, then the write lock. The store also holds the wallet's public manifest (spec §8.3),
//! outside the arena: `lock` keeps it. Memory protection (T10, feature `mlock`, best effort): each chunk is locked in RAM
//! (`mlock`) and, on Linux and Android, excluded from core dumps (`MADV_DONTDUMP`) at allocation; at release it is wiped,
//! unmarked and unlocked. A refused call is counted in [`MemoryProtection`], never an error. Outside that coverage: the crates'
//! key types rebuilt per operation and their temporaries, the scrypt work buffer, the caller's buffers, every target without
//! `mlock` (wasm32: compiled out, nothing is locked; Windows: no `VirtualLock` in this build, reported as not locked). The
//! process-wide `PR_SET_DUMPABLE` is never set: a host app that wants it sets it itself. UNAUDITED.
// the readers of secrets (`Handle::with`, the entropy for the vault) are the signers (T3a–T3d) and the vault (T9)
#![cfg_attr(not(feature = "vectors"), allow(dead_code))]
#[cfg(feature = "wallet")]
use super::manifest::{entry_ua, Manifest};
use super::{Error, Result};
#[cfg(feature = "wallet")]
use super::{KeyId, Vault};
#[cfg(feature = "wallet")]
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Condvar, Mutex, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
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

/// `mlock` and `MADV_DONTDUMP` of a chunk (feature `mlock`, Unix); public for a binding's own secret buffers (ua-dart-frb),
/// which keep the same rule: whole pages of their own, wiped before `off`.
#[cfg(all(feature = "mlock", unix))]
pub mod protect {
    use libc::c_void;

    /// Whether `[p, p + len)` is whole pages of this system (a 64 KiB-page kernel: no, so nothing is locked or marked; an
    /// unlock there would also release a neighbouring chunk sharing the page).
    fn whole_pages(p: *mut u8, len: usize) -> bool {
        // SAFETY: sysconf reads a constant of the system
        let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(ps)
            .is_ok_and(|ps| ps > 0 && (p as usize).is_multiple_of(ps) && len.is_multiple_of(ps))
    }

    /// `(locked, no_dump)`: whether `mlock` and `MADV_DONTDUMP` took on the chunk at `p`.
    pub fn on(p: *mut u8, len: usize) -> (bool, bool) {
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
    pub fn off(p: *mut u8, len: usize, locked: bool, no_dump: bool) {
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
pub mod protect {
    /// `(false, false)`: nothing taken.
    pub fn on(_: *mut u8, _: usize) -> (bool, bool) {
        (false, false)
    }
    /// Nothing to undo.
    pub fn off(_: *mut u8, _: usize, _: bool, _: bool) {}
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
        Chunk {
            page,
            locked,
            no_dump,
        }
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
        (
            RELEASED.load(Ordering::SeqCst),
            NONZERO.load(Ordering::SeqCst),
        )
    }

    std::thread_local! {
        static PAUSE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    }

    /// `f` runs once, on this thread, at the next point where a leased operation holds its copy of a store secret (T21 L82).
    pub fn pause_after_copy(f: impl FnOnce() + 'static) {
        PAUSE.with(|p| *p.borrow_mut() = Some(Box::new(f)));
    }

    pub(super) fn copied() {
        if let Some(f) = PAUSE.with(|p| p.borrow_mut().take()) {
            f();
        }
    }
}

/// The point where a leased operation holds its copy of a store secret: the test-only pause (feature `vectors`), else nothing.
pub(crate) fn copied() {
    #[cfg(feature = "vectors")]
    vectors::copied();
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Slot {
    chunk: usize,
    start: usize,
    len: usize,
}

pub(crate) struct Arena {
    chunks: Vec<Chunk>,
    used: usize,  // bytes used in the last chunk
    total: usize, // bytes written, every chunk
    #[cfg(feature = "wallet")]
    entropy: Slot,
    #[cfg(feature = "wallet")]
    seed: Slot,
    /// The `substrate-bip39` mini-secret, computed at open from the entropy and the passphrase (ua-rs-native spec §4.3).
    #[cfg(feature = "wallet")]
    mini: Slot,
    #[cfg(feature = "wallet")]
    keys: HashMap<KeyId, (Slot, Vec<u8>)>, // a derived key: its slot and its public key data
    #[cfg(feature = "wallet")]
    tested: HashSet<KeyId>, // the keys whose self-test ran in this store (a KEM key: FIPS 203 §7.3)
    #[cfg(feature = "wallet")]
    self_tests: usize, // self-tests run in this store
    /// The DEK of each label vault opened or sealed while this arena is open, and that vault as it stands (its public
    /// envelopes): what `Wallet::reseal_label_vault` re-seals under the same DEK (scaas-sdk spec §6.10). Wiped with the arena.
    #[cfg(feature = "wallet")]
    deks: HashMap<String, (Slot, Vault)>,
    /// The PRF key-encryption key retained at a passkey or platform unlock (scaas-sdk spec §6.10, owner 2026-11-18 (b)): label
    /// vaults open with it on first use. In the arena's locked pages, so `lock` and drop zero it with them.
    #[cfg(feature = "wallet")]
    prf_kek: Option<Slot>,
    /// Slots of destroyed app-core key handles, wiped, reused by a secret of the same length (scaas-sdk spec §12.2: a ratchet
    /// makes and destroys a key per message), and the app-core handles live in this arena (feature `key-handles`).
    free: Vec<Slot>,
    #[cfg(feature = "key-handles")]
    app_live: usize,
}

impl Arena {
    /// An arena with no entropy and no seed (an ephemeral key's store).
    fn empty() -> Arena {
        #[cfg(feature = "wallet")]
        let empty = Slot {
            chunk: 0,
            start: 0,
            len: 0,
        };
        Arena {
            chunks: Vec::new(),
            used: 0,
            total: 0,
            #[cfg(feature = "wallet")]
            entropy: empty,
            #[cfg(feature = "wallet")]
            seed: empty,
            #[cfg(feature = "wallet")]
            mini: empty,
            #[cfg(feature = "wallet")]
            keys: HashMap::new(),
            #[cfg(feature = "wallet")]
            tested: HashSet::new(),
            #[cfg(feature = "wallet")]
            self_tests: 0,
            #[cfg(feature = "wallet")]
            deks: HashMap::new(),
            #[cfg(feature = "wallet")]
            prf_kek: None,
            free: Vec::new(),
            #[cfg(feature = "key-handles")]
            app_live: 0,
        }
    }

    #[cfg(feature = "wallet")]
    fn new(entropy: &[u8], seed: &[u8; 64], mini: &[u8; 32]) -> Result<Arena> {
        let mut a = Arena::empty();
        a.entropy = a.put(entropy)?;
        a.seed = a.put(seed)?;
        a.mini = a.put(mini)?;
        Ok(a)
    }

    fn put(&mut self, bytes: &[u8]) -> Result<Slot> {
        if bytes.len() > PAGE {
            return Err(Error::Argument);
        }
        if let Some(i) = self.free.iter().position(|f| f.len == bytes.len()) {
            let slot = self.free.swap_remove(i);
            self.get_mut(slot)?.copy_from_slice(bytes);
            return Ok(slot);
        }
        if self.chunks.is_empty() || PAGE - self.used < bytes.len() {
            self.chunks.push(Chunk::new());
            self.used = 0;
        }
        let slot = Slot {
            chunk: self.chunks.len() - 1,
            start: self.used,
            len: bytes.len(),
        };
        let dst = self
            .chunks
            .last_mut()
            .and_then(|c| c.page.0.get_mut(slot.start..slot.start + slot.len))
            .ok_or(Error::Argument)?;
        dst.copy_from_slice(bytes);
        self.used += bytes.len();
        self.total += bytes.len();
        Ok(slot)
    }

    fn get(&self, s: Slot) -> Result<&[u8]> {
        self.chunks
            .get(s.chunk)
            .and_then(|c| c.page.0.get(s.start..s.start + s.len))
            .ok_or(Error::KeyRevoked)
    }

    fn get_mut(&mut self, s: Slot) -> Result<&mut [u8]> {
        self.chunks
            .get_mut(s.chunk)
            .and_then(|c| c.page.0.get_mut(s.start..s.start + s.len))
            .ok_or(Error::KeyRevoked)
    }

    #[cfg(feature = "wallet")]
    pub(crate) fn entropy(&self) -> Result<&[u8]> {
        self.get(self.entropy)
    }

    #[cfg(feature = "wallet")]
    pub(crate) fn seed_bytes(&self) -> Result<&[u8]> {
        self.get(self.seed)
    }

    #[cfg(feature = "wallet")]
    pub(crate) fn mini(&self) -> Result<&[u8]> {
        self.get(self.mini)
    }

    #[cfg(feature = "wallet")]
    /// The secret of key `id`, if the arena holds it.
    pub(crate) fn secret(&self, id: KeyId) -> Option<&[u8]> {
        self.get(self.keys.get(&id)?.0).ok()
    }

    #[cfg(feature = "wallet")]
    /// Holds `dek` as the DEK of label vault `vault` (opened or sealed anew), replacing what the label held.
    // ponytail: a replaced DEK's slot stays in the arena (wiped with it at `lock`); 32 bytes per vault opened again.
    pub(crate) fn hold_dek(&mut self, dek: &[u8; 32], vault: Vault) -> Result<()> {
        let slot = self.put(dek)?;
        self.deks.insert(vault.label().to_owned(), (slot, vault));
        Ok(())
    }

    #[cfg(feature = "wallet")]
    /// Records `vault` (re-sealed under the DEK its label holds) as the label's vault; `Argument` if the label holds none.
    pub(crate) fn resealed(&mut self, vault: Vault) -> Result<()> {
        let (_, v) = self.deks.get_mut(vault.label()).ok_or(Error::Argument)?;
        *v = vault;
        Ok(())
    }

    #[cfg(feature = "wallet")]
    /// Retains `kek` as the PRF key-encryption key (replacing one retained before).
    pub(crate) fn hold_prf_kek(&mut self, kek: &[u8; 32]) -> Result<()> {
        self.prf_kek = Some(self.put(kek)?);
        Ok(())
    }

    #[cfg(feature = "wallet")]
    /// The retained PRF key-encryption key, if any.
    pub(crate) fn prf_kek(&self) -> Option<Zeroizing<[u8; 32]>> {
        Some(Zeroizing::new(
            self.get(self.prf_kek?).ok()?.try_into().ok()?,
        ))
    }

    #[cfg(feature = "wallet")]
    /// Whether label vault `label` is open in this arena (its DEK held).
    pub(crate) fn holds_label(&self, label: &str) -> bool {
        self.deks.contains_key(label)
    }

    #[cfg(feature = "wallet")]
    /// The DEK held for label vault `label` and that vault, if any.
    pub(crate) fn dek(&self, label: &str) -> Option<(Zeroizing<[u8; 32]>, Vault)> {
        let (slot, v) = self.deks.get(label)?;
        let dek: [u8; 32] = self.get(*slot).ok()?.try_into().ok()?;
        Some((Zeroizing::new(dek), v.clone()))
    }

    #[cfg(feature = "wallet")]
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
    #[cfg(feature = "wallet")]
    manifest: Manifest,
}

pub(crate) struct SecretStore {
    inner: RwLock<Inner>,
    leases: Mutex<usize>, // leases in flight
    ended: Condvar,       // signalled when the last lease ends
}

/// A read lease of a store (T21 L82): held by an operation for the whole use of a secret it copied out of the arena. Leases
/// do not wait for each other (a lease begun while `lock` waits is let in: no lease waits for another, so nested leases
/// cannot deadlock); `lock` waits until none is in flight. A lease checks nothing itself: the store access inside it refuses
/// after `lock` (`WalletLocked`, `KeyRevoked`). `lock` on a thread that holds a lease of the same store never returns.
// ponytail: reader-preferring, so a stream of overlapping leases delays `lock` until a gap; a writer-preferring count if a
// wallet ever runs leased operations back to back on many threads.
pub(crate) struct Lease<'a>(&'a SecretStore);

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        let mut n = self.0.leases.lock().unwrap_or_else(PoisonError::into_inner);
        *n -= 1;
        if *n == 0 {
            self.0.ended.notify_all();
        }
    }
}

/// A secret's place in a store: what a key handle holds instead of its bytes.
pub(crate) struct Handle {
    store: Arc<SecretStore>,
    generation: u64,
    slot: Slot,
}

#[cfg(feature = "wallet")]
/// Whether `old` and `new` give every secret the arena holds outside the derivations the same entry: none left out, none
/// listed under another entry (T21 L29, L74).
fn keeps_held(a: &Arena, old: &Manifest, new: &Manifest) -> bool {
    fn same<E: PartialEq>(a: &Arena, old: &[E], new: &[E], id: impl Fn(&E) -> KeyId) -> bool {
        let held = |e: &&E| a.secret(id(e)).is_some();
        old.iter().filter(held).all(|e| new.contains(e))
            && new.iter().filter(held).all(|e| old.contains(e))
    }
    let imports = same(a, &old.imports, &new.imports, |e| KeyId::Import(e.n));
    #[cfg(feature = "pqz")]
    let imports = imports
        && same(a, &old.pqz_held, &new.pqz_held, |p| {
            KeyId::PqzHeld(p.pqz_key_hash)
        });
    imports
}

#[cfg(feature = "wallet")]
/// `WalletMismatch` if `m` has a first entry and `seed` does not derive its UA; an empty manifest has nothing to compare.
fn seed_matches(seed: &[u8; 64], m: &Manifest) -> Result<()> {
    match m.entries.first() {
        Some(e) if entry_ua(seed, e)? != e.ua => Err(Error::WalletMismatch),
        _ => Ok(()),
    }
}

impl SecretStore {
    #[cfg(feature = "wallet")]
    pub(crate) fn new() -> Arc<SecretStore> {
        Self::of(Inner {
            generation: 0,
            arena: None,
            manifest: Manifest::default(),
        })
    }

    fn of(inner: Inner) -> Arc<SecretStore> {
        Arc::new(SecretStore {
            inner: RwLock::new(inner),
            leases: Mutex::new(0),
            ended: Condvar::new(),
        })
    }

    /// A read lease of this store (taken before any of its guards, never while one is held).
    pub(crate) fn lease(&self) -> Lease<'_> {
        *self.leases.lock().unwrap_or_else(PoisonError::into_inner) += 1;
        Lease(self)
    }

    // a panic under the lock cannot leave a half-written arena that a reader would trust: every write path below either
    // completes or returns before it touches the arena, so a poisoned lock is taken as it is
    fn read(&self) -> RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(PoisonError::into_inner)
    }
    fn write(&self) -> RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(feature = "wallet")]
    /// The arena from the entropy and its seed, at the current generation; `Argument` while one is open (a second arena would
    /// move the slots of live handles); `WalletMismatch` if the manifest kept by `lock()` has a first entry and `seed` does not
    /// derive its UA (another wallet's seed), checked under the same write lock before the arena is built. An empty manifest
    /// (a new wallet, or one locked before any UA key was derived) has nothing to compare: any seed opens it.
    pub(crate) fn open(&self, entropy: &[u8], seed: &[u8; 64], mini: &[u8; 32]) -> Result<()> {
        let mut g = self.write();
        if g.arena.is_some() {
            return Err(Error::Argument);
        }
        seed_matches(seed, &g.manifest)?;
        g.arena = Some(Arena::new(entropy, seed, mini)?);
        Ok(())
    }

    #[cfg(feature = "wallet")]
    /// Replaces the manifest (a `manifest` vault opened). While unlocked, under the write lock and before it moves:
    /// `WalletMismatch` if the open seed does not derive the UA of `m`'s first entry (as [`SecretStore::open`]), or if the
    /// entries of the secrets the arena holds outside the derivations (imports, rebuilt PQZ keys) differ between `m` and the
    /// current manifest, in either direction: `m` lists a held key under another entry (CLI-SGN-11: the held key keeps its
    /// network), or leaves a held key out (it would drop out of every later backup; T21 L74). Locked, `m` is kept and
    /// [`SecretStore::open`] checks it at the next unlock.
    pub(crate) fn set_manifest(&self, m: Manifest) -> Result<()> {
        let mut g = self.write();
        if let Some(a) = &g.arena {
            seed_matches(
                &Zeroizing::new(a.get(a.seed)?.try_into().map_err(|_| Error::Argument)?),
                &m,
            )?;
            if !keeps_held(a, &g.manifest, &m) {
                return Err(Error::WalletMismatch);
            }
        }
        g.manifest = m;
        Ok(())
    }

    /// Waits for every lease in flight, then for every operation under the guard (the write lock), wipes the arena, raises
    /// the generation. The lease count stays held until the wipe, so no lease begins in between.
    pub(crate) fn lock(&self) {
        let n = self.leases.lock().unwrap_or_else(PoisonError::into_inner);
        let _n = self
            .ended
            .wait_while(n, |n| *n > 0)
            .unwrap_or_else(PoisonError::into_inner);
        let mut g = self.write();
        g.arena = None;
        g.generation += 1;
    }

    #[cfg(feature = "wallet")]
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

    #[cfg(feature = "wallet")]
    /// [`SecretStore::key`] with `derive` over the `substrate-bip39` mini-secret in place of the seed (a Polkadot key).
    pub(crate) fn key_from_mini(
        self: &Arc<Self>,
        id: KeyId,
        derive: impl FnOnce(&[u8; 32]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)>,
    ) -> Result<(Handle, Vec<u8>)> {
        let mut g = self.write();
        let generation = g.generation;
        let arena = g.arena.as_mut().ok_or(Error::WalletLocked)?;
        let mini: Zeroizing<[u8; 32]> =
            Zeroizing::new(arena.mini()?.try_into().map_err(|_| Error::Argument)?);
        self.key_in(arena, generation, id, |_| derive(&mini))
    }

    #[cfg(feature = "wallet")]
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
                let seed: Zeroizing<[u8; 64]> = Zeroizing::new(
                    arena
                        .get(arena.seed)?
                        .try_into()
                        .map_err(|_| Error::Argument)?,
                );
                let (secret, public) = derive(&seed)?;
                let slot = arena.put(&secret)?;
                arena.keys.insert(id, (slot, public.clone()));
                (slot, public)
            }
        };
        Ok((
            Handle {
                store: self.clone(),
                generation,
                slot,
            },
            public,
        ))
    }

    #[cfg(feature = "wallet")]
    /// A one-use secret put into the open arena at the store's generation (a FROST session's nonces, spec §8.2), under the
    /// write lock: its handle, revoked by `lock()` as every other. `WalletLocked` while locked.
    pub(crate) fn put(self: &Arc<Self>, bytes: &[u8]) -> Result<Handle> {
        let mut g = self.write();
        let generation = g.generation;
        let slot = g.arena.as_mut().ok_or(Error::WalletLocked)?.put(bytes)?;
        Ok(Handle {
            store: self.clone(),
            generation,
            slot,
        })
    }

    /// An app-core key handle's secret put into the open arena (scaas-sdk spec §12.2, feature `key-handles`): `AppArenaFull` when
    /// `max` handles are live, `WalletLocked` while locked.
    #[cfg(feature = "key-handles")]
    pub(crate) fn put_app(self: &Arc<Self>, bytes: &[u8], max: usize) -> Result<Handle> {
        let mut g = self.write();
        let generation = g.generation;
        let a = g.arena.as_mut().ok_or(Error::WalletLocked)?;
        if a.app_live >= max {
            return Err(Error::AppArenaFull);
        }
        let slot = a.put(bytes)?;
        a.app_live += 1;
        Ok(Handle {
            store: self.clone(),
            generation,
            slot,
        })
    }

    /// A store of its own with an open, empty arena (no entropy, no seed): the profile arena (user-profiles spec §7.1).
    #[cfg(feature = "key-handles")]
    pub(crate) fn empty_open() -> Arc<SecretStore> {
        Self::of(Inner {
            generation: 0,
            arena: Some(Arena::empty()),
            #[cfg(feature = "wallet")]
            manifest: Manifest::default(),
        })
    }

    #[cfg(feature = "wallet")]
    /// A store of its own holding only `secret` (an ephemeral KEM key, spec §8.2), and the secret's handle.
    pub(crate) fn single(secret: &[u8]) -> Result<Handle> {
        let mut arena = Arena::empty();
        let slot = arena.put(secret)?;
        let inner = Inner {
            generation: 0,
            arena: Some(arena),
            manifest: Manifest::default(),
        };
        Ok(Handle {
            store: Self::of(inner),
            generation: 0,
            slot,
        })
    }

    /// `f` over the open arena under the read guard; `WalletLocked` while locked.
    pub(crate) fn with_arena<R>(&self, f: impl FnOnce(&Arena) -> Result<R>) -> Result<R> {
        f(self.read().arena.as_ref().ok_or(Error::WalletLocked)?)
    }

    #[cfg(feature = "wallet")]
    /// `f` over the seed under the read guard (a derivation that stores nothing: discovery); `WalletLocked` while locked.
    pub(crate) fn with_seed<R>(&self, f: impl FnOnce(&[u8; 64]) -> Result<R>) -> Result<R> {
        self.with_arena(|a| {
            f(&Zeroizing::new(
                a.get(a.seed)?.try_into().map_err(|_| Error::Argument)?,
            ))
        })
    }

    #[cfg(feature = "wallet")]
    /// `f` over the open arena and the manifest under the write lock; `WalletLocked` while locked.
    pub(crate) fn with_all<R>(
        &self,
        f: impl FnOnce(&mut Arena, &mut Manifest) -> Result<R>,
    ) -> Result<R> {
        let mut g = self.write();
        let Inner {
            arena, manifest, ..
        } = &mut *g;
        f(arena.as_mut().ok_or(Error::WalletLocked)?, manifest)
    }

    /// The open arena's protection; all zero while locked.
    pub(crate) fn memory_protection(&self) -> MemoryProtection {
        self.read()
            .arena
            .as_ref()
            .map_or_else(MemoryProtection::default, |a| MemoryProtection {
                chunks: a.chunks.len(),
                locked: a.chunks.iter().filter(|c| c.locked).count(),
                no_dump: a.chunks.iter().filter(|c| c.no_dump).count(),
            })
    }

    #[cfg(feature = "wallet")]
    /// The manifest (public; kept by `lock`).
    pub(crate) fn manifest(&self) -> Manifest {
        self.read().manifest.clone()
    }

    #[cfg(feature = "wallet")]
    /// `f` over the manifest under the write lock, locked or not.
    pub(crate) fn note(&self, f: impl FnOnce(&mut Manifest)) {
        f(&mut self.write().manifest);
    }

    #[cfg(feature = "vectors")]
    pub(crate) fn seed(&self) -> Result<Zeroizing<[u8; 64]>> {
        self.with_arena(|a| {
            Ok(Zeroizing::new(
                a.get(a.seed)?.try_into().map_err(|_| Error::Argument)?,
            ))
        })
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
        Handle {
            store: self.store.clone(),
            generation: self.generation,
            slot: self.slot,
        }
    }

    /// Whether this handle is of store `s` (a backup's sender key of the wallet that seals).
    pub(crate) fn of_store(&self, s: &Arc<SecretStore>) -> bool {
        Arc::ptr_eq(&self.store, s)
    }

    /// A read lease of this handle's store ([`Lease`]).
    pub(crate) fn lease(&self) -> Lease<'_> {
        self.store.lease()
    }

    #[cfg(feature = "wallet")]
    /// `f` over this handle's store's manifest (a KEM key written at its first use).
    pub(crate) fn note(&self, f: impl FnOnce(&mut Manifest)) {
        self.store.note(f);
    }

    /// Locks this handle's store (wipes it, revokes every handle of it): an ephemeral key's own store only.
    pub(crate) fn revoke_store(&self) {
        self.store.lock();
    }

    #[cfg(feature = "wallet")]
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

    #[cfg(feature = "wallet")]
    /// `test` over the secret once per store for key `id`, under the write lock; the record is the store's (wiped with its
    /// arena). A failed test records nothing and is returned.
    pub(crate) fn self_test(
        &self,
        id: KeyId,
        test: impl FnOnce(&[u8]) -> Result<()>,
    ) -> Result<()> {
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
        Ok(Handle {
            store: self.store.clone(),
            generation: self.generation,
            slot,
        })
    }

    /// Wipes an app-core key handle's secret and frees its slot for reuse (feature `key-handles`); nothing once the store's
    /// generation moved (the arena was wiped with it).
    #[cfg(feature = "key-handles")]
    pub(crate) fn free_app(&self) {
        let mut g = self.store.write();
        if g.generation != self.generation {
            return;
        }
        if let Some(a) = g.arena.as_mut() {
            if let Ok(s) = a.get_mut(self.slot) {
                s.zeroize();
                a.free.push(self.slot);
                a.app_live = a.app_live.saturating_sub(1);
            }
        }
    }

    /// Whether two handles name the same store.
    #[cfg(feature = "key-handles")]
    pub(crate) fn same_store(&self, store: &Arc<SecretStore>) -> bool {
        Arc::ptr_eq(&self.store, store)
    }

    /// The secret's bytes, wiped in the arena as they are read (under the write lock): a one-use secret's only read.
    pub(crate) fn take(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.take_with(|s| Zeroizing::new(s.to_vec()))
    }

    /// `f` over the secret's bytes, wiped in the arena as they are read (under the write lock), with a read lease held until
    /// `f` returns: a one-use secret's whole use, so `lock()` waits for it while other signers run (spec §8.2, T21 L73, L82).
    /// `f` may read this store; it must not `lock()` it.
    pub(crate) fn take_with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R> {
        let _lease = self.lease();
        let out = {
            let mut g = self.store.write();
            if g.generation != self.generation {
                return Err(Error::KeyRevoked);
            }
            let s = g
                .arena
                .as_mut()
                .ok_or(Error::KeyRevoked)?
                .get_mut(self.slot)?;
            let out = Zeroizing::new(s.to_vec());
            s.zeroize();
            out
        };
        copied();
        Ok(f(&out))
    }

    /// `f` over the secret's bytes, under the store's read guard: `KeyRevoked` once the store's generation moved.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R> {
        let g = self.store.read();
        if g.generation != self.generation {
            return Err(Error::KeyRevoked);
        }
        Ok(f(g
            .arena
            .as_ref()
            .ok_or(Error::KeyRevoked)?
            .get(self.slot)?))
    }

    /// Whether the bytes [`Handle::with`] gives lie inside one of the arena's chunks and outside `owner` (the handle's own
    /// allocation, address and size).
    #[cfg(feature = "vectors")]
    pub(crate) fn in_arena(&self, owner: (usize, usize)) -> Result<bool> {
        let p = self.with(|s| s.as_ptr() as usize)?;
        let g = self.store.read();
        let a = g.arena.as_ref().ok_or(Error::KeyRevoked)?;
        let in_chunk = a
            .chunks
            .iter()
            .any(|c| (c.page.0.as_ptr() as usize..c.page.0.as_ptr() as usize + PAGE).contains(&p));
        Ok(in_chunk && !(owner.0..owner.0 + owner.1).contains(&p))
    }
}
