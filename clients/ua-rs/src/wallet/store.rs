// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The wallet's secret store (spec §8.2, C-02, C-09): one per wallet, shared by `Arc`, a read-write lock over the generation
//! and the arena. The arena is page-aligned chunks that never move or grow (a new chunk when one is full); every secret lives
//! in it as bytes. A handle holds the `Arc`, the generation at its creation and its slot: no secret bytes. Every secret
//! operation runs under the read guard and refuses `KeyRevoked` when its generation is not the store's; `lock` takes the
//! write lock (it waits for every operation in flight), wipes the arena and raises the generation, so no earlier handle works
//! again; `open` builds a new arena at the raised generation. `mlock` / no-dump of the chunks is T10. UNAUDITED.
// the readers of secrets (`Handle::with`, the entropy for the vault) are the signers (T3a–T3d) and the vault (T9)
#![cfg_attr(not(feature = "vectors"), allow(dead_code))]
use super::{Error, KeyId, Result};
use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use zeroize::{Zeroize, Zeroizing};

/// The chunk size and alignment: the largest page of a listed target (16 KiB on Apple aarch64 and 16 KiB Android), so a
/// chunk never shares a page with other data. A secret is at most one chunk (the largest planned: an ML-DSA-87 expanded key,
/// 4,896 B).
pub(crate) const PAGE: usize = 16384;

#[repr(C, align(16384))]
struct Page([u8; PAGE]);

#[derive(Clone, Copy, Debug)]
pub(crate) struct Slot {
    chunk: usize,
    start: usize,
    len: usize,
}

pub(crate) struct Arena {
    chunks: Vec<Box<Page>>,
    used: usize, // bytes used in the last chunk
    total: usize, // bytes written, every chunk
    entropy: Slot,
    seed: Slot,
    keys: HashMap<KeyId, (Slot, Vec<u8>)>, // a derived key: its slot and its public key data
}

impl Arena {
    fn new(entropy: &[u8], seed: &[u8; 64]) -> Result<Arena> {
        let empty = Slot { chunk: 0, start: 0, len: 0 };
        let mut a = Arena { chunks: Vec::new(), used: 0, total: 0, entropy: empty, seed: empty, keys: HashMap::new() };
        a.entropy = a.put(entropy)?;
        a.seed = a.put(seed)?;
        Ok(a)
    }

    fn put(&mut self, bytes: &[u8]) -> Result<Slot> {
        if bytes.len() > PAGE {
            return Err(Error::Argument);
        }
        if self.chunks.is_empty() || PAGE - self.used < bytes.len() {
            self.chunks.push(Box::new(Page([0; PAGE])));
            self.used = 0;
        }
        let slot = Slot { chunk: self.chunks.len() - 1, start: self.used, len: bytes.len() };
        let dst = self.chunks.last_mut().and_then(|c| c.0.get_mut(slot.start..slot.start + slot.len)).ok_or(Error::Argument)?;
        dst.copy_from_slice(bytes);
        self.used += bytes.len();
        self.total += bytes.len();
        Ok(slot)
    }

    fn get(&self, s: Slot) -> Result<&[u8]> {
        self.chunks.get(s.chunk).and_then(|c| c.0.get(s.start..s.start + s.len)).ok_or(Error::KeyRevoked)
    }

    fn get_mut(&mut self, s: Slot) -> Result<&mut [u8]> {
        self.chunks.get_mut(s.chunk).and_then(|c| c.0.get_mut(s.start..s.start + s.len)).ok_or(Error::KeyRevoked)
    }

    pub(crate) fn entropy(&self) -> Result<&[u8]> {
        self.get(self.entropy)
    }

}

impl Drop for Arena {
    fn drop(&mut self) {
        for c in &mut self.chunks {
            c.0.zeroize();
        }
    }
}

struct Inner {
    generation: u64,
    arena: Option<Arena>,
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
        Arc::new(SecretStore(RwLock::new(Inner { generation: 0, arena: None })))
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

    /// `f` over the open arena under the read guard; `WalletLocked` while locked.
    pub(crate) fn with_arena<R>(&self, f: impl FnOnce(&Arena) -> Result<R>) -> Result<R> {
        f(self.read().arena.as_ref().ok_or(Error::WalletLocked)?)
    }

    #[cfg(feature = "vectors")]
    pub(crate) fn seed(&self) -> Result<Zeroizing<[u8; 64]>> {
        self.with_arena(|a| Ok(Zeroizing::new(a.get(a.seed)?.try_into().map_err(|_| Error::Argument)?)))
    }

    #[cfg(feature = "vectors")]
    pub(crate) fn used(&self) -> Result<usize> {
        self.with_arena(|a| Ok(a.total))
    }
}

impl Handle {
    /// A second handle of the same secret (a session keeps its key's), for the crate only: handles are not `Clone`.
    pub(crate) fn dup(&self) -> Handle {
        Handle { store: self.store.clone(), generation: self.generation, slot: self.slot }
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
        let in_chunk = a.chunks.iter().any(|c| (c.0.as_ptr() as usize..c.0.as_ptr() as usize + PAGE).contains(&p));
        Ok(in_chunk && !(owner.0..owner.0 + owner.1).contains(&p))
    }
}
