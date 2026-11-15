// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The ML-DSA expanded-key cache's part transactions (CTR-UA-23 MD-3 / MD-4, NODE-JOB-29; owner 2026-11-15; clientkeys
//! `cacheExpandedKeyCall`, `mldsaCacheCalls`, `cacheThenRegister`). On a registry without the ML-DSA precompile (the deploy JSON's
//! `mldsa<x>_path` = `cache`) `register` of an ML-DSA key reverts `UAKeyNotCached(ua)` until every part is stored:
//! `cacheExpandedKey(kind, pk, part)` per part, a plain call (no signature; the subject or anyone sends it), then the
//! registration. The registry derives each part from `pk` itself; nothing here is a check of record. UNAUDITED.
use crate::ua8::{registration_args, Registration, RegistrationInput};
use crate::{word, UAError};

/// `keccak256("cacheExpandedKey(uint16,bytes,uint256)")[..4]`.
pub const CACHE_EXPANDED_KEY_SELECTOR: [u8; 4] = [0x8b, 0x73, 0x88, 0x73];

/// `(FIPS 204 public key length, cache part count)` of an ML-DSA kind (`PqUA.mldsaParts`); `None` for every other kind.
fn cache_of(kind: u16) -> Option<(usize, u64)> {
    match kind {
        0x0130 => Some((1312, 1)),
        0x0131 => Some((1952, 2)),
        0x0134 => Some((2592, 3)),
        _ => None,
    }
}

/// A refusal by the registry's error name: [`CacheError::code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheError {
    /// `UAKeyCache(kind)`: a kind with no cache, or a part past the last.
    KeyCache(u16),
    /// `UAKeyData`: a key of another length than the kind's.
    KeyData(u16),
    /// The registration itself ([`registration_args`]).
    Registration(UAError),
}

impl CacheError {
    pub fn code(&self) -> &'static str {
        match self {
            CacheError::KeyCache(_) => "UAKeyCache",
            CacheError::KeyData(_) => "UAKeyData",
            CacheError::Registration(e) => e.code(),
        }
    }
}

impl core::fmt::Display for CacheError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CacheError::Registration(e) => write!(f, "{e}"),
            CacheError::KeyCache(k) | CacheError::KeyData(k) => write!(f, "{}({k:#06x})", self.code()),
        }
    }
}

impl std::error::Error for CacheError {}

/// The cache part count of `kind`: 1 / 2 / 3 for mldsa44 / mldsa65 / mldsa87, 0 for every other kind (no cache).
pub fn parts(kind: u16) -> u64 {
    cache_of(kind).map_or(0, |(_, n)| n)
}

/// `cacheExpandedKey(kind, pk, part)` calldata, from the named fields.
pub fn part_call(kind: u16, pk: &[u8], part: u64) -> Result<Vec<u8>, CacheError> {
    let (len, n) = cache_of(kind).ok_or(CacheError::KeyCache(kind))?;
    if pk.len() != len {
        return Err(CacheError::KeyData(kind));
    }
    if part >= n {
        return Err(CacheError::KeyCache(kind));
    }
    let mut d = CACHE_EXPANDED_KEY_SELECTOR.to_vec();
    for w in [kind as u64, 96, part, len as u64] {
        d.extend_from_slice(&word(w));
    }
    d.extend_from_slice(pk);
    d.resize(d.len() + len.next_multiple_of(32) - len, 0);
    Ok(d)
}

/// Every part's calldata of `pk`, in part order.
pub fn part_calls(kind: u16, pk: &[u8]) -> Result<Vec<Vec<u8>>, CacheError> {
    (0..parts(kind).max(1)).map(|p| part_call(kind, pk, p)).collect()
}

/// The cache-then-register order: send `parts` in order (each after the last landed), then `registration` (its `kem_fill` after
/// it, as [`registration_args`] says).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheThenRegister {
    /// Each part's `cacheExpandedKey` calldata; empty for a kind with no cache.
    pub parts: Vec<Vec<u8>>,
    pub registration: Registration,
}

/// [`CacheThenRegister`] of `i`: an ML-DSA key's parts, then its registration; any other kind its registration alone.
pub fn cache_then_register(i: &RegistrationInput) -> Result<CacheThenRegister, CacheError> {
    let registration = registration_args(i).map_err(CacheError::Registration)?;
    let parts = if parts(i.kind) == 0 { Vec::new() } else { part_calls(i.kind, &i.key_data)? };
    Ok(CacheThenRegister { parts, registration })
}

#[cfg(test)]
mod tests {
    #[test]
    fn selector_is_the_signature_hash() {
        assert_eq!(crate::keccak256(b"cacheExpandedKey(uint16,bytes,uint256)")[..4], super::CACHE_EXPANDED_KEY_SELECTOR);
    }
}
