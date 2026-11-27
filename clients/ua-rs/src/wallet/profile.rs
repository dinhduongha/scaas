// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! User-profile keys (feature `key-handles`, which `user-profile` is: no signing code, owner 2026-11-27, O15; spec
//! docs/superpowers/specs/2026-11-27-user-profiles.md §7.1, §7.2, §7.5, §10.1):
//! [`ProfileKeys`], an app-core scope over a secret store of its own (an empty arena, no seed: the arena's locked pages and
//! wipe), holds a profile's `DEK_p` and its sub-keys `K_label`, `K_item`, `K_name` after `create_dek` or an open, until `lock`
//! or drop; [`ExportKey`] holds an export file's `K_x`. Keys (HKDF-SHA256, salt empty): `KEK_pass = HKDF(Argon2id(OpaqueString
//! (passphrase), salt; m, t, 4), "scaas.profile.wrap.v1")`, `K_plat = HKDF(platform secret, "scaas.profile.platform.v1")`,
//! `K_label` / `K_item` / `K_name` = `HKDF(DEK_p, "scaas.profile.{label,item,item-name}.v1")`, `K_x = HKDF(Argon2id(…),
//! "scaas.profile-export.v1")`. AEAD AES-256-GCM-SIV, every value `nonce ‖ ct ‖ tag` with a random nonce (`seal_key` for the
//! wraps, AD `"scaas/ua/v1/keywrap" ‖ 0x01 ‖ lp(domain) ‖ public JSON`), the export's chunks excepted (nonce `prefix ‖ be32(i) ‖
//! last`, `ct ‖ tag`). Every Argon2id run checks the bounds first (`Argument`, before any run) and maps argon2's
//! `OutOfMemory` to `KdfOutOfMemory`. Byte formats: clientkeys `src/profile.js`, `smartcontracts/vectors/profile/`. UNAUDITED.
use super::aead::{aead_open, aead_seal, hkdf_sha256, hmac_sha256, Alg};
use super::appkey::{
    passphrase_bytes, random_bytes, rng, AppKeys, Argon2Params, KeyHandle, KeyUsage, Nonce, Origin,
};
use super::store::{MemoryProtection, SecretStore};
use super::{Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use zeroize::Zeroizing;

const WRAP_PASS: &[u8] = b"scaas.profile.wrap";
const WRAP_PLATFORM: &[u8] = b"scaas.profile.platform";
const LABEL: &[u8] = b"scaas.profile.label";
const ITEM: &[u8] = b"scaas.profile.item";
const EXPORT: &[u8] = b"scaas.profile-export";
const INFO_PASS: &[u8] = b"scaas.profile.wrap.v1";
const INFO_PLATFORM: &[u8] = b"scaas.profile.platform.v1";
const INFO_LABEL: &[u8] = b"scaas.profile.label.v1";
const INFO_ITEM: &[u8] = b"scaas.profile.item.v1";
const INFO_NAME: &[u8] = b"scaas.profile.item-name.v1";
const INFO_EXPORT: &[u8] = b"scaas.profile-export.v1";
const CHUNK: usize = ExportKey::CHUNK;
const HEADER_MAX: usize = ExportKey::HEADER_MAX;
/// The most chunks of one export (its payload at most 64 MiB).
const CHUNKS_MAX: u32 = 64;

/// The test-only hooks (feature `test-hooks`): process-wide, so a test that reads them runs its KDFs alone.
#[cfg(feature = "test-hooks")]
mod hooks {
    use std::sync::atomic::{AtomicBool, AtomicU64};
    pub(super) static RUNS: AtomicU64 = AtomicU64::new(0);
    pub(super) static OOM: AtomicBool = AtomicBool::new(false);
}

/// `lp(x) = be16(len(x)) ‖ x`.
fn lp(x: &[u8]) -> Result<Vec<u8>> {
    let n = u16::try_from(x.len()).map_err(|_| Error::Argument)?;
    Ok([&n.to_be_bytes()[..], x].concat())
}

fn wrap_ad(domain: &[u8], public: &[u8]) -> Result<Vec<u8>> {
    Ok([lp(domain)?, public.to_vec()].concat())
}

fn label_ad(id: &str) -> Result<Vec<u8>> {
    Ok([lp(LABEL)?, 1u16.to_be_bytes().to_vec(), lp(id.as_bytes())?].concat())
}

fn item_ad(part: &str, name: &str, rev: u64) -> Result<Vec<u8>> {
    Ok([
        lp(ITEM)?,
        1u16.to_be_bytes().to_vec(),
        lp(part.as_bytes())?,
        lp(name.as_bytes())?,
        rev.to_be_bytes().to_vec(),
    ]
    .concat())
}

fn kdf_error(e: argon2::Error) -> Error {
    match e {
        argon2::Error::OutOfMemory => Error::KdfOutOfMemory,
        _ => Error::Argument,
    }
}

/// Argon2id (RFC 9106, v 0x13, 32 bytes) of `pw` under `salt` at `kdf`, after [`ProfileKeys::kdf_check`]: every run of this
/// file comes through here (counted under `test-hooks`).
fn argon2id_raw(pw: &[u8], salt: &[u8], kdf: Argon2Params) -> Result<Zeroizing<[u8; 32]>> {
    ProfileKeys::kdf_check(kdf, salt)?;
    let p = Params::new(kdf.m_kib, kdf.t, kdf.p, Some(32)).map_err(|_| Error::Argument)?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    #[cfg(feature = "test-hooks")]
    let r = {
        use std::sync::atomic::Ordering::SeqCst;
        hooks::RUNS.fetch_add(1, SeqCst);
        match hooks::OOM.load(SeqCst) {
            true => Err(argon2::Error::OutOfMemory),
            false => a.hash_password_into(pw, salt, &mut out[..]),
        }
    };
    #[cfg(not(feature = "test-hooks"))]
    let r = a.hash_password_into(pw, salt, &mut out[..]);
    r.map_err(kdf_error)?;
    Ok(out)
}

/// The Argon2id of a typed passphrase's OpaqueString bytes, a `Derive` handle of `keys`.
fn stretch(keys: &AppKeys, passphrase: &[u8], salt: &[u8], kdf: Argon2Params) -> Result<KeyHandle> {
    let out = argon2id_raw(&passphrase_bytes(passphrase)?, salt, kdf)?;
    keys.make(&out[..], KeyUsage::Derive, Origin::Derived, None)
}

struct Keys {
    dek: KeyHandle,
    label: KeyHandle,
    item: KeyHandle,
    name: KeyHandle,
}

enum State {
    Empty,
    Open(Box<Keys>),
    Locked,
}

/// One profile's keys in an arena of its own. No `Clone`, `Debug` or byte accessor; `lock` (or drop) wipes the arena, and
/// every call after `lock` is `WalletLocked`.
pub struct ProfileKeys {
    store: Arc<SecretStore>,
    keys: AppKeys,
    state: Mutex<State>,
}

impl Default for ProfileKeys {
    fn default() -> Self {
        Self::new()
    }
}

impl ProfileKeys {
    /// The default parameters (64 MiB, 3 passes, 4 lanes; owner Q-UP2).
    pub const KDF_DEFAULT: Argon2Params = Argon2Params {
        m_kib: 65_536,
        t: 3,
        p: 4,
    };
    /// The test set (8 MiB, 1 pass, 4 lanes; spec §7.5), accepted only under feature `test-hooks`.
    #[cfg(feature = "test-hooks")]
    pub const KDF_TEST: Argon2Params = Argon2Params {
        m_kib: 8192,
        t: 1,
        p: 4,
    };

    /// An empty profile arena: no key until [`ProfileKeys::create_dek`] or an open.
    pub fn new() -> ProfileKeys {
        let store = SecretStore::empty_open();
        ProfileKeys {
            keys: AppKeys::over(store.clone()),
            store,
            state: Mutex::new(State::Empty),
        }
    }

    /// The general bounds of spec §7.5, each field alone: `m` 65,536 to 1,048,576 KiB, `t` 3 to 10, `p` 4, a 16-byte salt;
    /// under `test-hooks` also exactly the test set. Else `Argument` (the SDK's `ProfileFormat`).
    pub fn kdf_check(kdf: Argon2Params, salt: &[u8]) -> Result<()> {
        let ok = (65_536..=1_048_576).contains(&kdf.m_kib) && (3..=10).contains(&kdf.t);
        #[cfg(feature = "test-hooks")]
        let ok = ok || (kdf.m_kib == 8192 && kdf.t == 1);
        if !ok || kdf.p != 4 || salt.len() != 16 {
            return Err(Error::Argument);
        }
        Ok(())
    }

    /// Randomness from the OS generator, at most 4,096 bytes (`Argument` above), in a buffer wiped on drop: a profile id's
    /// random bytes, a temporary directory's tag, the Matrix store key's bytes (the one key that leaves the arena,
    /// user-profiles spec §7.2; CLI-SDK-01: `scaas-profile` draws its randomness here). Needs no key: an empty or locked
    /// arena's too.
    pub fn random_bytes(n: usize) -> Result<Zeroizing<Vec<u8>>> {
        random_bytes(n).map(Zeroizing::new)
    }

    /// One Argon2id run at `kdf` over a random input, its output dropped (a hidden search's dummy run, spec §8).
    pub fn dummy_kdf(kdf: Argon2Params) -> Result<()> {
        let (mut pw, mut salt) = (Zeroizing::new([0u8; 32]), [0u8; 16]);
        rng(&mut pw[..])?;
        rng(&mut salt)?;
        argon2id_raw(&pw[..], &salt, kdf).map(drop)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `f` over the held keys; `WalletLocked` while none is held (before an open, after `lock`).
    fn with<R>(&self, f: impl FnOnce(&Keys) -> Result<R>) -> Result<R> {
        match &*self.state() {
            State::Open(k) => f(k),
            _ => Err(Error::WalletLocked),
        }
    }

    /// `Ok` while no key is held; `Argument` while one is, `WalletLocked` after `lock`.
    fn empty(&self) -> Result<()> {
        match &*self.state() {
            State::Empty => Ok(()),
            State::Open(_) => Err(Error::Argument),
            State::Locked => Err(Error::WalletLocked),
        }
    }

    /// `dek` and its sub-keys held.
    fn hold(&self, dek: KeyHandle) -> Result<()> {
        let d = |info, usage| self.keys.derive(&[&dek], &[], info, usage, false);
        let (label, item, name) = (
            d(INFO_LABEL, KeyUsage::Data)?,
            d(INFO_ITEM, KeyUsage::Data)?,
            d(INFO_NAME, KeyUsage::Derive)?,
        );
        let mut s = self.state();
        match &*s {
            State::Empty => {
                *s = State::Open(Box::new(Keys {
                    dek,
                    label,
                    item,
                    name,
                }));
                Ok(())
            }
            State::Open(_) => Err(Error::Argument),
            State::Locked => Err(Error::WalletLocked),
        }
    }

    /// A fresh random `DEK_p` (a new protected profile, a re-seal's new generation).
    pub fn create_dek(&self) -> Result<()> {
        self.empty()?;
        self.hold(self.keys.random_key(KeyUsage::Derive)?)
    }

    fn kek_pass(&self, passphrase: &[u8], salt: &[u8], kdf: Argon2Params) -> Result<KeyHandle> {
        let s = stretch(&self.keys, passphrase, salt, kdf)?;
        self.keys
            .derive(&[&s], &[], INFO_PASS, KeyUsage::KeyWrap, false)
    }

    fn k_platform(&self, secret: &[u8]) -> Result<KeyHandle> {
        // an app that left the lent buffer zero (or gave none) has no secret (spec §7.6)
        if secret.iter().fold(0u8, |a, b| a | b) == 0 {
            return Err(Error::Argument);
        }
        let k = hkdf_sha256(secret, &[], INFO_PLATFORM, 32)?;
        self.keys.make(&k, KeyUsage::KeyWrap, Origin::Derived, None)
    }

    /// The envelope's `pass`: the held `DEK_p` under `KEK_pass` (60 bytes), AD `lp("scaas.profile.wrap") ‖ public`, `public`
    /// the canonical public JSON (`format`, `v`, `id`, `state`, `gen`, `kdf`).
    pub fn wrap_pass(
        &self,
        passphrase: &[u8],
        salt: &[u8],
        kdf: Argon2Params,
        public: &[u8],
    ) -> Result<Vec<u8>> {
        self.with(|_| Ok(()))?;
        let kek = self.kek_pass(passphrase, salt, kdf)?;
        self.with(|k| {
            self.keys
                .seal_key(&kek, &k.dek, &wrap_ad(WRAP_PASS, public)?)
        })
    }

    /// Opens `pass` and holds its `DEK_p`: `Aead` for a wrong passphrase or an altered wrap or public JSON.
    pub fn open_pass(
        &self,
        passphrase: &[u8],
        salt: &[u8],
        kdf: Argon2Params,
        public: &[u8],
        wrap: &[u8],
    ) -> Result<()> {
        self.empty()?;
        if wrap.len() != 60 {
            return Err(Error::Argument);
        }
        let kek = self.kek_pass(passphrase, salt, kdf)?;
        let ad = wrap_ad(WRAP_PASS, public)?;
        self.hold(self.keys.open_key(&kek, wrap, KeyUsage::Derive, &ad)?)
    }

    /// Whether the typed passphrase opens `pass` to the held `DEK_p` (compared in constant time): `Ok`, else `Aead` (an export,
    /// a weakening settings change, spec §7.7, §10.1).
    pub fn check_pass(
        &self,
        passphrase: &[u8],
        salt: &[u8],
        kdf: Argon2Params,
        public: &[u8],
        wrap: &[u8],
    ) -> Result<()> {
        self.with(|_| Ok(()))?;
        if wrap.len() != 60 {
            return Err(Error::Argument);
        }
        let kek = self.kek_pass(passphrase, salt, kdf)?;
        let dek = self
            .keys
            .open_key(&kek, wrap, KeyUsage::Derive, &wrap_ad(WRAP_PASS, public)?)?;
        match self.with(|k| self.keys.same_key(&k.dek, &dek))? {
            true => Ok(()),
            false => Err(Error::Aead),
        }
    }

    /// `platform.wrap`: the held `DEK_p` under `K_plat` of the platform secret (all zero or empty: `Argument`), AD
    /// `lp("scaas.profile.platform") ‖ public`.
    pub fn wrap_platform(&self, secret: &[u8], public: &[u8]) -> Result<Vec<u8>> {
        self.with(|_| Ok(()))?;
        let kp = self.k_platform(secret)?;
        self.with(|k| {
            self.keys
                .seal_key(&kp, &k.dek, &wrap_ad(WRAP_PLATFORM, public)?)
        })
    }

    /// Opens `platform.wrap` and holds its `DEK_p`: `Aead` when it does not open.
    pub fn open_platform(&self, secret: &[u8], public: &[u8], wrap: &[u8]) -> Result<()> {
        self.empty()?;
        let kp = self.k_platform(secret)?;
        let ad = wrap_ad(WRAP_PLATFORM, public)?;
        self.hold(self.keys.open_key(&kp, wrap, KeyUsage::Derive, &ad)?)
    }

    /// The envelope's `label`: `json` (`{"name":…,"hidden":…}`) under `K_label`, AD `lp("scaas.profile.label") ‖ be16(1) ‖
    /// lp(id)`, a random nonce.
    pub fn seal_label(&self, id: &str, json: &[u8]) -> Result<Vec<u8>> {
        self.with(|k| {
            self.keys
                .seal(&k.label, Nonce::Random, &label_ad(id)?, json)
        })
    }

    /// The plaintext of a `label` of profile `id`: `Aead` when it does not open.
    pub fn open_label(&self, id: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.with(|k| {
            self.keys
                .open(&k.label, Nonce::Random, &label_ad(id)?, sealed)
        })
    }

    /// An item's file name: `hex(HMAC-SHA256(K_name, lp(part) ‖ lp(name)))`, 64 lower-case hex characters (public).
    pub fn item_file(&self, part: &str, name: &str) -> Result<String> {
        self.with(|k| {
            let data = [lp(part.as_bytes())?, lp(name.as_bytes())?].concat();
            let m = hmac_sha256(&self.keys.bytes(&k.name)?[..], &data);
            Ok(m.iter().map(|b| format!("{b:02x}")).collect())
        })
    }

    /// An item's `sealed`: `pt` under `K_item`, AD `lp("scaas.profile.item") ‖ be16(1) ‖ lp(part) ‖ lp(name) ‖ be64(rev)`, a
    /// random nonce.
    pub fn seal_item(&self, part: &str, name: &str, rev: u64, pt: &[u8]) -> Result<Vec<u8>> {
        self.with(|k| {
            self.keys
                .seal(&k.item, Nonce::Random, &item_ad(part, name, rev)?, pt)
        })
    }

    /// The plaintext of an item's `sealed` at (part, name, rev): `Aead` when it does not open.
    pub fn open_item(
        &self,
        part: &str,
        name: &str,
        rev: u64,
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.with(|k| {
            self.keys
                .open(&k.item, Nonce::Random, &item_ad(part, name, rev)?, sealed)
        })
    }

    /// Wipes the arena (every key) for good: every later call is `WalletLocked`.
    pub fn lock(&self) {
        let mut s = self.state();
        *s = State::Locked;
        self.store.lock();
    }

    /// The arena's protection now; all zero after `lock`.
    pub fn memory_protection(&self) -> MemoryProtection {
        self.store.memory_protection()
    }
}

/// Test-only hooks (feature `test-hooks`, never in a release build).
#[cfg(feature = "test-hooks")]
impl ProfileKeys {
    /// The Argon2id runs of this process (every entry of this file, dummy runs and forced failures included).
    pub fn kdf_runs() -> u64 {
        hooks::RUNS.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// While on, every Argon2id run of this process fails as argon2's `OutOfMemory`.
    pub fn force_kdf_oom(on: bool) {
        hooks::OOM.store(on, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Test-only entry points (feature `vectors`, never in a release build): fixed inputs and nonces, revealed keys.
#[cfg(feature = "vectors")]
impl ProfileKeys {
    /// Holds `dek` as `DEK_p` (a vector's input).
    pub fn vectors_set_dek(&self, dek: &[u8; 32]) -> Result<()> {
        self.empty()?;
        self.hold(self.keys.vectors_import(dek, KeyUsage::Derive)?)
    }

    /// `[DEK_p, K_label, K_item, K_name]`.
    pub fn vectors_reveal(&self) -> Result<[Vec<u8>; 4]> {
        self.with(|k| {
            let r = |h: &KeyHandle| self.keys.vectors_reveal(h);
            Ok([r(&k.dek)?, r(&k.label)?, r(&k.item)?, r(&k.name)?])
        })
    }

    /// [`ProfileKeys::wrap_pass`] with a fixed nonce: `(Argon2id output, KEK_pass, pass)` of one run.
    pub fn vectors_wrap_pass(
        &self,
        passphrase: &[u8],
        salt: &[u8],
        kdf: Argon2Params,
        public: &[u8],
        nonce: &[u8; 12],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        self.with(|_| Ok(()))?;
        let s = stretch(&self.keys, passphrase, salt, kdf)?;
        let kek = self
            .keys
            .derive(&[&s], &[], INFO_PASS, KeyUsage::KeyWrap, false)?;
        let ad = wrap_ad(WRAP_PASS, public)?;
        let w = self.with(|k| self.keys.vectors_seal_key(&kek, &k.dek, nonce, &ad))?;
        Ok((
            self.keys.vectors_reveal(&s)?,
            self.keys.vectors_reveal(&kek)?,
            w,
        ))
    }

    /// [`ProfileKeys::wrap_platform`] with a fixed nonce: `(K_plat, platform.wrap)`.
    pub fn vectors_wrap_platform(
        &self,
        secret: &[u8],
        public: &[u8],
        nonce: &[u8; 12],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let kp = self.k_platform(secret)?;
        let ad = wrap_ad(WRAP_PLATFORM, public)?;
        let w = self.with(|k| self.keys.vectors_seal_key(&kp, &k.dek, nonce, &ad))?;
        Ok((self.keys.vectors_reveal(&kp)?, w))
    }

    /// [`ProfileKeys::seal_label`] with a fixed nonce.
    pub fn vectors_seal_label(&self, id: &str, json: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        self.with(|k| {
            let ct = self
                .keys
                .vectors_seal(&k.label, nonce, &label_ad(id)?, json)?;
            Ok([&nonce[..], &ct].concat())
        })
    }

    /// [`ProfileKeys::seal_item`] with a fixed nonce.
    pub fn vectors_seal_item(
        &self,
        part: &str,
        name: &str,
        rev: u64,
        pt: &[u8],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>> {
        self.with(|k| {
            let ct = self
                .keys
                .vectors_seal(&k.item, nonce, &item_ad(part, name, rev)?, pt)?;
            Ok([&nonce[..], &ct].concat())
        })
    }
}

/// An export file's `K_x` in an arena of its own (wiped at drop).
pub struct ExportKey {
    keys: AppKeys,
    kx: KeyHandle,
}

impl ExportKey {
    /// An export chunk's plaintext: every chunk but the last exactly this, the last 1 to this.
    pub const CHUNK: usize = 1_048_576;
    /// The export header's largest length.
    pub const HEADER_MAX: usize = 4096;

    /// `K_x = HKDF(Argon2id(OpaqueString(passphrase), salt; kdf), "scaas.profile-export.v1")`; the bounds first (`Argument`).
    pub fn derive(passphrase: &[u8], salt: &[u8], kdf: Argon2Params) -> Result<ExportKey> {
        let keys = AppKeys::over(SecretStore::empty_open());
        let s = stretch(&keys, passphrase, salt, kdf)?;
        let kx = keys.derive(&[&s], &[], INFO_EXPORT, KeyUsage::Data, false)?;
        Ok(ExportKey { keys, kx })
    }

    /// Chunk `i`'s nonce `prefix ‖ be32(i) ‖ last` and AD `lp("scaas.profile-export") ‖ be32(len(header)) ‖ header ‖ be32(i)`.
    fn nonce_ad(
        prefix: &[u8; 7],
        i: u32,
        last: bool,
        header: &[u8],
    ) -> Result<([u8; 12], Vec<u8>)> {
        if i >= CHUNKS_MAX || header.len() > HEADER_MAX {
            return Err(Error::Argument);
        }
        let hl = u32::try_from(header.len()).map_err(|_| Error::Argument)?;
        let n = [&prefix[..], &i.to_be_bytes(), &[u8::from(last)]]
            .concat()
            .try_into()
            .map_err(|_| Error::Argument)?;
        let ad = [
            &lp(EXPORT)?[..],
            &hl.to_be_bytes(),
            header,
            &i.to_be_bytes(),
        ]
        .concat();
        Ok((n, ad))
    }

    /// Chunk `i` of the payload as `ct ‖ tag`: `pt` exactly [`ExportKey::CHUNK`] bytes before the last, 1 to it on the last; at
    /// most 64 chunks; else `Argument`.
    pub fn seal_chunk(
        &self,
        prefix: &[u8; 7],
        i: u32,
        last: bool,
        header: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>> {
        if pt.is_empty() || pt.len() > CHUNK || (!last && pt.len() != CHUNK) {
            return Err(Error::Argument);
        }
        let (n, ad) = Self::nonce_ad(prefix, i, last, header)?;
        aead_seal(Alg::Aes256GcmSiv, &*self.keys.bytes(&self.kx)?, &n, &ad, pt)
    }

    /// The plaintext of chunk `i`: `Aead` for a chunk of another length, index, flag, header or key.
    pub fn open_chunk(
        &self,
        prefix: &[u8; 7],
        i: u32,
        last: bool,
        header: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let (n, ad) = Self::nonce_ad(prefix, i, last, header)?;
        if ct.len() <= 16 || ct.len() > CHUNK + 16 || (!last && ct.len() != CHUNK + 16) {
            return Err(Error::Aead);
        }
        aead_open(Alg::Aes256GcmSiv, &*self.keys.bytes(&self.kx)?, &n, &ad, ct)
    }

    /// `K_x` (a vector's comparison; feature `vectors`).
    #[cfg(feature = "vectors")]
    pub fn vectors_reveal(&self) -> Result<Vec<u8>> {
        self.keys.vectors_reveal(&self.kx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test set is accepted only in a build with `test-hooks` (spec §7.5): run once with and once without the feature.
    #[test]
    fn profile_test_set_only_under_test_hooks() {
        let r = ProfileKeys::kdf_check(
            Argon2Params {
                m_kib: 8192,
                t: 1,
                p: 4,
            },
            &[0; 16],
        );
        if cfg!(feature = "test-hooks") {
            assert_eq!(r, Ok(()));
        } else {
            assert_eq!(r, Err(Error::Argument));
        }
        assert_eq!(
            ProfileKeys::kdf_check(ProfileKeys::KDF_DEFAULT, &[0; 16]),
            Ok(())
        );
    }
}
