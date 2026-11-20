// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! App-core key handles (scaas-sdk spec §12.2, §12.3, §23.1 item 9; feature `app-core`): an app core above the SDK holds
//! [`KeyHandle`]s, never key bytes. A handle's secret lies in its wallet's arena (locked pages, wiped at `lock`, which revokes
//! every handle), it has one [`KeyUsage`] fixed when it is made, belongs to the [`AppKeys`] scope that made it
//! (`AppHandleForeign` in another), and is neither `Clone`, `Debug` nor readable:
//!
//! ```compile_fail
//! fn f(h: scaas_ua::wallet::KeyHandle) { let _ = h.clone(); }
//! ```
//! ```compile_fail
//! fn f(h: scaas_ua::wallet::KeyHandle) { println!("{h:?}"); }
//! ```
//!
//! The usage is metadata enforced at every use (`AppKeyUsage`) and enters no byte (review K4), except [`AppKeys::seal_key`]'s
//! AAD `"scaas/ua/v1/keywrap" ‖ u8(usage) ‖ aad`, which `seal` and `open` refuse as a prefix. The KEM wrap's KDF info is
//! `label ‖ aad ‖ 0x01 ‖ keccak256(kemPk)` with `kemPk` the recipient's, the wrapped key under AES-256-GCM, nonce `0^96`,
//! AAD `aad`. Byte formats: clientkeys `src/appcore.js`, `smartcontracts/vectors/appcore/handles.json`. At most
//! [`APP_KEYS_MAX`] handles live in one arena (`AppArenaFull` past it; a destroyed handle's slot is reused). No app's label
//! or constant lives here: labels are the caller's. UNAUDITED.
use super::aead::{aead_open, aead_seal, hkdf_sha256, hmac_sha256, Alg};
use super::kem::KemKeyPair;
use super::store::{Handle, SecretStore};
use super::{Error, Result, Wallet};
use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{OsRng, RngCore};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use zeroize::Zeroizing;

/// The live app-core key handles one arena holds (scaas-sdk spec §12.2: UA-7 keeps up to 2,000 skipped keys per chain;
/// 16,384 handles of 32 bytes are 512 KiB of locked pages).
pub const APP_KEYS_MAX: usize = 16_384;
/// [`AppKeys::seal_key`]'s AAD prefix; `seal` and `open` refuse an `aad` that starts with it.
pub const KEYWRAP: &[u8] = b"scaas/ua/v1/keywrap";
/// The label of an app's per-account storage root ([`AppKeys::app_root_key`]).
pub const APP_ROOT: &[u8] = b"scaas/app/v1/root";
/// The most bytes [`AppKeys::random_bytes`] gives in one call.
const RANDOM_MAX: usize = 4096;

/// A handle's one usage, fixed when it is made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyUsage {
    /// HKDF or HMAC input only.
    Derive = 1,
    /// `seal` / `open`.
    Data = 2,
    /// `seal_key` / `open_key`.
    KeyWrap = 3,
}

/// How a handle came to be: the public MAC runs only on a key the scope drew or unwrapped (review K4, pqchat-core §5.3).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Origin {
    Drawn,
    Unwrapped,
    Derived,
}

/// A key in the arena. No `Clone`, `Debug` or byte accessor; released by [`AppKeys::destroy`] or the wallet's `lock`.
pub struct KeyHandle {
    h: Handle,
    usage: KeyUsage,
    scope: u64,
    origin: Origin,
    /// the nonce an HKDF output of 44 bytes gave with the key (`okm[32:44]`), for [`Nonce::FromKey`]
    nonce: Option<[u8; 12]>,
}

/// A dropped handle's key is wiped and its slot freed, as by [`AppKeys::destroy`].
impl Drop for KeyHandle {
    fn drop(&mut self) {
        self.h.free_app();
    }
}

impl KeyHandle {
    /// The usage fixed at its making.
    pub fn usage(&self) -> KeyUsage {
        self.usage
    }
}

/// A `seal` / `open` nonce.
pub enum Nonce<'a> {
    /// 12 random bytes, prepended to the output (`open` reads them from the input's start).
    Random,
    /// The nonce the key's own derivation gave (`okm[32:44]`): not in the output.
    FromKey,
    /// `HMAC(handle, 0x03)[0:12]` of a `Derive` handle (UA-7 §6.3): not in the output.
    FromHandle(&'a KeyHandle),
}

/// A KEM wrap of a key handle: the encapsulation and the sealed key (48 bytes for a 32-byte key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KemWrap {
    pub mlkem_ct: Vec<u8>,
    pub x25519_eph: [u8; 32],
    pub sealed_key: Vec<u8>,
}

/// Argon2id parameters (RFC 9106, version 0x13): memory in KiB, passes, lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

static SCOPES: AtomicU64 = AtomicU64::new(1);

/// One app core's scope of key handles over a wallet's arena.
pub struct AppKeys {
    store: Arc<SecretStore>,
    scope: u64,
}

impl Wallet {
    /// A new scope of app-core key handles over this wallet's arena: its handles serve this scope only.
    pub fn app_keys(&self) -> AppKeys {
        AppKeys {
            store: self.store.clone(),
            scope: SCOPES.fetch_add(1, Ordering::Relaxed),
        }
    }
}

fn rng(out: &mut [u8]) -> Result<()> {
    OsRng.try_fill_bytes(out).map_err(|_| Error::Rng)
}

fn key32(s: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    Ok(Zeroizing::new(s.try_into().map_err(|_| Error::Argument)?))
}

fn keywrap_aad(usage: KeyUsage, aad: &[u8]) -> Vec<u8> {
    [KEYWRAP, &[usage as u8], aad].concat()
}

fn refuse_keywrap(aad: &[u8]) -> Result<()> {
    if aad.starts_with(KEYWRAP) {
        return Err(Error::AppKeyUsage);
    }
    Ok(())
}

/// The KEK of a wrap to `kem_pk`: HKDF(ss, salt empty, info = label ‖ aad ‖ 0x01 ‖ keccak256(kem_pk), 32).
fn wrap_kek(ss: &[u8; 32], label: &[u8], aad: &[u8], kem_pk: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let info = [label, aad, &[1u8], &crate::keccak256(kem_pk)].concat();
    key32(&hkdf_sha256(ss, &[], &info, 32)?)
}

impl AppKeys {
    fn check(&self, h: &KeyHandle) -> Result<()> {
        if h.scope != self.scope || !h.h.same_store(&self.store) {
            return Err(Error::AppHandleForeign);
        }
        Ok(())
    }

    fn check_usage(&self, h: &KeyHandle, usage: KeyUsage) -> Result<()> {
        self.check(h)?;
        if h.usage != usage {
            return Err(Error::AppKeyUsage);
        }
        Ok(())
    }

    fn make(
        &self,
        key: &[u8],
        usage: KeyUsage,
        origin: Origin,
        nonce: Option<[u8; 12]>,
    ) -> Result<KeyHandle> {
        Ok(KeyHandle {
            h: self.store.put_app(key, APP_KEYS_MAX)?,
            usage,
            scope: self.scope,
            origin,
            nonce,
        })
    }

    fn bytes(&self, h: &KeyHandle) -> Result<Zeroizing<[u8; 32]>> {
        h.h.with(key32)?
    }

    /// Non-key randomness (a salt, a nonce prefix, passphrase words): at most 4,096 bytes.
    pub fn random_bytes(&self, n: usize) -> Result<Vec<u8>> {
        if n > RANDOM_MAX {
            return Err(Error::Argument);
        }
        let mut out = vec![0u8; n];
        rng(&mut out)?;
        Ok(out)
    }

    /// A fresh random 32-byte key of `usage`.
    pub fn random_key(&self, usage: KeyUsage) -> Result<KeyHandle> {
        let mut k = Zeroizing::new([0u8; 32]);
        rng(&mut k[..])?;
        self.make(&k[..], usage, Origin::Drawn, None)
    }

    /// HKDF-SHA-256 over the `Derive` handles `keys` (concatenated) with `salt` and `info` (`label ‖ context`, exactly): a
    /// 32-byte key of `usage`, and with `nonce` the next 12 bytes of the output kept on the handle for [`Nonce::FromKey`].
    pub fn derive(
        &self,
        keys: &[&KeyHandle],
        salt: &[u8],
        info: &[u8],
        usage: KeyUsage,
        nonce: bool,
    ) -> Result<KeyHandle> {
        let mut ikm = Zeroizing::new(Vec::with_capacity(32 * keys.len()));
        for k in keys {
            self.check_usage(k, KeyUsage::Derive)?;
            ikm.extend_from_slice(&self.bytes(k)?[..]);
        }
        let okm = hkdf_sha256(&ikm, salt, info, if nonce { 44 } else { 32 })?;
        let n = match nonce {
            true => Some(
                okm.get(32..44)
                    .and_then(|n| n.try_into().ok())
                    .ok_or(Error::Argument)?,
            ),
            false => None,
        };
        self.make(
            okm.get(..32).ok_or(Error::Argument)?,
            usage,
            Origin::Derived,
            n,
        )
    }

    /// HMAC-SHA-256 of `data` (exactly) under the `Derive` handle `key`, into a 32-byte key of `usage`.
    pub fn mac_derive(&self, key: &KeyHandle, data: &[u8], usage: KeyUsage) -> Result<KeyHandle> {
        self.check_usage(key, KeyUsage::Derive)?;
        let out = Zeroizing::new(hmac_sha256(&self.bytes(key)?[..], data));
        self.make(&out[..], usage, Origin::Derived, None)
    }

    /// One public MAC output of 1 to 8 bytes under a `Derive` key this scope drew or unwrapped (never a derived one).
    pub fn mac_public(&self, key: &KeyHandle, data: &[u8], len: usize) -> Result<Vec<u8>> {
        self.check_usage(key, KeyUsage::Derive)?;
        if key.origin == Origin::Derived {
            return Err(Error::AppKeyUsage);
        }
        if !(1..=8).contains(&len) {
            return Err(Error::Argument);
        }
        let out = hmac_sha256(&self.bytes(key)?[..], data);
        Ok(out.get(..len).ok_or(Error::Argument)?.to_vec())
    }

    fn nonce_of(&self, key: &KeyHandle, n: &Nonce, input: &[u8]) -> Result<([u8; 12], usize)> {
        match n {
            Nonce::Random if input.is_empty() => {
                let mut r = [0u8; 12];
                rng(&mut r)?;
                Ok((r, 0))
            }
            Nonce::Random => Ok((
                input
                    .get(..12)
                    .and_then(|n| n.try_into().ok())
                    .ok_or(Error::Aead)?,
                12,
            )),
            Nonce::FromKey => Ok((key.nonce.ok_or(Error::Argument)?, 0)),
            Nonce::FromHandle(h) => {
                self.check_usage(h, KeyUsage::Derive)?;
                let m = hmac_sha256(&self.bytes(h)?[..], &[3]);
                Ok((
                    m.get(..12)
                        .and_then(|n| n.try_into().ok())
                        .ok_or(Error::Argument)?,
                    0,
                ))
            }
        }
    }

    /// AES-256-GCM-SIV of `pt` under the `Data` handle `key` with `aad` (never starting with [`KEYWRAP`]): `nonce ‖ ct` for
    /// [`Nonce::Random`], `ct` otherwise.
    pub fn seal(&self, key: &KeyHandle, nonce: Nonce, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        self.check_usage(key, KeyUsage::Data)?;
        refuse_keywrap(aad)?;
        let (n, _) = self.nonce_of(key, &nonce, &[])?;
        let ct = aead_seal(Alg::Aes256GcmSiv, &*self.bytes(key)?, &n, aad, pt)?;
        Ok(match nonce {
            Nonce::Random => [&n[..], &ct].concat(),
            _ => ct,
        })
    }

    /// The plaintext of a [`AppKeys::seal`] output: `Aead` when it does not open.
    pub fn open(
        &self,
        key: &KeyHandle,
        nonce: Nonce,
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.check_usage(key, KeyUsage::Data)?;
        refuse_keywrap(aad)?;
        let probe: &[u8] = if matches!(nonce, Nonce::Random) {
            ct
        } else {
            &[]
        };
        let (n, skip) = match (&nonce, probe.is_empty()) {
            (Nonce::Random, true) => return Err(Error::Aead),
            _ => self.nonce_of(key, &nonce, probe)?,
        };
        aead_open(
            Alg::Aes256GcmSiv,
            &*self.bytes(key)?,
            &n,
            aad,
            ct.get(skip..).ok_or(Error::Aead)?,
        )
    }

    /// `nonce ‖ AES-256-GCM-SIV(under, nonce, key, KEYWRAP ‖ u8(usage of key) ‖ aad)` (60 bytes), `under` a `KeyWrap` handle.
    pub fn seal_key(&self, under: &KeyHandle, key: &KeyHandle, aad: &[u8]) -> Result<Vec<u8>> {
        self.check_usage(under, KeyUsage::KeyWrap)?;
        self.check(key)?;
        let mut n = [0u8; 12];
        rng(&mut n)?;
        let ct = aead_seal(
            Alg::Aes256GcmSiv,
            &*self.bytes(under)?,
            &n,
            &keywrap_aad(key.usage, aad),
            &self.bytes(key)?[..],
        )?;
        Ok([&n[..], &ct].concat())
    }

    /// The key a [`AppKeys::seal_key`] output holds, as a handle of `usage` (the one it was sealed with, else `Aead`).
    pub fn open_key(
        &self,
        under: &KeyHandle,
        wire: &[u8],
        usage: KeyUsage,
        aad: &[u8],
    ) -> Result<KeyHandle> {
        self.check_usage(under, KeyUsage::KeyWrap)?;
        let (n, ct) = match wire.len() {
            60 => wire.split_at(12),
            _ => return Err(Error::Argument),
        };
        let n: [u8; 12] = n.try_into().map_err(|_| Error::Argument)?;
        let k = aead_open(
            Alg::Aes256GcmSiv,
            &*self.bytes(under)?,
            &n,
            &keywrap_aad(usage, aad),
            ct,
        )?;
        self.make(&k, usage, Origin::Derived, None)
    }

    /// Whether two handles of this scope hold the same key (constant time over the bytes).
    pub fn same_key(&self, a: &KeyHandle, b: &KeyHandle) -> Result<bool> {
        self.check(a)?;
        self.check(b)?;
        let (x, y) = (self.bytes(a)?, self.bytes(b)?);
        Ok(x.iter().zip(y.iter()).fold(0u8, |d, (p, q)| d | (p ^ q)) == 0)
    }

    /// Argon2id (RFC 9106, version 0x13; no secret, no associated data) of `password` with `salt`, into a `Derive` handle.
    pub fn argon2id(
        &self,
        password: &[u8],
        salt: &[u8],
        params: Argon2Params,
    ) -> Result<KeyHandle> {
        let p =
            Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| Error::Argument)?;
        let mut out = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
            .hash_password_into(password, salt, &mut out[..])
            .map_err(|_| Error::Argument)?;
        self.make(&out[..], KeyUsage::Derive, Origin::Derived, None)
    }

    fn wrap_with(
        &self,
        key: &KeyHandle,
        label: &[u8],
        aad: &[u8],
        kem_pk: &[u8],
        m: &[u8; 32],
        e: &[u8; 32],
    ) -> Result<KemWrap> {
        self.check(key)?;
        let (mlkem_ct, x25519_eph, ss) = super::kem::encaps(kem_pk, m, e)?;
        let kek = wrap_kek(&ss, label, aad, kem_pk)?;
        let sealed_key = aead_seal(Alg::Aes256Gcm, &kek, &[0; 12], aad, &self.bytes(key)?[..])?;
        Ok(KemWrap {
            mlkem_ct,
            x25519_eph,
            sealed_key,
        })
    }

    /// `key` wrapped to the KEM key `kem_pk` (a UA's at a version the caller read, or a fresh ephemeral one): the FIPS 203
    /// §7.2 checks on `kem_pk` (`KemCheck`), the KEK's info `label ‖ aad ‖ 0x01 ‖ keccak256(kem_pk)` built here.
    pub fn kem_wrap(
        &self,
        key: &KeyHandle,
        label: &[u8],
        aad: &[u8],
        kem_pk: &[u8],
    ) -> Result<KemWrap> {
        let (mut m, mut e) = (Zeroizing::new([0u8; 32]), Zeroizing::new([0u8; 32]));
        rng(&mut m[..])?;
        rng(&mut e[..])?;
        self.wrap_with(key, label, aad, kem_pk, &m, &e)
    }

    /// The key of `wrap` by the KEM key `kem` (the account's, at the wrap's key version), as a handle of `usage`: `Aead` when
    /// it does not open.
    pub fn kem_unwrap(
        &self,
        kem: &KemKeyPair,
        wrap: &KemWrap,
        label: &[u8],
        aad: &[u8],
        usage: KeyUsage,
    ) -> Result<KeyHandle> {
        let kem_pk = kem.kem_pk();
        let ss = kem.decaps(&wrap.mlkem_ct, &wrap.x25519_eph)?;
        let kek = wrap_kek(&ss, label, aad, &kem_pk)?;
        let k = aead_open(Alg::Aes256Gcm, &kek, &[0; 12], aad, &wrap.sealed_key)?;
        self.make(&k, usage, Origin::Unwrapped, None)
    }

    /// The app's per-account storage root: HKDF-SHA-256(ikm = the wallet's BIP-39 seed, salt empty, info = [`APP_ROOT`] ‖
    /// `app_id` ‖ `ua`, 32), a `Derive` handle (owner 2026-11-20, confirmed).
    pub fn app_root_key(&self, app_id: &[u8; 32], ua: &[u8; 32]) -> Result<KeyHandle> {
        let info = [APP_ROOT, app_id, ua].concat();
        let k = self
            .store
            .with_seed(|seed| hkdf_sha256(seed, &[], &info, 32))?;
        self.make(&k, KeyUsage::Derive, Origin::Derived, None)
    }

    /// Wipes the handle's key and frees its slot (`AppHandleForeign` for another scope's; that handle is dropped all the
    /// same, so wiped).
    pub fn destroy(&self, h: KeyHandle) -> Result<()> {
        self.check(&h)
    }
}

/// Test-only entry points (feature `vectors`, never in a release build).
#[cfg(feature = "vectors")]
impl AppKeys {
    /// A handle holding `key` (a vector's input).
    pub fn vectors_import(&self, key: &[u8; 32], usage: KeyUsage) -> Result<KeyHandle> {
        self.make(key, usage, Origin::Drawn, None)
    }

    /// The handle's key bytes (a vector's comparison).
    pub fn vectors_reveal(&self, h: &KeyHandle) -> Result<Vec<u8>> {
        self.check(h)?;
        Ok(self.bytes(h)?.to_vec())
    }

    /// The handle's derived nonce, if it has one.
    pub fn vectors_nonce(&self, h: &KeyHandle) -> Option<[u8; 12]> {
        h.nonce
    }

    /// [`AppKeys::kem_wrap`] with fixed `m` and X25519 ephemeral secret.
    pub fn vectors_kem_wrap(
        &self,
        key: &KeyHandle,
        label: &[u8],
        aad: &[u8],
        kem_pk: &[u8],
        m: &[u8; 32],
        e: &[u8; 32],
    ) -> Result<KemWrap> {
        self.wrap_with(key, label, aad, kem_pk, m, e)
    }

    /// [`AppKeys::seal`] with a fixed nonce, the nonce not in the output.
    pub fn vectors_seal(
        &self,
        key: &KeyHandle,
        nonce: &[u8; 12],
        aad: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>> {
        self.check_usage(key, KeyUsage::Data)?;
        refuse_keywrap(aad)?;
        aead_seal(Alg::Aes256GcmSiv, &*self.bytes(key)?, nonce, aad, pt)
    }

    /// [`AppKeys::seal_key`] with a fixed nonce.
    pub fn vectors_seal_key(
        &self,
        under: &KeyHandle,
        key: &KeyHandle,
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        self.check_usage(under, KeyUsage::KeyWrap)?;
        let ct = aead_seal(
            Alg::Aes256GcmSiv,
            &*self.bytes(under)?,
            nonce,
            &keywrap_aad(key.usage, aad),
            &self.bytes(key)?[..],
        )?;
        Ok([&nonce[..], &ct].concat())
    }
}
