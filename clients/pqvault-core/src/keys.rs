// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! PqVault's key schedule (spec §6.2–§6.4, §6.8, §6.10; CLI-PQV-09) on the SDK's key handles: every KEM, HKDF, Argon2id and
//! AEAD step is one call of `scaas_sdk::app_core::AppCore`, run by `scaas-ua` in its key memory (C1). Nothing here holds a key
//! byte: `K_e`, `P_k`, `K_v`, `kInfo`, `kPrev`, `bk` and `kFile` are `AppKey` handles of one usage each. The bytes that come
//! out are ciphertexts, the 60-B key wraps, and the plaintexts the caller asked to open. UNAUDITED.
use crate::content::{self, Bad};
use crate::item::Item;
use crate::records::{item_aad, Addr, Wrap, B32};
use crate::Error;
use scaas_sdk::app_core::{AppCore, AppKey, AppKeyUsage as U, AppNonce, AppWrap, SecretBytes};
use scaas_sdk::op::KeyRef;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Every label of PqVault starts with it; the scope declares it (nothing below the SDK knows it).
pub const PREFIX: &str = "scaas/pqvault/v1/";
/// `passKdf = 1` (owner 2026-11-21, O8): Argon2id v0x13, 65,536 KiB, 3 passes, parallelism 4, 32 B, no associated data.
pub const PASS_KDF_1: (u32, u32, u32) = (65_536, 3, 4);
/// A ciphertext's bounds (VC9): `r` (16) ‖ AES-256-GCM-SIV of 256..16,384 B ‖ tag (16); the contract takes 32..16,416 B.
pub const CT_MIN: usize = 32;
pub const CT_MAX: usize = 16_416;

fn lbl(s: &str) -> Vec<u8> {
    format!("{PREFIX}{s}").into_bytes()
}

/// The wrap's AAD (spec §6.2): `vaultId ‖ epochId ‖ member ‖ be64(keyId)`; the SDK adds the scheme byte and `keccak256(kemPk)`
/// to the KDF info from the key it reads or holds.
pub fn wrap_aad(vault: B32, epoch: B32, member: B32, key_id: u64) -> Vec<u8> {
    [&vault.0[..], &epoch.0, &member.0, &key_id.to_be_bytes()].concat()
}

/// `K_e` wrapped to `member`'s KEM key at `key_id`, read by the SDK from the registry of `chain` (a read that feeds a
/// decryption, ARCH-POS-15).
pub async fn wrap_to(
    net: &dyn crate::Net,
    chain: &str,
    ke: Arc<AppKey>,
    vault: B32,
    epoch: B32,
    member: B32,
    key_id: u64,
) -> Result<Wrap, Error> {
    let w = net
        .kem_wrap(
            chain,
            member,
            key_id,
            ke,
            lbl("wrap"),
            wrap_aad(vault, epoch, member, key_id),
        )
        .await?;
    Ok(Wrap {
        member,
        key_id: crate::records::Num(key_id),
        mlkem_ct: crate::records::Bytes(w.mlkem_ct),
        x25519_eph: B32(w.x25519_eph.try_into().map_err(|_| Error::Unreadable)?),
        sealed_key: crate::records::Bytes(w.sealed_key),
    })
}

/// `K_e` (a `Derive` handle) of `account`'s own wrap, by its KEM key at the wrap's `keyId`. Any failure is `Unreadable` (one
/// class: whether the KEM, the AEAD or the key version failed is not told apart).
pub fn unwrap(
    core: &AppCore,
    account: &KeyRef,
    w: &Wrap,
    vault: B32,
    epoch: B32,
) -> Result<Arc<AppKey>, Error> {
    let aw = AppWrap {
        mlkem_ct: w.mlkem_ct.0.clone(),
        x25519_eph: w.x25519_eph.0.to_vec(),
        sealed_key: w.sealed_key.0.clone(),
    };
    core.kem_unwrap(
        account.clone(),
        w.key_id.0,
        aw,
        lbl("wrap"),
        wrap_aad(vault, epoch, w.member, w.key_id.0),
        U::Derive,
    )
    .map_err(|_| Error::Unreadable)
}

/// `P_k` (spec §6.3): Argon2id of the passphrase after RFC 8265's OpaqueString (the SDK's), under `salt`, at `passKdf`; `None`
/// for `passKdf` 0. An unknown set: `PassKdfUnknown`; a passphrase the profile refuses (empty, a control character):
/// `PassphraseInvalid`.
pub async fn pass_key(
    core: &Arc<AppCore>,
    seed: &str,
    pass_kdf: u16,
    pass: Option<&Arc<SecretBytes>>,
    salt: B32,
) -> Result<Option<Arc<AppKey>>, Error> {
    if pass_kdf == 0 {
        return Ok(None);
    }
    if pass_kdf != 1 {
        return Err(Error::PassKdfUnknown);
    }
    let pass = pass.ok_or(Error::PassphraseRequired)?;
    let (m, t, p) = PASS_KDF_1;
    core.argon2id_passphrase(seed.to_string(), pass.clone(), salt.0.to_vec(), m, t, p)
        .await
        .map(Some)
        .map_err(|_| Error::PassphraseInvalid)
}

/// `K_v = HKDF(K_e ‖ P_k, "scaas/pqvault/v1/vkey" ‖ vaultId ‖ epochId ‖ be16(passKdf))`, a `Derive` handle.
pub fn vault_key(
    core: &AppCore,
    ke: Arc<AppKey>,
    pk: Option<Arc<AppKey>>,
    vault: B32,
    epoch: B32,
    pass_kdf: u16,
) -> Result<Arc<AppKey>, Error> {
    let keys = std::iter::once(ke).chain(pk).collect();
    let ctx = [&vault.0[..], &epoch.0, &pass_kdf.to_be_bytes()].concat();
    Ok(core.derive(keys, vec![], lbl("vkey"), ctx, U::Derive, false)?)
}

fn info_key(
    core: &AppCore,
    kv: &Arc<AppKey>,
    vault: B32,
    epoch: B32,
) -> Result<Arc<AppKey>, Error> {
    let ctx = [vault.0, epoch.0].concat();
    Ok(core.derive(vec![kv.clone()], vec![], lbl("info"), ctx, U::Data, false)?)
}

/// `sealedInfo = n_i ‖ AES-256-GCM-SIV(kInfo, n_i, padInfo(canonical JSON))` (a fresh nonce from the OS RNG in `scaas-ua`).
pub fn seal_info(
    core: &AppCore,
    kv: &Arc<AppKey>,
    vault: B32,
    epoch: B32,
    info: &serde_json::Value,
) -> Result<Vec<u8>, Error> {
    let mut pt = content::pad_info(content::canonical(info)?.as_bytes())?;
    let k = info_key(core, kv, vault, epoch)?;
    Ok(core.seal(k, AppNonce::Random, vec![], std::mem::take(&mut *pt))?)
}

/// The JSON of `sealedInfo` under `kv`; `None` when its tag, padding or JSON fails (the caller names it: a wrong passphrase,
/// an unopenable epoch, a wrong history key).
pub fn open_info(
    core: &AppCore,
    kv: &Arc<AppKey>,
    vault: B32,
    epoch: B32,
    sealed: &[u8],
) -> Option<serde_json::Value> {
    let k = info_key(core, kv, vault, epoch).ok()?;
    let pt = core
        .open(k, AppNonce::Random, vec![], sealed.to_vec())
        .ok()?;
    pt.with(|b| content::unpad(b, true).and_then(content::parse_canonical))
        .ok()
        .filter(serde_json::Value::is_object)
}

fn prev_ctx(vault: B32, epoch: B32, prev: B32) -> Vec<u8> {
    [vault.0, epoch.0, prev.0].concat()
}

/// `prev.keyWrap` (spec §6.4, VC24): the earlier `K_v` sealed under `kPrev = HKDF(K_v, "…/prev" ‖ vaultId ‖ epochId ‖
/// prevEpochId)` (a `KeyWrap` handle), 60 B; the key bytes never leave `scaas-ua`.
pub fn seal_prev(
    core: &AppCore,
    kv: &Arc<AppKey>,
    vault: B32,
    epoch: B32,
    prev: B32,
    kv_prev: Arc<AppKey>,
) -> Result<Vec<u8>, Error> {
    let ctx = prev_ctx(vault, epoch, prev);
    let kp = core.derive(
        vec![kv.clone()],
        vec![],
        lbl("prev"),
        ctx.clone(),
        U::KeyWrap,
        false,
    )?;
    Ok(core.seal_key(kp, kv_prev, ctx)?)
}

/// The earlier `K_v` of `prev.keyWrap`, a `Derive` handle; `None` when it does not open.
pub fn open_prev(
    core: &AppCore,
    kv: &Arc<AppKey>,
    vault: B32,
    epoch: B32,
    prev: B32,
    wire: &[u8],
) -> Option<Arc<AppKey>> {
    let ctx = prev_ctx(vault, epoch, prev);
    let kp = core
        .derive(
            vec![kv.clone()],
            vec![],
            lbl("prev"),
            ctx.clone(),
            U::KeyWrap,
            false,
        )
        .ok()?;
    core.open_key(kp, wire.to_vec(), U::Derive, ctx).ok()
}

/// What an item version is bound to (spec §6.4).
#[derive(Debug, Clone, Copy)]
pub struct ItemAt {
    pub vault: B32,
    pub epoch: B32,
    pub item: B32,
    pub version: u32,
    pub author: B32,
    pub home_chain: B32,
    pub home: Addr,
}

impl ItemAt {
    fn ctx(&self) -> Vec<u8> {
        [
            &self.vault.0[..],
            &self.epoch.0,
            &self.item.0,
            &self.version.to_be_bytes(),
        ]
        .concat()
    }
    fn aad(&self) -> Vec<u8> {
        item_aad(
            self.vault,
            self.epoch,
            self.item,
            self.version,
            self.author,
            self.home_chain,
            self.home,
        )
    }
}

fn item_key(core: &AppCore, kv: &Arc<AppKey>, r: &[u8], x: &ItemAt) -> Result<Arc<AppKey>, Error> {
    let ctx = [x.ctx(), x.author.0.to_vec()].concat();
    Ok(core.derive(
        vec![kv.clone()],
        r.to_vec(),
        lbl("item"),
        ctx,
        U::Data,
        true,
    )?)
}

/// `ciphertext = r ‖ AES-256-GCM-SIV(bk, n, pt, aad)`, `r` 16 fresh random bytes, `(bk, n)` one HKDF output under `K_v`; the
/// plaintext's buffer handed to the SDK, which wipes it.
pub fn encrypt_item(
    core: &AppCore,
    seed: &str,
    kv: &Arc<AppKey>,
    x: &ItemAt,
    mut pt: Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    let r = core.random_bytes(seed, 16)?;
    let bk = item_key(core, kv, &r, x)?;
    let ct = core.seal(bk, AppNonce::FromKey, x.aad(), std::mem::take(&mut *pt))?;
    Ok([r, ct].concat())
}

/// The item a ciphertext holds under `kv` at `x`: its length, the tag, the padding, canonical JSON, each field typed by the
/// table and parsed inside the plaintext's secret buffer (CLI-PQV-16 H1). Every failure is the one local `Unreadable`
/// (ARCH-POS-13: nothing says which check failed, and nothing is sent).
pub fn decrypt_item(
    core: &AppCore,
    kv: &Arc<AppKey>,
    x: &ItemAt,
    ct: &[u8],
) -> Result<Item, Error> {
    if !(CT_MIN..=CT_MAX).contains(&ct.len()) {
        return Err(Error::Unreadable);
    }
    let (r, body) = ct.split_at(16);
    let bk = item_key(core, kv, r, x).map_err(|_| Error::Unreadable)?;
    let pt = core
        .open(bk, AppNonce::FromKey, x.aad(), body.to_vec())
        .map_err(|_| Error::Unreadable)?;
    pt.with(Item::from_plaintext).map_err(|_| Error::Unreadable)
}

/// A `file` item's key (spec §6.8): `seal_key` of the file key (a `Data` handle) under `kFile = HKDF(K_v, "…/file" ‖ vaultId ‖
/// epochId ‖ itemId ‖ be32(version))`, usage `KeyWrap`, never under `K_v` itself.
pub fn seal_file_key(
    core: &AppCore,
    kv: &Arc<AppKey>,
    x: &ItemAt,
    file_key: Arc<AppKey>,
) -> Result<Vec<u8>, Error> {
    let kf = core.derive(
        vec![kv.clone()],
        vec![],
        lbl("file"),
        x.ctx(),
        U::KeyWrap,
        false,
    )?;
    Ok(core.seal_key(kf, file_key, x.ctx())?)
}

/// The file key of a `file` item's `keyWrap`, a `Data` handle.
pub fn open_file_key(
    core: &AppCore,
    kv: &Arc<AppKey>,
    x: &ItemAt,
    wire: &[u8],
) -> Result<Arc<AppKey>, Error> {
    let kf = core.derive(
        vec![kv.clone()],
        vec![],
        lbl("file"),
        x.ctx(),
        U::KeyWrap,
        false,
    )?;
    core.open_key(kf, wire.to_vec(), U::Data, x.ctx())
        .map_err(|_| Error::Unreadable)
}

impl From<Bad> for Error {
    fn from(b: Bad) -> Error {
        match b {
            Bad::Shape => Error::Shape,
            Bad::Unreadable => Error::Unreadable,
        }
    }
}
