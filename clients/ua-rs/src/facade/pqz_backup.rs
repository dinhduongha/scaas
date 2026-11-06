// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Feature `pqz` (ua-rs-sign T16a; owner 2026-11-06, option (A) of `pq-mpc-threshold.md` §6, spec 3g §7.2): the k-of-n backup
//! of an `msig` holder's PQZ key. For an `msig` the PQZ key is one view / prove key held by an operator (CTR-PQZ-12); if the
//! operator loses it or leaves, every debit is stuck. The operator deals Shamir shares of the PQZ **`seed32` only** (never its
//! wallet entropy) to the `msig`'s members; any k of them rebuild it and the one who rebuilds becomes the new operator.
//!
//! - **Shares.** Shamir over GF(2^8) (the AES field, `x^8 + x^4 + x^3 + x + 1`), byte by byte: a random polynomial of degree
//!   `k − 1` per byte with the byte as its constant term, coefficients from the OS RNG; share `index` (1..=n) is its value at
//!   `x = index`. Every product of secret bytes runs without a secret branch or table.
//! - **Containers.** Share `i` goes to member `i`'s own single-key UA KEM key (MD-11: an `msig` holds no KEM key) in a T8
//!   container of purpose [`PURPOSE_PQZ_SHARE`], signed by the operator's UA key; the plaintext is `{v: 1, msigUa, version,
//!   pqzKeyHash, k, n, index, share}` (`0x` hex), so the header `(msig ua, version, pqzKeyHash, k, n, index)` is under the
//!   sender's signature and the AEAD tag. A member hands its share on to the one who rebuilds by
//!   [`KemKeyPair::reseal_pqz_share`] (the share never leaves the library in the clear).
//! - **Rebuild.** [`crate::wallet::Wallet::reconstruct_pqz_seed`] opens k or more containers, refuses fewer than the header's k,
//!   mixed headers, a header other than the expected `(msig ua, version, pqzKeyHash)` and repeated indices, interpolates, and
//!   installs the result only if its key hashes to the registered `pqzKeyHash`. The key lives in the rebuilder's wallet
//!   store (lock revokes it) and is not in that wallet's own backup: the new operator deals new shares of it (or rotates).
//! - **Warning, never a refusal** (owner 2026-11-06): [`seed_backup_warning`] says when an `msig` PQZ holder's key has no
//!   backup that covers it; `register` / `setPqzKey` are built either way.
//!
//! The format is ua-rs's own (every binding reaches it through ua-rs; clientkeys has no PQZ facade), pinned by the field and
//! split known answers of `tests/pqz_backup.rs`. Old versions' backups are the caller's to keep: nothing here deletes one.
//! Residual: the JSON strings of an opened share are wiped after the read, `serde_json`'s own copies while parsing are not.
//! UNAUDITED.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::disallowed_methods)]

use super::pqz::PqzKey;
use crate::ua8::{Accepted, Members, MsigStructure};
use crate::wallet::{
    bounded, from_hex, seal_container, to_hex, ContainerExpect, ContainerSigner, Error, KemKeyPair, Recipient, RecipientId, Result,
    SealedContainer, SecretStore, UaKey,
};
use rand_core::{OsRng, RngCore};
use serde_json::Value;
use std::sync::Arc;
use zeroize::Zeroizing;

/// The purpose of a PQZ share container.
pub const PURPOSE_PQZ_SHARE: &str = "scaas/pqz-share/v1";
/// What [`seed_backup_warning`] says.
pub const SEED_BACKUP_MISSING: &str = "PqzSeedBackupMissing";
const MSIG: u16 = 0x0120;
/// An `msig` has at most 16 members (CTR-UA-09).
const N_MAX: usize = 16;
/// A share payload: eight short fields.
const SHARE_JSON: usize = 1024;
/// [`PqzSeedBackup::from_json`]: 16 containers of a few KiB.
const BACKUP_JSON: usize = 1 << 20;
const BACKUP_DEPTH: usize = 9;

// --- GF(2^8) -------------------------------------------------------------------------------------------------------------

/// `a · b` in GF(2^8) mod `x^8 + x^4 + x^3 + x + 1`: eight rounds, masks only (no branch or table on either input).
fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0u8;
    for _ in 0..8 {
        r ^= a & 0u8.wrapping_sub(b & 1);
        a = (a << 1) ^ (0x1b & 0u8.wrapping_sub(a >> 7));
        b >>= 1;
    }
    r
}

/// `a^254 = a^-1` (`a ≠ 0`); used on the public x-coordinates only.
fn inv(a: u8) -> u8 {
    let (mut r, mut x) = (1u8, a);
    for bit in 0..8 {
        if (254u8 >> bit) & 1 == 1 {
            r = mul(r, x);
        }
        x = mul(x, x);
    }
    r
}

/// Shares `1..=n` of `secret` from the polynomial with constant term `secret` and the `k − 1` higher coefficients `coeffs`.
fn split_with(secret: &[u8; 32], coeffs: &[[u8; 32]], n: u8) -> Vec<Zeroizing<[u8; 32]>> {
    (1..=n)
        .map(|x| {
            let mut y = Zeroizing::new([0u8; 32]);
            for (b, out) in y.iter_mut().enumerate() {
                // Horner from the highest coefficient down to the secret
                let at = |c: &[u8; 32]| c.get(b).copied().unwrap_or(0);
                *out = coeffs.iter().rev().fold(0u8, |acc, c| mul(acc, x) ^ at(c));
                *out = mul(*out, x) ^ secret.get(b).copied().unwrap_or(0);
            }
            y
        })
        .collect()
}

/// The constant term of the polynomial through `shares` (`(x, y)`, distinct non-zero `x`): Lagrange at 0.
fn combine(shares: &[(u8, &[u8; 32])]) -> Zeroizing<[u8; 32]> {
    let mut s = Zeroizing::new([0u8; 32]);
    for (i, (xi, yi)) in shares.iter().enumerate() {
        let l = shares.iter().enumerate().filter(|(j, _)| *j != i).fold(1u8, |l, (_, (xj, _))| mul(l, mul(*xj, inv(xj ^ xi))));
        s.iter_mut().zip(yi.iter()).for_each(|(o, y)| *o ^= mul(l, *y));
    }
    s
}

// --- the share payload -----------------------------------------------------------------------------------------------------

/// A share's header: what the operator's signature binds with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareHeader {
    pub msig_ua: [u8; 32],
    pub version: u64,
    pub pqz_key_hash: [u8; 32],
    pub k: u8,
    pub n: u8,
}

struct Share {
    h: ShareHeader,
    index: u8,
    y: Zeroizing<[u8; 32]>,
}

impl Share {
    fn to_json(&self) -> Zeroizing<String> {
        let h = &self.h;
        let mut s = Zeroizing::new(format!(
            "{{\"v\":1,\"msigUa\":\"{}\",\"version\":{},\"pqzKeyHash\":\"{}\",\"k\":{},\"n\":{},\"index\":{},\"share\":\"",
            to_hex(&h.msig_ua),
            h.version,
            to_hex(&h.pqz_key_hash),
            h.k,
            h.n,
            self.index
        ));
        s.push_str(&Zeroizing::new(to_hex(&*self.y)));
        s.push_str("\"}");
        s
    }

    /// Exactly the eight fields, `v` 1, `1 ≤ k ≤ n ≤ 16`, `1 ≤ index ≤ n`, 32-byte words; else `Argument`. Strings wiped.
    fn from_json(pt: &[u8]) -> Result<Share> {
        let mut v = bounded::json(pt, SHARE_JSON, 1)?;
        let s = Self::parse(&v);
        bounded::wipe(&mut v);
        s.ok_or(Error::Argument)
    }

    fn parse(v: &Value) -> Option<Share> {
        let o = v.as_object().filter(|o| o.len() == 8)?;
        let word = |k: &str| -> Option<[u8; 32]> { from_hex(o.get(k)?.as_str()?)?.try_into().ok() };
        let small = |k: &str| u8::try_from(o.get(k)?.as_u64()?).ok();
        let (k, n, index) = (small("k")?, small("n")?, small("index")?);
        if o.get("v")?.as_u64()? != 1 || k == 0 || k > n || usize::from(n) > N_MAX || index == 0 || index > n {
            return None;
        }
        let h = ShareHeader { msig_ua: word("msigUa")?, version: o.get("version")?.as_u64()?, pqz_key_hash: word("pqzKeyHash")?, k, n };
        Some(Share { h, index, y: Zeroizing::new(word("share")?) })
    }
}

/// The plaintext of a share container, accepted as `expect` says (purpose [`PURPOSE_PQZ_SHARE`], else `Argument`).
fn open_share(kk: &KemKeyPair, c: &SealedContainer, expect: &ContainerExpect, members: &Members, accepted: Option<&Accepted>) -> Result<Share> {
    if expect.purpose != PURPOSE_PQZ_SHARE {
        return Err(Error::Argument);
    }
    Share::from_json(&kk.open_container(c, expect, members, accepted)?)
}

// --- the backup ------------------------------------------------------------------------------------------------------------

/// The operator's record of one backup: the header and the `n` share containers in index order (public data only: each share
/// is sealed to its member). JSON `{v: 1, msigUa, version, pqzKeyHash, k, n, shares: [container JSON]}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqzSeedBackup {
    pub header: ShareHeader,
    pub shares: Vec<SealedContainer>,
}

impl PqzSeedBackup {
    /// Whether this backup is of key `pqz_key_hash` at `version` of the `msig` `msig_ua`, with all `n` shares.
    pub fn covers(&self, msig_ua: &[u8; 32], version: u64, pqz_key_hash: &[u8; 32]) -> bool {
        let h = &self.header;
        h.msig_ua == *msig_ua && h.version == version && h.pqz_key_hash == *pqz_key_hash && self.shares.len() == usize::from(h.n)
    }

    pub fn to_json(&self) -> String {
        let h = &self.header;
        format!(
            "{{\"v\":1,\"msigUa\":\"{}\",\"version\":{},\"pqzKeyHash\":\"{}\",\"k\":{},\"n\":{},\"shares\":[{}]}}",
            to_hex(&h.msig_ua),
            h.version,
            to_hex(&h.pqz_key_hash),
            h.k,
            h.n,
            self.shares.iter().map(SealedContainer::to_json).collect::<Vec<_>>().join(",")
        )
    }

    /// [`PqzSeedBackup::to_json`] back (at most 1 MiB, depth 9): `Argument` if malformed, `1 ≤ k ≤ n ≤ 16` and `n` shares, each
    /// of purpose [`PURPOSE_PQZ_SHARE`].
    pub fn from_json(json: &[u8]) -> Result<PqzSeedBackup> {
        let v = bounded::json(json, BACKUP_JSON, BACKUP_DEPTH)?;
        let o = v.as_object().filter(|o| o.len() == 7 && o.get("v").and_then(Value::as_u64) == Some(1)).ok_or(Error::Argument)?;
        let word = |k: &str| -> Result<[u8; 32]> {
            o.get(k).and_then(Value::as_str).and_then(from_hex).and_then(|b| b.try_into().ok()).ok_or(Error::Argument)
        };
        let small = |k: &str| o.get(k).and_then(Value::as_u64).and_then(|x| u8::try_from(x).ok()).ok_or(Error::Argument);
        let header = ShareHeader {
            msig_ua: word("msigUa")?,
            version: o.get("version").and_then(Value::as_u64).ok_or(Error::Argument)?,
            pqz_key_hash: word("pqzKeyHash")?,
            k: small("k")?,
            n: small("n")?,
        };
        let list = o.get("shares").and_then(Value::as_array).ok_or(Error::Argument)?;
        let shares = list.iter().map(|c| SealedContainer::from_json(c.to_string().as_bytes())).collect::<Result<Vec<_>>>()?;
        let ok = header.k >= 1 && header.k <= header.n && usize::from(header.n) <= N_MAX && shares.len() == usize::from(header.n);
        if !ok || shares.iter().any(|c| c.purpose != PURPOSE_PQZ_SHARE) {
            return Err(Error::Argument);
        }
        Ok(PqzSeedBackup { header, shares })
    }
}

/// [`SEED_BACKUP_MISSING`] when `kind` is an `msig` (`0x0120`) and no backup in `backups` covers its PQZ key `pqz_key` at
/// `version` ([`PqzSeedBackup::covers`]); `None` otherwise (a single-key holder needs none: its key is its own seed's). The
/// client shows it and still builds `register` / `setPqzKey` (owner 2026-11-06: a warning, never a refusal); an unhashable
/// key warns too.
pub fn seed_backup_warning(kind: u16, ua: &[u8; 32], version: u64, pqz_key: &[u8], backups: &[PqzSeedBackup]) -> Option<&'static str> {
    if kind != MSIG {
        return None;
    }
    let kh = crate::key_hash_of(crate::PQZ_SCHEME, pqz_key).ok().flatten()?;
    (!backups.iter().any(|b| b.covers(ua, version, &kh))).then_some(SEED_BACKUP_MISSING)
}

fn os_coeffs(k: u8) -> Result<Zeroizing<Vec<[u8; 32]>>> {
    let mut c = Zeroizing::new(vec![[0u8; 32]; usize::from(k).saturating_sub(1)]);
    for x in c.iter_mut() {
        OsRng.try_fill_bytes(x).map_err(|_| Error::Rng)?;
    }
    Ok(c)
}

impl PqzKey {
    /// The k-of-n backup of this key's `seed32` as the PQZ key of record `version` of the `msig` `msig_key_data` (CTR-UA-09
    /// key data): one share container per recipient, in order (share `i + 1` to `recipients[i]`), each to a direct member's
    /// own single-key UA KEM key ([`Recipient::ua`]; distinct members), signed by `sender` (a UA key of a kind that signs
    /// containers). `k` the `msig` threshold when `None`; `1 ≤ k ≤ n`. `Argument` otherwise (a recipient that is no member, an
    /// ephemeral one, a repeated member, `k` out of range); `KeyRevoked` once the key's wallet was locked.
    pub fn seal_seed_backup(
        &self, sender: &UaKey, msig_key_data: &[u8], version: u64, k: Option<u8>, recipients: &[Recipient],
    ) -> Result<PqzSeedBackup> {
        self.seal_seed_backup_with(sender, msig_key_data, version, k, recipients, os_coeffs)
    }

    fn seal_seed_backup_with(
        &self, sender: &UaKey, msig_key_data: &[u8], version: u64, k: Option<u8>, recipients: &[Recipient],
        coeffs: impl FnOnce(u8) -> Result<Zeroizing<Vec<[u8; 32]>>>,
    ) -> Result<PqzSeedBackup> {
        let st = MsigStructure::from_key_data(msig_key_data).map_err(|_| Error::Argument)?;
        let msig_ua = crate::derive_ua(MSIG, msig_key_data, false)?;
        let n = u8::try_from(recipients.len()).ok().filter(|n| (1..=N_MAX).contains(&usize::from(*n))).ok_or(Error::Argument)?;
        let k = match k {
            Some(k) => k,
            None => u8::try_from(st.threshold).map_err(|_| Error::Argument)?,
        };
        if k == 0 || k > n {
            return Err(Error::Argument);
        }
        let mut seen: Vec<[u8; 32]> = Vec::with_capacity(recipients.len());
        for r in recipients {
            let RecipientId::Ua { ua, .. } = r.id() else { return Err(Error::Argument) };
            if seen.contains(&ua) || !st.members.iter().any(|m| m.id == ua) {
                return Err(Error::Argument);
            }
            seen.push(ua);
        }
        let pqz_key_hash = crate::key_hash_of(crate::PQZ_SCHEME, &self.pk())?.ok_or(Error::Argument)?;
        let header = ShareHeader { msig_ua, version, pqz_key_hash, k, n };
        let ys = split_with(&*self.leaf()?, &coeffs(k)?, n);
        let created = crate::wallet::now()?;
        let signer = ContainerSigner::Key(sender);
        let shares = recipients
            .iter()
            .zip(ys)
            .zip(1u8..)
            .map(|((r, y), index)| {
                let pt = Share { h: header, index, y }.to_json();
                seal_container(r, PURPOSE_PQZ_SHARE, &signer, created, pt.as_bytes(), None)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(PqzSeedBackup { header, shares })
    }

    /// Test-only (feature `vectors`): [`PqzKey::seal_seed_backup`] with the given polynomial coefficients.
    #[cfg(feature = "vectors")]
    pub fn vectors_seal_seed_backup(
        &self, sender: &UaKey, msig_key_data: &[u8], version: u64, k: Option<u8>, recipients: &[Recipient], coeffs: &[[u8; 32]],
    ) -> Result<PqzSeedBackup> {
        self.seal_seed_backup_with(sender, msig_key_data, version, k, recipients, |_| Ok(Zeroizing::new(coeffs.to_vec())))
    }
}

impl KemKeyPair {
    /// A member's share container `c` (opened by this key as `expect` says; purpose [`PURPOSE_PQZ_SHARE`]) sealed again, the same
    /// payload, to `to` (the one who rebuilds the key) and signed by `sender`. The share stays inside the library. Errors as
    /// [`KemKeyPair::open_container`] and [`seal_container`]; `Argument` for another purpose or a malformed payload.
    pub fn reseal_pqz_share(
        &self, c: &SealedContainer, expect: &ContainerExpect, members: &Members, accepted: Option<&Accepted>, to: &Recipient,
        sender: &UaKey,
    ) -> Result<SealedContainer> {
        let s = open_share(self, c, expect, members, accepted)?;
        seal_container(to, PURPOSE_PQZ_SHARE, &ContainerSigner::Key(sender), crate::wallet::now()?, s.to_json().as_bytes(), None)
    }
}

/// [`crate::wallet::Wallet::reconstruct_pqz_seed`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn reconstruct(
    store: &Arc<SecretStore>, kk: &KemKeyPair, containers: &[SealedContainer], expect: &ContainerExpect, members: &Members,
    accepted: Option<&Accepted>, msig_ua: &[u8; 32], version: u64, pqz_key_hash: &[u8; 32],
) -> Result<PqzKey> {
    if containers.len() > N_MAX {
        return Err(Error::Argument);
    }
    let shares = containers.iter().map(|c| open_share(kk, c, expect, members, accepted)).collect::<Result<Vec<_>>>()?;
    let first = shares.first().ok_or(Error::Argument)?.h;
    let want = (first.msig_ua == *msig_ua) && first.version == version && first.pqz_key_hash == *pqz_key_hash;
    if !want || shares.iter().any(|s| s.h != first) || shares.len() < usize::from(first.k) {
        return Err(Error::Argument);
    }
    let points: Vec<(u8, &[u8; 32])> = shares.iter().map(|s| (s.index, &*s.y)).collect();
    if points.iter().enumerate().any(|(i, p)| points.iter().skip(i + 1).any(|q| q.0 == p.0)) {
        return Err(Error::Argument);
    }
    #[cfg(feature = "vectors")]
    COMBINED.with(|n| n.set(n.get() + 1));
    super::pqz::install(store, &combine(&points), pqz_key_hash)
}

#[cfg(feature = "vectors")]
thread_local! {
    static COMBINED: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// Test-only (feature `vectors`): how many rebuilds on this thread reached the combination. A refusal of the header, count or
/// index checks must come before it, which the key-hash check's own refusal of a wrong combination would hide.
#[cfg(feature = "vectors")]
pub fn vectors_combined() -> usize {
    COMBINED.with(|n| n.get())
}

/// Test-only (feature `vectors`): GF(2^8) `a · b`, and the shares of `secret` from given coefficients.
#[cfg(feature = "vectors")]
pub fn vectors_gf_mul(a: u8, b: u8) -> u8 {
    mul(a, b)
}
#[cfg(feature = "vectors")]
pub fn vectors_split(secret: &[u8; 32], coeffs: &[[u8; 32]], n: u8) -> Vec<[u8; 32]> {
    split_with(secret, coeffs, n).iter().map(|y| **y).collect()
}
