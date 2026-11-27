// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The clientkeys vault v2, byte-compatible (spec §8.1, CLI-SGN-02, CLI-SGN-21, C-10, C-12; clientkeys `vault.js`; T9; owner
//! 2026-11-19, scaas-sdk T13b ruling 3: the AAD binds the vault's id, a keystore seed's id):
//!
//! ```text
//! {v: 2, id, label, data: {iv, ct}, pin: {kdf: "scrypt", N, r, p, salt, iv, ct}, prf?: {credentialId, salt, iv, ct}}   base64url
//! id   = a lower-case UUID v4 (the wallet's: drawn at its first seal, read from its seed vault at open)
//! data = AES-256-GCM(DEK, iv, secret, aad = id|label|data)           DEK: 32 random bytes, one per vault
//! pin  = AES-256-GCM(scrypt(NFKC(passphrase), salt, N, r, p, 32), iv, DEK, aad = id|label|pin)
//! prf  = AES-256-GCM(HKDF-SHA256(prf output, salt = none, "scaas-clientkeys-vault-v1/prf", 32), iv, DEK, aad = id|label|prf)
//! ```
//!
//! A pin envelope outside `N ∈ {2^15, 2^16, 2^17}, r = 8, p = 1` is refused (`VaultParams`) before scrypt runs; new envelopes
//! use `N = 2^17`. Any `v` other than 2 (`v: 1`: no migration) and the tombstone `{v: 2, moved}` are `VaultVersion`, never a
//! wrong passphrase; an `id` not a lower-case UUID v4 is `Argument`. The seed vault
//! (label `seed`) holds the BIP-39 entropy at its own length (16, 20, 24, 28 or 32 bytes; any other payload `VaultOpen`); the
//! BIP-39 passphrase is never stored. [`Vault::rewrap_pin`] replaces the pin envelope over the same DEK: it rotates the
//! passphrase KEK, **not** the DEK, so it revokes nothing from someone who learnt the DEK; recovery from a DEK compromise is a
//! new vault ([`Wallet::seal_vault`]). The scrypt work buffer is not wiped (spec §8.2, residual). UNAUDITED.
use super::aead::{aead_open, aead_seal, hkdf_sha256, Alg};
use super::{bounded, Error, Result, Wallet};
use base64ct::{Base64UrlUnpadded, Encoding};
use rand_core::{OsRng, RngCore};
use serde_json::Value;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// A vault's data key.
pub(crate) type Dek = Zeroizing<[u8; 32]>;

/// The scrypt `N` an envelope may carry (CLI-SGN-21), as `log2 N`; new envelopes use the last.
const LOG_N: [u8; 3] = [15, 16, 17];
const LOG_N_NEW: u8 = 17;
const PRF_INFO: &[u8] = b"scaas-clientkeys-vault-v1/prf";
/// The BIP-39 entropy lengths of 12, 15, 18, 21, 24 words.
pub(crate) const SEED_LENGTHS: [usize; 5] = [16, 20, 24, 28, 32];
/// The label prefix of a key-locked import (user-profiles spec §7.4, CLI-UPR-24): a pin envelope only.
pub(crate) const KEY_LOCKED: &str = "native-import-locked:";
/// Whether `label` is a key-locked import's.
pub(crate) fn key_locked(label: &str) -> bool {
    label.starts_with(KEY_LOCKED)
}
/// A vault's JSON: a 1 MiB secret in base64url and its envelopes; `{pin: {…}}` is depth 2.
const VAULT_JSON: usize = 2 << 20;
const VAULT_DEPTH: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
struct GcmBox {
    iv: Vec<u8>,
    ct: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Pin {
    kdf: String,
    n: u64,
    r: u64,
    p: u64,
    salt: Vec<u8>,
    sealed: GcmBox,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Prf {
    credential_id: String,
    salt: Vec<u8>,
    sealed: GcmBox,
}

/// A vault v2: encrypted, named fields; [`Vault::to_json`] / [`Vault::from_json`] are the clientkeys JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vault {
    id: String,
    label: String,
    data: GcmBox,
    pin: Pin,
    prf: Option<Prf>,
}

/// How a vault opens: its passphrase (NFKC) or a 32-byte platform secret through the PRF envelope.
#[derive(Clone, Copy)]
pub enum Unlock<'a> {
    VaultPassphrase(&'a str),
    Prf(&'a [u8; 32]),
}

/// A PRF envelope's inputs: the 32-byte platform secret (a passkey's PRF output, or HMAC(key, salt) of an Android Keystore /
/// iOS Keychain key), the credential id or key alias, the salt the platform was asked with (spec §8.1).
pub struct PrfEnvelope<'a> {
    pub output: &'a [u8; 32],
    pub credential_id: &'a str,
    pub salt: &'a [u8],
}

/// The policy of a **new** passphrase (clientkeys `checkPassphrase`): after NFKC at least 8 characters, not only digits and
/// white space; else `Argument`. Opening never checks it.
pub fn check_passphrase(p: &str) -> Result<()> {
    let p = super::sized(|| p.nfkc());
    // JS `\d` is ASCII, `\s` Unicode white space and U+FEFF
    let other = p
        .chars()
        .any(|c| !(c.is_ascii_digit() || c.is_whitespace() || c == '\u{feff}'));
    if p.chars().count() < 8 || !other {
        return Err(Error::Argument);
    }
    Ok(())
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    OsRng.try_fill_bytes(&mut b).map_err(|_| Error::Rng)?;
    Ok(b)
}

fn aad(id: &str, label: &str, part: &str) -> Vec<u8> {
    format!("{id}|{label}|{part}").into_bytes()
}

/// A lower-case UUID v4: a vault id.
pub(crate) fn is_vault_id(s: &str) -> bool {
    let b = s.as_bytes();
    let hex = |r: std::ops::Range<usize>| {
        b.get(r)
            .is_some_and(|x| x.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')))
    };
    b.len() == 36
        && [8, 13, 18, 23].iter().all(|i| b.get(*i) == Some(&b'-'))
        && hex(0..8)
        && hex(9..13)
        && hex(14..18)
        && hex(19..23)
        && hex(24..36)
        && b.get(14) == Some(&b'4')
        && matches!(b.get(19), Some(b'8' | b'9' | b'a' | b'b'))
}

/// A fresh vault id (UUID v4) from the OS generator.
pub(crate) fn new_vault_id() -> Result<String> {
    let mut b = random::<16>()?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

fn gcm_seal(key: &[u8; 32], data: &[u8], aad: &[u8]) -> Result<GcmBox> {
    let iv = random::<12>()?;
    Ok(GcmBox {
        ct: aead_seal(Alg::Aes256Gcm, key, &iv, aad, data)?,
        iv: iv.to_vec(),
    })
}

/// `VaultOpen` for a bad tag or an IV of other than 12 bytes.
fn gcm_open(key: &[u8; 32], b: &GcmBox, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let iv: [u8; 12] = b.iv.as_slice().try_into().map_err(|_| Error::VaultOpen)?;
    aead_open(Alg::Aes256Gcm, key, &iv, aad, &b.ct).map_err(|_| Error::VaultOpen)
}

fn key32(v: Zeroizing<Vec<u8>>, e: Error) -> Result<Zeroizing<[u8; 32]>> {
    Ok(Zeroizing::new(v.as_slice().try_into().map_err(|_| e)?))
}

/// scrypt(NFKC(pin), salt, 2^log_n, 8, 1, 32).
fn pin_kek(pin: &str, salt: &[u8], log_n: u8) -> Result<Zeroizing<[u8; 32]>> {
    let pw = super::sized(|| pin.nfkc());
    let params = scrypt::Params::new(log_n, 8, 1).map_err(|_| Error::VaultParams)?;
    let mut kek = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(pw.as_bytes(), salt, &params, &mut *kek).map_err(|_| Error::VaultParams)?;
    Ok(kek)
}

/// The PRF envelope's key-encryption key of a PRF output or platform secret: one for every vault of a seed (scaas-sdk spec §6.10).
pub(crate) fn prf_key(output: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    prf_kek(output)
}

fn prf_kek(output: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    key32(hkdf_sha256(output, &[], PRF_INFO, 32)?, Error::Argument)
}

fn pin_envelope(id: &str, label: &str, dek: &[u8; 32], pin: &str) -> Result<Pin> {
    let salt = random::<16>()?;
    let kek = pin_kek(pin, &salt, LOG_N_NEW)?;
    let sealed = gcm_seal(&kek, dek, &aad(id, label, "pin"))?;
    Ok(Pin {
        kdf: "scrypt".into(),
        n: 1 << LOG_N_NEW,
        r: 8,
        p: 1,
        salt: salt.to_vec(),
        sealed,
    })
}

fn prf_envelope(id: &str, label: &str, dek: &[u8; 32], prf: &PrfEnvelope) -> Result<Prf> {
    let sealed = gcm_seal(&*prf_kek(prf.output)?, dek, &aad(id, label, "prf"))?;
    Ok(Prf {
        credential_id: prf.credential_id.to_owned(),
        salt: prf.salt.to_vec(),
        sealed,
    })
}

impl Vault {
    /// A new vault of `secret` under `id` and `label`: a fresh DEK, the pin envelope at `N = 2^17` (the passphrase policy
    /// first), and the PRF envelope if given.
    pub(crate) fn seal(
        id: &str,
        label: &str,
        secret: &[u8],
        pin: &str,
        prf: Option<&PrfEnvelope>,
    ) -> Result<Vault> {
        Ok(Vault::seal_dek(id, label, secret, pin, prf)?.0)
    }

    /// [`Vault::seal`] and the new DEK; `Argument` for an `id` not a lower-case UUID v4 or a PRF envelope on a key-locked label.
    pub(crate) fn seal_dek(
        id: &str,
        label: &str,
        secret: &[u8],
        pin: &str,
        prf: Option<&PrfEnvelope>,
    ) -> Result<(Vault, Dek)> {
        check_passphrase(pin)?;
        if !is_vault_id(id) || (prf.is_some() && key_locked(label)) {
            return Err(Error::Argument);
        }
        let dek = Zeroizing::new(random::<32>()?);
        let data = gcm_seal(&dek, secret, &aad(id, label, "data"))?;
        let pin = pin_envelope(id, label, &dek, pin)?;
        let prf = prf.map(|p| prf_envelope(id, label, &dek, p)).transpose()?;
        Ok((
            Vault {
                id: id.to_owned(),
                label: label.to_owned(),
                data,
                pin,
                prf,
            },
            dek,
        ))
    }

    /// This vault with `data` replaced by `secret` sealed under `dek` (its DEK) and a fresh IV, both envelopes kept.
    pub(crate) fn with_data(&self, dek: &[u8; 32], secret: &[u8]) -> Result<Vault> {
        Ok(Vault {
            data: gcm_seal(dek, secret, &aad(&self.id, &self.label, "data"))?,
            ..self.clone()
        })
    }

    /// The vault with `secret` in place of its payload, under its **same DEK** (opened by `unlock`) and a fresh IV: the pin and
    /// PRF envelopes are kept byte for byte, so a session opened by either can persist a change and both still open it
    /// (clientkeys `resealData`; scaas-sdk spec §6.10). Errors as [`Vault::open`].
    pub fn reseal_data(&self, unlock: Unlock, secret: &[u8]) -> Result<Vault> {
        self.with_data(&*self.dek(unlock)?, secret)
    }

    /// The DEK: the PRF envelope (`Argument` if the vault has none) or the pin envelope, its parameters checked before scrypt
    /// runs (`VaultParams`); `VaultOpen` for a wrong unlock or an altered envelope.
    fn dek(&self, unlock: Unlock) -> Result<Zeroizing<[u8; 32]>> {
        let (kek, sealed, part) = match unlock {
            Unlock::Prf(output) => {
                let p = self.prf.as_ref().ok_or(Error::Argument)?;
                (prf_kek(output)?, &p.sealed, "prf")
            }
            Unlock::VaultPassphrase(pin) => {
                let p = &self.pin;
                let log_n = LOG_N
                    .iter()
                    .find(|l| 1u64 << **l == p.n)
                    .filter(|_| p.kdf == "scrypt" && p.r == 8 && p.p == 1);
                (
                    pin_kek(pin, &p.salt, *log_n.ok_or(Error::VaultParams)?)?,
                    &p.sealed,
                    "pin",
                )
            }
        };
        key32(
            gcm_open(&kek, sealed, &aad(&self.id, &self.label, part))?,
            Error::VaultOpen,
        )
    }

    /// The secret (errors as `dek`).
    pub(crate) fn open(&self, unlock: Unlock) -> Result<Zeroizing<Vec<u8>>> {
        Ok(self.open_dek(unlock)?.0)
    }

    /// [`Vault::open`] and the DEK.
    pub(crate) fn open_dek(&self, unlock: Unlock) -> Result<(Zeroizing<Vec<u8>>, Dek)> {
        let dek = self.dek(unlock)?;
        Ok((
            gcm_open(&dek, &self.data, &aad(&self.id, &self.label, "data"))?,
            dek,
        ))
    }

    /// [`Vault::open_dek`] through the PRF envelope with its key-encryption key `kek` already derived ([`prf_key`]): `Argument`
    /// for a vault without a PRF envelope, `VaultOpen` for another key or an altered envelope.
    pub(crate) fn open_dek_prf_kek(&self, kek: &[u8; 32]) -> Result<(Zeroizing<Vec<u8>>, Dek)> {
        let p = self.prf.as_ref().ok_or(Error::Argument)?;
        let dek = key32(
            gcm_open(kek, &p.sealed, &aad(&self.id, &self.label, "prf"))?,
            Error::VaultOpen,
        )?;
        Ok((
            gcm_open(&dek, &self.data, &aad(&self.id, &self.label, "data"))?,
            dek,
        ))
    }

    /// What the vault holds: `seed`, `manifest`, `native-import:<network>:<n>`, …
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The vault's id (a lower-case UUID v4): its seed's, bound into every AAD.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Whether the pin envelope is weaker than today's parameters (`N = 2^17, r = 8, p = 1`): rewrap it on unlock.
    pub fn needs_rewrap(&self) -> bool {
        !(self.pin.n >= 1 << LOG_N_NEW && self.pin.r >= 8 && self.pin.p >= 1)
    }

    /// A new pin envelope (fresh salt, today's parameters, `new` under the policy) over the same DEK; the data and PRF
    /// envelopes are untouched. It rotates the passphrase KEK, **not** the DEK: it revokes nothing from someone who learnt the
    /// DEK (C-12); a DEK compromise needs a new vault.
    pub fn rewrap_pin(&self, old: &str, new: &str) -> Result<Vault> {
        check_passphrase(new)?;
        let dek = self.dek(Unlock::VaultPassphrase(old))?;
        Ok(Vault {
            pin: pin_envelope(&self.id, &self.label, &dek, new)?,
            ..self.clone()
        })
    }

    /// The vault with a PRF envelope (replacing one it had), opened by the passphrase once; `Argument` for a key-locked label.
    pub fn enable_prf(&self, pin: &str, prf: &PrfEnvelope) -> Result<Vault> {
        if key_locked(&self.label) {
            return Err(Error::Argument);
        }
        let dek = self.dek(Unlock::VaultPassphrase(pin))?;
        Ok(Vault {
            prf: Some(prf_envelope(&self.id, &self.label, &dek, prf)?),
            ..self.clone()
        })
    }

    /// The vault without its PRF envelope (scaas-sdk spec §6.10 `disable_prf_unlock`): the data and pin envelopes unchanged. It
    /// revokes nothing from an earlier copy of the vault that still has the envelope.
    pub fn without_prf(&self) -> Vault {
        Vault {
            prf: None,
            ..self.clone()
        }
    }

    /// Whether the vault carries a PRF envelope, and its credential id and salt (public: what the authenticator is asked with).
    pub fn prf_params(&self) -> Option<(String, Vec<u8>)> {
        self.prf
            .as_ref()
            .map(|p| (p.credential_id.clone(), p.salt.clone()))
    }

    /// The clientkeys JSON (its field order).
    pub fn to_json(&self) -> String {
        let s = |x: &str| Value::from(x).to_string();
        let b = |x: &[u8]| Base64UrlUnpadded::encode_string(x);
        let gcm = |g: &GcmBox| format!("\"iv\":\"{}\",\"ct\":\"{}\"", b(&g.iv), b(&g.ct));
        let p = &self.pin;
        let prf = self.prf.as_ref().map_or(String::new(), |f| {
            format!(
                ",\"prf\":{{\"credentialId\":{},\"salt\":\"{}\",{}}}",
                s(&f.credential_id),
                b(&f.salt),
                gcm(&f.sealed)
            )
        });
        format!(
            "{{\"v\":2,\"id\":{},\"label\":{},\"data\":{{{}}},\"pin\":{{\"kdf\":{},\"N\":{},\"r\":{},\"p\":{},\"salt\":\"{}\",{}}}{prf}}}",
            s(&self.id),
            s(&self.label),
            gcm(&self.data),
            s(&p.kdf),
            p.n,
            p.r,
            p.p,
            b(&p.salt),
            gcm(&p.sealed),
        )
    }

    /// The named fields of a vault JSON: `Argument` past 2 MiB or depth 2, for a malformed field or an `id` not a lower-case UUID
    /// v4, or a key-locked label (`native-import-locked:`) with a `prf` envelope (user-profiles spec §7.4: the SDK reports it
    /// `VaultFormat`); `VaultVersion` for any `v` other than 2 and for the tombstone `{v: 2, moved}` (before any other field
    /// is read). A non-integer `N`, `r` or `p` is kept as 0 (refused on open).
    pub fn from_json(json: &[u8]) -> Result<Vault> {
        let v = bounded::json(json, VAULT_JSON, VAULT_DEPTH)?;
        if v.get("v").and_then(Value::as_u64) != Some(2) || v.get("moved").is_some() {
            return Err(Error::VaultVersion);
        }
        parse(&v)
            .filter(|x| is_vault_id(&x.id) && !(x.prf.is_some() && key_locked(&x.label)))
            .ok_or(Error::Argument)
    }
}

/// Test-only (feature `vectors`): a vault of any label and payload (a forged `pqz-held:` vault, T16b).
#[cfg(feature = "vectors")]
impl Vault {
    /// `id`: the vault id (a wallet's [`Wallet::vault_id`], so its label vaults open in it).
    pub fn vectors_seal(id: &str, label: &str, secret: &[u8], pin: &str) -> Result<Vault> {
        Vault::seal(id, label, secret, pin, None)
    }
}

fn parse(v: &Value) -> Option<Vault> {
    let bytes = |x: &Value, k: &str| Base64UrlUnpadded::decode_vec(x.get(k)?.as_str()?).ok();
    let gcm = |x: &Value| {
        Some(GcmBox {
            iv: bytes(x, "iv")?,
            ct: bytes(x, "ct")?,
        })
    };
    let int = |x: &Value, k: &str| x.get(k).and_then(Value::as_u64).unwrap_or(0);
    let p = v.get("pin")?;
    let pin = Pin {
        kdf: p.get("kdf")?.as_str()?.to_owned(),
        n: int(p, "N"),
        r: int(p, "r"),
        p: int(p, "p"),
        salt: bytes(p, "salt")?,
        sealed: gcm(p)?,
    };
    let prf = match v.get("prf") {
        None | Some(Value::Null) => None,
        Some(f) => Some(Prf {
            credential_id: f.get("credentialId")?.as_str()?.to_owned(),
            salt: bytes(f, "salt")?,
            sealed: gcm(f)?,
        }),
    };
    Some(Vault {
        id: v.get("id")?.as_str()?.to_owned(),
        label: v.get("label")?.as_str()?.to_owned(),
        data: gcm(v.get("data")?)?,
        pin,
        prf,
    })
}

impl Wallet {
    /// The seed vault (label `seed`) of this wallet's entropy at its own length, a new DEK, the pin envelope under
    /// `vault_passphrase` (the new-passphrase policy, `Argument`) and the PRF envelope if given; `WalletLocked` while locked.
    /// The BIP-39 passphrase is not in it. The entropy's copy is used under a read lease, so `lock()` waits for the seal
    /// (T21 L82).
    pub fn seal_vault(&self, vault_passphrase: &str, prf: Option<&PrfEnvelope>) -> Result<Vault> {
        let _lease = self.store.lease();
        let entropy = self
            .store
            .with_arena(|a| Ok(Zeroizing::new(a.entropy()?.to_vec())))?;
        super::store::copied();
        Vault::seal(&self.vault_id()?, "seed", &entropy, vault_passphrase, prf)
    }

    /// This wallet's vault id: its seed vault's (read at [`Wallet::open_vault`]), else drawn once at its first seal; every
    /// vault it seals carries it (the AAD binds it; scaas-sdk T13b ruling 3).
    pub fn vault_id(&self) -> Result<String> {
        if let Some(id) = self.vault_id.get() {
            return Ok(id.clone());
        }
        let id = new_vault_id()?;
        Ok(self.vault_id.get_or_init(|| id).clone())
    }

    /// The wallet of a seed vault and the BIP-39 passphrase (asked at every unlock, never stored): `Argument` for a label other
    /// than `seed`, `VaultParams` / `VaultOpen` as the envelope, `VaultOpen` for a payload of other than 16, 20, 24, 28 or 32
    /// bytes (never padded or cut).
    pub fn open_vault(vault: &Vault, unlock: Unlock, bip39_passphrase: &str) -> Result<Wallet> {
        let w = Wallet::from_entropy(&seed_entropy(vault, unlock)?, bip39_passphrase)?;
        let _ = w.vault_id.set(vault.id.clone());
        Ok(w)
    }

    /// Reopens this locked wallet from its seed vault (spec §8.2, §9.1): the checks of [`Wallet::open_vault`], then a new
    /// arena at the generation `lock()` raised. Earlier handles stay `KeyRevoked`; derive new ones. `Argument` while unlocked.
    /// The manifest is the one `lock()` kept; an imported key it lists is held again only once its `native-import:` vault is
    /// reopened with [`Wallet::open_label_vault`] ([`Wallet::imported_key`] is `Argument` until then): this call takes the seed
    /// vault alone, and each label vault has its own DEK and unlock. The vault must be this wallet's: the seed it holds, with
    /// `bip39_passphrase`, must derive the UA of the manifest's first entry (its `kind` / `account` / `index`), else
    /// `WalletMismatch` (another wallet's seed vault, or another BIP-39 passphrase) and the wallet stays locked; an error of
    /// that derivation (`KindUnavailable` for a Falcon entry on a build without Falcon) is returned as it is. A wallet locked
    /// before any UA key was derived has an empty manifest and nothing to compare: any seed vault reopens it.
    pub fn unlock(&self, vault: &Vault, unlock: Unlock, bip39_passphrase: &str) -> Result<()> {
        self.unlock_entropy(&seed_entropy(vault, unlock)?, bip39_passphrase)
    }
}

/// The entropy of a seed vault: `Argument` for a label other than `seed`, the envelope's errors, `VaultOpen` for a payload of
/// other than 16, 20, 24, 28 or 32 bytes (never padded or cut).
fn seed_entropy(vault: &Vault, unlock: Unlock) -> Result<Zeroizing<Vec<u8>>> {
    if vault.label != "seed" {
        return Err(Error::Argument);
    }
    let entropy = vault.open(unlock)?;
    if !SEED_LENGTHS.contains(&entropy.len()) {
        return Err(Error::VaultOpen);
    }
    Ok(entropy)
}
