// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The clientkeys vault v1, byte-compatible (spec §8.1, CLI-SGN-02, CLI-SGN-21, C-10, C-12; clientkeys `vault.js`; T9):
//!
//! ```text
//! {v: 1, label, data: {iv, ct}, pin: {kdf: "scrypt", N, r, p, salt, iv, ct}, prf?: {credentialId, salt, iv, ct}}   base64url
//! data = AES-256-GCM(DEK, iv, secret, aad = label|data)              DEK: 32 random bytes, one per vault
//! pin  = AES-256-GCM(scrypt(NFKC(passphrase), salt, N, r, p, 32), iv, DEK, aad = label|pin)
//! prf  = AES-256-GCM(HKDF-SHA256(prf output, salt = none, "scaas-clientkeys-vault-v1/prf", 32), iv, DEK, aad = label|prf)
//! ```
//!
//! A pin envelope outside `N ∈ {2^15, 2^16, 2^17}, r = 8, p = 1` is refused (`VaultParams`) before scrypt runs; new envelopes
//! use `N = 2^17`. Any `v` other than 1 (`v: 2` and its tombstone) is `VaultVersion`, never a wrong passphrase. The seed vault
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

/// The scrypt `N` an envelope may carry (CLI-SGN-21), as `log2 N`; new envelopes use the last.
const LOG_N: [u8; 3] = [15, 16, 17];
const LOG_N_NEW: u8 = 17;
const PRF_INFO: &[u8] = b"scaas-clientkeys-vault-v1/prf";
/// The BIP-39 entropy lengths of 12, 15, 18, 21, 24 words.
pub(crate) const SEED_LENGTHS: [usize; 5] = [16, 20, 24, 28, 32];
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

/// A vault v1: encrypted, named fields; [`Vault::to_json`] / [`Vault::from_json`] are the clientkeys JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vault {
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
    let p = Zeroizing::new(p.nfkc().collect::<String>());
    // JS `\d` is ASCII, `\s` Unicode white space and U+FEFF
    let other = p.chars().any(|c| !(c.is_ascii_digit() || c.is_whitespace() || c == '\u{feff}'));
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

fn aad(label: &str, part: &str) -> Vec<u8> {
    format!("{label}|{part}").into_bytes()
}

fn gcm_seal(key: &[u8; 32], data: &[u8], aad: &[u8]) -> Result<GcmBox> {
    let iv = random::<12>()?;
    Ok(GcmBox { ct: aead_seal(Alg::Aes256Gcm, key, &iv, aad, data)?, iv: iv.to_vec() })
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
    let pw = Zeroizing::new(pin.nfkc().collect::<String>());
    let params = scrypt::Params::new(log_n, 8, 1, 32).map_err(|_| Error::VaultParams)?;
    let mut kek = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(pw.as_bytes(), salt, &params, &mut *kek).map_err(|_| Error::VaultParams)?;
    Ok(kek)
}

fn prf_kek(output: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    key32(hkdf_sha256(output, &[], PRF_INFO, 32)?, Error::Argument)
}

fn pin_envelope(label: &str, dek: &[u8; 32], pin: &str) -> Result<Pin> {
    let salt = random::<16>()?;
    let kek = pin_kek(pin, &salt, LOG_N_NEW)?;
    let sealed = gcm_seal(&kek, dek, &aad(label, "pin"))?;
    Ok(Pin { kdf: "scrypt".into(), n: 1 << LOG_N_NEW, r: 8, p: 1, salt: salt.to_vec(), sealed })
}

fn prf_envelope(label: &str, dek: &[u8; 32], prf: &PrfEnvelope) -> Result<Prf> {
    let sealed = gcm_seal(&*prf_kek(prf.output)?, dek, &aad(label, "prf"))?;
    Ok(Prf { credential_id: prf.credential_id.to_owned(), salt: prf.salt.to_vec(), sealed })
}

impl Vault {
    /// A new vault of `secret` under `label`: a fresh DEK, the pin envelope at `N = 2^17` (the passphrase policy first), and
    /// the PRF envelope if given.
    pub(crate) fn seal(label: &str, secret: &[u8], pin: &str, prf: Option<&PrfEnvelope>) -> Result<Vault> {
        check_passphrase(pin)?;
        let dek = Zeroizing::new(random::<32>()?);
        let data = gcm_seal(&dek, secret, &aad(label, "data"))?;
        let pin = pin_envelope(label, &dek, pin)?;
        let prf = prf.map(|p| prf_envelope(label, &dek, p)).transpose()?;
        Ok(Vault { label: label.to_owned(), data, pin, prf })
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
                let log_n = LOG_N.iter().find(|l| 1u64 << **l == p.n).filter(|_| p.kdf == "scrypt" && p.r == 8 && p.p == 1);
                (pin_kek(pin, &p.salt, *log_n.ok_or(Error::VaultParams)?)?, &p.sealed, "pin")
            }
        };
        key32(gcm_open(&kek, sealed, &aad(&self.label, part))?, Error::VaultOpen)
    }

    /// The secret (errors as `dek`).
    pub(crate) fn open(&self, unlock: Unlock) -> Result<Zeroizing<Vec<u8>>> {
        gcm_open(&*self.dek(unlock)?, &self.data, &aad(&self.label, "data"))
    }

    /// What the vault holds: `seed`, `manifest`, `native-import:<network>:<n>`, …
    pub fn label(&self) -> &str {
        &self.label
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
        Ok(Vault { pin: pin_envelope(&self.label, &dek, new)?, ..self.clone() })
    }

    /// The vault with a PRF envelope (replacing one it had), opened by the passphrase once.
    pub fn enable_prf(&self, pin: &str, prf: &PrfEnvelope) -> Result<Vault> {
        let dek = self.dek(Unlock::VaultPassphrase(pin))?;
        Ok(Vault { prf: Some(prf_envelope(&self.label, &dek, prf)?), ..self.clone() })
    }

    /// The clientkeys JSON (its field order).
    pub fn to_json(&self) -> String {
        let s = |x: &str| Value::from(x).to_string();
        let b = |x: &[u8]| Base64UrlUnpadded::encode_string(x);
        let gcm = |g: &GcmBox| format!("\"iv\":\"{}\",\"ct\":\"{}\"", b(&g.iv), b(&g.ct));
        let p = &self.pin;
        let prf = self.prf.as_ref().map_or(String::new(), |f| {
            format!(",\"prf\":{{\"credentialId\":{},\"salt\":\"{}\",{}}}", s(&f.credential_id), b(&f.salt), gcm(&f.sealed))
        });
        format!(
            "{{\"v\":1,\"label\":{},\"data\":{{{}}},\"pin\":{{\"kdf\":{},\"N\":{},\"r\":{},\"p\":{},\"salt\":\"{}\",{}}}{prf}}}",
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

    /// The named fields of a vault JSON: `Argument` past 2 MiB or depth 2 or for a malformed field, `VaultVersion` for any `v`
    /// other than 1 (before any other field is read). A non-integer `N`, `r` or `p` is kept as 0 (refused on open).
    pub fn from_json(json: &[u8]) -> Result<Vault> {
        let v = bounded::json(json, VAULT_JSON, VAULT_DEPTH)?;
        if v.get("v").and_then(Value::as_u64) != Some(1) {
            return Err(Error::VaultVersion);
        }
        parse(&v).ok_or(Error::Argument)
    }
}

fn parse(v: &Value) -> Option<Vault> {
    let bytes = |x: &Value, k: &str| Base64UrlUnpadded::decode_vec(x.get(k)?.as_str()?).ok();
    let gcm = |x: &Value| Some(GcmBox { iv: bytes(x, "iv")?, ct: bytes(x, "ct")? });
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
        Some(f) => Some(Prf { credential_id: f.get("credentialId")?.as_str()?.to_owned(), salt: bytes(f, "salt")?, sealed: gcm(f)? }),
    };
    Some(Vault { label: v.get("label")?.as_str()?.to_owned(), data: gcm(v.get("data")?)?, pin, prf })
}

impl Wallet {
    /// The seed vault (label `seed`) of this wallet's entropy at its own length, a new DEK, the pin envelope under
    /// `vault_passphrase` (the new-passphrase policy, `Argument`) and the PRF envelope if given; `WalletLocked` while locked.
    /// The BIP-39 passphrase is not in it.
    pub fn seal_vault(&self, vault_passphrase: &str, prf: Option<&PrfEnvelope>) -> Result<Vault> {
        let entropy = self.store.with_arena(|a| Ok(Zeroizing::new(a.entropy()?.to_vec())))?;
        Vault::seal("seed", &entropy, vault_passphrase, prf)
    }

    /// The wallet of a seed vault and the BIP-39 passphrase (asked at every unlock, never stored): `Argument` for a label other
    /// than `seed`, `VaultParams` / `VaultOpen` as the envelope, `VaultOpen` for a payload of other than 16, 20, 24, 28 or 32
    /// bytes (never padded or cut).
    pub fn open_vault(vault: &Vault, unlock: Unlock, bip39_passphrase: &str) -> Result<Wallet> {
        Wallet::from_entropy(&seed_entropy(vault, unlock)?, bip39_passphrase)
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
