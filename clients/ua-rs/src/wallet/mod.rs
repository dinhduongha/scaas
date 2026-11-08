// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Feature `wallet` (ua-rs-sign; spec §4, §8.2, §9.1): a [`Wallet`] holds the BIP-39 entropy at its own length (16–32 bytes,
//! never padded) and the 64-byte seed of the BIP-39 passphrase, in its secret store; [`Wallet::ua_key`] and
//! [`Wallet::native_key`] derive keys exactly as clientkeys (`derive`) and return handles that hold the store, its generation
//! and a slot, no secret bytes. [`Wallet::lock`] waits for operations in flight, wipes the store and revokes every handle for
//! good (`KeyRevoked`); dropping the wallet locks it, and a handle that outlives it stays valid memory that answers
//! `KeyRevoked`. Signing: [`UaKey::sign_ua`], [`UaKey::sign_member`], the native keys' key proof and raw digest, all through
//! the [`Signer`] trait (`sign`, `signer`; T3a: the classic curves; `pqsign`, T3b: ML-DSA, SLH-DSA, Falcon; `pairing`, T3c:
//! scaas Schnorr, BLS with roles, the MuSig2 / FROST sessions, every arkworks secret multiplication by
//! `scaas_ct::secret_mul`); `uasig`, T3d: the `UASig` builder and the minimal `msig` sets over `&dyn Signer` (T4: native keys
//! and members by typed data); `eip712`, `policy`, T4: the faithful EIP-712 hasher, the SCaaS builders' canonical step, the
//! `Expect` policy of [`NativeKey::sign_typed`]; `tx`, T5: [`NativeKey::sign_transaction`], EVM types 0-3 (no type 4); `webauthn`, T6:
//! [`webauthn_challenge`] and [`webauthn_assertion`] (against the expected challenge, verified before return); `kem`, T7: the UA
//! KEM key through its UA key's own store ([`UaKey::kem_key`]), [`kem_encaps`], [`KemKeyPair`]; `aead`, `seal`, T8: AEAD, HKDF, HMAC,
//! [`seal`] / [`KemKeyPair::open`], the sealed containers of backup and link ([`seal_container`], [`KemKeyPair::open_container`],
//! [`LinkSession`], [`Wallet::from_link`]); `vault`, `manifest`, T9: the clientkeys vault v1 ([`Vault`], [`Wallet::seal_vault`],
//! [`Wallet::open_vault`]), the [`Manifest`], discovery, imported keys, the [`SeedBackup`] confirmation, [`Wallet::backup_seal`] and
//! [`Wallet::restore_backup`]; `store`, T10: [`Wallet::unlock`] (the seed vault into a new arena at the raised generation) and
//! [`Wallet::memory_protection`] (the arena's chunks `mlock`ed and no-dump, feature `mlock`). Randomness: `rand_core` 0.6
//! `OsRng` inside; no call takes an RNG. UNAUDITED.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::disallowed_methods)]

mod aead;
pub mod bounded;
#[cfg(feature = "vectors")]
pub mod derive;
mod eip712;
#[cfg(feature = "vectors")]
pub mod kem;
#[cfg(not(feature = "vectors"))]
mod kem;
#[cfg(not(feature = "vectors"))]
pub(crate) mod derive;
#[cfg(feature = "vectors")]
pub mod pairing;
#[cfg(not(feature = "vectors"))]
mod pairing;
mod manifest;
mod policy;
#[cfg(feature = "vectors")]
pub mod seal;
#[cfg(not(feature = "vectors"))]
mod seal;
#[cfg(feature = "vectors")]
pub mod pqsign;
#[cfg(not(feature = "vectors"))]
mod pqsign;
#[cfg(feature = "vectors")]
pub mod sign;
#[cfg(not(feature = "vectors"))]
mod sign;
mod signer;
mod store;
mod tx;
mod uasig;
mod vault;
mod webauthn;

pub use aead::{aead_open, aead_seal, hkdf_expand_sha256, hkdf_sha256, hmac_sha256, Alg};
pub use eip712::{pqz_verdict_typed_data, scaas_typed_data, TypedData};
#[cfg(any(feature = "zether", feature = "pqz"))]
pub(crate) use eip712::{from_hex, to_hex};
pub use kem::{is_kem_holder, kem_encaps, KemKeyPair};
#[cfg(feature = "vectors")]
pub use manifest::vectors_backup_payload;
pub use manifest::{AllowRollback, ImportEntry, KemEntry, Manifest, ManifestEntry, NativeEntry, PqzHeldEntry};
pub use pairing::{FrostSession, Musig2Session};
pub use policy::{sign_typed_by, AllowAnyTypedData, AllowRow, Expect, Invalidate, SubjectKey};
#[cfg(feature = "pqz")]
pub(crate) use seal::now;
pub use seal::{
    seal, seal_container, AcceptedJson, ContainerExpect, ContainerExpectJson, ContainerSigner, ExpectedSender, LinkSession,
    MembersJson, Recipient, RecipientId, Sealed, SealedContainer, LINK_WINDOW, MAX_PT, PURPOSE_BACKUP, PURPOSE_LINK,
};
pub use sign::{sign_digest_by, sign_key_proof_by};
#[cfg(feature = "vectors")]
pub use signer::TestExternalKey;
pub use signer::{AllowRawDigest, KeyRef, SigRole, SignRequest, Signer};
pub use tx::{sign_transaction_by, AccessListItem, EvmTx, SignedTx};
pub use uasig::{membership_sig, msig_sig, ua_sig, Slot, UaSigRequest};
pub use vault::{check_passphrase, PrfEnvelope, Unlock, Vault};
pub use webauthn::{webauthn_assertion, webauthn_challenge};
pub use zeroize::ZeroizeOnDrop;
#[cfg(feature = "vectors")]
pub use vectors::vectors_chunks_released;

use crate::UAError;
use rand_core::{OsRng, RngCore};
use std::sync::Arc;
pub(crate) use store::{Handle, SecretStore};
pub use store::{protect, MemoryProtection};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

/// A wallet error; [`Error::code`] is the name the vector files use. `Display` never shows an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An argument out of its range or form (index ≥ 2^31, a kind not derived from the seed, a bad mnemonic, JSON past its
    /// bounds).
    Argument,
    /// The handle's wallet was locked or freed after the handle was made (spec §8.2).
    KeyRevoked,
    /// The call needs secrets and the wallet is locked.
    WalletLocked,
    /// The kind exists but this build lacks it (Falcon on wasm32: no C).
    KindUnavailable,
    /// The OS random number generator failed.
    Rng,
    /// The signing policy refused the typed data: it is not what the `Expect` says the user confirmed (spec §5.4, MD-9).
    PolicyRefused,
    /// A WebAuthn assertion that is not the chains' form for the expected challenge, or does not verify (spec §5.6).
    WebAuthnAssertion,
    /// A KEM key asked of a kind that holds none (CTR-UA-32; an `msig` has none, MD-11; spec §6.1).
    KemHolder,
    /// A KEM input refused by its checks: `kemPk` scheme, length or modulus, a short ciphertext, an all-zero X25519 secret
    /// (spec §6.2); the derived key's self-test (FIPS 203 §7.3).
    KemCheck,
    /// An AEAD tag that does not verify (spec §7): no plaintext.
    Aead,
    /// A seal that does not open with this key, purpose and `aad` (decapsulation checks, tag), or a container whose sender
    /// signature, `UASig` form or member set does not verify (spec §6.3).
    SealOpen,
    /// A seal or container of a version or scheme other than 1 (spec §6.3).
    SealVersion,
    /// A container whose purpose, recipient, sender or key data is not the expected one, an `msig` sender without its
    /// `accepted` lookup or with a signer not accepted, an unknown member key (spec §6.3, C-03, CTR-UA-37).
    ContainerSender,
    /// A link container created outside its session's window (spec §6.3, C-11).
    ContainerReplay,
    /// A vault that does not open with this passphrase or PRF secret (wrong, or the vault altered), or a seed vault whose
    /// payload is not BIP-39 entropy (spec §8.1).
    VaultOpen,
    /// A pin envelope outside `N ∈ {2^15, 2^16, 2^17}, r = 8, p = 1` (refused before scrypt runs; CLI-SGN-21).
    VaultParams,
    /// A vault of a version other than 1 (`v: 2` and its tombstone): open it where it was made and export v1 (spec §8.1).
    VaultVersion,
    /// A backup older than the one the wallet holds, without [`AllowRollback`] (spec §6.3, C-11).
    BackupRollback,
    /// [`Wallet::unlock`] with a seed vault that opened but whose seed, with this BIP-39 passphrase, does not derive the UA of
    /// the kept manifest's first entry: another wallet's vault, or another BIP-39 passphrase. Not `VaultOpen` (the vault did
    /// open: a new vault passphrase does not help) and not `Argument` (the input is well formed); the wallet stays locked.
    WalletMismatch,
    /// A PQZ call whose `proofSystemId` or deployed parameter set is not this build's (spec §10.2: one set per build).
    PqzSetMismatch,
    /// An external key's answer that, once normalised (low-s, `v`), does not verify against its [`KeyRef`] under the request's
    /// role (spec §9.4, MD-13): nothing is returned.
    ExternalSignature,
    Ua(UAError),
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Error::Argument => "Argument",
            Error::KeyRevoked => "KeyRevoked",
            Error::WalletLocked => "WalletLocked",
            Error::KindUnavailable => "KindUnavailable",
            Error::Rng => "Rng",
            Error::PolicyRefused => "PolicyRefused",
            Error::WebAuthnAssertion => "WebAuthnAssertion",
            Error::KemHolder => "KemHolder",
            Error::KemCheck => "KemCheck",
            Error::Aead => "Aead",
            Error::SealOpen => "SealOpen",
            Error::SealVersion => "SealVersion",
            Error::ContainerSender => "ContainerSender",
            Error::ContainerReplay => "ContainerReplay",
            Error::VaultOpen => "VaultOpen",
            Error::VaultParams => "VaultParams",
            Error::VaultVersion => "VaultVersion",
            Error::BackupRollback => "BackupRollback",
            Error::WalletMismatch => "WalletMismatch",
            Error::PqzSetMismatch => "PqzSetMismatch",
            Error::ExternalSignature => "ExternalSignature",
            Error::Ua(e) => e.code(),
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Ua(e) => e.fmt(f),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for Error {}

impl From<UAError> for Error {
    fn from(e: UAError) -> Self {
        Error::Ua(e)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// The networks of clientkeys `NETWORKS` (`seed.js`), their SLIP-44 paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Network {
    Evm,
    Cosmos,
    HederaEcdsa,
    HederaEd25519,
    Sui,
    Stellar,
    Ton,
    Aptos,
    Solana,
}

const NETWORK_NAMES: [(Network, &str); 9] = [
    (Network::Evm, "evm"),
    (Network::Cosmos, "cosmos"),
    (Network::HederaEcdsa, "hedera_ecdsa"),
    (Network::HederaEd25519, "hedera_ed25519"),
    (Network::Sui, "sui"),
    (Network::Stellar, "stellar"),
    (Network::Ton, "ton"),
    (Network::Aptos, "aptos"),
    (Network::Solana, "solana"),
];

impl Network {
    /// The clientkeys name (`evm`, `hedera_ecdsa`, …).
    pub fn from_name(name: &str) -> Option<Network> {
        NETWORK_NAMES.iter().find(|(_, n)| *n == name).map(|(net, _)| *net)
    }
    pub fn name(self) -> &'static str {
        NETWORK_NAMES.iter().find(|(net, _)| *net == self).map_or("", |(_, n)| n)
    }
    fn ed25519(self) -> bool {
        !matches!(self, Network::Evm | Network::Cosmos | Network::HederaEcdsa)
    }
    /// The SLIP-44 path of key `i`; element 1 is the coin type.
    fn path(self, i: u32) -> Vec<u32> {
        const H: u32 = derive::HARDENED;
        match self {
            Network::Evm => vec![44 | H, 60 | H, H, 0, i],
            Network::Cosmos => vec![44 | H, 118 | H, H, 0, i],
            Network::HederaEcdsa => vec![44 | H, 3030 | H, H, 0, i],
            Network::HederaEd25519 => vec![44 | H, 3030 | H, H, H, i | H],
            Network::Sui => vec![44 | H, 784 | H, i | H, H, H],
            Network::Stellar => vec![44 | H, 148 | H, i | H],
            Network::Ton => vec![44 | H, 607 | H, i | H],
            Network::Aptos => vec![44 | H, 637 | H, i | H, H, H],
            Network::Solana => vec![44 | H, 501 | H, i | H, H],
        }
    }
}

/// What the store keeps one slot for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum KeyId {
    Ua(u16, u32, u32),
    Native(Network, u32, Option<u32>),
    /// A UA's KEM key: its UA and the KEM record's version (spec §6.1).
    Kem([u8; 32], u64),
    /// Imported key `n` (`native-import:<network>:<n>`, spec §8.3).
    Import(u32),
    /// The Zether key `m/12381/<coin>/<account>/<use>` (spec §10.1, feature `zether`).
    #[cfg(feature = "zether")]
    Zether(u32, u32, u32),
    /// The PQZ leaf `seed32` of `account` / `index` / key version (spec §10.2, group 3g C8; feature `pqz`).
    #[cfg(feature = "pqz")]
    Pqz(u32, u32, u64),
    /// A PQZ `seed32` rebuilt from an `msig`'s k-of-n backup, by its key hash (T16a, feature `pqz`).
    #[cfg(feature = "pqz")]
    PqzHeld([u8; 32]),
}

/// A mnemonic as clientkeys `normalizeMnemonic` (NFKD, lower case, single spaces), at most 1 KiB and 24 words (spec §9.3),
/// English, with its checksum.
fn parse_mnemonic(words: &str) -> Result<bip39::Mnemonic> {
    if words.len() > 1024 {
        return Err(Error::Argument);
    }
    let nfkd = Zeroizing::new(words.nfkd().collect::<String>());
    let lower = Zeroizing::new(nfkd.to_lowercase());
    if lower.split_whitespace().count() > 24 {
        return Err(Error::Argument);
    }
    let joined = Zeroizing::new(lower.split_whitespace().collect::<Vec<_>>().join(" "));
    bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &joined).map_err(|_| Error::Argument)
}

/// The 64-byte BIP-39 seed of `entropy` with the passphrase (NFKD).
fn seed_of(entropy: &[u8], bip39_passphrase: &str) -> Result<Zeroizing<[u8; 64]>> {
    let m = bip39::Mnemonic::from_entropy(entropy).map_err(|_| Error::Argument)?;
    let pass = Zeroizing::new(bip39_passphrase.nfkd().collect::<String>());
    Ok(Zeroizing::new(m.to_seed_normalized(&pass)))
}

/// The entropy of a parsed mnemonic, at its BIP-39 length; the `Mnemonic` (word indices, `ZeroizeOnDrop`) is dropped here.
fn entropy_of(m: bip39::Mnemonic) -> Result<Zeroizing<Vec<u8>>> {
    let (mut a, len) = m.to_entropy_array();
    let e = Zeroizing::new(a.get(..len).ok_or(Error::Argument)?.to_vec());
    a.zeroize();
    Ok(e)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BackupState {
    Fresh,
    Revealed,
    Challenged,
    Verified,
}

/// The recovery phrase of a new wallet (spec §8.4, CLI-SGN-11, clientkeys `SeedBackup`): shown once ([`SeedBackup::reveal`]),
/// confirmed by three words at random positions ([`SeedBackup::challenge`], [`SeedBackup::verify`]), only then handed out once
/// ([`SeedBackup::take`]) and forgotten. States `fresh → revealed → challenged → verified → taken`.
pub struct SeedBackup {
    entropy: Option<Zeroizing<Vec<u8>>>,
    state: BackupState,
    asked: [usize; 3],
}

impl SeedBackup {
    fn words(&self) -> Result<bip39::Mnemonic> {
        bip39::Mnemonic::from_entropy(self.entropy.as_deref().ok_or(Error::Argument)?).map_err(|_| Error::Argument)
    }

    /// The words, once (`Argument` after).
    pub fn reveal(&mut self) -> Result<Zeroizing<String>> {
        if self.state != BackupState::Fresh {
            return Err(Error::Argument);
        }
        let words = Zeroizing::new(self.words()?.to_string());
        self.state = BackupState::Revealed;
        Ok(words)
    }

    /// Three distinct positions to ask, 1-based and ascending (OS RNG); asked again after a miss. `Argument` before `reveal`.
    pub fn challenge(&mut self) -> Result<[usize; 3]> {
        if !matches!(self.state, BackupState::Revealed | BackupState::Challenged) {
            return Err(Error::Argument);
        }
        let count = self.words()?.word_count();
        let bound = u32::try_from(count).map_err(|_| Error::Argument)?;
        let mut picked: Vec<usize> = Vec::with_capacity(3);
        while picked.len() < 3 {
            let mut b = [0u8; 4];
            OsRng.try_fill_bytes(&mut b).map_err(|_| Error::Rng)?;
            let n = u32::from_be_bytes(b);
            // uniform: draws above the last whole multiple of `count` are redrawn
            if n >= u32::MAX - u32::MAX % bound {
                continue;
            }
            let i = usize::try_from(n % bound).map_err(|_| Error::Argument)?;
            if !picked.contains(&i) {
                picked.push(i);
            }
        }
        picked.sort_unstable();
        let mut asked = [0usize; 3];
        asked.iter_mut().zip(&picked).for_each(|(a, p)| *a = *p);
        self.asked = asked;
        self.state = BackupState::Challenged;
        Ok(asked.map(|i| i + 1))
    }

    /// Whether `answers` are the words at the asked positions, in order (case and surrounding space ignored); `true` makes the
    /// entropy available to [`SeedBackup::take`]. `Argument` before a challenge.
    pub fn verify(&mut self, answers: &[&str]) -> Result<bool> {
        if self.state != BackupState::Challenged {
            return Err(Error::Argument);
        }
        let m = self.words()?;
        let words: Vec<&str> = m.words().collect();
        let ok = answers.len() == self.asked.len()
            && self.asked.iter().zip(answers).all(|(i, a)| words.get(*i) == Some(&Zeroizing::new(a.trim().to_lowercase()).as_str()));
        if ok {
            self.state = BackupState::Verified;
        }
        Ok(ok)
    }

    /// The entropy, once the words were confirmed; `None` before that and after the first call.
    pub fn take(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        if self.state != BackupState::Verified {
            return None;
        }
        self.entropy.take()
    }
}

/// A wallet: its secret store. `Send + Sync`, no `Clone`; dropping it locks it.
///
/// The handles are neither `Clone` nor `Debug` and give no secret bytes (spec §8.2; positive control first):
/// ```
/// use scaas_ua::wallet::{KemKeyPair, NativeKey, UaKey, Wallet};
/// fn need<T: Send + Sync>() {}
/// need::<UaKey>();
/// need::<NativeKey>();
/// need::<KemKeyPair>();
/// need::<Wallet>();
/// ```
/// ```compile_fail,E0277
/// fn need<T: Clone>() {}
/// need::<scaas_ua::wallet::UaKey>();
/// ```
/// ```compile_fail,E0277
/// fn need<T: Clone>() {}
/// need::<scaas_ua::wallet::NativeKey>();
/// ```
/// ```compile_fail,E0277
/// fn need<T: Clone>() {}
/// need::<scaas_ua::wallet::KemKeyPair>();
/// ```
/// ```compile_fail,E0277
/// fn need<T: Clone>() {}
/// need::<scaas_ua::wallet::Wallet>();
/// ```
/// ```compile_fail,E0277
/// fn need<T: std::fmt::Debug>() {}
/// need::<scaas_ua::wallet::UaKey>();
/// ```
/// ```compile_fail,E0277
/// fn need<T: std::fmt::Debug>() {}
/// need::<scaas_ua::wallet::NativeKey>();
/// ```
/// ```compile_fail,E0277
/// fn need<T: std::fmt::Debug>() {}
/// need::<scaas_ua::wallet::KemKeyPair>();
/// ```
/// ```compile_fail,E0277
/// fn need<T: std::fmt::Debug>() {}
/// need::<scaas_ua::wallet::Wallet>();
/// ```
#[cfg_attr(
    not(feature = "vectors"),
    doc = "A release build (no feature `vectors`) has no secret accessor and no RNG or fixed-randomness parameter (F-01):",
    doc = "```compile_fail,E0599",
    doc = "fn f(k: &scaas_ua::wallet::UaKey) {",
    doc = "    let _ = k.vectors_with_secret(|s| s.to_vec());",
    doc = "}",
    doc = "```",
    doc = "```compile_fail,E0599",
    doc = "fn f(w: &scaas_ua::wallet::Wallet) {",
    doc = "    let _ = w.vectors_entropy();",
    doc = "}",
    doc = "```",
    doc = "```compile_fail,E0599",
    doc = "fn f(k: &scaas_ua::wallet::UaKey) {",
    doc = "    let _ = k.vectors_sign_ua_fixed(&[0; 32], &[0; 32], &[0; 32]);",
    doc = "}",
    doc = "```",
    doc = "```compile_fail,E0599",
    doc = "fn f(k: &scaas_ua::wallet::UaKey) {",
    doc = "    let _ = k.vectors_musig2_session(&[], &[], &[0; 32]);",
    doc = "}",
    doc = "```",
    doc = "```compile_fail,E0599",
    doc = "let _ = scaas_ua::wallet::KemKeyPair::vectors_ephemeral(&[0; 96]);",
    doc = "```",
    doc = "```compile_fail,E0599",
    doc = "fn f(w: &scaas_ua::wallet::Wallet, k: &scaas_ua::wallet::UaKey) {",
    doc = "    let _ = w.vectors_link_seal(k, &[], \"1\", 0, &[0; 32], &[0; 32]);",
    doc = "}",
    doc = "```"
)]
pub struct Wallet {
    store: Arc<SecretStore>,
}

impl Wallet {
    /// A new wallet of 24 words (32 bytes of OS entropy) and no BIP-39 passphrase, and its backup.
    pub fn generate() -> Result<(Wallet, SeedBackup)> {
        let mut e = Zeroizing::new(vec![0u8; 32]);
        OsRng.try_fill_bytes(&mut e).map_err(|_| Error::Rng)?;
        let w = Wallet::from_entropy(&e, "")?;
        Ok((w, SeedBackup { entropy: Some(e), state: BackupState::Fresh, asked: [0; 3] }))
    }

    /// The wallet of a 12- to 24-word English mnemonic (NFKD, case and spacing as clientkeys) and its BIP-39 passphrase.
    pub fn from_mnemonic(words: &str, bip39_passphrase: &str) -> Result<Wallet> {
        let entropy = entropy_of(parse_mnemonic(words)?)?;
        Wallet::from_entropy(&entropy, bip39_passphrase)
    }

    fn from_entropy(entropy: &[u8], bip39_passphrase: &str) -> Result<Wallet> {
        let w = Wallet { store: SecretStore::new() };
        w.store.open(entropy, &*seed_of(entropy, bip39_passphrase)?)?;
        Ok(w)
    }

    /// Waits for every operation in flight, wipes every secret and revokes every handle made before (spec §8.2).
    pub fn lock(&self) {
        self.store.lock();
    }

    /// The arena's memory protection now (spec §8.2, feature `mlock`, best effort): all zero while locked.
    pub fn memory_protection(&self) -> MemoryProtection {
        self.store.memory_protection()
    }

    /// Reopens a locked wallet from its entropy at the raised generation; earlier handles stay revoked. `Argument` if open.
    /// [`Wallet::unlock`] calls it.
    pub(crate) fn unlock_entropy(&self, entropy: &[u8], bip39_passphrase: &str) -> Result<()> {
        self.store.open(entropy, &*seed_of(entropy, bip39_passphrase)?)
    }

    /// The UA key `kind` of `account` / `index` (spec §4): `Argument` for a value ≥ 2^31, index ≠ 0 on an EIP-2333 kind
    /// (`0x0104`–`0x0107`, `0x0112`), or a kind not derived from the seed; `KindUnavailable` for Falcon on a build without
    /// it (wasm32); `WalletLocked` while locked.
    pub fn ua_key(&self, kind: u16, account: u32, index: u32) -> Result<UaKey> {
        let (secret, key_data) = self.store.key(KeyId::Ua(kind, account, index), |seed| {
            derive::ua_key(kind, derive::ua_secret(seed, kind, account, index)?)
        })?;
        // a MuSig2 participant (0x0110, 0x0112) has no UA of its own: its group is the UA
        let ua = if matches!(kind, 0x0110 | 0x0112) { None } else { Some(crate::derive_ua(kind, &key_data, false)?) };
        if let Some(ua) = ua {
            self.store.note(|m| m.add_ua(kind, account, index, ua));
        }
        Ok(UaKey { kind, account, index, key_data, ua, secret })
    }

    /// Key `index` of `network` (clientkeys `deriveKey`), `coin_type` in place of the network's (Pi Network: `Stellar`,
    /// 314159); `Argument` for a value ≥ 2^31.
    pub fn native_key(&self, network: Network, index: u32, coin_type: Option<u32>) -> Result<NativeKey> {
        let (secret, public_key) = self.store.key(KeyId::Native(network, index, coin_type), |seed| {
            let s = derive::native_secret(seed, network, index, coin_type)?;
            let public = derive::native_public(network, &s)?;
            Ok((s, public))
        })?;
        self.store.note(|m| m.add_native(network, coin_type, index));
        Ok(NativeKey { network, index, coin_type, public_key, secret })
    }
}

/// Feature `zether` (spec §10.1, T14): the facade's key handle.
#[cfg(feature = "zether")]
impl Wallet {
    /// The Zether key of `coin` / `account` (`key_use` 7: the conf key, 8: the viewing key; any other `Argument`), BLS12-381,
    /// EIP-2333 path `m/12381/<coin>/<account>/<use>` (zether-prover `ZetherKey::derive`); `x` stays in this wallet's arena
    /// (`lock()` revokes the handle), `Y` and the UA come out. `WalletLocked` while locked.
    pub fn zether_key(&self, coin: u32, account: u32, key_use: u32) -> Result<crate::facade::zether::ZetherKey> {
        crate::facade::zether::derive(&self.store, coin, account, key_use)
    }
}

/// Feature `pqz` (spec §10.2, T15): the facade's key handle and the one explicit export of a secret.
#[cfg(feature = "pqz")]
impl Wallet {
    /// The PQZ key of `account` / `index` (each below 2^31): `seed32 = HKDF-SHA256(seed, "scaas.ua.pq.v1",
    /// utf8("scaas.ua.pqz-mlwe.v1") ‖ be32(account) ‖ be32(index))` → `pqzl::keygen`; `seed32` stays in this wallet's arena
    /// (`lock()` revokes the handle), `pk` comes out. `WalletLocked` while locked.
    pub fn pqz_key(&self, account: u32, index: u32) -> Result<crate::facade::pqz::PqzKey> {
        self.pqz_key_version(account, index, 0)
    }

    /// The PQZ key of `account` / `index` at key version `version` (group 3g C8, ua-rs-sign T15o): version 0 is
    /// [`Wallet::pqz_key`]'s, every version v ≥ 1 appends `be64(v)` to the HKDF `info` (a single-key holder's rotation; an
    /// `msig` operator draws each version's `seed32` fresh instead, never from this). `WalletLocked` while locked.
    pub fn pqz_key_version(&self, account: u32, index: u32, version: u64) -> Result<crate::facade::pqz::PqzKey> {
        crate::facade::pqz::derive(&self.store, account, index, version)
    }

    /// The PQZ key of an `msig` rebuilt from its k-of-n backup (T16a, owner 2026-11-06; [`crate::facade::pqz_backup`]): the
    /// share `containers` (at most 16), each opened by `kk` as `expect` says (purpose `scaas/pqz-share/v1`); every header must
    /// be `(msig_ua, version, pqz_key_hash)` (the registered key's hash) with one `k` and `n`, the indices distinct, at least
    /// `k` of them; the rebuilt `seed32` must give a key of `pqz_key_hash`. Then it is installed in this wallet's store (lock
    /// revokes the handle) and this wallet's holder is the new operator. `Argument` for any of these; errors of the opening as
    /// [`KemKeyPair::open_container`]; `WalletLocked` while locked.
    ///
    /// It persists as an imported key does (T16b, owner 2026-11-06): listed in the manifest (`pqzHeld`, kept by `lock()`), in
    /// this wallet's backup and link payloads, and in a vault of label `pqz-held:<msig ua>:<version>:<pqzKeyHash>`
    /// ([`Wallet::seal_label_vault`]); after `unlock`, [`Wallet::open_label_vault`] of that vault holds it again (checked
    /// against `pqzKeyHash`) and [`Wallet::pqz_held_key`] returns it. The new operator should rotate to a new key version soon
    /// (spec 3g, `2026-11-06-pqz-key-versions.md` §1 / §7.2): every member who held k shares, and the old operator, can read
    /// under this version.
    #[cfg(feature = "pqz")]
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct_pqz_seed(
        &self, kk: &KemKeyPair, containers: &[SealedContainer], expect: &ContainerExpect, members: &crate::ua8::Members,
        accepted: Option<&crate::ua8::Accepted>, msig_ua: &[u8; 32], version: u64, pqz_key_hash: &[u8; 32],
    ) -> Result<crate::facade::pqz::PqzKey> {
        crate::facade::release_or_unlocked()?;
        let k = crate::facade::pqz_backup::reconstruct(&self.store, kk, containers, expect, members, accepted, msig_ua, version, pqz_key_hash)?;
        self.store.note(|m| m.add_pqz_held(PqzHeldEntry { ua: *msig_ua, version, pqz_key_hash: *pqz_key_hash }));
        Ok(k)
    }

    /// The PQZ key this wallet rebuilt ([`Wallet::reconstruct_pqz_seed`]) or reopened from its `pqz-held:` vault (T16b), by
    /// its key hash: `Argument` unless the manifest lists it and the store holds it (after `unlock`, open its vault first);
    /// `WalletLocked` while locked. Account and index `u32::MAX`.
    pub fn pqz_held_key(&self, pqz_key_hash: &[u8; 32]) -> Result<crate::facade::pqz::PqzKey> {
        if !self.store.manifest().pqz_held.iter().any(|e| e.pqz_key_hash == *pqz_key_hash) {
            return Err(Error::Argument);
        }
        crate::facade::pqz::held(&self.store, pqz_key_hash)
    }

    /// The 32-byte PQZ leaf `seed32` of `account` / `index` in the clear, for `pqz-cli` or a key oracle (spec §8.4,
    /// CTR-PQZ-13): the only call that returns a secret, so it takes the marker value. The caller wipes it (`Zeroizing`).
    pub fn export_pqz_leaf_raw(
        &self, account: u32, index: u32, marker: crate::facade::pqz::AllowSecretExport,
    ) -> Result<Zeroizing<[u8; 32]>> {
        self.export_pqz_leaf_raw_version(account, index, 0, marker)
    }

    /// [`Wallet::export_pqz_leaf_raw`] of key version `version` ([`Wallet::pqz_key_version`]; T15o).
    pub fn export_pqz_leaf_raw_version(
        &self, account: u32, index: u32, version: u64, _: crate::facade::pqz::AllowSecretExport,
    ) -> Result<Zeroizing<[u8; 32]>> {
        crate::facade::pqz::derive(&self.store, account, index, version)?.leaf()
    }
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.store.lock();
    }
}

// `ZeroizeOnDrop` (the marker of zeroize: a type whose drop wipes what it holds) of each type a C ABI handle wraps (T12, spec
// §9.2 "`_free` zeroizes"); ua-c checks the bound statically. Where the wipe happens:
// - `Wallet`: its drop locks the store, which wipes and releases every arena chunk (`store.rs`, each `Chunk` zeroized at drop).
// - `UaKey`, `NativeKey`, `KemKeyPair`: no secret bytes of their own (their store's `Arc`, a generation and a slot); the slot is
//   wiped with its store, at the wallet's lock or drop, or, for an ephemeral key's own store, when its last handle drops.
// - `SeedBackup`: the entropy is `Zeroizing`.
// - `LinkSession`: its key's store is its own (wiped as above) and `from_link` wipes it whatever the outcome.
impl zeroize::ZeroizeOnDrop for Wallet {}
impl zeroize::ZeroizeOnDrop for UaKey {}
impl zeroize::ZeroizeOnDrop for NativeKey {}
impl zeroize::ZeroizeOnDrop for KemKeyPair {}
impl zeroize::ZeroizeOnDrop for SeedBackup {}
impl zeroize::ZeroizeOnDrop for LinkSession {}

/// A UA key handle: its store, generation and slot; no secret bytes. No `Clone`.
pub struct UaKey {
    kind: u16,
    account: u32,
    index: u32,
    key_data: Vec<u8>,
    ua: Option<[u8; 32]>,
    secret: Handle,
}

impl UaKey {
    pub fn kind(&self) -> u16 {
        self.kind
    }
    pub fn account(&self) -> u32 {
        self.account
    }
    pub fn index(&self) -> u32 {
        self.index
    }
    pub fn key_data(&self) -> Vec<u8> {
        self.key_data.clone()
    }
    /// The UA; `None` for a MuSig2 participant (`0x0110`, `0x0112`).
    pub fn ua(&self) -> Option<[u8; 32]> {
        self.ua
    }
}

/// A native key handle; no secret bytes. No `Clone`.
pub struct NativeKey {
    network: Network,
    index: u32,
    coin_type: Option<u32>,
    public_key: Vec<u8>,
    secret: Handle,
}

impl NativeKey {
    pub fn network(&self) -> Network {
        self.network
    }
    pub fn index(&self) -> u32 {
        self.index
    }
    pub fn coin_type(&self) -> Option<u32> {
        self.coin_type
    }
    /// The compressed secp256k1 key or the ed25519 key.
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

/// Test-only hooks (feature `vectors`, never in a release build): they hand out secrets.
#[cfg(feature = "vectors")]
mod vectors {
    use super::*;

    /// `(released, released with a non-zero byte)`: the arena chunks released in this process (each wiped before it goes back).
    pub fn vectors_chunks_released() -> (usize, usize) {
        store::vectors::chunks_released()
    }

    impl Wallet {
        pub fn vectors_entropy(&self) -> Result<Zeroizing<Vec<u8>>> {
            self.store.with_arena(|a| Ok(Zeroizing::new(a.entropy()?.to_vec())))
        }
        pub fn vectors_seed(&self) -> Result<Zeroizing<[u8; 64]>> {
            self.store.seed()
        }
        /// Bytes written to the store's arena.
        pub fn vectors_arena_used(&self) -> Result<usize> {
            self.store.used()
        }
        /// The FIPS 203 §7.3 self-tests run in this wallet's current store.
        pub fn vectors_kem_self_tests(&self) -> Result<usize> {
            self.store.self_tests()
        }
        pub fn vectors_unlock(&self, words: &str, bip39_passphrase: &str) -> Result<()> {
            self.unlock_entropy(&entropy_of(parse_mnemonic(words)?)?, bip39_passphrase)
        }
    }

    impl UaKey {
        /// `f` over the secret, under the store's guard, as a signer will run.
        pub fn vectors_with_secret<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R> {
            self.secret.with(f)
        }
        /// Whether the bytes the handle's operations read lie in the arena and outside the handle itself.
        pub fn vectors_secret_in_arena(&self) -> Result<bool> {
            self.secret.in_arena((self as *const Self as usize, std::mem::size_of::<Self>()))
        }
    }

    impl NativeKey {
        pub fn vectors_with_secret<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R> {
            self.secret.with(f)
        }
        pub fn vectors_secret_in_arena(&self) -> Result<bool> {
            self.secret.in_arena((self as *const Self as usize, std::mem::size_of::<Self>()))
        }
    }
}
