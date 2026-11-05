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
//! `Expect` policy of [`NativeKey::sign_typed`]; `tx`, T5: [`NativeKey::sign_transaction`], EVM types 0-3 (no type 4); the vault
//! with T9. Randomness: `rand_core` 0.6 `OsRng` inside; no call takes an
//! RNG. UNAUDITED.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::disallowed_methods)]

pub mod bounded;
#[cfg(feature = "vectors")]
pub mod derive;
mod eip712;
#[cfg(not(feature = "vectors"))]
pub(crate) mod derive;
#[cfg(feature = "vectors")]
pub mod pairing;
#[cfg(not(feature = "vectors"))]
mod pairing;
mod policy;
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

pub use eip712::{scaas_typed_data, TypedData};
pub use pairing::{FrostSession, Musig2Session};
pub use policy::{AllowAnyTypedData, AllowRow, Expect, Invalidate, SubjectKey};
pub use signer::{AllowRawDigest, KeyRef, SigRole, SignRequest, Signer};
pub use tx::{AccessListItem, EvmTx, SignedTx};
pub use uasig::{membership_sig, msig_sig, ua_sig, Slot};

use crate::UAError;
use rand_core::{OsRng, RngCore};
use std::sync::Arc;
use store::{Handle, SecretStore};
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

/// The entropy of a new wallet, handed out once (spec §8.4; the three-word check and the vault are T9's).
pub struct SeedBackup {
    entropy: Option<Zeroizing<Vec<u8>>>,
}

impl SeedBackup {
    /// The entropy; `None` after the first call.
    pub fn take(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        self.entropy.take()
    }
}

/// A wallet: its secret store. `Send + Sync`, no `Clone`; dropping it locks it.
pub struct Wallet {
    store: Arc<SecretStore>,
}

impl Wallet {
    /// A new wallet of 24 words (32 bytes of OS entropy) and no BIP-39 passphrase, and its backup.
    pub fn generate() -> Result<(Wallet, SeedBackup)> {
        let mut e = Zeroizing::new(vec![0u8; 32]);
        OsRng.try_fill_bytes(&mut e).map_err(|_| Error::Rng)?;
        let w = Wallet::from_entropy(&e, "")?;
        Ok((w, SeedBackup { entropy: Some(e) }))
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

    /// Reopens a locked wallet from its entropy at the raised generation; earlier handles stay revoked. `Argument` if open.
    /// The vault's `unlock` (T9) calls it.
    #[cfg_attr(not(feature = "vectors"), allow(dead_code))]
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
        Ok(NativeKey { network, index, coin_type, public_key, secret })
    }
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.store.lock();
    }
}

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
