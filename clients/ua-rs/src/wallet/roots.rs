// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Classical-rooted seed sets (scaas-sdk spec §6.6, plan T6; feature `roots`): root (c) from two equal EIP-712 signatures of the
//! chain-free `KeyDerivation` message by an external EVM wallet, root (d) from a secp256k1 EVM private key; clientkeys
//! `rootFromEoaSignature` / `rootFromKey`, pinned by `smartcontracts/vectors/keys/roots.json`. Owner 2026-11-17 (spec §25): Argon2id
//! v0x13, m = 128 MiB, t = 3, p = 4, empty secret and data, 32 bytes, over the NFKC passphrase with salt keccak256(tag ‖ address);
//! the root = HKDF-SHA256(ikm, pw, tag ‖ u32be(set), 32), root (d) with an empty passphrase salted SHA-256(tag) instead; the root
//! is the new seed's 24-word entropy. The parameters are part of the derivation: they never change. UNAUDITED.

use super::{eip712, hkdf_sha256, sized, BackupState, Error, Result, SeedBackup, Wallet};
use crate::keccak256;
use argon2::{Algorithm, Argon2, Params, Version};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// Root (c)'s tag: its HKDF info and Argon2id salt prefix, and (hashed) its EIP-712 domain salt.
pub const ROOT_EOA_SIG_TAG: &str = "scaas.sdk.root.eoa-sig.v1";
/// Root (d)'s label (spec §25 Q-K18, fixed in plan T6).
pub const ROOT_RAW_KEY_TAG: &str = "scaas.sdk.root.raw-key.v1";
/// The fewest code points of a derivation passphrase after NFKC (owner R4).
pub const ROOT_PASSPHRASE_MIN: usize = 10;
/// The `warning` field of the derivation message (spec §6.6, research §5.3).
pub const KEY_DERIVATION_WARNING: &str = "This signature creates secret keys. Any site that obtains it, with your passphrase, \
controls those keys. Sign it only inside your SCaaS app.";
const ARGON2_M_KIB: u32 = 131_072;
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 4;

/// The derivation passphrase rule (spec §6.4): at least [`ROOT_PASSPHRASE_MIN`] code points after NFKC; with `optional` (root
/// (d)) the empty passphrase too. `Argument` otherwise (the SDK's `DerivationPassphraseShort`).
pub fn check_derivation_passphrase(p: &str, optional: bool) -> Result<()> {
    let n = sized(|| p.nfkc()).chars().count();
    if (optional && n == 0) || n >= ROOT_PASSPHRASE_MIN {
        Ok(())
    } else {
        Err(Error::Argument)
    }
}

/// Root (c)'s typed data (clientkeys `keyDerivationTypedData`; spec §25 Q-K5): the domain `{name: "SCaaS key derivation",
/// version: "1", salt: keccak256(ROOT_EOA_SIG_TAG)}` (no chainId, no verifyingContract) and `KeyDerivation(string warning,
/// address account, uint32 set)`. What the app's external wallet signs, twice.
pub fn key_derivation_typed_data(account: &[u8; 20], set: u32) -> Result<eip712::TypedData> {
    eip712::key_derivation_typed_data(account, set, KEY_DERIVATION_WARNING, &keccak256(ROOT_EOA_SIG_TAG.as_bytes()))
}

/// A 64-byte EIP-2098 compact signature `r ‖ yParityAndS` as `r ‖ s ‖ v` (v 27 / 28): the explicit conversion root (c) asks for.
pub fn signature_from_compact(sig: &[u8; 64]) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(sig);
    let parity = out[32] >> 7;
    out[32] &= 0x7f;
    out[64] = 27 + parity;
    out
}

/// Argon2id of spec §25 Q-K4 over the NFKC passphrase, salt keccak256(tag ‖ address).
fn stretch(passphrase: &str, tag: &str, address: &[u8; 20]) -> Result<Zeroizing<[u8; 32]>> {
    let p = sized(|| passphrase.nfkc());
    let salt = keccak256(&[tag.as_bytes(), address].concat());
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(32)).map_err(|_| Error::Argument)?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(p.as_bytes(), &salt, &mut *out)
        .map_err(|_| Error::Argument)?;
    Ok(out)
}

/// `tag ‖ u32be(n)`.
fn info(tag: &str, n: u32) -> Vec<u8> {
    [tag.as_bytes(), &n.to_be_bytes()].concat()
}

/// The EVM address of a secp256k1 verifying key.
fn address_of(vk: &VerifyingKey) -> Result<[u8; 20]> {
    let pt = vk.to_sec1_point(false);
    let h = keccak256(pt.as_bytes().get(1..).ok_or(Error::Argument)?);
    h.get(12..).and_then(|a| a.try_into().ok()).ok_or(Error::Argument)
}

/// Root (c)'s 32 bytes: `sig1` and `sig2` byte-equal, 65 bytes, `r`, `s` in [1, n), `v` in {0, 1, 27, 28}, recovering to
/// `account` over [`key_derivation_typed_data`]; then `r ‖ low-s s` is the HKDF input. `ExternalSignature` for a failed check
/// (the SDK's `OriginSignature`), `Argument` for a short passphrase (checked first).
pub fn root_from_eoa_signature(
    account: &[u8; 20], set: u32, sig1: &[u8], sig2: &[u8], passphrase: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    check_derivation_passphrase(passphrase, false)?;
    if sig1.len() != 65 || sig1 != sig2 {
        return Err(Error::ExternalSignature);
    }
    let (rs, v) = sig1.split_at(64);
    let mut bit = match v {
        [0] | [27] => 0u8,
        [1] | [28] => 1u8,
        _ => return Err(Error::ExternalSignature),
    };
    let s = Signature::from_slice(rs).map_err(|_| Error::ExternalSignature)?;
    let low = s.normalize_s();
    if low != s {
        bit ^= 1; // the same public key with the other recovery bit
    }
    let digest = key_derivation_typed_data(account, set)?.digest()?;
    let rec = RecoveryId::from_byte(bit).ok_or(Error::ExternalSignature)?;
    let vk = VerifyingKey::recover_from_prehash(&digest, &low, rec).map_err(|_| Error::ExternalSignature)?;
    if address_of(&vk)? != *account {
        return Err(Error::ExternalSignature);
    }
    let ikm = Zeroizing::new(low.to_bytes());
    let pw = stretch(passphrase, ROOT_EOA_SIG_TAG, account)?;
    let root = hkdf_sha256(&ikm, &*pw, &info(ROOT_EOA_SIG_TAG, set), 32)?;
    Ok(Zeroizing::new(root.as_slice().try_into().map_err(|_| Error::Argument)?))
}

/// Root (d)'s 32 bytes (spec §25 Q-K18): a secp256k1 EVM private key in [1, n), `index` the seed-set number, the passphrase
/// empty or ≥ 10 code points (`Argument` otherwise).
pub fn root_from_key(key: &[u8; 32], passphrase: &str, index: u32) -> Result<Zeroizing<[u8; 32]>> {
    check_derivation_passphrase(passphrase, true)?;
    let sk = SigningKey::from_slice(key).map_err(|_| Error::Argument)?;
    let info = info(ROOT_RAW_KEY_TAG, index);
    let root = if passphrase.is_empty() {
        let salt: [u8; 32] = Sha256::digest(ROOT_RAW_KEY_TAG.as_bytes()).into();
        hkdf_sha256(key, &salt, &info, 32)?
    } else {
        let pw = stretch(passphrase, ROOT_RAW_KEY_TAG, &address_of(sk.verifying_key())?)?;
        hkdf_sha256(key, &*pw, &info, 32)?
    };
    Ok(Zeroizing::new(root.as_slice().try_into().map_err(|_| Error::Argument)?))
}

impl Wallet {
    /// Root (c)'s new seed set (spec §6.6): the wallet of [`root_from_eoa_signature`]'s 24 words (empty BIP-39 passphrase) and its
    /// backup. Errors as that function.
    pub fn from_eoa_signature(
        account: &[u8; 20], set: u32, sig1: &[u8], sig2: &[u8], passphrase: &str,
    ) -> Result<(Wallet, SeedBackup)> {
        Self::from_root(root_from_eoa_signature(account, set, sig1, sig2, passphrase)?)
    }

    /// Root (d)'s new seed set (spec §6.6): the wallet of [`root_from_key`]'s 24 words and its backup.
    pub fn from_private_key(key: &[u8; 32], passphrase: &str, index: u32) -> Result<(Wallet, SeedBackup)> {
        Self::from_root(root_from_key(key, passphrase, index)?)
    }

    fn from_root(root: Zeroizing<[u8; 32]>) -> Result<(Wallet, SeedBackup)> {
        let e = Zeroizing::new(root.to_vec());
        let w = Wallet::from_entropy(&e, "")?;
        Ok((w, SeedBackup { entropy: Some(e), state: BackupState::Fresh, asked: [0; 3] }))
    }
}
