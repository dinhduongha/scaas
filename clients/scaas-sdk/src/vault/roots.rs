// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Classical-rooted seed sets (spec §6.6, CLI-SDK-05; feature `classical-roots`): root (c) from two equal EIP-712 signatures of
//! the fixed derivation message by the app's external EVM wallet, root (d) from a secp256k1 EVM private key, both built in
//! `scaas-ua` (`wallet::roots`). The new seed is 24 words, `class: classical-rooted` (MAC'd, inherited by its BIP-85 children),
//! `backup: pending`; the signatures, the key and the passphrases stay in `SecretBytes`. No RPC call names the origin address.

use super::seeds::{new_entry, passphrase, store_new, NewSeed, SeedBackup};
use super::Vault;
use crate::error::SdkError;
use scaas_ua::wallet::{roots, SecretBytes, Wallet};
use std::sync::{Arc, Mutex};

/// `vault.derive_from_signature`'s request (root (c)): the external wallet's account and the seed-set number `set` it signed
/// for, its two signatures of [`Vault::key_derivation_typed_data`] (65 bytes each; a 64-byte EIP-2098 one goes through
/// [`Vault::signature_from_compact`] first), the derivation passphrase (≥ 10 code points), the new seed's label and vault
/// passphrase.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", serde(deny_unknown_fields))]
pub struct DeriveFromSignature {
    pub label: String,
    /// `0x` and 40 hex digits, any case
    pub account: String,
    pub set: u32,
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::handle"))]
    pub signature1: Arc<SecretBytes>,
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::handle"))]
    pub signature2: Arc<SecretBytes>,
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::handle"))]
    pub derivation_passphrase: Arc<SecretBytes>,
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::handle"))]
    pub vault_passphrase: Arc<SecretBytes>,
}

/// `vault.derive_from_key`'s request (root (d)): a 32-byte key of `network` (`evm` only: `Argument` otherwise), the derivation
/// passphrase (empty, or ≥ 10 code points), the seed-set number `index`, the new seed's label and vault passphrase.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", serde(deny_unknown_fields))]
pub struct DeriveFromKey {
    pub label: String,
    pub network: String,
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::handle"))]
    pub key: Arc<SecretBytes>,
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::handle"))]
    pub derivation_passphrase: Arc<SecretBytes>,
    pub index: u32,
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::handle"))]
    pub vault_passphrase: Arc<SecretBytes>,
}

fn account(a: &str) -> Result<[u8; 20], SdkError> {
    let h = a
        .strip_prefix("0x")
        .filter(|h| h.len() == 40)
        .ok_or(SdkError::Argument)?;
    super::prf::unhex(h)
        .and_then(|b| b.try_into().ok())
        .ok_or(SdkError::Argument)
}

/// `scaas-ua`'s refusals by the SDK's names: a failed signature check is `OriginSignature`.
fn origin(e: scaas_ua::wallet::Error) -> SdkError {
    match e {
        scaas_ua::wallet::Error::ExternalSignature => SdkError::OriginSignature,
        other => SdkError::Ua(other),
    }
}

fn derivation_passphrase(p: &SecretBytes, optional: bool) -> Result<(), SdkError> {
    passphrase(p, |p| {
        roots::check_derivation_passphrase(p, optional)
            .map_err(|_| SdkError::DerivationPassphraseShort)
    })
}

impl Vault {
    /// Root (c)'s typed data for `account` and seed-set number `set`, as the JSON an EIP-712 wallet signs
    /// (`eth_signTypedData_v4`): built by `scaas-ua`, never by the app. `Argument` for a malformed account.
    pub fn key_derivation_typed_data(
        &self,
        account_hex: String,
        set: u32,
    ) -> Result<String, SdkError> {
        Ok(
            roots::key_derivation_typed_data(&account(&account_hex)?, set)?
                .to_value()
                .to_string(),
        )
    }

    /// A 64-byte EIP-2098 compact signature as the 65-byte `r ‖ s ‖ v` root (c) takes: the explicit conversion
    /// (`OriginSignature` for another length).
    pub fn signature_from_compact(
        &self,
        sig: Arc<SecretBytes>,
    ) -> Result<Arc<SecretBytes>, SdkError> {
        let full = sig.with(|b| {
            let c: &[u8; 64] = b.try_into().map_err(|_| SdkError::OriginSignature)?;
            Ok::<_, SdkError>(zeroize::Zeroizing::new(
                roots::signature_from_compact(c).to_vec(),
            ))
        })?;
        Ok(Arc::new(SecretBytes::from_zeroizing(full)?))
    }

    /// Root (c)'s new seed set (spec §6.6): the two signatures come from two requests to the wallet (one handle given for both is
    /// `Argument`). `OriginSignature` (the signatures differ, a wrong length, `r` / `s` / `v` out of
    /// range, recovering to another address), `DerivationPassphraseShort`, `VaultPassphraseWeak`, `SeedExists`, `LabelTaken`.
    pub async fn derive_from_signature(
        &self,
        req: DeriveFromSignature,
    ) -> Result<NewSeed, SdkError> {
        self.sdk.secrets_allowed()?;
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let acct = account(&req.account)?;
                precheck(&req.label, &req.vault_passphrase)?;
                derivation_passphrase(&req.derivation_passphrase, false)?;
                let (s1, s2, dp) = (req.signature1, req.signature2, req.derivation_passphrase);
                // nested `with`s on one secret would wait on its own lock: a secret given twice is read once. Review A2-5
                // (CLI-SDK-05: signed twice, the wallet's determinism test): one signature handle given as both is no second
                // signature, refused
                if Arc::ptr_eq(&dp, &s1) || Arc::ptr_eq(&dp, &s2) || Arc::ptr_eq(&s1, &s2) {
                    return Err(SdkError::Argument);
                }
                let set = req.set;
                let made = sdk
                    .heavy(move || {
                        let derive = |a: &[u8], b: &[u8]| {
                            passphrase(&dp, |p| {
                                Wallet::from_eoa_signature(&acct, set, a, b, p).map_err(origin)
                            })
                        };
                        s1.with2(&s2, derive)
                    })
                    .await?;
                store(&sdk, made, req.label, "eoa-sig", req.vault_passphrase).await
            })
            .await
    }

    /// Root (d)'s new seed set (spec §6.6): a secp256k1 EVM key only. `Argument` (another network, not 32 bytes, outside
    /// [1, n)), `DerivationPassphraseShort`, `VaultPassphraseWeak`, `SeedExists`, `LabelTaken`.
    pub async fn derive_from_key(&self, req: DeriveFromKey) -> Result<NewSeed, SdkError> {
        self.sdk.secrets_allowed()?;
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                if req.network != "evm" {
                    return Err(SdkError::Argument);
                }
                precheck(&req.label, &req.vault_passphrase)?;
                derivation_passphrase(&req.derivation_passphrase, true)?;
                let (key, dp, index) = (req.key, req.derivation_passphrase, req.index);
                let made = sdk
                    .heavy(move || {
                        key.with2(&dp, |k, p| {
                            let k: &[u8; 32] = k.try_into().map_err(|_| SdkError::Argument)?;
                            let p = std::str::from_utf8(p).map_err(|_| SdkError::Argument)?;
                            Ok(Wallet::from_private_key(k, p, index)?)
                        })
                    })
                    .await?;
                store(&sdk, made, req.label, "raw-key", req.vault_passphrase).await
            })
            .await
    }
}

/// The label and the new vault passphrase, checked before the Argon2id runs.
fn precheck(label: &str, pass: &SecretBytes) -> Result<(), SdkError> {
    if !super::keystore::new_label_ok(label) {
        return Err(SdkError::Argument);
    }
    passphrase(pass, |p| {
        scaas_ua::wallet::check_passphrase(p).map_err(|_| SdkError::VaultPassphraseWeak)
    })
}

/// The new classical-rooted seed stored as `generate` stores one.
async fn store(
    sdk: &Arc<crate::Sdk>,
    (wallet, backup): (Wallet, scaas_ua::wallet::SeedBackup),
    label: String,
    origin: &str,
    pass: Arc<SecretBytes>,
) -> Result<NewSeed, SdkError> {
    let entry = new_entry(
        sdk,
        wallet,
        label,
        origin,
        "classical-rooted",
        vec![],
        "pending",
        pass,
    )
    .await?;
    let info = store_new(sdk, entry).await?;
    Ok(NewSeed {
        info,
        backup: Arc::new(SeedBackup(Mutex::new(backup))),
    })
}
