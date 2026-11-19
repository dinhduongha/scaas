// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Passkey and platform unlock (spec §6.10, CLI-SDK-06): vault v1's PRF envelope on every vault of a seed, one credential and
//! one per-seed salt, so one assertion (or one platform secret) opens them all. The output is written by the app's
//! `Authenticator` into a `SecretBytes` the SDK passes in, and only reaches `scaas-ua`. An answer without a PRF output is
//! `AuthenticatorRefused`; the passphrase still opens. Changes keep the data key (CLI-UAL-19): a passphrase change re-wraps the
//! pin envelope, removing the PRF unlock drops the envelope; neither revokes an earlier copy.

use super::keystore::SeedEntry;
use super::seeds::{passphrase, passphrases};
use super::unlock::{Key, Unlock};
use super::Vault;
use crate::error::SdkError;
use crate::events::Event;
use crate::platform::{AssertionRequest, KeyPolicy};
use crate::Sdk;
use scaas_ua::wallet::{PrfEnvelope, SecretBytes, Vault as V1};
use std::collections::BTreeMap;
use std::sync::Arc;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
        .collect()
}

fn random32() -> Result<Vec<u8>, SdkError> {
    let mut b = vec![0u8; 32];
    getrandom::getrandom(&mut b).map_err(|_| SdkError::Internal)?;
    Ok(b)
}

/// Every vault of `e`, parsed.
fn vaults(e: &SeedEntry) -> Result<BTreeMap<String, V1>, SdkError> {
    e.vaults
        .iter()
        .map(|(k, t)| {
            Ok((
                k.clone(),
                V1::from_json(t.as_bytes()).map_err(|_| SdkError::VaultFormat)?,
            ))
        })
        .collect()
}

/// The prefix of a platform unlock's key handle (a passkey's credential is hex).
pub(crate) const PLATFORM_PREFIX: &str = "scaas.unlock.";

/// The platform key's handle of a seed's platform unlock.
fn platform_handle(seed: &str) -> String {
    format!("{PLATFORM_PREFIX}{seed}")
}

#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
impl Sdk {
    /// The secret `unlock` opens `e` with: the passphrase as given; for `Passkey` / `Platform` the seed vault's PRF envelope's
    /// credential and salt asked of the authenticator, its output written into a fresh 32-byte secret.
    pub(crate) async fn key_of(&self, e: &SeedEntry, unlock: Unlock) -> Result<Key, SdkError> {
        let passkey = match unlock {
            Unlock::Passphrase(p) => return Ok(Key::Pass(p)),
            Unlock::Passkey => true,
            Unlock::Platform => false,
        };
        let auth = self
            .authenticator
            .clone()
            .ok_or(SdkError::AuthenticatorRefused)?;
        let seed = V1::from_json(
            e.vaults
                .get("seed")
                .ok_or(SdkError::VaultFormat)?
                .as_bytes(),
        )
        .map_err(|_| SdkError::VaultFormat)?;
        let (credential, salt) = seed.prf_params().ok_or(SdkError::AuthenticatorRefused)?;
        let out = Arc::new(SecretBytes::new(32)?);
        if passkey {
            let allow = vec![unhex(&credential).ok_or(SdkError::VaultFormat)?];
            let req = AssertionRequest {
                rp_id: self.rp_id()?,
                challenge: random32()?,
                allow,
                prf_salt: Some(salt),
            };
            let a = auth
                .get_assertion(req, out.clone())
                .await
                .map_err(|_| SdkError::AuthenticatorRefused)?;
            if !a.prf {
                return Err(SdkError::AuthenticatorRefused);
            }
        } else {
            auth.platform_secret(credential, salt, "unlock".into(), None, out.clone())
                .await
                .map_err(|_| SdkError::AuthenticatorRefused)?;
        }
        Ok(Key::Prf(out))
    }

    fn rp_id(&self) -> Result<String, SdkError> {
        self.rp_id.clone().ok_or(SdkError::AuthenticatorRefused)
    }

    /// The open seed's wallet holds each label vault's envelopes from when it opened it (for the same-DEK re-seal, spec
    /// §6.10): after a rewrite it reopens the stored manifest with `p`, so the next re-seal keeps the new envelopes.
    async fn refresh(&self, seed: &str, p: Arc<SecretBytes>) -> Result<(), SdkError> {
        let Ok(open) = self.open_seed(seed) else {
            return Ok(());
        };
        let e = self.entry(seed).await?;
        self.heavy(move || {
            let m = V1::from_json(
                e.vaults
                    .get("manifest")
                    .ok_or(SdkError::VaultFormat)?
                    .as_bytes(),
            )
            .map_err(|_| SdkError::VaultFormat)?;
            passphrase(&p, |p| {
                Ok(open
                    .wallet
                    .open_label_vault(&m, scaas_ua::wallet::Unlock::VaultPassphrase(p))?)
            })
        })
        .await
    }

    /// Rewrites every vault of seed `seed` by `f`, and the index MAC, which covers the vault texts (owner 2026-11-19, T13b
    /// ruling 3): under the open seed's wallet, else under the wallet `pass` opens from the seed vault (`WalletLocked` with
    /// neither).
    async fn rewrite_vaults(
        &self,
        seed: &str,
        pass: Option<Arc<SecretBytes>>,
        f: impl Fn(&V1) -> Result<V1, SdkError> + Send + Sync + 'static,
    ) -> Result<(), SdkError> {
        let e = self.entry(seed).await?;
        let old = e.vaults.clone();
        let open = self.open_seed(seed).ok();
        if open.is_none() && pass.is_none() {
            return Err(SdkError::Ua(scaas_ua::wallet::Error::WalletLocked));
        }
        let f = Arc::new(f);
        let (new, index_mac) = self
            .heavy({
                let f = f.clone();
                move || {
                    let new = vaults(&e)?
                        .iter()
                        .map(|(k, v)| Ok((k.clone(), f(v)?.to_json())))
                        .collect::<Result<BTreeMap<_, _>, SdkError>>()?;
                    let mut ne = e.clone();
                    ne.vaults = new.clone();
                    let index_mac = match (&open, &pass) {
                        (Some(o), _) => super::seeds::mac(&o.wallet, &ne)?,
                        (None, Some(p)) => {
                            let seed_vault = super::unlock::vault_of(&e, "seed")?;
                            let w = passphrase(p, |p| {
                                Ok(scaas_ua::wallet::Wallet::open_vault(
                                    &seed_vault,
                                    scaas_ua::wallet::Unlock::VaultPassphrase(p),
                                    "",
                                )?)
                            })?;
                            let m = super::seeds::mac(&w, &ne);
                            w.lock();
                            m?
                        }
                        (None, None) => return Err(SdkError::Internal),
                    };
                    Ok((new, index_mac))
                }
            })
            .await?;
        let ks = self
            .keystore
            .update(|ks| {
                let e = ks
                    .seeds
                    .iter_mut()
                    .find(|s| s.id == seed)
                    .ok_or(SdkError::SeedUnknown)?;
                if e.vaults != old {
                    return Err(SdkError::StoreConflict);
                }
                e.vaults = new.clone();
                e.index_mac = index_mac.clone();
                Ok(())
            })
            .await?;
        self.emit(Event::KeystoreChanged { rev: ks.rev });
        Ok(())
    }
}

impl Vault {
    /// Adds a passkey PRF envelope to every vault of the seed (one credential, one fresh per-seed salt, one assertion),
    /// opened by the vault passphrase once. `AuthenticatorRefused` for no authenticator, no RP ID or an answer without a PRF
    /// output (nothing written).
    pub async fn enable_passkey_unlock(
        &self,
        seed: String,
        vault_passphrase: Arc<SecretBytes>,
    ) -> Result<(), SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let auth = sdk
                    .authenticator
                    .clone()
                    .ok_or(SdkError::AuthenticatorRefused)?;
                let salt = random32()?;
                let out = Arc::new(SecretBytes::new(32)?);
                let req = AssertionRequest {
                    rp_id: sdk.rp_id()?,
                    challenge: random32()?,
                    allow: vec![],
                    prf_salt: Some(salt.clone()),
                };
                let a = auth
                    .get_assertion(req, out.clone())
                    .await
                    .map_err(|_| SdkError::AuthenticatorRefused)?;
                if !a.prf {
                    return Err(SdkError::AuthenticatorRefused);
                }
                enable(
                    &sdk,
                    &seed,
                    out,
                    hex(&a.credential_id),
                    salt,
                    vault_passphrase,
                )
                .await
            })
            .await
    }

    /// Adds a platform-secret envelope (a Keychain / Android Keystore key under `policy`, research decision 8) to every vault of
    /// the seed, opened by the vault passphrase once.
    pub async fn enable_platform_unlock(
        &self,
        seed: String,
        vault_passphrase: Arc<SecretBytes>,
        policy: KeyPolicy,
    ) -> Result<(), SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let auth = sdk
                    .authenticator
                    .clone()
                    .ok_or(SdkError::AuthenticatorRefused)?;
                let (salt, handle) = (random32()?, platform_handle(&seed));
                let out = Arc::new(SecretBytes::new(32)?);
                auth.platform_secret(
                    handle.clone(),
                    salt.clone(),
                    "enable unlock".into(),
                    Some(policy),
                    out.clone(),
                )
                .await
                .map_err(|_| SdkError::AuthenticatorRefused)?;
                enable(&sdk, &seed, out, handle, salt, vault_passphrase).await
            })
            .await
    }

    /// Drops the PRF envelope of every vault of the seed (the passphrase still opens; an earlier copy keeps its envelope). The
    /// seed must be unlocked (`WalletLocked`): the index MAC covers the vault texts (T13b ruling 3), so its wallet rewrites it;
    /// then the seed is locked (its wallet holds the old envelopes, which a later re-seal would write back).
    pub async fn disable_prf_unlock(&self, seed: String) -> Result<(), SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                sdk.rewrite_vaults(&seed, None, |v| Ok(v.without_prf()))
                    .await?;
                sdk.lock_seed(&seed).await;
                Ok(())
            })
            .await
    }

    /// A new vault passphrase for every vault of the seed: the pin envelope re-wrapped, the data key kept (CLI-UAL-19), so the PRF
    /// envelope still opens. `VaultOpen` for a wrong old one, `VaultPassphraseWeak` for a new one under vault v1's rule.
    pub async fn change_passphrase(
        &self,
        seed: String,
        old: Arc<SecretBytes>,
        new: Arc<SecretBytes>,
    ) -> Result<(), SdkError> {
        passphrase(&new, |p| {
            scaas_ua::wallet::check_passphrase(p).map_err(|_| SdkError::VaultPassphraseWeak)
        })?;
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let (n2, o2) = (new.clone(), old.clone());
                sdk.rewrite_vaults(&seed, Some(o2), move |v| {
                    passphrases(&old, &n2, |o, n| Ok(v.rewrap_pin(o, n)?))
                })
                .await?;
                sdk.refresh(&seed, new).await
            })
            .await
    }
}

async fn enable(
    sdk: &Arc<Sdk>,
    seed: &str,
    out: Arc<SecretBytes>,
    credential: String,
    salt: Vec<u8>,
    pass: Arc<SecretBytes>,
) -> Result<(), SdkError> {
    let p2 = pass.clone();
    sdk.rewrite_vaults(seed, Some(pass.clone()), move |v| {
        out.with(|b| {
            let output: &[u8; 32] = b.try_into().map_err(|_| SdkError::AuthenticatorRefused)?;
            let env = PrfEnvelope {
                output,
                credential_id: &credential,
                salt: &salt,
            };
            passphrase(&p2, |p| Ok(v.enable_prf(p, &env)?))
        })
    })
    .await?;
    sdk.refresh(seed, pass).await
}
