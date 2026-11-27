// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Unlock and lock (spec §6.10) and hidden sets (§6.5). Unlock opens the `seed` vault through `scaas-ua`, checks the entry's
//! words and its index MAC (§6.2: `KeystoreMismatch`, the seed stays locked), then opens its label vaults. A hidden set is a
//! second, session-only wallet of the same vault under a BIP-39 passphrase: nothing about it is written or emitted.

use super::keystore::SeedEntry;
use super::seeds::{info, mac_ok, passphrase, passphrases, OpenSeed};
use super::Vault;
use crate::error::SdkError;
use crate::events::Event;
use crate::Sdk;
use scaas_ua::wallet::{SecretBytes, Vault as V1, Wallet};
use std::collections::BTreeSet;
use std::sync::{Arc, PoisonError};

/// How a seed opens (spec §6.10). `Passkey` and `Platform` go through the seed's PRF envelope (plan T7).
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", serde(deny_unknown_fields))]
pub enum Unlock {
    Passphrase(#[cfg_attr(feature = "wasm", serde(with = "crate::wasm::handle"))] Arc<SecretBytes>),
    Passkey,
    Platform,
}

/// A hidden set: its own session id, used in every reference to it; never written.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct SessionSet {
    pub id: String,
}

pub(crate) fn vault_of(e: &SeedEntry, label: &str) -> Result<V1, SdkError> {
    let t = e.vaults.get(label).ok_or(SdkError::VaultFormat)?;
    V1::from_json(t.as_bytes()).map_err(|err| match err {
        scaas_ua::wallet::Error::VaultVersion => SdkError::Ua(err),
        _ => SdkError::VaultFormat,
    })
}

/// The secret a vault opens with: its passphrase, or the 32-byte PRF output / platform secret of its PRF envelope.
pub(crate) enum Key {
    Pass(Arc<SecretBytes>),
    Prf(Arc<SecretBytes>),
}

/// `f` with the `scaas-ua` unlock of `k` (`AuthenticatorRefused` for a PRF secret that is not 32 bytes).
pub(crate) fn with_key<R>(
    k: &Key,
    f: impl FnOnce(scaas_ua::wallet::Unlock) -> Result<R, SdkError>,
) -> Result<R, SdkError> {
    match k {
        Key::Pass(p) => passphrase(p, |p| f(scaas_ua::wallet::Unlock::VaultPassphrase(p))),
        Key::Prf(s) => s.with(|b| {
            let out: &[u8; 32] = b.try_into().map_err(|_| SdkError::AuthenticatorRefused)?;
            f(scaas_ua::wallet::Unlock::Prf(out))
        }),
    }
}

/// Opens `e`'s seed vault (and, for the main set, checks its words and MAC and opens its label vaults).
fn open_entry(e: &SeedEntry, key: &Key, bip39: Option<&SecretBytes>) -> Result<Wallet, SdkError> {
    let seed = vault_of(e, "seed")?;
    // the vault and the BIP-39 passphrase: two secrets, or one given for both (read once)
    if let (Key::Pass(p), Some(b)) = (key, bip39) {
        return passphrases(p, b, |vp, bp| {
            Ok(Wallet::open_vault(
                &seed,
                scaas_ua::wallet::Unlock::VaultPassphrase(vp),
                bp,
            )?)
        });
    }
    with_key(key, |unlock| match bip39 {
        Some(b) => passphrase(b, |bp| Ok(Wallet::open_vault(&seed, unlock, bp)?)),
        None => {
            let w = Wallet::open_vault(&seed, unlock, "")?;
            if w.word_count()? != e.words {
                return Err(SdkError::VaultFormat);
            }
            if !mac_ok(&w, e)? {
                return Err(SdkError::KeystoreMismatch);
            }
            // a PRF unlock opens the manifest and keeps the PRF key; the other vaults open on first use (owner 2026-11-18 (b))
            let prf = matches!(unlock, scaas_ua::wallet::Unlock::Prf(_));
            for label in e.vaults.keys().filter(|l| l.as_str() != "seed") {
                if prf && label.as_str() != "manifest" {
                    continue;
                }
                w.open_label_vault(&vault_of(e, label)?, unlock)?;
            }
            // the output already borrowed by `with_key` (a second `with` on the same secret would wait on itself)
            if let scaas_ua::wallet::Unlock::Prf(out) = unlock {
                w.retain_prf_key(out)?;
            }
            Ok(w)
        }
    })
}

impl Vault {
    /// Unlocks the seed by its vault passphrase (every vault opened now, the passphrase not kept) or by its passkey / platform
    /// PRF envelope (the seed and manifest vaults opened, the PRF key kept for the others' first use; spec §6.10, owner
    /// 2026-11-18): `VaultOpen` for a wrong secret, `AuthenticatorRefused` (no authenticator, no envelope, no PRF output),
    /// `KeystoreMismatch` when the index MAC does not verify (the seed stays locked, the event says so), `SeedUnknown`. A seed
    /// already open stays as it is (`Ok`, nothing asked): one session per seed.
    pub async fn unlock(&self, seed: String, unlock: Unlock) -> Result<(), SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                // review T26 A-4 (CLI-SDK-06): an open seed keeps its one session, so `lock` locks the wallet every call holds
                if sdk.open_seed(&seed).is_ok() {
                    return Ok(());
                }
                let e = sdk.entry(&seed).await?;
                let key = sdk.key_of(&e, unlock).await?;
                let id = e.id.clone();
                let r = sdk.heavy(move || open_entry(&e, &key, None)).await;
                let wallet = match r {
                    Err(SdkError::KeystoreMismatch) => {
                        sdk.emit(Event::KeystoreMismatch { seed: id });
                        return Err(SdkError::KeystoreMismatch);
                    }
                    other => other?,
                };
                {
                    let mut open = sdk.open.lock().unwrap_or_else(PoisonError::into_inner);
                    // two unlocks at once: the first session stays, the second wallet is locked unused
                    if open.contains_key(&id) {
                        drop(open);
                        wallet.lock();
                        return Ok(());
                    }
                    open.insert(id.clone(), Arc::new(OpenSeed { wallet }));
                }
                sdk.emit(Event::SeedUnlocked { seed: id });
                Ok(())
            })
            .await
    }

    /// Opens a hidden set of the seed (spec §6.5): a second wallet of the same vault under `bip39_passphrase`, with its own random
    /// id; nothing written, no event, no row. A wrong BIP-39 passphrase is not an error (other addresses).
    pub async fn open_hidden(
        &self,
        seed: String,
        unlock: Unlock,
        bip39_passphrase: Arc<SecretBytes>,
    ) -> Result<SessionSet, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let e = sdk.entry(&seed).await?;
                let key = sdk.key_of(&e, unlock).await?;
                let wallet = sdk
                    .heavy(move || open_entry(&e, &key, Some(&bip39_passphrase)))
                    .await?;
                let id = super::seeds::uuid4()?;
                sdk.hidden
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(id.clone(), (seed, Arc::new(OpenSeed { wallet })));
                Ok(SessionSet { id })
            })
            .await
    }

    /// Locks the seed (and its hidden sets): every handle revoked, new calls refused at once; the hidden sets' operations not yet
    /// terminal come back (none are followed in memory before plan T10).
    pub async fn lock(&self, seed: String) -> Vec<String> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move { Ok(sdk.lock_seed(&seed).await) })
            .await
            .unwrap_or_default()
    }

    /// Locks every seed: each seed with an open main set or a hidden set (one `lock` each), so a hidden set opened on a locked
    /// seed is locked too.
    pub async fn lock_all(&self) -> Vec<String> {
        let mut ids: BTreeSet<String> = self
            .sdk
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .cloned()
            .collect();
        ids.extend(
            self.sdk
                .hidden
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .values()
                .map(|(seed, _)| seed.clone()),
        );
        let mut out = vec![];
        for id in ids {
            out.extend(self.lock(id).await);
        }
        out
    }

    /// The seed's info as listed now.
    pub async fn seed(&self, seed: String) -> Result<super::SeedInfo, SdkError> {
        let e = self.sdk.entry(&seed).await?;
        let unlocked = self.sdk.open_seed(&seed).is_ok();
        Ok(info(
            &e,
            unlocked,
            unlocked && super::seeds::rows_verified(&self.sdk, &e),
        ))
    }
}

#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
impl Sdk {
    /// The stored keystore; an older container put back (the anchor's verdict) is shown as `Event::KeystoreRollback` on every
    /// read (closing review P2-2; spec §6.3), never fatal.
    pub(crate) async fn load_keystore(&self) -> Result<super::Loaded, SdkError> {
        let l = self.keystore.load().await?;
        if l.rollback {
            self.emit(Event::KeystoreRollback);
        }
        Ok(l)
    }

    /// The entry of `seed` in the stored keystore (`SeedUnknown`).
    pub(crate) async fn entry(&self, seed: &str) -> Result<SeedEntry, SdkError> {
        let ks = self.load_keystore().await?.keystore;
        ks.seeds
            .into_iter()
            .find(|s| s.id == seed)
            .ok_or(SdkError::SeedUnknown)
    }

    /// Opens label vault `label` of the open seed on its first use (spec §6.10, owner 2026-11-18 (b)): a no-op when it is open;
    /// else through the PRF key the unlock kept (`Argument` when the seed opened by passphrase, which opens every vault at
    /// unlock). `WalletLocked`, `VaultFormat` for a label the entry has not.
    #[cfg_attr(
        not(any(test, feature = "evm")),
        expect(
            dead_code,
            reason = "its callers sign with an imported key (`wallet`, T12) or a pqz-held one (T16)"
        )
    )]
    pub(crate) async fn open_on_use(&self, seed: &str, label: &str) -> Result<(), SdkError> {
        let open = self.open_seed(seed)?;
        if open.wallet.label_open(label) {
            return Ok(());
        }
        let v = vault_of(&self.entry(seed).await?, label)?;
        Ok(open.wallet.open_label_vault_retained(&v)?)
    }

    /// The open main set of `seed`, or `WalletLocked`.
    pub(crate) fn open_seed(&self, seed: &str) -> Result<Arc<OpenSeed>, SdkError> {
        self.open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(seed)
            .cloned()
            .ok_or(SdkError::Ua(scaas_ua::wallet::Error::WalletLocked))
    }

    /// Takes the seed and its hidden sets out of the session first (new calls are `WalletLocked` at once), then locks their
    /// wallets (waiting for leases in flight) off the async workers.
    pub(crate) async fn lock_seed(&self, seed: &str) -> Vec<String> {
        let main = self
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(seed);
        let hidden: Vec<Arc<OpenSeed>> = {
            let mut h = self.hidden.lock().unwrap_or_else(PoisonError::into_inner);
            let ids: Vec<String> = h
                .iter()
                .filter(|(_, (p, _))| p == seed)
                .map(|(k, _)| k.clone())
                .collect();
            ids.iter()
                .filter_map(|k| h.remove(k))
                .map(|(_, w)| w)
                .collect()
        };
        let had_hidden = !hidden.is_empty();
        let locked = main.is_some();
        let all: Vec<Arc<OpenSeed>> = main.into_iter().chain(hidden).collect();
        #[cfg(not(target_arch = "wasm32"))]
        let _ = tokio::task::spawn_blocking(move || all.iter().for_each(|s| s.wallet.lock())).await;
        #[cfg(target_arch = "wasm32")]
        all.iter().for_each(|s| s.wallet.lock());
        if had_hidden {
            self.emit(Event::HiddenOpsAbandoned { count: 0 });
        }
        if locked {
            self.emit(Event::SeedLocked {
                seed: seed.to_owned(),
            });
        }
        vec![]
    }
}
