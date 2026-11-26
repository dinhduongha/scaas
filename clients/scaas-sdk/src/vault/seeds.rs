// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Seeds (spec §6.4): list, generate. Every key, vault, fingerprint and MAC through `scaas-ua`; the SDK keeps the container's
//! entry and the session's open wallets.

use super::keystore::{accounts_json, new_label_ok, SeedEntry};
use crate::error::SdkError;
use crate::events::Event;
use crate::Sdk;
use scaas_ua::wallet::{IndexFields, SecretBytes, Wallet};
use std::sync::{Arc, Mutex, PoisonError};
use zeroize::Zeroizing;

/// A seed as listed: public fields of the container entry, and whether it is unlocked (its MAC checked) in this session.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct SeedInfo {
    pub id: String,
    pub label: String,
    pub words: u32,
    pub origin: String,
    pub class: String,
    pub warnings: Vec<String>,
    pub backup: String,
    pub unlocked: bool,
    /// the index MAC of this entry was checked in this session (spec §6.2)
    pub verified: bool,
}

/// `vault.generate`'s request: the seed's label and its new vault passphrase (vault v1's rule).
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", serde(deny_unknown_fields))]
pub struct Generate {
    pub label: String,
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::handle"))]
    pub vault_passphrase: Arc<SecretBytes>,
}

/// A new seed and its one reveal.
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", serde(deny_unknown_fields))]
pub struct NewSeed {
    pub info: SeedInfo,
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::handle"))]
    pub backup: Arc<SeedBackup>,
}

/// The words of a seed made here: revealed once, a three-word check, then forgotten (`scaas-ua`'s `SeedBackup`, CLI-SGN-11).
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SeedBackup(pub(crate) Mutex<scaas_ua::wallet::SeedBackup>);

#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
impl SeedBackup {
    fn with<R>(&self, f: impl FnOnce(&mut scaas_ua::wallet::SeedBackup) -> R) -> R {
        f(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
    /// The words, once (`Argument` after), as a secret the caller reads through the copy call.
    pub fn reveal(&self) -> Result<Arc<SecretBytes>, SdkError> {
        let words = self.with(|b| b.reveal())?;
        Ok(Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(
            words.as_bytes().to_vec(),
        ))?))
    }
    /// Three positions to ask (1-based).
    pub fn challenge(&self) -> Result<Vec<u32>, SdkError> {
        Ok(self
            .with(|b| b.challenge())?
            .iter()
            .map(|p| *p as u32)
            .collect())
    }
    /// Whether `answers` (the three words, space-separated, as a secret) are the asked ones.
    pub fn verify(&self, answers: Arc<SecretBytes>) -> Result<bool, SdkError> {
        let text = answers.with(|b| std::str::from_utf8(b).map(|s| Zeroizing::new(s.to_owned())));
        let text = text.map_err(|_| SdkError::Argument)?;
        let words: Vec<&str> = text.split_whitespace().collect();
        Ok(self.with(|b| b.verify(&words))?)
    }
}

/// A seed open in this session: its main set's wallet.
pub(crate) struct OpenSeed {
    pub(crate) wallet: Wallet,
}

/// The seed module (spec §6).
#[derive(Clone)]
pub struct Vault {
    pub(crate) sdk: Arc<Sdk>,
}

/// A UUID v4 in lower case, from the OS generator (an id, not a key).
pub(crate) fn uuid4() -> Result<String, SdkError> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|_| SdkError::Internal)?;
    let u = uuid::Builder::from_random_bytes(b).into_uuid();
    Ok(u.hyphenated().to_string())
}

pub(crate) fn passphrase<R>(
    s: &SecretBytes,
    f: impl FnOnce(&str) -> Result<R, SdkError>,
) -> Result<R, SdkError> {
    s.with(|b| f(std::str::from_utf8(b).map_err(|_| SdkError::Argument)?))
}

/// `f` over two passphrases, read through `SecretBytes::with2` (one secret given for both is read once).
pub(crate) fn passphrases<R>(
    a: &SecretBytes,
    b: &SecretBytes,
    f: impl FnOnce(&str, &str) -> Result<R, SdkError>,
) -> Result<R, SdkError> {
    a.with2(b, |x, y| {
        let utf8 = |s| std::str::from_utf8(s).map_err(|_| SdkError::Argument);
        f(utf8(x)?, utf8(y)?)
    })
}

pub(crate) fn info(e: &SeedEntry, unlocked: bool, verified: bool) -> SeedInfo {
    SeedInfo {
        id: e.id.clone(),
        label: e.label.clone(),
        words: e.words,
        origin: e.origin.clone(),
        class: e.class.clone(),
        warnings: e.warnings.clone(),
        backup: e.backup.clone(),
        unlocked,
        verified,
    }
}

impl Vault {
    /// Whether the stored keystore is older than its anchor (an earlier copy put back, spec §6.3): an app checks it after
    /// `Sdk::open`, where no subscriber can see the event yet; every later read emits `Event::KeystoreRollback` while it holds.
    pub async fn keystore_rollback(&self) -> Result<bool, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move { Ok(sdk.load_keystore().await?.rollback) })
            .await
    }

    /// Accepts the stored keystore as it is after a `KeystoreRollback` (spec §6.3, review A-6): the user chose the older copy
    /// deliberately; the anchor is rewritten over it and writes resume. While a rollback holds, every write of the keystore is
    /// `KeystoreRollback` and changes nothing.
    pub async fn accept_rollback(&self) -> Result<(), SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move { sdk.keystore.accept_rollback().await })
            .await
    }

    /// The memory protection of an unlocked seed's key arena now (`mlock`, no-dump; best effort, closing review P3): an app can
    /// tell whether the retained PRF key and the opened keys are locked in RAM. `WalletLocked` for a locked seed.
    pub fn memory_protection(
        &self,
        seed: String,
    ) -> Result<scaas_ua::wallet::MemoryProtection, SdkError> {
        Ok(self.sdk.open_seed(&seed)?.wallet.memory_protection())
    }

    /// The seeds of the keystore, in display order.
    pub async fn seeds(&self) -> Result<Vec<SeedInfo>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let ks = sdk.load_keystore().await?.keystore;
                Ok(ks
                    .seeds
                    .iter()
                    .map(|e| {
                        let unlocked = sdk.open_seed(&e.id).is_ok();
                        info(e, unlocked, unlocked && rows_verified(&sdk, e))
                    })
                    .collect())
            })
            .await
    }

    /// A new 24-word seed (spec §6.4): 32 bytes of the OS generator inside `scaas-ua`, its seed and manifest vaults sealed
    /// under the vault passphrase, its entry written with `backup: pending` before the backup is handed out. `Argument` for a
    /// label outside its rule, `LabelTaken`, `VaultPassphraseWeak`; the store's errors as `VaultIo` / `StoreConflict`.
    pub async fn generate(&self, req: Generate) -> Result<NewSeed, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                if !new_label_ok(&req.label) {
                    return Err(SdkError::Argument);
                }
                let pass = req.vault_passphrase;
                passphrase(&pass, |p| {
                    scaas_ua::wallet::check_passphrase(p).map_err(|_| SdkError::VaultPassphraseWeak)
                })?;
                let (wallet, backup) = Wallet::generate()?;
                let entry = new_entry(
                    &sdk,
                    wallet,
                    req.label,
                    "generated",
                    "full",
                    vec![],
                    "pending",
                    pass,
                )
                .await?;
                let info = store_new(&sdk, entry).await?;
                Ok(NewSeed {
                    info,
                    backup: Arc::new(SeedBackup(Mutex::new(backup))),
                })
            })
            .await
    }
}

/// The entry's index MAC under its wallet (spec §6.2), 64 hex digits.
pub(crate) fn mac(w: &Wallet, e: &SeedEntry) -> Result<String, SdkError> {
    let accounts = accounts_json(&e.accounts);
    Ok(w.index_mac(&fields_of(e, &accounts))?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Review T26 A-1 (spec §6.2): `e` as stored verifies under `w` before anything changes it and its MAC is written again
/// (`KeystoreMismatch` otherwise): a writer never re-signs an entry changed behind the SDK.
pub(crate) fn stored_ok(w: &Wallet, e: &SeedEntry) -> Result<(), SdkError> {
    if mac_ok(w, e)? {
        Ok(())
    } else {
        Err(SdkError::KeystoreMismatch)
    }
}

/// Review T26 A-1: a writer's `KeystoreMismatch` emits the event and locks the seed, as at unlock.
pub(crate) async fn on_mismatch<T>(
    sdk: &Sdk,
    seed: &str,
    r: Result<T, SdkError>,
) -> Result<T, SdkError> {
    if let Err(SdkError::KeystoreMismatch) = &r {
        sdk.emit(Event::KeystoreMismatch { seed: seed.into() });
        sdk.lock_seed(seed).await;
    }
    r
}

/// Review T26 A-2 (spec §6.2): whether the rows of `e`, as just read, may be trusted: its seed is open and `e` verifies under
/// its wallet. A mismatch emits `KeystoreMismatch` and the rows read unverified.
pub(crate) fn rows_verified(sdk: &Sdk, e: &SeedEntry) -> bool {
    let Ok(open) = sdk.open_seed(&e.id) else {
        return false;
    };
    let ok = mac_ok(&open.wallet, e).unwrap_or(false);
    if !ok {
        sdk.emit(Event::KeystoreMismatch { seed: e.id.clone() });
    }
    ok
}

/// Whether `e`'s stored index MAC verifies under the open wallet, compared in constant time by `scaas-ua` (closing review P3);
/// a stored MAC that is not 64 hex digits does not.
pub(crate) fn mac_ok(w: &Wallet, e: &SeedEntry) -> Result<bool, SdkError> {
    let accounts = accounts_json(&e.accounts);
    let mut stored = [0u8; 32];
    for (i, b) in stored.iter_mut().enumerate() {
        match e
            .index_mac
            .get(2 * i..2 * i + 2)
            .map(|h| u8::from_str_radix(h, 16))
        {
            Some(Ok(x)) if e.index_mac.len() == 64 => *b = x,
            _ => return Ok(false),
        }
    }
    Ok(w.verify_index_mac(&fields_of(e, &accounts), &stored)?)
}

fn fields_of<'a>(e: &'a SeedEntry, accounts: &'a str) -> IndexFields<'a> {
    IndexFields {
        id: &e.id,
        label: &e.label,
        words: e.words,
        fingerprint: &e.fingerprint,
        origin: &e.origin,
        class: &e.class,
        warnings: &e.warnings,
        backup: &e.backup,
        accounts_json: accounts,
        vaults: &e.vaults,
    }
}

/// `vault.import_words`'s request: 12 to 24 English words as a secret.
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", serde(deny_unknown_fields))]
pub struct ImportWords {
    pub label: String,
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::handle"))]
    pub words: Arc<SecretBytes>,
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::handle"))]
    pub vault_passphrase: Arc<SecretBytes>,
}

/// `vault.derive_child`'s request: a stored seed (never a hidden set), the child's label and vault passphrase.
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", serde(deny_unknown_fields))]
pub struct DeriveChild {
    pub parent: String,
    pub label: String,
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::handle"))]
    pub vault_passphrase: Arc<SecretBytes>,
}

/// `vault.import_key`'s request (spec §6.7): a classical private key of `network` (32 bytes) as a leaf of a seed, sealed as the
/// new label vault `native-import:<network>:<n>` under the seed's vault passphrase.
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", serde(deny_unknown_fields))]
pub struct ImportKey {
    pub seed: String,
    /// `ua-rs`'s network name (`evm`, `cosmos`, `hedera_ecdsa`, `hedera_ed25519`, `sui`, `stellar`, `ton`, `aptos`, `solana`)
    pub network: String,
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::handle"))]
    pub secret: Arc<SecretBytes>,
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::handle"))]
    pub vault_passphrase: Arc<SecretBytes>,
}

/// An imported key's place: its network and its number `n` (the vault `native-import:<network>:<n>`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct ImportedKey {
    pub network: String,
    pub index: u32,
}

/// `Ok` when `p` opens the seed's `seed` vault (`VaultOpen` otherwise): every vault of a seed opens with one passphrase.
fn seed_passphrase(seed_vault: &scaas_ua::wallet::Vault, p: &str) -> Result<(), SdkError> {
    let check = Wallet::open_vault(seed_vault, scaas_ua::wallet::Unlock::VaultPassphrase(p), "")?;
    check.lock();
    Ok(())
}

/// The first marker of `remove`.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct ConfirmRemove {}
/// The second marker of `remove`, for a seed whose backup is `pending`.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct ConfirmRemoveUnbacked {}

/// `vault.remove`'s request.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", serde(deny_unknown_fields))]
pub struct Remove {
    pub seed: String,
    pub confirm: ConfirmRemove,
    pub unbacked: Option<ConfirmRemoveUnbacked>,
}

impl Vault {
    /// A BIP-85 child of the parent's main set (spec §6.4): 24 words at the parent's high-water mark `bip85Next`, raised and
    /// persisted in the parent's manifest (re-sealed under its same DEK) with the child's entry in one write; `class` and
    /// `warnings` inherited, `backup: pending`; the parent unlocked (`WalletLocked`), `SeedExists` (the index used up all the same:
    /// the raised mark is written), `LabelTaken`.
    pub async fn derive_child(&self, req: DeriveChild) -> Result<NewSeed, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                if !new_label_ok(&req.label) {
                    return Err(SdkError::Argument);
                }
                let pass = req.vault_passphrase;
                passphrase(&pass, |p| {
                    scaas_ua::wallet::check_passphrase(p).map_err(|_| SdkError::VaultPassphraseWeak)
                })?;
                let parent = sdk.open_seed(&req.parent)?;
                let pe = sdk.entry(&req.parent).await?;
                let (child, backup) = parent.wallet.bip85_child()?;
                let manifest = parent.wallet.reseal_label_vault("manifest")?.to_json();
                let (wallet, entry) = new_entry(
                    &sdk,
                    child,
                    req.label,
                    "bip85",
                    &pe.class,
                    pe.warnings.clone(),
                    "pending",
                    pass,
                )
                .await?;
                // a held child (`SeedExists`) still uses up its index: the raised mark is written, so the next call
                // derives the next child
                let mut held = false;
                let ks = sdk
                    .keystore
                    .update(|ks| {
                        if ks.seeds.iter().any(|s| s.label == entry.label) {
                            return Err(SdkError::LabelTaken);
                        }
                        held = ks.seeds.iter().any(|s| s.fingerprint == entry.fingerprint);
                        let p = ks
                            .seeds
                            .iter_mut()
                            .find(|s| s.id == req.parent)
                            .ok_or(SdkError::SeedUnknown)?;
                        stored_ok(&parent.wallet, p)?;
                        p.vaults.insert("manifest".into(), manifest.clone());
                        // the MAC covers the vault texts (T13b ruling 3)
                        p.index_mac = mac(&parent.wallet, p)?;
                        if !held {
                            ks.seeds.push(entry.clone());
                        }
                        Ok(())
                    })
                    .await;
                let ks = on_mismatch(&sdk, &req.parent, ks).await?;
                if held {
                    wallet.lock();
                    sdk.emit(Event::KeystoreChanged { rev: ks.rev });
                    return Err(SdkError::SeedExists);
                }
                sdk.open
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(entry.id.clone(), Arc::new(OpenSeed { wallet }));
                sdk.emit(Event::KeystoreChanged { rev: ks.rev });
                Ok(NewSeed {
                    info: info(&entry, true, true),
                    backup: Arc::new(SeedBackup(Mutex::new(backup))),
                })
            })
            .await
    }

    /// Whether `word` (one word, as a secret) is on the BIP-39 English list; the list never leaves `scaas-ua` (R17).
    pub fn word_in_list(&self, word: Arc<SecretBytes>) -> bool {
        word.with(|b| std::str::from_utf8(b).is_ok_and(scaas_ua::wallet::bip39_word_in_list))
    }

    /// Imports 12 to 24 English words (spec §6.4): checksum checked (`MnemonicInvalid`), 12 to 21 words with `short_seed`,
    /// `backup: verified`; `SeedExists` when its fingerprint is held, `LabelTaken`, `VaultPassphraseWeak`.
    pub async fn import_words(&self, req: ImportWords) -> Result<SeedInfo, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                if !new_label_ok(&req.label) {
                    return Err(SdkError::Argument);
                }
                let pass = req.vault_passphrase;
                passphrase(&pass, |p| {
                    scaas_ua::wallet::check_passphrase(p).map_err(|_| SdkError::VaultPassphraseWeak)
                })?;
                let wallet = req
                    .words
                    .with(|b| {
                        std::str::from_utf8(b)
                            .ok()
                            .map(|w| Wallet::from_mnemonic(w, ""))
                    })
                    .ok_or(SdkError::MnemonicInvalid)?
                    .map_err(|_| SdkError::MnemonicInvalid)?;
                let words = wallet.word_count()?;
                let warnings = if words < 24 {
                    vec!["short_seed".to_owned()]
                } else {
                    vec![]
                };
                let entry = new_entry(
                    &sdk, wallet, req.label, "imported", "full", warnings, "verified", pass,
                )
                .await?;
                store_new(&sdk, entry).await
            })
            .await
    }

    /// Imports a classical key as a leaf of the seed's main set (spec §6.7) through `ua-rs` `import_native_key` (tagged with its
    /// network, refused for another, CLI-SGN-11; the networks without import refuse it: `Argument`). The seed must be unlocked
    /// (`WalletLocked`); `vault_passphrase` must open the seed's own `seed` vault (`VaultOpen` otherwise: every vault of a seed
    /// opens with one passphrase). The new vault, the re-sealed manifest (same DEK, its envelopes kept), the warning
    /// `imported_key` and the rewritten MAC go in one write, refused `StoreConflict` when the stored seed moved since it was read
    /// (its label taken, its manifest another: a second SDK on the same store). Any failure after the open wallet took the key
    /// locks the seed, so no later re-seal writes a manifest that lists an import with no vault (closing review P2-7).
    pub async fn import_key(&self, req: ImportKey) -> Result<ImportedKey, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let network =
                    scaas_ua::wallet::Network::from_name(&req.network).ok_or(SdkError::Argument)?;
                let open = sdk.open_seed(&req.seed)?;
                let e = sdk.entry(&req.seed).await?;
                let manifest_read = e.vaults.get("manifest").cloned();
                let seed_vault = super::unlock::vault_of(&e, "seed")?;
                // a seed with passkey or platform unlock: the new vault carries the PRF envelope too, one assertion
                let prf = match seed_vault.prf_params() {
                    None => None,
                    Some((credential, salt)) => {
                        let how = if credential.starts_with(super::prf::PLATFORM_PREFIX) {
                            super::Unlock::Platform
                        } else {
                            super::Unlock::Passkey
                        };
                        let super::unlock::Key::Prf(out) = sdk.key_of(&e, how).await? else {
                            return Err(SdkError::Internal);
                        };
                        Some((out, credential, salt))
                    }
                };
                let pass = req.vault_passphrase;
                let secret = req.secret;
                let wallet = open.clone();
                let taken = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let took = taken.clone();
                let sealed = sdk
                    .heavy(move || {
                        passphrase(&pass, |p| seed_passphrase(&seed_vault, p))?;
                        let key = secret.with(|b| wallet.wallet.import_native_key(network, b))?;
                        took.store(true, std::sync::atomic::Ordering::SeqCst);
                        let n = key.index();
                        let label = format!("native-import:{}:{n}", network.name());
                        let vault = passphrase(&pass, |p| match &prf {
                            None => Ok(wallet.wallet.seal_label_vault(&label, p, None)?),
                            Some((out, credential, salt)) => out.with(|b| {
                                let output: &[u8; 32] =
                                    b.try_into().map_err(|_| SdkError::AuthenticatorRefused)?;
                                let env = scaas_ua::wallet::PrfEnvelope {
                                    output,
                                    credential_id: credential,
                                    salt,
                                };
                                Ok(wallet.wallet.seal_label_vault(&label, p, Some(&env))?)
                            }),
                        })?;
                        let manifest = wallet.wallet.reseal_label_vault("manifest")?;
                        Ok((label, n, vault.to_json(), manifest.to_json()))
                    })
                    .await;
                let written = match sealed {
                    Err(e) => Err(e),
                    Ok((label, n, vault, manifest)) => sdk
                        .keystore
                        .update(|ks| {
                            let i = ks
                                .seeds
                                .iter()
                                .position(|s| s.id == req.seed)
                                .ok_or(SdkError::SeedUnknown)?;
                            let mut e = ks.seeds.get(i).cloned().ok_or(SdkError::SeedUnknown)?;
                            stored_ok(&open.wallet, &e)?;
                            // the seed as read: its label free, its manifest the one the open wallet re-sealed
                            if e.vaults.contains_key(&label)
                                || e.vaults.get("manifest") != manifest_read.as_ref()
                            {
                                return Err(SdkError::StoreConflict);
                            }
                            e.vaults.insert(label.clone(), vault.clone());
                            e.vaults.insert("manifest".into(), manifest.clone());
                            if !e.warnings.iter().any(|w| w == "imported_key") {
                                e.warnings.push("imported_key".into());
                            }
                            e.index_mac = mac(&open.wallet, &e)?;
                            if let Some(slot) = ks.seeds.get_mut(i) {
                                *slot = e;
                            }
                            Ok(())
                        })
                        .await
                        .map(|ks| (ks, n)),
                };
                let (ks, n) = match written {
                    Ok(w) => w,
                    Err(e) => {
                        if taken.load(std::sync::atomic::Ordering::SeqCst) {
                            drop(open);
                            sdk.lock_seed(&req.seed).await;
                        }
                        return on_mismatch(&sdk, &req.seed, Err(e)).await;
                    }
                };
                sdk.emit(Event::KeystoreChanged { rev: ks.rev });
                Ok(ImportedKey {
                    network: req.network,
                    index: n,
                })
            })
            .await
    }

    /// Marks the seed's backup `verified` after the three-word check passed (the seed unlocked: the MAC is rewritten).
    pub async fn confirm_backup(&self, seed: String) -> Result<(), SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                change_entry(&sdk, &seed, |e| {
                    e.backup = "verified".into();
                    Ok(())
                })
                .await
            })
            .await
    }

    /// Renames the seed (unlocked: the MAC is rewritten); `LabelTaken`, `Argument` for a label outside its rule.
    pub async fn rename(&self, seed: String, label: String) -> Result<(), SdkError> {
        if !new_label_ok(&label) {
            return Err(SdkError::Argument);
        }
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                change_entry(&sdk, &seed, move |e| {
                    e.label = label.clone();
                    Ok(())
                })
                .await
            })
            .await
    }

    /// Removes the seed: locks it and drops its entry (the previous container stays as `keystore.prev`). A seed whose backup
    /// is `pending` needs `ConfirmRemoveUnbacked` too (`ConfirmationMissing`). No unlock needed.
    pub async fn remove(&self, req: Remove) -> Result<(), SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let _ = req.confirm;
                let unbacked = req.unbacked.is_some();
                let mut found = false;
                let ks = sdk
                    .keystore
                    .update(|ks| {
                        let e = ks
                            .seeds
                            .iter()
                            .find(|s| s.id == req.seed)
                            .ok_or(SdkError::SeedUnknown)?;
                        if e.backup == "pending" && !unbacked {
                            return Err(SdkError::ConfirmationMissing);
                        }
                        ks.seeds.retain(|s| s.id != req.seed);
                        found = true;
                        Ok(())
                    })
                    .await?;
                if found {
                    sdk.lock_seed(&req.seed).await;
                }
                sdk.emit(Event::KeystoreChanged { rev: ks.rev });
                Ok(())
            })
            .await
    }
}

/// A new entry of `wallet`: its seed and manifest vaults sealed under `pass` (off the async workers), its MAC.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn new_entry(
    sdk: &Arc<Sdk>,
    wallet: Wallet,
    label: String,
    origin: &str,
    class: &str,
    warnings: Vec<String>,
    backup: &str,
    pass: Arc<SecretBytes>,
) -> Result<(Wallet, SeedEntry), SdkError> {
    let (origin, class, backup) = (origin.to_owned(), class.to_owned(), backup.to_owned());
    sdk.heavy(move || {
        let seed = passphrase(&pass, |p| Ok(wallet.seal_vault(p, None)?))?;
        let manifest = passphrase(&pass, |p| Ok(wallet.seal_label_vault("manifest", p, None)?))?;
        // the seed's id is its vaults' (vault v2: every AAD binds it; owner 2026-11-19, T13b ruling 3)
        let id = wallet.vault_id()?;
        let fp: String = wallet
            .fingerprint()?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let mut e = SeedEntry {
            id,
            label,
            words: wallet.word_count()?,
            fingerprint: fp,
            origin,
            class,
            warnings,
            backup,
            vaults: [
                ("manifest".to_owned(), manifest.to_json()),
                ("seed".to_owned(), seed.to_json()),
            ]
            .into(),
            accounts: vec![],
            index_mac: String::new(),
        };
        e.index_mac = mac(&wallet, &e)?;
        Ok((wallet, e))
    })
    .await
}

/// Writes a new entry (`LabelTaken`, `SeedExists`), holds its wallet open, emits `KeystoreChanged`.
pub(crate) async fn store_new(
    sdk: &Arc<Sdk>,
    (wallet, entry): (Wallet, SeedEntry),
) -> Result<SeedInfo, SdkError> {
    let ks = sdk
        .keystore
        .update(|ks| {
            if ks.seeds.iter().any(|s| s.label == entry.label) {
                return Err(SdkError::LabelTaken);
            }
            if ks.seeds.iter().any(|s| s.fingerprint == entry.fingerprint) {
                return Err(SdkError::SeedExists);
            }
            ks.seeds.push(entry.clone());
            Ok(())
        })
        .await?;
    sdk.open
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(entry.id.clone(), Arc::new(OpenSeed { wallet }));
    sdk.emit(Event::KeystoreChanged { rev: ks.rev });
    Ok(info(&entry, true, true))
}

/// An index change of seed `seed` (spec §6.2): the seed must be unlocked (`WalletLocked`), the MAC is rewritten under its
/// wallet, `LabelTaken` if the change gives a label in use.
pub(crate) async fn change_entry(
    sdk: &Arc<Sdk>,
    seed: &str,
    mut f: impl FnMut(&mut SeedEntry) -> Result<(), SdkError>,
) -> Result<(), SdkError> {
    let open = sdk.open_seed(seed)?;
    let ks = sdk
        .keystore
        .update(|ks| {
            let i = ks
                .seeds
                .iter()
                .position(|s| s.id == seed)
                .ok_or(SdkError::SeedUnknown)?;
            let mut e = ks.seeds.get(i).cloned().ok_or(SdkError::SeedUnknown)?;
            stored_ok(&open.wallet, &e)?;
            f(&mut e)?;
            if ks
                .seeds
                .iter()
                .enumerate()
                .any(|(j, s)| j != i && s.label == e.label)
            {
                return Err(SdkError::LabelTaken);
            }
            e.index_mac = mac(&open.wallet, &e)?;
            if let Some(slot) = ks.seeds.get_mut(i) {
                *slot = e;
            }
            Ok(())
        })
        .await;
    drop(open);
    let ks = on_mismatch(sdk, seed, ks).await?;
    sdk.emit(Event::KeystoreChanged { rev: ks.rev });
    Ok(())
}
