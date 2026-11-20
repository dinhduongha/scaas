// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The generic surface for app cores above the SDK (spec §12; CLI-SDK-19, CLI-SDK-20; feature `app-core`, bit 26). An app core
//! gets an [`AppCore`] scope: key handles ([`AppKey`], held by `scaas-ua` in the seed's arena, one usage each, never bytes),
//! labels under the prefixes it declared (two live cores never declare prefixes where one starts the other:
//! `AppLabelRefused`), and app record signing on two paths with the refusals of §12.4 (`scaas-ua`'s lists; here the profile's:
//! the domain's `chainId` the chain's, its `verifyingContract` none of the profile's registry, factory, router, tokens or DEX).
//! Scoping avoids collisions; it does not isolate (§12.3: an app holding the user's unlocked seed acts for that UA in every app
//! namespace). The only bytes that leave are the plaintexts the app core asks to decrypt ([`AppCore::open`], a
//! `SecretBytes`). UNAUDITED.
use crate::error::SdkError;
use crate::op::KeyRef;
use crate::op::{ReviewField, Source};
use crate::Sdk;
use scaas_ua::wallet::{
    AppKeys, AppPath as UaPath, Argon2Params, KemWrap, KeyHandle, KeyUsage, Nonce, SecretBytes,
    Signer, TypedData,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

/// The prefixes every live app core declared, by core id (one process: §12.3 is about the cores one app links).
static DECLARED: Mutex<Vec<(u64, Vec<String>)>> = Mutex::new(Vec::new());
static CORES: AtomicU64 = AtomicU64::new(1);

fn ua(e: scaas_ua::wallet::Error) -> SdkError {
    SdkError::Ua(e)
}

fn hex32(s: &str) -> Result<[u8; 32], SdkError> {
    let h = s.strip_prefix("0x").ok_or(SdkError::Argument)?;
    let v = (0..h.len())
        .step_by(2)
        .map(|i| h.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect::<Option<Vec<u8>>>()
        .ok_or(SdkError::Argument)?;
    v.try_into().map_err(|_| SdkError::Argument)
}

/// The `i`-th handle `with` gave (it gives as many as it was asked for).
fn at<'a>(hs: &[&'a KeyHandle], i: usize) -> Result<&'a KeyHandle, SdkError> {
    hs.get(i).copied().ok_or(SdkError::Argument)
}

fn hex(b: &[u8]) -> String {
    format!(
        "0x{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

/// What an app core declares of itself (all self-declared: §12.3).
#[derive(Debug, Clone)]
pub struct AppDesc {
    /// `0x` + 64 hex, not zero; `None`: a scope that holds handles and labels and signs nothing under an app purpose
    pub app_id: Option<String>,
    pub name: String,
    /// the factory class of the app's contracts, if it has one (a factory instance of another class is refused as a domain)
    pub class: Option<u16>,
    /// the label prefixes the scope's labels must start with (`scaas/<app>/v1/`)
    pub labels: Vec<String>,
}

/// A handle's usage (spec §12.2): fixed at its making, enforced at every use, never in a byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppKeyUsage {
    Derive,
    Data,
    KeyWrap,
}

impl From<AppKeyUsage> for KeyUsage {
    fn from(u: AppKeyUsage) -> KeyUsage {
        match u {
            AppKeyUsage::Derive => KeyUsage::Derive,
            AppKeyUsage::Data => KeyUsage::Data,
            AppKeyUsage::KeyWrap => KeyUsage::KeyWrap,
        }
    }
}

/// A `seal` / `open` nonce.
pub enum AppNonce {
    /// 12 random bytes prepended to the output
    Random,
    /// the nonce the key's own 44-byte derivation gave
    FromKey,
    /// `HMAC(handle, 0x03)[0:12]` of a `Derive` handle of this scope
    FromHandle(Arc<AppKey>),
}

/// A KEM wrap's named fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppWrap {
    pub mlkem_ct: Vec<u8>,
    pub x25519_eph: Vec<u8>,
    pub sealed_key: Vec<u8>,
}

/// A key handle of one scope: no bytes, no `Clone` of its key; released by [`AppCore::destroy`], its drop, or the seed's lock.
pub struct AppKey {
    core: u64,
    seed: String,
    h: Mutex<Option<KeyHandle>>,
}

/// An app record's path (spec §12.2).
#[derive(Debug, Clone)]
pub enum AppPath {
    /// (A) `requirePortableApp`: the scope's `app_id`, its purpose `appPurpose(app_id)`
    Portable,
    /// (B) `requireAuthorized` on `chain`: `purpose` the app's own (`0x` + 64 hex), else `appPurpose(app_id)`
    ChainBound {
        chain: String,
        purpose: Option<String>,
    },
}

/// A signed app record: the `UASig`'s named fields, the typed digest and the review shown before it was signed.
#[derive(Debug, Clone)]
pub struct AppSigned {
    pub key_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub digest: String,
    pub review: Vec<ReviewField>,
}

/// One app core's scope (spec §12.2).
pub struct AppCore {
    sdk: Arc<Sdk>,
    id: u64,
    app_id: Option<[u8; 32]>,
    class: Option<u16>,
    labels: Vec<String>,
    /// one `scaas-ua` scope per seed the core used
    keys: Mutex<HashMap<String, Arc<AppKeys>>>,
}

impl Drop for AppCore {
    fn drop(&mut self) {
        DECLARED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(c, _)| *c != self.id);
    }
}

fn overlaps(a: &str, b: &str) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

impl AppCore {
    /// A new scope: `app_id` 0 or malformed, a name empty, no label prefix or an empty one: `Argument`; a prefix that starts
    /// or is started by another live core's (or another of its own): `AppLabelRefused`.
    pub fn new(sdk: Arc<Sdk>, desc: AppDesc) -> Result<Arc<AppCore>, SdkError> {
        let app_id = desc.app_id.as_deref().map(hex32).transpose()?;
        if app_id == Some([0; 32])
            || desc.name.is_empty()
            || desc.labels.is_empty()
            || desc.labels.iter().any(String::is_empty)
        {
            return Err(SdkError::Argument);
        }
        let mut d = DECLARED.lock().unwrap_or_else(PoisonError::into_inner);
        let own = desc
            .labels
            .iter()
            .enumerate()
            .any(|(i, a)| desc.labels.iter().skip(i + 1).any(|b| overlaps(a, b)));
        let other = d
            .iter()
            .flat_map(|(_, l)| l)
            .any(|b| desc.labels.iter().any(|a| overlaps(a, b)));
        if own || other {
            return Err(SdkError::AppLabelRefused);
        }
        let id = CORES.fetch_add(1, Ordering::Relaxed);
        d.push((id, desc.labels.clone()));
        Ok(Arc::new(AppCore {
            sdk,
            id,
            app_id,
            class: desc.class,
            labels: desc.labels,
            keys: Mutex::new(HashMap::new()),
        }))
    }

    fn scope(&self, seed: &str) -> Result<Arc<AppKeys>, SdkError> {
        let open = self.sdk.open_seed(seed)?;
        let mut m = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(m.entry(seed.to_string())
            .or_insert_with(|| Arc::new(open.wallet.app_keys()))
            .clone())
    }

    fn label(&self, label: &[u8]) -> Result<(), SdkError> {
        let ok = self.labels.iter().any(|p| label.starts_with(p.as_bytes()));
        ok.then_some(()).ok_or(SdkError::AppLabelRefused)
    }

    fn mine(&self, k: &AppKey) -> Result<(), SdkError> {
        (k.core == self.id)
            .then_some(())
            .ok_or(SdkError::Ua(scaas_ua::wallet::Error::AppHandleForeign))
    }

    /// `f` over the handles `ks` (each this scope's, of one seed), in `seed`'s `scaas-ua` scope.
    fn with<R>(
        &self,
        ks: &[&AppKey],
        f: impl FnOnce(&AppKeys, &[&KeyHandle]) -> Result<R, SdkError>,
    ) -> Result<R, SdkError> {
        let seed = ks
            .first()
            .map(|k| k.seed.clone())
            .ok_or(SdkError::Argument)?;
        for k in ks {
            self.mine(k)?;
            if k.seed != seed {
                return Err(SdkError::Ua(scaas_ua::wallet::Error::AppHandleForeign));
            }
        }
        let scope = self.scope(&seed)?;
        let guards: Vec<_> = ks
            .iter()
            .map(|k| k.h.lock().unwrap_or_else(PoisonError::into_inner))
            .collect();
        let hs = guards
            .iter()
            .map(|g| {
                g.as_ref()
                    .ok_or(SdkError::Ua(scaas_ua::wallet::Error::KeyRevoked))
            })
            .collect::<Result<Vec<_>, _>>()?;
        f(&scope, &hs)
    }

    fn wrap(&self, seed: &str, h: KeyHandle) -> Arc<AppKey> {
        Arc::new(AppKey {
            core: self.id,
            seed: seed.to_string(),
            h: Mutex::new(Some(h)),
        })
    }

    /// Non-key randomness of `n` bytes (at most 4,096): a salt, a nonce prefix, passphrase words.
    pub fn random_bytes(&self, seed: &str, n: u32) -> Result<Vec<u8>, SdkError> {
        self.scope(seed)?.random_bytes(n as usize).map_err(ua)
    }

    /// A fresh random key of `usage` in `seed`'s arena.
    pub fn random_key(&self, seed: &str, usage: AppKeyUsage) -> Result<Arc<AppKey>, SdkError> {
        let h = self.scope(seed)?.random_key(usage.into()).map_err(ua)?;
        Ok(self.wrap(seed, h))
    }

    /// HKDF-SHA-256 over the `Derive` handles `keys`, `info = label ‖ context` exactly, `label` under the scope's prefixes;
    /// with `nonce`, the output's next 12 bytes kept on the handle for [`AppNonce::FromKey`].
    pub fn derive(
        &self,
        keys: Vec<Arc<AppKey>>,
        salt: Vec<u8>,
        label: Vec<u8>,
        context: Vec<u8>,
        usage: AppKeyUsage,
        nonce: bool,
    ) -> Result<Arc<AppKey>, SdkError> {
        self.label(&label)?;
        let refs: Vec<&AppKey> = keys.iter().map(|k| &**k).collect();
        let seed = refs
            .first()
            .map(|k| k.seed.clone())
            .ok_or(SdkError::Argument)?;
        let info = [label, context].concat();
        let h = self.with(&refs, |s, hs| {
            s.derive(hs, &salt, &info, usage.into(), nonce).map_err(ua)
        })?;
        Ok(self.wrap(&seed, h))
    }

    /// HMAC-SHA-256 of `data` under a `Derive` handle into a key of `usage` (a chain step: no label); `data` starting with a
    /// declared prefix of any live core is refused (`AppLabelRefused`: it would rebuild a labelled key, pqchat-core §5.3 (6)).
    pub fn mac_derive(
        &self,
        key: Arc<AppKey>,
        data: Vec<u8>,
        usage: AppKeyUsage,
    ) -> Result<Arc<AppKey>, SdkError> {
        let declared = DECLARED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if declared
            .iter()
            .flat_map(|(_, l)| l)
            .any(|p| data.starts_with(p.as_bytes()))
        {
            return Err(SdkError::AppLabelRefused);
        }
        let h = self.with(&[&key], |s, hs| {
            s.mac_derive(at(hs, 0)?, &data, usage.into()).map_err(ua)
        })?;
        Ok(self.wrap(&key.seed, h))
    }

    /// One public MAC output of 1 to 8 bytes, `label_and_data` starting with a declared prefix, on a key this scope drew or
    /// unwrapped.
    pub fn mac_public(
        &self,
        key: Arc<AppKey>,
        label_and_data: Vec<u8>,
        len: u32,
    ) -> Result<Vec<u8>, SdkError> {
        self.label(&label_and_data)?;
        self.with(&[&key], |s, hs| {
            s.mac_public(at(hs, 0)?, &label_and_data, len as usize)
                .map_err(ua)
        })
    }

    fn nonce_of<'a>(n: &'a AppNonce, from: Option<&'a KeyHandle>) -> Nonce<'a> {
        match (n, from) {
            (AppNonce::Random, _) => Nonce::Random,
            (AppNonce::FromKey, _) => Nonce::FromKey,
            (AppNonce::FromHandle(_), Some(h)) => Nonce::FromHandle(h),
            (AppNonce::FromHandle(_), None) => Nonce::FromKey,
        }
    }

    /// AES-256-GCM-SIV of `pt` under a `Data` handle (`nonce ‖ ct` for a random nonce, `ct` otherwise).
    pub fn seal(
        &self,
        key: Arc<AppKey>,
        nonce: AppNonce,
        aad: Vec<u8>,
        pt: Vec<u8>,
    ) -> Result<Vec<u8>, SdkError> {
        match &nonce {
            AppNonce::FromHandle(n) => self.with(&[&key, n], |s, hs| {
                s.seal(
                    at(hs, 0)?,
                    Self::nonce_of(&nonce, Some(at(hs, 1)?)),
                    &aad,
                    &pt,
                )
                .map_err(ua)
            }),
            _ => self.with(&[&key], |s, hs| {
                s.seal(at(hs, 0)?, Self::nonce_of(&nonce, None), &aad, &pt)
                    .map_err(ua)
            }),
        }
    }

    /// The plaintext of a [`AppCore::seal`] output, as `Plaintext` (a `SecretBytes`): the only bytes that leave.
    pub fn open(
        &self,
        key: Arc<AppKey>,
        nonce: AppNonce,
        aad: Vec<u8>,
        ct: Vec<u8>,
    ) -> Result<SecretBytes, SdkError> {
        let pt = match &nonce {
            AppNonce::FromHandle(n) => self.with(&[&key, n], |s, hs| {
                s.open(
                    at(hs, 0)?,
                    Self::nonce_of(&nonce, Some(at(hs, 1)?)),
                    &aad,
                    &ct,
                )
                .map_err(ua)
            })?,
            _ => self.with(&[&key], |s, hs| {
                s.open(at(hs, 0)?, Self::nonce_of(&nonce, None), &aad, &ct)
                    .map_err(ua)
            })?,
        };
        SecretBytes::from_zeroizing(pt).map_err(ua)
    }

    /// `key` sealed under a `KeyWrap` handle (60 bytes, the key-wrap AAD with `key`'s usage).
    pub fn seal_key(
        &self,
        under: Arc<AppKey>,
        key: Arc<AppKey>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, SdkError> {
        self.with(&[&under, &key], |s, hs| {
            s.seal_key(at(hs, 0)?, at(hs, 1)?, &aad).map_err(ua)
        })
    }

    /// The key a [`AppCore::seal_key`] output holds, as a handle of `usage` (the one it was sealed with).
    pub fn open_key(
        &self,
        under: Arc<AppKey>,
        wire: Vec<u8>,
        usage: AppKeyUsage,
        aad: Vec<u8>,
    ) -> Result<Arc<AppKey>, SdkError> {
        let h = self.with(&[&under], |s, hs| {
            s.open_key(at(hs, 0)?, &wire, usage.into(), &aad)
                .map_err(ua)
        })?;
        Ok(self.wrap(&under.seed, h))
    }

    /// Whether two handles hold the same key.
    pub fn same_key(&self, a: Arc<AppKey>, b: Arc<AppKey>) -> Result<bool, SdkError> {
        self.with(&[&a, &b], |s, hs| {
            s.same_key(at(hs, 0)?, at(hs, 1)?).map_err(ua)
        })
    }

    /// Argon2id of `password` (a `SecretBytes`) into a `Derive` handle of `seed`'s arena, off the async workers.
    pub async fn argon2id(
        self: &Arc<Self>,
        seed: String,
        password: Arc<SecretBytes>,
        salt: Vec<u8>,
        m_kib: u32,
        t: u32,
        p: u32,
    ) -> Result<Arc<AppKey>, SdkError> {
        let me = self.clone();
        let sdk = self.sdk.clone();
        sdk.heavy(move || {
            let scope = me.scope(&seed)?;
            let h = password
                .with(|pw| scope.argon2id(pw, &salt, Argon2Params { m_kib, t, p }))
                .map_err(ua)?;
            Ok(me.wrap(&seed, h))
        })
        .await
    }

    /// `key` wrapped to the KEM key `kem_pk` (a fresh ephemeral key of a device link, or a UA's at a version the app read
    /// under `Purpose::FeedsDecryption`); `label` under the scope's prefixes.
    pub fn kem_wrap_to_key(
        &self,
        kem_pk: Vec<u8>,
        key: Arc<AppKey>,
        label: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<AppWrap, SdkError> {
        self.label(&label)?;
        let w = self.with(&[&key], |s, hs| {
            s.kem_wrap(at(hs, 0)?, &label, &aad, &kem_pk).map_err(ua)
        })?;
        Ok(AppWrap {
            mlkem_ct: w.mlkem_ct,
            x25519_eph: w.x25519_eph.to_vec(),
            sealed_key: w.sealed_key,
        })
    }

    /// The key of `wrap` by the account's KEM key at `key_version` (the wrap's `keyId`), as a handle of `usage`.
    pub fn kem_unwrap(
        &self,
        account: KeyRef,
        key_version: u64,
        wrap: AppWrap,
        label: Vec<u8>,
        aad: Vec<u8>,
        usage: AppKeyUsage,
    ) -> Result<Arc<AppKey>, SdkError> {
        self.label(&label)?;
        let KeyRef::Ua {
            seed,
            kind,
            account,
            index,
        } = account
        else {
            return Err(SdkError::Argument);
        };
        let open = self.sdk.open_seed(&seed)?;
        let kem = open
            .wallet
            .ua_key(kind, account, index)
            .and_then(|k| k.kem_key(key_version))
            .map_err(ua)?;
        let w = KemWrap {
            mlkem_ct: wrap.mlkem_ct,
            x25519_eph: wrap.x25519_eph.try_into().map_err(|_| SdkError::Argument)?,
            sealed_key: wrap.sealed_key,
        };
        let h = self
            .scope(&seed)?
            .kem_unwrap(&kem, &w, &label, &aad, usage.into())
            .map_err(ua)?;
        Ok(self.wrap(&seed, h))
    }

    /// The scope's per-account storage root of `account` (a UA key): `app_id` required (`Argument` without).
    pub fn app_root_key(&self, account: KeyRef) -> Result<Arc<AppKey>, SdkError> {
        let app_id = self.app_id.ok_or(SdkError::Argument)?;
        let KeyRef::Ua {
            seed,
            kind,
            account,
            index,
        } = account
        else {
            return Err(SdkError::Argument);
        };
        let open = self.sdk.open_seed(&seed)?;
        let id = open
            .wallet
            .ua_key(kind, account, index)
            .map_err(ua)?
            .ua()
            .ok_or(SdkError::Argument)?;
        let h = self.scope(&seed)?.app_root_key(&app_id, &id).map_err(ua)?;
        Ok(self.wrap(&seed, h))
    }

    /// Wipes the handle's key now.
    pub fn destroy(&self, key: Arc<AppKey>) -> Result<(), SdkError> {
        self.mine(&key)?;
        drop(key.h.lock().unwrap_or_else(PoisonError::into_inner).take());
        Ok(())
    }

    /// The review of an app record (spec §12.2: the domain's name and `app_id` taken from the typed data, the path, every
    /// domain and message field, source `Signed`).
    fn review(path: &AppPath, typed: &TypedData) -> Vec<ReviewField> {
        let v = typed.to_value();
        let mut out = vec![field(
            "path",
            match path {
                AppPath::Portable => "portable".to_string(),
                AppPath::ChainBound { chain, .. } => format!("chain-bound on {chain}"),
            },
            Source::Derived,
        )];
        out.push(field(
            "primaryType",
            typed.primary_type().to_string(),
            Source::Signed,
        ));
        for part in ["domain", "message"] {
            flatten(
                part,
                v.get(part).unwrap_or(&serde_json::Value::Null),
                &mut out,
            );
        }
        out
    }

    /// Signs the app record `typed_json` (EIP-712 JSON: types, primary type, domain, message; never a digest) on `path` by
    /// `account` (a UA key or a native EVM key; an `msig` or a stored key: `Argument` here). Refused by name (§12.4): a SCaaS
    /// purpose, a SCaaS domain name, path A's field set or salt (`scaas-ua`); on path B a `chainId` other than the profile's or
    /// a `verifyingContract` that is the profile's registry, factory or router, a listed token or DEX
    /// (`AppDomainRefused`). A scope without `app_id` signs nothing under an app purpose (`Argument`).
    pub async fn sign_app_record(
        self: &Arc<Self>,
        account: KeyRef,
        path: AppPath,
        typed_json: String,
    ) -> Result<AppSigned, SdkError> {
        let me = self.clone();
        let sdk = self.sdk.clone();
        sdk.clone()
            .spawn(async move {
                let typed = TypedData::from_json(typed_json.as_bytes()).map_err(ua)?;
                let (ua_path, registry) = me.ua_path(&path, &typed, &account).await?;
                let digest = scaas_ua::wallet::app_record_digest(&ua_path, &typed).map_err(ua)?;
                let review = Self::review(&path, &typed);
                let key = crate::op::key(&sdk, &account)?;
                let signer: &dyn Signer = match &key {
                    crate::op::Key::Ua(_, k) => k,
                    crate::op::Key::Native(_, k) => k,
                    #[allow(unreachable_patterns)]
                    _ => return Err(SdkError::Argument),
                };
                let sig =
                    scaas_ua::wallet::sign_app_record(signer, registry.as_ref(), &ua_path, &typed)
                        .map_err(ua)?;
                Ok(AppSigned {
                    key_data: sig.key_data,
                    signature: sig.signature,
                    digest: hex(&digest),
                    review,
                })
            })
            .await
    }

    /// The `scaas-ua` path of `path`, after the profile's checks of a chain-bound domain, and the registry's domain a native
    /// key signs `UAAuth` under.
    async fn ua_path(
        &self,
        path: &AppPath,
        typed: &TypedData,
        account: &KeyRef,
    ) -> Result<(UaPath, Option<scaas_ua::Domain>), SdkError> {
        let app_id = self.app_id.ok_or(SdkError::Argument)?;
        let (chain, purpose) = match path {
            AppPath::Portable => return Ok((UaPath::Portable { app_id }, None)),
            AppPath::ChainBound { chain, purpose } => (chain, purpose),
        };
        let purpose = match purpose {
            Some(p) => hex32(p)?,
            None => {
                scaas_ua::ua_portable::app_purpose(&app_id).map_err(|e| SdkError::Ua(e.into()))?
            }
        };
        let (profile, chain_id, pool) = crate::op::evm(&self.sdk, chain)?;
        let v = typed.to_value();
        let d = v
            .get("domain")
            .ok_or(SdkError::Ua(scaas_ua::wallet::Error::AppDomainRefused))?;
        let refused = SdkError::Ua(scaas_ua::wallet::Error::AppDomainRefused);
        let id = d.get("chainId").and_then(|c| {
            c.as_str()
                .map(str::to_string)
                .or_else(|| c.as_u64().map(|n| n.to_string()))
        });
        if id.as_deref() != Some(&chain_id.to_string()) {
            return Err(refused);
        }
        let vc = d
            .get("verifyingContract")
            .and_then(|c| c.as_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let listed = [
            profile.registry.clone(),
            profile.factory.clone(),
            profile.router.clone(),
        ]
        .into_iter()
        .flatten()
        .chain(profile.tokens.iter().map(|t| t.address.clone()))
        .chain(profile.dexes.iter().map(|x| x.address.clone()))
        .any(|a| a.eq_ignore_ascii_case(&vc));
        if listed {
            return Err(refused);
        }
        let _ = self.class; // a factory instance of another class: PLANNED with the factory listing read (part 4b)
        let registry = match account {
            KeyRef::Native { .. } => {
                let r = profile.registry.as_deref().ok_or(SdkError::Argument)?;
                let addr = r.parse().map_err(|_| SdkError::Argument)?;
                Some(crate::account::msig::domain(&self.sdk, chain, &pool, addr).await?)
            }
            _ => None,
        };
        Ok((UaPath::ChainBound { purpose }, registry))
    }

    /// Whether `ua`'s single key (`kind`, `key_data`, read by the caller from the UA's record) signs `typed_json` on `path`.
    pub fn verify_app_record_key(
        &self,
        kind: u16,
        key_data: Vec<u8>,
        path: AppPath,
        purpose: Option<String>,
        typed_json: String,
        signature: Vec<u8>,
    ) -> Result<bool, SdkError> {
        let typed = TypedData::from_json(typed_json.as_bytes()).map_err(ua)?;
        let p = match path {
            AppPath::Portable => UaPath::Portable {
                app_id: self.app_id.ok_or(SdkError::Argument)?,
            },
            AppPath::ChainBound { .. } => UaPath::ChainBound {
                purpose: match purpose {
                    Some(p) => hex32(&p)?,
                    None => {
                        scaas_ua::ua_portable::app_purpose(&self.app_id.ok_or(SdkError::Argument)?)
                            .map_err(|e| SdkError::Ua(e.into()))?
                    }
                },
            },
        };
        Ok(scaas_ua::wallet::verify_app_record_key(
            kind, &key_data, &p, &typed, &signature,
        ))
    }
}

fn field(name: &str, value: String, source: Source) -> ReviewField {
    ReviewField {
        name: name.to_string(),
        display: value.clone(),
        value,
        source,
    }
}

fn flatten(prefix: &str, v: &serde_json::Value, out: &mut Vec<ReviewField>) {
    match v {
        serde_json::Value::Object(o) => {
            for (k, x) in o {
                flatten(&format!("{prefix}.{k}"), x, out);
            }
        }
        serde_json::Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                flatten(&format!("{prefix}[{i}]"), x, out);
            }
        }
        serde_json::Value::String(s) => out.push(field(prefix, s.clone(), Source::Signed)),
        other => out.push(field(prefix, other.to_string(), Source::Signed)),
    }
}
