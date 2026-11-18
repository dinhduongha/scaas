// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The FRB surface of the T3 spike (plan T3; spec §16.1): the SDK's objects as opaque handles, its records and the platform
//! interfaces' answers as plain FRB types, every async call on the SDK's runtime. Not BUILT: T20 brings the whole surface
//! (profiles, the deployment's RP ID). The spike's `spike_*` calls are gone (closing review P2-10: one returned a function of a
//! PRF output, one fetched any URL); no exported name starts with `spike_`.
use flutter_rust_bridge::{frb, DartFnFuture};
use scaas_sdk::frb::{ClosureAuthenticator, ClosureStore, Fut};
use scaas_sdk::platform::{Assertion, AssertionRequest, AuthError};
use scaas_sdk::vault::{Generate, StoreError, StoredItem};
use scaas_sdk::{Event, Limits, RuntimeChoice, Sdk, SdkConfig, SdkError, Subscription};
use scaas_ua::wallet::SecretBytes;
use std::sync::Arc;

/// An SDK error: its stable code only.
#[derive(Debug)]
pub struct SdkFailure {
    pub code: String,
}

impl From<SdkError> for SdkFailure {
    fn from(e: SdkError) -> Self {
        SdkFailure { code: e.code().to_owned() }
    }
}

/// The binding surface's version this library was built with (spec §16.3).
#[frb(sync)]
pub fn api_version() -> u32 {
    Sdk::api_version()
}

/// This library's feature bits (spec §3.3).
#[frb(sync)]
pub fn features() -> u64 {
    Sdk::features()
}

/// A secret in Rust memory; its bytes move only through the C copy calls by `id`.
#[frb(opaque)]
pub struct Secret(Arc<SecretBytes>);

impl Secret {
    #[frb(sync)]
    pub fn id(&self) -> u64 {
        self.0.id()
    }
    #[frb(sync)]
    pub fn size(&self) -> u32 {
        u32::try_from(self.0.len()).unwrap_or(u32::MAX)
    }
}

/// A new secret of `len` zero bytes (16 MiB at most).
#[frb(sync)]
pub fn secret_new(len: u32) -> Result<Secret, SdkFailure> {
    let s = SecretBytes::new(len as usize).map_err(SdkError::from)?;
    Ok(Secret(Arc::new(s)))
}

/// A store's failure as the Dart side answers it.
pub enum StoreFailure {
    Conflict,
    Io,
    Unavailable,
    Unexpected,
}

fn store_error(f: StoreFailure) -> StoreError {
    match f {
        StoreFailure::Conflict => StoreError::Conflict,
        StoreFailure::Io => StoreError::Io,
        StoreFailure::Unavailable => StoreError::Unavailable,
        StoreFailure::Unexpected => StoreError::Unexpected,
    }
}

/// A store's answer to `get`: `error`, else the item when `found` (plain records: no data-carrying enum, so the generated Dart
/// needs no code generator of its own).
pub struct StoreGetAnswer {
    pub found: bool,
    pub bytes: Vec<u8>,
    pub rev: u64,
    pub error: Option<StoreFailure>,
}

/// A store's answer to `put_if`, `delete`, `lock` (`token` the lock's).
pub struct StoreAnswer {
    pub token: u64,
    pub error: Option<StoreFailure>,
}

pub enum AuthFailure {
    Refused,
    Cancelled,
    Unavailable,
    Unexpected,
}

/// An authenticator's answer to `get_assertion`: `error`, else the assertion (`prf`: the output was written).
pub struct AuthAnswer {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
    pub prf: bool,
    pub error: Option<AuthFailure>,
}

fn auth_error(f: AuthFailure) -> AuthError {
    match f {
        AuthFailure::Refused => AuthError::Refused,
        AuthFailure::Cancelled => AuthError::Cancelled,
        AuthFailure::Unavailable => AuthError::Unavailable,
        AuthFailure::Unexpected => AuthError::Unexpected,
    }
}

fn unavailable<A, T: Send + 'static>() -> Box<dyn Fn(A) -> Fut<Result<T, AuthError>> + Send + Sync> {
    Box::new(|_| Box::pin(async { Err(AuthError::Unavailable) }))
}

/// The SDK.
#[frb(opaque)]
pub struct SdkHandle(Arc<Sdk>);

/// A seed's one reveal.
#[frb(opaque)]
pub struct Backup(Arc<scaas_sdk::vault::SeedBackup>);

/// An event queue.
#[frb(opaque)]
pub struct Events(Arc<Subscription>);

/// A seed as listed (spec §6.4).
pub struct SeedRow {
    pub id: String,
    pub label: String,
    pub words: u32,
    pub origin: String,
    pub class: String,
    pub warnings: Vec<String>,
    pub backup: String,
    pub unlocked: bool,
    pub verified: bool,
}

/// Opens the SDK over a Dart store and a Dart authenticator (each a record of async closures) on its own runtime.
#[allow(clippy::too_many_arguments)]
pub async fn sdk_open(
    store_get: impl Fn(String) -> DartFnFuture<StoreGetAnswer> + Send + Sync + 'static,
    store_put_if: impl Fn(String, Option<u64>, Vec<u8>) -> DartFnFuture<StoreAnswer> + Send + Sync + 'static,
    store_delete: impl Fn(String) -> DartFnFuture<StoreAnswer> + Send + Sync + 'static,
    store_lock: impl Fn(String) -> DartFnFuture<StoreAnswer> + Send + Sync + 'static,
    store_unlock: impl Fn(u64) -> DartFnFuture<()> + Send + Sync + 'static,
    auth_get_assertion: impl Fn(String, Vec<u8>, Vec<Vec<u8>>, Option<Vec<u8>>, u64) -> DartFnFuture<AuthAnswer>
        + Send
        + Sync
        + 'static,
) -> Result<SdkHandle, SdkFailure> {
    let store_get = Arc::new(store_get);
    let store_put_if = Arc::new(store_put_if);
    let store_delete = Arc::new(store_delete);
    let store_lock = Arc::new(store_lock);
    let auth_get_assertion = Arc::new(auth_get_assertion);
    let store = ClosureStore {
        get: Box::new(move |name| {
            let f = store_get(name);
            Box::pin(async move {
                let a = f.await;
                match a.error {
                    Some(e) => Err(store_error(e)),
                    None if a.found => Ok(Some(StoredItem { bytes: a.bytes, rev: a.rev })),
                    None => Ok(None),
                }
            })
        }),
        put_if: Box::new(move |(name, prev, bytes)| {
            let f = store_put_if(name, prev, bytes);
            Box::pin(async move { done(f.await) })
        }),
        delete: Box::new(move |name| {
            let f = store_delete(name);
            Box::pin(async move { done(f.await) })
        }),
        lock: Box::new(move |name| {
            let f = store_lock(name);
            Box::pin(async move {
                let a = f.await;
                a.error.map_or(Ok(a.token), |e| Err(store_error(e)))
            })
        }),
        unlock: Arc::new(move |t| store_unlock(t)),
    };
    let auth = ClosureAuthenticator {
        create_passkey: unavailable(),
        get_assertion: Box::new(move |(req, prf_id): (AssertionRequest, u64)| {
            // the allowed credentials go through: an unlock names its credential (P2-10)
            let f = auth_get_assertion(req.rp_id, req.challenge, req.allow, req.prf_salt, prf_id);
            Box::pin(async move {
                let a = f.await;
                match a.error {
                    Some(e) => Err(auth_error(e)),
                    None => Ok(Assertion {
                        credential_id: a.credential_id,
                        authenticator_data: a.authenticator_data,
                        client_data_json: a.client_data_json,
                        signature: a.signature,
                        prf: a.prf,
                    }),
                }
            })
        }),
        platform_secret: unavailable(),
        p256_generate: unavailable(),
        p256_sign: unavailable(),
    };
    let config = SdkConfig {
        profiles: vec![],
        store: Arc::new(store),
        authenticator: Some(Arc::new(auth)),
        rp_id: Some("example.invalid".into()),
        runtime: RuntimeChoice::Own,
        limits: Limits::default(),
        clock: None,
    };
    Ok(SdkHandle(Sdk::open(config).await?))
}

fn done(a: StoreAnswer) -> Result<(), StoreError> {
    a.error.map_or(Ok(()), |e| Err(store_error(e)))
}

impl SdkHandle {
    /// `vault.seeds()`.
    pub async fn seeds(&self) -> Result<Vec<SeedRow>, SdkFailure> {
        let rows = self.0.vault().seeds().await?;
        Ok(rows
            .into_iter()
            .map(|s| SeedRow {
                id: s.id,
                label: s.label,
                words: s.words,
                origin: s.origin,
                class: s.class,
                warnings: s.warnings,
                backup: s.backup,
                unlocked: s.unlocked,
                verified: s.verified,
            })
            .collect())
    }

    /// `vault.generate`: the passphrase as a secret; the backup's one reveal back.
    pub async fn generate(&self, label: String, vault_passphrase: &Secret) -> Result<Backup, SdkFailure> {
        let req = Generate { label, vault_passphrase: vault_passphrase.0.clone() };
        Ok(Backup(self.0.vault().generate(req).await?.backup))
    }

    /// A subscription to the SDK's events.
    #[frb(sync)]
    pub fn subscribe(&self) -> Events {
        Events(self.0.subscribe())
    }
}

impl Backup {
    /// The words, once, as a secret.
    #[frb(sync)]
    pub fn reveal(&self) -> Result<Secret, SdkFailure> {
        Ok(Secret(self.0.reveal()?))
    }
}

impl Events {
    /// The next event's name, or `None` within `timeout_ms`.
    pub async fn next(&self, timeout_ms: u64) -> Option<String> {
        self.0.next(timeout_ms).await.map(|e| match e {
            Event::KeystoreChanged { rev } => format!("KeystoreChanged {rev}"),
            other => format!("{other:?}"),
        })
    }
}
