// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The FRB surface (plan T20; spec §16.1). `flutter_rust_bridge_codegen` scans this module and the `scaas-sdk` crate itself
//! (`rust_input: crate::api,scaas-sdk`): every public item of the SDK is generated from its own source (records and enums field
//! by field, the module objects and the operation objects opaque, their methods as they are). This module holds only what
//! FRB cannot take from the SDK directly:
//! - the opening of the SDK over the Dart side's store and authenticator, each a record of async closures (`DartFnFuture`)
//!   that the SDK's `frb` adapter wraps into its traits, with a binding's `SdkConfig` (`RuntimeChoice::Own`, no clock);
//! - the module accessors, which return `Arc<Module>` in Rust (the UniFFI convention) and the module itself here, so its
//!   methods are callable (FRB gives an `Arc<T>` no method of `T`);
//! - the read accessors of the objects the SDK hands out as `Arc` (`Prepared`, `PreparedOrder`, `RegistryWrite`, `SeedBackup`,
//!   `Subscription`, `SecretBytes`);
//! - the error's code (`SdkError::code` returns a `&'static str`), the two `scaas-rpc` enums and the one `scaas-ua` record a
//!   profile and a seed's info hold (mirrors), and the endpoint credential's constructors.
//!
//! Secrets: key material and passphrases are `Arc<SecretBytes>`, an opaque handle on every path; its bytes move only through
//! the two C copy calls of `lib.rs` (spec §5), never FRB's codec. The one exception: an endpoint's credential (a bearer
//! token, an HMAC secret, a header value) crosses the codec as a `String` in the three `endpoint_auth_*` constructors (F16,
//! review 2026-11-20; PLANNED: `Arc<SecretBytes>` for them). Rust-only items (`RuntimeChoice::Adopt`, the clock, `MemoryStore`, `FileStore`, `poll`,
//! `heavy_peak`, `authenticator`) are marked `#[frb(ignore)]` in the SDK (`frb_hint!`).
use flutter_rust_bridge::{frb, DartFnFuture};
pub use scaas_rpc::{Class, EndpointAuth, Policy};
pub use scaas_sdk::account::{Account, RegistrationGas, RegistryWrite};
pub use scaas_sdk::admin::Admin;
pub use scaas_sdk::confidential::Confidential;
pub use scaas_sdk::dex::{Dex, PreparedOrder};
use scaas_sdk::frb::{ClosureAuthenticator, ClosureStore};
pub use scaas_sdk::op::{KeyRef, Op, Prepared, ReviewField};
pub use scaas_sdk::platform::{
    Assertion, AssertionRequest, AuthError, KeyPolicy, PasskeyCreated, SePublic,
};
pub use scaas_sdk::vault::{SeedBackup, StoreError, StorePolicy, StoredItem};
pub use scaas_sdk::wallet::Wallet;
pub use scaas_sdk::{
    ChainProfile, Event, GasTable, Limits, RuntimeChoice, Sdk, SdkConfig, SdkError, Subscription,
    Vault,
};
pub use scaas_ua::wallet::{MemoryProtection, SecretBytes};
use std::sync::Arc;

#[frb(mirror(Class))]
pub enum _Class {
    Named,
    Default,
    Discovered,
}

#[frb(mirror(Policy))]
pub enum _Policy {
    Failover,
    StrictMajority,
}

#[frb(mirror(MemoryProtection))]
pub struct _MemoryProtection {
    pub chunks: usize,
    pub locked: usize,
    pub no_dump: usize,
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

/// An error's stable code (spec §15).
#[frb(sync)]
pub fn error_code(e: &SdkError) -> String {
    e.code().to_owned()
}

/// A new secret of `len` zero bytes (16 MiB at most); its bytes move only through the C copy calls by [`secret_id`].
#[frb(sync)]
pub fn secret_new(len: u32) -> Result<Arc<SecretBytes>, SdkError> {
    Ok(Arc::new(
        SecretBytes::new(len as usize).map_err(SdkError::from)?,
    ))
}

/// A secret's id for the C copy calls.
#[frb(sync)]
pub fn secret_id(s: &Arc<SecretBytes>) -> u64 {
    s.id()
}

/// A secret's length in bytes.
#[frb(sync)]
pub fn secret_len(s: &Arc<SecretBytes>) -> u32 {
    u32::try_from(s.len()).unwrap_or(u32::MAX)
}

/// An endpoint credential: `Authorization: Bearer`.
#[frb(sync)]
pub fn endpoint_auth_bearer(token: String) -> EndpointAuth {
    EndpointAuth::Bearer(scaas_rpc::endpoint::Secret::new(token))
}

/// An endpoint credential: a gateway's HMAC secret (NODE-GW-02).
#[frb(sync)]
pub fn endpoint_auth_hmac(secret: String) -> EndpointAuth {
    EndpointAuth::Hmac(scaas_rpc::endpoint::Secret::new(secret))
}

/// An endpoint credential: a provider's API key header.
#[frb(sync)]
pub fn endpoint_auth_header(name: String, value: String) -> EndpointAuth {
    EndpointAuth::Header {
        name,
        value: scaas_rpc::endpoint::Secret::new(value),
    }
}

/// A JSON value from its text (`Argument` when it does not parse): the SDK's records that hold one (`PqzVerdictRequest::op`).
#[frb(sync)]
pub fn json_parse(text: String) -> Result<serde_json::Value, SdkError> {
    serde_json::from_str(&text).map_err(|_| SdkError::Argument)
}

/// A JSON value's text (a verdict, `Confidential::request_verdict`).
#[frb(sync)]
pub fn json_text(v: &serde_json::Value) -> String {
    v.to_string()
}

/// A verdict request (spec §9.3), its `op` a JSON value of [`json_parse`].
#[frb(sync)]
pub fn pqz_verdict_request(
    chain: String,
    token: String,
    op: serde_json::Value,
    statement: String,
    proof: String,
) -> scaas_sdk::confidential::PqzVerdictRequest {
    scaas_sdk::confidential::PqzVerdictRequest {
        chain,
        token,
        op,
        statement,
        proof,
    }
}

/// The default limits (spec §4).
#[frb(sync)]
pub fn limits_default() -> Limits {
    Limits::default()
}

/// A store's answer to `get`: `error`, else the item when `found` (`rev` its revision).
pub struct StoreGetAnswer {
    pub found: bool,
    pub bytes: Vec<u8>,
    pub rev: u64,
    pub error: Option<StoreError>,
}

/// A store's answer to `put_if`, `delete`, `lock` (`token` the lock's).
pub struct StoreAnswer {
    pub token: u64,
    pub error: Option<StoreError>,
}

/// An authenticator's answer to `get_assertion`: `error`, else the assertion (its `prf`: the output was written).
pub struct AssertionAnswer {
    pub assertion: Option<Assertion>,
    pub error: Option<AuthError>,
}

/// An authenticator's answer to `create_passkey`.
pub struct PasskeyAnswer {
    pub created: Option<PasskeyCreated>,
    pub error: Option<AuthError>,
}

/// An authenticator's answer to `p256_generate`.
pub struct SeKeyAnswer {
    pub public: Option<SePublic>,
    pub error: Option<AuthError>,
}

/// An authenticator's answer to `p256_sign`: `error`, else the signature.
pub struct SignAnswer {
    pub signature: Vec<u8>,
    pub error: Option<AuthError>,
}

fn answer<T>(v: Option<T>, e: Option<AuthError>) -> Result<T, AuthError> {
    match (e, v) {
        (Some(e), _) => Err(e),
        (None, Some(v)) => Ok(v),
        // no value and no error: a foreign implementation's fault
        (None, None) => Err(AuthError::Unexpected),
    }
}

fn done(a: StoreAnswer) -> Result<(), StoreError> {
    a.error.map_or(Ok(()), Err)
}

/// The SDK.
#[frb(opaque)]
pub struct SdkHandle(Arc<Sdk>);

/// Opens the SDK (spec §4) over the Dart side's store (spec §6.9) and authenticator (spec §6.10), each a record of async
/// closures that answer every failure as a value, on the SDK's own runtime. `rp_id` is the deployment's passkey RP ID.
#[allow(clippy::too_many_arguments)]
pub async fn sdk_open(
    profiles: Vec<ChainProfile>,
    rp_id: Option<String>,
    limits: Limits,
    gas_tables: Vec<GasTable>,
    store_get: impl Fn(String, String) -> DartFnFuture<StoreGetAnswer> + Send + Sync + 'static,
    store_put_if: impl Fn(String, Option<u64>, Vec<u8>, StorePolicy) -> DartFnFuture<StoreAnswer>
        + Send
        + Sync
        + 'static,
    store_delete: impl Fn(String) -> DartFnFuture<StoreAnswer> + Send + Sync + 'static,
    store_lock: impl Fn(String) -> DartFnFuture<StoreAnswer> + Send + Sync + 'static,
    store_unlock: impl Fn(u64) -> DartFnFuture<()> + Send + Sync + 'static,
    auth_create_passkey: impl Fn(String, String, Vec<Vec<u8>>) -> DartFnFuture<PasskeyAnswer>
        + Send
        + Sync
        + 'static,
    auth_get_assertion: impl Fn(AssertionRequest, u64) -> DartFnFuture<AssertionAnswer>
        + Send
        + Sync
        + 'static,
    auth_platform_secret: impl Fn(String, Vec<u8>, String, Option<KeyPolicy>, u64) -> DartFnFuture<Option<AuthError>>
        + Send
        + Sync
        + 'static,
    auth_p256_generate: impl Fn(KeyPolicy) -> DartFnFuture<SeKeyAnswer> + Send + Sync + 'static,
    auth_p256_sign: impl Fn(String, Vec<u8>, String) -> DartFnFuture<SignAnswer> + Send + Sync + 'static,
) -> Result<SdkHandle, SdkError> {
    let store = ClosureStore {
        get: Box::new(move |(name, reason)| {
            let f = store_get(name, reason);
            Box::pin(async move {
                let a = f.await;
                match a.error {
                    Some(e) => Err(e),
                    None if a.found => Ok(Some(StoredItem {
                        bytes: a.bytes,
                        rev: a.rev,
                    })),
                    None => Ok(None),
                }
            })
        }),
        put_if: Box::new(move |(name, prev, bytes, policy)| {
            let f = store_put_if(name, prev, bytes, policy);
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
                a.error.map_or(Ok(a.token), Err)
            })
        }),
        unlock: Arc::new(move |t| store_unlock(t)),
    };
    let auth = ClosureAuthenticator {
        create_passkey: Box::new(move |(rp, user, exclude)| {
            let f = auth_create_passkey(rp, user, exclude);
            Box::pin(async move {
                let a = f.await;
                answer(a.created, a.error)
            })
        }),
        get_assertion: Box::new(move |(req, prf_out)| {
            let f = auth_get_assertion(req, prf_out);
            Box::pin(async move {
                let a = f.await;
                answer(a.assertion, a.error)
            })
        }),
        platform_secret: Box::new(move |(h, salt, reason, policy, out)| {
            let f = auth_platform_secret(h, salt, reason, policy, out);
            Box::pin(async move { f.await.map_or(Ok(()), Err) })
        }),
        p256_generate: Box::new(move |policy| {
            let f = auth_p256_generate(policy);
            Box::pin(async move {
                let a = f.await;
                answer(a.public, a.error)
            })
        }),
        p256_sign: Box::new(move |(h, msg, reason)| {
            let f = auth_p256_sign(h, msg, reason);
            Box::pin(async move {
                let a = f.await;
                a.error.map_or(Ok(a.signature), Err)
            })
        }),
    };
    let config = SdkConfig {
        profiles,
        store: Arc::new(store),
        authenticator: Some(Arc::new(auth)),
        rp_id,
        runtime: RuntimeChoice::Own,
        limits,
        clock: None,
        gas_tables,
    };
    Ok(SdkHandle(Sdk::open(config).await?))
}

impl SdkHandle {
    /// The seed module (spec §6).
    #[frb(sync)]
    pub fn vault(&self) -> Vault {
        (*self.0.vault()).clone()
    }
    /// The account module (spec §7).
    #[frb(sync)]
    pub fn account(&self) -> Account {
        (*self.0.account()).clone()
    }
    /// The wallet module (spec §8).
    #[frb(sync)]
    pub fn wallet(&self) -> Wallet {
        (*self.0.wallet()).clone()
    }
    /// The confidential module (spec §9).
    #[frb(sync)]
    pub fn confidential(&self) -> Confidential {
        (*self.0.confidential()).clone()
    }
    /// The DEX module (spec §10).
    #[frb(sync)]
    pub fn dex(&self) -> Dex {
        (*self.0.dex()).clone()
    }
    /// The admin module (spec §11).
    #[frb(sync)]
    pub fn admin(&self) -> Admin {
        (*self.0.admin()).clone()
    }
    /// The operations module (spec §13).
    #[frb(sync)]
    pub fn op(&self) -> Op {
        (*self.0.op()).clone()
    }
    /// A subscription to the SDK's events (spec §14).
    #[frb(sync)]
    pub fn subscribe(&self) -> Arc<Subscription> {
        self.0.subscribe()
    }
    /// The limits in force.
    #[frb(sync)]
    pub fn limits(&self) -> Limits {
        self.0.limits().clone()
    }
    /// Watches `account` on `chains` (spec §14).
    pub async fn watch(&self, account: String, chains: Vec<String>) -> Result<(), SdkError> {
        self.0.watch(account, chains).await
    }
    /// `sdk.state`'s `rev` now (R17).
    pub async fn state_rev(&self) -> Result<u64, SdkError> {
        self.0.state_rev().await
    }
}

/// The next event, or `None` within `timeout_ms` (spec §14).
pub async fn events_next(events: &Arc<Subscription>, timeout_ms: u64) -> Option<Event> {
    events.next(timeout_ms).await
}

/// A prepared operation as the user reviews it (spec §13.1).
pub struct PreparedView {
    pub id: String,
    pub chain: String,
    /// the contract function: `mtxPay`, `mtxCancelNonce`, …
    pub entry: String,
    pub review: Vec<ReviewField>,
    /// an undecoded call under `AllowOpaqueCall` (§13.2)
    pub opaque: bool,
    pub signer: KeyRef,
    /// the operation's `validUntil` (`u64::MAX`: none)
    pub expires_at: u64,
}

#[frb(sync)]
pub fn prepared_view(p: &Arc<Prepared>) -> PreparedView {
    PreparedView {
        id: p.id(),
        chain: p.chain(),
        entry: p.entry(),
        review: p.review(),
        opaque: p.opaque(),
        signer: p.signer(),
        expires_at: p.expires_at(),
    }
}

/// A prepared order as the user reviews it (spec §10).
pub struct PreparedOrderView {
    pub id: String,
    pub chain: String,
    pub review: Vec<ReviewField>,
    pub signer: KeyRef,
}

#[frb(sync)]
pub fn prepared_order_view(p: &Arc<PreparedOrder>) -> PreparedOrderView {
    PreparedOrderView {
        id: p.id(),
        chain: p.chain(),
        review: p.review(),
        signer: p.signer(),
    }
}

/// A registry write as the user reviews it (spec §7).
pub struct RegistryWriteView {
    pub id: String,
    pub chain: String,
    pub entry: String,
    pub ua: String,
    pub review: Vec<ReviewField>,
    pub calldata: String,
    pub payer: KeyRef,
    /// a registration carrying its PQZ key's proof: one transaction or two, each step's gas and the total (owner 2026-11-20)
    pub registration_gas: Option<RegistrationGas>,
}

#[frb(sync)]
pub fn registry_write_view(w: &Arc<RegistryWrite>) -> RegistryWriteView {
    RegistryWriteView {
        id: w.id(),
        chain: w.chain(),
        entry: w.entry(),
        ua: w.ua(),
        review: w.review(),
        calldata: w.calldata(),
        payer: w.payer(),
        registration_gas: w.registration_gas(),
    }
}

/// The words of a seed made here, once, as a secret (CLI-SGN-11).
#[frb(sync)]
pub fn backup_reveal(b: &Arc<SeedBackup>) -> Result<Arc<SecretBytes>, SdkError> {
    b.reveal()
}

/// The three word positions the user is asked for.
#[frb(sync)]
pub fn backup_challenge(b: &Arc<SeedBackup>) -> Result<Vec<u32>, SdkError> {
    b.challenge()
}

/// The user's three words (a secret) against the challenge.
#[frb(sync)]
pub fn backup_verify(b: &Arc<SeedBackup>, answers: Arc<SecretBytes>) -> Result<bool, SdkError> {
    b.verify(answers)
}
