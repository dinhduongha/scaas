// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The UniFFI surface (spec §16.1; plan T20b-T20h; feature `uniffi`), the one list every UniFFI generator reads: Python, Kotlin,
//! Swift (official UniFFI), Java, C#, Go (third-party generators) over the async API, and with feature `sync-api` the sync
//! surface (C++, `uniffi-bindgen-cpp`). Records, enums and the SDK's objects (`Prepared`, `PreparedOrder`, `RegistryWrite`,
//! `SeedBackup`) derive UniFFI's traits where the SDK declares them; this module holds what the generators cannot take from
//! the SDK directly:
//! - the module objects (`Sdk`, `Vault`, `Account`, `Wallet`, `Op`, `Confidential`, `Dex`, `Admin`): binding objects of the
//!   same names over the SDK's, their calls declared once in [`surface!`]: without `sync-api` each is the async call, spawned on
//!   the SDK's runtime (spec §14); with `sync-api` each is its `<call>_blocking` twin (`crate::sync_cpp`), never both;
//! - the opening over the app's store and authenticator (foreign traits: async here, sync under `sync-api`), with a binding's
//!   configuration ([`BindingConfig`]: `RuntimeChoice::Own`, the device's clock);
//! - the types of `scaas-rpc` and `scaas-ua` a profile and a seed's info hold (remote declarations: `Class`, `Policy`,
//!   `EndpointAuth`, `SecretBytes`), a JSON value as its text, the opaque-call marker (`true` only in a build with
//!   `opaque-calls`), and the free functions (`api_version`, `features`, the secret handles, the defaults, the helpers).
//!
//! Secrets: `Arc<SecretBytes>` is an object handle on every path; its bytes move only through the reference library's C copy
//! calls (`scaas_sdk_secret_{write,read,dispose}`, spec §5), never UniFFI's codec. An endpoint credential goes in as text and
//! never comes back out (it lowers to the empty string). Rust-only items stay outside: `RuntimeChoice::Adopt`, the clock,
//! `MemoryStore`, `FileStore`, `poll`, `heavy_peak`, `authenticator`, the raw native entry. UNAUDITED.
#![allow(clippy::too_many_arguments)]
// review B6: no unsafe in this module, held in every build that compiles it (UniFFI's expansions carry none here)
#![deny(unsafe_code)]

#[cfg(feature = "account")]
#[allow(unused_imports)]
use crate::account::{msig::*, smart::*, *};
#[cfg(feature = "admin")]
use crate::admin::{delay::*, *};
#[cfg(any(feature = "zether", feature = "pqz"))]
use crate::confidential::*;
#[cfg(feature = "dex")]
use crate::dex::*;
#[cfg(feature = "evm")]
use crate::op::*;
use crate::platform::*;
use crate::vault::*;
#[cfg(feature = "wallet")]
use crate::wallet::*;
#[cfg(feature = "evm")]
use crate::UaLine;
use crate::{ChainProfile, Event, GasTable, Limits, SdkError};
#[cfg(not(feature = "sync-api"))]
use async_trait::async_trait;
use scaas_rpc::endpoint::Secret;
use scaas_rpc::{Class, EndpointAuth, Policy};
use scaas_ua::wallet::SecretBytes;
use serde_json::Value;
use std::sync::Arc;

#[uniffi::remote(Enum)]
pub enum Class {
    Named,
    Default,
    Discovered,
}

#[uniffi::remote(Enum)]
pub enum Policy {
    Failover,
    StrictMajority,
}

// an endpoint credential: text in, never back out
uniffi::custom_type!(Secret, String, {
    remote,
    lower: |_s| String::new(),
    try_lift: |s| Ok(Secret::new(s)),
});

#[uniffi::remote(Enum)]
pub enum EndpointAuth {
    Bearer(Secret),
    Hmac(Secret),
    Header { name: String, value: Secret },
}

#[uniffi::remote(Object)]
pub struct SecretBytes;

// a JSON value as its text (a verdict, a request's `op`, a balance's words); text that does not parse is refused at the lift
uniffi::custom_type!(Value, String, {
    remote,
    lower: |v| v.to_string(),
    try_lift: |s| serde_json::from_str(&s).map_err(|_| SdkError::Argument.into()),
});

// the opaque-call marker (spec §13.2): `true` lifts only in a build with `opaque-calls`, as the Rust marker is constructible
#[cfg(feature = "evm")]
uniffi::custom_type!(AllowOpaqueCall, bool, {
    lower: |_m| true,
    try_lift: |b| marker(b),
});

#[cfg(all(feature = "evm", feature = "opaque-calls"))]
fn marker(b: bool) -> uniffi::Result<AllowOpaqueCall> {
    if b {
        Ok(AllowOpaqueCall::new())
    } else {
        Err(SdkError::OpaqueCallRefused.into())
    }
}

#[cfg(all(feature = "evm", not(feature = "opaque-calls")))]
fn marker(_b: bool) -> uniffi::Result<AllowOpaqueCall> {
    Err(SdkError::OpaqueCallRefused.into())
}

// `KeyRef` and `MsigSlot` hold each other (an `msig` signer's slots hold keys), and uniffi-bindgen-cpp refuses any cycle among
// records and enums. So a slot crosses every binding as `MsigSlotValue`, its keys `SlotKey`: a `KeyRef` whose `Msig` names the
// UA only. A slot's key is never an `msig` (spec §7: `Argument` at signing), so the lift loses nothing the SDK would take; the
// lowering of such a key (never made by a binding) keeps its UA and drops its slots.
#[cfg(feature = "evm")]
uniffi::custom_type!(MsigSlot, MsigSlotValue, {
    lower: |s| match s {
        MsigSlot::Member { index, key } => MsigSlotValue::Member { index, key: key.into() },
        MsigSlot::Msig { index, members } => MsigSlotValue::Msig {
            index,
            members: members.into_iter().map(|l| MsigLeafValue { index: l.index, key: l.key.into() }).collect(),
        },
        MsigSlot::Signed { index, member } => MsigSlotValue::Signed { index, member },
    },
    try_lift: |v| Ok(match v {
        MsigSlotValue::Member { index, key } => MsigSlot::Member { index, key: key.into() },
        MsigSlotValue::Msig { index, members } => MsigSlot::Msig {
            index,
            members: members.into_iter().map(|l| MsigLeaf { index: l.index, key: l.key.into() }).collect(),
        },
        MsigSlotValue::Signed { index, member } => MsigSlot::Signed { index, member },
    }),
});

/// One slot of an `msig` signature (`KeyRef::Msig`), as `MsigSlot`.
#[cfg(feature = "evm")]
#[derive(uniffi::Enum)]
pub enum MsigSlotValue {
    /// the signing (or native) member at `index` signs with `key`
    Member { index: u16, key: SlotKey },
    /// the `msig` member at `index` signs by its own slots, one level down
    Msig {
        index: u16,
        members: Vec<MsigLeafValue>,
    },
    /// the slot at `index` already signed on another device: its `MemberSig` JSON as `Op::member_sign` returned it
    Signed { index: u16, member: String },
}

/// A slot of an inner `msig`: its index there and its key.
#[cfg(feature = "evm")]
#[derive(uniffi::Record)]
pub struct MsigLeafValue {
    pub index: u16,
    pub key: SlotKey,
}

/// A slot's key: `KeyRef` without the slots of an `msig` (a slot's key is never one, spec §7).
#[cfg(feature = "evm")]
#[derive(uniffi::Enum)]
pub enum SlotKey {
    Ua {
        seed: String,
        kind: u16,
        account: u32,
        index: u32,
    },
    Native {
        seed: String,
        network: String,
        index: u32,
    },
    Imported {
        seed: String,
        network: String,
        index: u32,
    },
    Key {
        seed: String,
        id: String,
    },
    /// refused at signing (`Argument`)
    Msig {
        ua: String,
    },
    /// a `bls12381-multi` group's member key (as `KeyRef::BlsMulti`)
    BlsMulti {
        seed: String,
        account: u32,
        index: u32,
        key_data: String,
    },
    /// another party's signer (as `KeyRef::Signed`, a hand-off): never a slot's key, refused at signing
    Signed {
        signer: String,
    },
}

#[cfg(feature = "evm")]
impl From<KeyRef> for SlotKey {
    fn from(k: KeyRef) -> Self {
        match k {
            KeyRef::Ua {
                seed,
                kind,
                account,
                index,
            } => SlotKey::Ua {
                seed,
                kind,
                account,
                index,
            },
            KeyRef::Native {
                seed,
                network,
                index,
            } => SlotKey::Native {
                seed,
                network,
                index,
            },
            KeyRef::Imported {
                seed,
                network,
                index,
            } => SlotKey::Imported {
                seed,
                network,
                index,
            },
            KeyRef::Key { seed, id } => SlotKey::Key { seed, id },
            KeyRef::Msig { ua, .. } => SlotKey::Msig { ua },
            KeyRef::BlsMulti {
                seed,
                account,
                index,
                key_data,
            } => SlotKey::BlsMulti {
                seed,
                account,
                index,
                key_data,
            },
            KeyRef::Signed { signer } => SlotKey::Signed { signer },
        }
    }
}

#[cfg(feature = "evm")]
impl From<SlotKey> for KeyRef {
    fn from(k: SlotKey) -> Self {
        match k {
            SlotKey::Ua {
                seed,
                kind,
                account,
                index,
            } => KeyRef::Ua {
                seed,
                kind,
                account,
                index,
            },
            SlotKey::Native {
                seed,
                network,
                index,
            } => KeyRef::Native {
                seed,
                network,
                index,
            },
            SlotKey::Imported {
                seed,
                network,
                index,
            } => KeyRef::Imported {
                seed,
                network,
                index,
            },
            SlotKey::Key { seed, id } => KeyRef::Key { seed, id },
            SlotKey::Msig { ua } => KeyRef::Msig { ua, slots: vec![] },
            SlotKey::BlsMulti {
                seed,
                account,
                index,
                key_data,
            } => KeyRef::BlsMulti {
                seed,
                account,
                index,
                key_data,
            },
            SlotKey::Signed { signer } => KeyRef::Signed { signer },
        }
    }
}

/// A seed's memory protection (`scaas-ua`'s, its counts as `u64`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct MemoryProtection {
    /// the arena's chunks (16 KiB each)
    pub chunks: u64,
    /// chunks locked in RAM (`mlock`)
    pub locked: u64,
    /// chunks excluded from core dumps
    pub no_dump: u64,
}

impl From<scaas_ua::wallet::MemoryProtection> for MemoryProtection {
    fn from(m: scaas_ua::wallet::MemoryProtection) -> Self {
        let n = |v: usize| u64::try_from(v).unwrap_or(u64::MAX);
        MemoryProtection {
            chunks: n(m.chunks),
            locked: n(m.locked),
            no_dump: n(m.no_dump),
        }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for StoreError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        StoreError::Unexpected
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for AuthError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        AuthError::Unexpected
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// The module objects and their calls, declared once (spec §16.1): `async <call> / <call>_blocking (args) -> T;` is, without
/// `sync-api`, `async fn <call>(args) -> Result<T, SdkError>` spawned on the SDK's runtime (spec §14), and with `sync-api` the
/// twin `fn <call>_blocking(args, cancel: Option<Arc<CancelToken>>) -> Result<T, SdkError>` on the same body
/// (`crate::sync_cpp::block`). `tests/binding.rs` holds this list equal to the SDK's exported async calls both ways.
macro_rules! surface {
    ($(
        $(#[doc = $doc:literal])*
        $(#[cfg($oc:meta)])?
        object $obj:ident = $inner:path {
            $( $(#[$fm:meta])* async $f:ident / $fb:ident ( $($a:ident : $t:ty),* ) -> $r:ty ; )*
        }
    )*) => {
        $(
            $(#[doc = $doc])*
            $(#[cfg($oc)])?
            #[derive(uniffi::Object)]
            pub struct $obj {
                m: Arc<$inner>,
                sdk: Arc<crate::Sdk>,
            }

            $(#[cfg($oc)])?
            #[cfg(not(feature = "sync-api"))]
            #[uniffi::export]
            impl $obj {
                $(
                    $(#[$fm])*
                    pub async fn $f(&self, $($a: $t),*) -> Result<$r, SdkError> {
                        let m = self.m.clone();
                        self.sdk.spawn(async move { m.$f($($a),*).await }).await
                    }
                )*
            }

            $(#[cfg($oc)])?
            #[cfg(feature = "sync-api")]
            #[uniffi::export]
            impl $obj {
                $(
                    $(#[$fm])*
                    pub fn $fb(
                        &self,
                        $($a: $t,)*
                        cancel: Option<Arc<crate::sync_cpp::CancelToken>>,
                    ) -> Result<$r, SdkError> {
                        let m = self.m.clone();
                        crate::sync_cpp::block(&self.sdk, cancel, async move { m.$f($($a),*).await })
                    }
                )*
            }
        )*
        /// Every call of the list in this build as `(object, call, twin)`: the completeness test's.
        pub fn surface() -> Vec<(&'static str, &'static str, &'static str)> {
            #[allow(unused_mut)]
            let mut v = Vec::new();
            $(
                $(#[cfg($oc)])?
                {
                    $( $(#[$fm])* v.push((stringify!($obj), stringify!($f), stringify!($fb))); )*
                }
            )*
            v
        }
    };
}

crate::binding_list::binding_list!(surface);

impl Sdk {
    pub(crate) fn new(sdk: Arc<crate::Sdk>) -> Arc<Sdk> {
        Arc::new(Sdk {
            m: sdk.clone(),
            sdk,
        })
    }
    fn module<M>(&self, m: Arc<M>) -> (Arc<M>, Arc<crate::Sdk>) {
        (m, self.m.clone())
    }
    /// The SDK beneath (Rust-only: a library's own exported calls and its tests).
    pub fn inner(&self) -> Arc<crate::Sdk> {
        self.m.clone()
    }
    /// Runs `f` as an exported call runs, on the SDK's runtime, a panic `Internal` (Rust-only: a library's own exported calls,
    /// as the reference library's panic hook).
    #[cfg(not(feature = "sync-api"))]
    pub async fn run<T: Send + 'static>(
        &self,
        f: impl std::future::Future<Output = Result<T, SdkError>> + Send + 'static,
    ) -> Result<T, SdkError> {
        self.m.spawn(f).await
    }
    /// Runs `f` as a `*_blocking` twin runs (Rust-only, as [`Sdk::run`]).
    #[cfg(feature = "sync-api")]
    pub fn run_blocking<T: Send + 'static>(
        &self,
        cancel: Option<Arc<crate::sync_cpp::CancelToken>>,
        f: impl std::future::Future<Output = Result<T, SdkError>> + Send + 'static,
    ) -> Result<T, SdkError> {
        crate::sync_cpp::block(&self.m, cancel, f)
    }
}

#[uniffi::export]
impl Sdk {
    /// The seed module (spec §6).
    pub fn vault(&self) -> Arc<Vault> {
        let (m, sdk) = self.module(self.m.vault());
        Arc::new(Vault { m, sdk })
    }
    /// The account module (spec §7).
    #[cfg(feature = "account")]
    pub fn account(&self) -> Arc<Account> {
        let (m, sdk) = self.module(self.m.account());
        Arc::new(Account { m, sdk })
    }
    /// The wallet module (spec §8).
    #[cfg(feature = "wallet")]
    pub fn wallet(&self) -> Arc<Wallet> {
        let (m, sdk) = self.module(self.m.wallet());
        Arc::new(Wallet { m, sdk })
    }
    /// The operations module (spec §13).
    #[cfg(feature = "evm")]
    pub fn op(&self) -> Arc<Op> {
        let (m, sdk) = self.module(self.m.op());
        Arc::new(Op { m, sdk })
    }
    /// The confidential module (spec §9).
    #[cfg(any(feature = "zether", feature = "pqz"))]
    pub fn confidential(&self) -> Arc<Confidential> {
        let (m, sdk) = self.module(self.m.confidential());
        Arc::new(Confidential { m, sdk })
    }
    /// The DEX module (spec §10).
    #[cfg(feature = "dex")]
    pub fn dex(&self) -> Arc<Dex> {
        let (m, sdk) = self.module(self.m.dex());
        Arc::new(Dex { m, sdk })
    }
    /// The admin module (spec §11).
    #[cfg(feature = "admin")]
    pub fn admin(&self) -> Arc<Admin> {
        let (m, sdk) = self.module(self.m.admin());
        Arc::new(Admin { m, sdk })
    }
    /// A subscription to the SDK's events (spec §14).
    pub fn subscribe(&self) -> Arc<Subscription> {
        Arc::new(Subscription {
            m: self.m.subscribe(),
            sdk: self.m.clone(),
        })
    }
    /// The limits in force.
    pub fn limits(&self) -> Limits {
        self.m.limits().clone()
    }
}

/// A subscription to the SDK's events (spec §14): a bounded queue, `Lagged { missed }` for a slow reader.
#[derive(uniffi::Object)]
pub struct Subscription {
    m: Arc<crate::Subscription>,
    #[allow(dead_code)] // the runtime of the sync twin
    sdk: Arc<crate::Sdk>,
}

#[cfg(not(feature = "sync-api"))]
#[uniffi::export]
impl Subscription {
    /// The next event, or `None` within `timeout_ms`.
    pub async fn next(&self, timeout_ms: u64) -> Result<Option<Event>, SdkError> {
        let m = self.m.clone();
        self.sdk
            .spawn(async move { Ok(m.next(timeout_ms).await) })
            .await
    }
}

#[cfg(feature = "sync-api")]
#[uniffi::export]
impl Subscription {
    /// The next event, or `None` within `timeout_ms` (blocks the calling thread; never a UI thread).
    pub fn next_blocking(&self, timeout_ms: u64) -> Result<Option<Event>, SdkError> {
        let m = self.m.clone();
        crate::sync_cpp::block(&self.sdk, None, async move { Ok(m.next(timeout_ms).await) })
    }
}

#[cfg(not(feature = "sync-api"))]
#[uniffi::export]
impl Vault {
    /// Locks `seed`: the ids of the hidden sets abandoned with it. A failed call is its error (`Internal`), never an empty
    /// answer: the seed is then not known locked.
    pub async fn lock(&self, seed: String) -> Result<Vec<String>, SdkError> {
        let m = self.m.clone();
        self.sdk.spawn(async move { Ok(m.lock(seed).await) }).await
    }
    /// Locks every seed (a failed call is its error, as `lock`).
    pub async fn lock_all(&self) -> Result<Vec<String>, SdkError> {
        let m = self.m.clone();
        self.sdk.spawn(async move { Ok(m.lock_all().await) }).await
    }
}

#[cfg(feature = "sync-api")]
#[uniffi::export]
impl Vault {
    /// Locks `seed` (blocking twin of `lock`; a failed call, such as one from a runtime thread, is `Internal`).
    pub fn lock_blocking(&self, seed: String) -> Result<Vec<String>, SdkError> {
        let m = self.m.clone();
        crate::sync_cpp::block(&self.sdk, None, async move { Ok(m.lock(seed).await) })
    }
    /// Locks every seed (blocking twin of `lock_all`).
    pub fn lock_all_blocking(&self) -> Result<Vec<String>, SdkError> {
        let m = self.m.clone();
        crate::sync_cpp::block(&self.sdk, None, async move { Ok(m.lock_all().await) })
    }
}

#[uniffi::export]
impl Vault {
    /// The memory protection of an unlocked seed's arena.
    pub fn memory_protection(&self, seed: String) -> Result<MemoryProtection, SdkError> {
        self.m.memory_protection(seed).map(MemoryProtection::from)
    }
    /// Whether a word (a secret) is on the BIP-39 list.
    pub fn word_in_list(&self, word: Arc<SecretBytes>) -> bool {
        self.m.word_in_list(word)
    }
    /// Root (c)'s typed data for the account `account_hex` and set `set` (spec §6.6).
    #[cfg(feature = "classical-roots")]
    pub fn key_derivation_typed_data(
        &self,
        account_hex: String,
        set: u32,
    ) -> Result<String, SdkError> {
        self.m.key_derivation_typed_data(account_hex, set)
    }
    /// A 65-byte signature from its compact form (a secret in, a secret out).
    #[cfg(feature = "classical-roots")]
    pub fn signature_from_compact(
        &self,
        sig: Arc<SecretBytes>,
    ) -> Result<Arc<SecretBytes>, SdkError> {
        self.m.signature_from_compact(sig)
    }
}

#[cfg(feature = "evm")]
#[uniffi::export]
impl Op {
    /// Whether `part` is a valid partial of `prepared`'s group on it (`bls12381-multi`, spec §5.4).
    pub fn bls_multi_part_ok(&self, prepared: Arc<Prepared>, part: BlsMultiPart) -> bool {
        self.m.bls_multi_part_ok(&prepared, &part)
    }
    /// Member `member`'s PoP part for its group's registration.
    pub fn bls_multi_pop_part(&self, member: KeyRef) -> Result<BlsMultiPart, SdkError> {
        self.m.bls_multi_pop_part(member)
    }
    /// Whether `part` is a valid PoP part of the group `key_data` (`0x` hex).
    pub fn bls_multi_pop_part_ok(&self, key_data: String, part: BlsMultiPart) -> bool {
        self.m.bls_multi_pop_part_ok(&key_data, &part)
    }
}

#[cfg(feature = "admin")]
#[uniffi::export]
impl Admin {
    /// A creation's CREATE3 addresses (`scaas-ua` `create3_address`).
    pub fn create3_address(
        &self,
        factory: String,
        creator_id: String,
        contract_class: u16,
        kind: u16,
        salt: String,
    ) -> Result<Create3Preview, SdkError> {
        self.m
            .create3_address(factory, creator_id, contract_class, kind, salt)
    }
}

#[cfg(feature = "evm")]
#[uniffi::export]
impl Prepared {
    /// The typed digest, the node's in-flight key too.
    #[uniffi::method(name = "id")]
    pub fn binding_id(&self) -> String {
        self.id()
    }
    #[uniffi::method(name = "chain")]
    pub fn binding_chain(&self) -> String {
        self.chain()
    }
    /// The contract function: `mtxPay`, `mtxCancelNonce`, …
    #[uniffi::method(name = "entry")]
    pub fn binding_entry(&self) -> String {
        self.entry()
    }
    #[uniffi::method(name = "review")]
    pub fn binding_review(&self) -> Vec<ReviewField> {
        self.review()
    }
    /// An undecoded call under `AllowOpaqueCall` (§13.2).
    #[uniffi::method(name = "opaque")]
    pub fn binding_opaque(&self) -> bool {
        self.opaque()
    }
    #[uniffi::method(name = "signer")]
    pub fn binding_signer(&self) -> KeyRef {
        self.signer()
    }
    /// The operation's `validUntil` (`u64::MAX`: none).
    #[uniffi::method(name = "expires_at")]
    pub fn binding_expires_at(&self) -> u64 {
        self.expires_at()
    }
}

#[cfg(feature = "dex")]
#[uniffi::export]
impl PreparedOrder {
    /// The order's hash (its typed digest).
    #[uniffi::method(name = "id")]
    pub fn binding_id(&self) -> String {
        self.id()
    }
    #[uniffi::method(name = "chain")]
    pub fn binding_chain(&self) -> String {
        self.chain()
    }
    #[uniffi::method(name = "review")]
    pub fn binding_review(&self) -> Vec<ReviewField> {
        self.review()
    }
    #[uniffi::method(name = "signer")]
    pub fn binding_signer(&self) -> KeyRef {
        self.signer()
    }
}

#[cfg(all(feature = "account", feature = "evm"))]
#[uniffi::export]
impl RegistryWrite {
    #[uniffi::method(name = "id")]
    pub fn binding_id(&self) -> String {
        self.id()
    }
    #[uniffi::method(name = "chain")]
    pub fn binding_chain(&self) -> String {
        self.chain()
    }
    #[uniffi::method(name = "entry")]
    pub fn binding_entry(&self) -> String {
        self.entry()
    }
    #[uniffi::method(name = "ua")]
    pub fn binding_ua(&self) -> String {
        self.ua()
    }
    #[uniffi::method(name = "review")]
    pub fn binding_review(&self) -> Vec<ReviewField> {
        self.review()
    }
    #[uniffi::method(name = "calldata")]
    pub fn binding_calldata(&self) -> String {
        self.calldata()
    }
    #[uniffi::method(name = "payer")]
    pub fn binding_payer(&self) -> KeyRef {
        self.payer()
    }
    /// A registration carrying its PQZ key's proof: one transaction or two, each step's gas (owner 2026-11-20).
    #[uniffi::method(name = "registration_gas")]
    pub fn binding_registration_gas(&self) -> Option<RegistrationGas> {
        self.registration_gas()
    }
}

#[uniffi::export]
impl SeedBackup {
    /// The words, once (`Argument` after), as a secret read through the copy call.
    #[uniffi::method(name = "reveal")]
    pub fn binding_reveal(&self) -> Result<Arc<SecretBytes>, SdkError> {
        self.reveal()
    }
    /// Three positions to ask (1-based).
    #[uniffi::method(name = "challenge")]
    pub fn binding_challenge(&self) -> Result<Vec<u32>, SdkError> {
        self.challenge()
    }
    /// The user's three words (a secret) against the challenge.
    #[uniffi::method(name = "verify")]
    pub fn binding_verify(&self, answers: Arc<SecretBytes>) -> Result<bool, SdkError> {
        self.verify(answers)
    }
}

/// The binding surface's version this library was built with (spec §16.3).
#[uniffi::export]
pub fn api_version() -> u32 {
    crate::API_VERSION
}

/// This library's feature bits (spec §3.3).
#[uniffi::export]
pub fn features() -> u64 {
    crate::features()
}

/// A new secret of `len` zero bytes (16 MiB at most); its bytes move only through the C copy calls by [`secret_id`].
#[uniffi::export]
pub fn secret_new(len: u32) -> Result<Arc<SecretBytes>, SdkError> {
    let len = usize::try_from(len).map_err(|_| SdkError::Argument)?;
    Ok(Arc::new(SecretBytes::new(len)?))
}

/// A secret's id for the C copy calls.
#[uniffi::export]
pub fn secret_id(s: Arc<SecretBytes>) -> u64 {
    s.id()
}

/// A secret's length in bytes.
#[uniffi::export]
pub fn secret_len(s: Arc<SecretBytes>) -> u32 {
    u32::try_from(s.len()).unwrap_or(u32::MAX)
}

/// The default limits (spec §4).
#[uniffi::export]
pub fn limits_default() -> Limits {
    Limits::default()
}

/// The default store policy of an item (spec §6.9).
#[uniffi::export]
pub fn store_policy_default() -> StorePolicy {
    StorePolicy::default()
}

/// Whether `s` is a UUID v4 (a seed's or an account's id).
#[uniffi::export]
pub fn is_uuid4(s: String) -> bool {
    keystore::is_uuid4(&s)
}

/// Whether `label` is a valid seed label (spec §6.1).
#[uniffi::export]
pub fn label_ok(label: String) -> bool {
    keystore::label_ok(&label)
}

/// Whether `label` is a valid new seed label (NFC, spec §6.1).
#[uniffi::export]
pub fn new_label_ok(label: String) -> bool {
    keystore::new_label_ok(&label)
}

/// The account rows' JSON (the keystore's form).
#[uniffi::export]
pub fn accounts_json(rows: Vec<AccountRow>) -> String {
    keystore::accounts_json(&rows)
}

/// The revision of an item's bytes: its top-level JSON `rev`, else `u64::MAX`.
#[uniffi::export]
pub fn rev_of(bytes: Vec<u8>) -> u64 {
    store::rev_of(&bytes)
}

/// Whether an operation's state is final.
#[uniffi::export]
pub fn op_state_is_terminal(state: crate::OpState) -> bool {
    state.is_terminal()
}

/// A gas table file (spec §13.3), parsed and checked.
#[uniffi::export]
pub fn gas_table_parse(text: String) -> Result<GasTable, SdkError> {
    GasTable::parse(&text)
}

/// No gas rows.
#[uniffi::export]
pub fn gas_rows_default() -> crate::GasRows {
    crate::GasRows::default()
}

/// No registration attributes (no PQZ key, no KEM key).
#[cfg(all(feature = "account", feature = "evm"))]
#[uniffi::export]
pub fn register_attrs_default() -> RegisterAttrs {
    RegisterAttrs::default()
}

/// An `msig` structure: members sorted by id, the threshold checked (spec §7).
#[cfg(all(feature = "account", feature = "evm"))]
#[uniffi::export]
pub fn msig_structure(
    members: Vec<MsigMemberArgs>,
    threshold: u16,
) -> Result<MsigStructureArgs, SdkError> {
    crate::account::msig::msig_structure(members, threshold)
}

/// An `msig` structure's UA.
#[cfg(all(feature = "account", feature = "evm"))]
#[uniffi::export]
pub fn msig_structure_ua(args: MsigStructureArgs) -> Result<String, SdkError> {
    args.ua()
}

/// A `SmartKeyAccount`'s address before its deployment (spec §7).
#[cfg(all(feature = "account", feature = "evm"))]
#[uniffi::export]
pub fn smart_account_address(
    factory: String,
    implementation: String,
    first_key: SubjectKeyArgs,
    guardian: String,
) -> Result<String, SdkError> {
    crate::account::smart_account_address(&factory, &implementation, &first_key, &guardian)
}

/// A secp256k1 subject key from its address.
#[cfg(all(feature = "account", feature = "evm"))]
#[uniffi::export]
pub fn subject_key_args_secp256k1(address: String) -> Result<SubjectKeyArgs, SdkError> {
    SubjectKeyArgs::secp256k1(&address)
}

/// A registration blob from its JSON (spec §7.1).
#[cfg(all(feature = "account", feature = "evm"))]
#[uniffi::export]
pub fn registration_blob_from_json(text: String) -> Result<RegistrationBlob, SdkError> {
    RegistrationBlob::from_json(&text)
}

/// A registration blob's JSON (spec §7.1).
#[cfg(all(feature = "account", feature = "evm"))]
#[uniffi::export]
pub fn registration_blob_to_json(blob: RegistrationBlob) -> Result<String, SdkError> {
    blob.to_json()
}

/// A signed operation's hand-off blob from its JSON (spec §27.5 (c)).
#[cfg(feature = "wallet")]
#[uniffi::export]
pub fn signed_op_blob_from_json(text: String) -> Result<SignedOpBlob, SdkError> {
    SignedOpBlob::from_json(&text)
}

/// A hand-off blob's JSON (spec §27.5 (c)).
#[cfg(feature = "wallet")]
#[uniffi::export]
pub fn signed_op_blob_to_json(blob: SignedOpBlob) -> Result<String, SdkError> {
    blob.to_json()
}

/// The target of a key write of the UA (`UaLine::key_target`, §12): its holder.
#[cfg(feature = "evm")]
#[uniffi::export]
pub fn ua_line_key_target(line: crate::UaLine) -> String {
    line.key_target()
}

/// The target of a PQZ write of the UA (`UaLine::pqz_target`, §12): its PQZ home; `PqzHomeNone` where the walk has none.
#[cfg(feature = "evm")]
#[uniffi::export]
pub fn ua_line_pqz_target(line: crate::UaLine) -> Result<String, SdkError> {
    line.pqz_target()
}

/// A binding's configuration (spec §4): the profiles, the passkey RP ID, the limits, the module gas tables; the runtime is the
/// SDK's own (`RuntimeChoice::Own`) and the clock the device's. `expect_api` and `need_features` are the binding's load check
/// (spec §16.3): the `api_version` it was generated against and the feature bits it needs; the opening refuses another
/// library with `AbiMismatch`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct BindingConfig {
    pub expect_api: u32,
    pub need_features: u64,
    pub profiles: Vec<ChainProfile>,
    pub rp_id: Option<String>,
    pub limits: Limits,
    pub gas_tables: Vec<GasTable>,
}

impl BindingConfig {
    pub(crate) fn sdk_config(
        self,
        store: Arc<dyn SecureStore>,
        authenticator: Option<Arc<dyn Authenticator>>,
    ) -> Result<crate::SdkConfig, SdkError> {
        crate::load_check(self.expect_api, self.need_features)?;
        Ok(crate::SdkConfig {
            profiles: self.profiles,
            store,
            authenticator,
            rp_id: self.rp_id,
            runtime: crate::RuntimeChoice::Own,
            limits: self.limits,
            clock: None,
            gas_tables: self.gas_tables,
        })
    }
}

/// The app's store (spec §6.9) as a foreign async interface: `lock` answers a token that `unlock` releases when the SDK drops
/// the lock. A foreign exception arrives as `StoreError::Unexpected`.
#[cfg(not(feature = "sync-api"))]
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait ForeignStore: Send + Sync {
    async fn get(&self, name: String, reason: String) -> Result<Option<StoredItem>, StoreError>;
    async fn put_if(
        &self,
        name: String,
        prev_rev: Option<u64>,
        bytes: Vec<u8>,
        policy: StorePolicy,
    ) -> Result<(), StoreError>;
    async fn delete(&self, name: String) -> Result<(), StoreError>;
    async fn lock(&self, name: String) -> Result<u64, StoreError>;
    async fn unlock(&self, token: u64);
}

/// The app's authenticator (spec §6.10) as a foreign async interface. A PRF output or platform secret is written by the app
/// through the copy calls into the secret whose id it is given (`prf_out`, `out`). A foreign exception arrives as
/// `AuthError::Unexpected`.
#[cfg(not(feature = "sync-api"))]
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait ForeignAuthenticator: Send + Sync {
    async fn create_passkey(
        &self,
        rp_id: String,
        user_name: String,
        exclude: Vec<Vec<u8>>,
    ) -> Result<PasskeyCreated, AuthError>;
    async fn get_assertion(
        &self,
        req: AssertionRequest,
        prf_out: u64,
    ) -> Result<Assertion, AuthError>;
    /// `key_handle`: the platform key's handle (the Rust trait's `handle`; named apart from the generated callbacks' own local
    /// `handle`, which uniffi-bindgen-cs and -go do not rename)
    async fn platform_secret(
        &self,
        key_handle: String,
        salt: Vec<u8>,
        reason: String,
        policy: Option<KeyPolicy>,
        out: u64,
    ) -> Result<(), AuthError>;
    async fn p256_generate(&self, policy: KeyPolicy) -> Result<SePublic, AuthError>;
    async fn p256_sign(
        &self,
        key_handle: String,
        ua_msg: Vec<u8>,
        reason: String,
    ) -> Result<Vec<u8>, AuthError>;
}

#[cfg(not(feature = "sync-api"))]
struct StoreAdapter(Arc<dyn ForeignStore>);

#[cfg(not(feature = "sync-api"))]
struct Release(u64, Arc<dyn ForeignStore>);

#[cfg(not(feature = "sync-api"))]
impl Drop for Release {
    fn drop(&mut self) {
        // the release runs on the runtime that dropped the lock (every SDK call runs on one)
        let (token, store) = (self.0, self.1.clone());
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            h.spawn(async move { store.unlock(token).await });
        }
    }
}

#[cfg(not(feature = "sync-api"))]
#[async_trait]
impl SecureStore for StoreAdapter {
    async fn get(&self, name: String, reason: String) -> Result<Option<StoredItem>, StoreError> {
        self.0.get(name, reason).await
    }
    async fn put_if(
        &self,
        name: String,
        prev_rev: Option<u64>,
        bytes: Vec<u8>,
        policy: StorePolicy,
    ) -> Result<(), StoreError> {
        self.0.put_if(name, prev_rev, bytes, policy).await
    }
    async fn delete(&self, name: String) -> Result<(), StoreError> {
        self.0.delete(name).await
    }
    async fn lock(&self, name: String) -> Result<Arc<StoreLock>, StoreError> {
        let token = self.0.lock(name).await?;
        Ok(StoreLock::new(Box::new(Release(token, self.0.clone()))))
    }
}

#[cfg(not(feature = "sync-api"))]
struct AuthAdapter(Arc<dyn ForeignAuthenticator>);

#[cfg(not(feature = "sync-api"))]
#[async_trait]
impl Authenticator for AuthAdapter {
    async fn create_passkey(
        &self,
        rp_id: String,
        user_name: String,
        exclude: Vec<Vec<u8>>,
    ) -> Result<PasskeyCreated, AuthError> {
        self.0.create_passkey(rp_id, user_name, exclude).await
    }
    async fn get_assertion(
        &self,
        req: AssertionRequest,
        prf_out: Arc<SecretBytes>,
    ) -> Result<Assertion, AuthError> {
        self.0.get_assertion(req, prf_out.id()).await
    }
    async fn platform_secret(
        &self,
        handle: String,
        salt: Vec<u8>,
        reason: String,
        policy: Option<KeyPolicy>,
        out: Arc<SecretBytes>,
    ) -> Result<(), AuthError> {
        self.0
            .platform_secret(handle, salt, reason, policy, out.id())
            .await
    }
    async fn p256_generate(&self, policy: KeyPolicy) -> Result<SePublic, AuthError> {
        self.0.p256_generate(policy).await
    }
    async fn p256_sign(
        &self,
        handle: String,
        ua_msg: Vec<u8>,
        reason: String,
    ) -> Result<Vec<u8>, AuthError> {
        self.0.p256_sign(handle, ua_msg, reason).await
    }
}

/// Opens the SDK (spec §4) over the app's store and authenticator, on the SDK's own runtime. `AbiMismatch` is the binding's
/// load check (spec §16.3), run before this.
#[cfg(not(feature = "sync-api"))]
#[uniffi::export]
pub async fn open(
    config: BindingConfig,
    store: Arc<dyn ForeignStore>,
    authenticator: Option<Arc<dyn ForeignAuthenticator>>,
) -> Result<Arc<Sdk>, SdkError> {
    let auth = authenticator.map(|a| Arc::new(AuthAdapter(a)) as Arc<dyn Authenticator>);
    let config = config.sdk_config(Arc::new(StoreAdapter(store)), auth)?;
    // `Sdk::open` starts the runtime; its one read of the keystore is awaited here, on the caller's executor (it takes no
    // store lock and needs no reactor; spec §14)
    Ok(Sdk::new(crate::Sdk::open(config).await?))
}

/// Review B2: a refused lift is the SDK's code (UniFFI hands the call's error type only an error that downcasts to it).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use uniffi::{Lift, Lower};

    #[test]
    fn a_refused_lift_is_the_sdk_code() {
        let code = |e: uniffi::deps::anyhow::Error| e.downcast::<SdkError>().ok().map(|e| e.code());
        #[cfg(all(feature = "evm", not(feature = "opaque-calls")))]
        {
            let e = <AllowOpaqueCall as Lift<crate::UniFfiTag>>::try_lift(1)
                .err()
                .unwrap();
            assert_eq!(code(e), Some("OpaqueCallRefused"));
        }
        let bad = <String as Lower<crate::UniFfiTag>>::lower("{not json".into());
        let e = <Value as Lift<crate::UniFfiTag>>::try_lift(bad)
            .err()
            .unwrap();
        assert_eq!(code(e), Some("Argument"));
        // the endpoint credential goes in and never comes back out: it lowers to the empty string (review B15)
        let cred =
            <scaas_rpc::endpoint::Secret as Lower<crate::UniFfiTag>>::lower(Secret::new("token-1"));
        assert_eq!(
            <String as Lift<crate::UniFfiTag>>::try_lift(cred).unwrap(),
            ""
        );
        // control: text that parses lifts
        let good = <String as Lower<crate::UniFfiTag>>::lower("{\"a\":1}".into());
        assert!(<Value as Lift<crate::UniFfiTag>>::try_lift(good).is_ok());
    }
}
