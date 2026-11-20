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

#[cfg(feature = "account")]
#[allow(unused_imports)]
use crate::account::{msig::*, smart::*, *};
#[cfg(feature = "admin")]
use crate::admin::{delay::*, *};
#[cfg(any(feature = "zether", feature = "pqz"))]
use crate::confidential::*;
#[cfg(feature = "dex")]
use crate::dex::*;
#[cfg(feature = "wallet")]
use crate::op::*;
use crate::platform::*;
use crate::vault::*;
#[cfg(feature = "wallet")]
use crate::wallet::*;
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
    try_lift: |s| Ok(serde_json::from_str(&s)?),
});

// the opaque-call marker (spec §13.2): `true` lifts only in a build with `opaque-calls`, as the Rust marker is constructible
#[cfg(feature = "wallet")]
uniffi::custom_type!(AllowOpaqueCall, bool, {
    lower: |_m| true,
    try_lift: |b| marker(b),
});

#[cfg(all(feature = "wallet", feature = "opaque-calls"))]
fn marker(b: bool) -> uniffi::Result<AllowOpaqueCall> {
    if b {
        Ok(AllowOpaqueCall::new())
    } else {
        Err(uniffi::deps::anyhow::anyhow!("OpaqueCallRefused"))
    }
}

#[cfg(all(feature = "wallet", not(feature = "opaque-calls")))]
fn marker(_b: bool) -> uniffi::Result<AllowOpaqueCall> {
    Err(uniffi::deps::anyhow::anyhow!("OpaqueCallRefused"))
}

// `KeyRef` and `MsigSlot` hold each other (an `msig` signer's slots hold keys), and uniffi-bindgen-cpp refuses any cycle among
// records and enums. So a slot crosses every binding as `MsigSlotValue`, its keys `SlotKey`: a `KeyRef` whose `Msig` names the
// UA only. A slot's key is never an `msig` (spec §7: `Argument` at signing), so the lift loses nothing the SDK would take; the
// lowering of such a key (never made by a binding) keeps its UA and drops its slots.
#[cfg(feature = "wallet")]
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
#[cfg(feature = "wallet")]
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
#[cfg(feature = "wallet")]
#[derive(uniffi::Record)]
pub struct MsigLeafValue {
    pub index: u16,
    pub key: SlotKey,
}

/// A slot's key: `KeyRef` without the slots of an `msig` (a slot's key is never one, spec §7).
#[cfg(feature = "wallet")]
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
}

#[cfg(feature = "wallet")]
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
        }
    }
}

#[cfg(feature = "wallet")]
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

surface! {
    /// The SDK (spec §4): the module accessors, events, watching.
    object Sdk = crate::Sdk {
        #[cfg(feature = "wallet")] async watch / watch_blocking (account: String, chains: Vec<String>) -> ();
        #[cfg(feature = "wallet")] async state_rev / state_rev_blocking () -> u64;
    }
    /// Seeds (spec §6).
    object Vault = crate::vault::Vault {
        async enable_passkey_unlock / enable_passkey_unlock_blocking (seed: String, vault_passphrase: Arc<SecretBytes>) -> ();
        async enable_platform_unlock / enable_platform_unlock_blocking (seed: String, vault_passphrase: Arc<SecretBytes>, policy: KeyPolicy) -> ();
        async disable_prf_unlock / disable_prf_unlock_blocking (seed: String) -> ();
        async change_passphrase / change_passphrase_blocking (seed: String, old: Arc<SecretBytes>, new: Arc<SecretBytes>) -> ();
        #[cfg(feature = "classical-roots")] async derive_from_signature / derive_from_signature_blocking (req: DeriveFromSignature) -> NewSeed;
        #[cfg(feature = "classical-roots")] async derive_from_key / derive_from_key_blocking (req: DeriveFromKey) -> NewSeed;
        async keystore_rollback / keystore_rollback_blocking () -> bool;
        async seeds / seeds_blocking () -> Vec<SeedInfo>;
        async generate / generate_blocking (req: Generate) -> NewSeed;
        async derive_child / derive_child_blocking (req: DeriveChild) -> NewSeed;
        async import_words / import_words_blocking (req: ImportWords) -> SeedInfo;
        async import_key / import_key_blocking (req: ImportKey) -> ImportedKey;
        async confirm_backup / confirm_backup_blocking (seed: String) -> ();
        async rename / rename_blocking (seed: String, label: String) -> ();
        async remove / remove_blocking (req: Remove) -> ();
        async unlock / unlock_blocking (seed: String, unlock: Unlock) -> ();
        async open_hidden / open_hidden_blocking (seed: String, unlock: Unlock, bip39_passphrase: Arc<SecretBytes>) -> SessionSet;
        async seed / seed_blocking (seed: String) -> SeedInfo;
    }
    /// Accounts (spec §7).
    #[cfg(feature = "account")]
    object Account = crate::account::Account {
        async accounts / accounts_blocking (seed: String) -> Vec<AccountInfo>;
        async next_account / next_account_blocking (seed: String) -> u32;
        async add_ua / add_ua_blocking (req: AddUa) -> AccountInfo;
        async add_native / add_native_blocking (req: AddNative) -> AccountInfo;
        #[cfg(feature = "wallet")] async create_passkey_key / create_passkey_key_blocking (req: CreatePasskeyKey) -> KeyRef;
        #[cfg(feature = "wallet")] async create_se_key / create_se_key_blocking (req: CreateSeKey) -> KeyRef;
        async add_watch / add_watch_blocking (req: AddWatch) -> AccountInfo;
        async signs / signs_blocking (seed: String, id: String) -> bool;
        #[cfg(feature = "wallet")] async msig_state / msig_state_blocking (chain: String, ua: String) -> MsigState;
        #[cfg(feature = "wallet")] async prepare_msig_register / prepare_msig_register_blocking (req: MsigRegister) -> Vec<Arc<RegistryWrite>>;
        #[cfg(feature = "wallet")] async prepare_accept_membership / prepare_accept_membership_blocking (req: AcceptMembership) -> Option<Arc<RegistryWrite>>;
        #[cfg(feature = "wallet")] async prepare_update_msig / prepare_update_msig_blocking (req: UpdateMsig) -> MsigUpdatePlan;
        #[cfg(feature = "wallet")] async prepare_register / prepare_register_blocking (req: Register) -> Vec<Arc<RegistryWrite>>;
        #[cfg(feature = "wallet")] async quote_registry_write / quote_registry_write_blocking (write: Arc<RegistryWrite>) -> SubmitQuote;
        #[cfg(feature = "wallet")] async submit_registry_write / submit_registry_write_blocking (write: Arc<RegistryWrite>, quote: SubmitQuote) -> String;
        #[cfg(feature = "wallet")] async registration_of / registration_of_blocking (chain: String, ua: String) -> RegistrationState;
        #[cfg(feature = "wallet")] async prepare_kem_repair / prepare_kem_repair_blocking (key: KeyRef, chain: String, payer: KeyRef) -> Option<Arc<RegistryWrite>>;
        async marks / marks_blocking (seed: String, chain: String) -> Vec<AccountInfo>;
        async restore / restore_blocking (req: Restore) -> Vec<AccountInfo>;
        #[cfg(feature = "wallet")] async prepare_smart_add_key / prepare_smart_add_key_blocking (op: SmartOp, key: SubjectKeyArgs) -> Arc<Prepared>;
        #[cfg(feature = "wallet")] async prepare_smart_remove_key / prepare_smart_remove_key_blocking (op: SmartOp, index: String) -> Arc<Prepared>;
        #[cfg(feature = "wallet")] async prepare_smart_rotate_key / prepare_smart_rotate_key_blocking (op: SmartOp, index: String, key: SubjectKeyArgs) -> Arc<Prepared>;
        #[cfg(feature = "wallet")] async prepare_smart_set_guardian / prepare_smart_set_guardian_blocking (op: SmartOp, guardian: String) -> Arc<Prepared>;
        #[cfg(feature = "wallet")] async prepare_smart_cancel_recovery / prepare_smart_cancel_recovery_blocking (op: SmartOp) -> Arc<Prepared>;
        #[cfg(feature = "wallet")] async prepare_smart_cancel_nonce / prepare_smart_cancel_nonce_blocking (op: SmartOp, lane: String) -> Arc<Prepared>;
        #[cfg(feature = "wallet")] async prepare_smart_execute / prepare_smart_execute_blocking (op: SmartOp, call: SmartCall) -> Arc<Prepared>;
        #[cfg(feature = "wallet")] async prepare_smart_deploy / prepare_smart_deploy_blocking (key: KeyRef, chain: String, factory: String, first_key: SubjectKeyArgs, guardian: String) -> NativeQuote;
        #[cfg(feature = "wallet")] async prepare_complete_recovery / prepare_complete_recovery_blocking (key: KeyRef, chain: String, account: String, new_key: SubjectKeyArgs) -> NativeQuote;
        #[cfg(feature = "wallet")] async prepare_initiate_recovery / prepare_initiate_recovery_blocking (op: SmartOp, account: String, new_key: SubjectKeyArgs) -> Arc<Prepared>;
        #[cfg(feature = "wallet")] async registration_blob / registration_blob_blocking (key: KeyRef, attrs: RegisterAttrs) -> RegistrationBlob;
        #[cfg(feature = "wallet")] async prepare_submit_registration / prepare_submit_registration_blocking (blob: RegistrationBlob, chain: String, expected_ua: String, payer: KeyRef) -> Vec<Arc<RegistryWrite>>;
    }
    /// Tokens, balances, payments (spec §8).
    #[cfg(feature = "wallet")]
    object Wallet = crate::wallet::Wallet {
        async balances / balances_blocking (id: String, chain: String) -> Balances;
        async history / history_blocking (account: String, chain: String, before: Option<Cursor>, limit: u32) -> HistoryPage;
        async native_address / native_address_blocking (key: NativeKeyRef, ss58_prefix: Option<u16>) -> NativeAddress;
        async prepare_native_send / prepare_native_send_blocking (req: NativeSend) -> NativeQuote;
        async submit_native_send / submit_native_send_blocking (q: NativeQuote) -> String;
        async prepare_transfer / prepare_transfer_blocking (req: Transfer) -> Arc<Prepared>;
        async prepare_pay / prepare_pay_blocking (req: Pay) -> Arc<Prepared>;
        async prepare_pay_with_tax / prepare_pay_with_tax_blocking (req: PayWithTax) -> Arc<Prepared>;
        async prepare_payee_fee / prepare_payee_fee_blocking (req: PayeeFee) -> Arc<Prepared>;
        async prepare_pay_under_mandate / prepare_pay_under_mandate_blocking (req: PayUnderMandate) -> Arc<Prepared>;
        async prepare_relay_fee / prepare_relay_fee_blocking (req: RelayFee) -> Arc<Prepared>;
        async prepare_execute / prepare_execute_blocking (req: Execute) -> Arc<Prepared>;
        async tokens / tokens_blocking (chain: String, with_index: bool) -> Vec<TokenInfo>;
        async prepare_cancel_nonce / prepare_cancel_nonce_blocking (req: CancelNonce) -> Arc<Prepared>;
        async prepare_burn / prepare_burn_blocking (req: Burn) -> Arc<Prepared>;
        async prepare_wrap / prepare_wrap_blocking (req: Wrap) -> Arc<Prepared>;
        async prepare_wrap_leg / prepare_wrap_leg_blocking (req: WrapLeg) -> Arc<Prepared>;
        async prepare_unwrap / prepare_unwrap_blocking (req: Unwrap) -> Arc<Prepared>;
        async prepare_unwrap_leg / prepare_unwrap_leg_blocking (req: UnwrapLeg) -> Arc<Prepared>;
        async prepare_add_reserve / prepare_add_reserve_blocking (req: AddReserve) -> Arc<Prepared>;
        async prepare_wrap_to_ua / prepare_wrap_to_ua_blocking (req: WrapToUa) -> Arc<Prepared>;
        async prepare_unwrap_to_ua / prepare_unwrap_to_ua_blocking (req: UnwrapToUa) -> Arc<Prepared>;
        async prepare_set_mandate / prepare_set_mandate_blocking (req: SetMandate) -> Arc<Prepared>;
        async prepare_set_payee / prepare_set_payee_blocking (req: SetPayee) -> Arc<Prepared>;
        async prepare_revoke_mandate / prepare_revoke_mandate_blocking (req: RevokeMandate) -> Arc<Prepared>;
        async prepare_delegate_revoke / prepare_delegate_revoke_blocking (req: DelegateRevoke) -> Arc<Prepared>;
    }
    /// Operations: quote, submit, follow (spec §13).
    #[cfg(feature = "wallet")]
    object Op = crate::op::Op {
        #[cfg(feature = "account")] async member_sign / member_sign_blocking (prepared: Arc<Prepared>) -> String;
        async state / state_blocking (op: String) -> OpState;
        async quote / quote_blocking (prepared: Arc<Prepared>, path: SubmitPath) -> SubmitQuote;
        async quote_with_gas / quote_with_gas_blocking (prepared: Arc<Prepared>, path: SubmitPath, gas: u64) -> SubmitQuote;
        async submit / submit_blocking (prepared: Arc<Prepared>, quote: SubmitQuote) -> String;
        async resume / resume_blocking () -> u32;
        async resend / resend_blocking (op: String, quote: SubmitQuote) -> ();
    }
    /// Zether and PQZ (spec §9).
    #[cfg(any(feature = "zether", feature = "pqz"))]
    object Confidential = crate::confidential::Confidential {
        #[cfg(feature = "zether")] async zether_key / zether_key_blocking (seed: String, account: u32) -> ZetherKeyInfo;
        #[cfg(feature = "zether")] async zether_balance / zether_balance_blocking (req: ZetherBalanceRequest) -> ZetherBalance;
        #[cfg(feature = "pqz")] async pqz_balance / pqz_balance_blocking (r: PqzBalanceRequest) -> PqzBalance;
        #[cfg(feature = "pqz")] async pqz_balance_all / pqz_balance_all_blocking (r: PqzBalanceRequest) -> PqzBalanceAll;
        #[cfg(feature = "pqz")] async prepare_pqz_shield / prepare_pqz_shield_blocking (r: PqzShield) -> Arc<Prepared>;
        #[cfg(feature = "pqz")] async prepare_pqz_wrap_shield / prepare_pqz_wrap_shield_blocking (r: PqzWrapShield) -> Arc<Prepared>;
        #[cfg(feature = "pqz")] async prepare_pqz_prepare_acc / prepare_pqz_prepare_acc_blocking (r: PqzAccountOp) -> Arc<Prepared>;
        #[cfg(feature = "pqz")] async prepare_pqz_roll_over / prepare_pqz_roll_over_blocking (r: PqzAccountOp) -> Arc<Prepared>;
        #[cfg(feature = "pqz")] async prepare_pqz_transfer / prepare_pqz_transfer_blocking (r: PqzTransfer) -> Arc<Prepared>;
        #[cfg(feature = "pqz")] async prepare_pqz_transfer_compact / prepare_pqz_transfer_compact_blocking (r: PqzTransfer) -> Arc<Prepared>;
        #[cfg(feature = "pqz")] async prepare_pqz_transfer_multi / prepare_pqz_transfer_multi_blocking (r: PqzTransferMulti) -> Arc<Prepared>;
        #[cfg(feature = "pqz")] async prepare_pqz_transfer_multi_compact / prepare_pqz_transfer_multi_compact_blocking (r: PqzTransferMulti) -> Arc<Prepared>;
        #[cfg(feature = "pqz")] async prepare_pqz_unshield / prepare_pqz_unshield_blocking (r: PqzUnshield) -> Arc<Prepared>;
        #[cfg(feature = "pqz")] async prepare_pqz_unshield_unwrap / prepare_pqz_unshield_unwrap_blocking (r: PqzUnshieldUnwrap) -> Arc<Prepared>;
        #[cfg(feature = "pqz")] async request_verdict / request_verdict_blocking (r: PqzVerdictRequest) -> Value;
        #[cfg(feature = "zether")] async prepare_zether_shield / prepare_zether_shield_blocking (r: ZetherShield) -> Arc<Prepared>;
        #[cfg(feature = "zether")] async prepare_zether_wrap_shield / prepare_zether_wrap_shield_blocking (r: ZetherWrapShield) -> Arc<Prepared>;
        #[cfg(feature = "zether")] async prepare_zether_roll_over / prepare_zether_roll_over_blocking (r: ZetherRollOver) -> Arc<Prepared>;
        #[cfg(feature = "zether")] async prepare_zether_roll_over_batch / prepare_zether_roll_over_batch_blocking (r: ZetherRollOverBatch) -> Arc<Prepared>;
        #[cfg(feature = "zether")] async prepare_zether_transfer / prepare_zether_transfer_blocking (r: ZetherTransfer) -> Arc<Prepared>;
        #[cfg(feature = "zether")] async prepare_zether_unshield / prepare_zether_unshield_blocking (r: ZetherUnshield) -> Arc<Prepared>;
        #[cfg(feature = "zether")] async prepare_zether_unshield_unwrap / prepare_zether_unshield_unwrap_blocking (r: ZetherUnshieldUnwrap) -> Arc<Prepared>;
        #[cfg(feature = "zether")] async prepare_zether_transfer_multi / prepare_zether_transfer_multi_blocking (r: ZetherTransferMulti) -> Arc<Prepared>;
        #[cfg(feature = "zether")] async prepare_zether_transfer_compact / prepare_zether_transfer_compact_blocking (r: ZetherTransferMulti) -> Arc<Prepared>;
        #[cfg(feature = "zether")] async prepare_zether_owner_roll_over / prepare_zether_owner_roll_over_blocking (r: ZetherOwnerRollOver) -> Arc<Prepared>;
        #[cfg(feature = "zether")] async prepare_zether_roll_over_signed / prepare_zether_roll_over_signed_blocking (r: ZetherOwnerRollOver, relay: OwnerRelay) -> Arc<Prepared>;
        #[cfg(feature = "zether")] async prepare_zether_owner_set_mode / prepare_zether_owner_set_mode_blocking (r: ZetherOwnerSetMode) -> Arc<Prepared>;
        #[cfg(feature = "zether")] async prepare_zether_set_roll_over_mode / prepare_zether_set_roll_over_mode_blocking (r: ZetherOwnerSetMode, relay: OwnerRelay) -> Arc<Prepared>;
    }
    /// The DEX (spec §10).
    #[cfg(feature = "dex")]
    object Dex = crate::dex::Dex {
        async markets / markets_blocking (chain: String) -> String;
        async depth / depth_blocking (chain: String, market: i64, levels: Option<u32>) -> String;
        async trades / trades_blocking (chain: String, market: i64) -> String;
        async ticker / ticker_blocking (chain: String, market: i64) -> String;
        async orders / orders_blocking (chain: String, maker: String) -> String;
        async prepare_trade_order / prepare_trade_order_blocking (req: TradeOrder) -> Arc<PreparedOrder>;
        async sign_order / sign_order_blocking (order: Arc<PreparedOrder>) -> SignedOrder;
        async place / place_blocking (order: Arc<PreparedOrder>) -> String;
        async cancel_all / cancel_all_blocking (req: CancelAll) -> String;
        async prepare_cancel_order / prepare_cancel_order_blocking (req: CancelOrder) -> Arc<Prepared>;
        async prepare_cancel_wrap_order / prepare_cancel_wrap_order_blocking (req: CancelWrapOrder) -> Arc<Prepared>;
        async prepare_wrap_order / prepare_wrap_order_blocking (req: WrapOrder) -> Arc<Prepared>;
        async prepare_liquidity_order / prepare_liquidity_order_blocking (req: LiquidityOrder) -> Arc<PreparedOrder>;
    }
    /// Governance and admin rows (spec §11).
    #[cfg(feature = "admin")]
    object Admin = crate::admin::Admin {
        async sign_rescue_vault / sign_rescue_vault_blocking (req: RescueVault) -> SignedRescue;
        async sign_pqz_auditor_consent / sign_pqz_auditor_consent_blocking (req: AuditorConsent) -> String;
        async sign_zether_auditor_consent / sign_zether_auditor_consent_blocking (req: AuditorConsent) -> String;
        async governance_delay / governance_delay_blocking (chain: String, token: String, bit: u16, holder: Option<HolderKind>) -> Vec<DelaySentence>;
        async admin_ua_grant_role / admin_ua_grant_role_blocking (req: UaGrantRole) -> Arc<Prepared>;
        async admin_ua_revoke_role / admin_ua_revoke_role_blocking (req: UaRevokeRole) -> Arc<Prepared>;
        async admin_ua_set_grant / admin_ua_set_grant_blocking (req: UaSetGrant) -> Arc<Prepared>;
        async admin_ua_cancel_grant / admin_ua_cancel_grant_blocking (req: UaCancelGrant) -> Arc<Prepared>;
        async admin_ua_disable_feature / admin_ua_disable_feature_blocking (req: UaDisableFeature) -> Arc<Prepared>;
        async admin_ua_transfer_admin / admin_ua_transfer_admin_blocking (req: UaTransferAdmin) -> Arc<Prepared>;
        async admin_ua_accept_admin / admin_ua_accept_admin_blocking (req: UaAcceptAdmin) -> Arc<Prepared>;
        async admin_ua_renounce_admin / admin_ua_renounce_admin_blocking (req: UaRenounceAdmin) -> Arc<Prepared>;
        async admin_ua_renounce_role / admin_ua_renounce_role_blocking (req: UaRenounceRole) -> Arc<Prepared>;
        async admin_ua_mint / admin_ua_mint_blocking (req: UaMint) -> Arc<Prepared>;
        async admin_ua_mint_to_ua / admin_ua_mint_to_ua_blocking (req: UaMintToUA) -> Arc<Prepared>;
        async admin_ua_disable_wrap / admin_ua_disable_wrap_blocking (req: UaDisableWrap) -> Arc<Prepared>;
        async admin_ua_propose_rate / admin_ua_propose_rate_blocking (req: UaProposeRate) -> Arc<Prepared>;
        async admin_ua_cancel_rate / admin_ua_cancel_rate_blocking (req: UaCancelRate) -> Arc<Prepared>;
        async admin_ua_execute_rate / admin_ua_execute_rate_blocking (req: UaExecuteRate) -> Arc<Prepared>;
        async admin_ua_set_market / admin_ua_set_market_blocking (req: UaSetMarket) -> Arc<Prepared>;
        async admin_ua_set_exchange_target / admin_ua_set_exchange_target_blocking (req: UaSetExchangeTarget) -> Arc<Prepared>;
        async admin_ua_set_listed_only / admin_ua_set_listed_only_blocking (req: UaSetListedOnly) -> Arc<Prepared>;
        async admin_ua_set_fee_split / admin_ua_set_fee_split_blocking (req: UaSetFeeSplit) -> Arc<Prepared>;
        async admin_ua_freeze / admin_ua_freeze_blocking (req: UaFreeze) -> Arc<Prepared>;
        async admin_ua_unfreeze / admin_ua_unfreeze_blocking (req: UaUnfreeze) -> Arc<Prepared>;
        async admin_ua_force_transfer / admin_ua_force_transfer_blocking (req: UaForceTransfer) -> Arc<Prepared>;
        async admin_ua_pause / admin_ua_pause_blocking (req: UaPause) -> Arc<Prepared>;
        async admin_ua_unpause / admin_ua_unpause_blocking (req: UaUnpause) -> Arc<Prepared>;
        async admin_ua_record_order / admin_ua_record_order_blocking (req: UaRecordOrder) -> Arc<Prepared>;
        async admin_ua_revoke_order / admin_ua_revoke_order_blocking (req: UaRevokeOrder) -> Arc<Prepared>;
        async admin_ua_operator_transfer / admin_ua_operator_transfer_blocking (req: UaOperatorTransfer) -> Arc<Prepared>;
        async admin_ua_set_tax_rate / admin_ua_set_tax_rate_blocking (req: UaSetTaxRate) -> Arc<Prepared>;
        async admin_ua_set_tax_recipient / admin_ua_set_tax_recipient_blocking (req: UaSetTaxRecipient) -> Arc<Prepared>;
        async admin_ua_pqz_set_verifier / admin_ua_pqz_set_verifier_blocking (req: UaPqzSetVerifier) -> Arc<Prepared>;
        async admin_ua_pqz_cancel_verifier / admin_ua_pqz_cancel_verifier_blocking (req: UaPqzCancelVerifier) -> Arc<Prepared>;
        async admin_ua_pqz_revoke_verifier / admin_ua_pqz_revoke_verifier_blocking (req: UaPqzRevokeVerifier) -> Arc<Prepared>;
        async admin_ua_set_proof_store / admin_ua_set_proof_store_blocking (req: UaSetProofStore) -> Arc<Prepared>;
        async admin_ua_set_auditor_key / admin_ua_set_auditor_key_blocking (req: UaSetAuditorKey) -> Arc<Prepared>;
        async admin_ua_set_auditor_ua / admin_ua_set_auditor_ua_blocking (req: UaSetAuditorUA) -> Arc<Prepared>;
        async admin_ua_set_verifier_fee / admin_ua_set_verifier_fee_blocking (req: UaSetVerifierFee) -> Arc<Prepared>;
        async admin_ua_set_wrap_limits / admin_ua_set_wrap_limits_blocking (req: UaSetWrapLimits) -> Arc<Prepared>;
        async admin_ua_set_wrap_member / admin_ua_set_wrap_member_blocking (req: UaSetWrapMember) -> Arc<Prepared>;
        async admin_ua_set_max_supply / admin_ua_set_max_supply_blocking (req: UaSetMaxSupply) -> Arc<Prepared>;
        async admin_ua_set_max_wrap_supply / admin_ua_set_max_wrap_supply_blocking (req: UaSetMaxWrapSupply) -> Arc<Prepared>;
        async admin_ua_set_allowed / admin_ua_set_allowed_blocking (req: UaSetAllowed) -> Arc<Prepared>;
        async admin_ua_set_denied / admin_ua_set_denied_blocking (req: UaSetDenied) -> Arc<Prepared>;
        async admin_ua_enable_feature / admin_ua_enable_feature_blocking (req: UaEnableFeature) -> Arc<Prepared>;
        async admin_ua_publish_token_env / admin_ua_publish_token_env_blocking (req: UaPublishTokenEnv) -> Arc<Prepared>;
        async admin_ua_publish_dex_env / admin_ua_publish_dex_env_blocking (req: UaPublishDexEnv) -> Arc<Prepared>;
        async admin_ua_publish_class_env / admin_ua_publish_class_env_blocking (req: UaPublishClassEnv) -> Arc<Prepared>;
        async admin_ua_deprecate_token / admin_ua_deprecate_token_blocking (req: UaDeprecateToken) -> Arc<Prepared>;
        async admin_ua_deprecate_dex / admin_ua_deprecate_dex_blocking (req: UaDeprecateDex) -> Arc<Prepared>;
        async admin_ua_deprecate_release / admin_ua_deprecate_release_blocking (req: UaDeprecateRelease) -> Arc<Prepared>;
        async admin_ua_set_token_kind_enabled / admin_ua_set_token_kind_enabled_blocking (req: UaSetTokenKindEnabled) -> Arc<Prepared>;
        async admin_ua_set_class_kind_enabled / admin_ua_set_class_kind_enabled_blocking (req: UaSetClassKindEnabled) -> Arc<Prepared>;
        async admin_ua_set_kyc_provider / admin_ua_set_kyc_provider_blocking (req: UaSetKycProvider) -> Arc<Prepared>;
        async admin_ua_set_compliance / admin_ua_set_compliance_blocking (req: UaSetCompliance) -> Arc<Prepared>;
        async admin_ua_create_token / admin_ua_create_token_blocking (req: UaCreateToken) -> Arc<Prepared>;
        async admin_ua_create_dex / admin_ua_create_dex_blocking (req: UaCreateDex) -> Arc<Prepared>;
        async admin_ua_create_instance / admin_ua_create_instance_blocking (req: UaCreateInstance) -> Arc<Prepared>;
        async admin_ua_set_chain_entries / admin_ua_set_chain_entries_blocking (req: UaSetChainEntries) -> Arc<Prepared>;
        async admin_ua_approve_token_release / admin_ua_approve_token_release_blocking (req: UaApproveTokenRelease) -> Arc<Prepared>;
        async admin_ua_approve_dex_release / admin_ua_approve_dex_release_blocking (req: UaApproveDexRelease) -> Arc<Prepared>;
        async admin_ua_approve_release / admin_ua_approve_release_blocking (req: UaApproveRelease) -> Arc<Prepared>;
        async admin_ua_revoke_approval / admin_ua_revoke_approval_blocking (req: UaRevokeApproval) -> Arc<Prepared>;
        async admin_ua_cancel_nonce / admin_ua_cancel_nonce_blocking (req: UaCancelNonce) -> Arc<Prepared>;
    }
}

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
    #[cfg(feature = "wallet")]
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
    pub async fn next(&self, timeout_ms: u64) -> Option<Event> {
        let m = self.m.clone();
        self.sdk
            .spawn(async move { Ok(m.next(timeout_ms).await) })
            .await
            .unwrap_or(None)
    }
}

#[cfg(feature = "sync-api")]
#[uniffi::export]
impl Subscription {
    /// The next event, or `None` within `timeout_ms` (blocks the calling thread; never a UI thread).
    pub fn next_blocking(&self, timeout_ms: u64) -> Option<Event> {
        let m = self.m.clone();
        crate::sync_cpp::block(&self.sdk, None, async move { Ok(m.next(timeout_ms).await) })
            .unwrap_or(None)
    }
}

#[cfg(not(feature = "sync-api"))]
#[uniffi::export]
impl Vault {
    /// Locks `seed`: the ids of the hidden sets abandoned with it.
    pub async fn lock(&self, seed: String) -> Vec<String> {
        let m = self.m.clone();
        self.sdk
            .spawn(async move { Ok(m.lock(seed).await) })
            .await
            .unwrap_or_default()
    }
    /// Locks every seed.
    pub async fn lock_all(&self) -> Vec<String> {
        let m = self.m.clone();
        self.sdk
            .spawn(async move { Ok(m.lock_all().await) })
            .await
            .unwrap_or_default()
    }
}

#[cfg(feature = "sync-api")]
#[uniffi::export]
impl Vault {
    /// Locks `seed` (blocking twin of `lock`).
    pub fn lock_blocking(&self, seed: String) -> Vec<String> {
        let m = self.m.clone();
        crate::sync_cpp::block(&self.sdk, None, async move { Ok(m.lock(seed).await) })
            .unwrap_or_default()
    }
    /// Locks every seed (blocking twin of `lock_all`).
    pub fn lock_all_blocking(&self) -> Vec<String> {
        let m = self.m.clone();
        crate::sync_cpp::block(&self.sdk, None, async move { Ok(m.lock_all().await) })
            .unwrap_or_default()
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

#[cfg(feature = "wallet")]
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

#[cfg(all(feature = "account", feature = "wallet"))]
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
#[cfg(all(feature = "account", feature = "wallet"))]
#[uniffi::export]
pub fn register_attrs_default() -> RegisterAttrs {
    RegisterAttrs::default()
}

/// An `msig` structure: members sorted by id, the threshold checked (spec §7).
#[cfg(all(feature = "account", feature = "wallet"))]
#[uniffi::export]
pub fn msig_structure(
    members: Vec<MsigMemberArgs>,
    threshold: u16,
) -> Result<MsigStructureArgs, SdkError> {
    crate::account::msig::msig_structure(members, threshold)
}

/// An `msig` structure's UA.
#[cfg(all(feature = "account", feature = "wallet"))]
#[uniffi::export]
pub fn msig_structure_ua(args: MsigStructureArgs) -> Result<String, SdkError> {
    args.ua()
}

/// A `SmartKeyAccount`'s address before its deployment (spec §7).
#[cfg(all(feature = "account", feature = "wallet"))]
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
#[cfg(all(feature = "account", feature = "wallet"))]
#[uniffi::export]
pub fn subject_key_args_secp256k1(address: String) -> Result<SubjectKeyArgs, SdkError> {
    SubjectKeyArgs::secp256k1(&address)
}

/// A registration blob from its JSON (spec §7.1).
#[cfg(all(feature = "account", feature = "wallet"))]
#[uniffi::export]
pub fn registration_blob_from_json(text: String) -> Result<RegistrationBlob, SdkError> {
    RegistrationBlob::from_json(&text)
}

/// A registration blob's JSON (spec §7.1).
#[cfg(all(feature = "account", feature = "wallet"))]
#[uniffi::export]
pub fn registration_blob_to_json(blob: RegistrationBlob) -> Result<String, SdkError> {
    blob.to_json()
}

/// A binding's configuration (spec §4): the profiles, the passkey RP ID, the limits, the module gas tables; the runtime is the
/// SDK's own (`RuntimeChoice::Own`) and the clock the device's.
#[derive(Debug, Clone, uniffi::Record)]
pub struct BindingConfig {
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
    ) -> crate::SdkConfig {
        crate::SdkConfig {
            profiles: self.profiles,
            store,
            authenticator,
            rp_id: self.rp_id,
            runtime: crate::RuntimeChoice::Own,
            limits: self.limits,
            clock: None,
            gas_tables: self.gas_tables,
        }
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
    async fn platform_secret(
        &self,
        handle: String,
        salt: Vec<u8>,
        reason: String,
        policy: Option<KeyPolicy>,
        out: u64,
    ) -> Result<(), AuthError>;
    async fn p256_generate(&self, policy: KeyPolicy) -> Result<SePublic, AuthError>;
    async fn p256_sign(
        &self,
        handle: String,
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
    let config = config.sdk_config(Arc::new(StoreAdapter(store)), auth);
    // `Sdk::open` starts the runtime; its one read of the keystore runs on that runtime too (spec §14)
    Ok(Sdk::new(crate::Sdk::open(config).await?))
}
