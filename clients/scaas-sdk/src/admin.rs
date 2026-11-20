// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `admin` (spec §11; plan T18): one entry point per `GovernanceRouter` row of the typed table, `admin_<struct in snake case>`,
//! the request's fields the struct's named fields (the subject `from` the signer's id, `chainUid` the profile's, the envelope
//! [`Envelope`]), prepared on the profile's router (`ProfileMismatch` unless its `eip712Domain()` is the profile's router
//! domain) and sent by `Op::quote` / `Op::submit` (spec §13; not door-A entries: self-relay, NODE-GW-03). A field whose type is a
//! struct or a list of structs (`GrantTerms`, `Env`, `WrapLegLimits[]`, `ChainEntries`, a creation's `TokenConfig` /
//! `DexConfig`, the consent `UASig`) is its named-field JSON text, the node's form, parsed strictly by `scaas-ua`'s typed
//! builders (every field named, no other); a creation's `initHash` is the keccak of the config or initializer call `scaas-ua`
//! encodes. Also: the router's `UACancelNonce`, the CREATE3 preview ([`Admin::create3_address`]), the rescue vault
//! ([`Admin::sign_rescue_vault`]) and the set-auditor consent ([`Admin::sign_auditor_consent`]). Off by default. UNAUDITED.
use crate::op::{addr20, evm, hex, key_opened, unhex, KeyRef, Op, Prepared};
use crate::wallet::ops::{draft, from_of, id32, ids, kind_of, put_envelope, Envelope};
use crate::{Sdk, SdkError};
use scaas_ua::wallet::entries::{entry, entry_rows};
use serde_json::{json, Map, Value};
use std::sync::Arc;

pub mod delay;

/// The admin module.
#[derive(Clone)]
pub struct Admin {
    sdk: Arc<Sdk>,
}

#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
impl Sdk {
    /// The admin module (spec §11).
    pub fn admin(self: &Arc<Self>) -> Arc<Admin> {
        Arc::new(Admin { sdk: self.clone() })
    }
}

/// A router row's request beside its fields.
struct Row {
    name: &'static str,
    signer: KeyRef,
    chain: String,
    batch: String,
    chain_uid: Option<String>,
}

/// The longest nested JSON text a field takes, and its deepest nesting (an untrusted decode is bounded by both).
const NESTED_MAX: usize = 64 * 1024;
const NESTED_DEPTH: usize = 8;

fn depth(v: &Value) -> usize {
    match v {
        Value::Array(a) => 1 + a.iter().map(depth).max().unwrap_or(0),
        Value::Object(o) => 1 + o.values().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// A nested struct's named-field JSON text: at most 64 KiB and eight levels (`Argument`).
fn nested(s: &str) -> Result<Value, SdkError> {
    if s.len() > NESTED_MAX {
        return Err(SdkError::Argument);
    }
    let v: Value = serde_json::from_str(s).map_err(|_| SdkError::Argument)?;
    if depth(&v) > NESTED_DEPTH || !(v.is_object() || v.is_array()) {
        return Err(SdkError::Argument);
    }
    Ok(v)
}

/// A uint of at most 32 bits as its JSON number (`Argument`).
fn small(s: &str) -> Result<Value, SdkError> {
    s.parse::<u32>()
        .map(Value::from)
        .map_err(|_| SdkError::Argument)
}

/// The field types of the request structs: `s` a scalar as its text (hex, or decimal for a uint), `n` a uint of at most 32
/// bits, `b` a bool, `v` a list of scalars, `j` / `xj` a struct as named-field JSON text, `x` an unsigned scalar.
macro_rules! ty {
    (s) => { String };
    (n) => { String };
    (b) => { bool };
    (v) => { Vec<String> };
    (j) => { String };
    (x) => { String };
    (xj) => { String };
}

/// A field into the signed message (`fields`) or the entry's unsigned arguments (`extra`).
macro_rules! put {
    (s, $k:expr, $v:expr, $f:ident, $x:ident) => {
        $f.insert($k.into(), json!($v));
    };
    (n, $k:expr, $v:expr, $f:ident, $x:ident) => {
        $f.insert($k.into(), small(&$v)?);
    };
    (b, $k:expr, $v:expr, $f:ident, $x:ident) => {
        $f.insert($k.into(), json!($v));
    };
    (v, $k:expr, $v:expr, $f:ident, $x:ident) => {
        $f.insert($k.into(), json!($v));
    };
    (j, $k:expr, $v:expr, $f:ident, $x:ident) => {
        $f.insert($k.into(), nested(&$v)?);
    };
    (x, $k:expr, $v:expr, $f:ident, $x:ident) => {
        $x.insert($k.into(), json!($v));
    };
    (xj, $k:expr, $v:expr, $f:ident, $x:ident) => {
        $x.insert($k.into(), nested(&$v)?);
    };
}

/// A field from a vector row's message (`m`) or unsigned arguments (`x`), the tests' table-driven form.
#[cfg(test)]
macro_rules! take {
    (s, $k:expr, $m:ident, $x:ident) => {
        text(&$m[$k])
    };
    (n, $k:expr, $m:ident, $x:ident) => {
        text(&$m[$k])
    };
    (b, $k:expr, $m:ident, $x:ident) => {
        $m[$k].as_bool().unwrap_or_default()
    };
    (v, $k:expr, $m:ident, $x:ident) => {
        $m[$k]
            .as_array()
            .map(|a| a.iter().map(text).collect())
            .unwrap_or_default()
    };
    (j, $k:expr, $m:ident, $x:ident) => {
        $m[$k].to_string()
    };
    (x, $k:expr, $m:ident, $x:ident) => {
        text(&$x[$k])
    };
    (xj, $k:expr, $m:ident, $x:ident) => {
        $x[$k].to_string()
    };
}

#[cfg(test)]
fn text(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), String::from)
}

macro_rules! router_ops {
    ($( $req:ident, $f:ident, $name:literal { $( $field:ident : $k:ident => $json:literal ),* } )*) => {
        $(
            /// A request on the profile's `GovernanceRouter` (spec §11) for the row named below.
            #[doc = $name]
            #[derive(Debug, Clone, PartialEq, Eq)]
            #[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
            #[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
            pub struct $req {
                pub signer: KeyRef,
                pub chain: String,
                /// the lane, decimal
                pub batch: String,
                $( pub $field: ty!($k), )*
                /// the target's chain word (CTR-GOV-28) where the struct signs one; `None`: the profile's `chain_uid`
                pub chain_uid: Option<String>,
                pub envelope: Envelope,
            }
        )*
        impl Admin {
            $(
                #[doc = concat!("Prepares `", $name, "` (spec §11): `ProfileMismatch`, `Argument`, `WalletLocked`.")]
                pub async fn $f(&self, req: $req) -> Result<Arc<Prepared>, SdkError> {
                    #[allow(unused_mut)]
                    let (mut fields, mut extra) = (Map::new(), Map::new());
                    $( put!($k, $json, req.$field, fields, extra); )*
                    let r = Row { name: $name, signer: req.signer, chain: req.chain, batch: req.batch, chain_uid: req.chain_uid };
                    Box::pin(self.router(r, fields, extra, req.envelope)).await
                }
            )*
            /// The tests' table-driven form: a row's struct from its named fields.
            #[cfg(test)]
            #[allow(clippy::too_many_arguments)]
            pub(crate) async fn prepare_row(&self, name: &str, signer: KeyRef, chain: String, batch: String, m: &Value,
                x: &Value, envelope: Envelope) -> Result<Arc<Prepared>, SdkError> {
                match name {
                    $( $name => Box::pin(self.$f($req { signer, chain, batch, $( $field: take!($k, $json, m, x), )*
                        chain_uid: m.get("chainUid").map(text), envelope })).await, )*
                    _ => Err(SdkError::Argument),
                }
            }
        }
    };
}

router_ops! {
UaGrantRole, admin_ua_grant_role, "UAGrantRole" { target: s => "target", bit: n => "bit", account: s => "account" }
    UaRevokeRole, admin_ua_revoke_role, "UARevokeRole" { target: s => "target", bit: n => "bit", account: s => "account" }
    UaSetGrant, admin_ua_set_grant, "UASetGrant" { target: s => "target", bit: n => "bit", holder: s => "holder", terms: j => "terms" }
    UaCancelGrant, admin_ua_cancel_grant, "UACancelGrant" { target: s => "target", bit: n => "bit", account: s => "account" }
    UaDisableFeature, admin_ua_disable_feature, "UADisableFeature" { target: s => "target", bit: n => "bit" }
    UaTransferAdmin, admin_ua_transfer_admin, "UATransferAdmin" { target: s => "target", new_admin: s => "newAdmin" }
    UaAcceptAdmin, admin_ua_accept_admin, "UAAcceptAdmin" { target: s => "target" }
    UaRenounceAdmin, admin_ua_renounce_admin, "UARenounceAdmin" { target: s => "target" }
    UaRenounceRole, admin_ua_renounce_role, "UARenounceRole" { target: s => "target", bit: n => "bit" }
    UaMint, admin_ua_mint, "UAMint" { target: s => "target", to: s => "to", amount: s => "amount" }
    UaMintToUA, admin_ua_mint_to_ua, "UAMintToUA" { target: s => "target", to: s => "to", amount: s => "amount" }
    UaDisableWrap, admin_ua_disable_wrap, "UADisableWrap" { target: s => "target", leg: s => "leg", reason: s => "reason" }
    UaProposeRate, admin_ua_propose_rate, "UAProposeRate" { target: s => "target", leg: s => "leg", num: s => "num", den: s => "den" }
    UaCancelRate, admin_ua_cancel_rate, "UACancelRate" { target: s => "target" }
    UaExecuteRate, admin_ua_execute_rate, "UAExecuteRate" { target: s => "target" }
    UaSetMarket, admin_ua_set_market, "UASetMarket" { target: s => "target", base: s => "base", quote: s => "quote", listed: b => "listed" }
    UaSetExchangeTarget, admin_ua_set_exchange_target, "UASetExchangeTarget" { target: s => "target", exchange_target: s => "exchangeTarget", listed: b => "listed" }
    UaSetListedOnly, admin_ua_set_listed_only, "UASetListedOnly" { target: s => "target", on: b => "on" }
    UaSetFeeSplit, admin_ua_set_fee_split, "UASetFeeSplit" { target: s => "target", relayer_share_ppm: n => "relayerSharePpm", treasury: s => "treasury" }
    UaFreeze, admin_ua_freeze, "UAFreeze" { target: s => "target", account: s => "account", ref_id: s => "ref", record_id: s => "recordId" }
    UaUnfreeze, admin_ua_unfreeze, "UAUnfreeze" { target: s => "target", account: s => "account", ref_id: s => "ref" }
    UaForceTransfer, admin_ua_force_transfer, "UAForceTransfer" { target: s => "target", record_id: s => "recordId", amount: s => "amount" }
    UaPause, admin_ua_pause, "UAPause" { target: s => "target", ref_id: s => "ref", until: s => "until" }
    UaUnpause, admin_ua_unpause, "UAUnpause" { target: s => "target", ref_id: s => "ref" }
    UaRecordOrder, admin_ua_record_order, "UARecordOrder" { target: s => "target", order_id: s => "orderId", document_hash: s => "documentHash", subject: s => "subject", beneficiary: s => "beneficiary", max_amount: s => "maxAmount", freeze_until: s => "freezeUntil" }
    UaRevokeOrder, admin_ua_revoke_order, "UARevokeOrder" { target: s => "target", record_id: s => "recordId", reason_ref: s => "reasonRef" }
    UaOperatorTransfer, admin_ua_operator_transfer, "UAOperatorTransfer" { target: s => "target", account: s => "account", to: s => "to", amount: s => "amount", ref_id: s => "ref" }
    UaSetTaxRate, admin_ua_set_tax_rate, "UASetTaxRate" { target: s => "target", rate_ppm: n => "ratePpm" }
    UaSetTaxRecipient, admin_ua_set_tax_recipient, "UASetTaxRecipient" { target: s => "target", tax_recipient: s => "taxRecipient" }
    UaPqzSetVerifier, admin_ua_pqz_set_verifier, "UAPqzSetVerifier" { target: s => "target", next: s => "next" }
    UaPqzCancelVerifier, admin_ua_pqz_cancel_verifier, "UAPqzCancelVerifier" { target: s => "target" }
    UaPqzRevokeVerifier, admin_ua_pqz_revoke_verifier, "UAPqzRevokeVerifier" { target: s => "target" }
    UaSetProofStore, admin_ua_set_proof_store, "UASetProofStore" { target: s => "target", next: n => "next" }
    UaSetAuditorKey, admin_ua_set_auditor_key, "UASetAuditorKey" { target: s => "target", new_key: s => "newKey", epoch: n => "epoch", pop: x => "pop" }
    UaSetAuditorUA, admin_ua_set_auditor_ua, "UASetAuditorUA" { target: s => "target", new_auditor: s => "newAuditor", epoch: n => "epoch", consent: xj => "consent" }
    UaSetVerifierFee, admin_ua_set_verifier_fee, "UASetVerifierFee" { target: s => "target", next: s => "next" }
    UaSetWrapLimits, admin_ua_set_wrap_limits, "UASetWrapLimits" { target: s => "target", legs: j => "legs", net_unwrap: b => "netUnwrap", wrap_list: b => "wrapList", unwrap_list: b => "unwrapList" }
    UaSetWrapMember, admin_ua_set_wrap_member, "UASetWrapMember" { target: s => "target", account: s => "account", can_wrap: b => "canWrap", can_unwrap: b => "canUnwrap" }
    UaSetMaxSupply, admin_ua_set_max_supply, "UASetMaxSupply" { target: s => "target", max_supply: s => "maxSupply" }
    UaSetMaxWrapSupply, admin_ua_set_max_wrap_supply, "UASetMaxWrapSupply" { target: s => "target", max_wrap_supply: s => "maxWrapSupply" }
    UaSetAllowed, admin_ua_set_allowed, "UASetAllowed" { target: s => "target", accounts: v => "accounts", on: b => "on" }
    UaSetDenied, admin_ua_set_denied, "UASetDenied" { target: s => "target", accounts: v => "accounts", on: b => "on" }
    UaEnableFeature, admin_ua_enable_feature, "UAEnableFeature" { target: s => "target", bit: n => "bit" }
    UaPublishTokenEnv, admin_ua_publish_token_env, "UAPublishTokenEnv" { target: s => "target", kind: n => "kind", env_version: n => "envVersion", env: j => "env" }
    UaPublishDexEnv, admin_ua_publish_dex_env, "UAPublishDexEnv" { target: s => "target", env_version: n => "envVersion", env: j => "env" }
    UaPublishClassEnv, admin_ua_publish_class_env, "UAPublishClassEnv" { target: s => "target", contract_class: n => "contractClass", kind: n => "kind", env_version: n => "envVersion", env: j => "env" }
    UaDeprecateToken, admin_ua_deprecate_token, "UADeprecateToken" { target: s => "target", kind: n => "kind", version: s => "version", reason: s => "reason" }
    UaDeprecateDex, admin_ua_deprecate_dex, "UADeprecateDex" { target: s => "target", version: s => "version", reason: s => "reason" }
    UaDeprecateRelease, admin_ua_deprecate_release, "UADeprecateRelease" { target: s => "target", contract_class: n => "contractClass", kind: n => "kind", version: s => "version", reason: s => "reason" }
    UaSetTokenKindEnabled, admin_ua_set_token_kind_enabled, "UASetTokenKindEnabled" { target: s => "target", kind: n => "kind", on: b => "on" }
    UaSetClassKindEnabled, admin_ua_set_class_kind_enabled, "UASetClassKindEnabled" { target: s => "target", contract_class: n => "contractClass", kind: n => "kind", on: b => "on" }
    UaSetKycProvider, admin_ua_set_kyc_provider, "UASetKycProvider" { target: s => "target", provider: s => "provider", enabled: b => "enabled" }
    UaSetCompliance, admin_ua_set_compliance, "UASetCompliance" { target: s => "target", accounts: v => "accounts", flags: v => "flags", until: v => "until" }
    UaCreateToken, admin_ua_create_token, "UACreateToken" { target: s => "target", kind: n => "kind", version: s => "version", salt: s => "salt", config: xj => "config" }
    UaCreateDex, admin_ua_create_dex, "UACreateDex" { target: s => "target", version: s => "version", salt: s => "salt", config: xj => "config" }
    UaCreateInstance, admin_ua_create_instance, "UACreateInstance" { target: s => "target", contract_class: n => "contractClass", kind: n => "kind", version: s => "version", salt: s => "salt", init_call: x => "init_call" }
    UaSetChainEntries, admin_ua_set_chain_entries, "UASetChainEntries" { target: s => "target", entries: j => "entries" }
    UaApproveTokenRelease, admin_ua_approve_token_release, "UAApproveTokenRelease" { target: s => "target", kind: n => "kind", version: s => "version", env_version: n => "envVersion", initcode_hash: s => "initcodeHash", impl_args_hash: s => "implArgsHash", factory: s => "factory", admin_generation: n => "adminGeneration", until: s => "until" }
    UaApproveDexRelease, admin_ua_approve_dex_release, "UAApproveDexRelease" { target: s => "target", version: s => "version", env_version: n => "envVersion", initcode_hash: s => "initcodeHash", impl_args_hash: s => "implArgsHash", factory: s => "factory", admin_generation: n => "adminGeneration", until: s => "until" }
    UaApproveRelease, admin_ua_approve_release, "UAApproveRelease" { target: s => "target", contract_class: n => "contractClass", kind: n => "kind", version: s => "version", env_version: n => "envVersion", init_selector: s => "initSelector", interface_id: s => "interfaceId", initcode_hash: s => "initcodeHash", impl_args_hash: s => "implArgsHash", factory: s => "factory", admin_generation: n => "adminGeneration", until: s => "until" }
    UaRevokeApproval, admin_ua_revoke_approval, "UARevokeApproval" { target: s => "target", key: s => "key" }
    UaCancelNonce, admin_ua_cancel_nonce, "UACancelNonce" { lane: s => "lane" }
}

/// A rescue vault's admin operation (CTR-GOV-25): `seq` the vault's shared order, from 1.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub enum RescueOp {
    /// `setRescuer(seq, newRescuer)`, `new_rescuer` an address (not 0)
    SetRescuer { seq: u64, new_rescuer: String },
    /// `rotateAdmin(seq, newAdmin)`, `new_admin` a native UA (not 0)
    RotateAdmin { seq: u64, new_admin: String },
}

/// The rescue vault's signature request: the vault's admin key (a native EVM key) and the operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct RescueVault {
    pub signer: KeyRef,
    pub vault: String,
    pub op: RescueOp,
}

/// A signed rescue-vault operation: its typed digest and the admin's 65-byte signature, both `0x` hex.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct SignedRescue {
    pub digest: String,
    pub signature: String,
}

/// A creation's CREATE3 addresses (`scaas-ua` `create3_address`): the salt `s`, the proxy, the instance.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct Create3Preview {
    pub s: String,
    pub proxy: String,
    pub instance: String,
}

/// The new auditor's consent to a set-auditor (spec 2026-11-18 set-auditor §5.2): `AuditorConsent(token, auditor, epoch,
/// chainUid)` in the confidential token's domain.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct AuditorConsent {
    /// PQZ: the auditor's UA key; Zether: the auditor's Zether UA (`kind` 0x0141)
    pub signer: KeyRef,
    pub chain: String,
    pub token: String,
    pub epoch: u32,
}

impl Admin {
    /// A router row: `from` the signer's id, `fields`, `chainUid` the profile's where the struct has one, the envelope; a
    /// creation's `initHash` the keccak of what `scaas-ua` encodes of its config or initializer call.
    #[allow(clippy::too_many_arguments)]
    async fn router(
        &self,
        r: Row,
        fields: Map<String, Value>,
        extra: Map<String, Value>,
        env: Envelope,
    ) -> Result<Arc<Prepared>, SdkError> {
        let Row {
            name,
            signer,
            chain,
            batch,
            chain_uid,
        } = r;
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let (profile, _, _) = evm(&sdk, &chain)?;
                let router = addr20(
                    &profile
                        .router
                        .clone()
                        .ok_or(SdkError::Argument)?
                        .to_ascii_lowercase(),
                )?;
                let kind = kind_of(&sdk, &chain, name, router).await?;
                if kind != "gov_router" {
                    return Err(SdkError::Argument);
                }
                let row = entry_rows()
                    .into_iter()
                    .find(|r| r.name == name && r.kinds.contains(&kind))
                    .ok_or(SdkError::Argument)?;
                let mut m = Map::new();
                m.insert("from".into(), json!(from_of(&sdk, &signer, name).await?));
                m.extend(fields);
                match (row.fields.contains("bytes32 chainUid"), chain_uid) {
                    (true, w) => {
                        let w = w.unwrap_or(profile.chain_uid);
                        m.insert("chainUid".into(), json!(hex(&id32(&w)?)));
                    }
                    (false, None) => {}
                    (false, Some(_)) => return Err(SdkError::Argument),
                }
                put_envelope(&mut m, &batch, &env);
                let extra = Value::Object(extra);
                if row.plan.contains("init!") || row.plan.contains("initcall!") {
                    // the entry built once unsigned at nonce 0 names the initHash of the config it encodes
                    let mut probe = m.clone();
                    probe.insert("nonce".into(), json!("0"));
                    let unsigned = json!({"keyData": "0x", "signature": "0x", "members": []});
                    let b = entry(
                        name,
                        kind,
                        &router,
                        &Value::Object(probe),
                        &extra,
                        &unsigned,
                    )?;
                    let h = b
                        .message
                        .get("initHash")
                        .cloned()
                        .ok_or(SdkError::Internal)?;
                    m.insert("initHash".into(), h);
                }
                let mut d = draft(chain, name, kind, router, m, signer);
                d.extra = extra;
                Op::prepare(&sdk, d).await
            })
            .await
    }

    /// The CREATE3 addresses of a creation by `factory` (the router's creations: `UACreateToken`, `UACreateDex`,
    /// `UACreateInstance`): pure, `scaas-ua` `create3_address`.
    pub fn create3_address(
        &self,
        factory: String,
        creator_id: String,
        contract_class: u16,
        kind: u16,
        salt: String,
    ) -> Result<Create3Preview, SdkError> {
        let c = scaas_ua::factory::create3_address(
            &addr20(&factory.to_ascii_lowercase())?,
            &id32(&creator_id)?,
            contract_class,
            kind,
            &id32(&salt)?,
        );
        Ok(Create3Preview {
            s: hex(&c.s),
            proxy: hex(&c.proxy),
            instance: hex(&c.instance),
        })
    }

    /// Signs a rescue-vault operation (CTR-GOV-25): the typed data `scaas-ua` builds from the named fields
    /// (`rescue_vault_typed_data`, the vault's chain-neutral domain), signed by the admin's native EVM key; the review is the
    /// operation itself. `Argument`: `seq` 0, a zero rescuer, a new admin that is not a native UA, a key that is not an EVM key.
    pub async fn sign_rescue_vault(&self, req: RescueVault) -> Result<SignedRescue, SdkError> {
        use scaas_ua::wallet::{
            rescue_vault_typed_data, sign_typed_by, AllowAnyTypedData, Expect, RescueVaultOp,
        };
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let vault = addr20(&req.vault.to_ascii_lowercase())?;
                let op = match &req.op {
                    RescueOp::SetRescuer { seq, new_rescuer } => RescueVaultOp::SetRescuer {
                        seq: *seq,
                        new_rescuer: addr20(&new_rescuer.to_ascii_lowercase())?,
                    },
                    RescueOp::RotateAdmin { seq, new_admin } => RescueVaultOp::RotateAdmin {
                        seq: *seq,
                        new_admin: id32(new_admin)?,
                    },
                };
                let td = rescue_vault_typed_data(&vault, op)?;
                let crate::op::Key::Native(_, k) = key_opened(&sdk, &req.signer).await? else {
                    return Err(SdkError::Argument);
                };
                // the typed data is built here from the named fields: what is signed is the operation asked
                let sig = sign_typed_by(&k, &td, Expect::Any(AllowAnyTypedData))?;
                Ok(SignedRescue {
                    digest: hex(&td.digest()?),
                    signature: hex(&sig),
                })
            })
            .await
    }

    /// The new auditor's consent on a PQZ token (`AuditorConsent`, for `UASetAuditorUA`): the auditor UA's `UASig` under
    /// `auditor-consent`, JSON (the `consent` argument). `PqzAuditorNative` for a native (address) auditor, before any read;
    /// `Argument` for another domain kind.
    pub async fn sign_pqz_auditor_consent(&self, req: AuditorConsent) -> Result<String, SdkError> {
        self.consent(req, "pqz").await
    }

    /// The new auditor's consent on a Zether token (`AuditorConsent`, for `UASetAuditorKey`): the Zether key's proof of
    /// possession over the token's consent, `0x` hex (the `pop` argument), by `scaas-ua`'s Zether facade (`auditorPop`).
    /// `Argument` for another domain kind.
    pub async fn sign_zether_auditor_consent(
        &self,
        req: AuditorConsent,
    ) -> Result<String, SdkError> {
        self.consent(req, "zether").await
    }

    async fn consent(&self, req: AuditorConsent, want: &'static str) -> Result<String, SdkError> {
        // a group auditor has no consent path (M16; PLANNED)
        if matches!(req.signer, KeyRef::BlsMulti { .. }) {
            return Err(SdkError::Argument);
        }
        // a native (address) auditor of a PQZ token: refused up front (controller call, owner auto-run 2026-11-19); a native id
        // holds no PQZ key (CTR-UA-32), so the token refuses it at `_keyOf` before the consent is read
        if want == "pqz" && matches!(req.signer, KeyRef::Native { .. } | KeyRef::Imported { .. }) {
            return Err(SdkError::PqzAuditorNative);
        }
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let token = addr20(&req.token.to_ascii_lowercase())?;
                // a confidential token's domain (the consent has no entry row of its own: `UAShield`'s kinds are the same two)
                let kind = kind_of(&sdk, &req.chain, "UAShield", token).await?;
                if kind != want {
                    return Err(SdkError::Argument);
                }
                let (chain_id, uid) = ids(&sdk, &req.chain)?;
                let from = from_of(&sdk, &req.signer, "UASetAuditorUA").await?;
                let m = json!({"token": hex(&token), "auditor": from, "epoch": req.epoch, "chainUid": hex(&uid)});
                match kind {
                    #[cfg(feature = "pqz")]
                    "pqz" => {
                        let td = scaas_ua::wallet::scaas_typed_data(
                            "AuditorConsent",
                            Some(crate::op::domain_name(kind)?),
                            &token,
                            chain_id,
                            &uid,
                            &m,
                        )?;
                        let canonical = td.to_value().get("message").cloned().ok_or(SdkError::Internal)?;
                        let ex = scaas_ua::wallet::Expect::Op {
                            op: "AuditorConsent".into(),
                            contract: token,
                            chain_id,
                            chain_uid: uid,
                            message: canonical,
                            max_fee: "0".into(),
                            fee_recipient: None,
                            relayer: None,
                            now: 0,
                            max_window: 0,
                        };
                        // an `msig` auditor: its `UASig{"", "", members}` by the slots named (`account::msig`)
                        #[cfg(feature = "account")]
                        if let KeyRef::Msig { ua, slots } = &req.signer {
                            let s = crate::account::msig::sign_typed(&sdk, &req.chain, ua, slots, &td, &ex)
                                .await?;
                            return Ok(scaas_ua::json::uasig_json(&s));
                        }
                        let k = key_opened(&sdk, &req.signer).await?;
                        let s = crate::op::submit::sign_one(&sdk, &k, &td, &ex).await?;
                        Ok(json!({"keyData": hex(&s.key_data), "signature": hex(&s.signature), "members": []})
                            .to_string())
                    }
                    #[cfg(feature = "zether")]
                    "zether" => {
                        let KeyRef::Ua { seed, kind: 0x0141, account, index: 0 } = &req.signer else {
                            return Err(SdkError::Argument);
                        };
                        let (_s, key) = crate::confidential::handle(&sdk, seed, *account)?;
                        let q = json!({"curve": "bls12381", "chainId": chain_id.to_string(), "chainUid": hex(&uid),
                            "token": hex(&token), "epoch": req.epoch});
                        let out = key.call("auditorPop", q.to_string().as_bytes())?;
                        let v: Value = serde_json::from_str(&out).map_err(|_| SdkError::Internal)?;
                        let pop = v.get("pop").and_then(Value::as_str).ok_or(SdkError::Internal)?;
                        unhex(pop)?;
                        Ok(pop.to_string())
                    }
                    _ => Err(SdkError::FeatureMissing),
                }
            })
            .await
    }
}

#[cfg(test)]
#[path = "admin_tests.rs"]
mod tests;
