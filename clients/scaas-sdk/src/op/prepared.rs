// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Prepare and review (spec §13.1, CLI-SDK-08): the typed data and its check built by `scaas-ua` from a module's named fields,
//! kept in the SDK's table as an opaque [`Prepared`]; nothing is signed here.
use super::{dec, evm, hex, lane_nonce, KeyRef, Op};
use crate::{Sdk, SdkError};
use alloy::primitives::{Address, U256};
use scaas_ua::wallet::entries::entry_rows;
use scaas_ua::wallet::{scaas_typed_data, Expect, TypedData};
use serde_json::{Map, Value};
use std::sync::{Arc, PoisonError};

/// Where a reviewed value comes from (spec §13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum Source {
    /// a field of the signed struct (or committed to by it, as a pay's `PayMeta`), decoded
    Signed,
    /// what the request named and the signed struct holds only in encrypted form (a confidential amount, recipient)
    Request,
    /// what the SDK chose or read: the contract, every token or market touched with its mark
    Derived,
}

/// One reviewed value: its name (a path for a nested field, `payment.value`), the value as signed, its display form.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct ReviewField {
    pub name: String,
    pub value: String,
    pub display: String,
    pub source: Source,
}

/// A module's check builder: the chain's time and the canonical message give the `scaas-ua` check of what the user confirmed.
pub(crate) type ExpectFn = Box<dyn Fn(u64, &Value) -> Result<Expect, SdkError> + Send + Sync>;

/// What a module's `prepare_<op>` hands to [`Op::prepare`]: one `(struct, domain kind)` row with its named fields.
pub(crate) struct Draft {
    pub chain: String,
    pub name: &'static str,
    pub kind: &'static str,
    pub contract: [u8; 20],
    /// the signed struct by field name; an envelope without `nonce` takes the lane's next nonce, read here
    pub message: Value,
    /// what the entry takes unsigned (`meta`, …)
    pub extra: Value,
    pub signer: KeyRef,
    /// the module's own check (a payment's); `None`: `Expect::Op` over the message, its fee the cap
    pub expect: Option<ExpectFn>,
    /// decoded and request fields the module adds to the review
    pub review: Vec<ReviewField>,
    /// tokens and markets the operation touches besides a token domain's own contract
    pub touched: Vec<[u8; 20]>,
    pub opaque: bool,
    /// the transfer on ids (`mtxExecuteTransfer`, `POST /v1/ua-metatx`; owner 2026-11-18, ruling 6) instead of the row's entry
    pub ids: bool,
    /// a relay fee's paid call: its job `op` and signed calldata (owner 2026-11-19, ruling F)
    pub relay_call: Option<(Value, Vec<u8>)>,
    /// a statement the same key signs first, passed as the entry's named slot: its struct name, the slot and its message
    /// (`ownerSig` of `UARollOverSigned`, `UASetRollOverMode`, owner 2026-11-19, C3; a PQZ debit's `pqzAuth`, plan T16)
    pub owner: Option<(&'static str, &'static str, Value)>,
    /// a `SmartKeyAccount` entry's `AccountSig.keyIndex`: the signing key's index in the account (owner 2026-11-19, S3)
    pub key_index: U256,
    /// the contract the entry is called on when it is not the domain's (`UAWrapOrder`: signed in the underlying's domain, sent
    /// to the wrapper's `mtxWrapOrder`, job-api's Orders row; plan T17)
    pub target: Option<[u8; 20]>,
}

/// The parts `submit` needs; never in a record a caller could rebuild.
pub(crate) struct Typed {
    pub name: &'static str,
    pub kind: &'static str,
    pub contract: [u8; 20],
    pub td: TypedData,
    pub expect: Expect,
    /// the canonical message (unbound `relayer` / `feeRecipient` 0)
    pub message: Value,
    pub extra: Value,
    /// the lane: the subject's id bytes, its batch and nonce (`None`: a struct without an envelope)
    pub lane: Option<(Vec<u8>, U256, U256)>,
    /// the transfer on ids
    pub ids: bool,
    /// a relay fee's paid call (job `op`, signed calldata)
    pub relay_call: Option<(Value, Vec<u8>)>,
    /// the statement signed before the entry, with its check and the slot its signature goes in
    pub owner: Option<(TypedData, Expect, &'static str)>,
    /// the signing key's index in a `SmartKeyAccount`
    pub key_index: U256,
    /// the entry's contract when it is not the domain's
    pub target: Option<[u8; 20]>,
    /// an imported operation's signature in the entry's form and its signer's kind (`Op::import_signed`): `submit` signs
    /// nothing for it
    pub signed: Option<(Value, u16)>,
    /// an order row's closing fact: the contract, the event and the order hash (plan T17)
    pub fact: Option<([u8; 20], &'static str, [u8; 32])>,
}

impl Typed {
    /// The contract the entry is called on: the domain's, or the draft's `target`.
    pub(crate) fn entry_contract(&self) -> [u8; 20] {
        self.target.unwrap_or(self.contract)
    }
}

/// A prepared operation (spec §13.1): opaque, kept in the SDK's table; it holds no secret and nothing signed.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct Prepared {
    id: String,
    chain: String,
    entry: String,
    review: std::sync::Mutex<Vec<ReviewField>>,
    opaque: bool,
    signer: KeyRef,
    expires_at: u64,
    pub(crate) t: Typed,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared").field("id", &self.id).finish()
    }
}

#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
impl Prepared {
    /// The typed digest (`scaas-ua`'s), the node's in-flight key too.
    pub fn id(&self) -> String {
        self.id.clone()
    }
    pub fn chain(&self) -> String {
        self.chain.clone()
    }
    /// The contract function: `mtxPay`, `mtxCancelNonce`, …
    pub fn entry(&self) -> String {
        self.entry.clone()
    }
    pub fn review(&self) -> Vec<ReviewField> {
        self.review
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
    /// An undecoded call under `AllowOpaqueCall` (§13.2).
    pub fn opaque(&self) -> bool {
        self.opaque
    }
    pub fn signer(&self) -> KeyRef {
        self.signer.clone()
    }
    /// The operation's `validUntil` (`u64::MAX`: none).
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// The SCaaS reference table's coverage (owner 2026-11-19, part 3b): each `(entry, domain kinds)` here has a base row on both
/// lane states (`gas/reference.json`, forge-measured); the SDK's coverage test holds the table to it. [`UNMEASURED`] lists
/// what the SDK prepares without a row yet (PLANNED); the two lists are every entry the SDK prepares, none twice.
#[cfg(test)] // the coverage test's
pub(crate) const QUOTABLE: &[(&str, &[&str])] = &[
    ("mtxExecuteTransfer", TOKEN_KINDS),
    ("mtxPay", TOKEN_KINDS),
    ("mtxPayWithPayeeFee", TOKEN_KINDS),
    ("mtxPayWithTax", TOKEN_KINDS),
    ("mtxRelayFee", TOKEN_KINDS),
    (
        "mtxCancelNonce",
        &["token", "zether", "pqz", "wallet", "gov_router", "account"],
    ),
    ("mtxBurn", TOKEN_KINDS),
    ("mtxWrap", TOKEN_KINDS),
    ("mtxWrapLeg", TOKEN_KINDS),
    ("mtxAddReserve", TOKEN_KINDS),
    ("mtxWrapToUA", TOKEN_KINDS),
    ("mtxUnwrap", TOKEN_KINDS),
    ("mtxUnwrapLeg", TOKEN_KINDS),
    ("mtxUnwrapToUA", TOKEN_KINDS),
    ("mtxSetMandate", &["wallet"]),
    ("mtxSetPayee", &["wallet"]),
    ("mtxRevokeMandate", &["wallet"]),
    ("mtxExecute", &["wallet", "account"]),
    ("mtxPayUnderMandate", &["wallet"]),
    ("mtxDelegateRevoke", &["wallet"]),
    ("mtxCancelOrder", TOKEN_KINDS),
    ("mtxInvalidateNonces", &["token", "zether", "pqz", "dex"]),
    ("mtxWrapOrder", TOKEN_KINDS),
    ("mtxCancelOrders", &["dex"]),
    ("mtxAddKey", &["account"]),
    ("mtxRemoveKey", &["account"]),
    ("mtxRotateKey", &["account"]),
    ("mtxSetGuardian", &["account"]),
    ("mtxCancelRecovery", &["account"]),
    ("mtxShield", &["zether", "pqz"]),
    ("mtxWrapShield", &["zether", "pqz"]),
    ("mtxConfidentialTransferSingle", &["zether", "pqz"]),
    ("mtxUnshield", &["zether", "pqz"]),
    ("mtxUnshieldUnwrap", &["zether", "pqz"]),
    ("mtxRollOver", &["zether", "pqz"]),
    ("mtxRollOverSigned", &["zether"]),
    // I1 part 2 (owner 2026-11-19): measured at several counts, a per-item part
    ("mtxConfidentialTransfer", &["zether"]),
    ("mtxConfidentialTransferCompact", &["zether"]),
    ("mtxRollOverBatch", &["zether"]),
    ("mtxSetRollOverMode", &["zether"]),
    ("mtxPrepareAcc", &["pqz"]),
    // I2 (owner 2026-11-19): with the stand-ins of the PQZ precompile and the holder's ML-DSA-65 (`stand_in`)
    ("mtxConfidentialTransferSingleCompact", &["pqz"]),
    ("mtxAcceptAdmin", &["gov_router"]),
    ("mtxApproveDexRelease", &["gov_router"]),
    ("mtxApproveRelease", &["gov_router"]),
    ("mtxApproveTokenRelease", &["gov_router"]),
    ("mtxCancelGrant", &["gov_router"]),
    ("mtxCancelRate", &["gov_router"]),
    ("mtxCreateDex", &["gov_router"]),
    ("mtxCreateInstance", &["gov_router"]),
    ("mtxCreateToken", &["gov_router"]),
    ("mtxDeprecateDex", &["gov_router"]),
    ("mtxDeprecateRelease", &["gov_router"]),
    ("mtxDeprecateToken", &["gov_router"]),
    ("mtxDisableFeature", &["gov_router"]),
    ("mtxDisableWrap", &["gov_router"]),
    ("mtxEnableFeature", &["gov_router"]),
    ("mtxExecuteRate", &["gov_router"]),
    ("mtxForceTransfer", &["gov_router"]),
    ("mtxFreeze", &["gov_router"]),
    ("mtxGrantRole", &["gov_router"]),
    ("mtxMint", &["gov_router"]),
    ("mtxMintToUA", &["gov_router"]),
    ("mtxOperatorTransfer", &["gov_router"]),
    ("mtxPause", &["gov_router"]),
    ("mtxPqzCancelVerifier", &["gov_router"]),
    ("mtxPqzRevokeVerifier", &["gov_router"]),
    ("mtxPqzSetVerifier", &["gov_router"]),
    ("mtxProposeRate", &["gov_router"]),
    ("mtxPublishClassEnv", &["gov_router"]),
    ("mtxPublishDexEnv", &["gov_router"]),
    ("mtxPublishTokenEnv", &["gov_router"]),
    ("mtxRecordOrder", &["gov_router"]),
    ("mtxRenounceAdmin", &["gov_router"]),
    ("mtxRenounceRole", &["gov_router"]),
    ("mtxRevokeApproval", &["gov_router"]),
    ("mtxRevokeOrder", &["gov_router"]),
    ("mtxRevokeRole", &["gov_router"]),
    ("mtxSetAllowed", &["gov_router"]),
    ("mtxSetAuditorKey", &["gov_router"]),
    // I3 (owner 2026-11-19): measured without the consent's verify, the SDK adding it by the auditor's kind
    ("mtxSetAuditorUA", &["gov_router"]),
    ("mtxSetChainEntries", &["gov_router"]),
    ("mtxSetClassKindEnabled", &["gov_router"]),
    ("mtxSetCompliance", &["gov_router"]),
    ("mtxSetDenied", &["gov_router"]),
    ("mtxSetExchangeTarget", &["gov_router"]),
    ("mtxSetFeeSplit", &["gov_router"]),
    ("mtxSetGrant", &["gov_router"]),
    ("mtxSetKycProvider", &["gov_router"]),
    ("mtxSetListedOnly", &["gov_router"]),
    ("mtxSetMarket", &["gov_router"]),
    ("mtxSetMaxSupply", &["gov_router"]),
    ("mtxSetMaxWrapSupply", &["gov_router"]),
    ("mtxSetProofStore", &["gov_router"]),
    ("mtxSetTaxRate", &["gov_router"]),
    ("mtxSetTaxRecipient", &["gov_router"]),
    ("mtxSetTokenKindEnabled", &["gov_router"]),
    ("mtxSetVerifierFee", &["gov_router"]),
    ("mtxSetWrapLimits", &["gov_router"]),
    ("mtxSetWrapMember", &["gov_router"]),
    ("mtxTransferAdmin", &["gov_router"]),
    ("mtxUnfreeze", &["gov_router"]),
    ("mtxUnpause", &["gov_router"]),
];
#[cfg(test)] // the coverage test's
const TOKEN_KINDS: &[&str] = &["token", "zether", "pqz"];
/// What the SDK prepares without a reference row yet (PLANNED: their fixtures), each on the domain kinds listed.
#[cfg(test)] // the coverage test's
pub(crate) const UNMEASURED: &[(&str, &[&str])] = &[
    // U1 (owner 2026-11-19, "approved"): a follow-up after PR A. PQZ's multi transfers (P2: one line over the legs): the
    // PQZ precompile's stand-in at each auditor-group count not built yet; PQZ's signed rollover (P1: entries = min(n,
    // ROLL_MAX) + len(skip)): an opening token and the holder's ML-DSA authorization not built yet
    ("mtxConfidentialTransfer", &["pqz"]),
    ("mtxConfidentialTransferCompact", &["pqz"]),
    ("mtxRollOverSigned", &["pqz"]),
];

const CANCELLED_UA: &str = "UAOrderCancelled(bytes32,bytes32)";
const CANCELLED: &str = "OrderCancelled(bytes32,address)";
const FILLED_UA: &str = "UATradeFilled(bytes32,bytes32,uint256,uint256,uint256)";

/// The EIP-712 domain's name of a domain kind (`typed_ops.json`'s `domains`).
pub(crate) fn domain_name(kind: &str) -> Result<&'static str, SdkError> {
    Ok(match kind {
        "token" => "SCaaS MetaToken",
        "zether" => "SCaaS ZetherToken",
        "pqz" => "SCaaS PqzToken",
        "wallet" => "SCaaS MandateWallet",
        "account" => "SCaaS SmartKeyAccount",
        "dex" => "SCaaS Dex",
        "gov_router" => "SCaaS GovernanceRouter",
        _ => return Err(SdkError::Argument),
    })
}

/// The envelope's object: the message itself, or its `payment` (`UAPayeeFee`, `UAPayWithTax`).
pub(crate) fn envelope(m: &Value) -> Option<&Map<String, Value>> {
    let has = |o: &Map<String, Value>| {
        o.contains_key("from") && o.contains_key("batch") && o.contains_key("validUntil")
    };
    match m.as_object() {
        Some(o) if has(o) => Some(o),
        Some(o) => o
            .get("payment")
            .and_then(Value::as_object)
            .filter(|p| has(p)),
        None => None,
    }
}

fn envelope_mut(m: &mut Value) -> Option<&mut Map<String, Value>> {
    if m.get("payment").is_some() && m.get("batch").is_none() {
        m.get_mut("payment").and_then(Value::as_object_mut)
    } else {
        m.as_object_mut()
    }
}

/// Every leaf of the signed message, by path.
pub(crate) fn flatten(prefix: &str, v: &Value, out: &mut Vec<ReviewField>) {
    match v {
        Value::Object(o) => {
            for (k, x) in o {
                let p = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(&p, x, out);
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                flatten(&format!("{prefix}[{i}]"), x, out);
            }
        }
        Value::String(s) => out.push(field(prefix, s, s, Source::Signed)),
        other => {
            let s = other.to_string();
            out.push(field(prefix, &s, &s, Source::Signed));
        }
    }
}

pub(crate) fn field(name: &str, value: &str, display: &str, source: Source) -> ReviewField {
    ReviewField {
        name: name.into(),
        value: value.into(),
        display: display.into(),
        source,
    }
}

fn address_of(m: &Map<String, Value>, k: &str) -> Option<[u8; 20]> {
    m.get(k)
        .and_then(Value::as_str)
        .and_then(|s| super::addr20(s).ok())
        .filter(|a| *a != [0; 20])
}

impl Prepared {
    /// A line the import adds after its simulation (spec §27.5 (c): the effect shown before anything is signed).
    pub(crate) fn add_review(&self, f: ReviewField) {
        self.review
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(f);
    }
}

impl Op {
    /// [`Op::prepare_signed`] of an operation this SDK signs.
    pub(crate) async fn prepare(sdk: &Arc<Sdk>, d: Draft) -> Result<Arc<Prepared>, SdkError> {
        Op::prepare_signed(sdk, d, None).await
    }

    /// Builds and keeps a [`Prepared`] (spec §13.1): the lane's nonce and the chain's time read, the typed data and its check
    /// built by `scaas-ua`, every field listed for review. `WalletLocked`: the signer's seed is locked; `Argument`: a field the
    /// struct refuses.
    pub(crate) async fn prepare_signed(
        sdk: &Arc<Sdk>,
        d: Draft,
        signed: Option<(Value, u16)>,
    ) -> Result<Arc<Prepared>, SdkError> {
        let (profile, chain_id, pool) = evm(sdk, &d.chain)?;
        // a kind the chain's profile disables (owner 2026-11-22): a PQZ operation, a UA signer of that kind
        if d.kind == "pqz" {
            super::kind_enabled(&profile, "pqz")?;
        }
        if let KeyRef::Ua { kind, .. } = &d.signer {
            super::ua_kind_enabled(&profile, *kind)?;
        }
        // a locked seed refuses before any read (an `msig`'s slot keys are opened when it signs)
        if !matches!(d.signer, KeyRef::Msig { .. } | KeyRef::Signed { .. }) {
            drop(super::key_opened(sdk, &d.signer).await?);
        }
        let uid: [u8; 32] = super::unhex(&profile.chain_uid)?
            .try_into()
            .map_err(|_| SdkError::Argument)?;
        let mut message = d.message;
        let mut lane = None;
        // an order (`UAWrapOrder`) has `from`, `batch` and `validUntil` but its nonce is an order lane's (`minNonce`, signed
        // as given), not an envelope lane's: no lane is read or checked for it
        if let Some(e) = envelope(&message).filter(|_| d.name != "UAWrapOrder") {
            let from = super::unhex(
                e.get("from")
                    .and_then(Value::as_str)
                    .ok_or(SdkError::Argument)?,
            )?;
            let batch = dec(e.get("batch").ok_or(SdkError::Argument)?)?;
            let nonce = match e.get("nonce") {
                Some(n) => dec(n)?,
                None => lane_nonce(&pool, Address::from(d.contract), d.kind, &from, batch).await?,
            };
            if let Some(e) = envelope_mut(&mut message) {
                e.insert("nonce".into(), Value::String(nonce.to_string()));
            }
            lane = Some((from, batch, nonce));
        }
        let (_, now) = super::head(&pool).await?;
        // the struct's primary type: the row's name, but for `UAPqzRollOver`, signed as the PQZ domain's `UARollOver` (scaas-ua
        // `scaas_typed_data`: the domain named picks the row)
        let primary = if d.name == "UAPqzRollOver" {
            "UARollOver"
        } else {
            d.name
        };
        let td = scaas_typed_data(
            primary,
            Some(domain_name(d.kind)?),
            &d.contract,
            chain_id,
            &uid,
            &message,
        )?;
        let canonical = td
            .to_value()
            .get("message")
            .cloned()
            .ok_or(SdkError::Internal)?;
        let id = hex(&td.digest()?);
        let env = envelope(&canonical).cloned().unwrap_or_default();
        let mode = env.get("mode").map(dec).transpose()?.unwrap_or_default();
        // the fee the relayer takes, as the check computes it: a PERCENT envelope's `fee` is a rate in millionths of the amount
        // (closing review P2-4); the check's cap and the review's line are this amount
        let due = if env.is_empty() {
            "0".to_string()
        } else {
            scaas_ua::wallet::fee_due(d.name, &canonical)?
        };
        let expect = match &d.expect {
            Some(f) => f(now, &canonical)?,
            None => Expect::Op {
                op: d.name.into(),
                contract: d.contract,
                chain_id,
                chain_uid: uid,
                message: canonical.clone(),
                max_fee: due.clone(),
                fee_recipient: (mode.bit(1))
                    .then(|| address_of(&env, "feeRecipient"))
                    .flatten(),
                relayer: (mode.bit(0)).then(|| address_of(&env, "relayer")).flatten(),
                now,
                max_window: sdk.window(&d.chain),
            },
        };
        let mut review = Vec::new();
        flatten("", &canonical, &mut review);
        review.extend(d.review);
        let mut extra = d.extra;
        let owner = match d.owner {
            Some((name, slot, m)) => {
                let otd = scaas_typed_data(
                    name,
                    Some(domain_name(d.kind)?),
                    &d.contract,
                    chain_id,
                    &uid,
                    &m,
                )?;
                let om = otd
                    .to_value()
                    .get("message")
                    .cloned()
                    .ok_or(SdkError::Internal)?;
                flatten(slot.trim_end_matches("Sig"), &om, &mut review);
                let ex = Expect::Op {
                    op: name.into(),
                    contract: d.contract,
                    chain_id,
                    chain_uid: uid,
                    message: om,
                    max_fee: "0".into(),
                    fee_recipient: None,
                    relayer: None,
                    now,
                    max_window: sdk.window(&d.chain),
                };
                // the quote's unsigned form carries an empty signature in the slot; `submit` puts the signed one
                extra.as_object_mut().ok_or(SdkError::Internal)?.insert(
                    slot.into(),
                    serde_json::json!({"keyData": "0x", "signature": "0x", "members": []}),
                );
                Some((otd, ex, slot))
            }
            None => None,
        };
        if !env.is_empty() {
            review.push(field("fee.due", &due, &due, Source::Derived));
        }
        review.push(field(
            "contract",
            &hex(&d.contract),
            &hex(&d.contract),
            Source::Derived,
        ));
        if let Some(t) = d.target {
            review.push(field("target", &hex(&t), &hex(&t), Source::Derived));
        }
        let mut touched = d.touched;
        if matches!(d.kind, "token" | "zether" | "pqz") {
            touched.insert(0, d.contract);
        }
        for t in &touched {
            let a = hex(t);
            let listed = profile
                .tokens
                .iter()
                .find(|l| l.address.eq_ignore_ascii_case(&a));
            let display = listed.map_or("unlisted".to_string(), |l| format!("listed {}", l.symbol));
            review.push(field("token", &a, &display, Source::Derived));
        }
        let entry = match d.ids {
            true if d.name == "UAMetaTransfer" => "mtxExecuteTransfer".to_string(),
            true => return Err(SdkError::Argument),
            false => entry_rows()
                .into_iter()
                .find(|r| r.name == d.name && r.kinds.contains(&d.kind))
                .map(|r| r.entry.to_string())
                .ok_or(SdkError::Argument)?,
        };
        // an order row ends on its order's event, not an executed event (the token's and the DEX's trade events, R18)
        let order_hash = |ty: &str, m: &Value| -> Result<[u8; 32], SdkError> {
            Ok(scaas_typed_data(
                ty,
                Some(domain_name(d.kind)?),
                &d.contract,
                chain_id,
                &uid,
                m,
            )?
            .digest()?)
        };
        let inner = canonical.get("order").cloned().unwrap_or_default();
        let fact = match d.name {
            "CancelUAOrder" => Some((
                d.contract,
                CANCELLED_UA,
                order_hash("UATradeOrder", &inner)?,
            )),
            "CancelUAWrapOrder" => {
                Some((d.contract, CANCELLED_UA, order_hash("UAWrapOrder", &inner)?))
            }
            "CancelDexOrder" => Some((d.contract, CANCELLED, order_hash("DexOrder", &inner)?)),
            "UAWrapOrder" => Some((d.contract, FILLED_UA, td.digest()?)),
            _ => None,
        };
        let expires_at = env
            .get("validUntil")
            .map(dec)
            .transpose()?
            .map_or(u64::MAX, |v| u64::try_from(v).unwrap_or(u64::MAX));
        // the signing window on the SDK's clock (T13b ruling 1): not already past, not further than the chain's window, so an
        // endpoint's clock cannot stretch a signature's life
        if env.contains_key("validUntil") {
            let wall = sdk.now();
            if expires_at <= wall || expires_at > wall.saturating_add(sdk.window(&d.chain)) {
                return Err(SdkError::ValidUntilRefused);
            }
        }
        let p = Arc::new(Prepared {
            id: id.clone(),
            chain: d.chain,
            entry,
            review: std::sync::Mutex::new(review),
            opaque: d.opaque,
            signer: d.signer,
            expires_at,
            t: Typed {
                name: d.name,
                kind: d.kind,
                contract: d.contract,
                td,
                expect,
                message: canonical,
                extra,
                lane,
                ids: d.ids,
                relay_call: d.relay_call,
                owner,
                key_index: d.key_index,
                target: d.target,
                signed,
                fact,
            },
        });
        let mut table = sdk.prepared.lock().unwrap_or_else(PoisonError::into_inner);
        // the table holds what can still be submitted: one past its `validUntil` on the chain's clock is `PreparedStale` anyway
        // (closing review P3: the table no longer grows without bound)
        table.retain(|_, q| q.expires_at > now);
        table.insert(id, p.clone());
        Ok(p)
    }

    /// `p` if it is the one this SDK keeps under its id (`PreparedUnknown` otherwise).
    pub(crate) fn known(sdk: &Sdk, p: &Arc<Prepared>) -> Result<(), SdkError> {
        let t = sdk.prepared.lock().unwrap_or_else(PoisonError::into_inner);
        match t.get(&p.id) {
            Some(q) if Arc::ptr_eq(q, p) => Ok(()),
            _ => Err(SdkError::PreparedUnknown),
        }
    }
}
