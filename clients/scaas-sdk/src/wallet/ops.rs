// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `wallet` operations (spec §8.3, §21; plan T12): one `prepare_<op>` per `(struct, domain kind)` pair of the wallet's rows, the
//! request's named fields the struct's, then `Op::quote` and `Op::submit` (spec §13). The domain kind is the contract's own:
//! its ERC-5267 `eip712Domain()` names it, and its chain id, address and salt must be the profile's (`ProfileMismatch`). The
//! subject (`from`) is the signer's id: a UA key's UA, a native or imported EVM key's address (zero-padded where the struct
//! takes an id). Each is signed under its `scaas-ua` check: `Expect::Op` over the whole message by default, a transfer on ids
//! `Expect::Transfer`, a pay `Expect::PayMeta`, a payee fee `Expect::PayeeFee`. `UAExecute` takes a decoded call only, signed
//! under `Expect::Execute` (`scaas-ua` rebuilds its bytes); any other call needs [`AllowOpaqueCall`] (feature `opaque-calls`),
//! else `OpaqueCallRefused` (spec §13.2). The SDK never fills a
//! fee the user did not choose; 0 is kept. UNAUDITED.
use super::tokens::{abi_string, word};
use super::Wallet;
use crate::op::{
    addr20, dec, domain_name, evm, field, hex, key_opened, sim, unhex, Draft, Key, KeyRef, Op,
    Prepared, ReviewField, Source,
};
use crate::{Sdk, SdkError};
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, U256};
use scaas_ua::wallet::entries::{entry_rows, pay_meta_of};
use scaas_ua::wallet::{DecodedCall, Expect};
use serde_json::{json, Map, Value};
use std::sync::Arc;

const ZERO20: &str = "0x0000000000000000000000000000000000000000";
const KINDS: [&str; 7] = [
    "token",
    "zether",
    "pqz",
    "wallet",
    "account",
    "dex",
    "gov_router",
];

/// The envelope's terms the user chooses (the lane's nonce is read; a pay's lane is its `payLane(entryRef)`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct Envelope {
    /// unix seconds on the chain's clock
    pub valid_until: u64,
    /// the fee mode: bit 0 binds `relayer`, bit 1 binds `fee_recipient` (an unbound one is 0 in what is signed), the fee kind
    /// above
    pub mode: u32,
    pub relayer: Option<String>,
    /// the fee to the relayer in the token's smallest unit, decimal; 0 is a value
    pub fee: String,
    pub fee_recipient: Option<String>,
}

/// A pay's `PayMeta` v3 (CTR-MTX-26): committed to by the signed `entryRef` (`metaPayId`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct PayMeta {
    /// `0x` + 64 hex; `None`: 32 random bytes
    pub salt: Option<String>,
    /// a UUIDv7 in its text form, or `0x` + 64 hex; `None`: no number
    pub pay_no: Option<String>,
    /// store the payment's record under `pay_no` on chain
    pub save: bool,
    pub body: PayBody,
}

/// The `PayMeta` body by schema (pay-meta-tax spec §7.1), named.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub enum PayBody {
    None,
    Note {
        note: String,
    },
    CreditorRef {
        creditor_ref: String,
        due_date: u64,
    },
    BoundCall {
        chain_id: String,
        target: String,
        call_hash: String,
    },
    Ciphertext {
        ciphertext: String,
    },
}

/// The transfer on ids (`UAMetaTransfer`, entry `mtxExecuteTransfer`, `POST /v1/ua-metatx`; owner 2026-11-18, ruling 6): a plain
/// transfer, `entryRef = 0` on the lane `batch` the caller names, its nonce read, signed under `Expect::Transfer` (owner
/// 2026-11-19, ruling D): not recorded on chain as a payment, and a retry of the same request reads the same lane nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct Transfer {
    pub signer: KeyRef,
    pub chain: String,
    pub token: String,
    /// the receiver's 32-byte id (a native address zero-padded, or a UA)
    pub to: String,
    pub value: String,
    /// the lane, decimal
    pub batch: String,
    pub envelope: Envelope,
}

/// `mtxPay`: a `UAMetaTransfer` whose `entryRef` is `metaPayId(meta)`, on its pay lane, signed under `Expect::PayMeta`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct Pay {
    pub signer: KeyRef,
    pub chain: String,
    pub token: String,
    pub to: String,
    pub value: String,
    pub meta: PayMeta,
    pub envelope: Envelope,
}

/// `UAPayWithTax` (regulated kinds): the payer's payment and its tax.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct PayWithTax {
    pub signer: KeyRef,
    pub chain: String,
    pub token: String,
    pub to: String,
    pub value: String,
    pub meta: PayMeta,
    pub tax_mode: u8,
    pub tax: String,
    pub envelope: Envelope,
}

/// The payment a payee fee co-signs (the contract's shape: fee none, relayer bound).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct Payment {
    pub from: String,
    pub to: String,
    pub value: String,
    pub valid_until: u64,
    pub relayer: String,
}

/// The payer's `UASig` over the payment (no members).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct PayerAuth {
    /// `0x` hex; `0x` for a native id
    pub key_data: String,
    pub signature: String,
}

/// `UAPayeeFee` (CTR-MTX-86): the payee's co-signature of its fee over the payment it expects; signed by the payee.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct PayeeFee {
    pub signer: KeyRef,
    pub chain: String,
    pub token: String,
    pub payment: Payment,
    pub meta: PayMeta,
    pub payer_auth: PayerAuth,
    pub fee: String,
    pub fee_recipient: String,
    pub valid_until: u64,
}

/// `UAPayUnderMandate`: the delegate's payment from the mandate wallet, its `entryRef` `metaPayId(meta)`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct PayUnderMandate {
    pub signer: KeyRef,
    pub chain: String,
    pub wallet: String,
    pub token: String,
    pub payee: String,
    pub amount: String,
    pub epoch: String,
    pub batch: String,
    pub meta: PayMeta,
    pub envelope: Envelope,
}

/// `UARelayFee` (CTR-MTX-27): a fee to `payee` for relaying the operation `call`, bound by the hash of its signed calldata; the
/// gateway job carries that operation as its `call` (`scaas-ua` `relay_fee_op`; owner 2026-11-19, ruling F).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct RelayFee {
    pub signer: KeyRef,
    pub chain: String,
    pub token: String,
    /// the operation paid for: an operation id of this SDK (`Op::submit`'s), signed, on this chain, with a gateway job form;
    /// its contract is the signed `target`
    pub call: String,
    pub payee: String,
    pub value: String,
    pub batch: String,
    pub valid_until: u64,
    pub relayer: String,
}

/// The marker of an undecoded call (spec §13.2): constructible only with feature `opaque-calls`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowOpaqueCall(());

impl AllowOpaqueCall {
    #[cfg(feature = "opaque-calls")]
    pub fn new() -> Self {
        AllowOpaqueCall(())
    }
}

/// A mandate wallet's call (spec §13.2): decoded, or opaque under the marker.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub enum ExecuteCall {
    /// an ERC-20 `transfer(to, amount)` of `token` held by the wallet
    Transfer {
        token: String,
        to: String,
        amount: String,
    },
    /// any other call: `OpaqueCallRefused` without the marker
    Opaque {
        target: String,
        value: String,
        data: String,
        allow: Option<AllowOpaqueCall>,
    },
}

/// `UAExecute` on a mandate wallet: the owner's call, decoded only.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct Execute {
    pub signer: KeyRef,
    pub chain: String,
    pub wallet: String,
    pub call: ExecuteCall,
    pub batch: String,
    pub envelope: Envelope,
}

// --- the shared parts ---

/// The domain kind of `contract` by its `eip712Domain()` (ERC-5267), one of `name`'s rows' kinds: `ProfileMismatch` when its
/// chain id, address or salt is not the profile's; `Argument` for another struct's domain.
pub(crate) async fn kind_of(
    sdk: &Sdk,
    chain: &str,
    name: &str,
    contract: [u8; 20],
) -> Result<&'static str, SdkError> {
    let (profile, chain_id, pool) = evm(sdk, chain)?;
    let tx = alloy::rpc::types::TransactionRequest::default()
        .with_to(Address::from(contract))
        .with_input(Bytes::from(super::tokens::selector("eip712Domain()")));
    let b = pool.call_tx(tx).await.map_err(sim)?;
    let domain = abi_string(&b, 1)?;
    let id = U256::from_be_slice(word(&b, 3)?);
    if id != U256::from(chain_id)
        || word(&b, 4)?.get(12..) != Some(&contract[..])
        || hex(word(&b, 5)?) != profile.chain_uid.to_ascii_lowercase()
    {
        return Err(SdkError::ProfileMismatch);
    }
    let kind = KINDS
        .into_iter()
        .find(|k| domain_name(k).is_ok_and(|n| n == domain))
        .ok_or(SdkError::Argument)?;
    if !entry_rows()
        .iter()
        .any(|r| r.name == name && r.kinds.contains(&kind))
    {
        return Err(SdkError::Argument);
    }
    Ok(kind)
}

/// The signer's id as `name`'s `from` takes it: a UA key's UA (`bytes32`); an EVM key's address, zero-padded for `bytes32`.
pub(crate) async fn from_of(sdk: &Sdk, signer: &KeyRef, name: &str) -> Result<String, SdkError> {
    let ty = entry_rows()
        .into_iter()
        .find(|r| r.name == name)
        .and_then(|r| r.fields.split_once(" from").map(|(t, _)| t.to_string()))
        .ok_or(SdkError::Argument)?;
    id_of(sdk, signer, &ty).await
}

/// The signer's id as a field of type `ty` takes it (`bytes32` or `address`).
pub(crate) async fn id_of(sdk: &Sdk, signer: &KeyRef, ty: &str) -> Result<String, SdkError> {
    // an `msig` signs as its own UA (its slots sign at submit: `account::msig`)
    if let KeyRef::Msig { ua, .. } = signer {
        return match ty {
            "bytes32" => Ok(hex(&id32(ua)?)),
            _ => Err(SdkError::Argument),
        };
    }
    Ok(match (key_opened(sdk, signer).await?, ty) {
        (Key::Ua(_, k), "bytes32") => hex(&k.ua().ok_or(SdkError::Argument)?),
        #[cfg(feature = "zether")]
        (Key::Zether(_, k), "bytes32") => hex(&k.ua()),
        (Key::External(row, _), "bytes32") => hex(&row.ua),
        (Key::Native(_, k), t) => {
            let a = addr20(&k.address().ok_or(SdkError::Argument)?.to_ascii_lowercase())?;
            if t == "address" {
                hex(&a)
            } else {
                pad(&a)
            }
        }
        _ => return Err(SdkError::Argument),
    })
}

fn pad(a: &[u8; 20]) -> String {
    format!("0x{}{}", "00".repeat(12), &hex(a)[2..])
}

pub(crate) fn id32(s: &str) -> Result<[u8; 32], SdkError> {
    unhex(&s.to_ascii_lowercase())?
        .try_into()
        .map_err(|_| SdkError::Argument)
}

fn address(o: &Option<String>) -> String {
    o.clone().unwrap_or_else(|| ZERO20.into())
}

/// The envelope's fields into `m` (the nonce left to the lane's read).
pub(crate) fn put_envelope(m: &mut Map<String, Value>, batch: &str, e: &Envelope) {
    m.insert("batch".into(), json!(batch));
    m.insert("validUntil".into(), json!(e.valid_until.to_string()));
    m.insert("mode".into(), json!(e.mode));
    m.insert("relayer".into(), json!(address(&e.relayer)));
    m.insert("fee".into(), json!(e.fee));
    m.insert("feeRecipient".into(), json!(address(&e.fee_recipient)));
}

/// `keccak256("scaas.sdk.pay.salt.v1" ‖ (len ‖ part)…)` over `context` and the meta's fields (its `Debug` form names every one).
fn derived_salt(m: &PayMeta, context: &[&str]) -> [u8; 32] {
    let fields = format!("{:?} {} {:?}", m.pay_no, m.save, m.body);
    let mut b = b"scaas.sdk.pay.salt.v1".to_vec();
    for part in context.iter().copied().chain([fields.as_str()]) {
        b.extend_from_slice(&(part.len() as u64).to_be_bytes());
        b.extend_from_slice(part.as_bytes());
    }
    scaas_ua::keccak256(&b)
}

/// A pay lane's batch (`payLane(entryRef)`), decimal.
fn pay_lane(entry_ref: &[u8; 32]) -> String {
    U256::from_be_bytes(scaas_ua::pay_lane(entry_ref)).to_string()
}

/// The meta's named form (`scaas-ua`'s), its `entryRef` (`metaPayId`), the `scaas-ua` value, and its review lines. A salt the
/// request leaves out is derived from the request: `context` (the chain, the contract, the payer, the payee, the amounts) and
/// the meta's number, flag, schema and body (owner 2026-11-19, ruling D): a retry of the same pay takes the same pay lane, so at
/// most one of the two lands; two pays of the same terms need a `pay_no` or a salt of their own.
fn meta(
    m: &PayMeta,
    context: &[&str],
) -> Result<(Value, [u8; 32], scaas_ua::pay::PayMeta, Vec<ReviewField>), SdkError> {
    let salt = match &m.salt {
        Some(s) => id32(s)?,
        None => derived_salt(m, context),
    };
    let pay_no = match &m.pay_no {
        None => [0; 32],
        Some(s) if s.contains('-') => {
            scaas_ua::pay::pay_no_from_uuid(s).ok_or(SdkError::Argument)?
        }
        Some(s) => id32(s)?,
    };
    let (schema, body) = match &m.body {
        PayBody::None => (0, Value::Null),
        PayBody::Note { note } => (1, json!({ "note": note })),
        PayBody::CreditorRef {
            creditor_ref,
            due_date,
        } => (
            2,
            json!({"creditorRef": creditor_ref, "dueDate": due_date.to_string()}),
        ),
        PayBody::BoundCall {
            chain_id,
            target,
            call_hash,
        } => (
            3,
            json!({"chainId": chain_id, "target": target, "callHash": call_hash}),
        ),
        PayBody::Ciphertext { ciphertext } => (4, json!({ "ciphertext": ciphertext })),
    };
    let mut j =
        json!({"salt": hex(&salt), "payNo": hex(&pay_no), "save": m.save, "schema": schema});
    let mut review = vec![
        field(
            "payNo",
            &hex(&pay_no),
            &scaas_ua::pay::pay_no_to_uuid(&pay_no).unwrap_or_else(|| hex(&pay_no)),
            Source::Signed,
        ),
        field(
            "save",
            &m.save.to_string(),
            &m.save.to_string(),
            Source::Signed,
        ),
        field(
            "schema",
            &schema.to_string(),
            &schema.to_string(),
            Source::Signed,
        ),
    ];
    if let Value::Object(o) = &body {
        for (k, v) in o {
            let s = v.as_str().unwrap_or_default();
            review.push(field(&format!("body.{k}"), s, s, Source::Signed));
        }
        if let Some(x) = j.as_object_mut() {
            x.insert("body".into(), body.clone());
        }
    }
    let ua = pay_meta_of(&j)?;
    let id = scaas_ua::pay::meta_pay_id_v3(&ua).map_err(|_| SdkError::Argument)?;
    Ok((j, id, ua, review))
}

/// `(fee_recipient, relayer)`.
pub(crate) type Bound = (Option<[u8; 20]>, Option<[u8; 20]>);

/// The fee recipient and relayer a check names: those the mode binds.
pub(crate) fn bound(m: &Map<String, Value>) -> Result<Bound, SdkError> {
    let mode = m.get("mode").map(dec).transpose()?.unwrap_or_default();
    let a = |k: &str| -> Result<Option<[u8; 20]>, SdkError> {
        m.get(k)
            .and_then(Value::as_str)
            .map(|s| addr20(&s.to_ascii_lowercase()))
            .transpose()
            .map(|o| o.filter(|x| *x != [0; 20]))
    };
    Ok((
        if mode.bit(1) {
            a("feeRecipient")?
        } else {
            None
        },
        if mode.bit(0) { a("relayer")? } else { None },
    ))
}

/// The chain's id and `chain_uid` bytes.
pub(crate) fn ids(sdk: &Sdk, chain: &str) -> Result<(u64, [u8; 32]), SdkError> {
    let (p, id, _) = evm(sdk, chain)?;
    Ok((id, id32(&p.chain_uid)?))
}

pub(crate) fn draft(
    chain: String,
    name: &'static str,
    kind: &'static str,
    contract: [u8; 20],
    message: Map<String, Value>,
    signer: KeyRef,
) -> Draft {
    Draft {
        chain,
        name,
        kind,
        contract,
        message: Value::Object(message),
        extra: json!({}),
        signer,
        expect: None,
        review: vec![],
        touched: vec![],
        opaque: false,
        ids: false,
        relay_call: None,
        owner: None,
        key_index: U256::ZERO,
        target: None,
    }
}

impl Wallet {
    /// A plain row: `from`, the struct's fields, the envelope; checked under `Expect::Op`; the fields `token` and `underlying`
    /// listed as tokens touched.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn plain(
        &self,
        name: &'static str,
        signer: KeyRef,
        chain: String,
        contract: String,
        batch: String,
        fields: Map<String, Value>,
        env: Envelope,
    ) -> Result<Arc<Prepared>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let contract = addr20(&contract.to_ascii_lowercase())?;
                let kind = kind_of(&sdk, &chain, name, contract).await?;
                // the router's rows are `admin`'s (its `UACancelNonce` too): one entry point per pair
                if kind == "gov_router" {
                    return Err(SdkError::Argument);
                }
                let mut m = Map::new();
                m.insert("from".into(), json!(from_of(&sdk, &signer, name).await?));
                m.extend(fields.clone());
                put_envelope(&mut m, &batch, &env);
                let mut d = draft(chain, name, kind, contract, m, signer);
                for k in ["token", "underlying"] {
                    if let Some(t) = fields.get(k).and_then(Value::as_str) {
                        d.touched.push(addr20(&t.to_ascii_lowercase())?);
                    }
                }
                Op::prepare(&sdk, d).await
            })
            .await
    }
}

/// The plain rows (spec §21): one request struct and one `prepare_<op>` each, the struct's fields by name.
macro_rules! plain_ops {
    ($( $(#[$m:meta])* $req:ident, $f:ident, $name:literal { $( $field:ident : $ty:ty => $json:literal ),* } )*) => {
        $(
            $(#[$m])*
            #[derive(Debug, Clone, PartialEq, Eq)]
            #[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
            #[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
            pub struct $req {
                pub signer: KeyRef,
                pub chain: String,
                /// the contract (`0x` + 40 hex): a token, or a mandate wallet
                pub contract: String,
                /// the lane, decimal
                pub batch: String,
                $( pub $field: $ty, )*
                pub envelope: Envelope,
            }
        )*
        impl Wallet {
            $(
                #[doc = concat!("Prepares `", $name, "` (spec §21): `ProfileMismatch`, `Argument`, `WalletLocked`.")]
                pub async fn $f(&self, req: $req) -> Result<Arc<Prepared>, SdkError> {
                    #[allow(unused_mut)]
                    let mut fields = Map::new();
                    $( fields.insert($json.into(), json!(req.$field)); )*
                    self.plain($name, req.signer, req.chain, req.contract, req.batch, fields, req.envelope).await
                }
            )*
        }
    };
}

plain_ops! {
    /// The ordered cancel of a lane's nonce on ids (a token kind or a mandate wallet).
    CancelNonce, prepare_cancel_nonce, "UACancelNonce" { lane: String => "lane" }
    Burn, prepare_burn, "UABurn" { amount: String => "amount" }
    Wrap, prepare_wrap, "Wrap" { amount: String => "amount" }
    WrapLeg, prepare_wrap_leg, "WrapLeg" { underlying: String => "underlying", amount: String => "amount" }
    Unwrap, prepare_unwrap, "UAUnwrap" { wrapped: String => "wrapped", recipient: String => "recipient", min_out: String => "minOut" }
    UnwrapLeg, prepare_unwrap_leg, "UAUnwrapLeg" { underlying: String => "underlying", wrapped: String => "wrapped",
        recipient: String => "recipient", min_out: String => "minOut" }
    AddReserve, prepare_add_reserve, "AddReserve" { underlying: String => "underlying", amount: String => "amount" }
    WrapToUa, prepare_wrap_to_ua, "WrapToUA" { underlying: String => "underlying", amount: String => "amount", to: String => "to" }
    UnwrapToUa, prepare_unwrap_to_ua, "UAUnwrapToUA" { underlying: String => "underlying", wrapped: String => "wrapped",
        to: String => "to", min_out: String => "minOut" }
    SetMandate, prepare_set_mandate, "UASetMandate" { token: String => "token", delegate: String => "delegate",
        max_per_payment: String => "maxPerPayment", max_per_period: String => "maxPerPeriod",
        period_seconds: String => "periodSeconds", expiry: String => "expiry" }
    SetPayee, prepare_set_payee, "UASetPayee" { token: String => "token", payee: String => "payee", allowed: bool => "allowed" }
    RevokeMandate, prepare_revoke_mandate, "UARevokeMandate" { token: String => "token" }
    DelegateRevoke, prepare_delegate_revoke, "UADelegateRevoke" { token: String => "token", epoch: String => "epoch" }
}

/// `Expect::Payment` or `Expect::PayMeta` over a canonical payment message (`m`, a `UAMetaTransfer`).
#[allow(clippy::too_many_arguments)]
fn payment_expect(
    sdk: &Sdk,
    chain: &str,
    token: [u8; 20],
    meta: Option<scaas_ua::pay::PayMeta>,
    entry_ref: [u8; 32],
) -> Result<crate::op::ExpectFn, SdkError> {
    let (chain_id, chain_uid) = ids(sdk, chain)?;
    let max_window = sdk.window(chain);
    Ok(Box::new(move |now, m: &Value| {
        let o = m.as_object().ok_or(SdkError::Argument)?;
        let s = |k: &str| {
            o.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let (fee_recipient, relayer) = bound(o)?;
        let (account, payee, amount, max_fee) = (
            id32(&s("from"))?,
            id32(&s("to"))?,
            s("value"),
            scaas_ua::wallet::fee_due("UAMetaTransfer", m)?,
        );
        Ok(match &meta {
            Some(meta) => Expect::PayMeta {
                meta: meta.clone(),
                entry_ref: Some(entry_ref),
                account,
                chain_id,
                chain_uid,
                amount,
                decimals: 0,
                payee,
                expected_token: token,
                max_fee,
                fee_recipient,
                relayer,
                now,
                max_window,
            },
            None => Expect::Payment {
                account,
                chain_id,
                chain_uid,
                amount,
                decimals: 0,
                payee,
                entry_ref,
                expected_token: token,
                max_fee,
                fee_recipient,
                relayer,
                now,
                max_window,
            },
        })
    }))
}

/// `Expect::Transfer` over a canonical plain transfer (ruling D): `entryRef = 0` on lane `batch`.
fn transfer_expect(
    sdk: &Sdk,
    chain: &str,
    token: [u8; 20],
    batch: String,
) -> Result<crate::op::ExpectFn, SdkError> {
    let (chain_id, chain_uid) = ids(sdk, chain)?;
    let max_window = sdk.window(chain);
    Ok(Box::new(move |now, m: &Value| {
        let o = m.as_object().ok_or(SdkError::Argument)?;
        let s = |k: &str| {
            o.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let (fee_recipient, relayer) = bound(o)?;
        Ok(Expect::Transfer {
            account: id32(&s("from"))?,
            chain_id,
            chain_uid,
            amount: s("value"),
            decimals: 0,
            payee: id32(&s("to"))?,
            batch: batch.clone(),
            expected_token: token,
            max_fee: scaas_ua::wallet::fee_due("UAMetaTransfer", m)?,
            fee_recipient,
            relayer,
            now,
            max_window,
        })
    }))
}

impl Wallet {
    /// The transfer on ids (owner 2026-11-18, ruling 6): `UAMetaTransfer` sent as `mtxExecuteTransfer`, a gateway's
    /// `POST /v1/ua-metatx`.
    pub async fn prepare_transfer(&self, req: Transfer) -> Result<Arc<Prepared>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let token = addr20(&req.token.to_ascii_lowercase())?;
                let kind = kind_of(&sdk, &req.chain, "UAMetaTransfer", token).await?;
                let mut m = Map::new();
                m.insert(
                    "from".into(),
                    json!(from_of(&sdk, &req.signer, "UAMetaTransfer").await?),
                );
                m.insert("to".into(), json!(hex(&id32(&req.to)?)));
                m.insert("value".into(), json!(req.value));
                m.insert("entryRef".into(), json!(hex(&[0u8; 32])));
                // the lane's nonce is read by `Op::prepare` (no `nonce` here)
                put_envelope(&mut m, &req.batch, &req.envelope);
                let mut d = draft(
                    req.chain.clone(),
                    "UAMetaTransfer",
                    kind,
                    token,
                    m,
                    req.signer,
                );
                d.expect = Some(transfer_expect(&sdk, &req.chain, token, req.batch.clone())?);
                d.ids = true;
                Op::prepare(&sdk, d).await
            })
            .await
    }

    /// `mtxPay` with `PayMeta` v3: the `entryRef` its `metaPayId`, the review listing `payNo` (as UUID text), `save`, the
    /// schema and the body.
    pub async fn prepare_pay(&self, req: Pay) -> Result<Arc<Prepared>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let token = addr20(&req.token.to_ascii_lowercase())?;
                // a derived UA the registry does not hold: refused before anything is prepared (spec §7.1, R16)
                #[cfg(feature = "account")]
                crate::account::receiver_registered(&sdk, &req.chain, &id32(&req.to)?).await?;
                let kind = kind_of(&sdk, &req.chain, "UAMetaTransfer", token).await?;
                let from = from_of(&sdk, &req.signer, "UAMetaTransfer").await?;
                let (mj, entry_ref, ua, review) = meta(
                    &req.meta,
                    &[&req.chain, &hex(&token), &from, &req.to, &req.value],
                )?;
                let mut m = Map::new();
                m.insert("from".into(), json!(from));
                m.insert("to".into(), json!(hex(&id32(&req.to)?)));
                m.insert("value".into(), json!(req.value));
                m.insert("entryRef".into(), json!(hex(&entry_ref)));
                put_envelope(&mut m, &pay_lane(&entry_ref), &req.envelope);
                m.insert("nonce".into(), json!("0"));
                let mut d = draft(
                    req.chain.clone(),
                    "UAMetaTransfer",
                    kind,
                    token,
                    m,
                    req.signer,
                );
                d.expect = Some(payment_expect(
                    &sdk,
                    &req.chain,
                    token,
                    Some(ua),
                    entry_ref,
                )?);
                d.extra = json!({ "meta": mj });
                d.review = review;
                Op::prepare(&sdk, d).await
            })
            .await
    }

    /// `UAPayWithTax` (regulated kinds): the payment as a pay's, its tax; checked under `Expect::Op`.
    pub async fn prepare_pay_with_tax(&self, req: PayWithTax) -> Result<Arc<Prepared>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let token = addr20(&req.token.to_ascii_lowercase())?;
                let kind = kind_of(&sdk, &req.chain, "UAPayWithTax", token).await?;
                let from = from_of(&sdk, &req.signer, "UAMetaTransfer").await?;
                let tax_mode = req.tax_mode.to_string();
                let context = [
                    &req.chain,
                    &hex(&token),
                    &from,
                    &req.to,
                    &req.value,
                    &tax_mode,
                    &req.tax,
                ];
                let (mj, entry_ref, _, review) = meta(&req.meta, &context.map(String::as_str))?;
                let mut p = Map::new();
                p.insert("from".into(), json!(from));
                p.insert("to".into(), json!(hex(&id32(&req.to)?)));
                p.insert("value".into(), json!(req.value));
                p.insert("entryRef".into(), json!(hex(&entry_ref)));
                put_envelope(&mut p, &pay_lane(&entry_ref), &req.envelope);
                p.insert("nonce".into(), json!("0"));
                let mut m = Map::new();
                m.insert("payment".into(), Value::Object(p));
                m.insert("taxMode".into(), json!(req.tax_mode));
                m.insert("tax".into(), json!(req.tax));
                let mut d = draft(req.chain, "UAPayWithTax", kind, token, m, req.signer);
                d.extra = json!({ "meta": mj });
                d.review = review;
                Op::prepare(&sdk, d).await
            })
            .await
    }

    /// `UAPayeeFee`: the payee signs its fee over the payment it expects, under `Expect::PayeeFee` (never the payment's
    /// check); the payer's signature and the `PayMeta` ride unsigned.
    pub async fn prepare_payee_fee(&self, req: PayeeFee) -> Result<Arc<Prepared>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let token = addr20(&req.token.to_ascii_lowercase())?;
                let kind = kind_of(&sdk, &req.chain, "UAPayeeFee", token).await?;
                let pm = &req.payment;
                let (mj, entry_ref, _, review) =
                    meta(&req.meta, &[&req.chain, &hex(&token), &pm.from, &pm.to, &pm.value])?;
                let payee = id32(&pm.to)?;
                let mut p = Map::new();
                p.insert("from".into(), json!(hex(&id32(&pm.from)?)));
                p.insert("to".into(), json!(hex(&payee)));
                p.insert("value".into(), json!(pm.value));
                p.insert("entryRef".into(), json!(hex(&entry_ref)));
                let terms = Envelope {
                    valid_until: pm.valid_until,
                    mode: 1,
                    relayer: Some(pm.relayer.clone()),
                    fee: "0".into(),
                    fee_recipient: None,
                };
                put_envelope(&mut p, &pay_lane(&entry_ref), &terms);
                p.insert("nonce".into(), json!("0"));
                let mut m = Map::new();
                m.insert("payment".into(), Value::Object(p));
                m.insert("fee".into(), json!(req.fee));
                m.insert("feeRecipient".into(), json!(req.fee_recipient));
                m.insert("validUntil".into(), json!(req.valid_until.to_string()));
                let mut d = draft(req.chain.clone(), "UAPayeeFee", kind, token, m, req.signer);
                let (chain_id, chain_uid) = ids(&sdk, &req.chain)?;
                let (amount, fee, max_window) = (pm.value.clone(), req.fee.clone(), sdk.window(&req.chain));
                let fee_recipient = addr20(&req.fee_recipient.to_ascii_lowercase())?;
                d.expect = Some(Box::new(move |now, _| {
                    Ok(Expect::PayeeFee {
                        payee,
                        chain_id,
                        chain_uid,
                        amount: amount.clone(),
                        decimals: 0,
                        entry_ref,
                        expected_token: token,
                        max_fee: fee.clone(),
                        fee_recipient,
                        now,
                        max_window,
                    })
                }));
                let auth = &req.payer_auth;
                d.extra = json!({"meta": mj, "payerSig": {"keyData": auth.key_data, "signature": auth.signature, "members": []}});
                d.review = review;
                Op::prepare(&sdk, d).await
            })
            .await
    }

    /// `UAPayUnderMandate`: the delegate's payment from the mandate wallet `wallet`.
    pub async fn prepare_pay_under_mandate(
        &self,
        req: PayUnderMandate,
    ) -> Result<Arc<Prepared>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let wallet = addr20(&req.wallet.to_ascii_lowercase())?;
                let kind = kind_of(&sdk, &req.chain, "UAPayUnderMandate", wallet).await?;
                let token = addr20(&req.token.to_ascii_lowercase())?;
                let from = from_of(&sdk, &req.signer, "UAPayUnderMandate").await?;
                let context = [
                    &req.chain,
                    &hex(&wallet),
                    &hex(&token),
                    &from,
                    &req.payee,
                    &req.amount,
                ];
                let (mj, entry_ref, _, review) = meta(&req.meta, &context.map(String::as_str))?;
                let mut m = Map::new();
                m.insert("from".into(), json!(from));
                m.insert("token".into(), json!(hex(&token)));
                m.insert("payee".into(), json!(hex(&id32(&req.payee)?)));
                m.insert("amount".into(), json!(req.amount));
                m.insert("entryRef".into(), json!(hex(&entry_ref)));
                m.insert("epoch".into(), json!(req.epoch));
                put_envelope(&mut m, &req.batch, &req.envelope);
                let mut d = draft(req.chain, "UAPayUnderMandate", kind, wallet, m, req.signer);
                d.extra = json!({ "meta": mj });
                d.review = review;
                d.touched.push(token);
                Op::prepare(&sdk, d).await
            })
            .await
    }

    /// `UARelayFee`: a fee bound to the relayed call by its hash; the review lists the call's target and length.
    pub async fn prepare_relay_fee(&self, req: RelayFee) -> Result<Arc<Prepared>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let token = addr20(&req.token.to_ascii_lowercase())?;
                let kind = kind_of(&sdk, &req.chain, "UARelayFee", token).await?;
                let paid = crate::op::state::row(&sdk, &req.call).await?;
                if paid.chain != req.chain || paid.op_json.is_null() || paid.kind == "native" {
                    return Err(SdkError::Argument);
                }
                let call = unhex(&paid.calldata)?;
                let mut m = Map::new();
                m.insert(
                    "from".into(),
                    json!(from_of(&sdk, &req.signer, "UARelayFee").await?),
                );
                m.insert(
                    "target".into(),
                    json!(hex(&addr20(&paid.contract.to_ascii_lowercase())?)),
                );
                m.insert(
                    "callDataHash".into(),
                    json!(hex(&scaas_ua::keccak256(&call))),
                );
                m.insert("payee".into(), json!(hex(&id32(&req.payee)?)));
                m.insert("value".into(), json!(req.value));
                m.insert("batch".into(), json!(req.batch));
                m.insert("validUntil".into(), json!(req.valid_until.to_string()));
                m.insert("relayer".into(), json!(req.relayer));
                let mut d = draft(req.chain, "UARelayFee", kind, token, m, req.signer);
                let n = call.len().to_string();
                d.review
                    .push(field("call", &req.call, &paid.entry, Source::Derived));
                d.review.push(field("call.length", &n, &n, Source::Derived));
                d.relay_call = Some((paid.op_json, call));
                Op::prepare(&sdk, d).await
            })
            .await
    }

    /// `UAExecute` on a mandate wallet: a decoded call (spec §13.2), or an opaque one only under [`AllowOpaqueCall`]
    /// (`OpaqueCallRefused` otherwise), its review flagged `opaque`.
    pub async fn prepare_execute(&self, req: Execute) -> Result<Arc<Prepared>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let wallet = addr20(&req.wallet.to_ascii_lowercase())?;
                let mut review = vec![];
                let mut touched = vec![];
                let mut decoded = None;
                let (target, value, data, opaque) = match &req.call {
                    ExecuteCall::Transfer { token, to, amount } => {
                        let t = addr20(&token.to_ascii_lowercase())?;
                        let to20 = addr20(&to.to_ascii_lowercase())?;
                        U256::from_str_radix(amount, 10).map_err(|_| SdkError::Argument)?;
                        // `scaas-ua` builds the call's bytes and its check rebuilds them (ruling C)
                        let call = DecodedCall::Erc20Transfer {
                            token: t,
                            to: to20,
                            amount: amount.clone(),
                        };
                        let (_, _, data) = call.encode()?;
                        decoded = Some(call);
                        review.push(field(
                            "call",
                            "transfer",
                            "transfer(address,uint256)",
                            Source::Signed,
                        ));
                        review.push(field("call.token", &hex(&t), &hex(&t), Source::Signed));
                        review.push(field("call.to", &hex(&to20), &hex(&to20), Source::Signed));
                        review.push(field("call.amount", amount, amount, Source::Signed));
                        touched.push(t);
                        (t, "0".to_string(), data, false)
                    }
                    ExecuteCall::Opaque {
                        target,
                        value,
                        data,
                        allow,
                    } => {
                        if allow.is_none() {
                            return Err(SdkError::OpaqueCallRefused);
                        }
                        let data = unhex(&data.to_ascii_lowercase())?;
                        if data.len() > 128 * 1024 {
                            return Err(SdkError::Argument);
                        }
                        let sel = hex(data.get(..4).unwrap_or_default());
                        let n = data.len().to_string();
                        review.push(field("call.selector", &sel, &sel, Source::Signed));
                        review.push(field("call.length", &n, &n, Source::Derived));
                        (
                            addr20(&target.to_ascii_lowercase())?,
                            value.clone(),
                            data,
                            true,
                        )
                    }
                };
                let kind = kind_of(&sdk, &req.chain, "UAExecute", wallet).await?;
                let mut m = Map::new();
                m.insert(
                    "from".into(),
                    json!(from_of(&sdk, &req.signer, "UAExecute").await?),
                );
                m.insert("target".into(), json!(hex(&target)));
                m.insert("value".into(), json!(value));
                m.insert("data".into(), json!(hex(&data)));
                put_envelope(&mut m, &req.batch, &req.envelope);
                if let Some(call) = decoded {
                    let (chain_id, chain_uid) = ids(&sdk, &req.chain)?;
                    let max_window = sdk.window(&req.chain);
                    let mut d = draft(req.chain, "UAExecute", kind, wallet, m, req.signer);
                    d.expect = Some(Box::new(move |now, msg: &Value| {
                        let o = msg.as_object().ok_or(SdkError::Argument)?;
                        let (fee_recipient, relayer) = bound(o)?;
                        Ok(Expect::Execute {
                            wallet,
                            chain_id,
                            chain_uid,
                            message: msg.clone(),
                            call: call.clone(),
                            max_fee: scaas_ua::wallet::fee_due("UAExecute", msg)?,
                            fee_recipient,
                            relayer,
                            now,
                            max_window,
                        })
                    }));
                    d.review = review;
                    d.touched = touched;
                    return Op::prepare(&sdk, d).await;
                }
                let mut d = draft(req.chain, "UAExecute", kind, wallet, m, req.signer);
                d.review = review;
                d.touched = touched;
                d.opaque = opaque;
                Op::prepare(&sdk, d).await
            })
            .await
    }
}
