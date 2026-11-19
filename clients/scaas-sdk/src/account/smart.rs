// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `SmartKeyAccount` (spec §7; plan T13; CTR-ACC-01, CTR-ACC-03, CTR-ACC-10): its counterfactual address by `scaas-ua`, and its
//! own entries `AddKey`, `RemoveKey`, `RotateKey`, `SetGuardian`, `CancelRecovery`, `CancelNonce` and `Execute`, each signed by
//! one of the account's keys (`from` is the account itself) in its domain (`SCaaS SmartKeyAccount`, read from the contract's
//! `eip712Domain()` and held to the profile), then quoted and submitted as every operation (`Op::quote`, `Op::submit`; §13).
//! `Execute` takes a decoded call only (§13.2): `scaas-ua` builds its bytes and its check `Expect::Execute` rebuilds them; any
//! other call needs [`AllowOpaqueCall`] (feature `opaque-calls`), else `OpaqueCallRefused`. Guardian recovery: the guardian
//! `SmartKeyAccount`'s `Execute` of the decoded `initiateRecovery(newKey)` on the account it guards
//! ([`Account::prepare_initiate_recovery`]); `completeRecovery` is anyone's direct call after `RECOVERY_DELAY`. The account's
//! key signs as `AccountSig { keyIndex: 0, proof: [], signature }`: the first key (index 0). UNAUDITED.
use super::Account;
use crate::op::{addr20, field, hex, unhex, Draft, KeyRef, Op, Prepared, Source};
use crate::wallet::ops::{bound, ids, kind_of, put_envelope};
use crate::wallet::{AllowOpaqueCall, Envelope};
use crate::SdkError;
use alloy::primitives::U256;
use scaas_ua::wallet::{DecodedCall, Expect, SubjectKey};
use serde_json::{json, Map, Value};
use std::sync::Arc;

/// A `SubjectKey` by name: `kind` 1 a passkey (`x`, `y` P-256, `rpIdHash`, `originHash`), 2 a secp256k1 key (`x` its address
/// right-aligned, the rest 0); words as `0x` + 64 hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectKeyArgs {
    pub kind: u8,
    pub x: String,
    pub y: String,
    pub rp_id_hash: String,
    pub origin_hash: String,
}

impl SubjectKeyArgs {
    /// The secp256k1 key of an EVM address (`0x` + 40 hex).
    pub fn secp256k1(address: &str) -> Result<SubjectKeyArgs, SdkError> {
        let a = addr20(&address.to_ascii_lowercase())?;
        let z = hex(&[0; 32]);
        Ok(SubjectKeyArgs {
            kind: 2,
            x: format!("0x{}{}", "00".repeat(12), &hex(&a)[2..]),
            y: z.clone(),
            rp_id_hash: z.clone(),
            origin_hash: z,
        })
    }

    fn key(&self) -> Result<SubjectKey, SdkError> {
        let w = |s: &str| -> Result<[u8; 32], SdkError> {
            unhex(&s.to_ascii_lowercase())?
                .try_into()
                .map_err(|_| SdkError::Argument)
        };
        Ok(SubjectKey {
            kind: self.kind,
            x: w(&self.x)?,
            y: w(&self.y)?,
            rp_id_hash: w(&self.rp_id_hash)?,
            origin_hash: w(&self.origin_hash)?,
        })
    }

    fn put(&self, m: &mut Map<String, Value>) -> Result<(), SdkError> {
        let k = self.key()?;
        m.insert("kind".into(), json!(k.kind));
        m.insert("x".into(), json!(hex(&k.x)));
        m.insert("y".into(), json!(hex(&k.y)));
        m.insert("rpIdHash".into(), json!(hex(&k.rp_id_hash)));
        m.insert("originHash".into(), json!(hex(&k.origin_hash)));
        Ok(())
    }
}

/// The part every `SmartKeyAccount` entry shares: the account (`0x` + 40 hex), the key of it that signs, the lane, the envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmartOp {
    pub signer: KeyRef,
    pub chain: String,
    pub account: String,
    pub batch: String,
    pub envelope: Envelope,
}

/// The call of a `SmartKeyAccount`'s `Execute` (spec §13.2): decoded, or opaque under the marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmartCall {
    /// an ERC-20 `transfer(to, amount)` of `token` held by the account
    Transfer {
        token: String,
        to: String,
        amount: String,
    },
    /// `account.initiateRecovery(key)`: the signer's account is `account`'s guardian (CTR-ACC-03)
    InitiateRecovery { account: String, key: SubjectKeyArgs },
    /// any other call: `OpaqueCallRefused` without the marker
    Opaque {
        target: String,
        value: String,
        data: String,
        allow: Option<AllowOpaqueCall>,
    },
}

/// The counterfactual address of the `SmartKeyAccount` of `first_key` and `guardian` (`0x` + 40 hex; zero: none) deployed by
/// `factory` as a clone of `implementation` (CTR-ACC-01; `scaas-ua` `account_salt`, `account_address`).
pub fn smart_account_address(
    factory: &str,
    implementation: &str,
    first_key: &SubjectKeyArgs,
    guardian: &str,
) -> Result<String, SdkError> {
    let k = first_key.key()?;
    let a = |s: &str| addr20(&s.to_ascii_lowercase());
    let salt = scaas_ua::factory::account_salt(
        k.kind,
        &k.x,
        &k.y,
        &k.rp_id_hash,
        &k.origin_hash,
        &a(guardian)?,
    );
    Ok(hex(&scaas_ua::factory::account_address(
        &a(factory)?,
        &a(implementation)?,
        &salt,
    )))
}

impl Account {
    /// One entry: `from` the account, `fields` the struct's, the envelope; `Expect::Op` unless `expect` is given.
    async fn smart(
        &self,
        name: &'static str,
        op: SmartOp,
        fields: Map<String, Value>,
        decoded: Option<(DecodedCall, Vec<crate::op::ReviewField>)>,
        opaque: bool,
    ) -> Result<Arc<Prepared>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let account = addr20(&op.account.to_ascii_lowercase())?;
                let kind = kind_of(&sdk, &op.chain, name, account).await?;
                if kind != "account" {
                    return Err(SdkError::Argument);
                }
                let mut m = Map::new();
                m.insert("from".into(), json!(hex(&account)));
                m.extend(fields);
                put_envelope(&mut m, &op.batch, &op.envelope);
                let mut d: Draft = crate::wallet::ops::draft(op.chain.clone(), name, kind, account, m, op.signer);
                d.opaque = opaque;
                if let Some((call, review)) = decoded {
                    let (chain_id, chain_uid) = ids(&sdk, &op.chain)?;
                    let max_window = sdk.window(&op.chain);
                    d.review = review;
                    d.expect = Some(Box::new(move |now, msg: &Value| {
                        let o = msg.as_object().ok_or(SdkError::Argument)?;
                        let (fee_recipient, relayer) = bound(o)?;
                        Ok(Expect::Execute {
                            wallet: account,
                            chain_id,
                            chain_uid,
                            message: msg.clone(),
                            call: call.clone(),
                            max_fee: scaas_ua::wallet::fee_due(name, msg)?,
                            fee_recipient,
                            relayer,
                            now,
                            max_window,
                        })
                    }));
                }
                Op::prepare(&sdk, d).await
            })
            .await
    }

    /// `AddKey` (CTR-ACC-10): `ProfileMismatch`, `Argument`, `WalletLocked`.
    pub async fn prepare_smart_add_key(&self, op: SmartOp, key: SubjectKeyArgs) -> Result<Arc<Prepared>, SdkError> {
        let mut m = Map::new();
        key.put(&mut m)?;
        self.smart("AddKey", op, m, None, false).await
    }

    /// `RemoveKey` of the key at `index` (decimal).
    pub async fn prepare_smart_remove_key(&self, op: SmartOp, index: String) -> Result<Arc<Prepared>, SdkError> {
        let mut m = Map::new();
        m.insert("index".into(), json!(index));
        self.smart("RemoveKey", op, m, None, false).await
    }

    /// `RotateKey`: `key` added, the key at `index` removed, atomically.
    pub async fn prepare_smart_rotate_key(
        &self,
        op: SmartOp,
        index: String,
        key: SubjectKeyArgs,
    ) -> Result<Arc<Prepared>, SdkError> {
        let mut m = Map::new();
        m.insert("index".into(), json!(index));
        key.put(&mut m)?;
        self.smart("RotateKey", op, m, None, false).await
    }

    /// `SetGuardian` (`0x` + 40 hex; zero: none); it also cancels the old guardian's pending recovery.
    pub async fn prepare_smart_set_guardian(&self, op: SmartOp, guardian: String) -> Result<Arc<Prepared>, SdkError> {
        let mut m = Map::new();
        m.insert("guardian".into(), json!(hex(&addr20(&guardian.to_ascii_lowercase())?)));
        self.smart("SetGuardian", op, m, None, false).await
    }

    /// `CancelRecovery` of the pending recovery.
    pub async fn prepare_smart_cancel_recovery(&self, op: SmartOp) -> Result<Arc<Prepared>, SdkError> {
        self.smart("CancelRecovery", op, Map::new(), None, false).await
    }

    /// `CancelNonce` of lane `lane` (decimal) on the account.
    pub async fn prepare_smart_cancel_nonce(&self, op: SmartOp, lane: String) -> Result<Arc<Prepared>, SdkError> {
        let mut m = Map::new();
        m.insert("lane".into(), json!(lane));
        self.smart("CancelNonce", op, m, None, false).await
    }

    /// `Execute`: a decoded call (spec §13.2), or an opaque one only under [`AllowOpaqueCall`] (`OpaqueCallRefused`
    /// otherwise), its review flagged `opaque`.
    pub async fn prepare_smart_execute(&self, op: SmartOp, call: SmartCall) -> Result<Arc<Prepared>, SdkError> {
        let (decoded, review) = match &call {
            SmartCall::Transfer { token, to, amount } => {
                U256::from_str_radix(amount, 10).map_err(|_| SdkError::Argument)?;
                let (t, to20) = (addr20(&token.to_ascii_lowercase())?, addr20(&to.to_ascii_lowercase())?);
                let review = vec![
                    field("call", "transfer", "transfer(address,uint256)", Source::Signed),
                    field("call.token", &hex(&t), &hex(&t), Source::Signed),
                    field("call.to", &hex(&to20), &hex(&to20), Source::Signed),
                    field("call.amount", amount, amount, Source::Signed),
                ];
                let c = DecodedCall::Erc20Transfer {
                    token: t,
                    to: to20,
                    amount: amount.clone(),
                };
                (Some(c), review)
            }
            SmartCall::InitiateRecovery { account, key } => {
                let a = addr20(&account.to_ascii_lowercase())?;
                let k = key.key()?;
                let review = vec![
                    field("call", "initiateRecovery", "initiateRecovery(SubjectKey)", Source::Signed),
                    field("call.account", &hex(&a), &hex(&a), Source::Signed),
                    field("call.key.kind", &k.kind.to_string(), &k.kind.to_string(), Source::Signed),
                    field("call.key.x", &hex(&k.x), &hex(&k.x), Source::Signed),
                    field("call.key.y", &hex(&k.y), &hex(&k.y), Source::Signed),
                    field("call.key.rpIdHash", &hex(&k.rp_id_hash), &hex(&k.rp_id_hash), Source::Signed),
                    field("call.key.originHash", &hex(&k.origin_hash), &hex(&k.origin_hash), Source::Signed),
                ];
                (Some(DecodedCall::InitiateRecovery { account: a, key: k }), review)
            }
            SmartCall::Opaque { allow: None, .. } => return Err(SdkError::OpaqueCallRefused),
            SmartCall::Opaque { .. } => (None, vec![]),
        };
        let mut m = Map::new();
        match (&decoded, &call) {
            (Some(c), _) => {
                let (target, value, data) = c.encode()?;
                m.insert("target".into(), json!(hex(&target)));
                m.insert("value".into(), json!(U256::from_be_bytes(value).to_string()));
                m.insert("data".into(), json!(hex(&data)));
            }
            (
                None,
                SmartCall::Opaque {
                    target, value, data, ..
                },
            ) => {
                let data = unhex(&data.to_ascii_lowercase())?;
                if data.len() > 128 * 1024 {
                    return Err(SdkError::Argument);
                }
                m.insert("target".into(), json!(hex(&addr20(&target.to_ascii_lowercase())?)));
                m.insert("value".into(), json!(value));
                m.insert("data".into(), json!(hex(&data)));
            }
            _ => return Err(SdkError::Internal),
        }
        let opaque = decoded.is_none();
        self.smart("Execute", op, m, decoded.map(|c| (c, review)), opaque)
            .await
    }

    /// The guardian's recovery of `account` (CTR-ACC-03): `op` names the guardian `SmartKeyAccount` and its key; its `Execute`
    /// of the decoded `initiateRecovery(new_key)` on `account`. `completeRecovery(new_key)` may follow after `RECOVERY_DELAY`
    /// (two days), by anyone; the account's own `CancelRecovery` stops it.
    pub async fn prepare_initiate_recovery(
        &self,
        op: SmartOp,
        account: String,
        new_key: SubjectKeyArgs,
    ) -> Result<Arc<Prepared>, SdkError> {
        self.prepare_smart_execute(
            op,
            SmartCall::InitiateRecovery {
                account,
                key: new_key,
            },
        )
        .await
    }
}
