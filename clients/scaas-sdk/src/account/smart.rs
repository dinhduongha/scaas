// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `SmartKeyAccount` (spec §7; plan T13; CTR-ACC-01, CTR-ACC-03, CTR-ACC-10): its counterfactual address by `scaas-ua`, and its
//! own entries `AddKey`, `RemoveKey`, `RotateKey`, `SetGuardian`, `CancelRecovery`, `CancelNonce` and `Execute`, each signed by
//! one of the account's keys (`from` is the account itself) in its domain (`SCaaS SmartKeyAccount`, read from the contract's
//! `eip712Domain()` and held to the profile), then quoted and submitted as every operation (`Op::quote`, `Op::submit`; §13).
//! `Execute` takes a decoded call only (§13.2): `scaas-ua` builds its bytes and its check `Expect::Execute` rebuilds them; any
//! other call needs [`AllowOpaqueCall`] (feature `opaque-calls`), else `OpaqueCallRefused`. Guardian recovery: the guardian
//! `SmartKeyAccount`'s `Execute` of the decoded `initiateRecovery(newKey)` on the account it guards
//! ([`Account::prepare_initiate_recovery`]); `completeRecovery` is anyone's direct call after `RECOVERY_DELAY`
//! ([`Account::prepare_complete_recovery`]), the deploy the factory's `deploy(firstKey, guardian)`
//! ([`Account::prepare_smart_deploy`]), each a native send of the caller's EVM key (spec §8.5). The account's
//! key signs as `AccountSig { keyIndex, proof: [], signature }`, `keyIndex` the signing key's index in the account: the
//! caller's, or read from the account by the signer's key (owner 2026-11-19, S3). UNAUDITED.
use super::Account;
use crate::op::{addr20, field, hex, unhex, Draft, KeyRef, Op, Prepared, Source};
use crate::wallet::ops::{bound, ids, kind_of, put_envelope};
use crate::wallet::{AllowOpaqueCall, Envelope, NativeQuote, NativeSend};
use crate::SdkError;
use alloy::primitives::U256;
use scaas_ua::wallet::{DecodedCall, Expect, SubjectKey};
use serde_json::{json, Map, Value};
use std::sync::Arc;

/// A `SubjectKey` by name: `kind` 1 a passkey (`x`, `y` P-256, `rpIdHash`, `originHash`), 2 a secp256k1 key (`x` its address
/// right-aligned, the rest 0); words as `0x` + 64 hex.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
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
/// `key_index` (decimal) is the signer's index in the account; `None`: read from the account (S3).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct SmartOp {
    pub signer: KeyRef,
    pub key_index: Option<String>,
    pub chain: String,
    pub account: String,
    pub batch: String,
    pub envelope: Envelope,
}

/// The call of a `SmartKeyAccount`'s `Execute` (spec §13.2): decoded, or opaque under the marker.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub enum SmartCall {
    /// an ERC-20 `transfer(to, amount)` of `token` held by the account
    Transfer {
        token: String,
        to: String,
        amount: String,
    },
    /// `account.initiateRecovery(key)`: the signer's account is `account`'s guardian (CTR-ACC-03)
    InitiateRecovery {
        account: String,
        key: SubjectKeyArgs,
    },
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

/// `key` as the ABI's static tuple `(uint8 kind, bytes32 x, bytes32 y, bytes32 rpIdHash, bytes32 originHash)`.
fn key_words(key: &SubjectKeyArgs) -> Result<Vec<u8>, SdkError> {
    let k = key.key()?;
    let mut d = U256::from(k.kind).to_be_bytes::<32>().to_vec();
    for w in [k.x, k.y, k.rp_id_hash, k.origin_hash] {
        d.extend_from_slice(&w);
    }
    Ok(d)
}

/// The calldata of `sig` with `args` (static words).
fn direct_call(sig: &str, args: &[u8]) -> String {
    let mut d = scaas_ua::keccak256(sig.as_bytes())
        .get(..4)
        .unwrap_or_default()
        .to_vec();
    d.extend_from_slice(args);
    hex(&d)
}

/// The most key slots [`key_index_of`] reads; past it the caller names the index.
const KEY_SLOTS_READ: u64 = 64;

/// The index of `signer`'s key (an EVM key: `SubjectKey` kind 2, its address) in `account` (S3): `nextKeyIndex()`, then
/// `keyAt(i)` from 0 until one equals it (removed slots read as zero). `SignerNotAccountKey` (owner 2026-11-19, P2): no slot
/// holds it; `Argument`: an account of more than [`KEY_SLOTS_READ`] slots without it in them (the caller names the index), or
/// a signer that is no EVM key.
async fn key_index_of(
    sdk: &crate::Sdk,
    chain: &str,
    account: [u8; 20],
    signer: &KeyRef,
) -> Result<U256, SdkError> {
    use alloy::network::TransactionBuilder;
    let (_, _, pool) = crate::op::evm(sdk, chain)?;
    // an EVM key of the seed or imported (spec §6.7): its address
    let crate::op::Key::Native(_, k) = crate::op::key(sdk, signer)? else {
        return Err(SdkError::Argument);
    };
    if !matches!(signer, KeyRef::Native { network, .. } | KeyRef::Imported { network, .. } if network == "evm")
    {
        return Err(SdkError::Argument);
    }
    let want = key_words(&SubjectKeyArgs::secp256k1(
        &k.address().ok_or(SdkError::Argument)?,
    )?)?;
    let call = |sig: &str, arg: Option<u64>| {
        let mut d = scaas_ua::keccak256(sig.as_bytes())
            .get(..4)
            .unwrap_or_default()
            .to_vec();
        if let Some(a) = arg {
            d.extend_from_slice(&U256::from(a).to_be_bytes::<32>());
        }
        let tx = alloy::rpc::types::TransactionRequest::default()
            .with_to(alloy::primitives::Address::from(account))
            .with_input(alloy::primitives::Bytes::from(d));
        let pool = pool.clone();
        async move { pool.call_tx(tx).await.map_err(crate::op::sim) }
    };
    let next = call("nextKeyIndex()", None).await?;
    let next = u64::try_from(U256::from_be_slice(
        next.get(..32).ok_or(SdkError::Argument)?,
    ))
    .unwrap_or(u64::MAX);
    for i in 0..next.min(KEY_SLOTS_READ) {
        if call("keyAt(uint256)", Some(i)).await?.as_ref() == want.as_slice() {
            return Ok(U256::from(i));
        }
    }
    Err(if next > KEY_SLOTS_READ {
        SdkError::Argument
    } else {
        SdkError::SignerNotAccountKey
    })
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
                // only the `account` kind has these rows: another contract's domain is `Argument` here
                let kind = kind_of(&sdk, &op.chain, name, account).await?;
                let mut m = Map::new();
                m.insert("from".into(), json!(hex(&account)));
                m.extend(fields);
                put_envelope(&mut m, &op.batch, &op.envelope);
                let key_index = match &op.key_index {
                    Some(i) => U256::from_str_radix(i, 10).map_err(|_| SdkError::Argument)?,
                    None => key_index_of(&sdk, &op.chain, account, &op.signer).await?,
                };
                let mut d: Draft =
                    crate::wallet::ops::draft(op.chain.clone(), name, kind, account, m, op.signer);
                d.opaque = opaque;
                d.key_index = key_index;
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
    pub async fn prepare_smart_add_key(
        &self,
        op: SmartOp,
        key: SubjectKeyArgs,
    ) -> Result<Arc<Prepared>, SdkError> {
        let mut m = Map::new();
        key.put(&mut m)?;
        self.smart("AddKey", op, m, None, false).await
    }

    /// `RemoveKey` of the key at `index` (decimal).
    pub async fn prepare_smart_remove_key(
        &self,
        op: SmartOp,
        index: String,
    ) -> Result<Arc<Prepared>, SdkError> {
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
    pub async fn prepare_smart_set_guardian(
        &self,
        op: SmartOp,
        guardian: String,
    ) -> Result<Arc<Prepared>, SdkError> {
        let mut m = Map::new();
        m.insert(
            "guardian".into(),
            json!(hex(&addr20(&guardian.to_ascii_lowercase())?)),
        );
        self.smart("SetGuardian", op, m, None, false).await
    }

    /// `CancelRecovery` of the pending recovery.
    pub async fn prepare_smart_cancel_recovery(
        &self,
        op: SmartOp,
    ) -> Result<Arc<Prepared>, SdkError> {
        self.smart("CancelRecovery", op, Map::new(), None, false)
            .await
    }

    /// `CancelNonce` of lane `lane` (decimal) on the account.
    pub async fn prepare_smart_cancel_nonce(
        &self,
        op: SmartOp,
        lane: String,
    ) -> Result<Arc<Prepared>, SdkError> {
        let mut m = Map::new();
        m.insert("lane".into(), json!(lane));
        self.smart("CancelNonce", op, m, None, false).await
    }

    /// `Execute`: a decoded call (spec §13.2), or an opaque one only under [`AllowOpaqueCall`] (`OpaqueCallRefused`
    /// otherwise), its review flagged `opaque`.
    pub async fn prepare_smart_execute(
        &self,
        op: SmartOp,
        call: SmartCall,
    ) -> Result<Arc<Prepared>, SdkError> {
        let (decoded, review) = match &call {
            SmartCall::Transfer { token, to, amount } => {
                U256::from_str_radix(amount, 10).map_err(|_| SdkError::Argument)?;
                let (t, to20) = (
                    addr20(&token.to_ascii_lowercase())?,
                    addr20(&to.to_ascii_lowercase())?,
                );
                let review = vec![
                    field(
                        "call",
                        "transfer",
                        "transfer(address,uint256)",
                        Source::Signed,
                    ),
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
                    field(
                        "call",
                        "initiateRecovery",
                        "initiateRecovery(SubjectKey)",
                        Source::Signed,
                    ),
                    field("call.account", &hex(&a), &hex(&a), Source::Signed),
                    field(
                        "call.key.kind",
                        &k.kind.to_string(),
                        &k.kind.to_string(),
                        Source::Signed,
                    ),
                    field("call.key.x", &hex(&k.x), &hex(&k.x), Source::Signed),
                    field("call.key.y", &hex(&k.y), &hex(&k.y), Source::Signed),
                    field(
                        "call.key.rpIdHash",
                        &hex(&k.rp_id_hash),
                        &hex(&k.rp_id_hash),
                        Source::Signed,
                    ),
                    field(
                        "call.key.originHash",
                        &hex(&k.origin_hash),
                        &hex(&k.origin_hash),
                        Source::Signed,
                    ),
                ];
                (
                    Some(DecodedCall::InitiateRecovery { account: a, key: k }),
                    review,
                )
            }
            SmartCall::Opaque { allow: None, .. } => return Err(SdkError::OpaqueCallRefused),
            SmartCall::Opaque { .. } => (None, vec![]),
        };
        let mut m = Map::new();
        match (&decoded, &call) {
            (Some(c), _) => {
                let (target, value, data) = c.encode()?;
                m.insert("target".into(), json!(hex(&target)));
                m.insert(
                    "value".into(),
                    json!(U256::from_be_bytes(value).to_string()),
                );
                m.insert("data".into(), json!(hex(&data)));
            }
            (
                None,
                SmartCall::Opaque {
                    target,
                    value,
                    data,
                    ..
                },
            ) => {
                let data = unhex(&data.to_ascii_lowercase())?;
                if data.len() > 128 * 1024 {
                    return Err(SdkError::Argument);
                }
                m.insert(
                    "target".into(),
                    json!(hex(&addr20(&target.to_ascii_lowercase())?)),
                );
                m.insert("value".into(), json!(value));
                m.insert("data".into(), json!(hex(&data)));
            }
            _ => return Err(SdkError::Internal),
        }
        let opaque = decoded.is_none();
        self.smart("Execute", op, m, decoded.map(|c| (c, review)), opaque)
            .await
    }

    /// The deploy of the `SmartKeyAccount` of `first_key` and `guardian` (the zero address: none) by `factory`'s
    /// `deploy(firstKey, guardian)` (CTR-ACC-01), at [`smart_account_address`]'s address: a native send of `key` (an EVM key)
    /// quoted for review; `Wallet::submit_native_send` sends it. Errors as `Wallet::prepare_native_send` (a reverting call:
    /// its simulation's error).
    pub async fn prepare_smart_deploy(
        &self,
        key: KeyRef,
        chain: String,
        factory: String,
        first_key: SubjectKeyArgs,
        guardian: String,
    ) -> Result<NativeQuote, SdkError> {
        let mut args = key_words(&first_key)?;
        args.extend_from_slice(&[0; 12]);
        args.extend_from_slice(&addr20(&guardian.to_ascii_lowercase())?);
        let data = direct_call(
            "deploy((uint8,bytes32,bytes32,bytes32,bytes32),address)",
            &args,
        );
        self.direct(key, chain, factory, data).await
    }

    /// `completeRecovery(new_key)` on `account` (CTR-ACC-03): anyone's call once `RECOVERY_DELAY` (two days) has passed since
    /// the guardian's `initiateRecovery(new_key)`; a native send of `key` quoted for review (before the delay its simulation
    /// reverts and the quote fails).
    pub async fn prepare_complete_recovery(
        &self,
        key: KeyRef,
        chain: String,
        account: String,
        new_key: SubjectKeyArgs,
    ) -> Result<NativeQuote, SdkError> {
        let data = direct_call(
            "completeRecovery((uint8,bytes32,bytes32,bytes32,bytes32))",
            &key_words(&new_key)?,
        );
        self.direct(key, chain, account, data).await
    }

    async fn direct(
        &self,
        key: KeyRef,
        chain: String,
        to: String,
        data: String,
    ) -> Result<NativeQuote, SdkError> {
        let send = NativeSend {
            key,
            chain,
            to,
            value: "0".into(),
            data: Some(data),
            tx_type: None,
        };
        self.sdk.wallet().prepare_native_send(send).await
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
