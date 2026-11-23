// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The hand-off (spec §27.5 (c); plan T41.evm; decisions CLI-SDK-32's self-relay rule, CLI-SDK-33 (23), (49)): the signer signs
//! an operation once and hands its named fields and signature to its payee out of band ([`SignedOpBlob`]); the payee imports
//! it, every check in its order with its named refusal, and submits it with its own native key (`SubmitPath::SelfRelay`), paying
//! the gas. `scaas-ua` rebuilds the signed bytes from the named fields; the chain judges the signature (the simulation from the
//! payer). The signer's row is `handed_off` and ends only on chain facts (§13.5). UNAUDITED.
use super::prepared::{envelope, field, Draft, Prepared, Source};
use super::quote::{fee_of, payer_address, signer_kind};
use super::state::{self, Row};
use super::submit::{build, fresh, put_back, signature, take, unsigned};
use super::{dec, evm, hex, lane_nonce, sim, unhex, KeyRef, Op};
use crate::{Family, SdkError};
use alloy::primitives::{Address, Bytes, U256};
use serde_json::Value;
use std::sync::Arc;

/// The time an imported operation must still have before its `validUntil` on the chain's clock: the node's 120 s.
const IMPORT_MARGIN_SECS: u64 = 120;

pub use crate::wallet::handoff::{SignedOpBlob, HANDOFF_MAX};

/// What the payee expects of an imported operation: its chain, its own ids (`0x` + 64 hex: a pay or transfer must name one as
/// `to`), and the native key that will submit it (`SubmitPath::SelfRelay`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct ImportExpect {
    pub chain: String,
    pub payee: Vec<String>,
    pub payer: KeyRef,
}

/// The operation's payee: `to` of the struct or of its `payment`; `None` for a kind without one.
fn payee_of(m: &Value) -> Option<&str> {
    m.get("to")
        .or_else(|| m.get("payment").and_then(|p| p.get("to")))
        .and_then(Value::as_str)
}

impl Op {
    /// The signer's side (spec §27.5 (c)): signs `prepared` once under its check, writes its row ahead (state `handed_off`,
    /// path `handoff`, its id `prepared.id()` for `Op::state`), sends nothing, and returns the blob for its payee. `PreparedUnknown`, `PreparedStale`; `Argument` for an
    /// operation with a fee (a hand-off is fee 0, (b)), a relay fee's paid call, an order's other contract or a
    /// `bls12381-multi` group (its aggregate is `submit_bls_multi`'s). The row ends on chain facts only.
    pub async fn hand_off(&self, prepared: Arc<Prepared>) -> Result<SignedOpBlob, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                Op::known(&sdk, &prepared)?;
                let p = &prepared;
                if fee_of(p.t.name, &p.t.message)? != "0"
                    || p.t.relay_call.is_some()
                    || p.t.target.is_some()
                    || matches!(p.signer(), KeyRef::BlsMulti { .. } | KeyRef::Signed { .. })
                {
                    return Err(SdkError::Argument);
                }
                let (from, batch, nonce) =
                    p.t.lane
                        .as_ref()
                        .map(|(f, b, n)| (hex(f), b.to_string(), n.to_string()))
                        .ok_or(SdkError::Argument)?;
                fresh(&sdk, p).await?;
                let (profile, _, pool) = evm(&sdk, &p.chain())?;
                let from_block = super::final_number(&pool, &profile).await?;
                take(&sdk, &prepared)?;
                let signed = async {
                    let (sig, extra) = signature(&sdk, p).await?;
                    let built = build(p, &sig, &extra)?;
                    let kind = signer_kind(&sdk, p).await?;
                    Ok::<_, SdkError>((sig, extra, built, kind, unsigned(p)?.calldata.len()))
                }
                .await;
                let (sig, extra, built, kind, unsigned_len) = match signed {
                    Ok(v) => v,
                    Err(e) => {
                        put_back(&sdk, &prepared);
                        return Err(e);
                    }
                };
                // the row's id is the operation's (`prepared.id()`, the typed digest): the signer follows it by `Op::state`
                let row = Row {
                    op: p.id(),
                    chain: p.chain(),
                    entry: p.entry(),
                    name: p.t.name.into(),
                    kind: p.t.kind.into(),
                    contract: hex(&p.t.entry_contract()),
                    from: from.clone(),
                    batch,
                    nonce,
                    valid_until: p.expires_at(),
                    digest: p.id(),
                    op_json: built.op.clone().unwrap_or(Value::Null),
                    calldata: hex(&built.calldata),
                    raw: None,
                    tx_id: None,
                    tx_nonce: None,
                    path: "handoff".into(),
                    payer: None,
                    from_block,
                    state: "handed_off".into(),
                    detail: "Signed".into(),
                    landed: None,
                    relayer_bound: envelope(&p.t.message)
                        .and_then(|e| e.get("mode"))
                        .map(dec)
                        .transpose()?
                        .is_some_and(|m| m.bit(0)),
                    gas_limit: None,
                    signer_kind: Some(kind),
                    unsigned_len: Some(unsigned_len as u64),
                    members: None,
                    ended_at: None,
                    message: p.t.message.clone(),
                    extra: extra.clone(),
                    fact: None,
                    basis: None,
                };
                // the write ahead: the signature leaves the SDK only in the blob returned after it
                state::put(&sdk, &row).await?;
                Ok(SignedOpBlob {
                    v: 1,
                    chain_uid: profile.chain_uid.to_ascii_lowercase(),
                    family: "evm".into(),
                    contract: hex(&p.t.contract),
                    entry: p.entry(),
                    name: p.t.name.into(),
                    kind: p.t.kind.into(),
                    message: p.t.message.clone(),
                    extra,
                    signature: sig,
                    signer: from,
                    signer_kind: kind,
                    ids: p.t.ids,
                })
            })
            .await
    }

    /// The payee's side (spec §27.5 (c)): the blob's checks in order, each its refusal, then an ordinary [`Prepared`] whose
    /// signature is made, for `quote` and `submit` on `SubmitPath::SelfRelay` by `expect.payer`: the profile's `chain_uid` and
    /// family (`ProfileMismatch`); the contract a listed token of the profile (`ProfileMismatch`); a confidential kind or a
    /// struct the token rows do not hold (`ImportKindRefused`); a pay or transfer to none of `expect.payee` (`ImportNotPayee`);
    /// a `relayer` bound to another address than the payer's (`ImportRelayerBound`); a fee (`ImportFeeRefused`); fewer than
    /// 120 s left on the chain's clock (`ImportExpired`); its lane nonce spent (`ImportConsumed`); then `scaas-ua` rebuilds
    /// the typed data and the calldata from the named fields, and the calldata simulated from the payer must not revert
    /// (`ImportedOpRefused`); a signer kind the profile disables is `KindDisabled`. The review lists the signed fields, `handed_off` and the simulation's gas. `ChainUnknown`;
    /// `Argument` for a payer that is not an EVM native key.
    pub async fn import_signed(
        &self,
        blob: SignedOpBlob,
        expect: ImportExpect,
    ) -> Result<Arc<Prepared>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let c = sdk.chain(&expect.chain)?;
                // 1. the chain
                if blob.v != 1
                    || blob.family != "evm"
                    || c.profile.family != Family::Evm
                    || !blob.chain_uid.eq_ignore_ascii_case(&c.profile.chain_uid)
                {
                    return Err(SdkError::ProfileMismatch);
                }
                // 2. a listed token of the profile
                if !c
                    .profile
                    .tokens
                    .iter()
                    .any(|t| t.address.eq_ignore_ascii_case(&blob.contract))
                {
                    return Err(SdkError::ProfileMismatch);
                }
                // 3. the kind: a token's own rows, never a confidential one (spec §27.5 (g) 9)
                let ids =
                    blob.ids && blob.name == "UAMetaTransfer" && blob.entry == "mtxExecuteTransfer";
                let row = scaas_ua::wallet::entries::entry_rows()
                    .into_iter()
                    .find(|r| {
                        r.name == blob.name
                            && r.kinds.contains(&"token")
                            && (ids || (!blob.ids && r.entry == blob.entry))
                    })
                    .filter(|_| blob.kind == "token")
                    .ok_or(SdkError::ImportKindRefused)?;
                // 4. a payee's operation pays one of the importer's ids
                if let Some(to) = payee_of(&blob.message) {
                    if !expect.payee.iter().any(|p| p.eq_ignore_ascii_case(to)) {
                        return Err(SdkError::ImportNotPayee);
                    }
                }
                // 5. a bound relayer is the payer
                let payer = payer_address(&sdk, &expect.payer)?;
                let env = envelope(&blob.message).ok_or(SdkError::ImportKindRefused)?;
                let mode = env.get("mode").map(dec).transpose()?.unwrap_or_default();
                if mode.bit(0) {
                    let bound = env
                        .get("relayer")
                        .and_then(Value::as_str)
                        .and_then(|r| r.parse::<Address>().ok());
                    if bound != Some(payer) {
                        return Err(SdkError::ImportRelayerBound);
                    }
                }
                // 6. fee 0, to anyone: the envelope's own and the amount the relayer would take
                let fee = env.get("fee").map(dec).transpose()?.unwrap_or_default();
                if !fee.is_zero() || fee_of(row.name, &blob.message)? != "0" {
                    return Err(SdkError::ImportFeeRefused);
                }
                let (profile, _, pool) = evm(&sdk, &expect.chain)?;
                // a signer kind the chain's profile disables (owner 2026-11-22), as `prepare` refuses its own
                super::ua_kind_enabled(&profile, blob.signer_kind)?;
                let contract = super::addr20(&blob.contract)?;
                // 7. time left on the chain's clock
                let valid_until = env
                    .get("validUntil")
                    .map(dec)
                    .transpose()?
                    .ok_or(SdkError::Argument)?;
                let (_, now) = super::head(&pool).await?;
                if valid_until < U256::from(now.saturating_add(IMPORT_MARGIN_SECS)) {
                    return Err(SdkError::ImportExpired);
                }
                // 8. the lane nonce unspent
                let from = unhex(
                    env.get("from")
                        .and_then(Value::as_str)
                        .ok_or(SdkError::Argument)?,
                )?;
                let batch = dec(env.get("batch").ok_or(SdkError::Argument)?)?;
                let nonce = dec(env.get("nonce").ok_or(SdkError::Argument)?)?;
                if lane_nonce(&pool, Address::from(contract), "token", &from, batch).await? > nonce
                {
                    return Err(SdkError::ImportConsumed);
                }
                // 9. scaas-ua rebuilds the typed data and the calldata from the named fields
                let draft = Draft {
                    chain: expect.chain.clone(),
                    name: row.name,
                    kind: "token",
                    contract,
                    message: blob.message.clone(),
                    extra: blob.extra.clone(),
                    signer: KeyRef::Signed { signer: hex(&from) },
                    expect: None,
                    review: vec![field(
                        "handed_off",
                        &hex(&from),
                        &format!("handed off, signed by {}", hex(&from)),
                        Source::Derived,
                    )],
                    touched: vec![],
                    opaque: false,
                    ids: blob.ids,
                    relay_call: None,
                    owner: None,
                    key_index: U256::ZERO,
                    target: None,
                };
                let p = Op::prepare_signed(
                    &sdk,
                    draft,
                    Some((blob.signature.clone(), blob.signer_kind)),
                )
                .await?;
                if p.entry() != blob.entry {
                    let _ = take(&sdk, &p);
                    return Err(SdkError::ImportKindRefused);
                }
                // 10. the chain judges the signature: the signed calldata simulated from the payer
                let built = build(&p, &blob.signature, &blob.extra)?;
                let gas = match pool
                    .simulate_from(
                        payer,
                        Address::from(p.t.entry_contract()),
                        Bytes::from(built.calldata),
                    )
                    .await
                {
                    Ok(g) => g,
                    Err(e) => {
                        let _ = take(&sdk, &p);
                        return Err(match sim(e) {
                            SdkError::Rpc(scaas_rpc::RpcError::Revert { .. }) => {
                                SdkError::ImportedOpRefused
                            }
                            other => other,
                        });
                    }
                };
                p.add_review(field(
                    "simulation.gas",
                    &gas.to_string(),
                    &gas.to_string(),
                    Source::Derived,
                ));
                Ok(p)
            })
            .await
    }
}
