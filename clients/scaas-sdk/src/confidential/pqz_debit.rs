// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The PQZ debits (spec §9.2, §9.3, §21; plan T16): `UAPqzTransferSingle`, `…SingleCompact`, `UAPqzTransfer`, `…Compact`,
//! `UAPqzUnshield`, `UAPqzUnshieldUnwrap`, each a prepared operation of [`crate::op`] signed by the holder's UA key.
//!
//! 1. The reading layer ([`super::pqz`]) reads the holder's words and, as a second fixed set, the current keys of the
//!    recipients and of the token's auditor, at one final block (R1 to R7).
//! 2. The envelope's binding (`scaas-ua` `envelope_binding`, the lane's nonce read here) folded into the header's envelope word
//!    as the token folds it: a transfer's by `bind_mode` (the token's default form, or `HASH` for a `…Compact` entry), a burn's
//!    as given, an unwrap's with `unwrap_envelope`.
//! 3. The facade's `proveTransfer` / `proveTransferMulti` / `proveBurn` off the async workers (`Sdk::heavy`); the arguments
//!    are the statement's parts (`u`, `v_t`, `v_f`, `v_a`, per leg), its salt, the answer's `p`, `ownTag` and sealed memo.
//! 4. The holder's `PqzAuth` over the statement (`scaas-ua` `pqz_auth_message`, purpose `zether-auth`, P-T16-1), signed by
//!    `submit` before the entry and attached as `extra.pqzAuth`; the `PqzSignedVerdict` attached as `extra.pqzVerdict`: on an
//!    `OFFCHAIN` token the checked verdict of the token's verifier ([`super::verdict`]; refused: `VerdictRefused`, nothing
//!    sent), on a `PRECOMPILE` token the empty one the token never reads.
//!
//! `accHint` is sent empty: the token reads `acc`'s slots (a stale or missing hint never reverts). ponytail: no hint, which
//! costs a materialised PQZL op 1 0.5–0.9 M gas more (pq-zero-knowledge.md §7.2); send the packed stream when that matters.
//! Decoys of an op 7 (CTR-UA-29, T26 B2-2, as Zether's): the caller names the real legs and a count of decoys; the SDK draws
//! the decoys uniformly from the registry line's `0x0142` lists (never the holder or a real recipient, amount 0), then
//! shuffles every leg's position, both draws by the facade's CSPRNG (`pickDecoys`) on public data only; the facade refuses a
//! leg count outside the set's built ones.
//! UNAUDITED.
use super::pqz::{call, field as sfield, holder, read};
use super::verdict::{request as verdict, PqzVerdictRequest};
use crate::op::{
    addr20, dec, evm, field, hex, lane_nonce, unhex, Draft, KeyRef, Op, Prepared, ReviewField,
    Source,
};
use crate::wallet::{put_envelope, Envelope};
use crate::{Sdk, SdkError};
use alloy::primitives::{Address, U256};
use scaas_ua::facade::pqz::{
    bind_mode, envelope_binding, pqz_auth_message, pqz_set, unwrap_envelope, Mode, PqzEnvelope,
    Verification, V_BYTES,
};
use serde_json::{json, Map, Value};
use std::sync::Arc;

type W = [u8; 32];
const HEADER: usize = 640;
const ZERO20: &str = "0x0000000000000000000000000000000000000000";

/// `UAPqzTransferSingle` / `UAPqzTransferSingleCompact`: `amount` from the holder's account (the UA key `signer`, PQZ key
/// version `key_version`) to `to_ua`, a registered PQZ holder; the proof valid until block `valid_until_block`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct PqzTransfer {
    pub signer: KeyRef,
    pub chain: String,
    pub token: String,
    pub batch: String,
    pub key_version: u64,
    pub to_ua: String,
    pub amount: String,
    pub valid_until_block: u64,
    pub envelope: Envelope,
}

/// One leg of an op 7: a registered PQZ holder and its amount (`"0"`: a decoy).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct PqzLeg {
    pub to_ua: String,
    pub amount: String,
}

/// `UAPqzTransfer` / `UAPqzTransferCompact`: the real `legs` and `decoys` legs of amount 0 the SDK draws from the registry
/// line's `0x0142` lists, every leg's position shuffled (CTR-UA-29; their count one the set builds, 1, 2, 4 or 8),
/// `decoy_fee` the per-leg fee (decimal; at least the token's `minDecoyFee`, the contract's check).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct PqzTransferMulti {
    pub signer: KeyRef,
    pub chain: String,
    pub token: String,
    pub batch: String,
    pub key_version: u64,
    pub legs: Vec<PqzLeg>,
    pub decoys: u32,
    pub decoy_fee: String,
    pub valid_until_block: u64,
    pub envelope: Envelope,
}

/// `UAPqzUnshield`: `amount` out of the holder's account to `recipient` (a 32-byte id: a padded address or a registered UA).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct PqzUnshield {
    pub signer: KeyRef,
    pub chain: String,
    pub token: String,
    pub batch: String,
    pub key_version: u64,
    pub recipient: String,
    pub amount: String,
    pub valid_until_block: u64,
    pub envelope: Envelope,
}

/// `UAPqzUnshieldUnwrap` (`WRAPPED_PQZ`): `amount` out, unwrapped by leg `underlying` to `recipient`, at least `min_out`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct PqzUnshieldUnwrap {
    pub signer: KeyRef,
    pub chain: String,
    pub token: String,
    pub batch: String,
    pub key_version: u64,
    pub underlying: String,
    pub recipient: String,
    pub amount: String,
    pub min_out: String,
    pub valid_until_block: u64,
    pub envelope: Envelope,
}

/// What the proof proves beside the holder's account.
enum Form {
    Single {
        to: W,
        amount: u64,
    },
    Multi {
        legs: Vec<(W, u64)>,
        decoy_fee: u64,
        decoys: u32,
    },
    Burn {
        amount: u64,
        recipient: W,
    },
    Unwrap {
        underlying: [u8; 20],
        recipient: W,
        amount: u64,
        min_out: u64,
    },
}

struct Debit {
    name: &'static str,
    signer: KeyRef,
    chain: String,
    token: String,
    batch: String,
    key_version: u64,
    valid_until_block: u64,
    envelope: Envelope,
    form: Form,
    review: Vec<ReviewField>,
}

fn w32(s: &str) -> Result<W, SdkError> {
    unhex(&s.to_ascii_lowercase())?
        .try_into()
        .map_err(|_| SdkError::Argument)
}

fn num(s: &str) -> Result<u64, SdkError> {
    s.parse().map_err(|_| SdkError::Argument)
}

/// An address as an ABI word (`None`: 0).
fn addr_word(a: &Option<String>) -> Result<W, SdkError> {
    let mut w = [0u8; 32];
    if let Some(a) = a {
        w[12..].copy_from_slice(&addr20(&a.to_ascii_lowercase())?);
    }
    Ok(w)
}

/// `n` bytes of the statement at `off` (`Internal`: the facade's statement is shorter).
fn part(stmt: &[u8], off: usize, n: usize) -> Result<String, SdkError> {
    stmt.get(off..off + n).map(hex).ok_or(SdkError::Internal)
}

/// The empty `PqzSignedVerdict` a `PRECOMPILE` token never reads.
fn no_verdict() -> Value {
    let z = hex(&[0u8; 32]);
    json!({"pqzVerdict": {"token": ZERO20, "chainId": "0", "proofSystemId": z, "statementHash": z, "proofHash": z,
        "pqzVerifierEpoch": "0", "validUntil": "0"}, "sig": {"keyData": "0x", "signature": "0x", "members": []}})
}

impl super::Confidential {
    /// Prepares `UAPqzTransferSingle` (spec §9.2): the holder's words and the recipient's (and the auditor's) current key read at
    /// the final block, the proof by the facade, `PqzAuth` signed by `submit` first. `WalletLocked`, `ChainUnknown`,
    /// `ProfileMismatch`, `TokenUncatalogued`, `PqzOpeningUnsupported`, `PqzSetMismatch`, `LegKeyMismatch`,
    /// `ReceiverUnregistered`, `VerdictRefused` (an `OFFCHAIN` token), `Argument` (a word set the facade refuses, a balance
    /// below the amount and fee), the pool's codes.
    pub async fn prepare_pqz_transfer(&self, r: PqzTransfer) -> Result<Arc<Prepared>, SdkError> {
        self.pqz_single("UAPqzTransferSingle", r).await
    }

    /// Prepares `UAPqzTransferSingleCompact`: as [`Self::prepare_pqz_transfer`], commit-reveal (`HASH`) on every token.
    pub async fn prepare_pqz_transfer_compact(
        &self,
        r: PqzTransfer,
    ) -> Result<Arc<Prepared>, SdkError> {
        self.pqz_single("UAPqzTransferSingleCompact", r).await
    }

    /// Prepares `UAPqzTransfer` (op 7) in the token's default form.
    pub async fn prepare_pqz_transfer_multi(
        &self,
        r: PqzTransferMulti,
    ) -> Result<Arc<Prepared>, SdkError> {
        self.pqz_multi("UAPqzTransfer", r).await
    }

    /// Prepares `UAPqzTransferCompact` (op 7), commit-reveal on every token.
    pub async fn prepare_pqz_transfer_multi_compact(
        &self,
        r: PqzTransferMulti,
    ) -> Result<Arc<Prepared>, SdkError> {
        self.pqz_multi("UAPqzTransferCompact", r).await
    }

    /// Prepares `UAPqzUnshield` (op 2).
    pub async fn prepare_pqz_unshield(&self, r: PqzUnshield) -> Result<Arc<Prepared>, SdkError> {
        let form = Form::Burn {
            amount: num(&r.amount)?,
            recipient: w32(&r.recipient)?,
        };
        self.pqz_debit(Debit {
            name: "UAPqzUnshield",
            signer: r.signer,
            chain: r.chain,
            token: r.token,
            batch: r.batch,
            key_version: r.key_version,
            valid_until_block: r.valid_until_block,
            envelope: r.envelope,
            form,
            review: vec![],
        })
        .await
    }

    /// Prepares `UAPqzUnshieldUnwrap` (op 2 with the `Unwrap` leg signed in the struct).
    pub async fn prepare_pqz_unshield_unwrap(
        &self,
        r: PqzUnshieldUnwrap,
    ) -> Result<Arc<Prepared>, SdkError> {
        let form = Form::Unwrap {
            underlying: addr20(&r.underlying.to_ascii_lowercase())?,
            recipient: w32(&r.recipient)?,
            amount: num(&r.amount)?,
            min_out: num(&r.min_out)?,
        };
        self.pqz_debit(Debit {
            name: "UAPqzUnshieldUnwrap",
            signer: r.signer,
            chain: r.chain,
            token: r.token,
            batch: r.batch,
            key_version: r.key_version,
            valid_until_block: r.valid_until_block,
            envelope: r.envelope,
            form,
            review: vec![],
        })
        .await
    }

    async fn pqz_single(
        &self,
        name: &'static str,
        r: PqzTransfer,
    ) -> Result<Arc<Prepared>, SdkError> {
        let form = Form::Single {
            to: w32(&r.to_ua)?,
            amount: num(&r.amount)?,
        };
        let review = vec![
            field("request.to", &r.to_ua, &r.to_ua, Source::Request),
            field("request.amount", &r.amount, &r.amount, Source::Request),
        ];
        self.pqz_debit(Debit {
            name,
            signer: r.signer,
            chain: r.chain,
            token: r.token,
            batch: r.batch,
            key_version: r.key_version,
            valid_until_block: r.valid_until_block,
            envelope: r.envelope,
            form,
            review,
        })
        .await
    }

    async fn pqz_multi(
        &self,
        name: &'static str,
        r: PqzTransferMulti,
    ) -> Result<Arc<Prepared>, SdkError> {
        let mut legs = Vec::with_capacity(r.legs.len());
        let mut review = Vec::new();
        for (i, l) in r.legs.iter().enumerate() {
            legs.push((w32(&l.to_ua)?, num(&l.amount)?));
            review.push(field(
                &format!("request.to[{i}]"),
                &l.to_ua,
                &l.to_ua,
                Source::Request,
            ));
            review.push(field(
                &format!("request.amount[{i}]"),
                &l.amount,
                &l.amount,
                Source::Request,
            ));
        }
        if legs.is_empty() {
            return Err(SdkError::Argument);
        }
        review.push(field(
            "request.decoys",
            &r.decoys.to_string(),
            &r.decoys.to_string(),
            Source::Request,
        ));
        let form = Form::Multi {
            legs,
            decoy_fee: num(&r.decoy_fee)?,
            decoys: r.decoys,
        };
        self.pqz_debit(Debit {
            name,
            signer: r.signer,
            chain: r.chain,
            token: r.token,
            batch: r.batch,
            key_version: r.key_version,
            valid_until_block: r.valid_until_block,
            envelope: r.envelope,
            form,
            review,
        })
        .await
    }

    async fn pqz_debit(&self, mut d: Debit) -> Result<Arc<Prepared>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                // a profile disabling `pqz` refuses before any read, proof or verdict request (T26 B2-11)
                crate::op::kind_enabled(&evm(&sdk, &d.chain)?.0, "pqz")?;
                let (ua, key) = holder(&sdk, &d.signer, d.key_version)?;
                if let Form::Multi { legs, decoys, .. } = &mut d.form {
                    *legs = drawn(&sdk, &d.signer, d.key_version, &d.chain, &ua, legs, *decoys).await?;
                }
                let pk = key.1.pk();
                let (profile, chain_id, pool) = evm(&sdk, &d.chain)?;
                let t = addr20(&d.token.to_ascii_lowercase())?;
                let uid: W = unhex(&profile.chain_uid)?.try_into().map_err(|_| SdkError::Argument)?;
                let others: Vec<W> = match &d.form {
                    Form::Single { to, .. } => vec![*to],
                    Form::Multi { legs, .. } => legs.iter().map(|l| l.0).collect(),
                    _ => vec![],
                };
                let op7 = matches!(d.form, Form::Multi { .. });
                // the words first (§9.4): every check of them runs before anything else is read or proven
                let r = read(&sdk, &d.chain, &d.token, ua, d.key_version, &pk, op7, &others).await?;
                let offchain = sfield(&r.slot0, "pqzVerifyMode") == 1;
                // the envelope's binding over the lane's next nonce (`PqzLayer._uaEnvelopeBinding`)
                let e = &d.envelope;
                let batch = dec(&json!(d.batch))?;
                let nonce = lane_nonce(&pool, Address::from(t), "pqz", &ua, batch, None).await?;
                let word = |x: U256| x.to_be_bytes::<32>();
                let binding = envelope_binding(
                    chain_id,
                    &uid,
                    &t,
                    &PqzEnvelope {
                        from: ua,
                        batch: word(batch),
                        nonce: word(nonce),
                        valid_until: word(U256::from(e.valid_until)),
                        mode: word(U256::from(e.mode)),
                        relayer: addr_word(&e.relayer)?,
                        fee: word(dec(&json!(e.fee))?),
                        fee_recipient: addr_word(&e.fee_recipient)?,
                    },
                );
                let verification = if offchain {
                    Verification::Offchain {
                        verifier_fee: r.verifier_fee,
                    }
                } else {
                    Verification::Precompile
                };
                let hash = d.name.ends_with("Compact") || sfield(&r.slot0, "disclosureMode") == 1;
                let mode = if hash { Mode::Hash } else { Mode::Bundle };
                let mode_name = if hash { "HASH" } else { "BUNDLE" };
                // the header's public fee (`PqzCore._common`, no beneficiary): the verifier fee on `OFFCHAIN`, an op 7's legs'
                // decoy fee beside it
                let mut fee = if offchain { r.verifier_fee } else { 0 };
                let mut req = r.words.clone();
                let o = req.as_object_mut().ok_or(SdkError::Internal)?;
                // a debit's form is its command (`forOp7` is the balance's)
                o.remove("forOp7");
                o.insert("chainId".into(), json!(chain_id));
                o.insert("registry".into(), json!(hex(&r.registry)));
                o.insert("validUntilBlock".into(), json!(d.valid_until_block));
                o.insert("shieldIn".into(), json!(0));
                let pk_a = r.auditor.as_ref().map(|a| hex(&a.1));
                let (cmd, op, env_word) = match &d.form {
                    Form::Single { to, amount } => {
                        o.insert("toUA".into(), json!(hex(to)));
                        o.insert("pkT".into(), json!(hex(r.keys.first().ok_or(SdkError::Internal)?)));
                        o.insert("amount".into(), json!(amount));
                        o.insert("mode".into(), json!(mode_name));
                        ("proveTransfer", 1u8, bind_mode(&binding, mode, verification))
                    }
                    Form::Multi { legs, decoy_fee, .. } => {
                        let l: Vec<Value> = legs
                            .iter()
                            .zip(&r.keys)
                            .map(|(l, k)| json!({"pk": hex(k), "ua": hex(&l.0), "amount": l.1}))
                            .collect();
                        o.insert("legs".into(), json!(l));
                        o.insert("mode".into(), json!(mode_name));
                        let m = u64::try_from(legs.len()).map_err(|_| SdkError::Argument)?;
                        fee = decoy_fee.checked_mul(m).and_then(|x| x.checked_add(fee)).ok_or(SdkError::Argument)?;
                        ("proveTransferMulti", 7, bind_mode(&binding, mode, verification))
                    }
                    Form::Burn { amount, recipient } => {
                        o.insert("amount".into(), json!(amount));
                        o.insert("recipient".into(), json!(hex(recipient)));
                        ("proveBurn", 2, binding)
                    }
                    Form::Unwrap {
                        underlying,
                        recipient,
                        amount,
                        min_out,
                    } => {
                        o.insert("amount".into(), json!(amount));
                        o.insert("recipient".into(), json!(hex(recipient)));
                        ("proveBurn", 2, unwrap_envelope(&binding, underlying, *min_out))
                    }
                };
                if let (Some(a), 1 | 7) = (&pk_a, op) {
                    o.insert("pkA".into(), json!(a));
                }
                o.insert("fee".into(), json!(fee));
                o.insert("envelopeBinding".into(), json!(hex(&env_word)));
                // the proof, off the async workers
                let proved = call(&sdk, key, cmd, &req).await?;
                let s = |k: &str| proved.get(k).and_then(Value::as_str).ok_or(SdkError::Internal);
                let stmt = unhex(s("stmt")?)?;
                let proof = s("proof")?.to_string();
                let p = proved.get("p").and_then(Value::as_u64).ok_or(SdkError::Internal)?;
                let sealed = match proved.get("memo").and_then(Value::as_str) {
                    Some(m) => hex(unhex(m)?.get(16..).ok_or(SdkError::Internal)?),
                    None => "0x".into(),
                };
                // the arguments: the statement's parts at the token's offsets (`PqzCore._*Buffer`)
                let (pkl, v) = (pqz_set().pk_len, V_BYTES);
                let ct = pkl + v;
                let salt = part(&stmt, 18 * 32 + 16, 16)?;
                let mut args = Map::new();
                args.insert("p".into(), json!(p.to_string()));
                args.insert("validUntilBlock".into(), json!(d.valid_until_block.to_string()));
                args.insert("shieldIn".into(), json!("0"));
                args.insert("fromUA".into(), json!(hex(&ua)));
                args.insert("keyVersion".into(), json!(d.key_version.to_string()));
                args.insert("beneficiaryUA".into(), json!(hex(&[0u8; 32])));
                args.insert("ownTag".into(), json!(s("ownTag")?));
                let aud = usize::from(pk_a.is_some());
                let empty = json!({"mlkemCt": "0x", "x25519Eph": hex(&[0u8; 32]), "sealedSeed": "0x"});
                let mut message = Map::new();
                let mut vop = Map::new();
                vop.insert("binding".into(), json!(hex(&binding)));
                match &d.form {
                    Form::Single { to, .. } => {
                        let off = HEADER + pkl * (2 + aud) + ct;
                        args.insert("toUA".into(), json!(hex(to)));
                        args.insert("salt".into(), json!(salt));
                        args.insert("u".into(), json!(part(&stmt, off, pkl)?));
                        args.insert("vTo".into(), json!(part(&stmt, off + pkl, v)?));
                        args.insert("vFrom".into(), json!(part(&stmt, off + pkl + v, v)?));
                        let va = if aud == 1 { part(&stmt, off + pkl + 2 * v, v)? } else { "0x".into() };
                        args.insert("vAuditor".into(), json!(va));
                        args.insert("uFrom".into(), json!("0x"));
                        args.insert("sealedMemo".into(), json!(sealed));
                        args.insert("openingTo".into(), empty.clone());
                        args.insert("openingAuditor".into(), empty);
                    }
                    Form::Multi { legs, decoy_fee, .. } => {
                        // `header ‖ pk_f ‖ pk_0…pk_{M−1} ‖ [pk_a] ‖ T ‖ u_0…u_{G−1} ‖ v_0…v_{M−1} ‖ v_f ‖ [v_{a,0}…v_{a,M−1}]`
                        let m = legs.len();
                        let fixed = HEADER + pkl * (1 + m + aud) + ct + v * (m * (1 + aud) + 1);
                        let rest = stmt.len().checked_sub(fixed).ok_or(SdkError::Internal)?;
                        if rest % pkl != 0 {
                            return Err(SdkError::Internal);
                        }
                        let g = rest / pkl;
                        let us = HEADER + pkl * (1 + m + aud) + ct;
                        let vs = us + g * pkl;
                        let vas = vs + (m + 1) * v;
                        args.insert("decoyFee".into(), json!(decoy_fee.to_string()));
                        args.insert("salt".into(), json!(salt));
                        args.insert("u".into(), json!((0..g).map(|i| part(&stmt, us + i * pkl, pkl)).collect::<Result<Vec<_>, _>>()?));
                        let mut ls = Vec::with_capacity(m);
                        for (j, l) in legs.iter().enumerate() {
                            let va = if aud == 1 { part(&stmt, vas + j * v, v)? } else { "0x".into() };
                            ls.push(json!({"ua": hex(&l.0), "v": part(&stmt, vs + j * v, v)?, "vAuditor": va}));
                        }
                        args.insert("legs".into(), json!(ls));
                        args.insert("vFrom".into(), json!(part(&stmt, vs + m * v, v)?));
                        args.insert("sealedMemo".into(), json!(sealed));
                    }
                    Form::Burn { amount, recipient } => {
                        let off = HEADER + pkl + ct;
                        args.insert("u".into(), json!(part(&stmt, off, pkl)?));
                        args.insert("vFrom".into(), json!(part(&stmt, off + pkl, v)?));
                        message.insert("amount".into(), json!(amount.to_string()));
                        message.insert("recipient".into(), json!(hex(recipient)));
                        vop.insert("amount".into(), json!(amount.to_string()));
                        vop.insert("recipient".into(), json!(hex(recipient)));
                    }
                    Form::Unwrap {
                        underlying,
                        recipient,
                        amount,
                        min_out,
                    } => {
                        let off = HEADER + pkl + ct;
                        args.insert("u".into(), json!(part(&stmt, off, pkl)?));
                        args.insert("vFrom".into(), json!(part(&stmt, off + pkl, v)?));
                        let u = json!({"underlying": hex(underlying), "recipient": hex(recipient),
                            "amount": amount.to_string(), "minOut": min_out.to_string()});
                        message.insert("unwrap".into(), u.clone());
                        vop.insert("unwrap".into(), u);
                    }
                }
                let entry = scaas_ua::wallet::entries::entry_rows()
                    .into_iter()
                    .find(|row| row.name == d.name && row.kinds.contains(&"pqz"))
                    .map(|row| row.entry)
                    .ok_or(SdkError::Internal)?;
                vop.insert("entry".into(), json!(entry));
                vop.insert("args".into(), Value::Object(args.clone()));
                message.insert("from".into(), json!(hex(&ua)));
                message.insert("args".into(), Value::Object(args));
                message.insert("proof".into(), json!(proof));
                message.insert("accHint".into(), json!("0x"));
                put_envelope(&mut message, &d.batch, e);
                message.insert("nonce".into(), json!(nonce.to_string()));
                // the verdict on an `OFFCHAIN` token, checked before it is attached (spec §9.3); none on `PRECOMPILE`
                let verdict = if offchain {
                    let q = PqzVerdictRequest {
                        chain: d.chain.clone(),
                        token: d.token.clone(),
                        op: Value::Object(vop),
                        statement: hex(&stmt),
                        proof: proof.clone(),
                    };
                    verdict(&sdk, &q).await?
                } else {
                    no_verdict()
                };
                let auth = pqz_auth_message(op, &stmt)?;
                // round 3t (CTR-PQZ-36): an `OFFCHAIN` debit names its proved fee word for the node
                let mut extra = Map::new();
                extra.insert("pqzVerdict".into(), verdict);
                if offchain {
                    extra.insert("pqz_fee".into(), json!(fee.to_string()));
                }
                let touched = match &d.form {
                    Form::Unwrap { underlying, .. } => vec![*underlying],
                    _ => vec![],
                };
                Op::prepare(
                    &sdk,
                    Draft {
                        chain: d.chain,
                        name: d.name,
                        kind: "pqz",
                        contract: t,
                        message: Value::Object(message),
                        extra: Value::Object(extra),
                        signer: d.signer,
                        expect: None,
                        review: d.review,
                        touched,
                        opaque: false,
                        ids: false,
                        relay_call: None,
                        owner: Some(("PqzAuth", "pqzAuth", auth)),
                        key_index: U256::ZERO,
                        target: None,
                    },
                )
                .await
            })
            .await
    }
}

/// The legs of an op 7 (CTR-UA-29, T26 B2-2, as `zether::proved`): `decoys` drawn uniformly from the registry line's `0x0142`
/// lists ([`crate::line::decoy_candidates`]), never the holder `ua` or a real recipient, of amount 0, then every leg's position
/// shuffled; both draws by the facade's `pickDecoys` (its CSPRNG), on public data only.
async fn drawn(
    sdk: &Sdk,
    signer: &KeyRef,
    version: u64,
    chain: &str,
    ua: &W,
    legs: &[(W, u64)],
    decoys: u32,
) -> Result<Vec<(W, u64)>, SdkError> {
    let mut all: Vec<String> = legs.iter().map(|l| hex(&l.0)).collect();
    if decoys > 0 {
        let (registry, pool) = crate::line::bound(sdk, chain)?;
        let cands = crate::line::decoy_candidates(&pool, registry).await?;
        let mut exclude = vec![hex(ua)];
        exclude.extend(all.iter().cloned());
        let cands: Vec<String> = cands.iter().map(|u| hex(u)).collect();
        let req = json!({"candidates": cands, "exclude": exclude, "count": decoys});
        let d = call(sdk, holder(sdk, signer, version)?.1, "pickDecoys", &req).await?;
        for x in d
            .get("decoys")
            .and_then(Value::as_array)
            .ok_or(SdkError::Internal)?
        {
            all.push(x.as_str().ok_or(SdkError::Internal)?.to_string());
        }
    }
    let req = json!({"candidates": all, "exclude": [], "count": all.len()});
    let order = call(sdk, holder(sdk, signer, version)?.1, "pickDecoys", &req).await?;
    let mut out = Vec::with_capacity(all.len());
    for x in order
        .get("decoys")
        .and_then(Value::as_array)
        .ok_or(SdkError::Internal)?
    {
        let u = w32(x.as_str().ok_or(SdkError::Internal)?)?;
        out.push(legs.iter().find(|l| l.0 == u).map_or((u, 0), |l| *l));
    }
    if out.len() != all.len() {
        return Err(SdkError::Internal);
    }
    Ok(out)
}
