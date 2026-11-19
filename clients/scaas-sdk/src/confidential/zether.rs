// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Zether operations (spec §9.1, §21; plan T15): one `prepare_<op>` per `(struct, zether)` pair built so far, each a prepared
//! operation of [`crate::op`]. The proofs run in `ua-rs`'s Zether facade (`call`: `uaEnvelope`, `proveTransfer`, `proveBurn`,
//! `namedCall`) over the reading layer's words of one final block ([`super::read`]); the typed message is the facade's
//! `namedCall` and must give the digest `scaas-ua`'s typed data gives (two builders, one digest, else `Internal`). The Zether UA
//! (`KeyRef::Ua { kind: 0x0141, index: 0 }`) signs through `scaas-ua`'s `sign_scaas` (its check first) by [`ZetherSigner`],
//! which signs only the digest `submit` approved. The plaintext amount and recipient are reviewed as `Request` fields: the
//! signed struct holds them encrypted. UNAUDITED.
use super::{at, call, handle, read, set, ZETHER_KIND};
use crate::op::{addr20, dec, evm, field, hex, lane_nonce, unhex, Draft, KeyRef, Op, Prepared, Source};
use crate::wallet::Envelope;
use crate::SdkError;
use alloy::primitives::Address;
use scaas_ua::facade::zether::ZetherKey;
use scaas_ua::wallet::{SignRequest, Signer};
use serde_json::{json, Map, Value};
use std::sync::{Arc, Mutex, PoisonError};

const ZERO20: &str = "0x0000000000000000000000000000000000000000";
/// The purposes a Zether UA signs a SCaaS struct under (`sign_scaas`'s choices).
const PURPOSES: [&str; 3] = ["metatx", "payee-fee", "trade"];

/// The Zether UA as a `scaas-ua` signer: the facade's `uaSig` over the one digest [`ZetherSigner::approve`] set, under the
/// purpose whose `uaMessage` is the one asked for; anything else is `Argument`.
pub struct ZetherSigner {
    key: ZetherKey,
    digest: Mutex<Option<[u8; 32]>>,
}

impl ZetherSigner {
    pub(crate) fn new(key: ZetherKey) -> Self {
        ZetherSigner {
            key,
            digest: Mutex::new(None),
        }
    }
    pub(crate) fn ua(&self) -> [u8; 32] {
        self.key.ua()
    }
    /// The digest `submit` checked: the only one this signer signs.
    pub(crate) fn approve(&self, d: [u8; 32]) {
        *self.digest.lock().unwrap_or_else(PoisonError::into_inner) = Some(d);
    }
}

impl Signer for ZetherSigner {
    fn key_ref(&self) -> scaas_ua::wallet::KeyRef {
        scaas_ua::wallet::KeyRef::Ua {
            kind: ZETHER_KIND,
            key_data: self.key.y(),
        }
    }

    fn sign_request(&self, req: &SignRequest) -> scaas_ua::wallet::Result<Vec<u8>> {
        use scaas_ua::wallet::Error;
        let SignRequest::UaMsg { kind, ua_msg, .. } = req else {
            return Err(Error::Argument);
        };
        let d = (*self.digest.lock().unwrap_or_else(PoisonError::into_inner)).ok_or(Error::Argument)?;
        if *kind != ZETHER_KIND {
            return Err(Error::Argument);
        }
        for p in PURPOSES {
            if scaas_ua::ua_message(ZETHER_KIND, &scaas_ua::purpose_tag(p)?, &d)? == *ua_msg {
                let out = self.key.call(
                    "uaSig",
                    json!({"curve": "bls12381", "purpose": p, "digest": hex(&d)}).to_string().as_bytes(),
                )?;
                let v: Value = serde_json::from_str(&out).map_err(|_| Error::Argument)?;
                let sig = v.get("sig").and_then(Value::as_str).ok_or(Error::Argument)?;
                return unhex(sig).map_err(|_| Error::Argument);
            }
        }
        Err(Error::Argument)
    }
}

// --- the rows without a proof: `wallet`'s plain path, the contract's domain must be a Zether token's ---

/// `zether_shield` (`UAShield` on a Zether token): `amount` of the signer's public balance into `to_ua`'s pending balance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZetherShield {
    pub signer: KeyRef,
    pub chain: String,
    pub token: String,
    pub batch: String,
    pub to_ua: String,
    pub amount: String,
    pub envelope: Envelope,
}

/// `zether_wrap_shield` (`WrapShield` on a Zether token): wrap `amount_in` of `underlying` and shield it to `to_ua`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZetherWrapShield {
    pub signer: KeyRef,
    pub chain: String,
    pub token: String,
    pub batch: String,
    pub underlying: String,
    pub amount_in: String,
    pub to_ua: String,
    pub envelope: Envelope,
}

/// `UARollOver`: roll `ua`'s pending balance over (`n`: the entries to take).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZetherRollOver {
    pub signer: KeyRef,
    pub chain: String,
    pub token: String,
    pub batch: String,
    pub ua: String,
    pub n: String,
    pub envelope: Envelope,
}

/// `UARollOverBatch`: roll each of `uas` over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZetherRollOverBatch {
    pub signer: KeyRef,
    pub chain: String,
    pub token: String,
    pub batch: String,
    pub uas: Vec<String>,
    pub envelope: Envelope,
}

// --- the rows with a proof ---

/// `UAZetherTransferSingle`: `amount` from the holder's Zether account (`seed`, `account`) to `to_ua` (a registered Zether
/// UA), the proof valid until block `valid_until_block`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZetherTransfer {
    pub seed: String,
    pub account: u32,
    pub chain: String,
    pub token: String,
    pub batch: String,
    pub to_ua: String,
    pub amount: String,
    pub valid_until_block: u64,
    pub envelope: Envelope,
    /// the BSGS bits of the balance the proof needs (`None`: the facade's defaults)
    pub table_bits: Option<u32>,
    pub bound_bits: Option<u32>,
}

/// `UAZetherUnshield`: `amount` out of the holder's Zether account to `recipient` (a 32-byte id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZetherUnshield {
    pub seed: String,
    pub account: u32,
    pub chain: String,
    pub token: String,
    pub batch: String,
    pub recipient: String,
    pub amount: String,
    pub valid_until_block: u64,
    pub envelope: Envelope,
    pub table_bits: Option<u32>,
    pub bound_bits: Option<u32>,
}

fn w32(s: &str) -> Result<[u8; 32], SdkError> {
    unhex(&s.to_ascii_lowercase())?.try_into().map_err(|_| SdkError::Argument)
}

/// What a proof needs beside the words.
struct Proof {
    name: &'static str,
    cmd: &'static str,
    seed: String,
    account: u32,
    chain: String,
    token: String,
    batch: String,
    envelope: Envelope,
    /// the UAs whose registered `Y` the proof takes (the recipient of a transfer)
    others: Vec<[u8; 32]>,
    /// the command's own fields (`amount`, `recipient`, …) and those `namedCall` takes
    fields: Map<String, Value>,
    named: Map<String, Value>,
    review: Vec<crate::op::ReviewField>,
    valid_until_block: u64,
    bsgs: (Option<u32>, Option<u32>),
}

impl super::Confidential {
    #[allow(clippy::too_many_arguments)]
    async fn plain(
        &self,
        name: &'static str,
        signer: KeyRef,
        chain: String,
        token: String,
        batch: String,
        fields: Map<String, Value>,
        env: Envelope,
    ) -> Result<Arc<Prepared>, SdkError> {
        let p = self.sdk.wallet().plain(name, signer, chain, token, batch, fields, env).await?;
        if p.t.kind != "zether" {
            return Err(SdkError::Argument);
        }
        Ok(p)
    }

    /// Prepares `zether_shield` (`UAShield` on a Zether token; spec §9.1): `ProfileMismatch`, `Argument` (not a Zether token).
    pub async fn prepare_zether_shield(&self, r: ZetherShield) -> Result<Arc<Prepared>, SdkError> {
        let mut f = Map::new();
        f.insert("toUA".into(), json!(r.to_ua));
        f.insert("amount".into(), json!(r.amount));
        self.plain("UAShield", r.signer, r.chain, r.token, r.batch, f, r.envelope).await
    }

    /// Prepares `zether_wrap_shield` (`WrapShield` on a Zether token).
    pub async fn prepare_zether_wrap_shield(&self, r: ZetherWrapShield) -> Result<Arc<Prepared>, SdkError> {
        let mut f = Map::new();
        f.insert("underlying".into(), json!(r.underlying));
        f.insert("amountIn".into(), json!(r.amount_in));
        f.insert("toUA".into(), json!(r.to_ua));
        self.plain("WrapShield", r.signer, r.chain, r.token, r.batch, f, r.envelope).await
    }

    /// Prepares `UARollOver`.
    pub async fn prepare_zether_roll_over(&self, r: ZetherRollOver) -> Result<Arc<Prepared>, SdkError> {
        let mut f = Map::new();
        f.insert("ua".into(), json!(r.ua));
        f.insert("n".into(), json!(r.n));
        self.plain("UARollOver", r.signer, r.chain, r.token, r.batch, f, r.envelope).await
    }

    /// Prepares `UARollOverBatch`.
    pub async fn prepare_zether_roll_over_batch(&self, r: ZetherRollOverBatch) -> Result<Arc<Prepared>, SdkError> {
        let mut f = Map::new();
        f.insert("uas".into(), json!(r.uas));
        self.plain("UARollOverBatch", r.signer, r.chain, r.token, r.batch, f, r.envelope).await
    }

    /// Prepares `UAZetherTransferSingle` (spec §9.1): the words of the holder and the recipient's registered `Y` read at the
    /// final block (§9.4), the proof by the facade, the typed message by its `namedCall`. `WalletLocked`, `ChainUnknown`,
    /// `ProfileMismatch`, `Argument` (a word set that does not check, a balance below the amount), the pool's codes.
    pub async fn prepare_zether_transfer(&self, r: ZetherTransfer) -> Result<Arc<Prepared>, SdkError> {
        let to = w32(&r.to_ua)?;
        let mut fields = Map::new();
        fields.insert("amount".into(), json!(r.amount));
        self.proved(Proof {
            name: "UAZetherTransferSingle",
            cmd: "proveTransfer",
            seed: r.seed,
            account: r.account,
            chain: r.chain,
            token: r.token,
            batch: r.batch,
            envelope: r.envelope,
            others: vec![to],
            fields,
            named: Map::new(),
            review: vec![
                field("request.to", &r.to_ua, &r.to_ua, Source::Request),
                field("request.amount", &r.amount, &r.amount, Source::Request),
            ],
            valid_until_block: r.valid_until_block,
            bsgs: (r.table_bits, r.bound_bits),
        })
        .await
    }

    /// Prepares `UAZetherUnshield` (spec §9.1): as [`Self::prepare_zether_transfer`], the proof a burn of `amount` to `recipient`.
    pub async fn prepare_zether_unshield(&self, r: ZetherUnshield) -> Result<Arc<Prepared>, SdkError> {
        w32(&r.recipient)?;
        let mut fields = Map::new();
        fields.insert("amount".into(), json!(r.amount));
        fields.insert("recipient".into(), json!(r.recipient));
        let named = fields.clone();
        self.proved(Proof {
            name: "UAZetherUnshield",
            cmd: "proveBurn",
            seed: r.seed,
            account: r.account,
            chain: r.chain,
            token: r.token,
            batch: r.batch,
            envelope: r.envelope,
            others: vec![],
            fields,
            named,
            review: vec![],
            valid_until_block: r.valid_until_block,
            bsgs: (r.table_bits, r.bound_bits),
        })
        .await
    }

    async fn proved(&self, p: Proof) -> Result<Arc<Prepared>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let key = handle(&sdk, &p.seed, p.account)?;
                let (y, ua) = (key.1.y(), key.1.ua());
                let (profile, chain_id, pool) = evm(&sdk, &p.chain)?;
                let t = addr20(&p.token.to_ascii_lowercase())?;
                // the words first (§9.4); every check of them runs before anything else is read
                let r = read::zether(&sdk, &p.chain, &p.token, &y, ua, &p.others).await?;
                let e = &p.envelope;
                let batch = dec(&json!(p.batch))?;
                let nonce = lane_nonce(&pool, Address::from(t), "zether", &ua, batch).await?;
                // canonical (an unbound relayer / fee recipient is 0, `MetaTxLib.canon`): what the binding is taken over
                let bound = |bit: u32, a: &Option<String>| {
                    if e.mode & bit != 0 {
                        a.clone().unwrap_or_else(|| ZERO20.into())
                    } else {
                        ZERO20.into()
                    }
                };
                let (relayer, fee_recipient) = (bound(1, &e.relayer), bound(2, &e.fee_recipient));
                let env = json!({"from": hex(&ua), "batch": batch.to_string(), "nonce": nonce.to_string(),
                    "validUntil": e.valid_until.to_string(), "mode": e.mode, "relayer": relayer, "fee": e.fee,
                    "feeRecipient": fee_recipient});
                let loc = json!({"chainId": chain_id, "chainUid": profile.chain_uid.to_ascii_lowercase(), "token": hex(&t)});
                let mut meta = env.clone();
                set(&mut meta, "batch", json!(hex(&batch.to_be_bytes::<32>())))?;
                let mut req = loc.clone();
                set(&mut req, "meta", meta)?;
                let b = call(&sdk, handle(&sdk, &p.seed, p.account)?, "uaEnvelope", req).await?;
                let mut prove = r.words;
                let o = prove.as_object_mut().ok_or(SdkError::Internal)?;
                o.extend(p.fields);
                o.insert("envelopeBinding".into(), at(&b, &["binding"])?.clone());
                o.insert("validUntilBlock".into(), json!(p.valid_until_block));
                if let Some(y) = r.ys.first() {
                    o.insert("yTo".into(), json!(hex(y)));
                }
                if r.auditor_mode != 0 {
                    if let Some(a) = &r.y_aud {
                        o.insert("yAud".into(), json!(hex(a)));
                    }
                }
                for (k, v) in [("tableBits", p.bsgs.0), ("boundBits", p.bsgs.1)] {
                    if let Some(v) = v {
                        o.insert(k.into(), json!(v));
                    }
                }
                let proof = call(&sdk, key, p.cmd, prove).await?;
                let mut named = loc;
                let n = named.as_object_mut().ok_or(SdkError::Internal)?;
                n.extend(p.named);
                n.insert("op".into(), json!(p.name));
                n.insert("env".into(), env);
                n.insert("payload".into(), at(&proof, &["payload"])?.clone());
                n.insert("proof".into(), at(&proof, &["proof"])?.clone());
                n.insert("beneficiary".into(), json!(hex(&[0u8; 32])));
                let built = call(&sdk, handle(&sdk, &p.seed, p.account)?, "namedCall", named).await?;
                let digest = at(&built, &["digest"])?.as_str().ok_or(SdkError::Internal)?.to_ascii_lowercase();
                let d = Draft {
                    chain: p.chain,
                    name: p.name,
                    kind: "zether",
                    contract: t,
                    message: at(&built, &["message"])?.clone(),
                    extra: json!({}),
                    signer: KeyRef::Ua {
                        seed: p.seed,
                        kind: ZETHER_KIND,
                        account: p.account,
                        index: 0,
                    },
                    expect: None,
                    review: p.review,
                    touched: vec![],
                    opaque: false,
                    ids: false,
                    relay_call: None,
                };
                let prepared = Op::prepare(&sdk, d).await?;
                // the facade's typed digest and scaas-ua's are one
                if prepared.id() != digest {
                    return Err(SdkError::Internal);
                }
                Ok(prepared)
            })
            .await
    }
}
