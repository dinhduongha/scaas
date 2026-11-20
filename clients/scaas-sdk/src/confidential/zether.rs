// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Zether operations (spec §9.1, §21; plan T15): one `prepare_<op>` per `(struct, zether)` pair built so far, each a prepared
//! operation of [`crate::op`]. The proofs run in `ua-rs`'s Zether facade (`call`: `uaEnvelope`, `proveTransfer`, `proveBurn`,
//! `namedCall`) over the reading layer's words of one final block ([`super::read`]); the typed message is the facade's
//! `namedCall` and must give the digest `scaas-ua`'s typed data gives (two builders, one digest, else `Internal`). The Zether UA
//! (`KeyRef::Ua { kind: 0x0141, index: 0 }`) signs through `scaas-ua`'s `sign_scaas` (its check first) by [`ZetherSigner`],
//! which signs only the digest `submit` approved. The plaintext amount and recipient are reviewed as `Request` fields: the
//! signed struct holds them encrypted. UNAUDITED.
use super::{at, call, handle, read, set, ZETHER_KIND};
use crate::op::{
    addr20, dec, evm, field, hex, lane_nonce, unhex, Draft, KeyRef, Op, Prepared, Source,
};
use crate::wallet::Envelope;
use crate::SdkError;
use alloy::primitives::Address;
use scaas_ua::facade::zether::ZetherKey;
use scaas_ua::wallet::{SignRequest, Signer};
use serde_json::{json, Map, Value};
use std::sync::{Arc, Mutex, PoisonError};

const ZERO20: &str = "0x0000000000000000000000000000000000000000";
/// The purposes a Zether UA signs a SCaaS struct under (`sign_scaas`'s choices).
const PURPOSES: [&str; 4] = ["metatx", "payee-fee", "trade", "zether-owner"];

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
    /// The registration's key data (`Y`) and its portable PoP (`pop` v2 over the registration of no attributes), by the
    /// facade's `pop` (plan T13).
    pub(crate) fn pop(&self) -> Result<(Vec<u8>, Vec<u8>), SdkError> {
        let out = self.key.call("pop", br#"{"curve":"bls12381"}"#)?;
        let v: Value = serde_json::from_str(&out).map_err(|_| SdkError::Internal)?;
        let get = |k: &str| {
            v.get(k)
                .and_then(Value::as_str)
                .ok_or(SdkError::Internal)
                .and_then(unhex)
        };
        Ok((get("Y")?, get("pop")?))
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
        let d =
            (*self.digest.lock().unwrap_or_else(PoisonError::into_inner)).ok_or(Error::Argument)?;
        if *kind != ZETHER_KIND {
            return Err(Error::Argument);
        }
        for p in PURPOSES {
            if scaas_ua::ua_message(ZETHER_KIND, &scaas_ua::purpose_tag(p)?, &d)? == *ua_msg {
                let out = self.key.call(
                    "uaSig",
                    json!({"curve": "bls12381", "purpose": p, "digest": hex(&d)})
                        .to_string()
                        .as_bytes(),
                )?;
                let v: Value = serde_json::from_str(&out).map_err(|_| Error::Argument)?;
                let sig = v
                    .get("sig")
                    .and_then(Value::as_str)
                    .ok_or(Error::Argument)?;
                return unhex(sig).map_err(|_| Error::Argument);
            }
        }
        Err(Error::Argument)
    }
}

// --- the rows without a proof: `wallet`'s plain path, the contract's domain must be a Zether token's ---

/// `zether_shield` (`UAShield` on a Zether token): `amount` of the signer's public balance into `to_ua`'s pending balance.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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

/// `UAZetherUnshieldUnwrap` (`WRAPPED_ZETHER`): `amount` out of the holder's Zether account, unwrapped by leg `underlying` to
/// `recipient` (a 32-byte id: a native address zero-padded, or a derived UA in the leg's own ledger), at least `min_out` of
/// the leg. The burn proof binds `recipient` and `amount` (the contract's `unshieldWith(b, proof, x.amount, x.recipient, …)`);
/// the relayed form binds the envelope, never `unwrapBinding` (the direct call's).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ZetherUnshieldUnwrap {
    pub seed: String,
    pub account: u32,
    pub chain: String,
    pub token: String,
    pub batch: String,
    pub underlying: String,
    pub recipient: String,
    pub amount: String,
    pub min_out: String,
    pub valid_until_block: u64,
    pub envelope: Envelope,
    pub table_bits: Option<u32>,
    pub bound_bits: Option<u32>,
}

/// One real recipient of a multi-recipient transfer: a registered Zether UA and its amount.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ZetherLeg {
    pub to_ua: String,
    pub amount: String,
}

/// `UAZetherTransfer` / `UAZetherTransferCompact`: the real `recipients` and `decoys` legs of amount 0 drawn uniformly from
/// the registry's `0x0141` list (CTR-UA-29, the default), every leg's position shuffled. `decoy_fee`: the per-leg fee the
/// token pays (decimal, `"0"` none; the token's `minDecoyFee` is the contract's check). `ua_signer_gas`: the Zether UA's
/// verify gas the prover's gas-cap check adds for the relayed build (zether-prover `uaSignerGas`), the app's figure: a verify
/// row for `0x0141` in the gas tables (chain → module → reference) wins over it (owner 2026-11-19, P1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ZetherTransferMulti {
    pub seed: String,
    pub account: u32,
    pub chain: String,
    pub token: String,
    pub batch: String,
    pub recipients: Vec<ZetherLeg>,
    pub decoys: u32,
    pub decoy_fee: String,
    pub ua_signer_gas: u64,
    pub valid_until_block: u64,
    pub envelope: Envelope,
    pub table_bits: Option<u32>,
    pub bound_bits: Option<u32>,
}

/// The owner's roll-over (`ZetherRollOver`, its direct call `mtxRollOverSigned`; or with `relayed`, `UARollOverSigned`): every
/// pending entry up to the account's `pendingSeq` at the final block, signed by the Zether UA under `zether-owner` (owner
/// 2026-11-19, C3).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ZetherOwnerRollOver {
    pub seed: String,
    pub account: u32,
    pub chain: String,
    pub token: String,
    pub valid_until_block: u64,
}

/// The owner's roll-over mode (`ZetherSetRollOverMode`; or `UASetRollOverMode`): `mode` 0 PUBLIC, 1 OWNER_ONLY.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ZetherOwnerSetMode {
    pub seed: String,
    pub account: u32,
    pub chain: String,
    pub token: String,
    pub mode: u8,
    pub valid_until_block: u64,
}

/// The envelope of an owner statement's relayed form (`UARollOverSigned`, `UASetRollOverMode`): the Zether UA's own lane.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct OwnerRelay {
    pub batch: String,
    pub envelope: Envelope,
}

fn w32(s: &str) -> Result<[u8; 32], SdkError> {
    unhex(&s.to_ascii_lowercase())?
        .try_into()
        .map_err(|_| SdkError::Argument)
}

/// The owner statement: a roll-over, or a mode change to the mode given.
#[derive(Clone, Copy)]
enum Owner {
    Roll,
    Mode(u8),
}

/// A real recipient's UA and amount.
type Leg = ([u8; 32], String);

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
    /// a multi-recipient transfer: each real recipient's UA and amount, and the decoy count (the legs are read and shuffled)
    multi: Option<(Vec<Leg>, u32)>,
    /// tokens the operation touches besides the Zether token (an unwrap's leg)
    touched: Vec<[u8; 20]>,
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
        let p = self
            .sdk
            .wallet()
            .plain(name, signer, chain, token, batch, fields, env)
            .await?;
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
        self.plain(
            "UAShield", r.signer, r.chain, r.token, r.batch, f, r.envelope,
        )
        .await
    }

    /// Prepares `zether_wrap_shield` (`WrapShield` on a Zether token).
    pub async fn prepare_zether_wrap_shield(
        &self,
        r: ZetherWrapShield,
    ) -> Result<Arc<Prepared>, SdkError> {
        let mut f = Map::new();
        f.insert("underlying".into(), json!(r.underlying));
        f.insert("amountIn".into(), json!(r.amount_in));
        f.insert("toUA".into(), json!(r.to_ua));
        self.plain(
            "WrapShield",
            r.signer,
            r.chain,
            r.token,
            r.batch,
            f,
            r.envelope,
        )
        .await
    }

    /// Prepares `UARollOver`.
    pub async fn prepare_zether_roll_over(
        &self,
        r: ZetherRollOver,
    ) -> Result<Arc<Prepared>, SdkError> {
        let mut f = Map::new();
        f.insert("ua".into(), json!(r.ua));
        f.insert("n".into(), json!(r.n));
        self.plain(
            "UARollOver",
            r.signer,
            r.chain,
            r.token,
            r.batch,
            f,
            r.envelope,
        )
        .await
    }

    /// Prepares `UARollOverBatch`.
    pub async fn prepare_zether_roll_over_batch(
        &self,
        r: ZetherRollOverBatch,
    ) -> Result<Arc<Prepared>, SdkError> {
        let mut f = Map::new();
        f.insert("uas".into(), json!(r.uas));
        self.plain(
            "UARollOverBatch",
            r.signer,
            r.chain,
            r.token,
            r.batch,
            f,
            r.envelope,
        )
        .await
    }

    /// Prepares `UAZetherTransferSingle` (spec §9.1): the words of the holder and the recipient's registered `Y` read at the
    /// final block (§9.4), the proof by the facade, the typed message by its `namedCall`. `WalletLocked`, `ChainUnknown`,
    /// `ProfileMismatch`, `Argument` (a word set that does not check, a balance below the amount), the pool's codes.
    pub async fn prepare_zether_transfer(
        &self,
        r: ZetherTransfer,
    ) -> Result<Arc<Prepared>, SdkError> {
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
            multi: None,
            touched: vec![],
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
    pub async fn prepare_zether_unshield(
        &self,
        r: ZetherUnshield,
    ) -> Result<Arc<Prepared>, SdkError> {
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
            multi: None,
            touched: vec![],
            fields,
            named,
            review: vec![],
            valid_until_block: r.valid_until_block,
            bsgs: (r.table_bits, r.bound_bits),
        })
        .await
    }

    /// Prepares `UAZetherUnshieldUnwrap` (spec §9.1): the burn proof of `amount` to the unwrap's `recipient`, the `Unwrap` leg
    /// signed in the struct.
    pub async fn prepare_zether_unshield_unwrap(
        &self,
        r: ZetherUnshieldUnwrap,
    ) -> Result<Arc<Prepared>, SdkError> {
        w32(&r.recipient)?;
        let underlying = addr20(&r.underlying.to_ascii_lowercase())?;
        let mut fields = Map::new();
        fields.insert("amount".into(), json!(r.amount));
        fields.insert("recipient".into(), json!(r.recipient));
        let mut named = Map::new();
        named.insert(
            "unwrap".into(),
            json!({"underlying": hex(&underlying), "recipient": r.recipient.to_ascii_lowercase(), "amount": r.amount,
                "minOut": r.min_out}),
        );
        self.proved(Proof {
            name: "UAZetherUnshieldUnwrap",
            cmd: "proveBurn",
            seed: r.seed,
            account: r.account,
            chain: r.chain,
            token: r.token,
            batch: r.batch,
            envelope: r.envelope,
            others: vec![],
            multi: None,
            touched: vec![underlying],
            fields,
            named,
            review: vec![],
            valid_until_block: r.valid_until_block,
            bsgs: (r.table_bits, r.bound_bits),
        })
        .await
    }

    /// Prepares `UAZetherTransfer` (spec §9.1): [`ZetherTransferMulti`]'s legs, stored in the token's form (a COMPACT token's
    /// commit-reveal, else the bundle).
    pub async fn prepare_zether_transfer_multi(
        &self,
        r: ZetherTransferMulti,
    ) -> Result<Arc<Prepared>, SdkError> {
        self.multi("UAZetherTransfer", r).await
    }

    /// Prepares `UAZetherTransferCompact` (spec §9.1): as [`Self::prepare_zether_transfer_multi`], commit-reveal always.
    pub async fn prepare_zether_transfer_compact(
        &self,
        r: ZetherTransferMulti,
    ) -> Result<Arc<Prepared>, SdkError> {
        self.multi("UAZetherTransferCompact", r).await
    }

    async fn multi(
        &self,
        name: &'static str,
        r: ZetherTransferMulti,
    ) -> Result<Arc<Prepared>, SdkError> {
        let mut legs = Vec::with_capacity(r.recipients.len());
        let mut review = Vec::new();
        for (i, l) in r.recipients.iter().enumerate() {
            legs.push((w32(&l.to_ua)?, l.amount.clone()));
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
        let d = r.decoys.to_string();
        review.push(field("request.decoys", &d, &d, Source::Derived));
        let mut fields = Map::new();
        fields.insert("decoyFee".into(), json!(r.decoy_fee));
        // P1 (owner 2026-11-19): the gas table's verify row of the Zether UA in the lookup order (chain → module →
        // reference), else the request's figure
        let (profile, _, _) = evm(&self.sdk, &r.chain)?;
        let (ua_gas, _) = crate::op::gas::verify_or(
            &profile.gas,
            &profile.gas_opt_in,
            &self.sdk.gas_tables,
            ZETHER_KIND,
            r.ua_signer_gas,
        );
        fields.insert("uaSignerGas".into(), json!(ua_gas));
        self.proved(Proof {
            name,
            cmd: "proveTransferMulti",
            seed: r.seed,
            account: r.account,
            chain: r.chain,
            token: r.token,
            batch: r.batch,
            envelope: r.envelope,
            others: vec![],
            multi: Some((legs, r.decoys)),
            touched: vec![],
            fields,
            named: Map::new(),
            review,
            valid_until_block: r.valid_until_block,
            bsgs: (r.table_bits, r.bound_bits),
        })
        .await
    }

    /// Prepares `ZetherRollOver` (the direct `mtxRollOverSigned`; spec §9.1): `expectedPendingSeq` the account's `pendingSeq`
    /// and `accSeq` its own, both read at the final block (§9.4). `Argument`: nothing pending.
    pub async fn prepare_zether_owner_roll_over(
        &self,
        r: ZetherOwnerRollOver,
    ) -> Result<Arc<Prepared>, SdkError> {
        self.owner(
            Owner::Roll,
            r.seed,
            r.account,
            r.chain,
            r.token,
            r.valid_until_block,
            None,
        )
        .await
    }

    /// Prepares `UARollOverSigned`: the Zether UA's envelope over [`Self::prepare_zether_owner_roll_over`]'s statement, whose
    /// owner signature (`ZetherRollOver` under `zether-owner`) `submit` makes first and passes as `ownerSig`.
    pub async fn prepare_zether_roll_over_signed(
        &self,
        r: ZetherOwnerRollOver,
        relay: OwnerRelay,
    ) -> Result<Arc<Prepared>, SdkError> {
        self.owner(
            Owner::Roll,
            r.seed,
            r.account,
            r.chain,
            r.token,
            r.valid_until_block,
            Some(relay),
        )
        .await
    }

    /// Prepares `ZetherSetRollOverMode` (the direct `mtxSetRollOverMode`): `modeNonce` read at the final block. `Argument`: a
    /// mode other than 0 or 1.
    pub async fn prepare_zether_owner_set_mode(
        &self,
        r: ZetherOwnerSetMode,
    ) -> Result<Arc<Prepared>, SdkError> {
        self.owner(
            Owner::Mode(r.mode),
            r.seed,
            r.account,
            r.chain,
            r.token,
            r.valid_until_block,
            None,
        )
        .await
    }

    /// Prepares `UASetRollOverMode`: as [`Self::prepare_zether_roll_over_signed`] over `ZetherSetRollOverMode`.
    pub async fn prepare_zether_set_roll_over_mode(
        &self,
        r: ZetherOwnerSetMode,
        relay: OwnerRelay,
    ) -> Result<Arc<Prepared>, SdkError> {
        self.owner(
            Owner::Mode(r.mode),
            r.seed,
            r.account,
            r.chain,
            r.token,
            r.valid_until_block,
            Some(relay),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn owner(
        &self,
        what: Owner,
        seed: String,
        account: u32,
        chain: String,
        token: String,
        valid_until_block: u64,
        relay: Option<OwnerRelay>,
    ) -> Result<Arc<Prepared>, SdkError> {
        if matches!(what, Owner::Mode(m) if m > 1) {
            return Err(SdkError::Argument);
        }
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let key = handle(&sdk, &seed, account)?;
                let (y, ua) = (key.1.y(), key.1.ua());
                drop(key);
                let t = addr20(&token.to_ascii_lowercase())?;
                let r = read::zether(&sdk, &chain, &token, Some(&y), ua, &[]).await?;
                // the counters word and `modeNonce ‖ mode` (zether-prover `LAYOUT`; `modeNonce` the low 8 bytes of slot 5)
                let (c, m) = (r.account.get(4).ok_or(SdkError::Internal)?, r.account.get(5).ok_or(SdkError::Internal)?);
                let u64_at = |w: &[u8; 32], byte: usize| {
                    w.get(24 - byte..32 - byte)
                        .and_then(|b| b.try_into().ok())
                        .map(u64::from_be_bytes)
                        .ok_or(SdkError::Internal)
                };
                let (acc_seq, pending, rolled, mode_nonce) = (u64_at(c, 0)?, u64_at(c, 8)?, u64_at(c, 16)?, u64_at(m, 0)?);
                let uah = hex(&ua);
                let (inner, outer, fields) = match what {
                    Owner::Roll => {
                        if pending <= rolled {
                            return Err(SdkError::Argument);
                        }
                        (
                            ("ZetherRollOver", json!({"ua": uah, "accSeq": acc_seq.to_string(),
                                "expectedPendingSeq": pending.to_string(), "validUntilBlock": valid_until_block.to_string()})),
                            "UARollOverSigned",
                            json!({"ua": uah, "expectedPendingSeq": pending.to_string(),
                                "validUntilBlock": valid_until_block.to_string()}),
                        )
                    }
                    Owner::Mode(mode) => (
                        ("ZetherSetRollOverMode", json!({"ua": uah, "mode": mode, "modeNonce": mode_nonce.to_string(),
                            "validUntilBlock": valid_until_block.to_string()})),
                        "UASetRollOverMode",
                        json!({"ua": uah, "rollOverMode": mode, "validUntilBlock": valid_until_block.to_string()}),
                    ),
                };
                let signer = KeyRef::Ua {
                    seed,
                    kind: ZETHER_KIND,
                    account,
                    index: 0,
                };
                let mut d = Draft {
                    chain,
                    name: inner.0,
                    kind: "zether",
                    contract: t,
                    message: inner.1.clone(),
                    extra: json!({}),
                    signer,
                    expect: None,
                    review: vec![],
                    touched: vec![],
                    opaque: false,
                    ids: false,
                    relay_call: None,
                    owner: None,
                    key_index: alloy::primitives::U256::ZERO,
                    target: None,
                };
                if let Some(relay) = relay {
                    let mut m = fields.as_object().cloned().ok_or(SdkError::Internal)?;
                    m.insert("from".into(), json!(uah));
                    crate::wallet::put_envelope(&mut m, &relay.batch, &relay.envelope);
                    d.name = outer;
                    d.message = Value::Object(m);
                    d.owner = Some((inner.0, "ownerSig", inner.1));
                }
                Op::prepare(&sdk, d).await
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
                let mut others = p.others;
                let mut amounts = vec![];
                if let Some((legs, decoys)) = &p.multi {
                    // CTR-UA-29: the decoys drawn uniformly from the `0x0141` list (never the holder or a real recipient), then
                    // every leg's position shuffled; both draws by the facade's CSPRNG (`pickDecoys`), on public data only
                    let cands = read::candidates(&sdk, &p.chain, &p.token).await?;
                    let mut exclude = vec![hex(&ua)];
                    exclude.extend(legs.iter().map(|l| hex(&l.0)));
                    let hx = |v: &[[u8; 32]]| v.iter().map(|u| hex(u)).collect::<Vec<_>>();
                    let req = json!({"candidates": hx(&cands), "exclude": exclude, "count": decoys});
                    let d = call(&sdk, handle(&sdk, &p.seed, p.account)?, "pickDecoys", req).await?;
                    let mut all: Vec<String> = legs.iter().map(|l| hex(&l.0)).collect();
                    for x in at(&d, &["decoys"])?.as_array().ok_or(SdkError::Internal)? {
                        all.push(x.as_str().ok_or(SdkError::Internal)?.to_string());
                    }
                    let n = all.len();
                    let req = json!({"candidates": all, "exclude": [], "count": n});
                    let order = call(&sdk, handle(&sdk, &p.seed, p.account)?, "pickDecoys", req).await?;
                    for x in at(&order, &["decoys"])?.as_array().ok_or(SdkError::Internal)? {
                        let u = w32(x.as_str().ok_or(SdkError::Internal)?)?;
                        amounts.push(legs.iter().find(|l| l.0 == u).map_or("0".to_string(), |l| l.1.clone()));
                        others.push(u);
                    }
                }
                // the words first (§9.4); every check of them runs before anything else is read
                let r = read::zether(&sdk, &p.chain, &p.token, Some(&y), ua, &others).await?;
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
                if p.multi.is_some() {
                    let legs: Vec<Value> =
                        r.ys.iter().zip(&amounts).map(|(y, a)| json!({"yTo": hex(y), "amount": a})).collect();
                    o.insert("recipients".into(), json!(legs));
                    let compact = p.name == "UAZetherTransferCompact" || r.disclosure_mode == 1;
                    o.insert("mode".into(), json!(if compact { "compact" } else { "bundle" }));
                } else if let Some(y) = r.ys.first() {
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
                    touched: p.touched,
                    opaque: false,
                    ids: false,
                    relay_call: None,
                    owner: None,
                    key_index: alloy::primitives::U256::ZERO,
                    target: None,
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
