// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! PqChat's key entries on the app-core surface (pqchat-core spec §5 K1–K6, S1 / S2 sealing `sealedInfo` from its named
//! fields, S5, V1, V2; its §13 O3 (b); feature `pqchat-records`). Each is a thin call of `scaas-ua`'s `pqchat_keys` on this
//! scope's handles, in a scope that declared PqChat's prefix `scaas/pqchat/v1/` (`AppLabelRefused` otherwise). The SDK reads
//! the member's KEM key (K2) and the signer's registry records (V1) at the profile's final block as reads that feed a
//! decryption (CLI-PQC-13), and takes the sender, creator or author from the signing account, never from the caller. No entry
//! that signs takes a digest, typed data or a ciphertext of the caller's: the content and the info are sealed inside. A `file`
//! content's key enters it inside `scaas-ua` and a received file opens there (T10b).
//! Plaintexts leave as `SecretBytes` only. UNAUDITED.
use crate::app_core::{
    at, hex32, AppCore, AppInnerSig, AppKey, AppKeyUsage, AppMemberSig, AppUaSig,
};
use crate::error::SdkError;
use crate::op::{hex, KeyRef, Source};
use crate::pqchat_records::{
    PqChatEpoch, PqChatMessage, PqChatPrepared, PqChatSession, PqMemberKey, PqWrap,
};
use scaas_ua::ua_portable::UASig;
use scaas_ua::wallet::pqchat_keys::{self as pk, Header};
use scaas_ua::wallet::{pqchat, KemWrap, SecretBytes};
use std::sync::Arc;

/// A message's header as S5 takes it: the sender is the signing account's UA.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqMessageHeader {
    pub session_id: String,
    pub epoch_id: String,
    /// `bytes16`, `0x` + 32 hex
    pub device: String,
    pub counter: u64,
    /// at most 8, strictly ascending
    pub parents: Vec<String>,
}

/// S5's output: the record, its signature and id, and the bytes each store takes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqSealedMessage {
    pub record: PqChatMessage,
    pub sig: AppUaSig,
    pub message_id: String,
    /// `abi.encode(PqChatMessage, UASig)`: `postMessage`'s arguments
    pub inner: Vec<u8>,
    pub hint: Vec<u8>,
    pub env: Vec<u8>,
    /// `abi.encode(uint8 1, bytes8 hint, bytes env)`: `storeMessage`'s blob
    pub payload: Vec<u8>,
}

/// An envelope opened (K4, first half): the record and its signature, not yet checked (V1 and the membership check next).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqInner {
    pub record: PqChatMessage,
    pub sig: AppUaSig,
}

/// A stored payload decoded (V2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqPayload {
    pub hint: Vec<u8>,
    pub env: Vec<u8>,
}

/// A session record to seal and sign (S1): the creator is the signing account; `info_json` the `sealedInfo`'s named fields
/// as one JSON object, sealed inside under `K` (canonical JSON, padded) and listed field by field in the review.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqSessionNew {
    pub nonce: u64,
    pub home_chain: String,
    pub home_chat_contract: String,
    pub admins: Vec<String>,
    pub members: Vec<PqMemberKey>,
    pub wraps: Vec<PqWrap>,
    pub info_json: String,
}

/// An epoch record to seal and sign (S2): the author is the signing account.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqEpochNew {
    pub session_id: String,
    pub nonce: u64,
    pub epoch: u64,
    pub parent_epoch_id: String,
    pub admins: Vec<String>,
    pub members: Vec<PqMemberKey>,
    pub wraps: Vec<PqWrap>,
    pub info_json: String,
}

fn h32(s: &str) -> Result<[u8; 32], SdkError> {
    hex32(&s.to_ascii_lowercase())
}

fn h16(s: &str) -> Result<[u8; 16], SdkError> {
    crate::op::unhex(&s.to_ascii_lowercase())?
        .try_into()
        .map_err(|_| SdkError::Argument)
}

fn word(n: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}

fn record_of(h: &Header, ciphertext: Vec<u8>) -> PqChatMessage {
    PqChatMessage {
        session_id: hex(&h.session_id),
        epoch_id: hex(&h.epoch_id),
        sender: hex(&h.sender),
        device: hex(&h.device),
        counter: h.counter,
        parents: h.parents.iter().map(|p| hex(p)).collect(),
        ciphertext,
    }
}

fn header_of(r: &PqChatMessage) -> Result<Header, SdkError> {
    Ok(Header {
        session_id: h32(&r.session_id)?,
        epoch_id: h32(&r.epoch_id)?,
        sender: h32(&r.sender)?,
        device: h16(&r.device)?,
        counter: r.counter,
        parents: r.parents.iter().map(|p| h32(p)).collect::<Result<_, _>>()?,
    })
}

fn sig_of(s: &UASig) -> AppUaSig {
    AppUaSig {
        key_data: s.key_data.clone(),
        signature: s.signature.clone(),
        members: s
            .members
            .iter()
            .map(|m| AppMemberSig {
                index: m.index,
                members: m
                    .members
                    .iter()
                    .map(|x| AppInnerSig {
                        index: x.index,
                        sig: x.sig.clone(),
                    })
                    .collect(),
                sig: m.sig.clone(),
            })
            .collect(),
    }
}

fn wrap_of(member: &[u8; 32], key_id: u64, w: KemWrap) -> PqWrap {
    PqWrap {
        member: hex(member),
        key_id,
        mlkem_ct: w.mlkem_ct,
        x25519_eph: hex(&w.x25519_eph),
        sealed_key: w.sealed_key,
    }
}

fn kem_wrap_of(w: PqWrap) -> Result<KemWrap, SdkError> {
    Ok(KemWrap {
        mlkem_ct: w.mlkem_ct,
        x25519_eph: h32(&w.x25519_eph)?,
        sealed_key: w.sealed_key,
    })
}

fn secret(pt: zeroize::Zeroizing<Vec<u8>>) -> Result<SecretBytes, SdkError> {
    SecretBytes::from_zeroizing(pt).map_err(SdkError::Ua)
}

/// The `sealedInfo`'s fields listed in the review as request fields (CLI-PQC-04: the store list and the Matrix ids shown).
fn info_review(info_json: &str, s: &mut PqChatPrepared) -> Result<(), SdkError> {
    let v = scaas_ua::wallet::bounded::json(info_json.as_bytes(), pk::PT_MAX, pk::JSON_DEPTH)?;
    crate::app_core::flatten_as("sealedInfo", &v, Source::Request, &mut s.review);
    Ok(())
}

impl AppCore {
    /// K1: a fresh epoch key `K` of `seed`'s arena (a `Derive` handle this scope drew).
    pub fn pqchat_epoch_key(&self, seed: &str) -> Result<Arc<AppKey>, SdkError> {
        self.label(pk::PREFIX.as_bytes())?;
        self.random_key(seed, AppKeyUsage::Derive)
    }

    /// K2: `k` wrapped to `member`'s KEM key at `key_id`, read from the profile's registry at its final block as a read that
    /// feeds a decryption (scheme 1 only, `KemCheck`; P14's checks below the SDK); the `Wrap`'s named fields.
    pub async fn pqchat_wrap(
        self: &Arc<Self>,
        chain: String,
        k: Arc<AppKey>,
        session_id: String,
        epoch_id: String,
        member: String,
        key_id: u64,
    ) -> Result<PqWrap, SdkError> {
        self.label(pk::WRAP)?;
        let (s, e, m) = (h32(&session_id)?, h32(&epoch_id)?, h32(&member)?);
        let kem_pk = self.kem_pk_at(&chain, m, key_id).await?;
        let w = self.with(&[&k], |sc, hs| {
            sc.pqchat_wrap(at(hs, 0)?, &s, &e, &m, key_id, &kem_pk)
                .map_err(SdkError::Ua)
        })?;
        Ok(wrap_of(&m, key_id, w))
    }

    /// K2: the epoch key of `wrap` by `account`'s KEM key at the wrap's `keyId`, a `Derive` handle; `wrap.member` other than
    /// `account`'s UA `Argument`; `Aead` when it does not open.
    pub fn pqchat_unwrap(
        &self,
        account: KeyRef,
        session_id: String,
        epoch_id: String,
        wrap: PqWrap,
    ) -> Result<Arc<AppKey>, SdkError> {
        self.label(pk::WRAP)?;
        let me = self.account_ua(&account)?;
        let member = h32(&wrap.member)?;
        let KeyRef::Ua {
            seed,
            kind,
            account,
            index,
        } = account
        else {
            return Err(SdkError::Argument);
        };
        if me != member {
            return Err(SdkError::Argument);
        }
        let kem = self
            .sdk
            .open_seed(&seed)?
            .wallet
            .ua_key(kind, account, index)
            .and_then(|k| k.kem_key(wrap.key_id))
            .map_err(SdkError::Ua)?;
        let key_id = wrap.key_id;
        let h = self.scope(&seed)?.pqchat_unwrap(
            &kem,
            &kem_wrap_of(wrap)?,
            &h32(&session_id)?,
            &h32(&epoch_id)?,
            &member,
            key_id,
        )?;
        Ok(self.wrap(&seed, h))
    }

    /// K3: the sender chain's position at counter 0.
    pub fn pqchat_chain(
        &self,
        k: Arc<AppKey>,
        session_id: String,
        epoch_id: String,
        sender: String,
        device: String,
    ) -> Result<Arc<AppKey>, SdkError> {
        self.label(pk::CHAIN)?;
        let (s, e, u, d) = (
            h32(&session_id)?,
            h32(&epoch_id)?,
            h32(&sender)?,
            h16(&device)?,
        );
        let h = self.with(&[&k], |sc, hs| {
            sc.pqchat_chain(at(hs, 0)?, &s, &e, &u, &d)
                .map_err(SdkError::Ua)
        })?;
        Ok(self.wrap(k.seed(), h))
    }

    /// K3: the position `n` steps past `pos` in one call (`PqChatTooFar` above 2^20, before any step).
    pub fn pqchat_advance(&self, pos: Arc<AppKey>, n: u64) -> Result<Arc<AppKey>, SdkError> {
        self.label(pk::CHAIN)?;
        let h = self.with(&[&pos], |sc, hs| {
            sc.pqchat_advance(at(hs, 0)?, n).map_err(SdkError::Ua)
        })?;
        Ok(self.wrap(pos.seed(), h))
    }

    /// K6: the 8-byte hint of an epoch key this scope drew or unwrapped (a chain position: `AppKeyUsage`).
    pub fn pqchat_hint(&self, k: Arc<AppKey>) -> Result<Vec<u8>, SdkError> {
        self.label(pk::HINT)?;
        self.with(&[&k], |sc, hs| Ok(sc.pqchat_hint(at(hs, 0)?)?.to_vec()))
    }

    /// K5: a `sealedInfo` opened under `k`, its canonical JSON (`Aead`, `PqChatContent`).
    pub fn pqchat_open_info(
        &self,
        k: Arc<AppKey>,
        session_id: String,
        epoch_id: String,
        sealed: Vec<u8>,
    ) -> Result<SecretBytes, SdkError> {
        self.label(pk::INFO)?;
        let (s, e) = (h32(&session_id)?, h32(&epoch_id)?);
        let pt = self.with(&[&k], |sc, hs| {
            sc.pqchat_open_info(at(hs, 0)?, &s, &e, &sealed)
                .map_err(SdkError::Ua)
        })?;
        secret(pt)
    }

    /// K4, first half: an envelope opened and decoded (its record and signature, unchecked).
    pub fn pqchat_open_envelope(
        &self,
        k: Arc<AppKey>,
        session_id: String,
        epoch_id: String,
        env: Vec<u8>,
    ) -> Result<PqInner, SdkError> {
        self.label(pk::ENV)?;
        let (s, e) = (h32(&session_id)?, h32(&epoch_id)?);
        let i = self.with(&[&k], |sc, hs| {
            sc.pqchat_open_envelope(at(hs, 0)?, &s, &e, &env)
                .map_err(SdkError::Ua)
        })?;
        Ok(PqInner {
            record: record_of(&i.header, i.ciphertext),
            sig: sig_of(&i.sig),
        })
    }

    /// K4, second half (after V1 and the membership check): the record's content at `pos` (its sender chain at its counter),
    /// canonical JSON (`Aead`, `PqChatContent`; a position of another chain or counter `Argument`).
    pub fn pqchat_open_message(
        &self,
        pos: Arc<AppKey>,
        record: PqChatMessage,
    ) -> Result<SecretBytes, SdkError> {
        self.label(pk::CHAIN)?;
        let h = header_of(&record)?;
        let pt = self.with(&[&pos], |sc, hs| {
            sc.pqchat_open_message(at(hs, 0)?, &h, &record.ciphertext)
                .map_err(SdkError::Ua)
        })?;
        secret(pt)
    }

    /// S5: `content_json` canonicalised, padded and sealed at `pos` (the account's own chain at `header.counter`), then
    /// `PqChatMessage` signed by `account` (a single UA key: a native key or an `msig` `Argument`; the sender its UA), no
    /// per-message review (CLI-PQC-04), the envelope under `k` with a random nonce, the payload.
    pub async fn pqchat_seal_message(
        self: &Arc<Self>,
        account: KeyRef,
        k: Arc<AppKey>,
        pos: Arc<AppKey>,
        header: PqMessageHeader,
        content_json: String,
    ) -> Result<PqSealedMessage, SdkError> {
        self.seal_message_with(account, k, pos, header, content_json, None, None)
            .await
    }

    /// pqchat-core T10b (a), owner 2026-11-22: a `file` content sealed as S5 seals any content, its key entered inside
    /// `scaas-ua` from `file_key` (the `File` handle of `seal_for_arweave` or `seal_file`): `fields_json` is every field of
    /// UA-7 §6.4.1's `file` but `key` (`url` an `ar://<id>`), checked there (a `key` given, another type or a field out of
    /// its form `PqChatContent`; a handle of another usage `AppKeyUsage`). The key is in no byte that leaves but the
    /// ciphertext.
    pub async fn pqchat_seal_file_message(
        self: &Arc<Self>,
        account: KeyRef,
        k: Arc<AppKey>,
        pos: Arc<AppKey>,
        header: PqMessageHeader,
        fields_json: String,
        file_key: Arc<AppKey>,
    ) -> Result<PqSealedMessage, SdkError> {
        self.seal_message_with(account, k, pos, header, fields_json, Some(file_key), None)
            .await
    }

    /// pqchat-core T10b (b), owner 2026-11-22: the file of `object` named by `content`, a content K4 opened (the handle
    /// [`AppCore::pqchat_open_message`] gave): inside `scaas-ua` the content's `file` form checked (`PqChatContent`), then
    /// before any decryption the object's exact length (`FileLength`) and SHA-256 against its `ctSha256`
    /// (`FileHashMismatch`), then the tag, the frame and `sha256`; the key never leaves `scaas-ua`. Run on the user's action
    /// for that file only; a failure is shown on the device only (ARCH-POS-13).
    pub fn pqchat_open_file(
        &self,
        content: Arc<SecretBytes>,
        object: Vec<u8>,
    ) -> Result<SecretBytes, SdkError> {
        self.label(pk::PREFIX.as_bytes())?;
        let pt = content.with(|c| scaas_ua::wallet::pqchat_file::pqchat_open_file(c, &object))?;
        secret(pt)
    }

    #[allow(clippy::too_many_arguments)]
    async fn seal_message_with(
        self: &Arc<Self>,
        account: KeyRef,
        k: Arc<AppKey>,
        pos: Arc<AppKey>,
        header: PqMessageHeader,
        content_json: String,
        file_key: Option<Arc<AppKey>>,
        env_nonce: Option<[u8; 12]>,
    ) -> Result<PqSealedMessage, SdkError> {
        self.label(pk::ENV)?;
        if !matches!(account, KeyRef::Ua { .. }) {
            return Err(SdkError::Argument);
        }
        let me = self.clone();
        let sdk = self.sdk.clone();
        sdk.clone()
            .spawn(async move {
                let crate::op::Key::Ua(_, signer) = crate::op::key(&sdk, &account)? else {
                    return Err(SdkError::Argument);
                };
                let h = Header {
                    session_id: h32(&header.session_id)?,
                    epoch_id: h32(&header.epoch_id)?,
                    sender: signer.ua().ok_or(SdkError::Argument)?,
                    device: h16(&header.device)?,
                    counter: header.counter,
                    parents: header
                        .parents
                        .iter()
                        .map(|p| h32(p))
                        .collect::<Result<_, _>>()?,
                };
                let mut ks: Vec<&AppKey> = vec![&k, &pos];
                ks.extend(file_key.as_deref());
                let s = me.with(&ks, |sc, hs| {
                    let (kh, ph) = (at(hs, 0)?, at(hs, 1)?);
                    let c = content_json.as_bytes();
                    match (env_nonce, file_key.is_some()) {
                        (None, true) => {
                            sc.pqchat_seal_file_message(kh, ph, &h, c, at(hs, 2)?, &signer)
                        }
                        (None, false) => sc.pqchat_seal_message(kh, ph, &h, c, &signer),
                        #[cfg(feature = "vectors")]
                        (Some(n), false) => {
                            sc.pqchat_vectors_seal_message(kh, ph, &h, c, &signer, &n)
                        }
                        _ => Err(scaas_ua::wallet::Error::Argument),
                    }
                    .map_err(SdkError::Ua)
                })?;
                Ok(PqSealedMessage {
                    record: record_of(&s.header, s.ciphertext),
                    sig: sig_of(&s.sig),
                    message_id: hex(&s.message_id),
                    inner: s.inner,
                    hint: s.hint.to_vec(),
                    env: s.env,
                    payload: s.payload,
                })
            })
            .await
    }

    /// S1: `sealedInfo` sealed from `r.info_json` under `k` (random nonce), then `PqChatSession` prepared for `account`'s
    /// signature (the creator, its UA; [`PqChatPrepared::sign`] after the review, T26 A-5 part b), the session id computed, the
    /// info's fields in the review as request fields.
    pub async fn pqchat_prepare_session(
        self: &Arc<Self>,
        account: KeyRef,
        k: Arc<AppKey>,
        r: PqSessionNew,
    ) -> Result<PqChatPrepared, SdkError> {
        let creator = self.account_ua(&account)?;
        let sid = pqchat::id("session", &[creator, word(r.nonce)]);
        let sealed = self.seal_info(&k, &sid, &sid, &r.info_json)?;
        let rec = PqChatSession {
            creator: hex(&creator),
            nonce: r.nonce,
            home_chain: r.home_chain,
            home_chat_contract: r.home_chat_contract,
            admins: r.admins,
            members: r.members,
            wraps: r.wraps,
            sealed_info: sealed,
        };
        let mut s = self.prepare_pqchat_session(account, rec).await?;
        info_review(&r.info_json, &mut s)?;
        Ok(s)
    }

    /// S2: as S1 for `PqChatEpoch`, the author the signing account, the epoch id computed.
    pub async fn pqchat_prepare_epoch(
        self: &Arc<Self>,
        account: KeyRef,
        k: Arc<AppKey>,
        r: PqEpochNew,
    ) -> Result<PqChatPrepared, SdkError> {
        let author = self.account_ua(&account)?;
        let session = h32(&r.session_id)?;
        let eid = pqchat::id("epoch", &[session, author, word(r.nonce)]);
        let sealed = self.seal_info(&k, &session, &eid, &r.info_json)?;
        let rec = PqChatEpoch {
            session_id: hex(&session),
            author: hex(&author),
            nonce: r.nonce,
            epoch: r.epoch,
            parent_epoch_id: r.parent_epoch_id,
            admins: r.admins,
            members: r.members,
            wraps: r.wraps,
            sealed_info: sealed,
        };
        let mut s = self.prepare_pqchat_epoch(account, rec).await?;
        info_review(&r.info_json, &mut s)?;
        Ok(s)
    }

    /// V1: whether `sig` is `ua`'s portable signature of the PqChat record `name` holding `record_json` (one of `PqChat`'s
    /// signed structs, its fields by name), as the registry's `requirePortable(ua, PURPOSE_PQCHAT, …)` judges it on the
    /// records read at the profile's final block as a read that feeds a decryption (a single key, an `msig` minimal over two
    /// levels). A record that does not build: `Argument`; any other refusal: `false`, no detail.
    pub async fn verify_pqchat_record(
        self: &Arc<Self>,
        chain: String,
        ua: String,
        name: String,
        record_json: String,
        sig: AppUaSig,
    ) -> Result<bool, SdkError> {
        let id = h32(&ua)?;
        let v = scaas_ua::wallet::bounded::json(record_json.as_bytes(), 1 << 20, pk::JSON_DEPTH)?;
        let td = pqchat::typed(&name, v)?;
        let sig = UASig::from(&sig);
        self.with_records(&chain, id, false, &sig, |state| {
            pqchat::verify(&id, &td, &sig, state)
        })
        .await
    }

    /// V2: a stored payload's hint and envelope (bounded, its canonical form only: `Argument`).
    pub fn pqchat_decode_payload(&self, payload: Vec<u8>) -> Result<PqPayload, SdkError> {
        let (hint, env) = pk::decode_payload(&payload)?;
        Ok(PqPayload {
            hint: hint.to_vec(),
            env,
        })
    }

    fn seal_info(
        &self,
        k: &Arc<AppKey>,
        s: &[u8; 32],
        e: &[u8; 32],
        info: &str,
    ) -> Result<Vec<u8>, SdkError> {
        self.label(pk::INFO)?;
        self.with(&[k], |sc, hs| {
            sc.pqchat_seal_info(at(hs, 0)?, s, e, info.as_bytes())
                .map_err(SdkError::Ua)
        })
    }
}

/// Test-only entry points (feature `vectors`, never in a release build nor a binding): fixed randomness for the vectors.
#[cfg(feature = "vectors")]
impl AppCore {
    /// [`AppCore::pqchat_wrap`] to a given KEM key with fixed `m` and X25519 ephemeral secret `e`.
    #[allow(clippy::too_many_arguments)]
    pub fn pqchat_vectors_wrap(
        &self,
        k: Arc<AppKey>,
        session_id: String,
        epoch_id: String,
        member: String,
        key_id: u64,
        kem_pk: Vec<u8>,
        m: [u8; 32],
        e: [u8; 32],
    ) -> Result<PqWrap, SdkError> {
        self.label(pk::WRAP)?;
        let (s, ep, mb) = (h32(&session_id)?, h32(&epoch_id)?, h32(&member)?);
        let w = self.with(&[&k], |sc, hs| {
            sc.pqchat_vectors_wrap(at(hs, 0)?, &s, &ep, &mb, key_id, &kem_pk, &m, &e)
                .map_err(SdkError::Ua)
        })?;
        Ok(wrap_of(&mb, key_id, w))
    }

    /// [`AppCore::pqchat_unwrap`] by a vector's KEM key (`mlkemSeed ‖ x25519Secret`, 96 bytes) in `seed`'s arena.
    pub fn pqchat_vectors_unwrap(
        &self,
        seed: &str,
        kem_seed: Vec<u8>,
        session_id: String,
        epoch_id: String,
        wrap: PqWrap,
    ) -> Result<Arc<AppKey>, SdkError> {
        self.label(pk::WRAP)?;
        let ks: [u8; 96] = kem_seed.try_into().map_err(|_| SdkError::Argument)?;
        let kem = scaas_ua::wallet::KemKeyPair::vectors_ephemeral(&ks)?;
        let (member, key_id) = (h32(&wrap.member)?, wrap.key_id);
        let h = self.scope(seed)?.pqchat_unwrap(
            &kem,
            &kem_wrap_of(wrap)?,
            &h32(&session_id)?,
            &h32(&epoch_id)?,
            &member,
            key_id,
        )?;
        Ok(self.wrap(seed, h))
    }

    /// S1 / S2's seal with a fixed nonce.
    pub fn pqchat_vectors_seal_info(
        &self,
        k: Arc<AppKey>,
        session_id: String,
        epoch_id: String,
        info_json: String,
        nonce: [u8; 12],
    ) -> Result<Vec<u8>, SdkError> {
        self.label(pk::INFO)?;
        let (s, e) = (h32(&session_id)?, h32(&epoch_id)?);
        self.with(&[&k], |sc, hs| {
            sc.pqchat_vectors_seal_info(at(hs, 0)?, &s, &e, info_json.as_bytes(), &nonce)
                .map_err(SdkError::Ua)
        })
    }

    /// pqchat-core T11's hostile harness: S5 from a given padded plaintext `padded` (a non-zero fill stays: what an honest
    /// sealer never writes), signed by `account` (the sender its UA), the envelope under `k` with a fixed nonce.
    pub async fn pqchat_vectors_seal_padded(
        self: &Arc<Self>,
        account: KeyRef,
        k: Arc<AppKey>,
        pos: Arc<AppKey>,
        header: PqMessageHeader,
        padded: Vec<u8>,
        env_nonce: [u8; 12],
    ) -> Result<PqSealedMessage, SdkError> {
        self.label(pk::ENV)?;
        let crate::op::Key::Ua(_, signer) = crate::op::key(&self.sdk, &account)? else {
            return Err(SdkError::Argument);
        };
        let h = Header {
            session_id: h32(&header.session_id)?,
            epoch_id: h32(&header.epoch_id)?,
            sender: signer.ua().ok_or(SdkError::Argument)?,
            device: h16(&header.device)?,
            counter: header.counter,
            parents: header
                .parents
                .iter()
                .map(|p| h32(p))
                .collect::<Result<_, _>>()?,
        };
        let s = self.with(&[&k, &pos], |sc, hs| {
            sc.pqchat_vectors_seal_padded(at(hs, 0)?, at(hs, 1)?, &h, &padded, &signer, &env_nonce)
                .map_err(SdkError::Ua)
        })?;
        Ok(PqSealedMessage {
            record: record_of(&s.header, s.ciphertext),
            sig: sig_of(&s.sig),
            message_id: hex(&s.message_id),
            inner: s.inner,
            hint: s.hint.to_vec(),
            env: s.env,
            payload: s.payload,
        })
    }

    /// pqchat-core T11's hostile harness: a `sealedInfo` of the given padded plaintext `padded` under `k` (neither
    /// canonicalised nor padded here), with a fixed nonce.
    pub fn pqchat_vectors_seal_info_raw(
        &self,
        k: Arc<AppKey>,
        session_id: String,
        epoch_id: String,
        padded: Vec<u8>,
        nonce: [u8; 12],
    ) -> Result<Vec<u8>, SdkError> {
        self.label(pk::INFO)?;
        let (s, e) = (h32(&session_id)?, h32(&epoch_id)?);
        self.with(&[&k], |sc, hs| {
            sc.pqchat_vectors_seal_info_raw(at(hs, 0)?, &s, &e, &padded, &nonce)
                .map_err(SdkError::Ua)
        })
    }

    /// pqchat-core T11's hostile harness: the envelope under `k` of a record and a signature given apart (a record signed by
    /// a UA other than its sender, through the generic `prepare_pqchat_message`), with a fixed nonce.
    pub fn pqchat_vectors_envelope(
        &self,
        k: Arc<AppKey>,
        record: PqChatMessage,
        sig: AppUaSig,
        nonce: [u8; 12],
    ) -> Result<Vec<u8>, SdkError> {
        self.label(pk::ENV)?;
        let h = header_of(&record)?;
        let inner = pk::encode_inner(&h, &record.ciphertext, &UASig::from(&sig));
        self.with(&[&k], |sc, hs| {
            sc.pqchat_vectors_envelope(at(hs, 0)?, &h.session_id, &h.epoch_id, &inner, &nonce)
                .map_err(SdkError::Ua)
        })
    }

    /// [`AppCore::pqchat_seal_message`] with a fixed envelope nonce.
    pub async fn pqchat_vectors_seal_message(
        self: &Arc<Self>,
        account: KeyRef,
        k: Arc<AppKey>,
        pos: Arc<AppKey>,
        header: PqMessageHeader,
        content_json: String,
        env_nonce: [u8; 12],
    ) -> Result<PqSealedMessage, SdkError> {
        self.seal_message_with(account, k, pos, header, content_json, None, Some(env_nonce))
            .await
    }
}
