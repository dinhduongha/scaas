// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `PqChat`'s signed records as named SDK entries (spec §12.5, review r2 R8, owner R15; feature `pqchat-records`, bit 27): one
//! entry per signed struct of the SCaaS contract `PqChat` (factory class 3, `PURPOSE_PQCHAT` on the registry's closed list),
//! the public-topics records included. Each takes the struct's fields by name, computes what it can itself (a session's and an
//! epoch's `wrapHashes` from its `Wrap` objects, the record's id from its fields), has `scaas-ua` build the typed data in
//! `DS_C` and sign it by a UA key, and returns the review of every field. A caller passes ciphertexts, `sealedInfo` and ids,
//! never a digest. Vectors: `smartcontracts/vectors/pqchat/`. UNAUDITED.
use crate::app_core::{AppCore, AppUaSig};
use crate::error::SdkError;
use crate::op::{hex, KeyRef, ReviewField, Source};
use scaas_ua::wallet::pqchat;
use serde_json::{json, Value};
use std::sync::Arc;

/// `MemberKey(bytes32 ua, uint64 keyId, bytes32 via)`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqMemberKey {
    pub ua: String,
    pub key_id: u64,
    pub via: String,
}

/// `Wrap(bytes32 member, uint64 keyId, bytes mlkemCt, bytes32 x25519Eph, bytes sealedKey)`: hashed into `wrapHashes`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqWrap {
    pub member: String,
    pub key_id: u64,
    pub mlkem_ct: Vec<u8>,
    pub x25519_eph: String,
    pub sealed_key: Vec<u8>,
}

/// `PqChatSession`: `wrapHashes` computed from `wraps`; id `sessionId(creator, nonce)`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqChatSession {
    pub creator: String,
    pub nonce: u64,
    pub home_chain: String,
    pub home_chat_contract: String,
    pub admins: Vec<String>,
    pub members: Vec<PqMemberKey>,
    pub wraps: Vec<PqWrap>,
    pub sealed_info: Vec<u8>,
}

/// `PqChatEpoch`: `wrapHashes` computed from `wraps`; id `epochId(sessionId, author, nonce)`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqChatEpoch {
    pub session_id: String,
    pub author: String,
    pub nonce: u64,
    pub epoch: u64,
    pub parent_epoch_id: String,
    pub admins: Vec<String>,
    pub members: Vec<PqMemberKey>,
    pub wraps: Vec<PqWrap>,
    pub sealed_info: Vec<u8>,
}

/// `PqChatLeave`: id its typed digest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqChatLeave {
    pub session_id: String,
    pub epoch_id: String,
    pub member: String,
    pub nonce: u64,
}

/// `PqChatRemove`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqChatRemove {
    pub session_id: String,
    pub epoch_id: String,
    pub next_epoch: u64,
    pub members: Vec<String>,
    pub admin: String,
    pub nonce: u64,
}

/// `PqChatMessage`: id its typed digest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqChatMessage {
    pub session_id: String,
    pub epoch_id: String,
    pub sender: String,
    /// `bytes16`
    pub device: String,
    pub counter: u64,
    pub parents: Vec<String>,
    pub ciphertext: Vec<u8>,
}

/// `PqTopic`: id `topicId(admin, nonce)`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqTopic {
    pub admin: String,
    pub nonce: u64,
    pub home_chain: String,
    pub home_chat_contract: String,
    pub name: String,
    pub about: Vec<u8>,
    pub open_replies: bool,
}

/// `PqTopicUpdate`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqTopicUpdate {
    pub topic_id: String,
    pub seq: u64,
    pub name: String,
    pub about: Vec<u8>,
    pub open_replies: bool,
}

/// `PqTopicWriter`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqTopicWriter {
    pub topic_id: String,
    pub writer: String,
    pub granted: bool,
    pub seq: u64,
}

/// `EntryRef(bytes32 chainUid, address pqchat, bytes32 entryId, bytes32 contentHash)`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqEntryRef {
    pub chain_uid: String,
    pub pqchat: String,
    pub entry_id: String,
    pub content_hash: String,
}

/// `PqTopicEntry`: id `entryId(topicId, author, nonce)`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqTopicEntry {
    pub topic_id: String,
    pub author: String,
    pub nonce: u64,
    pub parent_id: String,
    pub entry_ref: PqEntryRef,
    pub media_type: String,
    pub body: Vec<u8>,
}

/// `PqTopicEdit`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqTopicEdit {
    pub entry_id: String,
    pub author: String,
    pub nonce: u64,
    pub version: u32,
    pub media_type: String,
    pub body: Vec<u8>,
}

/// `PqTopicVote`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqTopicVote {
    pub entry_id: String,
    pub voter: String,
    pub value: i8,
    pub seq: u64,
}

/// The signed contact card (UA-7 §14 O7, CLI-PQC-05): `PqChatCard(bytes32 ua, uint64 kemVersion, string matrixId)` in `DS_C`
/// under `PURPOSE_PQCHAT`; `matrix_id` empty when the UA has none. Signed off chain and exchanged out of band; no contract
/// stores it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqChatCard {
    pub ua: String,
    pub kem_version: u64,
    pub matrix_id: String,
}

/// A card signed: the card, its typed digest, the `UASig` and the review shown before signing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqCardSigned {
    pub card: PqChatCard,
    pub typed: String,
    pub sig: AppUaSig,
    pub review: Vec<ReviewField>,
}

/// A signed PqChat record: its struct, id (`None` for a struct without one), typed digest, the `wrapHashes` it computed, the
/// `UASig` and the review shown before signing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqChatSigned {
    pub record: String,
    pub id: Option<String>,
    pub typed: String,
    pub wrap_hashes: Vec<String>,
    pub sig: AppUaSig,
    pub review: Vec<ReviewField>,
}

fn w32(s: &str) -> Result<[u8; 32], SdkError> {
    crate::op::unhex(&s.to_ascii_lowercase())?
        .try_into()
        .map_err(|_| SdkError::Argument)
}

fn w64(n: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}

fn members(m: &[PqMemberKey]) -> Value {
    m.iter()
        .map(|k| json!({"ua": k.ua, "keyId": k.key_id, "via": k.via}))
        .collect()
}

/// Each wrap's `hashStruct(Wrap)`, in order.
fn wrap_hashes(wraps: &[PqWrap]) -> Result<Vec<String>, SdkError> {
    wraps
        .iter()
        .map(|w| {
            let v = json!({"member": w.member, "keyId": w.key_id, "mlkemCt": hex(&w.mlkem_ct),
                "x25519Eph": w.x25519_eph, "sealedKey": hex(&w.sealed_key)});
            Ok(hex(&pqchat::wrap_hash(v)?))
        })
        .collect()
}

/// How a record's id is made.
enum Id {
    None,
    Typed,
    Of(&'static str, Vec<[u8; 32]>),
}

fn card_of(c: &PqChatCard) -> Result<pqchat::Card, SdkError> {
    Ok(pqchat::Card {
        ua: w32(&c.ua)?,
        kem_version: c.kem_version,
        matrix_id: c.matrix_id.clone(),
    })
}

impl AppCore {
    /// The entry under each `sign_pqchat_*`: the typed data of `name` holding `message`, its id, the review (the struct, the
    /// id, every field), the signature of `account` (a UA key; a native key or an `msig`: `Argument`), in a PqChat scope.
    async fn sign_pq(
        self: &Arc<Self>,
        account: KeyRef,
        name: &'static str,
        message: Value,
        id: Id,
        wrap_hashes: Vec<String>,
    ) -> Result<PqChatSigned, SdkError> {
        // T26 A-9: a scope that declared PqChat's prefix only (`AppLabelRefused`). The signer field (creator, author, member,
        // admin, sender, voter) is the request's: the cross-language vectors sign records whose signer field is not the
        // vector key's UA, and the contract refuses a record whose signer is not that field (decision (126))
        self.label(scaas_ua::wallet::pqchat_keys::PREFIX.as_bytes())?;
        let sdk = self.sdk.clone();
        sdk.clone()
            .spawn(async move {
                let td = pqchat::typed(name, message.clone())?;
                let digest = td.digest()?;
                let id = match id {
                    Id::None => None,
                    Id::Typed => Some(hex(&digest)),
                    Id::Of(tag, words) => Some(hex(&pqchat::id(tag, &words))),
                };
                let mut review = vec![crate::app_core::field(
                    "record",
                    name.into(),
                    Source::Derived,
                )];
                if let Some(i) = &id {
                    review.push(crate::app_core::field("id", i.clone(), Source::Derived));
                }
                let v = td.to_value();
                crate::app_core::flatten(
                    "message",
                    v.get("message").unwrap_or(&Value::Null),
                    &mut review,
                );
                let crate::op::Key::Ua(_, k) = crate::op::key(&sdk, &account)? else {
                    return Err(SdkError::Argument);
                };
                let s = pqchat::sign(&k, &td)?;
                Ok(PqChatSigned {
                    record: name.into(),
                    id,
                    typed: hex(&digest),
                    wrap_hashes,
                    sig: AppUaSig {
                        key_data: s.key_data,
                        signature: s.signature,
                        members: vec![],
                    },
                    review,
                })
            })
            .await
    }

    /// `PqChatSession`, its `wrapHashes` from `r.wraps`.
    pub async fn sign_pqchat_session(
        self: &Arc<Self>,
        account: KeyRef,
        r: PqChatSession,
    ) -> Result<PqChatSigned, SdkError> {
        let wh = wrap_hashes(&r.wraps)?;
        let m = json!({"creator": r.creator, "nonce": r.nonce, "homeChain": r.home_chain,
            "homeChatContract": r.home_chat_contract, "admins": r.admins, "members": members(&r.members),
            "wrapHashes": wh, "sealedInfo": hex(&r.sealed_info)});
        let id = Id::Of("session", vec![w32(&r.creator)?, w64(r.nonce)]);
        self.sign_pq(account, "PqChatSession", m, id, wh).await
    }

    /// `PqChatEpoch`, its `wrapHashes` from `r.wraps`.
    pub async fn sign_pqchat_epoch(
        self: &Arc<Self>,
        account: KeyRef,
        r: PqChatEpoch,
    ) -> Result<PqChatSigned, SdkError> {
        let wh = wrap_hashes(&r.wraps)?;
        let m = json!({"sessionId": r.session_id, "author": r.author, "nonce": r.nonce, "epoch": r.epoch,
            "parentEpochId": r.parent_epoch_id, "admins": r.admins, "members": members(&r.members),
            "wrapHashes": wh, "sealedInfo": hex(&r.sealed_info)});
        let id = Id::Of(
            "epoch",
            vec![w32(&r.session_id)?, w32(&r.author)?, w64(r.nonce)],
        );
        self.sign_pq(account, "PqChatEpoch", m, id, wh).await
    }

    /// `PqChatLeave`.
    pub async fn sign_pqchat_leave(
        self: &Arc<Self>,
        account: KeyRef,
        r: PqChatLeave,
    ) -> Result<PqChatSigned, SdkError> {
        let m = json!({"sessionId": r.session_id, "epochId": r.epoch_id, "member": r.member, "nonce": r.nonce});
        self.sign_pq(account, "PqChatLeave", m, Id::Typed, vec![])
            .await
    }

    /// `PqChatRemove`.
    pub async fn sign_pqchat_remove(
        self: &Arc<Self>,
        account: KeyRef,
        r: PqChatRemove,
    ) -> Result<PqChatSigned, SdkError> {
        let m = json!({"sessionId": r.session_id, "epochId": r.epoch_id, "nextEpoch": r.next_epoch,
            "members": r.members, "admin": r.admin, "nonce": r.nonce});
        self.sign_pq(account, "PqChatRemove", m, Id::None, vec![])
            .await
    }

    /// `PqChatMessage`.
    pub async fn sign_pqchat_message(
        self: &Arc<Self>,
        account: KeyRef,
        r: PqChatMessage,
    ) -> Result<PqChatSigned, SdkError> {
        let m = json!({"sessionId": r.session_id, "epochId": r.epoch_id, "sender": r.sender, "device": r.device,
            "counter": r.counter, "parents": r.parents, "ciphertext": hex(&r.ciphertext)});
        self.sign_pq(account, "PqChatMessage", m, Id::Typed, vec![])
            .await
    }

    /// V2: `hashStruct(Wrap)` of a wrap read from state, for pqchat-core's check against the signed record's `wrapHashes[i]`
    /// before the wrap enters a decapsulation (CLI-PQC-07). No key; a wrap that does not build: `Argument`.
    pub fn pqchat_wrap_hash(&self, wrap: PqWrap) -> Result<String, SdkError> {
        wrap_hashes(std::slice::from_ref(&wrap))?
            .pop()
            .ok_or(SdkError::Internal)
    }

    /// The `messageId` of a received `PqChatMessage` (UA-7 §4.3, `typed(PqChatMessage)`): the one id a message has on every
    /// store (P19), for pqchat-core's dedupe. No key; a record that does not build: `Argument`.
    pub fn pqchat_message_id(&self, r: PqChatMessage) -> Result<String, SdkError> {
        let m = json!({"sessionId": r.session_id, "epochId": r.epoch_id, "sender": r.sender, "device": r.device,
            "counter": r.counter, "parents": r.parents, "ciphertext": hex(&r.ciphertext)});
        Ok(hex(&pqchat::typed("PqChatMessage", m)?.digest()?))
    }

    /// S4: `sessionId(creator, nonce)` (UA-7 §4.3), before signing: the wraps' AAD and the KEK bind it. No key.
    pub fn pqchat_session_id(&self, creator: String, nonce: u64) -> Result<String, SdkError> {
        Ok(hex(&pqchat::id("session", &[w32(&creator)?, w64(nonce)])))
    }

    /// S4: `epochId(sessionId, author, nonce)` (UA-7 §4.3), before signing. No key.
    pub fn pqchat_epoch_id(
        &self,
        session_id: String,
        author: String,
        nonce: u64,
    ) -> Result<String, SdkError> {
        Ok(hex(&pqchat::id(
            "epoch",
            &[w32(&session_id)?, w32(&author)?, w64(nonce)],
        )))
    }

    /// `PqTopic`.
    pub async fn sign_pqchat_topic(
        self: &Arc<Self>,
        account: KeyRef,
        r: PqTopic,
    ) -> Result<PqChatSigned, SdkError> {
        let m = json!({"admin": r.admin, "nonce": r.nonce, "homeChain": r.home_chain,
            "homeChatContract": r.home_chat_contract, "name": r.name, "about": hex(&r.about),
            "openReplies": r.open_replies});
        let id = Id::Of("topic", vec![w32(&r.admin)?, w64(r.nonce)]);
        self.sign_pq(account, "PqTopic", m, id, vec![]).await
    }

    /// `PqTopicUpdate`.
    pub async fn sign_pqchat_topic_update(
        self: &Arc<Self>,
        account: KeyRef,
        r: PqTopicUpdate,
    ) -> Result<PqChatSigned, SdkError> {
        let m = json!({"topicId": r.topic_id, "seq": r.seq, "name": r.name, "about": hex(&r.about),
            "openReplies": r.open_replies});
        self.sign_pq(account, "PqTopicUpdate", m, Id::None, vec![])
            .await
    }

    /// `PqTopicWriter`.
    pub async fn sign_pqchat_topic_writer(
        self: &Arc<Self>,
        account: KeyRef,
        r: PqTopicWriter,
    ) -> Result<PqChatSigned, SdkError> {
        let m =
            json!({"topicId": r.topic_id, "writer": r.writer, "granted": r.granted, "seq": r.seq});
        self.sign_pq(account, "PqTopicWriter", m, Id::None, vec![])
            .await
    }

    /// `PqTopicEntry` (a post or a reply).
    pub async fn sign_pqchat_topic_entry(
        self: &Arc<Self>,
        account: KeyRef,
        r: PqTopicEntry,
    ) -> Result<PqChatSigned, SdkError> {
        let e = &r.entry_ref;
        let m = json!({"topicId": r.topic_id, "author": r.author, "nonce": r.nonce, "parentId": r.parent_id,
            "ref": {"chainUid": e.chain_uid, "pqchat": e.pqchat, "entryId": e.entry_id, "contentHash": e.content_hash},
            "mediaType": r.media_type, "body": hex(&r.body)});
        let id = Id::Of(
            "entry",
            vec![w32(&r.topic_id)?, w32(&r.author)?, w64(r.nonce)],
        );
        self.sign_pq(account, "PqTopicEntry", m, id, vec![]).await
    }

    /// `PqTopicEdit`.
    pub async fn sign_pqchat_topic_edit(
        self: &Arc<Self>,
        account: KeyRef,
        r: PqTopicEdit,
    ) -> Result<PqChatSigned, SdkError> {
        let m = json!({"entryId": r.entry_id, "author": r.author, "nonce": r.nonce, "version": r.version,
            "mediaType": r.media_type, "body": hex(&r.body)});
        self.sign_pq(account, "PqTopicEdit", m, Id::None, vec![])
            .await
    }

    /// `PqTopicVote`.
    pub async fn sign_pqchat_topic_vote(
        self: &Arc<Self>,
        account: KeyRef,
        r: PqTopicVote,
    ) -> Result<PqChatSigned, SdkError> {
        let m = json!({"entryId": r.entry_id, "voter": r.voter, "value": r.value, "seq": r.seq});
        self.sign_pq(account, "PqTopicVote", m, Id::None, vec![])
            .await
    }

    /// The account's contact card (UA-7 §14 O7), in a PqChat scope (`AppLabelRefused`): its UA from the signing account (a UA key; a native key or an `msig`:
    /// `Argument`), `kem_version` and `matrix_id` (empty: none; a malformed one `Argument`) as given and shown in the review.
    pub async fn sign_pqchat_card(
        self: &Arc<Self>,
        account: KeyRef,
        kem_version: u64,
        matrix_id: String,
    ) -> Result<PqCardSigned, SdkError> {
        // T26 A-9: a PqChat scope only, as every PqChat entry
        self.label(scaas_ua::wallet::pqchat_keys::PREFIX.as_bytes())?;
        let card = PqChatCard {
            ua: hex(&self.account_ua(&account)?),
            kem_version,
            matrix_id,
        };
        let c = card_of(&card)?;
        let sdk = self.sdk.clone();
        sdk.clone()
            .spawn(async move {
                let td = pqchat::card_typed(&c)?;
                let mut review = vec![crate::app_core::field(
                    "record",
                    "PqChatCard".into(),
                    Source::Derived,
                )];
                let v = td.to_value();
                crate::app_core::flatten(
                    "message",
                    v.get("message").unwrap_or(&Value::Null),
                    &mut review,
                );
                let crate::op::Key::Ua(_, k) = crate::op::key(&sdk, &account)? else {
                    return Err(SdkError::Argument);
                };
                let s = pqchat::sign_card(&k, &c)?;
                Ok(PqCardSigned {
                    card,
                    typed: hex(&td.digest()?),
                    sig: AppUaSig {
                        key_data: s.key_data,
                        signature: s.signature,
                        members: vec![],
                    },
                    review,
                })
            })
            .await
    }

    /// Whether `card` counts for `ua` (CLI-PQC-05): its `ua` is `ua`, its Matrix id well formed, and `sig` is `ua`'s portable
    /// signature of it as V1 judges a record, on the registry's records read at the profile's final block as a read that
    /// feeds a decryption. A card whose `ua` is not 32 bytes: `Argument`; any other refusal: `false`, no detail.
    pub async fn verify_pqchat_card(
        self: &Arc<Self>,
        chain: String,
        ua: String,
        card: PqChatCard,
        sig: AppUaSig,
    ) -> Result<bool, SdkError> {
        let id = w32(&ua)?;
        let c = card_of(&card)?;
        let sig = scaas_ua::ua_portable::UASig::from(&sig);
        self.with_records(&chain, id, false, |state| {
            pqchat::verify_card(&id, &c, &sig, state)
        })
        .await
    }
}
