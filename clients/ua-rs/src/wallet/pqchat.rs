// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `PqChat`'s signed records as SCaaS entries (scaas-sdk spec §12.5, review r2 R8; feature `app-core`): each struct's typed
//! data in the contract's portable domain `DS_C` (`EIP712Domain(string name,string version)`, "SCaaS PqChat", "1"), built here
//! from the type strings UA-7 and the public-topics spec fix (clientkeys `src/pqchat.js` `TYPE_STRINGS`), a `Wrap`'s struct hash
//! (what a session or epoch lists as `wrapHashes`), the ids of the tags `scaas/pqchat/v1/*`, and a single UA key's signature
//! over `uaMessage(kind, PURPOSE_PQCHAT, typed)` (role `Pop`: the registry's `requirePortable` checks it, `keyData` empty).
//! The signed contact card (UA-7 §14 O7, [`Card`]) is signed and checked by its own calls, never as a record.
//! Vectors: `smartcontracts/vectors/pqchat/`. Not here: an `msig` or a native signer of a PqChat record. UNAUDITED.
use super::eip712::TypedData;
use super::signer::{KeyRef, SigRole, SignRequest, Signer};
use super::{Error, Result};
use crate::ua_portable::UASig;
use crate::{keccak256, ua_message};
use serde_json::{json, Value};

/// PqChat's app id in the registry's open app namespace (pqchat-core T10b, owner 2026-11-22): the scope's per-account
/// storage root (`app_root_key`), so the shared `seal_for_arweave` derives its upload keys. No app record is signed under it.
pub const APP_ID_TAG: &str = "scaas.pqchat.v1";

/// `APP_ID = keccak256("scaas.pqchat.v1")`.
pub fn app_id() -> [u8; 32] {
    keccak256(APP_ID_TAG.as_bytes())
}

/// The type strings, exactly as the specs fix them (UA-7 §4, public topics §2).
pub const TYPE_STRINGS: &[(&str, &str)] = &[
    ("MemberKey", "MemberKey(bytes32 ua,uint64 keyId,bytes32 via)"),
    (
        "Wrap",
        "Wrap(bytes32 member,uint64 keyId,bytes mlkemCt,bytes32 x25519Eph,bytes sealedKey)",
    ),
    (
        "PqChatSession",
        "PqChatSession(bytes32 creator,uint64 nonce,bytes32 homeChain,address homeChatContract,bytes32[] admins,MemberKey[] members,bytes32[] wrapHashes,bytes sealedInfo,uint8 groupMode)",
    ),
    (
        "PqChatEpoch",
        "PqChatEpoch(bytes32 sessionId,bytes32 author,uint64 nonce,uint64 epoch,bytes32 parentEpochId,bytes32[] admins,MemberKey[] members,bytes32[] wrapHashes,bytes sealedInfo)",
    ),
    (
        "PqChatLeave",
        "PqChatLeave(bytes32 sessionId,bytes32 epochId,bytes32 member,uint64 nonce)",
    ),
    (
        "PqChatRemove",
        "PqChatRemove(bytes32 sessionId,bytes32 epochId,uint64 nextEpoch,bytes32[] members,bytes32 admin,uint64 nonce)",
    ),
    (
        "PqChatMessage",
        "PqChatMessage(bytes32 sessionId,bytes32 epochId,bytes32 sender,bytes16 device,uint64 counter,bytes32[] parents,bytes ciphertext)",
    ),
    (
        "PqTopic",
        "PqTopic(bytes32 admin,uint64 nonce,bytes32 homeChain,address homeChatContract,string name,bytes about,bool openReplies)",
    ),
    (
        "PqTopicUpdate",
        "PqTopicUpdate(bytes32 topicId,uint64 seq,string name,bytes about,bool openReplies)",
    ),
    (
        "PqTopicWriter",
        "PqTopicWriter(bytes32 topicId,bytes32 writer,bool granted,uint64 seq)",
    ),
    (
        "PqTopicEntry",
        "PqTopicEntry(bytes32 topicId,bytes32 author,uint64 nonce,bytes32 parentId,EntryRef ref,string mediaType,bytes body)",
    ),
    (
        "EntryRef",
        "EntryRef(bytes32 chainUid,address pqchat,bytes32 entryId,bytes32 contentHash)",
    ),
    (
        "PqTopicEdit",
        "PqTopicEdit(bytes32 entryId,bytes32 author,uint64 nonce,uint32 version,string mediaType,bytes body)",
    ),
    (
        "PqTopicVote",
        "PqTopicVote(bytes32 entryId,bytes32 voter,int8 value,uint64 seq)",
    ),
    (
        "PqChatCard",
        "PqChatCard(bytes32 ua,uint64 kemVersion,string matrixId)",
    ),
];

/// The records a UA signs for a contract (every type string but the nested `MemberKey`, `Wrap` and `EntryRef`, and the card).
pub const RECORDS: &[&str] = &[
    "PqChatSession",
    "PqChatEpoch",
    "PqChatLeave",
    "PqChatRemove",
    "PqChatMessage",
    "PqTopic",
    "PqTopicUpdate",
    "PqTopicWriter",
    "PqTopicEntry",
    "PqTopicEdit",
    "PqTopicVote",
];

/// `PURPOSE_PQCHAT = keccak256("scaas.ua.purpose.pqchat.v1")`.
pub fn purpose() -> [u8; 32] {
    keccak256(b"scaas.ua.purpose.pqchat.v1")
}

/// `name`'s fields from its type string.
fn fields(name: &str) -> Option<Value> {
    let (_, s) = TYPE_STRINGS.iter().find(|(n, _)| *n == name)?;
    let list = s.strip_prefix(name)?.strip_prefix('(')?.strip_suffix(')')?;
    Some(Value::Array(
        list.split(',')
            .map(|f| {
                let (t, n) = f.split_once(' ')?;
                Some(json!({"name": n, "type": t}))
            })
            .collect::<Option<Vec<_>>>()?,
    ))
}

/// The typed data of the struct `name` (a type string above) holding `message` (its fields by name, `0x` hex bytes), in
/// `DS_C`. `Argument` for an unknown name; the message's own checks are the EIP-712 encoder's.
pub fn typed(name: &str, message: Value) -> Result<TypedData> {
    let mut types = serde_json::Map::new();
    types.insert(
        "EIP712Domain".into(),
        json!([{"name": "name", "type": "string"}, {"name": "version", "type": "string"}]),
    );
    let mut todo = vec![name.to_string()];
    while let Some(n) = todo.pop() {
        if types.contains_key(&n) {
            continue;
        }
        let f = fields(&n).ok_or(Error::Argument)?;
        for x in f.as_array().into_iter().flatten() {
            let t = x["type"]
                .as_str()
                .unwrap_or_default()
                .trim_end_matches("[]");
            if TYPE_STRINGS.iter().any(|(k, _)| *k == t) {
                todo.push(t.to_string());
            }
        }
        types.insert(n, f);
    }
    let v = json!({
        "types": types,
        "primaryType": name,
        "domain": {"name": "SCaaS PqChat", "version": "1"},
        "message": message,
    });
    TypedData::from_json(&serde_json::to_vec(&v).map_err(|_| Error::Argument)?)
}

/// `hashStruct(Wrap)`: one entry of a session's or epoch's `wrapHashes`.
pub fn wrap_hash(wrap: Value) -> Result<[u8; 32]> {
    typed("Wrap", wrap)?.struct_hash()
}

/// `keccak256(abi.encode(keccak256("scaas/pqchat/v1/" ‖ tag), words…))`: the ids and scopes of UA-7 §4.3 and the topics spec
/// (`words` each one ABI word: a `bytes32`, a `uint64` right-aligned, a `bytes16` left-aligned).
pub fn id(tag: &str, words: &[[u8; 32]]) -> [u8; 32] {
    let t = keccak256(format!("scaas/pqchat/v1/{tag}").as_bytes());
    keccak256(&[&t[..], &words.concat()].concat())
}

/// A single UA key's `UASig` over the record `td` (one of [`RECORDS`] in `DS_C`, else `Argument`): `uaMessage(kind,
/// PURPOSE_PQCHAT, typed)`, role `Pop`, no key data, no members. A native key or one claiming the `msig` kind: `Argument`.
pub fn sign(key: &dyn Signer, td: &TypedData) -> Result<UASig> {
    if !own_struct(td) {
        return Err(Error::Argument);
    }
    sign_typed(key, td)
}

/// Review A-8 (as PqVault's path checks its own): `td` is one of [`RECORDS`] with that record's own `encodeType` (referenced
/// types included), not another struct named like it.
fn own_struct(td: &TypedData) -> bool {
    RECORDS.contains(&td.primary_type())
        && td
            .to_value()
            .get("message")
            .cloned()
            .and_then(|m| typed(td.primary_type(), m).ok())
            .is_some_and(|t| t.encode_type() == td.encode_type())
}

/// [`sign`] after its struct check.
fn sign_typed(key: &dyn Signer, td: &TypedData) -> Result<UASig> {
    let KeyRef::Ua { kind, .. } = key.key_ref() else {
        return Err(Error::Argument);
    };
    let v = td.to_value();
    if kind == 0x0120 || v.get("domain") != Some(&json!({"name": "SCaaS PqChat", "version": "1"})) {
        return Err(Error::Argument);
    }
    let m = ua_message(kind, &purpose(), &td.digest()?)?;
    let req = if kind == 0x0100 {
        SignRequest::WebAuthn { challenge: m }
    } else {
        SignRequest::UaMsg {
            kind,
            ua_msg: m,
            role: SigRole::Pop,
        }
    };
    Ok(UASig {
        key_data: vec![],
        signature: super::webauthn::answer(key, &req)?,
        members: vec![],
    })
}

/// V1 (pqchat-core spec §5): whether `sig` is `ua`'s portable signature of the PqChat record `td` (one of [`RECORDS`] in
/// `DS_C`), as the registry's `requirePortable(ua, PURPOSE_PQCHAT, typed, sig)` judges it on `state` (a single key, or an
/// `msig` minimal over two levels, its native members over the typed digest). A native id, an unknown UA, another struct or
/// domain: `false`. No detail: a reader counts a refusal, it never answers one.
pub fn verify(ua: &[u8; 32], td: &TypedData, sig: &UASig, state: &super::AppRecordState) -> bool {
    own_struct(td) && verify_typed(ua, td, sig, state)
}

/// [`verify`] after its struct check.
fn verify_typed(ua: &[u8; 32], td: &TypedData, sig: &UASig, state: &super::AppRecordState) -> bool {
    let v = td.to_value();
    if v.get("domain") != Some(&json!({"name": "SCaaS PqChat", "version": "1"}))
        || crate::in_native_space(ua)
    {
        return false;
    }
    let (Ok(digest), Some((kind, key_data))) = (td.digest(), (state.members)(*ua)) else {
        return false;
    };
    crate::ua_portable::check_portable_current(
        kind,
        &key_data,
        ua,
        &purpose(),
        &digest,
        sig,
        state.members,
        state.current,
        Some(state.accepted),
    )
    .is_ok()
}

/// A Matrix user id's bound in bytes (the Matrix spec's).
pub const MATRIX_ID_MAX: usize = 255;

/// The signed contact card (UA-7 §14 O7, its Change of 2026-11-05; CLI-PQC-05): `PqChatCard(bytes32 ua, uint64 kemVersion,
/// string matrixId)` in `DS_C` under `PURPOSE_PQCHAT`, signed off chain and exchanged out of band; `matrix_id` empty when the
/// UA has none. Vectors: `smartcontracts/vectors/pqchat/cards.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    pub ua: [u8; 32],
    pub kem_version: u64,
    pub matrix_id: String,
}

/// A card's Matrix id: empty, or `@localpart:server` in at most [`MATRIX_ID_MAX`] bytes of printable ASCII (0x21-0x7e), the
/// localpart non-empty and without `:`, the server name non-empty; else `Argument`. Ids compare byte for byte.
pub fn check_matrix_id(id: &str) -> Result<()> {
    if id.is_empty() {
        return Ok(());
    }
    let b = id.as_bytes();
    let colon = id.find(':');
    if b.len() > MATRIX_ID_MAX
        || b.iter().any(|c| !(0x21..=0x7e).contains(c))
        || !id.starts_with('@')
        || colon.is_none_or(|i| i < 2 || i == b.len() - 1)
    {
        return Err(Error::Argument);
    }
    Ok(())
}

/// The card's typed data in `DS_C`; a malformed Matrix id: `Argument`.
pub fn card_typed(c: &Card) -> Result<TypedData> {
    check_matrix_id(&c.matrix_id)?;
    typed(
        "PqChatCard",
        json!({"ua": super::eip712::to_hex(&c.ua), "kemVersion": c.kem_version, "matrixId": c.matrix_id}),
    )
}

/// A single UA key's `UASig` over its card, as [`sign`] signs a record. The card's `ua` is the caller's to set (the SDK takes
/// it from the signing account).
pub fn sign_card(key: &dyn Signer, c: &Card) -> Result<UASig> {
    sign_typed(key, &card_typed(c)?)
}

/// Whether `c` counts for `ua` (CLI-PQC-05): its `ua` is `ua`, its Matrix id well formed, and `sig` is `ua`'s portable
/// signature of it as [`verify`] judges a record on `state`. No detail.
pub fn verify_card(ua: &[u8; 32], c: &Card, sig: &UASig, state: &super::AppRecordState) -> bool {
    c.ua == *ua && card_typed(c).is_ok_and(|td| verify_typed(ua, &td, sig, state))
}
