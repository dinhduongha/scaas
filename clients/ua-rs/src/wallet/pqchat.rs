// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `PqChat`'s signed records as SCaaS entries (scaas-sdk spec §12.5, review r2 R8; feature `app-core`): each struct's typed
//! data in the contract's portable domain `DS_C` (`EIP712Domain(string name,string version)`, "SCaaS PqChat", "1"), built here
//! from the type strings UA-7 and the public-topics spec fix (clientkeys `src/pqchat.js` `TYPE_STRINGS`), a `Wrap`'s struct hash
//! (what a session or epoch lists as `wrapHashes`), the ids of the tags `scaas/pqchat/v1/*`, and a single UA key's signature
//! over `uaMessage(kind, PURPOSE_PQCHAT, typed)` (role `Pop`: the registry's `requirePortable` checks it, `keyData` empty).
//! Vectors: `smartcontracts/vectors/pqchat/`. Not here: an `msig` or a native signer of a PqChat record. UNAUDITED.
use super::eip712::TypedData;
use super::signer::{KeyRef, SigRole, SignRequest, Signer};
use super::{Error, Result};
use crate::ua_portable::UASig;
use crate::{keccak256, ua_message};
use serde_json::{json, Value};

/// The type strings, exactly as the specs fix them (UA-7 §4, public topics §2).
pub const TYPE_STRINGS: &[(&str, &str)] = &[
    ("MemberKey", "MemberKey(bytes32 ua,uint64 keyId,bytes32 via)"),
    (
        "Wrap",
        "Wrap(bytes32 member,uint64 keyId,bytes mlkemCt,bytes32 x25519Eph,bytes sealedKey)",
    ),
    (
        "PqChatSession",
        "PqChatSession(bytes32 creator,uint64 nonce,bytes32 homeChain,address homeChatContract,bytes32[] admins,MemberKey[] members,bytes32[] wrapHashes,bytes sealedInfo)",
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
];

/// The structs a UA signs (every type string but the nested `MemberKey`, `Wrap` and `EntryRef`).
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
    let KeyRef::Ua { kind, .. } = key.key_ref() else {
        return Err(Error::Argument);
    };
    let v = td.to_value();
    let ds = v.get("domain");
    if kind == 0x0120
        || !RECORDS.contains(&td.primary_type())
        || ds != Some(&json!({"name": "SCaaS PqChat", "version": "1"}))
    {
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
