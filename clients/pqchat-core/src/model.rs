// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The control-plane records as the crate holds them: read from state by name (the SDK's named JSON), lower-case hex ids.
use crate::PqChatError;
use serde_json::Value;

/// `MemberKey`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Member {
    pub ua: String,
    pub key_id: u64,
    pub via: String,
}

/// A session record (epoch 0, its id the session's) or an epoch record, with its `sigHash`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Epoch {
    pub id: String,
    pub session_id: String,
    /// the creator for epoch 0
    pub author: String,
    pub nonce: u64,
    pub epoch: u64,
    /// zero for epoch 0
    pub parent: String,
    pub admins: Vec<String>,
    pub members: Vec<Member>,
    pub wrap_hashes: Vec<String>,
    pub sealed_info: Vec<u8>,
    pub sig_hash: String,
}

pub const ZERO32: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

impl Epoch {
    pub fn has_member(&self, ua: &str) -> bool {
        self.members.iter().any(|m| m.ua == ua)
    }
    pub fn index_of(&self, ua: &str) -> Option<usize> {
        self.members.iter().position(|m| m.ua == ua)
    }

    /// `sessionOf(sessionId)`'s answer (`{s, sigHash}`); `None` when the session is not stored (its creator zero).
    pub fn from_session(id: &str, v: &Value) -> Result<Option<Epoch>, PqChatError> {
        let s = &at(v, "s");
        let author = h(at(s, "creator"))?;
        if author == ZERO32 {
            return Ok(None);
        }
        Ok(Some(Epoch {
            id: id.to_ascii_lowercase(),
            session_id: id.to_ascii_lowercase(),
            author,
            nonce: num(at(s, "nonce"))?,
            epoch: 0,
            parent: ZERO32.into(),
            admins: list(at(s, "admins"))?,
            members: members(at(s, "members"))?,
            wrap_hashes: list(at(s, "wrapHashes"))?,
            sealed_info: bytes(at(s, "sealedInfo"))?,
            sig_hash: h(at(v, "sigHash"))?,
        }))
    }

    /// `epochOf(epochId)`'s answer (`{e, sigHash}`); `None` when not stored.
    pub fn from_epoch(id: &str, v: &Value) -> Result<Option<Epoch>, PqChatError> {
        let e = &at(v, "e");
        let session_id = h(at(e, "sessionId"))?;
        if session_id == ZERO32 {
            return Ok(None);
        }
        Ok(Some(Epoch {
            id: id.to_ascii_lowercase(),
            session_id,
            author: h(at(e, "author"))?,
            nonce: num(at(e, "nonce"))?,
            epoch: num(at(e, "epoch"))?,
            parent: h(at(e, "parentEpochId"))?,
            admins: list(at(e, "admins"))?,
            members: members(at(e, "members"))?,
            wrap_hashes: list(at(e, "wrapHashes"))?,
            sealed_info: bytes(at(e, "sealedInfo"))?,
            sig_hash: h(at(v, "sigHash"))?,
        }))
    }
}

fn bad() -> PqChatError {
    PqChatError::Internal
}

/// A `0x` hex string, lower case.
pub fn h(v: &Value) -> Result<String, PqChatError> {
    let s = v.as_str().ok_or_else(bad)?;
    if !s.starts_with("0x") {
        return Err(bad());
    }
    Ok(s.to_ascii_lowercase())
}

/// An integer as the SDK's named JSON gives it (a decimal string) or as a JSON number.
pub fn num(v: &Value) -> Result<u64, PqChatError> {
    match v {
        Value::String(s) => s.parse().map_err(|_| bad()),
        Value::Number(n) => n.as_u64().ok_or_else(bad),
        _ => Err(bad()),
    }
}

pub fn list(v: &Value) -> Result<Vec<String>, PqChatError> {
    v.as_array().ok_or_else(bad)?.iter().map(h).collect()
}

fn members(v: &Value) -> Result<Vec<Member>, PqChatError> {
    v.as_array()
        .ok_or_else(bad)?
        .iter()
        .map(|m| {
            Ok(Member {
                ua: h(at(m, "ua"))?,
                key_id: num(at(m, "keyId"))?,
                via: h(at(m, "via"))?,
            })
        })
        .collect()
}

/// `0x` hex to bytes (a transport encoding of the reads, no format of its own).
pub fn bytes(v: &Value) -> Result<Vec<u8>, PqChatError> {
    unhex(&h(v)?)
}

pub fn unhex(s: &str) -> Result<Vec<u8>, PqChatError> {
    let x = s.strip_prefix("0x").ok_or_else(bad)?;
    if !x.len().is_multiple_of(2) {
        return Err(bad());
    }
    (0..x.len())
        .step_by(2)
        .map(|i| {
            x.get(i..i + 2)
                .and_then(|b| u8::from_str_radix(b, 16).ok())
                .ok_or_else(bad)
        })
        .collect()
}

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 + 2 * b.len());
    s.push_str("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// The member `k` of a named-JSON answer (`Null` when absent: every reader then refuses the shape).
pub fn at<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.get(k).unwrap_or(&Value::Null)
}
