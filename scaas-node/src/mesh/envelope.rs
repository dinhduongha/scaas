//! Dạng dây `scaas-intent/1.2` (spec mesh §4.2–§4.3) và JSON chính tắc của body cho `body_hash`.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::Code;
use crate::adapter::Family;

pub const SPEC: &str = "scaas-intent/1.2";
const SPEC_PREFIX: &str = "scaas-intent/";
pub const MAX_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hub {
    pub id: String,
    pub pubkey: String,
    pub published_at: u64,
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Exclusive {
    pub relayer_id: String,
    pub until: u64,
}

/// Trường lạ ở cấp trên cùng bị bỏ qua (luật minor bump); trường lạ trong `evm`/`op` thì được băm (`body_hash`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub spec: String,
    pub intent_id: String,
    pub chain_key: String,
    pub family: String,
    pub contract: String,
    pub visibility: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evm: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op: Option<Value>,
    pub hub: Hub,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclusive: Option<Exclusive>,
    pub hop_count: u64,
}

impl Envelope {
    pub fn body(&self) -> &Value {
        self.evm.as_ref().or(self.op.as_ref()).expect("parse() checked the body")
    }

    pub fn network(&self) -> &str {
        self.chain_key.split_once(':').map_or("", |(_, n)| n)
    }

    pub fn private(&self) -> bool {
        self.visibility == "private"
    }
}

/// Envelope đã qua L0: `intent_id` (như người gửi khai), `body_hash`.
#[derive(Debug, Clone)]
pub struct Parsed {
    pub envelope: Envelope,
    pub claimed_id: [u8; 32],
    pub body_hash: [u8; 32],
}

/// Hex chữ thường đúng `n` byte; `0x` bắt buộc hoặc cấm theo `prefixed` (§4.2).
pub fn hex_n(s: &str, n: usize, prefixed: bool) -> Option<Vec<u8>> {
    let h = if prefixed { s.strip_prefix("0x")? } else { s };
    if h.len() != 2 * n || !h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    alloy::hex::decode(h).ok()
}

pub fn b32(s: &str, prefixed: bool) -> Option<[u8; 32]> {
    hex_n(s, 32, prefixed).and_then(|v| v.try_into().ok())
}

fn check(v: &Value) -> bool {
    let ascii = |s: &str| s.bytes().all(|b| (0x20..=0x7e).contains(&b));
    match v {
        Value::Null | Value::Bool(_) => true,
        Value::Number(n) => n.as_i64().is_some(),
        Value::String(s) => ascii(s),
        Value::Array(a) => a.iter().all(check),
        Value::Object(m) => m.iter().all(|(k, x)| ascii(k) && check(x)),
    }
}

/// Khoá sắp bytewise, không khoảng trắng, không số thực (số nguyên vừa `i64`), chuỗi ASCII in được.
/// `serde_json::Map` mặc định là `BTreeMap` — feature `preserve_order` mà bật thì vector 32 đỏ.
pub fn canonical_body(v: &Value) -> Result<Vec<u8>, Code> {
    if !check(v) {
        return Err(Code::BadEnvelope);
    }
    serde_json::to_vec(v).map_err(|_| Code::BadEnvelope)
}

fn spec_ok(s: &str) -> bool {
    let Some((major, minor)) = s.strip_prefix(SPEC_PREFIX).and_then(|v| v.split_once('.')) else { return false };
    major == "1" && minor.parse::<u32>().is_ok_and(|m| m >= 2)
}

/// L0 trừ "chain đã biết" (cần cấu hình, ở `accept`).
pub fn parse(bytes: &[u8]) -> Result<Parsed, Code> {
    if bytes.len() > MAX_BYTES {
        return Err(Code::BadEnvelope);
    }
    let v: Value = serde_json::from_slice(bytes).map_err(|_| Code::BadEnvelope)?;
    let spec = v.get("spec").and_then(Value::as_str).ok_or(Code::BadEnvelope)?;
    if !spec_ok(spec) {
        return Err(Code::UnsupportedSpec);
    }
    let family = v.get("family").and_then(Value::as_str).ok_or(Code::BadEnvelope)?.to_string();
    let fam = Family::parse(&family).filter(|f| *f != Family::Soroban).ok_or(Code::FamilyNotSupported)?;
    let envelope: Envelope = serde_json::from_value(v).map_err(|_| Code::BadEnvelope)?;
    let e = &envelope;
    let evm = matches!(fam, Family::Evm | Family::Hedera);
    let well_formed = e.chain_key.split_once(':').is_some_and(|(f, n)| f == family && !n.is_empty() && e.chain_key.len() <= 255)
        && matches!(e.visibility.as_str(), "open" | "private")
        && e.evm.is_some() == evm
        && e.op.is_some() != evm
        && b32(&e.hub.id, false).is_some()
        && b32(&e.hub.pubkey, false).is_some()
        && hex_n(&e.hub.sig, 64, false).is_some()
        && e.exclusive.as_ref().is_none_or(|x| b32(&x.relayer_id, false).is_some());
    let claimed_id = b32(&e.intent_id, true).filter(|_| well_formed).ok_or(Code::BadEnvelope)?;
    let body_hash = Sha256::digest(canonical_body(e.body())?).into();
    Ok(Parsed { envelope, claimed_id, body_hash })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_body_bytes_are_pinned() {
        let v: Value = serde_json::from_str(r#"{"b":{"z":1,"a":"x"},"a":[true,null,-3],"B":"\"q\\"}"#).unwrap();
        assert_eq!(canonical_body(&v).unwrap(), br#"{"B":"\"q\\","a":[true,null,-3],"b":{"a":"x","z":1}}"#);
        for bad in [json!({"a": 1.5}), json!({"a": u64::MAX}), json!({"a": "é"}), json!({"a": "\n"}), json!({"é": 1})] {
            assert_eq!(canonical_body(&bad), Err(Code::BadEnvelope), "{bad}");
        }
    }

    #[test]
    fn spec_versions() {
        for (s, ok) in [("scaas-intent/1.2", true), ("scaas-intent/1.3", true), ("scaas-intent/1.10", true),
                        ("scaas-intent/1.1", false), ("scaas-intent/2.0", false), ("legacy-intent/1.2", false),
                        ("scaas-intent/1", false), ("scaas-intent/1.x", false)] {
            assert_eq!(spec_ok(s), ok, "{s}");
        }
    }

    fn sample() -> Value {
        json!({"spec": SPEC, "intent_id": format!("0x{}", "ab".repeat(32)), "chain_key": "sui:localnet", "family": "sui",
               "contract": "0x01", "visibility": "open", "op": {"op_kind": "pay", "payload": "0x00"},
               "hub": {"id": "11".repeat(32), "pubkey": "22".repeat(32), "published_at": 1, "sig": "33".repeat(64)},
               "hop_count": 0})
    }

    #[test]
    fn parse_round_trips_and_ignores_unknown_top_level_fields() {
        let mut v = sample();
        let p = parse(&serde_json::to_vec(&v).unwrap()).unwrap();
        assert_eq!(serde_json::to_value(&p.envelope).unwrap(), v);
        v["later"] = json!({"x": 1});
        assert_eq!(parse(&serde_json::to_vec(&v).unwrap()).unwrap().envelope, p.envelope);
    }

    #[test]
    fn every_l0_code() {
        let code = |f: &dyn Fn(&mut Value)| {
            let mut v = sample();
            f(&mut v);
            parse(&serde_json::to_vec(&v).unwrap()).err()
        };
        assert_eq!(parse(b"[1]").err(), Some(Code::BadEnvelope));
        assert_eq!(parse(&vec![b' '; MAX_BYTES + 1]).err(), Some(Code::BadEnvelope));
        assert_eq!(code(&|v| v["spec"] = json!("scaas-intent/2.0")), Some(Code::UnsupportedSpec));
        assert_eq!(code(&|v| v["spec"] = json!(12)), Some(Code::BadEnvelope));
        assert_eq!(code(&|v| v["family"] = json!("soroban")), Some(Code::FamilyNotSupported));
        assert_eq!(code(&|v| v["family"] = json!("btc")), Some(Code::FamilyNotSupported));
        assert_eq!(code(&|v| v["chain_key"] = json!("aptos:4")), Some(Code::BadEnvelope), "family != chain_key prefix");
        assert_eq!(code(&|v| v["visibility"] = json!("public")), Some(Code::BadEnvelope));
        assert_eq!(code(&|v| v["intent_id"] = json!(format!("0x{}", "AB".repeat(32)))), Some(Code::BadEnvelope));
        assert_eq!(code(&|v| v["hub"]["sig"] = json!("33".repeat(63))), Some(Code::BadEnvelope));
        assert_eq!(code(&|v| v["evm"] = json!({})), Some(Code::BadEnvelope), "two bodies");
        assert_eq!(code(&|v| v["exclusive"] = json!({"relayer_id": "zz", "until": 1})), Some(Code::BadEnvelope));
        assert_eq!(code(&|v| v["op"]["extra"] = json!("ü")), Some(Code::BadEnvelope));
        assert_eq!(code(&|v| v["hop_count"] = json!(-1)), Some(Code::BadEnvelope));
        assert_eq!(code(&|_| {}), None);
    }

    proptest::proptest! {
        #[test]
        fn parse_never_panics(b in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..600)) {
            let _ = parse(&b);
        }
    }
}
