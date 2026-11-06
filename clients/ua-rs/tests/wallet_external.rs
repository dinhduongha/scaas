// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T16: the external-key interface (spec §9.4, MD-13). A `TestExternalKey` (feature `vectors`) hands each request to
//! its "device", a closure (here: an internal key, possibly tampered with); `ua-rs` normalises the answer (low-s, `v`) and
//! verifies it against the key's `KeyRef` with its own verifier, under the request's role, before returning it
//! (`ExternalSignature` otherwise). The rows of smartcontracts/vectors/ua/sign.json go through the builders that take
//! `&dyn Signer` and equal the internal key's answers. UNAUDITED.
use scaas_ua::verify::verify;
use scaas_ua::wallet::{
    sign_digest_by, sign_key_proof_by, sign_transaction_by, sign_typed_by, ua_sig, AllowAnyTypedData, AllowRawDigest, Error, EvmTx,
    Expect, KeyRef, Network, SigRole, SignRequest, Signer, TestExternalKey, TypedData, Wallet,
};
use scaas_ua::{member_digest, purpose_tag, ua_message};
use serde_json::Value;
use std::sync::Mutex;

fn load(path: &str) -> Value {
    let path = format!("{}/../../smartcontracts/vectors/ua/{path}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array().unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}
fn n32(v: &Value) -> u32 {
    v.as_u64().unwrap() as u32
}
fn json<T>(v: &Value, f: fn(&[u8]) -> Result<T, Error>) -> T {
    f(&serde_json::to_vec(v).unwrap()).unwrap()
}
fn wallet(id: &str) -> Wallet {
    let k = load("keys.json");
    let m = arr(&k, "mnemonics").iter().find(|m| m["id"] == id).unwrap();
    Wallet::from_mnemonic(m["words"].as_str().unwrap(), m["passphrase"].as_str().unwrap()).unwrap()
}
/// An external key whose device is `inner`, its answer passed through `edit`.
fn ext<'a>(inner: &'a dyn Signer, edit: impl Fn(Vec<u8>) -> Vec<u8> + Send + Sync + 'a) -> TestExternalKey<'a> {
    TestExternalKey::new(inner.key_ref(), move |r: &SignRequest| inner.sign_request(r).map(&edit))
}
fn same(s: Vec<u8>) -> Vec<u8> {
    s
}
fn flip(mut s: Vec<u8>) -> Vec<u8> {
    s[1] ^= 1;
    s
}
/// The kinds whose release signature is deterministic.
const DETERMINISTIC: [u16; 5] = [0x0101, 0x0102, 0x0106, 0x0107, 0x0108];
const SECP_N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
const P256_N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

/// `n - s` in place of `s` (bytes 32..64); for `r ‖ s ‖ v`, `v` flipped too (27 ↔ 28) or given as `raw_v` (0 / 1).
fn high_s(n: &str, mut sig: Vec<u8>, raw_v: bool) -> Vec<u8> {
    let n = hex::decode(n).unwrap();
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = n[i] as i16 - sig[32 + i] as i16 - borrow;
        borrow = (d < 0) as i16;
        sig[32 + i] = d.rem_euclid(256) as u8;
    }
    if sig.len() == 65 {
        sig[64] = if raw_v { 28 - sig[64] } else { 55 - sig[64] };
    }
    sig
}

/// Every `sign.json` `ua` row through a `TestExternalKey` over the row's internal key: the device sees the request's role
/// (read only), the answer equals the internal key's (deterministic kinds: the row's bytes) and verifies under the row's role
/// (BLS ordinary and PoP: the post-verification uses the role, else one of the two fails); every `member` row byte-equal.
#[test]
fn sign_json_rows_through_an_external_key_equal_the_internal_ones() {
    let s = load("sign.json");
    let (mut n, mut exact) = (0, 0);
    for r in arr(&s, "ua") {
        let kind = r["kind"].as_u64().unwrap() as u16;
        let w = wallet(r["mnemonic"].as_str().unwrap());
        let key = match w.ua_key(kind, n32(&r["account"]), n32(&r["index"])) {
            Err(Error::KindUnavailable) => continue, // Falcon without its C build
            k => k.unwrap(),
        };
        let role = if r["role"] == "pop" { SigRole::Pop } else { SigRole::Authorization };
        let seen = Mutex::new(vec![]);
        let x = TestExternalKey::new(key.key_ref(), |req: &SignRequest| {
            if let SignRequest::UaMsg { role, .. } = req {
                seen.lock().unwrap().push(*role);
            }
            key.sign_request(req)
        });
        let (purpose, digest) = (b32(&r["purposeTag"]), b32(&r["digest"]));
        let got = ua_sig(&x, None, &purpose, &digest).unwrap();
        assert_eq!(*seen.lock().unwrap(), [role], "{}", r["name"]);
        let ua_msg = ua_message(kind, &purpose, &digest).unwrap();
        assert!(verify(kind, &key.key_data(), &ua_msg, &got.signature, role == SigRole::Pop), "{}", r["name"]);
        if DETERMINISTIC.contains(&kind) {
            assert_eq!(got, ua_sig(&key, None, &purpose, &digest).unwrap(), "{}", r["name"]);
            assert_eq!(hex::encode(&got.signature), hex::encode(bytes(&r["signature"])), "{}", r["name"]);
            exact += 1;
        }
        n += 1;
    }
    assert!(n >= 44 && exact == 16, "{n} rows, {exact} byte-equal");
    let member = purpose_tag("member").unwrap();
    for r in arr(&s, "member") {
        let kind = r["kind"].as_u64().unwrap() as u16;
        let w = wallet(r["mnemonic"].as_str().unwrap());
        let key = w.ua_key(kind, n32(&r["account"]), n32(&r["index"])).unwrap();
        let md = member_digest(&b32(&r["structureUa"]), &b32(&r["structureUaMsg"]));
        let got = ua_sig(&ext(&key, same), None, &member, &md).unwrap();
        assert_eq!(hex::encode(got.signature), hex::encode(bytes(&r["signature"])), "{}", r["name"]);
    }
}

/// The native rows through an external EVM key: the policy's signed rows, the generic typed rows (`Any`), every transaction
/// row; the key proof and a raw digest of an EVM and an ed25519 key: each equals the internal key's.
#[test]
fn native_rows_through_an_external_key() {
    let s = load("sign.json");
    let w = wallet("pq_kat");
    let evm = w.native_key(Network::Evm, 0, None).unwrap();
    let x = ext(&evm, same);
    let mut signed = 0;
    for r in arr(&s, "policy").iter().filter(|r| !r["refused"].is_string()) {
        let (td, e) = (json(&r["td"], TypedData::from_json), json(&r["expect"], Expect::from_json));
        assert_eq!(sign_typed_by(&x, &td, e).unwrap(), evm.sign_typed(&td, json(&r["expect"], Expect::from_json)).unwrap());
        signed += 1;
    }
    assert_eq!(signed, 10);
    for r in arr(&s["typed"], "generic") {
        let td = json(&r["td"], TypedData::from_json);
        let any = || Expect::Any(AllowAnyTypedData);
        assert_eq!(sign_typed_by(&x, &td, any()).unwrap(), evm.sign_typed(&td, any()).unwrap(), "{}", r["id"]);
    }
    for r in arr(&s["tx"], "rows") {
        assert_eq!(r["signer"]["index"], 0);
        let got = sign_transaction_by(&x, &json(&r["tx"], EvmTx::from_json)).unwrap();
        assert_eq!(format!("0x{}", hex::encode(got.raw)), r["raw"].as_str().unwrap());
    }
    let sui = w.native_key(Network::Sui, 0, None).unwrap();
    for k in [&evm as &dyn Signer, &sui] {
        let x = ext(k, same);
        assert_eq!(sign_key_proof_by(&x, b"challenge").unwrap(), sign_key_proof_by(k, b"challenge").unwrap());
        assert_eq!(sign_digest_by(&x, &[7; 32], AllowRawDigest).unwrap(), sign_digest_by(k, &[7; 32], AllowRawDigest).unwrap());
    }
}

/// A `0x0100` passkey: the device answers the `WebAuthn` request with the row's assertion, verified against the challenge.
#[test]
fn webauthn_rows_through_an_external_passkey() {
    let s = load("sign.json");
    let mut n = 0;
    for r in arr(&s["webauthn"], "accepted") {
        let assertion = bytes(&r["assertion"]);
        let (challenge, answer) = (b32(&r["expectedChallenge"]), assertion.clone());
        let x = TestExternalKey::new(KeyRef::Ua { kind: 0x0100, key_data: bytes(&r["keyData"]) }, move |req: &SignRequest| match req {
            SignRequest::WebAuthn { challenge: c, .. } if *c == challenge => Ok(answer.clone()),
            _ => Err(Error::Argument),
        });
        let got = ua_sig(&x, None, &b32(&r["purposeTag"]), &b32(&r["digest"])).unwrap();
        assert_eq!(got.signature, assertion);
        let bad = TestExternalKey::new(x.key_ref(), move |_: &SignRequest| Ok(flip(assertion.clone())));
        assert_eq!(ua_sig(&bad, None, &b32(&r["purposeTag"]), &b32(&r["digest"])).err(), Some(Error::ExternalSignature));
        n += 1;
    }
    assert_eq!(n, 4);
}

/// A device answer that does not verify: one bit flipped, or another key's signature, per signing scheme (positive control
/// first, one change each): `ExternalSignature`, nothing returned.
#[test]
#[allow(non_snake_case)]
fn a_bad_external_signature_is_ExternalSignature() {
    let w = wallet("pq_kat");
    let (purpose, digest) = (purpose_tag("metatx").unwrap(), [5u8; 32]);
    for kind in [0x0101u16, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0130, 0x0131, 0x0133] {
        let key = w.ua_key(kind, 0, 0).unwrap();
        assert!(ua_sig(&ext(&key, same), None, &purpose, &digest).is_ok(), "{kind:#06x}");
        assert_eq!(ua_sig(&ext(&key, flip), None, &purpose, &digest).err(), Some(Error::ExternalSignature), "{kind:#06x}");
        let other = w.ua_key(kind, 1, 0).unwrap();
        let x = TestExternalKey::new(key.key_ref(), |r: &SignRequest| {
            let SignRequest::UaMsg { .. } = r else { return Err(Error::Argument) };
            ua_sig(&other, None, &purpose, &digest).map(|s| s.signature)
        });
        assert_eq!(ua_sig(&x, None, &purpose, &digest).err(), Some(Error::ExternalSignature), "{kind:#06x}: another key");
    }
    let td = json(&arr(&load("sign.json")["typed"], "generic")[0]["td"], TypedData::from_json);
    let evm = w.native_key(Network::Evm, 0, None).unwrap();
    let any = || Expect::Any(AllowAnyTypedData);
    assert!(sign_typed_by(&ext(&evm, same), &td, any()).is_ok());
    assert_eq!(sign_typed_by(&ext(&evm, flip), &td, any()).err(), Some(Error::ExternalSignature));
    let evm1 = w.native_key(Network::Evm, 1, None).unwrap();
    let x = TestExternalKey::new(evm.key_ref(), |r: &SignRequest| evm1.sign_request(r));
    assert_eq!(sign_typed_by(&x, &td, any()).err(), Some(Error::ExternalSignature), "another EVM key");
    let sui = w.native_key(Network::Sui, 0, None).unwrap();
    assert!(sign_key_proof_by(&ext(&sui, same), b"c").is_ok());
    assert_eq!(sign_key_proof_by(&ext(&sui, flip), b"c").err(), Some(Error::ExternalSignature));
}

/// A device's high-s answer (P-256 `r ‖ s`; secp256k1 `r ‖ s ‖ v` with `v` flipped, or as 0 / 1) is normalised to the
/// internal key's low-s signature with `v` ∈ {27, 28}.
#[test]
fn high_s_from_device_normalised() {
    let w = wallet("pq_kat");
    let (purpose, digest) = (purpose_tag("metatx").unwrap(), [9u8; 32]);
    for (kind, n) in [(0x0101u16, P256_N), (0x0108, SECP_N)] {
        let key = w.ua_key(kind, 0, 0).unwrap();
        let want = ua_sig(&key, None, &purpose, &digest).unwrap();
        let high = ua_sig(&ext(&key, move |s| high_s(n, s, false)), None, &purpose, &digest).unwrap();
        assert_eq!(high, want, "{kind:#06x}");
    }
    let evm = w.native_key(Network::Evm, 0, None).unwrap();
    let td = json(&arr(&load("sign.json")["typed"], "generic")[0]["td"], TypedData::from_json);
    let any = || Expect::Any(AllowAnyTypedData);
    let want = evm.sign_typed(&td, any()).unwrap();
    assert!(want[64] == 27 || want[64] == 28);
    assert_eq!(sign_typed_by(&ext(&evm, |s| high_s(SECP_N, s, false)), &td, any()).unwrap(), want);
    assert_eq!(sign_typed_by(&ext(&evm, |s| high_s(SECP_N, s, true)), &td, any()).unwrap(), want, "v as a recovery id");
    let raw_v = |mut s: Vec<u8>| {
        s[64] -= 27;
        s
    };
    assert_eq!(sign_typed_by(&ext(&evm, raw_v), &td, any()).unwrap(), want, "low s, v as 0 / 1");
}
