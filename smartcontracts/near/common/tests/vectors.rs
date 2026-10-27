//! Task 5 unit vectors (spec §2 row 1, §3.3, §3.5): `near-vectors.json` (gen_vectors.py) and `kinds.json`.
use near_sdk::serde_json::{self, Value};
use near_sdk::AccountId;
use scaas_near_common::auth::{self, Auth};
use scaas_near_common::hash::nep413_hash;
use scaas_near_common::metaop::MetaOp;
use scaas_near_common::ua::{self, KeyRecord};
use scaas_near_common::Holder;

const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/near-vectors.json");
const KINDS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/ua/kinds.json");

fn load(p: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn hx(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap().trim_start_matches("0x");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn b32(v: &Value) -> [u8; 32] {
    hx(v).try_into().unwrap()
}

fn holder(v: &Value) -> Holder {
    match v.get("Near") {
        Some(a) => Holder::Near(a.as_str().unwrap().parse().unwrap()),
        None => Holder::Ua(b32(&v["Ua"])),
    }
}

fn metaop(f: &Value) -> MetaOp {
    MetaOp {
        network: b32(&f["network"]),
        contract: f["contract"].as_str().unwrap().parse().unwrap(),
        op: f["op"].as_u64().unwrap() as u8,
        from: holder(&f["from"]),
        to: holder(&f["to"]),
        relayer: f["relayer"].as_str().map(|r| r.parse().unwrap()),
        amount: f["amount"].as_str().unwrap().parse().unwrap(),
        pay_ref: b32(&f["pay_ref"]),
        lane: b32(&f["lane"]),
        nonce: f["nonce"].as_u64().unwrap(),
        valid_until: f["valid_until"].as_u64().unwrap(),
        extra: b32(&f["extra"]),
    }
}

fn auth(a: &Value) -> Auth {
    match a["kind"].as_str().unwrap() {
        "ed25519" => Auth::Ed25519 { key: b32(&a["key"]), sig: hx(&a["sig"]).try_into().unwrap() },
        "secp256k1" => Auth::Secp256k1 {
            key: hx(&a["key"]).try_into().unwrap(),
            sig: hx(&a["sig"]).try_into().unwrap(),
            v: a["v"].as_u64().unwrap() as u8,
        },
        "passkey" => Auth::Passkey {
            key: hx(&a["key"]).try_into().unwrap(),
            authenticator_data: hx(&a["authenticatorData"]),
            client_data_json: a["clientDataJSON"].as_str().unwrap().as_bytes().to_vec(),
            sig: hx(&a["sig"]).try_into().unwrap(),
        },
        "msig" => Auth::Msig {
            key_data: hx(&a["keyData"]),
            sigs: a["sigs"].as_array().unwrap().iter().map(|s| (s["index"].as_u64().unwrap() as u8, auth(&s["auth"]))).collect(),
        },
        k => panic!("kind {k}"),
    }
}

/// Every op row: the Borsh encoding and digest, the bound parameters, and its signature through `auth::verify` (the
/// passkey origin as listed; the msig row's near-account member as the predecessor).
#[test]
fn metaop_vectors_match() {
    let d = load(VECTORS);
    let token: AccountId = d["accounts"]["token"].as_str().unwrap().parse().unwrap();
    let rows = d["metaops"]["vectors"].as_array().unwrap();
    assert!(rows.iter().filter(|r| r.get("params").is_some()).count() >= 9, "key-op rows missing");
    for r in rows {
        let op = metaop(&r["fields"]);
        assert_eq!(op.encode(), hx(&r["encoding"]), "{}", r["name"]);
        assert_eq!(op.digest().to_vec(), hx(&r["digest"]), "{}", r["name"]);
        if let Some(p) = r.get("params") {
            assert_eq!(op.extra, near_sdk::env::sha256_array(hx(p)), "{}", r["name"]);
        }
        let a = auth(&r["auth"]);
        let pred: AccountId = d["msig"]["predecessor"].as_str().unwrap().parse().unwrap();
        let origins = [r["auth"]["origin"].as_str().unwrap_or("").to_string()];
        assert!(auth::verify(&a, &op.digest(), &token, &pred, Some(&origins)).is_ok(), "{}", r["name"]);
        // lazily opened (no origin list): the assertion's own origin comes back
        let seen = auth::verify(&a, &op.digest(), &token, &pred, None).unwrap();
        assert_eq!(seen.is_empty(), r["auth"]["kind"] != "passkey", "{}", r["name"]);
        // the signer's key derives the UA the op is from, when it is a UA (lazy open)
        if let Holder::Ua(id) = op.from {
            if r["name"] != "start_recovery" {
                assert_eq!(a.key().unwrap().id(), id, "{}", r["name"]);
            }
        }
        // another digest fails
        let mut other = op.digest();
        other[0] ^= 1;
        assert!(auth::verify(&a, &other, &token, &pred, Some(&origins)).is_err(), "{}", r["name"]);
    }
}

#[test]
fn nep413_vectors_match() {
    let d = load(VECTORS);
    let s = &d["signing"];
    let token: AccountId = s["recipient"].as_str().unwrap().parse().unwrap();
    assert_eq!(s["tag"].as_u64().unwrap(), 2_147_484_061);
    let digest = b32(&s["nonce"]);
    assert_eq!(nep413_hash(&digest, &token).to_vec(), hx(&s["hash"]));
    assert_eq!(scaas_near_common::hash::signed_text(&digest), s["message"].as_str().unwrap());
    let mut n = 0;
    for r in d["metaops"]["vectors"].as_array().unwrap() {
        let a = &r["auth"];
        if a["kind"] == "ed25519" {
            assert_eq!(nep413_hash(&b32(&r["digest"]), &token).to_vec(), hx(&a["nep413Hash"]), "{}", r["name"]);
            n += 1;
        }
    }
    assert!(n > 5);
    // the secp256k1 high-s form is refused (ecrecover malleability flag)
    let k = &d["secp256k1"];
    let high = Auth::Secp256k1 {
        key: hx(&k["key"]).try_into().unwrap(),
        sig: hx(&k["highS"]["sig"]).try_into().unwrap(),
        v: k["highS"]["v"].as_u64().unwrap() as u8,
    };
    assert!(auth::verify(&high, &b32(&k["digest"]), &token, &token, Some(&[])).is_err());
}

#[test]
fn ua_of_matches_kinds_json_valid_rows() {
    let k = load(KINDS);
    let mut n = 0;
    for r in k["valid"].as_array().unwrap() {
        let kind = r["kind"].as_u64().unwrap() as u16;
        if [ua::KIND_WEBAUTHN_P256, ua::KIND_ED25519, ua::KIND_SECP256K1, ua::KIND_MSIG].contains(&kind) {
            assert_eq!(ua::ua_of(kind, &hx(&r["keyData"])).to_vec(), hx(&r["ua"]), "{r}");
            n += 1;
        }
    }
    assert!(n >= 10);
    // every invalid msig row of kinds.json is refused on NEAR too
    for r in k["invalid"].as_array().unwrap() {
        if r["kind"] == 0x0120 {
            assert!(KeyRecord { kind: ua::KIND_MSIG, key_data: hx(&r["keyData"]) }.validate().is_err(), "{r}");
        }
    }
    // the NEAR msig vector: id, members, threshold
    let d = load(VECTORS);
    let m = ua::parse_msig(&hx(&d["msig"]["keyData"])).unwrap();
    assert_eq!(ua::ua_of(ua::KIND_MSIG, &hx(&d["msig"]["keyData"])).to_vec(), hx(&d["msig"]["ua"]));
    assert_eq!(m.threshold, 2);
    let alice: AccountId = d["msig"]["predecessor"].as_str().unwrap().parse().unwrap();
    assert!(m.members.iter().any(|x| x.kind == ua::KIND_NEAR_ACCOUNT && x.id == ua::native_id(&alice)));
    // member cap
    let one = |id: u8| [&[0x01, 0x02][..], &[id; 32], &[0, 1]].concat();
    let cap = |n: u8| [&[0, 1, 0, n][..], &(1..=n).flat_map(one).collect::<Vec<_>>()].concat();
    assert!(ua::parse_msig(&cap(ua::MSIG_MAX_MEMBERS as u8)).is_ok());
    assert!(ua::parse_msig(&cap(ua::MSIG_MAX_MEMBERS as u8 + 1)).is_err());
}

#[test]
fn native_id_forms() {
    let d = load(VECTORS);
    let n = &d["nativeIds"];
    let forms: Vec<&str> = n["rows"].as_array().unwrap().iter().map(|r| r["form"].as_str().unwrap()).collect();
    assert!(forms.contains(&"implicit") && forms.contains(&"sha256"));
    for r in n["rows"].as_array().unwrap() {
        let a: AccountId = r["accountId"].as_str().unwrap().parse().unwrap();
        assert_eq!(ua::native_id(&a).to_vec(), hx(&r["id"]), "{r}");
        let raw = a.as_str().len() == 64;
        assert_eq!(r["form"] == "implicit", raw, "{r}");
        if !raw {
            assert_eq!(ua::native_id(&a), near_sdk::env::sha256_array(a.as_bytes()));
        }
    }
    assert!(n["rows"].as_array().unwrap().iter().any(|r| r["accountId"].as_str().unwrap().starts_with("0x")), "ETH-implicit row");
    for r in n["invalid"].as_array().unwrap() {
        assert!(r["accountId"].as_str().unwrap().parse::<AccountId>().is_err(), "{r}");
    }
}
