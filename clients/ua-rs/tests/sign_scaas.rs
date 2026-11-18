// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! scaas-sdk T10 (spec §13.2): `sign_scaas`, the one call that signs a typed SCaaS struct for its entry under the check of what
//! the user confirmed: a native EVM key's `UASig{"", r‖s‖v over the digest, []}` (the `typed_ops.json` row's signature), a UA
//! key's `UASig` over `uaMessage(kind, purpose, digest)` with the entry's purpose (`metatx`, `payee-fee`, `trade`); anything the
//! check refuses signs nothing. UNAUDITED.
use scaas_ua::wallet::{scaas_typed_data, sign_scaas, ua_sig, Error, Expect, NativeKey, Network, Signer, Wallet};
use scaas_ua::purpose_tag;
use scaas_ua::ua8::UASig;
use serde_json::Value;

fn ops() -> Value {
    let p = format!("{}/../../smartcontracts/vectors/typed/typed_ops.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn hexb(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

struct Row {
    contract: [u8; 20],
    chain_id: u64,
    uid: [u8; 32],
    message: Value,
    digest: Vec<u8>,
    signature: Vec<u8>,
}
fn row(name: &str, kind: &str) -> Row {
    let o = &ops()["ops"][name];
    let d = &o["domains"][kind];
    Row {
        contract: hexb(&d["domain"]["verifyingContract"]).try_into().unwrap(),
        chain_id: d["domain"]["chainId"].as_str().unwrap().parse().unwrap(),
        uid: hexb(&d["domain"]["salt"]).try_into().unwrap(),
        message: o["message"].clone(),
        digest: hexb(&d["digest"]),
        signature: hexb(&d["signature"]),
    }
}
fn op(r: &Row, name: &str, message: &Value) -> Expect {
    Expect::Op {
        op: name.into(),
        contract: r.contract,
        chain_id: r.chain_id,
        chain_uid: r.uid,
        message: message.clone(),
        max_fee: "1000000000000000000000".into(),
        fee_recipient: None,
        relayer: None,
        now: 1,
        max_window: u64::MAX / 2,
    }
}
const WORDS: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
/// The wallet stays alive beside its key (a dropped wallet revokes its handles).
fn native() -> (Wallet, NativeKey) {
    let w = Wallet::from_mnemonic(WORDS, "").unwrap();
    let k = w.native_key(Network::Evm, 0, None).unwrap();
    (w, k)
}

#[test]
fn native_key_signs_the_rows_digest() {
    let r = row("UACancelNonce", "token");
    let td = scaas_typed_data("UACancelNonce", Some("SCaaS MetaToken"), &r.contract, r.chain_id, &r.uid, &r.message).unwrap();
    assert_eq!(td.digest().unwrap().to_vec(), r.digest);
    let (_w, n) = native();
    let s = sign_scaas(&n, &td, op(&r, "UACancelNonce", &r.message)).unwrap();
    let want = n.sign_typed(&td, op(&r, "UACancelNonce", &r.message)).unwrap();
    assert_eq!(s, UASig { key_data: vec![], signature: want, members: vec![] }, "r || s || v over the row's digest, no key data");
    assert_eq!(r.signature.len(), s.signature.len());
    // a check of another value refuses: nothing signed
    let mut other = r.message.clone();
    other["lane"] = "8".into();
    assert_eq!(sign_scaas(&n, &td, op(&r, "UACancelNonce", &other)).unwrap_err(), Error::PolicyRefused);
}

#[test]
fn ua_key_signs_under_the_entrys_purpose() {
    let w = Wallet::from_mnemonic(WORDS, "").unwrap();
    let key = w.ua_key(0x0101, 0, 0).unwrap(); // p256: RFC 6979, one signature per message
    for (name, purpose) in [("UACancelNonce", "metatx"), ("UAPayeeFee", "payee-fee"), ("CancelUAOrder", "trade")] {
        let r = row(name, "token");
        let td = scaas_typed_data(name, Some("SCaaS MetaToken"), &r.contract, r.chain_id, &r.uid, &r.message).unwrap();
        let want = ua_sig(&key, None, &purpose_tag(purpose).unwrap(), &td.digest().unwrap()).unwrap();
        assert_eq!(sign_scaas(&key, &td, op(&r, name, &r.message)).unwrap(), want, "{name}: {purpose}");
        assert_eq!(key.key_ref(), scaas_ua::wallet::KeyRef::Ua { kind: 0x0101, key_data: want.key_data.clone() });
    }
    let r = row("UACancelNonce", "token");
    let td = scaas_typed_data("UACancelNonce", Some("SCaaS MetaToken"), &r.contract, r.chain_id, &r.uid, &r.message).unwrap();
    let mut other = r.message.clone();
    other["fee"] = "1".into();
    assert_eq!(sign_scaas(&key, &td, op(&r, "UACancelNonce", &other)).unwrap_err(), Error::PolicyRefused);
}
