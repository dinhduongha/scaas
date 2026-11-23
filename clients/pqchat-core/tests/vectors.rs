// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T3 (CLI-PQC-11): the rows of `smartcontracts/vectors/pqchat/` that cross the SDK boundary, produced or checked through
//! the crate's own code and the SDK's surface (its vectors build: key import, fixed randomness): the Matrix event (its padded
//! base64 exactly), the payload, the envelope and its record, the message content, its id, the wrap hashes, the P14 refusals
//! by the crate's name, `sealedInfo`, the hint, a message sealed with the crate's `parents`, V1 over the record and topic
//! rows; and every unbound field non-zero in some row. The crate reads the vectors and writes none.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#[path = "../../scaas-sdk/tests/common/fake_chain.rs"]
mod fake_chain;

use fake_chain::{fake, keccak_hex, serve, Fake};
use pqchat_core::{matrix, order, DropReason, PqChatError};
use scaas_sdk::app_core::{AppCore, AppKeyUsage, AppUaSig};
use scaas_sdk::op::KeyRef;
use scaas_sdk::pqchat_keys::PqMessageHeader;
use scaas_sdk::pqchat_records::{PqChatMessage, PqWrap};
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, Sdk, SdkConfig,
    SecretBytes,
};
use serde_json::Value;
use std::sync::Arc;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const REGISTRY: &str = "0x5ca00000000000000000000000000000000000a1";
const ZERO: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

fn pq(f: &str) -> Value {
    let p = format!(
        "{}/../../smartcontracts/vectors/pqchat/{f}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn s(v: &Value) -> String {
    v.as_str().unwrap().to_string()
}
fn unhex(v: &Value) -> Vec<u8> {
    let h = v.as_str().unwrap().trim_start_matches("0x");
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}
fn a32(v: &Value) -> [u8; 32] {
    unhex(v).try_into().unwrap()
}
fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn w(n: u64) -> String {
    format!("{n:064x}")
}
fn pad(b: &[u8]) -> String {
    let mut s = hexs(b);
    while !s.len().is_multiple_of(64) {
        s.push('0');
    }
    s
}

/// One live PqChat scope at a time (the SDK refuses a second scope of the same label prefix, `AppLabelRefused`).
static ONE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn app() -> (Arc<AppCore>, String, Fake) {
    let chain = fake();
    let url = serve(chain.clone()).await;
    let genesis = chain.lock().unwrap().genesis.clone();
    let profile = ChainProfile {
        key: "local".into(),
        family: Family::Evm,
        chain_id: Some(31337),
        chain_uid: genesis,
        rpc: vec![EndpointConfig {
            url,
            class: scaas_rpc::Class::Named,
            label: None,
            auth: None,
        }],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: Some(REGISTRY.into()),
        factory: None,
        router: None,
        finality: Finality::Finalized,
        tx_gas_cap: None,
        gas: Default::default(),
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![],
        wrappers: vec![],
        tokens: vec![],
        l1_fee: None,
        pinned_reads: true,
        disabled_kinds: vec![],
        family_params: None,
    };
    let sdk = Sdk::open(SdkConfig {
        profiles: vec![profile],
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
        clock: None,
        gas_tables: vec![],
    })
    .await
    .unwrap();
    let sec = |x: &str| {
        Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(x.as_bytes().to_vec())).unwrap())
    };
    let seed = sdk
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words: sec(REPO),
            vault_passphrase: sec(PASS),
        })
        .await
        .unwrap()
        .id;
    (pqchat_core::scope(&sdk).unwrap(), seed, chain)
}

fn record_of(r: &Value) -> PqChatMessage {
    PqChatMessage {
        session_id: s(&r["sessionId"]),
        epoch_id: s(&r["epochId"]),
        sender: s(&r["sender"]),
        device: s(&r["device"]),
        counter: r["counter"].as_u64().unwrap(),
        parents: r["parents"].as_array().unwrap().iter().map(s).collect(),
        ciphertext: unhex(&r["ciphertext"]),
    }
}

/// The Matrix event, both ways: the crate writes the `matrixEvent` row's content exactly from the payload row's hint and
/// envelope, reads it back, and drops another form of the same bytes (`decode`).
#[test]
fn matrix_event_row() {
    let m = pq("messages");
    let (hint, env) = (unhex(&m["payload"]["hint"]), unhex(&m["payload"]["env"]));
    assert_eq!(m["matrixEvent"]["type"], matrix::EVENT_TYPE);
    let ev = matrix::event(&hint, &env);
    assert_eq!(ev, m["matrixEvent"]["content"]);
    assert_eq!(ev["hint"], m["matrixEvent"]["content"]["hint"]);
    assert_eq!(ev["env"], m["matrixEvent"]["content"]["env"]);
    let text = serde_json::to_vec(&m["matrixEvent"]["content"]).unwrap();
    let (h, e) = matrix::parse(&text).unwrap();
    assert_eq!((h.to_vec(), e.clone()), (hint.clone(), env.clone()));
    // the same bytes unpadded: dropped
    let unpadded =
        serde_json::json!({"v": 1, "hint": s(&ev["hint"]).trim_end_matches('='), "env": ev["env"]});
    assert_eq!(
        matrix::parse(&serde_json::to_vec(&unpadded).unwrap()),
        Err(DropReason::Decode)
    );
}

/// The message rows through the SDK: the payload decoded, its envelope opened to the record row, the content row opened at
/// the sender's position, the record's id and V1 over it; the hint of `K`.
#[tokio::test(flavor = "multi_thread")]
async fn message_rows() {
    let _one = ONE.lock().await;
    let (a, seed, chain) = app().await;
    let (m, rec) = (pq("messages"), pq("records"));
    let r = &rec["message"]["record"];
    let k = a
        .vectors_import(&seed, a32(&m["message"]["K"]), AppKeyUsage::Derive)
        .unwrap();
    assert_eq!(
        a.pqchat_hint(k.clone()).unwrap(),
        unhex(&m["envelope"]["hint"])
    );
    let p = a
        .pqchat_decode_payload(unhex(&m["payload"]["payload"]))
        .unwrap();
    assert_eq!(
        (p.hint.clone(), p.env.clone()),
        (unhex(&m["payload"]["hint"]), unhex(&m["payload"]["env"]))
    );
    assert_eq!(p.env, unhex(&m["envelope"]["env"]));
    let inner = a
        .pqchat_open_envelope(k.clone(), s(&r["sessionId"]), s(&r["epochId"]), p.env)
        .unwrap();
    assert_eq!(inner.record, record_of(r));
    assert_eq!(inner.record.ciphertext, unhex(&m["message"]["ciphertext"]));
    assert_eq!(
        a.pqchat_message_id(inner.record.clone()).unwrap(),
        s(&rec["message"]["id"])
    );
    let p0 = a
        .pqchat_chain(
            k.clone(),
            s(&r["sessionId"]),
            s(&r["epochId"]),
            s(&r["sender"]),
            s(&r["device"]),
        )
        .unwrap();
    let at = a
        .pqchat_advance(p0, r["counter"].as_u64().unwrap())
        .unwrap();
    let pt = a.pqchat_open_message(at, inner.record.clone()).unwrap();
    assert_eq!(
        pt.with(|b| b.to_vec()),
        s(&m["message"]["content"]).as_bytes()
    );
    // V1 over the record row: its signer registered on the fake registry
    let signers = rec["signers"].as_array().unwrap();
    for x in signers {
        let kd = unhex(&x["publicKey"]);
        let out = format!(
            "{}{}{}{}{}{}{}",
            w(x["kind"].as_u64().unwrap()),
            w(0xa0),
            w(0),
            w(0),
            w(0),
            w(kd.len() as u64),
            pad(&kd)
        );
        let prefix = format!(
            "{}{}",
            &keccak_hex(b"registrationOf(bytes32)")[..10],
            hexs(&unhex(&x["ua"]))
        );
        chain
            .lock()
            .unwrap()
            .answers
            .push((REGISTRY.into(), prefix, format!("0x{out}")));
    }
    let v1 = |name: &str, row: &Value| {
        let who = signers.iter().find(|x| x["name"] == row["signer"]).unwrap();
        let sig = AppUaSig {
            key_data: unhex(&row["uaSig"]["keyData"]),
            signature: unhex(&row["uaSig"]["signature"]),
            members: vec![],
        };
        a.verify_pqchat_record(
            "local".into(),
            s(&who["ua"]),
            name.into(),
            row["record"].to_string(),
            sig,
        )
    };
    assert!(v1("PqChatMessage", &rec["message"]).await.unwrap());
    // CTR-CHAT-23: the control-plane rows are signed, as an `sstore2` home keeps them (CLI-PQC-15)
    for (name, row) in [
        ("PqChatSession", "session"),
        ("PqChatEpoch", "epoch"),
        ("PqChatEpoch", "epochDevices"), // owner (M) 2026-11-23: a member with two keys
        ("PqChatLeave", "leave"),
        ("PqChatRemove", "remove"),
    ] {
        assert!(v1(name, &rec[row]).await.unwrap(), "{row}");
    }
    let t = pq("topics");
    for (name, row) in [
        ("PqTopic", "topic"),
        ("PqTopicUpdate", "update"),
        ("PqTopicWriter", "writer"),
        ("PqTopicEntry", "post"),
        ("PqTopicEntry", "reply"),
        ("PqTopicEdit", "edit"),
        ("PqTopicVote", "vote"),
    ] {
        assert!(v1(name, &t[row]).await.unwrap(), "{row}");
    }
    drop(seed);
}

/// The wraps: every row's `hashStruct` through V2's wrap hash; every P14 row refused by the crate's name (`KemKeyInvalid`).
#[tokio::test(flavor = "multi_thread")]
async fn wrap_and_p14_rows() {
    let _one = ONE.lock().await;
    let (a, seed, _c) = app().await;
    let keys = pq("keys");
    for x in keys["wraps"].as_array().unwrap() {
        let wr = PqWrap {
            member: s(&x["wrap"]["member"]),
            key_id: x["wrap"]["keyId"].as_u64().unwrap(),
            mlkem_ct: unhex(&x["wrap"]["mlkemCt"]),
            x25519_eph: s(&x["wrap"]["x25519Eph"]),
            sealed_key: unhex(&x["wrap"]["sealedKey"]),
        };
        assert_eq!(
            a.pqchat_wrap_hash(wr).unwrap(),
            s(&x["hashStruct"]),
            "{}",
            x["name"]
        );
    }
    let k = a.pqchat_epoch_key(&seed).unwrap();
    let mut refused = 0;
    for r in keys["p14"]["rows"].as_array().unwrap() {
        let got = a.pqchat_vectors_wrap(
            k.clone(),
            format!("0x{}", "01".repeat(32)),
            format!("0x{}", "02".repeat(32)),
            format!("0x{}", "03".repeat(32)),
            1,
            unhex(&r["kemPk"]),
            [7; 32],
            [9; 32],
        );
        if r.get("error").is_some() {
            assert_eq!(
                PqChatError::from(got.unwrap_err()).code(),
                "KemKeyInvalid",
                "{}",
                r["name"]
            );
            refused += 1;
        } else {
            assert!(got.is_ok(), "{}", r["name"]);
        }
    }
    assert!(refused > 0);
}

/// `sealedInfo`: every row opens under its `K` to its canonical JSON.
#[tokio::test(flavor = "multi_thread")]
async fn sealed_info_rows() {
    let _one = ONE.lock().await;
    let (a, seed, _c) = app().await;
    let m = pq("messages");
    for r in m["sealedInfo"].as_array().unwrap() {
        let k = a
            .vectors_import(&seed, a32(&r["K"]), AppKeyUsage::Derive)
            .unwrap();
        let pt = a
            .pqchat_open_info(
                k,
                s(&r["sessionId"]),
                s(&r["epochId"]),
                unhex(&r["sealedInfo"]),
            )
            .unwrap();
        assert_eq!(
            pt.with(|b| b.to_vec()),
            s(&r["json"]).as_bytes(),
            "{}",
            r["name"]
        );
    }
}

/// A message sealed with the crate's `parents` (given out of order): the record carries them sorted, as the row does.
#[tokio::test(flavor = "multi_thread")]
async fn parents_sorted_into_s5() {
    let _one = ONE.lock().await;
    let (a, seed, _c) = app().await;
    let r = &pq("records")["message"]["record"];
    let want: Vec<String> = r["parents"].as_array().unwrap().iter().map(s).collect();
    assert!(want.len() >= 2);
    let mut given = want.clone();
    given.reverse();
    let k = a.pqchat_epoch_key(&seed).unwrap();
    let me = KeyRef::Ua {
        seed: seed.clone(),
        kind: 0x0131,
        account: 0,
        index: 0,
    };
    let ua = scaas_ua::wallet::Wallet::from_mnemonic(REPO, "")
        .unwrap()
        .ua_key(0x0131, 0, 0)
        .unwrap()
        .ua()
        .unwrap();
    let ua = format!("0x{}", hexs(&ua));
    let pos = a
        .pqchat_chain(
            k.clone(),
            s(&r["sessionId"]),
            s(&r["epochId"]),
            ua,
            s(&r["device"]),
        )
        .unwrap();
    let h = PqMessageHeader {
        session_id: s(&r["sessionId"]),
        epoch_id: s(&r["epochId"]),
        device: s(&r["device"]),
        counter: 0,
        parents: order::parents(&given).unwrap(),
    };
    let sealed = a
        .pqchat_seal_message(me, k, pos, h, r#"{"body":"x","type":"text"}"#.into())
        .await
        .unwrap();
    assert_eq!(sealed.record.parents, want);
}

/// Every unbound field is non-zero in some row (`via`, `device`, `parents`, `ref`): asserted on the rows themselves.
#[test]
fn unbound_fields_non_zero() {
    let rec = pq("records");
    let vias: Vec<String> = ["session", "epoch"]
        .iter()
        .flat_map(|r| {
            rec[*r]["record"]["members"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| s(&m["via"]))
        })
        .collect();
    assert!(vias.iter().any(|v| v != ZERO), "{vias:?}");
    let m = &rec["message"]["record"];
    assert_ne!(s(&m["device"]), format!("0x{}", "00".repeat(16)));
    assert!(m["parents"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| s(p) != ZERO));
    let t = pq("topics");
    let refs: Vec<&Value> = ["post", "reply"]
        .iter()
        .map(|r| &t[*r]["record"]["ref"])
        .collect();
    assert!(
        refs.iter()
            .any(|r| s(&r["entryId"]) != ZERO && s(&r["chainUid"]) != ZERO),
        "{refs:?}"
    );
}

/// Plan T10b: the `fileMessage` row through the crate's surface: its ciphertext opens to its content at the sender's
/// position, the crate reads the row's public fields (no key) as a `file`, and the SDK opens the row's object named by it
/// (the object by `scaas-ua`'s vectors seal under the row's file key); every `fileOpenRefused` row by its code; each
/// `fileContentRefused` content is no `file` to the crate or the SDK.
#[tokio::test(flavor = "multi_thread")]
async fn file_rows() {
    use pqchat_core::content::Content;
    let _one = ONE.lock().await;
    let (a, seed, _chain) = app().await;
    let m = pq("messages");
    let f = &m["fileMessage"];
    let r = &f["record"];
    let k = a
        .vectors_import(&seed, a32(&f["K"]), AppKeyUsage::Derive)
        .unwrap();
    let p0 = a
        .pqchat_chain(
            k,
            s(&r["sessionId"]),
            s(&r["epochId"]),
            s(&r["sender"]),
            s(&r["device"]),
        )
        .unwrap();
    let at = a
        .pqchat_advance(p0, r["counter"].as_u64().unwrap())
        .unwrap();
    let content = Arc::new(a.pqchat_open_message(at, record_of(r)).unwrap());
    assert_eq!(content.with(|b| b.to_vec()), s(&f["content"]).as_bytes());
    match content.with(Content::parse).content {
        Content::File {
            size,
            url,
            ct_sha256,
            ..
        } => {
            assert_eq!(size, f["size"].as_u64().unwrap());
            assert_eq!(url, s(&f["url"]));
            assert_eq!(ct_sha256, s(&f["ctSha256"]));
        }
        c => panic!("not a file: {c:?}"),
    }
    let w = scaas_ua::wallet::Wallet::from_mnemonic(REPO, "").unwrap();
    let uk = w.app_keys();
    let fk = uk
        .vectors_import(&a32(&f["fileKey"]), scaas_ua::wallet::KeyUsage::File)
        .unwrap();
    let object = uk.vectors_seal_file(fk, &unhex(&f["file"])).unwrap().object;
    let sec = |b: Vec<u8>| Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(b)).unwrap());
    for x in m["fileOpenRefused"].as_array().unwrap() {
        let mut o = object.clone();
        match x["change"].as_str() {
            Some("drop-last") => drop(o.pop()),
            Some("append-zero") => o.push(0),
            Some("flip-1000") => o[1000] ^= 1,
            _ => {}
        }
        let c = match x.get("content") {
            Some(v) => sec(scaas_ua::wallet::pqchat_keys::canonical_json(v)
                .unwrap()
                .into_bytes()),
            None => content.clone(),
        };
        let got = a.pqchat_open_file(c, o);
        match x["code"].as_str() {
            None => assert_eq!(got.unwrap().with(|b| b.to_vec()), unhex(&f["file"])),
            Some(want) => assert_eq!(got.err().unwrap().code(), want, "{}", x["name"]),
        }
    }
    for x in m["fileContentRefused"].as_array().unwrap() {
        let c = scaas_ua::wallet::pqchat_keys::canonical_json(&x["content"]).unwrap();
        // the crate shows it as no file only when its public fields fail; the SDK refuses every row
        assert_eq!(
            a.pqchat_open_file(sec(c.into_bytes()), object.clone())
                .err()
                .map(|e| e.code()),
            Some("PqChatContent"),
            "{}",
            x["name"]
        );
    }
    drop(seed);
}
