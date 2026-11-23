// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T21 part 5 (spec §12.5, review r2 R8): the `pqchat-records` entries reproduce `smartcontracts/vectors/pqchat/`: each
//! signed `PqChat` struct's typed digest and id from its named fields, a session's and an epoch's `wrapHashes` computed from
//! its `Wrap` objects (keys.json), the review of every field, a UA key's signature verifying over `uaMessage(kind,
//! PURPOSE_PQCHAT, typed)`; the feature's bit.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]
use scaas_sdk::app_core::{AppCore, AppDesc};
use scaas_sdk::op::KeyRef;
use scaas_sdk::pqchat_records::*;
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::{Limits, RuntimeChoice, Sdk, SdkConfig};
use scaas_ua::wallet::{SecretBytes, Signer, Wallet};
use serde_json::Value;
use std::sync::Arc;
use zeroize::Zeroizing;

const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const MLDSA65: u16 = 0x0131;

fn load(f: &str) -> Value {
    let p = format!(
        "{}/../../smartcontracts/vectors/pqchat/{f}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn s(v: &Value) -> String {
    v.as_str().unwrap().to_string()
}
fn b(v: &Value) -> Vec<u8> {
    alloy::hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn n(v: &Value) -> u64 {
    v.as_u64().unwrap()
}
fn strs(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(s).collect()
}
fn members(v: &Value) -> Vec<PqMemberKey> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|m| PqMemberKey {
            ua: s(&m["ua"]),
            key_id: n(&m["keyId"]),
            via: s(&m["via"]),
        })
        .collect()
}
fn wraps(keys: &Value, prefix: &str) -> Vec<PqWrap> {
    keys["wraps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|w| w["name"].as_str().unwrap().starts_with(prefix))
        .map(|w| {
            let w = &w["wrap"];
            PqWrap {
                member: s(&w["member"]),
                key_id: n(&w["keyId"]),
                mlkem_ct: b(&w["mlkemCt"]),
                x25519_eph: s(&w["x25519Eph"]),
                sealed_key: b(&w["sealedKey"]),
            }
        })
        .collect()
}

async fn core() -> (Arc<AppCore>, String, Arc<Sdk>) {
    let sdk = Sdk::open(SdkConfig {
        profiles: vec![],
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
            vault_passphrase: sec("river-otter-7 ünï"),
        })
        .await
        .unwrap()
        .id;
    // pqchat-core's scope: no app id (it signs SCaaS records only, through these entries)
    let a = AppCore::new(
        sdk.clone(),
        AppDesc {
            app_id: None,
            name: "PqChat".into(),
            class: Some(3),
            labels: vec!["scaas/pqchat/v1/".into()],
        },
    )
    .unwrap();
    (a, seed, sdk)
}

#[test]
fn the_bit_follows_the_feature() {
    use scaas_sdk::bits::PQCHAT_RECORDS;
    assert_eq!(scaas_sdk::features() & PQCHAT_RECORDS, PQCHAT_RECORDS);
    assert_eq!(PQCHAT_RECORDS, 1 << 27);
}

#[tokio::test(flavor = "multi_thread")]
async fn entries_reproduce_the_vectors() {
    let (a, seed, sdk) = core().await;
    let (rec, top, keys) = (load("records"), load("topics"), load("keys"));
    let key = KeyRef::Ua {
        seed: seed.clone(),
        kind: MLDSA65,
        account: 0,
        index: 0,
    };
    let k = Wallet::from_mnemonic(REPO, "")
        .unwrap()
        .ua_key(MLDSA65, 0, 0)
        .unwrap();
    let scaas_ua::wallet::KeyRef::Ua { key_data, .. } = k.key_ref() else {
        panic!()
    };
    let purpose = scaas_ua::keccak256(b"scaas.ua.purpose.pqchat.v1");
    let entry_ref = |r: &Value| PqEntryRef {
        chain_uid: s(&r["chainUid"]),
        pqchat: s(&r["pqchat"]),
        entry_id: s(&r["entryId"]),
        content_hash: s(&r["contentHash"]),
    };
    let entry = |r: &Value| PqTopicEntry {
        topic_id: s(&r["topicId"]),
        author: s(&r["author"]),
        nonce: n(&r["nonce"]),
        parent_id: s(&r["parentId"]),
        entry_ref: entry_ref(&r["ref"]),
        media_type: s(&r["mediaType"]),
        body: b(&r["body"]),
    };
    let r = |v: &Value, row: &str| v[row]["record"].clone();
    let mut got = vec![];
    let x = r(&rec, "session");
    got.push((
        &rec["session"],
        a.sign_pqchat_session(
            key.clone(),
            PqChatSession {
                creator: s(&x["creator"]),
                nonce: n(&x["nonce"]),
                home_chain: s(&x["homeChain"]),
                home_chat_contract: s(&x["homeChatContract"]),
                admins: strs(&x["admins"]),
                members: members(&x["members"]),
                wraps: wraps(&keys, "session/"),
                sealed_info: b(&x["sealedInfo"]),
            },
        )
        .await
        .unwrap(),
    ));
    let x = r(&rec, "epoch");
    got.push((
        &rec["epoch"],
        a.sign_pqchat_epoch(
            key.clone(),
            PqChatEpoch {
                session_id: s(&x["sessionId"]),
                author: s(&x["author"]),
                nonce: n(&x["nonce"]),
                epoch: n(&x["epoch"]),
                parent_epoch_id: s(&x["parentEpochId"]),
                admins: strs(&x["admins"]),
                members: members(&x["members"]),
                wraps: wraps(&keys, "epoch-1/"),
                sealed_info: b(&x["sealedInfo"]),
            },
        )
        .await
        .unwrap(),
    ));
    let x = r(&rec, "leave");
    got.push((
        &rec["leave"],
        a.sign_pqchat_leave(
            key.clone(),
            PqChatLeave {
                session_id: s(&x["sessionId"]),
                epoch_id: s(&x["epochId"]),
                member: s(&x["member"]),
                nonce: n(&x["nonce"]),
            },
        )
        .await
        .unwrap(),
    ));
    let x = r(&rec, "remove");
    got.push((
        &rec["remove"],
        a.sign_pqchat_remove(
            key.clone(),
            PqChatRemove {
                session_id: s(&x["sessionId"]),
                epoch_id: s(&x["epochId"]),
                next_epoch: n(&x["nextEpoch"]),
                members: strs(&x["members"]),
                admin: s(&x["admin"]),
                nonce: n(&x["nonce"]),
            },
        )
        .await
        .unwrap(),
    ));
    let x = r(&rec, "message");
    got.push((
        &rec["message"],
        a.sign_pqchat_message(
            key.clone(),
            PqChatMessage {
                session_id: s(&x["sessionId"]),
                epoch_id: s(&x["epochId"]),
                sender: s(&x["sender"]),
                device: s(&x["device"]),
                counter: n(&x["counter"]),
                parents: strs(&x["parents"]),
                ciphertext: b(&x["ciphertext"]),
            },
        )
        .await
        .unwrap(),
    ));
    let x = r(&top, "topic");
    got.push((
        &top["topic"],
        a.sign_pqchat_topic(
            key.clone(),
            PqTopic {
                admin: s(&x["admin"]),
                nonce: n(&x["nonce"]),
                home_chain: s(&x["homeChain"]),
                home_chat_contract: s(&x["homeChatContract"]),
                name: s(&x["name"]),
                about: b(&x["about"]),
                open_replies: x["openReplies"].as_bool().unwrap(),
            },
        )
        .await
        .unwrap(),
    ));
    let x = r(&top, "update");
    got.push((
        &top["update"],
        a.sign_pqchat_topic_update(
            key.clone(),
            PqTopicUpdate {
                topic_id: s(&x["topicId"]),
                seq: n(&x["seq"]),
                name: s(&x["name"]),
                about: b(&x["about"]),
                open_replies: x["openReplies"].as_bool().unwrap(),
            },
        )
        .await
        .unwrap(),
    ));
    let x = r(&top, "writer");
    got.push((
        &top["writer"],
        a.sign_pqchat_topic_writer(
            key.clone(),
            PqTopicWriter {
                topic_id: s(&x["topicId"]),
                writer: s(&x["writer"]),
                granted: x["granted"].as_bool().unwrap(),
                seq: n(&x["seq"]),
            },
        )
        .await
        .unwrap(),
    ));
    for row in ["post", "reply"] {
        got.push((
            &top[row],
            a.sign_pqchat_topic_entry(key.clone(), entry(&r(&top, row)))
                .await
                .unwrap(),
        ));
    }
    let x = r(&top, "edit");
    got.push((
        &top["edit"],
        a.sign_pqchat_topic_edit(
            key.clone(),
            PqTopicEdit {
                entry_id: s(&x["entryId"]),
                author: s(&x["author"]),
                nonce: n(&x["nonce"]),
                version: n(&x["version"]) as u32,
                media_type: s(&x["mediaType"]),
                body: b(&x["body"]),
            },
        )
        .await
        .unwrap(),
    ));
    let x = r(&top, "vote");
    got.push((
        &top["vote"],
        a.sign_pqchat_topic_vote(
            key.clone(),
            PqTopicVote {
                entry_id: s(&x["entryId"]),
                voter: s(&x["voter"]),
                value: x["value"].as_i64().unwrap() as i8,
                seq: n(&x["seq"]),
            },
        )
        .await
        .unwrap(),
    ));
    assert_eq!(got.len(), 12);
    for (want, g) in &got {
        let name = &g.record;
        assert_eq!(g.typed, s(&want["typed"]), "{name}");
        assert_eq!(g.id, want.get("id").map(s), "{name}");
        if let Some(wh) = want["record"].get("wrapHashes") {
            assert_eq!(g.wrap_hashes, strs(wh), "{name}");
        }
        let typed: [u8; 32] = b(&want["typed"]).try_into().unwrap();
        let m = scaas_ua::ua_message(MLDSA65, &purpose, &typed).unwrap();
        assert!(
            scaas_ua::verify::verify(MLDSA65, &key_data, &m, &g.sig.signature, true, false),
            "{name}"
        );
        assert!(
            g.sig.key_data.is_empty() && g.sig.members.is_empty(),
            "{name}"
        );
        // the review: the struct, every message field
        assert!(g
            .review
            .iter()
            .any(|f| f.name == "record" && f.value == *name));
        let fields = want["record"].as_object().unwrap().len();
        assert!(
            g.review
                .iter()
                .filter(|f| f.name.starts_with("message."))
                .count()
                >= fields,
            "{name}"
        );
    }
    // a native key signs no PqChat record
    let native = KeyRef::Native {
        seed,
        network: "evm".into(),
        index: 0,
    };
    let x = r(&rec, "leave");
    let l = PqChatLeave {
        session_id: s(&x["sessionId"]),
        epoch_id: s(&x["epochId"]),
        member: s(&x["member"]),
        nonce: n(&x["nonce"]),
    };
    assert_eq!(
        a.sign_pqchat_leave(native, l.clone())
            .await
            .map_or_else(|e| e.code(), |_| "Ok"),
        "Argument"
    );
    // T26 A-9: a scope without PqChat's prefix (`AppLabelRefused`); the control (the vector's leave) signed above
    let own = AppCore::new(
        sdk,
        AppDesc {
            app_id: None,
            name: "Other".into(),
            class: Some(3),
            labels: vec!["scaas/other/v1/".into()],
        },
    )
    .unwrap();
    assert_eq!(
        own.sign_pqchat_leave(key.clone(), l)
            .await
            .map_or_else(|e| e.code(), |_| "Ok"),
        "AppLabelRefused"
    );
}
