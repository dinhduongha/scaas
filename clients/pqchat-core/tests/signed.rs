// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! CLI-PQC-15 / CLI-PQC-16 (owner 2026-11-23, the spec's O11; CTR-CHAT-23): on an `sstore2` home every control-plane record the
//! crate uses counts only with its author's kept signature, verified through V1 over the record's fields; the rows of
//! `smartcontracts/vectors/pqchat/records.json` (real ML-DSA-65 signatures) served by a fake endpoint. A substituted `sealedInfo`,
//! another record's signature, a leave nobody signed and a downgraded setting are each refused by name; a `none` home is read as
//! before, or refused under `require_signed_records`; the agreed-read option routes the control-plane reads only.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;

use common::net::FakeNet;
use common::sdk::*;
use pqchat_core::message::OpenEpoch;
use pqchat_core::net::Net;
use pqchat_core::session::{CreateSession, Info, Me, StoreEntry};
use pqchat_core::{DropReason, MemoryStore, PqChat, PqChatConfig};
use scaas_sdk::op::KeyRef;
use serde_json::{json, Value};
use std::sync::Arc;

fn rows() -> Value {
    let p = format!(
        "{}/../../smartcontracts/vectors/pqchat/records.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn b32(v: &Value) -> [u8; 32] {
    unhex(v.as_str().unwrap()).try_into().unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    let h = s.trim_start_matches("0x");
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

/// The world with the vector signers registered on its fake chain and the vector records served at HOME (`sstore2`).
async fn served() -> (World, Value) {
    let w = world().await;
    let r = rows();
    for x in r["signers"].as_array().unwrap() {
        reg(
            &w.chain,
            &b32(&x["ua"]),
            0x0131,
            &unhex(x["publicKey"].as_str().unwrap()),
        );
    }
    list(&w.net, HOME, 3, 1);
    serve(&w.net, &r, 2);
    (w, r)
}

fn serve(net: &FakeNet, r: &Value, sig_store: u64) {
    let (sid, eid) = (&r["session"]["id"], &r["epoch"]["id"]);
    net.answer(
        HOME,
        "IPqChat.sigStore",
        json!({}),
        json!({"0": sig_store.to_string()}),
    );
    let row = |n: &str| {
        (
            &r[n]["record"],
            json!({"sig": r[n]["uaSig"]}),
            &r[n]["sigHash"],
        )
    };
    let (s, ss, sh) = row("session");
    net.answer(
        HOME,
        "IPqChat.sessionOf",
        json!({"sessionId": sid}),
        json!({"s": s, "sigHash": sh}),
    );
    net.answer(HOME, "IPqChat.sessionSig", json!({"sessionId": sid}), ss);
    let (e, es, eh) = row("epoch");
    net.answer(
        HOME,
        "IPqChat.epochOf",
        json!({"epochId": eid}),
        json!({"e": e, "sigHash": eh}),
    );
    net.answer(HOME, "IPqChat.epochSig", json!({"epochId": eid}), es);
    let i0 = json!({"epochId": eid, "index": "0"});
    net.answer(
        HOME,
        "IPqChat.leaveCount",
        json!({"epochId": eid}),
        json!({"0": "1"}),
    );
    let (l, ls, lh) = row("leave");
    net.answer(
        HOME,
        "IPqChat.leaveAt",
        i0.clone(),
        json!({"l": l, "sigHash": lh}),
    );
    net.answer(HOME, "IPqChat.leaveSig", i0.clone(), ls);
    net.answer(
        HOME,
        "IPqChat.removalCount",
        json!({"epochId": eid}),
        json!({"0": "1"}),
    );
    let (rm, rs, rh) = row("remove");
    net.answer(
        HOME,
        "IPqChat.removalAt",
        i0.clone(),
        json!({"r": rm, "sigHash": rh}),
    );
    net.answer(HOME, "IPqChat.removalSig", i0, rs);
    let m0 = json!({"sessionId": sid, "index": "0"});
    let (m, ms, mh) = row("message");
    net.answer(
        HOME,
        "IPqChat.messageAt",
        m0.clone(),
        json!({"m": m, "sigHash": mh}),
    );
    net.answer(HOME, "IPqChat.messageSig", m0, ms);
}

fn ids(r: &Value) -> (String, String) {
    (
        r["session"]["id"].as_str().unwrap().into(),
        r["epoch"]["id"].as_str().unwrap().into(),
    )
}

fn required(w: &World, require: bool) -> Arc<PqChat> {
    let c = PqChatConfig {
        require_signed_records: require,
        ..conf()
    };
    PqChat::with_net(
        w.app.clone(),
        w.net.clone(),
        Arc::new(MemoryStore::new()),
        c,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_kept_signature_counts_and_a_substituted_sealed_info_does_not() {
    let _one = ONE.lock().await;
    let (w, r) = served().await;
    let (sid, eid) = ids(&r);
    let s =
        w.pq.signed_record_at(CHAIN, HOME, &sid, &sid)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(s.author, r["session"]["record"]["creator"]);
    let e =
        w.pq.signed_record_at(CHAIN, HOME, &sid, &eid)
            .await
            .unwrap()
            .unwrap();
    assert_eq!((e.epoch, e.parent.clone()), (1, sid.clone()));
    assert_eq!(
        w.net.reads_of("IPqChat.sessionSig") + w.net.reads_of("IPqChat.epochSig"),
        2
    );
    // the threat the setting closes: an endpoint serves the epoch with a store list of its own
    let mut forged = r["epoch"]["record"].clone();
    forged["sealedInfo"] = json!("0xbad0");
    w.net.answer(
        HOME,
        "IPqChat.epochOf",
        json!({"epochId": eid}),
        json!({"e": forged, "sigHash": r["epoch"]["sigHash"]}),
    );
    assert_eq!(
        w.pq.signed_record_at(CHAIN, HOME, &sid, &eid)
            .await
            .unwrap_err(),
        DropReason::Signature
    );
    // another record's signature (the session's) under the session record's id: refused
    w.net.answer(
        HOME,
        "IPqChat.sessionSig",
        json!({"sessionId": sid}),
        json!({"sig": r["epoch"]["uaSig"]}),
    );
    assert_eq!(
        w.pq.signed_record_at(CHAIN, HOME, &sid, &sid)
            .await
            .unwrap_err(),
        DropReason::Signature
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn leaves_and_removals_count_by_their_signatures() {
    let _one = ONE.lock().await;
    let (w, r) = served().await;
    let (sid, eid) = ids(&r);
    let e =
        w.pq.signed_record_at(CHAIN, HOME, &sid, &eid)
            .await
            .unwrap()
            .unwrap();
    let (bob, alice) = (
        r["signers"][1]["ua"].as_str().unwrap(),
        r["signers"][0]["ua"].as_str().unwrap(),
    );
    let (left, removed) = w.pq.left_and_removed(CHAIN, HOME, &e).await.unwrap();
    assert_eq!(left, vec![bob.to_string()]);
    assert_eq!(removed, vec![bob.to_string(), alice.to_string()]);
    assert_eq!(
        w.net.reads_of("IPqChat.leftIn") + w.net.reads_of("IPqChat.removedIn"),
        0,
        "no flag read"
    );
    // a leave nobody signed: refused, not counted
    let i0 = json!({"epochId": eid, "index": "0"});
    w.net.answer(
        HOME,
        "IPqChat.leaveSig",
        i0.clone(),
        json!({"sig": r["remove"]["uaSig"]}),
    );
    assert_eq!(
        w.pq.left_and_removed(CHAIN, HOME, &e).await.unwrap_err(),
        DropReason::Signature
    );
    // a leave of an epoch that is neither this one nor an ancestor of it, served under this one: not counted
    let mut other = r["leave"]["record"].clone();
    other["epochId"] = json!(format!("0x{}", "ab".repeat(32)));
    w.net.answer(
        HOME,
        "IPqChat.leaveAt",
        i0.clone(),
        json!({"l": other, "sigHash": r["leave"]["sigHash"]}),
    );
    let (left, _) = w.pq.left_and_removed(CHAIN, HOME, &e).await.unwrap();
    assert!(left.is_empty());
    // a leave naming an ancestor (the session's epoch 0) is kept under the head it was applied at (C9, Change 2026-11-24):
    // it is a candidate, so its signature is checked (here the record changed under it: refused)
    other["epochId"] = json!(sid);
    w.net.answer(
        HOME,
        "IPqChat.leaveAt",
        i0,
        json!({"l": other, "sigHash": r["leave"]["sigHash"]}),
    );
    assert_eq!(
        w.pq.left_and_removed(CHAIN, HOME, &e).await.unwrap_err(),
        DropReason::Signature
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_none_home_is_read_as_before_or_refused_when_required() {
    let _one = ONE.lock().await;
    let (w, r) = served().await;
    serve(&w.net, &r, 0);
    let (sid, _) = ids(&r);
    assert!(w
        .pq
        .signed_record_at(CHAIN, HOME, &sid, &sid)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        w.net.reads_of("IPqChat.sessionSig"),
        0,
        "none: no signature read"
    );
    let strict = required(&w, true);
    assert_eq!(
        strict
            .signed_record_at(CHAIN, HOME, &sid, &sid)
            .await
            .unwrap_err(),
        DropReason::Unsigned
    );
    // the control: the same option on an sstore2 home reads and verifies
    let strict2 = required(&w, true);
    serve(&w.net, &r, 2);
    assert!(strict2
        .signed_record_at(CHAIN, HOME, &sid, &sid)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_setting_is_pinned_so_a_downgrade_is_refused() {
    let _one = ONE.lock().await;
    let (w, r) = served().await;
    assert_eq!(w.pq.sig_store(CHAIN, HOME).await.unwrap(), 2);
    serve(&w.net, &r, 0);
    assert_eq!(
        w.pq.sig_store(CHAIN, HOME).await.unwrap_err(),
        DropReason::Control
    );
    serve(&w.net, &r, 1);
    assert_eq!(
        required(&w, false)
            .sig_store(CHAIN, HOME)
            .await
            .unwrap_err(),
        DropReason::Control,
        "log: no mode here"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_posted_message_counts_by_its_kept_signature() {
    let _one = ONE.lock().await;
    let (w, r) = served().await;
    let (sid, eid) = ids(&r);
    let e =
        w.pq.signed_record_at(CHAIN, HOME, &sid, &eid)
            .await
            .unwrap()
            .unwrap();
    let ep = OpenEpoch {
        chain: CHAIN.into(),
        epoch: e,
        k: w.app.pqchat_epoch_key(&w.seed).unwrap(),
    };
    // past the signature: a later check refuses it (the epoch key here is not the vector's), never `signature`
    let past = w.pq.posted(HOME, 0, &ep).await.err().unwrap();
    assert!(
        !matches!(past, DropReason::Signature | DropReason::Unsigned),
        "{past:?}"
    );
    assert_eq!(w.net.reads_of("IPqChat.messageSig"), 1);
    let m0 = json!({"sessionId": sid, "index": "0"});
    w.net.answer(
        HOME,
        "IPqChat.messageSig",
        m0,
        json!({"sig": r["leave"]["uaSig"]}),
    );
    assert_eq!(
        w.pq.posted(HOME, 0, &ep).await.err().unwrap(),
        DropReason::Signature
    );
    serve(&w.net, &r, 0);
    assert_eq!(
        required(&w, true).posted(HOME, 0, &ep).await.err().unwrap(),
        DropReason::Unsigned
    );
}

/// CLI-PQC-16: the agreed option covers the trusted `IPqChat` reads only; over the SDK's one-endpoint list an agreed read is the
/// SDK's `Argument` (strict majority needs two endpoints), the same read without the option answers.
#[tokio::test(flavor = "multi_thread")]
async fn agreed_reads_cover_the_control_plane_only() {
    let _one = ONE.lock().await;
    let wd = world().await;
    use pqchat_core::net::{agreed_item, AgreedNet, SdkNet};
    assert!(
        agreed_item("IPqChat.sessionOf")
            && agreed_item("IPqChat.sessionSig")
            && agreed_item("IPqChat.sigStore")
    );
    assert!(
        !agreed_item("IPqChat.topics")
            && !agreed_item("IUARegistry.kemKeyOf")
            && !agreed_item("IPqChat.nowhere")
    );
    answer(&wd.chain, HOME, "sigStore()", &[], w(2));
    let net = || SdkNet {
        sdk: wd.sdk.clone(),
        app: wd.app.clone(),
    };
    let plain = net()
        .read(CHAIN, HOME, "IPqChat.sigStore", json!({}))
        .await
        .unwrap();
    assert_eq!(plain, json!({"0": "2"}));
    let e = AgreedNet(net())
        .read(CHAIN, HOME, "IPqChat.sigStore", json!({}))
        .await
        .unwrap_err();
    assert_eq!(e.code(), "Argument");
    // a read outside the option keeps the list's policy: the same answer through AgreedNet
    answer(
        &wd.chain,
        REGISTRY,
        "checkedOf(bytes32)",
        &[0x11; 32],
        w(0).repeat(3),
    );
    let c = json!({"ua": format!("0x{}", "11".repeat(32))});
    assert!(AgreedNet(net())
        .read(CHAIN, REGISTRY, "IUARegistry.checkedOf", c)
        .await
        .is_ok());
}

/// CLI-PQC-15: under `require_signed_records` a session is not created on a `none` home (`HomeUnsigned`, nothing prepared); the
/// control, the same request without the option, goes past that check (to the next one this fake does not answer).
#[tokio::test(flavor = "multi_thread")]
async fn a_session_is_not_created_on_a_none_home_when_required() {
    let _one = ONE.lock().await;
    let (w, r) = served().await;
    serve(&w.net, &r, 0);
    let req = || CreateSession {
        me: Me {
            key: w.alice.key.clone(),
            ua: w.alice.ua.clone(),
        },
        chain: CHAIN.into(),
        home: HOME.into(),
        nonce: 3,
        members: vec![w.bob.ua.clone()],
        admins: vec![],
        info: Info {
            stores: vec![StoreEntry::Chain {
                chain_id: "31337".into(),
                chain_uid: hex_of(&[7; 32]),
                contract: HOME.into(),
            }],
            name: "signed".into(),
            topic: "CLI-PQC-15".into(),
            matrix: Default::default(),
        },
        payer: KeyRef::Native {
            seed: w.seed.clone(),
            network: "evm".into(),
            index: 0,
        },
    };
    let e = required(&w, true).create(req()).await.err().unwrap();
    assert_eq!(e.code(), "HomeUnsigned");
    assert_eq!(w.net.writes(), 0);
    let other = required(&w, false)
        .create(req())
        .await
        .err()
        .map(|e| e.code());
    assert_ne!(other, Some("HomeUnsigned"));
}

fn hex_of(b: &[u8]) -> String {
    pqchat_core::model::hex(b)
}

/// CLI-PQC-16: `PqChat::new` takes the option: with `agreed_reads` its control-plane reads are agreed (refused on the one-endpoint
/// list, so the setting cannot be read: `decode`), without it the same read answers. Each over its own SDK (one scope per SDK).
#[tokio::test(flavor = "multi_thread")]
async fn pqchat_new_wires_the_agreed_option() {
    let _one = ONE.lock().await;
    for agreed in [false, true] {
        let chain = common::sdk::fake_chain::fake();
        let url = common::sdk::fake_chain::serve(chain.clone()).await;
        let genesis = chain.lock().unwrap().genesis.clone();
        let (sdk, _seed) = sdk_on(vec![named(url)], genesis).await;
        answer(&chain, HOME, "sigStore()", &[], w(2));
        let c = PqChatConfig {
            agreed_reads: agreed,
            ..conf()
        };
        let pq = PqChat::new(sdk, Arc::new(MemoryStore::new()), c).unwrap();
        let got = pq.sig_store(CHAIN, HOME).await;
        assert_eq!(
            got,
            if agreed {
                Err(DropReason::Decode)
            } else {
                Ok(2)
            },
            "agreed {agreed}"
        );
    }
}
