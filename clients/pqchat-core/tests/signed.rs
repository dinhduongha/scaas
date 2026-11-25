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
use pqchat_core::model::Epoch;
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

/// What a prepared write carries (the fake's recorded arguments) served as the home stores it on an `sstore2` instance: the
/// record under its id with its kept signature, its wraps at their indexes, no exit kept under it.
fn serve_written(net: &FakeNet, item: &str, args: &Value, id: &str) {
    let session = item == "IPqChat.createSession";
    let (view, sig_view, key) = if session {
        (
            "IPqChat.sessionOf",
            "IPqChat.sessionSig",
            json!({ "sessionId": id }),
        )
    } else {
        (
            "IPqChat.epochOf",
            "IPqChat.epochSig",
            json!({ "epochId": id }),
        )
    };
    let out = if session {
        json!({"s": args["s"], "sigHash": hex_of(&[9; 32])})
    } else {
        json!({"e": args["e"], "sigHash": hex_of(&[9; 32])})
    };
    net.answer(HOME, view, key.clone(), out);
    net.answer(HOME, sig_view, key, json!({"sig": args["sig"]}));
    for (i, w) in args["wraps"].as_array().unwrap().iter().enumerate() {
        net.answer(
            HOME,
            "IPqChat.wrapAt",
            json!({"epochId": id, "i": i.to_string()}),
            json!({ "0": w }),
        );
    }
    for c in ["IPqChat.leaveCount", "IPqChat.removalCount"] {
        net.answer(HOME, c, json!({ "epochId": id }), json!({"0": "0"}));
    }
}

fn me_of(a: &Acc) -> Me {
    Me {
        key: a.key.clone(),
        ua: a.ua.clone(),
    }
}

fn payer_of(w: &World) -> KeyRef {
    KeyRef::Native {
        seed: w.seed.clone(),
        network: "evm".into(),
        index: 0,
    }
}

fn info_of() -> Info {
    Info {
        stores: vec![StoreEntry::Chain {
            chain_id: "31337".into(),
            chain_uid: hex_of(&[7; 32]),
            contract: HOME.into(),
        }],
        name: "chain".into(),
        topic: "signed chain".into(),
        matrix: Default::default(),
    }
}

/// An `sstore2` HOME, prepares answered, alice, bob and carol at KEM version 1; alice's session with bob and carol (alice
/// its only admin) built by the crate and served.
async fn signed_session() -> (World, pqchat_core::reads::SessionRef, OpenEpoch) {
    let w = world().await;
    list(&w.net, HOME, 3, 1);
    w.net
        .answer(HOME, "IPqChat.sigStore", json!({}), json!({"0": "2"}));
    w.net
        .accept
        .store(true, std::sync::atomic::Ordering::SeqCst);
    for a in [&w.alice, &w.bob, &w.carol] {
        kem(&w, a, 1);
    }
    let b =
        w.pq.create(CreateSession {
            me: me_of(&w.alice),
            chain: CHAIN.into(),
            home: HOME.into(),
            nonce: 1,
            members: vec![w.bob.ua.clone(), w.carol.ua.clone()],
            admins: vec![],
            info: info_of(),
            payer: payer_of(&w),
        })
        .await
        .unwrap();
    serve_written(
        &w.net,
        "IPqChat.createSession",
        &w.net.writes_of("IPqChat.createSession")[0],
        &b.session_id,
    );
    let s = pqchat_core::reads::SessionRef {
        chain: CHAIN.into(),
        home: HOME.into(),
        session_id: b.session_id.clone(),
    };
    let o = OpenEpoch {
        chain: CHAIN.into(),
        epoch: b.epoch,
        k: b.k,
    };
    (w, s, o)
}

/// `by`'s rekey of `parent` (as an endpoint describes it: nothing checks it here) with `members` and `admins`, `left` flagged
/// at the parent for the builder, built by the crate's builder, signed, and served as the home keeps it.
#[allow(clippy::too_many_arguments)]
async fn rekey_on(
    w: &World,
    s: &pqchat_core::reads::SessionRef,
    parent: &OpenEpoch,
    by: &Acc,
    nonce: u64,
    members: &[&Acc],
    admins: &[&Acc],
    left: &[&Acc],
) -> OpenEpoch {
    let p = &parent.epoch;
    child(&w.net, HOME, &p.id, pqchat_core::model::ZERO32);
    for m in p
        .members
        .iter()
        .map(|m| m.ua.clone())
        .chain(p.admins.clone())
    {
        let gone = left.iter().any(|a| a.ua == m);
        w.net.answer(
            HOME,
            "IPqChat.leftIn",
            json!({"epochId": p.id, "member": m}),
            json!({"0": gone}),
        );
        w.net.answer(
            HOME,
            "IPqChat.removedIn",
            json!({"epochId": p.id, "member": m}),
            json!({"0": false}),
        );
    }
    let r = pqchat_core::session::Rekey {
        me: me_of(by),
        nonce,
        members: members.iter().map(|a| a.ua.clone()).collect(),
        admins: admins.iter().map(|a| a.ua.clone()).collect(),
        info: info_of(),
        payer: payer_of(w),
    };
    let b = w.pq.rekey(s, parent, r).await.unwrap();
    serve_written(
        &w.net,
        "IPqChat.rekey",
        w.net.writes_of("IPqChat.rekey").last().unwrap(),
        &b.epoch_id,
    );
    OpenEpoch {
        chain: CHAIN.into(),
        epoch: b.epoch,
        k: b.k,
    }
}

/// U-1 (fable-D 2026-11-25, settled by this test): on an `sstore2` home an endpoint serves, under ids it chose, a parent signed
/// by dave (here carol's UA, made no member: a registered UA outside the session) naming itself its admin, and its child
/// wrapping a key to bob. Each record's own signature verifies and the child is right against that parent, so a reader that
/// checks one link followed it (red before the walk); the walk to the signed session record refuses it (`control`: the forger
/// has no right on the session). Twin: the true chain is followed.
#[tokio::test(flavor = "multi_thread")]
async fn a_forged_parent_and_child_are_not_followed() {
    let _one = ONE.lock().await;
    let w = world().await;
    list(&w.net, HOME, 3, 1);
    w.net
        .answer(HOME, "IPqChat.sigStore", json!({}), json!({"0": "2"}));
    w.net
        .accept
        .store(true, std::sync::atomic::Ordering::SeqCst);
    for a in [&w.alice, &w.bob, &w.carol] {
        kem(&w, a, 1);
    }
    let b =
        w.pq.create(CreateSession {
            me: me_of(&w.alice),
            chain: CHAIN.into(),
            home: HOME.into(),
            nonce: 1,
            members: vec![w.bob.ua.clone()],
            admins: vec![],
            info: info_of(),
            payer: payer_of(&w),
        })
        .await
        .unwrap();
    let sid = b.session_id.clone();
    serve_written(
        &w.net,
        "IPqChat.createSession",
        &w.net.writes_of("IPqChat.createSession")[0],
        &sid,
    );
    let s = pqchat_core::reads::SessionRef {
        chain: CHAIN.into(),
        home: HOME.into(),
        session_id: sid.clone(),
    };
    let s0 = OpenEpoch {
        chain: CHAIN.into(),
        epoch: b.epoch.clone(),
        k: b.k.clone(),
    };
    // the endpoint's description of the session: carol its admin and a member beside bob
    let mut fake0 = s0.clone();
    fake0.epoch.admins = vec![w.carol.ua.clone()];
    fake0.epoch.members.retain(|m| m.ua == w.bob.ua);
    fake0.epoch.members.push(pqchat_core::model::Member {
        ua: w.carol.ua.clone(),
        key_id: 1,
        via: pqchat_core::model::ZERO32.into(),
    });
    fake0.epoch.members.sort_by(|x, y| x.ua.cmp(&y.ua));
    let p = rekey_on(&w, &s, &fake0, &w.carol, 7, &[&w.bob, &w.carol], &[], &[]).await;
    let c = rekey_on(&w, &s, &p, &w.carol, 8, &[&w.bob, &w.carol], &[], &[]).await;
    assert_eq!(
        (p.epoch.epoch, c.epoch.parent.clone()),
        (1, p.epoch.id.clone())
    );
    let got =
        w.pq.open_epoch(&s, &c.epoch.id, &w.bob.key, &w.bob.ua, None)
            .await;
    assert_eq!(
        got.err(),
        Some(DropReason::Control),
        "a forged chain followed"
    );
    // twin: alice's own rekey of the session (the true chain) is followed by bob
    let t = rekey_on(&w, &s, &s0, &w.alice, 9, &[&w.alice, &w.bob], &[], &[]).await;
    let ok =
        w.pq.open_epoch(&s, &t.epoch.id, &w.bob.key, &w.bob.ua, None)
            .await;
    assert!(ok.is_ok(), "{:?}", ok.err());
}

fn sig_json(s: &scaas_sdk::app_core::AppUaSig) -> Value {
    let inner = |m: &scaas_sdk::app_core::AppMemberSig| -> Vec<Value> {
        m.members
            .iter()
            .map(|x| json!({"index": x.index.to_string(), "sig": hex_of(&x.sig)}))
            .collect()
    };
    json!({"keyData": hex_of(&s.key_data), "signature": hex_of(&s.signature),
        "members": s.members.iter().map(|m| json!({"index": m.index.to_string(), "sig": hex_of(&m.sig),
            "members": inner(m)})).collect::<Vec<_>>()})
}

/// `by`'s leave naming `named`, signed by the SDK (no pre-check: the endpoint serves what it likes), as `leaveAt` serves it.
async fn leave_of(w: &World, by: &Acc, named: &Epoch, nonce: u64) -> Value {
    let l = scaas_sdk::pqchat_records::PqChatLeave {
        session_id: named.session_id.clone(),
        epoch_id: named.id.clone(),
        member: by.ua.clone(),
        nonce,
    };
    let sig = w
        .app
        .prepare_pqchat_leave(by.key.clone(), l)
        .await
        .unwrap()
        .sign()
        .await
        .unwrap()
        .sig;
    json!({"l": {"sessionId": named.session_id, "epochId": named.id, "member": by.ua, "nonce": nonce.to_string()},
        "sig": sig_json(&sig)})
}

/// `by`'s removal of `members` naming `named` with `next` as its `nextEpoch`, signed by the SDK, as `removalAt` serves it.
async fn removal_of(
    w: &World,
    by: &Acc,
    named: &Epoch,
    next: u64,
    members: &[&Acc],
    nonce: u64,
) -> Value {
    let mut m: Vec<String> = members.iter().map(|a| a.ua.clone()).collect();
    m.sort();
    let r = scaas_sdk::pqchat_records::PqChatRemove {
        session_id: named.session_id.clone(),
        epoch_id: named.id.clone(),
        next_epoch: next,
        members: m.clone(),
        admin: by.ua.clone(),
        nonce,
    };
    let sig = w
        .app
        .prepare_pqchat_remove(by.key.clone(), r)
        .await
        .unwrap()
        .sign()
        .await
        .unwrap()
        .sig;
    json!({"r": {"sessionId": named.session_id, "epochId": named.id, "nextEpoch": next.to_string(), "members": m,
        "admin": by.ua, "nonce": nonce.to_string()}, "sig": sig_json(&sig)})
}

/// The exits an endpoint serves as kept under `under` (`leaveAt` / `removalAt` with their signatures).
fn keep(net: &FakeNet, under: &Epoch, leaves: &[Value], removals: &[Value]) {
    keep_at(net, HOME, under, leaves, removals);
}

/// [`keep`] at `contract`.
fn keep_at(net: &FakeNet, contract: &str, under: &Epoch, leaves: &[Value], removals: &[Value]) {
    for (count, at, sig, rows, k) in [
        (
            "IPqChat.leaveCount",
            "IPqChat.leaveAt",
            "IPqChat.leaveSig",
            leaves,
            "l",
        ),
        (
            "IPqChat.removalCount",
            "IPqChat.removalAt",
            "IPqChat.removalSig",
            removals,
            "r",
        ),
    ] {
        net.answer(
            contract,
            count,
            json!({"epochId": under.id}),
            json!({"0": rows.len().to_string()}),
        );
        for (i, x) in rows.iter().enumerate() {
            let a = json!({"epochId": under.id, "index": i.to_string()});
            net.answer(
                contract,
                at,
                a.clone(),
                json!({ k: x[k], "sigHash": hex_of(&[8; 32]) }),
            );
            net.answer(contract, sig, a, json!({"sig": x["sig"]}));
        }
    }
}

/// The session and 17 plain rekeys by alice (alice, bob, carol; alice the admin throughout): `e[0..=17]`, signed and served.
async fn chain17() -> (World, pqchat_core::reads::SessionRef, Vec<OpenEpoch>) {
    let (w, s, s0) = signed_session().await;
    let mut e = vec![s0];
    for n in 1..=17u64 {
        let p = e.last().unwrap().clone();
        let next = rekey_on(
            &w,
            &s,
            &p,
            &w.alice,
            100 + n,
            &[&w.alice, &w.bob, &w.carol],
            &[&w.alice],
            &[],
        )
        .await;
        e.push(next);
    }
    (w, s, e)
}

/// B2-3 (mode 0, CTR-CHAT-10 / -20, C9): an exit kept under the head `e[17]` counts when it names the head or an ancestor at
/// most 16 above it, read through the verified chain; 17 above does not, nor a removal whose `nextEpoch` is not the named
/// number plus one. Each negative beside its positive control, one change at a time.
#[tokio::test(flavor = "multi_thread")]
async fn a_mode0_exit_names_the_head_or_an_ancestor_within_16() {
    let _one = ONE.lock().await;
    let (w, _s, e) = chain17().await;
    let head = &e[17].epoch;
    let lr = |w: &World| {
        let (pq, head) = (w.pq.clone(), head.clone());
        async move { pq.left_and_removed(CHAIN, HOME, &head).await }
    };
    let bob = w.bob.ua.clone();
    let carol = w.carol.ua.clone();
    for (named, counted) in [(17usize, true), (1, true), (0, false)] {
        keep(
            &w.net,
            head,
            &[leave_of(&w, &w.bob, &e[named].epoch, 40 + named as u64).await],
            &[],
        );
        let (left, _) = lr(&w).await.unwrap();
        assert_eq!(
            left == vec![bob.clone()],
            counted,
            "a leave naming epoch {named}"
        );
    }
    for (named, next, counted) in [
        (1usize, 2u64, true),
        (1, 18, false),
        (0, 1, false),
        (17, 18, true),
    ] {
        let r = removal_of(&w, &w.alice, &e[named].epoch, next, &[&w.carol], 60 + next).await;
        keep(&w.net, head, &[], &[r]);
        let (_, removed) = lr(&w).await.unwrap();
        assert_eq!(
            removed == vec![carol.clone()],
            counted,
            "a removal naming {named}, nextEpoch {next}"
        );
    }
}

/// E-4, CLI-PQC-15: an exit counts only as the contract could have accepted it at the parent: a removal by an admin of it of
/// its members or admins, a leave by a member of it; each beside its twin. D2-1: an ancestor is the record its id names; and
/// B2-4, a count above what the parent's UAs allow is refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_mode0_exit_counts_as_the_contract_judges_it() {
    let _one = ONE.lock().await;
    let (w, s, e) = signed_session().await;
    let e1 = rekey_on(
        &w,
        &s,
        &e,
        &w.alice,
        11,
        &[&w.alice, &w.bob, &w.carol],
        &[&w.alice],
        &[],
    )
    .await;
    // alice drops carol (an admin's membership change): carol is no member of e2
    let e2 = rekey_on(
        &w,
        &s,
        &e1,
        &w.alice,
        12,
        &[&w.alice, &w.bob],
        &[&w.alice],
        &[],
    )
    .await;
    let lr = |p: &Epoch| {
        let (pq, p) = (w.pq.clone(), p.clone());
        async move { pq.left_and_removed(CHAIN, HOME, &p).await }
    };
    // a removal by bob (no admin) of carol at e1: not counted; twin, alice's
    keep(
        &w.net,
        &e1.epoch,
        &[],
        &[removal_of(&w, &w.bob, &e1.epoch, 2, &[&w.carol], 1).await],
    );
    assert!(lr(&e1.epoch).await.unwrap().1.is_empty());
    keep(
        &w.net,
        &e1.epoch,
        &[],
        &[removal_of(&w, &w.alice, &e1.epoch, 2, &[&w.carol], 2).await],
    );
    assert_eq!(lr(&e1.epoch).await.unwrap().1, vec![w.carol.ua.clone()]);
    // a removal of carol at e2, where she is no member: not counted; twin, bob
    keep(
        &w.net,
        &e2.epoch,
        &[],
        &[removal_of(&w, &w.alice, &e2.epoch, 3, &[&w.carol], 3).await],
    );
    assert!(lr(&e2.epoch).await.unwrap().1.is_empty());
    keep(
        &w.net,
        &e2.epoch,
        &[],
        &[removal_of(&w, &w.alice, &e2.epoch, 3, &[&w.bob], 4).await],
    );
    assert_eq!(lr(&e2.epoch).await.unwrap().1, vec![w.bob.ua.clone()]);
    // a leave by carol at e2 (no member): not counted; twin, bob's
    keep(
        &w.net,
        &e2.epoch,
        &[leave_of(&w, &w.carol, &e2.epoch, 5).await],
        &[],
    );
    assert!(lr(&e2.epoch).await.unwrap().0.is_empty());
    keep(
        &w.net,
        &e2.epoch,
        &[leave_of(&w, &w.bob, &e2.epoch, 6).await],
        &[],
    );
    assert_eq!(lr(&e2.epoch).await.unwrap().0, vec![w.bob.ua.clone()]);
    // B2-4: a count above the UAs of the parent (2 members, 1 admin): refused; twin, 1
    w.net.answer(
        HOME,
        "IPqChat.leaveCount",
        json!({"epochId": e2.epoch.id}),
        json!({"0": "4"}),
    );
    assert_eq!(lr(&e2.epoch).await.unwrap_err(), DropReason::Control);
    w.net.answer(
        HOME,
        "IPqChat.leaveCount",
        json!({"epochId": e2.epoch.id}),
        json!({"0": "1"}),
    );
    assert!(lr(&e2.epoch).await.is_ok());
    // D2-1: under e1's id the endpoint serves bob's own epoch-1 record (validly signed, of the session, its number one below)
    // whose parent is an id Y of its choosing, and a leave of bob's naming Y under e2: the record is not the one e1's id names
    // (its id recomputed), refused; its twin, the leave naming e1 with e1 served, counts
    keep(
        &w.net,
        &e2.epoch,
        &[leave_of(&w, &w.bob, &e1.epoch, 7).await],
        &[],
    );
    assert_eq!(lr(&e2.epoch).await.unwrap().0, vec![w.bob.ua.clone()]);
    let mut y0 = e.clone();
    y0.epoch.id = hex_of(&[0x59; 32]);
    let forged = rekey_on(
        &w,
        &s,
        &y0,
        &w.bob,
        13,
        &[&w.alice, &w.bob, &w.carol],
        &[&w.alice],
        &[],
    )
    .await;
    let served_forged =
        w.net
            .answer_of(HOME, "IPqChat.epochOf", json!({"epochId": forged.epoch.id}));
    let sig_forged = w.net.answer_of(
        HOME,
        "IPqChat.epochSig",
        json!({"epochId": forged.epoch.id}),
    );
    w.net.answer(
        HOME,
        "IPqChat.epochOf",
        json!({"epochId": e1.epoch.id}),
        served_forged,
    );
    w.net.answer(
        HOME,
        "IPqChat.epochSig",
        json!({"epochId": e1.epoch.id}),
        sig_forged,
    );
    keep(
        &w.net,
        &e2.epoch,
        &[leave_of(&w, &w.bob, &y0.epoch, 8).await],
        &[],
    );
    assert_eq!(lr(&e2.epoch).await.unwrap_err(), DropReason::Control);
}

/// E-1 through the walk (mode 0, sstore2): carol leaves naming an ancestor 16 above the head; bob (no admin) drops her in a
/// plain rekey of the head, which the home accepts: every device follows it. 17 above: the drop is a membership change by a
/// non-admin (`control`).
#[tokio::test(flavor = "multi_thread")]
async fn a_plain_drop_after_a_lagged_leave_is_followed() {
    let _one = ONE.lock().await;
    let (w, s, e) = chain17().await;
    keep(
        &w.net,
        &e[17].epoch,
        &[leave_of(&w, &w.carol, &e[1].epoch, 70).await],
        &[],
    );
    let g = rekey_on(
        &w,
        &s,
        &e[17],
        &w.bob,
        71,
        &[&w.alice, &w.bob],
        &[&w.alice],
        &[&w.carol],
    )
    .await;
    let ok =
        w.pq.open_epoch(&s, &g.epoch.id, &w.alice.key, &w.alice.ua, None)
            .await;
    assert!(ok.is_ok(), "{:?}", ok.err());
    keep(
        &w.net,
        &e[17].epoch,
        &[leave_of(&w, &w.carol, &e[0].epoch, 72).await],
        &[],
    );
    let fresh = required(&w, false);
    let got = fresh
        .open_epoch(&s, &g.epoch.id, &w.alice.key, &w.alice.ua, None)
        .await;
    assert_eq!(got.err(), Some(DropReason::Control));
}

/// E-5, D2-2: the home keeps carol's leave (naming the session) under the head it was applied at, e1; a replica keeps it under
/// the epoch it names. bob's plain drop of carol (a child of e1) is read with that replica named: the replica's record counts
/// only when it equals the home's, judged at home, and no exit is read at the replica (before: `control`, the replica holds no
/// exit under e1). Twin: a replica record that differs is `replica`.
#[tokio::test(flavor = "multi_thread")]
async fn a_replica_record_is_compared_with_the_homes() {
    let _one = ONE.lock().await;
    let (w, s, s0) = signed_session().await;
    let e1 = rekey_on(
        &w,
        &s,
        &s0,
        &w.alice,
        11,
        &[&w.alice, &w.bob, &w.carol],
        &[&w.alice],
        &[],
    )
    .await;
    let l = leave_of(&w, &w.carol, &s0.epoch, 12).await;
    keep(&w.net, &e1.epoch, std::slice::from_ref(&l), &[]);
    let g = rekey_on(
        &w,
        &s,
        &e1,
        &w.bob,
        13,
        &[&w.alice, &w.bob],
        &[&w.alice],
        &[&w.carol],
    )
    .await;
    list(&w.net, REPLICA, 3, 1);
    w.net.mirror(HOME, REPLICA);
    keep_at(&w.net, REPLICA, &e1.epoch, &[], &[]);
    keep_at(&w.net, REPLICA, &s0.epoch, &[l], &[]);
    let ok =
        w.pq.open_epoch(
            &s,
            &g.epoch.id,
            &w.alice.key,
            &w.alice.ua,
            Some(REPLICA.into()),
        )
        .await;
    assert!(ok.is_ok(), "{:?}", ok.err());
    let mut other = w
        .net
        .answer_of(REPLICA, "IPqChat.epochOf", json!({"epochId": g.epoch.id}));
    other["sigHash"] = json!(hex_of(&[0x77; 32]));
    w.net.answer(
        REPLICA,
        "IPqChat.epochOf",
        json!({"epochId": g.epoch.id}),
        other,
    );
    let r =
        w.pq.open_epoch(
            &s,
            &g.epoch.id,
            &w.alice.key,
            &w.alice.ua,
            Some(REPLICA.into()),
        )
        .await;
    assert_eq!(r.err(), Some(DropReason::Replica));
}
