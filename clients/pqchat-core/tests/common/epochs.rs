// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Session and epoch records built by another client (the SDK's S1 / S2 directly, any `sealedInfo`), stored at HOME with
//! every wrap landed and the record complete, on the SDK's fake chain; with the small helpers the T8 and T9 tests share.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
use super::sdk::*;
use pqchat_core::message::OpenEpoch;
use pqchat_core::model::{hex, unhex, Epoch, Member, ZERO32};
use pqchat_core::reads::SessionRef;
use pqchat_core::session::Me;
use pqchat_core::stores::SendOpts;
use scaas_sdk::app_core::AppKey;
use scaas_sdk::op::KeyRef;
use scaas_sdk::pqchat_keys::{PqEpochNew, PqSessionNew};
use scaas_sdk::pqchat_records::PqMemberKey;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub fn me(a: &Acc) -> Me {
    Me {
        key: a.key.clone(),
        ua: a.ua.clone(),
    }
}

pub fn payer(w: &World) -> KeyRef {
    KeyRef::Native {
        seed: w.seed.clone(),
        network: "evm".into(),
        index: 0,
    }
}

pub fn opts(w: &World) -> SendOpts {
    SendOpts {
        payer: payer(w),
        post: false,
        post_cost_confirmed: false,
    }
}

pub fn chain_entry(contract: &str) -> Value {
    json!({"kind": "chain", "chainId": "31337", "chainUid": hex(&[7; 32]), "contract": contract})
}

pub fn room_entry(room: &str) -> Value {
    json!({"kind": "matrix", "room": room})
}

pub fn code<T>(r: Result<T, pqchat_core::PqChatError>) -> &'static str {
    match r {
        Ok(_) => "Ok",
        Err(e) => e.code(),
    }
}

/// A record built and stored: the record and its key.
pub struct Signed {
    pub e: Epoch,
    pub k: Arc<AppKey>,
}

impl Signed {
    pub fn open(&self) -> OpenEpoch {
        OpenEpoch {
            chain: CHAIN.into(),
            epoch: self.e.clone(),
            k: self.k.clone(),
        }
    }
}

pub fn sref(e: &Epoch) -> SessionRef {
    SessionRef {
        chain: CHAIN.into(),
        home: HOME.into(),
        session_id: e.session_id.clone(),
    }
}

/// The world: HOME and REPLICA listed, prepares and submits answered, every UA at KEM version 1.
pub async fn ready() -> World {
    let w = world().await;
    list(&w.net, HOME, 3, 1);
    list(&w.net, REPLICA, 3, 1);
    w.net.accept.store(true, Ordering::SeqCst);
    for a in [&w.alice, &w.bob, &w.carol] {
        kem(&w, a, 1);
    }
    w
}

/// `by`'s session (`parent` `None`) or epoch after `parent`, `members` and `admins` as given, `info` its `sealedInfo` JSON,
/// signed by the SDK and stored at HOME (every wrap landed, complete, its slot free).
pub async fn signed(
    w: &World,
    by: &Acc,
    parent: Option<&Epoch>,
    nonce: u64,
    members: &[&Acc],
    admins: &[&Acc],
    info: Value,
) -> Signed {
    let mut ms: Vec<&Acc> = members.to_vec();
    ms.sort_by(|a, b| a.ua.cmp(&b.ua));
    let mut admins: Vec<String> = admins.iter().map(|a| a.ua.clone()).collect();
    admins.sort();
    let sid = match parent {
        Some(p) => p.session_id.clone(),
        None => w.app.pqchat_session_id(by.ua.clone(), nonce).unwrap(),
    };
    let eid = match parent {
        Some(_) => w
            .app
            .pqchat_epoch_id(sid.clone(), by.ua.clone(), nonce)
            .unwrap(),
        None => sid.clone(),
    };
    let k = w.app.pqchat_epoch_key(&w.seed).unwrap();
    let mut wraps = vec![];
    for a in &ms {
        kem_at(&w.chain, &a.id, 1, &a.kem_pk);
        wraps.push(
            w.app
                .pqchat_wrap(
                    CHAIN.into(),
                    k.clone(),
                    sid.clone(),
                    eid.clone(),
                    a.ua.clone(),
                    1,
                )
                .await
                .unwrap(),
        );
    }
    let keys: Vec<PqMemberKey> = ms
        .iter()
        .map(|a| PqMemberKey {
            ua: a.ua.clone(),
            key_id: 1,
            via: ZERO32.into(),
        })
        .collect();
    let info_json = info.to_string();
    let signed = match parent {
        None => w
            .app
            .pqchat_prepare_session(
                by.key.clone(),
                k.clone(),
                PqSessionNew {
                    nonce,
                    home_chain: hex(&[7; 32]),
                    home_chat_contract: HOME.into(),
                    admins: admins.clone(),
                    members: keys,
                    wraps: wraps.clone(),
                    info_json,
                },
            )
            .await
            .unwrap()
            .sign()
            .await
            .unwrap(),
        Some(p) => w
            .app
            .pqchat_prepare_epoch(
                by.key.clone(),
                k.clone(),
                PqEpochNew {
                    session_id: sid.clone(),
                    nonce,
                    epoch: p.epoch + 1,
                    parent_epoch_id: p.id.clone(),
                    admins: admins.clone(),
                    members: keys,
                    wraps: wraps.clone(),
                    info_json,
                },
            )
            .await
            .unwrap()
            .sign()
            .await
            .unwrap(),
    };
    let sealed = &signed
        .review
        .iter()
        .find(|f| f.name == "message.sealedInfo")
        .unwrap()
        .value;
    let e = Epoch {
        id: eid.clone(),
        session_id: sid,
        author: by.ua.clone(),
        nonce,
        epoch: parent.map_or(0, |p| p.epoch + 1),
        parent: parent.map_or(ZERO32.into(), |p| p.id.clone()),
        admins,
        members: ms
            .iter()
            .map(|a| Member {
                ua: a.ua.clone(),
                key_id: 1,
                via: ZERO32.into(),
            })
            .collect(),
        wrap_hashes: signed.wrap_hashes.clone(),
        sealed_info: unhex(sealed).unwrap(),
        sig_hash: hex(&[0x5e; 32]),
    };
    put_record(&w.net, HOME, &e);
    for (i, x) in wraps.iter().enumerate() {
        put_wrap(&w.net, HOME, &eid, i, x);
    }
    child(&w.net, HOME, &eid, ZERO32);
    complete(&w.net, &eid, true);
    Signed { e, k }
}

/// `epochComplete(epoch)` at HOME answers `yes`.
pub fn complete(net: &super::net::FakeNet, epoch: &str, yes: bool) {
    net.answer(
        HOME,
        "IPqChat.epochComplete",
        json!({ "epochId": epoch }),
        json!({ "0": yes }),
    );
}

/// `info` with `stores` and the Matrix map `matrix` (UA → id).
pub fn info(stores: Vec<Value>, matrix: &[(&Acc, &str)]) -> Value {
    let mut v = json!({"stores": stores, "name": "t8", "topic": "plan T8"});
    if !matrix.is_empty() {
        let m: serde_json::Map<String, Value> = matrix
            .iter()
            .map(|(a, id)| (a.ua.clone(), json!(id)))
            .collect();
        v["matrix"] = Value::Object(m);
    }
    v
}
