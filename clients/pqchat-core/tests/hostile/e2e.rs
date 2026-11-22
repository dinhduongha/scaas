// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The hostile harness's e2e writes (plan T11): records an honest client refuses to build or to send, made from the SDK's
//! generic entries and sent as prepared or raw calldata, never by `pqchat-core`'s write paths.
use crate::common::chain::CHAIN;
use crate::harness::World;
use pqchat_core::model::hex;
use pqchat_core::net::Net;
use pqchat_core::session::{Info, Me};
use pqchat_core::PqChat;
use scaas_sdk::app_core::{AppCall, AppUaSig};
use scaas_sdk::pqchat_keys::PqSessionNew;
use scaas_sdk::pqchat_records::{PqMemberKey, PqWrap};
use serde_json::{json, Value};

fn sig_json(s: &AppUaSig) -> Value {
    json!({"keyData": hex(&s.key_data), "signature": hex(&s.signature),
        "members": s.members.iter().map(|m| json!({"index": m.index.to_string(), "sig": hex(&m.sig),
            "members": m.members.iter().map(|x| json!({"index": x.index.to_string(), "sig": hex(&x.sig)}))
                .collect::<Vec<_>>()})).collect::<Vec<_>>()})
}

fn wrap_json(w: &PqWrap) -> Value {
    json!({"member": w.member, "keyId": w.key_id.to_string(), "mlkemCt": hex(&w.mlkem_ct),
        "x25519Eph": w.x25519_eph, "sealedKey": hex(&w.sealed_key)})
}

/// A session record of `by` with `nonce` naming `home` as its home, members `members` (with `by`) at their highest KEM
/// versions, real wraps of a fresh `K`, signed through the SDK's entry and prepared at `at` (any instance, listed or not).
pub async fn session_at(
    w: &World,
    pq: &PqChat,
    by: &Me,
    nonce: u64,
    home: &str,
    members: &[&Me],
    at: &str,
) -> AppCall {
    let seed = match &by.key {
        scaas_sdk::op::KeyRef::Ua { seed, .. } => seed.clone(),
        _ => unreachable!(),
    };
    let me = by.ua.to_ascii_lowercase();
    let sid = w.app.pqchat_session_id(me.clone(), nonce).unwrap();
    let k = w.app.pqchat_epoch_key(&seed).unwrap();
    let mut uas: Vec<String> = members.iter().map(|m| m.ua.clone()).collect();
    uas.push(me.clone());
    uas.sort();
    uas.dedup();
    let mut keys = vec![];
    let mut wraps = vec![];
    for ua in &uas {
        let ver = pq.kem_version(CHAIN, ua).await.unwrap().0;
        wraps.push(
            w.app
                .pqchat_wrap(
                    CHAIN.into(),
                    k.clone(),
                    sid.clone(),
                    sid.clone(),
                    ua.clone(),
                    ver,
                )
                .await
                .unwrap(),
        );
        keys.push(PqMemberKey {
            ua: ua.clone(),
            key_id: ver,
            via: pqchat_core::model::ZERO32.into(),
        });
    }
    let info = serde_json::to_string(&Info {
        stores: vec![w.chain_store(home)],
        name: "hostile".into(),
        topic: "hostile".into(),
        matrix: Default::default(),
    })
    .unwrap();
    let signed = w
        .app
        .pqchat_sign_session(
            by.key.clone(),
            k,
            PqSessionNew {
                nonce,
                home_chain: w.l.uid.clone(),
                home_chat_contract: home.to_ascii_lowercase(),
                admins: vec![me.clone()],
                members: keys.clone(),
                wraps: wraps.clone(),
                info_json: info,
            },
        )
        .await
        .unwrap();
    let sealed = signed
        .review
        .iter()
        .find(|f| f.name == "message.sealedInfo")
        .unwrap()
        .value
        .clone();
    let s = json!({"creator": me, "nonce": nonce.to_string(), "homeChain": w.l.uid,
        "homeChatContract": home.to_ascii_lowercase(), "admins": [me],
        "members": keys.iter().map(|k| json!({"ua": k.ua, "keyId": k.key_id.to_string(), "via": k.via})).collect::<Vec<_>>(),
        "wrapHashes": signed.wrap_hashes, "sealedInfo": sealed});
    let a = json!({"s": s, "wraps": wraps.iter().map(wrap_json).collect::<Vec<_>>(), "sig": sig_json(&signed.sig)});
    w.net
        .inner
        .prepare(CHAIN, at, "IPqChat.createSession", a, &w.l.payer)
        .await
        .unwrap()
}
