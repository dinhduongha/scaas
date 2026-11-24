// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The hostile harness's e2e writes (plan T11): records an honest client refuses to build or to send, made from the SDK's
//! generic entries and sent as prepared or raw calldata, never by `pqchat-core`'s write paths; envelopes an honest client never
//! seals, through the SDK's vectors build (a record signed by a UA other than its sender, a non-zero fill, a `sealedInfo` not
//! in canonical form).
use crate::common::chain::CHAIN;
use crate::harness::World;
use pqchat_core::model::hex;
use pqchat_core::net::Net;
use pqchat_core::session::{Info, Me};
use pqchat_core::PqChat;
use scaas_sdk::app_core::{AppCall, AppKey, AppUaSig};
use scaas_sdk::pqchat_keys::{PqMessageHeader, PqSealedMessage, PqSessionNew};
use scaas_sdk::pqchat_records::{PqChatMessage, PqMemberKey, PqWrap};
use serde_json::{json, Value};
use std::sync::Arc;

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
        .pqchat_prepare_session(
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
        .unwrap()
        .sign()
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
        "homeChatContract": home.to_ascii_lowercase(), "groupMode": "0", "admins": [me],
        "members": keys.iter().map(|k| json!({"ua": k.ua, "keyId": k.key_id.to_string(), "via": k.via})).collect::<Vec<_>>(),
        "wrapHashes": signed.wrap_hashes, "sealedInfo": sealed});
    let a = json!({"s": s, "wraps": wraps.iter().map(wrap_json).collect::<Vec<_>>(), "sig": sig_json(&signed.sig)});
    w.net
        .inner
        .prepare(CHAIN, at, "IPqChat.createSession", a, &w.l.payer)
        .await
        .unwrap()
}

/// `by`'s position on its chain `(sid, eid, device)` under `k` at `counter`, and the header of a message there.
fn at_counter(
    w: &World,
    by: &Me,
    k: &Arc<AppKey>,
    (sid, eid): (&str, &str),
    device: &str,
    counter: u64,
) -> (Arc<AppKey>, PqMessageHeader) {
    let p0 = w
        .app
        .pqchat_chain(
            k.clone(),
            sid.into(),
            eid.into(),
            by.ua.clone(),
            device.into(),
        )
        .unwrap();
    let pos = if counter == 0 {
        p0
    } else {
        w.app.pqchat_advance(p0, counter).unwrap()
    };
    let h = PqMessageHeader {
        session_id: sid.into(),
        epoch_id: eid.into(),
        device: device.into(),
        counter,
        parents: vec![],
    };
    (pos, h)
}

/// A message of `by` sealed through the SDK's S5 under `k` of `(sid, eid)` (no client counter spent, nothing shown).
pub async fn sealed(
    w: &World,
    by: &Me,
    k: &Arc<AppKey>,
    ids: (&str, &str),
    device: &str,
    counter: u64,
    content: &str,
) -> PqSealedMessage {
    let (pos, h) = at_counter(w, by, k, ids, device, counter);
    w.app
        .pqchat_seal_message(by.key.clone(), k.clone(), pos, h, content.into())
        .await
        .unwrap()
}

/// A record of `(sid, eid)` naming `sender` and signed by `signer` (the generic `prepare_pqchat_message`), its envelope under
/// `k`: what V1 refuses.
pub async fn signed_by_another(
    w: &World,
    signer: &Me,
    sender: &str,
    k: &Arc<AppKey>,
    (sid, eid): (&str, &str),
) -> Vec<u8> {
    let r = PqChatMessage {
        session_id: sid.into(),
        epoch_id: eid.into(),
        sender: sender.into(),
        device: format!("0x{}", "b3".repeat(16)),
        counter: 0,
        parents: vec![],
        ciphertext: vec![0x5a; 1040],
    };
    let sig = w
        .app
        .prepare_pqchat_message(signer.key.clone(), r.clone())
        .await
        .unwrap()
        .sign()
        .await
        .unwrap()
        .sig;
    w.app
        .pqchat_vectors_envelope(k.clone(), r, sig, [3; 12])
        .unwrap()
}

/// A message of `by` whose padded plaintext has one non-zero fill byte (its last), sealed under `mk` at its position.
pub async fn with_fill(
    w: &World,
    by: &Me,
    k: &Arc<AppKey>,
    ids: (&str, &str),
    device: &str,
    counter: u64,
    content: &str,
) -> PqSealedMessage {
    let (pos, h) = at_counter(w, by, k, ids, device, counter);
    let mut pt = scaas_ua::wallet::pqchat_keys::pad(content.as_bytes()).unwrap();
    *pt.last_mut().unwrap() = 1;
    w.app
        .pqchat_vectors_seal_padded(by.key.clone(), k.clone(), pos, h, pt, [12; 12])
        .await
        .unwrap()
}

/// A `sealedInfo` of `(sid, eid)` under `k` whose plaintext is `canonical` with one space after its first brace: padded as a
/// sealer pads, but not the canonical form K5 requires.
pub fn info_spaced(
    w: &World,
    k: &Arc<AppKey>,
    (sid, eid): (&str, &str),
    canonical: &[u8],
) -> Vec<u8> {
    let mut t = b"{ ".to_vec();
    t.extend_from_slice(&canonical[1..]);
    let pt = scaas_ua::wallet::pqchat_keys::pad(&t).unwrap();
    w.app
        .pqchat_vectors_seal_info_raw(k.clone(), sid.into(), eid.into(), pt, [11; 12])
        .unwrap()
}
