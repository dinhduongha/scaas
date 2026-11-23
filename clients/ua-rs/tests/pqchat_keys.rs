// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! PqChat's key entries (`scaas_ua::wallet::pqchat_keys`, pqchat-core spec §5 K2–K6, S1 / S2's seal, S5, V2): every row of
//! `smartcontracts/vectors/pqchat/` that crosses them reproduced through handles, and each refusal by name, one change at a
//! time beside its positive twin. Feature `app-core,vectors`.
#![cfg(all(feature = "app-core", feature = "vectors"))]
use scaas_ua::ua_portable::UASig;
use scaas_ua::wallet::pqchat_keys::{
    self as pk, canonical_json, decode_inner, decode_payload, encode_inner, encode_payload, pad,
    sig_hash, unpad, Header, WALK_MAX,
};
use scaas_ua::wallet::{AppKeys, Error, KemKeyPair, KemWrap, KeyHandle, KeyUsage, Wallet};
use serde_json::{json, Value};

const MNEMONIC: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";

fn pq(f: &str) -> Value {
    let p = format!(
        "{}/../../smartcontracts/vectors/pqchat/{f}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn a32(v: &Value) -> [u8; 32] {
    unhex(v).try_into().unwrap()
}
fn a16(v: &Value) -> [u8; 16] {
    unhex(v).try_into().unwrap()
}
fn a12(v: &Value) -> [u8; 12] {
    unhex(v).try_into().unwrap()
}
fn keys() -> (Wallet, AppKeys) {
    let w = Wallet::from_mnemonic(MNEMONIC, "").unwrap();
    let k = w.app_keys();
    (w, k)
}
fn epoch_key(k: &AppKeys, v: &Value) -> KeyHandle {
    k.vectors_import(&a32(v), KeyUsage::Derive).unwrap()
}
fn reveal(k: &AppKeys, h: &KeyHandle) -> Vec<u8> {
    k.vectors_reveal(h).unwrap()
}
fn header(r: &Value) -> Header {
    Header {
        session_id: a32(&r["sessionId"]),
        epoch_id: a32(&r["epochId"]),
        sender: a32(&r["sender"]),
        device: a16(&r["device"]),
        counter: r["counter"].as_u64().unwrap(),
        parents: r["parents"].as_array().unwrap().iter().map(a32).collect(),
    }
}
fn uasig(v: &Value) -> UASig {
    assert!(v["members"].as_array().unwrap().is_empty());
    UASig {
        key_data: unhex(&v["keyData"]),
        signature: unhex(&v["signature"]),
        members: vec![],
    }
}
fn kem_of(keys: &Value, name: &str) -> (Vec<u8>, KemKeyPair) {
    let k = keys["kemKeys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["name"] == name)
        .unwrap();
    let seed: [u8; 96] = [unhex(&k["mlkemSeed"]), unhex(&k["x25519Secret"])]
        .concat()
        .try_into()
        .unwrap();
    let pair = KemKeyPair::vectors_ephemeral(&seed).unwrap();
    assert_eq!(pair.kem_pk(), unhex(&k["kemPk"]));
    (unhex(&k["kemPk"]), pair)
}
fn position(k: &AppKeys, kk: &KeyHandle, h: &Header) -> KeyHandle {
    let p0 = k
        .pqchat_chain(kk, &h.session_id, &h.epoch_id, &h.sender, &h.device)
        .unwrap();
    k.pqchat_advance(&p0, h.counter).unwrap()
}

/// K2: every `wraps` row reproduced from `K` and fixed randomness, the scheme byte and `kemPkHash` built below; each
/// member's KEM key reopens `K`; every P14 refusal row refused by name (`KemCheck`), the valid rows wrap.
#[test]
fn wraps_and_p14() {
    let (_w, k) = keys();
    let keys = pq("keys");
    for r in keys["wraps"].as_array().unwrap() {
        let (kem_pk, pair) = kem_of(&keys, r["kemKey"].as_str().unwrap());
        let kk = epoch_key(&k, &r["K"]);
        let (s, e, m, id) = (
            a32(&r["sessionId"]),
            a32(&r["epochId"]),
            a32(&r["member"]),
            r["keyId"].as_u64().unwrap(),
        );
        let w = k
            .pqchat_vectors_wrap(
                &kk,
                &s,
                &e,
                &m,
                id,
                &kem_pk,
                &a32(&r["mlkemM"]),
                &a32(&r["x25519Secret"]),
            )
            .unwrap();
        assert_eq!(w.mlkem_ct, unhex(&r["ctM"]), "{}", r["name"]);
        assert_eq!(w.x25519_eph.to_vec(), unhex(&r["E"]), "{}", r["name"]);
        assert_eq!(w.sealed_key, unhex(&r["sealedKey"]), "{}", r["name"]);
        let back = k.pqchat_unwrap(&pair, &w, &s, &e, &m, id).unwrap();
        assert_eq!(reveal(&k, &back), unhex(&r["K"]), "{}", r["name"]);
        // the AAD binds the key version: another keyId does not open
        assert_eq!(
            k.pqchat_unwrap(&pair, &w, &s, &e, &m, id + 1).err(),
            Some(Error::Aead)
        );
        // a random wrap opens too (the positive control of the random path)
        let w2 = k.pqchat_wrap(&kk, &s, &e, &m, id, &kem_pk).unwrap();
        assert_eq!(
            reveal(&k, &k.pqchat_unwrap(&pair, &w2, &s, &e, &m, id).unwrap()),
            unhex(&r["K"])
        );
    }
    let kk = epoch_key(&k, &keys["wraps"][0]["K"]);
    for r in keys["p14"]["rows"].as_array().unwrap() {
        let got = k.pqchat_wrap(&kk, &[1; 32], &[2; 32], &[3; 32], 1, &unhex(&r["kemPk"]));
        if r.get("error").is_some() {
            assert_eq!(got.err(), Some(Error::KemCheck), "{}", r["name"]);
        } else {
            assert!(got.is_ok(), "{}", r["name"]);
        }
    }
}

/// K3: `ck_0` and every step's `ck` from one `advance` call; the counter-5,000 row in one call (CLI-PQC-14).
#[test]
fn chains_and_the_far_read() {
    let (_w, k) = keys();
    let m = pq("messages");
    for c in m["chains"].as_array().unwrap() {
        let kk = epoch_key(&k, &c["K"]);
        let p0 = k
            .pqchat_chain(
                &kk,
                &a32(&c["sessionId"]),
                &a32(&c["epochId"]),
                &a32(&c["sender"]),
                &a16(&c["device"]),
            )
            .unwrap();
        assert_eq!(reveal(&k, &p0), unhex(&c["ck0"]), "{}", c["name"]);
        for s in c["steps"].as_array().unwrap() {
            let i = s["i"].as_u64().unwrap();
            let p = k.pqchat_advance(&p0, i + 1).unwrap();
            assert_eq!(reveal(&k, &p), unhex(&s["ck"]), "{} step {i}", c["name"]);
        }
    }
    let f = &m["chainFar"];
    let kk = epoch_key(&k, &f["K"]);
    let p0 = k
        .pqchat_chain(
            &kk,
            &a32(&f["sessionId"]),
            &a32(&f["epochId"]),
            &a32(&f["sender"]),
            &a16(&f["device"]),
        )
        .unwrap();
    let p = k
        .pqchat_advance(&p0, f["counter"].as_u64().unwrap() + 1)
        .unwrap();
    assert_eq!(reveal(&k, &p), unhex(&f["ck"]));
    // two advances compose
    let half = k.pqchat_advance(&p0, 2500).unwrap();
    assert_eq!(
        reveal(&k, &k.pqchat_advance(&half, 2501).unwrap()),
        unhex(&f["ck"])
    );
}

/// The walk bound (CLI-PQC-14): `WALK_MAX` steps walk, one more is `PqChatTooFar` before any step.
#[test]
fn the_walk_bound() {
    let (_w, k) = keys();
    let kk = k.random_key(KeyUsage::Derive).unwrap();
    let p0 = k
        .pqchat_chain(&kk, &[1; 32], &[2; 32], &[3; 32], &[4; 16])
        .unwrap();
    assert_eq!(
        k.pqchat_advance(&p0, WALK_MAX + 1).err(),
        Some(Error::PqChatTooFar)
    );
    assert!(k.pqchat_advance(&p0, WALK_MAX).is_ok());
}

/// Padding rows; `unpad`'s refusal rows each refused by name, each twin opens.
#[test]
fn padding_rows_and_unpad_refusals() {
    let m = pq("messages");
    for p in m["padding"].as_array().unwrap() {
        let n = p["length"].as_u64().unwrap() as usize;
        let content: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        let pt = pad(&content).unwrap();
        assert_eq!(pt.len() as u64, p["paddedLength"].as_u64().unwrap());
        assert_eq!(pt[..4].to_vec(), unhex(&p["prefix"]));
        assert_eq!(scaas_ua::keccak256(&pt).to_vec(), unhex(&p["ptKeccak256"]));
        assert_eq!(*unpad(&pt).unwrap(), content);
    }
    let rows = m["unpadRefused"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    for r in rows {
        assert_eq!(
            unpad(&unhex(&r["pt"])).err(),
            Some(Error::PqChatContent),
            "{}",
            r["name"]
        );
        assert_eq!(
            *unpad(&unhex(&r["twin"])).unwrap(),
            unhex(&r["content"]),
            "{}",
            r["name"]
        );
    }
}

/// Canonical JSON rows (UTF-16 key order, escapes, the safe-integer bound); the refused rows `PqChatContent`.
#[test]
fn canonical_json_rows() {
    let m = pq("messages");
    for r in m["canonicalJson"].as_array().unwrap() {
        let v: Value = serde_json::from_str(r["input"].as_str().unwrap()).unwrap();
        assert_eq!(
            canonical_json(&v).unwrap(),
            r["canonical"].as_str().unwrap(),
            "{}",
            r["name"]
        );
    }
    for r in m["canonicalRefused"].as_array().unwrap() {
        let v: Value = serde_json::from_str(r["input"].as_str().unwrap()).unwrap();
        assert_eq!(
            canonical_json(&v).err(),
            Some(Error::PqChatContent),
            "{}",
            r["name"]
        );
    }
}

/// S5 and K4: the message's ciphertext and id from the content value at its counter; the vector's inner bytes decode to
/// its record and `UASig` and re-encode; the envelope, hint and payload rows; the envelope and the message open back.
#[test]
fn message_envelope_payload() {
    let (w, k) = keys();
    let (m, rec) = (pq("messages"), pq("records"));
    let r = &rec["message"];
    let h = header(&r["record"]);
    let kk = epoch_key(&k, &m["message"]["K"]);
    let pos = position(&k, &kk, &h);
    let signer = w.ua_key(0x0131, 0, 0).unwrap();
    let content = m["message"]["content"].as_str().unwrap();
    let s = k
        .pqchat_vectors_seal_message(
            &kk,
            &pos,
            &h,
            content.as_bytes(),
            &signer,
            &a12(&m["envelope"]["nonce"]),
        )
        .unwrap();
    assert_eq!(s.ciphertext, unhex(&m["message"]["ciphertext"]));
    assert_eq!(s.message_id.to_vec(), unhex(&r["id"]));
    assert_eq!(s.hint.to_vec(), unhex(&m["envelope"]["hint"]));
    assert_eq!(pk::message_aad(&h), unhex(&m["message"]["aad"]));
    // a content value with another key order and whitespace seals to the same bytes (canonicalised in ua-rs)
    let loose = "{ \"type\": \"text\", \"body\": \"Hello from the PqChat vectors.\" }";
    let s2 = k
        .pqchat_vectors_seal_message(&kk, &pos, &h, loose.as_bytes(), &signer, &[0; 12])
        .unwrap();
    assert_eq!(s2.ciphertext, s.ciphertext);
    // the vector's own signed inner bytes
    let inner = unhex(&m["envelope"]["inner"]);
    let d = decode_inner(&inner).unwrap();
    assert_eq!(d.header, h);
    assert_eq!(d.ciphertext, s.ciphertext);
    assert_eq!(d.sig, uasig(&r["uaSig"]));
    assert_eq!(sig_hash(&d.sig).to_vec(), unhex(&r["sigHash"]));
    assert_eq!(encode_inner(&d.header, &d.ciphertext, &d.sig), inner);
    let (s_, e_) = (
        a32(&m["envelope"]["sessionId"]),
        a32(&m["envelope"]["epochId"]),
    );
    let env = k
        .pqchat_vectors_envelope(&kk, &s_, &e_, &inner, &a12(&m["envelope"]["nonce"]))
        .unwrap();
    assert_eq!(env, unhex(&m["envelope"]["env"]));
    let payload = encode_payload(&s.hint, &env);
    assert_eq!(payload, unhex(&m["payload"]["payload"]));
    assert_eq!(decode_payload(&payload).unwrap(), (s.hint, env.clone()));
    assert_eq!(k.pqchat_open_envelope(&kk, &s_, &e_, &env).unwrap(), d);
    // S5's own envelope opens to its own record, signed by the signer
    let own = k.pqchat_open_envelope(&kk, &s_, &e_, &s.env).unwrap();
    assert_eq!(
        (own.ciphertext.clone(), own.sig.clone()),
        (s.ciphertext.clone(), s.sig.clone())
    );
    assert_eq!(decode_payload(&s.payload).unwrap(), (s.hint, s.env.clone()));
    let pt = k.pqchat_open_message(&pos, &h, &d.ciphertext).unwrap();
    assert_eq!(pt.as_slice(), content.as_bytes());
}

/// S1 / S2's seal and K5: each `sealedInfo` row from its info value and nonce; it opens to its canonical JSON.
#[test]
fn sealed_info_rows() {
    let (_w, k) = keys();
    for r in pq("messages")["sealedInfo"].as_array().unwrap() {
        let kk = epoch_key(&k, &r["K"]);
        let (s, e) = (a32(&r["sessionId"]), a32(&r["epochId"]));
        let info = serde_json::to_vec(&r["info"]).unwrap();
        let sealed = k
            .pqchat_vectors_seal_info(&kk, &s, &e, &info, &a12(&r["nonce"]))
            .unwrap();
        assert_eq!(sealed, unhex(&r["sealedInfo"]), "{}", r["name"]);
        let open = k.pqchat_open_info(&kk, &s, &e, &sealed).unwrap();
        assert_eq!(
            open.as_slice(),
            r["json"].as_str().unwrap().as_bytes(),
            "{}",
            r["name"]
        );
        // a random nonce opens too; another epoch's key does not
        let again = k.pqchat_seal_info(&kk, &s, &e, &info).unwrap();
        assert_eq!(
            k.pqchat_open_info(&kk, &s, &e, &again).unwrap().as_slice(),
            open.as_slice()
        );
        assert_eq!(
            k.pqchat_open_info(&kk, &s, &[9; 32], &sealed).err(),
            Some(Error::Aead)
        );
    }
}

/// The refusals of the entries, one change at a time beside their positive twins.
#[test]
fn refusals_one_change_at_a_time() {
    let (w, k) = keys();
    let (m, rec) = (pq("messages"), pq("records"));
    let h = header(&rec["message"]["record"]);
    let kk = epoch_key(&k, &m["message"]["K"]);
    let pos = position(&k, &kk, &h);
    let signer = w.ua_key(0x0131, 0, 0).unwrap();
    let content = br#"{"body":"x","type":"text"}"#;
    assert!(k
        .pqchat_seal_message(&kk, &pos, &h, content, &signer)
        .is_ok());

    // the hint: on an epoch key yes; on a chain position or a derived key no (spec §5.3 item 3)
    assert!(k.pqchat_hint(&kk).is_ok());
    assert_eq!(k.pqchat_hint(&pos).err(), Some(Error::AppKeyUsage));
    let derived = k
        .derive(&[&kk], &[], b"scaas/pqchat/v1/x", KeyUsage::Derive, false)
        .unwrap();
    assert_eq!(k.pqchat_hint(&derived).err(), Some(Error::AppKeyUsage));
    assert_eq!(
        k.mac_public(&pos, b"scaas/pqchat/v1/hint", 8).err(),
        Some(Error::AppKeyUsage)
    );

    // advance: a position yes; an epoch key or a derived key no; another scope's position no
    assert!(k.pqchat_advance(&pos, 1).is_ok());
    assert_eq!(k.pqchat_advance(&kk, 1).err(), Some(Error::AppKeyUsage));
    assert_eq!(
        k.pqchat_advance(&derived, 1).err(),
        Some(Error::AppKeyUsage)
    );
    let other = w.app_keys();
    assert_eq!(
        other.pqchat_advance(&pos, 1).err(),
        Some(Error::AppHandleForeign)
    );

    // a position at another counter, or of another chain, opens nothing (Argument before any AEAD)
    let s = k
        .pqchat_seal_message(&kk, &pos, &h, content, &signer)
        .unwrap();
    assert!(k.pqchat_open_message(&pos, &h, &s.ciphertext).is_ok());
    let next = k.pqchat_advance(&pos, 1).unwrap();
    assert_eq!(
        k.pqchat_open_message(&next, &h, &s.ciphertext).err(),
        Some(Error::Argument)
    );
    let mut h2 = h.clone();
    h2.device = [7; 16];
    assert_eq!(
        k.pqchat_open_message(&pos, &h2, &s.ciphertext).err(),
        Some(Error::Argument)
    );

    // parents: at most 8, strictly sorted
    let mut hp = h.clone();
    hp.parents = (1..=8u8).map(|i| [i; 32]).collect();
    assert!(k
        .pqchat_seal_message(&kk, &pos, &hp, content, &signer)
        .is_ok());
    hp.parents.push([9; 32]);
    assert_eq!(
        k.pqchat_seal_message(&kk, &pos, &hp, content, &signer)
            .err(),
        Some(Error::Argument)
    );
    hp.parents = vec![[2; 32], [1; 32]];
    assert_eq!(
        k.pqchat_seal_message(&kk, &pos, &hp, content, &signer)
            .err(),
        Some(Error::Argument)
    );

    // a native signer is refused (a single UA key only, CLI-SDK-30 (i))
    let nat = w
        .native_key(scaas_ua::wallet::Network::Evm, 0, None)
        .unwrap();
    assert_eq!(
        k.pqchat_seal_message(&kk, &pos, &h, content, &nat).err(),
        Some(Error::Argument)
    );

    // the epoch key is a Derive handle: a Data handle of the same bytes is refused (the usage enters no byte)
    let data = k
        .vectors_import(&a32(&m["message"]["K"]), KeyUsage::Data)
        .unwrap();
    assert_eq!(k.pqchat_hint(&data).err(), Some(Error::AppKeyUsage));

    // content: depth 16 seals, depth 17 does not; a non-canonical content does not open
    let deep = |d: usize| format!("{}1{}", "[".repeat(d), "]".repeat(d));
    assert!(k
        .pqchat_seal_message(&kk, &pos, &h, deep(16).as_bytes(), &signer)
        .is_ok());
    assert_eq!(
        k.pqchat_seal_message(&kk, &pos, &h, deep(17).as_bytes(), &signer)
            .err(),
        Some(Error::PqChatContent)
    );
}

/// The canonical check on open: a ciphertext of padded, non-canonical JSON is refused (`PqChatContent`), its canonical twin
/// opens; a padded text with a non-zero fill is refused. Sealed here through the generic `seal` of the same key bytes, the
/// way a hostile sender would (`mk`, `n` from the vector chain).
#[test]
fn the_canonical_check_and_unpad_on_open() {
    let (_w, k) = keys();
    let m = pq("messages");
    let h = header(&pq("records")["message"]["record"]);
    let kk = epoch_key(&k, &m["message"]["K"]);
    let pos = position(&k, &kk, &h);
    let mk: [u8; 32] = a32(&m["message"]["mk"]);
    let n = a12(&m["message"]["n"]);
    let seal = |pt: &[u8]| {
        scaas_ua::wallet::aead_seal(
            scaas_ua::wallet::Alg::Aes256GcmSiv,
            &mk,
            &n,
            &pk::message_aad(&h),
            pt,
        )
        .unwrap()
    };
    let canon = br#"{"body":"x","type":"text"}"#;
    assert_eq!(
        k.pqchat_open_message(&pos, &h, &seal(&pad(canon).unwrap()))
            .unwrap()
            .as_slice(),
        canon
    );
    let loose = br#"{"type":"text","body":"x"}"#;
    assert_eq!(
        k.pqchat_open_message(&pos, &h, &seal(&pad(loose).unwrap()))
            .err(),
        Some(Error::PqChatContent)
    );
    let mut fill = pad(canon).unwrap();
    fill[200] = 1;
    assert_eq!(
        k.pqchat_open_message(&pos, &h, &seal(&fill)).err(),
        Some(Error::PqChatContent)
    );
}

/// V2: truncated, extended, non-canonical and over-long inputs refused; the vector decodes.
#[test]
fn bounded_decoders() {
    let m = pq("messages");
    let inner = unhex(&m["envelope"]["inner"]);
    assert!(decode_inner(&inner).is_ok());
    assert_eq!(
        decode_inner(&inner[..inner.len() - 1]).err(),
        Some(Error::Argument)
    );
    assert_eq!(
        decode_inner(&[&inner[..], &[0; 32]].concat()).err(),
        Some(Error::Argument)
    );
    let mut bad = inner.clone();
    bad[31] = 0x60; // the record's offset moved
    assert_eq!(decode_inner(&bad).err(), Some(Error::Argument));
    // a members list longer than the bound
    let mut d = decode_inner(&inner).unwrap();
    d.sig.members = (0..17)
        .map(|i| scaas_ua::ua_portable::MemberSig {
            index: i,
            members: vec![],
            sig: vec![1],
        })
        .collect();
    assert_eq!(
        decode_inner(&encode_inner(&d.header, &d.ciphertext, &d.sig)).err(),
        Some(Error::Argument)
    );
    d.sig.members.truncate(16);
    assert!(decode_inner(&encode_inner(&d.header, &d.ciphertext, &d.sig)).is_ok());
    let payload = unhex(&m["payload"]["payload"]);
    assert!(decode_payload(&payload).is_ok());
    assert_eq!(
        decode_payload(&payload[..payload.len() - 32]).err(),
        Some(Error::Argument)
    );
    let mut v2 = payload.clone();
    v2[31] = 2;
    assert_eq!(decode_payload(&v2).err(), Some(Error::Argument));
    assert_eq!(
        decode_payload(&encode_payload(&[1; 8], &[])).err(),
        Some(Error::Argument)
    );
}

#[allow(dead_code)]
fn _types(_: KemWrap) {}

/// V1: every record row with a signature (the control-plane records, the message and the topic records; CTR-CHAT-23: an
/// `sstore2` instance keeps the control-plane signatures in state) verifies against its signer's record as `requirePortable`
/// judges it; one change at a time (a signature byte, another signer's UA, a native id, a struct outside the records, a
/// control-plane record's `sealedInfo` or another field) does not.
#[test]
fn v1_verifies_the_record_rows() {
    use scaas_ua::wallet::{pqchat, AppRecordState};
    let (rec, top) = (pq("records"), pq("topics"));
    let signers: Vec<Value> = rec["signers"].as_array().unwrap().clone();
    let reg = |id: [u8; 32]| {
        signers
            .iter()
            .find(|s| a32(&s["ua"]) == id)
            .map(|s| (s["kind"].as_u64().unwrap() as u16, unhex(&s["publicKey"])))
    };
    let current = |_: [u8; 32]| None;
    let accepted = |_: [u8; 32], _: u16| false;
    let state = AppRecordState {
        members: &reg,
        current: &current,
        accepted: &accepted,
        domain: None,
    };
    let ua_of = |name: &str| a32(&signers.iter().find(|s| s["name"] == name).unwrap()["ua"]);
    let rows = [
        (&rec, "session", "PqChatSession"),
        (&rec, "epoch", "PqChatEpoch"),
        (&rec, "leave", "PqChatLeave"),
        (&rec, "remove", "PqChatRemove"),
        (&rec, "message", "PqChatMessage"),
        (&top, "topic", "PqTopic"),
        (&top, "post", "PqTopicEntry"),
        (&top, "reply", "PqTopicEntry"),
        (&top, "edit", "PqTopicEdit"),
        (&top, "vote", "PqTopicVote"),
    ];
    for (v, row, name) in rows {
        let r = &v[row];
        let td = pqchat::typed(name, r["record"].clone()).unwrap();
        let ua = ua_of(r["signer"].as_str().unwrap());
        let sig = uasig(&r["uaSig"]);
        assert!(pqchat::verify(&ua, &td, &sig, &state), "{row}");
        // CTR-CHAT-23: the threat a kept signature closes, a field the endpoint substitutes (a store list of its own in
        // `sealedInfo`, a member it adds) under the record's own signature
        for field in ["sealedInfo", "nonce"] {
            if let Some(x) = r["record"].get(field) {
                let mut changed = r["record"].clone();
                changed[field] = if x.is_string() {
                    json!("0xbad0")
                } else {
                    json!(x.as_u64().unwrap() + 1)
                };
                let td2 = pqchat::typed(name, changed).unwrap();
                assert!(
                    !pqchat::verify(&ua, &td2, &sig, &state),
                    "{row}: {field} changed"
                );
            }
        }
        let mut bad = sig.clone();
        bad.signature[0] ^= 1;
        assert!(
            !pqchat::verify(&ua, &td, &bad, &state),
            "{row}: a flipped byte"
        );
        let other = signers
            .iter()
            .map(|s| a32(&s["ua"]))
            .find(|u| *u != ua)
            .unwrap();
        assert!(
            !pqchat::verify(&other, &td, &sig, &state),
            "{row}: another signer"
        );
        let mut native = [0u8; 32];
        native[31] = 1;
        assert!(
            !pqchat::verify(&native, &td, &sig, &state),
            "{row}: a native id"
        );
    }
    let w = pqchat::typed("Wrap", pq("keys")["wraps"][0]["wrap"].clone()).unwrap();
    let r = &rec["message"];
    assert!(!pqchat::verify(
        &ua_of(r["signer"].as_str().unwrap()),
        &w,
        &uasig(&r["uaSig"]),
        &state
    ));
}

/// The contact card (UA-7 §14 O7): every row of cards.json reproduces (struct hash, typed and `uaMessage` digests) and
/// verifies for its UA against its signer's record; each refused row fails beside its passing twin; the Matrix id rows.
#[test]
fn cards_reproduce_the_rows() {
    use scaas_ua::wallet::pqchat::{self, Card};
    use scaas_ua::wallet::AppRecordState;
    let (rec, c) = (pq("records"), pq("cards"));
    let signers: Vec<Value> = rec["signers"].as_array().unwrap().clone();
    let reg = |id: [u8; 32]| {
        signers
            .iter()
            .find(|s| a32(&s["ua"]) == id)
            .map(|s| (s["kind"].as_u64().unwrap() as u16, unhex(&s["publicKey"])))
    };
    let current = |_: [u8; 32]| None;
    let accepted = |_: [u8; 32], _: u16| false;
    let state = AppRecordState {
        members: &reg,
        current: &current,
        accepted: &accepted,
        domain: None,
    };
    let card = |r: &Value| Card {
        ua: a32(&r["ua"]),
        kem_version: r["kemVersion"].as_u64().unwrap(),
        matrix_id: r["matrixId"].as_str().unwrap().to_string(),
    };
    let rows = c["cards"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for r in rows {
        let k = card(&r["record"]);
        let td = pqchat::card_typed(&k).unwrap();
        assert_eq!(td.struct_hash().unwrap(), a32(&r["hashStruct"]));
        assert_eq!(td.digest().unwrap(), a32(&r["typed"]));
        let kind = r["uaMessage"]["kind"].as_u64().unwrap() as u16;
        let m = scaas_ua::ua_message(kind, &pqchat::purpose(), &td.digest().unwrap()).unwrap();
        assert_eq!(m, a32(&r["uaMessage"]["digest"]));
        assert!(pqchat::verify_card(&k.ua, &k, &uasig(&r["uaSig"]), &state));
    }
    let refused = c["refused"].as_array().unwrap();
    assert_eq!(refused.len(), 3);
    for r in refused {
        let name = r["name"].as_str().unwrap();
        let t = &r["twin"];
        assert!(
            pqchat::verify_card(
                &a32(&t["ua"]),
                &card(&t["record"]),
                &uasig(&t["uaSig"]),
                &state
            ),
            "{name}: the twin"
        );
        assert!(
            !pqchat::verify_card(
                &a32(&r["ua"]),
                &card(&r["record"]),
                &uasig(&r["uaSig"]),
                &state
            ),
            "{name}"
        );
    }
    for id in c["matrixIdAccepted"].as_array().unwrap() {
        assert_eq!(pqchat::check_matrix_id(id.as_str().unwrap()), Ok(()));
    }
    for r in c["matrixIdRefused"].as_array().unwrap() {
        let name = r["name"].as_str().unwrap();
        assert_eq!(
            pqchat::check_matrix_id(r["id"].as_str().unwrap()),
            Err(Error::Argument),
            "{name}"
        );
        assert_eq!(
            pqchat::check_matrix_id(r["twin"].as_str().unwrap()),
            Ok(()),
            "{name}: the twin"
        );
        let mut k = card(&rows[0]["record"]);
        k.matrix_id = r["id"].as_str().unwrap().into();
        assert!(pqchat::card_typed(&k).is_err(), "{name}: no card");
    }
}

/// pqchat-core T10b (owner 2026-11-22): the `file` content rows. (a) the sealer is given every field but the key and a `File`
/// handle; the key enters the content here: the row's ciphertext and id; the content opens to the row's. (b) the reader opens
/// the object named by the opened content: its length and `ctSha256` before decryption, then the frame and `sha256`; every
/// refusal row by name (clientkeys' "file" is `PqChatContent`), each beside its twin; PqChat's app id.
#[cfg(feature = "fam-arweave")] // the row's object by seal_for_arweave; the calls under test need only app-core
#[test]
fn file_message_rows() {
    use scaas_ua::arweave::SigType;
    use scaas_ua::wallet::pqchat_file::pqchat_open_file;
    let (w, k) = keys();
    let (m, rec) = (pq("messages"), pq("records"));
    let f = &m["fileMessage"];
    assert_eq!(
        scaas_ua::wallet::pqchat::app_id().to_vec(),
        unhex(&rec["appId"]["hash"])
    );
    let h = header(&f["record"]);
    let kk = epoch_key(&k, &f["K"]);
    let pos = position(&k, &kk, &h);
    let signer = w.ua_key(0x0131, 0, 0).unwrap();
    let fk = || {
        k.vectors_import(&a32(&f["fileKey"]), KeyUsage::File)
            .unwrap()
    };
    let sealed = f["sealed"].as_str().unwrap().as_bytes();
    let nonce = a12(&f["envNonce"]);
    let s = k
        .pqchat_vectors_seal_file_message(&kk, &pos, &h, sealed, &fk(), &signer, &nonce)
        .unwrap();
    assert_eq!(s.ciphertext, unhex(&f["record"]["ciphertext"]));
    assert_eq!(s.message_id.to_vec(), unhex(&f["id"]));
    let content = k.pqchat_open_message(&pos, &h, &s.ciphertext).unwrap();
    assert_eq!(
        content.as_slice(),
        f["content"].as_str().unwrap().as_bytes()
    );
    let (s_, e_) = (h.session_id, h.epoch_id);
    let env = k
        .pqchat_vectors_envelope(&kk, &s_, &e_, &unhex(&f["inner"]), &nonce)
        .unwrap();
    assert_eq!(env, unhex(&f["env"]));
    // the object of the row, padded to its bucket inside the AEAD
    let root = k
        .vectors_import(&a32(&f["appRoot"]), KeyUsage::Derive)
        .unwrap();
    let file = unhex(&f["file"]);
    let a = k
        .vectors_seal_for_arweave(&root, fk(), &file, SigType::Ed25519)
        .unwrap();
    assert_eq!(a.url, f["url"].as_str().unwrap());
    assert_eq!(a.ct_sha256.to_vec(), unhex(&f["ctSha256"]));
    let object = a.item.data().to_vec();
    assert_eq!(object.len() as u64, f["objectLength"].as_u64().unwrap());
    assert_eq!(&pqchat_open_file(&content, &object).unwrap()[..], &file[..]);
    let code = |c: &str| {
        if c == "file" {
            "PqChatContent".to_string()
        } else {
            c.to_string()
        }
    };
    for r in m["fileOpenRefused"].as_array().unwrap() {
        let mut o = object.clone();
        match r["change"].as_str() {
            Some("drop-last") => drop(o.pop()),
            Some("append-zero") => o.push(0),
            Some("flip-1000") => o[1000] ^= 1,
            _ => {}
        }
        let c = match r.get("content") {
            Some(v) => canonical_json(v).unwrap().into_bytes(),
            None => content.to_vec(),
        };
        let got = pqchat_open_file(&c, &o);
        match r["code"].as_str() {
            None => assert_eq!(&got.unwrap()[..], &file[..], "{}", r["name"]),
            Some(x) => assert_eq!(got.unwrap_err().code(), code(x), "{}", r["name"]),
        }
    }
    for r in m["fileContentRefused"].as_array().unwrap() {
        let c = canonical_json(&r["content"]).unwrap();
        assert_eq!(
            pqchat_open_file(c.as_bytes(), &object).err(),
            Some(Error::PqChatContent),
            "{}",
            r["name"]
        );
        let t = canonical_json(&r["twin"]).unwrap();
        assert!(
            pqchat_open_file(t.as_bytes(), &object).is_ok(),
            "{}",
            r["name"]
        );
    }
    for r in m["fileSealRefused"].as_array().unwrap() {
        let c = serde_json::to_vec(&r["content"]).unwrap();
        assert_eq!(
            k.pqchat_seal_file_message(&kk, &pos, &h, &c, &fk(), &signer)
                .err(),
            Some(Error::PqChatContent),
            "{}",
            r["name"]
        );
        let t = serde_json::to_vec(&r["twin"]).unwrap();
        assert!(k
            .pqchat_seal_file_message(&kk, &pos, &h, &t, &fk(), &signer)
            .is_ok());
    }
    // the key handle is a File key: another usage is refused before anything is sealed
    let data = k.random_key(KeyUsage::Data).unwrap();
    assert_eq!(
        k.pqchat_seal_file_message(&kk, &pos, &h, sealed, &data, &signer)
            .err(),
        Some(Error::AppKeyUsage)
    );
    // the sealed message holds no key byte outside its ciphertext: the key is only inside the content
    let key = unhex(&f["fileKey"]);
    for b in [&s.inner, &s.env, &s.payload] {
        assert!(!b.windows(32).any(|x| x == &key[..]));
    }
}
