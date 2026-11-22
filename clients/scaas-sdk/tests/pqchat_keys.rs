// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! pqchat-core T1's SDK rows (pqchat-core spec §5 K1–K6, S1 / S2 / S5, V1 / V2; feature `pqchat-records` with `vectors`): every
//! row of `smartcontracts/vectors/pqchat/` that crosses the key entries reproduced through the SDK's surface only (no direct
//! `scaas-ua` call), each refusal by name, one change at a time beside its positive twin, and `read_app` on the fake chain.
#![cfg(all(feature = "pqchat-records", feature = "vectors"))]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]
#[path = "common/fake_chain.rs"]
mod fake_chain;

use fake_chain::{fake, keccak_hex, serve, Fake};
use scaas_sdk::app_core::{AppCore, AppDesc, AppKeyUsage, AppPath, AppUaSig};
use scaas_sdk::op::KeyRef;
use scaas_sdk::pqchat_keys::{PqMessageHeader, PqSessionNew};
use scaas_sdk::pqchat_records::{PqChatMessage, PqMemberKey, PqWrap};
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, Sdk, SdkConfig, SdkError,
};
use scaas_ua::wallet::{SecretBytes, Wallet};
use serde_json::{json, Value};
use std::sync::Arc;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const REGISTRY: &str = "0x5ca00000000000000000000000000000000000a1";
const APP_ID: &str = "0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const VIEW: &str = "0x00000000000000000000000000000000000000ab";
const PQC: &str = "scaas/pqchat/v1/";

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
fn dehex(s: &str) -> Vec<u8> {
    let h = s.trim_start_matches("0x");
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}
fn unhex(v: &Value) -> Vec<u8> {
    dehex(v.as_str().unwrap())
}
fn a32(v: &Value) -> [u8; 32] {
    unhex(v).try_into().unwrap()
}
fn a12(v: &Value) -> [u8; 12] {
    unhex(v).try_into().unwrap()
}
fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn sec(s: &str) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(s.as_bytes().to_vec())).unwrap())
}
fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}
fn revealed(a: &AppCore, k: &Arc<scaas_sdk::app_core::AppKey>) -> Vec<u8> {
    a.vectors_reveal(k.clone()).unwrap()
}
fn ua(seed: &str, kind: u16) -> KeyRef {
    KeyRef::Ua {
        seed: seed.into(),
        kind,
        account: 0,
        index: 0,
    }
}
/// One live scope declares PqChat's prefix at a time (spec §12.3: overlapping live prefixes are refused): the tests that
/// make one hold this lock.
static ONE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
fn desc(labels: &[&str]) -> AppDesc {
    AppDesc {
        app_id: Some(APP_ID.into()),
        name: "PqChat".into(),
        class: None,
        labels: labels.iter().map(|s| s.to_string()).collect(),
    }
}
fn profile(url: String, genesis: String) -> ChainProfile {
    ChainProfile {
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
        disabled_kinds: vec![],
        family_params: None,
    }
}
/// The SDK on the fake chain, the repository mnemonic imported (its `0x0131` account 0 is the vectors' `alice`).
async fn on_fake() -> (Arc<Sdk>, String, Fake) {
    let chain = fake();
    let url = serve(chain.clone()).await;
    let genesis = chain.lock().unwrap().genesis.clone();
    let s = Sdk::open(SdkConfig {
        profiles: vec![profile(url, genesis)],
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
    let seed = s
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words: sec(REPO),
            vault_passphrase: sec(PASS),
        })
        .await
        .unwrap()
        .id;
    (s, seed, chain)
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
fn sel(sig: &str) -> String {
    keccak_hex(sig.as_bytes())[..10].to_string()
}
fn answer(c: &Fake, to: &str, sig: &str, arg: &[u8], out: String) {
    let mut c = c.lock().unwrap();
    let prefix = format!("{}{}", sel(sig), hexs(arg));
    c.answers.retain(|(t, d, _)| !(t == to && *d == prefix));
    c.answers.push((to.into(), prefix, format!("0x{out}")));
}
fn word32(n: u64) -> Vec<u8> {
    let mut v = [0u8; 32];
    v[24..].copy_from_slice(&n.to_be_bytes());
    v.to_vec()
}
fn kem_answer(c: &Fake, id: &[u8; 32], v: u64, kem_pk: &[u8]) {
    let (ek, x) = (&kem_pk[1..1 + 1568], &kem_pk[1 + 1568..]);
    let sig_at = 0x40 + 0x60 + 0x20 + pad(ek).len() as u64 / 2;
    let out = format!(
        "{}{}{}{}{}{}{}{}",
        w(0x40),
        w(sig_at),
        w(1),
        w(0x60),
        hexs(x),
        w(ek.len() as u64),
        pad(ek),
        w(0)
    );
    answer(
        c,
        REGISTRY,
        "kemKeyAt(bytes32,uint64)",
        &[id.to_vec(), word32(v)].concat(),
        out,
    );
}
fn reg_answer(c: &Fake, id: &[u8; 32], kind: u16, kd: &[u8]) {
    let out = format!(
        "{}{}{}{}{}{}{}",
        w(u64::from(kind)),
        w(0xa0),
        w(0),
        w(0),
        w(0),
        w(kd.len() as u64),
        pad(kd)
    );
    answer(c, REGISTRY, "registrationOf(bytes32)", id, out);
}
fn kem_seed(keys: &Value, name: &str) -> (Vec<u8>, Vec<u8>) {
    let k = keys["kemKeys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["name"] == name)
        .unwrap();
    (
        [unhex(&k["mlkemSeed"]), unhex(&k["x25519Secret"])].concat(),
        unhex(&k["kemPk"]),
    )
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
fn sig_of(v: &Value) -> AppUaSig {
    AppUaSig {
        key_data: unhex(&v["keyData"]),
        signature: unhex(&v["signature"]),
        members: vec![],
    }
}

/// K1, K2: every `wraps` row from `K` and fixed randomness; the member's KEM key reopens `K`; every P14 row by name
/// (`KemCheck`); the real wrap reads the member's key at the final block and the account unwraps it; `wrap.member` other than
/// the account's UA refused (`Argument`) beside its twin.
#[tokio::test(flavor = "multi_thread")]
async fn wraps_p14_and_the_account_unwrap() {
    let _one = ONE.lock().await;
    let (sdk, seed, chain) = on_fake().await;
    let a = AppCore::new(sdk, desc(&[PQC])).unwrap();
    let keys = pq("keys");
    for r in keys["wraps"].as_array().unwrap() {
        let (kseed, kem_pk) = kem_seed(&keys, r["kemKey"].as_str().unwrap());
        let k = a
            .vectors_import(&seed, a32(&r["K"]), AppKeyUsage::Derive)
            .unwrap();
        let (sid, eid, m, id) = (
            s(&r["sessionId"]),
            s(&r["epochId"]),
            s(&r["member"]),
            r["keyId"].as_u64().unwrap(),
        );
        let wr = a
            .pqchat_vectors_wrap(
                k.clone(),
                sid.clone(),
                eid.clone(),
                m.clone(),
                id,
                kem_pk,
                a32(&r["mlkemM"]),
                a32(&r["x25519Secret"]),
            )
            .unwrap();
        assert_eq!(wr.mlkem_ct, unhex(&r["ctM"]), "{}", r["name"]);
        assert_eq!(wr.x25519_eph, s(&r["E"]), "{}", r["name"]);
        assert_eq!(wr.sealed_key, unhex(&r["sealedKey"]), "{}", r["name"]);
        let back = a.pqchat_vectors_unwrap(&seed, kseed, sid, eid, wr).unwrap();
        assert_eq!(revealed(&a, &back), unhex(&r["K"]));
    }
    let k = a.pqchat_epoch_key(&seed).unwrap();
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
        let want = if r.get("error").is_some() {
            "KemCheck"
        } else {
            "Ok"
        };
        assert_eq!(code(got), want, "{}", r["name"]);
    }
    // the real path: the member's key read from the registry, the account's own KEM key reopens it
    let wl = Wallet::from_mnemonic(REPO, "").unwrap();
    let uk = wl.ua_key(0x0131, 0, 0).unwrap();
    let me = uk.ua().unwrap();
    kem_answer(&chain, &me, 1, &uk.kem_key(1).unwrap().kem_pk());
    let (sid, eid) = (
        format!("0x{}", "21".repeat(32)),
        format!("0x{}", "22".repeat(32)),
    );
    let wr = a
        .pqchat_wrap(
            "local".into(),
            k.clone(),
            sid.clone(),
            eid.clone(),
            format!("0x{}", hexs(&me)),
            1,
        )
        .await
        .unwrap();
    let back = a
        .pqchat_unwrap(ua(&seed, 0x0131), sid.clone(), eid.clone(), wr.clone())
        .unwrap();
    assert!(a.same_key(back, k.clone()).unwrap());
    // one change: the wrap names another member
    let other = PqWrap {
        member: format!("0x{}", "33".repeat(32)),
        ..wr.clone()
    };
    assert_eq!(
        code(a.pqchat_unwrap(ua(&seed, 0x0131), sid.clone(), eid.clone(), other)),
        "Argument"
    );
    // one change: another epoch's AAD
    assert_eq!(
        code(a.pqchat_unwrap(ua(&seed, 0x0131), sid, format!("0x{}", "23".repeat(32)), wr)),
        "Aead"
    );
}

/// K3: every `chains` row's `ck_i`, the far read in one call, the walk bound (`PqChatTooFar`).
#[tokio::test(flavor = "multi_thread")]
async fn chains_and_the_far_read() {
    let _one = ONE.lock().await;
    let (sdk, seed, _c) = on_fake().await;
    let a = AppCore::new(sdk, desc(&[PQC])).unwrap();
    let m = pq("messages");
    for r in m["chains"].as_array().unwrap() {
        let k = a
            .vectors_import(&seed, a32(&r["K"]), AppKeyUsage::Derive)
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
        assert_eq!(revealed(&a, &p0), unhex(&r["ck0"]), "{}", r["name"]);
        for st in r["steps"].as_array().unwrap() {
            let p = a
                .pqchat_advance(p0.clone(), st["i"].as_u64().unwrap() + 1)
                .unwrap();
            assert_eq!(revealed(&a, &p), unhex(&st["ck"]), "{}", r["name"]);
        }
    }
    let f = &m["chainFar"];
    let k = a
        .vectors_import(&seed, a32(&f["K"]), AppKeyUsage::Derive)
        .unwrap();
    let p0 = a
        .pqchat_chain(
            k,
            s(&f["sessionId"]),
            s(&f["epochId"]),
            s(&f["sender"]),
            s(&f["device"]),
        )
        .unwrap();
    let far = a
        .pqchat_advance(p0.clone(), f["counter"].as_u64().unwrap() + 1)
        .unwrap();
    assert_eq!(revealed(&a, &far), unhex(&f["ck"]));
    assert_eq!(code(a.pqchat_advance(p0, (1 << 20) + 1)), "PqChatTooFar");
}

/// K4, V2, S5: the vector's payload decoded, its envelope opened to the message row's record and signature, the row's
/// ciphertext opened to its content at the sender chain's position. The row's signer is a raw seed the SDK cannot import and
/// S5 takes the sender from the signing account, so S5 is checked on its own record (ua-rs reproduces the row byte for
/// byte): the envelope under the fixed nonce opens to it, the content comes back canonical; padding, canonical and unpad rows
/// through the seal and open entries.
#[tokio::test(flavor = "multi_thread")]
async fn message_envelope_payload_and_content_rows() {
    let _one = ONE.lock().await;
    let (sdk, seed, _c) = on_fake().await;
    let a = AppCore::new(sdk, desc(&[PQC])).unwrap();
    let (m, rec) = (pq("messages"), pq("records"));
    let r = &rec["message"]["record"];
    let k = a
        .vectors_import(&seed, a32(&m["message"]["K"]), AppKeyUsage::Derive)
        .unwrap();
    let pos = |counter: u64| {
        let p0 = a
            .pqchat_chain(
                k.clone(),
                s(&r["sessionId"]),
                s(&r["epochId"]),
                s(&r["sender"]),
                s(&r["device"]),
            )
            .unwrap();
        a.pqchat_advance(p0, counter).unwrap()
    };
    let at = pos(r["counter"].as_u64().unwrap());
    // S5 signs as the repository account: its own chain
    let wl = Wallet::from_mnemonic(REPO, "").unwrap();
    let me = format!(
        "0x{}",
        hexs(&wl.ua_key(0x0131, 0, 0).unwrap().ua().unwrap())
    );
    let mine = |counter: u64| {
        let p0 = a
            .pqchat_chain(
                k.clone(),
                s(&r["sessionId"]),
                s(&r["epochId"]),
                me.clone(),
                s(&r["device"]),
            )
            .unwrap();
        a.pqchat_advance(p0, counter).unwrap()
    };
    let own_at = mine(r["counter"].as_u64().unwrap());
    let header = PqMessageHeader {
        session_id: s(&r["sessionId"]),
        epoch_id: s(&r["epochId"]),
        device: s(&r["device"]),
        counter: r["counter"].as_u64().unwrap(),
        parents: r["parents"].as_array().unwrap().iter().map(s).collect(),
    };
    let content = s(&m["message"]["content"]);
    let sealed = a
        .pqchat_vectors_seal_message(
            ua(&seed, 0x0131),
            k.clone(),
            own_at.clone(),
            header.clone(),
            content.clone(),
            a12(&m["envelope"]["nonce"]),
        )
        .await
        .unwrap();
    assert_eq!(sealed.record.sender, me);
    assert_eq!(sealed.hint, unhex(&m["envelope"]["hint"]));
    assert_eq!(&sealed.env[..12], &unhex(&m["envelope"]["nonce"])[..]);
    let back = a
        .pqchat_open_message(own_at.clone(), sealed.record.clone())
        .unwrap();
    assert_eq!(back.with(|b| b.to_vec()), content.as_bytes());
    // the sender's position does not open another sender's record (`Argument`)
    assert_eq!(
        code(a.pqchat_open_message(at.clone(), sealed.record.clone())),
        "Argument"
    );
    assert_eq!(
        a.pqchat_hint(k.clone()).unwrap(),
        unhex(&m["envelope"]["hint"])
    );
    // the vector's payload decoded (V2) and its envelope opened (K4)
    let p = a
        .pqchat_decode_payload(unhex(&m["payload"]["payload"]))
        .unwrap();
    assert_eq!(
        (p.hint.clone(), p.env.clone()),
        (unhex(&m["payload"]["hint"]), unhex(&m["payload"]["env"]))
    );
    let inner = a
        .pqchat_open_envelope(k.clone(), s(&r["sessionId"]), s(&r["epochId"]), p.env)
        .unwrap();
    assert_eq!(inner.record, record_of(r));
    assert_eq!(inner.sig, sig_of(&rec["message"]["uaSig"]));
    let pt = a.pqchat_open_message(at.clone(), inner.record).unwrap();
    assert_eq!(pt.with(|b| b.to_vec()), content.as_bytes());
    // S5's own payload decodes, its envelope opens to its own record
    let own = a.pqchat_decode_payload(sealed.payload.clone()).unwrap();
    assert_eq!(own.env, sealed.env);
    let own = a
        .pqchat_open_envelope(k.clone(), s(&r["sessionId"]), s(&r["epochId"]), own.env)
        .unwrap();
    assert_eq!(own.record, sealed.record);
    // V2: one byte added to the payload is refused
    let mut long = unhex(&m["payload"]["payload"]);
    long.push(0);
    assert_eq!(code(a.pqchat_decode_payload(long)), "Argument");
    // canonical rows: each input seals to the canonical text; the refused ones by name
    for c in m["canonicalJson"].as_array().unwrap() {
        let x = a
            .pqchat_seal_message(
                ua(&seed, 0x0131),
                k.clone(),
                own_at.clone(),
                header.clone(),
                s(&c["input"]),
            )
            .await
            .unwrap();
        let back = a.pqchat_open_message(own_at.clone(), x.record).unwrap();
        assert_eq!(
            back.with(|b| b.to_vec()),
            c["canonical"].as_str().unwrap().as_bytes()
        );
    }
    for c in m["canonicalRefused"].as_array().unwrap() {
        let x = a
            .pqchat_seal_message(
                ua(&seed, 0x0131),
                k.clone(),
                own_at.clone(),
                header.clone(),
                s(&c["input"]),
            )
            .await;
        assert_eq!(code(x), "PqChatContent", "{}", c["name"]);
    }
    // padding rows: the ciphertext is the padded length and the tag
    for c in m["padding"].as_array().unwrap() {
        let n = c["length"].as_u64().unwrap() as usize;
        if n < 11 {
            continue; // the shortest text below is `{"body":""}`, 11 bytes
        }
        let body = "x".repeat(n - 11);
        let text = json!({ "body": body }).to_string();
        assert_eq!(text.len(), n);
        let x = a
            .pqchat_seal_message(
                ua(&seed, 0x0131),
                k.clone(),
                own_at.clone(),
                header.clone(),
                text,
            )
            .await;
        // a record whose ciphertext passes the 16,384-B bucket is refused when signed: its typed data's JSON passes the
        // EIP-712 bound of 64 KiB (ua-rs `eip712::MAX_LEN`), so S5 sends at most 16,380 B of content
        let p = c["paddedLength"].as_u64().unwrap();
        let want = if p <= 16384 {
            Ok(p + 16)
        } else {
            Err("Argument")
        };
        let got = x
            .map(|y| y.record.ciphertext.len() as u64)
            .map_err(|e| e.code());
        assert_eq!(got, want, "{n}");
    }
    // unpad rows: each refused plaintext sealed at the position by the generic test seal, opened: `PqChatContent`; its twin
    let mk = a
        .vectors_import(&seed, a32(&m["message"]["mk"]), AppKeyUsage::Data)
        .unwrap();
    for c in m["unpadRefused"].as_array().unwrap() {
        // the twin: the message row's own padded plaintext (the row's `twin` unpads, but its content is not JSON)
        for (pt, want) in [(&c["pt"], "PqChatContent"), (&m["message"]["pt"], "Ok")] {
            let ct = a
                .vectors_seal(
                    mk.clone(),
                    a12(&m["message"]["n"]),
                    unhex(&m["message"]["aad"]),
                    unhex(pt),
                )
                .unwrap();
            let rec = PqChatMessage {
                ciphertext: ct,
                ..record_of(r)
            };
            assert_eq!(
                code(a.pqchat_open_message(at.clone(), rec)),
                want,
                "{}",
                c["name"]
            );
        }
    }
}

/// S1 / S2's seal and K5: each `sealedInfo` row from its info value and nonce, opened to its canonical JSON; S1 signs the
/// vector session's fields with the `wrapHashes` in `wraps`' order and lists the info's fields as request fields.
#[tokio::test(flavor = "multi_thread")]
async fn sealed_info_rows_and_s1() {
    let _one = ONE.lock().await;
    let (sdk, seed, _c) = on_fake().await;
    let a = AppCore::new(sdk, desc(&[PQC])).unwrap();
    for r in pq("messages")["sealedInfo"].as_array().unwrap() {
        let k = a
            .vectors_import(&seed, a32(&r["K"]), AppKeyUsage::Derive)
            .unwrap();
        let sealed = a
            .pqchat_vectors_seal_info(
                k.clone(),
                s(&r["sessionId"]),
                s(&r["epochId"]),
                r["info"].to_string(),
                a12(&r["nonce"]),
            )
            .unwrap();
        assert_eq!(sealed, unhex(&r["sealedInfo"]), "{}", r["name"]);
        let back = a
            .pqchat_open_info(k, s(&r["sessionId"]), s(&r["epochId"]), sealed)
            .unwrap();
        assert_eq!(
            back.with(|b| b.to_vec()),
            r["json"].as_str().unwrap().as_bytes()
        );
    }
    let rec = pq("records");
    let sr = &rec["session"]["record"];
    let keys = pq("keys");
    let wraps: Vec<PqWrap> = keys["wraps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["name"].as_str().unwrap().starts_with("session/"))
        .map(|x| PqWrap {
            member: s(&x["wrap"]["member"]),
            key_id: x["wrap"]["keyId"].as_u64().unwrap(),
            mlkem_ct: unhex(&x["wrap"]["mlkemCt"]),
            x25519_eph: s(&x["wrap"]["x25519Eph"]),
            sealed_key: unhex(&x["wrap"]["sealedKey"]),
        })
        .collect();
    let info = pq("messages")["sealedInfo"][0]["info"].clone();
    let k = a.pqchat_epoch_key(&seed).unwrap();
    let signed = a
        .pqchat_sign_session(
            ua(&seed, 0x0131),
            k.clone(),
            PqSessionNew {
                nonce: sr["nonce"].as_u64().unwrap(),
                home_chain: s(&sr["homeChain"]),
                home_chat_contract: s(&sr["homeChatContract"]),
                admins: sr["admins"].as_array().unwrap().iter().map(s).collect(),
                members: sr["members"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| PqMemberKey {
                        ua: s(&x["ua"]),
                        key_id: x["keyId"].as_u64().unwrap(),
                        via: s(&x["via"]),
                    })
                    .collect(),
                wraps,
                info_json: info.to_string(),
            },
        )
        .await
        .unwrap();
    let want: Vec<String> = sr["wrapHashes"].as_array().unwrap().iter().map(s).collect();
    assert_eq!(signed.wrap_hashes, want);
    // the creator is the signing account (not the row's alice): its own session id, under which the info was sealed
    let wl = Wallet::from_mnemonic(REPO, "").unwrap();
    let me = format!(
        "0x{}",
        hexs(&wl.ua_key(0x0131, 0, 0).unwrap().ua().unwrap())
    );
    let sid = signed.id.clone().unwrap();
    assert_ne!(sid, s(&rec["session"]["id"]));
    let r = &signed.review;
    assert!(r.iter().any(|f| f.name == "sealedInfo.name"
        && f.value == "PqChat vectors"
        && f.source == scaas_sdk::op::Source::Request));
    // the sealed info in the signed record opens under K to the canonical info
    let sealed_hex = r
        .iter()
        .find(|f| f.name == "message.sealedInfo")
        .unwrap()
        .value
        .clone();
    assert!(r
        .iter()
        .any(|f| f.name == "message.creator" && f.value == me));
    let back = a
        .pqchat_open_info(k, sid.clone(), sid, dehex(&sealed_hex))
        .unwrap();
    assert_eq!(
        back.with(|b| b.to_vec()),
        pq("messages")["sealedInfo"][0]["json"]
            .as_str()
            .unwrap()
            .as_bytes()
    );
}

/// V1 on the fake registry: every record row of `records.json` and `topics.json` verified at the final block; a flipped byte,
/// another signer, an unregistered signer refused (false).
#[tokio::test(flavor = "multi_thread")]
async fn v1_verifies_the_record_rows() {
    let _one = ONE.lock().await;
    let (sdk, _seed, chain) = on_fake().await;
    let a = AppCore::new(sdk, desc(&[PQC])).unwrap();
    let (rec, top) = (pq("records"), pq("topics"));
    let signers = rec["signers"].as_array().unwrap().clone();
    for x in &signers {
        reg_answer(
            &chain,
            &a32(&x["ua"]),
            x["kind"].as_u64().unwrap() as u16,
            &unhex(&x["publicKey"]),
        );
    }
    let ua_of = |n: &str| s(&signers.iter().find(|x| x["name"] == n).unwrap()["ua"]);
    let rows = [
        (&rec, "message", "PqChatMessage"),
        (&top, "topic", "PqTopic"),
        (&top, "update", "PqTopicUpdate"),
        (&top, "writer", "PqTopicWriter"),
        (&top, "post", "PqTopicEntry"),
        (&top, "reply", "PqTopicEntry"),
        (&top, "edit", "PqTopicEdit"),
        (&top, "vote", "PqTopicVote"),
    ];
    for (v, row, name) in rows {
        let r = &v[row];
        let who = ua_of(r["signer"].as_str().unwrap());
        let sig = sig_of(&r["uaSig"]);
        let check = |u: String, g: AppUaSig| {
            a.verify_pqchat_record("local".into(), u, name.into(), r["record"].to_string(), g)
        };
        assert!(check(who.clone(), sig.clone()).await.unwrap(), "{row}");
        let mut bad = sig.clone();
        bad.signature[0] ^= 1;
        assert!(
            !check(who.clone(), bad).await.unwrap(),
            "{row}: a flipped byte"
        );
        let other = signers
            .iter()
            .map(|x| s(&x["ua"]))
            .find(|u| *u != who)
            .unwrap();
        assert!(
            !check(other, sig.clone()).await.unwrap(),
            "{row}: another signer"
        );
        let unknown = format!("0x{}", "44".repeat(32));
        assert!(!check(unknown, sig).await.unwrap(), "{row}: unregistered");
    }
    // the read is a trusted one at the final block
    let reqs = chain.lock().unwrap().requests.clone();
    let r = reqs
        .iter()
        .find(|r| r.contains(&sel("registrationOf(bytes32)")[2..]))
        .unwrap();
    assert!(
        r.contains("blockHash") && r.contains("requireCanonical"),
        "{r}"
    );
}

/// The refusals of the key entries, one change at a time beside the twin.
#[tokio::test(flavor = "multi_thread")]
async fn refusals_one_change_at_a_time() {
    let _one = ONE.lock().await;
    let (sdk, seed, _c) = on_fake().await;
    let a = AppCore::new(sdk.clone(), desc(&[PQC])).unwrap();
    let m = pq("messages");
    let r = &m["chains"][0];
    let k = a
        .vectors_import(&seed, a32(&r["K"]), AppKeyUsage::Derive)
        .unwrap();
    let chain_of = |c: &AppCore, k| {
        c.pqchat_chain(
            k,
            s(&r["sessionId"]),
            s(&r["epochId"]),
            s(&r["sender"]),
            s(&r["device"]),
        )
    };
    // a scope without PqChat's prefix: `AppLabelRefused`; the twin with it above
    let other = AppCore::new(sdk.clone(), desc(&["scaas/notchat/v1/"])).unwrap();
    let ok = other
        .vectors_import(&seed, a32(&r["K"]), AppKeyUsage::Derive)
        .unwrap();
    assert_eq!(code(chain_of(&other, ok.clone())), "AppLabelRefused");
    assert_eq!(code(other.pqchat_hint(ok)), "AppLabelRefused");
    assert_eq!(code(other.pqchat_epoch_key(&seed)), "AppLabelRefused");
    let p0 = chain_of(&a, k.clone()).unwrap();
    // advance in a scope without the prefix `AppLabelRefused`; another PqChat scope's position `AppHandleForeign` (one live
    // PqChat scope at a time: the first dropped), the twin in its own scope
    assert_eq!(code(other.pqchat_advance(p0.clone(), 1)), "AppLabelRefused");
    assert_eq!(code(a.pqchat_advance(p0.clone(), 1)), "Ok");
    {
        let first = AppCore::new(sdk.clone(), desc(&["scaas/pqchat/"]));
        assert_eq!(code(first), "AppLabelRefused");
    }
    // the walk bound: 2^20 + 1 steps refused before any step; 5,000 walk
    assert_eq!(
        code(a.pqchat_advance(p0.clone(), (1 << 20) + 1)),
        "PqChatTooFar"
    );
    // the hint of a chain position `AppKeyUsage`; of the epoch key it is the hint
    assert_eq!(code(a.pqchat_hint(p0.clone())), "AppKeyUsage");
    assert_eq!(code(a.pqchat_hint(k.clone())), "Ok");
    // S5: a native or an msig signer `Argument`; the UA key signs
    let h = PqMessageHeader {
        session_id: s(&r["sessionId"]),
        epoch_id: s(&r["epochId"]),
        device: s(&r["device"]),
        counter: 0,
        parents: vec![],
    };
    let wl = Wallet::from_mnemonic(REPO, "").unwrap();
    let me = format!(
        "0x{}",
        hexs(&wl.ua_key(0x0131, 0, 0).unwrap().ua().unwrap())
    );
    let own = a
        .pqchat_chain(
            k.clone(),
            s(&r["sessionId"]),
            s(&r["epochId"]),
            me,
            s(&r["device"]),
        )
        .unwrap();
    let seal = |acct: KeyRef| {
        a.pqchat_seal_message(acct, k.clone(), own.clone(), h.clone(), "{\"t\":1}".into())
    };
    let native = KeyRef::Native {
        seed: seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    assert_eq!(code(seal(native).await), "Argument");
    let msig = KeyRef::Msig {
        ua: format!("0x{}", "55".repeat(32)),
        slots: vec![],
    };
    assert_eq!(code(seal(msig).await), "Argument");
    // the sender is the signing account: alice's own position seals, another account's (its UA is not the chain's) does not
    let alice = seal(ua(&seed, 0x0131)).await;
    assert_eq!(code(alice), "Ok");
    let bob = KeyRef::Ua {
        seed: seed.clone(),
        kind: 0x0131,
        account: 1,
        index: 0,
    };
    assert_eq!(code(seal(bob).await), "Argument");
    drop(a);
    let b = AppCore::new(sdk.clone(), desc(&[PQC])).unwrap();
    assert_eq!(code(b.pqchat_advance(p0, 1)), "AppHandleForeign");
}

/// Generic app signing refuses PqChat's purpose and its domain `DS_C` (spec §12.4); the twins sign.
#[tokio::test(flavor = "multi_thread")]
async fn generic_signing_refuses_pqchat() {
    let (sdk, seed, _c) = on_fake().await;
    let a = AppCore::new(sdk, desc(&["scaas/notpqc/v1/"])).unwrap();
    let typed = |domain: Value| {
        let fields: Vec<Value> = [
            ("name", "string"),
            ("version", "string"),
            ("chainId", "uint256"),
            ("verifyingContract", "address"),
            ("salt", "bytes32"),
        ]
        .iter()
        .filter(|(k, _)| domain.get(*k).is_some())
        .map(|(k, t)| json!({"name": k, "type": t}))
        .collect();
        json!({
            "types": {"EIP712Domain": fields, "Note": [{"name": "body", "type": "string"}]},
            "primaryType": "Note",
            "domain": domain,
            "message": {"body": "hello"},
        })
        .to_string()
    };
    let pqc = format!(
        "0x{}",
        keccak_hex(b"scaas.ua.purpose.pqchat.v1").trim_start_matches("0x")
    );
    let bound =
        json!({"name": "My App", "version": "1", "chainId": 31337, "verifyingContract": VIEW});
    let path = |p: Option<String>| AppPath::ChainBound {
        chain: "local".into(),
        purpose: p,
    };
    let sign = |p: AppPath, t: String| a.sign_app_record(ua(&seed, 0x0131), p, t);
    assert_eq!(
        code(sign(path(Some(pqc)), typed(bound.clone())).await),
        "AppPurposeRefused"
    );
    assert_eq!(code(sign(path(None), typed(bound)).await), "Ok");
    let dsc = json!({"name": "SCaaS PqChat", "version": "1"});
    assert_eq!(
        code(sign(AppPath::Portable, typed(dsc)).await),
        "AppDomainRefused"
    );
    let named = json!({"name": "SCaaS PqChat", "version": "1", "salt": APP_ID});
    assert_eq!(
        code(sign(AppPath::Portable, typed(named)).await),
        "AppDomainRefused"
    );
    let mine = json!({"name": "My App", "version": "1", "salt": APP_ID});
    assert_eq!(code(sign(AppPath::Portable, typed(mine)).await), "Ok");
}

/// `read_app`: a named JSON answer from the entry's outputs at the final block; trusted reads skip a discovered-only list
/// elsewhere (the KEM read's test); bounds by name.
#[tokio::test(flavor = "multi_thread")]
async fn read_app_named_json() {
    let _one = ONE.lock().await;
    let (sdk, _seed, chain) = on_fake().await;
    let a = AppCore::new(sdk, desc(&[PQC])).unwrap();
    let entry = json!({"type": "function", "name": "storedRange", "stateMutability": "view",
        "inputs": [{"name": "epochId", "type": "bytes32"}],
        "outputs": [{"name": "first", "type": "uint64"}, {"name": "count", "type": "uint64"},
                    {"name": "page", "type": "tuple[]", "components": [
                        {"name": "id", "type": "bytes32"}, {"name": "who", "type": "address"},
                        {"name": "blob", "type": "bytes"}, {"name": "ok", "type": "bool"}]}]})
    .to_string();
    let eid = [0x66u8; 32];
    // (first, count, page) with page one (id, who, blob, ok): heads, the array, its one tuple, the bytes
    let out = [
        w(5),
        w(1),
        w(0x60),
        w(1),
        w(0x20),
        hexs(&[0x77; 32]),
        w(0xab),
        w(0x80),
        w(1),
        w(2),
        pad(&[0xbe, 0xef]),
    ]
    .concat();
    answer(&chain, VIEW, "storedRange(bytes32)", &eid, out);
    let args = json!({"epochId": format!("0x{}", hexs(&eid))}).to_string();
    for trusted in [false, true] {
        let got = a
            .read_app(
                "local".into(),
                VIEW.into(),
                entry.clone(),
                args.clone(),
                trusted,
            )
            .await
            .unwrap();
        let v: Value = serde_json::from_str(&got).unwrap();
        assert_eq!(
            v,
            json!({"first": "5", "count": "1", "page": [{"id": format!("0x{}", "77".repeat(32)),
                "who": VIEW, "blob": "0xbeef", "ok": true}]})
        );
    }
    let reqs = chain.lock().unwrap().requests.clone();
    let r = reqs
        .iter()
        .find(|r| r.contains(&sel("storedRange(bytes32)")[2..]))
        .unwrap();
    assert!(
        r.contains("blockHash") && r.contains("requireCanonical"),
        "{r}"
    );
    // one change each: an argument of another name, an entry that does not parse, a state-changing entry, a nesting past the bound
    let bad = json!({"epoch": format!("0x{}", hexs(&eid))}).to_string();
    assert_eq!(
        code(
            a.read_app("local".into(), VIEW.into(), entry.clone(), bad, false)
                .await
        ),
        "Argument"
    );
    assert_eq!(
        code(
            a.read_app("local".into(), VIEW.into(), "{".into(), args.clone(), false)
                .await
        ),
        "Argument"
    );
    let pay = entry.replace("\"view\"", "\"nonpayable\"");
    assert_eq!(
        code(
            a.read_app("local".into(), VIEW.into(), pay, args.clone(), false)
                .await
        ),
        "Argument"
    );
    // the nesting bound by its own reason: 16 levels read (the answer's first word as the innermost uint8), 17 refused
    let deep_entry = |levels: usize| {
        let mut deep = json!({"name": "x", "type": "uint8"});
        for _ in 0..levels {
            deep = json!({"name": "x", "type": "tuple", "components": [deep]});
        }
        json!({"type": "function", "name": "storedRange", "stateMutability": "view",
            "inputs": [{"name": "epochId", "type": "bytes32"}], "outputs": [deep]})
        .to_string()
    };
    let at16 = a
        .read_app(
            "local".into(),
            VIEW.into(),
            deep_entry(16),
            args.clone(),
            false,
        )
        .await
        .unwrap();
    assert_eq!(at16.matches("\"x\":").count(), 17, "{at16}");
    assert!(at16.contains("\"x\":\"5\""), "{at16}");
    assert_eq!(
        code(
            a.read_app(
                "local".into(),
                VIEW.into(),
                deep_entry(17),
                args.clone(),
                false
            )
            .await
        ),
        "Argument"
    );
    // array dimensions count as levels too: uint8[1]…[1] of 16 dimensions read, of 17 refused
    let dims = |n: usize| {
        json!({"type": "function", "name": "storedRange", "stateMutability": "view",
            "inputs": [{"name": "epochId", "type": "bytes32"}],
            "outputs": [{"name": "x", "type": format!("uint8{}", "[1]".repeat(n))}]})
        .to_string()
    };
    let d16 = a
        .read_app("local".into(), VIEW.into(), dims(16), args.clone(), false)
        .await
        .unwrap();
    assert_eq!(
        d16,
        format!("{{\"x\":{}\"5\"{}}}", "[".repeat(16), "]".repeat(16))
    );
    assert_eq!(
        code(
            a.read_app("local".into(), VIEW.into(), dims(17), args, false)
                .await
        ),
        "Argument"
    );
}

/// The `vectors` feature's bit (28); no new signing entry takes a digest, typed data or a caller-made ciphertext.
#[test]
fn bit_and_no_caller_ciphertext() {
    use scaas_sdk::bits::VECTORS;
    assert_eq!(VECTORS, 1 << 28);
    assert_eq!(scaas_sdk::features() & VECTORS, VECTORS);
    let src = std::fs::read_to_string(format!("{}/src/pqchat_keys.rs", env!("CARGO_MANIFEST_DIR")))
        .unwrap();
    let mut seen = 0;
    for f in [
        "pqchat_seal_message",
        "pqchat_sign_session",
        "pqchat_sign_epoch",
    ] {
        let at = src.find(&format!("pub async fn {f}(")).unwrap();
        let sig = &src[at..at + src[at..].find('{').unwrap()];
        for bad in ["digest", "typed", "ciphertext", "sealed"] {
            assert!(!sig.contains(bad), "{f} takes {bad}");
        }
        seen += 1;
    }
    assert_eq!(seen, 3);
}

fn state_answer(c: &Fake, id: &[u8; 32], enabled: u64, accepted: u64) {
    answer(
        c,
        REGISTRY,
        "msigStateOf(bytes32)",
        id,
        format!("{}{}{}", w(0), w(enabled), w(accepted)),
    );
}

/// V1 of an `msig` signer (two derived members, threshold 1): one member's slot verifies; both slots (not minimal), a slot
/// enabled but not accepted, refused (false).
#[tokio::test(flavor = "multi_thread")]
async fn v1_msig_minimal_and_accepted() {
    use scaas_sdk::app_core::AppMemberSig;
    let _one = ONE.lock().await;
    let (sdk, _seed, chain) = on_fake().await;
    let a = AppCore::new(sdk, desc(&[PQC])).unwrap();
    let wl = Wallet::from_mnemonic(REPO, "").unwrap();
    let (k1, k2) = (
        wl.ua_key(0x0108, 0, 0).unwrap(),
        wl.ua_key(0x0131, 0, 0).unwrap(),
    );
    let mut m = vec![];
    for k in [&k1, &k2] {
        let scaas_ua::wallet::KeyRef::Ua { kind, key_data, .. } =
            scaas_ua::wallet::Signer::key_ref(k)
        else {
            panic!()
        };
        let id = k.ua().unwrap();
        reg_answer(&chain, &id, kind, &key_data);
        m.push((kind, id, 1u16));
    }
    m.sort_by_key(|x| x.1);
    let kd = scaas_ua::encode_msig(1, &m);
    let ms = scaas_ua::derive_ua(0x0120, &kd, false).unwrap();
    reg_answer(&chain, &ms, 0x0120, &kd);
    state_answer(&chain, &ms, 0b11, 0b11);
    let r = &pq("records")["message"]["record"];
    let td = scaas_ua::wallet::pqchat::typed("PqChatMessage", r.clone()).unwrap();
    let message = scaas_ua::ua_message(
        0x0120,
        &scaas_ua::wallet::pqchat::purpose(),
        &td.digest().unwrap(),
    )
    .unwrap();
    let md = scaas_ua::member_digest(&ms, &message);
    let tag = scaas_ua::purpose_tag("member").unwrap();
    let slot = |i: u16| {
        let k = if m[i as usize].1 == k1.ua().unwrap() {
            &k1
        } else {
            &k2
        };
        AppMemberSig {
            index: i,
            members: vec![],
            sig: scaas_ua::wallet::ua_sig(k, None, &tag, &md)
                .unwrap()
                .signature,
        }
    };
    let sig = |slots: Vec<AppMemberSig>| AppUaSig {
        members: slots,
        ..Default::default()
    };
    let check = |g: AppUaSig| {
        a.verify_pqchat_record(
            "local".into(),
            format!("0x{}", hexs(&ms)),
            "PqChatMessage".into(),
            r.to_string(),
            g,
        )
    };
    assert!(check(sig(vec![slot(0)])).await.unwrap(), "one slot");
    assert!(check(sig(vec![slot(1)])).await.unwrap(), "the other slot");
    assert!(
        !check(sig(vec![slot(0), slot(1)])).await.unwrap(),
        "both slots: not minimal"
    );
    state_answer(&chain, &ms, 0b11, 0b10);
    assert!(
        !check(sig(vec![slot(0)])).await.unwrap(),
        "a slot not accepted"
    );
    assert!(
        check(sig(vec![slot(1)])).await.unwrap(),
        "its twin, accepted"
    );
}
