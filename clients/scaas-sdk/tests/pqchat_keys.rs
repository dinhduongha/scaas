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

#[path = "common/prepared.rs"]
mod prepared;
use fake_chain::{fake, keccak_hex, serve, Fake};
use prepared::SignPrepared as _;
use scaas_sdk::app_core::{AppCore, AppDesc, AppKeyUsage, AppPath, AppUaSig};
use scaas_sdk::op::KeyRef;
use scaas_sdk::pqchat_keys::{PqMessageHeader, PqSessionNew};
use scaas_sdk::pqchat_records::{PqChatCard, PqChatMessage, PqMemberKey, PqWrap};
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, Sdk, SdkConfig, SdkError,
};
use scaas_ua::wallet::{SecretBytes, Signer as _, Wallet};
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
        pinned_reads: true,
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
        .pqchat_prepare_session(
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
        .unwrap()
        .sign()
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

/// V2's wrap hash (every `wraps` row's `hashStruct`) and a received message's id (the `message` row's `id`), each with a
/// one-change twin (pqchat-core T4's wrap-hash check and dedupe read them).
#[tokio::test(flavor = "multi_thread")]
async fn wrap_hash_and_message_id_rows() {
    let _one = ONE.lock().await;
    let (sdk, _seed, _c) = on_fake().await;
    let a = AppCore::new(sdk, desc(&[PQC])).unwrap();
    let keys = pq("keys");
    let rows = keys["wraps"].as_array().unwrap();
    assert!(!rows.is_empty());
    for x in rows {
        let w = PqWrap {
            member: s(&x["wrap"]["member"]),
            key_id: x["wrap"]["keyId"].as_u64().unwrap(),
            mlkem_ct: unhex(&x["wrap"]["mlkemCt"]),
            x25519_eph: s(&x["wrap"]["x25519Eph"]),
            sealed_key: unhex(&x["wrap"]["sealedKey"]),
        };
        assert_eq!(
            a.pqchat_wrap_hash(w.clone()).unwrap(),
            s(&x["hashStruct"]),
            "{}",
            x["name"]
        );
        let mut flip = w;
        flip.sealed_key[0] ^= 1;
        assert_ne!(a.pqchat_wrap_hash(flip).unwrap(), s(&x["hashStruct"]));
    }
    let m = &pq("records")["message"];
    let r = record_of(&m["record"]);
    assert_eq!(a.pqchat_message_id(r.clone()).unwrap(), s(&m["id"]));
    let other = PqChatMessage {
        counter: r.counter + 1,
        ..r.clone()
    };
    assert_ne!(a.pqchat_message_id(other).unwrap(), s(&m["id"]));
    let bad = PqChatMessage {
        device: "0x01".into(),
        ..r
    };
    assert_eq!(code(a.pqchat_message_id(bad)), "Argument");
    // S4: the session and epoch rows' ids before signing; one change each
    let rec = pq("records");
    let (sr, er) = (&rec["session"], &rec["epoch"]["record"]);
    let sid = a
        .pqchat_session_id(
            s(&sr["record"]["creator"]),
            sr["record"]["nonce"].as_u64().unwrap(),
        )
        .unwrap();
    assert_eq!(sid, s(&sr["id"]));
    assert_eq!(sid, s(&er["sessionId"]));
    let nonce = er["nonce"].as_u64().unwrap();
    let eid = a
        .pqchat_epoch_id(sid.clone(), s(&er["author"]), nonce)
        .unwrap();
    assert_eq!(eid, s(&rec["epoch"]["id"]));
    assert_ne!(
        a.pqchat_epoch_id(sid.clone(), s(&er["author"]), nonce + 1)
            .unwrap(),
        eid
    );
    assert_eq!(code(a.pqchat_session_id("0x01".into(), 1)), "Argument");
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

/// CTR-CHAT-23 option d (owner 2026-11-23): `read_app_agreed` is `read_app` as an agreed read (CLI-RPC-05), the read's own
/// option: on the fake chain's one-endpoint list it is refused by the agreed read's own check (`Argument`, two endpoints or
/// more), while the same `read_app` answers (the control). The agreement itself is scaas-rpc's
/// (`an_agreed_read_on_a_failover_list_outvotes_one_liar`).
#[tokio::test(flavor = "multi_thread")]
async fn read_app_agreed_is_the_agreed_read() {
    let _one = ONE.lock().await;
    let (sdk, _seed, chain) = on_fake().await;
    let a = AppCore::new(sdk, desc(&[PQC])).unwrap();
    let entry =
        json!({"type": "function", "name": "sigStore", "stateMutability": "view", "inputs": [],
        "outputs": [{"name": "", "type": "uint8"}]})
        .to_string();
    answer(&chain, VIEW, "sigStore()", &[], w(2));
    let plain = a
        .read_app("local".into(), VIEW.into(), entry.clone(), "{}".into())
        .await
        .unwrap();
    assert_eq!(plain, json!({"0": "2"}).to_string());
    assert_eq!(
        code(
            a.read_app_agreed("local".into(), VIEW.into(), entry, "{}".into())
                .await
        ),
        "Argument"
    );
}

/// Owner 2026-11-23 (T10b): under a scope of PqChat's own app id, the generic app signing is refused on both paths
/// (`AppPurposeRefused`: PqChat's app purpose is a SCaaS purpose, `scaas-ua`'s generated list); the twins under another app
/// id sign. PqChat's own paths are the named entries (`pqchat_prepare_*`, the card, `seal_for_arweave`).
#[tokio::test(flavor = "multi_thread")]
async fn generic_signing_refuses_pqchat_app_id() {
    let _one = ONE.lock().await;
    let (sdk, seed, _c) = on_fake().await;
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
    let bound =
        json!({"name": "My App", "version": "1", "chainId": 31337, "verifyingContract": VIEW});
    let chain_bound = AppPath::ChainBound {
        chain: "local".into(),
        purpose: None,
    };
    for (id, want) in [
        (keccak_hex(b"scaas.pqchat.v1"), "AppPurposeRefused"),
        (APP_ID.to_string(), "Ok"),
    ] {
        let a = AppCore::new(
            sdk.clone(),
            AppDesc {
                app_id: Some(id.clone()),
                ..desc(&[PQC])
            },
        )
        .unwrap();
        let mine = json!({"name": "My App", "version": "1", "salt": id});
        let p = a
            .sign_app_record(ua(&seed, 0x0131), AppPath::Portable, typed(mine))
            .await;
        assert_eq!(code(p), want, "portable under {id}");
        let b = a
            .sign_app_record(ua(&seed, 0x0131), chain_bound.clone(), typed(bound.clone()))
            .await;
        assert_eq!(code(b), want, "chain-bound under {id}");
        drop(a);
    }
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
        let (c, v, e, x) = (
            "local".to_string(),
            VIEW.to_string(),
            entry.clone(),
            args.clone(),
        );
        let got = if trusted {
            a.read_app(c, v, e, x).await
        } else {
            a.read_app_plain(c, v, e, x).await
        }
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
            a.read_app_plain("local".into(), VIEW.into(), entry.clone(), bad)
                .await
        ),
        "Argument"
    );
    assert_eq!(
        code(
            a.read_app_plain("local".into(), VIEW.into(), "{".into(), args.clone())
                .await
        ),
        "Argument"
    );
    let pay = entry.replace("\"view\"", "\"nonpayable\"");
    assert_eq!(
        code(
            a.read_app_plain("local".into(), VIEW.into(), pay, args.clone())
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
        .read_app_plain("local".into(), VIEW.into(), deep_entry(16), args.clone())
        .await
        .unwrap();
    assert_eq!(at16.matches("\"x\":").count(), 17, "{at16}");
    assert!(at16.contains("\"x\":\"5\""), "{at16}");
    assert_eq!(
        code(
            a.read_app_plain("local".into(), VIEW.into(), deep_entry(17), args.clone())
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
        .read_app_plain("local".into(), VIEW.into(), dims(16), args.clone())
        .await
        .unwrap();
    assert_eq!(
        d16,
        format!("{{\"x\":{}\"5\"{}}}", "[".repeat(16), "]".repeat(16))
    );
    assert_eq!(
        code(
            a.read_app_plain("local".into(), VIEW.into(), dims(17), args)
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
    // review T26 C-2: such a build is refused by every binding's opening (the load check)
    const { assert!(scaas_ua::VECTORS) };
    assert_eq!(
        scaas_sdk::load_check(scaas_sdk::Sdk::api_version(), 0).map_err(|e| e.code()),
        Err("AbiMismatch")
    );
    let src = std::fs::read_to_string(format!("{}/src/pqchat_keys.rs", env!("CARGO_MANIFEST_DIR")))
        .unwrap();
    let mut seen = 0;
    for f in [
        "pqchat_seal_message",
        "pqchat_prepare_session",
        "pqchat_prepare_epoch",
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

/// TODO 8b-8 (4), CLI-PQC-15 on F2's line (CTR-UA-70): V1, the check behind a kept signature (`require_signed_records` and
/// every `sstore2` home), reads the signer's record where the line says: `holderOf` on the bound registry (generation 2)
/// names generation 1, whose record verifies, though the bound registry holds none; every call of it at one block. The
/// controls: the holder the bound registry itself (no record there: false), a holder off the line (the read fails).
#[tokio::test(flavor = "multi_thread")]
async fn v1_follows_the_registry_line() {
    let _one = ONE.lock().await;
    let (sdk, _seed, chain) = on_fake().await;
    let a = AppCore::new(sdk, desc(&[PQC])).unwrap();
    let rec = pq("records");
    let r = &rec["message"];
    let x = rec["signers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == r["signer"])
        .unwrap();
    let (id, kind) = (a32(&x["ua"]), x["kind"].as_u64().unwrap() as u16);
    const OLD: &str = "0x5ca00000000000000000000000000000000000a0";
    let addr = |a: &str| format!("{:0>64}", a.trim_start_matches("0x"));
    answer(&chain, REGISTRY, "generation()", &[], w(2));
    answer(&chain, REGISTRY, "predecessor()", &[], addr(OLD));
    let holder = |h: &str| {
        answer(
            &chain,
            REGISTRY,
            "holderOf(bytes32)",
            &id,
            format!("{}{}{}", addr(h), w(u64::from(kind)), w(0)),
        )
    };
    holder(OLD);
    let kd = unhex(&x["publicKey"]);
    answer(
        &chain,
        OLD,
        "registrationOf(bytes32)",
        &id,
        format!(
            "{}{}{}{}{}{}{}",
            w(u64::from(kind)),
            w(0xa0),
            w(0),
            w(0),
            w(0),
            w(kd.len() as u64),
            pad(&kd)
        ),
    );
    let check = || {
        a.verify_pqchat_record(
            "local".into(),
            s(&x["ua"]),
            "PqChatMessage".into(),
            r["record"].to_string(),
            sig_of(&r["uaSig"]),
        )
    };
    chain.lock().unwrap().requests.clear();
    assert!(
        check().await.unwrap(),
        "the record at its holder, generation 1"
    );
    let blocks: std::collections::BTreeSet<String> = chain
        .lock()
        .unwrap()
        .requests
        .iter()
        .filter(|q| q.contains("eth_call"))
        .map(|q| {
            let t = q.split("\"blockHash\":\"").nth(1).unwrap_or_default();
            t.get(..66).unwrap_or(t).to_string()
        })
        .collect();
    assert_eq!(blocks.len(), 1, "one block: {blocks:?}");
    assert!(blocks.iter().all(|b| b.starts_with("0x")), "{blocks:?}");
    holder(REGISTRY);
    assert!(
        !check().await.unwrap(),
        "the bound registry holds no record"
    );
    holder("0x00000000000000000000000000000000000000ee");
    assert!(check().await.is_err(), "a holder off the line");
}

/// The contact card (UA-7 §14 O7) on the fake registry: every card row verifies for its UA at the final block, each refused
/// row is false beside its passing twin; the account signs its own card (its UA, the KEM version and Matrix id given, the
/// row's typed digest), which verifies; a malformed Matrix id and a native key refused (`Argument`).
#[tokio::test(flavor = "multi_thread")]
async fn cards_sign_and_verify() {
    let _one = ONE.lock().await;
    let (sdk, seed, chain) = on_fake().await;
    let a = AppCore::new(sdk, desc(&[PQC])).unwrap();
    let (rec, c) = (pq("records"), pq("cards"));
    for x in rec["signers"].as_array().unwrap() {
        reg_answer(
            &chain,
            &a32(&x["ua"]),
            x["kind"].as_u64().unwrap() as u16,
            &unhex(&x["publicKey"]),
        );
    }
    let card = |r: &Value| PqChatCard {
        ua: s(&r["ua"]),
        kem_version: r["kemVersion"].as_u64().unwrap(),
        matrix_id: r["matrixId"].as_str().unwrap().into(),
    };
    let check = |u: &Value, r: &Value, g: &Value| {
        a.verify_pqchat_card("local".into(), s(u), card(r), sig_of(g))
    };
    for r in c["cards"].as_array().unwrap() {
        assert!(
            check(&r["record"]["ua"], &r["record"], &r["uaSig"])
                .await
                .unwrap(),
            "{}",
            r["name"]
        );
    }
    for r in c["refused"].as_array().unwrap() {
        let t = &r["twin"];
        assert!(
            check(&t["ua"], &t["record"], &t["uaSig"]).await.unwrap(),
            "{}: the twin",
            r["name"]
        );
        assert!(
            !check(&r["ua"], &r["record"], &r["uaSig"]).await.unwrap(),
            "{}",
            r["name"]
        );
    }
    let reqs = chain.lock().unwrap().requests.clone();
    let r = reqs
        .iter()
        .find(|r| r.contains(&sel("registrationOf(bytes32)")[2..]))
        .unwrap();
    assert!(
        r.contains("blockHash") && r.contains("requireCanonical"),
        "{r}"
    );
    // the account's own card: its UA (not the rows' alice), registered, the fields as given
    let k = Wallet::from_mnemonic(REPO, "")
        .unwrap()
        .ua_key(0x0131, 0, 0)
        .unwrap();
    let scaas_ua::wallet::KeyRef::Ua { key_data, .. } = k.key_ref() else {
        panic!()
    };
    let me = k.ua().unwrap();
    reg_answer(&chain, &me, 0x0131, &key_data);
    let signed = a
        .prepare_pqchat_card(ua(&seed, 0x0131), 1, "@alice:example.org".into())
        .await
        .unwrap()
        .sign()
        .await
        .unwrap();
    assert_eq!(
        signed.card,
        PqChatCard {
            ua: format!("0x{}", hexs(&me)),
            kem_version: 1,
            matrix_id: "@alice:example.org".into()
        }
    );
    assert_ne!(
        signed.typed,
        s(&c["cards"][0]["typed"]),
        "another UA, another digest"
    );
    assert!(signed
        .review
        .iter()
        .any(|f| f.name == "message.matrixId" && f.value == "@alice:example.org"));
    assert!(a
        .verify_pqchat_card(
            "local".into(),
            signed.card.ua.clone(),
            signed.card.clone(),
            signed.sig.clone()
        )
        .await
        .unwrap());
    assert_eq!(
        code(
            async {
                a.prepare_pqchat_card(ua(&seed, 0x0131), 1, "alice:example.org".into())
                    .await?
                    .sign()
                    .await
            }
            .await
        ),
        "Argument"
    );
    let native = KeyRef::Native {
        seed: seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    assert_eq!(
        code(
            async {
                a.prepare_pqchat_card(native, 1, String::new())
                    .await?
                    .sign()
                    .await
            }
            .await
        ),
        "Argument"
    );
}

/// pqchat-core T10b (owner 2026-11-22: two new calls and an app id for PqChat): (b) the `fileMessage` row's ciphertext opens to its
/// content at the sender's position, and `pqchat_open_file` opens the row's object named by it (the object built by
/// `scaas-ua`'s vectors seal under the row's file key, the same bytes `seal_for_arweave` posts); every refusal row by name.
/// (a) `pqchat_seal_file_message` on the account's own chain: the content it seals is the row's (the key entered from the
/// handle, never given), the key in no byte that leaves; a handle of another usage `AppKeyUsage`; the sealer's refusals.
#[tokio::test(flavor = "multi_thread")]
async fn file_content_rows() {
    let _one = ONE.lock().await;
    let (sdk, seed, _c) = on_fake().await;
    let a = AppCore::new(sdk, desc(&[PQC])).unwrap();
    let m = pq("messages");
    let f = &m["fileMessage"];
    let r = &f["record"];
    let k = a
        .vectors_import(&seed, a32(&f["K"]), AppKeyUsage::Derive)
        .unwrap();
    let pos = |sender: String, counter: u64| {
        let p0 = a
            .pqchat_chain(
                k.clone(),
                s(&r["sessionId"]),
                s(&r["epochId"]),
                sender,
                s(&r["device"]),
            )
            .unwrap();
        a.pqchat_advance(p0, counter).unwrap()
    };
    let counter = r["counter"].as_u64().unwrap();
    let record = PqChatMessage {
        session_id: s(&r["sessionId"]),
        epoch_id: s(&r["epochId"]),
        sender: s(&r["sender"]),
        device: s(&r["device"]),
        counter,
        parents: r["parents"].as_array().unwrap().iter().map(s).collect(),
        ciphertext: unhex(&r["ciphertext"]),
    };
    let content = Arc::new(
        a.pqchat_open_message(pos(s(&r["sender"]), counter), record)
            .unwrap(),
    );
    assert_eq!(content.with(|b| b.to_vec()), s(&f["content"]).as_bytes());
    let w = Wallet::from_mnemonic(REPO, "").unwrap();
    let uk = w.app_keys();
    let fk = uk
        .vectors_import(&a32(&f["fileKey"]), scaas_ua::wallet::KeyUsage::File)
        .unwrap();
    let file = unhex(&f["file"]);
    let object = uk.vectors_seal_file(fk, &file).unwrap().object;
    assert_eq!(object.len() as u64, f["objectLength"].as_u64().unwrap());
    let got = a.pqchat_open_file(content.clone(), object.clone()).unwrap();
    assert_eq!(got.with(|b| b.to_vec()), file);
    let canon = |v: &Value| {
        let c = scaas_ua::wallet::pqchat_keys::canonical_json(v).unwrap();
        Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(c.into_bytes())).unwrap())
    };
    for x in m["fileOpenRefused"].as_array().unwrap() {
        let mut o = object.clone();
        match x["change"].as_str() {
            Some("drop-last") => drop(o.pop()),
            Some("append-zero") => o.push(0),
            Some("flip-1000") => o[1000] ^= 1,
            _ => {}
        }
        let c = x.get("content").map_or(content.clone(), canon);
        let want = x["code"].as_str().unwrap_or("Ok");
        let want = if want == "file" {
            "PqChatContent"
        } else {
            want
        };
        assert_eq!(code(a.pqchat_open_file(c, o)), want, "{}", x["name"]);
    }
    for x in m["fileContentRefused"].as_array().unwrap() {
        assert_eq!(
            code(a.pqchat_open_file(canon(&x["content"]), object.clone())),
            "PqChatContent",
            "{}",
            x["name"]
        );
        assert_eq!(
            code(a.pqchat_open_file(canon(&x["twin"]), object.clone())),
            "Ok"
        );
    }
    // (a) on the account's own chain
    let me = format!("0x{}", hexs(&w.ua_key(0x0131, 0, 0).unwrap().ua().unwrap()));
    let own = pos(me.clone(), counter);
    let header = PqMessageHeader {
        session_id: s(&r["sessionId"]),
        epoch_id: s(&r["epochId"]),
        device: s(&r["device"]),
        counter,
        parents: r["parents"].as_array().unwrap().iter().map(s).collect(),
    };
    let file_key = || {
        a.vectors_import(&seed, a32(&f["fileKey"]), AppKeyUsage::File)
            .unwrap()
    };
    let sealed = a
        .pqchat_seal_file_message(
            ua(&seed, 0x0131),
            k.clone(),
            own.clone(),
            header.clone(),
            s(&f["sealed"]),
            file_key(),
        )
        .await
        .unwrap();
    assert_eq!(sealed.record.sender, me);
    let back = a
        .pqchat_open_message(own.clone(), sealed.record.clone())
        .unwrap();
    assert_eq!(back.with(|b| b.to_vec()), s(&f["content"]).as_bytes());
    let key = unhex(&f["fileKey"]);
    let hexkey = s(&f["fileKey"]);
    let js = serde_json::to_string(&sealed).unwrap();
    assert!(
        !js.contains(&hexkey[2..]),
        "the key in no field that leaves"
    );
    for b in [
        &sealed.inner,
        &sealed.env,
        &sealed.payload,
        &sealed.record.ciphertext,
    ] {
        assert!(!b.windows(32).any(|x| x == &key[..]));
    }
    let data = a.random_key(&seed, AppKeyUsage::Data).unwrap();
    assert_eq!(
        code(
            a.pqchat_seal_file_message(
                ua(&seed, 0x0131),
                k.clone(),
                own.clone(),
                header.clone(),
                s(&f["sealed"]),
                data
            )
            .await
        ),
        "AppKeyUsage"
    );
    for x in m["fileSealRefused"].as_array().unwrap() {
        let seal = |v: &Value| {
            a.pqchat_seal_file_message(
                ua(&seed, 0x0131),
                k.clone(),
                own.clone(),
                header.clone(),
                v.to_string(),
                file_key(),
            )
        };
        assert_eq!(
            code(seal(&x["content"]).await),
            "PqChatContent",
            "{}",
            x["name"]
        );
        assert_eq!(code(seal(&x["twin"]).await), "Ok", "{}", x["name"]);
    }
}

/// pqchat-core T10b, the class fix: `AppCore::open_file` checks the length and `ctSha256` before any decryption.
#[tokio::test(flavor = "multi_thread")]
async fn open_file_checks_ct_sha256_first() {
    let _one = ONE.lock().await;
    let (sdk, seed, _c) = on_fake().await;
    let a = AppCore::new(sdk, desc(&[PQC])).unwrap();
    let s = a.seal_file(&seed, b"hello".to_vec()).unwrap();
    let open = |o: Vec<u8>, ct: Vec<u8>| a.open_file(s.key.clone(), o, 5, s.sha256.clone(), ct);
    assert_eq!(
        open(s.object.clone(), s.ct_sha256.clone())
            .unwrap()
            .with(|b| b.to_vec()),
        b"hello",
        "control"
    );
    let mut flip = s.object.clone();
    flip[100] ^= 1;
    assert_eq!(code(open(flip, s.ct_sha256.clone())), "FileHashMismatch");
    assert_eq!(
        code(open(s.object.clone(), vec![0; 32])),
        "FileHashMismatch"
    );
    assert_eq!(
        code(open(
            s.object[..s.object.len() - 1].to_vec(),
            s.ct_sha256.clone()
        )),
        "FileLength"
    );
    assert_eq!(code(open(s.object.clone(), vec![0; 31])), "Argument");
}

/// pqchat-core T11's hostile entries (vectors build only): the envelope of a record and a signature given apart reproduces
/// the `envelope` row; a `sealedInfo` of a given padded plaintext reproduces each `sealedInfo` row and, its plaintext made
/// non-canonical (one space), is refused at K5 (`PqChatContent`) beside its twin; S5 from the `message` row's padded
/// plaintext opens, and the same with a non-zero fill byte under `mk` is refused (`PqChatContent`).
#[tokio::test(flavor = "multi_thread")]
async fn hostile_seals_for_the_e2e() {
    let _one = ONE.lock().await;
    let (sdk, seed, _c) = on_fake().await;
    let a = AppCore::new(sdk, desc(&[PQC])).unwrap();
    let (m, rec) = (pq("messages"), pq("records"));
    let e = &m["envelope"];
    let k = a
        .vectors_import(&seed, a32(&e["K"]), AppKeyUsage::Derive)
        .unwrap();
    let r = &rec["message"]["record"];
    let env = a
        .pqchat_vectors_envelope(
            k.clone(),
            record_of(r),
            sig_of(&rec["message"]["uaSig"]),
            a12(&e["nonce"]),
        )
        .unwrap();
    assert_eq!(env, unhex(&e["env"]));
    for row in m["sealedInfo"].as_array().unwrap() {
        let k = a
            .vectors_import(&seed, a32(&row["K"]), AppKeyUsage::Derive)
            .unwrap();
        let (sid, eid) = (s(&row["sessionId"]), s(&row["epochId"]));
        let sealed = a
            .pqchat_vectors_seal_info_raw(
                k.clone(),
                sid.clone(),
                eid.clone(),
                unhex(&row["pt"]),
                a12(&row["nonce"]),
            )
            .unwrap();
        assert_eq!(sealed, unhex(&row["sealedInfo"]), "{}", row["name"]);
        let json = row["json"].as_str().unwrap();
        let spaced = format!("{{ {}", &json[1..]);
        let pt = |t: &str| {
            let mut p = (t.len() as u32).to_be_bytes().to_vec();
            p.extend_from_slice(t.as_bytes());
            p.resize(
                unhex(&row["pt"]).len().max(p.len().next_multiple_of(256)),
                0,
            );
            p
        };
        for (t, want) in [(json, "Ok"), (spaced.as_str(), "PqChatContent")] {
            let x = a
                .pqchat_vectors_seal_info_raw(k.clone(), sid.clone(), eid.clone(), pt(t), [7; 12])
                .unwrap();
            assert_eq!(
                code(a.pqchat_open_info(k.clone(), sid.clone(), eid.clone(), x)),
                want,
                "{}",
                row["name"]
            );
        }
    }
    // S5 from a padded plaintext at the account's own chain (the sender is the signing account)
    let k = a
        .vectors_import(&seed, a32(&m["message"]["K"]), AppKeyUsage::Derive)
        .unwrap();
    let wl = Wallet::from_mnemonic(REPO, "").unwrap();
    let me = format!(
        "0x{}",
        hexs(&wl.ua_key(0x0131, 0, 0).unwrap().ua().unwrap())
    );
    let header = PqMessageHeader {
        session_id: s(&r["sessionId"]),
        epoch_id: s(&r["epochId"]),
        device: s(&r["device"]),
        counter: 3,
        parents: vec![],
    };
    let pos = || {
        let p0 = a
            .pqchat_chain(
                k.clone(),
                s(&r["sessionId"]),
                s(&r["epochId"]),
                me.clone(),
                s(&r["device"]),
            )
            .unwrap();
        a.pqchat_advance(p0, 3).unwrap()
    };
    // the `message` row's padded plaintext, and the same with one fill byte non-zero (as the `unpadRefused` row)
    let twin = unhex(&m["message"]["pt"]);
    let mut fill = twin.clone();
    *fill.last_mut().unwrap() = 1;
    for (pt, want) in [(twin, "Ok"), (fill, "PqChatContent")] {
        let x = a
            .pqchat_vectors_seal_padded(
                ua(&seed, 0x0131),
                k.clone(),
                pos(),
                header.clone(),
                pt,
                [9; 12],
            )
            .await
            .unwrap();
        assert_eq!(x.record.sender, me);
        assert_eq!(code(a.pqchat_open_message(pos(), x.record)), want);
    }
}
