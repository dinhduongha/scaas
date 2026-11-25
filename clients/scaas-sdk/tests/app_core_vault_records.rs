// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! PqVault plan V9, part 2 (spec §5.2–§5.4, §6.9; CLI-PQV-12): `smartcontracts/vectors/pqvault/records.json` through the SDK's
//! PqVault signing path (owner 2026-11-22: `sign_pqvault_record`, `verify_pqvault_record`; no `scaas-ua` call below the test).
//! Every record's typed digest in its vault's domain (portable `DS_V` for mode 0, chain-bound `DS_B` for mode 1) as
//! `sign_pqvault_record` gives it; the two signing paths by the `PQV_ACCOUNT` keys the SDK opens from the vectors' mnemonic;
//! every committed signature (the `mldsa65` signers come from a raw 64-byte seed the SDK never opens, so their signatures are
//! verified, not reproduced) judged by `verify_pqvault_record` against a fake registry; the generic app calls refusing every
//! PqVault record and the dedicated ones refusing what is not one, each beside its control; the mode refusals (a mode flipped after signing, another instance); a native
//! EVM key's mode-0 seat signature inside an `msig`. Not here: ids, scopes, `sigHash` and blobs (`pqvault-core`'s encodings,
//! V10), and the native member's mode-1 row (its `msig` is a random id with no structure, and its registry is a
//! generation-2 one, whose `UAAuth` domain the SDK does not build yet: docs/clients/scaas-sdk.md, F2).
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
use scaas_sdk::account::msig::{msig_structure, MsigMemberArgs};
use scaas_sdk::app_core::{AppCore, AppDesc, AppMemberSig, AppPath, AppUaSig};
use scaas_sdk::op::KeyRef;
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, Sdk, SdkConfig,
};
use scaas_ua::wallet::SecretBytes;
use serde_json::{json, Map, Value};
use std::sync::Arc;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REGISTRY: &str = "0x5ca00000000000000000000000000000000000a1";
const PQV: &str = "scaas/pqvault/v1/";
const MSIG: u16 = 0x0120;
const EVM_EOA: u16 = 1;

fn doc() -> Value {
    let p = format!(
        "{}/../../smartcontracts/vectors/pqvault/records.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn unhex(v: &Value) -> Vec<u8> {
    let h = v.as_str().unwrap().trim_start_matches("0x");
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}
fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn sec(s: &str) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(s.as_bytes().to_vec())).unwrap())
}
fn s(v: &Value) -> String {
    v.as_str().unwrap().to_string()
}

/// An EIP-712 `encodeType` string (`A(t a,u b)B(…)…`) as the JSON `types` entries.
fn types_of(enc: &str, out: &mut Map<String, Value>) {
    let mut rest = enc;
    while let Some(open) = rest.find('(') {
        let close = open + rest[open..].find(')').unwrap();
        let fields: Vec<Value> = rest[open + 1..close]
            .split(',')
            .filter(|f| !f.is_empty())
            .map(|f| {
                let (t, n) = f.split_once(' ').unwrap();
                json!({"name": n, "type": t})
            })
            .collect();
        out.insert(rest[..open].to_string(), Value::Array(fields));
        rest = &rest[close + 1..];
    }
}

/// A record's typed data in a domain: the types from the vectors' type strings, the message the record's named fields.
fn typed(d: &Value, st: &str, record: &Value, domain: &Value) -> String {
    let mut types = Map::new();
    types_of(d["typehashes"][st]["type"].as_str().unwrap(), &mut types);
    let dk = if domain.get("salt").is_some() {
        "V"
    } else {
        "B"
    };
    types_of(d["domains"][dk]["type"].as_str().unwrap(), &mut types);
    json!({"types": types, "primaryType": st, "domain": domain, "message": record}).to_string()
}
fn ds_v(d: &Value) -> Value {
    let v = &d["domains"]["V"];
    json!({"name": v["name"], "version": v["version"], "salt": v["salt"]})
}
fn ds_b(d: &Value, chain_id: &Value, contract: &Value) -> Value {
    let b = &d["domains"]["B"];
    json!({"name": b["name"], "version": b["version"], "chainId": chain_id, "verifyingContract": contract})
}
fn chain_bound() -> AppPath {
    AppPath::ChainBound {
        chain: "local".into(),
        purpose: None,
    }
}
/// A vault's path and domain by its mode: 0 portable under `DS_V`, 1 chain-bound under `DS_B`.
fn by_mode(d: &Value, mode: u64) -> (AppPath, Value) {
    match mode {
        0 => (AppPath::Portable, ds_v(d)),
        1 => (
            chain_bound(),
            ds_b(
                d,
                &d["domains"]["B"]["chainId"],
                &d["domains"]["B"]["verifyingContract"],
            ),
        ),
        _ => panic!("mode {mode}"),
    }
}
/// Every record row with its vault's mode.
fn rows(d: &Value) -> Vec<(u64, Value)> {
    d["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|v| {
            let m = v["mode"].as_u64().unwrap();
            v["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(move |r| (m, r.clone()))
        })
        .collect()
}
fn named(d: &Value, name: &str) -> (u64, Value) {
    rows(d)
        .into_iter()
        .find(|(_, r)| r["name"] == name)
        .unwrap_or_else(|| panic!("{name}"))
}
fn signer<'a>(d: &'a Value, name: &str) -> &'a Value {
    d["signers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == name)
        .unwrap()
}
fn ua_sig(v: &Value) -> AppUaSig {
    assert!(v["members"].as_array().unwrap().is_empty());
    AppUaSig {
        key_data: unhex(&v["keyData"]),
        signature: unhex(&v["signature"]),
        members: vec![],
    }
}

/// One live scope declares PqVault's prefix at a time (spec §12.3): each test holds this lock.
static ONE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

/// The SDK on the fake chain with `pqvAccount`'s mnemonic imported, and PqVault's scope (its `app_id`, its prefix).
async fn on_fake(d: &Value) -> (Arc<AppCore>, String, Fake) {
    let (sdk, seed, chain) = open_fake(d).await;
    let a = AppCore::new(
        sdk,
        AppDesc {
            app_id: Some(s(&d["purpose"]["appId"])),
            name: "PqVault".into(),
            class: None,
            labels: vec![PQV.into()],
        },
    )
    .unwrap();
    (a, seed, chain)
}
/// The SDK on the fake chain with `pqvAccount`'s mnemonic imported.
async fn open_fake(d: &Value) -> (Arc<Sdk>, String, Fake) {
    let chain = fake();
    let url = serve(chain.clone()).await;
    let genesis = chain.lock().unwrap().genesis.clone();
    let sdk = Sdk::open(SdkConfig {
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
    let seed = sdk
        .vault()
        .import_words(ImportWords {
            label: "pqv".into(),
            words: sec(d["pqvAccount"]["mnemonic"].as_str().unwrap()),
            vault_passphrase: sec(PASS),
        })
        .await
        .unwrap()
        .id;
    (sdk, seed, chain)
}
/// A `PQV_ACCOUNT` key of the imported mnemonic (FN-DSA-512): index 0 the index vault's UA, 1 the personal vault's.
fn pqv_key(d: &Value, seed: &str, index: u32) -> KeyRef {
    KeyRef::Ua {
        seed: seed.into(),
        kind: u16::try_from(signer(d, "index")["kind"].as_u64().unwrap()).unwrap(),
        account: u32::try_from(d["pqvAccount"]["account"].as_u64().unwrap()).unwrap(),
        index,
    }
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
/// `registrationOf(id)`: `(uint16 kind, bytes keyData, …)` (the rest unread).
fn reg_answer(c: &Fake, id: &[u8], kind: u16, kd: &[u8]) {
    let out = [
        w(u64::from(kind)),
        w(0xa0),
        w(0),
        w(0),
        w(0),
        w(kd.len() as u64),
        pad(kd),
    ]
    .concat();
    answer(c, REGISTRY, "registrationOf(bytes32)", id, out);
}
/// Every signer of the vectors registered with its kind and public key (a stored kind: the key is the record's).
fn register_all(c: &Fake, d: &Value) {
    for x in d["signers"].as_array().unwrap() {
        let kind = u16::try_from(x["kind"].as_u64().unwrap()).unwrap();
        reg_answer(c, &unhex(&x["ua"]), kind, &unhex(&x["publicKey"]));
    }
}

/// Each record's typed digest in its vault's domain, as `sign_pqvault_record` states it (`digest`), equals the row's `typed`; the
/// flipped and other-instance rows' digests too, each beside the one signed.
#[tokio::test(flavor = "multi_thread")]
async fn typed_digests_in_both_domains() {
    let _one = ONE.lock().await;
    let d = doc();
    let (a, seed, _chain) = on_fake(&d).await;
    let key = pqv_key(&d, &seed, 0);
    let digest = |p: AppPath, t: String| {
        let (a, key) = (a.clone(), key.clone());
        async move { a.sign_pqvault_record(key, p, None, t).await.unwrap().digest }
    };
    let all = rows(&d);
    assert_eq!(all.len(), 23);
    let mut modes = [0u32; 2];
    for (mode, r) in &all {
        let (p, dom) = by_mode(&d, *mode);
        let t = typed(&d, r["struct"].as_str().unwrap(), &r["record"], &dom);
        assert_eq!(digest(p, t).await, s(&r["typed"]), "{}", r["name"]);
        modes[usize::try_from(*mode).unwrap()] += 1;
    }
    assert_eq!(modes, [13, 10]);
    // F-4 / D2-3: a leave's and a removal's review say that they apply within the lag of the epoch they name; other records none
    let mut exits = 0;
    for (mode, r) in &all {
        let (p, dom) = by_mode(&d, *mode);
        let st = r["struct"].as_str().unwrap();
        let t = typed(&d, st, &r["record"], &dom);
        let prep = a
            .prepare_pqvault_record(key.clone(), p, None, t)
            .await
            .unwrap();
        let line = prep
            .review
            .iter()
            .find(|f| f.name == "appliesWithin")
            .map(|f| f.value.clone());
        let want = match st {
            "PqVaultRemove" => Some(format!(
                "applies if it lands within 16 epochs of epoch {}; it cannot be withdrawn",
                r["record"]["nextEpoch"].as_u64().unwrap() - 1
            )),
            "PqVaultLeave" => Some(format!(
                "applies if it lands within 16 epochs of the epoch it names ({}); it cannot be withdrawn",
                s(&r["record"]["epochId"])
            )),
            _ => None,
        };
        exits += usize::from(want.is_some());
        assert_eq!(line, want, "{}", r["name"]);
    }
    assert!(exits >= 2, "a leave and a removal row");
    // CTR-PQV-18: `createTreeKem`, a create record of groupMode 1 (refused by the contract and pqvault-core), hashes as signed
    let tk = &d["createTreeKem"];
    assert_eq!(tk["record"]["groupMode"], 1);
    let t = typed(&d, "PqVaultCreate", &tk["record"], &ds_v(&d));
    assert_eq!(digest(AppPath::Portable, t).await, s(&tk["typed"]));
    // a create record with its mode flipped after signing: the new mode's domain gives `typed`, never `signedTyped`
    for f in d["modes"]["flipped"].as_array().unwrap() {
        let (_, of) = named(&d, f["of"].as_str().unwrap());
        assert_eq!(s(&of["typed"]), s(&f["signedTyped"]));
        let mode = f["mode"].as_u64().unwrap();
        let (p, dom) = match mode {
            0 => (AppPath::Portable, ds_v(&d)),
            _ => (
                chain_bound(),
                ds_b(&d, &f["chainId"], &f["verifyingContract"]),
            ),
        };
        let got = digest(p, typed(&d, "PqVaultCreate", &f["record"], &dom)).await;
        assert_eq!(got, s(&f["typed"]), "{}", f["name"]);
        assert_ne!(got, s(&f["signedTyped"]));
    }
    // a mode-1 record at another instance: its digest there
    for o in d["modes"]["otherInstance"].as_array().unwrap() {
        let (_, r) = named(&d, o["record"].as_str().unwrap());
        let dom = ds_b(&d, &d["domains"]["B"]["chainId"], &o["instance"]);
        let got = digest(
            chain_bound(),
            typed(&d, s(&r["struct"]).as_str(), &r["record"], &dom),
        )
        .await;
        assert_eq!(got, s(&o["typedThere"]));
        assert_ne!(got, s(&r["typed"]));
    }
}

/// The two signing paths by the keys the SDK opens: the index vault's records (mode 0) portable by `PQV_ACCOUNT` index 0,
/// the personal vault's (mode 1) chain-bound by index 1; the key data empty (a stored kind), the signature verified by the
/// registry's record of that UA (the vectors' public key: the SDK's key is the row's signer). The SDK's FN-DSA signing is
/// randomized (the generator's pq.js call is deterministic), so the committed signature is verified beside the SDK's, never
/// compared to it.
#[tokio::test(flavor = "multi_thread")]
async fn signing_paths_by_the_pqv_account() {
    let _one = ONE.lock().await;
    let d = doc();
    let (a, seed, chain) = on_fake(&d).await;
    register_all(&chain, &d);
    let mut n = 0;
    for (vault, who, index) in [("index0", "index", 0u32), ("personal1", "personal", 1)] {
        let v = d["vaults"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["name"] == vault)
            .unwrap();
        let ua = s(&signer(&d, who)["ua"]);
        assert_eq!(ua, s(&d["pqvAccount"]["rows"][index as usize]["ua"]));
        let (p, dom) = by_mode(&d, v["mode"].as_u64().unwrap());
        for r in v["records"].as_array().unwrap() {
            assert_eq!(r["signer"], who);
            let t = typed(&d, r["struct"].as_str().unwrap(), &r["record"], &dom);
            let sg = a
                .sign_pqvault_record(pqv_key(&d, &seed, index), p.clone(), None, t.clone())
                .await
                .unwrap();
            assert_eq!(sg.digest, s(&r["typed"]));
            assert!(sg.key_data.is_empty());
            // randomized: a second signature differs, from the SDK's and from the committed one
            let again = a
                .sign_pqvault_record(pqv_key(&d, &seed, index), p.clone(), None, t.clone())
                .await
                .unwrap();
            assert_ne!(again.signature, sg.signature);
            assert_ne!(sg.signature, unhex(&r["uaSig"]["signature"]));
            let mine = AppUaSig {
                key_data: sg.key_data,
                signature: sg.signature,
                members: vec![],
            };
            let ok = |sig: AppUaSig| {
                let (a, ua, p, t) = (a.clone(), ua.clone(), p.clone(), t.clone());
                async move {
                    a.verify_pqvault_record("local".into(), ua, p, t, sig)
                        .await
                        .unwrap()
                }
            };
            assert!(ok(mine.clone()).await, "{}", r["name"]);
            assert!(ok(ua_sig(&r["uaSig"])).await, "{}", r["name"]);
            // the twin: one byte of the SDK's signature changed
            let mut bad = mine;
            bad.signature[7] ^= 1;
            assert!(!ok(bad).await, "{}", r["name"]);
            n += 1;
        }
    }
    assert_eq!(n, 7);
}

/// Every committed signature verifies on its vault's path against the registry's records; each refusal one change at a time
/// beside its control: unregistered, another key under the UA, a changed signature, a changed field, the other path's
/// domain, a mode flipped after signing (UAUnauthorized at the contract), another instance (PqVaultShape there).
#[tokio::test(flavor = "multi_thread")]
async fn verify_app_record_on_the_committed_rows() {
    let _one = ONE.lock().await;
    let d = doc();
    let (a, _seed, chain) = on_fake(&d).await;
    register_all(&chain, &d);
    let verify = |ua: String, p: AppPath, t: String, sig: AppUaSig| {
        let a = a.clone();
        async move {
            a.verify_pqvault_record("local".into(), ua, p, t, sig)
                .await
                .unwrap()
        }
    };
    for (mode, r) in rows(&d) {
        let (p, dom) = by_mode(&d, mode);
        let ua = s(&signer(&d, r["signer"].as_str().unwrap())["ua"]);
        let t = typed(&d, r["struct"].as_str().unwrap(), &r["record"], &dom);
        assert!(verify(ua, p, t, ua_sig(&r["uaSig"])).await, "{}", r["name"]);
    }
    // CTR-PQV-18: `createTreeKem` carries its creator's real signature (refused for its groupMode alone, by the contract)
    let tk = &d["createTreeKem"];
    let t = typed(&d, "PqVaultCreate", &tk["record"], &ds_v(&d));
    let ua = s(&signer(&d, tk["signer"].as_str().unwrap())["ua"]);
    assert_eq!(tk["error"], "PqVaultModeUnsupported(1)");
    assert!(verify(ua, AppPath::Portable, t, ua_sig(&tk["uaSig"])).await);

    // one record per mode for the refusals
    for name in ["shared0.item", "shared1.item"] {
        let (mode, r) = named(&d, name);
        let st = s(&r["struct"]);
        let (p, dom) = by_mode(&d, mode);
        let t = typed(&d, &st, &r["record"], &dom);
        let who = signer(&d, r["signer"].as_str().unwrap());
        let (ua, kind) = (
            s(&who["ua"]),
            u16::try_from(who["kind"].as_u64().unwrap()).unwrap(),
        );
        let sig = ua_sig(&r["uaSig"]);
        let control = || verify(ua.clone(), p.clone(), t.clone(), sig.clone());
        assert!(control().await, "{name}");
        reg_answer(&chain, &unhex(&who["ua"]), 0, &[]);
        assert!(!control().await, "{name}: unregistered");
        reg_answer(
            &chain,
            &unhex(&who["ua"]),
            kind,
            &unhex(&signer(&d, "carol")["publicKey"]),
        );
        assert!(!control().await, "{name}: another key under the UA");
        reg_answer(&chain, &unhex(&who["ua"]), kind, &unhex(&who["publicKey"]));
        assert!(control().await, "{name}");
        let mut bad = sig.clone();
        bad.signature[11] ^= 1;
        assert!(
            !verify(ua.clone(), p.clone(), t.clone(), bad).await,
            "{name}: a changed signature"
        );
        let mut rec = r["record"].clone();
        rec["nonce"] = json!(rec["nonce"].as_u64().unwrap() + 1);
        assert!(
            !verify(
                ua.clone(),
                p.clone(),
                typed(&d, &st, &rec, &dom),
                sig.clone()
            )
            .await,
            "{name}: a changed field"
        );
        let (op, odom) = by_mode(&d, 1 - mode);
        assert!(
            !verify(
                ua.clone(),
                op,
                typed(&d, &st, &r["record"], &odom),
                sig.clone()
            )
            .await,
            "{name}: the other mode's domain"
        );
    }
    for f in d["modes"]["flipped"].as_array().unwrap() {
        assert_eq!(f["error"], "UAUnauthorized");
        let (mode, of) = named(&d, f["of"].as_str().unwrap());
        let ua = s(&signer(&d, of["signer"].as_str().unwrap())["ua"]);
        let sig = ua_sig(&of["uaSig"]);
        let (p, dom) = by_mode(&d, mode);
        assert!(
            verify(
                ua.clone(),
                p,
                typed(&d, "PqVaultCreate", &of["record"], &dom),
                sig.clone()
            )
            .await
        );
        let (fp, fdom) = match f["mode"].as_u64().unwrap() {
            0 => (AppPath::Portable, ds_v(&d)),
            _ => (
                chain_bound(),
                ds_b(&d, &f["chainId"], &f["verifyingContract"]),
            ),
        };
        assert!(
            !verify(ua, fp, typed(&d, "PqVaultCreate", &f["record"], &fdom), sig).await,
            "{}",
            f["name"]
        );
    }
    for o in d["modes"]["otherInstance"].as_array().unwrap() {
        let (_, r) = named(&d, o["record"].as_str().unwrap());
        let ua = s(&signer(&d, r["signer"].as_str().unwrap())["ua"]);
        let dom = ds_b(&d, &d["domains"]["B"]["chainId"], &o["instance"]);
        let t = typed(&d, s(&r["struct"]).as_str(), &r["record"], &dom);
        assert!(
            !verify(ua, chain_bound(), t, ua_sig(&r["uaSig"])).await,
            "{}",
            o["record"]
        );
    }
}

/// `nativeMember` mode 0: an EVM key holding a seat of an `msig` signs the record's typed digest itself; `verify_pqvault_record`
/// on the portable path takes it inside an `msig` whose structure holds that native id (the seat's `msig` in the vectors is a
/// random id, so this structure is the test's, the signature the vectors'); the mode-1 signature presented in mode 0 refused
/// (`UAUnauthorized` at the contract), and a seat not accepted.
#[tokio::test(flavor = "multi_thread")]
async fn native_member_in_an_msig() {
    let _one = ONE.lock().await;
    let d = doc();
    let (a, _seed, chain) = on_fake(&d).await;
    register_all(&chain, &d);
    let nm = &d["nativeMember"];
    let (mode, r) = named(&d, nm["mode0"]["record"].as_str().unwrap());
    assert_eq!(mode, 0);
    assert_eq!(nm["mode0"]["digest"], r["typed"]);
    let nid = format!(
        "0x{}{}",
        "00".repeat(12),
        s(&nm["address"]).trim_start_matches("0x")
    );
    let alice = signer(&d, "alice");
    let st = msig_structure(
        vec![
            MsigMemberArgs {
                kind: EVM_EOA,
                id: nid.clone(),
                weight: 1,
            },
            MsigMemberArgs {
                kind: u16::try_from(alice["kind"].as_u64().unwrap()).unwrap(),
                id: s(&alice["ua"]),
                weight: 1,
            },
        ],
        1,
    )
    .unwrap();
    let ms = st.ua().unwrap();
    // the registry's key data of the structure (CTR-UA-09): threshold, count, then (kind, id, weight) per slot
    let mut kd = [
        st.threshold.to_be_bytes(),
        (st.members.len() as u16).to_be_bytes(),
    ]
    .concat();
    for m in &st.members {
        kd.extend(m.kind.to_be_bytes());
        kd.extend(unhex(&json!(m.id)));
        kd.extend(m.weight.to_be_bytes());
    }
    let slot = u16::try_from(st.members.iter().position(|m| m.id == nid).unwrap()).unwrap();
    reg_answer(&chain, &unhex(&json!(ms)), MSIG, &kd);
    let state = |accepted: u64| {
        answer(
            &chain,
            REGISTRY,
            "msigStateOf(bytes32)",
            &unhex(&json!(ms)),
            [w(0), w(0b11), w(accepted)].concat(),
        )
    };
    state(0b11);
    let t = typed(&d, s(&r["struct"]).as_str(), &r["record"], &ds_v(&d));
    let seat = |sig: &Value| AppUaSig {
        key_data: vec![],
        signature: vec![],
        members: vec![AppMemberSig {
            index: slot,
            members: vec![],
            sig: unhex(sig),
        }],
    };
    let verify = |sig: AppUaSig| {
        let (a, ms, t) = (a.clone(), ms.clone(), t.clone());
        async move {
            a.verify_pqvault_record("local".into(), ms, AppPath::Portable, t, sig)
                .await
                .unwrap()
        }
    };
    assert!(verify(seat(&nm["mode0"]["signature"])).await);
    let refusal = nm["refusals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["signature"] == "mode1" && x["digest"] == "mode0")
        .unwrap();
    assert_eq!(refusal["error"], "UAUnauthorized");
    assert!(
        !verify(seat(&nm["mode1"]["signature"])).await,
        "{}",
        refusal["name"]
    );
    state(0b11 & !(1 << slot));
    assert!(
        !verify(seat(&nm["mode0"]["signature"])).await,
        "a seat not accepted"
    );
    state(0b11);
    assert!(verify(seat(&nm["mode0"]["signature"])).await);
}

fn code(e: scaas_sdk::SdkError) -> &'static str {
    e.code()
}

/// The two signing calls kept apart (owner 2026-11-22), each refusal beside its control: the generic call in PqVault's domain
/// on either path, and under PqVault's app id with an app's own domain name (control: the dedicated call on the same record);
/// the generic verification of a committed row (control: the dedicated one); the dedicated call in another domain (control:
/// `DS_V`), with a struct that is not PqVault's or a PqVault name with other fields (control: the record's own), and in a
/// scope of another app (control: PqVault's scope).
#[tokio::test(flavor = "multi_thread")]
async fn pqvault_path_refusals() {
    let _one = ONE.lock().await;
    let d = doc();
    let (a, seed, chain) = on_fake(&d).await;
    register_all(&chain, &d);
    let key = pqv_key(&d, &seed, 0);
    let sign_g = |p: AppPath, t: String| {
        let (a, key) = (a.clone(), key.clone());
        async move { a.sign_app_record(key, p, t).await.map(|s| s.digest) }
    };
    let sign_v = |p: AppPath, t: String| {
        let (a, key) = (a.clone(), key.clone());
        async move {
            a.sign_pqvault_record(key, p, None, t)
                .await
                .map(|s| s.digest)
        }
    };
    for name in ["index0.item-0", "personal1.item-0"] {
        let (mode, r) = named(&d, name);
        let (p, dom) = by_mode(&d, mode);
        let t = typed(&d, "PqVaultItem", &r["record"], &dom);
        assert_eq!(
            sign_v(p.clone(), t.clone()).await.unwrap(),
            s(&r["typed"]),
            "{name}"
        );
        assert_eq!(
            code(sign_g(p.clone(), t.clone()).await.unwrap_err()),
            "AppDomainRefused",
            "{name}"
        );
        // PqVault's app id or purpose under an app's own domain name: refused by the purpose
        let mut mine = dom.clone();
        mine["name"] = json!("My App");
        let tm = typed(&d, "PqVaultItem", &r["record"], &mine);
        assert_eq!(
            code(sign_g(p.clone(), tm.clone()).await.unwrap_err()),
            "AppPurposeRefused",
            "{name}"
        );
        // the dedicated call in that domain
        assert_eq!(
            code(sign_v(p.clone(), tm).await.unwrap_err()),
            "AppDomainRefused",
            "{name}"
        );
        // a struct that is not PqVault's, and PqVault's name with another field type
        let enc = d["typehashes"]["PqVaultItem"]["type"].as_str().unwrap();
        let mut types = Map::new();
        types_of(&enc.replace("PqVaultItem", "Note"), &mut types);
        let dk = if mode == 0 { "V" } else { "B" };
        types_of(d["domains"][dk]["type"].as_str().unwrap(), &mut types);
        let note =
            json!({"types": types, "primaryType": "Note", "domain": dom, "message": r["record"]})
                .to_string();
        assert_eq!(
            code(sign_v(p.clone(), note).await.unwrap_err()),
            "Argument",
            "{name}"
        );
        let mut types = Map::new();
        types_of(&enc.replace("uint64 nonce", "uint256 nonce"), &mut types);
        types_of(d["domains"][dk]["type"].as_str().unwrap(), &mut types);
        let wide =
            json!({"types": types, "primaryType": "PqVaultItem", "domain": dom, "message": r["record"]}).to_string();
        assert_eq!(
            code(sign_v(p.clone(), wide).await.unwrap_err()),
            "Argument",
            "{name}"
        );
        // a committed row: the generic verification false, the dedicated one true
        let ua = s(&signer(&d, r["signer"].as_str().unwrap())["ua"]);
        let sig = ua_sig(&r["uaSig"]);
        assert!(!a
            .verify_app_record(
                "local".into(),
                ua.clone(),
                p.clone(),
                t.clone(),
                sig.clone()
            )
            .await
            .unwrap());
        assert!(a
            .verify_pqvault_record("local".into(), ua, p, t, sig)
            .await
            .unwrap());
    }
    // a scope of another app: its path is not PqVault's (control: PqVault's scope above)
    let (sdk, seed, _chain) = open_fake(&d).await;
    let other = AppCore::new(
        sdk,
        AppDesc {
            app_id: Some(format!("0x{}", "5a".repeat(32))),
            name: "Other".into(),
            class: None,
            labels: vec!["scaas/other/v1/".into()],
        },
    )
    .unwrap();
    let (_, r) = named(&d, "index0.item-0");
    let t = typed(&d, "PqVaultItem", &r["record"], &ds_v(&d));
    let e = other
        .sign_pqvault_record(pqv_key(&d, &seed, 0), AppPath::Portable, None, t)
        .await
        .unwrap_err();
    assert_eq!(code(e), "AppDomainRefused");
}

/// Controller call 2026-11-22 (CLI-PQV-15, explicit parameters): the registry an `msig` signer's records are read on is named,
/// never searched for. On the portable path an `msig` without `records` is `Argument` (no read made), a single key with one
/// `Argument` (nothing reads it); on the chain-bound path `records` naming another chain is `Argument`; each beside its control
/// (the single key's portable signature without `records`, its chain-bound one with the path's own chain).
#[tokio::test(flavor = "multi_thread")]
async fn pqvault_records_chain_is_explicit() {
    use scaas_sdk::op::MsigSlot;
    let _one = ONE.lock().await;
    let d = doc();
    let (a, seed, chain) = on_fake(&d).await;
    register_all(&chain, &d);
    let key = pqv_key(&d, &seed, 0);
    let (mode, r) = named(&d, "index0.item-0");
    let (p, dom) = by_mode(&d, mode);
    assert!(matches!(p, AppPath::Portable));
    let t = typed(&d, "PqVaultItem", &r["record"], &dom);
    let msig = KeyRef::Msig {
        ua: format!("0x{}", "77".repeat(32)),
        slots: vec![MsigSlot::Member {
            index: 0,
            key: key.clone(),
        }],
    };
    let sign = |k: KeyRef, p: AppPath, rec: Option<&str>| {
        let (a, t) = (a.clone(), t.clone());
        let rec = rec.map(str::to_string);
        async move { a.sign_pqvault_record(k, p, rec, t).await.map(|s| s.digest) }
    };
    assert_eq!(
        sign(msig.clone(), AppPath::Portable, None)
            .await
            .err()
            .map(code),
        Some("Argument")
    );
    assert_eq!(
        sign(key.clone(), AppPath::Portable, Some("local"))
            .await
            .err()
            .map(code),
        Some("Argument")
    );
    assert_eq!(
        sign(key.clone(), AppPath::Portable, None).await.unwrap(),
        s(&r["typed"]),
        "the control"
    );
    let (mode1, r1) = named(&d, "personal1.item-0");
    let (pb, dom1) = by_mode(&d, mode1);
    let t1 = typed(&d, "PqVaultItem", &r1["record"], &dom1);
    let sign1 = |rec: Option<&str>| {
        let (a, t1, pb, key) = (a.clone(), t1.clone(), pb.clone(), key.clone());
        let rec = rec.map(str::to_string);
        async move {
            a.sign_pqvault_record(key, pb, rec, t1)
                .await
                .map(|s| s.digest)
        }
    };
    assert_eq!(
        sign1(Some("elsewhere")).await.err().map(code),
        Some("Argument")
    );
    assert_eq!(
        sign1(Some("local")).await.unwrap(),
        s(&r1["typed"]),
        "the control: the path's own chain"
    );
    assert_eq!(sign1(None).await.unwrap(), s(&r1["typed"]));
    // the portable msig with its records named reaches the registry read (an msig the fake registry does not hold)
    assert!(sign(msig, AppPath::Portable, Some("local")).await.is_err());
}
