// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T18: every `GovernanceRouter` row of `smartcontracts/vectors/typed/typed_ops.json` prepared by its own `admin_<struct>`
//! from the row's named fields (the row's key imported): the operation's id is the row's digest; a creation's `initHash` is
//! the named config's of `vectors/factory/create_config.json`; the CREATE3 preview is `vectors/factory/create3_kat.json`'s; the
//! wallet's rows refuse the router (its `UACancelNonce` is admin's). Local only: the fake chain of `tests/common`.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]
#[allow(clippy::duplicate_mod)]
#[path = "../tests/common/fake_chain.rs"]
mod fake_chain;

use super::*;
use crate::vault::{ImportKey, ImportWords, MemoryStore};
use crate::{ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, SdkConfig};
use fake_chain::{fake, serve, CHAIN_ID};
use scaas_ua::wallet::SecretBytes;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const CREATES: [&str; 3] = ["UACreateToken", "UACreateDex", "UACreateInstance"];

fn load(p: &str) -> Value {
    let path = format!("{}/../../{p}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn sec(b: &[u8]) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(b.to_vec())).unwrap())
}

fn endpoint(url: &str) -> EndpointConfig {
    EndpointConfig {
        url: url.into(),
        class: scaas_rpc::Class::Named,
        label: None,
        auth: None,
    }
}

/// An SDK whose profile's router is the rows' router (and a token of the rows' token domain), with the rows' key imported.
/// structures.json context A's registry (the typed_ops rows' `UAAuth` domain).
const REGISTRY: &str = "0x5ca0000000000000000000000000000000000001";

async fn setup() -> (Arc<Sdk>, KeyRef, Value) {
    let v = load("smartcontracts/vectors/typed/typed_ops.json");
    let d = &v["ops"]["UAGrantRole"]["domains"]["gov_router"]["domain"];
    let (router, salt) = (text(&d["verifyingContract"]), text(&d["salt"]));
    let token = text(&v["ops"]["UACancelNonce"]["domains"]["token"]["domain"]["verifyingContract"]);
    let chain = fake();
    {
        let mut c = chain.lock().unwrap();
        c.domains.insert(
            router.clone(),
            ("SCaaS GovernanceRouter".into(), salt.clone()),
        );
        c.domains
            .insert(token, ("SCaaS MetaToken".into(), salt.clone()));
        let pqz =
            text(&v["ops"]["AuditorConsent"]["domains"]["pqz"]["domain"]["verifyingContract"]);
        c.domains
            .insert(pqz, ("SCaaS PqzToken".into(), salt.clone()));
        let zether =
            text(&v["ops"]["AuditorConsent"]["domains"]["zether"]["domain"]["verifyingContract"]);
        c.domains
            .insert(zether, ("SCaaS ZetherToken".into(), salt.clone()));
        c.genesis = salt.clone();
        // structures.json context A's registry, generation 1 (`predecessor() == 0`): a native auditor's consent domain
        c.answers.push((
            REGISTRY.into(),
            fake_chain::keccak_hex(b"predecessor()")[..10].to_string(),
            format!("0x{:064x}", 0),
        ));
    }
    let url = serve(chain).await;
    let profile = ChainProfile {
        key: "local".into(),
        family: Family::Evm,
        chain_id: Some(CHAIN_ID),
        chain_uid: salt,
        rpc: vec![endpoint(&url)],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: Some(REGISTRY.into()),
        factory: None,
        router: Some(router),
        finality: Finality::Finalized,
        tx_gas_cap: None,
        tokens: vec![],
        gas: Default::default(),
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![],
        wrappers: vec![],
        l1_fee: None,
        pinned_reads: true,
        disabled_kinds: vec![],
        family_params: None,
    };
    let sdk = Sdk::open(SdkConfig {
        profiles: vec![profile],
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
        clock: Some(Arc::new(|| 1_800_000_000)),
        gas_tables: vec![],
    })
    .await
    .unwrap();
    let seed = sdk
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words: sec(REPO.as_bytes()),
            vault_passphrase: sec(PASS.as_bytes()),
        })
        .await
        .unwrap()
        .id;
    let private = unhex(&text(&v["key"]["private"])).unwrap();
    let k = sdk
        .vault()
        .import_key(ImportKey {
            seed: seed.clone(),
            network: "evm".into(),
            secret: sec(&private),
            vault_passphrase: sec(PASS.as_bytes()),
        })
        .await
        .unwrap();
    let signer = KeyRef::Imported {
        seed,
        network: "evm".into(),
        index: k.index,
    };
    (sdk, signer, v)
}

fn envelope(m: &Value) -> Envelope {
    Envelope {
        valid_until: text(&m["validUntil"]).parse().unwrap(),
        mode: m["mode"].as_u64().unwrap() as u32,
        relayer: Some(text(&m["relayer"])),
        fee: text(&m["fee"]),
        fee_recipient: Some(text(&m["feeRecipient"])),
    }
}

/// One test per router pair, run as one loop: each row's id is its digest (a creation's initHash is a filler in the row, so
/// its id is checked by `creation_init_hash_is_the_named_configs` instead).
#[tokio::test(flavor = "multi_thread")]
async fn every_router_row_is_its_digest() {
    let (sdk, signer, v) = setup().await;
    let admin = sdk.admin();
    let mut n = 0;
    for (name, row) in v["ops"].as_object().unwrap() {
        let Some(r) = row["domains"].get("gov_router") else {
            continue;
        };
        let m = &row["message"];
        let mut x = r.get("extra").cloned().unwrap_or(json!({}));
        if let Some(c) = x.get("initCall").cloned() {
            x["init_call"] = c;
        }
        if name == "UACreateToken" || name == "UACreateDex" {
            let k = if name == "UACreateToken" {
                "token"
            } else {
                "dex"
            };
            x["config"] =
                load("smartcontracts/vectors/factory/create_config.json")[k]["config"].clone();
        }
        let p = admin
            .prepare_row(
                name,
                signer.clone(),
                "local".into(),
                text(&m["batch"]),
                m,
                &x,
                envelope(m),
            )
            .await
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let entry = scaas_ua::wallet::entries::entry_rows()
            .into_iter()
            .find(|e| e.name == name && e.kinds.contains(&"gov_router"))
            .unwrap()
            .entry;
        assert_eq!(p.entry(), entry, "{name}");
        if !CREATES.contains(&name.as_str()) {
            assert_eq!(p.id(), text(&r["digest"]), "{name}");
        }
        n += 1;
    }
    assert_eq!(n, 62, "every router pair, UACancelNonce among them");
}

/// A creation's signed `initHash` is the keccak of what `scaas-ua` encodes of its named config (token, DEX) or its initializer
/// call (instance): `create_config.json`'s.
#[tokio::test(flavor = "multi_thread")]
async fn creation_init_hash_is_the_named_configs() {
    let (sdk, signer, v) = setup().await;
    let kat = load("smartcontracts/vectors/factory/create_config.json");
    for (name, k) in [
        ("UACreateToken", "token"),
        ("UACreateDex", "dex"),
        ("UACreateInstance", "instance"),
    ] {
        let m = &v["ops"][name]["message"];
        let x = match k {
            "instance" => json!({"init_call": kat[k]["initCall"]}),
            _ => json!({"config": kat[k]["config"]}),
        };
        let p = sdk
            .admin()
            .prepare_row(
                name,
                signer.clone(),
                "local".into(),
                text(&m["batch"]),
                m,
                &x,
                envelope(m),
            )
            .await
            .unwrap();
        let h = p
            .review()
            .into_iter()
            .find(|f| f.name == "initHash")
            .unwrap();
        assert_eq!(h.value, text(&kat[k]["initHash"]), "{name}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn create3_preview_equals_factory_kat() {
    let (sdk, _, _) = setup().await;
    let kat = load("smartcontracts/vectors/factory/create3_kat.json");
    let rows = kat["rows"].as_array().unwrap();
    assert!(!rows.is_empty());
    for r in rows {
        let p = sdk
            .admin()
            .create3_address(
                text(&kat["factory"]),
                text(&r["creatorId"]),
                r["contractClass"].as_u64().unwrap() as u16,
                r["kind"].as_u64().unwrap() as u16,
                text(&r["salt"]),
            )
            .unwrap();
        assert_eq!(
            (p.s, p.proxy),
            (text(&r["s"]), text(&r["proxy"]).to_ascii_lowercase()),
            "{r}"
        );
        assert_eq!(p.instance, text(&r["instance"]).to_ascii_lowercase(), "{r}");
    }
}

/// The router's `UACancelNonce` is admin's: the wallet's entry refuses it (one entry point per pair); a token is the wallet's.
#[tokio::test(flavor = "multi_thread")]
async fn wallet_refuses_the_router_admin_takes_it() {
    let (sdk, signer, v) = setup().await;
    let m = &v["ops"]["UACancelNonce"]["message"];
    let router =
        text(&v["ops"]["UACancelNonce"]["domains"]["gov_router"]["domain"]["verifyingContract"]);
    let token = text(&v["ops"]["UACancelNonce"]["domains"]["token"]["domain"]["verifyingContract"]);
    let req = |contract: String| crate::wallet::CancelNonce {
        signer: signer.clone(),
        chain: "local".into(),
        contract,
        batch: text(&m["batch"]),
        lane: text(&m["lane"]),
        envelope: envelope(m),
    };
    let w = sdk.wallet();
    assert_eq!(
        w.prepare_cancel_nonce(req(router))
            .await
            .unwrap_err()
            .code(),
        "Argument"
    );
    assert!(w.prepare_cancel_nonce(req(token)).await.is_ok());
    let a = sdk
        .admin()
        .admin_ua_cancel_nonce(UaCancelNonce {
            signer,
            chain: "local".into(),
            batch: text(&m["batch"]),
            lane: text(&m["lane"]),
            chain_uid: None,
            envelope: envelope(m),
        })
        .await
        .unwrap();
    assert_eq!(
        a.id(),
        text(&v["ops"]["UACancelNonce"]["domains"]["gov_router"]["digest"])
    );
}

/// A nested field is bounded by its length and depth before any decode reaches `scaas-ua`.
#[test]
fn nested_fields_are_bounded() {
    assert!(nested(r#"{"a":{"b":[1]}}"#).is_ok());
    assert_eq!(
        nested(&"[".repeat(9).to_string()).unwrap_err().code(),
        "Argument"
    );
    let deep = format!("{}{}", "[".repeat(9), "]".repeat(9));
    assert_eq!(nested(&deep).unwrap_err().code(), "Argument");
    let long = format!("[\"{}\"]", "a".repeat(NESTED_MAX));
    assert_eq!(nested(&long).unwrap_err().code(), "Argument");
    assert_eq!(nested("1").unwrap_err().code(), "Argument");
}

/// The PQZ consent (`AuditorConsent` under `auditor-consent`) of a derived auditor UA; a native auditor refused by name
/// (`PqzAuditorNative`); another domain kind refused by the PQZ entry and the Zether entry alike.
#[tokio::test(flavor = "multi_thread")]
async fn pqz_auditor_consent_of_a_derived_ua() {
    let (sdk, signer, v) = setup().await;
    let row = &v["ops"]["AuditorConsent"];
    let token = text(&row["domains"]["pqz"]["domain"]["verifyingContract"]);
    let salt = text(&row["domains"]["pqz"]["domain"]["salt"]);
    let req = |token: String| AuditorConsent {
        signer: signer.clone(),
        chain: "local".into(),
        token,
        epoch: 1,
    };
    let other = text(&v["ops"]["UACancelNonce"]["domains"]["token"]["domain"]["verifyingContract"]);
    let a = sdk.admin();
    // a derived auditor UA: its `UASig` under `auditor-consent` over the token's consent of that UA
    let KeyRef::Imported { seed, .. } = signer.clone() else {
        panic!()
    };
    let derived = AuditorConsent {
        signer: KeyRef::Ua {
            seed,
            kind: 0x0101,
            account: 0,
            index: 0,
        },
        ..req(token.clone())
    };
    let derived_req = derived.clone();
    let consent: Value =
        serde_json::from_str(&a.sign_pqz_auditor_consent(derived).await.unwrap()).unwrap();
    // T9 (review 2026-11-20): the signature verifies under `auditor-consent` over this token's consent of the derived UA
    let kd = crate::op::unhex(consent["keyData"].as_str().unwrap()).unwrap();
    let sig = crate::op::unhex(consent["signature"].as_str().unwrap()).unwrap();
    let auditor = scaas_ua::derive_ua(0x0101, &kd, false).unwrap();
    let (chain_id, uid) = ids(&sdk, "local").unwrap();
    let t20 = addr20(&token.to_ascii_lowercase()).unwrap();
    let digest_of = |t: &[u8; 20]| {
        let m = serde_json::json!({"token": hex(t), "auditor": hex(&auditor), "epoch": 1, "chainUid": hex(&uid)});
        scaas_ua::wallet::scaas_typed_data(
            "AuditorConsent",
            Some(crate::op::domain_name("pqz").unwrap()),
            t,
            chain_id,
            &uid,
            &m,
        )
        .unwrap()
        .digest()
        .unwrap()
    };
    let verifies = |purpose: &str, digest: &[u8; 32]| {
        let msg =
            scaas_ua::ua_message(0x0101, &scaas_ua::purpose_tag(purpose).unwrap(), digest).unwrap();
        scaas_ua::verify::verify(0x0101, &kd, &msg, &sig, false, false)
    };
    assert!(verifies("auditor-consent", &digest_of(&t20)));
    // the controls of the check itself: another purpose, another token's consent
    assert!(!verifies("metatx", &digest_of(&t20)));
    assert!(!verifies("auditor-consent", &digest_of(&[9; 20])));
    // a native (address) auditor: refused up front by name (controller call, owner auto-run 2026-11-19): a native id holds
    // no PQZ key (CTR-UA-32), so the token refuses it at `_keyOf` before the consent is read; nothing signed
    assert_eq!(
        a.sign_pqz_auditor_consent(req(token.clone()))
            .await
            .unwrap_err()
            .code(),
        "PqzAuditorNative"
    );
    assert_eq!(
        a.sign_pqz_auditor_consent(req(other.clone()))
            .await
            .unwrap_err()
            .code(),
        "PqzAuditorNative",
        "before the token's kind is read"
    );
    // another domain kind: refused by the PQZ entry (a derived auditor) and the Zether entry alike
    assert_eq!(
        a.sign_pqz_auditor_consent(AuditorConsent {
            token: other.clone(),
            ..derived_req.clone()
        })
        .await
        .unwrap_err()
        .code(),
        "Argument"
    );
    assert_eq!(
        a.sign_zether_auditor_consent(req(token))
            .await
            .unwrap_err()
            .code(),
        "Argument"
    );
    let _ = (other, salt);
}

/// The Zether consent (`AuditorConsent` in the Zether token's domain, CTR-ZTH-95) of the seed's Zether UA, against the vector
/// rows: `scaas-ua`'s typed builder gives the typed_ops row's digest for the row's auditor (the builder the SDK names its own
/// UA with), the SDK's `pop` verifies under the key's `Y` over the digest naming that UA (`verify_auditor_pop`, the rule
/// vectors/zether/auditor_pop.json pins for zether-prover and `ZetherAuditor.t.sol`), and not over the row's digest (another
/// auditor) nor another epoch's.
#[cfg(feature = "zether")]
#[tokio::test(flavor = "multi_thread")]
async fn zether_auditor_consent_against_the_rows() {
    use zether_prover::curve::{decode_point, Bls12381};
    use zether_prover::schnorr::verify_auditor_pop;
    let (sdk, signer, v) = setup().await;
    let KeyRef::Imported { seed, .. } = signer else {
        panic!()
    };
    let row = &v["ops"]["AuditorConsent"];
    let d = &row["domains"]["zether"];
    let token = text(&d["domain"]["verifyingContract"]);
    let salt = text(&d["domain"]["salt"]);
    let contract: [u8; 20] = unhex(&token).unwrap().try_into().unwrap();
    let uid: [u8; 32] = unhex(&salt).unwrap().try_into().unwrap();
    // the Zether domain's own message: it names the Zether token, as the SDK's consent does
    assert_eq!(
        text(&d["message"]["token"]),
        token,
        "the row names its own token"
    );
    let digest = |auditor: &str, epoch: u32| {
        let mut m = d["message"].clone();
        m["auditor"] = auditor.into();
        m["epoch"] = epoch.into();
        scaas_ua::wallet::scaas_typed_data(
            "AuditorConsent",
            Some("SCaaS ZetherToken"),
            &contract,
            CHAIN_ID,
            &uid,
            &m,
        )
        .unwrap()
        .digest()
        .unwrap()
    };
    let native = &d["consent"]["native"];
    assert_eq!(
        hex(&digest(&text(&native["ua"]), 1)),
        text(&native["digest"]),
        "the builder gives the row's digest"
    );
    let key = sdk
        .confidential()
        .zether_key(seed.clone(), 0)
        .await
        .unwrap();
    let pop = sdk
        .admin()
        .sign_zether_auditor_consent(AuditorConsent {
            signer: KeyRef::Ua {
                seed,
                kind: 0x0141,
                account: 0,
                index: 0,
            },
            chain: "local".into(),
            token: token.clone(),
            epoch: 1,
        })
        .await
        .unwrap();
    let y = decode_point::<Bls12381>(&unhex(&key.y).unwrap()).unwrap();
    let pop = unhex(&pop).unwrap();
    verify_auditor_pop::<Bls12381>(&y, &digest(&key.ua, 1), &pop).unwrap();
    let row_digest: [u8; 32] = unhex(&text(&native["digest"])).unwrap().try_into().unwrap();
    assert!(
        verify_auditor_pop::<Bls12381>(&y, &row_digest, &pop).is_err(),
        "another auditor"
    );
    assert!(
        verify_auditor_pop::<Bls12381>(&y, &digest(&key.ua, 2), &pop).is_err(),
        "another epoch"
    );
}
