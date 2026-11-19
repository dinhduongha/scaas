// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T13: the `account` operations (spec §7) against the fake chain of `tests/common/fake_chain.rs` (local only): the
//! registration's arguments and PoP by `scaas-ua`, its writes kept opaque, quoted, submitted and landed by the record; the KEM
//! repair of a hash commit; each refusal beside its control.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "common/fake_chain.rs"]
mod fake_chain;

use fake_chain::{fake, keccak_hex, serve, Fake, CHAIN_ID};
use scaas_sdk::account::{Register, RegisterAttrs};
use scaas_sdk::op::{KeyRef, OpState};
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, Sdk, SdkConfig, SdkError,
};
use scaas_ua::wallet::entries::registry_call;
use scaas_ua::wallet::{SecretBytes, Wallet};
use serde_json::{json, Value};
use std::sync::Arc;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const REGISTRY: &str = "0x5ca00000000000000000000000000000000000a1";
const ED25519: u16 = 0x0102;
const MLDSA44: u16 = 0x0130;

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

fn sec(b: &[u8]) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(b.to_vec())).unwrap())
}

fn hx(b: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(b))
}

fn load(p: &str) -> Value {
    let path = format!("{}/../../smartcontracts/vectors/{p}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

struct T {
    sdk: Arc<Sdk>,
    chain: Fake,
    seed: String,
    payer: KeyRef,
}

async fn setup() -> T {
    let chain = fake();
    let url = serve(chain.clone()).await;
    let profile = ChainProfile {
        key: "local".into(),
        family: Family::Evm,
        chain_id: Some(CHAIN_ID),
        chain_uid: chain.lock().unwrap().genesis.clone(),
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
        tx_gas_cap: Some(1 << 24),
        tokens: vec![],
        gas: Default::default(),
        max_valid_secs: None,
        gas_opt_in: vec![],
    };
    let sdk = Sdk::open(SdkConfig {
        profiles: vec![profile],
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
            label: "main".into(),
            words: sec(REPO.as_bytes()),
            vault_passphrase: sec(PASS.as_bytes()),
        })
        .await
        .unwrap()
        .id;
    let payer = KeyRef::Native {
        seed: seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    T {
        sdk,
        chain,
        seed,
        payer,
    }
}

fn ua_key(t: &T, kind: u16) -> KeyRef {
    KeyRef::Ua {
        seed: t.seed.clone(),
        kind,
        account: 0,
        index: 0,
    }
}

fn sel(sig: &str) -> String {
    keccak_hex(sig.as_bytes())[..10].to_string()
}

fn w(n: u64) -> String {
    format!("{n:064x}")
}

/// The fake registry's answers for `ua`: registered or not, the `attrs.kemPkHash` of its registration, a stored KEM key.
fn registry(t: &T, ua: &str, registered: bool, kem_pk_hash: &str, kem_stored: bool) {
    let mut c = t.chain.lock().unwrap();
    c.answers.retain(|(_, d, _)| !d.contains(&ua[2..]));
    let ua = &ua[2..];
    c.answers.push((
        REGISTRY.into(),
        format!("{}{ua}", sel("isRegistered(bytes32)")),
        format!("0x{}", w(u64::from(registered))),
    ));
    // `(uint16 kind, bytes keyData, UAAttrs attrs, bytes pop, bytes pqzPop)`: `attrs` at 0xc0 after an empty `keyData`
    c.answers.push((
        REGISTRY.into(),
        format!("{}{ua}", sel("registrationOf(bytes32)")),
        format!(
            "0x{}{}{}{}{}{}{}{}{}{}{}{}",
            w(1),
            w(0xa0),
            w(0xc0),
            w(0x1c0),
            w(0x1e0),
            w(0),
            w(0x80),
            w(0),
            w(0xa0),
            &kem_pk_hash[2..],
            w(0),
            w(0)
        ),
    ));
    // `(address ptr, bytes32 pqzPopHash, bool proven)`: no PQZ key
    c.answers.push((
        REGISTRY.into(),
        format!("{}{ua}", sel("pqzKeyAt(bytes32,uint64)")),
        format!("0x{}{}{}", w(0), w(0), w(0)),
    ));
    // `(KemKey kem, bytes sig)`: the tuple at 0x40, its scheme first
    c.answers.push((
        REGISTRY.into(),
        format!("{}{ua}", sel("kemKeyAt(bytes32,uint64)")),
        format!("0x{}{}{}{}{}{}", w(0x40), w(0xe0), w(u64::from(kem_stored)), w(0x60), w(0), w(0)),
    ));
}

/// The independent build of an ed25519 seed key's registration (`scaas-ua` directly): the calldata.
fn independent_register(kind: u16) -> (String, Vec<u8>, Value) {
    let wallet = Wallet::from_mnemonic(REPO, "").unwrap();
    let k = wallet.ua_key(kind, 0, 0).unwrap();
    let ua = k.ua().unwrap();
    let hp = scaas_ua::holder_pop_message(kind, &ua, &k.key_data(), None, None, None, None).unwrap();
    let pop = k
        .sign_ua(&scaas_ua::ua_portable::pop_v2_tag(), &hp.registration_digest)
        .unwrap();
    scaas_ua::ua_portable::check_registration(kind, &k.key_data(), &Default::default(), &pop, &[], &|_| None)
        .expect("the PoP verifies (the positive control of the independent build)");
    let input = json!({"kind": kind, "keyData": hx(&k.key_data()), "pqzKey": "0x", "pqzPopHash": "0x", "pqzPop": "0x",
        "kemPk": "0x", "pop": hx(&pop)});
    let r: Value =
        serde_json::from_str(&scaas_ua::json::registration_args_json(&input.to_string()).unwrap()).unwrap();
    let args = r["args"].clone();
    (hx(&ua), registry_call("register", &args).unwrap(), args)
}

fn req(t: &T, kind: u16, kem: bool) -> Register {
    Register {
        key: ua_key(t, kind),
        chain: "local".into(),
        attrs: RegisterAttrs { pqz_key: false, kem },
        payer: t.payer.clone(),
    }
}

/// The SDK's registration of a seed key is `scaas-ua`'s, byte for byte (ed25519 signs deterministically), in the named form
/// of `ua/portable.json`'s rows; a KEM key goes in full when it fits.
#[tokio::test(flavor = "multi_thread")]
async fn registration_args_equal_portable_json() {
    let t = setup().await;
    let (ua, calldata, args) = independent_register(ED25519);
    registry(&t, &ua, false, &hx(&[0; 32]), false);
    let ws = t.sdk.account().prepare_register(req(&t, ED25519, false)).await.unwrap();
    assert_eq!(ws.len(), 1);
    assert_eq!(ws[0].entry(), "register");
    assert_eq!(ws[0].ua(), ua);
    assert_eq!(ws[0].calldata(), hx(&calldata), "the SDK's calldata is scaas-ua's");
    // the named form: the vectors' row of the same entry has the same fields
    let v = load("ua/portable.json");
    let row = v["registrations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kindName"] == "ed25519")
        .unwrap();
    let keys = |o: &Value| {
        let mut k: Vec<String> = o.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(keys(&args), keys(&row["args"]));
    assert_eq!(keys(&args["attrs"]), keys(&row["args"]["attrs"]));
    assert!(ws[0].review().iter().any(|f| f.name == "args.pop"), "every argument reviewed");
    // a KEM holder with its KEM key: in full (it fits one call), scheme 1
    let mldsa = hx(&Wallet::from_mnemonic(REPO, "").unwrap().ua_key(MLDSA44, 0, 0).unwrap().ua().unwrap());
    registry(&t, &mldsa, false, &hx(&[0; 32]), false);
    let ws = t.sdk.account().prepare_register(req(&t, MLDSA44, true)).await.unwrap();
    assert_eq!(ws.len(), 1, "no fill: the full key fits");
    let kem = ws[0].review().into_iter().find(|f| f.name == "args.attrs.kem.scheme").unwrap();
    assert_eq!(kem.value, "1");
    // refusals beside the control: a KEM key on a kind that holds none; a native key; the PQZ key's proof is not built
    assert_eq!(code(t.sdk.account().prepare_register(req(&t, ED25519, true)).await), "KemHolder");
    let mut native = req(&t, ED25519, false);
    native.key = t.payer.clone();
    assert_eq!(code(t.sdk.account().prepare_register(native).await), "Argument");
    let mut pqz = req(&t, ED25519, false);
    pqz.attrs.pqz_key = true;
    assert_eq!(code(t.sdk.account().prepare_register(pqz).await), "FeatureMissing");
}

/// A registry write lands by its record, whoever sent it: no receipt for the payer's transaction, the record present is
/// `Landed`; absent, it stays in flight. A write is submitted once; a registered UA gives no write.
#[tokio::test(flavor = "multi_thread")]
async fn registry_write_landed_by_record() {
    let t = setup().await;
    let (ua, _, _) = independent_register(ED25519);
    registry(&t, &ua, false, &hx(&[0; 32]), false);
    let ws = t.sdk.account().prepare_register(req(&t, ED25519, false)).await.unwrap();
    let q = t.sdk.account().quote_registry_write(ws[0].clone()).await.unwrap();
    let op = t
        .sdk
        .account()
        .submit_registry_write(ws[0].clone(), q.clone())
        .await
        .unwrap();
    assert_eq!(
        code(t.sdk.account().submit_registry_write(ws[0].clone(), q).await),
        "PreparedUnknown",
        "one submit of a write"
    );
    for _ in 0..50 {
        if !t.chain.lock().unwrap().sent.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(t.chain.lock().unwrap().sent.len(), 1, "the payer's transaction sent");
    assert!(
        matches!(t.sdk.op().state(op.clone()).await.unwrap(), OpState::InFlight { .. }),
        "no record yet"
    );
    registry(&t, &ua, true, &hx(&[0; 32]), false);
    assert!(
        matches!(t.sdk.op().state(op).await.unwrap(), OpState::Landed { .. }),
        "the record lands it"
    );
    assert!(
        t.sdk.account().prepare_register(req(&t, ED25519, false)).await.unwrap().is_empty(),
        "a registered UA: nothing to write"
    );
    let s = t.sdk.account().registration_of("local".into(), ua).await.unwrap();
    assert!(s.registered && !s.kem_stored);
}

/// The repair of a front-run hash commit (CTR-UA-07): registered with `kemPkHash` set and no key stored, the fill is
/// `setKemKey(ua, 0, kem, UASig())`; a stored key or no commit is nothing to repair.
#[tokio::test(flavor = "multi_thread")]
async fn kem_repair_after_commit_form() {
    let t = setup().await;
    let wallet = Wallet::from_mnemonic(REPO, "").unwrap();
    let k = wallet.ua_key(MLDSA44, 0, 0).unwrap();
    let ua = hx(&k.ua().unwrap());
    let kem_pk = k.kem_key(0).unwrap().kem_pk();
    let commit = hx(&scaas_ua::keccak256(&kem_pk));
    let acc = t.sdk.account();
    let repair = || acc.prepare_kem_repair(ua_key(&t, MLDSA44), "local".into(), t.payer.clone());
    registry(&t, &ua, true, &commit, false);
    let fix = repair().await.unwrap().expect("an unfilled commit");
    assert_eq!(fix.entry(), "setKemKey");
    let kem = scaas_ua::ua_portable::KemKey::from_kem_pk(&kem_pk).unwrap();
    let want = registry_call(
        "setKemKey",
        &json!({"ua": ua, "version": 0, "kem": {"scheme": kem.scheme, "mlkemEk": hx(&kem.mlkem_ek), "x25519": hx(&kem.x25519)},
            "sig": {"keyData": "0x", "signature": "0x", "members": []}}),
    )
    .unwrap();
    assert_eq!(fix.calldata(), hx(&want));
    registry(&t, &ua, true, &commit, true);
    assert!(repair().await.unwrap().is_none(), "the key stored");
    registry(&t, &ua, true, &hx(&[0; 32]), false);
    assert!(repair().await.unwrap().is_none(), "no commit");
    registry(&t, &ua, false, &hx(&[0; 32]), false);
    assert!(repair().await.unwrap().is_none(), "not registered");
}
