// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T41.evm (spec §27.5 (c)): the hand-off against the fake chain of `tests/common/fake_chain.rs` (local only). A signs a
//! pay to B and hands it off; B imports it (every check in its order, each refusal beside its positive control: the passing
//! blob), quotes a self-relay by its own key and submits it; the signer's row ends only on chain facts. The blob's bounds and
//! its cap against the vectors' largest signed operation.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "common/fake_chain.rs"]
mod fake_chain;

use fake_chain::{fake, serve, Fake, CHAIN_ID};
use scaas_sdk::op::{
    ImportExpect, KeyRef, OpState, Prepared, SignedOpBlob, SubmitPath, HANDOFF_MAX,
};
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::wallet::{Burn, CancelNonce, Envelope, Pay, PayBody, PayMeta};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, GasBase, GasRows, GasVerify, Limits,
    ListedToken, RuntimeChoice, Sdk, SdkConfig, SdkError,
};
use scaas_ua::wallet::{Network, SecretBytes, Wallet};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const VND: &str = "0x5ca00000000000000000000000000000000000a1";
const REGISTRY: &str = "0x5ca00000000000000000000000000000000004e6";
const NOW: u64 = 1_800_000_000;
const UNTIL: u64 = NOW + 300;

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

fn root(p: &str) -> String {
    format!("{}/../../{p}", env!("CARGO_MANIFEST_DIR"))
}

fn load(p: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(root(p)).unwrap()).unwrap()
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

/// The address of the repository seed's key of `network` at `index`.
fn address(network: Network, index: u32) -> String {
    Wallet::from_mnemonic(REPO, "")
        .unwrap()
        .native_key(network, index, None)
        .unwrap()
        .address()
        .unwrap()
        .to_ascii_lowercase()
}

/// A native id: the address zero-padded to 32 bytes.
fn id_of(addr: &str) -> String {
    format!("0x{}{}", "00".repeat(12), &addr[2..])
}

/// A gas row for every entry of the token domain on both lane states, signed by a native EVM key (kind 0).
fn gas_rows() -> GasRows {
    let base = scaas_ua::wallet::entries::entry_rows()
        .into_iter()
        .filter(|r| r.kinds.contains(&"token"))
        .map(|r| r.entry.to_string())
        .chain(["mtxExecuteTransfer".to_string()])
        .flat_map(|entry| {
            [true, false].map(|fresh| GasBase {
                entry: entry.clone(),
                kind: "token".into(),
                fresh,
                gas: 100_000,
                per_byte: None,
                save: Some(1_000),
                fee_extra: None,
                ua_extra: None,
                per_item: None,
                regular: None,
            })
        })
        .collect();
    GasRows {
        base,
        verify: vec![GasVerify {
            line: Default::default(),
            signer: 0,
            gas: 0,
            sig_bytes: 0,
            margin: 0,
            per_item: None,
        }],
    }
}

/// One party: an SDK over the shared fake chain with the repository seed imported, and its seed id.
async fn party(url: &str, uid: &str, disabled: Vec<String>) -> (Arc<Sdk>, String) {
    let profile = ChainProfile {
        key: "local".into(),
        family: Family::Evm,
        chain_id: Some(CHAIN_ID),
        chain_uid: uid.into(),
        rpc: vec![endpoint(url)],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: Some(REGISTRY.into()),
        factory: None,
        router: None,
        finality: Finality::Finalized,
        tx_gas_cap: Some(1 << 24),
        tokens: vec![ListedToken {
            address: VND.into(),
            symbol: "VND".into(),
            decimals: 0,
        }],
        gas: gas_rows(),
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![],
        wrappers: vec![],
        l1_fee: None,
        pinned_reads: true,
        disabled_kinds: disabled,
        family_params: None,
    };
    let sdk = Sdk::open(SdkConfig {
        profiles: vec![profile],
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
        clock: Some(Arc::new(|| NOW)),
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
    (sdk, seed)
}

struct T {
    chain: Fake,
    url: String,
    uid: String,
    /// the signer A (the seed's EVM key 0) and the payee B (its EVM key 1), each its own SDK
    a: Arc<Sdk>,
    a_key: KeyRef,
    b: Arc<Sdk>,
    b_key: KeyRef,
    b_seed: String,
}

async fn setup() -> T {
    let v = load("smartcontracts/vectors/typed/typed_ops.json");
    let salt = v["ops"]["UABurn"]["domains"]["token"]["domain"]["salt"]
        .as_str()
        .unwrap()
        .to_string();
    let chain = fake();
    {
        let mut c = chain.lock().unwrap();
        c.domains
            .insert(VND.into(), ("SCaaS MetaToken".into(), salt.clone()));
        c.genesis = salt.clone();
        let sel = fake_chain::keccak_hex(b"isRegistered(bytes32)")[..10].to_string();
        c.answers
            .push((REGISTRY.into(), sel, format!("0x{}1", "0".repeat(63))));
    }
    let url = serve(chain.clone()).await;
    let (a, a_seed) = party(&url, &salt, vec![]).await;
    let (b, b_seed) = party(&url, &salt, vec![]).await;
    let key = |seed: &str, index| KeyRef::Native {
        seed: seed.into(),
        network: "evm".into(),
        index,
    };
    T {
        chain,
        url,
        uid: salt,
        a,
        a_key: key(&a_seed, 0),
        b,
        b_key: key(&b_seed, 1),
        b_seed,
    }
}

fn b_id() -> String {
    id_of(&address(Network::Evm, 1))
}

fn envelope(mode: u32, relayer: Option<String>, fee: &str) -> Envelope {
    Envelope {
        valid_until: UNTIL,
        mode,
        relayer,
        fee: fee.into(),
        fee_recipient: None,
    }
}

async fn pay(t: &T, no: &str, env: Envelope) -> Result<Arc<Prepared>, SdkError> {
    t.a.wallet()
        .prepare_pay(Pay {
            signer: t.a_key.clone(),
            chain: "local".into(),
            token: VND.into(),
            to: b_id(),
            value: "1000".into(),
            meta: PayMeta {
                salt: Some(format!("0x{}", "11".repeat(32))),
                pay_no: Some(format!("0x{no:0>64}")),
                save: false,
                body: PayBody::Note {
                    note: "hand-off".into(),
                },
            },
            envelope: env,
        })
        .await
}

/// A's pay to B, handed off.
async fn handed(t: &T, no: &str) -> (Arc<Prepared>, SignedOpBlob) {
    let p = pay(t, no, envelope(0, None, "0")).await.unwrap();
    let blob = t.a.op().hand_off(p.clone()).await.unwrap();
    (p, blob)
}

fn expect(t: &T) -> ImportExpect {
    ImportExpect {
        chain: "local".into(),
        payee: vec![b_id()],
        payer: t.b_key.clone(),
    }
}

async fn import(t: &T, blob: &SignedOpBlob) -> Result<Arc<Prepared>, SdkError> {
    t.b.op().import_signed(blob.clone(), expect(t)).await
}

/// `hex` (no `0x`) in a request the fake got, waited for (≤ 5 s): the send runs after `submit` returns.
async fn carried_soon(c: &Fake, hex: &str) -> bool {
    for _ in 0..100 {
        if c.lock()
            .unwrap()
            .requests
            .iter()
            .any(|b| b.to_ascii_lowercase().contains(hex))
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// The positive control and the whole path: A hands off (nothing sent), B imports (the same digest, the review naming the
/// hand-off and the simulation), quotes a self-relay by its own key, submits; the fake gets B's transaction carrying A's
/// signature. A's row is `InFlight` until a chain fact: here the lane spent, `Consumed`.
#[tokio::test(flavor = "multi_thread")]
async fn hand_off_import_quote_submit() {
    let t = setup().await;
    let (p, blob) = handed(&t, "1").await;
    assert!(
        t.chain.lock().unwrap().sent.is_empty(),
        "a hand-off sends nothing"
    );
    let blob = SignedOpBlob::from_json(&blob.to_json().unwrap()).unwrap();
    assert_eq!(
        (blob.entry.as_str(), blob.kind.as_str()),
        ("mtxPay", "token")
    );
    // the signer's row: written ahead, nothing to send, never resent
    assert_eq!(
        t.a.op().state(p.id()).await.unwrap(),
        OpState::InFlight {
            detail: scaas_sdk::InFlight::Signed
        }
    );
    assert_eq!(t.a.op().resume().await.unwrap(), 0);
    let imported = import(&t, &blob).await.unwrap();
    assert_eq!(
        imported.id(),
        p.id(),
        "scaas-ua rebuilt the same typed digest"
    );
    assert_eq!(imported.entry(), "mtxPay");
    let review = imported.review();
    assert!(review.iter().any(|f| f.name == "handed_off"));
    assert!(review
        .iter()
        .any(|f| f.name == "simulation.gas" && f.value == "100000"));
    assert!(review.iter().any(|f| f.name == "to" && f.value == b_id()));
    let q =
        t.b.op()
            .quote(
                imported.clone(),
                SubmitPath::SelfRelay {
                    payer: t.b_key.clone(),
                },
            )
            .await
            .unwrap();
    assert_eq!(
        q.payer.as_deref(),
        Some(address(Network::Evm, 1).as_str()),
        "B pays"
    );
    let op = t.b.op().submit(imported, q).await.unwrap();
    // a `UASig` for the `UA*` structs (its `signature`), else the bytes
    let sig = blob.signature.get("signature").unwrap_or(&blob.signature);
    let sig = sig.as_str().unwrap().trim_start_matches("0x").to_string();
    assert!(
        carried_soon(&t.chain, &sig).await,
        "B's transaction carries A's signature"
    );
    for _ in 0..100 {
        if !t.chain.lock().unwrap().sent.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(t.chain.lock().unwrap().sent.len(), 1, "sent once");
    assert!(matches!(
        t.b.op().state(op).await.unwrap(),
        OpState::InFlight { .. }
    ));
    // the lane spent on chain: the signer's row ends by that fact
    t.chain.lock().unwrap().nonces.insert(VND.into(), 1);
    assert_eq!(t.a.op().state(p.id()).await.unwrap(), OpState::Consumed);
}

/// The import's checks in their order, each refusal beside the passing blob (`hand_off_import_quote_submit`).
#[tokio::test(flavor = "multi_thread")]
async fn import_refusals_in_order() {
    let t = setup().await;
    let (_, good) = handed(&t, "2").await;
    assert_eq!(code(import(&t, &good).await), "Ok", "control");
    let with = |f: &dyn Fn(&mut SignedOpBlob)| {
        let mut b = good.clone();
        f(&mut b);
        b
    };
    // 1. the chain
    let b = with(&|b| b.chain_uid = format!("0x{}", "61".repeat(32)));
    assert_eq!(code(import(&t, &b).await), "ProfileMismatch");
    let b = with(&|b| b.family = "near".into());
    assert_eq!(code(import(&t, &b).await), "ProfileMismatch");
    // 2. a listed token
    let b = with(&|b| b.contract = "0x5ca00000000000000000000000000000000000a9".into());
    assert_eq!(code(import(&t, &b).await), "ProfileMismatch");
    // 3. the kind: confidential, or a struct the token rows do not hold
    let b = with(&|b| b.kind = "zether".into());
    assert_eq!(code(import(&t, &b).await), "ImportKindRefused");
    let b = with(&|b| b.name = "UAShield".into());
    assert_eq!(code(import(&t, &b).await), "ImportKindRefused");
    let b = with(&|b| b.entry = "mtxBurn".into());
    assert_eq!(code(import(&t, &b).await), "ImportKindRefused");
    // 4. the payee
    let mut e = expect(&t);
    e.payee = vec![id_of(&address(Network::Evm, 2))];
    assert_eq!(
        code(t.b.op().import_signed(good.clone(), e).await),
        "ImportNotPayee"
    );
    // 6. a fee
    let b = with(&|b| b.message["fee"] = json!("5"));
    assert_eq!(code(import(&t, &b).await), "ImportFeeRefused");
    // 7. time left: 100 s, below the node's 120
    t.chain.lock().unwrap().timestamp = UNTIL - 100;
    assert_eq!(code(import(&t, &good).await), "ImportExpired");
    t.chain.lock().unwrap().timestamp = UNTIL - 121;
    assert_eq!(code(import(&t, &good).await), "Ok", "control: 121 s left");
    t.chain.lock().unwrap().timestamp = NOW;
    // 8. the lane spent
    t.chain.lock().unwrap().nonces.insert(VND.into(), 1);
    assert_eq!(code(import(&t, &good).await), "ImportConsumed");
    t.chain.lock().unwrap().nonces.remove(VND);
    // 10. the simulation from the payer reverts
    t.chain.lock().unwrap().estimate_reverts = Some(|_| true);
    assert_eq!(code(import(&t, &good).await), "ImportedOpRefused");
    t.chain.lock().unwrap().estimate_reverts = None;
    assert_eq!(
        code(import(&t, &good).await),
        "Ok",
        "control: the same blob again"
    );
    // a signer kind the importer's profile disables (owner 2026-11-22), as its own operations
    let kind = scaas_ua::KINDS.iter().find(|k| k.kind == 0x0101).unwrap();
    let (d, d_seed) = party(&t.url, &t.uid, vec![kind.name.to_string()]).await;
    let mut e = expect(&t);
    e.payer = KeyRef::Native {
        seed: d_seed,
        network: "evm".into(),
        index: 1,
    };
    let b = with(&|b| b.signer_kind = 0x0101);
    assert_eq!(
        code(d.op().import_signed(b, e.clone()).await),
        "KindDisabled"
    );
    assert_eq!(
        code(d.op().import_signed(good.clone(), e).await),
        "Ok",
        "control: a native signer"
    );
}

/// 5. A bound relayer: another address than the payer's is refused, the payer's own accepted.
#[tokio::test(flavor = "multi_thread")]
async fn a_bound_relayer_must_be_the_payer() {
    let t = setup().await;
    let c = address(Network::Evm, 2);
    let p = pay(&t, "3", envelope(1, Some(c), "0")).await.unwrap();
    let blob = t.a.op().hand_off(p).await.unwrap();
    assert_eq!(code(import(&t, &blob).await), "ImportRelayerBound");
    let p = pay(&t, "4", envelope(1, Some(address(Network::Evm, 1)), "0"))
        .await
        .unwrap();
    let blob = t.a.op().hand_off(p).await.unwrap();
    assert_eq!(code(import(&t, &blob).await), "Ok", "bound to the payer");
}

/// A hand-off is fee 0 (spec §27.5 (b)); a group signer and an unknown prepared operation are refused.
#[tokio::test(flavor = "multi_thread")]
async fn hand_off_refusals() {
    let t = setup().await;
    let burn = |fee: &str, mode: u32| Burn {
        signer: t.a_key.clone(),
        chain: "local".into(),
        contract: VND.into(),
        batch: "7".into(),
        amount: "100".into(),
        envelope: envelope(mode, None, fee),
    };
    let p = t.a.wallet().prepare_burn(burn("5", 0x20)).await.unwrap(); // a FIXED fee (kind 2)
    assert_eq!(code(t.a.op().hand_off(p).await), "Argument", "a fee");
    let p = t.a.wallet().prepare_burn(burn("0", 0)).await.unwrap();
    assert_eq!(code(t.a.op().hand_off(p).await), "Ok", "control: fee 0");
    let q = pay(&t, "6", envelope(0, None, "0")).await.unwrap();
    assert_eq!(
        code(t.b.op().hand_off(q.clone()).await),
        "PreparedUnknown",
        "another SDK's"
    );
    assert_eq!(code(t.a.op().hand_off(q.clone()).await), "Ok", "control");
    assert_eq!(code(t.a.op().hand_off(q).await), "PreparedUnknown", "once");
}

/// An unbound `feeRecipient` set in the blob is zeroed by `scaas-ua`'s canonical form: the same digest.
#[tokio::test(flavor = "multi_thread")]
async fn an_unbound_fee_recipient_in_the_blob_is_zeroed() {
    let t = setup().await;
    let (p, mut blob) = handed(&t, "7").await;
    blob.message["feeRecipient"] = json!("0x00000000000000000000000000000000deadbeef");
    let imported = import(&t, &blob).await.unwrap();
    assert_eq!(imported.id(), p.id());
}

/// A non-pay kind with a pre-send check (`eth_call` from the payer) is importable; it names no payee.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_is_importable() {
    let t = setup().await;
    let p =
        t.a.wallet()
            .prepare_cancel_nonce(CancelNonce {
                signer: t.a_key.clone(),
                chain: "local".into(),
                contract: VND.into(),
                batch: "7".into(),
                lane: "7".into(),
                envelope: envelope(0, None, "0"),
            })
            .await
            .unwrap();
    let blob = t.a.op().hand_off(p.clone()).await.unwrap();
    assert_eq!(blob.entry, "mtxCancelNonce");
    let mut e = expect(&t);
    e.payee = vec![];
    assert_eq!(t.b.op().import_signed(blob, e).await.unwrap().id(), p.id());
}

/// The payer: an `evm` key or Hedera's `hedera_ecdsa`; `hedera_ed25519` is `Argument`. Two imports quoted by one payer take
/// two transaction nonces.
#[tokio::test(flavor = "multi_thread")]
async fn payers_and_their_nonces() {
    let t = setup().await;
    let (_, one) = handed(&t, "8").await;
    let (_, two) = handed(&t, "9").await;
    let mut e = expect(&t);
    e.payer = KeyRef::Native {
        seed: t.b_seed.clone(),
        network: "hedera_ed25519".into(),
        index: 0,
    };
    assert_eq!(
        code(t.b.op().import_signed(one.clone(), e.clone()).await),
        "Argument"
    );
    e.payer = KeyRef::Native {
        seed: t.b_seed.clone(),
        network: "hedera_ecdsa".into(),
        index: 0,
    };
    let p =
        t.b.op()
            .import_signed(one.clone(), e.clone())
            .await
            .unwrap();
    let q =
        t.b.op()
            .quote(
                p,
                SubmitPath::SelfRelay {
                    payer: e.payer.clone(),
                },
            )
            .await
            .unwrap();
    assert_eq!(
        q.payer.as_deref(),
        Some(address(Network::HederaEcdsa, 0).as_str())
    );
    // one payer, two imports: the second quote after the first submit takes the next nonce
    let p1 = import(&t, &one).await.unwrap();
    let q1 =
        t.b.op()
            .quote(
                p1.clone(),
                SubmitPath::SelfRelay {
                    payer: t.b_key.clone(),
                },
            )
            .await
            .unwrap();
    t.b.op().submit(p1, q1.clone()).await.unwrap();
    let p2 = import(&t, &two).await.unwrap();
    let q2 =
        t.b.op()
            .quote(
                p2,
                SubmitPath::SelfRelay {
                    payer: t.b_key.clone(),
                },
            )
            .await
            .unwrap();
    assert_eq!(q2.tx_nonce, q1.tx_nonce + 1);
}

/// The blob's bounds: above 256 KiB, deeper than 8 and an unknown field are `Argument`; the cap holds the vectors' largest
/// signed operation (an `msig` of three PQ members: `ua/pq_signatures.json` `msig.treasury`, its signature 14,722 B, the blob 15,800 B).
#[tokio::test(flavor = "multi_thread")]
async fn blob_bounds_and_the_cap() {
    let t = setup().await;
    let (_, blob) = handed(&t, "10").await;
    let text = blob.to_json().unwrap();
    assert!(SignedOpBlob::from_json(&text).is_ok(), "control");
    let mut v: Value = serde_json::from_str(&text).unwrap();
    v["extra"]["pad"] = json!("0".repeat(HANDOFF_MAX));
    assert_eq!(code(SignedOpBlob::from_json(&v.to_string())), "Argument");
    let mut v: Value = serde_json::from_str(&text).unwrap();
    v["extra"]["deep"] = json!([[[[[[[1]]]]]]]); // depth 9 with the blob's own and `extra`'s
    assert_eq!(code(SignedOpBlob::from_json(&v.to_string())), "Argument");
    v["extra"]["deep"] = json!([[[[[[1]]]]]]); // depth 8
    assert!(
        SignedOpBlob::from_json(&v.to_string()).is_ok(),
        "control: depth 8"
    );
    let mut v: Value = serde_json::from_str(&text).unwrap();
    v["unknown"] = json!(1);
    assert_eq!(code(SignedOpBlob::from_json(&v.to_string())), "Argument");
    // the largest signed operation of the vectors, as a blob's signature
    let auth = load("smartcontracts/vectors/ua/pq_signatures.json")["msig"]["treasury"]["sets"][0]
        ["auth"]
        .clone();
    let mut big = blob.clone();
    big.signature = auth.clone();
    let big = big.to_json().unwrap();
    assert!(SignedOpBlob::from_json(&big).is_ok());
    let sig_len = auth.as_str().unwrap().len();
    println!("handoff cap: the largest signed operation's signature {sig_len} B, its blob {} B, the cap {HANDOFF_MAX} B", big.len());
    assert!(big.len() * 10 < HANDOFF_MAX, "a tenth of the cap");
}
