// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T10: operations against the fake chain and gateway of `tests/common/fake_chain.rs` (local only). Unit tests: the generic
//! prepare is crate-internal until the modules' `prepare_<op>` (plan T12), so these drive it with a [`Draft`] as a module does.
//! Every refusal beside its control.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "../../tests/common/fake_chain.rs"]
mod fake_chain;

use super::*;
use crate::vault::{
    ImportWords, MemoryStore, SecureStore, StoreError, StoreLock, StorePolicy, StoredItem,
};
use crate::{
    ChainProfile, EndpointConfig, Event, Family, Finality, Limits, ListedToken, RuntimeChoice,
    SdkConfig,
};
use fake_chain::{executed_log, fake, serve, Fake, Gw, CHAIN_ID};
use scaas_ua::wallet::{SecretBytes, Wallet};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::time::Duration;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const TOKEN: &str = "0x5ca00000000000000000000000000000000000a1";
const OTHER: &str = "0x5ca00000000000000000000000000000000000b2";
const ZERO: &str = "0x0000000000000000000000000000000000000000";
const UID: &str = "0x6060606060606060606060606060606060606060606060606060606060606060";

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

/// A store whose `sdk.state` writes fail on demand: all of them, or those that mark a row `sent`.
#[derive(Default)]
struct Flaky {
    inner: MemoryStore,
    fail_state: AtomicBool,
    fail_sent: AtomicBool,
}

#[async_trait::async_trait]
impl SecureStore for Flaky {
    async fn get(&self, n: String, r: String) -> Result<Option<StoredItem>, StoreError> {
        self.inner.get(n, r).await
    }
    async fn put_if(
        &self,
        n: String,
        prev: Option<u64>,
        b: Vec<u8>,
        p: StorePolicy,
    ) -> Result<(), StoreError> {
        let sent = String::from_utf8_lossy(&b).contains("\"state\":\"sent\"");
        if n == "sdk.state"
            && (self.fail_state.load(SeqCst) || (self.fail_sent.load(SeqCst) && sent))
        {
            return Err(StoreError::Io);
        }
        self.inner.put_if(n, prev, b, p).await
    }
    async fn delete(&self, n: String) -> Result<(), StoreError> {
        self.inner.delete(n).await
    }
    async fn lock(&self, n: String) -> Result<Arc<StoreLock>, StoreError> {
        self.inner.lock(n).await
    }
}

struct T {
    sdk: Arc<Sdk>,
    store: Arc<Flaky>,
    chain: Fake,
    seed: String,
    profile: ChainProfile,
}

fn endpoint(url: &str) -> EndpointConfig {
    EndpointConfig {
        url: url.into(),
        class: scaas_rpc::Class::Named,
        label: None,
        auth: None,
    }
}

async fn open(store: Arc<Flaky>, profile: ChainProfile, limits: Limits) -> Arc<Sdk> {
    Sdk::open(SdkConfig {
        profiles: vec![profile],
        store,
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits,
    })
    .await
    .unwrap()
}

/// A seed on a fresh SDK over a fake chain with `gateways` gateways (each a server of the same fake).
async fn setup(gateways: usize, edit: impl FnOnce(&mut ChainProfile, &mut Limits)) -> T {
    let chain = fake();
    let url = serve(chain.clone()).await;
    let mut gws = vec![];
    for _ in 0..gateways {
        gws.push(endpoint(&serve(chain.clone()).await));
    }
    let mut profile = ChainProfile {
        key: "local".into(),
        family: Family::Evm,
        chain_id: Some(CHAIN_ID),
        chain_uid: UID.into(),
        rpc: vec![endpoint(&url)],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: gws,
        registry: None,
        factory: None,
        router: None,
        finality: Finality::Finalized,
        tx_gas_cap: Some(1 << 24),
        tokens: vec![ListedToken {
            address: TOKEN.into(),
            symbol: "VND".into(),
            decimals: 0,
        }],
    };
    let mut limits = Limits::default();
    edit(&mut profile, &mut limits);
    let store = Arc::new(Flaky::default());
    let sdk = open(store.clone(), profile.clone(), limits).await;
    let words =
        Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(REPO.as_bytes().to_vec())).unwrap());
    let pass =
        Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(PASS.as_bytes().to_vec())).unwrap());
    let seed = sdk
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words,
            vault_passphrase: pass,
        })
        .await
        .unwrap()
        .id;
    T {
        sdk,
        store,
        chain,
        seed,
        profile,
    }
}

fn ua() -> String {
    let w = Wallet::from_mnemonic(REPO, "").unwrap();
    hex(&w.ua_key(0x0101, 0, 0).unwrap().ua().unwrap())
}

fn evm_address() -> String {
    let w = Wallet::from_mnemonic(REPO, "").unwrap();
    w.native_key(Network::Evm, 0, None)
        .unwrap()
        .address()
        .unwrap()
        .to_ascii_lowercase()
}

fn ua_key(t: &T) -> KeyRef {
    KeyRef::Ua {
        seed: t.seed.clone(),
        kind: 0x0101,
        account: 0,
        index: 0,
    }
}

fn payer(t: &T) -> KeyRef {
    KeyRef::Native {
        seed: t.seed.clone(),
        network: "evm".into(),
        index: 0,
    }
}

/// A `UACancelNonce` (or `CancelNonce` on `account`) on `contract`, lane `lane`, envelope batch 7, nonce read from the lane.
fn cancel(t: &T, kind: &'static str, contract: &str, lane: &str, fee: &str) -> Draft {
    let (name, from, signer) = if kind == "account" {
        ("CancelNonce", evm_address(), payer(t))
    } else {
        ("UACancelNonce", ua(), ua_key(t))
    };
    let until = t.chain.lock().unwrap().timestamp + 3600;
    Draft {
        chain: "local".into(),
        name,
        kind,
        contract: addr20(contract).unwrap(),
        message: json!({"from": from, "lane": lane, "batch": "7", "validUntil": until.to_string(), "mode": 0,
            "relayer": ZERO, "fee": fee, "feeRecipient": ZERO}),
        extra: json!({}),
        signer,
        expect: None,
        review: vec![],
        touched: vec![],
        opaque: false,
    }
}

async fn prepare(t: &T, d: Draft) -> Arc<Prepared> {
    Op::prepare(&t.sdk, d).await.unwrap()
}

async fn gateway_quote(t: &T, p: &Arc<Prepared>) -> SubmitQuote {
    t.sdk
        .op()
        .quote(p.clone(), SubmitPath::Gateway)
        .await
        .unwrap()
}

/// The next `OpState` event of `op` within 5 s.
async fn event(sub: &crate::Subscription, op: &str) -> OpState {
    for _ in 0..50 {
        if let Some(Event::OpState { op: o, state }) = sub.next(100).await {
            if o == op {
                return state;
            }
        }
    }
    panic!("no OpState event for {op}");
}

/// Waits (≤ 5 s) until the fake holds `n` gateway bodies.
async fn bodies(t: &T, n: usize) -> Vec<String> {
    for _ in 0..100 {
        let b = t.chain.lock().unwrap().bodies.clone();
        if b.len() >= n {
            return b;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the gateway got fewer than {n} bodies");
}

async fn sent_txs(t: &T, n: usize) -> Vec<String> {
    for _ in 0..100 {
        let s = t.chain.lock().unwrap().sent.clone();
        if s.len() >= n {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("fewer than {n} transactions sent");
}

#[tokio::test(flavor = "multi_thread")]
async fn review_lists_every_named_field_with_its_source() {
    let t = setup(1, |_, _| {}).await;
    let until = t.chain.lock().unwrap().timestamp + 3600;
    let entry_ref = format!("0x{}", "e1".repeat(32));
    let d = Draft {
        chain: "local".into(),
        name: "UAMetaTransfer",
        kind: "token",
        contract: addr20(TOKEN).unwrap(),
        message: json!({"from": ua(), "to": format!("0x{}", "0b".repeat(32)), "value": "250", "entryRef": entry_ref,
            "batch": "9", "nonce": "0", "validUntil": until.to_string(), "mode": 1, "relayer": "0x00000000000000000000000000000000000000ee",
            "fee": "0", "feeRecipient": ZERO}),
        extra: json!({}),
        signer: ua_key(&t),
        expect: None,
        // what the wallet's pay adds (plan T12): the `PayMeta` it commits to, decoded
        review: vec![
            prepared::field(
                "payNo",
                "0x00000000000000000000000000000000018f0e3d6a7b7c8d9e0f112233445566",
                "018f0e3d-6a7b-7c8d-9e0f-112233445566",
                Source::Signed,
            ),
            prepared::field("save", "true", "true", Source::Signed),
        ],
        touched: vec![addr20(OTHER).unwrap()],
        opaque: false,
    };
    let p = prepare(&t, d).await;
    let r = p.review();
    let find = |n: &str| {
        r.iter()
            .find(|f| f.name == n)
            .unwrap_or_else(|| panic!("{n} not reviewed"))
            .clone()
    };
    for n in [
        "from",
        "to",
        "value",
        "entryRef",
        "batch",
        "nonce",
        "validUntil",
        "mode",
        "relayer",
        "fee",
        "feeRecipient",
    ] {
        assert_eq!(find(n).source, Source::Signed, "{n}");
    }
    assert_eq!(find("fee").value, "0");
    assert_eq!(
        find("relayer").value,
        "0x00000000000000000000000000000000000000ee",
        "a bound relayer as signed"
    );
    assert_eq!(
        find("payNo").display,
        "018f0e3d-6a7b-7c8d-9e0f-112233445566"
    );
    assert_eq!(find("save").source, Source::Signed);
    let tokens: Vec<_> = r.iter().filter(|f| f.name == "token").cloned().collect();
    assert_eq!(
        tokens.len(),
        2,
        "every token touched: the domain's own and the other"
    );
    assert!(tokens.iter().all(|f| f.source == Source::Derived));
    assert_eq!(
        tokens.iter().find(|f| f.value == TOKEN).unwrap().display,
        "listed VND"
    );
    assert_eq!(
        tokens.iter().find(|f| f.value == OTHER).unwrap().display,
        "unlisted",
        "an unlisted token is marked"
    );
    assert_eq!(p.entry(), "mtxPay");
    assert_eq!(
        p.id(),
        hex(&p.t.td.digest().unwrap()),
        "the id is the typed digest"
    );
    // ponytail: the PQZ half (the plaintext amount and recipient as `Request`) comes with the PQZ entries, plan T16
}

#[tokio::test(flavor = "multi_thread")]
async fn prepared_is_opaque() {
    let a = setup(1, |_, _| {}).await;
    let b = setup(1, |_, _| {}).await;
    let p = prepare(&a, cancel(&a, "token", TOKEN, "5", "0")).await;
    assert_eq!(
        code(b.sdk.op().quote(p.clone(), SubmitPath::Gateway).await),
        "PreparedUnknown",
        "another SDK's value"
    );
    let q = gateway_quote(&a, &p).await;
    assert_eq!(
        code(b.sdk.op().submit(p.clone(), q.clone()).await),
        "PreparedUnknown"
    );
    assert_eq!(
        code(a.sdk.op().submit(p.clone(), q.clone()).await),
        "Ok",
        "control: its own SDK"
    );
    assert_eq!(
        code(a.sdk.op().submit(p, q).await),
        "PreparedUnknown",
        "submitted once: no longer in the table"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn submit_signs_what_was_reviewed() {
    let t = setup(1, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let q = gateway_quote(&t, &p).await;
    let op = t.sdk.op().submit(p.clone(), q).await.unwrap();
    let row = state::row(&t.sdk, &op).await.unwrap();
    assert_eq!(row.digest, p.id(), "the row's digest is the reviewed one");
    let body: Value = serde_json::from_str(&bodies(&t, 1).await[0]).unwrap();
    assert_eq!(body["op"], row.op_json, "the gateway got the row's op");
    // the signed values are the reviewed ones
    for f in p.review().iter().filter(|f| f.source == Source::Signed) {
        let v = &p.t.message[&f.name];
        assert_eq!(
            v.as_str().map(String::from).unwrap_or(v.to_string()),
            f.value,
            "{}",
            f.name
        );
    }
    // the signature is the key's over that digest under the entry's check (scaas-ua's `sign_scaas`)
    let w = Wallet::from_mnemonic(REPO, "").unwrap();
    let k = w.ua_key(0x0101, 0, 0).unwrap();
    let s = scaas_ua::wallet::sign_scaas(&k, &p.t.td, p.t.expect.clone()).unwrap();
    assert!(
        row.op_json.to_string().contains(&hex(&s.signature)),
        "the posted signature is over the reviewed digest"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn prepared_stale_on_nonce_move() {
    let t = setup(1, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let q = gateway_quote(&t, &p).await; // control: fresh
    t.chain.lock().unwrap().nonces.insert(TOKEN.into(), 1);
    assert_eq!(
        code(t.sdk.op().quote(p.clone(), SubmitPath::Gateway).await),
        "PreparedStale"
    );
    assert_eq!(
        code(t.sdk.op().submit(p.clone(), q.clone()).await),
        "PreparedStale",
        "nothing signed"
    );
    t.chain.lock().unwrap().nonces.insert(TOKEN.into(), 0);
    t.chain.lock().unwrap().timestamp += 7200;
    assert_eq!(
        code(t.sdk.op().submit(p.clone(), q.clone()).await),
        "PreparedStale",
        "past validUntil"
    );
    t.chain.lock().unwrap().timestamp -= 7200;
    assert_eq!(code(t.sdk.op().submit(p, q).await), "Ok", "control");
    assert!(t.chain.lock().unwrap().sent.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn fee_zero_is_kept() {
    let t = setup(1, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    assert_eq!(
        p.review().iter().find(|f| f.name == "fee").unwrap().value,
        "0"
    );
    let q = gateway_quote(&t, &p).await;
    assert_eq!(q.fee_to_relayer, "0");
    let op = t.sdk.op().submit(p, q).await.unwrap();
    let row = state::row(&t.sdk, &op).await.unwrap();
    assert!(
        row.op_json.to_string().contains("\"fee\":\"0\"")
            || row.op_json.to_string().contains("\"fee\":0"),
        "{}",
        row.op_json
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn quote_shows_and_caps() {
    let t = setup(0, |_, l| l.max_fee_per_gas = "1000".into()).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let path = SubmitPath::SelfRelay { payer: payer(&t) };
    let q = t.sdk.op().quote(p.clone(), path.clone()).await.unwrap();
    let fee: u128 = q.max_fee_per_gas.parse().unwrap();
    assert_eq!(
        q.gas_limit, 150_000,
        "the unsigned form's estimate plus the margin"
    );
    assert_eq!(
        q.max_cost,
        (u128::from(q.gas_limit) * fee).to_string(),
        "max cost = gas x max fee"
    );
    assert_eq!(q.payer.as_deref(), Some(evm_address().as_str()));
    t.chain.lock().unwrap().prio = 1_000_000; // a failover endpoint answering a huge fee
    assert_eq!(
        code(t.sdk.op().quote(p.clone(), path.clone()).await),
        "FeeAboveCap",
        "the cap is the SDK's"
    );
    t.chain.lock().unwrap().prio = 1;
    t.chain.lock().unwrap().gas = (1 << 24) - 1;
    let t2 = setup(0, |_, l| l.max_gas = 1_000_000).await;
    t2.chain.lock().unwrap().gas = 2_000_000;
    let p2 = prepare(&t2, cancel(&t2, "token", TOKEN, "5", "0")).await;
    assert_eq!(
        code(
            t2.sdk
                .op()
                .quote(p2, SubmitPath::SelfRelay { payer: payer(&t2) })
                .await
        ),
        "FeeAboveCap",
        "a huge estimate"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn gas_above_tx_cap() {
    let t = setup(0, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let path = SubmitPath::SelfRelay { payer: payer(&t) };
    // the estimate plus half: 11_184_812 → 16_777_218, above 2^24; 11_184_811 → 2^24
    t.chain.lock().unwrap().gas = 11_184_812;
    assert_eq!(
        code(t.sdk.op().quote(p.clone(), path.clone()).await),
        "GasAboveTxCap"
    );
    t.chain.lock().unwrap().gas = 11_184_811;
    let q = t.sdk.op().quote(p.clone(), path).await.unwrap(); // control: at the cap
    assert_eq!(q.gas_limit, 1 << 24);
    // the fake refuses a transaction above its cap, as the chain does: the quote stopped it before
    assert!(t.chain.lock().unwrap().sent.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn payer_delegated() {
    let t = setup(0, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let path = SubmitPath::SelfRelay { payer: payer(&t) };
    t.chain
        .lock()
        .unwrap()
        .code
        .insert(evm_address(), format!("0xef0100{}", "33".repeat(20)));
    assert_eq!(
        code(t.sdk.op().quote(p.clone(), path.clone()).await),
        "PayerDelegated"
    );
    t.chain
        .lock()
        .unwrap()
        .code
        .insert(evm_address(), "0x6001".into());
    assert_eq!(
        code(t.sdk.op().quote(p, path).await),
        "Ok",
        "control: other code"
    );
    assert!(
        t.chain.lock().unwrap().sent.is_empty(),
        "no transaction signed or sent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn gateway_path_posts_the_same_bytes() {
    let t = setup(2, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let q = t
        .sdk
        .op()
        .quote(p.clone(), SubmitPath::Auto { payer: None })
        .await
        .unwrap();
    assert_eq!(
        (q.path.clone(), q.gateways.clone()),
        (SubmitPath::Gateway, vec![0, 1]),
        "Auto: door A with gateways"
    );
    t.sdk.op().submit(p, q).await.unwrap();
    let b = bodies(&t, 2).await;
    assert_eq!(b.len(), 2);
    assert_eq!(b[0], b[1], "the same body to every gateway (Fanout::All)");
}

#[tokio::test(flavor = "multi_thread")]
async fn submit_path_none() {
    let t = setup(0, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    assert_eq!(
        code(
            t.sdk
                .op()
                .quote(p.clone(), SubmitPath::Auto { payer: None })
                .await
        ),
        "SubmitPathNone"
    );
    assert_eq!(
        code(t.sdk.op().quote(p.clone(), SubmitPath::Gateway).await),
        "SubmitPathNone"
    );
    let q = t
        .sdk
        .op()
        .quote(
            p,
            SubmitPath::Auto {
                payer: Some(payer(&t)),
            },
        )
        .await
        .unwrap();
    assert!(
        matches!(q.path, SubmitPath::SelfRelay { .. }),
        "control: a payer"
    );
    // a non-door-A entry (the mandate wallet's) with gateways: Auto never picks a gateway
    let t = setup(1, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "wallet", OTHER, "5", "0")).await;
    assert_eq!(
        code(
            t.sdk
                .op()
                .quote(p.clone(), SubmitPath::Auto { payer: None })
                .await
        ),
        "SubmitPathNone"
    );
    let q = t
        .sdk
        .op()
        .quote(
            p,
            SubmitPath::Auto {
                payer: Some(payer(&t)),
            },
        )
        .await
        .unwrap();
    assert!(matches!(q.path, SubmitPath::SelfRelay { .. }));
}

#[tokio::test(flavor = "multi_thread")]
async fn submit_returns_after_the_row_write() {
    let t = setup(1, |_, _| {}).await;
    t.chain.lock().unwrap().gw = Gw::Refuse;
    let sub = t.sdk.subscribe();
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let q = gateway_quote(&t, &p).await;
    let op = t
        .sdk
        .op()
        .submit(p, q)
        .await
        .expect("a failed send is no error of submit");
    assert_eq!(
        event(&sub, &op).await,
        OpState::InFlight {
            detail: InFlight::GivenUpByEveryNode
        }
    );
    // the row write fails: an error, and nothing sent
    let p = prepare(&t, cancel(&t, "token", TOKEN, "6", "0")).await;
    let q = gateway_quote(&t, &p).await;
    t.store.fail_state.store(true, SeqCst);
    let before = t.chain.lock().unwrap().bodies.len();
    assert_eq!(code(t.sdk.op().submit(p, q).await), "VaultIo");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        t.chain.lock().unwrap().bodies.len(),
        before,
        "nothing is sent before its row is written"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn write_ahead_then_send() {
    // a kill between the send and its `sent` mark: the row stays `signed`; the restart sends the same bytes once
    let t = setup(0, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let q = t
        .sdk
        .op()
        .quote(p.clone(), SubmitPath::SelfRelay { payer: payer(&t) })
        .await
        .unwrap();
    t.store.fail_sent.store(true, SeqCst);
    let op = t.sdk.op().submit(p, q.clone()).await.unwrap();
    let first = sent_txs(&t, 1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(state::row(&t.sdk, &op).await.unwrap().state, "signed");
    t.store.fail_sent.store(false, SeqCst);
    let again = open(t.store.clone(), t.profile.clone(), Limits::default()).await;
    assert_eq!(again.op().resume().await.unwrap(), 1);
    let sent = sent_txs(&t, 2).await;
    assert_eq!(sent[1], first[0], "the same bytes");
    assert_eq!(state::row(&again, &op).await.unwrap().state, "sent");
    // a row `sent` is not sent again at restart; `resend` sends the same bytes
    let third = open(t.store.clone(), t.profile.clone(), Limits::default()).await;
    assert_eq!(third.op().resume().await.unwrap(), 0);
    assert_eq!(t.chain.lock().unwrap().sent.len(), 2);
    third.op().resend(op.clone(), q).await.unwrap();
    let sent = sent_txs(&t, 3).await;
    assert_eq!(sent[2], first[0], "resend: the same bytes, never re-signed");
}

#[tokio::test(flavor = "multi_thread")]
async fn dropped_future_still_completes() {
    let t = setup(1, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let q = gateway_quote(&t, &p).await;
    let op = t.sdk.op();
    // the caller gives up at once; the submit runs on the SDK's runtime to `sent`
    let _ = tokio::time::timeout(Duration::from_millis(1), op.submit(p, q)).await;
    bodies(&t, 1).await;
    for _ in 0..100 {
        let rows = state::rows(&t.sdk).await.unwrap();
        if rows.first().is_some_and(|r| r.state == "sent") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the submit did not complete to `sent`");
}

/// Submits a gateway `UACancelNonce` on `kind`'s `contract` and returns the operation and its digest.
async fn submitted(t: &T, kind: &'static str, contract: &str, lane: &str) -> (String, String) {
    let p = prepare(t, cancel(t, kind, contract, lane, "0")).await;
    let path = if kind == "token" {
        SubmitPath::Gateway
    } else {
        SubmitPath::SelfRelay { payer: payer(t) }
    };
    let q = t.sdk.op().quote(p.clone(), path).await.unwrap();
    let op = t.sdk.op().submit(p.clone(), q).await.unwrap();
    (op, p.id())
}

#[tokio::test(flavor = "multi_thread")]
async fn all_gateways_dead_is_in_flight() {
    let t = setup(2, |_, _| {}).await;
    t.chain.lock().unwrap().gw = Gw::Refuse;
    let sub = t.sdk.subscribe();
    let (op, digest) = submitted(&t, "token", TOKEN, "5").await;
    event(&sub, &op).await;
    // every node refused: the nonce unspent, validUntil ahead: in flight, never terminal
    assert_eq!(
        t.sdk.op().state(op.clone()).await.unwrap(),
        OpState::InFlight {
            detail: InFlight::GivenUpByEveryNode
        }
    );
    // controls, each on its own operation
    let (spent, _) = submitted(&t, "token", TOKEN, "6").await;
    t.chain.lock().unwrap().nonces.insert(TOKEN.into(), 1);
    assert_eq!(
        t.sdk.op().state(spent).await.unwrap(),
        OpState::Consumed,
        "the nonce spent without the event"
    );
    t.chain.lock().unwrap().nonces.insert(TOKEN.into(), 0);
    let (late, _) = submitted(&t, "token", TOKEN, "7").await;
    t.chain.lock().unwrap().timestamp += 7200;
    assert_eq!(
        t.sdk.op().state(late).await.unwrap(),
        OpState::Expired,
        "validUntil passed, the nonce unspent"
    );
    {
        let mut c = t.chain.lock().unwrap();
        c.timestamp -= 7200;
        let n = c.finalized;
        c.logs.push(executed_log(TOKEN, &digest, n, false));
    }
    let landed = t.sdk.op().state(op.clone()).await.unwrap();
    assert!(
        matches!(landed, OpState::Landed { block: 0x20, .. }),
        "{landed:?}"
    );
    assert_eq!(event(&sub, &op).await, landed);
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_self_relay_tx_is_not_terminal() {
    let t = setup(0, |_, _| {}).await;
    let (op, _) = submitted(&t, "wallet", OTHER, "5").await;
    sent_txs(&t, 1).await;
    let id = state::row(&t.sdk, &op).await.unwrap().tx_id.unwrap();
    t.chain.lock().unwrap().receipts.insert(id, false);
    assert_eq!(
        t.sdk.op().state(op).await.unwrap(),
        OpState::InFlight {
            detail: InFlight::TxFinalFailed
        }
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn executed_event_per_contract() {
    let t = setup(1, |_, _| {}).await;
    let wallet = "0x5ca00000000000000000000000000000000000c3";
    let router = "0x5ca00000000000000000000000000000000000d4";
    let account = "0x5ca00000000000000000000000000000000000e5";
    for (kind, contract, is_account) in [
        ("token", TOKEN, false),
        ("wallet", wallet, false),
        ("gov_router", router, false),
        ("account", account, true),
    ] {
        let (op, digest) = submitted(&t, kind, contract, "5").await;
        let n = t.chain.lock().unwrap().finalized;
        // the other contract kind's event for the same digest is not this operation's
        t.chain
            .lock()
            .unwrap()
            .logs
            .push(executed_log(contract, &digest, n, !is_account));
        assert!(
            matches!(
                t.sdk.op().state(op.clone()).await.unwrap(),
                OpState::InFlight { .. }
            ),
            "{kind}: the other event"
        );
        t.chain.lock().unwrap().logs.push(executed_log(
            contract,
            &format!("0x{}", "00".repeat(32)),
            n,
            is_account,
        ));
        assert!(
            matches!(
                t.sdk.op().state(op.clone()).await.unwrap(),
                OpState::InFlight { .. }
            ),
            "{kind}: another digest"
        );
        t.chain
            .lock()
            .unwrap()
            .logs
            .push(executed_log(contract, &digest, n, is_account));
        assert!(
            matches!(t.sdk.op().state(op).await.unwrap(), OpState::Landed { .. }),
            "{kind}: its event"
        );
    }
    // ponytail: a registry write (landed by its record) comes with the registry entries, plan T13
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_nonce_ends_it() {
    let t = setup(1, |_, _| {}).await;
    // the fake chain executes a `mtxCancelNonce` it receives: the lane's nonce moves
    t.chain.lock().unwrap().on_body = Some(|c, b| {
        if b["op"]["entry"] == "mtxCancelNonce" && b["op"]["args"]["lane"] == "7" {
            c.nonces.insert(TOKEN.into(), 1);
        }
    });
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await; // batch 7, nonce 0: the first operation
    let first_q = gateway_quote(&t, &p).await;
    t.chain.lock().unwrap().gw = Gw::Refuse;
    let first = t.sdk.op().submit(p, first_q).await.unwrap();
    bodies(&t, 1).await;
    assert!(matches!(
        t.sdk.op().state(first.clone()).await.unwrap(),
        OpState::InFlight { .. }
    ));
    t.chain.lock().unwrap().gw = Gw::Queue;
    // the user ends it for good: a cancel of lane 7 on its own lane (batch 7 too here; any lane of the subject)
    let mut d = cancel(&t, "token", TOKEN, "7", "0");
    d.message["batch"] = json!("8");
    let p = prepare(&t, d).await;
    let q = gateway_quote(&t, &p).await;
    t.sdk.op().submit(p, q).await.unwrap();
    bodies(&t, 2).await;
    assert_eq!(t.sdk.op().state(first).await.unwrap(), OpState::Consumed);
}

#[tokio::test(flavor = "multi_thread")]
async fn gateway_chain_uid_mismatch_is_refused() {
    let t = setup(1, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    assert_eq!(
        code(t.sdk.op().quote(p.clone(), SubmitPath::Gateway).await),
        "Ok",
        "control: the gateway's chain_uid is the profile's"
    );
    t.chain.lock().unwrap().gw_info["chains"][0]["chain_uid"] =
        format!("0x{}", "61".repeat(32)).into();
    assert_eq!(
        code(t.sdk.op().quote(p.clone(), SubmitPath::Gateway).await),
        "ProfileMismatch"
    );
    assert_eq!(
        code(
            t.sdk
                .op()
                .quote(p.clone(), SubmitPath::Auto { payer: None })
                .await
        ),
        "ProfileMismatch",
        "Auto too"
    );
    t.chain.lock().unwrap().gw_info["chains"][0]
        .as_object_mut()
        .unwrap()
        .remove("chain_uid");
    assert_eq!(
        code(t.sdk.op().quote(p, SubmitPath::Gateway).await),
        "ProfileMismatch",
        "none announced: refused too"
    );
    assert!(
        t.chain.lock().unwrap().bodies.is_empty(),
        "the gateway unused"
    );
}

// --- owner 2026-11-18, ruling 1: a quote never makes or sends a signature; submit signs once ---

fn signs(t: &T) -> u32 {
    t.sdk.signs.load(SeqCst)
}

/// The signature `submit` would make for `p` (deterministic): its hex without `0x`.
fn signature_of(p: &Prepared) -> String {
    let w = Wallet::from_mnemonic(REPO, "").unwrap();
    let k = w.ua_key(0x0101, 0, 0).unwrap();
    let s = scaas_ua::wallet::sign_scaas(&k, &p.t.td, p.t.expect.clone()).unwrap();
    hex(&s.signature)[2..].to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn quote_makes_no_signature() {
    let t = setup(1, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let sig = signature_of(&p);
    t.chain.lock().unwrap().requests.clear();
    let q = t
        .sdk
        .op()
        .quote(p.clone(), SubmitPath::SelfRelay { payer: payer(&t) })
        .await
        .unwrap();
    gateway_quote(&t, &p).await;
    assert_eq!(signs(&t), 0, "no signer call at quote time");
    let wire = t.chain.lock().unwrap().requests.clone();
    assert!(
        wire.iter().any(|b| b.contains("eth_estimateGas")),
        "the unsigned form was estimated"
    );
    assert!(
        !wire.iter().any(|b| b.contains(&sig)),
        "no signature on the wire"
    );
    // control: submit signs once, and the simulation carries that signature
    t.sdk.op().submit(p, q).await.unwrap();
    assert_eq!(signs(&t), 1, "submit: exactly one signer call");
    let wire = t.chain.lock().unwrap().requests.clone();
    assert!(
        wire.iter()
            .any(|b| b.contains("eth_estimateGas") && b.contains(&sig)),
        "submit simulates the signed calldata"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn submit_signs_once_on_each_path() {
    let t = setup(1, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let q = gateway_quote(&t, &p).await;
    t.sdk.op().submit(p, q).await.unwrap();
    assert_eq!(signs(&t), 1, "the gateway path");
    let p = prepare(&t, cancel(&t, "token", TOKEN, "6", "0")).await;
    let q = t
        .sdk
        .op()
        .quote(p.clone(), SubmitPath::SelfRelay { payer: payer(&t) })
        .await
        .unwrap();
    t.sdk.op().submit(p, q).await.unwrap();
    assert_eq!(signs(&t), 2, "the self-relay path: one more");
}

#[tokio::test(flavor = "multi_thread")]
async fn unsigned_form_refused_is_gas_unquoted() {
    let t = setup(0, |_, _| {}).await;
    let path = SubmitPath::SelfRelay { payer: payer(&t) };
    t.chain.lock().unwrap().call_revert = true;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    assert_eq!(
        code(t.sdk.op().quote(p, path.clone()).await),
        "GasUnquoted",
        "no pinned figure, the unsigned form refused"
    );
    // control: a pinned operation (the router's ordered cancel) takes its figure, no estimate
    let p = prepare(&t, cancel(&t, "gov_router", OTHER, "5", "0")).await;
    let q = t.sdk.op().quote(p.clone(), path).await.unwrap();
    let len = submit::unsigned(&p).unwrap().calldata.len() as u64;
    let want = (72_600 + 21_000 + 64 * len) * 3 / 2;
    assert!(
        q.gas_limit == want || q.gas_limit + 1 == want,
        "{} {want}",
        q.gas_limit
    );
    assert_eq!(signs(&t), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn submit_refuses_more_gas_than_quoted() {
    let t = setup(0, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let q = t
        .sdk
        .op()
        .quote(p.clone(), SubmitPath::SelfRelay { payer: payer(&t) })
        .await
        .unwrap();
    t.chain.lock().unwrap().gas = q.gas_limit + 1; // the signed form needs more than the user confirmed
    assert_eq!(
        code(t.sdk.op().submit(p.clone(), q.clone()).await),
        "GasUnquoted"
    );
    assert!(
        state::rows(&t.sdk).await.unwrap().is_empty(),
        "nothing written"
    );
    t.chain.lock().unwrap().gas = q.gas_limit; // control: within the quote
    t.sdk.op().submit(p, q).await.unwrap();
    sent_txs(&t, 1).await;
}
