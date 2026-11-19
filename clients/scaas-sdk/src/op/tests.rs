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
    open_at(store, profile, limits, 1_800_000_000).await
}

/// `open` on a clock fixed at `now`.
async fn open_at(store: Arc<Flaky>, profile: ChainProfile, limits: Limits, now: u64) -> Arc<Sdk> {
    Sdk::open(SdkConfig {
        profiles: vec![profile],
        store,
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits,
        clock: Some(std::sync::Arc::new(move || now)),
        // a module table every test SDK holds; read only by a profile that opts in to `vault`
        gas_tables: vec![crate::GasTable {
            name: "vault".into(),
            family: "evm".into(),
            rows: gas_rows(200_000),
        }],
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
        gas: gas_rows(100_000),
        max_valid_secs: None,
        gas_opt_in: vec![],
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

/// A base row of `g` for every entry and domain kind, fresh lane or not, and a verify row of 0 for the tests' UA (0x0101) and a
/// native EVM key: the figure is `g`.
fn gas_rows(g: u64) -> crate::GasRows {
    let mut base = vec![];
    for r in scaas_ua::wallet::entries::entry_rows() {
        for k in r.kinds {
            for fresh in [true, false] {
                base.push(crate::GasBase {
                    entry: r.entry.into(),
                    kind: (*k).into(),
                    fresh,
                    gas: g,
                    per_byte: None,
                    save: None,
                    fee_extra: None,
                    ua_extra: None,
                    per_item: None,
                });
            }
        }
    }
    let verify = [0x0101, gas::NATIVE_EVM]
        .map(|signer| crate::GasVerify {
            signer,
            gas: 0,
            sig_bytes: 0,
            margin: 0,
            per_item: None,
        })
        .to_vec();
    crate::GasRows { base, verify }
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
        ids: false,
        relay_call: None,
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
        ids: false,
        relay_call: None,
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
    // the signed values are the reviewed ones, read back from what was posted (closing review P3: not from the message the
    // review was built from)
    let text = |v: &Value| {
        v.as_str()
            .map(String::from)
            .unwrap_or(v.to_string())
            .to_ascii_lowercase()
    };
    for f in p.review().iter().filter(|f| f.source == Source::Signed) {
        let posted = [&body["op"]["args"], &body["op"]["envelope"], &body["op"]]
            .into_iter()
            .find_map(|o| o.get(&f.name))
            .unwrap_or_else(|| panic!("{} not posted", f.name));
        assert_eq!(text(posted), f.value.to_ascii_lowercase(), "{}", f.name);
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
    let len = submit::unsigned(&p).unwrap().calldata.len() as u64;
    assert_eq!(
        q.gas_limit,
        gas::with_margin(100_000 + 21_000 + 64 * len),
        "the gas row's figure, the intrinsic cost and the calldata, plus the margin"
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
    let t2 = setup(0, |p, l| {
        l.max_gas = 1_000_000;
        p.gas = gas_rows(2_000_000);
    })
    .await;
    let p2 = prepare(&t2, cancel(&t2, "token", TOKEN, "5", "0")).await;
    assert_eq!(
        code(
            t2.sdk
                .op()
                .quote(p2, SubmitPath::SelfRelay { payer: payer(&t2) })
                .await
        ),
        "FeeAboveCap",
        "a huge gas figure"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn gas_above_tx_cap() {
    let t = setup(0, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let len = submit::unsigned(&p).unwrap().calldata.len() as u64;
    // the figure (row + intrinsic + calldata) plus half: 11_184_812 → 16_777_218, above 2^24; 11_184_811 → 2^24
    let row = |total: u64| gas_rows(total - 21_000 - 64 * len);
    // (each SDK kept alive: a dropped wallet revokes the handles of the same seed's wallet)
    let t1 = setup(0, |p, _| p.gas = row(11_184_812)).await;
    let p = prepare(&t1, cancel(&t1, "token", TOKEN, "5", "0")).await;
    let path = SubmitPath::SelfRelay { payer: payer(&t1) };
    assert_eq!(
        code(t1.sdk.op().quote(p.clone(), path.clone()).await),
        "GasAboveTxCap"
    );
    let t = setup(0, |p, _| p.gas = row(11_184_811)).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let path = SubmitPath::SelfRelay { payer: payer(&t) };
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
        !wire.iter().any(|b| b.contains(&sig)),
        "no signature on the wire"
    );
    // control: submit signs once, and the simulation (after the write) carries that signature
    t.sdk.op().submit(p, q).await.unwrap();
    assert_eq!(signs(&t), 1, "submit: exactly one signer call");
    sent_txs(&t, 1).await;
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

/// Ruling B (P2-6), the split table (part 3b): the quote's gas is the base row of (entry, kind, lane state) plus the verify row
/// of the signer kind; a key without either is `GasUnquoted`, nothing estimated.
#[tokio::test(flavor = "multi_thread")]
async fn an_operation_without_a_gas_row_is_gas_unquoted() {
    let only = |signer: u16, fresh: bool| {
        move |p: &mut ChainProfile, _: &mut Limits| {
            let mut g = gas_rows(100_000);
            g.base.retain(|r| r.fresh == fresh);
            g.verify.retain(|r| r.signer == signer);
            p.gas = g;
        }
    };
    // verify rows for another signer kind only (an ML-DSA-65 UA's figure is not a P-256 one's)
    let t = setup(0, |p, _| {
        let mut g = gas_rows(100_000);
        g.verify = vec![crate::GasVerify {
            signer: 0x0131,
            gas: 0,
            sig_bytes: 0,
            margin: 0,
            per_item: None,
        }];
        p.gas = g;
    })
    .await;
    let path = SubmitPath::SelfRelay { payer: payer(&t) };
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    t.chain.lock().unwrap().requests.clear();
    assert_eq!(
        code(t.sdk.op().quote(p, path.clone()).await),
        "GasUnquoted",
        "another signer kind's row"
    );
    assert!(
        !t.chain
            .lock()
            .unwrap()
            .requests
            .iter()
            .any(|b| b.contains("eth_estimateGas")),
        "nothing estimated"
    );
    // rows for a used lane only: the lane's nonce is 0 here (its first use); each SDK kept alive (a dropped wallet revokes the
    // handles of the same seed's wallet)
    let t1 = setup(0, only(0x0101, false)).await;
    let p = prepare(&t1, cancel(&t1, "token", TOKEN, "5", "0")).await;
    let path = SubmitPath::SelfRelay { payer: payer(&t1) };
    assert_eq!(
        code(t1.sdk.op().quote(p, path).await),
        "GasUnquoted",
        "a used lane's row"
    );
    // control: the key's own row
    let t2 = setup(0, only(0x0101, true)).await;
    let p = prepare(&t2, cancel(&t2, "token", TOKEN, "5", "0")).await;
    assert_eq!(
        code(
            t2.sdk
                .op()
                .quote(p, SubmitPath::SelfRelay { payer: payer(&t2) })
                .await
        ),
        "Ok"
    );
    // the reference table, only on the profile's opt-in: the router's ordered cancel by a native EVM key on a used lane
    // (`mtxCancelNonce_router`)
    for opt_in in [false, true] {
        let t = setup(0, |p, _| {
            p.gas = Default::default();
            if opt_in {
                p.gas_opt_in = vec![gas::REFERENCE.into()];
            }
        })
        .await;
        t.chain.lock().unwrap().nonces.insert(OTHER.into(), 3);
        let mut d = cancel(&t, "gov_router", OTHER, "5", "0");
        d.signer = payer(&t);
        d.message["from"] = json!(format!("0x{}{}", "00".repeat(12), &evm_address()[2..]));
        let p = prepare(&t, d).await;
        let r = t
            .sdk
            .op()
            .quote(p.clone(), SubmitPath::SelfRelay { payer: payer(&t) })
            .await;
        if !opt_in {
            assert_eq!(
                code(r),
                "GasUnquoted",
                "the reference table is never read on its own"
            );
            continue;
        }
        let q = r.unwrap();
        let len = submit::unsigned(&p).unwrap().calldata.len() as u64;
        // the reference table's row of the router's cancel on a used lane (the generated file's figure: 55,000 for the old
        // seed pin, regular gas only; since part 3b's measurement regular + state gas)
        let rows = crate::GasTable::parse(gas::REFERENCE_FILE).unwrap().rows;
        let row = rows
            .base
            .iter()
            .find(|b| b.key() == ("mtxCancelNonce", "gov_router", false))
            .unwrap();
        // ruling 2 (owner 2026-11-19): the native key's signature bytes at 64 gas a byte over the unsigned calldata
        let sig = rows
            .verify
            .iter()
            .find(|v| v.signer == 0)
            .unwrap()
            .sig_bytes;
        assert_eq!(sig, 96);
        assert_eq!(
            q.gas_limit,
            gas::with_margin(row.gas + 21_000 + 64 * (len + sig))
        );
        assert_eq!(
            (q.gas, q.gas_from),
            (
                Some(q.gas_limit),
                Some(GasSources::both(GasFrom::Reference))
            )
        );
        assert_eq!(signs(&t), 0);
    }
}

/// Item 8 of the gas-table round (owner 2026-11-19): an entry formerly without a reference row (`UNMEASURED`) quotes from it
/// once measured: the account's ordered cancel by its native key on a fresh lane, `GasUnquoted` without the opt-in, the
/// reference row's figure with it.
#[tokio::test(flavor = "multi_thread")]
async fn a_newly_measured_entry_quotes_from_the_reference_table() {
    for opt_in in [false, true] {
        let t = setup(0, |p, _| {
            p.gas = Default::default();
            if opt_in {
                p.gas_opt_in = vec![gas::REFERENCE.into()];
            }
        })
        .await;
        let p = prepare(&t, cancel(&t, "account", OTHER, "5", "0")).await;
        let r = t
            .sdk
            .op()
            .quote(p.clone(), SubmitPath::SelfRelay { payer: payer(&t) })
            .await;
        if !opt_in {
            assert_eq!(code(r), "GasUnquoted");
            continue;
        }
        let q = r.unwrap();
        let len = submit::unsigned(&p).unwrap().calldata.len() as u64;
        let rows = crate::GasTable::parse(gas::REFERENCE_FILE).unwrap().rows;
        let row = rows
            .base
            .iter()
            .find(|b| b.key() == ("mtxCancelNonce", "account", true))
            .unwrap();
        let sig = rows
            .verify
            .iter()
            .find(|v| v.signer == 0)
            .unwrap()
            .sig_bytes;
        assert_eq!(
            q.gas_limit,
            gas::with_margin(row.gas + 21_000 + 64 * (len + sig))
        );
        assert_eq!(q.gas_from, Some(GasSources::both(GasFrom::Reference)));
    }
}

/// Owner 2026-11-19, I1, through the quote: `mtxRollOverBatch`'s base row with a per-item part on `accounts` quotes its gas
/// plus the part times the number of `uas` the operation names, on both paths; the same part on another count (`legs`), which
/// the operation lacks, refuses it as `GasCountUnknown` on both paths, the app's figure too; without the part the quote is
/// the row's alone.
#[tokio::test(flavor = "multi_thread")]
async fn a_counted_row_quotes_its_count_or_refuses() {
    let with = |item: Option<&'static str>| {
        move |p: &mut ChainProfile, _: &mut Limits| {
            for b in &mut p.gas.base {
                if b.entry == "mtxRollOverBatch" {
                    b.per_item = item.map(|i| crate::GasPerItem {
                        item: i.into(),
                        gas: 7_000,
                    });
                }
            }
        }
    };
    let batch = |t: &T| {
        let until = t.chain.lock().unwrap().timestamp + 3600;
        let uas: Vec<String> = (1..=3u8).map(|i| hex(&[i; 32])).collect();
        Draft {
            message: json!({"from": ua(), "uas": uas, "batch": "7", "validUntil": until.to_string(), "mode": 0,
                "relayer": ZERO, "fee": "0", "feeRecipient": ZERO}),
            name: "UARollOverBatch",
            kind: "zether",
            ..cancel(t, "token", TOKEN, "5", "0")
        }
    };
    let mut figures = vec![];
    for item in [None, Some("accounts"), Some("legs")] {
        let t = setup(1, with(item)).await;
        let p = prepare(&t, batch(&t)).await;
        let len = submit::unsigned(&p).unwrap().calldata.len() as u64;
        let self_relay = SubmitPath::SelfRelay { payer: payer(&t) };
        if item == Some("legs") {
            assert_eq!(
                code(t.sdk.op().quote(p.clone(), self_relay).await),
                "GasCountUnknown"
            );
            assert_eq!(
                code(t.sdk.op().quote(p.clone(), SubmitPath::Gateway).await),
                "GasCountUnknown"
            );
            let app = t
                .sdk
                .op()
                .quote_with_gas(p, SubmitPath::SelfRelay { payer: payer(&t) }, 500_000)
                .await;
            assert_eq!(
                code(app),
                "GasCountUnknown",
                "never the app's figure instead"
            );
            continue;
        }
        let q = t.sdk.op().quote(p.clone(), self_relay).await.unwrap();
        assert_eq!(
            gateway_quote(&t, &p).await.gas,
            Some(q.gas_limit),
            "the same figure on both paths"
        );
        figures.push((q.gas_limit, len));
    }
    let [(plain, len), (counted, _)] = figures[..] else {
        panic!("{figures:?}")
    };
    assert_eq!(plain, gas::with_margin(100_000 + 21_000 + 64 * len));
    assert_eq!(
        counted,
        gas::with_margin(100_000 + 3 * 7_000 + 21_000 + 64 * len)
    );
}

/// The gas-table rulings (owner 2026-11-19): each source on the self-relay path, in the lookup order chain → module (opted in)
/// → reference (opted in) → the app's figure → `GasUnquoted`; the quote names the source; an app figure above `max_gas` is
/// refused. No signature at quote time.
#[tokio::test(flavor = "multi_thread")]
async fn quote_names_its_gas_source_in_order() {
    let src = |opt: &'static [&'static str], chain: bool| {
        move |p: &mut ChainProfile, _: &mut Limits| {
            if !chain {
                p.gas = Default::default();
            }
            p.gas_opt_in = opt.iter().map(|s| s.to_string()).collect();
        }
    };
    let len = |p: &Arc<Prepared>| submit::unsigned(p).unwrap().calldata.len() as u64;
    let quote = |t: &T, p: Arc<Prepared>, app: Option<u64>| {
        let op = t.sdk.op();
        let path = SubmitPath::SelfRelay { payer: payer(t) };
        async move {
            match app {
                Some(g) => op.quote_with_gas(p, path, g).await,
                None => op.quote(p, path).await,
            }
        }
    };
    // chain rows first, whatever is opted in and whatever the app passes
    let t = setup(0, src(&["vault", "reference"], true)).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let q = quote(&t, p.clone(), Some(500_000)).await.unwrap();
    assert_eq!(q.gas_from, Some(GasSources::both(GasFrom::Chain)));
    assert_eq!(
        q.gas_limit,
        gas::with_margin(100_000 + 21_000 + 64 * len(&p))
    );
    // the module table the profile opts in to
    let t = setup(0, src(&["vault"], false)).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let q = quote(&t, p.clone(), Some(500_000)).await.unwrap();
    assert_eq!(
        q.gas_from,
        Some(GasSources::both(GasFrom::Module("vault".into())))
    );
    assert_eq!(
        q.gas_limit,
        gas::with_margin(200_000 + 21_000 + 64 * len(&p))
    );
    // each part on its own: the chain's base rows, the module's verify rows (gas_from names both)
    let t = setup(0, |p, _| {
        p.gas.verify.clear();
        p.gas_opt_in = vec!["vault".into()];
    })
    .await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let q = quote(&t, p.clone(), None).await.unwrap();
    assert_eq!(
        q.gas_from,
        Some(GasSources {
            base: GasFrom::Chain,
            verify: GasFrom::Module("vault".into())
        })
    );
    assert_eq!(
        q.gas_limit,
        gas::with_margin(100_000 + 21_000 + 64 * len(&p))
    );
    // the app's figure: no table row (nothing opted in), named `App`
    let t = setup(0, src(&[], false)).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let q = quote(&t, p.clone(), Some(500_000)).await.unwrap();
    assert_eq!(q.gas_from, Some(GasSources::both(GasFrom::App)));
    assert_eq!(
        q.gas_limit,
        gas::with_margin(500_000 + 21_000 + 64 * len(&p))
    );
    assert_eq!(q.gas, Some(q.gas_limit));
    // ... refused above `max_gas` (control: at it), and without it the self-relay is unquoted
    let max = t.sdk.limits.max_gas;
    assert_eq!(
        code(quote(&t, p.clone(), Some(max + 1)).await),
        "FeeAboveCap"
    );
    assert_ne!(code(quote(&t, p.clone(), Some(max)).await), "GasUnquoted");
    assert_eq!(code(quote(&t, p, None).await), "GasUnquoted");
    assert_eq!(signs(&t), 0);
}

/// The gas-table rulings (owner 2026-11-19): the gateway quote carries the gas figure and its source for the user and the app
/// (`gas_limit` and `max_cost` stay 0: the holder sends no transaction), and without a figure it reports the gas as unquoted
/// (`gas: None`) and is not refused.
#[tokio::test(flavor = "multi_thread")]
async fn gateway_quote_carries_gas_or_reports_it_unquoted() {
    let t = setup(1, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let q = gateway_quote(&t, &p).await;
    let len = submit::unsigned(&p).unwrap().calldata.len() as u64;
    assert_eq!(q.gas, Some(gas::with_margin(100_000 + 21_000 + 64 * len)));
    assert_eq!(q.gas_from, Some(GasSources::both(GasFrom::Chain)));
    assert_eq!((q.gas_limit, q.max_cost.as_str()), (0, "0"));
    let t = setup(1, |p, _| p.gas = Default::default()).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let q = gateway_quote(&t, &p).await;
    assert_eq!(
        (q.gas, q.gas_from.clone()),
        (None, None),
        "unquoted, not refused"
    );
    t.sdk.op().submit(p, q).await.unwrap();
    assert_eq!(signs(&t), 1, "the relayed submit goes on");
}

/// Ruling A (P1-1): sign → write the row → simulate → send. A simulation that reverts (or needs more gas than the confirmed
/// quote) after the endpoint saw the signed calldata leaves the operation tracked (`SimRefused`), never an error of `submit`
/// with no row; it is not sent, not sent again at restart, and another relayer landing the recorded calldata makes it
/// `Landed`.
#[tokio::test(flavor = "multi_thread")]
async fn sim_refused_is_written_and_followed() {
    for revert in [true, false] {
        let t = setup(0, |_, _| {}).await;
        let sub = t.sdk.subscribe();
        let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
        let q = t
            .sdk
            .op()
            .quote(p.clone(), SubmitPath::SelfRelay { payer: payer(&t) })
            .await
            .unwrap();
        if revert {
            t.chain.lock().unwrap().call_revert = true;
        } else {
            // the signed form needs more than the limit sent (the quote's, raised by G3 for the signature's bytes, which the
            // fixture's `sig_bytes` of 0 left out: below twice the quote's, asserted below)
            t.chain.lock().unwrap().gas = q.gas_limit * 2;
        }
        let op = t
            .sdk
            .op()
            .submit(p.clone(), q.clone())
            .await
            .expect("a refused simulation is no error");
        assert_eq!(
            event(&sub, &op).await,
            OpState::InFlight {
                detail: InFlight::SimRefused
            }
        );
        let row = state::row(&t.sdk, &op).await.unwrap();
        assert_eq!(
            (row.digest.as_str(), row.state.as_str(), row.detail.as_str()),
            (p.id().as_str(), "signed", "SimRefused")
        );
        assert!(row.gas_limit < Some(q.gas_limit * 2));
        // what the endpoint saw: the signed calldata, after the row was written
        assert!(t
            .chain
            .lock()
            .unwrap()
            .requests
            .iter()
            .any(|b| b.contains("eth_call") && b.contains(&row.calldata[2..])));
        assert!(t.chain.lock().unwrap().sent.is_empty(), "nothing sent");
        let again = open(t.store.clone(), t.profile.clone(), Limits::default()).await;
        assert_eq!(again.op().resume().await.unwrap(), 0, "not sent at restart");
        // another relayer lands the recorded calldata: the operation follows to the chain fact
        {
            let mut c = t.chain.lock().unwrap();
            let n = c.finalized;
            c.logs.push(executed_log(TOKEN, &row.digest, n, false));
            c.nonces.insert(TOKEN.into(), 1);
        }
        assert!(matches!(
            t.sdk.op().state(op).await.unwrap(),
            OpState::Landed { .. }
        ));
    }
    // the row write fails: an error, and the signed calldata never reached an endpoint (nothing signed left the SDK)
    let t = setup(0, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let sig = signature_of(&p);
    let q = t
        .sdk
        .op()
        .quote(p.clone(), SubmitPath::SelfRelay { payer: payer(&t) })
        .await
        .unwrap();
    t.store.fail_state.store(true, SeqCst);
    assert_eq!(code(t.sdk.op().submit(p, q).await), "VaultIo");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !t.chain
            .lock()
            .unwrap()
            .requests
            .iter()
            .any(|b| b.contains(&sig)),
        "the signature reached an endpoint before its row was written"
    );
    // control: within the quote it is sent
    let t = setup(0, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let q = t
        .sdk
        .op()
        .quote(p.clone(), SubmitPath::SelfRelay { payer: payer(&t) })
        .await
        .unwrap();
    t.chain.lock().unwrap().gas = q.gas_limit;
    t.sdk.op().submit(p, q).await.unwrap();
    sent_txs(&t, 1).await;
}

/// P2-5: the scan starts at the final block when the operation was signed, never the head: an operation landing between
/// the two is `Landed`, not `Consumed`.
#[tokio::test(flavor = "multi_thread")]
async fn from_block_is_the_final_block_at_submit() {
    let t = setup(1, |_, _| {}).await;
    t.chain.lock().unwrap().finalized = 0x18; // the head 0x20, an endpoint ahead of the final block
    let (op, digest) = submitted(&t, "token", TOKEN, "5").await;
    assert_eq!(state::row(&t.sdk, &op).await.unwrap().from_block, 0x18);
    {
        let mut c = t.chain.lock().unwrap();
        c.logs.push(executed_log(TOKEN, &digest, 0x1c, false));
        c.nonces.insert(TOKEN.into(), 1);
        c.finalized = 0x20;
    }
    let s = t.sdk.op().state(op).await.unwrap();
    assert!(matches!(s, OpState::Landed { block: 0x1c, .. }), "{s:?}");
}

/// P3: one `Prepared`, two concurrent `submit`s: one signs and writes, the other is `PreparedUnknown`.
#[tokio::test(flavor = "multi_thread")]
async fn one_prepared_submits_once() {
    let t = setup(1, |_, _| {}).await;
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let q = gateway_quote(&t, &p).await;
    let op = t.sdk.op();
    let (a, b) = tokio::join!(
        op.submit(p.clone(), q.clone()),
        op.submit(p.clone(), q.clone())
    );
    // the second is `PreparedUnknown`, or (when the first's row is written by then) that same operation (T13b ruling 7)
    let (a, b) = (a.map_err(|e| e.code()), b.map_err(|e| e.code()));
    assert!(
        matches!((&a, &b), (Ok(x), Ok(y)) if x == y)
            || matches!(
                (&a, &b),
                (Ok(_), Err("PreparedUnknown")) | (Err("PreparedUnknown"), Ok(_))
            ),
        "{a:?} {b:?}"
    );
    assert_eq!(signs(&t), 1, "signed once");
    assert_eq!(state::rows(&t.sdk).await.unwrap().len(), 1, "one row");
}

/// P3: a hand-built gateway quote is checked as `quote` checks it: a non-door-A entry is `SubmitPathNone`, gateways that do not
/// announce the profile's `chain_uid` are `ProfileMismatch`; nothing is signed.
#[tokio::test(flavor = "multi_thread")]
async fn hand_built_gateway_quote_is_checked() {
    let t = setup(1, |_, _| {}).await;
    let by_hand = |n: u32| SubmitQuote {
        path: SubmitPath::Gateway,
        payer: None,
        gas_limit: 0,
        gas: None,
        gas_from: None,
        max_fee_per_gas: "0".into(),
        max_priority_fee_per_gas: "0".into(),
        max_cost: "0".into(),
        fee_to_relayer: "0".into(),
        gateways: (0..n).collect(),
        tx_nonce: 0,
        tx_type: 0,
    };
    let p = prepare(&t, cancel(&t, "wallet", OTHER, "5", "0")).await;
    assert_eq!(
        code(t.sdk.op().submit(p, by_hand(1)).await),
        "SubmitPathNone",
        "a mandate wallet's entry"
    );
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    t.chain.lock().unwrap().gw_info["chains"][0]["chain_uid"] =
        json!(format!("0x{}", "61".repeat(32)));
    assert_eq!(
        code(t.sdk.op().submit(p.clone(), by_hand(1)).await),
        "ProfileMismatch"
    );
    assert_eq!(signs(&t), 0);
    assert!(t.chain.lock().unwrap().bodies.is_empty(), "nothing posted");
    t.chain.lock().unwrap().gw_info["chains"][0]["chain_uid"] = json!(UID);
    assert_eq!(
        code(t.sdk.op().submit(p, by_hand(1)).await),
        "Ok",
        "control"
    );
}

/// P2-3: one pool per chain for the session: an endpoint's identity is read once, not again by every call.
#[tokio::test(flavor = "multi_thread")]
async fn one_pool_per_chain_for_the_session() {
    let t = setup(1, |_, _| {}).await;
    let ids = |t: &T| {
        t.chain
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|b| b.contains("eth_chainId"))
            .count()
    };
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let after_prepare = ids(&t);
    assert!(after_prepare >= 1, "control: the identity was read");
    gateway_quote(&t, &p).await;
    t.sdk
        .op()
        .quote(p.clone(), SubmitPath::SelfRelay { payer: payer(&t) })
        .await
        .unwrap();
    assert_eq!(
        ids(&t),
        after_prepare,
        "no second identity read in later calls"
    );
}

/// Closing review P2-4: the review and the check carry the fee the relayer takes, never a PERCENT envelope's rate: a struct
/// without an amount refuses PERCENT; FIXED shows its fee (the control). The PERCENT amount itself: `wallet_ops`'
/// `percent_fee_is_reviewed_as_its_amount`.
#[tokio::test(flavor = "multi_thread")]
async fn percent_fee_needs_an_amount() {
    let t = setup(1, |_, _| {}).await;
    let mut d = cancel(&t, "token", TOKEN, "5", "5000");
    d.message["mode"] = json!(0x10);
    assert_eq!(code(Op::prepare(&t.sdk, d).await), "PolicyRefused");
    let mut d = cancel(&t, "token", TOKEN, "5", "5000");
    d.message["mode"] = json!(0x20);
    let p = Op::prepare(&t.sdk, d).await.unwrap();
    let due = p
        .review()
        .into_iter()
        .find(|f| f.name == "fee.due")
        .unwrap();
    assert_eq!(
        (due.value.as_str(), due.source),
        ("5000", Source::Derived),
        "control: FIXED"
    );
}

/// Closing review P3: a read that is not decisive (the first endpoint `discovered`, under failover) never makes an operation
/// terminal, even with its executed event and its nonce spent; a named endpoint's read does (the control).
#[tokio::test(flavor = "multi_thread")]
async fn a_non_decisive_read_is_never_terminal() {
    for (class, terminal) in [
        (scaas_rpc::Class::Discovered, false),
        (scaas_rpc::Class::Named, true),
    ] {
        let t = setup(1, |p, _| p.rpc[0].class = class).await;
        let (op, digest) = submitted(&t, "token", TOKEN, "5").await;
        {
            let mut c = t.chain.lock().unwrap();
            let n = c.finalized;
            c.logs.push(executed_log(TOKEN, &digest, n, false));
            c.nonces.insert(TOKEN.into(), 1);
        }
        let s = t.sdk.op().state(op).await.unwrap();
        assert_eq!(s.is_terminal(), terminal, "{class:?}: {s:?}");
    }
}

/// Closing review P3: `resend` of a gateway operation whose `relayer` is bound is refused on a self-relay (only that relayer
/// may send it); an unbound one goes (the control).
#[tokio::test(flavor = "multi_thread")]
async fn resend_with_a_bound_relayer_is_refused() {
    let t = setup(1, |_, _| {}).await;
    for (mode, relayer, want) in [
        (1, "0x000000000000000000000000000000000000beef", "Argument"),
        (0, ZERO, "Ok"),
    ] {
        let mut d = cancel(&t, "token", TOKEN, if mode == 1 { "5" } else { "6" }, "0");
        d.message["mode"] = json!(mode);
        d.message["relayer"] = json!(relayer);
        let p = prepare(&t, d).await;
        let q = gateway_quote(&t, &p).await;
        let op = t.sdk.op().submit(p.clone(), q).await.unwrap();
        let p2 = prepare(&t, cancel(&t, "token", TOKEN, "7", "0")).await;
        let q2 = t
            .sdk
            .op()
            .quote(p2, SubmitPath::SelfRelay { payer: payer(&t) })
            .await
            .unwrap();
        assert_eq!(code(t.sdk.op().resend(op, q2).await), want, "mode {mode}");
    }
}

/// Closing review P3: the SDK counts its own signed transactions: a second self-relay quoted before the first lands takes the
/// next nonce though every endpoint still answers the first's.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_self_relay_takes_the_next_nonce() {
    let t = setup(0, |_, _| {}).await;
    let path = SubmitPath::SelfRelay { payer: payer(&t) };
    let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    let q = t.sdk.op().quote(p.clone(), path.clone()).await.unwrap();
    assert_eq!(q.tx_nonce, 0);
    t.sdk.op().submit(p, q).await.unwrap();
    let p = prepare(&t, cancel(&t, "token", TOKEN, "6", "0")).await;
    let q = t.sdk.op().quote(p, path).await.unwrap();
    assert_eq!(q.tx_nonce, 1, "the endpoints still answer 0");
}

/// Closing review P3: the prepared table drops what is past its `validUntil` on the chain's clock (it no longer grows without
/// bound); a live one stays (the control).
#[tokio::test(flavor = "multi_thread")]
async fn the_prepared_table_drops_expired_entries() {
    let t = setup(1, |_, _| {}).await;
    let old = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
    t.chain.lock().unwrap().timestamp += 7200; // past the first's validUntil
    let live = prepare(&t, cancel(&t, "token", TOKEN, "6", "0")).await;
    let table = t.sdk.prepared.lock().unwrap();
    assert!(!table.contains_key(&old.id()), "expired: dropped");
    assert!(table.contains_key(&live.id()), "control: kept");
}

/// Owner 2026-11-19, T13b ruling 1: an operation's `validUntil` is held to the SDK's clock (a fixed one here): one already past,
/// or further ahead than the chain's window (the profile's, else the limits' default), is `ValidUntilRefused`, so an
/// endpoint whose clock runs ahead cannot stretch a signature's life; inside the window it prepares (the controls).
#[tokio::test(flavor = "multi_thread")]
async fn valid_until_is_held_to_the_sdk_clock() {
    const NOW: u64 = 1_800_000_000; // the tests' fixed clock
    let until = |t: &T, v: u64| {
        let mut d = cancel(t, "token", TOKEN, "5", "0");
        d.message["validUntil"] = json!(v.to_string());
        d
    };
    let t = setup(1, |_, _| {}).await;
    assert_eq!(
        code(Op::prepare(&t.sdk, until(&t, NOW)).await),
        "ValidUntilRefused",
        "already past"
    );
    assert_eq!(
        code(Op::prepare(&t.sdk, until(&t, NOW + 86_401)).await),
        "ValidUntilRefused",
        "beyond the default day"
    );
    assert_eq!(
        code(Op::prepare(&t.sdk, until(&t, NOW + 86_400)).await),
        "Ok",
        "control: the day's edge"
    );
    // an endpoint a month ahead: its own `now` would let a month-long validUntil through; the SDK's clock does not
    t.chain.lock().unwrap().timestamp = NOW + 30 * 86_400;
    assert_eq!(
        code(Op::prepare(&t.sdk, until(&t, NOW + 30 * 86_400 + 60)).await),
        "ValidUntilRefused"
    );
    // the profile's own window
    let t2 = setup(1, |p, _| p.max_valid_secs = Some(600)).await;
    assert_eq!(
        code(Op::prepare(&t2.sdk, until(&t2, NOW + 601)).await),
        "ValidUntilRefused",
        "the profile's window"
    );
    assert_eq!(
        code(Op::prepare(&t2.sdk, until(&t2, NOW + 600)).await),
        "Ok",
        "control"
    );
}

/// Owner 2026-11-19, T13b ruling 2: a terminal row is kept `state_retention_secs` (90 days by default) after it ended, then
/// pruned by the next write; a non-terminal row is never pruned, however old (the control beside it).
#[tokio::test(flavor = "multi_thread")]
async fn terminal_rows_pruned_after_retention() {
    let t = setup(1, |_, _| {}).await;
    let (ended, digest) = submitted(&t, "token", TOKEN, "5").await;
    let (open_op, _) = submitted(&t, "token", TOKEN, "6").await;
    {
        let mut c = t.chain.lock().unwrap();
        let n = c.finalized;
        c.logs.push(executed_log(TOKEN, &digest, n, false));
    }
    assert!(t.sdk.op().state(ended.clone()).await.unwrap().is_terminal());
    assert_eq!(
        state::row(&t.sdk, &ended).await.unwrap().ended_at,
        Some(1_800_000_000)
    );
    // 90 days less a second later: kept; 90 days later: pruned at the next write; the open row stays
    let day = 86_400;
    let soon = open_at(
        t.store.clone(),
        t.profile.clone(),
        Limits::default(),
        1_800_000_000 + 90 * day - 1,
    )
    .await;
    state::put(&soon, &state::row(&soon, &open_op).await.unwrap())
        .await
        .unwrap();
    assert!(
        state::row(&soon, &ended).await.is_ok(),
        "control: inside the retention"
    );
    let late = open_at(
        t.store.clone(),
        t.profile.clone(),
        Limits::default(),
        1_800_000_000 + 90 * day,
    )
    .await;
    state::put(&late, &state::row(&late, &open_op).await.unwrap())
        .await
        .unwrap();
    assert!(state::row(&late, &ended).await.is_err(), "pruned");
    let much_later = open_at(
        t.store.clone(),
        t.profile.clone(),
        Limits::default(),
        1_800_000_000 + 900 * day,
    )
    .await;
    state::put(
        &much_later,
        &state::row(&much_later, &open_op).await.unwrap(),
    )
    .await
    .unwrap();
    assert!(
        state::row(&much_later, &open_op).await.is_ok(),
        "a non-terminal row is never pruned"
    );
}

/// Owner 2026-11-19, T13b ruling 7: a retry on the lane of an operation whose `validUntil` lapsed is that operation until a chain
/// fact makes it `Expired`; then the retry signs on the same lane (a new operation).
#[tokio::test(flavor = "multi_thread")]
async fn retry_on_a_lane_waits_for_expired() {
    let t = setup(1, |_, _| {}).await;
    let (first, _) = submitted(&t, "token", TOKEN, "5").await;
    let retry = |t: &T| {
        let mut d = cancel(t, "token", TOKEN, "5", "0");
        d.message["validUntil"] = json!("1800007200");
        d
    };
    let p = prepare(&t, retry(&t)).await;
    let q = gateway_quote(&t, &p).await;
    assert_eq!(
        t.sdk.op().submit(p, q).await.unwrap(),
        first,
        "the earlier operation, not yet Expired"
    );
    assert_eq!(signs(&t), 1, "nothing signed again");
    // the chain passes the first's validUntil with its nonce unspent: Expired by a chain fact; the retry signs on the lane
    t.chain.lock().unwrap().timestamp += 3_601;
    let p = prepare(&t, retry(&t)).await;
    let q = gateway_quote(&t, &p).await;
    let second = t.sdk.op().submit(p, q).await.unwrap();
    assert_ne!(second, first);
    assert_eq!(t.sdk.op().state(first).await.unwrap(), OpState::Expired);
    assert_eq!(signs(&t), 2);
}

/// Owner 2026-11-19, G3: after signing and before anything is written, a self-relay's gas is recomputed from the signed
/// calldata: the signature's bytes beyond what the quote counted (the verify row's `sig_bytes`) at 64 gas a byte with the
/// margin, never below the quote's figure; the transaction is signed with it. Above `Limits::max_gas`: `SignedGasAboveCap`,
/// nothing written or sent, the operation still submittable (control: at the cap it is sent).
#[tokio::test(flavor = "multi_thread")]
async fn signed_gas_is_recomputed_from_the_signature() {
    // the tests' UA (0x0101, P-256) signs 128 bytes of key data and signature beyond the empty `UASig`
    let (mut sent_with, mut quoted) = (vec![], vec![]);
    for sig_bytes in [0u64, 100, 128, 1_000] {
        let t = setup(0, |p, _| {
            for v in p.gas.verify.iter_mut() {
                v.sig_bytes = sig_bytes;
            }
        })
        .await;
        let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
        let q = t
            .sdk
            .op()
            .quote(p.clone(), SubmitPath::SelfRelay { payer: payer(&t) })
            .await
            .unwrap();
        let unsigned = submit::unsigned(&p).unwrap().calldata.len() as u64;
        let op = t.sdk.op().submit(p, q.clone()).await.unwrap();
        let row = state::row(&t.sdk, &op).await.unwrap();
        let signed = unhex(&row.calldata).unwrap().len() as u64;
        assert_eq!(signed - unsigned, 128, "P-256: key data and signature");
        let more = 128u64.saturating_sub(sig_bytes);
        assert_eq!(
            row.gas_limit,
            Some(q.gas_limit + gas::with_margin(64 * more)),
            "sig_bytes {sig_bytes}: raised by the uncounted bytes only, never lowered"
        );
        sent_with.push(row.gas_limit.unwrap() - q.gas_limit);
        quoted.push(q.gas_limit);
    }
    assert_eq!(sent_with, [12_288, 2_688, 0, 0]);
    // above the cap: refused by name, nothing written or sent, the operation put back; control: at the cap it is sent
    for (over, max) in [(true, quoted[0] + 12_288 - 1), (false, quoted[0] + 12_288)] {
        let t = setup(0, |_, l| l.max_gas = max).await;
        let p = prepare(&t, cancel(&t, "token", TOKEN, "5", "0")).await;
        let q = t
            .sdk
            .op()
            .quote(p.clone(), SubmitPath::SelfRelay { payer: payer(&t) })
            .await
            .unwrap();
        assert_eq!(q.gas_limit, quoted[0], "the same quote");
        let got = t.sdk.op().submit(p.clone(), q.clone()).await;
        if over {
            assert_eq!(code(got), "SignedGasAboveCap");
            assert!(
                state::rows(&t.sdk).await.unwrap().is_empty(),
                "nothing written"
            );
            assert!(t.chain.lock().unwrap().sent.is_empty(), "nothing sent");
            Op::known(&t.sdk, &p).expect("put back");
        } else {
            got.unwrap();
            sent_txs(&t, 1).await;
        }
    }
}

/// Owner 2026-11-19, Q5: `resend` of a gateway operation as a self-relay recomputes its gas from the row's stored signed
/// calldata, as `submit` does (G3): the P-256 verify row counts 100 signature bytes (every other kind's 0, so a wrong signer
/// kind counts differently), so the signer's 128 bytes add `with_margin(64 × 28)` to the payer's quote, never below it, and
/// the transaction is signed with it. Above
/// `Limits::max_gas`: `SignedGasAboveCap`, the row unchanged and nothing sent (control: at the cap it is sent).
#[tokio::test(flavor = "multi_thread")]
async fn resend_as_self_relay_recomputes_the_signed_gas() {
    let mut quoted = 0;
    for (max, want) in [
        (None, "Ok"),
        (Some(-1), "SignedGasAboveCap"),
        (Some(0), "Ok"),
    ] {
        let more = gas::with_margin(64 * 28);
        let t = setup(1, |p, l| {
            for v in p.gas.verify.iter_mut().filter(|v| v.signer == 0x0101) {
                v.sig_bytes = 100;
            }
            if let Some(d) = max {
                l.max_gas = (quoted + more as i64 + d) as u64;
            }
        })
        .await;
        let p = prepare(&t, cancel(&t, "token", TOKEN, "6", "0")).await;
        let q = gateway_quote(&t, &p).await;
        let op = t.sdk.op().submit(p.clone(), q).await.unwrap();
        let before = state::row(&t.sdk, &op).await.unwrap();
        assert_eq!(before.path, "gateway");
        // the payer's quote of an operation of the same shape (the submitted one is taken)
        let p2 = prepare(&t, cancel(&t, "token", TOKEN, "7", "0")).await;
        let q2 = t
            .sdk
            .op()
            .quote(p2.clone(), SubmitPath::SelfRelay { payer: payer(&t) })
            .await
            .unwrap();
        assert_eq!(
            submit::unsigned(&p).unwrap().calldata.len(),
            submit::unsigned(&p2).unwrap().calldata.len()
        );
        quoted = q2.gas_limit as i64;
        assert_eq!(code(t.sdk.op().resend(op.clone(), q2.clone()).await), want);
        let row = state::row(&t.sdk, &op).await.unwrap();
        if want == "Ok" {
            assert_eq!(row.path, "self");
            assert_eq!(
                row.gas_limit,
                Some(q2.gas_limit + more),
                "raised, never below the quote"
            );
            sent_txs(&t, 1).await;
        } else {
            assert_eq!(
                (row.path, row.raw, row.gas_limit),
                ("gateway".into(), None, None)
            );
            assert!(t.chain.lock().unwrap().sent.is_empty(), "nothing sent");
        }
    }
}

// --- bls12381-multi (0x0121), plan Task 17 (spec 2026-11-19-bls12381-multi §5.4, §8.4) ---

const REGISTRY: &str = "0x5ca00000000000000000000000000000000000c3";

/// A group of the seed's member keys `ua_key(0x0121, a, 0)` for the accounts `accounts`, unit weights, threshold `t`: its key
/// data (`0x` hex) and each account's index in it.
fn bls_group(accounts: &[u32], t: u16) -> (String, Vec<u8>) {
    let w = Wallet::from_mnemonic(REPO, "").unwrap();
    let keys: Vec<[u8; 256]> = accounts
        .iter()
        .map(|a| {
            w.ua_key(0x0121, *a, 0)
                .unwrap()
                .key_data()
                .try_into()
                .unwrap()
        })
        .collect();
    let (d, map) = scaas_ua::bls_multi::build_key_data_unweighted(&keys, t).unwrap();
    (hex(&d), map.iter().map(|i| *i as u8).collect())
}

fn bls_member(t: &T, key_data: &str, account: u32) -> KeyRef {
    KeyRef::BlsMulti {
        seed: t.seed.clone(),
        account,
        index: 0,
        key_data: key_data.into(),
    }
}

/// A `UACancelNonce` from the group's UA, signed by the group (member 0 coordinating).
async fn bls_prepared(t: &T, key_data: &str) -> Arc<Prepared> {
    let mut d = cancel(t, "token", TOKEN, "5", "0");
    d.signer = bls_member(t, key_data, 0);
    d.message["from"] = json!(hex(&bls_multi::ua(&d.signer).unwrap()));
    prepare(t, d).await
}

/// The named `UASig` objects of a job body (`signers` beside `signature`).
fn named_sigs(v: &Value, out: &mut Vec<Value>) {
    match v {
        Value::Object(o) if o.contains_key("signers") => out.push(v.clone()),
        Value::Object(o) => o.values().for_each(|x| named_sigs(x, out)),
        Value::Array(a) => a.iter().for_each(|x| named_sigs(x, out)),
        _ => {}
    }
}

/// Plan Task 17: each member signs its partial of the prepared group operation (its `from` the group's UA); the coordinator
/// aggregates and submits; the gateway's job carries the `UASig` by name, `{signature: σ (128 B), signers}`, never the
/// 160-byte object, and that aggregate verifies on the operation's `ua_msg`. A key the group does not list, or a member of
/// another group, signs nothing.
#[tokio::test(flavor = "multi_thread")]
async fn bls_multi_sign_collect_aggregate_submit() {
    let t = setup(1, |_, _| {}).await;
    let (d, _) = bls_group(&[0, 1, 2], 2);
    let p = bls_prepared(&t, &d).await;
    let op = t.sdk.op();
    let mut parts = vec![];
    for a in [0, 1, 2] {
        let part = op
            .bls_multi_part(p.clone(), bls_member(&t, &d, a))
            .await
            .unwrap();
        assert!(op.bls_multi_part_ok(&p, &part), "member {a}'s partial");
        parts.push(part);
    }
    assert_eq!(
        code(op.bls_multi_part(p.clone(), bls_member(&t, &d, 5)).await),
        "Argument",
        "a key the group does not list"
    );
    let (d2, _) = bls_group(&[0, 3], 2);
    assert_eq!(
        code(op.bls_multi_part(p.clone(), bls_member(&t, &d2, 0)).await),
        "Argument",
        "a member key of another group"
    );
    let q = gateway_quote(&t, &p).await;
    op.submit_bls_multi(p.clone(), q, parts, false)
        .await
        .unwrap();
    let body = bodies(&t, 1).await.remove(0);
    let ua_msg = scaas_ua::wallet::scaas_bls_multi_message(&p.t.td).unwrap();
    let mut named = vec![];
    named_sigs(&serde_json::from_str(&body).unwrap(), &mut named);
    assert_eq!(named.len(), 1, "{body}");
    let s = &named[0];
    assert_eq!(
        s.as_object().unwrap().len(),
        2,
        "signature and signers only"
    );
    let sigma = unhex(s["signature"].as_str().unwrap()).unwrap();
    assert_eq!(sigma.len(), 128);
    let signers: Vec<u8> = s["signers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i.as_u64().unwrap() as u8)
        .collect();
    assert_eq!(signers.len(), 2, "a minimal set: t = 2 of three");
    let abi = scaas_ua::bls_multi::BlsMultiSig {
        signature: sigma.clone().try_into().unwrap(),
        signers,
        dropped: vec![],
    }
    .to_abi();
    assert!(!body.contains(&hex(&abi)[2..]), "never the 160-byte object");
    let d = unhex(&d).unwrap();
    assert!(scaas_ua::verify::verify(
        0x0121, &d, &ua_msg, &abi, false, true
    ));
}

/// N6, the stored paths (spec §5.3): the aggregate is minimal by default, every signer necessary (it verifies in the minimal
/// form); surplus only when asked (it verifies on the hot path only). The signer kind is 0x0121 and its quote counts the
/// group's n.
#[tokio::test(flavor = "multi_thread")]
async fn bls_multi_stored_path_minimal() {
    let t = setup(1, |_, _| {}).await;
    let (d, _) = bls_group(&[0, 1, 2, 3], 2);
    let p = bls_prepared(&t, &d).await;
    assert_eq!(quote::signer_kind(&p), 0x0121);
    assert_eq!(bls_multi::members(&p.signer()), Some(4));
    let op = t.sdk.op();
    let mut parts = vec![];
    for a in 0..4 {
        parts.push(
            op.bls_multi_part(p.clone(), bls_member(&t, &d, a))
                .await
                .unwrap(),
        );
    }
    let ua_msg = scaas_ua::wallet::scaas_bls_multi_message(&p.t.td).unwrap();
    let kd = unhex(&d).unwrap();
    let sig_of = |surplus: bool| {
        let b = bls_multi::sign(&p, &parts, surplus).unwrap();
        let mut named = vec![];
        named_sigs(b.op.as_ref().unwrap(), &mut named);
        let s = &named[0];
        let sig = scaas_ua::bls_multi::BlsMultiSig {
            signature: unhex(s["signature"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            signers: s["signers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i.as_u64().unwrap() as u8)
                .collect(),
            dropped: vec![],
        };
        assert!(
            b.calldata.windows(160).any(|w| w == sig.to_abi()),
            "the calldata carries σ ‖ bitmap"
        );
        sig
    };
    let min = sig_of(false);
    assert_eq!(min.signers.len(), 2);
    assert!(
        scaas_ua::verify::verify(0x0121, &kd, &ua_msg, &min.to_abi(), false, true),
        "minimal"
    );
    let all = sig_of(true);
    assert_eq!(all.signers, vec![0, 1, 2, 3]);
    assert!(
        scaas_ua::verify::verify(0x0121, &kd, &ua_msg, &all.to_abi(), false, false),
        "hot path"
    );
    assert!(
        !scaas_ua::verify::verify(0x0121, &kd, &ua_msg, &all.to_abi(), false, true),
        "a surplus set is not the stored form"
    );
    // plain `submit` never signs for a group
    let q = gateway_quote(&t, &p).await;
    assert_eq!(code(op.submit(p.clone(), q).await), "Argument");
    // the quote counts the group's n: signer 289's verify row `gas + per_item × 4`
    let t = setup(0, |p, _| {
        p.gas.verify.push(crate::GasVerify {
            signer: 0x0121,
            gas: 0,
            sig_bytes: 0,
            margin: 0,
            per_item: Some(crate::GasPerItem {
                item: "members".into(),
                gas: 1_000,
            }),
        })
    })
    .await;
    let p = bls_prepared(&t, &d).await;
    let len = submit::unsigned(&p).unwrap().calldata.len() as u64;
    let q = t
        .sdk
        .op()
        .quote(p, SubmitPath::SelfRelay { payer: payer(&t) })
        .await
        .unwrap();
    assert_eq!(
        q.gas_limit,
        gas::with_margin(100_000 + 1_000 * 4 + 21_000 + 64 * len)
    );
}

/// Spec §5.4: a bad partial is named by the coordinator's check and dropped from the aggregate while t of weight remain; below
/// t `BlsMultiBelowThreshold`, nothing sent and the prepared operation kept. A partial over another operation is bad.
#[tokio::test(flavor = "multi_thread")]
async fn bls_multi_bad_partial_named() {
    let t = setup(1, |_, _| {}).await;
    let (d, _) = bls_group(&[0, 1, 2], 2);
    let p = bls_prepared(&t, &d).await;
    let op = t.sdk.op();
    let good: Vec<_> = {
        let mut v = vec![];
        for a in 0..3 {
            v.push(
                op.bls_multi_part(p.clone(), bls_member(&t, &d, a))
                    .await
                    .unwrap(),
            );
        }
        v
    };
    // member 1's partial over another operation (another lane)
    let mut other = cancel(&t, "token", TOKEN, "6", "0");
    other.signer = bls_member(&t, &d, 0);
    other.message["from"] = json!(hex(&bls_multi::ua(&other.signer).unwrap()));
    let p2 = prepare(&t, other).await;
    let bad = op.bls_multi_part(p2, bls_member(&t, &d, 1)).await.unwrap();
    assert_eq!(bad.index, good[1].index);
    assert!(
        !op.bls_multi_part_ok(&p, &bad),
        "named: member {}",
        bad.index
    );
    let mut flipped = good[2].clone();
    let x = if &flipped.signature[200..202] == "00" {
        "01"
    } else {
        "00"
    };
    flipped.signature.replace_range(200..202, x); // a byte of σ_2's x coordinate
    assert!(!op.bls_multi_part_ok(&p, &flipped));
    // dropped while t remain: the signers are the two good ones
    let b = bls_multi::sign(&p, &[good[0].clone(), bad.clone(), good[2].clone()], false).unwrap();
    let mut named = vec![];
    named_sigs(b.op.as_ref().unwrap(), &mut named);
    let mut want = vec![good[0].index, good[2].index];
    want.sort_unstable();
    assert_eq!(named[0]["signers"], json!(want));
    // below t: refused, nothing sent, the prepared operation kept
    let q = gateway_quote(&t, &p).await;
    assert_eq!(
        code(
            op.submit_bls_multi(p.clone(), q.clone(), vec![good[0].clone(), bad], false)
                .await
        ),
        "BlsMultiBelowThreshold"
    );
    assert!(t.chain.lock().unwrap().bodies.is_empty(), "nothing sent");
    assert_eq!(
        code(
            op.submit_bls_multi(
                p.clone(),
                q.clone(),
                vec![good[0].clone(), good[0].clone()],
                false
            )
            .await
        ),
        "Argument",
        "an index twice"
    );
    op.submit_bls_multi(p, q, good, false).await.unwrap();
}

/// Spec §8.4, plan Task 17: the registration's self-relay quote is the reference row's `gas + per_item × n` (regular and
/// state gas, no verify part), the intrinsic cost and the calldata, with the margin; it grows with n; a group of 64 members is
/// above a 2^24 per-transaction cap (the quote counts the state gas); no registry, no row: refused.
#[tokio::test(flavor = "multi_thread")]
async fn bls_multi_register_quote_by_n() {
    let t = setup(0, |p, _| {
        p.registry = Some(REGISTRY.into());
        p.gas_opt_in = vec![gas::REFERENCE.into()];
    })
    .await;
    let op = t.sdk.op();
    let reference = crate::GasTable::parse(gas::REFERENCE_FILE).unwrap();
    let row = reference
        .rows
        .base
        .iter()
        .find(|b| b.key() == ("registerBlsMulti", "account", true))
        .unwrap();
    let mut last = 0;
    for n in [2u32, 3, 5] {
        let (d, _) = bls_group(&(0..n).collect::<Vec<_>>(), 2);
        let q = op
            .quote_register_bls_multi("local".into(), d.clone(), payer(&t))
            .await
            .unwrap();
        let len = bls_multi::register_calldata(&unhex(&d).unwrap(), &[0; 128])
            .unwrap()
            .len() as u64;
        let g = row.gas + row.per_item.as_ref().unwrap().gas * u64::from(n);
        assert_eq!(
            q.gas_limit,
            gas::with_margin(g + 21_000 + 64 * len),
            "n {n}"
        );
        assert_eq!(q.gas_from, Some(GasSources::both(GasFrom::Reference)));
        assert!(q.gas_limit > last, "grows with n");
        last = q.gas_limit;
    }
    let (d64, _) = bls_group(&(0..64).collect::<Vec<_>>(), 32);
    assert_eq!(
        code(
            op.quote_register_bls_multi("local".into(), d64, payer(&t))
                .await
        ),
        "GasAboveTxCap"
    );
    let (d, _) = bls_group(&[0, 1], 2);
    let none = setup(0, |p, _| p.gas_opt_in = vec![gas::REFERENCE.into()]).await;
    assert_eq!(
        code(
            none.sdk
                .op()
                .quote_register_bls_multi("local".into(), d.clone(), payer(&none))
                .await
        ),
        "Argument",
        "no registry"
    );
    let unrowed = setup(0, |p, _| p.registry = Some(REGISTRY.into())).await;
    assert_eq!(
        code(
            unrowed
                .sdk
                .op()
                .quote_register_bls_multi("local".into(), d, payer(&unrowed))
                .await
        ),
        "GasUnquoted",
        "no row"
    );
}

/// Spec §4, plan Task 17: every member's PoP part (each checked), aggregated into the registration's `pop`, sent as
/// `registerBlsMulti` by the payer; a missing or bad part is `RegistrationPopInvalid`, nothing sent; the calldata decodes to
/// the vectors' named arguments (portable.json `blsMultiRegistrations`).
#[tokio::test(flavor = "multi_thread")]
async fn bls_multi_register_sends_the_pop() {
    use alloy::sol_types::SolCall;
    let t = setup(0, |p, _| {
        p.registry = Some(REGISTRY.into());
        p.gas_opt_in = vec![gas::REFERENCE.into()];
    })
    .await;
    let op = t.sdk.op();
    let (d, _) = bls_group(&[0, 1, 2], 2);
    let parts: Vec<_> = (0..3)
        .map(|a| op.bls_multi_pop_part(bls_member(&t, &d, a)).unwrap())
        .collect();
    assert!(parts.iter().all(|p| op.bls_multi_pop_part_ok(&d, p)));
    let (d2, _) = bls_group(&[0, 1, 3], 2);
    let foreign = op.bls_multi_pop_part(bls_member(&t, &d2, 1)).unwrap();
    assert!(
        !op.bls_multi_pop_part_ok(&d, &foreign),
        "a part for another group"
    );
    let q = op
        .quote_register_bls_multi("local".into(), d.clone(), payer(&t))
        .await
        .unwrap();
    assert_eq!(
        code(
            op.register_bls_multi("local".into(), d.clone(), parts[..2].to_vec(), q.clone())
                .await
        ),
        "RegistrationPopInvalid",
        "a member missing"
    );
    let mut swapped = parts.clone();
    swapped[1].signature = foreign.signature.clone();
    assert_eq!(
        code(
            op.register_bls_multi("local".into(), d.clone(), swapped, q.clone())
                .await
        ),
        "RegistrationPopInvalid",
        "a bad part"
    );
    assert!(t.chain.lock().unwrap().sent.is_empty(), "nothing sent");
    // the simulation needs more than the quote (G3's rule): its gas with the margin, here above `Limits::max_gas`
    let quoted = t.chain.lock().unwrap().gas;
    t.chain.lock().unwrap().gas = 1 << 24;
    assert_eq!(
        code(
            op.register_bls_multi("local".into(), d.clone(), parts.clone(), q.clone())
                .await
        ),
        "SignedGasAboveCap"
    );
    t.chain.lock().unwrap().gas = quoted;
    op.register_bls_multi("local".into(), d.clone(), parts.clone(), q)
        .await
        .unwrap();
    let raw = sent_txs(&t, 1).await.remove(0);
    let kd = unhex(&d).unwrap();
    let pop = scaas_ua::bls_multi::aggregate_pop(
        &kd,
        &parts
            .iter()
            .map(|p| (p.index, unhex(&p.signature).unwrap().try_into().unwrap()))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let cd = bls_multi::register_calldata(&kd, &pop).unwrap();
    assert!(
        raw.contains(&hex(&cd)[2..]),
        "the registration's calldata sent"
    );
    // the vectors' rows: the calldata of their key data and pop decodes to their named arguments
    let v: Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/../../smartcontracts/vectors/ua/portable.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    for r in v["blsMultiRegistrations"].as_array().unwrap() {
        let h = |x: &Value| unhex(x.as_str().unwrap()).unwrap();
        let cd = bls_multi::register_calldata(&h(&r["keyData"]), &h(&r["pop"])).unwrap();
        let c = bls_multi::registerBlsMultiCall::abi_decode(&cd).unwrap();
        let a = &r["args"];
        assert_eq!(
            c.key.aggKey.to_vec(),
            h(&a["key"]["aggKey"]),
            "{}",
            r["name"]
        );
        assert_eq!(
            u64::from(c.key.threshold),
            a["key"]["threshold"].as_u64().unwrap()
        );
        let m = a["key"]["members"].as_array().unwrap();
        assert_eq!(c.key.members.len(), m.len());
        for (x, y) in c.key.members.iter().zip(m) {
            assert_eq!(x.key.to_vec(), h(&y["key"]));
            assert_eq!(u64::from(x.weight), y["weight"].as_u64().unwrap());
        }
        assert_eq!(c.pop.to_vec(), h(&a["pop"]));
        assert!(c.pqzPop.is_empty() && c.attrs.pqzKey.is_empty() && c.attrs.kem.mlkemEk.is_empty());
    }
}
