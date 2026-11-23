// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T11: `wallet` profiles' checks, tokens, balances, the EVM native send (spec §8), against the fake chain and gateway of
//! `tests/common/fake_chain.rs` (local only) and, ignored, `anvil`. Every refusal beside its control.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "common/fake_chain.rs"]
mod fake_chain;

use fake_chain::{fake, hash_of, serve, Fake, CHAIN_ID};
use scaas_sdk::op::{KeyRef, OpState, SubmitPath};
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::wallet::NativeSend;
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, ListedToken, RuntimeChoice, Sdk,
    SdkConfig, SdkError,
};
use scaas_ua::wallet::{Network, SecretBytes, Wallet};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const VND: &str = "0x5ca00000000000000000000000000000000000a1";
const USD: &str = "0x5ca00000000000000000000000000000000000a2";
const ODD: &str = "0x5ca00000000000000000000000000000000000a3";
const FACTORY: &str = "0x5ca00000000000000000000000000000000000f0";
const TO: &str = "0x00000000000000000000000000000000000000aa";

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

fn endpoint(url: &str) -> EndpointConfig {
    EndpointConfig {
        url: url.into(),
        class: scaas_rpc::Class::Named,
        label: None,
        auth: None,
    }
}

fn profile(rpc: Vec<String>, gateways: Vec<String>, uid: &str) -> ChainProfile {
    ChainProfile {
        key: "local".into(),
        family: Family::Evm,
        chain_id: Some(CHAIN_ID),
        chain_uid: uid.into(),
        rpc: rpc.iter().map(|u| endpoint(u)).collect(),
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: gateways.iter().map(|u| endpoint(u)).collect(),
        registry: None,
        factory: Some(FACTORY.into()),
        router: None,
        finality: Finality::Finalized,
        tx_gas_cap: Some(1 << 24),
        gas: Default::default(),
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![],
        wrappers: vec![],
        tokens: vec![
            ListedToken {
                address: VND.into(),
                symbol: "VND".into(),
                decimals: 0,
            },
            ListedToken {
                address: USD.into(),
                symbol: "USD".into(),
                decimals: 6,
            },
        ],
        l1_fee: None,
        pinned_reads: true,
        disabled_kinds: vec![],
        family_params: None,
    }
}

fn tokens(c: &Fake) {
    let mut c = c.lock().unwrap();
    for (a, n, s, d) in [
        (VND, "Dong", "VND", 0u8),
        (USD, "Dollar", "USD", 6),
        (ODD, "Odd\u{202e}dsu\u{200b} token", "U\u{202e}SD\u{7}", 18),
    ] {
        c.tokens
            .insert(a.into(), (n.into(), s.into(), d, hash_of(0)));
    }
    c.balances.insert(VND.into(), 1_000);
    c.balances.insert(USD.into(), 5_000_000);
    c.native_balance = 10u64.pow(18);
}

async fn sdk(p: ChainProfile) -> (Arc<Sdk>, String) {
    let s = Sdk::open(SdkConfig {
        profiles: vec![p],
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
    let sec = |t: &str| {
        Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(t.as_bytes().to_vec())).unwrap())
    };
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
    (s, seed)
}

async fn one(gateways: usize) -> (Arc<Sdk>, String, Fake) {
    let c = fake();
    tokens(&c);
    let url = serve(c.clone()).await;
    let mut gws = vec![];
    for _ in 0..gateways {
        gws.push(serve(c.clone()).await);
    }
    let (s, seed) = sdk(profile(vec![url], gws, &hash_of(0))).await;
    (s, seed, c)
}

fn evm_key(seed: &str) -> KeyRef {
    KeyRef::Native {
        seed: seed.into(),
        network: "evm".into(),
        index: 0,
    }
}

fn native_send(seed: &str, tx_type: Option<u8>) -> NativeSend {
    NativeSend {
        key: evm_key(seed),
        chain: "local".into(),
        to: TO.into(),
        value: "1000".into(),
        data: None,
        tx_type,
    }
}

fn address() -> String {
    let w = Wallet::from_mnemonic(REPO, "").unwrap();
    w.native_key(Network::Evm, 0, None)
        .unwrap()
        .address()
        .unwrap()
        .to_ascii_lowercase()
}

#[tokio::test(flavor = "multi_thread")]
async fn token_chain_uid_mismatch_is_refused() {
    let (s, _, c) = one(0).await;
    let t = s.wallet().tokens("local".into(), false).await.unwrap();
    assert_eq!(t.len(), 2, "control: the listed tokens");
    assert!(t.iter().all(|t| t.listed));
    let (s, _, c2) = one(0).await;
    c2.lock().unwrap().tokens.get_mut(USD).unwrap().3 = format!("0x{}", "61".repeat(32));
    assert_eq!(
        code(s.wallet().tokens("local".into(), false).await),
        "ProfileMismatch"
    );
    drop(c);
}

#[tokio::test(flavor = "multi_thread")]
async fn factory_index_token_off_list_is_unlisted() {
    let (s, _, c) = one(0).await;
    c.lock().unwrap().index = vec![VND.into(), ODD.into()];
    let t = s.wallet().tokens("local".into(), true).await.unwrap();
    assert_eq!(t.len(), 3);
    let odd = t.iter().find(|t| t.address == ODD).unwrap();
    assert!(!odd.listed, "an index token off the list");
    assert!(
        t.iter().filter(|t| t.address != ODD).all(|t| t.listed),
        "control: the listed ones"
    );
}

/// T26 B2-14: an index entry whose metadata does not read (an unregistered implementation's `name()` that answers nothing,
/// CTR-TOK-27's `createTokenUnregistered`) is listed as `[unreadable]`, never ending the whole list (a listed token that does
/// not read still fails the call). Control: the readable entries as before.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_index_token_is_marked() {
    const JUNK: &str = "0x5ca00000000000000000000000000000000000a9";
    let (s, _, c) = one(0).await;
    c.lock().unwrap().index = vec![VND.into(), JUNK.into(), ODD.into()];
    let t = s.wallet().tokens("local".into(), true).await.unwrap();
    assert_eq!(t.len(), 4);
    let junk = t.iter().find(|t| t.address == JUNK).unwrap();
    assert_eq!(
        (junk.listed, junk.display.as_str()),
        (false, "[unreadable]")
    );
    let odd = t.iter().find(|t| t.address == ODD).unwrap();
    assert_eq!(
        odd.display, "[unlisted] USD",
        "control: a readable index token"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unlisted_name_is_sanitised() {
    let (s, _, c) = one(0).await;
    let long = "x".repeat(70) + "é";
    c.lock()
        .unwrap()
        .tokens
        .insert(USD.into(), (long.clone(), "USD".into(), 6, hash_of(0)));
    c.lock().unwrap().index = vec![ODD.into()];
    let t = s.wallet().tokens("local".into(), true).await.unwrap();
    let odd = t.iter().find(|t| t.address == ODD).unwrap();
    assert_eq!(odd.symbol, "USD", "control and bidi characters stripped");
    assert_eq!(odd.name, "Odddsu token");
    assert_eq!(odd.display, "[unlisted] USD", "never without the mark");
    let usd = t.iter().find(|t| t.address == USD).unwrap();
    assert_eq!(
        usd.display, "USD",
        "control: a listed token shows its reviewed symbol"
    );
    assert_eq!(usd.name.len(), 64, "a name cut to 64 bytes");
}

#[tokio::test(flavor = "multi_thread")]
async fn balances_at_one_block() {
    let (s, _, _c) = one(0).await;
    let b = s
        .wallet()
        .balances(address(), "local".into())
        .await
        .unwrap();
    // the fake answers base + the block read at: every value from one block
    assert_eq!(b.native, Some((10u64.pow(18) + b.block).to_string()));
    assert_eq!(b.tokens[0].amount, (1_000 + b.block).to_string());
    assert_eq!(b.tokens[1].amount, (5_000_000 + b.block).to_string());
    assert_eq!(b.block, 0x1f, "the default block, one below the head");
    let ua = format!("0x{}", "0b".repeat(32));
    let d = s.wallet().balances(ua, "local".into()).await.unwrap();
    assert_eq!(d.native, None, "a derived UA holds no native coin");
}

#[tokio::test(flavor = "multi_thread")]
async fn strict_majority_profile_reads_agree() {
    let (a, b, liar) = (fake(), fake(), fake());
    for c in [&a, &b, &liar] {
        tokens(c);
    }
    liar.lock().unwrap().balances.insert(VND.into(), 999_999);
    let urls = vec![
        serve(a.clone()).await,
        serve(liar.clone()).await,
        serve(b.clone()).await,
    ];
    let mut p = profile(urls, vec![], &hash_of(0));
    p.rpc_policy = scaas_rpc::Policy::StrictMajority;
    let (s, _) = sdk(p).await;
    let bal = s
        .wallet()
        .balances(address(), "local".into())
        .await
        .unwrap();
    assert_eq!(
        bal.tokens[0].amount,
        (1_000 + bal.block).to_string(),
        "the majority's value, not the liar's"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn zero_gas_price_is_a_value() {
    let (s, seed, c) = one(0).await;
    {
        let mut c = c.lock().unwrap();
        c.base_fee = 0;
        c.prio = 0;
        // a chain whose plain transfer costs more than Ethereum's 21,000 (an L1 part, an account's creation: T26 B2-1)
        c.gas = 30_000;
    }
    let q = s
        .wallet()
        .prepare_native_send(native_send(&seed, Some(2)))
        .await
        .unwrap();
    assert_eq!(
        q.quote.gas_limit, 30_000,
        "a plain transfer at the chain's estimate"
    );
    // the chain's own value (scaas-rpc's fee reader floors the fee at 1 wei); the SDK adds no floor or price of its own
    let max: u128 = q.quote.max_fee_per_gas.parse().unwrap();
    let prio: u128 = q.quote.max_priority_fee_per_gas.parse().unwrap();
    assert!(max <= 1 && prio <= max, "{max} {prio}");
    assert_eq!(
        q.quote.max_cost,
        (30_000u128 * q.quote.max_fee_per_gas.parse::<u128>().unwrap()).to_string()
    );
    // T26 B-16: `submit` checks the caller's record as `prepare` checked the request: data above 128 KiB is `Argument`
    let mut big = q.clone();
    big.data = format!("0x{}", "00".repeat(128 * 1024 + 1));
    assert!(matches!(
        s.wallet().submit_native_send(big).await,
        Err(SdkError::Argument)
    ));
    s.wallet().submit_native_send(q).await.unwrap();
    for _ in 0..100 {
        if !c.lock().unwrap().sent.is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("not sent");
}

/// The EIP-2718 type of the `n`-th raw transaction the fake got.
async fn sent_type(c: &Fake, n: usize) -> u8 {
    for _ in 0..100 {
        if let Some(raw) = c.lock().unwrap().sent.get(n) {
            let b = u8::from_str_radix(&raw[2..4], 16).unwrap();
            return if b >= 0xc0 { 0 } else { b };
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("transaction {n} not sent");
}

#[tokio::test(flavor = "multi_thread")]
async fn native_send_types() {
    // owner 2026-11-18, ruling 3: 0, 1, 2 sent as asked; 3 (blob) and 4 (EIP-7702) refused before any read
    let (s, seed, c) = one(0).await;
    let reads = c.lock().unwrap().requests.len();
    for t in [4u8, 3, 5] {
        assert_eq!(
            code(
                s.wallet()
                    .prepare_native_send(native_send(&seed, Some(t)))
                    .await
            ),
            "TxTypeRefused",
            "type {t}"
        );
        assert_eq!(
            c.lock().unwrap().requests.len(),
            reads,
            "type {t} refused before any read"
        );
    }
    assert!(c.lock().unwrap().sent.is_empty());
    for (i, t) in [Some(0u8), Some(1), Some(2), None].into_iter().enumerate() {
        let q = s
            .wallet()
            .prepare_native_send(native_send(&seed, t))
            .await
            .unwrap();
        assert_eq!(q.from, address());
        s.wallet().submit_native_send(q).await.unwrap();
        assert_eq!(
            sent_type(&c, i).await,
            t.unwrap_or(2),
            "{t:?}: sent as asked, 2 by default"
        );
    }
    // a chain without a base fee: type 0 by default, type 2 refused
    let (s, seed, c) = one(0).await;
    c.lock().unwrap().no_base_fee = true;
    assert_eq!(
        code(
            s.wallet()
                .prepare_native_send(native_send(&seed, Some(2)))
                .await
        ),
        "TxTypeRefused",
        "type 2 without a base fee"
    );
    let q = s
        .wallet()
        .prepare_native_send(native_send(&seed, None))
        .await
        .unwrap();
    assert_eq!(q.quote.tx_type, 0, "no base fee: legacy");
    s.wallet().submit_native_send(q).await.unwrap();
    assert_eq!(sent_type(&c, 0).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn native_send_reverted_is_reverted() {
    // owner 2026-11-18, ruling 4: a native send final and reverted is `Reverted`; the control, final and successful, `Landed`
    let (s, seed, c) = one(0).await;
    let mut ops = vec![];
    for (i, ok) in [false, true].into_iter().enumerate() {
        let req = NativeSend {
            value: (1000 + i).to_string(), // two transactions, two ids (the fake's account nonce stays 0)
            ..native_send(&seed, None)
        };
        let q = s.wallet().prepare_native_send(req).await.unwrap();
        let op = s.wallet().submit_native_send(q).await.unwrap();
        sent_type(&c, i).await;
        let raw = c.lock().unwrap().sent[i].clone();
        let id = fake_chain::keccak_hex(&alloy::hex::decode(&raw[2..]).unwrap());
        c.lock().unwrap().receipts.insert(id, ok);
        ops.push(op);
    }
    let st = s.op().state(ops[0].clone()).await.unwrap();
    assert!(matches!(st, OpState::Reverted { .. }), "{st:?}");
    assert!(st.is_terminal());
    let st = s.op().state(ops[1].clone()).await.unwrap();
    assert!(matches!(st, OpState::Landed { .. }), "control: {st:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn delegated_sender_send_carries_the_mark() {
    // owner 2026-11-18, ruling 5: allowed, the review carries the delegation mark
    let (s, seed, c) = one(0).await;
    let q = s
        .wallet()
        .prepare_native_send(native_send(&seed, None))
        .await
        .unwrap();
    assert!(!q.delegated, "control: no code");
    c.lock()
        .unwrap()
        .code
        .insert(address(), format!("0xef0100{}", "33".repeat(20)));
    let q = s
        .wallet()
        .prepare_native_send(native_send(&seed, None))
        .await
        .unwrap();
    assert!(q.delegated, "the mark");
    s.wallet().submit_native_send(q).await.unwrap();
    sent_type(&c, 0).await;
}

// --- anvil (ignored: the `sdk-e2e` step's binary on PATH or `ANVIL`) ---

struct Anvil(std::process::Child, String);
impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn anvil() -> Anvil {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let bin = std::env::var("ANVIL").unwrap_or_else(|_| "anvil".into());
    let child = std::process::Command::new(bin)
        .args([
            "--port",
            &port.to_string(),
            "--chain-id",
            &CHAIN_ID.to_string(),
            "--silent",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("anvil (ANVIL or PATH)");
    // held from here: a panic below kills and waits for it (Drop)
    let a = Anvil(child, format!("http://127.0.0.1:{port}"));
    for _ in 0..200 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return a;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("anvil did not listen");
}

async fn rpc(url: &str, method: &str, params: serde_json::Value) -> serde_json::Value {
    let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        .to_string();
    let out = std::process::Command::new("curl")
        .args([
            "-s",
            "-H",
            "content-type: application/json",
            "--data-binary",
            &body,
            url,
        ])
        .output()
        .unwrap();
    serde_json::from_slice(&out.stdout).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "anvil: the sdk-e2e step"]
async fn native_send_quoted_and_lands() {
    let a = anvil();
    let genesis = rpc(
        &a.1,
        "eth_getBlockByNumber",
        serde_json::json!(["0x0", false]),
    )
    .await["result"]["hash"]
        .as_str()
        .unwrap()
        .to_string();
    rpc(
        &a.1,
        "anvil_setBalance",
        serde_json::json!([address(), "0xde0b6b3a7640000"]),
    )
    .await;
    let mut p = profile(vec![a.1.clone()], vec![], &genesis);
    p.tokens = vec![];
    p.finality = Finality::Depth(0);
    let (s, seed) = sdk(p).await;
    let q = s
        .wallet()
        .prepare_native_send(native_send(&seed, Some(2)))
        .await
        .unwrap();
    assert_eq!(q.quote.gas_limit, 21_000);
    let op = s.wallet().submit_native_send(q).await.unwrap();
    for _ in 0..100 {
        if let OpState::Landed { .. } = s.op().state(op.clone()).await.unwrap() {
            let bal = rpc(&a.1, "eth_getBalance", serde_json::json!([TO, "latest"])).await;
            assert_eq!(bal["result"], "0x3e8");
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the native send did not land");
}

/// Closing review P3: a native send signs with the reviewed key only: a quote whose payer is another key than the reviewed
/// `key` (an edited record) is `Argument`, nothing signed or sent; the quote as made is sent (the control).
#[tokio::test(flavor = "multi_thread")]
async fn native_send_signs_with_the_reviewed_key_only() {
    let (s, seed, c) = one(0).await;
    let q = s
        .wallet()
        .prepare_native_send(native_send(&seed, Some(2)))
        .await
        .unwrap();
    let mut other = q.clone();
    other.quote.path = SubmitPath::SelfRelay {
        payer: KeyRef::Native {
            seed: seed.clone(),
            network: "evm".into(),
            index: 1,
        },
    };
    assert_eq!(
        s.wallet()
            .submit_native_send(other)
            .await
            .unwrap_err()
            .code(),
        "Argument"
    );
    assert!(c.lock().unwrap().sent.is_empty());
    s.wallet().submit_native_send(q).await.unwrap();
}

/// Owner 2026-11-19, T13b ruling 5: a native send's estimate carries its value (`scaas-rpc` `simulate_value`): a value to a
/// non-payable contract is refused at quote time; the same call without a value quotes (the control).
#[tokio::test(flavor = "multi_thread")]
async fn native_send_estimate_carries_the_value() {
    let (s, seed, c) = one(0).await;
    {
        let mut c = c.lock().unwrap();
        c.value_reverts = true;
        c.code.insert(TO.to_ascii_lowercase(), "0x6001".into());
    }
    let mut req = native_send(&seed, Some(2));
    req.data = Some("0xdeadbeef".into());
    assert_eq!(
        s.wallet()
            .prepare_native_send(req.clone())
            .await
            .unwrap_err()
            .code(),
        "Revert"
    );
    req.value = "0".into();
    assert!(
        s.wallet().prepare_native_send(req).await.is_ok(),
        "control: no value"
    );
}
