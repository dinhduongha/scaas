// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T38 (spec §27.3, decisions CLI-SDK-33 (11)): on a profile with `l1_fee = OpStack` (Base, Celo, OP) the quote's
//! `max_cost` is `gas_limit × max fee per gas` + `GasPriceOracle.getL1Fee(unsigned)`, read at the quote's block (pinned by
//! hash); without the field no L1 read is made; an answer that is not a `uint256` is the endpoint's `AnswerMalformed`;
//! `FeeAboveCap` counts the L1 fee. Against the fake chain of `tests/common/fake_chain.rs`.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "common/fake_chain.rs"]
mod fake_chain;

use alloy::primitives::U256;
use fake_chain::{fake, hash_of, serve, Fake, CHAIN_ID};
use scaas_sdk::op::KeyRef;
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::wallet::NativeSend;
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, L1Fee, Limits, RuntimeChoice, Sdk, SdkConfig,
    SdkError,
};
use scaas_ua::wallet::{EvmTx, SecretBytes};
use serde_json::Value;
use std::sync::Arc;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const ORACLE: &str = "0x420000000000000000000000000000000000000f";
const GET_L1_FEE: &str = "0x49948e0e";
const TO: &str = "0x00000000000000000000000000000000000000aa";
const L1: u64 = 12_345_678_901;

fn profile(rpc: &str, l1_fee: Option<L1Fee>) -> ChainProfile {
    ChainProfile {
        key: "local".into(),
        family: Family::Evm,
        chain_id: Some(CHAIN_ID),
        chain_uid: hash_of(0),
        rpc: vec![EndpointConfig {
            url: rpc.into(),
            class: scaas_rpc::Class::Named,
            label: None,
            auth: None,
        }],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: None,
        factory: None,
        router: None,
        finality: Finality::Finalized,
        tx_gas_cap: Some(1 << 24),
        tokens: vec![],
        gas: Default::default(),
        gas_opt_in: vec![],
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        dexes: vec![],
        wrappers: vec![],
        family_params: None,
        l1_fee,
        pinned_reads: true,
        disabled_kinds: vec![],
    }
}

/// The fake chain with `answer` to `getL1Fee`, and the SDK on it.
async fn on(l1_fee: Option<L1Fee>, answer: &str, limits: Limits) -> (Arc<Sdk>, String, Fake) {
    let c = fake();
    {
        let mut f = c.lock().unwrap();
        f.native_balance = 10u64.pow(18);
        f.answers
            .push((ORACLE.into(), GET_L1_FEE.into(), answer.into()));
    }
    let url = serve(c.clone()).await;
    let s = Sdk::open(SdkConfig {
        profiles: vec![profile(&url, l1_fee)],
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits,
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
    (s, seed, c)
}

fn send(seed: &str) -> NativeSend {
    NativeSend {
        key: KeyRef::Native {
            seed: seed.into(),
            network: "evm".into(),
            index: 0,
        },
        chain: "local".into(),
        to: TO.into(),
        value: "1000".into(),
        data: None,
        tx_type: None,
    }
}

fn word(n: u64) -> String {
    format!("0x{n:064x}")
}

/// The `eth_call` requests to the oracle, as received.
fn oracle_calls(c: &Fake) -> Vec<Value> {
    c.lock()
        .unwrap()
        .requests
        .iter()
        .map(|r| serde_json::from_str::<Value>(r).unwrap())
        .filter(|r| r["method"] == "eth_call" && r["params"][0]["to"].as_str() == Some(ORACLE))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn op_stack_quote_adds_the_l1_fee_read_at_its_block() {
    let (s, seed, c) = on(Some(L1Fee::OpStack), &word(L1), Limits::default()).await;
    let q = s
        .wallet()
        .prepare_native_send(send(&seed))
        .await
        .unwrap()
        .quote;
    let fee: u128 = q.max_fee_per_gas.parse().unwrap();
    assert_eq!(
        q.max_cost,
        (U256::from(q.gas_limit) * U256::from(fee) + U256::from(L1)).to_string(),
        "gas_limit × max fee + getL1Fee"
    );
    let calls = oracle_calls(&c);
    assert_eq!(calls.len(), 1, "{calls:?}");
    // pinned by hash at the block the quote read (EIP-1898)
    assert_eq!(calls[0]["params"][1]["requireCanonical"], true);
    assert!(calls[0]["params"][1]["blockHash"].is_string());
    // over the unsigned transaction the quote names
    let tx = EvmTx::Eip1559 {
        chain_id: CHAIN_ID,
        nonce: q.tx_nonce,
        max_priority_fee_per_gas: U256::from_str_radix(&q.max_priority_fee_per_gas, 10)
            .unwrap()
            .to_be_bytes::<32>(),
        max_fee_per_gas: U256::from(fee).to_be_bytes::<32>(),
        gas_limit: q.gas_limit,
        to: Some(alloy::hex::decode(&TO[2..]).unwrap().try_into().unwrap()),
        value: U256::from(1000).to_be_bytes::<32>(),
        data: vec![],
        access_list: vec![],
    };
    let unsigned = tx.unsigned().unwrap();
    let want = format!(
        "{GET_L1_FEE}{:064x}{:064x}{}{}",
        32,
        unsigned.len(),
        alloy::hex::encode(&unsigned),
        "00".repeat((32 - unsigned.len() % 32) % 32)
    );
    // alloy names the call's bytes `input`
    let sent = &calls[0]["params"][0];
    let sent = sent
        .get("input")
        .or(sent.get("data"))
        .and_then(Value::as_str);
    assert_eq!(sent, Some(want.as_str()));
}

#[tokio::test(flavor = "multi_thread")]
async fn without_the_field_no_l1_read() {
    let (s, seed, c) = on(None, &word(L1), Limits::default()).await;
    let q = s
        .wallet()
        .prepare_native_send(send(&seed))
        .await
        .unwrap()
        .quote;
    let fee: u128 = q.max_fee_per_gas.parse().unwrap();
    assert_eq!(
        q.max_cost,
        (U256::from(q.gas_limit) * U256::from(fee)).to_string()
    );
    assert!(
        oracle_calls(&c).is_empty(),
        "no getL1Fee read without l1_fee"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_l1_fee_that_is_no_uint256_is_answer_malformed() {
    for bad in ["0x01", "0x", &format!("{}00", word(L1))] {
        let (s, seed, _) = on(Some(L1Fee::OpStack), bad, Limits::default()).await;
        match s.wallet().prepare_native_send(send(&seed)).await {
            Err(SdkError::Rpc(scaas_rpc::RpcError::EndpointAllFailed {
                last: Some(l), ..
            })) => {
                assert_eq!(l.kind, scaas_rpc::FailureKind::AnswerMalformed, "{bad}")
            }
            r => panic!("{bad}: {:?}", r.map(|q| q.quote)),
        }
    }
    let (s, seed, _) = on(Some(L1Fee::OpStack), &word(L1), Limits::default()).await;
    assert!(
        s.wallet().prepare_native_send(send(&seed)).await.is_ok(),
        "control: a uint256"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fee_above_cap_counts_the_l1_fee() {
    let (s, seed, _) = on(Some(L1Fee::OpStack), &word(L1), Limits::default()).await;
    let q = s
        .wallet()
        .prepare_native_send(send(&seed))
        .await
        .unwrap()
        .quote;
    // gas × max fee + the L1 fee, from the quote's own gas and fee (never its max_cost: the cap is checked against this sum)
    let fee: u128 = q.max_fee_per_gas.parse().unwrap();
    let total = U256::from(q.gas_limit) * U256::from(fee) + U256::from(L1);
    let cap = |c: U256| Limits {
        max_cost: c.to_string(),
        ..Limits::default()
    };
    let (s, seed, _) = on(Some(L1Fee::OpStack), &word(L1), cap(total - U256::from(1))).await;
    assert!(
        matches!(
            s.wallet().prepare_native_send(send(&seed)).await,
            Err(SdkError::FeeAboveCap)
        ),
        "the gas part is under the cap, the L1 fee takes it over"
    );
    let (s, seed, _) = on(Some(L1Fee::OpStack), &word(L1), cap(total)).await;
    assert!(
        s.wallet().prepare_native_send(send(&seed)).await.is_ok(),
        "control: at the cap"
    );
}
