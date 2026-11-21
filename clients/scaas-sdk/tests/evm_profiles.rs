// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T40: the EVM profiles of `smartcontracts/evm/chain-uids.json` (Ethereum, Ethereum Classic, OP Mainnet, Arbitrum One,
//! Linea; mainnet and testnet each) as release data: the row's chain id and `chain_uid`, the `profile.json` finality, per-
//! transaction cap and transaction type. Each profile loads; a native send's type follows the chain's base fee (ETC has
//! none: type 0, type 2 refused), against the fake chain of `tests/common/fake_chain.rs` answering the profile's own identity.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "common/fake_chain.rs"]
mod fake_chain;

use fake_chain::{fake, serve};
use scaas_sdk::op::KeyRef;
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::wallet::NativeSend;
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, Sdk, SdkConfig, SdkError,
};
use scaas_ua::wallet::SecretBytes;
use serde_json::Value;
use std::sync::Arc;
use zeroize::Zeroizing;

const KEYS: [&str; 10] = [
    "ethereum-mainnet",
    "ethereum-testnet",
    "etc-mainnet",
    "etc-testnet",
    "op-mainnet",
    "op-testnet",
    "arbitrum-mainnet",
    "arbitrum-testnet",
    "linea-mainnet",
    "linea-testnet",
];
const EVM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../smartcontracts/evm");
const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";

fn json(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap_or_else(|_| panic!("{path}"))).unwrap()
}

/// The profile of `key` on endpoint `rpc`, with the finality its profile.json states (`None` when it states none), its
/// transaction type and its chain id.
fn profile(key: &str, rpc: &str) -> (ChainProfile, Option<Finality>, u8) {
    let rows = json(&format!("{EVM}/chain-uids.json"));
    let row = rows["chains"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key"] == key)
        .unwrap()
        .clone();
    let p = json(&format!("{EVM}/src/chains/{key}/profile.json"));
    let finality = match &p["finality"] {
        Value::String(s) if s == "tag" => Some(Finality::Finalized),
        Value::Object(o) => o["depth"].as_u64().map(Finality::Depth),
        f => panic!("{key}: finality {f}"),
    };
    let c = ChainProfile {
        key: key.into(),
        family: Family::Evm,
        chain_id: row["chainId"].as_u64(),
        chain_uid: row["chainUid"].as_str().unwrap().into(),
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
        // ETC states no depth (the owner's): this test's own, never the profile's
        finality: finality.unwrap_or(Finality::Depth(64)),
        tx_gas_cap: p["txGasCap"].as_u64(),
        tokens: vec![],
        gas: Default::default(),
        gas_opt_in: vec![],
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        dexes: vec![],
        wrappers: vec![],
        family_params: None,
    };
    (c, finality, p["txType"].as_u64().unwrap() as u8)
}

async fn open(p: ChainProfile) -> (Arc<Sdk>, String) {
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

fn send(seed: &str, chain: &str, tx_type: Option<u8>) -> NativeSend {
    NativeSend {
        key: KeyRef::Native {
            seed: seed.into(),
            network: "evm".into(),
            index: 0,
        },
        chain: chain.into(),
        to: "0x00000000000000000000000000000000000000aa".into(),
        value: "1000".into(),
        data: None,
        tx_type,
    }
}

/// Every profile loads with its own chain id and `chain_uid`; the tag where the chain serves `finalized`, no finality on ETC
/// (proof of work: no finalized block, the depth is the owner's); the Ethereum and ETC rows share block 0 and differ by
/// chain id; an endpoint answering the other chain of the pair is never used (control: its own chain's endpoint).
#[tokio::test(flavor = "multi_thread")]
async fn each_profile_loads() {
    for key in KEYS {
        let c = fake();
        let (p, finality, _) = profile(key, "http://127.0.0.1:9");
        {
            let mut f = c.lock().unwrap();
            f.chain_id = p.chain_id.unwrap();
            f.genesis = p.chain_uid.clone();
            f.native_balance = 10u64.pow(18);
        }
        let url = serve(c.clone()).await;
        let (p, _, _) = profile(key, &url);
        assert_eq!(finality.is_none(), key.starts_with("etc-"), "{key}: the tag but on ETC");
        let (s, seed) = open(p.clone()).await;
        s.wallet()
            .prepare_native_send(send(&seed, key, None))
            .await
            .unwrap_or_else(|e| panic!("{key}: {e:?}"));
        // the other chain of the pair: the ETC id over Ethereum's block 0 and back, else the id + 1
        let other = match p.chain_id.unwrap() {
            1 => 61,
            61 => 1,
            id => id + 1,
        };
        c.lock().unwrap().chain_id = other;
        let (s, seed) = open(p).await;
        assert!(
            s.wallet().prepare_native_send(send(&seed, key, None)).await.is_err(),
            "{key}: an endpoint of chain {other} is not this profile's"
        );
    }
    let uid = |k: &str| profile(k, "http://127.0.0.1:9").0.chain_uid;
    assert_eq!(uid("ethereum-mainnet"), uid("etc-mainnet"));
}

/// A native send's type is the profile's: 2 where the head carries a base fee, 0 on ETC (no EIP-1559), where type 2 is
/// `TxTypeRefused`; the fake answers the profile's base fee or none.
#[tokio::test(flavor = "multi_thread")]
async fn a_native_send_type_follows_the_base_fee() {
    let mut zero = 0;
    for key in KEYS {
        let c = fake();
        let (p, _, ty) = profile(key, "http://127.0.0.1:9");
        {
            let mut f = c.lock().unwrap();
            f.chain_id = p.chain_id.unwrap();
            f.genesis = p.chain_uid.clone();
            f.native_balance = 10u64.pow(18);
            f.no_base_fee = ty == 0;
        }
        let url = serve(c.clone()).await;
        let (s, seed) = open(profile(key, &url).0).await;
        let q = s.wallet().prepare_native_send(send(&seed, key, None)).await.unwrap();
        assert_eq!(q.quote.tx_type, ty, "{key}");
        let two = s.wallet().prepare_native_send(send(&seed, key, Some(2))).await;
        if ty == 0 {
            zero += 1;
            assert!(matches!(two, Err(SdkError::TxTypeRefused)), "{key}: type 2 without a base fee");
        } else {
            assert_eq!(two.unwrap().quote.tx_type, 2, "{key}: control");
        }
    }
    assert_eq!(zero, 2, "ETC and Mordor are the type-0 profiles");
}
