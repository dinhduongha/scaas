// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! T41.evm step 0 (owner 2026-11-22, decisions CLI-SDK-32): the SDK's EVM part is the feature `evm`. Without it an EVM profile
//! is the shared `FeatureMissing` at `Sdk::open` (before any read or key), while `account` and `wallet` keep the rows and the
//! native keys; with it the same profile opens (the twin). No network I/O: `Sdk::open` reads nothing.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use scaas_sdk::account::{AddNative, AddUa};
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::{
    bits, ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, Sdk, SdkConfig,
    SdkError,
};
use scaas_ua::wallet::SecretBytes;
use std::sync::Arc;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";

fn profile(key: &str, family: Family) -> ChainProfile {
    ChainProfile {
        key: key.into(),
        family,
        chain_id: (family == Family::Evm).then_some(31337),
        chain_uid: format!("0x{}", "60".repeat(32)),
        rpc: vec![EndpointConfig {
            url: "http://127.0.0.1:9".into(),
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

async fn open(profiles: Vec<ChainProfile>) -> Result<Arc<Sdk>, SdkError> {
    Sdk::open(SdkConfig {
        profiles,
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
        clock: None,
        gas_tables: vec![],
    })
    .await
}

/// The refusal and its twin: an EVM profile is `FeatureMissing` without `evm` and opens with it; a NEAR profile opens in both
/// (the control); the feature bit says which build this is.
#[tokio::test(flavor = "multi_thread")]
async fn an_evm_profile_needs_the_evm_feature() {
    let evm = open(vec![profile("local", Family::Evm)]).await;
    if cfg!(feature = "evm") {
        assert!(evm.is_ok(), "the twin: with `evm` the profile opens");
    } else {
        assert!(
            matches!(evm, Err(SdkError::FeatureMissing)),
            "{:?}",
            evm.err()
        );
    }
    let near = open(vec![profile("near-testnet", Family::Near)]).await;
    assert!(
        near.is_ok(),
        "control: a NEAR profile opens in either build"
    );
    // `pinned_reads` false is an EVM pool's setting (decisions ARCH-POS-20 (2)): on another family it is refused
    let mut untrusted = profile("near-testnet", Family::Near);
    untrusted.pinned_reads = false;
    assert!(matches!(
        open(vec![untrusted]).await,
        Err(SdkError::Argument)
    ));
    // one refused profile refuses the configuration, whatever its place
    let both = open(vec![
        profile("near-testnet", Family::Near),
        profile("local", Family::Evm),
    ])
    .await;
    assert_eq!(both.is_ok(), cfg!(feature = "evm"));
    assert_eq!(Sdk::features() & bits::EVM != 0, cfg!(feature = "evm"));
}

/// `account` works without `evm`: UA rows and a non-EVM native key are added and listed on a seed.
#[tokio::test(flavor = "multi_thread")]
async fn account_rows_without_evm() {
    let s = open(vec![profile("near-testnet", Family::Near)])
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
    let ua = s
        .account()
        .add_ua(AddUa {
            seed: seed.clone(),
            kind: 0x0101,
            account: 0,
            index: 0,
            name: "ua".into(),
        })
        .await
        .unwrap();
    let sol = s
        .account()
        .add_native(AddNative {
            seed: seed.clone(),
            network: "solana".into(),
            index: 0,
            name: "sol".into(),
        })
        .await
        .unwrap();
    assert_eq!((ua.shape.as_str(), sol.shape.as_str()), ("ua", "native"));
    assert_eq!(s.account().accounts(seed).await.unwrap(), vec![ua, sol]);
}
