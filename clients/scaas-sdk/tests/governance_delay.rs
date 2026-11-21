// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T18b: the governance-delay sentence over every bit of `smartcontracts/vectors/governance/governance_bits.json`, the
//! token's and its factory's values read from the fake chain of `tests/common` (local only). A failed read is an error, never
//! a guessed "at once".
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::expect_used)]

#[path = "common/fake_chain.rs"]
mod fake_chain;

use fake_chain::{fake, keccak_hex, serve, Fake, CHAIN_ID};
use scaas_sdk::admin::delay::{DelaySentence, HolderKind};
use scaas_sdk::vault::MemoryStore;
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, Sdk, SdkConfig,
};
use serde_json::Value;
use std::sync::Arc;

const TOKEN: &str = "0x5ca00000000000000000000000000000000000a1";
const FACTORY: &str = "0x5ca000000000000000000000000000000000f0f0";

fn sel(sig: &str) -> String {
    keccak_hex(sig.as_bytes())[..10].to_string()
}

fn w(x: u64) -> String {
    format!("0x{x:064x}")
}

/// The views of the token and its factory: `notice` and `grant` delays, the locked word, the admin.
fn views(c: &Fake, notice: u64, grant: u64, locked: &str, admin: &str) {
    let mut c = c.lock().unwrap();
    c.answers.clear();
    let f = format!("0x{:0>64}", &FACTORY[2..]);
    c.answers.push((TOKEN.into(), sel("factory()"), f));
    c.answers
        .push((FACTORY.into(), sel("noticePeriod()"), w(notice)));
    c.answers
        .push((TOKEN.into(), sel("grantDelay()"), w(grant)));
    c.answers
        .push((TOKEN.into(), sel("lockedFeatures()"), locked.into()));
    c.answers.push((TOKEN.into(), sel("admin()"), admin.into()));
}

async fn setup() -> (Arc<Sdk>, Fake) {
    let chain = fake();
    let url = serve(chain.clone()).await;
    let genesis = chain.lock().unwrap().genesis.clone();
    let profile = ChainProfile {
        key: "local".into(),
        family: Family::Evm,
        chain_id: Some(CHAIN_ID),
        chain_uid: genesis,
        rpc: vec![EndpointConfig {
            url,
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
        tokens: vec![],
        gas: Default::default(),
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![],
        wrappers: vec![],
        family_params: None,
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
    (sdk, chain)
}

fn bits() -> Vec<(u16, bool)> {
    let v: Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/../../smartcontracts/vectors/governance/governance_bits.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    v["bits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            let s = &b["sentences"];
            let marked = ["atOnce", "singleKey", "locked"]
                .iter()
                .all(|k| s.get(k).is_some());
            (b["bit"].as_u64().unwrap() as u16, marked)
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn every_bit_has_its_named_sentence() {
    let (sdk, chain) = setup().await;
    let a = sdk.admin();
    let zero = w(0);
    let bits = bits();
    assert!(bits.iter().any(|(_, m)| *m), "the table marks a bit");
    for (bit, marked) in bits {
        let ask = |h| a.governance_delay("local".into(), TOKEN.into(), bit, h);
        if !marked {
            views(&chain, 0, 0, &zero, &zero);
            assert_eq!(
                ask(None).await.unwrap(),
                [DelaySentence::NoDelay],
                "bit {bit}"
            );
            continue;
        }
        // the longer of the factory's notice and the token's grant delay, each read
        views(&chain, 7_200, 3_600, &zero, &w(1));
        assert_eq!(
            ask(None).await.unwrap(),
            [DelaySentence::After { delay: 7_200 }]
        );
        views(&chain, 600, 86_400, &zero, &w(1));
        assert_eq!(
            ask(None).await.unwrap(),
            [DelaySentence::After { delay: 86_400 }]
        );
        // both 0: at once; a single-key holder adds its sentence (never read as "at once")
        views(&chain, 0, 0, &zero, &w(1));
        assert_eq!(ask(None).await.unwrap(), [DelaySentence::AtOnce]);
        views(&chain, 0, 3_600, &zero, &w(1));
        assert_eq!(
            ask(Some(HolderKind::SingleKey)).await.unwrap(),
            [
                DelaySentence::After { delay: 3_600 },
                DelaySentence::SingleKey
            ]
        );
        assert_eq!(
            ask(Some(HolderKind::Threshold)).await.unwrap(),
            [DelaySentence::After { delay: 3_600 }]
        );
        // locked: the bit locked and the admin gone; the bit locked with an admin is not
        let locked = format!("0x{:064x}", 1u128 << bit);
        views(&chain, 0, 3_600, &locked, &zero);
        assert_eq!(
            ask(None).await.unwrap(),
            [DelaySentence::After { delay: 3_600 }, DelaySentence::Locked]
        );
        views(&chain, 0, 3_600, &locked, &w(1));
        assert_eq!(
            ask(None).await.unwrap(),
            [DelaySentence::After { delay: 3_600 }]
        );
    }
    // a bit the table does not know
    let r = a
        .governance_delay("local".into(), TOKEN.into(), 200, None)
        .await
        .unwrap();
    assert_eq!(r, [DelaySentence::Unknown]);
}

/// A read that fails (the factory answers nothing) is an error, never a guessed "at once".
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_read_is_an_error() {
    let (sdk, chain) = setup().await;
    let marked = bits().into_iter().find(|(_, m)| *m).unwrap().0;
    views(&chain, 0, 0, &w(0), &w(1));
    chain
        .lock()
        .unwrap()
        .answers
        .retain(|(to, _, _)| to != FACTORY);
    let r = sdk
        .admin()
        .governance_delay("local".into(), TOKEN.into(), marked, None)
        .await;
    assert!(r.is_err(), "{r:?}");
}
