// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T12's e2e pay on `anvil` (gate `sdk-e2e`, ignored by default: needs `anvil`, `forge` and `cast` in PATH and
//! `smartcontracts/evm/lib`): the contracts' own `script/Deploy.s.sol` deploys the factory and a demo `NormalToken` holding
//! half its supply for the seed's EVM key; the SDK prepares a `mtxPay` with `PayMeta` v3, quotes a self-relay by that key
//! (a profile gas row: the table has no native-key row yet), submits it (sign → write → simulate → send), and follows it to
//! `Landed` by the token's executed event. Local only; nothing leaves the machine.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(feature = "app-core")]
#[path = "common/prepared.rs"]
mod prepared;
#[cfg(feature = "app-core")]
use prepared::SignPrepared as _;
use scaas_sdk::op::{BlsMultiPart, KeyRef, OpState, SubmitPath};
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::wallet::{Envelope, Pay, PayBody, PayMeta, Transfer};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, GasBase, GasRows, GasVerify, Limits,
    ListedToken, RuntimeChoice, Sdk, SdkConfig,
};
use scaas_ua::wallet::{Network, SecretBytes, Wallet};
#[cfg(feature = "app-core")]
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
#[path = "common/anvil.rs"]
mod anvil_chain;
use anvil_chain::*;

fn sec(s: &str) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(s.as_bytes().to_vec())).unwrap())
}

fn endpoint(url: &str) -> EndpointConfig {
    EndpointConfig {
        url: url.into(),
        class: scaas_rpc::Class::Named,
        label: None,
        auth: None,
    }
}

/// An SDK over one `anvil` profile (`Depth(0)`: anvil mines a block per transaction) with the repository seed imported; the
/// seed id.
async fn sdk_on(profile: ChainProfile) -> (Arc<Sdk>, String) {
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
            words: sec(REPO),
            vault_passphrase: sec(PASS),
        })
        .await
        .unwrap()
        .id;
    (sdk, seed)
}

/// The operation `op` followed to a terminal state (30 s at most).
async fn follow(sdk: &Arc<Sdk>, op: String) -> OpState {
    for _ in 0..60 {
        let s = sdk.op().state(op.clone()).await.unwrap();
        if s.is_terminal() {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    sdk.op().state(op).await.unwrap()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn e2e_pay_on_anvil() {
    let (_anvil, rpc) = anvil().await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    // the seed's EVM key 0: the token holder, the payer and the signer of the pay (a native id signs its own digest)
    let holder = funded_holder(rpc);
    let name = format!("local-31337-{port}-testnet");
    let dep = deploy(
        rpc,
        &name,
        &[("DEMO_SUPPLY", "1000000000000"), ("DEMO_HOLDER", &holder)],
    );
    let token = dep["demo_token"].as_str().unwrap().to_ascii_lowercase();
    let uid = cast(&["block", "0", "--field", "hash", "--rpc-url", rpc]);
    let profile = ChainProfile {
        key: "anvil".into(),
        family: Family::Evm,
        chain_id: Some(31337),
        chain_uid: uid,
        rpc: vec![endpoint(rpc)],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: None,
        factory: None,
        router: None,
        finality: Finality::Depth(0),
        tx_gas_cap: Some(1 << 24),
        tokens: vec![ListedToken {
            address: token.clone(),
            symbol: "DEMO".into(),
            decimals: 0,
        }],
        // a measured figure for this chain (ruling B: the table has no native-key `mtxPay` row yet), rounded up
        gas: with_tx(GasRows {
            base: vec![GasBase {
                entry: "mtxPay".into(),
                kind: "token".into(),
                fresh: true,
                gas: 400_000,
                per_byte: None,
                save: None,
                fee_extra: None,
                ua_extra: None,
                per_item: None,
                regular: None,
            }],
            verify: vec![GasVerify {
                line: Default::default(),
                signer: 0,
                gas: 0,
                sig_bytes: 0,
                margin: 0,
                per_item: None,
            }],
        }),
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
    let (sdk, seed) = sdk_on(profile).await;
    let key = KeyRef::Native {
        seed: seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    let now = now();
    let p = sdk
        .wallet()
        .prepare_pay(Pay {
            signer: key.clone(),
            chain: "anvil".into(),
            token: token.clone(),
            to: format!("0x{}{}", "00".repeat(12), "cafe".repeat(10)),
            value: "1000".into(),
            meta: PayMeta {
                salt: None,
                pay_no: Some("01890a5d-ac96-774b-bcce-b302099a8057".into()),
                save: false,
                body: PayBody::Note { note: "e2e".into() },
            },
            envelope: Envelope {
                valid_until: now + 600,
                mode: 0,
                relayer: None,
                fee: "0".into(),
                fee_recipient: None,
            },
        })
        .await
        .unwrap();
    assert_eq!(p.entry(), "mtxPay");
    let q = sdk
        .op()
        .quote(p.clone(), SubmitPath::SelfRelay { payer: key })
        .await
        .unwrap();
    let sub = sdk.subscribe();
    let op = sdk.op().submit(p, q).await.unwrap();
    // the send task: simulated after the write, then sent
    let mut sent = None;
    for _ in 0..100 {
        if let Some(scaas_sdk::Event::OpState { op: o, state }) = sub.next(200).await {
            if o == op {
                sent = Some(state);
                break;
            }
        }
    }
    assert_eq!(
        sent,
        Some(OpState::InFlight {
            detail: scaas_sdk::InFlight::Sent
        }),
        "simulated and sent"
    );
    let last = follow(&sdk, op).await;
    assert!(matches!(last, OpState::Landed { .. }), "{last:?}");
}

/// The seed's UA `kind` of wallet `account` (index 0) registered through the SDK (plan T13): each registry write quoted,
/// self-relayed by the seed's EVM key and followed to `Landed` by its record; the UA.
#[cfg(feature = "account")]
async fn register_with_sdk(
    sdk: &Arc<Sdk>,
    seed: &str,
    kind: u16,
    account: u32,
    kem: bool,
) -> String {
    use scaas_sdk::account::{Register, RegisterAttrs};
    let acc = sdk.account();
    let writes = acc
        .prepare_register(Register {
            key: KeyRef::Ua {
                seed: seed.into(),
                kind,
                account,
                index: 0,
            },
            chain: "anvil".into(),
            attrs: RegisterAttrs {
                pqz_key: false,
                kem,
            },
            payer: KeyRef::Native {
                seed: seed.into(),
                network: "evm".into(),
                index: 0,
            },
        })
        .await
        .unwrap();
    assert!(!writes.is_empty());
    let ua = writes[0].ua();
    for w in writes {
        let q = acc.quote_registry_write(w.clone()).await.unwrap();
        let op = acc.submit_registry_write(w.clone(), q).await.unwrap();
        let s = follow(sdk, op).await;
        assert!(matches!(s, OpState::Landed { .. }), "{}: {s:?}", w.entry());
    }
    ua
}

/// A `NORMAL_ZETHER` token (kind 2, version 1: BUNDLE, no auditor, scale 1) created through `factory` by the deployer, its
/// supply held by `holder`; the token.
#[cfg(feature = "zether")]
fn zether_token(rpc: &str, factory: &str, holder: &str) -> String {
    let z = format!("0x{}", "00".repeat(32));
    let a = format!("0x{}", "00".repeat(20));
    let cfg = format!(
        "(Zether e2e,zE2E,6,1,0,{z},({z},{z},{z},{z},{z},{z}),1000000,{holder},[],(0,0),\
         (0x,1,1099511627776,0,0,0,0,0,{z},false,0,0,0,false,false),0,{a},0,0,({a},0,0,{z},{z}))"
    );
    let init = cast(&[
        "abi-encode",
        "f((string,string,uint8,uint256,uint256,bytes32,(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32),uint256,address,\
         (address,uint256,uint256)[],(uint32,uint16),(bytes,uint256,uint256,uint256,uint8,uint8,uint256,uint8,bytes32,bool,\
         uint8,uint64,uint64,bool,bool),uint64,address,uint256,uint256,(address,uint64,uint64,bytes32,bytes32)))",
        &cfg,
    ]);
    let sig = "createToken(uint8,uint64,bytes,bytes32)";
    let salt = format!("0x{}", "5a".repeat(32));
    let base = ["--rpc-url", rpc, factory, sig, "2", "1", &init, &salt];
    let t = cast(&[&["call", "--from", DEPLOYER_ADDRESS][..], &base[..]].concat());
    cast(&[&["send", "--private-key", DEPLOYER][..], &base[..]].concat());
    format!("0x{}", &t[t.len() - 40..]).to_ascii_lowercase()
}

/// Plan T15's e2e (spec §9.1, §9.4): on `anvil` with the Zether stack (`DEPLOY_ZETHER=1`), the seed's Zether UAs of accounts
/// 0 and 1 registered first through the SDK (plan T13; owner-approved T16-d), a `NORMAL_ZETHER` token created through the factory; the seed's EVM key shields 1234 to account
/// 0's Zether UA and rolls it over, the Zether UA transfers 100 to account 1's (the proof over the reading layer's words,
/// self-relayed by the EVM key), and the balances read back through the reading layer: 1134 spendable, 100 pending.
#[cfg(all(feature = "zether", feature = "account"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn e2e_zether_shield_transfer_balance_on_anvil() {
    use scaas_sdk::confidential::{
        ZetherBalanceRequest, ZetherRollOver, ZetherShield, ZetherTransfer,
    };
    let (_anvil, rpc) = anvil().await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    let holder = funded_holder(rpc);
    let name = format!("local-31337-{port}-testnet");
    let dep = deploy(rpc, &name, &[("DEPLOY_ZETHER", "true")]);
    let factory = dep["token_factory"].as_str().unwrap().to_ascii_lowercase();
    let registry = dep["zether_registry"]
        .as_str()
        .unwrap()
        .to_ascii_lowercase();
    let token = zether_token(rpc, &factory, &holder);
    let uid = cast(&["block", "0", "--field", "hash", "--rpc-url", rpc]);
    let (sdk, seed) = sdk_on(ChainProfile {
        key: "anvil".into(),
        family: Family::Evm,
        chain_id: Some(31337),
        chain_uid: uid,
        rpc: vec![endpoint(rpc)],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: Some(registry.clone()),
        factory: Some(factory.clone()),
        router: None,
        finality: Finality::Depth(0),
        tx_gas_cap: Some(1 << 24),
        tokens: vec![],
        gas: GasRows::default(),
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
    })
    .await;
    let zether = 0x0141; // zether-bls12381
    let ua0 = register_with_sdk(&sdk, &seed, zether, 0, false).await;
    let ua1 = register_with_sdk(&sdk, &seed, zether, 1, false).await;
    let conf = sdk.confidential();
    assert_eq!(conf.zether_key(seed.clone(), 0).await.unwrap().ua, ua0);
    let payer = KeyRef::Native {
        seed: seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    let env = || Envelope {
        valid_until: now() + 600,
        mode: 0,
        relayer: None,
        fee: "0".into(),
        fee_recipient: None,
    };
    // self-relayed by the EVM key; the app's gas figure (no table row for these entries on anvil)
    let run = |p: Arc<scaas_sdk::op::Prepared>, gas: u64| {
        let (sdk, payer) = (sdk.clone(), payer.clone());
        async move {
            let q = sdk
                .op()
                .quote_with_gas(p.clone(), SubmitPath::SelfRelay { payer }, gas)
                .await
                .unwrap();
            let op = sdk.op().submit(p, q).await.unwrap();
            follow(&sdk, op).await
        }
    };
    let balance = |account: u32, pending: bool| {
        let (conf, seed, token) = (conf.clone(), seed.clone(), token.clone());
        async move {
            conf.zether_balance(ZetherBalanceRequest {
                seed,
                account,
                chain: "anvil".into(),
                token,
                pending,
                table_bits: None,
                bound_bits: None,
            })
            .await
            .unwrap()
            .amount
        }
    };
    let p = conf
        .prepare_zether_shield(ZetherShield {
            signer: payer.clone(),
            chain: "anvil".into(),
            token: token.clone(),
            batch: "1".into(),
            to_ua: ua0.clone(),
            amount: "1234".into(),
            envelope: env(),
        })
        .await
        .unwrap();
    let s = run(p, 1_000_000).await;
    assert!(matches!(s, OpState::Landed { .. }), "shield: {s:?}");
    assert_eq!(balance(0, true).await, "1234", "pending after the shield");
    let p = conf
        .prepare_zether_roll_over(ZetherRollOver {
            signer: payer.clone(),
            chain: "anvil".into(),
            token: token.clone(),
            batch: "1".into(),
            ua: ua0.clone(),
            n: "1".into(),
            envelope: env(),
        })
        .await
        .unwrap();
    let s = run(p, 1_000_000).await;
    assert!(matches!(s, OpState::Landed { .. }), "roll-over: {s:?}");
    assert_eq!(
        balance(0, false).await,
        "1234",
        "spendable after the roll-over"
    );
    let head: u64 = cast(&["block-number", "--rpc-url", rpc]).parse().unwrap();
    let p = conf
        .prepare_zether_transfer(ZetherTransfer {
            seed: seed.clone(),
            account: 0,
            chain: "anvil".into(),
            token: token.clone(),
            batch: "1".into(),
            to_ua: ua1.clone(),
            amount: "100".into(),
            valid_until_block: head + 1000,
            envelope: env(),
            table_bits: None,
            bound_bits: None,
        })
        .await
        .unwrap();
    assert_eq!(p.entry(), "mtxConfidentialTransferSingle");
    let s = run(p, 9_000_000).await;
    assert!(matches!(s, OpState::Landed { .. }), "transfer: {s:?}");
    assert_eq!(
        balance(0, false).await,
        "1134",
        "the holder after the transfer"
    );
    assert_eq!(
        balance(1, true).await,
        "100",
        "the recipient's pending after the transfer"
    );
}

/// Plan T13's e2e (spec §7): the seed's `fndsa512` UA (a PQ kind) with its KEM key registered through the SDK on `anvil`'s
/// registry, self-relayed by the seed's EVM key, each write followed to `Landed` by its record; the registry then holds the
/// UA and its KEM key.
#[cfg(feature = "account")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn e2e_register_pq_kind_on_anvil() {
    const FNDSA512: u16 = 0x0132;
    let (_anvil, rpc) = anvil().await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    funded_holder(rpc);
    let dep = deploy(rpc, &format!("local-31337-{port}-testnet"), &[]);
    let registry = dep["ua_registry"].as_str().unwrap().to_ascii_lowercase();
    assert_eq!(
        cast(&[
            "call",
            "--rpc-url",
            rpc,
            &registry,
            "kindEnabled(uint16)(bool)",
            &FNDSA512.to_string()
        ]),
        "true",
        "fndsa512 enabled on this registry"
    );
    let (sdk, seed) = sdk_on(registry_profile(rpc, &registry, Some(1 << 24))).await;
    let ua = register_with_sdk(&sdk, &seed, FNDSA512, 0, true).await;
    let acc = sdk.account();
    let r = acc.registration_of("anvil".into(), ua).await.unwrap();
    assert!(r.registered && r.kem_stored, "{r:?}");
}

/// The profile of `anvil` at `rpc` with `registry` and the per-transaction cap `cap`.
fn registry_profile(rpc: &str, registry: &str, cap: Option<u64>) -> ChainProfile {
    ChainProfile {
        key: "anvil".into(),
        family: Family::Evm,
        chain_id: Some(31337),
        chain_uid: cast(&["block", "0", "--field", "hash", "--rpc-url", rpc]),
        rpc: vec![endpoint(rpc)],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: Some(registry.into()),
        factory: None,
        router: None,
        finality: Finality::Depth(0),
        tx_gas_cap: cap,
        tokens: vec![],
        gas: GasRows::default(),
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
    }
}

/// Owner 2026-11-19, S2 (spec §7): an `fndsa512` UA with its PQZ key on a profile whose per-transaction cap is under the full
/// registration's estimate (`cast estimate`) splits into the registration without `pqzPop`, then `storePqzPop`; each lands by
/// its record, and the registry then shows the proof stored (`pqz_pop_stored`), whether a PoP verifier proved it or not. The
/// cap is the estimate − 100,000, not − 1: each preparation makes a new PoP and `R_REG` proof, whose estimates differ by a few
/// thousand gas (14,663,705 and 14,656,822 in one run); the part without the proof is millions below.
#[cfg(feature = "pqz")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn e2e_pqz_pop_split_stored_on_anvil() {
    use scaas_sdk::account::{Register, RegisterAttrs};
    const FNDSA512: u16 = 0x0132;
    let (_anvil, rpc) = anvil().await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    let payer_address = funded_holder(rpc);
    let dep = deploy(rpc, &format!("local-31337-{port}-testnet"), &[]);
    let registry = dep["ua_registry"].as_str().unwrap().to_ascii_lowercase();
    let req = |seed: &str| Register {
        key: KeyRef::Ua {
            seed: seed.into(),
            kind: FNDSA512,
            account: 0,
            index: 0,
        },
        chain: "anvil".into(),
        attrs: RegisterAttrs {
            pqz_key: true,
            kem: false,
        },
        payer: KeyRef::Native {
            seed: seed.into(),
            network: "evm".into(),
            index: 0,
        },
    };
    // the full call, unsplit under no cap of the profile, and its estimate
    let (sdk, seed) = sdk_on(registry_profile(rpc, &registry, None)).await;
    let full = sdk.account().prepare_register(req(&seed)).await.unwrap();
    assert_eq!(full.len(), 1, "no cap: one call");
    let est: u64 = cast(&[
        "estimate",
        "--from",
        &payer_address,
        &registry,
        &full[0].calldata(),
        "--rpc-url",
        rpc,
    ])
    .parse()
    .unwrap();
    let (sdk, seed) = sdk_on(registry_profile(rpc, &registry, Some(est - 100_000))).await;
    let acc = sdk.account();
    let writes = acc.prepare_register(req(&seed)).await.unwrap();
    let entries: Vec<_> = writes.iter().map(|w| w.entry()).collect();
    assert_eq!(
        entries.len(),
        2,
        "split under the full call's estimate: {entries:?}"
    );
    assert_eq!(entries[1], "storePqzPop");
    let ua = writes[0].ua();
    for w in writes {
        let q = acc.quote_registry_write(w.clone()).await.unwrap();
        let op = acc.submit_registry_write(w.clone(), q).await.unwrap();
        let s = follow(&sdk, op).await;
        assert!(matches!(s, OpState::Landed { .. }), "{}: {s:?}", w.entry());
    }
    let r = acc.registration_of("anvil".into(), ua).await.unwrap();
    assert!(r.registered && r.pqz_pop_stored, "{r:?}");
}

/// Plan T13b's positive control (spec §7.1, §18 "Sponsored registration"): on `anvil` with the demo token held by the seed's
/// EVM key, a pay to an unregistered derived UA is `ReceiverUnregistered`; the receiver's SDK makes its blob, the sender's SDK
/// checks it, submits it paying the gas and follows it to `Landed`; only then the pay is prepared, and it lands.
#[cfg(feature = "account")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn e2e_sponsored_registration_then_pay_on_anvil() {
    use scaas_sdk::account::RegisterAttrs;
    const ED25519: u16 = 0x0102;
    let (_anvil, rpc) = anvil().await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    let holder = funded_holder(rpc);
    let dep = deploy(
        rpc,
        &format!("local-31337-{port}-testnet"),
        &[("DEMO_SUPPLY", "1000000000000"), ("DEMO_HOLDER", &holder)],
    );
    let token = dep["demo_token"].as_str().unwrap().to_ascii_lowercase();
    let registry = dep["ua_registry"].as_str().unwrap().to_ascii_lowercase();
    let uid = cast(&["block", "0", "--field", "hash", "--rpc-url", rpc]);
    let profile = ChainProfile {
        key: "anvil".into(),
        family: Family::Evm,
        chain_id: Some(31337),
        chain_uid: uid,
        rpc: vec![endpoint(rpc)],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: Some(registry),
        factory: None,
        router: None,
        finality: Finality::Depth(0),
        tx_gas_cap: Some(1 << 24),
        tokens: vec![ListedToken {
            address: token.clone(),
            symbol: "DEMO".into(),
            decimals: 0,
        }],
        gas: with_tx(GasRows {
            base: vec![GasBase {
                entry: "mtxPay".into(),
                kind: "token".into(),
                fresh: true,
                gas: 400_000,
                per_byte: None,
                save: None,
                fee_extra: None,
                ua_extra: None,
                per_item: None,
                regular: None,
            }],
            verify: vec![GasVerify {
                line: Default::default(),
                signer: 0,
                gas: 0,
                sig_bytes: 0,
                margin: 0,
                per_item: None,
            }],
        }),
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
    // the receiver's app and the sender's app: two SDKs (the same test seed, roles apart)
    let (receiver, rseed) = sdk_on(profile.clone()).await;
    let (sender, sseed) = sdk_on(profile).await;
    let blob = receiver
        .account()
        .registration_blob(
            KeyRef::Ua {
                seed: rseed,
                kind: ED25519,
                account: 7,
                index: 0,
            },
            RegisterAttrs::default(),
        )
        .await
        .unwrap();
    // passed out of band as its JSON text, read back on the sender's side
    let blob = scaas_sdk::account::RegistrationBlob::from_json(&blob.to_json().unwrap()).unwrap();
    let to = blob.ua.clone();
    let payer = KeyRef::Native {
        seed: sseed,
        network: "evm".into(),
        index: 0,
    };
    let pay = || Pay {
        signer: payer.clone(),
        chain: "anvil".into(),
        token: token.clone(),
        to: to.clone(),
        value: "1000".into(),
        meta: PayMeta {
            salt: None,
            pay_no: Some("01890a5d-ac96-774b-bcce-b302099a8058".into()),
            save: false,
            body: PayBody::Note {
                note: "sponsored".into(),
            },
        },
        envelope: Envelope {
            valid_until: now() + 600,
            mode: 0,
            relayer: None,
            fee: "0".into(),
            fee_recipient: None,
        },
    };
    assert_eq!(
        sender
            .wallet()
            .prepare_pay(pay())
            .await
            .err()
            .map(|e| e.code()),
        Some("ReceiverUnregistered")
    );
    let acc = sender.account();
    let writes = acc
        .prepare_submit_registration(blob, "anvil".into(), to.clone(), payer.clone())
        .await
        .unwrap();
    assert_eq!(writes.len(), 1);
    for w in writes {
        let q = acc.quote_registry_write(w.clone()).await.unwrap();
        let op = acc.submit_registry_write(w, q).await.unwrap();
        let s = follow(&sender, op).await;
        assert!(matches!(s, OpState::Landed { .. }), "registration: {s:?}");
    }
    let p = sender.wallet().prepare_pay(pay()).await.unwrap();
    let q = sender
        .op()
        .quote(p.clone(), SubmitPath::SelfRelay { payer })
        .await
        .unwrap();
    let op = sender.op().submit(p, q).await.unwrap();
    let s = follow(&sender, op).await;
    assert!(matches!(s, OpState::Landed { .. }), "pay: {s:?}");
}

// --- plan T13: SmartKeyAccount and guardian recovery ---

/// The profile of `anvil` at `rpc` with measured gas figures of the account's entries (the table has no `account` rows),
/// rounded up.
fn account_profile(rpc: &str) -> ChainProfile {
    let row = |entry: &str, fresh: bool| GasBase {
        entry: entry.into(),
        kind: "account".into(),
        fresh,
        gas: 600_000,
        per_byte: None,
        save: None,
        fee_extra: None,
        ua_extra: None,
        per_item: None,
        regular: None,
    };
    ChainProfile {
        key: "anvil".into(),
        family: Family::Evm,
        chain_id: Some(31337),
        chain_uid: cast(&["block", "0", "--field", "hash", "--rpc-url", rpc]),
        rpc: vec![endpoint(rpc)],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: None,
        factory: None,
        router: None,
        finality: Finality::Depth(0),
        tx_gas_cap: Some(1 << 24),
        tokens: vec![],
        gas: with_tx(GasRows {
            base: [true, false]
                .iter()
                .flat_map(|&f| [row("mtxAddKey", f), row("mtxExecute", f)])
                .collect(),
            verify: vec![GasVerify {
                line: Default::default(),
                signer: 0,
                gas: 0,
                sig_bytes: 0,
                margin: 0,
                per_item: None,
            }],
        }),
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
    }
}

/// A `SmartKeyAccount` of the seed's EVM key `index` (its first key, secp256k1) and `guardian`, deployed through `factory`
/// by the SDK (`prepare_smart_deploy`, sent by the seed's EVM key 0); its address, checked against the SDK's counterfactual
/// one.
async fn deploy_account(
    sdk: &Arc<Sdk>,
    seed: &str,
    rpc: &str,
    factory: &str,
    index: u32,
    guardian: &str,
) -> String {
    use scaas_sdk::account::{smart_account_address, SubjectKeyArgs};
    let key = Wallet::from_mnemonic(REPO, "")
        .unwrap()
        .native_key(Network::Evm, index, None)
        .unwrap()
        .address()
        .unwrap();
    let first = SubjectKeyArgs::secp256k1(&key).unwrap();
    let implementation = cast(&[
        "call",
        factory,
        "IMPLEMENTATION()(address)",
        "--rpc-url",
        rpc,
    ]);
    let predicted = smart_account_address(factory, &implementation, &first, guardian).unwrap();
    let q = sdk
        .account()
        .prepare_smart_deploy(
            key0(seed),
            "anvil".into(),
            factory.into(),
            first,
            guardian.into(),
        )
        .await
        .unwrap();
    let op = sdk.wallet().submit_native_send(q).await.unwrap();
    let s = follow(sdk, op).await;
    assert!(matches!(s, OpState::Landed { .. }), "deploy: {s:?}");
    assert_ne!(
        cast(&["code", &predicted, "--rpc-url", rpc]),
        "0x",
        "deployed at the SDK's address"
    );
    predicted
}

fn smart_op(seed: &str, index: u32, account: &str) -> scaas_sdk::account::SmartOp {
    scaas_sdk::account::SmartOp {
        signer: KeyRef::Native {
            seed: seed.into(),
            network: "evm".into(),
            index,
        },
        key_index: None,
        chain: "anvil".into(),
        account: account.into(),
        batch: "1".into(),
        envelope: Envelope {
            valid_until: now() + 600,
            mode: 0,
            relayer: None,
            fee: "0".into(),
            fee_recipient: None,
        },
    }
}

/// The seed's EVM key 0.
fn key0(seed: &str) -> KeyRef {
    KeyRef::Native {
        seed: seed.into(),
        network: "evm".into(),
        index: 0,
    }
}

/// `p` quoted for a self-relay by the seed's EVM key 0, submitted and followed to its end.
async fn self_relay(sdk: &Arc<Sdk>, seed: &str, p: Arc<scaas_sdk::op::Prepared>) -> OpState {
    let payer = KeyRef::Native {
        seed: seed.into(),
        network: "evm".into(),
        index: 0,
    };
    let path = SubmitPath::SelfRelay { payer };
    // `mtxExecute`: the app's figure is the inner call's, added to the rows (owner 2026-11-19, ruling 5)
    let q = if p.entry() == "mtxExecute" {
        sdk.op().quote_with_gas(p.clone(), path, 100_000).await
    } else {
        sdk.op().quote(p.clone(), path).await
    }
    .unwrap();
    let op = sdk.op().submit(p, q).await.unwrap();
    follow(sdk, op).await
}

/// Plan T13 `smart_account_add_key_self_relay`: the account of the seed's EVM key 0 (deployed at the SDK's counterfactual
/// address) adds a second key by its own `AddKey`, signed by key 0 and self-relayed by the same key's address; `Landed`, and
/// the account holds two keys.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn smart_account_add_key_self_relay() {
    use scaas_sdk::account::SubjectKeyArgs;
    let (_anvil, rpc) = anvil().await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    funded_holder(rpc);
    let dep = deploy(rpc, &format!("local-31337-{port}-testnet"), &[]);
    let factory = dep["smart_key_account_factory"]
        .as_str()
        .unwrap()
        .to_string();
    let (sdk, seed) = sdk_on(account_profile(rpc)).await;
    let account = deploy_account(
        &sdk,
        &seed,
        rpc,
        &factory,
        0,
        "0x0000000000000000000000000000000000000000",
    )
    .await;
    assert_eq!(
        cast(&["call", &account, "keyCount()(uint256)", "--rpc-url", rpc]),
        "1"
    );
    let new_key = SubjectKeyArgs::secp256k1("0x00000000000000000000000000000000000000bb").unwrap();
    let p = sdk
        .account()
        .prepare_smart_add_key(smart_op(&seed, 0, &account), new_key)
        .await
        .unwrap();
    assert_eq!(p.entry(), "mtxAddKey");
    let s = self_relay(&sdk, &seed, p).await;
    assert!(matches!(s, OpState::Landed { .. }), "{s:?}");
    assert_eq!(
        cast(&["call", &account, "keyCount()(uint256)", "--rpc-url", rpc]),
        "2"
    );
    // another key signs (owner 2026-11-19, S3): the seed's EVM key 2 added at index 2, an `AddKey` it signs with the
    // index read from the account; a key the account does not hold is `SignerNotAccountKey` (P2)
    let key2 = Wallet::from_mnemonic(REPO, "")
        .unwrap()
        .native_key(Network::Evm, 2, None)
        .unwrap()
        .address()
        .unwrap();
    let p = sdk
        .account()
        .prepare_smart_add_key(
            smart_op(&seed, 0, &account),
            SubjectKeyArgs::secp256k1(&key2).unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        self_relay(&sdk, &seed, p).await,
        OpState::Landed { .. }
    ));
    let third = SubjectKeyArgs::secp256k1("0x00000000000000000000000000000000000000cc").unwrap();
    let refused = sdk
        .account()
        .prepare_smart_add_key(smart_op(&seed, 3, &account), third.clone())
        .await;
    assert_eq!(
        refused.err().map(|e| e.code()),
        Some("SignerNotAccountKey"),
        "not a key of the account"
    );
    let p = sdk
        .account()
        .prepare_smart_add_key(smart_op(&seed, 2, &account), third)
        .await
        .unwrap();
    let s = self_relay(&sdk, &seed, p).await;
    assert!(
        matches!(s, OpState::Landed { .. }),
        "signed by key index 2: {s:?}"
    );
    assert_eq!(
        cast(&["call", &account, "keyCount()(uint256)", "--rpc-url", rpc]),
        "4"
    );
}

/// Plan T13 `guardian_recovery_via_execute`: account A (the seed's EVM key 0) names the guardian `SmartKeyAccount` G (EVM key
/// 1); G's `Execute` of the decoded `initiateRecovery(newKey)` on A, signed by key 1 and self-relayed by key 0, lands and
/// starts the clock; `completeRecovery` is refused before the two days, passes after an `anvil` time warp, and A holds the
/// new key.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn guardian_recovery_via_execute() {
    use scaas_sdk::account::SubjectKeyArgs;
    let (_anvil, rpc) = anvil().await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    funded_holder(rpc);
    let dep = deploy(rpc, &format!("local-31337-{port}-testnet"), &[]);
    let factory = dep["smart_key_account_factory"]
        .as_str()
        .unwrap()
        .to_string();
    let (sdk, seed) = sdk_on(account_profile(rpc)).await;
    let guardian = deploy_account(
        &sdk,
        &seed,
        rpc,
        &factory,
        1,
        "0x0000000000000000000000000000000000000000",
    )
    .await;
    let account = deploy_account(&sdk, &seed, rpc, &factory, 0, &guardian).await;
    let new_key = SubjectKeyArgs::secp256k1("0x00000000000000000000000000000000000000dd").unwrap();
    let p = sdk
        .account()
        .prepare_initiate_recovery(
            smart_op(&seed, 1, &guardian),
            account.clone(),
            new_key.clone(),
        )
        .await
        .unwrap();
    assert_eq!(p.entry(), "mtxExecute");
    let s = self_relay(&sdk, &seed, p).await;
    assert!(matches!(s, OpState::Landed { .. }), "{s:?}");
    let pending = cast(&[
        "call",
        &account,
        "pendingRecovery()(bytes32)",
        "--rpc-url",
        rpc,
    ]);
    assert_ne!(
        pending,
        format!("0x{}", "00".repeat(32)),
        "the recovery started"
    );
    // `completeRecovery` through the SDK, sent by the seed's EVM key 0 (anyone may)
    let acc = sdk.account();
    let complete = || {
        acc.prepare_complete_recovery(
            key0(&seed),
            "anvil".into(),
            account.clone(),
            new_key.clone(),
        )
    };
    assert!(
        complete().await.is_err(),
        "refused before RECOVERY_DELAY: its simulation reverts"
    );
    cast(&["rpc", "--rpc-url", rpc, "evm_increaseTime", "172801"]);
    cast(&["rpc", "--rpc-url", rpc, "evm_mine"]);
    let op = sdk
        .wallet()
        .submit_native_send(complete().await.unwrap())
        .await
        .unwrap();
    let s = follow(&sdk, op).await;
    assert!(
        matches!(s, OpState::Landed { .. }),
        "after the two days, by anyone: {s:?}"
    );
    assert_eq!(
        cast(&["call", &account, "keyCount()(uint256)", "--rpc-url", rpc]),
        "2"
    );
}

// --- plan T13: msig ---

/// A registry write's quote, submit and follow to `Landed`.
#[cfg(feature = "account")]
async fn land_write(sdk: &Arc<Sdk>, w: Arc<scaas_sdk::account::RegistryWrite>) {
    let acc = sdk.account();
    let q = acc.quote_registry_write(w.clone()).await.unwrap();
    let op = acc.submit_registry_write(w.clone(), q).await.unwrap();
    let s = follow(sdk, op).await;
    assert!(matches!(s, OpState::Landed { .. }), "{}: {s:?}", w.entry());
}

/// Plan T13 `msig` on `anvil` (CTR-UA-37, CTR-UA-44): three ed25519 UAs of the seed registered, then a 2-of-3 `msig` over
/// them (`registerMsig`, classical: an empty `pop`), not active until two slots accept (`acceptMembership`, each landed by its
/// bit); the holder pays the `msig` 1000 of the demo token, the `msig` transfers 100 signed by its two accepted slots
/// (`KeyRef::Msig`, self-relayed by the seed's EVM key, landed by the token's event), then `updateMsig` disables the third slot
/// (version 1, landed by the registry's counter).
#[cfg(feature = "account")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn e2e_msig_register_accept_transfer_update_on_anvil() {
    use scaas_sdk::account::{
        msig_structure, AcceptMembership, MsigMemberArgs, MsigRegister, UpdateMsig,
    };
    use scaas_sdk::op::MsigSlot;
    use scaas_sdk::wallet::Transfer;
    const ED25519: u16 = 0x0102;
    let (_anvil, rpc) = anvil().await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    let holder = funded_holder(rpc);
    let dep = deploy(
        rpc,
        &format!("local-31337-{port}-testnet"),
        &[("DEMO_SUPPLY", "1000000000000"), ("DEMO_HOLDER", &holder)],
    );
    let token = dep["demo_token"].as_str().unwrap().to_ascii_lowercase();
    let registry = dep["ua_registry"].as_str().unwrap().to_ascii_lowercase();
    let mut profile = registry_profile(rpc, &registry, Some(1 << 24));
    profile.tokens = vec![ListedToken {
        address: token.clone(),
        symbol: "DEMO".into(),
        decimals: 0,
    }];
    // measured figures of this chain, rounded up (the table has no `msig` rows)
    let base = |entry: &str, fresh: bool| GasBase {
        entry: entry.into(),
        kind: "token".into(),
        fresh,
        gas: 500_000,
        per_byte: None,
        save: None,
        fee_extra: None,
        ua_extra: None,
        per_item: None,
        regular: None,
    };
    profile.gas = with_tx(GasRows {
        base: [true, false]
            .iter()
            .flat_map(|&f| [base("mtxPay", f), base("mtxExecuteTransfer", f)])
            .collect(),
        verify: vec![
            GasVerify {
                line: Default::default(),
                signer: 0,
                gas: 0,
                sig_bytes: 0,
                margin: 0,
                per_item: None,
            },
            GasVerify {
                line: Default::default(),
                signer: 0x0120,
                gas: 300_000,
                sig_bytes: 0,
                margin: 0,
                per_item: None,
            },
        ],
    });
    let (sdk, seed) = sdk_on(profile).await;
    let mut uas = vec![];
    for account in 20..23 {
        uas.push(register_with_sdk(&sdk, &seed, ED25519, account, false).await);
    }
    let key_of = |ua: &str| {
        let a = 20 + uas.iter().position(|u| u == ua).unwrap() as u32;
        KeyRef::Ua {
            seed: seed.clone(),
            kind: ED25519,
            account: a,
            index: 0,
        }
    };
    let s = msig_structure(
        uas.iter()
            .map(|u| MsigMemberArgs {
                kind: ED25519,
                id: u.clone(),
                weight: 1,
            })
            .collect(),
        2,
    )
    .unwrap();
    let ua = s.ua().unwrap();
    let acc = sdk.account();
    let ws = acc
        .prepare_msig_register(MsigRegister {
            chain: "anvil".into(),
            structure: s.clone(),
            slots: vec![],
            payer: key0(&seed),
        })
        .await
        .unwrap();
    assert_eq!(ws.len(), 1);
    land_write(&sdk, ws[0].clone()).await;
    assert!(
        !acc.msig_state("anvil".into(), ua.clone())
            .await
            .unwrap()
            .active,
        "no slot accepted yet"
    );
    let slot = |i: u16| MsigSlot::Member {
        index: i,
        key: key_of(&s.members[usize::from(i)].id),
    };
    for i in [0u16, 1] {
        let w = acc
            .prepare_accept_membership(AcceptMembership {
                chain: "anvil".into(),
                ua: ua.clone(),
                slot: slot(i),
                payer: key0(&seed),
            })
            .await
            .unwrap()
            .expect("not accepted yet");
        land_write(&sdk, w).await;
    }
    let st = acc.msig_state("anvil".into(), ua.clone()).await.unwrap();
    assert!(
        st.active && st.slots[0].accepted && st.slots[1].accepted && !st.slots[2].accepted,
        "{st:?}"
    );
    // the holder pays the msig, the msig transfers by slots 0 and 1
    let p = sdk
        .wallet()
        .prepare_pay(Pay {
            signer: key0(&seed),
            chain: "anvil".into(),
            token: token.clone(),
            to: ua.clone(),
            value: "1000".into(),
            meta: PayMeta {
                salt: None,
                pay_no: Some("01890a5d-ac96-774b-bcce-b302099a8059".into()),
                save: false,
                body: PayBody::Note {
                    note: "to the msig".into(),
                },
            },
            envelope: Envelope {
                valid_until: now() + 600,
                mode: 0,
                relayer: None,
                fee: "0".into(),
                fee_recipient: None,
            },
        })
        .await
        .unwrap();
    let s1 = self_relay(&sdk, &seed, p).await;
    assert!(matches!(s1, OpState::Landed { .. }), "pay: {s1:?}");
    let p = sdk
        .wallet()
        .prepare_transfer(Transfer {
            signer: KeyRef::Msig {
                ua: ua.clone(),
                slots: vec![slot(0), slot(1)],
            },
            chain: "anvil".into(),
            token: token.clone(),
            to: format!("0x{}{}", "00".repeat(12), "cafe".repeat(10)),
            value: "100".into(),
            batch: "1".into(),
            envelope: Envelope {
                valid_until: now() + 600,
                mode: 0,
                relayer: None,
                fee: "0".into(),
                fee_recipient: None,
            },
        })
        .await
        .unwrap();
    let s2 = self_relay(&sdk, &seed, p).await;
    assert!(
        matches!(s2, OpState::Landed { .. }),
        "msig transfer: {s2:?}"
    );
    // M1, `Op::member_sign` directly: slot 1 signs apart (its own device), slot 0 signs at submit with that `MemberSig` as a
    // `Signed` slot; both prepared from the same request (one `validUntil`), so one digest. Several local slots: `Argument`.
    let until = now() + 600;
    let wallet = sdk.wallet();
    let apart = |slots: Vec<MsigSlot>| {
        wallet.prepare_transfer(Transfer {
            signer: KeyRef::Msig {
                ua: ua.clone(),
                slots,
            },
            chain: "anvil".into(),
            token: token.clone(),
            to: format!("0x{}{}", "00".repeat(12), "cafe".repeat(10)),
            value: "50".into(),
            batch: "1".into(),
            envelope: Envelope {
                valid_until: until,
                mode: 0,
                relayer: None,
                fee: "0".into(),
                fee_recipient: None,
            },
        })
    };
    let two = apart(vec![slot(0), slot(1)]).await.unwrap();
    assert!(
        matches!(sdk.op().member_sign(two).await, Err(e) if e.code() == "Argument"),
        "one local slot only"
    );
    let member = sdk
        .op()
        .member_sign(apart(vec![slot(1)]).await.unwrap())
        .await
        .unwrap();
    let p = apart(vec![slot(0), MsigSlot::Signed { index: 1, member }])
        .await
        .unwrap();
    let s3 = self_relay(&sdk, &seed, p).await;
    assert!(
        matches!(s3, OpState::Landed { .. }),
        "msig transfer with a member signed apart: {s3:?}"
    );
    // `updateMsig`: the third slot disabled, signed by slots 0 and 1 of the stored structure
    let block: u64 = cast(&["block-number", "--rpc-url", rpc]).parse().unwrap();
    let plan = acc
        .prepare_update_msig(UpdateMsig {
            chain: "anvil".into(),
            ua: ua.clone(),
            structure: s.clone(),
            enabled: vec![0, 1],
            valid_until_block: block + 100,
            slots: vec![slot(0), slot(1)],
            payer: key0(&seed),
            verifier: false,
            family_without_update: false,
        })
        .await
        .unwrap();
    land_write(&sdk, plan.write).await;
    let st = acc.msig_state("anvil".into(), ua).await.unwrap();
    assert!(
        st.version == 1 && !st.slots[2].enabled && st.active,
        "{st:?}"
    );
}

/// Owner 2026-11-19, T1 (CTR-UA-23 MD-3): on `anvil` the ML-DSA verifiers have no precompile, so the registry caches the
/// expanded key: the SDK's registration of the seed's mldsa65 UA is its two `cacheExpandedKey` parts, then `register`, each
/// landed by its record (`expandedKeyOf(ua)[p]`, `isRegistered`); a second preparation has nothing left to write.
#[cfg(feature = "account")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn e2e_register_mldsa_cached_on_anvil() {
    use scaas_sdk::account::{Register, RegisterAttrs};
    const MLDSA65: u16 = 0x0131;
    let (_anvil, rpc) = anvil().await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    funded_holder(rpc);
    let dep = deploy(rpc, &format!("local-31337-{port}-testnet"), &[]);
    let registry = dep["ua_registry"].as_str().unwrap().to_ascii_lowercase();
    assert_eq!(
        cast(&[
            "call",
            "--rpc-url",
            rpc,
            &registry,
            "kindEnabled(uint16)(bool)",
            &MLDSA65.to_string()
        ]),
        "true",
        "mldsa65 enabled on this registry"
    );
    let (sdk, seed) = sdk_on(registry_profile(rpc, &registry, Some(1 << 24))).await;
    let acc = sdk.account();
    let req = || Register {
        key: KeyRef::Ua {
            seed: seed.clone(),
            kind: MLDSA65,
            account: 0,
            index: 0,
        },
        chain: "anvil".into(),
        attrs: RegisterAttrs::default(),
        payer: key0(&seed),
    };
    let writes = acc.prepare_register(req()).await.unwrap();
    let entries: Vec<_> = writes.iter().map(|w| w.entry()).collect();
    assert_eq!(
        entries,
        ["cacheExpandedKey", "cacheExpandedKey", "register"]
    );
    let ua = writes[0].ua();
    for w in writes {
        land_write(&sdk, w).await;
    }
    let ek = cast(&[
        "call",
        "--rpc-url",
        rpc,
        &registry,
        "expandedKeyOf(bytes32)(address[3])",
        &ua,
    ]);
    assert_eq!(
        ek.matches("0x0000000000000000000000000000000000000000")
            .count(),
        1,
        "parts 0 and 1 stored: {ek}"
    );
    assert!(
        acc.registration_of("anvil".into(), ua)
            .await
            .unwrap()
            .registered
    );
    assert!(
        acc.prepare_register(req()).await.unwrap().is_empty(),
        "nothing left to write"
    );
}

// --- owner 2026-11-19, T2: a passkey row registered ---

/// A test passkey on `scaas.example` over a fixed P-256 key: assertions with UP and UV, `r ‖ s` signatures; nothing else.
struct Passkey(p256::ecdsa::SigningKey);

impl Passkey {
    fn new() -> Self {
        Passkey(
            p256::ecdsa::SigningKey::from_slice(&scaas_ua::sha256(b"scaas-sdk.e2e.passkey"))
                .unwrap(),
        )
    }
}

#[async_trait::async_trait]
impl scaas_sdk::platform::Authenticator for Passkey {
    async fn create_passkey(
        &self,
        rp_id: String,
        _: String,
        _: Vec<Vec<u8>>,
    ) -> Result<scaas_sdk::platform::PasskeyCreated, scaas_sdk::platform::AuthError> {
        let xy = self.0.verifying_key().to_sec1_point(false).as_bytes()[1..].to_vec();
        Ok(scaas_sdk::platform::PasskeyCreated {
            credential_id: vec![7; 16],
            key_data: [xy, scaas_ua::sha256(rp_id.as_bytes()).to_vec()].concat(),
        })
    }
    async fn get_assertion(
        &self,
        req: scaas_sdk::platform::AssertionRequest,
        _: Arc<SecretBytes>,
    ) -> Result<scaas_sdk::platform::Assertion, scaas_sdk::platform::AuthError> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut challenge = String::new();
        for c in req.challenge.chunks(3) {
            let n = c
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, x)| n | u32::from(*x) << (16 - 8 * i));
            (0..=c.len())
                .for_each(|i| challenge.push(A[(n >> (18 - 6 * i) & 63) as usize] as char));
        }
        let auth = [
            &scaas_ua::sha256(req.rp_id.as_bytes())[..],
            &[0x05],
            &1u32.to_be_bytes(),
        ]
        .concat();
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://{}"}}"#,
            req.rp_id
        )
        .into_bytes();
        let pre = scaas_ua::sha256(&[auth.as_slice(), &scaas_ua::sha256(&cdj)].concat());
        let sig: p256::ecdsa::Signature = self.0.sign_prehash(&pre).unwrap();
        Ok(scaas_sdk::platform::Assertion {
            credential_id: vec![7; 16],
            authenticator_data: auth,
            client_data_json: cdj,
            signature: sig.to_bytes().to_vec(),
            prf: false,
        })
    }
    async fn platform_secret(
        &self,
        _: String,
        _: Vec<u8>,
        _: String,
        _: Option<scaas_sdk::platform::KeyPolicy>,
        _: Arc<SecretBytes>,
    ) -> Result<(), scaas_sdk::platform::AuthError> {
        Err(scaas_sdk::platform::AuthError::Unavailable)
    }
    async fn p256_generate(
        &self,
        _: scaas_sdk::platform::KeyPolicy,
    ) -> Result<scaas_sdk::platform::SePublic, scaas_sdk::platform::AuthError> {
        Err(scaas_sdk::platform::AuthError::Unavailable)
    }
    async fn p256_sign(
        &self,
        _: String,
        _: Vec<u8>,
        _: String,
    ) -> Result<Vec<u8>, scaas_sdk::platform::AuthError> {
        Err(scaas_sdk::platform::AuthError::Unavailable)
    }
}

/// Owner 2026-11-19, T2: a passkey key row (`create_passkey_key`, the RP ID the SDK's config gives) registers on `anvil`
/// through the SDK: `registerWebAuthn` with the PoP the passkey answered, sent by the seed's EVM key, landed by
/// `isRegistered`; the registry then holds its `webAuthnKeyOf`.
#[cfg(feature = "account")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn e2e_register_passkey_row_on_anvil() {
    use scaas_sdk::account::{CreatePasskeyKey, Register};
    let (_anvil, rpc) = anvil().await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    funded_holder(rpc);
    let dep = deploy(rpc, &format!("local-31337-{port}-testnet"), &[]);
    let registry = dep["ua_registry"].as_str().unwrap().to_ascii_lowercase();
    let sdk = Sdk::open(SdkConfig {
        profiles: vec![registry_profile(rpc, &registry, Some(1 << 24))],
        store: MemoryStore::new(),
        authenticator: Some(Arc::new(Passkey::new())),
        rp_id: Some("scaas.example".into()),
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
            words: sec(REPO),
            vault_passphrase: sec(PASS),
        })
        .await
        .unwrap()
        .id;
    let acc = sdk.account();
    let key = acc
        .create_passkey_key(CreatePasskeyKey {
            seed: seed.clone(),
            name: "phone".into(),
        })
        .await
        .unwrap();
    let writes = acc
        .prepare_register(Register {
            key,
            chain: "anvil".into(),
            attrs: Default::default(),
            payer: key0(&seed),
        })
        .await
        .unwrap();
    assert_eq!(
        writes.iter().map(|w| w.entry()).collect::<Vec<_>>(),
        ["registerWebAuthn"]
    );
    let ua = writes[0].ua();
    land_write(&sdk, writes[0].clone()).await;
    assert!(
        acc.registration_of("anvil".into(), ua.clone())
            .await
            .unwrap()
            .registered
    );
    let k = cast(&[
        "call",
        "--rpc-url",
        rpc,
        &registry,
        "webAuthnKeyOf(bytes32)((bytes32,bytes32,bytes32))",
        &ua,
    ]);
    assert!(
        k.contains(&format!(
            "0x{}",
            alloy::hex::encode(scaas_ua::sha256(b"scaas.example"))
        )),
        "{k}"
    );
}

/// Plan T17 on `anvil`: the cancel of a SCaaS sell token's order, prepared by the SDK from the order's named fields
/// (`CancelUAOrder`, signed by the seed's EVM key as its native id), is the digest the demo token computes
/// (`cancelOrderDigest`), self-relayed and followed to `Landed`; the order is then closed on the token (`pulled`). The place
/// through a venue is the fake gateway's (`tests/dex.rs`): this e2e runs no node.
#[cfg(feature = "dex")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn e2e_dex_cancel_order_on_anvil() {
    use scaas_sdk::dex::{CancelOrder, OrderTerms};
    let (_anvil, rpc) = anvil().await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    let holder = funded_holder(rpc);
    let dep = deploy(
        rpc,
        &format!("local-31337-{port}-testnet"),
        &[("DEMO_SUPPLY", "1000000000000"), ("DEMO_HOLDER", &holder)],
    );
    let token = dep["demo_token"].as_str().unwrap().to_ascii_lowercase();
    let uid = cast(&["block", "0", "--field", "hash", "--rpc-url", rpc]);
    let row = |entry: &str, fresh: bool| GasBase {
        entry: entry.into(),
        kind: "token".into(),
        fresh,
        gas: 400_000,
        per_byte: None,
        save: None,
        fee_extra: None,
        ua_extra: None,
        per_item: None,
        regular: None,
    };
    let profile = ChainProfile {
        key: "anvil".into(),
        family: Family::Evm,
        chain_id: Some(31337),
        chain_uid: uid,
        rpc: vec![endpoint(rpc)],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: None,
        factory: None,
        router: None,
        finality: Finality::Depth(0),
        tx_gas_cap: Some(1 << 24),
        tokens: vec![],
        // a figure for this chain (no table row for a native key's order cancel), rounded up
        gas: with_tx(GasRows {
            base: vec![row("mtxCancelOrder", true), row("mtxCancelOrder", false)],
            verify: vec![GasVerify {
                line: Default::default(),
                signer: 0,
                gas: 0,
                sig_bytes: 0,
                margin: 0,
                per_item: None,
            }],
        }),
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
    let (sdk, seed) = sdk_on(profile).await;
    let key = KeyRef::Native {
        seed,
        network: "evm".into(),
        index: 0,
    };
    let from = format!("0x{}{}", "00".repeat(12), &holder.to_ascii_lowercase()[2..]);
    let dex = "0x00000000000000000000000000000000000d0e0d";
    let receive = "0x00000000000000000000000000000000000b0b0b";
    let valid = (now() + 600).to_string();
    let order = OrderTerms {
        from: from.clone(),
        receive_token: receive.into(),
        amount: "1000".into(),
        receive_amount: "2000".into(),
        min_fill: "1000".into(),
        fee: "3000".into(),
        relayer: "0x0000000000000000000000000000000000000000".into(),
        dex: dex.into(),
        destination: format!("0x{}", "00".repeat(32)),
        flags: 0,
        batch: "7".into(),
        nonce: "0".into(),
        valid_until: valid.clone(),
    };
    let tuple = format!(
        "({from},{receive},1000,2000,1000,3000,0x0000000000000000000000000000000000000000,{dex},0x{},0,7,0,{valid})",
        "00".repeat(32)
    );
    let ty = "(bytes32,address,uint256,uint256,uint256,uint256,address,address,bytes32,uint8,uint256,uint256,uint256)";
    let p = sdk
        .dex()
        .prepare_cancel_order(CancelOrder {
            signer: key.clone(),
            chain: "anvil".into(),
            sell_token: token.clone(),
            order,
        })
        .await
        .unwrap();
    let digest = cast(&[
        "call",
        &token,
        &format!("cancelOrderDigest({ty})(bytes32)"),
        &tuple,
        "--rpc-url",
        rpc,
    ]);
    assert_eq!(
        p.id(),
        digest,
        "the SDK's CancelUAOrder digest is the token's"
    );
    let h = cast(&[
        "call",
        &token,
        &format!("tradeOrderDigest({ty})(bytes32)"),
        &tuple,
        "--rpc-url",
        rpc,
    ]);
    let pulled = |h: &str| {
        cast(&[
            "call",
            &token,
            "pulled(bytes32)(uint256)",
            h,
            "--rpc-url",
            rpc,
        ])
    };
    assert_eq!(pulled(&h), "0", "open before the cancel");
    let q = sdk
        .op()
        .quote(p.clone(), SubmitPath::SelfRelay { payer: key })
        .await
        .unwrap();
    let op = sdk.op().submit(p, q).await.unwrap();
    let last = follow(&sdk, op).await;
    assert!(matches!(last, OpState::Landed { .. }), "{last:?}");
    assert_ne!(pulled(&h), "0", "closed on the token");
}

/// A local anvil with the contracts' own `script/Deploy.s.sol` deployed (the demo token held by the seed's EVM key 0, funded):
/// the node, its URL, the deploy book, the chain's `chain_uid` and that key's address (the bls-multi e2e's shape over
/// [`anvil`] and [`deploy`]: a port from the OS, one forge script at a time).
async fn deployed() -> (Anvil, String, serde_json::Value, String, String) {
    let (a, rpc) = anvil().await;
    let port = rpc.rsplit(':').next().unwrap().to_string();
    let holder = funded_holder(&rpc);
    let name = format!("local-31337-{port}-testnet");
    let dep = deploy(
        &rpc,
        &name,
        &[("DEMO_SUPPLY", "1000000000000"), ("DEMO_HOLDER", &holder)],
    );
    let uid = cast(&["block", "0", "--field", "hash", "--rpc-url", &rpc]);
    (a, rpc, dep, uid, holder)
}

/// `op` followed to a terminal state (≤ 30 s): `Landed`.
async fn landed(sdk: &Arc<Sdk>, op: &str) {
    let mut last = None;
    for _ in 0..60 {
        let s = sdk.op().state(op.to_string()).await.unwrap();
        if s.is_terminal() {
            last = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(matches!(last, Some(OpState::Landed { .. })), "{last:?}");
}

/// Plan Task 17 (spec 2026-11-19-bls12381-multi §4, §5.4, §8.4), on anvil with the deploy's registry (0x0121 enabled where
/// EIP-2537 answers): a group of three of the seed's member keys (t = 2) registers by `registerBlsMulti` (every member's PoP
/// part, the quote by n from the reference table, a self-relay by the EVM key), receives a pay, and spends by a transfer on
/// ids that two members sign: partials collected, aggregated (minimal), self-relayed, `Landed`. Local only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn e2e_bls_multi_on_anvil() {
    let (_anvil, rpc, dep, uid, _) = deployed().await;
    let token = dep["demo_token"].as_str().unwrap().to_ascii_lowercase();
    let registry = dep["ua_registry"].as_str().unwrap().to_ascii_lowercase();
    let profile = ChainProfile {
        key: "anvil".into(),
        family: Family::Evm,
        chain_id: Some(31337),
        chain_uid: uid,
        rpc: vec![endpoint(&rpc)],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: Some(registry.clone()),
        factory: None,
        router: None,
        finality: Finality::Depth(0),
        tx_gas_cap: Some(1 << 24),
        tokens: vec![ListedToken {
            address: token.clone(),
            symbol: "DEMO".into(),
            decimals: 0,
        }],
        // the reference table's rows: the registration, the native pay, the transfer and signer 289's verify row
        gas: with_tx(GasRows {
            base: vec![],
            verify: vec![],
        }),
        max_valid_secs: None,
        gas_opt_in: vec!["reference".into()],
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
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
        clock: None,
        gas_tables: vec![],
    })
    .await
    .unwrap();
    let seed = sdk
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words: sec(REPO),
            vault_passphrase: sec(PASS),
        })
        .await
        .unwrap()
        .id;
    let payer = KeyRef::Native {
        seed: seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    // the group: member keys ua_key(0x0121, a, 0), a = 0, 1, 2; t = 2
    let w = Wallet::from_mnemonic(REPO, "").unwrap();
    let keys: Vec<[u8; 256]> = (0..3)
        .map(|a| {
            w.ua_key(0x0121, a, 0)
                .unwrap()
                .key_data()
                .try_into()
                .unwrap()
        })
        .collect();
    let (d, _) = scaas_ua::bls_multi::build_key_data_unweighted(&keys, 2).unwrap();
    let ua = scaas_ua::bls_multi::ua_of(&d);
    let d = format!("0x{}", alloy::hex::encode(&d));
    let member = |account: u32| KeyRef::BlsMulti {
        seed: seed.clone(),
        account,
        index: 0,
        key_data: d.clone(),
    };
    let op = sdk.op();
    let pops: Vec<BlsMultiPart> = (0..3)
        .map(|a| op.bls_multi_pop_part(member(a)).unwrap())
        .collect();
    let q = op
        .quote_register_bls_multi("anvil".into(), d.clone(), payer.clone())
        .await
        .unwrap();
    let tx = op
        .register_bls_multi("anvil".into(), d.clone(), pops, q)
        .await
        .unwrap();
    let ua_hex = format!("0x{}", alloy::hex::encode(ua));
    let mut registered = String::new();
    for _ in 0..60 {
        registered = cast(&[
            "call",
            &registry,
            "isRegistered(bytes32)(bool)",
            &ua_hex,
            "--rpc-url",
            &rpc,
        ]);
        if registered == "true" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(registered, "true", "registerBlsMulti {tx}");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let envelope = || Envelope {
        valid_until: now + 600,
        mode: 0,
        relayer: None,
        fee: "0".into(),
        fee_recipient: None,
    };
    // the holder pays the group's UA
    let p = sdk
        .wallet()
        .prepare_pay(Pay {
            signer: payer.clone(),
            chain: "anvil".into(),
            token: token.clone(),
            to: ua_hex.clone(),
            value: "1000".into(),
            meta: PayMeta {
                salt: None,
                pay_no: None,
                save: false,
                body: PayBody::None,
            },
            envelope: envelope(),
        })
        .await
        .unwrap();
    let q = op
        .quote(
            p.clone(),
            SubmitPath::SelfRelay {
                payer: payer.clone(),
            },
        )
        .await
        .unwrap();
    let paid = op.submit(p, q).await.unwrap();
    landed(&sdk, &paid).await;
    // the group spends: members 0 and 2 sign, member 0 coordinates
    let p = sdk
        .wallet()
        .prepare_transfer(Transfer {
            signer: member(0),
            chain: "anvil".into(),
            token: token.clone(),
            to: format!("0x{}{}", "00".repeat(12), "beef".repeat(10)),
            value: "7".into(),
            batch: "3".into(),
            envelope: envelope(),
        })
        .await
        .unwrap();
    let parts = vec![
        op.bls_multi_part(p.clone(), member(0)).await.unwrap(),
        op.bls_multi_part(p.clone(), member(2)).await.unwrap(),
    ];
    assert!(parts.iter().all(|x| op.bls_multi_part_ok(&p, x)));
    let q = op
        .quote(p.clone(), SubmitPath::SelfRelay { payer })
        .await
        .unwrap();
    let spent = op.submit_bls_multi(p, q, parts, false).await.unwrap();
    landed(&sdk, &spent).await;
}

/// The largest `bls12381-multi` group (unweighted, threshold `n / 2 + 1`) whose registration fitted one transaction in every
/// run on the local Nethermind copy, a chain capping the regular gas at 2^24 (`SCAAS_M20_BLS_FIND=1` measures it again):
/// `register_bls_multi` counts the whole raise above the table's quote as regular gas (owner 2026-11-22, "keep it as it
/// is"; decisions CLI-SDK-32's Change), so a larger group is refused `GasAboveTxCap` and must be split. 46 sits on the
/// edge (refused in one run, sent in another: the node's estimate moves with the chain's state); 47 and 48 were refused.
const BLS_MULTI_MAX_FIT: u32 = 45;
/// The smallest group refused in every run (the twin above the edge).
const BLS_MULTI_REFUSED: u32 = 48;

/// One `registerBlsMulti` of the group of members `first..first + n` (seed accounts, index 0) by self-relay: the quote, then
/// the registration (`Ok(tx)` sent, or the SDK's refusal before anything is signed). Each probe takes members no earlier
/// registration named: a member key the registry already holds makes the next group's estimate smaller (measured: 46
/// members refused on fresh keys, sent after a 45-member group of the same keys had landed).
async fn register_group(
    sdk: &Arc<Sdk>,
    seed: &str,
    payer: &KeyRef,
    first: u32,
    n: u32,
) -> Result<(String, [u8; 32]), scaas_sdk::SdkError> {
    let w = Wallet::from_mnemonic(REPO, "").unwrap();
    let keys: Vec<[u8; 256]> = (first..first + n)
        .map(|a| {
            w.ua_key(0x0121, a, 0)
                .unwrap()
                .key_data()
                .try_into()
                .unwrap()
        })
        .collect();
    let (d, _) = scaas_ua::bls_multi::build_key_data_unweighted(&keys, n as u16 / 2 + 1).unwrap();
    let ua = scaas_ua::bls_multi::ua_of(&d);
    let d = format!("0x{}", alloy::hex::encode(&d));
    let member = |account: u32| KeyRef::BlsMulti {
        seed: seed.into(),
        account,
        index: 0,
        key_data: d.clone(),
    };
    let op = sdk.op();
    let pops: Vec<BlsMultiPart> = (first..first + n)
        .map(|a| op.bls_multi_pop_part(member(a)).unwrap())
        .collect();
    let q = op
        .quote_register_bls_multi("copy".into(), d.clone(), payer.clone())
        .await?;
    println!(
        "M20 bls n {n} quote gas_limit {} regular_gas {}",
        q.gas_limit, q.regular_gas
    );
    let tx = op.register_bls_multi("copy".into(), d, pops, q).await;
    println!(
        "M20 bls n {n} register {}",
        tx.as_ref().map_or_else(|e| e.code(), |_| "sent")
    );
    Ok((tx?, ua))
}

/// Merged-tree review M20 (owner 2026-11-20) and the owner's ruling of 2026-11-22 on the raise: `register_bls_multi` against a
/// node that enforces EIP-7825 under EIP-8037 (a local Nethermind copy, never the live stack). A 64-member group is refused
/// `GasAboveTxCap` before anything is sent (the payer's pending nonce unchanged); [`BLS_MULTI_REFUSED`] members are refused the
/// same way, and the largest group that fitted in every run, [`BLS_MULTI_MAX_FIT`], lands. Env: `SCAAS_M20_RPC` (the copy's URL), `SCAAS_M20_BOOK` (the
/// deploy book), `SCAAS_M20_CHAIN_ID`; the seed's EVM key 0 funded; `SCAAS_M20_BLS_FIND=1` searches the largest count first
/// (each fitting probe lands). Prints `M20` lines; the run script records them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a local Nethermind copy with Amsterdam rules (clients/scaas-sdk/runs/2026-11-20-m20-nethermind.sh)"]
async fn e2e_bls_multi_group_limit_on_a_node() {
    let rpc = std::env::var("SCAAS_M20_RPC").expect("SCAAS_M20_RPC");
    let dep: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(std::env::var("SCAAS_M20_BOOK").unwrap()).unwrap(),
    )
    .unwrap();
    let chain_id: u64 = std::env::var("SCAAS_M20_CHAIN_ID")
        .unwrap()
        .parse()
        .unwrap();
    let registry = dep["ua_registry"].as_str().unwrap().to_ascii_lowercase();
    let uid = cast(&["block", "0", "--field", "hash", "--rpc-url", &rpc]);
    let profile = ChainProfile {
        key: "copy".into(),
        family: Family::Evm,
        chain_id: Some(chain_id),
        chain_uid: uid,
        rpc: vec![endpoint(&rpc)],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: Some(registry.clone()),
        factory: None,
        router: None,
        finality: Finality::Depth(1),
        tx_gas_cap: Some(1 << 24),
        tokens: vec![],
        gas: with_tx(GasRows {
            base: vec![],
            verify: vec![],
        }),
        max_valid_secs: None,
        gas_opt_in: vec!["reference".into()],
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        dexes: vec![],
        wrappers: vec![],
        l1_fee: None,
        pinned_reads: true,
        disabled_kinds: vec![],
        family_params: None,
    };
    // the app raises `max_gas` for this run: the default 2^24 holds the whole gas limit
    let sdk = Sdk::open(SdkConfig {
        profiles: vec![profile],
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits {
            max_gas: 1 << 27,
            ..Limits::default()
        },
        clock: None,
        gas_tables: vec![],
    })
    .await
    .unwrap();
    let seed = sdk
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words: sec(REPO),
            vault_passphrase: sec(PASS),
        })
        .await
        .unwrap()
        .id;
    let payer = KeyRef::Native {
        seed: seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    let holder = cast(&["wallet", "address", "--mnemonic", REPO]);
    // the pending nonce: a refusal sends nothing, while an earlier probe's transaction may still be mining
    let nonce = || cast(&["nonce", &holder, "--block", "pending", "--rpc-url", &rpc]);
    let refused = |r: Result<(String, [u8; 32]), scaas_sdk::SdkError>| match r {
        Err(e) => e.code(),
        Ok((tx, _)) => panic!("sent {tx}"),
    };
    // the ruling: 64 members refused before anything is signed or sent
    let before = nonce();
    assert_eq!(
        refused(register_group(&sdk, &seed, &payer, 0, 64).await),
        "GasAboveTxCap"
    );
    assert_eq!(nonce(), before, "nothing sent for 64 members");
    // the largest count that fits: measured (each fitting probe lands), else the pinned figure
    if std::env::var("SCAAS_M20_BLS_FIND").is_ok() {
        let (mut lo, mut hi) = (2u32, 64u32); // a group has at least 2 members; lo fits (landed below), hi refused
        let mut first = 100;
        while hi - lo > 1 {
            let mid = (lo + hi) / 2;
            first += 64; // fresh members for every probe
            match register_group(&sdk, &seed, &payer, first, mid).await {
                Ok(_) => lo = mid,
                Err(e) => {
                    assert_eq!(e.code(), "GasAboveTxCap", "{mid} members");
                    hi = mid
                }
            }
        }
        println!("M20 bls largest fitting group {lo}");
    }
    // the twin above the edge is refused, nothing sent; the pinned largest group lands
    let max = BLS_MULTI_MAX_FIT;
    let before = nonce();
    assert_eq!(
        refused(register_group(&sdk, &seed, &payer, 1000, BLS_MULTI_REFUSED).await),
        "GasAboveTxCap"
    );
    assert_eq!(
        nonce(),
        before,
        "nothing sent for {BLS_MULTI_REFUSED} members"
    );
    let ua_hex = |ua: [u8; 32]| format!("0x{}", alloy::hex::encode(ua));
    let is_registered = |ua: &str| {
        cast(&[
            "call",
            &registry,
            "isRegistered(bytes32)(bool)",
            ua,
            "--rpc-url",
            &rpc,
        ])
    };
    let (tx, ua) = match register_group(&sdk, &seed, &payer, 2000, max).await {
        Ok(x) => x,
        Err(e) => panic!("{max} members: {}", e.code()),
    };
    println!("M20 tx {tx}");
    let mut registered = String::new();
    for _ in 0..120 {
        registered = is_registered(&ua_hex(ua));
        if registered == "true" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }
    let receipt = cast(&["receipt", &tx, "--json", "--rpc-url", &rpc]);
    let r: serde_json::Value = serde_json::from_str(&receipt).unwrap();
    println!(
        "M20 receipt status {} gasUsed {} block {}",
        r["status"], r["gasUsed"], r["blockNumber"]
    );
    assert_eq!(
        registered, "true",
        "registerBlsMulti of {max} included {tx}"
    );
}

/// Merged-tree review M20 (owner 2026-11-20), the PQZ part: one PQZ debit (`mtxConfidentialTransferSingle`) by SDK self-relay
/// on the copy (the `PQZ` precompile verifies the proof): two `mldsa65` UAs registered with their PQZ keys (split when the
/// cap requires it), the payer's public units shielded to the holder, both halves of its account prepared, then the single
/// transfer to the other UA. Env as `e2e_bls_multi_group_limit_on_a_node` plus `SCAAS_M20_TOKEN` (a `NORMAL_PQZ` token whose public
/// units the seed's EVM key 0 holds). Prints one `M20` line per figure.
#[cfg(feature = "pqz")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a local Nethermind copy with the PQZ precompile (clients/scaas-sdk/runs/2026-11-20-m20-nethermind.sh)"]
async fn e2e_pqz_debit_on_a_node() {
    use scaas_sdk::account::{Register, RegisterAttrs};
    use scaas_sdk::confidential::{PqzAccountOp, PqzShield, PqzTransfer};
    let rpc = std::env::var("SCAAS_M20_RPC").expect("SCAAS_M20_RPC");
    // the payer: the seed's EVM key 0 (funded by the runner)
    let holder = Wallet::from_mnemonic(REPO, "")
        .unwrap()
        .native_key(Network::Evm, 0, None)
        .unwrap()
        .address()
        .unwrap();
    let dep: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(std::env::var("SCAAS_M20_BOOK").unwrap()).unwrap(),
    )
    .unwrap();
    let chain_id: u64 = std::env::var("SCAAS_M20_CHAIN_ID")
        .unwrap()
        .parse()
        .unwrap();
    let token = std::env::var("SCAAS_M20_TOKEN")
        .unwrap()
        .to_ascii_lowercase();
    let registry = dep["ua_registry"].as_str().unwrap().to_ascii_lowercase();
    let factory = dep["token_factory"].as_str().unwrap().to_ascii_lowercase();
    let profile_with = |cap: Option<u64>| {
        let mut profile = registry_profile(&rpc, &registry, cap);
        (profile.key, profile.chain_id, profile.finality) =
            ("copy".into(), Some(chain_id), Finality::Depth(1));
        profile.factory = Some(factory.clone());
        profile.gas_opt_in = vec!["reference".into()];
        profile.tokens = vec![ListedToken {
            address: token.clone(),
            symbol: "m20PQ".into(),
            decimals: 6,
        }];
        profile
    };
    let open = |cap: Option<u64>| {
        let profile = profile_with(cap);
        async move {
            let sdk = Sdk::open(SdkConfig {
                profiles: vec![profile],
                store: MemoryStore::new(),
                authenticator: None,
                rp_id: None,
                runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
                limits: Limits {
                    max_gas: 1 << 27,
                    ..Limits::default()
                },
                clock: None,
                gas_tables: vec![],
            })
            .await
            .unwrap();
            let seed = sdk
                .vault()
                .import_words(ImportWords {
                    label: "main".into(),
                    words: sec(REPO),
                    vault_passphrase: sec(PASS),
                })
                .await
                .unwrap()
                .id;
            (sdk, seed)
        }
    };
    // the registrations on the capped profile (owner ruling 2026-11-20): quoted from the gas table's rows, one transaction
    // when it fits (whole <= 50 % of the block gas limit, regular <= the cap), else `register` then `storePqzPop`
    let (sdk, seed) = open(Some(1 << 24)).await;
    let payer = KeyRef::Native {
        seed: seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    let ua_key = |account: u32| KeyRef::Ua {
        seed: seed.clone(),
        kind: 0x0131,
        account,
        index: 0,
    };
    let acc = sdk.account();
    let mut uas = vec![];
    for a in [1u32, 2] {
        let writes = acc
            .prepare_register(Register {
                key: ua_key(a),
                chain: "copy".into(),
                attrs: RegisterAttrs {
                    pqz_key: true,
                    kem: false,
                },
                payer: payer.clone(),
            })
            .await
            .unwrap();
        uas.push(writes[0].ua());
        println!(
            "M20 register {a} form: {} transaction(s) {:?}",
            writes.len(),
            writes.iter().map(|w| w.entry()).collect::<Vec<_>>()
        );
        for w in writes {
            let q = acc.quote_registry_write(w.clone()).await.unwrap();
            println!(
                "M20 register {a} {} quote gas_limit {} regular_gas {}",
                w.entry(),
                q.gas_limit,
                q.regular_gas
            );
            let limit = q.gas_limit;
            let op = acc.submit_registry_write(w.clone(), q).await.unwrap();
            let s = follow(&sdk, op).await;
            let (line, used) = receipt_line(&rpc, &holder, &s);
            println!("M20 register {a} {} {line}", w.entry());
            assert!(matches!(s, OpState::Landed { .. }), "{}: {s:?}", w.entry());
            // owner 2026-11-20 (the registry-write margin lowered): the quote never below the gas the node used
            assert!(
                used.is_some_and(|u| u <= limit),
                "{}: gasUsed {used:?} above the quote {limit}",
                w.entry()
            );
        }
        let r = acc
            .registration_of("copy".into(), uas.last().unwrap().clone())
            .await
            .unwrap();
        println!("M20 registered {a} proven {}", r.pqz_proven);
    }
    let envelope = || Envelope {
        valid_until: now() + 600,
        mode: 0,
        relayer: None,
        fee: "0".into(),
        fee_recipient: None,
    };
    let op = sdk.op();
    let run = |p: std::sync::Arc<scaas_sdk::op::Prepared>, label: &'static str| {
        let (op, sdk, payer, rpc, holder) = (
            op.clone(),
            sdk.clone(),
            payer.clone(),
            rpc.clone(),
            holder.clone(),
        );
        async move {
            let q = op
                .quote(p.clone(), SubmitPath::SelfRelay { payer })
                .await
                .unwrap();
            println!(
                "M20 {label} quote gas_limit {} regular_gas {}",
                q.gas_limit, q.regular_gas
            );
            let limit = q.gas_limit;
            let id = op.submit(p, q).await.unwrap();
            let s = follow(&sdk, id).await;
            let (line, used) = receipt_line(&rpc, &holder, &s);
            println!("M20 {label} {line}");
            assert!(matches!(s, OpState::Landed { .. }), "{label}: {s:?}");
            assert!(
                used.is_some_and(|u| u <= limit),
                "{label}: gasUsed {used:?} above the quote {limit}"
            );
        }
    };
    let conf = sdk.confidential();
    let shield = conf
        .prepare_pqz_shield(PqzShield {
            signer: payer.clone(),
            chain: "copy".into(),
            token: token.clone(),
            batch: "0".into(),
            to_ua: uas[0].clone(),
            amount: "1000000".into(),
            envelope: envelope(),
        })
        .await
        .unwrap();
    run(shield, "shield").await;
    for half in ["0", "1"] {
        let p = conf
            .prepare_pqz_prepare_acc(PqzAccountOp {
                signer: ua_key(1),
                chain: "copy".into(),
                token: token.clone(),
                batch: "0".into(),
                ua: uas[0].clone(),
                key_version: 0,
                value: half.into(),
                envelope: envelope(),
            })
            .await
            .unwrap();
        run(p, "prepare_acc").await;
    }
    let block: u64 = cast(&["block-number", "--rpc-url", &rpc]).parse().unwrap();
    let debit = conf
        .prepare_pqz_transfer(PqzTransfer {
            signer: ua_key(1),
            chain: "copy".into(),
            token: token.clone(),
            batch: "1".into(),
            key_version: 0,
            to_ua: uas[1].clone(),
            amount: "30".into(),
            valid_until_block: block + 200,
            envelope: envelope(),
        })
        .await
        .unwrap();
    run(debit, "transfer_single").await;
}

/// An operation's end with its transaction's receipt (status, `gasUsed`) when it landed (the M20 record), and that
/// `gasUsed`: a `Landed` names the block of the operation's fact (its hash), so the payer's transaction is found in that block.
#[cfg(feature = "pqz")]
fn receipt_line(rpc: &str, payer: &str, s: &OpState) -> (String, Option<u64>) {
    match s {
        OpState::Landed { block, .. } => {
            // the block by number through the raw RPC (its `transactions`: the hashes)
            let b: serde_json::Value = serde_json::from_str(&cast(&[
                "rpc",
                "eth_getBlockByNumber",
                &format!("{block:#x}"),
                "false",
                "--rpc-url",
                rpc,
            ]))
            .unwrap();
            let (mut out, mut gas) = (format!("landed block {block}"), None);
            for tx in b["transactions"]
                .as_array()
                .unwrap_or_else(|| panic!("no transactions in {b}"))
            {
                let tx = tx
                    .as_str()
                    .map_or_else(|| tx["hash"].as_str().unwrap().to_string(), String::from);
                let r: serde_json::Value = serde_json::from_str(&cast(&[
                    "receipt",
                    &tx,
                    "--json",
                    "--async",
                    "--rpc-url",
                    rpc,
                ]))
                .unwrap();
                if r["from"]
                    .as_str()
                    .is_some_and(|f| f.eq_ignore_ascii_case(payer))
                {
                    let used = u64::from_str_radix(
                        r["gasUsed"].as_str().unwrap().trim_start_matches("0x"),
                        16,
                    )
                    .unwrap();
                    out += &format!(" tx {tx} status {} gasUsed {used}", r["status"]);
                    gas = Some(used);
                }
            }
            (out, gas)
        }
        other => (format!("state {other:?}"), None),
    }
}

/// Plan T21's two path controls (spec §12.2, §18 "App cores"): an app record signed through the SDK is accepted by the deployed
/// registry itself, path A by `requirePortableApp` (a registered `secp256k1` UA), path B by `requireAuthorized` (the same UA,
/// and the seed's native EVM key over `UAAuth`), and `verify_app_record` agrees; the control's twin (one signature byte
/// changed) is refused by the registry.
#[cfg(feature = "app-core")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn e2e_app_records_on_anvil() {
    use scaas_sdk::app_core::{AppCore, AppDesc, AppPath, AppUaSig};
    const SECP: u16 = 0x0108;
    const APP_ID: &str = "0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
    let (_anvil, rpc) = anvil().await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    funded_holder(rpc);
    let dep = deploy(rpc, &format!("local-31337-{port}-testnet"), &[]);
    let registry = dep["ua_registry"].as_str().unwrap().to_ascii_lowercase();
    let (sdk, seed) = sdk_on(registry_profile(rpc, &registry, Some(1 << 24))).await;
    let ua = register_with_sdk(&sdk, &seed, SECP, 0, false).await;
    let core = AppCore::new(
        sdk.clone(),
        AppDesc {
            app_id: Some(APP_ID.into()),
            name: "E2E App".into(),
            class: None,
            labels: vec!["scaas/e2e-app/v1/".into()],
        },
    )
    .unwrap();
    let record = |domain: serde_json::Value| {
        let mut fields = vec![
            serde_json::json!({"name": "name", "type": "string"}),
            serde_json::json!({"name": "version", "type": "string"}),
        ];
        for (k, t) in [
            ("chainId", "uint256"),
            ("verifyingContract", "address"),
            ("salt", "bytes32"),
        ] {
            if domain.get(k).is_some() {
                fields.push(serde_json::json!({"name": k, "type": t}));
            }
        }
        serde_json::json!({
            "types": {"EIP712Domain": fields, "Note": [{"name": "id", "type": "bytes32"}, {"name": "body", "type": "string"}]},
            "primaryType": "Note",
            "domain": domain,
            "message": {"id": format!("0x{}", "11".repeat(32)), "body": "hello"},
        })
        .to_string()
    };
    let hx = |b: &[u8]| {
        format!(
            "0x{}",
            b.iter().map(|x| format!("{x:02x}")).collect::<String>()
        )
    };
    let ok = |args: &[&str]| {
        let out = Command::new("cast")
            .args(["call", "--rpc-url", rpc, &registry])
            .args(args)
            .output()
            .expect("cast in PATH");
        out.status.success()
    };
    let flipped = |s: &[u8]| {
        let mut s = s.to_vec();
        s[7] ^= 1;
        s
    };
    let key = KeyRef::Ua {
        seed: seed.clone(),
        kind: SECP,
        account: 0,
        index: 0,
    };
    let uasig = "(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])";

    // path A: requirePortableApp(ua, appId, typedDigest, UASig{"", sig, []})
    let pa = record(serde_json::json!({"name": "E2E App", "version": "1", "salt": APP_ID}));
    let sa = core
        .sign_app_record(key.clone(), AppPath::Portable, pa.clone())
        .await
        .unwrap();
    let call_a = |sig: &[u8]| {
        ok(&[
            &format!("requirePortableApp(bytes32,bytes32,bytes32,{uasig})"),
            &ua,
            APP_ID,
            &sa.digest,
            &format!("({},{},[])", hx(&sa.key_data), hx(sig)),
        ])
    };
    assert!(
        call_a(&sa.signature),
        "requirePortableApp accepts the SDK's record"
    );
    assert!(
        !call_a(&flipped(&sa.signature)),
        "the twin: one byte changed"
    );
    let v = |p: AppPath, t: String, u: String, key_data: Vec<u8>, signature: Vec<u8>| {
        let core = core.clone();
        async move {
            core.verify_app_record(
                "anvil".into(),
                u,
                p,
                t,
                AppUaSig {
                    key_data,
                    signature,
                    members: vec![],
                },
            )
            .await
            .unwrap()
        }
    };
    assert!(
        v(
            AppPath::Portable,
            pa.clone(),
            ua.clone(),
            vec![],
            sa.signature.clone()
        )
        .await
    );

    // path B: requireAuthorized(ua, appPurpose(appId), typedDigest, UASig{keyData, sig, []}), by the UA and by the native key
    let cb = record(
        serde_json::json!({"name": "E2E App", "version": "1", "chainId": "31337",
        "verifyingContract": "0x00000000000000000000000000000000000000aa"}),
    );
    let b = || AppPath::ChainBound {
        chain: "anvil".into(),
        purpose: None,
    };
    let app_id: [u8; 32] = alloy::hex::decode(&APP_ID[2..])
        .unwrap()
        .try_into()
        .unwrap();
    let purpose = hx(&scaas_ua::ua_portable::app_purpose(&app_id).unwrap());
    let sb = core.sign_app_record(key, b(), cb.clone()).await.unwrap();
    let call_b = |who: &str, key_data: &[u8], sig: &[u8], digest: &str| {
        ok(&[
            &format!("requireAuthorized(bytes32,bytes32,bytes32,{uasig})"),
            who,
            &purpose,
            digest,
            &format!("({},{},[])", hx(key_data), hx(sig)),
        ])
    };
    assert!(
        call_b(&ua, &sb.key_data, &sb.signature, &sb.digest),
        "requireAuthorized accepts the UA's record"
    );
    assert!(
        !call_b(&ua, &sb.key_data, &flipped(&sb.signature), &sb.digest),
        "the twin"
    );
    assert!(
        v(
            b(),
            cb.clone(),
            ua.clone(),
            sb.key_data.clone(),
            sb.signature.clone()
        )
        .await
    );
    let native = KeyRef::Native {
        seed: seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    let sn = core.sign_app_record(native, b(), cb.clone()).await.unwrap();
    let holder = Wallet::from_mnemonic(REPO, "")
        .unwrap()
        .native_key(Network::Evm, 0, None)
        .unwrap()
        .address()
        .unwrap()
        .to_ascii_lowercase();
    let nid = format!("0x{:0>64}", holder.trim_start_matches("0x"));
    assert!(
        call_b(&nid, &[], &sn.signature, &sn.digest),
        "requireAuthorized accepts the native key's record"
    );
    assert!(
        !call_b(&nid, &[], &flipped(&sn.signature), &sn.digest),
        "the twin"
    );
    assert!(v(b(), cb, nid, vec![], sn.signature.clone()).await);
}

/// Plan T41.evm (spec §27.5 (c)) on `anvil`: A (the seed's EVM key 0, the token holder) signs a pay to B (key 1, holding only
/// ether) and hands it off; B imports it, quotes a self-relay by its own key, submits it and sees `Landed`, and A's handed-off
/// row ends `Landed` by the same fact; the same blob again is `ImportConsumed`; a blob bound to C (key 2) is
/// `ImportRelayerBound` for B; A's own self-relay of its own pay lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn e2e_hand_off_on_anvil() {
    use scaas_sdk::op::ImportExpect;
    let (_anvil, rpc) = anvil().await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    let holder = funded_holder(rpc);
    let w = Wallet::from_mnemonic(REPO, "").unwrap();
    let addr = |i| {
        w.native_key(Network::Evm, i, None)
            .unwrap()
            .address()
            .unwrap()
            .to_ascii_lowercase()
    };
    let (b, c) = (addr(1), addr(2));
    cast(&[
        "rpc",
        "--rpc-url",
        rpc,
        "anvil_setBalance",
        &b,
        "0x8ac7230489e80000",
    ]);
    let name = format!("local-31337-{port}-testnet");
    let dep = deploy(
        rpc,
        &name,
        &[("DEMO_SUPPLY", "1000000000000"), ("DEMO_HOLDER", &holder)],
    );
    let token = dep["demo_token"].as_str().unwrap().to_ascii_lowercase();
    let uid = cast(&["block", "0", "--field", "hash", "--rpc-url", rpc]);
    let row = |fresh| GasBase {
        entry: "mtxPay".into(),
        kind: "token".into(),
        fresh,
        gas: 400_000,
        per_byte: None,
        save: None,
        fee_extra: None,
        ua_extra: None,
        per_item: None,
        regular: None,
    };
    let profile = ChainProfile {
        key: "anvil".into(),
        family: Family::Evm,
        chain_id: Some(31337),
        chain_uid: uid,
        rpc: vec![endpoint(rpc)],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: None,
        factory: None,
        router: None,
        finality: Finality::Depth(0),
        tx_gas_cap: Some(1 << 24),
        tokens: vec![ListedToken {
            address: token.clone(),
            symbol: "DEMO".into(),
            decimals: 0,
        }],
        gas: with_tx(GasRows {
            base: vec![row(true), row(false)],
            verify: vec![GasVerify {
                line: Default::default(),
                signer: 0,
                gas: 0,
                sig_bytes: 0,
                margin: 0,
                per_item: None,
            }],
        }),
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
    let (sa, seed_a) = sdk_on(profile.clone()).await;
    let (sb, seed_b) = sdk_on(profile).await;
    let key = |seed: &str, index| KeyRef::Native {
        seed: seed.into(),
        network: "evm".into(),
        index,
    };
    let to_b = format!("0x{}{}", "00".repeat(12), &b[2..]);
    let pay = |no: &str, mode: u32, relayer: Option<String>| Pay {
        signer: key(&seed_a, 0),
        chain: "anvil".into(),
        token: token.clone(),
        to: to_b.clone(),
        value: "1000".into(),
        meta: PayMeta {
            salt: None,
            pay_no: Some(format!("0x{no:0>64}")),
            save: false,
            body: PayBody::Note {
                note: "hand-off".into(),
            },
        },
        envelope: Envelope {
            valid_until: now() + 600,
            mode,
            relayer,
            fee: "0".into(),
            fee_recipient: None,
        },
    };
    let expect = ImportExpect {
        chain: "anvil".into(),
        payee: vec![to_b.clone()],
        payer: key(&seed_b, 1),
    };
    // A hands off; B imports, quotes, submits: Landed, and A's row with it
    let p = sa.wallet().prepare_pay(pay("1", 0, None)).await.unwrap();
    let blob = sa.op().hand_off(p.clone()).await.unwrap();
    let imported = sb
        .op()
        .import_signed(blob.clone(), expect.clone())
        .await
        .unwrap();
    let q = sb
        .op()
        .quote(
            imported.clone(),
            SubmitPath::SelfRelay {
                payer: key(&seed_b, 1),
            },
        )
        .await
        .unwrap();
    let op = sb.op().submit(imported, q).await.unwrap();
    let last = follow(&sb, op).await;
    assert!(
        matches!(last, OpState::Landed { .. }),
        "B's import: {last:?}"
    );
    assert!(
        matches!(follow(&sa, p.id()).await, OpState::Landed { .. }),
        "A's handed-off row"
    );
    // the same blob again
    let again = sb.op().import_signed(blob, expect.clone()).await;
    assert_eq!(again.err().map(|e| e.code()), Some("ImportConsumed"));
    // a blob bound to C
    let p = sa.wallet().prepare_pay(pay("2", 1, Some(c))).await.unwrap();
    let bound = sa.op().hand_off(p).await.unwrap();
    let r = sb.op().import_signed(bound, expect).await;
    assert_eq!(r.err().map(|e| e.code()), Some("ImportRelayerBound"));
    // A's own self-relay of its own pay
    let p = sa.wallet().prepare_pay(pay("3", 0, None)).await.unwrap();
    let q = sa
        .op()
        .quote(
            p.clone(),
            SubmitPath::SelfRelay {
                payer: key(&seed_a, 0),
            },
        )
        .await
        .unwrap();
    let op = sa.op().submit(p, q).await.unwrap();
    assert!(
        matches!(follow(&sa, op).await, OpState::Landed { .. }),
        "A's own self-relay"
    );
}

/// `rows` with the transaction row at Ethereum's figures (T26 B2-1: the SDK carries no gas figure; a test's table does).
fn with_tx(mut rows: scaas_sdk::GasRows) -> scaas_sdk::GasRows {
    rows.base.push(scaas_sdk::GasBase {
        entry: "transaction".into(),
        kind: "evm".into(),
        fresh: false,
        gas: 21_000,
        per_byte: Some(scaas_sdk::GasPerByte {
            input: "calldata".into(),
            gas: 64,
        }),
        save: None,
        fee_extra: None,
        ua_extra: None,
        per_item: None,
        regular: None,
    });
    rows
}
