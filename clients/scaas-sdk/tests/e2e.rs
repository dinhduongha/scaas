// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T12's e2e pay on `anvil` (gate `sdk-e2e`, ignored by default: needs `anvil`, `forge` and `cast` in PATH and
//! `smartcontracts/evm/lib`): the contracts' own `script/Deploy.s.sol` deploys the factory and a demo `NormalToken` holding
//! half its supply for the seed's EVM key; the SDK prepares a `mtxPay` with `PayMeta` v3, quotes a self-relay by that key
//! (a profile gas row: the table has no native-key row yet), submits it (sign → write → simulate → send), and follows it to
//! `Landed` by the token's executed event. Local only; nothing leaves the machine.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scaas_sdk::op::{KeyRef, OpState, SubmitPath};
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::wallet::{Envelope, Pay, PayBody, PayMeta};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, GasBase, GasRows, GasVerify, Limits,
    ListedToken, RuntimeChoice, Sdk, SdkConfig,
};
use scaas_ua::wallet::{Network, SecretBytes, Wallet};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
/// anvil's first key (a public test key): the deployer
const DEPLOYER: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const DEPLOYER_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

struct Anvil(Child);
impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn sc() -> String {
    format!("{}/../../smartcontracts/evm", env!("CARGO_MANIFEST_DIR"))
}

fn cast(args: &[&str]) -> String {
    let out = Command::new("cast")
        .args(args)
        .output()
        .expect("cast in PATH");
    assert!(
        out.status.success(),
        "cast {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

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

/// An `anvil` on a port of this process (stopped on drop), ready to answer; its URL.
async fn anvil(offset: u16) -> (Anvil, String) {
    let port = 20_000 + offset + (std::process::id() % 10_000) as u16;
    let rpc = format!("http://127.0.0.1:{port}");
    let a = Anvil(
        Command::new("anvil")
            .args([
                "--chain-id",
                "31337",
                "--hardfork",
                "amsterdam",
                "--gas-limit",
                "200000000",
                "--code-size-limit",
                "65536",
                "--port",
                &port.to_string(),
                "--silent",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("anvil in PATH"),
    );
    for _ in 0..100 {
        if Command::new("cast")
            .args(["chain-id", "--rpc-url", &rpc])
            .output()
            .is_ok_and(|o| o.status.success())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    (a, rpc)
}

/// The contracts' own `script/Deploy.s.sol` on `rpc` with `env`; its book (`deployments/<name>.json`, removed after reading).
/// One `forge script` at a time: the tests run in parallel, and forge's broadcast cache of a chain id takes a lock.
fn deploy(rpc: &str, name: &str, env: &[(&str, &str)]) -> serde_json::Value {
    static FORGE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = FORGE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let status = Command::new("forge")
        .current_dir(sc())
        .args([
            "script",
            "script/Deploy.s.sol",
            "--rpc-url",
            rpc,
            "--broadcast",
            "--slow",
            "--silent",
            "--disable-code-size-limit",
            "--sender",
            DEPLOYER_ADDRESS,
        ])
        .env("PRIVATE_KEY", DEPLOYER)
        .env("FOUNDRY_PROFILE", "scaas-testnet")
        .env("DEPLOY_NAME", name)
        .envs(env.iter().copied())
        .status()
        .expect("forge in PATH");
    assert!(status.success(), "forge script failed");
    let book = format!("{}/deployments/{name}.json", sc());
    let dep = serde_json::from_str(&std::fs::read_to_string(&book).unwrap()).unwrap();
    let _ = std::fs::remove_file(&book);
    dep
}

/// The seed's EVM key 0 (the token holder, the payer), funded with 10 ether.
fn funded_holder(rpc: &str) -> String {
    let holder = Wallet::from_mnemonic(REPO, "")
        .unwrap()
        .native_key(Network::Evm, 0, None)
        .unwrap()
        .address()
        .unwrap();
    cast(&["rpc", "--rpc-url", rpc, "anvil_setBalance", &holder, "0x8ac7230489e80000"]);
    holder
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
    let (_anvil, rpc) = anvil(0).await;
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
        gas: GasRows {
            base: vec![GasBase {
                entry: "mtxPay".into(),
                kind: "token".into(),
                fresh: true,
                gas: 400_000,
            }],
            verify: vec![GasVerify { signer: 0, gas: 0 }],
        },
        max_valid_secs: None,
        gas_opt_in: vec![],
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

/// The Zether UA `0x0141` of the seed's account `account` registered on `registry` with the facade's portable PoP (relayed by
/// the deployer: the SDK has no registration entry for it yet); the UA.
#[cfg(feature = "zether")]
fn register_zether(rpc: &str, registry: &str, account: u32) -> String {
    // the wallet kept open while its key is used (dropping it revokes the handle)
    let w = Wallet::from_mnemonic(REPO, "").unwrap();
    let k = w
        .zether_key(60, account, scaas_ua::facade::zether::USE_CONF)
        .unwrap();
    let p: serde_json::Value =
        serde_json::from_str(&k.call("pop", br#"{"curve":"bls12381"}"#).unwrap()).unwrap();
    let z = format!("0x{}", "00".repeat(32));
    cast(&[
        "send",
        "--rpc-url",
        rpc,
        "--private-key",
        DEPLOYER,
        registry,
        "register(uint16,bytes,(bytes,bytes32,(uint8,bytes,bytes32),bytes32),bytes,bytes)",
        "321",
        p["Y"].as_str().unwrap(),
        &format!("(0x,{z},(0,0x,{z}),{z})"),
        p["pop"].as_str().unwrap(),
        "0x",
    ]);
    p["UA"].as_str().unwrap().to_ascii_lowercase()
}

/// The seed's UA `kind` of wallet `account` (index 0) registered through the SDK (plan T13): each registry write quoted,
/// self-relayed by the seed's EVM key and followed to `Landed` by its record; the UA.
#[cfg(feature = "account")]
async fn register_with_sdk(sdk: &Arc<Sdk>, seed: &str, kind: u16, account: u32, kem: bool) -> String {
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
/// 0 and 1 registered first, a `NORMAL_ZETHER` token created through the factory; the seed's EVM key shields 1234 to account
/// 0's Zether UA and rolls it over, the Zether UA transfers 100 to account 1's (the proof over the reading layer's words,
/// self-relayed by the EVM key), and the balances read back through the reading layer: 1134 spendable, 100 pending.
#[cfg(feature = "zether")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn e2e_zether_shield_transfer_balance_on_anvil() {
    use scaas_sdk::confidential::{ZetherBalanceRequest, ZetherRollOver, ZetherShield, ZetherTransfer};
    let (_anvil, rpc) = anvil(1).await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    let holder = funded_holder(rpc);
    let name = format!("local-31337-{port}-testnet");
    let dep = deploy(rpc, &name, &[("DEPLOY_ZETHER", "true")]);
    let factory = dep["token_factory"].as_str().unwrap().to_ascii_lowercase();
    let registry = dep["zether_registry"].as_str().unwrap().to_ascii_lowercase();
    let (ua0, ua1) = (register_zether(rpc, &registry, 0), register_zether(rpc, &registry, 1));
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
        gas_opt_in: vec![],
    })
    .await;
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
    assert_eq!(balance(0, false).await, "1234", "spendable after the roll-over");
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
    assert_eq!(balance(0, false).await, "1134", "the holder after the transfer");
    assert_eq!(balance(1, true).await, "100", "the recipient's pending after the transfer");
}

/// Plan T13's e2e (spec §7): the seed's `fndsa512` UA (a PQ kind) with its KEM key registered through the SDK on `anvil`'s
/// registry, self-relayed by the seed's EVM key, each write followed to `Landed` by its record; the registry then holds the
/// UA and its KEM key.
#[cfg(feature = "account")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn e2e_register_pq_kind_on_anvil() {
    const FNDSA512: u16 = 0x0132;
    let (_anvil, rpc) = anvil(2).await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    funded_holder(rpc);
    let dep = deploy(rpc, &format!("local-31337-{port}-testnet"), &[]);
    let registry = dep["ua_registry"].as_str().unwrap().to_ascii_lowercase();
    assert_eq!(
        cast(&["call", "--rpc-url", rpc, &registry, "kindEnabled(uint16)(bool)", &FNDSA512.to_string()]),
        "true",
        "fndsa512 enabled on this registry"
    );
    let uid = cast(&["block", "0", "--field", "hash", "--rpc-url", rpc]);
    let (sdk, seed) = sdk_on(ChainProfile {
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
        tokens: vec![],
        gas: GasRows::default(),
        max_valid_secs: None,
        gas_opt_in: vec![],
    })
    .await;
    let ua = register_with_sdk(&sdk, &seed, FNDSA512, 0, true).await;
    let acc = sdk.account();
    let r = acc.registration_of("anvil".into(), ua).await.unwrap();
    assert!(r.registered && r.kem_stored, "{r:?}");
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
    let (_anvil, rpc) = anvil(3).await;
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
        gas: GasRows {
            base: vec![GasBase {
                entry: "mtxPay".into(),
                kind: "token".into(),
                fresh: true,
                gas: 400_000,
            }],
            verify: vec![GasVerify { signer: 0, gas: 0 }],
        },
        max_valid_secs: None,
        gas_opt_in: vec![],
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
    let to: serde_json::Value = serde_json::from_str(&blob).unwrap();
    let to = to["ua"].as_str().unwrap().to_string();
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
            body: PayBody::Note { note: "sponsored".into() },
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
        sender.wallet().prepare_pay(pay()).await.err().map(|e| e.code()),
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
