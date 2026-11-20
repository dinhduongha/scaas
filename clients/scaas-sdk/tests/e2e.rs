// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T12's e2e pay on `anvil` (gate `sdk-e2e`, ignored by default: needs `anvil`, `forge` and `cast` in PATH and
//! `smartcontracts/evm/lib`): the contracts' own `script/Deploy.s.sol` deploys the factory and a demo `NormalToken` holding
//! half its supply for the seed's EVM key; the SDK prepares a `mtxPay` with `PayMeta` v3, quotes a self-relay by that key
//! (a profile gas row: the table has no native-key row yet), submits it (sign → write → simulate → send), and follows it to
//! `Landed` by the token's executed event. Local only; nothing leaves the machine.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scaas_sdk::op::{BlsMultiPart, KeyRef, OpState, SubmitPath};
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::wallet::{Envelope, Pay, PayBody, PayMeta, Transfer};
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

/// A local anvil (Amsterdam) with the contracts' own `script/Deploy.s.sol` deployed: the node, its URL, the deploy book, the
/// chain's `chain_uid` and the seed's EVM key 0's address (funded; the demo token's holder). `slot` picks the port.
async fn deployed(slot: u16) -> (Anvil, String, serde_json::Value, String, String) {
    // one port per test of this process (`slot`), so the two ignored tests may run together
    let port = 20_000 + (std::process::id() % 5_000) as u16 * 2 + slot;
    let rpc = format!("http://127.0.0.1:{port}");
    let _anvil = Anvil(
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
    // the seed's EVM key 0: the token holder, the payer and the signer of the pay (a native id signs its own digest)
    let holder = Wallet::from_mnemonic(REPO, "")
        .unwrap()
        .native_key(Network::Evm, 0, None)
        .unwrap()
        .address()
        .unwrap();
    cast(&[
        "rpc",
        "--rpc-url",
        &rpc,
        "anvil_setBalance",
        &holder,
        "0x8ac7230489e80000",
    ]); // 10 ether
    let name = format!("local-31337-{port}-testnet");
    // one deploy at a time: forge script keeps its broadcast state per chain id (31337) in the shared cache, so two
    // tests deploying at once collide on it
    static DEPLOY: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let one = DEPLOY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let status = Command::new("forge")
        .current_dir(sc())
        .args([
            "script",
            "script/Deploy.s.sol",
            "--rpc-url",
            &rpc,
            "--broadcast",
            "--slow",
            "--silent",
            "--disable-code-size-limit",
            "--sender",
            DEPLOYER_ADDRESS,
        ])
        .env("PRIVATE_KEY", DEPLOYER)
        .env("DEMO_SUPPLY", "1000000000000")
        .env("DEMO_HOLDER", &holder)
        .env("FOUNDRY_PROFILE", "scaas-testnet")
        .env("DEPLOY_NAME", &name)
        .status()
        .expect("forge in PATH");
    assert!(status.success(), "forge script failed");
    drop(one);
    let book = format!("{}/deployments/{name}.json", sc());
    let dep: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&book).unwrap()).unwrap();
    let _ = std::fs::remove_file(&book);
    let uid = cast(&["block", "0", "--field", "hash", "--rpc-url", &rpc]);
    (_anvil, rpc, dep, uid, holder)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn e2e_pay_on_anvil() {
    let (_anvil, rpc, dep, uid, _) = deployed(0).await;
    let token = dep["demo_token"].as_str().unwrap().to_ascii_lowercase();
    let profile = ChainProfile {
        key: "anvil".into(),
        family: Family::Evm,
        chain_id: Some(31337),
        chain_uid: uid,
        rpc: vec![endpoint(&rpc)],
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
                per_byte: None,
                save: None,
                fee_extra: None,
                ua_extra: None,
                per_item: None,
                regular: None,
            }],
            verify: vec![GasVerify {
                signer: 0,
                gas: 0,
                sig_bytes: 0,
                margin: 0,
                per_item: None,
            }],
        },
        max_valid_secs: None,
        gas_opt_in: vec![],
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
    let key = KeyRef::Native {
        seed: seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
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
    let mut last = None;
    for _ in 0..60 {
        let s = sdk.op().state(op.clone()).await.unwrap();
        if s.is_terminal() {
            last = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(matches!(last, Some(OpState::Landed { .. })), "{last:?}");
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
    let (_anvil, rpc, dep, uid, _) = deployed(1).await;
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
        gas: GasRows {
            base: vec![],
            verify: vec![],
        },
        max_valid_secs: None,
        gas_opt_in: vec!["reference".into()],
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
