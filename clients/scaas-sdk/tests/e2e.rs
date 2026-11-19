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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn e2e_pay_on_anvil() {
    let port = 20_000 + (std::process::id() % 10_000) as u16;
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
    let book = format!("{}/deployments/{name}.json", sc());
    let dep: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&book).unwrap()).unwrap();
    let _ = std::fs::remove_file(&book);
    let token = dep["demo_token"].as_str().unwrap().to_ascii_lowercase();
    let uid = cast(&["block", "0", "--field", "hash", "--rpc-url", &rpc]);
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
            }],
            verify: vec![GasVerify { signer: 0, gas: 0 }],
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
