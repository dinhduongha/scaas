// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The chain tests' local chain (gate `pqc-chain`, plan T5–T10). anvil 1.8.5's `--enable-tx-gas-limit` holds a transaction's
//! whole gas limit to 2^24 (EIP-7825 as Osaka has it), and the contracts' deploy and the ML-DSA registrations ask more (their
//! state gas, EIP-8037): so the deploy (`script/Deploy.s.sol` with `DEPLOY_PQCHAT`: the registry, the factory, a `PqChat`
//! release and one listed instance) and the UAs' registrations through the SDK run first on an anvil without the flag, whose
//! state is dumped on exit; the chain every test then writes to is an `anvil --enable-tx-gas-limit` loaded from that state
//! (the same genesis: one fixed timestamp), its positive control first (a transaction above 2^24 gas refused). Every write of
//! the crate runs there, and the harness sends nothing above 2^24 gas (the second line). Local only; each anvil is stopped
//! on drop and its state file removed.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
use pqchat_core::session::Me;
use pqchat_core::{ChainConf, MemoryStore, PqChat, PqChatConfig};
use scaas_sdk::op::KeyRef;
use scaas_sdk::vault::{ImportWords, MemoryStore as Vaults};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, OpState, RuntimeChoice, Sdk, SdkConfig,
    SecretBytes,
};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

pub const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
pub const PASS: &str = "river-otter-7 ünï";
/// anvil's first key (a public test key): the deployer
pub const DEPLOYER: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
pub const DEPLOYER_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
pub const CHAIN: &str = "anvil";
pub const KIND: u16 = 0x0131;
/// EIP-7825's per-transaction cap
pub const TX_CAP: u64 = 1 << 24;

pub struct Anvil(pub Child);
impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn sc() -> String {
    format!("{}/../../smartcontracts/evm", env!("CARGO_MANIFEST_DIR"))
}

pub fn cast_out(args: &[&str]) -> std::process::Output {
    Command::new("cast")
        .args(args)
        .output()
        .expect("cast in PATH")
}

pub fn cast(args: &[&str]) -> String {
    let out = cast_out(args);
    assert!(
        out.status.success(),
        "cast {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// The genesis timestamp of both anvils (one genesis, one chain uid).
const GENESIS: &str = "1767225600";

/// An anvil on `port` answering as chain 31337 (`flags` added), once up.
async fn start(port: u16, flags: &[&str]) -> (Anvil, String) {
    let rpc = format!("http://127.0.0.1:{port}");
    let mut args = vec![
        "--chain-id",
        "31337",
        "--hardfork",
        "amsterdam",
        "--gas-limit",
        "200000000",
        "--code-size-limit",
        "65536",
        "--timestamp",
        GENESIS,
        "--silent",
    ];
    args.extend_from_slice(flags);
    let p = port.to_string();
    args.extend_from_slice(&["--port", &p]);
    let mut a = Anvil(
        Command::new("anvil")
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("anvil in PATH"),
    );
    for _ in 0..300 {
        assert!(
            a.0.try_wait().expect("anvil's state").is_none(),
            "anvil exited (port {port} taken?)"
        );
        let id = Command::new("cast")
            .args(["chain-id", "--rpc-url", &rpc])
            .output();
        if id.is_ok_and(|o| {
            o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "31337"
        }) {
            return (a, rpc);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("anvil on {port} never answered");
}

/// The positive control of the chain's cap: a transaction of 2^24 + 1 gas refused.
fn positive_control(rpc: &str) {
    let over = (TX_CAP + 1).to_string();
    let o = cast_out(&[
        "send",
        "--rpc-url",
        rpc,
        "--private-key",
        DEPLOYER,
        "--gas-limit",
        &over,
        DEPLOYER_ADDRESS,
    ]);
    assert!(
        !o.status.success(),
        "a transaction above 2^24 gas landed: the chain does not enforce EIP-7825"
    );
    println!("[chain] anvil {rpc}: a transaction of 2^24 + 1 gas refused (positive control)");
}

/// The contracts' own deploy with `DEPLOY_PQCHAT`: the book (`deployments/<name>.json`, removed after reading).
pub fn deploy(rpc: &str, name: &str) -> serde_json::Value {
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
        .env("TX_GAS_CAP", TX_CAP.to_string())
        .env("DEPLOY_NAME", name)
        .env("DEPLOY_PQCHAT", "true")
        .status()
        .expect("forge in PATH");
    assert!(status.success(), "forge script failed");
    let book = format!("{}/deployments/{name}.json", sc());
    let dep = serde_json::from_str(&std::fs::read_to_string(&book).unwrap()).unwrap();
    let _ = std::fs::remove_file(&book);
    dep
}

fn sec(s: &str) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(s.as_bytes().to_vec())).unwrap())
}

/// A deployed local chain with the SDK over it.
pub struct Local {
    pub anvil: Anvil,
    pub rpc: String,
    pub sdk: Arc<Sdk>,
    pub seed: String,
    pub registry: String,
    pub factory: String,
    pub home: String,
    pub uid: String,
    pub payer: KeyRef,
}

impl Local {
    pub fn conf(&self) -> PqChatConfig {
        PqChatConfig {
            chains: vec![ChainConf {
                chain: CHAIN.into(),
                chain_uid: self.uid.clone(),
                registry: self.registry.clone(),
                factory: self.factory.clone(),
            }],
        }
    }

    /// The crate over the SDK (one live scope at a time).
    pub fn pq(&self) -> Arc<PqChat> {
        PqChat::new(self.sdk.clone(), Arc::new(MemoryStore::new()), self.conf()).unwrap()
    }

    /// The chain's block gas limit set to `gas` (anvil's own call).
    pub fn block_gas(&self, gas: u64) {
        cast(&[
            "rpc",
            "--rpc-url",
            &self.rpc,
            "evm_setBlockGasLimit",
            &format!("{gas:#x}"),
        ]);
    }

    /// A view through `cast` (outside the crate's scope).
    pub fn call(&self, sig: &str, args: &[&str]) -> String {
        let mut a = vec!["call", "--rpc-url", &self.rpc, &self.home, sig];
        a.extend_from_slice(args);
        cast(&a)
    }
}

/// The SDK over the anvil at `rpc` with the repository seed imported; its seed id.
async fn sdk_at(rpc: &str, uid: &str, registry: &str, factory: &str) -> (Arc<Sdk>, String) {
    let profile = ChainProfile {
        key: CHAIN.into(),
        family: Family::Evm,
        chain_id: Some(31337),
        chain_uid: uid.into(),
        rpc: vec![EndpointConfig {
            url: rpc.into(),
            class: scaas_rpc::Class::Named,
            label: None,
            auth: None,
        }],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: Some(registry.into()),
        factory: Some(factory.into()),
        router: None,
        finality: Finality::Depth(0),
        tx_gas_cap: Some(TX_CAP),
        gas: Default::default(),
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![],
        wrappers: vec![],
        tokens: vec![],
        l1_fee: None,
        disabled_kinds: vec![],
        family_params: None,
    };
    let sdk = Sdk::open(SdkConfig {
        profiles: vec![profile],
        store: Vaults::new(),
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

fn payer_of(seed: &str) -> KeyRef {
    KeyRef::Native {
        seed: seed.into(),
        network: "evm".into(),
        index: 0,
    }
}

/// The deployed chain with the seed's UAs `accounts` registered (`(account, with a KEM key)`), then reloaded under
/// `--enable-tx-gas-limit` after its positive control; the SDK over it and the UAs in their order.
pub async fn local(accounts: &[(u32, bool)]) -> (Local, Vec<Me>) {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("a free port")
        .port();
    let dir = std::env::temp_dir().join(format!("pqchat-core-chain-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.json");
    let st = state.to_str().unwrap().to_string();
    let (a, rpc) = start(port, &["--dump-state", &st]).await;
    let dep = deploy(&rpc, &format!("local-31337-{port}-testnet"));
    let addr = |k: &str| {
        dep[k]
            .as_str()
            .unwrap_or_else(|| panic!("the book has no {k}"))
            .to_ascii_lowercase()
    };
    let (registry, factory, home) = (
        addr("ua_registry"),
        addr("token_factory"),
        addr("pqchat_instance"),
    );
    let uid = cast(&["block", "0", "--field", "hash", "--rpc-url", &rpc]);
    let holder = scaas_ua::wallet::Wallet::from_mnemonic(REPO, "")
        .unwrap()
        .native_key(scaas_ua::wallet::Network::Evm, 0, None)
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
    ]);
    println!("[chain] deployed: registry {registry}, factory {factory}, PqChat {home}");
    let mut mes = vec![];
    {
        let (sdk, seed) = sdk_at(&rpc, &uid, &registry, &factory).await;
        for (account, kem) in accounts {
            mes.push(register(&sdk, &seed, *account, *kem).await);
        }
        println!("[chain] {} UAs registered", mes.len());
    }
    // the state dumped on a graceful stop, then the chain under the cap
    let pid = a.0.id().to_string();
    assert!(Command::new("kill")
        .args(["-INT", &pid])
        .status()
        .unwrap()
        .success());
    let mut a = a;
    a.0.wait().unwrap();
    assert!(state.exists(), "anvil dumped no state");
    let (anvil, rpc) = start(port, &["--enable-tx-gas-limit", "--load-state", &st]).await;
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        cast(&["block", "0", "--field", "hash", "--rpc-url", &rpc]),
        uid,
        "the reloaded chain has another genesis"
    );
    positive_control(&rpc);
    let (sdk, seed) = sdk_at(&rpc, &uid, &registry, &factory).await;
    for m in &mut mes {
        if let KeyRef::Ua { seed: s, .. } = &mut m.key {
            s.clone_from(&seed);
        }
    }
    let payer = payer_of(&seed);
    (
        Local {
            anvil,
            rpc,
            sdk,
            seed,
            registry,
            factory,
            home,
            uid,
            payer,
        },
        mes,
    )
}

/// The operation followed to a terminal state.
pub async fn follow(sdk: &Arc<Sdk>, op: String) -> OpState {
    for _ in 0..240 {
        let s = sdk.op().state(op.clone()).await.unwrap();
        if s.is_terminal() {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    sdk.op().state(op).await.unwrap()
}

/// `call` refused by the harness above 2^24 gas, else sent exactly and followed to `Landed`; its gas limit.
pub async fn land(l: &Local, call: scaas_sdk::app_core::AppCall) -> u64 {
    let gas = call.quote.quote.gas_limit;
    assert!(
        gas <= TX_CAP,
        "the harness sends nothing above 2^24 gas ({gas})"
    );
    let op = l.sdk.wallet().submit_native_send(call.quote).await.unwrap();
    let s = follow(&l.sdk, op).await;
    assert!(matches!(s, OpState::Landed { .. }), "{s:?}");
    gas
}

/// The seed's UA of `account` registered on `sdk`'s chain (with a KEM key, version 0, or without), self-relayed: its `Me`.
pub async fn register(sdk: &Arc<Sdk>, seed: &str, account: u32, kem: bool) -> Me {
    use scaas_sdk::account::{Register, RegisterAttrs};
    let key = KeyRef::Ua {
        seed: seed.into(),
        kind: KIND,
        account,
        index: 0,
    };
    let acc = sdk.account();
    let writes = acc
        .prepare_register(Register {
            key: key.clone(),
            chain: CHAIN.into(),
            attrs: RegisterAttrs {
                pqz_key: false,
                kem,
            },
            payer: payer_of(seed),
        })
        .await
        .unwrap();
    let ua = writes[0].ua();
    for w in writes {
        let q = acc.quote_registry_write(w.clone()).await.unwrap();
        let op = acc.submit_registry_write(w.clone(), q).await.unwrap();
        let s = follow(sdk, op).await;
        assert!(matches!(s, OpState::Landed { .. }), "{}: {s:?}", w.entry());
    }
    Me {
        key,
        ua: ua.to_ascii_lowercase(),
    }
}
