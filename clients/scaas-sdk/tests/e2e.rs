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
/// 0 and 1 registered first through the SDK (plan T13; owner-approved T16-d), a `NORMAL_ZETHER` token created through the factory; the seed's EVM key shields 1234 to account
/// 0's Zether UA and rolls it over, the Zether UA transfers 100 to account 1's (the proof over the reading layer's words,
/// self-relayed by the EVM key), and the balances read back through the reading layer: 1134 spendable, 100 pending.
#[cfg(all(feature = "zether", feature = "account"))]
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
        gas_opt_in: vec![],
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
    let (_anvil, rpc) = anvil(6).await;
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
    let est: u64 = cast(&["estimate", "--from", &payer_address, &registry, &full[0].calldata(), "--rpc-url", rpc])
        .parse()
        .unwrap();
    let (sdk, seed) = sdk_on(registry_profile(rpc, &registry, Some(est - 100_000))).await;
    let acc = sdk.account();
    let writes = acc.prepare_register(req(&seed)).await.unwrap();
    let entries: Vec<_> = writes.iter().map(|w| w.entry()).collect();
    assert_eq!(entries.len(), 2, "split under the full call's estimate: {entries:?}");
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

// --- plan T13: SmartKeyAccount and guardian recovery ---

/// The profile of `anvil` at `rpc` with measured gas figures of the account's entries (the table has no `account` rows),
/// rounded up.
fn account_profile(rpc: &str) -> ChainProfile {
    let row = |entry: &str, fresh: bool| GasBase {
        entry: entry.into(),
        kind: "account".into(),
        fresh,
        gas: 600_000,
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
        gas: GasRows {
            base: [true, false].iter().flat_map(|&f| [row("mtxAddKey", f), row("mtxExecute", f)]).collect(),
            verify: vec![GasVerify { signer: 0, gas: 0 }],
        },
        max_valid_secs: None,
        gas_opt_in: vec![],
    }
}

/// A `SmartKeyAccount` of the seed's EVM key `index` (its first key, secp256k1) and `guardian`, deployed through `factory`
/// by the SDK (`prepare_smart_deploy`, sent by the seed's EVM key 0); its address, checked against the SDK's counterfactual
/// one.
async fn deploy_account(sdk: &Arc<Sdk>, seed: &str, rpc: &str, factory: &str, index: u32, guardian: &str) -> String {
    use scaas_sdk::account::{smart_account_address, SubjectKeyArgs};
    let key = Wallet::from_mnemonic(REPO, "")
        .unwrap()
        .native_key(Network::Evm, index, None)
        .unwrap()
        .address()
        .unwrap();
    let first = SubjectKeyArgs::secp256k1(&key).unwrap();
    let implementation = cast(&["call", factory, "IMPLEMENTATION()(address)", "--rpc-url", rpc]);
    let predicted = smart_account_address(factory, &implementation, &first, guardian).unwrap();
    let q = sdk
        .account()
        .prepare_smart_deploy(key0(seed), "anvil".into(), factory.into(), first, guardian.into())
        .await
        .unwrap();
    let op = sdk.wallet().submit_native_send(q).await.unwrap();
    let s = follow(sdk, op).await;
    assert!(matches!(s, OpState::Landed { .. }), "deploy: {s:?}");
    assert_ne!(cast(&["code", &predicted, "--rpc-url", rpc]), "0x", "deployed at the SDK's address");
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
    let q = sdk.op().quote(p.clone(), SubmitPath::SelfRelay { payer }).await.unwrap();
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
    let (_anvil, rpc) = anvil(4).await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    funded_holder(rpc);
    let dep = deploy(rpc, &format!("local-31337-{port}-testnet"), &[]);
    let factory = dep["smart_key_account_factory"].as_str().unwrap().to_string();
    let (sdk, seed) = sdk_on(account_profile(rpc)).await;
    let account = deploy_account(&sdk, &seed, rpc, &factory, 0, "0x0000000000000000000000000000000000000000").await;
    assert_eq!(cast(&["call", &account, "keyCount()(uint256)", "--rpc-url", rpc]), "1");
    let new_key = SubjectKeyArgs::secp256k1("0x00000000000000000000000000000000000000bb").unwrap();
    let p = sdk
        .account()
        .prepare_smart_add_key(smart_op(&seed, 0, &account), new_key)
        .await
        .unwrap();
    assert_eq!(p.entry(), "mtxAddKey");
    let s = self_relay(&sdk, &seed, p).await;
    assert!(matches!(s, OpState::Landed { .. }), "{s:?}");
    assert_eq!(cast(&["call", &account, "keyCount()(uint256)", "--rpc-url", rpc]), "2");
    // another key signs (owner 2026-11-19, S3): the seed's EVM key 2 added at index 2, an `AddKey` it signs with the
    // index read from the account; a key the account does not hold is `SignerNotAccountKey` (P2)
    let key2 = Wallet::from_mnemonic(REPO, "").unwrap().native_key(Network::Evm, 2, None).unwrap().address().unwrap();
    let p = sdk
        .account()
        .prepare_smart_add_key(smart_op(&seed, 0, &account), SubjectKeyArgs::secp256k1(&key2).unwrap())
        .await
        .unwrap();
    assert!(matches!(self_relay(&sdk, &seed, p).await, OpState::Landed { .. }));
    let third = SubjectKeyArgs::secp256k1("0x00000000000000000000000000000000000000cc").unwrap();
    let refused = sdk.account().prepare_smart_add_key(smart_op(&seed, 3, &account), third.clone()).await;
    assert_eq!(refused.err().map(|e| e.code()), Some("SignerNotAccountKey"), "not a key of the account");
    let p = sdk.account().prepare_smart_add_key(smart_op(&seed, 2, &account), third).await.unwrap();
    let s = self_relay(&sdk, &seed, p).await;
    assert!(matches!(s, OpState::Landed { .. }), "signed by key index 2: {s:?}");
    assert_eq!(cast(&["call", &account, "keyCount()(uint256)", "--rpc-url", rpc]), "4");
}

/// Plan T13 `guardian_recovery_via_execute`: account A (the seed's EVM key 0) names the guardian `SmartKeyAccount` G (EVM key
/// 1); G's `Execute` of the decoded `initiateRecovery(newKey)` on A, signed by key 1 and self-relayed by key 0, lands and
/// starts the clock; `completeRecovery` is refused before the two days, passes after an `anvil` time warp, and A holds the
/// new key.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate sdk-e2e)"]
async fn guardian_recovery_via_execute() {
    use scaas_sdk::account::SubjectKeyArgs;
    let (_anvil, rpc) = anvil(5).await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    funded_holder(rpc);
    let dep = deploy(rpc, &format!("local-31337-{port}-testnet"), &[]);
    let factory = dep["smart_key_account_factory"].as_str().unwrap().to_string();
    let (sdk, seed) = sdk_on(account_profile(rpc)).await;
    let guardian = deploy_account(&sdk, &seed, rpc, &factory, 1, "0x0000000000000000000000000000000000000000").await;
    let account = deploy_account(&sdk, &seed, rpc, &factory, 0, &guardian).await;
    let new_key = SubjectKeyArgs::secp256k1("0x00000000000000000000000000000000000000dd").unwrap();
    let p = sdk
        .account()
        .prepare_initiate_recovery(smart_op(&seed, 1, &guardian), account.clone(), new_key.clone())
        .await
        .unwrap();
    assert_eq!(p.entry(), "mtxExecute");
    let s = self_relay(&sdk, &seed, p).await;
    assert!(matches!(s, OpState::Landed { .. }), "{s:?}");
    let pending = cast(&["call", &account, "pendingRecovery()(bytes32)", "--rpc-url", rpc]);
    assert_ne!(pending, format!("0x{}", "00".repeat(32)), "the recovery started");
    // `completeRecovery` through the SDK, sent by the seed's EVM key 0 (anyone may)
    let acc = sdk.account();
    let complete = || acc.prepare_complete_recovery(key0(&seed), "anvil".into(), account.clone(), new_key.clone());
    assert!(complete().await.is_err(), "refused before RECOVERY_DELAY: its simulation reverts");
    cast(&["rpc", "--rpc-url", rpc, "evm_increaseTime", "172801"]);
    cast(&["rpc", "--rpc-url", rpc, "evm_mine"]);
    let op = sdk.wallet().submit_native_send(complete().await.unwrap()).await.unwrap();
    let s = follow(&sdk, op).await;
    assert!(matches!(s, OpState::Landed { .. }), "after the two days, by anyone: {s:?}");
    assert_eq!(cast(&["call", &account, "keyCount()(uint256)", "--rpc-url", rpc]), "2");
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
    use scaas_sdk::account::{msig_structure, AcceptMembership, MsigMemberArgs, MsigRegister, UpdateMsig};
    use scaas_sdk::op::MsigSlot;
    use scaas_sdk::wallet::Transfer;
    const ED25519: u16 = 0x0102;
    let (_anvil, rpc) = anvil(7).await;
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
    };
    profile.gas = GasRows {
        base: [true, false].iter().flat_map(|&f| [base("mtxPay", f), base("mtxExecuteTransfer", f)]).collect(),
        verify: vec![GasVerify { signer: 0, gas: 0 }, GasVerify { signer: 0x0120, gas: 300_000 }],
    };
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
        uas.iter().map(|u| MsigMemberArgs { kind: ED25519, id: u.clone(), weight: 1 }).collect(),
        2,
    )
    .unwrap();
    let ua = s.ua().unwrap();
    let acc = sdk.account();
    let ws = acc
        .prepare_msig_register(MsigRegister { chain: "anvil".into(), structure: s.clone(), slots: vec![], payer: key0(&seed) })
        .await
        .unwrap();
    assert_eq!(ws.len(), 1);
    land_write(&sdk, ws[0].clone()).await;
    assert!(!acc.msig_state("anvil".into(), ua.clone()).await.unwrap().active, "no slot accepted yet");
    let slot = |i: u16| MsigSlot::Member { index: i, key: key_of(&s.members[usize::from(i)].id) };
    for i in [0u16, 1] {
        let w = acc
            .prepare_accept_membership(AcceptMembership { chain: "anvil".into(), ua: ua.clone(), slot: slot(i), payer: key0(&seed) })
            .await
            .unwrap()
            .expect("not accepted yet");
        land_write(&sdk, w).await;
    }
    let st = acc.msig_state("anvil".into(), ua.clone()).await.unwrap();
    assert!(st.active && st.slots[0].accepted && st.slots[1].accepted && !st.slots[2].accepted, "{st:?}");
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
                body: PayBody::Note { note: "to the msig".into() },
            },
            envelope: Envelope { valid_until: now() + 600, mode: 0, relayer: None, fee: "0".into(), fee_recipient: None },
        })
        .await
        .unwrap();
    let s1 = self_relay(&sdk, &seed, p).await;
    assert!(matches!(s1, OpState::Landed { .. }), "pay: {s1:?}");
    let p = sdk
        .wallet()
        .prepare_transfer(Transfer {
            signer: KeyRef::Msig { ua: ua.clone(), slots: vec![slot(0), slot(1)] },
            chain: "anvil".into(),
            token: token.clone(),
            to: format!("0x{}{}", "00".repeat(12), "cafe".repeat(10)),
            value: "100".into(),
            batch: "1".into(),
            envelope: Envelope { valid_until: now() + 600, mode: 0, relayer: None, fee: "0".into(), fee_recipient: None },
        })
        .await
        .unwrap();
    let s2 = self_relay(&sdk, &seed, p).await;
    assert!(matches!(s2, OpState::Landed { .. }), "msig transfer: {s2:?}");
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
        })
        .await
        .unwrap();
    land_write(&sdk, plan.write).await;
    let st = acc.msig_state("anvil".into(), ua).await.unwrap();
    assert!(st.version == 1 && !st.slots[2].enabled && st.active, "{st:?}");
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
    let (_anvil, rpc) = anvil(8).await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    funded_holder(rpc);
    let dep = deploy(rpc, &format!("local-31337-{port}-testnet"), &[]);
    let registry = dep["ua_registry"].as_str().unwrap().to_ascii_lowercase();
    assert_eq!(
        cast(&["call", "--rpc-url", rpc, &registry, "kindEnabled(uint16)(bool)", &MLDSA65.to_string()]),
        "true",
        "mldsa65 enabled on this registry"
    );
    let (sdk, seed) = sdk_on(registry_profile(rpc, &registry, Some(1 << 24))).await;
    let acc = sdk.account();
    let req = || Register {
        key: KeyRef::Ua { seed: seed.clone(), kind: MLDSA65, account: 0, index: 0 },
        chain: "anvil".into(),
        attrs: RegisterAttrs::default(),
        payer: key0(&seed),
    };
    let writes = acc.prepare_register(req()).await.unwrap();
    let entries: Vec<_> = writes.iter().map(|w| w.entry()).collect();
    assert_eq!(entries, ["cacheExpandedKey", "cacheExpandedKey", "register"]);
    let ua = writes[0].ua();
    for w in writes {
        land_write(&sdk, w).await;
    }
    let ek = cast(&["call", "--rpc-url", rpc, &registry, "expandedKeyOf(bytes32)(address[3])", &ua]);
    assert_eq!(ek.matches("0x0000000000000000000000000000000000000000").count(), 1, "parts 0 and 1 stored: {ek}");
    assert!(acc.registration_of("anvil".into(), ua).await.unwrap().registered);
    assert!(acc.prepare_register(req()).await.unwrap().is_empty(), "nothing left to write");
}

// --- owner 2026-11-19, T2: a passkey row registered ---

/// A test passkey on `scaas.example` over a fixed P-256 key: assertions with UP and UV, `r ‖ s` signatures; nothing else.
struct Passkey(p256::ecdsa::SigningKey);

impl Passkey {
    fn new() -> Self {
        Passkey(p256::ecdsa::SigningKey::from_slice(&scaas_ua::sha256(b"scaas-sdk.e2e.passkey")).unwrap())
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
            let n = c.iter().enumerate().fold(0u32, |n, (i, x)| n | u32::from(*x) << (16 - 8 * i));
            (0..=c.len()).for_each(|i| challenge.push(A[(n >> (18 - 6 * i) & 63) as usize] as char));
        }
        let auth = [&scaas_ua::sha256(req.rp_id.as_bytes())[..], &[0x05], &1u32.to_be_bytes()].concat();
        let cdj = format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://{}"}}"#, req.rp_id)
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
    async fn p256_sign(&self, _: String, _: Vec<u8>, _: String) -> Result<Vec<u8>, scaas_sdk::platform::AuthError> {
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
    let (_anvil, rpc) = anvil(9).await;
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
        .import_words(ImportWords { label: "main".into(), words: sec(REPO), vault_passphrase: sec(PASS) })
        .await
        .unwrap()
        .id;
    let acc = sdk.account();
    let key = acc.create_passkey_key(CreatePasskeyKey { seed: seed.clone(), name: "phone".into() }).await.unwrap();
    let writes = acc
        .prepare_register(Register { key, chain: "anvil".into(), attrs: Default::default(), payer: key0(&seed) })
        .await
        .unwrap();
    assert_eq!(writes.iter().map(|w| w.entry()).collect::<Vec<_>>(), ["registerWebAuthn"]);
    let ua = writes[0].ua();
    land_write(&sdk, writes[0].clone()).await;
    assert!(acc.registration_of("anvil".into(), ua.clone()).await.unwrap().registered);
    let k = cast(&["call", "--rpc-url", rpc, &registry, "webAuthnKeyOf(bytes32)((bytes32,bytes32,bytes32))", &ua]);
    assert!(k.contains(&format!("0x{}", alloy::hex::encode(scaas_ua::sha256(b"scaas.example")))), "{k}");
}
