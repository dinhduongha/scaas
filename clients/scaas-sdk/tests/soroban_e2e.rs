// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T39 (open from T41.soroban): the SDK's Soroban paths on a live local network, the pinned Protocol 30 quickstart
//! (`smartcontracts/soroban/scripts/quickstart.sh`), the token built by `smartcontracts/scripts/build.sh soroban`:
//! A hands a pay off to B; B, holding only XLM, imports, quotes, submits and sees `landed`; the same blob again is
//! `ImportConsumed`; A's own self-relay lands, paid by another key of its seed and by its own key; a native XLM send lands.
//! Ignored: `cargo test --features soroban --test soroban_e2e -- --ignored` with the quickstart up. Env (defaults: the local quickstart): `STELLAR_URL`, `STELLAR_FRIENDBOT`,
//! `STELLAR_PASSPHRASE`, `STELLAR_BIN` (the pinned CLI, `quickstart.sh cli`), `SOROBAN_TOKEN_WASM`.
//! A and B are the vectors' keys 0 and 1 (smartcontracts/vectors/families/soroban.json); the token's admin is a CLI key in a
//! temporary config directory.
#![cfg(feature = "soroban")]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::wallet::{
    NativeKeyRef, SorobanImportExpect, SorobanNativeSend, SorobanOpKind, SorobanOpRequest,
    SorobanPath, Wallet,
};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, FamilyParams, Finality, Limits, ListedToken, NativeCap,
    RuntimeChoice, Sdk, SdkConfig,
};
use scaas_ua::wallet::SecretBytes;
use serde_json::Value;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const CHAIN: &str = "soroban-local";
const PASS: &str = "river-otter-7 ünï";

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.into())
}
fn rpc_url() -> String {
    env_or("STELLAR_URL", "http://127.0.0.1:31980/rpc")
}
fn passphrase() -> String {
    env_or("STELLAR_PASSPHRASE", "Standalone Network ; February 2017")
}
fn root() -> String {
    format!("{}/../..", env!("CARGO_MANIFEST_DIR"))
}
fn fam() -> Value {
    let p = format!("{}/smartcontracts/vectors/families/soroban.json", root());
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `stellar <args>` on the local network, the CLI's identities in `dir`; its stdout, or a panic with its stderr.
fn cli(dir: &str, args: &[&str]) -> String {
    let mut full: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let pos = full.iter().position(|a| a == "--").unwrap_or(full.len());
    // the options before `--` (the contract's own arguments follow it); `keys` takes no network
    let mut opts = vec!["--config-dir".to_string(), dir.into()];
    if !matches!(args.first(), Some(&"keys")) {
        opts.extend([
            "--rpc-url".into(),
            rpc_url(),
            "--network-passphrase".into(),
            passphrase(),
        ]);
    }
    full.splice(pos..pos, opts);
    let out = Command::new(env_or("STELLAR_BIN", "stellar"))
        .args(&full)
        .output()
        .expect("the stellar CLI");
    assert!(
        out.status.success(),
        "stellar {}: {}",
        full.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn fund(g: &str) {
    let url = format!(
        "{}?addr={g}",
        env_or("STELLAR_FRIENDBOT", "http://127.0.0.1:31980/friendbot")
    );
    let out = Command::new("curl")
        .args(["-s", "-m", "30", &url])
        .output()
        .unwrap();
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success()
            && (body.contains("\"successful\": true")
                || body.contains("AlreadyExist")
                || body.contains("already funded")
                || body.contains("\"hash\"")),
        "friendbot {g}: {body}"
    );
}

fn key(seed: &str, index: u32) -> NativeKeyRef {
    NativeKeyRef {
        seed: seed.into(),
        network: "stellar".into(),
        index,
        change: None,
        coin_type: None,
        path: None,
    }
}

/// Follows row `op` until it is terminal (at most 60 s); its last state.
async fn follow(w: &Wallet, op: &str) -> String {
    let mut s = String::new();
    for _ in 0..60 {
        s = w.soroban_follow(op.into()).await.unwrap();
        if s != "sent" && s != "signed" && s != "handed_off" {
            return s;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    s
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn a_hand_off_a_self_relay_and_a_native_send_land_on_the_local_network() {
    let v = fam();
    let (a, b) = (
        v["ops"][0]["shown"]["from"].as_str().unwrap().to_string(),
        v["ops"][0]["shown"]["to"].as_str().unwrap().to_string(),
    );
    // the CLI's identities in a directory of this run, removed at the end
    let dir = std::env::temp_dir().join(format!("scaas-sdk-soroban-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let d = dir.to_str().unwrap();
    cli(d, &["keys", "generate", "admin"]);
    let admin = cli(d, &["keys", "public-key", "admin"]);
    let payer = std::fs::read_to_string(format!(
        "{}/smartcontracts/vectors/native/soroban-tx.json",
        root()
    ))
    .map(|t| {
        serde_json::from_str::<Value>(&t).unwrap()["payer"]
            .as_str()
            .unwrap()
            .to_string()
    })
    .unwrap();
    for g in [&admin, &a, &b, &payer] {
        fund(g);
    }
    let wasm = env_or(
        "SOROBAN_TOKEN_WASM",
        &format!(
            "{}/smartcontracts/soroban/target/wasm32v1-none/release/scaas_token.wasm",
            root()
        ),
    );
    let token = cli(
        d,
        &[
            "contract",
            "deploy",
            "--wasm",
            &wasm,
            "--source-account",
            "admin",
            "--",
            "--admin",
            &admin,
            "--decimals",
            "7",
            "--name",
            "SCaaS",
            "--symbol",
            "BMB",
        ],
    );
    cli(
        d,
        &[
            "contract",
            "invoke",
            "--id",
            &token,
            "--source-account",
            "admin",
            "--",
            "mint",
            "--to",
            &a,
            "--amount",
            "10000000",
        ],
    );
    let sac = cli(d, &["contract", "id", "asset", "--asset", "native"]);

    let rpc = EndpointConfig {
        url: rpc_url(),
        class: scaas_rpc::Class::Named,
        label: None,
        auth: None,
    };
    let profile = ChainProfile {
        key: CHAIN.into(),
        family: Family::Soroban,
        chain_id: None,
        chain_uid: format!("0x{}", hex(&scaas_ua::sha256(passphrase().as_bytes()))),
        rpc: vec![rpc],
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
        tokens: vec![ListedToken {
            address: token.clone(),
            symbol: "BMB".into(),
            decimals: 7,
        }],
        l1_fee: None,
        pinned_reads: true,
        disabled_kinds: vec![],
        family_params: Some(FamilyParams::Soroban {
            passphrase: passphrase(),
            xlm_sac: sac,
        }),
    };
    let sdk = Sdk::open(SdkConfig {
        profiles: vec![profile],
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits {
            max_native_cost: vec![NativeCap {
                chain: CHAIN.into(),
                max: "100000000".into(),
            }],
            ..Limits::default()
        },
        clock: None,
        gas_tables: vec![],
    })
    .await
    .unwrap();
    let sec = |b: &[u8]| Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(b.to_vec())).unwrap());
    let seed = sdk
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words: sec(v["mnemonic"].as_str().unwrap().as_bytes()),
            vault_passphrase: sec(PASS.as_bytes()),
        })
        .await
        .unwrap()
        .id;
    let w = sdk.wallet();
    let pay = |to: &str, amount: &str, r: u8| SorobanOpRequest {
        chain: CHAIN.into(),
        subject: key(&seed, 0),
        contract: token.clone(),
        kind: SorobanOpKind::Pay {
            to: to.into(),
            amount: amount.into(),
            pay_ref: format!("0x{}", hex(&[r; 32])),
        },
        valid_until: now() + 600,
    };

    // 1. A hands a pay off to B (nothing sent); B, holding only XLM, imports, quotes from its own key, submits: landed
    let p = w.soroban_prepare(pay(&b, "1000000", 0xA1)).await.unwrap();
    let h = w.soroban_hand_off(p).await.unwrap();
    assert_eq!(w.soroban_follow(h.op.clone()).await.unwrap(), "handed_off");
    let me = SorobanImportExpect {
        chain: CHAIN.into(),
        payee: vec![b.clone()],
    };
    let imported = w.soroban_import(h.blob.clone(), me.clone()).await.unwrap();
    let q = w
        .soroban_quote(
            imported.clone(),
            SorobanPath::SelfRelay {
                payer: key(&seed, 1),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        q.payer.as_deref(),
        Some(b.as_str()),
        "B pays its own transaction"
    );
    let id = w.soroban_submit(imported, q).await.unwrap();
    assert_eq!(follow(&w, &id).await, "landed", "B's transaction");
    // 2. the same blob again: consumed; A's own row ends on the chain facts
    assert_eq!(
        w.soroban_import(h.blob, me)
            .await
            .map_err(|e| e.code())
            .unwrap_err(),
        "ImportConsumed"
    );
    assert_eq!(follow(&w, &h.op).await, "landed", "A's handed-off row");

    // 3. A's own self-relay: A signs its own pay and pays for it from another key of its seed (key 2, as the vectors' payer)
    let p = w.soroban_prepare(pay(&b, "2000000", 0xB2)).await.unwrap();
    let q = w
        .soroban_quote(
            p.clone(),
            SorobanPath::SelfRelay {
                payer: key(&seed, 2),
            },
        )
        .await
        .unwrap();
    assert_eq!(q.payer.as_deref(), Some(payer.as_str()));
    let id = w.soroban_submit(p, q).await.unwrap();
    assert_eq!(follow(&w, &id).await, "landed", "A's self-relay");
    let bal = cli(
        d,
        &[
            "contract",
            "invoke",
            "--id",
            &token,
            "--source-account",
            "admin",
            "--",
            "balance",
            "--id",
            &b,
        ],
    );
    assert_eq!(bal.trim_matches('"'), "3000000", "B holds both pays");
    // 3b. A's self-relay paid by A's own key (owner 2026-11-22, SourceAccount accepted when self-paying): the transaction's
    // source is the subject, whose simulation records a `SourceAccount` entry
    let p = w.soroban_prepare(pay(&b, "4000000", 0xC3)).await.unwrap();
    let q = w
        .soroban_quote(
            p.clone(),
            SorobanPath::SelfRelay {
                payer: key(&seed, 0),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        q.payer.as_deref(),
        Some(a.as_str()),
        "A pays its own transaction"
    );
    let id = w.soroban_submit(p, q).await.unwrap();
    assert_eq!(
        follow(&w, &id).await,
        "landed",
        "A's self-relay by its own key"
    );
    let bal = cli(
        d,
        &[
            "contract",
            "invoke",
            "--id",
            &token,
            "--source-account",
            "admin",
            "--",
            "balance",
            "--id",
            &b,
        ],
    );
    assert_eq!(bal.trim_matches('"'), "7000000", "B holds the three pays");

    // 4. a native XLM send from A to B
    let q = w
        .soroban_prepare_native_send(SorobanNativeSend {
            chain: CHAIN.into(),
            key: key(&seed, 0),
            to: b.clone(),
            amount: "12345678".into(),
        })
        .await
        .unwrap();
    assert_eq!(q.from, a);
    let id = w.soroban_submit_native_send(q).await.unwrap();
    assert_eq!(follow(&w, &id).await, "landed", "the native send");
    std::fs::remove_dir_all(&dir).unwrap();
}
