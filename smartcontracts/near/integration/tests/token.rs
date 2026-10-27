//! Task 4 (spec §3.2, R6): the NEAR token — NEP-141 / NEP-145 / NEP-148, the UA ledger, relayer-paid storage.
//! Needs `smartcontracts/scripts/build.sh near` first (the wasm under target/near/). One sandbox per test.
use near_contract_standards::fungible_token::metadata::{FungibleTokenMetadata, FT_METADATA_SPEC};
use near_workspaces::network::Sandbox;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Finality, NearToken};
use near_workspaces::{Account, Contract, Worker};
use scaas_near_token::{ACCOUNT_STORAGE_BYTES, UA_STORAGE_BYTES};
use serde_json::{json, Value};

const TOKEN_WASM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/near/scaas_near_token/scaas_near_token.wasm");
const RECEIVER_WASM: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../target/near/scaas_near_test_receiver/scaas_near_test_receiver.wasm");
const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/near-vectors.json");
const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../scripts/check_no_authority.sh");
const NETWORK: [u8; 32] = [0x22; 32];
const UA: [u8; 32] = [0x5a; 32];

struct T {
    w: Worker<Sandbox>,
    token: Contract,
    admin: Account,
    alice: Account,
    bob: Account,
}

fn wasm(path: &str) -> Vec<u8> {
    std::fs::read(path).expect("run smartcontracts/scripts/build.sh near first")
}

async fn setup() -> T {
    let w = near_workspaces::sandbox().await.unwrap();
    let token = w.dev_deploy(&wasm(TOKEN_WASM)).await.unwrap();
    let admin = w.dev_create_account().await.unwrap();
    let meta = FungibleTokenMetadata {
        spec: FT_METADATA_SPEC.into(),
        name: "SCaaS Test".into(),
        symbol: "SCT".into(),
        icon: None,
        reference: None,
        reference_hash: None,
        decimals: 6,
    };
    let args = borsh::to_vec(&(NETWORK, admin.id().to_string(), meta)).unwrap();
    token.call("new").args(args).transact().await.unwrap().into_result().unwrap();
    let alice = w.dev_create_account().await.unwrap();
    let bob = w.dev_create_account().await.unwrap();
    T { w, token, admin, alice, bob }
}

impl T {
    async fn call(&self, who: &Account, method: &str, args: Value, yocto: u128) -> ExecutionFinalResult {
        let out = who
            .call(self.token.id(), method)
            .args_json(args)
            .deposit(NearToken::from_yoctonear(yocto))
            .max_gas()
            .transact()
            .await
            .unwrap();
        println!("{method} by {}: {} = {:.3} Tgas, ok {}", who.id(), out.total_gas_burnt.as_gas(),
                 out.total_gas_burnt.as_gas() as f64 / 1e12, out.is_success());
        out
    }

    async fn view(&self, method: &str, args: Value) -> Value {
        self.token.view(method).args_json(args).await.unwrap().json().unwrap()
    }

    async fn balance(&self, who: &str) -> u128 {
        self.view("ft_balance_of", json!({ "account_id": who })).await.as_str().unwrap().parse().unwrap()
    }

    async fn ua_balance(&self, id: [u8; 32]) -> u128 {
        self.view("ua_balance_of", json!({ "id": id })).await.as_str().unwrap().parse().unwrap()
    }

    async fn min(&self) -> u128 {
        let b = self.view("storage_balance_bounds", json!({})).await;
        b["min"].as_str().unwrap().parse().unwrap()
    }

    async fn register(&self, who: &str) {
        let min = self.min().await;
        let out = self.call(&self.alice, "storage_deposit", json!({ "account_id": who }), min).await;
        assert!(out.is_success(), "{:?}", out.failures());
    }

    /// `alice` registered with `amount` minted (admin).
    async fn fund_alice(&self, amount: u128) {
        self.register(self.alice.id().as_str()).await;
        let out = self.call(&self.admin, "mint", json!({ "to": self.alice.id(), "amount": amount.to_string() }), 1).await;
        assert!(out.is_success(), "{:?}", out.failures());
    }

    async fn near_balance(&self, who: &Account) -> u128 {
        who.view_account().await.unwrap().balance.as_yoctonear()
    }

    async fn storage_usage(&self) -> u64 {
        self.token.view_account().await.unwrap().storage_usage
    }

    async fn byte_cost(&self) -> u128 {
        let cfg = self.w.protocol_config(Finality::Final.into()).await.unwrap();
        cfg.runtime_config.storage_amount_per_byte.as_yoctonear()
    }
}

fn failure_text(out: &ExecutionFinalResult) -> String {
    format!("{:?}", out.failures())
}

#[tokio::test]
async fn ft_transfer_registered_needs_one_yocto() {
    let t = setup().await;
    t.fund_alice(100).await;
    t.register(t.bob.id().as_str()).await;
    let args = json!({ "receiver_id": t.bob.id(), "amount": "10" });
    for yocto in [0, 2] {
        let out = t.call(&t.alice, "ft_transfer", args.clone(), yocto).await;
        assert!(out.is_failure(), "{yocto} yocto accepted");
        assert!(failure_text(&out).contains("Requires attached deposit of exactly 1 yoctoNEAR"));
    }
    let out = t.call(&t.alice, "ft_transfer", args, 1).await;
    assert!(out.is_success(), "{:?}", out.failures());
    assert!(out.logs().iter().any(|l| l.contains(r#""standard":"nep141""#) && l.contains(r#""event":"ft_transfer""#)));
    assert_eq!((t.balance(t.alice.id().as_str()).await, t.balance(t.bob.id().as_str()).await), (90, 10));
}

#[tokio::test]
async fn ft_transfer_unregistered_auto_registers() {
    let t = setup().await;
    t.fund_alice(100).await;
    let min = t.min().await;
    let bob = t.bob.id().as_str();
    assert_eq!(t.view("storage_balance_of", json!({ "account_id": bob })).await, Value::Null);

    // One yocto below the bound: refused, nothing registered.
    let out = t.call(&t.alice, "ft_transfer", json!({ "receiver_id": bob, "amount": "10" }), min - 1).await;
    assert!(out.is_failure());
    assert_eq!(t.view("storage_balance_of", json!({ "account_id": bob })).await, Value::Null);

    // min + 1 NEAR: bob registered for exactly min, the 1 NEAR excess back to the predecessor.
    let excess = NearToken::from_near(1).as_yoctonear();
    let before = t.near_balance(&t.alice).await;
    let out = t.call(&t.alice, "ft_transfer", json!({ "receiver_id": bob, "amount": "10" }), min + excess).await;
    assert!(out.is_success(), "{:?}", out.failures());
    let spent = before - t.near_balance(&t.alice).await;
    println!("auto-register: alice spent {spent} yocto (min {min} + fees)");
    assert!(spent >= min && spent < min + excess / 20, "excess not refunded: spent {spent}");
    let sb = t.view("storage_balance_of", json!({ "account_id": bob })).await;
    assert_eq!(sb, json!({ "total": min.to_string(), "available": "0" }));
    assert_eq!(t.balance(bob).await, 10);
}

#[tokio::test]
async fn storage_bounds_min_equals_max_equals_measured() {
    let t = setup().await;
    let v: Value = serde_json::from_str(&std::fs::read_to_string(VECTORS).unwrap()).unwrap();
    let records = &v["storage"]["records"];
    let cost = t.byte_cost().await;
    let b = t.view("storage_balance_bounds", json!({})).await;
    assert_eq!(b["min"], b["max"]);
    let min: u128 = b["min"].as_str().unwrap().parse().unwrap();

    // A registration of the longest account id (64 chars): the largest record, the fixed per-holder cost.
    let long = "f".repeat(64);
    let u0 = t.storage_usage().await;
    t.register(&long).await;
    let account_bytes = t.storage_usage().await - u0;

    // A new UA ledger record (the sender's and the pool's records already exist, so only the UA record is new).
    t.fund_alice(100).await;
    let u0 = t.storage_usage().await;
    let out = t.call(&t.alice, "transfer_to_ua", json!({ "id": UA, "amount": "1" }), min).await;
    assert!(out.is_success(), "{:?}", out.failures());
    let ua_bytes = t.storage_usage().await - u0;

    println!("storage_byte_cost {cost} yocto/byte (protocol config)");
    println!("record account (NEP-145 registration, 64-char id): {account_bytes} B, deposit {} yocto",
             account_bytes as u128 * cost);
    println!("record ua_balance (UA ledger entry): {ua_bytes} B, deposit {} yocto", ua_bytes as u128 * cost);
    assert_eq!(account_bytes, ACCOUNT_STORAGE_BYTES);
    assert_eq!(ua_bytes, UA_STORAGE_BYTES);
    assert_eq!(records["account"]["bytes"], account_bytes);
    assert_eq!(records["uaBalance"]["bytes"], ua_bytes);
    assert_eq!(min, account_bytes as u128 * cost);
}

#[tokio::test]
async fn storage_withdraw_positive_panics() {
    let t = setup().await;
    t.register(t.alice.id().as_str()).await;
    let min = t.min().await;
    let out = t.call(&t.alice, "storage_withdraw", json!({ "amount": "1" }), 1).await;
    assert!(out.is_failure());
    let out = t.call(&t.alice, "storage_withdraw", json!({}), 1).await;
    assert!(out.is_success(), "{:?}", out.failures());
    assert_eq!(out.json::<Value>().unwrap(), json!({ "total": min.to_string(), "available": "0" }));
}

#[tokio::test]
async fn storage_unregister_registered_panics_force_included() {
    let t = setup().await;
    t.fund_alice(5).await;
    for force in [json!({}), json!({ "force": false }), json!({ "force": true })] {
        let out = t.call(&t.alice, "storage_unregister", force.clone(), 1).await;
        assert!(out.is_failure(), "{force} accepted");
        assert!(failure_text(&out).contains("permanent"));
    }
    assert_eq!(t.balance(t.alice.id().as_str()).await, 5);
    let out = t.call(&t.bob, "storage_unregister", json!({ "force": true }), 1).await;
    assert!(out.is_success(), "{:?}", out.failures());
    assert!(!out.json::<bool>().unwrap());
}

#[tokio::test]
async fn ft_transfer_call_resolves_as_nep141() {
    let t = setup().await;
    t.fund_alice(100).await;
    let rx = t.w.dev_deploy(&wasm(RECEIVER_WASM)).await.unwrap();
    let min = t.min().await;
    let alice = t.alice.id().as_str();

    // Unregistered receiver contract: auto-registered from the deposit; it keeps 7, returns 3 unused.
    let args = json!({ "receiver_id": rx.id(), "amount": "10", "msg": "3" });
    let out = t.call(&t.alice, "ft_transfer_call", args, min).await;
    assert!(out.is_success(), "{:?}", out.failures());
    assert_eq!(out.json::<String>().unwrap(), "7");
    assert_eq!((t.balance(alice).await, t.balance(rx.id().as_str()).await), (93, 7));

    // Registered now: exactly 1 yocto; a receiver panic refunds everything (used = 0).
    let args = json!({ "receiver_id": rx.id(), "amount": "20", "msg": "panic" });
    assert!(t.call(&t.alice, "ft_transfer_call", args.clone(), 0).await.is_failure());
    let out = t.call(&t.alice, "ft_transfer_call", args, 1).await;
    assert!(out.logs().iter().any(|l| l.contains(r#""memo":"refund""#)));
    assert_eq!(out.json::<String>().unwrap(), "0");
    assert_eq!((t.balance(alice).await, t.balance(rx.id().as_str()).await), (93, 7));
    assert_eq!(t.view("ft_total_supply", json!({})).await, "100");
}

#[tokio::test]
async fn transfer_to_ua_credits_ua_ledger() {
    let t = setup().await;
    t.fund_alice(100).await;
    let min = t.min().await;
    let alice = t.alice.id().as_str();
    let ua_cost = UA_STORAGE_BYTES as u128 * t.byte_cost().await;

    // A new UA id: the record's storage from the deposit (one yocto below refused), the excess refunded.
    let args = json!({ "id": UA, "amount": "40" });
    assert!(t.call(&t.alice, "transfer_to_ua", args.clone(), ua_cost - 1).await.is_failure());
    let out = t.call(&t.alice, "transfer_to_ua", args.clone(), min).await;
    assert!(out.is_success(), "{:?}", out.failures());
    let logs = out.logs();
    let ua_hex = format!("0x{}", "5a".repeat(32));
    assert!(logs.iter().any(|l| l.contains(r#""standard":"nep141""#) && l.contains(t.token.id().as_str())));
    assert!(logs.iter().any(|l| l.contains(r#""standard":"scaas""#) && l.contains(r#""event":"ua_transfer""#)
        && l.contains(&ua_hex)));
    assert_eq!(t.ua_balance(UA).await, 40);
    assert_eq!(t.balance(alice).await, 60);
    assert_eq!(t.balance(t.token.id().as_str()).await, 40, "the token's own NEP-141 balance is the UA pool");
    assert_eq!(t.view("ft_total_supply", json!({})).await, "100");

    // The record exists now: exactly 1 yocto, as ft_transfer.
    assert!(t.call(&t.alice, "transfer_to_ua", args.clone(), 0).await.is_failure());
    assert!(t.call(&t.alice, "transfer_to_ua", args.clone(), 2).await.is_failure());
    assert!(t.call(&t.alice, "transfer_to_ua", args, 1).await.is_success());
    assert_eq!((t.ua_balance(UA).await, t.ua_balance([0; 32]).await), (80, 0));
}

#[tokio::test]
async fn mint_admin_only() {
    let t = setup().await;
    t.register(t.alice.id().as_str()).await;
    let args = json!({ "to": t.alice.id(), "amount": "50" });
    let out = t.call(&t.alice, "mint", args.clone(), 1).await;
    assert!(out.is_failure());
    assert!(failure_text(&out).contains("admin"));
    let out = t.call(&t.admin, "mint", args, 1).await;
    assert!(out.is_success(), "{:?}", out.failures());
    assert!(out.logs().iter().any(|l| l.contains(r#""event":"ft_mint""#)));
    assert_eq!(t.balance(t.alice.id().as_str()).await, 50);
    assert_eq!(t.view("ft_total_supply", json!({})).await, "50");
    assert_eq!(t.view("network", json!({})).await, json!(NETWORK));
    assert_eq!(t.view("ft_metadata", json!({})).await["symbol"], "SCT");
}

#[tokio::test]
async fn token_refuses_transfer_to_self() {
    let t = setup().await;
    t.fund_alice(100).await;
    let me = t.token.id();
    let min = t.min().await;
    for (m, args) in [
        ("ft_transfer", json!({ "receiver_id": me, "amount": "1" })),
        ("ft_transfer_call", json!({ "receiver_id": me, "amount": "1", "msg": "0" })),
    ] {
        for yocto in [1, min] {
            let out = t.call(&t.alice, m, args.clone(), yocto).await;
            assert!(out.is_failure(), "{m} to the token accepted");
            assert!(failure_text(&out).contains("token itself"), "{}", failure_text(&out));
        }
    }
    let out = t.call(&t.admin, "mint", json!({ "to": me, "amount": "1" }), 1).await;
    assert!(failure_text(&out).contains("token itself"));
    assert_eq!(t.balance(me.as_str()).await, 0);
}

#[test]
fn check_no_authority_finds_forbidden_api() {
    let run = |args: &[&str]| std::process::Command::new(SCRIPT).args(args).output().unwrap();
    let clean = run(&[]);
    assert!(clean.status.success(), "{}", String::from_utf8_lossy(&clean.stderr));
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("no_authority_fixture");
    std::fs::create_dir_all(&dir).unwrap();
    for api in ["deploy_contract", "add_full_access_key", "add_access_key", "delete_key", "delete_account",
                "deploy_global_contract", "use_global_contract"] {
        std::fs::write(dir.join("lib.rs"), format!("fn f() {{ Promise::new(a).{api}(x); }}\n")).unwrap();
        let out = run(&[dir.to_str().unwrap()]);
        assert!(!out.status.success(), "{api} not caught");
    }
}
