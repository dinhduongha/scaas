// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The e2e tests' local chain (gate `sdk-e2e`, the CLI's `cli-e2e`): an `anvil` on a port the OS gave, the contracts' own
//! `script/Deploy.s.sol`, `cast`, the repository seed's EVM key 0 funded. Shared by `tests/e2e.rs` and
//! `clients/scaas-cli/tests/e2e.rs`. Local only.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scaas_ua::wallet::{Network, Wallet};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// The repository's test seed (public): the token holder and payer of the e2e runs.
pub const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";

/// anvil's first key (a public test key): the deployer
pub const DEPLOYER: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
pub const DEPLOYER_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

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

pub fn cast(args: &[&str]) -> String {
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

/// An `anvil` (stopped on drop) on a port the OS gave as free, ready to answer as chain 31337 while the child is alive; its
/// URL. Never a computed port: another node of the machine (another agent's `anvil`, the testnet stack) is never asked.
pub async fn anvil() -> (Anvil, String) {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("a free port")
        .port();
    let rpc = format!("http://127.0.0.1:{port}");
    let mut a = Anvil(
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
            assert!(
                a.0.try_wait().expect("anvil's state").is_none(),
                "the node on {port} is not this anvil"
            );
            return (a, rpc);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("anvil on {port} never answered as chain 31337");
}

/// The contracts' own `script/Deploy.s.sol` on `rpc` with `env`; its book (`deployments/<name>.json`, removed after reading).
/// One `forge script` at a time: the tests run in parallel, and forge's broadcast cache of a chain id takes a lock.
pub fn deploy(rpc: &str, name: &str, env: &[(&str, &str)]) -> serde_json::Value {
    static FORGE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = FORGE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
pub fn funded_holder(rpc: &str) -> String {
    let holder = Wallet::from_mnemonic(REPO, "")
        .unwrap()
        .native_key(Network::Evm, 0, None)
        .unwrap()
        .address()
        .unwrap();
    cast(&[
        "rpc",
        "--rpc-url",
        rpc,
        "anvil_setBalance",
        &holder,
        "0x8ac7230489e80000",
    ]);
    holder
}
