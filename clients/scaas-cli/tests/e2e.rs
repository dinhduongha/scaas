// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T22's `sdk-e2e` driven through the CLI (gate `cli-e2e`, ignored by default: needs `anvil`, `forge` and `cast` in PATH
//! and `smartcontracts/evm/lib`; a `dev-profiles` build, which takes the anvil profile from a file): the SDK e2e's chain (the
//! contracts' own `script/Deploy.s.sol`, a demo `NormalToken` holding half its supply for the seed's EVM key 0), then the
//! `scaas` binary prepares a `mtxPay`, shows its review and its quote and stops on `n` (nothing sent), then the same command
//! answered `y` submits it as a self-relay by that key, and `scaas op state` follows it to `Landed`; the receiver's balance
//! moved by the amount. The session form passes the prepared operation and its quote by name to `op submit`. Local only.
#![cfg(feature = "dev-profiles")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

#[path = "../../scaas-sdk/tests/common/anvil.rs"]
mod anvil_chain;

use anvil_chain::{anvil, cast, deploy, funded_holder, REPO};
use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_scaas");
const PASS: &str = "river-otter-7 ünï";

fn run(args: &[String], stdin: &str) -> Output {
    let mut p = Command::new(BIN)
        .args(args)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    p.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    p.wait_with_output().unwrap()
}

fn lines(o: &Output) -> Vec<Value> {
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn balance(rpc: &str, token: &str, who: &str) -> u128 {
    let b = cast(&[
        "call",
        token,
        "balanceOfUA(bytes32)(uint256)",
        who,
        "--rpc-url",
        rpc,
    ]);
    b.split_whitespace().next().unwrap().parse().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate cli-e2e)"]
async fn cli_pay_on_anvil() {
    let (_anvil, rpc) = anvil().await;
    let rpc = rpc.as_str();
    let port = rpc.rsplit(':').next().unwrap();
    let holder = funded_holder(rpc);
    let dep = deploy(
        rpc,
        &format!("local-31337-{port}-cli-testnet"),
        &[("DEMO_SUPPLY", "1000000000000"), ("DEMO_HOLDER", &holder)],
    );
    let token = dep["demo_token"].as_str().unwrap().to_ascii_lowercase();
    let uid = cast(&["block", "0", "--field", "hash", "--rpc-url", rpc]);
    // the SDK e2e's profile: Depth(0) (anvil mines a block per transaction), the measured mtxPay row (no native-key row in
    // the table yet)
    let gas = scaas_sdk::GasRows {
        base: vec![scaas_sdk::GasBase {
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
        verify: vec![scaas_sdk::GasVerify {
            line: Default::default(),
            signer: 0,
            gas: 0,
            sig_bytes: 0,
            margin: 0,
            per_item: None,
        }],
    };
    let profile = json!({"profiles": [{"key": "anvil", "family": "Evm", "chain_id": 31337, "chain_uid": uid,
        "rpc": [{"url": rpc}], "finality": {"Depth": 0}, "tx_gas_cap": 16777216, "registry": null, "factory": null,
        "router": null, "max_valid_secs": null, "tokens": [{"address": token, "symbol": "DEMO", "decimals": 0}],
        "gas": serde_json::to_value(&gas).unwrap()}]});
    let dir = std::env::temp_dir().join(format!("scaas-cli-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pf = dir.join("profiles.json");
    std::fs::write(&pf, profile.to_string()).unwrap();
    let base: Vec<String> = [
        "--json",
        "--data-dir",
        dir.to_str().unwrap(),
        "--profiles",
        pf.to_str().unwrap(),
    ]
    .map(String::from)
    .to_vec();
    let cli = |extra: &[&str], stdin: String| {
        let mut a = base.clone();
        a.extend(extra.iter().map(|s| s.to_string()));
        tokio::task::spawn_blocking(move || run(&a, &stdin))
    };
    let o = cli(
        &[
            "vault",
            "import-words",
            "--label",
            "main",
            "--words-fd",
            "0",
            "--vault-passphrase-fd",
            "0",
        ],
        format!("{REPO}\n{PASS}\n"),
    )
    .await
    .unwrap();
    assert!(o.status.success(), "{}", err(&o));
    let seed = lines(&o)[0]["id"].as_str().unwrap().to_string();
    let key = json!({"Native": {"seed": seed, "network": "evm", "index": 0}}).to_string();
    let path =
        json!({"SelfRelay": {"payer": {"Native": {"seed": seed, "network": "evm", "index": 0}}}})
            .to_string();
    let to = format!("0x{}{}", "00".repeat(12), "cafe".repeat(10));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let valid = (now + 600).to_string();
    let pay = |answer: &str, pay_no: &str| {
        cli(
            &[
                "--unlock",
                &seed,
                "--passphrase-fd",
                "0",
                "--path",
                &path,
                "wallet",
                "prepare-pay",
                "--signer",
                &key,
                "--chain",
                "anvil",
                "--token",
                &token,
                "--to",
                &to,
                "--value",
                "1000",
                "--meta.pay-no",
                pay_no,
                "--meta.save",
                "false",
                "--meta.body",
                "{\"Note\":{\"note\":\"cli e2e\"}}",
                "--envelope.valid-until",
                &valid,
                "--envelope.mode",
                "0",
                "--envelope.fee",
                "0",
            ],
            format!("{PASS}\n{answer}\n"),
        )
    };
    let before = balance(rpc, &token, &to);
    let nonce = cast(&["nonce", &holder, "--rpc-url", rpc]);
    // n: the review and the quote shown, nothing sent
    let o = pay("n", "01890a5d-ac96-774b-bcce-b302099a8057")
        .await
        .unwrap();
    assert!(
        !o.status.success() && err(&o).contains("NotConfirmed"),
        "{}",
        err(&o)
    );
    let shown = &lines(&o)[0];
    let review = shown["review"].as_array().unwrap();
    for f in ["to", "value"] {
        assert!(
            review.iter().any(|r| r["name"] == f),
            "{f} reviewed: {shown}"
        );
    }
    assert!(shown["quote"]["max_cost"].is_string(), "{shown}");
    assert_eq!(shown["entry"], "mtxPay");
    assert_eq!(
        cast(&["nonce", &holder, "--rpc-url", rpc]),
        nonce,
        "nothing sent on n"
    );
    // y: submitted, sent before the process ends
    let o = pay("y", "01890a5d-ac96-774b-bcce-b302099a8058")
        .await
        .unwrap();
    assert!(o.status.success(), "{}", err(&o));
    let l = lines(&o);
    let op = l[1]["op"].as_str().unwrap().to_string();
    assert_eq!(
        l[1]["state"],
        json!({"InFlight": {"detail": "Sent"}}),
        "{}",
        l[1]
    );
    // followed to Landed by later processes over the same data directory
    let mut last = Value::Null;
    for _ in 0..60 {
        let o = cli(&["op", "state", "--op", &op], String::new())
            .await
            .unwrap();
        assert!(o.status.success(), "{}", err(&o));
        last = lines(&o)[0].clone();
        if last.get("Landed").is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert!(last.get("Landed").is_some(), "{last}");
    assert_eq!(balance(rpc, &token, &to), before + 1000);
    // the session form: the prepared operation and its quote by name, then `op submit` (asked on the terminal: `--yes`)
    let session = [
        json!([
            "--as",
            "p",
            "wallet",
            "prepare-pay",
            "--signer",
            key,
            "--chain",
            "anvil",
            "--token",
            token,
            "--to",
            to,
            "--value",
            "7",
            "--meta.pay-no",
            "01890a5d-ac96-774b-bcce-b302099a8059",
            "--meta.save",
            "false",
            "--meta.body",
            "{\"Note\":{\"note\":\"cli session\"}}",
            "--envelope.valid-until",
            valid,
            "--envelope.mode",
            "0",
            "--envelope.fee",
            "0"
        ]),
        json!([
            "--as",
            "q",
            "op",
            "quote",
            "--prepared",
            "p",
            "--path",
            path
        ]),
        json!(["op", "submit", "--prepared", "p", "--quote", "q"]),
    ]
    .map(|l| format!("{l}\n"))
    .concat();
    let pass = dir.join("pass");
    std::fs::write(&pass, format!("{PASS}\n")).unwrap();
    let mut a = base.clone();
    a.extend(
        [
            "--yes",
            "--unlock",
            &seed,
            "--passphrase-fd",
            "3",
            "session",
        ]
        .map(String::from),
    );
    let p = pass.to_str().unwrap().to_string();
    let o = tokio::task::spawn_blocking(move || {
        let mut c = Command::new("sh")
            .arg("-c")
            .arg("exec \"$0\" \"$@\" 3<\"$SCAAS_TEST_PASS_FILE\"")
            .arg(BIN)
            .args(&a)
            .env("SCAAS_TEST_PASS_FILE", p)
            .env_remove("XDG_CONFIG_HOME")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin
            .take()
            .unwrap()
            .write_all(session.as_bytes())
            .unwrap();
        c.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    assert!(o.status.success(), "{}", err(&o));
    let l = lines(&o);
    assert_eq!(l[0]["handle"], "p", "{}", l[0]);
    assert!(l[1]["value"]["max_cost"].is_string(), "{}", l[1]);
    // the submit's confirm printed what it signs, then the send
    assert_eq!(l[2]["prepared"], l[0]["prepared"]["id"], "{}", l[2]);
    let op2 = l[3]["op"].as_str().unwrap().to_string();
    let mut last = Value::Null;
    for _ in 0..60 {
        let o = cli(&["op", "state", "--op", &op2], String::new())
            .await
            .unwrap();
        last = lines(&o)[0].clone();
        if last.get("Landed").is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert!(last.get("Landed").is_some(), "{last}");
    assert_eq!(balance(rpc, &token, &to), before + 1007);
    std::fs::remove_dir_all(&dir).unwrap();
}
