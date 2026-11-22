// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T22: the CLI `scaas` (CLI-SDK-17) as a process: one command per SDK call both ways, no secret flag, no secret from the
//! environment, named JSON output, the one reveal, a data directory shared with a second SDK under the keystore's lock, pinned
//! profiles; in a `dev-profiles` build the review and the quote before anything is submitted, against the SDK tests' fake
//! chain and gateway (local only).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::io::Write;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_scaas");
const PASS: &str = "river-otter-7 ünï";

/// A fresh data directory under the system's temp dir (removed by the test).
fn data_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("scaas-cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// Runs `scaas <args>` with `stdin`, no terminal, no inherited `SCAAS_*` variable.
fn run(args: &[&str], stdin: &str, env: &[(&str, &str)]) -> Output {
    let mut c = Command::new(BIN);
    c.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c.env_remove("XDG_CONFIG_HOME");
    for (k, v) in env {
        c.env(k, v);
    }
    let mut p = c.spawn().unwrap();
    p.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    p.wait_with_output().unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn lines(o: &Output) -> Vec<Value> {
    out(o)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn commands() -> Value {
    let o = run(&["--json", "commands"], "", &[]);
    assert!(o.status.success(), "{}", err(&o));
    serde_json::from_slice(&o.stdout).unwrap()
}

/// The SDK's public calls from its source: `Type::fn` of each `pub fn` in an `impl Type` block, `<file>::fn` of a free one, and
/// the macro-made entries of `surface::ENTRY_POINTS`; the test feature's entries (`vectors`) and `frb` excepted.
fn sdk_calls() -> BTreeSet<String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../scaas-sdk/src");
    let mut files = vec![root.clone()];
    let mut out = BTreeSet::new();
    while let Some(p) = files.pop() {
        if p.is_dir() {
            files.extend(std::fs::read_dir(&p).unwrap().map(|e| e.unwrap().path()));
            continue;
        }
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if !name.ends_with(".rs")
            || name.ends_with("_tests.rs")
            || name == "tests.rs"
            || name == "frb.rs"
        {
            continue;
        }
        let stem = name.trim_end_matches(".rs").to_string();
        // (type, the impl's indentation)
        let mut ty: Option<(String, String)> = None;
        for l in std::fs::read_to_string(&p).unwrap().lines() {
            // the unit tests at the end of a file
            if l.starts_with("mod tests {") {
                break;
            }
            let body = l.trim_start();
            let indent = &l[..l.len() - body.len()];
            if let Some(rest) = body.strip_prefix("impl") {
                let rest = rest.trim_start_matches(|c| c != ' ').trim();
                let t = rest
                    .trim_end_matches('{')
                    .trim()
                    .rsplit("::")
                    .next()
                    .unwrap()
                    .split('<')
                    .next()
                    .unwrap();
                ty = (!rest.contains(" for ")).then(|| (t.to_string(), indent.to_string()));
                continue;
            }
            if ty.as_ref().is_some_and(|(_, i)| l == format!("{i}}}")) {
                ty = None;
            }
            let f = |s: &str| {
                s.split('(')
                    .next()
                    .unwrap()
                    .split('<')
                    .next()
                    .unwrap()
                    .to_string()
            };
            let method = ty.as_ref().and_then(|(t, i)| {
                let s = l.strip_prefix(&format!("{i}    "))?;
                s.strip_prefix("pub fn ")
                    .or_else(|| s.strip_prefix("pub async fn "))
                    .map(|s| (t.clone(), s))
            });
            if let Some((t, s)) = method {
                out.insert(format!("{t}::{}", f(s)));
            } else if let Some(s) = l
                .strip_prefix("pub fn ")
                .or_else(|| l.strip_prefix("pub async fn "))
            {
                out.insert(format!("{stem}::{}", f(s)));
            }
        }
    }
    for e in scaas_sdk::surface::ENTRY_POINTS {
        let mut m = e.module.chars();
        let t: String = m.next().unwrap().to_uppercase().chain(m).collect();
        out.insert(format!("{t}::{}", e.function));
    }
    out.retain(|c| !c.contains("vectors"));
    out
}

#[test]
fn one_command_per_sdk_call_both_ways() {
    let c = commands();
    let mut cli = BTreeSet::new();
    let mut names = BTreeSet::new();
    for x in c["commands"].as_array().unwrap() {
        assert!(
            cli.insert(x["sdk"].as_str().unwrap().to_string()),
            "two commands run {}",
            x["sdk"]
        );
        let n = x["command"].as_str().unwrap();
        assert!(names.insert(n.to_string()), "command {n} twice");
        // the command shares the call's name (`-` for `_`)
        let call = x["sdk"]
            .as_str()
            .unwrap()
            .rsplit("::")
            .next()
            .unwrap()
            .replace('_', "-");
        assert!(
            n.ends_with(&call) || n.ends_with(&call.trim_start_matches("admin-")),
            "{n} is not named after {call}"
        );
    }
    let excluded: BTreeSet<String> = c["excluded"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["sdk"].as_str().unwrap().to_string())
        .collect();
    let sdk = sdk_calls();
    let missing: Vec<_> = sdk
        .iter()
        .filter(|s| !cli.contains(*s) && !excluded.contains(*s))
        .collect();
    assert!(
        missing.is_empty(),
        "SDK calls without a command: {missing:?}"
    );
    let unknown: Vec<_> = cli.union(&excluded).filter(|s| !sdk.contains(*s)).collect();
    assert!(
        unknown.is_empty(),
        "commands or exclusions naming no SDK call: {unknown:?}"
    );
    assert!(cli.is_disjoint(&excluded));
    // the test feature never reaches the CLI
    assert_eq!(scaas_sdk::features() & scaas_sdk::bits::VECTORS, 0);
    // and an unknown command is refused by name
    let o = run(&["wallet", "prepare-vectors"], "", &[]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("UnknownCommand"));
}

#[test]
fn no_secret_flag_exists() {
    let c = commands();
    let secretish = [
        "pass",
        "word",
        "mnemonic",
        "secret",
        "private",
        "password",
        "signature1",
        "signature2",
    ];
    let mut fds = 0;
    for x in c["commands"].as_array().unwrap() {
        for f in x["flags"].as_array().unwrap() {
            let f = f.as_str().unwrap();
            assert!(
                !secretish.iter().any(|s| f.contains(s)),
                "{}: flag --{f} would take a secret",
                x["command"]
            );
        }
        fds += x["secret_fds"].as_array().unwrap().len();
    }
    assert!(fds > 10, "the secrets are listed as descriptors");
    // a secret given as a value is refused; the same command with the descriptor runs (positive control)
    let d = data_dir("noflag");
    let dd = d.to_str().unwrap();
    let o = run(
        &[
            "--data-dir",
            dd,
            "vault",
            "generate",
            "--label",
            "a",
            "--vault-passphrase",
            PASS,
        ],
        "",
        &[],
    );
    assert!(!o.status.success());
    assert!(err(&o).contains("Argument"), "{}", err(&o));
    let o = run(
        &[
            "--data-dir",
            dd,
            "vault",
            "generate",
            "--label",
            "a",
            "--vault-passphrase-fd",
            "0",
        ],
        &format!("{PASS}\nno\n"),
        &[],
    );
    assert!(o.status.success(), "{}", err(&o));
    // global options: --passphrase-fd only
    let o = run(&["--passphrase", PASS, "sdk", "api-version"], "", &[]);
    assert!(err(&o).contains("UnknownFlag"));
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn secret_never_from_environment() {
    let d = data_dir("env");
    let dd = d.to_str().unwrap();
    let env = [
        ("SCAAS_PASSPHRASE", PASS),
        ("SCAAS_VAULT_PASSPHRASE", PASS),
        ("VAULT_PASSPHRASE", PASS),
        ("PASSPHRASE", PASS),
    ];
    // no descriptor, no terminal: refused whatever the environment holds
    let o = run(
        &["--data-dir", dd, "vault", "generate", "--label", "a"],
        "",
        &env,
    );
    assert!(!o.status.success());
    assert!(err(&o).contains("NoTerminal"), "{}", err(&o));
    let o = run(&["--data-dir", dd, "--json", "vault", "seeds"], "", &[]);
    assert_eq!(
        lines(&o)[0].as_array().map(Vec::len),
        Some(0),
        "nothing was made"
    );
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn json_output_has_named_fields() {
    let d = data_dir("json");
    let dd = d.to_str().unwrap();
    let o = run(&["--json", "--data-dir", dd, "sdk", "api-version"], "", &[]);
    assert_eq!(lines(&o), vec![serde_json::json!({"api_version": 1})]);
    let o = run(
        &[
            "--json",
            "--data-dir",
            dd,
            "keystore",
            "is-uuid4",
            "--s",
            "x",
        ],
        "",
        &[],
    );
    assert_eq!(lines(&o), vec![serde_json::json!({"is_uuid4": false})]);
    let o = run(
        &[
            "--json",
            "--data-dir",
            dd,
            "vault",
            "generate",
            "--label",
            "Main",
            "--vault-passphrase-fd",
            "0",
        ],
        &format!("{PASS}\nno\n"),
        &[],
    );
    let l = lines(&o);
    assert_eq!(l.len(), 2, "{}", out(&o));
    assert!(
        l[0]["seed"]["id"].is_string() && l[0]["seed"]["label"] == "Main",
        "{}",
        l[0]
    );
    assert_eq!(l[1], serde_json::json!({"backup": "closed"}));
    // the table form names each row
    let o = run(&["--data-dir", dd, "sdk", "api-version"], "", &[]);
    assert_eq!(out(&o), "api_version: 1\n");
    // and an error is a named code on stderr
    let o = run(
        &[
            "--json",
            "--data-dir",
            dd,
            "vault",
            "seed",
            "--seed",
            "nope",
        ],
        "",
        &[],
    );
    let e: Value = serde_json::from_str(err(&o).trim().lines().last().unwrap()).unwrap();
    assert!(e["error"].is_string());
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn generate_reveals_once() {
    let d = data_dir("reveal");
    let dd = d.to_str().unwrap();
    let o = run(
        &[
            "--json",
            "--data-dir",
            dd,
            "vault",
            "generate",
            "--label",
            "a",
            "--vault-passphrase-fd",
            "0",
        ],
        &format!("{PASS}\nreveal\n"),
        &[],
    );
    assert!(o.status.success(), "{}", err(&o));
    let l = lines(&o);
    let words = l[1]["words"].as_str().unwrap();
    assert_eq!(words.split(' ').count(), 24);
    assert_eq!(out(&o).matches(words).count(), 1, "the words once");
    // --yes never answers the reveal
    let o = run(
        &[
            "--json",
            "--yes",
            "--data-dir",
            dd,
            "vault",
            "generate",
            "--label",
            "b",
            "--vault-passphrase-fd",
            "0",
        ],
        &format!("{PASS}\n\n"),
        &[],
    );
    assert!(o.status.success());
    assert_eq!(
        lines(&o)[1],
        serde_json::json!({"backup": "closed"}),
        "{}",
        out(&o)
    );
    assert_eq!(lines(&o).len(), 2);
    // a second process holds no backup: the words are never shown again (the SDK refuses a second reveal, tests/vault.rs)
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn session_passes_objects_by_name() {
    let d = data_dir("session");
    let dd = d.to_str().unwrap();
    let s = format!(
        "{}\n{}\n{}\n",
        serde_json::json!(["--as", "s", "sdk", "subscribe"]),
        serde_json::json!([
            "subscription",
            "next",
            "--subscription",
            "s",
            "--timeout-ms",
            "10"
        ]),
        serde_json::json!([
            "subscription",
            "next",
            "--subscription",
            "nope",
            "--timeout-ms",
            "10"
        ]),
    );
    let o = run(&["--json", "--data-dir", dd, "session"], &s, &[]);
    let l = lines(&o);
    assert_eq!(l[0]["handle"], "s");
    assert_eq!(l[1], serde_json::json!({"event": null}));
    // an unknown name is refused, and the session stops there
    assert_eq!(l.len(), 2);
    assert!(
        err(&o).contains("Argument") && err(&o).contains("no object named"),
        "{}",
        err(&o)
    );
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn remove_asks_first() {
    let d = data_dir("remove");
    let dd = d.to_str().unwrap();
    let o = run(
        &[
            "--json",
            "--data-dir",
            dd,
            "vault",
            "generate",
            "--label",
            "a",
            "--vault-passphrase-fd",
            "0",
        ],
        &format!("{PASS}\nno\n"),
        &[],
    );
    let id = lines(&o)[0]["seed"]["id"].as_str().unwrap().to_string();
    let rm = |answer: &str| {
        run(
            &[
                "--json",
                "--data-dir",
                dd,
                "vault",
                "remove",
                "--seed",
                &id,
                "--unbacked",
                "true",
            ],
            &format!("{answer}\n"),
            &[],
        )
    };
    let o = rm("n");
    assert!(err(&o).contains("NotConfirmed"), "{}", err(&o));
    assert_eq!(
        lines(&o)[0],
        serde_json::json!({"remove": id, "unbacked": true})
    );
    let seeds = |dd: &str| {
        lines(&run(
            &["--json", "--data-dir", dd, "vault", "seeds"],
            "",
            &[],
        ))[0]
            .as_array()
            .unwrap()
            .len()
    };
    assert_eq!(seeds(dd), 1);
    let o = rm("y");
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(seeds(dd), 0);
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn cli_and_sdk_share_a_directory() {
    let d = data_dir("share");
    let dd = d.to_str().unwrap().to_string();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let store = scaas_sdk::vault::FileStore::new(&dd).unwrap();
        let sdk = scaas_sdk::Sdk::open(scaas_sdk::SdkConfig {
            profiles: vec![],
            store,
            authenticator: None,
            rp_id: None,
            runtime: scaas_sdk::RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
            limits: Default::default(),
            clock: None,
            gas_tables: vec![],
        })
        .await
        .unwrap();
        let sec = |s: &str| {
            std::sync::Arc::new(
                scaas_ua::wallet::SecretBytes::from_zeroizing(zeroize::Zeroizing::new(
                    s.as_bytes().to_vec(),
                ))
                .unwrap(),
            )
        };
        let a = sdk
            .vault()
            .generate(scaas_sdk::vault::Generate {
                label: "sdk".into(),
                vault_passphrase: sec(PASS),
            })
            .await
            .unwrap()
            .info
            .id;
        // the CLI writes while this SDK holds the directory
        let dd2 = dd.clone();
        let o = tokio::task::spawn_blocking(move || {
            run(
                &[
                    "--json",
                    "--data-dir",
                    &dd2,
                    "vault",
                    "generate",
                    "--label",
                    "cli",
                    "--vault-passphrase-fd",
                    "0",
                ],
                &format!("{PASS}\nno\n"),
                &[],
            )
        })
        .await
        .unwrap();
        assert!(o.status.success(), "{}", err(&o));
        let b = lines(&o)[0]["seed"]["id"].as_str().unwrap().to_string();
        // then the SDK writes again
        sdk.vault().rename(a.clone(), "sdk2".into()).await.unwrap();
        let seeds = sdk.vault().seeds().await.unwrap();
        let labels: BTreeSet<_> = seeds
            .iter()
            .map(|s| (s.id.clone(), s.label.clone()))
            .collect();
        assert_eq!(
            labels,
            BTreeSet::from([
                (a.clone(), "sdk2".to_string()),
                (b.clone(), "cli".to_string())
            ])
        );
        // and the CLI reads both changes
        let dd3 = dd.clone();
        let o = tokio::task::spawn_blocking(move || {
            run(&["--json", "--data-dir", &dd3, "vault", "seeds"], "", &[])
        })
        .await
        .unwrap();
        let l = lines(&o);
        let got: BTreeSet<_> = l[0]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["label"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(got, BTreeSet::from(["sdk2".to_string(), "cli".to_string()]));
    });
    std::fs::remove_dir_all(&d).unwrap();
}

const PROFILE: &str = r#"{"profiles":[{"key":"local","family":"Evm","chain_id":31337,"chain_uid":"0x0000000000000000000000000000000000000000000000000000000000000001","rpc":[{"url":"http://127.0.0.1:9","label":"a"}],"finality":"Finalized","tx_gas_cap":null,"registry":null,"factory":null,"router":null,"max_valid_secs":null}]}"#;

#[test]
fn profiles_pinned() {
    let d = data_dir("pinned");
    let dd = d.to_str().unwrap();
    std::fs::create_dir_all(&d).unwrap();
    let pf = d.join("profiles.json");
    std::fs::write(&pf, PROFILE).unwrap();
    let o = run(
        &[
            "--data-dir",
            dd,
            "--profiles",
            pf.to_str().unwrap(),
            "sdk",
            "api-version",
        ],
        "",
        &[],
    );
    if cfg!(feature = "dev-profiles") {
        assert!(o.status.success(), "{}", err(&o));
        assert!(
            err(&o).contains("DEVELOPMENT BUILD") && err(&o).contains("sha256"),
            "{}",
            err(&o)
        );
    } else {
        assert!(!o.status.success());
        assert!(err(&o).contains("ProfilesPinned"), "{}", err(&o));
        // the release profiles are the compiled ones, no banner
        let o = run(&["--data-dir", dd, "sdk", "api-version"], "", &[]);
        assert!(o.status.success() && !err(&o).contains("DEVELOPMENT"));
    }
    // an overlay: a lower cap accepted, a raised one, a chain_uid, a contract or an endpoint list refused
    let ov = d.join("overlay.json");
    for (text, ok) in [
        (r#"{"limits":{"max_gas":1000}}"#, true),
        (r#"{"limits":{"max_gas":999999999999}}"#, false),
        (r#"{"chain_uid":"0x00"}"#, false),
        (r#"{"registry":"0x00"}"#, false),
        (r#"{"rpc":[{"url":"http://127.0.0.1:1"}]}"#, false),
    ] {
        std::fs::write(&ov, text).unwrap();
        let o = run(
            &[
                "--json",
                "--data-dir",
                dd,
                "--overlay",
                ov.to_str().unwrap(),
                "sdk",
                "limits",
            ],
            "",
            &[],
        );
        assert_eq!(o.status.success(), ok, "{text}: {}", err(&o));
        if ok {
            assert_eq!(lines(&o)[0]["max_gas"], 1000);
        }
    }
    std::fs::remove_dir_all(&d).unwrap();
}

#[cfg(feature = "dev-profiles")]
#[path = "../../scaas-sdk/tests/common/fake_chain.rs"]
mod fake_chain;

/// Without `--yes` an operation prints its review and its quote and stops on `n`, nothing sent; on `y` it is submitted once.
#[cfg(feature = "dev-profiles")]
#[test]
fn review_and_quote_before_submit() {
    use fake_chain::{fake, serve, CHAIN_ID};
    use serde_json::json;
    const WORDS: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
    let root = |p: &str| format!("{}/../../{p}", env!("CARGO_MANIFEST_DIR"));
    let v: Value = serde_json::from_str(
        &std::fs::read_to_string(root("smartcontracts/vectors/typed/typed_ops.json")).unwrap(),
    )
    .unwrap();
    let d = &v["ops"]["UACancelNonce"]["domains"]["token"]["domain"];
    let (salt, token) = (
        d["salt"].as_str().unwrap().to_string(),
        d["verifyingContract"].as_str().unwrap().to_string(),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let dir = data_dir("review");
    let dd = dir.to_str().unwrap().to_string();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let chain = fake();
        {
            let mut c = chain.lock().unwrap();
            c.domains.insert(token.clone(), ("SCaaS MetaToken".into(), salt.clone()));
            c.gw_info["chains"][0]["chain_uid"] = json!(salt);
            c.genesis = salt.clone();
            c.timestamp = now;
        }
        let rpc = serve(chain.clone()).await;
        let gw = serve(chain.clone()).await;
        let profile = json!({"profiles": [{"key": "local", "family": "Evm", "chain_id": CHAIN_ID, "chain_uid": salt,
            "rpc": [{"url": rpc}], "gateways": [{"url": gw}], "finality": "Finalized", "tx_gas_cap": 16777216,
            "registry": null, "factory": null, "router": null, "max_valid_secs": null}]});
        std::fs::create_dir_all(&dir).unwrap();
        let pf = dir.join("profiles.json");
        std::fs::write(&pf, profile.to_string()).unwrap();
        // the seed and the vector key, written by the CLI itself
        let pfs = pf.to_str().unwrap().to_string();
        let base = vec!["--json".to_string(), "--data-dir".into(), dd.clone(), "--profiles".into(), pfs];
        let cli = move |extra: Vec<String>, stdin: String| {
            let mut a = base.clone();
            a.extend(extra);
            tokio::task::spawn_blocking(move || {
                let a: Vec<&str> = a.iter().map(String::as_str).collect();
                run(&a, &stdin, &[])
            })
        };
        let s = |x: &[&str]| x.iter().map(|w| w.to_string()).collect::<Vec<_>>();
        let o = cli(s(&["vault", "import-words", "--label", "m", "--words-fd", "0", "--vault-passphrase-fd", "0"]), format!("{WORDS}\n{PASS}\n")).await.unwrap();
        assert!(o.status.success(), "{}", err(&o));
        let seed = lines(&o)[0]["id"].as_str().unwrap().to_string();
        let private = v["key"]["private"].as_str().unwrap();
        let o = cli(s(&["--unlock", &seed, "--passphrase-fd", "0", "vault", "import-key", "--seed", &seed, "--network", "evm", "--secret-fd", "0", "--vault-passphrase-fd", "0"]), format!("{PASS}\n{private}\n{PASS}\n")).await.unwrap();
        assert!(o.status.success(), "{}", err(&o));
        let index = lines(&o)[0]["index"].as_u64().unwrap();
        let signer = json!({"Imported": {"seed": seed, "network": "evm", "index": index}}).to_string();
        let op = |answer: &str| {
            let mut a = s(&["--unlock", &seed, "--passphrase-fd", "0", "--path", "Gateway", "wallet", "prepare-cancel-nonce", "--chain", "local", "--contract", &token, "--batch", "0", "--lane", "7"]);
            a.extend(s(&["--signer", &signer, "--envelope.valid-until", &(now + 3600).to_string(), "--envelope.mode", "0", "--envelope.fee", "0"]));
            cli(a, format!("{PASS}\n{answer}\n"))
        };
        let o = op("n").await.unwrap();
        assert!(!o.status.success());
        assert!(err(&o).contains("NotConfirmed"), "{}", err(&o));
        let shown = &lines(&o)[0];
        assert!(shown["review"].as_array().unwrap().iter().any(|f| f["name"] == "lane"), "{shown}");
        assert!(shown["quote"]["max_cost"].is_string() && shown["quote"]["path"] == "Gateway", "{shown}");
        assert!(chain.lock().unwrap().bodies.is_empty(), "nothing sent on n");
        let o = op("y").await.unwrap();
        assert!(o.status.success(), "{}", err(&o));
        let l = lines(&o);
        assert!(l[0]["prepared"].as_str().unwrap().starts_with("0x"), "{}", l[0]);
        assert!(l[1]["op"].is_string(), "{}", l[1]);
        // the send was reported before the process ended
        assert!(l[1]["state"]["InFlight"].is_object(), "{}", l[1]);
        assert_eq!(chain.lock().unwrap().bodies.len(), 1);
    });
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The confirm a command must have, from its SDK call's name alone (not from the CLI's table): a call that signs or submits
/// asks first (`sign`); a `prepare_*` or `admin_ua_*` call's operation is submitted only after its review and quote are
/// confirmed (`op`: the CLI's one confirm of an operation object); any other call neither signs nor submits (the removal of
/// a seed asks too, as the one destructive local change).
fn confirm_class(sdk: &str) -> Option<&'static str> {
    let f = sdk.rsplit("::").next().unwrap();
    let signs = f.starts_with("sign_")
        || f.contains("_sign_")
        || f.starts_with("submit")
        || [
            "member_sign",
            "hand_off",
            "place",
            "cancel_all",
            "resend",
            "register_bls_multi",
            "bls_multi_part",
            "bls_multi_pop_part",
            "pqchat_seal_message",
            "prepare_app_call",
            // SDK plan T41.soroban: the signer's hand-off, the subject's op signed, the payer's native send signed
            "soroban_submit",
            "soroban_hand_off",
            "soroban_submit_native_send",
        ]
        .contains(&f)
        || sdk == "Vault::remove";
    if signs {
        Some("sign")
    } else if f.starts_with("prepare_") || f.starts_with("admin_ua_") || f == "import_signed" {
        Some("op")
    } else {
        None
    }
}

/// `scaas commands` names each command's confirm, and it is the one its SDK call asks for (both ways): a signing command
/// listed without its confirm, or a reading one listed with one, fails here.
#[test]
fn every_command_declares_its_confirm_class() {
    let c = commands();
    let (mut sign, mut op) = (0, 0);
    for x in c["commands"].as_array().unwrap() {
        let want = confirm_class(x["sdk"].as_str().unwrap());
        assert_eq!(
            x["confirm"].as_str(),
            want,
            "{}: confirm {} (its SDK call {})",
            x["command"],
            x["confirm"],
            x["sdk"]
        );
        match want {
            Some("sign") => sign += 1,
            Some("op") => op += 1,
            _ => {}
        }
    }
    assert!(
        sign >= 30 && op >= 120,
        "{sign} signing, {op} operation commands"
    );
}

/// A value of `T` with every field at its zero (false, 0, "", empty, absent, an enum's first variant): a signing command
/// confirms before the SDK reads its request, so any value of the type reaches the confirm.
fn zero<T: serde::de::DeserializeOwned + serde::Serialize>() -> Value {
    let mut v = serde_json::to_value(T::deserialize(Zero).unwrap()).unwrap();
    fn strip(v: &mut Value) {
        match v {
            Value::Object(m) => {
                m.retain(|_, x| !x.is_null());
                m.values_mut().for_each(strip);
            }
            Value::Array(a) => a.iter_mut().for_each(strip),
            _ => {}
        }
    }
    strip(&mut v);
    v
}

struct Zero;
struct ZSeq(usize);
struct ZFields(std::slice::Iter<'static, &'static str>);
struct ZEnum(&'static str);
type ZErr = serde::de::value::Error;

impl<'de> serde::Deserializer<'de> for Zero {
    type Error = ZErr;
    fn deserialize_any<V: serde::de::Visitor<'de>>(self, v: V) -> Result<V::Value, ZErr> {
        v.visit_u64(0)
    }
    fn deserialize_bool<V: serde::de::Visitor<'de>>(self, v: V) -> Result<V::Value, ZErr> {
        v.visit_bool(false)
    }
    fn deserialize_f32<V: serde::de::Visitor<'de>>(self, v: V) -> Result<V::Value, ZErr> {
        v.visit_f64(0.0)
    }
    fn deserialize_f64<V: serde::de::Visitor<'de>>(self, v: V) -> Result<V::Value, ZErr> {
        v.visit_f64(0.0)
    }
    fn deserialize_char<V: serde::de::Visitor<'de>>(self, v: V) -> Result<V::Value, ZErr> {
        v.visit_char('0')
    }
    fn deserialize_str<V: serde::de::Visitor<'de>>(self, v: V) -> Result<V::Value, ZErr> {
        v.visit_str("")
    }
    fn deserialize_string<V: serde::de::Visitor<'de>>(self, v: V) -> Result<V::Value, ZErr> {
        v.visit_str("")
    }
    fn deserialize_bytes<V: serde::de::Visitor<'de>>(self, v: V) -> Result<V::Value, ZErr> {
        v.visit_bytes(&[])
    }
    fn deserialize_byte_buf<V: serde::de::Visitor<'de>>(self, v: V) -> Result<V::Value, ZErr> {
        v.visit_bytes(&[])
    }
    fn deserialize_option<V: serde::de::Visitor<'de>>(self, v: V) -> Result<V::Value, ZErr> {
        v.visit_none()
    }
    fn deserialize_unit<V: serde::de::Visitor<'de>>(self, v: V) -> Result<V::Value, ZErr> {
        v.visit_unit()
    }
    fn deserialize_unit_struct<V: serde::de::Visitor<'de>>(
        self,
        _: &'static str,
        v: V,
    ) -> Result<V::Value, ZErr> {
        v.visit_unit()
    }
    fn deserialize_newtype_struct<V: serde::de::Visitor<'de>>(
        self,
        _: &'static str,
        v: V,
    ) -> Result<V::Value, ZErr> {
        v.visit_newtype_struct(self)
    }
    fn deserialize_seq<V: serde::de::Visitor<'de>>(self, v: V) -> Result<V::Value, ZErr> {
        v.visit_seq(ZSeq(0))
    }
    fn deserialize_tuple<V: serde::de::Visitor<'de>>(
        self,
        n: usize,
        v: V,
    ) -> Result<V::Value, ZErr> {
        v.visit_seq(ZSeq(n))
    }
    fn deserialize_tuple_struct<V: serde::de::Visitor<'de>>(
        self,
        _: &'static str,
        n: usize,
        v: V,
    ) -> Result<V::Value, ZErr> {
        v.visit_seq(ZSeq(n))
    }
    fn deserialize_map<V: serde::de::Visitor<'de>>(self, v: V) -> Result<V::Value, ZErr> {
        v.visit_map(ZFields([].iter()))
    }
    fn deserialize_struct<V: serde::de::Visitor<'de>>(
        self,
        _: &'static str,
        fields: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, ZErr> {
        v.visit_map(ZFields(fields.iter()))
    }
    fn deserialize_enum<V: serde::de::Visitor<'de>>(
        self,
        _: &'static str,
        variants: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, ZErr> {
        v.visit_enum(ZEnum(variants[0]))
    }
    serde::forward_to_deserialize_any! { i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 identifier ignored_any }
}

impl<'de> serde::de::SeqAccess<'de> for ZSeq {
    type Error = ZErr;
    fn next_element_seed<S: serde::de::DeserializeSeed<'de>>(
        &mut self,
        s: S,
    ) -> Result<Option<S::Value>, ZErr> {
        if self.0 == 0 {
            return Ok(None);
        }
        self.0 -= 1;
        s.deserialize(Zero).map(Some)
    }
}

impl<'de> serde::de::MapAccess<'de> for ZFields {
    type Error = ZErr;
    fn next_key_seed<K: serde::de::DeserializeSeed<'de>>(
        &mut self,
        k: K,
    ) -> Result<Option<K::Value>, ZErr> {
        use serde::de::IntoDeserializer;
        self.0
            .next()
            .map(|f| k.deserialize((*f).into_deserializer()))
            .transpose()
    }
    fn next_value_seed<S: serde::de::DeserializeSeed<'de>>(
        &mut self,
        s: S,
    ) -> Result<S::Value, ZErr> {
        s.deserialize(Zero)
    }
}

impl<'de> serde::de::EnumAccess<'de> for ZEnum {
    type Error = ZErr;
    type Variant = Zero;
    fn variant_seed<S: serde::de::DeserializeSeed<'de>>(
        self,
        s: S,
    ) -> Result<(S::Value, Zero), ZErr> {
        use serde::de::IntoDeserializer;
        Ok((s.deserialize(self.0.into_deserializer())?, Zero))
    }
}

impl<'de> serde::de::VariantAccess<'de> for Zero {
    type Error = ZErr;
    fn unit_variant(self) -> Result<(), ZErr> {
        Ok(())
    }
    fn newtype_variant_seed<S: serde::de::DeserializeSeed<'de>>(
        self,
        s: S,
    ) -> Result<S::Value, ZErr> {
        s.deserialize(Zero)
    }
    fn tuple_variant<V: serde::de::Visitor<'de>>(self, n: usize, v: V) -> Result<V::Value, ZErr> {
        v.visit_seq(ZSeq(n))
    }
    fn struct_variant<V: serde::de::Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, ZErr> {
        v.visit_map(ZFields(fields.iter()))
    }
}

/// An object's fields as `--name value` flags (text as is, anything else as JSON).
#[cfg(feature = "dev-profiles")]
fn as_flags(v: &Value) -> Vec<String> {
    let mut out = vec![];
    for (k, x) in v.as_object().unwrap() {
        out.push(format!("--{}", k.replace('_', "-")));
        out.push(match x {
            Value::String(s) => s.clone(),
            o => o.to_string(),
        });
    }
    out
}

/// `scaas <args> session` without a controlling terminal (`setsid`): a confirm asked in a session reads the terminal only,
/// so here it refuses by name; the passphrase on descriptor 3 from `pass_file`.
#[cfg(feature = "dev-profiles")]
fn run_session(args: &[String], lines: &[Value], pass_file: &str) -> Output {
    let mut c = Command::new("setsid");
    c.arg("-w")
        .arg("sh")
        .arg("-c")
        .arg("exec \"$0\" \"$@\" 3<\"$SCAAS_TEST_PASS_FILE\"")
        .arg(BIN)
        .args(args)
        .arg("session")
        .env("SCAAS_TEST_PASS_FILE", pass_file)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut p = c.spawn().unwrap();
    let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
    p.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
    p.wait_with_output().unwrap()
}

/// Every signing command of `scaas commands` (its SDK call signs or submits, [`confirm_class`]) shows what it signs and asks
/// before anything is signed or sent: one run each, answered `n` (a session's confirm, with no terminal, refuses by name),
/// against the fake chain and gateway, which receive nothing. A command without its run here fails the test; so does one
/// that signs or sends without asking. Then each operation object (a prepared operation, registry writes, an order, a native
/// send) prepared by one command stops at its confirm the same way.
#[cfg(feature = "dev-profiles")]
#[test]
fn every_signing_command_asks_first() {
    use fake_chain::{fake, keccak_hex, serve, CHAIN_ID};
    use serde_json::json;
    const WORDS: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
    const REGISTRY: &str = "0x5ca000000000000000000000000000000000000e";
    const DEX: &str = "0x5ca00000000000000000000000000000000000b4";
    const RECEIVE: &str = "0x5ca00000000000000000000000000000000000b3";
    const FACTORY: &str = "0x5ca000000000000000000000000000000000f0f0";
    const APP_CONTRACT: &str = "0x00000000000000000000000000000000000000aa";
    const APP_ID: &str = "0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
    const ED25519: u16 = 0x0102;
    let sel = |sig: &str| keccak_hex(sig.as_bytes())[..10].to_string();
    let word = |hex: &str| format!("{:0>64}", hex.trim_start_matches("0x"));
    let w = |n: u64| format!("{n:064x}");
    let root = |p: &str| format!("{}/../../{p}", env!("CARGO_MANIFEST_DIR"));
    let v: Value = serde_json::from_str(
        &std::fs::read_to_string(root("smartcontracts/vectors/typed/typed_ops.json")).unwrap(),
    )
    .unwrap();
    let d = &v["ops"]["UACancelNonce"]["domains"]["token"]["domain"];
    let (salt, token) = (
        d["salt"].as_str().unwrap().to_string(),
        d["verifyingContract"].as_str().unwrap().to_string(),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // the seed's ed25519 UA, from scaas-ua directly
    let ua: String = scaas_ua::wallet::Wallet::from_mnemonic(WORDS, "")
        .unwrap()
        .ua_key(ED25519, 0, 0)
        .unwrap()
        .ua()
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let ua = format!("0x{ua}");
    let dir = data_dir("confirm");
    let dd = dir.to_str().unwrap().to_string();
    std::fs::create_dir_all(&dir).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let chain = fake();
        {
            let mut c = chain.lock().unwrap();
            c.domains.insert(token.clone(), ("SCaaS MetaToken".into(), salt.clone()));
            c.gw_info["chains"][0]["chain_uid"] = json!(salt);
            c.genesis = salt.clone();
            c.timestamp = now;
            // the DEX order's contracts (tests/dex.rs's fake): each kind's token, the DEX and its factory
            for (k, name) in [("token", "SCaaS MetaToken"), ("zether", "SCaaS ZetherToken"), ("pqz", "SCaaS PqzToken")] {
                let at = v["ops"]["CancelUAOrder"]["domains"][k]["domain"]["verifyingContract"].as_str().unwrap();
                c.domains.insert(at.into(), (name.into(), salt.clone()));
                c.answers.push((FACTORY.into(), format!("{}{}", sel("versionOf(address)"), word(at)), format!("0x{}{}", word("1"), word("1"))));
                c.answers.push((at.into(), sel("minNonce(bytes32,uint256)"), format!("0x{}", word("5"))));
            }
            c.domains.insert(DEX.into(), ("SCaaS Dex".into(), salt.clone()));
            c.answers.push((DEX.into(), sel("factory()"), format!("0x{}", word(FACTORY))));
            c.answers.push((DEX.into(), sel("minNonce(address,uint256)"), format!("0x{}", word("9"))));
            // the app contract: catalogued by the factory as class 7 (tests/app_core.rs's prepare_app_call)
            let app = word(APP_CONTRACT);
            c.answers.push((FACTORY.into(), format!("{}{app}", sel("infoOf(address)")), format!("0x{app}{}{}{}{}{}{}", w(9), w(7), w(1), w(1), w(1), w(1))));
            c.answers.push((FACTORY.into(), sel("versionOf(address)"), format!("0x{}{}", word("0"), word("0"))));
            // the registry: the seed's ed25519 UA not registered (tests/account_ops.rs's fake registry)
            let u = &ua[2..];
            c.answers.push((REGISTRY.into(), format!("{}{u}", sel("isRegistered(bytes32)")), format!("0x{}", w(0))));
            c.answers.push((REGISTRY.into(), format!("{}{u}", sel("registrationOf(bytes32)")),
                format!("0x{}{}{}{}{}{}{}{}{}{}{}{}", w(1), w(0xa0), w(0xc0), w(0x1c0), w(0x1e0), w(0), w(0x80), w(0), w(0xa0), w(0), w(0), w(0))));
            c.answers.push((REGISTRY.into(), format!("{}{u}", sel("expandedKeyOf(bytes32)")), format!("0x{}{}{}", w(0xc1), w(0xc2), w(0xc3))));
            c.answers.push((REGISTRY.into(), format!("{}{u}", sel("pqzKeyAt(bytes32,uint64)")), format!("0x{}{}{}", w(0), w(0), w(0))));
            c.answers.push((REGISTRY.into(), format!("{}{u}", sel("pqzPopOf(bytes32,uint64)")), format!("0x{}{}", w(0x20), w(0))));
            c.answers.push((REGISTRY.into(), format!("{}{u}", sel("kemKeyAt(bytes32,uint64)")), format!("0x{}{}{}{}{}{}", w(0x40), w(0xe0), w(0), w(0x60), w(0), w(0))));
        }
        let rpc = serve(chain.clone()).await;
        let gw = serve(chain.clone()).await;
        let profile = json!({"profiles": [{"key": "local", "family": "Evm", "chain_id": CHAIN_ID, "chain_uid": salt,
            "rpc": [{"url": rpc}], "gateways": [{"url": gw}], "finality": "Finalized", "tx_gas_cap": 16777216,
            "registry": REGISTRY, "factory": FACTORY, "router": null, "max_valid_secs": null,
            "tokens": [{"address": token, "symbol": "VND", "decimals": 0}],
            "dexes": [{"address": DEX, "liquidity": true, "position_readers": []}]}]});
        let pf = dir.join("profiles.json");
        std::fs::write(&pf, profile.to_string()).unwrap();
        let app = dir.join("app.json");
        std::fs::write(&app, json!({"app_id": APP_ID, "name": "My App", "class": 7, "labels": ["scaas/call/v1/"]}).to_string()).unwrap();
        let pass_file = dir.join("pass");
        std::fs::write(&pass_file, format!("{PASS}\n")).unwrap();
        let base = vec!["--json".to_string(), "--data-dir".into(), dd.clone(), "--profiles".into(),
            pf.to_str().unwrap().to_string(), "--app".into(), app.to_str().unwrap().to_string()];
        let one = {
            let base = base.clone();
            move |extra: Vec<String>, stdin: String| {
                let mut a = base.clone();
                a.extend(extra);
                tokio::task::spawn_blocking(move || {
                    let a: Vec<&str> = a.iter().map(String::as_str).collect();
                    run(&a, &stdin, &[])
                })
            }
        };
        let s = |x: &[&str]| x.iter().map(|w| w.to_string()).collect::<Vec<_>>();
        let o = one(s(&["vault", "import-words", "--label", "m", "--words-fd", "0", "--vault-passphrase-fd", "0"]), format!("{WORDS}\n{PASS}\n")).await.unwrap();
        assert!(o.status.success(), "{}", err(&o));
        let seed = lines(&o)[0]["id"].as_str().unwrap().to_string();
        let private = v["key"]["private"].as_str().unwrap();
        let o = one(s(&["--unlock", &seed, "--passphrase-fd", "0", "vault", "import-key", "--seed", &seed, "--network", "evm", "--secret-fd", "0", "--vault-passphrase-fd", "0"]), format!("{PASS}\n{private}\n{PASS}\n")).await.unwrap();
        assert!(o.status.success(), "{}", err(&o));
        let index = lines(&o)[0]["index"].as_u64().unwrap();
        let signer = json!({"Imported": {"seed": seed, "network": "evm", "index": index}});
        let native = json!({"Native": {"seed": seed, "network": "evm", "index": 0}});
        let ua_key = json!({"Ua": {"seed": seed, "kind": ED25519, "account": 0, "index": 0}});
        let (sg, nk) = (signer.to_string(), native.to_string());
        let valid = (now + 3600).to_string();
        // the objects a session's signing command takes, made by the commands that make them
        let prepared = || vec![
            json!(["--as", "p", "wallet", "prepare-cancel-nonce", "--chain", "local", "--contract", token, "--batch", "0", "--lane", "7",
                "--signer", sg, "--envelope.valid-until", valid, "--envelope.mode", "0", "--envelope.fee", "0"]),
            json!(["--as", "q", "op", "quote", "--prepared", "p", "--path", "Gateway"]),
        ];
        let order = json!(["--as", "o", "dex", "prepare-trade-order", "--signer", sg, "--chain", "local", "--sell-token", token, "--dex", DEX,
            "--receive-token", RECEIVE, "--amount", "1000", "--receive-amount", "2000", "--min-fill", "250", "--fee", "3000",
            "--relayer", "0x000000000000000000000000000000000000beef", "--flags", "0", "--batch", "7", "--valid-until", valid]);
        let register = json!(["--as", "w", "account", "prepare-register", "--key", ua_key.to_string(), "--chain", "local",
            "--attrs", "{\"pqz_key\":false,\"kem\":false}", "--payer", nk]);
        let app_key = |n: &str| json!(["--as", n, "app-core", "random-key", "--seed", seed, "--usage", "Derive"]);
        enum Run {
            /// one command, stdin answers `n`
            One(Vec<String>),
            /// a session: the lines before the signing command, then it
            Session(Vec<Value>, Value),
        }
        let zf = |pre: &[&str], z: Value| {
            let mut a = s(pre);
            a.extend(as_flags(&z));
            Run::One(a)
        };
        let rec = |cmd: &str, z: Value| {
            let mut a = s(&["app-core", cmd, "--account", &sg]);
            a.extend(["--r".to_string(), z.to_string()]);
            Run::One(a)
        };
        use scaas_sdk::pqchat_records::*;
        let fixture = |cmd: &str| -> Option<Run> {
            Some(match cmd {
                "vault remove" => Run::One(s(&["vault", "remove", "--seed", &seed, "--unbacked", "true"])),
                "op submit" => Run::Session(prepared(), json!(["op", "submit", "--prepared", "p", "--quote", "q"])),
                "op resend" => Run::Session(prepared(), json!(["op", "resend", "--op", "x", "--quote", "q"])),
                "op member-sign" => Run::Session(prepared(), json!(["op", "member-sign", "--prepared", "p"])),
                "op hand-off" => Run::Session(prepared(), json!(["op", "hand-off", "--prepared", "p"])),
                "op bls-multi-part" => Run::Session(prepared(), json!(["op", "bls-multi-part", "--prepared", "p", "--member", sg])),
                "op submit-bls-multi" => Run::Session(prepared(), json!(["op", "submit-bls-multi", "--prepared", "p", "--quote", "q", "--parts", "[]", "--surplus", "false"])),
                "op bls-multi-pop-part" => Run::One(s(&["op", "bls-multi-pop-part", "--member", &sg])),
                "op register-bls-multi" => Run::Session(prepared(), json!(["op", "register-bls-multi", "--chain", "local", "--key-data", "0x00", "--parts", "[]", "--quote", "q"])),
                "account submit-registry-write" => {
                    let mut l = prepared();
                    l.push(register.clone());
                    Run::Session(l, json!(["account", "submit-registry-write", "--write", "w.0", "--quote", "q"]))
                }
                "wallet submit-native-send" => zf(&["wallet", "submit-native-send"], zero::<scaas_sdk::wallet::NativeQuote>()),
                "wallet soroban-submit" => zf(&["wallet", "soroban-submit"], json!({"prepared": zero::<scaas_sdk::wallet::SorobanPrepared>(),
                    "quote": zero::<scaas_sdk::wallet::SorobanQuote>()})),
                "wallet soroban-hand-off" => zf(&["wallet", "soroban-hand-off"], zero::<scaas_sdk::wallet::SorobanPrepared>()),
                "wallet soroban-submit-native-send" => zf(&["wallet", "soroban-submit-native-send"], zero::<scaas_sdk::wallet::SorobanNativeQuote>()),
                "dex sign-order" => Run::Session(vec![order.clone()], json!(["dex", "sign-order", "--order", "o"])),
                "dex place" => Run::Session(vec![order.clone()], json!(["dex", "place", "--order", "o"])),
                "dex cancel-all" => zf(&["dex", "cancel-all"], zero::<scaas_sdk::dex::CancelAll>()),
                "admin sign-rescue-vault" => zf(&["admin", "sign-rescue-vault"], zero::<scaas_sdk::admin::RescueVault>()),
                "admin sign-pqz-auditor-consent" => zf(&["admin", "sign-pqz-auditor-consent"], zero::<scaas_sdk::admin::AuditorConsent>()),
                "admin sign-zether-auditor-consent" => zf(&["admin", "sign-zether-auditor-consent"], zero::<scaas_sdk::admin::AuditorConsent>()),
                "app-core sign-app-record" => Run::One(s(&["app-core", "sign-app-record", "--account", &sg, "--path", "Portable", "--typed-json", "{}"])),
                "app-core sign-pqvault-record" => Run::One(s(&["app-core", "sign-pqvault-record", "--account", &sg, "--path", "Portable", "--typed-json", "{}"])),
                "app-core sign-pqchat-card" => Run::One(s(&["app-core", "sign-pqchat-card", "--account", &sg, "--kem-version", "1", "--matrix-id", ""])),
                "app-core prepare-app-call" => {
                    let entry = json!({"type": "function", "name": "ping", "stateMutability": "nonpayable", "outputs": [],
                        "inputs": [{"name": "x", "type": "uint64"}]});
                    Run::One(s(&["--unlock", &seed, "--passphrase-fd", "0", "app-core", "prepare-app-call", "--chain", "local",
                        "--contract", APP_CONTRACT, "--entry", &entry.to_string(), "--args", "{\"x\":1}", "--payer", &nk]))
                }
                "app-core pqchat-seal-message" => Run::Session(vec![app_key("k")], json!(["app-core", "pqchat-seal-message", "--account", sg, "--k", "k",
                    "--pos", "k", "--header", zero::<scaas_sdk::pqchat_keys::PqMessageHeader>().to_string(), "--content-json", "{}"])),
                "app-core pqchat-sign-session" => Run::Session(vec![app_key("k")], json!(["app-core", "pqchat-sign-session", "--account", sg, "--k", "k",
                    "--r", zero::<scaas_sdk::pqchat_keys::PqSessionNew>().to_string()])),
                "app-core pqchat-sign-epoch" => Run::Session(vec![app_key("k")], json!(["app-core", "pqchat-sign-epoch", "--account", sg, "--k", "k",
                    "--r", zero::<scaas_sdk::pqchat_keys::PqEpochNew>().to_string()])),
                "app-core sign-pqchat-session" => rec("sign-pqchat-session", zero::<PqChatSession>()),
                "app-core sign-pqchat-epoch" => rec("sign-pqchat-epoch", zero::<PqChatEpoch>()),
                "app-core sign-pqchat-leave" => rec("sign-pqchat-leave", zero::<PqChatLeave>()),
                "app-core sign-pqchat-remove" => rec("sign-pqchat-remove", zero::<PqChatRemove>()),
                "app-core sign-pqchat-message" => rec("sign-pqchat-message", zero::<PqChatMessage>()),
                "app-core sign-pqchat-topic" => rec("sign-pqchat-topic", zero::<PqTopic>()),
                "app-core sign-pqchat-topic-update" => rec("sign-pqchat-topic-update", zero::<PqTopicUpdate>()),
                "app-core sign-pqchat-topic-writer" => rec("sign-pqchat-topic-writer", zero::<PqTopicWriter>()),
                "app-core sign-pqchat-topic-entry" => rec("sign-pqchat-topic-entry", zero::<PqTopicEntry>()),
                "app-core sign-pqchat-topic-edit" => rec("sign-pqchat-topic-edit", zero::<PqTopicEdit>()),
                "app-core sign-pqchat-topic-vote" => rec("sign-pqchat-topic-vote", zero::<PqTopicVote>()),
                _ => return None,
            })
        };
        let sent = |c: &fake_chain::Fake| {
            let c = c.lock().unwrap();
            (c.sent.len(), c.bodies.len())
        };
        let mut ran = 0;
        let mut failures = vec![];
        for x in commands()["commands"].as_array().unwrap() {
            if confirm_class(x["sdk"].as_str().unwrap()) != Some("sign") {
                continue;
            }
            let cmd = x["command"].as_str().unwrap();
            let Some(f) = fixture(cmd) else {
                failures.push(format!("{cmd}: no confirm run (add one here)"));
                continue;
            };
            let (shown, refused) = match f {
                Run::One(a) => {
                    let stdin = if a.first().map(String::as_str) == Some("--unlock") { format!("{PASS}\nn\n") } else { "n\n".into() };
                    let o = one(a, stdin).await.unwrap();
                    (out(&o).lines().next().is_some_and(|l| l.starts_with('{')),
                        !o.status.success() && err(&o).contains("NotConfirmed") || { failures.push(format!("{cmd}: {}", err(&o))); false })
                }
                Run::Session(pre, last) => {
                    let mut a = base.clone();
                    a.extend(s(&["--unlock", &seed, "--passphrase-fd", "3"]));
                    let mut l = pre.clone();
                    l.push(last);
                    let (a, pf) = (a, pass_file.to_str().unwrap().to_string());
                    let o = tokio::task::spawn_blocking(move || run_session(&a, &l, &pf)).await.unwrap();
                    let n = lines(&o).len();
                    (n == pre.len() + 1,
                        err(&o).contains("NoTerminal") && err(&o).contains("no terminal to confirm on") || { failures.push(format!("{cmd}: {} | {}", err(&o), out(&o))); false })
                }
            };
            if refused && !shown {
                failures.push(format!("{cmd}: asked without showing what it signs"));
            }
            assert_eq!(sent(&chain), (0, 0), "{cmd}: something was sent");
            ran += 1;
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert!(ran >= 30, "{ran} signing commands");
        // each kind of operation object stops at its confirm in one command: registry writes, an order, a native send (the
        // prepared operation: review_and_quote_before_submit)
        let objects = [
            register.as_array().unwrap()[2..].iter().map(|x| x.as_str().unwrap().to_string()).collect::<Vec<_>>(),
            order.as_array().unwrap()[2..].iter().map(|x| x.as_str().unwrap().to_string()).collect(),
            s(&["wallet", "prepare-native-send", "--key", &nk, "--chain", "local", "--to", APP_CONTRACT, "--value", "1"]),
        ];
        for o in objects {
            let mut a = s(&["--unlock", &seed, "--passphrase-fd", "0"]);
            a.extend(o.clone());
            let r = one(a, format!("{PASS}\nn\n")).await.unwrap();
            assert!(!r.status.success() && err(&r).contains("NotConfirmed"), "{o:?}: {}", err(&r));
            assert!(lines(&r)[0].is_object(), "{o:?}: shown first");
            assert_eq!(sent(&chain), (0, 0), "{o:?}: something was sent");
        }
    });
    std::fs::remove_dir_all(&dir).unwrap();
}

/// T41.evm: the hand-off blob's two commands (its bounds are the SDK's, `tests/handoff.rs`): `from-json` reads a blob's text
/// into its named fields, `to-json` writes them back, the same blob; an unknown field is the SDK's `Argument`. And `op
/// import-signed` of a blob for a chain the CLI does not hold is `ChainUnknown`, nothing read (the import's checks are the
/// SDK's, `tests/handoff.rs`).
#[test]
fn signed_op_blob_commands() {
    let blob = serde_json::json!({"v": 1, "chain_uid": format!("0x{}", "60".repeat(32)), "family": "evm",
        "contract": "0x5ca00000000000000000000000000000000000a1", "entry": "mtxCancelNonce", "struct": "UACancelNonce",
        "kind": "token", "message": {"lane": "7"}, "extra": {}, "signature": "0x01", "signer": format!("0x{}", "00".repeat(32)),
        "signer_kind": 0, "ids": false});
    let o = run(
        &[
            "--json",
            "signed-op-blob",
            "from-json",
            "--text",
            &blob.to_string(),
        ],
        "",
        &[],
    );
    assert!(o.status.success(), "{}", err(&o));
    let read = lines(&o)[0].clone();
    assert_eq!(read, blob, "the named fields");
    let mut a = vec![
        "--json".to_string(),
        "signed-op-blob".into(),
        "to-json".into(),
    ];
    for (k, x) in read.as_object().unwrap() {
        a.push(format!("--{}", k.replace('_', "-")));
        a.push(x.as_str().map_or_else(|| x.to_string(), String::from));
    }
    let a: Vec<&str> = a.iter().map(String::as_str).collect();
    let o = run(&a, "", &[]);
    assert!(o.status.success(), "{}", err(&o));
    let text = lines(&o)[0]["json"].as_str().unwrap().to_string();
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap(),
        blob,
        "the same blob back"
    );
    let mut bad = blob.clone();
    bad["unknown"] = serde_json::json!(1);
    let o = run(
        &[
            "--json",
            "signed-op-blob",
            "from-json",
            "--text",
            &bad.to_string(),
        ],
        "",
        &[],
    );
    assert!(
        !o.status.success() && err(&o).contains("Argument"),
        "{}",
        err(&o)
    );
    let expect = serde_json::json!({"chain": "nowhere", "payee": [], "payer": {"Native": {"seed": "s", "network": "evm", "index": 0}}});
    let dd = data_dir("import-signed");
    let o = run(
        &[
            "--json",
            "--data-dir",
            dd.to_str().unwrap(),
            "op",
            "import-signed",
            "--blob",
            &blob.to_string(),
            "--expect",
            &expect.to_string(),
        ],
        "",
        &[],
    );
    assert!(
        !o.status.success() && err(&o).contains("ChainUnknown"),
        "{}",
        err(&o)
    );
}
