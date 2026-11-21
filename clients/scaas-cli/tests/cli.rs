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
