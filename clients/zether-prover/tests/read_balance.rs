//! zether-limits D5 end to end: a balance > 2^44 is out of reach of a device BSGS, is held and
//! spent through the wallet cache (`checkBalance`, no BSGS), and after the cache is lost the
//! native `zether-read-balance` recovers it from the pasted ciphertext. The CLI runs with the
//! smallest bound that covers the balance (2^45, table 2^22) to keep the test short. ARCH-POS-13 (ua-rs-sign T15c): the
//! wallet half needs the raw commands (feature `hazmat`); `--rpc` is refused before any request goes out.
#![cfg_attr(not(feature = "hazmat"), allow(dead_code, unused_imports))]

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use zether_prover::api::{call, hx};
use zether_prover::curve::{decode_point, encode_point, generator, point_len, Bls12381, Fr, ZCurve, G};
#[cfg(feature = "bn254")]
use zether_prover::curve::Bn254;
use zether_prover::elgamal::Ciphertext;
use zether_prover::vectors::MNEMONIC;

const CLI: &str = env!("CARGO_BIN_EXE_zether-read-balance");

fn api(cmd: &str, v: Value) -> Result<Value, String> {
    call(cmd, &v.to_string()).map(|s| serde_json::from_str(&s).unwrap())
}

fn pt<C: ZCurve>(v: &Value) -> G<C> {
    decode_point::<C>(&hex::decode(&v.as_str().unwrap()[2..]).unwrap()).unwrap()
}

fn read_balance(args: &[&str], key: &Value) -> Result<Value, String> {
    let mut child = Command::new(CLI).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    // A CLI that refuses its arguments exits before reading stdin: the pipe breaks, the exit status carries the verdict.
    if let Err(e) = child.stdin.take().unwrap().write_all(key.to_string().as_bytes()) {
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
    }
    let out = child.wait_with_output().unwrap();
    if out.status.success() {
        Ok(serde_json::from_slice(&out.stdout).unwrap())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

#[cfg(feature = "hazmat")]
#[test]
fn big_balance_cache_spend_and_cli_recovery_bls12_381() {
    recovery::<Bls12381>();
}

#[cfg(all(feature = "bn254", feature = "hazmat"))]
#[test]
fn big_balance_cache_spend_and_cli_recovery_bn254() {
    recovery::<Bn254>();
}

fn recovery<C: ZCurve>() {
    let curve = C::NAME;
    let n = point_len::<C>();
    let (k0, k1) = (json!({"mnemonic": MNEMONIC, "coin": 60, "account": 0}), json!({"mnemonic": MNEMONIC, "coin": 60, "account": 1}));
    let (a, b) = (api("keygen", json!({"curve": curve, "key": k0})).unwrap(), api("keygen", json!({"curve": curve, "key": k1})).unwrap());
    let bal: u64 = (1 << 44) + (1 << 34);
    let acc = api("encrypt", json!({"curve": curve, "Y": a["Y"], "amount": bal.to_string()})).unwrap();

    // Device BSGS (scaled down: table 2^18, bound 2^24) cannot read it: the wallet sends the user to the CLI.
    let e = api("decrypt", json!({"curve": curve, "key": k0, "ct": acc, "tableBits": 18, "boundBits": 24})).unwrap_err();
    assert!(e.contains("zether-read-balance"), "{e}");

    // Cache: a right balance validates, a wrong one does not.
    let check = |acc: &Value, b: u64| api("checkBalance", json!({"curve": curve, "key": k0, "acc": acc, "balance": b.to_string()})).unwrap()["ok"].clone();
    assert_eq!(check(&acc, bal), json!(true));
    assert_eq!(check(&acc, bal - 1), json!(false));

    // Spend from the cached balance: v > 2^32 plus an inner fee.
    let v: u64 = (1 << 33) + 7;
    let fee: u64 = 300;
    let t = api("proveTransfer", json!({
        "curve": curve, "key": k0, "chainId": 31337, "chainUid": hx(&[0x24; 32]),
        "token": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
        "sendCounter": 0, "accSeq": 1, "validUntilBlock": 100, "acc": acc, "balance": bal.to_string(), "yTo": b["Y"],
        "amount": v.to_string(), "fee": fee, "beneficiary": hx(&[0x22; 32]),
    })).unwrap();
    assert_eq!(api("verifyTransfer", json!({"curve": curve, "statement": t["statement"], "proof": t["proof"]})).unwrap()["ok"], json!(true));
    // The token's debit: acc −= (C_deb + [fee]G, D_out). Payload = 96 B ‖ salt(16) ‖ Y_f ‖ Y_t ‖ C_out ‖ D_out ‖ C_deb ‖ C_aud.
    let pl = hex::decode(&t["payload"].as_str().unwrap()[2..]).unwrap();
    let at = |i: usize| decode_point::<C>(&pl[112 + n * i..112 + n * (i + 1)]).unwrap();
    let (d_out, c_deb) = (at(3), at(4));
    let g = generator::<C>();
    let acc2 = Ciphertext::<C> { c: pt::<C>(&acc["C"]) - c_deb - g * Fr::<C>::from(fee), d: pt::<C>(&acc["D"]) - d_out };
    let enc = |p: &G<C>| hx(&encode_point::<C>(p));
    let acc2_j = json!({"C": enc(&acc2.c), "D": enc(&acc2.d)});
    let left = bal - v - fee;
    assert!(left > 1 << 44);
    assert_eq!(check(&acc2_j, left), json!(true), "cache update b -= v + fee");

    // Cache lost: the CLI recovers the balance from the pasted ciphertext; the table file is
    // written on the first run, then loaded and verified on the second.
    let dir = std::env::temp_dir().join(format!("zrb-{}-{curve}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join(format!("{curve}-22.bsgs"));
    let ct = format!("{}:{}", acc2_j["C"].as_str().unwrap(), acc2_j["D"].as_str().unwrap());
    let args = ["--curve", curve, "--table-bits", "22", "--bound-bits", "45", "--ct", &ct, "--table-file", file.to_str().unwrap()];
    for _ in 0..2 {
        let out = read_balance(&args, &k0).unwrap();
        // review N3: a pasted ciphertext alone is the user's word, neither verified nor refuted.
        assert_eq!(out, json!({"balance": left.to_string(), "accSeq": null, "verified": null, "source": "pasted"}));
    }
    assert_eq!(std::fs::metadata(&file).unwrap().len(), (8 + 1 + curve.len() + 1) as u64 + (12 << 22));
    // A bound below the balance, out-of-range knobs and a table file of another size are refused.
    assert!(read_balance(&["--curve", curve, "--table-bits", "20", "--bound-bits", "21", "--ct", &ct], &k0).is_err());
    assert!(read_balance(&["--curve", curve, "--table-bits", "28", "--ct", &ct], &k0).is_err());
    assert!(read_balance(&["--curve", curve, "--table-bits", "19", "--ct", &ct], &k0).is_err());
    assert!(read_balance(&["--curve", curve, "--bound-bits", "55", "--ct", &ct], &k0).is_err());
    let other = ["--curve", curve, "--table-bits", "23", "--bound-bits", "45", "--ct", &ct, "--table-file", file.to_str().unwrap()];
    assert!(read_balance(&other, &k0).unwrap_err().contains("not 2^23"));

    std::fs::remove_dir_all(&dir).unwrap();
}

/// ARCH-POS-13 (ua-rs-sign T15c): `--rpc` is refused, naming the rule, before the key is read and before any request goes
/// out; the pasted `--ct` path runs (positive control). The URL's port is closed again before the call, so a build that sent
/// the request fails fast (connection refused, another error) instead of waiting on a listener that never answers.
#[test]
fn rpc_refused() {
    let k0 = json!({"mnemonic": MNEMONIC, "coin": 60, "account": 0});
    let url = format!("http://{}", std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap());
    let rpc = ["--curve", "bls12381", "--table-bits", "20", "--bound-bits", "24", "--rpc", &url, "--token", "0x5fbdb2315678afecb367f032d93f642f64180aa3"];
    let e = read_balance(&rpc, &k0).unwrap_err();
    assert!(e.contains("--rpc refused: ARCH-POS-13"), "{e}");
    let y = zether_prover::keys::ZetherKey::<Bls12381>::conf(&zether_prover::keys::seed_from_mnemonic(MNEMONIC, "").unwrap()[..], 60, 0).unwrap();
    let ct = zether_prover::elgamal::encrypt(&y.y, 77, &Fr::<Bls12381>::from(5u64));
    let pasted = format!("{}:{}", hx(&encode_point::<Bls12381>(&ct.c)), hx(&encode_point::<Bls12381>(&ct.d)));
    let out = read_balance(&["--curve", "bls12381", "--table-bits", "20", "--bound-bits", "24", "--ct", &pasted], &k0).unwrap();
    assert_eq!(out["balance"], json!("77"), "the pasted path: positive control");
}
