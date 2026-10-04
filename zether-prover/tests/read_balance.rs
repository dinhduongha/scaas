//! zether-limits D5 end to end: a balance > 2^44 is out of reach of a device BSGS, is held and
//! spent through the wallet cache (`checkBalance`, no BSGS), and after the cache is lost the
//! native `zether-read-balance` recovers it from the pasted ciphertext. The CLI runs with the
//! smallest bound that covers the balance (2^45, table 2^22) to keep the test short.

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use zether_prover::api::{call, hx};
use zether_prover::curve::{decode_point, encode_point, generator, Bn254, Fr, G};
use zether_prover::elgamal::Ciphertext;
use zether_prover::vectors::MNEMONIC;

const CLI: &str = env!("CARGO_BIN_EXE_zether-read-balance");

fn api(cmd: &str, v: Value) -> Result<Value, String> {
    call(cmd, &v.to_string()).map(|s| serde_json::from_str(&s).unwrap())
}

fn pt(v: &Value) -> G<Bn254> {
    decode_point::<Bn254>(&hex::decode(&v.as_str().unwrap()[2..]).unwrap()).unwrap()
}

fn read_balance(args: &[&str], key: &Value) -> Result<Value, String> {
    let mut child = Command::new(CLI).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    child.stdin.take().unwrap().write_all(key.to_string().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    if out.status.success() {
        Ok(serde_json::from_slice(&out.stdout).unwrap())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

#[test]
fn big_balance_cache_spend_and_cli_recovery() {
    let (k0, k1) = (json!({"mnemonic": MNEMONIC, "coin": 60, "account": 0}), json!({"mnemonic": MNEMONIC, "coin": 60, "account": 1}));
    let (a, b) = (api("keygen", json!({"curve": "bn254", "key": k0})).unwrap(), api("keygen", json!({"curve": "bn254", "key": k1})).unwrap());
    let bal: u64 = (1 << 44) + (1 << 34);
    let acc = api("encrypt", json!({"curve": "bn254", "Y": a["Y"], "amount": bal.to_string()})).unwrap();

    // Device BSGS (scaled down: table 2^18, bound 2^24) cannot read it: the wallet sends the user to the CLI.
    let e = api("decrypt", json!({"curve": "bn254", "key": k0, "ct": acc, "tableBits": 18, "boundBits": 24})).unwrap_err();
    assert!(e.contains("zether-read-balance"), "{e}");

    // Cache: a right balance validates, a wrong one does not.
    let check = |acc: &Value, b: u64| api("checkBalance", json!({"curve": "bn254", "key": k0, "acc": acc, "balance": b.to_string()})).unwrap()["ok"].clone();
    assert_eq!(check(&acc, bal), json!(true));
    assert_eq!(check(&acc, bal - 1), json!(false));

    // Spend from the cached balance: v > 2^32 plus an inner fee.
    let v: u64 = (1 << 33) + 7;
    let fee: u64 = 300;
    let t = api("proveTransfer", json!({
        "curve": "bn254", "key": k0, "chainId": 31337, "token": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
        "sendCounter": 0, "accSeq": 1, "acc": acc, "balance": bal.to_string(), "yTo": b["Y"],
        "amount": v.to_string(), "fee": fee, "beneficiary": hx(&[0x22; 32]),
    })).unwrap();
    assert_eq!(api("verifyTransfer", json!({"curve": "bn254", "statement": t["statement"], "proof": t["proof"]})).unwrap()["ok"], json!(true));
    // The token's debit: acc −= (C_deb + [fee]G, D_out). Payload = 64 B ‖ Y_f ‖ Y_t ‖ C_out ‖ D_out ‖ C_deb ‖ C_aud.
    let pl = hex::decode(&t["payload"].as_str().unwrap()[2..]).unwrap();
    let at = |i: usize| decode_point::<Bn254>(&pl[64 + 64 * i..128 + 64 * i]).unwrap();
    let (d_out, c_deb) = (at(3), at(4));
    let g = generator::<Bn254>();
    let acc2 = Ciphertext::<Bn254> { c: pt(&acc["C"]) - c_deb - g * Fr::<Bn254>::from(fee), d: pt(&acc["D"]) - d_out };
    let enc = |p: &G<Bn254>| hx(&encode_point::<Bn254>(p));
    let acc2_j = json!({"C": enc(&acc2.c), "D": enc(&acc2.d)});
    let left = bal - v - fee;
    assert!(left > 1 << 44);
    assert_eq!(check(&acc2_j, left), json!(true), "cache update b -= v + fee");

    // Cache lost: the CLI recovers the balance from the pasted ciphertext; the table file is
    // written on the first run, then loaded and verified on the second.
    let dir = std::env::temp_dir().join(format!("zrb-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("bn254-22.bsgs");
    let ct = format!("{}:{}", acc2_j["C"].as_str().unwrap(), acc2_j["D"].as_str().unwrap());
    let args = ["--curve", "bn254", "--table-bits", "22", "--bound-bits", "45", "--ct", &ct, "--table-file", file.to_str().unwrap()];
    for _ in 0..2 {
        let out = read_balance(&args, &k0).unwrap();
        assert_eq!(out["balance"], json!(left.to_string()));
        assert!(out["accSeq"].is_null());
    }
    assert_eq!(std::fs::metadata(&file).unwrap().len(), 15 + (12 << 22));
    // A bound below the balance, out-of-range knobs and a table file of another size are refused.
    assert!(read_balance(&["--curve", "bn254", "--table-bits", "20", "--bound-bits", "21", "--ct", &ct], &k0).is_err());
    assert!(read_balance(&["--curve", "bn254", "--table-bits", "28", "--ct", &ct], &k0).is_err());
    assert!(read_balance(&["--curve", "bn254", "--table-bits", "19", "--ct", &ct], &k0).is_err());
    assert!(read_balance(&["--curve", "bn254", "--bound-bits", "55", "--ct", &ct], &k0).is_err());
    let other = ["--curve", "bn254", "--table-bits", "23", "--bound-bits", "45", "--ct", &ct, "--table-file", file.to_str().unwrap()];
    assert!(read_balance(&other, &k0).unwrap_err().contains("not 2^23"));
    std::fs::remove_dir_all(&dir).unwrap();
}
