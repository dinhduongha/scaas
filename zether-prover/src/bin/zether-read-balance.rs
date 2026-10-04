//! zether-read-balance — read a Zether balance too large for the wallet's device BSGS (lost cache
//! on a big account, zether-limits §4–§5). Native only. UNAUDITED.
//!
//!   zether-read-balance --curve bn254|bls12381 [--table-bits 24] [--bound-bits 54]
//!                       [--table-file PATH] [--pending]
//!                       (--ct <C hex>:<D hex> | --rpc <url> --token <address>)
//!
//! The key is read from **stdin** as JSON, the `key` object of the prover API:
//! `{"x": "0x…"}` or `{"mnemonic": "…", "passphrase"?: "…", "coin": n, "account": n}`. It never
//! leaves this process: `--rpc` sends only `eth_call accountState(UA)` (public data), via `curl`.
//! `--table-bits` 20–27 (≈ 16 B × 2^bits of RAM; refused when free RAM is short), `--bound-bits`
//! ≤ 54; worst case 2^(bound − table) giant steps. `--table-file` loads and verifies a saved
//! baby table (public data), or writes one after generating it. Prints
//! `{"balance": "<decimal>", "accSeq": n|null}`; `accSeq` (RPC only) is what the wallet cache stores.

use std::io::Read;
use std::process::{Command, ExitCode, Stdio};

use serde_json::{json, Value};
use zeroize::Zeroizing;
use zether_prover::abi::decode_account_state;
use zether_prover::curve::{decode_point, Bls12381, Bn254, ZCurve};
use zether_prover::elgamal::{check_ram, mem_available, BsgsParams, BsgsTable, Ciphertext};
use zether_prover::envelope::selector;

const TABLE_BITS_CLI: std::ops::RangeInclusive<u32> = 20..=27;

struct Args {
    curve: String,
    table_bits: u32,
    bound_bits: u32,
    table_file: Option<String>,
    pending: bool,
    ct: Option<String>,
    rpc: Option<String>,
    token: Option<String>,
}

fn parse() -> Result<Args, String> {
    let mut a = Args {
        curve: String::new(),
        table_bits: 24,
        bound_bits: 54,
        table_file: None,
        pending: false,
        ct: None,
        rpc: None,
        token: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(f) = it.next() {
        let mut val = || it.next().ok_or(format!("{f} needs a value"));
        match f.as_str() {
            "--curve" => a.curve = val()?,
            "--table-bits" => a.table_bits = val()?.parse().map_err(|_| "--table-bits: integer")?,
            "--bound-bits" => a.bound_bits = val()?.parse().map_err(|_| "--bound-bits: integer")?,
            "--table-file" => a.table_file = Some(val()?),
            "--pending" => a.pending = true,
            "--ct" => a.ct = Some(val()?),
            "--rpc" => a.rpc = Some(val()?),
            "--token" => a.token = Some(val()?),
            _ => return Err(format!("unknown argument {f}")),
        }
    }
    if !TABLE_BITS_CLI.contains(&a.table_bits) {
        return Err("--table-bits must be 20..=27".into());
    }
    BsgsParams::new(a.table_bits, a.bound_bits).map_err(|e| e.to_string())?;
    if a.ct.is_some() == a.rpc.is_some() || (a.rpc.is_some() && a.token.is_none()) {
        return Err("give either --ct C:D or --rpc URL --token ADDRESS".into());
    }
    Ok(a)
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.trim().trim_start_matches("0x")).map_err(|_| format!("not hex: {s}"))
}

/// `eth_call accountState(UA)` through `curl` (http and https without a TLS dependency here).
fn fetch(rpc: &str, token: &str, ua: &[u8; 32]) -> Result<([Vec<u8>; 4], u64), String> {
    let mut data = selector("accountState(bytes32)").to_vec();
    data.extend_from_slice(ua);
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_call",
                      "params": [{"to": token, "data": format!("0x{}", hex::encode(data))}, "latest"]});
    let mut child = Command::new("curl")
        .args(["-sS", "-X", "POST", "-H", "content-type: application/json", "--data-binary", "@-", rpc])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("curl: {e}"))?;
    std::io::Write::write_all(child.stdin.as_mut().unwrap(), body.to_string().as_bytes()).map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_slice(&out.stdout).map_err(|_| "RPC returned no JSON".to_string())?;
    let ret = v["result"].as_str().ok_or(format!("RPC error: {}", v["error"]))?;
    decode_account_state(&unhex(ret)?).ok_or("cannot decode accountState".into())
}

fn table<C: ZCurve>(a: &Args) -> Result<BsgsTable<C>, String> {
    if let Some(path) = &a.table_file {
        if let Ok(bytes) = std::fs::read(path) {
            let t = BsgsTable::<C>::from_bytes(&bytes).map_err(|e| format!("{path}: {e}"))?;
            if t.table_bits() != a.table_bits {
                return Err(format!("{path} holds a 2^{} table, not 2^{}", t.table_bits(), a.table_bits));
            }
            return Ok(t);
        }
    }
    let t = BsgsTable::<C>::new(a.table_bits).map_err(|e| e.to_string())?;
    if let Some(path) = &a.table_file {
        std::fs::write(path, t.to_bytes()).map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(t)
}

fn run<C: ZCurve>(a: &Args, key_json: &Value) -> Result<Value, String> {
    let k = zether_prover::api::key::<C>(key_json)?;
    let point = |b: &[u8]| decode_point::<C>(b).map_err(|e| e.to_string());
    let (ct, acc_seq) = if let Some(s) = &a.ct {
        let (c, d) = s.split_once(':').ok_or("--ct is <C hex>:<D hex>")?;
        (Ciphertext { c: point(&unhex(c)?)?, d: point(&unhex(d)?)? }, None)
    } else {
        let (pts, seq) = fetch(a.rpc.as_ref().unwrap(), a.token.as_ref().unwrap(), &k.ua())?;
        let i = if a.pending { 2 } else { 0 };
        (Ciphertext { c: point(&pts[i])?, d: point(&pts[i + 1])? }, Some(seq))
    };
    check_ram(a.table_bits, mem_available()).map_err(|e| e.to_string())?;
    let b = table::<C>(a)?.decrypt(&ct, &k.x, a.bound_bits).map_err(|e| e.to_string())?;
    Ok(json!({"balance": b.to_string(), "accSeq": acc_seq}))
}

fn main() -> ExitCode {
    let res = parse().and_then(|a| {
        let mut input = Zeroizing::new(String::new());
        std::io::stdin().read_to_string(&mut input).map_err(|e| e.to_string())?;
        let key: Value = serde_json::from_str(&input).map_err(|_| "stdin: key JSON expected".to_string())?;
        let req = json!({"key": key});
        match a.curve.as_str() {
            "bn254" => run::<Bn254>(&a, &req),
            "bls12381" => run::<Bls12381>(&a, &req),
            _ => Err("--curve must be bn254 or bls12381".into()),
        }
    });
    match res {
        Ok(v) => {
            println!("{v}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
