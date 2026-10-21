//! Shared by tests/vectors.rs and tests/oracle_verify.rs: the frozen vectors (smartcontracts/vectors/pqz) as
//! (op, statement, proof) triples, and negative.json's inputs (pqz_kat.py's `apply_edits`).
#![allow(dead_code)]
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

pub const PQZL_ID: [u8; 32] = pqzl::PROOF_SYSTEM_ID;

/// the committed vectors of this build's parameter set (owner 2026-10-21, one set per build): the frozen v3 set
/// n2048-kmax1024 at smartcontracts/vectors/pqz (what the contracts read until plan 5h Task 8d), any other set under
/// smartcontracts/vectors/pqz/<set>/ once generated; None = this set has no vectors yet
pub fn vectors_dir() -> Option<PathBuf> {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../smartcontracts/vectors/pqz");
    if pqzl::SET == "n2048-kmax1024" {
        return Some(base);
    }
    let d = base.join(pqzl::SET);
    d.join("proof_pqzl.json").is_file().then_some(d)
}

pub fn json(file: &str) -> Value {
    let p = vectors_dir().unwrap_or_else(|| panic!("no vectors of set {} (smartcontracts/vectors/pqz/{0}/)", pqzl::SET)).join(file);
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))).unwrap()
}

pub fn hex(s: &Value) -> Vec<u8> {
    let s = s.as_str().expect("hex string").as_bytes();
    s.chunks(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).expect("hex")).collect()
}

/// pqz_kat.py `with_id`: the statement under the PQZL proofSystemId
pub fn with_id(mut s: Vec<u8>) -> Vec<u8> {
    s[32..64].copy_from_slice(&PQZL_ID);
    s
}

/// pqz_kat.py OP_BYTE (forms; an R_TXM case name has op 7)
pub fn op_of(form: &str) -> u8 {
    match form.trim_end_matches('0') {
        "TRANSFER" => 1,
        "BURN" | "REFRESH" => 2,
        "REGISTER" => 3,
        "DISCLOSE-SENDER" => 4,
        "DISCLOSE-RECEIVER" | "DISCLOSE-AUDITOR" => 5,
        _ => 7,
    }
}

/// the relation code of a form / R_TXM case (pqz_int.h)
pub fn rel_code(form: &str, case: Option<&str>) -> u8 {
    match form {
        "TRANSFER0" => 0x81,
        "TRANSFER-MULTI" => {
            let mut it = case.expect("R_TXM case")[1..].split('-');
            let m: u8 = it.next().unwrap().parse().unwrap();
            0x70 | ((it.next() == Some("on")) as u8) << 3 | m.trailing_zeros() as u8
        }
        f => op_of(f),
    }
}

/// statements by form (statement_*.json) and by R_TXM case, under the PQZL id
pub fn statements() -> HashMap<String, Vec<u8>> {
    let mut m = HashMap::new();
    for f in ["statement_transfer.json", "statement_burn.json", "statement_refresh.json", "statement_register.json",
              "statement_disclose.json", "statement_transfer_multi.json"] {
        for r in json(f)["rows"].as_array().unwrap() {
            let key = r.get("case").and_then(Value::as_str).unwrap_or_else(|| r["form"].as_str().unwrap());
            m.insert(key.to_string(), with_id(hex(&r["stmt"])));
        }
    }
    m
}

/// one honest PQZL proof
pub struct Row {
    pub name: String,
    pub op: u8,
    pub code: u8,
    pub stmt: Vec<u8>,
    pub proof: Vec<u8>,
    /// the prover's inputs of the row
    pub wit: Vec<u8>,
    pub rnd32: [u8; 32],
}

/// every PQZL row of proof_pqzl.json (19) and fee0.json (4); for a set without vectors, one honest row per bench
/// relation (pqzl::bench, the 14 relations of pqz_bench.c), proved by the C core (feature c-oracle) with a fixed
/// rnd32: the Rust prover must give the same bytes
pub fn pqzl_rows() -> Vec<Row> {
    if vectors_dir().is_none() {
        return bench_rows();
    }
    let st = statements();
    let mut out = Vec::new();
    for r in json("proof_pqzl.json")["rows"].as_array().unwrap() {
        let form = r["form"].as_str().unwrap();
        let case = r.get("case").and_then(Value::as_str);
        let key = case.unwrap_or(form);
        out.push(Row {
            name: key.to_string(),
            op: r["op"].as_u64().unwrap() as u8,
            code: rel_code(form, case),
            stmt: st[key].clone(),
            proof: hex(&r["proof"]),
            wit: hex(&r["wit"]),
            rnd32: hex(&r["rnd32"]).try_into().unwrap(),
        });
    }
    for r in json("fee0.json")["rows"].as_array().unwrap() {
        let form = r["form"].as_str().unwrap();
        out.push(Row {
            name: format!("fee0 {form}"),
            op: r["op"].as_u64().unwrap() as u8,
            code: rel_code(form, None),
            stmt: with_id(hex(&r["stmt"])),
            proof: hex(&r["pqzl"]["proof"]),
            wit: hex(&r["wit"]),
            rnd32: hex(&r["rnd32"]).try_into().unwrap(),
        });
    }
    out
}

#[cfg(all(feature = "bench", feature = "c-oracle"))]
fn bench_rows() -> Vec<Row> {
    let b = pqzl::bench::Bench::new().expect("bench setup");
    (0..pqzl::bench::NREL)
        .map(|rel| {
            let (op, code, stmt, wit) = b.instance(rel);
            let rnd32: [u8; 32] = core::array::from_fn(|i| (7 * rel + i) as u8);
            let proof = pqzl::c_oracle::c_prove(op, stmt, wit, &rnd32).expect("C prove of a bench relation");
            Row { name: format!("bench {}", pqzl::bench::NAMES[rel]), op, code, stmt: stmt.to_vec(), proof, wit: wit.to_vec(), rnd32 }
        })
        .collect()
}

#[cfg(not(all(feature = "bench", feature = "c-oracle")))]
fn bench_rows() -> Vec<Row> {
    panic!("set {} has no vectors: the rows come from pqzl::bench (features bench, c-oracle)", pqzl::SET)
}

/// negative.json's PQZL rows as precompile inputs u8(op) || be32(len) || stmt || proof (pqz_kat.py `apply_edits`);
/// empty for a set without vectors (said once on stderr: the bench's adversarial verifies cover it there)
pub fn negative_inputs() -> Vec<(String, Vec<u8>)> {
    if vectors_dir().is_none() {
        eprintln!("set {}: no negative.json yet (no vectors): no negative-vector rows", pqzl::SET);
        return Vec::new();
    }
    let j = json("negative.json");
    let st = statements();
    let mut proofs: HashMap<String, Vec<u8>> = HashMap::new();
    for r in json("proof_pqzl.json")["rows"].as_array().unwrap() {
        let key = r.get("case").and_then(Value::as_str).unwrap_or_else(|| r["form"].as_str().unwrap());
        proofs.insert(key.to_string(), hex(&r["proof"]));
    }
    let mut out = Vec::new();
    for r in j["rows"].as_array().unwrap() {
        if r["id"] != "pqzl" {
            continue;
        }
        let form = r["form"].as_str().unwrap();
        let key = if form == "TRANSFER-MULTI" { r["case"].as_str().unwrap() } else { form };
        let (mut op, mut s, mut p) = if form == "-" { (0, vec![], vec![]) } else { (op_of(form), st[key].clone(), proofs[key].clone()) };
        let (mut lenf, mut raw, mut size) = (None, None, None);
        for e in r["edits"].as_array().unwrap() {
            let (k, v) = e.as_object().unwrap().iter().next().unwrap();
            let u = |i: usize| v[i].as_u64().unwrap() as usize;
            match k.as_str() {
                "op" => op = v.as_u64().unwrap() as u8,
                "proof_from" => p = proofs[v.as_str().unwrap()].clone(),
                "proof_set" | "stmt_set" => {
                    let b = hex(&v[1]);
                    let x = if k == "proof_set" { &mut p } else { &mut s };
                    x[u(0)..u(0) + b.len()].copy_from_slice(&b);
                }
                "proof_copy" => {
                    let t = p[u(0)..u(0) + u(2)].to_vec();
                    p[u(1)..u(1) + u(2)].copy_from_slice(&t);
                }
                "proof_swap" => {
                    let a = p[u(0)..u(0) + u(2)].to_vec();
                    let b = p[u(1)..u(1) + u(2)].to_vec();
                    p[u(0)..u(0) + u(2)].copy_from_slice(&b);
                    p[u(1)..u(1) + u(2)].copy_from_slice(&a);
                }
                "stmt_resize" => s.resize(v.as_u64().unwrap() as usize, 0),
                "proof_resize" => p.resize(v.as_u64().unwrap() as usize, 0),
                "stmt_flip" => s[u(0)] ^= 1 << u(1),
                "proof_flip" => p[u(0)] ^= 1 << u(1),
                "len_field" => lenf = Some(v.as_u64().unwrap() as u32),
                "input_resize" => size = Some(v.as_u64().unwrap() as usize),
                "raw" => raw = Some(hex(v)),
                _ => panic!("edit {k}"),
            }
        }
        let mut b = raw.unwrap_or_else(|| {
            let mut b = vec![op];
            b.extend_from_slice(&lenf.unwrap_or(s.len() as u32).to_be_bytes());
            b.extend_from_slice(&s);
            b.extend_from_slice(&p);
            b
        });
        if let Some(n) = size {
            b.resize(n, 0);
        }
        use sha3::Digest;
        let sha: String = sha3::Sha3_256::digest(&b).iter().map(|x| format!("{x:02x}")).collect();
        assert_eq!((b.len() as u64, sha.as_str()), (r["input_bytes"].as_u64().unwrap(), r["input_sha3"].as_str().unwrap()), "{}", r["name"]);
        out.push((r["name"].as_str().unwrap().to_string(), b));
    }
    out
}

/// pqz-stmt `decode_input`'s split: (op, stmt, proof), `None` if the length field does not fit
pub fn split(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if b.len() < 5 {
        return None;
    }
    let n = u32::from_be_bytes([b[1], b[2], b[3], b[4]]) as usize;
    let rest = &b[5..];
    (n <= rest.len()).then(|| (b[0], &rest[..n], &rest[n..]))
}

/// tests/fixtures/cheating (export.sh): (case, op, statement, proof, accepted?). norm_z3_over / norm_z4_over come from
/// z34poc.sh (z3 / z4 inflated past their bounds, consistent with the commitments). Only the norm PoC's honest control
/// verifies: l2dom_honest is an honest witness proved by the pooled-slack prover, whose upsilon spread does not match
/// the per-block slack, so the fixed verifier rejects it too (check_tbox_fixes.sh requires that)
pub type Fixture = (&'static str, u8, Vec<u8>, Vec<u8>, bool);

pub fn cheating() -> Vec<Fixture> {
    // the v3 set's fixtures at tests/fixtures/cheating, another set's under tests/fixtures/cheating/<set>/ (export.sh)
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cheating");
    if pqzl::SET != "n2048-kmax1024" {
        dir = dir.join(pqzl::SET);
    }
    let rd = |f: String| std::fs::read(dir.join(&f)).unwrap_or_else(|e| panic!("{f}: {e}"));
    [
        "l2dom_honest",
        "l2dom_s_over_A",
        "l2dom_s_over_B",
        "tx_over",
        "norm_honest",
        "norm_z21_big",
        "norm_z1_over",
        "norm_w_over",
        "norm_z3_over",
        "norm_z4_over",
    ]
        .into_iter()
        .map(|c| (c, if c == "tx_over" { 1 } else { 3 }, rd(format!("{c}.stmt")), rd(format!("{c}.proof")), c == "norm_honest"))
        .collect()
}
