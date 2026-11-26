// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Every FN-DSA-512 / FN-DSA-1024 row of smartcontracts/vectors/ua with its stated verdict: clientkeys' pq_kat (+ mutations) and
//! pq_signatures, the NIST round-3 KATs of pq_external, the Falcon rows of rs_signatures and sign.json, and three refusals
//! derived from each accept row as FnDsa.t.sol does (a set padding byte, the other degree's header, a flipped message bit).
//! Shared by tests/fndsa_vrfy.rs (native) and tests/fndsa/wasm (the same rows in wasm32).
use serde_json::Value;

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn arr(v: &Value) -> &Vec<Value> {
    v.as_array().unwrap()
}

pub struct Row {
    pub what: String,
    pub kind: u16,
    pub pk: Vec<u8>,
    pub m: Vec<u8>,
    pub sig: Vec<u8>,
    pub valid: bool,
}

fn row(what: String, kind: u16, pk: &Value, m: &Value, sig: &Value, valid: bool) -> Row {
    Row {
        what,
        kind,
        pk: bytes(pk),
        m: bytes(m),
        sig: bytes(sig),
        valid,
    }
}

fn kind_of(name: &str) -> Option<u16> {
    match name {
        "fndsa512" => Some(0x0132),
        "fndsa1024" => Some(0x0135),
        _ => None,
    }
}

/// Every Falcon row of the vectors, with its stated verdict; `load` reads one file of smartcontracts/vectors/ua.
pub fn rows(load: impl Fn(&str) -> Value) -> Vec<Row> {
    let mut out = Vec::new();
    let v = load("pq_kat.json");
    for name in ["fndsa512", "fndsa1024"] {
        let (k, kind) = (&v["kinds"][name], kind_of(name).unwrap());
        out.push(row(
            format!("pq_kat {name}"),
            kind,
            &k["pk"],
            &k["ua_msg"],
            &k["sig"],
            true,
        ));
        for m in arr(&k["mutations"]) {
            let what = format!("pq_kat {name} {}", m["what"]);
            out.push(row(
                what,
                kind,
                &m["pk"],
                &m["ua_msg"],
                &m["sig"],
                m["valid"].as_bool().unwrap(),
            ));
        }
    }
    let v = load("pq_external.json");
    for (set, kind) in [("falcon_kat", 0x0132), ("falcon1024_kat", 0x0135)] {
        for c in arr(&v[set]["cases"]) {
            let what = format!("pq_external {set} {}", c["count"]);
            out.push(row(
                what,
                kind,
                &c["pk"],
                &c["msg"],
                &c["sig"],
                c["valid"].as_bool().unwrap(),
            ));
        }
    }
    let v = load("pq_signatures.json");
    for k in arr(&v["kinds"]) {
        let Some(kind) = kind_of(k["name"].as_str().unwrap()) else {
            continue;
        };
        let mut good: Vec<(String, &Value)> = ["pop", "popOther", "popPqz"]
            .iter()
            .filter_map(|f| k.get(*f).map(|s| (f.to_string(), s)))
            .collect();
        good.extend(
            arr(&k["sigs"])
                .iter()
                .enumerate()
                .map(|(i, s)| (format!("sigs[{i}]"), s)),
        );
        for (f, s) in good {
            let what = format!("pq_signatures {} {f}", k["name"]);
            out.push(row(
                what,
                kind,
                &k["keyData"],
                &s["message"],
                &s["sig"],
                true,
            ));
        }
        for n in arr(&k["negatives"]) {
            let what = format!("pq_signatures {} {}", k["name"], n["name"]);
            out.push(row(
                what,
                kind,
                &k["keyData"],
                &n["message"],
                &n["sig"],
                false,
            ));
        }
    }
    for (file, list, sig) in [
        ("rs_signatures.json", "rows", "signature"),
        ("rs_signatures.json", "appRows", "signature"),
        ("sign.json", "ua", "signature"),
    ] {
        let v = load(file);
        for (i, r) in arr(&v[list]).iter().enumerate() {
            let Some(kind) = kind_of(r["name"].as_str().unwrap_or("")) else {
                continue;
            };
            let what = format!("{file} {list}[{i}] {}", r["purpose"]);
            out.push(row(what, kind, &r["keyData"], &r["uaMsg"], &r[sig], true));
        }
    }
    // the contract test's refusals of each accept row (FnDsa.t.sol test_falcon_nistKat / test_falcon1024_nistKat)
    let derived: Vec<Row> = out
        .iter()
        .filter(|r| r.valid)
        .flat_map(|r| {
            let mut pad = r.sig.clone();
            *pad.last_mut().unwrap() ^= 0x01;
            let mut head = r.sig.clone();
            head[0] = if r.kind == 0x0132 { 0x3a } else { 0x39 };
            let mut msg = r.m.clone();
            msg[0] ^= 0x01;
            [
                ("padding byte", r.m.clone(), pad),
                ("other header", r.m.clone(), head),
                ("message bit", msg, r.sig.clone()),
            ]
            .map(|(how, m, sig)| Row {
                what: format!("{} / {how}", r.what),
                kind: r.kind,
                pk: r.pk.clone(),
                m,
                sig,
                valid: false,
            })
        })
        .collect();
    out.extend(derived);
    out
}
