// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Gate of the wasm32 Falcon verifier (owner 2026-11-26): every FN-DSA-512 / FN-DSA-1024 row of smartcontracts/vectors/ua
//! (clientkeys' pq_kat / pq_signatures, the NIST round-3 KATs of pq_external, rs_signatures, sign.json) through `fn-dsa-vrfy`
//! 0.4.0 beside PQClean (`pq::verify_raw`), plus refuse rows derived from each accept row as the contract test does (a set
//! padding byte, the other degree's header, a flipped message bit). A third column runs fn-dsa-comm's own decode, norm and
//! NTT with the round-3 message representative `HashToPoint(SHAKE256(nonce ‖ m))` (PQClean, EIP-8052), so a difference is
//! located: `fn-dsa-vrfy` hashes `nonce ‖ mu`, `mu = SHAKE256(SHAKE256(pk) ‖ 0x00 ‖ len(ctx) ‖ ctx ‖ m)` (FIPS 206 draft),
//! for every hash identifier, and `HASH_ID_EXTMU` takes a 64-byte `mu` only. UNAUDITED.
use fn_dsa_comm::{codec, mq, signature_size, vrfy_key_size};
use fn_dsa_vrfy::{VerifyingKey, VerifyingKey1024, VerifyingKey512, DOMAIN_NONE, HASH_ID_RAW};
use scaas_ua::pq;
use serde_json::Value;
use sha3::digest::{ExtendableOutput, Update, XofReader};

fn load(name: &str) -> Value {
    let path = format!(
        "{}/../../smartcontracts/vectors/ua/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn arr(v: &Value) -> &Vec<Value> {
    v.as_array().unwrap()
}

struct Row {
    what: String,
    kind: u16,
    pk: Vec<u8>,
    m: Vec<u8>,
    sig: Vec<u8>,
    valid: bool,
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

/// Every Falcon row of the vectors, with its stated verdict.
fn rows() -> Vec<Row> {
    let mut out = Vec::new();
    let v = load("pq_kat.json");
    for name in ["fndsa512", "fndsa1024"] {
        let (k, kind) = (&v["kinds"][name], kind_of(name).unwrap());
        out.push(row(format!("pq_kat {name}"), kind, &k["pk"], &k["ua_msg"], &k["sig"], true));
        for m in arr(&k["mutations"]) {
            let what = format!("pq_kat {name} {}", m["what"]);
            out.push(row(what, kind, &m["pk"], &m["ua_msg"], &m["sig"], m["valid"].as_bool().unwrap()));
        }
    }
    let v = load("pq_external.json");
    for (set, kind) in [("falcon_kat", 0x0132), ("falcon1024_kat", 0x0135)] {
        for c in arr(&v[set]["cases"]) {
            let what = format!("pq_external {set} {}", c["count"]);
            out.push(row(what, kind, &c["pk"], &c["msg"], &c["sig"], c["valid"].as_bool().unwrap()));
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
        good.extend(arr(&k["sigs"]).iter().enumerate().map(|(i, s)| (format!("sigs[{i}]"), s)));
        for (f, s) in good {
            let what = format!("pq_signatures {} {f}", k["name"]);
            out.push(row(what, kind, &k["keyData"], &s["message"], &s["sig"], true));
        }
        for n in arr(&k["negatives"]) {
            let what = format!("pq_signatures {} {}", k["name"], n["name"]);
            out.push(row(what, kind, &k["keyData"], &n["message"], &n["sig"], false));
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
            [("padding byte", r.m.clone(), pad), ("other header", r.m.clone(), head), ("message bit", msg, r.sig.clone())]
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

/// `fn-dsa-vrfy` as an integration would call it: the degree's key type, no context, the raw message.
fn fn_dsa(kind: u16, pk: &[u8], m: &[u8], sig: &[u8]) -> bool {
    match kind {
        0x0132 => VerifyingKey512::decode(pk).is_some_and(|k| k.verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, m)),
        0x0135 => VerifyingKey1024::decode(pk).is_some_and(|k| k.verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, m)),
        _ => false,
    }
}

/// fn-dsa-vrfy's `decode_inner` + `verify_inner` (0.4.0) on fn-dsa-comm's public pieces, with the round-3 hash in place of
/// `hash_to_point(nonce, mu)`: the one line that differs.
fn round3(kind: u16, pk: &[u8], m: &[u8], sig: &[u8]) -> bool {
    let logn: u32 = if kind == 0x0132 { 9 } else { 10 };
    let n = 1usize << logn;
    if pk.len() != vrfy_key_size(logn) || pk[0] != logn as u8 || sig.len() != signature_size(logn) {
        return false;
    }
    let mut h = vec![0u16; n];
    if codec::modq_decode(&pk[1..], &mut h).is_none() {
        return false;
    }
    mq::mqpoly_ext_to_int(logn, &mut h);
    if sig[0] != (0x30 + logn) as u8 {
        return false;
    }
    let mut s2 = vec![0i16; n];
    if !codec::comp_decode(&sig[41..], &mut s2) {
        return false;
    }
    let norm2 = mq::signed_poly_sqnorm(logn, &s2);
    // round 3: c = HashToPoint(SHAKE256(nonce ‖ m)), the same rejection sampling below 5q
    let mut xof = sha3::Shake256::default();
    xof.update(&sig[1..41]);
    xof.update(m);
    let mut rd = xof.finalize_xof();
    let mut t1 = vec![0u16; n];
    let mut i = 0;
    while i < n {
        let mut b = [0u8; 2];
        rd.read(&mut b);
        let w = u16::from_le_bytes(b);
        if w < 61445 {
            t1[i] = w % 12289;
            i += 1;
        }
    }
    mq::mqpoly_ext_to_int(logn, &mut t1);
    let mut t2 = vec![0u16; n];
    mq::mqpoly_signed_to_ext(logn, &s2, &mut t2);
    mq::mqpoly_ext_to_int(logn, &mut t2);
    mq::mqpoly_int_to_NTT(logn, &mut t2);
    mq::mqpoly_mul_ntt(logn, &mut t2, &h);
    mq::mqpoly_NTT_to_int(logn, &mut t2);
    mq::mqpoly_sub_int(logn, &mut t1, &t2);
    mq::mqpoly_int_to_ext(logn, &mut t1);
    let norm1 = mq::mqpoly_sqnorm_binf(logn, &t1);
    norm1 < norm2.wrapping_neg() && (norm1 + norm2) <= mq::SQBETA[logn as usize]
}

#[test]
fn fn_dsa_vrfy_against_every_falcon_row() {
    let rows = rows();
    let (mut acc, mut rej) = (0, 0);
    let (mut fn_mismatch, mut r3_mismatch, mut keys) = (Vec::new(), Vec::new(), 0);
    for r in &rows {
        let pqclean = pq::verify_raw(r.kind, &r.pk, &r.m, &r.sig);
        assert_eq!(pqclean, r.valid, "PQClean vs the row: {}", r.what);
        if r.valid {
            acc += 1
        } else {
            rej += 1
        }
        let decoded = match r.kind {
            0x0132 => VerifyingKey512::decode(&r.pk).is_some(),
            _ => VerifyingKey1024::decode(&r.pk).is_some(),
        };
        keys += decoded as usize;
        if fn_dsa(r.kind, &r.pk, &r.m, &r.sig) != pqclean {
            fn_mismatch.push(&r.what);
        }
        if round3(r.kind, &r.pk, &r.m, &r.sig) != pqclean {
            r3_mismatch.push(&r.what);
        }
    }
    println!(
        "{} rows: {acc} accept, {rej} refuse; fn-dsa-vrfy decodes {keys} keys; fn-dsa-vrfy verdict differs on {}, the round-3 \
         hash on fn-dsa-comm differs on {}",
        rows.len(),
        fn_mismatch.len(),
        r3_mismatch.len()
    );
    for w in fn_mismatch.iter().take(5) {
        println!("  fn-dsa-vrfy differs: {w}");
    }
    for w in r3_mismatch.iter().take(5) {
        println!("  round-3 port differs: {w}");
    }
    assert!(r3_mismatch.is_empty(), "round-3 port: {r3_mismatch:?}");
}
