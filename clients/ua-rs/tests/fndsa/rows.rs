// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Every FN-DSA-512 / FN-DSA-1024 row of smartcontracts/vectors/ua with its stated verdict: clientkeys' pq_kat (+ mutations) and
//! pq_signatures, the NIST round-3 KATs of pq_external, the Falcon rows of rs_signatures and sign.json, and three refusals
//! derived from each accept row as FnDsa.t.sol does (a set padding byte, the other degree's header, a flipped message bit), and
//! the encoding edges of each accept row (Fable audit FR-11, [`edges`]). Shared by tests/fndsa_vrfy.rs (native) and
//! tests/fndsa/wasm (the same rows in wasm32).
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
    let edges: Vec<Row> = out.iter().filter(|r| r.valid).flat_map(edges).collect();
    out.extend(edges);
    out
}

/// The rows' verdict counts: accept, refuse.
pub const COUNTS: (usize, usize) = (48, 796);

/// The bits of `b`, most significant first (the round-3 codecs' order).
fn bits(b: &[u8]) -> Vec<u8> {
    b.iter()
        .flat_map(|x| (0..8).rev().map(move |i| (x >> i) & 1))
        .collect()
}

/// `bits` packed into `len` bytes, zero-padded.
fn pack(bits: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for (i, b) in bits.iter().enumerate() {
        out[i / 8] |= b << (7 - i % 8);
    }
    out
}

/// Where each coefficient of a valid compressed `s2` starts (round 3 `comp_decode`: sign, seven low bits, the high part in
/// unary ended by a 1), and where the last one ends.
fn coefficients(bits: &[u8], n: usize) -> (Vec<usize>, usize) {
    let mut starts = Vec::with_capacity(n);
    let mut i = 0;
    for _ in 0..n {
        starts.push(i);
        i += 8;
        while bits[i] == 0 {
            i += 1;
        }
        i += 1;
    }
    (starts, i)
}

/// A 14-bit coefficient `k` of a public key (header byte, then `n` coefficients, round 3 `modq_encode`) set to `v`.
fn set_pk_coefficient(pk: &[u8], k: usize, v: u16) -> Vec<u8> {
    let mut b = bits(pk);
    for j in 0..14 {
        b[8 + 14 * k + j] = ((v >> (13 - j)) & 1) as u8;
    }
    pack(&b, pk.len())
}

/// The encoding edges of an accept row, each refused by PQClean and falcon-rs alike: a "-0" coefficient, a high part running
/// past 2,047, the first bit after `s2` set (an unused bit of its last byte, or the first padding byte), the signature without
/// its padding and one byte past it, a public-key coefficient equal to q and to 2^14 - 1, three other key headers and three
/// other signature headers (unpadded and constant-time formats, the high bit).
fn edges(r: &Row) -> Vec<Row> {
    let (n, logn) = if r.kind == 0x0132 {
        (512, 9u8)
    } else {
        (1024, 10)
    };
    let c = &r.sig[41..];
    let b = bits(c);
    let (starts, end) = coefficients(&b, n);
    let sig_with = |comp: Vec<u8>| [&r.sig[..41], &comp[..]].concat();
    let mut sigs: Vec<(&str, Vec<u8>)> = Vec::new();
    let minus_zero = [&[1, 0, 0, 0, 0, 0, 0, 0, 1][..], &b[starts[1]..end]].concat();
    sigs.push(("-0 coefficient", sig_with(pack(&minus_zero, c.len()))));
    sigs.push((
        "high part past 2047",
        sig_with(pack(&b[..starts[n / 2] + 8], c.len())),
    ));
    if end < b.len() {
        let mut after = b[..end].to_vec();
        after.push(1);
        sigs.push(("bit after s2", sig_with(pack(&after, c.len()))));
    }
    if 41 + end.div_ceil(8) < r.sig.len() {
        sigs.push(("unpadded", r.sig[..41 + end.div_ceil(8)].to_vec()));
    }
    sigs.push(("one byte past padding", [&r.sig[..], &[0]].concat()));
    for (what, h) in [
        ("sig header 0x2_", 0x20 + logn),
        ("sig header 0x5_", 0x50 + logn),
        ("sig header 0xb_", 0x80 | (0x30 + logn)),
    ] {
        let mut s = r.sig.clone();
        s[0] = h;
        sigs.push((what, s));
    }
    let mut pks: Vec<(&str, Vec<u8>)> = vec![
        ("pk coefficient q", set_pk_coefficient(&r.pk, 0, 12289)),
        (
            "pk coefficient 2^14-1",
            set_pk_coefficient(&r.pk, n - 1, 0x3fff),
        ),
    ];
    for (what, h) in [
        ("pk header other degree", logn ^ 0x03),
        ("pk header 0x1_", 0x10 | logn),
        ("pk header 0x8_", 0x80 | logn),
    ] {
        let mut k = r.pk.clone();
        k[0] = h;
        pks.push((what, k));
    }
    let row = |how: &str, pk: Vec<u8>, sig: Vec<u8>| Row {
        what: format!("{} / {how}", r.what),
        kind: r.kind,
        pk,
        m: r.m.clone(),
        sig,
        valid: false,
    };
    let mut out: Vec<Row> = sigs
        .into_iter()
        .map(|(h, s)| row(h, r.pk.clone(), s))
        .collect();
    out.extend(pks.into_iter().map(|(h, k)| row(h, k, r.sig.clone())));
    out
}
