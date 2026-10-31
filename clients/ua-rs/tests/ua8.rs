//! UA-8 A2 / typed-signing P2: the portable registration digests of `scaas_ua::ua8` against
//! smartcontracts/vectors/ua/portable.json (written by the JS reference, clientkeys scripts/ua-portable-vectors.mjs): the
//! typed EIP-712 records (TS-D1: domain, typehashes; every row's struct hash, digest and `typedData` JSON, hashed here by an
//! independent EIP-712 encoder), every digest of every registration, KEM record and PQZ key record, the native msig member
//! over the typed digest (TS-D4), and every holder / length / proof-hash refusal of `negatives[]` that is a digest-layer
//! rule. Rows that only a signature check or the registry's state can refuse (UAUnauthorized, the chain's PoP verdict) are
//! counted, not run.
use scaas_ua::ua8::*;
use scaas_ua::*;
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!("{}/../../smartcontracts/vectors/ua/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}
fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}
fn num(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}
fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array().unwrap()
}
fn find<'a>(v: &'a Value, k: &str, f: &str, x: &Value) -> &'a Value {
    arr(v, k).iter().find(|r| r[f] == *x).unwrap_or_else(|| panic!("no {k} row with {f} = {x}"))
}
fn zero(b: &[u8]) -> bool {
    b.iter().all(|x| *x == 0)
}
fn word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}
/// The legacy EIP-191 `personal_sign` prehash (legacy/typed-signing/portable_raw.rs): only for the negatives that pin it.
fn personal_sign(d: &[u8; 32]) -> [u8; 32] {
    keccak256(&[&b"\x19Ethereum Signed Message:\n32"[..], d].concat())
}

// ---------- an independent EIP-712 encoder over a wallet's typed-data JSON (the field types the portable records use) ----------

fn encode_type(types: &Value, t: &str) -> String {
    fn walk(types: &Value, t: &str, deps: &mut std::collections::BTreeSet<String>) {
        for f in types[t].as_array().unwrap() {
            let ft = f["type"].as_str().unwrap();
            if types.get(ft).is_some() && deps.insert(ft.to_string()) {
                walk(types, ft, deps);
            }
        }
    }
    let mut deps = std::collections::BTreeSet::new();
    walk(types, t, &mut deps);
    deps.remove(t);
    let one = |n: &str| {
        let fs: Vec<String> = types[n].as_array().unwrap().iter().map(|f| format!("{} {}", f["type"].as_str().unwrap(), f["name"].as_str().unwrap())).collect();
        format!("{n}({})", fs.join(","))
    };
    std::iter::once(one(t)).chain(deps.iter().map(|n| one(n))).collect()
}
fn hash_struct(types: &Value, t: &str, data: &Value) -> [u8; 32] {
    let mut enc = keccak256(encode_type(types, t).as_bytes()).to_vec();
    for f in types[t].as_array().unwrap() {
        let (ft, v) = (f["type"].as_str().unwrap(), &data[f["name"].as_str().unwrap()]);
        enc.extend(match ft {
            _ if types.get(ft).is_some() => hash_struct(types, ft, v),
            "string" => keccak256(v.as_str().unwrap().as_bytes()),
            "bytes32" => b32(v),
            "uint8" | "uint16" | "uint64" => word(num(v)),
            _ => panic!("field type {ft}"),
        });
    }
    keccak256(&enc)
}
/// `hashTypedData(td)`: what `eth_signTypedData_v4` signs for the JSON `td`.
fn hash_typed_data(td: &Value) -> [u8; 32] {
    let t = &td["types"];
    let ds = hash_struct(t, "EIP712Domain", &td["domain"]);
    keccak256(&[&[0x19u8, 0x01][..], &ds, &hash_struct(t, td["primaryType"].as_str().unwrap(), &td["message"])].concat())
}

/// `holder_pop_message` over a registration row's `attrs` (and `pqzPop` bytes, or only their hash when `hash_only`).
fn register(row: &Value, hash_only: bool) -> Result<HolderPop> {
    let a = &row["attrs"];
    let (key, pop, hash, pk) = (bytes(&a["pqzKey"]), bytes(&row["pqzPop"]), b32(&a["pqzPopHash"]), bytes(&a["kemPk"]));
    let opt = |b: &[u8]| (!b.is_empty()).then_some(b.to_vec());
    let (key, pop, pk) = (opt(&key), opt(&pop), opt(&pk));
    let kem = (num(&a["kemVersion"]) != 0 || pk.is_some()).then(|| (num(&a["kemVersion"]), pk.clone().unwrap_or_default()));
    holder_pop_message(
        num(&row["kind"]) as u16,
        &b32(&row["ua"]),
        &bytes(&row["keyData"]),
        key.as_deref(),
        if hash_only { None } else { pop.as_deref() },
        (!zero(&hash)).then_some(&hash),
        kem.as_ref().map(|(v, p)| (*v, &p[..])),
    )
}

#[test]
fn tags() {
    let p = load("portable.json");
    let t = &p["tags"];
    assert_eq!(hx(&pop_v2_tag()), t["PURPOSE_POP_V2"]["hash"]);
    assert_eq!(hx(&purpose_tag("kem").unwrap()), t["PURPOSE_KEM"]["hash"]);
    assert_eq!(hx(&purpose_tag("pqz-key").unwrap()), t["PURPOSE_PQZ_KEY"]["hash"]);
    assert!(t.get("KEM_RECORD_TAG").is_none() && t.get("PQZ_KEY_RECORD_TAG").is_none(), "raw record tags are legacy (TS-D3)");
    assert_eq!(hx(&group_tag("pqz-mlwe").unwrap()), t["PQZ_KEY_GROUP"]["hash"]);
    assert_eq!(purpose_tag_v("pop", 2).unwrap(), pop_v2_tag());
    assert_eq!(purpose_tag_v("pop", 1).unwrap(), purpose_tag("pop").unwrap());
    assert_eq!(purpose_tag_v("kem", 2), Err(UAError::PurposeUnknown));
    assert_eq!(KEM_PK_LENGTH as u64, num(&p["kemPkLength"]));
    for (name, c) in [("none", Checked::None), ("chain", Checked::Chain), ("relayer", Checked::Relayer([7; 32]))] {
        assert_eq!(c.code() as u64, num(&p["checked"][name]), "{name}");
    }
}

/// TS-D1: `DS_P = hashStruct(EIP712Domain{name: "SCaaS UA Portable", version: "1"})`, pinned and re-derived.
#[test]
fn domain_separator_pinned() {
    let p = load("portable.json");
    let t = &p["typed"];
    assert_eq!(hx(&PORTABLE_DOMAIN_SEPARATOR), "0x9a2c390d4dc940ccdb5fa6b21e673e87159bdd99aeef22ea791bcea9efc64ca1");
    assert_eq!(hx(&PORTABLE_DOMAIN_SEPARATOR), t["domainSeparator"]);
    assert_eq!((PORTABLE_DOMAIN_TYPE, PORTABLE_DOMAIN_NAME, PORTABLE_DOMAIN_VERSION), ("EIP712Domain(string name,string version)", "SCaaS UA Portable", "1"));
    assert_eq!(t["domainType"], PORTABLE_DOMAIN_TYPE);
    assert_eq!((t["domain"]["name"].as_str(), t["domain"]["version"].as_str()), (Some(PORTABLE_DOMAIN_NAME), Some(PORTABLE_DOMAIN_VERSION)));
    let derived = keccak256(&[keccak256(PORTABLE_DOMAIN_TYPE.as_bytes()), keccak256(PORTABLE_DOMAIN_NAME.as_bytes()), keccak256(PORTABLE_DOMAIN_VERSION.as_bytes())].concat());
    assert_eq!(derived, PORTABLE_DOMAIN_SEPARATOR);
}

/// TS-D1: the five portable typehashes (type strings: primary, then the referenced types sorted by name).
#[test]
fn portable_typehashes_pinned() {
    let p = load("portable.json");
    let want = [
        ("UAKemRecord", "0x0ab7989827627b89c268e88a0a0b06b62aefa70b0a466014931ca44acfa9a201"),
        ("UAPortableRecord", "0x0c1553cfab3c35326558484df79963dced75ead85272d2a85985f264757bfe7f"),
        ("UARegistration", "0xc78b548ceb2fadf1f0a895f79f88b517327c120f0f9ab345f02981441048c87e"),
        ("UAPqzKey", "0x827d90728b100bc830d06b04dd2b9b5f7853adaa05502b4082875f881d925a00"),
        ("UAPqzKeyRecord", "0xaba20a80603724f71232573a76d2506ae38f60f39ea9cd8e71f4b64775dd7567"),
    ];
    assert_eq!(PORTABLE_TYPES.map(|(n, _)| n), want.map(|(n, _)| n));
    assert_eq!(p["typed"]["types"].as_object().unwrap().len(), want.len());
    for ((name, ty), (_, th)) in PORTABLE_TYPES.iter().zip(want) {
        assert_eq!(hx(&portable_typehash(name)), th, "{name}");
        assert_eq!(hx(&keccak256(ty.as_bytes())), th, "{name}");
        assert_eq!(p["typed"]["types"][name]["type"], *ty, "{name}");
        assert_eq!(p["typed"]["types"][name]["typehash"], th, "{name}");
        // the wallet JSON's types encode to the same string
        let row = arr(&p, "registrations")[0]["typedData"]["types"].clone();
        if row.get(*name).is_some() {
            assert_eq!(encode_type(&row, name), *ty, "{name}");
        }
    }
}

/// Every row's `typedData` (the JSON `eth_signTypedData_v4` signs) hashes to the row's typed digest, its message carries
/// the row's words (`kind` included), and the struct hashes agree with the word-level functions.
#[test]
fn portable_rows_typed() {
    let p = load("portable.json");
    let mut n = 0;
    for r in arr(&p, "registrations") {
        let td = &r["typedData"];
        let (ua, kind) = (b32(&r["ua"]), num(&r["kind"]) as u16);
        assert_eq!((td["primaryType"].as_str(), &td["domain"]), (Some("UARegistration"), &p["typed"]["domain"]), "{}", r["name"]);
        assert_eq!(hx(&hash_typed_data(td)), r["registrationDigest"], "{}", r["name"]);
        let (rec, kem) = (&td["message"]["record"], &td["message"]["record"]["kem"]);
        assert_eq!((num(&rec["kind"]), b32(&rec["ua"]), b32(&kem["ua"])), (kind as u64, ua, ua), "{}", r["name"]);
        assert_eq!(rec["pqzKeyHash"], r["pqzKeyHash"], "{}", r["name"]);
        assert_eq!(td["message"]["pqzPopHash"], r["attrs"]["pqzPopHash"], "{}", r["name"]);
        assert_eq!(hx(&hash_struct(&td["types"], "UAKemRecord", kem)), r["kemRecordHash"], "{}", r["name"]);
        let (pk, v) = (bytes(&r["attrs"]["kemPk"]), num(&r["attrs"]["kemVersion"]));
        assert_eq!(hx(&kem_record_hash(&ua, v, &pk).unwrap()), r["kemRecordHash"], "{}", r["name"]);
        if pk.is_empty() {
            // TS-D2: no KEM record = UAKemRecord{ua, 0, 0, 0}
            assert_eq!((num(&kem["version"]), num(&kem["scheme"]), b32(&kem["kemPkHash"])), (0, 0, [0; 32]), "{}", r["name"]);
        } else {
            assert_eq!((num(&kem["version"]), num(&kem["scheme"]), b32(&kem["kemPkHash"])), (v, pk[0] as u64, keccak256(&pk)), "{}", r["name"]);
        }
        let words = (b32(&r["pqzKeyHash"]), b32(&r["kemRecordHash"]));
        assert_eq!(hx(&portable_record_hash(&ua, kind, &words.0, &words.1)), hx(&hash_struct(&td["types"], "UAPortableRecord", rec)), "{}", r["name"]);
        let mut rtd = td.clone(); // the R_REG record alone, as a wallet would show it
        rtd["primaryType"] = "UAPortableRecord".into();
        rtd["message"] = rec.clone();
        assert_eq!(hx(&hash_typed_data(&rtd)), r["portableRecordDigest"], "{}", r["name"]);
        n += 1;
    }
    for r in arr(&p, "kemRecords") {
        let td = &r["typedData"];
        assert_eq!(td["primaryType"], "UAKemRecord", "{}", r["id"]);
        assert_eq!(hx(&hash_typed_data(td)), r["digest"], "{}", r["id"]);
        assert_eq!(hx(&hash_struct(&td["types"], "UAKemRecord", &td["message"])), r["structHash"], "{}", r["id"]);
        let (ua, v, pk) = (b32(&r["ua"]), num(&r["version"]), bytes(&r["kemPk"]));
        assert_eq!(hx(&kem_record_hash(&ua, v, &pk).unwrap()), r["structHash"], "{}", r["id"]);
        assert_eq!((num(&td["message"]["version"]), num(&td["message"]["scheme"])), (v, pk[0] as u64), "{}", r["id"]);
        n += 1;
    }
    for r in arr(&p, "pqzKeyRecords") {
        let td = &r["typedData"];
        assert_eq!(td["primaryType"], "UAPqzKeyRecord", "{}", r["name"]);
        assert_eq!(hx(&hash_typed_data(td)), r["recordDigest"], "{}", r["name"]);
        let (ua, h, ph) = (b32(&r["ua"]), b32(&r["pqzKeyHash"]), b32(&r["pqzPopHash"]));
        assert_eq!((b32(&td["message"]["key"]["ua"]), b32(&td["message"]["key"]["pqzKeyHash"]), b32(&td["message"]["pqzPopHash"])), (ua, h, ph), "{}", r["name"]);
        assert_eq!(hx(&pqz_key_record_digest(&ua, &h, &ph)), r["recordDigest"], "{}", r["name"]);
        let mut ktd = td.clone();
        ktd["primaryType"] = "UAPqzKey".into();
        ktd["message"] = td["message"]["key"].clone();
        assert_eq!(hx(&hash_typed_data(&ktd)), r["pqzKeyDigest"], "{}", r["name"]);
        assert_eq!(hx(&pqz_key_digest(&ua, &h)), r["pqzKeyDigest"], "{}", r["name"]);
        n += 1;
    }
    assert_eq!(n, 25 + 9 + 8);
}

#[test]
fn portable_vectors() {
    let p = load("portable.json");
    let (mut n, mut with_pqz, mut msigs, mut reg_msgs) = (0, 0, 0, 0);
    for r in arr(&p, "registrations") {
        let (kind, ua) = (num(&r["kind"]) as u16, b32(&r["ua"]));
        assert_eq!(ua_of(kind, &bytes(&r["keyData"])).unwrap(), ua, "{}", r["name"]);
        for hash_only in [false, true] {
            let h = register(r, hash_only).unwrap_or_else(|e| panic!("{}: {e}", r["name"]));
            assert_eq!(hx(&h.pqz_key_hash), r["pqzKeyHash"], "{}", r["name"]);
            assert_eq!(hx(&h.pqz_pop_hash), r["attrs"]["pqzPopHash"], "{}", r["name"]);
            assert_eq!(hx(&h.kem_record_hash), r["kemRecordHash"], "{}", r["name"]);
            assert_eq!(hx(&h.portable_record_digest), r["portableRecordDigest"], "{}", r["name"]);
            assert_eq!(hx(&h.registration_digest), r["registrationDigest"], "{}", r["name"]);
            assert_eq!(hx(&h.message), r["popMessage"], "{}", r["name"]);
            // the word-level functions agree
            assert_eq!(portable_record_digest(&ua, kind, &h.pqz_key_hash, &h.kem_record_hash), h.portable_record_digest);
            assert_eq!(registration_digest(&ua, kind, &h.pqz_key_hash, &h.kem_record_hash, &h.pqz_pop_hash), h.registration_digest);
            assert_eq!(ua_message(kind, &pop_v2_tag(), &h.registration_digest).unwrap(), h.message);
            assert_eq!(h.member_digest.map(|d| hx(&d)), r.get("memberDigest").map(|d| d.as_str().unwrap().to_string()), "{}", r["name"]);
        }
        let pk = bytes(&r["attrs"]["pqzKey"]);
        if !pk.is_empty() {
            with_pqz += 1;
            let kem = (num(&r["attrs"]["kemVersion"]) != 0).then(|| (num(&r["attrs"]["kemVersion"]), bytes(&r["attrs"]["kemPk"])));
            let got = pqz_reg_message(kind, &ua, &pk, kem.as_ref().map(|(v, p)| (*v, &p[..]))).unwrap();
            assert_eq!(hx(&got), r["pqzRegMessage"], "{}", r["name"]);
            // TS-D3: R_REG proves over the typed UAPortableRecord of the registering kind
            assert_eq!(got, ua_message(PQZ_SCHEME, &pop_v2_tag(), &b32(&r["portableRecordDigest"])).unwrap(), "{}", r["name"]);
            reg_msgs += 1;
        } else {
            assert!(zero(&bytes(&r["pqzRegMessage"])), "{}", r["name"]);
        }
        msigs += (kind == 0x0120) as usize;
        n += 1;
    }
    assert_eq!((n, with_pqz, msigs, reg_msgs), (25, 8, 6, 8));
    println!("{n} registrations, {with_pqz} with a PQZ key, {msigs} msig");
}

#[test]
fn kem_record_vectors() {
    let p = load("portable.json");
    for r in arr(&p, "kemRecords") {
        let (kind, ua, v, pk) = (num(&r["kind"]) as u16, b32(&r["ua"]), num(&r["version"]), bytes(&r["kemPk"]));
        assert_eq!(hx(&kem_record_digest(&ua, v, &pk).unwrap()), r["digest"], "{}", r["id"]);
        assert_eq!(hx(&kem_record_hash(&ua, v, &pk).unwrap()), r["structHash"], "{}", r["id"]);
        let m = kem_record_message(kind, &ua, v, &pk).unwrap();
        assert_eq!(hx(&m), r["message"], "{}", r["id"]);
        assert_eq!(m, ua_message(kind, &purpose_tag("kem").unwrap(), &b32(&r["digest"])).unwrap());
        if kind == 0x0120 {
            assert_eq!(hx(&member_digest(&ua, &m)), r["memberDigest"], "{}", r["id"]);
        }
    }
    assert_eq!(arr(&p, "kemRecords").len(), 9);
    let ua = [1u8; 32];
    let kem = |scheme: u8, n: usize| [vec![scheme], vec![0u8; n - 1]].concat(); // scheme byte ‖ zeros, n bytes in all
    assert_eq!(kem_record_digest(&ua, 0, &kem(1, 1601)), Err(UAError::KemVersion));
    assert_eq!(kem_record_digest(&ua, 1, &kem(1, 1600)), Err(UAError::KemKeyLength));
    assert_eq!(kem_record_digest(&ua, 1, &kem(1, 1602)), Err(UAError::KemKeyLength));
    assert_eq!(kem_record_digest(&ua, 1, &[]), Err(UAError::KemKeyLength));
    // TS-D2: (0, no key) is the zero record's hash (never a signed record); version 0 with a key is UAKemVersion
    let th = keccak256(b"UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)");
    assert_eq!(kem_record_hash(&ua, 0, &[]).unwrap(), keccak256(&[th, ua, [0; 32], [0; 32], [0; 32]].concat()));
    assert_eq!(kem_record_hash(&ua, 0, &kem(1, 1601)), Err(UAError::KemVersion));
    assert_eq!(kem_record_hash(&ua, 1, &[]), Err(UAError::KemKeyLength));
    assert_eq!(kem_record_digest(&ua, 0, &[]), Err(UAError::KemVersion));
    // CTR-UA-32: scheme 1 only; 0, the reserved 2 and an unknown id are UAKemScheme, whatever the length
    for scheme in [0u8, 2, 0xff] {
        assert_eq!(kem_record_digest(&ua, 1, &kem(scheme, 1601)), Err(UAError::KemScheme));
        assert_eq!(kem_record_digest(&ua, 1, &kem(scheme, 1600)), Err(UAError::KemScheme));
    }
    // known answers (ua-py / ua-go): the 8-byte version word and the decimal "evm:" chain key
    assert_eq!(hx(&kem_record_digest(&ua, u64::MAX, &kem(1, 1601)).unwrap()), "0xa0063a84b56d80c83688d8caf5aeb4be8fb4556928e8bc649686449573938f07");
    assert_eq!(hx(&chain_key_hash((1 << 40) + 7)), "0x6e45d591a544f53396f6e86d49f5809196c5725f9d99dbd2ca97f9925c7ce950"); // keccak256("evm:1099511627783")
}

#[test]
fn pqz_key_record_vectors() {
    let p = load("portable.json");
    for r in arr(&p, "pqzKeyRecords") {
        let (kind, ua, key) = (num(&r["kind"]) as u16, b32(&r["ua"]), bytes(&r["pqzKey"]));
        let reg = find(&p, "registrations", "ua", &r["ua"]);
        let kd = bytes(&reg["keyData"]);
        for hash_only in [false, true] {
            let pop = bytes(&find(&p, "registrations", "set", &r["set"])["pqzPop"]);
            let h = b32(&r["pqzPopHash"]);
            let got = pqz_key_record_message(kind, &ua, &kd, &key, (!hash_only).then_some(&pop[..]), hash_only.then_some(&h), false)
                .unwrap_or_else(|e| panic!("{}: {e}", r["name"]));
            assert_eq!(hx(&got.pqz_key_hash), r["pqzKeyHash"], "{}", r["name"]);
            assert_eq!(hx(&got.pqz_pop_hash), r["pqzPopHash"], "{}", r["name"]);
            assert_eq!(hx(&got.pqz_key_digest), r["pqzKeyDigest"], "{}", r["name"]);
            assert_eq!(hx(&got.record_digest), r["recordDigest"], "{}", r["name"]);
            assert_eq!(hx(&got.message), r["message"], "{}", r["name"]);
            assert_eq!(hx(&got.pqz_reg_message), r["pqzRegMessage"], "{}", r["name"]);
            assert_eq!(pqz_key_digest(&ua, &got.pqz_key_hash), got.pqz_key_digest);
            assert_eq!(pqz_key_record_digest(&ua, &got.pqz_key_hash, &got.pqz_pop_hash), got.record_digest);
            assert_eq!(got.member_digest.is_some(), kind == 0x0120, "{}", r["name"]);
            if let Some(md) = got.member_digest {
                assert_eq!(member_digest(&ua, &got.message), md);
            }
        }
        // write-once: a key already set refuses; a non-holder refuses first
        let h = b32(&r["pqzPopHash"]);
        assert_eq!(pqz_key_record_message(kind, &ua, &kd, &key, None, Some(&h), true), Err(UAError::PqzKeySet), "{}", r["name"]);
    }
    assert_eq!(arr(&p, "pqzKeyRecords").len(), 8);
}

#[test]
fn negatives_refused() {
    let p = load("portable.json");
    let (mut run, mut sig_level) = (0, 0);
    for n in arr(&p, "negatives") {
        let (name, entry, err) = (n["name"].as_str().unwrap(), n["entry"].as_str().unwrap(), n["error"].as_str().unwrap());
        let m = &n["mutation"];
        let mut row = arr(&p, "registrations").iter().find(|r| r["name"] == m["row"]).cloned().unwrap_or(Value::Null);
        let mut set: Vec<(&String, &Value)> = m["set"].as_object().map(|o| o.iter().collect()).unwrap_or_default();
        if let Some(w) = m.get("registerWith") {
            for (k, v) in w.as_object().unwrap() {
                row[k] = v.clone();
            }
        }
        match entry {
            "register" | "storePqzPop" if set.iter().all(|(k, _)| k.starts_with("attrs.") || *k == "pqzPop") => {
                for (k, v) in set.drain(..) {
                    match k.strip_prefix("attrs.") {
                        Some(f) => row["attrs"][f] = v.clone(),
                        None => row[k] = v.clone(),
                    }
                }
                let got = register(&row, false);
                if err == "UAPoP" {
                    // the digest layer accepts it; the PoP of the unmutated row does not cover it
                    let h = got.unwrap_or_else(|e| panic!("{name}: {e}"));
                    assert_ne!(hx(&h.message), row["popMessage"], "{name}");
                } else {
                    assert_eq!(got.err().map(|e| e.code()), Some(err), "{name}");
                }
                run += 1;
            }
            "setPqzKey" if err == "UAPqzKeySet" || err == "UAPqzHolder" || err == "UAPqzPopHash" => {
                let rec = find(&p, "pqzKeyRecords", "name", &m["row"]);
                let ua = m["set"].get("ua").unwrap_or(&rec["ua"]);
                let holder_row = find(&p, "registrations", "ua", ua);
                let (kind, kd) = (num(&holder_row["kind"]) as u16, bytes(&holder_row["keyData"]));
                let h = b32(m["set"].get("pqzPopHash").unwrap_or(&rec["pqzPopHash"]));
                let already = holder_row["attrs"]["pqzKey"] != "0x"; // the state, not the expected error
                // already-set rows keep the holder (same kind as the record's); wrong-holder rows name a UA that is none
                let got = pqz_key_record_message(kind, &b32(ua), &kd, &bytes(&rec["pqzKey"]), None, Some(&h), already);
                assert_eq!(got.err().map(|e| e.code()), Some(err), "{name}");
                run += 1;
            }
            "setKemKey" if m["row"] == "fndsa512/v2" => {
                // the record of one UA offered for another: the signed message differs, so the signature cannot verify
                let k = find(&p, "kemRecords", "id", &m["row"]);
                let t = find(&p, "registrations", "ua", &m["set"]["ua"]);
                let msg = kem_record_message(num(&t["kind"]) as u16, &b32(&m["set"]["ua"]), num(&k["version"]), &bytes(&k["kemPk"])).unwrap();
                assert_ne!(hx(&msg), k["message"], "{name}");
                run += 1;
            }
            "register" if name == "native-uaauth-in-portable-pop" || name == "native-member-personal-sign" => {
                // TS-D4: neither a UAAuth-framed native signature nor the old personal_sign(memberDigest) recovers the
                // member over the typed registration digest; the old form is a valid signature over its own prehash
                let r = &row;
                let blob = bytes(&m["set"]["pop"]);
                let got = native_recovered(r, &blob, &b32(&r["registrationDigest"]));
                assert!(!got.is_empty() && got.iter().all(|(i, a)| a.as_ref() != Some(&member_address(r, *i))), "{name}");
                let old = native_recovered(r, &blob, &personal_sign(&b32(&r["memberDigest"])));
                assert_eq!(old.iter().all(|(i, a)| a.as_ref() == Some(&member_address(r, *i))), name == "native-member-personal-sign", "{name}");
                run += 1;
            }
            "register" if name == "record-kind-mismatch" => {
                // a valid pop over the same UA and attributes under another kind: the typed record binds `kind`
                let other = num(&m["otherKind"]) as u16;
                let (kind, ua) = (num(&row["kind"]) as u16, b32(&row["ua"]));
                let msg = ua_message(kind, &pop_v2_tag(), &registration_digest(&ua, other, &[0; 32], &kem_record_hash(&ua, 0, &[]).unwrap(), &[0; 32])).unwrap();
                assert_ne!(other, kind, "{name}");
                assert_ne!(hx(&msg), row["popMessage"], "{name}");
                let (kd, pop) = (bytes(&row["keyData"]), bytes(&m["set"]["pop"]));
                assert!(scaas_ua::verify::verify(kind, &kd, &msg, &pop, true), "{name}: signed over the other kind");
                assert!(!scaas_ua::verify::verify(kind, &kd, &b32(&row["popMessage"]), &pop, true), "{name}");
                run += 1;
            }
            "register" if name == "kem-record-as-registration" => {
                // the row's own KEM record (typed UAKemRecord) signed under pop v2 is not its registration (struct type)
                let k = find(&p, "kemRecords", "id", &format!("{}/v1", row["name"].as_str().unwrap()).into());
                let msg = ua_message(num(&row["kind"]) as u16, &pop_v2_tag(), &b32(&k["digest"])).unwrap();
                assert_ne!(hx(&msg), row["popMessage"], "{name}");
                assert_ne!(k["digest"], row["registrationDigest"], "{name}");
                run += 1;
            }
            "requireAuthorized" => {
                // valid personal_sign, but metatx is not a portable purpose: UAAuth there
                let (tag, auth) = (b32(&m["set"]["purposeTag"]), bytes(&m["set"]["auth"]));
                assert!(!is_portable_purpose(&tag), "{name}");
                assert_eq!(hx(bytes_at(&auth, 0)), row["keyData"], "{name}");
                let md = member_digest(&b32(&row["ua"]), &ua_message(0x0120, &tag, &b32(&m["set"]["digest"])).unwrap());
                let got = native_recovered(&row, bytes_at(&auth, 32), &personal_sign(&md));
                assert!(!got.is_empty() && got.iter().all(|(i, a)| a.as_ref() == Some(&member_address(&row, *i))), "{name}");
                run += 1;
            }
            _ => sig_level += 1, // PQ / classical signatures: verified by the signature vectors (no verifier in this crate)
        }
    }
    assert_eq!((run, sig_level), (65, 5), "{} negatives", arr(&p, "negatives").len());
    println!("{run} digest-layer negatives refused, {sig_level} signature-level");
}

fn word_at(b: &[u8], o: usize) -> usize {
    usize::from_be_bytes(b[o + 24..o + 32].try_into().unwrap())
}
/// `bytes` at the head word `o` of an abi-encoded blob (offset word, then length and data).
fn bytes_at(b: &[u8], o: usize) -> &[u8] {
    let p = word_at(b, o);
    &b[p + 32..p + 32 + word_at(b, p)]
}
/// The address each native (kind 0x0001) member's signature in a `MemberSig[]` blob recovers over the prehash `digest`
/// (None: not a 65-byte signature, or no recovery), by member index.
fn native_recovered(row: &Value, blob: &[u8], digest: &[u8; 32]) -> Vec<(usize, Option<String>)> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    let (list, count) = (word_at(blob, 0), word_at(blob, word_at(blob, 0)));
    let mut out = vec![];
    for i in 0..count {
        let t = list + 32 + word_at(blob, list + 32 + 32 * i);
        let idx = word_at(blob, t);
        if num(&row["members"][idx]["kind"]) != 1 {
            continue;
        }
        let sig_at = t + word_at(blob, t + 64);
        let sig = &blob[sig_at + 32..sig_at + 32 + word_at(blob, sig_at)];
        let addr = (sig.len() == 65)
            .then(|| {
                let s = Signature::from_slice(&sig[..64]).ok()?;
                let v = RecoveryId::from_byte(sig[64].checked_sub(27)?)?;
                let vk = VerifyingKey::recover_from_prehash(digest, &s, v).ok()?;
                Some(hx(&keccak256(&vk.to_encoded_point(false).as_bytes()[1..])[12..]))
            })
            .flatten();
        out.push((idx, addr));
    }
    out
}
fn member_address(row: &Value, idx: usize) -> String {
    format!("0x{}", &row["members"][idx]["id"].as_str().unwrap()[26..])
}

/// TS-D4 (owner decision 4): a native EOA msig member signs the portable record's typed digest itself
/// (`eth_signTypedData_v4`), not `personal_sign(memberDigest)`; the recovered address is the member's.
#[test]
fn native_member_typed_digest() {
    let p = load("portable.json");
    let r = find(&p, "registrations", "name", &"msig-pq-native".into());
    let mut cases = vec![(b32(&r["registrationDigest"]), bytes(&r["pop"]), b32(&r["memberDigest"]))];
    for k in arr(&p, "pqzKeyRecords").iter().filter(|k| k["ua"] == r["ua"]) {
        cases.push((b32(&k["recordDigest"]), bytes(&k["sig"]), b32(&k["memberDigest"])));
    }
    assert_eq!(cases.len(), 5, "the registration and its PQZ key record per set");
    for (typed, blob, md) in cases {
        let got = native_recovered(r, &blob, &typed);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, Some(member_address(r, got[0].0)), "over the typed digest");
        for other in [md, personal_sign(&md)] {
            assert_ne!(native_recovered(r, &blob, &other)[0].1, Some(member_address(r, got[0].0)), "not md, not personal_sign(md)");
        }
    }
    assert!(is_portable_purpose(&pop_v2_tag()) && is_portable_purpose(&purpose_tag("kem").unwrap()) && is_portable_purpose(&purpose_tag("pqz-key").unwrap()));
    assert!(!is_portable_purpose(&purpose_tag("metatx").unwrap()) && !is_portable_purpose(&purpose_tag("pop").unwrap()));
}

/// UAKeyData, as in the JS: a malformed msig key data is not "not a holder".
#[test]
fn malformed_msig_key_data() {
    let ua = [1u8; 32];
    let pk = vec![0u8; 16384];
    let proof = [7u8; 32];
    for kd in [&[0u8, 2, 0][..], &[0, 2, 0, 2, 9, 9][..]] {
        let want = Err(UAError::KeyData("length"));
        assert_eq!(holder_pop_message(0x0120, &ua, kd, Some(&pk), None, Some(&proof), None).map(|_| ()), want);
        assert_eq!(holder_pop_message(0x0120, &ua, kd, None, None, None, Some((1, &[0; 1600]))).map(|_| ()), want);
        assert_eq!(pqz_key_record_message(0x0120, &ua, kd, &pk, None, Some(&proof), false).map(|_| ()), want);
    }
    // no attributes: key data is not consulted; an msig without key data is not a holder
    assert!(holder_pop_message(0x0120, &ua, &[0, 2, 0], None, None, None, None).is_ok());
    assert_eq!(holder_pop_message(0x0120, &ua, &[], Some(&pk), None, Some(&proof), None).map(|_| ()), Err(UAError::PqzHolder(0x0120)));
}
