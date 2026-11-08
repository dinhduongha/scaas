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
    assert!(a.get("kemVersion").is_none(), "register takes no KEM version (typed-signing R1)");
    holder_pop_message(
        num(&row["kind"]) as u16,
        &b32(&row["ua"]),
        &bytes(&row["keyData"]),
        key.as_deref(),
        if hash_only { None } else { pop.as_deref() },
        (!zero(&hash)).then_some(&hash),
        pk.as_deref(), // the register KEM key: version 0 (owner 2026-10-31)
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

/// CTR-UA-37: every acceptance row: its typed digest, the message and `memberDigest` a derived member signs under `member`.
#[test]
fn membership_rows() {
    let p = load("portable.json");
    let rows = arr(&p, "memberships");
    assert_eq!(rows.len(), 6);
    for r in rows {
        let (ua, member) = (b32(&r["ua"]), b32(&r["member"]));
        let d = membership_digest(&ua, &member);
        assert_eq!(hx(&d), r["digest"], "{}", r["name"]);
        let m = ua_message(0x0120, &purpose_tag("membership").unwrap(), &d).unwrap();
        assert_eq!(hx(&m), r["message"], "{}", r["name"]);
        assert_eq!(hx(&member_digest(&ua, &m)), r["memberDigest"], "{}", r["name"]);
        assert!(is_portable_purpose(&purpose_tag("membership").unwrap()));
    }
}

/// TS-D1, CTR-UA-37: the six portable typehashes (type strings: primary, then the referenced types sorted by name).
#[test]
fn portable_typehashes_pinned() {
    let p = load("portable.json");
    let want = [
        ("UAKemRecord", "0x0ab7989827627b89c268e88a0a0b06b62aefa70b0a466014931ca44acfa9a201"),
        ("UAPortableRecord", "0x0c1553cfab3c35326558484df79963dced75ead85272d2a85985f264757bfe7f"),
        ("UARegistration", "0xc78b548ceb2fadf1f0a895f79f88b517327c120f0f9ab345f02981441048c87e"),
        ("UAPqzKey", "0x827d90728b100bc830d06b04dd2b9b5f7853adaa05502b4082875f881d925a00"),
        ("UAPqzKeyRecord", "0xaba20a80603724f71232573a76d2506ae38f60f39ea9cd8e71f4b64775dd7567"),
        ("UAPqzKeyVersion", "0x56bb760a3968427f1aa06b0497de42c05374beae46765175b61976c12e38b158"),
        ("UAPqzKeyVersionRecord", "0x2e00b7c0ff5cfbca3f50e0445bcd02bb227e0154c239c812b38d9b8fa6e7d6e5"),
        ("UAMembership", "0x2ffb61cab130ef54f9af88d7255ca81c570651b2562c2c368286a1f43bfe5cb4"),
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
        let (pk, v) = (bytes(&r["attrs"]["kemPk"]), 0); // the register KEM key is version 0 (owner 2026-10-31)
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
    // + mldsa87, fndsa1024 (CTR-UA-39 / -40): a registration, KEM v1-v3, PQZ key records at four sets each; CTR-UA-32: no msig KEM record
    assert_eq!(n, 27 + 12 + 16);
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
            let kem = bytes(&r["attrs"]["kemPk"]);
            let got = pqz_reg_message(kind, &ua, &pk, (!kem.is_empty()).then_some(&kem[..])).unwrap();
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
    assert_eq!((n, with_pqz, msigs, reg_msgs), (27, 8, 6, 8));
    // mldsa87 (CTR-UA-39), fndsa1024 (CTR-UA-40): holders, read here and in the record tests: a registration with its KEM register
    // key, KEM records v1-v3, PQZ key records at the four sets
    for k in [0x0134, 0x0135] {
        let got = ["registrations", "kemRecords", "pqzKeyRecords"].map(|s| arr(&p, s).iter().filter(|r| num(&r["kind"]) == k).count());
        assert_eq!(got, [1, 3, 4], "{k:#x}");
    }
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
        assert_ne!(kind, 0x0120, "{}: CTR-UA-32, an msig holds no KEM key", r["id"]);
    }
    assert_eq!(arr(&p, "kemRecords").len(), 12);
    let ua = [1u8; 32];
    let kem = |scheme: u8, n: usize| [vec![scheme], vec![0u8; n - 1]].concat(); // scheme byte ‖ zeros, n bytes in all
    // CTR-UA-32 (T66a): a PQ-eligible msig holds a PQZ key but no KEM key; the same record under a single PQ kind builds
    let mq = b32(&find(&p, "registrations", "name", &"msig-pq/n2048-kmax1024".into())["ua"]);
    assert_eq!(kem_record_message(0x0120, &mq, 1, &kem(1, 1601)), Err(UAError::KemHolder(0x0120)));
    assert!(kem_record_message(0x0131, &mq, 1, &kem(1, 1601)).is_ok(), "the control");
    assert_eq!(kem_record_digest(&ua, 0, &kem(1, 1601)), Err(UAError::KemVersion));
    assert_eq!(kem_record_digest(&ua, 1, &kem(1, 1600)), Err(UAError::KemKeyLength));
    assert_eq!(kem_record_digest(&ua, 1, &kem(1, 1602)), Err(UAError::KemKeyLength));
    assert_eq!(kem_record_digest(&ua, 1, &[]), Err(UAError::KemKeyLength));
    // TS-D2: (0, no key) is the zero record's hash; owner 2026-10-31: version 0 with a key is the register key's record
    // (scheme != 0: scheme 0 is UAKemScheme), never a setKemKey record (UAKemVersion)
    let th = keccak256(b"UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)");
    assert_eq!(kem_record_hash(&ua, 0, &[]).unwrap(), keccak256(&[th, ua, [0; 32], [0; 32], [0; 32]].concat()));
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(kem_record_hash(&ua, 0, &kem(1, 1601)).unwrap(), keccak256(&[th, ua, [0; 32], one, keccak256(&kem(1, 1601))].concat()));
    assert_eq!(kem_record_hash(&ua, 0, &kem(0, 1601)), Err(UAError::KemScheme));
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
    assert_eq!(arr(&p, "pqzKeyRecords").len(), 16);
}

#[test]
fn negatives_refused() {
    let p = load("portable.json");
    let (mut run, mut sig_level) = (0, 0);
    for n in arr(&p, "negatives") {
        if n["rule"] == "msig-minimal" {
            continue; // a registry rule over a full registration: portable_msig_rows_minimal
        }
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
            "setKemKey" if err == "UAKemHolder" => {
                // CTR-UA-32: an msig's KEM record is refused by its kind before any signature (the target's kind is the row's)
                let k = find(&p, "kemRecords", "id", &m["row"]);
                let t = find(&p, "registrations", "ua", &m["set"]["ua"]);
                assert_eq!(t["kind"], m["kind"], "{name}");
                let got = kem_record_message(num(&t["kind"]) as u16, &b32(&m["set"]["ua"]), num(&k["version"]), &bytes(&m["set"]["kemPk"]));
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
    assert_eq!((run, sig_level), (63, 5), "{} negatives", arr(&p, "negatives").len()); // + msig-kem-record (T66a)
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
        // a KEM key is refused by the kind alone, the key data unread (CTR-UA-32: an msig holds no KEM key)
        assert_eq!(holder_pop_message(0x0120, &ua, kd, None, None, None, Some(&[0; 1600])).map(|_| ()), Err(UAError::KemHolder(0x0120)));
        assert_eq!(pqz_key_record_message(0x0120, &ua, kd, &pk, None, Some(&proof), false).map(|_| ()), want);
    }
    // no attributes: key data is not consulted; an msig without key data is not a holder
    assert!(holder_pop_message(0x0120, &ua, &[0, 2, 0], None, None, None, None).is_ok());
    assert_eq!(holder_pop_message(0x0120, &ua, &[], Some(&pk), None, Some(&proof), None).map(|_| ()), Err(UAError::PqzHolder(0x0120)));
}

/// The `MemberSig` indexes of an `abi.encode(MemberSig[])` blob, in order.
fn sig_indexes(blob: &[u8]) -> Vec<u16> {
    let list = word_at(blob, 0);
    (0..word_at(blob, list)).map(|i| word_at(blob, list + 32 + word_at(blob, list + 32 + 32 * i)) as u16).collect()
}

/// msig minimal form (owner 2026-10-31; plan U8S-D1): T = the slots' total weight, N = the threshold; T >= N and
/// T - weight(i) < N for every slot. Same table as clientkeys `msigSlotsMinimal`.
#[test]
fn msig_slots_minimal_cases() {
    let kd = |t: u16, w: &[u16]| encode_msig(t, &w.iter().enumerate().map(|(i, w)| (0x0131, [0x10 + i as u8; 32], *w)).collect::<Vec<_>>());
    for (t, w, ix, want) in [
        (2, &[1, 1][..], &[0, 1][..], true),
        (2, &[1, 2], &[0, 1], false),
        (2, &[1, 2], &[1], true),
        (2, &[1, 2], &[0], false),
        (2, &[1, 1], &[], false),
        (2, &[1, 1, 1], &[1, 2], true),
        (2, &[1, 1, 1], &[0, 1, 2], false),
        (3, &[1, 1, 1, 2], &[0, 3], true),
        (3, &[1, 1, 1, 2], &[0, 1, 3], false),
        // a set the registry refuses (unsorted, repeated, out of range) is not minimal
        (2, &[1, 1], &[1, 0], false),
        (2, &[1, 1], &[0, 0], false),
        (2, &[1, 1], &[0, 2], false),
    ] {
        assert_eq!(ua8::msig_slots_minimal(&kd(t, w), ix), Ok(want), "{t}-of-{w:?} {ix:?}");
    }
    assert_eq!(ua8::msig_slots_minimal(&[0, 2, 0], &[0]), Err(UAError::KeyData("length")));
    assert_eq!(ua8::msig_slots_minimal(&kd(2, &[1, 1])[..40], &[0]), Err(UAError::KeyData("length")));
}

#[test]
fn portable_msig_rows_minimal() {
    let p = load("portable.json");
    let kd_of = |ua: &Value| bytes(&find(&p, "registrations", "ua", ua)["keyData"]);
    let mut n = 0;
    for r in arr(&p, "registrations").iter().filter(|r| r["kind"] == 0x0120 && r["pop"] != "0x") {
        assert_eq!(ua8::msig_slots_minimal(&bytes(&r["keyData"]), &sig_indexes(&bytes(&r["pop"]))), Ok(true), "{}", r["name"]);
        n += 1;
    }
    for k in arr(&p, "kemRecords").iter().chain(arr(&p, "pqzKeyRecords")).filter(|k| k["kind"] == 0x0120) {
        assert_eq!(ua8::msig_slots_minimal(&kd_of(&k["ua"]), &sig_indexes(&bytes(&k["sig"]))), Ok(true), "{}", k);
        n += 1;
    }
    assert_eq!(n, 9, "5 pops, 4 PQZ key records (CTR-UA-32: no msig KEM record)");
    // the negative: 2-of-(1, 2) over the registered mldsa65#1 / #2 (lower id weight 1), both slots sign
    let neg = find(&p, "negatives", "name", &"msig-pop-not-minimal".into());
    assert_eq!((&neg["entry"], &neg["rule"], &neg["error"]), (&"register".into(), &"msig-minimal".into(), &"UAPoP".into()));
    let r = &neg["registration"];
    let kd = bytes(&r["keyData"]);
    let mut ids = [&find(&p, "registrations", "name", &"mldsa65#1".into())["ua"], &find(&p, "registrations", "name", &"mldsa65#2".into())["ua"]]
        .map(b32);
    ids.sort();
    assert_eq!(kd, encode_msig(2, &[(0x0131, ids[0], 1), (0x0131, ids[1], 2)]));
    assert_eq!(ua_of(0x0120, &kd).unwrap(), b32(&r["ua"]));
    assert!(arr(&p, "registrations").iter().all(|x| x["ua"] != r["ua"]), "not a registrations[] row");
    let h = register(r, false).unwrap();
    assert_eq!(hx(&h.registration_digest), r["registrationDigest"]);
    assert_eq!(hx(&h.message), r["popMessage"]);
    assert_eq!(h.member_digest.map(|d| hx(&d)), r["memberDigest"].as_str().map(String::from));
    assert_eq!(sig_indexes(&bytes(&r["pop"])), [0, 1]);
    assert_eq!(ua8::msig_slots_minimal(&kd, &[0, 1]), Ok(false));
    assert_eq!(ua8::msig_slots_minimal(&kd, &[1]), Ok(true), "the weight-2 slot alone is the minimal set");
    // the builder never makes a set the registry refuses, as `portableMemberSigs`; the minimal set builds
    let slot = |index| MemberSig { index, members: vec![], sig: vec![1] };
    let input = |members| RegistrationInput { kind: 0x0120, key_data: kd.clone(), members, ..Default::default() };
    assert_eq!(registration_args(&input(vec![slot(0), slot(1)])), Err(UAError::Pop));
    assert!(registration_args(&input(vec![slot(1)])).is_ok());
    assert!(registration_args(&input(vec![])).is_ok(), "an empty pop is a registry rule of its own");
    // the lightest slot is not the first: T - weight(0) = 4 < 5 alone would pass, T - weight(1) = 5 refuses
    let light = bytes(&neg["lightestInMiddle"]["keyData"]);
    assert_eq!(ua8::msig_slots_minimal(&light, &[0, 1, 2]), Ok(false));
    assert_eq!(ua8::msig_slots_minimal(&light, &[0, 2]), Ok(true));
}

// --- typed-signing R1: the registry's explicit arguments (TS-D10 … TS-D12; owner KEM rulings 2026-10-31) ---

fn kem_json(k: &KemKey) -> Value {
    serde_json::json!({ "scheme": k.scheme, "mlkemEk": hx(&k.mlkem_ek), "x25519": hx(&k.x25519) })
}
fn member_sigs_json(m: &[MemberSig]) -> Value {
    let inner = |l: &[ua8::InnerSig]| l.iter().map(|x| serde_json::json!({ "index": x.index, "sig": hx(&x.sig) })).collect::<Vec<_>>();
    Value::Array(m.iter().map(|s| serde_json::json!({ "index": s.index, "members": inner(&s.members), "sig": hx(&s.sig) })).collect())
}
fn attrs_json(a: &UAAttrs) -> Value {
    serde_json::json!({ "pqzKey": hx(&a.pqz_key), "pqzPopHash": hx(&a.pqz_pop_hash), "kem": kem_json(&a.kem), "kemPkHash": hx(&a.kem_pk_hash) })
}
fn args_json(r: &RegisterArgs) -> Value {
    match r {
        RegisterArgs::Register { kind, key_data, attrs, pop, pqz_pop } => serde_json::json!({ "entry": "register", "kind": kind,
            "keyData": hx(key_data), "attrs": attrs_json(attrs), "pqzPop": hx(pqz_pop), "pop": hx(pop) }),
        RegisterArgs::RegisterMsig { structure, attrs, pop, pqz_pop } => serde_json::json!({ "entry": "registerMsig",
            "structure": { "threshold": structure.threshold, "members": structure.members.iter().map(|m| serde_json::json!({
                "kind": m.kind, "id": hx(&m.id), "weight": m.weight })).collect::<Vec<_>>() },
            "attrs": attrs_json(attrs), "pqzPop": hx(pqz_pop), "pop": member_sigs_json(pop) }),
        RegisterArgs::RegisterWebAuthn { key, attrs, pop, pqz_pop } => serde_json::json!({ "entry": "registerWebAuthn",
            "key": { "x": hx(&key.x), "y": hx(&key.y), "rpIdHash": hx(&key.rp_id_hash) },
            "attrs": attrs_json(attrs), "pqzPop": hx(pqz_pop), "pop": hx(pop) }),
        RegisterArgs::RegisterMuSig2 { kind, key, attrs, pop, pqz_pop } => serde_json::json!({ "entry": "registerMuSig2",
            "kind": kind, "key": { "aggKey": hx(&key.agg_key), "memberKeys": key.member_keys.iter().map(|k| hx(k)).collect::<Vec<_>>() },
            "attrs": attrs_json(attrs), "pqzPop": hx(pqz_pop), "pop": hx(pop) }),
        RegisterArgs::RegisterFrost { kind, key, attrs, pop, pqz_pop } => serde_json::json!({ "entry": "registerFrost",
            "kind": kind, "key": { "groupKey": hx(&key.group_key), "threshold": key.threshold, "members": key.members.iter().map(|m| serde_json::json!({
                "commitments": m.commitments.iter().map(|c| hx(c)).collect::<Vec<_>>(), "r": hx(&m.r), "z": hx(&m.z) })).collect::<Vec<_>>() },
            "attrs": attrs_json(attrs), "pqzPop": hx(pqz_pop), "pop": hx(pop) }),
    }
}
fn fill_json(f: &SetKemKeyArgs) -> Value {
    serde_json::json!({ "ua": hx(&f.ua), "version": f.version, "kem": kem_json(&f.kem), "sig": { "keyData": hx(&f.sig.key_data),
        "signature": hx(&f.sig.signature), "members": member_sigs_json(&f.sig.members) } })
}
/// `abi.encode(MemberSig[])` (the vectors' byte form) back to the typed list.
fn member_sigs(blob: &[u8]) -> Vec<MemberSig> {
    if blob.is_empty() {
        return vec![];
    }
    let w = |o: usize| usize::from_be_bytes(blob[o + 24..o + 32].try_into().unwrap());
    let (base, n) = (w(0), w(w(0)));
    (0..n)
        .map(|i| {
            let t = base + 32 + w(base + 32 + 32 * i);
            let field = |k: usize| {
                let o = t + w(t + 32 * k);
                blob[o + 32..o + 32 + w(o)].to_vec()
            };
            MemberSig { index: w(t) as u16, members: vec![], sig: field(2) }
        })
        .collect()
}
fn reg_input(row: &Value) -> RegistrationInput {
    let a = &row["attrs"];
    let kind = num(&row["kind"]) as u16;
    RegistrationInput {
        kind,
        key_data: bytes(&row["keyData"]),
        pqz_key: bytes(&a["pqzKey"]),
        pqz_pop_hash: b32(&a["pqzPopHash"]),
        pqz_pop: bytes(&row["pqzPop"]),
        kem_pk: bytes(&a["kemPk"]),
        pop: if kind == 0x0120 { vec![] } else { bytes(&row["pop"]) },
        members: if kind == 0x0120 { member_sigs(&bytes(&row["pop"])) } else { vec![] },
        kem_commit: None,
        inners: vec![],
    }
}

#[test]
fn registration_args_typed() {
    let p = load("portable.json");
    let mut commits = 0;
    for row in arr(&p, "registrations") {
        let name = row["name"].as_str().unwrap();
        let full = registration_args(&RegistrationInput { kem_commit: Some(false), ..reg_input(row) }).unwrap();
        assert_eq!(args_json(&full.args), row["args"], "{name}");
        assert!(full.kem_fill.is_none(), "{name}");
        let kem = full.args.attrs().kem.clone();
        assert_eq!(hx(&kem.kem_pk()), row["attrs"]["kemPk"].as_str().unwrap(), "{name}: KemKey assembles to kemPk");
        if let RegisterArgs::RegisterMsig { structure, .. } = &full.args {
            assert_eq!(structure.key_data(), bytes(&row["keyData"]), "{name}: the structure is the packed key data");
            assert_eq!(&MsigStructure::from_key_data(&bytes(&row["keyData"])).unwrap(), structure);
        }
        if row.get("kemCommit").is_none() {
            assert!(kem.kem_pk().is_empty(), "{name}");
            continue;
        }
        let c = registration_args(&RegistrationInput { kem_commit: Some(true), ..reg_input(row) }).unwrap();
        assert_eq!(args_json(&c.args), row["kemCommit"]["register"], "{name}");
        assert_eq!(fill_json(c.kem_fill.as_ref().unwrap()), row["kemCommit"]["fill"], "{name}");
        commits += 1;
    }
    assert_eq!(commits, 7); // + mldsa87, fndsa1024; msig-pq/<set> without a KEM key (CTR-UA-32)
    // CTR-UA-32 (T66a): a PQ-eligible msig holds no KEM key, in either form
    let mq = find(&p, "registrations", "name", &"msig-pq/n2048-kmax1024".into());
    let kem_pk = bytes(&arr(&p, "kemRecords")[0]["kemPk"]);
    for kem_commit in [Some(true), Some(false), None] {
        let got = registration_args(&RegistrationInput { kem_pk: kem_pk.clone(), kem_commit, ..reg_input(mq) });
        assert_eq!(got.map(|_| ()), Err(UAError::KemHolder(0x0120)), "{kem_commit:?}");
    }
    for k in arr(&p, "kemRecords") {
        let sig = bytes(&k["sig"]);
        let s = if num(&k["kind"]) == 0x0120 { UASig { members: member_sigs(&sig), ..Default::default() } } else {
            UASig { signature: sig, ..Default::default() }
        };
        let a = SetKemKeyArgs { ua: b32(&k["ua"]), version: num(&k["version"]), kem: KemKey::from_kem_pk(&bytes(&k["kemPk"])).unwrap(), sig: s };
        assert_eq!(fill_json(&a), k["args"]);
    }
    assert_eq!(KemKey::from_kem_pk(&[]).unwrap(), KemKey::default());
    assert!(KemKey::default().kem_pk().is_empty());
    assert_eq!(KemKey::from_kem_pk(&[1; 32]), Err(UAError::KemKeyLength));
}

/// The hash commit only when the full call does not fit one transaction (owner 2026-10-31; X0: PQZH n2560-kmax16384 with a
/// PQZ key and a KEM key): the same figures as clientkeys and ExplicitParamsCalldata.t.sol `test_r1_kemHashCommitFits`.
#[test]
fn registration_hash_commit_when_over_limit() {
    let proof = |set: &str| {
        let path = format!("{}/../../smartcontracts/evm/test/vectors/pqz-gas/{set}.json", env!("CARGO_MANIFEST_DIR"));
        let g: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        num(&g["pqzh"]["REGISTER"]["proof"]) as usize
    };
    let mut kem_pk = vec![0x5a; 1601];
    kem_pk[0] = 1;
    let input = |set: &str, pqz: usize| RegistrationInput {
        kind: 0x0131, key_data: vec![0x5a; 1952], pqz_key: vec![0x5a; pqz], pqz_pop: vec![0x5a; proof(set)],
        kem_pk: kem_pk.clone(), pop: vec![0x5a; 3309], ..Default::default()
    };
    assert_eq!(REGISTER_CALLDATA_LIMIT, 261_909);
    let x = input("n2560-kmax16384", 20480);
    let full = registration_args(&RegistrationInput { kem_commit: Some(false), ..x.clone() }).unwrap();
    assert_eq!(full.args.calldata_len(), 262_116);
    let auto = registration_args(&x).unwrap();
    assert_eq!(auto.args.calldata_len(), 260_548);
    let fill = auto.kem_fill.expect("over the limit: the hash commit");
    assert_eq!(fill.calldata_len(), 2020);
    assert_eq!(fill.kem.kem_pk(), kem_pk);
    assert_eq!(fill.ua, ua_of(0x0131, &x.key_data).unwrap());
    let small = registration_args(&input("n2304-kmax4096", 18432)).unwrap();
    assert!(small.kem_fill.is_none(), "under the limit: the full key");
}

/// PRV L6: the registry's KEM key check runs before a form is chosen: a commit of a malformed key could only revert at its fill.
#[test]
fn registration_refuses_malformed_kem() {
    let p = load("portable.json");
    let row = arr(&p, "registrations").iter().find(|r| r.get("kemCommit").is_some()).unwrap();
    let with = |head: u8, n: usize, kem_commit| {
        let mut kem_pk = vec![0x5a; n];
        kem_pk[0] = head;
        registration_args(&RegistrationInput { kem_pk, kem_commit, ..reg_input(row) }).unwrap_err()
    };
    for commit in [Some(true), Some(false), None] {
        assert_eq!(with(1, 40, commit), UAError::KemKeyLength);
        assert_eq!(with(2, 1601, commit), UAError::KemScheme);
    }
}

/// PRV M1 (owner 2026-11-01, option (a)): a client repairs a front-run hash commit from what it reads.
#[test]
fn kem_repair_fills_a_front_run_commit() {
    let p = load("portable.json");
    let row = arr(&p, "registrations").iter().find(|r| r.get("kemCommit").is_some()).unwrap();
    let (ua, key) = (b32(&row["ua"]), bytes(&row["attrs"]["kemPk"]));
    let (hash, stored, none) = (b32(&row["kemCommit"]["register"]["attrs"]["kemPkHash"]), KemKey::from_kem_pk(&key).unwrap(), KemKey::default());
    assert_eq!(kem_repair(&ua, &[0; 32], &stored, &key).unwrap(), None, "never committed, full key");
    assert_eq!(kem_repair(&ua, &[0; 32], &none, &key).unwrap(), None, "never committed, no key");
    assert_eq!(kem_repair(&ua, &hash, &stored, &key).unwrap(), None, "committed and filled");
    assert_eq!(fill_json(&kem_repair(&ua, &hash, &none, &key).unwrap().unwrap()), row["kemCommit"]["fill"]);
    assert_eq!(kem_repair(&ua, &hash, &none, &[]), Err(UAError::KemKeyLength));
}

/// typed-signing R1b (TS-D13, Appendix X row 12): `webauthn-p256` / MuSig2 / FROST register through `registerWebAuthn` /
/// `registerMuSig2` / `registerFrost` with typed keys that assemble to the packed key data (kinds.json `valid` rows), the
/// calldata lengths cast 1.8.5 gave (no attributes, a 32-byte pop, no pqzPop; as clientkeys and forge
/// `test_registerTypedKeysSameId`); any other single key stays `register`.
#[test]
fn registration_args_typed_keys() {
    let k = load("kinds.json");
    let mut n = 0;
    for v in arr(&k, "valid") {
        let kind = num(&v["kind"]) as u16;
        let (entry, len) = match kind {
            0x0100 => ("registerWebAuthn", 580),
            0x0110 | 0x0112 => ("registerMuSig2", 1124),
            0x0111 | 0x0113 => ("registerFrost", 2308),
            _ => continue,
        };
        let d = bytes(&v["keyData"]);
        let r = registration_args(&RegistrationInput { kind, key_data: d.clone(), pop: vec![0; 32], ..Default::default() }).unwrap();
        assert_eq!(args_json(&r.args)["entry"], entry);
        assert_eq!(r.args.calldata_len(), len, "{}", v["name"]);
        let packed = match &r.args {
            RegisterArgs::RegisterWebAuthn { key, .. } => [key.x, key.y, key.rp_id_hash].concat(),
            RegisterArgs::RegisterMuSig2 { key, .. } => {
                [key.agg_key.clone(), (key.member_keys.len() as u16).to_be_bytes().to_vec(), key.member_keys.concat()].concat()
            }
            RegisterArgs::RegisterFrost { key, .. } => {
                let mut o = [key.group_key.clone(), key.threshold.to_be_bytes().to_vec(), (key.members.len() as u16).to_be_bytes().to_vec()].concat();
                for m in &key.members {
                    o.extend([m.commitments.concat(), m.r.clone(), m.z.to_vec()].concat());
                }
                o
            }
            _ => unreachable!(),
        };
        assert_eq!(packed, d, "{}: the typed key is the packed key data", v["name"]);
        assert_eq!(r.args.key_data(), d);
        n += 1;
    }
    assert_eq!(n, 6);
    let p256 = &arr(&k, "valid")[1];
    let r = registration_args(&RegistrationInput { kind: 0x0101, key_data: bytes(&p256["keyData"]), ..Default::default() }).unwrap();
    assert!(matches!(r.args, RegisterArgs::Register { .. }));
}

// --- the off-chain verifier (ua8-soroban B5, UA8-D24, C14): the relayer's only check of what Soroban stores unverified ---

/// A `kemPk` as `KemKey` fields, whatever its bytes (`KemKey::from_kem_pk` refuses what these tests want refused later).
#[cfg(feature = "pq")]
fn kem_fields(pk: &[u8]) -> KemKey {
    match pk.len() {
        0 => KemKey::default(),
        n => KemKey { scheme: pk[0], mlkem_ek: pk[1..n - 32].to_vec(), x25519: pk[n - 32..].try_into().unwrap() },
    }
}
/// A row's `attrs` in `register`'s form.
#[cfg(feature = "pq")]
fn attrs_of(r: &Value) -> UAAttrs {
    let a = &r["attrs"];
    UAAttrs { pqz_key: bytes(&a["pqzKey"]), pqz_pop_hash: b32(&a["pqzPopHash"]), kem: kem_fields(&bytes(&a["kemPk"])), kem_pk_hash: [0; 32] }
}
/// The registered keys: what a node reads from the registry.
#[cfg(feature = "pq")]
fn keys(p: &Value) -> impl Fn([u8; 32]) -> Option<(u16, Vec<u8>)> + '_ {
    |id| arr(p, "registrations").iter().find(|r| b32(&r["ua"]) == id).map(|r| (num(&r["kind"]) as u16, bytes(&r["keyData"])))
}
#[cfg(feature = "pq")]
fn check_row(p: &Value, r: &Value) -> Result<()> {
    check_registration(num(&r["kind"]) as u16, &bytes(&r["keyData"]), &attrs_of(r), &bytes(&r["pop"]), &bytes(&r["pqzPop"]), &keys(p))
}
/// `kem_record` / `pqz_record` of a row, `sig` and the registration of `ua` given (a negative changes them).
#[cfg(feature = "pq")]
fn check_kem(p: &Value, k: &Value, ua: &Value, sig: &[u8]) -> Result<()> {
    let reg = find(p, "registrations", "ua", ua);
    check_kem_record(num(&reg["kind"]) as u16, &bytes(&reg["keyData"]), &b32(ua), num(&k["version"]), &bytes(&k["kemPk"]), sig, &keys(p))
}
#[cfg(feature = "pq")]
fn check_pqz(p: &Value, k: &Value, ua: &Value, hash: &Value, sig: &[u8]) -> Result<()> {
    let reg = find(p, "registrations", "ua", ua);
    check_pqz_key_record(num(&reg["kind"]) as u16, &bytes(&reg["keyData"]), &b32(ua), &bytes(&k["pqzKey"]), &b32(hash), sig, &keys(p))
}
/// `pop` with one bit flipped inside a signature (first, middle, last byte): never in the ABI of an msig blob, so the refusal
/// is the signature's and not the decoder's.
#[cfg(feature = "pq")]
fn flipped(kind: u16, sig: &[u8]) -> Vec<Vec<u8>> {
    let flip = |s: &[u8], i: usize| {
        let mut s = s.to_vec();
        s[i] ^= 1;
        s
    };
    if kind != 0x0120 {
        return [0, sig.len() / 2, sig.len() - 1].iter().map(|i| flip(sig, *i)).collect();
    }
    let m = decode_member_sigs(sig).expect("a vector's blob is canonical");
    assert_eq!(encode_member_sigs(&m), sig, "the encoder is the decoder's inverse");
    let mut out = vec![];
    for slot in 0..m.len() {
        for i in [0, m[slot].sig.len() / 2, m[slot].sig.len() - 1] {
            let mut x = m.clone();
            x[slot].sig = flip(&x[slot].sig, i);
            out.push(encode_member_sigs(&x));
        }
    }
    out
}

#[cfg(feature = "pq")]
#[test]
fn check_registration_vectors() {
    let p = load("portable.json");
    let (mut n, mut flips, mut commits) = (0, 0, 0);
    for r in arr(&p, "registrations") {
        let (name, kind, kd) = (&r["name"], num(&r["kind"]) as u16, bytes(&r["keyData"]));
        let (attrs, pop, proof) = (attrs_of(r), bytes(&r["pop"]), bytes(&r["pqzPop"]));
        assert_eq!(check_row(&p, r), Ok(()), "{name}");
        assert_eq!(check_registration(kind, &kd, &attrs, &pop, &[], &keys(&p)), Ok(()), "{name}: the proof bytes are optional");
        if !pop.is_empty() {
            for bad in flipped(kind, &pop) {
                assert_eq!(check_registration(kind, &kd, &attrs, &bad, &proof, &keys(&p)), Err(UAError::Pop), "{name}");
                flips += 1;
            }
        }
        if kind != 0x0120 {
            for bad in [&pop[..pop.len() - 1], &[&pop[..], &[0]].concat()] {
                assert_eq!(check_registration(kind, &kd, &attrs, bad, &proof, &keys(&p)), Err(UAError::Pop), "{name}: a byte off");
            }
        }
        if let Some(c) = r.get("kemCommit") {
            let (a, h) = (&c["register"]["attrs"], b32(&c["register"]["attrs"]["kemPkHash"]));
            assert_eq!(h, keccak256(&bytes(&r["attrs"]["kemPk"])), "{name}");
            let commit = UAAttrs { kem: KemKey { scheme: num(&a["kem"]["scheme"]) as u8, ..Default::default() }, kem_pk_hash: h, ..attrs.clone() };
            let try_attrs = |x: &UAAttrs| check_registration(kind, &kd, x, &pop, &proof, &keys(&p));
            assert_eq!(try_attrs(&commit), Ok(()), "{name}: the same pop signs the hash commit");
            let mut other = commit.clone();
            other.kem_pk_hash[0] ^= 1;
            assert_eq!(try_attrs(&other), Err(UAError::Pop), "{name}: another key's commit");
            let bad = |f: &dyn Fn(&mut UAAttrs)| {
                let mut x = commit.clone();
                f(&mut x);
                try_attrs(&x)
            };
            assert_eq!(bad(&|x| x.kem.scheme = 2), Err(UAError::KemScheme), "{name}");
            assert_eq!(bad(&|x| x.kem.scheme = 0), Err(UAError::KemScheme), "{name}");
            assert_eq!(bad(&|x| x.kem.mlkem_ek = vec![1]), Err(UAError::KemKeyLength), "{name}: key bytes next to the hash");
            assert_eq!(bad(&|x| x.kem.x25519 = [1; 32]), Err(UAError::KemKeyLength), "{name}: key bytes next to the hash");
            commits += 1;
        }
        n += 1;
    }
    assert_eq!((n, commits), (27, 7)); // CTR-UA-32: msig-pq/<set> without a KEM key
    println!("{n} registrations, {commits} hash commits, {flips} flipped signatures refused");
}

#[cfg(feature = "pq")]
#[test]
fn check_kem_record_vectors() {
    let p = load("portable.json");
    let mut flips = 0;
    for k in arr(&p, "kemRecords") {
        let (id, kind, sig) = (&k["id"], num(&k["kind"]) as u16, bytes(&k["sig"]));
        assert_eq!(check_kem(&p, k, &k["ua"], &sig), Ok(()), "{id}");
        for bad in flipped(kind, &sig) {
            assert_eq!(check_kem(&p, k, &k["ua"], &bad), Err(UAError::Unauthorized), "{id}");
            flips += 1;
        }
        let reg = find(&p, "registrations", "ua", &k["ua"]);
        let (kd, ua, pk) = (bytes(&reg["keyData"]), b32(&k["ua"]), bytes(&k["kemPk"]));
        let v = num(&k["version"]);
        let at = |ua: &[u8; 32], v: u64, pk: &[u8]| check_kem_record(kind, &kd, ua, v, pk, &sig, &keys(&p));
        assert_eq!(at(&ua, v, &pk), Ok(()), "{id}: the control");
        assert_eq!(at(&ua, v + 3, &pk), Err(UAError::Unauthorized), "{id}: signed for another version");
        assert_eq!(at(&ua, 0, &pk), Err(UAError::KemVersion), "{id}: version 0 is register's");
        assert_eq!(at(&ua, v, &pk[..1600]), Err(UAError::KemKeyLength), "{id}");
        assert_eq!(at(&ua, v, &[]), Err(UAError::KemKeyLength), "{id}");
        assert_eq!(at(&ua, v, &[&[2u8][..], &pk[1..]].concat()), Err(UAError::KemScheme), "{id}");
    }
    // not a holder: a valid signature cannot reach the signature check
    let s = find(&p, "registrations", "name", &"slhdsa128s".into());
    let pk = bytes(&arr(&p, "kemRecords")[0]["kemPk"]);
    let got = check_kem_record(0x0133, &bytes(&s["keyData"]), &b32(&s["ua"]), 1, &pk, &[0; 7856], &keys(&p));
    assert_eq!(got, Err(UAError::KemHolder(0x0133)));
    // one field off: `ua` is not this key's id. Key K must not sign for a victim's `ua`; a non-holder key, so that without the id
    // compare this is `KemHolder`, which a signature mismatch could not hide
    let got = check_kem_record(0x0133, &bytes(&s["keyData"]), &[9; 32], 1, &pk, &[0; 7856], &keys(&p));
    assert_eq!(got, Err(UAError::Unauthorized), "not the key data's id");
    assert_eq!(flips, 3 * 12, "3 per signature: 12 single keys (CTR-UA-32: no msig KEM record)");
    println!("12 KEM records, {flips} flipped signatures refused");
}

#[cfg(feature = "pq")]
/// Group 3g: portable.json `pqzKeyVersions` by digest, message and verdict; the builder's refusals on `pqzKeyVersionNegatives`.
#[test]
fn pqz_key_version_vectors() {
    let p = load("portable.json");
    let vers = arr(&p, "pqzKeyVersions");
    assert_eq!(vers.len(), 16);
    let stored = |r: &Value, versions: &[u64]| -> Vec<(u64, [u8; 32])> {
        let name = r["name"].as_str().unwrap();
        let (base, set) = (name.split('/').next().unwrap(), r["set"].as_str().unwrap());
        versions.iter().map(|&v| {
            let row = if v == 0 {
                find(&p, "pqzKeyRecords", "name", &format!("{base}/{set}").into())
            } else {
                find(&p, "pqzKeyVersions", "name", &format!("{base}/v{v}/{set}").into())
            };
            (v, b32(&row["pqzKeyHash"]))
        }).collect()
    };
    for r in vers {
        let (name, kind, ua, h, v) = (&r["name"], num(&r["kind"]) as u16, b32(&r["ua"]), b32(&r["pqzPopHash"]), num(&r["version"]));
        let kd = bytes(&find(&p, "registrations", "ua", &r["ua"])["keyData"]);
        let held = stored(r, if v == 2 { &[0, 1] } else { &[0] });
        let g = pqz_key_version_record_message(kind, &ua, &kd, v, &bytes(&r["pqzKey"]), None, Some(&h), &held, &|_| None).unwrap();
        assert_eq!(hx(&g.pqz_key_hash), r["pqzKeyHash"], "{name}");
        assert_eq!(hx(&g.version_digest), r["versionDigest"], "{name}");
        assert_eq!(hx(&g.record_digest), r["recordDigest"], "{name}");
        assert_eq!(hx(&g.message), r["message"], "{name}");
        assert_eq!(hx(&g.pqz_reg_message), r["pqzRegMessage"], "{name}");
        assert_eq!(g.member_digest.map(|m| hx(&m)).map(Value::from).unwrap_or(Value::Null), r["memberDigest"], "{name}");
        assert_eq!(pqz_key_version_digest(&ua, v, &g.pqz_key_hash), g.version_digest);
        let sig = bytes(&r["sig"]);
        assert_eq!(check_pqz_key_version_record(kind, &kd, &ua, v, &bytes(&r["pqzKey"]), &h, &sig, &keys(&p)), Ok(()), "{name}: the control");
        assert_eq!(check_pqz_key_version_record(kind, &kd, &ua, v + 1, &bytes(&r["pqzKey"]), &h, &sig, &keys(&p)), Err(UAError::Unauthorized), "{name}: another version");
        assert_eq!(check_pqz_key_version_record(kind, &kd, &ua, 0, &bytes(&r["pqzKey"]), &h, &sig, &keys(&p)), Err(UAError::PqzKeySet), "{name}: version 0");
    }
    let (mut builder, mut verdict) = (0, 0);
    for x in arr(&p, "pqzKeyVersionNegatives") {
        let (name, m) = (&x["name"], &x["mutation"]);
        let r = find(&p, "pqzKeyVersions", "name", &m["row"]);
        let (kind, h, v) = (num(&r["kind"]) as u16, b32(&r["pqzPopHash"]), num(&r["version"]));
        let kd = bytes(&find(&p, "registrations", "ua", &r["ua"])["keyData"]);
        if x["error"] == "UAUnauthorized" {
            let ua = if m["set"]["ua"].is_string() { b32(&m["set"]["ua"]) } else { b32(&r["ua"]) };
            let reg = find(&p, "registrations", "ua", &hx(&ua).into());
            let sig = if m["set"]["sig"].is_string() { bytes(&m["set"]["sig"]) } else { bytes(&r["sig"]) };
            let got = check_pqz_key_version_record(num(&reg["kind"]) as u16, &bytes(&reg["keyData"]), &ua, v, &bytes(&r["pqzKey"]), &h, &sig, &keys(&p));
            assert_eq!(got, Err(UAError::Unauthorized), "{name}");
            verdict += 1;
            continue;
        }
        let versions: Vec<u64> = m["stored"].as_array().unwrap().iter().map(|n| n.as_u64().unwrap()).collect();
        let key = if m["set"]["pqzKey"].is_string() { bytes(&m["set"]["pqzKey"]) } else { bytes(&r["pqzKey"]) };
        let got = pqz_key_version_record_message(kind, &b32(&r["ua"]), &kd, v, &key, None, Some(&h), &stored(r, &versions), &|_| None);
        assert_eq!(got.unwrap_err().code(), x["error"], "{name}");
        builder += 1;
    }
    assert_eq!((builder, verdict), (16, 12));
}

#[cfg(feature = "pq")]
#[test]
fn check_pqz_key_record_vectors() {
    let p = load("portable.json");
    let mut flips = 0;
    for k in arr(&p, "pqzKeyRecords") {
        let (name, kind, sig) = (&k["name"], num(&k["kind"]) as u16, bytes(&k["sig"]));
        assert_eq!(check_pqz(&p, k, &k["ua"], &k["pqzPopHash"], &sig), Ok(()), "{name}");
        for bad in flipped(kind, &sig) {
            assert_eq!(check_pqz(&p, k, &k["ua"], &k["pqzPopHash"], &bad), Err(UAError::Unauthorized), "{name}");
            flips += 1;
        }
        let reg = find(&p, "registrations", "ua", &k["ua"]);
        let (kd, ua, key, h) = (bytes(&reg["keyData"]), b32(&k["ua"]), bytes(&k["pqzKey"]), b32(&k["pqzPopHash"]));
        let at = |ua: &[u8; 32], key: &[u8], h: &[u8; 32]| check_pqz_key_record(kind, &kd, ua, key, h, &sig, &keys(&p));
        assert_eq!(at(&ua, &key, &h), Ok(()), "{name}: the control");
        let mut other = h;
        other[0] ^= 1;
        assert_eq!(at(&ua, &key, &other), Err(UAError::Unauthorized), "{name}: another proof's hash");
        assert_eq!(at(&ua, &key, &[0; 32]), Err(UAError::PqzPopHash), "{name}");
        assert_eq!(at(&ua, &key[..32], &h), Err(UAError::KeyData("PQZ key length")), "{name}");
        let mut swapped = key.clone();
        swapped[0] ^= 1;
        assert_eq!(at(&ua, &swapped, &h), Err(UAError::Unauthorized), "{name}: pqzKeyHash = keccak(PQZ_KEY_GROUP ‖ key)");
    }
    // the id compare, as in check_kem_record_vectors: the control first, then one field off (without the compare: `PqzHolder`)
    let (s, k) = (find(&p, "registrations", "name", &"slhdsa128s".into()), &arr(&p, "pqzKeyRecords")[0]);
    let at = |ua: &[u8; 32]| check_pqz_key_record(0x0133, &bytes(&s["keyData"]), ua, &bytes(&k["pqzKey"]), &b32(&k["pqzPopHash"]), &[0; 7856], &keys(&p));
    assert_eq!(at(&b32(&s["ua"])), Err(UAError::PqzHolder(0x0133)));
    assert_eq!(at(&[9; 32]), Err(UAError::Unauthorized), "not the key data's id");
    println!("16 PQZ key records, {flips} flipped signatures refused");
}

/// Every `negatives[]` row, by its exact error (Rust and clientkeys `verify*` take the same rows). What a stateless check
/// cannot see is counted and pinned as accepted: `pqz-key-record-already-set` is write-once state, the chain's `PqzKeySet`.
#[cfg(feature = "pq")]
#[test]
fn check_refuses_negatives() {
    let p = load("portable.json");
    let (mut refused, mut stateful, mut other_entry) = (0, 0, 0);
    let code = |r: Result<()>| r.err().map(|e| e.code());
    for n in arr(&p, "negatives") {
        let (name, err) = (n["name"].as_str().unwrap(), n["error"].as_str().unwrap());
        if n["rule"] == "msig-minimal" {
            // every slot verifies and the threshold is met: only the minimal rule can refuse it
            let r = &n["registration"];
            let (kd, slots) = (MsigStructure::from_key_data(&bytes(&r["keyData"])).unwrap(), decode_member_sigs(&bytes(&r["pop"])).unwrap());
            let md = b32(&r["memberDigest"]);
            let mt = purpose_tag("member").unwrap();
            for s in &slots {
                let m = &kd.members[s.index as usize];
                let key = keys(&p)(m.id).unwrap().1;
                assert!(verify::verify(m.kind, &key, &ua_message(m.kind, &mt, &md).unwrap(), &s.sig, false), "{name}: slot {}", s.index);
            }
            assert_eq!(code(check_row(&p, r)), Some(err), "{name}");
            refused += 1;
            continue;
        }
        let m = &n["mutation"];
        let set = &m["set"];
        match n["entry"].as_str().unwrap() {
            "register" | "storePqzPop" => {
                let mut row = find(&p, "registrations", "name", &m["row"]).clone();
                for (k, v) in set.as_object().unwrap() {
                    match k.strip_prefix("attrs.") {
                        Some(f) => row["attrs"][f] = v.clone(),
                        None => row[k] = v.clone(),
                    }
                }
                assert_eq!(code(check_row(&p, &row)), Some(err), "{name}");
                refused += 1;
            }
            "setPqzKey" => {
                let k = find(&p, "pqzKeyRecords", "name", &m["row"]);
                let (ua, hash) = (set.get("ua").unwrap_or(&k["ua"]), set.get("pqzPopHash").unwrap_or(&k["pqzPopHash"]));
                let got = check_pqz(&p, k, ua, hash, &bytes(set.get("sig").unwrap_or(&k["sig"])));
                if err == "UAPqzKeySet" {
                    assert_eq!(got, Ok(()), "{name}: the signature is good, the chain's state refuses");
                    stateful += 1;
                } else {
                    assert_eq!(code(got), Some(err), "{name}");
                    refused += 1;
                }
            }
            "setKemKey" => {
                let mut k = find(&p, "kemRecords", "id", &m["row"]).clone();
                if let Some(pk) = set.get("kemPk") {
                    k["kemPk"] = pk.clone();
                }
                if err == "UAKemHolder" {
                    // CTR-UA-32: every slot of the msig signs its own record, so only the holder rule can refuse it
                    let ua = b32(&set["ua"]);
                    let d = kem_record_digest(&ua, num(&k["version"]), &bytes(&k["kemPk"])).unwrap();
                    let md = member_digest(&ua, &ua_message(0x0120, &purpose_tag("kem").unwrap(), &d).unwrap());
                    let kd = MsigStructure::from_key_data(&bytes(&find(&p, "registrations", "ua", &set["ua"])["keyData"])).unwrap();
                    for s in decode_member_sigs(&bytes(&set["sig"])).unwrap() {
                        let mm = &kd.members[s.index as usize];
                        let msg = ua_message(mm.kind, &purpose_tag("member").unwrap(), &md).unwrap();
                        assert!(verify::verify(mm.kind, &keys(&p)(mm.id).unwrap().1, &msg, &s.sig, false), "{name}: slot {}", s.index);
                    }
                }
                let got = check_kem(&p, &k, set.get("ua").unwrap_or(&k["ua"]), &bytes(set.get("sig").unwrap_or(&k["sig"])));
                assert_eq!(code(got), Some(err), "{name}");
                refused += 1;
            }
            "requireAuthorized" => other_entry += 1, // a transaction authorisation: no stored record, nothing to check here
            e => panic!("{name}: {e}"),
        }
    }
    assert_eq!((refused, stateful, other_entry), (64, 4, 1), "{} negatives", arr(&p, "negatives").len()); // + msig-kem-record (T66a)
    println!("{refused} negatives refused by their error, {stateful} state-only, {other_entry} not a record");
}

/// CTR-UA-37, the relayer's check before it attests a slot the chain cannot read: every `memberships` row passes, one change each refuses.
#[cfg(feature = "pq")]
#[test]
fn check_membership_rows() {
    let p = load("portable.json");
    for r in arr(&p, "memberships") {
        let d = bytes(&find(&p, "registrations", "name", &r["msig"])["keyData"]);
        let ua = b32(&r["ua"]);
        let index = r["index"].as_u64().unwrap() as u16;
        let slot = MemberSig { index, members: vec![], sig: bytes(&r["sig"]) };
        let check = |d: &[u8], ua: &[u8; 32], s: &MemberSig| check_membership(d, ua, s, &keys(&p));
        assert_eq!(check(&d, &ua, &slot), Ok(()), "{}", r["name"]);
        let mut flipped = slot.clone();
        flipped.sig[3] ^= 1;
        assert_eq!(check(&d, &ua, &flipped), Err(UAError::Unauthorized), "{}", r["name"]);
        assert_eq!(check(&d, &ua, &MemberSig { members: vec![ua8::InnerSig::default()], ..slot.clone() }), Err(UAError::Unauthorized), "{}", r["name"]);
        assert_eq!(check(&d, &ua, &MemberSig { index: 9, ..slot.clone() }), Err(UAError::Unauthorized), "past the members");
        let other = MemberSig { index: if index == 0 { 1 } else { 0 }, ..slot.clone() };
        assert_eq!(check(&d, &ua, &other), Err(UAError::Unauthorized), "{}: another slot's member", r["name"]);
        assert_eq!(check(&d, &[1; 32], &slot), Err(UAError::Unauthorized), "another id");
        let mut other = d.clone();
        other[1] = 1; // the same members under another threshold: the signature is over `ua`, the structure is not its
        assert_eq!(check(&other, &ua, &slot), Err(UAError::Unauthorized), "the key data of another id");
    }
    let r = &arr(&p, "memberships")[0];
    let d = bytes(&find(&p, "registrations", "name", &r["msig"])["keyData"]);
    let contract = [&d[..4], &[0, 2], &d[6..]].concat();
    let ua = ua_of(0x0120, &contract).unwrap();
    let slot = MemberSig { index: 0, members: vec![], sig: bytes(&r["sig"]) };
    assert_eq!(check_membership(&contract, &ua, &slot, &keys(&p)), Err(UAError::NotVerifiable), "ERC-1271 runs nowhere here");
    assert_eq!(check_membership(&d, &b32(&r["ua"]), &MemberSig { index: 0, ..slot }, &|_| None), Err(UAError::MemberUnknown));
}

/// `check_*` fail closed: each case is one field off a row that passes (the first assert of each block).
#[cfg(feature = "pq")]
#[test]
fn check_fails_closed() {
    let p = load("portable.json");
    let row = |n: &str| find(&p, "registrations", "name", &n.into()).clone();
    let (none, q, native, classical) = (UAAttrs::default(), row("msig-pq/n2048-kmax1024"), row("msig-pq-native"), row("msig-classical"));
    let (qk, qa, qp, qz) = (bytes(&q["keyData"]), attrs_of(&q), bytes(&q["pop"]), bytes(&q["pqzPop"]));
    let on = |pop: &[u8]| check_registration(0x0120, &qk, &qa, pop, &qz, &keys(&p));
    let res = |kd: &[u8], pop: &[u8]| check_registration(0x0120, kd, &none, pop, &[], &keys(&p));

    // kinds: unknown, native, the PQZ scheme
    let m = row("mldsa65#1");
    let (mk, mp) = (bytes(&m["keyData"]), bytes(&m["pop"]));
    assert_eq!(check_registration(0x0131, &mk, &none, &mp, &[], &keys(&p)), Ok(()));
    for (kind, e) in [(0x0199, UAError::KindUnknown(0x0199)), (0x0001, UAError::KindNotDerived(0x0001)), (0x0142, UAError::KindNotDerived(0x0142))] {
        assert_eq!(check_registration(kind, &mk, &none, &mp, &[], &keys(&p)), Err(e));
        assert_eq!(check_kem_record(kind, &mk, &[1; 32], 1, &[1; 1601], &mp, &keys(&p)), Err(e));
        assert_eq!(check_pqz_key_record(kind, &mk, &[1; 32], &[1; 16384], &[1; 32], &mp, &keys(&p)), Err(e));
    }
    assert_eq!(check_registration(0x0131, &mk, &none, &[], &[], &keys(&p)), Err(UAError::Pop), "a single key's empty pop");

    // an evm-contract slot has no off-chain ERC-1271 check; a member that is no slot signs nothing
    let (nk, np) = (bytes(&native["keyData"]), bytes(&native["pop"]));
    assert_eq!(res(&nk, &np), Ok(()));
    assert_eq!(u16::from_be_bytes([nk[4], nk[5]]), 0x0001);
    let contract = |d: &[u8]| [&d[..4], &[0, 2], &d[6..]].concat();
    assert_eq!(res(&contract(&nk), &np), Err(UAError::NotVerifiable));
    let ck = bytes(&classical["keyData"]);
    assert_eq!(res(&ck, &[]), Ok(()));
    assert_eq!(u16::from_be_bytes([ck[4], ck[5]]), 0x0001);
    assert_eq!(res(&contract(&ck), &[]), Ok(()), "classical-dominant: no slot, no pop");
    assert_eq!(res(&ck, &[0; 64]), Err(UAError::Pop), "classical-dominant: an empty pop, U8S-D2");

    // members: unknown, another kind, another key under the id, a key that is not canonical but hashes to the id
    let ids: Vec<[u8; 32]> = MsigStructure::from_key_data(&qk).unwrap().members.iter().map(|m| m.id).collect();
    let via = |f: &dyn Fn([u8; 32]) -> Option<(u16, Vec<u8>)>| check_registration(0x0120, &qk, &qa, &qp, &qz, f);
    let good = keys(&p);
    assert_eq!(on(&qp), Ok(()));
    assert_eq!(via(&|id| if id == ids[0] { good(id) } else { None }), Err(UAError::MemberUnknown), "unresolved");
    assert_eq!(via(&|id| if id == ids[0] { good(id) } else { Some((0x0130, good(id)?.1)) }), Err(UAError::MemberUnknown), "kind");
    assert_eq!(via(&|id| if id == ids[0] { good(id) } else { good(ids[0]) }), Err(UAError::MemberUnknown), "another key");
    assert_eq!(check_registration(0x0120, &ck, &none, &[], &[], &|_| None), Err(UAError::MemberUnknown), "no slots: still resolved");
    let junk = vec![7u8; 100];
    let id = ua_of(0x0131, &junk).unwrap();
    let got = check_registration(0x0120, &encode_msig(1, &[(0x0131, id, 1)]), &none, &[], &[], &|_| Some((0x0131, junk.clone())));
    assert_eq!(got, Err(UAError::MemberUnknown), "the id matches, the key is no key");

    // the blob
    let slots = decode_member_sigs(&qp).unwrap();
    let enc = |s: &[MemberSig]| encode_member_sigs(s);
    assert_eq!(on(&enc(&slots)), Ok(()));
    let pad = [&qp[..], &[0u8; 32]].concat();
    assert_eq!(decode_member_sigs(&pad), None);
    assert_eq!(on(&pad), Err(UAError::Pop), "trailing bytes");
    assert_eq!(on(&[]), Err(UAError::Pop), "no slots");
    assert_eq!(on(&[[0u8; 31].as_slice(), &[32], &[0; 32]].concat()), Err(UAError::Pop), "abi.encode of no slots");
    assert!(enc(&[]).is_empty(), "no slots is the empty blob, as the registries and clientkeys");
    let mut with_list = slots.clone();
    with_list[0].members = vec![ua8::InnerSig::default()];
    assert_eq!(on(&enc(&with_list)), Err(UAError::Pop), "a list is an msig member's");
    let mut swapped = slots.clone();
    swapped.swap(0, 1);
    assert_eq!(on(&enc(&swapped)), Err(UAError::Pop), "order");
    assert_eq!(on(&enc(&[slots[0].clone(), slots[0].clone()])), Err(UAError::Pop), "repeated");
    assert_eq!(on(&enc(&slots[..1])), Err(UAError::Pop), "below the threshold");
    let mut past = slots.clone();
    past[1].index = 2;
    assert_eq!(on(&enc(&past)), Err(UAError::Pop), "past the members");

    // a native member: over the typed digest only, low s
    let ns = decode_member_sigs(&np).unwrap();
    let eoa = ns.iter().position(|s| s.sig.len() == 65).unwrap();
    let with_sig = |sig: Vec<u8>| {
        let mut x = ns.clone();
        x[eoa].sig = sig;
        res(&nk, &enc(&x))
    };
    assert_eq!(with_sig(ns[eoa].sig.clone()), Ok(()));
    assert_eq!(with_sig(high_s(&ns[eoa].sig)), Err(UAError::Pop), "the same point with the other s");
    let mut v = ns[eoa].sig.clone();
    v[64] += 2;
    assert_eq!(with_sig(v), Err(UAError::Pop), "v 29 / 30");

    // the proof hash binds the key, not the bytes offered next to it (the digest helpers derive it from the bytes)
    let mut x = qa.clone();
    x.pqz_pop_hash = [0; 32];
    assert_eq!(check_registration(0x0120, &qk, &x, &qp, &qz, &keys(&p)), Err(UAError::PqzPopHash), "a key without its hash");
    let plain = row("fndsa512");
    let mut y = attrs_of(&plain);
    assert_eq!(check_row(&p, &plain), Ok(()));
    // Falcon: exactly the 666 padded bytes (PQClean alone also takes the signature without its padding)
    let fp = bytes(&plain["pop"]);
    let stripped = &fp[..fp.iter().rposition(|b| *b != 0).unwrap() + 1];
    assert!(stripped.len() < 666);
    assert_eq!(check_registration(0x0132, &bytes(&plain["keyData"]), &attrs_of(&plain), stripped, &[], &keys(&p)), Err(UAError::Pop), "padding stripped");
    y.pqz_pop_hash = keccak256(&qz);
    assert_eq!(check_registration(0x0132, &bytes(&plain["keyData"]), &y, &bytes(&plain["pop"]), &qz, &keys(&p)), Err(UAError::PqzPopHash), "a hash without a key");
    let commit = UAAttrs { kem: KemKey { scheme: 1, ..Default::default() }, kem_pk_hash: [1; 32], ..Default::default() };
    assert_eq!(check_registration(0x0133, &bytes(&row("slhdsa128s")["keyData"]), &commit, &[], &[], &keys(&p)), Err(UAError::KemHolder(0x0133)), "a commit needs a holder");
}

/// The default build has no PQ verifier: a PQ signature is refused, never taken as checked, a classical one still verifies.
#[cfg(not(feature = "pq"))]
#[test]
fn check_without_pq_refuses_pq_kinds() {
    let p = load("portable.json");
    let res = |n: &str| {
        let r = find(&p, "registrations", "name", &n.into());
        check_registration(num(&r["kind"]) as u16, &bytes(&r["keyData"]), &UAAttrs::default(), &bytes(&r["pop"]), &[], &|_| None)
    };
    assert_eq!(res("p256"), Ok(()));
    for n in ["mldsa44", "mldsa65#1", "slhdsa128s"] {
        assert_eq!(res(n), Err(UAError::Pop), "{n}");
    }
}

/// `r ‖ (n − s) ‖ v'`: the other signature of the same key and digest.
#[cfg(feature = "pq")]
fn high_s(sig: &[u8]) -> Vec<u8> {
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf,
        0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    ];
    let mut out = sig.to_vec();
    let mut borrow = 0i32;
    for i in (0..32).rev() {
        let d = N[i] as i32 - sig[32 + i] as i32 - borrow;
        out[32 + i] = d.rem_euclid(256) as u8;
        borrow = (d < 0) as i32;
    }
    out[64] ^= 27 ^ 28;
    out
}

/// `kinds.json` `invalid[]`: Soroban stores a relayer-checked kind's key data on length alone, so a relayer that attested one
/// would put an invalid key on chain (B4 report: 75 of these rows). Each is refused by its error, an empty `pop` never
/// reached; `valid[]` is the control (the same check reaches the signature, `UAPoP`).
#[cfg(feature = "pq")]
#[test]
fn check_refuses_invalid_keys() {
    let k = load("kinds.json");
    let none = UAAttrs::default();
    let res = |r: &Value| check_registration(num(&r["kind"]) as u16, &bytes(&r["keyData"]), &none, &[0; 64], &[], &|_| None);
    for r in arr(&k, "invalid") {
        assert_eq!(res(r).err().map(|e| e.code()), r["error"].as_str(), "{r}");
    }
    for r in arr(&k, "valid").iter().filter(|r| r["kind"] != 0x0120) {
        assert_eq!(res(r), Err(UAError::Pop), "{r}");
    }
    println!("{} invalid key rows refused", arr(&k, "invalid").len());
}

/// Group kinds 0x0110–0x0113: the whole group check (`verify` with `pop`) over the portable message; clientkeys has no
/// verifier for them and refuses (`UANotVerifiable`, the report's C14 list).
#[cfg(feature = "pq")]
#[test]
fn check_group_kinds() {
    let g = load("groups.json");
    let mut n = 0;
    for r in arr(&g, "groups") {
        let (kind, kd, blob) = (num(&r["kind"]) as u16, bytes(&r["keyData"]), bytes(&r["pop"]["blob"]));
        let got = |pop: &[u8]| check_registration(kind, &kd, &UAAttrs::default(), pop, &[], &|_| None);
        assert_eq!(got(&blob), Ok(()), "{}", r["name"]);
        let mut bad = blob.clone();
        bad[blob.len() / 2] ^= 1;
        assert_eq!(got(&bad), Err(UAError::Pop), "{}", r["name"]);
        n += 1;
    }
    assert_eq!(n, 20);
}
