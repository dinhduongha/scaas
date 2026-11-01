//! `scaas_ua::pq` (feature `pq`: ml-dsa, slh-dsa, pqcrypto-falcon) against the PQ vectors of smartcontracts/vectors/ua: the
//! deterministic keys and signatures of pq_kat.json with their mutations, the published vectors of pq_external.json (ACVP,
//! the EIP-8051 / EIP-8355 rows, Falcon KATs) and pq_signatures.json. Every vector was written by noble (or imported and
//! re-checked with it), so a pass here means two implementations agree; a kind whose crate disagrees would be refused by
//! `pq::verify` (C14); none does.
use scaas_ua::pq;
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
fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array().unwrap()
}
const KINDS: [(&str, u16); 4] = [("mldsa44", 0x0130), ("mldsa65", 0x0131), ("fndsa512", 0x0132), ("slhdsa128s", 0x0133)];

#[test]
fn pq_kat_verifies() {
    let v = load("pq_kat.json");
    let mut mutations = 0;
    for (name, kind) in KINDS {
        let k = &v["kinds"][name];
        let (pk, msg, sig) = (bytes(&k["pk"]), b32(&k["ua_msg"]), bytes(&k["sig"]));
        assert_eq!(pq::signed_message(kind, &msg), bytes(&k["signed_message"]), "{name}");
        assert!(pq::verify(kind, &pk, &msg, &sig), "{name}");
        // another kind's key length, another kind's tag: never accepted
        for (other, okind) in KINDS.into_iter().filter(|(_, o)| *o != kind) {
            assert!(!pq::verify(okind, &pk, &msg, &sig), "{name} as {other}");
        }
        for m in arr(k, "mutations") {
            let got = pq::verify(kind, &bytes(&m["pk"]), &b32(&m["ua_msg"]), &bytes(&m["sig"]));
            assert_eq!(got, m["valid"].as_bool().unwrap(), "{name}: {}", m["what"]);
            mutations += 1;
        }
    }
    assert_eq!(mutations, 30);
    println!("4 kinds, {mutations} mutations refused");
}

/// `kind` of a parameter-set name or, for the EIP rows, of the key's length.
fn kind_of(c: &Value) -> u16 {
    match c["set"].as_str() {
        Some("ML-DSA-44") => 0x0130,
        Some("ML-DSA-65") => 0x0131,
        Some("SLH-DSA-SHA2-128s") => 0x0133,
        Some(s) => panic!("{s}"),
        None => match bytes(&c["pk"]).len() {
            1312 => 0x0130,
            1952 => 0x0131,
            n => panic!("key of {n} B"),
        },
    }
}

/// Published vectors over `M'`, the message the FIPS core verifies (the path `pq::verify` itself takes).
#[test]
fn pq_external_verifies() {
    let v = load("pq_external.json");
    let (mut good, mut bad) = (0, 0);
    let mut one = |kind: u16, pk: &[u8], m: &[u8], sig: &[u8], valid: bool, what: &str| {
        assert_eq!(pq::verify_raw(kind, pk, m, sig), valid, "{what}");
        if valid { good += 1 } else { bad += 1 }
    };
    for set in ["acvp_mldsa", "acvp_slhdsa", "eip8051_nist_kat", "eip8355"] {
        for c in arr(&v[set], "cases").iter().filter(|c| c.get("pk").is_some()) {
            let what = format!("{set} {} {} {}", c["set"], c["tc"], c["name"]);
            one(kind_of(c), &bytes(&c["pk"]), &bytes(&c["mprime"]), &bytes(&c["sig"]), c["valid"].as_bool().unwrap(), &what);
        }
    }
    for c in arr(&v["falcon_kat"], "cases") {
        one(0x0132, &bytes(&c["pk"]), &bytes(&c["msg"]), &bytes(&c["sig"]), c["valid"].as_bool().unwrap(), &format!("falcon {}", c["count"]));
    }
    assert_eq!((good, bad), (37, 73), "accepted, refused: every row with a key");
    println!("{good} accepted, {bad} refused");
}

/// pq_signatures.json: `pop` / `popOther` / `popPqz` and the `sigs` verify under the key; every negative refuses (each is
/// one field off a row above, and that row is the positive control).
#[test]
fn pq_signatures_verify() {
    let v = load("pq_signatures.json");
    let (mut ok, mut no) = (0, 0);
    let mut rows: Vec<&Value> = arr(&v, "kinds").iter().collect();
    rows.extend(arr(&v, "extraKeys"));
    for k in rows {
        let (kind, pk) = (k["kind"].as_u64().unwrap() as u16, bytes(&k["keyData"]));
        let mut good: Vec<&Value> = ["pop", "popOther", "popPqz"].iter().filter_map(|f| k.get(f)).collect();
        good.extend(k.get("sigs").and_then(Value::as_array).into_iter().flatten());
        for s in good {
            assert!(pq::verify(kind, &pk, &b32(&s["message"]), &bytes(&s["sig"])), "{} {s}", k["name"]);
            ok += 1;
        }
        for n in k.get("negatives").and_then(Value::as_array).into_iter().flatten() {
            assert!(!pq::verify(kind, &pk, &b32(&n["message"]), &bytes(&n["sig"])), "{} {}", k["name"], n["name"]);
            no += 1;
        }
    }
    assert_eq!((ok, no), (21, 33));
    println!("{ok} accepted, {no} refused");
}

/// Only the PQ kinds: the positive control is every row above.
#[test]
fn pq_other_kinds_refused() {
    assert!(!pq::verify(0x0134, &[0; 32], &[0; 32], &[0; 64]), "not a PQ kind");
    assert!(!pq::verify(0x0120, &[0; 32], &[0; 32], &[0; 64]), "not a PQ kind");
}
