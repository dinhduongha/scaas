//! UA-8 A2: the portable registration digests of `scaas_ua::ua8` against smartcontracts/vectors/ua/portable.json (written
//! by the JS reference, clientkeys scripts/ua-portable-vectors.mjs): every digest of every registration, KEM record and PQZ
//! key record, and every holder / length / proof-hash refusal of `negatives[]` that is a digest-layer rule. Rows that only a
//! signature check or the registry's state can refuse (UAUnauthorized, the chain's PoP verdict) are counted, not run.
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
    assert_eq!(hx(&kem_record_tag()), t["KEM_RECORD_TAG"]["hash"]);
    assert_eq!(hx(&pqz_key_record_tag()), t["PQZ_KEY_RECORD_TAG"]["hash"]);
    assert_eq!(hx(&group_tag("pqz-mlwe").unwrap()), t["PQZ_KEY_GROUP"]["hash"]);
    assert_eq!(purpose_tag_v("pop", 2).unwrap(), pop_v2_tag());
    assert_eq!(purpose_tag_v("pop", 1).unwrap(), purpose_tag("pop").unwrap());
    assert_eq!(purpose_tag_v("kem", 2), Err(UAError::PurposeUnknown));
    assert_eq!(KEM_PK_LENGTH as u64, num(&p["kemPkLength"]));
    for (name, c) in [("none", Checked::None), ("chain", Checked::Chain), ("relayer", Checked::Relayer([7; 32]))] {
        assert_eq!(c.code() as u64, num(&p["checked"][name]), "{name}");
    }
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
            assert_eq!(hx(&h.portable_pop_digest), r["portablePopDigest"], "{}", r["name"]);
            assert_eq!(hx(&h.registration_digest), r["registrationDigest"], "{}", r["name"]);
            assert_eq!(hx(&h.message), r["popMessage"], "{}", r["name"]);
            // the word-level functions agree
            let portable = portable_pop_digest(&ua, &h.pqz_key_hash, &h.kem_record_hash);
            assert_eq!(portable, h.portable_pop_digest);
            assert_eq!(registration_digest(&portable, &h.pqz_pop_hash), h.registration_digest);
            assert_eq!(ua_message(kind, &pop_v2_tag(), &h.registration_digest).unwrap(), h.message);
            assert_eq!(h.member_digest.map(|d| hx(&d)), r.get("memberDigest").map(|d| d.as_str().unwrap().to_string()), "{}", r["name"]);
        }
        let pk = bytes(&r["attrs"]["pqzKey"]);
        if !pk.is_empty() {
            with_pqz += 1;
            let kem = (num(&r["attrs"]["kemVersion"]) != 0).then(|| (num(&r["attrs"]["kemVersion"]), bytes(&r["attrs"]["kemPk"])));
            let got = pqz_reg_message(&ua, &pk, kem.as_ref().map(|(v, p)| (*v, &p[..]))).unwrap();
            assert_eq!(hx(&got), r["pqzRegMessage"], "{}", r["name"]);
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
        let m = kem_record_message(kind, &ua, v, &pk).unwrap();
        assert_eq!(hx(&m), r["message"], "{}", r["id"]);
        assert_eq!(m, ua_message(kind, &purpose_tag("kem").unwrap(), &b32(&r["digest"])).unwrap());
        if kind == 0x0120 {
            assert_eq!(hx(&member_digest(&ua, &m)), r["memberDigest"], "{}", r["id"]);
        }
    }
    assert_eq!(arr(&p, "kemRecords").len(), 9);
    let ua = [1u8; 32];
    assert_eq!(kem_record_digest(&ua, 0, &[0; 1600]), Err(UAError::KemVersion));
    assert_eq!(kem_record_digest(&ua, 1, &[0; 1599]), Err(UAError::KemKeyLength));
    assert_eq!(kem_record_digest(&ua, 1, &[0; 1601]), Err(UAError::KemKeyLength));
    assert!(kem_record_digest(&ua, u64::MAX, &[0; 1600]).is_ok());
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
            assert_eq!(pqz_key_record_digest(&got.pqz_key_digest, &got.pqz_pop_hash), got.record_digest);
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
            "register" if name == "native-uaauth-in-portable-pop" => {
                // a UAAuth-framed native signature does not recover the member over personal_sign(memberDigest)
                let r = &row;
                let got = native_recovered(r, &bytes(&m["set"]["pop"]), &b32(&r["memberDigest"]));
                assert!(!got.is_empty() && got.iter().all(|(i, a)| a.as_ref() != Some(&member_address(r, *i))), "{name}");
                run += 1;
            }
            "requireAuthorized" => {
                // valid personal_sign, but metatx is not a portable purpose: UAAuth there
                let (tag, auth) = (b32(&m["set"]["purposeTag"]), bytes(&m["set"]["auth"]));
                assert!(!is_portable_purpose(&tag), "{name}");
                assert_eq!(hx(bytes_at(&auth, 0)), row["keyData"], "{name}");
                let md = member_digest(&b32(&row["ua"]), &ua_message(0x0120, &tag, &b32(&m["set"]["digest"])).unwrap());
                let got = native_recovered(&row, bytes_at(&auth, 32), &md);
                assert!(!got.is_empty() && got.iter().all(|(i, a)| a.as_ref() == Some(&member_address(&row, *i))), "{name}");
                run += 1;
            }
            _ => sig_level += 1, // PQ / classical signatures: verified by the signature vectors (no verifier in this crate)
        }
    }
    assert_eq!((run, sig_level), (58, 5), "{} negatives", arr(&p, "negatives").len());
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
/// The address each native (kind 0x0001) member's signature in a `MemberSig[]` blob recovers over `personal_sign(md)`
/// (None: not a 65-byte signature, or no recovery), by member index.
fn native_recovered(row: &Value, blob: &[u8], md: &[u8; 32]) -> Vec<(usize, Option<String>)> {
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
                let vk = VerifyingKey::recover_from_prehash(&personal_sign_digest(md), &s, v).ok()?;
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

/// C7: the native msig member signs `personal_sign(memberDigest)`; the recovered address is the member's.
#[test]
fn native_member_personal_sign() {
    let p = load("portable.json");
    let r = find(&p, "registrations", "name", &"msig-pq-native".into());
    let md = b32(&r["memberDigest"]);
    let got = native_recovered(r, &bytes(&r["pop"]), &md);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].1, Some(member_address(r, got[0].0)));
    // the raw digest is not what it signs
    assert_ne!(personal_sign_digest(&md), md);
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
