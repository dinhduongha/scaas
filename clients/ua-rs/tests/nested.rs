// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Nested `msig` (spec 2026-11-02-msig-nested): every row of smartcontracts/vectors/ua/nested.json, the rows forge runs on the registry.
//! The signature verdicts need the feature `pq` (the rows sign with fndsa512). UNAUDITED.
use scaas_ua::ua8::*;
use scaas_ua::*;
use serde_json::Value;

fn nested() -> Value {
    let path = format!("{}/../../smartcontracts/vectors/ua/nested.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}
fn rows<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array().unwrap()
}
fn row<'a>(n: &'a Value, name: &Value) -> &'a Value {
    rows(n, "registrations").iter().find(|r| r["name"] == *name).unwrap()
}
fn typed(v: &Value) -> Vec<MemberSig> {
    let inner = |x: &Value| InnerSig { index: x["index"].as_u64().unwrap() as u16, sig: bytes(&x["sig"]) };
    let slot = |s: &Value| MemberSig { index: s["index"].as_u64().unwrap() as u16, members: s["members"].as_array().unwrap().iter().map(inner).collect(), sig: bytes(&s["sig"]) };
    v.as_array().unwrap().iter().map(slot).collect()
}
fn key_of(n: &Value, id: [u8; 32]) -> Option<(u16, Vec<u8>)> {
    rows(n, "registrations").iter().find(|r| b32(&r["ua"]) == id).map(|r| (r["kind"].as_u64().unwrap() as u16, bytes(&r["keyData"])))
}

#[test]
fn nested_eligibility_rows() {
    let n = nested();
    for r in rows(&n, "eligibility") {
        let d = bytes(&r["keyData"]);
        let inner = |id: [u8; 32]| r["inner"].get(hex_of(&id)).map(bytes);
        assert_eq!(msig_pqz_eligible_with(&d, &inner), Ok(r["eligible"].as_bool().unwrap()), "{}", r["reason"]);
        assert_eq!(msig_pqz_eligible(&d), Err(UAError::MemberUnknown), "the key data alone does not show it");
    }
    let outer = row(&n, &"msig-nested-pq".into());
    let third = bytes(&n["structures"][0]["keyData"]);
    assert_eq!(msig_pqz_eligible_with(&third, &|_| Some(bytes(&outer["keyData"]))), Err(UAError::MemberUnknown), "a third level");
}
fn hex_of(id: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(id))
}

#[test]
fn nested_rows_encode_and_digests() {
    let n = nested();
    let mut lists = 0;
    for r in rows(&n, "registrations").iter().filter(|r| r["kind"] == 0x0120) {
        assert_eq!(encode_member_sigs(&typed(&r["args"]["pop"])), bytes(&r["pop"]), "{}", r["name"]);
        if !bytes(&r["pop"]).is_empty() {
            assert_eq!(decode_member_sigs(&bytes(&r["pop"])).unwrap(), typed(&r["args"]["pop"]), "{}", r["name"]);
        }
        for d in r["innerDigests"].as_array().into_iter().flatten() {
            assert_eq!(inner_digest(&b32(&d["inner"]), &b32(&r["memberDigest"])), Ok(b32(&d["memberDigest"])), "{}", r["name"]);
            lists += 1;
        }
    }
    assert_eq!(lists, 7);
    for x in rows(&n, "negatives") {
        assert_eq!(encode_member_sigs(&typed(&x["popTyped"])), bytes(&x["pop"]), "{}", x["name"]);
    }
}

#[test]
fn nested_flat_bytes_unchanged_and_decode_bounded() {
    let sig = vec![1, 2, 3];
    let flat = encode_member_sigs(&[MemberSig { index: 7, members: vec![], sig: sig.clone() }]);
    // (uint16, bytes, bytes) with an empty `keyData`: index, the two heads, a zero length, then `sig`
    let word = |v: u8| [[0u8; 31].as_slice(), &[v]].concat();
    let want = [word(32), word(1), word(32), word(7), word(96), word(128), word(0), word(3), [&sig[..], &[0; 29]].concat()].concat();
    assert_eq!(flat, want);
    let of = |n: u16| encode_member_sigs(&[MemberSig { index: 0, members: (0..n).map(|index| InnerSig { index, sig: vec![9] }).collect(), sig: vec![] }]);
    assert_eq!(decode_member_sigs(&of(16)).unwrap()[0].members.len(), 16);
    assert_eq!(decode_member_sigs(&of(17)), None);
    assert_eq!(decode_member_sigs(&[of(1), vec![0; 32]].concat()), None, "trailing bytes");
}

#[test]
fn nested_minimal_at_both_levels() {
    let n = nested();
    let slots = |r: &Value, list: &[u16]| -> Vec<MemberSig> {
        let at = MsigStructure::from_key_data(&bytes(&r["keyData"])).unwrap().members;
        (0..2u16).map(|index| MemberSig {
            index,
            members: if at[index as usize].kind == 0x0120 { list.iter().map(|&index| InnerSig { index, sig: vec![] }).collect() } else { vec![] },
            sig: vec![],
        }).collect()
    };
    let inner = |id| key_of(&n, id).map(|(_, d)| d);
    let r = row(&n, &"msig-nested-heavy-inner".into());
    let d = bytes(&r["keyData"]);
    assert_eq!(msig_sig_minimal(&d, &slots(r, &[1]), &inner), Ok(true), "the weight-2 leaf alone");
    assert_eq!(msig_sig_minimal(&d, &slots(r, &[0, 1]), &inner), Ok(false), "a redundant leaf");
    assert_eq!(msig_sig_minimal(&d, &slots(r, &[0]), &inner), Ok(false), "below the inner threshold");
    assert_eq!(msig_sig_minimal(&d, &slots(r, &[1]), &|_| None), Err(UAError::MemberUnknown));
    let o = row(&n, &"msig-nested-heavy-outer".into());
    assert_eq!(msig_sig_minimal(&bytes(&o["keyData"]), &slots(o, &[0, 1]), &inner), Ok(false), "a redundant slot");
    let input = RegistrationInput { kind: 0x0120, key_data: d, members: slots(r, &[0, 1]), inners: rows(&n, "registrations").iter()
        .filter(|x| x["kind"] == 0x0120).map(|x| (b32(&x["ua"]), bytes(&x["keyData"]))).collect(), ..Default::default() };
    assert_eq!(registration_args(&input).unwrap_err(), UAError::Pop);
}

#[test]
fn nested_member_kind() {
    assert!(is_member(0x0120, false));
    let d = bytes(&nested()["eligibility"][0]["keyData"]);
    assert_eq!(derive_ua(0x0120, &d, false).map(|_| ()), Ok(()));
}

#[cfg(feature = "pq")]
mod verdicts {
    use super::*;
    fn attrs(r: &Value) -> UAAttrs {
        let a = &r["attrs"];
        let pk = bytes(&a["kemPk"]);
        UAAttrs { pqz_key: bytes(&a["pqzKey"]), pqz_pop_hash: b32(&a["pqzPopHash"]), kem: KemKey::from_kem_pk(&pk).unwrap(), kem_pk_hash: [0; 32] }
    }
    fn check(n: &Value, r: &Value, pop: &[u8]) -> Result<()> {
        check_registration(r["kind"].as_u64().unwrap() as u16, &bytes(&r["keyData"]), &attrs(r), pop, &bytes(&r["pqzPop"]), &|id| key_of(n, id))
    }
    fn flip(sig: &[u8]) -> Vec<u8> {
        let mut m = decode_member_sigs(sig).unwrap();
        let s = m.iter_mut().find(|s| !s.members.is_empty()).unwrap();
        s.members[0].sig[20] ^= 1;
        encode_member_sigs(&m)
    }

    #[test]
    fn nested_check_rows() {
        let n = nested();
        for r in rows(&n, "registrations") {
            assert_eq!(check(&n, r, &bytes(&r["pop"])), Ok(()), "{}", r["name"]);
        }
    }

    #[test]
    fn nested_check_negatives() {
        let n = nested();
        for x in rows(&n, "negatives") {
            assert_eq!(x["error"], "UAPoP");
            assert_eq!(check(&n, row(&n, &x["row"]), &bytes(&x["pop"])), Err(UAError::Pop), "{}", x["name"]);
        }
        for s in rows(&n, "structures") {
            let got = check_registration(0x0120, &bytes(&s["keyData"]), &UAAttrs::default(), &[], &[], &|id| key_of(&n, id));
            assert_eq!(got, Err(UAError::MemberUnknown), "{}", s["name"]);
        }
    }

    #[test]
    fn nested_check_records_and_acceptances() {
        let n = nested();
        let keys = |id| key_of(&n, id);
        for k in rows(&n, "kemRecords") {
            let (ua, sig) = (b32(&k["ua"]), bytes(&k["sig"]));
            let (kind, d) = key_of(&n, ua).unwrap();
            assert_eq!(check_kem_record(kind, &d, &ua, 1, &bytes(&k["kemPk"]), &sig, &keys), Ok(()));
            assert_eq!(check_kem_record(kind, &d, &ua, 1, &bytes(&k["kemPk"]), &flip(&sig), &keys), Err(UAError::Unauthorized));
        }
        for k in rows(&n, "pqzKeyRecords") {
            let (ua, sig) = (b32(&k["ua"]), bytes(&k["sig"]));
            let (kind, d) = key_of(&n, ua).unwrap();
            assert_eq!(check_pqz_key_record(kind, &d, &ua, &bytes(&k["pqzKey"]), &b32(&k["pqzPopHash"]), &sig, &keys), Ok(()));
            assert_eq!(check_pqz_key_record(kind, &d, &ua, &bytes(&k["pqzKey"]), &b32(&k["pqzPopHash"]), &flip(&sig), &keys), Err(UAError::Unauthorized));
        }
        let mut lists = 0;
        for m in rows(&n, "memberships") {
            let (ua, d) = (b32(&m["ua"]), key_of(&n, b32(&m["ua"])).unwrap().1);
            let slot = typed(&serde_json::json!([{ "index": m["index"], "members": m["members"], "sig": m["sig"] }])).remove(0);
            assert_eq!(check_membership(&d, &ua, &slot, &keys), Ok(()), "{}", m["name"]);
            if slot.members.is_empty() {
                let list = MemberSig { members: vec![InnerSig::default()], ..slot.clone() };
                assert_eq!(check_membership(&d, &ua, &list, &keys), Err(UAError::Unauthorized), "a list on a signing slot");
            } else {
                lists += 1;
                assert_eq!(check_membership(&d, &ua, &MemberSig { sig: vec![1], ..slot.clone() }, &keys), Err(UAError::Unauthorized), "a sig on an msig slot");
                let mut bad = slot.clone();
                bad.members[0].sig[20] ^= 1;
                assert_eq!(check_membership(&d, &ua, &bad, &keys), Err(UAError::Unauthorized), "a flipped leaf");
            }
        }
        assert_eq!(lists, 1);
    }

    #[test]
    fn nested_n5_one_signature_two_slots() {
        let n = nested();
        let r = row(&n, &"msig-nested-twice".into());
        let slots = decode_member_sigs(&bytes(&r["pop"])).unwrap();
        let native = |s: &MemberSig| {
            let leaves = MsigStructure::from_key_data(&key_of(&n, MsigStructure::from_key_data(&bytes(&r["keyData"])).unwrap().members[s.index as usize].id).unwrap().1).unwrap().members;
            s.members.iter().find(|x| leaves[x.index as usize].kind == 0x0001).unwrap().sig.clone()
        };
        assert_eq!(native(&slots[0]), native(&slots[1]));
    }
}
