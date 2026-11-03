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

/// CTR-UA-37: `membershipSigOf`'s bytes give back the slot, an `msig` slot its list, with no new signature.
#[test]
fn nested_replay_rows() {
    let n = nested();
    assert_eq!(rows(&n, "memberships").len(), 4);
    for m in rows(&n, "memberships") {
        let index = m["index"].as_u64().unwrap() as u16;
        let d = bytes(&rows(&n, "registrations").iter().find(|r| r["ua"] == m["ua"]).unwrap()["keyData"]);
        let want = typed(&serde_json::json!([{ "index": index, "members": m["members"], "sig": m["sig"] }])).remove(0);
        assert_eq!(replayed_member_sig(&d, index, &bytes(&m["stored"])), Ok(want.clone()), "{}", m["name"]);
        if !want.members.is_empty() {
            assert_eq!(encode_inner_sigs(&want.members), bytes(&m["stored"]));
            let stored = bytes(&m["stored"]);
            assert_eq!(replayed_member_sig(&d, index, &[stored.as_slice(), &[0]].concat()), Err(UAError::Unauthorized), "not canonical");
            assert_eq!(replayed_member_sig(&d, index, &[]), Err(UAError::Unauthorized));
        }
        assert_eq!(replayed_member_sig(&d, 16, &[]), Err(UAError::Unauthorized), "past the members");
    }
}

/// An offset word next to the end of `usize` refuses, never overflows (a panic in a debug build): `word(32) ‖ word(1) ‖ word(2^64 − 80)`.
#[test]
fn nested_decode_offsets_checked() {
    let word = |v: u64| [[0u8; 24].as_slice(), &v.to_be_bytes()].concat();
    let hostile = [word(32), word(1), word(u64::MAX - 79)].concat();
    let n = nested();
    let m = rows(&n, "memberships").iter().find(|m| !m["members"].as_array().unwrap().is_empty()).unwrap();
    let d = key_of(&n, b32(&m["ua"])).unwrap().1;
    assert_eq!(replayed_member_sig(&d, m["index"].as_u64().unwrap() as u16, &hostile), Err(UAError::Unauthorized));
    assert_eq!(decode_member_sigs(&hostile), None);
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
    /// The accepted bits (CTR-UA-37): what each `msig` row's `pop` accepted as it registered.
    fn popped(n: &Value, id: [u8; 32], i: u16) -> bool {
        rows(n, "registrations").iter().any(|r| b32(&r["ua"]) == id && r["popSigners"].as_array().is_some_and(|s| s.iter().any(|x| x.as_u64() == Some(i.into()))))
    }
    /// Then also what the `memberships` rows accept.
    fn after(n: &Value, id: [u8; 32], i: u16) -> bool {
        popped(n, id, i) || rows(n, "memberships").iter().any(|m| b32(&m["ua"]) == id && m["index"].as_u64() == Some(i.into()))
    }
    fn check_on(n: &Value, r: &Value, pop: &[u8], accepted: Option<&Accepted>) -> Result<()> {
        let kind = r["kind"].as_u64().unwrap() as u16;
        check_registration_with(kind, &bytes(&r["keyData"]), &attrs(r), pop, &bytes(&r["pqzPop"]), &|id| key_of(n, id), accepted)
    }
    fn check(n: &Value, r: &Value, pop: &[u8]) -> Result<()> {
        check_on(n, r, pop, Some(&|id, i| popped(n, id, i)))
    }
    fn any_row<'a>(n: &'a Value, name: &Value) -> &'a Value {
        rows(n, "registrations").iter().chain(rows(n, "afterAcceptance")).find(|r| r["name"] == *name).unwrap()
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
        for r in rows(&n, "afterAcceptance") {
            assert_eq!(check_on(&n, r, &bytes(&r["pop"]), Some(&|id, i| after(&n, id, i))), Ok(()), "{}", r["name"]);
        }
    }

    #[test]
    fn nested_check_negatives() {
        let n = nested();
        assert_eq!(rows(&n, "negatives").len(), 13);
        for x in rows(&n, "negatives") {
            assert_eq!(x["error"], "UAPoP");
            assert_eq!(check(&n, any_row(&n, &x["row"]), &bytes(&x["pop"])), Err(UAError::Pop), "{}", x["name"]);
        }
        for s in rows(&n, "structures") {
            let got = check_registration(0x0120, &bytes(&s["keyData"]), &UAAttrs::default(), &[], &[], &|id| key_of(&n, id));
            assert_eq!(got, Err(UAError::MemberUnknown), "{}", s["name"]);
        }
        // an acceptance never asks eligibility, so the record check alone refuses a third level
        let third = &rows(&n, "structures")[0];
        let (ua, d) = (b32(&third["ua"]), bytes(&third["keyData"]));
        let keys = |id: [u8; 32]| if id == ua { Some((0x0120, d.clone())) } else { key_of(&n, id) };
        let slot = MemberSig { index: 0, members: vec![InnerSig::default()], sig: vec![] };
        assert_eq!(check_membership(&d, &ua, &slot, &keys), Err(UAError::MemberUnknown), "a third level");
    }

    #[test]
    fn nested_check_records_and_acceptances() {
        let n = nested();
        let keys = |id| key_of(&n, id);
        let (at, all): (&Accepted, &Accepted) = (&|id, i| popped(&n, id, i), &|id, i| after(&n, id, i));
        for k in rows(&n, "kemRecords") {
            let (ua, sig) = (b32(&k["ua"]), bytes(&k["sig"]));
            let (kind, d) = key_of(&n, ua).unwrap();
            assert_eq!(check_kem_record_with(kind, &d, &ua, 1, &bytes(&k["kemPk"]), &sig, &keys, Some(at)), Ok(()));
            assert_eq!(check_kem_record_with(kind, &d, &ua, 1, &bytes(&k["kemPk"]), &flip(&sig), &keys, Some(at)), Err(UAError::Unauthorized));
        }
        for k in rows(&n, "pqzKeyRecords") {
            let (ua, sig) = (b32(&k["ua"]), bytes(&k["sig"]));
            let (kind, d) = key_of(&n, ua).unwrap();
            let pqz = |sig: &[u8]| check_pqz_key_record_with(kind, &d, &ua, &bytes(&k["pqzKey"]), &b32(&k["pqzPopHash"]), sig, &keys, Some(at));
            assert_eq!(pqz(&sig), Ok(()));
            assert_eq!(pqz(&flip(&sig)), Err(UAError::Unauthorized));
        }
        let mut lists = 0;
        for m in rows(&n, "memberships") {
            let (ua, d) = (b32(&m["ua"]), key_of(&n, b32(&m["ua"])).unwrap().1);
            let slot = typed(&serde_json::json!([{ "index": m["index"], "members": m["members"], "sig": m["sig"] }])).remove(0);
            let accept = |slot: &MemberSig| check_membership_with(&d, &ua, slot, &keys, Some(all));
            assert_eq!(accept(&slot), Ok(()), "{}", m["name"]);
            if slot.members.is_empty() {
                let list = MemberSig { members: vec![InnerSig::default()], ..slot.clone() };
                assert_eq!(accept(&list), Err(UAError::Unauthorized), "a list on a signing slot");
            } else {
                lists += 1;
                assert_eq!(accept(&MemberSig { sig: vec![1], ..slot.clone() }), Err(UAError::Unauthorized), "a sig on an msig slot");
                let mut bad = slot.clone();
                bad.members[0].sig[20] ^= 1;
                assert_eq!(accept(&bad), Err(UAError::Unauthorized), "a flipped leaf");
            }
        }
        assert_eq!(lists, 1);
    }

    /// CTR-UA-37 one level down: the inner bits read through `accepted` always, unchecked (`NotVerifiable`) without it, a `pop` accepting the
    /// slots of its own record only; a record's own bits outside its `pop` read when `accepted` comes.
    #[test]
    fn nested_check_inner_acceptance() {
        let n = nested();
        let keys = |id| key_of(&n, id);
        let at: &Accepted = &|id, i| popped(&n, id, i);
        let lists: Vec<&Value> = rows(&n, "registrations").iter().filter(|r| r["innerDigests"].as_array().is_some_and(|d| !d.is_empty()) && r["pop"] != "0x").collect();
        assert_eq!(lists.len(), 5);
        for r in lists {
            assert_eq!(check_on(&n, r, &bytes(&r["pop"]), None), Err(UAError::NotVerifiable), "{}: never Ok unread", r["name"]);
        }
        for r in rows(&n, "registrations").iter().filter(|r| r["innerDigests"].as_array().is_none_or(|d| d.is_empty())) {
            assert_eq!(check_on(&n, r, &bytes(&r["pop"]), None), Ok(()), "{}: no inner level", r["name"]);
        }
        let after_row = &rows(&n, "afterAcceptance")[0];
        let neg = rows(&n, "negatives").iter().find(|x| x["name"] == "inner-slot-not-accepted").unwrap();
        assert_eq!(neg["pop"], after_row["pop"]);
        let pop = bytes(&after_row["pop"]);
        assert_eq!(check_on(&n, after_row, &pop, Some(at)), Err(UAError::Pop), "before the memberships rows");
        assert_eq!(check_on(&n, after_row, &pop, None), Err(UAError::NotVerifiable));
        assert_eq!(check_on(&n, after_row, &pop, Some(&|id, i| after(&n, id, i))), Ok(()));
        let k = &rows(&n, "kemRecords")[0];
        let (ua, sig) = (b32(&k["ua"]), bytes(&k["sig"]));
        let (kind, d) = key_of(&n, ua).unwrap();
        let kem = |acc: Option<&Accepted>| check_kem_record_with(kind, &d, &ua, 1, &bytes(&k["kemPk"]), &sig, &keys, acc);
        assert_eq!(kem(Some(&|id, i| id != ua && popped(&n, id, i))), Err(UAError::Unauthorized), "the record's own bits");
        assert_eq!(kem(None), Err(UAError::NotVerifiable));
        let p = &rows(&n, "pqzKeyRecords")[0];
        let (ua, d) = (b32(&p["ua"]), key_of(&n, b32(&p["ua"])).unwrap().1);
        let got = check_pqz_key_record_with(0x0120, &d, &ua, &bytes(&p["pqzKey"]), &b32(&p["pqzPopHash"]), &bytes(&p["sig"]), &keys, None);
        assert_eq!(got, Err(UAError::NotVerifiable));
        let m = rows(&n, "memberships").iter().find(|m| !m["members"].as_array().unwrap().is_empty()).unwrap();
        let (ua, d) = (b32(&m["ua"]), key_of(&n, b32(&m["ua"])).unwrap().1);
        let slot = typed(&serde_json::json!([{ "index": m["index"], "members": m["members"], "sig": m["sig"] }])).remove(0);
        assert_eq!(check_membership_with(&d, &ua, &slot, &keys, Some(at)), Err(UAError::Unauthorized), "the inner slot not accepted yet");
        assert_eq!(check_membership(&d, &ua, &slot, &keys), Err(UAError::NotVerifiable));
    }

    /// `requireAuthorized` of every `authorizations` row (UAAuth leaves in context A, gen 1): the valid one passes, the others `Unauthorized`.
    #[test]
    fn nested_check_authorizations() {
        let n = nested();
        let path = format!("{}/../../smartcontracts/vectors/ua/structures.json", env!("CARGO_MANIFEST_DIR"));
        let s: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let c = &s["contexts"]["A"];
        let domain = |generation| Domain { generation, chain_id: c["chainId"].as_u64().unwrap(), registry: bytes(&c["registry"]).try_into().unwrap(), chain_uid: b32(&c["chainUid"]) };
        let keys = |id| key_of(&n, id);
        let at: &Accepted = &|id, i| popped(&n, id, i);
        assert_eq!(rows(&n, "authorizations").len(), 5);
        let auth = |a: &Value, g: u32, acc: Option<&Accepted>| {
            let ua = b32(&a["ua"]);
            check_authorization(&key_of(&n, ua).unwrap().1, &ua, &b32(&a["purposeTag"]), &b32(&a["digest"]), &typed(&a["uaSig"]["members"]), &domain(g), &keys, acc)
        };
        for a in rows(&n, "authorizations") {
            assert_eq!(decode_member_sigs(&bytes(&a["sig"])).unwrap(), typed(&a["uaSig"]["members"]), "{}", a["name"]);
            let want = if a["valid"] == true { Ok(()) } else { Err(UAError::Unauthorized) };
            assert_eq!(auth(a, 1, Some(at)), want, "{}", a["name"]);
        }
        let a = rows(&n, "authorizations").iter().find(|a| a["valid"] == true).unwrap();
        let ua = b32(&a["ua"]);
        let inner = MsigStructure::from_key_data(&key_of(&n, ua).unwrap().1).unwrap().members.iter().find(|m| m.kind == 0x0120).unwrap().id;
        assert_eq!(auth(a, 1, None), Err(UAError::NotVerifiable));
        assert_eq!(auth(a, 1, Some(&|id, i| id != ua && popped(&n, id, i))), Err(UAError::Unauthorized), "the outer bits");
        assert_eq!(auth(a, 1, Some(&|id, i| id != inner && popped(&n, id, i))), Err(UAError::Unauthorized), "the inner bits");
        assert_eq!(auth(a, 2, Some(at)), Err(UAError::Unauthorized), "another domain");
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
