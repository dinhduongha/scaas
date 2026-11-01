//! B2 (U8S-D3–D7): `register` with PQZ / KEM attributes against `portable.json` (the authority for bytes): the bytes stay
//! in contract state, unproven, and `registration_of` returns exactly the `register` arguments, as EVM `registrationOf`.
extern crate std;
use std::{format, vec::Vec as StdVec};

use serde_json::Value;
use soroban_sdk::{
    testutils::{storage::Persistent as _, Events as _, Ledger as _},
    xdr::{Limits, WriteXdr},
    Bytes, BytesN, Env, Event as _, Vec as SVec,
};

use crate::{
    test::{self, err, kem_key, msig, n, no_attrs, portable, portable_row, setup, structure_of, vecu8, Reg, Tried, PORTABLE},
    test_verify::{b, derived, hx, json, kind_of, n32},
    Error, Key, RegisteredRecord, UaKemKeySet, UaPqzKeySet, UaPqzPopStored, UaRegistered, UaRegistryClient,
};
use scaas_ua_common::*;

const KINDS: &str = include_str!("../../../../vectors/ua/kinds.json");
const DAY: u32 = 17_280;
const CHAIN: [u32; 7] = [0x0100, 0x0101, 0x0102, 0x0108, 0x0120, 0x0130, 0x0131];
const SET: &str = "n2048-kmax1024";

type Entry = (Bytes, Bytes, Checked);

/// The `registrations[]` rows of a `Chain` kind (`msig-classical`'s members are disabled kinds here: B4).
fn chain_rows() -> StdVec<Value> {
    let rows = json(PORTABLE)["registrations"].as_array().unwrap().clone();
    rows.into_iter().filter(|r| CHAIN.contains(&kind_of(&r["kind"])) && r["name"] != "msig-classical").collect()
}

/// An `msig` row's members, registered first.
fn members(env: &Env, c: &UaRegistryClient, kind: u32) {
    if kind == 0x0120 {
        portable(env, "mldsa65#1").on(c);
        portable(env, "mldsa65#2").on(c);
    }
}

fn registered(name: &str) -> (Env, UaRegistryClient<'static>, Reg) {
    let (env, c) = setup();
    let r = portable(&env, name);
    members(&env, &c, r.kind);
    assert_eq!(r.on(&c), r.ua, "{name}");
    (env, c, r)
}

fn entry<V: soroban_sdk::TryFromVal<Env, soroban_sdk::Val>>(env: &Env, c: &UaRegistryClient, k: &Key) -> Option<V> {
    env.as_contract(&c.address, || env.storage().persistent().get(k))
}

/// The row's `kemCommit`: the same registration with the KEM record's hash only (`kem` = its scheme).
fn commit_of(env: &Env, name: &str) -> Reg {
    let row = derived(PORTABLE, "registrations", name);
    let a = &row["kemCommit"]["register"]["attrs"];
    let mut r = portable_row(env, &row);
    r.attrs.kem = KemKey { scheme: a["kem"]["scheme"].as_u64().unwrap() as u32, ..KemKey::none(env) };
    r.attrs.kem_pk_hash = n32(env, &a["kemPkHash"]);
    r
}

/// Every `Chain` row: `registration_of` is the row byte for byte, `kem` against the row's typed `args`; an `msig`'s stored
/// `pop` is the row's `abi.encode(MemberSig[])`, assembled from the typed slots.
#[test]
fn ua8_register_attrs_rows() {
    let (mut all, mut pqz, mut kem, mut ms) = (0, 0, 0, 0);
    for row in chain_rows() {
        let name = row["name"].as_str().unwrap();
        let (env, c, r) = registered(name);
        let got = c.registration_of(&r.ua).unwrap();
        assert_eq!(got, (r.kind, r.kd.clone(), r.attrs.clone(), r.pop.clone(), r.pqz_pop.clone()), "{name}");
        let (a, k) = (&row["args"]["attrs"], &got.2.kem);
        assert_eq!((k.scheme as u64, vecu8(&k.mlkem_ek), k.x25519.to_array().to_vec()),
                   (a["kem"]["scheme"].as_u64().unwrap(), hx(&a["kem"]["mlkemEk"]), hx(&a["kem"]["x25519"])), "{name}");
        assert_eq!(got.2.kem_pk_hash, n32(&env, &a["kemPkHash"]), "{name}");
        assert_eq!(vecu8(&got.2.pqz_key), hx(&a["pqzKey"]), "{name}");
        assert_eq!(c.pop_of(&r.ua), r.pop, "{name}");
        assert_eq!(c.pqz_pop_of(&r.ua), r.pqz_pop, "{name}");
        all += 1;
        pqz += !r.attrs.pqz_key.is_empty() as u32;
        kem += (r.attrs.kem != KemKey::none(&env)) as u32;
        ms += (r.kind == 0x0120) as u32;
    }
    assert_eq!((all, pqz, kem, ms), (16, 8, 8, 5));
}

/// EVM's hash commit (`kemCommit`, the same `pop`): the scheme and hash stay in the record, version 0 stays empty until
/// `set_kem_key(ua, 0, …)` (B3), `registration_of` returns the committed form; the commit's own rules.
#[test]
fn ua8_register_kem_commit() {
    for name in [format!("mldsa65/{SET}"), format!("msig-pq/{SET}")] {
        let (env, c) = setup();
        let r = commit_of(&env, &name);
        members(&env, &c, r.kind);
        let pk_hash = r.attrs.kem_pk_hash.clone();
        assert_eq!(r.on(&c), r.ua, "{name}");
        assert_eq!(c.registration_of(&r.ua).unwrap().2, r.attrs, "{name}");
        assert_eq!(entry::<Entry>(&env, &c, &Key::Kem(r.ua.clone(), 0)), None, "{name}");
        assert_eq!(c.checked_of(&r.ua).2, Checked::None, "{name}: not filled");
        let rec = c.record_of(&r.ua).unwrap();
        assert_eq!((rec.attrs.kem.scheme, rec.attrs.kem_pk_hash), (1, pk_hash), "{name}");
    }
    let (env, c) = setup();
    let base = || commit_of(&env, &format!("mldsa65/{SET}"));
    let mut r = base();
    r.attrs.kem.mlkem_ek = b(&env, &[1]);
    assert_eq!(r.refused(&c), Error::KemKeyLength);
    let mut r = base();
    r.attrs.kem.x25519 = n(&env, [1; 32]);
    assert_eq!(r.refused(&c), Error::KemKeyLength);
    let mut r = base();
    r.attrs.kem.scheme = 2;
    assert_eq!(r.refused(&c), Error::KemScheme);
    let mut r = portable(&env, "p256");
    r.attrs.kem_pk_hash = n(&env, [1; 32]);
    assert_eq!(r.refused(&c), Error::KemHolder);
}

#[test]
fn ua8_pqz_bytes_in_state() {
    let (env, c, r) = registered(&format!("msig-pq/{SET}"));
    let rec = c.record_of(&r.ua).unwrap();
    assert!(rec.attrs.pqz_key.is_empty(), "the key only in PqzK (C12)");
    assert_eq!((rec.attrs.kem, rec.attrs.pqz_pop_hash.clone()), (KemKey::none(&env), r.attrs.pqz_pop_hash.clone()));
    let none = Bytes::new(&env);
    assert_eq!(entry::<Entry>(&env, &c, &Key::PqzK(r.ua.clone())), Some((r.attrs.pqz_key.clone(), none.clone(), Checked::Chain)));
    assert_eq!(entry::<Bytes>(&env, &c, &Key::PqzP(r.ua.clone())), Some(r.pqz_pop.clone()));
    assert_eq!(entry::<Entry>(&env, &c, &Key::Kem(r.ua.clone(), 0)), Some((kem_pk(&env, &r.attrs.kem), none, Checked::Chain)));
    assert_eq!(r.attrs.pqz_key.len(), 16_384);
    assert_eq!(r.pqz_pop.len(), 28_191);
}

#[test]
fn ua8_pqz_attrs_stored_unproven() {
    for name in [format!("mldsa65/{SET}"), format!("msig-pq/{SET}")] {
        let (env, c, r) = registered(&name);
        let rec = c.record_of(&r.ua).unwrap();
        assert!(!rec.proven && rec.pqz_pop_checked == Checked::None, "{name}");
        assert_eq!(c.key_owner(&pqz_key_hash(&env, &r.attrs.pqz_key)), None, "{name}: no Key entry (UA8-D8)");
        assert_eq!(c.ua_count(&0x0142), 0, "{name}");
    }
}

#[test]
fn ua8_register_without_pqz_pop() {
    let (env, c) = setup();
    let mut r = portable(&env, &format!("mldsa65/{SET}"));
    r.pqz_pop = Bytes::new(&env);
    let ua = r.on(&c);
    assert!(!env.as_contract(&c.address, || env.storage().persistent().has(&Key::PqzP(ua.clone()))));
    assert!(c.pqz_pop_of(&ua).is_empty());
    let got = c.registration_of(&ua).unwrap();
    assert_eq!((got.2, got.4), (r.attrs.clone(), Bytes::new(&env)), "the key and its hash, no proof");
}

/// `attrs.pqz_key` comes from `PqzK` iff `register` carried one: a later key (the entry `set_pqz_key` writes, B3 completes
/// this with the entry point) is no `register` argument, so the arguments read back unchanged.
#[test]
fn ua8_registration_of_reassembles() {
    let (env, c, r) = registered("mldsa65#1");
    let later: Entry = (b(&env, &[7; 16_384]), b(&env, &[8]), Checked::Chain);
    env.as_contract(&c.address, || crate::put(&env, &Key::PqzK(r.ua.clone()), &later));
    assert_eq!(c.registration_of(&r.ua), Some((r.kind, r.kd, r.attrs, r.pop, r.pqz_pop)));
    assert_eq!(c.registration_of(&n(&env, [0x42; 32])), None);
    assert!(c.pop_of(&n(&env, [0x42; 32])).is_empty());
    assert!(c.pqz_pop_of(&n(&env, [0x42; 32])).is_empty());
}

fn mutate(env: &Env, r: &mut Reg, set: &Value) {
    for (k, v) in set.as_object().into_iter().flatten() {
        match k.as_str() {
            "attrs.pqzKey" => r.attrs.pqz_key = b(env, &hx(v)),
            "attrs.pqzPopHash" => r.attrs.pqz_pop_hash = n32(env, v),
            "attrs.kemPk" => r.attrs.kem = kem_key(env, &hx(v)),
            "pqzPop" => r.pqz_pop = b(env, &hx(v)),
            "pop" => r.pop = b(env, &hx(v)),
            _ => panic!("unknown mutation {k}"),
        }
    }
}

/// U8S-D5's map; `UAPoP` is `Pop` or a host error (plan finding F1).
fn expect(name: &str, want: &str, got: Tried) {
    let e = match got {
        Err(Ok(e)) => e,
        other => panic!("{name}: {other:?}"),
    };
    let contract = Error::try_from(e);
    let code = match want {
        "UAPoP" => {
            assert!(contract.as_ref().map_or(true, |x| *x == Error::Pop), "{name}: {e:?}");
            return;
        }
        "UAPqzPopHash" => Error::PqzPopHash,
        "UAKeyData" => Error::KeyData,
        "UAPqzHolder" => Error::PqzHolder,
        "UAKemHolder" => Error::KemHolder,
        "UAKemKeyLength" => Error::KemKeyLength,
        "UAKemScheme" => Error::KemScheme,
        _ => panic!("{name}: unmapped {want}"),
    };
    assert_eq!(contract, Ok(code), "{name}");
}

/// Every `register` negative. A row of a kind Soroban does not enable yet is `KindDisabled` until B4, and its mutation
/// runs on a stand-in of an enabled kind: `slhdsa128s` ⇒ `p256` (non-holders), `fndsa512` ⇒ `mldsa65#1` (a holder without
/// a key), or a holder with a KEM key where the mutation changes that key's record.
#[test]
fn ua8_negatives_from_portable_json() {
    let negs = json(PORTABLE)["negatives"].as_array().unwrap().clone();
    let mut seen = 0;
    for neg in negs.iter().filter(|x| x["entry"] == "register") {
        let (name, want) = (neg["name"].as_str().unwrap(), neg["error"].as_str().unwrap());
        seen += 1;
        let (env, c) = setup();
        if neg["registration"].is_object() {
            let r = portable_row(&env, &neg["registration"]);
            members(&env, &c, r.kind);
            expect(name, want, r.tried(&c));
            continue;
        }
        let row = neg["mutation"]["row"].as_str().unwrap();
        if row == "msig-classical" {
            continue; // `ua8_classical_msig_with_kem`: its members are disabled kinds here
        }
        let mut r = portable(&env, row);
        let stand_in = match row {
            "slhdsa128s" => Some("p256".into()),
            "fndsa512" if want == "UAPoP" => Some(format!("mldsa65/{SET}")),
            "fndsa512" => Some("mldsa65#1".into()),
            _ => None,
        };
        if let Some(other) = stand_in {
            assert_eq!(r.refused(&c), Error::KindDisabled, "{name}");
            r = portable(&env, &other);
        }
        members(&env, &c, r.kind);
        mutate(&env, &mut r, &neg["mutation"]["set"]);
        expect(name, want, r.tried(&c));
        assert_eq!(c.record_of(&r.ua), None, "{name}");
    }
    assert_eq!(seen, 48);
}

/// `classical-msig-with-kem` (`msig-classical`'s members are disabled kinds here): an in-test classical-dominant `msig`.
#[test]
fn ua8_classical_msig_with_kem() {
    let (env, c) = setup();
    let e = test::ed(21);
    let ua = e.register(&env, &c);
    let m = msig(&env, 1, &[(0x0102, ua.to_array(), 1)]);
    let neg = derived(PORTABLE, "negatives", "classical-msig-with-kem");
    assert_eq!(neg["error"], "UAKemHolder");
    let attrs = UaAttrs { kem: kem_key(&env, &hx(&neg["mutation"]["set"]["attrs.kemPk"])), ..no_attrs(&env) };
    let got = c.try_register_msig(&m.s, &attrs, &SVec::new(&env), &Bytes::new(&env), &None);
    assert_eq!(err(got), Error::KemHolder);
    let attrs = UaAttrs { pqz_key: portable(&env, &format!("mldsa65/{SET}")).attrs.pqz_key, pqz_pop_hash: n(&env, [1; 32]), ..no_attrs(&env) };
    assert_eq!(err(c.try_register_msig(&m.s, &attrs, &SVec::new(&env), &Bytes::new(&env), &None)), Error::PqzHolder);
}

/// `KemKey.scheme` is a `u32` on Soroban: 0x101 would be scheme 1 in the assembled first byte.
#[test]
fn ua8_kem_scheme_above_a_byte_refused() {
    let (env, c) = setup();
    let mut r = portable(&env, &format!("mldsa65/{SET}"));
    r.attrs.kem.scheme = 0x101;
    assert_eq!(r.refused(&c), Error::KemScheme);
}

#[test]
fn ua8_checked_of_shape() {
    let (env, c, r) = registered(&format!("mldsa65/{SET}"));
    assert_eq!(c.checked_of(&r.ua), (Checked::Chain, Checked::None, Checked::Chain));
    let plain = portable(&env, "mldsa65#1");
    plain.on(&c);
    assert_eq!(c.checked_of(&plain.ua), (Checked::Chain, Checked::None, Checked::None));
    assert_eq!(c.checked_of(&n(&env, [0x42; 32])), (Checked::None, Checked::None, Checked::None));
}

/// U8S-D4: the largest row's events fit the 16,384 B limit; `UaRegistered`'s `attrs` hold no bytes; the hashes are logged.
#[test]
fn ua8_events_fit_and_hash() {
    let (env, c) = setup();
    let r = portable(&env, "msig-pq/n2816-kmax65536");
    members(&env, &c, r.kind);
    r.on(&c);
    let all = env.events().all();
    let evs = all.events();
    let size: usize = evs.iter().map(|e| e.to_xdr(Limits::none()).unwrap().len()).sum();
    std::println!("register msig-pq/n2816-kmax65536: {} events, {size} B", evs.len());
    assert!(size < 16_384, "{size}");
    let sig_hash: BytesN<32> = env.crypto().keccak256(&Bytes::new(&env)).into();
    let stored = UaAttrs { pqz_key: Bytes::new(&env), kem: KemKey::none(&env), ..r.attrs.clone() };
    let rec = c.record_of(&r.ua).unwrap();
    assert_eq!(rec.attrs, stored);
    let reg = UaRegistered {
        ua: r.ua.clone(),
        kind: r.kind,
        record: RegisteredRecord {
            kind: r.kind,
            key_data: r.kd.clone(),
            attrs: stored,
            pop_hash: env.crypto().keccak256(&r.pop).into(),
            pop_checked: Checked::Chain,
            pqz_pop_checked: Checked::None,
            proven: false,
            signable: true,
            index: 0,
            ledger: env.ledger().sequence(),
        },
        checked: Checked::Chain,
    };
    let pqz = UaPqzKeySet {
        ua: r.ua.clone(),
        pqz_key_hash: pqz_key_hash(&env, &r.attrs.pqz_key),
        pqz_pop_hash: r.attrs.pqz_pop_hash.clone(),
        sig_hash: sig_hash.clone(),
        checked: Checked::Chain,
    };
    let proof = UaPqzPopStored { ua: r.ua.clone(), pqz_pop_hash: r.attrs.pqz_pop_hash.clone() };
    let kem = UaKemKeySet {
        ua: r.ua.clone(),
        version: 0,
        kem_pk_hash: env.crypto().keccak256(&kem_pk(&env, &r.attrs.kem)).into(),
        sig_hash,
        checked: Checked::Chain,
    };
    let want = [pqz.to_xdr(&env, &c.address), proof.to_xdr(&env, &c.address), kem.to_xdr(&env, &c.address), reg.to_xdr(&env, &c.address)];
    assert_eq!(evs, want);
}

#[test]
fn ua8_entries_extend_ttl() {
    let (env, c, r) = registered(&format!("mldsa65/{SET}"));
    let ua = r.ua.clone();
    env.as_contract(&c.address, || crate::put(&env, &Key::KemMax(ua.clone()), &0u64)); // written by `set_kem_key`, B3
    let keys = [Key::PqzK(ua.clone()), Key::PqzP(ua.clone()), Key::Kem(ua.clone(), 0), Key::KemMax(ua.clone())];
    let ttl = |k: &Key| env.as_contract(&c.address, || env.storage().persistent().get_ttl(k));
    for k in &keys {
        assert_eq!(ttl(k), 60 * DAY);
    }
    env.ledger().with_mut(|l| l.sequence_number += 31 * DAY);
    for k in &keys {
        assert_eq!(ttl(k), 29 * DAY);
    }
    c.registration_of(&ua).unwrap();
    c.checked_of(&ua);
    for k in &keys {
        assert_eq!(ttl(k), 60 * DAY, "extended on read");
    }
}

/// `Attrs` keeps its code point, unused: T3's refused cases now register, or are their own error (`register_attrs_accepted`).
#[test]
fn ua8_attrs_error_unused() {
    assert_eq!(Error::Attrs as u32, 7);
    for name in [format!("mldsa65/{SET}"), format!("msig-pq/{SET}")] {
        registered(&name);
    }
    let (env, c) = setup();
    let mut r = portable(&env, "p256");
    r.attrs.pqz_key = b(&env, &[1; 16_384]);
    assert_ne!(r.refused(&c), Error::Attrs);
}

/// `msig` has one typed form, as EVM: `register` refuses the kind; a value its `u16` cannot hold is `KeyData`, never a
/// truncated id; the assembled bytes are the row's key data (its id comes back).
#[test]
fn ua8_register_msig_typed() {
    let (env, c, r) = registered(&format!("msig-pq/{SET}"));
    let refused = |s: &MsigStructure| err(c.try_register_msig(s, &no_attrs(&env), &SVec::new(&env), &Bytes::new(&env), &None));
    let e = err(c.try_register(&0x0120, &r.kd, &no_attrs(&env), &Bytes::new(&env), &Bytes::new(&env), &None));
    assert_eq!(e, Error::KeyData);
    let good = structure_of(&env, &vecu8(&r.kd)).unwrap();
    assert_eq!(refused(&MsigStructure { threshold: 0x1_0002, ..good.clone() }), Error::KeyData);
    let member = |i: u32, f: fn(&mut MsigMember)| {
        let mut s = good.clone();
        let mut m = s.members.get(i).unwrap();
        f(&mut m);
        s.members.set(i, m);
        s
    };
    assert_eq!(refused(&member(0, |m| m.kind += 0x1_0000)), Error::KeyData);
    assert_eq!(refused(&member(1, |m| m.weight += 0x1_0000)), Error::KeyData);
    let mut many = good.clone();
    for i in 0..15u8 {
        many.members.push_back(MsigMember { kind: 0x0131, id: n(&env, [0xa0 + i; 32]), weight: 1 });
    }
    assert_eq!(refused(&many), Error::KeyData);
    assert_eq!(refused(&MsigStructure { threshold: 1, members: SVec::new(&env) }), Error::KeyData);
}

/// TS-D12: a single key is `signature` only; `key_data` and `members` set are `Unauthorized` before any verify.
#[test]
fn ua8_require_authorized_uasig_fields() {
    let (env, c) = setup();
    let s = test::ed(22);
    let ua = s.register(&env, &c);
    let (d, p) = (n(&env, [0x11; 32]), PURPOSE_METATX);
    let good = UaSig::single(&env, s.sign(&env, &test::msg(&env, 0x0102, p, &d)));
    let pt = n(&env, p);
    c.require_authorized(&ua, &pt, &d, &good);
    let extra = UaSig { key_data: b(&env, &[1]), ..good.clone() };
    assert_eq!(err(c.try_require_authorized(&ua, &pt, &d, &extra)), Error::Unauthorized);
    let mut members = SVec::new(&env);
    members.push_back(MemberSig { index: 0, key_data: Bytes::new(&env), sig: Bytes::new(&env) });
    let extra = UaSig { members, ..good };
    assert_eq!(err(c.try_require_authorized(&ua, &pt, &d, &extra)), Error::Unauthorized);
}

/// TS-D5: `kind_name` is EVM's table (`kinds.json`); any other id, one above `u16` too, is `KindUnknown`.
#[test]
fn ua8_kind_name_table() {
    let (env, c) = setup();
    let v = json(KINDS);
    let mut known = StdVec::new();
    for r in v["kinds"].as_array().unwrap().iter().chain(v["schemes"].as_array().unwrap()) {
        let kind = kind_of(&r["kind"]);
        assert_eq!(c.kind_name(&kind), soroban_sdk::String::from_str(&env, r["name"].as_str().unwrap()));
        known.push(kind);
    }
    assert_eq!(known.len(), 32);
    for kind in (0..0x0200).chain([0x1_0120, u32::MAX]).filter(|k| !known.contains(k)) {
        assert_eq!(err(c.try_kind_name(&kind)), Error::KindUnknown, "{kind:#x}");
    }
}
