//! B2, B3 (U8S-D3–D7): `register` with PQZ / KEM attributes and the later writes against `portable.json` (the authority
//! for bytes): the bytes stay in contract state, unproven, and `registration_of` returns exactly the `register` arguments,
//! as EVM `registrationOf`.
extern crate std;
use std::{format, vec::Vec as StdVec};

use serde_json::Value;
use soroban_sdk::{
    testutils::{storage::Persistent as _, Address as _, Events as _, Ledger as _},
    xdr::{Limits, WriteXdr},
    Address, Bytes, BytesN, Env, Event as _, Vec as SVec,
};

use crate::{
    test::{self, err, kem_key, msig, n, no_attrs, portable, portable_row, setup, structure_of, vecu8, Reg, PORTABLE},
    test_verify::{b, derived, hx, json, kind_of, n32},
    Error, Key, RegisteredRecord, UaKemKeySet, UaPqzKeySet, UaPqzPopStored, UaRegistered, UaRegistryClient,
};
use scaas_ua_common::*;

const KINDS: &str = include_str!("../../../../vectors/ua/kinds.json");
const DAY: u32 = 17_280;
const CHAIN: [u32; 7] = [0x0100, 0x0101, 0x0102, 0x0108, 0x0120, 0x0130, 0x0131];
const SET: &str = "n2048-kmax1024";

type Entry = (Bytes, Bytes, Checked);
type PqzEntry = (Bytes, Bytes, Checked, BytesN<32>);
type Tried<T> = Result<Result<T, soroban_sdk::ConversionError>, Result<soroban_sdk::Error, soroban_sdk::InvokeError>>;
type Slot = (u32, StdVec<u8>, StdVec<u8>);

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
/// `set_kem_key(ua, 0, …)` (`ua8_kem_commit_filled_once`), `registration_of` returns the committed form; the commit's own
/// rules.
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
    let pqz = (r.attrs.pqz_key.clone(), none.clone(), Checked::Chain, r.attrs.pqz_pop_hash.clone());
    assert_eq!(entry::<PqzEntry>(&env, &c, &Key::PqzK(r.ua.clone())), Some(pqz));
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

/// `attrs.pqz_key` comes from `PqzK` iff `register` carried one: a later key and its proof are no `register` arguments, so
/// the arguments read back unchanged.
#[test]
fn ua8_registration_of_reassembles() {
    let (env, c, r) = registered("msig-pq-native");
    pqz_id(&env, &format!("msig-pq-native/{SET}")).set(&c);
    c.store_pqz_pop(&r.ua, &portable(&env, &format!("mldsa65/{SET}")).pqz_pop);
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

/// U8S-D5's map; `UAPoP` and `UAUnauthorized` are that error or a host error (plan finding F1: a host verify traps).
fn expect<T: core::fmt::Debug>(name: &str, want: &str, got: Tried<T>) {
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
        "UAUnauthorized" => {
            assert!(contract.as_ref().map_or(true, |x| *x == Error::Unauthorized), "{name}: {e:?}");
            return;
        }
        "UAPqzPopHash" => Error::PqzPopHash,
        "UAKeyData" => Error::KeyData,
        "UAPqzHolder" => Error::PqzHolder,
        "UAKemHolder" => Error::KemHolder,
        "UAKemKeyLength" => Error::KemKeyLength,
        "UAKemScheme" => Error::KemScheme,
        "UAPqzKeySet" => Error::PqzKeySet,
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
        if name == "kem-record-as-registration" {
            // The row's 666 B FN-DSA signature cannot reach ML-DSA-65's verify: a real signature of this key and length.
            let rows = json(PORTABLE)["kemRecords"].as_array().unwrap().clone();
            let k = rows.iter().find(|x| x["id"] == "mldsa65/v1").unwrap();
            assert_eq!(n32(&env, &k["ua"]), r.ua);
            r.pop = b(&env, &hx(&k["sig"]));
        }
        expect(name, want, r.tried(&c));
        assert_eq!(c.record_of(&r.ua), None, "{name}");
    }
    assert_eq!(seen, 48);
}

/// A `pop` is bound to its purpose and to its record, each alone: a real signature by the registering key over the right
/// digest under purpose `kem`, then under purpose `pop` v2 over the UA's own KEM record (the vector
/// `kem-record-as-registration`, a disabled kind's row here, on an enabled kind). Only the right pair registers.
#[test]
fn ua8_pop_purpose_and_record_separated() {
    let (env, c) = setup();
    let s = test::ml(23);
    let (ua, kind, kd) = (s.ua(&env), s.kind(), s.key_data(&env));
    let attrs = UaAttrs { kem: portable(&env, &format!("mldsa65/{SET}")).attrs.kem, ..no_attrs(&env) };
    let pk = kem_pk(&env, &attrs.kem);
    let zero = n(&env, [0; 32]);
    let rec = portable_record_hash(&env, &ua, kind, &zero, &kem_pk_record_hash(&env, &ua, 0, &pk));
    let reg: BytesN<32> = registration_digest(&env, &rec, &zero).into();
    let tried = |p: [u8; 32], d: &BytesN<32>| {
        let pop = s.sign(&env, &test::msg(&env, kind, p, d));
        c.try_register(&kind, &kd, &attrs, &pop, &Bytes::new(&env), &None)
    };
    expect("the registration under purpose kem", "UAPoP", tried(PURPOSE_KEM, &reg));
    expect("the KEM record under purpose pop v2", "UAPoP", tried(PURPOSE_POP_V2, &kem_record_digest(&env, &ua, 0, &pk).to_bytes()));
    assert_eq!(tried(PURPOSE_POP_V2, &reg).unwrap().unwrap(), ua);
}

/// The typed `ua_of` forms are the packed one's ids (packed-bytes inventory).
#[test]
fn ua8_ua_of_typed() {
    let (env, c) = setup();
    let row = derived(PORTABLE, "registrations", "webauthn-p256");
    let a = &row["args"]["key"];
    let key = WebAuthnKey { x: n32(&env, &a["x"]), y: n32(&env, &a["y"]), rp_id_hash: n32(&env, &a["rpIdHash"]) };
    assert_eq!(c.ua_of_webauthn(&key), n32(&env, &row["ua"]));
    let r = portable(&env, &format!("msig-pq/{SET}"));
    let s = structure_of(&env, &vecu8(&r.kd)).unwrap();
    assert_eq!(c.ua_of_msig(&s), r.ua);
    assert_eq!(c.ua_of(&r.kind, &r.kd), r.ua);
    assert_eq!(err(c.try_ua_of_msig(&MsigStructure { threshold: 0x1_0002, ..s })), Error::KeyData);
}

/// TS-D13: `register_webauthn` from the row's typed `args.key` is the packed `register`: the same id, the same record.
#[test]
fn ua8_register_webauthn_typed() {
    let (env, c) = setup();
    let row = derived(PORTABLE, "registrations", "webauthn-p256");
    let r = portable_row(&env, &row);
    let a = &row["args"]["key"];
    assert_eq!(row["args"]["entry"], "registerWebAuthn");
    let key = WebAuthnKey { x: n32(&env, &a["x"]), y: n32(&env, &a["y"]), rp_id_hash: n32(&env, &a["rpIdHash"]) };
    let none = Bytes::new(&env);
    let other = WebAuthnKey { rp_id_hash: n(&env, [1; 32]), ..key.clone() };
    expect("another rpIdHash", "UAPoP", c.try_register_webauthn(&other, &r.attrs, &r.pop, &none, &None));
    assert_eq!(c.register_webauthn(&key, &r.attrs, &r.pop, &none, &None), r.ua);
    assert_eq!(c.registration_of(&r.ua), Some((r.kind, r.kd.clone(), r.attrs.clone(), r.pop.clone(), none)));
    assert_eq!(r.refused(&c), Error::AlreadyRegistered, "one record, either form");
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
    kem_id(&env, "mldsa65/v1").set(&c);
    let keys = [Key::PqzK(ua.clone()), Key::PqzP(ua.clone()), Key::Kem(ua.clone(), 0), Key::Kem(ua.clone(), 1), Key::KemMax(ua.clone())];
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
    let short = UaSig::single(&env, b(&env, &[1]));
    assert_eq!(err(c.try_require_authorized(&ua, &pt, &d, &short)), Error::Unauthorized, "the caller's error, as EVM");
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

// ---------- B3: `set_kem_key`, `set_pqz_key`, `store_pqz_pop`, the views (U8S-D3, D4, D6, D7; TS-D9) ----------

/// A record's typed `args.sig` (EVM `UASig`).
fn typed_sig(env: &Env, s: &Value) -> UaSig {
    let mut members = SVec::new(env);
    for m in s["members"].as_array().unwrap() {
        members.push_back(MemberSig { index: m["index"].as_u64().unwrap() as u32, key_data: b(env, &hx(&m["keyData"])), sig: b(env, &hx(&m["sig"])) });
    }
    UaSig { key_data: b(env, &hx(&s["keyData"])), signature: b(env, &hx(&s["signature"])), members }
}

/// A `kemRecords[]` row: its typed arguments and the bytes stored for `sig`.
#[derive(Clone)]
struct KemRow {
    ua: BytesN<32>,
    version: u64,
    kem: KemKey,
    sig: UaSig,
    stored: Bytes,
}

impl KemRow {
    fn tried(&self, c: &UaRegistryClient) -> Tried<()> {
        c.try_set_kem_key(&self.ua, &self.version, &self.kem, &self.sig, &None)
    }
    fn set(&self, c: &UaRegistryClient) {
        self.tried(c).unwrap().unwrap()
    }
    fn view(&self) -> (KemKey, Bytes, Checked) {
        (self.kem.clone(), self.stored.clone(), Checked::Chain)
    }
}

fn kem_row(env: &Env, r: &Value) -> KemRow {
    KemRow {
        ua: n32(env, &r["ua"]),
        version: r["version"].as_u64().unwrap(),
        kem: kem_key(env, &hx(&r["kemPk"])),
        sig: typed_sig(env, &r["args"]["sig"]),
        stored: b(env, &hx(&r["sig"])),
    }
}

fn kem_id(env: &Env, id: &str) -> KemRow {
    kem_row(env, json(PORTABLE)["kemRecords"].as_array().unwrap().iter().find(|r| r["id"] == id).unwrap())
}

/// A `pqzKeyRecords[]` row, likewise.
#[derive(Clone)]
struct PqzRow {
    ua: BytesN<32>,
    key: Bytes,
    pop_hash: BytesN<32>,
    sig: UaSig,
    stored: Bytes,
}

impl PqzRow {
    fn tried(&self, c: &UaRegistryClient) -> Tried<()> {
        c.try_set_pqz_key(&self.ua, &self.key, &self.pop_hash, &self.sig, &None)
    }
    fn set(&self, c: &UaRegistryClient) {
        self.tried(c).unwrap().unwrap()
    }
}

fn pqz_row(env: &Env, r: &Value) -> PqzRow {
    PqzRow {
        ua: n32(env, &r["ua"]),
        key: b(env, &hx(&r["pqzKey"])),
        pop_hash: n32(env, &r["pqzPopHash"]),
        sig: typed_sig(env, &r["args"]["sig"]),
        stored: b(env, &hx(&r["sig"])),
    }
}

fn pqz_id(env: &Env, name: &str) -> PqzRow {
    pqz_row(env, &derived(PORTABLE, "pqzKeyRecords", name))
}

fn negatives(entry: &str) -> StdVec<Value> {
    json(PORTABLE)["negatives"].as_array().unwrap().iter().filter(|x| x["entry"] == entry).cloned().collect()
}

/// A registered classical-dominant `msig`: not a holder.
fn classical(env: &Env, c: &UaRegistryClient) -> BytesN<32> {
    let e = test::ed(36);
    e.register(env, c);
    msig(env, 1, &[(0x0102, e.ua(env).to_array(), 1)]).register(env, c, &SVec::new(env))
}

/// A registered `p256`, standing in for `slhdsa128s`, a disabled kind here until B4: not a holder.
fn non_holder(env: &Env, c: &UaRegistryClient) -> BytesN<32> {
    assert_eq!(portable(env, "slhdsa128s").refused(c), Error::KindDisabled);
    portable(env, "p256").on(c)
}

/// 2-of-(1, 2) of in-test `mldsa65` keys, the weight-1 member first (so the old rule passes both slots), registered by the
/// weight-2 slot alone (U8S-D1).
fn msig_1_2(env: &Env, c: &UaRegistryClient) -> (test::Msig, test::Sk, test::Sk) {
    let (mut one, mut two) = (test::ml(31), test::ml(32));
    if one.ua(env).to_array() > two.ua(env).to_array() {
        core::mem::swap(&mut one, &mut two);
    }
    one.register(env, c);
    two.register(env, c);
    let m = msig(env, 2, &[(0x0131, one.ua(env).to_array(), 1), (0x0131, two.ua(env).to_array(), 2)]);
    m.register(env, c, &test::member_sigs(env, &[m.slot(env, &two, PURPOSE_POP_V2, &test::reg_digest(env, &m.ua, 0x0120))]));
    (m, one, two)
}

/// Versions 3, 1, 2 (P4): `kem_key_of` follows the highest; a repeated version and the `register` version are `KemVersion`,
/// and version 0 with nothing committed too (a key given in whole at `register` is not refillable, TS-D9).
#[test]
fn ua8_kem_any_order_write_once() {
    let (env, c, r) = registered(&format!("mldsa65/{SET}"));
    let [v1, v2, v3] = [1, 2, 3].map(|v| kem_id(&env, &format!("mldsa65/v{v}")));
    let (whole, none) = (r.attrs.kem.clone(), UaSig::none(&env));
    let (of, no_sig) = (|v: &KemRow| Some((v.version, v.kem.clone(), v.stored.clone(), Checked::Chain)), Bytes::new(&env));
    let register_key = (whole.clone(), no_sig.clone(), Checked::Chain);
    assert_eq!(c.kem_key_of(&r.ua), Some((0, whole.clone(), no_sig, Checked::Chain)), "the `register` key alone");
    assert_eq!(c.kem_key_at(&r.ua, &1), None);
    v3.set(&c);
    assert_eq!(c.kem_key_of(&r.ua), of(&v3));
    for v in [&v1, &v2] {
        v.set(&c);
        assert_eq!(c.kem_key_of(&r.ua), of(&v3), "a lower version is stored, the highest stays");
        assert_eq!(c.kem_key_at(&r.ua, &v.version), Some(v.view()));
    }
    assert_eq!(err(v2.tried(&c)), Error::KemVersion);
    assert_eq!(err(c.try_set_kem_key(&r.ua, &0, &whole, &none, &None)), Error::KemVersion);
    assert_eq!(c.kem_key_at(&r.ua, &0), Some(register_key));
    assert_eq!(c.kem_key_at(&r.ua, &3), Some(v3.view()));
    assert_eq!(c.checked_of(&r.ua).2, Checked::Chain);
    let plain = portable(&env, "mldsa65#1");
    plain.on(&c);
    assert_eq!(c.kem_key_of(&plain.ua), None);
    assert_eq!(err(c.try_set_kem_key(&plain.ua, &0, &whole, &none, &None)), Error::KemVersion, "nothing committed");
}

/// Every `kemRecords[]` row of a `Chain` holder from its typed arguments: an `msig`'s stored `sig` is the row's
/// `abi.encode(MemberSig[])`, a single key's the signature; the `register` arguments do not move. `fndsa512` rows: B4.
#[test]
fn ua8_kem_from_vectors() {
    let rows = json(PORTABLE)["kemRecords"].as_array().unwrap().clone();
    let mut seen = 0;
    for name in [format!("mldsa65/{SET}"), format!("msig-pq/{SET}")] {
        let (env, c, r) = registered(&name);
        let before = c.registration_of(&r.ua);
        for row in rows.iter().filter(|x| n32(&env, &x["ua"]) == r.ua) {
            let k = kem_row(&env, row);
            k.set(&c);
            assert_eq!(c.kem_key_at(&r.ua, &k.version), Some(k.view()), "{}", row["id"]);
            assert_eq!(c.kem_key_of(&r.ua).unwrap().0, k.version, "{}", row["id"]);
            seen += 1;
        }
        assert_eq!(c.registration_of(&r.ua), before, "{name}");
    }
    assert_eq!(seen, 6);
    let (env, c) = setup();
    assert_eq!(portable(&env, "fndsa512").refused(&c), Error::KindDisabled);
    assert_eq!(rows.iter().filter(|x| kind_of(&x["kind"]) == 0x0132).count() + seen, rows.len());
}

/// `set_kem_key(ua, 0, …)` fills the `register` commit once: no signature (the `pop` signed it), open to anyone, the key
/// must hash to the commit (`KemKeyHash`), and `registration_of` keeps the committed form, as EVM.
#[test]
fn ua8_kem_commit_filled_once() {
    for name in [format!("mldsa65/{SET}"), format!("msig-pq/{SET}")] {
        let (env, c) = setup();
        let whole = portable(&env, &name).attrs.kem;
        let r = commit_of(&env, &name);
        members(&env, &c, r.kind);
        r.on(&c);
        let (none, no_sig) = (UaSig::none(&env), Bytes::new(&env));
        let fill = |k: &KemKey, s: &UaSig| c.try_set_kem_key(&r.ua, &0, k, s, &None);
        assert_eq!(err(fill(&kem_id(&env, "mldsa65/v1").kem, &none)), Error::KemKeyHash, "{name}");
        assert_eq!(err(fill(&KemKey { scheme: 2, ..whole.clone() }, &none)), Error::KemScheme, "{name}");
        assert_eq!(err(fill(&whole, &UaSig::single(&env, b(&env, &[1])))), Error::Unauthorized, "{name}");
        assert_eq!(c.kem_key_of(&r.ua), None, "{name}");
        fill(&whole, &none).unwrap().unwrap();
        assert_eq!(c.kem_key_of(&r.ua), Some((0, whole.clone(), no_sig.clone(), Checked::Chain)), "{name}");
        assert_eq!(c.kem_key_at(&r.ua, &0), Some((whole.clone(), no_sig, Checked::Chain)), "{name}");
        assert_eq!(c.checked_of(&r.ua).2, Checked::Chain, "{name}");
        assert_eq!(c.registration_of(&r.ua).unwrap().2, r.attrs, "{name}: the committed form, filled or not");
        assert_eq!(err(fill(&whole, &none)), Error::KemVersion, "{name}");
    }
}

/// U8S-D5, D7 in EVM's check order: holder → version → key → signature; `portable.json`'s `setKemKey` negatives.
#[test]
fn ua8_kem_rules() {
    let (env, c, r) = registered(&format!("mldsa65/{SET}"));
    let k = kem_id(&env, "mldsa65/v1");
    let refused = |kem: &KemKey| err(c.try_set_kem_key(&r.ua, &1, kem, &k.sig, &None));
    assert_eq!(refused(&KemKey::none(&env)), Error::KemKeyLength);
    assert_eq!(refused(&KemKey { mlkem_ek: k.kem.mlkem_ek.slice(1..), ..k.kem.clone() }), Error::KemKeyLength);
    let mut long = k.kem.mlkem_ek.clone();
    long.push_back(0);
    assert_eq!(refused(&KemKey { mlkem_ek: long, ..k.kem.clone() }), Error::KemKeyLength);
    for scheme in [0, 2, 3, 0xff, 0x101] {
        assert_eq!(refused(&KemKey { scheme, ..k.kem.clone() }), Error::KemScheme, "{scheme:#x}");
    }
    assert_eq!(refused(&KemKey { scheme: 2, mlkem_ek: Bytes::new(&env), ..k.kem.clone() }), Error::KemScheme, "the scheme first");
    let (p, m) = (non_holder(&env, &c), classical(&env, &c));
    for ua in [&p, &m] {
        assert_eq!(err(c.try_set_kem_key(ua, &1, &k.kem, &k.sig, &None)), Error::KemHolder);
        assert_eq!(err(c.try_set_kem_key(ua, &0, &k.kem, &k.sig, &None)), Error::KemHolder, "holder before version");
        assert_eq!(c.kem_key_of(ua), None);
    }
    let unknown = n(&env, [0x42; 32]);
    assert_eq!(err(c.try_set_kem_key(&unknown, &1, &k.kem, &k.sig, &None)), Error::NotRegistered);
    k.set(&c);
    assert_eq!(refused(&KemKey::none(&env)), Error::KemVersion, "version before key");
    for neg in negatives("setKemKey") {
        let (name, set) = (neg["name"].as_str().unwrap(), &neg["mutation"]["set"]);
        let mut k = kem_id(&env, neg["mutation"]["row"].as_str().unwrap());
        k.version += 10; // a free version of `r`: the row's own is taken above
        if let Some(sig) = set.get("sig") {
            k.sig = UaSig::single(&env, b(&env, &hx(sig)));
        }
        if let Some(ua) = set.get("ua") {
            k.ua = n32(&env, ua);
        }
        assert_eq!(k.ua, r.ua, "{name}");
        expect(name, neg["error"].as_str().unwrap(), k.tried(&c));
    }
    let bad = KemRow { version: 4, sig: UaSig::single(&env, b(&env, &[1])), ..k.clone() };
    assert_eq!(err(bad.tried(&c)), Error::Unauthorized, "a signature of the wrong length is the caller's error");
}

/// CTR-UA-32: anyone submits, a relayer is accepted and ignored for chain-verified parts (SOR-D6), and there is no owner
/// check (two UAs may list one key); a signature by another UA is refused.
#[test]
fn ua8_kem_by_third_party() {
    let (env, c) = setup();
    let kem = kem_id(&env, "mldsa65/v1").kem;
    let pk = kem_pk(&env, &kem);
    let (a, z) = (test::ml(33), test::ml(34));
    let signed = |s: &test::Sk, ua: &BytesN<32>| {
        let d = kem_record_digest(&env, ua, 1, &pk).to_bytes();
        UaSig::single(&env, s.sign(&env, &test::msg(&env, s.kind(), PURPOSE_KEM, &d)))
    };
    let (ua, other) = (a.register(&env, &c), z.register(&env, &c));
    expect("signed by another UA", "UAUnauthorized", c.try_set_kem_key(&ua, &1, &kem, &signed(&z, &ua), &None));
    c.set_kem_key(&ua, &1, &kem, &signed(&a, &ua), &Some(Address::generate(&env)));
    c.set_kem_key(&other, &1, &kem, &signed(&z, &other), &None);
    assert_eq!(c.kem_key_of(&ua).unwrap().1, c.kem_key_of(&other).unwrap().1, "one key, two UAs");
}

/// U8S-D1: a stored `msig` signature is minimal; both slots verify and reach the threshold, but the weight-2 slot alone is
/// enough: `Unauthorized`, on both writes. The weight-1 slot alone is short; the weight-2 slot alone is stored.
#[test]
fn msig_kem_sig_not_minimal_refused() {
    let (env, c) = setup();
    let (m, one, two) = msig_1_2(&env, &c);
    let kem = kem_id(&env, "mldsa65/v1").kem;
    let d = kem_record_digest(&env, &m.ua, 1, &kem_pk(&env, &kem)).to_bytes();
    let (s1, s2) = (m.slot(&env, &one, PURPOSE_KEM, &d), m.slot(&env, &two, PURPOSE_KEM, &d));
    let tried = |s: &[Slot]| c.try_set_kem_key(&m.ua, &1, &kem, &test::msig_auth(&env, s), &None);
    assert_eq!(err(tried(&[s1.clone(), s2.clone()])), Error::Unauthorized);
    assert_eq!(err(tried(&[s1])), Error::Unauthorized);
    tried(&[s2]).unwrap().unwrap();

    let (key, ph) = (b(&env, &[7; 16_384]), n(&env, [9; 32]));
    let d = pqz_key_record_digest(&env, &m.ua, &pqz_key_hash(&env, &key), &ph).to_bytes();
    let (s1, s2) = (m.slot(&env, &one, PURPOSE_PQZ_KEY, &d), m.slot(&env, &two, PURPOSE_PQZ_KEY, &d));
    let tried = |s: &[Slot]| c.try_set_pqz_key(&m.ua, &key, &ph, &test::msig_auth(&env, s), &None);
    assert_eq!(err(tried(&[s1.clone(), s2.clone()])), Error::Unauthorized);
    tried(&[s2]).unwrap().unwrap();
}

/// TS-D12 on the two writes: a single key only `signature`, an `msig` only `members`, `key_data` never.
#[test]
fn ua8_portable_sig_fields() {
    let (env, c, _) = registered(&format!("mldsa65/{SET}"));
    let k = kem_id(&env, "mldsa65/v1");
    let slot = || {
        let mut v = SVec::new(&env);
        v.push_back(MemberSig { index: 0, key_data: Bytes::new(&env), sig: b(&env, &[1]) });
        v
    };
    for sig in [UaSig { key_data: b(&env, &[1]), ..k.sig.clone() }, UaSig { members: slot(), ..k.sig.clone() }, UaSig::none(&env)] {
        assert_eq!(err(KemRow { sig, ..k.clone() }.tried(&c)), Error::Unauthorized);
    }
    let (env, c, _) = registered(&format!("msig-pq/{SET}"));
    let k = kem_id(&env, "msig-pq/v1");
    for sig in [UaSig { key_data: b(&env, &[1]), ..k.sig.clone() }, UaSig { signature: b(&env, &[1]), ..k.sig.clone() }, UaSig::none(&env)] {
        assert_eq!(err(KemRow { sig, ..k.clone() }.tried(&c)), Error::Unauthorized);
    }
    let (env, c, _) = registered("msig-pq-native");
    let p = pqz_id(&env, &format!("msig-pq-native/{SET}"));
    for sig in [UaSig { key_data: b(&env, &[1]), ..p.sig.clone() }, UaSig { signature: b(&env, &[1]), ..p.sig.clone() }, UaSig::none(&env)] {
        assert_eq!(err(PqzRow { sig, ..p.clone() }.tried(&c)), Error::Unauthorized);
    }
}

/// `pqzKeyRecords[]` of a `Chain` holder: `msig-pq-native` (`fndsa512`'s rows: B4), its `evm-eoa` slot over the typed record
/// digest. The key is in `PqzK`, unproven, no `Key` entry; the `register` arguments do not move.
#[test]
fn ua8_set_pqz_key_from_vectors() {
    let rows = json(PORTABLE)["pqzKeyRecords"].as_array().unwrap().clone();
    let mut seen = 0;
    for row in rows.iter().filter(|x| kind_of(&x["kind"]) == 0x0120) {
        let name = row["name"].as_str().unwrap();
        let (env, c, r) = registered("msig-pq-native");
        let p = pqz_row(&env, row);
        assert_eq!(p.ua, r.ua, "{name}");
        let (args, rec) = (c.registration_of(&r.ua), c.record_of(&r.ua));
        assert_eq!(c.pqz_key_of(&r.ua), None, "{name}");
        p.set(&c);
        assert_eq!(c.registration_of(&r.ua), args, "{name}");
        assert_eq!(c.record_of(&r.ua), rec, "{name}: `Ua(ua)` is not rewritten");
        assert_eq!(c.pqz_key_of(&r.ua), Some((p.key.clone(), p.pop_hash.clone(), false, Checked::Chain)), "{name}");
        assert_eq!(c.pqz_key_sig_of(&r.ua), p.stored, "{name}");
        assert_eq!(c.checked_of(&r.ua).1, Checked::None, "{name}");
        assert_eq!(c.key_owner(&pqz_key_hash(&env, &p.key)), None, "{name}");
        assert_eq!(c.ua_count(&0x0142), 0, "{name}");
        seen += 1;
    }
    assert_eq!(seen, 4);
    let (env, c) = setup();
    assert_eq!(portable(&env, "fndsa512").refused(&c), Error::KindDisabled);
    assert_eq!(rows.iter().filter(|x| kind_of(&x["kind"]) == 0x0132).count() + seen, rows.len());
}

/// U8S-D6: without a verifier nothing is ever replaced, a key of another set neither; a `register` key counts.
#[test]
fn ua8_set_pqz_key_write_once() {
    let (env, c, r) = registered("msig-pq-native");
    let p = pqz_id(&env, &format!("msig-pq-native/{SET}"));
    p.set(&c);
    assert_eq!(err(p.tried(&c)), Error::PqzKeySet);
    assert_eq!(err(pqz_id(&env, "msig-pq-native/n2816-kmax65536").tried(&c)), Error::PqzKeySet);
    assert_eq!(c.pqz_key_of(&r.ua).unwrap().0, p.key);
    let (env, c, r) = registered(&format!("mldsa65/{SET}"));
    let other = PqzRow { ua: r.ua.clone(), ..pqz_id(&env, &format!("msig-pq-native/{SET}")) };
    assert_eq!(err(other.tried(&c)), Error::PqzKeySet);
    let want = (r.attrs.pqz_key.clone(), r.attrs.pqz_pop_hash.clone(), false, Checked::Chain);
    assert_eq!(c.pqz_key_of(&r.ua), Some(want));
    assert!(c.pqz_key_sig_of(&r.ua).is_empty(), "its consent is the `pop`");
}

/// Every `setPqzKey` negative. `fndsa512` and `slhdsa128s` are disabled kinds here (B4): `already-set` runs on the row's
/// `mldsa65/<set>`, `wrong-holder` on `p256`, the others on `mldsa65#1`, a holder without a key.
#[test]
fn ua8_set_pqz_key_negatives() {
    let negs = negatives("setPqzKey");
    assert_eq!(negs.len(), 13);
    for neg in &negs {
        let (name, want, set) = (neg["name"].as_str().unwrap(), neg["error"].as_str().unwrap(), &neg["mutation"]["set"]);
        let (env, c) = setup();
        let row = neg["mutation"]["row"].as_str().unwrap();
        let mut p = pqz_id(&env, row);
        p.ua = match want {
            "UAPqzKeySet" => portable(&env, &format!("mldsa65/{}", row.split('/').nth(1).unwrap())).on(&c),
            "UAPqzHolder" => non_holder(&env, &c),
            _ => portable(&env, "mldsa65#1").on(&c),
        };
        if let Some(sig) = set.get("sig") {
            p.sig = UaSig::single(&env, b(&env, &hx(sig)));
        }
        if let Some(h) = set.get("pqzPopHash") {
            p.pop_hash = n32(&env, h);
        }
        expect(name, want, p.tried(&c));
        assert_eq!(c.pqz_key_of(&p.ua).is_some(), want == "UAPqzKeySet", "{name}");
    }
}

/// EVM's check order: holder → key already there → length → proof hash → signature; every refused bytes leaves no key.
#[test]
fn ua8_set_pqz_key_rules() {
    let (env, c, r) = registered("msig-pq-native");
    let p = pqz_id(&env, &format!("msig-pq-native/{SET}"));
    let unknown = PqzRow { ua: n(&env, [0x42; 32]), ..p.clone() };
    assert_eq!(err(unknown.tried(&c)), Error::NotRegistered);
    for len in [0, 1, 16_383, 16_385, 14_336, 24_576] {
        let bad = PqzRow { key: b(&env, &std::vec![7; len]), pop_hash: n(&env, [0; 32]), ..p.clone() };
        assert_eq!(err(bad.tried(&c)), Error::KeyData, "{len}: the length before the proof hash");
    }
    assert_eq!(err(PqzRow { pop_hash: n(&env, [0; 32]), ..p.clone() }.tried(&c)), Error::PqzPopHash);
    let (ua, m) = (non_holder(&env, &c), classical(&env, &c));
    for ua in [ua, m] {
        assert_eq!(err(PqzRow { ua, ..p.clone() }.tried(&c)), Error::PqzHolder);
    }
    let mut key = vecu8(&p.key);
    key[0] ^= 1;
    let tampered = PqzRow { key: b(&env, &key), ..p.clone() };
    assert_eq!(err(tampered.tried(&c)), Error::Unauthorized, "the `evm-eoa` slot recovers another address");
    let mut slots = p.sig.members.clone();
    let mut short = slots.get(1).unwrap();
    short.sig = b(&env, &[1]);
    slots.set(1, short);
    let bad = PqzRow { sig: UaSig::msig(&env, slots), ..p.clone() };
    assert_eq!(err(bad.tried(&c)), Error::Unauthorized, "a slot of the wrong length");
    assert_eq!(c.pqz_key_of(&r.ua), None);
    p.set(&c);
    let late = PqzRow { key: b(&env, &[7; 1]), ..p.clone() };
    assert_eq!(err(late.tried(&c)), Error::PqzKeySet, "before the length");
}

/// A proof given later hashes to the stored `pqz_pop_hash`: it reads back as a `register` argument for a `register` key,
/// and only from `pqz_pop_of` for a later key (EVM `registrationOf`). Unproven either way.
#[test]
fn ua8_store_pqz_pop_hash_checked() {
    let (env, c) = setup();
    let mut r = portable(&env, &format!("mldsa65/{SET}"));
    let proof = core::mem::replace(&mut r.pqz_pop, Bytes::new(&env));
    r.on(&c);
    c.store_pqz_pop(&r.ua, &proof);
    assert_eq!(c.pqz_pop_of(&r.ua), proof);
    assert_eq!(c.registration_of(&r.ua).unwrap().4, proof);
    assert_eq!(c.pqz_key_of(&r.ua).unwrap().2, false);
    assert_eq!(c.checked_of(&r.ua).1, Checked::None);

    let (env, c, r) = registered("msig-pq-native");
    let p = pqz_id(&env, &format!("msig-pq-native/{SET}"));
    let proof = portable(&env, &format!("mldsa65/{SET}")).pqz_pop;
    assert_eq!(err(c.try_store_pqz_pop(&r.ua, &proof)), Error::PqzPopHash, "no key yet");
    p.set(&c);
    c.store_pqz_pop(&r.ua, &proof);
    assert_eq!(c.pqz_pop_of(&r.ua), proof);
    assert!(c.registration_of(&r.ua).unwrap().4.is_empty());
}

/// Stored: a no-op without an event, for a proof that came with `register` too; other bytes are still refused.
#[test]
fn ua8_store_pqz_pop_idempotent() {
    let (env, c) = setup();
    let mut r = portable(&env, &format!("mldsa65/{SET}"));
    let proof = core::mem::replace(&mut r.pqz_pop, Bytes::new(&env));
    r.on(&c);
    let events = || env.events().all().events().len();
    c.store_pqz_pop(&r.ua, &proof);
    assert_eq!(events(), 1);
    c.store_pqz_pop(&r.ua, &proof);
    assert_eq!(events(), 0);
    assert_eq!(err(c.try_store_pqz_pop(&r.ua, &b(&env, &[1]))), Error::PqzPopHash);
    let (env, c, r) = registered(&format!("mldsa65/{SET}"));
    c.store_pqz_pop(&r.ua, &r.pqz_pop);
    assert_eq!(env.events().all().events().len(), 0);
    assert_eq!(c.pqz_pop_of(&r.ua), r.pqz_pop);
}

#[test]
fn ua8_store_pqz_pop_negatives() {
    let negs = negatives("storePqzPop");
    assert_eq!(negs.len(), 4);
    for neg in &negs {
        let (name, m) = (neg["name"].as_str().unwrap(), &neg["mutation"]);
        let (env, c) = setup();
        let mut r = portable(&env, m["row"].as_str().unwrap());
        mutate(&env, &mut r, &m["registerWith"]);
        r.on(&c);
        expect(name, neg["error"].as_str().unwrap(), c.try_store_pqz_pop(&r.ua, &b(&env, &hx(&m["set"]["pqzPop"]))));
        assert!(c.pqz_pop_of(&r.ua).is_empty(), "{name}");
    }
    let (env, c) = setup();
    let plain = portable(&env, "mldsa65#1");
    plain.on(&c);
    let (proof, none) = (portable(&env, &format!("mldsa65/{SET}")).pqz_pop, Bytes::new(&env));
    assert_eq!(err(c.try_store_pqz_pop(&plain.ua, &proof)), Error::PqzPopHash, "no key: the hash is 0");
    assert_eq!(err(c.try_store_pqz_pop(&plain.ua, &none)), Error::PqzPopHash, "an empty proof is no proof");
    assert_eq!(err(c.try_store_pqz_pop(&n(&env, [0x42; 32]), &proof)), Error::NotRegistered);
}

/// U8S-D4: the three writes log hashes, the bytes are read from the views; an `msig` signature fits the events limit.
#[test]
fn ua8_set_events_hash_only() {
    let (env, c, r) = registered(&format!("msig-pq/{SET}"));
    let k = kem_id(&env, "msig-pq/v1");
    k.set(&c);
    let kem = UaKemKeySet {
        ua: r.ua.clone(),
        version: 1,
        kem_pk_hash: env.crypto().keccak256(&kem_pk(&env, &k.kem)).into(),
        sig_hash: env.crypto().keccak256(&k.stored).into(),
        checked: Checked::Chain,
    };
    assert_eq!(env.events().all().events(), [kem.to_xdr(&env, &c.address)]);

    let (env, c, r) = registered("msig-pq-native");
    let p = pqz_id(&env, &format!("msig-pq-native/{SET}"));
    p.set(&c);
    let key = UaPqzKeySet {
        ua: r.ua.clone(),
        pqz_key_hash: pqz_key_hash(&env, &p.key),
        pqz_pop_hash: p.pop_hash.clone(),
        sig_hash: env.crypto().keccak256(&p.stored).into(),
        checked: Checked::Chain,
    };
    assert_eq!(env.events().all().events(), [key.to_xdr(&env, &c.address)]);
    c.store_pqz_pop(&r.ua, &portable(&env, &format!("mldsa65/{SET}")).pqz_pop);
    let proof = UaPqzPopStored { ua: r.ua.clone(), pqz_pop_hash: p.pop_hash.clone() };
    assert_eq!(env.events().all().events(), [proof.to_xdr(&env, &c.address)]);
}

/// The views: a `register` key's PQZ attributes and KEM key, nothing for an unregistered id.
#[test]
fn ua8_views_of_register() {
    let (env, c, r) = registered(&format!("mldsa65/{SET}"));
    let want = (r.attrs.pqz_key.clone(), r.attrs.pqz_pop_hash.clone(), false, Checked::Chain);
    assert_eq!(c.pqz_key_of(&r.ua), Some(want));
    let unknown = n(&env, [0x42; 32]);
    assert_eq!((c.pqz_key_of(&unknown), c.kem_key_of(&unknown), c.kem_key_at(&unknown, &0)), (None, None, None));
    assert!(c.pqz_key_sig_of(&unknown).is_empty());
}

/// B2 review: `register`'s slot refusals are `Pop`: a `G…` slot with bytes, a registered member's slot with `key_data`.
#[test]
fn ua8_register_slot_fields_pop() {
    let (env, c) = setup();
    let q = test::ml(35);
    q.register(&env, &c);
    let g = [0x44; 32];
    let m = msig(&env, 2, &[(0x0011, g, 1), (0x0131, q.ua(&env).to_array(), 1)]);
    let refused = |s: &[Slot]| err(c.try_register_msig(&m.s, &no_attrs(&env), &test::member_sigs(&env, s), &Bytes::new(&env), &None));
    assert_eq!(refused(&[(m.index(&g), std::vec![], std::vec![1])]), Error::Pop);
    let (i, _, sig) = m.slot(&env, &q, PURPOSE_POP_V2, &test::reg_digest(&env, &m.ua, 0x0120));
    assert_eq!(refused(&[(i, std::vec![1], sig)]), Error::Pop);
}

/// `set_pqz_key` by an n-of-n `msig` of in-test `mldsa65` keys, weight 1 each: every slot signs, so `PqzK` holds `n` of
/// them. The contract and the key are real; only the size matters here, so the key is not a set's key material.
fn pqz_key_by_n_of_n(len: usize, count: u8) {
    let (env, c) = setup();
    let keys: StdVec<test::Sk> = (0..count).map(|i| test::ml(0x40 + i)).collect();
    keys.iter().for_each(|k| {
        k.register(&env, &c);
    });
    let list: StdVec<_> = keys.iter().map(|k| (0x0131u16, k.ua(&env).to_array(), 1u16)).collect();
    let m = msig(&env, count as u16, &list);
    let slots = |purpose: [u8; 32], d: &BytesN<32>| {
        let mut v: StdVec<Slot> = keys.iter().map(|k| m.slot(&env, k, purpose, d)).collect();
        v.sort_by_key(|s| s.0);
        v
    };
    m.register(&env, &c, &test::member_sigs(&env, &slots(PURPOSE_POP_V2, &test::reg_digest(&env, &m.ua, 0x0120))));
    let (key, ph) = (b(&env, &std::vec![7; len]), n(&env, [9; 32]));
    let d = pqz_key_record_digest(&env, &m.ua, &pqz_key_hash(&env, &key), &ph).to_bytes();
    c.set_pqz_key(&m.ua, &key, &ph, &test::msig_auth(&env, &slots(PURPOSE_PQZ_KEY, &d)), &None);
    assert_eq!(c.pqz_key_of(&m.ua).unwrap().0, key);
    let size: usize = entry::<PqzEntry>(&env, &c, &Key::PqzK(m.ua.clone())).map(|e| (e.0.len() + e.1.len()) as usize).unwrap();
    std::println!("set_pqz_key {count}-of-{count}, key {len} B: key + sig {size} B");
}

/// B0's published maximum under U8S-D3 (`PqzK` = key + `sig`, one 65,536 B entry): the largest number of signing ML-DSA-65
/// slots is 13 at n2048-kmax1024 / n2304-kmax4096 and 12 at n2560-kmax16384 / n2816-kmax65536. The SDK's metering enforces
/// the entry limit in this test env, without Wasm or the transaction envelope.
#[test]
fn ua8_set_pqz_key_msig_largest_fits() {
    for (len, count) in [(16_384, 13), (18_432, 13), (20_480, 12), (22_528, 12)] {
        pqz_key_by_n_of_n(len, count);
    }
}

#[test]
#[should_panic(expected = "contract data entry")]
fn ua8_set_pqz_key_msig_over_limit_n2816() {
    pqz_key_by_n_of_n(22_528, 13);
}

#[test]
#[should_panic(expected = "contract data entry")]
fn ua8_set_pqz_key_msig_over_limit_n2048() {
    pqz_key_by_n_of_n(16_384, 14);
}
