// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! B2, B3 (U8S-D3–D7): `register` with PQZ / KEM attributes and the later writes against `portable.json` (the authority
//! for bytes): the bytes stay in contract state, unproven, and `registration_of` returns exactly the `register` arguments,
//! as EVM `registrationOf`. B4 (U8S-D8, UA8-D18–D20): the relayer-checked mode, a listed relayer's auth mocked. B7 (C15): the
//! bytes read back against the vector, `ua8-roundtrip.json`.
extern crate std;
use std::{format, vec, vec::Vec as StdVec};

use serde_json::Value;
use soroban_sdk::{
    testutils::{storage::{Instance as _, Persistent as _}, Address as _, Events as _, Ledger as _, MockAuth, MockAuthInvoke},
    xdr::{Limits, WriteXdr},
    Address, Bytes, BytesN, Env, Event as _, IntoVal, Vec as SVec,
};

use crate::{
    digest,
    test::{self, err, kem_key, msig, n, no_attrs, portable, portable_row, setup, structure_of, vecu8, Reg, PORTABLE},
    test_verify::{b, derived, hx, json, kind_of, n32},
    Error, Key, RegisteredRecord, UaKemKeySet, UaPqzKeySet, UaPqzPopStored, UaRegistered, UaRegistryClient,
};
use scaas_ua_common::*;

const KINDS: &str = include_str!("../../../../vectors/ua/kinds.json");
const DAY: u32 = 17_280;
const CHAIN: [u32; 7] = [0x0100, 0x0101, 0x0102, 0x0108, 0x0120, 0x0130, 0x0131];
/// U8S-D8: every other derived kind the off-chain verifier checks.
const RELAYER: [u32; 12] = [0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0110, 0x0111, 0x0112, 0x0113, 0x0132, 0x0133, 0x0141];
const SET: &str = "n2048-kmax1024";

type Entry = (Bytes, Bytes, Checked);
type PqzEntry = (Bytes, Bytes, Checked, BytesN<32>);
type Tried<T> = Result<Result<T, soroban_sdk::ConversionError>, Result<soroban_sdk::Error, soroban_sdk::InvokeError>>;
type Slot = (u32, StdVec<u8>, StdVec<u8>);
/// A host verify's failure as the caller sees it (plan finding F1): the contract cannot answer `Unauthorized` for it.
pub(crate) const HOST_REFUSED: soroban_sdk::Error = soroban_sdk::Error::from_type_and_code(soroban_sdk::xdr::ScErrorType::Context, soroban_sdk::xdr::ScErrorCode::InvalidAction);

/// A registry listing one relayer, whose auth is mocked; the relayer as the entries take it.
pub(crate) fn relayed() -> (Env, UaRegistryClient<'static>, Option<Address>) {
    let env = test::new_env();
    let relayer = Address::generate(&env);
    let c = test::deploy(&env, &[relayer.clone()]);
    env.mock_all_auths();
    (env, c, Some(relayer))
}

/// A KEM key of the vectors, for an in-test `msig`'s record.
pub(crate) fn kem_row_key(env: &Env) -> KemKey {
    kem_id(env, "mldsa65/v1").kem
}

/// The `Relayer` mark of `relayed()`'s relayer.
fn marked(by: &Option<Address>) -> Checked {
    Checked::Relayer(by.clone().unwrap())
}

/// `x` with its first byte flipped: same form, not the same signature.
pub(crate) fn flipped(env: &Env, x: &Bytes) -> Bytes {
    let mut v = vecu8(x);
    v[0] ^= 1;
    b(env, &v)
}

/// The `registrations[]` rows of a U8S-D8 `Relayer` kind; the four group kinds have no row here, only `kinds.json`'s.
fn offchain_rows() -> StdVec<Value> {
    let rows = json(PORTABLE)["registrations"].as_array().unwrap().clone();
    rows.into_iter().filter(|r| RELAYER.contains(&kind_of(&r["kind"]))).collect()
}

/// The `registrations[]` rows of a `Chain` kind (`msig-classical`, on relayer-checked members: `ua8_relayer_classical_msig_row`).
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
    let (env, c, _) = relayed();
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

/// U8S-D5's map; `UAPoP` and `UAUnauthorized` are that error or the host's refusal (plan finding F1: a host verify traps).
fn expect<T: core::fmt::Debug>(name: &str, want: &str, got: Tried<T>) {
    let e = match got {
        Err(Ok(e)) => e,
        other => panic!("{name}: {other:?}"),
    };
    let contract = Error::try_from(e);
    let code = match want {
        "UAPoP" => {
            assert!(e == HOST_REFUSED || contract == Ok(Error::Pop), "{name}: {e:?}");
            return;
        }
        "UAUnauthorized" => {
            assert!(e == HOST_REFUSED || contract == Ok(Error::Unauthorized), "{name}: {e:?}");
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

/// Every `register` negative on its own row, a listed relayer given, so the row's rule alone refuses: the row itself then
/// registers (U8S-D8). Three `fndsa512` rows want `UAPoP`, a signature the chain cannot verify: here they are `NotVerifiable`
/// without a relayer, a listed relayer that signs them stores them (P11.6, `ua8_relayer_bad_record_takes_slot_marked`), and
/// the rule itself runs on `mldsa65/<set>`, a holder with a KEM key the mutation can change.
#[test]
fn ua8_negatives_from_portable_json() {
    let negs = json(PORTABLE)["negatives"].as_array().unwrap().clone();
    let (mut seen, mut offchain) = (0, 0);
    for neg in negs.iter().filter(|x| x["entry"] == "register") {
        let (name, want) = (neg["name"].as_str().unwrap(), neg["error"].as_str().unwrap());
        seen += 1;
        let (env, c, by) = relayed();
        if neg["registration"].is_object() {
            let r = portable_row(&env, &neg["registration"]);
            members(&env, &c, r.kind);
            expect(name, want, r.tried_by(&c, &by));
            assert_eq!(c.record_of(&r.ua), None, "{name}");
            continue;
        }
        let mut row = format!("{}", neg["mutation"]["row"].as_str().unwrap());
        if row == "msig-classical" {
            classical_members(&env, &c, &by);
        }
        let mut r = portable(&env, &row);
        members(&env, &c, r.kind);
        mutate(&env, &mut r, &neg["mutation"]["set"]);
        if RELAYER.contains(&r.kind) && want == "UAPoP" {
            assert_eq!(r.refused(&c), Error::NotVerifiable, "{name}");
            offchain += 1;
            row = format!("mldsa65/{SET}");
            r = portable(&env, &row);
            mutate(&env, &mut r, &neg["mutation"]["set"]);
        }
        if name == "kem-record-as-registration" {
            // The row's 666 B FN-DSA signature cannot reach ML-DSA-65's verify: a real signature of this key and length.
            let rows = json(PORTABLE)["kemRecords"].as_array().unwrap().clone();
            let k = rows.iter().find(|x| x["id"] == "mldsa65/v1").unwrap();
            assert_eq!(n32(&env, &k["ua"]), r.ua);
            r.pop = b(&env, &hx(&k["sig"]));
        }
        expect(name, want, r.tried_by(&c, &by));
        assert_eq!(c.record_of(&r.ua), None, "{name}");
        assert_eq!(portable(&env, &row).on_by(&c, &by), r.ua, "{name}: the row itself");
    }
    assert_eq!((seen, offchain), (48, 3));
}

/// A `pop` is bound to its purpose and to its record, each alone: a real signature by the registering key over the right
/// digest under purpose `kem`, then under purpose `pop` v2 over the UA's own KEM record (the vector
/// `kem-record-as-registration`, whose `fndsa512` row the chain cannot verify, on a `Chain` kind). Only the right pair
/// registers.
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

/// EVM `msigOf` and `webAuthnKeyOf` on the bytes EVM's `test_typedViewsMatchTheRows` reads: each view is its row's typed `args`, whatever form
/// registered it, and the empty form for an id of another kind or no record. `ua8_relayer_group_kinds_typed` has the MuSig2 and FROST views.
#[test]
fn ua8_typed_views_match_the_rows() {
    let (env, c) = setup();
    let none = Bytes::new(&env);
    let (no_key, no_msig) = (WebAuthnKey { x: n(&env, [0; 32]), y: n(&env, [0; 32]), rp_id_hash: n(&env, [0; 32]) }, MsigStructure { threshold: 0, members: SVec::new(&env) });
    let row = derived(PORTABLE, "registrations", "webauthn-p256");
    let r = portable_row(&env, &row);
    assert_eq!((c.web_authn_key_of(&r.ua), c.msig_of(&r.ua)), (no_key.clone(), no_msig.clone()), "no record");
    r.on(&c);
    let a = &row["args"]["key"];
    assert_eq!(c.web_authn_key_of(&r.ua), WebAuthnKey { x: n32(&env, &a["x"]), y: n32(&env, &a["y"]), rp_id_hash: n32(&env, &a["rpIdHash"]) });
    assert_eq!(c.msig_of(&r.ua), no_msig);
    assert_eq!((c.mu_sig2_key_of(&r.ua).agg_key, c.frost_key_of(&r.ua).group_key), (none.clone(), none));
    let (env2, c2, m) = registered(&format!("msig-pq/{SET}"));
    let row = derived(PORTABLE, "registrations", &format!("msig-pq/{SET}"));
    let want = &row["args"]["structure"];
    let got = c2.msig_of(&m.ua);
    assert_eq!(got.threshold as u64, want["threshold"].as_u64().unwrap());
    let members: StdVec<(u32, BytesN<32>, u32)> = got.members.iter().map(|x| (x.kind, x.id, x.weight)).collect();
    let rows: StdVec<(u32, BytesN<32>, u32)> = want["members"].as_array().unwrap().iter().map(|x| (kind_of(&x["kind"]), n32(&env2, &x["id"]), kind_of(&x["weight"]))).collect();
    assert_eq!(members, rows);
    assert_eq!(c2.web_authn_key_of(&m.ua).x, n(&env2, [0; 32]));
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

/// `classical-msig-with-kem` (its own row: `ua8_negatives_from_portable_json`) on an in-test classical-dominant `msig` of a
/// `Chain` member, and the PQZ twin.
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

/// Every write extends the contract's instance, `relayers()` too, and no other view: the list stays live while the registry is used.
#[test]
fn ua8_instance_ttl() {
    let (env, c) = setup();
    let ttl = || env.as_contract(&c.address, || env.storage().instance().get_ttl());
    assert_eq!(ttl(), 60 * DAY, "from the constructor");
    env.ledger().with_mut(|l| l.sequence_number += 31 * DAY);
    let r = portable(&env, "mldsa65#1");
    assert_eq!(c.record_of(&r.ua), None);
    assert_eq!(ttl(), 29 * DAY, "a view leaves it");
    r.on(&c);
    assert_eq!(ttl(), 60 * DAY, "extended by the write");
    env.ledger().with_mut(|l| l.sequence_number += 31 * DAY);
    assert_eq!(ttl(), 29 * DAY);
    c.relayers();
    assert_eq!(ttl(), 60 * DAY, "`relayers()` extends it");
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
    fn tried_by(&self, c: &UaRegistryClient, relayer: &Option<Address>) -> Tried<()> {
        c.try_set_kem_key(&self.ua, &self.version, &self.kem, &self.sig, relayer)
    }
    fn tried(&self, c: &UaRegistryClient) -> Tried<()> {
        self.tried_by(c, &None)
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
    fn tried_by(&self, c: &UaRegistryClient, relayer: &Option<Address>) -> Tried<()> {
        c.try_set_pqz_key(&self.ua, &self.key, &self.pop_hash, &self.sig, relayer)
    }
    fn tried(&self, c: &UaRegistryClient) -> Tried<()> {
        self.tried_by(c, &None)
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

/// A registered `slhdsa128s`, through the listed relayer of `relayed()`: not a holder, whoever checked it.
fn non_holder(env: &Env, c: &UaRegistryClient) -> BytesN<32> {
    portable(env, "slhdsa128s").on_by(c, &Some(c.relayers().get(0).unwrap()))
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
/// `abi.encode(MemberSig[])`, a single key's the signature; the `register` arguments do not move. `fndsa512` rows:
/// `ua8_relayer_fndsa512_kem_and_pqz`.
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

/// `pqzKeyRecords[]` of a `Chain` holder: `msig-pq-native` (`fndsa512`'s rows: `ua8_relayer_fndsa512_kem_and_pqz`), its `evm-eoa` slot over the typed record
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

/// Every `setPqzKey` negative on its own row, a registered `fndsa512` with a listed relayer given, so the row's rule alone
/// refuses: the row itself then stores. `already-set` and `wrong-holder` go to the UA the row names, `mldsa65/<set>` and
/// `slhdsa128s`. `signed-by-other-ua` is a signature the chain cannot verify on `fndsa512`: `NotVerifiable` there without a
/// relayer. Its rule runs on `mldsa65#2`, the signature being `mldsa65#1`'s: it reaches the host's verify, so the exact
/// refusal is `HOST_REFUSED`.
#[test]
fn ua8_set_pqz_key_negatives() {
    let negs = negatives("setPqzKey");
    assert_eq!(negs.len(), 13);
    for neg in &negs {
        let (name, want, set) = (neg["name"].as_str().unwrap(), neg["error"].as_str().unwrap(), &neg["mutation"]["set"]);
        let (env, c, by) = relayed();
        let row = neg["mutation"]["row"].as_str().unwrap();
        let good = pqz_id(&env, row);
        assert_eq!(portable(&env, "fndsa512").on_by(&c, &by), good.ua, "{name}");
        let mut p = good.clone();
        if let Some(sig) = set.get("sig") {
            p.sig = UaSig::single(&env, b(&env, &hx(sig)));
        }
        if let Some(h) = set.get("pqzPopHash") {
            p.pop_hash = n32(&env, h);
        }
        if let Some(ua) = set.get("ua") {
            let other = if want == "UAPqzKeySet" { format!("mldsa65/{}", row.split('/').nth(1).unwrap()) } else { "slhdsa128s".into() };
            assert_eq!(portable(&env, &other).on_by(&c, &by), n32(&env, ua), "{name}");
            p.ua = n32(&env, ua);
        }
        if want == "UAUnauthorized" {
            assert_eq!(err(p.tried(&c)), Error::NotVerifiable, "{name}");
            p.ua = portable(&env, "mldsa65#2").on(&c);
            assert_eq!(p.tried_by(&c, &by), Err(Ok(HOST_REFUSED)), "{name}");
        } else {
            expect(name, want, p.tried_by(&c, &by));
        }
        assert_eq!(c.pqz_key_of(&p.ua).is_some(), want == "UAPqzKeySet", "{name}");
        assert_eq!(c.pqz_key_of(&good.ua), None, "{name}");
        good.tried_by(&c, &by).unwrap().unwrap();
    }
}

/// `set_pqz_key` on a single key, which `pqzKeyRecords[]` has no `Chain` row for: anyone submits, a relayer is accepted and
/// ignored, no owner check (no `Key` entry, U8S-D6: two UAs may list one key). A signature by another UA is refused by the
/// host's verify (plan finding F1), not by the contract; only the holder's own is stored.
#[test]
fn ua8_set_pqz_key_single_key() {
    let (env, c) = setup();
    let (key, ph) = (b(&env, &[7; 16_384]), n(&env, [9; 32]));
    let (a, z) = (test::ml(37), test::ml(38));
    let signed = |s: &test::Sk, ua: &BytesN<32>| {
        let d = pqz_key_record_digest(&env, ua, &pqz_key_hash(&env, &key), &ph).to_bytes();
        s.sign(&env, &test::msg(&env, s.kind(), PURPOSE_PQZ_KEY, &d))
    };
    let (ua, other) = (a.register(&env, &c), z.register(&env, &c));
    let tried = |ua: &BytesN<32>, sig: &Bytes, r: &Option<Address>| c.try_set_pqz_key(ua, &key, &ph, &UaSig::single(&env, sig.clone()), r);
    assert_eq!(tried(&ua, &signed(&z, &ua), &None), Err(Ok(HOST_REFUSED)), "signed by another UA");
    assert_eq!(c.pqz_key_of(&ua), None);
    let own = signed(&a, &ua);
    tried(&ua, &own, &Some(Address::generate(&env))).unwrap().unwrap();
    assert_eq!(c.pqz_key_of(&ua), Some((key.clone(), ph.clone(), false, Checked::Chain)));
    assert_eq!(c.pqz_key_sig_of(&ua), own);
    tried(&other, &signed(&z, &other), &None).unwrap().unwrap();
    assert_eq!(c.pqz_key_of(&other).unwrap().0, key, "one key, two UAs");
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
/// `q` alone meets the threshold, so the `key_data` is all that refuses that slot: the same slot without it registers.
#[test]
fn ua8_register_slot_fields_pop() {
    let (env, c) = setup();
    let q = test::ml(35);
    q.register(&env, &c);
    let g = [0x44; 32];
    let m = msig(&env, 2, &[(0x0011, g, 1), (0x0131, q.ua(&env).to_array(), 2)]);
    let refused = |s: &[Slot]| err(c.try_register_msig(&m.s, &no_attrs(&env), &test::member_sigs(&env, s), &Bytes::new(&env), &None));
    assert_eq!(refused(&[(m.index(&g), std::vec![], std::vec![1])]), Error::Pop);
    let (i, _, sig) = m.slot(&env, &q, PURPOSE_POP_V2, &test::reg_digest(&env, &m.ua, 0x0120));
    assert_eq!(refused(&[(i, std::vec![1], sig.clone())]), Error::Pop);
    assert_eq!(m.register(&env, &c, &test::member_sigs(&env, &[(i, std::vec![], sig)])), m.ua);
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

// ---------- B4: the relayer-checked mode (U8S-D8, UA8-D18–D20, spec §6, P11) ----------

const METATX: [u8; 32] = PURPOSE_METATX;

/// A host auth failure as the caller sees it: any host trap in contract code reads the same (B3), so a refusal of it counts
/// beside the relayer's own auth of the same call storing.
const AUTH_REFUSED: soroban_sdk::Error = HOST_REFUSED;

/// `kinds.json`'s `valid[]` rows of the `Relayer` kinds.
fn valid_rows() -> StdVec<Value> {
    json(KINDS)["valid"].as_array().unwrap().iter().filter(|r| RELAYER.contains(&kind_of(&r["kind"]))).cloned().collect()
}

/// `msig-classical`'s derived members; its fourth is an `evm-eoa`.
pub(crate) fn classical_members(env: &Env, c: &UaRegistryClient, by: &Option<Address>) {
    for name in ["bls-bn254-minsig", "schnorr-bn254", "p256"] {
        portable(env, name).on_by(c, by);
    }
}

fn sorted(mut s: StdVec<Slot>) -> StdVec<Slot> {
    s.sort_by_key(|x| x.0);
    s
}

fn msig_tried(env: &Env, c: &UaRegistryClient, m: &test::Msig, s: &[Slot], by: &Option<Address>) -> Tried<BytesN<32>> {
    c.try_register_msig(&m.s, &no_attrs(env), &test::member_sigs(env, s), &Bytes::new(env), by)
}

/// A relayer-checked member's slot: bytes the chain never reads, the relayer's to check (P11.1).
fn attested(m: &test::Msig, id: &BytesN<32>, len: usize) -> Slot {
    (m.index(&id.to_array()), vec![], vec![0xf5; len])
}

/// `RelayerNotListed` needs the list to refuse: the outsider's auth is mocked, and the listed relayer stores the same bytes
/// on all three writes.
#[test]
fn ua8_relayer_unlisted_refused() {
    let (env, c, by) = relayed();
    let other = Some(Address::generate(&env));
    let r = portable(&env, "fndsa512");
    assert_eq!(err(r.tried_by(&c, &other)), Error::RelayerNotListed);
    assert_eq!(c.record_of(&r.ua), None);
    r.on_by(&c, &by);
    let k = kem_id(&env, "fndsa512/v1");
    assert_eq!(err(k.tried_by(&c, &other)), Error::RelayerNotListed);
    k.tried_by(&c, &by).unwrap().unwrap();
    let p = pqz_id(&env, &format!("fndsa512/{SET}"));
    assert_eq!(err(p.tried_by(&c, &other)), Error::RelayerNotListed);
    p.tried_by(&c, &by).unwrap().unwrap();
    assert_eq!(c.relayers(), SVec::from_array(&env, [by.unwrap()]));
    let (env, c) = setup();
    assert_eq!(err(portable(&env, "fndsa512").tried_by(&c, &Some(Address::generate(&env)))), Error::RelayerNotListed, "an empty list");
}

/// `relayer`'s auth of the one word `attest` asks for: the auth is an entry on `function`, over `digest_of`'s digest of `args`.
pub(crate) fn authorise(env: &Env, c: &UaRegistryClient, relayer: &Address, function: &str, digest_of: &str, args: SVec<soroban_sdk::Val>) {
    let d = attest_digest(env, &c.address, digest_of, args);
    env.mock_auths(&[MockAuth { address: relayer, invoke: &MockAuthInvoke { contract: &c.address, fn_name: function, args: (d,).into_val(env), sub_invokes: &[] } }]);
}

/// Listed, no auth: the host refuses. An auth for another call is no auth either; only the relayer's auth of this very call
/// stores, on each of the three writes.
#[test]
fn ua8_relayer_must_authorise() {
    let env = test::new_env();
    let relayer = Address::generate(&env);
    let c = test::deploy(&env, &[relayer.clone()]);
    let by = Some(relayer.clone());
    let allow = |f: &str, args: soroban_sdk::Vec<soroban_sdk::Val>| authorise(&env, &c, &relayer, f, f, args);
    let r = portable(&env, "fndsa512");
    let args = |pop: &Bytes| (r.kind, r.kd.clone(), r.attrs.clone(), pop.clone(), r.pqz_pop.clone(), by.clone()).into_val(&env);
    assert_eq!(r.tried_by(&c, &by), Err(Ok(AUTH_REFUSED)));
    allow("register", args(&flipped(&env, &r.pop)));
    assert_eq!(r.tried_by(&c, &by), Err(Ok(AUTH_REFUSED)), "an auth of other arguments");
    assert_eq!(c.record_of(&r.ua), None);
    allow("register", args(&r.pop));
    assert_eq!(r.on_by(&c, &by), r.ua);
    assert_eq!(env.auths()[0].0, relayer);
    assert_eq!(c.record_of(&r.ua).unwrap().pop_checked, marked(&by));

    let k = kem_id(&env, "fndsa512/v1");
    env.set_auths(&[]);
    assert_eq!(k.tried_by(&c, &by), Err(Ok(AUTH_REFUSED)));
    allow("set_kem_key", (k.ua.clone(), k.version, k.kem.clone(), k.sig.clone(), by.clone()).into_val(&env));
    k.tried_by(&c, &by).unwrap().unwrap();
    let p = pqz_id(&env, &format!("fndsa512/{SET}"));
    env.set_auths(&[]);
    assert_eq!(p.tried_by(&c, &by), Err(Ok(AUTH_REFUSED)));
    allow("set_pqz_key", (p.ua.clone(), p.key.clone(), p.pop_hash.clone(), p.sig.clone(), by.clone()).into_val(&env));
    p.tried_by(&c, &by).unwrap().unwrap();
}

/// Every `portable.json` row of a `Relayer` kind: the row's bytes, `Relayer(id)` in the record, `checked_of` and the event,
/// the relayer really asked, never a signer and never receivable. `kind`'s tag and group are real: the row's id comes back.
#[test]
fn ua8_relayer_checked_every_offchain_kind() {
    let rows = offchain_rows();
    assert_eq!(rows.len(), 8);
    for row in rows {
        let name = row["name"].as_str().unwrap();
        let (env, c, by) = relayed();
        let r = portable_row(&env, &row);
        assert_eq!(r.on_by(&c, &by), r.ua, "{name}");
        let last = env.events().all().events().last().unwrap().clone();
        assert_eq!((env.auths().len(), env.auths()[0].0.clone()), (1, by.clone().unwrap()), "{name}");
        let rec = c.record_of(&r.ua).unwrap();
        let (ua, m) = (r.ua.clone(), marked(&by));
        let want = RegisteredRecord {
            kind: r.kind,
            key_data: r.kd.clone(),
            attrs: UaAttrs { kem: KemKey::none(&env), ..r.attrs.clone() },
            pop_hash: env.crypto().keccak256(&r.pop).into(),
            pop_checked: m.clone(),
            pqz_pop_checked: Checked::None,
            proven: false,
            signable: false,
            index: 0,
            ledger: env.ledger().sequence(),
        };
        assert_eq!(last, UaRegistered { ua, kind: r.kind, record: want, checked: m.clone() }.to_xdr(&env, &c.address), "{name}");
        assert_eq!((rec.pop_checked, rec.pqz_pop_checked, rec.proven, rec.signable), (m.clone(), Checked::None, false, false), "{name}");
        assert!(!c.receivable(&r.ua), "{name}");
        assert_eq!(c.checked_of(&r.ua).0, m, "{name}");
        assert_eq!(c.pop_of(&r.ua), r.pop, "{name}: everything to re-check is stored");
        assert_eq!(c.registration_of(&r.ua), Some((r.kind, r.kd.clone(), r.attrs.clone(), r.pop.clone(), r.pqz_pop.clone())), "{name}");
        assert_eq!((c.ua_of(&r.kind, &r.kd), c.ua_count(&r.kind), c.ua_at(&r.kind, &0)), (r.ua.clone(), 1, r.ua.clone()), "{name}");
        assert_eq!(c.key_owner(&crate::key_hash(&env, r.kind, &r.kd).unwrap()), Some(r.ua.clone()), "{name}");
    }
}

/// The same bytes with and without a relayer: `NotVerifiable` is `relayer` alone, on every `Relayer` kind.
#[test]
fn ua8_relayer_kind_without_relayer_not_verifiable() {
    let mut seen = StdVec::new();
    for row in offchain_rows() {
        let (env, c, by) = relayed();
        let r = portable_row(&env, &row);
        assert_eq!(r.refused(&c), Error::NotVerifiable, "{}", row["name"]);
        assert_eq!(c.record_of(&r.ua), None);
        assert_eq!(r.on_by(&c, &by), r.ua);
        seen.push(r.kind);
    }
    for row in valid_rows().iter().filter(|r| (0x0110..=0x0113).contains(&kind_of(&r["kind"]))) {
        let (env, c, by) = relayed();
        let (kind, kd, none) = (kind_of(&row["kind"]), b(&env, &hx(&row["keyData"])), Bytes::new(&env));
        let tried = |r: &Option<Address>| c.try_register(&kind, &kd, &no_attrs(&env), &b(&env, &[1; 64]), &none, r);
        assert_eq!(err(tried(&None)), Error::NotVerifiable, "{}", row["name"]);
        tried(&by).unwrap().unwrap();
        seen.push(kind);
    }
    seen.sort();
    assert_eq!(seen, RELAYER);
}

/// `relayer` changes nothing for a part the chain verifies, on any of the three writes: a flipped signature with a listed
/// relayer is refused, by the rule of its kind. The same call unflipped stores `Chain`, and the relayer is not asked.
#[test]
fn ua8_relayer_mode_still_verifies_chain_parts() {
    for name in ["webauthn-p256", "p256", "ed25519", "secp256k1", "mldsa44", "mldsa65#1"] {
        let (env, c, by) = relayed();
        let mut r = portable(&env, name);
        r.pop = flipped(&env, &r.pop);
        expect(name, "UAPoP", r.tried_by(&c, &by));
        assert_eq!(c.record_of(&r.ua), None, "{name}");
        assert_eq!(portable(&env, name).on_by(&c, &by), r.ua, "{name}");
        assert!(env.auths().is_empty(), "{name}");
        assert_eq!(c.record_of(&r.ua).unwrap().pop_checked, Checked::Chain, "{name}");
    }
    let (env, c, by) = relayed();
    let mut r = portable(&env, "mldsa65#2");
    r.pop = flipped(&env, &r.pop);
    assert_eq!(r.tried_by(&c, &by), Err(Ok(HOST_REFUSED)), "`mldsa65`: the host's verify");

    let (env, c, r) = registered(&format!("mldsa65/{SET}"));
    let by = Some(c.relayers().get(0).unwrap());
    let k = kem_id(&env, "mldsa65/v1");
    let bad = KemRow { sig: UaSig::single(&env, flipped(&env, &k.sig.signature)), ..k.clone() };
    assert_eq!(bad.tried_by(&c, &by), Err(Ok(HOST_REFUSED)));
    assert_eq!(c.kem_key_at(&r.ua, &1), None);
    k.tried_by(&c, &by).unwrap().unwrap();
    assert!(env.auths().is_empty());
    assert_eq!(c.kem_key_at(&r.ua, &1), Some(k.view()));

    let (env, c, r) = registered("msig-pq-native");
    let by = Some(c.relayers().get(0).unwrap());
    let p = pqz_id(&env, &format!("msig-pq-native/{SET}"));
    let bad = PqzRow { key: flipped(&env, &p.key), ..p.clone() };
    assert_eq!(err(bad.tried_by(&c, &by)), Error::Unauthorized, "the `evm-eoa` slot recovers another address");
    assert_eq!(c.pqz_key_of(&r.ua), None);
    p.tried_by(&c, &by).unwrap().unwrap();
    assert!(env.auths().is_empty());
    assert_eq!(c.pqz_key_of(&r.ua).unwrap().3, Checked::Chain);
}

/// An `msig` with a `fndsa512` slot is `Relayer`, on all three writes, and its chain slot is still verified; all `mldsa65` is
/// `Chain` and asks no relayer.
#[test]
fn ua8_relayer_msig_mixed_members() {
    let (env, c, by) = relayed();
    let m_by = marked(&by);
    let f = portable(&env, "fndsa512");
    f.on_by(&c, &by);
    let q = test::ml(61);
    q.register(&env, &c);
    let m = msig(&env, 2, &[(0x0132, f.ua.to_array(), 1), (0x0131, q.ua(&env).to_array(), 1)]);
    let rd = test::reg_digest(&env, &m.ua, 0x0120);
    let (good, other) = (m.slot(&env, &q, PURPOSE_POP_V2, &rd), attested(&m, &f.ua, 666));
    let slots = sorted(vec![good.clone(), other.clone()]);
    assert_eq!(err(msig_tried(&env, &c, &m, &slots, &None)), Error::NotVerifiable);
    assert_eq!(err(msig_tried(&env, &c, &m, &slots, &Some(Address::generate(&env)))), Error::RelayerNotListed);
    let mut bad = good.clone();
    bad.2[0] ^= 1;
    let bad = sorted(vec![bad, other.clone()]);
    assert_eq!(msig_tried(&env, &c, &m, &bad, &by), Err(Ok(HOST_REFUSED)), "the chain slot, whatever `relayer` says");
    assert_eq!(c.record_of(&m.ua), None);
    assert_eq!(msig_tried(&env, &c, &m, &slots, &by).unwrap().unwrap(), m.ua);
    let rec = c.record_of(&m.ua).unwrap();
    assert_eq!((rec.pop_checked, rec.signable), (m_by.clone(), false), "the chain weight 1 is under the threshold 2");
    assert_eq!(c.pop_of(&m.ua), crate::abi::encode_member_sigs(&env, &test::member_sigs(&env, &slots)));
    assert!(!c.receivable(&m.ua));

    let kem = kem_id(&env, "mldsa65/v1").kem;
    let d = kem_record_digest(&env, &m.ua, 1, &kem_pk(&env, &kem)).to_bytes();
    let s = test::msig_auth(&env, &sorted(vec![m.slot(&env, &q, PURPOSE_KEM, &d), attested(&m, &f.ua, 666)]));
    assert_eq!(err(c.try_set_kem_key(&m.ua, &1, &kem, &s, &None)), Error::NotVerifiable);
    c.set_kem_key(&m.ua, &1, &kem, &s, &by);
    assert_eq!(c.kem_key_of(&m.ua).unwrap().3, m_by);
    let (key, ph) = (b(&env, &[7; 16_384]), n(&env, [9; 32]));
    let d = pqz_key_record_digest(&env, &m.ua, &pqz_key_hash(&env, &key), &ph).to_bytes();
    let s = test::msig_auth(&env, &sorted(vec![m.slot(&env, &q, PURPOSE_PQZ_KEY, &d), attested(&m, &f.ua, 666)]));
    assert_eq!(err(c.try_set_pqz_key(&m.ua, &key, &ph, &s, &None)), Error::NotVerifiable);
    c.set_pqz_key(&m.ua, &key, &ph, &s, &by);
    assert_eq!(c.pqz_key_of(&m.ua).unwrap().3, m_by);

    let (env, c, by) = relayed();
    let r = portable(&env, &format!("msig-pq/{SET}"));
    members(&env, &c, r.kind);
    assert_eq!(r.on_by(&c, &by), r.ua);
    assert!(env.auths().is_empty());
    assert_eq!(c.record_of(&r.ua).unwrap().pop_checked, Checked::Chain);
}

/// `checked` follows the slots given, `signable` the chain members: a relayer slot alone is `Relayer`, a chain slot alone of
/// the same structure is `Chain`. A relayer slot never authorises; the chain member of the same `msig` does.
#[test]
fn ua8_relayer_msig_signable_counts_chain_members() {
    let (env, c, by) = relayed();
    let f = portable(&env, "fndsa512");
    f.on_by(&c, &by);
    let (a, q) = (test::ml(62), test::ml(63));
    a.register(&env, &c);
    q.register(&env, &c);
    let m = msig(&env, 1, &[(0x0131, a.ua(&env).to_array(), 1), (0x0132, f.ua.to_array(), 1)]);
    let s = [attested(&m, &f.ua, 666)];
    msig_tried(&env, &c, &m, &s, &by).unwrap().unwrap();
    let rec = c.record_of(&m.ua).unwrap();
    assert_eq!((rec.pop_checked, rec.signable), (marked(&by), true), "the `mldsa65` member alone reaches the threshold");
    let (pt, d) = (n(&env, METATX), n(&env, [0x71; 32]));
    assert_eq!(err(c.try_require_authorized(&m.ua, &pt, &d, &test::msig_auth(&env, &s))), Error::Unauthorized, "a relayer slot never authorises");
    m.accepted_by(&env, &c, &[&a]);
    c.require_authorized(&m.ua, &pt, &d, &test::msig_auth(&env, &[m.slot(&env, &a, METATX, &d)]));

    let m = msig(&env, 1, &[(0x0131, q.ua(&env).to_array(), 1), (0x0132, f.ua.to_array(), 1)]);
    let rd = test::reg_digest(&env, &m.ua, 0x0120);
    msig_tried(&env, &c, &m, &[m.slot(&env, &q, PURPOSE_POP_V2, &rd)], &None).unwrap().unwrap();
    assert_eq!(c.record_of(&m.ua).unwrap().pop_checked, Checked::Chain, "no relayer part, no relayer");

    // The minimal form counts a relayer slot's weight: both reach 2, the weight-2 slot alone does too.
    let (p, fa) = (test::ml(64), f.ua.to_array());
    p.register(&env, &c);
    let m = msig(&env, 2, &[(0x0132, fa, 1), (0x0131, p.ua(&env).to_array(), 2)]);
    let two = m.slot(&env, &p, PURPOSE_POP_V2, &test::reg_digest(&env, &m.ua, 0x0120));
    assert_eq!(err(msig_tried(&env, &c, &m, &sorted(vec![two.clone(), attested(&m, &f.ua, 666)]), &by)), Error::Pop);
    msig_tried(&env, &c, &m, &[two], &by).unwrap().unwrap();
}

/// U8S-D8's member rule: a registered relayer-checked UA of the stated kind. Each refused structure differs from the
/// registered one in that alone.
#[test]
fn ua8_relayer_msig_member_rules() {
    let (env, c, by) = relayed();
    let f = portable(&env, "fndsa512");
    f.on_by(&c, &by);
    let a = test::ml(65);
    a.register(&env, &c);
    let (fa, aa) = (f.ua.to_array(), a.ua(&env).to_array());
    for (kind, id, what) in [(0x0133, fa, "another relayer kind"), (0x0131, fa, "a chain kind"), (0x0132, aa, "a chain record"), (0x0132, [7; 32], "unregistered")] {
        let m = msig(&env, 1, &[(kind, id, 1)]);
        let s = [(0, vec![], vec![0xf5; 666])];
        assert_eq!(err(msig_tried(&env, &c, &m, &s, &by)), Error::MemberUnknown, "{what}");
    }
    let m = msig(&env, 1, &[(0x0132, fa, 1)]);
    msig_tried(&env, &c, &m, &[attested(&m, &f.ua, 666)], &by).unwrap().unwrap();
}

/// Spec §6: an `evm-contract` slot is `Relayer` with a listed relayer, `NotVerifiable` without, and never authorises.
#[test]
fn ua8_relayer_evm_contract_slot() {
    let (env, c, by) = relayed();
    let q = test::ml(66);
    q.register(&env, &c);
    let qa = q.ua(&env).to_array();
    let mut id = [0u8; 32];
    id[12..].copy_from_slice(&[0x22; 20]);
    let m = msig(&env, 2, &[(0x0002, id, 1), (0x0131, qa, 1)]);
    let rd = test::reg_digest(&env, &m.ua, 0x0120);
    let slots = sorted(vec![(m.index(&id), vec![], vec![1; 65]), m.slot(&env, &q, PURPOSE_POP_V2, &rd)]);
    assert_eq!(err(msig_tried(&env, &c, &m, &slots, &None)), Error::NotVerifiable);
    assert_eq!(err(msig_tried(&env, &c, &m, &slots, &Some(Address::generate(&env)))), Error::RelayerNotListed);
    msig_tried(&env, &c, &m, &slots, &by).unwrap().unwrap();
    let rec = c.record_of(&m.ua).unwrap();
    assert_eq!((rec.pop_checked, rec.signable), (marked(&by), false));

    let m = msig(&env, 2, &[(0x0002, id, 1), (0x0131, qa, 2)]);
    let rd = test::reg_digest(&env, &m.ua, 0x0120);
    msig_tried(&env, &c, &m, &[m.slot(&env, &q, PURPOSE_POP_V2, &rd)], &None).unwrap().unwrap();
    let (pt, d) = (n(&env, METATX), n(&env, [0x72; 32]));
    c.accept_membership(&m.ua, &MemberSig { index: m.index(&id), key_data: Bytes::new(&env), sig: b(&env, &[1; 65]) }, &by);
    let slot = test::msig_auth(&env, &[(m.index(&id), vec![], vec![1; 65])]);
    assert_eq!(err(c.try_require_authorized(&m.ua, &pt, &d, &slot)), Error::NotVerifiable, "no attestation at signing");
    c.require_authorized(&m.ua, &pt, &d, &test::msig_auth(&env, &[m.slot(&env, &q, METATX, &d)]));
}

/// `fndsa512`'s own rows: the `register` KEM key takes `pop_checked`, every `kemRecords[]` and `pqzKeyRecords[]` row is
/// `Relayer(id)` in state and event, their signature bytes kept, and the record does not move.
#[test]
fn ua8_relayer_fndsa512_kem_and_pqz() {
    let (env, c, by) = relayed();
    let m = marked(&by);
    let r = portable(&env, "fndsa512");
    r.on_by(&c, &by);
    assert_eq!(c.kem_key_at(&r.ua, &0), Some((r.attrs.kem.clone(), Bytes::new(&env), m.clone())));
    assert_eq!(c.checked_of(&r.ua), (m.clone(), Checked::None, m.clone()));
    let before = c.registration_of(&r.ua);
    for v in 1..=3u64 {
        let k = kem_id(&env, &format!("fndsa512/v{v}"));
        assert_eq!(k.ua, r.ua);
        assert_eq!(err(k.tried(&c)), Error::NotVerifiable, "v{v}");
        k.tried_by(&c, &by).unwrap().unwrap();
        let ev = UaKemKeySet {
            ua: r.ua.clone(),
            version: v,
            kem_pk_hash: env.crypto().keccak256(&kem_pk(&env, &k.kem)).into(),
            sig_hash: env.crypto().keccak256(&k.stored).into(),
            checked: m.clone(),
        };
        assert_eq!(env.events().all().events(), [ev.to_xdr(&env, &c.address)], "v{v}");
        assert_eq!(c.kem_key_at(&r.ua, &v), Some((k.kem.clone(), k.stored.clone(), m.clone())), "v{v}");
    }
    assert_eq!(c.kem_key_of(&r.ua).unwrap().3, m);
    assert_eq!(c.registration_of(&r.ua), before);

    for row in json(PORTABLE)["pqzKeyRecords"].as_array().unwrap().iter().filter(|x| kind_of(&x["kind"]) == 0x0132) {
        let name = row["name"].as_str().unwrap();
        let (env, c, by) = relayed();
        let m = marked(&by);
        let r = portable(&env, "fndsa512");
        r.on_by(&c, &by);
        let p = pqz_row(&env, row);
        assert_eq!(p.ua, r.ua, "{name}");
        assert_eq!(err(p.tried(&c)), Error::NotVerifiable, "{name}");
        assert_eq!(c.pqz_key_of(&r.ua), None, "{name}");
        p.tried_by(&c, &by).unwrap().unwrap();
        let ev = UaPqzKeySet {
            ua: r.ua.clone(),
            pqz_key_hash: pqz_key_hash(&env, &p.key),
            pqz_pop_hash: p.pop_hash.clone(),
            sig_hash: env.crypto().keccak256(&p.stored).into(),
            checked: m.clone(),
        };
        assert_eq!(env.events().all().events(), [ev.to_xdr(&env, &c.address)], "{name}");
        assert_eq!(c.pqz_key_of(&r.ua), Some((p.key.clone(), p.pop_hash.clone(), false, m.clone())), "{name}");
        assert_eq!(c.pqz_key_sig_of(&r.ua), p.stored, "{name}");
    }
}

/// A `fndsa512` PQZ key given at `register` is `pop_checked` too, and filling a hash commit asks no relayer, the chain
/// checks the hash, but the key is the one the relayer-checked `pop` committed: it keeps `pop_checked`.
#[test]
fn ua8_relayer_register_parts_take_pop_checked() {
    let (env, c, by) = relayed();
    let m = marked(&by);
    let whole = portable(&env, "fndsa512").attrs.kem;
    let mut r = commit_of(&env, "fndsa512");
    r.attrs.pqz_key = portable(&env, &format!("mldsa65/{SET}")).attrs.pqz_key;
    r.attrs.pqz_pop_hash = n(&env, [9; 32]);
    r.on_by(&c, &by);
    let pqz = UaPqzKeySet {
        ua: r.ua.clone(),
        pqz_key_hash: pqz_key_hash(&env, &r.attrs.pqz_key),
        pqz_pop_hash: r.attrs.pqz_pop_hash.clone(),
        sig_hash: env.crypto().keccak256(&Bytes::new(&env)).into(),
        checked: m.clone(),
    };
    assert!(env.events().all().events().contains(&pqz.to_xdr(&env, &c.address)), "the PQZ event names the relayer");
    assert_eq!(c.pqz_key_of(&r.ua).unwrap().3, m);
    assert_eq!(c.kem_key_of(&r.ua), None);
    c.set_kem_key(&r.ua, &0, &whole, &UaSig::none(&env), &None);
    assert!(env.auths().is_empty());
    assert_eq!(c.kem_key_of(&r.ua), Some((0, whole.clone(), Bytes::new(&env), m.clone())));
    assert_eq!(c.checked_of(&r.ua), (m.clone(), Checked::None, m));
}

/// `register`'s KEM event names the relayer too, with the full key in the call.
#[test]
fn ua8_relayer_register_kem_event_names_it() {
    let (env, c, by) = relayed();
    let m = marked(&by);
    let r = portable(&env, "fndsa512");
    r.on_by(&c, &by);
    let kem = UaKemKeySet {
        ua: r.ua.clone(),
        version: 0,
        kem_pk_hash: env.crypto().keccak256(&kem_pk(&env, &r.attrs.kem)).into(),
        sig_hash: env.crypto().keccak256(&Bytes::new(&env)).into(),
        checked: m.clone(),
    };
    assert!(env.events().all().events().contains(&kem.to_xdr(&env, &c.address)));
    assert_eq!(c.kem_key_of(&r.ua).unwrap().3, m);
}

/// P11.6: a listed relayer that stores a bad record takes that write-once slot, on all three writes: the bytes it stored stay
/// readable, its id on them, and the good record is refused here. The good bytes on a fresh registry: `ua8_relayer_fndsa512_kem_and_pqz`.
#[test]
fn ua8_relayer_bad_record_takes_slot_marked() {
    let (env, c, by) = relayed();
    let m = marked(&by);
    let good = portable(&env, "fndsa512");
    let mut bad = portable(&env, "fndsa512");
    bad.pop = flipped(&env, &bad.pop);
    assert_eq!(bad.on_by(&c, &by), good.ua, "the id is the key: a relayer never moves it");
    let rec = c.record_of(&good.ua).unwrap();
    assert_eq!((rec.pop, rec.pop_checked), (bad.pop.clone(), m.clone()));
    assert_eq!(err(good.tried_by(&c, &by)), Error::AlreadyRegistered);

    let k = kem_id(&env, "fndsa512/v1");
    let wrong = KemRow { sig: UaSig::single(&env, flipped(&env, &k.sig.signature)), stored: flipped(&env, &k.stored), ..k.clone() };
    wrong.tried_by(&c, &by).unwrap().unwrap();
    assert_eq!(c.kem_key_at(&k.ua, &1), Some((wrong.kem.clone(), wrong.stored.clone(), m.clone())));
    assert_eq!(err(k.tried_by(&c, &by)), Error::KemVersion);

    let p = pqz_id(&env, &format!("fndsa512/{SET}"));
    let wrong = PqzRow { sig: UaSig::single(&env, flipped(&env, &p.sig.signature)), stored: flipped(&env, &p.stored), ..p.clone() };
    wrong.tried_by(&c, &by).unwrap().unwrap();
    assert_eq!(c.pqz_key_sig_of(&p.ua), wrong.stored);
    assert_eq!(c.pqz_key_of(&p.ua).unwrap().3, m);
    assert_eq!(err(p.tried_by(&c, &by)), Error::PqzKeySet);
}

/// P11.5: a relayer-checked record authorises nothing, whatever signature comes; the token half is in the token's tests. The
/// same call by a `Chain` UA passes.
#[test]
fn ua8_relayer_checked_ua_authorises_nothing() {
    for row in offchain_rows() {
        let (env, c, by) = relayed();
        let r = portable_row(&env, &row);
        r.on_by(&c, &by);
        let (pt, d) = (n(&env, METATX), n(&env, [0x73; 32]));
        for sig in [Bytes::new(&env), r.pop.clone()] {
            assert_eq!(err(c.try_require_authorized(&r.ua, &pt, &d, &UaSig::single(&env, sig))), Error::Unauthorized, "{}", row["name"]);
        }
        let e = test::ed(67);
        let ua = e.register(&env, &c);
        c.require_authorized(&ua, &pt, &d, &UaSig::single(&env, e.sign(&env, &test::msg(&env, 0x0102, METATX, &d))));
    }
}

/// C11: the list has one writer, the constructor. `check-registry-interface.sh`'s list is the Wasm's exact function list (the
/// gate), and this test ties that list to the source: no entry beyond it, one write of `Key::Relayers`, in the constructor.
#[test]
fn ua8_relayer_list_immutable() {
    const SCRIPT: &str = include_str!("../../../scripts/check-registry-interface.sh");
    const SOURCE: &str = include_str!("lib.rs");
    let want = SCRIPT.lines().find_map(|l| l.strip_prefix("want=\"")).unwrap().trim_end_matches('"');
    let want: StdVec<&str> = want.split(' ').collect();
    let imp = SOURCE.split("impl UaRegistry {").nth(1).unwrap().split("\n}\n").next().unwrap();
    let mut got: StdVec<&str> = imp.lines().filter_map(|l| l.trim_start().strip_prefix("pub fn ")).map(|l| l.split('(').next().unwrap()).collect();
    got.sort();
    assert_eq!(got, want);
    assert_eq!(want.iter().filter(|f| f.contains("relayer")).collect::<StdVec<_>>(), [&"relayers"], "one read, no writer");
    assert_eq!(SOURCE.matches("set(&Key::Relayers").count(), 1);
    let ctor = imp.split("pub fn __constructor").nth(1).unwrap().split("pub fn ").next().unwrap();
    assert!(ctor.contains("set(&Key::Relayers"));
}

/// `msig-classical`'s own row: relayer-checked members register it; an empty `pop` checks nothing, so `Chain` and no relayer
/// (U8S-D2), and its `p256` member's weight 1 is under the threshold 3, so never a signer.
#[test]
fn ua8_relayer_classical_msig_row() {
    let (env, c, by) = relayed();
    let r = portable(&env, "msig-classical");
    assert_eq!(r.refused(&c), Error::MemberUnknown);
    classical_members(&env, &c, &by);
    assert_eq!(r.on(&c), r.ua);
    assert!(env.auths().is_empty());
    let rec = c.record_of(&r.ua).unwrap();
    assert_eq!((rec.pop_checked, rec.signable, rec.pop.len()), (Checked::Chain, false, 0));
}

fn group_size(kind: u32) -> usize {
    if kind == 0x0110 || kind == 0x0111 { 33 } else { 64 }
}

fn be16(kd: &[u8], o: usize) -> usize {
    u16::from_be_bytes([kd[o], kd[o + 1]]) as usize
}

/// The typed form of `aggKey ‖ u16 n ‖ n × key`.
fn musig2_of(env: &Env, kd: &[u8], size: usize) -> MuSig2Key {
    let mut member_keys = SVec::new(env);
    for i in 0..be16(kd, size) {
        let o = size + 2 + i * size;
        member_keys.push_back(b(env, &kd[o..o + size]));
    }
    MuSig2Key { agg_key: b(env, &kd[..size]), member_keys }
}

/// The typed form of `groupKey ‖ u16 t ‖ u16 n ‖ n × (t commitments ‖ r ‖ z)`.
fn frost_of(env: &Env, kd: &[u8], size: usize) -> FrostKey {
    let (t, count) = (be16(kd, size), be16(kd, size + 2));
    let mut members = SVec::new(env);
    for i in 0..count {
        let o = size + 4 + i * ((t + 1) * size + 32);
        let mut commitments = SVec::new(env);
        for j in 0..t {
            commitments.push_back(b(env, &kd[o + j * size..o + (j + 1) * size]));
        }
        let (r, z) = (o + t * size, o + (t + 1) * size);
        members.push_back(FrostMember { commitments, r: b(env, &kd[r..z]), z: n(env, kd[z..z + 32].try_into().unwrap()) });
    }
    FrostKey { group_key: b(env, &kd[..size]), threshold: t as u32, members }
}

/// `register_musig2` / `register_frost` from `kinds.json`'s rows are the packed `register`: the same id, record and key data
/// (EVM `registerMuSig2`, `registerFrost`, TS-D13), through the relayer mode.
#[test]
fn ua8_relayer_group_kinds_typed() {
    let mut seen = 0;
    for row in valid_rows().iter().filter(|r| (0x0110..=0x0113).contains(&kind_of(&r["kind"]))) {
        let (env, c, by) = relayed();
        let (kind, kd, ua) = (kind_of(&row["kind"]), hx(&row["keyData"]), n32(&env, &row["ua"]));
        let (attrs, pop, none) = (no_attrs(&env), b(&env, &[1; 64]), Bytes::new(&env));
        let size = group_size(kind);
        let tried = |r: &Option<Address>| {
            if kind == 0x0110 || kind == 0x0112 {
                c.try_register_musig2(&kind, &musig2_of(&env, &kd, size), &attrs, &pop, &none, r)
            } else {
                c.try_register_frost(&kind, &frost_of(&env, &kd, size), &attrs, &pop, &none, r)
            }
        };
        assert_eq!(err(tried(&None)), Error::NotVerifiable, "{}", row["name"]);
        assert_eq!(tried(&by).unwrap().unwrap(), ua, "{}", row["name"]);
        let rec = c.record_of(&ua).unwrap();
        assert_eq!((rec.key_data, rec.pop_checked, rec.signable), (b(&env, &kd), marked(&by), false), "{}", row["name"]);
        assert_eq!(c.key_owner(&n32(&env, &row["keyHash"])), Some(ua.clone()), "{}", row["name"]);
        let empty = (MuSig2Key { agg_key: none.clone(), member_keys: SVec::new(&env) }, FrostKey { group_key: none.clone(), threshold: 0, members: SVec::new(&env) });
        if kind == 0x0110 || kind == 0x0112 {
            assert_eq!((c.mu_sig2_key_of(&ua), c.frost_key_of(&ua)), (musig2_of(&env, &kd, size), empty.1), "{}", row["name"]);
        } else {
            assert_eq!((c.mu_sig2_key_of(&ua), c.frost_key_of(&ua)), (empty.0, frost_of(&env, &kd, size)), "{}", row["name"]);
        }
        let packed = c.try_register(&kind, &b(&env, &kd), &attrs, &pop, &none, &by);
        assert_eq!(err(packed), Error::AlreadyRegistered, "one record, either form");
        if kind == 0x0110 || kind == 0x0112 {
            assert_eq!(c.ua_of_musig2(&kind, &musig2_of(&env, &kd, size)), ua);
        } else {
            assert_eq!(c.ua_of_frost(&kind, &frost_of(&env, &kd, size)), ua);
        }
        seen += 1;
    }
    assert_eq!(seen, 4);
}

/// EVM's typed rules: another kind, a point of the wrong length, a member without `threshold` commitments; a value its `u16`
/// cannot hold is `KeyData`, no truncated id. Every refused key differs from a good one in that alone, and the good one
/// registers. All but the kind run on the `ua_of_*` views, which have no layout check: `register_*`'s `check_key_data` would
/// refuse most of these without the assembly's own rule.
#[test]
fn ua8_relayer_group_typed_rules() {
    let valid = valid_rows();
    let row = |kind: u32| valid.iter().find(|r| kind_of(&r["kind"]) == kind).unwrap();
    let (env, c, by) = relayed();
    let (attrs, pop, none) = (no_attrs(&env), b(&env, &[1; 64]), Bytes::new(&env));
    let good = musig2_of(&env, &hx(&row(0x0110)["keyData"]), 33);
    let refused = |kind: u32, k: &MuSig2Key| err(c.try_register_musig2(&kind, k, &attrs, &pop, &none, &by));
    for kind in [0x0111, 0x0113, 0x0131, 0x0120] {
        assert_eq!(refused(kind, &good), Error::KeyData, "{kind:#x}");
    }
    let view = |k: &MuSig2Key| err(c.try_ua_of_musig2(&0x0110, k));
    assert_eq!(view(&MuSig2Key { agg_key: b(&env, &[2; 32]), ..good.clone() }), Error::KeyData);
    let mut long = good.clone();
    long.member_keys.set(0, b(&env, &[2; 34]));
    assert_eq!(view(&long), Error::KeyData);
    let mut many = good.clone();
    while many.member_keys.len() < 17 {
        many.member_keys.push_back(good.agg_key.clone());
    }
    assert_eq!(view(&many), Error::KeyData);
    assert_eq!(c.try_register_musig2(&0x0110, &good, &attrs, &pop, &none, &by).unwrap().unwrap(), n32(&env, &row(0x0110)["ua"]));

    let good = frost_of(&env, &hx(&row(0x0111)["keyData"]), 33);
    let refused = |kind: u32, k: &FrostKey| err(c.try_register_frost(&kind, k, &attrs, &pop, &none, &by));
    for kind in [0x0110, 0x0112, 0x0131, 0x0120] {
        assert_eq!(refused(kind, &good), Error::KeyData, "{kind:#x}");
    }
    let no_members = SVec::new(&env);
    let wide = FrostKey { threshold: 0x1_0002, members: no_members, ..good.clone() };
    let view = |k: &FrostKey| err(c.try_ua_of_frost(&0x0111, k));
    assert_eq!(view(&wide), Error::KeyData, "no id of a truncated threshold");
    let mut many = good.clone();
    while many.members.len() < 17 {
        many.members.push_back(good.members.get(0).unwrap());
    }
    assert_eq!(view(&many), Error::KeyData);
    let edit = |f: fn(&mut FrostMember, &Env)| {
        let mut k = good.clone();
        let mut m = k.members.get(0).unwrap();
        f(&mut m, &env);
        k.members.set(0, m);
        k
    };
    assert_eq!(view(&edit(|m, _| { m.commitments.pop_back(); })), Error::KeyData, "a commitment short");
    assert_eq!(view(&edit(|m, e| m.r = b(e, &[2; 32]))), Error::KeyData);
    assert_eq!(view(&edit(|m, e| m.commitments.set(0, b(e, &[2; 32])))), Error::KeyData);
    assert_eq!(c.try_register_frost(&0x0111, &good, &attrs, &pop, &none, &by).unwrap().unwrap(), n32(&env, &row(0x0111)["ua"]));
}

/// `kinds.json` `invalid[]` of the `Relayer` kinds, each on a fresh registry with a listed relayer. The chain checks length and
/// layout (`KeyData`); curve membership, a canonical coordinate, sorted members and the FN-DSA encoding are the relayer's
/// (U8S-D8: `scaas_ua::keydata`), so those rows store, marked.
#[test]
fn ua8_relayer_key_data_layout() {
    const LAYOUT: [&str; 17] = [
        "empty", "one byte short", "one byte long", "trailing byte", "n = 1", "n = 17", "n = 65535 and no members", "t = 1", "t > n",
        "t = n = 65535 and no body", "t = 4 > n = 3", "MuSig2 n = 3 with two members", "MuSig2 header alone", "MuSig2 body one byte short",
        "FROST with one participant missing", "FROST header alone", "FROST body one byte short",
    ];
    let (mut layout, mut canonical) = (0, 0);
    for row in json(KINDS)["invalid"].as_array().unwrap().iter().filter(|r| RELAYER.contains(&kind_of(&r["kind"]))) {
        let (env, c, by) = relayed();
        let (kind, kd, reason) = (kind_of(&row["kind"]), b(&env, &hx(&row["keyData"])), row["reason"].as_str().unwrap());
        let got = c.try_register(&kind, &kd, &no_attrs(&env), &b(&env, &[1; 64]), &Bytes::new(&env), &by);
        if LAYOUT.contains(&reason) {
            assert_eq!(err(got), Error::KeyData, "{kind:#x} {reason}");
            layout += 1;
        } else {
            assert_eq!(c.record_of(&got.unwrap().unwrap()).unwrap().pop_checked, marked(&by), "{kind:#x} {reason}");
            canonical += 1;
        }
    }
    std::println!("relayer kinds, kinds.json invalid: {layout} refused by layout, {canonical} left to the relayer");
    assert_eq!((layout, canonical), (55, 75));
}

/// `keyHash` by `kinds.json` group: every valid row of a `Relayer` kind, and a group two relayer kinds share. Against a `Chain`
/// kind: `ua8_relayer_marked_record_blocks_no_chain_kind`, `ua8_relayer_kind_refused_over_chain_key`.
#[test]
fn ua8_relayer_key_hash_groups() {
    let env = Env::default();
    let mut seen = 0;
    for row in valid_rows() {
        let (kind, kd) = (kind_of(&row["kind"]), b(&env, &hx(&row["keyData"])));
        assert_eq!(crate::key_hash(&env, kind, &kd).unwrap().to_array().to_vec(), hx(&row["keyHash"]), "{}", row["name"]);
        seen += 1;
    }
    assert!(seen >= 12, "{seen}");

    let (env, c, by) = relayed();
    let (attrs, pop, none) = (no_attrs(&env), b(&env, &[1; 64]), Bytes::new(&env));
    let r = portable(&env, "schnorr-bls12381");
    r.on_by(&c, &by);
    assert_eq!(err(c.try_register(&0x0141, &r.kd, &attrs, &pop, &none, &by)), Error::KeyInUse, "`bls12381-g1`");
    portable(&env, "zether-bls12381").on_by(&c, &by);
}

/// The kinds of `secp256k1`'s group other than `secp256k1`, the one group a `Relayer` kind shares with a `Chain` kind.
const SECP_RELAYER: [u32; 3] = [0x0103, 0x0110, 0x0111];

/// Key data of `kind` holding `x`, length and layout only, as a listed relayer can store it: no proof, any prefix byte.
fn over_x(env: &Env, kind: u32, x: &[u8]) -> Bytes {
    let group = [&[7u8][..], x].concat();
    b(env, &match kind {
        0x0103 => x.to_vec(),
        0x0110 => [&group[..], &[0, 2], &[2; 66]].concat(),
        _ => [&group[..], &[0, 2, 0, 2], &vec![2; 2 * (3 * 33 + 32)]].concat(),
    })
}

/// A marked record proves nothing, so it blocks no `Chain` kind (controller ruling on P11.6): over a victim's `x`, on every
/// relayer kind of the group, the real key still registers, owns its `key_hash`, signs, and an `msig` can name it. The marked
/// record stays, marked, and a client ignores it.
#[test]
fn ua8_relayer_marked_record_blocks_no_chain_kind() {
    for kind in SECP_RELAYER {
        let (env, c, by) = relayed();
        let s = test::Sk::K1(test::k1(68));
        let kd = s.key_data(&env);
        let kh = crate::key_hash(&env, 0x0108, &kd).unwrap();
        let (pop, none) = (b(&env, &[1; 64]), Bytes::new(&env));
        let squat = c.register(&kind, &over_x(&env, kind, &vecu8(&kd.slice(0..32))), &no_attrs(&env), &pop, &none, &by);
        assert_eq!(c.key_owner(&kh), Some(squat.clone()), "{kind:#x}: the marked record alone");

        let ua = s.register(&env, &c);
        assert_eq!(c.key_owner(&kh), Some(ua.clone()), "{kind:#x}: the proved record");
        assert_eq!(c.record_of(&ua).unwrap().pop_checked, Checked::Chain, "{kind:#x}");
        assert_eq!(c.record_of(&squat).unwrap().pop_checked, marked(&by), "{kind:#x}");
        assert!(c.receivable(&ua), "{kind:#x}");
        let (pt, d) = (n(&env, METATX), n(&env, [0x74; 32]));
        c.require_authorized(&ua, &pt, &d, &UaSig::single(&env, s.sign(&env, &test::msg(&env, 0x0108, METATX, &d))));
        let m = msig(&env, 1, &[(0x0108, ua.to_array(), 1)]);
        m.register(&env, &c, &SVec::new(&env));
        m.accepted_by(&env, &c, &[&s]);
        c.require_authorized(&m.ua, &pt, &d, &test::msig_auth(&env, &[m.slot(&env, &s, METATX, &d)]));
    }
}

/// The reverse order: a relayer kind checks `Key` too, so it never stores over a key a `Chain` kind proved, while the same
/// call over another `x` stores. Two relayer kinds also keep one `x` between them.
#[test]
fn ua8_relayer_kind_refused_over_chain_key() {
    for kind in SECP_RELAYER {
        let (env, c, by) = relayed();
        let s = test::Sk::K1(test::k1(69));
        let kd = s.key_data(&env);
        let (attrs, pop, none) = (no_attrs(&env), b(&env, &[1; 64]), Bytes::new(&env));
        let ua = s.register(&env, &c);
        let x = vecu8(&kd.slice(0..32));
        assert_eq!(err(c.try_register(&kind, &over_x(&env, kind, &x), &attrs, &pop, &none, &by)), Error::KeyInUse, "{kind:#x}");
        assert_eq!(c.key_owner(&crate::key_hash(&env, 0x0108, &kd).unwrap()), Some(ua.clone()), "{kind:#x}");
        let other = c.register(&kind, &over_x(&env, kind, &[0x11; 32]), &attrs, &pop, &none, &by);
        assert_eq!(c.record_of(&other).unwrap().pop_checked, marked(&by), "{kind:#x}");
        for k in SECP_RELAYER.iter().filter(|k| **k != kind) {
            assert_eq!(err(c.try_register(k, &over_x(&env, *k, &[0x11; 32]), &attrs, &pop, &none, &by)), Error::KeyInUse, "{kind:#x} then {k:#x}");
        }
    }
}

/// An n-of-n `msig` of `n` relayer-checked `slhdsa128s` members, its slots of 7,856 B each.
fn slh_msig(count: u8) -> (Env, UaRegistryClient<'static>, Option<Address>, test::Msig, StdVec<Slot>) {
    let (env, c, by) = relayed();
    let (pop, none) = (b(&env, &[0x5a; 7_856]), Bytes::new(&env));
    let mut list = StdVec::new();
    for i in 0..count {
        let ua = c.register(&0x0133, &b(&env, &[0x80 + i; 32]), &no_attrs(&env), &pop, &none, &by);
        list.push((0x0133u16, ua.to_array(), 1u16));
    }
    let m = msig(&env, count as u16, &list);
    let slots = sorted(list.iter().map(|x| (m.index(&x.1), vec![], vec![0x5a; 7_856])).collect());
    (env, c, by, m, slots)
}

/// `set_pqz_key` by `count` relayer-checked `slhdsa128s` slots: the key and all the slots in one `PqzK`.
fn pqz_key_by_slhdsa(len: usize, count: u8) {
    let (env, c, by, m, slots) = slh_msig(count);
    msig_tried(&env, &c, &m, &slots, &by).unwrap().unwrap();
    let (key, ph) = (b(&env, &vec![7; len]), n(&env, [9; 32]));
    c.set_pqz_key(&m.ua, &key, &ph, &test::msig_auth(&env, &slots), &by);
    let size: usize = entry::<PqzEntry>(&env, &c, &Key::PqzK(m.ua.clone())).map(|e| (e.0.len() + e.1.len()) as usize).unwrap();
    assert_eq!(size, len + 64 + count as usize * 8_064, "key + 64 + n × (192 + the signature padded to 32)");
    std::println!("set_pqz_key {count} slhdsa128s slots, key {len} B: key + sig {size} B");
}

/// The Chain figures 13 / 12 are ML-DSA-65's. A `slhdsa128s` slot takes 8,064 B of `abi.encode(MemberSig[])`, so 6 at
/// n2048-kmax1024 and 5 at the other sets: the limit is bytes, not slots.
#[test]
fn ua8_set_pqz_key_relayer_slots_largest_fit() {
    for (len, count) in [(16_384, 6), (18_432, 5), (20_480, 5), (22_528, 5)] {
        pqz_key_by_slhdsa(len, count);
    }
}

#[test]
#[should_panic(expected = "contract data entry")]
fn ua8_set_pqz_key_relayer_slots_over_limit_n2816() {
    pqz_key_by_slhdsa(22_528, 6);
}

#[test]
#[should_panic(expected = "contract data entry")]
fn ua8_set_pqz_key_relayer_slots_over_limit_n2048() {
    pqz_key_by_slhdsa(16_384, 7);
}

/// The stored `pop` of `register` is under the same byte rule: 7 `slhdsa128s` slots fit `Ua(ua)`, 8 do not (56,512 B and
/// 64,576 B of `pop`, and the record around it).
#[test]
fn ua8_register_relayer_slots_largest_fit() {
    let (env, c, by, m, slots) = slh_msig(7);
    msig_tried(&env, &c, &m, &slots, &by).unwrap().unwrap();
    assert_eq!(env.auths().len(), 1, "one attestation for all the relayer slots: a second `require_auth` needs a second entry");
    assert_eq!(c.pop_of(&m.ua).len(), 64 + 7 * 8_064);
}

#[test]
#[should_panic(expected = "contract data entry")]
fn ua8_register_relayer_slots_over_limit() {
    let (env, c, by, m, slots) = slh_msig(8);
    msig_tried(&env, &c, &m, &slots, &by).unwrap().unwrap();
}

// ---------- B7 (C15): the record bytes, read back against the vector ----------

const ROUND_TRIP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/ua8-roundtrip.json");

fn checked_code(c: &Checked) -> u32 {
    match c {
        Checked::None => 0,
        Checked::Chain => 1,
        Checked::Relayer(_) => 2,
    }
}

/// `kem` read back against a row's typed `kem`, field by field.
fn assert_kem(k: &KemKey, row: &Value, what: &str) {
    assert_eq!((k.scheme as u64, vecu8(&k.mlkem_ek), k.x25519.to_array().to_vec()),
               (row["scheme"].as_u64().unwrap(), hx(&row["mlkemEk"]), hx(&row["x25519"])), "{what}");
}

/// A registered `row` read back through `registration_of` / `kem_key_at` / `pqz_key_of`, every byte against the vector's JSON
/// and not the values given to `register`; then its KEM records in `order`, each read back the same way, `kem_key_of` sampled
/// after each write. Returns the row's line of `ua8-roundtrip.json`, all of it read from the contract.
fn round_trip(env: &Env, c: &UaRegistryClient, row: &Value, order: &[u64], relayer: &Option<Address>) -> Value {
    let (name, ua) = (row["name"].as_str().unwrap(), n32(env, &row["ua"]));
    let a = &row["args"]["attrs"];
    let read = c.registration_of(&ua).unwrap();
    let (kind, kd, attrs, pop, pqz_pop) = read.clone();
    assert_eq!((kind, vecu8(&kd)), (kind_of(&row["kind"]), hx(&row["keyData"])), "{name}");
    assert_eq!((vecu8(&attrs.pqz_key), vecu8(&attrs.pqz_pop_hash.clone().into()), vecu8(&attrs.kem_pk_hash.clone().into())),
               (hx(&a["pqzKey"]), hx(&a["pqzPopHash"]), hx(&a["kemPkHash"])), "{name}");
    assert_kem(&attrs.kem, &a["kem"], name);
    assert_eq!((vecu8(&pop), vecu8(&pqz_pop)), (hx(&row["pop"]), hx(&row["pqzPop"])), "{name}");
    if hx(&a["kem"]["mlkemEk"]).is_empty() {
        assert_eq!(c.kem_key_at(&ua, &0), None, "{name}");
    } else {
        let (kem, sig, _) = c.kem_key_at(&ua, &0).unwrap();
        assert_kem(&kem, &a["kem"], name);
        assert!(sig.is_empty(), "{name}: the pop signed version 0");
    }
    let pqz = c.pqz_key_of(&ua);
    if let Some((key, hash, proven, _)) = &pqz {
        assert_eq!((vecu8(key), vecu8(&hash.clone().into()), proven), (hx(&a["pqzKey"]), hx(&a["pqzPopHash"]), &false), "{name}");
    } else {
        assert!(hx(&a["pqzKey"]).is_empty(), "{name}: the key is in state");
    }

    let rows = json(PORTABLE)["kemRecords"].as_array().unwrap().clone();
    let mut max_after = StdVec::new();
    for v in order {
        let r = rows.iter().find(|k| k["ua"] == row["ua"] && k["version"] == *v).unwrap();
        kem_row(env, r).tried_by(c, relayer).unwrap().unwrap();
        let (kem, sig, _) = c.kem_key_at(&ua, v).unwrap();
        assert_kem(&kem, &r["args"]["kem"], name);
        assert_eq!(vecu8(&sig), hx(&r["sig"]), "{name} v{v}");
        max_after.push(c.kem_key_of(&ua).unwrap().0);
    }
    assert_eq!(c.registration_of(&ua).unwrap(), read, "{name}: a later KEM record is no `register` argument");
    let (p, q, k) = c.checked_of(&ua);
    serde_json::json!({
        "name": name, "ua": row["ua"], "kind": kind,
        "checked": {"pop": checked_code(&p), "pqzPop": checked_code(&q), "kem": checked_code(&k),
                    "pqzKey": pqz.map(|x| checked_code(&x.3))},
        "kemOrder": order, "kemMaxAfter": max_after,
    })
}

/// C15: the `Chain` rows with their KEM records, a `fndsa512` through the relayer mode with KEM records 3 then 1, `msig-pq`
/// with its minimal `pop` among the `Chain` rows. `checked` and the KEM order are pinned in `ua8-roundtrip.json`
/// (`UA8_WRITE=1` writes it, every other run compares), which `e2e_ua8` also takes its order from.
#[test]
fn ua8_record_bytes_round_trip() {
    let mut rows = StdVec::new();
    for row in chain_rows() {
        let (env, c, _) = registered(row["name"].as_str().unwrap());
        let order: &[u64] = if json(PORTABLE)["kemRecords"].as_array().unwrap().iter().any(|k| k["ua"] == row["ua"]) { &[3, 1, 2] } else { &[] };
        rows.push(round_trip(&env, &c, &row, order, &None));
    }
    let (env, c, by) = relayed();
    let row = derived(PORTABLE, "registrations", "fndsa512");
    portable_row(&env, &row).on_by(&c, &by);
    rows.push(round_trip(&env, &c, &row, &[3, 1], &by));
    assert_eq!(rows.len(), 17);
    assert_eq!(rows.iter().filter(|r| !r["kemOrder"].as_array().unwrap().is_empty()).count(), 9);

    let got = serde_json::json!({
        "note": "Generated by ua8_record_bytes_round_trip (UA8_WRITE=1), never edit by hand: what the registry answered for each row of portable.json. checked: 0 none, 1 chain, 2 relayer.",
        "rows": rows,
    });
    if std::env::var("UA8_WRITE").is_ok_and(|v| v == "1") {
        std::fs::write(ROUND_TRIP, serde_json::to_string_pretty(&got).unwrap() + "\n").unwrap();
    }
    let file = std::fs::read_to_string(ROUND_TRIP).expect("vectors/ua8-roundtrip.json: run once with UA8_WRITE=1");
    assert_eq!(got, serde_json::from_str::<Value>(&file).unwrap(), "the answers moved from ua8-roundtrip.json");
}

// ---------- B7b (owner 2026-11-01): the relayer's auth is one word over every argument ----------

/// A relayer-mode write with all its arguments, named, so one class can change at a time.
#[derive(Clone)]
enum Write {
    Register { kind: u32, key_data: Bytes, attrs: UaAttrs, pop: Bytes, pqz_pop: Bytes, by: Option<Address> },
    Msig { structure: MsigStructure, attrs: UaAttrs, pop: SVec<MemberSig>, pqz_pop: Bytes, by: Option<Address> },
    Musig2 { kind: u32, key: MuSig2Key, attrs: UaAttrs, pop: Bytes, pqz_pop: Bytes, by: Option<Address> },
    Frost { kind: u32, key: FrostKey, attrs: UaAttrs, pop: Bytes, pqz_pop: Bytes, by: Option<Address> },
    SetKem { ua: BytesN<32>, version: u64, kem: KemKey, sig: UaSig, by: Option<Address> },
    SetPqz { ua: BytesN<32>, key: Bytes, hash: BytesN<32>, sig: UaSig, by: Option<Address> },
}

impl Write {
    fn function(&self) -> &'static str {
        match self {
            Write::Register { .. } => "register",
            Write::Msig { .. } => "register_msig",
            Write::Musig2 { .. } => "register_musig2",
            Write::Frost { .. } => "register_frost",
            Write::SetKem { .. } => "set_kem_key",
            Write::SetPqz { .. } => "set_pqz_key",
        }
    }
    /// Every argument in the entry's order, written here and not read from the contract: the test's own account of what is bound.
    fn args(&self, env: &Env) -> SVec<soroban_sdk::Val> {
        match self.clone() {
            Write::Register { kind, key_data, attrs, pop, pqz_pop, by } => (kind, key_data, attrs, pop, pqz_pop, by).into_val(env),
            Write::Msig { structure, attrs, pop, pqz_pop, by } => (structure, attrs, pop, pqz_pop, by).into_val(env),
            Write::Musig2 { kind, key, attrs, pop, pqz_pop, by } => (kind, key, attrs, pop, pqz_pop, by).into_val(env),
            Write::Frost { kind, key, attrs, pop, pqz_pop, by } => (kind, key, attrs, pop, pqz_pop, by).into_val(env),
            Write::SetKem { ua, version, kem, sig, by } => (ua, version, kem, sig, by).into_val(env),
            Write::SetPqz { ua, key, hash, sig, by } => (ua, key, hash, sig, by).into_val(env),
        }
    }
    fn by(&self) -> Address {
        match self {
            Write::Register { by, .. } | Write::Msig { by, .. } | Write::Musig2 { by, .. } | Write::Frost { by, .. } | Write::SetKem { by, .. } | Write::SetPqz { by, .. } => by.clone().unwrap(),
        }
    }
    fn tried(&self, c: &UaRegistryClient) -> Result<(), soroban_sdk::Error> {
        let done = |x: bool, e: Option<soroban_sdk::Error>| if x { Ok(()) } else { Err(e.unwrap()) };
        let id = |r: Tried<BytesN<32>>| done(r.is_ok(), r.err().map(|e| e.unwrap_or_else(|_| panic!("an invoke error"))));
        let unit = |r: Tried<()>| done(r.is_ok(), r.err().map(|e| e.unwrap_or_else(|_| panic!("an invoke error"))));
        match self {
            Write::Register { kind, key_data, attrs, pop, pqz_pop, by } => id(c.try_register(kind, key_data, attrs, pop, pqz_pop, by)),
            Write::Msig { structure, attrs, pop, pqz_pop, by } => id(c.try_register_msig(structure, attrs, pop, pqz_pop, by)),
            Write::Musig2 { kind, key, attrs, pop, pqz_pop, by } => id(c.try_register_musig2(kind, key, attrs, pop, pqz_pop, by)),
            Write::Frost { kind, key, attrs, pop, pqz_pop, by } => id(c.try_register_frost(kind, key, attrs, pop, pqz_pop, by)),
            Write::SetKem { ua, version, kem, sig, by } => unit(c.try_set_kem_key(ua, version, kem, sig, by)),
            Write::SetPqz { ua, key, hash, sig, by } => unit(c.try_set_pqz_key(ua, key, hash, sig, by)),
        }
    }
}

/// One relayer's digest of `w`, under `w`'s entry.
fn attest_write(env: &Env, c: &UaRegistryClient, w: &Write) {
    authorise(env, c, &w.by(), w.function(), w.function(), w.args(env));
}

type Change = (&'static str, fn(&Env, &mut Write, &Address));

/// For each change, on a fresh registry: the attestation of `base` does not pass for the changed write, and that write stores on
/// its own attestation, so the refusal was the hash and no rule of the contract.
fn binds(base: fn(&Env, &UaRegistryClient, &Option<Address>) -> Write, changes: &[Change]) {
    for (what, change) in changes {
        let env = test::new_env();
        let (r, other) = (Address::generate(&env), Address::generate(&env));
        let c = test::deploy(&env, &[r.clone(), other.clone()]);
        env.mock_all_auths();
        let w = base(&env, &c, &Some(r));
        let mut v = w.clone();
        change(&env, &mut v, &other);
        let name = w.function();
        attest_write(&env, &c, &w);
        assert_eq!(v.tried(&c), Err(AUTH_REFUSED), "{name}: {what}: the attestation of other arguments passed");
        attest_write(&env, &c, &v);
        assert_eq!(v.tried(&c), Ok(()), "{name}: {what}: refused for another reason than the hash");
    }
}

fn set_row(env: &Env) -> Reg {
    portable(env, &format!("mldsa65/{SET}"))
}

fn fndsa_write(env: &Env, _: &UaRegistryClient, by: &Option<Address>) -> Write {
    let (r, s) = (portable(env, "fndsa512"), set_row(env));
    Write::Register { kind: r.kind, key_data: r.kd, attrs: s.attrs, pop: r.pop, pqz_pop: s.pqz_pop, by: by.clone() }
}

fn attrs_of(w: &mut Write) -> &mut UaAttrs {
    match w {
        Write::Register { attrs, .. } | Write::Msig { attrs, .. } | Write::Musig2 { attrs, .. } | Write::Frost { attrs, .. } => attrs,
        _ => panic!("no attrs"),
    }
}

fn set_by(w: &mut Write, to: &Address) {
    match w {
        Write::Register { by, .. } | Write::Msig { by, .. } | Write::Musig2 { by, .. } | Write::Frost { by, .. } | Write::SetKem { by, .. } | Write::SetPqz { by, .. } => *by = Some(to.clone()),
    }
}

/// Every argument class of `register`.
#[test]
fn ua8_attest_binds_register() {
    binds(fndsa_write, &[
        ("key_data", |e, w, _| if let Write::Register { key_data, .. } = w { *key_data = flipped(e, key_data) }),
        ("pop", |e, w, _| if let Write::Register { pop, .. } = w { *pop = flipped(e, pop) }),
        ("pqz_pop", |e, w, _| if let Write::Register { pqz_pop, .. } = w { *pqz_pop = Bytes::new(e) }),
        ("attrs.pqz_key", |e, w, _| { let a = attrs_of(w); a.pqz_key = flipped(e, &a.pqz_key) }),
        ("attrs.pqz_pop_hash", |e, w, _| {
            let v = b(e, &[9; 64]);
            let h: BytesN<32> = e.crypto().keccak256(&v).into();
            attrs_of(w).pqz_pop_hash = h;
            if let Write::Register { pqz_pop, .. } = w { *pqz_pop = v }
        }),
        ("attrs.kem.mlkem_ek", |e, w, _| { let a = attrs_of(w); a.kem.mlkem_ek = flipped(e, &a.kem.mlkem_ek) }),
        ("attrs.kem.x25519", |e, w, _| attrs_of(w).kem.x25519 = n(e, [0x33; 32])),
        ("attrs.kem_pk_hash", |e, w, _| { let a = attrs_of(w); a.kem = KemKey { scheme: 1, ..KemKey::none(e) }; a.kem_pk_hash = n(e, [0x44; 32]) }),
        ("relayer", |_, w, other| set_by(w, other)),
    ]);
    // `kind`: two kinds of one key length, so only the hash can tell them apart
    binds(|e, _, by| Write::Register { kind: 0x0133, key_data: b(e, &[7; 32]), attrs: no_attrs(e), pop: b(e, &[1; 64]), pqz_pop: Bytes::new(e), by: by.clone() }, &[
        ("kind", |_, w, _| if let Write::Register { kind, .. } = w { *kind = 0x0103 }),
    ]);
}

/// `fndsa512` members of the `msig` of `register_msig`, a third registered for the change of a member.
fn msig_write(env: &Env, c: &UaRegistryClient, by: &Option<Address>) -> Write {
    let members: StdVec<_> = (0..3u8).map(|i| {
        let ua = c.register(&0x0132, &b(env, &[0x70 + i; 897]), &no_attrs(env), &b(env, &[1; 666]), &Bytes::new(env), by);
        (0x0132u16, ua.to_array(), 2u16)
    }).collect();
    let m = msig(env, 4, &members[..2]);
    let slots = [(0, vec![], vec![5; 666]), (1, vec![], vec![6; 666])];
    Write::Msig { structure: m.s, attrs: no_attrs(env), pop: test::member_sigs(env, &slots), pqz_pop: Bytes::new(env), by: by.clone() }
}

fn structure(w: &mut Write) -> &mut MsigStructure {
    match w {
        Write::Msig { structure, .. } => structure,
        _ => panic!("no structure"),
    }
}

/// The same `msig` with a third member in the structure, so a slot's `index` can move, and a PQZ key whose proof can go.
fn msig_write_with_proof(env: &Env, c: &UaRegistryClient, by: &Option<Address>) -> Write {
    let Write::Msig { pop, .. } = msig_write(env, c, by) else { unreachable!() };
    let third = (0x0132u16, digest::ua_of(env, 0x0132, &b(env, &[0x72; 897])).to_array(), 2u16);
    let first: StdVec<_> = (0..2u8).map(|i| (0x0132u16, digest::ua_of(env, 0x0132, &b(env, &[0x70 + i; 897])).to_array(), 2u16)).collect();
    let s = set_row(env);
    Write::Msig { structure: msig(env, 4, &[first[0], first[1], third]).s, attrs: s.attrs, pop, pqz_pop: s.pqz_pop, by: by.clone() }
}

/// Every argument class of `register_msig`, a structure's fields and a slot's among them.
#[test]
fn ua8_attest_binds_register_msig() {
    binds(msig_write_with_proof, &[
        ("pqz_pop", |e, w, _| if let Write::Msig { pqz_pop, .. } = w { *pqz_pop = Bytes::new(e) }),
        ("pop.index", |_, w, _| if let Write::Msig { pop, .. } = w {
            let mut s = pop.get(1).unwrap();
            s.index = 2;
            pop.set(1, s);
        }),
    ]);
    binds(msig_write, &[
        ("structure.threshold", |_, w, _| structure(w).threshold = 3),
        ("structure.members.weight", |_, w, _| {
            let mut m = structure(w).members.get(1).unwrap();
            m.weight = 3;
            structure(w).members.set(1, m);
        }),
        ("structure.members.id", |e, w, _| {
            let (s, third) = (structure(w), digest::ua_of(e, 0x0132, &b(e, &[0x72; 897])));
            let mut ids: StdVec<_> = [s.members.get(0).unwrap().id, third].iter().map(|x| (0x0132u16, x.to_array(), 2u16)).collect();
            ids.sort_by_key(|x| x.1);
            *s = msig(e, 4, &ids).s;
        }),
        ("attrs", |e, w, _| *attrs_of(w) = set_row(e).attrs),
        ("pop.sig", |e, w, _| if let Write::Msig { pop, .. } = w {
            let mut s = pop.get(0).unwrap();
            s.sig = flipped(e, &s.sig);
            pop.set(0, s);
        }),
        ("relayer", |_, w, other| set_by(w, other)),
    ]);
}

#[test]
fn ua8_attest_binds_group_keys() {
    binds(|e, _, by| {
        let mut member_keys = SVec::new(e);
        member_keys.push_back(b(e, &[2; 33]));
        member_keys.push_back(b(e, &[3; 33]));
        Write::Musig2 { kind: 0x0110, key: MuSig2Key { agg_key: b(e, &[1; 33]), member_keys }, attrs: no_attrs(e), pop: b(e, &[1; 64]), pqz_pop: Bytes::new(e), by: by.clone() }
    }, &[
        ("key.agg_key", |e, w, _| if let Write::Musig2 { key, .. } = w { key.agg_key = b(e, &[9; 33]) }),
        ("key.member_keys", |e, w, _| if let Write::Musig2 { key, .. } = w { key.member_keys.set(1, b(e, &[8; 33])) }),
        ("pop", |e, w, _| if let Write::Musig2 { pop, .. } = w { *pop = flipped(e, pop) }),
        // a group `kind` fixes the point size, so it can only change with the points: alone it is `KeyData` before `attest`
        ("kind, with the points its size needs", |e, w, _| if let Write::Musig2 { kind, key, .. } = w {
            *kind = 0x0112;
            key.agg_key = b(e, &[1; 64]);
            let mut member_keys = SVec::new(e);
            member_keys.push_back(b(e, &[2; 64]));
            member_keys.push_back(b(e, &[3; 64]));
            key.member_keys = member_keys;
        }),
        ("relayer", |_, w, other| set_by(w, other)),
    ]);
    binds(|e, _, by| {
        let member = |x: u8| {
            let mut commitments = SVec::new(e);
            commitments.push_back(b(e, &[x; 33]));
            commitments.push_back(b(e, &[x + 1; 33]));
            FrostMember { commitments, r: b(e, &[x + 2; 33]), z: n(e, [x + 3; 32]) }
        };
        let mut members = SVec::new(e);
        members.push_back(member(0x10));
        members.push_back(member(0x20));
        Write::Frost { kind: 0x0111, key: FrostKey { group_key: b(e, &[1; 33]), threshold: 2, members }, attrs: no_attrs(e), pop: b(e, &[1; 64]), pqz_pop: Bytes::new(e), by: by.clone() }
    }, &[
        ("key.group_key", |e, w, _| if let Write::Frost { key, .. } = w { key.group_key = b(e, &[9; 33]) }),
        ("key.members.z", |e, w, _| if let Write::Frost { key, .. } = w {
            let mut m = key.members.get(0).unwrap();
            m.z = n(e, [0x77; 32]);
            key.members.set(0, m);
        }),
        ("key.members.commitments", |e, w, _| if let Write::Frost { key, .. } = w {
            let mut m = key.members.get(0).unwrap();
            m.commitments.set(1, b(e, &[0x66; 33]));
            key.members.set(0, m);
        }),
        ("key.members.r", |e, w, _| if let Write::Frost { key, .. } = w {
            let mut m = key.members.get(1).unwrap();
            m.r = b(e, &[0x55; 33]);
            key.members.set(1, m);
        }),
        // `threshold` fixes each member's commitments, so it can only change with them: alone it is `KeyData` before `attest`
        ("key.threshold, with the commitments it counts", |e, w, _| if let Write::Frost { key, .. } = w {
            key.threshold = 3;
            let mut members = SVec::new(e);
            for mut m in key.members.iter() {
                m.commitments.push_back(b(e, &[0x44; 33]));
                members.push_back(m);
            }
            members.push_back(members.get(0).unwrap());
            key.members = members;
        }),
        ("pop", |e, w, _| if let Write::Frost { pop, .. } = w { *pop = flipped(e, pop) }),
        ("relayer", |_, w, other| set_by(w, other)),
    ]);
    // `frost` of the other curve: as `register_musig2`, its `kind` comes with its points
    binds(|e, _, by| {
        let member = |x: u8| {
            let mut commitments = SVec::new(e);
            commitments.push_back(b(e, &[x; 33]));
            commitments.push_back(b(e, &[x + 1; 33]));
            FrostMember { commitments, r: b(e, &[x + 2; 33]), z: n(e, [x + 3; 32]) }
        };
        let mut members = SVec::new(e);
        members.push_back(member(0x10));
        members.push_back(member(0x20));
        Write::Frost { kind: 0x0111, key: FrostKey { group_key: b(e, &[1; 33]), threshold: 2, members }, attrs: no_attrs(e), pop: b(e, &[1; 64]), pqz_pop: Bytes::new(e), by: by.clone() }
    }, &[
        ("kind, with the points its size needs", |e, w, _| if let Write::Frost { kind, key, .. } = w {
            *kind = 0x0113;
            key.group_key = b(e, &[1; 64]);
            let mut members = SVec::new(e);
            for mut m in key.members.iter() {
                let mut commitments = SVec::new(e);
                commitments.push_back(b(e, &[0x31; 64]));
                commitments.push_back(b(e, &[0x32; 64]));
                m.commitments = commitments;
                m.r = b(e, &[0x33; 64]);
                members.push_back(m);
            }
            key.members = members;
        }),
    ]);
}

/// A `fndsa512` holder, a second one for the change of `ua`.
fn holder_of(env: &Env, c: &UaRegistryClient, by: &Option<Address>) -> BytesN<32> {
    let id = c.register(&0x0132, &b(env, &[0x51; 897]), &no_attrs(env), &b(env, &[1; 666]), &Bytes::new(env), by);
    c.register(&0x0132, &b(env, &[0x52; 897]), &no_attrs(env), &b(env, &[1; 666]), &Bytes::new(env), by);
    id
}

fn other_holder(env: &Env) -> BytesN<32> {
    digest::ua_of(env, 0x0132, &b(env, &[0x52; 897]))
}

#[test]
fn ua8_attest_binds_set_kem_key() {
    binds(|e, c, by| {
        let ua = holder_of(e, c, by);
        let k = kem_id(e, "fndsa512/v1");
        Write::SetKem { ua, version: 1, kem: k.kem, sig: UaSig { key_data: Bytes::new(e), signature: b(e, &[1; 666]), members: SVec::new(e) }, by: by.clone() }
    }, &[
        ("ua", |e, w, _| if let Write::SetKem { ua, .. } = w { *ua = other_holder(e) }),
        ("version", |_, w, _| if let Write::SetKem { version, .. } = w { *version = 2 }),
        ("kem.mlkem_ek", |e, w, _| if let Write::SetKem { kem, .. } = w { kem.mlkem_ek = flipped(e, &kem.mlkem_ek) }),
        ("kem.x25519", |e, w, _| if let Write::SetKem { kem, .. } = w { kem.x25519 = n(e, [0x33; 32]) }),
        ("sig", |e, w, _| if let Write::SetKem { sig, .. } = w { sig.signature = flipped(e, &sig.signature) }),
        ("relayer", |_, w, other| set_by(w, other)),
    ]);
}

#[test]
fn ua8_attest_binds_set_pqz_key() {
    binds(|e, c, by| {
        let (ua, s) = (holder_of(e, c, by), set_row(e));
        Write::SetPqz { ua, key: s.attrs.pqz_key, hash: s.attrs.pqz_pop_hash, sig: UaSig { key_data: Bytes::new(e), signature: b(e, &[1; 666]), members: SVec::new(e) }, by: by.clone() }
    }, &[
        ("ua", |e, w, _| if let Write::SetPqz { ua, .. } = w { *ua = other_holder(e) }),
        ("pqz_key", |e, w, _| if let Write::SetPqz { key, .. } = w { *key = flipped(e, key) }),
        ("pqz_pop_hash", |e, w, _| if let Write::SetPqz { hash, .. } = w { *hash = n(e, [0x44; 32]) }),
        ("sig", |e, w, _| if let Write::SetPqz { sig, .. } = w { sig.signature = flipped(e, &sig.signature) }),
        ("relayer", |_, w, other| set_by(w, other)),
    ]);
}

/// A digest of another entry over the same arguments is refused, under either entry's name: one word is not enough to confuse them.
#[test]
fn ua8_attest_hash_of_another_entry_refused() {
    let env = test::new_env();
    let r = Address::generate(&env);
    let c = test::deploy(&env, &[r.clone()]);
    env.mock_all_auths();
    let w = fndsa_write(&env, &c, &Some(r.clone()));
    for (entry, digest_of) in [("register", "register_msig"), ("register", "set_kem_key"), ("register_msig", "register"), ("set_kem_key", "set_kem_key")] {
        authorise(&env, &c, &r, entry, digest_of, w.args(&env));
        assert_eq!(w.tried(&c), Err(AUTH_REFUSED), "an auth on {entry} over a digest of {digest_of}");
    }
    attest_write(&env, &c, &w);
    assert_eq!(w.tried(&c), Ok(()));
}

/// Only the relayer the write names is asked: another listed relayer's auth of the same digest stores nothing.
#[test]
fn ua8_attest_needs_the_named_relayer() {
    let env = test::new_env();
    let (r, other) = (Address::generate(&env), Address::generate(&env));
    let c = test::deploy(&env, &[r.clone(), other.clone()]);
    env.mock_all_auths();
    let w = fndsa_write(&env, &c, &Some(r.clone()));
    authorise(&env, &c, &other, w.function(), w.function(), w.args(&env));
    assert_eq!(w.tried(&c), Err(AUTH_REFUSED));
    env.set_auths(&[]);
    assert_eq!(w.tried(&c), Err(AUTH_REFUSED), "no auth at all");
    let none = match w.clone() {
        Write::Register { kind, key_data, attrs, pop, pqz_pop, .. } => c.try_register(&kind, &key_data, &attrs, &pop, &pqz_pop, &None),
        _ => unreachable!(),
    };
    assert_eq!(err(none), Error::NotVerifiable, "`Some(relayer)` is still required");
    attest_write(&env, &c, &w);
    assert_eq!(w.tried(&c), Ok(()));
    let ua = digest::ua_of(&env, 0x0132, &portable(&env, "fndsa512").kd);
    assert_eq!(c.record_of(&ua).unwrap().pop_checked, Checked::Relayer(r));
    assert!(!c.receivable(&ua), "an attestation never makes a key able to authorise");
}

/// The digest against the bytes `smartcontracts/soroban/scripts/attest-digest-vector.py` builds by hand, and `scaas-node`'s twin
/// pins the same two words.
#[test]
fn ua8_attest_digest_vector() {
    let env = test::new_env();
    env.ledger().set_network_id([0x11; 32]);
    let c = Address::from_str(&env, "CARCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEVQO");
    let args: SVec<soroban_sdk::Val> = (7u32, b(&env, &[1, 2]), ()).into_val(&env);
    let hex = |d: BytesN<32>| d.to_array().iter().map(|x| format!("{x:02x}")).collect::<StdVec<_>>().concat();
    assert_eq!(hex(attest_digest(&env, &c, "register", args.clone())), "10c27d0f11b12ccc54ceeff725eea285795a0ea2d18bb5320b95c1c9e6e95b92");
    assert_eq!(hex(attest_digest(&env, &c, "set_kem_key", args)), "2da85a452358a70d013d2dbe4fd4136bec2234b25380f7f222fcfff6c712aa53");
}

// ---------- B7c (owner 2026-11-01, CTR-UA-33.A on Soroban): `UaRegistered` carries `key_data` unless too large ----------

/// `key_data` of the last `UaRegistered`, read from the event's own XDR.
fn event_key_data_of(env: &Env) -> StdVec<u8> {
    use soroban_sdk::xdr::{ContractEventBody, ScVal};
    let all = env.events().all();
    let e = all.events().iter().rev().find(|e| matches!(&e.body, ContractEventBody::V0(b) if format!("{:?}", b.topics.first()).contains("UaRegistered"))).expect("UaRegistered").clone();
    let ContractEventBody::V0(b) = e.body;
    let ScVal::Vec(Some(data)) = b.data else { panic!("not the event's vec") };
    let ScVal::Map(Some(record)) = &data[0] else { panic!("not the record") };
    let f = record.iter().find(|x| matches!(&x.key, ScVal::Symbol(k) if k.0.as_slice() == b"key_data")).unwrap();
    let ScVal::Bytes(k) = &f.val else { panic!("key_data") };
    k.to_vec()
}

/// A `frost-bn254` key of `t` of `n`, and its bytes put together here, not by the contract.
fn frost_bn254(env: &Env, t: u32, n_: u32) -> (FrostKey, StdVec<u8>) {
    let point = |x: u8| vec![x; 64];
    let mut kd = point(0x31);
    kd.extend_from_slice(&(t as u16).to_be_bytes());
    kd.extend_from_slice(&(n_ as u16).to_be_bytes());
    let mut members = SVec::new(env);
    for i in 0..n_ {
        let mut commitments = SVec::new(env);
        for c in 0..t {
            commitments.push_back(b(env, &point(0x40 + c as u8)));
            kd.extend(point(0x40 + c as u8));
        }
        kd.extend(point(0x60 + i as u8));
        kd.extend([0x70 + i as u8; 32]);
        members.push_back(FrostMember { commitments, r: b(env, &point(0x60 + i as u8)), z: n(env, [0x70 + i as u8; 32]) });
    }
    (FrostKey { group_key: b(env, &point(0x31)), threshold: t, members }, kd)
}

/// The rule, at its edge. No real key has exactly this length, a FROST key's lengths being discrete, so the edge is here and
/// `ua8_event_frost_sizes` holds the nearest real lengths on each side.
#[test]
fn ua8_event_key_data_limit() {
    let env = test::new_env();
    let at = b(&env, &vec![7; crate::EVENT_KEY_DATA_MAX as usize]);
    assert_eq!(crate::event_key_data(&env, &at), at, "exactly the constant is in the event");
    let over = b(&env, &vec![7; crate::EVENT_KEY_DATA_MAX as usize + 1]);
    assert!(crate::event_key_data(&env, &over).is_empty(), "one byte more is not");
    assert!(crate::event_key_data(&env, &Bytes::new(&env)).is_empty());
    assert_eq!(crate::EVENT_KEY_DATA_MAX, 15_360);
}

/// Below the limit the event is EVM's `keyData`, on every entry: the vector's bytes, not the ones given.
#[test]
fn ua8_event_is_evm_key_data_below_the_limit() {
    for row in chain_rows().iter().chain(offchain_rows().iter().filter(|r| r["name"] == "fndsa512")) {
        let name = row["name"].as_str().unwrap();
        let (env, c, by) = relayed();
        let r = portable_row(&env, row);
        members(&env, &c, r.kind);
        r.on_by(&c, &by);
        assert_eq!(event_key_data_of(&env), hx(&row["keyData"]), "{name}");
    }
    // the typed entries the rows do not reach
    let (env, c, by) = relayed();
    let r = portable(&env, "webauthn-p256");
    let d = vecu8(&r.kd);
    let key = WebAuthnKey { x: n(&env, d[..32].try_into().unwrap()), y: n(&env, d[32..64].try_into().unwrap()), rp_id_hash: n(&env, d[64..96].try_into().unwrap()) };
    c.register_webauthn(&key, &r.attrs, &r.pop, &r.pqz_pop, &None);
    assert_eq!(event_key_data_of(&env), d);
    let mut member_keys = SVec::new(&env);
    let mut kd = vec![1; 64];
    kd.extend([0, 16]);
    for i in 0..16u8 {
        member_keys.push_back(b(&env, &[0x20 + i; 64]));
        kd.extend([0x20 + i; 64]);
    }
    c.register_musig2(&0x0112, &MuSig2Key { agg_key: b(&env, &[1; 64]), member_keys }, &no_attrs(&env), &b(&env, &[1; 64]), &Bytes::new(&env), &by);
    assert_eq!(event_key_data_of(&env), kd);
}

/// The nearest real lengths on each side of the limit, and threshold 1, which no chain admits. Emptied or not: the record is the
/// input, byte for byte, and `ua` is the key's.
#[test]
fn ua8_event_frost_sizes() {
    for (t, count, whole) in [(2, 2, true), (13, 16, true), (14, 15, true), (15, 15, false), (14, 16, false), (15, 16, false), (16, 16, false)] {
        let (env, c, by) = relayed();
        let (key, kd) = frost_bn254(&env, t, count);
        let (attrs, pop, none) = (no_attrs(&env), b(&env, &[1; 64]), Bytes::new(&env));
        let ua = c.register_frost(&0x0113, &key, &attrs, &pop, &none, &by);
        let got = event_key_data_of(&env);
        assert_eq!(got, if whole { kd.clone() } else { vec![] }, "{t} of {count}: {} B", kd.len());
        assert_eq!(ua, digest::ua_of(&env, 0x0113, &b(&env, &kd)), "{t} of {count}: the id is the key's, emptied or not");
        assert_eq!(c.ua_of_frost(&0x0113, &key), ua);
        assert_eq!(vecu8(&c.record_of(&ua).unwrap().key_data), kd, "{t} of {count}");
        assert_eq!(c.registration_of(&ua), Some((0x0113, b(&env, &kd), attrs, pop, none)), "{t} of {count}");
    }
    let (env, c, by) = relayed();
    let (key, _) = frost_bn254(&env, 1, 2);
    assert_eq!(err(c.try_register_frost(&0x0113, &key, &no_attrs(&env), &b(&env, &[1; 64]), &Bytes::new(&env), &by)), Error::KeyData, "threshold 1: EVM and ua-rs refuse it too");
}
