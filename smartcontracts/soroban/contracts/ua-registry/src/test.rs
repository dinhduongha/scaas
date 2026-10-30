//! T3: the `UaRegistry` entries against the shared UA vectors (`smartcontracts/vectors/ua/`) and in-test keys. Real
//! authorization only: no test mocks auths; the one native member signs a real ed25519 auth entry.
extern crate std;
use std::{format, vec, vec::Vec as StdVec};

use ed25519_dalek::Signer as _;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use soroban_sdk::{
    testutils::{storage::Persistent as _, Address as _, Events as _, Ledger as _},
    xdr::{
        self, AccountId, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limits, PublicKey,
        ScAddress, ScMap, ScMapEntry, ScSymbol, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
        SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, Uint256, WriteXdr,
    },
    Address, Bytes, BytesN, Env, Event as _, IntoVal, TryFromVal, Val, Vec as SVec,
};

use crate::{
    digest,
    test_verify::{abi_encode_webauthn, b, derived, hx, json, kind_of, n32},
    webauthn::b64url32,
    Error, Key, RegisteredRecord, UaRegistered, UaRegistry, UaRegistryClient,
};
use scaas_ua_common::*;

const KINDS: &str = include_str!("../../../../vectors/ua/kinds.json");
const SIGNATURES: &str = include_str!("../../../../vectors/ua/signatures.json");
const PQ_SIGNATURES: &str = include_str!("../../../../vectors/ua/pq_signatures.json");
const PORTABLE: &str = include_str!("../../../../vectors/ua/portable.json");

const DAY: u32 = 17_280;
const NETWORK: [u8; 32] = [7; 32];
const RP: [u8; 32] = [0x5a; 32];
/// The single-key `registrations[]` rows of an S3 kind with empty `attrs`.
const S3_ROWS: [&str; 7] = ["webauthn-p256", "p256", "ed25519", "secp256k1", "mldsa44", "mldsa65#1", "mldsa65#2"];
const PURPOSES: [[u8; 32]; 4] = [PURPOSE_METATX, PURPOSE_TRADE, PURPOSE_METATX_CANCEL, PURPOSE_MEMBER];

// ---------- setup ----------

fn new_env() -> Env {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    env.ledger().with_mut(|l| l.network_id = NETWORK);
    env
}

fn deploy(env: &Env, relayers: &[Address]) -> UaRegistryClient<'static> {
    let mut v = SVec::new(env);
    for r in relayers {
        v.push_back(r.clone());
    }
    UaRegistryClient::new(env, &env.register(UaRegistry, (v,)))
}

fn setup() -> (Env, UaRegistryClient<'static>) {
    let env = new_env();
    let c = deploy(&env, &[]);
    (env, c)
}

/// The contract error of a failed call (a host error or a success panics).
fn err<T, C: core::fmt::Debug>(r: Result<T, Result<soroban_sdk::Error, C>>) -> Error {
    match r {
        Err(Ok(e)) => Error::try_from(e).unwrap_or_else(|_| panic!("host error {e:?}")),
        Err(Err(e)) => panic!("invoke error {e:?}"),
        Ok(_) => panic!("succeeded"),
    }
}

fn n(env: &Env, a: [u8; 32]) -> BytesN<32> {
    BytesN::from_array(env, &a)
}

fn vecu8(x: &Bytes) -> StdVec<u8> {
    x.iter().collect()
}

fn no_attrs(env: &Env) -> UaAttrs {
    UaAttrs { pqz_key: Bytes::new(env), pqz_pop_hash: n(env, [0; 32]), kem_version: 0, kem_pk: Bytes::new(env) }
}

/// `registrationDigest` of a record without attributes (UA8-D1): what its `pop` signs under purpose `pop` v2.
fn reg_digest(env: &Env, ua: &BytesN<32>) -> BytesN<32> {
    let z = n(env, [0; 32]);
    digest::registration_digest(env, &digest::portable_pop_digest(env, ua, &z, &z), &z)
}

fn msg(env: &Env, kind: u32, purpose: [u8; 32], d: &BytesN<32>) -> [u8; 32] {
    digest::ua_message(env, kind, &n(env, purpose), d).to_array()
}

// ---------- portable rows ----------

struct Reg {
    kind: u32,
    kd: Bytes,
    attrs: UaAttrs,
    pop: Bytes,
    pqz_pop: Bytes,
    ua: BytesN<32>,
}

fn portable(env: &Env, name: &str) -> Reg {
    let r = derived(PORTABLE, "registrations", name);
    let a = &r["attrs"];
    Reg {
        kind: kind_of(&r["kind"]),
        kd: b(env, &hx(&r["keyData"])),
        attrs: UaAttrs {
            pqz_key: b(env, &hx(&a["pqzKey"])),
            pqz_pop_hash: n32(env, &a["pqzPopHash"]),
            kem_version: a["kemVersion"].as_u64().unwrap(),
            kem_pk: b(env, &hx(&a["kemPk"])),
        },
        pop: b(env, &hx(&r["pop"])),
        pqz_pop: b(env, &hx(&r["pqzPop"])),
        ua: n32(env, &r["ua"]),
    }
}

impl Reg {
    fn on(&self, c: &UaRegistryClient) -> BytesN<32> {
        c.register(&self.kind, &self.kd, &self.attrs, &self.pop, &self.pqz_pop, &None)
    }
    fn refused(&self, c: &UaRegistryClient) -> Error {
        err(c.try_register(&self.kind, &self.kd, &self.attrs, &self.pop, &self.pqz_pop, &None))
    }
}

/// `keccak256(GROUP(g) ‖ pubkey)` from `kinds.json` `groups` (x alone for the ECDSA kinds).
fn expected_key_hash(env: &Env, kind: u32, kd: &[u8]) -> BytesN<32> {
    let g = match kind {
        0x0100 | 0x0101 => "p256",
        0x0102 => "ed25519",
        0x0108 => "secp256k1",
        0x0130 => "mldsa44",
        _ => "mldsa65",
    };
    let row = json(KINDS)["groups"].as_array().unwrap().iter().find(|r| r["group"] == g).unwrap().clone();
    let mut v = hx(&row["GROUP"]);
    v.extend_from_slice(if [0x0100, 0x0101, 0x0108].contains(&kind) { &kd[..32] } else { kd });
    env.crypto().keccak256(&b(env, &v)).into()
}

// ---------- in-test keys ----------

enum Sk {
    Ed(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
    Wa(p256::ecdsa::SigningKey),
    K1(k256::ecdsa::SigningKey),
}

fn ed(seed: u8) -> Sk {
    Sk::Ed(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}
fn p256k(seed: u8) -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap()
}
fn k1(seed: u8) -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap()
}

/// `r ‖ s ‖ v` (v = 27 / 28) of a low-s secp256k1 signature over a 32-byte prehash.
fn k1_sign(sk: &k256::ecdsa::SigningKey, h: &[u8; 32]) -> StdVec<u8> {
    let (sig, rid) = sk.sign_prehash_recoverable(h).unwrap();
    assert!(sig.normalize_s().is_none(), "k256 signs low-s");
    let mut v = sig.to_bytes().to_vec();
    v.push(27 + rid.to_byte());
    v
}

/// A WebAuthn assertion over `m` (UP | UV); `ext` bytes of authenticator extensions make the blob as large as wanted.
fn webauthn_sig(env: &Env, sk: &p256::ecdsa::SigningKey, m: &[u8; 32], ext: usize) -> StdVec<u8> {
    let challenge = std::string::String::from_utf8(b64url32(m).to_vec()).unwrap();
    let cdj = format!("{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\",\"origin\":\"https://a.example\"}}");
    let mut auth_data = RP.to_vec();
    auth_data.extend_from_slice(&[if ext > 0 { 0x85 } else { 0x05 }, 0, 0, 0, 1]);
    auth_data.extend(std::iter::repeat_n(0xa0u8, ext));
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&env.crypto().sha256(&b(env, cdj.as_bytes())).to_array());
    let sig: p256::ecdsa::Signature = sk.sign(&signed);
    abi_encode_webauthn(&auth_data, cdj.as_bytes(), &sig.normalize_s().unwrap_or(sig).to_bytes())
}

impl Sk {
    fn kind(&self) -> u32 {
        match self {
            Sk::Wa(_) => 0x0100,
            Sk::P256(_) => 0x0101,
            Sk::Ed(_) => 0x0102,
            Sk::K1(_) => 0x0108,
        }
    }
    fn key_data(&self, env: &Env) -> Bytes {
        let v = match self {
            Sk::Ed(k) => k.verifying_key().to_bytes().to_vec(),
            Sk::P256(k) => k.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec(),
            Sk::Wa(k) => [&k.verifying_key().to_encoded_point(false).as_bytes()[1..], &RP[..]].concat(),
            Sk::K1(k) => k.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec(),
        };
        b(env, &v)
    }
    fn ua(&self, env: &Env) -> BytesN<32> {
        digest::ua_of(env, self.kind(), &self.key_data(env))
    }
    /// The kind's signature over `ua_msg` (spec §3).
    fn sign(&self, env: &Env, m: &[u8; 32]) -> Bytes {
        let v = match self {
            Sk::Ed(k) => k.sign(m).to_bytes().to_vec(),
            Sk::P256(k) => {
                let s: p256::ecdsa::Signature = k.sign(m);
                s.normalize_s().unwrap_or(s).to_bytes().to_vec()
            }
            Sk::Wa(k) => webauthn_sig(env, k, m, 0),
            Sk::K1(k) => k1_sign(k, m),
        };
        b(env, &v)
    }
    fn pop(&self, env: &Env) -> Bytes {
        let ua = self.ua(env);
        self.sign(env, &msg(env, self.kind(), PURPOSE_POP_V2, &reg_digest(env, &ua)))
    }
    fn register(&self, env: &Env, c: &UaRegistryClient) -> BytesN<32> {
        c.register(&self.kind(), &self.key_data(env), &no_attrs(env), &self.pop(env), &Bytes::new(env), &None)
    }
}

// ---------- msig ----------

struct Msig {
    kd: Bytes,
    ua: BytesN<32>,
    ids: StdVec<[u8; 32]>,
}

/// CTR-UA-09 key data, members sorted by id.
fn msig(env: &Env, threshold: u16, members: &[(u16, [u8; 32], u16)]) -> Msig {
    let mut m = members.to_vec();
    m.sort_by_key(|x| x.1);
    let mut v = threshold.to_be_bytes().to_vec();
    v.extend_from_slice(&(m.len() as u16).to_be_bytes());
    for (k, id, w) in &m {
        v.extend_from_slice(&k.to_be_bytes());
        v.extend_from_slice(id);
        v.extend_from_slice(&w.to_be_bytes());
    }
    let kd = b(env, &v);
    Msig { ua: digest::ua_of(env, 0x0120, &kd), kd, ids: m.iter().map(|x| x.1).collect() }
}

impl Msig {
    fn index(&self, id: &[u8; 32]) -> u32 {
        self.ids.iter().position(|x| x == id).unwrap() as u32
    }
    /// `member_digest(ua, ua_message(msig, purpose, digest))`.
    fn md(&self, env: &Env, purpose: [u8; 32], d: &BytesN<32>) -> BytesN<32> {
        digest::member_digest(env, &self.ua, &digest::ua_message(env, 0x0120, &n(env, purpose), d))
    }
    /// A registered member's slot: empty `keyData`, the signature under purpose `member` over `md`.
    fn slot(&self, env: &Env, s: &Sk, purpose: [u8; 32], d: &BytesN<32>) -> (u32, StdVec<u8>, StdVec<u8>) {
        let m = msg(env, s.kind(), PURPOSE_MEMBER, &self.md(env, purpose, d));
        (self.index(&s.ua(env).to_array()), vec![], vecu8(&s.sign(env, &m)))
    }
    fn register(&self, env: &Env, c: &UaRegistryClient, pop: &Bytes) -> BytesN<32> {
        c.register(&0x0120, &self.kd, &no_attrs(env), pop, &Bytes::new(env), &None)
    }
}

/// `abi.encode(MemberSig[])` (`{u16 index, bytes keyData, bytes sig}`), canonical.
fn member_sigs(env: &Env, slots: &[(u32, StdVec<u8>, StdVec<u8>)]) -> Bytes {
    let w = |v: usize| {
        let mut x = [0u8; 32];
        x[24..].copy_from_slice(&(v as u64).to_be_bytes());
        x
    };
    let pad = |v: &[u8]| {
        let mut x = v.to_vec();
        x.resize(v.len().div_ceil(32) * 32, 0);
        x
    };
    let mut heads = StdVec::new();
    let mut tails = StdVec::new();
    let mut off = 32 * slots.len();
    for (i, kd, sig) in slots {
        heads.extend_from_slice(&w(off));
        let mut t = StdVec::new();
        t.extend_from_slice(&w(*i as usize));
        t.extend_from_slice(&w(96));
        t.extend_from_slice(&w(96 + 32 + pad(kd).len()));
        t.extend_from_slice(&w(kd.len()));
        t.extend_from_slice(&pad(kd));
        t.extend_from_slice(&w(sig.len()));
        t.extend_from_slice(&pad(sig));
        off += t.len();
        tails.extend_from_slice(&t);
    }
    let mut out = w(32).to_vec();
    out.extend_from_slice(&w(slots.len()));
    out.extend_from_slice(&heads);
    out.extend_from_slice(&tails);
    b(env, &out)
}

// ---------- register ----------

#[test]
fn register_portable_pop_from_portable_json() {
    let (env, c) = setup();
    for name in S3_ROWS.iter() {
        let r = portable(&env, name);
        assert_eq!(r.attrs, no_attrs(&env), "{name}");
        let ua = r.on(&c);
        assert_eq!(ua, r.ua, "{name}");
        let ev = UaRegistered {
            ua: ua.clone(),
            kind: r.kind,
            record: RegisteredRecord {
                kind: r.kind,
                key_data: r.kd.clone(),
                attrs: r.attrs.clone(),
                pop_hash: env.crypto().keccak256(&r.pop).into(),
                pop_checked: Checked::Chain,
                pqz_pop_checked: Checked::None,
                proven: false,
                signable: true,
                index: if *name == "mldsa65#2" { 1 } else { 0 },
                ledger: env.ledger().sequence(),
            },
            checked: Checked::Chain,
        };
        assert_eq!(env.events().all().events().last().unwrap(), &ev.to_xdr(&env, &c.address), "{name}");
        let got = c.registration_of(&ua).unwrap();
        assert_eq!(got, (r.kind, r.kd.clone(), r.attrs.clone(), r.pop.clone(), r.pqz_pop.clone()), "{name}");
        let rec = c.record_of(&ua).unwrap();
        assert_eq!(rec.pop, r.pop, "pop stays in Ua(ua): {name}");
        assert!(rec.signable && rec.pop_checked == Checked::Chain && rec.pqz_pop_checked == Checked::None && !rec.proven);
        assert_eq!(c.key_owner(&expected_key_hash(&env, r.kind, &vecu8(&r.kd))), Some(ua.clone()), "{name}");
        assert!(c.receivable(&ua));
        assert_eq!(c.ua_of(&r.kind, &r.kd), ua);
    }
}

#[test]
fn register_any_submitter() {
    let (env, c) = setup();
    portable(&env, "p256").on(&c);
    assert!(env.auths().is_empty(), "no source-account (or any) auth required");
}

#[test]
fn register_front_run_identical() {
    let (env, c) = setup();
    let r = portable(&env, "ed25519");
    let ua = r.on(&c);
    let first = c.record_of(&ua).unwrap();
    assert_eq!(r.refused(&c), Error::AlreadyRegistered);
    assert_eq!(c.record_of(&ua).unwrap(), first);
    assert_eq!(c.ua_count(&r.kind), 1);
}

#[test]
fn register_disabled_kind_refused() {
    let (env, c) = setup();
    for name in ["bip340", "fndsa512", "slhdsa128s", "zether-bls12381"] {
        assert_eq!(portable(&env, name).refused(&c), Error::KindDisabled, "{name}");
    }
    let e = err(c.try_register(&0x0011, &b(&env, &[1; 32]), &no_attrs(&env), &Bytes::new(&env), &Bytes::new(&env), &None));
    assert_eq!(e, Error::KindDisabled, "a native kind registers nothing");
}

#[test]
fn register_attrs_refused_4b() {
    let (env, c) = setup();
    assert_eq!(portable(&env, "mldsa65/n2304-kmax4096").refused(&c), Error::Attrs);
    let (env, c) = setup();
    portable(&env, "mldsa65#1").on(&c);
    portable(&env, "mldsa65#2").on(&c);
    assert_eq!(portable(&env, "msig-pq/n2304-kmax4096").refused(&c), Error::Attrs);
    // A pqz_pop without attrs is an attribute too.
    let mut r = portable(&env, "p256");
    r.pqz_pop = b(&env, &[1]);
    assert_eq!(r.refused(&c), Error::Attrs);
}

#[test]
fn register_unverifiable_part_refused_4b() {
    let env = new_env();
    let relayer = Address::generate(&env);
    let c = deploy(&env, &[relayer.clone()]);
    let e = ed(1);
    e.register(&env, &c);
    let mut contract_id = [0u8; 32];
    contract_id[12..].copy_from_slice(&[0x22; 20]);
    let m = msig(&env, 2, &[(0x0002, contract_id, 1), (0x0102, e.ua(&env).to_array(), 1)]);
    let rd = reg_digest(&env, &m.ua);
    let pop = member_sigs(&env, &[(m.index(&contract_id), vec![], vec![1; 65]), m.slot(&env, &e, PURPOSE_POP_V2, &rd)]);
    for r in [None, Some(relayer)] {
        let got = err(c.try_register(&0x0120, &m.kd, &no_attrs(&env), &pop, &Bytes::new(&env), &r));
        assert_eq!(got, Error::NotVerifiable);
    }
}

/// No key has a derived id with 96 zero top bits, so `register`'s `IdInNativeSpace` is shown on its predicate, which
/// `register` applies to `ua_of(kind, key_data)` (step 3), against `kinds.json` `nativeSpace`.
#[test]
fn id_in_native_space_refused() {
    let env = Env::default();
    let rows = json(KINDS)["nativeSpace"].as_array().unwrap().clone();
    assert!(rows.len() >= 4);
    for r in rows {
        let id = n32(&env, &r["id"]).to_array();
        assert_eq!(crate::in_native_space(&id), r["inNativeSpace"].as_bool().unwrap(), "{}", r["id"]);
    }
}

#[test]
fn key_hash_unique() {
    let (env, c) = setup();
    // The contract's keyHash against kinds.json for every valid row of an S3 single-key kind.
    let mut seen = 0;
    for r in json(KINDS)["valid"].as_array().unwrap() {
        let kind = kind_of(&r["kind"]);
        if [0x0100, 0x0101, 0x0102, 0x0108, 0x0130, 0x0131].contains(&kind) {
            let kh = crate::key_hash(&env, kind, &b(&env, &hx(&r["keyData"]))).unwrap();
            assert_eq!(kh.to_array().to_vec(), hx(&r["keyHash"]), "{}", r["name"]);
            seen += 1;
        }
    }
    assert!(seen >= 6);
    // One P-256 key, two kinds (same group, same x): the second is `KeyInUse`.
    let (p, w) = (Sk::P256(p256k(9)), Sk::Wa(p256k(9)));
    let ua = p.register(&env, &c);
    let e = err(c.try_register(&w.kind(), &w.key_data(&env), &no_attrs(&env), &w.pop(&env), &Bytes::new(&env), &None));
    assert_eq!(e, Error::KeyInUse);
    assert_eq!(c.key_owner(&expected_key_hash(&env, 0x0101, &vecu8(&p.key_data(&env)))), Some(ua));
}

/// `kinds.json` `invalid[]` rows of the S3 kinds: all refused; `KeyData` wherever the contract checks (length,
/// canonical coordinates, the ed25519 key check, the `msig` layout). Off-curve points and the ed25519 "not a point"
/// key are left to the host's verify of the `pop` (spec §3; plan finding F1).
#[test]
fn key_data_invalid_rows_refused() {
    let (env, c) = setup();
    let mut keydata = 0;
    for r in json(KINDS)["invalid"].as_array().unwrap() {
        let kind = kind_of(&r["kind"]);
        if ![0x0100, 0x0101, 0x0102, 0x0108, 0x0120, 0x0130, 0x0131].contains(&kind) {
            continue;
        }
        let res = c.try_register(&kind, &b(&env, &hx(&r["keyData"])), &no_attrs(&env), &b(&env, &[0; 64]), &Bytes::new(&env), &None);
        let reason = r["reason"].as_str().unwrap();
        if ["off the curve", "(0, 0)", "not a point"].contains(&reason) {
            assert!(res.is_err(), "{kind} {reason}");
        } else {
            assert_eq!(err(res), Error::KeyData, "{kind} {reason}");
            keydata += 1;
        }
    }
    assert!(keydata >= 55, "{keydata}");
}

#[test]
fn registration_of_returns_register_args() {
    let (env, c) = setup();
    let r = portable(&env, "mldsa44");
    let ua = r.on(&c);
    assert_eq!(c.registration_of(&ua), Some((r.kind, r.kd, r.attrs, r.pop, r.pqz_pop)));
    let other = n(&env, [0x42; 32]);
    assert_eq!(c.registration_of(&other), None);
    assert_eq!(c.record_of(&other), None);
}

#[test]
fn msig_member_unknown_refused() {
    let (env, c) = setup();
    // EVM's msig-classical: members of kinds Soroban does not enable (bls-bn254-minsig, schnorr-bn254).
    assert_eq!(portable(&env, "msig-classical").refused(&c), Error::MemberUnknown);
    // An S3 member that is not registered, and a registered key stated under another kind.
    let (e, p) = (ed(2), Sk::P256(p256k(3)));
    let pua = p.register(&env, &c);
    let m = msig(&env, 1, &[(0x0102, e.ua(&env).to_array(), 1)]);
    let pop = member_sigs(&env, &[m.slot(&env, &e, PURPOSE_POP_V2, &reg_digest(&env, &m.ua))]);
    assert_eq!(err(c.try_register(&0x0120, &m.kd, &no_attrs(&env), &pop, &Bytes::new(&env), &None)), Error::MemberUnknown);
    let m = msig(&env, 1, &[(0x0100, pua.to_array(), 1)]);
    assert_eq!(err(c.try_register(&0x0120, &m.kd, &no_attrs(&env), &pop, &Bytes::new(&env), &None)), Error::MemberUnknown);
}

/// A 2-of-3 `msig` of an in-test ed25519 key, an in-test P-256 key and `mldsa65#1`.
fn msig_2of3(env: &Env, c: &UaRegistryClient) -> (Msig, Sk, Sk) {
    let (e, p) = (ed(4), Sk::P256(p256k(5)));
    e.register(env, c);
    p.register(env, c);
    let q = portable(env, "mldsa65#1");
    q.on(c);
    let m = msig(env, 2, &[(0x0102, e.ua(env).to_array(), 1), (0x0101, p.ua(env).to_array(), 1), (0x0131, q.ua.to_array(), 1)]);
    let rd = reg_digest(env, &m.ua);
    let mut slots = vec![m.slot(env, &e, PURPOSE_POP_V2, &rd), m.slot(env, &p, PURPOSE_POP_V2, &rd)];
    slots.sort_by_key(|s| s.0);
    let ua = m.register(env, c, &member_sigs(env, &slots));
    assert_eq!(ua, m.ua);
    let rec = c.record_of(&ua).unwrap();
    assert!(rec.signable && rec.pop_checked == Checked::Chain);
    assert!(c.receivable(&ua));
    (m, e, p)
}

fn two_slots(env: &Env, m: &Msig, e: &Sk, p: &Sk, purpose: [u8; 32], d: &BytesN<32>) -> StdVec<(u32, StdVec<u8>, StdVec<u8>)> {
    let mut s = vec![m.slot(env, e, purpose, d), m.slot(env, p, purpose, d)];
    s.sort_by_key(|x| x.0);
    s
}

#[test]
fn kind_msig_vectors_verify() {
    let (env, c) = setup();
    let (m, e, p) = msig_2of3(&env, &c);
    let d = n(&env, [0x31; 32]);
    for purpose in PURPOSES {
        c.require_authorized(&m.ua, &n(&env, purpose), &d, &member_sigs(&env, &two_slots(&env, &m, &e, &p, purpose, &d)));
    }
}

#[test]
fn kind_msig_negatives_fail() {
    let (env, c) = setup();
    let (m, e, p) = msig_2of3(&env, &c);
    let (d, pm) = (n(&env, [0x32; 32]), n(&env, PURPOSE_METATX));
    let good = two_slots(&env, &m, &e, &p, PURPOSE_METATX, &d);
    // One member: below the threshold.
    for s in &good {
        assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &member_sigs(&env, &[s.clone()]))), Error::Unauthorized);
    }
    // Swapped indexes: each signature checked against the other member's key.
    let swapped = vec![(good[0].0, vec![], good[1].2.clone()), (good[1].0, vec![], good[0].2.clone())];
    assert!(c.try_require_authorized(&m.ua, &pm, &d, &member_sigs(&env, &swapped)).is_err());
    // An index past the members.
    let mut past = good.clone();
    past[1].0 = 3;
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &member_sigs(&env, &past))), Error::Unauthorized);
    // Non-canonical encodings: a trailing byte; a non-minimal outer offset.
    let enc = vecu8(&member_sigs(&env, &good));
    let mut t = enc.clone();
    t.push(0);
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &b(&env, &t))), Error::Pop);
    let mut t = vec![0u8; 31];
    t.push(64);
    t.extend_from_slice(&[0u8; 32]);
    t.extend_from_slice(&enc[32..]);
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &b(&env, &t))), Error::Pop);
    // A registered member's slot with its key data: refused (`Pop`), even though the key is right.
    let mut kd = good.clone();
    let signer = if kd[0].0 == m.index(&e.ua(&env).to_array()) { &e } else { &p };
    kd[0].1 = vecu8(&signer.key_data(&env));
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &member_sigs(&env, &kd))), Error::Pop);
    // Another purpose, another digest.
    assert!(c.try_require_authorized(&m.ua, &n(&env, PURPOSE_TRADE), &d, &member_sigs(&env, &good)).is_err());
    assert!(c.try_require_authorized(&m.ua, &pm, &n(&env, [0x33; 32]), &member_sigs(&env, &good)).is_err());
    c.require_authorized(&m.ua, &pm, &d, &member_sigs(&env, &good));
}

// ---------- native members ----------

fn ledger_account(pk: [u8; 32]) -> (std::boxed::Box<xdr::LedgerKey>, (std::boxed::Box<xdr::LedgerEntry>, Option<u32>)) {
    let id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk)));
    (
        std::boxed::Box::new(xdr::LedgerKey::Account(xdr::LedgerKeyAccount { account_id: id.clone() })),
        (
            std::boxed::Box::new(xdr::LedgerEntry {
                last_modified_ledger_seq: 0,
                data: xdr::LedgerEntryData::Account(xdr::AccountEntry {
                    account_id: id,
                    balance: 1_000_000_000,
                    seq_num: xdr::SequenceNumber(0),
                    num_sub_entries: 0,
                    inflation_dest: None,
                    flags: 0,
                    home_domain: Default::default(),
                    thresholds: xdr::Thresholds([1, 0, 0, 0]),
                    signers: Default::default(),
                    ext: xdr::AccountEntryExt::V0,
                }),
                ext: xdr::LedgerEntryExt::V0,
            }),
            None,
        ),
    )
}

/// A real ed25519-signed auth entry of account `sk` rooted at `contract.f(args)`.
fn signed_entry(env: &Env, sk: &ed25519_dalek::SigningKey, nonce: i64, contract: &Address, f: &str, args: SVec<Val>) -> SorobanAuthorizationEntry {
    let root = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: contract.into(),
            function_name: f.try_into().unwrap(),
            args: args.iter().map(|v| ScVal::try_from_val(env, &v).unwrap()).collect::<StdVec<_>>().try_into().unwrap(),
        }),
        sub_invocations: Default::default(),
    };
    let pre = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: xdr::Hash(NETWORK),
        nonce,
        signature_expiration_ledger: 200,
        invocation: root.clone(),
    })
    .to_xdr(Limits::none())
    .unwrap();
    let sig = sk.sign(&Sha256::digest(pre)).to_bytes();
    let pk = sk.verifying_key().to_bytes();
    let kv = |k: &str, v: &[u8]| ScMapEntry { key: ScVal::Symbol(ScSymbol(k.try_into().unwrap())), val: ScVal::Bytes(v.to_vec().try_into().unwrap()) };
    let map = ScMap(vec![kv("public_key", &pk), kv("signature", &sig)].try_into().unwrap());
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk)))),
            nonce,
            signature_expiration_ledger: 200,
            signature: ScVal::Vec(Some(vec![ScVal::Map(Some(map))].try_into().unwrap())),
        }),
        root_invocation: root,
    }
}

/// S10: a `G…` member is checked by the host, `require_auth_for_args((ua, purpose, digest))`, over a real signed entry
/// (as `relay_g_account_payer_real_signed_entries`); without the entry the call fails.
#[test]
fn msig_soroban_native_member_host_auth() {
    let gsk = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
    let gpk = gsk.verifying_key().to_bytes();
    let mut snap: soroban_ledger_snapshot::LedgerSnapshot = Env::default().to_ledger_snapshot();
    snap.ledger_entries.push(ledger_account(gpk));
    let env = Env::from_ledger_snapshot(snap);
    env.cost_estimate().budget().reset_unlimited();
    env.ledger().with_mut(|l| l.network_id = NETWORK);
    let c = deploy(&env, &[]);
    let m = msig(&env, 1, &[(0x0011, gpk, 1)]);
    let empty_slot = member_sigs(&env, &[(0, vec![], vec![])]);
    let rd = reg_digest(&env, &m.ua);
    let pv2 = n(&env, PURPOSE_POP_V2);
    // register: the G member authorises (ua, pop v2, registrationDigest).
    assert!(c.try_register(&0x0120, &m.kd, &no_attrs(&env), &empty_slot, &Bytes::new(&env), &None).is_err());
    let args: SVec<Val> = (m.ua.clone(), pv2, rd).into_val(&env);
    env.set_auths(&[signed_entry(&env, &gsk, 1, &c.address, "register", args)]);
    m.register(&env, &c, &empty_slot);
    assert!(c.record_of(&m.ua).unwrap().signable);
    // require_authorized: the same member over (ua, metatx, digest).
    let (pm, d) = (n(&env, PURPOSE_METATX), n(&env, [0x51; 32]));
    env.set_auths(&[]);
    assert!(c.try_require_authorized(&m.ua, &pm, &d, &empty_slot).is_err(), "without the signed entry");
    let other: SVec<Val> = (m.ua.clone(), pm.clone(), n(&env, [0x52; 32])).into_val(&env);
    env.set_auths(&[signed_entry(&env, &gsk, 2, &c.address, "require_authorized", other)]);
    assert!(c.try_require_authorized(&m.ua, &pm, &d, &empty_slot).is_err(), "an entry for another digest");
    let args: SVec<Val> = (m.ua.clone(), pm.clone(), d.clone()).into_val(&env);
    env.set_auths(&[signed_entry(&env, &gsk, 3, &c.address, "require_authorized", args)]);
    c.require_authorized(&m.ua, &pm, &d, &empty_slot);
    // A native slot carrying bytes is refused.
    env.set_auths(&[]);
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &member_sigs(&env, &[(0, vec![], vec![1])]))), Error::Pop);
}

/// `personal_sign(member_digest)` of an EOA key and its 20-byte address as a native-space id.
fn eoa(env: &Env, sk: &k256::ecdsa::SigningKey) -> [u8; 32] {
    let pt = sk.verifying_key().to_encoded_point(false);
    let h = env.crypto().keccak256(&b(env, &pt.as_bytes()[1..])).to_array();
    let mut id = [0u8; 32];
    id[12..].copy_from_slice(&h[12..]);
    id
}
fn personal_sign(env: &Env, sk: &k256::ecdsa::SigningKey, md: &BytesN<32>) -> StdVec<u8> {
    let mut m = b"\x19Ethereum Signed Message:\n32".to_vec();
    m.extend_from_slice(&md.to_array());
    k1_sign(sk, &env.crypto().keccak256(&b(env, &m)).to_array())
}

/// S10: an `evm-eoa` member signs the portable `pop` (EIP-191 `personal_sign`) and never counts for signing.
#[test]
fn msig_evm_eoa_member_portable_only() {
    let (env, c) = setup();
    // EVM's msig-pq-native registers by its personal_sign pop (members evm-eoa + mldsa65#1, 2-of-2).
    portable(&env, "mldsa65#1").on(&c);
    let r = portable(&env, "msig-pq-native");
    let ua = r.on(&c);
    assert!(!c.record_of(&ua).unwrap().signable, "the EOA's weight does not count for signing");
    // In-test: 1-of-2 (evm-eoa, ed25519), registered by the EOA alone; signing needs the ed25519 member.
    let (k, e) = (k1(6), ed(7));
    e.register(&env, &c);
    let id = eoa(&env, &k);
    let m = msig(&env, 1, &[(0x0001, id, 1), (0x0102, e.ua(&env).to_array(), 1)]);
    let rd = reg_digest(&env, &m.ua);
    let pop = member_sigs(&env, &[(m.index(&id), vec![], personal_sign(&env, &k, &m.md(&env, PURPOSE_POP_V2, &rd)))]);
    m.register(&env, &c, &pop);
    assert!(c.receivable(&m.ua));
    let (pm, d) = (n(&env, PURPOSE_METATX), n(&env, [0x61; 32]));
    let eoa_slot = member_sigs(&env, &[(m.index(&id), vec![], personal_sign(&env, &k, &m.md(&env, PURPOSE_METATX, &d)))]);
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &eoa_slot)), Error::NotVerifiable);
    c.require_authorized(&m.ua, &pm, &d, &member_sigs(&env, &[m.slot(&env, &e, PURPOSE_METATX, &d)]));
}

#[test]
fn msig_unsignable_not_receivable() {
    let (env, c) = setup();
    portable(&env, "mldsa65#1").on(&c);
    let r = portable(&env, "msig-pq-native");
    let ua = r.on(&c);
    assert!(!c.record_of(&ua).unwrap().signable);
    assert!(!c.receivable(&ua));
    // Its own pop slots, offered as a metatx signature: refused before any member check.
    let e = err(c.try_require_authorized(&ua, &n(&env, PURPOSE_METATX), &n(&env, [1; 32]), &r.pop));
    assert_eq!(e, Error::Unauthorized);
    assert!(!c.receivable(&n(&env, [0x42; 32])), "unregistered: false (SOR-D15)");
}

// ---------- require_authorized ----------

/// Every S3 single-key kind: its `signatures.json` / `pq_signatures.json` row registers by its `pop` (context A, no
/// attributes) and each signature passes under its purpose and fails under every other one; in-test keys of the
/// classical kinds also sign `trade` and `metatx-cancel` (the vectors sign `metatx` and `member` only).
#[test]
fn require_authorized_each_kind_and_purpose() {
    let (env, c) = setup();
    let rows: StdVec<Value> = ["webauthn-p256", "p256", "ed25519", "secp256k1"]
        .iter()
        .map(|nm| derived(SIGNATURES, "derived", nm))
        .chain(["mldsa44", "mldsa65"].iter().map(|nm| derived(PQ_SIGNATURES, "kinds", nm)))
        .collect();
    for row in rows {
        let (kind, kd) = (kind_of(&row["kind"]), b(&env, &hx(&row["keyData"])));
        let ua = n32(&env, &row["ua"]);
        assert_eq!(row["pop"]["registrationDigest"].as_str().unwrap(), format!("0x{}", hex(&reg_digest(&env, &ua).to_array())));
        assert_eq!(c.register(&kind, &kd, &no_attrs(&env), &b(&env, &hx(&row["pop"]["sig"])), &Bytes::new(&env), &None), ua);
        for s in row["sigs"].as_array().unwrap() {
            let (p, d, sig) = (n32(&env, &s["purposeTag"]), n32(&env, &s["digest"]), b(&env, &hx(&s["sig"])));
            c.require_authorized(&ua, &p, &d, &sig);
            for other in PURPOSES.iter().filter(|x| **x != p.to_array()) {
                assert!(c.try_require_authorized(&ua, &n(&env, *other), &d, &sig).is_err(), "{} under another purpose", row["name"]);
            }
        }
    }
    for s in [Sk::Wa(p256k(11)), Sk::P256(p256k(12)), ed(13), Sk::K1(k1(14))] {
        let ua = s.register(&env, &c);
        let d = n(&env, [0x71; 32]);
        for p in PURPOSES {
            let sig = s.sign(&env, &msg(&env, s.kind(), p, &d));
            c.require_authorized(&ua, &n(&env, p), &d, &sig);
            for other in PURPOSES.iter().filter(|x| **x != p) {
                assert!(c.try_require_authorized(&ua, &n(&env, *other), &d, &sig).is_err());
            }
        }
    }
}

fn hex(v: &[u8]) -> std::string::String {
    v.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn require_authorized_refuses_portable_purposes() {
    let (env, c) = setup();
    let s = Sk::P256(p256k(21));
    let ua = s.register(&env, &c);
    let d = n(&env, [0x81; 32]);
    for p in [PURPOSE_POP_V2, PURPOSE_KEM, PURPOSE_PQZ_KEY] {
        let sig = s.sign(&env, &msg(&env, s.kind(), p, &d));
        assert_eq!(err(c.try_require_authorized(&ua, &n(&env, p), &d, &sig)), Error::Unauthorized);
    }
    // The registration pop itself, replayed through require_authorized.
    let rd = reg_digest(&env, &ua);
    assert_eq!(err(c.try_require_authorized(&ua, &n(&env, PURPOSE_POP_V2), &rd, &s.pop(&env))), Error::Unauthorized);
}

#[test]
fn require_authorized_not_registered() {
    let (env, c) = setup();
    let e = err(c.try_require_authorized(&n(&env, [0x91; 32]), &n(&env, PURPOSE_METATX), &n(&env, [0; 32]), &Bytes::new(&env)));
    assert_eq!(e, Error::NotRegistered);
}

// ---------- lists, TTL, relayers ----------

#[test]
fn ua_lists_per_kind() {
    let (env, c) = setup();
    let eds: StdVec<BytesN<32>> = (30..33).map(|i| ed(i).register(&env, &c)).collect();
    let p = Sk::P256(p256k(33)).register(&env, &c);
    assert_eq!((c.ua_count(&0x0102), c.ua_count(&0x0101), c.ua_count(&0x0130)), (3, 1, 0));
    for (i, ua) in eds.iter().enumerate() {
        assert_eq!(&c.ua_at(&0x0102, &(i as u32)), ua);
        assert_eq!(c.record_of(ua).unwrap().index, i as u32);
    }
    assert_eq!(c.ua_at(&0x0101, &0), p);
    assert_eq!(c.record_of(&p).unwrap().index, 0);
    assert_eq!(err(c.try_ua_at(&0x0102, &3)), Error::NotRegistered);
    let page = |s: u32, k: u32| c.ua_page(&0x0102, &s, &k).iter().collect::<StdVec<_>>();
    assert_eq!(page(0, 10), eds);
    assert_eq!(page(1, 1), eds[1..2].to_vec());
    assert_eq!(page(2, u32::MAX), eds[2..].to_vec());
    assert!(page(3, 5).is_empty() && page(9, 1).is_empty() && page(0, 0).is_empty());
    assert!(c.ua_page(&0x0130, &0, &5).is_empty());
}

#[test]
fn entries_extend_ttl() {
    let (env, c) = setup();
    let s = Sk::P256(p256k(41));
    let ua = s.register(&env, &c);
    let kh = expected_key_hash(&env, 0x0101, &vecu8(&s.key_data(&env)));
    let ttl = |k: &Key| env.as_contract(&c.address, || env.storage().persistent().get_ttl(k));
    let keys = [Key::Ua(ua.clone()), Key::Key(kh), Key::List(0x0101, 0), Key::Count(0x0101), Key::Signer(ua.clone())];
    for k in &keys {
        assert_eq!(ttl(k), 60 * DAY);
    }
    env.ledger().with_mut(|l| l.sequence_number += 31 * DAY);
    for k in &keys {
        assert_eq!(ttl(k), 29 * DAY);
    }
    let d = n(&env, [0xa1; 32]);
    c.require_authorized(&ua, &n(&env, PURPOSE_METATX), &d, &s.sign(&env, &msg(&env, 0x0101, PURPOSE_METATX, &d)));
    assert_eq!(ttl(&Key::Ua(ua.clone())), 60 * DAY, "Ua(ua) extended by require_authorized");
    assert_eq!(ttl(&Key::Signer(ua.clone())), 60 * DAY);
    assert_eq!(ttl(&Key::Count(0x0101)), 29 * DAY, "an entry not read keeps its TTL");
}

#[test]
fn relayers_from_constructor() {
    let env = new_env();
    assert!(deploy(&env, &[]).relayers().is_empty());
    let (a, b2) = (Address::generate(&env), Address::generate(&env));
    let got = deploy(&env, &[a.clone(), b2.clone()]).relayers();
    assert_eq!(got.iter().collect::<StdVec<_>>(), vec![a, b2]);
}

/// msig-pophash I1 (controller): a member check reads the member's key alone. The same WebAuthn member, registered
/// once with a normal `pop` and once (another ledger, everything else identical) with a 16 KiB `pop` (authenticator
/// extensions), is the sole member of a 1-of-1 `msig`: `require_authorized` costs exactly the same CPU and memory
/// budget; reading the whole record shows the `pop` difference the check avoids.
#[test]
fn member_large_pop_same_budget() {
    let run = |ext: usize| {
        let (env, c) = setup();
        let s = Sk::Wa(p256k(51));
        let (ua, Sk::Wa(k)) = (s.ua(&env), &s) else { unreachable!() };
        let pop = webauthn_sig(&env, k, &msg(&env, 0x0100, PURPOSE_POP_V2, &reg_digest(&env, &ua)), ext);
        c.register(&0x0100, &s.key_data(&env), &no_attrs(&env), &b(&env, &pop), &Bytes::new(&env), &None);
        let m = msig(&env, 1, &[(0x0100, ua.to_array(), 1)]);
        m.register(&env, &c, &member_sigs(&env, &[m.slot(&env, &s, PURPOSE_POP_V2, &reg_digest(&env, &m.ua))]));
        let d = n(&env, [0xb1; 32]);
        let auth = member_sigs(&env, &[m.slot(&env, &s, PURPOSE_METATX, &d)]);
        c.require_authorized(&m.ua, &n(&env, PURPOSE_METATX), &d, &auth);
        let bud = env.cost_estimate().budget();
        let check = (bud.cpu_instruction_cost(), bud.memory_bytes_cost());
        let rec = c.record_of(&ua).unwrap();
        (check, env.cost_estimate().budget().memory_bytes_cost(), rec.pop.len())
    };
    let (normal, large) = (run(0), run(16_384));
    std::println!("require_authorized (cpu, mem): normal pop ({} B) {:?}, large pop ({} B) {:?}", normal.2, normal.0, large.2, large.0);
    std::println!("record_of memory: normal pop {}, large pop {}", normal.1, large.1);
    assert!(large.2 >= normal.2 + 16_384);
    assert_eq!(normal.0, large.0, "the member's pop never enters the check");
    assert!(large.1 > normal.1 + 16_384, "a whole-record read would scale with the pop");
}

/// T3 review m2: `native_address` rebuilds the `Address` of a `C…` (0x0012) and a `G…` (0x0011) id from its 32 bytes.
#[test]
fn native_address_round_trip() {
    use soroban_sdk::xdr::ToXdr as _;
    let env = new_env();
    let g = Address::from_str(&env, "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6");
    for (kind, a) in [(digest::SOROBAN_CONTRACT, Address::generate(&env)), (digest::STELLAR_ACCOUNT, g)] {
        let x = a.clone().to_xdr(&env);
        let id: [u8; 32] = vecu8(&x.slice(x.len() - 32..)).try_into().unwrap();
        assert_eq!(crate::native_address(&env, kind, &id), a);
    }
}
