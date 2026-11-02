//! T3: the `UaRegistry` entries against the shared UA vectors (`smartcontracts/vectors/ua/`) and in-test keys. Real
//! authorization only: no test mocks auths; the one native member signs a real ed25519 auth entry.
extern crate std;
use std::{format, vec, vec::Vec as StdVec};

use ed25519_dalek::Signer as _;
use ml_dsa::Keypair as _;
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
pub(crate) const PORTABLE: &str = include_str!("../../../../vectors/ua/portable.json");

const DAY: u32 = 17_280;
pub(crate) const NETWORK: [u8; 32] = [7; 32];
const RP: [u8; 32] = [0x5a; 32];
/// The single-key `registrations[]` rows of an S3 kind with empty `attrs`.
const S3_ROWS: [&str; 7] = ["webauthn-p256", "p256", "ed25519", "secp256k1", "mldsa44", "mldsa65#1", "mldsa65#2"];
const PURPOSES: [[u8; 32]; 4] = [PURPOSE_METATX, PURPOSE_TRADE, PURPOSE_METATX_CANCEL, PURPOSE_MEMBER];

// ---------- setup ----------

pub(crate) fn new_env() -> Env {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    env.ledger().with_mut(|l| l.network_id = NETWORK);
    env
}

pub(crate) fn deploy(env: &Env, relayers: &[Address]) -> UaRegistryClient<'static> {
    let mut v = SVec::new(env);
    for r in relayers {
        v.push_back(r.clone());
    }
    UaRegistryClient::new(env, &env.register(UaRegistry, (v,)))
}

pub(crate) fn setup() -> (Env, UaRegistryClient<'static>) {
    let env = new_env();
    let c = deploy(&env, &[]);
    (env, c)
}

/// The contract error of a failed call (a host error or a success panics).
pub(crate) fn err<T, C: core::fmt::Debug>(r: Result<T, Result<soroban_sdk::Error, C>>) -> Error {
    match r {
        Err(Ok(e)) => Error::try_from(e).unwrap_or_else(|_| panic!("host error {e:?}")),
        Err(Err(e)) => panic!("invoke error {e:?}"),
        Ok(_) => panic!("succeeded"),
    }
}

pub(crate) fn n(env: &Env, a: [u8; 32]) -> BytesN<32> {
    BytesN::from_array(env, &a)
}

pub(crate) fn vecu8(x: &Bytes) -> StdVec<u8> {
    x.iter().collect()
}

pub(crate) fn no_attrs(env: &Env) -> UaAttrs {
    UaAttrs::none(env)
}

/// `kem_pk` split into its `KemKey` fields (the empty key = none).
pub(crate) fn kem_key(env: &Env, pk: &[u8]) -> KemKey {
    if pk.is_empty() {
        return KemKey::none(env);
    }
    let x = pk.len() - 32;
    KemKey { scheme: pk[0] as u32, mlkem_ek: b(env, &pk[1..x]), x25519: n(env, pk[x..].try_into().unwrap()) }
}

/// The typed form of CTR-UA-09 key data; `None` when the bytes are no structure at all (no typed call can send them).
pub(crate) fn structure_of(env: &Env, kd: &[u8]) -> Option<MsigStructure> {
    if kd.len() < 4 || (kd.len() - 4) % 36 != 0 {
        return None;
    }
    let u16_at = |o: usize| u16::from_be_bytes([kd[o], kd[o + 1]]) as u32;
    let mut members = SVec::new(env);
    for o in (4..kd.len()).step_by(36) {
        members.push_back(MsigMember { kind: u16_at(o), id: n(env, kd[o + 2..o + 34].try_into().unwrap()), weight: u16_at(o + 34) });
    }
    (u16_at(2) == members.len()).then(|| MsigStructure { threshold: u16_at(0), members })
}

/// A vector's `pop` / `auth` bytes `abi.encode(MemberSig[])` as typed slots ("" = none).
pub(crate) fn members_of(env: &Env, pop: &Bytes) -> SVec<MemberSig> {
    if pop.is_empty() { SVec::new(env) } else { crate::abi::decode_member_sigs(env, pop) }
}

/// typed(`UARegistration`) of a record without attributes (TS-D1, the zero KEM record): what its `pop` signs under
/// purpose `pop` v2.
pub(crate) fn reg_digest(env: &Env, ua: &BytesN<32>, kind: u32) -> BytesN<32> {
    let z = n(env, [0; 32]);
    registration_digest(env, &portable_record_hash(env, ua, kind, &z, &kem_record_hash(env, ua, 0, 0, &z)), &z).into()
}

pub(crate) fn msg(env: &Env, kind: u32, purpose: [u8; 32], d: &BytesN<32>) -> [u8; 32] {
    digest::ua_message(env, kind, &n(env, purpose), d).to_array()
}

// ---------- portable rows ----------

pub(crate) struct Reg {
    pub(crate) kind: u32,
    pub(crate) kd: Bytes,
    pub(crate) attrs: UaAttrs,
    pub(crate) pop: Bytes,
    pub(crate) pqz_pop: Bytes,
    pub(crate) ua: BytesN<32>,
}

pub(crate) type Tried = Result<Result<BytesN<32>, soroban_sdk::ConversionError>, Result<soroban_sdk::Error, soroban_sdk::InvokeError>>;

pub(crate) fn portable(env: &Env, name: &str) -> Reg {
    portable_row(env, &derived(PORTABLE, "registrations", name))
}

pub(crate) fn portable_row(env: &Env, r: &Value) -> Reg {
    let a = &r["attrs"];
    Reg {
        kind: kind_of(&r["kind"]),
        kd: b(env, &hx(&r["keyData"])),
        attrs: UaAttrs {
            pqz_key: b(env, &hx(&a["pqzKey"])),
            pqz_pop_hash: n32(env, &a["pqzPopHash"]),
            kem: kem_key(env, &hx(&a["kemPk"])),
            kem_pk_hash: n(env, [0; 32]),
        },
        pop: b(env, &hx(&r["pop"])),
        pqz_pop: b(env, &hx(&r["pqzPop"])),
        ua: n32(env, &r["ua"]),
    }
}

impl Reg {
    /// `register`, or `register_msig` of an `msig` row (one typed form, as EVM).
    pub(crate) fn tried_by(&self, c: &UaRegistryClient, relayer: &Option<Address>) -> Tried {
        if self.kind != 0x0120 {
            return c.try_register(&self.kind, &self.kd, &self.attrs, &self.pop, &self.pqz_pop, relayer);
        }
        let env = &c.env;
        let s = structure_of(env, &vecu8(&self.kd)).unwrap();
        c.try_register_msig(&s, &self.attrs, &members_of(env, &self.pop), &self.pqz_pop, relayer)
    }
    pub(crate) fn tried(&self, c: &UaRegistryClient) -> Tried {
        self.tried_by(c, &None)
    }
    pub(crate) fn on_by(&self, c: &UaRegistryClient, relayer: &Option<Address>) -> BytesN<32> {
        self.tried_by(c, relayer).unwrap().unwrap()
    }
    pub(crate) fn on(&self, c: &UaRegistryClient) -> BytesN<32> {
        self.on_by(c, &None)
    }
    pub(crate) fn refused(&self, c: &UaRegistryClient) -> Error {
        err(self.tried(c))
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

pub(crate) enum Sk {
    Ed(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
    Wa(p256::ecdsa::SigningKey),
    K1(k256::ecdsa::SigningKey),
    Ml(std::boxed::Box<ml_dsa::SigningKey<ml_dsa::MlDsa65>>),
}

pub(crate) fn ed(seed: u8) -> Sk {
    Sk::Ed(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}
fn p256k(seed: u8) -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap()
}
/// An in-test `mldsa65` key: an in-test `msig` of a PQ majority needs a real member signature over its own digest.
pub(crate) fn ml(seed: u8) -> Sk {
    Sk::Ml(std::boxed::Box::new(ml_dsa::SigningKey::from_seed(&ml_dsa::Seed::from([seed; 32]))))
}
pub(crate) fn k1(seed: u8) -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap()
}

/// `r ‖ s ‖ v` (v = 27 / 28) of a low-s secp256k1 signature over a 32-byte prehash.
pub(crate) fn k1_sign(sk: &k256::ecdsa::SigningKey, h: &[u8; 32]) -> StdVec<u8> {
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
    pub(crate) fn kind(&self) -> u32 {
        match self {
            Sk::Wa(_) => 0x0100,
            Sk::P256(_) => 0x0101,
            Sk::Ed(_) => 0x0102,
            Sk::K1(_) => 0x0108,
            Sk::Ml(_) => 0x0131,
        }
    }
    pub(crate) fn key_data(&self, env: &Env) -> Bytes {
        let v = match self {
            Sk::Ed(k) => k.verifying_key().to_bytes().to_vec(),
            Sk::P256(k) => k.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec(),
            Sk::Wa(k) => [&k.verifying_key().to_encoded_point(false).as_bytes()[1..], &RP[..]].concat(),
            Sk::K1(k) => k.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec(),
            Sk::Ml(k) => k.verifying_key().encode().as_slice().to_vec(),
        };
        b(env, &v)
    }
    pub(crate) fn ua(&self, env: &Env) -> BytesN<32> {
        digest::ua_of(env, self.kind(), &self.key_data(env))
    }
    /// The kind's signature over `ua_msg` (spec §3).
    pub(crate) fn sign(&self, env: &Env, m: &[u8; 32]) -> Bytes {
        let v = match self {
            Sk::Ed(k) => k.sign(m).to_bytes().to_vec(),
            Sk::P256(k) => {
                let s: p256::ecdsa::Signature = k.sign(m);
                s.normalize_s().unwrap_or(s).to_bytes().to_vec()
            }
            Sk::Wa(k) => webauthn_sig(env, k, m, 0),
            Sk::K1(k) => k1_sign(k, m),
            Sk::Ml(k) => {
                let pq = env.crypto().keccak256(&b(env, &[digest::TAG(env, 0x0131).to_array(), *m].concat())).to_array();
                k.expanded_key().sign_deterministic(&pq, &[]).unwrap().encode().as_slice().to_vec()
            }
        };
        b(env, &v)
    }
    fn pop(&self, env: &Env) -> Bytes {
        let ua = self.ua(env);
        self.sign(env, &msg(env, self.kind(), PURPOSE_POP_V2, &reg_digest(env, &ua, self.kind())))
    }
    pub(crate) fn register(&self, env: &Env, c: &UaRegistryClient) -> BytesN<32> {
        c.register(&self.kind(), &self.key_data(env), &no_attrs(env), &self.pop(env), &Bytes::new(env), &None)
    }
}

// ---------- msig ----------

pub(crate) struct Msig {
    pub(crate) s: MsigStructure,
    kd: Bytes,
    pub(crate) ua: BytesN<32>,
    ids: StdVec<[u8; 32]>,
}

/// CTR-UA-09 key data, members sorted by id.
pub(crate) fn msig(env: &Env, threshold: u16, members: &[(u16, [u8; 32], u16)]) -> Msig {
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
    let s = structure_of(env, &v).unwrap();
    Msig { s, ua: digest::ua_of(env, 0x0120, &kd), kd, ids: m.iter().map(|x| x.1).collect() }
}

impl Msig {
    pub(crate) fn index(&self, id: &[u8; 32]) -> u32 {
        self.ids.iter().position(|x| x == id).unwrap() as u32
    }
    /// `member_digest(ua, ua_message(msig, purpose, digest))`.
    pub(crate) fn md(&self, env: &Env, purpose: [u8; 32], d: &BytesN<32>) -> BytesN<32> {
        digest::member_digest(env, &self.ua, &digest::ua_message(env, 0x0120, &n(env, purpose), d))
    }
    /// A registered member's slot: empty `keyData`, the signature under purpose `member` over `md`.
    pub(crate) fn slot(&self, env: &Env, s: &Sk, purpose: [u8; 32], d: &BytesN<32>) -> (u32, StdVec<u8>, StdVec<u8>) {
        let m = msg(env, s.kind(), PURPOSE_MEMBER, &self.md(env, purpose, d));
        (self.index(&s.ua(env).to_array()), vec![], vecu8(&s.sign(env, &m)))
    }
    pub(crate) fn register(&self, env: &Env, c: &UaRegistryClient, pop: &SVec<MemberSig>) -> BytesN<32> {
        c.register_msig(&self.s, &no_attrs(env), pop, &Bytes::new(env), &None)
    }
    /// `typed(UAMembership{ua, member})` (CTR-UA-37).
    pub(crate) fn membership(&self, env: &Env, member: &[u8; 32]) -> BytesN<32> {
        membership_digest(env, &self.ua, &n(env, *member)).to_bytes()
    }
    /// A registered member's acceptance of its own slot.
    pub(crate) fn acceptance(&self, env: &Env, s: &Sk) -> MemberSig {
        let d = self.membership(env, &s.ua(env).to_array());
        let (index, _, sig) = self.slot(env, s, PURPOSE_MEMBERSHIP, &d);
        MemberSig { index, key_data: Bytes::new(env), sig: b(env, &sig) }
    }
    /// Each of `signers` accepts its slot.
    pub(crate) fn accepted_by(&self, env: &Env, c: &UaRegistryClient, signers: &[&Sk]) {
        for s in signers {
            c.accept_membership(&self.ua, &self.acceptance(env, s), &None);
        }
    }
}

/// Typed slots from `(index, keyData, sig)`.
pub(crate) fn member_sigs(env: &Env, slots: &[(u32, StdVec<u8>, StdVec<u8>)]) -> SVec<MemberSig> {
    let mut out = SVec::new(env);
    for (index, kd, sig) in slots {
        out.push_back(MemberSig { index: *index, key_data: b(env, kd), sig: b(env, sig) });
    }
    out
}

/// An `msig`'s `auth`.
pub(crate) fn msig_auth(env: &Env, slots: &[(u32, StdVec<u8>, StdVec<u8>)]) -> UaSig {
    UaSig::msig(env, member_sigs(env, slots))
}

// ---------- register ----------

#[test]
fn register_rows_from_portable_json() {
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

/// Only the kinds outside U8S-D8 stay `KindDisabled`: the natives (they register nothing), the scheme `pqz-mlwe` and ids of
/// no kind. A listed relayer changes nothing here, and the U8S-D8 kinds beside them do not stop at this rule
/// (`ua8_relayer_kind_without_relayer_not_verifiable`).
#[test]
fn register_disabled_kind_refused() {
    let env = new_env();
    let relayer = Address::generate(&env);
    let c = deploy(&env, &[relayer.clone()]);
    let (d, none) = (b(&env, &[1; 32]), Bytes::new(&env));
    for kind in [0x0001, 0x0011, 0x0012, 0x0109, 0x0114, 0x0134, 0x0140, 0x0142, 0x0143] {
        for r in [None, Some(relayer.clone())] {
            assert_eq!(err(c.try_register(&kind, &d, &no_attrs(&env), &none, &none, &r)), Error::KindDisabled, "{kind:#x}");
        }
    }
}

/// T3's `register_attrs_refused_4b` under the UA-8 rule: PQZ / KEM attributes register on a holder; on a non-holder, and a
/// proof with no key, each is its own error (`Attrs` stays unused, U8S-D5).
#[test]
fn register_attrs_accepted() {
    let (env, c) = setup();
    portable(&env, "mldsa65/n2304-kmax4096").on(&c);
    let (env, c) = setup();
    portable(&env, "mldsa65#1").on(&c);
    portable(&env, "mldsa65#2").on(&c);
    portable(&env, "msig-pq/n2304-kmax4096").on(&c);
    // A KEM key alone on a non-holder.
    let mut r = portable(&env, "p256");
    r.attrs.kem = portable(&env, "fndsa512").attrs.kem;
    assert_eq!(r.refused(&c), Error::KemHolder);
    // A pqz_pop without a key.
    let mut r = portable(&env, "p256");
    r.pqz_pop = b(&env, &[1]);
    assert_eq!(r.refused(&c), Error::PqzPopHash);
}

/// Without a relayer an `evm-contract` slot is `NotVerifiable` at the slot; with one, `ua8_relayer_evm_contract_slot`.
#[test]
fn register_unverifiable_part_refused() {
    let (env, c) = setup();
    let q = portable(&env, "mldsa65#1");
    q.on(&c);
    let mut contract_id = [0u8; 32];
    contract_id[12..].copy_from_slice(&[0x22; 20]);
    let m = msig(&env, 2, &[(0x0002, contract_id, 1), (0x0131, q.ua.to_array(), 1)]);
    let pop = member_sigs(&env, &[(m.index(&contract_id), vec![], vec![1; 65])]);
    assert_eq!(err(c.try_register_msig(&m.s, &no_attrs(&env), &pop, &Bytes::new(&env), &None)), Error::NotVerifiable);
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
        let kd = hx(&r["keyData"]);
        let reason = r["reason"].as_str().unwrap();
        if kind == 0x0120 {
            // `msig` has one typed form: bytes it cannot carry never reach it, and `register` refuses the kind.
            let e = c.try_register(&kind, &b(&env, &kd), &no_attrs(&env), &Bytes::new(&env), &Bytes::new(&env), &None);
            assert_eq!(err(e), Error::KeyData, "{reason}");
            if let Some(s) = structure_of(&env, &kd) {
                let e = c.try_register_msig(&s, &no_attrs(&env), &SVec::new(&env), &Bytes::new(&env), &None);
                assert_eq!(err(e), Error::KeyData, "typed: {reason}");
            }
            keydata += 1;
            continue;
        }
        let res = c.try_register(&kind, &b(&env, &kd), &no_attrs(&env), &b(&env, &[0; 64]), &Bytes::new(&env), &None);
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
    let pop = member_sigs(&env, &[m.slot(&env, &e, PURPOSE_POP_V2, &reg_digest(&env, &m.ua, 0x0120))]);
    assert_eq!(err(c.try_register_msig(&m.s, &no_attrs(&env), &pop, &Bytes::new(&env), &None)), Error::MemberUnknown);
    let m = msig(&env, 1, &[(0x0100, pua.to_array(), 1)]);
    assert_eq!(err(c.try_register_msig(&m.s, &no_attrs(&env), &pop, &Bytes::new(&env), &None)), Error::MemberUnknown);
}

/// A 2-of-3 `msig` of an in-test ed25519 key, an in-test P-256 key and `mldsa65#1`: classical-dominant, an empty `pop`.
fn msig_2of3(env: &Env, c: &UaRegistryClient) -> (Msig, Sk, Sk) {
    let (e, p) = (ed(4), Sk::P256(p256k(5)));
    e.register(env, c);
    p.register(env, c);
    let q = portable(env, "mldsa65#1");
    q.on(c);
    let m = msig(env, 2, &[(0x0102, e.ua(env).to_array(), 1), (0x0101, p.ua(env).to_array(), 1), (0x0131, q.ua.to_array(), 1)]);
    let ua = m.register(env, c, &SVec::new(env));
    assert_eq!(ua, m.ua);
    let rec = c.record_of(&ua).unwrap();
    assert!(rec.signable && rec.pop_checked == Checked::Chain);
    assert!(c.receivable(&ua));
    m.accepted_by(env, c, &[&e, &p]);
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
        c.require_authorized(&m.ua, &n(&env, purpose), &d, &msig_auth(&env, &two_slots(&env, &m, &e, &p, purpose, &d)));
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
        assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &msig_auth(&env, &[s.clone()]))), Error::Unauthorized);
    }
    // Swapped indexes: each signature checked against the other member's key.
    let swapped = vec![(good[0].0, vec![], good[1].2.clone()), (good[1].0, vec![], good[0].2.clone())];
    assert!(c.try_require_authorized(&m.ua, &pm, &d, &msig_auth(&env, &swapped)).is_err());
    // An index past the members.
    let mut past = good.clone();
    past[1].0 = 3;
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &msig_auth(&env, &past))), Error::Unauthorized);
    // Slots out of order, or the same member twice.
    let reversed = vec![good[1].clone(), good[0].clone()];
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &msig_auth(&env, &reversed))), Error::Unauthorized);
    let twice = vec![good[0].clone(), good[0].clone()];
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &msig_auth(&env, &twice))), Error::Unauthorized);
    // `UaSig`: an `msig` is `members` only.
    let mut a = msig_auth(&env, &good);
    a.signature = b(&env, &[1]);
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &a)), Error::Unauthorized);
    let mut a = msig_auth(&env, &good);
    a.key_data = m.kd.clone();
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &a)), Error::Unauthorized);
    // A registered member's slot with its key data: refused (the caller's error, as EVM), even though the key is right.
    let mut kd = good.clone();
    let signer = if kd[0].0 == m.index(&e.ua(&env).to_array()) { &e } else { &p };
    kd[0].1 = vecu8(&signer.key_data(&env));
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &msig_auth(&env, &kd))), Error::Unauthorized);
    // Another purpose, another digest.
    assert!(c.try_require_authorized(&m.ua, &n(&env, PURPOSE_TRADE), &d, &msig_auth(&env, &good)).is_err());
    assert!(c.try_require_authorized(&m.ua, &pm, &n(&env, [0x33; 32]), &msig_auth(&env, &good)).is_err());
    c.require_authorized(&m.ua, &pm, &d, &msig_auth(&env, &good));
}

// ---------- native members ----------

pub(crate) fn ledger_account(pk: [u8; 32]) -> (std::boxed::Box<xdr::LedgerKey>, (std::boxed::Box<xdr::LedgerEntry>, Option<u32>)) {
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
pub(crate) fn signed_entry(env: &Env, sk: &ed25519_dalek::SigningKey, nonce: i64, contract: &Address, f: &str, args: SVec<Val>) -> SorobanAuthorizationEntry {
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
    let q = ml(10);
    q.register(&env, &c);
    // register, PQ-eligible (a PQ majority): the G member authorises (ua, pop v2, registrationDigest) beside the PQ member.
    let m = msig(&env, 2, &[(0x0011, gpk, 1), (0x0131, q.ua(&env).to_array(), 1)]);
    let rd = reg_digest(&env, &m.ua, 0x0120);
    let mut slots = vec![(m.index(&gpk), vec![], vec![]), m.slot(&env, &q, PURPOSE_POP_V2, &rd)];
    slots.sort_by_key(|s| s.0);
    let pop = member_sigs(&env, &slots);
    assert!(c.try_register_msig(&m.s, &no_attrs(&env), &pop, &Bytes::new(&env), &None).is_err());
    let args: SVec<Val> = (m.ua.clone(), n(&env, PURPOSE_POP_V2), rd).into_val(&env);
    env.set_auths(&[signed_entry(&env, &gsk, 1, &c.address, "register_msig", args)]);
    m.register(&env, &c, &pop);
    assert!(c.record_of(&m.ua).unwrap().signable);
    // A sole G member is classical-dominant: an empty `pop`, its host auth is the signing check.
    env.set_auths(&[]);
    let m = msig(&env, 1, &[(0x0011, gpk, 1)]);
    let empty_slot = msig_auth(&env, &[(0, vec![], vec![])]);
    m.register(&env, &c, &SVec::new(&env));
    assert!(c.record_of(&m.ua).unwrap().signable);
    // CTR-UA-37: the member accepts first, by the same host auth
    let accept: SVec<Val> = (m.ua.clone(), n(&env, PURPOSE_MEMBERSHIP), m.membership(&env, &gpk)).into_val(&env);
    env.set_auths(&[signed_entry(&env, &gsk, 4, &c.address, "accept_membership", accept)]);
    c.accept_membership(&m.ua, &MemberSig { index: 0, key_data: Bytes::new(&env), sig: Bytes::new(&env) }, &None);
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
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &msig_auth(&env, &[(0, vec![], vec![1])]))), Error::Unauthorized);
}

/// An EOA key's 20-byte address as a native-space id.
pub(crate) fn eoa(env: &Env, sk: &k256::ecdsa::SigningKey) -> [u8; 32] {
    let pt = sk.verifying_key().to_encoded_point(false);
    let h = env.crypto().keccak256(&b(env, &pt.as_bytes()[1..])).to_array();
    let mut id = [0u8; 32];
    id[12..].copy_from_slice(&h[12..]);
    id
}
/// EIP-191 `personal_sign` of a 32-byte message (the pre-typed-signing member form, now refused).
fn personal_sign(env: &Env, sk: &k256::ecdsa::SigningKey, md: &BytesN<32>) -> StdVec<u8> {
    let mut m = b"\x19Ethereum Signed Message:\n32".to_vec();
    m.extend_from_slice(&md.to_array());
    k1_sign(sk, &env.crypto().keccak256(&b(env, &m)).to_array())
}

/// S10 / TS-D4: an `evm-eoa` member signs the record's typed digest itself (`eth_signTypedData_v4`, ECDSA, no
/// `personal_sign`), for the portable `pop` only, and never counts for signing.
#[test]
fn msig_evm_eoa_member_typed_digest() {
    let (env, c) = setup();
    // EVM's msig-pq-native registers by its typed pop (members evm-eoa + mldsa65#1, 2-of-2).
    portable(&env, "mldsa65#1").on(&c);
    let r = portable(&env, "msig-pq-native");
    let ua = r.on(&c);
    assert!(!c.record_of(&ua).unwrap().signable, "the EOA's weight does not count for signing");
    // In-test: 1-of-2 (evm-eoa, ed25519), classical-dominant, an empty `pop`; signing needs the ed25519 member.
    let (k, e) = (k1(6), ed(7));
    e.register(&env, &c);
    let id = eoa(&env, &k);
    let m = msig(&env, 1, &[(0x0001, id, 1), (0x0102, e.ua(&env).to_array(), 1)]);
    m.register(&env, &c, &SVec::new(&env));
    assert!(c.receivable(&m.ua));
    let accepted = MemberSig { index: m.index(&id), key_data: Bytes::new(&env), sig: b(&env, &k1_sign(&k, &m.membership(&env, &id).to_array())) };
    c.accept_membership(&m.ua, &accepted, &None);
    m.accepted_by(&env, &c, &[&e]);
    let (pm, d) = (n(&env, PURPOSE_METATX), n(&env, [0x61; 32]));
    let eoa_slot = msig_auth(&env, &[(m.index(&id), vec![], k1_sign(&k, &m.md(&env, PURPOSE_METATX, &d).to_array()))]);
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &eoa_slot)), Error::NotVerifiable);
    c.require_authorized(&m.ua, &pm, &d, &msig_auth(&env, &[m.slot(&env, &e, PURPOSE_METATX, &d)]));
}

/// TS-D4: the EIP-191 `personal_sign` member forms (over `member_digest`, as before typed-signing, or over the typed
/// digest) and an ECDSA signature over `member_digest` are each `Pop`.
#[test]
fn msig_evm_eoa_personal_sign_refused() {
    let (env, c) = setup();
    let k = k1(8);
    let q = ml(9);
    q.register(&env, &c);
    let id = eoa(&env, &k);
    let m = msig(&env, 2, &[(0x0001, id, 1), (0x0131, q.ua(&env).to_array(), 1)]); // PQ-eligible: a member-signed `pop`
    let rd = reg_digest(&env, &m.ua, 0x0120);
    let md = m.md(&env, PURPOSE_POP_V2, &rd);
    // The PQ slot always verifies, so each form decides by its own validity: an accepted one would reach the threshold.
    let pop = |sig: StdVec<u8>| {
        let mut slots = [(m.index(&id), vec![], sig), m.slot(&env, &q, PURPOSE_POP_V2, &rd)];
        slots.sort_by_key(|s| s.0);
        member_sigs(&env, &slots)
    };
    for sig in [personal_sign(&env, &k, &md), personal_sign(&env, &k, &rd), k1_sign(&k, &md.to_array())] {
        assert_eq!(err(c.try_register_msig(&m.s, &no_attrs(&env), &pop(sig), &Bytes::new(&env), &None)), Error::Pop);
    }
    assert_eq!(c.record_of(&m.ua), None);
    assert_eq!(m.register(&env, &c, &pop(k1_sign(&k, &rd.to_array()))), m.ua, "the typed form registers");
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
    let e = err(c.try_require_authorized(&ua, &n(&env, PURPOSE_METATX), &n(&env, [1; 32]), &UaSig::msig(&env, members_of(&env, &r.pop))));
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
        assert_eq!(row["pop"]["registrationDigest"].as_str().unwrap(), format!("0x{}", hex(&reg_digest(&env, &ua, kind).to_array())));
        assert_eq!(c.register(&kind, &kd, &no_attrs(&env), &b(&env, &hx(&row["pop"]["sig"])), &Bytes::new(&env), &None), ua);
        for s in row["sigs"].as_array().unwrap() {
            let (p, d, sig) = (n32(&env, &s["purposeTag"]), n32(&env, &s["digest"]), UaSig::single(&env, b(&env, &hx(&s["sig"]))));
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
            let sig = UaSig::single(&env, s.sign(&env, &msg(&env, s.kind(), p, &d)));
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
        let sig = UaSig::single(&env, s.sign(&env, &msg(&env, s.kind(), p, &d)));
        assert_eq!(err(c.try_require_authorized(&ua, &n(&env, p), &d, &sig)), Error::Unauthorized);
    }
    // The registration pop itself, replayed through require_authorized.
    let rd = reg_digest(&env, &ua, s.kind());
    assert_eq!(err(c.try_require_authorized(&ua, &n(&env, PURPOSE_POP_V2), &rd, &UaSig::single(&env, s.pop(&env)))), Error::Unauthorized);
}

#[test]
fn require_authorized_not_registered() {
    let (env, c) = setup();
    let e = err(c.try_require_authorized(&n(&env, [0x91; 32]), &n(&env, PURPOSE_METATX), &n(&env, [0; 32]), &UaSig::none(&env)));
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
    c.require_authorized(&ua, &n(&env, PURPOSE_METATX), &d, &UaSig::single(&env, s.sign(&env, &msg(&env, 0x0101, PURPOSE_METATX, &d))));
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
        let pop = webauthn_sig(&env, k, &msg(&env, 0x0100, PURPOSE_POP_V2, &reg_digest(&env, &ua, 0x0100)), ext);
        c.register(&0x0100, &s.key_data(&env), &no_attrs(&env), &b(&env, &pop), &Bytes::new(&env), &None);
        let m = msig(&env, 1, &[(0x0100, ua.to_array(), 1)]);
        m.register(&env, &c, &SVec::new(&env));
        m.accepted_by(&env, &c, &[&s]);
        let d = n(&env, [0xb1; 32]);
        let auth = msig_auth(&env, &[m.slot(&env, &s, PURPOSE_METATX, &d)]);
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

/// T3 review m2: `stellar_account` rebuilds the `Address` of a `G…` (0x0011) id from its 32 bytes.
#[test]
fn stellar_account_round_trip() {
    use soroban_sdk::xdr::ToXdr as _;
    let env = new_env();
    let g = Address::from_str(&env, "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6");
    let x = g.clone().to_xdr(&env);
    let id: [u8; 32] = vecu8(&x.slice(x.len() - 32..)).try_into().unwrap();
    assert_eq!(crate::stellar_account(&env, &id), g);
}

/// S10, owner ruling 2026-10-31 (final review A-I1): a `soroban-contract` (`C…`) member is `MemberUnknown`, also
/// when the other member alone reaches the threshold (a contract calling the registry would meet its slot by invoker
/// auth); the `msig` without it registers, classical-dominant, with an empty `pop`.
#[test]
fn msig_soroban_contract_member_refused() {
    use soroban_sdk::xdr::ToXdr as _;
    let (env, c) = setup();
    let e = ed(9);
    e.register(&env, &c);
    let x = c.address.clone().to_xdr(&env);
    let cid: [u8; 32] = vecu8(&x.slice(x.len() - 32..)).try_into().unwrap();
    let m = msig(&env, 1, &[(0x0102, e.ua(&env).to_array(), 1), (0x0012, cid, 1)]);
    assert_eq!(err(c.try_register_msig(&m.s, &no_attrs(&env), &SVec::new(&env), &Bytes::new(&env), &None)), Error::MemberUnknown);
    let m = msig(&env, 1, &[(0x0102, e.ua(&env).to_array(), 1)]);
    m.register(&env, &c, &SVec::new(&env));
}

// ---------- U8S-D1 (owner 2026-10-31): a stored msig signature is minimal; U8S-D2: a classical-dominant msig has no `pop` ----------

/// portable.json `msig-pop-not-minimal`: both slots verify and the old rule passes (1, then 3 >= 2), but the weight-2
/// slot alone reaches the threshold: `Pop`. The weight-1 slot alone is below it; the weight-2 slot alone registers.
#[test]
fn msig_pop_not_minimal_refused() {
    let (env, c) = setup();
    portable(&env, "mldsa65#1").on(&c);
    portable(&env, "mldsa65#2").on(&c);
    let neg = derived(PORTABLE, "negatives", "msig-pop-not-minimal");
    assert_eq!(neg["error"], "UAPoP");
    let s = structure_of(&env, &hx(&neg["registration"]["keyData"])).unwrap();
    let slots = members_of(&env, &b(&env, &hx(&neg["registration"]["pop"])));
    let refused = |pop: &SVec<MemberSig>| err(c.try_register_msig(&s, &no_attrs(&env), pop, &Bytes::new(&env), &None));
    assert_eq!(refused(&slots), Error::Pop);
    assert_eq!(refused(&SVec::new(&env)), Error::Pop, "PQ-eligible: an empty `pop` is refused (U8S-D2's other branch)");
    let alone = |i: u32| member_sigs(&env, &[(i, vec![], vecu8(&slots.get(i).unwrap().sig))]);
    assert_eq!(refused(&alone(0)), Error::Pop);
    let ua = c.register_msig(&s, &no_attrs(&env), &alone(1), &Bytes::new(&env), &None);
    assert_eq!(ua, n32(&env, &neg["registration"]["ua"]));
}

/// Every slot counts its member's weight, a native one too: 2-of-(`G…` 1, `mldsa65` 2) with the `G…` member's host auth
/// present is `Pop`, as its slot is not needed; the PQ slot alone registers.
#[test]
fn msig_g_member_redundant_slot_refused() {
    let gsk = ed25519_dalek::SigningKey::from_bytes(&[12; 32]);
    let gpk = gsk.verifying_key().to_bytes();
    let mut snap: soroban_ledger_snapshot::LedgerSnapshot = Env::default().to_ledger_snapshot();
    snap.ledger_entries.push(ledger_account(gpk));
    let env = Env::from_ledger_snapshot(snap);
    env.cost_estimate().budget().reset_unlimited();
    env.ledger().with_mut(|l| l.network_id = NETWORK);
    let c = deploy(&env, &[]);
    let q = ml(13);
    q.register(&env, &c);
    let m = msig(&env, 2, &[(0x0011, gpk, 1), (0x0131, q.ua(&env).to_array(), 2)]);
    let rd = reg_digest(&env, &m.ua, 0x0120);
    let pq = m.slot(&env, &q, PURPOSE_POP_V2, &rd);
    assert_eq!(m.index(&gpk), 0, "the G slot first: the threshold is not met before the PQ slot");
    let slots = vec![(0, vec![], vec![]), pq.clone()];
    let args: SVec<Val> = (m.ua.clone(), n(&env, PURPOSE_POP_V2), rd).into_val(&env);
    env.set_auths(&[signed_entry(&env, &gsk, 1, &c.address, "register_msig", args)]);
    assert_eq!(err(c.try_register_msig(&m.s, &no_attrs(&env), &member_sigs(&env, &slots), &Bytes::new(&env), &None)), Error::Pop);
    env.set_auths(&[]);
    m.register(&env, &c, &member_sigs(&env, &[pq]));
}

/// U8S-D1 scope: a transaction authorisation is not stored and keeps the old rule: 2-of-(1, 2) signed by both slots
/// passes `require_authorized`, lower index first; a slot after the threshold still fails.
#[test]
fn msig_require_authorized_keeps_rule() {
    let (env, c) = setup();
    let (e, p) = (ed(14), Sk::P256(p256k(15)));
    e.register(&env, &c);
    p.register(&env, &c);
    let mut ids = [(0x0102u16, e.ua(&env).to_array()), (0x0101u16, p.ua(&env).to_array())];
    ids.sort_by_key(|x| x.1);
    let (d, pm) = (n(&env, [0x71; 32]), n(&env, PURPOSE_METATX));
    let m = msig(&env, 2, &[(ids[0].0, ids[0].1, 1), (ids[1].0, ids[1].1, 2)]);
    m.register(&env, &c, &SVec::new(&env));
    m.accepted_by(&env, &c, &[&e, &p]);
    c.require_authorized(&m.ua, &pm, &d, &msig_auth(&env, &two_slots(&env, &m, &e, &p, PURPOSE_METATX, &d)));
    let m = msig(&env, 2, &[(ids[0].0, ids[0].1, 2), (ids[1].0, ids[1].1, 1)]);
    m.register(&env, &c, &SVec::new(&env));
    m.accepted_by(&env, &c, &[&e, &p]);
    let auth = msig_auth(&env, &two_slots(&env, &m, &e, &p, PURPOSE_METATX, &d));
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &auth)), Error::Unauthorized);
}

/// U8S-D2, as EVM (CTR-UA-07): `ed25519` (2) + `mldsa65#1` (1), threshold 2: the classical weight reaches the threshold,
/// so an empty `pop` registers (`Chain`, signable by member weight) and a member-signed `pop` is `Pop`.
#[test]
fn msig_classical_dominant_empty_pop() {
    let (env, c) = setup();
    let e = ed(16);
    e.register(&env, &c);
    let q = portable(&env, "mldsa65#1");
    q.on(&c);
    let m = msig(&env, 2, &[(0x0102, e.ua(&env).to_array(), 2), (0x0131, q.ua.to_array(), 1)]);
    let pop = member_sigs(&env, &[m.slot(&env, &e, PURPOSE_POP_V2, &reg_digest(&env, &m.ua, 0x0120))]);
    assert_eq!(err(c.try_register_msig(&m.s, &no_attrs(&env), &pop, &Bytes::new(&env), &None)), Error::Pop);
    m.register(&env, &c, &SVec::new(&env));
    let rec = c.record_of(&m.ua).unwrap();
    assert!(rec.signable && rec.pop_checked == Checked::Chain && rec.pop.is_empty());
    // the rule is EVM's: a portable.json msig row has a `pop` exactly when it is PQ-eligible
    for row in json(PORTABLE)["registrations"].as_array().unwrap().iter().filter(|r| r["kind"] == 0x0120) {
        let (kd, pop) = (b(&env, &hx(&row["keyData"])), hx(&row["pop"]));
        assert_eq!(crate::pq_eligible(&kd), !pop.is_empty(), "{}", row["name"]);
    }
}

/// U8S-D2: the copied record is the EVM `register` argument form: `registration_of` returns the empty `pop`, so the bytes
/// of a classical-dominant `msig` are one record on both families (`msig-classical` on EVM has `pop` empty too).
#[test]
fn msig_classical_dominant_matches_evm_bytes() {
    let (env, c) = setup();
    assert!(portable(&env, "msig-classical").pop.is_empty());
    let e = ed(17);
    e.register(&env, &c);
    let m = msig(&env, 1, &[(0x0102, e.ua(&env).to_array(), 1)]);
    let ua = m.register(&env, &c, &SVec::new(&env));
    assert_eq!(c.registration_of(&ua), Some((0x0120, m.kd.clone(), no_attrs(&env), Bytes::new(&env), Bytes::new(&env))));
}
