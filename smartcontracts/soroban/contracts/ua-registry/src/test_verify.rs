//! T2: the digests and the per-kind verifiers against the shared UA vectors (`smartcontracts/vectors/ua/`, the
//! authority). A `Hash<32>` exists only from a host hash, so each test derives the message with `ua_message` from the
//! vector's purpose and digest (and checks it against the vector's message) instead of reading the message bytes.
extern crate std;
use std::{string::String, vec::Vec as StdVec};

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::Value;
use soroban_sdk::{
    contract, contractimpl, testutils::Ledger, Address, Bytes, BytesN, Env, IntoVal, Val,
    Vec as SVec,
};

use crate::{abi, digest, verify, webauthn};
use scaas_ua_common::*;

const KINDS: &str = include_str!("../../../../vectors/ua/kinds.json");
const SIGNATURES: &str = include_str!("../../../../vectors/ua/signatures.json");
const PQ_SIGNATURES: &str = include_str!("../../../../vectors/ua/pq_signatures.json");
const PORTABLE: &str = include_str!("../../../../vectors/ua/portable.json");
const PAYMETA: &str = include_str!("../../../../vectors/metatx/paymeta.json");

/// The S3 kinds (spec §3).
const S3: [u32; 7] = [0x0100, 0x0101, 0x0102, 0x0108, 0x0120, 0x0130, 0x0131];

/// Calls the crate-private functions inside a contract frame, so a failure (contract or host error) is an `Err`.
#[contract]
struct Harness;

#[contractimpl]
impl Harness {
    pub fn check(env: Env, kind: u32, key_data: Bytes, purpose: BytesN<32>, digest: BytesN<32>, sig: Bytes) {
        let m = digest::ua_message(&env, kind, &purpose, &digest);
        verify::check(&env, kind, &key_data, &m, &sig);
    }

    pub fn ed25519(env: Env, pk: BytesN<32>, msg: Bytes, sig: Bytes) {
        verify::ed25519(&env, &pk, &msg, &sig);
    }

    pub fn ed25519_key_ok(_env: Env, pk: BytesN<32>) -> bool {
        verify::ed25519_key_ok(&pk.to_array())
    }

    pub fn eoa(env: Env, id20: BytesN<20>, member_digest: BytesN<32>, sig: Bytes) {
        verify::check_evm_eoa_personal_sign(&env, &id20, &member_digest, &sig);
    }

    /// `(index, keyData length, sig length)` of each decoded member.
    pub fn decode(env: Env, b: Bytes) -> SVec<(u32, u32, u32)> {
        let mut out = SVec::new(&env);
        for m in abi::decode_member_sigs(&env, &b).iter() {
            out.push_back((m.index, m.key_data.len(), m.sig.len()));
        }
        out
    }
}

fn setup() -> (Env, HarnessClient<'static>) {
    let env = Env::default();
    let id = env.register(Harness, ());
    let c = HarnessClient::new(&env, &id);
    (env, c)
}

pub(super) fn json(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}

pub(super) fn hx(v: &Value) -> StdVec<u8> {
    let s = v.as_str().unwrap().trim_start_matches("0x");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

pub(super) fn b(env: &Env, v: &[u8]) -> Bytes {
    Bytes::from_slice(env, v)
}

pub(super) fn n32(env: &Env, v: &Value) -> BytesN<32> {
    BytesN::from_array(env, &hx(v).try_into().unwrap())
}

pub(super) fn kind_of(v: &Value) -> u32 {
    v.as_u64().map(|k| k as u32).unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}

pub(super) fn derived(file: &str, list: &str, name: &str) -> Value {
    json(file)[list].as_array().unwrap().iter().find(|r| r["name"] == name).unwrap().clone()
}

/// Every (purpose, digest) a row signs: its `sigs[]` and its `pop` / `popOther` / `popPqz` (purpose `pop` v2).
fn signed_pairs(env: &Env, row: &Value) -> StdVec<(BytesN<32>, BytesN<32>, Value, Value)> {
    let mut out = StdVec::new();
    for s in row["sigs"].as_array().unwrap() {
        out.push((n32(env, &s["purposeTag"]), n32(env, &s["digest"]), s["message"].clone(), s["sig"].clone()));
    }
    for p in ["pop", "popOther", "popPqz"] {
        if row[p].is_object() {
            let x = &row[p];
            let pv2 = BytesN::from_array(env, &PURPOSE_POP_V2);
            out.push((pv2, n32(env, &x["registrationDigest"]), x["message"].clone(), x["sig"].clone()));
        }
    }
    out
}

/// Every signature of the row verifies (its message re-derived by `ua_message`); every negative is refused.
fn kind_vectors(row: &Value, negatives: bool) {
    let (env, c) = setup();
    let kind = kind_of(&row["kind"]);
    let kd = b(&env, &hx(&row["keyData"]));
    let pairs = signed_pairs(&env, row);
    if !negatives {
        for (p, d, m, sig) in &pairs {
            assert_eq!(digest::ua_message(&env, kind, p, d).to_array().to_vec(), hx(m), "message of {}", row["name"]);
            c.check(&kind, &kd, p, d, &b(&env, &hx(sig)));
        }
        return;
    }
    let negs = row["negatives"].as_array().unwrap();
    assert!(!negs.is_empty());
    for n in negs {
        let (p, d, _, _) = pairs
            .iter()
            .find(|(p, d, _, _)| digest::ua_message(&env, kind, p, d).to_array().to_vec() == hx(&n["message"]))
            .unwrap_or_else(|| panic!("negative {} of {}: message not a signed pair", n["name"], row["name"]));
        assert!(c.try_check(&kind, &kd, p, d, &b(&env, &hx(&n["sig"]))).is_err(), "negative {} of {}", n["name"], row["name"]);
    }
}

fn classical(name: &str) -> Value {
    derived(SIGNATURES, "derived", name)
}

fn pq(name: &str) -> Value {
    derived(PQ_SIGNATURES, "kinds", name)
}

#[test]
fn tags_match_kinds_json() {
    let env = Env::default();
    let k = json(KINDS);
    let mut seen = 0;
    for row in k["kinds"].as_array().unwrap() {
        let kind = kind_of(&row["kind"]);
        if S3.contains(&kind) {
            assert_eq!(digest::TAG(&env, kind).to_array().to_vec(), hx(&row["TAG"]), "TAG of {}", row["name"]);
            seen += 1;
        }
    }
    assert_eq!(seen, S3.len());
    assert_eq!(digest::MSG_TAG.to_vec(), hx(&k["constants"]["MSG_TAG"]));
}

#[test]
fn purpose_tags_match_kinds_json() {
    let k = json(KINDS);
    let tag = |name: &str| {
        let r = k["purposes"].as_array().unwrap().iter().find(|p| p["tag"] == name).unwrap();
        hx(&r["purposeTag"])
    };
    assert_eq!(PURPOSE_METATX.to_vec(), tag("scaas.ua.purpose.metatx.v1"));
    assert_eq!(PURPOSE_METATX_CANCEL.to_vec(), tag("scaas.ua.purpose.metatx-cancel.v1"));
    assert_eq!(PURPOSE_TRADE.to_vec(), tag("scaas.ua.purpose.trade.v1"));
    assert_eq!(PURPOSE_MEMBER.to_vec(), tag("scaas.ua.purpose.member.v1"));
    assert_eq!(PURPOSE_POP_V2.to_vec(), tag("scaas.ua.purpose.pop.v2"));
    assert_eq!(PURPOSE_KEM.to_vec(), tag("scaas.ua.purpose.kem.v1"));
    assert_eq!(PURPOSE_PQZ_KEY.to_vec(), tag("scaas.ua.purpose.pqz-key.v1"));
}

#[test]
fn ua_message_matches_kinds_json() {
    let env = Env::default();
    let mut seen = 0;
    for m in json(KINDS)["messages"].as_array().unwrap() {
        let kind = kind_of(&m["kind"]);
        if !S3.contains(&kind) {
            continue;
        }
        let got = digest::ua_message(&env, kind, &n32(&env, &m["purposeTag"]), &n32(&env, &m["digest"]));
        assert_eq!(got.to_array().to_vec(), hx(&m["uaMsg"]), "{kind} {}", m["purpose"]);
        seen += 1;
    }
    assert!(seen >= S3.len());
}

/// Every `registrations[]` row: `portablePopDigest` and `registrationDigest` (kind-independent), and `popMessage` for
/// the rows of an S3 kind (`ua_message` knows the TAGs of the S3 kinds only: every other kind is `KindDisabled`). The
/// row's id is `ua_of` for the S3 kinds; an `msig` row's `memberDigest` is `member_digest(ua, popMessage)`.
#[test]
fn portable_digests_match_portable_json() {
    let env = Env::default();
    let (mut all, mut s3) = (0, 0);
    for r in json(PORTABLE)["registrations"].as_array().unwrap() {
        let ua = n32(&env, &r["ua"]);
        let portable = digest::portable_pop_digest(&env, &ua, &n32(&env, &r["pqzKeyHash"]), &n32(&env, &r["kemRecordHash"]));
        assert_eq!(portable.to_array().to_vec(), hx(&r["portablePopDigest"]), "portablePopDigest of {}", r["name"]);
        let pqz_pop = hx(&r["pqzPop"]);
        let pqz_pop_hash = if pqz_pop.is_empty() { [0u8; 32] } else { env.crypto().keccak256(&b(&env, &pqz_pop)).to_array() };
        assert_eq!(pqz_pop_hash.to_vec(), hx(&r["attrs"]["pqzPopHash"]), "pqzPopHash of {}", r["name"]);
        let reg = digest::registration_digest(&env, &portable, &BytesN::from_array(&env, &pqz_pop_hash));
        assert_eq!(reg.to_array().to_vec(), hx(&r["registrationDigest"]), "registrationDigest of {}", r["name"]);
        all += 1;
        let kind = kind_of(&r["kind"]);
        if S3.contains(&kind) {
            assert_eq!(digest::ua_of(&env, kind, &b(&env, &hx(&r["keyData"]))), ua, "ua of {}", r["name"]);
            let pv2 = BytesN::from_array(&env, &PURPOSE_POP_V2);
            let m = digest::ua_message(&env, kind, &pv2, &reg);
            assert_eq!(m.to_array().to_vec(), hx(&r["popMessage"]), "popMessage of {}", r["name"]);
            if r["memberDigest"].is_string() {
                assert_eq!(digest::member_digest(&env, &ua, &m).to_array().to_vec(), hx(&r["memberDigest"]), "{}", r["name"]);
            }
            s3 += 1;
        }
    }
    assert_eq!(all, 25);
    assert!(s3 >= 7 + 6, "single-key S3 rows and the msig rows");
}

/// The token's `cross_implementation_vector` (`token/src/test.rs`): pay(FROM, TO, 12345, 0x11×32, 1_800_000_300) on
/// CONTRACT under the standalone network id.
#[test]
fn op_digest_matches_token_cross_vector() {
    let env = Env::default();
    let net = env.crypto().sha256(&b(&env, b"Standalone Network ; February 2017")).to_array();
    env.ledger().with_mut(|l| l.network_id = net);
    let contract = Address::from_str(&env, "CARCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEVQO");
    let from = Address::from_str(&env, "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6");
    let to = Address::from_str(&env, "GAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTHCM6");
    let args: SVec<Val> = (from, to, 12_345i128, BytesN::from_array(&env, &[0x11; 32]), 1_800_000_300u64).into_val(&env);
    let d = op_digest(&env, &contract, "pay", args);
    let want = "0bb4e9123b86f99303e03cfd8aacb1eecd3b8ccb10d572907e1228a715369b00";
    assert_eq!(d.to_array().iter().map(|x| std::format!("{x:02x}")).collect::<String>(), want);
}

/// `meta_pay_id` and `pay_lane` against `vectors/metatx/paymeta.json` (`payId`, `payLane = payLane(payId)`).
#[test]
fn pay_ids_match_paymeta_json() {
    let env = Env::default();
    for r in json(PAYMETA).as_array().unwrap() {
        let id = meta_pay_id(&env, &n32(&env, &r["salt"]), &b(&env, &hx(&r["meta"])));
        assert_eq!(id.to_array().to_vec(), hx(&r["payId"]), "{}", r["name"]);
        assert_eq!(pay_lane(&env, &id).to_array().to_vec(), hx(&r["payLane"]), "{}", r["name"]);
    }
}

#[test]
fn kind_webauthn_p256_vectors_verify() {
    kind_vectors(&classical("webauthn-p256"), false);
}
#[test]
fn kind_webauthn_p256_negatives_fail() {
    kind_vectors(&classical("webauthn-p256"), true);
}
#[test]
fn kind_p256_vectors_verify() {
    kind_vectors(&classical("p256"), false);
}
#[test]
fn kind_p256_negatives_fail() {
    kind_vectors(&classical("p256"), true);
}
#[test]
fn kind_ed25519_vectors_verify() {
    kind_vectors(&classical("ed25519"), false);
}
#[test]
fn kind_ed25519_negatives_fail() {
    kind_vectors(&classical("ed25519"), true);
}
#[test]
fn kind_secp256k1_vectors_verify() {
    kind_vectors(&classical("secp256k1"), false);
}
#[test]
fn kind_secp256k1_negatives_fail() {
    kind_vectors(&classical("secp256k1"), true);
}
#[test]
fn kind_mldsa44_vectors_verify() {
    kind_vectors(&pq("mldsa44"), false);
}
#[test]
fn kind_mldsa44_negatives_fail() {
    kind_vectors(&pq("mldsa44"), true);
}
#[test]
fn kind_mldsa65_vectors_verify() {
    kind_vectors(&pq("mldsa65"), false);
}
#[test]
fn kind_mldsa65_negatives_fail() {
    kind_vectors(&pq("mldsa65"), true);
}

/// RFC 8032 §7.1 and the strictness rows, `valid` as given (host `verify_strict` plus the contract's key check).
#[test]
fn kind_ed25519_rfc8032_vectors() {
    let (env, c) = setup();
    let rows = json(SIGNATURES)["ed25519Rfc8032"].as_array().unwrap().clone();
    assert!(rows.len() >= 11);
    for r in rows {
        let pk = n32(&env, &r["publicKey"]);
        let ok = c.try_ed25519(&pk, &b(&env, &hx(&r["message"])), &b(&env, &hx(&r["sig"]))).is_ok();
        assert_eq!(ok, r["valid"].as_bool().unwrap(), "{}: {}", r["name"], r["comment"]);
    }
}

/// The contract's ed25519 key check over `kinds.json`: every valid row passes, every 32-byte invalid row is refused
/// except "not a point", which only the host's decompression refuses (at every verify, so its `pop` never verifies).
#[test]
fn ed25519_key_check_matches_kinds_json() {
    let (env, c) = setup();
    let k = json(KINDS);
    for r in k["valid"].as_array().unwrap().iter().filter(|r| kind_of(&r["kind"]) == 0x0102) {
        assert!(c.ed25519_key_ok(&n32(&env, &r["keyData"])));
    }
    let mut refused = 0;
    for r in k["invalid"].as_array().unwrap().iter().filter(|r| kind_of(&r["kind"]) == 0x0102) {
        let kd = hx(&r["keyData"]);
        if kd.len() != 32 {
            continue;
        }
        let ok = c.ed25519_key_ok(&BytesN::from_array(&env, &kd.try_into().unwrap()));
        assert_eq!(ok, r["reason"] == "not a point", "{}", r["reason"]);
        refused += !ok as u32;
    }
    assert_eq!(refused, 12);
}

/// `abi.encode(MemberSig[])`: the `msig-pq-native` pop (registered members, empty `keyData`) decodes; a trailing byte,
/// a non-minimal offset and an unsorted (or repeated) index are refused.
#[test]
fn member_sigs_abi_canonical_only() {
    let (env, c) = setup();
    let r = derived(PORTABLE, "registrations", "msig-pq-native");
    let pop = hx(&r["pop"]);
    let got = c.decode(&b(&env, &pop));
    assert_eq!(got.len(), 2);
    assert_eq!(got.get(0).unwrap(), (0, 0, 65));
    assert_eq!(got.get(1).unwrap(), (1, 0, 3309));

    let mut trailing = pop.clone();
    trailing.push(0);
    assert!(c.try_decode(&b(&env, &trailing)).is_err(), "trailing byte");

    let mut padded = std::vec![0u8; 32];
    padded[31] = 64; // outer offset 64 with a zero word in between: decodes in a lax decoder, not canonical
    padded.extend_from_slice(&[0u8; 32]);
    padded.extend_from_slice(&pop[32..]);
    assert!(c.try_decode(&b(&env, &padded)).is_err(), "non-minimal offset");

    let word = |v: &[u8], o: usize| u32::from_be_bytes(v[o + 28..o + 32].try_into().unwrap()) as usize;
    let (t0, t1) = (64 + word(&pop, 64), 64 + word(&pop, 96));
    for (i0, i1) in [(1u8, 0u8), (1, 1)] {
        let mut bad = pop.clone();
        bad[t0 + 31] = i0;
        bad[t1 + 31] = i1;
        assert!(c.try_decode(&b(&env, &bad)).is_err(), "indices {i0}, {i1}");
    }
    let mut big = pop.clone();
    big[t0 + 29] = 1; // index 65536: not a u16
    assert!(c.try_decode(&b(&env, &big)).is_err(), "index above u16");
}

/// S10: the `msig-pq-native` member 0 (`evm-eoa`) signs `memberDigest` by EIP-191 `personal_sign`.
#[test]
fn evm_eoa_member_personal_sign_recovers() {
    let (env, c) = setup();
    let r = derived(PORTABLE, "registrations", "msig-pq-native");
    let pop = b(&env, &hx(&r["pop"]));
    let m0 = env.as_contract(&c.address, || abi::decode_member_sigs(&env, &pop).get(0).unwrap());
    assert_eq!(m0.index, 0);
    let id = hx(&r["keyData"])[6..38].to_vec(); // member 0: u16 kind ‖ bytes32 id ‖ u16 weight after the u16 header pair
    assert_eq!(id[..12], [0u8; 12]);
    let id20 = BytesN::from_array(&env, &id[12..].try_into().unwrap());
    let md = n32(&env, &r["memberDigest"]);
    c.eoa(&id20, &md, &m0.sig);
    let other = BytesN::from_array(&env, &[7; 32]);
    assert!(c.try_eoa(&id20, &other, &m0.sig).is_err(), "another digest");
    assert!(c.try_eoa(&BytesN::from_array(&env, &[9; 20]), &md, &m0.sig).is_err(), "another address");
}

// --- WebAuthn: in-test P-256 signatures over clientDataJSON variants ---

const RP_ID_HASH: [u8; 32] = [0x5a; 32];

/// `(key_data, auth)` for `ua_msg(webauthn-p256, metatx, digest)` with the given clientDataJSON tail after the challenge.
fn passkey(env: &Env, digest: &BytesN<32>, tail: &str) -> (Bytes, Bytes) {
    let sk = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
    let pt = sk.verifying_key().to_encoded_point(false);
    let mut kd = pt.as_bytes()[1..].to_vec();
    kd.extend_from_slice(&RP_ID_HASH);
    let kd = b(env, &kd);
    let m = digest::ua_message(env, 0x0100, &BytesN::from_array(env, &PURPOSE_METATX), digest).to_array();
    let challenge = String::from_utf8(webauthn::b64url32(&m).to_vec()).unwrap();
    let cdj = std::format!("{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\"{tail}");
    let mut auth_data = RP_ID_HASH.to_vec();
    auth_data.extend_from_slice(&[0x05, 0, 0, 0, 1]);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&env.crypto().sha256(&b(env, cdj.as_bytes())).to_array());
    let sig: Signature = sk.sign(&signed);
    let sig = sig.normalize_s().unwrap_or(sig).to_bytes();
    (kd, b(env, &abi_encode_webauthn(&auth_data, cdj.as_bytes(), &sig)))
}

/// `abi.encode(bytes authenticatorData, bytes clientDataJSON, bytes32 r, bytes32 s)`.
pub(super) fn abi_encode_webauthn(a: &[u8], c: &[u8], rs: &[u8]) -> StdVec<u8> {
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
    let mut out = StdVec::new();
    out.extend_from_slice(&w(128));
    out.extend_from_slice(&w(128 + 32 + pad(a).len()));
    out.extend_from_slice(rs);
    out.extend_from_slice(&w(a.len()));
    out.extend_from_slice(&pad(a));
    out.extend_from_slice(&w(c.len()));
    out.extend_from_slice(&pad(c));
    out
}

/// No origin compare (accounts.md "Passkey id without origin"): one key, two origins, both verify.
#[test]
fn webauthn_origin_not_compared() {
    let (env, c) = setup();
    let digest = BytesN::from_array(&env, &[3; 32]);
    let p = BytesN::from_array(&env, &PURPOSE_METATX);
    for origin in ["https://scaas.example", "https://wallet.other.example"] {
        let (kd, auth) = passkey(&env, &digest, &std::format!(",\"origin\":\"{origin}\"}}"));
        c.check(&0x0100, &kd, &p, &digest, &auth);
    }
    let (kd, auth) = passkey(&env, &digest, ",\"origin\":\"https://a.example\",\"crossOrigin\":false}");
    c.check(&0x0100, &kd, &p, &digest, &auth);
}

/// NET-SOR-13: `"crossOrigin":true` and a `topOrigin` are refused (signatures valid over those clientDataJSONs).
#[test]
fn webauthn_cross_origin_refused() {
    let (env, c) = setup();
    let digest = BytesN::from_array(&env, &[4; 32]);
    let p = BytesN::from_array(&env, &PURPOSE_METATX);
    for tail in [
        ",\"origin\":\"https://a.example\",\"crossOrigin\":true}",
        ",\"origin\":\"https://a.example\",\"crossOrigin\":false,\"topOrigin\":\"https://b.example\"}",
        ",\"origin\":\"https://a.example\",\"crossOrigin\":false,\"x\":1,\"topOrigin\":\"https://b.example\"}",
        ",\"origin\":\"https://a.example\",\"topOrigin\":\"https://b.example\"}",
    ] {
        let (kd, auth) = passkey(&env, &digest, tail);
        assert!(c.try_check(&0x0100, &kd, &p, &digest, &auth).is_err(), "{tail}");
    }
}

/// Owner 2026-10-30: the WebAuthn blob is accepted only in its canonical ABI encoding.
#[test]
fn webauthn_blob_canonical_only() {
    let (env, c) = setup();
    let digest = BytesN::from_array(&env, &[5; 32]);
    let p = BytesN::from_array(&env, &PURPOSE_METATX);
    let (kd, auth) = passkey(&env, &digest, ",\"origin\":\"https://a.example\"}");
    c.check(&0x0100, &kd, &p, &digest, &auth);
    let v: StdVec<u8> = auth.iter().collect();
    let w = |x: &[u8], o: usize| u32::from_be_bytes(x[o + 28..o + 32].try_into().unwrap()) as usize;
    let (a_len, a_off) = (w(&v, 128), 128);
    let a_end = a_off + 32 + a_len.div_ceil(32) * 32;
    let (c_len, c_off) = (w(&v, a_end), a_end);
    let c_end = c_off + 32 + c_len.div_ceil(32) * 32;
    assert_eq!(c_end, v.len());
    assert!(a_len % 32 != 0 && c_len % 32 != 0, "need padding bytes to corrupt");
    let a = v[a_off + 32..a_off + 32 + a_len].to_vec();
    let cd = v[c_off + 32..c_off + 32 + c_len].to_vec();
    let put = |v: &mut StdVec<u8>, at: usize, x: usize| {
        v[at..at + 32].fill(0);
        v[at + 24..at + 32].copy_from_slice(&(x as u64).to_be_bytes());
    };
    let mut bad: StdVec<(&str, StdVec<u8>)> = StdVec::new();
    let mut t = v.clone();
    t.push(0);
    bad.push(("trailing byte", t));
    // authenticatorData shifted by one empty word (both offsets fixed up)
    let mut t = v.clone();
    t.splice(128..128, [0u8; 32]);
    put(&mut t, 0, 160);
    put(&mut t, 32, w(&v, 32) + 32);
    bad.push(("shifted authenticatorData offset", t));
    // clientDataJSON shifted by one empty word
    let mut t = v.clone();
    t.splice(c_off..c_off, [0u8; 32]);
    put(&mut t, 32, w(&v, 32) + 32);
    bad.push(("shifted clientDataJSON offset", t));
    let mut t = v.clone();
    t[a_off + 32 + a_len] = 1;
    bad.push(("padding after authenticatorData", t));
    let mut t = v.clone();
    t[c_off + 32 + c_len] = 1;
    bad.push(("padding after clientDataJSON", t));
    let mut t = v.clone();
    put(&mut t, c_off, c_len + 64);
    bad.push(("length word beyond data", t));
    let mut t = v.clone();
    put(&mut t, a_off, a_len + 64);
    bad.push(("authenticatorData length beyond data", t));
    // fields swapped: clientDataJSON first, offsets fixed up
    let pad = |x: &[u8]| {
        let mut y = x.to_vec();
        y.resize(x.len().div_ceil(32) * 32, 0);
        y
    };
    let mut t = v[..128].to_vec();
    put(&mut t, 0, 128 + 32 + pad(&cd).len());
    put(&mut t, 32, 128);
    for f in [&cd, &a] {
        t.extend_from_slice(&[0u8; 32]);
        let n = t.len() - 32;
        put(&mut t, n, f.len());
        t.extend_from_slice(&pad(f));
    }
    bad.push(("fields swapped", t));
    for (name, blob) in bad {
        assert!(c.try_check(&0x0100, &kd, &p, &digest, &b(&env, &blob)).is_err(), "{name}");
    }
}
