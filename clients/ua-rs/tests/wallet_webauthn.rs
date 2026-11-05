// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T6: the WebAuthn builders (spec §5.6, C-07): `webauthn_challenge` is the `ua_msg` of `0x0100`; `webauthn_assertion`
//! checks `0 < r, s < n` first, makes `s` low, accepts the exact clientDataJSON bytes only by the chains' rule against the
//! *expected* challenge, and verifies the whole encoding before it returns it. Against smartcontracts/vectors/ua/sign.json
//! `webauthn` (written by clientkeys `webauthnAssertion`), the webauthn-p256 rows of signatures.json and portable.json, and
//! assertions signed here with a test key. A passkey reaches the `UASig` builder through `SignRequest::WebAuthn`. UNAUDITED.
use p256::elliptic_curve::ff::PrimeField;
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{FieldBytes, ProjectivePoint, Scalar};
use scaas_ua::verify::verify;
use scaas_ua::wallet::{msig_sig, ua_sig, webauthn_assertion, webauthn_challenge, Error, KeyRef, SignRequest, Signer, Slot};
use scaas_ua::{derive_ua, encode_msig, member_digest, purpose_tag, ua_message, UAError};
use serde_json::Value;
use sha2::{Digest, Sha256};

const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e,
    0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
const ORIGIN: &str = "https://scaas.example";

fn load(path: &str) -> Value {
    let path = format!("{}/../../smartcontracts/vectors/ua/{path}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}
fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    parts.iter().for_each(|p| h.update(p));
    h.finalize().into()
}
fn word(b: &[u8], o: usize) -> usize {
    usize::from_be_bytes(b[o + 24..o + 32].try_into().unwrap())
}
/// `(authData, clientDataJSON, r, s)` of a canonical `abi.encode(bytes, bytes, uint256, uint256)`.
fn fields(blob: &[u8]) -> (Vec<u8>, Vec<u8>, [u8; 32], [u8; 32]) {
    let dynamic = |head: usize| {
        let o = word(blob, head);
        blob[o + 32..o + 32 + word(blob, o)].to_vec()
    };
    (dynamic(0), dynamic(32), blob[64..96].try_into().unwrap(), blob[96..128].try_into().unwrap())
}
/// The builder on a row's named fields, `expectedChallenge` as given.
fn row_assertion(r: &Value) -> Result<Vec<u8>, Error> {
    webauthn_assertion(&bytes(&r["keyData"]), &b32(&r["expectedChallenge"]), &bytes(&r["authData"]), &bytes(&r["clientDataJSON"]),
        &b32(&r["r"]), &b32(&r["s"]))
}
/// The builder on a whole blob's fields against `expected`.
fn rebuild(key_data: &[u8], expected: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, Error> {
    let (a, c, r, s) = fields(blob);
    webauthn_assertion(key_data, expected, &a, &c, &r, &s)
}
fn low(s: &[u8; 32]) -> bool {
    *s <= half_n()
}
fn half_n() -> [u8; 32] {
    let mut h = [0u8; 32];
    let mut carry = 0u8;
    for (i, b) in N.iter().enumerate() {
        h[i] = (carry << 7) | (b >> 1);
        carry = b & 1;
    }
    h
}
fn sub_from_n(s: &[u8; 32]) -> [u8; 32] {
    let (mut out, mut borrow) = ([0u8; 32], 0i16);
    for i in (0..32).rev() {
        let d = N[i] as i16 - s[i] as i16 - borrow;
        borrow = (d < 0) as i16;
        out[i] = d.rem_euclid(256) as u8;
    }
    out
}
fn add_n(s: &[u8; 32]) -> [u8; 32] {
    let (mut out, mut carry) = ([0u8; 32], 0u16);
    for i in (0..32).rev() {
        let t = N[i] as u16 + s[i] as u16 + carry;
        out[i] = t as u8;
        carry = t >> 8;
    }
    assert_eq!(carry, 0, "s + n fits 256 bits");
    out
}

fn b64url(d: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in d.chunks(3) {
        let n = c.iter().enumerate().fold(0u32, |a, (i, x)| a | (*x as u32) << (16 - 8 * i));
        (0..=c.len()).for_each(|i| out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char));
    }
    out
}
fn auth_data(flags: u8) -> Vec<u8> {
    [&sha(&[b"scaas.example"])[..], &[flags], &7u32.to_be_bytes()].concat()
}
fn client_data(ty: &str, challenge: &[u8; 32], origin: &[u8]) -> Vec<u8> {
    [format!("{{\"type\":\"{ty}\",\"challenge\":\"{}\",\"origin\":\"", b64url(challenge)).as_bytes(), origin, b"\"}"].concat()
}

/// A test passkey: a fixed P-256 key on the rp id `scaas.example`.
struct Passkey(p256::ecdsa::SigningKey);
impl Passkey {
    fn new(seed: u8) -> Passkey {
        Passkey(p256::ecdsa::SigningKey::from_slice(&sha(&[b"scaas.ua-rs-sign.t6.passkey", &[seed]])).unwrap())
    }
    fn key_data(&self) -> Vec<u8> {
        let p = self.0.verifying_key().to_sec1_point(false);
        [&p.as_bytes()[1..], &sha(&[b"scaas.example"])[..]].concat()
    }
    /// `(authData, clientDataJSON, r, s)` as the authenticator returns them (s as signed, possibly high).
    fn assert(&self, auth: &[u8], cdj: &[u8]) -> (Vec<u8>, Vec<u8>, [u8; 32], [u8; 32]) {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: p256::ecdsa::Signature = self.0.sign_prehash(&sha(&[auth, &sha(&[cdj])])).unwrap();
        let (r, s) = sig.split_bytes();
        (auth.to_vec(), cdj.to_vec(), r.into(), s.into())
    }
}
impl Signer for Passkey {
    fn key_ref(&self) -> KeyRef {
        KeyRef::Ua { kind: 0x0100, key_data: self.key_data() }
    }
    /// The phase-2 path: the device signs `challenge` and the assertion goes through the builder.
    fn sign_request(&self, req: &SignRequest) -> scaas_ua::wallet::Result<Vec<u8>> {
        let SignRequest::WebAuthn { challenge, .. } = req else { return Err(Error::Argument) };
        let (a, c, r, s) = self.assert(&auth_data(0x05), &client_data("webauthn.get", challenge, ORIGIN.as_bytes()));
        webauthn_assertion(&self.key_data(), challenge, &a, &c, &r, &s)
    }
}

/// `webauthn_challenge(purpose, digest)` = `uaMessage(0x0100, purpose, digest)`, as clientkeys `webauthnChallenge` and the
/// `message` of every signatures.json webauthn row; a purpose outside `PURPOSES` / `pop` v2 refused.
#[test]
fn webauthn_challenge_is_ua_msg() {
    let v = load("sign.json");
    for r in v["webauthn"]["accepted"].as_array().unwrap() {
        let c = webauthn_challenge(&b32(&r["purposeTag"]), &b32(&r["digest"])).unwrap();
        assert_eq!(c, b32(&r["expectedChallenge"]));
        assert_eq!(c, ua_message(0x0100, &b32(&r["purposeTag"]), &b32(&r["digest"])).unwrap());
    }
    let s = load("signatures.json");
    let d = s["derived"].as_array().unwrap().iter().find(|d| d["kind"] == 0x0100).unwrap();
    for r in d["sigs"].as_array().unwrap() {
        assert_eq!(webauthn_challenge(&b32(&r["purposeTag"]), &b32(&r["digest"])).unwrap(), b32(&r["message"]));
    }
    assert_eq!(webauthn_challenge(&[7; 32], &[0; 32]), Err(Error::Ua(UAError::PurposeUnknown)));
}

/// sign.json `webauthn.accepted`: the encoding byte for byte (a high `s` normalised), and it verifies.
#[test]
fn sign_json_accepted_rows() {
    let v = load("sign.json");
    let rows = v["webauthn"]["accepted"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    let mut high = 0;
    for r in rows {
        let blob = row_assertion(r).unwrap_or_else(|e| panic!("{e:?}: {}", r["clientDataJSON"]));
        assert_eq!(blob, bytes(&r["assertion"]));
        assert!(verify(0x0100, &bytes(&r["keyData"]), &b32(&r["expectedChallenge"]), &blob, false));
        assert!(low(&fields(&blob).3));
        high += (r["highS"] == true) as usize;
    }
    assert_eq!(high, 1);
}

/// sign.json `webauthn.refusals`: wrong challenge with a self-consistent JSON, reordered JSON, `crossOrigin: true`, `r = 0`,
/// `s = n`, `s = 0`, a flipped signature, no UV flag, another key, a clientDataJSON that is not UTF-8 (clientkeys refuses it
/// too): each `WebAuthnAssertion`.
#[test]
fn sign_json_refusals() {
    let v = load("sign.json");
    let rows = v["webauthn"]["refusals"].as_array().unwrap();
    let cases: Vec<&str> = rows.iter().map(|r| r["case"].as_str().unwrap()).collect();
    for c in ["wrong-challenge", "reordered-json", "cross-origin-true", "r-zero", "s-n", "client-data-not-utf8"] {
        assert!(cases.contains(&c), "{c}");
    }
    for r in rows {
        let e = row_assertion(r).expect_err(r["case"].as_str().unwrap());
        assert_eq!(e, Error::WebAuthnAssertion, "{}", r["case"]);
        assert_eq!(e.code(), r["error"].as_str().unwrap());
    }
}

/// The wrong-challenge row is self-consistent: its JSON carries a challenge it is validly signed over. Only the caller's
/// expected challenge refuses it.
#[test]
fn challenge_from_the_json_is_never_the_reference() {
    let v = load("sign.json");
    let r = v["webauthn"]["refusals"].as_array().unwrap().iter().find(|r| r["case"] == "wrong-challenge").unwrap();
    let (a, c) = (bytes(&r["authData"]), bytes(&r["clientDataJSON"]));
    let other = v["webauthn"]["accepted"].as_array().unwrap().iter().find(|x| x["digest"] != r["digest"]).unwrap();
    let in_json = b32(&other["expectedChallenge"]);
    assert!(c.windows(43).any(|w| w == b64url(&in_json).as_bytes()), "the JSON carries the other challenge");
    let ok = webauthn_assertion(&bytes(&r["keyData"]), &in_json, &a, &c, &b32(&r["r"]), &b32(&r["s"]));
    assert!(ok.is_ok(), "positive control: valid against the challenge in the JSON");
    assert_eq!(row_assertion(r), Err(Error::WebAuthnAssertion));
}

/// signatures.json webauthn-p256: every signature and the PoP rebuilt from their fields, byte for byte; each negative a
/// builder can be handed refused, but `high-s`, which the builder makes low (and which then verifies). The `abi-*` negatives
/// are encodings, not builder input: the builder writes the canonical one itself.
#[test]
fn signatures_json_rows() {
    let s = load("signatures.json");
    let d = s["derived"].as_array().unwrap().iter().find(|d| d["kind"] == 0x0100).unwrap();
    let kd = bytes(&d["keyData"]);
    for r in d["sigs"].as_array().unwrap() {
        assert_eq!(rebuild(&kd, &b32(&r["message"]), &bytes(&r["sig"])).unwrap(), bytes(&r["sig"]), "{}", r["purpose"]);
    }
    assert_eq!(rebuild(&kd, &b32(&d["pop"]["message"]), &bytes(&d["pop"]["sig"])).unwrap(), bytes(&d["pop"]["sig"]));
    let mut refused = 0;
    for n in d["negatives"].as_array().unwrap() {
        let name = n["name"].as_str().unwrap();
        if name.starts_with("abi-") {
            continue;
        }
        let (msg, sig) = (b32(&n["message"]), bytes(&n["sig"]));
        let got = rebuild(&kd, &msg, &sig);
        if name == "high-s" {
            let blob = got.unwrap();
            assert!(!low(&fields(&sig).3) && low(&fields(&blob).3));
            assert!(verify(0x0100, &kd, &msg, &blob, false));
        } else {
            assert_eq!(got, Err(Error::WebAuthnAssertion), "{name}");
            refused += 1;
        }
    }
    assert_eq!(refused, 12);
}

/// portable.json: the webauthn-p256 registration PoP rebuilt byte for byte against its `popMessage`.
#[test]
fn portable_json_pop_row() {
    let p = load("portable.json");
    let r = p["registrations"].as_array().unwrap().iter().find(|r| r["kindName"] == "webauthn-p256").unwrap();
    let pop = bytes(&r["pop"]);
    assert_eq!(rebuild(&bytes(&r["keyData"]), &b32(&r["popMessage"]), &pop).unwrap(), pop);
}

/// A `type` other than `webauthn.get`, validly signed: refused (positive control first).
#[test]
fn wrong_type_refused() {
    let k = Passkey::new(1);
    let ch = [9u8; 32];
    let (a, c, r, s) = k.assert(&auth_data(0x05), &client_data("webauthn.get", &ch, ORIGIN.as_bytes()));
    assert!(webauthn_assertion(&k.key_data(), &ch, &a, &c, &r, &s).is_ok());
    let (a, c, r, s) = k.assert(&auth_data(0x05), &client_data("webauthn.create", &ch, ORIGIN.as_bytes()));
    assert_eq!(webauthn_assertion(&k.key_data(), &ch, &a, &c, &r, &s), Err(Error::WebAuthnAssertion));
}

/// A clientDataJSON that is not UTF-8 (a 0xff in the origin), validly signed: the chains' byte rule alone passes it, the builder
/// refuses it.
#[test]
fn non_utf8_client_data_refused() {
    let k = Passkey::new(1);
    let ch = [9u8; 32];
    let origin = [ORIGIN.as_bytes(), &[0xff]].concat();
    let (a, c, r, s) = k.assert(&auth_data(0x05), &client_data("webauthn.get", &ch, &origin));
    assert!(std::str::from_utf8(&c).is_err());
    assert_eq!(webauthn_assertion(&k.key_data(), &ch, &a, &c, &r, &s), Err(Error::WebAuthnAssertion));
    let mut enc = vec![];
    for w in [0x80usize, 0xa0 + a.len().next_multiple_of(32)] {
        enc.extend([[0u8; 24].as_slice(), &(w as u64).to_be_bytes()].concat());
    }
    let s_low = if low(&s) { s } else { sub_from_n(&s) };
    enc.extend(r);
    enc.extend(s_low);
    for f in [&a, &c] {
        enc.extend([[0u8; 24].as_slice(), &(f.len() as u64).to_be_bytes()].concat());
        enc.extend(f.iter());
        enc.resize(enc.len() + f.len().next_multiple_of(32) - f.len(), 0);
    }
    assert!(verify(0x0100, &k.key_data(), &ch, &enc, false), "control: the chains' byte rule accepts it");
}

/// A high `s` from the authenticator comes back low and equal to the low-s build; the input `s` is refused only out of range.
#[test]
fn high_s_normalised() {
    let k = Passkey::new(2);
    let ch = [3u8; 32];
    let (a, c, r, s) = k.assert(&auth_data(0x05), &client_data("webauthn.get", &ch, ORIGIN.as_bytes()));
    let (lo, hi) = if low(&s) { (s, sub_from_n(&s)) } else { (sub_from_n(&s), s) };
    let from_low = webauthn_assertion(&k.key_data(), &ch, &a, &c, &r, &lo).unwrap();
    let from_high = webauthn_assertion(&k.key_data(), &ch, &a, &c, &r, &hi).unwrap();
    assert_eq!(from_low, from_high);
    assert_eq!(fields(&from_high).3, lo);
}

/// `0 < s < n` is checked on the input before anything else: a key made so that `(r, 1)` is a valid signature, then `s = n + 1`
/// (≡ 1 mod n) refused. A builder that reduced or normalised first and checked after would accept it.
#[test]
fn s_out_of_range_refused_before_normalisation() {
    let ch = [5u8; 32];
    let (a, c) = (auth_data(0x05), client_data("webauthn.get", &ch, ORIGIN.as_bytes()));
    let z = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(sha(&[&a, &sha(&[&c])])));
    let k = Scalar::from(7u64);
    let big_r = (ProjectivePoint::GENERATOR * k).to_affine();
    let r_bytes: [u8; 32] = big_r.x().into();
    let r = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(r_bytes))).expect("x(7G) < n");
    // s = 1: d = (k - z) / r
    let d = (k - z) * Option::<Scalar>::from(r.invert()).unwrap();
    let q = (ProjectivePoint::GENERATOR * d).to_affine().to_sec1_point(false);
    let kd = [&q.as_bytes()[1..], &sha(&[b"scaas.example"])[..]].concat();
    let mut one = [0u8; 32];
    one[31] = 1;
    assert!(webauthn_assertion(&kd, &ch, &a, &c, &r_bytes, &one).is_ok(), "positive control: (r, 1) verifies");
    assert_eq!(webauthn_assertion(&kd, &ch, &a, &c, &r_bytes, &add_n(&one)), Err(Error::WebAuthnAssertion));
    assert_eq!(webauthn_assertion(&kd, &ch, &a, &c, &add_n(&[0; 32]), &one), Err(Error::WebAuthnAssertion), "r = n");
}

/// An assertion of one passkey handed in with another's key data: refused (the sign.json row and one signed here).
#[test]
fn assertion_for_another_key_refused() {
    let v = load("sign.json");
    let r = v["webauthn"]["refusals"].as_array().unwrap().iter().find(|r| r["case"] == "another-key").unwrap();
    assert_eq!(row_assertion(r), Err(Error::WebAuthnAssertion));
    let (k1, k2) = (Passkey::new(1), Passkey::new(2));
    let ch = [4u8; 32];
    let (a, c, rr, s) = k1.assert(&auth_data(0x05), &client_data("webauthn.get", &ch, ORIGIN.as_bytes()));
    assert!(webauthn_assertion(&k1.key_data(), &ch, &a, &c, &rr, &s).is_ok());
    assert_eq!(webauthn_assertion(&k2.key_data(), &ch, &a, &c, &rr, &s), Err(Error::WebAuthnAssertion));
}

/// A passkey through the `UASig` builder (the phase-2 path, spec §9.4): it is asked `SignRequest::WebAuthn { challenge }` with
/// `challenge = webauthn_challenge(purpose, digest)`, never a `UaMsg`, and the `UASig` verifies as `0x0100`; as an `msig` member
/// it signs the `member` message of its slot.
#[test]
fn passkey_signs_through_the_uasig_builder() {
    let k = Passkey::new(3);
    let (purpose, digest) = (purpose_tag("metatx").unwrap(), [6u8; 32]);
    let sig = ua_sig(&k, None, &purpose, &digest).unwrap();
    assert_eq!(sig.key_data, k.key_data());
    assert!(verify(0x0100, &k.key_data(), &webauthn_challenge(&purpose, &digest).unwrap(), &sig.signature, false));
    let id = derive_ua(0x0100, &k.key_data(), false).unwrap();
    let kd = encode_msig(1, &[(0x0100, id, 1)]);
    let s = msig_sig(&kd, &|_| None, &purpose, &digest, None, None, &[Slot::Member { index: 0, key: &k }]).unwrap();
    let ua = derive_ua(0x0120, &kd, false).unwrap();
    let md = member_digest(&ua, &ua_message(0x0120, &purpose, &digest).unwrap());
    let member_msg = ua_message(0x0100, &purpose_tag("member").unwrap(), &md).unwrap();
    assert!(verify(0x0100, &k.key_data(), &member_msg, &s.members[0].sig, false));
}
