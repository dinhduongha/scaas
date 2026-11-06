// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T8: AEAD, HKDF, HMAC (spec §7) on their published vectors (NIST GCM, RFC 8452, RFC 5869, RFC 4231); seal / open and
//! the sealed containers of backup and link (spec §6.3, C-03, C-11, MD-10, MD-11) against smartcontracts/vectors/ua/seal.json
//! (written by clientkeys `seal.js`): every `seal`, `refusals`, `argumentRefusals`, `containers` (byte-equal, rebuilt here with
//! the row's `m` and `e`), `acceptance` row and the link rows of `replay`. The backup restore rows (`restore`, the rollback rows of
//! `replay`) are T9's. The `vectors` tests use the test-only entry points (fixed `m` and `e`, the ephemeral key and the link
//! session from given bytes). UNAUDITED.
use scaas_ua::wallet::{
    aead_open, aead_seal, hkdf_expand_sha256, hkdf_sha256, hmac_sha256, seal, Alg, ContainerExpect, ContainerSigner, Error,
    ExpectedSender, KemKeyPair, LinkSession, Recipient, RecipientId, Sealed, SealedContainer, Wallet,
};
use scaas_ua::{keccak256, seal_purpose_tag, UAError};
use serde_json::Value;
use std::collections::HashMap;

fn path(f: &str) -> String {
    format!("{}/../../smartcontracts/vectors/ua/{f}", env!("CARGO_MANIFEST_DIR"))
}
fn load(f: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path(f)).unwrap()).unwrap()
}
fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array().unwrap()
}
fn h(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    h(v.as_str().unwrap())
}
fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}
fn num(v: &Value) -> u64 {
    v.as_u64().unwrap()
}
fn wallet(id: &str) -> Wallet {
    let k = load("keys.json");
    let m = arr(&k, "mnemonics").iter().find(|m| m["id"] == id).unwrap();
    Wallet::from_mnemonic(m["words"].as_str().unwrap(), m["passphrase"].as_str().unwrap()).unwrap()
}
/// The KEM key a `{mnemonic, kind, account, index, version}` names, and its wallet (dropping it revokes the key).
fn kem_of(r: &Value) -> (Wallet, KemKeyPair) {
    let w = wallet(r["mnemonic"].as_str().unwrap());
    let key = w.ua_key(num(&r["kind"]) as u16, num(&r["account"]) as u32, num(&r["index"]) as u32).unwrap();
    let kk = key.kem_key(num(&r["version"])).unwrap();
    (w, kk)
}
fn container(v: &Value) -> Result<SealedContainer, Error> {
    SealedContainer::from_json(v.to_string().as_bytes())
}
/// A row's `expect`: the purpose, the expected UA or the approved set, the recipient.
struct Expect {
    purpose: String,
    sender: Vec<[u8; 32]>,
    one: bool,
    recipient: RecipientId,
}
impl Expect {
    fn of(e: &Value) -> Expect {
        let r = &e["recipient"];
        let recipient = match r.get("kemPkHash") {
            Some(k) => RecipientId::KemPkHash(b32(k)),
            None => RecipientId::Ua { ua: b32(&r["ua"]), version: num(&r["version"]) },
        };
        let (sender, one) = match e["sender"].get("ua") {
            Some(u) => (vec![b32(u)], true),
            None => (e["sender"]["set"].as_array().unwrap().iter().map(b32).collect(), false),
        };
        Expect { purpose: e["purpose"].as_str().unwrap().to_owned(), sender, one, recipient }
    }
    fn get(&self) -> ContainerExpect<'_> {
        let sender = if self.one { ExpectedSender::Ua(self.sender[0]) } else { ExpectedSender::Set(&self.sender) };
        ContainerExpect { purpose: &self.purpose, sender, recipient: self.recipient }
    }
}
type MemberMap = HashMap<[u8; 32], (u16, Vec<u8>)>;
/// A row's `members`: `{id: {kind, keyData}}`, the opener's lookup of an `msig` sender's member keys.
fn members_of(r: &Value) -> MemberMap {
    let mut m = HashMap::new();
    if let Some(o) = r.get("members").and_then(Value::as_object) {
        for (id, x) in o {
            m.insert(h(id).try_into().unwrap(), (num(&x["kind"]) as u16, bytes(&x["keyData"])));
        }
    }
    m
}
/// A row's `accepted`: `{id: [indices]}` (an index not listed is not accepted), `None` without one or for `null`.
fn accepted_of(r: &Value) -> Option<HashMap<[u8; 32], Vec<u16>>> {
    let o = r.get("accepted")?.as_object()?;
    Some(o.iter().map(|(id, l)| (h(id).try_into().unwrap(), l.as_array().unwrap().iter().map(|i| num(i) as u16).collect())).collect())
}
/// `open_container` with a row's expect, members and accepted.
fn open_row(kk: &KemKeyPair, c: &SealedContainer, r: &Value) -> Result<Vec<u8>, Error> {
    let e = Expect::of(&r["expect"]);
    let map = members_of(r);
    let members = move |id: [u8; 32]| map.get(&id).cloned();
    let acc = accepted_of(r);
    let accepted = |id: [u8; 32], i: u16| acc.as_ref().is_some_and(|a| a.get(&id).is_some_and(|l| l.contains(&i)));
    let accepted_ref: Option<&scaas_ua::ua8::Accepted> = if acc.is_some() { Some(&accepted) } else { None };
    kk.open_container(c, &e.get(), &members, accepted_ref).map(|p| p.to_vec())
}

// --- AEAD, HKDF, HMAC: published vectors ---

/// NIST GCM (McGrew–Viega, the GCM specification's test cases 13–16: AES-256): `ct ‖ tag`, and back.
#[test]
fn nist_gcm_aes256() {
    let k15 = h("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    let p = h("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
    let iv = h("cafebabefacedbaddecaf888");
    let a16 = h("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    // (key, nonce, aad, pt, ct ‖ tag)
    type Case<'a> = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, &'a str);
    let cases: [Case; 4] = [
        (vec![0; 32], vec![0; 12], vec![], vec![], "530f8afbc74536b9a963b4f1c4cb738b"),
        (vec![0; 32], vec![0; 12], vec![], vec![0; 16], "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"),
        (k15.clone(), iv.clone(), vec![], p.clone(),
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3cc6c"),
        (k15, iv, a16, p[..60].to_vec(),
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b"),
    ];
    for (k, n, a, p, ct) in cases {
        let (k, n): ([u8; 32], [u8; 12]) = (k.try_into().unwrap(), n.try_into().unwrap());
        assert_eq!(hex::encode(aead_seal(Alg::Aes256Gcm, &k, &n, &a, &p).unwrap()), ct);
        assert_eq!(*aead_open(Alg::Aes256Gcm, &k, &n, &a, &h(ct)).unwrap(), p);
    }
}

/// RFC 8452 Appendix C.2 (AEAD_AES_256_GCM_SIV): `ct ‖ tag`, and back.
#[test]
fn rfc8452_aes256_gcm_siv() {
    let k: [u8; 32] = h("0100000000000000000000000000000000000000000000000000000000000000").try_into().unwrap();
    let n: [u8; 12] = h("030000000000000000000000").try_into().unwrap();
    for (a, p, ct) in [
        ("", "", "07f5f4169bbf55a8400cd47ea6fd400f"),
        ("", "0100000000000000", "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28"),
        ("", "01000000000000000000000000000000", "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366"),
        ("01", "0200000000000000", "1de22967237a813291213f267e3b452f02d01ae33e4ec854"),
    ] {
        assert_eq!(hex::encode(aead_seal(Alg::Aes256GcmSiv, &k, &n, &h(a), &h(p)).unwrap()), ct);
        assert_eq!(*aead_open(Alg::Aes256GcmSiv, &k, &n, &h(a), &h(ct)).unwrap(), h(p));
    }
}

/// A bad tag, a changed `aad` or a short input: `Aead`, no plaintext; the two algorithms do not open each other.
#[test]
fn aead_open_refusals() {
    let (k, n) = ([7u8; 32], [9u8; 12]);
    for alg in [Alg::Aes256Gcm, Alg::Aes256GcmSiv] {
        let ct = aead_seal(alg, &k, &n, b"aad", b"plaintext").unwrap();
        assert_eq!(*aead_open(alg, &k, &n, b"aad", &ct).unwrap(), b"plaintext"); // control
        let mut bad = ct.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(aead_open(alg, &k, &n, b"aad", &bad).err(), Some(Error::Aead));
        assert_eq!(aead_open(alg, &k, &n, b"aaD", &ct).err(), Some(Error::Aead));
        assert_eq!(aead_open(alg, &k, &n, b"aad", &ct[..15]).err(), Some(Error::Aead));
    }
    let ct = aead_seal(Alg::Aes256Gcm, &k, &n, b"", b"x").unwrap();
    assert_eq!(aead_open(Alg::Aes256GcmSiv, &k, &n, b"", &ct).err(), Some(Error::Aead));
}

/// RFC 5869 A.1 and A.3 (HKDF-SHA256): PRK and OKM; `len ≤ 255 × 32`, a PRK shorter than 32 bytes refused.
#[test]
fn rfc5869_hkdf_sha256() {
    let ikm = [0x0b; 22];
    let okm1 = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
    assert_eq!(hex::encode(&*hkdf_sha256(&ikm, &h("000102030405060708090a0b0c"), &h("f0f1f2f3f4f5f6f7f8f9"), 42).unwrap()), okm1);
    let prk1 = h("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    assert_eq!(hex::encode(&*hkdf_expand_sha256(&prk1, &h("f0f1f2f3f4f5f6f7f8f9"), 42).unwrap()), okm1);
    let okm3 = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8";
    assert_eq!(hex::encode(&*hkdf_sha256(&ikm, &[], &[], 42).unwrap()), okm3);
    assert_eq!(hkdf_sha256(&ikm, &[], &[], 255 * 32).unwrap().len(), 255 * 32);
    assert_eq!(hkdf_sha256(&ikm, &[], &[], 255 * 32 + 1).err(), Some(Error::Argument));
    assert_eq!(hkdf_expand_sha256(&prk1, &[], 255 * 32 + 1).err(), Some(Error::Argument));
    assert_eq!(hkdf_expand_sha256(&prk1[..31], &[], 32).err(), Some(Error::Argument));
}

/// RFC 4231 test cases 1 and 2 (HMAC-SHA-256).
#[test]
fn rfc4231_hmac_sha256() {
    assert_eq!(hex::encode(hmac_sha256(&[0x0b; 20], b"Hi There")), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    assert_eq!(
        hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

// --- seal / open ---

/// seal.json `seal`: every row opens to its `pt` with its recipient's key (a derived key; the link row's ephemeral key is the
/// `vectors` test's), the wire form parses to the named fields.
#[test]
fn seal_json_open() {
    let v = load("seal.json");
    let mut n = 0;
    for r in arr(&v, "seal") {
        let s = Sealed::from_wire(&bytes(&r["wire"])).unwrap();
        assert_eq!((s.mlkem_ct.clone(), s.x25519_eph.to_vec(), s.ciphertext.clone()), (bytes(&r["mlkemCt"]), bytes(&r["x25519Eph"]), bytes(&r["ciphertext"])));
        assert_eq!(s.to_wire(), bytes(&r["wire"]));
        if r["recipient"].get("mnemonic").is_some() {
            let (_w, kk) = kem_of(&r["recipient"]);
            assert_eq!(kk.kem_pk(), bytes(&r["kemPk"]));
            assert_eq!(*kk.open(r["purpose"].as_str().unwrap(), &bytes(&r["aad"]), &s).unwrap(), bytes(&r["pt"]), "{}", r["id"]);
            n += 1;
        }
    }
    assert_eq!(n, 2);
}

/// seal.json `refusals`: each change of the base row alone: purpose, `aad`, a flipped byte of each field, version or scheme 2,
/// another KEM key (version 1); the base row opens (control).
#[test]
fn seal_json_refusals() {
    let v = load("seal.json");
    let base = arr(&v, "seal").iter().find(|r| r["id"] == v["refusals"]["base"]).unwrap();
    let (_w, k0) = kem_of(&v["refusals"]["key"]);
    let purpose = base["purpose"].as_str().unwrap();
    let wire = bytes(&base["wire"]);
    assert_eq!(*k0.open(purpose, &bytes(&base["aad"]), &Sealed::from_wire(&wire).unwrap()).unwrap(), bytes(&base["pt"]));
    let mut n = 0;
    for r in arr(&v["refusals"], "rows") {
        let (_w1, other) = r.get("key").map(kem_of).unzip();
        let kk = other.as_ref().unwrap_or(&k0);
        let p = r.get("purpose").and_then(Value::as_str).unwrap_or(purpose);
        let aad = r.get("aad").map_or_else(|| bytes(&base["aad"]), bytes);
        let w = r.get("wire").map_or_else(|| wire.clone(), bytes);
        let got = Sealed::from_wire(&w).and_then(|s| kk.open(p, &aad, &s).map(|_| ()));
        assert_eq!(got.err().map(|e| e.code()), r["error"].as_str(), "{}", r["id"]);
        n += 1;
    }
    assert_eq!(n, 10);
    // the named fields refused the same way as the wire form
    let mut s = Sealed::from_wire(&wire).unwrap();
    s.version = 2;
    assert_eq!(k0.open(purpose, &bytes(&base["aad"]), &s).err(), Some(Error::SealVersion));
    let mut s = Sealed::from_wire(&wire).unwrap();
    s.mlkem_ct.pop();
    assert_eq!(k0.open(purpose, &bytes(&base["aad"]), &s).err(), Some(Error::SealOpen));
    assert_eq!(Sealed::from_wire(&wire[..2 + 1568 + 32 + 15]).err(), Some(Error::SealOpen));
}

/// seal.json `argumentRefusals`: purpose not `[a-z0-9./-]{1,64}`, `pt` over 1 MiB: `Argument`, before any encapsulation.
#[test]
fn seal_json_argument_refusals() {
    let v = load("seal.json");
    let (_w, kk) = kem_of(&v["refusals"]["key"]);
    let mut n = 0;
    for r in arr(&v, "argumentRefusals") {
        let pt = vec![0u8; num(&r["ptLength"]) as usize];
        assert_eq!(seal(&kk.kem_pk(), r["purpose"].as_str().unwrap(), b"", &pt).err(), Some(Error::Argument), "{}", r["id"]);
        assert_eq!(kk.open(r["purpose"].as_str().unwrap(), b"", &Sealed::from_wire(&bytes(&arr(&v, "seal")[0]["wire"])).unwrap()).err().map(|e| e.code()),
            Some(if r["purpose"] == "scaas/backup/v1" { "SealOpen" } else { "Argument" }), "{}", r["id"]);
        n += 1;
    }
    assert_eq!(n, 4);
}

#[test]
fn empty_pt_ok() {
    let (_w, kk) = kem_of(&serde_json::json!({"mnemonic": "pq_kat", "kind": 0x0130, "account": 0, "index": 0, "version": 0}));
    let s = seal(&kk.kem_pk(), "scaas/test/v1", b"", b"").unwrap();
    assert_eq!(s.ciphertext.len(), 16);
    assert!(kk.open("scaas/test/v1", b"", &s).unwrap().is_empty());
}

#[test]
#[allow(non_snake_case)]
fn pt_over_1_MiB_refused() {
    let (_w, kk) = kem_of(&serde_json::json!({"mnemonic": "pq_kat", "kind": 0x0130, "account": 0, "index": 0, "version": 0}));
    let max = vec![0u8; 1 << 20];
    let s = seal(&kk.kem_pk(), "scaas/backup/v1", b"a", &max).unwrap(); // control: exactly 1 MiB
    assert_eq!(kk.open("scaas/backup/v1", b"a", &s).unwrap().len(), 1 << 20);
    assert_eq!(seal(&kk.kem_pk(), "scaas/backup/v1", b"a", &[0u8; (1 << 20) + 1]).err(), Some(Error::Argument));
}

/// A release seal (OS randomness): two seals of one `pt` differ, both open; a bad `kemPk` is `KemCheck`.
#[test]
fn release_seal_round_trip() {
    let (_w, kk) = kem_of(&serde_json::json!({"mnemonic": "pq_kat", "kind": 0x0134, "account": 0, "index": 0, "version": 2}));
    let (a, b) = (seal(&kk.kem_pk(), "scaas/x", b"aad", b"pt").unwrap(), seal(&kk.kem_pk(), "scaas/x", b"aad", b"pt").unwrap());
    assert_ne!(a.to_wire(), b.to_wire());
    assert_eq!(*kk.open("scaas/x", b"aad", &a).unwrap(), b"pt");
    assert_eq!(*kk.open("scaas/x", b"aad", &b).unwrap(), b"pt");
    let mut pk = kk.kem_pk();
    pk[0] = 2;
    assert_eq!(seal(&pk, "scaas/x", b"", b"").err(), Some(Error::KemCheck));
    let eph = KemKeyPair::generate_ephemeral().unwrap();
    assert_eq!(eph.recipient(), RecipientId::KemPkHash(keccak256(&eph.kem_pk())));
    assert_eq!(kk.recipient(), RecipientId::Ua { ua: kk_ua(), version: 2 });
}
fn kk_ua() -> [u8; 32] {
    wallet("pq_kat").ua_key(0x0134, 0, 0).unwrap().ua().unwrap()
}

// --- containers ---

/// seal.json `containers`: each opens to its `pt` (the link row through its session: the `vectors` test), and its JSON
/// round-trips through the named fields.
#[test]
fn seal_json_containers_open() {
    let v = load("seal.json");
    let mut n = 0;
    for r in arr(&v, "containers") {
        let c = container(&r["container"]).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&c.to_json()).unwrap(), r["container"], "{}", r["id"]);
        if let Some(k) = r["opener"].get("kem") {
            let (_w, kk) = kem_of(k);
            assert_eq!(open_row(&kk, &c, r).unwrap(), bytes(&r["pt"]), "{}", r["id"]);
            n += 1;
        }
    }
    assert_eq!(n, 3);
}

/// seal.json `acceptance`: every row from an otherwise valid container, opened with its opener's key: `ContainerSender`,
/// `SealOpen`, `SealVersion` or accepted. The restore row (`restore`) opens here: its refusal is the restore's (T9); the link
/// row is the `vectors` test's.
#[test]
fn seal_json_acceptance() {
    let v = load("seal.json");
    let mut n = 0;
    for r in arr(&v, "acceptance") {
        if r.get("link").is_some() {
            continue;
        }
        let (_w, kk) = kem_of(&r["opener"]["kem"]);
        let got = container(&r["container"]).and_then(|c| open_row(&kk, &c, r).map(|_| ()));
        let want = if r.get("restore").is_some() { None } else { r["error"].as_str() };
        assert_eq!(got.err().map(|e| e.code()), want, "{}", r["id"]);
        n += 1;
    }
    assert_eq!(n, 28);
}

/// An `msig` member of an `msig` sender signs only by its own list: a signature of its own in its slot is `SealOpen` (clientkeys
/// `msigOk`; seal.json has no row for it). Control: the nested row opens unchanged.
#[test]
fn msig_member_msig_with_own_sig_refused() {
    let v = load("seal.json");
    let r = arr(&v, "containers").iter().find(|r| r["id"] == "msig sender: nested, inner {two of three} + bls12381").unwrap();
    let (_w, kk) = kem_of(&r["opener"]["kem"]);
    assert_eq!(open_row(&kk, &container(&r["container"]).unwrap(), r).unwrap(), bytes(&r["pt"]));
    let mut j = r["container"].clone();
    let slot = &mut j["sender"]["auth"]["members"][0];
    assert!(!slot["members"].as_array().unwrap().is_empty() && slot["sig"] == "", "slot 0 is the inner msig");
    slot["sig"] = Value::from("AQ");
    assert_eq!(open_row(&kk, &container(&j).unwrap(), r).err(), Some(Error::SealOpen));
}

/// An `msig` sender with no `accepted` lookup: `ContainerSender`; the same container with the lookup opens (control).
#[test]
fn msig_sender_without_accepted_refused() {
    let v = load("seal.json");
    let r = arr(&v, "containers").iter().find(|r| r["id"] == "msig sender: flat {p256, ed25519}").unwrap();
    let (_w, kk) = kem_of(&r["opener"]["kem"]);
    let c = container(&r["container"]).unwrap();
    assert_eq!(open_row(&kk, &c, r).unwrap(), bytes(&r["pt"]));
    let e = Expect::of(&r["expect"]);
    let map = members_of(r);
    let members = move |id: [u8; 32]| map.get(&id).cloned();
    assert_eq!(kk.open_container(&c, &e.get(), &members, None).err(), Some(Error::ContainerSender));
    let nobody = |_: [u8; 32], _: u16| false;
    assert_eq!(kk.open_container(&c, &e.get(), &members, Some(&nobody)).err(), Some(Error::ContainerSender));
}

/// A single-key sender never asks `accepted` (a lookup that panics is never called) nor `members`, with or without them.
#[test]
fn single_key_sender_never_asks_accepted() {
    let v = load("seal.json");
    let r = &arr(&v, "containers")[0];
    let (_w, kk) = kem_of(&r["opener"]["kem"]);
    let c = container(&r["container"]).unwrap();
    let e = Expect::of(&r["expect"]);
    let members = |_: [u8; 32]| -> Option<(u16, Vec<u8>)> { panic!("members asked") };
    let accepted = |_: [u8; 32], _: u16| -> bool { panic!("accepted asked") };
    assert_eq!(*kk.open_container(&c, &e.get(), &members, Some(&accepted)).unwrap(), bytes(&r["pt"]));
    assert_eq!(*kk.open_container(&c, &e.get(), &members, None).unwrap(), bytes(&r["pt"]));
}

/// The expected sender set holds at most 64 UAs (spec §9.3): `Argument`.
#[test]
fn approved_set_bounded() {
    let v = load("seal.json");
    let r = &arr(&v, "containers")[0];
    let (_w, kk) = kem_of(&r["opener"]["kem"]);
    let c = container(&r["container"]).unwrap();
    let e = Expect::of(&r["expect"]);
    let none = |_: [u8; 32]| None;
    let mut set = vec![[1u8; 32]; 63];
    set.push(e.sender[0]);
    let ok = ContainerExpect { purpose: &e.purpose, sender: ExpectedSender::Set(&set), recipient: e.recipient };
    assert!(kk.open_container(&c, &ok, &none, None).is_ok()); // control: 64
    set.push([2u8; 32]);
    let over = ContainerExpect { purpose: &e.purpose, sender: ExpectedSender::Set(&set), recipient: e.recipient };
    assert_eq!(kk.open_container(&c, &over, &none, None).err(), Some(Error::Argument));
}

/// Container JSON past its bounds or malformed: `SealOpen` (fields), `SealVersion` (`v` ≠ 1), `Argument` (length, depth).
#[test]
fn container_json_bounds() {
    let v = load("seal.json");
    let good = arr(&v, "containers")[0]["container"].clone();
    let good_json = good.to_string();
    assert!(container(&good).is_ok());
    let mut c = good.clone();
    c["sender"]["auth"]["signature"] = Value::from("!");
    assert_eq!(container(&c).err(), Some(Error::SealOpen));
    let mut c = good.clone();
    c["sealed"]["x25519Eph"] = Value::from("AAAA");
    assert_eq!(container(&c).err(), Some(Error::SealOpen));
    let mut c = good.clone();
    c["sender"]["auth"]["members"] = serde_json::json!([{"index": 0, "members": [{"index": 0, "members": [{"index": 0, "sig": ""}], "sig": ""}], "sig": ""}]);
    assert!(container(&c).is_err(), "a third level");
    let mut c = good;
    c["v"] = Value::from(2);
    assert_eq!(container(&c).err(), Some(Error::SealVersion));
    // a valid container padded with whitespace: up to 4 MiB it reads (control), one byte past it `Argument`
    let mut padded = good_json.into_bytes();
    padded.resize(4 << 20, b' ');
    assert!(SealedContainer::from_json(&padded).is_ok());
    padded.push(b' ');
    assert_eq!(SealedContainer::from_json(&padded).err(), Some(Error::Argument));
    assert_eq!(SealedContainer::from_json("[".repeat(64).as_bytes()).err(), Some(Error::Argument));
}

/// MD-10: the seal purpose is off-chain, refused by `sign_ua` (only the container builder signs under it), in no `PURPOSES`.
#[test]
fn seal_purpose_only_from_the_container_builder() {
    assert_eq!(seal_purpose_tag(), keccak256(b"scaas.ua.purpose.seal.v1"));
    assert!(!scaas_ua::PURPOSES.contains(&"seal"));
    let w = wallet("twelve_words");
    let key = w.ua_key(0x0102, 0, 0).unwrap();
    assert!(key.sign_ua(&scaas_ua::purpose_tag("member").unwrap(), &[0; 32]).is_ok()); // control
    assert_eq!(key.sign_ua(&seal_purpose_tag(), &[0; 32]).err(), Some(Error::Ua(UAError::PurposeUnknown)));
}

/// MD-11: a container recipient is a single-key KEM holder by construction; an `msig` (or any non-holder) is `KemHolder`.
#[test]
fn msig_recipient_refused() {
    let w = wallet("pq_kat");
    let key = w.ua_key(0x0130, 0, 0).unwrap();
    let kk = key.kem_key(0).unwrap();
    let r = Recipient::ua(0x0130, &key.key_data(), 0, &kk.kem_pk()).unwrap(); // control
    assert_eq!(r.id(), kk.recipient());
    let v = load("seal.json");
    let msig_kd = bytes(&arr(&v, "containers")[2]["sender"]["msig"]["keyData"]);
    assert_eq!(Recipient::ua(0x0120, &msig_kd, 0, &kk.kem_pk()).err(), Some(Error::KemHolder));
    let ed = w.ua_key(0x0102, 0, 0).unwrap();
    assert_eq!(Recipient::ua(0x0102, &ed.key_data(), 0, &kk.kem_pk()).err(), Some(Error::KemHolder));
    assert!(Recipient::ua(0x0130, &ed.key_data(), 0, &kk.kem_pk()).is_err(), "key data not of its kind");
}

/// A release container (OS randomness) from a wallet's identity key to a link session, installed by `from_link`: the new wallet
/// derives the sender's keys; a native key cannot sign a container.
#[test]
fn release_link_round_trip() {
    let w = wallet("twelve_words");
    let key = w.ua_key(0x0102, 0, 0).unwrap();
    let session = LinkSession::new().unwrap();
    assert!(session.short_code().len() == 8 && session.short_code().bytes().all(|b| b.is_ascii_digit()));
    let rec = Recipient::ephemeral(&session.kem_pk());
    let entropy = hex::encode(w_entropy("twelve_words"));
    let pt = format!(
        "{{\"v\":1,\"generation\":1,\"entropy\":\"{}\",\"secrets\":[],\"manifest\":{{\"entries\":[]}}}}",
        b64url(&hex::decode(entropy).unwrap())
    );
    let c = scaas_ua::wallet::seal_container(&rec, "scaas/link/v1", &ContainerSigner::Key(&key), session.start(), pt.as_bytes(), Some(&session.short_code())).unwrap();
    let native = w.native_key(scaas_ua::wallet::Network::Evm, 0, None).unwrap();
    assert_eq!(scaas_ua::wallet::seal_container(&rec, "scaas/link/v1", &ContainerSigner::Key(&native), session.start(), b"", Some("1")).err(), Some(Error::Argument));
    let expect = ContainerExpect { purpose: "scaas/link/v1", sender: ExpectedSender::Ua(key.ua().unwrap()), recipient: session.recipient() };
    let none = |_: [u8; 32]| None;
    let linked = Wallet::from_link(session, &SealedContainer::from_json(c.to_json().as_bytes()).unwrap(), &expect, &none, None, "").unwrap();
    assert_eq!(linked.ua_key(0x0102, 0, 0).unwrap().ua(), key.ua());
}
fn w_entropy(id: &str) -> Vec<u8> {
    let k = load("keys.json");
    bytes(&arr(&k, "mnemonics").iter().find(|m| m["id"] == id).unwrap()["entropy"])
}
fn b64url(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = c.iter().enumerate().fold(0u32, |n, (i, x)| n | u32::from(*x) << (16 - 8 * i));
        for i in 0..=c.len() {
            s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    s
}

#[cfg(feature = "vectors")]
mod vectors {
    use super::*;
    use scaas_ua::wallet::seal::{vectors_seal, vectors_seal_container};
    use scaas_ua::wallet::{Signer, Slot, UaKey};

    fn session(v: &Value, short_code: Option<&str>) -> LinkSession {
        let s = &arr(v, "containers")[1]["opener"]["session"];
        let code = short_code.unwrap_or(s["shortCode"].as_str().unwrap());
        LinkSession::vectors_new(&bytes(&s["seed"]).try_into().unwrap(), code, num(&s["start"])).unwrap()
    }
    fn link(v: &Value, r: &Value, code: Option<&str>) -> Result<Wallet, Error> {
        let e = Expect::of(&r["expect"]);
        let none = |_: [u8; 32]| None;
        Wallet::from_link(session(v, code), &container(&r["container"])?, &e.get(), &none, None, "")
    }

    /// seal.json `seal`: with the row's `m` and `e`, `(mlkemCt, x25519Eph, ciphertext)` and the wire form byte-equal; the link
    /// row's ephemeral key from its 96 bytes opens it.
    #[test]
    fn seal_json_seal_rows() {
        let v = load("seal.json");
        let mut n = 0;
        for r in arr(&v, "seal") {
            let kem_pk = bytes(&r["kemPk"]);
            let (m, e) = (b32(&r["m"]), b32(&r["e"]));
            let s = vectors_seal(&kem_pk, r["purpose"].as_str().unwrap(), &bytes(&r["aad"]), &bytes(&r["pt"]), &m, &e).unwrap();
            assert_eq!(hex::encode(s.to_wire()), hex::encode(bytes(&r["wire"])), "{}", r["id"]);
            if let Some(seed) = r["recipient"].get("ephemeralSeed") {
                let kk = KemKeyPair::vectors_ephemeral(&bytes(seed).try_into().unwrap()).unwrap();
                assert_eq!(kk.kem_pk(), kem_pk);
                assert_eq!(*kk.open(r["purpose"].as_str().unwrap(), &bytes(&r["aad"]), &s).unwrap(), bytes(&r["pt"]));
            }
            n += 1;
        }
        assert_eq!(n, 3);
    }

    fn key_of(w: &HashMap<String, Wallet>, k: &Value) -> UaKey {
        w[k["mnemonic"].as_str().unwrap()].ua_key(num(&k["kind"]) as u16, num(&k["account"]) as u32, num(&k["index"]) as u32).unwrap()
    }

    /// seal.json `containers`: rebuilt from the row's sender (the wallet's identity key, or an `msig` by its member keys: flat and
    /// nested) with the row's `m` and `e`, the container JSON equal to the row's; the link row opens through its session.
    #[test]
    fn seal_json_containers_rebuilt() {
        let v = load("seal.json");
        let wallets: HashMap<String, Wallet> = ["pq_kat", "twelve_words"].iter().map(|id| (id.to_string(), wallet(id))).collect();
        let mut n = 0;
        for r in arr(&v, "containers") {
            let c = &r["container"];
            let (kem_pk, rec) = match r["opener"].get("kem") {
                Some(k) => {
                    let key = key_of(&wallets, k);
                    let kem_pk = bytes(&k["kemPk"]);
                    (kem_pk.clone(), Recipient::ua(key.kind(), &key.key_data(), num(&k["version"]), &kem_pk).unwrap())
                }
                None => {
                    let pk = session(&v, None).kem_pk();
                    (pk.clone(), Recipient::ephemeral(&pk))
                }
            };
            let _ = kem_pk;
            let code = r["opener"].get("session").map(|s| s["shortCode"].as_str().unwrap().to_owned());
            let (m, e) = (b32(&r["m"]), b32(&r["e"]));
            let purpose = c["purpose"].as_str().unwrap();
            let built = if let Some(s) = r["sender"].get("msig") {
                let inner: HashMap<[u8; 32], Vec<u8>> = s
                    .get("inner")
                    .and_then(Value::as_object)
                    .map(|o| o.iter().map(|(id, kd)| (h(id).try_into().unwrap(), bytes(kd))).collect())
                    .unwrap_or_default();
                let inner_f = move |id: [u8; 32]| inner.get(&id).cloned();
                let slot_keys: Vec<Vec<UaKey>> = arr(s, "slots")
                    .iter()
                    .map(|sl| match sl.get("members") {
                        Some(ms) => ms.as_array().unwrap().iter().map(|x| key_of(&wallets, &x["key"])).collect(),
                        None => vec![key_of(&wallets, &sl["key"])],
                    })
                    .collect();
                let slots: Vec<Slot> = arr(s, "slots")
                    .iter()
                    .zip(&slot_keys)
                    .map(|(sl, ks)| match sl.get("members") {
                        Some(ms) => Slot::Msig {
                            index: num(&sl["index"]) as u16,
                            members: ms.as_array().unwrap().iter().zip(ks).map(|(x, k)| (num(&x["index"]) as u16, k as &dyn Signer)).collect(),
                        },
                        None => Slot::Member { index: num(&sl["index"]) as u16, key: &ks[0] },
                    })
                    .collect();
                let kd = bytes(&s["keyData"]);
                let sender = ContainerSigner::Msig { key_data: &kd, inner: &inner_f, slots: &slots };
                vectors_seal_container(&rec, purpose, &sender, num(&c["created"]), &bytes(&r["pt"]), code.as_deref(), &m, &e).unwrap()
            } else {
                let key = key_of(&wallets, &r["sender"]);
                vectors_seal_container(&rec, purpose, &ContainerSigner::Key(&key), num(&c["created"]), &bytes(&r["pt"]), code.as_deref(), &m, &e)
                    .unwrap()
            };
            assert_eq!(serde_json::from_str::<Value>(&built.to_json()).unwrap(), *c, "{}", r["id"]);
            n += 1;
        }
        assert_eq!(n, 4);
        let r = &arr(&v, "containers")[1];
        let linked = link(&v, r, None).unwrap();
        assert_eq!(linked.vectors_entropy().unwrap().to_vec(), w_entropy("twelve_words"));
        assert_eq!(linked.ua_key(0x0102, 0, 0).unwrap().ua().unwrap(), b32(&r["expect"]["sender"]["ua"]));
    }

    /// seal.json `acceptance` "link: swapped short code": `SealOpen` through `from_link`; the session's own code opens (control).
    #[test]
    fn seal_json_acceptance_link() {
        let v = load("seal.json");
        let r = arr(&v, "acceptance").iter().find(|r| r.get("link").is_some()).unwrap();
        assert!(link(&v, r, None).is_ok());
        assert_eq!(link(&v, r, r["link"]["shortCode"].as_str()).err(), Some(Error::SealOpen));
    }

    /// seal.json `replay` (link rows): `created` outside `[start, start + 600]` is `ContainerReplay`, the window's end accepted.
    #[test]
    fn seal_json_replay_link() {
        let v = load("seal.json");
        let mut n = 0;
        for r in arr(&v, "replay").iter().filter(|r| r["kind"] == "link") {
            assert_eq!(link(&v, r, None).err().map(|e| e.code()), r["error"].as_str(), "{}", r["id"]);
            n += 1;
        }
        assert_eq!(n, 3);
        // a link session opens scaas/link/v1 only
        let r = &arr(&v, "containers")[0];
        assert_eq!(link(&v, r, None).err(), Some(Error::Argument));
    }

    /// The session's ephemeral key is wiped when `from_link` returns (installed or refused): a probe of its store is revoked.
    #[test]
    fn link_session_key_wiped_after_install() {
        let v = load("seal.json");
        let r = &arr(&v, "containers")[1];
        let s = session(&v, None);
        let probe = s.vectors_key();
        let c = container(&r["container"]).unwrap();
        let (ct, eph) = (c.sealed.mlkem_ct.clone(), c.sealed.x25519_eph);
        assert!(probe.decaps(&ct, &eph).is_ok()); // control
        let e = Expect::of(&r["expect"]);
        let none = |_: [u8; 32]| None;
        Wallet::from_link(s, &c, &e.get(), &none, None, "").unwrap();
        assert_eq!(probe.decaps(&ct, &eph).err(), Some(Error::KeyRevoked));
        let s = session(&v, Some("00000000"));
        let probe = s.vectors_key();
        assert_eq!(Wallet::from_link(s, &c, &e.get(), &none, None, "").err(), Some(Error::SealOpen));
        assert_eq!(probe.decaps(&ct, &eph).err(), Some(Error::KeyRevoked));
    }
}
