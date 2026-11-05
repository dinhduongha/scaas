// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T3d: the `UASig` builder over `&dyn Signer` handles and the `msig` member sets (spec §5.2, §9.4; CTR-UA-07 minimal form,
//! CTR-UA-17 key data, CTR-UA-33 member slots, CTR-UA-37 acceptance), against smartcontracts/vectors/ua/{sign,portable,nested,
//! pq_signatures}.json (written by clientkeys). Every set the builder returns is checked by the off-chain verifier of `ua8.rs`
//! (the registry's rule); byte-equal where every leaf signs deterministically (ML-DSA through the `vectors` hook, rnd = 0, as the
//! JS `extraEntropy: false`). T4: a native (`evm-eoa`) member signs typed data (the record's typed data in the portable purposes,
//! `UAAuth` under the registry's domain elsewhere; R17: a native `UASig` is `{"", signature, []}`); the vector files' native member is
//! the fixed key of typed_ops.json (no wallet key), signed here through a test `Signer` (the phase-2 external-key path). Rows with a
//! member that is no key here (the fixed-seed classical keys of signatures.json) are counted apart. UNAUDITED.
use scaas_ua::ua8::{
    check_authorization, check_kem_record_with, check_membership_with, check_pqz_key_record_with, check_registration_with,
    decode_member_sigs, encode_member_sigs, membership_digest, pop_v2_tag, InnerSig, KemKey, MemberSig, MsigStructure, UAAttrs, UASig,
};
use scaas_ua::verify::{native_ecdsa, verify};
use scaas_ua::wallet::{membership_sig, msig_sig, ua_sig, Error, KeyRef, Network, SignRequest, Signer, Slot, TypedData, UaKey, Wallet};
use scaas_ua::{derive_ua, keccak256, purpose_tag, ua_auth_digest, ua_message, Domain, UAError};
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};

fn load(path: &str) -> Value {
    let path = format!("{}/../../smartcontracts/vectors/ua/{path}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array().unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}
fn u16_of(v: &Value) -> u16 {
    v.as_u64().unwrap() as u16
}
fn wallet() -> Wallet {
    let k = load("keys.json");
    let m = arr(&k, "mnemonics").iter().find(|m| m["id"] == "pq_kat").unwrap();
    Wallet::from_mnemonic(m["words"].as_str().unwrap(), m["passphrase"].as_str().unwrap()).unwrap()
}
const POP: Pop = Pop;
struct Pop;
impl PartialEq<Pop> for Result<UASig, Error> {
    fn eq(&self, _: &Pop) -> bool {
        matches!(self, Err(Error::Ua(UAError::Pop)))
    }
}

/// A record: `(kind, key data)`.
type Record = (u16, Vec<u8>);

/// The vector wallet's keys the msig rows use: p256, ed25519, secp256k1 (accounts 0, 1, indices 0-2), bls12381-minsig (accounts
/// 0, 1), mldsa65 and fndsa512 (account 0, indices 0-2).
struct Keys(Vec<UaKey>, Native);
impl Keys {
    fn new(w: &Wallet) -> Keys {
        let mut keys = vec![];
        for (kinds, accounts, indices) in
            [(&[0x0101u16, 0x0102, 0x0108][..], 0..2, 0..3), (&[0x0106][..], 0..2, 0..1), (&[0x0131, 0x0132][..], 0..1, 0..3)]
        {
            for &kind in kinds {
                for a in accounts.clone() {
                    for i in indices.clone() {
                        keys.push(w.ua_key(kind, a, i).unwrap());
                    }
                }
            }
        }
        Keys(keys, Native::fixed())
    }
    fn get(&self, id: &[u8; 32]) -> Option<S<'_>> {
        if *id == self.1.id() {
            return Some(S::Native(&self.1));
        }
        self.0.iter().find(|k| k.ua() == Some(*id)).map(S::Ua)
    }
    /// `id` → `(kind, key data)` of every wallet key and every `msig` in `records`, the verifier's lookup.
    fn members(&self, records: &[(u16, Vec<u8>)]) -> impl Fn([u8; 32]) -> Option<(u16, Vec<u8>)> + '_ {
        let mut all: Vec<([u8; 32], Record)> = self.0.iter().map(|k| (k.ua().unwrap(), (k.kind(), k.key_data()))).collect();
        all.extend(records.iter().map(|(k, d)| (derive_ua(*k, d, false).unwrap(), (*k, d.clone()))));
        move |id| all.iter().find(|(x, _)| *x == id).map(|(_, r)| r.clone())
    }
}

/// The vector files' native member: the fixed secp256k1 key of typed_ops.json (structures.json context A), an EVM key outside the
/// wallet, as a phase-2 external key: it signs the typed data a `SignRequest::Eip712` carries (RFC 6979, low-s, `r ‖ s ‖ v`).
struct Native(k256::ecdsa::SigningKey);
impl Native {
    fn fixed() -> Native {
        let t = serde_json::from_str::<Value>(
            &std::fs::read_to_string(format!("{}/../../smartcontracts/vectors/typed/typed_ops.json", env!("CARGO_MANIFEST_DIR"))).unwrap(),
        )
        .unwrap();
        Native(k256::ecdsa::SigningKey::from_slice(&bytes(&t["key"]["private"])).unwrap())
    }
    fn address(&self) -> [u8; 20] {
        let p = self.0.verifying_key().to_sec1_point(false);
        keccak256(&p.as_bytes()[1..])[12..].try_into().unwrap()
    }
    fn id(&self) -> [u8; 32] {
        let mut id = [0; 32];
        id[12..].copy_from_slice(&self.address());
        id
    }
}
impl Signer for Native {
    fn key_ref(&self) -> KeyRef {
        let public_key = self.0.verifying_key().to_sec1_point(true).as_bytes().to_vec();
        KeyRef::Native { network: Network::Evm, coin_type: None, address: Some(format!("0x{}", hex::encode(self.address()))), public_key }
    }
    fn sign_request(&self, req: &SignRequest) -> scaas_ua::wallet::Result<Vec<u8>> {
        let SignRequest::Eip712 { domain_separator, struct_hash, typed_data, .. } = req else { return Err(Error::Argument) };
        let d = keccak256(&[&[0x19, 0x01][..], domain_separator, struct_hash].concat());
        assert_eq!(typed_data.digest().unwrap(), d, "the typed data shown is the one signed");
        let (sig, rec) = self.0.sign_prehash_recoverable(&d);
        Ok([&sig.to_bytes()[..], &[27 + rec.to_byte()]].concat())
    }
}

/// A key as the builder sees it: a wallet key (with feature `vectors` ML-DSA signs with rnd = 0, the JS rows' deterministic form)
/// or the native member.
enum S<'a> {
    Ua(&'a UaKey),
    Native(&'a Native),
}
impl S<'_> {
    fn kind(&self) -> u16 {
        match self {
            S::Ua(k) => k.kind(),
            S::Native(_) => 0x0001,
        }
    }
}
impl Signer for S<'_> {
    fn key_ref(&self) -> KeyRef {
        match self {
            S::Ua(k) => k.key_ref(),
            S::Native(n) => n.key_ref(),
        }
    }
    fn sign_request(&self, req: &SignRequest) -> scaas_ua::wallet::Result<Vec<u8>> {
        let k = match self {
            S::Native(n) => return n.sign_request(req),
            S::Ua(k) => k,
        };
        #[cfg(feature = "vectors")]
        if let (SignRequest::UaMsg { ua_msg, .. }, 0x0130 | 0x0131 | 0x0134) = (req, k.kind()) {
            return k.vectors_sign_ua_msg(ua_msg, &[0; 32]);
        }
        k.sign_request(req)
    }
}
/// Every signature of a key of this kind is one byte string in this build (native: RFC 6979).
fn exact(kind: u16) -> bool {
    matches!(kind, 0x0001 | 0x0101 | 0x0102 | 0x0106 | 0x0108) || (cfg!(feature = "vectors") && matches!(kind, 0x0130 | 0x0131 | 0x0134))
}
/// structures.json context A, generation 1: the registry domain of the vector files' `UAAuth` rows.
fn context_a() -> Domain {
    let s = serde_json::from_str::<Value>(
        &std::fs::read_to_string(format!("{}/../../smartcontracts/vectors/ua/structures.json", env!("CARGO_MANIFEST_DIR"))).unwrap(),
    )
    .unwrap();
    let a = &s["contexts"]["A"];
    Domain { generation: 1, chain_id: a["chainId"].as_u64().unwrap(), registry: bytes(&a["registry"]).try_into().unwrap(),
        chain_uid: b32(&a["chainUid"]) }
}
fn typed(v: &Value) -> TypedData {
    TypedData::from_json(&serde_json::to_vec(v).unwrap()).unwrap()
}

/// A set's shape: per slot its index and, for an `msig` member, its leaves' indices.
type Shape = Vec<(u16, Option<Vec<u16>>)>;
fn shape_of(sigs: &[MemberSig]) -> Shape {
    sigs.iter().map(|s| (s.index, (!s.members.is_empty()).then(|| s.members.iter().map(|x| x.index).collect()))).collect()
}
fn sigs_of(v: &Value) -> Vec<MemberSig> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| MemberSig {
            index: u16_of(&s["index"]),
            members: arr(s, "members").iter().map(|x| InnerSig { index: u16_of(&x["index"]), sig: bytes(&x["sig"]) }).collect(),
            sig: bytes(&s["sig"]),
        })
        .collect()
}
fn inner_of(records: &[(u16, Vec<u8>)]) -> impl Fn([u8; 32]) -> Option<Vec<u8>> + '_ {
    |id| records.iter().find(|(k, d)| *k == 0x0120 && derive_ua(0x0120, d, false).ok() == Some(id)).map(|(_, d)| d.clone())
}
/// The signers of `shape` (a level-1 member, or an `msig` slot's leaves), `None` when one is not a wallet key.
fn resolve<'k>(keys: &'k Keys, kd: &[u8], inner: &dyn Fn([u8; 32]) -> Option<Vec<u8>>, shape: &Shape) -> Option<Vec<Vec<S<'k>>>> {
    let ms = MsigStructure::from_key_data(kd).unwrap().members;
    shape
        .iter()
        .map(|(i, list)| {
            let m = ms.get(*i as usize)?;
            match list {
                None => Some(vec![keys.get(&m.id)?]),
                Some(l) => {
                    let ims = MsigStructure::from_key_data(&inner(m.id)?).ok()?.members;
                    l.iter().map(|j| keys.get(&ims.get(*j as usize)?.id)).collect()
                }
            }
        })
        .collect()
}
fn slots<'a>(shape: &Shape, signers: &'a [Vec<S<'_>>]) -> Vec<Slot<'a>> {
    shape
        .iter()
        .zip(signers)
        .map(|((i, list), ss)| match list {
            None => Slot::Member { index: *i, key: &ss[0] },
            Some(l) => Slot::Msig { index: *i, members: l.iter().zip(ss).map(|(j, s)| (*j, s as &dyn Signer)).collect() },
        })
        .collect()
}
fn all_exact(signers: &[Vec<S<'_>>]) -> bool {
    signers.iter().flatten().all(|s| exact(s.kind()))
}
/// Every slot index strictly increasing, at both levels.
fn sorted(m: &[MemberSig]) -> bool {
    m.windows(2).all(|w| w[0].index < w[1].index) && m.iter().all(|s| s.members.windows(2).all(|w| w[0].index < w[1].index))
}
/// A signer that counts its signatures.
struct Count<'a>(&'a dyn Signer, AtomicUsize);
impl Signer for Count<'_> {
    fn key_ref(&self) -> KeyRef {
        self.0.key_ref()
    }
    fn sign_request(&self, req: &SignRequest) -> scaas_ua::wallet::Result<Vec<u8>> {
        self.1.fetch_add(1, Ordering::SeqCst);
        self.0.sign_request(req)
    }
}
fn all_accepted(_: [u8; 32], _: u16) -> bool {
    true
}

/// `sign.json` `msig` rows (clientkeys `msigMemberSigs`): the minimal sets byte-equal (every member deterministic), the
/// non-minimal (level 1, level 2), unsorted and below-threshold sets refused `UAPoP`; the result is `UASig{"", "", members}`.
#[test]
fn sign_json_msig_rows() {
    let s = load("sign.json");
    let w = wallet();
    let keys = Keys::new(&w);
    let (mut built, mut refused) = (0, 0);
    for r in arr(&s, "msig") {
        let kd = bytes(&r["keyData"]);
        assert_eq!(derive_ua(0x0120, &kd, false).unwrap(), b32(&r["ua"]));
        let inner_map: Vec<(u16, Vec<u8>)> =
            r["inner"].as_object().map_or(vec![], |o| o.values().map(|d| (0x0120, bytes(d))).collect());
        let inner = inner_of(&inner_map);
        let shape: Shape = arr(r, "slots")
            .iter()
            .map(|s| (u16_of(&s["index"]), s["members"].as_array().map(|l| l.iter().map(|x| u16_of(&x["index"])).collect())))
            .collect();
        let signers = resolve(&keys, &kd, &inner, &shape).expect("every sign.json member is a vector wallet key");
        let got = msig_sig(&kd, &inner, &b32(&r["purposeTag"]), &b32(&r["digest"]), None, None, &slots(&shape, &signers));
        if r["refused"].is_string() {
            assert_eq!(r["refused"], "UAPoP");
            assert!(got == POP, "{}: {got:?}", r["case"]);
            refused += 1;
        } else {
            let got = got.unwrap();
            assert!(got.key_data.is_empty() && got.signature.is_empty(), "{}", r["case"]);
            assert!(all_exact(&signers));
            assert_eq!(hex::encode(encode_member_sigs(&got.members)), hex::encode(bytes(&r["memberSigs"])), "{}", r["case"]);
            built += 1;
        }
    }
    assert_eq!((built, refused), (3, 4));
}

/// The nested row of `sign.json` with its inner list made non-minimal (three of t = 2, the vector's row) and two variants: an inner
/// list below the inner threshold and an `msig` slot with no list. Each is `UAPoP`, and nothing is signed for it.
#[test]
fn non_minimal_set_refused_at_level_2() {
    let s = load("sign.json");
    let w = wallet();
    let keys = Keys::new(&w);
    let r = arr(&s, "msig").iter().find(|r| r["case"] == "nested minimal: inner {two of three} + bls12381").unwrap();
    let kd = bytes(&r["keyData"]);
    let inner_map: Vec<(u16, Vec<u8>)> = r["inner"].as_object().unwrap().values().map(|d| (0x0120, bytes(d))).collect();
    let inner = inner_of(&inner_map);
    let (purpose, digest) = (b32(&r["purposeTag"]), b32(&r["digest"]));
    let run = |shape: Shape| {
        let signers = resolve(&keys, &kd, &inner, &shape).unwrap();
        msig_sig(&kd, &inner, &purpose, &digest, None, None, &slots(&shape, &signers))
    };
    let msig_at = MsigStructure::from_key_data(&kd).unwrap().members.iter().position(|m| m.kind == 0x0120).unwrap() as u16;
    let other = 1 - msig_at;
    let with = |inner_list: Vec<u16>| {
        let mut sh: Shape = vec![(msig_at, Some(inner_list)), (other, None)];
        sh.sort_by_key(|(i, _)| *i);
        sh
    };
    assert!(run(with(vec![0, 1])).is_ok(), "positive control");
    assert!(run(with(vec![0, 1, 2])) == POP, "inner three of t = 2");
    assert!(run(with(vec![0])) == POP, "inner one of t = 2");
    assert!(run(with(vec![])) == POP, "an msig slot with no list");
    // level 1 too: the outer pair is minimal only as a pair
    assert!(run(vec![(other, None)]) == POP, "outer one of t = 2");
}

/// Slots are taken in the caller's order and must be strictly increasing at both levels (the registry's form, CTR-UA-07):
/// an unsorted set is refused `UAPoP` (never sorted silently), at level 1 and level 2; every set returned is sorted.
#[test]
fn slots_sorted() {
    let s = load("sign.json");
    let w = wallet();
    let keys = Keys::new(&w);
    let r = arr(&s, "msig").iter().find(|r| r["case"] == "nested minimal: inner {two of three} + bls12381").unwrap();
    let kd = bytes(&r["keyData"]);
    let inner_map: Vec<(u16, Vec<u8>)> = r["inner"].as_object().unwrap().values().map(|d| (0x0120, bytes(d))).collect();
    let inner = inner_of(&inner_map);
    let (purpose, digest) = (b32(&r["purposeTag"]), b32(&r["digest"]));
    let run = |shape: Shape| {
        let signers = resolve(&keys, &kd, &inner, &shape).unwrap();
        msig_sig(&kd, &inner, &purpose, &digest, None, None, &slots(&shape, &signers))
    };
    let msig_at = MsigStructure::from_key_data(&kd).unwrap().members.iter().position(|m| m.kind == 0x0120).unwrap() as u16;
    let other = 1 - msig_at;
    let pair = |a: (u16, Option<Vec<u16>>), b: (u16, Option<Vec<u16>>)| if a.0 < b.0 { vec![a, b] } else { vec![b, a] };
    let ok = run(pair((msig_at, Some(vec![0, 1])), (other, None))).unwrap();
    assert!(sorted(&ok.members));
    let mut rev = pair((msig_at, Some(vec![0, 1])), (other, None));
    rev.reverse();
    assert!(run(rev) == POP, "level 1 unsorted");
    assert!(run(pair((msig_at, Some(vec![1, 0])), (other, None))) == POP, "level 2 unsorted");
    assert!(run(pair((msig_at, Some(vec![0, 0])), (other, None))) == POP, "level 2 repeated");
    // the flat vector row
    let r = arr(&s, "msig").iter().find(|r| r["case"] == "flat unsorted").unwrap();
    let kd = bytes(&r["keyData"]);
    let shape: Shape = arr(r, "slots").iter().map(|s| (u16_of(&s["index"]), None)).collect();
    let signers = resolve(&keys, &kd, &|_| None, &shape).unwrap();
    let got = msig_sig(&kd, &|_| None, &b32(&r["purposeTag"]), &b32(&r["digest"]), None, None, &slots(&shape, &signers));
    assert!(got == POP);
    let mut fixed = shape.clone();
    fixed.sort_by_key(|(i, _)| *i);
    let signers = resolve(&keys, &kd, &|_| None, &fixed).unwrap();
    let got = msig_sig(&kd, &|_| None, &b32(&r["purposeTag"]), &b32(&r["digest"]), None, None, &slots(&fixed, &signers)).unwrap();
    assert!(sorted(&got.members) && got.members.iter().map(|m| m.index).eq(fixed.iter().map(|(i, _)| *i)));
}

/// What a vector file's `msig` rows check: built through the builder from the row's own slot shape, verified by `ua8.rs` (the
/// registry's rule), byte-equal when every leaf is deterministic in this build.
struct Tally {
    exact: usize,
    verified: usize,
    skipped: usize,
}
impl Tally {
    fn add(&mut self, exact: bool, ok: bool, what: &str) {
        assert!(ok, "{what}");
        self.verified += 1;
        self.exact += exact as usize;
    }
}
fn check_rows(file: &Value, records: &[(u16, Vec<u8>)], keys: &Keys) -> Tally {
    let inner = inner_of(records);
    let everything = all_records(file);
    let members = keys.members(&everything);
    let kd_of = |ua: &[u8; 32]| records.iter().find(|(_, d)| derive_ua(0x0120, d, false).ok() == Some(*ua)).map(|(_, d)| d.clone());
    let mut t = Tally { exact: 0, verified: 0, skipped: 0 };
    let mut rows: Vec<(&Value, &str)> = vec![];
    for table in ["registrations", "afterAcceptance", "kemRecords", "pqzKeyRecords", "authorizations"] {
        rows.extend(file[table].as_array().map_or(&[][..], |a| a.as_slice()).iter().map(|r| (r, table)));
    }
    for (r, table) in rows {
        let name = format!("{table} {}", r["name"]);
        let ua = b32(&r["ua"]);
        let Some(kd) = kd_of(&ua) else { continue }; // a single-key row
        let (purpose, digest, expected) = match table {
            "registrations" | "afterAcceptance" => {
                let pop = bytes(&r["pop"]);
                if pop.is_empty() {
                    continue; // a classical-dominant msig signs no pop
                }
                (pop_v2_tag(), b32(&r["registrationDigest"]), decode_member_sigs(&pop).unwrap())
            }
            "kemRecords" => (purpose_tag("kem").unwrap(), b32(&r["digest"]), sigs_of(&r["args"]["sig"]["members"])),
            "pqzKeyRecords" => (purpose_tag("pqz-key").unwrap(), b32(&r["recordDigest"]), sigs_of(&r["args"]["sig"]["members"])),
            _ => (b32(&r["purposeTag"]), b32(&r["digest"]), sigs_of(&r["uaSig"]["members"])),
        };
        let shape = shape_of(&expected);
        let Some(signers) = resolve(keys, &kd, &inner, &shape) else {
            eprintln!("skipped (a member is no key here, or a form a Slot cannot express): {name}");
            t.skipped += 1;
            continue;
        };
        // a native leaf: the record's typed data (portable purposes), `UAAuth` in context A (authorizations)
        let record = (table != "authorizations").then(|| typed(&r["typedData"]));
        let domain = context_a();
        let got = msig_sig(&kd, &inner, &purpose, &digest, Some(&domain), record.as_ref(), &slots(&shape, &signers));
        if table == "authorizations" && r["valid"] == false {
            // a set below a threshold is refused; the forms a `Slot` cannot express (a signature on an msig slot, a list on a
            // signing slot) and a content defect of a valid shape (one-level-short: the inner leaves over the outer digest) are
            // built in their valid form
            if r["name"] == "inner-below-threshold" {
                assert!(got == POP, "{name}");
                t.verified += 1;
            }
            continue;
        }
        let got = got.unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(got.key_data.is_empty() && got.signature.is_empty() && shape_of(&got.members) == shape, "{name}");
        let blob = encode_member_sigs(&got.members);
        let exact = all_exact(&signers);
        if exact {
            assert_eq!(hex::encode(&blob), hex::encode(encode_member_sigs(&expected)), "{name}");
        }
        let acc: Option<&dyn Fn([u8; 32], u16) -> bool> = Some(&all_accepted);
        let ok = match table {
            "registrations" | "afterAcceptance" => {
                let attrs = UAAttrs {
                    pqz_key: bytes(&r["attrs"]["pqzKey"]),
                    pqz_pop_hash: b32(&r["attrs"]["pqzPopHash"]),
                    kem: KemKey::from_kem_pk(&bytes(&r["attrs"]["kemPk"])).unwrap(),
                    kem_pk_hash: [0; 32],
                };
                check_registration_with(0x0120, &kd, &attrs, &blob, &[], &members, acc)
            }
            "kemRecords" => {
                check_kem_record_with(0x0120, &kd, &ua, r["version"].as_u64().unwrap(), &bytes(&r["kemPk"]), &blob, &members, acc)
            }
            "pqzKeyRecords" => {
                check_pqz_key_record_with(0x0120, &kd, &ua, &bytes(&r["pqzKey"]), &b32(&r["pqzPopHash"]), &blob, &members, acc)
            }
            _ => check_authorization(&kd, &ua, &purpose, &digest, &got.members, &domain, &members, acc),
        };
        t.add(exact, ok.is_ok(), &format!("{name}: {ok:?}"));
    }
    for r in file["memberships"].as_array().unwrap() {
        let name = format!("memberships {}", r["name"]);
        let ua = b32(&r["ua"]);
        let kd = kd_of(&ua).unwrap();
        let index = u16_of(&r["index"]);
        assert_eq!(membership_digest(&ua, &b32(&r["member"])), b32(&r["digest"]), "{name}");
        let expected = MemberSig {
            index,
            members: r["members"].as_array().map_or(vec![], |_| sigs_of(&Value::Array(vec![r.clone()]))[0].members.clone()),
            sig: bytes(&r["sig"]),
        };
        let shape = shape_of(std::slice::from_ref(&expected));
        let Some(signers) = resolve(keys, &kd, &inner, &shape) else {
            eprintln!("skipped (a member is no key here): {name}");
            t.skipped += 1;
            continue;
        };
        let slot = slots(&shape, &signers).remove(0);
        let got = membership_sig(&kd, &inner, &slot).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(shape_of(std::slice::from_ref(&got)), shape, "{name}");
        let exact = all_exact(&signers);
        if exact {
            assert_eq!(hex::encode(encode_one(&got)), hex::encode(encode_one(&expected)), "{name}");
        }
        let ok = check_membership_with(&kd, &ua, &got, &members, Some(&all_accepted));
        t.add(exact, ok.is_ok(), &format!("{name}: {ok:?}"));
    }
    t
}
fn encode_one(m: &MemberSig) -> Vec<u8> {
    encode_member_sigs(std::slice::from_ref(m))
}
fn msig_records(file: &Value) -> Vec<(u16, Vec<u8>)> {
    all_records(file).into_iter().filter(|(k, _)| *k == 0x0120).collect()
}
/// Every record a vector file registers (its fixed-seed classical members too: the verifier reads every member's key).
fn all_records(file: &Value) -> Vec<(u16, Vec<u8>)> {
    ["registrations", "afterAcceptance"]
        .iter()
        .flat_map(|t| file[*t].as_array().map_or(&[][..], |a| a.as_slice()))
        .map(|r| (r["kind"].as_u64().unwrap() as u16, bytes(&r["keyData"])))
        .filter(|(k, d)| derive_ua(*k, d, false).is_ok())
        .collect()
}

/// `portable.json`: `msig-pq` (two mldsa65 members) at every parameter set and `msig-pq-native` (native + mldsa65, T4: the native
/// member over the record's typed data), the KEM records v1-v3, the PQZ key records of `msig-pq-native` at every set, and the
/// acceptances of `msig-pq-native`'s two members and of `msig-classical`'s native member: 15, byte for byte with feature `vectors`
/// (the native leaf is RFC 6979 in every build). Skipped: the acceptances of `msig-classical`'s fixed-seed classical members
/// (signatures.json's keys, no key here): 3.
#[test]
fn portable_json_msig_rows() {
    let p = load("portable.json");
    let w = wallet();
    let keys = Keys::new(&w);
    let t = check_rows(&p, &msig_records(&p), &keys);
    assert_eq!((t.verified, t.skipped), (15, 3), "registrations 5, kemRecords 3, pqzKeyRecords 4, memberships 3");
    assert_eq!(t.exact, if cfg!(feature = "vectors") { 15 } else { PORTABLE_EXACT_DEFAULT });
}
/// The rows whose every leaf is deterministic in a default build (ML-DSA hedged): the native acceptances.
const PORTABLE_EXACT_DEFAULT: usize = 2;

/// `nested.json`: the registrations, KEM / PQZ key records, authorizations and acceptances whose leaves are vector wallet keys
/// (fndsa512 #0-#2: verified, Falcon is randomized; an inner `msig` slot by its own minimal list over `innerDigest`).
#[test]
fn nested_json_msig_rows() {
    let n = load("nested.json");
    let w = wallet();
    let keys = Keys::new(&w);
    let records = msig_records(&n);
    let t = check_rows(&n, &records, &keys);
    // registrations msig-inner-pq, -inner-native, -inner-native-2, -inner-heavy, -nested-pq, -nested-native, -nested-twice,
    // -nested-heavy-inner, -nested-heavy-outer; kemRecords msig-nested-pq; pqzKeyRecords msig-nested-native at every set; the
    // authorization two-levels (a native leaf over UAAuth in context A); memberships msig-nested-classical/0. Skipped (a fixed-seed
    // classical member, or the list-on-signing-slot form a `Slot` cannot express): afterAcceptance msig-nested-after-acceptance,
    // authorizations list-on-signing-slot, memberships msig-inner-classical/0, /1, msig-nested-classical/1.
    assert_eq!((t.verified, t.exact, t.skipped), (17, 0, 5));
    // every slot's acceptance the wallet can sign (the file's rows are mostly native or fixed-seed classical): a signing slot, and an
    // `msig` slot by the first minimal subset of its own members (bit order), verified by `check_membership_with`
    let inner = inner_of(&records);
    let members = keys.members(&records);
    let (mut signing, mut nested) = (0, 0);
    for (_, kd) in &records {
        let ua = derive_ua(0x0120, kd, false).unwrap();
        for (i, m) in MsigStructure::from_key_data(kd).unwrap().members.iter().enumerate() {
            let list = (m.kind == 0x0120).then(|| {
                let d = inner(m.id).unwrap();
                let n = MsigStructure::from_key_data(&d).unwrap().members.len() as u16;
                (1u32..1 << n)
                    .map(|bits| (0..n).filter(|j| bits >> j & 1 == 1).collect::<Vec<u16>>())
                    .find(|l| scaas_ua::ua8::msig_slots_minimal(&d, l).unwrap())
                    .unwrap()
            });
            let shape: Shape = vec![(i as u16, list)];
            let Some(signers) = resolve(&keys, kd, &inner, &shape) else { continue };
            let slot = slots(&shape, &signers).remove(0);
            let got = membership_sig(kd, &inner, &slot).unwrap();
            assert_eq!(check_membership_with(kd, &ua, &got, &members, Some(&all_accepted)), Ok(()), "{i}");
            if m.kind == 0x0120 { nested += 1 } else { signing += 1 }
        }
    }
    assert_eq!((signing, nested), (NESTED_SIGNING, NESTED_MSIG));
}
// T3d: 12 and 3; T4 adds the native member's slots (it signs `UAMembership` itself) and the `msig` slots whose first minimal subset
// holds it: 14 and 6
const NESTED_SIGNING: usize = 14;
const NESTED_MSIG: usize = 6;

/// `pq_signatures.json` `msig.treasury` (three mldsa65 members, t = 2, purpose metatx): both minimal pairs byte-equal (feature
/// `vectors`) or verified; the set below the threshold refused.
#[test]
fn pq_signatures_json_treasury() {
    let p = load("pq_signatures.json");
    let w = wallet();
    let keys = Keys::new(&w);
    let t = &p["msig"]["treasury"];
    let kd = bytes(&t["keyData"]);
    let ua = derive_ua(0x0120, &kd, false).unwrap();
    assert_eq!(ua, b32(&t["ua"]));
    let (purpose, digest) = (purpose_tag(t["purpose"].as_str().unwrap()).unwrap(), b32(&t["digest"]));
    let members = keys.members(&[]);
    for set in arr(t, "sets") {
        let shape: Shape = arr(set, "indices").iter().map(|i| (u16_of(i), None)).collect();
        let signers = resolve(&keys, &kd, &|_| None, &shape).unwrap();
        let got = msig_sig(&kd, &|_| None, &purpose, &digest, None, None, &slots(&shape, &signers));
        if set["valid"] == false {
            assert!(got == POP, "{}", set["name"]);
            continue;
        }
        let got = got.unwrap();
        if cfg!(feature = "vectors") {
            assert_eq!(hex::encode(encode_member_sigs(&got.members)), hex::encode(encode_member_sigs(&sigs_of(&set["memberSigs"]))));
        }
        let domain = Domain { generation: 1, chain_id: 0, registry: [0; 20], chain_uid: [0; 32] };
        assert_eq!(check_authorization(&kd, &ua, &purpose, &digest, &got.members, &domain, &members, Some(&all_accepted)), Ok(()));
    }
}

/// A single key's `UASig` (CTR-UA-17, TS-D12): its signature over `uaMessage(kind, purpose, digest)` with the purpose's role,
/// no members; `keyData` its key data, empty for a stored kind (the PQ kinds) and for the purposes whose `UASig` carries none
/// (`member`; the portable `pop` v2, `kem`, `pqz-key`, `membership`).
#[test]
fn single_key_uasig_forms() {
    let w = wallet();
    let digest = [7u8; 32];
    let metatx = purpose_tag("metatx").unwrap();
    for (kind, purpose, carries) in [
        (0x0101, metatx, true),
        (0x0108, metatx, true),
        (0x0106, metatx, true),
        (0x0101, pop_v2_tag(), false),
        (0x0101, purpose_tag("kem").unwrap(), false),
        (0x0101, purpose_tag("pqz-key").unwrap(), false),
        (0x0101, purpose_tag("member").unwrap(), false),
        (0x0131, metatx, false),
        (0x0131, pop_v2_tag(), false),
    ] {
        let key = w.ua_key(kind, 0, 0).unwrap();
        let sig = ua_sig(&key, None, &purpose, &digest).unwrap();
        assert_eq!(sig.key_data.is_empty(), !carries, "{kind:#06x}");
        if carries {
            assert_eq!(sig.key_data, key.key_data());
        }
        assert!(sig.members.is_empty());
        let pop = purpose == pop_v2_tag() || [purpose_tag("kem").unwrap(), purpose_tag("pqz-key").unwrap()].contains(&purpose);
        assert!(verify(kind, &key.key_data(), &ua_message(kind, &purpose, &digest).unwrap(), &sig.signature, pop), "{kind:#06x}");
    }
    let key = w.ua_key(0x0101, 0, 0).unwrap();
    assert_eq!(ua_sig(&key, None, &[9; 32], &digest).err(), Some(Error::Ua(UAError::PurposeUnknown)));
}

/// R17: a native key's `UASig` is `{"", signature, []}`, its signature over `UAAuth(id, purpose, digest)` under the registry's domain
/// (`requireAuthorized`, CTR-UA-24); with no domain, a portable purpose (a native id has no portable record of its own), an unknown
/// purpose, or a key of an ed25519 network: refused.
#[test]
fn native_ua_sig_r17() {
    let w = wallet();
    let native = w.native_key(Network::Evm, 0, None).unwrap();
    let address: [u8; 20] = hex::decode(native.address().unwrap().trim_start_matches("0x")).unwrap().try_into().unwrap();
    let mut id = [0; 32];
    id[12..].copy_from_slice(&address);
    let (domain, metatx, digest) = (context_a(), purpose_tag("metatx").unwrap(), [1; 32]);
    let sig = ua_sig(&native, Some(&domain), &metatx, &digest).unwrap();
    assert!(sig.key_data.is_empty() && sig.members.is_empty());
    assert!(native_ecdsa(&address, &ua_auth_digest(&domain, &id, &metatx, &digest), &sig.signature));
    // another domain is another digest
    let other = Domain { generation: 2, ..context_a() };
    assert!(!native_ecdsa(&address, &ua_auth_digest(&other, &id, &metatx, &digest), &sig.signature));
    assert_eq!(ua_sig(&native, None, &metatx, &digest).err(), Some(Error::Argument));
    assert_eq!(ua_sig(&native, Some(&domain), &pop_v2_tag(), &digest).err(), Some(Error::Argument));
    assert_eq!(ua_sig(&native, Some(&domain), &purpose_tag("membership").unwrap(), &digest).err(), Some(Error::Argument));
    assert_eq!(ua_sig(&native, Some(&domain), &[9; 32], &digest).err(), Some(Error::Ua(UAError::PurposeUnknown)));
    let sol = w.native_key(Network::Solana, 0, None).unwrap();
    assert_eq!(ua_sig(&sol, Some(&domain), &metatx, &digest).err(), Some(Error::Argument));
}

/// A native slot needs what its purpose signs: the record's typed data, whose digest is the one signed and whose domain is the
/// portable one, in the portable purposes; the registry's domain elsewhere. Missing or another record: `Argument`, nothing signed.
#[test]
fn native_slot_needs_its_typed_data() {
    let p = serde_json::from_str::<Value>(
        &std::fs::read_to_string(format!("{}/../../smartcontracts/vectors/ua/nested.json", env!("CARGO_MANIFEST_DIR"))).unwrap(),
    )
    .unwrap();
    let w = wallet();
    let keys = Keys::new(&w);
    let records = msig_records(&p);
    let inner = inner_of(&records);
    let r = arr(&p, "authorizations").iter().find(|r| r["name"] == "two-levels").unwrap();
    let ua = b32(&r["ua"]);
    let kd = records.iter().find(|(_, d)| derive_ua(0x0120, d, false).unwrap() == ua).unwrap().1.clone();
    let expected = sigs_of(&r["uaSig"]["members"]);
    let shape = shape_of(&expected);
    let signers = resolve(&keys, &kd, &inner, &shape).expect("the native leaf and the wallet keys");
    let (purpose, digest) = (b32(&r["purposeTag"]), b32(&r["digest"]));
    let domain = context_a();
    let got = msig_sig(&kd, &inner, &purpose, &digest, Some(&domain), None, &slots(&shape, &signers)).unwrap();
    let members = keys.members(&all_records(&p));
    assert_eq!(check_authorization(&kd, &ua, &purpose, &digest, &got.members, &domain, &members, Some(&all_accepted)), Ok(()), "positive control");
    // the native leaf (RFC 6979) byte for byte; the Falcon leaf is randomized
    let leaf = |m: &[MemberSig]| m.iter().flat_map(|s| s.members.iter().map(|x| x.sig.clone())).find(|sig| sig.len() == 65).unwrap();
    assert_eq!(hex::encode(leaf(&got.members)), hex::encode(leaf(&expected)));
    assert_eq!(msig_sig(&kd, &inner, &purpose, &digest, None, None, &slots(&shape, &signers)).err(), Some(Error::Argument));
    // a portable purpose: the record is required and must be the digest's
    let reg = arr(&p, "registrations").iter().find(|x| x["ua"] == r["ua"]).unwrap();
    let (rd, record) = (b32(&reg["registrationDigest"]), typed(&reg["typedData"]));
    let pop = decode_member_sigs(&bytes(&reg["pop"])).unwrap();
    let pshape = shape_of(&pop);
    let psigners = resolve(&keys, &kd, &inner, &pshape).unwrap();
    assert!(msig_sig(&kd, &inner, &pop_v2_tag(), &rd, None, Some(&record), &slots(&pshape, &psigners)).is_ok(), "positive control");
    assert_eq!(msig_sig(&kd, &inner, &pop_v2_tag(), &rd, Some(&domain), None, &slots(&pshape, &psigners)).err(), Some(Error::Argument));
    let other = typed(&arr(&p, "registrations").iter().find(|x| x["ua"] != r["ua"]).unwrap()["typedData"]);
    assert_eq!(msig_sig(&kd, &inner, &pop_v2_tag(), &rd, None, Some(&other), &slots(&pshape, &psigners)).err(), Some(Error::Argument));
}

/// A slot's key must be that slot's member (its kind and its id), a signing slot must name a derived member and an `msig` slot an
/// `msig` member whose key data `inner` gives (`MemberUnknown` otherwise); the purpose must be known; nothing is signed for a
/// refused set.
#[test]
fn slot_must_match_its_member() {
    let s = load("sign.json");
    let w = wallet();
    let keys = Keys::new(&w);
    let r = arr(&s, "msig").iter().find(|r| r["case"] == "nested minimal: inner {two of three} + bls12381").unwrap();
    let kd = bytes(&r["keyData"]);
    let inner_map: Vec<(u16, Vec<u8>)> = r["inner"].as_object().unwrap().values().map(|d| (0x0120, bytes(d))).collect();
    let inner = inner_of(&inner_map);
    let (purpose, digest) = (b32(&r["purposeTag"]), b32(&r["digest"]));
    let ms = MsigStructure::from_key_data(&kd).unwrap().members;
    let msig_at = ms.iter().position(|m| m.kind == 0x0120).unwrap() as u16;
    let other = 1 - msig_at;
    let shape: Shape = {
        let mut sh = vec![(msig_at, Some(vec![0, 1])), (other, None)];
        sh.sort_by_key(|(i, _)| *i);
        sh
    };
    let signers = resolve(&keys, &kd, &inner, &shape).unwrap();
    let good = slots(&shape, &signers);
    let run = |s: &[Slot]| msig_sig(&kd, &inner, &purpose, &digest, None, None, s);
    assert!(run(&good).is_ok(), "positive control");
    let leaves = &signers[shape.iter().position(|(i, _)| *i == msig_at).unwrap()];
    let (leaf, bls) = (&leaves[0], &signers[shape.iter().position(|(i, _)| *i == other).unwrap()][0]);
    fn pair<'a>(a: Slot<'a>, b: Slot<'a>, a_first: bool) -> Vec<Slot<'a>> {
        if a_first { vec![a, b] } else { vec![b, a] }
    }
    let first = msig_at < other;
    // the inner leaves count what they sign: a refused set signs nothing (every slot is checked first; the bls slot comes after)
    let counted: Vec<Count> = leaves.iter().map(|l| Count(l, AtomicUsize::new(0))).collect();
    let signed = || counted.iter().map(|c| c.1.load(Ordering::SeqCst)).sum::<usize>();
    let inner_slot = || Slot::Msig { index: msig_at, members: vec![(0, &counted[0] as &dyn Signer), (1, &counted[1])] };
    let wrong_kind = w.ua_key(0x0102, 0, 0).unwrap(); // a key of another kind than the bls member
    let wrong_id = w.ua_key(0x0106, 1, 0).unwrap(); // the member's kind, another key
    for k in [&wrong_kind as &dyn Signer, &wrong_id] {
        assert_eq!(run(&pair(inner_slot(), Slot::Member { index: other, key: k }, first)).err(), Some(Error::Argument));
    }
    // an inner leaf signed by the outer bls key
    let bad_leaf = Slot::Msig { index: msig_at, members: vec![(0, bls as &dyn Signer), (1, &leaves[1])] };
    assert_eq!(run(&pair(bad_leaf, Slot::Member { index: other, key: bls }, first)).err(), Some(Error::Argument));
    // a signing slot on the msig member, a list on the signing member
    let on_msig = Slot::Member { index: msig_at, key: leaf };
    assert_eq!(run(&pair(on_msig, Slot::Member { index: other, key: bls }, first)).err(), Some(Error::Argument));
    let on_member = Slot::Msig { index: other, members: vec![(0, leaf as &dyn Signer), (1, &leaves[1])] };
    assert_eq!(run(&pair(inner_slot(), on_member, first)).err(), Some(Error::Argument));
    assert_eq!(signed(), 0, "a refused set signs nothing");
    assert!(run(&pair(inner_slot(), Slot::Member { index: other, key: bls }, first)).is_ok(), "positive control of the count");
    assert_eq!(signed(), 2);
    // the inner msig's key data unknown, or another msig's (`inner` is the caller's: never trusted)
    assert_eq!(msig_sig(&kd, &|_| None, &purpose, &digest, None, None, &good).err(), Some(Error::Ua(UAError::MemberUnknown)));
    let flat = bytes(&arr(&s, "msig")[0]["keyData"]);
    assert_eq!(msig_sig(&kd, &|_| Some(flat.clone()), &purpose, &digest, None, None, &good).err(), Some(Error::Ua(UAError::MemberUnknown)));
    // the purpose unknown
    assert_eq!(msig_sig(&kd, &inner, &[9; 32], &digest, None, None, &good).err(), Some(Error::Ua(UAError::PurposeUnknown)));
    // acceptance: the slot past the members
    assert_eq!(membership_sig(&kd, &inner, &Slot::Member { index: 9, key: bls }).err(), Some(Error::Argument));
}
