//! smartcontracts/vectors/ua/groups.json (accounts.md §1.16, UA-2c) — the generator and its byte-for-byte check, plus the
//! signers against the official vectors: BIP-327 (bitcoin/bips bip-0327/vectors, vendored in tests/data/bip327), RFC 9591
//! Appendix E.5 (tests/data/rfc9591_e5.json) and the ZF frost-secp256k1 3.0.0 DKG vector (tests/data/zf_frost_secp256k1_dkg.json).
//! Regenerate: `cargo test --features signers --test groups -- --ignored write_groups_json`.
//! Every row is deterministic: secrets are tagged hashes of the row label, randomness is ChaCha20 seeded by the label.
use frost_core::{Ciphersuite, Element, Field, Group, Scalar};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use scaas_ua::frost::{dkg, id, Bn254Keccak256, Dkg, Secp256K1Sha256};
use scaas_ua::musig2::{self as mu, Bn254, Curve, KeyAgg, Secp256k1};
use scaas_ua::*;
use serde_json::{json, Value};

const MUSIG_SECP: u16 = 0x0110;
const FROST_SECP: u16 = 0x0111;
const MUSIG_BN: u16 = 0x0112;
const FROST_BN: u16 = 0x0113;
const SECP_N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
const BN_R: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
const BIP327: [&str; 5] = ["key_sort_vectors", "key_agg_vectors", "nonce_gen_vectors", "nonce_agg_vectors", "sign_verify_vectors"];
const BIP327_COMMIT: &str = "927b6de9915c9262615a6399de51b200f81e5aa4";

fn root(rel: &str) -> String {
    format!("{}/{rel}", env!("CARGO_MANIFEST_DIR"))
}
fn read_json(rel: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(root(rel)).unwrap()).unwrap()
}
fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}
fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn rng(label: &str) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(keccak256(format!("scaas.ua.groups.v1/rng/{label}").as_bytes()))
}
fn rand32(r: &mut impl RngCore) -> [u8; 32] {
    let mut b = [0u8; 32];
    r.fill_bytes(&mut b);
    b
}
fn flip_last(b: &[u8]) -> Vec<u8> {
    let mut v = b.to_vec();
    *v.last_mut().unwrap() ^= 1;
    v
}

// ---------- context ----------

struct Ctx {
    name: &'static str,
    chain_id: u64,
    uid: [u8; 32],
    registry: [u8; 20],
}
/// Context A (the PoPs), B (the other-context negative) and the fixed digest of the `sigs` rows.
struct Env {
    a: Ctx,
    b: Ctx,
    digest: [u8; 32],
}
fn contexts() -> (Value, Env) {
    let s = read_json("../../smartcontracts/vectors/ua/signatures.json");
    let ctx = |name: &'static str| {
        let c = &s["contexts"][name];
        Ctx { name, chain_id: c["chainId"].as_u64().unwrap(), uid: unhex(&c["chainUid"]).try_into().unwrap(), registry: unhex(&c["registry"]).try_into().unwrap() }
    };
    let contexts = json!({ "A": s["contexts"]["A"], "B": s["contexts"]["B"] });
    (contexts, Env { a: ctx("A"), b: ctx("B"), digest: unhex(&s["digest"]).try_into().unwrap() })
}
/// `(ua, popDigest, ua_msg)` of key data under a context (authRef 0).
fn pop_of(kind: u16, kd: &[u8], c: &Ctx) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let ua = ua_of(kind, kd).unwrap();
    let pd = pop_digest(c.chain_id, &c.uid, &c.registry, &ua, &[0; 32]);
    (ua, pd, ua_message(kind, &purpose_tag("pop").unwrap(), &pd).unwrap())
}

/// A negative row: `entry` "register" (keyData + pop blob under context A; `error` UAKeyData = refused by key-data
/// validation, UAPoP = verifyPop false; `sigValid`: whether the blob's signature part alone verifies against the key
/// data's Q/Y over `message`, i.e. whether only the group check refuses it) or "verify" (stored vk, message, sig; false).
fn neg_register(name: &str, kind: u16, kd: &[u8], blob: &[u8], error: &str, a: &Ctx, comment: &str) -> Value {
    let (ua, pd, m) = pop_of(kind, kd, a);
    let (w, sl) = sig_layout(kind);
    let sig_valid = scaas_ua::verify::verify(kind, &kd[..w], &m, &blob[..sl.min(blob.len())], false);
    json!({ "name": name, "entry": "register", "error": error, "keyData": hx(kd), "ua": hx(&ua), "popDigest": hx(&pd),
            "message": hx(&m), "pop": hx(blob), "sigValid": sig_valid, "comment": comment })
}
/// `(vk width, signature length)` of a group kind.
fn sig_layout(kind: u16) -> (usize, usize) {
    match kind {
        MUSIG_SECP => (33, 64),
        FROST_SECP => (33, 65),
        _ => (64, 96),
    }
}
fn neg_verify(name: &str, vk: &[u8], msg: &[u8; 32], sig: &[u8], comment: &str) -> Value {
    json!({ "name": name, "entry": "verify", "error": "false", "vk": hx(vk), "message": hx(msg), "sig": hx(sig), "comment": comment })
}

// ---------- MuSig2 ----------

trait MusigKind: Curve + Sized {
    const KIND: u16;
    fn secret(label: &str, i: usize) -> Self::S;
    /// A single-key signature by `d` (BIP-340 / scaas Schnorr) — for attacker and parity negatives.
    fn single(d: &Self::S, msg: &[u8; 32]) -> Vec<u8>;
    /// `n × H_i` (musig2-secp256k1 only).
    fn hints(ka: &KeyAgg<Self>, pks: &[Vec<u8>]) -> Vec<u8>;
}
impl MusigKind for Secp256k1 {
    const KIND: u16 = MUSIG_SECP;
    fn secret(label: &str, i: usize) -> Self::S {
        Self::hash_s("scaas.ua.groups.v1/secret", &[label.as_bytes(), &(i as u32).to_be_bytes()])
    }
    fn single(d: &Self::S, msg: &[u8; 32]) -> Vec<u8> {
        k256::schnorr::SigningKey::from_bytes(&Self::s_bytes(d)).unwrap().sign_raw(msg, &[0; 32]).unwrap().to_bytes().to_vec()
    }
    fn hints(ka: &KeyAgg<Self>, pks: &[Vec<u8>]) -> Vec<u8> {
        pks.iter().flat_map(|pk| uncompressed(&(Self::parse(pk).unwrap() * ka.coef(pk)))).collect()
    }
}
impl MusigKind for Bn254 {
    const KIND: u16 = MUSIG_BN;
    fn secret(label: &str, i: usize) -> Self::S {
        Self::hash_s("scaas.ua.groups.v1/secret", &[label.as_bytes(), &(i as u32).to_be_bytes()])
    }
    fn single(d: &Self::S, msg: &[u8; 32]) -> Vec<u8> {
        schnorr_bn254(d, msg)
    }
    fn hints(_: &KeyAgg<Self>, _: &[Vec<u8>]) -> Vec<u8> {
        vec![]
    }
}
fn uncompressed(p: &k256::ProjectivePoint) -> Vec<u8> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    p.to_affine().to_encoded_point(false).as_bytes()[1..].to_vec()
}
/// scaas Schnorr by `d`: `R = k·G`, `z = k + e·d`, deterministic `k`.
fn schnorr_bn254(d: &ark_bn254::Fr, msg: &[u8; 32]) -> Vec<u8> {
    let k = Bn254::hash_s("scaas.ua.groups.v1/schnorr-nonce", &[&Bn254::s_bytes(d), msg]);
    let (r, y) = (Bn254::g() * k, Bn254::g() * *d);
    Bn254::sig(&r, &(k + Bn254::challenge(&r, &y, msg) * *d))
}

struct Musig<C: MusigKind> {
    sks: Vec<Vec<u8>>,
    pks: Vec<Vec<u8>>,
    ka: KeyAgg<C>,
    d: C::S,
}
impl<C: MusigKind> Musig<C> {
    /// Members in the given order (no sorting): the caller decides.
    fn new(secrets: &[C::S]) -> Self {
        let sks: Vec<Vec<u8>> = secrets.iter().map(|s| C::s_bytes(s).to_vec()).collect();
        let pks: Vec<Vec<u8>> = secrets.iter().map(|s| C::ser(&(C::g() * *s))).collect();
        let ka = mu::key_agg::<C>(&pks).unwrap();
        let d = secrets.iter().zip(&pks).fold(C::zero_s(), |acc, (s, pk)| acc + ka.coef(pk) * *s);
        assert!(C::g() * d == ka.q);
        Musig { sks, pks, ka, d }
    }
    fn sorted(label: &str, n: usize) -> Self {
        let mut s: Vec<C::S> = (0..n).map(|i| C::secret(label, i)).collect();
        s.sort_by_key(|x| C::ser(&(C::g() * *x)));
        Self::new(&s)
    }
    fn key_data_with(&self, q: &C::P) -> Vec<u8> {
        [C::ser(q), (self.pks.len() as u16).to_be_bytes().to_vec(), self.pks.concat()].concat()
    }
    fn key_data(&self) -> Vec<u8> {
        self.key_data_with(&self.ka.q)
    }
    fn sign(&self, msg: &[u8; 32], r: &mut impl RngCore) -> Vec<u8> {
        let rands: Vec<[u8; 32]> = (0..self.sks.len()).map(|_| rand32(r)).collect();
        mu::sign_all::<C>(&self.sks, &self.pks, msg, &rands).unwrap()
    }
    fn hints(&self) -> Vec<u8> {
        C::hints(&self.ka, &self.pks)
    }
}

fn musig_row<C: MusigKind>(label: &str, n: usize, role: &str, e: &Env) -> Value {
    let (a, b, digest) = (&e.a, &e.b, &e.digest);
    let kind = C::KIND;
    let mut r = rng(label);
    let g = Musig::<C>::sorted(label, n);
    let kd = g.key_data();
    assert_eq!(derive_ua(kind, &kd, false).unwrap(), ua_of(kind, &kd).unwrap());
    let (ua, pd, m) = pop_of(kind, &kd, a);
    let sig = g.sign(&m, &mut r);
    let hints = g.hints();
    let blob = [sig.clone(), hints.clone()].concat();
    let vk = &kd[..C::PLEN];
    let mut sigs = vec![];
    let mut negs = vec![];
    if role == "main" {
        for p in ["metatx", "member"] {
            let pt = purpose_tag(p).unwrap();
            let mm = ua_message(kind, &pt, digest).unwrap();
            sigs.push(json!({ "purpose": p, "purposeTag": hx(&pt), "digest": hx(digest), "message": hx(&mm), "sig": hx(&g.sign(&mm, &mut r)) }));
        }
        let reg = |name: &str, kd2: &[u8], blob2: &[u8], err: &str, c: &str| neg_register(name, kind, kd2, blob2, err, a, c);
        let attacker = C::secret(&format!("{label}/attacker"), 0);
        // the board's list under an attacker's own key as Q (T-REG-6), signed by the attacker
        let kd2 = g.key_data_with(&(C::g() * attacker));
        let m2 = pop_of(kind, &kd2, a).2;
        negs.push(reg("wrong-q-own-key", &kd2, &[C::single(&attacker, &m2), hints.clone()].concat(), "UAPoP",
            "Q = the attacker's key with the board's list; the PoP is a valid signature by Q; only KeyAgg refuses it"));
        // −Q: same x, other parity; signed by −d (BIP-340 valid under x(Q) for secp256k1)
        let kd2 = g.key_data_with(&-g.ka.q);
        let m2 = pop_of(kind, &kd2, a).2;
        negs.push(reg("wrong-q-negated", &kd2, &[C::single(&-g.d, &m2), hints.clone()].concat(), "UAPoP",
            "Q negated (secp256k1: parity flipped, same x); the PoP signature by −d is valid; KeyAgg (x and parity) refuses it"));
        // unsorted / duplicate / n out of range: Q recomputed for that list, all hints valid, PoP signed by the group
        let mut members: Vec<C::S> = (0..n).map(|i| C::secret(label, i)).collect();
        members.sort_by_key(|x| C::ser(&(C::g() * *x)));
        let variants: Vec<(&str, Vec<C::S>, &str)> = vec![
            ("unsorted-keys", [vec![members[1], members[0]], members[2..].to_vec()].concat(), "pk_1 and pk_2 swapped; Q, hints and PoP valid for that order"),
            ("duplicate-key", [vec![members[0]], members.clone()].concat(), "pk_1 listed twice (n = 4); Q, hints and PoP valid for that list"),
            ("n-one", vec![members[0]], "n = 1; Q, hint and PoP valid"),
            ("n-seventeen", {
                let mut v: Vec<C::S> = (0..17).map(|i| C::secret(&format!("{label}/n17"), i)).collect();
                v.sort_by_key(|x| C::ser(&(C::g() * *x)));
                v
            }, "n = 17 sorted keys; Q, hints and PoP valid"),
        ];
        for (name, secrets, c) in variants {
            let v = Musig::<C>::new(&secrets);
            let kd2 = v.key_data();
            let m2 = pop_of(kind, &kd2, a).2;
            negs.push(reg(name, &kd2, &[v.sign(&m2, &mut r), v.hints()].concat(), "UAKeyData", c));
        }
        if kind == MUSIG_SECP {
            let h = |i: usize| hints[64 * i..64 * i + 64].to_vec();
            let shift = |i: usize, neg: bool| {
                let p = <k256::PublicKey as k256::elliptic_curve::sec1::FromEncodedPoint<k256::Secp256k1>>::from_encoded_point(
                    &k256::EncodedPoint::from_bytes([&[4u8][..], &h(i)].concat()).unwrap(),
                ).unwrap().to_projective();
                let gp = k256::ProjectivePoint::GENERATOR;
                uncompressed(&if neg { p - gp } else { p + gp })
            };
            let p1 = {
                use k256::elliptic_curve::sec1::FromEncodedPoint;
                let ep = k256::EncodedPoint::from_bytes(&g.pks[0]).unwrap();
                uncompressed(&k256::ProjectivePoint::from(k256::AffinePoint::from_encoded_point(&ep).unwrap()))
            };
            let with = |i: usize, x: Vec<u8>| { let mut v = hints.clone(); v[64 * i..64 * i + 64].copy_from_slice(&x); v };
            negs.push(reg("bad-hint", &kd, &[sig.clone(), with(0, p1)].concat(), "UAPoP", "H_1 = P_1 (a valid point, not a_1·P_1; a_2 = 1 makes H_2 = P_2 correct)"));
            negs.push(reg("hints-shifted", &kd, &[sig.clone(), { let v = with(0, shift(0, false)); let mut v2 = v.clone(); v2[64..128].copy_from_slice(&shift(1, true)); v2 }].concat(), "UAPoP",
                "H_1 + G and H_2 − G: Σ H_i still equals Q, only the per-hint ecrecover check refuses it"));
            negs.push(reg("hint-missing", &kd, &[sig.clone(), hints[..64 * (n - 1)].to_vec()].concat(), "UAPoP", "n − 1 hints"));
            negs.push(reg("hint-extra", &kd, &[sig.clone(), hints.clone(), h(0)].concat(), "UAPoP", "n + 1 hints"));
        } else {
            negs.push(reg("pop-trailing-byte", &kd, &[blob.clone(), vec![0]].concat(), "UAPoP", "the 96-byte signature plus one byte"));
        }
        negs.push(reg("pop-sig-mutated", &kd, &[flip_last(&sig), hints.clone()].concat(), "UAPoP", "last byte of s flipped"));
        let mb = pop_of(kind, &kd, b).2;
        negs.push(reg("pop-other-context", &kd, &[g.sign(&mb, &mut r), hints.clone()].concat(), "UAPoP", "a valid PoP for context B (other chainUid) offered under context A"));
        let s0 = unhex(&sigs[0]["sig"]);
        let (m_meta, m_member): ([u8; 32], [u8; 32]) = (unhex(&sigs[0]["message"]).try_into().unwrap(), unhex(&sigs[1]["message"]).try_into().unwrap());
        negs.push(neg_verify("wrong-purpose", vk, &m_member, &s0, "the metatx signature offered for the member message"));
        negs.push(neg_verify("sig-mutated", vk, &m_meta, &flip_last(&s0), "metatx signature, last byte flipped"));
        let order = hex::decode(if kind == MUSIG_SECP { SECP_N } else { BN_R }).unwrap();
        negs.push(neg_verify("s-equals-order", vk, &m_meta, &[&s0[..s0.len() - 32], &order[..]].concat(), "s replaced by the group order"));
    }
    let coefs: Vec<String> = g.pks.iter().map(|pk| hx(&C::s_bytes(&g.ka.coef(pk)))).collect();
    json!({
        "name": format!("{} n={n}", kind_info(kind).unwrap().name), "label": label, "role": role, "kind": kind,
        "kindName": kind_info(kind).unwrap().name, "n": n, "t": n,
        "secrets": g.sks.iter().map(|s| hx(s)).collect::<Vec<_>>(), "groupSecret": hx(&C::s_bytes(&g.d)),
        "members": g.pks.iter().map(|p| hx(p)).collect::<Vec<_>>(), "L": hx(&g.ka.l), "coefficients": coefs,
        "hints": hints.chunks(64).map(hx).collect::<Vec<_>>(), "dkg": [],
        "keyData": hx(&kd), "ua": hx(&ua), "keyHash": hx(&key_hash_of(kind, &kd).unwrap().unwrap()), "vk": hx(vk),
        "pop": { "context": a.name, "popDigest": hx(&pd), "message": hx(&m), "sig": hx(&sig), "blob": hx(&blob) },
        "sigs": sigs, "negatives": negs,
    })
}

// ---------- FROST ----------

fn ge<C: Ciphersuite>(b: &[u8]) -> Element<C> {
    let Ok(s) = <C::Group as Group>::Serialization::try_from(b) else { panic!("element length") };
    <C::Group>::deserialize(&s).expect("element")
}
fn gs<C: Ciphersuite>(e: &Element<C>) -> Vec<u8> {
    <C::Group>::serialize(e).expect("non-identity").as_ref().to_vec()
}
fn ss<C: Ciphersuite>(s: &Scalar<C>) -> Vec<u8> {
    <<C::Group as Group>::Field>::serialize(s).as_ref().to_vec()
}
fn sd<C: Ciphersuite>(b: &[u8]) -> Scalar<C> {
    let Ok(s) = <<C::Group as Group>::Field as Field>::Serialization::try_from(b) else { panic!("scalar length") };
    <<C::Group as Group>::Field>::deserialize(&s).expect("scalar")
}
fn single_frost<C: Ciphersuite>(secret: &Scalar<C>, msg: &[u8], r: &mut (impl RngCore + CryptoRng)) -> Vec<u8> {
    frost_core::SigningKey::<C>::from_scalar(*secret).unwrap().sign(&mut *r, msg).serialize().unwrap()
}

/// Per participant `{id, commitments, R, mu, preimage, challenge}` of key data `kd` (w = element width).
fn dkg_rows<C: Ciphersuite>(kd: &[u8], w: usize) -> Vec<Value> {
    let (t, n) = (u16::from_be_bytes([kd[w], kd[w + 1]]) as usize, u16::from_be_bytes([kd[w + 2], kd[w + 3]]) as usize);
    let per = (t + 1) * w + 32;
    (0..n)
        .map(|i| {
            let b = &kd[w + 4 + i * per..w + 4 + (i + 1) * per];
            let pre = [id::<C>(i as u16 + 1).serialize(), b[..w].to_vec(), b[t * w..(t + 1) * w].to_vec()].concat();
            json!({ "id": i + 1, "commitments": b[..t * w].chunks(w).map(hx).collect::<Vec<_>>(), "R": hx(&b[t * w..(t + 1) * w]),
                    "mu": hx(&b[(t + 1) * w..]), "preimage": hx(&pre), "challenge": hx(&ss::<C>(&C::HDKG(&pre).unwrap())) })
        })
        .collect()
}

/// Key data with participant blocks rebuilt by `f(i, commitments, R‖μ)`, `Y`, `t` overridden.
fn frost_kd(y: &[u8], t: u16, blocks: &[(Vec<Vec<u8>>, Vec<u8>)]) -> Vec<u8> {
    let mut d = [y, &t.to_be_bytes()[..], &(blocks.len() as u16).to_be_bytes()].concat();
    for (cs, pok) in blocks {
        d.extend(cs.concat());
        d.extend(pok);
    }
    d
}
fn frost_blocks(kd: &[u8], w: usize) -> Vec<(Vec<Vec<u8>>, Vec<u8>)> {
    let (t, n) = (u16::from_be_bytes([kd[w], kd[w + 1]]) as usize, u16::from_be_bytes([kd[w + 2], kd[w + 3]]) as usize);
    let per = (t + 1) * w + 32;
    (0..n).map(|i| {
        let b = &kd[w + 4 + i * per..w + 4 + (i + 1) * per];
        (b[..t * w].chunks(w).map(|c| c.to_vec()).collect(), b[t * w..].to_vec())
    }).collect()
}

fn frost_row<C: Ciphersuite>(kind: u16, label: &str, (t, n): (u16, u16), role: &str, e: &Env) -> Value {
    let (a, b, digest) = (&e.a, &e.b, &e.digest);
    let w = if kind == FROST_SECP { 33 } else { 64 };
    let mut r = rng(label);
    let g: Dkg<C> = dkg::<C, _>(t, n, &mut r).unwrap();
    let kd = g.key_data();
    assert_eq!(derive_ua(kind, &kd, false).unwrap(), ua_of(kind, &kd).unwrap());
    let (ua, pd, m) = pop_of(kind, &kd, a);
    let first: Vec<u16> = (1..=t).collect();
    let last: Vec<u16> = (n - t + 1..=n).collect();
    let sig = g.sign(&first, &m, &mut r).unwrap().serialize().unwrap();
    let vk = kd[..w].to_vec();
    let secret = g.group_secret().to_scalar();
    let mut sigs = vec![];
    let mut negs = vec![];
    if role == "main" {
        for p in ["metatx", "member"] {
            let pt = purpose_tag(p).unwrap();
            let mm = ua_message(kind, &pt, digest).unwrap();
            sigs.push(json!({ "purpose": p, "purposeTag": hx(&pt), "digest": hx(digest), "message": hx(&mm), "signers": last,
                              "sig": hx(&g.sign(&last, &mm, &mut r).unwrap().serialize().unwrap()) }));
        }
        let reg = |name: &str, kd2: &[u8], blob2: &[u8], err: &str, c: &str| neg_register(name, kind, kd2, blob2, err, a, c);
        let blocks = frost_blocks(&kd, w);
        // a transcript change: PoP re-signed by the real group over the changed ua
        let mut group_signed = |name: &str, kd2: Vec<u8>, err: &str, c: &str, negs: &mut Vec<Value>| {
            let m2 = pop_of(kind, &kd2, a).2;
            let s2 = g.sign(&first, &m2, &mut r).unwrap().serialize().unwrap();
            negs.push(reg(name, &kd2, &s2, err, c));
        };
        let mut bad = blocks.clone();
        let mu1 = sd::<C>(&bad[0].1[w..]) + <<C::Group as Group>::Field>::one();
        bad[0].1 = [bad[0].1[..w].to_vec(), ss::<C>(&mu1)].concat();
        group_signed("bad-pok", frost_kd(&vk, t, &bad), "UAPoP", "μ_1 + 1", &mut negs);
        let mut sw = blocks.clone();
        sw.swap(0, 1);
        group_signed("pok-ids-swapped", frost_kd(&vk, t, &sw), "UAPoP",
            "participants 1 and 2 swapped: Y = Σ C_i0 still holds, the PoK challenges bind the identifiers", &mut negs);
        let mut ext = blocks.clone();
        ext[0].0.push(gs::<C>(&<C::Group>::generator()));
        group_signed("commitments-extra", frost_kd(&vk, t, &ext), "UAKeyData", "participant 1 publishes t + 1 commitments", &mut negs);
        let mut short = blocks.clone();
        short[0].0.pop();
        group_signed("commitments-missing", frost_kd(&vk, t, &short), "UAKeyData", "participant 1 publishes t − 1 commitments", &mut negs);
        let one: Vec<_> = blocks.iter().map(|(cs, pok)| (vec![cs[0].clone()], pok.clone())).collect();
        group_signed("t-one", frost_kd(&vk, 1, &one), "UAKeyData", "t = 1 with only C_i0 each: PoKs and Y = Σ C_i0 valid, t ≥ 2 refuses it", &mut negs);
        let gt: Vec<_> = blocks.iter().map(|(cs, pok)| {
            let mut cs = cs.clone();
            while cs.len() < n as usize + 1 { cs.push(gs::<C>(&<C::Group>::generator())); }
            (cs, pok.clone())
        }).collect();
        group_signed("t-gt-n", frost_kd(&vk, n + 1, &gt), "UAKeyData", "t = n + 1 (padded commitment vectors)", &mut negs);
        // attacker-controlled Y, signed by the attacker
        let att = frost_core::SigningKey::<C>::new(&mut r).to_scalar();
        let ya = <C::Group>::generator() * att;
        let kd2 = frost_kd(&gs::<C>(&ya), t, &blocks);
        let m2 = pop_of(kind, &kd2, a).2;
        negs.push(reg("y-not-sum", &kd2, &single_frost::<C>(&att, &m2, &mut r), "UAPoP", "Y = an attacker key (valid PoP by it), Y ≠ Σ C_i0"));
        let mut rogue = blocks.clone();
        let c0 = |i: usize| ge::<C>(&blocks[i].0[0]);
        let mut rest = ya;
        for i in 0..n as usize - 1 { rest = rest - c0(i); }
        rogue[n as usize - 1].0[0] = gs::<C>(&rest);
        let kd2 = frost_kd(&gs::<C>(&ya), t, &rogue);
        let m2 = pop_of(kind, &kd2, a).2;
        negs.push(reg("rogue-contribution", &kd2, &single_frost::<C>(&att, &m2, &mut r), "UAPoP",
            "C_n0 = Y_att − Σ_{i<n} C_i0 so Y = Σ C_i0 = Y_att (valid PoP by the attacker); the participant's PoK no longer verifies"));
        let neg_s = <<C::Group as Group>::Field>::zero() - secret;
        let kd2 = frost_kd(&gs::<C>(&(<C::Group>::generator() * neg_s)), t, &blocks);
        let m2 = pop_of(kind, &kd2, a).2;
        negs.push(reg("y-negated", &kd2, &single_frost::<C>(&neg_s, &m2, &mut r), "UAPoP", "Y negated, PoP by −s valid; Y ≠ Σ C_i0"));
        negs.push(reg("pop-sig-mutated", &kd, &flip_last(&sig), "UAPoP", "last byte of z flipped"));
        let mb = pop_of(kind, &kd, b).2;
        negs.push(reg("pop-other-context", &kd, &g.sign(&first, &mb, &mut r).unwrap().serialize().unwrap(), "UAPoP",
            "a valid PoP for context B (other chainUid) offered under context A"));
        if kind == FROST_SECP {
            let bip = Secp256k1::single(&Secp256k1::s_parse(&ss::<C>(&secret)).unwrap(), &m);
            negs.push(reg("pop-bip340", &kd, &bip, "UAPoP", "a BIP-340 signature by x(Y) as the PoP (T-FROST: never verified as BIP-340)"));
        }
        let s0 = unhex(&sigs[0]["sig"]);
        let (m_meta, m_member): ([u8; 32], [u8; 32]) = (unhex(&sigs[0]["message"]).try_into().unwrap(), unhex(&sigs[1]["message"]).try_into().unwrap());
        negs.push(neg_verify("wrong-purpose", &vk, &m_member, &s0, "the metatx signature offered for the member message"));
        negs.push(neg_verify("sig-mutated", &vk, &m_meta, &flip_last(&s0), "metatx signature, last byte flipped"));
        let order = hex::decode(if kind == FROST_SECP { SECP_N } else { BN_R }).unwrap();
        negs.push(neg_verify("z-equals-order", &vk, &m_meta, &[&s0[..w], &order[..]].concat(), "z replaced by the group order"));
        if kind == FROST_SECP {
            negs.push(neg_verify("r-prefix-04", &vk, &m_meta, &[&[4u8][..], &s0[1..]].concat(), "R with prefix 0x04"));
        }
    }
    let shares: Vec<String> = g.keys.values().map(|k| hx(&ss::<C>(&k.signing_share().to_scalar()))).collect();
    json!({
        "name": format!("{} t={t} n={n}", kind_info(kind).unwrap().name), "label": label, "role": role, "kind": kind,
        "kindName": kind_info(kind).unwrap().name, "n": n, "t": t,
        "secrets": shares, "groupSecret": hx(&ss::<C>(&secret)),
        "members": [], "L": "0x", "coefficients": [], "hints": [], "dkg": dkg_rows::<C>(&kd, w),
        "keyData": hx(&kd), "ua": hx(&ua), "keyHash": hx(&key_hash_of(kind, &kd).unwrap().unwrap()), "vk": hx(&vk),
        "pop": { "context": a.name, "popDigest": hx(&pd), "message": hx(&m), "signers": first, "sig": hx(&sig), "blob": hx(&sig) },
        "sigs": sigs, "negatives": negs,
    })
}

// ---------- official vectors, T-FROST ----------

fn bip327_section() -> Value {
    let mut official = serde_json::Map::new();
    let mut sha = serde_json::Map::new();
    for f in BIP327 {
        let text = std::fs::read(root(&format!("tests/data/bip327/{f}.json"))).unwrap();
        use sha2::Digest;
        sha.insert(f.into(), hx(&sha2::Sha256::digest(&text)).into());
        official.insert(f.into(), serde_json::from_slice(&text).unwrap());
    }
    // KeyAgg valid cases with Q (x and parity), L, a_i and the hints the EVM check takes
    let ka = &official["key_agg_vectors"];
    let pks: Vec<Vec<u8>> = ka["pubkeys"].as_array().unwrap().iter().map(unhex).collect();
    let rows: Vec<Value> = ka["valid_test_cases"].as_array().unwrap().iter().map(|c| {
        let keys: Vec<Vec<u8>> = c["key_indices"].as_array().unwrap().iter().map(|i| pks[i.as_u64().unwrap() as usize].clone()).collect();
        let agg = mu::key_agg::<Secp256k1>(&keys).unwrap();
        let q = Secp256k1::ser(&agg.q);
        assert_eq!(hx(&q[1..]), hx(&unhex(&c["expected"])).to_lowercase());
        json!({ "keys": keys.iter().map(|k| hx(k)).collect::<Vec<_>>(), "L": hx(&agg.l), "secondKey": hx(&agg.second),
                "coefficients": keys.iter().map(|k| hx(&Secp256k1::s_bytes(&agg.coef(k)))).collect::<Vec<_>>(),
                "Q": hx(&q), "expectedX": hx(&unhex(&c["expected"])),
                "hints": Secp256k1::hints(&agg, &keys).chunks(64).map(hx).collect::<Vec<_>>() })
    }).collect();
    json!({ "source": format!("https://github.com/bitcoin/bips/tree/{BIP327_COMMIT}/bip-0327/vectors"), "sha256": sha,
            "keyAgg": rows, "official": official })
}

fn rfc9591_section() -> Value {
    let e = read_json("tests/data/rfc9591_e5.json");
    json!({ "source": e["source"], "groupPublicKey": hx(&unhex(&e["group_public_key"])), "groupSecretKey": hx(&unhex(&e["group_secret_key"])),
            "message": hx(&unhex(&e["message"])), "participantList": [1, 3], "sig": hx(&unhex(&e["sig"])), "full": e })
}

/// ZF frost-secp256k1 3.0.0 `tests/helpers/vectors_dkg.json` in registry key-data layout (no PoP: PoKs and Y = Σ C_i0 only).
fn zf_dkg_section() -> Value {
    let z = read_json("tests/data/zf_frost_secp256k1_dkg.json");
    let inp = &z["inputs"];
    let blocks: Vec<(Vec<Vec<u8>>, Vec<u8>)> = (1..=3).map(|i| {
        let p = &inp[i.to_string()];
        (p["vss_commitments"].as_array().unwrap().iter().map(unhex).collect(), unhex(&p["proof_of_knowledge"]))
    }).collect();
    let kd = frost_kd(&unhex(&inp["verifying_key"]), 2, &blocks);
    validate_key_data(FROST_SECP, &kd, false).unwrap();
    json!({ "source": "ZF frost-secp256k1 3.0.0 tests/helpers/vectors_dkg.json (crates.io)", "t": 2, "n": 3,
            "keyData": hx(&kd), "ua": hx(&ua_of(FROST_SECP, &kd).unwrap()), "dkg": dkg_rows::<Secp256K1Sha256>(&kd, 33) })
}

fn t_frost(groups: &[Value], bip340_official: &Value, e5: &Value) -> Vec<Value> {
    let row = |name: &str, verifier: &str, key: &[u8], msg: &[u8], sig: &[u8], valid: bool, c: &str| {
        json!({ "name": name, "verifier": verifier, "key": hx(key), "message": hx(msg), "sig": hx(sig), "valid": valid, "comment": c })
    };
    let mut out = vec![];
    let (y, m, s) = (unhex(&e5["groupPublicKey"]), unhex(&e5["message"]), unhex(&e5["sig"]));
    out.push(row("rfc9591-e5", "frost-secp256k1", &y, &m, &s, true, "RFC 9591 E.5 (message \"test\", 4 bytes)"));
    out.push(row("rfc9591-e5-as-bip340", "bip340", &y[1..], &m, &[&s[1..33], &s[33..]].concat(), false, "x(R) ‖ z under x(Y)"));
    let fg = groups.iter().find(|g| g["kind"] == FROST_SECP && g["role"] == "main").unwrap();
    let (y, m, s) = (unhex(&fg["vk"]), unhex(&fg["pop"]["message"]), unhex(&fg["pop"]["sig"]));
    out.push(row("frost-pop", "frost-secp256k1", &y, &m, &s, true, "the frost-secp256k1 main group's PoP"));
    out.push(row("frost-pop-as-bip340", "bip340", &y[1..], &m, &[&s[1..33], &s[33..]].concat(), false, "x(R) ‖ z under x(Y)"));
    let bip = Secp256k1::single(&Secp256k1::s_parse(&unhex(&fg["groupSecret"])).unwrap(), &m.clone().try_into().unwrap());
    out.push(row("bip340-by-y", "bip340", &y[1..], &m, &bip, true, "BIP-340 by the FROST group secret over the PoP message"));
    out.push(row("bip340-by-y-as-frost", "frost-secp256k1", &y, &m, &[&[2u8][..], &bip].concat(), false, "(02 ‖ r) ‖ s under Y"));
    let mg = groups.iter().find(|g| g["kind"] == MUSIG_SECP && g["role"] == "main").unwrap();
    let (q, m, s) = (unhex(&mg["vk"]), unhex(&mg["pop"]["message"]), unhex(&mg["pop"]["sig"]));
    out.push(row("musig2-pop", "bip340", &q[1..], &m, &s, true, "the musig2-secp256k1 main group's PoP (BIP-340 by x(Q))"));
    out.push(row("musig2-pop-as-frost", "frost-secp256k1", &[&[2u8][..], &q[1..]].concat(), &m, &[&[2u8][..], &s].concat(), false, "(02 ‖ r) ‖ s under 02 ‖ x(Q)"));
    let o = &bip340_official[0];
    let (pk, m, s) = (unhex(&o["publicKey"]), unhex(&o["message"]), unhex(&o["sig"]));
    out.push(row("bip340-official-0", "bip340", &pk, &m, &s, true, "BIP-340 test vector 0"));
    out.push(row("bip340-official-0-as-frost", "frost-secp256k1", &[&[2u8][..], &pk].concat(), &m, &[&[2u8][..], &s].concat(), false, "(02 ‖ r) ‖ s under 02 ‖ pk"));
    out
}

// ---------- the file ----------

fn generate() -> String {
    let (contexts, env) = contexts();
    let mut groups = vec![];
    for (n, role) in [(3, "main"), (2, "gas"), (8, "gas"), (16, "gas")] {
        groups.push(musig_row::<Secp256k1>(&format!("musig2-secp256k1/n{n}"), n, role, &env));
    }
    for (t, n, role) in [(2, 3, "main"), (2, 2, "gas"), (2, 8, "gas"), (8, 8, "gas"), (2, 16, "gas"), (16, 16, "gas")] {
        groups.push(frost_row::<Secp256K1Sha256>(FROST_SECP, &format!("frost-secp256k1/t{t}n{n}"), (t, n), role, &env));
    }
    for (n, role) in [(3, "main"), (2, "gas"), (8, "gas"), (16, "gas")] {
        groups.push(musig_row::<Bn254>(&format!("musig2-bn254/n{n}"), n, role, &env));
    }
    for (t, n, role) in [(2, 3, "main"), (2, 2, "gas"), (2, 8, "gas"), (8, 8, "gas"), (2, 16, "gas"), (16, 16, "gas")] {
        groups.push(frost_row::<Bn254Keccak256>(FROST_BN, &format!("frost-bn254/t{t}n{n}"), (t, n), role, &env));
    }
    let e5 = rfc9591_section();
    let sigs = read_json("../../smartcontracts/vectors/ua/signatures.json");
    let tf = t_frost(&groups, &sigs["bip340Official"], &e5);
    let v = json!({
        "note": "Generated by clients/scaas-ua tests/groups.rs (feature signers: BIP-327 MuSig2 over k256 + the bn254 port, ZF frost-core 3.0.0 / frost-secp256k1 3.0.0 + the FROST(bn254, keccak256) ciphersuite); never edit by hand. Schema: SCHEMA in the UA-2c plan (groups[] rows, negatives with entry/error, bip327, rfc9591E5, zfDkg, tFrost). The secp256k1 rows are re-verified by clientkeys test/ua-groups.test.js (noble); musig2-bn254 (our BIP-327 port) and FROST(bn254, keccak256) have no independent second implementation: clients/scaas-ua agreeing on them is self-consistency only (accounts.md §1.16).",
        "version": 1,
        "context": "A",
        "contextOther": "B",
        "contexts": contexts,
        "digest": hx(&env.digest),
        "ciphersuites": {
            "frost-secp256k1": { "contextString": "FROST-secp256k1-SHA256-v1", "H2": "expand_message_xmd SHA-256, DST contextString ‖ \"chal\", 48 bytes mod N, over R(33) ‖ Y(33) ‖ msg",
                                 "HDKG": "expand_message_xmd SHA-256, DST contextString ‖ \"dkg\", 48 bytes mod N, over id(32, big-endian) ‖ C_i0(33) ‖ R_i(33)" },
            "frost-bn254": { "contextString": "FROST-BN254-KECCAK256-SCAAS-v1", "H2": "scaas Schnorr challenge over R(64) ‖ Y(64) ‖ msg",
                             "HDKG": "keccak256(cs ‖ \"dkg\" ‖ m ‖ 0x00) ‖ keccak256(cs ‖ \"dkg\" ‖ m ‖ 0x01) mod r, m = id(32, big-endian) ‖ C_i0(64) ‖ R_i(64)" },
            "musig2-bn254": { "L": "tagged(\"KeyAgg list\", P_1 ‖ … ‖ P_n), 32 bytes, P_i 64 bytes", "a_i": "tagged(\"KeyAgg coefficient\", L ‖ P_i ‖ 0x00) ‖ tagged(… ‖ 0x01) mod r; 1 for the second distinct key",
                              "b": "widened tagged(\"MuSig/noncecoef\", aggnonce(128) ‖ Q(64) ‖ msg) mod r", "challenge": "scaas Schnorr over R(64) ‖ Q(64) ‖ msg" }
        },
        "groups": groups,
        "bip327": bip327_section(),
        "rfc9591E5": e5,
        "zfDkg": zf_dkg_section(),
        "tFrost": tf,
    });
    serde_json::to_string_pretty(&v).unwrap() + "\n"
}

const OUT: &str = "../../smartcontracts/vectors/ua/groups.json";

#[test]
#[ignore = "writes smartcontracts/vectors/ua/groups.json"]
fn write_groups_json() {
    std::fs::write(root(OUT), generate()).unwrap();
}

#[test]
fn groups_json_regenerates_byte_for_byte() {
    assert!(std::fs::read_to_string(root(OUT)).unwrap() == generate(), "groups.json differs from the generator's output");
}

// ---------- the signers against the official vectors ----------

fn bip(name: &str) -> Value {
    read_json(&format!("tests/data/bip327/{name}.json"))
}
fn list(v: &Value) -> Vec<Vec<u8>> {
    v.as_array().unwrap().iter().map(unhex).collect()
}
fn pick(all: &[Vec<u8>], idx: &Value) -> Vec<Vec<u8>> {
    idx.as_array().unwrap().iter().map(|i| all[i.as_u64().unwrap() as usize].clone()).collect()
}
fn contribution(e: &Value) -> mu::Error {
    match e["type"].as_str().unwrap() {
        "invalid_contribution" => mu::Error::Contribution(e["signer"].as_u64().map(|s| s as usize), match e["contrib"].as_str().unwrap() {
            "pubkey" => "pubkey",
            "pubnonce" => "pubnonce",
            "aggnonce" => "aggnonce",
            other => panic!("{other}"),
        }),
        _ => mu::Error::Value(match e["message"].as_str().unwrap() {
            "The signer's pubkey must be included in the list of pubkeys." => "The signer's pubkey must be included in the list of pubkeys.",
            "first secnonce value is out of range." => "first secnonce value is out of range.",
            other => panic!("{other}"),
        }),
    }
}

#[test]
fn bip327_key_sort_and_key_agg() {
    let v = bip("key_sort_vectors");
    let mut pks = list(&v["pubkeys"]);
    mu::key_sort(&mut pks);
    assert_eq!(pks, list(&v["sorted_pubkeys"]));
    let v = bip("key_agg_vectors");
    let pks = list(&v["pubkeys"]);
    for c in v["valid_test_cases"].as_array().unwrap() {
        let q = mu::key_agg::<Secp256k1>(&pick(&pks, &c["key_indices"])).unwrap().q;
        assert_eq!(Secp256k1::agg_bytes(&q), unhex(&c["expected"]));
    }
    let mut n = 0;
    for c in v["error_test_cases"].as_array().unwrap() {
        if !c["tweak_indices"].as_array().unwrap().is_empty() {
            continue; // tweaks: not implemented (the registry has none)
        }
        assert_eq!(mu::key_agg::<Secp256k1>(&pick(&pks, &c["key_indices"])).err().unwrap(), contribution(&c["error"]));
        n += 1;
    }
    assert_eq!(n, 3);
}

#[test]
fn bip327_nonce_gen_and_agg() {
    for c in bip("nonce_gen_vectors")["test_cases"].as_array().unwrap() {
        let opt = |k: &str| (!c[k].is_null()).then(|| unhex(&c[k]));
        let (sk, agg, msg, extra) = (opt("sk"), opt("aggpk"), opt("msg"), opt("extra_in"));
        let (sec, pubn) = mu::nonce_gen::<Secp256k1>(&unhex(&c["rand_"]).try_into().unwrap(), sk.as_deref(), &unhex(&c["pk"]), agg.as_deref(), msg.as_deref(), extra.as_deref());
        assert_eq!(sec, unhex(&c["expected_secnonce"]));
        assert_eq!(pubn, unhex(&c["expected_pubnonce"]));
    }
    let v = bip("nonce_agg_vectors");
    let pn = list(&v["pnonces"]);
    for c in v["valid_test_cases"].as_array().unwrap() {
        assert_eq!(mu::nonce_agg::<Secp256k1>(&pick(&pn, &c["pnonce_indices"])).unwrap(), unhex(&c["expected"]));
    }
    for c in v["error_test_cases"].as_array().unwrap() {
        assert_eq!(mu::nonce_agg::<Secp256k1>(&pick(&pn, &c["pnonce_indices"])).err().unwrap(), contribution(&c["error"]));
    }
}

#[test]
fn bip327_sign_and_verify() {
    let v = bip("sign_verify_vectors");
    let (sk, pks, sec, pn, an, msgs) = (unhex(&v["sk"]), list(&v["pubkeys"]), list(&v["secnonces"]), list(&v["pnonces"]), list(&v["aggnonces"]), list(&v["msgs"]));
    for c in v["valid_test_cases"].as_array().unwrap() {
        let keys = pick(&pks, &c["key_indices"]);
        let nonces = pick(&pn, &c["nonce_indices"]);
        let agg = &an[c["aggnonce_index"].as_u64().unwrap() as usize];
        assert_eq!(&mu::nonce_agg::<Secp256k1>(&nonces).unwrap(), agg);
        let msg = &msgs[c["msg_index"].as_u64().unwrap() as usize];
        let i = c["signer_index"].as_u64().unwrap() as usize;
        let s = mu::sign::<Secp256k1>(&sec[0], &sk, agg, &keys, msg).unwrap();
        assert_eq!(s.to_vec(), unhex(&c["expected"]));
        assert!(mu::partial_sig_verify::<Secp256k1>(&s, &nonces, &keys, msg, i).unwrap());
    }
    for c in v["sign_error_test_cases"].as_array().unwrap() {
        let keys = pick(&pks, &c["key_indices"]);
        let agg = &an[c["aggnonce_index"].as_u64().unwrap() as usize];
        let msg = &msgs[c["msg_index"].as_u64().unwrap() as usize];
        let s = &sec[c["secnonce_index"].as_u64().unwrap() as usize];
        assert_eq!(mu::sign::<Secp256k1>(s, &sk, agg, &keys, msg).err().unwrap(), contribution(&c["error"]), "{}", c["comment"]);
    }
    for c in v["verify_fail_test_cases"].as_array().unwrap() {
        let (keys, nonces) = (pick(&pks, &c["key_indices"]), pick(&pn, &c["nonce_indices"]));
        let msg = &msgs[c["msg_index"].as_u64().unwrap() as usize];
        assert!(!mu::partial_sig_verify::<Secp256k1>(&unhex(&c["sig"]), &nonces, &keys, msg, c["signer_index"].as_u64().unwrap() as usize).unwrap());
    }
    for c in v["verify_error_test_cases"].as_array().unwrap() {
        let (keys, nonces) = (pick(&pks, &c["key_indices"]), pick(&pn, &c["nonce_indices"]));
        let msg = &msgs[c["msg_index"].as_u64().unwrap() as usize];
        let r = mu::partial_sig_verify::<Secp256k1>(&unhex(&c["sig"]), &nonces, &keys, msg, c["signer_index"].as_u64().unwrap() as usize);
        assert_eq!(r.err().unwrap(), contribution(&c["error"]), "{}", c["comment"]);
    }
}

/// An RNG replaying fixed bytes: frost-core's `commit` draws the hiding then the binding nonce randomness (32 bytes each).
struct Replay(Vec<u8>);
impl RngCore for Replay {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }
    fn fill_bytes(&mut self, d: &mut [u8]) {
        d.copy_from_slice(&self.0[..d.len()]);
        self.0.drain(..d.len());
    }
    fn try_fill_bytes(&mut self, d: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
        self.fill_bytes(d);
        Ok(())
    }
}
impl CryptoRng for Replay {}

#[test]
fn rfc9591_e5_reproduced_by_frost_secp256k1() {
    use frost_core::keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare};
    type C = Secp256K1Sha256;
    let e = read_json("tests/data/rfc9591_e5.json");
    let vk = frost_core::VerifyingKey::<C>::deserialize(&unhex(&e["group_public_key"])).unwrap();
    let msg = unhex(&e["message"]);
    let share = |i: u16| SigningShare::<C>::deserialize(&unhex(&e["participants"][i.to_string()])).unwrap();
    let shares: std::collections::BTreeMap<_, _> = (1..=3).map(|i| (id::<C>(i), VerifyingShare::from(share(i)))).collect();
    let public = PublicKeyPackage::new(shares, vk, Some(2));
    let mut nonces = std::collections::BTreeMap::new();
    let mut commitments = std::collections::BTreeMap::new();
    for i in [1u16, 3] {
        let p = &e["signers"][i.to_string()];
        let mut rng = Replay([unhex(&p["hiding_nonce_randomness"]), unhex(&p["binding_nonce_randomness"])].concat());
        let (n, c) = frost_core::round1::commit(&share(i), &mut rng);
        assert_eq!(c.hiding().serialize().unwrap(), unhex(&p["hiding_nonce_commitment"]));
        assert_eq!(c.binding().serialize().unwrap(), unhex(&p["binding_nonce_commitment"]));
        nonces.insert(id::<C>(i), n);
        commitments.insert(id::<C>(i), c);
    }
    let package = frost_core::SigningPackage::new(commitments, &msg);
    let mut sig_shares = std::collections::BTreeMap::new();
    for (i, n) in &nonces {
        let ii: u16 = if *i == id::<C>(1) { 1 } else { 3 };
        let kp = KeyPackage::new(*i, share(ii), VerifyingShare::from(share(ii)), vk, 2);
        let s = frost_core::round2::sign(&package, n, &kp).unwrap();
        assert_eq!(s.serialize(), unhex(&e["signers"][ii.to_string()]["sig_share"]));
        sig_shares.insert(*i, s);
    }
    let sig = frost_core::aggregate(&package, &sig_shares, &public).unwrap();
    assert_eq!(sig.serialize().unwrap(), unhex(&e["sig"]));
    assert!(scaas_ua::verify::frost_secp256k1(&unhex(&e["group_public_key"]), &msg, &unhex(&e["sig"])));
}

#[test]
fn zf_dkg_vector_pok_preimage() {
    // the ZF vector's PoKs verify through frost-core's own check (part2 would refuse otherwise) and through ours
    let z = read_json("tests/data/zf_frost_secp256k1_dkg.json");
    let inp = &z["inputs"];
    for i in 1..=3u16 {
        let p = &inp[i.to_string()];
        let cs: Vec<Vec<u8>> = list(&p["vss_commitments"]);
        let pok = unhex(&p["proof_of_knowledge"]);
        let pre = [id::<Secp256K1Sha256>(i).serialize(), cs[0].clone(), pok[..33].to_vec()].concat();
        let c = Secp256K1Sha256::HDKG(&pre).unwrap();
        let (r, mu_) = (ge::<Secp256K1Sha256>(&pok[..33]), sd::<Secp256K1Sha256>(&pok[33..]));
        assert!(r == <<Secp256K1Sha256 as Ciphersuite>::Group as Group>::generator() * mu_ - ge::<Secp256K1Sha256>(&cs[0]) * c);
    }
}
