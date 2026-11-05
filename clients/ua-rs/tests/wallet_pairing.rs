// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T3c: the pairing-curve kinds and the group sessions (spec §3, §9.1, §9.4, §12): scaas Schnorr `0x0104` /
//! `0x0105` (nonce `k = hashToScalar(keccak256("scaas.ua.schnorr.nonce.v1" ‖ be32(sk) ‖ Y ‖ ua_msg ‖ aux))`, `aux` from the
//! OS RNG), BLS min-sig `0x0106` / `0x0107` under the role's domain, MuSig2 (`0x0110`, `0x0112`) and FROST sessions whose
//! secret nonce is consumed once, every secret multiplication on arkworks through `scaas_ct::secret_mul` — against
//! smartcontracts/vectors/ua/sign.json (written by clientkeys). The `vectors` tests use the test-only entry points (fixed
//! `aux` / randomness, raw secrets) and the ladder's record (the **structural test**: per secret path, two calls with one
//! secret give one point and two blinded integers, each `≥ r`, `≡ k (mod r)`, 384 iterations). UNAUDITED.
use scaas_ua::frost::{dkg, id, Bn254Keccak256, Secp256K1Sha256};
use scaas_ua::musig2::{self as mu, Bn254, Curve, Secp256k1};
use scaas_ua::verify::verify;
use scaas_ua::wallet::{Error, FrostSession, Wallet};
use scaas_ua::{purpose_tag, purpose_tag_v, ua_message};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

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
fn u32_of(v: &Value) -> u32 {
    v.as_u64().unwrap() as u32
}
fn kind_of(r: &Value) -> u16 {
    r["kind"].as_u64().unwrap() as u16
}
fn wallet(id: &str) -> Wallet {
    let k = load("keys.json");
    let m = arr(&k, "mnemonics").iter().find(|m| m["id"] == id).unwrap();
    Wallet::from_mnemonic(m["words"].as_str().unwrap(), m["passphrase"].as_str().unwrap()).unwrap()
}
/// The pairing-curve kinds: schnorr-bn254, schnorr-bls12381, bls12381-minsig, bls-bn254-minsig.
const PAIRING: [u16; 4] = [0x0104, 0x0105, 0x0106, 0x0107];

/// Every `sign.json` `ua` row of the pairing kinds: key data, `ua_msg`; the row's signature verifies under its role (Rust
/// verifies the JS signer); BLS (deterministic) byte-equal through `sign_ua`; scaas Schnorr's release signature of the same
/// request verifies under the role.
#[test]
fn sign_json_pairing_rows() {
    let s = load("sign.json");
    let mut wallets = HashMap::new();
    let (mut n, mut bls) = (0, 0);
    for r in arr(&s, "ua").iter().filter(|r| PAIRING.contains(&kind_of(r))) {
        let kind = kind_of(r);
        let w = wallets.entry(r["mnemonic"].as_str().unwrap().to_string()).or_insert_with(|| wallet(r["mnemonic"].as_str().unwrap()));
        let key = w.ua_key(kind, u32_of(&r["account"]), u32_of(&r["index"])).unwrap();
        assert_eq!(hex::encode(key.key_data()), hex::encode(bytes(&r["keyData"])), "{r}");
        let (purpose, digest) = (b32(&r["purposeTag"]), b32(&r["digest"]));
        let ua_msg = ua_message(kind, &purpose, &digest).unwrap();
        assert_eq!(ua_msg, b32(&r["uaMsg"]), "{r}");
        let pop = r["role"] == "pop";
        assert!(verify(kind, &key.key_data(), &ua_msg, &bytes(&r["signature"]), pop), "{r}");
        let mine = key.sign_ua(&purpose, &digest).unwrap();
        assert!(verify(kind, &key.key_data(), &ua_msg, &mine, pop), "{r}");
        if matches!(kind, 0x0106 | 0x0107) {
            assert_eq!(hex::encode(&mine), hex::encode(bytes(&r["signature"])), "{r}");
            bls += 1;
        }
        n += 1;
    }
    assert_eq!((n, bls), (14, 6));
}

/// `sign.json` `refusals`: a BLS signature of the right message under the other role's domain does not verify; the control
/// (its own role) does.
#[test]
fn bls_wrong_dst_refusal_rows() {
    let s = load("sign.json");
    let mut n = 0;
    for r in arr(&s, "refusals").iter().filter(|r| r["case"] == "bls-wrong-dst") {
        let (kind, kd, m, sig) = (kind_of(r), bytes(&r["keyData"]), b32(&r["uaMsg"]), bytes(&r["signature"]));
        assert_eq!(verify(kind, &kd, &m, &sig, r["pop"].as_bool().unwrap()), r["valid"].as_bool().unwrap(), "{r}");
        assert!(verify(kind, &kd, &m, &sig, r["signedAs"] == "pop"), "{r}");
        n += 1;
    }
    assert_eq!(n, 4);
}

/// The BLS kinds sign under the domain of the request's role: an authorization signature does not verify as a PoP and the
/// reverse; the two signatures of one digest differ.
#[test]
fn right_message_wrong_dst_refused() {
    let w = wallet("pq_kat");
    let d = [5u8; 32];
    for kind in [0x0106, 0x0107] {
        let key = w.ua_key(kind, 0, 0).unwrap();
        let (auth, pop) = (purpose_tag("metatx").unwrap(), purpose_tag_v("pop", 2).unwrap());
        let (sa, sp) = (key.sign_ua(&auth, &d).unwrap(), key.sign_ua(&pop, &d).unwrap());
        let (ma, mp) = (ua_message(kind, &auth, &d).unwrap(), ua_message(kind, &pop, &d).unwrap());
        assert!(verify(kind, &key.key_data(), &ma, &sa, false), "{kind:#06x}");
        assert!(!verify(kind, &key.key_data(), &ma, &sa, true), "{kind:#06x}");
        assert!(verify(kind, &key.key_data(), &mp, &sp, true), "{kind:#06x}");
        assert!(!verify(kind, &key.key_data(), &mp, &sp, false), "{kind:#06x}");
    }
}

/// scaas Schnorr in a release build: `aux` from the OS RNG, so two signatures of one request differ and both verify; BLS
/// repeats.
#[test]
fn release_randomness_per_kind() {
    let w = wallet("pq_kat");
    let (p, d) = (purpose_tag("metatx").unwrap(), [3u8; 32]);
    for kind in PAIRING {
        let key = w.ua_key(kind, 0, 0).unwrap();
        let (a, b) = (key.sign_ua(&p, &d).unwrap(), key.sign_ua(&p, &d).unwrap());
        assert_eq!(a == b, matches!(kind, 0x0106 | 0x0107), "{kind:#06x}");
        let m = ua_message(kind, &p, &d).unwrap();
        assert!(verify(kind, &key.key_data(), &m, &a, false) && verify(kind, &key.key_data(), &m, &b, false), "{kind:#06x}");
    }
}

/// A revoked pairing handle signs nothing; a MuSig2 session made before `lock()` signs nothing after it.
#[test]
fn locked_wallet_pairing_handles_sign_nothing() {
    let w = wallet("pq_kat");
    let keys: Vec<_> = PAIRING.iter().map(|k| w.ua_key(*k, 0, 0).unwrap()).collect();
    let (a, b) = (w.ua_key(0x0112, 0, 0).unwrap(), w.ua_key(0x0112, 1, 0).unwrap());
    let pks = vec![a.key_data(), b.key_data()];
    let msg = [6u8; 32];
    let (mut sa, sb) = (a.musig2_session(&pks, &msg).unwrap(), b.musig2_session(&pks, &msg).unwrap());
    let agg = mu::nonce_agg::<Bn254>(&[sa.pubnonce(), sb.pubnonce()]).unwrap();
    let (p, d) = (purpose_tag("metatx").unwrap(), [1u8; 32]);
    w.lock();
    for key in keys {
        assert_eq!(key.sign_ua(&p, &d).err(), Some(Error::KeyRevoked));
    }
    assert_eq!(sa.sign(&agg).err(), Some(Error::KeyRevoked));
    assert_eq!(a.musig2_session(&pks, &msg).err(), Some(Error::KeyRevoked));
}

/// MuSig2 over the wallet's participant keys, both curves: each session's nonce signs once (a second `sign` is an error);
/// the partial signatures verify, the aggregate verifies under the group key (`schnorr-bn254` / BIP-340). A session refuses
/// a key list without its own key and a kind that is not a MuSig2 participant.
#[test]
fn second_sign_on_a_session_errors() {
    fn run<C: Curve>(kind: u16, w: &Wallet) {
        let (a, b) = (w.ua_key(kind, 0, 0).unwrap(), w.ua_key(kind, 1, 0).unwrap());
        let mut pks = vec![a.key_data(), b.key_data()];
        mu::key_sort(&mut pks);
        let msg = [8u8; 32];
        let (mut sa, mut sb) = (a.musig2_session(&pks, &msg).unwrap(), b.musig2_session(&pks, &msg).unwrap());
        let pubnonces = vec![sa.pubnonce(), sb.pubnonce()];
        let agg = mu::nonce_agg::<C>(&pubnonces).unwrap();
        let (pa, pb) = (sa.sign(&agg).unwrap(), sb.sign(&agg).unwrap());
        assert_eq!(sa.sign(&agg).err(), Some(Error::Argument), "{kind:#06x}: the nonce is spent");
        assert_eq!(sb.sign(&agg).err(), Some(Error::Argument), "{kind:#06x}");
        let ia = pks.iter().position(|k| *k == a.key_data()).unwrap();
        let ordered: Vec<Vec<u8>> = if ia == 0 { pubnonces.clone() } else { vec![pubnonces[1].clone(), pubnonces[0].clone()] };
        let (p0, p1) = if ia == 0 { (pa, pb) } else { (pb, pa) };
        assert!(mu::partial_sig_verify::<C>(&p0, &ordered, &pks, &msg, 0).unwrap(), "{kind:#06x}");
        assert!(mu::partial_sig_verify::<C>(&p1, &ordered, &pks, &msg, 1).unwrap(), "{kind:#06x}");
        let sig = mu::partial_sig_agg::<C>(&[p0, p1], &agg, &pks, &msg).unwrap();
        let q = C::ser(&mu::key_agg::<C>(&pks).unwrap().q);
        assert!(verify(kind, &q, &msg, &sig, false), "{kind:#06x}: the aggregate");
        assert_eq!(a.musig2_session(&[b.key_data()], &msg).err(), Some(Error::Argument), "{kind:#06x}: own key missing");
    }
    let w = wallet("pq_kat");
    run::<Secp256k1>(0x0110, &w);
    run::<Bn254>(0x0112, &w);
    let other = w.ua_key(0x0104, 0, 0).unwrap();
    assert_eq!(other.musig2_session(&[other.key_data()], &[0u8; 32]).err(), Some(Error::Argument));
}

/// FROST sessions on both ciphersuites: the nonces sign once; the shares aggregate to a signature that verifies.
#[test]
fn frost_session_nonce_signs_once() {
    fn run<C: frost_core::Ciphersuite>() {
        use rand_chacha::rand_core::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(3);
        let g = dkg::<C, _>(2, 3, &mut rng).unwrap();
        let signers = [id::<C>(1), id::<C>(3)];
        let mut sessions: BTreeMap<_, _> = signers.iter().map(|i| (*i, FrostSession::new(&g.keys[i]))).collect();
        let commitments = sessions.iter().map(|(i, s)| (*i, s.commitments())).collect();
        let msg = b"frost session";
        let package = frost_core::SigningPackage::new(commitments, msg);
        let mut shares = BTreeMap::new();
        for (i, s) in sessions.iter_mut() {
            shares.insert(*i, s.sign(&package, &g.keys[i]).unwrap());
            assert_eq!(s.sign(&package, &g.keys[i]).err(), Some(Error::Argument), "the nonces are spent");
        }
        let sig = frost_core::aggregate(&package, &shares, &g.public).unwrap();
        g.public.verifying_key().verify(msg, &sig).unwrap();
    }
    run::<Bn254Keccak256>();
    run::<Secp256K1Sha256>();
}

#[cfg(feature = "vectors")]
mod vectors {
    use super::*;
    use ark_ff::{BigInteger, PrimeField};
    use scaas_ua::scaas_ct::trace;
    use scaas_ua::wallet::{pairing, SigRole, SignRequest, Signer};

    /// `sign.json` scaas Schnorr `compare: bytes` rows (fixed `aux`) through `sign_ua`'s path, byte-equal.
    #[test]
    fn sign_json_fixed_aux_rows() {
        let s = load("sign.json");
        let w = wallet("pq_kat");
        let mut n = 0;
        for r in arr(&s, "ua").iter().filter(|r| matches!(kind_of(r), 0x0104 | 0x0105) && r["compare"] == "bytes") {
            let key = w.ua_key(kind_of(r), u32_of(&r["account"]), u32_of(&r["index"])).unwrap();
            let sig = key.vectors_sign_ua_fixed(&b32(&r["purposeTag"]), &b32(&r["digest"]), &bytes(&r["fixed"]["aux"])).unwrap();
            assert_eq!(hex::encode(sig), hex::encode(bytes(&r["signature"])), "{r}");
            n += 1;
        }
        assert_eq!(n, 4);
    }

    fn be32<F: PrimeField>(f: F) -> [u8; 32] {
        f.into_bigint().to_bytes_be().try_into().unwrap()
    }
    fn dec<F: PrimeField>(v: &Value) -> [u8; 32] {
        be32(v.as_str().unwrap().parse::<F>().ok().unwrap())
    }

    /// `sign.json` `nonceMap` (computed by the generator, not by the signer): the nonce input, `k` by the 512-bit map (not
    /// the biased 256-bit one), and the signature with that `aux`.
    #[test]
    fn nonce_map_rows() {
        let s = load("sign.json");
        let w = wallet("pq_kat");
        let mut n = 0;
        for r in arr(&s, "nonceMap") {
            let kind = kind_of(r);
            let key = w.ua_key(kind, 0, 0).unwrap();
            let sk: [u8; 32] = key.vectors_with_secret(|s| s.try_into().unwrap()).unwrap();
            assert_eq!(sk.to_vec(), bytes(&r["skBytes"]), "{r}");
            assert_eq!(key.key_data(), bytes(&r["keyData"]), "{r}");
            let (m, aux) = (b32(&r["uaMsg"]), b32(&r["aux"]));
            let input = [&b"scaas.ua.schnorr.nonce.v1"[..], &sk, &key.key_data(), &m, &aux].concat();
            assert_eq!(input, bytes(&r["input"]), "{r}");
            assert_eq!(scaas_ua::keccak256(&input), b32(&r["seed"]), "{r}");
            let (k, k256) = match kind {
                0x0104 => (dec::<ark_bn254::Fr>(&r["k"]), dec::<ark_bn254::Fr>(&r["k256"])),
                _ => (dec::<ark_bls12_381::Fr>(&r["k"]), dec::<ark_bls12_381::Fr>(&r["k256"])),
            };
            let mine = pairing::schnorr_nonce(kind, &sk, &key.key_data(), &m, &aux).unwrap();
            assert_eq!(mine, k, "{r}");
            assert_ne!(mine, k256, "{r}");
            let sig = key.vectors_sign_ua_fixed(&b32(&r["purposeTag"]), &b32(&r["digest"]), &aux).unwrap();
            assert_eq!(hex::encode(sig), hex::encode(bytes(&r["signature"])), "{r}");
            n += 1;
        }
        assert_eq!(n, 2);
    }

    /// The BLS kinds through the common `Signer`: the request carries the role of its purpose (`pop` v2 → `Pop`), and the
    /// signature verifies under that role only.
    #[test]
    fn bls_pop_and_sig_through_the_trait() {
        let w = wallet("pq_kat");
        let d = [9u8; 32];
        for kind in [0x0106, 0x0107] {
            let key = w.ua_key(kind, 0, 0).unwrap();
            for (purpose, want) in [(purpose_tag_v("pop", 2).unwrap(), SigRole::Pop), (purpose_tag("metatx").unwrap(), SigRole::Authorization)] {
                let req = key.vectors_request(&purpose, &d).unwrap();
                let SignRequest::UaMsg { ua_msg, role, .. } = req.clone() else { panic!() };
                assert_eq!(role, want);
                let sig = Signer::sign_request(&key, &req).unwrap();
                let pop = want == SigRole::Pop;
                assert!(verify(kind, &key.key_data(), &ua_msg, &sig, pop), "{kind:#06x} {want:?}");
                assert!(!verify(kind, &key.key_data(), &ua_msg, &sig, !pop), "{kind:#06x} {want:?}");
            }
        }
    }

    /// Fixed `aux` is 32 bytes for scaas Schnorr; BLS takes none.
    #[test]
    fn fixed_randomness_shapes() {
        let w = wallet("pq_kat");
        let (p, d) = (purpose_tag("metatx").unwrap(), [2u8; 32]);
        let key = w.ua_key(0x0104, 0, 0).unwrap();
        assert!(key.vectors_sign_ua_fixed(&p, &d, &[1u8; 32]).is_ok());
        assert_eq!(key.vectors_sign_ua_fixed(&p, &d, &[1u8; 31]).err(), Some(Error::Argument));
        let bls = w.ua_key(0x0106, 0, 0).unwrap();
        assert_eq!(bls.vectors_sign_ua_fixed(&p, &d, &[1u8; 32]).err(), Some(Error::Argument));
    }

    // --- the structural test (spec §12) ---

    fn be(k: &[u64; 6]) -> Vec<u8> {
        k.iter().rev().flat_map(|l| l.to_be_bytes()).collect()
    }

    /// Two ladder records of one secret path (`a`, `b`: one call each, same secret): same count, every integer `≥ r`, `≡`
    /// the expected scalar `(mod r)`, 384 iterations, the two calls' integers different. Returns the reduced scalars.
    fn blinded<F: PrimeField>(path: &str, a: &[trace::Entry], b: &[trace::Entry], want: Option<&[[u8; 32]]>) -> Vec<F> {
        assert!(!a.is_empty(), "{path}: no ladder ran (secret_mul bypassed)");
        assert_eq!(a.len(), b.len(), "{path}");
        let r = F::MODULUS.to_bytes_be();
        let mut out = Vec::new();
        for (i, (x, y)) in a.iter().zip(b).enumerate() {
            assert_ne!(x.k, y.k, "{path} #{i}: one blinded integer for two calls");
            let (fx, fy) = (F::from_be_bytes_mod_order(&be(&x.k)), F::from_be_bytes_mod_order(&be(&y.k)));
            assert_eq!(fx, fy, "{path} #{i}: k' ≢ k");
            for e in [x, y] {
                assert_eq!(e.iterations, 384, "{path} #{i}");
                let k = be(&e.k);
                let (hi, lo) = k.split_at(k.len() - r.len());
                assert!(hi.iter().any(|b| *b != 0) || lo >= &r[..], "{path} #{i}: k' < r");
            }
            if let Some(w) = want {
                assert_eq!(be32(fx), w[i], "{path} #{i}: k' ≢ the secret (mod r)");
            }
            out.push(fx);
        }
        out
    }

    fn secret(key: &scaas_ua::wallet::UaKey) -> [u8; 32] {
        key.vectors_with_secret(|s| s.try_into().unwrap()).unwrap()
    }

    /// Keygen: two wallets of one mnemonic derive one key data through two blinded integers (G1: `0x0104`, `0x0105`,
    /// `0x0112`; G2: `0x0106`, `0x0107`).
    fn keygen(kinds: &[u16], path: &str) {
        for &kind in kinds {
            trace::take();
            let (w1, w2) = (wallet("pq_kat"), wallet("pq_kat"));
            let k1 = w1.ua_key(kind, 0, 0).unwrap();
            let a = trace::take();
            let k2 = w2.ua_key(kind, 0, 0).unwrap();
            let b = trace::take();
            assert_eq!(k1.key_data(), k2.key_data());
            let want = [secret(&k1)];
            let p = format!("{path} {kind:#06x}");
            if matches!(kind, 0x0104 | 0x0107 | 0x0112) {
                blinded::<ark_bn254::Fr>(&p, &a, &b, Some(&want));
            } else {
                blinded::<ark_bls12_381::Fr>(&p, &a, &b, Some(&want));
            }
            assert_eq!(a.len(), 1, "{p}");
        }
    }

    #[test]
    fn structural_keygen_g1() {
        keygen(&[0x0104, 0x0105, 0x0112], "keygen G1");
    }

    #[test]
    fn structural_keygen_g2() {
        keygen(&[0x0106, 0x0107], "keygen G2");
    }

    /// The scaas Schnorr nonce point `k·G`: one fixed `aux`, two signatures, one `R`, two blinded integers of `k`.
    #[test]
    fn structural_nonce_point() {
        let w = wallet("pq_kat");
        let (p, d, aux) = (purpose_tag("metatx").unwrap(), [4u8; 32], [7u8; 32]);
        for kind in [0x0104, 0x0105] {
            let key = w.ua_key(kind, 0, 0).unwrap();
            let k = pairing::schnorr_nonce(kind, &secret(&key), &key.key_data(), &ua_message(kind, &p, &d).unwrap(), &aux).unwrap();
            trace::take();
            let s1 = key.vectors_sign_ua_fixed(&p, &d, &aux).unwrap();
            let a = trace::take();
            let s2 = key.vectors_sign_ua_fixed(&p, &d, &aux).unwrap();
            let b = trace::take();
            assert_eq!(s1, s2);
            let path = format!("nonce point {kind:#06x}");
            if kind == 0x0104 {
                blinded::<ark_bn254::Fr>(&path, &a, &b, Some(&[k]));
            } else {
                blinded::<ark_bls12_381::Fr>(&path, &a, &b, Some(&[k]));
            }
            assert_eq!(a.len(), 1, "{path}");
        }
    }

    /// BLS `sk·H(m)`: two signatures, one point, two blinded integers of `sk`.
    #[test]
    fn structural_bls_sign() {
        let w = wallet("pq_kat");
        let (p, d) = (purpose_tag("metatx").unwrap(), [5u8; 32]);
        for kind in [0x0106, 0x0107] {
            let key = w.ua_key(kind, 0, 0).unwrap();
            trace::take();
            let s1 = key.sign_ua(&p, &d).unwrap();
            let a = trace::take();
            let s2 = key.sign_ua(&p, &d).unwrap();
            let b = trace::take();
            assert_eq!(s1, s2);
            let path = format!("BLS sign {kind:#06x}");
            if kind == 0x0107 {
                blinded::<ark_bn254::Fr>(&path, &a, &b, Some(&[secret(&key)]));
            } else {
                blinded::<ark_bls12_381::Fr>(&path, &a, &b, Some(&[secret(&key)]));
            }
            assert_eq!(a.len(), 1, "{path}");
        }
    }

    /// MuSig2-bn254: two sessions of one fixed `rand'` give one public nonce through blinded `k1·G`, `k2·G` (the BIP-327
    /// NonceGen scalars), and each partial signature's `sk·G` (the signer's own key check) is blinded too.
    #[test]
    fn structural_musig2_bn254() {
        let w = wallet("pq_kat");
        let (a, b) = (w.ua_key(0x0112, 0, 0).unwrap(), w.ua_key(0x0112, 1, 0).unwrap());
        let pks = vec![a.key_data(), b.key_data()];
        let (msg, rand) = ([3u8; 32], [11u8; 32]);
        let agg_pk = Bn254::agg_bytes(&mu::key_agg::<Bn254>(&pks).unwrap().q);
        let (sec, _) = mu::nonce_gen::<Bn254>(&rand, Some(&secret(&a)), &a.key_data(), Some(&agg_pk), Some(&msg), None).unwrap();
        let want: [[u8; 32]; 2] = [sec[..32].try_into().unwrap(), sec[32..64].try_into().unwrap()];
        trace::take();
        let mut s1 = a.vectors_musig2_session(&pks, &msg, &rand).unwrap();
        let t1 = trace::take();
        let mut s2 = a.vectors_musig2_session(&pks, &msg, &rand).unwrap();
        let t2 = trace::take();
        assert_eq!(s1.pubnonce(), s2.pubnonce());
        blinded::<ark_bn254::Fr>("MuSig2-bn254 nonces", &t1, &t2, Some(&want));
        assert_eq!(t1.len(), 2);
        let sb = b.musig2_session(&pks, &msg).unwrap();
        let agg = mu::nonce_agg::<Bn254>(&[s1.pubnonce(), sb.pubnonce()]).unwrap();
        trace::take();
        let p1 = s1.sign(&agg).unwrap();
        let t1 = trace::take();
        let p2 = s2.sign(&agg).unwrap();
        let t2 = trace::take();
        assert_eq!(p1, p2);
        blinded::<ark_bn254::Fr>("MuSig2-bn254 sign", &t1, &t2, Some(&[secret(&a)]));
        assert_eq!(t1.len(), 1);
    }

    /// FROST-BN254 through the `Bn254Group` element newtype: two sessions of one fixed RNG give one pair of commitments
    /// through blinded integers of the hiding and binding nonces.
    #[test]
    fn structural_frost_bn254() {
        use frost_core::{Ciphersuite, Group};
        use rand_chacha::rand_core::SeedableRng;
        type G = <Bn254Keccak256 as Ciphersuite>::Group;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(4);
        let g = dkg::<Bn254Keccak256, _>(2, 2, &mut rng).unwrap();
        let key = &g.keys[&id::<Bn254Keccak256>(1)];
        trace::take();
        let s1 = FrostSession::vectors_with_rng(key, &mut rand_chacha::ChaCha20Rng::seed_from_u64(5));
        let t1 = trace::take();
        let s2 = FrostSession::vectors_with_rng(key, &mut rand_chacha::ChaCha20Rng::seed_from_u64(5));
        let t2 = trace::take();
        assert_eq!(s1.commitments(), s2.commitments());
        let ks = blinded::<ark_bn254::Fr>("FROST-BN254 commitments", &t1, &t2, None);
        assert_eq!(ks.len(), 2);
        let c = s1.commitments();
        assert_eq!(G::serialize(&(G::generator() * ks[0])).unwrap(), c.hiding().serialize().unwrap()[..]);
        assert_eq!(G::serialize(&(G::generator() * ks[1])).unwrap(), c.binding().serialize().unwrap()[..]);
    }
}
