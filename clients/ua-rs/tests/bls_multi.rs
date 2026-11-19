// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `bls12381-multi` (0x0121, spec 2026-11-19-bls12381-multi): key data (§2), the stored form, verify / verifyMinimal (§5),
//! the PoP check (§4), Review Focus 1–3 of the plan. Signatures are made here with arkworks from fixed scalars. UNAUDITED.
use ark_bls12_381::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use scaas_ua::bls_multi::{self, compress, expand, g1_encode, g2_encode, neg_g2, parse, ua_of};
use scaas_ua::verify::{hash_to_g1_bls12381, verify, BLS12381_DST_SIG};
use scaas_ua::{keccak256, validate_key_data, UAError};

const K: u16 = 0x0121;

pub fn pk_of(sk: &Fr) -> G2Affine {
    (G2Affine::generator() * sk).into_affine()
}

/// A group from `(sk, weight)` sorted by key: `(d, sks and weights in key-data order)`.
pub fn group(members: &[(Fr, u16)], t: u16) -> (Vec<u8>, Vec<(Fr, u16)>) {
    group_points(&members.iter().map(|(sk, w)| (pk_of(sk), *sk, *w)).collect::<Vec<_>>(), t)
}

pub fn group_points(members: &[(G2Affine, Fr, u16)], t: u16) -> (Vec<u8>, Vec<(Fr, u16)>) {
    let mut m: Vec<([u8; 256], Fr, u16)> = members.iter().map(|(p, sk, w)| (g2_encode(p), *sk, *w)).collect();
    m.sort_by_key(|a| a.0);
    let apk: G2Projective = members.iter().map(|(p, _, _)| p.into_group()).sum();
    let mut d = g2_encode(&apk.into_affine()).to_vec();
    d.extend_from_slice(&t.to_be_bytes());
    d.extend_from_slice(&(m.len() as u16).to_be_bytes());
    for (k, _, w) in &m {
        d.extend_from_slice(k);
        d.extend_from_slice(&w.to_be_bytes());
    }
    (d, m.iter().map(|(_, sk, w)| (*sk, *w)).collect())
}

fn sks(n: u64) -> Vec<(Fr, u16)> {
    (0..n).map(|i| (Fr::from(1_000 + 7 * i), 1)).collect()
}

/// `σ ‖ signers` by the listed members over `memberDigest(ua, ua_msg)` under `dst`.
pub fn sign_with(d: &[u8], members: &[(Fr, u16)], ua_msg: &[u8; 32], signers: &[u8], dst: &[u8]) -> Vec<u8> {
    let m = keccak256(&[&ua_of(d)[..], ua_msg].concat());
    let h = hash_to_g1_bls12381(&m, dst);
    let sigma: G1Projective = signers.iter().map(|i| h * members[*i as usize].0).sum();
    [&g1_encode(&sigma.into_affine())[..], &bls_multi::indices_bitmap(signers)].concat()
}
fn sign(d: &[u8], members: &[(Fr, u16)], ua_msg: &[u8; 32], signers: &[u8]) -> Vec<u8> {
    sign_with(d, members, ua_msg, signers, bls_multi::DST_MULTI_SIG)
}
fn ok(d: &[u8], msg: &[u8; 32], sig: &[u8]) -> bool {
    verify(K, d, msg, sig, false, false)
}
fn ok_min(d: &[u8], msg: &[u8; 32], sig: &[u8]) -> bool {
    verify(K, d, msg, sig, false, true)
}
const MSG: [u8; 32] = [7u8; 32];

fn refused(d: &[u8]) -> bool {
    matches!(validate_key_data(K, d, false), Err(UAError::KeyData(_)))
}

#[test]
fn key_data_valid_rows() {
    for n in [2u64, 16, 64] {
        let m = sks(n);
        for t in [1u16, n as u16] {
            let (d, _) = group(&m, t);
            assert_eq!(d.len(), 260 + 258 * n as usize);
            assert!(validate_key_data(K, &d, false).is_ok(), "n {n} t {t}");
        }
    }
    let w = |ws: &[u16]| -> Vec<(Fr, u16)> { ws.iter().enumerate().map(|(i, w)| (Fr::from(50 + i as u64), *w)).collect() };
    assert!(validate_key_data(K, &group(&w(&[3, 1, 1]), 3).0, false).is_ok());
    // a weight above t is valid (owner ruling R2-Q3)
    assert!(validate_key_data(K, &group(&w(&[5, 1]), 2).0, false).is_ok());
    assert_eq!(scaas_ua::key_hash_of(K, &group(&sks(2), 1).0).unwrap(), None, "no keyHash (Q5)");
    assert!(scaas_ua::is_signing(K) && scaas_ua::is_member(K, false) && scaas_ua::has_surplus_form(K));
    assert!(!scaas_ua::has_surplus_form(0x0106) && !scaas_ua::has_surplus_form(0x0120));
}

/// A point on the G2 curve outside the prime-order subgroup.
fn off_subgroup() -> G2Affine {
    for i in 1u64.. {
        if let Some(p) = G2Affine::get_point_from_x_unchecked(Fq2::new(Fq::from(i), Fq::from(1u64)), false) {
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                return p;
            }
        }
    }
    unreachable!()
}

#[test]
fn key_data_refusals() {
    let base = sks(3);
    let (d, _) = group(&base, 2);
    assert!(!refused(&d), "positive control");
    let n = |d: &mut Vec<u8>, v: u16| d[258..260].copy_from_slice(&v.to_be_bytes());
    let t = |d: &mut Vec<u8>, v: u16| d[256..258].copy_from_slice(&v.to_be_bytes());
    let key = |i: usize| 260 + 258 * i;
    // n = 1 (length consistent with it)
    let (mut x, _) = group(&base[..2], 1);
    n(&mut x, 1);
    x.truncate(260 + 258);
    assert!(refused(&x), "n = 1");
    // n = 65
    let (x, _) = group(&sks(65), 1);
    assert!(refused(&x), "n = 65");
    let mut x = d.clone();
    t(&mut x, 0);
    assert!(refused(&x), "t = 0");
    let mut x = d.clone();
    t(&mut x, 4);
    assert!(refused(&x), "t = Σw + 1");
    let mut x = d.clone();
    t(&mut x, 3);
    assert!(!refused(&x), "t = Σw");
    let mut x = d.clone();
    x[key(1) + 256..key(1) + 258].copy_from_slice(&[0, 0]);
    assert!(refused(&x), "weight 0");
    for len in [d.len() - 1, d.len() + 1, 0, 259] {
        let mut x = d.clone();
        x.resize(len, 0);
        assert!(refused(&x), "length {len}");
    }
    // unsorted pair: swap members 0 and 1
    let mut x = d.clone();
    let (a, b) = (x[key(0)..key(1)].to_vec(), x[key(1)..key(2)].to_vec());
    x[key(0)..key(1)].copy_from_slice(&b);
    x[key(1)..key(2)].copy_from_slice(&a);
    assert!(refused(&x), "unsorted");
    // duplicate key (apk recomputed so only the order fails)
    let p = pk_of(&Fr::from(9u64));
    let (x, _) = group_points(&[(p, Fr::from(9u64), 1), (p, Fr::from(9u64), 1), (pk_of(&Fr::from(3u64)), Fr::from(3u64), 1)], 1);
    assert!(refused(&x), "duplicate");
    // off curve
    let mut x = d.clone();
    x[key(1) + 255] ^= 1;
    assert!(refused(&x), "off curve");
    // on the curve, outside the subgroup (apk the sum, so only the subgroup check fails)
    let q = off_subgroup();
    let (x, _) = group_points(&[(q, Fr::from(1u64), 1), (pk_of(&Fr::from(3u64)), Fr::from(3u64), 1)], 1);
    assert!(refused(&x), "subgroup");
    // a key at infinity
    let (x, _) = group_points(&[(G2Affine::identity(), Fr::from(0u64), 1), (pk_of(&Fr::from(3u64)), Fr::from(3u64), 1)], 1);
    assert!(refused(&x), "infinity key");
    // non-canonical limb: top bytes non-zero, and a limb ≥ p
    let mut x = d.clone();
    x[key(2)] = 1;
    assert!(refused(&x), "top bytes");
    let mut x = d.clone();
    x[key(2) + 16..key(2) + 64].fill(0xff);
    assert!(refused(&x), "limb ≥ p");
    // apk ≠ the sum
    let mut x = d.clone();
    x[..256].copy_from_slice(&g2_encode(&pk_of(&Fr::from(77u64))));
    assert!(refused(&x), "apk");
    // apk = the sum but at infinity: two keys that cancel
    let p = pk_of(&Fr::from(5u64));
    let (x, _) = group_points(&[(p, Fr::from(5u64), 1), (-p, -Fr::from(5u64), 1)], 1);
    assert_eq!(&x[..256], &[0u8; 256][..]);
    assert!(refused(&x), "apk at infinity");
}

#[test]
fn compress_expand_round_trip() {
    for n in [2u64, 5, 64] {
        let (d, _) = group(&sks(n), 1);
        let s = compress(&d).unwrap();
        assert_eq!(s.len(), 196 + 194 * n as usize);
        assert_eq!(expand(&s).unwrap(), d);
        let p = bls_multi::stored(&d).unwrap();
        assert_eq!(p.len(), 228 + 194 * n as usize);
        assert_eq!(&p[..32], &ua_of(&d)[..], "p = ua ‖ s");
        assert_eq!(&p[32..], &s[..]);
    }
    let (mut d, _) = group(&sks(2), 1);
    d[260 + 258 + 64] = 1; // a top byte of a limb
    assert!(compress(&d).is_err());
}

#[test]
fn weight_sum_wide() {
    let m: Vec<(Fr, u16)> = vec![(Fr::from(11u64), 65535), (Fr::from(12u64), 65535)];
    let (d, s) = group(&m, 65535);
    assert!(validate_key_data(K, &d, false).is_ok(), "Σw = 131070 ≥ t");
    let kd = parse(&d).unwrap();
    for one in [0u8, 1] {
        assert!(ok(&d, &MSG, &sign(&d, &s, &MSG, &[one])), "{{{one}}} authorises");
        assert!(ok_min(&d, &MSG, &sign(&d, &s, &MSG, &[one])), "{{{one}}} minimal");
        assert!(bls_multi::minimal(&kd, &[one]));
    }
    let both = sign(&d, &s, &MSG, &[0, 1]);
    assert!(ok(&d, &MSG, &both), "{{0, 1}} authorises");
    assert!(!ok_min(&d, &MSG, &both), "{{0, 1}} is not minimal");
    assert!(!bls_multi::minimal(&kd, &[0, 1]));
}

#[test]
fn negation_zero_component() {
    assert_eq!(neg_g2(&[0u8; 256]), [0u8; 256], "O ↦ O");
    let p = pk_of(&Fr::from(3u64));
    let e = g2_encode(&p);
    assert_eq!(neg_g2(&e), g2_encode(&-p));
    // one zero y component stays zero, the other is negated
    let mut z = e;
    z[128..192].fill(0);
    let n = neg_g2(&z);
    assert_eq!(&n[128..192], &[0u8; 64][..]);
    assert_eq!(&n[..128], &e[..128]);
    assert_eq!(&n[192..], &g2_encode(&-p)[192..]);
}

#[test]
fn subtract_cancelling_pair() {
    // n = 6: pk, −pk, pk_c … pk_f; signers everyone but the pair (k = 4 > (n + 1) / 2: the subtract path, non-signers sum to O)
    let a = Fr::from(41u64);
    let mut pts = vec![(pk_of(&a), a, 1u16), (pk_of(&-a), -a, 1)];
    for i in 0..4u64 {
        let s = Fr::from(60 + i);
        pts.push((pk_of(&s), s, 1));
    }
    let (d, s) = group_points(&pts, 4);
    assert!(validate_key_data(K, &d, false).is_ok());
    let pair: Vec<u8> = (0..6u8).filter(|i| s[*i as usize].0 == a || s[*i as usize].0 == -a).collect();
    let signers: Vec<u8> = (0..6u8).filter(|i| !pair.contains(i)).collect();
    assert_eq!(signers.len(), 4);
    let sig = sign(&d, &s, &MSG, &signers);
    assert!(ok(&d, &MSG, &sig));
    assert!(ok_min(&d, &MSG, &sig));
}

#[test]
fn f12_cancelling_pair_documented() {
    // keys pk, −pk, pk_c, t = 3, all bits set, σ by pk_c alone verifies (spec §11 residual, not a defect)
    let (a, c) = (Fr::from(41u64), Fr::from(43u64));
    let (d, s) = group_points(&[(pk_of(&a), a, 1), (pk_of(&-a), -a, 1), (pk_of(&c), c, 1)], 3);
    assert!(validate_key_data(K, &d, false).is_ok());
    let ic = s.iter().position(|x| x.0 == c).unwrap() as u8;
    let mut sig = sign(&d, &s, &MSG, &[ic]);
    sig[128..].copy_from_slice(&bls_multi::indices_bitmap(&[0, 1, 2]));
    assert!(ok(&d, &MSG, &sig));
}

#[test]
fn verify_paths() {
    let (d, s) = group(&sks(5), 3);
    let at = |set: &[u8]| sign(&d, &s, &MSG, set);
    assert!(ok(&d, &MSG, &at(&[0, 2, 4])), "k = t");
    assert!(ok_min(&d, &MSG, &at(&[0, 2, 4])), "k = t minimal");
    assert!(ok(&d, &MSG, &at(&[0, 1, 2, 3, 4])), "k = n");
    assert!(!ok_min(&d, &MSG, &at(&[0, 1, 2, 3, 4])), "k = n not minimal");
    assert!(!ok(&d, &MSG, &at(&[0, 2])), "weight t − 1");
    let mut x = at(&[0, 2, 4]);
    x[128..].fill(0);
    assert!(!ok(&d, &MSG, &x), "signers 0");
    let mut x = at(&[0, 2, 4]);
    x[159] |= 1 << 5; // bit 5 = n (byte 31 of the bitmap)
    assert!(!ok(&d, &MSG, &x), "a bit ≥ n");
    let mut x = at(&[0, 2, 4]);
    x[..128].fill(0);
    assert!(!ok(&d, &MSG, &x), "σ at infinity");
    let x = at(&[0, 2, 4]);
    assert!(!ok(&d, &MSG, &x[..159]), "159");
    assert!(!ok(&d, &MSG, &[&x[..], &[0]].concat()), "161");
    let mut x = at(&[0, 2, 4]);
    x[159] |= 1 << 1;
    assert!(!ok(&d, &MSG, &x), "one bit added");
    let mut x = at(&[0, 2, 4]);
    x[159] &= !1;
    assert!(!ok(&d, &MSG, &x), "one bit cleared");
    assert!(!ok(&d, &[8u8; 32], &at(&[0, 2, 4])), "another message");
    // a stored-key byte flipped (pk_2 of the fixture)
    let mut e = d.clone();
    e[260 + 258 * 2 + 200] ^= 1;
    assert!(!ok(&e, &MSG, &at(&[0, 2, 4])));
    // σ off the subgroup: a G1 point on the curve outside it
    let mut x = at(&[0, 2, 4]);
    let q = (1u64..)
        .find_map(|i| G1Affine::get_point_from_x_unchecked(Fq::from(i), false).filter(|p| !p.is_in_correct_subgroup_assuming_on_curve()))
        .unwrap();
    x[..128].copy_from_slice(&g1_encode(&q));
    assert!(!ok(&d, &MSG, &x), "σ off the subgroup");
}

#[test]
fn apk_path_boundary() {
    // Review Focus 3: 2k = n + 1 (add) and 2k = n + 2 (subtract)
    for (n, ks) in [(5u64, [3usize, 4]), (64, [32, 33])] {
        let (d, s) = group(&sks(n), 1);
        for k in ks {
            let set: Vec<u8> = (0..k as u8).map(|i| (i * 7) % n as u8).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
            let set: Vec<u8> = if set.len() == k { set } else { (0..k as u8).collect() };
            let sig = sign(&d, &s, &MSG, &set);
            assert!(ok(&d, &MSG, &sig), "n {n} k {k}");
            // the same σ with one member swapped in the bitmap fails
            let mut other = set.clone();
            let out = (0..n as u8).find(|i| !set.contains(i)).unwrap();
            other[0] = out;
            other.sort();
            let mut x = sig.clone();
            x[128..].copy_from_slice(&bls_multi::indices_bitmap(&other));
            assert!(!ok(&d, &MSG, &x), "n {n} k {k} other set");
        }
    }
}

#[test]
fn minimal_rows() {
    let w = |ws: &[u16]| -> Vec<(Fr, u16)> { ws.iter().enumerate().map(|(i, w)| (Fr::from(90 + i as u64), *w)).collect() };
    let (d, s) = group(&w(&[3, 1, 1]), 3);
    let kd = parse(&d).unwrap();
    let heavy = s.iter().position(|x| x.1 == 3).unwrap() as u8;
    let light: Vec<u8> = (0..3u8).filter(|i| *i != heavy).collect();
    assert!(ok_min(&d, &MSG, &sign(&d, &s, &MSG, &[heavy])), "the weight-3 member alone: minimal");
    assert!(!ok(&d, &MSG, &sign(&d, &s, &MSG, &light)), "the two weight-1 members do not authorise");
    let mut two = vec![heavy, light[0]];
    two.sort();
    let sig = sign(&d, &s, &MSG, &two);
    assert!(ok(&d, &MSG, &sig), "{{3, 1}} authorises");
    assert!(!ok_min(&d, &MSG, &sig), "{{3, 1}} refused on a stored path: 4 − 1 ≥ 3");
    assert!(!bls_multi::minimal(&kd, &two));
    // the min over S, not over all members: weights {3, 3, 1}, t = 5, S = the two 3s: 6 − 3 < 5 (minimal); over all 6 − 1 ≥ 5
    let (d, s) = group(&w(&[3, 3, 1]), 5);
    let set: Vec<u8> = (0..3u8).filter(|i| s[*i as usize].1 == 3).collect();
    assert!(ok_min(&d, &MSG, &sign(&d, &s, &MSG, &set)));
    assert!(bls_multi::minimal(&parse(&d).unwrap(), &set));
}

#[test]
fn dsts_separate() {
    // one 32-byte input forced on both kinds
    let a = Fr::from(123u64);
    let pk = g2_encode(&pk_of(&a));
    let (d, s) = group(&[(a, 1), (Fr::from(124u64), 1)], 1);
    let ia = s.iter().position(|x| x.0 == a).unwrap() as u8;
    let x = keccak256(&[&ua_of(&d)[..], &MSG].concat()); // what the member signs
    // a member partial verified as a 0x0106 signature over the same 32 bytes
    let partial = g1_encode(&(hash_to_g1_bls12381(&x, bls_multi::DST_MULTI_SIG) * a).into_affine());
    assert!(!verify(0x0106, &pk, &x, &partial, false, false));
    assert!(ok(&d, &MSG, &[&partial[..], &bls_multi::indices_bitmap(&[ia])].concat()), "positive control");
    // a 0x0106 signature over the same 32 bytes as a one-signer 0x0121 aggregate
    let single = g1_encode(&(hash_to_g1_bls12381(&x, BLS12381_DST_SIG) * a).into_affine());
    assert!(verify(0x0106, &pk, &x, &single, false, false), "positive control");
    assert!(!ok(&d, &MSG, &[&single[..], &bls_multi::indices_bitmap(&[ia])].concat()));
    // a signature under DST_MULTI_POP instead of DST_MULTI_SIG
    assert!(!ok(&d, &MSG, &sign_with(&d, &s, &MSG, &[ia], bls_multi::DST_MULTI_POP)));
    assert_eq!(bls_multi::DST_MULTI_SIG.len(), 53);
    assert_ne!(&bls_multi::DST_MULTI_SIG[..], &bls_multi::DST_MULTI_POP[..]);
}

#[test]
fn cross_group() {
    let (a, b, c) = (Fr::from(201u64), Fr::from(202u64), Fr::from(203u64));
    let (d1, s1) = group(&[(a, 1), (b, 1)], 2);
    let (d2, s2) = group(&[(a, 1), (b, 1), (c, 1)], 2);
    let sig1 = sign(&d1, &s1, &MSG, &[0, 1]);
    assert!(ok(&d1, &MSG, &sig1), "positive control");
    let ab: Vec<u8> = (0..3u8).filter(|i| s2[*i as usize].0 != c).collect();
    let mut x = sig1.clone();
    x[128..].copy_from_slice(&bls_multi::indices_bitmap(&ab));
    assert!(!ok(&d2, &MSG, &x), "G1's aggregate refused for G2");
    assert!(ok(&d2, &MSG, &sign(&d2, &s2, &MSG, &ab)), "G2's own");
}

#[test]
fn pop_check() {
    // the registration PoP: all n members, distinct messages m_i = keccak256(popMsg ‖ pk_i) under DST_MULTI_POP
    let (d, s) = group(&sks(3), 2);
    let pm = [9u8; 32];
    let part = |i: usize| hash_to_g1_bls12381(&bls_multi::pop_member_message(&pm, d[260 + 258 * i..260 + 258 * i + 256].try_into().unwrap()), bls_multi::DST_MULTI_POP) * s[i].0;
    let pop: G1Projective = (0..3).map(part).sum();
    let pop = g1_encode(&pop.into_affine());
    assert!(verify(K, &d, &pm, &pop, true, false));
    let two: G1Projective = (0..2).map(part).sum();
    assert!(!verify(K, &d, &pm, &g1_encode(&two.into_affine()), true, false), "missing one π_i");
    assert!(!verify(K, &d, &pm, &[0u8; 128], true, false), "pop = O");
    assert!(!verify(K, &d, &[8u8; 32], &pop, true, false), "another popMsg");
}
