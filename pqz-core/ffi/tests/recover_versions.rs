// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Group 3g (spec 2026-11-06-pqz-key-versions §3.6, KV-11, Codex #4, §14): the sender's recovery of an audited op 7 after the sender,
//! the receivers and the auditor each rotated: additive, the work the sum of the version lists, never their product. A wallet's
//! reference; `Enc`'s noise draws are checked here not to depend on any key, the premise of the rule. No proof, no chain. UNAUDITED.
use hkdf::Hkdf;
use pqz_ffi::pqzl::{self, EncMulti, Key, PK_BYTES};
use pqz_ffi::selftest::digits;
use sha2::Sha256;

type Pk = [u8; PK_BYTES];

fn keys(tag: u8, n: u8) -> Vec<Key> {
    (0..n).map(|v| pqzl::keygen(&[tag ^ (v << 4); 32]).unwrap()).collect()
}

/// CTR-PQZ-19: `seed_enc = HKDF-SHA256(ikm = pqzKeySeed, salt = "SCAAS-PQZ-ENC-V2", info = chainUid ‖ token ‖ fromUA ‖ be32(counter) ‖ salt)`.
fn seed_enc(key_seed: &[u8; 32], salt: &[u8; 16]) -> [u8; 32] {
    let mut info = vec![0x77; 32 + 20 + 32];
    info.extend_from_slice(&5u32.to_be_bytes());
    info.extend_from_slice(salt);
    let mut out = [0; 32];
    Hkdf::<Sha256>::new(Some(b"SCAAS-PQZ-ENC-V2"), key_seed).expand(&info, &mut out).unwrap();
    out
}

fn enc(pk_f: &Pk, d_f: [u8; 16], legs: &[(&Pk, [u8; 16])], pk_a: Option<&Pk>, seed: &[u8; 32]) -> EncMulti {
    pqzl::enc_multi(pk_f, d_f, legs, pk_a, seed).unwrap()
}

fn view(l: &[(Pk, [u8; 16])]) -> Vec<(&Pk, [u8; 16])> {
    l.iter().map(|x| (&x.0, x.1)).collect()
}

/// The premise (§3.6, "to verify there"): `u`, `r`, `e1` and every `e2`, the attempt counter included, are the same whichever keys
/// the legs, the sender and the auditor have; only each `v` under the key it names differs.
#[test]
fn noise_draws_do_not_depend_on_a_key() {
    // pk_f, pk_a and every leg distinct (review 3w u3-4: `enc_multi` refuses equal keys, as the contract's KV-9)
    let (a, b) = (keys(0x21, 10), keys(0x52, 10));
    let seed = [0x3c; 32];
    for aud in [false, true] {
        for m in [1usize, 2, 3, 4, 5, 8] {
            let amounts: Vec<[u8; 16]> = (0..m).map(|j| digits(1000 + j as u64)).collect();
            let legs = |ks: &[Key]| -> Vec<(Pk, [u8; 16])> { (0..m).map(|j| (*ks[2 + j].pk, amounts[j])).collect() };
            let (la, lb) = (legs(&a), legs(&b));
            let x = enc(&a[0].pk, digits(7), &view(&la), aud.then_some(&*a[1].pk), &seed);
            let y = enc(&b[0].pk, digits(7), &view(&lb), aud.then_some(&*b[1].pk), &seed);
            assert_eq!(x.groups.len(), y.groups.len());
            for (g, h) in x.groups.iter().zip(&y.groups) {
                assert_eq!(g.u, h.u, "u, m = {m}, aud = {aud}");
                assert_eq!(g.r, h.r, "r");
                assert_eq!(g.e1, h.e1, "e1");
                assert_eq!(g.e2, h.e2, "the e2 draws");
                assert_eq!(g.ctr, h.ctr, "the attempt");
            }
            assert_eq!((&x.e2, x.e2_f, &x.e2_a), (&y.e2, y.e2_f, &y.e2_a), "the e2 of each leg");
            assert!(x.v.iter().zip(&y.v).all(|(p, q)| p != q), "another key: another v");
            assert_ne!(x.v_f, y.v_f);
        }
    }
}

/// The leg's stored `v` matched against the UA's versions: the same randomness, one key changed at a time. Returns the index of the
/// matching version, `None` without one; each candidate is one trial encryption.
fn match_version(cands: &[Key], stored: &[u8; 128], trials: &mut usize, trial: impl Fn(&Pk) -> [u8; 128]) -> Option<usize> {
    let mut found = None;
    for (x, k) in cands.iter().enumerate() {
        *trials += 1;
        if &trial(&k.pk) == stored {
            assert!(found.is_none(), "two versions match one leg");
            found = Some(x);
        }
    }
    found
}

/// §14's recovery case: an audited op 7 with `m` legs, each UA at another version, recovered from the stored `u_0`, `v_j`, `v_a,j`, `v_f`.
fn recover(m: usize, n_versions: u8) -> usize {
    let sender = keys(0x11, n_versions);
    let sender_seeds: Vec<[u8; 32]> = (0..n_versions).map(|w| [0x40 ^ w; 32]).collect();
    let (w_true, auditor) = ((n_versions - 1) as usize, keys(0x77, n_versions));
    let receivers: Vec<Vec<Key>> = (0..m).map(|j| keys(0x90 ^ ((j as u8) << 1), n_versions)).collect();
    let amounts: Vec<u64> = (0..m).map(|j| 100 + j as u64).collect();
    let d: Vec<[u8; 16]> = amounts.iter().map(|&a| digits(a)).collect();
    let d_f = digits(9_999);
    let salt = [0xA5; 16];
    // what is stored: each receiver at its own version, the auditor at version 0, the sender at its latest
    let x_true: Vec<usize> = (0..m).map(|j| j % n_versions as usize).collect();
    let legs: Vec<(&Pk, [u8; 16])> = (0..m).map(|j| (&*receivers[j][x_true[j]].pk, d[j])).collect();
    let stored = enc(&sender[w_true].pk, d_f, &legs, Some(&*auditor[0].pk), &seed_enc(&sender_seeds[w_true], &salt));

    let mut trials = 0;
    // 1. the sender's version: `u_0` depends on no receiver key, so the match names w; any key in the other seats, distinct
    // (review 3w u3-4: `enc_multi` refuses two equal keys of one statement, as the contract's KV-9): placeholder keys
    let (dummies, dummy_a) = (keys(0x33, m as u8), keys(0x35, 1).remove(0));
    let any: Vec<(&Pk, [u8; 16])> = (0..m).map(|j| (&*dummies[j].pk, d[j])).collect();
    let mut w_found = None;
    for (w, s) in sender_seeds.iter().enumerate() {
        trials += 1;
        let c = enc(&sender[0].pk, d_f, &any, Some(&*dummy_a.pk), &seed_enc(s, &salt));
        if c.groups[0].u == stored.groups[0].u {
            assert!(w_found.is_none());
            w_found = Some(w);
        }
    }
    assert_eq!(w_found, Some(w_true), "the sender's version");
    let seed = seed_enc(&sender_seeds[w_true], &salt);
    // 3. each leg on its own over its UA's versions, the others left as they are
    let mut got = Vec::new();
    for (j, r) in receivers.iter().enumerate() {
        let x = match_version(r, &stored.v[j], &mut trials, |pk| {
            let mut one = any.clone();
            one[j].0 = pk;
            enc(&sender[w_true].pk, d_f, &one, Some(&*dummy_a.pk), &seed).v[j]
        });
        got.push(x.expect("a leg's version"));
    }
    assert_eq!(got, x_true, "each leg's version");
    // the auditor copy on its own, over the auditor's versions
    for j in 0..m {
        let a = match_version(&auditor, &stored.v_a[j], &mut trials, |pk| enc(&sender[w_true].pk, d_f, &any, Some(pk), &seed).v_a[j]);
        assert_eq!(a, Some(0), "the auditor copy of leg {j}");
    }
    // 4. the whole ciphertext rebuilt from the versions found
    let again: Vec<(&Pk, [u8; 16])> = (0..m).map(|j| (&*receivers[j][got[j]].pk, d[j])).collect();
    let c = enc(&sender[w_true].pk, d_f, &again, Some(&*auditor[0].pk), &seed);
    assert_eq!((&c.v, &c.v_a, c.v_f), (&stored.v, &stored.v_a, stored.v_f), "R rebuilt");
    for (g, h) in c.groups.iter().zip(&stored.groups) {
        assert_eq!(g.u, h.u);
    }
    // the receiver: a consumed credit found by trial decryption, the amount read under the version that opens it
    for (j, r) in receivers.iter().enumerate() {
        let g = j / pqz_ffi::stmt::legs_per_group(true);
        let mut ct = [0u8; pqzl::CT_BYTES];
        ct[..PK_BYTES].copy_from_slice(&stored.groups[g].u[..]);
        ct[PK_BYTES..].copy_from_slice(&stored.v[j]);
        let opened: Vec<usize> = (0..r.len()).filter(|&x| {
            let (msg, _noise) = pqzl::dec(&r[x].s, &ct).unwrap();
            msg.iter().zip(&d[j]).all(|(a, &b)| *a == b as i64)
        }).collect();
        assert_eq!(opened, vec![x_true[j]], "leg {j} opens under its own version only");
    }
    trials
}

#[test]
fn recovery_is_additive_over_the_versions() {
    for (m, n) in [(1usize, 3u8), (3, 3), (8, 3)] {
        let (trials, n) = (recover(m, n), n as usize);
        assert_eq!(trials, n + m * n + m * n, "m = {m}, {n} versions: the sum of the lists, not their product");
    }
}
