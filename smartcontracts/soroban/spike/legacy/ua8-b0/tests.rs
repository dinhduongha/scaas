// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Moved from ua-spike; see README.md. Not built.
// --- B0 (plan ua8-soroban B0): the full PQZ + KEM registration, the split, set_kem_key, set_pqz_key ---
use crate::{kc, umsg, Registration, UaAttrs, P_KEM, P_MEMBER, P_POP_V2, P_PQZ_KEY};
use ml_dsa::{Keypair, MlDsa65, Seed, SigningKey};

const SETS: [&str; 4] = ["n2048-kmax1024", "n2304-kmax4096", "n2560-kmax16384", "n2816-kmax65536"];

fn bx(env: &Env, r: &Value, k: &str) -> Bytes {
    b(env, &hx(r[k].as_str().unwrap()))
}

fn b32(env: &Env, s: &str) -> BytesN<32> {
    BytesN::from_array(env, &hx(s).try_into().unwrap())
}

fn attrs_of(env: &Env, r: &Value) -> UaAttrs {
    let a = &r["attrs"];
    UaAttrs {
        pqz_key: bx(env, a, "pqzKey"),
        pqz_pop_hash: b32(env, a["pqzPopHash"].as_str().unwrap()),
        kem_version: 0, // a KEM key given at registration is version 0 (typed-signing P1b); the row carries no version
        kem_pk: bx(env, a, "kemPk"),
    }
}

fn empty_attrs(env: &Env) -> UaAttrs {
    UaAttrs { pqz_key: Bytes::new(env), pqz_pop_hash: BytesN::from_array(env, &[0; 32]), kem_version: 0, kem_pk: Bytes::new(env) }
}

fn rec(env: &Env, c: &UaSpikeClient, ua: &BytesN<32>) -> Registration {
    env.as_contract(&c.address, || env.storage().persistent().get(&crate::Key::Ua(ua.clone())).unwrap())
}

/// `n` ML-DSA-65 members (fixed seeds), seeded as signable records, sorted by id: (id, signing key, pk).
fn members(env: &Env, c: &UaSpikeClient, n: u8) -> StdVec<(BytesN<32>, SigningKey<MlDsa65>, Bytes)> {
    let mut out: StdVec<_> = (0..n)
        .map(|i| {
            let sk = SigningKey::<MlDsa65>::from_seed(&Seed::from([i + 1; 32]));
            let pk = b(env, sk.verifying_key().encode().as_slice());
            (c.seed(&K_MLDSA65, &pk, &None), sk, pk)
        })
        .collect();
    out.sort_by_key(|m| m.0.to_array());
    out
}

fn sign(sk: &SigningKey<MlDsa65>, env: &Env, kind: u32, m: &BytesN<32>) -> StdVec<u8> {
    let pq = kc(env, &[&crate::tag32(kind), &m.to_array()]);
    sk.expanded_key().sign_deterministic(&pq.to_array(), &[]).unwrap().encode().as_slice().to_vec()
}

fn w(v: u32) -> [u8; 32] {
    let mut x = [0u8; 32];
    x[28..].copy_from_slice(&v.to_be_bytes());
    x
}

/// abi.encode(MemberSig[]) with empty keyData (UA8-D5; owner ruling 2026-10-30).
fn member_sigs(sigs: &[(u32, StdVec<u8>)]) -> StdVec<u8> {
    let pad = |n: usize| (n + 31) / 32 * 32;
    let tuples: StdVec<StdVec<u8>> = sigs
        .iter()
        .map(|(i, s)| {
            let mut t = [w(*i), w(96), w(128), w(0), w(s.len() as u32)].concat();
            t.extend_from_slice(s);
            t.resize(160 + pad(s.len()), 0);
            t
        })
        .collect();
    let mut out = [w(32), w(sigs.len() as u32)].concat();
    let mut off = 32 * sigs.len();
    for t in &tuples {
        out.extend_from_slice(&w(off as u32));
        off += t.len();
    }
    tuples.iter().for_each(|t| out.extend_from_slice(t));
    out
}

/// An msig over `ms` (weights 1, threshold `threshold`): key data, id.
fn msig_kd(env: &Env, ms: &[(BytesN<32>, SigningKey<MlDsa65>, Bytes)], threshold: u16) -> (Bytes, BytesN<32>) {
    let mut kd = [threshold.to_be_bytes(), (ms.len() as u16).to_be_bytes()].concat();
    for (id, _, _) in ms {
        kd.extend_from_slice(&(K_MLDSA65 as u16).to_be_bytes());
        kd.extend_from_slice(&id.to_array());
        kd.extend_from_slice(&1u16.to_be_bytes());
    }
    let kd = b(env, &kd);
    let id = tagged(env, K_MSIG, &kd);
    (kd, id)
}

/// The msig's stored signature over `ua_message(MSIG, purpose, digest)`: every member signs (minimal when threshold = n).
fn msig_sig(env: &Env, ms: &[(BytesN<32>, SigningKey<MlDsa65>, Bytes)], ua: &BytesN<32>, purpose: &[u8; 32], digest: &BytesN<32>) -> Bytes {
    let md = kc(env, &[&ua.to_array(), &umsg(env, K_MSIG, purpose, digest).to_array()]);
    let m = umsg(env, K_MLDSA65, &P_MEMBER, &md);
    let sigs: StdVec<_> = ms.iter().enumerate().map(|(i, (_, sk, _))| (i as u32, sign(sk, env, K_MLDSA65, &m))).collect();
    b(env, &member_sigs(&sigs))
}

/// The `register` digest (UA8-D1) of `attrs` for `ua`.
fn reg_digest(env: &Env, ua: &BytesN<32>, a: &UaAttrs) -> BytesN<32> {
    let z = [0u8; 32];
    let pkh = if a.pqz_key.is_empty() { z } else { crate::kb(env, &crate::GROUP_PQZ, &a.pqz_key).to_array() };
    let kem = if a.kem_version == 0 { z } else { crate::kem_record_digest(env, ua, a.kem_version, &a.kem_pk).to_array() };
    let portable = kc(env, &[&P_POP_V2, &ua.to_array(), &pkh, &kem]);
    kc(env, &[&portable.to_array(), &a.pqz_pop_hash.to_array()])
}

#[test]
fn spike_register_pqz_kem_model_budget() {
    for set in SETS {
        // mldsa65/<set>: the real row, so the digests and the pop are the vectors'
        let (env, c) = setup();
        let r = row(&std::format!("mldsa65/{set}"));
        let (kd, a, pop, pp) = (bx(&env, &r, "keyData"), attrs_of(&env, &r), bx(&env, &r, "pop"), bx(&env, &r, "pqzPop"));
        let mut bad = hx(r["pqzPop"].as_str().unwrap());
        bad[7] ^= 1;
        assert!(c.try_register_pqz_kem_model(&K_MLDSA65, &kd, &a, &pop, &b(&env, &bad)).is_err(), "PqzPopHash");
        let id = measure(&env, &std::format!("register_pqz_kem_model mldsa65 {set} full"), || {
            c.register_pqz_kem_model(&K_MLDSA65, &kd, &a, &pop, &pp)
        });
        assert_eq!(id.to_array().to_vec(), hx(r["ua"].as_str().unwrap()));
        let stored = rec(&env, &c, &id);
        assert!(stored.attrs.pqz_key.is_empty() && stored.attrs.kem_pk.is_empty() && !stored.proven);
        env.as_contract(&c.address, || {
            let s = env.storage().persistent();
            let (k, _, _, _): (Bytes, BytesN<32>, Bytes, crate::Checked) = s.get(&crate::Key::PqzK(id.clone())).unwrap();
            assert_eq!(k, a.pqz_key, "the PQZ key bytes in state");
            assert_eq!(s.get::<_, Bytes>(&crate::Key::PqzP(id.clone())).unwrap(), pp, "the proof bytes in state");
        });
        assert!(c.try_register_pqz_kem_model(&K_MLDSA65, &kd, &a, &pop, &pp).is_err(), "already registered");

        // msig-pq/<set>: two ML-DSA-65 members (mldsa65#1, #2), the row's member-signed pop
        let (env, c) = setup();
        for m in ["mldsa65#1", "mldsa65#2"] {
            c.seed(&K_MLDSA65, &bx(&env, &row(m), "keyData"), &None);
        }
        let r = row(&std::format!("msig-pq/{set}"));
        let (kd, a, pop, pp) = (bx(&env, &r, "keyData"), attrs_of(&env, &r), bx(&env, &r, "pop"), bx(&env, &r, "pqzPop"));
        let id = measure(&env, &std::format!("register_pqz_kem_model msig-pq n=2 {set} full"), || {
            c.register_pqz_kem_model(&K_MSIG, &kd, &a, &pop, &pp)
        });
        assert_eq!(id.to_array().to_vec(), hx(r["ua"].as_str().unwrap()));
    }
}

#[test]
fn spike_register_split_and_store_pqz_pop_budget() {
    for set in SETS {
        let (env, c) = setup();
        let r = row(&std::format!("mldsa65/{set}"));
        let (kd, a, pop, pp) = (bx(&env, &r, "keyData"), attrs_of(&env, &r), bx(&env, &r, "pop"), bx(&env, &r, "pqzPop"));
        let id = measure(&env, &std::format!("register_pqz_kem_model mldsa65 {set} split"), || {
            c.register_pqz_kem_model(&K_MLDSA65, &kd, &a, &pop, &Bytes::new(&env))
        });
        assert!(!env.as_contract(&c.address, || env.storage().persistent().has(&crate::Key::PqzP(id.clone()))));
        let mut bad = hx(r["pqzPop"].as_str().unwrap());
        bad[0] ^= 1;
        assert!(c.try_store_pqz_pop_model(&id, &b(&env, &bad)).is_err(), "PqzPopHash");
        measure(&env, &std::format!("store_pqz_pop_model {set}"), || c.store_pqz_pop_model(&id, &pp));
        c.store_pqz_pop_model(&id, &pp); // stored: a no-op
    }
}

#[test]
fn spike_msig_pqz_kem_model_budget() {
    let set = "n2816-kmax65536";
    let r = row(&std::format!("mldsa65/{set}"));
    for n in [2u8, 4, 8, 16] {
        let (env, c) = setup();
        env.cost_estimate().disable_resource_limits(); // the network run is the gate; print every n
        let ms = members(&env, &c, n);
        let a = attrs_of(&env, &r);
        let pp = bx(&env, &r, "pqzPop");
        let (kd, id) = msig_kd(&env, &ms, n as u16);
        let pop = msig_sig(&env, &ms, &id, &P_POP_V2, &reg_digest(&env, &id, &a));
        if n == 2 {
            // U8S-D1: threshold 1 with both slots signed: T − w_min = 1 ≥ N = 1, a redundant slot
            let (kd1, id1) = msig_kd(&env, &ms, 1);
            let pop1 = msig_sig(&env, &ms, &id1, &P_POP_V2, &reg_digest(&env, &id1, &a));
            assert!(c.try_register_pqz_kem_model(&K_MSIG, &kd1, &a, &pop1, &pp).is_err(), "msig pop not minimal");
        }
        let got = measure(&env, &std::format!("register_pqz_kem_model msig n={n} mldsa65 {set} full"), || {
            c.register_pqz_kem_model(&K_MSIG, &kd, &a, &pop, &pp)
        });
        assert_eq!(got, id);
    }
}

/// A single `mldsa65` UA (member 0) and an `msig` of 16, both registered without PQZ / KEM attributes.
fn targets(env: &Env, c: &UaSpikeClient) -> StdVec<(StdVec<(BytesN<32>, SigningKey<MlDsa65>, Bytes)>, BytesN<32>)> {
    let ms = members(env, c, 16);
    let (kd, id) = msig_kd(env, &ms, 16);
    let pop = msig_sig(env, &ms, &id, &P_POP_V2, &reg_digest(env, &id, &empty_attrs(env)));
    assert_eq!(c.register_pqz_kem_model(&K_MSIG, &kd, &empty_attrs(env), &pop, &Bytes::new(env)), id);
    std::vec![(StdVec::from([ms[0].clone()]), ms[0].0.clone()), (ms, id)]
}

fn sig_by(env: &Env, ms: &[(BytesN<32>, SigningKey<MlDsa65>, Bytes)], ua: &BytesN<32>, purpose: &[u8; 32], d: &BytesN<32>) -> Bytes {
    if ms.len() == 1 && ms[0].0 == *ua {
        b(env, &sign(&ms[0].1, env, K_MLDSA65, &umsg(env, K_MLDSA65, purpose, d)))
    } else {
        msig_sig(env, ms, ua, purpose, d)
    }
}

#[test]
fn spike_set_kem_key_model_budget() {
    let (env, c) = setup();
    env.cost_estimate().disable_resource_limits();
    let kem = bx(&env, &row("mldsa65/n2816-kmax65536")["attrs"], "kemPk");
    for (ms, ua) in targets(&env, &c) {
        let d = crate::kem_record_digest(&env, &ua, 1, &kem);
        let sig = sig_by(&env, &ms, &ua, &P_KEM, &d);
        let label = std::format!("set_kem_key_model v1 n={}", ms.len());
        measure(&env, &label, || c.set_kem_key_model(&ua, &1, &kem, &sig));
        assert!(c.try_set_kem_key_model(&ua, &1, &kem, &sig).is_err(), "KemVersion: once");
    }
}

#[test]
fn spike_set_pqz_key_model_budget() {
    let (env, c) = setup();
    env.cost_estimate().disable_resource_limits();
    let r = row("mldsa65/n2816-kmax65536");
    let a = attrs_of(&env, &r);
    for (ms, ua) in targets(&env, &c) {
        let kh = crate::kb(&env, &crate::GROUP_PQZ, &a.pqz_key);
        let key_digest = kc(&env, &[&crate::PQZ_KEY_RECORD_TAG, &ua.to_array(), &kh.to_array()]);
        let d = kc(&env, &[&key_digest.to_array(), &a.pqz_pop_hash.to_array()]);
        let sig = sig_by(&env, &ms, &ua, &P_PQZ_KEY, &d);
        let label = std::format!("set_pqz_key_model n2816-kmax65536 n={}", ms.len());
        measure(&env, &label, || c.set_pqz_key_model(&ua, &a.pqz_key, &a.pqz_pop_hash, &sig));
        assert!(c.try_set_pqz_key_model(&ua, &a.pqz_key, &a.pqz_pop_hash, &sig).is_err(), "PqzKeySet: write-once");
    }
}

#[test]
fn spike_keccak_budget() {
    let (env, c) = setup();
    for (n, len) in [(1u32, 64u32), (100, 64), (100, 256), (1, 8_192)] {
        measure(&env, &std::format!("keccak_model n={n} len={len}"), || c.keccak_model(&n, &len));
    }
}
