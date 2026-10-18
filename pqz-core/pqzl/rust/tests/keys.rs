//! The key methods of `Ctx` (owner 2026-10-18: `Ctx::{keygen, keypair_from_secret, encrypt, enc_seed}` reuse the
//! `Ctx`'s A) are byte-equal to the free functions, on a fresh `Ctx`, and after a `verify` and a `verify_fast` on the
//! same `Ctx` (A and the relation's keys cached by the verifier). The keys KAT runs through the methods too
//! (`keys_kat 1000 ctx`, run.sh).
use pqzl::{enc_seed, encrypt, keygen, keypair_from_secret, Ctx, Enc, Error, Key, POLYVEC_BYTES};

mod common;

fn key_eq(a: &Result<Key, Error>, b: &Result<Key, Error>) -> bool {
    match (a, b) {
        (Ok(a), Ok(b)) => a.pk == b.pk && a.s == b.s && a.e == b.e && a.ctr == b.ctr,
        (Err(a), Err(b)) => a == b,
        _ => false,
    }
}

fn enc_eq(a: &Result<Enc, Error>, b: &Result<Enc, Error>) -> bool {
    match (a, b) {
        (Ok(a), Ok(b)) => a.u == b.u && a.vs == b.vs && a.r == b.r && a.e1 == b.e1 && a.e2 == b.e2 && a.ctr == b.ctr,
        (Err(a), Err(b)) => a == b,
        _ => false,
    }
}

/// every method = its free function over 6 seeds (encryptions to 1, 2 and 3 recipients, and Enc's input errors),
/// before and after verify / verify_fast on the same `Ctx`
#[test]
fn ctx_eq_free() {
    let row = common::pqzl_rows().into_iter().find(|r| r.code == 1).unwrap();
    let mut c = Ctx::new();
    for round in 0..2 {
        if round == 1 {
            assert!(c.verify(row.op, &row.stmt, &row.proof));
            assert!(c.verify_fast(row.op, &row.stmt, &row.proof));
        }
        let mut keys = Vec::new();
        for i in 0..6u8 {
            let seed: [u8; 32] = core::array::from_fn(|j| (37 * i as usize + j + round) as u8);
            let (k, kc) = (keygen(&seed), c.keygen(&seed));
            assert!(key_eq(&k, &kc), "keygen seed {i} round {round}");
            let k = k.unwrap();
            let (p, pc) = (keypair_from_secret(&k.s, &k.e), c.keypair_from_secret(&k.s, &k.e));
            assert_eq!(p, pc, "keypair_from_secret seed {i}");
            assert_eq!(p.unwrap(), k.pk);
            keys.push(k);
        }
        for i in 0..6 {
            let n = 1 + i % 3;
            let pks: Vec<&[u8; POLYVEC_BYTES]> = (0..n).map(|j| &*keys[(i + j) % 6].pk).collect();
            let msgs: Vec<[u8; 16]> = (0..n).map(|j| core::array::from_fn(|d| ((i * 7 + j * 3 + d) % 16) as u8)).collect();
            let se: [u8; 32] = core::array::from_fn(|j| (11 * i + j + 100 * round) as u8);
            let (e, ec) = (enc_seed(&pks, &msgs, &se), c.enc_seed(&pks, &msgs, &se));
            assert!(enc_eq(&e, &ec), "enc_seed {i} round {round}");
            let e = e.unwrap();
            let (x, xc) = (encrypt(&pks, &msgs, &e.r, &e.e1, &e.e2), c.encrypt(&pks, &msgs, &e.r, &e.e1, &e.e2));
            assert!(enc_eq(&x, &xc), "encrypt {i}");
            let x = x.unwrap();
            assert_eq!((x.u, x.vs), (e.u, e.vs), "encrypt = enc_seed's ciphertext {i}");
        }
        // input errors: a digit > 15, a non-canonical key, counts that disagree
        let pk = &*keys[0].pk;
        let mut bad = Box::new(*pk);
        bad[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        let (m16, se) = ([[16u8; 16]], [0u8; 32]);
        for (pks, msgs) in [(vec![pk], &m16[..]), (vec![&*bad], &[[0u8; 16]][..]), (vec![pk, pk], &[[0u8; 16]][..])] {
            assert!(enc_eq(&enc_seed(&pks, msgs, &se), &c.enc_seed(&pks, msgs, &se)));
            assert_eq!(enc_seed(&pks, msgs, &se).err(), Some(Error::Input));
        }
        let k = &keys[0];
        let e2 = [[0i16; 16]; 2];
        assert!(enc_eq(&encrypt(&[pk], &[[0; 16]], &k.s, &k.e, &e2), &c.encrypt(&[pk], &[[0; 16]], &k.s, &k.e, &e2)));
    }
    // the verifiers still accept after the key methods
    assert!(c.verify(row.op, &row.stmt, &row.proof));
    assert!(c.verify_fast(row.op, &row.stmt, &row.proof));
}
