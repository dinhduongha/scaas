//! Keys, Enc and Dec against the C core (feature `c-oracle`): seeded inputs, Rust = C (outputs and error codes),
//! including what the vectors and the keys KAT never feed: short vectors over the whole i8 / i16 range, digits up to
//! 255 and non-canonical pk / u / v coefficients (up to 2^64 - 1) into `encrypt` / `decrypt_raw`, which check nothing,
//! and non-canonical ciphertexts and keys into `dec` / `enc_seed`, which reject them.
use pqzl::c_oracle::{c_dec, c_decrypt_raw, c_enc_group_seed, c_enc_seed, c_encrypt, c_keygen, c_keypair_from_secret};
use pqzl::{dec, decrypt_raw, enc_group_seed, enc_seed, encrypt, keygen, keypair_from_secret, CT_BYTES, POLYVEC_BYTES,
           V_BYTES};

const N: usize = 200;
const Q: u64 = pqzl::Q;

/// xorshift64*
struct Rnd(u64);

impl Rnd {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(2_685_821_657_736_338_717)
    }

    fn seed(&mut self) -> [u8; 32] {
        core::array::from_fn(|_| self.next() as u8)
    }

    /// n be8 coefficients: canonical, or (one call in 4) each one in 8 any u64 (q, near 2^63, 2^64 - 1 ...)
    fn coeffs(&mut self, out: &mut [u8]) {
        let wild = self.next().is_multiple_of(4);
        for c in out.chunks_mut(8) {
            let v = match (wild, self.next() % 8) {
                (true, 0) => [Q, Q + 1, 1 << 63, (1 << 63) + 5, u64::MAX, (1 << 63) - 1][(self.next() % 6) as usize],
                (true, 1) => self.next(),
                _ => self.next() % Q,
            };
            c.copy_from_slice(&v.to_be_bytes());
        }
    }

    fn pk(&mut self) -> Box<[u8; POLYVEC_BYTES]> {
        let mut p = Box::new([0u8; POLYVEC_BYTES]);
        self.coeffs(&mut p[..]);
        p
    }
}

#[test]
fn keypair_encrypt_decrypt_raw_eq_c() {
    let mut rnd = Rnd(0x6b65_7973_2d6f_7261);
    for it in 0..N {
        let s: [i8; pqzl::N] = core::array::from_fn(|_| rnd.next() as i8);
        let e: [i16; pqzl::N] = core::array::from_fn(|_| rnd.next() as i16);
        let pk = keypair_from_secret(&s, &e);
        assert_eq!(pk.as_ref().ok(), c_keypair_from_secret(&s, &e).as_ref().ok(), "keypair_from_secret {it}");

        let npk = (rnd.next() % 4) as usize;
        let pks: Vec<_> = (0..npk).map(|_| rnd.pk()).collect();
        let pkr: Vec<&[u8; POLYVEC_BYTES]> = pks.iter().map(|p| &**p).collect();
        let msgs: Vec<[u8; 16]> = (0..npk).map(|_| core::array::from_fn(|_| rnd.next() as u8)).collect();
        let r: [i8; pqzl::N] = core::array::from_fn(|_| rnd.next() as i8);
        let e1: [i16; pqzl::N] = core::array::from_fn(|_| rnd.next() as i16);
        let e2: Vec<[i16; 16]> = (0..npk).map(|_| core::array::from_fn(|_| rnd.next() as i16)).collect();
        let c = encrypt(&pkr, &msgs, &r, &e1, &e2).expect("encrypt");
        let (u, vs) = c_encrypt(&pkr, &msgs, &r, &e1, &e2).expect("c encrypt");
        assert_eq!((&c.u, &c.vs), (&u, &vs), "encrypt {it} (npk {npk})");
        assert_eq!((&*c.r, &*c.e1, &c.e2, c.ctr), (&r, &e1, &e2, 0));

        let mut u = rnd.pk();
        let mut v = [0u8; V_BYTES];
        rnd.coeffs(&mut v);
        if it % 2 == 0 {
            u.copy_from_slice(&c.u[..]); // a real u half the time
        }
        assert_eq!(decrypt_raw(&s, &u, &v), c_decrypt_raw(&s, &u, &v), "decrypt_raw {it}");
    }
}

#[test]
fn keygen_enc_dec_eq_c() {
    let mut rnd = Rnd(0x656e_632d_6465_632e);
    let (mut rejected, mut ok) = (0, 0);
    for it in 0..N {
        let sd = rnd.seed();
        let (k, kc) = (keygen(&sd).expect("keygen"), c_keygen(&sd).expect("c keygen"));
        assert_eq!((&k.pk, &k.s, &k.e, k.ctr), (&kc.pk, &kc.s, &kc.e, kc.ctr), "keygen {it}");

        let npk = (rnd.next() % 4) as usize;
        let mut pks: Vec<_> = (0..npk).map(|_| k.pk.clone()).collect();
        let mut msgs: Vec<[u8; 16]> = (0..npk).map(|_| core::array::from_fn(|_| (rnd.next() % 16) as u8)).collect();
        match rnd.next() % 8 {
            0 if npk > 0 => pks[npk - 1] = rnd.pk(), // canonical or not
            1 if npk > 0 => msgs[0][(rnd.next() % 16) as usize] = 16 + (rnd.next() % 240) as u8,
            _ => {}
        }
        let pkr: Vec<&[u8; POLYVEC_BYTES]> = pks.iter().map(|p| &**p).collect();
        let se = rnd.seed();
        let c = enc_seed(&pkr, &msgs, &se);
        let cc = c_enc_seed(&pkr, &msgs, &se);
        match (&c, &cc) {
            (Ok(c), Ok(cc)) => {
                assert_eq!((&c.u, &c.vs, &c.r, &c.e1, &c.e2, c.ctr), (&cc.u, &cc.vs, &cc.r, &cc.e1, &cc.e2, cc.ctr));
                ok += 1;
            }
            (a, b) => {
                assert_eq!(a.as_ref().err(), b.as_ref().err(), "enc_seed {it}");
                rejected += 1;
            }
        }

        let mut ct = Box::new([0u8; CT_BYTES]);
        rnd.coeffs(&mut ct[..]);
        if let (Ok(c), true) = (&c, rnd.next().is_multiple_of(2)) {
            if let Some(v) = c.vs.first() {
                ct[..POLYVEC_BYTES].copy_from_slice(&c.u[..]); // a real ciphertext half the time
                ct[POLYVEC_BYTES..].copy_from_slice(v);
            }
        }
        assert_eq!(dec(&k.s, &ct), c_dec(&k.s, &ct), "dec {it}");

        let g = [0, 1, rnd.next() as u32][it % 3];
        assert_eq!(enc_group_seed(&se, g), c_enc_group_seed(&se, g), "enc_group_seed {it} g {g}");
    }
    println!("keygen_enc_dec_eq_c: {ok} encryptions, {rejected} rejected inputs, all equal");
    assert!(ok >= N / 2 && rejected >= N / 20, "ok {ok}, rejected {rejected}");
}
