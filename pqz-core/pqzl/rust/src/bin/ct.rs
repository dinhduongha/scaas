//! The constant-time check of the prover under valgrind memcheck (ctgrind; review fix E, pqzl/test/ct.sh's Rust
//! twin): `ct [rels] [nprove]` proves with the witness and rnd32 marked secret (`Bench::prove_ct`); memcheck reports
//! every branch or address that depends on them. A third argument runs that many rounds of KeyGen (seed secret), Enc to
//! two recipients (seed_enc and the digits secret) and Dec (s secret). Run by `pqzl/test/ct.sh` (feature `ctgrind`, x86-64 only).
use pqzl::bench::{Bench, NAMES, NREL};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let arg = |i: usize, d: u32| a.get(i).map_or(d, |s| s.parse().expect("a number"));
    let (rels, np, nk) = (arg(1, 1), arg(2, 1), arg(3, 0));
    let mut b = Bench::new().expect("init");
    let mut fails = 0;
    for tx in (0..NREL).filter(|&t| rels >> t & 1 == 1) {
        for i in 0..np {
            let rc = b.prove_ct(tx, i);
            let ok = rc.is_ok() && b.verify(tx);
            println!("{{\"rel\": \"{}\", \"run\": {i}, \"prove\": \"{rc:?}\", \"verify\": {ok}, \"fnv\": \"{:08x}\"}}", NAMES[tx], b.hash(tx));
            fails += !ok as u32;
        }
    }
    for i in 0..nk {
        let mut keys = Vec::new();
        for k in 0..2u32 {
            let seed: [u8; 32] = core::array::from_fn(|j| (31 * i + 7 * k + j as u32) as u8);
            pqzl::ct::secret(&seed);
            let key = pqzl::keygen(&seed).expect("keygen");
            pqzl::ct::public(&key.pk[..]); // the public key
            keys.push(key);
        }
        let seed_enc: [u8; 32] = core::array::from_fn(|j| (17 * i + j as u32) as u8);
        let msgs: [[u8; 16]; 2] = [
            core::array::from_fn(|j| ((i + j as u32) & 15) as u8),
            core::array::from_fn(|j| ((3 * i + 5 * j as u32) & 15) as u8),
        ];
        pqzl::ct::secret(&seed_enc);
        pqzl::ct::secret(&msgs);
        let pks = [&*keys[0].pk, &*keys[1].pk];
        let enc = pqzl::enc_seed(&pks, &msgs, &seed_enc).expect("enc");
        pqzl::ct::public(&enc.u[..]); // the ciphertext
        pqzl::ct::public(&enc.vs[..]);
        pqzl::ct::public(&msgs);
        let mut ok = true;
        for (k, key) in keys.iter().enumerate() {
            let mut ct = [0u8; pqzl::CT_BYTES];
            ct[..pqzl::POLYVEC_BYTES].copy_from_slice(&enc.u[..]);
            ct[pqzl::POLYVEC_BYTES..].copy_from_slice(&enc.vs[k]);
            let (m, _) = pqzl::dec(&key.s, &ct).expect("dec");
            pqzl::ct::public(&m); // the driver checks the plaintext
            ok &= m.iter().zip(&msgs[k]).all(|(&a, &b)| a == b as i64);
        }
        println!("{{\"keys\": {i}, \"dec_ok\": {ok}, \"ctr\": [{}, {}]}}", keys[1].ctr, enc.ctr);
        fails += !ok as u32;
    }
    println!("{{\"fails\": {fails}}}");
    std::process::exit((fails != 0) as i32);
}
