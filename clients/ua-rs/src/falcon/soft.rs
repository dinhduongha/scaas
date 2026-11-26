// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Falcon-padded-512 / -1024 on wasm32 (CLI-UAL-66): falcon-rs 0.4.0's `round3` module (falcon-rs 0.3.1, a port of the
//! round-3 reference), the format and algorithm of the vendored PQClean that native builds use. The key pair of a 48-byte
//! seed: SHAKE256 of the seed as keygen's stream (seeded.c `keypair`). A signature: `rnd` = the 40-byte nonce, then the 48-byte
//! seed of the sampler's SHAKE256 stream, `HashToPoint(SHAKE256(nonce ‖ m))`, padded, retried on the same stream when it does
//! not fit (seeded.c `do_sign`). Verify: the padded format only, trailing bytes zero. The caller (src/falcon.rs) checks every
//! length first. tests/fndsa_vrfy.rs includes this file as it is and runs it beside PQClean on every row. Secrets in this
//! file's buffers are cleared before return; falcon-rs's own internals clear none (a stated residual, as PQClean's).
//! UNAUDITED.
use ::falcon::round3::falcon as r3;
use ::falcon::round3::shake::InnerShake256Context;

fn wipe(b: &mut [u8], rng: &mut InnerShake256Context) {
    b.fill(0);
    *rng = InnerShake256Context::new();
    core::hint::black_box((b, rng));
}

/// The key pair of `seed` into `pk` and `sk` at degree `2^logn`; `false` if falcon-rs refuses.
#[allow(dead_code)]
pub fn keypair(logn: u32, seed: &[u8], pk: &mut [u8], sk: &mut [u8]) -> bool {
    let mut rng = InnerShake256Context::new();
    r3::shake256_init_prng_from_seed(&mut rng, seed);
    let mut tmp = vec![0u8; r3::falcon_tmpsize_keygen(logn)];
    let rc = r3::falcon_keygen_make(&mut rng, logn, sk, Some(pk), &mut tmp);
    wipe(&mut tmp, &mut rng);
    rc == 0
}

/// The padded signature of `m` with `sk` and `rnd` (nonce ‖ sampler seed) into `sig`; `false` if falcon-rs refuses.
#[allow(dead_code)]
pub fn sign(logn: u32, sk: &[u8], m: &[u8], rnd: &[u8], sig: &mut [u8]) -> bool {
    let (nonce, seed) = rnd.split_at(40);
    let mut hash = InnerShake256Context::new();
    r3::shake256_init(&mut hash);
    r3::shake256_inject(&mut hash, nonce);
    r3::shake256_inject(&mut hash, m);
    let mut rng = InnerShake256Context::new();
    r3::shake256_init_prng_from_seed(&mut rng, seed);
    let mut tmp = vec![0u8; r3::falcon_tmpsize_signdyn(logn)];
    let mut len = sig.len();
    let rc = r3::falcon_sign_dyn_finish(
        &mut rng,
        sig,
        &mut len,
        r3::FALCON_SIG_PADDED,
        sk,
        &mut hash,
        nonce,
        &mut tmp,
    );
    wipe(&mut tmp, &mut rng);
    rc == 0 && len == sig.len()
}

/// Whether `sig` is a valid padded signature of `m` under `pk` at degree `2^logn`.
pub fn verify(logn: u32, pk: &[u8], m: &[u8], sig: &[u8]) -> bool {
    let mut tmp = vec![0u8; r3::falcon_tmpsize_verify(logn)];
    r3::falcon_verify(sig, r3::FALCON_SIG_PADDED, pk, m, &mut tmp) == 0
}
