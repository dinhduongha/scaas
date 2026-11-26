// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Falcon-padded-512 / -1024 on wasm32 (CLI-UAL-66): falcon-rs 0.3.1 (vendor/falcon-rs-0.3.1, a port of the round-3
//! reference, feature `fpemu`), the format and algorithm of the vendored PQClean that native builds use. The key pair of a 48-byte
//! seed: SHAKE256 of the seed as keygen's stream (seeded.c `keypair`). A signature: `rnd` = the 40-byte nonce, then the 48-byte
//! seed of the sampler's SHAKE256 stream, `HashToPoint(SHAKE256(nonce ‖ m))`, padded, retried on the same stream when it does
//! not fit (seeded.c `do_sign`). Verify: the padded format only, trailing bytes zero. The caller (src/falcon.rs) checks every
//! length first. tests/fndsa_vrfy.rs includes this file as it is and runs it beside PQClean on every row.
//!
//! Byte-equal to PQClean, with two known differences of falcon-rs's `fpemu` (Fable audit FR-1, FR-2): key pairs are equal;
//! a signature equals PQClean's for the same `(sk, m, rnd)` except with probability about 2^-39 per signature, where
//! `fpr_expm_p63` (emulated binary64 Horner; PQClean clean: 64-bit fixed point) tips one `BerExp` decision, and then both are
//! valid: nothing may rely on signature bytes being equal across platforms. Signed zero differs in `fpr_floor`, `fpr_half`,
//! `fpr_sqrt` and `fpr_lt`, which a hashed target does not reach.
//!
//! Only `::falcon::falcon::*` and its context type `::falcon::shake::InnerShake256Context` (FR-8): the crate's other public
//! modules (`sign`, `keygen`, `vrfy`, `fft`, `codec`) take buffers whose size and alignment they check in debug builds only;
//! tests/fndsa_vrfy.rs `soft_uses_the_round3_api_only` refuses any other path here.
//!
//! The message is public (`ua_msg`, CTR-UA-23) and must stay so: the padded signer hashes it to a point in variable time
//! (`hash_to_point_vartime`, FR-7), so never a secret message through this path. This file's buffers are cleared (`zeroize`)
//! before return; inside falcon-rs the sampler, the ffSampling scratch and `s1` are wiped on drop, but a candidate the padded
//! retry rejects (`sv_buf`, a second signature on the same hash point) is freed unwiped (FR-6, open upstream).
//! falcon-rs stops where the C loops: key generation after 1,000 attempts ([`KEYGEN_CAP`], a named error in src/falcon.rs),
//! and its sampler panics after 1,000 rejections. Both have probability below 2^-1000 with a working stream; on wasm32 a panic
//! aborts (the target's `panic = "abort"`: nothing to catch), so the sampler's stays a panic (FR-9). UNAUDITED.
use ::falcon::falcon as r3;
use ::falcon::shake::InnerShake256Context;
use zeroize::Zeroize;

/// falcon-rs's code when key generation gave up after its 1,000 attempts.
#[allow(dead_code)]
pub const KEYGEN_CAP: i32 = r3::FALCON_ERR_RANDOM;

fn wipe(b: &mut [u8], rng: &mut InnerShake256Context) {
    b.zeroize();
    *rng = InnerShake256Context::new(); // the old state zeroizes on drop
}

/// The key pair of `seed` into `pk` and `sk` at degree `2^logn`: falcon-rs's code, 0 on success, [`KEYGEN_CAP`] when it
/// gave up.
#[allow(dead_code)]
pub fn keypair(logn: u32, seed: &[u8], pk: &mut [u8], sk: &mut [u8]) -> i32 {
    let mut rng = InnerShake256Context::new();
    r3::shake256_init_prng_from_seed(&mut rng, seed);
    let mut tmp = vec![0u8; r3::falcon_tmpsize_keygen(logn)];
    let rc = r3::falcon_keygen_make(&mut rng, logn, sk, Some(pk), &mut tmp);
    wipe(&mut tmp, &mut rng);
    rc
}

/// The padded signature of public `m` with `sk` and `rnd` (nonce ‖ sampler seed) into `sig`; `false` if falcon-rs refuses.
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
