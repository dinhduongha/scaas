// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Feature `pq`: PQClean Falcon-padded-512 / -1024 (clean), vendored with its randomness passed in
//! (vendor/pqclean-falcon-seeded, MD-8; replaces `pqcrypto-falcon`, RUSTSEC-2026-0162/-0163/-0165). Every length is checked
//! here before a pointer reaches the C code, which reads fixed sizes. Without `cfg(scaas_falcon)` (wasm32: no libc for
//! the C code) nothing is built: no key, no signature, and no signature verifies. UNAUDITED.

/// The parameters of one degree: log2 of the degree, public key, secret key and padded signature lengths.
#[derive(Clone, Copy)]
pub(crate) struct Params {
    #[cfg_attr(not(scaas_falcon), allow(dead_code))]
    pub logn: u8,
    pub pk: usize,
    #[cfg_attr(not(feature = "wallet"), allow(dead_code))]
    pub sk: usize,
    pub sig: usize,
}

pub(crate) const FNDSA512: Params = Params { logn: 9, pk: 897, sk: 1281, sig: 666 };
pub(crate) const FNDSA1024: Params = Params { logn: 10, pk: 1793, sk: 2305, sig: 1280 };
/// The keygen seed (clientkeys' 48-byte `pqSeed`).
#[cfg_attr(not(feature = "wallet"), allow(dead_code))]
pub(crate) const SEED_LEN: usize = 48;
/// A signature's randomness: the 40-byte nonce, then the 48-byte seed of the sampler.
#[cfg_attr(not(feature = "wallet"), allow(dead_code))]
pub(crate) const RND_LEN: usize = 88;

/// Whether this build has Falcon.
#[cfg_attr(not(feature = "wallet"), allow(dead_code))]
pub(crate) const AVAILABLE: bool = cfg!(scaas_falcon);

#[cfg(scaas_falcon)]
#[cfg_attr(not(feature = "wallet"), allow(dead_code))]
mod ffi {
    use core::ffi::c_int;
    extern "C" {
        pub fn scaas_ua_fndsa512_keypair(pk: *mut u8, sk: *mut u8, seed: *const u8) -> c_int;
        pub fn scaas_ua_fndsa512_sign(sig: *mut u8, m: *const u8, mlen: usize, sk: *const u8, rnd: *const u8) -> c_int;
        pub fn scaas_ua_fndsa512_verify(sig: *const u8, siglen: usize, m: *const u8, mlen: usize, pk: *const u8) -> c_int;
        pub fn scaas_ua_fndsa1024_keypair(pk: *mut u8, sk: *mut u8, seed: *const u8) -> c_int;
        pub fn scaas_ua_fndsa1024_sign(sig: *mut u8, m: *const u8, mlen: usize, sk: *const u8, rnd: *const u8) -> c_int;
        pub fn scaas_ua_fndsa1024_verify(sig: *const u8, siglen: usize, m: *const u8, mlen: usize, pk: *const u8) -> c_int;
    }
}

/// The key pair of a 48-byte seed into `pk` and `sk` (exactly `p.pk` / `p.sk` bytes); `false` on a wrong length.
#[cfg(feature = "wallet")]
pub(crate) fn keypair(p: Params, seed: &[u8], pk: &mut [u8], sk: &mut [u8]) -> bool {
    if seed.len() != SEED_LEN || pk.len() != p.pk || sk.len() != p.sk {
        return false;
    }
    #[cfg(scaas_falcon)]
    {
        // SAFETY: the three buffers have the lengths the C code reads and writes (checked above)
        let rc = unsafe {
            match p.logn {
                9 => ffi::scaas_ua_fndsa512_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()),
                10 => ffi::scaas_ua_fndsa1024_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()),
                _ => -1,
            }
        };
        rc == 0
    }
    #[cfg(not(scaas_falcon))]
    false
}

/// The padded signature of `m` with `sk` and `rnd` (88 bytes) into `sig` (exactly `p.sig` bytes); `false` on a wrong length
/// or a secret key PQClean does not decode.
#[cfg(feature = "wallet")]
pub(crate) fn sign(p: Params, sk: &[u8], m: &[u8], rnd: &[u8], sig: &mut [u8]) -> bool {
    if sk.len() != p.sk || rnd.len() != RND_LEN || sig.len() != p.sig {
        return false;
    }
    #[cfg(scaas_falcon)]
    {
        // SAFETY: `sig`, `sk` and `rnd` have the lengths the C code reads and writes (checked above); `m` is read for `m.len()`
        let rc = unsafe {
            match p.logn {
                9 => ffi::scaas_ua_fndsa512_sign(sig.as_mut_ptr(), m.as_ptr(), m.len(), sk.as_ptr(), rnd.as_ptr()),
                10 => ffi::scaas_ua_fndsa1024_sign(sig.as_mut_ptr(), m.as_ptr(), m.len(), sk.as_ptr(), rnd.as_ptr()),
                _ => -1,
            }
        };
        rc == 0
    }
    #[cfg(not(scaas_falcon))]
    {
        let _ = m;
        false
    }
}

/// Whether `sig` is a valid padded signature of `m` under `pk`: exactly `p.sig` bytes (PQClean alone also takes the
/// signature without its padding) and a `p.pk`-byte key.
pub(crate) fn verify(p: Params, pk: &[u8], m: &[u8], sig: &[u8]) -> bool {
    if pk.len() != p.pk || sig.len() != p.sig {
        return false;
    }
    #[cfg(scaas_falcon)]
    {
        // SAFETY: `pk` has the length the C code reads (checked above); `sig` and `m` are read for their lengths
        let rc = unsafe {
            match p.logn {
                9 => ffi::scaas_ua_fndsa512_verify(sig.as_ptr(), sig.len(), m.as_ptr(), m.len(), pk.as_ptr()),
                10 => ffi::scaas_ua_fndsa1024_verify(sig.as_ptr(), sig.len(), m.as_ptr(), m.len(), pk.as_ptr()),
                _ => -1,
            }
        };
        rc == 0
    }
    #[cfg(not(scaas_falcon))]
    {
        let _ = m;
        false
    }
}
