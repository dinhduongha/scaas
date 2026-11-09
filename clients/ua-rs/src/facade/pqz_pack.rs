// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The PQZ stored form (P46, owner 2026-10-21; `PqzCt.sol` on `ua-mtx-merge`): what a PQZ token stores (the SSTORE2 op blobs and a
//! materialised `acc`) holds each coefficient in `B = PACK_BITS = ⌈log2 q⌉` bits; one 64-bit-lane word (four coefficients
//! `c0 ‖ c1 ‖ c2 ‖ c3`) becomes `GROUP = B / 2` bytes, the four fields big-endian, `c0` first. Calldata, the statement and the
//! precompile keep the 64-bit lanes (`be8` per coefficient). The facade reads stored words and never writes them (ua-rs-sign
//! T15e; spec no-decryption-oracle §4.4); it packs only to hash its own fresh ciphertexts for `ownTag`, whose message takes
//! `keccak256(P(u) ‖ P(v_f))` (proof-path spec PP-3; ua-rs-sign T20d2). UNAUDITED.
use pqz_ffi::stmt::{PK_BYTES, Q, V_BYTES};

/// Bits per stored coefficient: `⌈log2 q⌉`, the bits of `q − 1` (`PqzSet.PACK_BITS`; 42 / 46 / 50 / 54 at the four sets).
pub const B: usize = (u64::BITS - (Q - 1).leading_zeros()) as usize;
/// Bytes per stored 64-bit-lane word (four coefficients).
pub const GROUP: usize = B / 2;
/// Stored bytes of a `u` (or a key), of a `v`, of a ciphertext.
pub const PKP: usize = PK_BYTES / 32 * GROUP;
pub const VP: usize = V_BYTES / 32 * GROUP;
pub const CTP: usize = PKP + VP;
/// The slots of a materialised `acc` (`PQZ_ACC_WORDS`): `⌈CTP / 32⌉`, each `not(stream word)`.
pub const ACC_WORDS: usize = CTP.div_ceil(32);
const _: () = assert!(B.is_multiple_of(2) && B < 64 && PK_BYTES.is_multiple_of(32) && V_BYTES.is_multiple_of(32));

/// The 64-bit-lane bytes (`be8` per coefficient, as the statement holds them) of `packed`, a whole number of groups; `None`
/// otherwise. No range check: a field may be any `B`-bit value (the caller checks `< q` where the contract's state is canonical).
pub fn unpack(packed: &[u8]) -> Option<Vec<u8>> {
    if !packed.len().is_multiple_of(GROUP) {
        return None;
    }
    let mask = (1u128 << B) - 1;
    let mut out = Vec::with_capacity(packed.len() / GROUP * 32);
    for g in packed.chunks_exact(GROUP) {
        // 4·B bits, big-endian: shift each byte in, emit a field whenever B bits are held (at most B + 7 < 128 bits held)
        let (mut acc, mut held) = (0u128, 0usize);
        for &b in g {
            acc = acc << 8 | u128::from(b);
            held += 8;
            if held >= B {
                held -= B;
                out.extend_from_slice(&(((acc >> held) & mask) as u64).to_be_bytes());
                acc &= (1u128 << held) - 1;
            }
        }
    }
    Some(out)
}

/// The stored form of 64-bit lanes (`PqzCt.packMem`; the inverse of [`unpack`]): each coefficient's `B` bits, big-endian, in
/// order; `None` when `lanes` is not a whole number of words or a coefficient does not fit `B` bits.
pub fn pack(lanes: &[u8]) -> Option<Vec<u8>> {
    if !lanes.len().is_multiple_of(32) {
        return None;
    }
    let mut out = Vec::with_capacity(lanes.len() / 32 * GROUP);
    let (mut acc, mut held) = (0u128, 0usize);
    for c in lanes.chunks_exact(8) {
        let x = u64::from_be_bytes(c.try_into().ok()?);
        if x >> B != 0 {
            return None;
        }
        acc = acc << B | u128::from(x);
        held += B;
        while held >= 8 {
            held -= 8;
            out.push((acc >> held) as u8);
            acc &= (1u128 << held) - 1;
        }
    }
    (held == 0).then_some(out)
}
