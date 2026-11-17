// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! T0 spike: touches each pinned crate so a compile-only cross-build compiles its code paths. No API, no tests.
pub fn touch() -> usize {
    use aes_gcm::aead::KeyInit;
    let mut n = core::mem::size_of::<ml_kem::MlKem1024>();
    n += x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([7u8; 32])).as_bytes().len();
    n += core::mem::size_of_val(&aes_gcm::Aes256Gcm::new(&[0u8; 32].into()));
    n += core::mem::size_of_val(&aes_gcm_siv::Aes256GcmSiv::new(&[0u8; 32].into()));
    n += core::mem::size_of_val(&hkdf::Hkdf::<sha2::Sha256>::new(None, b"x"));
    n += scrypt::Params::new(10, 8, 1, 32).map(|_| 1).unwrap_or(0);
    n += bip39::Mnemonic::from_entropy(&[0u8; 16]).map(|m| m.word_count()).unwrap_or(0);
    n += core::mem::size_of::<bip32::XPrv>();
    n += alloy_rlp::length_of_length(300);
    let mut b = [0u8; 8];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    n += b.len();
    n += scaas_ua::algorand::metaop_digest(&b).len();
    n
}
