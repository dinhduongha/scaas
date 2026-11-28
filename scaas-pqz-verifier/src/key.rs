// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The verdict key (owner 2026-11-28, CTR-PQZ-28 Change): the verifier signs every `PqzVerdict` with k256 0.14
//! (crypto-bigint 0.7, RUSTSEC-2026-0387 fixed), never through alloy's `PrivateKeySigner` (k256 0.13, crypto-bigint 0.5.5).
//! The secret is read raw from the encrypted JSON keystore (eth-keystore, alloy's own reader), held in `Zeroizing` only
//! until the k256 key is built, and never logged or put in an error. Signing is RFC 6979, deterministic, low s: byte for
//! byte the signature the alloy path made (tests/verdict_key.rs).

use std::path::Path;

use alloy::primitives::{keccak256, Address, B256};
use k256::ecdsa::SigningKey;
use zeroize::Zeroizing;

/// A secp256k1 signing key and its native address (the verifier UA). k256's `SigningKey` zeroes its scalar on drop.
pub struct VerdictKey {
    key: SigningKey,
    address: Address,
}

impl VerdictKey {
    /// From the 32 secret bytes, dropped (zeroed) before this returns; another length or an invalid scalar (0, >= n) is a
    /// named error without the bytes.
    pub fn from_secret(secret: Zeroizing<Vec<u8>>) -> anyhow::Result<Self> {
        // exactly 32 bytes: k256's `from_slice` would left-pad a shorter slice (24 bytes or more)
        anyhow::ensure!(secret.len() == 32, "the verifier key: not 32 bytes");
        let key = SigningKey::from_slice(&secret)
            .map_err(|_| anyhow::anyhow!("the verifier key: not a secp256k1 secret key"))?;
        drop(secret);
        let point = key.verifying_key().to_sec1_point(false);
        let address = Address::from_slice(&keccak256(&point.as_bytes()[1..])[12..]);
        Ok(Self { key, address })
    }

    /// From the encrypted JSON keystore at `path` (scrypt or PBKDF2, AES-128-CTR, as alloy's `decrypt_keystore`).
    pub fn decrypt_keystore(
        path: impl AsRef<Path>,
        password: impl AsRef<[u8]>,
    ) -> anyhow::Result<Self> {
        let secret = eth_keystore::decrypt_key(path, password)
            .map_err(|e| anyhow::anyhow!("the keystore: {e}"))?;
        Self::from_secret(Zeroizing::new(secret))
    }

    pub fn address(&self) -> Address {
        self.address
    }

    /// The 65-byte signature of the 32-byte `hash`: r ‖ s ‖ 27 + recovery id (alloy's `Signature::as_bytes`), RFC 6979
    /// with no extra data; k256 normalises to low s and flips the recovery id with it.
    pub fn sign_hash(&self, hash: &B256) -> [u8; 65] {
        let (sig, rec) = self.key.sign_prehash_recoverable(hash.as_slice());
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = 27 + rec.to_byte();
        out
    }
}
