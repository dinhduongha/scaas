// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The verdict key (owner 2026-11-28, CTR-PQZ-28 Change): the verifier signs every `PqzVerdict` with k256 0.14
//! (crypto-bigint 0.7, RUSTSEC-2026-0387 fixed), never through alloy's `PrivateKeySigner` (k256 0.13, crypto-bigint 0.5.5).
//! The secret is read raw from the encrypted JSON keystore (eth-keystore, alloy's own reader) after the file's size and
//! KDF parameters are bounded here, held in `Zeroizing` only until the k256 key is built, and never logged or put in an
//! error; no error carries the password or the file's content. Signing is RFC 6979, deterministic, low s, v in {27, 28}:
//! byte-identical to the alloy path for every prehash below n, so for every keccak256 digest (tests/verdict_key.rs). A
//! prehash >= n (probability about 2^-128 for a digest) gets another valid signature: k256 0.13 fed it unreduced to
//! RFC 6979, k256 0.14 reduces it as the RFC says.

use std::path::Path;

use alloy::primitives::{keccak256, Address, B256};
use k256::ecdsa::SigningKey;
use zeroize::Zeroizing;

/// A secp256k1 signing key and its native address (the verifier UA). k256's `SigningKey` zeroes its scalar on drop.
pub struct VerdictKey {
    key: SigningKey,
    address: Address,
}

/// The keystore password: the bytes of the environment variable `name` (any bytes, UTF-8 or not). The error names the
/// variable only, never its value (verifier-k256 review VK-1). The process environment keeps its own copy for the life of
/// the process; the returned copy is zeroed on drop.
pub fn password_from_env(name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let v = std::env::var_os(name)
        .ok_or_else(|| anyhow::anyhow!("the keystore password: env {name} is not set"))?;
    Ok(Zeroizing::new(v.into_encoded_bytes()))
}

/// The largest keystore file read (a v3 keystore is under 1 KiB).
const KEYSTORE_MAX: u64 = 64 * 1024;
/// scrypt bounds before eth-keystore runs (VK-8): n a power of two up to 2^18 (geth's standard), r <= 8, p <= 4, so at
/// most 128 * n * r = 256 MiB; PBKDF2 c <= 2^22.
const SCRYPT_N_MAX: u64 = 1 << 18;
const SCRYPT_R_MAX: u64 = 8;
const SCRYPT_P_MAX: u64 = 4;
const PBKDF2_C_MAX: u64 = 1 << 22;

/// The file's size and the fields eth-keystore 0.5.0 would trust unchecked (`dklen` < 32 or a short `iv` panic there,
/// a huge scrypt `n` exhausts memory, `cipher` and `kdf` are ignored), refused by name; no error quotes the file.
fn check_keystore(path: &Path) -> anyhow::Result<()> {
    use std::io::Read;
    let bail = |why: &str| anyhow::anyhow!("the keystore: {why}");
    let f = std::fs::File::open(path).map_err(|e| bail(&format!("cannot open ({})", e.kind())))?;
    let mut raw = Vec::new();
    f.take(KEYSTORE_MAX + 1)
        .read_to_end(&mut raw)
        .map_err(|e| bail(&format!("cannot read ({})", e.kind())))?;
    if raw.len() as u64 > KEYSTORE_MAX {
        return Err(bail("file larger than 64 KiB"));
    }
    let v: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| bail("not a keystore JSON"))?;
    let c = v
        .get("crypto")
        .filter(|c| c.is_object())
        .ok_or_else(|| bail("not a keystore JSON"))?;
    let hex_len = |x: Option<&serde_json::Value>| {
        x.and_then(|x| x.as_str())
            .and_then(|h| alloy::primitives::hex::decode(h).ok())
            .map(|b| b.len())
    };
    let num = |x: &serde_json::Value, k: &str| x.get(k).and_then(|n| n.as_u64());
    if c.get("cipher").and_then(|x| x.as_str()) != Some("aes-128-ctr") {
        return Err(bail("cipher not aes-128-ctr"));
    }
    if hex_len(c.get("cipherparams").and_then(|p| p.get("iv"))) != Some(16) {
        return Err(bail("iv not 16 bytes"));
    }
    if hex_len(c.get("ciphertext")) != Some(32) {
        return Err(bail("ciphertext not 32 bytes"));
    }
    if hex_len(c.get("mac")) != Some(32) {
        return Err(bail("mac not 32 bytes"));
    }
    let p = c
        .get("kdfparams")
        .filter(|p| p.is_object())
        .ok_or_else(|| bail("no kdfparams"))?;
    if !matches!(num(p, "dklen"), Some(32..=64)) {
        return Err(bail("kdf dklen not in 32..=64"));
    }
    match c.get("kdf").and_then(|x| x.as_str()) {
        Some("scrypt") => {
            if !num(p, "n").is_some_and(|n| (2..=SCRYPT_N_MAX).contains(&n) && n.is_power_of_two())
            {
                return Err(bail("scrypt n not a power of two in 2..=2^18"));
            }
            if !num(p, "r").is_some_and(|r| (1..=SCRYPT_R_MAX).contains(&r)) {
                return Err(bail("scrypt r not in 1..=8"));
            }
            if !num(p, "p").is_some_and(|x| (1..=SCRYPT_P_MAX).contains(&x)) {
                return Err(bail("scrypt p not in 1..=4"));
            }
        }
        Some("pbkdf2") => {
            if !num(p, "c").is_some_and(|c| (1..=PBKDF2_C_MAX).contains(&c)) {
                return Err(bail("pbkdf2 c not in 1..=2^22"));
            }
            if p.get("prf").and_then(|x| x.as_str()) != Some("hmac-sha256") {
                return Err(bail("pbkdf2 prf not hmac-sha256"));
            }
        }
        _ => return Err(bail("kdf not scrypt or pbkdf2")),
    }
    Ok(())
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

    /// From the encrypted JSON keystore at `path` (scrypt or PBKDF2, AES-128-CTR, as alloy's `decrypt_keystore`), its size
    /// and KDF parameters bounded first (`check_keystore`). The file is read twice (here, then by eth-keystore): it is the
    /// operator's own, read once at start.
    pub fn decrypt_keystore(
        path: impl AsRef<Path>,
        password: impl AsRef<[u8]>,
    ) -> anyhow::Result<Self> {
        let path = path.as_ref();
        check_keystore(path)?;
        let secret = eth_keystore::decrypt_key(path, password).map_err(|e| match e {
            eth_keystore::KeystoreError::MacMismatch => {
                anyhow::anyhow!("the keystore: MAC mismatch (wrong password or a damaged file)")
            }
            // the other errors (IO, JSON, KDF parameters) are fixed text: none may quote the file
            _ => anyhow::anyhow!("the keystore: not decryptable"),
        })?;
        Self::from_secret(Zeroizing::new(secret))
    }

    pub fn address(&self) -> Address {
        self.address
    }

    /// The 65-byte signature of the 32-byte `hash`: r ‖ s ‖ v (alloy's `Signature::as_bytes`), RFC 6979 with no extra
    /// data; k256 normalises to low s and flips the recovery id with it.
    pub fn sign_hash(&self, hash: &B256) -> [u8; 65] {
        let (sig, rec) = self.key.sign_prehash_recoverable(hash.as_slice());
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = v_byte(rec);
        out
    }
}

/// v = 27 + the y parity only, so 27 or 28 by construction (alloy's `From<(Signature, RecoveryId)>`); the x-reduced bit
/// (r's x overflowed n, about 2^-128) never makes 29 / 30 (VK-5).
fn v_byte(rec: k256::ecdsa::RecoveryId) -> u8 {
    27 + u8::from(rec.is_y_odd())
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::RecoveryId;

    #[test]
    fn v_is_27_or_28_for_every_recovery_id() {
        for (odd, reduced, v) in [
            (false, false, 27),
            (true, false, 28),
            (false, true, 27),
            (true, true, 28),
        ] {
            assert_eq!(
                super::v_byte(RecoveryId::new(odd, reduced)),
                v,
                "y odd {odd}, x reduced {reduced}"
            );
        }
    }
}
