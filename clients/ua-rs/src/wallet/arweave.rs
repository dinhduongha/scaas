// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `seal_for_arweave` and the upload key (CLI-UAL-64, CLI-UAL-65; features `app-core` and `fam-arweave`; chains-arweave plan
//! T17): in one call a fresh file key handle, the frame and the object ([`AppKeys::seal_file`]'s), `ctSha256` computed here
//! over the object, the upload key `HKDF-SHA-256(ikm = app root key ‖ file key, salt empty, info = "scaas/arweave/v1/upload" ‖
//! type ‖ ctSha256 [‖ counter], 32)`, and the item over the object built, signed and verified. The upload key lives in an
//! `UploadSign` for that call only: bound to one type and one `ctSha256`, its one operation signs an item `ua-rs` built after
//! recomputing SHA-256 of the item's data (another: `AppKeyUsage`), and no app core can name, make, import or unwrap one
//! (it is no [`super::KeyUsage`]; controller call CLI-SDK-33). One upload key signs exactly one byte string: no target, no
//! anchor, no tag (C9), and both schemes are deterministic. No parameter carries a hash. UNAUDITED.
use super::aead::hkdf_sha256;
use super::{AppKeys, Error, KeyHandle, KeyUsage, Result};
use crate::arweave::{self as ar, DataItem, SigType};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;

/// The upload key's HKDF info prefix.
pub const UPLOAD_INFO: &[u8] = b"scaas/arweave/v1/upload";

/// Signatures `UploadSign` made in this process (a test's counting spy: one per item, none on a re-post).
static SIGNS: AtomicU64 = AtomicU64::new(0);

/// `seal_for_arweave`'s answer: the file key handle and the public parts; the object is the item's data.
pub struct ArweaveFile {
    pub key: KeyHandle,
    pub ct_sha256: [u8; 32],
    pub sha256: [u8; 32],
    pub size: u64,
    /// the signed, verified item (no target, no anchor, no tag); its data is the object
    pub item: DataItem,
    /// `ar://<id>`
    pub url: String,
}

/// The item `UploadSign` may sign: a C9 item over `data`. No public constructor.
struct Unsigned<'a> {
    data: &'a [u8],
}

/// An upload key bound to one type and one `ctSha256`, alive for one `seal_for_arweave` call.
struct UploadSign {
    seed: Zeroizing<[u8; 32]>,
    t: SigType,
    ct_sha256: [u8; 32],
}

impl UploadSign {
    /// The item over `u.data`, signed and verified, only when SHA-256 of the data is the bound hash (else `AppKeyUsage`).
    fn sign(&self, u: &Unsigned) -> Result<DataItem> {
        let h: [u8; 32] = Sha256::digest(u.data).into();
        if h != self.ct_sha256 {
            return Err(Error::AppKeyUsage);
        }
        let it = ar::build(self.t, &self.seed, u.data, None, None, &[])
            .map_err(|_| Error::ArweaveItem)?;
        SIGNS.fetch_add(1, Ordering::Relaxed);
        Ok(it)
    }
}

/// The seed of the upload key, with the counter used: ed25519 takes the first output; secp256k1 the first that is a scalar
/// in `[1, n)` (`refuse(k)`: a test fixture refusing the `k`-th candidate too).
fn upload_seed(
    ikm: &[u8],
    t: SigType,
    ct_sha256: &[u8; 32],
    refuse: impl Fn(u8) -> bool,
) -> Result<(Zeroizing<[u8; 32]>, u8)> {
    let base = [UPLOAD_INFO, &[t as u8], &ct_sha256[..]].concat();
    for k in 0u8..=255 {
        let info = if k == 0 {
            base.clone()
        } else {
            [&base[..], &[k]].concat()
        };
        let okm = hkdf_sha256(ikm, &[], &info, 32)?;
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            okm.get(..32)
                .and_then(|s| s.try_into().ok())
                .ok_or(Error::Argument)?,
        );
        let valid = match t {
            SigType::Ethereum => k256::SecretKey::from_slice(&seed[..]).is_ok(),
            _ => true,
        };
        if valid && !refuse(k) {
            return Ok((seed, k));
        }
    }
    Err(Error::Argument)
}

impl AppKeys {
    fn seal_for_arweave_under(
        &self,
        root: &KeyHandle,
        key: KeyHandle,
        file: &[u8],
        t: SigType,
        cap: u64,
    ) -> Result<ArweaveFile> {
        self.check_usage(root, KeyUsage::Derive)?;
        let sealed = self.seal_file_under(key, file, cap)?;
        let ikm = Zeroizing::new([&self.bytes(root)?[..], &self.bytes(&sealed.key)?[..]].concat());
        let (seed, _) = upload_seed(&ikm, t, &sealed.ct_sha256, |_| false)?;
        let signer = UploadSign {
            seed,
            t,
            ct_sha256: sealed.ct_sha256,
        };
        let item = signer.sign(&Unsigned {
            data: &sealed.object,
        })?;
        drop(signer);
        Ok(ArweaveFile {
            key: sealed.key,
            ct_sha256: sealed.ct_sha256,
            sha256: sealed.sha256,
            size: sealed.size,
            url: item.url(),
            item,
        })
    }

    /// `file` sealed for Arweave in one call (spec §7.3, §7.6): a fresh file key, the object, its `ctSha256`, the upload key
    /// from the app root key `root` (a `Derive` handle) and the file key, the item built, signed and verified. `cap` is the
    /// store's largest bucket (the bundler profile's largest single request); with the platform's cap, the smaller one holds
    /// (`FileTooLarge` above it).
    pub fn seal_for_arweave(
        &self,
        root: &KeyHandle,
        file: &[u8],
        t: SigType,
        cap: u64,
    ) -> Result<ArweaveFile> {
        self.seal_for_arweave_under(root, self.random_key(KeyUsage::File)?, file, t, cap)
    }
}

/// Test-only entry points (feature `vectors`, never in a release build).
#[cfg(feature = "vectors")]
impl AppKeys {
    /// [`AppKeys::seal_for_arweave`] under a given `File` handle (a vector's fixed key).
    pub fn vectors_seal_for_arweave(
        &self,
        root: &KeyHandle,
        key: KeyHandle,
        file: &[u8],
        t: SigType,
    ) -> Result<ArweaveFile> {
        self.seal_for_arweave_under(root, key, file, t, crate::file::CAP)
    }
}

/// Test-only (feature `vectors`): the upload key's seed, owner and counter from raw bytes (`refuse_first`: the fixture that
/// refuses the first candidate).
#[cfg(feature = "vectors")]
pub fn vectors_upload_key(
    root: &[u8; 32],
    file_key: &[u8; 32],
    t: SigType,
    ct_sha256: &[u8; 32],
    refuse_first: bool,
) -> Result<([u8; 32], Vec<u8>, u8)> {
    let ikm = [&root[..], &file_key[..]].concat();
    let (seed, k) = upload_seed(&ikm, t, ct_sha256, |k| refuse_first && k == 0)?;
    let owner = ar::owner_of(t, &seed).ok_or(Error::Argument)?;
    Ok((*seed, owner, k))
}

/// Test-only (feature `vectors`): the signatures `UploadSign` made in this process.
#[cfg(feature = "vectors")]
pub fn vectors_sign_count() -> u64 {
    SIGNS.load(Ordering::Relaxed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// A handle bound to object A refuses an item over object B (the item built by this test-only path), and signs A's.
    #[test]
    fn an_upload_key_signs_only_its_object() {
        let (a, b) = (b"object A".to_vec(), b"object B".to_vec());
        let ct: [u8; 32] = Sha256::digest(&a).into();
        let (seed, _) = upload_seed(&[7u8; 64], SigType::Ed25519, &ct, |_| false).unwrap();
        let s = UploadSign {
            seed,
            t: SigType::Ed25519,
            ct_sha256: ct,
        };
        assert_eq!(
            s.sign(&Unsigned { data: &b }).unwrap_err(),
            Error::AppKeyUsage
        );
        let it = s.sign(&Unsigned { data: &a }).unwrap();
        assert_eq!(it.data(), &a[..]);
        assert!(it.is_c9());
    }

    /// The counter path: a refused candidate moves to the next counter, which gives another key.
    #[test]
    fn the_counter_byte_moves_the_key() {
        let ct = [1u8; 32];
        let (a, ka) = upload_seed(&[3u8; 64], SigType::Ethereum, &ct, |_| false).unwrap();
        let (b, kb) = upload_seed(&[3u8; 64], SigType::Ethereum, &ct, |k| k == 0).unwrap();
        assert_eq!((ka, kb), (0, 1));
        assert_ne!(*a, *b);
    }
}
