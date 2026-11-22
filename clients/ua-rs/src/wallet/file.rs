// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The generic file seal of app cores (CLI-UAL-65; decisions CLI-SDK-33 (35): in the core, whatever the store; feature
//! `app-core`): [`AppKeys::seal_file`] draws a fresh file key (a [`KeyUsage::File`] handle), frames the file as
//! `size (8 B big-endian) ‖ file ‖ 0x00…` up to its power-of-two bucket ([`crate::file::bucket`]) and encrypts the frame with
//! AES-256-GCM under that key and the nonce `0^96` (safe: the key is never used again to seal), so the object is exactly
//! `bucket + 16` B; [`AppKeys::open_file`] checks the length, the tag, the frame's `len` against the signed `size`, every pad
//! byte zero and SHA-256 of the file against the signed `sha256` before any plaintext leaves (C15). Byte formats: clientkeys
//! `src/arweave.js`, `smartcontracts/vectors/arweave/objects.json`. UNAUDITED.
use super::aead::{aead_open, aead_seal, Alg};
use super::{AppKeys, Error, KeyHandle, KeyUsage, Result};
use crate::file::{bucket, CAP};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// A sealed file: its key handle and the public object with its hashes and size.
pub struct SealedFile {
    /// the fresh file key (`KeyUsage::File`), to wrap into the message or the vault item (`seal_key`, `kem_wrap`)
    pub key: KeyHandle,
    /// `AES-256-GCM(key, 0^96, frame)`, exactly `bucket(size) + 16` B
    pub object: Vec<u8>,
    /// SHA-256 of the object
    pub ct_sha256: [u8; 32],
    /// SHA-256 of the file
    pub sha256: [u8; 32],
    pub size: u64,
}

fn frame(file: &[u8], cap: u64) -> Result<Zeroizing<Vec<u8>>> {
    let size = file.len() as u64;
    let b = bucket(size, cap).ok_or(Error::FileTooLarge)?;
    let mut fr = Zeroizing::new(vec![
        0u8;
        usize::try_from(b).map_err(|_| Error::FileTooLarge)?
    ]);
    fr.get_mut(..8)
        .ok_or(Error::Argument)?
        .copy_from_slice(&size.to_be_bytes());
    fr.get_mut(8..8 + file.len())
        .ok_or(Error::Argument)?
        .copy_from_slice(file);
    Ok(fr)
}

impl AppKeys {
    pub(super) fn seal_file_under(
        &self,
        key: KeyHandle,
        file: &[u8],
        cap: u64,
    ) -> Result<SealedFile> {
        self.check_usage(&key, KeyUsage::File)?;
        let fr = frame(file, cap)?;
        let object = aead_seal(Alg::Aes256Gcm, &*self.bytes(&key)?, &[0; 12], &[], &fr)?;
        Ok(SealedFile {
            key,
            ct_sha256: Sha256::digest(&object).into(),
            sha256: Sha256::digest(file).into(),
            size: file.len() as u64,
            object,
        })
    }

    /// `file` sealed under a fresh file key: the object and its hashes (`FileTooLarge` above the platform's cap).
    pub fn seal_file(&self, file: &[u8]) -> Result<SealedFile> {
        self.seal_file_under(self.random_key(KeyUsage::File)?, file, CAP)
    }

    /// The file of `object` under the `File` handle `key`, after every check: the length `bucket(size) + 16` (`FileLength`;
    /// a bucket above the cap `FileTooLarge`), the tag (`Aead`), the frame's `len` equal to `size` and the zero pad
    /// (`FileFrame`), SHA-256 of the file equal to `sha256` (`FileHashMismatch`).
    pub fn open_file(
        &self,
        key: &KeyHandle,
        object: &[u8],
        size: u64,
        sha256: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.check_usage(key, KeyUsage::File)?;
        let b = bucket(size, CAP).ok_or(Error::FileTooLarge)?;
        if object.len() as u64 != b + 16 {
            return Err(Error::FileLength);
        }
        let fr = aead_open(Alg::Aes256Gcm, &*self.bytes(key)?, &[0; 12], &[], object)?;
        let n = usize::try_from(size).map_err(|_| Error::FileTooLarge)?;
        let len = fr.get(..8).ok_or(Error::FileFrame)?;
        if len != size.to_be_bytes() {
            return Err(Error::FileFrame);
        }
        let pad = fr.get(8 + n..).ok_or(Error::FileFrame)?;
        if pad.iter().fold(0u8, |a, x| a | x) != 0 {
            return Err(Error::FileFrame);
        }
        let file = Zeroizing::new(fr.get(8..8 + n).ok_or(Error::FileFrame)?.to_vec());
        let h: [u8; 32] = Sha256::digest(&file[..]).into();
        if h.iter().zip(sha256).fold(0u8, |a, (x, y)| a | (x ^ y)) != 0 {
            return Err(Error::FileHashMismatch);
        }
        Ok(file)
    }
}

/// Test-only entry points (feature `vectors`, never in a release build).
#[cfg(feature = "vectors")]
impl AppKeys {
    /// [`AppKeys::seal_file`] under a given `File` handle (a vector's fixed key).
    pub fn vectors_seal_file(&self, key: KeyHandle, file: &[u8]) -> Result<SealedFile> {
        self.seal_file_under(key, file, CAP)
    }
}
