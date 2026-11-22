// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The file object's sizes (CLI-UAL-65; decisions CLI-SDK-33 (35): the generic file seal is the core's, whatever the store):
//! `bucket(size)` is the smallest power of two that is at least `max(2^16, size + 8)`, in integers, up to the platform's
//! in-memory cap ([`CAP`]: 2^30 B on 64-bit targets, 2^27 B on wasm32, since one-shot AES-GCM holds the whole object); the
//! object is exactly `bucket + 16` B. The seal and the open are `wallet::AppKeys::seal_file` / `open_file` (feature
//! `app-core`). Byte formats: clientkeys `src/arweave.js`, `smartcontracts/vectors/arweave/objects.json`. UNAUDITED.

/// The smallest bucket.
pub const BUCKET_MIN: u64 = 1 << 16;
/// The in-memory cap of 64-bit targets.
pub const CAP_64: u64 = 1 << 30;
/// The in-memory cap of wasm32.
pub const CAP_WASM32: u64 = 1 << 27;
/// This platform's cap.
#[cfg(target_arch = "wasm32")]
pub const CAP: u64 = CAP_WASM32;
/// This platform's cap.
#[cfg(not(target_arch = "wasm32"))]
pub const CAP: u64 = CAP_64;
/// The AES-256-GCM tag after the frame.
pub const TAG: u64 = 16;

/// `bucket(size)` under `cap` (the smaller of the platform's [`CAP`] and a store's largest object), `None` above it.
pub fn bucket(size: u64, cap: u64) -> Option<u64> {
    let b = size
        .checked_add(8)?
        .max(BUCKET_MIN)
        .checked_next_power_of_two()?;
    (b <= cap.min(CAP)).then_some(b)
}

/// The exact length of the object of a file of `size` bytes, `None` above `cap`.
pub fn object_len(size: u64, cap: u64) -> Option<u64> {
    bucket(size, cap).map(|b| b + TAG)
}

/// Why a reader refused an object before decrypting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectError {
    /// the signed `size`'s bucket is above the cap (`FileTooLarge`)
    TooLarge,
    /// the object's length is not exactly `bucket(size) + 16` (`FileLength`)
    Length,
    /// SHA-256 of the object is not `ctSha256` (`FileHashMismatch`)
    HashMismatch,
}

/// The reader's check before decryption (CLI-UAL-65): the exact length, then SHA-256 equal to `ct_sha256`.
pub fn check_object(
    object: &[u8],
    size: u64,
    ct_sha256: &[u8; 32],
    cap: u64,
) -> Result<(), ObjectError> {
    use sha2::{Digest, Sha256};
    let want = object_len(size, cap).ok_or(ObjectError::TooLarge)?;
    if object.len() as u64 != want {
        return Err(ObjectError::Length);
    }
    let h: [u8; 32] = Sha256::digest(object).into();
    if h.iter().zip(ct_sha256).fold(0u8, |a, (x, y)| a | (x ^ y)) != 0 {
        return Err(ObjectError::HashMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_at_their_edges() {
        assert_eq!(bucket(0, CAP), Some(1 << 16));
        assert_eq!(bucket((1 << 16) - 8, CAP), Some(1 << 16));
        assert_eq!(bucket((1 << 16) - 7, CAP), Some(1 << 17));
        assert_eq!(bucket((1 << 30) - 8, CAP_64), Some(1 << 30));
        assert_eq!(bucket((1 << 30) - 7, CAP_64), None);
        assert_eq!(bucket((1 << 27) - 7, CAP_WASM32), None);
        assert_eq!(bucket(u64::MAX, CAP), None);
        assert_eq!(object_len(5, CAP), Some((1 << 16) + 16));
    }
}
