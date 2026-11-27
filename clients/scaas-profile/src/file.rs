// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The file helpers of the store, as the SDK's `FileStore` writes (spec §6.9 of the SDK spec): a temporary beside the file,
//! `fsync`ed, renamed over it, the directory `fsync`ed, mode `0600`; an advisory lock on `<file>.lock`; an item's revision.
//! Copied from the SDK (this crate depends on no part of it); both follow the same rules.
use crate::Error;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// An item's plain bound (the SDK's `vault::keystore::MAX_BYTES`): 16 MiB.
pub(crate) const MAX_BYTES: usize = 16 << 20;
/// A sealed item's bound (spec §7.2 "Size"): the base64 of the 16 MiB plain bound plus 1 KiB.
pub(crate) const SEALED_MAX: usize = 4 * MAX_BYTES.div_ceil(3) + 1024;

/// Whether `bytes` begin as a sealed item does, `{"rev":<digits>,"sealed":"` (plan pinned format 6).
pub(crate) fn sealed_form(bytes: &[u8]) -> bool {
    let rest = bytes.strip_prefix(br#"{"rev":"#).unwrap_or_default();
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    rest.get(digits..)
        .is_some_and(|r| r.starts_with(br#","sealed":""#))
}

/// The revision of an item's bytes (the SDK's `vault::store::rev_of`): its top-level JSON `rev`, else `u64::MAX`. Read up to
/// 16 MiB, or for a sealed item up to the base64 of 16 MiB plus 1 KiB.
pub fn rev_of(bytes: &[u8]) -> u64 {
    #[derive(serde::Deserialize)]
    struct Rev {
        rev: u64,
    }
    let max = if sealed_form(bytes) {
        SEALED_MAX
    } else {
        MAX_BYTES
    };
    if bytes.len() > max || scaas_ua::json::depth_within(bytes, 64).is_err() {
        return u64::MAX;
    }
    serde_json::from_slice::<Rev>(bytes).map_or(u64::MAX, |r| r.rev)
}

fn io<T>(r: std::io::Result<T>) -> Result<T, Error> {
    r.map_err(|_| Error::VaultIo)
}

/// The file `p`: its revision ([`rev_of`]) and bytes, `None` when absent.
pub(crate) fn read(p: &Path) -> Result<Option<(u64, Vec<u8>)>, Error> {
    match std::fs::read(p) {
        Ok(bytes) => Ok(Some((rev_of(&bytes), bytes))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Error::VaultIo),
    }
}

/// `bytes` to a temporary beside `p` (mode `0600`, `<p>.tmp.<pid>.<n>`), `fsync`ed, renamed over `p`, the directory `dir`
/// `fsync`ed; the temporary removed on a failure.
pub(crate) fn write(dir: &Path, p: &Path, bytes: &[u8]) -> Result<(), Error> {
    static N: AtomicU64 = AtomicU64::new(0);
    let tmp = p.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let r = (|| {
        let mut o = OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let mut f = io(o.open(&tmp))?;
        io(f.write_all(bytes))?;
        io(f.sync_all())?;
        io(std::fs::rename(&tmp, p))?;
        io(File::open(dir).and_then(|d| d.sync_all()))
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

/// An exclusive advisory lock on the file `p` (created, mode `0600`), held while the returned file lives.
pub(crate) fn lock_file(p: &Path) -> Result<File, Error> {
    let mut o = OpenOptions::new();
    o.write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let f = io(o.open(p))?;
    io(f.lock())?;
    Ok(f)
}
