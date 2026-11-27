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
/// The largest revision a stored JSON may carry (review G-9): 2^53, exact in every JSON reader; above it the file is refused
/// at parse, so no counter is ever followed to an overflow.
pub(crate) const REV_MAX: u64 = 1 << 53;

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

/// The file `p`: its revision ([`rev_of`]) and bytes, `None` when absent. Read bounded: a file above [`SEALED_MAX`], the
/// largest the store writes, is `VaultFormat` and never read whole.
pub(crate) fn read(p: &Path) -> Result<Option<(u64, Vec<u8>)>, Error> {
    match read_bounded(p, SEALED_MAX)? {
        None => Ok(None),
        Some(None) => Err(Error::VaultFormat),
        Some(Some(bytes)) => Ok(Some((rev_of(&bytes), bytes))),
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

/// The file `p` when it holds at most `max` bytes: `None` when absent, `Some(None)` when larger.
pub(crate) fn read_bounded(p: &Path, max: usize) -> Result<Option<Option<Vec<u8>>>, Error> {
    use std::io::Read;
    let f = match File::open(p) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::VaultIo),
    };
    let mut bytes = Vec::new();
    let cap = u64::try_from(max)
        .map_err(|_| Error::Argument)?
        .saturating_add(1);
    io(f.take(cap).read_to_end(&mut bytes))?;
    Ok(Some((bytes.len() <= max).then_some(bytes)))
}

/// The directory `p` (mode `0700`), kept when it exists.
pub(crate) fn mkdir(p: &Path) -> Result<(), Error> {
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    match b.create(p) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => Err(Error::VaultIo),
        _ => Ok(()),
    }
}

/// A non-blocking exclusive advisory lock on the file `p` (created, mode `0600`): `None` while another holds it. Nothing is
/// written into the file.
pub(crate) fn try_lock_file(p: &Path) -> Result<Option<File>, Error> {
    let mut o = OpenOptions::new();
    o.write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let f = io(o.open(p))?;
    match f.try_lock() {
        Ok(()) => Ok(Some(f)),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(_) => Err(Error::VaultIo),
    }
}
