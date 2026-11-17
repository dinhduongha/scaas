// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The facades (spec §10): `ua-rs` holds the key and gives the ABI; every proof, transcript, statement and encryption stays in
//! the prover crates. Zether and PQZ are separate modules, handles and features; neither calls the other. UNAUDITED.
pub mod decoys;
#[cfg(feature = "pqz")]
pub mod pqz;
#[cfg(feature = "pqz")]
pub mod pqz_backup;
#[cfg(feature = "pqz")]
pub mod pqz_pack;
#[cfg(feature = "pqz")]
pub mod pqz_path;
#[cfg(feature = "zether")]
pub mod zether;

/// Test-only (feature `vectors`; spec no-decryption-oracle §4.8, Codex C1): the marker that lets a `vectors` build make key
/// handles. Cargo unifies features, so a dependency that turns on `scaas-ua/vectors` would hand a release build the raw
/// commands; in a `vectors` build every key-handle constructor (`Wallet::pqz_key`, `pqz_held_key`, `reconstruct_pqz_seed`,
/// `zether_key`, `export_pqz_leaf_raw`) refuses (`Argument`) until [`vectors_unlock`] took this marker. A release build has
/// neither (the `compile_fail` test on `PqzKey`).
#[cfg(feature = "vectors")]
#[derive(Clone, Copy, Debug)]
pub struct TestOnly;

#[cfg(feature = "vectors")]
static UNLOCKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Test-only (feature `vectors`): key handles from now on, in this process.
#[cfg(feature = "vectors")]
pub fn vectors_unlock(_: TestOnly) {
    UNLOCKED.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// `Ok` in a release build; in a `vectors` build only after [`vectors_unlock`] (else `Argument`).
pub(crate) fn release_or_unlocked() -> crate::wallet::Result<()> {
    #[cfg(feature = "vectors")]
    if !UNLOCKED.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(crate::wallet::Error::Argument);
    }
    Ok(())
}
