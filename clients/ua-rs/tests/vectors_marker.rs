// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T15c2 (Codex C1; spec no-decryption-oracle §4.8): Cargo unifies features, so a dependency that turns on
//! `scaas-ua/vectors` would hand a release build the raw commands. In a `vectors` build every key-handle constructor refuses
//! (`Argument`) until the test-only marker unlocked this process. One test in its own binary: the unlock is process-wide.
use scaas_ua::facade::pqz::AllowSecretExport;
use scaas_ua::facade::{vectors_unlock, TestOnly};
use scaas_ua::wallet::{Error, Wallet};

#[test]
fn key_handles_need_the_test_only_marker() {
    const { assert!(scaas_ua::VECTORS && scaas_ua::build::VECTORS) };
    let w = Wallet::from_mnemonic("legal winner thank year wave sausage worth useful legal winner thank yellow", "").unwrap();
    assert_eq!(w.pqz_key(0, 0).err(), Some(Error::Argument), "pqz_key before the marker");
    assert_eq!(w.zether_key(60, 0, 7).err(), Some(Error::Argument), "zether_key before the marker");
    assert_eq!(w.export_pqz_leaf_raw(0, 0, AllowSecretExport).err(), Some(Error::Argument), "export before the marker");
    vectors_unlock(TestOnly);
    assert!(w.pqz_key(0, 0).is_ok() && w.zether_key(60, 0, 7).is_ok(), "after the marker (positive control)");
    assert!(w.export_pqz_leaf_raw(0, 0, AllowSecretExport).is_ok());
}
