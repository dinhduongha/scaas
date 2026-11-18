// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! scaas-sdk T4, owner 2026-11-18 (b) (spec §6.10): the PRF key-encryption key derived once at a passkey or platform unlock and
//! kept in the arena; label vaults open with it on first use; `lock()` zeroes it with the arena.
#![allow(clippy::unwrap_used)]
use scaas_ua::wallet::{Error, Network, PrfEnvelope, Unlock, Wallet};

const MNEMONIC: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const PASS: &str = "river-otter-7 ünï";
const PRF: [u8; 32] = [7; 32];
const OTHER: [u8; 32] = [8; 32];

fn envelope() -> PrfEnvelope<'static> {
    PrfEnvelope { output: &PRF, credential_id: "Yw", salt: &[9; 32] }
}

/// A seed with one imported key; its seed, manifest and import vaults, each with the PRF envelope.
fn sealed() -> (Wallet, [scaas_ua::wallet::Vault; 3]) {
    let w = Wallet::from_mnemonic(MNEMONIC, "").unwrap();
    w.import_native_key(Network::Evm, &[0x11; 32]).unwrap();
    let seed = w.seal_vault(PASS, Some(&envelope())).unwrap();
    let manifest = w.seal_label_vault("manifest", PASS, Some(&envelope())).unwrap();
    let import = w.seal_label_vault("native-import:evm:0", PASS, Some(&envelope())).unwrap();
    (w, [seed, manifest, import])
}

#[test]
fn retained_key_opens_label_vaults_on_first_use() {
    let (_, [seed, manifest, import]) = sealed();
    let w = Wallet::open_vault(&seed, Unlock::Prf(&PRF), "").unwrap();
    assert_eq!(w.open_label_vault_retained(&manifest), Err(Error::Argument), "nothing retained yet");
    w.retain_prf_key(&PRF).unwrap();
    w.open_label_vault_retained(&manifest).unwrap();
    assert!(!w.label_open("native-import:evm:0"), "not opened before its first use");
    assert_eq!(w.imported_key(Network::Evm, 0).err(), Some(Error::Argument), "not held before its first use");
    w.open_label_vault_retained(&import).unwrap();
    assert!(w.label_open("native-import:evm:0"));
    assert!(w.imported_key(Network::Evm, 0).is_ok(), "held after its first use");
    assert!(w.reseal_label_vault("native-import:evm:0").is_ok(), "its DEK held for the re-seal");
}

#[test]
fn retained_key_refusals() {
    let (src, [seed, _, import]) = sealed();
    let w = Wallet::open_vault(&seed, Unlock::Prf(&PRF), "").unwrap();
    w.retain_prf_key(&OTHER).unwrap();
    assert_eq!(w.open_label_vault_retained(&import), Err(Error::VaultOpen), "another key");
    w.retain_prf_key(&PRF).unwrap();
    let plain = src.seal_label_vault("native-import:evm:0", PASS, None).unwrap();
    assert_eq!(w.open_label_vault_retained(&plain), Err(Error::Argument), "a vault without a PRF envelope");
    assert!(w.open_label_vault_retained(&import).is_ok(), "control");
    w.lock();
    assert_eq!(w.retain_prf_key(&PRF), Err(Error::WalletLocked));
    assert_eq!(w.open_label_vault_retained(&import), Err(Error::WalletLocked));
}

/// `lock()` zeroes the retained key: every chunk released reads zero, and after the next unlock no key is retained.
#[cfg(feature = "vectors")]
#[test]
fn lock_zeroizes_the_retained_key() {
    let (_, [seed, manifest, _]) = sealed();
    let w = Wallet::open_vault(&seed, Unlock::Prf(&PRF), "").unwrap();
    w.retain_prf_key(&PRF).unwrap();
    w.open_label_vault_retained(&manifest).unwrap();
    let before = scaas_ua::wallet::vectors_chunks_released();
    w.lock();
    let after = scaas_ua::wallet::vectors_chunks_released();
    assert!(after.0 > before.0, "lock() released the arena holding the key");
    assert_eq!(after.1, 0, "a chunk released with a non-zero byte");
    w.unlock(&seed, Unlock::VaultPassphrase(PASS), "").unwrap();
    assert_eq!(w.open_label_vault_retained(&manifest), Err(Error::Argument), "the key did not survive lock()");
}
