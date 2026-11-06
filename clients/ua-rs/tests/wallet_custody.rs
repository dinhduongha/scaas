// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T10: custody (spec §8.2, §12 custody tests; C-02, C-09). `lock()` keeps the manifest and drops every secret;
//! `unlock` reopens the seed vault into a new arena at the raised generation and never revives an old handle; every secret
//! operation of a handle made before `lock()` is `KeyRevoked`; a wallet call that needs secrets while locked is
//! `WalletLocked`; a dropped wallet leaves its children valid memory that answers `KeyRevoked`; `lock()` against signers in
//! flight. Prove (the Zether and PQZ handles) comes with their facades (T14, T15). The `vectors` tests use the test-only
//! hooks. UNAUDITED.
use scaas_ua::musig2::{self as mu, Bn254};
use scaas_ua::verify::verify;
use scaas_ua::wallet::{
    kem_encaps, seal, AllowRawDigest, Error, KemKeyPair, MemoryProtection, Network, Recipient, UaKey, Unlock, Wallet,
};
use scaas_ua::{purpose_tag, ua_message};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

const PASS: &str = "river-otter-7 custody";

fn words() -> String {
    let path = format!("{}/../../smartcontracts/vectors/ua/keys.json", env!("CARGO_MANIFEST_DIR"));
    let k: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let m = k["mnemonics"].as_array().unwrap().iter().find(|m| m["id"] == "pq_kat").unwrap();
    m["words"].as_str().unwrap().to_owned()
}
fn wallet() -> Wallet {
    Wallet::from_mnemonic(&words(), "").unwrap()
}
fn md() -> ([u8; 32], [u8; 32]) {
    (purpose_tag("metatx").unwrap(), [7u8; 32])
}
/// A signature of `key` that verifies.
fn signs(key: &UaKey) -> bool {
    let (p, d) = md();
    let m = ua_message(key.kind(), &p, &d).unwrap();
    key.sign_ua(&p, &d).is_ok_and(|s| verify(key.kind(), &key.key_data(), &m, &s, false))
}

#[test]
fn lock_keeps_manifest_drops_secrets() {
    let w = wallet();
    let key = w.ua_key(0x0102, 0, 0).unwrap();
    w.native_key(Network::Evm, 0, None).unwrap();
    w.import_native_key(Network::Evm, &[0x11; 32]).unwrap();
    w.add_backup_sender([9; 32]);
    let before = w.manifest();
    assert!(!before.entries.is_empty() && !before.natives.is_empty() && !before.imports.is_empty());
    let r = Recipient::ephemeral(&KemKeyPair::generate_ephemeral().unwrap().kem_pk());
    // positive controls: each call below works while unlocked
    assert!(w.seal_label_vault("manifest", PASS, None).is_ok());
    assert!(w.backup_seal(&key, std::slice::from_ref(&r)).is_ok());
    assert!(w.discover_candidates(0x0102, 0, 1).is_ok());
    assert!(w.imported_key(Network::Evm, 0).is_ok());
    assert!(w.memory_protection().chunks >= 1);
    w.lock();
    let mut after = w.manifest();
    assert_eq!(after.backup_generation, before.backup_generation + 1); // the backup_seal above
    after.backup_generation = before.backup_generation;
    assert_eq!(after, before, "lock() keeps the public manifest");
    assert_eq!(w.memory_protection(), MemoryProtection::default(), "no arena while locked");
    let locked = Some(Error::WalletLocked);
    assert_eq!(w.ua_key(0x0102, 0, 0).err(), locked);
    assert_eq!(w.native_key(Network::Evm, 0, None).err(), locked);
    assert_eq!(w.imported_key(Network::Evm, 0).err(), locked);
    assert_eq!(w.import_native_key(Network::Evm, &[0x12; 32]).err(), locked);
    assert_eq!(w.seal_vault(PASS, None).err(), locked);
    assert_eq!(w.seal_label_vault("native-import:evm:0", PASS, None).err(), locked);
    assert_eq!(w.discover_candidates(0x0102, 0, 1).err(), locked);
    assert_eq!(w.backup_seal(&key, &[r]).err(), locked);
    #[cfg(feature = "vectors")]
    {
        assert_eq!(w.vectors_entropy().err(), locked);
        assert_eq!(w.vectors_seed().err(), locked);
        assert_eq!(w.vectors_arena_used().err(), locked);
    }
}

#[test]
fn unlock_reopens_the_vault() {
    let w = wallet();
    let vault = w.seal_vault(PASS, None).unwrap();
    let key = w.ua_key(0x0108, 0, 0).unwrap();
    let imported = w.import_native_key(Network::Evm, &[0x11; 32]).unwrap();
    let import_vault = w.seal_label_vault("native-import:evm:0", PASS, None).unwrap();
    let manifest_vault = w.seal_label_vault("manifest", PASS, None).unwrap();
    assert_eq!(w.unlock(&vault, Unlock::VaultPassphrase(PASS), "").err(), Some(Error::Argument), "unlocked: refused");
    w.lock();
    // the checks of open_vault: the label, the passphrase; a failed unlock leaves the wallet locked
    assert_eq!(w.unlock(&manifest_vault, Unlock::VaultPassphrase(PASS), "").err(), Some(Error::Argument));
    assert_eq!(w.unlock(&vault, Unlock::VaultPassphrase("river-otter-8 custody"), "").err(), Some(Error::VaultOpen));
    assert_eq!(w.ua_key(0x0108, 0, 0).err(), Some(Error::WalletLocked));
    w.unlock(&vault, Unlock::VaultPassphrase(PASS), "").unwrap();
    let new = w.ua_key(0x0108, 0, 0).unwrap();
    assert_eq!(new.key_data(), key.key_data());
    assert!(signs(&new));
    assert!(!signs(&key), "the old handle stays revoked");
    // imported keys: listed, not held until their own vault is reopened (unlock takes the seed vault only)
    assert!(w.manifest().imports.iter().any(|i| i.n == 0));
    assert_eq!(w.imported_key(Network::Evm, 0).err(), Some(Error::Argument));
    w.open_label_vault(&import_vault, Unlock::VaultPassphrase(PASS)).unwrap();
    let back = w.imported_key(Network::Evm, 0).unwrap();
    assert_eq!(back.public_key(), imported.public_key());
    assert!(back.sign_key_proof(b"c").is_ok());
    assert_eq!(imported.sign_key_proof(b"c").err(), Some(Error::KeyRevoked));
}

#[test]
#[allow(non_snake_case)]
fn derive_lock_then_sign_decaps_open_prove_are_KeyRevoked() {
    let w = wallet();
    let (p, d) = md();
    let ua = w.ua_key(0x0108, 0, 0).unwrap();
    let holder = w.ua_key(0x0130, 0, 0).unwrap();
    let kk = holder.kem_key(0).unwrap();
    let native = w.native_key(Network::Evm, 0, None).unwrap();
    let (a, b) = (w.ua_key(0x0112, 0, 0).unwrap(), w.ua_key(0x0112, 1, 0).unwrap());
    let pks = vec![a.key_data(), b.key_data()];
    let (mut sa, sb) = (a.musig2_session(&pks, &[6; 32]).unwrap(), b.musig2_session(&pks, &[6; 32]).unwrap());
    let agg = mu::nonce_agg::<Bn254>(&[sa.pubnonce(), sb.pubnonce()]).unwrap();
    let (ct, eph, ss) = kem_encaps(&kk.kem_pk()).unwrap();
    let sealed = seal(&kk.kem_pk(), "scaas/test/v1", b"aad", b"pt").unwrap();
    // positive controls
    assert!(signs(&ua));
    assert!(ua.sign_member(&d, &d).is_ok());
    assert_eq!(*kk.decaps(&ct, &eph).unwrap(), *ss);
    assert_eq!(*kk.open("scaas/test/v1", b"aad", &sealed).unwrap(), b"pt");
    assert!(holder.kem_key(0).is_ok());
    assert!(native.sign_key_proof(b"c").is_ok());
    assert!(native.sign_digest(&d, AllowRawDigest).is_ok());
    w.lock();
    let revoked = Some(Error::KeyRevoked);
    assert_eq!(ua.sign_ua(&p, &d).err(), revoked);
    assert_eq!(ua.sign_member(&d, &d).err(), revoked);
    assert_eq!(kk.decaps(&ct, &eph).err(), revoked);
    assert_eq!(kk.open("scaas/test/v1", b"aad", &sealed).err(), revoked);
    assert_eq!(holder.kem_key(0).err(), revoked);
    assert_eq!(native.sign_key_proof(b"c").err(), revoked);
    assert_eq!(native.sign_digest(&d, AllowRawDigest).err(), revoked);
    assert_eq!(sa.sign(&agg).err(), revoked);
    assert_eq!(a.musig2_session(&pks, &[6; 32]).err(), revoked);
}

#[test]
fn unlock_does_not_revive_old_handles() {
    let w = wallet();
    let vault = w.seal_vault(PASS, None).unwrap();
    let old = w.ua_key(0x0108, 0, 0).unwrap();
    let holder = w.ua_key(0x0130, 0, 0).unwrap();
    let kk = holder.kem_key(0).unwrap();
    let (ct, eph, ss) = kem_encaps(&kk.kem_pk()).unwrap();
    w.lock();
    w.unlock(&vault, Unlock::VaultPassphrase(PASS), "").unwrap();
    // an old handle's derivation is refused before it writes the new arena
    #[cfg(feature = "vectors")]
    let used = w.vectors_arena_used().unwrap();
    assert_eq!(holder.kem_key(0).err(), Some(Error::KeyRevoked));
    #[cfg(feature = "vectors")]
    assert_eq!(w.vectors_arena_used().unwrap(), used, "a revoked handle wrote the new arena");
    // the same derivations again: the new arena has the old slots at the same places; the generation alone refuses
    let new = w.ua_key(0x0108, 0, 0).unwrap();
    let fresh = w.ua_key(0x0130, 0, 0).unwrap().kem_key(0).unwrap();
    assert!(signs(&new));
    assert_eq!(*fresh.decaps(&ct, &eph).unwrap(), *ss);
    assert!(!signs(&old));
    assert_eq!(old.sign_ua(&md().0, &md().1).err(), Some(Error::KeyRevoked));
    assert_eq!(kk.decaps(&ct, &eph).err(), Some(Error::KeyRevoked));
    assert_eq!(holder.kem_key(0).err(), Some(Error::KeyRevoked));
    // a second lock / unlock: still revoked
    w.lock();
    w.unlock(&vault, Unlock::VaultPassphrase(PASS), "").unwrap();
    assert_eq!(old.sign_ua(&md().0, &md().1).err(), Some(Error::KeyRevoked));
    assert_eq!(new.sign_ua(&md().0, &md().1).err(), Some(Error::KeyRevoked));
}

#[test]
#[allow(non_snake_case)]
fn ua_key_on_locked_wallet_is_WalletLocked() {
    let w = wallet();
    assert!(w.ua_key(0x0101, 0, 0).is_ok());
    w.lock();
    for kind in [0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0108, 0x0110, 0x0112, 0x0130, 0x0131] {
        assert_eq!(w.ua_key(kind, 0, 0).err(), Some(Error::WalletLocked), "{kind:#06x}");
    }
    assert_eq!(w.native_key(Network::Solana, 0, None).err(), Some(Error::WalletLocked));
}

#[test]
fn wallet_dropped_with_children_retained() {
    let w = wallet();
    let (p, d) = md();
    let ua = w.ua_key(0x0108, 0, 0).unwrap();
    let kk = w.ua_key(0x0130, 0, 0).unwrap().kem_key(0).unwrap();
    let native = w.native_key(Network::Evm, 0, None).unwrap();
    let imported = w.import_native_key(Network::Stellar, &[1; 32]).unwrap();
    let (a, b) = (w.ua_key(0x0112, 0, 0).unwrap(), w.ua_key(0x0112, 1, 0).unwrap());
    let pks = vec![a.key_data(), b.key_data()];
    let (mut sa, sb) = (a.musig2_session(&pks, &[6; 32]).unwrap(), b.musig2_session(&pks, &[6; 32]).unwrap());
    let agg = mu::nonce_agg::<Bn254>(&[sa.pubnonce(), sb.pubnonce()]).unwrap();
    let (ct, eph, _) = kem_encaps(&kk.kem_pk()).unwrap();
    assert!(signs(&ua) && kk.decaps(&ct, &eph).is_ok() && imported.sign_key_proof(b"c").is_ok());
    drop(w);
    let revoked = Some(Error::KeyRevoked);
    assert_eq!(ua.sign_ua(&p, &d).err(), revoked);
    assert_eq!(kk.decaps(&ct, &eph).err(), revoked);
    assert_eq!(native.sign_key_proof(b"c").err(), revoked);
    assert_eq!(imported.sign_key_proof(b"c").err(), revoked);
    assert_eq!(sa.sign(&agg).err(), revoked);
    // the public parts are valid memory; each child is freed after, in any order
    assert_eq!((ua.kind(), kk.kem_pk().len(), native.public_key().len()), (0x0108, 1601, 33));
    drop(kk);
    drop(sa);
    drop(ua);
    drop((native, imported, a, b, sb));
}

/// Spec §12: signers in flight while one thread calls `lock()`. Each result is a valid signature or `KeyRevoked`; no call
/// started after `lock()` returned signs; once revoked, always revoked. Bounded: each signer stops three calls after its first
/// `KeyRevoked`, and at most `MAX` calls.
#[test]
fn concurrent_lock_and_sign() {
    const THREADS: usize = 4;
    const MAX: usize = 200_000;
    let w = wallet();
    let key = w.ua_key(0x0108, 0, 0).unwrap();
    let (p, d) = md();
    let m = ua_message(0x0108, &p, &d).unwrap();
    let locked = AtomicBool::new(false);
    let (first_tx, first_rx) = mpsc::channel();
    #[cfg(feature = "vectors")]
    let before = scaas_ua::wallet::vectors_chunks_released();
    std::thread::scope(|s| {
        let signers: Vec<_> = (0..THREADS)
            .map(|_| {
                let (first_tx, key, locked, kd) = (first_tx.clone(), &key, &locked, key.key_data());
                s.spawn(move || {
                    let (mut ok, mut revoked) = (0usize, 0usize);
                    for _ in 0..MAX {
                        let started_after_lock = locked.load(Ordering::SeqCst);
                        match key.sign_ua(&p, &d) {
                            Ok(sig) => {
                                assert!(!started_after_lock, "a call started after lock() returned signed");
                                assert_eq!(revoked, 0, "a signature after KeyRevoked");
                                assert!(verify(0x0108, &kd, &m, &sig, false));
                                ok += 1;
                                if ok == 1 {
                                    first_tx.send(()).unwrap();
                                }
                            }
                            Err(e) => {
                                assert_eq!(e, Error::KeyRevoked);
                                revoked += 1;
                                if revoked == 3 {
                                    break;
                                }
                            }
                        }
                    }
                    (ok, revoked)
                })
            })
            .collect();
        for _ in 0..THREADS {
            first_rx.recv().unwrap(); // every signer has signed once: lock() lands among calls in flight
        }
        w.lock();
        locked.store(true, Ordering::SeqCst);
        for h in signers {
            let (ok, revoked) = h.join().unwrap();
            assert!(ok >= 1 && revoked == 3, "ok {ok}, revoked {revoked}");
        }
    });
    assert_eq!(w.memory_protection(), MemoryProtection::default());
    // the arena read zero when lock() released it (every chunk wiped before it went back)
    #[cfg(feature = "vectors")]
    {
        let after = scaas_ua::wallet::vectors_chunks_released();
        assert!(after.0 > before.0, "lock() released the arena's chunks");
        assert_eq!(after.1, 0, "a chunk released with non-zero bytes");
    }
}

/// `lock()` takes the write lock: while an operation runs under the read guard, `lock()` does not return (a bounded wait of
/// one second, no loop); it returns once the operation left.
#[cfg(feature = "vectors")]
#[test]
fn lock_returns_only_after_operations_in_flight() {
    let w = wallet();
    let key = w.ua_key(0x0108, 0, 0).unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (locked_tx, locked_rx) = mpsc::channel();
    std::thread::scope(|s| {
        let (key, w) = (&key, &w);
        let op = s.spawn(move || {
            key.vectors_with_secret(|secret| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                secret.iter().any(|b| *b != 0) // the secret is intact while the operation runs
            })
        });
        entered_rx.recv().unwrap();
        let locker = s.spawn(move || {
            w.lock();
            locked_tx.send(()).unwrap();
        });
        let early = locked_rx.recv_timeout(std::time::Duration::from_secs(1));
        release_tx.send(()).unwrap();
        assert_eq!(op.join().unwrap(), Ok(true));
        locker.join().unwrap();
        assert!(early.is_err(), "lock() returned while an operation held the read guard");
    });
    assert_eq!(key.vectors_with_secret(|_| ()).err(), Some(Error::KeyRevoked));
}
