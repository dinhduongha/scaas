// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T4: `vault` seeds, integrity, unlock and lock (spec §6.2–§6.5, §6.10 passphrase path), each refusal with its control.
#![allow(clippy::unwrap_used)]

use scaas_sdk::vault::{
    ConfirmRemove, ConfirmRemoveUnbacked, Generate, ImportKey, ImportWords, Keystore, MemoryStore,
    Remove, SecureStore, StorePolicy, Unlock,
};
use scaas_sdk::{Event, Limits, RuntimeChoice, Sdk, SdkConfig, SdkError};
use scaas_ua::wallet::SecretBytes;
use std::sync::Arc;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const TWELVE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn sec(s: &str) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(s.as_bytes().to_vec())).unwrap())
}

async fn open_with(store: Arc<dyn SecureStore>) -> Arc<Sdk> {
    open_limits(store, Limits::default()).await
}

async fn open_limits(store: Arc<dyn SecureStore>, limits: Limits) -> Arc<Sdk> {
    Sdk::open(SdkConfig {
        profiles: vec![],
        store,
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits,
    })
    .await
    .unwrap()
}

async fn sdk() -> (Arc<Sdk>, Arc<MemoryStore>) {
    let m = MemoryStore::new();
    (open_with(m.clone()).await, m)
}

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

async fn import(s: &Arc<Sdk>, label: &str, words: &str) -> Result<String, SdkError> {
    let req = ImportWords {
        label: label.into(),
        words: sec(words),
        vault_passphrase: sec(PASS),
    };
    s.vault().import_words(req).await.map(|i| i.id)
}

/// A mnemonic of `n` words (the BIP-39 crate, the reference outside the SDK).
fn mnemonic(n: usize, fill: u8) -> String {
    bip39::Mnemonic::from_entropy(&vec![fill; n * 4 / 3])
        .unwrap()
        .to_string()
}

/// One field changed behind the SDK.
type Change = Box<dyn Fn(&mut Keystore)>;

async fn stored(m: &MemoryStore) -> Keystore {
    let i = m
        .get("keystore".into(), String::new())
        .await
        .unwrap()
        .unwrap();
    Keystore::parse(&i.bytes).unwrap()
}

/// Replaces the stored container behind the SDK (a tampered file).
async fn tamper(m: &MemoryStore, f: impl FnOnce(&mut Keystore)) {
    let i = m
        .get("keystore".into(), String::new())
        .await
        .unwrap()
        .unwrap();
    let mut ks = Keystore::parse(&i.bytes).unwrap();
    f(&mut ks);
    m.put_if(
        "keystore".into(),
        Some(i.rev),
        ks.serialize().unwrap().into_bytes(),
        StorePolicy::default(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn generate_makes_24_words_and_a_pending_backup() {
    let (s, m) = sdk().await;
    let new = s
        .vault()
        .generate(Generate {
            label: "Main".into(),
            vault_passphrase: sec(PASS),
        })
        .await
        .unwrap();
    assert_eq!(
        (
            new.info.words,
            new.info.backup.as_str(),
            new.info.origin.as_str()
        ),
        (24, "pending", "generated")
    );
    assert_eq!(
        stored(&m).await.seeds[0].backup,
        "pending",
        "written before the backup is handed out"
    );
    let words = new.backup.reveal().unwrap();
    let text = words.with(|b| String::from_utf8(b.to_vec()).unwrap());
    assert_eq!(text.split(' ').count(), 24);
    assert_eq!(code(new.backup.reveal()), "Argument", "revealed once");
    let asked = new.backup.challenge().unwrap();
    let all: Vec<&str> = text.split(' ').collect();
    let wrong = sec("zoo zoo zoo");
    assert!(!new.backup.verify(wrong).unwrap());
    let asked = new.backup.challenge().unwrap_or(asked);
    let answers: Vec<&str> = asked.iter().map(|p| all[*p as usize - 1]).collect();
    assert!(new.backup.verify(sec(&answers.join(" "))).unwrap());
    s.vault().confirm_backup(new.info.id.clone()).await.unwrap();
    assert_eq!(stored(&m).await.seeds[0].backup, "verified");
}

#[tokio::test]
async fn import_accepts_12_to_24() {
    let (s, _) = sdk().await;
    for (i, n) in [12usize, 15, 18, 21, 24].iter().enumerate() {
        let id = import(&s, &format!("S{n}"), &mnemonic(*n, i as u8 + 1))
            .await
            .unwrap();
        let info = s.vault().seed(id).await.unwrap();
        let want: Vec<String> = if *n < 24 {
            vec!["short_seed".into()]
        } else {
            vec![]
        };
        assert_eq!(
            (
                info.words,
                info.warnings,
                info.backup.as_str(),
                info.origin.as_str()
            ),
            (*n as u32, want, "verified", "imported")
        );
    }
}

#[tokio::test]
async fn word_in_list() {
    let (s, _) = sdk().await;
    assert!(s.vault().word_in_list(sec("bench")));
    assert!(!s.vault().word_in_list(sec("benchh")));
    assert!(!s.vault().word_in_list(sec("bnech")));
}

#[tokio::test]
async fn import_refuses_13_words_and_a_bad_checksum() {
    let (s, _) = sdk().await;
    assert_eq!(
        code(import(&s, "A", &format!("{TWELVE} abandon")).await),
        "MnemonicInvalid"
    );
    assert_eq!(
        code(import(&s, "B", &TWELVE.replace("about", "abandon")).await),
        "MnemonicInvalid"
    );
    assert_eq!(code(import(&s, "C", TWELVE).await), "Ok", "control");
}

#[tokio::test]
async fn vault_passphrase_rule() {
    let (s, _) = sdk().await;
    for (pass, want) in [
        ("1234567", "VaultPassphraseWeak"),
        ("12345678901", "VaultPassphraseWeak"),
        ("abcdefg", "VaultPassphraseWeak"),
        ("abcdefgh", "Ok"),
    ] {
        let req = ImportWords {
            label: pass.into(),
            words: sec(TWELVE),
            vault_passphrase: sec(pass),
        };
        assert_eq!(code(s.vault().import_words(req).await), want, "{pass}");
    }
}

#[tokio::test]
async fn unlock_lock_revokes_handles() {
    let (s, _) = sdk().await;
    let id = import(&s, "Main", REPO).await.unwrap();
    let ev = s.subscribe();
    s.vault().lock(id.clone()).await;
    assert_eq!(
        ev.next(1000).await,
        Some(Event::SeedLocked { seed: id.clone() })
    );
    assert_eq!(
        code(s.vault().rename(id.clone(), "X".into()).await),
        "WalletLocked",
        "refused at once after lock"
    );
    s.vault()
        .unlock(id.clone(), Unlock::Passphrase(sec(PASS)))
        .await
        .unwrap();
    assert_eq!(
        ev.next(1000).await,
        Some(Event::SeedUnlocked { seed: id.clone() })
    );
    s.vault().rename(id.clone(), "X".into()).await.unwrap();
    assert_eq!(s.vault().lock_all().await, Vec::<String>::new());
    assert!(!s.vault().seed(id).await.unwrap().unlocked);
}

#[tokio::test]
async fn wrong_passphrase_is_vault_open() {
    let (s, _) = sdk().await;
    let id = import(&s, "Main", REPO).await.unwrap();
    s.vault().lock(id.clone()).await;
    assert_eq!(
        code(
            s.vault()
                .unlock(id.clone(), Unlock::Passphrase(sec("river-otter-8 ünï")))
                .await
        ),
        "VaultOpen"
    );
    assert_eq!(
        code(
            s.vault()
                .unlock(id.clone(), Unlock::Passphrase(sec(PASS)))
                .await
        ),
        "Ok"
    );
    assert_eq!(
        code(
            s.vault()
                .unlock("no-such".into(), Unlock::Passphrase(sec(PASS)))
                .await
        ),
        "SeedUnknown"
    );
}

#[tokio::test]
async fn seed_exists_on_reimport_and_label_taken() {
    let (s, _) = sdk().await;
    import(&s, "Main", REPO).await.unwrap();
    assert_eq!(code(import(&s, "Again", REPO).await), "SeedExists");
    assert_eq!(code(import(&s, "Main", TWELVE).await), "LabelTaken");
    assert_eq!(code(import(&s, "Other", TWELVE).await), "Ok");
    let id = s.vault().seeds().await.unwrap()[1].id.clone();
    assert_eq!(
        code(s.vault().rename(id, "Main".into()).await),
        "LabelTaken"
    );
}

#[tokio::test]
async fn remove_pending_needs_both_markers() {
    let (s, m) = sdk().await;
    let new = s
        .vault()
        .generate(Generate {
            label: "Main".into(),
            vault_passphrase: sec(PASS),
        })
        .await
        .unwrap();
    let id = new.info.id;
    let r = Remove {
        seed: id.clone(),
        confirm: ConfirmRemove,
        unbacked: None,
    };
    assert_eq!(code(s.vault().remove(r).await), "ConfirmationMissing");
    assert_eq!(stored(&m).await.seeds.len(), 1);
    let r = Remove {
        seed: id.clone(),
        confirm: ConfirmRemove,
        unbacked: Some(ConfirmRemoveUnbacked),
    };
    s.vault().remove(r).await.unwrap();
    assert!(stored(&m).await.seeds.is_empty());
    // a verified seed needs the first marker only
    let id = import(&s, "Imported", REPO).await.unwrap();
    s.vault()
        .remove(Remove {
            seed: id,
            confirm: ConfirmRemove,
            unbacked: None,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn mac_mismatch_keeps_the_seed_locked() {
    let changes: Vec<(&str, Change)> = vec![
        (
            "label",
            Box::new(|k: &mut Keystore| k.seeds[0].label = "Changed".into()),
        ),
        (
            "class",
            Box::new(|k: &mut Keystore| k.seeds[0].class = "classical-rooted".into()),
        ),
        (
            "warning",
            Box::new(|k: &mut Keystore| k.seeds[0].warnings = vec!["imported_key".into()]),
        ),
        (
            "backup",
            Box::new(|k: &mut Keystore| k.seeds[0].backup = "pending".into()),
        ),
        (
            "account row",
            Box::new(|k: &mut Keystore| {
                k.seeds[0]
                    .accounts
                    .push(scaas_sdk::vault::AccountRow::Watch {
                        id: "6f1d1f4e-58b5-4d0c-8a6e-1a2b3c4d5e6f".into(),
                        name: "x".into(),
                        watch: "0x01".into(),
                    })
            }),
        ),
        (
            "a seed vault moved under another entry",
            Box::new(|k: &mut Keystore| {
                let other = k.seeds[1].vaults["seed"].clone();
                k.seeds[0].vaults.insert("seed".into(), other);
            }),
        ),
    ];
    for (what, f) in changes {
        let (s, m) = sdk().await;
        let id = import(&s, "Main", mnemonic(24, 3).as_str()).await.unwrap();
        import(&s, "Second", mnemonic(24, 4).as_str())
            .await
            .unwrap();
        s.vault().lock(id.clone()).await;
        tamper(&m, f).await;
        let ev = s.subscribe();
        assert_eq!(
            code(
                s.vault()
                    .unlock(id.clone(), Unlock::Passphrase(sec(PASS)))
                    .await
            ),
            "KeystoreMismatch",
            "{what}"
        );
        assert_eq!(
            ev.next(1000).await,
            Some(Event::KeystoreMismatch { seed: id.clone() }),
            "{what}"
        );
        assert!(
            !s.vault().seed(id.clone()).await.unwrap().unlocked,
            "{what}: stays locked"
        );
    }
    // control: the untouched container unlocks
    let (s, _) = sdk().await;
    let id = import(&s, "Main", mnemonic(24, 3).as_str()).await.unwrap();
    s.vault().lock(id.clone()).await;
    s.vault()
        .unlock(id, Unlock::Passphrase(sec(PASS)))
        .await
        .unwrap();
}

#[tokio::test]
async fn locked_rows_are_unverified() {
    let (s, _) = sdk().await;
    let id = import(&s, "Main", REPO).await.unwrap();
    let (s2, _) = (open_with(Arc::new(MemoryStore::default())).await, ());
    drop(s2);
    s.vault().lock(id.clone()).await;
    let row = s.vault().seeds().await.unwrap().remove(0);
    assert_eq!((row.unlocked, row.verified), (false, false));
    s.vault()
        .unlock(id, Unlock::Passphrase(sec(PASS)))
        .await
        .unwrap();
    let row = s.vault().seeds().await.unwrap().remove(0);
    assert_eq!((row.unlocked, row.verified), (true, true));
}

#[tokio::test]
async fn index_changes_need_the_seed_unlocked() {
    let (s, m) = sdk().await;
    let id = import(&s, "Main", REPO).await.unwrap();
    s.vault().lock(id.clone()).await;
    let before = stored(&m).await;
    assert_eq!(
        code(s.vault().rename(id.clone(), "New".into()).await),
        "WalletLocked"
    );
    assert_eq!(
        code(s.vault().confirm_backup(id.clone()).await),
        "WalletLocked"
    );
    assert_eq!(stored(&m).await, before, "nothing written");
    s.vault()
        .unlock(id.clone(), Unlock::Passphrase(sec(PASS)))
        .await
        .unwrap();
    s.vault().rename(id.clone(), "New".into()).await.unwrap();
    // the rewritten MAC verifies at the next unlock
    s.vault().lock(id.clone()).await;
    s.vault()
        .unlock(id, Unlock::Passphrase(sec(PASS)))
        .await
        .unwrap();
}

#[tokio::test]
async fn hidden_set_writes_and_emits_nothing() {
    let (s, m) = sdk().await;
    let id = import(&s, "Main", REPO).await.unwrap();
    let before = m.get("keystore".into(), String::new()).await.unwrap();
    let ev = s.subscribe();
    let h = s
        .vault()
        .open_hidden(id.clone(), Unlock::Passphrase(sec(PASS)), sec("hidden ünï"))
        .await
        .unwrap();
    assert_eq!(ev.next(200).await, None, "no event");
    assert_eq!(
        m.get("keystore".into(), String::new()).await.unwrap(),
        before,
        "nothing written"
    );
    assert!(m
        .get("sdk.state".into(), String::new())
        .await
        .unwrap()
        .is_none());
    assert_ne!(h.id, id, "its own id");
    assert!(scaas_sdk::vault::keystore::is_uuid4(&h.id));
    assert!(
        s.vault()
            .seeds()
            .await
            .unwrap()
            .iter()
            .all(|r| r.id != h.id),
        "not listed"
    );
    s.vault().lock(id.clone()).await;
    assert_eq!(
        ev.next(1000).await,
        Some(Event::HiddenOpsAbandoned { count: 0 })
    );
    assert_eq!(ev.next(1000).await, Some(Event::SeedLocked { seed: id }));
    assert_eq!(
        m.get("keystore".into(), String::new()).await.unwrap(),
        before
    );
}

#[tokio::test]
async fn hidden_set_wrong_passphrase_is_another_set() {
    let (s, _) = sdk().await;
    let id = import(&s, "Main", REPO).await.unwrap();
    let a = s
        .vault()
        .open_hidden(id.clone(), Unlock::Passphrase(sec(PASS)), sec("one"))
        .await
        .unwrap();
    let b = s
        .vault()
        .open_hidden(id.clone(), Unlock::Passphrase(sec(PASS)), sec("two"))
        .await
        .unwrap();
    assert_ne!(a.id, b.id);
    assert_eq!(
        code(
            s.vault()
                .open_hidden(id, Unlock::Passphrase(sec("wrong-pass-9")), sec("x"))
                .await
        ),
        "VaultOpen"
    );
}

#[tokio::test]
async fn vault_never_formatted() {
    // nothing in the SDK logs yet: no `tracing` call, so no `Vault` can reach a log line; a `{:?}` of a vault would need one
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = vec![src];
    let mut seen = 0;
    while let Some(p) = files.pop() {
        if p.is_dir() {
            files.extend(std::fs::read_dir(p).unwrap().map(|e| e.unwrap().path()));
        } else if p.extension().is_some_and(|e| e == "rs") {
            let t = std::fs::read_to_string(&p).unwrap();
            assert!(!t.contains("tracing::"), "{}", p.display());
            seen += 1;
        }
    }
    assert!(seen > 5, "control: the sources were read");
}

#[test]
fn classical_roots_absent() {
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .unwrap();
    assert!(
        !manifest.contains("classical-roots ="),
        "the feature does not exist before plan T6"
    );
    assert!(manifest.contains("\nvault ="), "control");
}

#[cfg(feature = "file-store")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_sdks_one_directory_generate_and_import() {
    let d = std::env::temp_dir().join(format!("scaas-sdk-vault-two-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let a = open_with(scaas_sdk::vault::FileStore::new(&d).unwrap()).await;
    let b = open_with(scaas_sdk::vault::FileStore::new(&d).unwrap()).await;
    let (va, vb) = (a.vault(), b.vault());
    let (ra, rb) = tokio::join!(
        va.generate(Generate {
            label: "A".into(),
            vault_passphrase: sec(PASS)
        }),
        vb.import_words(ImportWords {
            label: "B".into(),
            words: sec(REPO),
            vault_passphrase: sec(PASS)
        })
    );
    ra.unwrap();
    rb.unwrap();
    let labels: Vec<String> = a
        .vault()
        .seeds()
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.label)
        .collect();
    assert_eq!(labels.len(), 2);
    std::fs::remove_dir_all(&d).unwrap();
}

fn key_req(seed: &str, network: &str, secret: &[u8], pass: &str) -> ImportKey {
    ImportKey {
        seed: seed.into(),
        network: network.into(),
        secret: Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(secret.to_vec())).unwrap()),
        vault_passphrase: sec(pass),
    }
}

/// Spec §6.7 (owner 2026-11-18: `import_key` in T4): the key sealed as `native-import:<network>:<n>`, the manifest re-sealed,
/// the warning `imported_key` MAC'd; the seed unlocks again by its passphrase with the import in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_key_seals_a_leaf_and_marks_it() {
    let (s, m) = sdk().await;
    let id = import(&s, "Main", REPO).await.unwrap();
    let ev = s.subscribe();
    let k = s
        .vault()
        .import_key(key_req(&id, "evm", &[0x11; 32], PASS))
        .await
        .unwrap();
    assert_eq!((k.network.as_str(), k.index), ("evm", 0));
    assert!(matches!(
        ev.next(1000).await,
        Some(Event::KeystoreChanged { .. })
    ));
    let e = &stored(&m).await.seeds[0];
    assert!(e.vaults.contains_key("native-import:evm:0"));
    assert_eq!(e.warnings, vec!["imported_key".to_owned()]);
    let k2 = s
        .vault()
        .import_key(key_req(&id, "solana", &[0x22; 32], PASS))
        .await
        .unwrap();
    assert_eq!(k2.index, 1, "the next free number");
    assert_eq!(
        stored(&m).await.seeds[0].warnings,
        vec!["imported_key".to_owned()],
        "one mark"
    );
    s.vault().lock(id.clone()).await;
    s.vault()
        .unlock(id.clone(), Unlock::Passphrase(sec(PASS)))
        .await
        .unwrap();
    assert!(
        s.vault().seed(id).await.unwrap().verified,
        "the MAC covers the mark"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_key_refusals() {
    let (s, _) = sdk().await;
    let id = import(&s, "Main", REPO).await.unwrap();
    let v = s.vault();
    assert_eq!(
        code(
            v.import_key(key_req(&id, "evm", &[0x11; 32], "river-otter-8 ünï"))
                .await
        ),
        "VaultOpen",
        "another passphrase than the seed's"
    );
    assert_eq!(
        code(
            v.import_key(key_req(&id, "no-such", &[0x11; 32], PASS))
                .await
        ),
        "Argument"
    );
    assert_eq!(
        code(v.import_key(key_req(&id, "near", &[0x11; 32], PASS)).await),
        "Argument",
        "a network without import"
    );
    assert_eq!(
        code(v.import_key(key_req(&id, "evm", &[0x11; 31], PASS)).await),
        "Argument"
    );
    assert_eq!(
        code(
            v.import_key(key_req("no-such", "evm", &[0x11; 32], PASS))
                .await
        ),
        "WalletLocked"
    );
    v.lock(id.clone()).await;
    assert_eq!(
        code(v.import_key(key_req(&id, "evm", &[0x11; 32], PASS)).await),
        "WalletLocked"
    );
    v.unlock(id.clone(), Unlock::Passphrase(sec(PASS)))
        .await
        .unwrap();
    assert_eq!(
        code(v.import_key(key_req(&id, "evm", &[0x11; 32], PASS)).await),
        "Ok",
        "control"
    );
}

/// Two unlocks at once run their scrypt one at a time under `max_concurrent_heavy = 1`; at 2 they overlap (the control).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn heavy_work_one_at_a_time() {
    for (limit, want) in [(1u32, 1u32), (2, 2)] {
        let m = MemoryStore::new();
        let s = open_limits(
            m,
            Limits {
                max_concurrent_heavy: limit,
                ..Limits::default()
            },
        )
        .await;
        let a = import(&s, "A", REPO).await.unwrap();
        let b = import(&s, "B", TWELVE).await.unwrap();
        s.vault().lock_all().await;
        let (va, vb) = (s.vault(), s.vault());
        let (ra, rb) = tokio::join!(
            va.unlock(a, Unlock::Passphrase(sec(PASS))),
            vb.unlock(b, Unlock::Passphrase(sec(PASS)))
        );
        ra.unwrap();
        rb.unwrap();
        assert_eq!(s.heavy_peak(), want, "limit {limit}");
    }
}

/// Owner 2026-11-18 (i): the passphrase is never retained: once `unlock` returns the SDK holds no reference to the caller's
/// secret, so dropping it zeroes and frees it (`SecretBytes` zeroes on drop; the copy call then finds no such id).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn passphrase_not_retained_after_unlock() {
    let (s, _) = sdk().await;
    let id = import(&s, "Main", REPO).await.unwrap();
    s.vault().lock(id.clone()).await;
    let pass = sec(PASS);
    let sid = pass.id();
    s.vault()
        .unlock(id, Unlock::Passphrase(pass.clone()))
        .await
        .unwrap();
    assert_eq!(Arc::strong_count(&pass), 1, "no copy of the handle kept");
    let mut buf = [0u8; 64];
    assert!(
        scaas_ua::wallet::secret_read(sid, &mut buf).is_ok(),
        "control: alive while held"
    );
    drop(pass);
    assert!(
        scaas_ua::wallet::secret_read(sid, &mut buf).is_err(),
        "gone (zeroed and freed) once dropped"
    );
}
