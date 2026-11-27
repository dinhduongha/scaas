// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! User profiles (spec docs/superpowers/specs/2026-11-27-user-profiles.md, plan docs/superpowers/plans/2026-11-27-user-profiles.md):
//! the SDK's side of the store `scaas-profile` (owner 2026-11-27; the store's own tests are clients/scaas-profile/tests/). UP5:
//! the `SecureStore` face and the codes. Profiles are built by hand: a generation directory and a `ProfileKeys` with a fresh
//! `DEK_p` (`create_dek`, no Argon2id). UP6b (§10 lock, §11, §17 G11): `UserProfiles`, `UserProfile::sdk`, `Sdk::close`; the
//! protected profiles there are planted by hand (one wrap at the test KDF set) and opened through `UserProfiles`. UP7 (§7.3,
//! §7.6): `set_passphrase` and `change_passphrase` through `UserProfile`, and every secret-creating call refused
//! `ProfilePassphraseRequired` before any work on an unprotected profile's `Sdk`. UP8 (§8): the hidden calls route to the
//! store's (its own tests are clients/scaas-profile/tests/hidden.rs). UP10 (§7.7, §10.1; §17 settings R2-C-3, G9): the
//! settings rule, export and import through the SDK (the store's own tests: clients/scaas-profile/tests/{settings,export}.rs).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

#[cfg(feature = "evm")]
#[path = "common/fake_chain.rs"]
mod fake_chain;

use scaas_sdk::user_profile::{
    Core, CoreOpen, Error, Head, KdfParams, PartStore, ProfilePart, ProfileSdkConfig,
    ProfileUnlock, ProfilesConfig, UserProfile, UserProfiles,
};
use scaas_sdk::vault::{ImportWords, SecureStore, StoreError, StorePolicy, Unlock};
use scaas_sdk::{ChainProfile, Event, RuntimeChoice, SdkError};
use scaas_ua::wallet::{ProfileKeys, SecretBytes};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

const SDK: ProfilePart = ProfilePart::Sdk;

fn tmp() -> PathBuf {
    use std::hash::{BuildHasher, RandomState};
    let d = std::env::temp_dir().join(format!(
        "scaas-sdk-up-{}-{:x}",
        std::process::id(),
        RandomState::new().hash_one(0u8)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn keys() -> Arc<ProfileKeys> {
    let k = ProfileKeys::new();
    k.create_dek().unwrap();
    Arc::new(k)
}

fn open(dir: &Path, keys: &Arc<ProfileKeys>) -> Core {
    Core::open(CoreOpen {
        dir: dir.to_path_buf(),
        id: "01a21ce0-6e7b-7e63-9b1d-f667cc7d8daa".into(),
        gen: 1,
        keys: Some(keys.clone()),
        keychain: None,
        envelope: Head::of(1, b"profile.envelope at rev 1"),
        migration_pending: false,
    })
    .unwrap()
}

fn item(rev: u64, body: &str) -> Vec<u8> {
    format!(r#"{{"rev":{rev},"body":"{body}"}}"#).into_bytes()
}

fn file_of(dir: &Path, keys: &ProfileKeys, part: &str, name: &str) -> PathBuf {
    dir.join("g1").join(keys.item_file(part, name).unwrap())
}

/// The store's codes reach the SDK by name: each `scaas-profile` code is the `SdkError` of the same name (none collapsed).
#[test]
fn store_codes_are_the_sdks() {
    assert_eq!(Error::ALL.len(), 28);
    for e in Error::ALL {
        assert_eq!(SdkError::from(*e).code(), e.code());
    }
}

/// The `SecureStore` face: items round-trip under the face's revisions; `keystore.head` passes through unsealed to the profile
/// directory; `lock(name)` is the item's `.lock` file; the core's codes reach the store's.
#[tokio::test(flavor = "multi_thread")]
async fn secure_store_face() {
    let (d, k) = (tmp(), keys());
    let core = Arc::new(open(&d, &k));
    let s = PartStore::new(core.clone(), SDK).unwrap();
    let p = StorePolicy::default();
    s.put_if("keystore".into(), None, item(1, "k"), p)
        .await
        .unwrap();
    let got = s
        .get("keystore".into(), String::new())
        .await
        .unwrap()
        .unwrap();
    assert_eq!((got.bytes, got.rev), (item(1, "k"), 1));
    assert_eq!(
        s.put_if("keystore".into(), None, item(1, "k"), p).await,
        Err(StoreError::Conflict)
    );
    let head = br#"{"rev":1,"sha256":"00112233445566778899aabbccddeeff"}"#.to_vec();
    s.put_if("keystore.head".into(), None, head.clone(), p)
        .await
        .unwrap();
    assert_eq!(std::fs::read(d.join("keystore.head")).unwrap(), head);
    assert_eq!(
        s.get("keystore.head".into(), String::new())
            .await
            .unwrap()
            .unwrap()
            .bytes,
        head
    );
    let held = s.lock("keystore".into()).await.unwrap();
    let lock = file_of(&d, &k, "sdk", "keystore").with_extension("lock");
    let other = std::fs::OpenOptions::new().write(true).open(&lock).unwrap();
    assert!(other.try_lock().is_err(), "held");
    drop(held);
    assert!(other.try_lock().is_ok(), "released");
    s.delete("keystore".into()).await.unwrap();
    assert!(s
        .get("keystore".into(), String::new())
        .await
        .unwrap()
        .is_none());
    // codes: a rollback and a busy writer through the face
    s.put_if("settings".into(), None, item(1, "a"), p)
        .await
        .unwrap();
    let f = file_of(&d, &k, "sdk", "settings");
    let old = std::fs::read(&f).unwrap();
    s.put_if("settings".into(), Some(1), item(2, "b"), p)
        .await
        .unwrap();
    std::fs::write(&f, old).unwrap();
    // review C-3 (spec §7.2): a rolled-back item reads; a write to it is `ProfileRollback` until it is accepted
    assert_eq!(
        s.get("settings".into(), String::new())
            .await
            .unwrap()
            .unwrap()
            .bytes,
        item(1, "a")
    );
    assert_eq!(
        s.put_if("settings".into(), Some(1), item(2, "c"), p).await,
        Err(StoreError::ProfileRollback)
    );
    core.set_write_wait(Duration::from_millis(50));
    let g = core.write_lock().unwrap();
    // owner 2026-11-28: the store's own code by name (it was `Unavailable`)
    assert_eq!(
        s.put_if("sdk.state".into(), None, item(1, "s"), p).await,
        Err(StoreError::ProfileBusy)
    );
    drop(g);
}

// ---- UP6b: UserProfiles, UserProfile::sdk, Sdk::close (spec §10 lock, §11; §17 G11) ----

const PASS: &str = "correct horse battery staple";
const VAULT_PASS: &str = "river-otter-7 \u{fc}n\u{ef}";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";

fn sec(s: &str) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(s.as_bytes().to_vec())).unwrap())
}

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

/// A protected profile at the test KDF set planted under `root/p/` by hand (one wrap of a fresh `DEK_p`, its label, its hint
/// `name`), as scaas-profile's own tests build one; start rebuilds the index from it. Returns its id.
fn plant_protected(root: &Path, name: &str) -> String {
    use base64::Engine;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let k = ProfileKeys::new();
    let r: [u8; 10] = ProfileKeys::random_bytes(10).unwrap()[..]
        .try_into()
        .unwrap();
    let id = scaas_profile::uuid7(ms, &r);
    let salt = ProfileKeys::random_bytes(16).unwrap();
    let kdf = format!(
        r#"{{"alg":"argon2id","v":1,"m":8192,"t":1,"p":4,"salt":"{}"}}"#,
        b64(&salt[..])
    );
    let public = format!(
        r#"{{"format":"scaas.profile","v":1,"id":"{id}","state":"protected","gen":1,"kdf":{kdf}}}"#
    );
    k.create_dek().unwrap();
    let wrap = k
        .wrap_pass(
            PASS.as_bytes(),
            &salt,
            ProfileKeys::KDF_TEST,
            public.as_bytes(),
        )
        .unwrap();
    let label = k
        .seal_label(
            &id,
            1,
            format!(r#"{{"name":"{name}","hidden":false}}"#).as_bytes(),
        )
        .unwrap();
    let d = root.join("p").join(&id);
    // its generation too: a protected profile without its `g<gen>/` is `ProfileDamaged` (review G-11)
    std::fs::create_dir_all(d.join("g1")).unwrap();
    std::fs::write(
        d.join("profile.envelope"),
        format!(
            r#"{{"format":"scaas.profile","v":1,"id":"{id}","state":"protected","rev":1,"gen":1,"name":"{name}","kdf":{kdf},"pass":"{}","label":"{}"}}"#,
            b64(&wrap),
            b64(&label)
        ),
    )
    .unwrap();
    id
}

/// A root holding one planted protected profile, started; the profile opened by its passphrase.
async fn open_protected() -> (Arc<UserProfiles>, Arc<UserProfile>, PathBuf) {
    let root = tmp().join("root");
    let id = plant_protected(&root, "work");
    let ups = UserProfiles::new(ProfilesConfig::new(root.to_string_lossy().into_owned()))
        .await
        .unwrap();
    let up = ups
        .open(id, Some(ProfileUnlock::Passphrase(sec(PASS))))
        .await
        .unwrap();
    (ups, up, root)
}

/// Review C-3 through the SDK: an old copy of an item put back reads, `Event::ProfileRollback` reaches
/// `UserProfiles::events()`, and a write to it is `ProfileRollback` until `UserProfile::accept_rollback`; then it writes.
#[tokio::test(flavor = "multi_thread")]
async fn c3_accept_rollback_through_sdk() {
    let (ups, up, _root) = open_protected().await;
    let s = up.part_store(ProfilePart::PqVault).unwrap();
    let p = StorePolicy::default();
    s.put_if("a".into(), None, item(1, "old"), p).await.unwrap();
    let core = up.core();
    let f = file_of(core.dir(), &core.keys().unwrap(), "pqvault", "a");
    let old = std::fs::read(&f).unwrap();
    s.put_if("a".into(), Some(1), item(2, "new"), p)
        .await
        .unwrap();
    std::fs::write(&f, old).unwrap();
    ups.events();
    let got = s.get("a".into(), String::new()).await.unwrap().unwrap();
    assert_eq!(got.bytes, item(1, "old"));
    assert!(ups.events().contains(&Event::ProfileRollback));
    assert_eq!(
        s.put_if("a".into(), Some(1), item(2, "again"), p).await,
        Err(StoreError::ProfileRollback)
    );
    up.accept_rollback(ProfilePart::PqVault, "a".into())
        .await
        .unwrap();
    s.put_if("a".into(), Some(1), item(2, "again"), p)
        .await
        .unwrap();
}

fn sdk_config(chain_profiles: Vec<ChainProfile>) -> ProfileSdkConfig {
    ProfileSdkConfig {
        chain_profiles,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        clock: None,
        gas_tables: vec![],
    }
}

/// G11: `sdk()` twice returns the same `Sdk`; after `lock` every call on the old `Sdk` is `ProfileLocked` (a vault call, a
/// second `sdk()`), and so is every call of the store face, `keystore.head` included. Each beside its control before the lock.
#[tokio::test(flavor = "multi_thread")]
async fn g11_sdk_twice_and_locked() {
    let (ups, up, _) = open_protected().await;
    assert_eq!(code(ups.list().await.map(|l| l.len())), "Ok");
    let s = up.sdk(sdk_config(vec![])).await.unwrap();
    let again = up.sdk(sdk_config(vec![])).await.unwrap();
    assert!(Arc::ptr_eq(&s, &again), "sdk() twice: the same Sdk");
    let face = up.part_store(ProfilePart::PqVault).unwrap();
    let p = StorePolicy::default();
    face.put_if("cache".into(), None, item(1, "c"), p)
        .await
        .unwrap();
    let head = PartStore::new(up.core(), SDK).unwrap();
    let anchor = br#"{"rev":1,"sha256":"00112233445566778899aabbccddeeff"}"#.to_vec();
    head.put_if("keystore.head".into(), None, anchor, p)
        .await
        .unwrap();
    assert_eq!(code(s.vault().seeds().await.map(|v| v.len())), "Ok");
    assert!(up.clone().lock().await.is_empty());
    assert_eq!(code(s.vault().seeds().await), "ProfileLocked");
    assert_eq!(code(s.vault().seed("x".into()).await), "ProfileLocked");
    assert_eq!(code(up.sdk(sdk_config(vec![])).await), "ProfileLocked");
    assert_eq!(
        face.get("cache".into(), String::new()).await,
        Err(StoreError::ProfileLocked)
    );
    assert_eq!(
        head.get("keystore.head".into(), String::new()).await,
        Err(StoreError::ProfileLocked),
        "keystore.head passes through the face, never past the lock"
    );
    assert_eq!(
        head.put_if("keystore.head".into(), Some(1), item(2, "h"), p)
            .await,
        Err(StoreError::ProfileLocked)
    );
    assert_eq!(
        code(up.part_store(ProfilePart::PqVault).map(|_| ())),
        "ProfileLocked"
    );
    assert_eq!(code(up.matrix_store().map(|_| ())), "ProfileLocked");
}

/// G11 (A-8's fix): `lock` with a hidden set open on a seed that is not unlocked revokes it.
#[tokio::test(flavor = "multi_thread")]
async fn g11_lock_revokes_hidden_set_of_a_locked_seed() {
    let (_ups, up, _) = open_protected().await;
    let s = up.sdk(sdk_config(vec![])).await.unwrap();
    let id = s
        .vault()
        .import_words(ImportWords {
            label: "Main".into(),
            words: sec(REPO),
            vault_passphrase: sec(VAULT_PASS),
        })
        .await
        .unwrap()
        .id;
    s.vault().lock(id.clone()).await;
    assert!(!s.vault().seed(id.clone()).await.unwrap().unlocked);
    s.vault()
        .open_hidden(id, Unlock::Passphrase(sec(VAULT_PASS)), sec("h"))
        .await
        .unwrap();
    let ev = s.subscribe();
    assert_eq!(
        up.clone().lock().await,
        Vec::<String>::new(),
        "lock's answer"
    );
    assert_eq!(
        ev.next(1000).await,
        Some(Event::HiddenOpsAbandoned { count: 0 }),
        "the hidden set is locked"
    );
}

/// The crate's events reach the SDK's by name: a UUID-named directory without an envelope is `ProfileDamaged` at start; a
/// clean root reports none (the control).
#[tokio::test(flavor = "multi_thread")]
async fn events_are_the_sdks() {
    let clean = tmp().join("root");
    let ups = UserProfiles::new(ProfilesConfig::new(clean.to_string_lossy().into_owned()))
        .await
        .unwrap();
    assert_eq!(ups.events(), Vec::<Event>::new());
    let root = tmp().join("root");
    plant_protected(&root, "work");
    std::fs::create_dir_all(root.join("p/01a21ce0-6e7b-7e63-9b1d-f667cc7d8dab")).unwrap();
    let ups = UserProfiles::new(ProfilesConfig::new(root.to_string_lossy().into_owned()))
        .await
        .unwrap();
    assert_eq!(ups.events(), vec![Event::ProfileDamaged]);
    assert_eq!(ups.events(), Vec::<Event>::new(), "drained");
}

/// The fake chain at `url` as the EVM chain profile "local".
#[cfg(feature = "evm")]
fn local(url: String) -> ChainProfile {
    use fake_chain::{hash_of, CHAIN_ID};
    let endpoint = scaas_sdk::EndpointConfig {
        url,
        class: scaas_rpc::Class::Named,
        label: None,
        auth: None,
    };
    ChainProfile {
        key: "local".into(),
        family: scaas_sdk::Family::Evm,
        chain_id: Some(CHAIN_ID),
        chain_uid: hash_of(0),
        rpc: vec![endpoint],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: None,
        factory: Some("0x5ca00000000000000000000000000000000000f0".into()),
        router: None,
        finality: scaas_sdk::Finality::Finalized,
        tx_gas_cap: Some(1 << 24),
        gas: Default::default(),
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![],
        wrappers: vec![],
        tokens: vec![],
        l1_fee: None,
        pinned_reads: true,
        disabled_kinds: vec![],
        family_params: None,
    }
}

/// G11: after `lock` no request leaves on the old `Sdk` (`Sdk::close`: pools dropped, the closed flag): a chain call is
/// `ProfileLocked` by its exact code, and the fake chain sees nothing more. Control first: the same call reaches the chain each
/// time while the profile is open.
#[cfg(feature = "evm")]
#[tokio::test(flavor = "multi_thread")]
async fn g11_no_request_after_lock() {
    use fake_chain::{fake, serve};
    let c = fake();
    c.lock().unwrap().index = vec![];
    let url = serve(c.clone()).await;
    let (_ups, up, _) = open_protected().await;
    let s = up.sdk(sdk_config(vec![local(url)])).await.unwrap();
    let seen = || c.lock().unwrap().requests.len();
    let n0 = seen();
    assert_eq!(code(s.wallet().tokens("local".into(), true).await), "Ok");
    let n1 = seen();
    assert!(n1 > n0, "control: the call reaches the chain");
    assert_eq!(code(s.wallet().tokens("local".into(), true).await), "Ok");
    let n2 = seen();
    assert!(n2 > n1, "control: again");
    up.clone().lock().await;
    assert_eq!(
        code(s.wallet().tokens("local".into(), true).await),
        "ProfileLocked"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(seen(), n2, "no request after lock");
}

// ---- UP7: the re-seal through `UserProfile`, the gate on an unprotected profile's `Sdk` (spec §7.3, §7.6, §12) ----

const PASS2: &str = "another passphrase, longer";
const TEST_KDF: KdfParams = KdfParams { m_kib: 8192, t: 1 };

/// Spec §7.6: on the first run's unprotected "default", every secret-creating call of its `Sdk` (`generate`, `import_words`,
/// `derive_child`, `import_key`, `derive_from_signature`, `derive_from_key`, `create_passkey_key`, `create_se_key`, an app
/// core's construction under `app-core`) is `ProfilePassphraseRequired` before any work: the store sees no call. The positive
/// twin: after `set_passphrase` the same `Sdk` imports a seed, and the profile reopens with it under the passphrase.
#[tokio::test(flavor = "multi_thread")]
async fn passphrase_required_before_any_work() {
    use scaas_sdk::account::{CreatePasskeyKey, CreateSeKey};
    use scaas_sdk::platform::KeyPolicy;
    use scaas_sdk::vault::{DeriveChild, Generate, ImportKey};
    let root = tmp().join("root");
    let ups = UserProfiles::new(ProfilesConfig::new(root.to_string_lossy().into_owned()))
        .await
        .unwrap();
    let id = ups.list().await.unwrap()[0].id.clone();
    let up = ups.open(id.clone(), None).await.unwrap();
    let s = up.sdk(sdk_config(vec![])).await.unwrap();
    let (v, a) = (s.vault(), s.account());
    let core = up.core();
    let calls = core.calls();
    let words = || ImportWords {
        label: "Main".into(),
        words: sec(REPO),
        vault_passphrase: sec(VAULT_PASS),
    };
    let key = [7u8; 32];
    let refused = vec![
        code(
            v.generate(Generate {
                label: "G".into(),
                vault_passphrase: sec(VAULT_PASS),
            })
            .await
            .map(drop),
        ),
        code(v.import_words(words()).await.map(drop)),
        code(
            v.derive_child(DeriveChild {
                parent: "s".into(),
                label: "C".into(),
                vault_passphrase: sec(VAULT_PASS),
            })
            .await
            .map(drop),
        ),
        code(
            v.import_key(ImportKey {
                seed: "s".into(),
                network: "evm".into(),
                secret: Arc::new(
                    SecretBytes::from_zeroizing(Zeroizing::new(key.to_vec())).unwrap(),
                ),
                vault_passphrase: sec(VAULT_PASS),
            })
            .await
            .map(drop),
        ),
        code(
            a.create_passkey_key(CreatePasskeyKey {
                seed: "s".into(),
                name: "pk".into(),
            })
            .await
            .map(drop),
        ),
        code(
            a.create_se_key(CreateSeKey {
                seed: "s".into(),
                name: "se".into(),
                policy: KeyPolicy {
                    biometry_current_set: true,
                    invalidated_by_enrollment: true,
                },
            })
            .await
            .map(drop),
        ),
    ];
    #[cfg(feature = "classical-roots")]
    let refused = [
        refused,
        vec![
            code(
                v.derive_from_signature(scaas_sdk::vault::DeriveFromSignature {
                    label: "S".into(),
                    account: "0x5ca0000000000000000000000000000000000001".into(),
                    set: 0,
                    signature1: sec("one"),
                    signature2: sec("two"),
                    derivation_passphrase: sec("a derivation passphrase"),
                    vault_passphrase: sec(VAULT_PASS),
                })
                .await
                .map(drop),
            ),
            code(
                v.derive_from_key(scaas_sdk::vault::DeriveFromKey {
                    label: "K".into(),
                    network: "evm".into(),
                    key: Arc::new(
                        SecretBytes::from_zeroizing(Zeroizing::new(key.to_vec())).unwrap(),
                    ),
                    derivation_passphrase: sec("a derivation passphrase"),
                    index: 0,
                    vault_passphrase: sec(VAULT_PASS),
                })
                .await
                .map(drop),
            ),
        ],
    ]
    .concat();
    let n = if cfg!(feature = "classical-roots") {
        8
    } else {
        6
    };
    assert_eq!(refused.len(), n);
    assert!(
        refused.iter().all(|c| *c == "ProfilePassphraseRequired"),
        "{refused:?}"
    );
    #[cfg(feature = "app-core")]
    assert_eq!(
        code(
            scaas_sdk::app_core::AppCore::new(
                s.clone(),
                scaas_sdk::app_core::AppDesc {
                    app_id: None,
                    name: "My App".into(),
                    class: None,
                    labels: vec!["scaas/my-app/v1/".into()],
                },
            )
            .map(drop)
        ),
        "ProfilePassphraseRequired"
    );
    assert_eq!(
        core.calls(),
        calls,
        "refused before any work: no store call"
    );
    // the positive twin
    up.set_passphrase(sec(PASS), Some(TEST_KDF), None, None)
        .await
        .unwrap();
    let seed = v.import_words(words()).await.unwrap().id;
    assert!(core.calls() > calls);
    up.clone().lock().await;
    let up = ups
        .open(id, Some(ProfileUnlock::Passphrase(sec(PASS))))
        .await
        .unwrap();
    let s = up.sdk(sdk_config(vec![])).await.unwrap();
    assert_eq!(s.vault().seeds().await.unwrap()[0].id, seed);
}

/// `change_passphrase` through `UserProfile` (spec §7.3): the open `Sdk` keeps working on the new generation (its keystore
/// read and written after the commit); the profile reopens under the new passphrase only.
#[tokio::test(flavor = "multi_thread")]
async fn change_passphrase_through_sdk() {
    let (ups, up, _) = open_protected().await;
    let s = up.sdk(sdk_config(vec![])).await.unwrap();
    let seed = s
        .vault()
        .import_words(ImportWords {
            label: "Main".into(),
            words: sec(REPO),
            vault_passphrase: sec(VAULT_PASS),
        })
        .await
        .unwrap()
        .id;
    assert_eq!(
        code(
            up.change_passphrase(sec(PASS2), sec(PASS), Some(TEST_KDF))
                .await
        ),
        "ProfileOpen"
    );
    up.change_passphrase(sec(PASS), sec(PASS2), Some(TEST_KDF))
        .await
        .unwrap();
    assert_eq!(s.vault().seeds().await.unwrap()[0].id, seed);
    s.vault().lock(seed.clone()).await;
    let id = s.vault().seeds().await.unwrap()[0].id.clone();
    up.clone().lock().await;
    let list = ups.list().await.unwrap();
    let pid = list[0].id.clone();
    assert_eq!(
        code(
            ups.open(pid.clone(), Some(ProfileUnlock::Passphrase(sec(PASS))))
                .await
                .map(drop)
        ),
        "ProfileOpen"
    );
    let up = ups
        .open(pid, Some(ProfileUnlock::Passphrase(sec(PASS2))))
        .await
        .unwrap();
    let s = up.sdk(sdk_config(vec![])).await.unwrap();
    assert_eq!(s.vault().seeds().await.unwrap()[0].id, id);
}

/// UP8: `create_hidden`, `open_hidden`, `hide`, `show` and `rename` route to the store's calls (name and passphrase as
/// `SecretBytes`): a hidden profile is unlisted and opens by its name in another case; a wrong passphrase is `ProfileOpen`; a
/// hidden rename without its passphrase `Argument`, with it the new name opens; `show` lists it, `hide` takes it off.
#[tokio::test(flavor = "multi_thread")]
async fn hidden_calls_route() {
    let root = tmp().join("root");
    let ups = UserProfiles::new(ProfilesConfig::new(root.to_string_lossy().into_owned()))
        .await
        .unwrap();
    let names = || async {
        let mut v: Vec<String> = ups
            .list()
            .await
            .unwrap()
            .into_iter()
            .map(|i| i.name)
            .collect();
        v.sort();
        v
    };
    let up = ups
        .create_hidden(sec("Hidden one"), sec(PASS), Some(TEST_KDF))
        .await
        .unwrap();
    up.lock().await;
    assert_eq!(names().await, ["default"]);
    assert_eq!(
        code(
            ups.open_hidden(sec("hidden ONE"), sec(PASS2))
                .await
                .map(drop)
        ),
        "ProfileOpen"
    );
    let up = ups.open_hidden(sec("hidden ONE"), sec(PASS)).await.unwrap();
    assert_eq!(code(up.rename(sec("Renamed"), None).await), "Argument");
    up.rename(sec("Renamed"), Some(sec(PASS))).await.unwrap();
    up.clone().lock().await;
    let up = ups.open_hidden(sec("renamed"), sec(PASS)).await.unwrap();
    up.show().await.unwrap();
    assert_eq!(names().await, ["Renamed", "default"]);
    up.hide(sec(PASS)).await.unwrap();
    assert_eq!(names().await, ["default"]);
}

// ---- UP9: delete, delete_locked, rebuild_index, the migrated "default" (spec §6, §10, §12; §17 G10, G4) ----

/// Spec §12: a migrated "default" holds the CLI's keystore while unprotected, so every vault call on its `Sdk` is
/// `ProfilePassphraseRequired` before any store call, until `set_passphrase` seals it; then the migrated keystore opens with
/// its seeds (the positive control: the legacy store written by the SDK itself over a `FileStore` at the CLI's directory, one
/// generated seed and one imported), the plain `g0/` is gone, the anchor followed, and the profile reopens under the
/// passphrase. `delete_preview` reads the migrated keystore throughout (two seeds, one without a backup).
#[tokio::test(flavor = "multi_thread")]
async fn migrated_default_refused_until_sealed() {
    use scaas_sdk::user_profile::ConfirmMigratedSeeds;
    use scaas_sdk::vault::{FileStore, Generate};
    use scaas_sdk::{Sdk, SdkConfig};
    let base = tmp();
    let (root, cli) = (base.join("root"), base.join("cli"));
    let legacy = Sdk::open(SdkConfig {
        profiles: vec![],
        store: FileStore::new(&cli).unwrap(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Default::default(),
        clock: None,
        gas_tables: vec![],
    })
    .await
    .unwrap();
    let (lv, gen) = (legacy.vault(), sec(VAULT_PASS));
    let generated = lv
        .generate(Generate {
            label: "G".into(),
            vault_passphrase: gen,
        })
        .await
        .unwrap()
        .info
        .id;
    let imported = lv
        .import_words(ImportWords {
            label: "Main".into(),
            words: sec(REPO),
            vault_passphrase: sec(VAULT_PASS),
        })
        .await
        .unwrap()
        .id;
    lv.lock_all().await;
    legacy.close().await;
    assert!(cli.join("keystore.head").is_file());
    let mut c = ProfilesConfig::new(root.to_string_lossy().into_owned());
    c.legacy = Some(cli.to_string_lossy().into_owned());
    let ups = UserProfiles::new(c).await.unwrap();
    let list = ups.list().await.unwrap();
    assert_eq!((list.len(), list[0].name.as_str()), (1, "default"));
    assert!(!cli.join("keystore").exists());
    let up = ups.open(list[0].id.clone(), None).await.unwrap();
    let s = up.sdk(sdk_config(vec![])).await.unwrap();
    let v = s.vault();
    let core = up.core();
    let calls = core.calls();
    let refused = vec![
        code(v.seeds().await.map(drop)),
        code(v.seed(imported.clone()).await.map(drop)),
        code(
            v.unlock(imported.clone(), Unlock::Passphrase(sec(VAULT_PASS)))
                .await,
        ),
        code(v.keystore_rollback().await.map(drop)),
        code(v.accept_rollback().await),
        code(
            v.import_words(ImportWords {
                label: "Two".into(),
                words: sec(REPO),
                vault_passphrase: sec(VAULT_PASS),
            })
            .await
            .map(drop),
        ),
    ];
    assert!(
        refused.iter().all(|c| *c == "ProfilePassphraseRequired"),
        "{refused:?}"
    );
    // the calls that first need an unlocked seed meet `WalletLocked` (no seed unlocks while the keystore is refused)
    assert_eq!(
        code(v.confirm_backup(generated.clone()).await),
        "WalletLocked"
    );
    assert_eq!(
        code(v.rename(imported.clone(), "Other".into()).await),
        "WalletLocked"
    );
    assert_eq!(core.calls(), calls, "refused before any store call");
    let p = up.delete_preview().await.unwrap();
    assert_eq!((p.seeds, p.unbacked), (2, 1));
    // G-3 (owner 2026-11-28): the seeds being moved are shown (labels and count, the keystore's public fields), and sealing
    // needs the user's confirm of that count (`ConfirmationMissing` without it or with another count, nothing written)
    let m = up.migrated_seeds().await.unwrap().unwrap();
    let mut labels = m.labels.clone();
    labels.sort();
    assert_eq!(
        (m.seeds, labels),
        (2, vec!["G".to_string(), "Main".to_string()])
    );
    for wrong in [None, Some(ConfirmMigratedSeeds { seeds: 1 })] {
        assert_eq!(
            code(
                up.set_passphrase(sec(PASS), Some(TEST_KDF), None, wrong)
                    .await
            ),
            "ConfirmationMissing"
        );
    }
    assert!(!up.core().protected(), "nothing sealed");
    // the positive control: sealed, the same `Sdk` reads the migrated keystore
    up.set_passphrase(
        sec(PASS),
        Some(TEST_KDF),
        None,
        Some(ConfirmMigratedSeeds { seeds: 2 }),
    )
    .await
    .unwrap();
    assert_eq!(
        up.migrated_seeds().await.unwrap(),
        None,
        "no longer migrating"
    );
    let mut ids: Vec<String> = v.seeds().await.unwrap().into_iter().map(|s| s.id).collect();
    ids.sort();
    let mut want = vec![generated.clone(), imported.clone()];
    want.sort();
    assert_eq!(ids, want);
    assert!(!v.keystore_rollback().await.unwrap());
    v.unlock(imported.clone(), Unlock::Passphrase(sec(VAULT_PASS)))
        .await
        .unwrap();
    let dir = core.dir().to_path_buf();
    assert!(
        !dir.join("g0").exists(),
        "the plain g0 removed after the commit"
    );
    up.clone().lock().await;
    let up = ups
        .open(
            list[0].id.clone(),
            Some(ProfileUnlock::Passphrase(sec(PASS))),
        )
        .await
        .unwrap();
    let s = up.sdk(sdk_config(vec![])).await.unwrap();
    assert_eq!(s.vault().seeds().await.unwrap().len(), 2);
}

/// Delete through the SDK (spec §10, §11): `delete_preview` counts the seeds and those whose backup is `pending`; `delete` with
/// such a seed needs `ConfirmDeleteUnbacked` and the name typed again (`ConfirmationMissing` otherwise, nothing deleted); then
/// the profile is gone and its `Sdk` is `ProfileLocked`. `delete_locked` takes a locked visible profile with its name and
/// `ConfirmDeleteUnreadable`; `rebuild_index` lists every visible profile again. Each refusal beside its control.
#[tokio::test(flavor = "multi_thread")]
async fn delete_through_sdk() {
    use scaas_sdk::user_profile::{
        ConfirmDeleteProfile, ConfirmDeleteUnbacked, ConfirmDeleteUnreadable, ConfirmRebuildIndex,
    };
    use scaas_sdk::vault::Generate;
    let (ups, up, root) = open_protected().await;
    let s = up.sdk(sdk_config(vec![])).await.unwrap();
    s.vault()
        .generate(Generate {
            label: "G".into(),
            vault_passphrase: sec(VAULT_PASS),
        })
        .await
        .unwrap();
    let p = up.delete_preview().await.unwrap();
    assert_eq!((p.seeds, p.unbacked), (1, 1));
    let named = |n: &str| ConfirmDeleteProfile { name: sec(n) };
    assert_eq!(
        code(up.clone().delete(named("work"), None).await),
        "ConfirmationMissing"
    );
    assert_eq!(
        code(
            up.clone()
                .delete(named("play"), Some(ConfirmDeleteUnbacked {}))
                .await
        ),
        "ConfirmationMissing"
    );
    assert_eq!(s.vault().seeds().await.unwrap().len(), 1, "still open");
    up.clone()
        .delete(named("WORK"), Some(ConfirmDeleteUnbacked {}))
        .await
        .unwrap();
    assert_eq!(code(s.vault().seeds().await.map(drop)), "ProfileLocked");
    let names = |l: Vec<scaas_sdk::user_profile::UserProfileInfo>| {
        let mut v: Vec<String> = l.into_iter().map(|i| i.name).collect();
        v.sort();
        v
    };
    assert!(names(ups.list().await.unwrap()).is_empty());
    ups.create("keep".into()).await.unwrap();
    let other = ups.create("other".into()).await.unwrap().id;
    let c = ConfirmDeleteUnreadable {};
    assert_eq!(
        code(ups.delete_locked(other.clone(), named("x"), c).await),
        "ConfirmationMissing"
    );
    ups.delete_locked(other, named("Other"), c).await.unwrap();
    std::fs::remove_file(root.join("profiles.json")).unwrap();
    ups.rebuild_index(ConfirmRebuildIndex {}).await.unwrap();
    assert_eq!(names(ups.list().await.unwrap()), ["keep"]);
}

// ---- UP10: settings, export, import (spec §7.7, §10.1; §17 settings R2-C-3, G9) ----

use scaas_sdk::user_profile::{ConfirmExportProfile, ExportTarget, ImportChoices, ImportSource};

const XPASS: &str = "export passphrase, typed twice";
const NEW: &str = "a new passphrase, typed twice";

/// §17 settings (R2-C-3) through the SDK: an added endpoint, a `first` mark, a credential reference, the idle lock off and the
/// clipboard on, each without the typed passphrase `Argument`, with a wrong one `ProfileOpen`; a lowered cap and a stronger
/// policy pass without it.
#[tokio::test(flavor = "multi_thread")]
async fn settings_weakening_needs_the_passphrase() {
    use scaas_sdk::user_profile::{
        ChainSettings, CredentialKind, CredentialRef, Endpoint, EndpointList,
    };
    let (_ups, up, _) = open_protected().await;
    let mut s = up.settings().await.unwrap();
    s.idle_lock_s = Some(300);
    up.set_settings(s, None).await.unwrap();
    let base = up.settings().await.unwrap();
    let mut with_ep = base.clone();
    with_ep.chains.insert(
        "scaas-testnet".into(),
        ChainSettings {
            endpoints: vec![Endpoint {
                list: EndpointList::Rpc,
                label: "mine".into(),
                url: "https://rpc.example".into(),
                first: false,
            }],
            ..ChainSettings::default()
        },
    );
    let mut first = with_ep.clone();
    first.chains.get_mut("scaas-testnet").unwrap().endpoints[0].first = true;
    let mut cred = base.clone();
    cred.credentials.push(CredentialRef {
        chain_profile: "scaas-testnet".into(),
        list: EndpointList::Rpc,
        label: "mine".into(),
        kind: CredentialKind::Bearer,
        file: None,
        env: Some("SCAAS_TOKEN".into()),
    });
    let mut idle_off = base.clone();
    idle_off.idle_lock_s = None;
    let mut clip = base.clone();
    clip.clipboard = true;
    for (what, n) in [
        ("an endpoint", &with_ep),
        ("a credential", &cred),
        ("idle off", &idle_off),
        ("clipboard on", &clip),
    ] {
        assert_eq!(
            code(up.set_settings(n.clone(), None).await),
            "Argument",
            "{what}"
        );
        assert_eq!(
            code(
                up.set_settings(n.clone(), Some(sec("a wrong passphrase")))
                    .await
            ),
            "ProfileOpen",
            "{what}"
        );
    }
    up.set_settings(with_ep, Some(sec(PASS))).await.unwrap();
    assert_eq!(
        code(up.set_settings(first, None).await),
        "Argument",
        "a first mark"
    );
    let mut strong = up.settings().await.unwrap();
    strong.caps.max_gas = Some(1000);
    strong
        .chains
        .get_mut("scaas-testnet")
        .unwrap()
        .strict_majority = true;
    up.set_settings(strong, None).await.unwrap();
    let got = up.settings().await.unwrap();
    assert!(got.caps.max_gas == Some(1000) && got.chains["scaas-testnet"].strict_majority);
    assert!(got.idle_lock_s == Some(300) && !got.clipboard && got.credentials.is_empty());
}

fn export_rows() -> serde_json::Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../smartcontracts/vectors/profile/export.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Every file under `root` with its bytes, sorted.
fn snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut todo = vec![root.to_path_buf()];
    while let Some(d) = todo.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                todo.push(e.path());
            } else {
                out.push((e.path(), std::fs::read(e.path()).unwrap_or_default()));
            }
        }
    }
    out.sort();
    out
}

/// A file row's file: its `file`, else reproduced by the store's test entry point from its payload, salt and nonce prefix.
fn row_file(f: &serde_json::Value) -> Vec<u8> {
    use base64::Engine;
    if let Some(h) = f["file"].as_str() {
        return unhex(h);
    }
    let filler = |name: &str, n: usize| {
        let mut out = Vec::with_capacity(n + 32);
        let mut i = 0;
        while out.len() < n {
            out.extend(scaas_ua::keccak256(
                format!("scaas/profile/vectors/{name}/{i}").as_bytes(),
            ));
            i += 1;
        }
        out.truncate(n);
        out
    };
    let items: Vec<(String, Vec<u8>)> = f["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            let b = match i[1].as_str() {
                Some(h) => unhex(h),
                // the filler item: `{"rev":<rev>,"f":"<hex>"}` of exactly `len` bytes (export.json's comment)
                None => {
                    let f = &i[1];
                    let head = format!("{{\"rev\":{},\"f\":\"", f["rev"].as_u64().unwrap());
                    let k = f["len"].as_u64().unwrap() as usize - head.len() - 2;
                    let hex: String = filler(f["filler"].as_str().unwrap(), k.div_ceil(2))
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    [head.as_bytes(), &hex.as_bytes()[..k], b"\"}"].concat()
                }
            };
            (i[0].as_str().unwrap().to_string(), b)
        })
        .collect();
    let refs: Vec<(&str, &[u8])> = items.iter().map(|(n, b)| (n.as_str(), &b[..])).collect();
    let pl = scaas_profile::Profiles::test_payload(
        f["label"].as_str().unwrap().as_bytes(),
        &unhex(f["settings"].as_str().unwrap()),
        &refs,
    )
    .unwrap();
    let salt = base64::engine::general_purpose::STANDARD
        .decode(f["kdf"]["salt"].as_str().unwrap())
        .unwrap();
    let p = scaas_profile::Profiles::new(scaas_profile::ProfilesConfig::new(tmp().join("rows")))
        .unwrap();
    p.test_export(
        &pl,
        f["passphrase"].as_str().unwrap().as_bytes(),
        TEST_KDF,
        &salt.try_into().unwrap(),
        &unhex(f["nonce_prefix"].as_str().unwrap())
            .try_into()
            .unwrap(),
    )
    .unwrap()
}

/// The refusal row `r`'s file (export.json's comment): `file`, built from `build`, `file_len` zeros led by `prefix_bytes`, or
/// `base` with `edit`.
fn refusal_file(
    r: &serde_json::Value,
    bases: &std::collections::HashMap<String, Vec<u8>>,
) -> Vec<u8> {
    const STEP: usize = 1_048_576 + 16;
    if let Some(h) = r["file"].as_str() {
        return unhex(h);
    }
    if r["build"].is_object() {
        return row_file(&r["build"]);
    }
    if let Some(len) = r["file_len"].as_u64() {
        let mut f = vec![0u8; len as usize];
        let p = unhex(r["prefix_bytes"].as_str().unwrap());
        f[..p.len()].copy_from_slice(&p);
        return f;
    }
    let mut f = bases[r["base"].as_str().unwrap()].clone();
    let e = &r["edit"];
    let hl = u32::from_be_bytes(f[8..12].try_into().unwrap()) as usize;
    let at = |i: u64| 12 + hl + i as usize * STEP;
    let chunk = |f: &[u8], i: u64| f[at(i)..(at(i) + STEP).min(f.len())].to_vec();
    match e["op"].as_str() {
        None => {}
        Some("truncate") => f.truncate(f.len() - e["n"].as_u64().unwrap() as usize),
        Some("replace") => {
            let o = e["offset"].as_u64().unwrap() as usize;
            let b = unhex(e["hex"].as_str().unwrap());
            f[o..o + b.len()].copy_from_slice(&b);
        }
        Some("drop_chunk") => {
            let i = e["i"].as_u64().unwrap();
            let c = chunk(&f, i).len();
            f.drain(at(i)..at(i) + c);
        }
        Some("swap_chunks") => {
            let (i, j) = (e["i"].as_u64().unwrap(), e["j"].as_u64().unwrap());
            let mut g = f[..at(0)].to_vec();
            for k in 0..((f.len() - at(0)).div_ceil(STEP) as u64) {
                let from = if k == i {
                    j
                } else if k == j {
                    i
                } else {
                    k
                };
                g.extend(chunk(&f, from));
            }
            f = g;
        }
        Some("append_chunk") => {
            let c = chunk(&f, e["i"].as_u64().unwrap());
            f.extend(c);
        }
        Some(op) => panic!("edit {op}"),
    }
    f
}

/// §17 G9: every refusal row of export.json at the test set read by the SDK as `ProfileImportOpen`, and nothing written under
/// the root (the row without `test-hooks` is the store's default build's: clients/scaas-profile/tests/export.rs).
#[tokio::test(flavor = "multi_thread")]
async fn g9_every_refusal_row_is_import_open() {
    let v = export_rows();
    let root = tmp().join("root");
    let ups = UserProfiles::new(ProfilesConfig::new(root.to_string_lossy().into_owned()))
        .await
        .unwrap();
    let bases: std::collections::HashMap<String, Vec<u8>> = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["case"].as_str().unwrap().to_string(), row_file(f)))
        .collect();
    let before = snapshot(&root);
    let mut n = 0;
    for r in v["refusals"].as_array().unwrap() {
        if !r["test_hooks"].as_bool().unwrap() {
            continue;
        }
        let f = refusal_file(r, &bases);
        let pass = sec(r["passphrase"].as_str().unwrap());
        let got = code(
            ups.import_preview(ImportSource::Bytes(f), pass)
                .await
                .map(drop),
        );
        assert_eq!(got, "ProfileImportOpen", "{}", r["case"]);
        n += 1;
    }
    assert_eq!(n, 31);
    assert!(snapshot(&root) == before, "nothing written");
}

/// §17 G9 through the SDK, the positive control: a protected profile with a seed exports; its file previews (one seed,
/// nothing written) and imports with a new id under a new passphrase; the imported profile holds the same seed fingerprints,
/// the seed unlocks there with its own vault passphrase to the same native address, and `sdk.state`'s operation in flight is
/// marked `imported` (a landed one kept). Export refusals: the name, the profile passphrase, an existing file.
#[tokio::test(flavor = "multi_thread")]
async fn g9_export_import_through_sdk() {
    use scaas_sdk::vault::Keystore;
    use scaas_sdk::wallet::NativeKeyRef;
    let (ups, up, root) = open_protected().await;
    let s = up.sdk(sdk_config(vec![])).await.unwrap();
    let seed = s
        .vault()
        .import_words(ImportWords {
            label: "Main".into(),
            words: sec(REPO),
            vault_passphrase: sec(VAULT_PASS),
        })
        .await
        .unwrap()
        .id;
    let key = |seed: String| NativeKeyRef {
        seed,
        network: "stellar".into(),
        index: 0,
        change: None,
        coin_type: None,
        path: None,
    };
    let addr = s
        .wallet()
        .native_address(key(seed.clone()), None)
        .await
        .unwrap();
    let store = PartStore::new(up.core(), SDK).unwrap();
    store
        .put_if(
            "sdk.state".into(),
            None,
            ops_state(),
            StorePolicy::default(),
        )
        .await
        .unwrap();
    let fingerprints = |b: &[u8]| -> Vec<String> {
        Keystore::parse(b)
            .unwrap()
            .seeds
            .into_iter()
            .map(|e| e.fingerprint)
            .collect()
    };
    let ks = store.get("keystore".into(), String::new()).await.unwrap();
    let before = fingerprints(&ks.unwrap().bytes);
    let dir = tmp();
    let target = dir.join("work.scaasx").to_string_lossy().into_owned();
    let confirm = |n: &str| ConfirmExportProfile { name: sec(n) };
    let ex = |c, p: &str, t: &str| {
        up.export(
            c,
            sec(p),
            sec(XPASS),
            Some(TEST_KDF),
            ExportTarget::Path(t.into()),
        )
    };
    assert_eq!(
        code(ex(confirm("play"), PASS, &target).await),
        "ConfirmationMissing"
    );
    assert_eq!(
        code(ex(confirm("work"), "a wrong passphrase", &target).await),
        "ProfileOpen"
    );
    ex(confirm("Work"), PASS, &target).await.unwrap();
    assert_eq!(
        code(ex(confirm("work"), PASS, &target).await),
        "Argument",
        "an existing file"
    );
    let snap = snapshot(&root);
    let review = ups
        .import_preview(ImportSource::Path(target.clone()), sec(XPASS))
        .await
        .unwrap();
    assert!(snapshot(&root) == snap, "the preview wrote nothing");
    assert!(review.name() == "work" && !review.hidden() && review.seeds == 1);
    let choices = ImportChoices {
        confirm: vec![],
        kdf: Some(TEST_KDF),
    };
    let info = ups
        .import(review, choices, sec(NEW), Some("work 2".into()))
        .await
        .unwrap();
    let list = ups.list().await.unwrap();
    let old = list.into_iter().find(|i| i.name == "work").unwrap().id;
    assert!(info.id != old && info.protected);
    let up2 = ups
        .open(info.id, Some(ProfileUnlock::Passphrase(sec(NEW))))
        .await
        .unwrap();
    let store2 = PartStore::new(up2.core(), SDK).unwrap();
    let ks = store2.get("keystore".into(), String::new()).await.unwrap();
    assert_eq!(
        fingerprints(&ks.unwrap().bytes),
        before,
        "the same seed fingerprints"
    );
    let st = store2.get("sdk.state".into(), String::new()).await.unwrap();
    let st: serde_json::Value = serde_json::from_slice(&st.unwrap().bytes).unwrap();
    let states: Vec<&str> = st["ops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["state"].as_str().unwrap())
        .collect();
    assert_eq!(
        states,
        ["imported", "imported", "imported", "landed", "reverted", "consumed", "expired"],
        "every operation in flight marked, none followed; the terminal ones kept"
    );
    let s2 = up2.sdk(sdk_config(vec![])).await.unwrap();
    let id2 = s2.vault().seeds().await.unwrap()[0].id.clone();
    s2.vault()
        .unlock(id2.clone(), Unlock::Passphrase(sec(VAULT_PASS)))
        .await
        .unwrap();
    assert_eq!(
        s2.wallet().native_address(key(id2), None).await.unwrap(),
        addr
    );
}

// ---- R3: the review's SDK findings (C-1, C-4, C-5, C-6, C-7, C-8) ----

/// Waits until the fake chain holds more than `n` requests (one reached the stalled endpoint).
#[cfg(feature = "evm")]
async fn stalled(c: &fake_chain::Fake, n: usize) {
    for _ in 0..500 {
        if c.lock().unwrap().requests.len() > n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("no request reached the stalled endpoint");
}

/// Review C-1: a seed unlock (and a hidden open) whose KDF ends while `lock()` runs leaves no wallet open in the closed `Sdk`.
/// The test hook drives the race: the call waits after its KDF until the close stands between its closed flag and its seeds'
/// lock, and the close waits there until the call has kept or refused its wallet; the call ends `ProfileLocked`. The twin: the
/// same call with no lock keeps its wallet.
#[tokio::test(flavor = "multi_thread")]
async fn c1_unlock_racing_lock_keeps_nothing() {
    use scaas_sdk::user_profile::{open_sets, set_sdk_hook};
    use scaas_sdk::vault::Vault;
    use std::sync::{mpsc::channel, Mutex};
    for hidden in [false, true] {
        let (_ups, up, _) = open_protected().await;
        let s = up.sdk(sdk_config(vec![])).await.unwrap();
        let v = s.vault();
        let id = v
            .import_words(ImportWords {
                label: "Main".into(),
                words: sec(REPO),
                vault_passphrase: sec(VAULT_PASS),
            })
            .await
            .unwrap()
            .id;
        v.lock(id.clone()).await;
        let call = move |v: Arc<Vault>, id: String| async move {
            let pass = Unlock::Passphrase(sec(VAULT_PASS));
            match hidden {
                false => v.unlock(id, pass).await,
                true => v.open_hidden(id, pass, sec("h")).await.map(drop),
            }
        };
        call(v.clone(), id.clone()).await.unwrap();
        assert_eq!(open_sets(&s), 1, "the twin: kept");
        v.lock(id.clone()).await;
        assert_eq!(open_sets(&s), 0);
        let (reached_tx, reached) = channel::<()>();
        let (go_tx, go) = channel::<()>();
        let (done_tx, done) = channel::<()>();
        let (reached_tx, go, done_tx) =
            (Mutex::new(reached_tx), Mutex::new(go), Mutex::new(done_tx));
        let (go_tx, done) = (Mutex::new(go_tx), Mutex::new(done));
        set_sdk_hook(
            &s,
            Arc::new(move |point| match point {
                "unlock" => {
                    reached_tx.lock().unwrap().send(()).unwrap();
                    go.lock().unwrap().recv().unwrap();
                }
                "unlock.done" => done_tx.lock().unwrap().send(()).unwrap(),
                "close" => {
                    go_tx.lock().unwrap().send(()).unwrap();
                    done.lock().unwrap().recv().unwrap();
                }
                _ => {}
            }),
        );
        let racing = tokio::spawn(call(v.clone(), id.clone()));
        tokio::task::spawn_blocking(move || reached.recv().unwrap())
            .await
            .unwrap();
        up.clone().lock().await;
        assert_eq!(open_sets(&s), 0, "hidden {hidden}: nothing open after lock");
        assert_eq!(
            code(racing.await.unwrap()),
            "ProfileLocked",
            "hidden {hidden}"
        );
    }
}

/// Review C-4: the profile's `Sdk` holds the open profile: with the `UserProfile` dropped without `lock()`, the profile stays in
/// use (`ProfileInUse` for another open) and its `Sdk` answers; with the `Sdk` dropped too, the profile opens again.
#[tokio::test(flavor = "multi_thread")]
async fn c4_sdk_keeps_the_profile_open() {
    let (ups, up, _) = open_protected().await;
    let id = ups.list().await.unwrap()[0].id.clone();
    let s = up.sdk(sdk_config(vec![])).await.unwrap();
    drop(up);
    let again = || ups.open(id.clone(), Some(ProfileUnlock::Passphrase(sec(PASS))));
    assert_eq!(code(again().await.map(drop)), "ProfileInUse");
    assert_eq!(code(s.vault().seeds().await.map(drop)), "Ok");
    drop(s);
    assert_eq!(code(again().await.map(drop)), "Ok", "the twin");
}

/// Review C-5 (= E-10): the preview reads `sdk.state` with the SDK's own parser of the item: a state the store's marking takes
/// (each row with a string `state`) but no operation call could load (rows without their fields) is `ProfileImportOpen`,
/// nothing written. The twin: `g9_export_import_through_sdk` (whole rows preview, import and read back marked).
#[tokio::test(flavor = "multi_thread")]
async fn c5_preview_reads_state_with_the_sdk_parser() {
    let (ups, up, root) = open_protected().await;
    let store = PartStore::new(up.core(), SDK).unwrap();
    let bad = br#"{"rev":1,"ops":[{"op":"a","state":"signed"}]}"#.to_vec();
    store
        .put_if("sdk.state".into(), None, bad, StorePolicy::default())
        .await
        .unwrap();
    let target = tmp().join("bad.scaasx").to_string_lossy().into_owned();
    up.export(
        ConfirmExportProfile { name: sec("work") },
        sec(PASS),
        sec(XPASS),
        Some(TEST_KDF),
        ExportTarget::Path(target.clone()),
    )
    .await
    .unwrap();
    let snap = snapshot(&root);
    let got = ups
        .import_preview(ImportSource::Path(target), sec(XPASS))
        .await;
    assert_eq!(code(got.map(drop)), "ProfileImportOpen");
    assert!(snapshot(&root) == snap, "nothing written");
}

/// Review C-6: `part_store` refuses the part `sdk` (`Argument`; the profile's own `Sdk` reaches it through `sdk()`). The twin:
/// another part's face.
#[tokio::test(flavor = "multi_thread")]
async fn c6_part_store_refuses_the_sdk_part() {
    let (_ups, up, _) = open_protected().await;
    assert_eq!(code(up.part_store(SDK).map(drop)), "Argument");
    assert_eq!(code(up.part_store(ProfilePart::PqVault).map(drop)), "Ok");
}

/// Review C-7: a call in flight across `lock()` (its endpoint stalled) is aborted and waited for: `lock` returns, the call ends
/// `ProfileLocked`, and no request leaves after it. The twin: the same call answers while the profile is open.
#[cfg(feature = "evm")]
#[tokio::test(flavor = "multi_thread")]
async fn c7_call_across_lock_aborted() {
    use fake_chain::{fake, serve};
    let c = fake();
    c.lock().unwrap().index = vec![];
    let url = serve(c.clone()).await;
    let (_ups, up, _) = open_protected().await;
    let s = up.sdk(sdk_config(vec![local(url)])).await.unwrap();
    let tokens =
        |s: Arc<scaas_sdk::Sdk>| async move { s.wallet().tokens("local".into(), true).await };
    assert_eq!(code(tokens(s.clone()).await), "Ok", "the twin");
    c.lock().unwrap().stall = true;
    let n0 = c.lock().unwrap().requests.len();
    let call = tokio::spawn(tokens(s.clone()));
    stalled(&c, n0).await;
    tokio::time::timeout(Duration::from_secs(5), up.clone().lock())
        .await
        .expect("lock returns with the call aborted");
    let got = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("the call ended")
        .unwrap();
    assert_eq!(code(got), "ProfileLocked");
    let n = c.lock().unwrap().requests.len();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(c.lock().unwrap().requests.len(), n, "no request after lock");
}

/// Review C-8 (c): a call cancelled under a plain `Sdk` that was never closed (its adopted runtime shut down while the call
/// waits on a stalled endpoint) is `Internal`; `ProfileLocked` is a closed `Sdk`'s alone (`c7_call_across_lock_aborted`).
#[cfg(feature = "evm")]
#[tokio::test(flavor = "multi_thread")]
async fn c8_cancelled_plain_sdk_call_is_internal() {
    use fake_chain::{fake, serve};
    use scaas_sdk::vault::FileStore;
    use scaas_sdk::{Sdk, SdkConfig};
    let c = fake();
    c.lock().unwrap().index = vec![];
    let url = serve(c.clone()).await;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let s = Sdk::open(SdkConfig {
        profiles: vec![local(url)],
        store: FileStore::new(tmp()).unwrap(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(rt.handle().clone()),
        limits: Default::default(),
        clock: None,
        gas_tables: vec![],
    })
    .await
    .unwrap();
    c.lock().unwrap().stall = true;
    let n0 = c.lock().unwrap().requests.len();
    let call = {
        let s = s.clone();
        tokio::spawn(async move { s.wallet().tokens("local".into(), true).await })
    };
    stalled(&c, n0).await;
    rt.shutdown_background();
    let got = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("the call ended")
        .unwrap();
    assert_eq!(code(got), "Internal");
}

/// The rows of an `sdk.state` as the SDK writes them, one per state: three in flight (`signed`, `sent`, an earlier import's
/// `imported`) and the four a chain fact ended.
fn ops_state() -> Vec<u8> {
    let ops: Vec<serde_json::Value> = [
        "signed", "sent", "imported", "landed", "reverted", "consumed", "expired",
    ]
    .iter()
    .enumerate()
    .map(|(i, state)| {
        serde_json::json!({
            "op": format!("op{i}"), "chain": "local", "entry": "mtxTransfer", "struct": "Transfer", "kind": "token",
            "contract": "0x5ca0000000000000000000000000000000000001", "from": "0x01", "batch": "0", "nonce": "1",
            "valid_until": 1_900_000_000u64, "digest": "0x00", "op_json": null, "calldata": "0x", "path": "gateway",
            "from_block": 1, "state": state, "detail": "", "relayer_bound": false
        })
    })
    .collect();
    serde_json::to_vec(&serde_json::json!({ "rev": 1, "ops": ops })).unwrap()
}

/// Review E-5 through the SDK: `ProfilesConfig::write_last` false (the CLI) opens without writing the index's `last`; true (the
/// default: an app or a TUI instance) writes it.
#[tokio::test(flavor = "multi_thread")]
async fn e5_write_last_through_sdk() {
    for write_last in [true, false] {
        let root = tmp().join("root");
        let mut c = ProfilesConfig::new(root.to_string_lossy().into_owned());
        assert!(c.write_last, "the default");
        c.write_last = write_last;
        let ups = UserProfiles::new(c).await.unwrap();
        let id = ups.list().await.unwrap()[0].id.clone();
        ups.open(id.clone(), None).await.unwrap().lock().await;
        let ix = std::fs::read_to_string(root.join("profiles.json")).unwrap();
        assert_eq!(
            ix.contains(&format!(r#""last":"{id}""#)),
            write_last,
            "{ix}"
        );
    }
}

/// Review E-6: the SDK hands a client the store's one name helper (spec §6: names compared everywhere by it).
#[test]
fn e6_name_helpers_reexported() {
    use scaas_sdk::user_profile::{check_name, name_key, same_name};
    assert!(same_name("Work", "WORK") && !same_name("work", "play"));
    assert_eq!(*name_key("Work"), "work");
    assert_eq!(
        code(check_name("").map_err(SdkError::from)),
        "ProfileNameInvalid"
    );
    assert_eq!(check_name("work").unwrap(), "work");
}

/// G-1 two-step (owner 2026-11-28) through the SDK: a copy of a deleted profile's directory put back under its id is
/// `ProfileRollback`; `purge_tombstones` drops the marker and it opens. Control: the open before the delete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g1_purge_tombstones_through_sdk() {
    use scaas_sdk::user_profile::{ConfirmDeleteProfile, ConfirmPurgeTombstones};
    let base = tmp();
    let root = base.join("root");
    let ups = UserProfiles::new(ProfilesConfig::new(root.to_string_lossy().into_owned()))
        .await
        .unwrap();
    let id = ups.list().await.unwrap()[0].id.clone();
    let up = ups.open(id.clone(), None).await.unwrap();
    let dir = root.join("p").join(&id);
    let copy = base.join("copy");
    std::fs::create_dir_all(copy.join("g0")).unwrap();
    std::fs::copy(dir.join("profile.envelope"), copy.join("profile.envelope")).unwrap();
    let name = ConfirmDeleteProfile {
        name: sec("default"),
    };
    up.delete(name, None).await.unwrap();
    std::fs::rename(&copy, &dir).unwrap();
    assert_eq!(code(ups.open(id.clone(), None).await), "ProfileRollback");
    ups.purge_tombstones(ConfirmPurgeTombstones {})
        .await
        .unwrap();
    ups.open(id, None).await.unwrap();
}

/// Owner 2026-11-28 through the SDK: two hidden profiles of one (name, passphrase) (one moved in from another root, as two
/// instances' concurrent `create_hidden` would leave them) are `ProfileHiddenAmbiguous` at `open_hidden`; `hidden_matches`
/// lists both; `open_hidden_match` opens the chosen one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hidden_duplicates_through_sdk() {
    let base = tmp();
    let root = |n: &str| base.join(n).to_string_lossy().into_owned();
    let ups = UserProfiles::new(ProfilesConfig::new(root("a")))
        .await
        .unwrap();
    let other = UserProfiles::new(ProfilesConfig::new(root("b")))
        .await
        .unwrap();
    let mut ids = vec![];
    for u in [&ups, &other] {
        let h = u
            .create_hidden(sec("Twin"), sec(PASS), Some(TEST_KDF))
            .await
            .unwrap();
        ids.push(
            h.core()
                .dir()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        );
        h.lock().await;
    }
    std::fs::rename(
        base.join("b/p").join(&ids[1]),
        base.join("a/p").join(&ids[1]),
    )
    .unwrap();
    ids.sort();
    assert_eq!(
        code(ups.open_hidden(sec("Twin"), sec(PASS)).await),
        "ProfileHiddenAmbiguous"
    );
    let m = ups.hidden_matches(sec("Twin"), sec(PASS)).await.unwrap();
    assert_eq!(m.len(), 2);
    let o = ups
        .open_hidden_match(sec("Twin"), sec(PASS), m[1])
        .await
        .unwrap();
    assert!(o.core().dir().ends_with(&ids[1]));
}
