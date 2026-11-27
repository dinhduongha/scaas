// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! User profiles (spec docs/superpowers/specs/2026-11-27-user-profiles.md, plan docs/superpowers/plans/2026-11-27-user-profiles.md):
//! the SDK's side of the store `scaas-profile` (owner 2026-11-27; the store's own tests are clients/scaas-profile/tests/). UP5:
//! the `SecureStore` face and the codes. Profiles are built by hand: a generation directory and a `ProfileKeys` with a fresh
//! `DEK_p` (`create_dek`, no Argon2id). UP6b (§10 lock, §11, §17 G11): `UserProfiles`, `UserProfile::sdk`, `Sdk::close`; the
//! protected profiles there are planted by hand (one wrap at the test KDF set) and opened through `UserProfiles`. UP7 (§7.3,
//! §7.6): `set_passphrase` and `change_passphrase` through `UserProfile`, and every secret-creating call refused
//! `ProfilePassphraseRequired` before any work on an unprotected profile's `Sdk`. UP8 (§8): the hidden calls route to the
//! store's (its own tests are clients/scaas-profile/tests/hidden.rs).
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
    assert_eq!(Error::ALL.len(), 24);
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
    assert_eq!(
        s.get("settings".into(), String::new()).await,
        Err(StoreError::ProfileRollback)
    );
    core.set_write_wait(Duration::from_millis(50));
    let g = core.write_lock().unwrap();
    assert_eq!(
        s.put_if("sdk.state".into(), None, item(1, "s"), p).await,
        Err(StoreError::Unavailable)
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
        b64(&salt)
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
            format!(r#"{{"name":"{name}","hidden":false}}"#).as_bytes(),
        )
        .unwrap();
    let d = root.join("p").join(&id);
    std::fs::create_dir_all(&d).unwrap();
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
    let head = up.part_store(SDK).unwrap();
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
    assert_eq!(code(up.part_store(SDK).map(|_| ())), "ProfileLocked");
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

/// G11: after `lock` no request leaves on the old `Sdk` (`Sdk::close`: pools dropped, the closed flag): a chain call is
/// `ProfileLocked` by its exact code, and the fake chain sees nothing more. Control first: the same call reaches the chain each
/// time while the profile is open.
#[cfg(feature = "evm")]
#[tokio::test(flavor = "multi_thread")]
async fn g11_no_request_after_lock() {
    use fake_chain::{fake, hash_of, serve, CHAIN_ID};
    let c = fake();
    c.lock().unwrap().index = vec![];
    let url = serve(c.clone()).await;
    let endpoint = scaas_sdk::EndpointConfig {
        url,
        class: scaas_rpc::Class::Named,
        label: None,
        auth: None,
    };
    let profile = ChainProfile {
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
    };
    let (_ups, up, _) = open_protected().await;
    let s = up.sdk(sdk_config(vec![profile])).await.unwrap();
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
    up.set_passphrase(sec(PASS), Some(TEST_KDF), None)
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
