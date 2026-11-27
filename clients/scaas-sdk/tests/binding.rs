// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The UniFFI surface's list (plan T20b; spec §16.1): every exported async call of the SDK's module objects has its entry in
//! `binding::surface()` with its `<call>_blocking` twin, and every entry names an async call of the SDK (both ways); every
//! typed entry point and every plain call of a module object is exported (review B7). Needs the
//! features of the reference library and `uniffi`; with `sync-api` too, the sync surface's own tests (module `sync`).
use std::collections::BTreeSet;

const MODULES: [&str; 8] = [
    "Sdk",
    "Vault",
    "Account",
    "Wallet",
    "Op",
    "Confidential",
    "Dex",
    "Admin",
];

/// `(object, call)` of every `pub async fn` (`asynchronous`) or plain `pub fn` in an `impl <Module>` block of `src/`, the
/// binding modules and the calls of a feature outside the SDK's default ones excluded. A macro-made call reads as `$f`: [`entry_points`] names those.
fn exported(asynchronous: bool) -> BTreeSet<(String, String)> {
    let prefix = if asynchronous {
        "pub async fn "
    } else {
        "pub fn "
    };
    let mut out = BTreeSet::new();
    let mut stack = vec![std::path::PathBuf::from("src")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let name = p.to_string_lossy().to_string();
            if !name.ends_with(".rs")
                || name.ends_with("tests.rs")
                || name.ends_with("binding.rs")
                || name.contains("/wasm")
                // decisions CLI-SDK-33 (100): the bindings expose the SDK's default features; the `soroban_*` wallet calls
                // are feature `soroban`'s, outside them (the reference library builds without it)
                || name.ends_with("soroban_ops.rs")
            {
                continue;
            }
            let mut obj: Option<String> = None;
            for line in std::fs::read_to_string(&p).unwrap().lines() {
                let t = line.trim_start();
                if let Some(rest) = t.strip_prefix("impl ") {
                    let ty = rest.split([' ', '{']).next().unwrap_or("");
                    let ty = ty.rsplit("::").next().unwrap_or("").to_string();
                    obj = MODULES.contains(&ty.as_str()).then_some(ty);
                } else if let (Some(o), Some(rest)) = (&obj, t.strip_prefix(prefix)) {
                    let f: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                        .collect();
                    out.insert((o.clone(), f));
                }
            }
        }
    }
    out
}

/// The SDK's typed entry points (`src/surface.rs`, held equal to the vectors by `tests/completeness.rs`): the calls its
/// macros make, by name.
fn entry_points() -> BTreeSet<String> {
    scaas_sdk::surface::ENTRY_POINTS
        .iter()
        .map(|e| e.function.to_string())
        .collect()
}

/// `(object, call)` of every `pub async fn` in an `impl <Module>` block of `src/` (the Rust-only calls excluded).
fn exported_async() -> BTreeSet<(String, String)> {
    let rust_only = [
        ("Sdk", "open"),
        ("Sdk", "spawn"),
        ("Sdk", "poll"),
        // user-profiles UP6b: the profile layer's (`UserProfile::lock`), outside the binding surface in wave 1
        ("Sdk", "close"),
        ("Wallet", "native_sign"),
        ("Vault", "lock"),
        ("Vault", "lock_all"),
    ];
    exported(true)
        .into_iter()
        .filter(|(o, f)| !rust_only.contains(&(o.as_str(), f.as_str())))
        .collect()
}

#[test]
fn every_async_call_has_a_blocking_twin() {
    let list = scaas_sdk::binding::surface();
    for (o, f, fb) in &list {
        assert_eq!(*fb, format!("{f}_blocking"), "{o}::{f}: the twin's name");
    }
    let listed: BTreeSet<_> = list
        .iter()
        .map(|(o, f, _)| (o.to_string(), f.to_string()))
        .collect();
    let src = exported_async();
    // the macro-made rows (`$f`) are read from the list's side only: the source names them by the macro's variable
    let src_named: BTreeSet<_> = src.iter().filter(|(_, f)| f != "$f").cloned().collect();
    assert!(src_named.len() > 100, "control: the source is read");
    let missing: Vec<_> = src_named.difference(&listed).collect();
    assert!(
        missing.is_empty(),
        "async calls without a twin: {missing:?}"
    );
    // a macro-made call is named by the SDK's own table of typed entry points (review B7), not by a prefix
    let eps = entry_points();
    let unknown: Vec<_> = listed
        .iter()
        .filter(|(o, f)| !src_named.contains(&(o.clone(), f.clone())) && !eps.contains(f))
        .collect();
    assert!(
        unknown.is_empty(),
        "entries naming no SDK async call: {unknown:?}"
    );
}

/// Review B7: every typed entry point of the SDK (`ENTRY_POINTS`, the macro-made calls among them) is a call of the list.
#[test]
fn every_typed_entry_point_is_listed() {
    let listed: BTreeSet<String> = scaas_sdk::binding::surface()
        .iter()
        .map(|(_, f, _)| f.to_string())
        .collect();
    let eps = entry_points();
    assert!(eps.len() > 60, "control: the table is read ({})", eps.len());
    let missing: Vec<_> = eps.difference(&listed).collect();
    assert!(
        missing.is_empty(),
        "typed entry points not in the binding list: {missing:?}"
    );
}

/// Review B7: every plain `pub fn` of the SDK's module objects is exported by `binding.rs` (a method of the same object), or
/// named Rust-only here.
#[test]
fn every_sync_call_is_exported() {
    // Rust-only (the header of src/binding.rs): the platform authenticator in use, the heavy-job peak of a test; the load
    // check's two values are free functions of the binding (`api_version`, `features`)
    let rust_only = [
        ("Sdk", "authenticator"),
        ("Sdk", "heavy_peak"),
        ("Sdk", "api_version"),
        ("Sdk", "features"),
    ];
    let binding = std::fs::read_to_string("src/binding.rs").unwrap();
    let mut exported_here = BTreeSet::new();
    let mut obj: Option<String> = None;
    for line in binding.lines() {
        let t = line.trim_start();
        if !line.starts_with(' ') {
            obj = t
                .strip_prefix("impl ")
                .map(|r| r.split([' ', '{']).next().unwrap_or("").to_string());
            continue;
        }
        if let (Some(o), Some(rest)) = (&obj, t.strip_prefix("pub fn ")) {
            let f: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            exported_here.insert((o.clone(), f.trim_end_matches("_blocking").to_string()));
        }
    }
    let sync = exported(false);
    assert!(
        sync.len() > 5,
        "control: the source is read ({})",
        sync.len()
    );
    let missing: Vec<_> = sync
        .iter()
        .filter(|(o, f)| {
            !exported_here.contains(&(o.clone(), f.clone()))
                && !rust_only.contains(&(o.as_str(), f.as_str()))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "sync calls of the module objects without a binding export: {missing:?}"
    );
}

/// The JS binding (spec §16.4; plan T20g) exports every call `binding.rs` exports beside the list (the list itself is one, read
/// by both): a module object's method under its name, a handle object's (`Prepared`, `PreparedOrder`, `RegistryWrite`,
/// `SeedBackup`) as `<object>_<method>(handle)`, a free function under its name. Read from the two sources.
#[test]
fn wasm_exports_every_binding_call() {
    let handle_objects = ["Prepared", "PreparedOrder", "RegistryWrite", "SeedBackup"];
    let snake = |s: &str| {
        let mut o = String::new();
        for (i, c) in s.chars().enumerate() {
            if c.is_uppercase() && i > 0 {
                o.push('_');
            }
            o.push(c.to_ascii_lowercase());
        }
        o
    };
    let name_of = |rest: &str| -> String {
        rest.chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect()
    };
    // `(object, call)`: a module object's method by its object, a handle object's as the free `<object>_<call>`, a free
    // function with no object (review B8: both sides keyed by object)
    let binding = std::fs::read_to_string("src/binding.rs").unwrap();
    let mut want = BTreeSet::new();
    let (mut exported, mut obj, mut renamed): (bool, Option<String>, Option<String>) =
        (false, None, None);
    for line in binding.lines() {
        let t = line.trim_start();
        if t.starts_with("#[uniffi::export") {
            exported = true;
            continue;
        }
        if let Some(n) = t.strip_prefix("#[uniffi::method(name = \"") {
            renamed = Some(n.split('"').next().unwrap_or("").to_string());
            continue;
        }
        if !line.starts_with(' ') {
            if let Some(rest) = t.strip_prefix("impl ") {
                obj = exported.then(|| name_of(rest));
            } else if let Some(rest) = t
                .strip_prefix("pub fn ")
                .or(t.strip_prefix("pub async fn "))
            {
                if exported {
                    want.insert((String::new(), name_of(rest)));
                }
                obj = None;
            } else if t.starts_with('}') {
                obj = None;
            }
            if !t.starts_with("#[") {
                exported = false;
            }
            continue;
        }
        if let (Some(o), Some(rest)) = (
            &obj,
            t.strip_prefix("pub fn ")
                .or(t.strip_prefix("pub async fn ")),
        ) {
            let m = renamed.take().unwrap_or_else(|| name_of(rest));
            if m.ends_with("_blocking") {
                continue;
            }
            want.insert(match handle_objects.contains(&o.as_str()) {
                true => (String::new(), format!("{}_{m}", snake(o))),
                false => (o.clone(), m),
            });
        }
    }
    // the JS side: `#[wasm_bindgen] impl X` methods, `#[wasm_bindgen] pub fn` and the `free!` rows (no object)
    let js = std::fs::read_to_string("src/wasm/js.rs").unwrap();
    let mut have = BTreeSet::new();
    let (mut wb, mut in_free, mut jobj): (bool, bool, Option<String>) = (false, false, None);
    for line in js.lines() {
        let t = line.trim_start();
        if !line.starts_with(' ') {
            if t == "free! {" {
                in_free = true;
            } else if t.starts_with('}') {
                (in_free, jobj) = (false, None);
            } else if let Some(rest) = t.strip_prefix("impl ") {
                jobj = wb.then(|| name_of(rest));
            } else if let Some(rest) = t.strip_prefix("pub fn ") {
                if wb {
                    have.insert((String::new(), name_of(rest)));
                }
            }
            if t.starts_with("#[wasm_bindgen") {
                wb = true;
            } else if !t.starts_with("#[") && !t.starts_with("///") {
                wb = false;
            }
            continue;
        }
        if let (true, Some(rest)) = (in_free, t.strip_prefix("fn ")) {
            have.insert((String::new(), name_of(rest)));
        } else if let (Some(o), Some(rest)) = (&jobj, t.strip_prefix("pub fn ")) {
            have.insert((o.clone(), name_of(rest)));
        }
    }
    // sync-api only: the blocking open
    let missing: Vec<_> = want
        .iter()
        .filter(|(o, n)| !have.contains(&(o.clone(), n.clone())) && n != "open_blocking")
        .collect();
    assert!(
        want.len() > 40,
        "control: binding.rs is read ({} names)",
        want.len()
    );
    assert!(
        have.len() > 40,
        "control: js.rs is read ({} names)",
        have.len()
    );
    assert!(
        missing.is_empty(),
        "binding.rs exports without a JS export: {missing:?}"
    );
}

/// The sync surface (spec §16.1 (a′)) from Rust, as a foreign caller sees it: `open_blocking` over a sync store and
/// authenticator, the twins, the cancel token, `next_blocking`.
#[cfg(feature = "sync-api")]
#[allow(clippy::unwrap_used)]
mod sync {
    use scaas_sdk::binding::{BindingConfig, Sdk};
    use scaas_sdk::platform::{
        Assertion, AssertionRequest, AuthError, KeyPolicy, PasskeyCreated, SePublic,
    };
    use scaas_sdk::sync_cpp::{open_blocking, CancelToken, SyncAuthenticator, SyncStore};
    use scaas_sdk::vault::store::rev_of;
    use scaas_sdk::vault::{ImportWords, StoreError, StorePolicy, StoredItem, Unlock};
    use scaas_sdk::{Event, Limits, SdkError};
    use scaas_ua::wallet::{hmac_sha256, SecretBytes};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    const PASS: &str = "river-otter-7 ünï";
    const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";

    #[derive(Default)]
    struct Store {
        items: Mutex<HashMap<String, Vec<u8>>>,
        throw: AtomicBool,
        locks: std::sync::atomic::AtomicU64,
        unlocks: std::sync::atomic::AtomicU64,
    }

    impl SyncStore for Store {
        fn get(&self, name: String, _: String) -> Result<Option<StoredItem>, StoreError> {
            // a Rust panic stands for a foreign exception here (both reach the SDK as `Unexpected`)
            assert!(!self.throw.load(Ordering::SeqCst), "the app's store threw");
            Ok(self.items.lock().unwrap().get(&name).map(|b| StoredItem {
                rev: rev_of(b),
                bytes: b.clone(),
            }))
        }
        fn put_if(
            &self,
            name: String,
            prev: Option<u64>,
            bytes: Vec<u8>,
            _: StorePolicy,
        ) -> Result<(), StoreError> {
            let mut items = self.items.lock().unwrap();
            if items.get(&name).map(|b| rev_of(b)) != prev {
                return Err(StoreError::Conflict);
            }
            items.insert(name, bytes);
            Ok(())
        }
        fn remove(&self, name: String) -> Result<(), StoreError> {
            self.items.lock().unwrap().remove(&name);
            Ok(())
        }
        // one caller at a time in these tests: no lock to hold, the calls counted
        fn lock(&self, _: String) -> Result<u64, StoreError> {
            self.locks.fetch_add(1, Ordering::SeqCst);
            Ok(1)
        }
        fn unlock(&self, _: u64) {
            self.unlocks.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// An HMAC PRF (as tests/passkey.rs), its output written by the copy call into the secret whose id it is given.
    struct Auth;

    impl SyncAuthenticator for Auth {
        fn create_passkey(
            &self,
            _: String,
            _: String,
            _: Vec<Vec<u8>>,
        ) -> Result<PasskeyCreated, AuthError> {
            Err(AuthError::Unavailable)
        }
        fn get_assertion(
            &self,
            req: AssertionRequest,
            prf_out: u64,
        ) -> Result<Assertion, AuthError> {
            let salt = req.prf_salt.ok_or(AuthError::Refused)?;
            scaas_ua::wallet::secret_write(prf_out, &hmac_sha256(b"secret with UV", &salt))
                .map_err(|_| AuthError::Refused)?;
            Ok(Assertion {
                credential_id: vec![0xc1, 0xed],
                authenticator_data: vec![0; 37],
                client_data_json: vec![],
                signature: vec![0; 64],
                prf: true,
            })
        }
        fn platform_secret(
            &self,
            _: String,
            _: Vec<u8>,
            _: String,
            _: Option<KeyPolicy>,
            _: u64,
        ) -> Result<(), AuthError> {
            Err(AuthError::Unavailable)
        }
        fn p256_generate(&self, _: KeyPolicy) -> Result<SePublic, AuthError> {
            Err(AuthError::Unavailable)
        }
        fn p256_sign(&self, _: String, _: Vec<u8>, _: String) -> Result<Vec<u8>, AuthError> {
            Err(AuthError::Unavailable)
        }
    }

    fn sec(s: &str) -> Arc<SecretBytes> {
        Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(s.as_bytes().to_vec())).unwrap())
    }

    fn config() -> BindingConfig {
        BindingConfig {
            expect_api: 1,
            need_features: scaas_sdk::features(),
            profiles: vec![],
            rp_id: Some("wallet.example".into()),
            limits: Limits::default(),
            gas_tables: vec![],
        }
    }

    fn open(store: Arc<Store>) -> Arc<Sdk> {
        open_blocking(config(), store, Some(Arc::new(Auth))).unwrap()
    }

    fn import(s: &Sdk) -> String {
        let req = ImportWords {
            label: "Main".into(),
            words: sec(REPO),
            vault_passphrase: sec(PASS),
        };
        s.vault().import_words_blocking(req, None).unwrap().id
    }

    #[test]
    fn blocking_twin_equals_async() {
        let s = open(Arc::new(Store::default()));
        let id = import(&s);
        let inner = s.inner();
        let i2 = inner.clone();
        let async_seeds = s
            .run_blocking(None, async move { i2.vault().seeds().await })
            .unwrap();
        assert_eq!(s.vault().seeds_blocking(None).unwrap(), async_seeds);
        assert_eq!(async_seeds.len(), 1, "control: the seed is listed");
        let id2 = id.clone();
        let async_seed = s
            .run_blocking(None, async move { inner.vault().seed(id2).await })
            .unwrap();
        assert_eq!(s.vault().seed_blocking(id, None).unwrap(), async_seed);
    }

    #[test]
    fn cancel_token_cancels() {
        let s = open(Arc::new(Store::default()));
        let (token, done) = (CancelToken::new(), Arc::new(AtomicBool::new(false)));
        // the call runs until released, so its return can only be the cancel's (no wall-clock bound; review B15)
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let release = Arc::new(Mutex::new(Some(release_tx)));
        let t = token.clone();
        let canceller = std::thread::spawn(move || {
            started_rx.recv().unwrap();
            t.cancel();
        });
        // a watchdog, never the verdict: a twin that ignores the token is released after 60 s and returns Ok, so the assertion
        // below fails instead of the test hanging (the t20b-sync mutant); a twin that honours it returns long before
        let (returned_tx, returned_rx) = std::sync::mpsc::channel::<()>();
        let w = release.clone();
        let watchdog = std::thread::spawn(move || {
            if returned_rx.recv_timeout(Duration::from_secs(60)).is_err() {
                if let Some(tx) = w.lock().unwrap().take() {
                    let _ = tx.send(());
                }
            }
        });
        let d = done.clone();
        let r = s.run_blocking(Some(token), async move {
            started_tx.send(()).unwrap();
            let _ = release_rx.await;
            d.store(true, Ordering::SeqCst);
            Ok(())
        });
        let _ = returned_tx.send(());
        watchdog.join().unwrap();
        canceller.join().unwrap();
        assert_eq!(r.map_err(|e| e.code()), Err("Cancelled"));
        assert!(
            !done.load(Ordering::SeqCst),
            "returned at the cancel, the call still running"
        );
        // the effect of a dropped future (spec §13.4): the work goes on on the SDK's runtime
        release.lock().unwrap().take().unwrap().send(()).unwrap();
        let start = Instant::now();
        while !done.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            done.load(Ordering::SeqCst),
            "the cancelled call's work went on"
        );
        // control: without a cancel the call runs to its end; a token cancelled before the call refuses it
        assert!(s.run_blocking(None, async { Ok(7) }).unwrap() == 7);
        let c = CancelToken::new();
        c.cancel();
        assert_eq!(
            s.vault().seeds_blocking(Some(c)).map_err(|e| e.code()),
            Err("Cancelled")
        );
    }

    /// Review B15: the store's lock is released to the app (`unlock`) when the SDK drops it.
    #[test]
    fn the_store_lock_is_released() {
        let st = Arc::new(Store::default());
        let s = open(st.clone());
        import(&s);
        let (locks, unlocks) = (
            st.locks.load(Ordering::SeqCst),
            st.unlocks.load(Ordering::SeqCst),
        );
        assert!(locks > 0, "control: the import locked the keystore");
        let start = Instant::now();
        while st.unlocks.load(Ordering::SeqCst) < locks && start.elapsed() < Duration::from_secs(10)
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            st.unlocks.load(Ordering::SeqCst),
            locks,
            "every lock released ({unlocks} at first)"
        );
    }

    #[test]
    fn a_panic_is_internal() {
        let s = open(Arc::new(Store::default()));
        let r: Result<(), SdkError> = s.run_blocking(None, async { panic!("inside a call") });
        assert_eq!(r.map_err(|e| e.code()), Err("Internal"));
        assert_eq!(
            s.vault().seeds_blocking(None).unwrap().len(),
            0,
            "the SDK goes on"
        );
    }

    #[test]
    fn sync_store_foreign_exception_is_unexpected() {
        let store = Arc::new(Store::default());
        let s = open(store.clone());
        import(&s);
        store.throw.store(true, Ordering::SeqCst);
        // `Unexpected` reaches the caller as the store's failure (`VaultIo`), never as a panic of the twin
        assert_eq!(
            s.vault().seeds_blocking(None).map_err(|e| e.code()),
            Err("VaultIo")
        );
        store.throw.store(false, Ordering::SeqCst);
        assert_eq!(s.vault().seeds_blocking(None).unwrap().len(), 1, "control");
    }

    #[test]
    fn prf_returns_through_the_sync_authenticator() {
        let s = open(Arc::new(Store::default()));
        let id = import(&s);
        s.vault()
            .enable_passkey_unlock_blocking(id.clone(), sec(PASS), None)
            .unwrap();
        s.vault().lock_blocking(id.clone()).unwrap();
        assert!(!s.vault().seed_blocking(id.clone(), None).unwrap().unlocked);
        s.vault()
            .unlock_blocking(id.clone(), Unlock::Passkey, None)
            .unwrap();
        assert!(s.vault().seed_blocking(id, None).unwrap().unlocked);
    }

    #[test]
    fn next_blocking_on_the_subscription() {
        let s = open(Arc::new(Store::default()));
        let sub = s.subscribe();
        assert_eq!(
            sub.next_blocking(50).unwrap(),
            None,
            "nothing yet: the timeout"
        );
        import(&s);
        let mut seen = vec![];
        while let Some(e) = sub.next_blocking(200).unwrap() {
            seen.push(e);
        }
        assert!(
            seen.iter()
                .any(|e| matches!(e, Event::KeystoreChanged { .. })),
            "{seen:?}"
        );
    }

    #[test]
    fn a_twin_on_a_runtime_thread_is_refused() {
        let s = open(Arc::new(Store::default()));
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let r = rt.block_on(async { s.vault().seeds_blocking(None) });
        assert_eq!(r.map_err(|e| e.code()), Err("Internal"));
    }

    /// Review B1: a lock that cannot run is its error, never an empty answer; the seed is still reported unlocked.
    #[test]
    fn a_lock_that_cannot_run_is_internal() {
        let s = open(Arc::new(Store::default()));
        let id = import(&s);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let r = rt.block_on(async { s.vault().lock_blocking(id.clone()) });
        assert_eq!(r.map_err(|e| e.code()), Err("Internal"));
        let r = rt.block_on(async { s.vault().lock_all_blocking() });
        assert_eq!(r.map_err(|e| e.code()), Err("Internal"));
        assert!(s.vault().seed_blocking(id.clone(), None).unwrap().unlocked);
        // control: off the runtime the lock runs
        assert_eq!(
            s.vault().lock_blocking(id.clone()).unwrap(),
            Vec::<String>::new()
        );
        assert!(!s.vault().seed_blocking(id, None).unwrap().unlocked);
    }

    /// Review B11: the load check refuses another `api_version`, a missing feature bit; control: this library's.
    #[test]
    fn the_opening_runs_the_load_check() {
        let refused = |c: BindingConfig| {
            open_blocking(c, Arc::new(Store::default()), None)
                .err()
                .map(|e| e.code())
        };
        assert_eq!(
            refused(BindingConfig {
                expect_api: 2,
                ..config()
            }),
            Some("AbiMismatch")
        );
        assert_eq!(
            refused(BindingConfig {
                need_features: 1 << 62,
                ..config()
            }),
            Some("AbiMismatch")
        );
        assert_eq!(refused(config()), None);
    }
}
