// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The UniFFI surface's list (plan T20b; spec §16.1): every exported async call of the SDK's module objects has its entry in
//! `binding::surface()` with its `<call>_blocking` twin, and every entry names an async call of the SDK (both ways). Needs the
//! features of the reference library and `uniffi`; with `sync-api` too, the sync surface's own tests (module `sync`).
use std::collections::BTreeSet;

/// `(object, call)` of every `pub async fn` in an `impl <Module>` block of `src/` (the Rust-only calls excluded).
fn exported_async() -> BTreeSet<(String, String)> {
    let modules = [
        "Sdk",
        "Vault",
        "Account",
        "Wallet",
        "Op",
        "Confidential",
        "Dex",
        "Admin",
    ];
    let rust_only = [
        ("Sdk", "open"),
        ("Sdk", "spawn"),
        ("Sdk", "poll"),
        ("Wallet", "native_sign"),
        ("Vault", "lock"),
        ("Vault", "lock_all"),
    ];
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
            if !name.ends_with(".rs") || name.ends_with("tests.rs") || name.ends_with("binding.rs")
            {
                continue;
            }
            let mut obj: Option<String> = None;
            for line in std::fs::read_to_string(&p).unwrap().lines() {
                let t = line.trim_start();
                if let Some(rest) = t.strip_prefix("impl ") {
                    let ty = rest.split([' ', '{']).next().unwrap_or("");
                    let ty = ty.rsplit("::").next().unwrap_or("").to_string();
                    obj = modules.contains(&ty.as_str()).then_some(ty);
                } else if let (Some(o), Some(rest)) = (&obj, t.strip_prefix("pub async fn ")) {
                    let f: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                        .collect();
                    if !rust_only.contains(&(o.as_str(), f.as_str())) {
                        out.insert((o.clone(), f));
                    }
                }
            }
        }
    }
    out
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
    let unknown: Vec<_> = listed
        .iter()
        .filter(|(o, f)| {
            !src_named.contains(&(o.clone(), f.clone()))
                && !(f.starts_with("admin_ua_") || f.starts_with("prepare_"))
        })
        .collect();
    assert!(
        unknown.is_empty(),
        "entries naming no SDK async call: {unknown:?}"
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
                    want.insert(name_of(rest));
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
                true => format!("{}_{m}", snake(o)),
                false => m,
            });
        }
    }
    let js = std::fs::read_to_string("src/wasm/js.rs").unwrap();
    let have: BTreeSet<String> = js
        .lines()
        .filter_map(|l| {
            let t = l.trim_start();
            t.strip_prefix("pub fn ")
                .or(t.strip_prefix("fn "))
                .map(name_of)
        })
        .collect();
    // sync-api only: the blocking open and the run hooks are not calls of the async surface
    let sync_only = [
        "open_blocking",
        "run",
        "run_blocking",
        "inner",
        "new",
        "module",
    ];
    let missing: Vec<_> = want
        .iter()
        .filter(|n| !have.contains(*n) && !sync_only.contains(&n.as_str()))
        .collect();
    assert!(
        want.len() > 40,
        "control: binding.rs is read ({} names)",
        want.len()
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
        // one caller at a time in these tests: no lock to hold
        fn lock(&self, _: String) -> Result<u64, StoreError> {
            Ok(1)
        }
        fn unlock(&self, _: u64) {}
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
        let t = token.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            t.cancel();
        });
        let d = done.clone();
        let start = Instant::now();
        let r = s.run_blocking(Some(token), async move {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            d.store(true, Ordering::SeqCst);
            Ok(())
        });
        canceller.join().unwrap();
        assert_eq!(r.map_err(|e| e.code()), Err("Cancelled"));
        assert!(
            start.elapsed() < Duration::from_millis(1000),
            "returned at the cancel, not at the call's end"
        );
        // the effect of a dropped future (spec §13.4): the work goes on on the SDK's runtime
        while !done.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(10) {
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
        s.vault().lock_blocking(id.clone());
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
        assert_eq!(sub.next_blocking(50), None, "nothing yet: the timeout");
        import(&s);
        let mut seen = vec![];
        while let Some(e) = sub.next_blocking(200) {
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
}
