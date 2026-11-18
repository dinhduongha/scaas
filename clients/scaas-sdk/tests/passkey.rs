// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T7: passkey and platform unlock (spec §6.10) through a test-only `FakeAuthenticator`: an HMAC PRF with separate secrets
//! with and without UV (CTAP2 `hmac-secret`), a platform secret, an "enrollment changed" answer.
#![allow(clippy::unwrap_used)]

use async_trait::async_trait;
use scaas_sdk::platform::{
    Assertion, AssertionRequest, AuthError, Authenticator, KeyPolicy, PasskeyCreated, SePublic,
};
use scaas_sdk::vault::{DeriveChild, ImportKey, ImportWords, MemoryStore, SecureStore, Unlock};
use scaas_sdk::{Limits, RuntimeChoice, Sdk, SdkConfig, SdkError};
use scaas_ua::wallet::{hmac_sha256, SecretBytes};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";

#[derive(Default)]
struct Fake {
    no_uv: AtomicBool,
    no_prf: AtomicBool,
    enrollment_changed: AtomicBool,
    /// every secret output written, to look for it elsewhere
    outputs: Mutex<Vec<[u8; 32]>>,
    /// the policy of each platform-secret call
    policies: Mutex<Vec<Option<KeyPolicy>>>,
}

impl Fake {
    fn write(&self, out: &SecretBytes, v: [u8; 32]) {
        out.with_mut(|b| b.copy_from_slice(&v));
        self.outputs.lock().unwrap().push(v);
    }
}

#[async_trait]
impl Authenticator for Fake {
    async fn create_passkey(
        &self,
        _: String,
        _: String,
        _: Vec<Vec<u8>>,
    ) -> Result<PasskeyCreated, AuthError> {
        Err(AuthError::Unavailable)
    }
    async fn get_assertion(
        &self,
        req: AssertionRequest,
        prf_out: Arc<SecretBytes>,
    ) -> Result<Assertion, AuthError> {
        let prf = !self.no_prf.load(Ordering::SeqCst);
        if let (true, Some(salt)) = (prf, &req.prf_salt) {
            let key: &[u8] = if self.no_uv.load(Ordering::SeqCst) {
                b"secret without UV"
            } else {
                b"secret with UV"
            };
            self.write(&prf_out, hmac_sha256(key, salt));
        }
        Ok(Assertion {
            credential_id: vec![0xc1, 0xed],
            authenticator_data: vec![0; 37],
            client_data_json: vec![],
            signature: vec![0; 64],
            prf,
        })
    }
    async fn platform_secret(
        &self,
        handle: String,
        salt: Vec<u8>,
        _: String,
        policy: Option<KeyPolicy>,
        out: Arc<SecretBytes>,
    ) -> Result<(), AuthError> {
        self.policies.lock().unwrap().push(policy);
        if self.enrollment_changed.load(Ordering::SeqCst) {
            return Err(AuthError::Refused);
        }
        self.write(&out, hmac_sha256(handle.as_bytes(), &salt));
        Ok(())
    }
    async fn p256_generate(&self, _: KeyPolicy) -> Result<SePublic, AuthError> {
        Err(AuthError::Unavailable)
    }
    async fn p256_sign(&self, _: String, _: Vec<u8>, _: String) -> Result<Vec<u8>, AuthError> {
        Err(AuthError::Unavailable)
    }
}

fn sec(s: &str) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(s.as_bytes().to_vec())).unwrap())
}

async fn sdk() -> (Arc<Sdk>, Arc<MemoryStore>, Arc<Fake>) {
    let (m, f) = (MemoryStore::new(), Arc::new(Fake::default()));
    let s = Sdk::open(SdkConfig {
        profiles: vec![],
        store: m.clone(),
        authenticator: Some(f.clone()),
        rp_id: Some("wallet.example".into()),
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
        clock: None,
    })
    .await
    .unwrap();
    (s, m, f)
}

async fn seed(s: &Arc<Sdk>) -> String {
    let req = ImportWords {
        label: "Main".into(),
        words: sec(REPO),
        vault_passphrase: sec(PASS),
    };
    s.vault().import_words(req).await.unwrap().id
}

fn code(r: Result<(), SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |()| "Ok")
}

async fn keystore_text(m: &MemoryStore) -> String {
    String::from_utf8(
        m.get("keystore".into(), String::new())
            .await
            .unwrap()
            .unwrap()
            .bytes,
    )
    .unwrap()
}

#[tokio::test]
async fn enable_then_unlock_by_passkey() {
    let (s, m, _) = sdk().await;
    let id = seed(&s).await;
    s.vault()
        .enable_passkey_unlock(id.clone(), sec(PASS))
        .await
        .unwrap();
    // every vault of the seed carries the PRF envelope, one salt
    let ks = scaas_sdk::vault::Keystore::parse(keystore_text(&m).await.as_bytes()).unwrap();
    let salts: Vec<String> = ks.seeds[0]
        .vaults
        .values()
        .map(|t| {
            serde_json::from_str::<serde_json::Value>(t).unwrap()["prf"]["salt"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(salts.len(), 2);
    assert!(salts.windows(2).all(|w| w[0] == w[1]), "one salt per seed");
    s.vault().lock(id.clone()).await;
    s.vault().unlock(id.clone(), Unlock::Passkey).await.unwrap();
    assert!(s.vault().seed(id).await.unwrap().unlocked);
}

#[tokio::test]
async fn no_prf_is_refused() {
    let (s, _, f) = sdk().await;
    let id = seed(&s).await;
    f.no_prf.store(true, Ordering::SeqCst);
    assert_eq!(
        code(s.vault().enable_passkey_unlock(id.clone(), sec(PASS)).await),
        "AuthenticatorRefused"
    );
    f.no_prf.store(false, Ordering::SeqCst);
    s.vault()
        .enable_passkey_unlock(id.clone(), sec(PASS))
        .await
        .unwrap();
    s.vault().lock(id.clone()).await;
    f.no_prf.store(true, Ordering::SeqCst);
    assert_eq!(
        code(s.vault().unlock(id.clone(), Unlock::Passkey).await),
        "AuthenticatorRefused"
    );
    assert_eq!(
        code(s.vault().unlock(id, Unlock::Passphrase(sec(PASS))).await),
        "Ok",
        "the passphrase still opens"
    );
}

#[tokio::test]
async fn non_uv_prf_output_does_not_open() {
    let (s, _, f) = sdk().await;
    let id = seed(&s).await;
    s.vault()
        .enable_passkey_unlock(id.clone(), sec(PASS))
        .await
        .unwrap();
    s.vault().lock(id.clone()).await;
    f.no_uv.store(true, Ordering::SeqCst);
    assert_eq!(
        code(s.vault().unlock(id.clone(), Unlock::Passkey).await),
        "VaultOpen"
    );
    f.no_uv.store(false, Ordering::SeqCst);
    assert_eq!(code(s.vault().unlock(id, Unlock::Passkey).await), "Ok");
}

#[tokio::test]
async fn platform_secret_unlock() {
    let (s, _, f) = sdk().await;
    let id = seed(&s).await;
    let policy = KeyPolicy {
        biometry_current_set: true,
        invalidated_by_enrollment: true,
    };
    s.vault()
        .enable_platform_unlock(id.clone(), sec(PASS), policy)
        .await
        .unwrap();
    s.vault().lock(id.clone()).await;
    s.vault()
        .unlock(id.clone(), Unlock::Platform)
        .await
        .unwrap();
    // closing review P2-8: the policy reaches the authenticator when the key is made, none at an unlock
    assert_eq!(*f.policies.lock().unwrap(), vec![Some(policy), None]);
    s.vault().lock(id.clone()).await;
    f.enrollment_changed.store(true, Ordering::SeqCst);
    assert_eq!(
        code(s.vault().unlock(id.clone(), Unlock::Platform).await),
        "AuthenticatorRefused"
    );
    assert_eq!(
        code(s.vault().unlock(id, Unlock::Passphrase(sec(PASS))).await),
        "Ok"
    );
}

#[tokio::test]
async fn manifest_reseal_keeps_prf() {
    let (s, _, _) = sdk().await;
    let id = seed(&s).await;
    // enabled while the seed is open, then a manifest change in the same session (a BIP-85 child)
    s.vault()
        .enable_passkey_unlock(id.clone(), sec(PASS))
        .await
        .unwrap();
    let child = |l: &str| DeriveChild {
        parent: id.clone(),
        label: l.into(),
        vault_passphrase: sec(PASS),
    };
    s.vault().derive_child(child("C0")).await.unwrap();
    s.vault().lock(id.clone()).await;
    // the next passkey unlock opens the re-sealed manifest, and it holds the raised index
    s.vault().unlock(id.clone(), Unlock::Passkey).await.unwrap();
    let c1 = s.vault().derive_child(child("C1")).await.unwrap();
    let rows: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../smartcontracts/vectors/keys/bip85.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let words = c1
        .backup
        .reveal()
        .unwrap()
        .with(|b| String::from_utf8(b.to_vec()).unwrap());
    assert_eq!(words, rows["children"][1]["words"].as_str().unwrap());
    s.vault().lock(id.clone()).await;
    s.vault().unlock(id, Unlock::Passkey).await.unwrap();
}

#[tokio::test]
async fn prf_output_never_leaves() {
    let (s, m, f) = sdk().await;
    let id = seed(&s).await;
    let ev = s.subscribe();
    s.vault()
        .enable_passkey_unlock(id.clone(), sec(PASS))
        .await
        .unwrap();
    s.vault().lock(id.clone()).await;
    s.vault().unlock(id.clone(), Unlock::Passkey).await.unwrap();
    f.no_uv.store(true, Ordering::SeqCst);
    s.vault().lock(id.clone()).await;
    let err = s.vault().unlock(id, Unlock::Passkey).await.unwrap_err();
    let outs = f.outputs.lock().unwrap().clone();
    assert!(outs.len() >= 3, "control: outputs were recorded");
    let mut seen = keystore_text(&m).await.into_bytes();
    seen.extend(format!("{err:?} {err}").into_bytes());
    while let Some(e) = ev.next(50).await {
        seen.extend(format!("{e:?}").into_bytes());
    }
    for o in outs {
        let hexed: String = o.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!seen.windows(32).any(|w| w == o), "raw output");
        assert!(
            !String::from_utf8_lossy(&seen).contains(&hexed),
            "hex output"
        );
    }
}

#[tokio::test]
async fn disable_prf_unlock() {
    let (s, _, _) = sdk().await;
    let id = seed(&s).await;
    s.vault()
        .enable_passkey_unlock(id.clone(), sec(PASS))
        .await
        .unwrap();
    s.vault().disable_prf_unlock(id.clone()).await.unwrap();
    assert!(
        !s.vault().seed(id.clone()).await.unwrap().unlocked,
        "locked by the disable"
    );
    assert_eq!(
        code(s.vault().unlock(id.clone(), Unlock::Passkey).await),
        "AuthenticatorRefused",
        "no envelope"
    );
    assert_eq!(
        code(s.vault().unlock(id, Unlock::Passphrase(sec(PASS))).await),
        "Ok"
    );
}

#[tokio::test]
async fn change_passphrase_keeps_the_dek() {
    let (s, _, _) = sdk().await;
    let id = seed(&s).await;
    s.vault()
        .enable_passkey_unlock(id.clone(), sec(PASS))
        .await
        .unwrap();
    let new = "otter-river-8 ünï";
    assert_eq!(
        code(
            s.vault()
                .change_passphrase(id.clone(), sec("wrong-pass-9"), sec(new))
                .await
        ),
        "VaultOpen"
    );
    assert_eq!(
        code(
            s.vault()
                .change_passphrase(id.clone(), sec(PASS), sec("1234567"))
                .await
        ),
        "VaultPassphraseWeak"
    );
    s.vault()
        .change_passphrase(id.clone(), sec(PASS), sec(new))
        .await
        .unwrap();
    s.vault().lock(id.clone()).await;
    assert_eq!(
        code(
            s.vault()
                .unlock(id.clone(), Unlock::Passphrase(sec(PASS)))
                .await
        ),
        "VaultOpen"
    );
    s.vault()
        .unlock(id.clone(), Unlock::Passphrase(sec(new)))
        .await
        .unwrap();
    s.vault().lock(id.clone()).await;
    s.vault().unlock(id, Unlock::Passkey).await.unwrap();
}

/// Spec §6.7 (owner 2026-11-18: restored with `import_key` in T4): an import made in a passkey session asks the authenticator
/// once and its new vault carries the seed's PRF envelope (its credential and salt), which opens it.
#[tokio::test]
async fn new_import_in_a_passkey_session_carries_the_prf_envelope() {
    let (s, m, f) = sdk().await;
    let id = seed(&s).await;
    s.vault()
        .enable_passkey_unlock(id.clone(), sec(PASS))
        .await
        .unwrap();
    s.vault().lock(id.clone()).await;
    s.vault().unlock(id.clone(), Unlock::Passkey).await.unwrap();
    let key = Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(vec![0x11; 32])).unwrap());
    let req = ImportKey {
        seed: id.clone(),
        network: "evm".into(),
        secret: key,
        vault_passphrase: sec(PASS),
    };
    s.vault().import_key(req).await.unwrap();
    let ks = scaas_sdk::vault::Keystore::parse(keystore_text(&m).await.as_bytes()).unwrap();
    let vaults = &ks.seeds[0].vaults;
    let prf =
        |l: &str| serde_json::from_str::<serde_json::Value>(&vaults[l]).unwrap()["prf"].clone();
    assert!(
        prf("native-import:evm:0").is_object(),
        "the new vault carries the PRF envelope"
    );
    assert_eq!(
        prf("native-import:evm:0")["salt"],
        prf("seed")["salt"],
        "the seed's one salt"
    );
    assert_eq!(
        prf("native-import:evm:0")["credentialId"],
        prf("seed")["credentialId"]
    );
    // it opens with the passkey's output
    let out = *f.outputs.lock().unwrap().last().unwrap();
    let v = scaas_ua::wallet::Vault::from_json(vaults["native-import:evm:0"].as_bytes()).unwrap();
    let w = scaas_ua::wallet::Wallet::from_mnemonic(REPO, "").unwrap();
    assert!(w
        .open_label_vault(&v, scaas_ua::wallet::Unlock::Prf(&out))
        .is_ok());
}

/// T13 P2-1: `change_passphrase` with one secret object for the old and the new passphrase completes (a nested lock of one
/// secret waits on itself inside the heavy job and holds the only permit); a later unlock still runs. The SDK on its own
/// runtime, so a hang fails the timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_passphrase_one_secret_for_both() {
    let s = Sdk::open(SdkConfig {
        profiles: vec![],
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Own,
        limits: Limits {
            max_concurrent_heavy: 1,
            ..Limits::default()
        },
        clock: None,
    })
    .await
    .unwrap();
    let within = std::time::Duration::from_secs(120);
    let id = seed(&s).await;
    let p = sec(PASS);
    tokio::time::timeout(
        within,
        s.vault().change_passphrase(id.clone(), p.clone(), p),
    )
    .await
    .expect("change_passphrase with one object for both hangs")
    .unwrap();
    s.vault().lock(id.clone()).await;
    let r = tokio::time::timeout(within, s.vault().unlock(id, Unlock::Passphrase(sec(PASS))))
        .await
        .expect("a later heavy job waits");
    assert_eq!(code(r), "Ok");
}
