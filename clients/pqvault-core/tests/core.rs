// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `pqvault-core` without a chain (plan V10): P1 before any other work (no SDK call recorded by a test seam), a pending or an
//! unverified vault never unlocked, the dependency rule (C1, CLI-PQV-01), and no key byte in the crate's public surface.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

use pqvault_core::records::*;
use pqvault_core::{Error, Instance, Mode, Net, Passphrase, PqVault, VaultInfo, VaultState};
use scaas_sdk::app_core::{AppCall, AppKey, AppPath, AppSigned, AppWrap, SecretBytes};
use scaas_sdk::op::KeyRef;
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::{Limits, RuntimeChoice, Sdk, SdkConfig, SdkError};
use serde_json::Value;
use std::sync::{Arc, Mutex};

const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const TWELVE: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn sec(b: &[u8]) -> Arc<SecretBytes> {
    let s = SecretBytes::new(b.len()).unwrap();
    s.with_mut(|m| m.copy_from_slice(b));
    Arc::new(s)
}

/// A seam that records every call and answers none.
#[derive(Default)]
struct Recorder(Mutex<Vec<String>>);
#[async_trait::async_trait]
impl Net for Recorder {
    async fn read(&self, _: &str, _: Addr, sig: &str, _: Value) -> Result<Value, SdkError> {
        self.0.lock().unwrap().push(format!("read {sig}"));
        Err(SdkError::Argument)
    }
    async fn sign(
        &self,
        _: &str,
        _: &KeyRef,
        _: AppPath,
        _: String,
    ) -> Result<AppSigned, SdkError> {
        self.0.lock().unwrap().push("sign".into());
        Err(SdkError::Argument)
    }
    async fn verify(
        &self,
        _: &str,
        _: B32,
        _: AppPath,
        _: String,
        _: UaSig,
    ) -> Result<Option<Vec<scaas_sdk::app_core::MsigVersion>>, SdkError> {
        self.0.lock().unwrap().push("verify".into());
        Err(SdkError::Argument)
    }
    async fn kem_wrap(
        &self,
        _: &str,
        _: B32,
        _: u64,
        _: Arc<AppKey>,
        _: Vec<u8>,
        _: Vec<u8>,
    ) -> Result<AppWrap, SdkError> {
        self.0.lock().unwrap().push("kem_wrap".into());
        Err(SdkError::Argument)
    }
    async fn call(
        &self,
        _: &str,
        _: Addr,
        _: &str,
        _: Value,
        _: KeyRef,
    ) -> Result<AppCall, SdkError> {
        self.0.lock().unwrap().push("call".into());
        Err(SdkError::Argument)
    }
    async fn quote(
        &self,
        _: &str,
        _: Addr,
        _: &str,
        _: Value,
        _: KeyRef,
        _: KeyRef,
    ) -> Result<scaas_sdk::app_core::AppQuote, SdkError> {
        self.0.lock().unwrap().push("quote".into());
        Err(SdkError::Argument)
    }
}

static ONE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn setup() -> (PqVault, Arc<Recorder>, String, String) {
    let sdk = Sdk::open(SdkConfig {
        profiles: vec![],
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
        clock: None,
        gas_tables: vec![],
    })
    .await
    .unwrap();
    let mut ids = vec![];
    for (label, w) in [("full", REPO), ("twelve", TWELVE)] {
        ids.push(
            sdk.vault()
                .import_words(ImportWords {
                    label: label.into(),
                    words: sec(w.as_bytes()),
                    vault_passphrase: sec("river-otter-7 ünï".as_bytes()),
                })
                .await
                .unwrap()
                .id,
        );
    }
    let core = PqVault::scope(&sdk).unwrap();
    let rec = Arc::new(Recorder::default());
    let pv = PqVault::with_net(sdk, core, rec.clone());
    (pv, rec, ids[0].clone(), ids[1].clone())
}

fn ua_key(seed: &str, kind: u16) -> KeyRef {
    KeyRef::Ua {
        seed: seed.into(),
        kind,
        account: 0,
        index: 0,
    }
}

/// A payer of `k`'s seed (its native EVM key).
fn payer(k: &KeyRef) -> KeyRef {
    let (KeyRef::Ua { seed, .. } | KeyRef::Native { seed, .. }) = k else {
        unreachable!()
    };
    KeyRef::Native {
        seed: seed.clone(),
        network: "evm".into(),
        index: 0,
    }
}

fn at() -> Instance {
    Instance {
        chain: "anvil".into(),
        chain_id: 31337,
        contract: Addr([0xaa; 20]),
    }
}

fn info() -> VaultInfo {
    VaultInfo {
        name: "v".into(),
        shared: false,
        icon: None,
        settings: None,
    }
}

/// P1 (CLI-PQV-06): a 12-word set, a native key and a classical kind are refused before any SDK call; the positive control (a
/// PQ kind of the 24-word set) passes P1 and reaches the seam.
#[tokio::test(flavor = "multi_thread")]
async fn p1_refusals_before_any_call() {
    let _one = ONE.lock().await;
    let (pv, rec, full, twelve) = setup().await;
    let members = |pv: &PqVault, k: &KeyRef| {
        vec![MemberKey {
            ua: pv.ua(k).unwrap(),
            key_id: Num(0),
            via: B32::default(),
        }]
    };
    let off = Passphrase::Off;
    for (k, want) in [
        (ua_key(&twelve, pqvault_core::FNDSA512), "SeedNotPqRooted"),
        (
            KeyRef::Native {
                seed: full.clone(),
                network: "evm".into(),
                index: 0,
            },
            "SeedNotPqRooted",
        ),
        (ua_key(&full, 0x0108), "UaKindNotPq"),
    ] {
        let m = if matches!(k, KeyRef::Ua { .. }) {
            members(&pv, &k)
        } else {
            vec![]
        };
        let r = pv
            .create_vault(&k, &info(), &m, &at(), Mode::Portable, &off, payer(&k))
            .await;
        assert_eq!(format!("{:?}", r.err().unwrap()), want);
        let r = pv.recover(&k, &at()).await;
        assert_eq!(format!("{:?}", r.err().unwrap()), want);
        assert!(rec.0.lock().unwrap().is_empty(), "no SDK call before P1");
    }
    let k = PqVault::vault_key(&full, 1);
    let r = pv
        .create_vault(
            &k,
            &info(),
            &members(&pv, &k),
            &at(),
            Mode::Portable,
            &off,
            payer(&k),
        )
        .await;
    assert!(matches!(r, Err(Error::Sdk(_))));
    assert_eq!(
        rec.0.lock().unwrap().len(),
        1,
        "the control reaches the seam: {:?}",
        rec.0.lock().unwrap()
    );
}

/// VC19: a user-chosen passphrase under 16 characters is refused before any SDK call; 16 pass.
#[tokio::test(flavor = "multi_thread")]
async fn passphrase_length() {
    let _one = ONE.lock().await;
    let (pv, rec, full, _) = setup().await;
    let k = PqVault::vault_key(&full, 1);
    let m = vec![MemberKey {
        ua: pv.ua(&k).unwrap(),
        key_id: Num(0),
        via: B32::default(),
    }];
    let short = Passphrase::On(sec("fifteen chars!!".as_bytes()));
    let r = pv
        .create_vault(&k, &info(), &m, &at(), Mode::Portable, &short, payer(&k))
        .await;
    assert!(matches!(r, Err(Error::PassphraseTooShort)));
    assert!(rec.0.lock().unwrap().is_empty());
    let ok = Passphrase::On(sec("sixteen chars!!!".as_bytes()));
    let r = pv
        .create_vault(&k, &info(), &m, &at(), Mode::Portable, &ok, payer(&k))
        .await;
    assert!(matches!(r, Err(Error::Sdk(_))));
}

fn state(pv: &PqVault, k: &KeyRef, verified: bool, pending: bool) -> VaultState {
    let me = pv.ua(k).unwrap();
    let create = VaultCreate {
        creator: me,
        nonce: Num(1),
        mode: Num(0),
        home_chain: B32([1; 32]),
        home_vault_contract: Addr([0xaa; 20]),
        admins: vec![me],
        members: vec![],
        wrap_hashes: vec![],
        pass_kdf: Num(0),
        pass_salt: B32::default(),
        sealed_info: Bytes(vec![]),
        group_mode: Num(0),
    };
    VaultState {
        at: at(),
        chain_uid: B32([1; 32]),
        vault_id: B32([2; 32]),
        create,
        epochs: vec![],
        me,
        verified,
        pending,
    }
}

/// VC18, VC15: a pending vault is `Pending` and an unverified one `ChainUnverified` at unlock, with no SDK call; a state read
/// for another UA is `NotMember`.
#[tokio::test(flavor = "multi_thread")]
async fn pending_and_unverified_never_unlock() {
    let _one = ONE.lock().await;
    let (pv, rec, full, _) = setup().await;
    let k = PqVault::vault_key(&full, 1);
    let off = Passphrase::Off;
    assert!(matches!(
        pv.unlock(&k, state(&pv, &k, true, true), &off).await,
        Err(Error::Pending)
    ));
    assert!(matches!(
        pv.unlock(&k, state(&pv, &k, false, false), &off).await,
        Err(Error::ChainUnverified)
    ));
    let other = PqVault::vault_key(&full, 2);
    assert!(matches!(
        pv.unlock(&other, state(&pv, &k, true, false), &off).await,
        Err(Error::NotMember)
    ));
    // the control: verified, accepted, the right UA, and no epoch: refused for having none, past the three checks
    assert!(matches!(
        pv.unlock(&k, state(&pv, &k, true, false), &off).await,
        Err(Error::ChainUnverified)
    ));
    assert!(rec.0.lock().unwrap().is_empty());
}

/// CLI-PQV-01: `scaas-sdk` is the only SCaaS crate the library depends on (`cargo tree -e normal --depth 1`).
#[test]
fn depends_on_the_sdk_only() {
    let out = std::process::Command::new(env!("CARGO"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "tree",
            "--offline",
            "--locked",
            "-e",
            "normal",
            "--depth",
            "1",
            "--prefix",
            "none",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let t = String::from_utf8(out.stdout).unwrap();
    let names: Vec<&str> = t
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    assert!(names.contains(&"scaas-sdk"), "{t}");
    for no in ["scaas-ua", "scaas-rpc"] {
        assert!(!names.contains(&no), "{no} is a direct dependency:\n{t}");
    }
}

/// C1 (CLI-PQV-12): the library never calls the SDK's test entries that take or give key bytes, and no public item of it
/// carries a key: every key is an `AppKey` handle in a private field (a scan of `src/`).
#[test]
fn no_key_bytes_in_the_surface() {
    let dir = format!("{}/src", env!("CARGO_MANIFEST_DIR"));
    for f in std::fs::read_dir(dir).unwrap() {
        let p = f.unwrap().path();
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(!s.contains("vectors_"), "{p:?} calls a test entry");
        for (i, l) in s.lines().enumerate() {
            let t = l.trim_start();
            if t.starts_with("pub ") && !t.starts_with("pub fn") && !t.starts_with("pub async fn") {
                assert!(
                    !t.contains("AppKey"),
                    "{p:?}:{} a public key handle field: {t}",
                    i + 1
                );
            }
            assert!(
                !(t.starts_with("pub") && t.contains("SecretBytes>") && t.contains("->")),
                "{p:?}:{}",
                i + 1
            );
        }
    }
}

/// VC12: the migration plan moves every live item's latest version, skips tombstones, lists what does not open, and carries
/// the warning.
#[test]
fn migration_plan_and_warning() {
    use pqvault_core::{Item, ItemVersion};
    let v = |id: u8, value: Item| ItemVersion {
        item_id: B32([id; 32]),
        version: 1,
        version_count: 1,
        epoch_id: B32([9; 32]),
        author: B32([8; 32]),
        value: Ok(value),
    };
    let from = vec![(
        B32([1; 32]),
        vec![
            v(1, Item::new("login")),
            v(2, Item::deleted()),
            ItemVersion {
                value: Err(Error::Unreadable),
                ..v(3, Item::new("login"))
            },
        ],
    )];
    let p = PqVault::migration_plan(&from);
    assert_eq!(p.items, vec![(B32([1; 32]), B32([1; 32]))]);
    assert_eq!(p.unreadable, vec![(B32([1; 32]), B32([3; 32]))]);
    assert_eq!(p.skipped_tombstones, 1);
    assert!(p.warning.contains("stay on chain") && p.warning.contains("changed at its service"));
}

/// Owner 2026-11-22 (CLI-PQV-15 (2)): `generate_passphrase` gives 6 BIP-39 English words, drawn below the SDK, with no
/// network call.
#[tokio::test(flavor = "multi_thread")]
async fn generated_passphrase_is_six_bip39_words() {
    let _one = ONE.lock().await;
    let (pv, rec, full, _) = setup().await;
    let Passphrase::Given(s) = pv.generate_passphrase(&full).unwrap() else {
        panic!("a given passphrase")
    };
    let words: Vec<String> = s.with(|b| {
        std::str::from_utf8(b)
            .unwrap()
            .split(' ')
            .map(str::to_string)
            .collect()
    });
    assert_eq!(words.len(), 6);
    for w in &words {
        assert!(pv.sdk.vault().word_in_list(sec(w.as_bytes())), "{w}");
    }
    assert!(rec.0.lock().unwrap().is_empty());
}

/// CTR-PQV-18: the vector row `createTreeKem` (shared0's create record with groupMode 1, signed by its creator) is
/// `ChainUnverified` at verify before any SDK call; the control, the same record with groupMode 0, reaches the seam's
/// signature check.
#[tokio::test(flavor = "multi_thread")]
async fn a_vault_of_group_mode_1_is_refused_before_any_call() {
    let _one = ONE.lock().await;
    let (pv, rec, _, _) = setup().await;
    let p = format!(
        "{}/../../smartcontracts/vectors/pqvault/records.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let d: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let row = &d["createTreeKem"];
    assert_eq!(row["error"], "PqVaultModeUnsupported(1)");
    let create: VaultCreate = serde_json::from_value(row["record"].clone()).unwrap();
    assert_eq!(create.group_mode, Num(1));
    let vid = vault_id(
        create.creator,
        create.nonce.0,
        0,
        create.home_chain,
        create.home_vault_contract,
    );
    assert_eq!(
        hex(&vid.0),
        row["id"].as_str().unwrap(),
        "the row's vaultId"
    );
    let s = |c: VaultCreate| VaultState {
        at: at(),
        chain_uid: c.home_chain,
        vault_id: vid,
        epochs: vec![pqvault_core::EpochState {
            id: vid,
            number: 0,
            parent: B32::default(),
            author: c.creator,
            admins: c.admins.clone(),
            members: c.members.clone(),
            wrap_hashes: c.wrap_hashes.clone(),
            pass_kdf: 1,
            pass_salt: c.pass_salt,
            sealed_info: c.sealed_info.0.clone(),
            nonce: c.nonce.0,
            sig: sig_of(&row["uaSig"]).unwrap(),
            removals: vec![],
            own_wraps: vec![],
        }],
        me: c.creator,
        create: c,
        verified: false,
        pending: false,
    };
    assert!(matches!(
        pv.verify(s(create.clone())).await,
        Err(Error::ChainUnverified)
    ));
    assert!(
        rec.0.lock().unwrap().is_empty(),
        "refused before any SDK call"
    );
    let mut flat = create;
    flat.group_mode = Num(0);
    assert!(pv.verify(s(flat)).await.is_err());
    assert_eq!(
        *rec.0.lock().unwrap(),
        vec!["verify".to_string()],
        "the control reaches the signature check"
    );
}
