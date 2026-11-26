// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Owner (M) 2026-11-23 (CTR-CHAT-24, PqVault on the shared base): a member UA may hold several of its own KEM keys in an epoch,
//! members strictly ascending by `(ua, keyId)`, one wrap each, at most 8 keys per UA. `pqvault-core` keeps every key a caller
//! names (sorted, a repeated `(ua, keyId)` once), refuses a ninth key of one UA before any SDK call, opens each own key's
//! wrap, and reads rights per UA (a member's added key is no new member). Offline: a seam that wraps to the repository seed's
//! KEM keys and signs nothing.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

use pqvault_core::records::*;
use pqvault_core::{
    keys, EpochState, Error, Instance, Link, Mode, Net, Passphrase, PqVault, VaultInfo, VaultState,
};
use scaas_sdk::app_core::{AppCall, AppCore, AppKey, AppPath, AppSigned, AppWrap, SecretBytes};
use scaas_sdk::op::KeyRef;
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::{Limits, RuntimeChoice, Sdk, SdkConfig, SdkError};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const UID: B32 = B32([1; 32]);

fn sec(b: &[u8]) -> Arc<SecretBytes> {
    let s = SecretBytes::new(b.len()).unwrap();
    s.with_mut(|m| m.copy_from_slice(b));
    Arc::new(s)
}

/// The chain's side: `factoryInfo`'s `chainUid`, a wrap to the repository seed's KEM key of the vault UA at the version asked
/// (`kemKeyAt` as the registry answers it), every signature accepted and a dummy signer; each wrap's `(ua, keyId)` recorded.
struct Seam {
    core: Arc<AppCore>,
    kem: Vec<(B32, u64, Vec<u8>)>,
    calls: Mutex<Vec<(B32, u64)>>,
}
#[async_trait::async_trait]
impl Net for Seam {
    async fn read(&self, _: &str, _: Addr, sig: &str, _: Value) -> Result<Value, SdkError> {
        assert!(sig.starts_with("function factoryInfo()"), "{sig}");
        Ok(json!({"info": {"chainUid": UID}}))
    }
    async fn sign(
        &self,
        _: &str,
        _: &KeyRef,
        _: AppPath,
        _: String,
    ) -> Result<AppSigned, SdkError> {
        Ok(AppSigned {
            key_data: vec![],
            signature: vec![1],
            members: vec![],
            digest: String::new(),
            review: vec![],
        })
    }
    async fn verify(
        &self,
        _: &str,
        _: B32,
        _: AppPath,
        _: String,
        _: UaSig,
    ) -> Result<Option<Vec<scaas_sdk::app_core::MsigVersion>>, SdkError> {
        Ok(Some(vec![]))
    }
    async fn kem_wrap(
        &self,
        _: &str,
        ua: B32,
        version: u64,
        key: Arc<AppKey>,
        label: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<AppWrap, SdkError> {
        self.calls.lock().unwrap().push((ua, version));
        let pk = self
            .kem
            .iter()
            .find(|(u, v, _)| *u == ua && *v == version)
            .map(|(_, _, pk)| pk.clone())
            .ok_or(SdkError::Argument)?;
        self.core.kem_wrap_to_key(pk, key, label, aad)
    }
    async fn call(
        &self,
        _: &str,
        _: Addr,
        _: &str,
        _: Value,
        _: KeyRef,
    ) -> Result<AppCall, SdkError> {
        Err(SdkError::Argument)
    }
}

static ONE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct World {
    pv: PqVault,
    seam: Arc<Seam>,
    core: Arc<AppCore>,
    me: KeyRef,
    a: B32,
    b: B32,
    c: B32,
}

/// The vault UAs 1 (`a`, the user), 2 (`b`) and 3 (`c`) of the repository seed, each with KEM keys 1 to 9.
async fn world() -> World {
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
    let seed = sdk
        .vault()
        .import_words(ImportWords {
            label: "full".into(),
            words: sec(REPO.as_bytes()),
            vault_passphrase: sec("river-otter-7 ünï".as_bytes()),
        })
        .await
        .unwrap()
        .id;
    let core = PqVault::scope(&sdk).unwrap();
    let wl = scaas_ua::wallet::Wallet::from_mnemonic(REPO, "").unwrap();
    let mut kem = vec![];
    let mut uas = vec![];
    for index in 1..=3 {
        let k = wl
            .ua_key(pqvault_core::FNDSA512, pqvault_core::PQV_ACCOUNT, index)
            .unwrap();
        let ua = B32(k.ua().unwrap());
        for v in 1..=9 {
            kem.push((ua, v, k.kem_key(v).unwrap().kem_pk()));
        }
        uas.push(ua);
    }
    let seam = Arc::new(Seam {
        core: core.clone(),
        kem,
        calls: Mutex::new(vec![]),
    });
    let pv = PqVault::with_net(sdk, core.clone(), seam.clone());
    let me = PqVault::vault_key(&seed, 1);
    assert_eq!(pv.ua(&me).unwrap(), uas[0]);
    World {
        pv,
        seam,
        core,
        me,
        a: uas[0],
        b: uas[1],
        c: uas[2],
    }
}

fn key(ua: B32, k: u64) -> MemberKey {
    MemberKey {
        ua,
        key_id: Num(k),
        via: B32::default(),
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
        shared: true,
        icon: None,
        settings: None,
    }
}

fn keys_of(m: &[MemberKey]) -> Vec<(B32, u64)> {
    m.iter().map(|m| (m.ua, m.key_id.0)).collect()
}

/// The state a node would answer for `s` (epoch 0 only), the user's own wraps by member index.
fn state(w: &World, s: &Signed<VaultCreate>, wraps: &[Wrap]) -> VaultState {
    let c = &s.record;
    let vid = vault_id(c.creator, c.nonce.0, 0, c.home_chain, c.home_vault_contract);
    VaultState {
        at: at(),
        chain_uid: UID,
        vault_id: vid,
        create: c.clone(),
        epochs: vec![EpochState {
            id: vid,
            number: 0,
            parent: B32::default(),
            author: c.creator,
            admins: c.admins.clone(),
            members: c.members.clone(),
            wrap_hashes: c.wrap_hashes.clone(),
            pass_kdf: 0,
            pass_salt: B32::default(),
            sealed_info: c.sealed_info.0.clone(),
            nonce: c.nonce.0,
            sig: s.sig.clone(),
            removals: vec![],
            own_wraps: c
                .members
                .iter()
                .enumerate()
                .filter(|(_, m)| m.ua == w.a)
                .map(|(i, _)| (i, wraps[i].clone()))
                .collect(),
        }],
        me: w.a,
        verified: false,
        pending: false,
    }
}

/// The user's UA `a` with keys 2 and 1 (given out of order, key 2 twice) and `b` with key 1: the record keeps all three
/// entries, `(ua, keyId)` ascending, one wrap each to that key; each of `a`'s two wraps opens to the same `K_e`, and the
/// vault unlocks by either alone.
#[tokio::test(flavor = "multi_thread")]
async fn each_own_key_is_kept_and_its_wrap_opens() {
    let _one = ONE.lock().await;
    let w = world().await;
    let given = [key(w.a, 2), key(w.b, 1), key(w.a, 1), key(w.a, 2)];
    let (s, wraps) =
        w.pv.create_vault(
            &w.me,
            &info(),
            &given,
            &at(),
            Mode::Portable,
            &Passphrase::Off,
        )
        .await
        .unwrap();
    let mut want = vec![(w.a, 1), (w.a, 2), (w.b, 1)];
    want.sort();
    assert_eq!(
        keys_of(&s.record.members),
        want,
        "every key, (ua, keyId) ascending"
    );
    assert_eq!(
        *w.seam.calls.lock().unwrap(),
        want,
        "one wrap per key, to that key"
    );
    assert_eq!(
        wraps
            .iter()
            .map(|x| (x.member, x.key_id.0))
            .collect::<Vec<_>>(),
        want
    );
    let st = w.pv.verify(state(&w, &s, &wraps)).await.unwrap();
    let own = &st.epochs[0].own_wraps;
    assert_eq!(own.len(), 2, "both of the user's wraps read");
    let vid = st.vault_id;
    let kes: Vec<Arc<AppKey>> = own
        .iter()
        .map(|(_, x)| keys::unwrap(&w.core, &w.me, x, vid, vid).unwrap())
        .collect();
    assert!(
        w.core.same_key(kes[0].clone(), kes[1].clone()).unwrap(),
        "one K_e under both keys"
    );
    // the control: a wrap of another member's key does not open by the user's
    let theirs = wraps.iter().find(|x| x.member == w.b).unwrap();
    assert!(keys::unwrap(&w.core, &w.me, theirs, vid, vid).is_err());
    // unlocked by either own wrap alone: each key's wrap is enough
    for keep in 0..2 {
        let mut one = st.clone();
        one.epochs[0].own_wraps.remove(1 - keep);
        let u = w.pv.unlock(&w.me, one, &Passphrase::Off).await.unwrap();
        assert_eq!(u.readable(), vec![vid], "own wrap {keep}");
    }
    // a wrong first wrap is skipped and the second opens
    let mut skip = st.clone();
    skip.epochs[0].own_wraps[0].1.sealed_key.0[0] ^= 1;
    let u = w.pv.unlock(&w.me, skip, &Passphrase::Off).await.unwrap();
    assert_eq!(u.readable(), vec![vid]);
}

/// At most 8 keys per UA: a ninth key of one UA is `Shape` before any SDK call; 8 pass. In a rekey too.
#[tokio::test(flavor = "multi_thread")]
async fn at_most_eight_keys_per_ua() {
    let _one = ONE.lock().await;
    let w = world().await;
    let mut nine: Vec<MemberKey> = (1..=9).map(|k| key(w.a, k)).collect();
    nine.push(key(w.b, 1));
    let r =
        w.pv.create_vault(
            &w.me,
            &info(),
            &nine,
            &at(),
            Mode::Portable,
            &Passphrase::Off,
        )
        .await;
    assert!(matches!(r, Err(Error::Shape)), "{:?}", r.err());
    assert!(
        w.seam.calls.lock().unwrap().is_empty(),
        "no wrap before the refusal"
    );
    nine.remove(8);
    let (s, wraps) =
        w.pv.create_vault(
            &w.me,
            &info(),
            &nine,
            &at(),
            Mode::Portable,
            &Passphrase::Off,
        )
        .await
        .unwrap();
    assert_eq!(s.record.members.len(), 9, "8 keys of a and b's one");
    let st = w.pv.verify(state(&w, &s, &wraps)).await.unwrap();
    let u = w.pv.unlock(&w.me, st, &Passphrase::Off).await.unwrap();
    let mut more: Vec<MemberKey> = (1..=9).map(|k| key(w.a, k)).collect();
    more.push(key(w.b, 1));
    w.seam.calls.lock().unwrap().clear();
    let r = w.pv.rekey(&u, &more, &[w.a], None, Link::None).await;
    assert!(matches!(r, Err(Error::Shape)), "a rekey's ninth key");
    assert!(w.seam.calls.lock().unwrap().is_empty());
}

/// Rights stay per UA: a member's added key is no new member (the rekey is not weaker), a new UA is; the admin right is the
/// UA's, whichever key; a removal names the UA, every key of it.
#[tokio::test(flavor = "multi_thread")]
async fn rights_stay_per_ua() {
    let _one = ONE.lock().await;
    let w = world().await;
    let (s, wraps) =
        w.pv.create_vault(
            &w.me,
            &info(),
            &[key(w.a, 1), key(w.b, 1)],
            &at(),
            Mode::Portable,
            &Passphrase::Off,
        )
        .await
        .unwrap();
    let st = w.pv.verify(state(&w, &s, &wraps)).await.unwrap();
    let u = w.pv.unlock(&w.me, st, &Passphrase::Off).await.unwrap();
    let (e, ew, x) =
        w.pv.rekey(
            &u,
            &[key(w.a, 1), key(w.b, 1), key(w.b, 2)],
            &[w.a],
            None,
            Link::None,
        )
        .await
        .unwrap();
    assert_eq!(keys_of(&e.record.members), {
        let mut v = vec![(w.a, 1), (w.b, 1), (w.b, 2)];
        v.sort();
        v
    });
    assert_eq!(ew.len(), 3);
    assert!(!x.weaker, "b's second key: no new member");
    let (_, _, x) =
        w.pv.rekey(
            &u,
            &[key(w.a, 1), key(w.b, 1), key(w.c, 1)],
            &[w.a],
            None,
            Link::None,
        )
        .await
        .unwrap();
    assert!(x.weaker, "the control: c is a new member");
    // the admin right is a's (the UA), a removal names b's UA once
    let (r, _) = w.pv.remove(&u, &[w.b, w.b]).await.unwrap();
    assert_eq!(r.record.members, vec![w.b]);
    assert_eq!(r.record.admin, w.a);
}
