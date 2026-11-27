// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Owner (M) 2026-11-23 (CTR-CHAT-24, PqVault on the shared base): a member UA may hold several of its own KEM keys in an epoch,
//! members strictly ascending by `(ua, keyId)`, one wrap each, at most 8 keys per UA. `pqvault-core` keeps every key a caller
//! names (sorted, a repeated `(ua, keyId)` once), refuses a ninth key of one UA before any SDK call, opens each own key's
//! wrap, and reads rights per UA (a member's added key is no new member). Offline: a seam that wraps to the repository seed's
//! KEM keys and signs with a dummy signer, counting its signing calls (CLI-SDK-36: nothing is signed before the confirm).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

use pqvault_core::records::*;
use pqvault_core::{
    keys, EpochState, Error, Field, Instance, Item, ItemVersion, Link, Mode, Net, Passphrase,
    PqVault, Prepared, VaultInfo, VaultState,
};
use scaas_sdk::app_core::{
    AppCall, AppCore, AppKey, AppPath, AppQuote, AppSigned, AppWrap, SecretBytes,
};
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
/// (`kemKeyAt` as the registry answers it), every signature accepted and a dummy signer; each wrap's `(ua, keyId)` recorded,
/// each signing call and each quote counted, each prepared call's arguments kept (its answer an empty call).
struct Seam {
    core: Arc<AppCore>,
    kem: Vec<(B32, u64, Vec<u8>)>,
    calls: Mutex<Vec<(B32, u64)>>,
    signs: Mutex<u32>,
    quotes: Mutex<u32>,
    called: Mutex<Vec<Value>>,
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
        let mut n = self.signs.lock().unwrap();
        *n += 1;
        Ok(AppSigned {
            key_data: vec![],
            signature: vec![1, u8::try_from(*n).unwrap()],
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
        chain: &str,
        _: Addr,
        _: &str,
        args: Value,
        payer: KeyRef,
    ) -> Result<AppCall, SdkError> {
        self.called.lock().unwrap().push(args);
        Ok(AppCall {
            review: vec![],
            quote: scaas_sdk::wallet::NativeQuote {
                key: payer.clone(),
                chain: chain.into(),
                from: String::new(),
                to: String::new(),
                value: "0".into(),
                data: String::new(),
                quote: scaas_sdk::op::SubmitQuote {
                    path: scaas_sdk::op::SubmitPath::SelfRelay { payer },
                    payer: None,
                    gas_limit: 0,
                    regular_gas: 0,
                    gas: None,
                    gas_from: None,
                    max_fee_per_gas: "0".into(),
                    max_priority_fee_per_gas: "0".into(),
                    max_cost: "0".into(),
                    fee_to_relayer: "0".into(),
                    gateways: vec![],
                    tx_nonce: 0,
                    tx_type: 2,
                },
                delegated: false,
            },
        })
    }
    async fn quote(
        &self,
        _: &str,
        _: Addr,
        _: &str,
        _: Value,
        _: KeyRef,
        _: KeyRef,
    ) -> Result<AppQuote, SdkError> {
        *self.quotes.lock().unwrap() += 1;
        Ok(AppQuote {
            review: vec![],
            quote: None,
        })
    }
}

static ONE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct World {
    pv: PqVault,
    seam: Arc<Seam>,
    core: Arc<AppCore>,
    me: KeyRef,
    payer: KeyRef,
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
        signs: Mutex::new(0),
        quotes: Mutex::new(0),
        called: Mutex::new(vec![]),
    });
    let pv = PqVault::with_net(sdk, core.clone(), seam.clone());
    let me = PqVault::vault_key(&seed, 1);
    assert_eq!(pv.ua(&me).unwrap(), uas[0]);
    let payer = KeyRef::Native {
        seed: seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    World {
        pv,
        seam,
        core,
        me,
        payer,
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

/// The state a node would answer for the vault `p` creates (epoch 0 only, the seam's verifier accepts any signature), the
/// user's own wraps by member index.
fn state(w: &World, p: &Prepared<VaultCreate>) -> VaultState {
    let (c, wraps) = (&p.record, &p.wraps);
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
            sig: UaSig::default(),
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
    let s =
        w.pv.create_vault(
            &w.me,
            &info(),
            &given,
            &at(),
            Mode::Portable,
            &Passphrase::Off,
            w.payer.clone(),
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
        s.wraps
            .iter()
            .map(|x| (x.member, x.key_id.0))
            .collect::<Vec<_>>(),
        want
    );
    let st = w.pv.verify(state(&w, &s)).await.unwrap();
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
    let theirs = s.wraps.iter().find(|x| x.member == w.b).unwrap();
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
            w.payer.clone(),
        )
        .await;
    assert!(matches!(r, Err(Error::Shape)), "{:?}", r.err());
    assert!(
        w.seam.calls.lock().unwrap().is_empty(),
        "no wrap before the refusal"
    );
    nine.remove(8);
    let s =
        w.pv.create_vault(
            &w.me,
            &info(),
            &nine,
            &at(),
            Mode::Portable,
            &Passphrase::Off,
            w.payer.clone(),
        )
        .await
        .unwrap();
    assert_eq!(s.record.members.len(), 9, "8 keys of a and b's one");
    let st = w.pv.verify(state(&w, &s)).await.unwrap();
    let u = w.pv.unlock(&w.me, st, &Passphrase::Off).await.unwrap();
    let mut more: Vec<MemberKey> = (1..=9).map(|k| key(w.a, k)).collect();
    more.push(key(w.b, 1));
    w.seam.calls.lock().unwrap().clear();
    let r =
        w.pv.rekey(&u, &more, &[w.a], None, Link::None, w.payer.clone())
            .await;
    assert!(matches!(r, Err(Error::Shape)), "a rekey's ninth key");
    assert!(w.seam.calls.lock().unwrap().is_empty());
}

/// Rights stay per UA: a member's added key is no new member (the rekey is not weaker), a new UA is; the admin right is the
/// UA's, whichever key; a removal names the UA, every key of it.
#[tokio::test(flavor = "multi_thread")]
async fn rights_stay_per_ua() {
    let _one = ONE.lock().await;
    let w = world().await;
    let s =
        w.pv.create_vault(
            &w.me,
            &info(),
            &[key(w.a, 1), key(w.b, 1)],
            &at(),
            Mode::Portable,
            &Passphrase::Off,
            w.payer.clone(),
        )
        .await
        .unwrap();
    let st = w.pv.verify(state(&w, &s)).await.unwrap();
    let u = w.pv.unlock(&w.me, st, &Passphrase::Off).await.unwrap();
    let (e, x) =
        w.pv.rekey(
            &u,
            &[key(w.a, 1), key(w.b, 1), key(w.b, 2)],
            &[w.a],
            None,
            Link::None,
            w.payer.clone(),
        )
        .await
        .unwrap();
    assert_eq!(keys_of(&e.record.members), {
        let mut v = vec![(w.a, 1), (w.b, 1), (w.b, 2)];
        v.sort();
        v
    });
    assert_eq!(e.wraps.len(), 3);
    assert!(!x.weaker, "b's second key: no new member");
    let (_, x) =
        w.pv.rekey(
            &u,
            &[key(w.a, 1), key(w.b, 1), key(w.c, 1)],
            &[w.a],
            None,
            Link::None,
            w.payer.clone(),
        )
        .await
        .unwrap();
    assert!(x.weaker, "the control: c is a new member");
    // the admin right is a's (the UA), a removal names b's UA once
    let (r, _) = w.pv.remove(&u, &[w.b, w.b], w.payer.clone()).await.unwrap();
    assert_eq!(r.record.members, vec![w.b]);
    assert_eq!(r.record.admin, w.a);
}

fn signs(w: &World) -> u32 {
    *w.seam.signs.lock().unwrap()
}

/// Two prepared twins of one write, `n` signing calls before either was prepared: preparing signed nothing, the dropped
/// review signs nothing, its confirmed twin signs once and its call carries that signature.
async fn dropped_then_confirmed<R: pqvault_core::records::Record>(
    w: &World,
    n: u32,
    dropped: Prepared<R>,
    kept: Prepared<R>,
    what: &str,
) -> Signed<R> {
    assert_eq!(signs(w), n, "{what}: prepared, nothing signed");
    drop(dropped);
    assert_eq!(signs(w), n, "{what}: a review left signs nothing");
    let (s, _) = w.pv.confirm(kept).await.unwrap();
    assert_eq!(signs(w), n + 1, "{what}: the confirm signs once");
    let last = w.seam.called.lock().unwrap().last().cloned().unwrap();
    assert_eq!(
        last["sig"]["signature"],
        json!(hex(&s.sig.signature)),
        "{what}: its call carries that signature"
    );
    s
}

/// CLI-SDK-36 (rule 23): every write of `pqvault-core` is built for its review and quoted without a signing call; a review
/// left makes zero signing calls, its confirmed twin one. A vault, an item, an edit, a tombstone, a batch, a share (a rekey
/// adding a member), a passphrase change, a removal, a leave, an accept and a decline.
#[tokio::test(flavor = "multi_thread")]
async fn nothing_is_signed_before_the_confirm() {
    let _one = ONE.lock().await;
    let w = world().await;
    let pay = || w.payer.clone();
    let off = Passphrase::Off;
    let members = [key(w.a, 1), key(w.b, 1)];
    let (vi, here) = (info(), at());
    let mk = || {
        w.pv.create_vault(&w.me, &vi, &members, &here, Mode::Portable, &off, pay())
    };
    let (a, b) = (mk().await.unwrap(), mk().await.unwrap());
    let st = w.pv.verify(state(&w, &b)).await.unwrap();
    assert_eq!(
        *w.seam.quotes.lock().unwrap(),
        2,
        "each prepared write quoted"
    );
    dropped_then_confirmed(&w, 0, a, b, "a vault").await;
    let u = w.pv.unlock(&w.me, st.clone(), &off).await.unwrap();
    let mut login = Item::new("login");
    login
        .set("title", Field::Plain(json!("mail")))
        .set("password", Field::secret(b"correct-horse").unwrap());
    let n = signs(&w);
    let (a, b) = (
        w.pv.create_item(&u, &login, pay()).await.unwrap(),
        w.pv.create_item(&u, &login, pay()).await.unwrap(),
    );
    let created = dropped_then_confirmed(&w, n, a, b, "an item").await;
    let base = ItemVersion {
        item_id: item_id(st.vault_id, w.a, created.record.nonce.0),
        version: 1,
        version_count: 1,
        epoch_id: st.vault_id,
        author: w.a,
        value: Ok(login.clone()),
    };
    let n = signs(&w);
    let (a, b) = (
        w.pv.edit_item(&u, &base, &login, pay()).await.unwrap(),
        w.pv.edit_item(&u, &base, &login, pay()).await.unwrap(),
    );
    dropped_then_confirmed(&w, n, a, b, "an edit").await;
    let n = signs(&w);
    let tomb = Item::deleted();
    let (a, b) = (
        w.pv.edit_item(&u, &base, &tomb, pay()).await.unwrap(),
        w.pv.edit_item(&u, &base, &tomb, pay()).await.unwrap(),
    );
    dropped_then_confirmed(&w, n, a, b, "a tombstone").await;
    let limits = pqvault_core::ChainLimits {
        max_gas: 30_000_000,
        base_gas: 400_000,
        item_gas: 150_000,
        byte_gas: 700,
    };
    let n = signs(&w);
    let two = [login.clone(), login.clone()];
    let mut a = w.pv.create_items(&u, &two, &limits, pay()).await.unwrap();
    let mut b = w.pv.create_items(&u, &two, &limits, pay()).await.unwrap();
    assert_eq!((a.len(), b.len()), (1, 1));
    dropped_then_confirmed(&w, n, a.remove(0), b.remove(0), "a batch").await;
    let n = signs(&w);
    let share = [key(w.a, 1), key(w.b, 1), key(w.c, 1)];
    let admins = [w.a];
    let rk = || w.pv.rekey(&u, &share, &admins, None, Link::Prev, pay());
    let ((a, x), (b, _)) = (rk().await.unwrap(), rk().await.unwrap());
    assert!(x.weaker, "a share adds a member");
    dropped_then_confirmed(&w, n, a, b, "a share").await;
    let n = signs(&w);
    let pass = Passphrase::On(sec("a new vault passphrase".as_bytes()));
    let ch = || {
        w.pv.rekey(&u, &members, &admins, Some(&pass), Link::Prev, pay())
    };
    let ((a, _), (b, _)) = (ch().await.unwrap(), ch().await.unwrap());
    dropped_then_confirmed(&w, n, a, b, "a passphrase change").await;
    let n = signs(&w);
    let ((a, _), (b, _)) = (
        w.pv.remove(&u, &[w.b], pay()).await.unwrap(),
        w.pv.remove(&u, &[w.b], pay()).await.unwrap(),
    );
    dropped_then_confirmed(&w, n, a, b, "a removal").await;
    let n = signs(&w);
    let (a, b) = (
        w.pv.leave(&u, pay()).await.unwrap(),
        w.pv.leave(&u, pay()).await.unwrap(),
    );
    dropped_then_confirmed(&w, n, a, b, "a leave").await;
    for yes in [true, false] {
        let n = signs(&w);
        let (a, b) = (
            w.pv.accept(&u, &st, yes, None, pay()).await.unwrap(),
            w.pv.accept(&u, &st, yes, None, pay()).await.unwrap(),
        );
        dropped_then_confirmed(&w, n, a, b, if yes { "an accept" } else { "a decline" }).await;
    }
}
