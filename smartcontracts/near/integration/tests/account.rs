//! Task 5 (spec §3.3, §3.5; R7): subject accounts in the token — SCaaS key records, signatures (ed25519 NEP-413,
//! secp256k1 `ecrecover`, P-256 passkey), key ops, recovery, msig. Needs `smartcontracts/scripts/build.sh near` first.
//! One sandbox per test. Signers are generated here (the op digest binds the dev-deployed token id).
use near_contract_standards::fungible_token::metadata::{FungibleTokenMetadata, FT_METADATA_SPEC};
use near_workspaces::network::Sandbox;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Finality, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, AccountId, Contract, Worker};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use scaas_near_common::hash::nep413_hash;
use scaas_near_common::metaop::*;
use scaas_near_common::ua::{self, KeyRecord, KIND_ED25519, KIND_MSIG, KIND_NEAR_ACCOUNT};
use scaas_near_common::webauthn::b64url;
use scaas_near_common::{Auth, Holder};
use scaas_near_token::{record_bytes, Check, Subject, RECOVERY_DELAY_S};
use sha2::{Digest, Sha256};

const TOKEN_WASM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/near/scaas_near_token/scaas_near_token.wasm");
const NETWORK: [u8; 32] = [0x22; 32];
const VU: u64 = 4_102_444_800;
const RP: &str = "pay.scaas.test";
const ORIGIN: &str = "https://pay.scaas.test";

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn b<T: borsh::BorshSerialize>(x: &T) -> Vec<u8> {
    borsh::to_vec(x).unwrap()
}

/// A SCaaS key: ed25519, secp256k1 (near-crypto) or a P-256 passkey of `rp`.
enum Signer {
    Ed(near_crypto::SecretKey),
    K1(near_crypto::SecretKey),
    Pk(p256::ecdsa::SigningKey, String),
}

impl Signer {
    fn ed(seed: &str) -> Self {
        Signer::Ed(near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, seed))
    }
    fn k1(seed: &str) -> Self {
        Signer::K1(near_crypto::SecretKey::from_seed(near_crypto::KeyType::SECP256K1, seed))
    }
    fn pk(seed: u8, rp: &str) -> Self {
        Signer::Pk(p256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap(), rp.into())
    }
    fn raw(&self) -> Vec<u8> {
        match self {
            Signer::Ed(k) | Signer::K1(k) => b(&k.public_key())[1..].to_vec(),
            Signer::Pk(k, _) => k.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec(),
        }
    }
    fn key(&self) -> KeyRecord {
        match self {
            Signer::Ed(_) => KeyRecord { kind: ua::KIND_ED25519, key_data: self.raw() },
            Signer::K1(_) => KeyRecord { kind: ua::KIND_SECP256K1, key_data: self.raw() },
            Signer::Pk(_, rp) => {
                KeyRecord { kind: ua::KIND_WEBAUTHN_P256, key_data: [self.raw(), sha(rp.as_bytes()).to_vec()].concat() }
            }
        }
    }
    fn ua(&self) -> Holder {
        Holder::Ua(self.key().id())
    }
    /// The auth for `op` (passkey assertions from `origin`).
    fn sign(&self, op: &MetaOp, origin: &str) -> Auth {
        let digest = op.digest();
        match self {
            Signer::Ed(k) => Auth::Ed25519 {
                key: self.raw().try_into().unwrap(),
                sig: b(&k.sign(&nep413_hash(&digest, &op.contract)))[1..].try_into().unwrap(),
            },
            Signer::K1(k) => {
                let s = b(&k.sign(&digest))[1..].to_vec();
                Auth::Secp256k1 { key: self.raw().try_into().unwrap(), sig: s[..64].try_into().unwrap(), v: s[64] }
            }
            Signer::Pk(k, rp) => {
                let ad = [&sha(rp.as_bytes())[..], &[0x05, 0, 0, 0, 0]].concat();
                let cdj = format!(
                    r#"{{"type":"webauthn.get","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
                    b64url(&digest)
                );
                let sig: p256::ecdsa::Signature = k.sign_prehash(&sha(&[&ad[..], &sha(cdj.as_bytes())].concat())).unwrap();
                Auth::Passkey {
                    key: self.raw().try_into().unwrap(),
                    authenticator_data: ad,
                    client_data_json: cdj.into_bytes(),
                    sig: sig.normalize_s().unwrap_or(sig).to_bytes().into(),
                }
            }
        }
    }
}

struct T {
    w: Worker<Sandbox>,
    token: Contract,
    relayer: Account,
    alice: Account,
    bob: Account,
}

async fn setup() -> T {
    let w = near_workspaces::sandbox().await.unwrap();
    let token = w.dev_deploy(&std::fs::read(TOKEN_WASM).expect("run build.sh near first")).await.unwrap();
    let meta = FungibleTokenMetadata {
        spec: FT_METADATA_SPEC.into(),
        name: "SCaaS Test".into(),
        symbol: "SCT".into(),
        icon: None,
        reference: None,
        reference_hash: None,
        decimals: 6,
    };
    let args = b(&(NETWORK, token.id().to_string(), meta));
    token.call("new").args(args).transact().await.unwrap().into_result().unwrap();
    let relayer = w.dev_create_account().await.unwrap();
    let alice = w.dev_create_account().await.unwrap();
    let bob = w.dev_create_account().await.unwrap();
    T { w, token, relayer, alice, bob }
}

fn tgas(out: &ExecutionFinalResult) -> f64 {
    out.total_gas_burnt.as_gas() as f64 / 1e12
}

impl T {
    fn id(&self) -> AccountId {
        self.token.id().clone()
    }

    fn near(&self, a: &Account) -> Holder {
        Holder::Near(a.id().as_str().parse().unwrap())
    }

    /// A key op (codes 6–12) of `from` at key nonce `nonce`, `extra = sha256(params)`.
    fn op(&self, code: u8, from: &Holder, to: &Holder, nonce: u64, params: &[u8]) -> MetaOp {
        MetaOp {
            network: NETWORK,
            contract: self.id().as_str().parse().unwrap(),
            op: code,
            from: from.clone(),
            to: to.clone(),
            relayer: None,
            amount: 0,
            pay_ref: [0; 32],
            lane: [0; 32],
            nonce,
            valid_until: VU,
            extra: sha(params),
        }
    }

    async fn check(&self, caller: &Account, entry: &str, op: &MetaOp, auth: &Auth, params: &[u8]) -> Check {
        let args = [b(&caller.id().as_str()), b(op), b(auth), params.to_vec()].concat();
        self.token.view(&format!("{entry}_check")).args(args).await.unwrap().borsh().unwrap()
    }

    async fn call(&self, who: &Account, entry: &str, args: Vec<u8>, yocto: u128) -> ExecutionFinalResult {
        let out = who
            .call(self.token.id(), entry)
            .args(args)
            .deposit(NearToken::from_yoctonear(yocto))
            .max_gas()
            .transact()
            .await
            .unwrap();
        println!("{entry} by {}: {:.3} Tgas, ok {}", who.id(), tgas(&out), out.is_success());
        out
    }

    /// `entry_check` (caller = `who`) then the entry with exactly `storage_needed` attached.
    async fn exec(&self, who: &Account, entry: &str, op: &MetaOp, auth: &Auth, params: &[u8]) -> (Check, ExecutionFinalResult) {
        let c = self.check(who, entry, op, auth, params).await;
        let out = self.call(who, entry, [b(op), b(auth), params.to_vec()].concat(), c.storage_needed.0).await;
        (c, out)
    }

    /// `exec` that must succeed with no error in its check.
    async fn ok(&self, who: &Account, entry: &str, op: &MetaOp, auth: &Auth, params: &[u8]) -> Check {
        let (c, out) = self.exec(who, entry, op, auth, params).await;
        assert_eq!(c.error, None, "{entry}");
        assert!(out.is_success(), "{entry}: {:?}", out.failures());
        c
    }

    /// The check reports `err` and the entry panics with it.
    async fn refused(&self, who: &Account, entry: &str, op: &MetaOp, auth: &Auth, params: &[u8], err: &str) {
        let (c, out) = self.exec(who, entry, op, auth, params).await;
        assert!(c.error.as_deref().is_some_and(|e| e.contains(err)), "{entry}: check {:?}, want {err}", c.error);
        assert!(out.is_failure() && format!("{:?}", out.failures()).contains(err), "{entry}: {:?}", out.failures());
    }

    async fn subject(&self, h: &Holder) -> Option<Subject> {
        self.token.view("subject").args(b(h)).await.unwrap().borsh().unwrap()
    }

    async fn byte_cost(&self) -> u128 {
        let cfg = self.w.protocol_config(Finality::Final.into()).await.unwrap();
        cfg.runtime_config.storage_amount_per_byte.as_yoctonear()
    }

    async fn usage(&self) -> u64 {
        self.token.view_account().await.unwrap().storage_usage
    }

    async fn now_s(&self) -> u64 {
        self.w.view_block().await.unwrap().timestamp() / 1_000_000_000
    }

    /// `mtx_set_guardian(guardian)` signed by `s` for `from` at `nonce`.
    async fn set_guardian(&self, who: &Account, s: &Signer, from: &Holder, nonce: u64, g: Option<Holder>) -> Check {
        let p = b(&g);
        let op = self.op(OP_SET_GUARDIAN, from, from, nonce, &p);
        self.ok(who, "mtx_set_guardian", &op, &s.sign(&op, ORIGIN), &p).await
    }
}

#[tokio::test]
async fn ua_opened_lazily_relayer_pays_storage() {
    let t = setup().await;
    let (erin, k2) = (Signer::ed("erin"), Signer::ed("erin-2").key());
    let h = erin.ua();
    assert_eq!(t.subject(&h).await, None);
    let p = b(&(k2.clone(), None::<String>));
    let op = t.op(OP_ADD_KEY, &h, &h, 0, &p);
    let auth = erin.sign(&op, ORIGIN);
    let c = t.check(&t.relayer, "mtx_add_key", &op, &auth, &p).await;
    let want = Subject { keys: vec![erin.key(), k2.clone()], key_nonce: 1, ..Default::default() };
    let bytes = record_bytes(&h, &want);
    // near-vectors.json storage.records.subjectEd25519Ua (one key) and +38 B per ed25519 key
    assert_eq!(record_bytes(&h, &Subject { keys: vec![erin.key()], ..Default::default() }), 130);
    assert_eq!(bytes, 168);
    let cost = t.byte_cost().await;
    println!("ed25519 UA opened by mtx_add_key, 2 keys: {bytes} B record = {} yocto", bytes as u128 * cost);
    assert_eq!(c, Check { error: None, storage_needed: (bytes as u128 * cost).into() });

    let args = [b(&op), b(&auth), p.clone()].concat();
    let short = t.call(&t.relayer, "mtx_add_key", args.clone(), c.storage_needed.0 - 1).await;
    assert!(format!("{:?}", short.failures()).contains("attached deposit is less"), "{:?}", short.failures());
    let excess = NearToken::from_near(1).as_yoctonear();
    let (u0, before) = (t.usage().await, t.relayer.view_account().await.unwrap().balance.as_yoctonear());
    let out = t.call(&t.relayer, "mtx_add_key", args.clone(), c.storage_needed.0 + excess).await;
    assert!(out.is_success(), "{:?}", out.failures());
    let spent = before - t.relayer.view_account().await.unwrap().balance.as_yoctonear();
    assert_eq!(t.usage().await - u0, bytes, "measured record bytes");
    assert!(spent >= c.storage_needed.0 && spent < c.storage_needed.0 + excess / 20, "excess not refunded: {spent}");
    assert!(out.logs().iter().any(|l| l.contains(r#""event":"key_op""#) && l.contains("add_key")));
    assert_eq!(t.subject(&h).await, Some(want));

    // replay refused; the next op needs no deposit (the record does not grow)
    let replay = t.call(&t.relayer, "mtx_add_key", args, c.storage_needed.0).await;
    assert!(format!("{:?}", replay.failures()).contains("wrong key nonce"));
    let p = b(&k2);
    let op = t.op(OP_REMOVE_KEY, &h, &h, 1, &p);
    let c = t.ok(&t.relayer, "mtx_remove_key", &op, &erin.sign(&op, ORIGIN), &p).await;
    assert_eq!(c.storage_needed.0, 0);
    assert_eq!(t.subject(&h).await.unwrap().keys, vec![erin.key()]);
}

#[tokio::test]
async fn ed25519_secp256k1_passkey_each_accepted() {
    let t = setup().await;
    let cost = t.byte_cost().await;
    let bob = t.near(&t.bob);
    for (name, s) in [("ed25519", Signer::ed("erin")), ("secp256k1", Signer::k1("carol")), ("passkey", Signer::pk(4, RP))] {
        let h = s.ua();
        let u0 = t.usage().await;
        let c = t.set_guardian(&t.relayer, &s, &h, 0, Some(bob.clone())).await;
        let bytes = t.usage().await - u0;
        println!("{name} UA opened by mtx_set_guardian: record {bytes} B, storage_needed {}", c.storage_needed.0);
        assert_eq!(c.storage_needed.0, bytes as u128 * cost, "{name}");
        let got = t.subject(&h).await.unwrap();
        assert_eq!((got.keys, got.guardian.clone(), got.key_nonce), (vec![s.key()], Some(bob.clone()), 1), "{name}");
        assert_eq!(got.origins, if name == "passkey" { vec![ORIGIN.to_string()] } else { vec![] });
        // the existing record's path
        let c = t.set_guardian(&t.relayer, &s, &h, 1, None).await;
        assert_eq!(c.storage_needed.0, 0);
        assert_eq!(t.subject(&h).await.unwrap().guardian, None);
    }
}

#[tokio::test]
async fn secp256k1_high_s_refused() {
    let t = setup().await;
    let carol = Signer::k1("carol");
    let h = carol.ua();
    let p = b(&None::<Holder>);
    let op = t.op(OP_SET_GUARDIAN, &h, &h, 0, &p);
    let Auth::Secp256k1 { key, sig, v } = carol.sign(&op, ORIGIN) else { unreachable!() };
    // s' = n - s, v' = v ^ 1: the same point, the malleated form
    let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap();
    let mut high = sig;
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = n[i] as i16 - sig[32 + i] as i16 - borrow;
        high[32 + i] = d.rem_euclid(256) as u8;
        borrow = (d < 0) as i16;
    }
    let bad = Auth::Secp256k1 { key, sig: high, v: v ^ 1 };
    t.refused(&t.relayer, "mtx_set_guardian", &op, &bad, &p, "secp256k1 signature").await;
    t.ok(&t.relayer, "mtx_set_guardian", &op, &Auth::Secp256k1 { key, sig, v }, &p).await;
}

#[tokio::test]
async fn ninth_key_refused() {
    let t = setup().await;
    let alice = t.near(&t.alice);
    let keys: Vec<Signer> = (0..9).map(|i| Signer::ed(&format!("alice-{i}"))).collect();
    let dep = NearToken::from_millinear(100).as_yoctonear();
    for k in &keys[..8] {
        let out = t.call(&t.alice, "add_key_native", b(&(k.key(), None::<String>)), dep).await;
        assert!(out.is_success(), "{:?}", out.failures());
    }
    let out = t.call(&t.alice, "add_key_native", b(&(keys[8].key(), None::<String>)), dep).await;
    assert!(format!("{:?}", out.failures()).contains("MAX_KEYS"), "{:?}", out.failures());
    let p = b(&(keys[8].key(), None::<String>));
    let op = t.op(OP_ADD_KEY, &alice, &alice, 0, &p);
    t.refused(&t.relayer, "mtx_add_key", &op, &keys[0].sign(&op, ORIGIN), &p, "MAX_KEYS").await;
    let got = t.subject(&alice).await.unwrap();
    assert_eq!(got.keys, keys[..8].iter().map(Signer::key).collect::<Vec<_>>());
    println!("Near holder record, 8 ed25519 keys: {} B", record_bytes(&alice, &got));
    // a Near holder's key signs as the account (relayed)
    t.set_guardian(&t.relayer, &keys[7], &alice, 0, Some(t.near(&t.bob))).await;
}

#[tokio::test]
async fn origin_and_rp_checked() {
    let t = setup().await;
    let dave = Signer::pk(4, RP);
    let h = dave.ua();
    let other = "https://app.scaas.test";
    t.set_guardian(&t.relayer, &dave, &h, 0, None).await; // opened at ORIGIN
    let p = b(&None::<Holder>);
    let op = t.op(OP_SET_GUARDIAN, &h, &h, 1, &p);
    t.refused(&t.relayer, "mtx_set_guardian", &op, &dave.sign(&op, other), &p, "clientDataJSON").await;
    let po = b(&other.to_string());
    let add = t.op(OP_ADD_ORIGIN, &h, &h, 1, &po);
    t.ok(&t.relayer, "mtx_add_origin", &add, &dave.sign(&add, ORIGIN), &po).await;
    let op = t.op(OP_SET_GUARDIAN, &h, &h, 2, &p);
    t.ok(&t.relayer, "mtx_set_guardian", &op, &dave.sign(&op, other), &p).await;
    assert_eq!(t.subject(&h).await.unwrap().origins, vec![ORIGIN.to_string(), other.to_string()]);
    // the same key under another rpId is another key: not this subject's, and it does not derive this id
    let evil = Signer::pk(4, "evil.test");
    let op = t.op(OP_SET_GUARDIAN, &h, &h, 3, &p);
    t.refused(&t.relayer, "mtx_set_guardian", &op, &evil.sign(&op, ORIGIN), &p, "not a key of the subject").await;
    let fresh = Signer::pk(5, RP).ua();
    let op = t.op(OP_SET_GUARDIAN, &fresh, &fresh, 0, &p);
    t.refused(&t.relayer, "mtx_set_guardian", &op, &Signer::pk(5, "evil.test").sign(&op, ORIGIN), &p, "does not derive")
        .await;
    // removing the last origin of a passkey subject is refused
    let pr = b(&ORIGIN.to_string());
    let rm = t.op(OP_REMOVE_ORIGIN, &h, &h, 3, &pr);
    t.ok(&t.relayer, "mtx_remove_origin", &rm, &dave.sign(&rm, other), &pr).await;
    let pr = b(&other.to_string());
    let rm = t.op(OP_REMOVE_ORIGIN, &h, &h, 4, &pr);
    t.refused(&t.relayer, "mtx_remove_origin", &rm, &dave.sign(&rm, other), &pr, "a passkey needs an origin").await;
}

/// `erin` (key nonce 1 after this) with guardian `g` (a UA); `g` starts recovery to `frank` (a stranger cannot).
async fn recovery_setup() -> (T, Signer, Signer, Signer) {
    let t = setup().await;
    let (erin, g, frank) = (Signer::ed("erin"), Signer::ed("guardian"), Signer::ed("frank"));
    t.set_guardian(&t.relayer, &erin, &erin.ua(), 0, Some(g.ua())).await;
    // not the guardian
    let p = b(&(frank.key(), None::<String>));
    let mallory = Signer::ed("mallory");
    let op = t.op(OP_START_RECOVERY, &mallory.ua(), &erin.ua(), 0, &p);
    t.refused(&t.relayer, "mtx_start_recovery", &op, &mallory.sign(&op, ORIGIN), &p, "not the subject's guardian").await;
    let op = t.op(OP_START_RECOVERY, &g.ua(), &erin.ua(), 0, &p);
    t.ok(&t.relayer, "mtx_start_recovery", &op, &g.sign(&op, ORIGIN), &p).await;
    (t, erin, g, frank)
}

#[tokio::test]
async fn recovery_after_delay_only() {
    let (t, erin, _g, frank) = recovery_setup().await;
    let h = erin.ua();
    let now = t.now_s().await;
    let mut s = t.subject(&h).await.unwrap();
    let r = s.recovery.clone().unwrap();
    assert_eq!(r.key, frank.key());
    assert!(r.ready_at > now + RECOVERY_DELAY_S - 30 && r.ready_at <= now + RECOVERY_DELAY_S, "ready_at {}", r.ready_at);
    let out = t.call(&t.bob, "finish_recovery", b(&h), 0).await;
    assert!(format!("{:?}", out.failures()).contains("recovery delay"), "{:?}", out.failures());
    // 172,800 s pass (the sandbox clock cannot jump two days): the stored ready_at moves back by the delay
    s.recovery.as_mut().unwrap().ready_at -= RECOVERY_DELAY_S;
    t.w.patch_state(t.token.id(), &[b"a".as_slice(), &b(&h)].concat(), &b(&s)).await.unwrap();
    let out = t.call(&t.bob, "finish_recovery", b(&h), 0).await;
    assert!(out.is_success(), "{:?}", out.failures());
    let got = t.subject(&h).await.unwrap();
    assert_eq!((got.keys, got.recovery, got.key_nonce), (vec![frank.key()], None, 2));
    let p = b(&None::<Holder>);
    let op = t.op(OP_SET_GUARDIAN, &h, &h, 2, &p);
    t.refused(&t.relayer, "mtx_set_guardian", &op, &erin.sign(&op, ORIGIN), &p, "not a key of the subject").await;
    t.ok(&t.relayer, "mtx_set_guardian", &op, &frank.sign(&op, ORIGIN), &p).await;
}

#[tokio::test]
async fn cancel_recovery_by_key() {
    let (t, erin, _g, _frank) = recovery_setup().await;
    let h = erin.ua();
    let op = t.op(OP_CANCEL_RECOVERY, &h, &h, 1, &[]);
    t.ok(&t.relayer, "mtx_cancel_recovery", &op, &erin.sign(&op, ORIGIN), &[]).await;
    assert_eq!(t.subject(&h).await.unwrap().recovery, None);
    let out = t.call(&t.bob, "finish_recovery", b(&h), 0).await;
    assert!(format!("{:?}", out.failures()).contains("no recovery pending"), "{:?}", out.failures());
    let op = t.op(OP_CANCEL_RECOVERY, &h, &h, 2, &[]);
    t.refused(&t.relayer, "mtx_cancel_recovery", &op, &erin.sign(&op, ORIGIN), &[], "no recovery pending").await;
}

#[tokio::test]
async fn msig_native_member_only_as_predecessor() {
    let t = setup().await;
    let erin = Signer::ed("erin");
    let Holder::Ua(erin_id) = erin.ua() else { unreachable!() };
    let alice_id = ua::native_id(&t.alice.id().as_str().parse().unwrap());
    let mut members = [(KIND_NEAR_ACCOUNT, alice_id), (KIND_ED25519, erin_id)];
    members.sort_by_key(|m| m.1);
    // threshold 2, count 2, each member weight 1
    let body: Vec<u8> = members.iter().flat_map(|(k, i)| [&k.to_be_bytes()[..], i, &[0, 1]].concat()).collect();
    let kd = [&[0u8, 2, 0, 2][..], &body].concat();
    let ie = members.iter().position(|m| m.1 == erin_id).unwrap() as u8;
    let m = Holder::Ua(ua::ua_of(KIND_MSIG, &kd));
    let p = b(&None::<Holder>);
    let op = t.op(OP_SET_GUARDIAN, &m, &m, 0, &p);
    let erin_sig = (ie, erin.sign(&op, ORIGIN));
    let only_erin = Auth::Msig { key_data: kd.clone(), sigs: vec![erin_sig.clone()] };
    // relayed: erin alone is below the threshold
    t.refused(&t.relayer, "mtx_set_guardian", &op, &only_erin, &p, "msig threshold not met").await;
    // alice's access key signature never counts for her member
    let ak: near_crypto::SecretKey = t.alice.secret_key().to_string().parse().unwrap();
    let a_auth = Auth::Ed25519 {
        key: b(&ak.public_key())[1..].try_into().unwrap(),
        sig: b(&ak.sign(&nep413_hash(&op.digest(), &op.contract)))[1..].try_into().unwrap(),
    };
    let mut both = vec![(1 - ie, a_auth), erin_sig];
    both.sort_by_key(|x| x.0);
    let forged = Auth::Msig { key_data: kd.clone(), sigs: both };
    t.refused(&t.relayer, "mtx_set_guardian", &op, &forged, &p, "counts only as the predecessor").await;
    // alice as the predecessor: her weight plus erin's signature
    let c = t.ok(&t.alice, "mtx_set_guardian", &op, &only_erin, &p).await;
    println!("msig UA (near-account + ed25519) opened: storage_needed {}", c.storage_needed.0);
    assert_eq!(t.subject(&m).await.unwrap().keys, vec![KeyRecord { kind: KIND_MSIG, key_data: kd.clone() }]);
    let op = t.op(OP_SET_GUARDIAN, &m, &m, 1, &p);
    let only_erin = Auth::Msig { key_data: kd, sigs: vec![(ie, erin.sign(&op, ORIGIN))] };
    t.refused(&t.relayer, "mtx_set_guardian", &op, &only_erin, &p, "msig threshold not met").await;
    t.ok(&t.alice, "mtx_set_guardian", &op, &only_erin, &p).await;
}

#[tokio::test]
async fn access_key_signature_never_accepted() {
    let t = setup().await;
    // an implicit account: its id is its ed25519 access key
    let sk = SecretKey::from_seed(KeyType::ED25519, "implicit");
    let nk: near_crypto::SecretKey = sk.to_string().parse().unwrap();
    let pk: [u8; 32] = b(&nk.public_key())[1..].try_into().unwrap();
    let id: AccountId = hex::encode(pk).parse().unwrap();
    let r = t.w.root_account().unwrap().transfer_near(&id, NearToken::from_near(10)).await.unwrap();
    assert!(r.is_success());
    let imp = Account::from_secret_key(id.clone(), sk, &t.w);
    assert_eq!(imp.view_access_keys().await.unwrap().len(), 1);
    let h = Holder::Near(id.as_str().parse().unwrap());
    let p = b(&None::<Holder>);
    let op = t.op(OP_SET_GUARDIAN, &h, &h, 0, &p);
    let own = Auth::Ed25519 { key: pk, sig: b(&nk.sign(&nep413_hash(&op.digest(), &op.contract)))[1..].try_into().unwrap() };
    for who in [&imp, &t.relayer] {
        t.refused(who, "mtx_set_guardian", &op, &own, &p, "no SCaaS key").await;
    }
    // nor as a UA id of the raw key (the ed25519 UA id is UA(0x0102, pk), not pk)
    let raw = Holder::Ua(pk);
    let op = t.op(OP_SET_GUARDIAN, &raw, &raw, 0, &p);
    let own = Auth::Ed25519 { key: pk, sig: b(&nk.sign(&nep413_hash(&op.digest(), &op.contract)))[1..].try_into().unwrap() };
    t.refused(&imp, "mtx_set_guardian", &op, &own, &p, "does not derive").await;
}

#[tokio::test]
async fn wrong_network_or_contract_refused() {
    let t = setup().await;
    let erin = Signer::ed("erin");
    let h = erin.ua();
    let p = b(&None::<Holder>);
    let base = t.op(OP_SET_GUARDIAN, &h, &h, 0, &p);
    let cases: [(&str, Box<dyn Fn(&mut MetaOp)>); 6] = [
        ("wrong network", Box::new(|o| o.network = [0x23; 32])),
        ("wrong contract", Box::new(|o| o.contract = "bob.test.near".parse().unwrap())),
        ("expired", Box::new(|o| o.valid_until = 1)),
        ("relayer is not the predecessor", Box::new(|o| o.relayer = Some("bob.test.near".parse().unwrap()))),
        ("extra is not sha256", Box::new(|o| o.extra = [0; 32])),
        ("key op shape", Box::new(|o| o.op = OP_REMOVE_KEY)),
    ];
    for (err, f) in cases {
        let mut op = base.clone();
        f(&mut op);
        t.refused(&t.relayer, "mtx_set_guardian", &op, &erin.sign(&op, ORIGIN), &p, err).await;
    }
    // bound to this relayer: accepted
    let mut op = base;
    op.relayer = Some(t.relayer.id().as_str().parse().unwrap());
    t.ok(&t.relayer, "mtx_set_guardian", &op, &erin.sign(&op, ORIGIN), &p).await;
}
