//! Task 5 (spec §3.3, §3.5; R7): subject accounts in the token — SCaaS key records, signatures (ed25519 NEP-413,
//! secp256k1 `ecrecover`, P-256 passkey), key ops, recovery, msig. Needs `smartcontracts/scripts/build.sh near` first.
//! One sandbox per test. Signers are generated here (the op digest binds the dev-deployed token id).
mod common;
use common::*;

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
    assert_eq!(record_bytes(&h, &Subject { keys: vec![erin.key()], ..Default::default() }), 131);
    assert_eq!(bytes, 169);
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

/// Final review m1 (as Aptos `EKEY_OP`): `mtx_add_origin` of an origin the subject already holds is refused (no charged
/// no-op); a new origin is added once, and adding it again is refused too.
#[tokio::test]
async fn add_origin_present_refused() {
    let t = setup().await;
    let dave = Signer::pk(4, RP);
    let h = dave.ua();
    t.set_guardian(&t.relayer, &dave, &h, 0, None).await; // opened at ORIGIN
    let present = "origin already present";
    let po = b(&ORIGIN.to_string());
    let add = t.op(OP_ADD_ORIGIN, &h, &h, 1, &po);
    t.refused(&t.relayer, "mtx_add_origin", &add, &dave.sign(&add, ORIGIN), &po, present).await;
    let other = "https://app.scaas.test";
    let po = b(&other.to_string());
    let add = t.op(OP_ADD_ORIGIN, &h, &h, 1, &po);
    t.ok(&t.relayer, "mtx_add_origin", &add, &dave.sign(&add, ORIGIN), &po).await;
    let add = t.op(OP_ADD_ORIGIN, &h, &h, 2, &po);
    t.refused(&t.relayer, "mtx_add_origin", &add, &dave.sign(&add, ORIGIN), &po, present).await;
    assert_eq!(t.subject(&h).await.unwrap().origins, vec![ORIGIN.to_string(), other.to_string()]);
    assert_eq!(t.subject(&h).await.unwrap().key_nonce, 2, "the refused ops consumed no key nonce");
}

/// `erin` (key nonce 1 after this) with guardian `g` (a UA, key nonce 1 after this); `g` starts recovery to
/// `frank` (a stranger cannot).
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

impl T {
    /// `mtx_finish_recovery` of `subject` signed by `by` at its key nonce `nonce`: op code 11, `extra` over the signed
    /// params `[KEYOP_FINISH_RECOVERY]`; the entry itself takes no arguments after `(op, auth)`.
    fn finish_op(&self, by: &Signer, subject: &Holder, nonce: u64) -> (MetaOp, Auth, Vec<u8>) {
        let op = self.op(OP_START_RECOVERY, &by.ua(), subject, nonce, &[KEYOP_FINISH_RECOVERY]);
        let a = by.sign(&op, ORIGIN);
        (op, a, vec![])
    }
}

#[tokio::test]
async fn recovery_after_delay_only() {
    let (t, erin, g, frank) = recovery_setup().await;
    let h = erin.ua();
    let now = t.now_s().await;
    let mut s = t.subject(&h).await.unwrap();
    let r = s.recovery.clone().unwrap();
    assert_eq!(r.key, frank.key());
    assert!(r.ready_at > now + RECOVERY_DELAY_S - 30 && r.ready_at <= now + RECOVERY_DELAY_S, "ready_at {}", r.ready_at);
    let (op, a, p) = t.finish_op(&g, &h, 1);
    t.refused(&t.relayer, "mtx_finish_recovery", &op, &a, &p, "recovery delay").await;
    // 172,800 s pass (the sandbox clock cannot jump two days): the stored ready_at moves back by the delay
    s.recovery.as_mut().unwrap().ready_at -= RECOVERY_DELAY_S;
    t.w.patch_state(t.token.id(), &[b"a".as_slice(), &b(&h)].concat(), &b(&s)).await.unwrap();
    // only the guardian finishes
    let (op, a, p) = t.finish_op(&Signer::ed("mallory"), &h, 0);
    t.refused(&t.relayer, "mtx_finish_recovery", &op, &a, &p, "not the subject's guardian").await;
    let (op, a, p) = t.finish_op(&g, &h, 1);
    t.ok(&t.relayer, "mtx_finish_recovery", &op, &a, &p).await;
    // CTR-ACC-03: the key is added, none removed
    let got = t.subject(&h).await.unwrap();
    assert_eq!((got.keys, got.recovery, got.key_nonce), (vec![erin.key(), frank.key()], None, 2));
    let p = b(&None::<Holder>);
    let op = t.op(OP_SET_GUARDIAN, &h, &h, 2, &p);
    t.ok(&t.relayer, "mtx_set_guardian", &op, &erin.sign(&op, ORIGIN), &p).await;
    let op = t.op(OP_SET_GUARDIAN, &h, &h, 3, &p);
    t.ok(&t.relayer, "mtx_set_guardian", &op, &frank.sign(&op, ORIGIN), &p).await;
}

#[tokio::test]
async fn cancel_recovery_by_key() {
    let (t, erin, g, frank) = recovery_setup().await;
    let h = erin.ua();
    // any current key cancels during the delay
    let op = t.op(OP_CANCEL_RECOVERY, &h, &h, 1, &[]);
    t.ok(&t.relayer, "mtx_cancel_recovery", &op, &erin.sign(&op, ORIGIN), &[]).await;
    assert_eq!(t.subject(&h).await.unwrap().recovery, None);
    let (op, a, p) = t.finish_op(&g, &h, 1);
    t.refused(&t.relayer, "mtx_finish_recovery", &op, &a, &p, "no recovery pending").await;
    let op = t.op(OP_CANCEL_RECOVERY, &h, &h, 2, &[]);
    t.refused(&t.relayer, "mtx_cancel_recovery", &op, &erin.sign(&op, ORIGIN), &[], "no recovery pending").await;
    // mtx_set_guardian cancels a pending recovery
    let pr = b(&(frank.key(), None::<String>));
    let op = t.op(OP_START_RECOVERY, &g.ua(), &h, 1, &pr);
    t.ok(&t.relayer, "mtx_start_recovery", &op, &g.sign(&op, ORIGIN), &pr).await;
    assert!(t.subject(&h).await.unwrap().recovery.is_some());
    t.set_guardian(&t.relayer, &erin, &h, 2, Some(g.ua())).await;
    assert_eq!(t.subject(&h).await.unwrap().recovery, None);
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

    // a 2-of-2 of two ed25519 members: signatures out of member order or a repeated index are refused
    let frank = Signer::ed("frank");
    let Holder::Ua(frank_id) = frank.ua() else { unreachable!() };
    let mut ids = [erin_id, frank_id];
    ids.sort();
    let body: Vec<u8> = ids.iter().flat_map(|i| [&KIND_ED25519.to_be_bytes()[..], i, &[0, 1]].concat()).collect();
    let kd = [&[0u8, 2, 0, 2][..], &body].concat();
    let m2 = Holder::Ua(ua::ua_of(KIND_MSIG, &kd));
    let op = t.op(OP_SET_GUARDIAN, &m2, &m2, 0, &p);
    let by = |i: usize| if ids[i] == erin_id { erin.sign(&op, ORIGIN) } else { frank.sign(&op, ORIGIN) };
    let msig = |sigs: Vec<(u8, Auth)>| Auth::Msig { key_data: kd.clone(), sigs };
    let swapped = msig(vec![(1, by(1)), (0, by(0))]);
    t.refused(&t.relayer, "mtx_set_guardian", &op, &swapped, &p, "not in member order").await;
    let twice = msig(vec![(0, by(0)), (0, by(0))]);
    t.refused(&t.relayer, "mtx_set_guardian", &op, &twice, &p, "not in member order").await;
    t.ok(&t.relayer, "mtx_set_guardian", &op, &msig(vec![(0, by(0)), (1, by(1))]), &p).await;
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

#[tokio::test]
async fn set_policy_by_key_op() {
    let t = setup().await;
    let erin = Signer::ed("erin"); // a wallet-kind key (not a passkey)
    let h = erin.ua();
    let set = |nonce, p: u8| {
        let params = b(&p);
        (t.op(OP_SET_GUARDIAN, &h, &h, nonce, &[KEYOP_SET_POLICY, p]), params)
    };
    let (op, p) = set(0, POLICY_PASSKEY_FOR_VALUE);
    let c = t.ok(&t.relayer, "mtx_set_policy", &op, &erin.sign(&op, ORIGIN), &p).await;
    let got = t.subject(&h).await.unwrap();
    assert_eq!((got.policy, got.key_nonce), (POLICY_PASSKEY_FOR_VALUE, 1));
    assert_eq!(c.storage_needed.0, record_bytes(&h, &got) as u128 * t.byte_cost().await);
    // with the bit set a wallet key still authorises key ops (enforcement on value ops: Task 6)
    t.set_guardian(&t.relayer, &erin, &h, 1, Some(t.near(&t.bob))).await;
    // unknown bits refused; the policy bound by extra: a set_guardian op does not set it
    let (op, p) = set(2, 2);
    t.refused(&t.relayer, "mtx_set_policy", &op, &erin.sign(&op, ORIGIN), &p, "unknown policy bit").await;
    let (mut op, p) = set(2, 0);
    op.extra = sha(&b(&None::<Holder>));
    t.refused(&t.relayer, "mtx_set_policy", &op, &erin.sign(&op, ORIGIN), &p, "extra is not sha256").await;
    // set_policy's signed op fed to mtx_set_guardian: its params are no Option<Holder>, and with guardian params
    // the extra does not match
    let (op, _) = set(2, 0);
    let a = erin.sign(&op, ORIGIN);
    let out = t.call(&t.relayer, "mtx_set_guardian", [b(&op), b(&a), vec![KEYOP_SET_POLICY, 0]].concat(), 0).await;
    assert!(out.is_failure());
    t.refused(&t.relayer, "mtx_set_guardian", &op, &a, &b(&None::<Holder>), "extra is not sha256").await;
    let (op, p) = set(2, 0);
    t.ok(&t.relayer, "mtx_set_policy", &op, &erin.sign(&op, ORIGIN), &p).await;
    assert_eq!(t.subject(&h).await.unwrap().policy, 0);
}
