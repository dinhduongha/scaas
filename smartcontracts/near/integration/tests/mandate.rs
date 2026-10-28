//! Task 7 (spec §3.6, README §3 item 2, CTR-ACC-06 / CTR-ACC-12, ruling R9): the mandate in the token. The owner opens
//! it with a value op on its own lane (op 13: `amount` = `terms.funding` moves into the token ledger under the mandate
//! id, `to = Ua(id)`, `extra = sha256(Borsh(id, terms))`); the delegate signs each `mtx_mandate_pay` (op 2, `from =
//! Ua(id)`, the mandate's lane `payLane(pay_ref)` at nonce 0: each `pay_ref` once per mandate) within the per-payment
//! and per-period caps, to the payee, until the expiry; the owner or the delegate revokes (op 3), which returns the
//! funds. One sandbox per test.
mod common;
use common::*;
use scaas_near_common::hash::{hex, pay_lane};
use scaas_near_token::{lane_bytes, mandate_bytes, Mandate, MandateTerms, UA_STORAGE_BYTES};

const PER_PAYMENT: &str = "over the per-payment cap";
const PER_PERIOD: &str = "over the per-period cap";
const PAYEE: &str = "payee not allowed";
const EXPIRED: &str = "mandate expired";
const REVOKED: &str = "mandate revoked";
const PAID: &str = "pay_ref already paid under this mandate";
const PERIOD_S: u64 = 3_600;

fn x(b: &[u8]) -> String {
    format!("0x{}", hex(b))
}

/// The mandate id the token derives: `sha256(Borsh(from, terms, lane, nonce))` of the opening op.
fn mandate_id(from: &Holder, terms: &MandateTerms, lane: [u8; 32], nonce: u64) -> [u8; 32] {
    sha(&b(&(from, terms, lane, nonce)))
}

impl T {
    fn terms(&self, delegate: &Holder, payee: &Holder, per_payment: u128, per_period: u128, funding: u128) -> MandateTerms {
        MandateTerms {
            delegate: delegate.clone(),
            payee: payee.clone(),
            per_payment,
            per_period,
            period_s: PERIOD_S,
            expiry: VU,
            funding,
        }
    }

    /// `mtx_mandate_open` of `owner` on its lane `lane` at `nonce` (ruling R9: `amount = funding`, `to = Ua(id)`,
    /// `extra = sha256(Borsh(id, terms))`).
    fn open_op(&self, owner: &Holder, terms: &MandateTerms, lane: [u8; 32], nonce: u64) -> (MetaOp, [u8; 32]) {
        let id = mandate_id(owner, terms, lane, nonce);
        let op = MetaOp {
            amount: terms.funding,
            lane,
            to: Holder::Ua(id),
            extra: sha(&b(&(id, terms))),
            ..self.op(OP_MANDATE_OPEN, owner, owner, nonce, &[])
        };
        (op, id)
    }

    /// `mtx_mandate_pay` under mandate `id`: `from = Ua(id)`, lane `payLane(pay_ref)`, nonce 0, `extra = sha256([])`.
    fn mpay_op(&self, id: [u8; 32], payee: &Holder, amount: u128, pay_ref: [u8; 32]) -> MetaOp {
        MetaOp { amount, pay_ref, lane: pay_lane(&pay_ref), ..self.op(OP_MANDATE_PAY, &Holder::Ua(id), payee, 0, &[]) }
    }

    /// `mtx_revoke` of mandate `id` signed by `by` (the owner or the delegate): `to = Ua(id)`, `extra = sha256([])`.
    fn revoke_op(&self, by: &Holder, id: [u8; 32]) -> MetaOp {
        self.op(OP_REVOKE, by, &Holder::Ua(id), 0, &[])
    }

    async fn mandate(&self, id: [u8; 32]) -> Option<Mandate> {
        self.token.view("mandate").args(b(&id)).await.unwrap().borsh().unwrap()
    }

    /// Moves a stored mandate (the sandbox clock cannot jump an hour): the record under key `m` ‖ id.
    async fn patch_mandate(&self, id: [u8; 32], f: impl FnOnce(&mut Mandate)) {
        let mut m = self.mandate(id).await.unwrap();
        f(&mut m);
        self.w.patch_state(self.token.id(), &[b"m".as_slice(), &id].concat(), &b(&m)).await.unwrap();
    }

    /// Owner `erin` (a UA funded with `fund`) opens a mandate with `terms` on lane `[0xb0; 32]` at nonce 0.
    async fn opened(&self, erin: &Signer, fund: u128, terms: MandateTerms) -> [u8; 32] {
        let h = erin.ua();
        self.fund(&h, fund).await;
        let (op, id) = self.open_op(&h, &terms, [0xb0; 32], 0);
        self.ok(&self.relayer, "mtx_mandate_open", &op, &erin.sign(&op, ORIGIN), &b(&terms)).await;
        id
    }
}

#[tokio::test]
async fn mandate_pay_within_limits() {
    let t = setup().await;
    let (erin, dele) = (Signer::ed("erin"), Signer::ed("dele"));
    let (h, bob) = (erin.ua(), t.near(&t.bob));
    t.fund(&h, 1_000).await;
    let terms = t.terms(&dele.ua(), &bob, 100, 1_000, 300);
    let (op, id) = t.open_op(&h, &terms, [0xb0; 32], 0);
    let cost = t.byte_cost().await;
    let u0 = t.usage().await;
    let (c, out) = t.exec(&t.relayer, "mtx_mandate_open", &op, &erin.sign(&op, ORIGIN), &b(&terms)).await;
    assert!(out.is_success(), "{:?}", out.failures());
    let m = t.mandate(id).await.unwrap();
    let opened = record_bytes(&h, &Subject { keys: vec![erin.key()], ..Default::default() });
    let bytes = opened + lane_bytes(&h) + UA_STORAGE_BYTES + mandate_bytes(&m);
    assert_eq!(c, Check { error: None, storage_needed: (bytes as u128 * cost).into() });
    assert_eq!(t.usage().await - u0, bytes, "measured bytes");
    println!("mtx_mandate_open: {:.3} Tgas, {bytes} B (mandate record {} B)", tgas(&out), mandate_bytes(&m));
    assert_eq!((m.owner.clone(), m.terms.clone(), m.spent, m.revoked), (h.clone(), terms.clone(), 0, false));
    assert!(out.logs().iter().any(|l| l.contains(r#""event":"mandate""#) && l.contains(&x(&id))), "{:?}", out.logs());
    assert_eq!((t.balance(&h).await, t.balance(&Holder::Ua(id)).await), (700, 300));
    // the delegate pays (opened lazily); anyone may submit
    let op = t.mpay_op(id, &bob, 100, [1; 32]);
    let u0 = t.usage().await;
    let (c, out) = t.exec(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[]).await;
    assert!(out.is_success(), "{:?}", out.failures());
    let grew = t.usage().await - u0;
    let d = record_bytes(&dele.ua(), &Subject { keys: vec![dele.key()], ..Default::default() });
    let mua = Holder::Ua(id);
    let bytes = d + lane_bytes(&mua) + scaas_near_token::ACCOUNT_STORAGE_BYTES;
    assert_eq!(c, Check { error: None, storage_needed: (bytes as u128 * cost).into() });
    // NEP-145 charges a fixed registration (the 64-char id); the payee's shorter id measures `64 - len` B less
    let short = 64 - t.bob.id().as_str().len() as u64;
    assert_eq!(grew, bytes - short, "first pay: {grew} B measured, {bytes} B charged");
    println!("mtx_mandate_pay (first, delegate opened, payee registered): {:.3} Tgas, {bytes} B", tgas(&out));
    let settled = format!(r#""from":"{}","to":"{bob}","amount":"100","pay_ref":"{}""#, x(&id), x(&[1; 32]));
    assert!(out.logs().iter().any(|l| l.contains("payment_settled") && l.contains(&settled)), "{:?}", out.logs());
    // the owner's own key is not the delegate
    let op = t.mpay_op(id, &bob, 100, [2; 32]);
    t.refused(&t.relayer, "mtx_mandate_pay", &op, &erin.sign(&op, ORIGIN), &[], "not a key of the subject").await;
    let u0 = t.usage().await;
    let (c, out) = t.exec(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[]).await;
    assert!(out.is_success(), "{:?}", out.failures());
    assert_eq!(c.storage_needed.0, lane_bytes(&mua) as u128 * cost, "only the mandate's pay lane is new");
    assert_eq!(t.usage().await - u0, lane_bytes(&mua), "next pay: measured = charged (114 B)");
    println!("mtx_mandate_pay (next): {:.3} Tgas", tgas(&out));
    assert_eq!((t.balance(&bob).await, t.balance(&mua).await, t.balance(&h).await), (200, 100, 700));
    assert_eq!(t.mandate(id).await.unwrap().spent, 200);
    // a relayer-bound pay is only for that relayer
    let mut op = t.mpay_op(id, &bob, 10, [3; 32]);
    op.relayer = Some(t.relayer.id().as_str().parse().unwrap());
    t.refused(&t.bob, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[], "relayer is not the predecessor").await;
    t.ok(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[]).await;
    // a pay above the mandate's balance (90 left) is refused
    let op = t.mpay_op(id, &bob, 100, [4; 32]);
    t.refused(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[], "the mandate's balance is short").await;
}

/// Ruling R9: the funded amount is `op.amount` and `terms.funding` must equal it; the id is bound by `extra` and `to`.
#[tokio::test]
async fn open_funding_equals_op_amount() {
    let t = setup().await;
    let (erin, dele) = (Signer::ed("erin"), Signer::ed("dele"));
    let (h, bob) = (erin.ua(), t.near(&t.bob));
    t.fund(&h, 1_000).await;
    let terms = t.terms(&dele.ua(), &bob, 100, 250, 300);
    let (good, _) = t.open_op(&h, &terms, [0xb0; 32], 0);
    let p = b(&terms);
    let cases: [(fn(&mut MetaOp), &str); 5] = [
        (|o| o.amount = 299, "terms.funding must equal op.amount"),
        (|o| o.extra = [0; 32], "extra is not sha256 of the mandate id and terms"),
        (|o| o.to = Holder::Ua([7; 32]), "to must be the mandate id"),
        (|o| o.pay_ref = [1; 32], "mtx_mandate_open carries no pay_ref"),
        (|o| o.op = OP_PAY, "wrong op code"),
    ];
    for (f, err) in cases {
        let mut op = good.clone();
        f(&mut op);
        t.refused(&t.relayer, "mtx_mandate_open", &op, &erin.sign(&op, ORIGIN), &p, err).await;
    }
    // terms other than the signed ones: the id (and so `extra`) differs
    let other = MandateTerms { per_payment: 101, ..terms.clone() };
    t.refused(&t.relayer, "mtx_mandate_open", &good, &erin.sign(&good, ORIGIN), &b(&other), "to must be the mandate id").await;
    // limits
    let bad: [(MandateTerms, &str); 4] = [
        (MandateTerms { period_s: 0, ..terms.clone() }, "bad mandate limits"),
        (MandateTerms { per_payment: 0, ..terms.clone() }, "bad mandate limits"),
        (MandateTerms { per_payment: 251, ..terms.clone() }, "bad mandate limits"),
        (MandateTerms { expiry: t.now_s().await - 1, ..terms.clone() }, "mandate expiry is past"),
    ];
    for (tm, err) in bad {
        let (op, _) = t.open_op(&h, &tm, [0xb0; 32], 0);
        t.refused(&t.relayer, "mtx_mandate_open", &op, &erin.sign(&op, ORIGIN), &b(&tm), err).await;
    }
    let tm = t.terms(&dele.ua(), &Holder::Near(t.id().as_str().parse().unwrap()), 100, 250, 300);
    let (op, _) = t.open_op(&h, &tm, [0xb0; 32], 0);
    t.refused(&t.relayer, "mtx_mandate_open", &op, &erin.sign(&op, ORIGIN), &b(&tm), "token refuses").await;
    assert_eq!(t.balance(&h).await, 1_000, "nothing moved");
    t.ok(&t.relayer, "mtx_mandate_open", &good, &erin.sign(&good, ORIGIN), &p).await;
    // the opening lane is consumed: the same op again is refused
    t.refused(&t.relayer, "mtx_mandate_open", &good, &erin.sign(&good, ORIGIN), &p, "wrong lane nonce").await;
    // ruling R8: a value op of a POLICY_PASSKEY_FOR_VALUE owner needs a passkey
    let op = t.op(OP_SET_GUARDIAN, &h, &h, 0, &[KEYOP_SET_POLICY, POLICY_PASSKEY_FOR_VALUE]);
    t.ok(&t.relayer, "mtx_set_policy", &op, &erin.sign(&op, ORIGIN), &b(&POLICY_PASSKEY_FOR_VALUE)).await;
    let (op, _) = t.open_op(&h, &terms, [0xb0; 32], 1);
    t.refused(&t.relayer, "mtx_mandate_open", &op, &erin.sign(&op, ORIGIN), &p, "POLICY_PASSKEY_FOR_VALUE").await;
    assert_eq!(t.balance(&h).await, 700);
}

#[tokio::test]
async fn per_payment_and_per_period_exceeded_refused() {
    let t = setup().await;
    let (erin, dele) = (Signer::ed("erin"), Signer::ed("dele"));
    let bob = t.near(&t.bob);
    let id = t.opened(&erin, 1_000, t.terms(&dele.ua(), &bob, 50, 80, 300)).await;
    let pay = |amount, r: u8| t.mpay_op(id, &bob, amount, [r; 32]);
    let op = pay(51, 1);
    t.refused(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[], PER_PAYMENT).await;
    let op = pay(50, 2);
    t.ok(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[]).await;
    let op = pay(31, 3);
    t.refused(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[], PER_PERIOD).await;
    let op = pay(30, 4);
    t.ok(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[]).await;
    let op = pay(1, 5);
    t.refused(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[], PER_PERIOD).await;
    // 1.5 periods later: the window moves on the grid (whole periods from the start), the budget is fresh
    let start = t.mandate(id).await.unwrap().period_start;
    t.patch_mandate(id, |m| m.period_start -= PERIOD_S + PERIOD_S / 2).await;
    let op = pay(1, 5);
    t.ok(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[]).await;
    let m = t.mandate(id).await.unwrap();
    assert_eq!((m.period_start, m.spent), (start - PERIOD_S / 2, 1), "grid, not now");
    let op = pay(50, 6);
    t.ok(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[]).await;
    let op = pay(30, 7);
    t.refused(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[], PER_PERIOD).await;
    assert_eq!(t.balance(&bob).await, 131);
}

#[tokio::test]
async fn wrong_payee_refused() {
    let t = setup().await;
    let (erin, dele) = (Signer::ed("erin"), Signer::ed("dele"));
    let bob = t.near(&t.bob);
    let id = t.opened(&erin, 1_000, t.terms(&dele.ua(), &bob, 100, 250, 300)).await;
    for to in [t.near(&t.alice), t.near(&t.relayer), Signer::ed("zed").ua(), erin.ua()] {
        let op = t.mpay_op(id, &to, 10, [1; 32]);
        t.refused(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[], PAYEE).await;
    }
    let op = t.mpay_op(id, &bob, 10, [1; 32]);
    t.ok(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[]).await;
    assert_eq!(t.balance(&bob).await, 10);
}

#[tokio::test]
async fn expired_refused() {
    let t = setup().await;
    let (erin, dele) = (Signer::ed("erin"), Signer::ed("dele"));
    let (h, bob) = (erin.ua(), t.near(&t.bob));
    let id = t.opened(&erin, 1_000, t.terms(&dele.ua(), &bob, 100, 250, 300)).await;
    // a live mandate is not refunded
    let out = t.call(&t.relayer, "mandate_refund", b(&id), 0).await;
    assert!(format!("{:?}", out.failures()).contains("mandate live"), "{:?}", out.failures());
    // up to the expiry a pay is allowed (the exact second `now == expiry`: unit test `pay_at_expiry_second_allowed`)
    let now = t.now_s().await;
    t.patch_mandate(id, |m| m.terms.expiry = now + 30).await;
    let op = t.mpay_op(id, &bob, 10, [2; 32]);
    t.ok(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[]).await;
    t.patch_mandate(id, |m| m.terms.expiry = now - 1).await;
    let op = t.mpay_op(id, &bob, 10, [1; 32]);
    t.refused(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[], EXPIRED).await;
    // after the expiry anyone returns the funds to the owner
    let out = t.call(&t.relayer, "mandate_refund", b(&id), 0).await;
    assert!(out.is_success(), "{:?}", out.failures());
    assert_eq!((t.balance(&h).await, t.balance(&Holder::Ua(id)).await, t.balance(&bob).await), (990, 0, 10));
    // a revoke after the expiry is allowed and returns what arrived since
    t.fund(&t.near(&t.alice), 5).await;
    let out = t.alice.call(t.token.id(), "transfer_to_ua").args_json(json!({"id": id.to_vec(), "amount": "5"}))
        .deposit(NearToken::from_yoctonear(1)).transact().await.unwrap();
    assert!(out.is_success(), "{:?}", out.failures());
    let op = t.revoke_op(&h, id);
    t.ok(&t.relayer, "mtx_revoke", &op, &erin.sign(&op, ORIGIN), &[]).await;
    assert!(t.mandate(id).await.unwrap().revoked);
    assert_eq!((t.balance(&h).await, t.balance(&Holder::Ua(id)).await), (995, 0));
}

/// Ruling R8 for the pay: the delegate's own POLICY_PASSKEY_FOR_VALUE binds its mandate pays.
#[tokio::test]
async fn delegate_policy_passkey_for_value() {
    let t = setup().await;
    let (erin, dele, pk) = (Signer::ed("erin"), Signer::ed("dele"), Signer::pk(4, RP));
    let (d, bob) = (dele.ua(), t.near(&t.bob));
    let id = t.opened(&erin, 1_000, t.terms(&d, &bob, 100, 250, 300)).await;
    let p = b(&(pk.key(), Some(ORIGIN.to_string())));
    let op = t.op(OP_ADD_KEY, &d, &d, 0, &p);
    t.ok(&t.relayer, "mtx_add_key", &op, &dele.sign(&op, ORIGIN), &p).await;
    let op = t.op(OP_SET_GUARDIAN, &d, &d, 1, &[KEYOP_SET_POLICY, POLICY_PASSKEY_FOR_VALUE]);
    t.ok(&t.relayer, "mtx_set_policy", &op, &dele.sign(&op, ORIGIN), &b(&POLICY_PASSKEY_FOR_VALUE)).await;
    let op = t.mpay_op(id, &bob, 10, [1; 32]);
    t.refused(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[], "POLICY_PASSKEY_FOR_VALUE").await;
    assert_eq!(t.balance(&Holder::Ua(id)).await, 300);
    t.ok(&t.relayer, "mtx_mandate_pay", &op, &pk.sign(&op, ORIGIN), &[]).await;
    assert_eq!((t.balance(&bob).await, t.balance(&Holder::Ua(id)).await), (10, 290));
}

#[tokio::test]
async fn revoked_refused_then_funds_back() {
    let t = setup().await;
    let (erin, dele, mallory) = (Signer::ed("erin"), Signer::ed("dele"), Signer::ed("mallory"));
    let (h, bob) = (erin.ua(), t.near(&t.bob));
    let terms = t.terms(&dele.ua(), &bob, 100, 250, 300);
    let id = t.opened(&erin, 1_000, terms.clone()).await;
    let op = t.mpay_op(id, &bob, 40, [1; 32]);
    t.ok(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[]).await;
    // only the owner or the delegate revokes
    let op = t.revoke_op(&mallory.ua(), id);
    t.refused(&t.relayer, "mtx_revoke", &op, &mallory.sign(&op, ORIGIN), &[], "only the owner or the delegate revokes").await;
    // the delegate's kill switch: the remaining funds go back to the owner at once
    let op = t.revoke_op(&dele.ua(), id);
    let u0 = t.usage().await;
    let (c, out) = t.exec(&t.relayer, "mtx_revoke", &op, &dele.sign(&op, ORIGIN), &[]).await;
    assert_eq!(c, Check { error: None, storage_needed: 0.into() });
    assert!(out.is_success(), "{:?}", out.failures());
    assert_eq!(t.usage().await, u0, "revoke writes no new record");
    println!("mtx_revoke (delegate): {:.3} Tgas", tgas(&out));
    assert!(t.mandate(id).await.unwrap().revoked);
    assert_eq!((t.balance(&h).await, t.balance(&Holder::Ua(id)).await, t.balance(&bob).await), (960, 0, 40));
    let op = t.mpay_op(id, &bob, 10, [2; 32]);
    t.refused(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[], REVOKED).await;
    let op = t.revoke_op(&h, id);
    t.refused(&t.relayer, "mtx_revoke", &op, &erin.sign(&op, ORIGIN), &[], REVOKED).await;
    // a refund that would move nothing is refused (owner rule: no effect for a no-op; as Algorand)
    let out = t.call(&t.relayer, "mandate_refund", b(&id), 0).await;
    assert!(format!("{:?}", out.failures()).contains("nothing to refund"), "{:?}", out.failures());
    // funds that reach a revoked mandate later go back through the permissionless refund
    t.fund(&Holder::Near(t.alice.id().as_str().parse().unwrap()), 5).await;
    let out = t.alice.call(t.token.id(), "transfer_to_ua").args_json(json!({"id": id.to_vec(), "amount": "5"}))
        .deposit(NearToken::from_yoctonear(1)).transact().await.unwrap();
    assert!(out.is_success(), "{:?}", out.failures());
    let out = t.call(&t.relayer, "mandate_refund", b(&id), 0).await;
    assert!(out.is_success(), "{:?}", out.failures());
    assert_eq!(t.balance(&h).await, 965);
    let out = t.call(&t.relayer, "mandate_refund", b(&id), 0).await;
    assert!(format!("{:?}", out.failures()).contains("nothing to refund"), "{:?}", out.failures());
    assert_eq!(t.balance(&h).await, 965);
    // the owner revokes a second mandate (lane nonce 1)
    let (op, id2) = t.open_op(&h, &terms, [0xb0; 32], 1);
    t.ok(&t.relayer, "mtx_mandate_open", &op, &erin.sign(&op, ORIGIN), &b(&terms)).await;
    assert_eq!(t.balance(&h).await, 665);
    let op = t.revoke_op(&h, id2);
    t.ok(&t.relayer, "mtx_revoke", &op, &erin.sign(&op, ORIGIN), &[]).await;
    assert_eq!(t.balance(&h).await, 965);
}

#[tokio::test]
async fn pay_ref_once_per_mandate() {
    let t = setup().await;
    let (erin, dele) = (Signer::ed("erin"), Signer::ed("dele"));
    let (h, bob) = (erin.ua(), t.near(&t.bob));
    let terms = t.terms(&dele.ua(), &bob, 100, 250, 300);
    let id = t.opened(&erin, 1_000, terms.clone()).await;
    let op = t.mpay_op(id, &bob, 10, [1; 32]);
    let a = dele.sign(&op, ORIGIN);
    t.ok(&t.relayer, "mtx_mandate_pay", &op, &a, &[]).await;
    t.refused(&t.relayer, "mtx_mandate_pay", &op, &a, &[], PAID).await;
    let again = t.mpay_op(id, &bob, 11, [1; 32]);
    t.refused(&t.relayer, "mtx_mandate_pay", &again, &dele.sign(&again, ORIGIN), &[], PAID).await;
    // the lane is derived from pay_ref, at nonce 0 (another lane or nonce would pay the ref twice)
    let shape = "mandate pay shape (pay_ref set, lane = payLane(pay_ref), nonce 0, extra = sha256([]))";
    let fs: [fn(&mut MetaOp); 4] = [|o| o.lane = [9; 32], |o| o.nonce = 1, |o| o.pay_ref = [0; 32], |o| o.extra = [0; 32]];
    for f in fs {
        let mut o = t.mpay_op(id, &bob, 10, [2; 32]);
        f(&mut o);
        t.refused(&t.relayer, "mtx_mandate_pay", &o, &dele.sign(&o, ORIGIN), &[], shape).await;
    }
    // the same pay_ref under another mandate of the same owner pays
    let (op, id2) = t.open_op(&h, &terms, [0xb0; 32], 1);
    t.ok(&t.relayer, "mtx_mandate_open", &op, &erin.sign(&op, ORIGIN), &b(&terms)).await;
    let op = t.mpay_op(id2, &bob, 10, [1; 32]);
    t.ok(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[]).await;
    assert_eq!((t.balance(&bob).await, t.balance(&Holder::Ua(id)).await, t.balance(&Holder::Ua(id2)).await), (20, 290, 290));
    // an unknown mandate
    let op = t.mpay_op([5; 32], &bob, 10, [1; 32]);
    t.refused(&t.relayer, "mtx_mandate_pay", &op, &dele.sign(&op, ORIGIN), &[], "no such mandate").await;
}

/// metatx-split §6.2: the mandate has no pay-meta entry.
#[tokio::test]
async fn mandate_has_no_pay_meta_entry() {
    let t = setup().await;
    let (erin, dele) = (Signer::ed("erin"), Signer::ed("dele"));
    let bob = t.near(&t.bob);
    let id = t.opened(&erin, 1_000, t.terms(&dele.ua(), &bob, 100, 250, 300)).await;
    let op = t.mpay_op(id, &bob, 10, [1; 32]);
    let args = [b(&op), b(&dele.sign(&op, ORIGIN)), b(&[0u8; 32]), b(&vec![1u8])].concat();
    for m in ["mtx_mandate_pay_meta", "mtx_mandate_pay_meta_check"] {
        let out = t.call(&t.relayer, m, args.clone(), 0).await;
        assert!(format!("{:?}", out.failures()).contains("MethodNotFound"), "{m}: {:?}", out.failures());
    }
    assert_eq!(t.balance(&bob).await, 0);
}
