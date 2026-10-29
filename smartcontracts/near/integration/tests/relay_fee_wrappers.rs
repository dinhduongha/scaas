//! Task 9 (spec §3.8 wrappers, §2 rows 8–14; CTR-MTX-27; rulings R1, R2, R6, T9 pre-flight a–f): `relay_fee_<entry>` runs
//! a fee-less signed entry, then the payer's routed pay (`pay_ref = ref`, `lane = payLane(ref)`, nonce 0, `relayer` =
//! the token id) in one receipt; `ref = keccak256("scaas.relayfee" ‖ network ‖ u8 len ‖ token id ‖ keccak256(u8 len ‖
//! mtx_<entry> ‖ Borsh(entry arguments)) ‖ pay_op.extra)`. Open mode (`to` = the token) pays the submitting relayer, a
//! bound payee is paid directly. Every wrapper here is signed by passkeys on both sides (the two-passkey case of R1) and
//! submitted with 300 Tgas prepaid. One sandbox per test.
#![allow(unused_must_use)] // `relay` asserts success itself; only the gas tests read its result
mod common;
use common::*;
use scaas_near_common::hash::{hex, pay_lane, relay_ref};
use scaas_near_token::{Mandate, MandateTerms, OrderClose};

const SHORT: &str = "The attached deposit is less than the storage cost of the new record";
const TO_SELF: &str = "token refuses a transfer to the token itself";
const SHAPE: &str = "routed pay shape (op 0, pay_ref = ref, lane = payLane(ref), nonce 0, relayer = the marker)";
const RELAYER: &str = "relayer is not the predecessor";
const POLICY: &str = "POLICY_PASSKEY_FOR_VALUE: value ops need a passkey signature";
const SALT: [u8; 32] = [0x5a; 32];
const FEE: u128 = 10;
const ORIGIN2: &str = "https://app.scaas.test";

fn x(b: &[u8]) -> String {
    format!("0x{}", hex(b))
}

/// Index of the first log (any receipt) with `"event":"<name>"`.
fn at(out: &ExecutionFinalResult, name: &str) -> Option<usize> {
    let tag = format!(r#""event":"{name}""#);
    out.logs().iter().position(|l| l.contains(&tag))
}

fn entry_event(entry: &str) -> &'static str {
    match entry {
        "mandate_open" | "revoke" => "mandate",
        "cancel" => "order_cancelled",
        "invalidate_nonces" => "nonces_invalidated",
        _ => "key_op",
    }
}

/// A wrapped call: the entry op, its auth and the Borsh of the entry's other parameters.
struct Entry<'a> {
    name: &'a str,
    op: MetaOp,
    auth: Auth,
    params: Vec<u8>,
}

impl Entry<'_> {
    /// Borsh(entry arguments) = Borsh(op) ‖ Borsh(auth) ‖ params.
    fn args(&self) -> Vec<u8> {
        [b(&self.op), b(&self.auth), self.params.clone()].concat()
    }
}

impl T {
    fn marker(&self) -> Holder {
        Holder::Near(self.id().as_str().parse().unwrap())
    }

    /// Spec §2 row 8 / §3.8: target = u8 len ‖ token id, call = u8 len ‖ `mtx_<entry>` ‖ Borsh(entry arguments).
    fn fee_ref(&self, e: &Entry, salt: [u8; 32]) -> [u8; 32] {
        let id = self.id().to_string();
        let target = [&[id.len() as u8][..], id.as_bytes()].concat();
        let m = format!("mtx_{}", e.name);
        relay_ref(&NETWORK, &target, &[&[m.len() as u8][..], m.as_bytes(), &e.args()].concat(), &salt)
    }

    /// The payment op of `from` for `r`: op 0, `pay_ref = r`, `lane = payLane(r)`, nonce 0, `relayer` = the token,
    /// `extra` = the salt.
    fn pay_op(&self, from: &Holder, to: &Holder, amount: u128, r: [u8; 32], salt: [u8; 32]) -> MetaOp {
        let token = Some(self.id().as_str().parse().unwrap());
        MetaOp { amount, pay_ref: r, lane: pay_lane(&r), relayer: token, extra: salt, ..self.op(OP_PAY, from, to, 0, &[]) }
    }

    async fn fee_check(&self, caller: &Account, e: &Entry<'_>, pay: &MetaOp, pa: &Auth) -> Check {
        let args = [b(&caller.id().as_str()), e.args(), b(pay), b(pa)].concat();
        self.token.view(&format!("relay_fee_{}_check", e.name)).args(args).await.unwrap().borsh().unwrap()
    }

    /// `relay_fee_<entry>_check` then `relay_fee_<entry>` with exactly `storage_needed` attached, 300 Tgas prepaid.
    async fn fee_exec(&self, who: &Account, e: &Entry<'_>, pay: &MetaOp, pa: &Auth) -> (Check, ExecutionFinalResult) {
        let c = self.fee_check(who, e, pay, pa).await;
        let args = [e.args(), b(pay), b(pa)].concat();
        let out = self.call(who, &format!("relay_fee_{}", e.name), args, c.storage_needed.0).await;
        (c, out)
    }

    /// Check and call both refused with `err`; nothing is paid and no fee event exists (spec §3.8, NET-NEAR-07).
    async fn fee_refused(&self, who: &Account, e: &Entry<'_>, pay: &MetaOp, pa: &Auth, err: &str) {
        let before = self.balance(&pay.from).await;
        let (c, out) = self.fee_exec(who, e, pay, pa).await;
        assert!(c.error.as_deref().is_some_and(|m| m.contains(err)), "{}: check {:?}, want {err}", e.name, c.error);
        assert!(out.is_failure() && format!("{:?}", out.failures()).contains(err), "{}: {:?}", e.name, out.failures());
        assert_eq!(at(&out, "relay_fee_paid"), None, "no relay_fee_paid on a refusal");
        assert_eq!(self.balance(&pay.from).await, before, "nothing paid");
        assert_eq!(self.lane_nonce(&pay.from, pay.lane).await, 0, "the payment's lane unused");
    }

    /// A wrapped call that must succeed: the payment of `FEE` from `payer` to `to` (the token = open mode) for `e`, salt
    /// `SALT`. Asserts: `storage_needed` is the exact deposit (one yoctoNEAR less is refused, all of it taken: the relayer
    /// pays storage, spec §2 row 15), within 300 Tgas, the payee credited,
    /// the payer debited (plus the entry's own amount when it signs the entry too), events entry → payment →
    /// `relay_fee_paid` with `ref`. Prints gas and storage.
    async fn relay(&self, who: &Account, e: &Entry<'_>, payer: &Signer, to: &Holder) -> ExecutionFinalResult {
        self.relay_as(who, e, payer, &payer.ua(), to).await
    }

    /// `relay` with the payment of `from` signed by `payer`, one of `from`'s keys.
    async fn relay_as(&self, who: &Account, e: &Entry<'_>, payer: &Signer, from: &Holder, to: &Holder) -> ExecutionFinalResult {
        let from = from.clone();
        let r = self.fee_ref(e, SALT);
        let pay = self.pay_op(&from, to, FEE, r, SALT);
        let pa = payer.sign(&pay, ORIGIN);
        let payee = if *to == self.marker() { Holder::Near(who.id().as_str().parse().unwrap()) } else { to.clone() };
        let (p0, q0, u0) = (self.balance(&from).await, self.balance(&payee).await, self.usage().await);
        let c = self.fee_check(who, e, &pay, &pa).await;
        assert_eq!(c.error, None, "relay_fee_{}", e.name);
        let (entry, args) = (format!("relay_fee_{}", e.name), [e.args(), b(&pay), b(&pa)].concat());
        let short = self.call(who, &entry, args.clone(), c.storage_needed.0 - 1).await;
        assert!(format!("{:?}", short.failures()).contains(SHORT), "{entry}: one yocto short: {:?}", short.failures());
        let out = self.call(who, &entry, args, c.storage_needed.0).await;
        assert!(out.is_success(), "{entry}: {:?}", out.failures());
        let g = tgas(&out);
        assert!(g <= 300.0, "{entry}: {g} Tgas over 300 (R1)");
        let (grown, charged) = (self.usage().await as i64 - u0 as i64, c.storage_needed.0 / self.byte_cost().await);
        let own = if e.op.from == from { e.op.amount } else { 0 };
        assert_eq!(p0 - self.balance(&from).await, FEE + own, "payer debited");
        assert_eq!(self.balance(&payee).await - q0, FEE, "payee credited");
        let (ev, settled, paid) = (at(&out, entry_event(e.name)), at(&out, "payment_settled"), at(&out, "relay_fee_paid"));
        assert!(ev.is_some() && ev < settled && settled < paid, "relay_fee_{}: entry, payment, fee: {:?}", e.name, out.logs());
        let fee_log = out.logs()[paid.unwrap()].to_string();
        let id = self.id().to_string();
        for want in [
            format!(r#""ref":"{}""#, x(&r)),
            format!(r#""target":"{id}""#),
            format!(r#""token":"{id}""#),
            format!(r#""payer":"{from}""#),
            format!(r#""payee":"{payee}""#),
            format!(r#""amount":"{FEE}""#),
        ] {
            assert!(fee_log.contains(&want), "{want} in {fee_log}");
        }
        println!("GAS {entry}: {g:.3} Tgas burnt (margin {:.3} Tgas to 300); storage charged {charged} B, grown {grown} B", 300.0 - g);
        out
    }

    fn entry<'a>(&self, name: &'a str, s: &Signer, op: MetaOp, params: Vec<u8>) -> Entry<'a> {
        let auth = s.sign(&op, ORIGIN);
        Entry { name, op, auth, params }
    }

    /// `mandate` open op of `owner` with `terms` on lane `[0xb0; 32]`, nonce 0 (ruling R9).
    fn open_op(&self, owner: &Holder, terms: &MandateTerms) -> (MetaOp, [u8; 32]) {
        let lane = [0xb0; 32];
        let id = sha(&b(&(owner, terms, lane, 0u64)));
        let op = MetaOp {
            amount: terms.funding,
            lane,
            to: Holder::Ua(id),
            extra: sha(&b(&(id, terms))),
            ..self.op(OP_MANDATE_OPEN, owner, owner, 0, &[])
        };
        (op, id)
    }

    fn terms(&self, delegate: &Holder, funding: u128) -> MandateTerms {
        let bob = self.near(&self.bob);
        MandateTerms { delegate: delegate.clone(), payee: bob, per_payment: 100, per_period: 250, period_s: 3_600, expiry: VU, funding }
    }
}

/// Entry signer `pa`, payer `py` (both passkey UAs; `py` funded with 1,000).
async fn two() -> (T, Signer, Signer) {
    let t = setup().await;
    let (pa, py) = (Signer::pk(1, RP), Signer::pk(2, RP));
    t.fund(&py.ua(), 1_000).await;
    (t, pa, py)
}

// ------------------------------------------------------------------------------------------- one success per wrapper

/// The entry's signer is the payer, its subject not yet open: the entry opens it, the payment never opens it again
/// (`storage_needed` exact).
#[tokio::test]
async fn relay_fee_add_key_ok() {
    let t = setup().await;
    let (pa, frank) = (Signer::pk(1, RP), Signer::ed("frank"));
    let h = pa.ua();
    t.fund(&h, 1_000).await;
    let p = b(&(frank.key(), None::<String>));
    let e = t.entry("add_key", &pa, t.op(OP_ADD_KEY, &h, &h, 0, &p), p);
    t.relay(&t.relayer, &e, &pa, &t.marker()).await;
    assert_eq!(t.subject(&h).await.unwrap().keys, vec![pa.key(), frank.key()]);
}

#[tokio::test]
async fn relay_fee_remove_key_ok() {
    let (t, pa, py) = two().await;
    let (h, frank) = (pa.ua(), Signer::ed("frank"));
    let p = b(&(frank.key(), None::<String>));
    let op = t.op(OP_ADD_KEY, &h, &h, 0, &p);
    t.ok(&t.relayer, "mtx_add_key", &op, &pa.sign(&op, ORIGIN), &p).await;
    let p = b(&frank.key());
    let e = t.entry("remove_key", &pa, t.op(OP_REMOVE_KEY, &h, &h, 1, &p), p);
    t.relay(&t.relayer, &e, &py, &t.marker()).await;
    assert_eq!(t.subject(&h).await.unwrap().keys, vec![pa.key()]);
}

#[tokio::test]
async fn relay_fee_add_origin_ok() {
    let (t, pa, py) = two().await;
    let h = pa.ua();
    let p = b(&ORIGIN2.to_string());
    let e = t.entry("add_origin", &pa, t.op(OP_ADD_ORIGIN, &h, &h, 0, &p), p);
    t.relay(&t.relayer, &e, &py, &t.marker()).await;
    assert_eq!(t.subject(&h).await.unwrap().origins, vec![ORIGIN.to_string(), ORIGIN2.to_string()]);
}

#[tokio::test]
async fn relay_fee_remove_origin_ok() {
    let (t, pa, py) = two().await;
    let h = pa.ua();
    let p = b(&ORIGIN2.to_string());
    let op = t.op(OP_ADD_ORIGIN, &h, &h, 0, &p);
    t.ok(&t.relayer, "mtx_add_origin", &op, &pa.sign(&op, ORIGIN), &p).await;
    let e = t.entry("remove_origin", &pa, t.op(OP_REMOVE_ORIGIN, &h, &h, 1, &p), p);
    t.relay(&t.relayer, &e, &py, &t.marker()).await;
    assert_eq!(t.subject(&h).await.unwrap().origins, vec![ORIGIN.to_string()]);
}

#[tokio::test]
async fn relay_fee_set_guardian_ok() {
    let (t, pa, py) = two().await;
    let (h, g) = (pa.ua(), Signer::pk(3, RP).ua());
    let p = b(&Some(g.clone()));
    let e = t.entry("set_guardian", &pa, t.op(OP_SET_GUARDIAN, &h, &h, 0, &p), p);
    t.relay(&t.relayer, &e, &py, &t.marker()).await;
    assert_eq!(t.subject(&h).await.unwrap().guardian, Some(g));
}

/// `mtx_set_policy` is a key op (the set_policy action under op code 10, Task 5 fix 1): wrapped as every key op (§3.8).
#[tokio::test]
async fn relay_fee_set_policy_ok() {
    let (t, pa, py) = two().await;
    let h = pa.ua();
    let e = t.entry("set_policy", &pa, t.op(OP_SET_GUARDIAN, &h, &h, 0, &[KEYOP_SET_POLICY, 1]), b(&POLICY_PASSKEY_FOR_VALUE));
    t.relay(&t.relayer, &e, &py, &t.marker()).await;
    assert_eq!(t.subject(&h).await.unwrap().policy, POLICY_PASSKEY_FOR_VALUE);
}

/// `pa` with guardian `g` (passkey UA, opened lazily here by its start): returns the subject and the guardian.
async fn guarded(t: &T, pa: &Signer) -> (Holder, Signer) {
    let g = Signer::pk(3, RP);
    t.set_guardian(&t.relayer, pa, &pa.ua(), 0, Some(g.ua())).await;
    (pa.ua(), g)
}

#[tokio::test]
async fn relay_fee_start_recovery_ok() {
    let (t, pa, py) = two().await;
    let (h, g) = guarded(&t, &pa).await;
    let p = b(&(Signer::ed("frank").key(), None::<String>));
    let e = t.entry("start_recovery", &g, t.op(OP_START_RECOVERY, &g.ua(), &h, 0, &p), p);
    t.relay(&t.relayer, &e, &py, &t.marker()).await;
    assert!(t.subject(&h).await.unwrap().recovery.is_some());
}

/// Guardian `g` has started a recovery of `pa` to `frank` (plain entry).
async fn recovering(t: &T, pa: &Signer) -> (Holder, Signer) {
    let (h, g) = guarded(t, pa).await;
    let p = b(&(Signer::ed("frank").key(), None::<String>));
    let op = t.op(OP_START_RECOVERY, &g.ua(), &h, 0, &p);
    t.ok(&t.relayer, "mtx_start_recovery", &op, &g.sign(&op, ORIGIN), &p).await;
    (h, g)
}

#[tokio::test]
async fn relay_fee_cancel_recovery_ok() {
    let (t, pa, py) = two().await;
    let (h, _) = recovering(&t, &pa).await;
    let e = t.entry("cancel_recovery", &pa, t.op(OP_CANCEL_RECOVERY, &h, &h, 1, &[]), vec![]);
    t.relay(&t.relayer, &e, &py, &t.marker()).await;
    assert_eq!(t.subject(&h).await.unwrap().recovery, None);
}

/// Task 5 made finish guardian-signed (op 11, params `[KEYOP_FINISH_RECOVERY]`): ruling (a) wraps it.
#[tokio::test]
async fn relay_fee_finish_recovery_ok() {
    let (t, pa, py) = two().await;
    let (h, g) = recovering(&t, &pa).await;
    let mut s = t.subject(&h).await.unwrap();
    s.recovery.as_mut().unwrap().ready_at -= RECOVERY_DELAY_S; // the sandbox clock cannot jump two days
    t.w.patch_state(t.token.id(), &[b"a".as_slice(), &b(&h)].concat(), &b(&s)).await.unwrap();
    let e = t.entry("finish_recovery", &g, t.op(OP_START_RECOVERY, &g.ua(), &h, 1, &[KEYOP_FINISH_RECOVERY]), vec![]);
    t.relay(&t.relayer, &e, &py, &t.marker()).await;
    assert_eq!(t.subject(&h).await.unwrap().keys, vec![pa.key(), Signer::ed("frank").key()]);
}

/// The owner pays the fee from the balance the open also draws from: the check counts both (`funding + fee`), a
/// balance one short is refused by the check and the call alike, nothing moves.
#[tokio::test]
async fn relay_fee_mandate_open_ok() {
    let t = setup().await;
    let pa = Signer::pk(1, RP);
    let h = pa.ua();
    t.fund(&h, 1_000 + FEE).await;
    let terms = t.terms(&Signer::ed("dele").ua(), 1_000);
    let (op, id) = t.open_op(&h, &terms);
    let e = t.entry("mandate_open", &pa, op, b(&terms));
    let r = t.fee_ref(&e, SALT);
    let short = t.pay_op(&h, &t.marker(), FEE + 1, r, SALT);
    t.fee_refused(&t.relayer, &e, &short, &pa.sign(&short, ORIGIN), "doesn't have enough balance").await;
    assert_eq!(t.balance(&h).await, 1_000 + FEE);
    t.relay(&t.relayer, &e, &pa, &t.marker()).await;
    assert_eq!(t.balance(&Holder::Ua(id)).await, 1_000);
}

#[tokio::test]
async fn relay_fee_revoke_ok() {
    let (t, pa, py) = two().await;
    let h = pa.ua();
    t.fund(&h, 1_000).await;
    let terms = t.terms(&Signer::ed("dele").ua(), 1_000);
    let (op, id) = t.open_op(&h, &terms);
    t.ok(&t.relayer, "mtx_mandate_open", &op, &pa.sign(&op, ORIGIN), &b(&terms)).await;
    let e = t.entry("revoke", &pa, t.op(OP_REVOKE, &h, &Holder::Ua(id), 0, &[]), vec![]);
    t.relay(&t.relayer, &e, &py, &t.marker()).await;
    let m: Option<Mandate> = t.token.view("mandate").args(b(&id)).await.unwrap().borsh().unwrap();
    assert!(m.unwrap().revoked);
    assert_eq!(t.balance(&h).await, 1_000, "funds back to the owner");
}

#[tokio::test]
async fn relay_fee_cancel_ok() {
    let (t, pa, py) = two().await;
    let h = pa.ua();
    let p = b(&([0xc0u8; 32], 5u64));
    let e = t.entry("cancel", &pa, t.op(OP_CANCEL, &h, &h, 0, &p), p);
    t.relay(&t.relayer, &e, &py, &t.marker()).await;
    let c: Option<OrderClose> = t.token.view("order_closed").args(b(&(h, [0xc0u8; 32], 5u64))).await.unwrap().borsh().unwrap();
    assert_eq!(c, Some(OrderClose::Cancelled));
}

#[tokio::test]
async fn relay_fee_invalidate_nonces_ok() {
    let (t, pa, py) = two().await;
    let h = pa.ua();
    let p = b(&([0xc0u8; 32], 10u64));
    let e = t.entry("invalidate_nonces", &pa, t.op(OP_INVALIDATE_NONCES, &h, &h, 0, &p), p);
    t.relay(&t.relayer, &e, &py, &t.marker()).await;
    let m: u64 = t.token.view("min_nonce").args(b(&(h, [0xc0u8; 32]))).await.unwrap().borsh().unwrap();
    assert_eq!(m, 10);
}

// ------------------------------------------------------------------------------------------- payee, refusal, shape

/// `invalidate_nonces` of `pa` (ed25519 here) at `min_nonce`.
fn invalidate<'a>(t: &T, s: &Signer, min_nonce: u64) -> Entry<'a> {
    let h = s.ua();
    let p = b(&([0xc0u8; 32], min_nonce));
    t.entry("invalidate_nonces", s, t.op(OP_INVALIDATE_NONCES, &h, &h, 0, &p), p)
}

/// CTR-MTX-27 step 5 / spec §2 row 9: any relayer may submit; open mode (`to` = the token, the marker) pays the
/// predecessor that submitted, never the token.
#[tokio::test]
async fn wrapper_open_mode_pays_predecessor() {
    let t = setup().await;
    let (erin, carol) = (Signer::ed("erin"), Signer::k1("carol"));
    t.fund(&carol.ua(), 100).await;
    let pool = t.balance(&t.marker()).await;
    t.relay(&t.bob, &invalidate(&t, &erin, 3), &carol, &t.marker()).await;
    assert_eq!(t.balance(&t.near(&t.bob)).await, FEE, "bob submitted: bob paid");
    assert!(!t.registered(&t.relayer).await, "the other relayer gets nothing");
    assert_eq!(pool - t.balance(&t.marker()).await, FEE, "the token's own balance is only the UA pool (the payer left it)");
}

/// A bound payee (`to` ≠ the token) is paid directly, whoever submits.
#[tokio::test]
async fn wrapper_bound_payee_paid_directly() {
    let t = setup().await;
    let (erin, carol) = (Signer::ed("erin"), Signer::k1("carol"));
    t.fund(&carol.ua(), 100).await;
    t.relay(&t.relayer, &invalidate(&t, &erin, 3), &carol, &t.near(&t.alice)).await;
    assert!(!t.registered(&t.relayer).await, "the submitting relayer is not paid");
}

/// Spec §3.8: a refused entry panics, so nothing is paid — a cancel of a filled order, and the no-op wrappers (review
/// T9 m4): a cancel of an already-cancelled order, a revoke of an already-revoked mandate.
#[tokio::test]
async fn refused_entry_pays_nothing() {
    let (t, pa, py) = two().await;
    let h = pa.ua();
    let key = [b"o".as_slice(), &b(&(h.clone(), [0xc0u8; 32], 5u64))].concat();
    t.w.patch_state(t.token.id(), &key, &b(&OrderClose::Filled([0xee; 32]))).await.unwrap();
    let p = b(&([0xc0u8; 32], 5u64));
    let e = t.entry("cancel", &pa, t.op(OP_CANCEL, &h, &h, 0, &p), p);
    let pay = t.pay_op(&py.ua(), &t.marker(), FEE, t.fee_ref(&e, SALT), SALT);
    t.fee_refused(&t.relayer, &e, &pay, &py.sign(&pay, ORIGIN), "order filled: cancel refused").await;
    assert_eq!(t.subject(&h).await, None, "the entry wrote nothing (no lazy open)");
    // cancel of an order already cancelled (plain mtx_cancel first)
    let p = b(&([0xc0u8; 32], 6u64));
    let op = t.op(OP_CANCEL, &h, &h, 0, &p);
    t.ok(&t.relayer, "mtx_cancel", &op, &pa.sign(&op, ORIGIN), &p).await;
    let e = t.entry("cancel", &pa, op, p);
    let pay = t.pay_op(&py.ua(), &t.marker(), FEE, t.fee_ref(&e, SALT), SALT);
    t.fee_refused(&t.relayer, &e, &pay, &py.sign(&pay, ORIGIN), "order already cancelled").await;
    // revoke of a mandate already revoked (plain mtx_revoke first)
    t.fund(&h, 1_000).await;
    let terms = t.terms(&Signer::ed("dele").ua(), 1_000);
    let (op, id) = t.open_op(&h, &terms);
    t.ok(&t.relayer, "mtx_mandate_open", &op, &pa.sign(&op, ORIGIN), &b(&terms)).await;
    let op = t.op(OP_REVOKE, &h, &Holder::Ua(id), 0, &[]);
    t.ok(&t.relayer, "mtx_revoke", &op, &pa.sign(&op, ORIGIN), &[]).await;
    let e = t.entry("revoke", &pa, op, vec![]);
    let pay = t.pay_op(&py.ua(), &t.marker(), FEE, t.fee_ref(&e, SALT), SALT);
    t.fee_refused(&t.relayer, &e, &pay, &py.sign(&pay, ORIGIN), "mandate revoked").await;
    assert_eq!(t.balance(&py.ua()).await, 1_000, "the payer paid nothing across the three refusals");
}

/// Shape (spec §3.8, R2): `pay_ref = ref`, `lane = payLane(ref)`, nonce 0, `relayer` = the token, op 0 — each violation
/// refused, the entry not applied. `ref`'s salt is the payment's own `extra`, always (§2 row 8, pre-flight (e)): a
/// payment signed with another `extra` than the salt its `pay_ref` was made with is refused. The valid payment never
/// settles through a plain pay entry (rule 7). A replay of the whole wrapper is refused.
#[tokio::test]
async fn pay_op_shape_enforced() {
    let t = setup().await;
    let (erin, carol) = (Signer::ed("erin"), Signer::k1("carol"));
    let payer = carol.ua();
    t.fund(&payer, 100).await;
    let e = invalidate(&t, &erin, 3);
    let r = t.fee_ref(&e, SALT);
    let good = t.pay_op(&payer, &t.marker(), FEE, r, SALT);
    let relayer = Some(t.relayer.id().as_str().parse().unwrap());
    let cases: [(&str, MetaOp); 7] = [
        ("pay_ref ≠ ref", MetaOp { pay_ref: [7; 32], lane: pay_lane(&[7; 32]), ..good.clone() }),
        ("lane ≠ payLane(ref)", MetaOp { lane: [7; 32], ..good.clone() }),
        ("nonce ≠ 0", MetaOp { nonce: 1, ..good.clone() }),
        ("relayer None", MetaOp { relayer: None, ..good.clone() }),
        ("relayer = the submitter", MetaOp { relayer: relayer.clone(), ..good.clone() }),
        ("op 5", MetaOp { op: OP_EXECUTE_TRANSFER, ..good.clone() }),
        ("extra ≠ the salt of pay_ref", MetaOp { extra: [0x5b; 32], ..good.clone() }),
    ];
    for (what, pay) in cases {
        println!("shape case: {what}");
        t.fee_refused(&t.relayer, &e, &pay, &carol.sign(&pay, ORIGIN), SHAPE).await;
    }
    assert_eq!(t.subject(&erin.ua()).await, None, "no entry applied");
    // never through a plain pay entry: open mode pays the token itself (rule 12), a bound payment names the token as
    // relayer (rule 7)
    t.refused(&t.relayer, "mtx_pay", &good, &carol.sign(&good, ORIGIN), &[], TO_SELF).await;
    let bound = MetaOp { to: t.near(&t.alice), ..good.clone() };
    t.refused(&t.relayer, "mtx_pay", &bound, &carol.sign(&bound, ORIGIN), &[], RELAYER).await;
    let ga = carol.sign(&good, ORIGIN);
    let (c, out) = t.fee_exec(&t.relayer, &e, &good, &ga).await;
    assert!(c.error.is_none() && out.is_success(), "{:?}", out.failures());
    // replay: refused by the entry's state (min_nonce only increases) and the spent payment lane
    let (c, out) = t.fee_exec(&t.relayer, &e, &good, &ga).await;
    assert!(c.error.is_some() && out.is_failure());
    assert_eq!(t.balance(&payer).await, 100 - FEE, "paid once");
}

/// R8 / NET-ALL-23 item 3: the payer's `POLICY_PASSKEY_FOR_VALUE` binds the routed payment as `mtx_pay`.
#[tokio::test]
async fn wrapper_payment_policy_passkey_for_value() {
    let t = setup().await;
    let (erin, pk, dan) = (Signer::ed("erin"), Signer::pk(4, RP), Signer::ed("dan"));
    let h = erin.ua();
    t.fund(&h, 100).await;
    let p = b(&(pk.key(), Some(ORIGIN.to_string())));
    let op = t.op(OP_ADD_KEY, &h, &h, 0, &p);
    t.ok(&t.relayer, "mtx_add_key", &op, &erin.sign(&op, ORIGIN), &p).await;
    let p = b(&POLICY_PASSKEY_FOR_VALUE);
    let op = t.op(OP_SET_GUARDIAN, &h, &h, 1, &[KEYOP_SET_POLICY, 1]);
    t.ok(&t.relayer, "mtx_set_policy", &op, &erin.sign(&op, ORIGIN), &p).await;
    let e = invalidate(&t, &dan, 3);
    let pay = t.pay_op(&h, &t.marker(), FEE, t.fee_ref(&e, SALT), SALT);
    t.fee_refused(&t.relayer, &e, &pay, &erin.sign(&pay, ORIGIN), POLICY).await;
    t.relay_as(&t.relayer, &e, &pk, &h, &t.marker()).await;
}

// ------------------------------------------------------------------------------------------- 300 Tgas (R1)

/// Spec §3.5 gate / R1: the costliest wrapper (`relay_fee_mandate_open`, measured: see the gas log) with a passkey entry
/// auth and a passkey payment succeeds at 300 Tgas prepaid, burnt ≤ 300 Tgas; the margin goes to the gas log.
#[tokio::test]
async fn near_relay_fee_two_passkey_within_300_tgas() {
    let t = setup().await;
    let (pa, py) = (Signer::pk(1, RP), Signer::pk(2, RP));
    t.fund(&pa.ua(), 1_000).await;
    t.fund(&py.ua(), 1_000).await;
    let terms = t.terms(&Signer::ed("dele").ua(), 1_000);
    let (op, _) = t.open_op(&pa.ua(), &terms);
    let out = t.relay(&t.relayer, &t.entry("mandate_open", &pa, op, b(&terms)), &py, &t.marker()).await;
    println!("GAS two-passkey relay_fee_mandate_open: {:.3} Tgas burnt, margin {:.3} Tgas to 300", tgas(&out), 300.0 - tgas(&out));
}

/// R1: the costliest wrapper (`relay_fee_mandate_open`, review T9 m2) with entry auth = an msig of `MSIG_MAX_MEMBERS`
/// (12) passkey members, all signing (threshold 12), owning and funding the mandate, plus a passkey payment: fits 300
/// Tgas.
#[tokio::test]
async fn relay_fee_msig_cap_fits_300_tgas() {
    let t = setup().await;
    let py = Signer::pk(2, RP);
    t.fund(&py.ua(), 1_000).await;
    let mut ms: Vec<Signer> = (20..20 + ua::MSIG_MAX_MEMBERS as u8).map(|i| Signer::pk(i, RP)).collect();
    ms.sort_by_key(|s| s.key().id());
    let n = ms.len() as u8;
    let body: Vec<u8> = ms.iter().flat_map(|s| [&ua::KIND_WEBAUTHN_P256.to_be_bytes()[..], &s.key().id(), &[0, 1]].concat()).collect();
    let kd = [&[0u8, n, 0, n][..], &body].concat();
    let m = Holder::Ua(ua::ua_of(KIND_MSIG, &kd));
    t.fund(&m, 1_000).await;
    let terms = t.terms(&Signer::ed("dele").ua(), 1_000);
    let (op, id) = t.open_op(&m, &terms);
    let auth = Auth::Msig { key_data: kd.clone(), sigs: ms.iter().enumerate().map(|(i, s)| (i as u8, s.sign(&op, ORIGIN))).collect() };
    let e = Entry { name: "mandate_open", op, auth, params: b(&terms) };
    let out = t.relay(&t.relayer, &e, &py, &t.marker()).await;
    assert_eq!(t.balance(&Holder::Ua(id)).await, 1_000, "the mandate funded");
    println!("GAS msig-cap ({n} passkey signatures) + passkey payment, relay_fee_mandate_open: {:.3} Tgas burnt, margin {:.3} Tgas to 300", tgas(&out), 300.0 - tgas(&out));
}
