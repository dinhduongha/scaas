//! Mandate (spec §3.6, README §3 item 2, CTR-ACC-06 / CTR-ACC-07 / CTR-ACC-12; rulings R8, R9): a delegate pays from
//! funds the owner moved into the token ledger under the mandate's id, within limits checked here — per payment, per
//! period (fixed windows on a grid, CTR-ACC-07), one payee, an expiry, revocation, each `pay_ref` once. No pay-meta
//! entry (metatx-split §6.2). One-shot: a revoked mandate stays revoked; a new one is a new open.
//!
//! - `mtx_mandate_open(op, auth, terms)`, op 13, signed by the owner (`op.from`): a value op on the owner's lane `(from,
//!   lane)` at its next nonce; `id = sha256(Borsh(from, terms, lane, nonce))`, `to = Ua(id)`, `amount = terms.funding`
//!   (R9), `extra = sha256(Borsh(id, terms))`, `pay_ref` zero. The funds sit in the UA ledger under `id` (no key derives
//!   it, so only this module moves them).
//! - `mtx_mandate_pay(op, auth)`, op 2, signed by `terms.delegate` (any SCaaS subject: its keys, lazily opened as any
//!   signer): `from = Ua(id)`, `to = terms.payee`, `pay_ref ≠ 0`, `lane = payLane(pay_ref)`, nonce 0 on the mandate's
//!   own lanes (so a `pay_ref` pays once per mandate), `extra = sha256([])`; the pay body is `settle_pay`. The
//!   delegate's own `POLICY_PASSKEY_FOR_VALUE` applies (R8: the signer's policy).
//! - `mtx_revoke(op, auth)`, op 3, signed by the owner or the delegate (kill switch): `to = Ua(id)`, amount, `pay_ref`,
//!   lane and nonce zero, `extra = sha256([])`; once (a revoked mandate refuses it). The balance goes back to the owner.
//! - `mandate_refund(id)`, anyone, after revocation or expiry: the balance (funds that arrived later) to the owner.
//!
//! The entry bodies (`mandate_open`, `mandate_pay`, `revoke`) charge nothing themselves: the `mtx_*` entries and Task 9's
//! `relay_fee_<entry>` wrappers call them, then `charge_storage` once.
use crate::account::now_s;
use crate::metatx::{lane_bytes, value_policy, x};
use crate::{record_bytes, Check, Event, Holder, Subject, Token, TokenExt};
use near_sdk::json_types::U128;
use near_sdk::{borsh, env, near, AccountId};
use scaas_near_common::auth::Auth;
use scaas_near_common::hash::pay_lane;
use scaas_near_common::metaop::*;

/// Bytes of one mandate record = this + Borsh(Mandate): key prefix `m` (1) + id (32) + NEAR's per-record overhead (40).
/// `new` measures one record against it.
pub const MANDATE_RECORD_OVERHEAD: u64 = 73;

type R<T> = Result<T, &'static str>;

#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MandateTerms {
    /// Signs every `mtx_mandate_pay` (README §3 item 2 "a delegate signs"; a UA may delegate, CTR-ACC-12).
    pub delegate: Holder,
    pub payee: Holder,
    pub per_payment: u128,
    pub per_period: u128,
    pub period_s: u64,
    /// Seconds; a pay after it is refused.
    pub expiry: u64,
    /// The amount moved in at the open: equals `op.amount` (R9).
    pub funding: u128,
}

#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mandate {
    pub owner: Holder,
    pub terms: MandateTerms,
    pub period_start: u64,
    pub spent: u128,
    pub revoked: bool,
}

pub fn mandate_bytes(m: &Mandate) -> u64 {
    MANDATE_RECORD_OVERHEAD + borsh::to_vec(m).unwrap().len() as u64
}

/// The id of the mandate an open op creates: `sha256(Borsh(from, terms, lane, nonce))`.
pub fn mandate_id(from: &Holder, terms: &MandateTerms, lane: &[u8; 32], nonce: u64) -> [u8; 32] {
    env::sha256_array(borsh::to_vec(&(from, terms, lane, nonce)).unwrap())
}

fn no_params() -> [u8; 32] {
    env::sha256_array([])
}

/// `Check` from a plan's new bytes.
fn check(r: R<u64>) -> Check {
    match r {
        Ok(bytes) => Check { error: None, storage_needed: U128(env::storage_byte_cost().as_yoctonear() * bytes as u128) },
        Err(e) => Check { error: Some(e.into()), storage_needed: U128(0) },
    }
}

/// A signer's record after `signed` and the bytes of a lazy open.
struct Signer {
    who: Holder,
    subject: Subject,
    old: u64,
}

impl Signer {
    fn open_bytes(&self) -> u64 {
        if self.old == 0 { record_bytes(&self.who, &self.subject) } else { 0 }
    }
}

impl Token {
    fn load_mandate(&self, h: &Holder) -> R<([u8; 32], Mandate)> {
        let Holder::Ua(id) = h else { return Err("no such mandate") };
        self.mandates.get(id).map(|m| (*id, m.clone())).ok_or("no such mandate")
    }

    /// No write: the open's shape and terms (R9), then the plain value checks (`pay_checks`: the owner's signature,
    /// relayer, value policy, lane nonce, balance). Returns the owner, the new record and every new byte.
    fn open_plan(&self, caller: &AccountId, op: &MetaOp, auth: &Auth, terms: &MandateTerms) -> R<(Signer, Mandate, u64)> {
        if op.op != OP_MANDATE_OPEN {
            return Err("wrong op code");
        }
        if op.pay_ref != [0; 32] {
            return Err("mtx_mandate_open carries no pay_ref");
        }
        if terms.funding != op.amount {
            return Err("terms.funding must equal op.amount");
        }
        if terms.period_s == 0 || terms.per_payment == 0 || terms.per_payment > terms.per_period {
            return Err("bad mandate limits (period_s > 0, 0 < per_payment <= per_period)");
        }
        if terms.expiry <= now_s() {
            return Err("mandate expiry is past");
        }
        let id = mandate_id(&op.from, terms, &op.lane, op.nonce);
        if op.to != Holder::Ua(id) {
            return Err("to must be the mandate id");
        }
        if op.extra != env::sha256_array(borsh::to_vec(&(id, terms)).unwrap()) {
            return Err("extra is not sha256 of the mandate id and terms");
        }
        if terms.payee == Holder::Near(env::current_account_id()) {
            return Err("token refuses a transfer to the token itself");
        }
        let (subject, old, bytes) = self.pay_checks(caller, caller, op, auth, &op.to)?;
        let m = Mandate { owner: op.from.clone(), terms: terms.clone(), period_start: now_s(), spent: 0, revoked: false };
        let b = bytes + mandate_bytes(&m);
        Ok((Signer { who: op.from.clone(), subject, old }, m, b))
    }

    /// No write: the pay's shape, the mandate's state and limits (the period moved on its grid), the delegate's
    /// signature and value policy, `pay_ref` unused, the balance. Returns the delegate, the updated mandate, new bytes.
    fn pay_plan(&self, caller: &AccountId, op: &MetaOp, auth: &Auth) -> R<(Signer, Mandate, u64)> {
        if op.op != OP_MANDATE_PAY {
            return Err("wrong op code");
        }
        let (_, mut m) = self.load_mandate(&op.from)?;
        if op.pay_ref == [0; 32] || op.lane != pay_lane(&op.pay_ref) || op.nonce != 0 || op.extra != no_params() {
            return Err("mandate pay shape (pay_ref set, lane = payLane(pay_ref), nonce 0, extra = sha256([]))");
        }
        if m.revoked {
            return Err("mandate revoked");
        }
        let now = now_s();
        if now > m.terms.expiry {
            return Err("mandate expired");
        }
        if op.to != m.terms.payee {
            return Err("payee not allowed");
        }
        if op.amount == 0 {
            return Err("The amount should be a positive number");
        }
        if op.amount > m.terms.per_payment {
            return Err("over the per-payment cap");
        }
        // CTR-ACC-07: fixed windows on the grid from the open, never restarted at `now`
        let p = m.terms.period_s;
        let elapsed = now.saturating_sub(m.period_start);
        if elapsed >= p {
            m.period_start += elapsed / p * p;
            m.spent = 0;
        }
        // compared by subtraction: `spent <= per_period` always, so no overflow
        if op.amount > m.terms.per_period - m.spent {
            return Err("over the per-period cap");
        }
        m.spent += op.amount;
        let (subject, old) = self.signed_by(caller, caller, op, auth, &m.terms.delegate)?;
        value_policy(&subject, auth)?;
        if self.next_nonce(&op.from, &op.lane).is_some() {
            return Err("pay_ref already paid under this mandate");
        }
        if self.balance(&op.from) < op.amount {
            return Err("the mandate's balance is short");
        }
        let s = Signer { who: m.terms.delegate.clone(), subject, old };
        let bytes = s.open_bytes() + lane_bytes(&op.from) + self.receiver_bytes(&op.to);
        Ok((s, m, bytes))
    }

    /// No write: the revoke's shape, the signer is the owner or the delegate, its signature, the mandate not revoked.
    fn revoke_plan(&self, caller: &AccountId, op: &MetaOp, auth: &Auth) -> R<(Signer, [u8; 32], Mandate)> {
        if op.op != OP_REVOKE || op.amount != 0 || op.pay_ref != [0; 32] || op.lane != [0; 32] || op.nonce != 0 {
            return Err("revoke shape (op 3, amount 0, pay_ref, lane and nonce zero)");
        }
        if op.extra != no_params() {
            return Err("extra is not sha256 of the parameters");
        }
        let (id, m) = self.load_mandate(&op.to)?;
        if op.from != m.owner && op.from != m.terms.delegate {
            return Err("only the owner or the delegate revokes");
        }
        if m.revoked {
            return Err("mandate revoked");
        }
        let (subject, old) = self.signed(caller, caller, op, auth)?;
        Ok((Signer { who: op.from.clone(), subject, old }, id, m))
    }

    /// The whole balance under the mandate's id back to its owner (registered: it funded the mandate).
    fn sweep(&mut self, id: [u8; 32], m: &Mandate) {
        let bal = self.balance(&Holder::Ua(id));
        if bal > 0 {
            self.move_balance(&Holder::Ua(id), &m.owner, bal, None);
        }
    }

    pub(crate) fn mandate_open(&mut self, op: &MetaOp, auth: &Auth, terms: &MandateTerms) {
        let p = env::predecessor_account_id();
        let (s, m, _) = self.open_plan(&p, op, auth, terms).unwrap_or_else(|e| env::panic_str(e));
        let Holder::Ua(id) = op.to else { unreachable!() };
        self.open_lazily(&s.who, s.subject, s.old);
        self.storage_due += mandate_bytes(&m);
        self.mandates.insert(id, m);
        self.settle_pay(op, &op.from, &op.to);
        Event::Mandate { mandate: x(&id), action: "open".into(), by: op.from.to_string() }.emit();
    }

    pub(crate) fn mandate_pay(&mut self, op: &MetaOp, auth: &Auth) {
        let p = env::predecessor_account_id();
        let (s, m, _) = self.pay_plan(&p, op, auth).unwrap_or_else(|e| env::panic_str(e));
        let Holder::Ua(id) = op.from else { unreachable!() };
        self.open_lazily(&s.who, s.subject, s.old);
        self.mandates.insert(id, m);
        self.settle_pay(op, &op.from, &op.to);
    }

    pub(crate) fn revoke(&mut self, op: &MetaOp, auth: &Auth) {
        let p = env::predecessor_account_id();
        let (s, id, mut m) = self.revoke_plan(&p, op, auth).unwrap_or_else(|e| env::panic_str(e));
        self.open_lazily(&s.who, s.subject, s.old);
        m.revoked = true;
        self.sweep(id, &m);
        self.mandates.insert(id, m);
        Event::Mandate { mandate: x(&id), action: "revoke".into(), by: op.from.to_string() }.emit();
    }
}

#[near]
impl Token {
    #[payable]
    pub fn mtx_mandate_open(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] terms: MandateTerms,
    ) {
        self.mandate_open(&op, &auth, &terms);
        self.charge_storage();
    }

    #[payable]
    pub fn mtx_mandate_pay(&mut self, #[serializer(borsh)] op: MetaOp, #[serializer(borsh)] auth: Auth) {
        self.mandate_pay(&op, &auth);
        self.charge_storage();
    }

    #[payable]
    pub fn mtx_revoke(&mut self, #[serializer(borsh)] op: MetaOp, #[serializer(borsh)] auth: Auth) {
        self.revoke(&op, &auth);
        self.charge_storage();
    }

    /// Anyone, once the mandate is revoked or expired: its balance back to the owner (nothing to attach).
    pub fn mandate_refund(&mut self, #[serializer(borsh)] id: [u8; 32]) {
        let (_, m) = self.load_mandate(&Holder::Ua(id)).unwrap_or_else(|e| env::panic_str(e));
        if !m.revoked && now_s() <= m.terms.expiry {
            env::panic_str("mandate live: no refund before revocation or expiry");
        }
        self.sweep(id, &m);
    }

    #[result_serializer(borsh)]
    pub fn mandate(&self, #[serializer(borsh)] id: [u8; 32]) -> Option<Mandate> {
        self.mandates.get(&id).cloned()
    }

    #[result_serializer(borsh)]
    pub fn mtx_mandate_open_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] terms: MandateTerms,
    ) -> Check {
        check(self.open_plan(&caller, &op, &auth, &terms).map(|(_, _, b)| b))
    }

    #[result_serializer(borsh)]
    pub fn mtx_mandate_pay_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
    ) -> Check {
        check(self.pay_plan(&caller, &op, &auth).map(|(_, _, b)| b))
    }

    #[result_serializer(borsh)]
    pub fn mtx_revoke_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
    ) -> Check {
        check(self.revoke_plan(&caller, &op, &auth).map(|(s, _, _)| s.open_bytes()))
    }
}

#[cfg(test)]
mod tests {
    //! The contract's mandate derivation against `near-vectors.json` (gen_vectors.py `mandate_vectors`, ruling R5).
    use super::*;
    use near_sdk::serde_json::{self, Value};

    const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/near-vectors.json");

    fn hx(v: &Value) -> Vec<u8> {
        let s = v.as_str().unwrap().trim_start_matches("0x");
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn b32(v: &Value) -> [u8; 32] {
        hx(v).try_into().unwrap()
    }

    #[test]
    fn mandate_vectors_match() {
        let d: Value = serde_json::from_str(&std::fs::read_to_string(VECTORS).unwrap()).unwrap();
        let rows = d["metaops"]["vectors"].as_array().unwrap();
        let row = |n: &str| rows.iter().find(|r| r["name"] == n).unwrap_or_else(|| panic!("no row {n}"));
        let (open, pay, rev) = (row("mandate_open"), row("mandate_pay"), row("mandate_revoke"));
        let terms: MandateTerms = borsh::from_slice(&hx(&open["terms"])).unwrap();
        assert_eq!(terms.funding.to_string(), open["fields"]["amount"].as_str().unwrap(), "R9: funding = amount");
        let from = Holder::Ua(b32(&open["fields"]["from"]["Ua"]));
        let (lane, nonce) = (b32(&open["fields"]["lane"]), open["fields"]["nonce"].as_u64().unwrap());
        let id = mandate_id(&from, &terms, &lane, nonce);
        assert_eq!(id, b32(&open["mandateId"]));
        assert_eq!(id, b32(&open["fields"]["to"]["Ua"]));
        assert_eq!(env::sha256_array(borsh::to_vec(&(id, &terms)).unwrap()), b32(&open["fields"]["extra"]));
        assert_eq!(open["fields"]["op"], OP_MANDATE_OPEN);
        assert_eq!((b32(&pay["fields"]["from"]["Ua"]), pay["fields"]["op"].as_u64()), (id, Some(OP_MANDATE_PAY as u64)));
        assert_eq!(b32(&pay["fields"]["lane"]), pay_lane(&b32(&pay["fields"]["pay_ref"])));
        for r in [pay, rev] {
            assert_eq!(b32(&r["fields"]["extra"]), no_params(), "{}", r["name"]);
        }
        assert_eq!((b32(&rev["fields"]["to"]["Ua"]), rev["fields"]["op"].as_u64()), (id, Some(OP_REVOKE as u64)));
    }
}
