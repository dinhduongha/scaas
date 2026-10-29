//! Relay-fee wrappers (spec §3.8 "Wrappers (atomic)", §2 rows 8–14; CTR-MTX-27; rulings R2, R6, T9 pre-flight a–f).
//! `relay_fee_<entry>(entry arguments…, pay_op, pay_auth)` runs the body of the fee-less signed entry `mtx_<entry>`
//! (which panics on a refusal, so nothing is paid), then the payer's routed pay: `routed_plan` with the token's own id
//! as the marker (`pay_ref = ref`, `lane = payLane(ref)`, nonce 0, `relayer == Some(token)`: no plain entry can settle
//! it, rule 7), the payee = the predecessor in open mode (`to` = the token) else `to`, the value policy (R8), then
//! `settle_pay`, the storage of both charged once from the attached deposit, and `relay_fee_paid` last. One receipt, no
//! cross-contract call: a panic anywhere reverts the entry and the payment together.
//!
//! `ref = keccak256("scaas.relayfee" ‖ network ‖ u8 len ‖ token id ‖ keccak256(call) ‖ pay_op.extra)` with `call = u8
//! len ‖ "mtx_<entry>" ‖ Borsh(entry arguments)` (`op`, `auth`, then the entry's parameters, as the entry takes them),
//! recomputed here from the arguments actually run. `relay_fee_<entry>_check(caller, …)` returns the error of either
//! part, or the deposit both need (Task 16's simulate). Wrapped: every key op (`mtx_set_policy` and the guardian's
//! `mtx_finish_recovery` included), `mtx_mandate_open`, `mtx_revoke`, `mtx_cancel`, `mtx_invalidate_nonces`.
use crate::account::{check_of, Action};
use crate::metatx::x;
use crate::{record_bytes, Check, Event, Holder, MandateTerms, Token, TokenExt};
use near_sdk::borsh::{self, BorshSerialize};
use near_sdk::json_types::U128;
use near_sdk::{env, near, AccountId};
use scaas_near_common::auth::Auth;
use scaas_near_common::hash::relay_ref;
use scaas_near_common::metaop::MetaOp;
use scaas_near_common::ua::KeyRecord;

type R<T> = Result<T, &'static str>;

/// Spec §2 row 8 for a wrapper: target = u8 len ‖ this token's id, `call` = u8 len ‖ `entry` ‖ `args`, `salt` = the
/// payment's `extra`.
pub fn wrapper_ref(network: &[u8; 32], entry: &str, args: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    let me = env::current_account_id();
    let target = [&[me.as_str().len() as u8][..], me.as_bytes()].concat();
    relay_ref(network, &target, &[&[entry.len() as u8][..], entry.as_bytes(), args].concat(), salt)
}

impl Token {
    fn fee_ref(&self, entry: &str, args: &impl BorshSerialize, pay: &MetaOp) -> [u8; 32] {
        wrapper_ref(&self.network, entry, &borsh::to_vec(args).expect("borsh"), &pay.extra)
    }

    /// After the entry body: the routed pay of `pay` for `r`, the storage of the whole call, then `relay_fee_paid`.
    fn relay_fee_pay(&mut self, r: [u8; 32], pay: &MetaOp, pay_auth: &Auth) {
        let (p, me) = (env::predecessor_account_id(), env::current_account_id());
        let rt = self.routed_plan(&p, &me, &Holder::Near(p.clone()), pay, pay_auth, &r).unwrap_or_else(|e| env::panic_str(e));
        self.open_lazily(&pay.from, rt.subject, rt.old);
        self.settle_pay(pay, &pay.from, &rt.payee);
        self.charge_storage();
        Event::RelayFeePaid {
            r#ref: x(&r),
            target: me.to_string(),
            token: me.to_string(),
            payer: pay.from.to_string(),
            payee: rt.payee.to_string(),
            amount: U128(pay.amount),
        }
        .emit();
    }

    /// `entry`'s checks (`bytes`), then the payment's against the state now. When the entry's signer pays, the entry
    /// opens its record first (the payment never opens it twice) and draws `op.amount` first (`mtx_mandate_open`).
    #[allow(clippy::too_many_arguments)]
    fn relay_fee_check(&self, caller: &AccountId, entry: &str, args: &impl BorshSerialize, op: &MetaOp, bytes: R<u64>, pay: &MetaOp, pay_auth: &Auth) -> Check {
        check_of(bytes.and_then(|b| {
            let me = env::current_account_id();
            let rt = self.routed_plan(caller, &me, &Holder::Near(caller.clone()), pay, pay_auth, &self.fee_ref(entry, args, pay))?;
            if pay.from != op.from {
                return Ok(b + rt.bytes);
            }
            if self.balance(&pay.from) < op.amount.saturating_add(pay.amount) {
                return Err(match pay.from {
                    Holder::Near(_) => "The account doesn't have enough balance",
                    Holder::Ua(_) => "The UA doesn't have enough balance",
                });
            }
            Ok(b + rt.bytes - if rt.old == 0 { record_bytes(&pay.from, &rt.subject) } else { 0 })
        }))
    }
}

#[near]
impl Token {
    #[payable]
    pub fn relay_fee_add_key(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] key: KeyRecord,
        #[serializer(borsh)] origin: Option<String>,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) {
        let r = self.fee_ref("mtx_add_key", &(&op, &auth, &key, &origin), &pay_op);
        self.key_op(&op, &auth, Action::AddKey(key, origin));
        self.relay_fee_pay(r, &pay_op, &pay_auth);
    }

    #[payable]
    pub fn relay_fee_remove_key(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] key: KeyRecord,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) {
        let r = self.fee_ref("mtx_remove_key", &(&op, &auth, &key), &pay_op);
        self.key_op(&op, &auth, Action::RemoveKey(key));
        self.relay_fee_pay(r, &pay_op, &pay_auth);
    }

    #[payable]
    pub fn relay_fee_add_origin(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] origin: String,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) {
        let r = self.fee_ref("mtx_add_origin", &(&op, &auth, &origin), &pay_op);
        self.key_op(&op, &auth, Action::AddOrigin(origin));
        self.relay_fee_pay(r, &pay_op, &pay_auth);
    }

    #[payable]
    pub fn relay_fee_remove_origin(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] origin: String,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) {
        let r = self.fee_ref("mtx_remove_origin", &(&op, &auth, &origin), &pay_op);
        self.key_op(&op, &auth, Action::RemoveOrigin(origin));
        self.relay_fee_pay(r, &pay_op, &pay_auth);
    }

    #[payable]
    pub fn relay_fee_set_guardian(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] guardian: Option<Holder>,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) {
        let r = self.fee_ref("mtx_set_guardian", &(&op, &auth, &guardian), &pay_op);
        self.key_op(&op, &auth, Action::SetGuardian(guardian));
        self.relay_fee_pay(r, &pay_op, &pay_auth);
    }

    #[payable]
    pub fn relay_fee_set_policy(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] policy: u8,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) {
        let r = self.fee_ref("mtx_set_policy", &(&op, &auth, &policy), &pay_op);
        self.key_op(&op, &auth, Action::SetPolicy(policy));
        self.relay_fee_pay(r, &pay_op, &pay_auth);
    }

    #[payable]
    pub fn relay_fee_start_recovery(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] key: KeyRecord,
        #[serializer(borsh)] origin: Option<String>,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) {
        let r = self.fee_ref("mtx_start_recovery", &(&op, &auth, &key, &origin), &pay_op);
        self.key_op(&op, &auth, Action::StartRecovery(key, origin));
        self.relay_fee_pay(r, &pay_op, &pay_auth);
    }

    #[payable]
    pub fn relay_fee_cancel_recovery(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) {
        let r = self.fee_ref("mtx_cancel_recovery", &(&op, &auth), &pay_op);
        self.key_op(&op, &auth, Action::CancelRecovery);
        self.relay_fee_pay(r, &pay_op, &pay_auth);
    }

    #[payable]
    pub fn relay_fee_finish_recovery(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) {
        let r = self.fee_ref("mtx_finish_recovery", &(&op, &auth), &pay_op);
        self.key_op(&op, &auth, Action::FinishRecovery);
        self.relay_fee_pay(r, &pay_op, &pay_auth);
    }

    #[payable]
    pub fn relay_fee_mandate_open(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] terms: MandateTerms,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) {
        let r = self.fee_ref("mtx_mandate_open", &(&op, &auth, &terms), &pay_op);
        self.mandate_open(&op, &auth, &terms);
        self.relay_fee_pay(r, &pay_op, &pay_auth);
    }

    #[payable]
    pub fn relay_fee_revoke(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) {
        let r = self.fee_ref("mtx_revoke", &(&op, &auth), &pay_op);
        self.revoke(&op, &auth);
        self.relay_fee_pay(r, &pay_op, &pay_auth);
    }

    #[payable]
    pub fn relay_fee_cancel(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] target_lane: [u8; 32],
        #[serializer(borsh)] target_nonce: u64,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) {
        let r = self.fee_ref("mtx_cancel", &(&op, &auth, &target_lane, &target_nonce), &pay_op);
        self.cancel(&op, &auth, &target_lane, target_nonce);
        self.relay_fee_pay(r, &pay_op, &pay_auth);
    }

    #[payable]
    pub fn relay_fee_invalidate_nonces(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] lane: [u8; 32],
        #[serializer(borsh)] min_nonce: u64,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) {
        let r = self.fee_ref("mtx_invalidate_nonces", &(&op, &auth, &lane, &min_nonce), &pay_op);
        self.invalidate_nonces(&op, &auth, &lane, min_nonce);
        self.relay_fee_pay(r, &pay_op, &pay_auth);
    }

    // ------------------------------------------------------------------------------- `_check` views (`caller` first)

    #[result_serializer(borsh)]
    pub fn relay_fee_add_key_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] key: KeyRecord,
        #[serializer(borsh)] origin: Option<String>,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) -> Check {
        let b = self.key_op_bytes(&caller, &op, &auth, &Action::AddKey(key.clone(), origin.clone()));
        self.relay_fee_check(&caller, "mtx_add_key", &(&op, &auth, &key, &origin), &op, b, &pay_op, &pay_auth)
    }

    #[result_serializer(borsh)]
    pub fn relay_fee_remove_key_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] key: KeyRecord,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) -> Check {
        let b = self.key_op_bytes(&caller, &op, &auth, &Action::RemoveKey(key.clone()));
        self.relay_fee_check(&caller, "mtx_remove_key", &(&op, &auth, &key), &op, b, &pay_op, &pay_auth)
    }

    #[result_serializer(borsh)]
    pub fn relay_fee_add_origin_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] origin: String,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) -> Check {
        let b = self.key_op_bytes(&caller, &op, &auth, &Action::AddOrigin(origin.clone()));
        self.relay_fee_check(&caller, "mtx_add_origin", &(&op, &auth, &origin), &op, b, &pay_op, &pay_auth)
    }

    #[result_serializer(borsh)]
    pub fn relay_fee_remove_origin_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] origin: String,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) -> Check {
        let b = self.key_op_bytes(&caller, &op, &auth, &Action::RemoveOrigin(origin.clone()));
        self.relay_fee_check(&caller, "mtx_remove_origin", &(&op, &auth, &origin), &op, b, &pay_op, &pay_auth)
    }

    #[result_serializer(borsh)]
    pub fn relay_fee_set_guardian_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] guardian: Option<Holder>,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) -> Check {
        let b = self.key_op_bytes(&caller, &op, &auth, &Action::SetGuardian(guardian.clone()));
        self.relay_fee_check(&caller, "mtx_set_guardian", &(&op, &auth, &guardian), &op, b, &pay_op, &pay_auth)
    }

    #[result_serializer(borsh)]
    pub fn relay_fee_set_policy_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] policy: u8,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) -> Check {
        let b = self.key_op_bytes(&caller, &op, &auth, &Action::SetPolicy(policy));
        self.relay_fee_check(&caller, "mtx_set_policy", &(&op, &auth, &policy), &op, b, &pay_op, &pay_auth)
    }

    #[result_serializer(borsh)]
    pub fn relay_fee_start_recovery_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] key: KeyRecord,
        #[serializer(borsh)] origin: Option<String>,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) -> Check {
        let b = self.key_op_bytes(&caller, &op, &auth, &Action::StartRecovery(key.clone(), origin.clone()));
        self.relay_fee_check(&caller, "mtx_start_recovery", &(&op, &auth, &key, &origin), &op, b, &pay_op, &pay_auth)
    }

    #[result_serializer(borsh)]
    pub fn relay_fee_cancel_recovery_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) -> Check {
        let b = self.key_op_bytes(&caller, &op, &auth, &Action::CancelRecovery);
        self.relay_fee_check(&caller, "mtx_cancel_recovery", &(&op, &auth), &op, b, &pay_op, &pay_auth)
    }

    #[result_serializer(borsh)]
    pub fn relay_fee_finish_recovery_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) -> Check {
        let b = self.key_op_bytes(&caller, &op, &auth, &Action::FinishRecovery);
        self.relay_fee_check(&caller, "mtx_finish_recovery", &(&op, &auth), &op, b, &pay_op, &pay_auth)
    }

    #[result_serializer(borsh)]
    pub fn relay_fee_mandate_open_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] terms: MandateTerms,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) -> Check {
        let b = self.open_bytes(&caller, &op, &auth, &terms);
        self.relay_fee_check(&caller, "mtx_mandate_open", &(&op, &auth, &terms), &op, b, &pay_op, &pay_auth)
    }

    #[result_serializer(borsh)]
    pub fn relay_fee_revoke_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) -> Check {
        let b = self.revoke_bytes(&caller, &op, &auth);
        self.relay_fee_check(&caller, "mtx_revoke", &(&op, &auth), &op, b, &pay_op, &pay_auth)
    }

    #[result_serializer(borsh)]
    pub fn relay_fee_cancel_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] target_lane: [u8; 32],
        #[serializer(borsh)] target_nonce: u64,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) -> Check {
        let b = self.cancel_plan(&caller, &op, &auth, &target_lane, target_nonce).map(|(_, _, b)| b);
        self.relay_fee_check(&caller, "mtx_cancel", &(&op, &auth, &target_lane, &target_nonce), &op, b, &pay_op, &pay_auth)
    }

    #[result_serializer(borsh)]
    pub fn relay_fee_invalidate_nonces_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] lane: [u8; 32],
        #[serializer(borsh)] min_nonce: u64,
        #[serializer(borsh)] pay_op: MetaOp,
        #[serializer(borsh)] pay_auth: Auth,
    ) -> Check {
        let b = self.invalidate_plan(&caller, &op, &auth, &lane, min_nonce).map(|(_, _, b)| b);
        self.relay_fee_check(&caller, "mtx_invalidate_nonces", &(&op, &auth, &lane, &min_nonce), &op, b, &pay_op, &pay_auth)
    }
}

#[cfg(test)]
mod tests {
    //! `ref` of a wrapper with real entry arguments against `near-vectors.json` (`relayRefs` row `wrapper_add_key_real`,
    //! gen_vectors.py; rulings R5, R6, T9 pre-flight d–e).
    use super::*;
    use near_sdk::serde_json::{self, Value};
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/near-vectors.json");

    fn hx(v: &Value) -> Vec<u8> {
        let s = v.as_str().unwrap().trim_start_matches("0x");
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn b32(v: &Value) -> [u8; 32] {
        hx(v).try_into().unwrap()
    }

    #[test]
    fn relay_ref_vectors() {
        let d: Value = serde_json::from_str(&std::fs::read_to_string(VECTORS).unwrap()).unwrap();
        let r = d["relayRefs"].as_array().unwrap().iter().find(|r| r["name"] == "wrapper_add_key_real").unwrap();
        let ops = d["metaops"]["vectors"].as_array().unwrap();
        let row = |n: &Value| ops.iter().find(|m| m["name"] == *n).unwrap();
        let token: AccountId = r["target"].as_str().unwrap().parse().unwrap();
        testing_env!(VMContextBuilder::new().current_account_id(token.clone()).build());
        // the wrapper re-encodes its arguments: Borsh decodes canonically, so these are the client's bytes
        let args = hx(&r["args"]);
        let (op, auth, key, origin): (MetaOp, Auth, KeyRecord, Option<String>) = borsh::from_slice(&args).unwrap();
        assert_eq!(borsh::to_vec(&(&op, &auth, &key, &origin)).unwrap(), args);
        assert_eq!(op.digest(), b32(&row(&r["entryOp"])["digest"]), "the entry op is the key op row");
        assert_eq!([&[11u8][..], b"mtx_add_key", &args].concat(), hx(&r["call"]), "R6: the full entry name");
        // salt = the payment op's payer-signed extra, always (spec §2 row 8)
        let pay = &row(&r["payment"])["fields"];
        let net = b32(&d["network"]);
        assert_eq!(wrapper_ref(&net, "mtx_add_key", &args, &b32(&pay["extra"])), b32(&r["ref"]));
        assert_ne!(wrapper_ref(&net, "mtx_add_key", &args, &[0; 32]), b32(&r["ref"]));
        assert_eq!(b32(&pay["pay_ref"]), b32(&r["ref"]));
        assert_eq!((pay["relayer"].as_str(), pay["to"]["Near"].as_str()), (Some(token.as_str()), Some(token.as_str())), "bound to the token");
    }
}
