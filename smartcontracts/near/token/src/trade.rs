//! Trade legs, cancel, invalidate (spec §3.4, §3.6; CTR-DEX-09 / -10; README §11). Orders are keyed `(holder, lane,
//! nonce)` on order lanes of their own (never the meta-tx lanes, dex.md §10); each closes once, filled or cancelled, and
//! the record is permanent. `min_nonce` per `(holder, lane)` voids every order below it.
//!
//! - `mtx_trade(op, auth, order, receiver) -> bool`, op 1, only for the order's DEX: `to = Near(dex)`, `relayer =
//!   Some(dex)` (the predecessor), `amount = order.sell_amount` (fill-or-kill), `extra = sha256(Borsh(order))`,
//!   `pay_ref` zero. Moves the whole amount from the seller into the DEX's NEP-141 balance and registers `receiver`
//!   (the counter-order's maker, paid this token at settlement with 1 yoctoNEAR). A refused leg returns `false` and
//!   writes nothing; the attached deposit, or its excess over the new records, goes back to the transaction signer
//!   (the relayer that paid it; the predecessor is the keyless DEX).
//! - `mtx_cancel(op, auth, target_lane, target_nonce)`, op 14; `mtx_invalidate_nonces(op, auth, lane, min_nonce)`, op
//!   15 (`min_nonce < 2^63`, only increasing). Shape as the revoke: `to = from`, amount / `pay_ref` / lane / nonce zero,
//!   `extra = sha256(Borsh(params))`; a replay is refused by the state (closed order, `min_nonce` not raised). Their
//!   bodies (`cancel`, `invalidate_nonces`) charge nothing themselves, for Task 9's `relay_fee_<entry>` wrappers.
use crate::account::{check_of as check, now_s};
use crate::metatx::{value_policy, x};
use crate::storage::charge;
use crate::{record_bytes, Check, Holder, Subject, Token, TokenExt};
use near_sdk::json_types::U128;
use near_sdk::{borsh, env, near, AccountId, NearToken, Promise};
use scaas_near_common::auth::Auth;
use scaas_near_common::metaop::*;

/// Bytes of an order record = this + Borsh(holder) + Borsh(OrderClose) (key `o` ‖ holder ‖ lane 32 ‖ nonce 8, NEAR's
/// 40-byte record overhead); a `min_nonce` record = this + Borsh(holder) (key `n` ‖ holder ‖ lane 32, value u64 8).
/// `new` measures one of each.
pub const TRADE_RECORD_OVERHEAD: u64 = 81;
/// CTR-DEX-10: `min_nonce < 2^(w−1)`, `w` = 64.
pub const MIN_NONCE_CAP: u64 = 1 << 63;

type R<T> = Result<T, &'static str>;

/// A closed order `(holder, lane, nonce)`: filled by the leg op with this digest, or cancelled.
#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderClose {
    Filled([u8; 32]),
    Cancelled,
}

pub fn order_bytes(h: &Holder, c: &OrderClose) -> u64 {
    TRADE_RECORD_OVERHEAD + (borsh::to_vec(h).unwrap().len() + borsh::to_vec(c).unwrap().len()) as u64
}

pub fn min_nonce_bytes(h: &Holder) -> u64 {
    TRADE_RECORD_OVERHEAD + borsh::to_vec(h).unwrap().len() as u64
}

/// The shape of a cancel / invalidate: `to = from`, amount, `pay_ref`, lane and nonce zero, `extra` = the params.
fn admin_shape(op: &MetaOp, code: u8, params: &[u8], err: &'static str) -> R<()> {
    if op.op != code || op.to != op.from || op.amount != 0 || op.pay_ref != [0; 32] || op.lane != [0; 32] || op.nonce != 0 {
        return Err(err);
    }
    if op.extra != env::sha256_array(params) {
        return Err("extra is not sha256 of the parameters");
    }
    Ok(())
}

impl Token {
    fn closed(&self, h: &Holder, lane: &[u8; 32], nonce: u64) -> Option<&OrderClose> {
        self.orders.get(&(h.clone(), *lane, nonce))
    }

    fn min_nonce_of(&self, h: &Holder, lane: &[u8; 32]) -> u64 {
        self.min_nonces.get(&(h.clone(), *lane)).copied().unwrap_or(0)
    }

    /// The order `(h, lane, nonce)` is still open: not closed, not below `min_nonce`.
    fn open_order(&self, h: &Holder, lane: &[u8; 32], nonce: u64, filled_err: &'static str) -> R<()> {
        match self.closed(h, lane, nonce) {
            Some(OrderClose::Filled(_)) => return Err(filled_err),
            Some(OrderClose::Cancelled) => return Err("order cancelled"),
            None => {}
        }
        if nonce < self.min_nonce_of(h, lane) {
            return Err("order nonce below min_nonce");
        }
        Ok(())
    }

    /// No write: every check of a leg, cheap first; returns the signer's record, its old size and the new bytes.
    fn trade_plan(&self, caller: &AccountId, op: &MetaOp, auth: &Auth, order: &Order, receiver: &Holder) -> R<(Subject, u64, u64)> {
        let me = env::current_account_id();
        if op.op != OP_TRADE {
            return Err("wrong op code");
        }
        let dex = Holder::Near(caller.clone());
        if op.to != dex || op.relayer.as_ref() != Some(caller) {
            return Err("a leg is pulled only by the order's DEX (to = relayer = predecessor)");
        }
        if order.sell_token != me {
            return Err("order sells another token");
        }
        if op.amount != order.sell_amount || op.amount == 0 {
            return Err("fill-or-kill: op amount = sell_amount");
        }
        if op.pay_ref != [0; 32] {
            return Err("a trade leg carries no pay_ref");
        }
        if op.extra != order.hash() {
            return Err("extra is not sha256 of the order");
        }
        if now_s() > order.expiry {
            return Err("order expired");
        }
        if *receiver == Holder::Near(me) {
            return Err("token refuses a transfer to the token itself");
        }
        self.open_order(&op.from, &op.lane, op.nonce, "order filled")?;
        let (s, old) = self.signed(caller, caller, op, auth)?;
        value_policy(&s, auth)?;
        if self.balance(&op.from) < op.amount {
            return Err(match op.from {
                Holder::Near(_) => "The account doesn't have enough balance",
                Holder::Ua(_) => "The UA doesn't have enough balance",
            });
        }
        let open = if old == 0 { record_bytes(&op.from, &s) } else { 0 };
        let rec = order_bytes(&op.from, &OrderClose::Filled([0; 32]));
        Ok((s, old, open + rec + self.receiver_bytes(&dex) + self.receiver_bytes(receiver)))
    }

    pub(crate) fn cancel_plan(&self, caller: &AccountId, op: &MetaOp, auth: &Auth, lane: &[u8; 32], nonce: u64) -> R<(Subject, u64, u64)> {
        let shape = "cancel shape (op 14, to = from, amount, pay_ref, lane and nonce zero)";
        admin_shape(op, OP_CANCEL, &borsh::to_vec(&(lane, nonce)).unwrap(), shape)?;
        if let Some(OrderClose::Cancelled) = self.closed(&op.from, lane, nonce) {
            return Err("order already cancelled");
        }
        self.open_order(&op.from, lane, nonce, "order filled: cancel refused")?;
        let (s, old) = self.signed(caller, caller, op, auth)?;
        let open = if old == 0 { record_bytes(&op.from, &s) } else { 0 };
        Ok((s, old, open + order_bytes(&op.from, &OrderClose::Cancelled)))
    }

    pub(crate) fn invalidate_plan(&self, caller: &AccountId, op: &MetaOp, auth: &Auth, lane: &[u8; 32], min_nonce: u64) -> R<(Subject, u64, u64)> {
        let shape = "invalidate shape (op 15, to = from, amount, pay_ref, lane and nonce zero)";
        admin_shape(op, OP_INVALIDATE_NONCES, &borsh::to_vec(&(lane, min_nonce)).unwrap(), shape)?;
        if min_nonce >= MIN_NONCE_CAP {
            return Err("min_nonce must be below 2^63");
        }
        if min_nonce <= self.min_nonce_of(&op.from, lane) {
            return Err("min_nonce only increases");
        }
        let (s, old) = self.signed(caller, caller, op, auth)?;
        let open = if old == 0 { record_bytes(&op.from, &s) } else { 0 };
        let new = if self.min_nonces.contains_key(&(op.from.clone(), *lane)) { 0 } else { min_nonce_bytes(&op.from) };
        Ok((s, old, open + new))
    }

    /// `mtx_cancel`'s body (also Task 9's wrapper): panics on a refusal; the new bytes go to `storage_due`.
    pub(crate) fn cancel(&mut self, op: &MetaOp, auth: &Auth, lane: &[u8; 32], nonce: u64) {
        let p = env::predecessor_account_id();
        let (s, old, _) = self.cancel_plan(&p, op, auth, lane, nonce).unwrap_or_else(|e| env::panic_str(e));
        self.open_lazily(&op.from, s, old);
        self.storage_due += order_bytes(&op.from, &OrderClose::Cancelled);
        self.orders.insert((op.from.clone(), *lane, nonce), OrderClose::Cancelled);
        crate::Event::OrderCancelled { from: op.from.to_string(), lane: x(lane), nonce }.emit();
    }

    /// `mtx_invalidate_nonces`'s body (also Task 9's wrapper): panics on a refusal; new bytes go to `storage_due`.
    pub(crate) fn invalidate_nonces(&mut self, op: &MetaOp, auth: &Auth, lane: &[u8; 32], min_nonce: u64) {
        let p = env::predecessor_account_id();
        let (s, old, _) = self.invalidate_plan(&p, op, auth, lane, min_nonce).unwrap_or_else(|e| env::panic_str(e));
        self.open_lazily(&op.from, s, old);
        if self.min_nonces.insert((op.from.clone(), *lane), min_nonce).is_none() {
            self.storage_due += min_nonce_bytes(&op.from);
        }
        crate::Event::NoncesInvalidated { from: op.from.to_string(), lane: x(lane), min_nonce }.emit();
    }
}

#[near]
impl Token {
    /// A leg of a DEX settlement (only the order's DEX calls it); `true` = the whole `sell_amount` moved to the DEX.
    #[payable]
    #[result_serializer(borsh)]
    pub fn mtx_trade(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] order: Order,
        #[serializer(borsh)] receiver: Holder,
    ) -> bool {
        let p = env::predecessor_account_id();
        let plan = self.trade_plan(&p, &op, &auth, &order, &receiver).and_then(|(s, old, bytes)| {
            match env::attached_deposit() >= env::storage_byte_cost().saturating_mul(bytes.into()) {
                true => Ok((s, old)),
                false => Err("the attached deposit is short of the leg's storage"),
            }
        });
        let (s, old) = match plan {
            Ok(v) => v,
            Err(e) => {
                env::log_str(&format!("mtx_trade refused: {e}"));
                let d = env::attached_deposit();
                if d > NearToken::from_yoctonear(0) {
                    Promise::new(env::signer_account_id()).transfer(d).detach();
                }
                return false;
            }
        };
        let dex = Holder::Near(p.clone());
        self.open_lazily(&op.from, s, old);
        let digest = op.digest();
        // Ruling T8-I1 (controller call): the order closes here, for good. When the counter-leg fails, the DEX refunds
        // this leg's amount, but the order stays `Filled` (it never re-opens): the maker re-signs. Clients bind orders to
        // a relayer (`Order.relayer = Some`, CTR-DEX-09) by default so only the chosen relayer can pair them.
        self.storage_due += order_bytes(&op.from, &OrderClose::Filled(digest));
        self.orders.insert((op.from.clone(), op.lane, op.nonce), OrderClose::Filled(digest));
        self.storage_due += self.register(&dex) + self.register(&receiver);
        crate::Event::OrderFilled {
            from: op.from.to_string(),
            dex: p.to_string(),
            lane: x(&op.lane),
            nonce: op.nonce,
            amount: U128(op.amount),
            digest: x(&digest),
        }
        .emit();
        self.move_balance(&op.from, &dex, op.amount, None);
        charge(std::mem::take(&mut self.storage_due), env::signer_account_id());
        true
    }

    #[payable]
    pub fn mtx_cancel(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] target_lane: [u8; 32],
        #[serializer(borsh)] target_nonce: u64,
    ) {
        self.cancel(&op, &auth, &target_lane, target_nonce);
        self.charge_storage();
    }

    #[payable]
    pub fn mtx_invalidate_nonces(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] lane: [u8; 32],
        #[serializer(borsh)] min_nonce: u64,
    ) {
        self.invalidate_nonces(&op, &auth, &lane, min_nonce);
        self.charge_storage();
    }

    /// The order `(holder, lane, nonce)` was filled (by any leg op).
    #[result_serializer(borsh)]
    pub fn filled(&self, #[serializer(borsh)] holder: Holder, #[serializer(borsh)] lane: [u8; 32], #[serializer(borsh)] nonce: u64) -> bool {
        matches!(self.closed(&holder, &lane, nonce), Some(OrderClose::Filled(_)))
    }

    /// How the order closed (the filling leg op's digest, or cancelled); `None` while open. The DEX's `refund_expired`
    /// reads it.
    #[result_serializer(borsh)]
    pub fn order_closed(
        &self,
        #[serializer(borsh)] holder: Holder,
        #[serializer(borsh)] lane: [u8; 32],
        #[serializer(borsh)] nonce: u64,
    ) -> Option<OrderClose> {
        self.closed(&holder, &lane, nonce).cloned()
    }

    #[result_serializer(borsh)]
    pub fn min_nonce(&self, #[serializer(borsh)] holder: Holder, #[serializer(borsh)] lane: [u8; 32]) -> u64 {
        self.min_nonce_of(&holder, &lane)
    }

    /// `caller` = the DEX that will call `mtx_trade`.
    #[result_serializer(borsh)]
    pub fn mtx_trade_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] order: Order,
        #[serializer(borsh)] receiver: Holder,
    ) -> Check {
        check(self.trade_plan(&caller, &op, &auth, &order, &receiver).map(|(_, _, b)| b))
    }

    #[result_serializer(borsh)]
    pub fn mtx_cancel_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] target_lane: [u8; 32],
        #[serializer(borsh)] target_nonce: u64,
    ) -> Check {
        check(self.cancel_plan(&caller, &op, &auth, &target_lane, target_nonce).map(|(_, _, b)| b))
    }

    #[result_serializer(borsh)]
    pub fn mtx_invalidate_nonces_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] lane: [u8; 32],
        #[serializer(borsh)] min_nonce: u64,
    ) -> Check {
        check(self.invalidate_plan(&caller, &op, &auth, &lane, min_nonce).map(|(_, _, b)| b))
    }
}

#[cfg(test)]
mod tests {
    //! The contract's derivation of the trade / cancel / invalidate `extra` against `near-vectors.json` (gen_vectors.py
    //! `dex_vectors`, ruling R5).
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
    fn dex_vectors_match() {
        let d: Value = serde_json::from_str(&std::fs::read_to_string(VECTORS).unwrap()).unwrap();
        let rows = d["metaops"]["vectors"].as_array().unwrap();
        let row = |n: &str| rows.iter().find(|r| r["name"] == n).unwrap_or_else(|| panic!("no row {n}"));
        for n in ["trade_a", "trade_b"] {
            let r = row(n);
            let order: Order = borsh::from_slice(&hx(&r["order"])).unwrap();
            let f = &r["fields"];
            assert_eq!(f["op"], OP_TRADE);
            assert_eq!(order.hash(), b32(&f["extra"]), "{n}: extra = sha256(Borsh(Order))");
            assert_eq!(order.sell_amount.to_string(), f["amount"].as_str().unwrap(), "{n}: amount = sell_amount");
            assert_eq!(order.sell_token.as_str(), f["contract"].as_str().unwrap(), "{n}: the leg's token sells");
            assert_eq!(f["to"]["Near"], f["relayer"], "{n}: to = relayer = dex");
        }
        let c = row("cancel");
        let (lane, nonce): ([u8; 32], u64) = borsh::from_slice(&hx(&c["params"])).unwrap();
        assert_eq!(env::sha256_array(borsh::to_vec(&(lane, nonce)).unwrap()), b32(&c["fields"]["extra"]));
        assert_eq!(c["fields"]["op"], OP_CANCEL);
        let i = row("invalidate_nonces");
        let (lane, min): ([u8; 32], u64) = borsh::from_slice(&hx(&i["params"])).unwrap();
        assert!(min < MIN_NONCE_CAP);
        assert_eq!(env::sha256_array(borsh::to_vec(&(lane, min)).unwrap()), b32(&i["fields"]["extra"]));
        assert_eq!(i["fields"]["op"], OP_INVALIDATE_NONCES);
    }
}
