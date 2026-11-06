// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The signing policy in front of every typed signature (spec §5.4, MD-9; T4): [`NativeKey::sign_typed`] takes an [`Expect`],
//! one variant per clientkeys `check*` (`evm.js`: `checkPayment`, `checkReceiverFee`, `checkPayMeta`, `checkOp`, `checkCall`,
//! `checkOwnerCall`, `checkCancel`, `checkTradeOrder`, `checkWrapOrder`) with the check's named inputs as the user confirmed
//! them, or `Any(AllowAnyTypedData)`, the general EVM wallet's opt-in. A check rebuilds what the user asked for with the SCaaS
//! builders (their canonical step) and compares that digest with the **faithful** digest of the server's typed data: a mismatch
//! is `PolicyRefused` and nothing is signed. So a server value whose unbound `relayer` (mode bit 1 clear) or `feeRecipient`
//! (bit 2 clear) is non-zero is refused, never zeroed (owner 2026-11-05): what the user confirmed is what is hashed. `Any` signs
//! the standard digest of the values as supplied (no canonical step). The ports read the same `sign.json` `policy` rows as
//! clientkeys. `now` is an input (no clock inside `ua-rs`; wasm32 has none). UNAUDITED.
use super::eip712::{
    self, def, eip712_digest, from_hex, op_types, scaas_typed_data, to_hex, u256_add, u256_dec, u256_div, u256_from, u256_mul_add,
    u256_to_dec, Fields, TypedData, U256, ZERO_ADDRESS,
};
use super::signer::{SignRequest, Signer};
use super::{bounded, Error, NativeKey, Result};
use crate::{keccak256, meta_pay_id, pay_lane};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

const MAX_LEN: usize = 16 * 1024;
const MAX_DEPTH: usize = 4;
const ZERO_ID: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
const DAY: u64 = 86_400;

/// The explicit opt-in of a typed signature with no SCaaS check (`scaas_ua_sign_typed_any`): the general EVM wallet's path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowAnyTypedData;

/// One row of a contract's published `mtxSelectors()` (CLI-SGN-34): `fee_class` 2 is AMOUNT, its amount the `amount_arg`-th word.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowRow {
    pub selector: [u8; 4],
    pub name: String,
    pub fee_class: u8,
    pub amount_arg: u32,
}

/// The new key of an owner call (`SubjectKey`, `AddKey`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectKey {
    pub kind: u8,
    pub x: [u8; 32],
    pub y: [u8; 32],
    pub rp_id_hash: [u8; 32],
    pub origin_hash: [u8; 32],
}

/// A nonce floor the user chose (`InvalidateNonces` / `UAInvalidateNonces`); decimal strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invalidate {
    pub batch: String,
    pub min_nonce: String,
}

/// What the user confirmed, per clientkeys check (its inputs by name; amounts and fees as decimal strings, `max_fee` in base units,
/// 0 by default; ids of 20 bytes or, on a UA path, 32). [`Expect::from_json`] reads clientkeys' `expectDigest` input.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Expect {
    /// `checkPayment`: a `MetaTransfer` from `account` to `payee` of `amount` (in `decimals`) with `entry_ref`, on its lane
    /// `payLane(entry_ref)` nonce 0, in `expected_token`'s domain.
    Payment {
        account: [u8; 20],
        chain_id: u64,
        chain_uid: [u8; 32],
        amount: String,
        decimals: u32,
        payee: [u8; 20],
        entry_ref: [u8; 32],
        expected_token: [u8; 20],
        max_fee: String,
        fee_recipient: Option<[u8; 20]>,
        relayer: Option<[u8; 20]>,
        now: u64,
        max_window: u64,
    },
    /// `checkReceiverFee`: the payee's co-signature of `ReceiverFee` / `UAReceiverFee` over the payment it expects.
    ReceiverFee {
        payee: Vec<u8>,
        chain_id: u64,
        chain_uid: [u8; 32],
        amount: String,
        decimals: u32,
        entry_ref: [u8; 32],
        expected_token: [u8; 20],
        max_fee: String,
        fee_recipient: [u8; 20],
        now: u64,
        max_window: u64,
    },
    /// `checkPayMeta`: a payment whose `entryRef` is `metaPayId(salt, meta)` of the metadata the client holds.
    PayMeta {
        salt: [u8; 32],
        meta: Vec<u8>,
        entry_ref: Option<[u8; 32]>,
        account: [u8; 20],
        chain_id: u64,
        chain_uid: [u8; 32],
        amount: String,
        decimals: u32,
        payee: [u8; 20],
        expected_token: [u8; 20],
        max_fee: String,
        fee_recipient: Option<[u8; 20]>,
        relayer: Option<[u8; 20]>,
        now: u64,
        max_window: u64,
    },
    /// `checkOp`: the named struct `op` on `contract` with every field of `message` as the client built it.
    Op {
        op: String,
        contract: [u8; 20],
        chain_id: u64,
        chain_uid: [u8; 32],
        message: Value,
        max_fee: String,
        fee_recipient: Option<[u8; 20]>,
        relayer: Option<[u8; 20]>,
        now: u64,
        max_window: u64,
    },
    /// `checkCall`: a self-call `MetaTransaction` of exactly `data` on `contract`, its selector on `allowlist`.
    Call {
        account: [u8; 20],
        chain_id: u64,
        chain_uid: [u8; 32],
        allowlist: Vec<AllowRow>,
        contract: [u8; 20],
        data: Vec<u8>,
        max_fee: String,
        fee_recipient: Option<[u8; 20]>,
        relayer: Option<[u8; 20]>,
        now: u64,
        max_window: u64,
    },
    /// `checkOwnerCall`: exactly `AddKey(new_key)` signed by `account` itself, lane 0, no relayer, no fee.
    OwnerCall { account: [u8; 20], chain_id: u64, chain_uid: [u8; 32], new_key: SubjectKey, now: u64, max_window: u64 },
    /// `checkCancel`: the cancel of the client's own stored `order`, or the nonce floor `invalidate`.
    Cancel {
        account: Vec<u8>,
        chain_id: u64,
        chain_uid: [u8; 32],
        contract: [u8; 20],
        order: Option<Value>,
        invalidate: Option<Invalidate>,
        ua: bool,
    },
    /// `checkTradeOrder`: the order the client built, selling `sell_token`, on a DEX of `dexes`.
    TradeOrder {
        account: Vec<u8>,
        chain_id: u64,
        chain_uid: [u8; 32],
        order: Value,
        sell_token: [u8; 20],
        outside: bool,
        dexes: Vec<[u8; 20]>,
        ua: bool,
        now: u64,
        max_window: u64,
    },
    /// `checkWrapOrder`: the wrap by signature the client built, its wrapper on `wrappers`.
    WrapOrder {
        account: Vec<u8>,
        chain_id: u64,
        chain_uid: [u8; 32],
        order: Value,
        sell_token: [u8; 20],
        wrappers: Vec<[u8; 20]>,
        ua: bool,
        now: u64,
        max_window: u64,
    },
    /// No SCaaS check: the standard digest of the values as supplied.
    Any(AllowAnyTypedData),
}

/// The named inputs of one `Expect` JSON object; every key read once, an unread key is refused.
struct In(Map<String, Value>);
impl In {
    fn take(&mut self, k: &str) -> Option<Value> {
        self.0.remove(k).filter(|v| !v.is_null())
    }
    fn req(&mut self, k: &str) -> Result<Value> {
        self.take(k).ok_or(Error::Argument)
    }
    fn hex(v: &Value) -> Result<Vec<u8>> {
        v.as_str().filter(|s| s.starts_with("0x")).and_then(from_hex).ok_or(Error::Argument)
    }
    fn fixed<const N: usize>(v: &Value) -> Result<[u8; N]> {
        In::hex(v)?.try_into().map_err(|_| Error::Argument)
    }
    fn addr(&mut self, k: &str) -> Result<[u8; 20]> {
        In::fixed(&self.req(k)?)
    }
    fn opt_addr(&mut self, k: &str) -> Result<Option<[u8; 20]>> {
        self.take(k).map(|v| In::fixed(&v)).transpose()
    }
    fn b32(&mut self, k: &str) -> Result<[u8; 32]> {
        In::fixed(&self.req(k)?)
    }
    /// A native address or a 32-byte id.
    fn id(&mut self, k: &str) -> Result<Vec<u8>> {
        let b = In::hex(&self.req(k)?)?;
        if b.len() == 20 || b.len() == 32 {
            Ok(b)
        } else {
            Err(Error::Argument)
        }
    }
    fn u64(&mut self, k: &str) -> Result<u64> {
        In::u64_of(&self.req(k)?)
    }
    fn u64_of(v: &Value) -> Result<u64> {
        match v {
            Value::Number(n) => n.as_u64(),
            Value::String(s) if !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) => s.parse().ok(),
            _ => None,
        }
        .ok_or(Error::Argument)
    }
    fn opt_u64(&mut self, k: &str, default: u64) -> Result<u64> {
        self.take(k).map_or(Ok(default), |v| In::u64_of(&v))
    }
    /// An amount or a fee as written: a string, or a JSON integer.
    fn dec(&mut self, k: &str) -> Result<String> {
        match self.req(k)? {
            Value::String(s) => Ok(s),
            Value::Number(n) if n.as_u64().is_some() => Ok(n.to_string()),
            _ => Err(Error::Argument),
        }
    }
    fn opt_dec(&mut self, k: &str) -> Result<String> {
        if self.0.get(k).is_none_or(Value::is_null) {
            return Ok("0".into());
        }
        self.dec(k)
    }
    fn flag(&mut self, k: &str) -> Result<bool> {
        match self.take(k) {
            None => Ok(false),
            Some(Value::Bool(b)) => Ok(b),
            Some(_) => Err(Error::Argument),
        }
    }
    fn decimals(&mut self) -> Result<u32> {
        // 10^77 < 2^256 < 10^78: no amount has more decimals
        u32::try_from(self.u64("decimals")?).ok().filter(|d| *d <= 77).ok_or(Error::Argument)
    }
    fn done<T>(self, v: T) -> Result<T> {
        if self.0.is_empty() {
            Ok(v)
        } else {
            Err(Error::Argument)
        }
    }
}

impl Expect {
    /// clientkeys' `expectDigest` input `{check, …inputs}` (16 KiB, JSON depth 4, spec §9.3). `Argument`: an unknown check, a
    /// missing or malformed input, a key no input of the check; `PolicyRefused`: `Any` without `allowAnyTypedData: true`.
    pub fn from_json(json: &[u8]) -> Result<Expect> {
        let Value::Object(o) = bounded::json(json, MAX_LEN, MAX_DEPTH)? else { return Err(Error::Argument) };
        let mut x = In(o);
        let check = x.req("check")?;
        let check = check.as_str().ok_or(Error::Argument)?;
        let e = match check {
            "Payment" => Expect::Payment {
                account: x.addr("account")?,
                chain_id: x.u64("chainId")?,
                chain_uid: x.b32("chainUid")?,
                amount: x.dec("amount")?,
                decimals: x.decimals()?,
                payee: x.addr("payee")?,
                entry_ref: x.b32("entryRef")?,
                expected_token: x.addr("expectedToken")?,
                max_fee: x.opt_dec("maxFee")?,
                fee_recipient: x.opt_addr("feeRecipient")?,
                relayer: x.opt_addr("relayer")?,
                now: x.u64("now")?,
                max_window: x.opt_u64("maxWindow", DAY)?,
            },
            "ReceiverFee" => Expect::ReceiverFee {
                payee: x.id("payee")?,
                chain_id: x.u64("chainId")?,
                chain_uid: x.b32("chainUid")?,
                amount: x.dec("amount")?,
                decimals: x.decimals()?,
                entry_ref: x.b32("entryRef")?,
                expected_token: x.addr("expectedToken")?,
                max_fee: x.opt_dec("maxFee")?,
                fee_recipient: x.addr("feeRecipient")?,
                now: x.u64("now")?,
                max_window: x.opt_u64("maxWindow", DAY)?,
            },
            "PayMeta" => Expect::PayMeta {
                salt: x.b32("salt")?,
                meta: In::hex(&x.req("meta")?)?,
                entry_ref: x.take("entryRef").map(|v| In::fixed(&v)).transpose()?,
                account: x.addr("account")?,
                chain_id: x.u64("chainId")?,
                chain_uid: x.b32("chainUid")?,
                amount: x.dec("amount")?,
                decimals: x.decimals()?,
                payee: x.addr("payee")?,
                expected_token: x.addr("expectedToken")?,
                max_fee: x.opt_dec("maxFee")?,
                fee_recipient: x.opt_addr("feeRecipient")?,
                relayer: x.opt_addr("relayer")?,
                now: x.u64("now")?,
                max_window: x.opt_u64("maxWindow", DAY)?,
            },
            "Op" => Expect::Op {
                op: x.req("op")?.as_str().ok_or(Error::Argument)?.to_string(),
                contract: x.addr("contract")?,
                chain_id: x.u64("chainId")?,
                chain_uid: x.b32("chainUid")?,
                message: x.req("message")?,
                max_fee: x.opt_dec("maxFee")?,
                fee_recipient: x.opt_addr("feeRecipient")?,
                relayer: x.opt_addr("relayer")?,
                now: x.u64("now")?,
                max_window: x.opt_u64("maxWindow", 3600)?,
            },
            "Call" => {
                let Value::Object(call) = x.req("call")? else { return Err(Error::Argument) };
                let mut call = In(call);
                let (contract, data) = (call.addr("contract")?, In::hex(&call.req("data")?)?);
                call.done(())?;
                let Value::Array(rows) = x.req("allowlist")? else { return Err(Error::Argument) };
                let allowlist = rows
                    .into_iter()
                    .map(|r| {
                        let Value::Object(r) = r else { return Err(Error::Argument) };
                        let mut r = In(r);
                        let row = AllowRow {
                            selector: In::fixed(&r.req("selector")?)?,
                            name: r.req("name")?.as_str().ok_or(Error::Argument)?.to_string(),
                            fee_class: u8::try_from(r.u64("feeClass")?).map_err(|_| Error::Argument)?,
                            amount_arg: u32::try_from(r.opt_u64("amountArg", 0)?).map_err(|_| Error::Argument)?,
                        };
                        r.done(row)
                    })
                    .collect::<Result<Vec<_>>>()?;
                Expect::Call {
                    account: x.addr("account")?,
                    chain_id: x.u64("chainId")?,
                    chain_uid: x.b32("chainUid")?,
                    allowlist,
                    contract,
                    data,
                    max_fee: x.opt_dec("maxFee")?,
                    fee_recipient: x.opt_addr("feeRecipient")?,
                    relayer: x.opt_addr("relayer")?,
                    now: x.u64("now")?,
                    max_window: x.opt_u64("maxWindow", 3600)?,
                }
            }
            "OwnerCall" => {
                let Value::Array(k) = x.req("newKey")? else { return Err(Error::Argument) };
                let [kind, kx, ky, rp, origin] = k.as_slice() else { return Err(Error::Argument) };
                let new_key = SubjectKey {
                    kind: u8::try_from(In::u64_of(kind)?).map_err(|_| Error::Argument)?,
                    x: In::fixed(kx)?,
                    y: In::fixed(ky)?,
                    rp_id_hash: In::fixed(rp)?,
                    origin_hash: In::fixed(origin)?,
                };
                Expect::OwnerCall {
                    account: x.addr("account")?,
                    chain_id: x.u64("chainId")?,
                    chain_uid: x.b32("chainUid")?,
                    new_key,
                    now: x.u64("now")?,
                    max_window: x.opt_u64("maxWindow", 3600)?,
                }
            }
            "Cancel" => {
                let invalidate = match x.take("invalidate") {
                    None => None,
                    Some(Value::Object(i)) => {
                        let mut i = In(i);
                        let v = Invalidate { batch: i.dec("batch")?, min_nonce: i.dec("minNonce")? };
                        Some(i.done(v)?)
                    }
                    Some(_) => return Err(Error::Argument),
                };
                Expect::Cancel {
                    account: x.id("account")?,
                    chain_id: x.u64("chainId")?,
                    chain_uid: x.b32("chainUid")?,
                    contract: x.addr("contract")?,
                    order: x.take("order"),
                    invalidate,
                    ua: x.flag("ua")?,
                }
            }
            "TradeOrder" => Expect::TradeOrder {
                account: x.id("account")?,
                chain_id: x.u64("chainId")?,
                chain_uid: x.b32("chainUid")?,
                order: x.req("order")?,
                sell_token: x.addr("sellToken")?,
                outside: x.flag("outside")?,
                dexes: addrs(x.take("dexes"))?,
                ua: x.flag("ua")?,
                now: x.u64("now")?,
                max_window: x.opt_u64("maxWindow", 30 * DAY)?,
            },
            "WrapOrder" => Expect::WrapOrder {
                account: x.id("account")?,
                chain_id: x.u64("chainId")?,
                chain_uid: x.b32("chainUid")?,
                order: x.req("order")?,
                sell_token: x.addr("sellToken")?,
                wrappers: addrs(x.take("wrappers"))?,
                ua: x.flag("ua")?,
                now: x.u64("now")?,
                max_window: x.opt_u64("maxWindow", 30 * DAY)?,
            },
            "Any" => {
                if x.take("allowAnyTypedData") != Some(Value::Bool(true)) {
                    return Err(Error::PolicyRefused);
                }
                Expect::Any(AllowAnyTypedData)
            }
            _ => return Err(Error::Argument),
        };
        x.done(e)
    }
}

fn addrs(v: Option<Value>) -> Result<Vec<[u8; 20]>> {
    match v {
        None => Ok(vec![]),
        Some(Value::Array(a)) => a.iter().map(In::fixed).collect(),
        Some(_) => Err(Error::Argument),
    }
}

impl NativeKey {
    /// The EIP-712 signature (`r ‖ s ‖ v`) of `td` once `expect` approves it: a check of clientkeys refuses anything but the value
    /// the user confirmed (`PolicyRefused`, nothing signed; a non-zero unbound `relayer` / `feeRecipient` included); `Any` signs the
    /// value as supplied. The digest signed is always the faithful one of `td`. `Argument`: malformed typed data, an ed25519 key.
    pub fn sign_typed(&self, td: &TypedData, expect: Expect) -> Result<Vec<u8>> {
        sign_typed_by(self, td, expect)
    }
}

/// [`NativeKey::sign_typed`] by any [`Signer`] (spec §9.4: an external key's typed data passes the same policy).
pub fn sign_typed_by(key: &dyn Signer, td: &TypedData, expect: Expect) -> Result<Vec<u8>> {
    let req = eip712::request(td)?;
    let SignRequest::Eip712 { domain_separator, struct_hash, .. } = &req else { return Err(Error::Argument) };
    let digest = eip712_digest(domain_separator, struct_hash);
    if !matches!(expect, Expect::Any(AllowAnyTypedData)) && check(td, &expect)? != digest {
        return Err(Error::PolicyRefused);
    }
    key.sign_request(&req)
}

// --- the ports of clientkeys `evm.js` (same order of checks; every refusal is `PolicyRefused`) ---

fn refuse<T>() -> Result<T> {
    Err(Error::PolicyRefused)
}
/// What the user asked for, as the digest of its rebuilt typed data.
fn check(td: &TypedData, e: &Expect) -> Result<[u8; 32]> {
    match e {
        Expect::Payment {
            account, chain_id, chain_uid, amount, decimals, payee, entry_ref, expected_token, max_fee, fee_recipient, relayer, now,
            max_window,
        } => payment(td, &Pay { account, chain_id: *chain_id, chain_uid, amount, decimals: *decimals, payee, expected_token, max_fee,
            fee_recipient: fee_recipient.as_ref(), relayer: relayer.as_ref(), now: *now, max_window: *max_window }, entry_ref),
        Expect::ReceiverFee {
            payee, chain_id, chain_uid, amount, decimals, entry_ref, expected_token, max_fee, fee_recipient, now, max_window,
        } => receiver_fee(td, payee, *chain_id, chain_uid, &to_base(amount, *decimals)?, entry_ref, expected_token, max_fee, fee_recipient,
            *now, *max_window),
        Expect::PayMeta {
            salt, meta, entry_ref, account, chain_id, chain_uid, amount, decimals, payee, expected_token, max_fee, fee_recipient,
            relayer, now, max_window,
        } => {
            decode_meta(meta)?;
            let pay_id = meta_pay_id(salt, meta);
            if entry_ref.is_some_and(|e| e != pay_id) || !same(obj(td.message()).get("entryRef"), &pay_id) {
                return refuse();
            }
            payment(td, &Pay { account, chain_id: *chain_id, chain_uid, amount, decimals: *decimals, payee, expected_token, max_fee,
                fee_recipient: fee_recipient.as_ref(), relayer: relayer.as_ref(), now: *now, max_window: *max_window }, &pay_id)
        }
        Expect::Op { op, contract, chain_id, chain_uid, message, max_fee, fee_recipient, relayer, now, max_window } => {
            check_op(td, op, contract, *chain_id, chain_uid, message, max_fee, fee_recipient.as_ref(), relayer.as_ref(), *now, *max_window)
        }
        Expect::Call {
            account, chain_id, chain_uid, allowlist, contract, data, max_fee, fee_recipient, relayer, now, max_window,
        } => call(td, account, *chain_id, chain_uid, allowlist, contract, data, max_fee, fee_recipient.as_ref(), relayer.as_ref(), *now,
            *max_window),
        Expect::OwnerCall { account, chain_id, chain_uid, new_key: k, now, max_window } => {
            let message = serde_json::json!({"from": to_hex(account), "kind": k.kind, "x": to_hex(&k.x), "y": to_hex(&k.y),
                "rpIdHash": to_hex(&k.rp_id_hash), "originHash": to_hex(&k.origin_hash), "batch": 0, "mode": 0,
                "relayer": ZERO_ADDRESS, "fee": 0, "feeRecipient": ZERO_ADDRESS});
            check_op(td, "AddKey", account, *chain_id, chain_uid, &message, "0", None, None, *now, *max_window)
        }
        Expect::Cancel { account, chain_id, chain_uid, contract, order, invalidate, ua } => {
            cancel(td, account, *chain_id, chain_uid, contract, order.as_ref(), invalidate.as_ref(), *ua)
        }
        Expect::TradeOrder { account, chain_id, chain_uid, order, sell_token, outside, dexes, ua, now, max_window } => {
            trade_order(td, account, *chain_id, chain_uid, order, sell_token, *outside, dexes, *ua, *now, *max_window)
        }
        Expect::WrapOrder { account, chain_id, chain_uid, order, sell_token, wrappers, ua, now, max_window } => {
            wrap_order(td, account, *chain_id, chain_uid, order, sell_token, wrappers, *ua, *now, *max_window)
        }
        Expect::Any(_) => td.digest(),
    }
}

/// `td.message || {}`.
fn obj(v: &Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}
fn get<'a>(m: &'a Map<String, Value>, k: &str) -> Option<&'a Value> {
    m.get(k).filter(|v| !v.is_null())
}
/// clientkeys `same(v, id)`: the server's value is `0x` hex of these bytes, case aside.
fn same(v: Option<&Value>, id: &[u8]) -> bool {
    matches!(v, Some(Value::String(s)) if s.starts_with("0x") && from_hex(s).as_deref() == Some(id))
}
/// JS `String(v).toLowerCase()`, for `same` between two client values.
fn js_str(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(Value::String(s)) => s.to_lowercase(),
        Some(other) => other.to_string().to_lowercase(),
    }
}
/// clientkeys `uint(v)`: decimal digits only (a JSON integer or a string), else refused.
fn uint(v: Option<&Value>) -> Result<U256> {
    match v {
        Some(Value::Number(n)) => n.as_u64().map(u256_from),
        Some(Value::String(s)) => u256_dec(s),
        _ => None,
    }
    .map_or_else(refuse, Ok)
}
fn uint_str(s: &str) -> Result<U256> {
    u256_dec(s).map_or_else(refuse, Ok)
}
fn zero(x: &U256) -> bool {
    *x == [0; 32]
}
fn dec(x: &U256) -> Value {
    Value::String(u256_to_dec(x))
}
/// A value at most `0xff`, as a byte.
fn small(x: &U256) -> Option<u8> {
    x.get(..31).filter(|h| h.iter().all(|b| *b == 0)).and(x.last().copied())
}
/// clientkeys `deadline`: `now < validUntil ≤ now + max`.
fn deadline(valid_until: Option<&Value>, now: u64, max: u64) -> Result<()> {
    let until = uint(valid_until)?;
    let hi = u256_from(now.checked_add(max).ok_or(Error::PolicyRefused)?);
    if until > u256_from(now) && until <= hi {
        Ok(())
    } else {
        refuse()
    }
}
/// clientkeys `toBase`: `^[0-9]+(\.[0-9]+)?$`, at most `decimals` places.
fn to_base(amount: &str, decimals: u32) -> Result<U256> {
    let (int, frac) = amount.split_once('.').unwrap_or((amount, ""));
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    if !digits(int) || (amount.contains('.') && !digits(frac)) || frac.len() > decimals as usize {
        return refuse();
    }
    uint_str(&format!("{int}{frac:0<w$}", w = decimals as usize))
}
/// The digest of the SCaaS builder's value; a value it refuses is refused.
fn build(primary: &str, name: Option<&str>, contract: &[u8; 20], chain_id: u64, chain_uid: &[u8; 32], message: Map<String, Value>) -> Result<[u8; 32]> {
    scaas_typed_data(primary, name, contract, chain_id, chain_uid, &Value::Object(message))
        .and_then(|t| t.digest())
        .map_err(|_| Error::PolicyRefused)
}
fn name_of(td: &TypedData) -> Option<&str> {
    td.domain().get("name").and_then(Value::as_str)
}

/// clientkeys `feePolicy` (CTR-MTX-13): known flags and fee kind, NONE carries no fee, FIXED `fee`, PERCENT (≤ 1 %, only with an
/// amount) ⌊basis · fee / 10^6⌋, at most `max_fee`; a bound fee recipient is the one named, a bound relayer the one named if any.
fn fee_policy(m: &Map<String, Value>, max_fee: &str, fee_recipient: Option<&[u8; 20]>, relayer: Option<&[u8; 20]>, basis: Option<&U256>) -> Result<()> {
    let mode = small(&uint(get(m, "mode"))?).ok_or(Error::PolicyRefused)?;
    let kind = mode >> 4;
    if mode & !0xf3 != 0 || kind > 2 {
        return refuse();
    }
    let rate = uint(get(m, "fee"))?;
    if kind == 0 && !zero(&rate) {
        return refuse();
    }
    let fee = if kind == 1 {
        let (Some(basis), Some(r)) = (basis, small_u64(&rate).filter(|r| *r <= 10_000)) else { return refuse() };
        let (q, rem) = u256_div(basis, 1_000_000);
        let hi = u256_mul_add(&q, r, 0).ok_or(Error::PolicyRefused)?;
        u256_add(&hi, &u256_from(rem * r / 1_000_000)).ok_or(Error::PolicyRefused)?
    } else {
        rate
    };
    if fee > uint_str(max_fee)? {
        return refuse();
    }
    if mode & 2 != 0 && !fee_recipient.is_some_and(|f| same(get(m, "feeRecipient"), f)) {
        return refuse();
    }
    if mode & 1 != 0 && relayer.is_some_and(|r| !same(get(m, "relayer"), r)) {
        return refuse();
    }
    Ok(())
}
fn small_u64(x: &U256) -> Option<u64> {
    let (hi, lo) = x.split_at(24);
    hi.iter().all(|b| *b == 0).then(|| lo.iter().fold(0u64, |a, b| a << 8 | u64::from(*b)))
}

/// The payment inputs `checkPayment` and `checkPayMeta` share.
struct Pay<'a> {
    account: &'a [u8; 20],
    chain_id: u64,
    chain_uid: &'a [u8; 32],
    amount: &'a str,
    decimals: u32,
    payee: &'a [u8; 20],
    expected_token: &'a [u8; 20],
    max_fee: &'a str,
    fee_recipient: Option<&'a [u8; 20]>,
    relayer: Option<&'a [u8; 20]>,
    now: u64,
    max_window: u64,
}

/// clientkeys `checkPayment`.
fn payment(td: &TypedData, p: &Pay, entry_ref: &[u8; 32]) -> Result<[u8; 32]> {
    if td.primary_type() != "MetaTransfer" {
        return refuse();
    }
    let (m, d) = (obj(td.message()), td.domain());
    if !same(d.get("verifyingContract"), p.expected_token) || !same(get(&m, "to"), p.payee) {
        return refuse();
    }
    let value = to_base(p.amount, p.decimals)?;
    if uint(get(&m, "value"))? != value || zero(&value) || *entry_ref == [0; 32] || !same(get(&m, "entryRef"), entry_ref) {
        return refuse();
    }
    let batch = pay_lane(entry_ref);
    if uint(get(&m, "batch"))? != batch || !zero(&uint(get(&m, "nonce"))?) {
        return refuse();
    }
    fee_policy(&m, p.max_fee, p.fee_recipient, p.relayer, Some(&value))?;
    deadline(get(&m, "validUntil"), p.now, p.max_window)?;
    let mut msg = m.clone();
    msg.insert("from".into(), to_hex(p.account).into());
    msg.insert("to".into(), to_hex(p.payee).into());
    msg.insert("value".into(), dec(&value));
    msg.insert("entryRef".into(), to_hex(entry_ref).into());
    msg.insert("batch".into(), dec(&batch));
    msg.insert("nonce".into(), 0.into());
    build("MetaTransfer", name_of(td), p.expected_token, p.chain_id, p.chain_uid, msg)
}

/// clientkeys `checkReceiverFee` (both paths).
#[allow(clippy::too_many_arguments)]
fn receiver_fee(
    td: &TypedData, payee: &[u8], chain_id: u64, chain_uid: &[u8; 32], value: &U256, entry_ref: &[u8; 32], token: &[u8; 20], max_fee: &str,
    fee_recipient: &[u8; 20], now: u64, max_window: u64,
) -> Result<[u8; 32]> {
    let ua = td.primary_type() == "UAReceiverFee";
    if !(ua || td.primary_type() == "ReceiverFee") {
        return refuse();
    }
    let (m, d) = (obj(td.message()), td.domain());
    let p = obj(get(&m, "payment").unwrap_or(&Value::Null));
    if !same(d.get("verifyingContract"), token) || !same(get(&p, "to"), payee) {
        return refuse();
    }
    if uint(get(&p, "value"))? != *value || zero(value) || *entry_ref == [0; 32] || !same(get(&p, "entryRef"), entry_ref) {
        return refuse();
    }
    let batch = pay_lane(entry_ref);
    if uint(get(&p, "batch"))? != batch || !zero(&uint(get(&p, "nonce"))?) {
        return refuse();
    }
    if uint(get(&p, "mode"))? != u256_from(1) || !zero(&uint(get(&p, "fee"))?) {
        return refuse();
    }
    let fee = uint(get(&m, "fee"))?;
    if zero(&fee) || fee > *value || fee > uint_str(max_fee)? || !same(get(&m, "feeRecipient"), fee_recipient) {
        return refuse();
    }
    deadline(get(&m, "validUntil"), now, max_window)?;
    let mut payment = p.clone();
    payment.insert("to".into(), to_hex(payee).into());
    payment.insert("value".into(), dec(value));
    payment.insert("entryRef".into(), to_hex(entry_ref).into());
    payment.insert("batch".into(), dec(&batch));
    payment.insert("nonce".into(), 0.into());
    let mut msg = Map::new();
    msg.insert("payment".into(), Value::Object(payment));
    msg.insert("fee".into(), dec(&fee));
    msg.insert("feeRecipient".into(), to_hex(fee_recipient).into());
    msg.insert("validUntil".into(), get(&m, "validUntil").cloned().unwrap_or(Value::Null));
    build(if ua { "UAReceiverFee" } else { "ReceiverFee" }, name_of(td), token, chain_id, chain_uid, msg)
}

const E_FIELDS: [&str; 7] = ["batch", "nonce", "validUntil", "mode", "relayer", "fee", "feeRecipient"];

/// clientkeys `requireWhole`: every field of the client's value present (on the envelope struct `open`, the `E` fields may be the
/// server's), recursively; a relayer or fee recipient it names must be bound by its mode (the server's when the client leaves it).
fn require_whole(types: &BTreeMap<String, Fields>, ty: &str, v: Option<&Value>, open: bool, mode: Option<&Value>) -> Result<()> {
    if let Some(elem) = ty.strip_suffix("[]") {
        let Some(Value::Array(a)) = v else { return refuse() };
        return a.iter().try_for_each(|x| require_whole(types, elem, Some(x), false, None));
    }
    let Some(fields) = types.get(ty) else { return Ok(()) };
    let Some(Value::Object(o)) = v else { return refuse() };
    for (n, t) in fields {
        if open && E_FIELDS.contains(&n.as_str()) {
            continue;
        }
        let x = get(o, n).ok_or(Error::PolicyRefused)?;
        require_whole(types, t, Some(x), false, None)?;
    }
    if !["mode", "relayer", "feeRecipient"].iter().all(|k| fields.iter().any(|(n, _)| n == k)) {
        return Ok(());
    }
    let bits = uint(get(o, "mode").or(mode.filter(|m| !m.is_null())))?.last().copied().unwrap_or(0);
    let dropped = |k: &str, bit: u8| get(o, k).is_some_and(|id| js_str(Some(id)) != ZERO_ADDRESS) && bits & bit == 0;
    if dropped("relayer", 1) || dropped("feeRecipient", 2) {
        return refuse();
    }
    Ok(())
}

/// clientkeys `checkOp` (`checkOwnerCall` through it): struct `op` on `contract`, every field of `message` the client's.
#[allow(clippy::too_many_arguments)]
fn check_op(
    td: &TypedData, op: &str, contract: &[u8; 20], chain_id: u64, chain_uid: &[u8; 32], message: &Value, max_fee: &str,
    fee_recipient: Option<&[u8; 20]>, relayer: Option<&[u8; 20]>, now: u64, max_window: u64,
) -> Result<[u8; 32]> {
    if op == "WrapOrder" || op == "UAWrapOrder" {
        return refuse(); // `checkWrapOrder` carries its rules (CLI-SGN-36)
    }
    let Some(o) = def(op) else { return refuse() };
    if td.primary_type() != op {
        return refuse();
    }
    let (m, d) = (obj(td.message()), td.domain());
    if !same(d.get("verifyingContract"), contract) {
        return refuse();
    }
    let types = op_types(op).map_err(|_| Error::PolicyRefused)?;
    require_whole(&types, op, Some(message), o.envelope, get(&m, "mode"))?;
    let msg = message.as_object().ok_or(Error::PolicyRefused)?;
    let mut full = Map::new();
    if o.envelope {
        let basis = o.amount.map(|a| uint(get(msg, a))).transpose()?;
        let mut merged = m.clone();
        merged.extend(msg.clone());
        fee_policy(&merged, max_fee, fee_recipient, relayer, basis.as_ref())?;
        deadline(get(msg, "validUntil").or(get(&m, "validUntil")), now, max_window)?;
        full.insert("batch".into(), dec(&uint(get(&m, "batch"))?));
        full.insert("nonce".into(), dec(&uint(get(&m, "nonce"))?));
        for k in ["validUntil", "mode", "relayer", "fee", "feeRecipient"] {
            if let Some(v) = get(&m, k) {
                full.insert(k.into(), v.clone());
            }
        }
    }
    full.extend(msg.clone());
    build(op, name_of(td), contract, chain_id, chain_uid, full)
}

/// The selectors never signed as a call (CLI-SGN-34, CLI-SGN-36): moving funds and approvals.
fn never_called(selector: &[u8]) -> bool {
    [
        "transfer(address,uint256)", "transferFrom(address,address,uint256)", "approve(address,uint256)",
        "payWithFee(address,uint256,uint8,uint256,address,bytes32)", "pay(bytes32)",
        "payWithFeeToUA(bytes32,uint256,uint8,uint256,address,bytes32)",
    ]
    .iter()
    .any(|s| keccak256(s.as_bytes()).get(..4) == Some(selector))
}

/// clientkeys `checkCall`: the self-call `MetaTransaction` of exactly `data` on `contract`.
#[allow(clippy::too_many_arguments)]
fn call(
    td: &TypedData, account: &[u8; 20], chain_id: u64, chain_uid: &[u8; 32], allowlist: &[AllowRow], contract: &[u8; 20], data: &[u8],
    max_fee: &str, fee_recipient: Option<&[u8; 20]>, relayer: Option<&[u8; 20]>, now: u64, max_window: u64,
) -> Result<[u8; 32]> {
    if td.primary_type() != "MetaTransaction" {
        return refuse();
    }
    let (m, d) = (obj(td.message()), td.domain());
    if !same(d.get("verifyingContract"), contract) || !same(get(&m, "data"), data) {
        return refuse();
    }
    let Some(selector) = data.get(..4) else { return refuse() };
    if never_called(selector) {
        return refuse();
    }
    let Some(row) = allowlist.iter().find(|r| r.selector == selector) else { return refuse() };
    let at = 4 + 32 * row.amount_arg as usize;
    let basis = (row.fee_class == 2).then(|| data.get(at..at + 32).and_then(|w| <U256>::try_from(w).ok())).flatten();
    fee_policy(&m, max_fee, fee_recipient, relayer, basis.as_ref())?;
    deadline(get(&m, "validUntil"), now, max_window)?;
    let mut msg = m.clone();
    msg.insert("from".into(), to_hex(account).into());
    msg.insert("data".into(), to_hex(data).into());
    build("MetaTransaction", name_of(td), contract, chain_id, chain_uid, msg)
}

const CANCELS: [&str; 5] = ["CancelOrder", "CancelUAOrder", "CancelWrapOrder", "CancelUAWrapOrder", "CancelDexOrder"];

/// clientkeys `checkCancel`.
#[allow(clippy::too_many_arguments)]
fn cancel(
    td: &TypedData, account: &[u8], chain_id: u64, chain_uid: &[u8; 32], contract: &[u8; 20], order: Option<&Value>,
    invalidate: Option<&Invalidate>, ua: bool,
) -> Result<[u8; 32]> {
    if let Some(i) = invalidate {
        let mut msg = Map::new();
        msg.insert("from".into(), to_hex(account).into());
        msg.insert("batch".into(), i.batch.clone().into());
        msg.insert("minNonce".into(), i.min_nonce.clone().into());
        return build(if ua { "UAInvalidateNonces" } else { "InvalidateNonces" }, name_of(td), contract, chain_id, chain_uid, msg);
    }
    let primary = td.primary_type();
    if !CANCELS.contains(&primary) {
        return refuse();
    }
    let order = order.cloned().unwrap_or(Value::Null);
    let o = obj(&order);
    let held = if primary == "CancelDexOrder" { obj(get(&o, "order").unwrap_or(&Value::Null)) } else { o.clone() };
    if !same(get(&held, "from"), account) {
        return refuse();
    }
    // `dex == receiveToken` was signed as a `WrapOrder`: its cancel is a `CancelWrapOrder` (TS-D19)
    if ["CancelOrder", "CancelUAOrder"].contains(&primary) && js_str(o.get("dex")) == js_str(o.get("receiveToken")) {
        return refuse();
    }
    check_op(td, primary, contract, chain_id, chain_uid, &serde_json::json!({"order": order}), "0", None, None, 0, 0)
}

/// The order the client built: `order` over the defaults, `from` the account, the server's nonce, `validUntil` the client's or
/// the server's.
fn order_of(order: &Value, account: &[u8], got: &Map<String, Value>, ua: bool) -> Result<Map<String, Value>> {
    let Value::Object(given) = order else { return refuse() };
    let mut o = Map::new();
    for (k, v) in [("minFill", "0".into()), ("fee", "0".into()), ("relayer", ZERO_ADDRESS.into()),
        ("destination", (if ua { ZERO_ID } else { ZERO_ADDRESS }).into()), ("flags", 0.into()), ("batch", "0".into())]
    {
        o.insert(k.to_string(), v);
    }
    o.extend(given.clone());
    o.insert("from".into(), to_hex(account).into());
    o.insert("nonce".into(), dec(&uint(get(got, "nonce"))?));
    let valid_until = get(given, "validUntil").or(get(got, "validUntil")).cloned().unwrap_or(Value::Null);
    o.insert("validUntil".into(), valid_until);
    Ok(o)
}

/// clientkeys `orderTerms` (CLI-SGN-35): a nonce below 2^128, a fee of at most 1 %, known flags (no ESCROW outside).
fn order_terms(o: &Map<String, Value>, outside: bool) -> Result<()> {
    let nonce = uint(get(o, "nonce"))?;
    if nonce.get(..16).is_some_and(|h| h.iter().any(|b| *b != 0)) || uint(get(o, "fee"))? > u256_from(10_000) {
        return refuse();
    }
    let flags = small(&uint(get(o, "flags"))?).ok_or(Error::PolicyRefused)?;
    if flags & !7 != 0 || (flags & 2 != 0 && (outside || flags & 1 == 0)) {
        return refuse();
    }
    Ok(())
}

/// clientkeys `checkTradeOrder`.
#[allow(clippy::too_many_arguments)]
fn trade_order(
    td: &TypedData, account: &[u8], chain_id: u64, chain_uid: &[u8; 32], order: &Value, sell_token: &[u8; 20], outside: bool,
    dexes: &[[u8; 20]], ua: bool, now: u64, max_window: u64,
) -> Result<[u8; 32]> {
    if ua && outside {
        return refuse();
    }
    let want = if outside { "DexOrder" } else if ua { "UATradeOrder" } else { "TradeOrder" };
    if td.primary_type() != want {
        return refuse();
    }
    let msg = obj(td.message());
    let got = if outside { obj(get(&msg, "order").unwrap_or(&Value::Null)) } else { msg };
    let o = order_of(order, account, &got, ua)?;
    order_terms(&o, outside)?;
    if js_str(o.get("receiveToken")) == js_str(o.get("dex")) || !dexes.iter().any(|x| same(get(&o, "dex"), x)) {
        return refuse();
    }
    let (amount, min_fill) = (uint(get(&o, "amount"))?, uint(get(&o, "minFill"))?);
    if zero(&amount) || zero(&uint(get(&o, "receiveAmount"))?) || min_fill > amount {
        return refuse();
    }
    deadline(get(&o, "validUntil"), now, max_window)?;
    // the struct's own fields of the order (tradeOrderTypedData keeps those)
    let types = op_types(if ua { "UATradeOrder" } else { "TradeOrder" }).map_err(|_| Error::PolicyRefused)?;
    let fields = types.get(if ua { "UATradeOrder" } else { "TradeOrder" }).ok_or(Error::PolicyRefused)?;
    let picked: Map<String, Value> = fields.iter().filter_map(|(n, _)| o.get(n).map(|v| (n.clone(), v.clone()))).collect();
    let name = name_of(td).filter(|n| !n.is_empty());
    if outside {
        let dex: [u8; 20] = get(&o, "dex").and_then(Value::as_str).and_then(from_hex).and_then(|b| b.try_into().ok()).ok_or(Error::PolicyRefused)?;
        let mut m = Map::new();
        m.insert("sellToken".into(), to_hex(sell_token).into());
        m.insert("order".into(), Value::Object(picked));
        return build("DexOrder", name, &dex, chain_id, chain_uid, m);
    }
    build(want, name, sell_token, chain_id, chain_uid, picked)
}

/// clientkeys `checkWrapOrder` (and `checkUAWrapOrder`).
#[allow(clippy::too_many_arguments)]
fn wrap_order(
    td: &TypedData, account: &[u8], chain_id: u64, chain_uid: &[u8; 32], order: &Value, sell_token: &[u8; 20], wrappers: &[[u8; 20]],
    ua: bool, now: u64, max_window: u64,
) -> Result<[u8; 32]> {
    let ty = if ua { "UAWrapOrder" } else { "WrapOrder" };
    if td.primary_type() != ty {
        return refuse();
    }
    let o = order_of(order, account, &obj(td.message()), ua)?;
    order_terms(&o, false)?;
    if !wrappers.iter().any(|w| same(get(&o, "wrappedToken"), w)) {
        return refuse();
    }
    let (amount, min_fill) = (uint(get(&o, "amount"))?, uint(get(&o, "minFill"))?);
    if zero(&amount) || zero(&uint(get(&o, "minMinted"))?) || min_fill != amount {
        return refuse();
    }
    deadline(get(&o, "validUntil"), now, max_window)?;
    build(ty, name_of(td), sell_token, chain_id, chain_uid, o)
}

// --- CTR-MTX-26: the payment id commits to its metadata (clientkeys `decodeMeta`) ---

fn word_at(b: &[u8], i: usize) -> Result<U256> {
    b.get(32 * i..32 * i + 32).and_then(|w| <U256>::try_from(w).ok()).map_or_else(refuse, Ok)
}
fn as_usize(x: &U256) -> Option<usize> {
    small_u64(x).and_then(|v| usize::try_from(v).ok())
}
/// The `bytes` whose head word is word `i` of `b`, read strictly.
fn dyn_at(b: &[u8], i: usize) -> Result<&[u8]> {
    let off = as_usize(&word_at(b, i)?).filter(|o| o.checked_add(32).is_some_and(|e| e <= b.len())).ok_or(Error::PolicyRefused)?;
    let tail = b.get(off..).ok_or(Error::PolicyRefused)?;
    let n = as_usize(&word_at(tail, 0)?).ok_or(Error::PolicyRefused)?;
    tail.get(32..32usize.checked_add(n).ok_or(Error::PolicyRefused)?).map_or_else(refuse, Ok)
}
fn padded(b: &[u8]) -> Vec<u8> {
    let mut out = u256_from(b.len() as u64).to_vec();
    out.extend_from_slice(b);
    out.resize(out.len() + (32 - b.len() % 32) % 32, 0);
    out
}
fn utf8(b: &[u8]) -> Result<()> {
    std::str::from_utf8(b).map(|_| ()).map_err(|_| Error::PolicyRefused)
}
/// A `meta = abi.encode(uint16 schema, bytes body)` in canonical form, schema 1 (a UTF-8 note), 2 (`abi.encode(bytes creditorRef,
/// bytes invoiceNo, uint64 dueDate)`, UTF-8), 3 (a bound call, 96 bytes) or 4 (encrypted); anything else refused.
fn decode_meta(m: &[u8]) -> Result<()> {
    if m.len() < 96 {
        return refuse();
    }
    let schema = small_u64(&word_at(m, 0)?).filter(|s| *s <= 0xffff).ok_or(Error::PolicyRefused)?;
    let body = dyn_at(m, 1)?;
    let mut canon = u256_from(schema).to_vec();
    canon.extend_from_slice(&u256_from(64));
    canon.extend(padded(body));
    if canon != m {
        return refuse();
    }
    match schema {
        1 => utf8(body),
        2 => {
            if body.len() < 96 {
                return refuse();
            }
            let (creditor, invoice, due) = (dyn_at(body, 0)?, dyn_at(body, 1)?, word_at(body, 2)?);
            let (pc, pi) = (padded(creditor), padded(invoice));
            let mut canon = u256_from(96).to_vec();
            canon.extend_from_slice(&u256_from(96 + pc.len() as u64));
            canon.extend_from_slice(&due);
            canon.extend(pc);
            canon.extend(pi);
            if due.get(..24).is_some_and(|h| h.iter().any(|b| *b != 0)) || canon != body {
                return refuse();
            }
            utf8(creditor)?;
            utf8(invoice)
        }
        3 if body.len() == 96 => Ok(()),
        4 => Ok(()),
        _ => refuse(),
    }
}
