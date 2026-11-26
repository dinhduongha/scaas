// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The signing policy in front of every typed signature (spec §5.4, MD-9; T4): [`NativeKey::sign_typed`] takes an [`Expect`],
//! one variant per clientkeys `check*` (`evm.js`: `checkPayment`, `checkPayeeFee`, `checkPayMeta`, `checkOp`, `checkCall`,
//! `checkOwnerCall`, `checkCancel`, `checkTradeOrder`, `checkWrapOrder`, `checkLiquidityOrder`; T21 L40), `Erc7739` (the
//! ERC-7739 nest of a confirmed app typed data, T21 O6), with the check's named inputs as the user confirmed
//! them, or `Any(AllowAnyTypedData)`, the general EVM wallet's opt-in. A check rebuilds what the user asked for with the SCaaS
//! builders (their canonical step) and compares that digest with the **faithful** digest of the server's typed data: a mismatch
//! is `PolicyRefused` and nothing is signed. So a server value whose unbound `relayer` (mode bit 1 clear) or `feeRecipient`
//! (bit 2 clear) is non-zero is refused, never zeroed (owner 2026-11-05): what the user confirmed is what is hashed. `Any` signs
//! the standard digest of the values as supplied (no canonical step). The ports read the same `sign.json` `policy` rows as
//! clientkeys. `now` is an input (no clock inside `ua-rs`; wasm32 has none). UNAUDITED.
use super::eip712::{
    self, eip712_digest, from_hex, liquidity_order_typed_data, op_row, op_types, scaas_typed_data,
    to_hex, typed_data_of, u256_add, u256_dec, u256_div, u256_from, u256_mul_add, u256_to_dec,
    Erc7739Wallet, Fields, TypedData, U256, ZERO_ADDRESS,
};
use super::signer::{SignRequest, Signer};
use super::{bounded, Error, NativeKey, Result};
use crate::pay::{meta_pay_id_v3, PayMeta};
use crate::{keccak256, pay_lane};
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
/// 0 by default; ids of 32 bytes, a native address zero-padded (`padId`), where the struct takes ids). [`Expect::from_json`] reads
/// clientkeys' `expectDigest` input. ua-mtx-merge (R12, R20, R39, R46): the token's address `MetaTransfer`, `ReceiverFee`,
/// `TradeOrder`, `WrapOrder` and their cancels left; a payment, a payee fee, a SCaaS sell token's order and a wrap order are
/// the `UA` structs.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Expect {
    /// `checkPayment`: a `UAMetaTransfer` from `account` to `payee` of `amount` (in `decimals`) with `entry_ref`, on its lane
    /// `payLane(entry_ref)` nonce 0, in `expected_token`'s domain.
    Payment {
        account: [u8; 32],
        chain_id: u64,
        chain_uid: [u8; 32],
        amount: String,
        decimals: u32,
        payee: [u8; 32],
        entry_ref: [u8; 32],
        expected_token: [u8; 20],
        max_fee: String,
        fee_recipient: Option<[u8; 20]>,
        relayer: Option<[u8; 20]>,
        now: u64,
        max_window: u64,
    },
    /// `checkPayeeFee`: the payee's co-signature of `UAPayeeFee` over the payment it expects (CTR-MTX-86, owner 2026-11-12: was
    /// `ReceiverFee`).
    PayeeFee {
        payee: [u8; 32],
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
    /// `checkPayMeta`: a payment whose `entryRef` is `metaPayId(meta)` (`PayMeta` v3, CTR-MTX-26, T83) of the metadata the
    /// client holds.
    PayMeta {
        meta: PayMeta,
        entry_ref: Option<[u8; 32]>,
        account: [u8; 32],
        chain_id: u64,
        chain_uid: [u8; 32],
        amount: String,
        decimals: u32,
        payee: [u8; 32],
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
    /// A plain transfer on ids (scaas-sdk; owner 2026-11-19, ruling D): a `UAMetaTransfer` from `account` to `payee` of `amount` (in
    /// `decimals`) with `entryRef = 0` on the caller-named lane `batch` (decimal; any nonce, the lane's), in `expected_token`'s
    /// domain: not a payment. No clientkeys counterpart and no JSON form (built by the SDK).
    Transfer {
        account: [u8; 32],
        chain_id: u64,
        chain_uid: [u8; 32],
        amount: String,
        decimals: u32,
        payee: [u8; 32],
        batch: String,
        expected_token: [u8; 20],
        max_fee: String,
        fee_recipient: Option<[u8; 20]>,
        relayer: Option<[u8; 20]>,
        now: u64,
        max_window: u64,
    },
    /// A mandate wallet's `UAExecute` of a decoded call (scaas-sdk spec §13.2; owner 2026-11-19, ruling C), or a `SmartKeyAccount`'s
    /// `Execute` (scaas-sdk T13; the typed data's primary type names which, `wallet` the contract): `checkOp` over `message` with
    /// `target`, `value` and `data` rebuilt from `call`, so only the decoded call is signed. No clientkeys counterpart and no JSON
    /// form (built by the SDK).
    Execute {
        wallet: [u8; 20],
        chain_id: u64,
        chain_uid: [u8; 32],
        message: Value,
        call: DecodedCall,
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
    OwnerCall {
        account: [u8; 20],
        chain_id: u64,
        chain_uid: [u8; 32],
        new_key: SubjectKey,
        now: u64,
        max_window: u64,
    },
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
    /// `checkTradeOrder`: the order the client built, selling `sell_token`, on a DEX of `dexes`: a `UATradeOrder` (`ua`, by default
    /// unless `outside`) or an outside token's `DexOrder`.
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
    /// `checkWrapOrder`: the `UAWrapOrder` the client built, its wrapper on `wrappers`.
    WrapOrder {
        account: Vec<u8>,
        chain_id: u64,
        chain_uid: [u8; 32],
        order: Value,
        sell_token: [u8; 20],
        wrappers: Vec<[u8; 20]>,
        now: u64,
        max_window: u64,
    },
    /// `checkLiquidityOrder` (T21 L40; spec 2026-11-10-dex-liquidity.md): the `LiquidityOrder` the client built (`order`, the
    /// fields it set) for `account` (a 32-byte id), on a DEX of `dexes` that is also in `liquidity_dexes`; `readers` the
    /// position readers of the chain profile per position manager; `scaas_tokens` the tokens with the UA ledger on;
    /// `extra_tokens` counted in the plan's token list; `partial` a partial withdraw or fee collect (it must receive the
    /// position back).
    LiquidityOrder {
        account: [u8; 32],
        chain_id: u64,
        chain_uid: [u8; 32],
        order: Value,
        dexes: Vec<[u8; 20]>,
        liquidity_dexes: Vec<[u8; 20]>,
        readers: Vec<([u8; 20], Vec<[u8; 20]>)>,
        scaas_tokens: Vec<[u8; 20]>,
        extra_tokens: Vec<[u8; 20]>,
        partial: bool,
        now: u64,
        max_window: u64,
    },
    /// ERC-7739 (T21 O6, owner 2026-11-16): the `TypedDataSign` nest of `app`, the app's typed data the user confirmed, for the
    /// wallet `wallet` at `address` ([`TypedData::erc7739`]); any other typed data is refused. The contents are the app's, signed
    /// as confirmed (no SCaaS check of them). Built by the caller (no JSON form: the app's typed data is deeper than the
    /// `Expect` JSON's depth 4).
    Erc7739 {
        app: Box<TypedData>,
        wallet: Erc7739Wallet,
        address: [u8; 20],
        chain_id: u64,
        chain_uid: [u8; 32],
    },
    /// No SCaaS check: the standard digest of the values as supplied.
    Any(AllowAnyTypedData),
}

/// A decoded call of [`Expect::Execute`]: `ua-rs` builds its `(target, value, data)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedCall {
    /// `token.transfer(to, amount)`, `amount` a decimal string of the token's smallest unit, value 0
    Erc20Transfer {
        token: [u8; 20],
        to: [u8; 20],
        amount: String,
    },
    /// `account.initiateRecovery(key)` on a `SmartKeyAccount` by its guardian (CTR-ACC-03; scaas-sdk T13: a guardian
    /// `SmartKeyAccount`'s `Execute`), value 0
    InitiateRecovery { account: [u8; 20], key: SubjectKey },
}

impl DecodedCall {
    /// The call's `(target, value, data)` as the struct signs them.
    pub fn encode(&self) -> Result<([u8; 20], U256, Vec<u8>)> {
        match self {
            DecodedCall::Erc20Transfer { token, to, amount } => {
                let n = u256_dec(amount).ok_or(Error::Argument)?;
                let mut data = keccak256(b"transfer(address,uint256)")
                    .get(..4)
                    .ok_or(Error::Argument)?
                    .to_vec();
                data.extend_from_slice(&[0u8; 12]);
                data.extend_from_slice(to);
                data.extend_from_slice(&n);
                Ok((*token, [0u8; 32], data))
            }
            DecodedCall::InitiateRecovery { account, key } => {
                let mut data =
                    keccak256(b"initiateRecovery((uint8,bytes32,bytes32,bytes32,bytes32))")
                        .get(..4)
                        .ok_or(Error::Argument)?
                        .to_vec();
                let mut kind = [0u8; 32];
                kind[31] = key.kind;
                for w in [&kind, &key.x, &key.y, &key.rp_id_hash, &key.origin_hash] {
                    data.extend_from_slice(w);
                }
                Ok((*account, [0u8; 32], data))
            }
        }
    }
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
        v.as_str()
            .filter(|s| s.starts_with("0x"))
            .and_then(from_hex)
            .ok_or(Error::Argument)
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
            Value::String(s) if !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) => {
                s.parse().ok()
            }
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
    /// [`In::dec`], `"0"` when absent or `null` (the key taken either way, as the other optional readers).
    fn opt_dec(&mut self, k: &str) -> Result<String> {
        if self.0.get(k).is_none_or(Value::is_null) {
            self.0.remove(k);
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
        u32::try_from(self.u64("decimals")?)
            .ok()
            .filter(|d| *d <= 77)
            .ok_or(Error::Argument)
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
        let Value::Object(o) = bounded::json(json, MAX_LEN, MAX_DEPTH)? else {
            return Err(Error::Argument);
        };
        let mut x = In(o);
        let check = x.req("check")?;
        let check = check.as_str().ok_or(Error::Argument)?;
        let e = match check {
            "Payment" => Expect::Payment {
                account: x.b32("account")?,
                chain_id: x.u64("chainId")?,
                chain_uid: x.b32("chainUid")?,
                amount: x.dec("amount")?,
                decimals: x.decimals()?,
                payee: x.b32("payee")?,
                entry_ref: x.b32("entryRef")?,
                expected_token: x.addr("expectedToken")?,
                max_fee: x.opt_dec("maxFee")?,
                fee_recipient: x.opt_addr("feeRecipient")?,
                relayer: x.opt_addr("relayer")?,
                now: x.u64("now")?,
                max_window: x.opt_u64("maxWindow", DAY)?,
            },
            "PayeeFee" => Expect::PayeeFee {
                payee: x.b32("payee")?,
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
                meta: pay_meta(x.req("meta")?)?,
                entry_ref: x.take("entryRef").map(|v| In::fixed(&v)).transpose()?,
                account: x.b32("account")?,
                chain_id: x.u64("chainId")?,
                chain_uid: x.b32("chainUid")?,
                amount: x.dec("amount")?,
                decimals: x.decimals()?,
                payee: x.b32("payee")?,
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
                let Value::Object(call) = x.req("call")? else {
                    return Err(Error::Argument);
                };
                let mut call = In(call);
                let (contract, data) = (call.addr("contract")?, In::hex(&call.req("data")?)?);
                call.done(())?;
                let Value::Array(rows) = x.req("allowlist")? else {
                    return Err(Error::Argument);
                };
                let allowlist = rows
                    .into_iter()
                    .map(|r| {
                        let Value::Object(r) = r else {
                            return Err(Error::Argument);
                        };
                        let mut r = In(r);
                        let row = AllowRow {
                            selector: In::fixed(&r.req("selector")?)?,
                            name: r.req("name")?.as_str().ok_or(Error::Argument)?.to_string(),
                            fee_class: u8::try_from(r.u64("feeClass")?)
                                .map_err(|_| Error::Argument)?,
                            amount_arg: u32::try_from(r.opt_u64("amountArg", 0)?)
                                .map_err(|_| Error::Argument)?,
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
                let Value::Array(k) = x.req("newKey")? else {
                    return Err(Error::Argument);
                };
                let [kind, kx, ky, rp, origin] = k.as_slice() else {
                    return Err(Error::Argument);
                };
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
                        let v = Invalidate {
                            batch: i.dec("batch")?,
                            min_nonce: i.dec("minNonce")?,
                        };
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
            "TradeOrder" => {
                let outside = x.flag("outside")?;
                Expect::TradeOrder {
                    account: x.id("account")?,
                    chain_id: x.u64("chainId")?,
                    chain_uid: x.b32("chainUid")?,
                    order: x.req("order")?,
                    sell_token: x.addr("sellToken")?,
                    outside,
                    dexes: addrs(x.take("dexes"))?,
                    ua: if x.0.contains_key("ua") {
                        x.flag("ua")?
                    } else {
                        !outside
                    },
                    now: x.u64("now")?,
                    max_window: x.opt_u64("maxWindow", 30 * DAY)?,
                }
            }
            "WrapOrder" => Expect::WrapOrder {
                account: x.id("account")?,
                chain_id: x.u64("chainId")?,
                chain_uid: x.b32("chainUid")?,
                order: x.req("order")?,
                sell_token: x.addr("sellToken")?,
                wrappers: addrs(x.take("wrappers"))?,
                now: x.u64("now")?,
                max_window: x.opt_u64("maxWindow", 30 * DAY)?,
            },
            "LiquidityOrder" => Expect::LiquidityOrder {
                account: x.b32("account")?,
                chain_id: x.u64("chainId")?,
                chain_uid: x.b32("chainUid")?,
                order: x.req("order")?,
                dexes: addrs(x.take("dexes"))?,
                liquidity_dexes: addrs(x.take("liquidityDexes"))?,
                readers: match x.take("readers") {
                    None => vec![],
                    Some(Value::Object(m)) => m
                        .iter()
                        .map(|(k, v)| {
                            Ok((
                                In::fixed(&Value::from(k.as_str()))?,
                                addrs(Some(v.clone()))?,
                            ))
                        })
                        .collect::<Result<_>>()?,
                    Some(_) => return Err(Error::Argument),
                },
                scaas_tokens: addrs(x.take("scaasTokens"))?,
                extra_tokens: addrs(x.take("extraTokens"))?,
                partial: x.flag("partial")?,
                now: x.u64("now")?,
                max_window: x.opt_u64("maxWindow", 3600)?,
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

/// clientkeys `payMeta` input `{salt, payNo, save, schema, body}` (T83: `payNo` 32 bytes, 0 by default; `save` false, `schema` 0
/// by default; `body` hex, empty by default; the salt is required here: a check holds the metadata it was shown). Its rules are
/// `metaPayId`'s, at the check.
fn pay_meta(v: Value) -> Result<PayMeta> {
    let Value::Object(m) = v else {
        return Err(Error::Argument);
    };
    let mut m = In(m);
    let salt = m.b32("salt")?;
    let pay_no = m
        .take("payNo")
        .map(|v| In::fixed(&v))
        .transpose()?
        .unwrap_or([0; 32]);
    let save = m.flag("save")?;
    let schema = u16::try_from(m.opt_u64("schema", 0)?).map_err(|_| Error::Argument)?;
    let body = m
        .take("body")
        .map(|b| In::hex(&b))
        .transpose()?
        .unwrap_or_default();
    m.done(PayMeta {
        salt,
        pay_no,
        save,
        schema,
        body,
    })
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
    let SignRequest::Eip712 {
        domain_separator,
        struct_hash,
        ..
    } = &req
    else {
        return Err(Error::Argument);
    };
    let digest = eip712_digest(domain_separator, struct_hash);
    if !matches!(expect, Expect::Any(AllowAnyTypedData)) && check(td, &expect)? != digest {
        return Err(Error::PolicyRefused);
    }
    key.sign_request(&req)
}

/// scaas-sdk spec §13.2: the `UASig` of the typed SCaaS struct `td` for its named entry, once `expect` approves it (the same check
/// as [`sign_typed_by`]; `PolicyRefused`, nothing signed, otherwise). A native EVM key: `{"", r ‖ s ‖ v over the digest, []}` (a
/// native id signs the digest itself on a named entry, CTR-MTX-28); a UA key: [`super::ua_sig`] over the digest under the entry's
/// purpose, `payee-fee` for `UAPayeeFee`, `trade` for the orders and their cancels (`TradeLib`), `zether-owner` for the Zether
/// owner statements `ZetherRollOver` and `ZetherSetRollOverMode` (`ZetherLib`, owner 2026-11-19 C3; the outer `UA*` forms carry
/// that signature as `ownerSig`), `zether-auth` for `PqzRollOver` (`PqzStateLib`, CTR-PQZ-41) and a debit's `PqzAuth`
/// (`PqzCore.requireHolder`, P-T16-1), `auditor-consent` for
/// `AuditorConsent` (`PqzStateLib`, CTR-PQZ-43), `metatx` for every other envelope. `Expect::Any` and `Expect::Erc7739` are `Argument` here: a SCaaS entry is always signed under its check.
pub fn sign_scaas(
    key: &dyn Signer,
    td: &TypedData,
    expect: Expect,
) -> Result<crate::ua_portable::UASig> {
    // review A2-8: an ERC-7739 nested signature is an app's typed data, never a SCaaS entry's
    if matches!(expect, Expect::Any(_) | Expect::Erc7739 { .. }) {
        return Err(Error::Argument);
    }
    if let super::signer::KeyRef::Native { .. } = key.key_ref() {
        // the token checks a consent through the registry, never the digest itself: [`sign_auditor_consent_native`]
        if td.primary_type() == "AuditorConsent" {
            return Err(Error::Argument);
        }
        return Ok(crate::ua_portable::UASig {
            key_data: vec![],
            signature: sign_typed_by(key, td, expect)?,
            members: vec![],
        });
    }
    let digest = td.digest()?;
    if check(td, &expect)? != digest {
        return Err(Error::PolicyRefused);
    }
    super::uasig::ua_sig(key, None, &scaas_purpose(td)?, &digest)
}

/// A native (EVM address) auditor's consent to a set-auditor (`AuditorConsent`, set-auditor spec §5.2): the PQZ token checks it
/// through the registry (`PqzStateLib._auditorChecks`: `requireAuthorized(auditor, PURPOSE_AUDITOR_CONSENT, digest, consent)`),
/// so the key signs `UAAuth(id, auditor-consent, digest)` under the registry's domain `registry` over the consent's typed
/// digest, never that digest bare: `{"", r ‖ s ‖ v, []}`. Checked against `expect` as [`sign_scaas`] checks a UA key
/// (`PolicyRefused`, nothing signed); `Argument` for a key other than a native EVM key, another primary type, or a consent
/// whose `auditor` is not the key's own id.
pub fn sign_auditor_consent_native(
    key: &dyn Signer,
    td: &TypedData,
    expect: Expect,
    registry: &crate::Domain,
) -> Result<crate::ua_portable::UASig> {
    if matches!(expect, Expect::Any(_) | Expect::Erc7739 { .. })
        || td.primary_type() != "AuditorConsent"
    {
        return Err(Error::Argument);
    }
    let digest = td.digest()?;
    if check(td, &expect)? != digest {
        return Err(Error::PolicyRefused);
    }
    let id = super::uasig::native_id(&key.key_ref()).ok_or(Error::Argument)?;
    let v = td.to_value();
    let auditor = v
        .get("message")
        .and_then(|m| m.get("auditor"))
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase);
    let own: String = id.iter().map(|b| format!("{b:02x}")).collect();
    if auditor != Some(format!("0x{own}")) {
        return Err(Error::Argument);
    }
    super::uasig::ua_sig(
        key,
        Some(registry),
        &crate::purpose_tag("auditor-consent")?,
        &digest,
    )
}

/// The purpose tag a UA key signs the typed SCaaS struct `td` under in [`sign_scaas`] (its table, public so an external key's
/// caller computes the challenge or `ua_msg` the device signs before asking it: owner 2026-11-19, P1).
pub fn scaas_purpose(td: &TypedData) -> Result<[u8; 32]> {
    Ok(crate::purpose_tag(match td.primary_type() {
        "UAPayeeFee" => "payee-fee",
        "UAWrapOrder" | "UATradeOrder" | "CancelUAOrder" | "CancelUAWrapOrder"
        | "UAInvalidateNonces" => "trade",
        "ZetherRollOver" | "ZetherSetRollOverMode" => "zether-owner",
        "PqzRollOver" | "PqzAuth" => "zether-auth",
        "AuditorConsent" => "auditor-consent",
        _ => "metatx",
    })?)
}

/// The `ua_msg` a `bls12381-multi` (`0x0121`) group signs for the typed SCaaS struct `td`: `uaMessage(0x0121, purpose,
/// digest)`, the purpose as [`sign_scaas`] takes it (spec 2026-11-19-bls12381-multi §5.4). What an aggregator checks the
/// partials on; it signs nothing.
pub fn scaas_bls_multi_message(td: &TypedData) -> Result<[u8; 32]> {
    crate::ua_message(crate::bls_multi::KIND, &scaas_purpose(td)?, &td.digest()?)
        .map_err(|_| Error::Argument)
}

/// [`sign_scaas`] for a `bls12381-multi` member key (`key`, kind `0x0121`) of the group `key_data` (`d`): once `expect`
/// approves `td` (`PolicyRefused`, nothing signed, otherwise; `Expect::Any` `Argument`), the member's partial (128 bytes) over
/// `memberDigest(ua, ua_msg)`, `ua_msg` [`scaas_bls_multi_message`], `ua` derived from `d` (spec §5.4, N5); `Argument` unless
/// `d` lists the key.
pub fn sign_scaas_bls_multi(
    key: &dyn Signer,
    key_data: &[u8],
    td: &TypedData,
    expect: Expect,
) -> Result<Vec<u8>> {
    if matches!(expect, Expect::Any(_) | Expect::Erc7739 { .. }) {
        return Err(Error::Argument);
    }
    if check(td, &expect)? != td.digest()? {
        return Err(Error::PolicyRefused);
    }
    key.sign_request(&SignRequest::BlsMultiMember {
        key_data: key_data.to_vec(),
        message: scaas_bls_multi_message(td)?,
        role: super::signer::SigRole::Authorization,
    })
}

// --- the ports of clientkeys `evm.js` (same order of checks; every refusal is `PolicyRefused`) ---

fn refuse<T>() -> Result<T> {
    Err(Error::PolicyRefused)
}
/// What the user asked for, as the digest of its rebuilt typed data.
fn check(td: &TypedData, e: &Expect) -> Result<[u8; 32]> {
    match e {
        Expect::Payment {
            account,
            chain_id,
            chain_uid,
            amount,
            decimals,
            payee,
            entry_ref,
            expected_token,
            max_fee,
            fee_recipient,
            relayer,
            now,
            max_window,
        } => payment(
            td,
            &Pay {
                account,
                chain_id: *chain_id,
                chain_uid,
                amount,
                decimals: *decimals,
                payee,
                expected_token,
                max_fee,
                fee_recipient: fee_recipient.as_ref(),
                relayer: relayer.as_ref(),
                now: *now,
                max_window: *max_window,
            },
            entry_ref,
        ),
        Expect::PayeeFee {
            payee,
            chain_id,
            chain_uid,
            amount,
            decimals,
            entry_ref,
            expected_token,
            max_fee,
            fee_recipient,
            now,
            max_window,
        } => payee_fee(
            td,
            payee,
            *chain_id,
            chain_uid,
            &to_base(amount, *decimals)?,
            entry_ref,
            expected_token,
            max_fee,
            fee_recipient,
            *now,
            *max_window,
        ),
        Expect::PayMeta {
            meta,
            entry_ref,
            account,
            chain_id,
            chain_uid,
            amount,
            decimals,
            payee,
            expected_token,
            max_fee,
            fee_recipient,
            relayer,
            now,
            max_window,
        } => {
            // clientkeys `payMetaParts`: the checked `PayMeta`, its commitment, the request's `entryRef`, the body read strictly
            let pay_id = meta_pay_id_v3(meta).map_err(|_| Error::PolicyRefused)?;
            if entry_ref.is_some_and(|e| e != pay_id) {
                return refuse();
            }
            decode_meta_body(meta.schema, &meta.body)?;
            if !same(obj(td.message()).get("entryRef"), &pay_id) {
                return refuse();
            }
            payment(
                td,
                &Pay {
                    account,
                    chain_id: *chain_id,
                    chain_uid,
                    amount,
                    decimals: *decimals,
                    payee,
                    expected_token,
                    max_fee,
                    fee_recipient: fee_recipient.as_ref(),
                    relayer: relayer.as_ref(),
                    now: *now,
                    max_window: *max_window,
                },
                &pay_id,
            )
        }
        Expect::Op {
            op,
            contract,
            chain_id,
            chain_uid,
            message,
            max_fee,
            fee_recipient,
            relayer,
            now,
            max_window,
        } => check_op(
            td,
            op,
            contract,
            *chain_id,
            chain_uid,
            message,
            max_fee,
            fee_recipient.as_ref(),
            relayer.as_ref(),
            *now,
            *max_window,
        ),
        Expect::Transfer {
            account,
            chain_id,
            chain_uid,
            amount,
            decimals,
            payee,
            batch,
            expected_token,
            max_fee,
            fee_recipient,
            relayer,
            now,
            max_window,
        } => plain_transfer(
            td,
            &Pay {
                account,
                chain_id: *chain_id,
                chain_uid,
                amount,
                decimals: *decimals,
                payee,
                expected_token,
                max_fee,
                fee_recipient: fee_recipient.as_ref(),
                relayer: relayer.as_ref(),
                now: *now,
                max_window: *max_window,
            },
            batch,
        ),
        Expect::Execute {
            wallet,
            chain_id,
            chain_uid,
            message,
            call,
            max_fee,
            fee_recipient,
            relayer,
            now,
            max_window,
        } => {
            let (target, value, data) = call.encode()?;
            let mut m = message.as_object().cloned().ok_or(Error::PolicyRefused)?;
            m.insert("target".into(), to_hex(&target).into());
            m.insert("value".into(), dec(&value));
            m.insert("data".into(), to_hex(&data).into());
            // a mandate wallet's `UAExecute`, or a `SmartKeyAccount`'s `Execute` (scaas-sdk T13): `check_op` holds the typed
            // data to that struct's row and `wallet` as its verifying contract either way
            let op = match td.primary_type() {
                "Execute" => "Execute",
                _ => "UAExecute",
            };
            check_op(
                td,
                op,
                wallet,
                *chain_id,
                chain_uid,
                &Value::Object(m),
                max_fee,
                fee_recipient.as_ref(),
                relayer.as_ref(),
                *now,
                *max_window,
            )
        }
        Expect::Call {
            account,
            chain_id,
            chain_uid,
            allowlist,
            contract,
            data,
            max_fee,
            fee_recipient,
            relayer,
            now,
            max_window,
        } => call(
            td,
            account,
            *chain_id,
            chain_uid,
            allowlist,
            contract,
            data,
            max_fee,
            fee_recipient.as_ref(),
            relayer.as_ref(),
            *now,
            *max_window,
        ),
        Expect::OwnerCall {
            account,
            chain_id,
            chain_uid,
            new_key: k,
            now,
            max_window,
        } => {
            let message = serde_json::json!({"from": to_hex(account), "kind": k.kind, "x": to_hex(&k.x), "y": to_hex(&k.y),
                "rpIdHash": to_hex(&k.rp_id_hash), "originHash": to_hex(&k.origin_hash), "batch": 0, "mode": 0,
                "relayer": ZERO_ADDRESS, "fee": 0, "feeRecipient": ZERO_ADDRESS});
            check_op(
                td,
                "AddKey",
                account,
                *chain_id,
                chain_uid,
                &message,
                "0",
                None,
                None,
                *now,
                *max_window,
            )
        }
        Expect::Cancel {
            account,
            chain_id,
            chain_uid,
            contract,
            order,
            invalidate,
            ua,
        } => cancel(
            td,
            account,
            *chain_id,
            chain_uid,
            contract,
            order.as_ref(),
            invalidate.as_ref(),
            *ua,
        ),
        Expect::TradeOrder {
            account,
            chain_id,
            chain_uid,
            order,
            sell_token,
            outside,
            dexes,
            ua,
            now,
            max_window,
        } => trade_order(
            td,
            account,
            *chain_id,
            chain_uid,
            order,
            sell_token,
            *outside,
            dexes,
            *ua,
            *now,
            *max_window,
        ),
        Expect::WrapOrder {
            account,
            chain_id,
            chain_uid,
            order,
            sell_token,
            wrappers,
            now,
            max_window,
        } => wrap_order(
            td,
            account,
            *chain_id,
            chain_uid,
            order,
            sell_token,
            wrappers,
            *now,
            *max_window,
        ),
        Expect::LiquidityOrder {
            account,
            chain_id,
            chain_uid,
            order,
            dexes,
            liquidity_dexes,
            readers,
            scaas_tokens,
            extra_tokens,
            partial,
            now,
            max_window,
        } => liquidity_order(
            td,
            &Liquidity {
                account,
                chain_id: *chain_id,
                chain_uid,
                order,
                dexes,
                liquidity_dexes,
                readers,
                scaas_tokens,
                extra_tokens,
                partial: *partial,
                now: *now,
                max_window: *max_window,
            },
        ),
        Expect::Erc7739 {
            app,
            wallet,
            address,
            chain_id,
            chain_uid,
        } => app
            .erc7739(*wallet, address, *chain_id, chain_uid)?
            .digest(),
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
    x.get(..31)
        .filter(|h| h.iter().all(|b| *b == 0))
        .and(x.last().copied())
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
fn build(
    primary: &str,
    name: Option<&str>,
    contract: &[u8; 20],
    chain_id: u64,
    chain_uid: &[u8; 32],
    message: Map<String, Value>,
) -> Result<[u8; 32]> {
    scaas_typed_data(
        primary,
        name,
        contract,
        chain_id,
        chain_uid,
        &Value::Object(message),
    )
    .and_then(|t| t.digest())
    .map_err(|_| Error::PolicyRefused)
}
fn name_of(td: &TypedData) -> Option<&str> {
    td.domain().get("name").and_then(Value::as_str)
}

/// clientkeys `feePolicy` (CTR-MTX-13): known flags and fee kind, NONE carries no fee, FIXED `fee`, PERCENT (≤ 1 %, only with an
/// amount) ⌊basis · fee / 10^6⌋, at most `max_fee`; a bound fee recipient is the one named, a bound relayer the one named if any.
fn fee_policy(
    m: &Map<String, Value>,
    max_fee: &str,
    fee_recipient: Option<&[u8; 20]>,
    relayer: Option<&[u8; 20]>,
    basis: Option<&U256>,
) -> Result<()> {
    let mode = small(&uint(get(m, "mode"))?).ok_or(Error::PolicyRefused)?;
    let fee = fee_of(m, basis)?;
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
/// The fee an envelope pays its relayer (`feePolicy`'s amount): NONE 0 (any other `fee` refused), FIXED `fee`, PERCENT (≤ 1 %, only
/// with an amount) ⌊basis · fee / 10^6⌋.
fn fee_of(m: &Map<String, Value>, basis: Option<&U256>) -> Result<U256> {
    let mode = small(&uint(get(m, "mode"))?).ok_or(Error::PolicyRefused)?;
    let kind = mode >> 4;
    if mode & !0xf3 != 0 || kind > 2 {
        return refuse();
    }
    let rate = uint(get(m, "fee"))?;
    if kind == 0 && !zero(&rate) {
        return refuse();
    }
    if kind != 1 {
        return Ok(rate);
    }
    let (Some(basis), Some(r)) = (basis, small_u64(&rate).filter(|r| *r <= 10_000)) else {
        return refuse();
    };
    let (q, rem) = u256_div(basis, 1_000_000);
    let hi = u256_mul_add(&q, r, 0).ok_or(Error::PolicyRefused)?;
    u256_add(&hi, &u256_from(rem * r / 1_000_000)).ok_or(Error::PolicyRefused)
}

/// The fee the relayer takes under the envelope of struct `op`'s `message`, decimal, as the signing check computes it (scaas-sdk
/// closing review P2-4): the amount a review shows and the `max_fee` a check is given. For a PERCENT envelope the basis is the
/// struct's amount field (its op row's, else `value`), a nested `payment`'s `value` for the structs that carry one.
/// A struct without a fee form is 0. `PolicyRefused`: an unknown fee kind, a fee on NONE, PERCENT above 1 % or without an amount.
pub fn fee_due(op: &str, message: &Value) -> Result<String> {
    let m = obj(message);
    let (env, basis) = match get(&m, "payment") {
        Some(Value::Object(p)) => (
            p.clone(),
            get(p, "value").map(|v| uint(Some(v))).transpose()?,
        ),
        // a row without the envelope (`UAWrapOrder`: its `fee` the DEX fee rate the order caps, no fee mode) pays its relayer
        // no envelope fee (owner ruling G6, 2026-11-19: it was `PolicyRefused` at any fee for the missing mode)
        _ if op_row(op).is_some_and(|o| !o.envelope) => return Ok("0".into()),
        _ => {
            let field = op_row(op).and_then(|o| o.amount).unwrap_or("value");
            let basis = get(&m, field).map(|v| uint(Some(v))).transpose()?;
            (m.clone(), basis)
        }
    };
    if get(&env, "mode").is_none() && get(&env, "fee").is_none() {
        return Ok("0".into()); // a struct without a fee form (`UARelayFee` pays its fee as its value)
    }
    Ok(u256_to_dec(&fee_of(&env, basis.as_ref())?))
}

fn small_u64(x: &U256) -> Option<u64> {
    let (hi, lo) = x.split_at(24);
    hi.iter()
        .all(|b| *b == 0)
        .then(|| lo.iter().fold(0u64, |a, b| a << 8 | u64::from(*b)))
}

/// The payment inputs `checkPayment` and `checkPayMeta` share.
struct Pay<'a> {
    account: &'a [u8; 32],
    chain_id: u64,
    chain_uid: &'a [u8; 32],
    amount: &'a str,
    decimals: u32,
    payee: &'a [u8; 32],
    expected_token: &'a [u8; 20],
    max_fee: &'a str,
    fee_recipient: Option<&'a [u8; 20]>,
    relayer: Option<&'a [u8; 20]>,
    now: u64,
    max_window: u64,
}

/// clientkeys `checkPayment`.
fn payment(td: &TypedData, p: &Pay, entry_ref: &[u8; 32]) -> Result<[u8; 32]> {
    if td.primary_type() != "UAMetaTransfer" {
        return refuse();
    }
    let (m, d) = (obj(td.message()), td.domain());
    if !same(d.get("verifyingContract"), p.expected_token) || !same(get(&m, "to"), p.payee) {
        return refuse();
    }
    let value = to_base(p.amount, p.decimals)?;
    if uint(get(&m, "value"))? != value
        || zero(&value)
        || *entry_ref == [0; 32]
        || !same(get(&m, "entryRef"), entry_ref)
    {
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
    build(
        "UAMetaTransfer",
        name_of(td),
        p.expected_token,
        p.chain_id,
        p.chain_uid,
        msg,
    )
}

/// A plain transfer on ids (ruling D): `checkPayment`'s rules with `entryRef = 0` on the named lane `batch`, the lane's nonce.
fn plain_transfer(td: &TypedData, p: &Pay, batch: &str) -> Result<[u8; 32]> {
    if td.primary_type() != "UAMetaTransfer" {
        return refuse();
    }
    let (m, d) = (obj(td.message()), td.domain());
    if !same(d.get("verifyingContract"), p.expected_token) || !same(get(&m, "to"), p.payee) {
        return refuse();
    }
    let value = to_base(p.amount, p.decimals)?;
    let lane = uint_str(batch)?;
    if uint(get(&m, "value"))? != value
        || zero(&value)
        || !same(get(&m, "entryRef"), &[0u8; 32])
        || uint(get(&m, "batch"))? != lane
    {
        return refuse();
    }
    fee_policy(&m, p.max_fee, p.fee_recipient, p.relayer, Some(&value))?;
    deadline(get(&m, "validUntil"), p.now, p.max_window)?;
    let mut msg = m.clone();
    msg.insert("from".into(), to_hex(p.account).into());
    msg.insert("to".into(), to_hex(p.payee).into());
    msg.insert("value".into(), dec(&value));
    msg.insert("entryRef".into(), to_hex(&[0u8; 32]).into());
    msg.insert("batch".into(), dec(&lane));
    msg.insert("nonce".into(), dec(&uint(get(&m, "nonce"))?));
    build(
        "UAMetaTransfer",
        name_of(td),
        p.expected_token,
        p.chain_id,
        p.chain_uid,
        msg,
    )
}

/// clientkeys `checkPayeeFee`.
#[allow(clippy::too_many_arguments)]
fn payee_fee(
    td: &TypedData,
    payee: &[u8],
    chain_id: u64,
    chain_uid: &[u8; 32],
    value: &U256,
    entry_ref: &[u8; 32],
    token: &[u8; 20],
    max_fee: &str,
    fee_recipient: &[u8; 20],
    now: u64,
    max_window: u64,
) -> Result<[u8; 32]> {
    if td.primary_type() != "UAPayeeFee" {
        return refuse();
    }
    let (m, d) = (obj(td.message()), td.domain());
    let p = obj(get(&m, "payment").unwrap_or(&Value::Null));
    if !same(d.get("verifyingContract"), token) || !same(get(&p, "to"), payee) {
        return refuse();
    }
    if uint(get(&p, "value"))? != *value
        || zero(value)
        || *entry_ref == [0; 32]
        || !same(get(&p, "entryRef"), entry_ref)
    {
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
    if zero(&fee)
        || fee > *value
        || fee > uint_str(max_fee)?
        || !same(get(&m, "feeRecipient"), fee_recipient)
    {
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
    msg.insert(
        "validUntil".into(),
        get(&m, "validUntil").cloned().unwrap_or(Value::Null),
    );
    build("UAPayeeFee", name_of(td), token, chain_id, chain_uid, msg)
}

const E_FIELDS: [&str; 7] = [
    "batch",
    "nonce",
    "validUntil",
    "mode",
    "relayer",
    "fee",
    "feeRecipient",
];

/// clientkeys `requireWhole`: every field of the client's value present (on the envelope struct `open`, the `E` fields may be the
/// server's), recursively; a relayer or fee recipient it names must be bound by its mode (the server's when the client leaves it).
fn require_whole(
    types: &BTreeMap<String, Fields>,
    ty: &str,
    v: Option<&Value>,
    open: bool,
    mode: Option<&Value>,
) -> Result<()> {
    if let Some(elem) = ty.strip_suffix("[]") {
        let Some(Value::Array(a)) = v else {
            return refuse();
        };
        return a
            .iter()
            .try_for_each(|x| require_whole(types, elem, Some(x), false, None));
    }
    let Some(fields) = types.get(ty) else {
        return Ok(());
    };
    let Some(Value::Object(o)) = v else {
        return refuse();
    };
    for (n, t) in fields {
        if open && E_FIELDS.contains(&n.as_str()) {
            continue;
        }
        let x = get(o, n).ok_or(Error::PolicyRefused)?;
        require_whole(types, t, Some(x), false, None)?;
    }
    if !["mode", "relayer", "feeRecipient"]
        .iter()
        .all(|k| fields.iter().any(|(n, _)| n == k))
    {
        return Ok(());
    }
    let bits = uint(get(o, "mode").or(mode.filter(|m| !m.is_null())))?
        .last()
        .copied()
        .unwrap_or(0);
    let dropped = |k: &str, bit: u8| {
        get(o, k).is_some_and(|id| js_str(Some(id)) != ZERO_ADDRESS) && bits & bit == 0
    };
    if dropped("relayer", 1) || dropped("feeRecipient", 2) {
        return refuse();
    }
    Ok(())
}

/// clientkeys `checkOp` (`checkOwnerCall` through it): struct `op` on `contract`, every field of `message` the client's.
#[allow(clippy::too_many_arguments)]
fn check_op(
    td: &TypedData,
    op: &str,
    contract: &[u8; 20],
    chain_id: u64,
    chain_uid: &[u8; 32],
    message: &Value,
    max_fee: &str,
    fee_recipient: Option<&[u8; 20]>,
    relayer: Option<&[u8; 20]>,
    now: u64,
    max_window: u64,
) -> Result<[u8; 32]> {
    if op == "UAWrapOrder" {
        return refuse(); // `checkWrapOrder` carries its rules (CLI-SGN-36)
    }
    // a row of the op table (clientkeys `TYPED_OPS[op]`), never a generic-path struct
    let Some(o) = op_row(op) else { return refuse() };
    if td.primary_type() != o.primary {
        return refuse();
    }
    let (m, d) = (obj(td.message()), td.domain());
    if !same(d.get("verifyingContract"), contract) {
        return refuse();
    }
    let types = op_types(op).map_err(|_| Error::PolicyRefused)?;
    require_whole(
        &types,
        o.primary,
        Some(message),
        o.envelope,
        get(&m, "mode"),
    )?;
    let msg = message.as_object().ok_or(Error::PolicyRefused)?;
    let mut full = Map::new();
    if o.envelope {
        let basis = o.amount.map(|a| uint(get(msg, a))).transpose()?;
        let mut merged = m.clone();
        merged.extend(msg.clone());
        fee_policy(&merged, max_fee, fee_recipient, relayer, basis.as_ref())?;
        deadline(
            get(msg, "validUntil").or(get(&m, "validUntil")),
            now,
            max_window,
        )?;
        full.insert("batch".into(), dec(&uint(get(&m, "batch"))?));
        full.insert("nonce".into(), dec(&uint(get(&m, "nonce"))?));
        for k in ["validUntil", "mode", "relayer", "fee", "feeRecipient"] {
            if let Some(v) = get(&m, k) {
                full.insert(k.into(), v.clone());
            }
        }
    }
    full.extend(msg.clone());
    typed_data_of(
        &o,
        name_of(td),
        contract,
        chain_id,
        chain_uid,
        &Value::Object(full),
    )
    .and_then(|t| t.digest())
    .map_err(|_| Error::PolicyRefused)
}

/// The selectors never signed as a call (CLI-SGN-34, CLI-SGN-36): moving funds and approvals; clientkeys `NEVER_CALLED`, the
/// pay entries in every `PayMeta` form (v2 `(bytes32,string,uint16,bytes)`, gone with T83, and v3).
fn never_called(selector: &[u8]) -> bool {
    [
        "transfer(address,uint256)", "transferFrom(address,address,uint256)", "approve(address,uint256)",
        "payWithFee(address,uint256,uint8,uint256,address,bytes32)", "pay(bytes32)",
        "payWithFeeToUA(bytes32,uint256,uint8,uint256,address,bytes32)",
        "payWithFee(address,uint256,uint8,uint256,address,bytes32,(bytes32,string,uint16,bytes))",
        "payWithFeeToUA(bytes32,uint256,uint8,uint256,address,bytes32,(bytes32,string,uint16,bytes))",
        "payWithTax(bytes32,uint256,uint8,uint256,bytes32,(bytes32,string,uint16,bytes))",
        "payWithFee(address,uint256,uint8,uint256,address,bytes32,(bytes32,bytes32,bool,uint16,bytes))",
        "payWithFeeToUA(bytes32,uint256,uint8,uint256,address,bytes32,(bytes32,bytes32,bool,uint16,bytes))",
        "payWithTax(bytes32,uint256,uint8,uint256,bytes32,(bytes32,bytes32,bool,uint16,bytes))",
    ]
    .iter()
    .any(|s| keccak256(s.as_bytes()).get(..4) == Some(selector))
}

/// clientkeys `checkCall`: the self-call `MetaTransaction` of exactly `data` on `contract`.
#[allow(clippy::too_many_arguments)]
fn call(
    td: &TypedData,
    account: &[u8; 20],
    chain_id: u64,
    chain_uid: &[u8; 32],
    allowlist: &[AllowRow],
    contract: &[u8; 20],
    data: &[u8],
    max_fee: &str,
    fee_recipient: Option<&[u8; 20]>,
    relayer: Option<&[u8; 20]>,
    now: u64,
    max_window: u64,
) -> Result<[u8; 32]> {
    if td.primary_type() != "MetaTransaction" {
        return refuse();
    }
    let (m, d) = (obj(td.message()), td.domain());
    if !same(d.get("verifyingContract"), contract) || !same(get(&m, "data"), data) {
        return refuse();
    }
    let Some(selector) = data.get(..4) else {
        return refuse();
    };
    if never_called(selector) {
        return refuse();
    }
    let Some(row) = allowlist.iter().find(|r| r.selector == selector) else {
        return refuse();
    };
    // checked in `usize`: `32 * amountArg` wraps on a 32-bit target (wasm32); past the calldata, no basis (a PERCENT fee refused)
    let word = usize::try_from(row.amount_arg)
        .ok()
        .and_then(|a| a.checked_mul(32)?.checked_add(4))
        .and_then(|at| data.get(at..at.checked_add(32)?));
    let basis = (row.fee_class == 2)
        .then(|| word.and_then(|w| <U256>::try_from(w).ok()))
        .flatten();
    fee_policy(&m, max_fee, fee_recipient, relayer, basis.as_ref())?;
    deadline(get(&m, "validUntil"), now, max_window)?;
    let mut msg = m.clone();
    msg.insert("from".into(), to_hex(account).into());
    msg.insert("data".into(), to_hex(data).into());
    build(
        "MetaTransaction",
        name_of(td),
        contract,
        chain_id,
        chain_uid,
        msg,
    )
}

const CANCELS: [&str; 3] = ["CancelUAOrder", "CancelUAWrapOrder", "CancelDexOrder"];

/// clientkeys `checkCancel`.
#[allow(clippy::too_many_arguments)]
fn cancel(
    td: &TypedData,
    account: &[u8],
    chain_id: u64,
    chain_uid: &[u8; 32],
    contract: &[u8; 20],
    order: Option<&Value>,
    invalidate: Option<&Invalidate>,
    ua: bool,
) -> Result<[u8; 32]> {
    if let Some(i) = invalidate {
        let mut msg = Map::new();
        msg.insert("from".into(), to_hex(account).into());
        msg.insert("batch".into(), i.batch.clone().into());
        msg.insert("minNonce".into(), i.min_nonce.clone().into());
        return build(
            if ua {
                "UAInvalidateNonces"
            } else {
                "InvalidateNonces"
            },
            name_of(td),
            contract,
            chain_id,
            chain_uid,
            msg,
        );
    }
    let primary = td.primary_type();
    if !CANCELS.contains(&primary) {
        return refuse();
    }
    let order = order.cloned().unwrap_or(Value::Null);
    let o = obj(&order);
    let held = if primary == "CancelDexOrder" {
        obj(get(&o, "order").unwrap_or(&Value::Null))
    } else {
        o.clone()
    };
    if !same(get(&held, "from"), account) {
        return refuse();
    }
    // `dex == receiveToken` was signed as a `UAWrapOrder`: its cancel is a `CancelUAWrapOrder` (TS-D19)
    if primary == "CancelUAOrder" && js_str(o.get("dex")) == js_str(o.get("receiveToken")) {
        return refuse();
    }
    check_op(
        td,
        primary,
        contract,
        chain_id,
        chain_uid,
        &serde_json::json!({"order": order}),
        "0",
        None,
        None,
        0,
        0,
    )
}

/// The order the client built: `order` over the defaults, `from` the account, the server's nonce, `validUntil` the client's or
/// the server's.
fn order_of(
    order: &Value,
    account: &[u8],
    got: &Map<String, Value>,
    ua: bool,
) -> Result<Map<String, Value>> {
    let Value::Object(given) = order else {
        return refuse();
    };
    let mut o = Map::new();
    for (k, v) in [
        ("minFill", "0".into()),
        ("fee", "0".into()),
        ("relayer", ZERO_ADDRESS.into()),
        (
            "destination",
            (if ua { ZERO_ID } else { ZERO_ADDRESS }).into(),
        ),
        ("flags", 0.into()),
        ("batch", "0".into()),
    ] {
        o.insert(k.to_string(), v);
    }
    o.extend(given.clone());
    o.insert("from".into(), to_hex(account).into());
    o.insert("nonce".into(), dec(&uint(get(got, "nonce"))?));
    let valid_until = get(given, "validUntil")
        .or(get(got, "validUntil"))
        .cloned()
        .unwrap_or(Value::Null);
    o.insert("validUntil".into(), valid_until);
    Ok(o)
}

/// clientkeys `orderTerms` (CLI-SGN-35): a nonce below 2^128, a fee of at most 1 %, known flags (no ESCROW outside).
fn order_terms(o: &Map<String, Value>, outside: bool) -> Result<()> {
    let nonce = uint(get(o, "nonce"))?;
    if nonce.get(..16).is_some_and(|h| h.iter().any(|b| *b != 0))
        || uint(get(o, "fee"))? > u256_from(10_000)
    {
        return refuse();
    }
    let flags = small(&uint(get(o, "flags"))?).ok_or(Error::PolicyRefused)?;
    if flags & !7 != 0 || (flags & 2 != 0 && (outside || flags & 1 == 0)) {
        return refuse();
    }
    Ok(())
}

/// A plan token of a liquidity order: its address (if one) and its amount.
type PlanToken<'a> = (Option<[u8; 20]>, Option<&'a Value>);

/// The inputs of [`liquidity_order`], as [`Expect::LiquidityOrder`] names them.
struct Liquidity<'a> {
    account: &'a [u8; 32],
    chain_id: u64,
    chain_uid: &'a [u8; 32],
    order: &'a Value,
    dexes: &'a [[u8; 20]],
    liquidity_dexes: &'a [[u8; 20]],
    readers: &'a [([u8; 20], Vec<[u8; 20]>)],
    scaas_tokens: &'a [[u8; 20]],
    extra_tokens: &'a [[u8; 20]],
    partial: bool,
    now: u64,
    max_window: u64,
}

/// clientkeys `checkLiquidityOrder` (T21 L40), the same refusals in the same order (a RelayFeeRouter wrap is not offered here,
/// so its refusal has no input): the DEX on the profile and liquidity-capable; the order's own terms (nonce below 2^128, fee at
/// most 1 %, flags 4 only, at most eight tokens per list, no token repeated or shared, no zero input maximum, no zero token and
/// not the position manager); a position needs its manager; a received position `tickLower < tickUpper`, a minimum liquidity
/// and a profile reader of its manager, else no position field; a partial withdraw receives the position back; the recipient
/// (0: `from`) is no plan token, manager or DEX; a derived signer gives and a derived recipient receives SCaaS ledger tokens only
/// and no position; the deadline near. The digest of the rebuilt order.
fn liquidity_order(td: &TypedData, l: &Liquidity) -> Result<[u8; 32]> {
    if td.primary_type() != "LiquidityOrder" {
        return refuse();
    }
    let dex: [u8; 20] = td
        .domain()
        .get("verifyingContract")
        .and_then(Value::as_str)
        .and_then(from_hex)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::PolicyRefused)?;
    if !l.dexes.contains(&dex) || !l.liquidity_dexes.contains(&dex) {
        return refuse();
    }
    let got = obj(td.message());
    let Value::Object(given) = l.order else {
        return refuse();
    };
    let mut o = Map::new();
    for (k, v) in [
        ("inputs", Value::Array(vec![])),
        ("outputs", Value::Array(vec![])),
        ("positionManager", ZERO_ADDRESS.into()),
        ("positionReader", ZERO_ADDRESS.into()),
        ("positionIn", "0".into()),
        ("positionPool", ZERO_ID.into()),
        ("tickLower", 0.into()),
        ("tickUpper", 0.into()),
        ("minLiquidity", "0".into()),
        ("recipient", ZERO_ID.into()),
        ("fee", "0".into()),
        ("relayer", ZERO_ADDRESS.into()),
        ("flags", 0.into()),
        ("batch", "0".into()),
    ] {
        o.insert(k.to_string(), v);
    }
    o.extend(given.clone());
    o.insert("from".into(), to_hex(l.account).into());
    let nonce = uint(get(&got, "nonce"))?;
    o.insert("nonce".into(), dec(&nonce));
    let valid_until = get(given, "validUntil")
        .or(get(&got, "validUntil"))
        .cloned()
        .unwrap_or(Value::Null);
    o.insert("validUntil".into(), valid_until);
    if nonce.get(..16).is_some_and(|h| h.iter().any(|b| *b != 0))
        || uint(get(&o, "fee"))? > u256_from(10_000)
    {
        return refuse();
    }
    if small(&uint(get(&o, "flags"))?).is_none_or(|f| f & !4 != 0) {
        return refuse();
    }
    let addr = |v: Option<&Value>| -> Result<[u8; 20]> {
        v.and_then(Value::as_str)
            .and_then(from_hex)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::PolicyRefused)
    };
    let list = |k: &str| -> Result<Vec<PlanToken>> {
        let Some(Value::Array(a)) = o.get(k) else {
            return refuse();
        };
        Ok(a.iter()
            .map(|t| (addr(t.get("token")).ok(), t.get("amount")))
            .collect())
    };
    let (inputs, outputs) = (list("inputs")?, list("outputs")?);
    if inputs.len() > 8 || outputs.len() > 8 || l.extra_tokens.len() > 8 {
        return refuse();
    }
    let all: Vec<[u8; 20]> = inputs
        .iter()
        .chain(&outputs)
        .map(|(t, _)| t.ok_or(Error::PolicyRefused))
        .chain(l.extra_tokens.iter().copied().map(Ok))
        .collect::<Result<_>>()?;
    if all
        .iter()
        .enumerate()
        .any(|(i, t)| all.iter().take(i).any(|x| x == t))
    {
        return refuse();
    }
    for (_, amount) in &inputs {
        if zero(&uint(*amount)?) {
            return refuse();
        }
    }
    let pm = addr(get(&o, "positionManager"))?;
    let pool = get(&o, "positionPool")
        .and_then(Value::as_str)
        .and_then(from_hex)
        .filter(|b| b.len() == 32)
        .ok_or(Error::PolicyRefused)?;
    let received = pool.iter().any(|b| *b != 0);
    let given_pos = !zero(&uint(get(&o, "positionIn"))?);
    if all.iter().any(|t| *t == [0; 20] || *t == pm) || (pm == [0; 20] && (given_pos || received)) {
        return refuse();
    }
    let tick = |k: &str| -> Result<i64> {
        match get(&o, k) {
            Some(Value::Number(n)) => n.as_i64().ok_or(Error::PolicyRefused),
            Some(Value::String(s)) => s.parse().map_err(|_| Error::PolicyRefused),
            _ => refuse(),
        }
    };
    let (lower, upper, min_liquidity) = (
        tick("tickLower")?,
        tick("tickUpper")?,
        uint(get(&o, "minLiquidity"))?,
    );
    let reader = addr(get(&o, "positionReader"))?;
    if received {
        if lower >= upper
            || zero(&min_liquidity)
            || !l
                .readers
                .iter()
                .any(|(m, rs)| *m == pm && rs.contains(&reader))
        {
            return refuse();
        }
    } else if reader != [0; 20] || lower != 0 || upper != 0 || !zero(&min_liquidity) {
        return refuse();
    }
    if l.partial && given_pos && !received {
        return refuse();
    }
    let rec: [u8; 32] = get(&o, "recipient")
        .and_then(Value::as_str)
        .and_then(from_hex)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::PolicyRefused)?;
    let recipient = if rec == [0; 32] { *l.account } else { rec };
    let pad = |a: &[u8; 20]| {
        let mut w = [0u8; 32];
        w.get_mut(12..)
            .into_iter()
            .for_each(|x| x.copy_from_slice(a));
        w
    };
    if all.iter().chain([&pm, &dex]).any(|a| pad(a) == recipient) {
        return refuse();
    }
    let native = |id: &[u8; 32]| id.get(..12) == Some(&[0; 12][..]);
    let ledger = |t: &Option<[u8; 20]>| t.is_some_and(|t| l.scaas_tokens.contains(&t));
    if !native(l.account) && (given_pos || inputs.iter().any(|(t, _)| !ledger(t))) {
        return refuse();
    }
    if !native(&recipient) && (received || outputs.iter().any(|(t, _)| !ledger(t))) {
        return refuse();
    }
    deadline(get(&o, "validUntil"), l.now, l.max_window)?;
    liquidity_order_typed_data(&dex, l.chain_id, l.chain_uid, &Value::Object(o))
        .and_then(|t| t.digest())
        .map_err(|_| Error::PolicyRefused)
}

/// clientkeys `checkTradeOrder`.
#[allow(clippy::too_many_arguments)]
fn trade_order(
    td: &TypedData,
    account: &[u8],
    chain_id: u64,
    chain_uid: &[u8; 32],
    order: &Value,
    sell_token: &[u8; 20],
    outside: bool,
    dexes: &[[u8; 20]],
    ua: bool,
    now: u64,
    max_window: u64,
) -> Result<[u8; 32]> {
    if ua == outside {
        return refuse(); // a UA order sells a SCaaS token only; a SCaaS sell token takes a `UATradeOrder`
    }
    let want = if outside { "DexOrder" } else { "UATradeOrder" };
    if td.primary_type() != want {
        return refuse();
    }
    let msg = obj(td.message());
    let got = if outside {
        obj(get(&msg, "order").unwrap_or(&Value::Null))
    } else {
        msg
    };
    let o = order_of(order, account, &got, ua)?;
    order_terms(&o, outside)?;
    if js_str(o.get("receiveToken")) == js_str(o.get("dex"))
        || !dexes.iter().any(|x| same(get(&o, "dex"), x))
    {
        return refuse();
    }
    let (amount, min_fill) = (uint(get(&o, "amount"))?, uint(get(&o, "minFill"))?);
    if zero(&amount) || zero(&uint(get(&o, "receiveAmount"))?) || min_fill > amount {
        return refuse();
    }
    deadline(get(&o, "validUntil"), now, max_window)?;
    // the struct's own fields of the order (tradeOrderTypedData keeps those)
    let types = op_types(want).map_err(|_| Error::PolicyRefused)?;
    let fields = types
        .get(if outside { "TradeOrder" } else { want })
        .ok_or(Error::PolicyRefused)?;
    let picked: Map<String, Value> = fields
        .iter()
        .filter_map(|(n, _)| o.get(n).map(|v| (n.clone(), v.clone())))
        .collect();
    let name = name_of(td).filter(|n| !n.is_empty());
    if outside {
        let dex: [u8; 20] = get(&o, "dex")
            .and_then(Value::as_str)
            .and_then(from_hex)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::PolicyRefused)?;
        let mut m = Map::new();
        m.insert("sellToken".into(), to_hex(sell_token).into());
        m.insert("order".into(), Value::Object(picked));
        return build("DexOrder", name, &dex, chain_id, chain_uid, m);
    }
    build(want, name, sell_token, chain_id, chain_uid, picked)
}

/// clientkeys `checkWrapOrder` (and `checkUAWrapOrder`): a `UAWrapOrder`.
#[allow(clippy::too_many_arguments)]
fn wrap_order(
    td: &TypedData,
    account: &[u8],
    chain_id: u64,
    chain_uid: &[u8; 32],
    order: &Value,
    sell_token: &[u8; 20],
    wrappers: &[[u8; 20]],
    now: u64,
    max_window: u64,
) -> Result<[u8; 32]> {
    let ty = "UAWrapOrder";
    if td.primary_type() != ty {
        return refuse();
    }
    let o = order_of(order, account, &obj(td.message()), true)?;
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

// --- CTR-MTX-26: the payment id commits to its metadata (clientkeys `payMetaParts`, `decodeMetaBody`) ---

fn word_at(b: &[u8], i: usize) -> Result<U256> {
    b.get(32 * i..32 * i + 32)
        .and_then(|w| <U256>::try_from(w).ok())
        .map_or_else(refuse, Ok)
}
fn as_usize(x: &U256) -> Option<usize> {
    small_u64(x).and_then(|v| usize::try_from(v).ok())
}
fn padded(b: &[u8]) -> Vec<u8> {
    let mut out = u256_from(b.len() as u64).to_vec();
    out.extend_from_slice(b);
    out.resize(out.len() + (32 - b.len() % 32) % 32, 0);
    out
}
fn utf8(b: &[u8]) -> Result<()> {
    std::str::from_utf8(b)
        .map(|_| ())
        .map_err(|_| Error::PolicyRefused)
}
/// clientkeys `decodeMetaBody` (CTR-MTX-26, `PayMeta` v3; the body rules unchanged since v2): the body of `schema` read
/// strictly: 0 none; 1 a non-empty UTF-8 note; 2 `abi.encode(string creditorRef, uint64 dueDate)` in canonical form, UTF-8; 3
/// exactly 96 bytes (a bound call); 4 the ciphertext; any other schema is opaque data (shown as such, never as facts).
fn decode_meta_body(schema: u16, b: &[u8]) -> Result<()> {
    match schema {
        0 if b.is_empty() => Ok(()),
        0 => refuse(),
        1 if !b.is_empty() => utf8(b),
        1 => refuse(),
        2 => {
            if b.len() < 96 || word_at(b, 0)? != u256_from(64) {
                return refuse();
            }
            let text = as_usize(&word_at(b, 2)?)
                .and_then(|n| b.get(96..96usize.checked_add(n)?))
                .ok_or(Error::PolicyRefused)?;
            let due = word_at(b, 1)?;
            let mut canon = u256_from(64).to_vec();
            canon.extend_from_slice(&due);
            canon.extend(padded(text));
            if due.get(..24).is_some_and(|h| h.iter().any(|x| *x != 0)) || canon != b {
                return refuse();
            }
            utf8(text)
        }
        3 if b.len() == 96 => Ok(()),
        3 => refuse(),
        _ => Ok(()),
    }
}
