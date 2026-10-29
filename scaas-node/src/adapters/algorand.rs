//! Algorand (near-algorand spec §5 Algorand column; §2 rows 1–17, §4; CTR-MTX-26 / -27; plan Task 17). A `signed_op`
//! job carries `payload` = the `MetaOp` v1 encoding (`"scaas.metaop.v1"` ‖ the ARC-4 static tuple, the vectors'
//! `encoding`), `signature` = the entry's `auth: byte[]` (a native payer's 64-byte wallet signature, else tag ‖ body,
//! account.py), both hex, and `contract` = the token app id (decimal). Lane = an ed25519 account at
//! `m/44'/283'/0'/0'/i'`; Algorand has no account sequence (replay is the txid within FirstValid..LastValid), so a lane
//! has no head-of-line. Each job is one atomic group: transactions are canonical msgpack hand-encoded here, signed over
//! `"TX"` ‖ bytes (`smartcontracts/algorand/vectors/algorand-tx.json` pins the bytes against py-algorand-sdk). The check
//! is algod `simulate` of the exact group (sender of the target = the executor LogicSig, its program evaluated): a group
//! that fails there is refused, and a group that fails on chain is never included, so it costs the lane nothing — the
//! only lane cost is a group that lands (its fee + its MBR payments), which the relay fee must cover. Events = ARC-28
//! logs of configured apps in algod blocks (a block holds only successful groups); finality is one round.
//!
//! Jobs (`op.kind`, `adapter::op_kind`): none = `token.mtx_pay`; `pay_meta` (`op.salt`, `op.meta`) =
//! `token.mtx_pay_meta`; `relay_fee` = the router group `[MBR → router]? [MBR → target]? [target, sender = executor]
//! [router.relay(token, op, auth)] [dex.carry …]` with `op.extra.call` = the router `call` bytes (target app id u64 ‖ u8
//! n ‖ (u16 len ‖ arg)×n), the target's resource references in `op.extra.{accounts, apps, boxes}` and, for a DEX
//! settle with carried auths, `op.extra.carries` (hex auths, a's first). The node then adds bare `budget` calls on the
//! token carrying every resource simulate found unnamed (the msig members' addresses among them), sets each MBR payment
//! to the apps' exact figure and the pooled fee to one min fee per transaction and per inner transaction (+ the per-byte
//! fee when the network sets one).
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use async_trait::async_trait;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512_256};
use tracing::info;

use crate::adapter::{Built, ChainAdapter, Family, Head, Lane, Rejected, Signed, TxStatus};
use crate::addresses::{algorand_address, b32decode, b32encode};
use crate::chain::SimError;
use crate::config::ChainCfg;
use crate::odoo::Job;
use crate::signer::{LocalSigner, Signer};

pub use super::aptos::{meta_pay_id, pay_lane};

pub const LABEL: &[u8] = b"scaas.metaop.v1";
pub const METAOP_LEN: usize = 291;
const OP_PAY: u8 = 0;
const KIND_ADDRESS: u8 = 0;
const KIND_UA: u8 = 1;
/// Task 11's measured fit (`runs/2026-10-28-algorand-limits.txt`, `test_pay_meta_cap_measured`): `PaymentMeta` with
/// more `meta` exceeds the AVM's 1,024 B per-transaction log limit, on the native and the passkey UA payer path.
pub const MAX_PAY_META_BYTES: usize = 507;
/// Lesson 7 (NEAR fix 2 R1 / R2): the payment, a target op, a mandate's expiry and DEX orders / legs must stay valid this
/// long past now, else the group could expire before a round takes it (refused, not lost: it would only fail).
pub const RELAY_EXPIRY_MARGIN_S: u64 = 120;
/// Protocol: LastValid − FirstValid ≤ MaxTxnLife (1,000 rounds in every consensus version).
pub const MAX_TXN_LIFE: u64 = 1000;
const MAX_GROUP: usize = 16;
/// Inner-fee credit of the discovery simulate (T15 `FEE_CREDIT`: the worst measured relay group takes 45–49 inner calls).
pub const DISCOVERY_CREDIT: u64 = 64;
/// Rounds sampled for the round time (two block timestamps).
const ROUND_SAMPLE: u64 = 100;
/// `simulate` extra budget of a read-only query (as the contract tests' `sim`): no inner budget call, no fee credit.
const QUERY_BUDGET: u64 = 20_000;
const BOX_FLAT: u64 = 2_500;
const BOX_BYTE: u64 = 400;
pub const MBR_AMOUNT_BOX: u64 = BOX_FLAT + BOX_BYTE * (33 + 32);
pub const MBR_LANE_BOX: u64 = BOX_FLAT + BOX_BYTE * (33 + 8);
pub const MBR_ORDER_BOX: u64 = BOX_FLAT + BOX_BYTE * (33 + 1);
pub const MBR_MANDATE_BOX: u64 = BOX_FLAT + BOX_BYTE * (41 + 204);
/// account.py record: header, then keys and origins (32 B each); name `"s"` ‖ kind ‖ id (34 B).
const REC_HEADER: usize = 118;
const MAX_ORIGIN_LEN: usize = 128;
const ABI_RETURN: [u8; 4] = [0x15, 0x1f, 0x7c, 0x75];

pub const METAOP_ABI: &str = "(byte[32],byte[32],uint8,(uint8,byte[32]),(uint8,byte[32]),byte[32],uint128,byte[32],byte[32],uint64,uint64,byte[32])";
pub const ORDER_ABI: &str = "(uint64,uint64,uint128,uint128,byte[32],uint64)";
pub const TERMS_ABI: &str = "((uint8,byte[32]),(uint8,byte[32]),uint128,uint128,uint64,uint64,uint128)";
pub const EV_TRANSFER: &str = "arc200_Transfer(address,address,uint256)";
pub const EV_UA_TRANSFER: &str = "UaTransfer((uint8,byte[32]),(uint8,byte[32]),uint256)";
pub const EV_EXECUTED: &str = "MetaTransactionExecuted((uint8,byte[32]),address,byte[32],uint64,byte[32])";
pub const EV_SETTLED: &str = "PaymentSettled((uint8,byte[32]),(uint8,byte[32]),uint256,byte[32])";
pub const EV_META: &str = "PaymentMeta(byte[32],byte[])";
pub const EV_FILLED: &str = "OrderFilled((uint8,byte[32]),address,byte[32],uint64,uint256,byte[32])";
pub const EV_FEE: &str = "RelayFeePaid(byte[32],uint64,uint64,(uint8,byte[32]),(uint8,byte[32]),uint256)";
pub const EV_MANDATE_PAY: &str = "MandatePaymentSettled(uint64,(uint8,byte[32]),(uint8,byte[32]),uint256,byte[32])";
pub const EV_MATCHED: &str = "Matched(byte[32],uint64,uint64,byte[32],byte[32])";
const ADD_KEY_NATIVE: &str = "add_key_native((uint16,byte[]),byte[])void";

const ARTIFACTS: &str = include_str!("../../../smartcontracts/algorand/artifacts.json");

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub fn sha512_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha512_256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    alloy::primitives::keccak256(parts.concat()).0
}

fn hex0x(b: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(b))
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn b64d(s: &str) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

fn now() -> u64 {
    crate::submit::now()
}

/// `sha512_256("appID" ‖ u64 BE)`.
pub fn app_address(id: u64) -> [u8; 32] {
    sha512_256(&[b"appID", &id.to_be_bytes()])
}

/// ARC-4 method selector: the first 4 bytes of `sha512_256(signature)`; an ARC-28 event's too.
pub fn selector(sig: &str) -> [u8; 4] {
    let h = sha512_256(&[sig.as_bytes()]);
    [h[0], h[1], h[2], h[3]]
}

/// A LogicSig's address: `sha512_256("Program" ‖ program)`.
pub fn program_address(program: &[u8]) -> [u8; 32] {
    sha512_256(&[b"Program", program])
}

/// ARC-4 `byte[]`: u16 length ‖ bytes.
pub fn abi_bytes(b: &[u8]) -> Vec<u8> {
    [&(b.len() as u16).to_be_bytes()[..], b].concat()
}

/// Exactly one ARC-4 `byte[]`.
fn un_abi_bytes(b: &[u8]) -> Result<&[u8]> {
    let n = b.get(..2).map(|x| u16::from_be_bytes([x[0], x[1]]) as usize).ok_or_else(|| anyhow!("byte[] without its length"))?;
    ensure!(b.len() == 2 + n, "byte[] length {n} but {} bytes", b.len().saturating_sub(2));
    Ok(&b[2..])
}

fn arr32(b: &[u8]) -> Result<[u8; 32]> {
    b.try_into().map_err(|_| anyhow!("{} bytes, not 32", b.len()))
}

fn be_u64(b: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(b.try_into().map_err(|_| anyhow!("{} bytes, not a uint64", b.len()))?))
}

/// go-algorand `basics.IsEdwards25519Point` / puya's autosalt predicate (conftest `on_curve`): `x² = (y² − 1) / (d y² + 1)`
/// has a root mod p. An off-curve address has no ed25519 key.
pub fn on_curve(key: &[u8; 32]) -> bool {
    use alloy::primitives::U256;
    let p = (U256::from(1u8) << 255) - U256::from(19u8);
    let sub = |a: U256, b: U256| -> U256 { (a + p - b) % p };
    let mut k = *key;
    k[31] &= 0x7f;
    let y = U256::from_le_bytes(k) % p;
    let d = sub(U256::ZERO, U256::from(121_665u32)).mul_mod(U256::from(121_666u32).pow_mod(p - U256::from(2u8), p), p);
    let yy = y.mul_mod(y, p);
    let u = sub(yy, U256::from(1u8));
    let v = d.mul_mod(yy, p).add_mod(U256::from(1u8), p);
    let uv7 = u.mul_mod(v.pow_mod(U256::from(7u8), p), p);
    let x = u.mul_mod(v.pow_mod(U256::from(3u8), p), p).mul_mod(uv7.pow_mod((p - U256::from(5u8)) >> 3usize, p), p);
    let vxx = v.mul_mod(x.mul_mod(x, p), p);
    vxx == u || vxx == sub(U256::ZERO, u)
}

// ------------------------------------------------------------------ executor (T15, ruling T15-salt)

/// The router's keyless executor LogicSig: `EXEC_PREFIX ‖ u64 BE router id ‖ EXEC_SUFFIX ‖ 20 01 salt` (artifacts.json
/// "relayfee"), salt = the router's creation-time global (`intcblock 1 salt`, dead code after the final return).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Executor {
    pub router: u64,
    pub salt: u8,
    pub program: Vec<u8>,
    pub address: [u8; 32],
}

impl Executor {
    pub fn new(router: u64, salt: u8) -> Result<Self> {
        let a: Value = serde_json::from_str(ARTIFACTS).context("artifacts.json")?;
        let part = |k: &str| a["relayfee"][k].as_str().and_then(|s| alloy::hex::decode(s).ok()).ok_or_else(|| anyhow!("artifacts.json relayfee.{k}"));
        ensure!(salt < 128, "executor salt {salt} is not below 128");
        let program = [part("executor_prefix")?, router.to_be_bytes().to_vec(), part("executor_suffix")?, vec![0x20, 1, salt]].concat();
        let address = program_address(&program);
        Ok(Self { router, salt, program, address })
    }
}

// ------------------------------------------------------------------ MetaOp v1 (ARC-4 static tuple)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Holder {
    pub kind: u8,
    pub id: [u8; 32],
}

impl Holder {
    pub fn addr(id: [u8; 32]) -> Self {
        Self { kind: KIND_ADDRESS, id }
    }

    fn read(b: &[u8]) -> Result<Self> {
        ensure!(b.len() == 33, "a holder is 33 bytes");
        let kind = b[0];
        ensure!(kind <= KIND_UA, "holder kind {kind} (0 an address, 1 a UA id)");
        Ok(Self { kind, id: arr32(&b[1..])? })
    }

    fn bytes(&self) -> Vec<u8> {
        [&[self.kind][..], &self.id].concat()
    }

    /// The event / Odoo form: an Algorand address (kind 0) or `0x` ‖ 64 hex (a UA id).
    pub fn display(&self) -> String {
        if self.kind == KIND_ADDRESS { algorand_address(&self.id) } else { hex0x(&self.id) }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaOp {
    pub network: [u8; 32],
    pub contract: [u8; 32],
    pub op: u8,
    pub from: Holder,
    pub to: Holder,
    pub relayer: [u8; 32],
    pub amount: u128,
    pub pay_ref: [u8; 32],
    pub lane: [u8; 32],
    pub nonce: u64,
    pub valid_until: u64,
    pub extra: [u8; 32],
}

impl MetaOp {
    /// `"scaas.metaop.v1"` ‖ the 291-byte ARC-4 tuple, nothing after it; holder kinds 0 / 1 only.
    pub fn decode(b: &[u8]) -> Result<Self> {
        Self::from_arc4(b.strip_prefix(LABEL).ok_or_else(|| anyhow!("payload without the scaas.metaop.v1 label"))?)
    }

    pub fn from_arc4(b: &[u8]) -> Result<Self> {
        ensure!(b.len() == METAOP_LEN, "a MetaOp is {METAOP_LEN} bytes, not {}", b.len());
        let a = |i: usize| arr32(&b[i..i + 32]);
        Ok(Self {
            network: a(0)?,
            contract: a(32)?,
            op: b[64],
            from: Holder::read(&b[65..98])?,
            to: Holder::read(&b[98..131])?,
            relayer: a(131)?,
            amount: u128::from_be_bytes(b[163..179].try_into()?),
            pay_ref: a(179)?,
            lane: a(211)?,
            nonce: be_u64(&b[243..251])?,
            valid_until: be_u64(&b[251..259])?,
            extra: a(259)?,
        })
    }

    pub fn arc4(&self) -> Vec<u8> {
        [&self.network[..], &self.contract, &[self.op], &self.from.bytes(), &self.to.bytes(), &self.relayer, &self.amount.to_be_bytes(),
         &self.pay_ref, &self.lane, &self.nonce.to_be_bytes(), &self.valid_until.to_be_bytes(), &self.extra].concat()
    }

    pub fn encode(&self) -> Vec<u8> {
        [LABEL, &self.arc4()].concat()
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.encode())
    }
}

// ------------------------------------------------------------------ CTR-MTX-27 (spec §2 row 8, §4.8)

/// `keccak256("scaas.relayfee" ‖ GenesisHash ‖ target app address ‖ keccak256(call) ‖ salt)` (common.py `relay_ref`).
pub fn relay_ref(network: &[u8; 32], target: &[u8; 32], call: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    keccak(&[b"scaas.relayfee", network, target, &keccak(&[call]), salt])
}

/// `call = target app id (u64) ‖ u8 n ‖ (u16 len ‖ arg)×n`, arg 0 = the ARC-4 selector.
pub fn router_call(app: u64, args: &[Vec<u8>]) -> Vec<u8> {
    let mut c = [&app.to_be_bytes()[..], &[args.len() as u8]].concat();
    for a in args {
        c.extend_from_slice(&(a.len() as u16).to_be_bytes());
        c.extend_from_slice(a);
    }
    c
}

/// Exactly one call: its target app and arguments (an ARC-4 method call: arg 0 = a 4-byte selector, ≤ 16 args).
pub fn parse_router_call(call: &[u8]) -> Result<(u64, Vec<Vec<u8>>)> {
    ensure!(call.len() >= 9, "op.extra.call is shorter than app id ‖ n");
    let app = be_u64(&call[..8])?;
    let n = call[8] as usize;
    ensure!((1..=16).contains(&n), "op.extra.call has {n} application arguments (an ARC-4 call has 1 to 16)");
    let (mut at, mut args) = (9, Vec::with_capacity(n));
    for _ in 0..n {
        let len = call.get(at..at + 2).map(|x| u16::from_be_bytes([x[0], x[1]]) as usize).ok_or_else(|| anyhow!("op.extra.call truncated"))?;
        let a = call.get(at + 2..at + 2 + len).ok_or_else(|| anyhow!("op.extra.call truncated"))?;
        args.push(a.to_vec());
        at += 2 + len;
    }
    ensure!(at == call.len(), "op.extra.call has {} bytes after its arguments", call.len() - at);
    ensure!(args[0].len() == 4, "op.extra.call argument 0 is not an ARC-4 selector");
    Ok((app, args))
}

// ------------------------------------------------------------------ policy, entries

/// What the node accepts (T17 uniform keys): `params = { account_app, mandate_app, dex_app, relayfee_app }` (app ids,
/// TOML integers; `account_app` required, the others optional: no router = no relay-fee jobs), `params.relay_fee = {
/// min_amount, relay_bound_payee, min_microalgo_value, targets }`, `params.max_pay_meta_bytes`, the chain's `tokens` (app
/// ids).
#[derive(Debug, Clone, Default)]
pub struct RelayFeePolicy {
    pub tokens: Vec<u64>,
    pub account_app: u64,
    pub mandate_app: Option<u64>,
    pub dex_app: Option<u64>,
    pub router: Option<u64>,
    pub params: crate::config::RelayParams,
    /// `min_microalgo_value = { "<token app id>" = <µALGO per base unit> }`: the node's floor price of a fee token.
    pub min_microalgo_value: HashMap<u64, u128>,
    /// `targets = { "<app id>" = ["method(sig)ret", …] }`: third-party router targets the operator vouches for, per method.
    pub targets: BTreeMap<u64, Vec<[u8; 4]>>,
}

fn app_id_str(s: &str) -> Result<u64> {
    crate::addresses::algorand(s).ok().filter(|v| !v.contains(|c: char| !c.is_ascii_digit()))
        .and_then(|v| v.parse().ok()).ok_or_else(|| anyhow!("{s:?} is not an Algorand app id"))
}

impl RelayFeePolicy {
    /// A set but malformed or inconsistent value is a startup error: an app id that is not a positive TOML integer, one
    /// app in two roles, `relay_fee.router` (the router is `relayfee_app`), a price that names no configured token or is
    /// not a non-negative integer, a target that is an app of the deployment, an empty method list, a method that is not
    /// an ARC-4 signature or is `add_key_native`.
    pub fn from_cfg(cfg: &ChainCfg) -> Result<Self> {
        let params = cfg.relay_params()?;
        if params.router.is_some() {
            bail!("algorand: the router is params.relayfee_app (an app id), not params.relay_fee.router");
        }
        let app = |k: &str| -> Result<Option<u64>> {
            match cfg.params.get(k) {
                None => Ok(None),
                Some(v) => v.as_integer().filter(|n| *n > 0).map(|n| Some(n as u64))
                    .ok_or_else(|| anyhow!("params.{k} must be an app id (a positive TOML integer), not {v}")),
            }
        };
        let account_app = app("account_app")?.ok_or_else(|| anyhow!("algorand needs params.account_app (the deployment's account app id)"))?;
        let (mandate_app, dex_app, router) = (app("mandate_app")?, app("dex_app")?, app("relayfee_app")?);
        let tokens = cfg.tokens.iter().map(|t| app_id_str(&t.address).context("tokens: a token is its app id")).collect::<Result<Vec<u64>>>()?;
        let mut all: Vec<u64> = tokens.iter().copied().chain([account_app]).chain(mandate_app).chain(dex_app).chain(router).collect();
        all.sort_unstable();
        if all.windows(2).any(|w| w[0] == w[1]) {
            bail!("algorand: an app id appears twice among tokens, account_app, mandate_app, dex_app and relayfee_app");
        }
        let t = cfg.params.get("relay_fee").and_then(|v| v.as_table());
        let mut min_microalgo_value = HashMap::new();
        if let Some(v) = t.and_then(|t| t.get("min_microalgo_value")) {
            let table = v.as_table().ok_or_else(|| anyhow!("params.relay_fee.min_microalgo_value must be a table of token app id = µALGO"))?;
            for (k, n) in table {
                let id = app_id_str(k).ok().filter(|id| tokens.contains(id))
                    .ok_or_else(|| anyhow!("params.relay_fee.min_microalgo_value.{k}: not a configured token"))?;
                let price = match n {
                    toml::Value::Integer(i) => u128::try_from(*i).ok(),
                    toml::Value::String(s) if !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) => s.parse().ok(),
                    _ => None,
                };
                let price = price.ok_or_else(|| anyhow!("params.relay_fee.min_microalgo_value.{k} must be a non-negative integer, not {n}"))?;
                min_microalgo_value.insert(id, price);
            }
        }
        let mut targets = BTreeMap::new();
        if let Some(v) = t.and_then(|t| t.get("targets")) {
            let table = v.as_table().ok_or_else(|| anyhow!("params.relay_fee.targets must be a table of app id = [method signatures]"))?;
            for (k, ms) in table {
                let id = app_id_str(k).context("params.relay_fee.targets")?;
                if all.contains(&id) {
                    bail!("params.relay_fee.targets: {id} is an app of the deployment (a token, account, mandate, DEX or the router)");
                }
                let list = ms.as_array().filter(|l| !l.is_empty())
                    .ok_or_else(|| anyhow!("params.relay_fee.targets.{k} must be a non-empty list of ARC-4 method signatures"))?;
                let sels = list.iter().map(|m| match m.as_str() {
                    Some(s) if s != ADD_KEY_NATIVE && s.find('(').is_some_and(|i| i > 0) && s.contains(')') => Ok(selector(s)),
                    _ => Err(anyhow!("params.relay_fee.targets.{k}: {m} is not a relayable ARC-4 method signature")),
                }).collect::<Result<Vec<_>>>()?;
                targets.insert(id, sels);
            }
        }
        Ok(Self { tokens, account_app, mandate_app, dex_app, router, params, min_microalgo_value, targets })
    }

    /// Every app address of the deployment: never a payee (rules 12 / 15: the DEX holds a permanent box per token, the
    /// mandate only through an open, the router and the tokens strand what they get).
    fn app_addresses(&self) -> Vec<[u8; 32]> {
        self.tokens.iter().copied().chain([self.account_app]).chain(self.mandate_app).chain(self.dex_app).chain(self.router)
            .map(app_address).collect()
    }

    fn never_paid(&self, exec: Option<&Executor>, h: &Holder) -> bool {
        h.kind == KIND_ADDRESS && (self.app_addresses().contains(&h.id) || exec.is_some_and(|e| e.address == h.id))
    }
}

/// The entry a job runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Pay,
    PayMeta { salt: [u8; 32], meta: Vec<u8> },
    /// The router group's target: app id and application arguments (arg 0 = the selector), bound by `ref`.
    Fee { target_app: u64, args: Vec<Vec<u8>> },
}

fn hex_field(v: &Value, what: &str) -> Result<Vec<u8>> {
    let s = v.as_str().ok_or_else(|| anyhow!("op.{what} missing"))?;
    Ok(alloy::hex::decode(s.trim().trim_start_matches("0x"))?)
}

fn bound(op: &MetaOp, r: &[u8; 32], o: &Value) -> Result<()> {
    if op.op != OP_PAY || op.pay_ref != *r || op.lane != pay_lane(r) || op.nonce != 0 {
        bail!("the payment is not bound to this call (op 0, pay_ref = ref, lane = payLane(ref), nonce 0, salt = its extra)");
    }
    if !o["ref"].is_null() && hex_field(&o["ref"], "ref")? != r {
        bail!("op.ref != relay_ref(call, salt)");
    }
    Ok(())
}

/// The entry of a job, checked before any RPC (fail closed). `op.kind` (`adapter::op_kind`): none = the plain pay;
/// `pay_meta`: the commitment and `min(MAX_PAY_META_BYTES, max_pay_meta_bytes)`; `relay_fee`: the router configured and
/// its executor derived (`start_check`), the payment bound to exactly this call with the router as relayer, rule 13
/// (no app 0, not the router, no `add_key_native`), the target and its method allowed. Never pays an app of the
/// deployment or the executor (only the router itself, as the open-mode marker of a relay-fee payment).
pub fn entry(policy: &RelayFeePolicy, exec: Option<&Executor>, op: &MetaOp, o: &Value) -> Result<Entry> {
    let kind = crate::adapter::op_kind(o, &crate::adapter::PAY_KINDS)?;
    let open = policy.router.is_some_and(|r| op.to == Holder::addr(app_address(r)));
    if policy.never_paid(exec, &op.to) && !(kind == Some("relay_fee") && open) {
        bail!("never pay {} (an app of the deployment or the executor): the funds would be stranded", op.to.display());
    }
    match kind {
        Some("pay_meta") => {
            let salt: [u8; 32] = hex_field(&o["salt"], "salt")?.try_into().map_err(|_| anyhow!("op.salt is 32 bytes"))?;
            let meta = hex_field(&o["meta"], "meta")?;
            let cap = MAX_PAY_META_BYTES.min(policy.params.max_pay_meta_bytes);
            if meta.len() > cap {
                bail!("meta is {} B, above the pay-meta cap {cap} (MAX_PAY_META_BYTES {MAX_PAY_META_BYTES}, max_pay_meta_bytes {})",
                      meta.len(), policy.params.max_pay_meta_bytes);
            }
            let id = meta_pay_id(&salt, &meta);
            if op.pay_ref != id || op.lane != pay_lane(&id) || op.nonce != 0 {
                bail!("pay-meta: pay_ref / lane / nonce are not metaPayId(salt, meta) / payLane / 0");
            }
            Ok(Entry::PayMeta { salt, meta })
        }
        Some("relay_fee") => fee_entry(policy, exec, op, o),
        _ => Ok(Entry::Pay),
    }
}

const EXTRA_KEYS: [&str; 5] = ["call", "accounts", "apps", "boxes", "carries"];

fn fee_entry(policy: &RelayFeePolicy, exec: Option<&Executor>, op: &MetaOp, o: &Value) -> Result<Entry> {
    let router = policy.router.ok_or_else(|| anyhow!("relay-fee jobs need params.relayfee_app"))?;
    let exec = exec.ok_or_else(|| anyhow!("the router's executor is not derived yet (start_check)"))?;
    let extra = o["extra"].as_object().ok_or_else(|| anyhow!("op.extra must be an object with call"))?;
    if let Some(k) = extra.keys().find(|k| !EXTRA_KEYS.contains(&k.as_str())) {
        bail!("op.extra.{k} is not a relay-fee key ({}): the target call is always NoOp", EXTRA_KEYS.join(", "));
    }
    if op.relayer != app_address(router) {
        bail!("the payment's relayer is not the router {router}'s address");
    }
    let call = hex_field(&o["extra"]["call"], "extra.call")?;
    let (target, args) = parse_router_call(&call)?;
    bound(op, &relay_ref(&op.network, &app_address(target), &call, &op.extra), o)?;
    if target == 0 {
        bail!("relay-fee target app 0 (an app create) is refused (rule 13)");
    }
    if target == router {
        bail!("the relay-fee target is the router");
    }
    if args[0] == selector(ADD_KEY_NATIVE) {
        bail!("add_key_native is never relayed (no key is ever registered for the executor)");
    }
    match scaas_method(policy, target, &args[0]) {
        Some((_, Some(m))) if m.n + 1 != args.len() => bail!("{} takes {} arguments, the call has {}", m.name, m.n, args.len() - 1),
        Some((_, Some(_))) => {}
        Some((_, None)) => bail!("app {target} / {} is not an allowed router target: not a relayable entry of that app", hex0x(&args[0])),
        None => match policy.targets.get(&target) {
            Some(ms) if ms.iter().any(|s| s[..] == args[0][..]) => {}
            Some(_) => bail!("{} is not a listed method of router target {target} (params.relay_fee.targets)", hex0x(&args[0])),
            None => bail!("app {target} is not an allowed router target (a token's, the account app's, the mandate's or the DEX's \
                           relayable entry, or params.relay_fee.targets)"),
        },
    }
    if op.to == Holder::addr(exec.address) {
        bail!("the executor is never paid");
    }
    Ok(Entry::Fee { target_app: target, args })
}

/// The SCaaS apps a router job may target and their relayable entries (`n` ABI arguments; the signed op at `op`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum App {
    Token,
    Account,
    Mandate,
    Dex,
}

#[derive(Debug, Clone, Copy)]
pub struct Method {
    pub app: App,
    pub name: &'static str,
    params: &'static str,
    pub n: usize,
}

const METHODS: &[Method] = &[
    Method { app: App::Token, name: "mtx_pay", params: "OP,byte[],address", n: 3 },
    Method { app: App::Token, name: "mtx_pay_meta", params: "OP,byte[],byte[32],byte[]", n: 4 },
    Method { app: App::Token, name: "mtx_transfer", params: "OP,byte[]", n: 2 },
    Method { app: App::Token, name: "mtx_execute_transfer", params: "OP,byte[]", n: 2 },
    Method { app: App::Token, name: "mtx_cancel", params: "OP,byte[],byte[32],uint64", n: 4 },
    Method { app: App::Token, name: "mtx_invalidate_nonces", params: "OP,byte[],byte[32],uint64", n: 4 },
    Method { app: App::Account, name: "mtx_add_key", params: "OP,byte[],(uint16,byte[]),byte[]", n: 4 },
    Method { app: App::Account, name: "mtx_remove_key", params: "OP,byte[],(uint16,byte[])", n: 3 },
    Method { app: App::Account, name: "mtx_add_origin", params: "OP,byte[],byte[]", n: 3 },
    Method { app: App::Account, name: "mtx_remove_origin", params: "OP,byte[],byte[]", n: 3 },
    Method { app: App::Account, name: "mtx_set_guardian", params: "OP,byte[],(uint8,byte[32])", n: 3 },
    Method { app: App::Account, name: "mtx_set_policy", params: "OP,byte[],uint8", n: 3 },
    Method { app: App::Account, name: "mtx_start_recovery", params: "OP,byte[],(uint16,byte[]),byte[]", n: 4 },
    Method { app: App::Account, name: "mtx_finish_recovery", params: "OP,byte[]", n: 2 },
    Method { app: App::Account, name: "mtx_cancel_recovery", params: "OP,byte[]", n: 2 },
    Method { app: App::Mandate, name: "mtx_mandate_open", params: "uint64,OP,byte[],TERMS,uint64", n: 5 },
    Method { app: App::Mandate, name: "mtx_mandate_pay", params: "uint64,OP,byte[]", n: 3 },
    Method { app: App::Mandate, name: "mtx_revoke", params: "uint64,OP,byte[]", n: 3 },
    Method { app: App::Dex, name: "settle", params: "ORDER,OP,byte[],ORDER,OP,byte[],uint64[4]", n: 7 },
];

fn sig_of(m: &Method) -> String {
    let p = m.params.replace("OP", METAOP_ABI).replace("TERMS", TERMS_ABI).replace("ORDER", ORDER_ABI);
    format!("{}({p})void", m.name)
}

fn method_sels() -> &'static Vec<([u8; 4], Method)> {
    static S: OnceLock<Vec<([u8; 4], Method)>> = OnceLock::new();
    S.get_or_init(|| METHODS.iter().map(|m| (selector(&sig_of(m)), *m)).collect())
}

/// The SCaaS app kind of `target` (configured), and its relayable method with selector `sel` if it has one.
fn scaas_method(policy: &RelayFeePolicy, target: u64, sel: &[u8]) -> Option<(App, Option<Method>)> {
    let app = if policy.tokens.contains(&target) {
        App::Token
    } else if target == policy.account_app {
        App::Account
    } else if policy.mandate_app == Some(target) {
        App::Mandate
    } else if policy.dex_app == Some(target) {
        App::Dex
    } else {
        return None;
    };
    Some((app, method_sels().iter().find(|(s, m)| m.app == app && s[..] == *sel).map(|(_, m)| *m)))
}

/// A relay-fee job's resource references for the target (`op.extra.accounts` addresses, `apps` app ids, `boxes` = [{app
/// (0 = the target), name hex}]) and its carried DEX auths (`op.extra.carries`, hex).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Refs {
    pub accounts: Vec<[u8; 32]>,
    pub apps: Vec<u64>,
    pub boxes: Vec<(u64, Vec<u8>)>,
}

fn json_u64(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str().and_then(|s| app_id_str(s).ok()))
}

pub fn job_refs(o: &Value) -> Result<(Refs, Vec<Vec<u8>>)> {
    let e = &o["extra"];
    let list = |k: &str| -> Result<Vec<Value>> {
        match &e[k] {
            Value::Null => Ok(vec![]),
            Value::Array(a) => Ok(a.clone()),
            v => bail!("op.extra.{k} must be a list, not {v}"),
        }
    };
    let accounts = list("accounts")?.iter().map(|a| crate::addresses::algorand_key(a.as_str().unwrap_or_default()).context("op.extra.accounts"))
        .collect::<Result<Vec<_>>>()?;
    let apps = list("apps")?.iter().map(|a| json_u64(a).ok_or_else(|| anyhow!("op.extra.apps: {a} is not an app id"))).collect::<Result<Vec<_>>>()?;
    let boxes = list("boxes")?.iter().map(|b| {
        let app = json_u64(&b["app"]).or_else(|| (b["app"] == json!(0)).then_some(0)).ok_or_else(|| anyhow!("op.extra.boxes: {b} has no app"))?;
        let name = hex_field(&b["name"], "extra.boxes.name")?;
        ensure!(name.len() <= 64, "op.extra.boxes: a box name is at most 64 bytes");
        Ok((app, name))
    }).collect::<Result<Vec<_>>>()?;
    let carries = list("carries")?.iter().map(|c| hex_field(c, "extra.carries")).collect::<Result<Vec<_>>>()?;
    ensure!(accounts.len() <= 4 && accounts.len() + apps.len() + boxes.len() <= 8,
            "op.extra: at most 4 accounts and 8 references in all on the target transaction");
    Ok((Refs { accounts, apps, boxes }, carries))
}

/// What the target of a router job signs and moves, read off its arguments.
#[derive(Debug, Clone)]
pub struct TargetInfo {
    pub app: Option<App>,
    pub method: &'static str,
    /// The signed ops (a settle has two legs) and their auths.
    pub ops: Vec<(MetaOp, Vec<u8>)>,
    /// The holders whose account records the target opens when absent (its signers through the account app).
    pub signers: Vec<Holder>,
    /// A settle's MBR parts, summed (they are signed arguments).
    pub dex_mbr: u64,
}

fn margin(vu: u64, now: u64, what: &str) -> Result<()> {
    if vu <= now.saturating_add(RELAY_EXPIRY_MARGIN_S) {
        bail!("{what} expires within {RELAY_EXPIRY_MARGIN_S} s: it could expire before a round takes the group");
    }
    Ok(())
}

/// Note 9, lessons 2 / 7 (static, before any simulate): a SCaaS target's signed op is for this network and app, relayer
/// zero (the executor is its sender: rule 7 refuses any other relayer; a mandate funding op names the mandate), valid
/// ≥ 120 s; a value op never pays an app of the deployment or the executor; a mandate's terms expire ≥ 120 s out; a
/// settle's orders are open or bound to this lane (the router's sender is the submitter), on configured tokens, valid ≥
/// 120 s, and its empty auths are exactly the job's carries. A listed third-party target is the operator's.
#[allow(clippy::too_many_arguments)]
pub fn target_check(policy: &RelayFeePolicy, exec: &Executor, pay: &MetaOp, target: u64, args: &[Vec<u8>], lane: &[u8; 32], carries: usize,
                    now: u64) -> Result<TargetInfo> {
    let sel = args.first().ok_or_else(|| anyhow!("a target call without a selector"))?;
    let Some((app, m)) = scaas_method(policy, target, sel) else {
        ensure!(carries == 0, "carries are for a DEX settle only");
        return Ok(TargetInfo { app: None, method: "listed", ops: vec![], signers: vec![], dex_mbr: 0 });
    };
    let m = m.ok_or_else(|| anyhow!("{target} is not called with one of its relayable entries"))?;
    ensure!(m.n + 1 == args.len(), "{target} is not called with one of its relayable entries");
    ensure!(app == App::Dex || carries == 0, "carries are for a DEX settle only");
    let signed = |at: usize, contract: [u8; 32], relayer: [u8; 32]| -> Result<(MetaOp, Vec<u8>)> {
        let op = MetaOp::from_arc4(&args[at]).with_context(|| format!("{} op", m.name))?;
        ensure!(op.network == pay.network, "{}: the target op is for another network", m.name);
        ensure!(op.contract == contract, "{}: the target op's contract is not app {target}'s", m.name);
        ensure!(op.relayer == relayer, "{}: the target op's relayer must be {} (the executor sends it)", m.name,
                if relayer == [0; 32] { "zero".to_string() } else { algorand_address(&relayer) });
        margin(op.valid_until, now, &format!("{}'s op", m.name))?;
        Ok((op, un_abi_bytes(&args[at + 1])?.to_vec()))
    };
    let value = |op: &MetaOp| -> Result<()> {
        ensure!(!policy.never_paid(Some(exec), &op.to), "{}: never pay {} (an app of the deployment or the executor)", m.name, op.to.display());
        Ok(())
    };
    let me = app_address(target);
    let mut info = TargetInfo { app: Some(app), method: m.name, ops: vec![], signers: vec![], dex_mbr: 0 };
    match app {
        App::Token | App::Account => {
            let (op, auth) = signed(1, me, [0; 32])?;
            if matches!(m.name, "mtx_pay" | "mtx_pay_meta" | "mtx_transfer" | "mtx_execute_transfer") {
                value(&op)?;
            }
            info.signers.push(op.from);
            info.ops.push((op, auth));
        }
        App::Mandate => {
            let token = be_u64(&args[1])?;
            ensure!(policy.tokens.contains(&token), "{}: token {token} is not a configured token", m.name);
            let mandate = app_address(target);
            if m.name == "mtx_mandate_open" {
                let (op, auth) = signed(2, app_address(token), mandate)?;
                ensure!(op.to == Holder::addr(mandate), "mtx_mandate_open: the funding pays the mandate app");
                let terms = &args[4];
                ensure!(terms.len() == 130, "mtx_mandate_open: terms are 130 bytes");
                margin(be_u64(&terms[106..114])?, now, "the mandate")?;
                be_u64(&args[5])?;
                info.signers.push(op.from);
                info.ops.push((op, auth));
            } else {
                let (op, auth) = signed(2, mandate, [0; 32])?;
                if m.name == "mtx_revoke" {
                    info.signers.push(op.from);
                }
                info.ops.push((op, auth));
            }
        }
        App::Dex => {
            let dex = app_address(target);
            let mut empty = 0;
            for (o, at) in [(1usize, 2usize), (4, 5)] {
                let order = &args[o];
                ensure!(order.len() == 88, "settle: an order is 88 bytes");
                let (sell, buy) = (be_u64(&order[..8])?, be_u64(&order[8..16])?);
                ensure!(policy.tokens.contains(&sell) && policy.tokens.contains(&buy), "settle: order tokens {sell} / {buy} are not both configured");
                let relayer = arr32(&order[48..80])?;
                ensure!(relayer == [0; 32] || relayer == *lane, "settle: an order is bound to another relayer");
                margin(be_u64(&order[80..88])?, now, "a settle's order")?;
                let (op, auth) = signed(at, app_address(sell), dex)?;
                ensure!(op.to == Holder::addr(dex), "settle: a leg pays the DEX");
                if auth.is_empty() {
                    empty += 1;
                }
                info.signers.push(op.from);
                info.ops.push((op, auth));
            }
            ensure!(empty == carries, "settle: {empty} carried auth(s) in the call, {carries} in op.extra.carries");
            let mbr = &args[7];
            ensure!(mbr.len() == 32, "settle: mbr is uint64[4]");
            info.dex_mbr = mbr.chunks(8).try_fold(0u64, |s, c| be_u64(c).ok().and_then(|x| s.checked_add(x)))
                .ok_or_else(|| anyhow!("settle: mbr parts overflow"))?;
        }
    }
    Ok(info)
}

/// Passkey origins (sha256) of an auth, as the account app reads them (`client_origin` = NEAR `origin_of`, ≤ 128 B):
/// a passkey's, or an msig's passkey members'. Other tags have none.
pub fn auth_origins(auth: &[u8], digest: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
    let passkey = |a: &[u8]| -> Result<[u8; 32]> {
        ensure!(a.len() >= 131, "passkey auth length");
        let n = u16::from_be_bytes([a[129], a[130]]) as usize;
        let cd = a.get(131 + n..).ok_or_else(|| anyhow!("passkey authenticatorData truncated"))?;
        let o = super::near::origin_of(cd, digest).filter(|o| o.len() <= MAX_ORIGIN_LEN)
            .ok_or_else(|| anyhow!("passkey clientDataJSON is not in the account app's grammar for this op"))?;
        Ok(sha256(o))
    };
    Ok(match auth.first() {
        Some(3) => vec![passkey(auth)?],
        Some(4) if auth.len() >= 3 => {
            let kd = u16::from_be_bytes([auth[1], auth[2]]) as usize;
            let mut at = 3 + kd;
            let mut out = Vec::new();
            ensure!(at <= auth.len(), "msig key data truncated");
            while at < auth.len() {
                let len = auth.get(at + 1..at + 3).map(|x| u16::from_be_bytes([x[0], x[1]]) as usize).ok_or_else(|| anyhow!("msig member truncated"))?;
                let a = auth.get(at + 3..at + 3 + len).ok_or_else(|| anyhow!("msig member truncated"))?;
                if a.first() == Some(&3) && a.len() != 64 {
                    let o = passkey(a)?;
                    if !out.contains(&o) {
                        out.push(o);
                    }
                }
                at += 3 + len;
            }
            out
        }
        _ => vec![],
    })
}

/// The record growth (bytes) of an own key op (`mtx_add_key` … `mtx_cancel_recovery` except the recovery pair) on a
/// record of `len` bytes holding the origin hashes `origins` (`old` = its stored length, `None` = not stored yet).
pub fn key_op_delta(args: &[Vec<u8>], old: Option<usize>, len: usize, origins: &[[u8; 32]]) -> Result<i64> {
    let m = method_sels().iter().find(|(s, m)| m.app == App::Account && args.first().is_some_and(|a| s[..] == a[..])).map(|(_, m)| m.name)
        .ok_or_else(|| anyhow!("not an account key op"))?;
    let origin = |b: &[u8]| -> Result<i64> {
        let o = un_abi_bytes(b)?;
        Ok(if o.is_empty() || origins.contains(&sha256(o)) { 0 } else { 32 })
    };
    let grow: i64 = match m {
        "mtx_add_key" => 32 + origin(args.get(4).ok_or_else(|| anyhow!("mtx_add_key origin"))?)?,
        "mtx_add_origin" => origin(args.get(3).ok_or_else(|| anyhow!("mtx_add_origin origin"))?)?,
        "mtx_remove_key" | "mtx_remove_origin" => -32,
        "mtx_set_guardian" | "mtx_set_policy" | "mtx_cancel_recovery" => 0,
        other => bail!("{other} is not an own key op"),
    };
    let new = (len as i64).saturating_add(grow).max(REC_HEADER as i64);
    Ok(box_delta(old, new as usize))
}

/// The MBR change of writing a record box of `new` bytes over one of `old` (`None` = absent): name 34 B.
fn box_delta(old: Option<usize>, new: usize) -> i64 {
    match old {
        None => (BOX_FLAT + BOX_BYTE * (34 + new as u64)) as i64,
        Some(o) => BOX_BYTE as i64 * (new as i64 - o as i64),
    }
}

/// Review Focus 1: the LastValid of a group first valid at `first`: at most MaxTxnLife rounds, and no round whose
/// estimated time (`ts_last` at `last_round`, then `secs` per `rounds` as measured from algod's block timestamps) is
/// past `valid_until` (seconds). No measured time (`secs` 0): no time bound.
pub fn last_valid(first: u64, last_round: u64, ts_last: u64, rounds: u64, secs: u64, valid_until: u64) -> Result<u64> {
    ensure!(valid_until >= ts_last, "valid_until {valid_until} is before the last block's time {ts_last}");
    let mut lv = first.saturating_add(MAX_TXN_LIFE);
    if secs > 0 && rounds > 0 {
        let ahead = u128::from(valid_until - ts_last) * u128::from(rounds) / u128::from(secs);
        lv = lv.min(last_round.saturating_add(u64::try_from(ahead).unwrap_or(u64::MAX)));
    }
    ensure!(lv >= first, "the payload expires before round {first}");
    Ok(lv)
}

// ------------------------------------------------------------------ canonical msgpack

/// A msgpack value; `Str` keeps raw bytes (algod encodes logs as strings).
#[derive(Debug, Clone, PartialEq)]
pub enum Mp {
    Nil,
    Bool(bool),
    Int(i128),
    Bin(Vec<u8>),
    Str(Vec<u8>),
    Arr(Vec<Mp>),
    Map(Vec<(Mp, Mp)>),
}

impl Mp {
    pub fn str(s: &str) -> Self {
        Mp::Str(s.as_bytes().to_vec())
    }

    pub fn get(&self, k: &str) -> Option<&Mp> {
        match self {
            Mp::Map(m) => m.iter().find(|(x, _)| matches!(x, Mp::Str(s) if s == k.as_bytes())).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn arr(&self) -> &[Mp] {
        match self {
            Mp::Arr(a) => a,
            _ => &[],
        }
    }

    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Mp::Bin(b) | Mp::Str(b) => Some(b),
            _ => None,
        }
    }

    pub fn u64(&self) -> Option<u64> {
        match self {
            Mp::Int(n) => u64::try_from(*n).ok(),
            _ => None,
        }
    }
}

fn mp_len(out: &mut Vec<u8>, n: usize, fix: u8, fix_max: usize, tags: [u8; 3]) {
    if n <= fix_max {
        out.push(fix | n as u8);
    } else if tags[0] != 0 && n <= 0xff {
        out.extend([tags[0], n as u8]);
    } else if n <= 0xffff {
        out.push(tags[1]);
        out.extend((n as u16).to_be_bytes());
    } else {
        out.push(tags[2]);
        out.extend((n as u32).to_be_bytes());
    }
}

fn mp_write(v: &Mp, out: &mut Vec<u8>) {
    match v {
        Mp::Nil => out.push(0xc0),
        Mp::Bool(b) => out.push(if *b { 0xc3 } else { 0xc2 }),
        Mp::Int(n) => {
            let n = *n;
            if (0..=0x7f).contains(&n) {
                out.push(n as u8);
            } else if (0..=0xff).contains(&n) {
                out.extend([0xcc, n as u8]);
            } else if (0..=0xffff).contains(&n) {
                out.push(0xcd);
                out.extend((n as u16).to_be_bytes());
            } else if (0..=0xffff_ffff).contains(&n) {
                out.push(0xce);
                out.extend((n as u32).to_be_bytes());
            } else if n >= 0 {
                out.push(0xcf);
                out.extend((n as u64).to_be_bytes());
            } else if n >= -32 {
                out.push(n as i8 as u8);
            } else if n >= i8::MIN as i128 {
                out.extend([0xd0, n as i8 as u8]);
            } else if n >= i16::MIN as i128 {
                out.push(0xd1);
                out.extend((n as i16).to_be_bytes());
            } else if n >= i32::MIN as i128 {
                out.push(0xd2);
                out.extend((n as i32).to_be_bytes());
            } else {
                out.push(0xd3);
                out.extend((n as i64).to_be_bytes());
            }
        }
        Mp::Bin(b) => {
            let n = b.len();
            if n <= 0xff {
                out.extend([0xc4, n as u8]);
            } else if n <= 0xffff {
                out.push(0xc5);
                out.extend((n as u16).to_be_bytes());
            } else {
                out.push(0xc6);
                out.extend((n as u32).to_be_bytes());
            }
            out.extend_from_slice(b);
        }
        Mp::Str(s) => {
            mp_len(out, s.len(), 0xa0, 31, [0xd9, 0xda, 0xdb]);
            out.extend_from_slice(s);
        }
        Mp::Arr(a) => {
            mp_len(out, a.len(), 0x90, 15, [0, 0xdc, 0xdd]);
            a.iter().for_each(|x| mp_write(x, out));
        }
        Mp::Map(m) => {
            mp_len(out, m.len(), 0x80, 15, [0, 0xde, 0xdf]);
            let mut sorted: Vec<&(Mp, Mp)> = m.iter().collect();
            sorted.sort_by(|a, b| a.0.bytes().cmp(&b.0.bytes()));
            for (k, x) in sorted {
                mp_write(k, out);
                mp_write(x, out);
            }
        }
    }
}

/// Canonical msgpack (go-algorand / py-algorand-sdk): smallest encodings, map keys sorted bytewise.
pub fn mp_encode(v: &Mp) -> Vec<u8> {
    let mut out = Vec::new();
    mp_write(v, &mut out);
    out
}

struct MpReader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> MpReader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self.b.get(self.at..self.at.checked_add(n).ok_or_else(|| anyhow!("msgpack length overflow"))?).ok_or_else(|| anyhow!("msgpack truncated"))?;
        self.at += n;
        Ok(s)
    }

    fn uint(&mut self, n: usize) -> Result<u64> {
        Ok(self.take(n)?.iter().fold(0u64, |a, &x| a << 8 | x as u64))
    }

    fn read(&mut self, depth: u32) -> Result<Mp> {
        ensure!(depth < 32, "msgpack nested too deep");
        let t = self.take(1)?[0];
        let n = |r: &mut Self, k: usize| r.uint(k).map(|x| x as usize);
        Ok(match t {
            0x00..=0x7f => Mp::Int(t as i128),
            0x80..=0x8f => self.map((t & 0x0f) as usize, depth)?,
            0x90..=0x9f => self.arr((t & 0x0f) as usize, depth)?,
            0xa0..=0xbf => Mp::Str(self.take((t & 0x1f) as usize)?.to_vec()),
            0xc0 => Mp::Nil,
            0xc2 => Mp::Bool(false),
            0xc3 => Mp::Bool(true),
            0xc4..=0xc6 => {
                let len = n(self, 1 << (t - 0xc4))?;
                Mp::Bin(self.take(len)?.to_vec())
            }
            0xcc..=0xcf => Mp::Int(self.uint(1 << (t - 0xcc))? as i128),
            0xd0 => Mp::Int(self.take(1)?[0] as i8 as i128),
            0xd1 => Mp::Int(i16::from_be_bytes(self.take(2)?.try_into()?) as i128),
            0xd2 => Mp::Int(i32::from_be_bytes(self.take(4)?.try_into()?) as i128),
            0xd3 => Mp::Int(i64::from_be_bytes(self.take(8)?.try_into()?) as i128),
            0xd9..=0xdb => {
                let len = n(self, 1 << (t - 0xd9))?;
                Mp::Str(self.take(len)?.to_vec())
            }
            0xdc | 0xdd => {
                let len = n(self, 2 << (t - 0xdc))?;
                self.arr(len, depth)?
            }
            0xde | 0xdf => {
                let len = n(self, 2 << (t - 0xde))?;
                self.map(len, depth)?
            }
            0xe0..=0xff => Mp::Int(t as i8 as i128),
            _ => bail!("msgpack type 0x{t:02x} is not read here"),
        })
    }

    fn arr(&mut self, len: usize, depth: u32) -> Result<Mp> {
        ensure!(len <= self.b.len() - self.at, "msgpack array longer than its bytes");
        (0..len).map(|_| self.read(depth + 1)).collect::<Result<_>>().map(Mp::Arr)
    }

    fn map(&mut self, len: usize, depth: u32) -> Result<Mp> {
        ensure!(len <= self.b.len() - self.at, "msgpack map longer than its bytes");
        (0..len).map(|_| Ok((self.read(depth + 1)?, self.read(depth + 1)?))).collect::<Result<_>>().map(Mp::Map)
    }
}

/// Exactly one msgpack value.
pub fn mp_decode(b: &[u8]) -> Result<Mp> {
    let mut r = MpReader { b, at: 0 };
    let v = r.read(0)?;
    ensure!(r.at == b.len(), "{} bytes after the msgpack value", b.len() - r.at);
    Ok(v)
}

// ------------------------------------------------------------------ transactions and groups

/// One transaction of a job's group: a lane payment (an MBR payment) or an app call, sent by the lane or (the router
/// target) the executor. `boxes` = (foreign-app index, name), index 0 = the called app. Always NoOp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tx {
    Pay { to: [u8; 32], amount: u64 },
    Call { app: u64, args: Vec<Vec<u8>>, accounts: Vec<[u8; 32]>, apps: Vec<u64>, boxes: Vec<(u64, Vec<u8>)>, executor: bool },
}

impl Tx {
    fn call(app: u64, args: Vec<Vec<u8>>) -> Self {
        Tx::Call { app, args, accounts: vec![], apps: vec![], boxes: vec![], executor: false }
    }

    fn refs(&self) -> (usize, usize) {
        match self {
            Tx::Call { accounts, apps, boxes, .. } => (accounts.len(), accounts.len() + apps.len() + boxes.len()),
            Tx::Pay { .. } => (0, 0),
        }
    }
}

/// A job's group: `main` = the lane's call that carries the pooled `fee`; `mbr` = its MBR payments, summed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub txs: Vec<Tx>,
    pub main: usize,
    pub fee: u64,
    pub mbr: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub gen: String,
    pub gh: [u8; 32],
}

fn k(s: &str) -> Mp {
    Mp::str(s)
}

/// The canonical transaction map (zero / empty fields omitted, as go-algorand's `omitempty`).
fn txn_map(tx: &Tx, snd: &[u8; 32], fee: u64, fv: u64, lv: u64, chain: &Chain, grp: Option<&[u8; 32]>) -> Mp {
    let mut m = Vec::new();
    let int = |m: &mut Vec<(Mp, Mp)>, key: &str, n: u64| {
        if n != 0 {
            m.push((k(key), Mp::Int(n as i128)));
        }
    };
    match tx {
        Tx::Pay { to, amount } => {
            int(&mut m, "amt", *amount);
            m.push((k("rcv"), Mp::Bin(to.to_vec())));
            m.push((k("type"), k("pay")));
        }
        Tx::Call { app, args, accounts, apps, boxes, .. } => {
            if !args.is_empty() {
                m.push((k("apaa"), Mp::Arr(args.iter().map(|a| Mp::Bin(a.clone())).collect())));
            }
            if !accounts.is_empty() {
                m.push((k("apat"), Mp::Arr(accounts.iter().map(|a| Mp::Bin(a.to_vec())).collect())));
            }
            if !boxes.is_empty() {
                m.push((k("apbx"), Mp::Arr(boxes.iter().map(|(i, n)| {
                    let mut b = Vec::new();
                    int(&mut b, "i", *i);
                    if !n.is_empty() {
                        b.push((k("n"), Mp::Bin(n.clone())));
                    }
                    Mp::Map(b)
                }).collect())));
            }
            if !apps.is_empty() {
                m.push((k("apfa"), Mp::Arr(apps.iter().map(|a| Mp::Int(*a as i128)).collect())));
            }
            int(&mut m, "apid", *app);
            m.push((k("type"), k("appl")));
        }
    }
    int(&mut m, "fee", fee);
    int(&mut m, "fv", fv);
    if !chain.gen.is_empty() {
        m.push((k("gen"), k(&chain.gen)));
    }
    m.push((k("gh"), Mp::Bin(chain.gh.to_vec())));
    if let Some(g) = grp {
        m.push((k("grp"), Mp::Bin(g.to_vec())));
    }
    int(&mut m, "lv", lv);
    m.push((k("snd"), Mp::Bin(snd.to_vec())));
    Mp::Map(m)
}

/// `sha512_256("TX" ‖ msgpack(txn))`.
fn txid(txn: &Mp) -> [u8; 32] {
    sha512_256(&[b"TX", &mp_encode(txn)])
}

/// `sha512_256("TG" ‖ msgpack({txlist}))`.
pub fn group_id(ids: &[[u8; 32]]) -> [u8; 32] {
    let list = Mp::Map(vec![(k("txlist"), Mp::Arr(ids.iter().map(|i| Mp::Bin(i.to_vec())).collect()))]);
    sha512_256(&[b"TG", &mp_encode(&list)])
}

fn sender(tx: &Tx, lane: &[u8; 32], exec: Option<&Executor>) -> Result<[u8; 32]> {
    match tx {
        Tx::Call { executor: true, .. } => exec.map(|e| e.address).ok_or_else(|| anyhow!("an executor call without the executor")),
        _ => Ok(*lane),
    }
}

fn maps(g: &Group, chain: &Chain, fv: u64, lv: u64, lane: &[u8; 32], exec: Option<&Executor>, grp: Option<&[u8; 32]>) -> Result<Vec<Mp>> {
    g.txs.iter().enumerate().map(|(i, t)| {
        let fee = if i == g.main { g.fee } else { 0 };
        Ok(txn_map(t, &sender(t, lane, exec)?, fee, fv, lv, chain, grp))
    }).collect()
}

/// The txids of the group's transactions before the group id is set (what the group id hashes).
pub fn group_txids(g: &Group, chain: &Chain, fv: u64, lv: u64, lane: &[u8; 32], exec: Option<&Executor>) -> Vec<[u8; 32]> {
    maps(g, chain, fv, lv, lane, exec, None).map(|m| m.iter().map(txid).collect()).unwrap_or_default()
}

/// The grouped maps (group id set) of the group's transactions.
fn grouped(g: &Group, chain: &Chain, fv: u64, lv: u64, lane: &[u8; 32], exec: Option<&Executor>) -> Result<Vec<Mp>> {
    let gid = (g.txs.len() > 1).then(|| group_id(&group_txids(g, chain, fv, lv, lane, exec)));
    maps(g, chain, fv, lv, lane, exec, gid.as_ref())
}

fn signed_map(tx: &Tx, txn: Mp, sig: Option<Vec<u8>>, exec: Option<&Executor>) -> Result<Mp> {
    Ok(match (tx, sig) {
        (Tx::Call { executor: true, .. }, _) => {
            let e = exec.ok_or_else(|| anyhow!("an executor call without the executor"))?;
            Mp::Map(vec![(k("lsig"), Mp::Map(vec![(k("l"), Mp::Bin(e.program.clone()))])), (k("txn"), txn)])
        }
        (_, Some(s)) => Mp::Map(vec![(k("sig"), Mp::Bin(s)), (k("txn"), txn)]),
        (_, None) => Mp::Map(vec![(k("txn"), txn)]),
    })
}

pub type SignFn<'a> = dyn Fn(&[u8]) -> Result<Vec<u8>> + 'a;

/// The group signed: the lane's transactions by `sign("TX" ‖ msgpack)`, the executor's by its program. Returns the
/// concatenated signed transactions (algod's group submission) and their txids.
pub fn sign_group(g: &Group, chain: &Chain, fv: u64, lv: u64, sign: &SignFn, lane: &[u8; 32], exec: Option<&Executor>) -> Result<(Vec<u8>, Vec<[u8; 32]>)> {
    let (mut raw, mut ids) = (Vec::new(), Vec::new());
    for (t, m) in g.txs.iter().zip(grouped(g, chain, fv, lv, lane, exec)?) {
        ids.push(txid(&m));
        let sig = match t {
            Tx::Call { executor: true, .. } => None,
            _ => Some(sign(&[&b"TX"[..], &mp_encode(&m)].concat())?),
        };
        raw.extend(mp_encode(&signed_map(t, m, sig, exec)?));
    }
    Ok((raw, ids))
}

// ------------------------------------------------------------------ simulate

/// Resources a simulate found accessed but not named (accounts, apps, boxes as (app id, name), extra box quota); `other`
/// = assets, holdings or locals (never used by SCaaS apps: such a job is refused).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Unnamed {
    pub accounts: Vec<[u8; 32]>,
    pub apps: Vec<u64>,
    pub boxes: Vec<(u64, Vec<u8>)>,
    pub extra_box_refs: u64,
    pub other: bool,
}

#[derive(Debug, Default)]
pub struct SimOut {
    pub failure: Option<String>,
    /// Inner transactions in the whole group (each needs one min fee of credit).
    pub inner: u64,
    pub unnamed: Unnamed,
    /// Per transaction (an app below AVM 9 shares no resource across the group).
    pub per_txn: Vec<Unnamed>,
    /// Each top-level transaction's logs.
    pub logs: Vec<Vec<Vec<u8>>>,
}

fn unnamed_of(v: &Value) -> Result<Unnamed> {
    if v.is_null() {
        return Ok(Unnamed::default());
    }
    let list = |k: &str| v[k].as_array().cloned().unwrap_or_default();
    Ok(Unnamed {
        accounts: list("accounts").iter().map(|a| crate::addresses::algorand_key(a.as_str().unwrap_or_default())).collect::<Result<_>>()?,
        apps: list("apps").iter().map(|a| a.as_u64().ok_or_else(|| anyhow!("unnamed app {a}"))).collect::<Result<_>>()?,
        boxes: list("boxes").iter().map(|b| Ok((b["app"].as_u64().ok_or_else(|| anyhow!("unnamed box {b}"))?, b64d(b["name"].as_str().unwrap_or_default())?)))
            .collect::<Result<_>>()?,
        extra_box_refs: v["extra-box-refs"].as_u64().unwrap_or(0),
        other: ["assets", "app-locals", "asset-holdings"].iter().any(|k| !list(k).is_empty()),
    })
}

fn count_inner(r: &Value, depth: u32) -> u64 {
    if depth > 8 {
        return 0;
    }
    r["inner-txns"].as_array().map_or(0, |a| a.iter().map(|x| 1 + count_inner(x, depth + 1)).sum())
}

/// algod `simulate`'s JSON answer for one group.
pub fn parse_sim(v: &Value) -> Result<SimOut> {
    let g = &v["txn-groups"][0];
    ensure!(g.is_object(), "simulate: no txn-groups");
    let results = g["txn-results"].as_array().cloned().unwrap_or_default();
    let failure = g["failure-message"].as_str().filter(|s| !s.is_empty()).map(str::to_string);
    let mut out = SimOut { failure, unnamed: unnamed_of(&g["unnamed-resources-accessed"])?, ..Default::default() };
    for r in &results {
        out.inner += count_inner(&r["txn-result"], 0);
        out.per_txn.push(unnamed_of(&r["unnamed-resources-accessed"])?);
        out.logs.push(r["txn-result"]["logs"].as_array().into_iter().flatten().map(|l| b64d(l.as_str().unwrap_or_default())).collect::<Result<_>>()?);
    }
    Ok(out)
}

/// Bare `budget` calls on `token` carrying the unnamed resources (group resource sharing, AVM ≥ 9): at most 4 accounts
/// and 8 references each; a box of another app names that app in the same call.
fn budget_calls(token: u64, u: &Unnamed) -> Result<Vec<Tx>> {
    ensure!(!u.other, "the group touches assets, holdings or local state the node does not reference");
    enum Item {
        Account([u8; 32]),
        App(u64),
        Box(u64, Vec<u8>),
    }
    let items = u.accounts.iter().map(|a| Item::Account(*a)).chain(u.apps.iter().map(|a| Item::App(*a)))
        .chain(u.boxes.iter().map(|(a, n)| Item::Box(*a, n.clone()))).chain((0..u.extra_box_refs).map(|_| Item::Box(token, vec![])));
    let mut out: Vec<Tx> = Vec::new();
    for it in items {
        loop {
            let fits = match (out.last(), &it) {
                (Some(t @ Tx::Call { apps, .. }), Item::Box(a, _)) => t.refs().1 + if *a == token || apps.contains(a) { 1 } else { 2 } <= 8,
                (Some(t), Item::Account(_)) => t.refs().0 < 4 && t.refs().1 < 8,
                (Some(t), _) => t.refs().1 < 8,
                (None, _) => false,
            };
            if !fits {
                out.push(Tx::call(token, vec![]));
                continue;
            }
            let Some(Tx::Call { accounts, apps, boxes, .. }) = out.last_mut() else { unreachable!("a call was just pushed") };
            match &it {
                Item::Account(a) => accounts.push(*a),
                Item::App(a) => apps.push(*a),
                Item::Box(a, n) => {
                    let i = if *a == token {
                        0
                    } else {
                        if !apps.contains(a) {
                            apps.push(*a);
                        }
                        apps.iter().position(|x| x == a).map_or(0, |p| p as u64 + 1)
                    };
                    boxes.push((i, n.clone()));
                }
            }
            break;
        }
    }
    Ok(out)
}

/// Adds a transaction's own unnamed resources (an app below AVM 9) to it, within its limits.
fn add_own(tx: &mut Tx, u: &Unnamed) -> Result<()> {
    if *u == Unnamed::default() {
        return Ok(());
    }
    ensure!(!u.other, "the group touches assets, holdings or local state the node does not reference");
    let Tx::Call { app, accounts, apps, boxes, .. } = tx else { bail!("a payment with unnamed resources") };
    accounts.extend(&u.accounts);
    apps.extend(&u.apps);
    for (a, n) in &u.boxes {
        let i = if a == app {
            0
        } else {
            if !apps.contains(a) {
                apps.push(*a);
            }
            apps.iter().position(|x| x == a).map_or(0, |p| p as u64 + 1)
        };
        boxes.push((i, n.clone()));
    }
    boxes.extend((0..u.extra_box_refs).map(|_| (0, vec![])));
    let (acc, all) = tx.refs();
    ensure!(acc <= 4 && all <= 8, "a pre-AVM-9 app needs more references than one transaction holds");
    Ok(())
}

/// The target call with the job's references (box app ids → foreign-app indexes).
fn target_tx(app: u64, args: Vec<Vec<u8>>, r: &Refs) -> Result<Tx> {
    let mut apps = r.apps.clone();
    let mut boxes = Vec::new();
    for (a, n) in &r.boxes {
        let i = if *a == 0 || *a == app {
            0
        } else {
            if !apps.contains(a) {
                apps.push(*a);
            }
            apps.iter().position(|x| x == a).map_or(0, |p| p as u64 + 1)
        };
        boxes.push((i, n.clone()));
    }
    let t = Tx::Call { app, args, accounts: r.accounts.clone(), apps, boxes, executor: true };
    let (acc, all) = t.refs();
    ensure!(acc <= 4 && all <= 8, "op.extra: the target's references exceed one transaction's");
    Ok(t)
}

// ------------------------------------------------------------------ events (ARC-28)

pub struct Ids {
    pub tokens: Vec<u64>,
    pub router: Option<u64>,
    pub mandate: Option<u64>,
    pub dex: Option<u64>,
}

struct Sels {
    transfer: [u8; 4],
    ua: [u8; 4],
    executed: [u8; 4],
    settled: [u8; 4],
    meta: [u8; 4],
    filled: [u8; 4],
    fee: [u8; 4],
    mandate: [u8; 4],
    matched: [u8; 4],
}

fn sels() -> &'static Sels {
    static S: OnceLock<Sels> = OnceLock::new();
    S.get_or_init(|| Sels {
        transfer: selector(EV_TRANSFER), ua: selector(EV_UA_TRANSFER), executed: selector(EV_EXECUTED), settled: selector(EV_SETTLED),
        meta: selector(EV_META), filled: selector(EV_FILLED), fee: selector(EV_FEE), mandate: selector(EV_MANDATE_PAY), matched: selector(EV_MATCHED),
    })
}

/// An app-call node of a block transaction: its app id, logs and inner transactions.
struct Node<'a> {
    app: u64,
    logs: Vec<&'a [u8]>,
    inner: Vec<Node<'a>>,
}

fn node(stib: &Mp, depth: u32) -> Node<'_> {
    let txn = stib.get("txn");
    let app = if txn.and_then(|t| t.get("type")).and_then(Mp::bytes) == Some(b"appl") {
        txn.and_then(|t| t.get("apid")).and_then(Mp::u64).unwrap_or(0)
    } else {
        0
    };
    let dt = stib.get("dt");
    let logs = dt.and_then(|d| d.get("lg")).map(|l| l.arr().iter().filter_map(Mp::bytes).collect()).unwrap_or_default();
    let inner = if depth < 8 { dt.and_then(|d| d.get("itx")).map(|i| i.arr().iter().map(|x| node(x, depth + 1)).collect()).unwrap_or_default() } else { vec![] };
    Node { app, logs, inner }
}

fn walk<'a, 'b>(n: &'b Node<'a>, out: &mut Vec<&'b Node<'a>>) {
    out.push(n);
    for c in &n.inner {
        walk(c, out);
    }
}

fn ev<'a>(log: &'a [u8], sel: &[u8; 4], len: usize) -> Option<&'a [u8]> {
    log.strip_prefix(&sel[..]).filter(|b| b.len() == len)
}

fn holder_at(b: &[u8]) -> Option<String> {
    Holder::read(b).ok().map(|h| h.display())
}

fn u256_dec(b: &[u8]) -> Option<String> {
    // amounts are uint256 on chain, ≤ 2^128 − 1 by the token's supply cap
    let low: [u8; 16] = b.get(16..32)?.try_into().ok()?;
    b[..16].iter().all(|x| *x == 0).then(|| u128::from_be_bytes(low).to_string())
}

/// The canonical txid of a block transaction (the stored map + the block's genesis hash, and its genesis id when
/// `hgi`), `0x` hex.
fn block_txid(stib: &Mp, block: &Mp) -> Option<String> {
    let Some(Mp::Map(m)) = stib.get("txn") else { return None };
    let mut m = m.clone();
    if !m.iter().any(|(x, _)| x.bytes() == Some(b"gh")) {
        m.push((k("gh"), block.get("gh")?.clone()));
    }
    if matches!(stib.get("hgi"), Some(Mp::Bool(true))) && !m.iter().any(|(x, _)| x.bytes() == Some(b"gen")) {
        m.push((k("gen"), block.get("gen")?.clone()));
    }
    Some(hex0x(&txid(&Mp::Map(m))))
}

/// The events of one block (`block` = algod's `block` map), for `chain_event_ingest`: ARC-28 logs of configured apps
/// only (a block holds only successful groups). Token (in `ids.tokens`): `PaymentSettled`, `PaymentMeta`,
/// `MetaTransactionExecuted`, one `Transfer` per holder move (`UaTransfer`; `arc200_Transfer` unless a side is the token
/// itself — its UA pool — or the zero address, a mint); router: `RelayFeePaid` of a configured token; mandate:
/// `MandatePaymentSettled` of a configured token, as that token's `PaymentSettled` from `0x` ‖ mandate id (keyed (token,
/// id), no `MetaTransactionExecuted`). DEX trades are the tokens' transfers: the transfer in a leg's token call (next to
/// its `OrderFilled`) carries `leg_digest` and, when the configured DEX's `Matched` lists it, `settle_id`; `Matched`
/// alone books nothing. Joined by `indexer::join_pay_events` (ids, never position). `log_index` counts the top-level
/// transaction's logs depth first (an app's own logs, then its inner transactions').
pub fn block_events(ids: &Ids, block: &Mp, block_hash: &str) -> Result<Vec<Value>> {
    let round = block.get("rnd").and_then(Mp::u64).unwrap_or(0);
    let s = sels();
    let mut rows = Vec::new();
    for stib in block.get("txns").map(Mp::arr).unwrap_or_default() {
        let root = node(stib, 0);
        let mut nodes = Vec::new();
        walk(&root, &mut nodes);
        if !nodes.iter().any(|n| ids.tokens.contains(&n.app)) {
            continue;
        }
        let Some(tx_hash) = block_txid(stib, block) else { continue };
        let mut settles: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
        for n in nodes.iter().filter(|n| ids.dex == Some(n.app)) {
            for b in n.logs.iter().filter_map(|l| ev(l, &s.matched, 112)) {
                let sid = arr32(&b[..32]).ok();
                for leg in [&b[48..80], &b[80..112]] {
                    if let (Some(sid), Ok(leg)) = (sid, arr32(leg)) {
                        settles.insert(leg, sid);
                    }
                }
            }
        }
        let mut index = 0u64;
        for n in nodes {
            let first = index;
            index += n.logs.len() as u64;
            let token = ids.tokens.contains(&n.app);
            let (router, mandate) = (ids.router == Some(n.app), ids.mandate == Some(n.app));
            if !(token || router || mandate) {
                continue;
            }
            let me = app_address(n.app);
            let (mut here, mut leg) = (Vec::new(), None);
            for (i, log) in n.logs.iter().enumerate() {
                let row = if token {
                    if let Some(b) = ev(log, &s.settled, 130) {
                        (|| Some(json!({"event": "PaymentSettled", "from": holder_at(&b[..33])?, "to": holder_at(&b[33..66])?,
                                        "amount": u256_dec(&b[66..98])?, "entry_ref": hex0x(&b[98..130])})))()
                    } else if let Some(b) = log.strip_prefix(&s.meta[..]).filter(|b| b.len() >= 36 && b[32..34] == [0, 34]) {
                        let len = u16::from_be_bytes([b[34], b[35]]) as usize;
                        (b.len() == 36 + len).then(|| json!({"event": "PaymentMeta", "entry_ref": hex0x(&b[..32]), "meta": hex0x(&b[36..])}))
                    } else if let Some(b) = ev(log, &s.executed, 137) {
                        (|| Some(json!({"event": "MetaTransactionExecuted", "from": holder_at(&b[..33])?, "relayer": algorand_address(&arr32(&b[33..65]).ok()?),
                                        "lane": hex0x(&b[65..97]), "nonce": be_u64(&b[97..105]).ok()?.to_string(), "digest": hex0x(&b[105..137])})))()
                    } else if let Some(b) = ev(log, &s.ua, 98) {
                        (|| Some(json!({"event": "Transfer", "from": holder_at(&b[..33])?, "to": holder_at(&b[33..66])?, "amount": u256_dec(&b[66..98])?})))()
                    } else if let Some(b) = ev(log, &s.transfer, 96) {
                        let (f, t) = (arr32(&b[..32]).ok(), arr32(&b[32..64]).ok());
                        match (f, t) {
                            (Some(f), Some(t)) if f != me && t != me && f != [0; 32] && t != [0; 32] => u256_dec(&b[64..96])
                                .map(|a| json!({"event": "Transfer", "from": algorand_address(&f), "to": algorand_address(&t), "amount": a})),
                            _ => None,
                        }
                    } else if let Some(b) = ev(log, &s.filled, 169) {
                        leg = arr32(&b[137..169]).ok();
                        None
                    } else {
                        None
                    }
                } else if router {
                    ev(log, &s.fee, 146).and_then(|b| {
                        let t = be_u64(&b[40..48]).ok().filter(|t| ids.tokens.contains(t))?;
                        Some(json!({"event": "RelayFeePaid", "token": t.to_string(), "entry_ref": hex0x(&b[..32]),
                            "target": be_u64(&b[32..40]).ok()?.to_string(), "from": holder_at(&b[48..81])?, "to": holder_at(&b[81..114])?,
                            "amount": u256_dec(&b[114..146])?}))
                    })
                } else {
                    ev(log, &s.mandate, 138).and_then(|b| {
                        let t = be_u64(&b[..8]).ok().filter(|t| ids.tokens.contains(t))?;
                        Some(json!({"event": "PaymentSettled", "token": t.to_string(), "from": holder_at(&b[8..41])?,
                            "to": holder_at(&b[41..74])?, "amount": u256_dec(&b[74..106])?, "entry_ref": hex0x(&b[106..138])}))
                    })
                };
                if let Some(mut row) = row {
                    let contract = match row.get("token").and_then(Value::as_str) {
                        Some(t) if mandate => t.to_string(),
                        _ => n.app.to_string(),
                    };
                    if mandate {
                        row.as_object_mut().map(|o| o.remove("token"));
                    }
                    row["contract"] = json!(contract);
                    row["block_number"] = json!(round);
                    row["block_hash"] = json!(block_hash);
                    row["tx_hash"] = json!(tx_hash);
                    row["log_index"] = json!(first + i as u64);
                    here.push(row);
                }
            }
            if let Some(d) = leg {
                for r in here.iter_mut().filter(|r| r["event"] == "Transfer") {
                    r["leg_digest"] = json!(hex0x(&d));
                    if let Some(sid) = settles.get(&d) {
                        r["settle_id"] = json!(hex0x(sid));
                    }
                }
            }
            rows.extend(here);
        }
    }
    Ok(crate::indexer::join_pay_events(rows))
}

// ------------------------------------------------------------------ adapter

/// An algod REST error: HTTP status and its `message`.
#[derive(Debug)]
pub struct AlgodError {
    pub status: u16,
    pub message: String,
}

impl std::fmt::Display for AlgodError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "algod {}: {}", self.status, self.message)
    }
}

impl std::error::Error for AlgodError {}

fn status_of(e: &anyhow::Error) -> Option<u16> {
    e.downcast_ref::<AlgodError>().map(|a| a.status)
}

fn transport(e: anyhow::Error) -> SimError {
    SimError::Transport(format!("{e:#}"))
}

/// A failed simulate: the group's own failure kills the job, except a lane short of ALGO (`overspend`: the lane's
/// balance, not the job — lesson 14, as NEAR's view gas cap: retried).
fn sim_failed(m: &str) -> SimError {
    if m.contains("overspend") {
        SimError::Transport(format!("simulate: the lane cannot pay: {m}"))
    } else {
        SimError::Revert(format!("simulate: {m}"))
    }
}

struct Params {
    min_fee: u64,
    fpb: u64,
    last_round: u64,
    chain: Chain,
}

pub struct AlgorandAdapter {
    key: String,
    network: [u8; 32],
    rpc: Vec<String>,
    token: Option<String>,
    http: reqwest::Client,
    quorum: usize,
    lanes: Vec<Lane>,
    pks: Vec<[u8; 32]>,
    signers: Vec<LocalSigner>,
    policy: RelayFeePolicy,
    /// Derived at `start_check` from the router's salt global.
    exec: Mutex<Option<Executor>>,
    /// tx id ⇒ what the lane paid (fee + MBR payments), for `tx_fee`.
    spent: Mutex<HashMap<String, u128>>,
}

struct Work {
    op: MetaOp,
    token: u64,
    auth: Vec<u8>,
    entry: Entry,
    refs: Refs,
    carries: Vec<Vec<u8>>,
}

impl AlgorandAdapter {
    /// `network` = the genesis hash (base64, algod's `genesis-hash`); `params.algod_token_env` (optional) = the env var
    /// holding the `X-Algo-API-Token`.
    pub fn new(cfg: &ChainCfg, signers: &[LocalSigner]) -> Result<Self> {
        if cfg.rpc_urls.is_empty() || signers.is_empty() {
            bail!("chain {}: needs rpc_urls and at least one lane", cfg.chain_key());
        }
        let net = cfg.network.as_deref().ok_or_else(|| anyhow!("algorand: network must be the genesis hash (base64)"))?;
        let network = arr32(&b64d(net).context("algorand: network must be the genesis hash (base64 of 32 bytes)")?)?;
        let token = match cfg.params.get("algod_token_env") {
            None => None,
            Some(v) => {
                let name = v.as_str().ok_or_else(|| anyhow!("params.algod_token_env must be an env var name"))?;
                Some(std::env::var(name).with_context(|| format!("params.algod_token_env: {name} is not set"))?)
            }
        };
        let (mut lanes, mut pks, mut own) = (Vec::new(), Vec::new(), Vec::new());
        for (s, &i) in signers.iter().zip(&cfg.lanes) {
            let LocalSigner::Ed(k) = s else { bail!("algorand lanes are ed25519") };
            let pk = k.verifying_key().to_bytes();
            lanes.push(Lane { index: i, address: algorand_address(&pk) });
            pks.push(pk);
            own.push(LocalSigner::Ed(k.clone()));
        }
        Ok(Self {
            key: cfg.chain_key(),
            network,
            rpc: cfg.rpc_urls.iter().map(|u| u.trim_end_matches('/').to_string()).collect(),
            token,
            http: reqwest::Client::builder().timeout(Duration::from_secs(20)).build()?,
            quorum: cfg.finality.quorum.max(1),
            lanes,
            pks,
            signers: own,
            policy: RelayFeePolicy::from_cfg(cfg)?,
            exec: Mutex::new(None),
            spent: Mutex::new(HashMap::new()),
        })
    }

    fn req(&self, r: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(t) => r.header("X-Algo-API-Token", t),
            None => r,
        }
    }

    async fn answer(r: reqwest::Response) -> Result<Vec<u8>> {
        let status = r.status().as_u16();
        let body = r.bytes().await?.to_vec();
        if !(200..300).contains(&status) {
            let message = serde_json::from_slice::<Value>(&body).ok().and_then(|v| v["message"].as_str().map(str::to_string))
                .unwrap_or_else(|| String::from_utf8_lossy(&body).chars().take(300).collect());
            return Err(AlgodError { status, message }.into());
        }
        Ok(body)
    }

    async fn get_raw_at(&self, url: &str, path: &str, query: &[(&str, String)]) -> Result<Vec<u8>> {
        Self::answer(self.req(self.http.get(format!("{url}{path}")).query(query)).send().await?).await
    }

    async fn get(&self, path: &str) -> Result<Value> {
        Ok(serde_json::from_slice(&self.get_raw_at(&self.rpc[0], path, &[]).await?)?)
    }

    async fn post(&self, path: &str, body: Vec<u8>, ctype: &str) -> Result<Value> {
        let r = self.req(self.http.post(format!("{}{path}", self.rpc[0])).header("Content-Type", ctype).body(body)).send().await?;
        Ok(serde_json::from_slice(&Self::answer(r).await?)?)
    }

    async fn params(&self) -> Result<Params> {
        let v = self.get("/v2/transactions/params").await?;
        let gh = arr32(&b64d(v["genesis-hash"].as_str().ok_or_else(|| anyhow!("params without genesis-hash"))?)?)?;
        if gh != self.network {
            bail!("algod's genesis hash {} is not the configured network {}", b64(&gh), b64(&self.network));
        }
        let n = |k: &str| v[k].as_u64().ok_or_else(|| anyhow!("params without {k}"));
        Ok(Params { min_fee: n("min-fee")?, fpb: n("fee")?, last_round: n("last-round")?,
                    chain: Chain { gen: v["genesis-id"].as_str().unwrap_or_default().to_string(), gh } })
    }

    async fn app(&self, id: u64) -> Result<Option<Value>> {
        match self.get(&format!("/v2/applications/{id}")).await {
            Ok(v) => Ok(Some(v)),
            Err(e) if status_of(&e) == Some(404) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn box_value(&self, app: u64, name: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.get_raw_at(&self.rpc[0], &format!("/v2/applications/{app}/box"), &[("name", format!("b64:{}", b64(name)))]).await {
            Ok(b) => {
                let v: Value = serde_json::from_slice(&b)?;
                Ok(Some(b64d(v["value"].as_str().ok_or_else(|| anyhow!("box without value"))?)?))
            }
            Err(e) if status_of(&e) == Some(404) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn exec(&self) -> Option<Executor> {
        self.exec.lock().ok().and_then(|e| e.clone())
    }

    fn sim_request(&self, p: &Params, g: &Group, lane: &[u8; 32], exec: Option<&Executor>, unnamed: bool, extra_budget: u64) -> Result<Vec<u8>> {
        let lv = p.last_round.saturating_add(10);
        let txns = g.txs.iter().zip(grouped(g, &p.chain, p.last_round, lv, lane, exec)?)
            .map(|(t, m)| signed_map(t, m, None, exec)).collect::<Result<Vec<_>>>()?;
        let mut req = vec![(k("allow-empty-signatures"), Mp::Bool(true)), (k("txn-groups"), Mp::Arr(vec![Mp::Map(vec![(k("txns"), Mp::Arr(txns))])]))];
        if unnamed {
            req.push((k("allow-unnamed-resources"), Mp::Bool(true)));
        }
        if extra_budget > 0 {
            req.push((k("extra-opcode-budget"), Mp::Int(extra_budget as i128)));
        }
        Ok(mp_encode(&Mp::Map(req)))
    }

    /// algod `simulate` of `g` (lane signatures empty, the executor's program evaluated). HTTP errors (the endpoint's
    /// own limits, a node down) are transport: retried.
    async fn simulate(&self, p: &Params, g: &Group, lane: &[u8; 32], exec: Option<&Executor>, unnamed: bool, extra_budget: u64)
                      -> std::result::Result<SimOut, SimError> {
        let body = self.sim_request(p, g, lane, exec, unnamed, extra_budget).map_err(|e| SimError::Revert(format!("{e:#}")))?;
        let v = self.post("/v2/transactions/simulate?format=json", body, "application/msgpack").await.map_err(transport)?;
        parse_sim(&v).map_err(transport)
    }

    /// A read-only ABI query by simulate (as the lane): its return value.
    async fn query(&self, p: &Params, lane: &[u8; 32], app: u64, args: Vec<Vec<u8>>) -> std::result::Result<Vec<u8>, SimError> {
        let g = Group { txs: vec![Tx::call(app, args)], main: 0, fee: p.min_fee, mbr: 0 };
        let s = self.simulate(p, &g, lane, None, true, QUERY_BUDGET).await?;
        if let Some(f) = s.failure {
            return Err(sim_failed(&f));
        }
        s.logs.first().and_then(|l| l.last()).and_then(|l| l.strip_prefix(&ABI_RETURN[..])).map(<[u8]>::to_vec)
            .ok_or_else(|| SimError::Transport(format!("app {app}: no ABI return")))
    }

    async fn query_u64(&self, p: &Params, lane: &[u8; 32], app: u64, args: Vec<Vec<u8>>) -> std::result::Result<u64, SimError> {
        be_u64(&self.query(p, lane, app, args).await?).map_err(transport)
    }

    fn rec_name(h: &Holder) -> Vec<u8> {
        [&b"s"[..], &h.bytes()].concat()
    }

    /// The account app's part of a signer's first op: 0 for a native wallet signature or an existing record, else
    /// `verify_mbr` (the lazy open of a UA record).
    async fn record_mbr(&self, p: &Params, lane: &[u8; 32], h: &Holder, digest: &[u8; 32], auth: &[u8]) -> std::result::Result<u64, SimError> {
        if h.kind == KIND_ADDRESS && auth.len() == 64 {
            return Ok(0);
        }
        if self.box_value(self.policy.account_app, &Self::rec_name(h)).await.map_err(transport)?.is_some() {
            return Ok(0);
        }
        self.query_u64(p, lane, self.policy.account_app, vec![selector("verify_mbr(uint8,byte[32],byte[32],byte[])uint64").to_vec(), vec![h.kind],
                                                             h.id.to_vec(), digest.to_vec(), abi_bytes(auth)]).await
    }

    /// The token's part of a value op (`mbr_needed`: the payer's lane box, the payee's balance box).
    async fn token_mbr(&self, p: &Params, lane: &[u8; 32], token: u64, op: &MetaOp) -> std::result::Result<u64, SimError> {
        self.query_u64(p, lane, token, vec![selector(&format!("mbr_needed({METAOP_ABI})uint64")).to_vec(), op.arc4()]).await
    }

    /// A record's (stored length, length, origin hashes) as `signed` sees it: stored, a native address's empty header, or
    /// the lazy UA record `verify_mbr` sizes (its passkey origins listed).
    async fn record_as_signed(&self, p: &Params, lane: &[u8; 32], h: &Holder, digest: &[u8; 32], auth: &[u8])
                              -> std::result::Result<(Option<usize>, usize, Vec<[u8; 32]>), SimError> {
        match self.box_value(self.policy.account_app, &Self::rec_name(h)).await.map_err(transport)? {
            Some(r) => {
                let (nk, no) = (r.get(116).copied().unwrap_or(0) as usize, r.get(117).copied().unwrap_or(0) as usize);
                let at = REC_HEADER + 32 * nk;
                let origins = (0..no).filter_map(|i| r.get(at + 32 * i..at + 32 * i + 32).and_then(|o| o.try_into().ok())).collect();
                Ok((Some(r.len()), r.len(), origins))
            }
            None if h.kind == KIND_ADDRESS && auth.len() == 64 => Ok((None, REC_HEADER, vec![])),
            None => {
                let m = self.record_mbr(p, lane, h, digest, auth).await?;
                let len = m.checked_sub(BOX_FLAT).map(|x| x / BOX_BYTE).and_then(|x| x.checked_sub(34))
                    .ok_or_else(|| SimError::Revert(format!("verify_mbr {m} is not a record's MBR")))?;
                let origins = auth_origins(auth, digest).map_err(|e| SimError::Revert(format!("{e:#}")))?;
                Ok((None, len as usize, origins))
            }
        }
    }

    /// The target's own exact MBR payment, per entry (the apps' rules; the job dies in simulate if it is off).
    async fn target_mbr(&self, p: &Params, lane: &[u8; 32], target: u64, args: &[Vec<u8>], info: &TargetInfo) -> std::result::Result<u64, SimError> {
        let revert = |e: anyhow::Error| SimError::Revert(format!("{e:#}"));
        let Some(app) = info.app else { return Ok(0) };
        let one = info.ops.first().cloned();
        let (op, auth) = match (&one, app) {
            (_, App::Dex) => return Ok(info.dex_mbr),
            (Some(x), _) => (x.0.clone(), x.1.clone()),
            (None, _) => return Err(SimError::Revert("target without its op".into())),
        };
        let d = op.digest();
        Ok(match (app, info.method) {
            (App::Token, "mtx_cancel") => MBR_ORDER_BOX + self.record_mbr(p, lane, &op.from, &d, &auth).await?,
            (App::Token, "mtx_invalidate_nonces") => {
                let name = [&b"n"[..], &sha256(&[&op.from.bytes()[..], &args[3]].concat())].concat();
                let new = self.box_value(target, &name).await.map_err(transport)?.is_none();
                (if new { MBR_LANE_BOX } else { 0 }) + self.record_mbr(p, lane, &op.from, &d, &auth).await?
            }
            (App::Token, _) => self.token_mbr(p, lane, target, &op).await? + self.record_mbr(p, lane, &op.from, &d, &auth).await?,
            (App::Account, "mtx_start_recovery" | "mtx_finish_recovery") => {
                let (old_g, len_g, _) = self.record_as_signed(p, lane, &op.from, &d, &auth).await?;
                let mut delta = box_delta(old_g, len_g);
                if info.method == "mtx_finish_recovery" {
                    let t = self.box_value(self.policy.account_app, &Self::rec_name(&op.to)).await.map_err(transport)?
                        .ok_or_else(|| SimError::Revert("finish_recovery: no such subject".into()))?;
                    let (nk, no) = (t.get(116).copied().unwrap_or(0) as usize, t.get(117).copied().unwrap_or(0) as usize);
                    let oh = t.get(84..116).unwrap_or_default();
                    let at = REC_HEADER + 32 * nk;
                    let listed = (0..no).any(|i| t.get(at + 32 * i..at + 32 * i + 32) == Some(oh));
                    let grow = 32 + if oh != [0; 32] && !listed { 32 } else { 0 };
                    delta += box_delta(Some(t.len()), t.len() + grow);
                }
                delta.max(0) as u64
            }
            (App::Account, _) => {
                let (old, len, origins) = self.record_as_signed(p, lane, &op.from, &d, &auth).await?;
                key_op_delta(args, old, len, &origins).map_err(revert)?.max(0) as u64
            }
            (App::Mandate, "mtx_mandate_open") => {
                let token = be_u64(&args[1]).map_err(revert)?;
                let payee = Holder::read(&args[4][33..66]).map_err(revert)?;
                let name = [if payee.kind == KIND_ADDRESS { &b"b"[..] } else { &b"u"[..] }, &payee.id].concat();
                let fund = be_u64(&args[5]).map_err(revert)?;
                let new = self.box_value(token, &name).await.map_err(transport)?.is_none();
                MBR_MANDATE_BOX.saturating_add(fund).saturating_add(if new { MBR_AMOUNT_BOX } else { 0 })
            }
            (App::Mandate, "mtx_mandate_pay") => {
                let key = [&b"m"[..], &args[1], &op.from.id].concat();
                let m = self.box_value(target, &key).await.map_err(transport)?.ok_or_else(|| SimError::Revert("mandate pay: no such mandate".into()))?;
                let delegate = Holder::read(m.get(33..66).unwrap_or_default()).map_err(revert)?;
                MBR_LANE_BOX + self.record_mbr(p, lane, &delegate, &d, &auth).await?
            }
            (App::Mandate, _) => self.record_mbr(p, lane, &op.from, &d, &auth).await?,
            (App::Dex, _) => info.dex_mbr,
        })
    }

    fn work(&self, job: &Job, exec: Option<&Executor>) -> Result<Work> {
        let o = job.op.as_ref().ok_or_else(|| anyhow!("not a signed_op job"))?;
        let op = MetaOp::decode(&hex_field(&o["payload"], "payload")?)?;
        if op.op != OP_PAY {
            bail!("only pay ops (op 0) are relayed as jobs on Algorand (every other entry is a relay-fee target)");
        }
        if op.network != self.network {
            bail!("the payload is for another network than {}", b64(&self.network));
        }
        let token = app_id_str(o["contract"].as_str().unwrap_or_default()).context("op.contract is the token app id")?;
        if app_address(token) != op.contract {
            bail!("op.contract {token} is not the payload's token");
        }
        if !self.policy.tokens.contains(&token) {
            bail!("token {token} is not a configured token of this chain");
        }
        let auth = hex_field(&o["signature"], "signature")?;
        let entry = entry(&self.policy, exec, &op, o)?;
        let (refs, carries) = if matches!(entry, Entry::Fee { .. }) { job_refs(o)? } else { Default::default() };
        Ok(Work { op, token, auth, entry, refs, carries })
    }

    /// The bytes a transaction takes signed, at most (fee / rounds at their widest), for the per-byte fee.
    fn signed_len(t: &Tx, chain: &Chain, exec: Option<&Executor>) -> usize {
        let m = txn_map(t, &[1; 32], u64::MAX, u64::MAX, u64::MAX, chain, Some(&[1; 32]));
        signed_map(t, m, Some(vec![1; 64]), exec).map(|s| mp_encode(&s).len()).unwrap_or(4096)
    }

    fn fee_of(p: &Params, g: &Group, inner: u64, exec: Option<&Executor>) -> u64 {
        g.txs.iter().map(|t| p.min_fee.max(p.fpb.saturating_mul(Self::signed_len(t, &p.chain, exec) as u64)))
            .fold(0u64, u64::saturating_add).saturating_add(inner.saturating_mul(p.min_fee))
    }

    /// Two block timestamps `ROUND_SAMPLE` rounds apart, ending at `last`: (ts of `last`, rounds, seconds).
    async fn round_time(&self, last: u64) -> Result<(u64, u64, u64)> {
        let ts = |b: Vec<u8>| -> Result<u64> {
            mp_decode(&b)?.get("block").and_then(|b| b.get("ts")).and_then(Mp::u64).ok_or_else(|| anyhow!("block without ts"))
        };
        let t1 = ts(self.get_raw_at(&self.rpc[0], &format!("/v2/blocks/{last}"), &[("format", "msgpack".into())]).await?)?;
        let first = last.saturating_sub(ROUND_SAMPLE).max(1);
        if first >= last {
            return Ok((t1, 0, 0));
        }
        let t0 = ts(self.get_raw_at(&self.rpc[0], &format!("/v2/blocks/{first}"), &[("format", "msgpack".into())]).await?)?;
        Ok((t1, last - first, t1.saturating_sub(t0)))
    }

    async fn block_hash_at(&self, url: &str, h: u64) -> Result<String> {
        let v: Value = serde_json::from_slice(&self.get_raw_at(url, &format!("/v2/blocks/{h}/hash"), &[]).await?)?;
        let s = v["blockHash"].as_str().ok_or_else(|| anyhow!("block {h} without blockHash"))?;
        Ok(hex0x(&arr32(&b32decode(s.trim_start_matches("blk-"))?)?))
    }

    /// R9: the key set of `holder` per configured token. Every token verifies through the one account app (start_check
    /// asserts each token's `account_app`), so the sets are one record: (token, key ids), `None` = no record.
    pub async fn key_sets(&self, holder: &Holder) -> Result<Vec<(u64, Option<Vec<[u8; 32]>>)>> {
        let rec = self.box_value(self.policy.account_app, &Self::rec_name(holder)).await?;
        let keys = rec.map(|r| {
            let n = r.get(116).copied().unwrap_or(0) as usize;
            (0..n).filter_map(|i| r.get(REC_HEADER + 32 * i..REC_HEADER + 32 * i + 32).and_then(|x| x.try_into().ok())).collect()
        });
        Ok(self.policy.tokens.iter().map(|t| (*t, keys.clone())).collect())
    }
}

#[async_trait]
impl ChainAdapter for AlgorandAdapter {
    fn family(&self) -> Family {
        Family::Algorand
    }

    fn chain_key(&self) -> &str {
        &self.key
    }

    fn lanes(&self) -> &[Lane] {
        &self.lanes
    }

    /// R80: the payer's lane box on the token has passed the op's nonce. Every job kind is one atomic group (no escrow,
    /// no refund), so a consumed payment lane means the job's group landed (lesson 1).
    async fn op_consumed(&self, job: &Job) -> Result<Option<bool>> {
        let Ok(w) = self.work(job, self.exec().as_ref()) else { return Ok(None) };
        let name = [&b"l"[..], &sha256(&[&w.op.from.bytes()[..], &w.op.lane].concat())].concat();
        let next = match self.box_value(w.token, &name).await? {
            Some(v) => be_u64(&v)?,
            None => 0,
        };
        Ok(Some(next > w.op.nonce))
    }

    /// The §5 checks, the group with the apps' exact MBR payments, a discovery simulate (unnamed resources allowed, a
    /// generous fee credit) whose unnamed resources go onto budget calls, then the exact group simulated with every
    /// resource named and the fee = one min fee per transaction and per inner transaction (re-run until the inner count
    /// settles); `Revert` = the job dies with the group's reason. A fee that is the node's must cover fee + MBR.
    async fn build(&self, job: &Job, lane: usize) -> std::result::Result<Built, SimError> {
        let revert = |e: anyhow::Error| SimError::Revert(format!("{e:#}"));
        let exec = self.exec();
        let w = self.work(job, exec.as_ref()).map_err(|e| SimError::Revert(format!("bad payload: {e:#}")))?;
        let now = now();
        if w.op.valid_until <= now {
            return Err(SimError::Revert("payload expired".into()));
        }
        margin(w.op.valid_until, now, "the payment").map_err(revert)?;
        let lane_pk = *self.pks.get(lane).ok_or_else(|| SimError::Transport(format!("no lane {lane}")))?;
        let p = self.params().await.map_err(transport)?;
        let digest = w.op.digest();
        let token_addr = app_address(w.token);
        let mut fee_ours = false;
        let mut g = match &w.entry {
            Entry::Pay | Entry::PayMeta { .. } => {
                if w.op.relayer != [0; 32] && w.op.relayer != lane_pk {
                    return Err(SimError::Revert("the op is bound to another relayer (rule 7)".into()));
                }
                let mbr = self.token_mbr(&p, &lane_pk, w.token, &w.op).await? + self.record_mbr(&p, &lane_pk, &w.op.from, &digest, &w.auth).await?;
                let args = match &w.entry {
                    Entry::PayMeta { salt, meta } => vec![selector(&format!("mtx_pay_meta({METAOP_ABI},byte[],byte[32],byte[])void")).to_vec(), w.op.arc4(),
                                                          abi_bytes(&w.auth), salt.to_vec(), abi_bytes(meta)],
                    _ => vec![selector(&format!("mtx_pay({METAOP_ABI},byte[],address)void")).to_vec(), w.op.arc4(), abi_bytes(&w.auth), lane_pk.to_vec()],
                };
                let mut txs = Vec::new();
                if mbr > 0 {
                    txs.push(Tx::Pay { to: token_addr, amount: mbr });
                }
                txs.push(Tx::call(w.token, args));
                Group { main: txs.len() - 1, txs, fee: 0, mbr: 0 }
            }
            Entry::Fee { target_app, args } => {
                let ex = exec.as_ref().ok_or_else(|| SimError::Transport("the router's executor is not derived yet (start_check)".into()))?;
                let router = self.policy.router.ok_or_else(|| SimError::Revert("no router".into()))?;
                let open = w.op.to == Holder::addr(app_address(router));
                let to_lane = w.op.to == Holder::addr(lane_pk);
                crate::adapter::relay_fee_ours(open, to_lane, w.op.amount, &self.policy.params).map_err(revert)?;
                fee_ours = open || to_lane;
                if self.app(*target_app).await.map_err(transport)?.is_none() {
                    return Err(SimError::Revert(format!("relay-fee target app {target_app} is missing (rule 13)")));
                }
                let info = target_check(&self.policy, ex, &w.op, *target_app, args, &lane_pk, w.carries.len(), now).map_err(revert)?;
                if info.app == Some(App::Account) {
                    if let Some((op, _)) = info.ops.first() {
                        match self.key_sets(&op.from).await {
                            Ok(s) => info!(chain = %self.key, subject = %op.from.display(), keys = ?s.first().map(|x| x.1.as_ref().map(|k| k.iter().map(|x| hex0x(x)).collect::<Vec<_>>())), "key op job: the subject's key set (one record for every token)"),
                            Err(e) => info!(chain = %self.key, "key op job: key set unreadable: {e:#}"),
                        }
                    }
                }
                let pt = self.target_mbr(&p, &lane_pk, *target_app, args, &info).await?;
                let payee = if open { Holder::addr(lane_pk) } else { w.op.to };
                let opens = !(w.op.from.kind == KIND_ADDRESS && w.auth.len() == 64) && info.signers.contains(&w.op.from)
                    && info.ops.iter().any(|(o, a)| o.from == w.op.from && !(o.from.kind == KIND_ADDRESS && a.len() == 64));
                let rec = if opens && self.box_value(self.policy.account_app, &Self::rec_name(&w.op.from)).await.map_err(transport)?.is_none() {
                    0 // the target opens the payer's record before the router's pay verifies (one atomic group)
                } else {
                    self.record_mbr(&p, &lane_pk, &w.op.from, &digest, &w.auth).await?
                };
                let pr = self.token_mbr(&p, &lane_pk, w.token, &MetaOp { to: payee, ..w.op.clone() }).await? + rec;
                let mut txs = Vec::new();
                if pr > 0 {
                    txs.push(Tx::Pay { to: app_address(router), amount: pr });
                }
                if pt > 0 {
                    txs.push(Tx::Pay { to: app_address(*target_app), amount: pt });
                }
                txs.push(target_tx(*target_app, args.clone(), &w.refs).map_err(revert)?);
                txs.push(Tx::call(router, vec![selector(&format!("relay(uint64,{METAOP_ABI},byte[])void")).to_vec(), w.token.to_be_bytes().to_vec(),
                                               w.op.arc4(), abi_bytes(&w.auth)]));
                let main = txs.len() - 1;
                for c in &w.carries {
                    txs.push(Tx::call(*target_app, vec![selector("carry(byte[])void").to_vec(), abi_bytes(c)]));
                }
                Group { txs, main, fee: 0, mbr: 0 }
            }
        };
        let ex = exec.as_ref();
        g.fee = p.min_fee.saturating_mul(g.txs.len() as u64 + DISCOVERY_CREDIT);
        let d = self.simulate(&p, &g, &lane_pk, ex, true, 0).await?;
        if let Some(f) = &d.failure {
            return Err(sim_failed(f));
        }
        for (t, u) in g.txs.iter_mut().zip(&d.per_txn) {
            add_own(t, u).map_err(revert)?;
        }
        g.txs.extend(budget_calls(w.token, &d.unnamed).map_err(revert)?);
        if g.txs.len() > MAX_GROUP {
            return Err(SimError::Revert(format!("the group needs {} transactions, above {MAX_GROUP}", g.txs.len())));
        }
        let mut inner = d.inner;
        let mut settled = false;
        for _ in 0..3 {
            g.fee = Self::fee_of(&p, &g, inner, ex);
            let s = self.simulate(&p, &g, &lane_pk, ex, false, 0).await?;
            if let Some(f) = &s.failure {
                return Err(sim_failed(f));
            }
            if s.inner == inner {
                settled = true;
                break;
            }
            inner = s.inner;
        }
        if !settled {
            return Err(SimError::Revert("the group's inner transaction count does not settle".into()));
        }
        g.mbr = g.txs.iter().map(|t| if let Tx::Pay { amount, .. } = t { *amount } else { 0 }).sum();
        if fee_ours {
            let price = self.policy.min_microalgo_value.get(&w.token)
                .ok_or_else(|| SimError::Revert(format!("params.relay_fee.min_microalgo_value has no price for token {}", w.token)))?;
            let quote = u128::from(g.fee) + u128::from(g.mbr);
            let value = w.op.amount.saturating_mul(*price);
            if value < quote {
                return Err(SimError::Revert(format!("fee {} × min_microalgo_value {price} = {value} µALGO is below the {quote} µALGO the group costs \
                                                     (fee {} + MBR {})", w.op.amount, g.fee, g.mbr)));
            }
        }
        let meta = serde_json::to_value(&g).map_err(|e| SimError::Revert(e.to_string()))?;
        Ok(Built { job_id: job.id, body: vec![], valid_until: w.op.valid_until, meta })
    }

    /// FirstValid = `sequence` (the last round), LastValid by `last_valid` from two block timestamps; the group id set,
    /// the lane's transactions signed over `"TX"` ‖ bytes, the executor's by its program.
    async fn sign(&self, built: Built, lane: usize, sequence: u64) -> Result<Signed> {
        let g: Group = serde_json::from_value(built.meta)?;
        let s = self.signers.get(lane).ok_or_else(|| anyhow!("no lane {lane}"))?;
        let p = self.params().await?;
        let (ts, rounds, secs) = self.round_time(sequence).await?;
        let lv = last_valid(sequence, sequence, ts, rounds, secs, built.valid_until)?;
        let exec = self.exec();
        let (raw, ids) = sign_group(&g, &p.chain, sequence, lv, &|m| s.sign(m), &self.pks[lane], exec.as_ref())?;
        let tx_id = hex0x(ids.get(g.main).ok_or_else(|| anyhow!("group without its main transaction"))?);
        if let Ok(mut m) = self.spent.lock() {
            m.insert(tx_id.clone(), u128::from(g.fee) + u128::from(g.mbr));
        }
        Ok(Signed { job_id: built.job_id, tx_id, raw, valid_until: built.valid_until, sequence })
    }

    /// A 4xx answer (dead window, fee, overspend, a logic failure at the pool's check): the same bytes never pass ⇒
    /// `Rejected`; "already in ledger" = it landed.
    async fn submit(&self, signed: &Signed) -> Result<()> {
        match self.post("/v2/transactions", signed.raw.clone(), "application/x-binary").await {
            Ok(_) => Ok(()),
            Err(e) if e.downcast_ref::<AlgodError>().is_some_and(|a| a.message.contains("already in ledger")) => Ok(()),
            Err(e) if status_of(&e).is_some_and(|s| (400..500).contains(&s)) => Err(Rejected(format!("{e:#}")).into()),
            Err(e) => Err(e),
        }
    }

    /// One-round finality: confirmed = mined; a pool error (the group failed or its window closed) = reverted (lesson
    /// 16: never requeued); not in the pool = unknown.
    async fn tx_status(&self, tx_id: &str) -> Result<TxStatus> {
        let id = b32encode(&arr32(&alloy::hex::decode(tx_id.trim_start_matches("0x"))?)?);
        let v = match self.get(&format!("/v2/transactions/pending/{id}")).await {
            Ok(v) => v,
            Err(e) if status_of(&e) == Some(404) => return Ok(TxStatus::Unknown),
            Err(e) => return Err(e),
        };
        if let Some(h) = v["confirmed-round"].as_u64().filter(|h| *h > 0) {
            return Ok(TxStatus::Mined { height: h, tx_hash: None });
        }
        match v["pool-error"].as_str().filter(|s| !s.is_empty()) {
            Some(e) => Ok(TxStatus::Reverted { reason: e.to_string() }),
            None => Ok(TxStatus::Pending),
        }
    }

    /// No account sequence on Algorand: the last round (the next group's FirstValid).
    async fn sequence(&self, _lane: usize) -> Result<u64> {
        self.get("/v2/status").await?["last-round"].as_u64().ok_or_else(|| anyhow!("status without last-round"))
    }

    async fn lane_balance(&self, lane: usize) -> Result<Option<u128>> {
        let a = &self.lanes.get(lane).ok_or_else(|| anyhow!("no lane {lane}"))?.address;
        Ok(self.get(&format!("/v2/accounts/{a}?exclude=all")).await?["amount"].as_u64().map(u128::from))
    }

    /// What the lane paid for its group: the pooled fee + its MBR payments (known since `sign`; read once, at mined).
    async fn tx_fee(&self, tx_id: &str) -> Result<Option<u128>> {
        Ok(self.spent.lock().ok().and_then(|mut m| m.remove(tx_id)))
    }

    /// The last round (one-round finality); with `quorum > 1` further endpoints must agree on its hash.
    async fn final_head(&self) -> Result<Option<Head>> {
        let height = self.sequence(0).await?;
        let hash = self.block_hash_at(&self.rpc[0], height).await?;
        let mut agree = 1;
        for url in &self.rpc[1..] {
            if self.block_hash_at(url, height).await.ok().as_deref() == Some(hash.as_str()) {
                agree += 1;
            }
        }
        Ok((agree >= self.quorum).then_some(Head { height, hash }))
    }

    async fn block_hash(&self, height: u64) -> Result<String> {
        self.block_hash_at(&self.rpc[0], height).await
    }

    /// Every round of [from, to] (none is ever skipped): a round algod no longer has (a non-archival node's pruned
    /// history) fails the range (lesson 9). With `quorum > 1` further endpoints must return the same block bytes.
    /// ponytail: two RPCs per round (block + hash); an indexer feed when a busy chain needs it.
    async fn events(&self, from: u64, to: u64, contracts: &[String]) -> Result<Vec<Value>> {
        let tokens: Vec<u64> = contracts.iter().filter_map(|c| app_id_str(c).ok()).collect();
        if tokens.is_empty() && !contracts.is_empty() {
            bail!("none of the {} registered tokens is an Algorand app id", contracts.len());
        }
        if tokens.is_empty() || from > to {
            return Ok(vec![]);
        }
        let ids = Ids { tokens, router: self.policy.router, mandate: self.policy.mandate_app, dex: self.policy.dex_app };
        let mut out = Vec::new();
        for h in from..=to {
            let q = [("format", "msgpack".to_string())];
            let raw = match self.get_raw_at(&self.rpc[0], &format!("/v2/blocks/{h}"), &q).await {
                Ok(b) => b,
                Err(e) if status_of(&e) == Some(404) => bail!("round {h} is not in algod's history (pruned: use an archival node): {e:#}"),
                Err(e) => return Err(e),
            };
            if self.quorum > 1 {
                let mut agree = 1;
                for url in &self.rpc[1..] {
                    if self.get_raw_at(url, &format!("/v2/blocks/{h}"), &q).await.ok().as_deref() == Some(&raw[..]) {
                        agree += 1;
                    }
                }
                ensure!(agree >= self.quorum, "block {h}: {agree} endpoint(s) agree, quorum is {}", self.quorum);
            }
            let b = mp_decode(&raw)?;
            let block = b.get("block").ok_or_else(|| anyhow!("round {h}: no block"))?;
            let hash = self.block_hash(h).await?;
            out.extend(block_events(&ids, block, &hash)?);
        }
        Ok(out)
    }

    /// Spec §5 startup errors (R11): algod's genesis is the configured network; every configured app exists (else
    /// "missing app id") and its approval and clear programs hash (sha512_256) to artifacts.json (else the chain is
    /// halted); each token's and the mandate's `account_app` and the DEX's `router_app` are the configured ones; the
    /// router's executor (from its salt global) equals `executor()` and is off-curve (note 1); every lane and the router's
    /// address hold at least their minimum balance.
    async fn start_check(&self) -> Result<()> {
        self.params().await?;
        let a: Value = serde_json::from_str(ARTIFACTS).context("artifacts.json")?;
        let mut apps: Vec<(u64, &str)> = self.policy.tokens.iter().map(|t| (*t, "token")).collect();
        apps.push((self.policy.account_app, "account"));
        apps.extend(self.policy.mandate_app.map(|m| (m, "mandate")));
        apps.extend(self.policy.dex_app.map(|d| (d, "dex")));
        apps.extend(self.policy.router.map(|r| (r, "relayfee")));
        let mut salt = None;
        for (id, program) in apps {
            let v = self.app(id).await?.ok_or_else(|| anyhow!("missing app id: {program} app {id} does not exist"))?;
            let pp = &v["params"];
            for (field, key) in [("approval-program", "approval_sha512_256"), ("clear-state-program", "clear_sha512_256")] {
                let got = alloy::hex::encode(sha512_256(&[&b64d(pp[field].as_str().unwrap_or_default())?]));
                let want = a[program][key].as_str().ok_or_else(|| anyhow!("artifacts.json {program}.{key}"))?;
                if got != want {
                    bail!("{program} app {id}: {field} sha512_256 {got} is not artifacts.json {want}: the chain is halted (spec §4.9)");
                }
            }
            let global = |name: &str| pp["global-state"].as_array().into_iter().flatten()
                .find(|g| g["key"].as_str() == Some(b64(name.as_bytes()).as_str())).and_then(|g| g["value"]["uint"].as_u64());
            match program {
                "token" | "mandate" if global("account_app") != Some(self.policy.account_app) => {
                    bail!("{program} app {id}: account_app {:?} is not params.account_app {}", global("account_app"), self.policy.account_app)
                }
                "dex" if global("router_app") != self.policy.router => {
                    bail!("dex app {id}: router_app {:?} is not params.relayfee_app {:?}", global("router_app"), self.policy.router)
                }
                "relayfee" => salt = Some(global("salt").and_then(|s| u8::try_from(s).ok()).ok_or_else(|| anyhow!("router {id}: no salt global"))?),
                _ => {}
            }
        }
        if let (Some(router), Some(salt)) = (self.policy.router, salt) {
            let x = Executor::new(router, salt)?;
            let p = self.params().await?;
            let got = self.query(&p, &self.pks[0], router, vec![selector("executor()address").to_vec()]).await
                .map_err(|e| anyhow!("router executor(): {e:?}"))?;
            if got != x.address {
                bail!("router {router} executor() is {}, not the executor rebuilt from its salt {salt}: {}", hex0x(&got), algorand_address(&x.address));
            }
            if on_curve(&x.address) {
                bail!("router {router}'s executor {} (salt {salt}) is on-curve: an ed25519 key could sign for it (redeploy the router)",
                      algorand_address(&x.address));
            }
            if let Ok(mut e) = self.exec.lock() {
                *e = Some(x);
            }
        }
        // note 2: the router's address holds its base minimum (an account below it cannot receive the MBR it forwards)
        let router = self.policy.router.map(|r| ("router", algorand_address(&app_address(r))));
        for (what, a) in self.lanes.iter().map(|l| ("lane", l.address.clone())).chain(router) {
            let v = self.get(&format!("/v2/accounts/{a}?exclude=all")).await?;
            let (amount, min) = (v["amount"].as_u64().unwrap_or(0), v["min-balance"].as_u64().unwrap_or(0));
            if amount == 0 || amount < min {
                bail!("{what} {a} holds {amount} µALGO, below its minimum balance {min}");
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex as M};

    const VECTORS: &str = include_str!("../../../smartcontracts/algorand/vectors/algorand-vectors.json");
    const TXV: &str = include_str!("../../../smartcontracts/algorand/vectors/algorand-tx.json");
    const PAYMETA: &str = include_str!("../../../smartcontracts/vectors/metatx/paymeta.json");
    const TOKEN: u64 = 1001;
    const ROUTER: u64 = 1002;
    const TARGET: u64 = 1003;
    const ACCOUNT: u64 = 1004;
    const MANDATE: u64 = 1005;
    const DEX: u64 = 1006;
    const TOKEN_B: u64 = 1007;

    fn v() -> Value {
        serde_json::from_str(VECTORS).unwrap()
    }
    fn hx(v: &Value) -> Vec<u8> {
        alloy::hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
    }
    fn b32(v: &Value) -> [u8; 32] {
        hx(v).try_into().unwrap()
    }
    fn h(b: &[u8]) -> String {
        format!("0x{}", alloy::hex::encode(b))
    }
    fn row(name: &str) -> Value {
        v()["metaops"]["vectors"].as_array().unwrap().iter().find(|r| r["name"] == name).unwrap_or_else(|| panic!("{name}")).clone()
    }
    fn op_of(name: &str) -> MetaOp {
        MetaOp::decode(&hx(&row(name)["encoding"])).unwrap()
    }
    /// The `auth: byte[]` a row's op is relayed with: a native payer's 64-byte signature, else tag ‖ body.
    fn auth_of(name: &str) -> Vec<u8> {
        let r = row(name);
        if r["authBytes"].is_string() {
            return hx(&r["authBytes"]);
        }
        let a = &r["auth"];
        let sig = hx(&a["sig"]);
        match a["kind"].as_str().unwrap() {
            "ed25519" if r["fields"]["from"]["kind"] == 0 => sig,
            "ed25519" => [vec![1], hx(&a["key"]), sig].concat(),
            "secp256k1" => [vec![2], hx(&a["key"]), sig[..64].to_vec()].concat(),
            "passkey" => {
                let ad = hx(&a["authenticatorData"]);
                [vec![3], hx(&a["key"]), sig, (ad.len() as u16).to_be_bytes().to_vec(), ad, a["clientDataJSON"].as_str().unwrap().as_bytes().to_vec()].concat()
            }
            k => panic!("{k}"),
        }
    }
    fn network() -> [u8; 32] {
        b32(&v()["network"])
    }
    fn lane0() -> LocalSigner {
        LocalSigner::new(crate::signer::Curve::Ed25519, &[7; 32]).unwrap()
    }
    fn lane_pk() -> [u8; 32] {
        lane0().public_key().try_into().unwrap()
    }
    fn exec() -> Executor {
        Executor::new(ROUTER, 2).unwrap()
    }
    fn pol() -> RelayFeePolicy {
        RelayFeePolicy {
            tokens: vec![TOKEN, TOKEN_B],
            account_app: ACCOUNT,
            mandate_app: Some(MANDATE),
            dex_app: Some(DEX),
            router: Some(ROUTER),
            params: crate::config::RelayParams { min_amount: 1, ..Default::default() },
            min_microalgo_value: HashMap::from([(TOKEN, 1_000)]),
            targets: BTreeMap::from([(TARGET, vec![selector(&format!("mtx_add_key({METAOP_ABI},byte[],(uint16,byte[]),byte[])void"))])]),
        }
    }
    fn job(o: Value) -> Job {
        serde_json::from_value(json!({"id": 7, "kind": "signed_op", "op": o})).unwrap()
    }
    fn o_op(op: &MetaOp, auth: &[u8], extra: Value) -> Value {
        let mut o = json!({"payload": h(&op.encode()), "signature": h(auth), "contract": TOKEN.to_string()});
        for (k, x) in extra.as_object().cloned().unwrap_or_default() {
            o[k] = x;
        }
        o
    }
    fn holder(kind: u8, id: [u8; 32]) -> Holder {
        Holder { kind, id }
    }
    fn far() -> u64 {
        now() + 86_400
    }
    /// A payment op of `call` (open mode unless `to` is given), signed by nobody (the mocked simulate decides).
    fn fee_op(call: &[u8], salt: [u8; 32], to: Option<Holder>) -> MetaOp {
        let r = relay_ref(&network(), &app_address(parse_router_call(call).unwrap().0), call, &salt);
        MetaOp {
            network: network(), contract: app_address(TOKEN), op: 0, from: holder(1, [0x11; 32]),
            to: to.unwrap_or(holder(0, app_address(ROUTER))), relayer: app_address(ROUTER), amount: 50_000, pay_ref: r,
            lane: pay_lane(&r), nonce: 0, valid_until: far(), extra: salt,
        }
    }
    fn fee_job(call: &[u8], op: &MetaOp, extra: Value) -> Value {
        let mut e = json!({"call": h(call)});
        for (k, x) in extra.as_object().cloned().unwrap_or_default() {
            e[k] = x;
        }
        o_op(op, &[0xaa; 70], json!({"kind": "relay_fee", "extra": e}))
    }
    fn target_op(contract: [u8; 32], op: u8, from: Holder, to: Holder) -> MetaOp {
        MetaOp { network: network(), contract, op, from, to, relayer: [0; 32], amount: 5, pay_ref: [0; 32], lane: [0x33; 32],
                 nonce: 0, valid_until: far(), extra: [0; 32] }
    }
    fn transfer_call(t: &MetaOp) -> Vec<u8> {
        router_call(TOKEN, &[selector(&format!("mtx_transfer({METAOP_ABI},byte[])void")).to_vec(), t.arc4(), abi_bytes(&[0xbb; 70])])
    }

    // ------------------------------------------------------------ mocked algod
    #[derive(Default)]
    struct World {
        genesis: [u8; 32],
        last_round: u64,
        min_fee: u64,
        fpb: u64,
        apps: HashMap<u64, Value>,
        boxes: HashMap<(u64, Vec<u8>), Vec<u8>>,
        accounts: HashMap<String, (u64, u64)>,
        blocks: HashMap<u64, (Vec<u8>, [u8; 32])>,
        /// selector ⇒ the ABI return of a one-transaction simulate (a read-only query)
        views: HashMap<[u8; 4], Vec<u8>>,
        unnamed: Value,
        inner: u64,
        fail: Option<String>,
        sims: Vec<Mp>,
        submitted: Vec<Vec<u8>>,
        submit_err: Option<String>,
        pending: HashMap<String, Value>,
    }

    fn app_json(program: &str, globals: Value) -> Value {
        let b = |f: &str| base64::engine::general_purpose::STANDARD.encode(std::fs::read(format!("../smartcontracts/algorand/out/{f}")).unwrap());
        json!({"id": 0, "params": {"approval-program": b(&format!("{program}.approval.bin")), "clear-state-program": b(&format!("{program}.clear.bin")),
                                   "global-state": globals}})
    }
    fn g_uint(k: &str, n: u64) -> Value {
        json!({"key": base64::engine::general_purpose::STANDARD.encode(k), "value": {"type": 2, "uint": n}})
    }

    fn world() -> World {
        let mut w = World { genesis: network(), last_round: 5_000, min_fee: 1_000, inner: 3, unnamed: json!({}), ..Default::default() };
        w.apps.insert(TOKEN, app_json("Token", json!([g_uint("account_app", ACCOUNT)])));
        w.apps.insert(TOKEN_B, app_json("Token", json!([g_uint("account_app", ACCOUNT)])));
        w.apps.insert(ACCOUNT, app_json("Account", json!([])));
        w.apps.insert(MANDATE, app_json("Mandate", json!([g_uint("account_app", ACCOUNT)])));
        w.apps.insert(DEX, app_json("Dex", json!([g_uint("router_app", ROUTER)])));
        w.apps.insert(ROUTER, app_json("RelayFee", json!([g_uint("salt", 2)])));
        w.apps.insert(TARGET, app_json("RelayTarget", json!([])));
        w.accounts.insert(algorand_address(&lane_pk()), (10_000_000, 100_000));
        w.accounts.insert(algorand_address(&app_address(ROUTER)), (100_000, 100_000));
        w.views.insert(selector("executor()address"), exec().address.to_vec());
        w.views.insert(selector(&format!("mbr_needed({METAOP_ABI})uint64")), 47_400u64.to_be_bytes().to_vec());
        w.views.insert(selector("verify_mbr(uint8,byte[32],byte[32],byte[])uint64"), 76_100u64.to_be_bytes().to_vec());
        let ts = |r: u64| 1_800_000_000 + r * 3;
        for r in [4_900u64, 5_000] {
            let b = Mp::Map(vec![(Mp::str("block"), Mp::Map(vec![(Mp::str("rnd"), Mp::Int(r as i128)), (Mp::str("ts"), Mp::Int(ts(r) as i128))]))]);
            w.blocks.insert(r, (mp_encode(&b), [r as u8; 32]));
        }
        w
    }

    fn txns_of(req: &Mp) -> Vec<Mp> {
        req.get("txn-groups").and_then(|g| g.arr().first().cloned()).and_then(|g| g.get("txns").map(|t| t.arr().to_vec())).unwrap_or_default()
    }

    fn simulate(w: &mut World, req: Mp) -> Value {
        let txns = txns_of(&req);
        w.sims.push(req.clone());
        let sel = |t: &Mp| t.get("txn").and_then(|x| x.get("apaa")).and_then(|a| a.arr().first().and_then(|s| s.bytes().map(|b| b.to_vec())));
        if txns.len() == 1 {
            if let Some(ret) = sel(&txns[0]).and_then(|s| w.views.get(&<[u8; 4]>::try_from(&s[..]).ok()?).cloned()) {
                let log = base64::engine::general_purpose::STANDARD.encode([&[0x15, 0x1f, 0x7c, 0x75][..], &ret].concat());
                return json!({"txn-groups": [{"txn-results": [{"txn-result": {"logs": [log]}}]}]});
            }
        }
        if let Some(f) = &w.fail {
            return json!({"txn-groups": [{"failure-message": f, "failed-at": [0], "txn-results": []}]});
        }
        let mut results: Vec<Value> = txns.iter().map(|_| json!({"txn-result": {}})).collect();
        let inner: Vec<Value> = (0..w.inner).map(|_| json!({"txn": {}})).collect();
        if let Some(last) = results.iter_mut().rev().find(|_| true) {
            last["txn-result"]["inner-txns"] = json!([{"inner-txns": inner}]);
        }
        let unnamed = req.get("allow-unnamed-resources").is_some_and(|b| matches!(b, Mp::Bool(true)));
        // the "inner-txns" tree holds w.inner + 1 transactions in all
        json!({"txn-groups": [{"txn-results": results, "unnamed-resources-accessed": if unnamed { w.unnamed.clone() } else { json!(null) }}]})
    }

    async fn serve(w: Arc<M<World>>) -> String {
        use axum::extract::{Path, Query, State};
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        use axum::routing::{get, post};
        type S = State<Arc<M<World>>>;
        let nf = || (StatusCode::NOT_FOUND, axum::Json(json!({"message": "not found"}))).into_response();
        let app = axum::Router::new()
            .route("/v2/transactions/params", get(|State(s): S| async move {
                let w = s.lock().unwrap();
                axum::Json(json!({"genesis-hash": base64::engine::general_purpose::STANDARD.encode(w.genesis), "genesis-id": "scaas-localnet-v1",
                                  "last-round": w.last_round, "min-fee": w.min_fee, "fee": w.fpb, "consensus-version": "future"}))
            }))
            .route("/v2/status", get(|State(s): S| async move { axum::Json(json!({"last-round": s.lock().unwrap().last_round})) }))
            .route("/v2/applications/{id}", get(move |State(s): S, Path(id): Path<u64>| async move {
                match s.lock().unwrap().apps.get(&id) { Some(a) => axum::Json(a.clone()).into_response(), None => nf() }
            }))
            .route("/v2/applications/{id}/box", get(move |State(s): S, Path(id): Path<u64>, Query(q): Query<HashMap<String, String>>| async move {
                let name = base64::engine::general_purpose::STANDARD.decode(q["name"].trim_start_matches("b64:")).unwrap();
                match s.lock().unwrap().boxes.get(&(id, name)) {
                    Some(b) => axum::Json(json!({"value": base64::engine::general_purpose::STANDARD.encode(b)})).into_response(),
                    None => nf(),
                }
            }))
            .route("/v2/accounts/{a}", get(|State(s): S, Path(a): Path<String>| async move {
                let (amount, min) = s.lock().unwrap().accounts.get(&a).copied().unwrap_or((0, 0));
                axum::Json(json!({"address": a, "amount": amount, "min-balance": min}))
            }))
            .route("/v2/blocks/{r}", get(move |State(s): S, Path(r): Path<u64>| async move {
                match s.lock().unwrap().blocks.get(&r) { Some((b, _)) => b.clone().into_response(), None => nf() }
            }))
            .route("/v2/blocks/{r}/hash", get(move |State(s): S, Path(r): Path<u64>| async move {
                match s.lock().unwrap().blocks.get(&r) {
                    Some((_, hh)) => axum::Json(json!({"blockHash": crate::addresses::b32encode(hh)})).into_response(),
                    None => nf(),
                }
            }))
            .route("/v2/transactions/simulate", post(|State(s): S, body: axum::body::Bytes| async move {
                let req = mp_decode(&body).unwrap();
                axum::Json(simulate(&mut s.lock().unwrap(), req))
            }))
            .route("/v2/transactions", post(|State(s): S, body: axum::body::Bytes| async move {
                let mut w = s.lock().unwrap();
                w.submitted.push(body.to_vec());
                match w.submit_err.clone() {
                    Some(m) => (StatusCode::BAD_REQUEST, axum::Json(json!({"message": m}))).into_response(),
                    None => axum::Json(json!({"txId": "X"})).into_response(),
                }
            }))
            .route("/v2/transactions/pending/{id}", get(move |State(s): S, Path(id): Path<String>| async move {
                match s.lock().unwrap().pending.get(&id) { Some(p) => axum::Json(p.clone()).into_response(), None => nf() }
            }))
            .with_state(w);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        url
    }

    fn cfg(url: &str, relay_fee: &str) -> ChainCfg {
        let b64 = base64::engine::general_purpose::STANDARD.encode(network());
        toml::from_str(&format!(r#"
family = "algorand"
network = "{b64}"
rpc_urls = ["{url}"]
lanes = [0]
tokens = [{{ address = "{TOKEN}", decimals = 6 }}, {{ address = "{TOKEN_B}", decimals = 6 }}]
params = {{ account_app = {ACCOUNT}, mandate_app = {MANDATE}, dex_app = {DEX}, relayfee_app = {ROUTER}{relay_fee} }}
"#)).unwrap()
    }
    const FEE_CFG: &str = ", relay_fee = { min_amount = 1, min_microalgo_value = { \"1001\" = 1000 }, targets = { \"1003\" = [\"ping(uint64)void\"] } }";

    async fn adapter(w: World) -> (AlgorandAdapter, Arc<M<World>>) {
        let w = Arc::new(M::new(w));
        let url = serve(w.clone()).await;
        let a = AlgorandAdapter::new(&cfg(&url, FEE_CFG), &[lane0()]).unwrap();
        a.start_check().await.unwrap();
        (a, w)
    }
    fn group(b: &Built) -> Group {
        serde_json::from_value(b.meta.clone()).unwrap()
    }
    fn last_sim(w: &Arc<M<World>>) -> Mp {
        w.lock().unwrap().sims.last().cloned().unwrap()
    }

    // ------------------------------------------------------------ tests

    /// Every vector row decodes, re-encodes byte for byte and digests as the vectors say; anything else is refused.
    #[test]
    fn algorand_metaop_decode_vectors() {
        let vv = v();
        let rows = vv["metaops"]["vectors"].as_array().unwrap();
        assert!(rows.len() >= 33);
        for r in rows {
            let enc = hx(&r["encoding"]);
            let op = MetaOp::decode(&enc).unwrap_or_else(|e| panic!("{}: {e:#}", r["name"]));
            let f = &r["fields"];
            assert_eq!(op.network.to_vec(), hx(&f["network"]));
            assert_eq!(op.contract.to_vec(), hx(&f["contract"]));
            assert_eq!(op.contract, app_address(f["contractApp"].as_u64().unwrap()), "{}", r["name"]);
            assert_eq!(u64::from(op.op), f["op"].as_u64().unwrap());
            assert_eq!((u64::from(op.from.kind), op.from.id.to_vec()), (f["from"]["kind"].as_u64().unwrap(), hx(&f["from"]["id"])));
            assert_eq!((u64::from(op.to.kind), op.to.id.to_vec()), (f["to"]["kind"].as_u64().unwrap(), hx(&f["to"]["id"])));
            if let Some(a) = f["from"]["address"].as_str() {
                assert_eq!(op.from.display(), a);
            }
            assert_eq!(op.relayer.to_vec(), hx(&f["relayer"]));
            assert_eq!(op.amount.to_string(), f["amount"].as_str().unwrap());
            assert_eq!((op.pay_ref.to_vec(), op.lane.to_vec(), op.extra.to_vec()), (hx(&f["pay_ref"]), hx(&f["lane"]), hx(&f["extra"])));
            assert_eq!((op.nonce, op.valid_until), (f["nonce"].as_u64().unwrap(), f["valid_until"].as_u64().unwrap()));
            assert_eq!(op.encode(), enc, "{}", r["name"]);
            assert_eq!(op.digest().to_vec(), hx(&r["digest"]), "{}", r["name"]);
            assert_eq!(op.arc4().len(), METAOP_LEN);
            assert!(MetaOp::decode(&enc[..enc.len() - 1]).is_err(), "truncated");
            assert!(MetaOp::decode(&[&enc[..], &[0]].concat()).is_err(), "trailing byte");
            assert!(MetaOp::decode(&enc[1..]).is_err(), "label");
            let mut k = enc.clone();
            k[15 + 65] = 2; // from.kind
            assert!(MetaOp::decode(&k).is_err(), "holder kind 2");
        }
        assert_eq!(op_of("pay_ua_ed25519_u128_max").amount, u128::MAX, "Review Focus 5: 2^128 - 1 round-trips");
        let sel = |s: &str| h(&selector(s));
        assert_eq!(sel(&format!("relay(uint64,{METAOP_ABI},byte[])void")), "0x4af7ebf5", "the executor's next-call selector");
        assert_eq!(h(&selector(&format!("mtx_add_key({METAOP_ABI},byte[],(uint16,byte[]),byte[])void"))), h(&hx(&vv["routerCall"]["selector"])));
    }

    /// CTR-MTX-26: pay_ref = metaPayId(salt, meta), lane = payLane(pay_ref), nonce 0; the cap is Task 11's measured
    /// MAX_PAY_META_BYTES (507, the 1,024 B log limit), below `max_pay_meta_bytes`.
    #[test]
    fn algorand_pay_meta_job_checks_commitment() {
        let rows: Vec<Value> = serde_json::from_str(PAYMETA).unwrap();
        let mut n = 0;
        for r in v()["metaops"]["vectors"].as_array().unwrap().iter().filter(|r| r["paymetaRow"].is_string()) {
            let pm = rows.iter().find(|x| x["name"] == r["paymetaRow"]).unwrap();
            let (salt, meta) = (hx(&pm["salt"]), hx(&pm["meta"]));
            let op = MetaOp::decode(&hx(&r["encoding"])).unwrap();
            let o = json!({"kind": "pay_meta", "salt": h(&salt), "meta": h(&meta)});
            let got = entry(&pol(), Some(&exec()), &op, &o);
            if meta.len() <= MAX_PAY_META_BYTES {
                assert_eq!(got.unwrap(), Entry::PayMeta { salt: salt.clone().try_into().unwrap(), meta }, "{}", r["name"]);
            } else {
                assert!(got.unwrap_err().to_string().contains("507"), "{}", r["name"]);
            }
            n += 1;
        }
        assert_eq!(n, 6);
        let base = op_of("pay_meta_note_utf8");
        let at = |len: usize, max: usize| {
            let meta = vec![0x5a; len];
            let id = meta_pay_id(&[3; 32], &meta);
            let op = MetaOp { pay_ref: id, lane: pay_lane(&id), ..base.clone() };
            let p = RelayFeePolicy { params: crate::config::RelayParams { max_pay_meta_bytes: max, ..Default::default() }, ..pol() };
            entry(&p, None, &op, &json!({"kind": "pay_meta", "salt": h(&[3; 32]), "meta": h(&meta)}))
        };
        assert!(at(MAX_PAY_META_BYTES, 2048).is_ok());
        assert!(at(MAX_PAY_META_BYTES + 1, 2048).is_err(), "above the measured fit");
        assert!(at(100, 99).is_err() && at(99, 99).is_ok(), "a smaller max_pay_meta_bytes binds");
        let pm = rows.iter().find(|x| x["name"] == "note_utf8").unwrap();
        let o = json!({"kind": "pay_meta", "salt": pm["salt"], "meta": pm["meta"]});
        let bad = |op: &MetaOp, o: &Value| entry(&pol(), None, op, o).is_err();
        assert!(!bad(&base, &o));
        let mut j = o.clone();
        j["meta"] = json!(format!("{}00", pm["meta"].as_str().unwrap()));
        assert!(bad(&base, &j), "meta does not hash to pay_ref");
        j = o.clone();
        j["salt"] = json!(h(&[0; 31]));
        assert!(bad(&base, &j), "salt is 32 bytes");
        assert!(bad(&MetaOp { nonce: 1, ..base.clone() }, &o), "nonce 1");
        assert!(bad(&MetaOp { lane: [1; 32], ..base.clone() }, &o), "another lane");
        assert!(bad(&MetaOp { to: holder(0, app_address(DEX)), ..base.clone() }, &o), "never pay the DEX");
    }

    /// Spec §4.8 / §2 rows 8–14: `ref` of every relayRefs row from the exact call bytes and the payment's `extra`; a job
    /// binds to the router as relayer and marker, the call, and its target's allowed method.
    #[test]
    fn algorand_relay_fee_job_checks_ref() {
        let vv = v();
        for r in vv["relayRefs"].as_array().unwrap() {
            let call = hx(&r["call"]);
            let (t, args) = parse_router_call(&call).unwrap();
            assert_eq!(t, r["targetApp"].as_u64().unwrap());
            assert_eq!(args, r["args"].as_array().unwrap().iter().map(hx).collect::<Vec<_>>());
            assert_eq!(router_call(t, &args), call);
            assert_eq!(app_address(t).to_vec(), hx(&r["target"]));
            let rf = relay_ref(&network(), &app_address(t), &call, &b32(&r["salt"]));
            assert_eq!((rf.to_vec(), pay_lane(&rf).to_vec()), (hx(&r["ref"]), hx(&r["lane"])), "{}", r["name"]);
            let op = op_of(r["payment"].as_str().unwrap());
            let o = json!({"kind": "relay_fee", "extra": {"call": r["call"]}, "ref": r["ref"]});
            assert_eq!(entry(&pol(), Some(&exec()), &op, &o).unwrap(), Entry::Fee { target_app: t, args: args.clone() }, "{}", r["name"]);
            let bad = |op: &MetaOp, o: &Value| entry(&pol(), Some(&exec()), op, o).unwrap_err().to_string();
            let mut j = o.clone();
            j["ref"] = json!(h(&[9; 32]));
            assert!(bad(&op, &j).contains("op.ref"));
            assert!(bad(&MetaOp { extra: [0; 32], ..op.clone() }, &o).contains("not bound"), "salt = the payment's extra");
            assert!(bad(&MetaOp { relayer: [0; 32], ..op.clone() }, &o).contains("relayer"));
            assert!(entry(&RelayFeePolicy { router: None, ..pol() }, Some(&exec()), &op, &o).is_err(), "no router configured");
            assert!(entry(&pol(), None, &op, &o).is_err(), "executor not derived yet");
            j = o.clone();
            j["extra"]["call"] = json!(h(&call[..call.len() - 1]));
            assert!(entry(&pol(), Some(&exec()), &op, &j).is_err(), "truncated call");
            j["extra"]["call"] = json!(h(&[&call[..], &[0]].concat()));
            assert!(entry(&pol(), Some(&exec()), &op, &j).is_err(), "trailing byte");
            j = o.clone();
            j["extra"]["on_completion"] = json!("clear_state");
            assert!(bad(&op, &j).contains("on_completion"), "unknown extra key");
            assert!(entry(&RelayFeePolicy { targets: BTreeMap::new(), ..pol() }, Some(&exec()), &op, &o).unwrap_err().to_string().contains("allowed"));
            let other = RelayFeePolicy { targets: BTreeMap::from([(TARGET, vec![selector("ping(uint64)void")])]), ..pol() };
            assert!(entry(&other, Some(&exec()), &op, &o).unwrap_err().to_string().contains("method"));
        }
        // payee rules (rule 12): never the executor, an app of the deployment or a token; open mode = the router
        let t = target_op(app_address(TOKEN), 4, holder(1, [0x11; 32]), holder(0, [0x44; 32]));
        let call = transfer_call(&t);
        for to in [holder(0, exec().address), holder(0, app_address(TOKEN)), holder(0, app_address(DEX)), holder(0, app_address(MANDATE)),
                   holder(0, app_address(ACCOUNT))] {
            let op = fee_op(&call, [5; 32], Some(to));
            assert!(entry(&pol(), Some(&exec()), &op, &fee_job(&call, &op, json!({}))).is_err(), "{}", to.display());
        }
        let op = fee_op(&call, [5; 32], None);
        assert!(entry(&pol(), Some(&exec()), &op, &fee_job(&call, &op, json!({}))).is_ok(), "open mode");
        // rule 13 and the allowlist, before any RPC
        let refused = |call: Vec<u8>| {
            let op = fee_op(&call, [5; 32], None);
            entry(&pol(), Some(&exec()), &op, &fee_job(&call, &op, json!({}))).unwrap_err().to_string()
        };
        assert!(refused(router_call(ROUTER, &[selector("x()void").to_vec()])).contains("router"));
        assert!(refused(router_call(0, &[selector("x()void").to_vec()])).contains("app 0"));
        assert!(refused(router_call(ACCOUNT, &[selector("add_key_native((uint16,byte[]),byte[])void").to_vec(), vec![0, 1], vec![0, 0]])).contains("add_key_native"));
        assert!(refused(router_call(TOKEN, &[selector(&format!("mtx_trade({METAOP_ABI},byte[],(uint64,uint64,uint128,uint128,byte[32],uint64))void")).to_vec()])).contains("allowed"));
        assert!(refused(router_call(ACCOUNT, &[selector("verify(uint8,byte[32],byte[32],byte[])bool").to_vec()])).contains("allowed"));
        assert!(refused(router_call(TOKEN, &[selector(&format!("mtx_transfer({METAOP_ABI},byte[])void")).to_vec()])).contains("arguments"), "argument count");
        assert!(refused(router_call(9999, &[selector("ping(uint64)void").to_vec()])).contains("allowed"), "unlisted app");
    }

    /// Rule 13 before the group runs: a missing target app or app 0 is refused, the target transaction is always NoOp
    /// (no `apan`), and a job cannot ask for another OnCompletion (unknown `op.extra` keys are refused).
    #[tokio::test]
    async fn relay_fee_target_app_missing_or_clearstate_refused() {
        let ping = router_call(TARGET, &[selector("ping(uint64)void").to_vec(), 9u64.to_be_bytes().to_vec()]);
        let mut w = world();
        w.apps.remove(&TARGET);
        let (a, _) = adapter(w).await;
        let op = fee_op(&ping, [5; 32], None);
        let e = a.build(&job(fee_job(&ping, &op, json!({}))), 0).await.unwrap_err();
        assert!(matches!(&e, SimError::Revert(m) if m.contains("missing")), "{e:?}");
        for extra in [json!({"on_completion": "clear_state"}), json!({"on_complete": 3}), json!({"route": "router"})] {
            let e = a.build(&job(fee_job(&ping, &op, extra.clone())), 0).await.unwrap_err();
            assert!(matches!(&e, SimError::Revert(m) if m.contains("op.extra")), "{extra}: {e:?}");
        }
        let (a, w) = adapter(world()).await;
        let b = a.build(&job(fee_job(&ping, &op, json!({}))), 0).await.unwrap();
        let g = group(&b);
        let t = g.txs.iter().position(|t| matches!(t, Tx::Call { executor: true, .. })).unwrap();
        assert_eq!(g.main, t + 1, "the router call right after the target");
        let sent = txns_of(&last_sim(&w));
        let tm = sent[t].get("txn").unwrap();
        assert!(tm.get("apan").is_none() && tm.get("apid").and_then(Mp::u64) == Some(TARGET), "NoOp on the target");
        assert!(sent[t].get("lsig").is_some(), "the executor signs by its program");
        assert_eq!(tm.get("snd").and_then(Mp::bytes), Some(&exec().address[..]));
        assert!(tm.get("fee").is_none(), "the executor pays no fee");
    }

    /// Spec §5 "group with the exact MBR payment and budget calls": the MBR payment = the token's `mbr_needed` + the
    /// account app's `verify_mbr` (a UA's first op), budget calls carry every resource simulate found unnamed, and the
    /// pooled fee is one min fee per transaction and per inner transaction; the last simulate runs that exact group
    /// with unnamed resources refused.
    #[tokio::test]
    async fn group_has_exact_mbr_payment_and_budget_calls() {
        let mut w = world();
        let acct = [0x99; 32];
        let rec = [&b"s"[..], &[1], &[0x11; 32]].concat();
        w.unnamed = json!({"accounts": [algorand_address(&acct)],
                           "boxes": [{"app": TOKEN, "name": base64::engine::general_purpose::STANDARD.encode(b"l-lane-box")},
                                     {"app": ACCOUNT, "name": base64::engine::general_purpose::STANDARD.encode(&rec)}],
                           "extra-box-refs": 1});
        let (a, w) = adapter(w).await;
        let op = MetaOp { from: holder(1, [0x11; 32]), valid_until: far(), ..op_of("pay_ua_ed25519_u128_max") };
        let auth = [vec![1], vec![0x22; 96]].concat();
        let b = a.build(&job(o_op(&op, &auth, json!({}))), 0).await.unwrap();
        let g = group(&b);
        assert_eq!(g.txs[0], Tx::Pay { to: app_address(TOKEN), amount: 47_400 + 76_100 }, "token part + the record's lazy open");
        assert_eq!(g.main, 1);
        let Tx::Call { app, args, executor: false, .. } = &g.txs[1] else { panic!() };
        assert_eq!((*app, args.len()), (TOKEN, 4));
        assert_eq!(args[0], selector(&format!("mtx_pay({METAOP_ABI},byte[],address)void")).to_vec());
        assert_eq!((args[1].clone(), args[2].clone(), args[3].clone()), (op.arc4(), abi_bytes(&auth), lane_pk().to_vec()));
        assert_eq!(g.txs.len(), 3, "one budget call carries 5 references");
        let Tx::Call { app, args, accounts, apps, boxes, executor: false } = &g.txs[2] else { panic!() };
        assert_eq!((*app, args.is_empty()), (TOKEN, true), "a bare budget call");
        assert_eq!((accounts.clone(), apps.clone()), (vec![acct], vec![ACCOUNT]));
        assert_eq!(boxes.clone(), vec![(0, b"l-lane-box".to_vec()), (1, rec.clone()), (0, vec![])]);
        assert_eq!(g.fee, 1_000 * (3 + 4), "3 transactions + 4 inner");
        assert_eq!(g.mbr, 123_500);
        let last = last_sim(&w);
        assert!(matches!(last.get("allow-unnamed-resources"), None | Some(Mp::Bool(false))), "the exact group names every resource");
        let sent = txns_of(&last);
        assert_eq!(sent.len(), 3);
        assert_eq!(sent[1].get("txn").and_then(|t| t.get("fee")).and_then(Mp::u64), Some(7_000));
        assert_eq!(sent[0].get("txn").and_then(|t| t.get("amt")).and_then(Mp::u64), Some(123_500));
        // a native payer's own wallet signature: no account record, no MBR when nothing is new
        let mut w2 = world();
        w2.views.insert(selector(&format!("mbr_needed({METAOP_ABI})uint64")), 0u64.to_be_bytes().to_vec());
        let (a2, _) = adapter(w2).await;
        let op2 = MetaOp { valid_until: far(), ..op_of("pay") };
        let g2 = group(&a2.build(&job(o_op(&op2, &auth_of("pay"), json!({}))), 0).await.unwrap());
        assert_eq!((g2.txs.len(), g2.main, g2.mbr), (1, 0, 0), "no payment, no budget call");
        // router group: [MBR → router][MBR → target][target, executor][relay]; the payer's record opens in the target
        let (a3, w3) = adapter(world()).await;
        let t = target_op(app_address(TOKEN), 4, holder(1, [0x11; 32]), holder(0, [0x44; 32]));
        let call = transfer_call(&t);
        let op3 = fee_op(&call, [5; 32], None);
        let g3 = group(&a3.build(&job(fee_job(&call, &op3, json!({}))), 0).await.unwrap());
        assert_eq!(g3.txs[0], Tx::Pay { to: app_address(ROUTER), amount: 47_400 }, "the record part is 0: the target opens it");
        assert_eq!(g3.txs[1], Tx::Pay { to: app_address(TOKEN), amount: 47_400 + 76_100 });
        assert!(matches!(&g3.txs[2], Tx::Call { app: TOKEN, executor: true, .. }));
        assert!(matches!(&g3.txs[3], Tx::Call { app: ROUTER, executor: false, .. }) && g3.main == 3);
        let Tx::Call { args, .. } = &g3.txs[3] else { panic!() };
        assert_eq!(args[0], h2(&selector(&format!("relay(uint64,{METAOP_ABI},byte[])void"))));
        assert_eq!((args[1].clone(), args[2].clone()), (TOKEN.to_be_bytes().to_vec(), op3.arc4()));
        assert_eq!(g3.fee, 1_000 * (4 + 4));
        // the router's MBR query asked for the open payee: the lane
        let q = w3.lock().unwrap().sims.iter().filter_map(|s| {
            let t = txns_of(s);
            let a = t.first()?.get("txn")?.get("apaa")?.arr().to_vec();
            (t.len() == 1 && a[0].bytes() == Some(&selector(&format!("mbr_needed({METAOP_ABI})uint64"))[..])).then(|| a[1].bytes().unwrap().to_vec())
        }).collect::<Vec<_>>();
        assert!(q.iter().any(|o| MetaOp::from_arc4(o).unwrap().to == holder(0, lane_pk())), "mbr_needed with to = the lane");
        // too many unnamed resources for one group of 16
        let mut w4 = world();
        w4.unnamed = json!({"accounts": (0..80u8).map(|i| algorand_address(&[i; 32])).collect::<Vec<_>>()});
        let (a4, _) = adapter(w4).await;
        let e = a4.build(&job(o_op(&op, &auth, json!({}))), 0).await.unwrap_err();
        assert!(matches!(&e, SimError::Revert(m) if m.contains("16")), "{e:?}");
    }
    fn h2(b: &[u8]) -> Vec<u8> {
        b.to_vec()
    }

    /// T15 fix 1 / note 1: program = prefix ‖ router id ‖ suffix ‖ 20 01 salt; its address equals the vector (the SDK's
    /// LogicSig address) and is off-curve; salts 0 and 1 of router 1002 are on-curve; start_check refuses an executor()
    /// that differs or an on-curve salt.
    #[tokio::test]
    async fn executor_address_matches_contract() {
        let e = &v()["executor"];
        let x = Executor::new(ROUTER, 2).unwrap();
        assert_eq!(x.program, hx(&e["program"]));
        assert_eq!(algorand_address(&x.address), e["address"].as_str().unwrap());
        assert_eq!(x.address, program_address(&x.program));
        assert!(!on_curve(&x.address));
        for s in [0u8, 1] {
            assert!(on_curve(&Executor::new(ROUTER, s).unwrap().address), "salt {s}");
        }
        let key: [u8; 32] = lane0().public_key().try_into().unwrap();
        assert!(on_curve(&key), "a real ed25519 key is on the curve");
        let mut w = world();
        w.views.insert(selector("executor()address"), [1u8; 32].to_vec());
        let ww = Arc::new(M::new(w));
        let url = serve(ww.clone()).await;
        let a = AlgorandAdapter::new(&cfg(&url, FEE_CFG), &[lane0()]).unwrap();
        assert!(a.start_check().await.unwrap_err().to_string().contains("executor"));
        ww.lock().unwrap().views.insert(selector("executor()address"), Executor::new(ROUTER, 0).unwrap().address.to_vec());
        ww.lock().unwrap().apps.insert(ROUTER, app_json("RelayFee", json!([g_uint("salt", 0)])));
        assert!(a.start_check().await.unwrap_err().to_string().contains("on-curve"));
    }

    /// R11 / §4.9: a deployed approval (or clear) program whose sha512_256 differs from artifacts.json halts the chain.
    #[tokio::test]
    async fn start_check_approval_hash_mismatch_halts() {
        let (a, w) = adapter(world()).await;
        for (id, program) in [(TOKEN, "Token"), (ACCOUNT, "Account"), (MANDATE, "Mandate"), (DEX, "Dex"), (ROUTER, "RelayFee")] {
            let mut x = w.lock().unwrap().apps[&id].clone();
            let mut p = base64::engine::general_purpose::STANDARD.decode(x["params"]["approval-program"].as_str().unwrap()).unwrap();
            p[3] ^= 1;
            x["params"]["approval-program"] = json!(base64::engine::general_purpose::STANDARD.encode(&p));
            let old = w.lock().unwrap().apps.insert(id, x).unwrap();
            let e = a.start_check().await.unwrap_err().to_string();
            assert!(e.contains("halted") && e.contains(program.to_lowercase().as_str()), "{program}: {e}");
            w.lock().unwrap().apps.insert(id, old);
        }
        a.start_check().await.unwrap();
        w.lock().unwrap().apps.remove(&MANDATE);
        assert!(a.start_check().await.unwrap_err().to_string().contains("missing app id"));
        w.lock().unwrap().apps.insert(DEX, app_json("Dex", json!([g_uint("router_app", 77)])));
        w.lock().unwrap().apps.insert(MANDATE, app_json("Mandate", json!([g_uint("account_app", ACCOUNT)])));
        assert!(a.start_check().await.unwrap_err().to_string().contains("router_app"), "the DEX was created with another router");
    }

    #[tokio::test]
    async fn start_check_genesis_mismatch_errors() {
        let (a, w) = adapter(world()).await;
        w.lock().unwrap().genesis = [1; 32];
        assert!(a.start_check().await.unwrap_err().to_string().contains("genesis"));
        let mut op = op_of("pay");
        op.valid_until = far();
        op.network = [1; 32];
        assert!(a.build(&job(o_op(&op, &auth_of("pay"), json!({}))), 0).await.is_err());
    }

    #[tokio::test]
    async fn start_check_lane_below_min_balance_errors() {
        let (a, w) = adapter(world()).await;
        w.lock().unwrap().accounts.insert(algorand_address(&lane_pk()), (99_999, 100_000));
        assert!(a.start_check().await.unwrap_err().to_string().contains("minimum balance"));
        w.lock().unwrap().accounts.remove(&algorand_address(&lane_pk()));
        assert!(a.start_check().await.unwrap_err().to_string().contains("minimum balance"), "an unfunded lane");
        w.lock().unwrap().accounts.insert(algorand_address(&lane_pk()), (10_000_000, 100_000));
        a.start_check().await.unwrap();
        w.lock().unwrap().accounts.remove(&algorand_address(&app_address(ROUTER)));
        assert!(a.start_check().await.unwrap_err().to_string().contains("router"), "note 2: an unfunded router address");
    }

    /// Review Focus 1: LastValid ≤ the last round whose estimated time ≤ valid_until (seconds), the round time read
    /// from algod's block timestamps, never assumed; at most 1,000 rounds (MaxTxnLife).
    #[tokio::test]
    async fn algorand_last_valid_within_valid_until() {
        let ts = 1_800_000_000u64;
        // 100 rounds in 280 s: 2.8 s per round
        assert_eq!(last_valid(1_000, 1_000, ts, 100, 280, ts + 28).unwrap(), 1_010);
        assert_eq!(last_valid(1_000, 1_000, ts, 100, 280, ts + 27).unwrap(), 1_009);
        assert_eq!(last_valid(1_000, 1_000, ts, 100, 280, ts + 1).unwrap(), 1_000);
        assert_eq!(last_valid(1_000, 1_000, ts, 100, 280, ts + 10_000_000).unwrap(), 2_000, "MaxTxnLife");
        assert_eq!(last_valid(1_000, 1_000, ts, 100, 0, ts + 5).unwrap(), 2_000, "rounds without time: no time bound");
        assert!(last_valid(1_000, 1_000, ts, 100, 280, ts - 1).is_err(), "already past");
        assert!(last_valid(1_002, 1_000, ts, 100, 280, ts + 3).is_err(), "expires before the first valid round");
        // through sign(): the mocked blocks 4,900 / 5,000 are 300 s apart (3 s per round)
        let (a, _) = adapter(world()).await;
        let op = MetaOp { valid_until: 1_800_000_000 + 5_000 * 3 + 400, ..op_of("pay") };
        let b = Built { job_id: 1, body: vec![], valid_until: op.valid_until,
                        meta: serde_json::to_value(Group { txs: vec![Tx::Pay { to: [5; 32], amount: 1 }], main: 0, fee: 1_000, mbr: 1 }).unwrap() };
        let s = a.sign(b, 0, 5_000).await.unwrap();
        let t = mp_decode(&s.raw).unwrap();
        let t = t.get("txn").unwrap();
        assert_eq!((t.get("fv").and_then(Mp::u64), t.get("lv").and_then(Mp::u64)), (Some(5_000), Some(5_133)));
    }

    #[test]
    fn unknown_job_kind_is_refused() {
        let op = op_of("pay");
        for k in [json!("pay"), json!("wrapper"), json!("PAY_META"), json!(7), json!(true), json!({})] {
            assert!(entry(&pol(), Some(&exec()), &op, &json!({"kind": k})).is_err(), "{k}");
        }
        assert!(entry(&pol(), Some(&exec()), &op, &json!({"salt": h(&[0; 32])})).is_err(), "pay-meta without its kind");
        assert_eq!(entry(&pol(), Some(&exec()), &op, &json!({})).unwrap(), Entry::Pay);
    }

    /// The hand-encoded canonical msgpack, `"TX"` ids, the group id and the signatures equal py-algorand-sdk's.
    #[test]
    fn tx_matches_algosdk() {
        let t: Value = serde_json::from_str(TXV).unwrap();
        let seed = b32(&t["seed"]);
        let lane = LocalSigner::new(crate::signer::Curve::Ed25519, &seed).unwrap();
        let pk: [u8; 32] = lane.public_key().try_into().unwrap();
        assert_eq!(algorand_address(&pk), t["lane"].as_str().unwrap());
        let x = Executor::new(t["router"].as_u64().unwrap(), 2).unwrap();
        assert_eq!(algorand_address(&x.address), t["executor"].as_str().unwrap());
        let alice = crate::addresses::algorand_key(t["alice"].as_str().unwrap()).unwrap();
        let token = t["token"].as_u64().unwrap();
        let g = Group {
            txs: vec![
                Tx::Pay { to: app_address(t["router"].as_u64().unwrap()), amount: 18_900 },
                Tx::Call { app: t["target"].as_u64().unwrap(), args: t["targetArgs"].as_array().unwrap().iter().map(hx).collect(), accounts: vec![],
                           apps: vec![], boxes: vec![], executor: true },
                Tx::Call { app: t["router"].as_u64().unwrap(), args: t["relayArgs"].as_array().unwrap().iter().map(hx).collect(), accounts: vec![alice],
                           apps: vec![token], boxes: vec![(1, [&b"l"[..], &[1; 32]].concat()), (0, vec![])], executor: false },
                Tx::Call { app: token, args: vec![], accounts: vec![], apps: vec![], boxes: vec![(0, [&b"u"[..], &[2; 32]].concat())], executor: false },
            ],
            main: 2, fee: 7_000, mbr: 18_900,
        };
        let chain = Chain { gen: t["genesisId"].as_str().unwrap().into(), gh: b32(&t["genesisHash"]) };
        let (raw, ids) = sign_group(&g, &chain, 1_000, 2_000, &|m| lane.sign(m), &pk, Some(&x)).unwrap();
        for (i, tx) in t["txns"].as_array().unwrap().iter().enumerate() {
            assert_eq!(h(&ids[i]), tx["txid"].as_str().unwrap(), "txid {i}");
        }
        assert_eq!(h(&group_id(&group_txids(&g, &chain, 1_000, 2_000, &pk, Some(&x)))), t["group"].as_str().unwrap());
        assert_eq!(h(&raw), t["raw"].as_str().unwrap());
        // the decoder reads what the encoder wrote, canonically
        let mut at = 0;
        for tx in t["txns"].as_array().unwrap() {
            let s = hx(&tx["signed"]);
            assert_eq!(mp_encode(&mp_decode(&s).unwrap()), s);
            at += s.len();
        }
        assert_eq!(at, raw.len());
    }

    #[test]
    fn relay_fee_config_must_parse() {
        let c = |p: &str| cfg("http://x", p);
        RelayFeePolicy::from_cfg(&c(FEE_CFG)).unwrap();
        for bad in [
            ", relay_fee = { router = \"1002\" }",
            ", relay_fee = { min_microalgo_value = { \"9\" = 1 } }",
            ", relay_fee = { min_microalgo_value = { \"1001\" = -1 } }",
            ", relay_fee = { targets = { \"1003\" = [] } }",
            ", relay_fee = { targets = { \"1003\" = [\"add_key_native((uint16,byte[]),byte[])void\"] } }",
            ", relay_fee = { targets = { \"1001\" = [\"ping(uint64)void\"] } }",
            ", relay_fee = { targets = { \"x\" = [\"ping(uint64)void\"] } }",
            ", relay_fee = { targets = { \"1003\" = [\"ping\"] } }",
            ", relay_fee = { targets = [\"1003\"] }",
        ] {
            assert!(RelayFeePolicy::from_cfg(&c(bad)).is_err(), "{bad}");
        }
        let mut x = c("");
        x.params.remove("account_app");
        assert!(RelayFeePolicy::from_cfg(&x).unwrap_err().to_string().contains("account_app"));
        x = c("");
        x.params.insert("dex_app".into(), toml::Value::Integer(TOKEN as i64));
        assert!(RelayFeePolicy::from_cfg(&x).is_err(), "one app in two roles");
        x = c("");
        x.params.insert("mandate_app".into(), "1005".into());
        assert!(RelayFeePolicy::from_cfg(&x).is_err(), "an app id is a TOML integer");
        x = c("");
        x.tokens[0].address = algorand_address(&[3; 32]);
        assert!(RelayFeePolicy::from_cfg(&x).is_err(), "a token is an app id");
    }

    /// T17 fee-covers-cost: a fee that is the node's (open mode or bound to the lane) must be worth, at
    /// `min_microalgo_value`, the group's fee + every MBR payment (no resend: a group lands once or costs nothing).
    #[tokio::test]
    async fn quote_covers_fees_and_mbr() {
        let t = target_op(app_address(TOKEN), 4, holder(1, [0x11; 32]), holder(0, [0x44; 32]));
        let call = transfer_call(&t);
        let quote = 8_000u128 + 47_400 + 47_400 + 76_100;
        let (a, _) = adapter(world()).await;
        for (amount, ok) in [(quote.div_ceil(1_000), true), (quote / 1_000 - 1, false)] {
            let op = MetaOp { amount, ..fee_op(&call, [5; 32], None) };
            let r = a.build(&job(fee_job(&call, &op, json!({}))), 0).await;
            assert_eq!(r.is_ok(), ok, "{amount}: {r:?}");
            if !ok {
                assert!(matches!(r, Err(SimError::Revert(m)) if m.contains("below")));
            }
        }
        // bound to the lane: priced; bound elsewhere: sponsored only with relay_bound_payee
        let op = MetaOp { amount: 1, ..fee_op(&call, [5; 32], Some(holder(0, lane_pk()))) };
        assert!(a.build(&job(fee_job(&call, &op, json!({}))), 0).await.is_err());
        let op = MetaOp { amount: 1, ..fee_op(&call, [5; 32], Some(holder(0, [0x55; 32]))) };
        assert!(matches!(a.build(&job(fee_job(&call, &op, json!({}))), 0).await, Err(SimError::Revert(m)) if m.contains("relay_bound_payee")));
        // a failing group is refused with its message; an overspent lane is the lane's problem (retry)
        let mut w = world();
        w.fail = Some("logic eval error: insufficient balance".into());
        let (a, ww) = adapter(w).await;
        let op = MetaOp { amount: 1_000, ..fee_op(&call, [5; 32], None) };
        assert!(matches!(a.build(&job(fee_job(&call, &op, json!({}))), 0).await, Err(SimError::Revert(m)) if m.contains("insufficient balance")));
        ww.lock().unwrap().fail = Some("overspend (account X, data {...})".into());
        assert!(matches!(a.build(&job(fee_job(&call, &op, json!({}))), 0).await, Err(SimError::Transport(_))));
    }

    /// Note 9 / lessons 2, 7: static target checks before any simulate.
    #[test]
    fn relay_fee_target_static_checks() {
        let lane = lane_pk();
        let now = now();
        let tc = |t: u64, args: &[Vec<u8>], carries: usize| {
            target_check(&pol(), &exec(), &fee_op(&router_call(t, args), [5; 32], None), t, args, &lane, carries, now)
        };
        let tsel = selector(&format!("mtx_transfer({METAOP_ABI},byte[])void")).to_vec();
        let base = target_op(app_address(TOKEN), 4, holder(1, [0x11; 32]), holder(0, [0x44; 32]));
        assert!(tc(TOKEN, &[tsel.clone(), base.arc4(), abi_bytes(&[1; 70])], 0).is_ok());
        for (bad, why) in [
            (MetaOp { relayer: lane, ..base.clone() }, "relayer"),
            (MetaOp { valid_until: now + 60, ..base.clone() }, "120"),
            (MetaOp { network: [1; 32], ..base.clone() }, "network"),
            (MetaOp { contract: app_address(TOKEN_B), ..base.clone() }, "contract"),
            (MetaOp { to: holder(0, exec().address), ..base.clone() }, "never pay"),
            (MetaOp { to: holder(0, app_address(DEX)), ..base.clone() }, "never pay"),
        ] {
            let e = tc(TOKEN, &[tsel.clone(), bad.arc4(), abi_bytes(&[1; 70])], 0).unwrap_err().to_string();
            assert!(e.contains(why), "{why}: {e}");
        }
        assert!(tc(TOKEN, &[tsel.clone(), base.arc4()[1..].to_vec(), abi_bytes(&[1; 70])], 0).is_err(), "short op");
        assert!(tc(TOKEN, &[tsel.clone(), base.arc4(), vec![0, 9, 1]], 0).is_err(), "bad byte[]");
        // DEX: orders open or bound to this lane, configured tokens, not expiring; carried auths = empty auths
        let order = |sell: u64, buy: u64, relayer: [u8; 32], expiry: u64| {
            [sell.to_be_bytes().to_vec(), buy.to_be_bytes().to_vec(), 100u128.to_be_bytes().to_vec(), 50u128.to_be_bytes().to_vec(), relayer.to_vec(),
             expiry.to_be_bytes().to_vec()].concat()
        };
        let leg = |t: u64| MetaOp { relayer: app_address(DEX), to: holder(0, app_address(DEX)), op: 1, ..target_op(app_address(t), 1, holder(1, [7; 32]), holder(0, [0; 32])) };
        let dsel = selector(&format!("settle({ORDER_ABI},{METAOP_ABI},byte[],{ORDER_ABI},{METAOP_ABI},byte[],uint64[4])void")).to_vec();
        let mbr = [16_100u64, 16_100, 0, 28_500].iter().flat_map(|x| x.to_be_bytes()).collect::<Vec<u8>>();
        let settle = |oa: Vec<u8>, ob: Vec<u8>, aa: Vec<u8>| vec![dsel.clone(), oa, leg(TOKEN).arc4(), abi_bytes(&aa), ob, leg(TOKEN_B).arc4(), abi_bytes(&[1; 70]), mbr.clone()];
        let ok = settle(order(TOKEN, TOKEN_B, [0; 32], far()), order(TOKEN_B, TOKEN, lane, far()), vec![1; 70]);
        let i = tc(DEX, &ok, 0).unwrap();
        assert_eq!(i.dex_mbr, 60_700);
        assert!(tc(DEX, &settle(order(TOKEN, TOKEN_B, [0; 32], far()), order(TOKEN_B, TOKEN, lane, far()), vec![]), 1).is_ok(), "a carried auth");
        assert!(tc(DEX, &settle(order(TOKEN, TOKEN_B, [0; 32], far()), order(TOKEN_B, TOKEN, lane, far()), vec![]), 0).is_err(), "no carry");
        assert!(tc(DEX, &ok, 1).is_err(), "a carry without an empty auth");
        assert!(tc(DEX, &settle(order(TOKEN, TOKEN_B, [9; 32], far()), order(TOKEN_B, TOKEN, lane, far()), vec![1; 70]), 0).is_err(), "bound to another relayer");
        assert!(tc(DEX, &settle(order(TOKEN, 4242, [0; 32], far()), order(4242, TOKEN, lane, far()), vec![1; 70]), 0).is_err(), "unconfigured token");
        assert!(tc(DEX, &settle(order(TOKEN, TOKEN_B, [0; 32], now + 30), order(TOKEN_B, TOKEN, lane, far()), vec![1; 70]), 0).is_err(), "order expiry margin");
        // mandate open: the terms' expiry gets the margin too
        let osel = selector(&format!("mtx_mandate_open(uint64,{METAOP_ABI},byte[],{TERMS_ABI},uint64)void")).to_vec();
        let fund = MetaOp { relayer: app_address(MANDATE), to: holder(0, app_address(MANDATE)), ..target_op(app_address(TOKEN), 0, holder(1, [7; 32]), holder(0, [0; 32])) };
        let terms = |expiry: u64| [vec![1u8], vec![8; 32], vec![0], vec![9; 32], 100u128.to_be_bytes().to_vec(), 250u128.to_be_bytes().to_vec(),
                                    86_400u64.to_be_bytes().to_vec(), expiry.to_be_bytes().to_vec(), 5u128.to_be_bytes().to_vec()].concat();
        let open = |e: u64| vec![osel.clone(), TOKEN.to_be_bytes().to_vec(), fund.arc4(), abi_bytes(&[1; 70]), terms(e), 0u64.to_be_bytes().to_vec()];
        assert!(tc(MANDATE, &open(far()), 0).is_ok());
        assert!(tc(MANDATE, &open(now + 100), 0).unwrap_err().to_string().contains("mandate"));
    }

    /// Spec §5: ARC-28 logs of configured apps only (a block holds only successful groups); joins by ids: PaymentMeta
    /// and RelayFeePaid onto the token's PaymentSettled, mandate pays keyed (token, id), DEX trades from OrderFilled +
    /// the leg's transfer joined to the configured DEX's Matched.
    #[test]
    fn algorand_events_book_configured_only_and_join() {
        let ids = Ids { tokens: vec![TOKEN, TOKEN_B], router: Some(ROUTER), mandate: Some(MANDATE), dex: Some(DEX) };
        let alice = holder(0, [0xa1; 32]);
        let bob = holder(0, [0xb0; 32]);
        let lane = holder(0, lane_pk());
        let ua = holder(1, [0x11; 32]);
        let amt = |n: u128| [vec![0; 16], n.to_be_bytes().to_vec()].concat();
        let log = |sig: &str, body: Vec<u8>| [selector(sig).to_vec(), body].concat();
        let hb = |x: &Holder| [vec![x.kind], x.id.to_vec()].concat();
        let settled = |f: &Holder, t: &Holder, n: u128, r: [u8; 32]| log(EV_SETTLED, [hb(f), hb(t), amt(n), r.to_vec()].concat());
        let xfer = |f: [u8; 32], t: [u8; 32], n: u128| log(EV_TRANSFER, [f.to_vec(), t.to_vec(), amt(n)].concat());
        let pref = [0x77; 32];
        let meta = b"invoice 42".to_vec();
        let meta_log = log(EV_META, [pref.to_vec(), vec![0, 34], (meta.len() as u16).to_be_bytes().to_vec(), meta.clone()].concat());
        let exec_log = log(EV_EXECUTED, [hb(&alice), lane.id.to_vec(), [5; 32].to_vec(), 0u64.to_be_bytes().to_vec(), [6; 32].to_vec()].concat());
        let fee_log = log(EV_FEE, [[0x88; 32].to_vec(), TARGET.to_be_bytes().to_vec(), TOKEN.to_be_bytes().to_vec(), hb(&ua), hb(&lane), amt(9)].concat());
        let fake_fee = log(EV_FEE, [[0x88; 32].to_vec(), TARGET.to_be_bytes().to_vec(), 4242u64.to_be_bytes().to_vec(), hb(&ua), hb(&lane), amt(9)].concat());
        let mpay = log(EV_MANDATE_PAY, [TOKEN.to_be_bytes().to_vec(), hb(&holder(1, [0x3c; 32])), hb(&bob), amt(100), [0x5e; 32].to_vec()].concat());
        let mpay_fake = log(EV_MANDATE_PAY, [4242u64.to_be_bytes().to_vec(), hb(&holder(1, [0x3c; 32])), hb(&bob), amt(100), [0x5f; 32].to_vec()].concat());
        let (da, db) = ([0xda; 32], [0xdb; 32]);
        let sid = [0x51; 32];
        let filled = |d: [u8; 32]| log(EV_FILLED, [hb(&ua), app_address(DEX).to_vec(), [1; 32].to_vec(), 0u64.to_be_bytes().to_vec(), amt(100), d.to_vec()].concat());
        let matched = log(EV_MATCHED, [sid.to_vec(), TOKEN.to_be_bytes().to_vec(), TOKEN_B.to_be_bytes().to_vec(), da.to_vec(), db.to_vec()].concat());
        let node = |app: u64, logs: Vec<Vec<u8>>, inner: Vec<Mp>| {
            let mut dt = vec![(Mp::str("lg"), Mp::Arr(logs.into_iter().map(Mp::Str).collect()))];
            if !inner.is_empty() {
                dt.push((Mp::str("itx"), Mp::Arr(inner)));
            }
            Mp::Map(vec![(Mp::str("dt"), Mp::Map(dt)), (Mp::str("txn"), Mp::Map(vec![(Mp::str("apid"), Mp::Int(app as i128)), (Mp::str("type"), Mp::str("appl"))]))])
        };
        let txns = vec![
            // 0: a plain pay-meta on the token
            node(TOKEN, vec![meta_log.clone(), exec_log.clone(), xfer(alice.id, bob.id, 5), settled(&alice, &bob, 5, pref)], vec![]),
            // 1: an unconfigured token: nothing
            node(4242, vec![settled(&alice, &bob, 5, pref), xfer(alice.id, bob.id, 5)], vec![]),
            // 2: a router relay: the token's pay inside, RelayFeePaid after
            node(ROUTER, vec![fee_log.clone()], vec![node(TOKEN, vec![settled(&ua, &lane, 9, [0x88; 32]), log(EV_UA_TRANSFER, [hb(&ua), hb(&lane), amt(9)].concat()),
                                                                         xfer(app_address(TOKEN), lane.id, 9)], vec![])]),
            // 3: a fake router's RelayFeePaid and a configured router's for an unconfigured token: nothing joins
            node(4343, vec![fee_log.clone()], vec![]),
            node(ROUTER, vec![fake_fee], vec![]),
            // 5: a mandate pay (configured token) and one for an unconfigured token
            node(MANDATE, vec![mpay, mpay_fake], vec![node(TOKEN, vec![xfer(app_address(MANDATE), bob.id, 100)], vec![])]),
            // 6: a DEX settle: two legs, the payouts, Matched last
            node(DEX, vec![matched.clone()], vec![
                node(TOKEN, vec![filled(da), xfer(alice.id, app_address(DEX), 100)], vec![]),
                node(TOKEN_B, vec![filled(db), xfer(bob.id, app_address(DEX), 60)], vec![]),
                node(TOKEN, vec![xfer(app_address(DEX), bob.id, 100)], vec![]),
            ]),
            // 7: Matched from another app: no settle id
            node(4444, vec![matched], vec![node(TOKEN, vec![filled([0xdc; 32]), xfer(alice.id, app_address(DEX), 1)], vec![])]),
        ];
        let block = Mp::Map(vec![(Mp::str("gen"), Mp::str("scaas-localnet-v1")), (Mp::str("gh"), Mp::Bin(network().to_vec())),
                                 (Mp::str("rnd"), Mp::Int(77)), (Mp::str("txns"), Mp::Arr(txns))]);
        let rows = block_events(&ids, &block, "0xbb").unwrap();
        let of = |e: &str| rows.iter().filter(|r| r["event"] == e).cloned().collect::<Vec<_>>();
        let ps = of("PaymentSettled");
        assert_eq!(ps.len(), 3, "{rows:#?}");
        assert_eq!(ps[0]["meta"], json!(h(&meta)));
        assert_eq!((ps[0]["contract"].clone(), ps[0]["from"].clone(), ps[0]["to"].clone(), ps[0]["amount"].clone()),
                   (json!("1001"), json!(alice.display()), json!(bob.display()), json!("5")));
        assert_eq!(ps[1]["relay_payee"], json!(lane.display()), "RelayFeePaid joined (open mode, the lane)");
        assert_eq!(ps[1]["relay_target"], json!(TARGET.to_string()));
        assert_eq!((ps[2]["contract"].clone(), ps[2]["from"].clone(), ps[2]["entry_ref"].clone()),
                   (json!("1001"), json!(h(&[0x3c; 32])), json!(h(&[0x5e; 32]))), "mandate pay keyed (token, id)");
        assert!(of("PaymentMeta").is_empty() && of("RelayFeePaid").is_empty());
        let ex = of("MetaTransactionExecuted");
        assert_eq!(ex.len(), 1);
        assert_eq!(ex[0]["relayer"], json!(lane.display()));
        let tr = of("Transfer");
        let leg = tr.iter().filter(|r| r["leg_digest"].is_string()).collect::<Vec<_>>();
        assert_eq!(leg.len(), 3, "{tr:#?}");
        assert_eq!((leg[0]["leg_digest"].clone(), leg[0]["settle_id"].clone()), (json!(h(&da)), json!(h(&sid))));
        assert_eq!((leg[1]["leg_digest"].clone(), leg[1]["contract"].clone()), (json!(h(&db)), json!("1007")));
        assert!(leg[2]["settle_id"].is_null(), "Matched of an unconfigured DEX");
        assert!(tr.iter().all(|r| r["contract"] != "4242"));
        assert!(tr.iter().any(|r| r["from"] == json!(ua.display()) && r["to"] == json!(lane.display())), "UaTransfer row");
        assert!(!tr.iter().any(|r| r["from"] == json!(algorand_address(&app_address(TOKEN)))), "the UA pool side is skipped");
        let tx0 = ps[0]["tx_hash"].as_str().unwrap();
        assert_eq!(tx0.len(), 66);
        assert!(rows.iter().all(|r| r["block_number"] == 77 && r["block_hash"] == "0xbb"));
        assert_ne!(ps[0]["tx_hash"], ps[1]["tx_hash"]);
    }

    /// One-round finality; a pruned (missing) round in the range fails the range; quorum endpoints must agree.
    #[tokio::test]
    async fn events_scan_blocks_and_pruned_rounds_error() {
        let mut w = world();
        let b = Mp::Map(vec![(Mp::str("block"), Mp::Map(vec![(Mp::str("gh"), Mp::Bin(network().to_vec())), (Mp::str("rnd"), Mp::Int(4_950)),
                                                              (Mp::str("ts"), Mp::Int(1))]))]);
        w.blocks.insert(4_950, (mp_encode(&b), [0x49; 32]));
        let (a, w) = adapter(w).await;
        let head = a.final_head().await.unwrap().unwrap();
        assert_eq!((head.height, head.hash.clone()), (5_000, h(&[5_000u64 as u8; 32])));
        assert_eq!(a.block_hash(4_950).await.unwrap(), h(&[0x49; 32]));
        assert!(a.events(4_950, 4_950, &["1001".into()]).await.unwrap().is_empty());
        assert!(a.events(4_949, 4_950, &["1001".into()]).await.unwrap_err().to_string().contains("4949"), "pruned");
        w.lock().unwrap().blocks.clear();
        assert!(a.block_hash(4_950).await.is_err());
    }

    #[tokio::test]
    async fn submit_and_status_are_classified() {
        let (a, w) = adapter(world()).await;
        let s = Signed { job_id: 1, tx_id: h(&[0x42; 32]), raw: vec![1, 2], valid_until: far(), sequence: 5_000 };
        a.submit(&s).await.unwrap();
        w.lock().unwrap().submit_err = Some("TransactionPool.Remember: transaction already in ledger: X".into());
        a.submit(&s).await.unwrap();
        w.lock().unwrap().submit_err = Some("TransactionPool.Remember: txn dead: round 5000 outside of 10--20".into());
        assert!(a.submit(&s).await.unwrap_err().downcast_ref::<Rejected>().is_some());
        let id = crate::addresses::b32encode(&[0x42; 32]);
        assert_eq!(a.tx_status(&s.tx_id).await.unwrap(), TxStatus::Unknown);
        w.lock().unwrap().pending.insert(id.clone(), json!({"pool-error": "", "confirmed-round": 0}));
        assert_eq!(a.tx_status(&s.tx_id).await.unwrap(), TxStatus::Pending);
        w.lock().unwrap().pending.insert(id.clone(), json!({"pool-error": "logic eval error: x", "confirmed-round": 0}));
        assert!(matches!(a.tx_status(&s.tx_id).await.unwrap(), TxStatus::Reverted { reason } if reason.contains("logic eval")));
        w.lock().unwrap().pending.insert(id, json!({"pool-error": "", "confirmed-round": 4_999}));
        assert_eq!(a.tx_status(&s.tx_id).await.unwrap(), TxStatus::Mined { height: 4_999, tx_hash: None });
        assert_eq!(a.sequence(0).await.unwrap(), 5_000);
        assert_eq!(a.lane_balance(0).await.unwrap(), Some(10_000_000));
    }

    /// R80: the payer's lane box on the token has passed the op's nonce; a router job too (one atomic group, no refund).
    #[tokio::test]
    async fn op_consumed_reads_the_lane_box() {
        let (a, w) = adapter(world()).await;
        let op = MetaOp { valid_until: far(), ..op_of("pay") };
        let j = job(o_op(&op, &auth_of("pay"), json!({})));
        assert_eq!(a.op_consumed(&j).await.unwrap(), Some(false));
        let name = [&b"l"[..], &sha256(&[&[op.from.kind][..], &op.from.id, &op.lane].concat())].concat();
        w.lock().unwrap().boxes.insert((TOKEN, name), 1u64.to_be_bytes().to_vec());
        assert_eq!(a.op_consumed(&j).await.unwrap(), Some(true));
        assert_eq!(a.op_consumed(&job(json!({"payload": "0x00"}))).await.unwrap(), None);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]
        /// Untrusted input never panics: job bytes and JSON, call bytes, auths, target arguments, msgpack blocks and
        /// simulate answers.
        #[test]
        fn algorand_jobs_never_panic(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..700),
                                     cut in 0usize..400, kind in 0u8..6, pick in 0usize..8) {
            let _ = MetaOp::decode(&bytes);
            let _ = MetaOp::from_arc4(&bytes);
            let _ = parse_router_call(&bytes);
            let _ = auth_origins(&bytes, &[1; 32]);
            if let Ok(m) = mp_decode(&bytes) {
                let _ = block_events(&Ids { tokens: vec![TOKEN], router: Some(ROUTER), mandate: Some(MANDATE), dex: Some(DEX) }, &m, "0x");
                let _ = mp_encode(&m);
            }
            let _ = parse_sim(&serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null));
            let _ = parse_sim(&json!({"txn-groups": [{"txn-results": [{"txn-result": {"inner-txns": [{"inner-txns": bytes.len()}]}}],
                                                      "unnamed-resources-accessed": {"accounts": [h(&bytes)], "boxes": [{"app": "x"}]}}]}));
            // a payment consistent with a random call to a random target, through entry and the target checks
            let targets = [TOKEN, ACCOUNT, MANDATE, DEX, TARGET, ROUTER, 0, 77];
            let sels = [format!("mtx_transfer({METAOP_ABI},byte[])void"), format!("mtx_add_key({METAOP_ABI},byte[],(uint16,byte[]),byte[])void"),
                        format!("mtx_mandate_open(uint64,{METAOP_ABI},byte[],{TERMS_ABI},uint64)void"),
                        format!("settle({ORDER_ABI},{METAOP_ABI},byte[],{ORDER_ABI},{METAOP_ABI},byte[],uint64[4])void"), "ping(uint64)void".into(),
                        format!("mtx_cancel({METAOP_ABI},byte[],byte[32],uint64)void")];
            let t = targets[pick];
            let mut args = vec![selector(&sels[kind as usize]).to_vec()];
            let mut rest = &bytes[..];
            while !rest.is_empty() && args.len() < 9 {
                let n = cut.min(rest.len()).max(1);
                args.push(rest[..n].to_vec());
                rest = &rest[n..];
            }
            let call = router_call(t, &args);
            let _ = parse_router_call(&call);
            let op = fee_op(&call, [5; 32], None);
            let o = fee_job(&call, &op, json!({"carries": [h(&bytes)], "accounts": [h(&bytes)], "boxes": [{"app": 1, "name": h(&bytes)}]}));
            let _ = entry(&pol(), Some(&exec()), &op, &o);
            let _ = job_refs(&o);
            let _ = target_check(&pol(), &exec(), &op, t, &args, &lane_pk(), kind as usize % 2, now());
            let _ = key_op_delta(&args, None, 118, &[]);
            let pm = json!({"kind": "pay_meta", "salt": h(&bytes[..bytes.len().min(32)]), "meta": h(&bytes)});
            let _ = entry(&pol(), None, &op, &pm);
        }
    }
}
