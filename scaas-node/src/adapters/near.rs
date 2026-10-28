//! NEAR (near-algorand spec §5 NEAR column; §2 rows 1–17, §3; CTR-MTX-26 / -27; plan Task 16). A `signed_op` job
//! carries `payload` = the `MetaOp` v1 encoding (`"scaas.metaop.v1"` ‖ Borsh, the shared vectors' `encoding`),
//! `signature` = Borsh(`Auth`) (common/src/auth.rs), both hex, and `contract` = the token account. Lane = an implicit
//! account (the 64-hex ed25519 key at `m/44'/397'/0'/0'/i'`), its access-key nonce the sequence, one function-call
//! transaction per job; the Borsh transaction and the ed25519 signature are hand-encoded here (no NEAR SDK;
//! `smartcontracts/near/vectors/near-tx.json` pins the bytes against near-primitives). NEAR has no write simulation:
//! simulate = the entry's `*_check` view (the relayer's RPC must allow `max_gas_burnt_view` ≥ 300 Tgas: a 12-passkey
//! check burns ≈ 265 Tgas), gas = pinned per-job figures (unused gas is refunded), the attached deposit = exactly what
//! the view reports. Events = NEP-297 logs of successful receipts on configured contracts, read from the final
//! outcomes of transactions in final blocks.
//!
//! Jobs (`op.kind`, `adapter::op_kind`): none = `mtx_pay`; `pay_meta` (`op.salt`, `op.meta`) = `mtx_pay_meta`;
//! `relay_fee` with `op.extra.call` (hex) and `op.extra.route`: `wrapper` = the token's atomic `relay_fee_<entry>`
//! (`call` = u8 len ‖ `mtx_<entry>` ‖ Borsh(entry arguments)), `router` = the escrow router's `relay` (`call` = u8 len ‖
//! target ‖ u8 len ‖ method ‖ args, plus `op.extra.target_gas` / `target_deposit` as decimal strings). A wrapper job's
//! simulation can disagree with its run where the entry changes what the payment's checks read (the entry adds or
//! removes the payment's signing key, a revoke refund funds the payer, `set_policy` turns on passkey-for-value for the
//! payer): such a job fails on chain and is reported reverted, never retried blindly (Task 9 note).
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::adapter::{Built, ChainAdapter, Family, Head, Lane, Rejected, Signed, TxStatus};
use crate::addresses::near as near_id;
use crate::chain::SimError;
use crate::config::ChainCfg;
use crate::odoo::Job;
use crate::signer::{LocalSigner, Signer};

pub use super::aptos::{meta_pay_id, pay_lane};

pub const LABEL: &[u8] = b"scaas.metaop.v1";
const OP_PAY: u8 = 0;
pub const TGAS: u64 = 1_000_000_000_000;
/// One transaction's protocol gas limit (spec §3.5: no chain's own larger limit is assumed).
pub const MAX_GAS: u64 = 300 * TGAS;
/// A job's receipt without its signature checks: the costliest measured entry (a `relay_fee_<entry>` wrapper writing
/// both records) burns ≤ 4.1 Tgas besides its verifies (`smartcontracts/near/runs/2026-10-28-near-relayfee*.txt`,
/// `-near-gas.txt`); pinned × 2.5 for 16 KiB arguments.
pub const GAS_JOB_BASE: u64 = 10 * TGAS;
/// Prepaid per P-256 passkey signature: 20.005 Tgas measured per verify (Task 1, `runs/2026-10-28-p256-spike.txt`)
/// × 1.05, so Task 9's largest wrapper (12-passkey msig entry + passkey payment, 265.6 Tgas burnt) fits 10 + 13 × 21.
pub const GAS_PASSKEY: u64 = 21 * TGAS;
/// Prepaid per ed25519 / secp256k1 signature (< 0.5 Tgas measured; the contracts' `GAS_SIG_KEY`).
pub const GAS_KEY_SIG: u64 = TGAS;
/// Task 9 / note 5: passkey signatures per wrapper job (entry + payment) that fit 300 Tgas.
pub const MAX_WRAPPER_PASSKEYS: usize = 13;
/// relayfee `relay_gas` without the payment's signatures and the target: `GAS_RELAY` 5 + `GAS_ON_HOLD` 5 + `GAS_EXEC` 4
/// + `call_gas` (4 + 2 × 5 + 3) + `GAS_HOLD` 5 Tgas (relayfee/src/lib.rs); `relay` refuses less prepaid gas.
pub const ROUTER_FIXED_GAS: u64 = 36 * TGAS;
/// The router's `sig_gas` figures (common/src/auth.rs `GAS_SIG_PASSKEY`, `GAS_SIG_KEY`).
const ROUTER_SIG_PASSKEY: u64 = 25 * TGAS;
const ROUTER_SIG_KEY: u64 = TGAS;
/// relayfee `MAX_ARGS_BYTES`.
pub const MAX_ARGS_BYTES: usize = 16_384;
/// common/src/auth.rs `PASSKEY_FIELD_MAX`: a longer passkey field is refused on chain (its verify is not budgeted).
pub const PASSKEY_FIELD_MAX: usize = 1024;
/// `relay_timeout(ref)`: its receipt, a token settle and a deposit return (`GAS_RELEASE` 5 each), `on_settle` 3.
const GAS_RELAY_TIMEOUT: u64 = 30 * TGAS;
/// A `relay_timeout` this node sent that has not settled the entry yet is sent again after this long.
const RELAY_TIMEOUT_RETRY_S: u64 = 120;
/// An entry still pending this long after its deadline (every `relay_timeout` failed) ends the job as reverted, so the
/// lane is not held forever; anyone may still settle the entry with `relay_timeout`.
const RELAY_STUCK_S: u64 = 3_600;
/// Heights walked down to the block produced at or before a skipped height.
const MAX_SKIP: u64 = 100;
/// `code_hash` of an account without a contract.
const NO_CODE: &str = "11111111111111111111111111111111";

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
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

/// A NEAR hash (base58 of 32 bytes).
fn b58_32(s: &str) -> Result<[u8; 32]> {
    bs58::decode(s).into_vec().ok().and_then(|v| v.try_into().ok()).ok_or_else(|| anyhow!("{s:?} is not a base58 hash"))
}

fn now() -> u64 {
    crate::submit::now()
}

// ------------------------------------------------------------------ Borsh

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.i.checked_add(n).filter(|e| *e <= self.b.len()).ok_or_else(|| anyhow!("truncated"))?;
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
    }
    fn u128(&mut self) -> Result<u128> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into()?))
    }
    fn arr32(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into()?)
    }
    /// `Vec<u8>` (u32 length).
    fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn string(&mut self) -> Result<String> {
        Ok(std::str::from_utf8(self.bytes()?)?.to_string())
    }
    /// `AccountId`: a string nearcore accepts as an account id.
    fn account(&mut self) -> Result<String> {
        near_id(&self.string()?)
    }
    fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            t => bail!("bool {t}"),
        }
    }
    fn option<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<Option<T>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(f(self)?)),
            t => bail!("option tag {t}"),
        }
    }
    fn holder(&mut self) -> Result<Holder> {
        match self.u8()? {
            0 => Ok(Holder::Near(self.account()?)),
            1 => Ok(Holder::Ua(self.arr32()?)),
            t => bail!("holder tag {t}"),
        }
    }
    fn end(&self) -> Result<()> {
        if self.i != self.b.len() {
            bail!("trailing bytes");
        }
        Ok(())
    }
    fn rest(&mut self) -> &'a [u8] {
        let s = &self.b[self.i..];
        self.i = self.b.len();
        s
    }
}

fn put_bytes(o: &mut Vec<u8>, b: &[u8]) {
    o.extend_from_slice(&(b.len() as u32).to_le_bytes());
    o.extend_from_slice(b);
}

fn put_str(o: &mut Vec<u8>, s: &str) {
    put_bytes(o, s.as_bytes());
}

fn borsh_str(s: &str) -> Vec<u8> {
    let mut o = Vec::new();
    put_str(&mut o, s);
    o
}

/// `u8 len ‖ bytes` (the `ref` target and `call` forms, spec §11: account ids ≤ 64, method names ≤ 255 bytes).
fn len8(s: &str) -> Vec<u8> {
    [&[s.len() as u8][..], s.as_bytes()].concat()
}

// ------------------------------------------------------------------ MetaOp, Auth (spec §2 row 1, §3.5)

/// common/src/holder.rs: Borsh variant 0 `Near(AccountId)`, 1 `Ua([u8; 32])`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Holder {
    Near(String),
    Ua([u8; 32]),
}

impl Holder {
    fn write(&self, o: &mut Vec<u8>) {
        match self {
            Holder::Near(a) => {
                o.push(0);
                put_str(o, a);
            }
            Holder::Ua(id) => {
                o.push(1);
                o.extend_from_slice(id);
            }
        }
    }

    /// The event / log form: the account id, or `0x` ‖ 64 lower-case hex for a UA id.
    pub fn display(&self) -> String {
        match self {
            Holder::Near(a) => a.clone(),
            Holder::Ua(id) => hex0x(id),
        }
    }
}

/// common/src/metaop.rs `MetaOp` (field order of `gen_vectors.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaOp {
    pub network: [u8; 32],
    pub contract: String,
    pub op: u8,
    pub from: Holder,
    pub to: Holder,
    pub relayer: Option<String>,
    pub amount: u128,
    pub pay_ref: [u8; 32],
    pub lane: [u8; 32],
    pub nonce: u64,
    pub valid_until: u64,
    pub extra: [u8; 32],
}

impl MetaOp {
    /// The job's `payload`: `"scaas.metaop.v1"` ‖ Borsh, canonical (account ids valid, tags known, nothing after).
    pub fn decode(b: &[u8]) -> Result<Self> {
        let body = b.strip_prefix(LABEL).ok_or_else(|| anyhow!("not a scaas.metaop.v1 payload"))?;
        let mut r = Reader::new(body);
        let op = Self::read(&mut r)?;
        r.end()?;
        Ok(op)
    }

    fn read(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            network: r.arr32()?,
            contract: r.account()?,
            op: r.u8()?,
            from: r.holder()?,
            to: r.holder()?,
            relayer: r.option(|r| r.account())?,
            amount: r.u128()?,
            pay_ref: r.arr32()?,
            lane: r.arr32()?,
            nonce: r.u64()?,
            valid_until: r.u64()?,
            extra: r.arr32()?,
        })
    }

    /// Borsh(MetaOp), the contracts' `op` argument.
    pub fn borsh(&self) -> Vec<u8> {
        let mut o = self.network.to_vec();
        put_str(&mut o, &self.contract);
        o.push(self.op);
        self.from.write(&mut o);
        self.to.write(&mut o);
        match &self.relayer {
            None => o.push(0),
            Some(a) => {
                o.push(1);
                put_str(&mut o, a);
            }
        }
        o.extend_from_slice(&self.amount.to_le_bytes());
        o.extend_from_slice(&self.pay_ref);
        o.extend_from_slice(&self.lane);
        o.extend_from_slice(&self.nonce.to_le_bytes());
        o.extend_from_slice(&self.valid_until.to_le_bytes());
        o.extend_from_slice(&self.extra);
        o
    }

    pub fn encode(&self) -> Vec<u8> {
        [LABEL, &self.borsh()[..]].concat()
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.encode())
    }
}

/// The shape of a Borsh `Auth` (common/src/auth.rs: 0 ed25519, 1 secp256k1, 2 passkey, 3 msig), checked off chain only
/// for its size and signature budget; the job forwards the bytes as signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    Ed25519,
    Secp256k1,
    Passkey,
    Msig(Vec<Auth>),
}

impl Auth {
    /// Exactly one `Auth`; an msig inside an msig and a passkey field over `PASSKEY_FIELD_MAX` refused (as on chain).
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let a = Self::read(&mut r, true)?;
        r.end()?;
        Ok(a)
    }

    fn read(r: &mut Reader, top: bool) -> Result<Self> {
        Ok(match r.u8()? {
            0 => {
                r.take(32 + 64)?;
                Auth::Ed25519
            }
            1 => {
                r.take(64 + 64 + 1)?;
                Auth::Secp256k1
            }
            2 => {
                r.take(64)?;
                let (ad, cd) = (r.bytes()?.len(), r.bytes()?.len());
                r.take(64)?;
                if ad > PASSKEY_FIELD_MAX || cd > PASSKEY_FIELD_MAX {
                    bail!("passkey clientDataJSON / authenticatorData over {PASSKEY_FIELD_MAX} bytes");
                }
                Auth::Passkey
            }
            3 if top => {
                r.bytes()?;
                let n = r.u32()?;
                let mut sigs = Vec::new();
                for _ in 0..n {
                    r.u8()?;
                    sigs.push(Self::read(r, false)?);
                }
                Auth::Msig(sigs)
            }
            3 => bail!("msig inside msig"),
            t => bail!("auth tag {t}"),
        })
    }

    pub fn passkeys(&self) -> usize {
        match self {
            Auth::Passkey => 1,
            Auth::Msig(v) => v.iter().map(Self::passkeys).sum(),
            _ => 0,
        }
    }

    /// Gas a job prepays for this auth's signatures.
    fn attach_gas(&self) -> u64 {
        match self {
            Auth::Passkey => GAS_PASSKEY,
            Auth::Ed25519 | Auth::Secp256k1 => GAS_KEY_SIG,
            Auth::Msig(v) => v.iter().map(Self::attach_gas).fold(0, u64::saturating_add),
        }
    }

    /// The router's `sig_gas` of this auth (its `relay_gas` term).
    fn router_gas(&self) -> u64 {
        match self {
            Auth::Passkey => ROUTER_SIG_PASSKEY,
            Auth::Ed25519 | Auth::Secp256k1 => ROUTER_SIG_KEY,
            Auth::Msig(v) => v.iter().map(Self::router_gas).fold(0, u64::saturating_add),
        }
    }
}

// ------------------------------------------------------------------ CTR-MTX-27 (spec §2 row 8, §3.8)

/// `ref = keccak256("scaas.relayfee" ‖ network ‖ target ‖ keccak256(call) ‖ salt)` (common/src/hash.rs), `target` =
/// u8 len ‖ account id, `salt` = the payment's `extra`.
pub fn relay_ref(network: &[u8; 32], target: &[u8], call: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    keccak(&[b"scaas.relayfee", network, target, &keccak(&[call]), salt])
}

/// The router's `call` (relayfee `call_ref`): u8 len ‖ target ‖ u8 len ‖ method ‖ args.
pub fn router_call(target: &str, method: &str, args: &[u8]) -> Vec<u8> {
    [len8(target), len8(method), args.to_vec()].concat()
}

fn parse_router_call(call: &[u8]) -> Result<(String, String, Vec<u8>)> {
    let mut r = Reader::new(call);
    let n = r.u8()? as usize;
    let target = near_id(std::str::from_utf8(r.take(n)?)?).context("router call target")?;
    let n = r.u8()? as usize;
    let method = std::str::from_utf8(r.take(n)?)?.to_string();
    if method.is_empty() {
        bail!("router call: empty method");
    }
    Ok((target, method, r.rest().to_vec()))
}

/// Borsh kinds of a wrapped entry's parameters after `(op, auth)`.
#[derive(Debug, Clone, Copy)]
enum P {
    KeyRecord,
    OptString,
    Str,
    OptHolder,
    U8,
    Terms,
    Arr32,
    U64,
}

/// The fee-less signed entries the token's `relay_fee_<entry>` wrappers serve (token/src/relayfee.rs, 13 wrappers).
const WRAPPED: &[(&str, &[P])] = {
    use P::*;
    &[
        ("mtx_add_key", &[KeyRecord, OptString]),
        ("mtx_remove_key", &[KeyRecord]),
        ("mtx_add_origin", &[Str]),
        ("mtx_remove_origin", &[Str]),
        ("mtx_set_guardian", &[OptHolder]),
        ("mtx_set_policy", &[U8]),
        ("mtx_start_recovery", &[KeyRecord, OptString]),
        ("mtx_cancel_recovery", &[]),
        ("mtx_finish_recovery", &[]),
        ("mtx_mandate_open", &[Terms]),
        ("mtx_revoke", &[]),
        ("mtx_cancel", &[Arr32, U64]),
        ("mtx_invalidate_nonces", &[Arr32, U64]),
    ]
};

fn read_param(r: &mut Reader, p: P) -> Result<()> {
    match p {
        P::KeyRecord => {
            r.u16()?;
            r.bytes()?;
        }
        P::OptString => {
            r.option(|r| r.string())?;
        }
        P::Str => {
            r.string()?;
        }
        P::OptHolder => {
            r.option(|r| r.holder())?;
        }
        P::U8 => {
            r.u8()?;
        }
        // MandateTerms { delegate, payee, per_payment, per_period, period_s, expiry, funding }
        P::Terms => {
            r.holder()?;
            r.holder()?;
            r.u128()?;
            r.u128()?;
            r.u64()?;
            r.u64()?;
            r.u128()?;
        }
        P::Arr32 => {
            r.arr32()?;
        }
        P::U64 => {
            r.u64()?;
        }
    }
    Ok(())
}

/// A wrapped entry's arguments, canonical and complete: `(op, auth, parameters…)`; returns its `auth`.
fn wrapper_args(entry: &str, args: &[u8]) -> Result<Auth> {
    let (_, params) = WRAPPED.iter().find(|w| w.0 == entry).ok_or_else(|| anyhow!("{entry} is not a wrapped entry"))?;
    let mut r = Reader::new(args);
    MetaOp::read(&mut r)?;
    let auth = Auth::read(&mut r, true)?;
    for p in params.iter() {
        read_param(&mut r, *p)?;
    }
    r.end()?;
    Ok(auth)
}

/// A wrapper `call`: u8 len ‖ the entry's full name ‖ its arguments.
fn parse_wrapper_call(call: &[u8]) -> Result<(String, Vec<u8>)> {
    let mut r = Reader::new(call);
    let n = r.u8()? as usize;
    let entry = std::str::from_utf8(r.take(n)?)?.to_string();
    let args = r.rest().to_vec();
    wrapper_args(&entry, &args).with_context(|| format!("op.extra.call is not a canonical call of a wrapped entry ({entry})"))?;
    Ok((entry, args))
}

// ------------------------------------------------------------------ policy, entries

/// What the node accepts as a relay-fee job (T17 uniform keys): `params.relay_fee = { router, executor, min_amount,
/// relay_bound_payee, min_yocto_value }`, `params.max_pay_meta_bytes`, the chain's `tokens`.
#[derive(Debug, Clone, Default)]
pub struct RelayFeePolicy {
    pub router: Option<String>,
    pub executor: Option<String>,
    pub tokens: Vec<String>,
    pub params: crate::config::RelayParams,
    /// `min_yocto_value = { "<token>" = "<yoctoNEAR per base unit>" }`: the node's floor price of a fee token.
    pub min_yocto_value: HashMap<String, u128>,
}

impl RelayFeePolicy {
    /// A set but malformed or inconsistent value is a startup error, never a silently disabled router: a router without
    /// its executor (or the reverse), router = executor, either one a configured token, a price that is not a
    /// non-negative integer (TOML integer or decimal string) or names no configured token. `router.executor()` itself
    /// is checked at start (`start_check`).
    pub fn from_cfg(cfg: &ChainCfg) -> Result<Self> {
        let params = cfg.relay_params()?;
        let tokens: Vec<String> = cfg.tokens.iter()
            .map(|t| near_id(&t.address).with_context(|| format!("tokens: {} is not a NEAR account id", t.address)))
            .collect::<Result<_>>()?;
        let t = cfg.params.get("relay_fee").and_then(|v| v.as_table());
        let router = params.router.as_deref().map(|r| near_id(r).context("params.relay_fee.router")).transpose()?;
        let executor = match t.and_then(|t| t.get("executor")) {
            None => None,
            Some(v) => Some(near_id(v.as_str().ok_or_else(|| anyhow!("params.relay_fee.executor must be a string"))?)
                .context("params.relay_fee.executor")?),
        };
        match (&router, &executor) {
            (Some(_), None) => bail!("params.relay_fee.router needs params.relay_fee.executor (the router's executor account)"),
            (None, Some(_)) => bail!("params.relay_fee.executor needs params.relay_fee.router"),
            (Some(r), Some(e)) if r == e => bail!("params.relay_fee.router and executor are one account"),
            (Some(r), Some(e)) if tokens.contains(r) || tokens.contains(e) => {
                bail!("params.relay_fee.router / executor is a configured token")
            }
            _ => {}
        }
        let mut min_yocto_value = HashMap::new();
        if let Some(v) = t.and_then(|t| t.get("min_yocto_value")) {
            let table = v.as_table().ok_or_else(|| anyhow!("params.relay_fee.min_yocto_value must be a table of token = yoctoNEAR"))?;
            for (k, n) in table {
                if !tokens.contains(k) {
                    bail!("params.relay_fee.min_yocto_value.{k}: not a configured token");
                }
                let price = match n {
                    toml::Value::Integer(i) => u128::try_from(*i).ok(),
                    toml::Value::String(s) => dec_u128(&json!(s), "").ok(),
                    _ => None,
                };
                let price = price.ok_or_else(|| anyhow!("params.relay_fee.min_yocto_value.{k} must be a non-negative integer, not {n}"))?;
                min_yocto_value.insert(k.clone(), price);
            }
        }
        Ok(Self { router, executor, tokens, params, min_yocto_value })
    }
}

/// The entry a job runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Pay,
    PayMeta { salt: [u8; 32], meta: Vec<u8> },
    /// `relay_fee_<entry>` on the token: `entry` = the full wrapped name (`mtx_add_key`), `args` = its Borsh arguments.
    FeeWrapper { entry: String, args: Vec<u8> },
    /// The router's `relay(target, method, args, target_gas, target_deposit, token, op, auth)`.
    FeeRouter { target: String, method: String, args: Vec<u8>, target_gas: u64, target_deposit: u128 },
}

fn hex_field(v: &Value, what: &str) -> Result<Vec<u8>> {
    let s = v.as_str().ok_or_else(|| anyhow!("op.{what} missing"))?;
    Ok(alloy::hex::decode(s.trim().trim_start_matches("0x"))?)
}

/// A u128 amount as JSON: a decimal string only (never a JSON number: an f64 above 2^53 loses digits).
pub fn dec_u128(v: &Value, what: &str) -> Result<u128> {
    let s = v.as_str().ok_or_else(|| anyhow!("{what} must be a decimal string, not {v}"))?;
    if s.is_empty() || s.len() > 39 || !s.bytes().all(|c| c.is_ascii_digit()) {
        bail!("{what} must be a decimal string, not {s:?}");
    }
    s.parse().map_err(|_| anyhow!("{what} {s} is above 2^128 - 1"))
}

fn dec_u64(v: &Value, what: &str) -> Result<u64> {
    u64::try_from(dec_u128(v, what)?).map_err(|_| anyhow!("{what} is above 2^64 - 1"))
}

fn bound(op: &MetaOp, r: &[u8; 32], o: &Value) -> Result<()> {
    if op.op != OP_PAY || op.pay_ref != *r || op.lane != pay_lane(r) || op.nonce != 0 {
        bail!("the payment is not bound to this call (op 0, pay_ref = ref, lane = payLane(ref), nonce 0)");
    }
    if !o["ref"].is_null() && hex_field(&o["ref"], "ref")? != r {
        bail!("op.ref != relay_ref(call, salt)");
    }
    Ok(())
}

fn pays(op: &MetaOp, who: Option<&String>) -> bool {
    who.is_some_and(|w| op.to == Holder::Near(w.clone()))
}

/// The entry of a job, checked before simulation (fail closed). `op.kind` (one rule, `adapter::op_kind`): none = the
/// plain pay; `pay_meta`: `pay_ref == metaPayId(salt, meta)`, `lane == payLane(pay_ref)`, `nonce == 0`, `meta` within
/// `max_pay_meta_bytes`; `relay_fee`: a configured token, `op.extra.route` and the payment bound to exactly this call
/// (`ref` from the call bytes and the payment's `extra`, the marker as relayer). Never pays the router, its executor or
/// the token itself (the wrapper marker) outside the route whose open mode it is (CTR-MTX-27 step 2).
pub fn entry(policy: &RelayFeePolicy, op: &MetaOp, o: &Value) -> Result<Entry> {
    let kind = crate::adapter::op_kind(o, &crate::adapter::PAY_KINDS)?;
    if kind != Some("relay_fee")
        && (op.to == Holder::Near(op.contract.clone()) || pays(op, policy.router.as_ref()) || pays(op, policy.executor.as_ref()))
    {
        bail!("never pay {} (the token itself, the relay-fee router or its executor): the funds would be stranded", op.to.display());
    }
    match kind {
        Some("pay_meta") => {
            let salt: [u8; 32] = hex_field(&o["salt"], "salt")?.try_into().map_err(|_| anyhow!("op.salt is 32 bytes"))?;
            let meta = hex_field(&o["meta"], "meta")?;
            if meta.len() > policy.params.max_pay_meta_bytes {
                bail!("meta is {} B, above max_pay_meta_bytes {}", meta.len(), policy.params.max_pay_meta_bytes);
            }
            let id = meta_pay_id(&salt, &meta);
            if op.pay_ref != id || op.lane != pay_lane(&id) || op.nonce != 0 {
                bail!("pay-meta: pay_ref / lane / nonce are not metaPayId(salt, meta) / payLane / 0");
            }
            Ok(Entry::PayMeta { salt, meta })
        }
        Some("relay_fee") => fee_entry(policy, op, o),
        _ => Ok(Entry::Pay),
    }
}

fn fee_entry(policy: &RelayFeePolicy, op: &MetaOp, o: &Value) -> Result<Entry> {
    if !policy.tokens.contains(&op.contract) {
        bail!("token {} is not a configured token of this chain", op.contract);
    }
    let route = o["extra"]["route"].as_str().ok_or_else(|| anyhow!("op.extra.route must be \"wrapper\" or \"router\""))?;
    let call = hex_field(&o["extra"]["call"], "extra.call")?;
    match route {
        "wrapper" => {
            if op.relayer.as_ref() != Some(&op.contract) {
                bail!("the payment's relayer {:?} is not the wrapper marker (the token {})", op.relayer, op.contract);
            }
            bound(op, &relay_ref(&op.network, &len8(&op.contract), &call, &op.extra), o)?;
            if pays(op, policy.router.as_ref()) || pays(op, policy.executor.as_ref()) {
                bail!("never pay the relay-fee router or its executor");
            }
            let (entry, args) = parse_wrapper_call(&call)?;
            Ok(Entry::FeeWrapper { entry, args })
        }
        "router" => {
            let (Some(router), Some(executor)) = (&policy.router, &policy.executor) else {
                bail!("router relay-fee jobs need params.relay_fee.router and executor");
            };
            if op.relayer.as_ref() != Some(router) {
                bail!("the payment's relayer {:?} is not the configured router {router}", op.relayer);
            }
            let (target, method, args) = parse_router_call(&call)?;
            bound(op, &relay_ref(&op.network, &len8(&target), &call, &op.extra), o)?;
            if target == *router || target == *executor {
                bail!("the target {target} is the router or its executor");
            }
            // T12 m5 NEAR counterpart: no key may ever be registered for the executor
            if method == "add_key_native" {
                bail!("a relay-fee target method add_key_native is refused (no key is ever registered for the executor)");
            }
            if pays(op, Some(executor)) {
                bail!("the executor is never paid");
            }
            if op.to == Holder::Near(op.contract.clone()) {
                bail!("never pay the token itself");
            }
            if args.len() > MAX_ARGS_BYTES {
                bail!("router args are {} B, above {MAX_ARGS_BYTES}", args.len());
            }
            let target_gas = dec_u64(&o["extra"]["target_gas"], "op.extra.target_gas")?;
            let target_deposit = dec_u128(&o["extra"]["target_deposit"], "op.extra.target_deposit")?;
            Ok(Entry::FeeRouter { target, method, args, target_gas, target_deposit })
        }
        r => bail!("op.extra.route {r:?} must be \"wrapper\" or \"router\""),
    }
}

/// The job's pinned prepaid gas (§5: no estimate RPC). A plain / pay-meta job: `GAS_JOB_BASE` + its signatures; a
/// wrapper: also the entry's signatures, at most 13 passkeys in all (note 5); a router job: the router's own
/// `relay_gas` (36 Tgas + the payment's `sig_gas` + `target_gas`, note 6). Above 300 Tgas is refused.
pub fn job_gas(entry: &Entry, auth: &Auth) -> Result<u64> {
    let gas = match entry {
        Entry::Pay | Entry::PayMeta { .. } => GAS_JOB_BASE.saturating_add(auth.attach_gas()),
        Entry::FeeWrapper { entry, args } => {
            let a = wrapper_args(entry, args)?;
            let n = a.passkeys().saturating_add(auth.passkeys());
            if n > MAX_WRAPPER_PASSKEYS {
                bail!("{n} passkey signatures in one wrapper job (entry + payment): at most {MAX_WRAPPER_PASSKEYS} fit 300 Tgas");
            }
            GAS_JOB_BASE.saturating_add(a.attach_gas()).saturating_add(auth.attach_gas())
        }
        Entry::FeeRouter { target_gas, .. } => ROUTER_FIXED_GAS.saturating_add(auth.router_gas()).saturating_add(*target_gas),
    };
    if gas > MAX_GAS {
        bail!("the job needs {} Tgas, above the 300 Tgas one transaction may prepay", gas / TGAS);
    }
    Ok(gas)
}

/// The relay-fee route's marker: the token (wrapper) or the router.
fn marker<'a>(policy: &'a RelayFeePolicy, op: &'a MetaOp, entry: &Entry) -> Option<&'a String> {
    match entry {
        Entry::FeeWrapper { .. } => Some(&op.contract),
        Entry::FeeRouter { .. } => policy.router.as_ref(),
        _ => None,
    }
}

/// T17 payee rule (`adapter::relay_fee_ours`): open mode (`to` = the marker, which pays the submitting lane) or bound
/// to the lane, at least `min_amount`; bound to anyone else only with `relay_bound_payee` (sponsored).
pub fn relay_payee(policy: &RelayFeePolicy, op: &MetaOp, entry: &Entry, lane: &str) -> Result<()> {
    let Some(m) = marker(policy, op, entry) else { return Ok(()) };
    crate::adapter::relay_fee_ours(pays(op, Some(m)), op.to == Holder::Near(lane.into()), op.amount, &policy.params)
}

/// Spec §5 / T17 fee-covers-cost: a fee that is the node's must be worth, at `min_yocto_value`, at least `quote` = the
/// job's prepaid gas × the node's gas price + every deposit the job attaches.
fn fee_covers(policy: &RelayFeePolicy, op: &MetaOp, quote: u128) -> Result<()> {
    let price = policy.min_yocto_value.get(&op.contract)
        .ok_or_else(|| anyhow!("params.relay_fee.min_yocto_value has no price for token {}", op.contract))?;
    let value = op.amount.saturating_mul(*price);
    if value < quote {
        bail!("fee {} × min_yocto_value {price} = {value} yoctoNEAR is below the {quote} yoctoNEAR the job costs (gas at the node's price + deposits)", op.amount);
    }
    Ok(())
}

// ------------------------------------------------------------------ transaction (Borsh, hand-encoded)

/// One function-call action of a lane transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub receiver: String,
    pub method: String,
    pub args: Vec<u8>,
    pub gas: u64,
    pub deposit: u128,
}

/// The job's call (deposit 0 until the simulation reports it): `mtx_pay(op, auth)`, `mtx_pay_meta(op, auth, salt,
/// meta)`, `relay_fee_<entry>(entry args…, op, auth)` on the token, or the router's `relay(…)`. Its `*_check` view
/// takes the same arguments, after `caller` on the token (the router's `relay_check` has none).
pub fn call_of(policy: &RelayFeePolicy, entry: &Entry, op: &MetaOp, auth: &[u8]) -> Result<Call> {
    let gas = job_gas(entry, &Auth::decode(auth)?)?;
    let pay = [op.borsh(), auth.to_vec()].concat();
    let (receiver, method, args) = match entry {
        Entry::Pay => (op.contract.clone(), "mtx_pay".to_string(), pay),
        Entry::PayMeta { salt, meta } => {
            let mut a = [pay, salt.to_vec()].concat();
            put_bytes(&mut a, meta);
            (op.contract.clone(), "mtx_pay_meta".into(), a)
        }
        Entry::FeeWrapper { entry, args } => {
            let short = entry.strip_prefix("mtx_").ok_or_else(|| anyhow!("{entry} is not an mtx_ entry"))?;
            (op.contract.clone(), format!("relay_fee_{short}"), [args.clone(), pay].concat())
        }
        Entry::FeeRouter { target, method, args, target_gas, target_deposit } => {
            let router = policy.router.clone().ok_or_else(|| anyhow!("no params.relay_fee.router"))?;
            let mut a = borsh_str(target);
            put_str(&mut a, method);
            put_bytes(&mut a, args);
            a.extend_from_slice(&target_gas.to_le_bytes());
            a.extend_from_slice(&target_deposit.to_le_bytes());
            put_str(&mut a, &op.contract);
            a.extend_from_slice(&pay);
            (router, "relay".into(), a)
        }
    };
    Ok(Call { receiver, method, args, gas, deposit: 0 })
}

/// `Transaction::V0 { signer_id, public_key (ed25519), nonce, receiver_id, block_hash, actions: [FunctionCall] }`.
pub fn function_call_tx(signer: &str, pk: &[u8; 32], nonce: u64, block_hash: &[u8; 32], call: &Call) -> Vec<u8> {
    let mut o = borsh_str(signer);
    o.push(0); // KeyType::ED25519
    o.extend_from_slice(pk);
    o.extend_from_slice(&nonce.to_le_bytes());
    put_str(&mut o, &call.receiver);
    o.extend_from_slice(block_hash);
    o.extend_from_slice(&1u32.to_le_bytes());
    o.push(2); // Action::FunctionCall
    put_str(&mut o, &call.method);
    put_bytes(&mut o, &call.args);
    o.extend_from_slice(&call.gas.to_le_bytes());
    o.extend_from_slice(&call.deposit.to_le_bytes());
    o
}

/// `SignedTransaction { transaction, signature: Signature::ED25519 }`.
pub fn signed_tx(tx: &[u8], sig: &[u8]) -> Vec<u8> {
    [tx, &[0], sig].concat()
}

/// The transaction hash (and what the lane signs): `sha256(Borsh(Transaction))`.
pub fn tx_hash(tx: &[u8]) -> [u8; 32] {
    sha256(tx)
}

/// `Check { error: Option<String>, storage_needed: u128 }` (token `*_check` views).
fn decode_check(b: &[u8]) -> Result<std::result::Result<u128, String>> {
    let mut r = Reader::new(b);
    let err = r.option(|r| r.string())?;
    let storage = r.u128()?;
    r.end()?;
    Ok(err.map_or(Ok(storage), Err))
}

/// relayfee `Check { error, storage_needed, deposit_needed, gas_needed }` ⇒ `(deposit_needed, gas_needed)`.
fn decode_router_check(b: &[u8]) -> Result<std::result::Result<(u128, u64), String>> {
    let mut r = Reader::new(b);
    let err = r.option(|r| r.string())?;
    r.u128()?;
    let (deposit, gas) = (r.u128()?, r.u64()?);
    r.end()?;
    Ok(err.map_or(Ok((deposit, gas)), Err))
}

/// relayfee `pending(ref) -> Option<Pending>` ⇒ `(deadline, stage)` (stage 0 Hold, 1 Call, 2 Settle, 3 Owed).
fn decode_pending(b: &[u8]) -> Result<Option<(u64, u8)>> {
    let mut r = Reader::new(b);
    let p = r.option(|r| {
        r.u64()?;
        r.account()?;
        r.account()?;
        r.holder()?;
        r.option(|r| r.holder())?;
        r.u128()?;
        r.account()?;
        r.u128()?;
        r.u128()?;
        let deadline = r.u64()?;
        let stage = r.u8()?;
        r.bool()?;
        Ok((deadline, stage))
    })?;
    r.end()?;
    Ok(p)
}

/// The `ref` (= the payment's `pay_ref`) of a `relay` call's arguments.
fn relay_args_ref(args: &[u8]) -> Result<[u8; 32]> {
    let mut r = Reader::new(args);
    r.account()?;
    r.string()?;
    r.bytes()?;
    r.u64()?;
    r.u128()?;
    r.account()?;
    let op = MetaOp::read(&mut r)?;
    Auth::read(&mut r, true)?;
    r.end()?;
    Ok(op.pay_ref)
}

/// A final outcome's `status`: `Ok(Some(value))` / `Ok(None)` (a receipt id) on success, `Err(reason)` on failure.
fn outcome_status(s: &Value) -> Result<std::result::Result<Option<Vec<u8>>, String>> {
    if let Some(v) = s.get("SuccessValue") {
        return Ok(Ok(Some(b64d(v.as_str().ok_or_else(|| anyhow!("bad SuccessValue"))?)?)));
    }
    if s.get("SuccessReceiptId").is_some() {
        return Ok(Ok(None));
    }
    if let Some(f) = s.get("Failure") {
        return Ok(Err(f.to_string()));
    }
    bail!("unknown outcome status {s}")
}

// ------------------------------------------------------------------ events (NEP-297)

/// The ids whose events count: Odoo's registered tokens (`contracts`) and the configured router and DEX.
#[derive(Debug, Clone, Default)]
pub struct Ids {
    pub tokens: Vec<String>,
    pub router: Option<String>,
    pub dex: Option<String>,
}

fn nep297(log: &str) -> Option<(String, String, Vec<Value>)> {
    let v: Value = serde_json::from_str(log.strip_prefix("EVENT_JSON:")?).ok()?;
    let data = match &v["data"] {
        Value::Array(a) => a.clone(),
        d @ Value::Object(_) => vec![d.clone()],
        _ => return None,
    };
    Some((v["standard"].as_str()?.to_string(), v["event"].as_str()?.to_string(), data))
}

/// A holder in its event form: a NEAR account id or `0x` ‖ 64 lower-case hex (a UA id).
fn holder_s(v: &Value) -> Option<String> {
    let s = v.as_str()?;
    let ua = s.len() == 66 && s.starts_with("0x") && s[2..].bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
    if ua { Some(s.to_string()) } else { near_id(s).ok() }
}

fn h32(v: &Value) -> Option<String> {
    let b = alloy::hex::decode(v.as_str()?.strip_prefix("0x")?).ok()?;
    (b.len() == 32).then(|| hex0x(&b))
}

fn amount(v: &Value) -> Option<String> {
    dec_u128(v, "amount").ok().map(|a| a.to_string())
}

fn succeeded(outcome: &Value) -> bool {
    outcome["status"].get("SuccessValue").is_some() || outcome["status"].get("SuccessReceiptId").is_some()
}

/// One holder move, `None` when a side is the token itself (its UA pool / relay escrow: the `ua_transfer` or the
/// payment events tell the holder's side) or a field is malformed.
fn transfer(token: &str, from: &Value, to: &Value, n: &Value) -> Option<Value> {
    let (from, to, n) = (holder_s(from)?, holder_s(to)?, amount(n)?);
    (from != token && to != token).then(|| json!({"event": "Transfer", "from": from, "to": to, "amount": n}))
}

/// The events of one final transaction outcome, for `chain_event_ingest`: only receipts that SUCCEEDED (a failed
/// receipt keeps its logs, NET-NEAR-07) on configured contracts (a copy elsewhere emits identical events). Token:
/// `payment_settled` (a mandate pay's `from` = `0x` ‖ mandate id, so keyed by (token, id)), `payment_meta`,
/// `meta_transaction_executed`, its own wrapper `relay_fee_paid`, and one `Transfer` per holder move (`ft_transfer`,
/// `ua_transfer`); router: `relay_fee_paid` of a configured token only; then joined (`indexer::join_pay_events`, by
/// ids, never by position). DEX trades are booked from the tokens' transfers: a leg's transfer into the DEX carries its
/// `order_filled` digest (`leg_digest`) and, when the configured DEX's `matched` lists it, `settle_id`; `matched` alone
/// books nothing (it is emitted before the payouts). `log_index` counts every log of the transaction in outcome order.
pub fn tx_events(ids: &Ids, tx: &Value, block: u64, block_hash: &str, tx_hash: &str) -> Vec<Value> {
    let receipts = tx["receipts_outcome"].as_array().cloned().unwrap_or_default();
    let mut settles: HashMap<String, String> = HashMap::new();
    for rc in &receipts {
        let o = &rc["outcome"];
        if !succeeded(o) || ids.dex.as_deref() != o["executor_id"].as_str() {
            continue;
        }
        for (std, ev, data) in o["logs"].as_array().into_iter().flatten().filter_map(|l| nep297(l.as_str()?)) {
            if (std.as_str(), ev.as_str()) != ("scaas", "matched") {
                continue;
            }
            for d in &data {
                let Some(sid) = h32(&d["settle_id"]) else { continue };
                for leg in d["legs"].as_array().into_iter().flatten().filter_map(h32) {
                    settles.insert(leg, sid.clone());
                }
            }
        }
    }
    let mut rows = Vec::new();
    let mut index = 0u64;
    for rc in &receipts {
        let o = &rc["outcome"];
        let logs = o["logs"].as_array().cloned().unwrap_or_default();
        let first = index;
        index += logs.len() as u64;
        let exec = o["executor_id"].as_str().unwrap_or_default();
        let token = ids.tokens.iter().any(|t| t == exec);
        let router = ids.router.as_deref() == Some(exec);
        if !succeeded(o) || !(token || router) {
            continue;
        }
        let (mut receipt_rows, mut leg) = (Vec::new(), None);
        for (i, log) in logs.iter().enumerate() {
            let Some((std, ev, data)) = log.as_str().and_then(nep297) else { continue };
            for d in &data {
                let row = match (token, std.as_str(), ev.as_str()) {
                    (true, "scaas", "payment_settled") => settled_row(d),
                    (true, "scaas", "payment_meta") => meta_row(d),
                    (true, "scaas", "meta_transaction_executed") => executed_row(d),
                    (true, "scaas", "ua_transfer") => transfer(exec, &d["from"], &d["to"], &d["amount"]),
                    (true, "nep141", "ft_transfer") => transfer(exec, &d["old_owner_id"], &d["new_owner_id"], &d["amount"]),
                    (true, "scaas", "order_filled") => {
                        leg = h32(&d["digest"]);
                        None
                    }
                    // a wrapper's fee: the token is its own target and marker
                    (true, "scaas", "relay_fee_paid") if d["token"].as_str() == Some(exec) && d["target"].as_str() == Some(exec) => {
                        fee_row(exec, exec, d)
                    }
                    // the router's: only a configured token's, joined to that token's payment_settled
                    (false, "scaas", "relay_fee_paid") => match d["token"].as_str() {
                        Some(t) if ids.tokens.iter().any(|x| x == t) => fee_row(exec, t, d),
                        _ => None,
                    },
                    _ => None,
                };
                if let Some(mut row) = row {
                    row["contract"] = json!(exec);
                    row["block_number"] = json!(block);
                    row["block_hash"] = json!(block_hash);
                    row["tx_hash"] = json!(tx_hash);
                    row["log_index"] = json!(first + i as u64);
                    receipt_rows.push(row);
                }
            }
        }
        if let Some(d) = leg {
            for r in receipt_rows.iter_mut().filter(|r| r["event"] == "Transfer") {
                r["leg_digest"] = json!(d);
                if let Some(sid) = settles.get(&d) {
                    r["settle_id"] = json!(sid);
                }
            }
        }
        rows.extend(receipt_rows);
    }
    crate::indexer::join_pay_events(rows)
}

fn settled_row(d: &Value) -> Option<Value> {
    Some(json!({"event": "PaymentSettled", "from": holder_s(&d["from"])?, "to": holder_s(&d["to"])?,
                "amount": amount(&d["amount"])?, "entry_ref": h32(&d["pay_ref"])?}))
}

fn meta_row(d: &Value) -> Option<Value> {
    let meta = alloy::hex::decode(d["meta"].as_str()?.strip_prefix("0x")?).ok()?;
    Some(json!({"event": "PaymentMeta", "entry_ref": h32(&d["pay_ref"])?, "meta": hex0x(&meta)}))
}

fn executed_row(d: &Value) -> Option<Value> {
    Some(json!({"event": "MetaTransactionExecuted", "from": holder_s(&d["from"])?, "relayer": near_id(d["relayer"].as_str()?).ok()?,
                "lane": h32(&d["lane"])?, "nonce": d["nonce"].as_u64()?.to_string(), "digest": h32(&d["digest"])?}))
}

fn fee_row(contract: &str, token: &str, d: &Value) -> Option<Value> {
    Some(json!({"event": "RelayFeePaid", "contract": contract, "token": token, "entry_ref": h32(&d["ref"])?,
                "target": near_id(d["target"].as_str()?).ok()?, "from": holder_s(&d["payer"])?, "to": holder_s(&d["payee"])?,
                "amount": amount(&d["amount"])?}))
}

// ------------------------------------------------------------------ adapter

/// A NEAR JSON-RPC error: `cause` = its `cause.name` (`UNKNOWN_BLOCK`, `INVALID_TRANSACTION`, …).
#[derive(Debug)]
pub struct RpcError {
    pub cause: String,
    pub body: Value,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NEAR RPC {}: {}", self.cause, self.body)
    }
}

impl std::error::Error for RpcError {}

fn cause_of(e: &anyhow::Error) -> Option<&str> {
    e.downcast_ref::<RpcError>().map(|r| r.cause.as_str())
}

fn transport(e: anyhow::Error) -> SimError {
    SimError::Transport(format!("{e:#}"))
}

/// A view's own failure (the contract panicked) kills the job; anything else is retried.
fn sim(e: anyhow::Error) -> SimError {
    match cause_of(&e) {
        Some("CONTRACT_EXECUTION_ERROR") => SimError::Revert(format!("{e:#}")),
        _ => transport(e),
    }
}

/// `(height, 0x hash)` of a block.
fn header(b: &Value) -> Result<(u64, String)> {
    let height = b["header"]["height"].as_u64().ok_or_else(|| anyhow!("block without height"))?;
    let hash = b58_32(b["header"]["hash"].as_str().ok_or_else(|| anyhow!("block without hash"))?)?;
    Ok((height, hex0x(&hash)))
}

pub struct NearAdapter {
    key: String,
    network: [u8; 32],
    network_b58: String,
    rpc: Vec<String>,
    http: reqwest::Client,
    quorum: usize,
    lanes: Vec<Lane>,
    pks: Vec<[u8; 32]>,
    signers: Vec<LocalSigner>,
    relay_fee: RelayFeePolicy,
    dex: Option<String>,
    /// `ref` ⇒ when this node last sent `relay_timeout` for it.
    timeouts: Mutex<HashMap<[u8; 32], u64>>,
}

struct Work {
    op: MetaOp,
    auth_raw: Vec<u8>,
    entry: Entry,
}

impl NearAdapter {
    pub fn new(cfg: &ChainCfg, signers: &[LocalSigner]) -> Result<Self> {
        if cfg.rpc_urls.is_empty() || signers.is_empty() {
            bail!("chain {}: needs rpc_urls and at least one lane", cfg.chain_key());
        }
        let net = cfg.network.as_deref().ok_or_else(|| anyhow!("near: network must be the genesis hash (base58)"))?;
        let network = b58_32(net).context("near: network must be the genesis hash (base58 of 32 bytes)")?;
        let dex = match cfg.params.get("dex") {
            None => None,
            Some(v) => Some(near_id(v.as_str().ok_or_else(|| anyhow!("params.dex must be a string"))?).context("params.dex")?),
        };
        let (mut lanes, mut pks, mut own) = (Vec::new(), Vec::new(), Vec::new());
        for (s, &i) in signers.iter().zip(&cfg.lanes) {
            let LocalSigner::Ed(k) = s else { bail!("near lanes are ed25519") };
            let pk = k.verifying_key().to_bytes();
            lanes.push(Lane { index: i, address: alloy::hex::encode(pk) });
            pks.push(pk);
            own.push(LocalSigner::Ed(k.clone()));
        }
        Ok(Self {
            key: cfg.chain_key(),
            network,
            network_b58: net.to_string(),
            rpc: cfg.rpc_urls.clone(),
            http: reqwest::Client::builder().timeout(Duration::from_secs(20)).build()?,
            quorum: cfg.finality.quorum.max(1),
            lanes,
            pks,
            signers: own,
            relay_fee: RelayFeePolicy::from_cfg(cfg)?,
            dex,
            timeouts: Mutex::new(HashMap::new()),
        })
    }

    async fn rpc_at(&self, url: &str, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": "scaas", "method": method, "params": params});
        let v: Value = self.http.post(url).json(&body).send().await?.json().await?;
        if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
            let cause = e.pointer("/cause/name").or_else(|| e.get("name")).and_then(Value::as_str).unwrap_or("UNKNOWN").to_string();
            return Err(RpcError { cause, body: e.clone() }.into());
        }
        v.get("result").cloned().ok_or_else(|| anyhow!("{method}: no result"))
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        self.rpc_at(&self.rpc[0], method, params).await
    }

    /// `rpc_urls[0]`'s answer; with `quorum > 1`, further endpoints must return the same `pick` (event bodies follow the
    /// same rule as block hashes, as Aptos review L3).
    async fn agreed(&self, method: &str, params: Value, pick: fn(&Value) -> Value) -> Result<Value> {
        let v = self.rpc(method, params.clone()).await?;
        if self.quorum > 1 {
            let want = pick(&v);
            let mut agree = 1;
            for url in &self.rpc[1..] {
                if matches!(self.rpc_at(url, method, params.clone()).await, Ok(o) if pick(&o) == want) {
                    agree += 1;
                }
            }
            if agree < self.quorum {
                bail!("{method}: {agree} endpoint(s) agree, quorum is {}", self.quorum);
            }
        }
        Ok(v)
    }

    async fn view(&self, account: &str, method: &str, args: &[u8]) -> Result<Vec<u8>> {
        let v = self.rpc("query", json!({"request_type": "call_function", "finality": "final", "account_id": account,
                                         "method_name": method, "args_base64": b64(args)})).await?;
        if let Some(e) = v.get("error").and_then(Value::as_str) {
            return Err(RpcError { cause: "CONTRACT_EXECUTION_ERROR".into(), body: json!(e) }.into());
        }
        v["result"].as_array().ok_or_else(|| anyhow!("view {method}: no result"))?.iter()
            .map(|x| x.as_u64().and_then(|n| u8::try_from(n).ok()).ok_or_else(|| anyhow!("view {method}: bad result byte")))
            .collect()
    }

    /// `None` = no such account; `Some(code deployed)`.
    async fn has_code(&self, account: &str) -> Result<Option<bool>> {
        match self.rpc("query", json!({"request_type": "view_account", "finality": "final", "account_id": account})).await {
            Ok(v) => Ok(Some(v["code_hash"].as_str().ok_or_else(|| anyhow!("view_account: no code_hash"))? != NO_CODE)),
            Err(e) if cause_of(&e) == Some("UNKNOWN_ACCOUNT") => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn gas_price(&self) -> Result<u128> {
        dec_u128(&self.rpc("gas_price", json!([null])).await?["gas_price"], "gas_price")
    }

    async fn final_block(&self) -> Result<[u8; 32]> {
        let b = self.rpc("block", json!({"finality": "final"})).await?;
        b58_32(b["header"]["hash"].as_str().ok_or_else(|| anyhow!("block without hash"))?)
    }

    fn work(&self, job: &Job) -> Result<Work> {
        let o = job.op.as_ref().ok_or_else(|| anyhow!("not a signed_op job"))?;
        let op = MetaOp::decode(&hex_field(&o["payload"], "payload")?)?;
        if op.op != OP_PAY {
            bail!("only pay ops (op 0) are relayed on NEAR");
        }
        if op.network != self.network {
            bail!("the payload is for another network than {}", self.network_b58);
        }
        if o["contract"].as_str() != Some(op.contract.as_str()) {
            bail!("op.contract is not the payload's token {}", op.contract);
        }
        // a plain job's lane attaches what the token's view asks: only configured (startup-checked) tokens
        if !self.relay_fee.tokens.contains(&op.contract) {
            bail!("token {} is not a configured token of this chain", op.contract);
        }
        let auth_raw = hex_field(&o["signature"], "signature")?;
        let entry = entry(&self.relay_fee, &op, o)?;
        job_gas(&entry, &Auth::decode(&auth_raw)?)?;
        Ok(Work { op, auth_raw, entry })
    }

    fn lane_of(&self, account: &str) -> Option<usize> {
        self.lanes.iter().position(|l| l.address == account)
    }

    async fn sign_call(&self, lane: usize, nonce: u64, call: &Call) -> Result<(String, Vec<u8>)> {
        let s = self.signers.get(lane).ok_or_else(|| anyhow!("no lane {lane}"))?;
        let tx = function_call_tx(&self.lanes[lane].address, &self.pks[lane], nonce, &self.final_block().await?, call);
        let hash = tx_hash(&tx);
        let sig = s.sign(&hash)?;
        Ok((hex0x(&hash), signed_tx(&tx, &sig)))
    }

    async fn block_height_of(&self, hash: &Value) -> Result<u64> {
        let hash = hash.as_str().ok_or_else(|| anyhow!("outcome without block_hash"))?;
        Ok(header(&self.rpc("block", json!({"block_id": hash})).await?)?.0)
    }

    /// The final outcome of `tx_id` (`0x` + 64 hex), asked with each lane as sender (the RPC routes by sender); `None` =
    /// not known to the node.
    async fn find_tx(&self, tx_id: &str) -> Result<Option<Value>> {
        let hash: [u8; 32] = alloy::hex::decode(tx_id.strip_prefix("0x").unwrap_or(tx_id))?.try_into()
            .map_err(|_| anyhow!("bad tx id {tx_id}"))?;
        let key = bs58::encode(hash).into_string();
        for lane in &self.lanes {
            match self.rpc("EXPERIMENTAL_tx_status", json!({"tx_hash": key, "sender_account_id": lane.address, "wait_until": "NONE"})).await {
                Ok(v) => return Ok(Some(v)),
                Err(e) if cause_of(&e) == Some("UNKNOWN_TRANSACTION") => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    /// A relay-fee router job (spec §5 escrow tracking, as TON): released (`on_settle` returned true) = mined; else the
    /// router's entry: gone = refunded or the hold refused (reverted: the payer was not charged); still there = pending,
    /// and past its `deadline` (no settlement in flight) this node sends `relay_timeout(ref)` itself (anyone may), again
    /// after `RELAY_TIMEOUT_RETRY_S`; `RELAY_STUCK_S` past the deadline the job ends reverted so the lane moves on.
    async fn escrow_status(&self, v: &Value, height: u64) -> Result<TxStatus> {
        let router = self.relay_fee.router.as_deref().ok_or_else(|| anyhow!("no router configured"))?;
        let value = outcome_status(&v["status"])?;
        if matches!(&value, Ok(Some(b)) if b == &[1]) {
            return Ok(TxStatus::Mined { height, tx_hash: None });
        }
        let args = b64d(v.pointer("/transaction/actions/0/FunctionCall/args").and_then(Value::as_str).ok_or_else(|| anyhow!("relay without args"))?)?;
        let r = relay_args_ref(&args)?;
        let Some((deadline, stage)) = decode_pending(&self.view(router, "pending", &r).await?)? else {
            let why = value.err().map(|f| format!(" ({f})")).unwrap_or_default();
            return Ok(TxStatus::Reverted { reason: format!("relay fee refunded: the call failed, the hold was refused or the relay timed out (the payer was not charged){why}") });
        };
        let now = now();
        if now > deadline.saturating_add(RELAY_STUCK_S) {
            return Ok(TxStatus::Reverted { reason: format!("escrow entry {} still pending {RELAY_STUCK_S} s past its deadline: relay_timeout(ref) settles it", hex0x(&r)) });
        }
        let due = now > deadline && stage != 2
            && self.timeouts.lock().ok().and_then(|t| t.get(&r).copied()).is_none_or(|at| now >= at + RELAY_TIMEOUT_RETRY_S);
        if due {
            let lane = v.pointer("/transaction/signer_id").and_then(Value::as_str).and_then(|s| self.lane_of(s));
            match lane {
                Some(lane) => {
                    let call = Call { receiver: router.into(), method: "relay_timeout".into(), args: r.to_vec(), gas: GAS_RELAY_TIMEOUT, deposit: 0 };
                    let sent = async {
                        let (_, raw) = self.sign_call(lane, self.sequence(lane).await?, &call).await?;
                        self.rpc("send_tx", json!({"signed_tx_base64": b64(&raw), "wait_until": "NONE"})).await
                    };
                    match sent.await {
                        Ok(_) => {
                            if let Ok(mut t) = self.timeouts.lock() {
                                t.insert(r, now);
                            }
                        }
                        Err(e) => tracing::warn!(chain = %self.key, "relay_timeout not sent; retry: {e:#}"),
                    }
                }
                None => tracing::warn!(chain = %self.key, "relay past its deadline was not sent by one of our lanes"),
            }
        }
        Ok(TxStatus::Pending)
    }

    /// R9: a subject's SCaaS key set on each configured token (`(kind, key_data)`; `None` = no account there). Keys
    /// live per token (spec §3.1), so they can drift between tokens; this is what the node shows.
    pub async fn key_sets(&self, holder: &Holder) -> Result<Vec<(String, Option<Vec<(u16, Vec<u8>)>>)>> {
        let mut args = Vec::new();
        holder.write(&mut args);
        let mut out = Vec::new();
        for t in &self.relay_fee.tokens {
            let b = self.view(t, "subject", &args).await?;
            let mut r = Reader::new(&b);
            let keys = r.option(|r| {
                let n = r.u32()?;
                let mut keys = Vec::new();
                for _ in 0..n {
                    keys.push((r.u16()?, r.bytes()?.to_vec()));
                }
                Ok(keys)
            })?;
            out.push((t.clone(), keys));
        }
        Ok(out)
    }
}

#[async_trait]
impl ChainAdapter for NearAdapter {
    fn family(&self) -> Family {
        Family::Near
    }

    fn chain_key(&self) -> &str {
        &self.key
    }

    fn lanes(&self) -> &[Lane] {
        &self.lanes
    }

    /// R80: the payer's lane `(from, lane)` has passed the op's nonce (every NEAR job kind consumes a lane).
    async fn op_consumed(&self, job: &Job) -> Result<Option<bool>> {
        let Ok(w) = self.work(job) else { return Ok(None) };
        let mut args = Vec::new();
        w.op.from.write(&mut args);
        args.extend_from_slice(&w.op.lane);
        let b = self.view(&w.op.contract, "lane_nonce", &args).await?;
        let next = u64::from_le_bytes(b.try_into().map_err(|_| anyhow!("bad lane_nonce result"))?);
        Ok(Some(next > w.op.nonce))
    }

    /// The §5 checks, then the entry's `*_check` view as the lane (`Revert` = the job dies with the contract's reason),
    /// the attached deposit = what it reports, and, for a fee that is the node's, the fee floor.
    async fn build(&self, job: &Job, lane: usize) -> std::result::Result<Built, SimError> {
        let revert = |e: anyhow::Error| SimError::Revert(format!("{e:#}"));
        let w = self.work(job).map_err(|e| SimError::Revert(format!("bad payload: {e:#}")))?;
        if w.op.valid_until <= now() {
            return Err(SimError::Revert("payload expired".into()));
        }
        let lane_id = self.lanes.get(lane).ok_or_else(|| SimError::Transport(format!("no lane {lane}")))?.address.clone();
        let fee = marker(&self.relay_fee, &w.op, &w.entry).cloned();
        if fee.is_some() {
            relay_payee(&self.relay_fee, &w.op, &w.entry, &lane_id).map_err(revert)?;
        }
        let mut call = call_of(&self.relay_fee, &w.entry, &w.op, &w.auth_raw).map_err(revert)?;
        call.deposit = match &w.entry {
            Entry::FeeRouter { target, .. } => {
                match self.has_code(target).await.map_err(transport)? {
                    None => return Err(SimError::Revert(format!("relay-fee target {target} does not exist"))),
                    Some(false) => return Err(SimError::Revert(format!("relay-fee target {target} has no code"))),
                    Some(true) => {}
                }
                let rc = self.view(&call.receiver, "relay_check", &call.args).await.map_err(sim)?;
                let (deposit, gas) = decode_router_check(&rc).map_err(transport)?.map_err(|e| SimError::Revert(format!("relay_check: {e}")))?;
                if gas != call.gas {
                    return Err(SimError::Revert(format!("router relay_check needs {gas} gas, the node pins {}", call.gas)));
                }
                let hold = [borsh_str(&call.receiver), borsh_str(&lane_id), w.op.borsh(), w.auth_raw.clone()].concat();
                let hc = self.view(&w.op.contract, "relay_hold_check", &hold).await.map_err(sim)?;
                let held = decode_check(&hc).map_err(transport)?.map_err(|e| SimError::Revert(format!("relay_hold_check: {e}")))?;
                deposit.checked_add(held).ok_or_else(|| SimError::Revert("deposit overflow".into()))?
            }
            // + 0 yoctoNEAR: no `mtx_*` / `relay_fee_*` entry has a NEP 1-yocto rule (spec §3.2: authority is the signature)
            _ => {
                let args = [borsh_str(&lane_id), call.args.clone()].concat();
                let c = self.view(&call.receiver, &format!("{}_check", call.method), &args).await.map_err(sim)?;
                decode_check(&c).map_err(transport)?.map_err(|e| SimError::Revert(format!("{}_check: {e}", call.method)))?
            }
        };
        if fee.as_ref().is_some_and(|m| pays(&w.op, Some(m)) || w.op.to == Holder::Near(lane_id.clone())) {
            let price = self.gas_price().await.map_err(transport)?;
            let quote = u128::from(call.gas).saturating_mul(price).saturating_add(call.deposit);
            fee_covers(&self.relay_fee, &w.op, quote).map_err(revert)?;
        }
        let meta = json!({"receiver": call.receiver, "method": call.method, "gas": call.gas, "deposit": call.deposit.to_string()});
        Ok(Built { job_id: job.id, body: call.args, valid_until: w.op.valid_until, meta })
    }

    async fn sign(&self, built: Built, lane: usize, sequence: u64) -> Result<Signed> {
        let m = &built.meta;
        let s = |k: &str| m[k].as_str().map(str::to_string).ok_or_else(|| anyhow!("built without {k}"));
        let call = Call {
            receiver: s("receiver")?,
            method: s("method")?,
            args: built.body,
            gas: m["gas"].as_u64().ok_or_else(|| anyhow!("built without gas"))?,
            deposit: dec_u128(&m["deposit"], "deposit")?,
        };
        let (tx_id, raw) = self.sign_call(lane, sequence, &call).await?;
        Ok(Signed { job_id: built.job_id, tx_id, raw, valid_until: built.valid_until, sequence })
    }

    /// `INVALID_TRANSACTION` (nonce, balance, expired block hash, signature…): the same bytes never pass ⇒ `Rejected`.
    async fn submit(&self, signed: &Signed) -> Result<()> {
        match self.rpc("send_tx", json!({"signed_tx_base64": b64(&signed.raw), "wait_until": "NONE"})).await {
            Ok(_) => Ok(()),
            Err(e) if cause_of(&e) == Some("INVALID_TRANSACTION") => Err(Rejected(format!("{e:#}")).into()),
            Err(e) => Err(e),
        }
    }

    /// Mined / reverted only once every receipt is in a final block (`FINAL`); a failed receipt is reported reverted with
    /// its reason, never retried (the lane nonce moved; the payer's op was not consumed).
    async fn tx_status(&self, tx_id: &str) -> Result<TxStatus> {
        let Some(v) = self.find_tx(tx_id).await? else { return Ok(TxStatus::Unknown) };
        if v["final_execution_status"].as_str() != Some("FINAL") {
            return Ok(TxStatus::Pending);
        }
        let height = self.block_height_of(&v["transaction_outcome"]["block_hash"]).await?;
        let relay = v.pointer("/transaction/actions/0/FunctionCall/method_name").and_then(Value::as_str) == Some("relay");
        if relay && self.relay_fee.router.is_some() && v["transaction"]["receiver_id"].as_str() == self.relay_fee.router.as_deref() {
            return self.escrow_status(&v, height).await;
        }
        Ok(match outcome_status(&v["status"])? {
            Ok(_) => TxStatus::Mined { height, tx_hash: None },
            Err(reason) => TxStatus::Reverted { reason },
        })
    }

    /// The lane's next nonce: its access key's nonce + 1.
    async fn sequence(&self, lane: usize) -> Result<u64> {
        let pk = self.pks.get(lane).ok_or_else(|| anyhow!("no lane {lane}"))?;
        let v = self.rpc("query", json!({"request_type": "view_access_key", "finality": "optimistic",
            "account_id": self.lanes[lane].address, "public_key": format!("ed25519:{}", bs58::encode(pk).into_string())})).await?;
        v["nonce"].as_u64().and_then(|n| n.checked_add(1)).ok_or_else(|| anyhow!("bad access key nonce"))
    }

    async fn lane_balance(&self, lane: usize) -> Result<Option<u128>> {
        let a = &self.lanes.get(lane).ok_or_else(|| anyhow!("no lane {lane}"))?.address;
        let v = self.rpc("query", json!({"request_type": "view_account", "finality": "final", "account_id": a})).await?;
        Ok(dec_u128(&v["amount"], "amount").ok())
    }

    async fn tx_fee(&self, tx_id: &str) -> Result<Option<u128>> {
        let Some(v) = self.find_tx(tx_id).await? else { return Ok(None) };
        let burnt = std::iter::once(&v["transaction_outcome"]).chain(v["receipts_outcome"].as_array().into_iter().flatten())
            .map(|o| dec_u128(&o["outcome"]["tokens_burnt"], "tokens_burnt").unwrap_or(0))
            .fold(0u128, u128::saturating_add);
        Ok(Some(burnt))
    }

    /// The `final` block; with `quorum > 1` further endpoints must agree on its hash.
    async fn final_head(&self) -> Result<Option<Head>> {
        let (height, hash) = header(&self.rpc("block", json!({"finality": "final"})).await?)?;
        let mut agree = 1;
        for url in &self.rpc[1..] {
            if let Ok(b) = self.rpc_at(url, "block", json!({"block_id": height})).await {
                if header(&b).ok().map(|h| h.1).as_deref() == Some(hash.as_str()) {
                    agree += 1;
                }
            }
        }
        Ok((agree >= self.quorum).then_some(Head { height, hash }))
    }

    /// The block at `height`, or the one produced last before it (NEAR skips heights).
    async fn block_hash(&self, height: u64) -> Result<String> {
        for h in (height.saturating_sub(MAX_SKIP)..=height).rev() {
            match self.rpc("block", json!({"block_id": h})).await {
                Ok(b) => return Ok(header(&b)?.1),
                Err(e) if cause_of(&e) == Some("UNKNOWN_BLOCK") => continue,
                Err(e) => return Err(e),
            }
        }
        bail!("no block produced in {MAX_SKIP} heights up to {height}")
    }

    /// Every chunk included at each height of [from, to]: the transactions sent to a configured token, the router or
    /// the DEX, read back as final outcomes (`tx_events`); a transaction whose receipts are not all final yet keeps the
    /// range open (`Err`). ponytail: one RPC round per block and per watched transaction, and only transactions sent
    /// TO a configured contract — a third-party contract calling a token (e.g. its own `ft_transfer`) is not seen; a
    /// busy chain needs NEAR Lake / an indexer feed (T21 note).
    async fn events(&self, from: u64, to: u64, contracts: &[String]) -> Result<Vec<Value>> {
        let tokens: Vec<String> = contracts.iter().filter_map(|c| near_id(c).ok()).collect();
        if tokens.is_empty() && !contracts.is_empty() {
            bail!("none of the {} registered tokens is a NEAR account id", contracts.len());
        }
        if tokens.is_empty() || from > to {
            return Ok(vec![]);
        }
        let ids = Ids { tokens, router: self.relay_fee.router.clone(), dex: self.dex.clone() };
        let watched = |a: &str| ids.tokens.iter().chain(&ids.router).chain(&ids.dex).any(|x| x == a);
        let mut out = Vec::new();
        for h in from..=to {
            let b = match self.agreed("block", json!({"block_id": h}), |b| json!([b["header"]["hash"], b["chunks"]])).await {
                Ok(b) => b,
                Err(e) if cause_of(&e) == Some("UNKNOWN_BLOCK") => continue,
                Err(e) => return Err(e),
            };
            let (_, bh) = header(&b)?;
            for c in b["chunks"].as_array().into_iter().flatten().filter(|c| c["height_included"].as_u64() == Some(h)) {
                let id = c["chunk_hash"].as_str().ok_or_else(|| anyhow!("block {h}: chunk without hash"))?;
                let ch = self.agreed("chunk", json!({"chunk_id": id}), |c| c["transactions"].clone()).await?;
                for t in ch["transactions"].as_array().into_iter().flatten() {
                    let (Some(hash), Some(signer), Some(recv)) = (t["hash"].as_str(), t["signer_id"].as_str(), t["receiver_id"].as_str()) else {
                        bail!("chunk {id}: bad transaction {t}");
                    };
                    if !watched(recv) {
                        continue;
                    }
                    let s = self.agreed("EXPERIMENTAL_tx_status", json!({"tx_hash": hash, "sender_account_id": signer, "wait_until": "NONE"}),
                        |s| json!([s["final_execution_status"], s["status"], s["receipts_outcome"]])).await?;
                    if s["final_execution_status"].as_str() != Some("FINAL") {
                        bail!("transaction {hash} of block {h} is not final yet");
                    }
                    out.extend(tx_events(&ids, &s, h, &bh, &hex0x(&b58_32(hash)?)));
                }
            }
        }
        Ok(out)
    }

    /// Spec §5 startup errors (R11, NODE-STO-07): the RPC's genesis is the configured network; every configured id
    /// (tokens, router, executor, DEX) exists with code and has NO access key (else halted: the lane never starts, the
    /// runner retries); each token carries this network; the router's `executor()` is the configured executor; every
    /// lane is registered (`storage_deposit`) on every token.
    async fn start_check(&self) -> Result<()> {
        let st = self.rpc("status", json!([])).await?;
        let g = st["genesis_hash"].as_str().ok_or_else(|| anyhow!("status without genesis_hash"))?;
        if g != self.network_b58 {
            bail!("the RPC's genesis hash {g} is not the configured network {}", self.network_b58);
        }
        let mut ids: Vec<(&str, &str)> = self.relay_fee.tokens.iter().map(|t| (t.as_str(), "token")).collect();
        ids.extend(self.relay_fee.router.as_deref().map(|r| (r, "router")));
        ids.extend(self.relay_fee.executor.as_deref().map(|e| (e, "executor")));
        ids.extend(self.dex.as_deref().map(|d| (d, "dex")));
        for (id, what) in &ids {
            match self.has_code(id).await? {
                None => bail!("missing contract id: {what} {id} does not exist"),
                Some(false) => bail!("missing contract id: {what} {id} has no code"),
                Some(true) => {}
            }
            let keys = self.rpc("query", json!({"request_type": "view_access_key_list", "finality": "final", "account_id": id})).await?;
            if keys["keys"].as_array().is_none_or(|k| !k.is_empty()) {
                bail!("{what} {id} has an access key: the chain is halted (spec §3.9: every SCaaS account is keyless)");
            }
        }
        for t in &self.relay_fee.tokens {
            let net: Vec<u8> = serde_json::from_slice(&self.view(t, "network", &[]).await?).context("token network()")?;
            if net != self.network {
                bail!("token {t} network {} is not this chain's genesis {}", hex0x(&net), hex0x(&self.network));
            }
            for l in &self.lanes {
                let b = self.view(t, "storage_balance_of", &serde_json::to_vec(&json!({"account_id": l.address}))?).await?;
                if serde_json::from_slice::<Value>(&b)?.is_null() {
                    bail!("lane {} is not registered on token {t} (storage_deposit)", l.address);
                }
            }
        }
        if let (Some(r), Some(e)) = (&self.relay_fee.router, &self.relay_fee.executor) {
            let x = Reader::new(&self.view(r, "executor", &[]).await?).account()?;
            if x != *e {
                bail!("router {r} executor() is {x}, not params.relay_fee.executor {e}");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::sync::{Arc, Mutex};

    const NV: &str = include_str!("../../../smartcontracts/near/vectors/near-vectors.json");
    const TXV: &str = include_str!("../../../smartcontracts/near/vectors/near-tx.json");
    const PAYMETA: &str = include_str!("../../../smartcontracts/vectors/metatx/paymeta.json");
    const NET_B58: &str = "68XTWuVmYJkVmj4HM9zFwXdDiS4DE2KX7RbVBdRERiCk";
    const TOKEN: &str = "token.test.near";
    const ROUTER: &str = "relayfee.test.near";
    const EXECUTOR: &str = "relayexec.test.near";
    const DEX: &str = "dex.test.near";
    const NO_CODE: &str = "11111111111111111111111111111111";

    fn nv() -> Value {
        serde_json::from_str(NV).unwrap()
    }

    fn hx(v: &Value) -> Vec<u8> {
        alloy::hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
    }

    fn b32(v: &Value) -> [u8; 32] {
        hx(v).try_into().unwrap()
    }

    fn h(b: &[u8]) -> String {
        alloy::hex::encode(b)
    }

    fn b64(b: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    fn row(name: &str) -> Value {
        nv()["metaops"]["vectors"].as_array().unwrap().iter().find(|m| m["name"] == name).unwrap_or_else(|| panic!("{name}")).clone()
    }

    fn bvec(b: &[u8]) -> Vec<u8> {
        [(b.len() as u32).to_le_bytes().to_vec(), b.to_vec()].concat()
    }

    fn bstr(s: &str) -> Vec<u8> {
        bvec(s.as_bytes())
    }

    /// Borsh `Auth` of a vector row's `auth` (common/src/auth.rs: 0 ed25519, 1 secp256k1, 2 passkey).
    fn auth_bytes(a: &Value) -> Vec<u8> {
        match a["kind"].as_str().unwrap() {
            "ed25519" => [vec![0], hx(&a["key"]), hx(&a["sig"])].concat(),
            "secp256k1" => [vec![1], hx(&a["key"]), hx(&a["sig"]), vec![a["v"].as_u64().unwrap() as u8]].concat(),
            "passkey" => [vec![2], hx(&a["key"]), bvec(&hx(&a["authenticatorData"])), bstr(a["clientDataJSON"].as_str().unwrap()), hx(&a["sig"])]
                .concat(),
            "msig" => {
                let sigs = a["sigs"].as_array().unwrap();
                let mut b = [vec![3], bvec(&hx(&a["keyData"])), (sigs.len() as u32).to_le_bytes().to_vec()].concat();
                for s in sigs {
                    b.push(s["index"].as_u64().unwrap() as u8);
                    b.extend(auth_bytes(&s["auth"]));
                }
                b
            }
            k => panic!("{k}"),
        }
    }

    fn op_of(name: &str) -> MetaOp {
        MetaOp::decode(&hx(&row(name)["encoding"])).unwrap()
    }

    /// The signed_op job fields of a vector row (`payload` = the encoding, `signature` = Borsh `Auth`).
    fn o_of(name: &str, extra: Value) -> Value {
        let r = row(name);
        let mut o = json!({"payload": r["encoding"], "signature": h(&auth_bytes(&r["auth"])), "contract": r["fields"]["contract"]});
        for (k, v) in extra.as_object().unwrap() {
            o[k] = v.clone();
        }
        o
    }

    fn o_op(op: &MetaOp, auth: &[u8], extra: Value) -> Value {
        let mut o = json!({"payload": h(&op.encode()), "signature": h(auth), "contract": op.contract});
        for (k, v) in extra.as_object().unwrap() {
            o[k] = v.clone();
        }
        o
    }

    fn job(o: Value) -> Job {
        Job { id: 1, op: Some(o), ..serde_json::from_value(json!({"id": 1})).unwrap() }
    }

    fn pol() -> RelayFeePolicy {
        RelayFeePolicy {
            router: Some(ROUTER.into()),
            executor: Some(EXECUTOR.into()),
            tokens: vec![TOKEN.into()],
            params: crate::config::RelayParams { min_amount: 1, ..Default::default() },
            min_yocto_value: HashMap::from([(TOKEN.to_string(), 1_000)]),
        }
    }

    fn rref(name: &str) -> Value {
        nv()["relayRefs"].as_array().unwrap().iter().find(|r| r["name"] == name).unwrap().clone()
    }

    fn wrapper_job(name: &str) -> (MetaOp, Value) {
        let r = rref(name);
        let o = o_of(r["payment"].as_str().unwrap(), json!({"kind": "relay_fee", "ref": r["ref"], "extra": {"call": r["call"], "route": "wrapper"}}));
        (op_of(r["payment"].as_str().unwrap()), o)
    }

    fn router_job(name: &str, target_gas: &str, target_deposit: &str) -> (MetaOp, Value) {
        let r = rref(name);
        let o = o_of(r["payment"].as_str().unwrap(), json!({"kind": "relay_fee", "ref": r["ref"],
            "extra": {"call": r["call"], "route": "router", "target_gas": target_gas, "target_deposit": target_deposit}}));
        (op_of(r["payment"].as_str().unwrap()), o)
    }

    /// A router payment for (target, method, args) consistent with its ref (signature not checked off chain).
    fn router_op(target: &str, method: &str, args: &[u8], to: Holder) -> (MetaOp, Value) {
        let mut op = op_of("relay_fee_pay_router_short");
        let call = router_call(target, method, args);
        let tb = [&[target.len() as u8][..], target.as_bytes()].concat();
        let r = relay_ref(&op.network, &tb, &call, &op.extra);
        op.pay_ref = r;
        op.lane = pay_lane(&r);
        op.to = to;
        let o = o_op(&op, &auth_bytes(&row("relay_fee_pay_router_short")["auth"]), json!({"kind": "relay_fee",
            "extra": {"call": h(&call), "route": "router", "target_gas": "30000000000000", "target_deposit": "0"}}));
        (op, o)
    }

    fn check_ok(s: u128) -> Vec<u8> {
        [vec![0], s.to_le_bytes().to_vec()].concat()
    }

    fn check_err(m: &str) -> Vec<u8> {
        [vec![1], bstr(m), 0u128.to_le_bytes().to_vec()].concat()
    }

    fn router_check(storage: u128, deposit: u128, gas: u64) -> Vec<u8> {
        [vec![0], storage.to_le_bytes().to_vec(), deposit.to_le_bytes().to_vec(), gas.to_le_bytes().to_vec()].concat()
    }

    // ------------------------------------------------------------------------------------------------ fake RPC

    #[derive(Default)]
    struct World {
        genesis: String,
        /// (account, view method) → Borsh / JSON result bytes; missing = the view panics.
        views: HashMap<(String, String), Vec<u8>>,
        /// accounts with code / without code / with an access key.
        code: Vec<String>,
        plain: Vec<String>,
        keyed: Vec<String>,
        gas_price: u128,
        nonce: u64,
        txs: HashMap<String, Value>,
        blocks: Vec<Value>,
        chunks: HashMap<String, Value>,
        send_err: Option<Value>,
        calls: Vec<(String, Value)>,
    }

    fn rpc_err(name: &str) -> Value {
        json!({"name": "HANDLER_ERROR", "cause": {"name": name, "info": {}}, "code": -32000, "message": "Server error"})
    }

    fn answer(w: &mut World, method: &str, p: &Value) -> std::result::Result<Value, Value> {
        w.calls.push((method.to_string(), p.clone()));
        let s = |k: &str| p[k].as_str().unwrap_or_default().to_string();
        match method {
            "status" => Ok(json!({"chain_id": "localnet", "genesis_hash": w.genesis})),
            "gas_price" => Ok(json!({"gas_price": w.gas_price.to_string()})),
            "block" => {
                let b = match (&p["finality"], &p["block_id"]) {
                    (Value::String(_), _) => w.blocks.last().cloned(),
                    (_, Value::Number(n)) => w.blocks.iter().find(|b| b["header"]["height"].as_u64() == n.as_u64()).cloned(),
                    (_, Value::String(x)) => w.blocks.iter().find(|b| b["header"]["hash"] == *x).cloned(),
                    _ => None,
                };
                b.ok_or_else(|| rpc_err("UNKNOWN_BLOCK"))
            }
            "chunk" => w.chunks.get(&s("chunk_id")).cloned().ok_or_else(|| rpc_err("UNKNOWN_CHUNK")),
            "send_tx" => w.send_err.clone().map_or(Ok(json!({"final_execution_status": "NONE"})), Err),
            "EXPERIMENTAL_tx_status" => w.txs.get(&s("tx_hash")).cloned().ok_or_else(|| rpc_err("UNKNOWN_TRANSACTION")),
            "query" => match s("request_type").as_str() {
                "view_account" if w.code.contains(&s("account_id")) => Ok(json!({"amount": "5000", "code_hash": "E8jZ1giWcVs7nYUmVrvKYV4AsHnjngjNE5mQ4KCi8Ain"})),
                "view_account" if w.plain.contains(&s("account_id")) => Ok(json!({"amount": "5000", "code_hash": NO_CODE})),
                "view_account" => Err(rpc_err("UNKNOWN_ACCOUNT")),
                "view_access_key_list" => {
                    let k = w.keyed.contains(&s("account_id"));
                    Ok(json!({"keys": if k { json!([{"public_key": "ed25519:x", "access_key": {"nonce": 1, "permission": "FullAccess"}}]) } else { json!([]) }}))
                }
                "view_access_key" => Ok(json!({"nonce": w.nonce, "permission": "FullAccess"})),
                "call_function" => match w.views.get(&(s("account_id"), s("method_name"))) {
                    Some(b) => Ok(json!({"result": b, "logs": [], "block_height": 1})),
                    None => Err(rpc_err("CONTRACT_EXECUTION_ERROR")),
                },
                _ => Err(rpc_err("UNKNOWN")),
            },
            _ => Err(rpc_err("METHOD_NOT_FOUND")),
        }
    }

    async fn serve(w: Arc<Mutex<World>>) -> String {
        use axum::extract::State;
        async fn h(State(w): State<Arc<Mutex<World>>>, body: String) -> axum::Json<Value> {
            let v: Value = serde_json::from_str(&body).unwrap();
            let r = answer(&mut w.lock().unwrap(), v["method"].as_str().unwrap(), &v["params"]);
            axum::Json(match r {
                Ok(r) => json!({"jsonrpc": "2.0", "id": v["id"], "result": r}),
                Err(e) => json!({"jsonrpc": "2.0", "id": v["id"], "error": e}),
            })
        }
        let app = axum::Router::new().fallback(h).with_state(w);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        url
    }

    fn lane0() -> LocalSigner {
        let seed = crate::keys::Seed::from_words(&format!("{}art", "abandon ".repeat(23)), None).unwrap();
        let (c, k) = crate::keys::lane_secret(&seed, "near", 0).unwrap();
        LocalSigner::new(c, &k).unwrap()
    }

    const LANE0: &str = "c5f869f1fa4165f42f2a837376db218644cf0b97dd818b834297e693144695c6";

    fn cfg(url: &str, relay_fee: &str) -> ChainCfg {
        toml::from_str(&format!(
            "family = \"near\"\nnetwork = \"{NET_B58}\"\nrpc_urls = [\"{url}\"]\nlanes = [0]\n\
             tokens = [{{ address = \"{TOKEN}\", decimals = 6 }}]\nfinality = {{ mode = \"instant\" }}\n\
             params = {{ dex = \"{DEX}\"{relay_fee} }}"
        ))
        .unwrap()
    }

    fn fee_cfg(price: &str) -> String {
        format!(", relay_fee = {{ router = \"{ROUTER}\", executor = \"{EXECUTOR}\", min_amount = 1, min_yocto_value = {{ \"{TOKEN}\" = \"{price}\" }} }}")
    }

    /// A healthy chain: genesis = the vectors' network, every contract deployed and keyless, lane 0 registered.
    fn world() -> World {
        let mut w = World { genesis: NET_B58.into(), gas_price: 100_000_000, nonce: 41, ..Default::default() };
        w.code = [TOKEN, ROUTER, EXECUTOR, DEX].map(String::from).to_vec();
        let net: Vec<u8> = serde_json::to_vec(&b32(&nv()["network"]).to_vec()).unwrap();
        w.views.insert((TOKEN.into(), "network".into()), net);
        w.views.insert((ROUTER.into(), "executor".into()), bstr(EXECUTOR));
        w.views.insert((TOKEN.into(), "storage_balance_of".into()), br#"{"total":"1250000000000000000000","available":"0"}"#.to_vec());
        w.blocks.push(json!({"header": {"height": 100, "hash": "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2"}, "chunks": []}));
        w
    }

    async fn adapter(w: World, relay_fee: &str) -> (NearAdapter, Arc<Mutex<World>>) {
        let w = Arc::new(Mutex::new(w));
        let url = serve(w.clone()).await;
        (NearAdapter::new(&cfg(&url, relay_fee), &[lane0()]).unwrap(), w)
    }

    fn sent(w: &Arc<Mutex<World>>) -> Vec<Vec<u8>> {
        let w = w.lock().unwrap();
        w.calls.iter().filter(|c| c.0 == "send_tx")
            .map(|c| base64::engine::general_purpose::STANDARD.decode(c.1["signed_tx_base64"].as_str().unwrap()).unwrap()).collect()
    }

    fn view_args(w: &Arc<Mutex<World>>, method: &str) -> Vec<u8> {
        let w = w.lock().unwrap();
        let c = w.calls.iter().rev().find(|c| c.0 == "query" && c.1["method_name"] == method).unwrap_or_else(|| panic!("{method} not called"));
        base64::engine::general_purpose::STANDARD.decode(c.1["args_base64"].as_str().unwrap()).unwrap()
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    // ------------------------------------------------------------------------------------------------ vectors

    /// Every `metaops` row of near-vectors.json decodes to its fields, re-encodes byte for byte and hashes to its digest;
    /// non-canonical input is refused.
    #[test]
    fn near_metaop_decode_vectors() {
        let d = nv();
        let rows = d["metaops"]["vectors"].as_array().unwrap();
        assert_eq!(rows.len(), 37);
        let mut n_auth = 0;
        let holder = |v: &Value| match (v["Near"].as_str(), v["Ua"].as_str()) {
            (Some(a), _) => Holder::Near(a.into()),
            (_, Some(u)) => Holder::Ua(b32(&json!(u))),
            _ => panic!("{v}"),
        };
        for r in rows {
            let (f, enc) = (&r["fields"], hx(&r["encoding"]));
            let op = MetaOp::decode(&enc).unwrap_or_else(|e| panic!("{}: {e:#}", r["name"]));
            let want = MetaOp {
                network: b32(&f["network"]),
                contract: f["contract"].as_str().unwrap().into(),
                op: f["op"].as_u64().unwrap() as u8,
                from: holder(&f["from"]),
                to: holder(&f["to"]),
                relayer: f["relayer"].as_str().map(String::from),
                amount: f["amount"].as_str().unwrap().parse().unwrap(),
                pay_ref: b32(&f["pay_ref"]),
                lane: b32(&f["lane"]),
                nonce: f["nonce"].as_u64().unwrap(),
                valid_until: f["valid_until"].as_u64().unwrap(),
                extra: b32(&f["extra"]),
            };
            assert_eq!(op, want, "{}", r["name"]);
            assert_eq!(op.encode(), enc, "{}", r["name"]);
            assert_eq!(op.digest().to_vec(), hx(&r["digest"]), "{}", r["name"]);
            assert_eq!(op.borsh(), enc[15..].to_vec());
            if r["auth"].is_object() && r["auth"]["kind"].is_string() {
                Auth::decode(&auth_bytes(&r["auth"])).unwrap_or_else(|e| panic!("{} auth: {e:#}", r["name"]));
                n_auth += 1;
            }
        }
        assert_eq!(n_auth, rows.len(), "every row's auth decodes");
        assert_eq!(Auth::decode(&auth_bytes(&row("set_guardian_msig")["auth"])).unwrap(), Auth::Msig(vec![Auth::Ed25519]));
        assert_eq!(op_of("pay_ua_ed25519_u128_max").amount, u128::MAX);
        assert_eq!(Holder::Ua([0xab; 32]).display(), format!("0x{}", "ab".repeat(32)));
        assert_eq!(Holder::Near("alice.test.near".into()).display(), "alice.test.near");
        let enc = hx(&row("pay")["encoding"]);
        assert!(MetaOp::decode(&enc[..enc.len() - 1]).is_err(), "truncated");
        assert!(MetaOp::decode(&[&enc[..], &[0]].concat()).is_err(), "trailing");
        assert!(MetaOp::decode(&enc[15..]).is_err(), "no label");
        let mut bad = enc.clone();
        bad[15 + 32 + 4] = b'T'; // token.test.near → Token.test.near: not an account id
        assert!(MetaOp::decode(&bad).is_err(), "upper-case account id");
        let at = 15 + 32 + 4 + 15 + 1; // the `from` Holder tag
        let mut bad = enc.clone();
        bad[at] = 2;
        assert!(MetaOp::decode(&bad).is_err(), "holder tag 2");
        // Auth: trailing, unknown tag, msig in msig, an oversized passkey field
        let a = auth_bytes(&row("pay")["auth"]);
        assert!(Auth::decode(&[&a[..], &[0]].concat()).is_err());
        assert!(Auth::decode(&[&[4u8][..], &a[1..]].concat()).is_err());
        let msig = |inner: &[u8]| [vec![3], bvec(&[0, 1]), 1u32.to_le_bytes().to_vec(), vec![0], inner.to_vec()].concat();
        assert_eq!(Auth::decode(&msig(&a)).unwrap(), Auth::Msig(vec![Auth::Ed25519]));
        assert!(Auth::decode(&msig(&msig(&a))).is_err(), "msig inside msig");
        let pk = |cd: usize| [vec![2], vec![0; 64], bvec(&[0; 37]), bvec(&vec![b'x'; cd]), vec![0; 64]].concat();
        assert_eq!(Auth::decode(&pk(1024)).unwrap(), Auth::Passkey);
        assert!(Auth::decode(&pk(1025)).is_err(), "passkey field over 1024 bytes (contract PASSKEY_FIELD_MAX)");
    }

    /// The node's hand-encoded Borsh transaction and lane signature equal nearcore's (`near-tx.json`, written by
    /// `smartcontracts/near/integration/tests/node_tx_vector.rs` with near-primitives 0.38.0).
    #[test]
    fn tx_matches_near_primitives() {
        let v: Value = serde_json::from_str(TXV).unwrap();
        let s = lane0();
        let pk: [u8; 32] = s.public_key().try_into().unwrap();
        assert_eq!(h(&pk), v["signer"].as_str().unwrap());
        let op = op_of("pay");
        let auth = auth_bytes(&row("pay")["auth"]);
        let call = call_of(&pol(), &Entry::Pay, &op, &auth).unwrap();
        assert_eq!(call.args, hx(&v["args"]));
        let call = Call { gas: v["gas"].as_u64().unwrap(), deposit: dec_u128(&v["deposit"], "deposit").unwrap(), ..call };
        assert_eq!((call.receiver.as_str(), call.method.as_str()), (TOKEN, "mtx_pay"));
        let tx = function_call_tx(LANE0, &pk, 7, &b32(&v["block_hash"]), &call);
        assert_eq!(h(&tx), h(&hx(&v["transaction"])));
        assert_eq!(tx_hash(&tx).to_vec(), hx(&v["hash"]));
        let sig = s.sign(&tx_hash(&tx)).unwrap();
        assert_eq!(sig, hx(&v["signature"]));
        assert_eq!(h(&signed_tx(&tx, &sig)), h(&hx(&v["signed"])));
    }

    // ------------------------------------------------------------------------------------------------ jobs

    #[test]
    fn near_pay_meta_job_checks_commitment() {
        let rows: Vec<Value> = serde_json::from_str(PAYMETA).unwrap();
        for r in &rows {
            let id = meta_pay_id(&hx(&r["salt"]), &hx(&r["meta"]));
            assert_eq!((id.to_vec(), pay_lane(&id).to_vec()), (hx(&r["payId"]), hx(&r["payLane"])), "{}", r["name"]);
        }
        let mut n = 0;
        for v in nv()["metaops"]["vectors"].as_array().unwrap().iter().filter(|v| v["paymetaRow"].is_string()) {
            let pm = rows.iter().find(|r| r["name"] == v["paymetaRow"]).unwrap();
            let (salt, meta) = (hx(&pm["salt"]), hx(&pm["meta"]));
            let op = MetaOp::decode(&hx(&v["encoding"])).unwrap();
            let o = json!({"kind": "pay_meta", "salt": h(&salt), "meta": h(&meta)});
            let wide = RelayFeePolicy { params: crate::config::RelayParams { max_pay_meta_bytes: 8192, ..Default::default() }, ..pol() };
            assert_eq!(entry(&wide, &op, &o).unwrap(), Entry::PayMeta { salt: salt.clone().try_into().unwrap(), meta: meta.clone() }, "{}", v["name"]);
            n += 1;
        }
        assert_eq!(n, 6, "every paymeta.json row has a NEAR pay-meta op");
        let op = op_of("pay_meta_note_utf8");
        let pm = rows.iter().find(|r| r["name"] == "note_utf8").unwrap();
        let o = json!({"kind": "pay_meta", "salt": pm["salt"], "meta": pm["meta"]});
        entry(&pol(), &op, &o).unwrap();
        let bad = |op: &MetaOp, o: &Value| entry(&pol(), op, o).is_err();
        let mut j = o.clone();
        j["meta"] = json!(format!("{}00", pm["meta"].as_str().unwrap()));
        assert!(bad(&op, &j), "meta does not hash to pay_ref");
        j = o.clone();
        j["salt"] = json!(h(&[0; 32]));
        assert!(bad(&op, &j), "salt does not hash to pay_ref");
        j["salt"] = json!(h(&[0; 31]));
        assert!(bad(&op, &j), "salt is 32 bytes");
        assert!(bad(&op, &json!({"kind": "pay_meta", "meta": pm["meta"]})), "no salt");
        assert!(bad(&MetaOp { nonce: 1, ..op.clone() }, &o), "nonce 1");
        assert!(bad(&MetaOp { lane: [1; 32], ..op.clone() }, &o), "another lane");
        let big = vec![0u8; 2049];
        let id = meta_pay_id(&[1; 32], &big);
        let o2 = MetaOp { pay_ref: id, lane: pay_lane(&id), ..op.clone() };
        let bj = json!({"kind": "pay_meta", "salt": h(&[1; 32]), "meta": h(&big)});
        assert!(bad(&o2, &bj), "over max_pay_meta_bytes (2,048 default)");
    }

    /// Spec §2 rows 8–14 / §3.8: `ref` of every relayRefs row; a wrapper job binds to its token as marker and the exact
    /// call bytes (a real entry's arguments, canonical), a router job to the router, its target, method and args.
    #[test]
    fn near_relay_fee_job_checks_ref() {
        let d = nv();
        let net = b32(&d["network"]);
        for r in d["relayRefs"].as_array().unwrap() {
            assert_eq!(relay_ref(&net, &hx(&r["targetBytes"]), &hx(&r["call"]), &b32(&r["salt"])), b32(&r["ref"]), "{}", r["name"]);
            if r["kind"] == "router" {
                assert_eq!(router_call(r["target"].as_str().unwrap(), r["method"].as_str().unwrap(), &hx(&r["args"])), hx(&r["call"]));
            }
        }
        // wrapper: the real add_key call; the short / 4096 rows carry placeholder args (not a canonical entry call)
        let (op, o) = wrapper_job("wrapper_add_key_real");
        let args = hx(&rref("wrapper_add_key_real")["args"]);
        assert_eq!(entry(&pol(), &op, &o).unwrap(), Entry::FeeWrapper { entry: "mtx_add_key".into(), args: args.clone() });
        assert!(entry(&RelayFeePolicy { router: None, executor: None, ..pol() }, &op, &o).is_ok(), "a wrapper needs no router");
        let (sop, so) = wrapper_job("wrapper_short");
        assert!(format!("{:#}", entry(&pol(), &sop, &so).unwrap_err()).contains("call"), "placeholder args");
        // router: open (to = router) and bound payee
        for name in ["router_short", "router_bound"] {
            let (op, o) = router_job(name, "30000000000000", "0");
            let r = rref(name);
            assert_eq!(entry(&pol(), &op, &o).unwrap(), Entry::FeeRouter {
                target: DEX.into(), method: "settle".into(), args: hx(&r["args"]), target_gas: 30 * TGAS, target_deposit: 0 }, "{name}");
        }
        let err = |op: &MetaOp, o: &Value, p: &RelayFeePolicy| format!("{:#}", entry(p, op, o).unwrap_err());
        // binding: other call bytes, another salt, a nonce / lane off the ref, another network, a wrong `ref`
        for (op, o) in [wrapper_job("wrapper_add_key_real"), router_job("router_short", "1", "0")] {
            let mut c = hx(&o["extra"]["call"]);
            let n = c.len();
            c[n - 1] ^= 1;
            let mut j = o.clone();
            j["extra"]["call"] = json!(h(&c));
            assert!(err(&op, &j, &pol()).contains("not bound"), "another call");
            assert!(err(&MetaOp { extra: [0x52; 32], ..op.clone() }, &o, &pol()).contains("not bound"));
            assert!(err(&MetaOp { nonce: 1, ..op.clone() }, &o, &pol()).contains("not bound"));
            assert!(err(&MetaOp { lane: [1; 32], ..op.clone() }, &o, &pol()).contains("not bound"));
            assert!(err(&MetaOp { network: [9; 32], ..op.clone() }, &o, &pol()).contains("not bound"));
            assert!(err(&MetaOp { relayer: None, ..op.clone() }, &o, &pol()).contains("relayer"));
            assert!(err(&MetaOp { relayer: Some("relayer.test.near".into()), ..op.clone() }, &o, &pol()).contains("relayer"));
            j = o.clone();
            j["ref"] = json!(h(&[1; 32]));
            assert!(err(&op, &j, &pol()).contains("op.ref"));
            assert!(err(&op, &o, &RelayFeePolicy { tokens: vec![], ..pol() }).contains("configured"), "token not configured");
            j = o.clone();
            j["extra"]["route"] = json!("other");
            assert!(err(&op, &j, &pol()).contains("route"));
            j["extra"] = json!({"call": o["extra"]["call"]});
            assert!(err(&op, &j, &pol()).contains("route"));
        }
        let (op, o) = router_job("router_short", "1", "0");
        assert!(err(&op, &o, &RelayFeePolicy { router: None, executor: None, ..pol() }).contains("router"), "router not configured");
        // amounts are decimal strings, never JSON numbers
        let mut j = o.clone();
        j["extra"]["target_gas"] = json!(30_000_000_000_000u64);
        assert!(err(&op, &j, &pol()).contains("target_gas"));
        j = o.clone();
        j["extra"]["target_deposit"] = json!(1.5);
        assert!(err(&op, &j, &pol()).contains("target_deposit"));
        j["extra"]["target_deposit"] = json!("-1");
        assert!(err(&op, &j, &pol()).contains("target_deposit"));
        // a wrapper call under the router route, and the reverse, are refused
        let (wop, wo) = wrapper_job("wrapper_add_key_real");
        j = wo.clone();
        j["extra"]["route"] = json!("router");
        j["extra"]["target_gas"] = json!("1");
        j["extra"]["target_deposit"] = json!("0");
        assert!(entry(&pol(), &wop, &j).is_err());
    }

    /// Note 7 / CTR-MTX-27 step 2: never call the router or executor as a target, never `add_key_native` (no key for the
    /// executor), never pay the router, executor or marker (token id) outside its relay-fee route.
    #[test]
    fn relay_fee_target_router_or_executor_refused() {
        let alice = Holder::Near("alice.test.near".into());
        for t in [ROUTER, EXECUTOR] {
            let (op, o) = router_op(t, "relay_timeout", &[0; 32], Holder::Near(ROUTER.into()));
            assert!(format!("{:#}", entry(&pol(), &op, &o).unwrap_err()).contains("router or its executor"), "{t}");
        }
        for t in [TOKEN, "other-token.near"] {
            let (op, o) = router_op(t, "add_key_native", &[0; 8], Holder::Near(ROUTER.into()));
            assert!(format!("{:#}", entry(&pol(), &op, &o).unwrap_err()).contains("add_key_native"), "{t}");
        }
        let (op, o) = router_op(DEX, "settle", &[1; 8], Holder::Near(EXECUTOR.into()));
        assert!(format!("{:#}", entry(&pol(), &op, &o).unwrap_err()).contains("executor"), "pay the executor");
        let (op, o) = router_op(DEX, "settle", &[1; 8], Holder::Near(TOKEN.into()));
        assert!(entry(&pol(), &op, &o).is_err(), "pay the token through the router");
        assert!(entry(&pol(), &router_op(DEX, "settle", &[1; 8], alice.clone()).0, &router_op(DEX, "settle", &[1; 8], alice).1).is_ok());
        // a plain pay / pay-meta to the router, the executor or the token (marker) strands the funds
        for to in [ROUTER, EXECUTOR, TOKEN] {
            let op = MetaOp { to: Holder::Near(to.into()), ..op_of("pay") };
            assert!(format!("{:#}", entry(&pol(), &op, &json!({})).unwrap_err()).contains("never pay"), "{to}");
            assert!(format!("{:#}", entry(&RelayFeePolicy::default(), &MetaOp { to: Holder::Near(TOKEN.into()), ..op.clone() }, &json!({})).unwrap_err())
                .contains("never pay"));
        }
        // a wrapper payment to the router / executor
        let (wop, wo) = wrapper_job("wrapper_add_key_real");
        for to in [ROUTER, EXECUTOR] {
            assert!(entry(&pol(), &MetaOp { to: Holder::Near(to.into()), ..wop.clone() }, &wo).is_err(), "{to}");
        }
    }

    #[test]
    fn unknown_job_kind_is_refused() {
        let op = op_of("pay");
        assert_eq!(entry(&pol(), &op, &json!({})).unwrap(), Entry::Pay);
        for k in [json!("pay-meta"), json!("pay"), json!(""), json!(7), json!(true), json!({})] {
            let e = format!("{:#}", entry(&pol(), &op, &json!({"kind": k})).unwrap_err());
            assert!(e.contains("unknown op.kind"), "{k}: {e}");
        }
        assert!(entry(&pol(), &op, &json!({"meta": "00"})).is_err(), "a kind-less job with meta");
    }

    /// Note 5 / R1: at most 13 passkey signatures per wrapper job (entry + payment), gas within 300 Tgas; note 6: a
    /// router job's relay_gas = 36 Tgas + the payment's signature budget + target_gas ≤ 300 Tgas.
    #[test]
    fn signature_budgets() {
        let pk = [vec![2], vec![0; 64], bvec(&[0; 37]), bvec(&[b'x'; 200]), vec![0; 64]].concat();
        let msig = |n: usize| {
            let mut b = [vec![3], bvec(&[0; 4]), (n as u32).to_le_bytes().to_vec()].concat();
            (0..n).for_each(|i| {
                b.push(i as u8);
                b.extend_from_slice(&pk);
            });
            b
        };
        let wrapper = |n: usize| {
            let call = [&[19u8][..], b"mtx_cancel_recovery", &op_of("cancel_recovery").borsh(), &msig(n)].concat();
            Entry::FeeWrapper { entry: "mtx_cancel_recovery".into(), args: call[20..].to_vec() }
        };
        let pay = Auth::decode(&pk).unwrap();
        assert!(job_gas(&wrapper(12), &pay).unwrap() <= MAX_GAS, "12 + 1 passkeys");
        assert!(format!("{:#}", job_gas(&wrapper(13), &pay).unwrap_err()).contains("13"), "13 + 1 passkeys");
        let ed = Auth::decode(&auth_bytes(&row("pay")["auth"])).unwrap();
        assert!(job_gas(&wrapper(13), &ed).is_ok(), "13 passkeys + an ed25519 payment");
        assert!(job_gas(&Entry::Pay, &ed).unwrap() < job_gas(&Entry::Pay, &pay).unwrap(), "a passkey costs more");
        let router = |tg: u64| Entry::FeeRouter { target: DEX.into(), method: "settle".into(), args: vec![], target_gas: tg * TGAS, target_deposit: 0 };
        assert_eq!(job_gas(&router(10), &ed).unwrap(), (36 + 1 + 10) * TGAS);
        assert_eq!(job_gas(&router(239), &pay).unwrap(), 300 * TGAS);
        assert!(job_gas(&router(240), &pay).is_err(), "over 300 Tgas");
        assert!(job_gas(&router(u64::MAX / TGAS), &pay).is_err(), "no overflow");
    }

    /// Startup: a set but malformed / inconsistent `params.relay_fee` or `params.dex` is an error, never ignored.
    #[test]
    fn relay_fee_config_must_parse() {
        let k = [lane0()];
        let ok = NearAdapter::new(&cfg("http://r", &fee_cfg("170141183460469231731687303715884105729")), &k).unwrap();
        assert_eq!(ok.relay_fee.min_yocto_value[TOKEN], (1u128 << 127) + 1);
        assert_eq!((ok.relay_fee.router.as_deref(), ok.relay_fee.executor.as_deref()), (Some(ROUTER), Some(EXECUTOR)));
        assert_eq!(ok.lanes[0].address, LANE0);
        let none = NearAdapter::new(&cfg("http://r", ""), &k).unwrap();
        assert_eq!(none.relay_fee.router, None);
        for (t, what) in [
            (", relay_fee = { router = \"Bad.near\", executor = \"relayexec.test.near\" }".to_string(), "router"),
            (format!(", relay_fee = {{ router = \"{ROUTER}\" }}"), "executor"),
            (format!(", relay_fee = {{ executor = \"{EXECUTOR}\" }}"), "router"),
            (format!(", relay_fee = {{ router = \"{ROUTER}\", executor = \"{ROUTER}\" }}"), "executor"),
            (format!(", relay_fee = {{ router = \"{TOKEN}\", executor = \"{EXECUTOR}\" }}"), "token"),
            (fee_cfg("-1"), "min_yocto_value"),
            (fee_cfg("1e3"), "min_yocto_value"),
            (format!(", relay_fee = {{ router = \"{ROUTER}\", executor = \"{EXECUTOR}\", min_yocto_value = {{ \"other.near\" = \"1\" }} }}"), "min_yocto_value"),
            (format!(", relay_fee = {{ router = \"{ROUTER}\", executor = \"{EXECUTOR}\", min_ton_value = 1 }}"), "min_ton_value"),
        ] {
            let e = NearAdapter::new(&cfg("http://r", &t), &k).err().unwrap();
            assert!(format!("{e:#}").contains(what), "{t}: {e:#}");
        }
        let mut c = cfg("http://r", "");
        c.params.insert("dex".into(), "Dex".into());
        assert!(format!("{:#}", NearAdapter::new(&c, &k).err().unwrap()).contains("dex"));
        let mut c = cfg("http://r", "");
        c.network = Some("not-base58-0OIl".into());
        assert!(format!("{:#}", NearAdapter::new(&c, &k).err().unwrap()).contains("network"));
    }

    // ------------------------------------------------------------------------------------------------ build / quote

    #[tokio::test]
    async fn relay_fee_target_without_code_refused() {
        for (code, plain) in [(vec![TOKEN, ROUTER, EXECUTOR], vec![DEX]), (vec![TOKEN, ROUTER, EXECUTOR], vec![])] {
            let mut w = world();
            w.code = code.into_iter().map(String::from).collect();
            w.plain = plain.into_iter().map(String::from).collect();
            let (a, _) = adapter(w, &fee_cfg("1000000000000000000000")).await;
            let (_, o) = router_job("router_short", "30000000000000", "0");
            match a.build(&job(o), 0).await {
                Err(SimError::Revert(r)) => assert!(r.contains("no code") || r.contains("does not exist"), "{r}"),
                other => panic!("{other:?}"),
            }
        }
    }

    /// The fee at the node's floor price covers the pinned gas at the node's gas price plus every deposit the job attaches
    /// (`storage_needed`, the router's `deposit_needed` with `target_deposit`, the hold's storage); one unit short is
    /// refused. A sponsored job (bound payee, relay_bound_payee) is not priced.
    #[tokio::test]
    async fn quote_covers_gas_and_storage_needed() {
        // wrapper (open mode: to = the token, the fee pays the lane)
        let (wop, wo) = wrapper_job("wrapper_add_key_real");
        let storage = 1_160 * 10u128.pow(19);
        let gas = job_gas(&entry(&pol(), &wop, &wo).unwrap(), &Auth::decode(&hx(&wo["signature"])).unwrap()).unwrap();
        let quote = gas as u128 * 100_000_000 + storage;
        for (price, ok) in [(quote.div_ceil(wop.amount), true), ((quote - 1) / wop.amount, false)] {
            let mut w = world();
            w.views.insert((TOKEN.into(), "relay_fee_add_key_check".into()), check_ok(storage));
            let (a, _) = adapter(w, &fee_cfg(&price.to_string())).await;
            match (a.build(&job(wo.clone()), 0).await, ok) {
                (Ok(b), true) => assert_eq!(b.meta["deposit"], json!(storage.to_string())),
                (Err(SimError::Revert(r)), false) => assert!(r.contains("below"), "{r}"),
                (r, _) => panic!("price {price}: {r:?}"),
            }
        }
        // router: deposit_needed (entry + payee registration + 2 yocto + target_deposit) + the hold's storage_needed
        let td = 7 * 10u128.pow(21);
        let (rop, ro) = router_job("router_short", "30000000000000", &td.to_string());
        let g = job_gas(&entry(&pol(), &rop, &ro).unwrap(), &Auth::decode(&hx(&ro["signature"])).unwrap()).unwrap();
        let (entry_dep, hold) = (3_140 * 10u128.pow(18) + 1_250 * 10u128.pow(18) + 2 + td, 2_800 * 10u128.pow(18));
        let quote = g as u128 * 100_000_000 + entry_dep + hold;
        for (price, ok) in [(quote.div_ceil(rop.amount), true), ((quote - 1) / rop.amount, false)] {
            let mut w = world();
            w.views.insert((ROUTER.into(), "relay_check".into()), router_check(3_140 * 10u128.pow(18), entry_dep, g));
            w.views.insert((TOKEN.into(), "relay_hold_check".into()), check_ok(hold));
            let (a, _) = adapter(w, &fee_cfg(&price.to_string())).await;
            match (a.build(&job(ro.clone()), 0).await, ok) {
                (Ok(b), true) => assert_eq!(b.meta["deposit"], json!((entry_dep + hold).to_string())),
                (Err(SimError::Revert(r)), false) => assert!(r.contains("below"), "{r}"),
                (r, _) => panic!("price {price}: {r:?}"),
            }
        }
        // sponsored: bound to bob (not the lane), relayed only with relay_bound_payee, and then not priced
        let (bop, bo) = router_job("router_bound", "30000000000000", "0");
        let mut w = world();
        w.views.insert((ROUTER.into(), "relay_check".into()), router_check(1, 1, job_gas(&entry(&pol(), &bop, &bo).unwrap(), &Auth::decode(&hx(&bo["signature"])).unwrap()).unwrap()));
        w.views.insert((TOKEN.into(), "relay_hold_check".into()), check_ok(1));
        let (a, _) = adapter(w, &fee_cfg("1")).await;
        match a.build(&job(bo.clone()), 0).await {
            Err(SimError::Revert(r)) => assert!(r.contains("relay_bound_payee"), "{r}"),
            r => panic!("{r:?}"),
        }
        let mut w = world();
        w.views.insert((ROUTER.into(), "relay_check".into()), router_check(1, 1, job_gas(&entry(&pol(), &bop, &bo).unwrap(), &Auth::decode(&hx(&bo["signature"])).unwrap()).unwrap()));
        w.views.insert((TOKEN.into(), "relay_hold_check".into()), check_ok(1));
        let sponsored = format!(", relay_fee = {{ router = \"{ROUTER}\", executor = \"{EXECUTOR}\", relay_bound_payee = true }}");
        let (a, _) = adapter(w, &sponsored).await;
        a.build(&job(bo), 0).await.unwrap();
        // a check view's refusal kills the job (Revert), naming the contract's reason
        let mut w = world();
        w.views.insert((TOKEN.into(), "relay_fee_add_key_check".into()), check_err("wrong lane nonce"));
        let (a, _) = adapter(w, &fee_cfg("1")).await;
        assert!(matches!(a.build(&job(wo), 0).await, Err(SimError::Revert(r)) if r.contains("wrong lane nonce")));
    }

    /// §5 Submit: the attached deposit is exactly the check view's `storage_needed` (+ 0 yoctoNEAR: no `mtx_*` /
    /// `relay_fee_*` entry has a NEP 1-yocto rule), and the router's exactly `deposit_needed` + the hold's storage.
    #[tokio::test]
    async fn deposit_equals_storage_needed_plus_nep_yocto() {
        let s = 1_234_567u128;
        let mut w = world();
        w.views.insert((TOKEN.into(), "mtx_pay_check".into()), check_ok(s));
        w.views.insert((TOKEN.into(), "mtx_pay_meta_check".into()), check_ok(s + 1));
        let (a, w) = adapter(w, "").await;
        let b = a.build(&job(o_of("pay", json!({}))), 0).await.unwrap();
        assert_eq!((b.meta["receiver"].as_str(), b.meta["method"].as_str(), b.meta["deposit"].as_str()), (Some(TOKEN), Some("mtx_pay"), Some("1234567")));
        assert_eq!(view_args(&w, "mtx_pay_check")[..4 + 64], bstr(LANE0)[..], "caller = the lane");
        let signed = a.sign(b, 0, 42).await.unwrap();
        assert!(contains(&signed.raw, &[&2u8.to_le_bytes()[..], &bstr("mtx_pay")].concat()), "a FunctionCall action");
        assert!(contains(&signed.raw, &s.to_le_bytes()), "the deposit");
        assert!(contains(&signed.raw, &42u64.to_le_bytes()), "the lane nonce");
        a.submit(&signed).await.unwrap();
        assert_eq!(sent(&w), vec![signed.raw.clone()]);
        assert_eq!(signed.tx_id, format!("0x{}", h(&tx_hash(&signed.raw[..signed.raw.len() - 65]))));
        let rows: Vec<Value> = serde_json::from_str(PAYMETA).unwrap();
        let pm = rows.iter().find(|r| r["name"] == "note_utf8").unwrap();
        let b = a.build(&job(o_of("pay_meta_note_utf8", json!({"kind": "pay_meta", "salt": pm["salt"], "meta": pm["meta"]}))), 0).await.unwrap();
        assert_eq!((b.meta["method"].as_str(), b.meta["deposit"].as_str()), (Some("mtx_pay_meta"), Some("1234568")));
        assert!(b.body.ends_with(&[&hx(&pm["salt"])[..], &bvec(&hx(&pm["meta"]))].concat()), "salt, meta after op, auth");
    }

    /// Review focus 5: an amount above 2^53 (here 2^127 + 1) survives the job's decode, the `*_check` view's args and the
    /// submitted transaction; the router's `target_deposit` (a decimal string) too.
    #[tokio::test]
    async fn near_amount_above_2_pow_53_round_trips() {
        let big = (1u128 << 127) + 1;
        let op = MetaOp { amount: big, ..op_of("pay") };
        assert_eq!(MetaOp::decode(&op.encode()).unwrap().amount, big);
        let mut w = world();
        w.views.insert((TOKEN.into(), "mtx_pay_check".into()), check_ok(big));
        let (a, w) = adapter(w, "").await;
        let b = a.build(&job(o_op(&op, &auth_bytes(&row("pay")["auth"]), json!({}))), 0).await.unwrap();
        assert!(contains(&view_args(&w, "mtx_pay_check"), &big.to_le_bytes()), "check args");
        assert_eq!(b.meta["deposit"], json!(big.to_string()), "the deposit as a decimal string");
        let signed = a.sign(b, 0, 1).await.unwrap();
        assert_eq!(signed.raw.windows(16).filter(|x| *x == big.to_le_bytes()).count(), 2, "amount and deposit");
        // router: target_deposit 2^127 + 1 from the job's decimal string to relay_check's args
        let (rop, ro) = router_job("router_bound", "30000000000000", &big.to_string());
        let Entry::FeeRouter { target_deposit, .. } = entry(&pol(), &rop, &ro).unwrap() else { panic!() };
        assert_eq!(target_deposit, big);
        let relay = call_of(&pol(), &entry(&pol(), &rop, &ro).unwrap(), &rop, &hx(&ro["signature"])).unwrap();
        assert!(contains(&relay.args, &big.to_le_bytes()));
        assert_eq!(dec_u128(&json!(big.to_string()), "x").unwrap(), big);
        assert!(dec_u128(&json!(9007199254740993u64), "x").is_err(), "a JSON number is refused");
        assert!(dec_u128(&json!("340282366920938463463374607431768211456"), "x").is_err(), "2^128");
        assert!(dec_u128(&json!("+1"), "x").is_err() && dec_u128(&json!(""), "x").is_err() && dec_u128(&json!(" 1"), "x").is_err());
    }

    // ------------------------------------------------------------------------------------------------ start checks

    #[tokio::test]
    async fn start_check_genesis_mismatch_errors() {
        let (a, _) = adapter(world(), &fee_cfg("1")).await;
        a.start_check().await.unwrap();
        let mut w = world();
        w.genesis = "3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3".into();
        let (a, _) = adapter(w, &fee_cfg("1")).await;
        assert!(format!("{:#}", a.start_check().await.unwrap_err()).contains("genesis"));
        let mut w = world();
        w.views.insert((TOKEN.into(), "network".into()), serde_json::to_vec(&[7u8; 32].to_vec()).unwrap());
        let (a, _) = adapter(w, &fee_cfg("1")).await;
        assert!(format!("{:#}", a.start_check().await.unwrap_err()).contains("network"));
        // a router whose executor() is not the configured executor
        let mut w = world();
        w.views.insert((ROUTER.into(), "executor".into()), bstr("other.near"));
        let (a, _) = adapter(w, &fee_cfg("1")).await;
        assert!(format!("{:#}", a.start_check().await.unwrap_err()).contains("executor"));
    }

    /// Spec §3.9 / NODE-STO-07: a SCaaS account (token, router, executor, DEX) with any access key halts the chain;
    /// a configured id that does not exist or has no code is a startup error.
    #[tokio::test]
    async fn start_check_access_key_present_halts() {
        for acct in [TOKEN, ROUTER, EXECUTOR, DEX] {
            let mut w = world();
            w.keyed.push(acct.into());
            let (a, _) = adapter(w, &fee_cfg("1")).await;
            let e = format!("{:#}", a.start_check().await.unwrap_err());
            assert!(e.contains("access key") && e.contains("halted") && e.contains(acct), "{acct}: {e}");
        }
        for acct in [TOKEN, ROUTER, EXECUTOR, DEX] {
            let mut w = world();
            w.code.retain(|c| c != acct);
            let (a, _) = adapter(w, &fee_cfg("1")).await;
            let e = format!("{:#}", a.start_check().await.unwrap_err());
            assert!(e.contains("missing") && e.contains(acct), "{acct}: {e}");
        }
    }

    #[tokio::test]
    async fn start_check_lane_unregistered_errors() {
        let mut w = world();
        w.views.insert((TOKEN.into(), "storage_balance_of".into()), b"null".to_vec());
        let (a, _) = adapter(w, "").await;
        let e = format!("{:#}", a.start_check().await.unwrap_err());
        assert!(e.contains("not registered") && e.contains(LANE0) && e.contains(TOKEN), "{e}");
    }

    // ------------------------------------------------------------------------------------------------ status / escrow

    fn fc(method: &str, args: &[u8]) -> Value {
        json!({"FunctionCall": {"method_name": method, "args": b64(args), "gas": 1, "deposit": "0"}})
    }

    fn receipt(executor: &str, ok: bool, logs: &[String]) -> Value {
        let status = if ok { json!({"SuccessValue": ""}) } else { json!({"Failure": {"ActionError": {"index": 0, "kind": {}}}}) };
        json!({"id": "r", "block_hash": "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2",
               "outcome": {"executor_id": executor, "logs": logs, "status": status, "tokens_burnt": "1000"}})
    }

    fn outcome(receiver: &str, action: Value, status: Value, receipts: Vec<Value>) -> Value {
        json!({"final_execution_status": "FINAL", "status": status,
               "transaction": {"signer_id": LANE0, "receiver_id": receiver, "hash": "x", "actions": [action]},
               "transaction_outcome": {"block_hash": "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2", "id": "x",
                   "outcome": {"executor_id": LANE0, "logs": [], "status": {"SuccessReceiptId": "r"}, "tokens_burnt": "500"}},
               "receipts_outcome": receipts})
    }

    fn pending(deadline: u64, stage: u8) -> Vec<u8> {
        [vec![1], 0u64.to_le_bytes().to_vec(), bstr(TOKEN), bstr(DEX), [vec![0], bstr("alice.test.near")].concat(), vec![0],
         10u128.to_le_bytes().to_vec(), bstr(LANE0), 0u128.to_le_bytes().to_vec(), 3u128.to_le_bytes().to_vec(),
         deadline.to_le_bytes().to_vec(), vec![stage, 0]].concat()
    }

    /// Spec §5 escrow tracking (as TON): a relay that has not released is pending while the router's entry exists; past
    /// its deadline this node sends `relay_timeout(ref)` (anyone may), once per retry window; once the entry is gone and
    /// nothing was released, the job is reverted (the payer was not charged).
    #[tokio::test]
    async fn escrow_tracking_times_out_after_deadline() {
        let (rop, ro) = router_job("router_short", "30000000000000", "0");
        let relay = call_of(&pol(), &entry(&pol(), &rop, &ro).unwrap(), &rop, &hx(&ro["signature"])).unwrap();
        let hash = [0x33u8; 32];
        let id = format!("0x{}", h(&hash));
        let key = bs58::encode(hash).into_string();
        let refunded = outcome(ROUTER, fc("relay", &relay.args), json!({"SuccessValue": b64(&[0])}), vec![]);
        let now = crate::submit::now();
        let mut w = world();
        w.txs.insert(key.clone(), refunded.clone());
        w.views.insert((ROUTER.into(), "pending".into()), pending(now + 600, 1));
        let (a, w) = adapter(w, &fee_cfg("1")).await;
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Pending, "before the deadline");
        assert!(sent(&w).is_empty(), "no timeout before the deadline");
        w.lock().unwrap().views.insert((ROUTER.into(), "pending".into()), pending(now - 1, 1));
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Pending);
        let s = sent(&w);
        assert_eq!(s.len(), 1, "relay_timeout sent");
        assert!(contains(&s[0], &[&bstr("relay_timeout")[..], &bvec(&rop.pay_ref)].concat()), "relay_timeout(ref) on the router");
        assert!(contains(&s[0], &bstr(ROUTER)));
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Pending);
        assert_eq!(sent(&w).len(), 1, "not again inside the retry window");
        // the entry is gone: refunded
        w.lock().unwrap().views.insert((ROUTER.into(), "pending".into()), vec![0]);
        assert!(matches!(a.tx_status(&id).await.unwrap(), TxStatus::Reverted { reason } if reason.contains("refunded")));
        // released: mined at the block of the transaction
        let released = outcome(ROUTER, fc("relay", &relay.args), json!({"SuccessValue": b64(&[1])}), vec![]);
        w.lock().unwrap().txs.insert(key.clone(), released);
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Mined { height: 100, tx_hash: None });
        // a plain job: success = mined, failure = reverted (never retried blindly, note 5), not final = pending
        let plain = outcome(TOKEN, fc("mtx_pay", &[1]), json!({"Failure": {"ActionError": {"kind": {"FunctionCallError": {"ExecutionError": "wrong lane nonce"}}}}}), vec![]);
        w.lock().unwrap().txs.insert(key.clone(), plain);
        assert!(matches!(a.tx_status(&id).await.unwrap(), TxStatus::Reverted { reason } if reason.contains("wrong lane nonce")));
        let mut open = outcome(TOKEN, fc("mtx_pay", &[1]), json!({"SuccessValue": ""}), vec![]);
        open["final_execution_status"] = json!("EXECUTED_OPTIMISTIC");
        w.lock().unwrap().txs.insert(key.clone(), open);
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Pending);
        w.lock().unwrap().txs.clear();
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Unknown);
        assert!(a.tx_status("0xzz").await.is_err());
    }

    #[tokio::test]
    async fn submit_errors_are_classified() {
        let (a, w) = adapter(world(), "").await;
        let signed = Signed { job_id: 1, tx_id: "0x00".into(), raw: vec![1, 2], valid_until: 0, sequence: 0 };
        a.submit(&signed).await.unwrap();
        w.lock().unwrap().send_err = Some(rpc_err("INVALID_TRANSACTION"));
        assert!(a.submit(&signed).await.unwrap_err().downcast_ref::<Rejected>().is_some(), "same bytes never pass");
        w.lock().unwrap().send_err = Some(rpc_err("TIMEOUT_ERROR"));
        assert!(a.submit(&signed).await.unwrap_err().downcast_ref::<Rejected>().is_none(), "retry the same bytes");
        assert_eq!(a.sequence(0).await.unwrap(), 42, "the access key's nonce + 1");
    }

    // ------------------------------------------------------------------------------------------------ events

    fn ev(standard: &str, event: &str, data: Value) -> String {
        format!("EVENT_JSON:{}", json!({"standard": standard, "version": "1.0.0", "event": event, "data": data}))
    }

    fn ids() -> Ids {
        Ids { tokens: vec![TOKEN.into()], router: Some(ROUTER.into()), dex: Some(DEX.into()) }
    }

    fn settled(from: &str, to: &str, amount: &str, r: &str) -> String {
        ev("scaas", "payment_settled", json!({"from": from, "to": to, "amount": amount, "pay_ref": r}))
    }

    /// Note 2 / NET-NEAR-07: only successful receipts (a failed receipt keeps its logs), only configured contracts (a copy
    /// of the token elsewhere emits identical events); one `Transfer` per holder move (the UA pool / escrow side skipped);
    /// amounts decimal strings; hashes `0x` + hex.
    #[test]
    fn near_events_success_only_configured() {
        let r = format!("0x{}", "01".repeat(32));
        let ft = |a: &str, b: &str, n: &str| ev("nep141", "ft_transfer", json!([{"old_owner_id": a, "new_owner_id": b, "amount": n}]));
        let big = ((1u128 << 127) + 1).to_string();
        let tx = outcome(TOKEN, fc("mtx_pay", &[]), json!({"SuccessValue": ""}), vec![
            receipt(TOKEN, true, &[ev("scaas", "meta_transaction_executed", json!({"from": "alice.test.near", "relayer": LANE0,
                "lane": format!("0x{}", "a1".repeat(32)), "nonce": 0, "digest": format!("0x{}", "dd".repeat(32))})),
                ft("alice.test.near", "bob.test.near", &big), settled("alice.test.near", "bob.test.near", &big, &r)]),
            receipt(TOKEN, false, &[settled("alice.test.near", "bob.test.near", "5", &r)]),
            receipt("copy.test.near", true, &[settled("alice.test.near", "bob.test.near", "6", &r)]),
            receipt(TOKEN, true, &[ft(TOKEN, "bob.test.near", "8"), ev("scaas", "ua_transfer", json!({"from": format!("0x{}", "ee".repeat(32)), "to": "bob.test.near", "amount": "8"}))]),
            receipt(TOKEN, true, &["not json".into(), "EVENT_JSON:{".into(), ev("scaas", "payment_settled", json!({"from": "a", "amount": 1.5})), settled("Bad", "b.near", "1", &r)]),
        ]);
        let rows = tx_events(&ids(), &tx, 100, "0xbb", "0xcc");
        let kinds: Vec<&str> = rows.iter().map(|e| e["event"].as_str().unwrap()).collect();
        assert_eq!(kinds, ["MetaTransactionExecuted", "Transfer", "PaymentSettled", "Transfer"], "{rows:#?}");
        let p = &rows[2];
        assert_eq!((p["contract"].as_str(), p["from"].as_str(), p["to"].as_str(), p["amount"].as_str()), (Some(TOKEN), Some("alice.test.near"), Some("bob.test.near"), Some(big.as_str())));
        assert_eq!((p["entry_ref"].as_str(), p["block_number"].as_u64(), p["tx_hash"].as_str()), (Some(r.as_str()), Some(100), Some("0xcc")));
        assert_eq!(rows[3]["from"], json!(format!("0x{}", "ee".repeat(32))), "the UA side of a pool move");
        let idx: Vec<u64> = rows.iter().map(|e| e["log_index"].as_u64().unwrap()).collect();
        assert!(idx.windows(2).all(|w| w[0] < w[1]), "log_index increases: {idx:?}");
        assert!(tx_events(&Ids { tokens: vec![], ..ids() }, &tx, 100, "0xbb", "0xcc").is_empty(), "no configured token");
    }

    /// CTR-MTX-26 / -27 joins (`indexer::join_pay_events`): `payment_meta` gives its meta to the settle; the router's
    /// `relay_fee_paid` (note 6, review T10 m5) only for a configured token and joined to that token's `payment_settled`
    /// by (payer, ref); a wrapper's from the token itself; mandate pays keep `from` = the mandate id (note 3).
    #[test]
    fn near_events_join_meta_relay_fee_and_mandate() {
        let r = format!("0x{}", "05".repeat(32));
        let fee = |token: &str| ev("scaas", "relay_fee_paid", json!({"ref": r, "target": DEX, "token": token, "payer": "alice.test.near", "payee": LANE0, "amount": "10"}));
        let tx = outcome(ROUTER, fc("relay", &[]), json!({"SuccessValue": b64(&[1])}), vec![
            receipt(TOKEN, true, &[settled("alice.test.near", LANE0, "10", &r)]),
            receipt(ROUTER, true, &[fee(TOKEN), fee("fake-token.near")]),
        ]);
        let rows = tx_events(&ids(), &tx, 7, "0xbb", "0xcc");
        assert_eq!(rows.len(), 1, "{rows:#?}");
        assert_eq!((rows[0]["relay_payee"].as_str(), rows[0]["relay_target"].as_str()), (Some(LANE0), Some(DEX)));
        let no_router = tx_events(&Ids { router: None, ..ids() }, &tx, 7, "0xbb", "0xcc");
        assert!(no_router[0]["relay_payee"].is_null(), "an unconfigured router's event joins nothing");
        // a fake token's settle with the same ref takes nothing
        let tx = outcome(ROUTER, fc("relay", &[]), json!({"SuccessValue": b64(&[1])}), vec![
            receipt("fake-token.near", true, &[settled("alice.test.near", LANE0, "10", &r)]),
            receipt(ROUTER, true, &[fee("fake-token.near")]),
        ]);
        assert!(tx_events(&ids(), &tx, 7, "0xbb", "0xcc").is_empty());
        // wrapper: the token's own relay_fee_paid; pay-meta
        let pid = format!("0x{}", "04".repeat(32));
        let tx = outcome(TOKEN, fc("relay_fee_add_key", &[]), json!({"SuccessValue": ""}), vec![receipt(TOKEN, true, &[
            ev("scaas", "payment_meta", json!({"pay_ref": pid, "meta": "0xabcd"})),
            settled("alice.test.near", "bob.test.near", "100", &pid),
            settled("alice.test.near", LANE0, "10", &r),
            ev("scaas", "relay_fee_paid", json!({"ref": r, "target": TOKEN, "token": TOKEN, "payer": "alice.test.near", "payee": LANE0, "amount": "10"})),
        ])]);
        let rows = tx_events(&ids(), &tx, 7, "0xbb", "0xcc");
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0]["meta"].as_str(), rows[1]["relay_payee"].as_str()), (Some("0xabcd"), Some(LANE0)));
        // mandate pay: from = 0x<mandate id>, keyed by (token, id)
        let mid = format!("0x{}", "b0".repeat(32));
        let tx = outcome(TOKEN, fc("mtx_mandate_pay", &[]), json!({"SuccessValue": ""}), vec![receipt(TOKEN, true, &[settled(&mid, "bob.test.near", "100", &r)])]);
        let rows = tx_events(&ids(), &tx, 7, "0xbb", "0xcc");
        assert_eq!((rows[0]["contract"].as_str(), rows[0]["from"].as_str()), (Some(TOKEN), Some(mid.as_str())));
    }

    /// Note 4: trades are booked from the tokens' transfer events in successful receipts — the legs into the DEX carry
    /// their `order_filled` digest and the configured DEX's `matched` settle id — never from `matched` alone.
    #[test]
    fn near_events_trades_from_transfers() {
        let (da, db, sid) = (format!("0x{}", "da".repeat(32)), format!("0x{}", "db".repeat(32)), format!("0x{}", "5e".repeat(32)));
        let leg = |from: &str, d: &str| receipt(TOKEN, true, &[
            ev("nep141", "ft_transfer", json!([{"old_owner_id": from, "new_owner_id": DEX, "amount": "100"}])),
            ev("scaas", "order_filled", json!({"from": from, "dex": DEX, "lane": format!("0x{}", "a0".repeat(32)), "nonce": 0, "amount": "100", "digest": d})),
        ]);
        let matched = |dex: &str| receipt(dex, true, &[ev("scaas", "matched", json!({"settle_id": sid, "legs": [da, db]}))]);
        let payout = receipt(TOKEN, true, &[ev("nep141", "ft_transfer", json!([{"old_owner_id": DEX, "new_owner_id": "erin.near", "amount": "100"}]))]);
        let tx = outcome(DEX, fc("settle", &[]), json!({"SuccessValue": ""}), vec![leg("carol.near", &da), matched(DEX), payout.clone()]);
        let rows = tx_events(&ids(), &tx, 9, "0xbb", "0xcc");
        assert_eq!(rows.len(), 2, "{rows:#?}");
        assert!(rows.iter().all(|e| e["event"] == "Transfer"));
        assert_eq!((rows[0]["leg_digest"].as_str(), rows[0]["settle_id"].as_str()), (Some(da.as_str()), Some(sid.as_str())));
        assert_eq!((rows[1]["from"].as_str(), rows[1]["to"].as_str()), (Some(DEX), Some("erin.near")));
        let other = tx_events(&ids(), &outcome(DEX, fc("settle", &[]), json!({"SuccessValue": ""}), vec![leg("carol.near", &da), matched("fake-dex.near")]), 9, "0xbb", "0xcc");
        assert!(other[0]["settle_id"].is_null(), "an unconfigured DEX's matched joins nothing");
        assert!(tx_events(&ids(), &outcome(DEX, fc("settle", &[]), json!({"SuccessValue": ""}), vec![matched(DEX)]), 9, "0xbb", "0xcc").is_empty(), "matched alone books nothing");
    }

    /// `events` scans final blocks' chunks for transactions to configured contracts and reads their final outcomes;
    /// a skipped height is passed over; a transaction not final yet keeps the range open.
    #[tokio::test]
    async fn events_scan_blocks() {
        let r = format!("0x{}", "01".repeat(32));
        let mut w = world();
        let bh = bs58::encode([0xbb; 32]).into_string();
        w.blocks = vec![json!({"header": {"height": 5, "hash": bh}, "chunks": [{"chunk_hash": "C5", "height_included": 5}, {"chunk_hash": "C4", "height_included": 4}]})];
        let th = bs58::encode([0xcc; 32]).into_string();
        w.chunks.insert("C5".into(), json!({"transactions": [{"hash": th, "signer_id": LANE0, "receiver_id": TOKEN},
                                                              {"hash": "other", "signer_id": LANE0, "receiver_id": "elsewhere.near"}]}));
        w.txs.insert(th.clone(), outcome(TOKEN, fc("mtx_pay", &[]), json!({"SuccessValue": ""}), vec![receipt(TOKEN, true, &[settled("alice.test.near", "bob.test.near", "1", &r)])]));
        let (a, w) = adapter(w, "").await;
        let rows = a.events(4, 5, &[TOKEN.into()]).await.unwrap();
        assert_eq!(rows.len(), 1, "{rows:#?}");
        assert_eq!((rows[0]["block_hash"].as_str(), rows[0]["tx_hash"].as_str()), (Some(format!("0x{}", "bb".repeat(32)).as_str()), Some(format!("0x{}", "cc".repeat(32)).as_str())));
        assert!(w.lock().unwrap().calls.iter().all(|c| c.1["chunk_id"] != "C4"), "a chunk carried over from height 4 is not re-read");
        assert_eq!(a.block_hash(6).await.unwrap(), format!("0x{}", "bb".repeat(32)), "skipped height 6: the block produced before it");
        w.lock().unwrap().txs.get_mut(&th).unwrap()["final_execution_status"] = json!("EXECUTED_OPTIMISTIC");
        assert!(a.events(5, 5, &[TOKEN.into()]).await.is_err(), "not final: the range stays open");
        assert_eq!(a.final_head().await.unwrap(), Some(Head { height: 5, hash: format!("0x{}", "bb".repeat(32)) }));
        assert!(a.events(5, 5, &["Bad".into()]).await.is_err(), "no usable token id: never an empty Ok");
    }

    /// R9: the node shows a subject's key set per token (keys drift between tokens: a key op is per token).
    #[tokio::test]
    async fn key_sets_per_token() {
        let mut w = world();
        let rec = [258u16.to_le_bytes().to_vec(), bvec(&[7; 32])].concat();
        let subject = [vec![1], 1u32.to_le_bytes().to_vec(), rec, 0u32.to_le_bytes().to_vec(), vec![0, 0], 3u64.to_le_bytes().to_vec(), vec![0]].concat();
        w.views.insert((TOKEN.into(), "subject".into()), subject);
        let (a, _) = adapter(w, "").await;
        let ks = a.key_sets(&Holder::Ua([1; 32])).await.unwrap();
        assert_eq!(ks, vec![(TOKEN.to_string(), Some(vec![(258u16, vec![7u8; 32])]))]);
    }

    proptest! {
        /// Untrusted input never panics (§5): job bytes and JSON, RPC JSON, event logs.
        #[test]
        fn near_jobs_never_panic(b in proptest::collection::vec(any::<u8>(), 0..600), s in "\\PC{0,120}", k in 0usize..4,
                                 n in any::<u64>(), relayer in proptest::option::of("[a-z.]{0,12}")) {
            let _ = MetaOp::decode(&b);
            let _ = MetaOp::decode(&[LABEL, &b[..]].concat());
            let _ = Auth::decode(&b);
            let hb = h(&b);
            let kind = [json!("pay_meta"), json!("relay_fee"), json!(s.clone()), json!(n)][k].clone();
            let route = if n % 2 == 0 { "wrapper" } else { "router" };
            let o = json!({"kind": kind, "salt": hb, "meta": s, "ref": hb,
                           "extra": {"call": if n % 3 == 0 { s.clone() } else { hb.clone() }, "route": route, "target_gas": s, "target_deposit": n.to_string()}});
            let mut op = op_of("relay_fee_pay_router_short");
            op.relayer = relayer;
            let _ = entry(&pol(), &op, &o);
            let _ = entry(&pol(), &op_of("pay"), &o);
            if let Ok(e) = entry(&pol(), &op, &o) {
                let _ = job_gas(&e, &Auth::Ed25519);
                let _ = call_of(&pol(), &e, &op, &b);
            }
            let _ = job_gas(&Entry::FeeWrapper { entry: "mtx_cancel".into(), args: b.clone() }, &Auth::Passkey);
            let _ = dec_u128(&json!(s), "x");
            let logs = [s.clone(), format!("EVENT_JSON:{s}"), ev("scaas", "payment_settled", json!({"from": s, "to": s, "amount": s, "pay_ref": s})),
                        ev("nep141", "ft_transfer", json!(s)), ev("scaas", "matched", json!({"settle_id": s, "legs": s}))];
            let tx = outcome(TOKEN, fc("relay", &b), json!({"SuccessValue": s}), vec![receipt(TOKEN, true, &logs), receipt(ROUTER, true, &logs), receipt(DEX, true, &logs)]);
            let _ = tx_events(&ids(), &tx, n, &s, &s);
            if let Ok(v) = serde_json::from_str::<Value>(&s) {
                let _ = tx_events(&ids(), &v, n, &s, &s);
                let _ = tx_events(&ids(), &json!({"receipts_outcome": [v.clone()], "transaction": v}), n, &s, &s);
            }
        }
    }
}
