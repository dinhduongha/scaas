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
use std::collections::{BTreeMap, HashMap};
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
/// common `IMPLICIT_TRANSFER_GAS` (T19 ruling A): what a contract budgets per NEAR transfer to an account it does not
/// control; a transfer to an implicit account (every lane is one) costs 8.35 Tgas (0.825 send + 7.525 prepaid).
pub const IMPLICIT_TRANSFER_GAS: u64 = 10 * TGAS;
/// A job's receipt without its signature checks: the costliest measured entry (a `relay_fee_<entry>` wrapper writing
/// both records) burns ≤ 4.1 Tgas besides its verifies (`smartcontracts/near/runs/2026-10-28-near-relayfee*.txt`,
/// `-near-gas.txt`); pinned × 2.5 for 16 KiB arguments, plus one `IMPLICIT_TRANSFER_GAS` (T19 ruling A, concern C: a
/// record the check counted that exists at execution makes the deposit's excess a refund to the lane).
pub const GAS_JOB_BASE: u64 = 10 * TGAS + IMPLICIT_TRANSFER_GAS;
/// Prepaid per P-256 passkey signature: 20.005 Tgas measured per verify (Task 1, `runs/2026-10-28-p256-spike.txt`)
/// × 1.05, so Task 9's largest wrapper (12-passkey msig entry + passkey payment, 265.6 Tgas burnt; 266.3 on near-sandbox
/// through the node, T19) fits `GAS_JOB_BASE` 20 + 13 × 21 = 293.
pub const GAS_PASSKEY: u64 = 21 * TGAS;
/// Prepaid per ed25519 / secp256k1 signature (< 0.5 Tgas measured; the contracts' `GAS_SIG_KEY`).
pub const GAS_KEY_SIG: u64 = TGAS;
/// Task 9 / note 5: passkey signatures per wrapper job (entry + payment) that fit 300 Tgas.
pub const MAX_WRAPPER_PASSKEYS: usize = 13;
/// relayfee `relay_gas` without the payment's signatures and the target (relayfee/src/lib.rs): `GAS_RELAY` 5,
/// `GAS_ON_HOLD` 5, `GAS_EXEC` 4, `call_gas` (4 + 2 × 5 + 3) and `GAS_HOLD` 5 Tgas, plus one `IMPLICIT_TRANSFER_GAS`
/// for each of `GAS_HOLD`, `GAS_ON_HOLD`, `GAS_EXEC`, both `GAS_RELEASE` and `GAS_ON_SETTLE` (T19 ruling A); `relay`
/// refuses less prepaid gas.
pub const ROUTER_FIXED_GAS: u64 = 36 * TGAS + 6 * IMPLICIT_TRANSFER_GAS;
/// The router's `sig_gas` figures (common/src/auth.rs `GAS_SIG_PASSKEY`, `GAS_SIG_KEY`).
const ROUTER_SIG_PASSKEY: u64 = 25 * TGAS;
const ROUTER_SIG_KEY: u64 = TGAS;
/// relayfee `MAX_ARGS_BYTES`.
pub const MAX_ARGS_BYTES: usize = 16_384;
/// common/src/auth.rs `PASSKEY_FIELD_MAX`: a longer passkey field is refused on chain (its verify is not budgeted).
pub const PASSKEY_FIELD_MAX: usize = 1024;
/// Fix 2 R1 / R2: a relay-fee payment, its wrapped entry op, a router target op or a DEX order / leg must stay valid
/// this long past now (controller ruling), else it could expire in transit (checks read `final` state ≈ 2–3 blocks
/// old; the hold, the target and a settle's legs run blocks after inclusion) and the relay fails unpaid.
pub const RELAY_EXPIRY_MARGIN_S: u64 = 120;
/// `relay_timeout(ref)`: its receipt, a token settle and a deposit return (`GAS_RELEASE` 5 each), `on_settle` 3; one
/// `IMPLICIT_TRANSFER_GAS` each for its own `target_deposit` return, the two settlements and `on_settle` (ruling A).
const GAS_RELAY_TIMEOUT: u64 = 30 * TGAS + 4 * IMPLICIT_TRANSFER_GAS;
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

/// A Borsh `Auth` (common/src/auth.rs: 0 ed25519, 1 secp256k1, 2 passkey, 3 msig), read off chain for its size, its
/// signature budget and the key record / passkey origin it signs with; the job forwards the bytes as signed. Read with
/// the challenge it signs (the token's `op.digest()` of its op, every msig member alike).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    Ed25519([u8; 32]),
    Secp256k1([u8; 64]),
    /// `rp` = the authenticatorData's rpIdHash (its first 32 bytes), `origin` = clientDataJSON's origin as the token
    /// reads it (`origin_of`).
    Passkey { key: [u8; 64], rp: Option<[u8; 32]>, origin: String },
    Msig { key_data: Vec<u8>, sigs: Vec<Auth> },
}

/// common/src/webauthn.rs `origin_of`, ported byte for byte (fix 4 N1; `smartcontracts/near/vectors/webauthn-origin.json`
/// runs against both): clientDataJSON is exactly `{"type":"webauthn.get","challenge":"<b64url(challenge)>","origin":"`
/// ‖ origin ‖ `"`, then `}` (end), or `,"crossOrigin":false` then `}` (end) or `,` … `}` without `"topOrigin"` /
/// `"crossOrigin"`. That tail need not be JSON and may repeat members (`origin` too): the origin is the first, non-empty,
/// without `\`. Every passkey origin the node reads comes from here, as the token's do.
pub fn origin_of<'a>(cd: &'a [u8], challenge: &[u8; 32]) -> Option<&'a [u8]> {
    let has = |hay: &[u8], pat: &[u8]| hay.windows(pat.len()).any(|w| w == pat);
    let c = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);
    let prefix = format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":""#);
    let rest = cd.strip_prefix(prefix.as_bytes())?;
    let end = rest.iter().position(|c| *c == b'"')?;
    let (origin, tail) = (&rest[..end], &rest[end + 1..]);
    let ok = match tail.strip_prefix(br#","crossOrigin":false"#) {
        _ if tail == b"}" => true,
        Some(t) => t == b"}" || (t.starts_with(b",") && t.ends_with(b"}") && !has(t, br#""topOrigin""#) && !has(t, br#""crossOrigin""#)),
        None => false,
    };
    (ok && !origin.is_empty() && !origin.contains(&b'\\')).then_some(origin)
}

/// UA kinds (common/src/ua.rs).
const KIND_WEBAUTHN_P256: u16 = 0x0100;
const KIND_ED25519: u16 = 0x0102;
const KIND_SECP256K1: u16 = 0x0108;
const KIND_MSIG: u16 = 0x0120;

impl Auth {
    /// Exactly one `Auth`; an msig inside an msig and a passkey field over `PASSKEY_FIELD_MAX` refused (as on chain).
    pub fn decode(b: &[u8], challenge: &[u8; 32]) -> Result<Self> {
        let mut r = Reader::new(b);
        let a = Self::read(&mut r, true, challenge)?;
        r.end()?;
        Ok(a)
    }

    fn read(r: &mut Reader, top: bool, challenge: &[u8; 32]) -> Result<Self> {
        Ok(match r.u8()? {
            0 => {
                let key = r.arr32()?;
                r.take(64)?;
                Auth::Ed25519(key)
            }
            1 => {
                let key: [u8; 64] = r.take(64)?.try_into()?;
                r.take(64 + 1)?;
                Auth::Secp256k1(key)
            }
            2 => {
                let key: [u8; 64] = r.take(64)?.try_into()?;
                let (ad, cd) = (r.bytes()?, r.bytes()?);
                r.take(64)?;
                if ad.len() > PASSKEY_FIELD_MAX || cd.len() > PASSKEY_FIELD_MAX {
                    bail!("passkey clientDataJSON / authenticatorData over {PASSKEY_FIELD_MAX} bytes");
                }
                let rp = ad.get(..32).and_then(|x| x.try_into().ok());
                // fix 4 N1: as the token reads it (its `webauthn::origin`); a clientDataJSON it cannot parse never verifies
                let origin = origin_of(cd, challenge).and_then(|o| String::from_utf8(o.to_vec()).ok()).ok_or_else(|| {
                    anyhow!("passkey clientDataJSON is not in the token's grammar for this op (webauthn origin_of: type, challenge, origin, tail)")
                })?;
                Auth::Passkey { key, rp, origin }
            }
            3 if top => {
                let key_data = r.bytes()?.to_vec();
                let n = r.u32()?;
                let mut sigs = Vec::new();
                for _ in 0..n {
                    r.u8()?;
                    sigs.push(Self::read(r, false, challenge)?);
                }
                Auth::Msig { key_data, sigs }
            }
            3 => bail!("msig inside msig"),
            t => bail!("auth tag {t}"),
        })
    }

    pub fn passkeys(&self) -> usize {
        match self {
            Auth::Passkey { .. } => 1,
            Auth::Msig { sigs, .. } => sigs.iter().map(Self::passkeys).sum(),
            _ => 0,
        }
    }

    /// Gas a job prepays for this auth's signatures.
    fn attach_gas(&self) -> u64 {
        match self {
            Auth::Passkey { .. } => GAS_PASSKEY,
            Auth::Ed25519(_) | Auth::Secp256k1(_) => GAS_KEY_SIG,
            Auth::Msig { sigs, .. } => sigs.iter().map(Self::attach_gas).fold(0, u64::saturating_add),
        }
    }

    /// The router's `sig_gas` of this auth (its `relay_gas` term; the DEX's `leg_gas` term).
    fn router_gas(&self) -> u64 {
        match self {
            Auth::Passkey { .. } => ROUTER_SIG_PASSKEY,
            Auth::Ed25519(_) | Auth::Secp256k1(_) => ROUTER_SIG_KEY,
            Auth::Msig { sigs, .. } => sigs.iter().map(Self::router_gas).fold(0, u64::saturating_add),
        }
    }

    /// The subject key record this auth signs as (`Auth::key` on chain), `None` for a passkey without an rpIdHash.
    pub fn record(&self) -> Option<(u16, Vec<u8>)> {
        match self {
            Auth::Ed25519(k) => Some((KIND_ED25519, k.to_vec())),
            Auth::Secp256k1(k) => Some((KIND_SECP256K1, k.to_vec())),
            Auth::Passkey { key, rp, .. } => rp.map(|rp| (KIND_WEBAUTHN_P256, [&key[..], &rp].concat())),
            Auth::Msig { key_data, .. } => Some((KIND_MSIG, key_data.clone())),
        }
    }

    /// The origins of its passkey signatures.
    fn origins(&self) -> Vec<String> {
        match self {
            Auth::Passkey { origin, .. } => vec![origin.clone()],
            Auth::Msig { sigs, .. } => sigs.iter().flat_map(Self::origins).collect(),
            _ => vec![],
        }
    }

    /// Passes `POLICY_PASSKEY_FOR_VALUE` (token `value_policy`): a passkey, or an msig whose members are all passkeys.
    fn passkey_only(&self) -> bool {
        match self {
            Auth::Passkey { .. } => true,
            Auth::Msig { key_data, .. } => {
                let n = key_data.get(2..4).map_or(0, |c| u16::from_be_bytes([c[0], c[1]]) as usize);
                n > 0 && key_data.len() == 4 + 36 * n
                    && (0..n).all(|i| key_data[4 + 36 * i..4 + 36 * i + 2] == KIND_WEBAUTHN_P256.to_be_bytes())
            }
            _ => false,
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
    let op = MetaOp::read(&mut r)?;
    let auth = Auth::read(&mut r, true, &op.digest())?;
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
    /// `params.dex`: the escrow DEX (a router target, its `matched` joins trade legs).
    pub dex: Option<String>,
    /// `params.relay_fee.targets`: third-party router targets beside the configured tokens and the DEX, each with the
    /// methods the operator vouches for.
    pub targets: BTreeMap<String, Vec<String>>,
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
        let dex = match cfg.params.get("dex") {
            None => None,
            Some(v) => Some(near_id(v.as_str().ok_or_else(|| anyhow!("params.dex must be a string"))?).context("params.dex")?),
        };
        // fix 2 f2: `targets = { "<account id>" = ["method", …] }`, strict
        let mut targets = BTreeMap::new();
        if let Some(v) = t.and_then(|t| t.get("targets")) {
            let table = v.as_table().ok_or_else(|| anyhow!("params.relay_fee.targets must be a table of account id = [methods]"))?;
            for (k, ms) in table {
                let id = near_id(k).context("params.relay_fee.targets")?;
                if Some(&id) == router.as_ref() || Some(&id) == executor.as_ref() || tokens.contains(&id) || dex.as_ref() == Some(&id) {
                    bail!("params.relay_fee.targets: {id} is the router, its executor, a token or the DEX");
                }
                let list = ms.as_array().filter(|l| !l.is_empty())
                    .ok_or_else(|| anyhow!("params.relay_fee.targets.{k} must be a non-empty list of method names"))?;
                let methods = list.iter().map(|m| match m.as_str() {
                    Some(m) if (1..=255).contains(&m.len()) && m != "add_key_native" => Ok(m.to_string()),
                    _ => Err(anyhow!("params.relay_fee.targets.{k}: {m} is not a method name")),
                }).collect::<Result<Vec<_>>>()?;
                targets.insert(id, methods);
            }
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
        Ok(Self { router, executor, tokens, params, min_yocto_value, dex, targets })
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
            // fix 1 I2: only targets whose calls the node can vouch for (SCaaS, checked in `build`) or the operator lists
            let allowed = policy.tokens.iter().chain(&policy.dex).chain(policy.targets.keys()).any(|x| *x == target);
            if !allowed {
                bail!("{target} is not an allowed router target (configured tokens, params.dex, params.relay_fee.targets)");
            }
            if policy.targets.get(&target).is_some_and(|ms| !ms.contains(&method)) {
                bail!("{method} is not a listed method of router target {target} (params.relay_fee.targets)");
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

/// relayfee `relay_held(router, ref) -> Option<Held>` ⇒ something is held.
fn decode_held(b: &[u8]) -> Result<bool> {
    let mut r = Reader::new(b);
    let held = r.option(|r| {
        r.holder()?;
        r.holder()?;
        r.u128()?;
        r.account()?;
        r.u128()
    })?;
    r.end()?;
    Ok(held.is_some())
}

/// One leg of a DEX `settle(order_a, op_a, auth_a, order_b, op_b, auth_b)` (common/src/metaop.rs `Order`).
#[derive(Debug, Clone)]
struct SettleLeg {
    order: Vec<u8>,
    sell_token: String,
    buy_token: String,
    sell_amount: u128,
    min_buy: u128,
    expiry: u64,
    relayer: Option<String>,
    op: MetaOp,
    auth_raw: Vec<u8>,
    auth: Auth,
}

/// A `settle` call's arguments, canonical and complete.
fn settle_legs(b: &[u8]) -> Result<Vec<SettleLeg>> {
    let mut r = Reader::new(b);
    let mut legs = Vec::new();
    for _ in 0..2 {
        let start = r.i;
        let sell_token = r.account()?;
        let buy_token = r.account()?;
        let (sell_amount, min_buy) = (r.u128()?, r.u128()?);
        let relayer = r.option(|r| r.account())?;
        let expiry = r.u64()?;
        let order = b[start..r.i].to_vec();
        let op = MetaOp::read(&mut r)?;
        let at = r.i;
        let auth = Auth::read(&mut r, true, &op.digest())?;
        legs.push(SettleLeg { order, sell_token, buy_token, sell_amount, min_buy, expiry, relayer, op, auth_raw: b[at..r.i].to_vec(), auth });
    }
    r.end()?;
    Ok(legs)
}

/// dex/src/lib.rs `leg()` without the clock: op 1 for the order's sell token, `to = relayer = the DEX`, amount =
/// `sell_amount` > 0, `extra = sha256(Borsh(order))`.
fn dex_leg(l: &SettleLeg, dex: &str) -> std::result::Result<(), &'static str> {
    let me = Holder::Near(dex.into());
    if l.op.op != 1 || l.op.contract != l.sell_token || l.op.to != me || l.op.relayer.as_deref() != Some(dex) {
        return Err("leg: op 1 for the order's sell token, to = relayer = this DEX");
    }
    if l.op.amount != l.sell_amount || l.op.amount == 0 {
        return Err("fill-or-kill: op amount = sell_amount");
    }
    if l.op.extra != sha256(&l.order) {
        return Err("extra is not sha256 of the order");
    }
    Ok(())
}

/// dex/src/lib.rs `pair()`: the orders cross (each buys what the other sells, two distinct tokens) and are fill-or-kill;
/// two distinct legs (`settle` indexes each leg once).
fn dex_pair(a: &SettleLeg, b: &SettleLeg) -> std::result::Result<(), &'static str> {
    if a.sell_token != b.buy_token || b.sell_token != a.buy_token || a.sell_token == a.buy_token {
        return Err("orders do not pair (each buys what the other sells)");
    }
    if a.sell_amount < b.min_buy || b.sell_amount < a.min_buy {
        return Err("fill-or-kill: each side's sell_amount covers the other's min_buy");
    }
    if a.op.digest() == b.op.digest() {
        return Err("the same leg twice");
    }
    Ok(())
}

/// The token entries that move value from the op's `from` (`op.amount`; a mandate open: its funding).
const VALUE_ENTRIES: &[&str] = &["mtx_pay", "mtx_pay_meta", "mtx_transfer", "mtx_execute_transfer", "mtx_mandate_open"];

/// The token entries a router job may target: each has a `<method>_check(caller, …same args)` view and takes
/// `(op, auth, …)` first (token/src/{metatx,account,mandate,trade}.rs).
const TOKEN_CHECKED: &[&str] = &[
    "mtx_pay", "mtx_pay_meta", "mtx_transfer", "mtx_execute_transfer", "mtx_add_key", "mtx_remove_key", "mtx_add_origin",
    "mtx_remove_origin", "mtx_set_guardian", "mtx_set_policy", "mtx_start_recovery", "mtx_finish_recovery",
    "mtx_cancel_recovery", "mtx_mandate_open", "mtx_mandate_pay", "mtx_revoke", "mtx_trade", "mtx_cancel",
    "mtx_invalidate_nonces",
];
/// The DEX `settle` floor (dex/src/lib.rs `settle_gas`): `GAS_SETTLE_SELF` 9 + `GAS_ON_LEGS` 18 + per leg `GAS_LEG_BASE`
/// 6 + `IMPLICIT_TRANSFER_GAS` (a leg refunds its excess deposit to the signer, ruling A) + its `sig_gas`.
const DEX_SETTLE_GAS: u64 = 27 * TGAS;
const DEX_LEG_GAS: u64 = 6 * TGAS + IMPLICIT_TRANSFER_GAS;
/// dex `PAYOUT_YOCTO`, and the fixed bytes of a settle entry beside Borsh(Settle) (near-vectors.json `dexEntry`: key
/// `s` ‖ id 33 + 40, two leg-index records 105 each).
const DEX_PAYOUT_YOCTO: u128 = 2;
const DEX_ENTRY_FIXED_BYTES: u64 = 283;
/// The `target_gas` floor of a listed third-party target (`params.relay_fee.targets`): the node cannot read its call,
/// so only an empty budget is refused; the operator vouches for the target.
pub const GAS_TARGET_MIN: u64 = 5 * TGAS;

/// The Borsh size of a holder.
fn holder_len(h: &Holder) -> u64 {
    match h {
        Holder::Near(a) => 1 + 4 + a.len() as u64,
        Holder::Ua(_) => 33,
    }
}

/// Fix 1 m4: a wrapper job whose entry makes its own fee payment fail is refused before simulation (the check view
/// runs both against the state before the entry, so it passes): removing the payment's signing key, removing its
/// passkey's origin, or turning on passkey-for-value while the payment is not passkey-signed — when the entry's subject
/// is the payer.
pub fn wrapper_conflicts(entry: &Entry, op: &MetaOp, auth: &Auth) -> Result<()> {
    let Entry::FeeWrapper { entry, args } = entry else { return Ok(()) };
    let mut r = Reader::new(args);
    let eop = MetaOp::read(&mut r)?;
    Auth::read(&mut r, true, &eop.digest())?;
    if eop.from != op.from {
        return Ok(());
    }
    match entry.as_str() {
        "mtx_remove_key" => {
            let key = (r.u16()?, r.bytes()?.to_vec());
            if auth.record() == Some(key) {
                bail!("the entry would remove the key the fee payment is signed with: the payment must fail");
            }
        }
        "mtx_remove_origin" => {
            let origin = r.string()?;
            if auth.origins().contains(&origin) {
                bail!("the entry would remove the origin {origin} of the fee payment's passkey: the payment must fail");
            }
        }
        "mtx_set_policy" => anyhow::ensure!(
            r.u8()? & 1 == 0 || auth.passkey_only(),
            "the entry turns on passkey-for-value but the fee payment is not passkey-signed: the payment must fail"
        ),
        _ => {}
    }
    Ok(())
}

/// Fix 3 N2: the `expiry` of a `mtx_mandate_open(op, auth, terms)` call's `MandateTerms`.
fn mandate_expiry(args: &[u8]) -> Result<u64> {
    let mut r = Reader::new(args);
    let op = MetaOp::read(&mut r)?;
    Auth::read(&mut r, true, &op.digest())?;
    r.holder()?;
    r.holder()?;
    r.u128()?;
    r.u128()?;
    r.u64()?;
    r.u64()
}

/// Fix 3 N1: a wrapped key entry's subject and the passkey origins the subject holds right after the entry when it
/// was not opened yet: its own assertion's origins (`open_lazily`) and an origin it adds (`mtx_add_origin`,
/// `mtx_add_key(key, Some(origin))`).
fn entry_origins(entry: &str, args: &[u8]) -> Result<(Holder, Vec<String>)> {
    let mut r = Reader::new(args);
    let op = MetaOp::read(&mut r)?;
    let mut origins = Auth::read(&mut r, true, &op.digest())?.origins();
    match entry {
        "mtx_add_origin" => origins.push(r.string()?),
        "mtx_add_key" => {
            r.u16()?;
            r.bytes()?;
            origins.extend(r.option(|r| r.string())?);
        }
        _ => {}
    }
    Ok((op.from, origins))
}

/// The chain's action fees the node prices (gas): an action receipt's creation, a function call's base and per byte of
/// method name and args. T19 ruling B: read from the RPC's `EXPERIMENTAL_protocol_config` at start (customer chains
/// may differ; protocol 88 has 0.2 / 0.78 Tgas per call where the old pin was 2.32), each item = max(send_sir,
/// send_not_sir, execution), charged once at send and once at execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionFees {
    pub receipt: u64,
    pub function_call: u64,
    pub per_byte: u64,
}

impl ActionFees {
    /// `runtime_config.transaction_costs` of `EXPERIMENTAL_protocol_config`; a missing item is an error.
    pub fn from_protocol_config(pc: &Value) -> Result<Self> {
        let tc = &pc["runtime_config"]["transaction_costs"];
        let item = |v: &Value, what: &str| -> Result<u64> {
            ["send_sir", "send_not_sir", "execution"].iter().try_fold(0u64, |m, k| {
                v[k].as_u64().map(|x| m.max(x)).ok_or_else(|| anyhow!("protocol config: no transaction_costs {what}.{k}"))
            })
        };
        Ok(Self {
            receipt: item(&tc["action_receipt_creation_config"], "action_receipt_creation_config")?,
            function_call: item(&tc["action_creation_config"]["function_call_cost"], "function_call_cost")?,
            per_byte: item(&tc["action_creation_config"]["function_call_cost_per_byte"], "function_call_cost_per_byte")?,
        })
    }
}

/// Fix 1 m5: the gas a lane transaction burns besides its prepaid gas (its action fees).
pub fn action_fees(fees: &ActionFees, call: &Call) -> u64 {
    let bytes = (call.method.len() as u64).saturating_add(call.args.len() as u64);
    2u64.saturating_mul(fees.receipt.saturating_add(fees.function_call).saturating_add(fees.per_byte.saturating_mul(bytes)))
}

/// Fix 1 m5: one `relay_timeout(ref)` transaction (prepaid + action fees), which a router job may have to send.
pub fn timeout_gas(fees: &ActionFees) -> u64 {
    let c = Call { receiver: String::new(), method: "relay_timeout".into(), args: vec![0; 32], gas: GAS_RELAY_TIMEOUT, deposit: 0 };
    GAS_RELAY_TIMEOUT + action_fees(fees, &c)
}

/// A subject's keys on one token: `(kind, key_data)`.
pub type KeyList = Vec<(u16, Vec<u8>)>;

/// Fix 1 m6 (R9): a one-line view of a subject's key sets per token, and whether they differ between tokens.
pub fn describe_key_sets(sets: &[(String, Option<KeyList>)]) -> (String, bool) {
    let drift = sets.windows(2).any(|w| w[0].1 != w[1].1);
    let line = sets.iter().map(|(t, k)| match k {
        None => format!("{t}: no account"),
        Some(k) => {
            let keys: Vec<String> = k.iter().map(|(kind, d)| format!("{kind:#06x}:{}", alloy::hex::encode(&d[..d.len().min(8)]))).collect();
            format!("{t}: [{}]", keys.join(", "))
        }
    });
    (line.collect::<Vec<_>>().join("; "), drift)
}

/// The wrapped key ops (their subject's key set is shown, R9).
const KEY_OPS: &[&str] = &[
    "mtx_add_key", "mtx_remove_key", "mtx_add_origin", "mtx_remove_origin", "mtx_set_guardian", "mtx_set_policy",
    "mtx_start_recovery", "mtx_cancel_recovery", "mtx_finish_recovery",
];

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
    let gas = job_gas(entry, &Auth::decode(auth, &op.digest())?)?;
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

/// An escrow entry as the node follows it: who staked it, at which token, until when, at which stage.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingEntry {
    token: String,
    relayer: String,
    deadline: u64,
    /// 0 Hold, 1 Call, 2 Settle, 3 Owed.
    stage: u8,
}

/// relayfee `pending(ref) -> Option<Pending>`.
fn decode_pending(b: &[u8]) -> Result<Option<PendingEntry>> {
    let mut r = Reader::new(b);
    let p = r.option(|r| {
        r.u64()?;
        let token = r.account()?;
        r.account()?;
        r.holder()?;
        r.option(|r| r.holder())?;
        r.u128()?;
        let relayer = r.account()?;
        r.u128()?;
        r.u128()?;
        let deadline = r.u64()?;
        let stage = r.u8()?;
        r.bool()?;
        Ok(PendingEntry { token, relayer, deadline, stage })
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
    Auth::read(&mut r, true, &op.digest())?;
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
/// Fix 1 m7: a view stopped by the RPC's own `max_gas_burnt_view` (`GasLimitExceeded`) is the RPC's limit, not the
/// job's: retried (the relayer's RPC must allow ≥ 300 Tgas, module doc).
fn sim(e: anyhow::Error) -> SimError {
    let text = format!("{e:#}");
    let rpc_limit = text.contains("GasLimitExceeded") || text.contains("Exceeded the maximum amount of gas");
    match cause_of(&e) {
        Some("CONTRACT_EXECUTION_ERROR") if !rpc_limit => SimError::Revert(text),
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
    /// `ref` ⇒ when this node last sent `relay_timeout` for it.
    timeouts: Mutex<HashMap<[u8; 32], u64>>,
    /// The chain's action fees, read once (`start_check`, ruling B).
    fees: std::sync::OnceLock<ActionFees>,
}

struct Work {
    op: MetaOp,
    auth_raw: Vec<u8>,
    auth: Auth,
    entry: Entry,
}

impl NearAdapter {
    pub fn new(cfg: &ChainCfg, signers: &[LocalSigner]) -> Result<Self> {
        if cfg.rpc_urls.is_empty() || signers.is_empty() {
            bail!("chain {}: needs rpc_urls and at least one lane", cfg.chain_key());
        }
        let net = cfg.network.as_deref().ok_or_else(|| anyhow!("near: network must be the genesis hash (base58)"))?;
        let network = b58_32(net).context("near: network must be the genesis hash (base58 of 32 bytes)")?;
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
            timeouts: Mutex::new(HashMap::new()),
            fees: std::sync::OnceLock::new(),
        })
    }

    /// T19 ruling B: the chain's action fees from `EXPERIMENTAL_protocol_config` (read once; never assumed).
    pub async fn fees(&self) -> Result<ActionFees> {
        if let Some(f) = self.fees.get() {
            return Ok(*f);
        }
        let pc = self.rpc("EXPERIMENTAL_protocol_config", json!({"finality": "final"})).await?;
        let f = ActionFees::from_protocol_config(&pc)?;
        Ok(*self.fees.get_or_init(|| f))
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
        let auth = Auth::decode(&auth_raw, &op.digest())?;
        // fix 4 n1: a router job's target_gas is the node's (`build`, `target_check`): only the rest is bounded here
        let mut pinned = entry.clone();
        if let Entry::FeeRouter { target_gas, .. } = &mut pinned {
            *target_gas = 0;
        }
        job_gas(&pinned, &auth)?;
        wrapper_conflicts(&entry, &op, &auth)?;
        Ok(Work { op, auth_raw, auth, entry })
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
        // fix 1 m1: our relay refused at its own first receipt (e.g. this ref already in flight): nothing of ours is held
        let first = v.pointer("/transaction_outcome/outcome/status/SuccessReceiptId").and_then(Value::as_str);
        let tx_failed = v.pointer("/transaction_outcome/outcome/status/Failure").is_some();
        let first_failed = v["receipts_outcome"].as_array().into_iter().flatten()
            .find(|rc| first.is_some() && rc["id"].as_str() == first)
            .is_some_and(|rc| !succeeded(&rc["outcome"]));
        if tx_failed || first_failed {
            let why = value.err().unwrap_or_default();
            return Ok(TxStatus::Reverted { reason: format!("relay refused at its first receipt: nothing was held ({why})") });
        }
        let args = b64d(v.pointer("/transaction/actions/0/FunctionCall/args").and_then(Value::as_str).ok_or_else(|| anyhow!("relay without args"))?)?;
        let r = relay_args_ref(&args)?;
        let signer = v.pointer("/transaction/signer_id").and_then(Value::as_str).unwrap_or_default();
        let entry = decode_pending(&self.view(router, "pending", &r).await?)?;
        if entry.as_ref().is_some_and(|p| p.relayer != signer) {
            return Ok(TxStatus::Reverted { reason: format!("the escrow entry under {} was staked by another relayer; ours held nothing", hex0x(&r)) });
        }
        let Some(p) = entry else {
            let why = value.err().map(|f| format!(" ({f})")).unwrap_or_default();
            return Ok(TxStatus::Reverted { reason: format!("relay fee refunded: the call failed, the hold was refused or the relay timed out (the payer was not charged){why}") });
        };
        self.escrow_due(v, r, p).await
    }

    /// T19 (near-sandbox): a router call in flight (a target that yields, a callback chain still waiting) keeps its
    /// transaction `INCLUDED_FINAL` / `Started`; past the deadline our entry is timed out here, as in `escrow_due`. No
    /// entry yet, gone, or another relayer's: pending, the final outcome decides (`escrow_status`).
    async fn escrow_in_flight(&self, v: &Value) -> Result<TxStatus> {
        let router = self.relay_fee.router.as_deref().ok_or_else(|| anyhow!("no router configured"))?;
        let Some(args) = v.pointer("/transaction/actions/0/FunctionCall/args").and_then(Value::as_str) else { return Ok(TxStatus::Pending) };
        let r = relay_args_ref(&b64d(args)?)?;
        let signer = v.pointer("/transaction/signer_id").and_then(Value::as_str).unwrap_or_default();
        match decode_pending(&self.view(router, "pending", &r).await?)? {
            Some(p) if p.relayer == signer => self.escrow_due(v, r, p).await,
            _ => Ok(TxStatus::Pending),
        }
    }

    /// Our entry `r` still pending: past its deadline (no settlement in flight) send `relay_timeout(ref)`, again after
    /// `RELAY_TIMEOUT_RETRY_S`; `RELAY_STUCK_S` past it the job ends reverted so the lane moves on.
    async fn escrow_due(&self, v: &Value, r: [u8; 32], p: PendingEntry) -> Result<TxStatus> {
        let router = self.relay_fee.router.as_deref().ok_or_else(|| anyhow!("no router configured"))?;
        let PendingEntry { token, deadline, stage, .. } = p;
        let now = now();
        if now > deadline.saturating_add(RELAY_STUCK_S) && stage == 2 {
            // fix 1 m2: on_settle failed after a token settle that may have been a release: ask the token
            let mut a = borsh_str(router);
            a.extend_from_slice(&r);
            let reason = if decode_held(&self.view(&token, "relay_held", &a).await?)? {
                format!("escrow entry {} still held at token {token} {RELAY_STUCK_S} s past its deadline with a settlement stuck in flight: the payer is not charged while it is held", hex0x(&r))
            } else {
                format!("escrow entry {} settled at the token {token} (released or refunded) but the router's on_settle failed: the token's payment_settled for this ref tells which", hex0x(&r))
            };
            return Ok(TxStatus::Reverted { reason });
        }
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

    /// Fix 1 I2 (the TON I1 rule on every family: the relayer never pays for a call bound to fail): the router target's
    /// call as far as the node can see it. A configured token: a relayable entry (`TOKEN_CHECKED`) whose `<method>_check`
    /// passes with the executor as caller (the target sees the executor), `target_gas` ≥ the entry's pinned job gas,
    /// `target_deposit` ≥ what it stores. The DEX's `settle`: canonical legs, each order open or bound to the executor,
    /// each leg's `mtx_trade_check` on its (configured) sell token as the DEX, `target_gas` ≥ `settle_gas`,
    /// `target_deposit` ≥ the settle entry + 2 yoctoNEAR + both legs' storage. A listed third-party target:
    /// `target_gas` ≥ `GAS_TARGET_MIN` only (the operator vouches for it).
    async fn target_check(&self, pay: &MetaOp, target: &str, method: &str, args: &[u8], gas: u64, deposit: u128) -> std::result::Result<(u64, u128), SimError> {
        let rv = |m: String| SimError::Revert(m);
        let executor = self.relay_fee.executor.as_deref().ok_or_else(|| rv("no executor configured".into()))?;
        let check = |b: Vec<u8>, what: &str| -> std::result::Result<u128, SimError> {
            decode_check(&b).map_err(transport)?.map_err(|e| rv(format!("router target {what}: {e}")))
        };
        let margin = |vu: u64, what: &str| match vu <= now().saturating_add(RELAY_EXPIRY_MARGIN_S) {
            true => Err(rv(format!("{what} expires within {RELAY_EXPIRY_MARGIN_S} s (at {vu}): it would expire in transit"))),
            false => Ok(()),
        };
        if self.relay_fee.tokens.iter().any(|t| t == target) {
            if !TOKEN_CHECKED.contains(&method) {
                return Err(rv(format!("router target {target}: {method} is not a relayable token entry (no check view)")));
            }
            let mut r = Reader::new(args);
            let (auth, top) = MetaOp::read(&mut r).and_then(|op| Ok((Auth::read(&mut r, true, &op.digest())?, op)))
                .map_err(|e| rv(format!("router target args of {method}: {e:#}")))?;
            margin(top.valid_until, "the target op")?;
            if method == "mtx_mandate_open" {
                margin(mandate_expiry(args).map_err(|e| rv(format!("router target args of {method}: {e:#}")))?, "the mandate")?;
            }
            let c = self.view(target, &format!("{method}_check"), &[borsh_str(executor), args.to_vec()].concat()).await.map_err(sim)?;
            let need = check(c, &format!("{method}_check"))?;
            // fix 2 R3: relay_hold debits the fee before the target runs; the target's check read the balance before it
            if target == pay.contract && VALUE_ENTRIES.contains(&method) && top.from == pay.from {
                let have = self.balance(target, &pay.from).await?;
                let want = top.amount.saturating_add(pay.amount);
                if have < want {
                    return Err(rv(format!("the payer's balance {have} on {target} is below the target's {} + the fee {}", top.amount, pay.amount)));
                }
            }
            // fix 3 g1 (target_gas / target_deposit are relayer-chosen, not in ref): the entry's pinned gas, and exactly
            // what it stores (fix 2 f4: a surplus would be refunded to the executor, its predecessor)
            return Ok((GAS_JOB_BASE.saturating_add(auth.attach_gas()), need));
        }
        if self.relay_fee.dex.as_deref() == Some(target) {
            if method != "settle" {
                return Err(rv(format!("router target {target}: {method} is not the DEX's settle")));
            }
            let legs = settle_legs(args).map_err(|e| rv(format!("router target args of settle: {e:#}")))?;
            if let Some(l) = legs.iter().find(|l| l.relayer.as_deref().is_some_and(|x| x != executor)) {
                return Err(rv(format!("order relayer {:?} is not the executor: the DEX refuses it via the router", l.relayer)));
            }
            if let Some(l) = legs.iter().find(|l| !self.relay_fee.tokens.contains(&l.sell_token)) {
                return Err(rv(format!("a settle leg sells {}, not a configured token", l.sell_token)));
            }
            // fix 2 R4: dex `leg()` and `pair()`, off chain
            for l in &legs {
                dex_leg(l, target).map_err(|e| rv(e.into()))?;
                margin(l.expiry, "a DEX order")?;
                margin(l.op.valid_until, "a DEX leg op")?;
            }
            dex_pair(&legs[0], &legs[1]).map_err(|e| rv(e.into()))?;
            let settle_gas = legs.iter().fold(DEX_SETTLE_GAS, |g, l| g.saturating_add(DEX_LEG_GAS).saturating_add(l.auth.router_gas()));
            let (da, db) = (legs[0].op.digest(), legs[1].op.digest());
            if self.view(target, "pending", &sha256(&[da, db].concat())).await.map_err(transport)?.first() != Some(&0) {
                return Err(rv("this pair is already pending at the DEX (settle_id(a, b))".into()));
            }
            // fix 2 f1: a leg indexed in another settle (e.g. a failed direct settle) panics `settle`
            for d in [da, db] {
                if self.view(target, "leg_settle", &d).await.map_err(transport)?.first() != Some(&0) {
                    return Err(rv(format!("leg {} is already in a settle at the DEX", hex0x(&d))));
                }
            }
            let mut larger = 0u128;
            for (i, l) in legs.iter().enumerate() {
                let receiver = &legs[1 - i].op.from;
                let mut a = [borsh_str(target), l.op.borsh(), l.auth_raw.clone(), l.order.clone()].concat();
                receiver.write(&mut a);
                let c = self.view(&l.sell_token, "mtx_trade_check", &a).await.map_err(sim)?;
                larger = larger.max(check(c, "mtx_trade_check")?);
            }
            // Borsh(Settle): per leg token, seller, lane 32, nonce 8, digest 32, amount 16; relayer; deposit 16, expiry 8, done 1
            let settle = legs.iter().map(|l| 4 + l.sell_token.len() as u64 + holder_len(&l.op.from) + 88).sum::<u64>()
                + 4 + executor.len() as u64 + 25;
            let pc = self.rpc("EXPERIMENTAL_protocol_config", json!({"finality": "final"})).await.map_err(transport)?;
            let cost = dec_u128(&pc["runtime_config"]["storage_amount_per_byte"], "storage_amount_per_byte").map_err(transport)?;
            // fix 2 f3: settle splits the rest evenly between the legs: 2 × the larger leg
            let need = cost.saturating_mul(u128::from(DEX_ENTRY_FIXED_BYTES + settle))
                .saturating_add(DEX_PAYOUT_YOCTO).saturating_add(larger.saturating_mul(2));
            // fix 3 g1: settle_gas and the floor, set by the node
            return Ok((settle_gas, need));
        }
        // fix 2 f2: a listed third-party target, only its listed methods (checked in `entry`); its figures are the job's,
        // target_gas raised to the floor (fix 3 g1)
        Ok((gas.max(GAS_TARGET_MIN), deposit))
    }

    /// A holder's balance on a token (`ft_balance_of` / `ua_balance_of`, NEP-141 JSON).
    async fn balance(&self, token: &str, h: &Holder) -> std::result::Result<u128, SimError> {
        let (method, args) = match h {
            Holder::Near(a) => ("ft_balance_of", json!({"account_id": a})),
            Holder::Ua(id) => ("ua_balance_of", json!({"id": id})),
        };
        let b = self.view(token, method, &serde_json::to_vec(&args).map_err(|e| transport(e.into()))?).await.map_err(sim)?;
        let v: Value = serde_json::from_slice(&b).map_err(|e| transport(e.into()))?;
        dec_u128(&v, method).map_err(transport)
    }

    /// Fix 1 m6 (R9): logs the key-op subject's key sets on every configured token; a drift is a warning.
    async fn show_key_sets(&self, args: &[u8]) {
        let Ok(op) = MetaOp::read(&mut Reader::new(args)) else { return };
        match self.key_sets(&op.from).await {
            Ok(sets) => {
                let (line, drift) = describe_key_sets(&sets);
                if drift {
                    tracing::warn!(chain = %self.key, subject = %op.from.display(), "key sets differ between tokens: {line}");
                } else {
                    tracing::info!(chain = %self.key, subject = %op.from.display(), "key sets: {line}");
                }
            }
            Err(e) => tracing::warn!(chain = %self.key, subject = %op.from.display(), "key sets unreadable: {e:#}"),
        }
    }

    /// R9: a subject's SCaaS key set on each configured token (`(kind, key_data)`; `None` = no account there). Keys
    /// live per token (spec §3.1), so they can drift between tokens; this is what the node shows.
    pub async fn key_sets(&self, holder: &Holder) -> Result<Vec<(String, Option<KeyList>)>> {
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
        // fix 1 I1: relay_hold spends the payment lane even when the escrow refunds: the outcome is the escrow's
        if matches!(w.entry, Entry::FeeRouter { .. }) {
            return Ok(None);
        }
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
        // fix 2 R1 / R2, fix 3 g2 / N2: the payment (every job), a wrapped entry's op and a wrapped mandate's expiry stay
        // valid through the relay
        let (entry_vu, mandate) = match &w.entry {
            Entry::FeeWrapper { entry, args } => (
                MetaOp::read(&mut Reader::new(args)).ok().map(|o| o.valid_until),
                (entry == "mtx_mandate_open").then(|| mandate_expiry(args).ok()).flatten(),
            ),
            _ => (None, None),
        };
        let soon = now().saturating_add(RELAY_EXPIRY_MARGIN_S);
        for (vu, what) in [(Some(w.op.valid_until), "the payment"), (entry_vu, "the wrapped entry op"), (mandate, "the mandate")] {
            if vu.is_some_and(|vu| vu <= soon) {
                return Err(SimError::Revert(format!("{what} expires within {RELAY_EXPIRY_MARGIN_S} s: it would expire in transit")));
            }
        }
        // fix 3 N1: an unopened subject paying for its own wrapped entry: the entry opens it with its own origins, then the
        // payment's passkey is checked against them
        if let Entry::FeeWrapper { entry, args } = &w.entry {
            let pay_origins = w.auth.origins();
            let (from, origins) = entry_origins(entry, args).map_err(revert)?;
            if from == w.op.from && !pay_origins.is_empty() {
                let mut a = Vec::new();
                from.write(&mut a);
                let opened = self.view(&w.op.contract, "subject", &a).await.map_err(sim)?.first() == Some(&1);
                if let Some(o) = pay_origins.iter().find(|o| !opened && !origins.contains(o)) {
                    return Err(SimError::Revert(format!(
                        "the payment's passkey origin {o} is not among the origins the entry opens the subject {} with: the payment must fail",
                        from.display()
                    )));
                }
            }
        }
        // fix 3 g1: a router job's target figures are the node's (relayer-chosen, not in ref)
        let entry = match &w.entry {
            Entry::FeeRouter { target, method, args, target_gas, target_deposit } => {
                match self.has_code(target).await.map_err(transport)? {
                    None => return Err(SimError::Revert(format!("relay-fee target {target} does not exist"))),
                    Some(false) => return Err(SimError::Revert(format!("relay-fee target {target} has no code"))),
                    Some(true) => {}
                }
                let (tg, td) = self.target_check(&w.op, target, method, args, *target_gas, *target_deposit).await?;
                Entry::FeeRouter { target: target.clone(), method: method.clone(), args: args.clone(), target_gas: tg, target_deposit: td }
            }
            e => e.clone(),
        };
        let mut call = call_of(&self.relay_fee, &entry, &w.op, &w.auth_raw).map_err(revert)?;
        call.deposit = match &entry {
            Entry::FeeRouter { .. } => {
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
            let fees = self.fees().await.map_err(transport)?;
            // fix 1 m5: the transaction's action fees, and a router job's possible relay_timeout transaction
            let resend = if matches!(w.entry, Entry::FeeRouter { .. }) { timeout_gas(&fees) } else { 0 };
            let gas = call.gas.saturating_add(action_fees(&fees, &call)).saturating_add(resend);
            let quote = u128::from(gas).saturating_mul(price).saturating_add(call.deposit);
            fee_covers(&self.relay_fee, &w.op, quote).map_err(revert)?;
        }
        if let Entry::FeeWrapper { entry, args } = &w.entry {
            if KEY_OPS.contains(&entry.as_str()) {
                self.show_key_sets(args).await;
            }
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
    /// T19: `wait_until = INCLUDED` (one block): with `NONE` the RPC accepts a stale nonce and drops the transaction
    /// silently (near-sandbox 2.14), so `Rejected` never comes and the lane waits for the payload to expire.
    async fn submit(&self, signed: &Signed) -> Result<()> {
        match self.rpc("send_tx", json!({"signed_tx_base64": b64(&signed.raw), "wait_until": "INCLUDED"})).await {
            Ok(_) => Ok(()),
            Err(e) if cause_of(&e) == Some("INVALID_TRANSACTION") => Err(Rejected(format!("{e:#}")).into()),
            Err(e) => Err(e),
        }
    }

    /// Mined / reverted only once every receipt is in a final block (`FINAL`); a failed receipt is reported reverted with
    /// its reason, never retried (the lane nonce moved; the payer's op was not consumed).
    async fn tx_status(&self, tx_id: &str) -> Result<TxStatus> {
        let Some(v) = self.find_tx(tx_id).await? else { return Ok(TxStatus::Unknown) };
        let relay = v.pointer("/transaction/actions/0/FunctionCall/method_name").and_then(Value::as_str) == Some("relay");
        let escrow = relay && self.relay_fee.router.is_some() && v["transaction"]["receiver_id"].as_str() == self.relay_fee.router.as_deref();
        if v["final_execution_status"].as_str() != Some("FINAL") {
            // T19: a call in flight past its deadline keeps the transaction short of FINAL: its timeout is due now
            return if escrow { self.escrow_in_flight(&v).await } else { Ok(TxStatus::Pending) };
        }
        let height = self.block_height_of(&v["transaction_outcome"]["block_hash"]).await?;
        if escrow {
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
        // fix 1 I3: a non-archival RPC answers UNKNOWN_BLOCK for pruned heights too: never read below its horizon
        let st = self.rpc("status", json!([])).await?;
        let earliest = st.pointer("/sync_info/earliest_block_height").and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("status without sync_info.earliest_block_height"))?;
        if from < earliest {
            bail!("range starts at {from}, below the RPC's earliest kept block {earliest} (pruned: use an archival RPC)");
        }
        let ids = Ids { tokens, router: self.relay_fee.router.clone(), dex: self.relay_fee.dex.clone() };
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
        // ruling B: no assumed fees: without the chain's action fees the node does not start
        self.fees().await.context("the RPC's EXPERIMENTAL_protocol_config (action fees): the chain does not start without them")?;
        let st = self.rpc("status", json!([])).await?;
        let g = st["genesis_hash"].as_str().ok_or_else(|| anyhow!("status without genesis_hash"))?;
        if g != self.network_b58 {
            bail!("the RPC's genesis hash {g} is not the configured network {}", self.network_b58);
        }
        let mut ids: Vec<(&str, &str)> = self.relay_fee.tokens.iter().map(|t| (t.as_str(), "token")).collect();
        ids.extend(self.relay_fee.router.as_deref().map(|r| (r, "router")));
        ids.extend(self.relay_fee.executor.as_deref().map(|e| (e, "executor")));
        ids.extend(self.relay_fee.dex.as_deref().map(|d| (d, "dex")));
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
    /// The nearcore genesis `RuntimeFeesConfig` figures (send = exec), a fixture only: the node reads the chain's (ruling B).
    const PINNED: ActionFees = ActionFees { receipt: 108_059_500_000, function_call: 2_319_861_500_000, per_byte: 2_235_934 };

    fn fee_item(g: u64) -> Value {
        json!({"send_sir": g, "send_not_sir": g, "execution": g})
    }

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

    /// Chrome's tail after the origin (WebAuthn L3); Safari's is `}`.
    const CHROME_TAIL: &str = r#","crossOrigin":false}"#;

    /// `{"type":"webauthn.get","challenge":"<b64url(ch)>","origin":"<origin>"` ‖ `tail`.
    fn cdj(ch: &[u8; 32], origin: &str, tail: &str) -> String {
        let c = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ch);
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{origin}"{tail}"#)
    }

    /// A Borsh passkey auth carrying clientDataJSON `cd` (key and signature not checked off chain).
    fn passkey(cd: &str) -> Vec<u8> {
        [vec![2], vec![7; 64], bvec(&[1; 37]), bstr(cd), vec![0; 64]].concat()
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
            dex: Some(DEX.into()),
            targets: BTreeMap::new(),
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
        router_op_g(target, method, args, to, "30000000000000", "0")
    }

    fn router_op_g(target: &str, method: &str, args: &[u8], to: Holder, tg: &str, td: &str) -> (MetaOp, Value) {
        let mut op = op_of("relay_fee_pay_router_short");
        let call = router_call(target, method, args);
        let tb = [&[target.len() as u8][..], target.as_bytes()].concat();
        let r = relay_ref(&op.network, &tb, &call, &op.extra);
        op.pay_ref = r;
        op.lane = pay_lane(&r);
        op.to = to;
        let o = o_op(&op, &auth_bytes(&row("relay_fee_pay_router_short")["auth"]), json!({"kind": "relay_fee",
            "extra": {"call": h(&call), "route": "router", "target_gas": tg, "target_deposit": td}}));
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
        /// `status.sync_info.earliest_block_height` (the RPC's oldest kept block).
        earliest: u64,
        /// `storage_amount_per_byte` (yoctoNEAR).
        byte_cost: u128,
        /// (account, view) → the error text of a failing view.
        view_errs: HashMap<(String, String), String>,
        /// `relay_check` answers the contract's `relay_gas` for an ed25519 payment: ROUTER_FIXED_GAS + 1 Tgas + target_gas.
        auto_relay: bool,
        /// `EXPERIMENTAL_protocol_config` without `transaction_costs` (ruling B: the node must not start).
        no_fees: bool,
    }

    /// `(target_gas, target_deposit)` of `relay` (or `relay_check`) arguments: after target, method and args.
    fn relay_figures(b: &[u8]) -> (u64, u128) {
        let mut i = 0;
        for _ in 0..3 {
            i += 4 + u32::from_le_bytes(b[i..i + 4].try_into().unwrap()) as usize;
        }
        (u64::from_le_bytes(b[i..i + 8].try_into().unwrap()), u128::from_le_bytes(b[i + 8..i + 24].try_into().unwrap()))
    }

    fn rpc_err(name: &str) -> Value {
        json!({"name": "HANDLER_ERROR", "cause": {"name": name, "info": {}}, "code": -32000, "message": "Server error"})
    }

    fn answer(w: &mut World, method: &str, p: &Value) -> std::result::Result<Value, Value> {
        w.calls.push((method.to_string(), p.clone()));
        let s = |k: &str| p[k].as_str().unwrap_or_default().to_string();
        match method {
            "status" => Ok(json!({"chain_id": "localnet", "genesis_hash": w.genesis,
                                  "sync_info": {"earliest_block_height": w.earliest, "latest_block_height": 100}})),
            "EXPERIMENTAL_protocol_config" if w.no_fees => Ok(json!({"runtime_config": {"storage_amount_per_byte": w.byte_cost.to_string()}})),
            "EXPERIMENTAL_protocol_config" => Ok(json!({"runtime_config": {"storage_amount_per_byte": w.byte_cost.to_string(),
                "transaction_costs": {"action_receipt_creation_config": fee_item(PINNED.receipt),
                    "action_creation_config": {"function_call_cost": fee_item(PINNED.function_call),
                        "function_call_cost_per_byte": fee_item(PINNED.per_byte)}}}})),
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
                "call_function" if w.auto_relay && s("method_name") == "relay_check" => {
                    let a = base64::engine::general_purpose::STANDARD.decode(s("args_base64")).unwrap();
                    Ok(json!({"result": router_check(1, 1, ROUTER_FIXED_GAS + TGAS + relay_figures(&a).0), "logs": []}))
                }
                "call_function" if w.view_errs.contains_key(&(s("account_id"), s("method_name"))) => {
                    let m = &w.view_errs[&(s("account_id"), s("method_name"))];
                    Err(json!({"name": "HANDLER_ERROR", "cause": {"name": "CONTRACT_EXECUTION_ERROR", "info": {"vm_error": m}},
                               "code": -32000, "message": "Server error", "data": m}))
                }
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
        cfg_tokens(url, relay_fee, &[TOKEN])
    }

    fn cfg_tokens(url: &str, relay_fee: &str, tokens: &[&str]) -> ChainCfg {
        let t: Vec<String> = tokens.iter().map(|t| format!("{{ address = \"{t}\", decimals = 6 }}")).collect();
        toml::from_str(&format!(
            "family = \"near\"\nnetwork = \"{NET_B58}\"\nrpc_urls = [\"{url}\"]\nlanes = [0]\n\
             tokens = [{}]\nfinality = {{ mode = \"instant\" }}\n\
             params = {{ dex = \"{DEX}\"{relay_fee} }}", t.join(", ")
        ))
        .unwrap()
    }

    fn fee_cfg(price: &str) -> String {
        format!(", relay_fee = {{ router = \"{ROUTER}\", executor = \"{EXECUTOR}\", min_amount = 1, min_yocto_value = {{ \"{TOKEN}\" = \"{price}\" }} }}")
    }

    /// A healthy chain: genesis = the vectors' network, every contract deployed and keyless, lane 0 registered.
    fn world() -> World {
        let mut w = World { genesis: NET_B58.into(), gas_price: 100_000_000, nonce: 41, byte_cost: 10u128.pow(19), ..Default::default() };
        w.code = [TOKEN, ROUTER, EXECUTOR, DEX].map(String::from).to_vec();
        let net: Vec<u8> = serde_json::to_vec(&b32(&nv()["network"]).to_vec()).unwrap();
        w.views.insert((TOKEN.into(), "network".into()), net);
        w.views.insert((ROUTER.into(), "executor".into()), bstr(EXECUTOR));
        w.views.insert((TOKEN.into(), "storage_balance_of".into()), br#"{"total":"1250000000000000000000","available":"0"}"#.to_vec());
        w.views.insert((TOKEN.into(), "ft_balance_of".into()), br#""1000000000000""#.to_vec());
        w.views.insert((DEX.into(), "leg_settle".into()), vec![0]);
        w.views.insert((DEX.into(), "pending".into()), vec![0]);
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
                Auth::decode(&auth_bytes(&r["auth"]), &op.digest()).unwrap_or_else(|e| panic!("{} auth: {e:#}", r["name"]));
                n_auth += 1;
            }
        }
        assert_eq!(n_auth, rows.len(), "every row's auth decodes");
        assert!(matches!(Auth::decode(&auth_bytes(&row("set_guardian_msig")["auth"]), &op_of("set_guardian_msig").digest()).unwrap(), Auth::Msig { sigs, .. } if matches!(sigs[..], [Auth::Ed25519(_)])));
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
        let z = [0; 32];
        assert!(Auth::decode(&[&a[..], &[0]].concat(), &z).is_err());
        assert!(Auth::decode(&[&[4u8][..], &a[1..]].concat(), &z).is_err());
        let msig = |inner: &[u8]| [vec![3], bvec(&[0, 1]), 1u32.to_le_bytes().to_vec(), vec![0], inner.to_vec()].concat();
        assert!(matches!(Auth::decode(&msig(&a), &z).unwrap(), Auth::Msig { sigs, .. } if matches!(sigs[..], [Auth::Ed25519(_)])));
        assert!(Auth::decode(&msig(&msig(&a)), &z).is_err(), "msig inside msig");
        let pk = |n: usize| passkey(&cdj(&z, &format!("https://{}", "a".repeat(n - cdj(&z, "https://", "}").len())), "}"));
        assert_eq!(Auth::decode(&pk(1024), &z).unwrap().passkeys(), 1);
        assert!(Auth::decode(&pk(1025), &z).is_err(), "passkey field over 1024 bytes (contract PASSKEY_FIELD_MAX)");
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
        let ch = op_of("cancel_recovery").digest();
        let pk = passkey_from(&ch, "https://pay.scaas.test");
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
        let pay = Auth::decode(&pk, &ch).unwrap();
        assert!(job_gas(&wrapper(12), &pay).unwrap() <= MAX_GAS, "12 + 1 passkeys");
        assert!(format!("{:#}", job_gas(&wrapper(13), &pay).unwrap_err()).contains("13"), "13 + 1 passkeys");
        let ed = Auth::decode(&auth_bytes(&row("pay")["auth"]), &ch).unwrap();
        assert!(job_gas(&wrapper(13), &ed).is_ok(), "13 passkeys + an ed25519 payment");
        assert!(job_gas(&Entry::Pay, &ed).unwrap() < job_gas(&Entry::Pay, &pay).unwrap(), "a passkey costs more");
        let router = |tg: u64| Entry::FeeRouter { target: DEX.into(), method: "settle".into(), args: vec![], target_gas: tg * TGAS, target_deposit: 0 };
        assert_eq!(job_gas(&router(10), &ed).unwrap(), (36 + 60 + 1 + 10) * TGAS);
        assert_eq!(job_gas(&router(179), &pay).unwrap(), 300 * TGAS);
        assert!(job_gas(&router(180), &pay).is_err(), "over 300 Tgas");
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
        let wcall = call_of(&pol(), &entry(&pol(), &wop, &wo).unwrap(), &wop, &hx(&wo["signature"])).unwrap();
        let quote = (wcall.gas + action_fees(&PINNED, &wcall)) as u128 * 100_000_000 + storage;
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
        // (a token's mtx_pay as the target: fix 1 I2 checks it as the executor)
        let td = 7 * 10u128.pow(21);
        let pay = [op_of("pay").borsh(), auth_bytes(&row("pay")["auth"])].concat();
        let (rop, ro) = router_op_g(TOKEN, "mtx_pay", &pay, Holder::Near(ROUTER.into()), "30000000000000", &td.to_string());
        // (fix 3 g1: the node's target figures, the entry's pinned gas 11 Tgas and its storage td)
        let set = Entry::FeeRouter { target: TOKEN.into(), method: "mtx_pay".into(), args: pay.clone(), target_gas: GAS_JOB_BASE + GAS_KEY_SIG, target_deposit: td };
        let g = job_gas(&set, &Auth::decode(&hx(&ro["signature"]), &rop.digest()).unwrap()).unwrap();
        let (entry_dep, hold) = (3_140 * 10u128.pow(18) + 1_250 * 10u128.pow(18) + 2 + td, 2_800 * 10u128.pow(18));
        let rcall = call_of(&pol(), &set, &rop, &hx(&ro["signature"])).unwrap();
        let quote = (g + action_fees(&PINNED, &rcall) + timeout_gas(&PINNED)) as u128 * 100_000_000 + entry_dep + hold;
        for (price, ok) in [(quote.div_ceil(rop.amount), true), ((quote - 1) / rop.amount, false)] {
            let mut w = world();
            w.views.insert((ROUTER.into(), "relay_check".into()), router_check(3_140 * 10u128.pow(18), entry_dep, g));
            w.views.insert((TOKEN.into(), "relay_hold_check".into()), check_ok(hold));
            w.views.insert((TOKEN.into(), "mtx_pay_check".into()), check_ok(td));
            let (a, _) = adapter(w, &fee_cfg(&price.to_string())).await;
            match (a.build(&job(ro.clone()), 0).await, ok) {
                (Ok(b), true) => assert_eq!(b.meta["deposit"], json!((entry_dep + hold).to_string())),
                (Err(SimError::Revert(r)), false) => assert!(r.contains("below"), "{r}"),
                (r, _) => panic!("price {price}: {r:?}"),
            }
        }
        // sponsored: bound to bob (not the lane), relayed only with relay_bound_payee, and then not priced
        let (_, bo) = router_op_g(TOKEN, "mtx_pay", &pay, Holder::Near("bob.test.near".into()), "30000000000000", "0");
        let mut w = World { auto_relay: true, ..world() };
        w.views.insert((TOKEN.into(), "relay_hold_check".into()), check_ok(1));
        w.views.insert((TOKEN.into(), "mtx_pay_check".into()), check_ok(0));
        let (a, _) = adapter(w, &fee_cfg("1")).await;
        match a.build(&job(bo.clone()), 0).await {
            Err(SimError::Revert(r)) => assert!(r.contains("relay_bound_payee"), "{r}"),
            r => panic!("{r:?}"),
        }
        let mut w = World { auto_relay: true, ..world() };
        w.views.insert((TOKEN.into(), "relay_hold_check".into()), check_ok(1));
        w.views.insert((TOKEN.into(), "mtx_pay_check".into()), check_ok(0));
        let sponsored = format!(", relay_fee = {{ router = \"{ROUTER}\", executor = \"{EXECUTOR}\", relay_bound_payee = true }}");
        let (a, _) = adapter(w, &sponsored).await;
        a.build(&job(bo), 0).await.unwrap();
        // a check view's refusal kills the job (Revert), naming the contract's reason
        let mut w = world();
        w.views.insert((TOKEN.into(), "relay_fee_add_key_check".into()), check_err("wrong lane nonce"));
        let (a, _) = adapter(w, &fee_cfg("1")).await;
        assert!(matches!(a.build(&job(wo), 0).await, Err(SimError::Revert(r)) if r.contains("wrong lane nonce")));
    }

    /// Fix 1 m5: nearcore's action fees (receipt creation + function call base + per byte of method and args, send and
    /// execution, `RuntimeFeesConfig` defaults) are charged on top of the prepaid gas; a router job may need one
    /// `relay_timeout` transaction more.
    #[test]
    fn action_fees_and_timeout_are_priced() {
        let c = Call { receiver: TOKEN.into(), method: "mtx_pay".into(), args: vec![0; 100], gas: 1, deposit: 0 };
        assert_eq!(action_fees(&PINNED, &c), 2 * 108_059_500_000 + 2 * 2_319_861_500_000 + 2 * 2_235_934 * 107);
        let t = Call { receiver: ROUTER.into(), method: "relay_timeout".into(), args: vec![0; 32], gas: GAS_RELAY_TIMEOUT, deposit: 0 };
        assert_eq!(timeout_gas(&PINNED), (30 + 40) * TGAS + action_fees(&PINNED, &t));
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

    /// T19 ruling B: the action fees come from the RPC's protocol config, each item max(send_sir, send_not_sir,
    /// execution) (protocol 88's figures here); an RPC without them stops the node at `start_check`, and a fee job is
    /// not quoted (retried) while they are unknown.
    #[tokio::test]
    async fn action_fees_read_from_the_rpc() {
        let p88 = json!({"runtime_config": {"transaction_costs": {
            "action_receipt_creation_config": {"send_sir": 108_059_500_000u64, "send_not_sir": 108_059_500_000u64, "execution": 108_059_500_000u64},
            "action_creation_config": {
                "function_call_cost": {"send_sir": 200_000_000_000u64, "send_not_sir": 200_000_000_000u64, "execution": 780_000_000_000u64},
                "function_call_cost_per_byte": {"send_sir": 2_235_934u64, "send_not_sir": 47_683_715u64, "execution": 2_235_934u64}}}}});
        let f = ActionFees::from_protocol_config(&p88).unwrap();
        assert_eq!(f, ActionFees { receipt: 108_059_500_000, function_call: 780_000_000_000, per_byte: 47_683_715 });
        let c = Call { receiver: TOKEN.into(), method: "mtx_pay".into(), args: vec![0; 100], gas: 0, deposit: 0 };
        assert_eq!(action_fees(&f, &c), 2 * (108_059_500_000 + 780_000_000_000 + 47_683_715 * 107));
        let mut gap = p88.clone();
        gap["runtime_config"]["transaction_costs"]["action_creation_config"]["function_call_cost"]["execution"] = json!(null);
        assert!(format!("{:#}", ActionFees::from_protocol_config(&gap).unwrap_err()).contains("function_call_cost.execution"));
        // the mocked RPC serves the fixture: read once, then cached
        let (a, w) = adapter(world(), &fee_cfg("1")).await;
        a.start_check().await.unwrap();
        assert_eq!(a.fees().await.unwrap(), PINNED);
        let n = w.lock().unwrap().calls.iter().filter(|c| c.0 == "EXPERIMENTAL_protocol_config").count();
        a.fees().await.unwrap();
        assert_eq!(w.lock().unwrap().calls.iter().filter(|c| c.0 == "EXPERIMENTAL_protocol_config").count(), n, "cached");
        // without them the node does not start, and a fee job is retried, never priced on assumed fees
        let (a, _) = adapter(World { no_fees: true, ..world() }, &fee_cfg("1")).await;
        let e = format!("{:#}", a.start_check().await.unwrap_err());
        assert!(e.contains("EXPERIMENTAL_protocol_config") && e.contains("transaction_costs"), "{e}");
    }

    /// T19 (near-sandbox 2.14): `send_tx` with `wait_until = NONE` answers `{"final_execution_status": "NONE"}` even for a
    /// stale nonce (the transaction is then dropped, so the lane would wait until the payload expires); `INCLUDED`
    /// returns `INVALID_TRANSACTION` (`InvalidNonce`, expired block hash, …) synchronously, which is `Rejected`.
    #[tokio::test]
    async fn submit_waits_until_included() {
        let (a, w) = adapter(world(), "").await;
        let signed = Signed { job_id: 1, tx_id: "0x00".into(), raw: vec![1, 2], valid_until: 0, sequence: 0 };
        a.submit(&signed).await.unwrap();
        let w = w.lock().unwrap();
        let send = w.calls.iter().find(|c| c.0 == "send_tx").unwrap();
        assert_eq!(send.1["wait_until"], "INCLUDED");
    }

    /// T19 (near-sandbox): a router call still in flight (a yielded target, a callback chain that waits) keeps its
    /// transaction `INCLUDED_FINAL` / `Started`, never `FINAL`, so the timeout must be followed before finality: past the
    /// deadline this node sends `relay_timeout(ref)`; before it, or once the entry is gone (or staked by another
    /// relayer), the job stays pending until the transaction is final.
    #[tokio::test]
    async fn escrow_in_flight_times_out_after_deadline() {
        let (rop, ro) = router_job("router_short", "30000000000000", "0");
        let relay = call_of(&pol(), &entry(&pol(), &rop, &ro).unwrap(), &rop, &hx(&ro["signature"])).unwrap();
        let hash = [0x34u8; 32];
        let id = format!("0x{}", h(&hash));
        let mut flying = outcome(ROUTER, fc("relay", &relay.args), json!("Started"), vec![]);
        flying["final_execution_status"] = json!("INCLUDED_FINAL");
        let now = crate::submit::now();
        let mut w = world();
        w.txs.insert(bs58::encode(hash).into_string(), flying);
        w.views.insert((ROUTER.into(), "pending".into()), pending(now + 600, 1));
        let (a, w) = adapter(w, &fee_cfg("1")).await;
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Pending, "before the deadline");
        assert!(sent(&w).is_empty());
        w.lock().unwrap().views.insert((ROUTER.into(), "pending".into()), pending(now - 1, 1));
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Pending);
        let s = sent(&w);
        assert_eq!(s.len(), 1, "relay_timeout sent while the call is in flight");
        assert!(contains(&s[0], &[&bstr("relay_timeout")[..], &bvec(&rop.pay_ref)].concat()));
        // refunded meanwhile: still pending until the transaction is final (then `escrow_status` reverts it)
        w.lock().unwrap().views.insert((ROUTER.into(), "pending".into()), vec![0]);
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Pending);
        // another relayer's entry under the same ref: never timed out by us
        let mut other = pending(now - 1, 1);
        let at = other.windows(4 + LANE0.len()).position(|x| x == bstr(LANE0)).unwrap();
        other[at + 4] = b'b';
        w.lock().unwrap().views.insert((ROUTER.into(), "pending".into()), other);
        a.timeouts.lock().unwrap().clear();
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Pending);
        assert_eq!(sent(&w).len(), 1);
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

    // ------------------------------------------------------------------------------------------------ fix 1

    /// I1 (review RV1): `relay_hold` spends the payment lane even when the escrow is refunded, so a router job's
    /// outcome is the escrow's (`tx_status`), never "consumed"; a wrapper (atomic) or plain job keeps the lane answer.
    #[tokio::test]
    async fn refunded_router_job_is_not_consumed() {
        let mut w = world();
        w.views.insert((TOKEN.into(), "lane_nonce".into()), 1u64.to_le_bytes().to_vec());
        let (a, _) = adapter(w, &fee_cfg("1")).await;
        let (_, ro) = router_job("router_short", "30000000000000", "0");
        assert_eq!(a.op_consumed(&job(ro)).await.unwrap(), None);
        let (_, wo) = wrapper_job("wrapper_add_key_real");
        assert_eq!(a.op_consumed(&job(wo)).await.unwrap(), Some(true));
        assert_eq!(a.op_consumed(&job(o_of("pay", json!({})))).await.unwrap(), Some(true));
    }

    const TOKENB: &str = "tokenb.test.near";

    const FAR: u64 = 4_102_444_800;

    fn order(sell: &str, buy: &str, amount: u128, min_buy: u128, relayer: Option<&str>) -> Vec<u8> {
        order_x(sell, buy, amount, min_buy, relayer, FAR)
    }

    fn order_x(sell: &str, buy: &str, amount: u128, min_buy: u128, relayer: Option<&str>, expiry: u64) -> Vec<u8> {
        let rel = match relayer {
            None => vec![0],
            Some(r) => [vec![1], bstr(r)].concat(),
        };
        [bstr(sell), bstr(buy), amount.to_le_bytes().to_vec(), min_buy.to_le_bytes().to_vec(), rel, expiry.to_le_bytes().to_vec()].concat()
    }

    /// A shared trade leg op bound to `order` (`extra = sha256(Borsh(order))`, as the DEX's `leg()` checks).
    fn leg_op(name: &str, order: &[u8]) -> MetaOp {
        MetaOp { extra: sha256(order), ..op_of(name) }
    }

    fn settle_with(oa: &[u8], a: &MetaOp, ob: &[u8], b: &MetaOp) -> Vec<u8> {
        [oa.to_vec(), a.borsh(), auth_bytes(&row("trade_a")["auth"]), ob.to_vec(), b.borsh(), auth_bytes(&row("trade_b")["auth"])].concat()
    }

    fn settle_orders(oa: &[u8], ob: &[u8]) -> Vec<u8> {
        settle_with(oa, &leg_op("trade_a", oa), ob, &leg_op("trade_b", ob))
    }

    /// The settle args of the shared trade legs with the given orders' relayers.
    fn settle_args(ra: Option<&str>, rb: Option<&str>) -> Vec<u8> {
        settle_orders(&order(TOKEN, TOKENB, 100, 50, ra), &order(TOKENB, TOKEN, 60, 100, rb))
    }

    /// A world where the honest router job's views pass.
    fn router_world(g: u64) -> World {
        let mut w = World { auto_relay: true, ..world() };
        w.code.extend([TOKENB.to_string(), "app.near".to_string(), "elsewhere.near".to_string()]);
        w.views.insert((ROUTER.into(), "relay_check".into()), router_check(1, 1, g));
        w.views.insert((TOKEN.into(), "relay_hold_check".into()), check_ok(1));
        w.views.insert((TOKEN.into(), "mtx_trade_check".into()), check_ok(5));
        w.views.insert((TOKENB.into(), "mtx_trade_check".into()), check_ok(5));
        w.views.insert((TOKEN.into(), "mtx_pay_check".into()), check_ok(7));
        w
    }

    async fn build_router(w: World, relay_fee: &str, target: &str, method: &str, args: &[u8], tg: &str, td: &str) -> (std::result::Result<Built, SimError>, Arc<Mutex<World>>) {
        let (op, o) = router_op_g(target, method, args, Holder::Near("bob.test.near".into()), tg, td);
        build_router_op(w, relay_fee, op, o).await
    }

    async fn build_router_op(w: World, relay_fee: &str, op: MetaOp, o: Value) -> (std::result::Result<Built, SimError>, Arc<Mutex<World>>) {
        let gas = entry(&RelayFeePolicy { dex: Some(DEX.into()), targets: BTreeMap::from([("app.near".to_string(), vec!["anything".to_string()])]), tokens: vec![TOKEN.into(), TOKENB.into()], ..pol() }, &op, &o)
            .ok().and_then(|e| job_gas(&e, &Auth::decode(&hx(&o["signature"]), &op.digest()).unwrap()).ok()).unwrap_or(0);
        let mut w = w;
        w.views.insert((ROUTER.into(), "relay_check".into()), router_check(1, 1, gas));
        let w = Arc::new(Mutex::new(w));
        let url = serve(w.clone()).await;
        let a = NearAdapter::new(&cfg_tokens(&url, relay_fee, &[TOKEN, TOKENB]), &[lane0()]).unwrap();
        (a.build(&job(o), 0).await, w)
    }

    /// I2 (TON I1 rule on every family): the relayer never pays for a target call bound to fail. Router targets are
    /// allowlisted (configured tokens, the DEX, `params.relay_fee.targets`); a SCaaS target's call is checked first
    /// (`<method>_check` as the executor on a token, each leg's `mtx_trade_check` for the DEX's `settle`), its
    /// `target_gas` must reach the call's pinned floor and its `target_deposit` what the call stores.
    #[tokio::test]
    async fn router_target_bound_to_fail_refused() {
        let sponsored = format!(", relay_fee = {{ router = \"{ROUTER}\", executor = \"{EXECUTOR}\", relay_bound_payee = true, targets = {{ \"app.near\" = [\"anything\"] }} }}");
        let ok = |r: &std::result::Result<Built, SimError>| r.is_ok();
        let refused = |r: &std::result::Result<Built, SimError>, what: &str| matches!(r, Err(SimError::Revert(e)) if e.contains(what));
        let big = "100000000000000000000000";
        // honest: DEX settle of two open orders; a token's mtx_pay as the executor; a listed third-party target
        let (r, w) = build_router(router_world(0), &sponsored, DEX, "settle", &settle_args(None, Some(EXECUTOR)), "200000000000000", big).await;
        assert!(ok(&r), "{r:?}");
        assert_eq!(view_args(&w, "mtx_trade_check")[..4 + DEX.len()], bstr(DEX)[..], "legs checked as the DEX");
        let pay = [op_of("pay").borsh(), auth_bytes(&row("pay")["auth"])].concat();
        let (r, w) = build_router(router_world(0), &sponsored, TOKEN, "mtx_pay", &pay, "20000000000000", "7").await;
        assert!(ok(&r), "{r:?}");
        assert_eq!(view_args(&w, "mtx_pay_check"), [bstr(EXECUTOR), pay.clone()].concat(), "the target's check as the executor");
        let (r, _) = build_router(router_world(0), &sponsored, "app.near", "anything", &[1, 2, 3], "5000000000000", "0").await;
        assert!(ok(&r), "{r:?}");
        // unlisted target; a method without a check view; garbage args; target_gas below the floor; short deposit
        let (r, w) = build_router(router_world(0), &sponsored, "elsewhere.near", "anything", &[1], "100000000000000", "0").await;
        assert!(refused(&r, "not an allowed router target"), "{r:?}");
        assert!(sent(&w).is_empty());
        let (r, _) = build_router(router_world(0), &sponsored, TOKEN, "mtx_nope", &pay, "100000000000000", big).await;
        assert!(refused(&r, "mtx_nope"), "{r:?}");
        let (r, _) = build_router(router_world(0), &sponsored, TOKEN, "mtx_pay", &[1, 2, 3], "100000000000000", big).await;
        assert!(refused(&r, "args"), "{r:?}");
        let (r, _) = build_router(router_world(0), &sponsored, DEX, "settle", &[9; 40], "200000000000000", big).await;
        assert!(refused(&r, "args"), "{r:?}");
        let (r, _) = build_router(router_world(0), &sponsored, DEX, "nope", &settle_args(None, None), "200000000000000", big).await;
        assert!(refused(&r, "nope"), "{r:?}");
        // fix 3 g1: target_gas / target_deposit are relayer-chosen (not in ref): the node sets the floors itself — the
        // target's pinned gas, a token's exact storage_needed (fix 2 f4: no surplus at the executor), the DEX's floor
        let figures = |r: &std::result::Result<Built, SimError>| relay_figures(&r.as_ref().unwrap().body);
        for (tg, td) in [("0", "6"), ("100000000000000", "8"), ("1", big)] {
            let (r, _) = build_router(router_world(0), &sponsored, TOKEN, "mtx_pay", &pay, tg, td).await;
            assert_eq!(figures(&r), (GAS_JOB_BASE + GAS_KEY_SIG, 7), "{tg} {td}");
        }
        let (r, _) = build_router(router_world(0), &sponsored, DEX, "settle", &settle_args(None, None), "0", "0").await;
        assert_eq!(figures(&r).0, 27 * TGAS + 2 * (6 + 10 + 1) * TGAS, "settle_gas");
        assert!(figures(&r).1 > 10u128.pow(21), "the settle entry's deposit");
        let (r, _) = build_router(router_world(0), &sponsored, "app.near", "anything", &[1], "0", "0").await;
        assert_eq!(figures(&r), (GAS_TARGET_MIN, 0), "a third party's floor");
        let (r, _) = build_router(router_world(0), &sponsored, "app.near", "anything", &[1], "9000000000000", "3").await;
        assert_eq!(figures(&r), (9 * TGAS, 3), "above its floor: the job's own figures");
        // the target's own refusal; a leg bound to another relayer (the executor submits); a leg on an unconfigured token
        let mut w = router_world(0);
        w.views.insert((TOKEN.into(), "mtx_pay_check".into()), check_err("wrong lane nonce"));
        let (r, _) = build_router(w, &sponsored, TOKEN, "mtx_pay", &pay, "20000000000000", big).await;
        assert!(refused(&r, "wrong lane nonce"), "{r:?}");
        let mut w = router_world(0);
        w.views.insert((TOKENB.into(), "mtx_trade_check".into()), check_err("order expired"));
        let (r, _) = build_router(w, &sponsored, DEX, "settle", &settle_args(None, None), "200000000000000", big).await;
        assert!(refused(&r, "order expired"), "{r:?}");
        let (r, _) = build_router(router_world(0), &sponsored, DEX, "settle", &settle_args(Some("relayer.test.near"), None), "200000000000000", big).await;
        assert!(refused(&r, "relayer"), "{r:?}");
        // config: targets is a list of account ids, none the router or the executor
        let k = [lane0()];
        for (t, what) in [
            (format!(", relay_fee = {{ router = \"{ROUTER}\", executor = \"{EXECUTOR}\", targets = \"app.near\" }}"), "targets"),
            (format!(", relay_fee = {{ router = \"{ROUTER}\", executor = \"{EXECUTOR}\", targets = [\"app.near\"] }}"), "targets"),
            (format!(", relay_fee = {{ router = \"{ROUTER}\", executor = \"{EXECUTOR}\", targets = {{ \"Bad\" = [\"m\"] }} }}"), "targets"),
            (format!(", relay_fee = {{ router = \"{ROUTER}\", executor = \"{EXECUTOR}\", targets = {{ \"{EXECUTOR}\" = [\"m\"] }} }}"), "targets"),
            (format!(", relay_fee = {{ router = \"{ROUTER}\", executor = \"{EXECUTOR}\", targets = {{ \"{DEX}\" = [\"settle\"] }} }}"), "targets"),
            (format!(", relay_fee = {{ router = \"{ROUTER}\", executor = \"{EXECUTOR}\", targets = {{ \"app.near\" = \"m\" }} }}"), "targets"),
            (format!(", relay_fee = {{ router = \"{ROUTER}\", executor = \"{EXECUTOR}\", targets = {{ \"app.near\" = [] }} }}"), "targets"),
            (format!(", relay_fee = {{ router = \"{ROUTER}\", executor = \"{EXECUTOR}\", targets = {{ \"app.near\" = [\"add_key_native\"] }} }}"), "targets"),
        ] {
            let e = NearAdapter::new(&cfg("http://r", &t), &k).err().unwrap();
            assert!(format!("{e:#}").contains(what), "{t}: {e:#}");
        }
        let p = NearAdapter::new(&cfg("http://r", &sponsored), &k).unwrap();
        assert_eq!((p.relay_fee.targets.clone(), p.relay_fee.dex.as_deref()), (BTreeMap::from([("app.near".to_string(), vec!["anything".to_string()])]), Some(DEX)));
    }

    /// I3 (review RV3): a non-archival RPC answers UNKNOWN_BLOCK for garbage-collected heights too; a range starting
    /// below `earliest_block_height` is an error, never an empty answer that moves the cursor past real payments.
    #[tokio::test]
    async fn pruned_heights_error() {
        let mut w = world();
        w.earliest = 50;
        let (a, _) = adapter(w, "").await;
        let e = format!("{:#}", a.events(1, 99, &[TOKEN.into()]).await.unwrap_err());
        assert!(e.contains("earliest"), "{e}");
        assert!(a.events(50, 99, &[TOKEN.into()]).await.unwrap().is_empty(), "skipped heights above the horizon pass");
    }

    /// m1 (review RV2): our `relay` failed at its first receipt (e.g. "this ref is already in flight") ⇒ reverted at once;
    /// an entry under the ref staked by another relayer is never followed nor timed out as ours.
    #[tokio::test]
    async fn escrow_foreign_entry_not_followed() {
        let (rop, ro) = router_job("router_short", "30000000000000", "0");
        let relay = call_of(&pol(), &entry(&pol(), &rop, &ro).unwrap(), &rop, &hx(&ro["signature"])).unwrap();
        let key = bs58::encode([0x44u8; 32]).into_string();
        let id = format!("0x{}", "44".repeat(32));
        let now = crate::submit::now();
        let foreign = |deadline: u64| {
            let mut p = pending(deadline, 1);
            let at = p.len() - (16 + 16 + 8 + 2) - (4 + LANE0.len());
            p.splice(at..at + 4 + LANE0.len(), bstr("other.near"));
            p
        };
        let mut failed = outcome(ROUTER, fc("relay", &relay.args), json!({"Failure": {"ActionError": {}}}), vec![receipt(ROUTER, false, &[])]);
        failed["receipts_outcome"][0]["id"] = json!("r");
        let mut w = world();
        w.txs.insert(key.clone(), failed);
        w.views.insert((ROUTER.into(), "pending".into()), foreign(now - 10));
        let (a, w) = adapter(w, &fee_cfg("1")).await;
        assert!(matches!(a.tx_status(&id).await.unwrap(), TxStatus::Reverted { .. }));
        assert!(sent(&w).is_empty(), "no relay_timeout for an entry that is not ours");
        let mut held = outcome(ROUTER, fc("relay", &relay.args), json!({"SuccessValue": b64(&[0])}), vec![receipt(ROUTER, true, &[])]);
        held["receipts_outcome"][0]["id"] = json!("r");
        w.lock().unwrap().txs.insert(key.clone(), held);
        assert!(matches!(a.tx_status(&id).await.unwrap(), TxStatus::Reverted { reason } if reason.contains("another relayer")));
        assert!(sent(&w).is_empty());
    }

    /// m2: an entry stuck at stage Settle past deadline + 1 h: the token's `relay_held` tells what happened; a settled
    /// hold (release or refund) is never reported as "not charged".
    #[tokio::test]
    async fn stuck_settle_checks_relay_held() {
        let (rop, ro) = router_job("router_short", "30000000000000", "0");
        let relay = call_of(&pol(), &entry(&pol(), &rop, &ro).unwrap(), &rop, &hx(&ro["signature"])).unwrap();
        let key = bs58::encode([0x55u8; 32]).into_string();
        let id = format!("0x{}", "55".repeat(32));
        let mut w = world();
        w.txs.insert(key, outcome(ROUTER, fc("relay", &relay.args), json!({"SuccessValue": b64(&[0])}), vec![]));
        w.views.insert((ROUTER.into(), "pending".into()), pending(crate::submit::now() - 7_300, 2));
        let held = [vec![1], vec![0], bstr("alice.test.near"), vec![0], bstr(LANE0), 10u128.to_le_bytes().to_vec(), bstr(LANE0), 3u128.to_le_bytes().to_vec()].concat();
        w.views.insert((TOKEN.into(), "relay_held".into()), held);
        let (a, w) = adapter(w, &fee_cfg("1")).await;
        assert!(matches!(a.tx_status(&id).await.unwrap(), TxStatus::Reverted { reason } if reason.contains("still held")));
        assert_eq!(view_args(&w, "relay_held"), [bstr(ROUTER), rop.pay_ref.to_vec()].concat());
        w.lock().unwrap().views.insert((TOKEN.into(), "relay_held".into()), vec![0]);
        let st = a.tx_status(&id).await.unwrap();
        assert!(matches!(&st, TxStatus::Reverted { reason } if reason.contains("settled at the token") && !reason.contains("not charged")), "{st:?}");
    }

    /// m4: wrapper jobs whose check passes but whose run must fail are refused up front: the entry removes the payment's
    /// own key or its passkey's origin, or turns on passkey-for-value while the payment is not passkey-signed.
    #[tokio::test]
    async fn wrapper_conflicts_refused() {
        let alice = Holder::Near("alice.test.near".into());
        let pay = op_of("pay");
        let ed = Auth::decode(&auth_bytes(&row("pay")["auth"]), &pay.digest()).unwrap();
        let pk_auth = Auth::decode(&auth_bytes(&row("pay_ua_passkey")["auth"]), &op_of("pay_ua_passkey").digest()).unwrap();
        let eop = MetaOp { from: alice.clone(), ..op_of("remove_key") };
        let ea = auth_bytes(&row("remove_key")["auth"]);
        let w = |name: &str, params: Vec<u8>, from: &Holder| Entry::FeeWrapper {
            entry: name.into(), args: [MetaOp { from: from.clone(), ..eop.clone() }.borsh(), ea.clone(), params].concat() };
        let rec = |a: &Auth| { let (k, d) = a.record().unwrap(); [k.to_le_bytes().to_vec(), bvec(&d)].concat() };
        let bob = Holder::Near("bob.test.near".into());
        let err = |e: &Entry, a: &Auth| wrapper_conflicts(e, &pay, a).map_err(|e| format!("{e:#}"));
        assert!(err(&w("mtx_remove_key", rec(&ed), &alice), &ed).unwrap_err().contains("remove"));
        assert!(err(&w("mtx_remove_key", rec(&ed), &bob), &ed).is_ok(), "another subject's key");
        assert!(err(&w("mtx_remove_key", rec(&pk_auth), &alice), &ed).is_ok(), "another key");
        let origin = row("pay_ua_passkey")["auth"]["origin"].as_str().unwrap().to_string();
        assert!(err(&w("mtx_remove_origin", bstr(&origin), &alice), &pk_auth).unwrap_err().contains("origin"));
        assert!(err(&w("mtx_remove_origin", bstr("https://other.test"), &alice), &pk_auth).is_ok());
        assert!(err(&w("mtx_set_policy", vec![1], &alice), &ed).unwrap_err().contains("passkey"));
        assert!(err(&w("mtx_set_policy", vec![1], &alice), &pk_auth).is_ok(), "a passkey payment passes the policy");
        assert!(err(&w("mtx_set_policy", vec![0], &alice), &ed).is_ok());
        assert!(err(&Entry::Pay, &ed).is_ok());
        // and the job is refused before simulation
        let call = [&[14u8][..], b"mtx_remove_key", &[MetaOp { from: alice.clone(), ..eop.clone() }.borsh(), ea.clone(), rec(&ed)].concat()].concat();
        let mut op = MetaOp { relayer: Some(TOKEN.into()), to: Holder::Near(TOKEN.into()), extra: [0x51; 32], ..pay.clone() };
        op.pay_ref = relay_ref(&op.network, &[&[TOKEN.len() as u8][..], TOKEN.as_bytes()].concat(), &call, &op.extra);
        op.lane = pay_lane(&op.pay_ref);
        let o = o_op(&op, &auth_bytes(&row("pay")["auth"]), json!({"kind": "relay_fee", "extra": {"call": h(&call), "route": "wrapper"}}));
        let mut wd = world();
        wd.views.insert((TOKEN.into(), "relay_fee_remove_key_check".into()), check_ok(1));
        let (a, _) = adapter(wd, &fee_cfg("1000000000000000000000000")).await;
        assert!(matches!(a.build(&job(o), 0).await, Err(SimError::Revert(r)) if r.contains("remove")));
    }

    /// m6 (R9): a key-op wrapper job shows the subject's key set on every configured token (keys live per token and can
    /// drift); `describe_key_sets` flags a drift.
    #[tokio::test]
    async fn key_sets_shown_for_key_op_jobs() {
        let one = |k: u8| Some(vec![(258u16, vec![k; 32])]);
        let (s, drift) = describe_key_sets(&[(TOKEN.into(), one(7)), (TOKENB.into(), one(8))]);
        assert!(drift && s.contains(TOKEN) && s.contains(TOKENB), "{s}");
        assert!(!describe_key_sets(&[(TOKEN.into(), one(7)), (TOKENB.into(), one(7))]).1);
        assert!(describe_key_sets(&[(TOKEN.into(), one(7)), (TOKENB.into(), None)]).1, "an account on one token only");
        let mut w = world();
        w.views.insert((TOKEN.into(), "relay_fee_add_key_check".into()), check_ok(1));
        w.views.insert((TOKEN.into(), "subject".into()), vec![0]);
        let (a, w) = adapter(w, &fee_cfg("1000000000000000000000000")).await;
        let (_, wo) = wrapper_job("wrapper_add_key_real");
        a.build(&job(wo), 0).await.unwrap();
        assert!(w.lock().unwrap().calls.iter().any(|c| c.1["method_name"] == "subject"), "key sets read for a key op");
    }

    /// m7: a view stopped by the RPC's own `max_gas_burnt_view` is the RPC's limit, not the job's: retried (Transport);
    /// a contract panic still kills the job.
    #[tokio::test]
    async fn view_over_gas_cap_is_transport() {
        let mut w = world();
        w.view_errs.insert((TOKEN.into(), "mtx_pay_check".into()), "wasm execution failed with error: HostError(GasLimitExceeded)".into());
        let (a, w) = adapter(w, "").await;
        assert!(matches!(a.build(&job(o_of("pay", json!({}))), 0).await, Err(SimError::Transport(_))));
        w.lock().unwrap().view_errs.insert((TOKEN.into(), "mtx_pay_check".into()), "wasm execution failed with error: Smart contract panicked: x".into());
        assert!(matches!(a.build(&job(o_of("pay", json!({}))), 0).await, Err(SimError::Revert(_))));
    }

    // ------------------------------------------------------------------------------------------------ fix 2

    fn sponsored_cfg() -> String {
        format!(", relay_fee = {{ router = \"{ROUTER}\", executor = \"{EXECUTOR}\", relay_bound_payee = true, targets = {{ \"app.near\" = [\"anything\"] }} }}")
    }

    /// R3 (review RV4): `relay_hold` debits the fee before the executor calls the target, while the target's check read
    /// the balance before it. A value target on the payment's token by the same payer needs balance ≥ target amount +
    /// fee; the shape itself stays allowed, and another payer's target is not read against this balance.
    #[tokio::test]
    async fn same_token_value_target_needs_balance() {
        let pay = [op_of("pay").borsh(), auth_bytes(&row("pay")["auth"])].concat(); // alice pays bob 100 on TOKEN
        let fee = op_of("relay_fee_pay_router_short").amount; // alice's fee on TOKEN
        let bal = |n: u128| {
            let mut w = router_world(0);
            w.views.insert((TOKEN.into(), "ft_balance_of".into()), format!("\"{n}\"").into_bytes());
            w
        };
        let (r, w) = build_router(bal(100 + fee - 1), &sponsored_cfg(), TOKEN, "mtx_pay", &pay, "20000000000000", "7").await;
        assert!(matches!(&r, Err(SimError::Revert(e)) if e.contains("balance")), "{r:?}");
        assert_eq!(view_args(&w, "ft_balance_of"), br#"{"account_id":"alice.test.near"}"#.to_vec());
        let (r, _) = build_router(bal(100 + fee), &sponsored_cfg(), TOKEN, "mtx_pay", &pay, "20000000000000", "7").await;
        assert!(r.is_ok(), "{r:?}");
        // a UA payer is read through ua_balance_of; another payer's target is not this balance's business
        let from_bob = [MetaOp { from: Holder::Near("bob.test.near".into()), to: Holder::Near("carol.test.near".into()), ..op_of("pay") }.borsh(),
                        auth_bytes(&row("pay")["auth"])].concat();
        let (r, w) = build_router(bal(0), &sponsored_cfg(), TOKEN, "mtx_pay", &from_bob, "20000000000000", "7").await;
        assert!(r.is_ok(), "{r:?}");
        assert!(!w.lock().unwrap().calls.iter().any(|c| c.1["method_name"] == "ft_balance_of"));
        // a non-value target (a key op) on the same token by the same payer is not a value target
        let key_op = [MetaOp { from: Holder::Near("alice.test.near".into()), ..op_of("cancel_recovery") }.borsh(), auth_bytes(&row("cancel_recovery")["auth"])].concat();
        let mut w = bal(0);
        w.views.insert((TOKEN.into(), "mtx_cancel_recovery_check".into()), check_ok(0));
        let (r, _) = build_router(w, &sponsored_cfg(), TOKEN, "mtx_cancel_recovery", &key_op, "20000000000000", "0").await;
        assert!(r.is_ok(), "{r:?}");
    }

    /// R4 (review RV5) + f1: the DEX's `leg()` / `pair()` replicated off chain (each leg bound to its order and the DEX,
    /// the orders crossing, fill-or-kill, two distinct tokens, two distinct legs), and no settle reusing a pending pair
    /// (`pending(settle_id)`) or an indexed leg (`leg_settle`).
    #[tokio::test]
    async fn dex_pair_and_index_replicated() {
        let big = "100000000000000000000000";
        let go = |args: Vec<u8>, w: World| async move { build_router(w, &sponsored_cfg(), DEX, "settle", &args, "200000000000000", big).await.0 };
        let refused = |r: &std::result::Result<Built, SimError>, what: &str| matches!(r, Err(SimError::Revert(e)) if e.contains(what));
        assert!(go(settle_args(None, None), router_world(0)).await.is_ok());
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (settle_orders(&order(TOKEN, TOKENB, 100, 61, None), &order(TOKENB, TOKEN, 60, 100, None)), "fill-or-kill"),
            (settle_orders(&order(TOKEN, TOKENB, 100, 50, None), &order(TOKENB, TOKEN, 60, 101, None)), "fill-or-kill"),
            (settle_orders(&order(TOKEN, TOKENB, 100, 50, None), &order(TOKENB, TOKENB, 60, 100, None)), "pair"),
            (settle_orders(&order(TOKEN, TOKEN, 100, 50, None), &order(TOKENB, TOKEN, 60, 100, None)), "pair"),
        ];
        for (args, what) in cases {
            let r = go(args, router_world(0)).await;
            assert!(refused(&r, what), "{what}: {r:?}");
        }
        // a leg not bound to its order (extra), amount != sell_amount, the same leg twice
        let (oa, ob) = (order(TOKEN, TOKENB, 100, 50, None), order(TOKENB, TOKEN, 60, 100, None));
        let r = go(settle_with(&oa, &op_of("trade_a"), &ob, &leg_op("trade_b", &ob)), router_world(0)).await;
        assert!(refused(&r, "order"), "{r:?}");
        let r = go(settle_with(&oa, &MetaOp { amount: 99, ..leg_op("trade_a", &oa) }, &ob, &leg_op("trade_b", &ob)), router_world(0)).await;
        assert!(refused(&r, "sell_amount"), "{r:?}");
        let r = go(settle_with(&oa, &leg_op("trade_a", &oa), &oa, &leg_op("trade_a", &oa)), router_world(0)).await;
        assert!(r.is_err(), "the same leg twice: {r:?}");
        // a pair already pending, a leg already indexed in another settle (f1: an attacker's failed direct settle)
        let mut w = router_world(0);
        w.views.insert((DEX.into(), "pending".into()), vec![1, 0]);
        let (r, w) = build_router(w, &sponsored_cfg(), DEX, "settle", &settle_args(None, None), "200000000000000", big).await;
        assert!(refused(&r, "pending"), "{r:?}");
        let (a, b) = (leg_op("trade_a", &oa), leg_op("trade_b", &ob));
        assert_eq!(view_args(&w, "pending"), sha256(&[a.digest(), b.digest()].concat()).to_vec(), "settle_id(a, b)");
        let mut w = router_world(0);
        w.views.insert((DEX.into(), "leg_settle".into()), [vec![1], vec![7; 32]].concat());
        let r = go(settle_args(None, None), w).await;
        assert!(refused(&r, "already in a settle"), "{r:?}");
    }

    /// R1 / R2 (review RV6): a payment, a target op, a wrapped entry op or a DEX order that expires within
    /// RELAY_EXPIRY_MARGIN_S of now is refused (it would expire while the relay is in transit, unpaid).
    #[tokio::test]
    async fn expiry_margin_refused() {
        let now = crate::submit::now();
        let soon = now + RELAY_EXPIRY_MARGIN_S - 5;
        let later = now + RELAY_EXPIRY_MARGIN_S + 60;
        let refused = |r: &std::result::Result<Built, SimError>| matches!(r, Err(SimError::Revert(e)) if e.contains("expires"));
        let pay = |vu: u64| [MetaOp { valid_until: vu, ..op_of("pay") }.borsh(), auth_bytes(&row("pay")["auth"])].concat();
        // the payment
        for (vu, bad) in [(soon, true), (later, false)] {
            let (mut op, mut o) = router_op_g(TOKEN, "mtx_pay", &pay(FAR), Holder::Near("bob.test.near".into()), "20000000000000", "7");
            op.valid_until = vu;
            o["payload"] = json!(h(&op.encode()));
            let (r, _) = build_router_op(router_world(0), &sponsored_cfg(), op, o).await;
            assert_eq!(refused(&r), bad, "payment {vu}: {r:?}");
        }
        // the target op
        let (r, _) = build_router(router_world(0), &sponsored_cfg(), TOKEN, "mtx_pay", &pay(soon), "20000000000000", "7").await;
        assert!(refused(&r), "{r:?}");
        let (r, _) = build_router(router_world(0), &sponsored_cfg(), TOKEN, "mtx_pay", &pay(later), "20000000000000", "7").await;
        assert!(r.is_ok(), "{r:?}");
        // a DEX order, and a leg op
        let big = "100000000000000000000000";
        let (oa, ob) = (order_x(TOKEN, TOKENB, 100, 50, None, soon), order(TOKENB, TOKEN, 60, 100, None));
        let (r, _) = build_router(router_world(0), &sponsored_cfg(), DEX, "settle", &settle_orders(&oa, &ob), "200000000000000", big).await;
        assert!(refused(&r), "{r:?}");
        let oa = order(TOKEN, TOKENB, 100, 50, None);
        let a = MetaOp { valid_until: soon, ..leg_op("trade_a", &oa) };
        let (r, _) = build_router(router_world(0), &sponsored_cfg(), DEX, "settle", &settle_with(&oa, &a, &ob, &leg_op("trade_b", &ob)), "200000000000000", big).await;
        assert!(refused(&r), "{r:?}");
        // a wrapper job: its payment, and its entry op
        let (wop, wo) = wrapper_job("wrapper_add_key_real");
        let mut w = world();
        w.views.insert((TOKEN.into(), "relay_fee_add_key_check".into()), check_ok(1));
        let (a, _) = adapter(w, &fee_cfg("1000000000000000000000000")).await;
        a.build(&job(wo.clone()), 0).await.unwrap();
        let mut j = wo.clone();
        j["payload"] = json!(h(&MetaOp { valid_until: soon, ..wop.clone() }.encode()));
        assert!(refused(&a.build(&job(j), 0).await));
        let eop = MetaOp { valid_until: soon, ..op_of("cancel_recovery") };
        let call = [&[19u8][..], b"mtx_cancel_recovery", &eop.borsh(), &auth_bytes(&row("cancel_recovery")["auth"])].concat();
        let mut op = MetaOp { relayer: Some(TOKEN.into()), to: Holder::Near(TOKEN.into()), extra: [0x51; 32], ..op_of("pay") };
        op.pay_ref = relay_ref(&op.network, &[&[TOKEN.len() as u8][..], TOKEN.as_bytes()].concat(), &call, &op.extra);
        op.lane = pay_lane(&op.pay_ref);
        let o = o_op(&op, &auth_bytes(&row("pay")["auth"]), json!({"kind": "relay_fee", "extra": {"call": h(&call), "route": "wrapper"}}));
        let mut w = world();
        w.views.insert((TOKEN.into(), "relay_fee_cancel_recovery_check".into()), check_ok(1));
        let (a, _) = adapter(w, &fee_cfg("1000000000000000000000000")).await;
        assert!(refused(&a.build(&job(o), 0).await));
    }

    /// f2: a listed third-party target accepts only the methods listed for it.
    #[tokio::test]
    async fn third_party_methods_listed() {
        let (r, _) = build_router(router_world(0), &sponsored_cfg(), "app.near", "anything", &[1], "5000000000000", "0").await;
        assert!(r.is_ok(), "{r:?}");
        let (r, _) = build_router(router_world(0), &sponsored_cfg(), "app.near", "other_method", &[1], "5000000000000", "0").await;
        assert!(matches!(&r, Err(SimError::Revert(e)) if e.contains("other_method")), "{r:?}");
    }

    /// f3: `settle` splits the rest of its deposit evenly between the legs, so the floor is the entry + 2 yoctoNEAR +
    /// 2 × the larger leg's storage (a + b would leave the bigger leg short: settle's own receipt succeeds, the fee is
    /// released, the trade fails).
    #[tokio::test]
    async fn dex_deposit_floor_covers_the_larger_leg_twice() {
        let mut w = router_world(0);
        w.views.insert((TOKENB.into(), "mtx_trade_check".into()), check_ok(50));
        let (oa, ob) = (order(TOKEN, TOKENB, 100, 50, None), order(TOKENB, TOKEN, 60, 100, None));
        let (a, b) = (leg_op("trade_a", &oa), leg_op("trade_b", &ob));
        let settle = [(TOKEN, &a), (TOKENB, &b)].iter().map(|(t, l)| 4 + t.len() as u64 + holder_len(&l.from) + 88).sum::<u64>() + 4 + EXECUTOR.len() as u64 + 25;
        let entry = 10u128.pow(19) * u128::from(283 + settle) + 2;
        let floor = entry + 2 * 50;
        // fix 3 g1: the node attaches exactly this floor, whatever the job quoted
        for td in [floor, floor - 1, entry + 5 + 50, 0] {
            let mut w2 = router_world(0);
            w2.views.insert((TOKENB.into(), "mtx_trade_check".into()), check_ok(50));
            let (r, _) = build_router(w2, &sponsored_cfg(), DEX, "settle", &settle_args(None, None), "200000000000000", &td.to_string()).await;
            assert_eq!(relay_figures(&r.unwrap().body).1, floor, "{td}");
        }
        drop(w);
    }

    // ------------------------------------------------------------------------------------------------ fix 3

    /// A Chrome-shaped passkey auth (bytes) for challenge `ch` asserted from `origin` (signature and key not checked off
    /// chain).
    fn passkey_from(ch: &[u8; 32], origin: &str) -> Vec<u8> {
        passkey(&cdj(ch, origin, CHROME_TAIL))
    }

    /// A wrapper job for `entry` with `params` after (op, auth), its op signed `entry_auth`, its payment `pay_auth(digest
    /// of the payment op)`, open mode on TOKEN.
    fn wrapper_for(entry: &str, eop: MetaOp, entry_auth: &[u8], params: &[u8], pay_from: Holder, pay_auth: impl Fn(&[u8; 32]) -> Vec<u8>) -> Value {
        let call = [&[entry.len() as u8][..], entry.as_bytes(), &eop.borsh(), entry_auth, params].concat();
        let mut op = MetaOp { from: pay_from, relayer: Some(TOKEN.into()), to: Holder::Near(TOKEN.into()), extra: [0x51; 32], ..op_of("pay") };
        op.pay_ref = relay_ref(&op.network, &[&[TOKEN.len() as u8][..], TOKEN.as_bytes()].concat(), &call, &op.extra);
        op.lane = pay_lane(&op.pay_ref);
        o_op(&op, &pay_auth(&op.digest()), json!({"kind": "relay_fee", "extra": {"call": h(&call), "route": "wrapper"}}))
    }

    /// N1 (review RV7): an unopened UA pays for its own wrapped entry; the entry opens the subject with its assertion's
    /// origins (+ an origin it adds), so a payment passkey from another origin is refused on chain after the check view
    /// (pre-entry state) passed both. The node requires the payment's origins among the entry's; an opened subject or
    /// another payer needs no rule.
    #[tokio::test]
    async fn unopened_subject_origins() {
        let x = Holder::Ua([0xee; 32]);
        let eop = MetaOp { from: x.clone(), ..op_of("cancel_recovery") };
        let opened = [vec![1], 1u32.to_le_bytes().to_vec(), 256u16.to_le_bytes().to_vec(), bvec(&[7; 96]), 1u32.to_le_bytes().to_vec(),
                      bstr("https://a.test"), vec![0, 0], 0u64.to_le_bytes().to_vec(), vec![0]].concat();
        let run = |o: Value, subject: Vec<u8>| async move {
            let mut w = world();
            w.views.insert((TOKEN.into(), "relay_fee_cancel_recovery_check".into()), check_ok(1));
            w.views.insert((TOKEN.into(), "relay_fee_add_origin_check".into()), check_ok(1));
            w.views.insert((TOKEN.into(), "subject".into()), subject);
            let (a, _) = adapter(w, &fee_cfg("1000000000000000000000000")).await;
            a.build(&job(o), 0).await
        };
        let pa = passkey_from(&eop.digest(), "https://a.test");
        let (ra, rb) = (|d: &[u8; 32]| passkey_from(d, "https://a.test"), |d: &[u8; 32]| passkey_from(d, "https://b.test"));
        let r = run(wrapper_for("mtx_cancel_recovery", eop.clone(), &pa, &[], x.clone(), rb), vec![0]).await;
        assert!(matches!(&r, Err(SimError::Revert(e)) if e.contains("origin")), "{r:?}");
        assert!(run(wrapper_for("mtx_cancel_recovery", eop.clone(), &pa, &[], x.clone(), ra), vec![0]).await.is_ok(), "same origin");
        assert!(run(wrapper_for("mtx_cancel_recovery", eop.clone(), &pa, &[], x.clone(), rb), opened).await.is_ok(), "opened subject");
        assert!(run(wrapper_for("mtx_add_origin", eop.clone(), &pa, &bstr("https://b.test"), x.clone(), rb), vec![0]).await.is_ok(),
                "the entry adds the payment's origin");
        let other = Holder::Ua([0xdd; 32]);
        assert!(run(wrapper_for("mtx_cancel_recovery", eop.clone(), &pa, &[], other, rb), vec![0]).await.is_ok(), "another payer");
        let ed = auth_bytes(&row("pay")["auth"]);
        let r = run(wrapper_for("mtx_cancel_recovery", eop, &ed, &[], x, rb), vec![0]).await;
        assert!(matches!(&r, Err(SimError::Revert(e)) if e.contains("origin")), "a key-signed entry opens no origin: {r:?}");
    }

    fn terms(expiry: u64) -> Vec<u8> {
        let delegate = [vec![1], vec![0x10; 32]].concat();
        [delegate, [vec![0], bstr("bob.test.near")].concat(), 100u128.to_le_bytes().to_vec(), 250u128.to_le_bytes().to_vec(),
         86_400u64.to_le_bytes().to_vec(), expiry.to_le_bytes().to_vec(), 1_000u128.to_le_bytes().to_vec()].concat()
    }

    /// N2 (review RV8): `MandateTerms.expiry` gets the same margin (`mtx_mandate_open` refuses an expired mandate):
    /// the wrapped `relay_fee_mandate_open` and a router target `mtx_mandate_open`.
    #[tokio::test]
    async fn mandate_terms_expiry_margin() {
        let now = crate::submit::now();
        let (soon, later) = (now + RELAY_EXPIRY_MARGIN_S - 5, now + RELAY_EXPIRY_MARGIN_S + 60);
        let mop = op_of("mandate_open");
        let ma = auth_bytes(&row("mandate_open")["auth"]);
        let expires = |r: &std::result::Result<Built, SimError>| matches!(r, Err(SimError::Revert(e)) if e.contains("expires"));
        for (exp, bad) in [(soon, true), (later, false)] {
            let mut w = world();
            w.views.insert((TOKEN.into(), "relay_fee_mandate_open_check".into()), check_ok(1));
            let (a, _) = adapter(w, &fee_cfg("1000000000000000000000000")).await;
            let o = wrapper_for("mtx_mandate_open", mop.clone(), &ma, &terms(exp), Holder::Near("alice.test.near".into()), |_: &[u8; 32]| auth_bytes(&row("pay")["auth"]));
            let r = a.build(&job(o), 0).await;
            assert_eq!(expires(&r), bad, "wrapper {exp}: {r:?}");
            let mut w = router_world(0);
            w.views.insert((TOKEN.into(), "mtx_mandate_open_check".into()), check_ok(0));
            let args = [mop.borsh(), ma.clone(), terms(exp)].concat();
            let (r, _) = build_router(w, &sponsored_cfg(), TOKEN, "mtx_mandate_open", &args, "20000000000000", "0").await;
            assert_eq!(expires(&r), bad, "router {exp}: {r:?}");
        }
    }

    /// g1: the node's own target figures are what the fee must cover (a job quoted with a lower target_gas is priced at
    /// the floor the node attaches).
    #[tokio::test]
    async fn node_target_figures_are_priced() {
        let pay = [op_of("pay").borsh(), auth_bytes(&row("pay")["auth"])].concat();
        let (rop, ro) = router_op_g(TOKEN, "mtx_pay", &pay, Holder::Near(ROUTER.into()), "1", "0");
        let set = Entry::FeeRouter { target: TOKEN.into(), method: "mtx_pay".into(), args: pay.clone(), target_gas: GAS_JOB_BASE + GAS_KEY_SIG, target_deposit: 7 };
        let call = call_of(&pol(), &set, &rop, &hx(&ro["signature"])).unwrap();
        let quote = u128::from(call.gas + action_fees(&PINNED, &call) + timeout_gas(&PINNED)) * 100_000_000 + 1 + 1;
        for (price, ok) in [(quote.div_ceil(rop.amount), true), ((quote - 1) / rop.amount, false)] {
            let mut w = router_world(0);
            w.views.insert((TOKEN.into(), "relay_hold_check".into()), check_ok(1));
            let (r, _) = build_router_op(w, &fee_cfg(&price.to_string()), rop.clone(), ro.clone()).await;
            match (r, ok) {
                (Ok(b), true) => assert_eq!(relay_figures(&b.body), (GAS_JOB_BASE + GAS_KEY_SIG, 7)),
                (Err(SimError::Revert(e)), false) => assert!(e.contains("below"), "{e}"),
                (r, _) => panic!("{price}: {r:?}"),
            }
        }
    }

    /// g2: a plain pay / pay-meta job gets the same 120 s margin (no fee pays a lane for an op that expires in transit).
    #[tokio::test]
    async fn plain_pay_expiry_margin() {
        let soon = crate::submit::now() + RELAY_EXPIRY_MARGIN_S - 5;
        let mut w = world();
        w.views.insert((TOKEN.into(), "mtx_pay_check".into()), check_ok(1));
        let (a, _) = adapter(w, "").await;
        let op = MetaOp { valid_until: soon, ..op_of("pay") };
        let r = a.build(&job(o_op(&op, &auth_bytes(&row("pay")["auth"]), json!({}))), 0).await;
        assert!(matches!(&r, Err(SimError::Revert(e)) if e.contains("expires")), "{r:?}");
        a.build(&job(o_of("pay", json!({}))), 0).await.unwrap();
    }

    // ------------------------------------------------------------------------------------------------ fix 4

    const ORIGIN_VECTORS: &str = include_str!("../../../smartcontracts/near/vectors/webauthn-origin.json");

    /// N1 (fix 3 re-review): the node's `origin_of` is common/src/webauthn.rs's byte for byte. Every
    /// `webauthn-origin.json` row (also run by common/tests/vectors.rs `origin_of_parity_vectors`) gives its `origin`,
    /// and `Auth::decode` takes exactly that origin or refuses the passkey (directly or as an msig member).
    #[test]
    fn origin_of_parity_vectors() {
        let v: Value = serde_json::from_str(ORIGIN_VECTORS).unwrap();
        let rows = v["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 31);
        for r in rows {
            let (cd, ch, want) = (r["clientDataJSON"].as_str().unwrap(), b32(&r["challenge"]), r["origin"].as_str());
            assert_eq!(origin_of(cd.as_bytes(), &ch).map(|o| std::str::from_utf8(o).unwrap()), want, "{}", r["name"]);
            let msig = [vec![3], bvec(&[0; 4]), 1u32.to_le_bytes().to_vec(), vec![0], passkey(cd)].concat();
            match (Auth::decode(&passkey(cd), &ch), want) {
                (Ok(a), Some(o)) => {
                    assert_eq!(a.origins(), [o], "{}", r["name"]);
                    assert_eq!(Auth::decode(&msig, &ch).unwrap().origins(), [o], "{}", r["name"]);
                }
                (Err(e), None) => {
                    assert!(format!("{e:#}").contains("clientDataJSON"), "{}: {e:#}", r["name"]);
                    assert!(Auth::decode(&msig, &ch).is_err(), "{}", r["name"]);
                }
                (a, _) => panic!("{}: {a:?}", r["name"]),
            }
        }
    }

    /// N1 and the m4 `mtx_remove_origin` rule read the origin the token verifies. A payment whose clientDataJSON
    /// carries origin b behind a non-JSON tail or a later duplicate `"origin":"a"` is from b: refused against an entry
    /// that opens the subject with {a}, and against an entry that removes b; the duplicate on the entry's side opens
    /// {b}. A passkey the token cannot parse is refused. Honest Chrome (with or without its extra member) and Safari
    /// assertions stay accepted.
    #[tokio::test]
    async fn passkey_origin_shapes_as_on_chain() {
        let (a, b) = ("https://a.test", "https://b.test");
        let extra = r#","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}"#;
        let non_json = r#","crossOrigin":false,x}"#;
        let dup = |o: &str| format!(r#","crossOrigin":false,"origin":"{o}"}}"#);
        let honest = [CHROME_TAIL, extra, "}"];
        let x = Holder::Ua([0xee; 32]);
        let eop = MetaOp { from: x.clone(), ..op_of("cancel_recovery") };
        type PayCd = Box<dyn Fn(&[u8; 32]) -> String>;
        let run = |entry_cd: String, pay: PayCd| {
            let o = wrapper_for("mtx_cancel_recovery", eop.clone(), &passkey(&entry_cd), &[], x.clone(), |d| passkey(&pay(d)));
            async move {
                let mut w = world();
                w.views.insert((TOKEN.into(), "relay_fee_cancel_recovery_check".into()), check_ok(1));
                w.views.insert((TOKEN.into(), "subject".into()), vec![0]);
                let (ad, _) = adapter(w, &fee_cfg("1000000000000000000000000")).await;
                ad.build(&job(o), 0).await
            }
        };
        let ch = eop.digest();
        // honest shapes, same origin: passes
        for te in honest {
            for tp in honest {
                let r = run(cdj(&ch, a, te), Box::new(move |d: &[u8; 32]| cdj(d, a, tp))).await;
                assert!(r.is_ok(), "{te} / {tp}: {r:?}");
            }
        }
        let r = run(cdj(&ch, a, non_json), Box::new(move |d: &[u8; 32]| cdj(d, a, non_json))).await;
        assert!(r.is_ok(), "the token accepts a non-JSON tail: {r:?}");
        // the token reads b (fix 3 review N1 (a), (b)), and b on the entry's side
        let origin_refused = |r: &std::result::Result<Built, SimError>| matches!(r, Err(SimError::Revert(e)) if e.contains("origin https://"));
        let r = run(cdj(&ch, a, CHROME_TAIL), Box::new(move |d: &[u8; 32]| cdj(d, b, non_json))).await;
        assert!(origin_refused(&r), "non-JSON tail: {r:?}");
        let r = run(cdj(&ch, a, CHROME_TAIL), Box::new(move |d: &[u8; 32]| cdj(d, b, &dup(a)))).await;
        assert!(origin_refused(&r), "duplicate origin in the payment: {r:?}");
        let r = run(cdj(&ch, b, &dup(a)), Box::new(move |d: &[u8; 32]| cdj(d, a, CHROME_TAIL))).await;
        assert!(origin_refused(&r), "duplicate origin in the entry: {r:?}");
        // unparseable for the token: refused, on either side
        for i in 0..4 {
            let bad = move |d: &[u8; 32]| match i {
                0 => cdj(d, a, "}").replacen("\":\"", "\": \"", 1),
                1 => cdj(&[8; 32], a, "}"),
                2 => cdj(d, a, r#","crossOrigin":true}"#),
                _ => format!(r#"{{"type":"webauthn.get","challenge":"x","origin":"{a}"}}"#),
            };
            let r = run(cdj(&ch, a, CHROME_TAIL), Box::new(bad)).await;
            assert!(matches!(&r, Err(SimError::Revert(e)) if e.contains("clientDataJSON")), "payment {i}: {r:?}");
        }
        let r = run(cdj(&ch, a, r#","crossOrigin":true}"#), Box::new(move |d: &[u8; 32]| cdj(d, a, CHROME_TAIL))).await;
        assert!(matches!(&r, Err(SimError::Revert(e)) if e.contains("clientDataJSON")), "entry: {r:?}");
        // m4: an entry removing b fails a payment the token reads as from b, whatever its tail; a payment from a passes
        let pay = op_of("pay_ua_passkey");
        let pd = pay.digest();
        let eop = MetaOp { from: pay.from.clone(), ..op_of("remove_origin") };
        let remove = Entry::FeeWrapper { entry: "mtx_remove_origin".into(), args: [eop.borsh(), auth_bytes(&row("pay")["auth"]), bstr(b)].concat() };
        for tail in [CHROME_TAIL.to_string(), non_json.into(), dup(a)] {
            let auth = Auth::decode(&passkey(&cdj(&pd, b, &tail)), &pd).unwrap();
            assert!(format!("{:#}", wrapper_conflicts(&remove, &pay, &auth).unwrap_err()).contains(b), "{tail}");
        }
        for tail in honest {
            let auth = Auth::decode(&passkey(&cdj(&pd, a, tail)), &pd).unwrap();
            assert!(wrapper_conflicts(&remove, &pay, &auth).is_ok(), "{tail}");
        }
    }

    /// n1 (fix 3 re-review): a router job's relayer-chosen `target_gas` is not bounded before the node replaces it with
    /// its own figure (it was refused as a bad payload above 300 Tgas in all).
    #[tokio::test]
    async fn router_job_gas_on_node_figures() {
        let pay = [op_of("pay").borsh(), auth_bytes(&row("pay")["auth"])].concat();
        for tg in ["264000000000000", "18446744073709551615"] {
            let (r, _) = build_router(router_world(0), &sponsored_cfg(), TOKEN, "mtx_pay", &pay, tg, "0").await;
            let b = r.unwrap_or_else(|e| panic!("{tg}: {e:?}"));
            assert_eq!(relay_figures(&b.body), (GAS_JOB_BASE + GAS_KEY_SIG, 7), "{tg}");
        }
    }

    proptest! {
        /// Untrusted input never panics (§5): job bytes and JSON, RPC JSON, event logs.
        #[test]
        fn near_jobs_never_panic(b in proptest::collection::vec(any::<u8>(), 0..600), s in "\\PC{0,120}", k in 0usize..4,
                                 n in any::<u64>(), relayer in prop_oneof![Just(None), Just(Some(TOKEN.to_string())),
                                     Just(Some(ROUTER.to_string())), proptest::option::of("[a-z.]{0,12}")]) {
            let _ = MetaOp::decode(&b);
            let _ = MetaOp::decode(&[LABEL, &b[..]].concat());
            let _ = Auth::decode(&b, &[0; 32]);
            let pre = cdj(&[0; 32], "", "");
            let _ = (origin_of(&b, &[0; 32]), origin_of(&[&pre.as_bytes()[..pre.len() - 1], &b].concat(), &[0; 32]));
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
                let _ = job_gas(&e, &Auth::Ed25519([0; 32]));
                let _ = call_of(&pol(), &e, &op, &b);
            }
            let _ = job_gas(&Entry::FeeWrapper { entry: "mtx_cancel".into(), args: b.clone() }, &Auth::Passkey { key: [0; 64], rp: None, origin: String::new() });
            let _ = dec_u128(&json!(s), "x");
            // fix 1 m3: reach the relay-fee parsers past the binding (a payment consistent with random call bytes)
            for (route, call) in [("wrapper", [&[11u8][..], b"mtx_add_key", &b].concat()), ("wrapper", [&[9u8][..], b"mtx_cancel", &b].concat()),
                                  ("router", [&[13u8][..], DEX.as_bytes(), &[6], b"settle", &b].concat()),
                                  ("router", [&[15u8][..], TOKEN.as_bytes(), &[7], b"mtx_pay", &b].concat()), ("router", b.clone())] {
                let target = if route == "wrapper" { TOKEN } else { DEX };
                let mut op = MetaOp { relayer: Some(if route == "wrapper" { TOKEN } else { ROUTER }.into()), ..op_of("relay_fee_pay_router_short") };
                op.pay_ref = relay_ref(&op.network, &[&[target.len() as u8][..], target.as_bytes()].concat(), &call, &op.extra);
                op.lane = pay_lane(&op.pay_ref);
                let o = json!({"kind": "relay_fee", "extra": {"call": h(&call), "route": route, "target_gas": n.to_string(), "target_deposit": s}});
                let p = RelayFeePolicy { dex: Some(DEX.into()), targets: BTreeMap::from([("app.near".to_string(), vec!["anything".to_string()])]), ..pol() };
                if let Ok(e) = entry(&p, &op, &o) {
                    let _ = job_gas(&e, &Auth::Ed25519([0; 32]));
                    let _ = wrapper_conflicts(&e, &op, &Auth::Ed25519([0; 32]));
                    let _ = call_of(&p, &e, &op, &b);
                }
            }
            let _ = (decode_check(&b), decode_router_check(&b), decode_pending(&b), decode_held(&b), relay_args_ref(&b), settle_legs(&b));
            let _ = (parse_router_call(&b), parse_wrapper_call(&b));
            if let Ok(v) = serde_json::from_str::<Value>(&s) {
                let _ = (outcome_status(&v), header(&v), outcome_status(&json!({"SuccessValue": v})), header(&json!({"header": v})));
            }
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
