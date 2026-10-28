//! Aptos (S11; thiết kế `docs/history/specs/2026-10-04-net-aptos.md` §6). Job `signed_op` mang BCS của
//! `scaas::meta::MetaOp` (309 byte) + blob chữ ký `sig64 ‖ envelope` (phong bì signMessage của ví, hoặc assertion
//! WebAuthn) + khoá công khai. Lane = tài khoản ed25519 `m/44'/637'/{i}'/0'/0'` của relayer: gửi sequence-number tx,
//! một tx bay mỗi lane, tự trả phí (RS11-6). `RawTransaction` BCS dựng TẠI ĐÂY, không crate `aptos-sdk` (RS11-7);
//! hash tx tính trước khi gửi. Event đọc qua Aptos Indexer API (GraphQL) làm GỢI Ý tx của package, nội dung và tính
//! thành công đọc lại từ fullnode REST (owner OQ2; RS11-9).
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};

use crate::adapter::{Built, ChainAdapter, Family, Head, Lane, Rejected, Signed, TxStatus};
use crate::chain::SimError;
use crate::config::ChainCfg;
use crate::odoo::Job;
use crate::signer::{LocalSigner, Signer};

pub type Addr = [u8; 32];

const DOMAIN: &[u8] = b"scaas.metaop.v1";
const OP_PAY: u8 = 0;
const DEFAULT_TTL: u64 = 600;
const DEFAULT_MAX_GAS: u64 = 200_000;
const PROCESSOR: &str = "user_transaction_processor";
const BCS_SIGNED_TX: &str = "application/x.aptos.signed_transaction+bcs";
/// Lỗi validation (trước khi chạy): gửi lại cùng bytes không bao giờ qua ⇒ `Rejected` (RS11-8, spec §6.4).
const REJECTED_CODES: &[&str] = &[
    "SEQUENCE_NUMBER_TOO_OLD",
    "SEQUENCE_NUMBER_TOO_NEW",
    "INSUFFICIENT_BALANCE_FOR_TRANSACTION_FEE",
    "TRANSACTION_EXPIRED",
    "INVALID_SIGNATURE",
    "INVALID_AUTH_KEY",
    "SENDING_ACCOUNT_DOES_NOT_EXIST",
    "GAS_UNIT_PRICE_BELOW_MIN_BOUND",
    "GAS_UNIT_PRICE_ABOVE_MAX_BOUND",
    "MAX_GAS_UNITS_BELOW_MIN_TRANSACTION_GAS_UNITS",
    "MAX_GAS_UNITS_EXCEEDS_MAX_GAS_UNITS_BOUND",
    "EXCEEDED_MAX_TRANSACTION_SIZE",
    "BAD_CHAIN_ID",
];

pub fn sha3(b: &[u8]) -> [u8; 32] {
    Sha3_256::digest(b).into()
}

// ------------------------------------------------------------------ BCS

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.i.checked_add(n).filter(|e| *e <= self.b.len()).ok_or_else(|| anyhow!("truncated"))?;
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn vec(&mut self) -> Result<Vec<u8>> {
        let n = self.uleb()?;
        Ok(self.take(n)?.to_vec())
    }
    /// ULEB128 chuẩn (BCS): ≤ 4 byte cho độ dài, không byte thừa.
    fn uleb(&mut self) -> Result<usize> {
        let (mut n, mut shift) = (0usize, 0u32);
        loop {
            let b = self.u8()?;
            if shift > 21 {
                bail!("uleb128 too long");
            }
            n |= ((b & 0x7f) as usize) << shift;
            if b & 0x80 == 0 {
                if b == 0 && shift > 0 {
                    bail!("non-canonical uleb128");
                }
                break;
            }
            shift += 7;
        }
        Ok(n)
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
    }
    fn u128(&mut self) -> Result<u128> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into()?))
    }
    fn addr(&mut self) -> Result<Addr> {
        Ok(self.take(32)?.try_into()?)
    }
}

fn uleb(out: &mut Vec<u8>, mut n: usize) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn vec(out: &mut Vec<u8>, b: &[u8]) {
    uleb(out, b.len());
    out.extend_from_slice(b);
}

/// `0x…` ≤ 64 hex (AIP-40 dạng ngắn được đệm) ⇒ 32 byte.
pub fn parse_addr(s: &str) -> Result<Addr> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    if h.is_empty() || h.len() > 64 {
        bail!("bad Aptos address {s}");
    }
    let mut a = [0u8; 32];
    alloy::hex::decode_to_slice(format!("{h:0>64}"), &mut a).with_context(|| format!("bad Aptos address {s}"))?;
    Ok(a)
}

pub fn addr_hex(a: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(a))
}

// ------------------------------------------------------------------ payload (spec §4.1)

/// `scaas::meta::MetaOp` (BCS). `domain` cố định nên không lưu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaOp {
    pub chain_id: u8,
    pub contract: Addr,
    pub asset: Addr,
    pub op: u8,
    pub from: Addr,
    pub to: Addr,
    pub amount: u128,
    pub pay_ref: Vec<u8>,
    pub lane: Vec<u8>,
    pub nonce: u64,
    pub valid_until: u64,
    pub relayer: Addr,
    pub extra: Vec<u8>,
}

impl MetaOp {
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader { b, i: 0 };
        if r.vec()? != DOMAIN {
            bail!("not a scaas.metaop.v1 payload");
        }
        let op = Self {
            chain_id: r.u8()?,
            contract: r.addr()?,
            asset: r.addr()?,
            op: r.u8()?,
            from: r.addr()?,
            to: r.addr()?,
            amount: r.u128()?,
            pay_ref: r.vec()?,
            lane: r.vec()?,
            nonce: r.u64()?,
            valid_until: r.u64()?,
            relayer: r.addr()?,
            extra: r.vec()?,
        };
        if r.i != b.len() {
            bail!("trailing bytes");
        }
        if op.pay_ref.len() != 32 || op.lane.len() != 32 || op.extra.len() != 32 {
            bail!("pay_ref, lane and extra are 32 bytes");
        }
        Ok(op)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(309);
        vec(&mut o, DOMAIN);
        o.push(self.chain_id);
        o.extend_from_slice(&self.contract);
        o.extend_from_slice(&self.asset);
        o.push(self.op);
        o.extend_from_slice(&self.from);
        o.extend_from_slice(&self.to);
        o.extend_from_slice(&self.amount.to_le_bytes());
        vec(&mut o, &self.pay_ref);
        vec(&mut o, &self.lane);
        o.extend_from_slice(&self.nonce.to_le_bytes());
        o.extend_from_slice(&self.valid_until.to_le_bytes());
        o.extend_from_slice(&self.relayer);
        vec(&mut o, &self.extra);
        o
    }
}

/// `object::create_object_address(source, seed)` = sha3_256(source ‖ seed ‖ 0xFE).
pub fn object_address(source: &Addr, seed: &[u8]) -> Addr {
    let mut b = source.to_vec();
    b.extend_from_slice(seed);
    b.push(0xfe);
    sha3(&b)
}

/// Account của `owner` dưới package `package` (spec §3.1).
pub fn account_of(package: &Addr, owner: &Addr) -> Addr {
    let root = object_address(package, b"scaas.root");
    let mut seed = b"acct".to_vec();
    seed.extend_from_slice(owner);
    object_address(&root, &seed)
}

/// Địa chỉ ed25519 legacy (lane): auth key `sha3_256(pk ‖ 0x00)`.
pub fn lane_address(pk: &[u8]) -> Addr {
    let mut b = pk.to_vec();
    b.push(0);
    sha3(&b)
}

/// Blob chữ ký của job: `sig64 ‖ envelope` (hex) + khoá công khai (hex, 32 ed25519 / 65 WebAuthn P-256).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    pub public_key: Vec<u8>,
    pub sig: Vec<u8>,
    pub envelope: Vec<u8>,
}

pub fn parse_auth(signature: &str, public_key: &str) -> Result<Auth> {
    let blob = alloy::hex::decode(signature.trim().trim_start_matches("0x"))?;
    let public_key = alloy::hex::decode(public_key.trim().trim_start_matches("0x"))?;
    if !(public_key.len() == 32 || (public_key.len() == 65 && public_key[0] == 4)) {
        bail!("an Aptos key is ed25519 (32 bytes) or WebAuthn P-256 (65 bytes uncompressed)");
    }
    if blob.len() <= 64 || blob.len() > 8192 {
        bail!("bad signature blob length");
    }
    Ok(Auth { public_key, sig: blob[..64].to_vec(), envelope: blob[64..].to_vec() })
}

// ------------------------------------------------------------------ transaction (spec §6.2)

/// `TransactionPayload::EntryFunction` (biến thể 2) của `<package>::<module>::<function>`, không type arg; mỗi đối số
/// là BCS của giá trị, đúng thứ tự Move (sau `&signer` của lane).
fn entry_payload(package: &Addr, module: &str, function: &str, args: &[Vec<u8>]) -> Vec<u8> {
    let mut o = vec![2u8];
    o.extend_from_slice(package);
    vec(&mut o, module.as_bytes());
    vec(&mut o, function.as_bytes());
    uleb(&mut o, 0); // type args
    uleb(&mut o, args.len());
    args.iter().for_each(|a| vec(&mut o, a));
    o
}

/// BCS của `vector<u8>`.
fn bytes(b: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    vec(&mut v, b);
    v
}

/// The pay entries' last three arguments: `public_key, sig, envelope`.
fn auth_args(auth: &Auth) -> [Vec<u8>; 3] {
    [bytes(&auth.public_key), bytes(&auth.sig), bytes(&auth.envelope)]
}

/// `<package>::meta::relay_pay` — đối số đúng thứ tự Move.
pub fn relay_pay_payload(package: &Addr, op: &MetaOp, auth: &Auth) -> Vec<u8> {
    let args: Vec<Vec<u8>> = vec![
        op.from.to_vec(),
        op.asset.to_vec(),
        op.to.to_vec(),
        op.amount.to_le_bytes().to_vec(),
        bytes(&op.pay_ref),
        bytes(&op.lane),
        op.nonce.to_le_bytes().to_vec(),
        op.valid_until.to_le_bytes().to_vec(),
        op.relayer.to_vec(),
        bytes(&op.extra),
        bytes(&auth.public_key),
        bytes(&auth.sig),
        bytes(&auth.envelope),
    ];
    entry_payload(package, "meta", "relay_pay", &args)
}

/// CTR-MTX-26: `meta::relay_pay_meta(lane, owner, asset, to, amount, salt, meta, valid_until, relayer, extra,
/// public_key, sig, envelope)`; `pay_ref`, `lane`, `nonce` are derived on chain.
pub fn relay_pay_meta_payload(package: &Addr, op: &MetaOp, auth: &Auth, salt: &[u8], meta: &[u8]) -> Vec<u8> {
    let mut args = vec![
        op.from.to_vec(),
        op.asset.to_vec(),
        op.to.to_vec(),
        op.amount.to_le_bytes().to_vec(),
        bytes(salt),
        bytes(meta),
        op.valid_until.to_le_bytes().to_vec(),
        op.relayer.to_vec(),
        bytes(&op.extra),
    ];
    args.extend(auth_args(auth));
    entry_payload(package, "meta", "relay_pay_meta", &args)
}

/// CTR-MTX-27: `relayfee::relay_<entry>(lane, <the call's arguments>, payer, asset, to, amount, valid_until, extra,
/// public_key, sig, envelope)`; `pay_ref`, `lane`, `nonce`, `relayer` are derived on chain from the call.
pub fn relay_fee_payload(package: &Addr, op: &MetaOp, auth: &Auth, call: &RelayCall) -> Vec<u8> {
    let mut args = call.args.clone();
    args.extend([
        op.from.to_vec(),
        op.asset.to_vec(),
        op.to.to_vec(),
        op.amount.to_le_bytes().to_vec(),
        op.valid_until.to_le_bytes().to_vec(),
        bytes(&op.extra),
    ]);
    args.extend(auth_args(auth));
    entry_payload(package, "relayfee", call.wrapper, &args)
}

// ------------------------------------------------------------------ CTR-MTX-26 / -27 (spec §6.2, §7.2)


fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    alloy::primitives::keccak256(parts.concat()).0
}

/// CTR-MTX-26: `keccak256("scaas.pay.meta" ‖ salt ‖ keccak256(meta))` (`meta::meta_pay_id`).
pub fn meta_pay_id(salt: &[u8], meta: &[u8]) -> [u8; 32] {
    keccak(&[b"scaas.pay.meta", salt, &keccak(&[meta])])
}

/// `keccak256("scaas.pay.lane" ‖ p)` (`meta::pay_lane`).
pub fn pay_lane(p: &[u8]) -> [u8; 32] {
    keccak(&[b"scaas.pay.lane", p])
}

/// `relayfee::marker()` = `object::create_object_address(&package, b"scaas.relayfee")`: no transaction can sign for it.
pub fn relay_marker(package: &Addr) -> Addr {
    object_address(package, b"scaas.relayfee")
}

/// `relayfee::relay_ref`: `keccak256("scaas.relayfee" ‖ chain_id (1) ‖ package (32) ‖ keccak256(call) ‖ salt)`, `salt`
/// the payment's `extra`.
pub fn relay_ref(chain_id: u8, package: &Addr, call: &[u8], salt: &[u8]) -> [u8; 32] {
    keccak(&[b"scaas.relayfee", &[chain_id], package, &keccak(&[call]), salt])
}

/// BCS kinds of a wrapped entry's arguments.
#[derive(Debug, Clone, Copy)]
enum Arg {
    Addr,
    U8,
    U64,
    U128,
    Bytes,
    Addrs,
}

/// The fee-less signed entries `scaas::relayfee` wraps: (entry, wrapper, arguments after the lane signer).
const WRAPPED: &[(&str, &str, &[Arg])] = {
    use Arg::*;
    &[
        ("meta::manage_signed", "relay_manage_signed", &[Addr, U8, U8, Bytes, Bytes, Bytes, Addr, U64, Bytes, Bytes, Bytes]),
        ("mandate::open", "relay_mandate_open", &[Addr, Bytes, Bytes, U64, U64, U64, U64, Addrs, U64, Bytes, Bytes, Bytes]),
        ("mandate::revoke_signed", "relay_revoke_signed", &[Addr, U64, Bytes, Bytes, Bytes]),
        ("dex::cancel_signed", "relay_cancel_signed", &[Addr, Bytes, Bytes, Bytes, Bytes]),
        ("dex::invalidate_nonces_signed", "relay_invalidate_nonces_signed", &[Addr, Addr, U128, Bytes, Bytes, Bytes]),
    ]
};

/// The wrapped call (`op.extra.call`): `bcs(entry name) ‖ bcs(each argument)`, the entry's signature included, the
/// lane signer excluded — the bytes `relayfee` hashes into `ref`. Each argument's BCS is also its argument in the
/// entry-function payload, so the node forwards exactly the bytes the payer's `ref` commits to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCall {
    pub wrapper: &'static str,
    pub args: Vec<Vec<u8>>,
}

impl RelayCall {
    /// Exactly one wrapped entry's call (canonical BCS: ULEB128 lengths are canonical), nothing after it.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader { b, i: 0 };
        let name = r.vec()?;
        let (_, wrapper, kinds) = WRAPPED.iter().find(|w| w.0.as_bytes() == name.as_slice()).ok_or_else(|| {
            anyhow!("not a call of a wrapped entry (meta::manage_signed, mandate::open, mandate::revoke_signed, \
                     dex::cancel_signed, dex::invalidate_nonces_signed)")
        })?;
        let mut args = Vec::with_capacity(kinds.len());
        for k in kinds.iter() {
            let start = r.i;
            match k {
                Arg::Addr => {
                    r.addr()?;
                }
                Arg::U8 => {
                    r.u8()?;
                }
                Arg::U64 => {
                    r.u64()?;
                }
                Arg::U128 => {
                    r.u128()?;
                }
                Arg::Bytes => {
                    r.vec()?;
                }
                Arg::Addrs => {
                    let n = r.uleb()?;
                    r.take(n.checked_mul(32).ok_or_else(|| anyhow!("too many addresses"))?)?;
                }
            }
            args.push(b[start..r.i].to_vec());
        }
        if r.i != b.len() {
            bail!("trailing bytes after the call");
        }
        Ok(Self { wrapper, args })
    }
}

/// What the node accepts as a relay-fee job (controller call 2026-10-27, owner may override): the router marker of
/// this package as the payment's relayer, a registered token, and a fee of at least `min_amount`.
#[derive(Debug, Clone, Default)]
pub struct RelayFeePolicy {
    pub router: Option<Addr>,
    pub tokens: Vec<Addr>,
    pub params: crate::config::RelayParams,
}

impl RelayFeePolicy {
    /// `params.relay_fee = { router = "<relayfee::marker()>", min_amount = N }` (default 1) and the chain's `tokens`
    /// (FA metadata addresses). A `router` that is set but is not an Aptos address or not `relayfee::marker()` of
    /// `package`, a `min_amount` that is not a non-negative integer, or a malformed token is a startup error, never a
    /// silently disabled router.
    pub fn from_cfg(cfg: &ChainCfg, package: &Addr) -> Result<Self> {
        let t = cfg.params.get("relay_fee");
        let router = match t.and_then(|t| t.get("router")) {
            None => None,
            Some(v) => {
                let r = parse_addr(v.as_str().ok_or_else(|| anyhow!("params.relay_fee.router must be a 0x… string"))?)
                    .context("params.relay_fee.router")?;
                if r != relay_marker(package) {
                    bail!("params.relay_fee.router {} is not relayfee::marker() {} of this package", addr_hex(&r),
                          addr_hex(&relay_marker(package)));
                }
                Some(r)
            }
        };
        let tokens = cfg
            .tokens
            .iter()
            .map(|t| parse_addr(&t.address).with_context(|| format!("tokens: {} is not an Aptos address", t.address)))
            .collect::<Result<_>>()?;
        Ok(Self { router, tokens, params: cfg.relay_params()? })
    }
}

/// The entry a job runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Pay,
    PayMeta { salt: Vec<u8>, meta: Vec<u8> },
    Fee { call: RelayCall },
}

fn hex_field(v: &Value, what: &str) -> Result<Vec<u8>> {
    let s = v.as_str().ok_or_else(|| anyhow!("op.{what} missing"))?;
    Ok(alloy::hex::decode(s.trim().trim_start_matches("0x"))?)
}

/// The entry of a job, checked before simulation (fail closed). `op.kind`: `"pay_meta"` (`op.salt`, `op.meta` hex:
/// `pay_ref == metaPayId(salt, meta)`, `lane == payLane(pay_ref)`, `nonce == 0`, `meta` within the cap) or
/// `"relay_fee"` (`op.extra.call` hex = the wrapped call's bytes, optional `op.ref`): the policy (router marker as
/// relayer, registered token, minimum fee) and the payment commits to exactly this call: `pay_ref == ref`,
/// `lane == payLane(ref)`, `nonce == 0`. No `op.kind` is `relay_pay`; any other kind is refused (a typo must not burn
/// the `(payer, payId)` lane as a plain pay). A plain pay or pay-meta to the router marker is refused whether or not a
/// router is configured (the marker is derived from the package): nobody can spend from it, so the funds would be
/// stranded (CTR-MTX-27: never pay the marker; the router's open mode pays the submitting lane instead).
pub fn entry(package: &Addr, policy: &RelayFeePolicy, op: &MetaOp, o: &Value) -> Result<Entry> {
    let kind = crate::adapter::op_kind(o, &crate::adapter::PAY_KINDS)?;
    if kind != Some("relay_fee") && op.to == relay_marker(package) {
        bail!("a plain pay to the relay-fee router marker {} would strand the funds", addr_hex(&op.to));
    }
    match kind {
        Some("pay_meta") => {
            let (salt, meta) = (hex_field(&o["salt"], "salt")?, hex_field(&o["meta"], "meta")?);
            if salt.len() != 32 {
                bail!("op.salt is 32 bytes");
            }
            if meta.len() > policy.params.max_pay_meta_bytes {
                bail!("meta is {} B, above max_pay_meta_bytes {}", meta.len(), policy.params.max_pay_meta_bytes);
            }
            let id = meta_pay_id(&salt, &meta);
            if op.pay_ref != id || op.lane != pay_lane(&id) || op.nonce != 0 {
                bail!("pay-meta: pay_ref / lane / nonce are not metaPayId(salt, meta) / payLane / 0");
            }
            Ok(Entry::PayMeta { salt, meta })
        }
        Some("relay_fee") => {
            let Some(router) = policy.router else { bail!("relay-fee jobs need params.relay_fee.router") };
            if op.relayer != router {
                bail!("the payment's relayer {} is not the configured params.relay_fee.router", addr_hex(&op.relayer));
            }
            if !policy.tokens.contains(&op.asset) {
                bail!("token {} is not registered on this chain", addr_hex(&op.asset));
            }
            let bytes = hex_field(&o["extra"]["call"], "extra.call")?;
            let call = RelayCall::decode(&bytes)?;
            let r = relay_ref(op.chain_id, package, &bytes, &op.extra);
            if op.pay_ref != r || op.lane != pay_lane(&r) || op.nonce != 0 {
                bail!("the payment is not bound to this call (ref, payLane(ref), nonce 0)");
            }
            if !o["ref"].is_null() && hex_field(&o["ref"], "ref")? != r {
                bail!("op.ref != relay_ref(call, salt)");
            }
            Ok(Entry::Fee { call })
        }
        _ => Ok(Entry::Pay),
    }
}

/// T17 (one payee rule, `adapter::relay_fee_ours`): a relay fee reaches this lane in open mode (`to` = the router
/// marker, which pays the submitting lane) or bound to the lane, and then must be at least `min_amount`; a fee bound
/// to anyone else only with `relay_bound_payee` (sponsored). Checked per lane in `build`.
pub fn relay_payee(policy: &RelayFeePolicy, op: &MetaOp, lane: &Addr) -> Result<()> {
    crate::adapter::relay_fee_ours(policy.router == Some(op.to), op.to == *lane, op.amount, &policy.params)
}

/// `RawTransaction` BCS.
pub fn raw_tx(sender: &Addr, sequence: u64, payload: &[u8], max_gas: u64, gas_price: u64, expiration: u64, chain_id: u8) -> Vec<u8> {
    let mut o = sender.to_vec();
    o.extend_from_slice(&sequence.to_le_bytes());
    o.extend_from_slice(payload);
    o.extend_from_slice(&max_gas.to_le_bytes());
    o.extend_from_slice(&gas_price.to_le_bytes());
    o.extend_from_slice(&expiration.to_le_bytes());
    o.push(chain_id);
    o
}

/// Thông điệp lane ký: `sha3_256("APTOS::RawTransaction") ‖ bcs(raw)`.
pub fn signing_message(raw: &[u8]) -> Vec<u8> {
    let mut m = sha3(b"APTOS::RawTransaction").to_vec();
    m.extend_from_slice(raw);
    m
}

/// `SignedTransaction` = raw ‖ `TransactionAuthenticator::Ed25519 { pk, sig }` (biến thể 0).
pub fn signed_tx(raw: &[u8], pk: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut o = raw.to_vec();
    o.push(0);
    vec(&mut o, pk);
    vec(&mut o, sig);
    o
}

/// Hash Aptos của tx người dùng: `sha3_256(sha3_256("APTOS::Transaction") ‖ 0x00 ‖ bcs(SignedTransaction))`.
pub fn tx_hash(signed: &[u8]) -> [u8; 32] {
    let mut m = sha3(b"APTOS::Transaction").to_vec();
    m.push(0);
    m.extend_from_slice(signed);
    sha3(&m)
}

// ------------------------------------------------------------------ phân loại (spec §6.4)

/// Body lỗi 400 của `POST /v1/transactions` ⇒ `Rejected` nếu là lỗi validation vĩnh viễn với cùng bytes.
pub fn classify_submit(status: u16, body: &str) -> Result<()> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let msg = v["message"].as_str().unwrap_or(body);
    if status == 400 && REJECTED_CODES.iter().any(|c| msg.contains(c)) {
        return Err(Rejected(msg.to_string()).into());
    }
    bail!("submit HTTP {status}: {msg}")
}

/// Một tx đã vào sổ: `success=false` vì abort/lỗi chạy op ⇒ `Reverted`; hết gas (gas do relayer chọn, thay đổi đã
/// rollback, nonce người trả còn nguyên) ⇒ `Rejected` để job về hàng đợi và dựng lại (L3/L4).
pub fn classify_committed(tx: &Value, height: u64) -> Result<TxStatus> {
    if tx["success"].as_bool() == Some(true) {
        return Ok(TxStatus::Mined { height, tx_hash: None });
    }
    let vm = tx["vm_status"].as_str().unwrap_or("failure").to_string();
    // Mô tả abort lấy từ doc comment của module (hook FA dispatchable viết gì cũng được) ⇒ không bao giờ là OOG (I3).
    if !vm.starts_with("Move abort") && (vm.contains("OUT_OF_GAS") || vm.eq_ignore_ascii_case("out of gas")) {
        return Err(Rejected(vm).into());
    }
    Ok(TxStatus::Reverted { reason: vm })
}

fn num(v: &Value) -> Option<u64> {
    v.as_str().and_then(|s| s.parse().ok()).or_else(|| v.as_u64())
}

fn bytes_of(v: &Value) -> Option<Vec<u8>> {
    v.as_str().and_then(|s| s.strip_prefix("0x")).and_then(|h| alloy::hex::decode(h).ok())
}

fn canon(v: &Value) -> Option<String> {
    v.as_str().and_then(|s| parse_addr(s).ok()).map(|a| addr_hex(&a))
}

/// Event REST của một tx ⇒ event chuẩn hoá cho Odoo; `None` nếu không phải của package này / token lạ / hỏng.
// TODO(T17): `meta::PaymentMeta` (`pay_id`, `meta`, joined by `pay_ref`) and `relayfee::RelayFeePaid` (module
// `relayfee`; `token` filtered against the registered assets).
pub fn normalize(package: &Addr, tokens: &[String], ev: &Value, block: u64, block_hash: &str, tx_hash: &str, log_index: usize) -> Option<Value> {
    let ty = ev.get("type")?.as_str()?;
    let mut it = ty.splitn(3, "::");
    let (pkg, module, name) = (it.next()?, it.next()?, it.next()?);
    if parse_addr(pkg).ok()? != *package || !matches!(module, "meta" | "relayfee") {
        return None;
    }
    let d = ev.get("data")?;
    // `RelayFeePaid` (the `relayfee` module) names its token; the `meta` events are the token's own
    let contract = canon(d.get(if module == "relayfee" { "token" } else { "contract" })?)?;
    if !tokens.contains(&contract) {
        return None;
    }
    let log_index = log_index as u64;
    let mut out = json!({
        "contract": contract, "block_number": block, "block_hash": block_hash, "tx_hash": tx_hash, "log_index": log_index,
    });
    let b32 = |k: &str| bytes_of(d.get(k)?).filter(|b| b.len() == 32).map(|b| addr_hex(&b));
    match (module, name) {
        ("meta", "PaymentSettled") => {
            out["event"] = json!("PaymentSettled");
            out["from"] = json!(canon(d.get("from")?)?);
            out["to"] = json!(canon(d.get("to")?)?);
            out["amount"] = json!(num(d.get("amount")?)?.to_string());
            out["entry_ref"] = json!(b32("pay_ref")?);
        }
        ("meta", "MetaTransactionExecuted") => {
            out["event"] = json!("MetaTransactionExecuted");
            out["from"] = json!(canon(d.get("from")?)?);
            out["digest"] = json!(b32("digest")?);
        }
        // CTR-MTX-26 / -27: joined to their `PaymentSettled` (`indexer::join_pay_events`), never sent alone
        ("meta", "PaymentMeta") => {
            out["event"] = json!("PaymentMeta");
            out["entry_ref"] = json!(b32("pay_id")?);
            out["meta"] = json!(format!("0x{}", alloy::hex::encode(bytes_of(d.get("meta")?)?)));
        }
        ("relayfee", "RelayFeePaid") => {
            out["event"] = json!("RelayFeePaid");
            out["contract"] = json!(addr_hex(package));
            out["token"] = json!(contract);
            out["entry_ref"] = json!(b32("ref")?);
            out["target"] = json!(canon(d.get("target")?)?);
            out["from"] = json!(canon(d.get("payer")?)?);
            out["to"] = json!(canon(d.get("payee")?)?);
            out["amount"] = json!(num(d.get("amount")?)?.to_string());
        }
        _ => return None,
    }
    Some(out)
}

// ------------------------------------------------------------------ adapter

pub struct AptosAdapter {
    key: String,
    chain_id: u8,
    rest: Vec<String>,
    indexer: String,
    indexer_key: Option<String>,
    http: reqwest::Client,
    package: Addr,
    ttl: u64,
    max_gas: u64,
    quorum: usize,
    lanes: Vec<Lane>,
    signers: Vec<LocalSigner>,
    relay_fee: RelayFeePolicy,
}

struct Work {
    op: MetaOp,
    auth: Auth,
    entry: Entry,
}

fn transport(e: anyhow::Error) -> SimError {
    SimError::Transport(format!("{e:#}"))
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl AptosAdapter {
    pub fn new(cfg: &ChainCfg, signers: &[LocalSigner]) -> Result<Self> {
        if cfg.rpc_urls.is_empty() || signers.is_empty() {
            bail!("chain {}: needs rpc_urls and at least one lane", cfg.chain_key());
        }
        let p = |k: &str| cfg.params.get(k).and_then(|v| v.as_str());
        let n = |k: &str, d: u64| cfg.params.get(k).and_then(|v| v.as_integer()).map_or(d, |v| v.max(0) as u64);
        let chain_id: u8 = cfg.network.as_deref().unwrap_or_default().parse()
            .map_err(|_| anyhow!("aptos: network must be the chain id (1 mainnet, 2 testnet, 4 localnet)"))?;
        let package = parse_addr(p("package").ok_or_else(|| anyhow!("aptos: params.package is required"))?)?;
        let indexer = p("indexer_url").ok_or_else(|| anyhow!("aptos: params.indexer_url (Indexer API GraphQL) is required"))?;
        let indexer_key = match p("indexer_api_key_env") {
            Some(var) => Some(std::env::var(var).with_context(|| format!("environment variable {var} is not set"))?),
            None => None,
        };
        let mut lanes = Vec::new();
        let mut own = Vec::new();
        for (s, &i) in signers.iter().zip(&cfg.lanes) {
            let LocalSigner::Ed(k) = s else { bail!("aptos lanes are ed25519") };
            lanes.push(Lane { index: i, address: addr_hex(&lane_address(&k.verifying_key().to_bytes())) });
            own.push(LocalSigner::Ed(k.clone()));
        }
        Ok(Self {
            key: cfg.chain_key(),
            chain_id,
            rest: cfg.rpc_urls.iter().map(|u| u.trim_end_matches('/').to_string()).collect(),
            indexer: indexer.to_string(),
            indexer_key,
            http: reqwest::Client::builder().timeout(Duration::from_secs(20)).build()?,
            package,
            ttl: n("tx_ttl_s", DEFAULT_TTL).max(30),
            max_gas: n("max_gas_amount", DEFAULT_MAX_GAS),
            quorum: cfg.finality.quorum.max(1),
            lanes,
            signers: own,
            relay_fee: RelayFeePolicy::from_cfg(cfg, &package)?,
        })
    }

    async fn get_at(&self, base: &str, path: &str) -> Result<Option<Value>> {
        let r = self.http.get(format!("{base}{path}")).send().await?;
        if r.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let status = r.status();
        let body = r.text().await?;
        if !status.is_success() {
            bail!("GET {path}: HTTP {status}: {body}");
        }
        Ok(Some(serde_json::from_str(&body)?))
    }

    async fn get(&self, path: &str) -> Result<Value> {
        self.get_at(&self.rest[0], path).await?.ok_or_else(|| anyhow!("GET {path}: not found"))
    }

    async fn view(&self, function: &str, type_args: &[&str], args: &[impl serde::Serialize]) -> Result<Value> {
        let body = json!({"function": function, "type_arguments": type_args, "arguments": args});
        let r = self.http.post(format!("{}/view", self.rest[0])).json(&body).send().await?;
        let status = r.status();
        let v: Value = r.json().await?;
        if !status.is_success() {
            bail!("view {function}: HTTP {status}: {v}");
        }
        Ok(v[0].clone())
    }

    async fn graphql(&self, query: &str, variables: Value) -> Result<Value> {
        let mut req = self.http.post(&self.indexer).json(&json!({"query": query, "variables": variables}));
        if let Some(k) = &self.indexer_key {
            req = req.bearer_auth(k);
        }
        let v: Value = req.send().await?.error_for_status()?.json().await?;
        if let Some(e) = v.get("errors") {
            bail!("indexer: {e}");
        }
        Ok(v["data"].clone())
    }

    /// Phiên bản ledger cuối mà processor `user_transactions` đã xử lý (cursor không vượt nó — owner OQ2).
    async fn indexed_version(&self) -> Result<u64> {
        let d = self.graphql(
            "query($p: String!) { processor_status(where: {processor: {_eq: $p}}) { last_success_version } }",
            json!({"p": PROCESSOR}),
        ).await?;
        d["processor_status"][0]["last_success_version"].as_u64().ok_or_else(|| anyhow!("indexer: no status for {PROCESSOR}"))
    }

    fn work(&self, job: &Job) -> Result<Work> {
        let o = job.op.as_ref().ok_or_else(|| anyhow!("not a signed_op job"))?;
        let payload = alloy::hex::decode(o["payload"].as_str().unwrap_or_default().trim_start_matches("0x"))?;
        let op = MetaOp::decode(&payload)?;
        if op.op != OP_PAY {
            bail!("only pay ops are relayed on Aptos");
        }
        if op.chain_id != self.chain_id {
            bail!("payload is for chain {}, this chain is {}", op.chain_id, self.chain_id);
        }
        let contract = parse_addr(o["contract"].as_str().unwrap_or_default())?;
        if contract != op.contract || account_of(&self.package, &op.from) != op.contract {
            bail!("payload contract is not the payer's Account under this package");
        }
        let auth = parse_auth(o["signature"].as_str().unwrap_or_default(), o["public_key"].as_str().unwrap_or_default())?;
        let entry = entry(&self.package, &self.relay_fee, &op, o)?;
        Ok(Work { op, auth, entry })
    }

    async fn account_exists(&self, owner: &Addr) -> Result<bool> {
        let v = self.view(&format!("{}::meta::exists_at", addr_hex(&self.package)), &[], &[addr_hex(owner)]).await?;
        v.as_bool().ok_or_else(|| anyhow!("bad exists_at {v}"))
    }

    /// `meta::pay_check` / `pay_meta_check` (view): abort ⇒ `Revert` (job chết), lỗi khác ⇒ `Transport`.
    async fn pay_check(&self, lane: &Addr, w: &Work) -> std::result::Result<(), SimError> {
        let (op, a) = (&w.op, &w.auth);
        let hx = |b: &[u8]| format!("0x{}", alloy::hex::encode(b));
        let (function, mid) = match &w.entry {
            Entry::PayMeta { salt, meta } => ("pay_meta_check", vec![hx(salt), hx(meta)]),
            Entry::Pay => ("pay_check", vec![hx(&op.pay_ref), hx(&op.lane), op.nonce.to_string()]),
            Entry::Fee { .. } => return Err(SimError::Revert("relay-fee jobs are simulated, never pay_check'ed".into())),
        };
        let mut args = vec![addr_hex(lane), addr_hex(&op.from), addr_hex(&op.asset), addr_hex(&op.to), op.amount.to_string()];
        args.extend(mid);
        args.extend([op.valid_until.to_string(), addr_hex(&op.relayer), hx(&op.extra), hx(&a.public_key), hx(&a.sig), hx(&a.envelope)]);
        match self.view(&format!("{}::meta::{function}", addr_hex(&self.package)), &[], &args).await {
            Ok(_) => Ok(()),
            Err(e) if format!("{e:#}").contains("Move abort") => Err(SimError::Revert(format!("{e:#}"))),
            Err(e) => Err(transport(e)),
        }
    }

    fn lane_addr(&self, lane: usize) -> Result<Addr> {
        parse_addr(&self.lanes.get(lane).ok_or_else(|| anyhow!("no lane {lane}"))?.address)
    }

    async fn gas_price(&self) -> Result<u64> {
        num(&self.get("/estimate_gas_price").await?["gas_estimate"]).ok_or_else(|| anyhow!("bad gas estimate"))
    }

    async fn block(&self, base: &str, height: u64) -> Result<Value> {
        self.get_at(base, &format!("/blocks/by_height/{height}")).await?.ok_or_else(|| anyhow!("block {height} not served"))
    }

    /// `path` từ `rest[0]`; `quorum > 1` ⇒ thêm endpoint phải trả cùng `pick` cho tới đủ quorum. Nội dung tx (event,
    /// thành công, hash) và block chịu cùng quy tắc với hash block ở `final_head` (review L3).
    async fn agreed(&self, path: &str, pick: fn(&Value) -> Value) -> Result<Value> {
        let v = self.get(path).await?;
        if self.quorum > 1 {
            let want = pick(&v);
            let mut agree = 1;
            for url in &self.rest[1..] {
                if matches!(self.get_at(url, path).await, Ok(Some(o)) if pick(&o) == want) {
                    agree += 1;
                }
            }
            if agree < self.quorum {
                bail!("GET {path}: {agree} endpoint(s) agree, quorum is {}", self.quorum);
            }
        }
        Ok(v)
    }

    fn block_hash_of(b: &Value) -> Result<String> {
        bytes_of(&b["block_hash"]).filter(|h| h.len() == 32).map(|h| addr_hex(&h)).ok_or_else(|| anyhow!("bad block hash"))
    }
}

#[async_trait]
impl ChainAdapter for AptosAdapter {
    fn family(&self) -> Family {
        Family::Aptos
    }

    fn chain_key(&self) -> &str {
        &self.key
    }

    fn lanes(&self) -> &[Lane] {
        &self.lanes
    }

    /// R80: `pay` ⇒ view `meta::lane_nonce(from, lane)` (Account chưa mở ⇒ chưa gì bị tiêu thụ).
    async fn op_consumed(&self, job: &Job) -> Result<Option<bool>> {
        let Ok(w) = self.work(job) else { return Ok(None) };
        if !self.account_exists(&w.op.from).await? {
            return Ok(Some(false));
        }
        let lane = format!("0x{}", alloy::hex::encode(&w.op.lane));
        let v = self.view(&format!("{}::meta::lane_nonce", addr_hex(&self.package)), &[], &[addr_hex(&w.op.from), lane]).await?;
        let next = num(&v).ok_or_else(|| anyhow!("bad lane_nonce {v}"))?;
        Ok(Some(next > w.op.nonce))
    }

    /// Mô phỏng với chữ ký toàn số 0 (API từ chối mô phỏng tx có chữ ký hợp lệ). Abort ⇒ `Revert` (job chết).
    async fn build(&self, job: &Job, lane: usize) -> std::result::Result<Built, SimError> {
        let w = self.work(job).map_err(|e| SimError::Revert(format!("bad payload: {e:#}")))?;
        if w.op.valid_until <= now() {
            return Err(SimError::Revert("payload expired".into()));
        }
        let sender = self.lane_addr(lane).map_err(transport)?;
        if matches!(w.entry, Entry::Fee { .. }) {
            relay_payee(&self.relay_fee, &w.op, &sender).map_err(|e| SimError::Revert(format!("{e:#}")))?;
        }
        let seq = self.sequence(lane).await.map_err(transport)?;
        let price = self.gas_price().await.map_err(transport)?;
        let payload = match &w.entry {
            Entry::Pay => relay_pay_payload(&self.package, &w.op, &w.auth),
            Entry::PayMeta { salt, meta } => relay_pay_meta_payload(&self.package, &w.op, &w.auth, salt, meta),
            Entry::Fee { call } => relay_fee_payload(&self.package, &w.op, &w.auth, call),
        };
        let exp = w.op.valid_until.min(now() + self.ttl);
        if !self.account_exists(&w.op.from).await.map_err(transport)? {
            if matches!(w.entry, Entry::Fee { .. }) {
                // No view runs the wrapped call, and `simulate` hangs on a payment that opens the Account (below):
                // fail closed. The payer opens its Account first (`meta::open` or any plain pay).
                return Err(SimError::Revert("relay-fee: the payer's Account is not open yet".into()));
            }
            // Account chưa mở: `simulate` của aptos-node 9.6.0 treo với tx vừa tạo object vừa chi từ store có sẵn của nó
            // (tx thật chạy bình thường — spec §16). View `pay_check` chạy đúng mọi kiểm tra của `relay_pay` thay mô
            // phỏng; gas = trần cấu hình (lần chi đầu gồm phí lưu trữ Account).
            self.pay_check(&sender, &w).await?;
            let meta = json!({"max_gas": self.max_gas, "gas_price": price, "expiration": exp});
            return Ok(Built { job_id: job.id, body: payload, valid_until: w.op.valid_until, meta });
        }
        let raw = raw_tx(&sender, seq, &payload, self.max_gas, price, exp, self.chain_id);
        let pk = &self.signers[lane].public_key();
        let body = signed_tx(&raw, pk, &[0u8; 64]);
        let url = format!("{}/transactions/simulate?estimate_max_gas_amount=true&estimate_gas_unit_price=true", self.rest[0]);
        let r = self.http.post(url).header("content-type", BCS_SIGNED_TX).body(body).send().await.map_err(|e| transport(e.into()))?;
        let status = r.status();
        let v: Value = r.json().await.map_err(|e| transport(e.into()))?;
        if !status.is_success() {
            return Err(SimError::Transport(format!("simulate HTTP {status}: {v}")));
        }
        let sim = &v[0];
        if sim["success"].as_bool() != Some(true) {
            return Err(SimError::Revert(sim["vm_status"].as_str().unwrap_or("simulation failed").to_string()));
        }
        let used = num(&sim["gas_used"]).unwrap_or(0);
        let max_gas = (used + used.div_ceil(10) * 3).max(used + 10).min(self.max_gas);
        let price = num(&sim["gas_unit_price"]).unwrap_or(price).max(price);
        let meta = json!({"max_gas": max_gas, "gas_price": price, "expiration": exp});
        Ok(Built { job_id: job.id, body: payload, valid_until: w.op.valid_until, meta })
    }

    async fn sign(&self, built: Built, lane: usize, sequence: u64) -> Result<Signed> {
        let s = self.signers.get(lane).ok_or_else(|| anyhow!("no lane {lane}"))?;
        let m = |k: &str| built.meta[k].as_u64().ok_or_else(|| anyhow!("built without {k}"));
        let raw = raw_tx(&self.lane_addr(lane)?, sequence, &built.body, m("max_gas")?, m("gas_price")?, m("expiration")?, self.chain_id);
        let sig = s.sign(&signing_message(&raw))?;
        let signed = signed_tx(&raw, &s.public_key(), &sig);
        Ok(Signed { job_id: built.job_id, tx_id: addr_hex(&tx_hash(&signed)), raw: signed, valid_until: built.valid_until, sequence })
    }

    async fn submit(&self, signed: &Signed) -> Result<()> {
        let r = self.http.post(format!("{}/transactions", self.rest[0]))
            .header("content-type", BCS_SIGNED_TX).body(signed.raw.clone()).send().await?;
        let status = r.status().as_u16();
        let body = r.text().await?;
        classify_submit(status, &body)
    }

    async fn tx_status(&self, tx_id: &str) -> Result<TxStatus> {
        let Some(tx) = self.get_at(&self.rest[0], &format!("/transactions/by_hash/{tx_id}")).await? else {
            return Ok(TxStatus::Unknown);
        };
        if tx["type"].as_str() == Some("pending_transaction") {
            return Ok(TxStatus::Pending);
        }
        let version = num(&tx["version"]).ok_or_else(|| anyhow!("committed tx without version"))?;
        let b = self.get(&format!("/blocks/by_version/{version}")).await?;
        classify_committed(&tx, num(&b["block_height"]).ok_or_else(|| anyhow!("bad block height"))?)
    }

    /// Sequence ĐÃ COMMIT (0 cho tài khoản stateless — AIP-115).
    async fn sequence(&self, lane: usize) -> Result<u64> {
        let v = self.view("0x1::account::get_sequence_number", &[], &[addr_hex(&self.lane_addr(lane)?)]).await?;
        num(&v).ok_or_else(|| anyhow!("bad sequence number {v}"))
    }

    async fn lane_balance(&self, lane: usize) -> Result<Option<u128>> {
        let v = self.view("0x1::coin::balance", &["0x1::aptos_coin::AptosCoin"], &[addr_hex(&self.lane_addr(lane)?)]).await?;
        Ok(v.as_str().and_then(|s| s.parse().ok()))
    }

    async fn tx_fee(&self, tx_id: &str) -> Result<Option<u128>> {
        let Some(tx) = self.get_at(&self.rest[0], &format!("/transactions/by_hash/{tx_id}")).await? else { return Ok(None) };
        Ok(num(&tx["gas_used"]).zip(num(&tx["gas_unit_price"])).map(|(g, p)| g as u128 * p as u128))
    }

    /// AptosBFT: block đã commit là final. Đỉnh báo Odoo = min(đỉnh REST, block mà indexer đã xử lý TRỌN) — con trỏ
    /// không bao giờ vượt indexer (owner OQ2); nhiều `rpc_urls` ⇒ cùng hash ở đỉnh đó (quorum).
    async fn final_head(&self) -> Result<Option<Head>> {
        let head = num(&self.get("").await?["block_height"]).ok_or_else(|| anyhow!("bad ledger info"))?;
        let done = self.indexed_version().await?;
        let b = self.get(&format!("/blocks/by_version/{done}")).await?;
        let (h, last) = (num(&b["block_height"]), num(&b["last_version"]));
        let (Some(h), Some(last)) = (h, last) else { bail!("bad block for version {done}") };
        let indexed = if last == done { Some(h) } else { h.checked_sub(1) };
        let Some(height) = indexed.map(|i| i.min(head)) else { return Ok(None) };
        let hash = Self::block_hash_of(&self.block(&self.rest[0], height).await?)?;
        let mut agree = 1;
        for url in &self.rest[1..] {
            if self.block(url, height).await.ok().and_then(|b| Self::block_hash_of(&b).ok()).as_deref() == Some(hash.as_str()) {
                agree += 1;
            }
        }
        Ok((agree >= self.quorum).then_some(Head { height, hash }))
    }

    async fn block_hash(&self, height: u64) -> Result<String> {
        Self::block_hash_of(&self.block(&self.rest[0], height).await?)
    }

    /// GỢI Ý từ Indexer API: tx người dùng gọi một entry function của package trong vùng block; nội dung (thành công,
    /// hash, event, block) đọc lại từ fullnode. Indexer chưa xử lý hết vùng ⇒ `Err` (vùng không được chốt).
    /// Entry được relay là `package entry` (review M3): script/module khác không gói được, nên tx của ta luôn có entry
    /// function của package. Indexer API không có bảng `events` để gợi ý theo type. `ponytail:` multisig thực thi
    /// chỉ-hash vẫn gọi được entry mà không lộ payload (spec §6.6) — cần thì thêm gợi ý `fungible_asset_activities`
    /// theo `asset_type` (đắt với tài sản đông giao dịch).
    async fn events(&self, from: u64, to: u64, contracts: &[String]) -> Result<Vec<Value>> {
        let tokens: Vec<String> = contracts.iter().filter_map(|c| parse_addr(c).ok()).map(|a| addr_hex(&a)).collect();
        if tokens.is_empty() || from > to {
            return Ok(vec![]);
        }
        let last = num(&self.block(&self.rest[0], to).await?["last_version"]).ok_or_else(|| anyhow!("bad block {to}"))?;
        let done = self.indexed_version().await?;
        if done < last {
            bail!("indexer has processed version {done}, block {to} ends at {last}");
        }
        let q = "query($p: String!, $from: bigint!, $to: bigint!, $after: bigint!) { user_transactions(where: { \
                 entry_function_contract_address: {_eq: $p}, block_height: {_gte: $from, _lte: $to}, version: {_gt: $after}}, \
                 order_by: {version: asc}, limit: 100) { version block_height } }";
        let mut hints: Vec<(u64, u64)> = Vec::new();
        let mut after: i64 = -1;
        loop {
            let d = self.graphql(q, json!({"p": addr_hex(&self.package), "from": from, "to": to, "after": after})).await?;
            let rows = d["user_transactions"].as_array().cloned().unwrap_or_default();
            for r in &rows {
                let (v, h) = (r["version"].as_u64(), r["block_height"].as_u64());
                let (Some(v), Some(h)) = (v, h) else { bail!("indexer: bad row {r}") };
                hints.push((v, h));
                after = v as i64;
            }
            if rows.len() < 100 {
                break;
            }
        }
        let mut out = Vec::new();
        let mut blocks: std::collections::HashMap<u64, (u64, u64, String)> = Default::default();
        for (version, height) in hints {
            let (fv, lv, bh) = match blocks.entry(height) {
                std::collections::hash_map::Entry::Occupied(e) => e.get().clone(),
                std::collections::hash_map::Entry::Vacant(e) => {
                    let b = self.agreed(&format!("/blocks/by_height/{height}"), |b| {
                        json!([b["first_version"], b["last_version"], b["block_hash"]])
                    }).await?;
                    let (Some(fv), Some(lv)) = (num(&b["first_version"]), num(&b["last_version"])) else {
                        bail!("bad block {height}")
                    };
                    e.insert((fv, lv, Self::block_hash_of(&b)?)).clone()
                }
            };
            if version < fv || version > lv {
                bail!("indexer placed version {version} in block {height} ({fv}..={lv})");
            }
            let tx = self.agreed(&format!("/transactions/by_version/{version}"), |t| {
                json!([t["type"], t["hash"], t["success"], t["events"]])
            }).await?;
            if tx["type"].as_str() != Some("user_transaction") {
                bail!("version {version} is not a user transaction");
            }
            if tx["success"].as_bool() != Some(true) {
                continue;
            }
            let hash = bytes_of(&tx["hash"]).filter(|h| h.len() == 32).map(|h| addr_hex(&h)).ok_or_else(|| anyhow!("bad tx hash"))?;
            let evs = tx["events"].as_array().cloned().unwrap_or_default();
            out.extend(crate::indexer::join_pay_events(
                evs.iter().enumerate().filter_map(|(i, ev)| normalize(&self.package, &tokens, ev, height, &bh, &hash, i)).collect()));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Vector chéo — cùng bytes ở smartcontracts/move/aptos/tests/vectors.move và dms_blockchain/tests/test_fam_aptos.py.
    const PAYLOAD: &str = "0f73636161732e6d6574616f702e7631041ca0afea08a65090449eac9c077fca180ea47d12664cc7adb773c23ba5e982020f52836b9e4baedcc626ae27b9dbad9b9e1ed624576d899f41168bb985c3a39200376a224a674671b33d8dfb3ba382aca22eeffb39bbcb285ec45e8407cad34faa000000000000000000000000000000000000000000000000000000000000beef6400000000000000000000000000000020010101010101010101010101010101010101010101010101010101010101010120a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10000000000000000e8030000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000";
    const DIGEST: &str = "5b83ca76bf1595dc0edc9aa61d4f0ebf1dd8d606ac19e59d1e02b30945e51353";
    const BLOB: &str = "910771997fd6987009daa1361b2546cdfc549cb663142b01e71466129e20a238f37032a98dd451c321ee48b118e22a96e9bdc7e86cc25023d8eef4af0627110b4150544f530a6d6573736167653a2073636161732e6d6574616f702e76313a3078356238336361373662663135393564633065646339616136316434663065626631646438643630366163313965353964316530326233303934356535313335330a6e6f6e63653a2061316131613161316131613161316131613161316131613161316131613161316131613161316131613161316131613161316131613161316131613161316131";
    const ALICE_PK: &str = "d5bf4a3fcce717b0388bcc2749ebc148ad9969b23f45ee1b605fd58778576ac4";
    const ALICE_ACCOUNT: &str = "0x1ca0afea08a65090449eac9c077fca180ea47d12664cc7adb773c23ba5e98202";
    // @aptos-labs/ts-sdk 7.3.0 (`smartcontracts/move/aptos/scripts/tx_vector.mjs`): lane 0 of ART24, sequence 7, max gas 200000,
    // price 100, expiry 1700000000, chain 4, package 0xb0b.
    const TX_SIGNED: &str = "226b5b5c15d19946b1fd26c3e4ad36833fd8c9c11c612b1327e608f824a5f2d40700000000000000020000000000000000000000000000000000000000000000000000000000000b0b046d6574610972656c61795f706179000d20376a224a674671b33d8dfb3ba382aca22eeffb39bbcb285ec45e8407cad34faa200f52836b9e4baedcc626ae27b9dbad9b9e1ed624576d899f41168bb985c3a39220000000000000000000000000000000000000000000000000000000000000beef1064000000000000000000000000000000212001010101010101010101010101010101010101010101010101010101010101012120a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a108000000000000000008e803000000000000200000000000000000000000000000000000000000000000000000000000000000212000000000000000000000000000000000000000000000000000000000000000002120d5bf4a3fcce717b0388bcc2749ebc148ad9969b23f45ee1b605fd58778576ac44140910771997fd6987009daa1361b2546cdfc549cb663142b01e71466129e20a238f37032a98dd451c321ee48b118e22a96e9bdc7e86cc25023d8eef4af0627110bab01a9014150544f530a6d6573736167653a2073636161732e6d6574616f702e76313a3078356238336361373662663135393564633065646339616136316434663065626631646438643630366163313965353964316530326233303934356535313335330a6e6f6e63653a2061316131613161316131613161316131613161316131613161316131613161316131613161316131613161316131613161316131613161316131613161316131400d030000000000640000000000000000f1536500000000040020ba489e5562452afe9b4d4b4fdb0a1abcd4ddce7401276675a71715de5d6d16c240d50a04877df6362de4eb49178e68579213607709992b5231885e007c5ff2dfca389bd919f2661e0f2b562dae9f8770aa65ffde420af027571dd68a0141a62000";
    const TX_HASH: &str = "0x804567dba010d7ae0374636c383407e4e4a0d6490987181eabc3a70d7e1babd7";

    fn vector_op() -> MetaOp {
        MetaOp::decode(&alloy::hex::decode(PAYLOAD).unwrap()).unwrap()
    }

    #[test]
    fn payload_and_digest_match_move_and_python() {
        let b = alloy::hex::decode(PAYLOAD).unwrap();
        let op = vector_op();
        assert_eq!(op.encode(), b);
        assert_eq!(b.len(), 309);
        assert_eq!(alloy::hex::encode(sha3(&b)), DIGEST);
        assert_eq!((op.chain_id, op.amount, op.nonce, op.valid_until), (4, 100, 0, 1000));
        assert_eq!(addr_hex(&op.contract), ALICE_ACCOUNT);
        assert_eq!(account_of(&parse_addr("0xb0b").unwrap(), &op.from), op.contract);
    }

    #[test]
    fn tx_matches_the_ts_sdk() {
        let words = format!("{}art", "abandon ".repeat(23));
        let seed = crate::keys::Seed::from_words(&words, None).unwrap();
        let (curve, k) = crate::keys::lane_secret(&seed, "aptos", 0).unwrap();
        let s = LocalSigner::new(curve, &k).unwrap();
        assert_eq!(addr_hex(&lane_address(&s.public_key())), "0x226b5b5c15d19946b1fd26c3e4ad36833fd8c9c11c612b1327e608f824a5f2d4");
        let auth = parse_auth(BLOB, ALICE_PK).unwrap();
        let payload = relay_pay_payload(&parse_addr("0xb0b").unwrap(), &vector_op(), &auth);
        let raw = raw_tx(&lane_address(&s.public_key()), 7, &payload, 200_000, 100, 1_700_000_000, 4);
        let signed = signed_tx(&raw, &s.public_key(), &s.sign(&signing_message(&raw)).unwrap());
        assert_eq!(alloy::hex::encode(&signed), TX_SIGNED.trim());
        assert_eq!(addr_hex(&tx_hash(&signed)), TX_HASH);
    }

    #[test]
    fn submit_errors_are_classified() {
        let old = r#"{"message":"Invalid transaction: Type: Validation Code: SEQUENCE_NUMBER_TOO_OLD","error_code":"vm_error","vm_error_code":3}"#;
        assert!(classify_submit(400, old).unwrap_err().downcast_ref::<Rejected>().is_some());
        let fee = r#"{"message":"Invalid transaction: Type: Validation Code: INSUFFICIENT_BALANCE_FOR_TRANSACTION_FEE","error_code":"vm_error","vm_error_code":5}"#;
        assert!(classify_submit(400, fee).unwrap_err().downcast_ref::<Rejected>().is_some());
        let full = r#"{"message":"Mempool is full","error_code":"mempool_is_full"}"#;
        assert!(classify_submit(507, full).unwrap_err().downcast_ref::<Rejected>().is_none(), "retry same bytes");
        assert!(classify_submit(500, "oops").unwrap_err().downcast_ref::<Rejected>().is_none());
        assert!(classify_submit(202, "{}").is_ok());
    }

    #[test]
    fn committed_failures_are_classified() {
        let ok = json!({"type": "user_transaction", "success": true, "vm_status": "Executed successfully"});
        assert_eq!(classify_committed(&ok, 9).unwrap(), TxStatus::Mined { height: 9, tx_hash: None });
        let abort = json!({"success": false, "vm_status": "Move abort in 0xd752::meta: 0x4"});
        assert!(matches!(classify_committed(&abort, 9).unwrap(), TxStatus::Reverted { .. }));
        let oog = json!({"success": false, "vm_status": "Out of gas"});
        assert!(classify_committed(&oog, 9).unwrap_err().downcast_ref::<Rejected>().is_some());
        // I3: abort descriptions come from module doc comments (a dispatchable-FA hook can write anything)
        let spoof = json!({"success": false, "vm_status": "Move abort in 0xbad::hook: EOOG(0x1): Out of gas, OUT_OF_GAS"});
        assert!(matches!(classify_committed(&spoof, 9).unwrap(), TxStatus::Reverted { .. }));
    }

    /// REST + Indexer API giả cho `events`: tx version 101 ở block 5 phát một `PaymentSettled` với `amount` cho trước
    /// (một endpoint nói dối thì đổi số tiền).
    async fn fake_aptos(amount: &'static str) -> String {
        use axum::extract::State;
        use axum::http::Uri;
        async fn h(State(amount): State<&'static str>, uri: Uri, body: String) -> axum::Json<Value> {
            let p = uri.path();
            axum::Json(if p == "/graphql" && body.contains("processor_status") {
                json!({"data": {"processor_status": [{"last_success_version": 1000}]}})
            } else if p == "/graphql" {
                json!({"data": {"user_transactions": [{"version": 101, "block_height": 5}]}})
            } else if p.starts_with("/blocks/by_height/") {
                json!({"block_height": "5", "block_hash": format!("0x{}", "bb".repeat(32)), "first_version": "100",
                       "last_version": "102"})
            } else if p == "/transactions/by_version/101" {
                json!({"type": "user_transaction", "success": true, "hash": format!("0x{}", "cc".repeat(32)), "events": [{
                    "type": format!("{}::meta::PaymentSettled", addr_hex(&parse_addr("0xb0b").unwrap())),
                    "data": {"contract": "0xa", "from": "0x1", "to": "0xbeef", "amount": amount,
                             "pay_ref": format!("0x{}", "01".repeat(32))}}]})
            } else {
                panic!("unexpected {p}")
            })
        }
        let app = axum::Router::new().fallback(h).with_state(amount);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        url
    }

    fn events_adapter(rest: &[&str], quorum: usize) -> AptosAdapter {
        let urls: Vec<String> = rest.iter().map(|u| format!("\"{u}\"")).collect();
        let cfg: ChainCfg = toml::from_str(&format!(
            "family = \"aptos\"\nnetwork = \"4\"\nrpc_urls = [{}]\nlanes = [0]\nfinality = {{ mode = \"instant\", quorum = {quorum} }}\n\
             params = {{ package = \"0xb0b\", indexer_url = \"{}/graphql\" }}",
            urls.join(", "), rest[0]
        ))
        .unwrap();
        AptosAdapter::new(&cfg, &[LocalSigner::new(crate::signer::Curve::Ed25519, &[1; 32]).unwrap()]).unwrap()
    }

    // L3: with quorum > 1, event bodies need the same agreement as block hashes — one endpoint cannot invent a payment.
    #[tokio::test]
    async fn event_bodies_follow_the_quorum() {
        let (honest, honest2, liar) = (fake_aptos("100").await, fake_aptos("100").await, fake_aptos("999").await);
        let tokens = [addr_hex(&parse_addr("0xa").unwrap())];
        let evs = events_adapter(&[&honest, &honest2], 2).events(5, 5, &tokens).await.unwrap();
        assert_eq!((evs.len(), evs[0]["amount"].as_str()), (1, Some("100")));
        assert!(events_adapter(&[&liar, &honest], 2).events(5, 5, &tokens).await.is_err(), "first endpoint lies");
        assert!(events_adapter(&[&honest, &liar], 2).events(5, 5, &tokens).await.is_err(), "no quorum");
        let one = events_adapter(&[&liar, &honest], 1).events(5, 5, &tokens).await.unwrap();
        assert_eq!(one[0]["amount"].as_str(), Some("999"), "quorum 1 trusts the first endpoint (documented)");
    }

    /// T17 (G): `meta::PaymentMeta` and `relayfee::RelayFeePaid` decode and join the expected token's
    /// `PaymentSettled` of the same transaction; a fee in an unregistered token is dropped; neither is a row.
    #[test]
    fn aptos_indexer_joins_pay_meta_and_relay_fee() {
        let pkg = parse_addr("0xb0b").unwrap();
        let tok = addr_hex(&parse_addr("0xa").unwrap());
        let ev = |module: &str, name: &str, data: Value| json!({"type": format!("{}::{module}::{name}", addr_hex(&pkg)), "data": data});
        let (pid, rf) = (format!("0x{}", "04".repeat(32)), format!("0x{}", "05".repeat(32)));
        let evs = [
            ev("meta", "PaymentMeta", json!({"contract": "0xa", "pay_id": pid, "meta": "0xabcd"})),
            ev("meta", "PaymentSettled", json!({"contract": "0xa", "from": "0x1", "to": "0xbeef", "amount": "100", "pay_ref": pid})),
            ev("meta", "PaymentSettled", json!({"contract": "0xa", "from": "0x1", "to": "0x1e", "amount": "5", "pay_ref": rf})),
            ev("relayfee", "RelayFeePaid", json!({"ref": rf, "target": "0xb0b", "token": "0xa", "payer": "0x1", "payee": "0x1e", "amount": "5"})),
            ev("relayfee", "RelayFeePaid", json!({"ref": rf, "target": "0xb0b", "token": "0xb", "payer": "0x1", "payee": "0x1e", "amount": "5"})),
            // a meta whose payment never settled in this transaction
            ev("meta", "PaymentMeta", json!({"contract": "0xa", "pay_id": rf, "meta": "0x01"})),
        ];
        let out = crate::indexer::join_pay_events(evs.iter().enumerate()
            .filter_map(|(i, e)| normalize(&pkg, std::slice::from_ref(&tok), e, 5, "0xbb", "0xcc", i)).collect());
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|e| e["event"] == "PaymentSettled"));
        assert_eq!((out[0]["meta"].as_str(), out[1]["meta"].as_str()), (Some("0xabcd"), None), "the later meta joins nothing");
        assert_eq!(out[1]["relay_payee"], addr_hex(&parse_addr("0x1e").unwrap()));
    }

    #[test]
    fn events_of_other_packages_or_tokens_are_dropped() {
        let pkg = parse_addr("0xb0b").unwrap();
        let tok = addr_hex(&parse_addr("0xa").unwrap());
        let ev = |ty: &str, contract: &str| json!({"type": ty, "data": {"contract": contract, "from": "0x1", "to": "0xbeef",
            "amount": "100", "pay_ref": format!("0x{}", "01".repeat(32)), "digest": format!("0x{}", "ab".repeat(32))}});
        let ours = format!("{}::meta::PaymentSettled", addr_hex(&pkg));
        let n = normalize(&pkg, std::slice::from_ref(&tok), &ev(&ours, "0xa"), 5, "0xbb", "0xcc", 2).unwrap();
        assert_eq!((n["event"].as_str(), n["amount"].as_str(), n["log_index"].as_u64()), (Some("PaymentSettled"), Some("100"), Some(2)));
        assert_eq!(n["entry_ref"], json!(format!("0x{}", "01".repeat(32))));
        assert!(normalize(&pkg, std::slice::from_ref(&tok), &ev("0xc0bb::meta::PaymentSettled", "0xa"), 5, "0xbb", "0xcc", 0).is_none(), "copy package");
        assert!(normalize(&pkg, std::slice::from_ref(&tok), &ev(&ours, "0xb"), 5, "0xbb", "0xcc", 0).is_none(), "unregistered token");
        let exec = format!("{}::meta::MetaTransactionExecuted", addr_hex(&pkg));
        let m = normalize(&pkg, &[tok], &ev(&exec, "0xa"), 5, "0xbb", "0xcc", 1).unwrap();
        assert_eq!(m["digest"], json!(format!("0x{}", "ab".repeat(32))));
    }

    // ---------------------------------------------------------------- CTR-MTX-26 / -27 (spec §6.2, §7.2)

    const VECTORS: &str = include_str!("../../../smartcontracts/move/aptos/tests/vectors.move");

    /// The line of `public fun <name>(` in the Move suite's vectors (`smartcontracts/move/aptos/tests/vectors.move`,
    /// `scripts/gen_vectors.py`). Only ed25519 (deterministic) signatures are read.
    fn mv_line(name: &str) -> &'static str {
        VECTORS.lines().map(str::trim).find(|l| l.starts_with(&format!("public fun {name}("))).unwrap_or_else(|| panic!("{name}"))
    }

    /// Every `x"…"` literal of that function's body, in order.
    fn hexes(name: &str) -> Vec<Vec<u8>> {
        let line = mv_line(name);
        line[line.find('{').unwrap()..].split("x\"").skip(1).map(|h| alloy::hex::decode(&h[..h.find('"').unwrap()]).unwrap()).collect()
    }

    fn mvb(name: &str) -> Vec<u8> {
        hexes(name).remove(0)
    }

    fn b32(name: &str) -> [u8; 32] {
        mvb(name).try_into().unwrap()
    }

    /// `public fun <name>(): address { @0x… }`.
    fn mva(name: &str) -> Addr {
        let line = mv_line(name);
        let a = &line[line.find('@').unwrap() + 1..];
        parse_addr(a.split_whitespace().next().unwrap()).unwrap()
    }

    fn pkg() -> Addr {
        parse_addr("0xb0b").unwrap()
    }

    /// The payment of a vector: its last four literals are `extra, public_key, sig, envelope`.
    fn pay_auth(name: &str) -> (Vec<u8>, Auth) {
        let mut h = hexes(name);
        let n = h.len();
        let mut t = h.split_off(n - 4).into_iter();
        let extra = t.next().unwrap();
        (extra, Auth { public_key: t.next().unwrap(), sig: t.next().unwrap(), envelope: t.next().unwrap() })
    }

    /// Alice's pay op as `gen_vectors.py` signed it: the envelope carries this op's digest.
    fn alice_op(to: Addr, amount: u128, pay_ref: [u8; 32], valid_until: u64, relayer: Addr, extra: Vec<u8>, auth: &Auth) -> MetaOp {
        let alice = mva("alice");
        let op = MetaOp {
            chain_id: 4, contract: account_of(&pkg(), &alice), asset: mva("eur"), op: OP_PAY, from: alice, to, amount,
            pay_ref: pay_ref.to_vec(), lane: pay_lane(&pay_ref).to_vec(), nonce: 0, valid_until, relayer, extra,
        };
        let env = String::from_utf8(auth.envelope.clone()).unwrap();
        assert!(env.contains(&alloy::hex::encode(sha3(&op.encode()))), "the vector signed another op");
        op
    }

    /// `(module, function, args)` of an entry-function payload (variant 2, this package, no type args).
    fn decode_entry(p: &[u8]) -> (String, String, Vec<Vec<u8>>) {
        let mut r = Reader { b: p, i: 0 };
        assert_eq!(r.u8().unwrap(), 2);
        assert_eq!(r.addr().unwrap(), pkg());
        let (m, f) = (String::from_utf8(r.vec().unwrap()).unwrap(), String::from_utf8(r.vec().unwrap()).unwrap());
        assert_eq!(r.uleb().unwrap(), 0, "no type arguments");
        let args = (0..r.uleb().unwrap()).map(|_| r.vec().unwrap()).collect();
        assert_eq!(r.i, p.len());
        (m, f, args)
    }

    /// Rule 1 (every row of the shared vectors) and the pay-meta payload: `relay_pay_meta`'s arguments in Move order
    /// (owner, asset, to, amount, salt, meta, valid_until, relayer, extra, public_key, sig, envelope), the first four
    /// those of `relay_pay` (whose payload the TS SDK pins, `tx_matches_the_ts_sdk`).
    #[test]
    fn aptos_pay_meta_payload_bytes() {
        let rows: Vec<Value> = serde_json::from_str(include_str!("../../../smartcontracts/vectors/metatx/paymeta.json")).unwrap();
        let h = |v: &Value| alloy::hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap();
        assert_eq!(rows.len(), 6);
        for r in &rows {
            let id = meta_pay_id(&h(&r["salt"]), &h(&r["meta"]));
            assert_eq!((id.to_vec(), pay_lane(&id).to_vec()), (h(&r["payId"]), h(&r["payLane"])), "{}", r["name"]);
        }
        let (salt, meta, id) = (mvb("pm_note_salt"), mvb("pm_note_meta"), b32("pm_note_id"));
        let (extra, auth) = pay_auth("pm_a_note");
        let op = alice_op(parse_addr("0xbeef").unwrap(), 100, id, 1000, [0; 32], extra, &auth);
        assert_eq!(sha3(&op.encode()).to_vec(), mvb("pm_a_note_digest"));
        let job = json!({"kind": "pay_meta", "salt": alloy::hex::encode(&salt), "meta": alloy::hex::encode(&meta)});
        let pol = RelayFeePolicy::default();
        assert_eq!(entry(&pkg(), &pol, &op, &job).unwrap(), Entry::PayMeta { salt: salt.clone(), meta: meta.clone() });
        let p = relay_pay_meta_payload(&pkg(), &op, &auth, &salt, &meta);
        let (m, f, args) = decode_entry(&p);
        assert_eq!((m.as_str(), f.as_str(), args.len()), ("meta", "relay_pay_meta", 12));
        assert_eq!(args[..4], decode_entry(&relay_pay_payload(&pkg(), &op, &auth)).2[..4]);
        assert_eq!((&args[4], &args[5]), (&bytes(&salt), &bytes(&meta)));
        assert_eq!(args[6..9], [1000u64.to_le_bytes().to_vec(), vec![0; 32], bytes(&[0; 32])]);
        assert_eq!(args[9..], auth_args(&auth));
        assert_eq!(addr_hex(&sha3(&p)), "0x4509e9eade5f0bfe819e962172106cf07ede479ea7a57969286639c52cc0c9fa", "{}", alloy::hex::encode(&p));
        // fail closed before the simulation
        let bad = |o: &MetaOp, j: &Value| entry(&pkg(), &pol, o, j).is_err();
        let mut j = job.clone();
        j["meta"] = json!(format!("{}00", job["meta"].as_str().unwrap()));
        assert!(bad(&op, &j), "meta does not hash to pay_ref");
        j["meta"] = job["meta"].clone();
        j["salt"] = json!(alloy::hex::encode([0u8; 32]));
        assert!(bad(&op, &j), "salt does not hash to pay_ref");
        j["salt"] = json!(alloy::hex::encode(&salt[..31]));
        assert!(bad(&op, &j), "salt is 32 bytes");
        assert!(bad(&op, &json!({"kind": "pay_meta", "meta": job["meta"]})), "no salt");
        assert!(bad(&MetaOp { nonce: 1, ..op.clone() }, &job), "nonce 1");
        assert!(bad(&MetaOp { lane: vec![1; 32], ..op.clone() }, &job), "another lane");
        let big = vec![0u8; 2049];
        let id = meta_pay_id(&[1; 32], &big);
        let o = MetaOp { pay_ref: id.to_vec(), lane: pay_lane(&id).to_vec(), ..op.clone() };
        let bj = json!({"kind": "pay_meta", "salt": alloy::hex::encode([1; 32]), "meta": alloy::hex::encode(&big)});
        assert!(bad(&o, &bj), "over the cap");
        let wide = RelayFeePolicy { params: crate::config::RelayParams { max_pay_meta_bytes: 4096, ..Default::default() }, ..pol.clone() };
        assert!(entry(&pkg(), &wide, &o, &bj).is_ok(), "params.max_pay_meta_bytes raises it");
    }

    fn fee_policy() -> RelayFeePolicy {
        RelayFeePolicy { router: Some(mva("relay_fee_marker")), tokens: vec![mva("eur")],
                         params: crate::config::RelayParams { min_amount: 5, ..Default::default() } }
    }

    /// Alice's open-mode payment for `relay_manage_signed` (`rf_manage`: 10 EUR, valid until 2000 s, salt 0x51…).
    fn manage_job() -> (MetaOp, Auth, Value) {
        let marker = mva("relay_fee_marker");
        let (extra, auth) = pay_auth("rf_manage");
        assert_eq!(extra, vec![0x51; 32]);
        let op = alice_op(marker, 10, b32("rf_manage_ref"), 2000, marker, extra, &auth);
        let job = json!({"kind": "relay_fee", "ref": alloy::hex::encode(mvb("rf_manage_ref")),
                         "extra": {"call": alloy::hex::encode(mvb("rf_manage_call"))}});
        (op, auth, job)
    }

    /// The wrapped calls' `ref` (rule 5: the bytes the Move wrappers rebuild on chain; `relay_ref_vectors` there), the
    /// policy (rule 8), the binding, and the wrapper payload: the call's arguments as the payload's arguments.
    #[test]
    fn aptos_relay_fee_job_checks_ref() {
        let pkg = pkg();
        assert_eq!(relay_marker(&pkg), mva("relay_fee_marker"));
        for (name, salt, wrapper, n) in [("manage", 0x51u8, "relay_manage_signed", 11), ("open", 0x52, "relay_mandate_open", 12),
                                         ("revoke", 0x53, "relay_revoke_signed", 5), ("cancel", 0x54, "relay_cancel_signed", 5),
                                         ("nonces", 0x55, "relay_invalidate_nonces_signed", 6),
                                         ("nonces_by_bob", 0x56, "relay_invalidate_nonces_signed", 6)] {
            let call = mvb(&format!("rf_{name}_call"));
            assert_eq!(relay_ref(4, &pkg, &call, &[salt; 32]).to_vec(), mvb(&format!("rf_{name}_ref")), "{name}");
            let c = RelayCall::decode(&call).unwrap();
            assert_eq!((c.wrapper, c.args.len()), (wrapper, n), "{name}");
            assert!(mv_line(&format!("rf_{name}")).contains(&format!("relayfee::{wrapper}(lane, ")), "{name}");
            let mut r = Reader { b: &call, i: 0 };
            r.vec().unwrap();
            assert_eq!(c.args.concat(), call[r.i..], "{name}: the arguments are the call bytes");
        }
        let (op, auth, job) = manage_job();
        let pol = fee_policy();
        let Entry::Fee { call } = entry(&pkg, &pol, &op, &job).unwrap() else { panic!("not a fee entry") };
        let p = relay_fee_payload(&pkg, &op, &auth, &call);
        let (m, f, args) = decode_entry(&p);
        assert_eq!((m.as_str(), f.as_str(), args.len()), ("relayfee", "relay_manage_signed", 20));
        assert_eq!(args[..11], call.args[..]);
        assert_eq!(args[11..15], decode_entry(&relay_pay_payload(&pkg, &op, &auth)).2[..4], "payer, asset, to, amount");
        assert_eq!(args[15..17], [2000u64.to_le_bytes().to_vec(), bytes(&[0x51; 32])]);
        assert_eq!(args[17..], auth_args(&auth));
        assert_eq!(addr_hex(&sha3(&p)), "0xed7a46258277d794a0d2aeacf6eba6f7a151097f982d9ba10c73bd3300a51c3b", "{}", alloy::hex::encode(&p));

        let err = |o: &MetaOp, j: &Value, p: &RelayFeePolicy| format!("{:#}", entry(&pkg, p, o, j).unwrap_err());
        // policy (rule 8): router configured and named as relayer, registered token, minimum fee
        assert!(err(&op, &job, &RelayFeePolicy { router: None, ..pol.clone() }).contains("params.relay_fee.router"));
        assert!(err(&op, &job, &RelayFeePolicy { router: Some([9; 32]), ..pol.clone() }).contains("router"));
        assert!(err(&op, &job, &RelayFeePolicy { tokens: vec![], ..pol.clone() }).contains("registered"));
        // the payee rule (T17), per lane: open mode at min_amount, a fee bound to the lane, elsewhere only sponsored
        let lane = [0x1e; 32];
        relay_payee(&pol, &op, &lane).unwrap();
        let dear = RelayFeePolicy { params: crate::config::RelayParams { min_amount: 11, ..Default::default() }, ..pol.clone() };
        assert!(format!("{:#}", relay_payee(&dear, &op, &lane).unwrap_err()).contains("min_amount"));
        relay_payee(&pol, &MetaOp { to: lane, ..op.clone() }, &lane).unwrap();
        let elsewhere = MetaOp { to: [0x44; 32], ..op.clone() };
        assert!(format!("{:#}", relay_payee(&pol, &elsewhere, &lane).unwrap_err()).contains("relay_bound_payee"));
        let sponsored = RelayFeePolicy { params: crate::config::RelayParams { relay_bound_payee: true, min_amount: 1 << 100, ..Default::default() }, ..pol.clone() };
        relay_payee(&sponsored, &elsewhere, &lane).unwrap();
        // binding: other call bytes, another salt, a lane / nonce off the ref, a wrong `ref`, a plain-relayer payment
        let mut c = mvb("rf_manage_call");
        let n = c.len();
        c[n - 70] ^= 1; // a byte of the KeyOp's envelope
        let mut j = job.clone();
        j["extra"]["call"] = json!(alloy::hex::encode(&c));
        assert!(err(&op, &j, &pol).contains("not bound"), "another call");
        assert!(err(&MetaOp { extra: vec![0x52; 32], ..op.clone() }, &job, &pol).contains("not bound"));
        assert!(err(&MetaOp { nonce: 1, ..op.clone() }, &job, &pol).contains("not bound"));
        assert!(err(&MetaOp { lane: vec![1; 32], ..op.clone() }, &job, &pol).contains("not bound"));
        assert!(err(&MetaOp { chain_id: 1, ..op.clone() }, &job, &pol).contains("not bound"), "another chain");
        assert!(err(&MetaOp { relayer: [0; 32], ..op.clone() }, &job, &pol).contains("router"));
        j = job.clone();
        j["ref"] = json!(alloy::hex::encode([1u8; 32]));
        assert!(err(&op, &j, &pol).contains("op.ref"));
        assert!(err(&op, &json!({"kind": "relay_fee"}), &pol).contains("extra.call"));
        // canonical bytes of a wrapped entry only: trailing data, a truncated call, an unknown entry
        let mut c = mvb("rf_manage_call");
        c.push(0);
        assert!(RelayCall::decode(&c).is_err(), "trailing");
        assert!(RelayCall::decode(&c[..c.len() - 2]).is_err(), "truncated");
        let mut c = vec![];
        vec(&mut c, b"meta::relay_pay");
        assert!(RelayCall::decode(&c).is_err(), "not wrapped");
    }

    /// No plain pay / pay-meta to the router marker (rule 4): nobody can spend from it. The router's open-mode
    /// payment (`to == marker`) still passes.
    #[test]
    fn plain_pay_to_the_marker_is_refused() {
        let (op, _, job) = manage_job();
        let pol = fee_policy();
        assert!(matches!(entry(&pkg(), &pol, &op, &job), Ok(Entry::Fee { .. })), "router open mode");
        for j in [json!({}), json!({"kind": "pay_meta", "salt": alloy::hex::encode([0u8; 32]), "meta": ""})] {
            let e = format!("{:#}", entry(&pkg(), &pol, &op, &j).unwrap_err());
            assert!(e.contains("strand"), "{j}: {e}");
        }
        // no router configured: the marker is still derived from the package, so a plain pay to it is refused
        let plain = MetaOp { relayer: [0; 32], ..op.clone() };
        let e = format!("{:#}", entry(&pkg(), &RelayFeePolicy::default(), &plain, &json!({})).unwrap_err());
        assert!(e.contains("strand"), "no router configured: {e}");
        let to_beef = MetaOp { to: parse_addr("0xbeef").unwrap(), ..op };
        assert_eq!(entry(&pkg(), &pol, &to_beef, &json!({})).unwrap(), Entry::Pay);
    }

    /// Fix 1: an unknown `op.kind` (a typo of `pay_meta`) is refused, never run as a plain pay.
    #[test]
    fn unknown_job_kind_is_refused() {
        let op = vector_op();
        assert_eq!(entry(&pkg(), &RelayFeePolicy::default(), &op, &json!({})).unwrap(), Entry::Pay);
        for k in [json!("pay-meta"), json!("pay"), json!(""), json!(7), json!(true), json!({})] {
            let e = format!("{:#}", entry(&pkg(), &RelayFeePolicy::default(), &op, &json!({"kind": k})).unwrap_err());
            assert!(e.contains("unknown op.kind"), "{k}: {e}");
        }
        assert!(entry(&pkg(), &RelayFeePolicy::default(), &op, &json!({"meta": "00"})).is_err(), "a kind-less job with meta");
    }

    fn relay_cfg(params: &str, tokens: &str) -> ChainCfg {
        toml::from_str(&format!(
            "family = \"aptos\"\nnetwork = \"4\"\nrpc_urls = [\"http://r\"]\nlanes = [0]\ntokens = [{tokens}]\n\
             finality = {{ mode = \"instant\" }}\nparams = {{ package = \"0xb0b\", indexer_url = \"http://i\"{params} }}"
        ))
        .unwrap()
    }

    /// A configured but unparsable or foreign `params.relay_fee.router`, a bad `min_amount` or a malformed token fails
    /// at startup.
    #[test]
    fn relay_fee_config_must_parse() {
        let k = [LocalSigner::new(crate::signer::Curve::Ed25519, &[1; 32]).unwrap()];
        let marker = addr_hex(&relay_marker(&pkg()));
        let eur = format!("{{ address = \"{}\", decimals = 6 }}", addr_hex(&mva("eur")));
        for (t, tokens, what) in [
            (", relay_fee = { router = \"0xzz\" }".to_string(), eur.clone(), "router"),
            (", relay_fee = { router = 7 }".to_string(), eur.clone(), "router"),
            (", relay_fee = { router = \"0x5\" }".to_string(), eur.clone(), "marker"),
            (format!(", relay_fee = {{ router = \"{marker}\", min_amount = \"9\" }}"), eur.clone(), "min_amount"),
            (format!(", relay_fee = {{ router = \"{marker}\", min_amount = -1 }}"), eur.clone(), "min_amount"),
            (String::new(), "{ address = \"0xnot-hex\", decimals = 6 }".to_string(), "tokens"),
        ] {
            let e = AptosAdapter::new(&relay_cfg(&t, &tokens), &k).err().unwrap();
            assert!(format!("{e:#}").contains(what), "{t} {tokens}: {e:#}");
        }
        let a = AptosAdapter::new(&relay_cfg(&format!(", relay_fee = {{ router = \"{marker}\", min_amount = 9 }}"), &eur), &k).unwrap();
        assert_eq!((a.relay_fee.router, a.relay_fee.params.min_amount, a.relay_fee.tokens.clone()), (Some(relay_marker(&pkg())), 9, vec![mva("eur")]));
        assert_eq!(AptosAdapter::new(&relay_cfg("", &eur), &k).unwrap().relay_fee.router, None, "no relay_fee: relay-fee jobs refused");
    }

    proptest! {
        #[test]
        fn decoders_never_panic(b in proptest::collection::vec(any::<u8>(), 0..400), s in ".{0,300}", k in ".{0,140}") {
            let _ = MetaOp::decode(&b);
            let _ = parse_auth(&s, &k);
            let _ = parse_auth(&alloy::hex::encode(&b), &k);
            let _ = classify_submit(400, &s);
        }

        /// The new jobs on untrusted input (rule 8): no panic, whatever the bytes / JSON.
        #[test]
        fn relay_fee_and_pay_meta_jobs_never_panic(b in proptest::collection::vec(any::<u8>(), 0..400), kind in 0usize..3,
                                                   s in "\\PC{0,80}", w in 0usize..5, relayer in any::<[u8; 32]>()) {
            let _ = RelayCall::decode(&b);
            let mut c = vec![];
            vec(&mut c, WRAPPED[w].0.as_bytes());
            c.extend_from_slice(&b);
            let _ = RelayCall::decode(&c);
            let hexb = alloy::hex::encode(&b);
            let kind_s = ["pay_meta", "relay_fee", "other"][kind];
            let job = json!({"kind": kind_s, "salt": hexb, "meta": s, "ref": hexb,
                             "extra": {"call": if kind == 1 { alloy::hex::encode(&c) } else { s.clone() }}});
            let op = MetaOp { relayer, ..vector_op() };
            let pol = RelayFeePolicy { router: Some(relayer), tokens: vec![op.asset], params: crate::config::RelayParams { min_amount: 0, ..Default::default() } };
            let _ = entry(&pkg(), &pol, &op, &job);
        }

        #[test]
        fn payload_round_trips(amount in any::<u128>(), nonce in any::<u64>(), vu in any::<u64>(), chain in any::<u8>()) {
            let mut op = vector_op();
            op.amount = amount;
            op.nonce = nonce;
            op.valid_until = vu;
            op.chain_id = chain;
            prop_assert_eq!(MetaOp::decode(&op.encode()).unwrap(), op);
        }
    }
}
