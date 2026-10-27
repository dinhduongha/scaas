//! Solana (S12; thiết kế `docs/history/specs/2026-10-04-net-solana.md` §6). Job `signed_op` mang `MetaOp` v1
//! (336 byte) + blob chữ ký `kind ‖ key_index ‖ sig64 ‖ [u16le n ‖ authData ‖ cdj]` + khoá công khai. Lane = khoá
//! ed25519 `m/44'/501'/{i}'/0'` của relayer, làm fee payer; thứ tự mỗi lane = durable nonce account
//! `create_with_seed(lane, "scaas-nonce-v1", System)` (RS12-14): `sequence` = 8 byte đầu giá trị nonce, một tx bay.
//! Tx v1 (SIMD-0385) dựng TẠI ĐÂY, không crate `solana-sdk` (RS12-15): `AdvanceNonceAccount` ‖ precompile
//! Ed25519/Secp256r1 dựng từ blob ‖ `scaas::relay_pay`. Event đọc qua JSON-RPC chuẩn (`getSignaturesForAddress` +
//! `getTransaction`, commitment `finalized`), chỉ inner instruction `emit_cpi!` của đúng program + event authority
//! (RS12-18).
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::adapter::{Built, ChainAdapter, Family, Head, Lane, Rejected, Signed, TxStatus};
use crate::chain::SimError;
use crate::config::ChainCfg;
use crate::odoo::Job;
use crate::signer::{LocalSigner, Signer};

pub type Key = [u8; 32];

pub const SYSTEM: Key = [0; 32];
const DOMAIN: &[u8] = b"scaas.metaop.v1";
const LABEL: &str = "scaas.metaop.v1";
const OP_PAY: u8 = 0;
const KIND_RAW: u8 = 0;
const KIND_OCMS: u8 = 1;
const KIND_PASSKEY: u8 = 2;
const NONCE_SEED: &str = "scaas-nonce-v1";
const NONCE_SPACE: u64 = 80;
/// Tag self-CPI của `emit_cpi!` (Anchor): sha256("anchor:event")[..8] đọc LE.
const EVENT_IX_TAG: [u8; 8] = 0x1d9acb512ea545e4u64.to_le_bytes();
const DEFAULT_MAX_CU: u32 = 600_000;
const DEFAULT_MAX_PRIORITY: u64 = 2_000_000;
const DEFAULT_LOADED_BYTES: u32 = 4 * 1024 * 1024;
const PAGE: usize = 1000;
/// Program id của test/localnet — khoá đã công khai (review M3), không bao giờ chạy trên cluster công khai.
pub const TEST_PROGRAM_ID: &str = "BDo6exf1vzqX44BJc1WDf4Pw6sGZcxqmuVmQPfgUgS3d";
/// Genesis hash của mainnet-beta, devnet, testnet.
pub const PUBLIC_GENESIS: [&str; 3] = [
    "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
    "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
    "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY",
];
const REBROADCAST: Duration = Duration::from_secs(2);

pub fn b58(k: &[u8]) -> String {
    bs58::encode(k).into_string()
}

pub fn key(s: &str) -> Result<Key> {
    let v = bs58::decode(s.trim()).into_vec().with_context(|| format!("not base58: {s}"))?;
    v.try_into().map_err(|_| anyhow!("a Solana address is 32 bytes: {s}"))
}

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    parts.iter().for_each(|p| h.update(p));
    h.finalize().into()
}

fn hx(b: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(b))
}

// ------------------------------------------------------------------ addresses (spec §3.1)

pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const ED25519_PROGRAM: &str = "Ed25519SigVerify111111111111111111111111111";
pub const SECP256R1_PROGRAM: &str = "Secp256r1SigVerify1111111111111111111111111";
pub const INSTRUCTIONS_SYSVAR: &str = "Sysvar1nstructions1111111111111111111111111";
pub const RECENT_BLOCKHASHES: &str = "SysvarRecentB1ockHashes11111111111111111111";
pub const RENT_SYSVAR: &str = "SysvarRent111111111111111111111111111111111";

fn k(s: &str) -> Key {
    key(s).expect("constant address")
}

/// `CompressedEdwardsY::decompress().is_some()` — điểm nằm trên đường cong ed25519.
pub fn on_curve(b: &Key) -> bool {
    ed25519_dalek::VerifyingKey::from_bytes(b).is_ok()
}

/// `Pubkey::find_program_address`.
pub fn find_pda(seeds: &[&[u8]], program: &Key) -> (Key, u8) {
    for bump in (0..=255u8).rev() {
        let mut parts: Vec<&[u8]> = seeds.to_vec();
        let b = [bump];
        parts.extend_from_slice(&[&b, program, b"ProgramDerivedAddress"]);
        let h = sha(&parts);
        if !on_curve(&h) {
            return (h, bump);
        }
    }
    unreachable!("no viable bump")
}

pub fn account_of(program: &Key, owner: &Key) -> Key {
    find_pda(&[b"acct", owner], program).0
}

pub fn ata(owner: &Key, mint: &Key, token_program: &Key) -> Key {
    find_pda(&[owner, token_program, mint], &k(ATA_PROGRAM)).0
}

/// `Pubkey::create_with_seed(base, seed, owner)`.
pub fn with_seed(base: &Key, seed: &str, owner: &Key) -> Key {
    sha(&[base, seed.as_bytes(), owner])
}

pub fn nonce_account(lane: &Key) -> Key {
    with_seed(lane, NONCE_SEED, &SYSTEM)
}

pub fn event_authority(program: &Key) -> Key {
    find_pda(&[b"__event_authority"], program).0
}

/// Discriminator Anchor: sha256("global:<name>")[..8] (instruction), sha256("event:<Name>")[..8] (event).
pub fn discriminator(namespace: &str, name: &str) -> [u8; 8] {
    sha(&[format!("{namespace}:{name}").as_bytes()])[..8].try_into().unwrap()
}

// ------------------------------------------------------------------ payload (spec §4.1)

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaOp {
    pub network: Key,
    pub contract: Key,
    pub asset: Key,
    pub op: u8,
    pub from: Key,
    pub to: Key,
    pub amount: u128,
    pub pay_ref: Key,
    pub lane: Key,
    pub nonce: u64,
    pub valid_until: u64,
    pub relayer: Key,
    pub extra: Key,
}

impl MetaOp {
    pub const LEN: usize = 336;

    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != Self::LEN || &b[..DOMAIN.len()] != DOMAIN {
            bail!("not a scaas.metaop.v1 payload");
        }
        let k32 = |o: usize| -> Key { b[o..o + 32].try_into().unwrap() };
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        Ok(Self {
            network: k32(15),
            contract: k32(47),
            asset: k32(79),
            op: b[111],
            from: k32(112),
            to: k32(144),
            amount: u128::from_le_bytes(b[176..192].try_into().unwrap()),
            pay_ref: k32(192),
            lane: k32(224),
            nonce: u64_at(256),
            valid_until: u64_at(264),
            relayer: k32(272),
            extra: k32(304),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(Self::LEN);
        o.extend_from_slice(DOMAIN);
        for x in [&self.network, &self.contract, &self.asset] {
            o.extend_from_slice(x);
        }
        o.push(self.op);
        o.extend_from_slice(&self.from);
        o.extend_from_slice(&self.to);
        o.extend_from_slice(&self.amount.to_le_bytes());
        o.extend_from_slice(&self.pay_ref);
        o.extend_from_slice(&self.lane);
        o.extend_from_slice(&self.nonce.to_le_bytes());
        o.extend_from_slice(&self.valid_until.to_le_bytes());
        o.extend_from_slice(&self.relayer);
        o.extend_from_slice(&self.extra);
        o
    }

    pub fn digest(&self) -> [u8; 32] {
        sha(&[&self.encode()])
    }
}

pub fn text(digest: &[u8; 32]) -> Vec<u8> {
    format!("{LABEL}:{}", alloy::hex::encode(digest)).into_bytes()
}

pub fn ocms(pk: &[u8], t: &[u8]) -> Vec<u8> {
    let mut m = b"\xffsolana offchain\x01\x01".to_vec();
    m.extend_from_slice(pk);
    m.extend_from_slice(t);
    m
}

/// Blob chữ ký của job (spec §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    pub kind: u8,
    pub key_index: u8,
    pub sig: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub cdj: Vec<u8>,
    pub public_key: Vec<u8>,
}

pub fn parse_auth(signature: &str, public_key: &str) -> Result<Auth> {
    let blob = alloy::hex::decode(signature.trim().trim_start_matches("0x"))?;
    let public_key = alloy::hex::decode(public_key.trim().trim_start_matches("0x"))?;
    if blob.len() < 66 || blob.len() > 4096 {
        bail!("bad signature blob length");
    }
    let (kind, key_index, sig, rest) = (blob[0], blob[1], blob[2..66].to_vec(), &blob[66..]);
    match kind {
        KIND_RAW | KIND_OCMS => {
            if !rest.is_empty() || public_key.len() != 32 {
                bail!("an ed25519 signature blob is kind ‖ key ‖ sig64 with a 32-byte key");
            }
            Ok(Auth { kind, key_index, sig, auth_data: vec![], cdj: vec![], public_key })
        }
        KIND_PASSKEY => {
            if rest.len() < 2 || public_key.len() != 33 || !matches!(public_key[0], 2 | 3) {
                bail!("a passkey blob carries authenticatorData + clientDataJSON and a compressed P-256 key");
            }
            let n = u16::from_le_bytes([rest[0], rest[1]]) as usize;
            if n < 37 || 2 + n > rest.len() {
                bail!("bad authenticatorData length");
            }
            Ok(Auth { kind, key_index, sig, auth_data: rest[2..2 + n].to_vec(), cdj: rest[2 + n..].to_vec(), public_key })
        }
        _ => bail!("unknown signature kind {kind}"),
    }
}

// ------------------------------------------------------------------ instructions + tx v1 (spec §6.2)

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub key: Key,
    pub signer: bool,
    pub writable: bool,
}

fn m(key: Key, signer: bool, writable: bool) -> Meta {
    Meta { key, signer, writable }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ix {
    pub program: Key,
    pub accounts: Vec<Meta>,
    pub data: Vec<u8>,
}

/// Instruction precompile một chữ ký: `1, 0, offsets`, rồi `pk ‖ sig ‖ msg`; mọi chỉ số instruction = u16::MAX.
pub fn precompile_ix(program: Key, pk: &[u8], sig: &[u8], msg: &[u8]) -> Ix {
    let base = 16u16;
    let (pk_off, sig_off) = (base, base + pk.len() as u16);
    let msg_off = sig_off + 64;
    let mut data = vec![1u8, 0];
    for v in [sig_off, u16::MAX, pk_off, u16::MAX, msg_off, msg.len() as u16, u16::MAX] {
        data.extend_from_slice(&v.to_le_bytes());
    }
    data.extend_from_slice(pk);
    data.extend_from_slice(sig);
    data.extend_from_slice(msg);
    Ix { program, accounts: vec![], data }
}

/// Instruction precompile cho blob: ed25519 ký `T` (kind 0) / OCMS (kind 1); P-256 ký `authData ‖ sha256(cdj)`.
pub fn auth_ix(a: &Auth, digest: &[u8; 32]) -> Ix {
    match a.kind {
        KIND_PASSKEY => {
            let mut msg = a.auth_data.clone();
            msg.extend_from_slice(&sha(&[&a.cdj]));
            precompile_ix(k(SECP256R1_PROGRAM), &a.public_key, &a.sig, &msg)
        }
        kind => {
            let t = text(digest);
            let msg = if kind == KIND_RAW { t } else { ocms(&a.public_key, &t) };
            precompile_ix(k(ED25519_PROGRAM), &a.public_key, &a.sig, &msg)
        }
    }
}

/// Mọi tham số của một `relay_pay` / `relay_pay_meta` / `relay_fee` (instruction thứ 2 sau precompile ở chỉ số 1).
pub struct Pay<'a> {
    pub program: Key,
    pub lane: Key,
    pub op: &'a MetaOp,
    pub auth: &'a Auth,
    pub token_program: Key,
    pub subject_exists: bool,
}

pub fn relay_pay_ix(p: &Pay) -> Ix {
    pay_ix(p, &Entry::Pay)
}

/// Lối vào của job (cùng `MetaOp` `pay`, cùng 14 account): `relay_pay`, `relay_pay_meta` (CTR-MTX-26) hoặc `relay_fee`
/// (CTR-MTX-27: target program + account của nó sau 14 account, `recipient` = lane ở open mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Pay,
    PayMeta { salt: Key, meta: Vec<u8> },
    Fee { target: Key, accounts: Vec<Meta>, data: Vec<u8>, recipient: Key },
    /// Static wrapper `relay_fee_<entry>` (owner 2026-10-27): the inner entry's own instruction data (`data`, its
    /// `auth` naming precompile instruction 2) and declared accounts, its remaining accounts, its signature's
    /// precompile instruction (`sig`, instruction 2 of the transaction).
    Wrapped { entry: String, data: Vec<u8>, accounts: Vec<Meta>, rest: Vec<Meta>, recipient: Key, sig: Ix },
}

/// The fee-less signed entries of `scaas` with a `relay_fee_<entry>` wrapper.
pub const WRAPPED_ENTRIES: [&str; 6] =
    ["manage_signed", "mandate_open", "mandate_revoke_signed", "mandate_close_signed", "cancel_signed", "invalidate_nonces_signed"];

/// Instruction data = Borsh của Anchor: `disc ‖ owner ‖ PayArgs ‖ [salt ‖ u32 len ‖ meta | u32 len ‖ target_data ‖
/// u8 target_accounts] ‖ Auth` (precompile ở chỉ số 1).
pub fn pay_ix(p: &Pay, e: &Entry) -> Ix {
    let (op, a) = (p.op, p.auth);
    let subject = account_of(&p.program, &op.from);
    let name = match e {
        Entry::Pay => "relay_pay".to_string(),
        Entry::PayMeta { .. } => "relay_pay_meta".to_string(),
        Entry::Fee { .. } => "relay_fee".to_string(),
        Entry::Wrapped { entry, .. } => format!("relay_fee_{entry}"),
    };
    let mut data = discriminator("global", &name).to_vec();
    if let Entry::Wrapped { data: inner, .. } = e {
        data.extend_from_slice(inner.get(8..).unwrap_or_default()); // the entry's arguments first
    }
    data.extend_from_slice(&op.from);
    data.extend_from_slice(&op.to);
    data.extend_from_slice(&(op.amount as u64).to_le_bytes());
    data.extend_from_slice(&op.pay_ref);
    data.extend_from_slice(&op.lane);
    data.extend_from_slice(&op.nonce.to_le_bytes());
    data.extend_from_slice(&op.valid_until.to_le_bytes());
    data.extend_from_slice(&op.relayer);
    data.extend_from_slice(&op.extra);
    match e {
        Entry::Pay => {}
        Entry::PayMeta { salt, meta } => {
            data.extend_from_slice(salt);
            data.extend_from_slice(&(meta.len() as u32).to_le_bytes());
            data.extend_from_slice(meta);
        }
        Entry::Fee { accounts, data: d, .. } => {
            data.extend_from_slice(&(d.len() as u32).to_le_bytes());
            data.extend_from_slice(d);
            data.push(accounts.len() as u8);
        }
        Entry::Wrapped { .. } => {}
    }
    data.extend_from_slice(&[a.kind, a.key_index, 1, 0]);
    data.extend_from_slice(&(a.cdj.len() as u32).to_le_bytes());
    data.extend_from_slice(&a.cdj);
    let recipient = match e {
        Entry::Fee { recipient, .. } | Entry::Wrapped { recipient, .. } => *recipient,
        _ => op.to,
    };
    let mut accounts = match e {
        Entry::Wrapped { accounts, .. } => accounts.clone(),
        _ => vec![],
    };
    accounts.extend([
        m(p.lane, true, true),
        m(find_pda(&[b"config"], &p.program).0, false, false),
        // RS12-2: readonly unless this pay opens the Account lazily.
        m(subject, false, !p.subject_exists),
        m(find_pda(&[b"lane", &subject, &op.lane], &p.program).0, false, true),
        m(ata(&subject, &op.asset, &p.token_program), false, true),
        m(recipient, false, false),
        m(ata(&recipient, &op.asset, &p.token_program), false, true),
        m(op.asset, false, false),
        m(p.token_program, false, false),
        m(k(ATA_PROGRAM), false, false),
        m(SYSTEM, false, false),
        m(k(INSTRUCTIONS_SYSVAR), false, false),
        m(event_authority(&p.program), false, false),
        m(p.program, false, false),
    ]);
    match e {
        Entry::Fee { target, accounts: t, .. } => {
            accounts.push(m(*target, false, false));
            accounts.extend(t.iter().cloned());
        }
        Entry::Wrapped { rest, .. } => accounts.extend(rest.iter().cloned()),
        _ => {}
    }
    Ix { program: p.program, accounts, data }
}

// ------------------------------------------------------------------ CTR-MTX-26 / -27 (spec §6.2, §7.2)

/// `max_pay_meta_bytes` (spec §9): the node's cap on a pay-meta `meta`.
// TODO(T17): becomes the `max_pay_meta_bytes` config key (default 2,048) for every family, with the indexer
// decoding of `PaymentMeta` / `RelayFeePaid`.
const MAX_PAY_META_BYTES: usize = 2048;

fn keccak(parts: &[&[u8]]) -> Key {
    alloy::primitives::keccak256(parts.concat()).0
}

/// CTR-MTX-26: `keccak256("scaas.pay.meta" ‖ salt ‖ keccak256(meta))`, the program's `meta_pay_id`.
pub fn meta_pay_id(salt: &[u8], meta: &[u8]) -> Key {
    keccak(&[b"scaas.pay.meta", salt, &keccak(&[meta])])
}

/// `keccak256("scaas.pay.lane" ‖ p)`, the 32-byte lane id of a pay-meta / relay-fee payment.
pub fn pay_lane(p: &Key) -> Key {
    keccak(&[b"scaas.pay.lane", p])
}

/// CTR-MTX-27 call bytes: `target ‖ u8 n ‖ (pubkey ‖ is_signer ‖ is_writable)×n ‖ data`.
pub fn relay_call(target: &Key, accounts: &[Meta], data: &[u8]) -> Vec<u8> {
    let mut c = target.to_vec();
    c.push(accounts.len() as u8);
    for a in accounts {
        c.extend_from_slice(&a.key);
        c.extend_from_slice(&[a.signer as u8, a.writable as u8]);
    }
    c.extend_from_slice(data);
    c
}

/// `ref = keccak256("scaas.relayfee" ‖ network ‖ target ‖ keccak256(call) ‖ salt)`, `salt` = the op's `extra` (the
/// payer signs it in the `MetaOp`).
pub fn relay_ref(network: &Key, target: &Key, call: &[u8], salt: &Key) -> Key {
    keccak(&[b"scaas.relayfee", network, target, &keccak(&[call]), salt])
}

/// The router marker: the PDA `[b"relayfee"]` of the program (no transaction can sign for it).
pub fn relay_fee_marker(program: &Key) -> Key {
    find_pda(&[b"relayfee"], program).0
}

/// What the node accepts as a relay-fee job (controller call 2026-10-27, owner may override): the configured router
/// (on Solana the `scaas` program itself), a registered token, and a fee of at least `min_amount`.
#[derive(Debug, Clone, Default)]
pub struct RelayFeePolicy {
    pub router: Option<Key>,
    pub tokens: Vec<Key>,
    pub min_amount: u64,
}

impl RelayFeePolicy {
    /// `params.relay_fee = { router = "<program id>", min_amount = N }` (default 1) and the chain's `tokens` (mints). A
    /// `router` that is set but is not a base58 address is a config error, never a silently disabled router.
    pub fn from_cfg(cfg: &ChainCfg) -> Result<Self> {
        let t = cfg.params.get("relay_fee");
        let router = match t.and_then(|t| t.get("router")) {
            None => None,
            Some(v) => Some(key(v.as_str().ok_or_else(|| anyhow!("params.relay_fee.router must be a base58 string"))?)
                .context("params.relay_fee.router")?),
        };
        Ok(Self {
            router,
            tokens: cfg.tokens.iter().filter_map(|t| key(&t.address).ok()).collect(),
            min_amount: t.and_then(|t| t.get("min_amount")).and_then(|v| v.as_integer()).map_or(1, |v| v.max(0) as u64),
        })
    }
}

fn hex_field(v: &Value, what: &str) -> Result<Vec<u8>> {
    let s = v.as_str().ok_or_else(|| anyhow!("op.{what} missing"))?;
    Ok(alloy::hex::decode(s.trim().trim_start_matches("0x"))?)
}

fn key_field(v: &Value, what: &str) -> Result<Key> {
    hex_field(v, what)?.try_into().map_err(|_| anyhow!("op.{what} is 32 bytes"))
}

/// The entry a job runs, checked before simulation (fail closed). `op.kind`: `"pay_meta"` (`op.salt`, `op.meta`:
/// `pay_ref == metaPayId(salt, meta)`, `lane == payLane(pay_ref)`, `nonce == 0`, `meta` within the cap) or
/// `"relay_fee"` (`op.extra.target` program, `op.extra.target_accounts` `[{pubkey, is_signer, is_writable}]`,
/// `op.extra.target_data` hex, optional `op.ref`: the policy, no signer among the target's accounts (the lane is the
/// only signer and would lend its signature to the target), the target is not the program, and the payment commits
/// to exactly this call: `pay_ref == ref`, `lane == payLane(ref)`, `nonce == 0`, `relayer == marker`); anything else
/// is the plain `relay_pay`.
pub fn entry(program: &Key, network: &Key, lane: &Key, policy: &RelayFeePolicy, op: &MetaOp, o: &Value) -> Result<Entry> {
    match o["kind"].as_str() {
        Some("pay_meta") => {
            let (salt, meta) = (key_field(&o["salt"], "salt")?, hex_field(&o["meta"], "meta")?);
            if meta.len() > MAX_PAY_META_BYTES {
                bail!("meta is {} B, above the {MAX_PAY_META_BYTES} B cap", meta.len());
            }
            let id = meta_pay_id(&salt, &meta);
            if op.pay_ref != id || op.lane != pay_lane(&id) || op.nonce != 0 {
                bail!("pay-meta: pay_ref / lane / nonce are not metaPayId(salt, meta) / payLane / 0");
            }
            Ok(Entry::PayMeta { salt, meta })
        }
        Some("relay_fee") => {
            if policy.router != Some(*program) {
                bail!("relay-fee router {} is not the configured params.relay_fee.router", b58(program));
            }
            if !policy.tokens.contains(&op.asset) {
                bail!("token {} is not registered on this chain", b58(&op.asset));
            }
            if op.amount < policy.min_amount as u128 {
                bail!("fee {} is below relay_fee.min_amount {}", op.amount, policy.min_amount);
            }
            let x = &o["extra"];
            if !x["entry"].is_null() {
                return wrapped(program, network, lane, op, o);
            }
            let target = key(x["target"].as_str().ok_or_else(|| anyhow!("op.extra.target missing"))?)?;
            let accounts = metas(&x["target_accounts"], "target_accounts")?;
            if accounts.iter().any(|a| a.key == *lane) {
                bail!("a target account is this lane: the target call must not touch the relayer's account");
            }
            if accounts.iter().any(|a| a.signer) {
                bail!("a target account is flagged signer: the program refuses it (no signature is lent to the target)");
            }
            if target == *program {
                bail!("the target is the scaas program itself");
            }
            let data = hex_field(&x["target_data"], "extra.target_data")?;
            let marker = relay_fee_marker(program);
            let r = relay_ref(network, &target, &relay_call(&target, &accounts, &data), &op.extra);
            if op.pay_ref != r || op.lane != pay_lane(&r) || op.nonce != 0 || op.relayer != marker {
                bail!("the payment is not bound to this call (ref, payLane(ref), nonce 0, relayer = marker)");
            }
            if !o["ref"].is_null() && key_field(&o["ref"], "ref")? != r {
                bail!("op.ref != relay_ref(target, call, salt)");
            }
            let recipient = if op.to == marker { *lane } else { op.to };
            Ok(Entry::Fee { target, accounts, data, recipient })
        }
        _ => Ok(Entry::Pay),
    }
}

/// `[{pubkey, is_signer, is_writable}]`, at most 255.
fn metas(v: &Value, what: &str) -> Result<Vec<Meta>> {
    let list = v.as_array().ok_or_else(|| anyhow!("op.extra.{what} missing"))?;
    if list.len() > 255 {
        bail!("more than 255 {what}");
    }
    list.iter()
        .map(|a| {
            let flag = |k: &str| a[k].as_bool().ok_or_else(|| anyhow!("{what}: {k} missing"));
            let pubkey = key(a["pubkey"].as_str().ok_or_else(|| anyhow!("{what}: pubkey missing"))?)?;
            Ok(Meta { key: pubkey, signer: flag("is_signer")?, writable: flag("is_writable")? })
        })
        .collect()
}

/// A static-wrapper job (`op.extra.entry` one of `WRAPPED_ENTRIES`): `extra.inner_data` (the entry's instruction
/// data, discriminator first), `extra.inner_accounts` (its declared accounts, the lane first and the only signer),
/// `extra.inner_remaining` (mandate close quads), `extra.inner_sig {program: "ed25519" | "secp256r1", public_key,
/// signature, message}`. The payment must commit to exactly this call (`ref` over target = the program).
fn wrapped(program: &Key, network: &Key, lane: &Key, op: &MetaOp, o: &Value) -> Result<Entry> {
    let x = &o["extra"];
    let entry = x["entry"].as_str().filter(|e| WRAPPED_ENTRIES.contains(e)).ok_or_else(|| anyhow!("op.extra.entry is not a wrapped entry"))?;
    let data = hex_field(&x["inner_data"], "extra.inner_data")?;
    if data.get(..8) != Some(&discriminator("global", entry)[..]) {
        bail!("inner_data is not a {entry} instruction");
    }
    let accounts = metas(&x["inner_accounts"], "inner_accounts")?;
    let rest = if x["inner_remaining"].is_null() { vec![] } else { metas(&x["inner_remaining"], "inner_remaining")? };
    if accounts.first().map(|a| (a.key, a.signer)) != Some((*lane, true)) {
        bail!("the inner entry's first account must be this lane, as its signer");
    }
    if accounts[1..].iter().chain(&rest).any(|a| a.signer) {
        bail!("only the lane signs the inner entry");
    }
    let marker = relay_fee_marker(program);
    let all: Vec<Meta> = accounts.iter().chain(&rest).cloned().collect();
    let r = relay_ref(network, program, &relay_call(program, &all, &data), &op.extra);
    if op.pay_ref != r || op.lane != pay_lane(&r) || op.nonce != 0 || op.relayer != marker {
        bail!("the payment is not bound to this call (ref, payLane(ref), nonce 0, relayer = marker)");
    }
    if !o["ref"].is_null() && key_field(&o["ref"], "ref")? != r {
        bail!("op.ref != relay_ref(scaas, call, salt)");
    }
    let s = &x["inner_sig"];
    let (pk, sig, msg) = (hex_field(&s["public_key"], "inner_sig.public_key")?, hex_field(&s["signature"], "inner_sig.signature")?, hex_field(&s["message"], "inner_sig.message")?);
    let (prog, pk_len) = match s["program"].as_str() {
        Some("ed25519") => (k(ED25519_PROGRAM), 32),
        Some("secp256r1") => (k(SECP256R1_PROGRAM), 33),
        _ => bail!("inner_sig.program is ed25519 or secp256r1"),
    };
    if pk.len() != pk_len || sig.len() != 64 || msg.is_empty() || msg.len() > 1024 {
        bail!("inner_sig: bad key / signature / message length");
    }
    let recipient = if op.to == marker { *lane } else { op.to };
    Ok(Entry::Wrapped { entry: entry.to_string(), data, accounts, rest, recipient, sig: precompile_ix(prog, &pk, &sig, &msg) })
}

pub fn advance_nonce_ix(nonce: &Key, authority: &Key) -> Ix {
    Ix {
        program: SYSTEM,
        accounts: vec![m(*nonce, false, true), m(k(RECENT_BLOCKHASHES), false, false), m(*authority, true, false)],
        data: 4u32.to_le_bytes().to_vec(),
    }
}

/// Tạo nonce account tất định của lane: `Transfer` (bù tới rent, nếu thiếu) + `AllocateWithSeed(owner System)` +
/// `InitializeNonceAccount(authority = lane)`. Địa chỉ công khai nên ai cũng gửi lamports trước được; `CreateAccountWithSeed`
/// sẽ lỗi `AccountAlreadyInUse` mãi, đường này thì không (review M1). `existing` = lamports đang có ở địa chỉ đó.
pub fn create_nonce_ixs(lane: &Key, rent: u64, existing: u64) -> Vec<Ix> {
    let nonce = nonce_account(lane);
    let mut ixs = Vec::new();
    let top = rent.saturating_sub(existing);
    if top > 0 {
        let mut d = 2u32.to_le_bytes().to_vec();
        d.extend_from_slice(&top.to_le_bytes());
        ixs.push(Ix { program: SYSTEM, accounts: vec![m(*lane, true, true), m(nonce, false, true)], data: d });
    }
    let mut d = 9u32.to_le_bytes().to_vec();
    d.extend_from_slice(lane);
    d.extend_from_slice(&(NONCE_SEED.len() as u64).to_le_bytes());
    d.extend_from_slice(NONCE_SEED.as_bytes());
    d.extend_from_slice(&NONCE_SPACE.to_le_bytes());
    d.extend_from_slice(&SYSTEM);
    ixs.push(Ix { program: SYSTEM, accounts: vec![m(nonce, false, true), m(*lane, true, false)], data: d });
    let mut d = 6u32.to_le_bytes().to_vec();
    d.extend_from_slice(lane);
    let init = Ix {
        program: SYSTEM,
        accounts: vec![m(nonce, false, true), m(k(RECENT_BLOCKHASHES), false, false), m(k(RENT_SYSVAR), false, false)],
        data: d,
    };
    ixs.push(init);
    ixs
}

/// Giới hạn đặt ở header của tx v1 (bắt buộc: bỏ trống = 0 ⇒ tx không chạy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    pub priority_lamports: u64,
    pub cu: u32,
    pub loaded_bytes: u32,
}

/// Message v1: `0x81 ‖ header ‖ config mask u32 ‖ lifetime ‖ n_ix ‖ n_keys ‖ keys ‖ config values ‖ ix headers ‖ ix
/// payloads`. Thứ tự account: fee payer, rồi signer ghi/đọc, rồi ghi/đọc — trong nhóm theo lần xuất hiện đầu (program
/// trước account của nó). Trả (message, số chữ ký).
pub fn message_v1(payer: &Key, lifetime: &[u8; 32], ixs: &[Ix], b: &Budget) -> Result<(Vec<u8>, usize)> {
    let mut keys: Vec<Meta> = vec![m(*payer, true, true)];
    let mut add = |x: &Meta| match keys.iter_mut().find(|e| e.key == x.key) {
        Some(e) => {
            e.signer |= x.signer;
            e.writable |= x.writable;
        }
        None => keys.push(x.clone()),
    };
    for ix in ixs {
        add(&m(ix.program, false, false));
        ix.accounts.iter().for_each(&mut add);
    }
    let rank = |e: &Meta| (e.key != *payer, !e.signer, !e.writable);
    keys.sort_by_key(rank); // stable: first appearance inside each group
    if keys.len() > 64 {
        bail!("a v1 transaction holds at most 64 accounts, got {}", keys.len());
    }
    let n_sig = keys.iter().filter(|e| e.signer).count();
    let ro_signed = keys.iter().filter(|e| e.signer && !e.writable).count();
    let ro_unsigned = keys.iter().filter(|e| !e.signer && !e.writable).count();
    let index = |key: &Key| keys.iter().position(|e| e.key == *key).unwrap() as u8;
    let mut o = vec![0x81, n_sig as u8, ro_signed as u8, ro_unsigned as u8];
    o.extend_from_slice(&0b1111u32.to_le_bytes()); // priority fee (bits 0-1), CU limit, loaded data size
    o.extend_from_slice(lifetime);
    o.push(ixs.len() as u8);
    o.push(keys.len() as u8);
    keys.iter().for_each(|e| o.extend_from_slice(&e.key));
    o.extend_from_slice(&b.priority_lamports.to_le_bytes());
    o.extend_from_slice(&b.cu.to_le_bytes());
    o.extend_from_slice(&b.loaded_bytes.to_le_bytes());
    for ix in ixs {
        o.push(index(&ix.program));
        o.push(ix.accounts.len() as u8);
        o.extend_from_slice(&(ix.data.len() as u16).to_le_bytes());
    }
    for ix in ixs {
        ix.accounts.iter().for_each(|a| o.push(index(&a.key)));
        o.extend_from_slice(&ix.data);
    }
    if o.len() + 64 * n_sig > 4096 {
        bail!("transaction of {} bytes exceeds 4096", o.len() + 64 * n_sig);
    }
    Ok((o, n_sig))
}

/// Tx v1 trên dây: message rồi chữ ký (một: lane).
pub fn wire_v1(message: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut o = message.to_vec();
    o.extend_from_slice(sig);
    o
}

/// Nonce account (bincode `Versions::Current(State::Initialized)`): authority 8..40, giá trị 40..72.
pub fn parse_nonce(data: &[u8]) -> Result<([u8; 32], Key)> {
    if data.len() != NONCE_SPACE as usize || data[4..8] != 1u32.to_le_bytes() {
        bail!("not an initialized nonce account");
    }
    Ok((data[40..72].try_into()?, data[8..40].try_into()?))
}

/// `sequence` của lane = 8 byte đầu của giá trị nonce (LE), bỏ bit dấu (cột `outer_nonce` là `int8`).
pub fn nonce_sequence(value: &[u8; 32]) -> u64 {
    u64::from_le_bytes(value[..8].try_into().unwrap()) & 0x7FFF_FFFF_FFFF_FFFF
}

// ------------------------------------------------------------------ classification (spec §6.4)

/// Lỗi JSON-RPC có cấu trúc (để phân loại).
#[derive(Debug)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Value,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rpc {}: {} {}", self.code, self.message, self.data)
    }
}

impl std::error::Error for RpcError {}

fn err_name(err: &Value) -> String {
    match err {
        Value::String(s) => s.clone(),
        Value::Object(o) => o.keys().next().cloned().unwrap_or_default(),
        _ => String::new(),
    }
}

/// `InstructionError: [i, e]` ⇒ (i, e).
fn instruction_error(err: &Value) -> Option<(u64, &Value)> {
    let a = err.get("InstructionError")?.as_array()?;
    Some((a.first()?.as_u64()?, a.get(1)?))
}

const BUDGET_ERRORS: &[&str] = &["ComputationalBudgetExceeded", "ProgramFailedToComplete"];

/// Lỗi tx đã VÀO SỔ (meta.err): lỗi của precompile/`scaas` (chỉ số ≥ 1) ⇒ `Reverted`; hết CU, lỗi ở advance nonce,
/// lỗi cấp tx ⇒ `Rejected` (mọi thay đổi đã rollback trừ phí + nonce lane; lane PDA người trả còn nguyên ⇒ dựng lại).
pub fn classify_landed(err: &Value, slot: u64) -> Result<TxStatus> {
    if err.is_null() {
        return Ok(TxStatus::Mined { height: slot, tx_hash: None });
    }
    match instruction_error(err) {
        Some((_, e)) if BUDGET_ERRORS.contains(&err_name(e).as_str()) => Err(Rejected(err.to_string()).into()),
        Some((i, _)) if i >= 1 => Ok(TxStatus::Reverted { reason: err.to_string() }),
        _ => Err(Rejected(err.to_string()).into()),
    }
}

/// Lỗi mô phỏng: lỗi ở precompile/`scaas` (chỉ số ≥ 1) ⇒ `Revert` (job chết); hết CU, lỗi cấp tx, và lane thiếu
/// lamports trả rent (lane PDA / Account lười / ATA — System "insufficient lamports", review L3) ⇒ `Transport` (thử lại,
/// lùi dần, breaker). ponytail: nhận diện qua log của System; tx đã vào sổ với lỗi này vẫn là `Reverted` (hiếm: mô
/// phỏng chặn trước).
pub fn classify_sim(err: &Value, logs: &[String]) -> SimError {
    let text = format!("{err} {}", logs.join(" | "));
    match instruction_error(err) {
        Some(_) if logs.iter().any(|l| l.contains("insufficient lamports")) => SimError::Transport(format!("lane short of rent: {text}")),
        Some((i, e)) if i >= 1 && !BUDGET_ERRORS.contains(&err_name(e).as_str()) => SimError::Revert(text),
        _ => SimError::Transport(format!("simulation: {text}")),
    }
}

/// Lỗi `sendTransaction`: preflight/nonce/phí ⇒ `Rejected` (gửi lại cùng bytes không bao giờ qua); `AlreadyProcessed` ⇒
/// đã gửi; lỗi mạng ⇒ lỗi thường (gửi lại cùng bytes).
pub fn classify_submit(e: &RpcError) -> Result<()> {
    let name = err_name(&e.data["err"]);
    if name == "AlreadyProcessed" || e.message.contains("AlreadyProcessed") {
        return Ok(());
    }
    let rejected = e.code == -32002
        || e.code == -32003
        || ["BlockhashNotFound", "InsufficientFundsForFee", "InsufficientFundsForRent", "SignatureFailure", "AccountNotFound", "InstructionError"]
            .iter()
            .any(|n| name == *n || e.message.contains(n));
    if rejected {
        return Err(Rejected(e.to_string()).into());
    }
    bail!("{e}")
}

// ------------------------------------------------------------------ events (spec §6.6)

/// Event `emit_cpi!` trong inner instruction ⇒ event chuẩn hoá cho Odoo; `None` nếu không phải của program/event
/// authority này, không phải event Odoo đọc, hoặc mint chưa đăng ký.
pub fn normalize(data: &[u8], tokens: &[String], slot: u64, block_hash: &str, tx_hash: &str, log_index: usize) -> Option<Value> {
    if data.len() < 16 || data[..8] != EVENT_IX_TAG {
        return None;
    }
    let (disc, body) = (&data[8..16], &data[16..]);
    let k32 = |o: usize| -> Option<Key> { body.get(o..o + 32)?.try_into().ok() };
    let contract = b58(&k32(0)?);
    if !tokens.contains(&contract) {
        return None;
    }
    let mut out = json!({"contract": contract, "block_number": slot, "block_hash": block_hash, "tx_hash": tx_hash,
        "log_index": log_index});
    if disc == discriminator("event", "MetaTransactionExecuted") && body.len() == 168 {
        out["event"] = json!("MetaTransactionExecuted");
        out["from"] = json!(b58(&k32(64)?));
        out["digest"] = json!(hx(&k32(96)?));
    } else if disc == discriminator("event", "PaymentSettled") && body.len() == 136 {
        out["event"] = json!("PaymentSettled");
        out["from"] = json!(b58(&k32(32)?));
        out["to"] = json!(b58(&k32(64)?));
        out["amount"] = json!(u64::from_le_bytes(body[96..104].try_into().ok()?).to_string());
        out["entry_ref"] = json!(hx(&k32(104)?));
    } else {
        return None;
    }
    Some(out)
}

/// Mọi event của một tx `getTransaction` (encoding json): chỉ khi `meta.err = null`, chỉ inner instruction gọi đúng
/// `program` với account đầu = event authority của nó (L2: program sao chép ở id khác không ký được).
pub fn tx_events(program: &Key, tokens: &[String], tx: &Value, block_hash: &str) -> Result<Vec<Value>> {
    let meta = &tx["meta"];
    if !meta["err"].is_null() {
        return Ok(vec![]);
    }
    let sig = tx["transaction"]["signatures"][0].as_str().ok_or_else(|| anyhow!("tx without signature"))?;
    let tx_hash = hx(&bs58::decode(sig).into_vec()?);
    let slot = tx["slot"].as_u64().ok_or_else(|| anyhow!("tx without slot"))?;
    let mut keys: Vec<String> = tx["transaction"]["message"]["accountKeys"]
        .as_array()
        .ok_or_else(|| anyhow!("tx without account keys"))?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    for part in ["writable", "readonly"] {
        keys.extend(meta["loadedAddresses"][part].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from)));
    }
    let (prog, auth) = (b58(program), b58(&event_authority(program)));
    let mut out = Vec::new();
    let mut n = 0;
    for group in meta["innerInstructions"].as_array().into_iter().flatten() {
        for ix in group["instructions"].as_array().into_iter().flatten() {
            let key_at = |v: &Value| v.as_u64().and_then(|i| keys.get(i as usize)).cloned();
            if key_at(&ix["programIdIndex"]).as_deref() != Some(&prog) || key_at(&ix["accounts"][0]).as_deref() != Some(&auth) {
                continue;
            }
            let data = bs58::decode(ix["data"].as_str().unwrap_or_default()).into_vec()?;
            if data.starts_with(&EVENT_IX_TAG) {
                if let Some(e) = normalize(&data, tokens, slot, block_hash, &tx_hash, n) {
                    out.push(e);
                }
                n += 1;
            }
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------ adapter

/// Bytes đã gửi, giữ để tự rebroadcast trong `tx_status` (RS12-16).
struct Sent {
    raw: Vec<u8>,
    lane: usize,
    sequence: u64,
    last: Instant,
}

/// Kế hoạch tx (body của `Built`): instruction sau `AdvanceNonceAccount` + giới hạn header.
#[derive(Serialize, Deserialize)]
struct Plan {
    ixs: Vec<Ix>,
    budget: Budget,
}

pub struct SolanaAdapter {
    key: String,
    network: Key,
    rpcs: Vec<String>,
    http: reqwest::Client,
    program: Key,
    max_cu: u32,
    max_priority: u64,
    loaded_bytes: u32,
    quorum: usize,
    lanes: Vec<Lane>,
    signers: Vec<LocalSigner>,
    sent: Mutex<HashMap<String, Sent>>,
    domain_checked: tokio::sync::OnceCell<()>,
    relay_fee: RelayFeePolicy,
}

struct Work {
    op: MetaOp,
    auth: Auth,
    token_program: Key,
}

fn transport(e: anyhow::Error) -> SimError {
    SimError::Transport(format!("{e:#}"))
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl SolanaAdapter {
    pub fn new(cfg: &ChainCfg, signers: &[LocalSigner]) -> Result<Self> {
        if cfg.rpc_urls.is_empty() || signers.is_empty() {
            bail!("chain {}: needs rpc_urls and at least one lane", cfg.chain_key());
        }
        let p = |k: &str| cfg.params.get(k).and_then(|v| v.as_str());
        let n = |k: &str, d: u64| cfg.params.get(k).and_then(|v| v.as_integer()).map_or(d, |v| v.max(0) as u64);
        let network = key(cfg.network.as_deref().unwrap_or_default()).context("solana: network must be the genesis hash (base58)")?;
        let program = key(p("program_id").ok_or_else(|| anyhow!("solana: params.program_id is required"))?)?;
        if b58(&program) == TEST_PROGRAM_ID && PUBLIC_GENESIS.contains(&b58(&network).as_str()) {
            bail!("solana: {TEST_PROGRAM_ID} is the test-only program id (its key is public); deploy your own (smartcontracts/solana/scripts/deploy.sh)");
        }
        let mut lanes = Vec::new();
        let mut own = Vec::new();
        for (s, &i) in signers.iter().zip(&cfg.lanes) {
            let LocalSigner::Ed(sk) = s else { bail!("solana lanes are ed25519") };
            lanes.push(Lane { index: i, address: b58(&sk.verifying_key().to_bytes()) });
            own.push(LocalSigner::Ed(sk.clone()));
        }
        Ok(Self {
            key: cfg.chain_key(),
            network,
            rpcs: cfg.rpc_urls.clone(),
            http: reqwest::Client::builder().timeout(Duration::from_secs(20)).build()?,
            program,
            max_cu: n("max_cu", DEFAULT_MAX_CU as u64).clamp(10_000, 1_400_000) as u32,
            max_priority: n("max_priority_lamports", DEFAULT_MAX_PRIORITY),
            loaded_bytes: n("max_loaded_bytes", DEFAULT_LOADED_BYTES as u64).clamp(64 * 1024, 64 * 1024 * 1024) as u32,
            quorum: cfg.finality.quorum.max(1),
            lanes,
            signers: own,
            sent: Mutex::new(HashMap::new()),
            domain_checked: tokio::sync::OnceCell::new(),
            relay_fee: RelayFeePolicy::from_cfg(cfg)?,
        })
    }

    async fn rpc_at(&self, url: &str, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let v: Value = self.http.post(url).json(&body).send().await?.error_for_status()?.json().await?;
        if let Some(e) = v.get("error") {
            return Err(RpcError {
                code: e["code"].as_i64().unwrap_or(0),
                message: e["message"].as_str().unwrap_or_default().to_string(),
                data: e.get("data").cloned().unwrap_or(Value::Null),
            }
            .into());
        }
        Ok(v["result"].clone())
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        self.rpc_at(&self.rpcs[0], method, params).await
    }

    async fn account_data(&self, k: &Key, commitment: &str) -> Result<Option<(Vec<u8>, Key)>> {
        let v = self.rpc("getAccountInfo", json!([b58(k), {"encoding": "base64", "commitment": commitment}])).await?;
        let a = &v["value"];
        if a.is_null() {
            return Ok(None);
        }
        let data = base64::engine::general_purpose::STANDARD.decode(a["data"][0].as_str().unwrap_or_default())?;
        Ok(Some((data, key(a["owner"].as_str().unwrap_or_default())?)))
    }

    /// RS12-8: genesis của RPC = `network` của chain trong Odoo = `Config.network` của program; lệch ⇒ không chạy.
    async fn check_domain(&self) -> Result<()> {
        self.domain_checked
            .get_or_try_init(|| async {
                let g = key(self.rpc("getGenesisHash", json!([])).await?.as_str().unwrap_or_default())?;
                if g != self.network {
                    bail!("RPC genesis {} is not the configured network {}", b58(&g), b58(&self.network));
                }
                let config = find_pda(&[b"config"], &self.program).0;
                let (data, owner) = self.account_data(&config, "confirmed").await?.ok_or_else(|| anyhow!("program Config not initialized"))?;
                if owner != self.program || data.get(40..72) != Some(&self.network[..]) {
                    bail!("program Config.network is not {}", b58(&self.network));
                }
                Ok(())
            })
            .await
            .map(|_| ())
    }

    fn work(&self, job: &Job) -> Result<Work> {
        let o = job.op.as_ref().ok_or_else(|| anyhow!("not a signed_op job"))?;
        let payload = alloy::hex::decode(o["payload"].as_str().unwrap_or_default().trim_start_matches("0x"))?;
        let op = MetaOp::decode(&payload)?;
        if op.op != OP_PAY {
            bail!("only pay ops are relayed on Solana");
        }
        if op.network != self.network {
            bail!("payload is for network {}, this chain is {}", b58(&op.network), b58(&self.network));
        }
        if key(o["contract"].as_str().unwrap_or_default())? != op.contract || account_of(&self.program, &op.from) != op.contract {
            bail!("payload contract is not the payer's Account under this program");
        }
        if key(o["extra"]["asset"].as_str().unwrap_or_default())? != op.asset {
            bail!("payload asset is not the job's token");
        }
        if op.amount > u64::MAX as u128 {
            bail!("amount above u64");
        }
        let token_program = key(o["extra"]["token_program"].as_str().unwrap_or(TOKEN_PROGRAM))?;
        if token_program != k(TOKEN_PROGRAM) && token_program != k(TOKEN_2022) {
            bail!("unknown token program {}", b58(&token_program));
        }
        let auth = parse_auth(o["signature"].as_str().unwrap_or_default(), o["public_key"].as_str().unwrap_or_default())?;
        Ok(Work { op, auth, token_program })
    }

    fn lane_key(&self, lane: usize) -> Result<Key> {
        key(&self.lanes.get(lane).ok_or_else(|| anyhow!("no lane {lane}"))?.address)
    }

    /// Giá trị nonce hiện tại của lane (commitment `confirmed`); tạo nonce account nếu chưa có (một tx setup do lane trả).
    /// `ponytail:` side-effect trong `sequence`, đủ vì chỉ chạy một lần mỗi lane.
    async fn nonce(&self, lane: usize) -> Result<[u8; 32]> {
        let lk = self.lane_key(lane)?;
        let addr = nonce_account(&lk);
        let mut existing = 0;
        if let Some((data, owner)) = self.account_data(&addr, "confirmed").await? {
            if owner != SYSTEM {
                bail!("nonce account {} is not this lane's", b58(&addr));
            }
            if !data.is_empty() {
                let (value, authority) = parse_nonce(&data)?;
                if authority != lk {
                    bail!("nonce account {} is not this lane's", b58(&addr));
                }
                return Ok(value);
            }
            // pre-funded by someone (M1): keep its lamports, allocate in place
            existing = self.rpc("getBalance", json!([b58(&addr), {"commitment": "confirmed"}])).await?["value"].as_u64().unwrap_or(0);
        }
        let rent = self.rpc("getMinimumBalanceForRentExemption", json!([NONCE_SPACE])).await?.as_u64().ok_or_else(|| anyhow!("bad rent"))?;
        let bh = self.rpc("getLatestBlockhash", json!([{"commitment": "confirmed"}])).await?;
        let bh = key(bh["value"]["blockhash"].as_str().unwrap_or_default())?;
        let budget = Budget { priority_lamports: 0, cu: 10_000, loaded_bytes: 64 * 1024 };
        let (msg, _) = message_v1(&lk, &bh, &create_nonce_ixs(&lk, rent, existing), &budget)?;
        let tx = wire_v1(&msg, &self.signers[lane].sign(&msg)?);
        tracing::info!(chain = %self.key, lane, nonce = %b58(&addr), "creating the lane's durable nonce account");
        self.send_raw(&tx).await?;
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Some((data, _)) = self.account_data(&addr, "confirmed").await? {
                if !data.is_empty() {
                    return Ok(parse_nonce(&data)?.0);
                }
            }
        }
        bail!("nonce account {} not created", b58(&addr))
    }

    async fn send_raw(&self, raw: &[u8]) -> Result<()> {
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let r = self.rpc("sendTransaction", json!([b64, {"encoding": "base64", "skipPreflight": false,
            "preflightCommitment": "confirmed", "maxRetries": 0}])).await;
        match r {
            Ok(_) => Ok(()),
            Err(e) => match e.downcast_ref::<RpcError>() {
                Some(re) => classify_submit(re),
                None => Err(e),
            },
        }
    }

    fn sign_message(&self, lane: usize, nonce: &[u8; 32], plan: &Plan) -> Result<(Vec<u8>, Vec<u8>)> {
        let lk = self.lane_key(lane)?;
        let mut ixs = vec![advance_nonce_ix(&nonce_account(&lk), &lk)];
        ixs.extend(plan.ixs.iter().cloned());
        let (msg, _) = message_v1(&lk, nonce, &ixs, &plan.budget)?;
        let sig = self.signers[lane].sign(&msg)?;
        Ok((wire_v1(&msg, &sig), sig))
    }

    /// Block được SẢN XUẤT cuối cùng ≤ `slot` (slot bị bỏ qua là bình thường trên Solana) và blockhash của nó.
    async fn produced_at_or_before(&self, url: &str, slot: u64) -> Result<(u64, String)> {
        let blocks = self.rpc_at(url, "getBlocks", json!([slot.saturating_sub(2048), slot, {"commitment": "finalized"}])).await?;
        let s = blocks.as_array().and_then(|a| a.last()).and_then(|v| v.as_u64()).ok_or_else(|| anyhow!("no block produced in the 2048 slots up to {slot}"))?;
        Ok((s, self.blockhash_at(url, s).await?))
    }

    async fn blockhash_at(&self, url: &str, slot: u64) -> Result<String> {
        let b = self.rpc_at(url, "getBlock", json!([slot, {"commitment": "finalized", "transactionDetails": "none",
            "rewards": false, "maxSupportedTransactionVersion": 1}])).await?;
        Ok(hx(&key(b["blockhash"].as_str().unwrap_or_default())?))
    }

    async fn priority_fee(&self, writable: &[Key], cu: u32) -> u64 {
        let keys: Vec<String> = writable.iter().map(|k| b58(k)).collect();
        let Ok(v) = self.rpc("getRecentPrioritizationFees", json!([keys])).await else { return 0 };
        let mut fees: Vec<u64> = v.as_array().into_iter().flatten().filter_map(|f| f["prioritizationFee"].as_u64()).collect();
        if fees.is_empty() {
            return 0;
        }
        fees.sort_unstable();
        let p75 = fees[(fees.len() * 3 / 4).min(fees.len() - 1)];
        ((cu as u128 * p75 as u128 / 1_000_000) as u64).min(self.max_priority)
    }
}

#[async_trait]
impl ChainAdapter for SolanaAdapter {
    fn family(&self) -> Family {
        Family::Solana
    }

    fn chain_key(&self) -> &str {
        &self.key
    }

    fn lanes(&self) -> &[Lane] {
        &self.lanes
    }

    /// R80: `pay` ⇒ `LanePda.next` (8 byte sau discriminator; chưa tạo hoặc đã dọn = 0) so với nonce đã ký.
    async fn op_consumed(&self, job: &Job) -> Result<Option<bool>> {
        let Ok(w) = self.work(job) else { return Ok(None) };
        let pda = find_pda(&[b"lane", &w.op.contract, &w.op.lane], &self.program).0;
        let next = match self.account_data(&pda, "confirmed").await? {
            None => 0,
            Some((d, owner)) if owner == self.program && d.len() >= 16 => u64::from_le_bytes(d[8..16].try_into().expect("8")),
            Some(_) => bail!("lane PDA {} is not this program's", b58(&pda)),
        };
        Ok(Some(next > w.op.nonce))
    }

    /// Dựng + mô phỏng (`sigVerify:false`, nonce thật). Lỗi ở precompile/`scaas` ⇒ `Revert` (job chết); còn lại
    /// (RPC, nonce vừa đổi, lane thiếu phí, cấu hình lệch miền) ⇒ `Transport` (thử lại, lùi dần).
    async fn build(&self, job: &Job, lane: usize) -> std::result::Result<Built, SimError> {
        let w = self.work(job).map_err(|e| SimError::Revert(format!("bad payload: {e:#}")))?;
        if w.op.valid_until <= now() {
            return Err(SimError::Revert("payload expired".into()));
        }
        self.check_domain().await.map_err(transport)?;
        let lk = self.lane_key(lane).map_err(transport)?;
        let subject = account_of(&self.program, &w.op.from);
        let subject_exists = self.account_data(&subject, "confirmed").await.map_err(transport)?.is_some();
        let o = job.op.as_ref().ok_or_else(|| SimError::Revert("not a signed_op job".into()))?;
        let e = entry(&self.program, &self.network, &lk, &self.relay_fee, &w.op, o).map_err(|e| SimError::Revert(format!("{e:#}")))?;
        let pay = Pay { program: self.program, lane: lk, op: &w.op, auth: &w.auth, token_program: w.token_program, subject_exists };
        let mut ixs = vec![auth_ix(&w.auth, &w.op.digest())];
        if let Entry::Wrapped { sig, .. } = &e {
            ixs.push(sig.clone()); // instruction 2: the inner entry's own signature
        }
        ixs.push(pay_ix(&pay, &e));
        let nonce = self.nonce(lane).await.map_err(transport)?;
        let plan = Plan { ixs, budget: Budget { priority_lamports: 0, cu: self.max_cu, loaded_bytes: self.loaded_bytes } };
        let (raw, _) = self.sign_message(lane, &nonce, &plan).map_err(|e| SimError::Revert(format!("{e:#}")))?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
        let sim = self
            .rpc("simulateTransaction", json!([b64, {"encoding": "base64", "sigVerify": false, "replaceRecentBlockhash": false,
                "commitment": "confirmed"}]))
            .await
            .map_err(transport)?;
        let v = &sim["value"];
        if !v["err"].is_null() {
            let logs: Vec<String> = v["logs"].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect();
            return Err(classify_sim(&v["err"], &logs));
        }
        let used = v["unitsConsumed"].as_u64().unwrap_or(self.max_cu as u64);
        let cu = (used + used.div_ceil(5)).clamp(1_000, self.max_cu as u64) as u32;
        let writable: Vec<Key> = plan.ixs.iter().flat_map(|ix| ix.accounts.iter().filter(|a| a.writable).map(|a| a.key)).collect();
        let budget = Budget { priority_lamports: self.priority_fee(&writable, cu).await, cu, loaded_bytes: self.loaded_bytes };
        let plan = Plan { ixs: plan.ixs, budget };
        let body = serde_json::to_vec(&plan).map_err(|e| SimError::Revert(e.to_string()))?;
        Ok(Built { job_id: job.id, body, valid_until: w.op.valid_until, meta: json!({"units": used, "subject_exists": subject_exists}) })
    }

    /// Đọc lại nonce: phải khớp `sequence` runner đã journal (khác ⇒ lỗi thường, runner thử lại).
    async fn sign(&self, built: Built, lane: usize, sequence: u64) -> Result<Signed> {
        let plan: Plan = serde_json::from_slice(&built.body)?;
        let nonce = self.nonce(lane).await?;
        if nonce_sequence(&nonce) != sequence {
            bail!("lane {lane} nonce moved while signing");
        }
        let (raw, sig) = self.sign_message(lane, &nonce, &plan)?;
        Ok(Signed { job_id: built.job_id, tx_id: hx(&sig), raw, valid_until: built.valid_until, sequence })
    }

    async fn submit(&self, signed: &Signed) -> Result<()> {
        let lane = self.lane_of(&signed.raw).unwrap_or(0);
        self.sent.lock().map_err(|_| anyhow!("poisoned"))?.insert(
            signed.tx_id.clone(),
            Sent { raw: signed.raw.clone(), lane, sequence: signed.sequence, last: Instant::now() },
        );
        self.send_raw(&signed.raw).await
    }

    async fn tx_status(&self, tx_id: &str) -> Result<TxStatus> {
        let sig = b58(&alloy::hex::decode(tx_id.trim_start_matches("0x"))?);
        let v = self.rpc("getSignatureStatuses", json!([[sig], {"searchTransactionHistory": true}])).await?;
        let st = &v["value"][0];
        if st.is_null() {
            // Tự rebroadcast (RPC rớt tx khi nghẽn): cùng bytes, ≤ 1 lần / 2 s, chỉ khi nonce lane chưa đổi.
            // ponytail: rebroadcast trong `tx_status`, tách task riêng khi cần nhiều RPC song song.
            let due = self.sent.lock().ok().and_then(|mut s| {
                let e = s.get_mut(tx_id)?;
                (e.last.elapsed() >= REBROADCAST).then(|| {
                    e.last = Instant::now();
                    (e.raw.clone(), e.lane, e.sequence)
                })
            });
            if let Some((raw, lane, seq)) = due {
                if matches!(self.nonce(lane).await, Ok(n) if nonce_sequence(&n) == seq) {
                    let _ = self.send_raw(&raw).await;
                }
            }
            return Ok(TxStatus::Unknown);
        }
        if st["confirmationStatus"].as_str().unwrap_or("processed") == "processed" {
            return Ok(TxStatus::Pending);
        }
        self.sent.lock().map_err(|_| anyhow!("poisoned"))?.remove(tx_id);
        classify_landed(&st["err"], st["slot"].as_u64().unwrap_or(0))
    }

    async fn sequence(&self, lane: usize) -> Result<u64> {
        Ok(nonce_sequence(&self.nonce(lane).await?))
    }

    async fn lane_balance(&self, lane: usize) -> Result<Option<u128>> {
        let v = self.rpc("getBalance", json!([b58(&self.lane_key(lane)?), {"commitment": "confirmed"}])).await?;
        Ok(v["value"].as_u64().map(u128::from))
    }

    async fn tx_fee(&self, tx_id: &str) -> Result<Option<u128>> {
        let sig = b58(&alloy::hex::decode(tx_id.trim_start_matches("0x"))?);
        let v = self.rpc("getTransaction", json!([sig, {"commitment": "confirmed", "maxSupportedTransactionVersion": 1}])).await?;
        Ok(v["meta"]["fee"].as_u64().map(u128::from))
    }

    /// Restart: không còn bytes cũ ⇒ advance nonce của lane một lần để mọi tx đã ký trước crash không bao giờ vào sổ nữa;
    /// `recover_lane` thấy nonce đổi ⇒ job về hàng đợi ngay thay vì giữ lane tới hạn payload (review agy #1).
    /// ponytail: một tx (5 000 lamport) mỗi lần khởi động mỗi lane, kể cả khi không có job dở.
    async fn resend_journaled(&self, lane: usize) -> Result<()> {
        let lk = self.lane_key(lane)?;
        let before = self.nonce(lane).await?;
        let plan = Plan { ixs: vec![], budget: Budget { priority_lamports: 0, cu: 10_000, loaded_bytes: 64 * 1024 } };
        let (raw, _) = self.sign_message(lane, &before, &plan)?;
        self.send_raw(&raw).await.or_else(|e| if e.downcast_ref::<Rejected>().is_some() { Ok(()) } else { Err(e) })?;
        for _ in 0..60 {
            if self.nonce(lane).await? != before {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        bail!("lane {} nonce did not advance", b58(&lk))
    }

    /// Đỉnh `finalized` (min slot giữa các endpoint) quy về block sản xuất cuối ≤ nó; quorum = cùng hash.
    async fn final_head(&self) -> Result<Option<Head>> {
        let mut slots = Vec::new();
        for url in &self.rpcs {
            if let Ok(v) = self.rpc_at(url, "getSlot", json!([{"commitment": "finalized"}])).await {
                if let Some(s) = v.as_u64() {
                    slots.push(s);
                }
            }
        }
        if slots.len() < self.quorum {
            return Ok(None);
        }
        let slot = *slots.iter().min().unwrap();
        let (height, hash) = self.produced_at_or_before(&self.rpcs[0], slot).await?;
        let mut agree = 1;
        for url in &self.rpcs[1..] {
            if self.blockhash_at(url, height).await.ok().as_deref() == Some(hash.as_str()) {
                agree += 1;
            }
        }
        Ok((agree >= self.quorum).then_some(Head { height, hash }))
    }

    async fn block_hash(&self, height: u64) -> Result<String> {
        Ok(self.produced_at_or_before(&self.rpcs[0], height).await?.1)
    }

    /// Phân trang lùi `getSignaturesForAddress(program)` (finalized) tới slot < `from` hoặc trang rỗng; hết lịch sử mà chưa tới `from`
    /// ⇒ RPC phải còn block từ `from` (`getFirstAvailableBlock`), không thì `Err` (vùng không được chốt).
    /// ponytail: mỗi bước phân trang từ đỉnh xuống `to` — O(độ tụt hậu) khi bắt kịp trên mainnet; nhớ chữ ký biên hoặc
    /// Geyser khi tải cao (owner OQ2).
    async fn events(&self, from: u64, to: u64, contracts: &[String]) -> Result<Vec<Value>> {
        let tokens: Vec<String> = contracts.iter().filter_map(|c| key(c).ok()).map(|k| b58(&k)).collect();
        if tokens.is_empty() && !contracts.is_empty() {
            // L1: Ok([]) here would let index_step move the cursor past real events
            bail!("none of the {} registered tokens is a Solana address", contracts.len());
        }
        if tokens.is_empty() || from > to {
            return Ok(vec![]);
        }
        let mut sigs: Vec<(u64, String)> = Vec::new();
        let mut before: Option<String> = None;
        loop {
            let mut opts = json!({"commitment": "finalized", "limit": PAGE});
            if let Some(b) = &before {
                opts["before"] = json!(b);
            }
            let page = self.rpc("getSignaturesForAddress", json!([b58(&self.program), opts])).await?;
            let page = page.as_array().cloned().unwrap_or_default();
            let mut reached = false;
            for item in &page {
                let (Some(slot), Some(sig)) = (item["slot"].as_u64(), item["signature"].as_str()) else { bail!("bad signature page") };
                before = Some(sig.to_string());
                if slot > to {
                    continue;
                }
                if slot < from {
                    reached = true;
                    break;
                }
                if item["err"].is_null() {
                    sigs.push((slot, sig.to_string()));
                }
            }
            if reached {
                break;
            }
            // L2: a short page is NOT the end (providers cap `limit`, bigtable/ledger seams); only an empty page is
            if page.is_empty() {
                let first = self.rpc("getFirstAvailableBlock", json!([])).await?.as_u64().unwrap_or(u64::MAX);
                if first > from {
                    bail!("RPC history starts at slot {first}, after the range start {from}");
                }
                break;
            }
        }
        sigs.reverse();
        let mut hashes: HashMap<u64, String> = HashMap::new();
        let mut out = Vec::new();
        for (slot, sig) in sigs {
            let tx = self.rpc("getTransaction", json!([sig, {"commitment": "finalized", "maxSupportedTransactionVersion": 1,
                "encoding": "json"}])).await?;
            if tx.is_null() {
                bail!("finalized transaction {sig} not served");
            }
            let bh = match hashes.get(&slot) {
                Some(h) => h.clone(),
                None => {
                    let h = self.blockhash_at(&self.rpcs[0], slot).await?;
                    hashes.insert(slot, h.clone());
                    h
                }
            };
            out.extend(tx_events(&self.program, &tokens, &tx, &bh)?);
        }
        Ok(out)
    }
}

impl SolanaAdapter {
    /// Lane đã ký tx v1 này: fee payer = account tĩnh đầu tiên (sau header 4 + mask 4 + lifetime 32 + 2 byte đếm).
    fn lane_of(&self, raw: &[u8]) -> Option<usize> {
        let payer = raw.get(42..74)?;
        self.signers.iter().position(|s| s.public_key() == payer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::sync::Arc;

    // Vector chéo — cùng giá trị ở smartcontracts/solana/programs/scaas/tests/vectors.rs và dms_blockchain/tests/test_fam_solana.py.
    const PROGRAM: &str = "BDo6exf1vzqX44BJc1WDf4Pw6sGZcxqmuVmQPfgUgS3d";
    const NETWORK: &str = "5VWXHhdzL461VPajmqi6CUUGVgxd818183cWN47vQAsi";
    const ALICE: &str = "FPP21sbqhr2LPjSnJkw5NBetPubeFG4PsQFBxHj8noTq";
    const BOB: &str = "GwCXyJ8AesaucFMTUSZmiFVMhVngpeBxaBC7mQJiZct3";
    const USD: &str = "E5XS6w9DtMRaPTk38iGhD3iSwDJzYUNkKtmUqEpNpUsf";
    const ALICE_ACCOUNT: &str = "Cpdv3d1ppikVEJVQmEoT6ATWaChLS59Raxg5DfCdpHjv";
    const ALICE_LANE_PDA: &str = "E6Zuj4rbZwGu1Qk6sQUtba4TFhotWRtf56p9ZmrRNRs6";
    const BOB_ATA_USD: &str = "4cNKNsfY1HwhsqcMWgQ7bu7pLpGgg5xUsX5eaQbguvLM";
    const DIGEST: &str = "90bdedbc80fce8a0492ee6ed3a1b8da9d3664b74225884e384ce3abfa6e587de";
    const PAYLOAD: &str = concat!(
        "73636161732e6d6574616f702e763142bc642743f255b32605335bb91b7ecd8f6d0cea0056238c3b3518534dc9aba9afa497f9db8f42d7",
        "0fb0ef45b544030815b53b0ec8812ced192f3f6df4d896f1c250a9ebc1dc2e6299d0873da3edfd78261d872701b4dc7ad557d9eabe3bce",
        "8e00d5bf4a3fcce717b0388bcc2749ebc148ad9969b23f45ee1b605fd58778576ac4ecc1b58727f3f12b3194881a9ecb9de0b28ce7b207",
        "230d8e930fe1bce75e256c6400000000000000000000000000000001010101010101010101010101010101010101010101010101010101",
        "01010101a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10000000000000000e803000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000",
    );
    const BLOB_RAW: &str = concat!(
        "00005fa5be22ec3cb7690ce2702ed545503055db92647040e3d9779e9e80cf2f6dc1f6f9955382ab7c51e8540025e57cf148d127a8cd0f",
        "3bcc8a0afa2ae621d5530b",
    );
    // @solana/kit 8.4.0 (`smartcontracts/solana/scripts/tx_vector.mjs`): lane = ed25519 seed sha256("lane0"), nonce value 0x42…,
    // instructions AdvanceNonceAccount ‖ Ed25519 precompile ‖ scaas::relay_pay of the vector payload, CU 200 000,
    // priority 5 000 lamports, loaded bytes 4 MiB.
    const TX_V1: &str = concat!(
        "8101000c0f00000042424242424242424242424242424242424242424242424242424242424242420311ab514c44076f6416bc2fb0742e",
        "e1823e7054395b513aa382709794d04a208e3f384090ca632b7eeb8458926e3e099245f9830875b969714b68b31333b235c5e0c2950b62",
        "d6a0e997e0ebdc44500a8a62d2e78c587cd746279ebcf40c7abc2e21d6b9f980bd8ad8b7db434ee0cbf2d9f4530cd5ce499d28bc45b544",
        "4e0664b24135a27dfc65442868e9a4ad98b8aed6707adb765961e1926d25ff2151153238e6000000000000000000000000000000000000",
        "000000000000000000000000000006a7d517192c568ee08a845f73d29788cf035c3145b21ab344d8062ea9400000037d46d67c93fbbe12",
        "f9428f838d40ff0570744927f48a64fcca70448000000097dbf6298ebc1d1aba6fe95a3c688f723fbd62ea8fe24fcd18b1de8988fea4c4",
        "3b3e9943cbb124644de5ca101c9331b97c9fb087d3181a0d25ec3015e5c21d37afa497f9db8f42d70fb0ef45b544030815b53b0ec8812c",
        "ed192f3f6df4d896f1ecc1b58727f3f12b3194881a9ecb9de0b28ce7b207230d8e930fe1bce75e256cc250a9ebc1dc2e6299d0873da3ed",
        "fd78261d872701b4dc7ad557d9eabe3bce8e06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a98c97258f4e",
        "2489f1bb3d1029148e0d830b5a1399daff1084048e7bd8dbe9f85906a7d517187bd16635dad40455fdc2c0c124c68f215675a5dbbacb5f",
        "08000000b4d5b65321eff24d9763b980f4d8dace33e62e1685e673dc058f5c1f244af9668813000000000000400d030000004000050304",
        "000700c000080ee8000106000400000001003000ffff1000ffff70005000ffffd5bf4a3fcce717b0388bcc2749ebc148ad9969b23f45ee",
        "1b605fd58778576ac45fa5be22ec3cb7690ce2702ed545503055db92647040e3d9779e9e80cf2f6dc1f6f9955382ab7c51e8540025e57c",
        "f148d127a8cd0f3bcc8a0afa2ae621d5530b73636161732e6d6574616f702e76313a393062646564626338306663653861303439326565",
        "3665643361316238646139643336363462373432323538383465333834636533616266613665353837646500090a02030b040c0d0e050f",
        "1008fe773b8107d9d057d5bf4a3fcce717b0388bcc2749ebc148ad9969b23f45ee1b605fd58778576ac4ecc1b58727f3f12b3194881a9e",
        "cb9de0b28ce7b207230d8e930fe1bce75e256c640000000000000001010101010101010101010101010101010101010101010101010101",
        "01010101a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10000000000000000e803000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000010000000000c2542f3c2d87a4eb8b1fd83eab904b7c5d1b08ccabfee1cac7b4750649f734b63b7efd89d2e54c8a4c",
        "6b319bd4262d10e30e4d21cb1b6d29c3b85f01cfc1ba0a",
    );

    fn lane0() -> LocalSigner {
        LocalSigner::new(crate::signer::Curve::Ed25519, &sha(&[b"lane0"])).unwrap()
    }

    #[test]
    fn payload_digest_and_addresses_match_python_and_the_program() {
        let b = alloy::hex::decode(PAYLOAD.trim()).unwrap();
        let op = MetaOp::decode(&b).unwrap();
        assert_eq!(op.encode(), b);
        assert_eq!(alloy::hex::encode(op.digest()), DIGEST);
        assert_eq!((b58(&op.network), b58(&op.from), b58(&op.to), b58(&op.asset)), (NETWORK.into(), ALICE.into(), BOB.into(), USD.into()));
        assert_eq!((op.amount, op.nonce, op.valid_until), (100, 0, 1000));
        let program = key(PROGRAM).unwrap();
        assert_eq!(b58(&account_of(&program, &op.from)), ALICE_ACCOUNT);
        assert_eq!(b58(&op.contract), ALICE_ACCOUNT);
        assert_eq!(b58(&find_pda(&[b"lane", &op.contract, &op.lane], &program).0), ALICE_LANE_PDA);
        assert_eq!(b58(&ata(&op.to, &op.asset, &k(TOKEN_PROGRAM))), BOB_ATA_USD);
        assert!(on_curve(&op.from) && !on_curve(&op.contract));
    }

    #[test]
    fn signature_blobs_parse() {
        let alice = alloy::hex::encode(key(ALICE).unwrap());
        let a = parse_auth(BLOB_RAW.trim(), &alice).unwrap();
        assert_eq!((a.kind, a.key_index, a.sig.len()), (KIND_RAW, 0, 64));
        // the precompile instruction carries the exact text the wallet signed
        let ix = auth_ix(&a, &alloy::hex::decode(DIGEST).unwrap().try_into().unwrap());
        assert!(ix.data.ends_with(format!("{LABEL}:{DIGEST}").as_bytes()));
        assert_eq!(&ix.data[..2], &[1, 0]);
        assert!(parse_auth(BLOB_RAW.trim(), &alice[..62]).is_err());
        assert!(parse_auth(&format!("05{}", &BLOB_RAW.trim()[2..]), &alice).is_err());
        let mut pk = vec![2u8];
        pk.extend_from_slice(&[7; 32]);
        let mut blob = vec![KIND_PASSKEY, 0];
        blob.extend_from_slice(&[1; 64]);
        blob.extend_from_slice(&37u16.to_le_bytes());
        blob.extend_from_slice(&[5; 37]);
        blob.extend_from_slice(b"{}");
        let p = parse_auth(&alloy::hex::encode(&blob), &alloy::hex::encode(&pk)).unwrap();
        assert_eq!((p.auth_data.len(), p.cdj.as_slice()), (37, &b"{}"[..]));
        let ix = auth_ix(&p, &[0; 32]);
        assert_eq!(ix.program, k(SECP256R1_PROGRAM));
        assert!(ix.data.ends_with(&sha(&[b"{}"])));
    }

    #[test]
    fn tx_v1_matches_solana_kit() {
        let s = lane0();
        let lane: Key = s.public_key().try_into().unwrap();
        let op = MetaOp::decode(&alloy::hex::decode(PAYLOAD.trim()).unwrap()).unwrap();
        let a = parse_auth(BLOB_RAW.trim(), &alloy::hex::encode(op.from)).unwrap();
        let pay = Pay { program: key(PROGRAM).unwrap(), lane, op: &op, auth: &a, token_program: k(TOKEN_PROGRAM), subject_exists: true };
        let ixs = vec![advance_nonce_ix(&nonce_account(&lane), &lane), auth_ix(&a, &op.digest()), relay_pay_ix(&pay)];
        let budget = Budget { priority_lamports: 5_000, cu: 200_000, loaded_bytes: 4 * 1024 * 1024 };
        let (msg, n) = message_v1(&lane, &[0x42; 32], &ixs, &budget).unwrap();
        assert_eq!(n, 1);
        let tx = wire_v1(&msg, &s.sign(&msg).unwrap());
        assert_eq!(alloy::hex::encode(&tx), TX_V1.trim());
        assert!(tx.len() <= 1232, "fits even the legacy packet size: {} bytes", tx.len());
        // the subject is read-only unless this pay opens it
        assert_eq!(relay_pay_ix(&pay).accounts.iter().filter(|a| a.writable).count(), 4);
        let lazy = Pay { subject_exists: false, ..pay };
        assert!(relay_pay_ix(&lazy).accounts[2].writable);
        assert_eq!(&discriminator("global", "relay_pay"), &relay_pay_ix(&lazy).data[..8]);
    }

    /// Review M3: the test program id's key is public (it was in the repo) ⇒ refused on mainnet-beta/devnet/testnet.
    #[test]
    fn the_test_program_id_is_refused_on_public_clusters() {
        let cfg = |network: &str, program: &str| {
            let mut params = toml::Table::new();
            params.insert("program_id".into(), program.into());
            ChainCfg { family: "solana".into(), network: Some(network.into()), rpc_urls: vec!["http://rpc".into()], lanes: vec![0], params, ..Default::default() }
        };
        for net in PUBLIC_GENESIS {
            let e = SolanaAdapter::new(&cfg(net, TEST_PROGRAM_ID), &[lane0()]).err().expect("refused");
            assert!(format!("{e:#}").contains("test-only"), "{e:#}");
            assert!(SolanaAdapter::new(&cfg(net, ALICE), &[lane0()]).is_ok());
        }
        assert!(SolanaAdapter::new(&cfg(NETWORK, TEST_PROGRAM_ID), &[lane0()]).is_ok(), "localnet");
    }

    /// A configured but unparsable `params.relay_fee.router` fails at startup instead of disabling the router.
    #[test]
    fn relay_fee_router_config_must_parse() {
        let cfg = |router: Option<toml::Value>| {
            let mut params = toml::Table::new();
            params.insert("program_id".into(), PROGRAM.into());
            if let Some(r) = router {
                let mut t = toml::Table::new();
                t.insert("router".into(), r);
                params.insert("relay_fee".into(), toml::Value::Table(t));
            }
            ChainCfg { family: "solana".into(), network: Some(NETWORK.into()), rpc_urls: vec!["http://rpc".into()], lanes: vec![0], params, ..Default::default() }
        };
        for bad in [toml::Value::from("not-base58-0OIl"), toml::Value::from(7), toml::Value::from(b58(&[1; 31]))] {
            let e = SolanaAdapter::new(&cfg(Some(bad.clone())), &[lane0()]).err().unwrap_or_else(|| panic!("{bad} accepted"));
            assert!(format!("{e:#}").contains("relay_fee.router"), "{e:#}");
        }
        assert_eq!(RelayFeePolicy::from_cfg(&cfg(Some(PROGRAM.into()))).unwrap().router, Some(key(PROGRAM).unwrap()));
        assert_eq!(RelayFeePolicy::from_cfg(&cfg(None)).unwrap().router, None, "no relay_fee: relay-fee jobs refused");
    }

    #[test]
    fn nonce_account_and_sequence() {
        let lane = key("3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx").unwrap();
        // `solana create-address-with-seed --from <lane> scaas-nonce-v1 11111111111111111111111111111111` (Agave 4.3.0)
        assert_eq!(b58(&nonce_account(&lane)), "6uMgpkiUFY2teooJc1jjCPbXzAFWT2fxVgP4BcmioQVJ");
        // kit `createAddressWithSeed` for the vector lane sha256("lane0")
        let lane0: Key = lane0().public_key().try_into().unwrap();
        assert_eq!(b58(&nonce_account(&lane0)), "4naw8K74hiLb7SSpnVG72VRYJrkgum61Cr6A1nJZV5EX");
        let mut data = vec![0u8; 80];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        data[8..40].copy_from_slice(&lane);
        data[40..72].copy_from_slice(&[0xff; 32]);
        let (v, auth) = parse_nonce(&data).unwrap();
        assert_eq!((auth, nonce_sequence(&v)), (lane, i64::MAX as u64));
        data[4] = 0;
        assert!(parse_nonce(&data).is_err(), "uninitialized");
    }

    #[test]
    fn landed_and_submit_errors_are_classified() {
        assert_eq!(classify_landed(&Value::Null, 9).unwrap(), TxStatus::Mined { height: 9, tx_hash: None });
        let custom = json!({"InstructionError": [2, {"Custom": 6013}]});
        assert!(matches!(classify_landed(&custom, 9).unwrap(), TxStatus::Reverted { .. }));
        let token = json!({"InstructionError": [2, {"Custom": 1}]});
        assert!(matches!(classify_landed(&token, 9).unwrap(), TxStatus::Reverted { .. }), "insufficient funds in the token CPI");
        let cu = json!({"InstructionError": [2, "ComputationalBudgetExceeded"]});
        assert!(classify_landed(&cu, 9).unwrap_err().downcast_ref::<Rejected>().is_some());
        let rent = json!({"InsufficientFundsForRent": {"account_index": 3}});
        assert!(classify_landed(&rent, 9).unwrap_err().downcast_ref::<Rejected>().is_some());
        let nonce = json!({"InstructionError": [0, {"Custom": 0}]});
        assert!(classify_landed(&nonce, 9).unwrap_err().downcast_ref::<Rejected>().is_some());
        let e = |code, msg: &str, data| RpcError { code, message: msg.into(), data };
        let preflight = e(-32002, "Transaction simulation failed: Blockhash not found", json!({"err": "BlockhashNotFound"}));
        assert!(classify_submit(&preflight).unwrap_err().downcast_ref::<Rejected>().is_some());
        let fee = e(-32002, "Transaction simulation failed: Attempt to debit an account but found no record of a prior credit.", json!({"err": "AccountNotFound"}));
        assert!(classify_submit(&fee).unwrap_err().downcast_ref::<Rejected>().is_some());
        assert!(classify_submit(&e(-32002, "x", json!({"err": "AlreadyProcessed"}))).is_ok());
        assert!(classify_submit(&e(-32005, "Node is behind", Value::Null)).unwrap_err().downcast_ref::<Rejected>().is_none());
    }

    fn event(name: &str, body: &[u8]) -> Vec<u8> {
        let mut d = EVENT_IX_TAG.to_vec();
        d.extend_from_slice(&discriminator("event", name));
        d.extend_from_slice(body);
        d
    }

    #[test]
    fn events_of_other_programs_authorities_or_mints_are_dropped() {
        let program = key(PROGRAM).unwrap();
        let usd = key(USD).unwrap();
        let tokens = vec![USD.to_string()];
        let mut settled = usd.to_vec();
        settled.extend_from_slice(&key(ALICE).unwrap());
        settled.extend_from_slice(&key(BOB).unwrap());
        settled.extend_from_slice(&100u64.to_le_bytes());
        settled.extend_from_slice(&[1; 32]);
        let mut exec = usd.to_vec();
        exec.extend_from_slice(&[9; 32]);
        exec.extend_from_slice(&key(ALICE).unwrap());
        exec.extend_from_slice(&[0xd1; 32]);
        exec.extend_from_slice(&[0xa1; 32]);
        exec.extend_from_slice(&0u64.to_le_bytes());
        let ea = b58(&event_authority(&program));
        let copy = "Copy111111111111111111111111111111111111111";
        let tx = |prog_idx: u64, auth_idx: u64, data: &[u8], err: Value| json!({
            "slot": 77, "meta": {"err": err, "innerInstructions": [{"index": 2, "instructions": [
                {"programIdIndex": prog_idx, "accounts": [auth_idx], "data": b58(data)}]}],
                "loadedAddresses": {"writable": [], "readonly": []}},
            "transaction": {"signatures": [b58(&[7; 64])], "message": {"accountKeys": [ALICE, PROGRAM, ea, copy]}}});
        let bh = format!("0x{}", "bb".repeat(32));
        let ok = tx_events(&program, &tokens, &tx(1, 2, &event("PaymentSettled", &settled), Value::Null), &bh).unwrap();
        assert_eq!(ok.len(), 1);
        let e = &ok[0];
        assert_eq!((e["event"].as_str(), e["amount"].as_str(), e["to"].as_str(), e["block_number"].as_u64()), (Some("PaymentSettled"), Some("100"), Some(BOB), Some(77)));
        assert_eq!(e["tx_hash"], json!(format!("0x{}", "07".repeat(64))));
        assert_eq!(e["entry_ref"], json!(format!("0x{}", "01".repeat(32))));
        let x = tx_events(&program, &tokens, &tx(1, 2, &event("MetaTransactionExecuted", &exec), Value::Null), &bh).unwrap();
        assert_eq!((x[0]["digest"].clone(), x[0]["from"].clone()), (json!(format!("0x{}", "d1".repeat(32))), json!(ALICE)));
        assert!(tx_events(&program, &tokens, &tx(3, 2, &event("PaymentSettled", &settled), Value::Null), &bh).unwrap().is_empty(), "copy program");
        assert!(tx_events(&program, &tokens, &tx(1, 0, &event("PaymentSettled", &settled), Value::Null), &bh).unwrap().is_empty(), "not the event authority");
        assert!(tx_events(&program, &[], &tx(1, 2, &event("PaymentSettled", &settled), Value::Null), &bh).unwrap().is_empty(), "unregistered mint");
        assert!(tx_events(&program, &tokens, &tx(1, 2, &event("PaymentSettled", &settled), json!("x")), &bh).unwrap().is_empty(), "failed tx");
        assert!(tx_events(&program, &tokens, &tx(1, 2, &event("PaidUnderMandate", &settled), Value::Null), &bh).unwrap().is_empty(), "Odoo does not ingest it");
    }

    /// Review M1: the deterministic nonce address may already hold lamports (anyone can send them) — creation tops up
    /// to rent, then `AllocateWithSeed` + `InitializeNonceAccount` (no `CreateAccountWithSeed`, which fails on a
    /// funded address).
    #[test]
    fn nonce_creation_survives_a_prefunded_address() {
        let lane = key("3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx").unwrap();
        let nonce = nonce_account(&lane);
        let fresh = create_nonce_ixs(&lane, 1_447_680, 0);
        assert_eq!(fresh.len(), 3);
        assert_eq!(fresh[0].data, [&2u32.to_le_bytes()[..], &1_447_680u64.to_le_bytes()].concat(), "transfer the rent");
        assert_eq!((fresh[0].accounts[0].key, fresh[0].accounts[1].key), (lane, nonce));
        let squatted = create_nonce_ixs(&lane, 1_447_680, 1_000_000);
        assert_eq!(squatted[0].data, [&2u32.to_le_bytes()[..], &447_680u64.to_le_bytes()].concat(), "top up only");
        let rich = create_nonce_ixs(&lane, 1_447_680, 5_000_000);
        assert_eq!(rich.len(), 2, "no transfer");
        let alloc = &rich[0];
        let mut want = 9u32.to_le_bytes().to_vec();
        want.extend_from_slice(&lane);
        want.extend_from_slice(&(NONCE_SEED.len() as u64).to_le_bytes());
        want.extend_from_slice(NONCE_SEED.as_bytes());
        want.extend_from_slice(&NONCE_SPACE.to_le_bytes());
        want.extend_from_slice(&SYSTEM);
        assert_eq!(alloc.data, want);
        assert_eq!(alloc.accounts.iter().map(|a| (a.key, a.signer, a.writable)).collect::<Vec<_>>(), vec![(nonce, false, true), (lane, true, false)]);
        assert_eq!(&rich[1].data[..4], &6u32.to_le_bytes());
    }

    /// Review L3: a lane short of lamports for rent (lane PDA, lazy Account, ATA) is the relayer's problem ⇒ retry; a
    /// program error stays a revert.
    #[test]
    fn simulation_errors_are_classified() {
        let ix1 = json!({"InstructionError": [2, {"Custom": 1}]});
        let logs = |l: &str| vec![l.to_string()];
        assert!(matches!(classify_sim(&ix1, &logs("Transfer: insufficient lamports 5, need 1447680")), SimError::Transport(_)));
        assert!(matches!(classify_sim(&ix1, &logs("Program log: Error: insufficient funds")), SimError::Revert(_)));
        assert!(matches!(classify_sim(&json!({"InstructionError": [2, {"Custom": 6013}]}), &[]), SimError::Revert(_)));
        assert!(matches!(classify_sim(&json!({"InstructionError": [2, "ComputationalBudgetExceeded"]}), &[]), SimError::Transport(_)));
        assert!(matches!(classify_sim(&json!({"InstructionError": [0, {"Custom": 1}]}), &[]), SimError::Transport(_)));
        assert!(matches!(classify_sim(&json!("BlockhashNotFound"), &[]), SimError::Transport(_)));
    }

    /// Fake JSON-RPC: `getSignaturesForAddress` serves SHORT pages (a provider capping `limit`); records every
    /// `getTransaction`.
    async fn fake_rpc(fetched: Arc<Mutex<Vec<String>>>) -> String {
        use axum::extract::State;
        use axum::Json;
        fn sig(i: u8) -> String {
            b58(&[i; 64])
        }
        async fn h(State(f): State<Arc<Mutex<Vec<String>>>>, Json(b): Json<Value>) -> Json<Value> {
            let p = &b["params"];
            let r = match b["method"].as_str().unwrap_or_default() {
                "getSignaturesForAddress" => match p[1]["before"].as_str() {
                    None => json!([{"slot": 90, "signature": sig(1), "err": null}, {"slot": 80, "signature": sig(2), "err": null}]),
                    Some(s) if s == sig(2) => json!([{"slot": 60, "signature": sig(3), "err": null}]),
                    Some(s) if s == sig(3) => json!([{"slot": 5, "signature": sig(4), "err": null}]),
                    _ => json!([]),
                },
                "getTransaction" => {
                    let s = p[0].as_str().unwrap().to_string();
                    f.lock().unwrap().push(s.clone());
                    json!({"slot": 1, "meta": {"err": null, "innerInstructions": []}, "transaction": {"signatures": [s], "message": {"accountKeys": []}}})
                }
                "getBlock" => json!({"blockhash": b58(&[2; 32])}),
                "getFirstAvailableBlock" => json!(0),
                m => panic!("unexpected {m}"),
            };
            Json(json!({"jsonrpc": "2.0", "id": 1, "result": r}))
        }
        let app = axum::Router::new().route("/", axum::routing::post(h)).with_state(fetched);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        url
    }

    /// Review L2: a short page is not the end of history (paging goes on until an empty page or `from`); L1: Odoo
    /// tokens that all fail to parse are an error, so the cursor never moves past real events.
    #[tokio::test]
    async fn events_page_past_short_pages_and_refuse_unparsable_tokens() {
        let fetched = Arc::new(Mutex::new(Vec::new()));
        let url = fake_rpc(fetched.clone()).await;
        let mut params = toml::Table::new();
        params.insert("program_id".into(), PROGRAM.into());
        let cfg = ChainCfg { family: "solana".into(), network: Some(NETWORK.into()), rpc_urls: vec![url], lanes: vec![0], params, ..Default::default() };
        let a = SolanaAdapter::new(&cfg, &[lane0()]).unwrap();
        assert!(a.events(10, 100, &[USD.into()]).await.unwrap().is_empty());
        assert_eq!(*fetched.lock().unwrap(), vec![b58(&[3; 64]), b58(&[2; 64]), b58(&[1; 64])], "slot 60 is on the second page");
        assert!(a.events(10, 100, &["0xnot-a-mint".into()]).await.is_err());
        assert!(a.events(10, 100, &[]).await.unwrap().is_empty(), "no tokens at all: index_step holds the cursor");
    }

    // CTR-MTX-26 / -27 vectors: `smartcontracts/vectors/metatx/paymeta.json` and `programs/scaas/tests/vectors.rs`
    // (`gen_vectors.py` `relay_fee_vectors`); the marker and the two instruction-data hashes are pinned in the program's
    // `tests/relay_fee.rs` too.
    const MARKER: &str = "9wtnhXbQazahGQXbNLD5ZAERPfzmvFvC2mYwCRjPvT5t";
    const RELAY_TARGET: &str = "12aa1ee86dd9304ebc6d74d59ce7aa3f39c4dfb3eb23207660b3a064020850bf";
    const RELAY_RECORD: &str = "259e0907108fa85c5ec686c434c500dc7f11e4240918e532c17d4ee1e7148639";
    const RELAY_DATA: &str = "0068656c6c6f";
    const RELAY_SALT: &str = "0909090909090909090909090909090909090909090909090909090909090909";
    const RELAY_CALL: &str = "12aa1ee86dd9304ebc6d74d59ce7aa3f39c4dfb3eb23207660b3a064020850bf01259e0907108fa85c5ec686c434c500dc7f11e4240918e532c17d4ee1e714863900010068656c6c6f";
    const RELAY_REF: &str = "249ae7174454dace542a9cb3b1454ec743234ff0909d8e6d4fc3f3d6f8870e9d";
    const RELAY_LANE: &str = "b639636317daa6c63d022351faeede402f3e4e5c23e2fa1e9e1ab196519f644b";
    /// sha256 of the `relay_pay_meta` / `relay_fee` instruction data of the vectors below (Anchor Borsh in the program test).
    const PAY_META_IX_SHA: &str = "ba205082adb76c44a6f3937e80ab6d9686d99756e0423ddb071425ed25fd3e15";
    const RELAY_FEE_IX_SHA: &str = "d33e8ca18314c4cda621124ad04b154060820f1b8acf66b78fcca807e09b216b";

    // Static wrapper vector (`gen_vectors.py` `relay_fee_vectors`, program `tests/wrappers.rs::wrapper_ref_vectors`):
    // `relay_fee_invalidate_nonces_signed`, accounts sha256("wrap.<name>"), min_nonce 5, salt 0a…, Alice pays 100.
    const WRAP_CALL: &str = "97dbf6298ebc1d1aba6fe95a3c688f723fbd62ea8fe24fcd18b1de8988fea4c4075421fcfb0116acc6327ccb1a03e80acb59de8e0dc23a91857ffb493c3ac2cf1a0101771dba68087aff89d4f5d15ae879d0fc21bb8be436e410e23088eaad848b04b9000039c966052a231ee909b683aee751e3cd5a60ddb9f0e56167480bb8978592c4e70000611912e7fb9a7a8a5412cd08609e81305463b363388d8e8d527ff784c6ebf014000080eeb8c3aa7062d37e68479374cec72a820f5eaca1d965544940eee9923bab27000106a7d517187bd16635dad40455fdc2c0c124c68f215675a5dbbacb5f0800000000000000000000000000000000000000000000000000000000000000000000000000000055751035c3cffac805000000000000000000020000000000";
    const WRAP_REF: &str = "8f1fffe61e9b7a2bfd7dbc279dad559bd7b0e445e93a2e7882f9de5c3150d335";
    const WRAP_LANE: &str = "807d560fabea55637473a58d62124ccb5ad7383eae5f3d87b266710dbc79ccb9";
    const WRAP_SALT: &str = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";
    const WRAP_IX_SHA: &str = "faea8705feee1d86cc00e788f905bdeb1e107dc612d3496615c80dffdaa4a033";

    fn meta_rows() -> Vec<Value> {
        serde_json::from_str(include_str!("../../../smartcontracts/vectors/metatx/paymeta.json")).unwrap()
    }

    fn h(v: &Value) -> Vec<u8> {
        alloy::hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
    }

    fn k32(s: &str) -> Key {
        alloy::hex::decode(s).unwrap().try_into().unwrap()
    }

    fn vector_op() -> MetaOp {
        MetaOp::decode(&alloy::hex::decode(PAYLOAD.trim()).unwrap()).unwrap()
    }

    fn lane0_key() -> Key {
        lane0().public_key().try_into().unwrap()
    }

    /// Alice pays Bob 100 USD under row 0 of `paymeta.json`: `pay_ref = payId`, `lane = payLane(payId)`.
    fn meta_op() -> (MetaOp, Value) {
        let r = meta_rows()[0].clone();
        let mut op = vector_op();
        op.pay_ref = h(&r["payId"]).try_into().unwrap();
        op.lane = h(&r["payLane"]).try_into().unwrap();
        (op, json!({"kind": "pay_meta", "salt": r["salt"], "meta": r["meta"]}))
    }

    #[test]
    fn solana_pay_meta_job_builds_ix() {
        let (program, network, lane) = (key(PROGRAM).unwrap(), key(NETWORK).unwrap(), lane0_key());
        for r in meta_rows() {
            assert_eq!(meta_pay_id(&h(&r["salt"]), &h(&r["meta"])).to_vec(), h(&r["payId"]), "{}", r["name"]);
            assert_eq!(pay_lane(&h(&r["payId"]).try_into().unwrap()).to_vec(), h(&r["payLane"]), "{}", r["name"]);
        }
        let pol = RelayFeePolicy::default();
        let (op, job) = meta_op();
        let e = entry(&program, &network, &lane, &pol, &op, &job).unwrap();
        assert_eq!(e, Entry::PayMeta { salt: h(&job["salt"]).try_into().unwrap(), meta: h(&job["meta"]) });
        let a = parse_auth(BLOB_RAW.trim(), &alloy::hex::encode(op.from)).unwrap();
        let pay = Pay { program, lane, op: &op, auth: &a, token_program: k(TOKEN_PROGRAM), subject_exists: true };
        let ix = pay_ix(&pay, &e);
        assert_eq!(&ix.data[..8], &discriminator("global", "relay_pay_meta"));
        assert_eq!(ix.accounts, relay_pay_ix(&pay).accounts, "the same accounts as relay_pay");
        assert_eq!(alloy::hex::encode(sha(&[&ix.data])), PAY_META_IX_SHA, "the program's Borsh encoding");
        let bad = |op: &MetaOp, job: &Value| entry(&program, &network, &lane, &pol, op, job).is_err();
        let mut j = job.clone();
        j["meta"] = json!(format!("{}00", job["meta"].as_str().unwrap()));
        assert!(bad(&op, &j), "meta does not hash to pay_ref");
        let mut j = job.clone();
        j["salt"] = json!(format!("0x{}", "00".repeat(32)));
        assert!(bad(&op, &j), "another salt");
        let mut o = op.clone();
        o.lane = [0xa1; 32];
        assert!(bad(&o, &job), "lane is not payLane(pay_ref)");
        let mut o = op.clone();
        o.nonce = 1;
        assert!(bad(&o, &job), "nonce is not 0");
        let big = vec![7u8; MAX_PAY_META_BYTES + 1];
        let mut o = op.clone();
        o.pay_ref = meta_pay_id(&[1; 32], &big);
        o.lane = pay_lane(&o.pay_ref);
        assert!(bad(&o, &json!({"kind": "pay_meta", "salt": alloy::hex::encode([1; 32]), "meta": alloy::hex::encode(&big)})), "over the cap");
        assert!(bad(&op, &json!({"kind": "pay_meta", "meta": job["meta"]})), "no salt");
        // the node's cap fits a v1 transaction (nonce advance, precompile, a lazily opened Account)
        let cap = Entry::PayMeta { salt: [1; 32], meta: vec![7; MAX_PAY_META_BYTES] };
        let lazy = Pay { subject_exists: false, ..pay };
        let ixs = vec![advance_nonce_ix(&nonce_account(&lane), &lane), auth_ix(&a, &op.digest()), pay_ix(&lazy, &cap)];
        let budget = Budget { priority_lamports: 0, cu: 200_000, loaded_bytes: 4 * 1024 * 1024 };
        assert!(message_v1(&lane, &[0x42; 32], &ixs, &budget).is_ok(), "2,048 B of meta in one v1 transaction");
        assert_eq!(entry(&program, &network, &lane, &pol, &op, &json!({})).unwrap(), Entry::Pay, "a job without kind is a plain pay");
    }

    fn fee_policy(op: &MetaOp) -> RelayFeePolicy {
        RelayFeePolicy { router: Some(key(PROGRAM).unwrap()), tokens: vec![op.asset], min_amount: 100 }
    }

    /// Alice pays 100 USD for the vector call (`relay_target`, record writable, data `00 "hello"`, salt 09…), open mode.
    fn fee_op() -> (MetaOp, Value) {
        let marker = relay_fee_marker(&key(PROGRAM).unwrap());
        let mut op = vector_op();
        op.to = marker;
        op.pay_ref = k32(RELAY_REF);
        op.lane = k32(RELAY_LANE);
        op.relayer = marker;
        op.extra = k32(RELAY_SALT);
        let job = json!({"kind": "relay_fee", "ref": format!("0x{RELAY_REF}"), "extra": {
            "target": b58(&k32(RELAY_TARGET)), "target_data": RELAY_DATA,
            "target_accounts": [{"pubkey": b58(&k32(RELAY_RECORD)), "is_signer": false, "is_writable": true}]}});
        (op, job)
    }

    #[test]
    fn solana_relay_fee_job_checks_ref() {
        let (program, network, lane) = (key(PROGRAM).unwrap(), key(NETWORK).unwrap(), lane0_key());
        let marker = relay_fee_marker(&program);
        assert_eq!(b58(&marker), MARKER, "the program's Pubkey::find_program_address([b\"relayfee\"])");
        let (target, record) = (k32(RELAY_TARGET), k32(RELAY_RECORD));
        let call = relay_call(&target, &[m(record, false, true)], &alloy::hex::decode(RELAY_DATA).unwrap());
        assert_eq!(alloy::hex::encode(&call), RELAY_CALL);
        let r = relay_ref(&network, &target, &call, &k32(RELAY_SALT));
        assert_eq!((alloy::hex::encode(r), alloy::hex::encode(pay_lane(&r))), (RELAY_REF.into(), RELAY_LANE.into()));
        assert_ne!(relay_ref(&network, &target, &call, &[8; 32]), r, "the salt is in the ref");

        let (op, job) = fee_op();
        let pol = fee_policy(&op);
        let e = entry(&program, &network, &lane, &pol, &op, &job).unwrap();
        let Entry::Fee { recipient, .. } = &e else { panic!("{e:?}") };
        assert_eq!(*recipient, lane, "open mode pays the lane");
        let a = parse_auth(BLOB_RAW.trim(), &alloy::hex::encode(op.from)).unwrap();
        let pay = Pay { program, lane, op: &op, auth: &a, token_program: k(TOKEN_PROGRAM), subject_exists: true };
        let ix = pay_ix(&pay, &e);
        assert_eq!(&ix.data[..8], &discriminator("global", "relay_fee"));
        assert_eq!(alloy::hex::encode(sha(&[&ix.data])), RELAY_FEE_IX_SHA, "the program's Borsh encoding");
        assert_eq!(ix.accounts.len(), 16);
        assert_eq!((ix.accounts[5].key, ix.accounts[6].key), (lane, ata(&lane, &op.asset, &k(TOKEN_PROGRAM))));
        assert_eq!((&ix.accounts[14], &ix.accounts[15]), (&m(target, false, false), &m(record, false, true)));
        // bound payee: the recipient is `to`
        let mut bound = op.clone();
        bound.to = key(BOB).unwrap();
        let Entry::Fee { recipient, .. } = entry(&program, &network, &lane, &pol, &bound, &job).unwrap() else { panic!() };
        assert_eq!(recipient, key(BOB).unwrap());

        let err = |op: &MetaOp, job: &Value, pol: &RelayFeePolicy| format!("{:#}", entry(&program, &network, &lane, pol, op, job).unwrap_err());
        // policy (rule 8): router, registered token, minimum fee
        assert!(err(&op, &job, &RelayFeePolicy { router: None, ..pol.clone() }).contains("router"));
        assert!(err(&op, &job, &RelayFeePolicy { router: Some(lane), ..pol.clone() }).contains("router"));
        assert!(err(&op, &job, &RelayFeePolicy { tokens: vec![], ..pol.clone() }).contains("registered"));
        assert!(err(&op, &job, &RelayFeePolicy { min_amount: 101, ..pol.clone() }).contains("min_amount"));
        // the lane never lends its signature to the target
        let mut j = job.clone();
        j["extra"]["target_accounts"][0]["is_signer"] = json!(true);
        assert!(err(&op, &j, &pol).contains("signer"));
        // the lane itself among the target accounts (even unsigned): refused with its own message
        let mut j = job.clone();
        j["extra"]["target_accounts"][0]["pubkey"] = json!(b58(&lane));
        assert!(err(&op, &j, &pol).contains("this lane"));
        let mut j = job.clone();
        j["extra"]["target"] = json!(PROGRAM);
        assert!(err(&op, &j, &pol).contains("scaas program"));
        // the payment commits to exactly this call
        let mut j = job.clone();
        j["extra"]["target_data"] = json!("0068656c6c70");
        assert!(err(&op, &j, &pol).contains("not bound"), "other data");
        let mut j = job.clone();
        j["extra"]["target_accounts"][0]["is_writable"] = json!(false);
        assert!(err(&op, &j, &pol).contains("not bound"), "other flags");
        for f in [|o: &mut MetaOp| o.extra = [8; 32], |o: &mut MetaOp| o.lane = [0xa1; 32], |o: &mut MetaOp| o.nonce = 1,
                  |o: &mut MetaOp| o.relayer = [0; 32]] {
            let mut o = op.clone();
            f(&mut o);
            assert!(err(&o, &job, &pol).contains("not bound"));
        }
        let mut o = op.clone();
        o.relayer = lane;
        assert!(err(&o, &job, &pol).contains("not bound"), "relayer = lane");
        let mut j = job.clone();
        j["ref"] = json!(format!("0x{}", "11".repeat(32)));
        assert!(err(&op, &j, &pol).contains("op.ref"));
        let mut j = job.clone();
        j["extra"]["target_accounts"] = json!("x");
        assert!(entry(&program, &network, &lane, &pol, &op, &j).is_err());
    }

    fn wk(name: &str) -> Key {
        sha(&[name.as_bytes()])
    }

    /// The vector wrapper job: lane = sha256("wrap.lane"), the inner entry's declared accounts and data, its signature.
    fn wrap_job() -> (MetaOp, Value, Key) {
        let program = key(PROGRAM).unwrap();
        let marker = relay_fee_marker(&program);
        let mut op = vector_op();
        op.to = marker;
        op.pay_ref = k32(WRAP_REF);
        op.lane = k32(WRAP_LANE);
        op.relayer = marker;
        op.extra = k32(WRAP_SALT);
        let acct = |k: Key, s: bool, w: bool| json!({"pubkey": b58(&k), "is_signer": s, "is_writable": w});
        let mut data = discriminator("global", "invalidate_nonces_signed").to_vec();
        data.extend_from_slice(&5u64.to_le_bytes());
        data.extend_from_slice(&[0, 0, 2, 0, 0, 0, 0, 0]);
        let job = json!({"kind": "relay_fee", "ref": format!("0x{WRAP_REF}"), "extra": {
            "entry": "invalidate_nonces_signed", "inner_data": alloy::hex::encode(&data),
            "inner_accounts": [acct(wk("wrap.lane"), true, true), acct(wk("wrap.config"), false, false), acct(wk("wrap.market"), false, false),
                               acct(wk("wrap.subject"), false, false), acct(wk("wrap.min_nonce"), false, true),
                               acct(k(INSTRUCTIONS_SYSVAR), false, false), acct(SYSTEM, false, false)],
            "inner_sig": {"program": "ed25519", "public_key": alloy::hex::encode([7u8; 32]), "signature": "ab".repeat(64), "message": "00".repeat(80)}}});
        (op, job, wk("wrap.lane"))
    }

    #[test]
    fn solana_relay_fee_wrapper_job_builds_ix() {
        let (program, network) = (key(PROGRAM).unwrap(), key(NETWORK).unwrap());
        let (op, job, lane) = wrap_job();
        let pol = fee_policy(&op);
        let e = entry(&program, &network, &lane, &pol, &op, &job).unwrap();
        let Entry::Wrapped { accounts, rest, recipient, sig, .. } = &e else { panic!("{e:?}") };
        assert!(rest.is_empty());
        assert_eq!(*recipient, lane, "open mode pays the lane");
        let call = relay_call(&program, accounts, &hex_field(&job["extra"]["inner_data"], "d").unwrap());
        assert_eq!(alloy::hex::encode(&call), WRAP_CALL);
        assert_eq!(alloy::hex::encode(relay_ref(&network, &program, &call, &k32(WRAP_SALT))), WRAP_REF);
        assert_eq!(sig.program, k(ED25519_PROGRAM));
        let a = parse_auth(BLOB_RAW.trim(), &alloy::hex::encode(op.from)).unwrap();
        let pay = Pay { program, lane, op: &op, auth: &a, token_program: k(TOKEN_PROGRAM), subject_exists: true };
        let ix = pay_ix(&pay, &e);
        assert_eq!(&ix.data[..8], &discriminator("global", "relay_fee_invalidate_nonces_signed"));
        assert_eq!(alloy::hex::encode(sha(&[&ix.data])), WRAP_IX_SHA, "the program's Borsh encoding");
        assert_eq!(ix.accounts.len(), 7 + 14);
        assert_eq!((ix.accounts[0].key, ix.accounts[7].key, ix.accounts[7 + 5].key), (lane, lane, lane));
        // the whole transaction: nonce advance, the payer's precompile (1), the inner signature (2), the wrapper
        let ixs = vec![advance_nonce_ix(&nonce_account(&lane), &lane), auth_ix(&a, &op.digest()), sig.clone(), ix];
        let budget = Budget { priority_lamports: 0, cu: 200_000, loaded_bytes: 4 * 1024 * 1024 };
        assert!(message_v1(&lane, &[0x42; 32], &ixs, &budget).is_ok());

        let err = |op: &MetaOp, job: &Value| format!("{:#}", entry(&program, &network, &lane, &pol, op, job).unwrap_err());
        let set = |f: &dyn Fn(&mut Value)| {
            let mut j = job.clone();
            f(&mut j);
            j
        };
        assert!(err(&op, &set(&|j| j["extra"]["entry"] = json!("relay_pay"))).contains("wrapped entry"));
        assert!(err(&op, &set(&|j| j["extra"]["entry"] = json!("cancel_signed"))).contains("not a cancel_signed"));
        assert!(err(&op, &job_with_lane_unsigned()).contains("first account"));
        assert!(err(&op, &set(&|j| j["extra"]["inner_accounts"][3]["is_signer"] = json!(true))).contains("only the lane"));
        assert!(err(&op, &set(&|j| j["extra"]["inner_remaining"] = json!([{"pubkey": b58(&[3; 32]), "is_signer": true, "is_writable": false}]))).contains("only the lane"));
        assert!(err(&op, &set(&|j| j["extra"]["inner_accounts"][4]["is_writable"] = json!(false))).contains("not bound"));
        let longer = set(&|j| j["extra"]["inner_data"] = json!(format!("{}06", j["extra"]["inner_data"].as_str().unwrap())));
        assert!(err(&op, &longer).contains("not bound"));
        assert!(err(&op, &set(&|j| j["extra"]["inner_sig"]["program"] = json!("secp256k1"))).contains("inner_sig"));
        assert!(err(&op, &set(&|j| j["extra"]["inner_sig"]["signature"] = json!("ab"))).contains("inner_sig"));
        for f in [|o: &mut MetaOp| o.extra = [8; 32], |o: &mut MetaOp| o.nonce = 1, |o: &mut MetaOp| o.relayer = [0; 32]] {
            let mut o = op.clone();
            f(&mut o);
            assert!(err(&o, &job).contains("not bound"));
        }
        // a lane other than the inner entry's
        assert!(entry(&program, &network, &key(BOB).unwrap(), &pol, &op, &job).is_err());
        // the policy applies to wrappers too
        assert!(entry(&program, &network, &lane, &RelayFeePolicy { min_amount: 101, ..pol.clone() }, &op, &job).is_err());
    }

    fn job_with_lane_unsigned() -> Value {
        let (_, mut j, _) = wrap_job();
        j["extra"]["inner_accounts"][0]["is_signer"] = json!(false);
        j
    }

    proptest! {
        /// The wrapper job decoder never panics (any entry name, data, accounts, signature).
        #[test]
        fn wrapper_jobs_never_panic(entry_ix in 0..8usize, data in "[0-9a-f]{0,120}", n in 0..20usize, flag in any::<bool>(),
                                    pkey in ".{0,50}", sig in "[0-9a-f]{0,200}", prog in 0..3usize, bytes in proptest::collection::vec(any::<u8>(), 32)) {
            let (program, network) = (key(PROGRAM).unwrap(), key(NETWORK).unwrap());
            let (mut op, mut job, lane) = wrap_job();
            op.extra = bytes[..32].try_into().unwrap();
            let names = ["manage_signed", "mandate_open", "mandate_revoke_signed", "mandate_close_signed", "cancel_signed",
                         "invalidate_nonces_signed", "relay_pay", ""];
            job["extra"]["entry"] = json!(names[entry_ix]);
            job["extra"]["inner_data"] = json!(data);
            let acct = json!({"pubkey": pkey, "is_signer": flag, "is_writable": flag});
            if n % 2 == 0 {
                job["extra"]["inner_accounts"] = json!(vec![acct.clone(); n]);
            }
            job["extra"]["inner_remaining"] = json!(vec![acct; n / 3]);
            job["extra"]["inner_sig"] = json!({"program": (["ed25519", "secp256r1", "x"][prog]), "public_key": sig, "signature": sig, "message": sig});
            if let Ok(e) = entry(&program, &network, &lane, &fee_policy(&op), &op, &job) {
                let a = parse_auth(BLOB_RAW.trim(), &alloy::hex::encode(op.from)).unwrap();
                let _ = pay_ix(&Pay { program, lane, op: &op, auth: &a, token_program: k(TOKEN_PROGRAM), subject_exists: true }, &e);
            }
        }
    }

    proptest! {
        #[test]
        fn decoders_never_panic(b in proptest::collection::vec(any::<u8>(), 0..400), s in ".{0,300}", k in ".{0,140}") {
            let _ = MetaOp::decode(&b);
            let _ = parse_auth(&s, &k);
            let _ = parse_auth(&alloy::hex::encode(&b), &k);
            let _ = parse_auth(&alloy::hex::encode(&b), &alloy::hex::encode(&b[..b.len().min(33)]));
            let _ = parse_nonce(&b);
            let _ = normalize(&b, &[], 0, "", "", 0);
            let _ = key(&s);
        }

        /// Rule 8: no panic on untrusted pay-meta / relay-fee jobs (any JSON shape, any field bytes).
        #[test]
        fn jobs_never_panic_on_untrusted_input(kind in 0..3usize, salt in ".{0,80}", meta in "[0-9a-f]{0,300}", target in ".{0,60}",
                                               data in "[0-9a-fx]{0,120}", n in 0..300usize, flag in 0..3u8, pkey in ".{0,60}",
                                               ref_ in ".{0,70}", bytes in proptest::collection::vec(any::<u8>(), 96)) {
            let (program, network, lane) = (key(PROGRAM).unwrap(), key(NETWORK).unwrap(), lane0_key());
            let (mut op, _) = fee_op();
            op.pay_ref = bytes[..32].try_into().unwrap();
            op.extra = bytes[32..64].try_into().unwrap();
            op.to = bytes[64..].try_into().unwrap();
            let kinds = ["pay_meta", "relay_fee", "other"];
            let fl = [json!(true), json!(false), json!("no")][flag as usize].clone();
            let acct = json!({"pubkey": pkey, "is_signer": fl, "is_writable": fl});
            let job = json!({"kind": kinds[kind], "salt": salt, "meta": meta, "ref": ref_,
                             "extra": {"target": target, "target_data": data, "target_accounts": vec![acct; n]}});
            let pol = fee_policy(&op);
            if let Ok(e) = entry(&program, &network, &lane, &pol, &op, &job) {
                let a = parse_auth(BLOB_RAW.trim(), &alloy::hex::encode(op.from)).unwrap();
                let _ = pay_ix(&Pay { program, lane, op: &op, auth: &a, token_program: k(TOKEN_PROGRAM), subject_exists: false }, &e);
            }
            // the good relay job with one field of the op mutated
            let (mut op, job) = fee_op();
            op.extra[n % 32] ^= bytes[0] | 1;
            prop_assert!(entry(&program, &network, &lane, &pol, &op, &job).is_err());
        }

        #[test]
        fn payload_round_trips(amount in any::<u128>(), nonce in any::<u64>(), vu in any::<u64>(), op in any::<u8>()) {
            let mut m = MetaOp::decode(&alloy::hex::decode(PAYLOAD.trim()).unwrap()).unwrap();
            m.amount = amount;
            m.nonce = nonce;
            m.valid_until = vu;
            m.op = op;
            prop_assert_eq!(MetaOp::decode(&m.encode()).unwrap(), m);
        }
    }
}
