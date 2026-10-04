//! Solana (S12; thiết kế `docs/superpowers/specs/2026-10-04-net-solana.md` §6). Job `signed_op` mang `MetaOp` v1
//! (337 byte) + blob chữ ký `kind ‖ key_index ‖ sig64 ‖ [u16le n ‖ authData ‖ cdj]` + khoá công khai. Lane = khoá
//! ed25519 `m/44'/501'/{i}'/0'` của relayer, làm fee payer; thứ tự mỗi lane = durable nonce account
//! `create_with_seed(lane, "bamboo-nonce-v1", System)` (RS12-14): `sequence` = 8 byte đầu giá trị nonce, một tx bay.
//! Tx v1 (SIMD-0385) dựng TẠI ĐÂY, không crate `solana-sdk` (RS12-15): `AdvanceNonceAccount` ‖ precompile
//! Ed25519/Secp256r1 dựng từ blob ‖ `bamboo::relay_pay`. Event đọc qua JSON-RPC chuẩn (`getSignaturesForAddress` +
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
const DOMAIN: &[u8] = b"bamboo.metaop.v1";
const LABEL: &str = "bamboo.metaop.v1";
const OP_PAY: u8 = 0;
const KIND_RAW: u8 = 0;
const KIND_OCMS: u8 = 1;
const KIND_PASSKEY: u8 = 2;
const NONCE_SEED: &str = "bamboo-nonce-v1";
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
    pub const LEN: usize = 337;

    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != Self::LEN || &b[..16] != DOMAIN {
            bail!("not a bamboo.metaop.v1 payload");
        }
        let k32 = |o: usize| -> Key { b[o..o + 32].try_into().unwrap() };
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        Ok(Self {
            network: k32(16),
            contract: k32(48),
            asset: k32(80),
            op: b[112],
            from: k32(113),
            to: k32(145),
            amount: u128::from_le_bytes(b[177..193].try_into().unwrap()),
            pay_ref: k32(193),
            lane: k32(225),
            nonce: u64_at(257),
            valid_until: u64_at(265),
            relayer: k32(273),
            extra: k32(305),
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

/// Mọi tham số của một `relay_pay` (instruction thứ 2 sau precompile ở chỉ số 1).
pub struct Pay<'a> {
    pub program: Key,
    pub lane: Key,
    pub op: &'a MetaOp,
    pub auth: &'a Auth,
    pub token_program: Key,
    pub subject_exists: bool,
}

pub fn relay_pay_ix(p: &Pay) -> Ix {
    let (op, a) = (p.op, p.auth);
    let subject = account_of(&p.program, &op.from);
    let mut data = discriminator("global", "relay_pay").to_vec();
    data.extend_from_slice(&op.from);
    data.extend_from_slice(&op.to);
    data.extend_from_slice(&(op.amount as u64).to_le_bytes());
    data.extend_from_slice(&op.pay_ref);
    data.extend_from_slice(&op.lane);
    data.extend_from_slice(&op.nonce.to_le_bytes());
    data.extend_from_slice(&op.valid_until.to_le_bytes());
    data.extend_from_slice(&op.relayer);
    data.extend_from_slice(&op.extra);
    data.extend_from_slice(&[a.kind, a.key_index, 1, 0]);
    data.extend_from_slice(&(a.cdj.len() as u32).to_le_bytes());
    data.extend_from_slice(&a.cdj);
    let accounts = vec![
        m(p.lane, true, true),
        m(find_pda(&[b"config"], &p.program).0, false, false),
        // RS12-2: readonly unless this pay opens the Account lazily.
        m(subject, false, !p.subject_exists),
        m(find_pda(&[b"lane", &subject, &op.lane], &p.program).0, false, true),
        m(ata(&subject, &op.asset, &p.token_program), false, true),
        m(op.to, false, false),
        m(ata(&op.to, &op.asset, &p.token_program), false, true),
        m(op.asset, false, false),
        m(p.token_program, false, false),
        m(k(ATA_PROGRAM), false, false),
        m(SYSTEM, false, false),
        m(k(INSTRUCTIONS_SYSVAR), false, false),
        m(event_authority(&p.program), false, false),
        m(p.program, false, false),
    ];
    Ix { program: p.program, accounts, data }
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

/// Lỗi tx đã VÀO SỔ (meta.err): lỗi của precompile/`bamboo` (chỉ số ≥ 1) ⇒ `Reverted`; hết CU, lỗi ở advance nonce,
/// lỗi cấp tx ⇒ `Rejected` (mọi thay đổi đã rollback trừ phí + nonce lane; lane PDA người trả còn nguyên ⇒ dựng lại).
pub fn classify_landed(err: &Value, slot: u64) -> Result<TxStatus> {
    if err.is_null() {
        return Ok(TxStatus::Mined { height: slot });
    }
    match instruction_error(err) {
        Some((_, e)) if BUDGET_ERRORS.contains(&err_name(e).as_str()) => Err(Rejected(err.to_string()).into()),
        Some((i, _)) if i >= 1 => Ok(TxStatus::Reverted { reason: err.to_string() }),
        _ => Err(Rejected(err.to_string()).into()),
    }
}

/// Lỗi mô phỏng: lỗi ở precompile/`bamboo` (chỉ số ≥ 1) ⇒ `Revert` (job chết); hết CU, lỗi cấp tx, và lane thiếu
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
            bail!("solana: {TEST_PROGRAM_ID} is the test-only program id (its key is public); deploy your own (chains/solana/scripts/deploy.sh)");
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

    /// Dựng + mô phỏng (`sigVerify:false`, nonce thật). Lỗi ở precompile/`bamboo` ⇒ `Revert` (job chết); còn lại
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
        let pay = Pay { program: self.program, lane: lk, op: &w.op, auth: &w.auth, token_program: w.token_program, subject_exists };
        let ixs = vec![auth_ix(&w.auth, &w.op.digest()), relay_pay_ix(&pay)];
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

    // Vector chéo — cùng giá trị ở chains/solana/programs/bamboo/tests/vectors.rs và dms_blockchain/tests/test_fam_solana.py.
    const PROGRAM: &str = "BDo6exf1vzqX44BJc1WDf4Pw6sGZcxqmuVmQPfgUgS3d";
    const NETWORK: &str = "9Bjy32z5orwpyvcJehikjj76VQtVLtc7WdCmTyN3FsWY";
    const ALICE: &str = "FPP21sbqhr2LPjSnJkw5NBetPubeFG4PsQFBxHj8noTq";
    const BOB: &str = "GwCXyJ8AesaucFMTUSZmiFVMhVngpeBxaBC7mQJiZct3";
    const USD: &str = "E5XS6w9DtMRaPTk38iGhD3iSwDJzYUNkKtmUqEpNpUsf";
    const ALICE_ACCOUNT: &str = "Cpdv3d1ppikVEJVQmEoT6ATWaChLS59Raxg5DfCdpHjv";
    const ALICE_LANE_PDA: &str = "E6Zuj4rbZwGu1Qk6sQUtba4TFhotWRtf56p9ZmrRNRs6";
    const BOB_ATA_USD: &str = "4cNKNsfY1HwhsqcMWgQ7bu7pLpGgg5xUsX5eaQbguvLM";
    const DIGEST: &str = "8c2886f0dc1cb1e4a1397ae40e940913961b041c6c36b3e882c1cd016ed08cd3";
    const PAYLOAD: &str = concat!(
        "62616d626f6f2e6d6574616f702e7631799de2ace2cd00af66fcc120fa522604d115bf9af9c6fb2780d6594260fdb729afa497f9db8f42",
        "d70fb0ef45b544030815b53b0ec8812ced192f3f6df4d896f1c250a9ebc1dc2e6299d0873da3edfd78261d872701b4dc7ad557d9eabe3b",
        "ce8e00d5bf4a3fcce717b0388bcc2749ebc148ad9969b23f45ee1b605fd58778576ac4ecc1b58727f3f12b3194881a9ecb9de0b28ce7b2",
        "07230d8e930fe1bce75e256c64000000000000000000000000000000010101010101010101010101010101010101010101010101010101",
        "0101010101a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10000000000000000e8030000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000",
    );
    const BLOB_RAW: &str = concat!(
        "00008278a07e2a5e0c47ab6b2c9e0287af6c9eedf30159108af21c66884b0a763f313fa1a4638e1b04d99085479a7238521f58a99ea303",
        "3b7a0a8f9bc9edeb1f9d08",
    );
    // @solana/kit 8.4.0 (`chains/solana/scripts/tx_vector.mjs`): lane = ed25519 seed sha256("lane0"), nonce value 0x42…,
    // instructions AdvanceNonceAccount ‖ Ed25519 precompile ‖ bamboo::relay_pay of the vector payload, CU 200 000,
    // priority 5 000 lamports, loaded bytes 4 MiB.
    const TX_V1: &str = concat!(
        "8101000c0f00000042424242424242424242424242424242424242424242424242424242424242420311ab514c44076f6416bc2fb0742e",
        "e1823e7054395b513aa382709794d04a208e3f34573d30e56dc74a547e22b1e668d586d8a14bac1fb8c6f4c744d39d88e56bfbc2950b62",
        "d6a0e997e0ebdc44500a8a62d2e78c587cd746279ebcf40c7abc2e21d6b9f980bd8ad8b7db434ee0cbf2d9f4530cd5ce499d28bc45b544",
        "4e0664b24135a27dfc65442868e9a4ad98b8aed6707adb765961e1926d25ff2151153238e6000000000000000000000000000000000000",
        "000000000000000000000000000006a7d517192c568ee08a845f73d29788cf035c3145b21ab344d8062ea9400000037d46d67c93fbbe12",
        "f9428f838d40ff0570744927f48a64fcca70448000000097dbf6298ebc1d1aba6fe95a3c688f723fbd62ea8fe24fcd18b1de8988fea4c4",
        "3b3e9943cbb124644de5ca101c9331b97c9fb087d3181a0d25ec3015e5c21d37afa497f9db8f42d70fb0ef45b544030815b53b0ec8812c",
        "ed192f3f6df4d896f1ecc1b58727f3f12b3194881a9ecb9de0b28ce7b207230d8e930fe1bce75e256cc250a9ebc1dc2e6299d0873da3ed",
        "fd78261d872701b4dc7ad557d9eabe3bce8e06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a98c97258f4e",
        "2489f1bb3d1029148e0d830b5a1399daff1084048e7bd8dbe9f85906a7d517187bd16635dad40455fdc2c0c124c68f215675a5dbbacb5f",
        "08000000b4d5b65321eff24d9763b980f4d8dace33e62e1685e673dc058f5c1f244af9668813000000000000400d030000004000050304",
        "000700c100080ee8000106000400000001003000ffff1000ffff70005100ffffd5bf4a3fcce717b0388bcc2749ebc148ad9969b23f45ee",
        "1b605fd58778576ac48278a07e2a5e0c47ab6b2c9e0287af6c9eedf30159108af21c66884b0a763f313fa1a4638e1b04d99085479a7238",
        "521f58a99ea3033b7a0a8f9bc9edeb1f9d0862616d626f6f2e6d6574616f702e76313a3863323838366630646331636231653461313339",
        "376165343065393430393133393631623034316336633336623365383832633163643031366564303863643300090a02030b040c0d0e05",
        "0f1008fe773b8107d9d057d5bf4a3fcce717b0388bcc2749ebc148ad9969b23f45ee1b605fd58778576ac4ecc1b58727f3f12b3194881a",
        "9ecb9de0b28ce7b207230d8e930fe1bce75e256c6400000000000000010101010101010101010101010101010101010101010101010101",
        "0101010101a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10000000000000000e8030000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000001000000000038ea11703ba5c4dbeb572051c98c4f717e486c2592aceab1ae6caec741e41a94c99eb2b01a64bc97",
        "3d1adba6b1de8054e97ac08cba1cfdbfd6edcf18012efd08",
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

    #[test]
    fn nonce_account_and_sequence() {
        let lane = key("3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx").unwrap();
        // `solana create-address-with-seed --from <lane> bamboo-nonce-v1 11111111111111111111111111111111` (Agave 4.3.0)
        assert_eq!(b58(&nonce_account(&lane)), "HMnAf4DMH4exGHGuGtohsasYdmULndZ3b9v9TLrbjENm");
        // kit `createAddressWithSeed` for the vector lane sha256("lane0")
        let lane0: Key = lane0().public_key().try_into().unwrap();
        assert_eq!(b58(&nonce_account(&lane0)), "4XKMaxU5GKc1NQ2VxyGXUEAsrf2ruB2coFHko7697UvW");
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
        assert_eq!(classify_landed(&Value::Null, 9).unwrap(), TxStatus::Mined { height: 9 });
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
