//! TON (R67, spec `docs/history/specs/2026-10-03-net-ton.md`). Lane = ví W5R1 của relayer (seqno riêng,
//! một external message bay mỗi lane — R62); tx gửi internal message `SignedOp` tới jetton wallet của người trả,
//! nơi contract kiểm chữ ký chủ thể trên phong bì TON Connect (R30: chủ thể không bao giờ gửi tx).
//! API: TON Center v3 (`masterchainInfo`, `blocks`, `transactionsByMasterchainBlock`, `transactionsByMessage`,
//! `message`, `runGetMethod`, `walletInformation`). Cell/BOC tối thiểu ở đây, không thêm crate.
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::adapter::{Built, ChainAdapter, Family, Head, Lane, Signed, TxStatus};
use crate::chain::SimError;
use crate::config::ChainCfg;
use crate::odoo::Job;
use crate::signer::{LocalSigner, Signer};

// ====================================================================== cells

/// Ordinary cell (or a level-0 exotic read from a BOC). Hash/depth computed once at construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    data: Vec<u8>,
    bits: usize,
    refs: Vec<Arc<Cell>>,
    exotic: bool,
    hash: [u8; 32],
    depth: u16,
}

impl Cell {
    fn new(data: Vec<u8>, bits: usize, refs: Vec<Arc<Cell>>, exotic: bool) -> Result<Self> {
        if bits > 1023 || refs.len() > 4 || data.len() != bits.div_ceil(8) {
            bail!("cell overflow");
        }
        let mut c = Cell { data, bits, refs, exotic, hash: [0; 32], depth: 0 };
        let mut h = Sha256::new();
        h.update(c.descriptors());
        h.update(c.padded());
        for r in &c.refs {
            h.update(r.depth.to_be_bytes());
        }
        for r in &c.refs {
            h.update(r.hash);
        }
        c.hash = h.finalize().into();
        c.depth = c.refs.iter().map(|r| r.depth + 1).max().unwrap_or(0);
        Ok(c)
    }

    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn depth(&self) -> u16 {
        self.depth
    }

    pub fn refs(&self) -> &[Arc<Cell>] {
        &self.refs
    }

    pub fn bit_len(&self) -> usize {
        self.bits
    }

    fn descriptors(&self) -> [u8; 2] {
        [self.refs.len() as u8 + if self.exotic { 8 } else { 0 }, (self.bits / 8 + self.bits.div_ceil(8)) as u8]
    }

    /// Data with the completion tag (`1` then zeros) when not byte aligned.
    fn padded(&self) -> Vec<u8> {
        let mut d = self.data.clone();
        if !self.bits.is_multiple_of(8) {
            let last = d.len() - 1;
            d[last] |= 0x80 >> (self.bits % 8);
        }
        d
    }

    pub fn parser(&self) -> Reader<'_> {
        Reader { cell: self, pos: 0, refp: 0 }
    }
}

#[derive(Default, Clone)]
pub struct Builder {
    data: Vec<u8>,
    bits: usize,
    refs: Vec<Arc<Cell>>,
}

impl Builder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bit(mut self, b: bool) -> Self {
        if self.bits.is_multiple_of(8) {
            self.data.push(0);
        }
        if b {
            let last = self.data.len() - 1;
            self.data[last] |= 0x80 >> (self.bits % 8);
        }
        self.bits += 1;
        self
    }

    /// Big-endian unsigned, `n ≤ 128` bits.
    pub fn uint(mut self, v: u128, n: usize) -> Self {
        for i in (0..n).rev() {
            self = self.bit(i < 128 && (v >> i) & 1 == 1);
        }
        self
    }

    pub fn int(self, v: i64, n: usize) -> Self {
        let mask = if n >= 128 { u128::MAX } else { (1u128 << n) - 1 };
        self.uint((v as i128 as u128) & mask, n)
    }

    pub fn bytes(mut self, b: &[u8]) -> Self {
        for byte in b {
            self = self.uint(*byte as u128, 8);
        }
        self
    }

    /// Copy the remaining bits of a reader.
    pub fn bits_from(mut self, r: &Reader<'_>) -> Self {
        for i in r.pos..r.cell.bits {
            self = self.bit(r.cell.data[i / 8] & (0x80 >> (i % 8)) != 0);
        }
        self
    }

    pub fn addr(self, a: Option<&Addr>) -> Self {
        match a {
            None => self.uint(0, 2),
            Some(a) => self.uint(0b100, 3).int(a.wc as i64, 8).bytes(&a.hash),
        }
    }

    /// `Grams` / `VarUInteger 16`.
    pub fn coins(self, v: u128) -> Self {
        let len = (128 - v.leading_zeros() as usize).div_ceil(8);
        self.uint(len as u128, 4).uint(v, len * 8)
    }

    pub fn reference(mut self, c: Arc<Cell>) -> Self {
        self.refs.push(c);
        self
    }

    pub fn maybe_ref(self, c: Option<Arc<Cell>>) -> Self {
        match c {
            Some(c) => self.bit(true).reference(c),
            None => self.bit(false),
        }
    }

    pub fn end(self) -> Result<Arc<Cell>> {
        Ok(Arc::new(Cell::new(self.data, self.bits, self.refs, false)?))
    }
}

pub struct Reader<'a> {
    cell: &'a Cell,
    pos: usize,
    refp: usize,
}

impl Reader<'_> {
    pub fn remaining(&self) -> usize {
        self.cell.bits - self.pos
    }

    pub fn bit(&mut self) -> Result<bool> {
        if self.pos >= self.cell.bits {
            bail!("cell underflow");
        }
        let b = self.cell.data[self.pos / 8] & (0x80 >> (self.pos % 8)) != 0;
        self.pos += 1;
        Ok(b)
    }

    pub fn uint(&mut self, n: usize) -> Result<u128> {
        if n > 128 {
            bail!("uint wider than 128 bits");
        }
        let mut v = 0u128;
        for _ in 0..n {
            v = (v << 1) | self.bit()? as u128;
        }
        Ok(v)
    }

    pub fn int(&mut self, n: usize) -> Result<i64> {
        let v = self.uint(n)? as i128;
        Ok(if n > 0 && v >> (n - 1) & 1 == 1 { (v - (1i128 << n)) as i64 } else { v as i64 })
    }

    pub fn bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        (0..n).map(|_| self.uint(8).map(|v| v as u8)).collect()
    }

    pub fn b256(&mut self) -> Result<[u8; 32]> {
        Ok(self.bytes(32)?.try_into().expect("32"))
    }

    /// `MsgAddress`: `None` = addr_none; only addr_std without anycast is accepted.
    pub fn addr(&mut self) -> Result<Option<Addr>> {
        match self.uint(2)? {
            0 => Ok(None),
            2 => {
                if self.bit()? {
                    bail!("anycast addresses are not supported");
                }
                let wc = self.int(8)? as i32;
                Ok(Some(Addr { wc, hash: self.b256()? }))
            }
            _ => bail!("unsupported address kind"),
        }
    }

    pub fn coins(&mut self) -> Result<u128> {
        let len = self.uint(4)? as usize;
        self.uint(len * 8)
    }

    pub fn reference(&mut self) -> Result<Arc<Cell>> {
        let c = self.cell.refs.get(self.refp).cloned().ok_or_else(|| anyhow!("no more refs"))?;
        self.refp += 1;
        Ok(c)
    }

    pub fn end(&self) -> Result<()> {
        if self.pos != self.cell.bits || self.refp != self.cell.refs.len() {
            bail!("trailing data in cell");
        }
        Ok(())
    }
}

/// Single-root BOC (`b5ee9c72`), no index, no CRC.
pub fn boc_serialize(root: &Arc<Cell>) -> Vec<u8> {
    // Order: DFS pre-order (de-duplicated), then stable-sorted by the longest distance from the root so every
    // cell comes after all its parents — the same order @ton/core and fam_ton.py produce for these trees.
    let mut seen: Vec<Arc<Cell>> = Vec::new();
    let mut level: HashMap<[u8; 32], usize> = HashMap::new();
    fn walk(c: &Arc<Cell>, d: usize, seen: &mut Vec<Arc<Cell>>, level: &mut HashMap<[u8; 32], usize>) {
        match level.get(&c.hash) {
            Some(l) if *l >= d => return,
            Some(_) => {}
            None => seen.push(c.clone()),
        }
        level.insert(c.hash, d);
        for r in &c.refs {
            walk(r, d + 1, seen, level);
        }
    }
    walk(root, 0, &mut seen, &mut level);
    seen.sort_by_key(|c| level[&c.hash]);
    let order: Vec<(usize, Arc<Cell>)> = seen.into_iter().map(|c| (0, c)).collect();
    let index: HashMap<[u8; 32], usize> = order.iter().enumerate().map(|(i, (_, c))| (c.hash, i)).collect();
    let size = (usize::BITS - order.len().leading_zeros()).div_ceil(8).max(1) as usize;
    let mut payload = Vec::new();
    for (_, c) in &order {
        payload.extend_from_slice(&c.descriptors());
        payload.extend_from_slice(&c.padded());
        for r in &c.refs {
            payload.extend_from_slice(&index[&r.hash].to_be_bytes()[8 - size..]);
        }
    }
    let off = (usize::BITS - payload.len().leading_zeros()).div_ceil(8).max(1) as usize;
    let be = |v: usize, n: usize| v.to_be_bytes()[8 - n..].to_vec();
    let mut out = vec![0xb5, 0xee, 0x9c, 0x72, size as u8, off as u8];
    out.extend(be(order.len(), size));
    out.extend(be(1, size));
    out.extend(be(0, size));
    out.extend(be(payload.len(), off));
    out.extend(be(0, size));
    out.extend(payload);
    out
}

/// Parse a BOC (any flags; first root). Cells with a level (pruned/merkle) are refused.
pub fn boc_parse(data: &[u8]) -> Result<Arc<Cell>> {
    let mut p = 0usize;
    let mut take = |n: usize| -> Result<&[u8]> {
        let s = data.get(p..p + n).ok_or_else(|| anyhow!("BOC truncated"))?;
        p += n;
        Ok(s)
    };
    if take(4)? != [0xb5, 0xee, 0x9c, 0x72] {
        bail!("not a BOC");
    }
    let flags = take(1)?[0];
    let (has_idx, size) = (flags & 0x80 != 0, (flags & 7) as usize);
    let off = take(1)?[0] as usize;
    if size == 0 || size > 4 || off == 0 || off > 8 {
        bail!("bad BOC header");
    }
    let num = |b: &[u8]| b.iter().fold(0usize, |a, x| (a << 8) | *x as usize);
    let cells = num(take(size)?);
    let roots = num(take(size)?);
    let _absent = num(take(size)?);
    let _total = num(take(off)?);
    if roots == 0 || cells == 0 || cells > 4096 {
        bail!("bad BOC counts");
    }
    let root = num(take(size)?);
    for _ in 1..roots {
        take(size)?;
    }
    if has_idx {
        take(cells.checked_mul(off).ok_or_else(|| anyhow!("BOC index"))?)?;
    }
    let mut raw = Vec::with_capacity(cells);
    for _ in 0..cells {
        let d = take(2)?;
        let (d1, d2) = (d[0], d[1] as usize);
        if d1 & 0xF0 != 0 {
            bail!("BOC cells with a level or stored hashes are not supported");
        }
        let body = take(d2.div_ceil(2))?.to_vec();
        let refs: Vec<usize> = (0..(d1 & 7)).map(|_| take(size).map(num)).collect::<Result<_>>()?;
        if refs.len() > 4 {
            bail!("too many refs");
        }
        raw.push((d2, body, refs, d1 & 8 != 0));
    }
    let mut built: Vec<Option<Arc<Cell>>> = vec![None; cells];
    for i in (0..cells).rev() {
        let (d2, mut body, refs, exotic) = raw[i].clone();
        let bits = if d2 % 2 == 1 {
            let last = *body.last().ok_or_else(|| anyhow!("empty padded cell"))?;
            if last == 0 {
                bail!("bad completion tag");
            }
            let tz = last.trailing_zeros() as usize;
            let len = body.len();
            body[len - 1] &= !(1u8 << tz);
            (len * 8) - tz - 1
        } else {
            body.len() * 8
        };
        let children = refs
            .iter()
            .map(|&r| if r > i { built[r].clone().ok_or_else(|| anyhow!("bad ref")) } else { Err(anyhow!("BOC ref order")) })
            .collect::<Result<Vec<_>>>()?;
        built[i] = Some(Arc::new(Cell::new(body, bits, children, exotic)?));
    }
    built.get(root).cloned().flatten().ok_or_else(|| anyhow!("bad BOC root"))
}

// ====================================================================== base64, addresses

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |a, (i, b)| a | (*b as u32) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Standard or URL-safe alphabet, padding optional.
pub fn b64decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut nbits) = (0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => bail!("not base64"),
        } as u32;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            acc &= (1 << nbits) - 1;
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Addr {
    pub wc: i32,
    pub hash: [u8; 32],
}

impl Addr {
    /// Raw `wc:hex64` (any case) or user-friendly 48-char base64/base64url.
    pub fn parse(s: &str) -> Result<Self> {
        if let Some((wc, h)) = s.split_once(':') {
            let wc: i32 = wc.parse().context("workchain")?;
            let hash: [u8; 32] = alloy::hex::decode(h)?.try_into().map_err(|_| anyhow!("address hash length"))?;
            return Ok(Self { wc, hash });
        }
        let raw = b64decode(s)?;
        if raw.len() != 36 || crate::signer::crc16_xmodem(&raw[..34]) != u16::from_be_bytes([raw[34], raw[35]]) {
            bail!("bad friendly address");
        }
        Ok(Self { wc: raw[1] as i8 as i32, hash: raw[2..34].try_into().expect("32") })
    }

    /// Canonical form shared with Odoo (`addresses.canonical('ton', …)`).
    pub fn raw(&self) -> String {
        format!("{}:{}", self.wc, alloy::hex::encode(self.hash))
    }

    fn of_state_init(si: &Arc<Cell>) -> Self {
        Self { wc: 0, hash: si.hash() }
    }
}

fn hex0x(b: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(b))
}

fn b32(hex: &str) -> Result<[u8; 32]> {
    let v = alloy::hex::decode(hex.trim_start_matches("0x"))?;
    v.try_into().map_err(|_| anyhow!("expected 32 bytes"))
}

// ====================================================================== protocol (§2, common.tact)

pub const SIGN_DATA_PREFIX: u128 = 0x75569022;
pub const SCHEMA_CRC: u128 = 0x45ba8d70;
pub const OP_SIGNED: u128 = 0x5b0a1d01;
pub const OP_MANDATE_PAY: u128 = 0x5b0a1d10;
pub const EV_MTE: u128 = 0x9b1c0d01;
pub const EV_PAID: u128 = 0x9b1c0d02;
/// Floors the wallet adds under the signed ones (jetton.tact `MIN_LEG_TON`, `CANCEL_TON`).
const MIN_LEG_TON: u128 = 100_000_000;
const CANCEL_TON: u128 = 100_000_000;
const E_NONCE: i64 = 706;
/// A legit transaction of ours emits at most two events; anything past that is someone's noise (review M3).
const MAX_EVENTS_PER_TX: usize = 4;
const W5R1_CODE: &str = "b5ee9c7201021401000281000114ff00f4a413f4bcf2c80b01020120020d020148030402dcd020d749c120915b8f6320d70b1f2082106578746ebd21821073696e74bdb0925f03e082106578746eba8eb48020d72101d074d721fa4030fa44f828fa443058bd915be0ed44d0810141d721f4058307f40e6fa1319130e18040d721707fdb3ce03120d749810280b99130e070e2100f020120050c020120060902016e07080019adce76a2684020eb90eb85ffc00019af1df6a2684010eb90eb858fc00201480a0b0017b325fb51341c75c875c2c7e00011b262fb513435c280200019be5f0f6a2684080a0eb90fa02c0102f20e011e20d70b1f82107369676ebaf2e08a7f0f01e68ef0eda2edfb218308d722028308d723208020d721d31fd31fd31fed44d0d200d31f20d31fd3ffd70a000af90140ccf9109a28945f0adb31e1f2c087df02b35007b0f2d0845125baf2e0855036baf2e086f823bbf2d0882292f800de01a47fc8ca00cb1f01cf16c9ed542092f80fde70db3cd81003f6eda2edfb02f404216e926c218e4c0221d73930709421c700b38e2d01d72820761e436c20d749c008f2e09320d74ac002f2e09320d71d06c712c2005230b0f2d089d74cd7393001a4e86c128407bbf2e093d74ac000f2e093ed55e2d20001c000915be0ebd72c08142091709601d72c081c12e25210b1e30f20d74a111213009601fa4001fa44f828fa443058baf2e091ed44d0810141d718f405049d7fc8ca0040048307f453f2e08b8e14038307f45bf2e08c22d70a00216e01b3b0f2d090e2c85003cf1612f400c9ed54007230d72c08248e2d21f2e092d200ed44d0d2005113baf2d08f54503091319c01810140d721d70a00f2e08ee2c8ca0058cf16c9ed5493f2c08de20010935bdb31e1d74cd0";
const W5R1_HASHES: [&str; 2] = [
    "20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f",
    "44b96c52eaa2e18b272629e6e496004d08e0c364c1835a7418b92fb7585a2ed1",
];
const V4_V3_HASHES: [&str; 2] = [
    "feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0",
    "84dafa449f98a6987789ba232358072bc0f76dc4524002a5d0918b9a75d2d599",
];

/// Fields of a `MetaOp` v1 cell the relayer needs (the contract re-checks everything).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaOp {
    pub network: i32,
    pub op: u8,
    pub amount: u128,
    pub nonce: u64,
    pub valid_until: u64,
    pub contract: Addr,
    pub from: Addr,
    pub to: Addr,
    pub relayer: Option<Addr>,
    pub pay_ref: [u8; 32],
    pub lane: [u8; 32],
    pub extra: [u8; 32],
    pub digest: [u8; 32],
}

pub fn parse_metaop(c: &Arc<Cell>) -> Result<MetaOp> {
    let mut s = c.parser();
    if s.bytes(15)? != b"scaas.metaop.v1" {
        bail!("not a MetaOp v1");
    }
    let network = s.int(32)? as i32;
    let op = s.uint(8)? as u8;
    let amount = s.uint(128)?;
    let nonce = s.uint(64)? as u64;
    let valid_until = s.uint(64)? as u64;
    let contract = s.addr()?.ok_or_else(|| anyhow!("MetaOp without contract"))?;
    let parties = s.reference()?;
    let refs = s.reference()?;
    s.end()?;
    let mut p = parties.parser();
    let from = p.addr()?.ok_or_else(|| anyhow!("MetaOp without from"))?;
    let to = p.addr()?.ok_or_else(|| anyhow!("MetaOp without to"))?;
    let relayer = p.addr()?;
    p.end()?;
    let mut r = refs.parser();
    let (pay_ref, lane, extra) = (r.b256()?, r.b256()?, r.b256()?);
    r.end()?;
    Ok(MetaOp { network, op, amount, nonce, valid_until, contract, from, to, relayer, pay_ref, lane, extra, digest: c.hash() })
}

/// `TradeParams.forwardTon` (common.tact): the forward TON floor the payer signed for a DEX leg.
pub fn trade_forward_floor(params: &Arc<Cell>) -> Result<u128> {
    let mut s = params.parser();
    s.addr()?;
    s.addr()?;
    s.uint(128)?;
    s.addr()?;
    s.uint(32)?;
    let f = s.coins()?;
    s.end()?;
    Ok(f)
}

/// Jetton wallet of `owner` for `master` without RPC — `walletInit` of jetton.tact, same as Odoo's
/// `fam_ton.jetton_wallet_address` (R20). The wallet code is known by hash and depth only.
pub fn jetton_wallet_address(owner: &Addr, master: &Addr, code_hash: &[u8; 32], code_depth: u16) -> Result<Addr> {
    let tail = Builder::new().uint(0, 2 + 3 * 32).end()?; // lanes oldLanes rotatedAt laneCount oldCount
    let data = Builder::new().addr(Some(owner)).addr(Some(master)).uint(0, 4).bytes(&[0; 32]).bit(false).reference(tail).end()?;
    // StateInit `00110 ^code ^data`: 2 refs, 5 bits + completion tag.
    let mut h = Sha256::new();
    h.update([2u8, 1, 0x34]);
    h.update(code_depth.to_be_bytes());
    h.update(data.depth().to_be_bytes());
    h.update(code_hash);
    h.update(data.hash());
    Ok(Addr { wc: 0, hash: h.finalize().into() })
}

/// TEP-81 wire form used by TON Connect, as a `storeStringTail` snake (127 bytes per cell).
pub fn domain_cell(domain: &str) -> Result<Arc<Cell>> {
    let wire: Vec<u8> = domain.split('.').rev().flat_map(|l| l.bytes().chain(std::iter::once(0))).collect();
    snake(&wire)
}

/// Bytes as a snake: 127 bytes per cell along the first ref (`storeStringTail`'s chunking); empty = one empty cell.
pub fn snake(bytes: &[u8]) -> Result<Arc<Cell>> {
    let mut cell: Option<Arc<Cell>> = None;
    let chunks: Vec<&[u8]> = if bytes.is_empty() { vec![&[]] } else { bytes.chunks(127).collect() };
    for chunk in chunks.iter().rev() {
        let mut b = Builder::new().bytes(chunk);
        if let Some(c) = cell {
            b = b.reference(c);
        }
        cell = Some(b.end()?);
    }
    Ok(cell.expect("one chunk"))
}

pub fn envelope_hash(owner: &Addr, timestamp: u64, domain: &str, payload: &Arc<Cell>) -> Result<[u8; 32]> {
    Ok(Builder::new()
        .uint(SIGN_DATA_PREFIX, 32)
        .uint(SCHEMA_CRC, 32)
        .uint(timestamp as u128, 64)
        .addr(Some(owner))
        .reference(domain_cell(domain)?)
        .reference(payload.clone())
        .end()?
        .hash())
}

/// Owner key from the owner's wallet StateInit (same rule as `pubkeyFromStateInit` in common.tact).
pub fn pubkey_from_state_init(si: &Arc<Cell>, owner: &Addr) -> Result<[u8; 32]> {
    if owner.wc != 0 || si.hash() != owner.hash {
        bail!("StateInit does not belong to {}", owner.raw());
    }
    let mut s = si.parser();
    if s.bit()? || s.bit()? || !s.bit()? {
        bail!("unexpected StateInit");
    }
    let code = s.reference()?;
    if !s.bit()? {
        bail!("StateInit without data");
    }
    let data = s.reference()?;
    let mut d = data.parser();
    let ch = alloy::hex::encode(code.hash());
    if W5R1_HASHES.contains(&ch.as_str()) {
        d.uint(65)?;
    } else if V4_V3_HASHES.contains(&ch.as_str()) {
        d.uint(64)?;
    } else {
        bail!("unknown wallet code {ch}");
    }
    d.b256()
}

/// The connector's signature JSON (`ton.js` / Odoo `fam_ton.parse_signature`).
#[derive(Debug, Clone)]
pub enum Auth {
    TonConnect { signature: [u8; 64], timestamp: u64, domain: String, state_init: Option<Arc<Cell>> },
    Passkey { r: [u8; 32], s: [u8; 32], authenticator_data: Vec<u8>, client_data_json: String },
}

pub fn parse_auth(sig: &str) -> Result<Auth> {
    let v: Value = serde_json::from_str(sig).context("TON signature is not JSON")?;
    let str_of = |k: &str| v.get(k).and_then(Value::as_str).ok_or_else(|| anyhow!("signature.{k} missing"));
    match str_of("kind")? {
        "ton_connect" => {
            let signature: [u8; 64] =
                b64decode(str_of("signature")?)?.try_into().map_err(|_| anyhow!("signature must be 64 bytes"))?;
            let timestamp = v.get("timestamp").and_then(Value::as_u64).ok_or_else(|| anyhow!("signature.timestamp"))?;
            let domain = str_of("domain")?.to_string();
            if domain.len() > 255 {
                bail!("domain too long");
            }
            let state_init = match v.get("state_init").and_then(Value::as_str) {
                Some(s) if !s.is_empty() => Some(boc_parse(&b64decode(s)?)?),
                _ => None,
            };
            Ok(Auth::TonConnect { signature, timestamp, domain, state_init })
        }
        "passkey" => Ok(Auth::Passkey {
            r: b32(str_of("r")?)?,
            s: b32(str_of("s")?)?,
            authenticator_data: b64decode(str_of("authenticator_data")?)?,
            client_data_json: str_of("client_data_json")?.to_string(),
        }),
        other => bail!("unknown signature kind {other}"),
    }
}

const CDJ_PREFIX: &str = "{\"type\":\"webauthn.get\",\"challenge\":\"";

/// `auth` cell of common.tact (kind 0 / kind 1).
pub fn auth_cell(auth: &Auth) -> Result<Arc<Cell>> {
    match auth {
        Auth::TonConnect { signature, timestamp, domain, .. } => Builder::new()
            .uint(0, 8)
            .bytes(signature)
            .uint(*timestamp as u128, 64)
            .reference(domain_cell(domain)?)
            .end(),
        Auth::Passkey { r, s, authenticator_data, client_data_json } => {
            if authenticator_data.len() < 37 || authenticator_data.len() > 127 {
                bail!("authenticator data length");
            }
            let suffix = client_data_json
                .strip_prefix(CDJ_PREFIX)
                .and_then(|rest| rest.get(43..))
                .ok_or_else(|| anyhow!("clientDataJSON does not start with the WebAuthn prefix"))?
                .as_bytes();
            if suffix.len() > 254 {
                bail!("clientDataJSON too long");
            }
            let mut sc = Builder::new().bytes(&suffix[..suffix.len().min(127)]);
            if suffix.len() > 127 {
                sc = sc.reference(Builder::new().bytes(&suffix[127..]).end()?);
            }
            Builder::new()
                .uint(1, 8)
                .bytes(r)
                .bytes(s)
                .reference(Builder::new().bytes(authenticator_data).end()?)
                .reference(sc.end()?)
                .end()
        }
    }
}

// ---------------------------------------------------------------------- CTR-MTX-26 (spec §6.2, §9)

/// `max_pay_meta_bytes` (spec §9): the node's cap on a pay-meta `meta`. On TON it is far below what a lane can carry
/// (measured, `jetton.spec.ts` › meta size limit: 38,100 B = 300 snake cells settle in @ton/sandbox 0.45.0; config
/// param 43 bounds the external message at 65,535 B and depth 512).
// TODO(T17): becomes the `max_pay_meta_bytes` config key (default 2,048) for every family, with the indexer
// decoding of `PaymentMeta` (opcode `EV_META`, joined to `PaymentSettled` by `pay_ref`).
pub const MAX_PAY_META_BYTES: usize = 2048;
pub const EV_META: u128 = 0x9b1c0d04;

fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    alloy::primitives::keccak256(parts.concat()).0
}

/// `keccak256("scaas.pay.meta" ‖ salt ‖ keccak256(meta))` (common.tact `metaPayId`).
pub fn meta_pay_id(salt: &[u8], meta: &[u8]) -> [u8; 32] {
    keccak(&[b"scaas.pay.meta", salt, &keccak(&[meta])])
}

/// `keccak256("scaas.pay.lane" ‖ p)` (common.tact `payLane`).
pub fn pay_lane(p: &[u8]) -> [u8; 32] {
    keccak(&[b"scaas.pay.lane", p])
}

fn hex_field(v: &Value, what: &str) -> Result<Vec<u8>> {
    let s = v.as_str().ok_or_else(|| anyhow!("op.{what} missing"))?;
    Ok(alloy::hex::decode(s.trim().trim_start_matches("0x"))?)
}

/// The `SignedOp.params` a pay op carries, checked before any getter (fail closed). `op.kind`: none = the plain pay
/// (`params = null`: on `OP_PAY` a `params` cell means pay-meta, so a plain pay never carries `extra.params`);
/// `"pay_meta"` (`op.salt` 32 bytes hex, `op.meta` hex within the cap) = `params = salt:uint256 ^meta` (`meta` as
/// snake bytes), with `pay_ref == metaPayId(salt, meta)`, `lane == payLane(pay_ref)`, `nonce == 0` on an `OP_PAY`;
/// any other kind is refused (a typo must not burn the `(payer, payId)` lane as a plain pay). `Ok(None)`: the op's
/// own `extra.params` (trade, set_key) as before.
pub fn pay_params(m: &MetaOp, o: &Value) -> Result<Option<Arc<Cell>>> {
    match o["kind"].as_str() {
        None if m.op == 1 && o["extra"]["params"].is_string() => {
            bail!("a plain pay carries no params (a pay-meta is op.kind = \"pay_meta\")")
        }
        None => Ok(None),
        Some("pay_meta") => {
            if m.op != 1 {
                bail!("pay-meta: the MetaOp is op {}, not pay", m.op);
            }
            let (salt, meta) = (hex_field(&o["salt"], "salt")?, hex_field(&o["meta"], "meta")?);
            let salt: [u8; 32] = salt.try_into().map_err(|_| anyhow!("op.salt is 32 bytes"))?;
            if meta.len() > MAX_PAY_META_BYTES {
                bail!("meta is {} B, above the {MAX_PAY_META_BYTES} B cap", meta.len());
            }
            let id = meta_pay_id(&salt, &meta);
            if m.pay_ref != id || m.lane != pay_lane(&id) || m.nonce != 0 {
                bail!("pay-meta: pay_ref / lane / nonce are not metaPayId(salt, meta) / payLane(pay_ref) / 0");
            }
            Ok(Some(Builder::new().bytes(&salt).reference(snake(&meta)?).end()?))
        }
        Some(k) => bail!("unknown op.kind {k:?} (pay_meta, or none for a plain pay)"),
    }
}

/// `SignedOp` body exactly as Tact lays it out (trailing fields in a ref cell).
pub fn signed_op_body(op: &Arc<Cell>, auth: &Arc<Cell>, params: Option<Arc<Cell>>, state_init: Option<Arc<Cell>>, response: &Addr, forward_ton: u128, match_with: [u8; 32]) -> Result<Arc<Cell>> {
    let tail = Builder::new().maybe_ref(params).maybe_ref(state_init).addr(Some(response)).coins(forward_ton).bytes(&match_with).end()?;
    Builder::new().uint(OP_SIGNED, 32).reference(op.clone()).reference(auth.clone()).reference(tail).end()
}

pub fn mandate_pay_body(op: &Arc<Cell>, signature: &[u8; 64], response: &Addr) -> Result<Arc<Cell>> {
    Builder::new().uint(OP_MANDATE_PAY, 32).reference(op.clone()).bytes(signature).addr(Some(response)).end()
}

// ---------------------------------------------------------------------- W5R1 (relayer lanes)

pub struct W5 {
    pub code: Arc<Cell>,
    pub wallet_id: u32,
    pub pubkey: [u8; 32],
}

impl W5 {
    pub fn new(pubkey: [u8; 32], global_id: i32) -> Result<Self> {
        Ok(Self { code: boc_parse(&alloy::hex::decode(W5R1_CODE)?)?, wallet_id: (global_id as u32) ^ 0x8000_0000, pubkey })
    }

    pub fn state_init(&self) -> Result<Arc<Cell>> {
        let data = Builder::new().bit(true).uint(0, 32).uint(self.wallet_id as u128, 32).bytes(&self.pubkey).bit(false).end()?;
        Builder::new().uint(0b00110, 5).reference(self.code.clone()).reference(data).end()
    }

    pub fn address(&self) -> Result<Addr> {
        Ok(Addr::of_state_init(&self.state_init()?))
    }

    /// Bytes the lane key signs (hash of the signing cell) and the body builder to append the signature to.
    fn signing(&self, seqno: u32, valid_until: u32, msg: Arc<Cell>) -> Result<Builder> {
        let out_list = Builder::new().reference(Builder::new().end()?).uint(0x0ec3c86d, 32).uint(3, 8).reference(msg).end()?;
        Ok(Builder::new()
            .uint(0x7369676e, 32)
            .uint(self.wallet_id as u128, 32)
            .uint(valid_until as u128, 32)
            .uint(seqno as u128, 32)
            .maybe_ref(Some(out_list))
            .bit(false))
    }
}

/// `MessageRelaxed` internal, bounceable, body as a ref (forceRef).
pub fn internal_message(to: &Addr, value: u128, body: Arc<Cell>) -> Result<Arc<Cell>> {
    Builder::new()
        .bit(false) // int_msg_info$0
        .bit(true) // ihr_disabled
        .bit(true) // bounce
        .bit(false) // bounced
        .addr(None)
        .addr(Some(to))
        .coins(value)
        .bit(false) // no extra currencies
        .coins(0)
        .coins(0)
        .uint(0, 64)
        .uint(0, 32)
        .bit(false) // no init
        .bit(true)
        .reference(body)
        .end()
}

/// External-in message (`init` included only for the first message of an undeployed lane wallet).
pub fn external_message(to: &Addr, init: Option<Arc<Cell>>, body: Arc<Cell>) -> Result<Arc<Cell>> {
    let mut b = Builder::new().uint(0b10, 2).addr(None).addr(Some(to)).coins(0);
    b = match init {
        Some(i) => b.bit(true).bit(true).reference(i),
        None => b.bit(false),
    };
    b.bit(true).reference(body).end()
}

/// Signed W5R1 external message ⇒ (BOC, message hash). The hash is the tx id: TON Center indexes the
/// inbound message of the lane wallet's transaction under it, and we always send these exact bytes.
pub fn w5_transfer(w5: &W5, signer: &dyn Signer, seqno: u32, valid_until: u32, to: &Addr, value: u128, body: Arc<Cell>) -> Result<(Vec<u8>, [u8; 32])> {
    let signing = w5.signing(seqno, valid_until, internal_message(to, value, body)?)?;
    let to_sign = signing.clone().end()?.hash();
    let sig = signer.sign(&to_sign)?;
    let w5body = signing.bytes(&sig).end()?;
    let init = if seqno == 0 { Some(w5.state_init()?) } else { None };
    let ext = external_message(&w5.address()?, init, w5body)?;
    Ok((boc_serialize(&ext), ext.hash()))
}

// ---------------------------------------------------------------------- events

/// A jetton wallet code known by (representation hash, depth): enough to derive every wallet address.
pub type WalletCode = ([u8; 32], u16);

/// One external-out message body of ours, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TonEvent {
    Executed { master: Addr, from: Addr, digest: [u8; 32] },
    Paid { from: Addr, to: Addr, amount: u128, pay_ref: [u8; 32] },
}

pub fn decode_event(body: &Arc<Cell>) -> Result<Option<TonEvent>> {
    let mut s = body.parser();
    if s.remaining() < 32 {
        return Ok(None);
    }
    Ok(match s.uint(32)? {
        EV_MTE => {
            let master = s.addr()?.ok_or_else(|| anyhow!("event master"))?;
            let from = s.addr()?.ok_or_else(|| anyhow!("event from"))?;
            let digest = s.b256()?;
            s.end()?;
            Some(TonEvent::Executed { master, from, digest })
        }
        EV_PAID => {
            let from = s.addr()?.ok_or_else(|| anyhow!("event from"))?;
            let to = s.addr()?.ok_or_else(|| anyhow!("event to"))?;
            let amount = s.coins()?;
            let pay_ref = s.b256()?;
            s.end()?;
            Some(TonEvent::Paid { from, to, amount, pay_ref })
        }
        _ => None,
    })
}

// ====================================================================== TON Center v3 client

#[derive(Clone)]
pub struct Api {
    http: reqwest::Client,
    base: String,
    key: Option<String>,
}

impl Api {
    pub fn new(base: &str, key: Option<String>) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder().timeout(std::time::Duration::from_secs(20)).build()?,
            base: base.trim_end_matches('/').to_string(),
            key,
        })
    }

    async fn send(&self, rb: reqwest::RequestBuilder, what: &str) -> Result<Value> {
        let rb = match &self.key {
            Some(k) => rb.header("X-API-Key", k),
            None => rb,
        };
        let res = rb.send().await.with_context(|| format!("{what}: transport"))?;
        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() {
            let head: String = text.chars().take(300).collect();
            bail!("{what}: HTTP {status}: {head}");
        }
        serde_json::from_str(&text).with_context(|| format!("{what}: decode"))
    }

    pub async fn get(&self, path: &str, query: &[(&str, String)]) -> Result<Value> {
        self.send(self.http.get(format!("{}/api/v3/{path}", self.base)).query(query), path).await
    }

    pub async fn post(&self, path: &str, body: Value) -> Result<Value> {
        self.send(self.http.post(format!("{}/api/v3/{path}", self.base)).json(&body), path).await
    }

    /// Get-method; numeric results only (`num` entries, `0x…` hex or decimal).
    pub async fn run_get(&self, addr: &Addr, method: &str, stack: Vec<Value>) -> Result<Vec<Value>> {
        let v = self.post("runGetMethod", json!({"address": addr.raw(), "method": method, "stack": stack})).await?;
        let code = v.get("exit_code").and_then(Value::as_i64).unwrap_or(0);
        if code != 0 {
            bail!("{method}: exit code {code}");
        }
        Ok(v.get("stack").and_then(Value::as_array).cloned().unwrap_or_default())
    }
}

pub fn stack_num(v: &Value) -> Result<u128> {
    let s = v.get("value").and_then(Value::as_str).ok_or_else(|| anyhow!("stack entry without value"))?;
    let neg = s.starts_with('-');
    let t = s.trim_start_matches('-');
    let n = match t.strip_prefix("0x") {
        Some(h) => u128::from_str_radix(h, 16)?,
        None => t.parse()?,
    };
    if neg && n != 0 {
        bail!("negative stack number");
    }
    Ok(n)
}

pub fn stack_cell(v: &Value) -> Result<Arc<Cell>> {
    boc_parse(&b64decode(v.get("value").and_then(Value::as_str).ok_or_else(|| anyhow!("stack entry without value"))?)?)
}

/// Hash fields of TON Center: base64 (any alphabet) or hex ⇒ 32 bytes.
pub fn api_hash(v: &Value) -> Result<[u8; 32]> {
    let s = v.as_str().ok_or_else(|| anyhow!("hash is not a string"))?;
    let bytes = if s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()) { alloy::hex::decode(s)? } else { b64decode(s)? };
    bytes.try_into().map_err(|_| anyhow!("hash is not 32 bytes"))
}

/// Events of one TON Center transaction, before source authentication: (log_index, emitter, event).
pub fn tx_events(tx: &Value) -> Result<Vec<(usize, Addr, TonEvent)>> {
    let account = Addr::parse(tx.get("account").and_then(Value::as_str).ok_or_else(|| anyhow!("tx.account"))?)?;
    let mut out = Vec::new();
    let msgs = tx.get("out_msgs").and_then(Value::as_array).cloned().unwrap_or_default();
    for (i, m) in msgs.iter().enumerate() {
        if !m.get("destination").is_none_or(Value::is_null) {
            continue; // internal: not an event
        }
        let Some(body) = m.pointer("/message_content/body").and_then(Value::as_str) else { continue };
        let Ok(cell) = b64decode(body).and_then(|b| boc_parse(&b)) else { continue };
        if let Ok(Some(ev)) = decode_event(&cell) {
            out.push((i, account, ev));
            if out.len() == MAX_EVENTS_PER_TX {
                break;
            }
        }
    }
    Ok(out)
}

fn exit_code(tx: &Value) -> Option<i64> {
    tx.pointer("/description/compute_ph/exit_code").and_then(Value::as_i64)
}

/// Digest of the MetaOp a lane transaction carried: first ref of both `SignedOp` and `MandatePay`.
fn carried_digest(out_msg: &Value) -> Option<[u8; 32]> {
    let body = out_msg.pointer("/message_content/body").and_then(Value::as_str)?;
    let cell = boc_parse(&b64decode(body).ok()?).ok()?;
    cell.refs().first().map(|op| op.hash())
}

fn compute_ok(tx: &Value) -> std::result::Result<(), String> {
    let d = tx.get("description").cloned().unwrap_or(Value::Null);
    if d.get("aborted").and_then(Value::as_bool).unwrap_or(false) {
        let code = d.pointer("/compute_ph/exit_code").and_then(Value::as_i64).unwrap_or(-1);
        return Err(format!("aborted (exit code {code})"));
    }
    if d.pointer("/compute_ph/success").and_then(Value::as_bool) == Some(false) {
        return Err(format!("compute failed (exit code {})", d.pointer("/compute_ph/exit_code").and_then(Value::as_i64).unwrap_or(-1)));
    }
    if d.pointer("/action/success").and_then(Value::as_bool) == Some(false) {
        return Err("action phase failed".into());
    }
    Ok(())
}

// ====================================================================== adapter

pub struct TonAdapter {
    key: String,
    lanes: Vec<Lane>,
    signers: Vec<LocalSigner>,
    w5: Vec<W5>,
    api: Api,
    global_id: i32,
    attach: u128,
    forward: u128,
    /// master ⇒ its jetton wallet code (hash, depth), `None` = not a jetton master; immutable, one call per master.
    codes: RwLock<HashMap<Addr, Option<WalletCode>>>,
}

fn param_str(cfg: &ChainCfg, k: &str) -> Option<String> {
    cfg.params.get(k).and_then(|v| v.as_str()).map(str::to_string)
}

fn param_u128(cfg: &ChainCfg, k: &str, default: u128) -> u128 {
    cfg.params.get(k).and_then(|v| v.as_integer()).map(|v| v as u128).unwrap_or(default)
}

impl TonAdapter {
    /// `params`: `global_id` (default by network: `-239`, `-3`; required otherwise), `attach_nanoton` (default
    /// 0.15 TON), `forward_nanoton` (default 0; never below the floor the payer signed), `api_key_env`.
    /// Jetton masters are NOT configured here: they are Odoo's token list (`node_config`, review H1).
    pub fn new(cfg: &ChainCfg, signers: &[LocalSigner]) -> Result<Self> {
        let net = cfg.network.clone().unwrap_or_default();
        let global_id = match cfg.params.get("global_id").and_then(|v| v.as_integer()) {
            Some(g) => g as i32,
            None => net.parse::<i32>().map_err(|_| anyhow!("chain {}: params.global_id is required for {net}", cfg.chain_key()))?,
        };
        let mut w5 = Vec::new();
        let mut lanes = Vec::new();
        for (s, &i) in signers.iter().zip(&cfg.lanes) {
            let pk: [u8; 32] = s.public_key().try_into().map_err(|_| anyhow!("TON lanes need ed25519 keys"))?;
            let w = W5::new(pk, global_id)?;
            lanes.push(Lane { index: i, address: w.address()?.raw() });
            w5.push(w);
        }
        let signers = signers.iter().map(clone_signer).collect::<Result<Vec<_>>>()?;
        let key = param_str(cfg, "api_key_env").and_then(|e| std::env::var(e).ok());
        Ok(Self {
            key: cfg.chain_key(),
            lanes,
            signers,
            w5,
            api: Api::new(cfg.rpc_urls.first().ok_or_else(|| anyhow!("no rpc_urls"))?, key)?,
            global_id,
            attach: param_u128(cfg, "attach_nanoton", 150_000_000),
            forward: param_u128(cfg, "forward_nanoton", 0),
            codes: RwLock::new(HashMap::new()),
        })
    }

    pub fn lane_wallet(&self, lane: usize) -> Result<&W5> {
        self.w5.get(lane).ok_or_else(|| anyhow!("no lane {lane}"))
    }

    /// Wallet code of a registered master (`get_jetton_data`, cached). A contract that answers with a non-zero
    /// exit code is not a jetton master (e.g. a Mandate Odoo registered): `None`, never a stall.
    async fn wallet_code(&self, master: &Addr) -> Result<Option<WalletCode>> {
        if let Some(c) = self.codes.read().ok().and_then(|m| m.get(master).copied()) {
            return Ok(c);
        }
        let v = self.api.post("runGetMethod", json!({"address": master.raw(), "method": "get_jetton_data", "stack": []})).await?;
        let code = match v.get("exit_code").and_then(Value::as_i64).unwrap_or(0) {
            0 => {
                let c = stack_cell(v.pointer("/stack/4").ok_or_else(|| anyhow!("get_jetton_data: no wallet code"))?)?;
                Some((c.hash(), c.depth()))
            }
            _ => None,
        };
        if let Ok(mut m) = self.codes.write() {
            m.insert(*master, code);
        }
        Ok(code)
    }

    async fn tx_by_in_msg(&self, hash: &[u8; 32]) -> Result<Option<Value>> {
        let v = self.api.get("transactionsByMessage", &[("msg_hash", alloy::hex::encode(hash)), ("direction", "in".into())]).await?;
        Ok(v.get("transactions").and_then(Value::as_array).and_then(|a| a.first().cloned()))
    }

    /// Masterchain height of the contract's recent transaction that executed `digest`, if any.
    async fn executed_by_copy(&self, child: &Value, digest: Option<[u8; 32]>) -> Result<Option<u64>> {
        let (Some(digest), Some(account)) = (digest, child.get("account").and_then(Value::as_str)) else { return Ok(None) };
        let contract = Addr::parse(account)?;
        let v = self.api.get("transactions", &[("account", contract.raw()), ("limit", "64".into()), ("sort", "desc".into())]).await?;
        for tx in v.get("transactions").and_then(Value::as_array).into_iter().flatten() {
            if compute_ok(tx).is_ok() && tx_events(tx)?.iter().any(|(_, e, ev)| *e == contract && matches!(ev, TonEvent::Executed { digest: d, .. } if *d == digest)) {
                return Ok(Some(tx.get("mc_block_seqno").and_then(Value::as_u64).unwrap_or_default()));
            }
        }
        Ok(None)
    }

    async fn mc_block(&self, seqno: u64) -> Result<String> {
        let v = self
            .api
            .get("blocks", &[("workchain", "-1".into()), ("shard", "8000000000000000".into()), ("seqno", seqno.to_string())])
            .await?;
        let b = v.pointer("/blocks/0").ok_or_else(|| anyhow!("no masterchain block {seqno}"))?;
        Ok(hex0x(&api_hash(b.get("root_hash").unwrap_or(&Value::Null))?))
    }
}

/// Normalized event for Odoo, or `None` when the emitter is not one of ours (R10-10). No network call: the
/// emitter must be the wallet `walletInit(owner, master)` derives to (review M3); a Mandate only when Odoo lists
/// its address (review L10). `masters` = Odoo's contracts with their wallet code (`None`: not a master).
pub fn authenticate(emitter: &Addr, ev: &TonEvent, masters: &[(Addr, Option<WalletCode>)]) -> Option<(Addr, TonEvent)> {
    let wallet_of = |master: &Addr, owner: &Addr| {
        let (_, code) = masters.iter().find(|(m, _)| m == master)?;
        let (h, d) = (*code)?;
        jetton_wallet_address(owner, master, &h, d).ok()
    };
    match ev {
        TonEvent::Executed { master, from, .. } => {
            masters.iter().find(|(m, c)| m == master && c.is_some())?;
            // A Mandate emits for itself (`from` = the mandate) or for its owner's withdrawals.
            let registered = masters.iter().any(|(m, code)| m == emitter && code.is_none());
            (wallet_of(master, from).as_ref() == Some(emitter) || registered).then(|| (*master, ev.clone()))
        }
        TonEvent::Paid { to, .. } => masters.iter().map(|(m, _)| m).find(|m| wallet_of(m, to).as_ref() == Some(emitter)).map(|m| (*m, ev.clone())),
    }
}

/// What `build` hands to `sign`: the target contract and the internal message body.
fn built_meta(to: &Addr, value: u128) -> Value {
    json!({"to": to.raw(), "value": value.to_string()})
}

#[async_trait]
impl ChainAdapter for TonAdapter {
    fn family(&self) -> Family {
        Family::Ton
    }

    fn chain_key(&self) -> &str {
        &self.key
    }

    fn lanes(&self) -> &[Lane] {
        &self.lanes
    }

    /// R80: `pay` (op 1) ⇒ getter `get_lane_nonce` của ví người trả so với nonce đã ký. Revoke (`next == nonce + 1`
    /// là còn chờ) và mandate không trả lời (review M6).
    async fn op_consumed(&self, job: &Job) -> Result<Option<bool>> {
        let Some(op) = job.op.as_ref().filter(|o| o["op_kind"] == "pay") else { return Ok(None) };
        let s = |k: &str| op.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        let m = parse_metaop(&boc_parse(&alloy::hex::decode(s("payload").trim_start_matches("0x"))?)?)?;
        if m.op != 1 {
            return Ok(None);
        }
        let next = self.api.run_get(&Addr::parse(&s("contract"))?, "get_lane_nonce", vec![json!({"type": "num", "value": hex0x(&m.lane)})]).await?;
        let next = next.first().map(stack_num).transpose()?.unwrap_or(0) as u64;
        Ok(Some(next > m.nonce))
    }

    async fn build(&self, job: &Job, lane: usize) -> std::result::Result<Built, SimError> {
        let revert = |e: anyhow::Error| SimError::Revert(format!("{e:#}"));
        let transport = |e: anyhow::Error| SimError::Transport(format!("{e:#}"));
        let op = job.op.as_ref().ok_or_else(|| SimError::Revert("not a signed_op job".into()))?;
        let s = |k: &str| op.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        let cell = alloy::hex::decode(s("payload").trim_start_matches("0x")).map_err(|e| revert(e.into())).and_then(|b| boc_parse(&b).map_err(revert))?;
        let m = parse_metaop(&cell).map_err(revert)?;
        if hex0x(&m.digest) != s("digest").to_lowercase() {
            return Err(SimError::Revert("payload does not hash to the job digest".into()));
        }
        let contract = Addr::parse(&s("contract")).map_err(revert)?;
        if contract != m.contract || m.network != self.global_id {
            return Err(SimError::Revert("payload contract/network does not match the job".into()));
        }
        if m.valid_until <= crate::submit::now() {
            return Err(SimError::Revert("signed payload expired".into()));
        }
        let me = self.lane_wallet(lane).and_then(|w| w.address()).map_err(transport)?;
        if m.relayer.is_some_and(|r| r != me) {
            return Err(SimError::Revert("payload is bound to another relayer".into()));
        }
        let pay_meta = pay_params(&m, op).map_err(revert)?;
        let extra = op.get("extra").cloned().unwrap_or(Value::Null);
        let mut forward = 0u128;
        let body = if s("op_kind") == "mandate_pay" {
            let sig: [u8; 64] = alloy::hex::decode(s("signature").trim_start_matches("0x"))
                .map_err(|e| revert(e.into()))?
                .try_into()
                .map_err(|_| SimError::Revert("delegate signature must be 64 bytes".into()))?;
            mandate_pay_body(&cell, &sig, &me).map_err(revert)?
        } else {
            let auth = parse_auth(&s("signature")).map_err(revert)?;
            // Simulation by getters (R27): lane/nonce unused, key bound or provable, signature valid.
            let next = self.api.run_get(&contract, "get_lane_nonce", vec![json!({"type": "num", "value": hex0x(&m.lane)})]).await.map_err(transport)?;
            let next = next.first().map(stack_num).transpose().map_err(transport)?.unwrap_or(0);
            let next = next as u64;
            if next != m.nonce && !(m.op == 4 && next == m.nonce + 1) {
                return Err(SimError::Revert(format!("lane nonce is {next}, payload has {}", m.nonce)));
            }
            if let Auth::TonConnect { signature, timestamp, domain, state_init } = &auth {
                let bound = self.api.run_get(&contract, "get_owner_pubkey", vec![]).await.map_err(transport)?;
                let bound = bound.first().and_then(|v| v.get("value")).and_then(Value::as_str).unwrap_or("0x0");
                let mut pk = left_pad32(bound).map_err(revert)?;
                if pk == [0; 32] {
                    let si = state_init.as_ref().ok_or_else(|| SimError::Revert("owner key not bound and no StateInit".into()))?;
                    pk = pubkey_from_state_init(si, &m.from).map_err(revert)?;
                }
                let h = envelope_hash(&m.from, *timestamp, domain, &cell).map_err(revert)?;
                let vk = VerifyingKey::from_bytes(&pk).map_err(|_| SimError::Revert("bad owner key".into()))?;
                vk.verify_strict(&h, &Signature::from_bytes(signature)).map_err(|_| SimError::Revert("signature does not verify".into()))?;
            }
            let state_init = match &auth {
                Auth::TonConnect { state_init, .. } => state_init.clone(),
                Auth::Passkey { .. } => None,
            };
            let params = match (pay_meta, extra.get("params").and_then(Value::as_str)) {
                (Some(p), _) => Some(p),
                (None, Some(p)) => Some(boc_parse(&alloy::hex::decode(p.trim_start_matches("0x")).map_err(|e| revert(e.into()))?).map_err(revert)?),
                (None, None) => None,
            };
            let match_with = match extra.get("match_with").and_then(Value::as_str) {
                Some(h) => b32(h).map_err(revert)?,
                None => [0; 32],
            };
            // The payer signed a floor for the forward TON (review H2); the wallet refuses less.
            let floor = match m.op {
                1 if m.extra[..16] != [0; 16] => return Err(SimError::Revert("signed forward floor is not a TON amount".into())),
                1 => u128::from_be_bytes(m.extra[16..].try_into().expect("16")),
                2 => trade_forward_floor(params.as_ref().ok_or_else(|| SimError::Revert("trade without params".into()))?).map_err(revert)?.max(MIN_LEG_TON),
                4 if next == m.nonce + 1 => CANCEL_TON,
                _ => 0,
            };
            forward = extra.get("forward_nanoton").and_then(Value::as_u64).map(u128::from).unwrap_or(self.forward).max(floor);
            signed_op_body(&cell, &auth_cell(&auth).map_err(revert)?, params, state_init, &me, forward, match_with).map_err(revert)?
        };
        // Sized from THIS job's forward (review L8): the wallet wants 0.05 TON + forward.
        let value = self.attach.max(forward + 100_000_000);
        Ok(Built { job_id: job.id, body: boc_serialize(&body), valid_until: m.valid_until, meta: built_meta(&contract, value) })
    }

    async fn sign(&self, built: Built, lane: usize, sequence: u64) -> Result<Signed> {
        let to = Addr::parse(built.meta["to"].as_str().unwrap_or_default())?;
        let value: u128 = built.meta["value"].as_str().unwrap_or("0").parse()?;
        let body = boc_parse(&built.body)?;
        let w5 = self.lane_wallet(lane)?;
        let signer = self.signers.get(lane).ok_or_else(|| anyhow!("no lane {lane}"))?;
        // The lane tx expires with the subject's payload (review S14): a stuck tx never pins the seqno.
        let vu = u32::try_from(built.valid_until).unwrap_or(u32::MAX);
        let (raw, id) = w5_transfer(w5, signer, sequence as u32, vu, &to, value, body)?;
        Ok(Signed { job_id: built.job_id, tx_id: hex0x(&id), raw, valid_until: built.valid_until, sequence })
    }

    async fn submit(&self, signed: &Signed) -> Result<()> {
        self.api.post("message", json!({"boc": b64encode(&signed.raw)})).await.map(|_| ())
    }

    async fn tx_status(&self, tx_id: &str) -> Result<TxStatus> {
        let Some(tx) = self.tx_by_in_msg(&b32(tx_id)?).await? else { return Ok(TxStatus::Unknown) };
        if let Err(why) = compute_ok(&tx) {
            return Ok(TxStatus::Reverted { reason: format!("lane wallet: {why}") });
        }
        let Some(out) = tx.pointer("/out_msgs/0") else {
            return Ok(TxStatus::Reverted { reason: "lane wallet sent nothing (insufficient TON?)".into() });
        };
        let Some(child) = self.tx_by_in_msg(&api_hash(out.get("hash").unwrap_or(&Value::Null))?).await? else { return Ok(TxStatus::Pending) };
        if let Err(why) = compute_ok(&child) {
            // Anyone may relay a signed op (`relayer` = addr_none): if a copy got there first, the op ran (review L6).
            if exit_code(&child) == Some(E_NONCE) {
                if let Some(height) = self.executed_by_copy(&child, carried_digest(out)).await? {
                    // Not our tx: Odoo keeps ours and flags `landed_elsewhere`.
                    return Ok(TxStatus::Mined { height, tx_hash: None });
                }
            }
            return Ok(TxStatus::Reverted { reason: format!("contract: {why}") });
        }
        // The payer's wallet (or Mandate) emits `MetaTransactionExecuted`: its tx is the hash the indexer reports.
        let tx_hash = api_hash(child.get("hash").unwrap_or(&Value::Null)).ok().map(|h| hex0x(&h));
        // Follow the bounceable hops (where the tokens go) to the end: a bounce there sends them back (review L7).
        let mut last = child;
        for _ in 0..4 {
            let Some(next) = last.get("out_msgs").and_then(Value::as_array).and_then(|o| {
                o.iter().find(|m| m.get("bounce").and_then(Value::as_bool) == Some(true) && !m.get("destination").is_none_or(Value::is_null)).cloned()
            }) else {
                break;
            };
            let Some(t) = self.tx_by_in_msg(&api_hash(next.get("hash").unwrap_or(&Value::Null))?).await? else { return Ok(TxStatus::Pending) };
            if let Err(why) = compute_ok(&t) {
                return Ok(TxStatus::Reverted { reason: format!("{}: {why}", t.get("account").and_then(Value::as_str).unwrap_or("next hop")) });
            }
            last = t;
        }
        Ok(TxStatus::Mined { height: last.get("mc_block_seqno").and_then(Value::as_u64).unwrap_or_default(), tx_hash })
    }

    async fn sequence(&self, lane: usize) -> Result<u64> {
        let me = self.lane_wallet(lane)?.address()?;
        let v = self.api.get("walletInformation", &[("address", me.raw()), ("use_v2", "false".into())]).await;
        Ok(match v {
            Ok(v) => v.get("seqno").and_then(Value::as_u64).unwrap_or(0),
            Err(e) if format!("{e:#}").contains("404") => 0, // never deployed
            Err(e) => return Err(e),
        })
    }

    async fn final_head(&self) -> Result<Option<Head>> {
        // Masterchain blocks are final once committed (BFT).
        let v = self.api.get("masterchainInfo", &[]).await?;
        let last = v.get("last").ok_or_else(|| anyhow!("masterchainInfo.last"))?;
        let height = last.get("seqno").and_then(Value::as_u64).ok_or_else(|| anyhow!("masterchainInfo.last.seqno"))?;
        Ok(Some(Head { height, hash: hex0x(&api_hash(last.get("root_hash").unwrap_or(&Value::Null))?) }))
    }

    async fn block_hash(&self, height: u64) -> Result<String> {
        self.mc_block(height).await
    }

    async fn events(&self, from: u64, to: u64, contracts: &[String]) -> Result<Vec<Value>> {
        // Odoo's token list (raw `0:…`); anything else is not a TON master. None left ⇒ refuse rather than let
        // the cursor pass over blocks nobody filtered (review H1).
        let mut masters = Vec::new();
        for c in contracts.iter().filter_map(|c| Addr::parse(c).ok()) {
            masters.push((c, self.wallet_code(&c).await?));
        }
        if !masters.iter().any(|(_, code)| code.is_some()) {
            bail!("node_config lists no TON jetton master");
        }
        let mut out = Vec::new();
        for seqno in from..=to {
            let mut offset = 0usize;
            let mut block_hash: Option<String> = None;
            loop {
                let v = self
                    .api
                    .get("transactionsByMasterchainBlock", &[("seqno", seqno.to_string()), ("limit", "256".into()), ("offset", offset.to_string()), ("sort", "asc".into())])
                    .await?;
                let txs = v.get("transactions").and_then(Value::as_array).cloned().unwrap_or_default();
                for tx in &txs {
                    let evs = tx_events(tx)?;
                    if evs.is_empty() {
                        continue;
                    }
                    let tx_hash = hex0x(&api_hash(tx.get("hash").unwrap_or(&Value::Null))?);
                    for (log_index, emitter, ev) in evs {
                        let Some((master, ev)) = authenticate(&emitter, &ev, &masters) else { continue };
                        if block_hash.is_none() {
                            block_hash = Some(self.mc_block(seqno).await?);
                        }
                        let mut e = json!({
                            "contract": master.raw(), "block_number": seqno, "block_hash": block_hash.clone(),
                            "tx_hash": tx_hash, "log_index": log_index,
                        });
                        match ev {
                            TonEvent::Executed { from, digest, .. } => {
                                e["event"] = json!("MetaTransactionExecuted");
                                e["from"] = json!(from.raw());
                                e["digest"] = json!(hex0x(&digest));
                            }
                            TonEvent::Paid { from, to, amount, pay_ref } => {
                                e["event"] = json!("PaymentSettled");
                                e["from"] = json!(from.raw());
                                e["to"] = json!(to.raw());
                                e["amount"] = json!(amount.to_string());
                                e["entry_ref"] = json!(hex0x(&pay_ref));
                            }
                        }
                        out.push(e);
                    }
                }
                if txs.len() < 256 {
                    break;
                }
                offset += txs.len();
            }
        }
        Ok(out)
    }
}

fn clone_signer(s: &LocalSigner) -> Result<LocalSigner> {
    match s {
        LocalSigner::Ed(k) => Ok(LocalSigner::Ed(k.clone())),
        LocalSigner::Secp(_) => bail!("TON lanes need ed25519 keys (m/44'/607'/i')"),
    }
}

/// Stack numbers come as `0x…` without leading zeros.
fn left_pad32(v: &str) -> Result<[u8; 32]> {
    if !v.starts_with("0x") {
        let n: u128 = v.parse().context("stack number")?;
        let mut out = [0u8; 32];
        out[16..].copy_from_slice(&n.to_be_bytes());
        return Ok(out);
    }
    let h = v.trim_start_matches("0x");
    let h = if h.len() % 2 == 1 { format!("0{h}") } else { h.to_string() };
    let b = alloy::hex::decode(h)?;
    if b.len() > 32 {
        bail!("value wider than 32 bytes");
    }
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::Curve;

    fn vectors() -> Value {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/ton/vectors/ton-vectors.json");
        serde_json::from_str(&std::fs::read_to_string(p).expect("vectors")).expect("json")
    }

    fn cell(v: &Value, ptr: &str) -> Arc<Cell> {
        boc_parse(&alloy::hex::decode(v.pointer(ptr).unwrap().as_str().unwrap()).unwrap()).unwrap()
    }

    fn s<'a>(v: &'a Value, ptr: &str) -> &'a str {
        v.pointer(ptr).unwrap().as_str().unwrap()
    }

    #[test]
    fn metaop_vector_parses_and_hashes() {
        let v = vectors();
        let c = cell(&v, "/metaop/boc");
        assert_eq!(hex0x(&c.hash()), s(&v, "/metaop/digest"));
        let m = parse_metaop(&c).unwrap();
        assert_eq!(m.network, -239);
        assert_eq!(m.amount, 1_234_567);
        assert_eq!(m.contract.raw(), s(&v, "/metaop/contract"));
        assert_eq!(m.from.raw(), s(&v, "/metaop/from"));
        assert_eq!(m.to.raw(), s(&v, "/metaop/to"));
        assert_eq!(hex0x(&m.lane), s(&v, "/metaop/lane"));
        assert_eq!(hex0x(&m.pay_ref), s(&v, "/metaop/pay_ref"));
        assert!(m.relayer.is_none());
        // our serializer round-trips; for this tree it is byte-identical to @ton/core
        assert_eq!(alloy::hex::encode(boc_serialize(&c)), s(&v, "/metaop/boc"));
    }

    #[test]
    fn envelope_state_init_and_signature() {
        let v = vectors();
        let op = cell(&v, "/metaop/boc");
        let owner = Addr::parse(s(&v, "/payer_w5/address")).unwrap();
        assert_eq!(hex0x(&domain_cell(s(&v, "/sign_data/domain")).unwrap().hash()), s(&v, "/sign_data/domain_cell_hash"));
        let ts = v.pointer("/sign_data/timestamp").unwrap().as_u64().unwrap();
        let h = envelope_hash(&owner, ts, s(&v, "/sign_data/domain"), &op).unwrap();
        assert_eq!(hex0x(&h), s(&v, "/sign_data/envelope_hash"));
        let pk = pubkey_from_state_init(&cell(&v, "/payer_w5/state_init_boc"), &owner).unwrap();
        assert_eq!(alloy::hex::encode(pk), s(&v, "/sign_data/pubkey"));
        assert!(pubkey_from_state_init(&cell(&v, "/payer_w5/state_init_boc"), &Addr::parse(s(&v, "/metaop/to")).unwrap()).is_err());
        let sig: [u8; 64] = alloy::hex::decode(s(&v, "/sign_data/signature")).unwrap().try_into().unwrap();
        VerifyingKey::from_bytes(&pk).unwrap().verify_strict(&h, &Signature::from_bytes(&sig)).unwrap();
        // the auth cell the relayer builds from the connector JSON equals the contract test's
        let json = json!({"kind": "ton_connect", "signature": b64encode(&sig), "timestamp": ts,
                          "domain": s(&v, "/sign_data/domain"), "state_init": b64encode(&alloy::hex::decode(s(&v, "/payer_w5/state_init_boc")).unwrap())});
        let auth = parse_auth(&json.to_string()).unwrap();
        assert_eq!(hex0x(&auth_cell(&auth).unwrap().hash()), s(&v, "/sign_data/auth_cell_hash"));
        let Auth::TonConnect { state_init, .. } = &auth else { panic!() };
        // SignedOp body (Tact layout) equals the @ton/core one
        let lane = Addr::parse(s(&v, "/lane_w5/address")).unwrap();
        let body = signed_op_body(&op, &auth_cell(&auth).unwrap(), None, state_init.clone(), &lane, 0, [0; 32]).unwrap();
        assert_eq!(hex0x(&body.hash()), s(&v, "/signed_op/hash"));
    }

    #[test]
    fn w5r1_lane_wallet_and_external_message_match_ton_core() {
        let v = vectors();
        let seed: [u8; 32] = alloy::hex::decode(s(&v, "/lane_w5/seed")).unwrap().try_into().unwrap();
        let signer = LocalSigner::new(Curve::Ed25519, &seed).unwrap();
        assert_eq!(alloy::hex::encode(signer.public_key()), s(&v, "/lane_w5/pubkey"));
        let w5 = W5::new(signer.public_key().try_into().unwrap(), -239).unwrap();
        assert_eq!(w5.wallet_id as u64, v.pointer("/lane_w5/wallet_id").unwrap().as_u64().unwrap());
        assert_eq!(w5.address().unwrap().raw(), s(&v, "/lane_w5/address"));
        let to = Addr::parse(s(&v, "/jetton/payer_wallet")).unwrap();
        let body = cell(&v, "/signed_op/boc");
        let value: u128 = s(&v, "/lane_w5/value").parse().unwrap();
        assert_eq!(hex0x(&internal_message(&to, value, body.clone()).unwrap().hash()), s(&v, "/lane_w5/relaxed_hash"));
        let (boc, id) = w5_transfer(&w5, &signer, 0, 1_800_000_300, &to, value, body).unwrap();
        assert_eq!(hex0x(&boc_parse(&boc).unwrap().hash()), s(&v, "/lane_w5/ext_hash"));
        assert_eq!(hex0x(&id), s(&v, "/lane_w5/ext_hash"));
    }

    #[test]
    fn events_decode() {
        let v = vectors();
        let Some(TonEvent::Executed { master, from, digest }) = decode_event(&cell(&v, "/events/mte_boc")).unwrap() else { panic!() };
        assert_eq!(master.raw(), s(&v, "/jetton/master"));
        assert_eq!(from.raw(), s(&v, "/payer_w5/address"));
        assert_eq!(hex0x(&digest), s(&v, "/metaop/digest"));
        let Some(TonEvent::Paid { amount, pay_ref, to, .. }) = decode_event(&cell(&v, "/events/ps_boc")).unwrap() else { panic!() };
        assert_eq!((amount, hex0x(&pay_ref), to.raw()), (1_234_567, s(&v, "/metaop/pay_ref").to_string(), s(&v, "/metaop/to").to_string()));
        // a TON Center transaction carrying it as an external-out message
        let tx = json!({"account": s(&v, "/jetton/payer_wallet").to_uppercase(), "out_msgs": [
            {"destination": "0:" .to_string() + &"11".repeat(32), "message_content": {"body": b64encode(&alloy::hex::decode(s(&v, "/events/ps_boc")).unwrap())}},
            {"destination": null, "message_content": {"body": b64encode(&alloy::hex::decode(s(&v, "/events/mte_boc")).unwrap())}}]});
        let evs = tx_events(&tx).unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].0, 1);
        assert_eq!(evs[0].1.raw(), s(&v, "/jetton/payer_wallet"));
    }

    #[test]
    fn jetton_wallet_code_and_addresses() {
        let v = vectors();
        let code = cell(&v, "/jetton/wallet_code_boc");
        assert_eq!(hex0x(&code.hash()), s(&v, "/jetton/wallet_code_hash"));
        assert_eq!(code.depth() as u64, v.pointer("/jetton/wallet_code_depth").unwrap().as_u64().unwrap());
        let f = Addr::parse("EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N").unwrap();
        assert_eq!(f.raw(), "0:83dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8");
        assert!(Addr::parse("EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2A").is_err());
    }

    #[test]
    fn base64_and_stack_helpers() {
        for n in 0..10 {
            let d: Vec<u8> = (0..n).collect();
            assert_eq!(b64decode(&b64encode(&d)).unwrap(), d);
        }
        assert_eq!(b64encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(stack_num(&json!({"type": "num", "value": "0x1f"})).unwrap(), 31);
        assert_eq!(stack_num(&json!({"type": "num", "value": "7"})).unwrap(), 7);
        assert_eq!(left_pad32("0x1").unwrap()[31], 1);
        assert_eq!(api_hash(&json!(b64encode(&[7u8; 32]))).unwrap(), [7u8; 32]);
    }

    #[test]
    fn passkey_auth_cell_splits_client_data() {
        let digest = [0xffu8; 32];
        let challenge = "_".repeat(43);
        let cdj = format!("{CDJ_PREFIX}{challenge}\",\"origin\":\"https://pay.example\",\"crossOrigin\":false{}}}", ",\"x\":\"".to_string() + &"y".repeat(120) + "\"");
        let a = Auth::Passkey { r: [1; 32], s: [2; 32], authenticator_data: vec![0; 37], client_data_json: cdj };
        let c = auth_cell(&a).unwrap();
        assert_eq!(c.refs().len(), 2);
        assert_eq!(c.refs()[1].refs().len(), 1, "long client data spills into a second cell");
        let _ = digest;
        assert!(auth_cell(&Auth::Passkey { r: [1; 32], s: [2; 32], authenticator_data: vec![0; 37], client_data_json: "{}".into() }).is_err());
    }

    #[test]
    fn wallet_address_without_rpc_matches_the_contract() {
        let v = vectors();
        let code = cell(&v, "/jetton/wallet_code_boc");
        let (owner, master) = (Addr::parse(s(&v, "/metaop/from")).unwrap(), Addr::parse(s(&v, "/jetton/master")).unwrap());
        assert_eq!(jetton_wallet_address(&owner, &master, &code.hash(), code.depth()).unwrap().raw(), s(&v, "/jetton/payer_wallet"));
    }

    /// Review M3 + L10: authentication is local (no RPC per event), a forged emitter, an unregistered master and an
    /// unregistered Mandate are skipped, and one transaction cannot make us decode more than a handful of events.
    #[test]
    fn events_are_authenticated_locally_and_capped() {
        let v = vectors();
        let code = cell(&v, "/jetton/wallet_code_boc");
        let (payer, master) = (Addr::parse(s(&v, "/metaop/from")).unwrap(), Addr::parse(s(&v, "/jetton/master")).unwrap());
        let wallet = Addr::parse(s(&v, "/jetton/payer_wallet")).unwrap();
        let mandate = Addr { wc: 0, hash: [0x4d; 32] };
        let masters = vec![(master, Some((code.hash(), code.depth())))];
        let exe = TonEvent::Executed { master, from: payer, digest: [1; 32] };
        assert_eq!(authenticate(&wallet, &exe, &masters), Some((master, exe.clone())));
        assert_eq!(authenticate(&Addr { wc: 0, hash: [9; 32] }, &exe, &masters), None, "forged emitter");
        assert_eq!(authenticate(&wallet, &TonEvent::Executed { master: mandate, from: payer, digest: [1; 32] }, &masters), None, "unregistered master");
        assert_eq!(authenticate(&mandate, &exe, &masters), None, "unregistered mandate");
        let with_mandate = vec![masters[0], (mandate, None)];
        assert_eq!(authenticate(&mandate, &exe, &with_mandate), Some((master, exe.clone())));
        let paid = TonEvent::Paid { from: mandate, to: payer, amount: 5, pay_ref: [2; 32] };
        assert_eq!(authenticate(&wallet, &paid, &masters), Some((master, paid.clone())));
        assert_eq!(authenticate(&mandate, &paid, &with_mandate), None, "a Mandate never emits PaymentSettled");
        let body = b64encode(&alloy::hex::decode(s(&v, "/events/mte_boc")).unwrap());
        let flood: Vec<Value> = (0..255).map(|_| json!({"destination": null, "message_content": {"body": body}})).collect();
        assert_eq!(tx_events(&json!({"account": wallet.raw(), "out_msgs": flood})).unwrap().len(), MAX_EVENTS_PER_TX);
    }

    // ------------------------------------------------------------ a TON Center v3 stand-in for build/tx_status

    #[derive(Default)]
    struct Fake {
        getters: HashMap<String, Value>,
        by_msg: HashMap<String, Value>,
        by_account: Vec<Value>,
    }

    async fn fake_api(f: Fake) -> String {
        use axum::extract::{Path, Query, State};
        type S = Arc<std::sync::Mutex<Fake>>;
        async fn h(State(s): State<S>, Path(path): Path<String>, Query(q): Query<HashMap<String, String>>, body: String) -> axum::Json<Value> {
            let f = s.lock().unwrap();
            axum::Json(match path.as_str() {
                "runGetMethod" => {
                    let b: Value = serde_json::from_str(&body).unwrap();
                    f.getters.get(b["method"].as_str().unwrap()).cloned().unwrap_or(json!({"exit_code": 11, "stack": []}))
                }
                "transactionsByMessage" => json!({"transactions": f.by_msg.get(&q["msg_hash"]).into_iter().collect::<Vec<_>>()}),
                "transactions" => json!({"transactions": f.by_account}),
                _ => json!({}),
            })
        }
        let app = axum::Router::new().route("/api/v3/{path}", axum::routing::any(h)).with_state(Arc::new(std::sync::Mutex::new(f)));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        url
    }

    fn adapter(url: &str) -> TonAdapter {
        let cfg = ChainCfg {
            family: "ton".into(),
            network: Some("-239".into()),
            evm_chain_number: 0,
            rpc_urls: vec![url.into()],
            signer_key_env: String::new(),
            private_key: None,
            lanes: vec![0],
            params: toml::Table::new(),
            finality: crate::config::FinalityCfg { mode: "depth".into(), depth: 0, quorum: 1 },
            dex: None,
            poll_ms: 200,
            stuck_after_secs: 60,
            max_gas_per_tx: 0,
            max_fee_cap_gwei: 0,
            ..Default::default()
        };
        TonAdapter::new(&cfg, &[LocalSigner::new(Curve::Ed25519, &[0x11; 32]).unwrap()]).unwrap()
    }

    fn num(n: u128) -> Value {
        json!({"exit_code": 0, "stack": [{"type": "num", "value": format!("0x{n:x}")}]})
    }

    /// The forward TON a built `SignedOp` carries, and the TON the lane attaches.
    fn forward_and_value(b: &Built) -> (u128, u128) {
        let body = boc_parse(&b.body).unwrap();
        let mut t = body.refs()[2].parser();
        if t.bit().unwrap() {
            t.reference().unwrap();
        }
        if t.bit().unwrap() {
            t.reference().unwrap();
        }
        t.addr().unwrap();
        (t.coins().unwrap(), b.meta["value"].as_str().unwrap().parse().unwrap())
    }

    /// Review H2 + L8: the node attaches at least the forward TON the payer signed, a job's own `forward_nanoton`
    /// when larger, and sizes the lane's TON from that job's forward (not the node default).
    #[tokio::test]
    async fn build_attaches_the_signed_forward_floor_and_sizes_value_per_job() {
        let url = fake_api(Fake { getters: HashMap::from([("get_lane_nonce".into(), num(0)), ("get_owner_pubkey".into(), num(0))]), ..Default::default() }).await;
        let a = adapter(&url);
        let key = LocalSigner::new(Curve::Ed25519, &[1; 32]).unwrap();
        let w5 = W5::new(key.public_key().try_into().unwrap(), -239).unwrap();
        let (from, contract) = (w5.address().unwrap(), Addr { wc: 0, hash: [0xc0; 32] });
        let floor: u128 = 300_000_000;
        let mut extra = [0u8; 32];
        extra[16..].copy_from_slice(&floor.to_be_bytes());
        let vu = crate::submit::now() + 600;
        let op = Builder::new()
            .bytes(b"scaas.metaop.v1")
            .int(-239, 32)
            .uint(1, 8)
            .uint(10, 128)
            .uint(0, 64)
            .uint(vu as u128, 64)
            .addr(Some(&contract))
            .reference(Builder::new().addr(Some(&from)).addr(Some(&Addr { wc: 0, hash: [2; 32] })).addr(None).end().unwrap())
            .reference(Builder::new().bytes(&[3; 32]).bytes(&[4; 32]).bytes(&extra).end().unwrap())
            .end()
            .unwrap();
        let ts = 1_800_000_000u64;
        let sig = key.sign(&envelope_hash(&from, ts, "pay.example", &op).unwrap()).unwrap();
        let signature = json!({"kind": "ton_connect", "signature": b64encode(&sig), "timestamp": ts, "domain": "pay.example",
                               "state_init": b64encode(&boc_serialize(&w5.state_init().unwrap()))});
        let job = |extra: Value| -> Job {
            serde_json::from_value(json!({"id": 1, "kind": "signed_op", "op": {"contract": contract.raw(), "op_kind": "pay",
                "payload": alloy::hex::encode(boc_serialize(&op)), "signature": signature.to_string(), "digest": hex0x(&op.hash()), "extra": extra}}))
            .unwrap()
        };
        let b = a.build(&job(json!({})), 0).await.unwrap();
        assert_eq!(forward_and_value(&b), (floor, floor + 100_000_000), "the signed floor, not the node default 0");
        let b = a.build(&job(json!({"forward_nanoton": 500_000_000u64})), 0).await.unwrap();
        assert_eq!(forward_and_value(&b), (500_000_000, 600_000_000), "this job's forward sizes the value");
    }

    /// R80 + review M6: only `pay` (op 1) answers from `get_lane_nonce`; revoke and mandate ops are unknown (None).
    #[tokio::test]
    async fn op_consumed_reads_the_lane_nonce_for_pay_only() {
        let contract = Addr { wc: 0, hash: [0xc0; 32] };
        let op = |code: u128| {
            Builder::new().bytes(b"scaas.metaop.v1").int(-239, 32).uint(code, 8).uint(10, 128).uint(5, 64).uint(1 << 40, 64)
                .addr(Some(&contract))
                .reference(Builder::new().addr(Some(&Addr { wc: 0, hash: [1; 32] })).addr(Some(&Addr { wc: 0, hash: [2; 32] })).addr(None).end().unwrap())
                .reference(Builder::new().bytes(&[3; 32]).bytes(&[4; 32]).bytes(&[0; 32]).end().unwrap())
                .end()
                .unwrap()
        };
        let job = |kind: &str, code: u128| -> Job {
            serde_json::from_value(json!({"id": 1, "kind": "signed_op", "op": {"contract": contract.raw(), "op_kind": kind,
                "payload": alloy::hex::encode(boc_serialize(&op(code)))}})).unwrap()
        };
        for (next, want) in [(6, Some(true)), (5, Some(false))] {
            let a = adapter(&fake_api(Fake { getters: HashMap::from([("get_lane_nonce".into(), num(next))]), ..Default::default() }).await);
            assert_eq!(a.op_consumed(&job("pay", 1)).await.unwrap(), want, "next {next}");
            assert_eq!(a.op_consumed(&job("pay", 4)).await.unwrap(), None, "revoke");
            assert_eq!(a.op_consumed(&job("mandate_pay", 1)).await.unwrap(), None);
        }
    }

    /// Review L6 + L7: the lane's tx is followed to the hop that credits the payee (its bounce = not paid), and a
    /// nonce failure whose op a copy already executed is reported as mined.
    #[tokio::test]
    async fn tx_status_follows_the_tokens_and_spots_a_front_run_copy() {
        let v = vectors();
        let (lane_tx, h1, h2) = ([0x0au8; 32], [0x01u8; 32], [0x02u8; 32]);
        let wallet = s(&v, "/jetton/payer_wallet").to_string();
        let ok = json!({"compute_ph": {"success": true, "exit_code": 0}});
        let failed = |code: i64| json!({"aborted": true, "compute_ph": {"success": false, "exit_code": code}});
        let signed_op = b64encode(&alloy::hex::decode(s(&v, "/signed_op/boc")).unwrap());
        let lane = json!({"account": "0:".to_string() + &"11".repeat(32), "description": ok, "out_msgs": [
            {"hash": b64encode(&h1), "destination": wallet, "bounce": true, "message_content": {"body": signed_op}}]});
        let payer_tx = [0x0bu8; 32];
        let payer = |d: Value| json!({"account": wallet, "hash": b64encode(&payer_tx), "description": d, "mc_block_seqno": 5, "out_msgs": [
            {"hash": b64encode(&h2), "destination": "0:".to_string() + &"22".repeat(32), "bounce": true},
            {"hash": b64encode(&[3; 32]), "destination": "0:".to_string() + &"11".repeat(32), "bounce": false}]});
        let payee = |d: Value| json!({"account": "0:".to_string() + &"22".repeat(32), "description": d, "mc_block_seqno": 6, "out_msgs": [
            {"hash": b64encode(&[4; 32]), "destination": "0:".to_string() + &"33".repeat(32), "bounce": false}]});
        let id = hex0x(&lane_tx);
        let at = |m: Vec<(&[u8; 32], Value)>| m.into_iter().map(|(k, t)| (alloy::hex::encode(k), t)).collect::<HashMap<_, _>>();

        let id = id.as_str();
        let st = |f: Fake| async move { adapter(&fake_api(f).await).tx_status(id).await.unwrap() };
        let pending = st(Fake { by_msg: at(vec![(&lane_tx, lane.clone()), (&h1, payer(ok.clone()))]), ..Default::default() }).await;
        assert!(matches!(pending, TxStatus::Pending), "payee hop not seen yet: {pending:?}");
        let bounced = st(Fake { by_msg: at(vec![(&lane_tx, lane.clone()), (&h1, payer(ok.clone())), (&h2, payee(failed(-14)))]), ..Default::default() }).await;
        assert!(matches!(bounced, TxStatus::Reverted { .. }), "payee hop bounced: {bounced:?}");
        let mined = st(Fake { by_msg: at(vec![(&lane_tx, lane.clone()), (&h1, payer(ok.clone())), (&h2, payee(ok.clone()))]), ..Default::default() }).await;
        // The tx id is the lane wallet's external message; Odoo hears of the payer wallet's tx (it emits the event).
        assert_eq!(mined, TxStatus::Mined { height: 6, tx_hash: Some(hex0x(&payer_tx)) });

        let mte = b64encode(&alloy::hex::decode(s(&v, "/events/mte_boc")).unwrap());
        let copy = json!({"account": wallet, "description": ok, "mc_block_seqno": 4, "out_msgs": [{"destination": null, "message_content": {"body": mte}}]});
        let nonce_used = at(vec![(&lane_tx, lane.clone()), (&h1, payer(failed(E_NONCE)))]);
        let r = st(Fake { by_msg: nonce_used.clone(), by_account: vec![copy], ..Default::default() }).await;
        assert_eq!(r, TxStatus::Mined { height: 4, tx_hash: None }, "a copy executed our digest: not our tx");
        let r = st(Fake { by_msg: nonce_used, ..Default::default() }).await;
        assert!(matches!(r, TxStatus::Reverted { .. }), "{r:?}");
    }

    // ---------------------------------------------------------------- CTR-MTX-26 (spec §6.2, §9)

    fn hexv(v: &Value) -> Vec<u8> {
        alloy::hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
    }

    /// A signed `OP_PAY` of `from` (the W5R1 of key `[1; 32]`) with these refs, as the job JSON the node receives.
    fn pay_job(pay_ref: [u8; 32], lane: [u8; 32], nonce: u64, op_code: u128, more: Value) -> (Job, MetaOp) {
        let key = LocalSigner::new(Curve::Ed25519, &[1; 32]).unwrap();
        let w5 = W5::new(key.public_key().try_into().unwrap(), -239).unwrap();
        let (from, contract) = (w5.address().unwrap(), Addr { wc: 0, hash: [0xc0; 32] });
        let op = Builder::new()
            .bytes(b"scaas.metaop.v1").int(-239, 32).uint(op_code, 8).uint(10, 128).uint(nonce as u128, 64)
            .uint((crate::submit::now() + 600) as u128, 64).addr(Some(&contract))
            .reference(Builder::new().addr(Some(&from)).addr(Some(&Addr { wc: 0, hash: [2; 32] })).addr(None).end().unwrap())
            .reference(Builder::new().bytes(&pay_ref).bytes(&lane).bytes(&[0; 32]).end().unwrap())
            .end()
            .unwrap();
        let ts = 1_800_000_000u64;
        let sig = key.sign(&envelope_hash(&from, ts, "pay.example", &op).unwrap()).unwrap();
        let signature = json!({"kind": "ton_connect", "signature": b64encode(&sig), "timestamp": ts, "domain": "pay.example",
                               "state_init": b64encode(&boc_serialize(&w5.state_init().unwrap()))});
        let mut o = json!({"contract": contract.raw(), "op_kind": "pay", "payload": alloy::hex::encode(boc_serialize(&op)),
                           "signature": signature.to_string(), "digest": hex0x(&op.hash())});
        o.as_object_mut().unwrap().extend(more.as_object().unwrap().clone());
        (serde_json::from_value(json!({"id": 1, "kind": "signed_op", "op": o})).unwrap(), parse_metaop(&op).unwrap())
    }

    /// `SignedOp.params` of a built body (tail ref: `params:Maybe ^Cell`).
    fn built_params(b: &Built) -> Option<Arc<Cell>> {
        let body = boc_parse(&b.body).unwrap();
        let mut t = body.refs()[2].parser();
        t.bit().unwrap().then(|| t.reference().unwrap())
    }

    /// Rule 1 (every row of the shared vectors in Rust) and the pay-meta job: `params = salt:uint256 ^meta` byte for byte
    /// the cell `vectors.spec.ts` built with @ton/core (`/pay_meta/params_boc`), checked before any getter.
    #[tokio::test]
    async fn ton_pay_meta_job_builds_params() {
        let rows: Vec<Value> = serde_json::from_str(include_str!("../../../smartcontracts/vectors/metatx/paymeta.json")).unwrap();
        assert_eq!(rows.len(), 6);
        for r in &rows {
            let id = meta_pay_id(&hexv(&r["salt"]), &hexv(&r["meta"]));
            assert_eq!((id.to_vec(), pay_lane(&id).to_vec()), (hexv(&r["payId"]), hexv(&r["payLane"])), "{}", r["name"]);
        }
        let v = vectors();
        let pm = &v["pay_meta"];
        let (salt, meta) = (hexv(&pm["salt"]), hexv(&pm["meta"]));
        assert_eq!(snake(&meta).unwrap().hash(), cell(&v, "/pay_meta/meta_boc").hash(), "snake chunking = @ton/core's");
        let id: [u8; 32] = hexv(&pm["pay_id"]).try_into().unwrap();
        assert_eq!(hex0x(&pay_lane(&id)), s(&v, "/pay_meta/pay_lane"));
        let more = json!({"kind": "pay_meta", "salt": pm["salt"], "meta": pm["meta"]});

        let url = fake_api(Fake { getters: HashMap::from([("get_lane_nonce".into(), num(0)), ("get_owner_pubkey".into(), num(0))]), ..Default::default() }).await;
        let a = adapter(&url);
        let (job, _) = pay_job(id, pay_lane(&id), 0, 1, more.clone());
        let b = a.build(&job, 0).await.unwrap();
        assert_eq!(hex0x(&built_params(&b).unwrap().hash()), s(&v, "/pay_meta/params_hash"));
        assert_eq!(alloy::hex::encode(boc_serialize(&built_params(&b).unwrap())), s(&v, "/pay_meta/params_boc"));
        // the plain pay still sends params = null
        let (plain, _) = pay_job(id, pay_lane(&id), 0, 1, json!({}));
        assert!(built_params(&a.build(&plain, 0).await.unwrap()).is_none());
        // the `PaymentMeta` event is not one the indexer decodes yet (T17), and never an error
        assert_eq!(decode_event(&cell(&v, "/events/pm_boc")).unwrap(), None);

        // fail closed before any getter: an adapter whose API is unreachable still refuses each with its reason
        let dead = adapter("http://127.0.0.1:9");
        let refused = |job: Job| {
            let dead = &dead;
            async move {
                match dead.build(&job, 0).await {
                    Err(SimError::Revert(e)) => e,
                    other => panic!("{other:?}"),
                }
            }
        };
        let with = |k: &str, val: Value| {
            let mut m = more.clone();
            m[k] = val;
            m
        };
        let tail = format!("{}00", pm["meta"].as_str().unwrap());
        assert!(refused(pay_job(id, pay_lane(&id), 0, 1, with("meta", json!(tail))).0).await.contains("metaPayId"), "meta does not hash to pay_ref");
        assert!(refused(pay_job(id, pay_lane(&id), 0, 1, with("salt", json!("0x01"))).0).await.contains("32 bytes"));
        assert!(refused(pay_job(id, [9; 32], 0, 1, more.clone()).0).await.contains("payLane"), "lane");
        assert!(refused(pay_job(id, pay_lane(&id), 1, 1, more.clone()).0).await.contains("payLane"), "nonce");
        assert!(refused(pay_job(id, pay_lane(&id), 0, 2, more.clone()).0).await.contains("not pay"), "a trade op");
        assert!(refused(pay_job(id, pay_lane(&id), 0, 1, json!({"kind": "pay_meta", "meta": pm["meta"]})).0).await.contains("op.salt missing"));
        // the cap: a meta that hashes right but is one byte above it
        let big = vec![0x61u8; MAX_PAY_META_BYTES + 1];
        let big_id = meta_pay_id(&salt, &big);
        let e = refused(pay_job(big_id, pay_lane(&big_id), 0, 1, with("meta", json!(alloy::hex::encode(&big)))).0).await;
        assert!(e.contains("2048 B cap"), "{e}");
        let at_cap = vec![0x61u8; MAX_PAY_META_BYTES];
        let cap_id = meta_pay_id(&salt, &at_cap);
        let (job, m) = pay_job(cap_id, pay_lane(&cap_id), 0, 1, with("meta", json!(alloy::hex::encode(&at_cap))));
        assert_eq!(pay_params(&m, job.op.as_ref().unwrap()).unwrap().unwrap().refs()[0].hash(), snake(&at_cap).unwrap().hash());
        // unknown kinds and a plain pay with params are refused, never sent as a plain pay
        for k in ["pay-meta", "pay", "", "relay_fee"] {
            let e = refused(pay_job(id, pay_lane(&id), 0, 1, with("kind", json!(k))).0).await;
            assert!(e.contains("unknown op.kind"), "{k}: {e}");
        }
        let e = refused(pay_job(id, pay_lane(&id), 0, 1, json!({"extra": {"params": s(&v, "/pay_meta/params_boc")}})).0).await;
        assert!(e.contains("plain pay carries no params"), "{e}");
    }

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn boc_parser_never_panics(data in proptest::collection::vec(any::<u8>(), 0..400)) {
                let _ = boc_parse(&data);
                let mut with_magic = vec![0xb5, 0xee, 0x9c, 0x72];
                with_magic.extend(&data);
                let _ = boc_parse(&with_magic);
            }

            #[test]
            fn cells_round_trip(bits in proptest::collection::vec(any::<bool>(), 0..1023), nrefs in 0usize..4, inner in proptest::collection::vec(any::<u8>(), 0..100)) {
                let mut b = Builder::new();
                for x in &bits { b = b.bit(*x); }
                for i in 0..nrefs { b = b.reference(Builder::new().bytes(&inner).uint(i as u128, 3).end().unwrap()); }
                let c = b.end().unwrap();
                let back = boc_parse(&boc_serialize(&c)).unwrap();
                prop_assert_eq!(back.hash(), c.hash());
                prop_assert_eq!(back.bit_len(), bits.len());
            }

            /// The pay-meta job on untrusted input (rule 4): no panic, whatever the JSON.
            #[test]
            fn pay_meta_job_never_panics(kind in 0usize..4, salt in "\\PC{0,80}", meta in proptest::collection::vec(any::<u8>(), 0..300),
                                         hexy in any::<bool>(), op_code in 0u8..6, nonce in 0u64..2) {
                let v = vectors();
                let mut m = parse_metaop(&cell(&v, "/metaop/boc")).unwrap();
                m.op = op_code;
                m.nonce = nonce;
                let salt_v = if hexy { json!(alloy::hex::encode(salt.as_bytes())) } else { json!(salt) };
                let kind_v = [json!("pay_meta"), json!("other"), Value::Null, json!(7)][kind].clone();
                let o = json!({"kind": kind_v, "salt": salt_v, "meta": alloy::hex::encode(&meta), "extra": {"params": salt}});
                let _ = pay_params(&m, &o);
                let id = meta_pay_id(salt.as_bytes(), &meta);
                m.pay_ref = id;
                m.lane = pay_lane(&id);
                let _ = pay_params(&m, &o);
            }

            #[test]
            fn decoders_never_panic(body in proptest::collection::vec(any::<u8>(), 0..127), kind in 0u8..3, s in ".{0,200}") {
                if let Ok(c) = Builder::new().uint(if kind == 0 { EV_MTE } else { EV_PAID }, 32).bytes(&body).end() {
                    let _ = decode_event(&c);
                    let _ = parse_metaop(&c);
                }
                let _ = parse_auth(&s);
                let _ = tx_events(&json!({"account": s, "out_msgs": [{"destination": null, "message_content": {"body": s}}]}));
                let _ = api_hash(&json!(s));
                let _ = stack_num(&json!({"value": s}));
            }
        }
    }
}
