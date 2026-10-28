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
            .map(|&r| if r > i { built.get(r).cloned().flatten().ok_or_else(|| anyhow!("bad ref")) } else { Err(anyhow!("BOC ref order")) })
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

/// The default `max_pay_meta_bytes` (spec §9, `params.max_pay_meta_bytes`): far below what a lane can carry on TON
/// (measured, `jetton.spec.ts` › meta size limit: 38,100 B = 300 snake cells settle in @ton/sandbox 0.45.0; config
/// param 43 bounds the external message at 65,535 B and depth 512).
pub const MAX_PAY_META_BYTES: usize = crate::config::DEFAULT_MAX_PAY_META_BYTES;
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
pub fn pay_params(m: &MetaOp, o: &Value, max_meta: usize) -> Result<Option<Arc<Cell>>> {
    // the one kind rule (`adapter::op_kind`): a present non-string or unknown kind is refused, never a plain pay
    match crate::adapter::op_kind(o, &crate::adapter::PAY_KINDS)? {
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
            if meta.len() > max_meta {
                bail!("meta is {} B, above max_pay_meta_bytes {max_meta}", meta.len());
            }
            let id = meta_pay_id(&salt, &meta);
            if m.pay_ref != id || m.lane != pay_lane(&id) || m.nonce != 0 {
                bail!("pay-meta: pay_ref / lane / nonce are not metaPayId(salt, meta) / payLane(pay_ref) / 0");
            }
            Ok(Some(Builder::new().bytes(&salt).reference(snake(&meta)?).end()?))
        }
        Some(k) => bail!("op.kind {k:?} is not a pay op's params"),
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

// ---------------------------------------------------------------------- CTR-MTX-27 (spec §7.2 TON row, §9)

pub const OP_RELAY_CALL: u128 = 0x5b0a1d30;
pub const OP_RELAY_REFUND: u128 = 0x5b0a1d31;
// The router's events identify OUR relay's outcome (`settled_event`, `tx_status`); the indexer does not join them to
// the escrow's `PaymentSettled`: the release / refund lands in a later transaction, often a later range, after that
// row reached Odoo (T17, recorded).
pub const EV_RELAY_FEE_PAID: u128 = 0x9b1c0d05;
pub const EV_RELAY_FEE_REFUNDED: u128 = 0x9b1c0d06;
/// The served fee-less entries (relayfee.tact `servedCall`): the wallet's `revoke` / `set_key`, the Mandate's `revoke`.
const SERVED_OPS: [u8; 2] = [4, 5];
/// The `deadline` the node sets on a `RelayCall`: inside the router's `RELAY_TIMEOUT` (3,600 s).
const RELAY_DEADLINE_S: u64 = 600;
/// A sent `RelayRefund` that has not settled the escrow after this long is sent again.
const RELAY_REFUND_RETRY_S: u64 = 120;

/// common.tact `LANE_TTL`: the jetton wallet refuses a MetaOp valid further ahead (`E_TTL`).
const LANE_TTL_S: u64 = 2_592_000;

/// The `SignedOp` fields (Tact layout, `signed_op_body`): `(op, auth, params, state_init, responseDestination, forwardTon)`.
pub fn parse_signed_op(c: &Arc<Cell>) -> Result<(Arc<Cell>, Arc<Cell>, Option<Arc<Cell>>, Option<Arc<Cell>>, Addr, u128)> {
    let mut s = c.parser();
    if s.uint(32)? != OP_SIGNED {
        bail!("not a SignedOp");
    }
    let (op, auth, tail) = (s.reference()?, s.reference()?, s.reference()?);
    s.end()?;
    let mut t = tail.parser();
    let params = if t.bit()? { Some(t.reference()?) } else { None };
    let state_init = if t.bit()? { Some(t.reference()?) } else { None };
    let response = t.addr()?.ok_or_else(|| anyhow!("SignedOp without responseDestination"))?;
    let forward = t.coins()?;
    t.b256()?;
    t.end()?;
    Ok((op, auth, params, state_init, response, forward))
}

/// A `SignedOp.auth` cell back to `Auth` (the inverse of `auth_cell`). The TON Connect domain must be the TEP-81 wire
/// form of a domain. A passkey's fields are not read: the node does not check P-256 (as for a passkey payment).
pub fn auth_of_cell(c: &Arc<Cell>, state_init: Option<Arc<Cell>>) -> Result<Auth> {
    let mut a = c.parser();
    match a.uint(8)? {
        0 => {
            let signature: [u8; 64] = a.bytes(64)?.try_into().expect("64");
            let timestamp = a.uint(64)? as u64;
            let d = a.reference()?;
            a.end()?;
            let (mut wire, mut next) = (Vec::new(), Some(d.clone()));
            while let Some(c) = next {
                let mut p = c.parser();
                wire.extend(p.bytes(p.remaining() / 8)?);
                next = c.refs().first().cloned();
            }
            let domain = String::from_utf8(wire)?.split('\0').filter(|l| !l.is_empty()).rev().collect::<Vec<_>>().join(".");
            if domain_cell(&domain)?.hash() != d.hash() {
                bail!("the auth domain is not a TEP-81 wire form");
            }
            Ok(Auth::TonConnect { signature, timestamp, domain, state_init })
        }
        1 => Ok(Auth::Passkey { r: [0; 32], s: [0; 32], authenticator_data: Vec::new(), client_data_json: String::new() }),
        k => bail!("unknown auth kind {k}"),
    }
}

/// `keccak256("scaas.relayfee" ‖ global id:int32 ‖ target wc:int8 ‖ target hash ‖ cellHash(call) ‖ salt)`
/// (relayfee.tact `relayRef`): the call by its representation hash, so every ref counts.
pub fn relay_ref(global_id: i32, target: &Addr, call: &Arc<Cell>, salt: &[u8; 32]) -> [u8; 32] {
    keccak(&[b"scaas.relayfee", &global_id.to_be_bytes(), &[target.wc as i8 as u8], &target.hash, &call.hash(), salt])
}

/// The router's escrow key of `(payer, ref)`: the hash of `from:MsgAddress ref:uint256`.
pub fn escrow_key(from: &Addr, r: &[u8; 32]) -> Result<[u8; 32]> {
    Ok(Builder::new().addr(Some(from)).bytes(r).end()?.hash())
}

/// `RelayCall` exactly as Tact lays it out: `op target ^code ^data ^[ ^call salt payWallet ^payOp ^payAuth
/// payStateInit:Maybe ^Cell master deadline:uint32 ]` (`code`, `data` = the target's StateInit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCall {
    pub target: Addr,
    pub target_code: Arc<Cell>,
    pub target_data: Arc<Cell>,
    pub call: Arc<Cell>,
    pub salt: [u8; 32],
    pub pay_wallet: Addr,
    pub pay_op: Arc<Cell>,
    pub pay_auth: Arc<Cell>,
    pub pay_state_init: Option<Arc<Cell>>,
    pub master: Addr,
    pub deadline: u32,
}

impl RelayCall {
    pub fn body(&self) -> Result<Arc<Cell>> {
        let tail = Builder::new().reference(self.call.clone()).bytes(&self.salt).addr(Some(&self.pay_wallet)).reference(self.pay_op.clone())
            .reference(self.pay_auth.clone()).maybe_ref(self.pay_state_init.clone()).addr(Some(&self.master)).uint(self.deadline as u128, 32).end()?;
        Builder::new().uint(OP_RELAY_CALL, 32).addr(Some(&self.target)).reference(self.target_code.clone()).reference(self.target_data.clone())
            .reference(tail).end()
    }

    pub fn parse(c: &Arc<Cell>) -> Result<Self> {
        let mut s = c.parser();
        if s.uint(32)? != OP_RELAY_CALL {
            bail!("not a RelayCall");
        }
        let need = |a: Option<Addr>| a.ok_or_else(|| anyhow!("RelayCall without an address"));
        let (target, target_code, target_data, tail) = (need(s.addr()?)?, s.reference()?, s.reference()?, s.reference()?);
        s.end()?;
        let mut t = tail.parser();
        let (call, salt, pay_wallet, pay_op, pay_auth) = (t.reference()?, t.b256()?, need(t.addr()?)?, t.reference()?, t.reference()?);
        let pay_state_init = if t.bit()? { Some(t.reference()?) } else { None };
        let (master, deadline) = (need(t.addr()?)?, t.uint(32)? as u32);
        t.end()?;
        Ok(Self { target, target_code, target_data, call, salt, pay_wallet, pay_op, pay_auth, pay_state_init, master, deadline })
    }
}

/// The outcome of OUR relay of `(payer, r)` in one router event: `Some(true)` = `RelayFeePaid { ref, target, token,
/// ^[payer, payee, amount] }` with `payee == lane`, `Some(false)` = `RelayFeeRefunded { ref, payer, relayer, amount }`
/// with `relayer == lane` (amount 0: our payment never arrived). Another relayer's events are not ours (a copied
/// `RelayCall` after a release refunds its own relayer with amount 0), anything else `None`.
pub fn settled_event(c: &Arc<Cell>, lane: &Addr, payer: &Addr, r: &[u8; 32]) -> Option<bool> {
    let mut p = c.parser();
    let op = p.uint(32).ok()?;
    if p.b256().ok()? != *r {
        return None;
    }
    match op {
        EV_RELAY_FEE_PAID => {
            let mut q = c.refs().first()?.parser();
            (q.addr().ok()?.as_ref() == Some(payer) && q.addr().ok()?.as_ref() == Some(lane)).then_some(true)
        }
        EV_RELAY_FEE_REFUNDED => (p.addr().ok()?.as_ref() == Some(payer) && p.addr().ok()?.as_ref() == Some(lane)).then_some(false),
        _ => None,
    }
}

pub fn relay_refund_body(from: &Addr, r: &[u8; 32]) -> Result<Arc<Cell>> {
    Builder::new().uint(OP_RELAY_REFUND, 32).addr(Some(from)).bytes(r).end()
}

/// What the node accepts as a relay-fee job (controller call 2026-10-27/28, owner may override): the configured router,
/// a registered token (jetton master), a fee of at least `min_amount`, and a fee worth at least the TON the relay
/// puts at risk (`min_ton_value`: the node's floor price of one base unit of the token, in nanoton; spec §9).
#[derive(Debug, Clone, Default)]
pub struct RelayFeePolicy {
    pub router: Option<Addr>,
    pub tokens: Vec<Addr>,
    pub params: crate::config::RelayParams,
    pub min_ton_value: HashMap<Addr, u128>,
}

impl RelayFeePolicy {
    /// `params.relay_fee = { router = "<router address>", min_amount = N, min_ton_value = { "<master>" = nanoton } }`
    /// (`min_amount` default 1; a master without a `min_ton_value` gets no relay-fee job) and the chain's `tokens` (jetton
    /// masters). A `router`, a token or a `min_ton_value` key that is not a TON address, or an amount that is not a
    /// non-negative integer, is a startup error, never a silently disabled router.
    pub fn from_cfg(cfg: &ChainCfg) -> Result<Self> {
        let t = cfg.params.get("relay_fee");
        let router = match t.and_then(|t| t.get("router")) {
            None => None,
            Some(v) => Some(Addr::parse(v.as_str().ok_or_else(|| anyhow!("params.relay_fee.router must be a TON address string"))?)
                .context("params.relay_fee.router")?),
        };
        let params = cfg.relay_params()?;
        let tokens = cfg
            .tokens
            .iter()
            .map(|t| Addr::parse(&t.address).with_context(|| format!("tokens: {} is not a TON address", t.address)))
            .collect::<Result<_>>()?;
        let mut min_ton_value = HashMap::new();
        if let Some(v) = t.and_then(|t| t.get("min_ton_value")) {
            let table = v.as_table().ok_or_else(|| anyhow!("params.relay_fee.min_ton_value must be a table of master = nanoton"))?;
            for (k, n) in table {
                let master = Addr::parse(k).with_context(|| format!("params.relay_fee.min_ton_value: {k} is not a TON address"))?;
                let n = n.as_integer().and_then(|n| u128::try_from(n).ok())
                    .ok_or_else(|| anyhow!("params.relay_fee.min_ton_value.{k} must be a non-negative integer"))?;
                min_ton_value.insert(master, n);
            }
        }
        Ok(Self { router, tokens, params, min_ton_value })
    }
}

/// A relay-fee job, checked before any getter (fail closed). `op.contract` = the router, `op.payload` = the payer's
/// router-bound `OP_PAY` MetaOp, `op.extra` = `{ target, target_code, target_data (the target's StateInit, BOC hex),
/// call (BOC hex), salt (32 bytes hex), master }`, optional `op.ref`: the policy (router, registered master with a
/// `min_ton_value`, minimum fee), the StateInit derives the target, the call is a served entry's `SignedOp` (the router
/// also checks the code set and the executor), and the payment commits to exactly this call: `pay_ref == relay_ref(global
/// id, target, call, salt)`, `lane == payLane(ref)`, `nonce == 0`, `relayer == to == router`.
pub fn relay_fee_job(policy: &RelayFeePolicy, global_id: i32, cell: &Arc<Cell>, o: &Value) -> Result<(Addr, RelayCall)> {
    let m = &parse_metaop(cell)?;
    let router = policy.router.ok_or_else(|| anyhow!("params.relay_fee.router is not set"))?;
    if Addr::parse(o["contract"].as_str().unwrap_or_default()).ok() != Some(router) {
        bail!("op.contract is not params.relay_fee.router");
    }
    let x = &o["extra"];
    let addr = |k: &str| Addr::parse(x[k].as_str().ok_or_else(|| anyhow!("op.extra.{k} missing"))?).with_context(|| format!("op.extra.{k}"));
    let master = addr("master")?;
    if !policy.tokens.contains(&master) {
        bail!("token {} is not registered on this chain", master.raw());
    }
    if !policy.min_ton_value.contains_key(&master) {
        bail!("params.relay_fee.min_ton_value has no price for token {}", master.raw());
    }
    if m.op != 1 {
        bail!("the relay-fee payment is not a pay op");
    }
    // always open mode on TON (`to == router`, checked below: the escrow releases to the relaying lane)
    crate::adapter::relay_fee_ours(true, false, m.amount, &policy.params)?;
    let target = addr("target")?;
    let boc = |k: &str| hex_field(&x[k], &format!("extra.{k}")).and_then(|b| boc_parse(&b)).with_context(|| format!("op.extra.{k}"));
    let (target_code, target_data) = (boc("target_code")?, boc("target_data")?);
    let si = Builder::new().uint(0b00110, 5).reference(target_code.clone()).reference(target_data.clone()).end()?;
    if Addr::of_state_init(&si) != target {
        bail!("op.extra.target_code / target_data do not derive op.extra.target");
    }
    let call = boc("call")?;
    let mut cs = call.parser();
    let inner = (cs.uint(32).ok() == Some(OP_SIGNED)).then(|| call.refs().first().cloned()).flatten().and_then(|op| parse_metaop(&op).ok());
    if !inner.as_ref().is_some_and(|i| SERVED_OPS.contains(&i.op) && i.relayer != Some(router)) {
        bail!("op.extra.call is not a served fee-less entry (a SignedOp revoke / set_key not bound to the router)");
    }
    let salt: [u8; 32] = hex_field(&x["salt"], "extra.salt")?.try_into().map_err(|_| anyhow!("op.extra.salt is 32 bytes"))?;
    let r = relay_ref(global_id, &target, &call, &salt);
    if m.pay_ref != r || m.lane != pay_lane(&r) || m.nonce != 0 || m.relayer != Some(router) || m.to != router {
        bail!("the payment is not bound to this call (ref, payLane(ref), nonce 0, relayer = to = router)");
    }
    if !o["ref"].is_null() && hex_field(&o["ref"], "ref")? != r {
        bail!("op.ref != relay_ref(target, call, salt)");
    }
    // `pay_auth`, `pay_state_init` and `deadline` are the builder's (the signature JSON, the clock).
    let rc = RelayCall { target, target_code, target_data, call, salt, pay_wallet: m.contract, pay_op: cell.clone(),
        pay_auth: Builder::new().end()?, pay_state_init: None, master, deadline: 0 };
    Ok((router, rc))
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
    /// CTR-MTX-26 (`EV_META`): no `from`; the payer is the same transaction's `Executed` (`meta_payer`).
    Meta { master: Addr, pay_id: [u8; 32], meta: Vec<u8> },
}

/// The bytes of a snake chain (each cell whole bytes, at most one ref). A cell with more than one ref is refused:
/// Tact's `keccak256(Slice)` (the `payId` commitment) follows only the first ref, so further refs would be unsigned
/// bytes the event shows (T15).
pub fn snake_bytes(c: &Arc<Cell>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur = c.clone();
    loop {
        if cur.refs().len() > 1 || !cur.bits.is_multiple_of(8) {
            bail!("meta is not a snake chain (a cell with {} refs, {} bits)", cur.refs().len(), cur.bits);
        }
        out.extend_from_slice(&cur.data[..cur.bits / 8]);
        let Some(next) = cur.refs().first().cloned() else { return Ok(out) };
        cur = next;
    }
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
        EV_META => {
            let master = s.addr()?.ok_or_else(|| anyhow!("event master"))?;
            let pay_id = s.b256()?;
            let meta = snake_bytes(&s.reference()?)?;
            s.end()?;
            Some(TonEvent::Meta { master, pay_id, meta })
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

fn out_body(out_msg: &Value) -> Option<Arc<Cell>> {
    let body = out_msg.pointer("/message_content/body").and_then(Value::as_str)?;
    boc_parse(&b64decode(body).ok()?).ok()
}

/// Digest of the MetaOp a lane transaction carried: first ref of both `SignedOp` and `MandatePay`.
fn carried_digest(out_msg: &Value) -> Option<[u8; 32]> {
    out_body(out_msg)?.refs().first().map(|op| op.hash())
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
    relay_fee: RelayFeePolicy,
    /// escrow key ⇒ when this node last sent its `RelayRefund` (one in flight per escrow).
    refunds: RwLock<HashMap<[u8; 32], u64>>,
    /// `PaymentMeta`s waiting for their `PaymentSettled` (`ton_tx_events`), persisted in `meta_journal`.
    metas: std::sync::Mutex<MetaWait>,
    meta_journal: Option<std::path::PathBuf>,
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
        // the node sets it under its store directory (`main`); unset (tests, the example) = in memory only
        let meta_journal = param_str(cfg, "meta_journal").map(std::path::PathBuf::from);
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
            relay_fee: RelayFeePolicy::from_cfg(cfg).with_context(|| format!("chain {}", cfg.chain_key()))?,
            refunds: RwLock::new(HashMap::new()),
            metas: std::sync::Mutex::new(match &meta_journal { Some(f) => load_meta_wait(f)?, None => MetaWait::new() }),
            meta_journal,
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

    /// Simulation by getters (R27) of a signed op on its contract: lane/nonce unused, key bound or provable, signature
    /// valid. Returns the lane's next nonce.
    async fn simulate_signed(&self, contract: &Addr, m: &MetaOp, cell: &Arc<Cell>, auth: &Auth) -> std::result::Result<u64, SimError> {
        let revert = |e: anyhow::Error| SimError::Revert(format!("{e:#}"));
        let transport = |e: anyhow::Error| SimError::Transport(format!("{e:#}"));
        let next = self.api.run_get(contract, "get_lane_nonce", vec![json!({"type": "num", "value": hex0x(&m.lane)})]).await.map_err(transport)?;
        let next = next.first().map(stack_num).transpose().map_err(transport)?.unwrap_or(0) as u64;
        if next != m.nonce && !(m.op == 4 && next == m.nonce + 1) {
            return Err(SimError::Revert(format!("lane nonce is {next}, payload has {}", m.nonce)));
        }
        if let Auth::TonConnect { signature, timestamp, domain, state_init } = auth {
            let bound = self.api.run_get(contract, "get_owner_pubkey", vec![]).await.map_err(transport)?;
            let bound = bound.first().and_then(|v| v.get("value")).and_then(Value::as_str).unwrap_or("0x0");
            let mut pk = left_pad32(bound).map_err(revert)?;
            if pk == [0; 32] {
                let si = state_init.as_ref().ok_or_else(|| SimError::Revert("owner key not bound and no StateInit".into()))?;
                pk = pubkey_from_state_init(si, &m.from).map_err(revert)?;
            }
            let h = envelope_hash(&m.from, *timestamp, domain, cell).map_err(revert)?;
            let vk = VerifyingKey::from_bytes(&pk).map_err(|_| SimError::Revert("bad owner key".into()))?;
            vk.verify_strict(&h, &Signature::from_bytes(signature)).map_err(|_| SimError::Revert("signature does not verify".into()))?;
        }
        Ok(next)
    }

    /// I1 (final review, fix round 1): the relayed call must run on its target as far as the getters show, so the relayer
    /// never pays the bounce of a call bound to fail (every other family simulates the whole relay). Locally: the envelope
    /// (target, chain, `from` = the target's owner, valid past the relay's deadline), `relayer` none or the executor. By
    /// the router's getters: `responseDestination` = `get_executor(payer, salt)` (else 741 in the router), the target's
    /// code one of `get_codes` (else 741: refused here, never retried). The jetton wallet: TON Connect only (a passkey's
    /// P-256 signature is not checkable here yet, F1), like any signed op (`simulate_signed`: lane nonce incl. a revoke at
    /// n+1, bound or StateInit key, signature), plus its `E_TTL`, set_key (`params` hashing to `extra`, laid out as a
    /// passkey record) and cancel rules. The Mandate: an owner revoke, TON Connect-signed, at `get_lane_nonce`, verified
    /// against `get_state`'s `ownerPubkey`; a revoke of a revoked Mandate is a no-op and refused as such (owner rulings
    /// list item 6), not because it would fail.
    async fn check_relayed_call(&self, rc: &RelayCall, router: &Addr, payer: &Addr, now: u64) -> std::result::Result<(), SimError> {
        let refuse = |why: &str| SimError::Revert(format!("RELAY_CALL_REFUSED: {why}"));
        let revert = |e: anyhow::Error| refuse(&format!("{e:#}"));
        let transport = |e: anyhow::Error| SimError::Transport(format!("{e:#}"));
        let (op, auth, params, state_init, response, forward) = parse_signed_op(&rc.call).map_err(revert)?;
        let m = parse_metaop(&op).map_err(revert)?;
        let auth = auth_of_cell(&auth, state_init).map_err(revert)?;
        if m.contract != rc.target || m.network != self.global_id || rc.target_data.parser().addr().ok().flatten() != Some(m.from) {
            return Err(refuse("the call's contract, network or from is not the target, this chain or the target's owner"));
        }
        if m.valid_until <= rc.deadline as u64 {
            return Err(refuse("the call expires before the relay's deadline"));
        }
        if m.relayer.is_some_and(|r| r != response) {
            return Err(refuse("the call is bound to a relayer other than its executor"));
        }
        let addr_arg = |a: &Addr| Builder::new().addr(Some(a)).end().map(|c| json!({"type": "slice", "value": b64encode(&boc_serialize(&c))}));
        let args = vec![addr_arg(payer).map_err(revert)?, json!({"type": "num", "value": hex0x(&rc.salt)})];
        let exec = self.api.run_get(router, "get_executor", args).await.map_err(transport)?;
        let exec = exec.first().ok_or_else(|| anyhow!("get_executor: empty")).and_then(|v| stack_cell(v)?.parser().addr()).map_err(transport)?;
        if exec != Some(response) {
            return Err(refuse("the call's responseDestination is not the payer's executor"));
        }
        // CodeSet { wallet, mandate }, flattened
        let codes = self.api.run_get(router, "get_codes", vec![]).await.map_err(transport)?;
        let code = |i: usize| codes.get(i).and_then(|v| v.get("value")).and_then(Value::as_str).ok_or_else(|| anyhow!("get_codes: no field {i}"))
            .and_then(left_pad32).map_err(transport);
        let (wallet, mandate) = (code(0)?, code(1)?);
        if rc.target_code.hash() == wallet {
            if matches!(auth, Auth::Passkey { .. }) {
                return Err(refuse("a passkey-signed call is not relayed: the node cannot check its P-256 signature yet"));
            }
            if m.valid_until > now + LANE_TTL_S {
                return Err(refuse("the call is valid further ahead than LANE_TTL"));
            }
            if m.op == 5 && m.extra != [0; 32] && !params.as_ref().is_some_and(|p| p.hash() == m.extra && p.bit_len() == 520 && p.refs().len() == 1) {
                return Err(refuse("set_key: params must hash to extra and be a passkey record (520 bits, 1 ref)"));
            }
            let next = self.simulate_signed(&rc.target, &m, &op, &auth).await.map_err(|e| match e {
                SimError::Revert(r) => refuse(&r),
                t => t,
            })?;
            if m.op == 4 && next == m.nonce + 1 && forward < CANCEL_TON {
                return Err(refuse("a cancel carries less than CANCEL_TON forward"));
            }
            return Ok(());
        }
        if rc.target_code.hash() != mandate {
            return Err(refuse("unknown target code: neither the SCaaS jetton wallet nor the Mandate"));
        }
        let Auth::TonConnect { signature, timestamp, domain, .. } = &auth else {
            return Err(refuse("a Mandate owner op is TON Connect-signed"));
        };
        if m.op != 4 {
            return Err(refuse("a Mandate serves only the owner's revoke"));
        }
        // MandateState, flattened: revoked periodStart spent balance perPayment perPeriod periodSeconds expiresAt
        // ownerPubkey delegatePubkey
        let st = self.api.run_get(&rc.target, "get_state", vec![]).await.map_err(transport)?;
        let field = |i: usize| st.get(i).and_then(|v| v.get("value")).and_then(Value::as_str).ok_or_else(|| SimError::Transport(format!("get_state: no field {i}")));
        if !matches!(field(0)?, "0" | "0x0") {
            return Err(refuse("the Mandate is already revoked: the revoke would change nothing (a no-op is not relayed)"));
        }
        let next = self.api.run_get(&rc.target, "get_lane_nonce", vec![json!({"type": "num", "value": hex0x(&m.lane)})]).await.map_err(transport)?;
        let next = next.first().map(stack_num).transpose().map_err(transport)?.unwrap_or(0);
        if next != m.nonce as u128 {
            return Err(refuse(&format!("Mandate lane nonce is {next}, the call has {}", m.nonce)));
        }
        let pk = left_pad32(field(8)?).map_err(revert)?;
        let h = envelope_hash(&m.from, *timestamp, domain, &op).map_err(revert)?;
        if !VerifyingKey::from_bytes(&pk).is_ok_and(|vk| vk.verify_strict(&h, &Signature::from_bytes(signature)).is_ok()) {
            return Err(refuse("the owner signature does not verify against the Mandate's ownerPubkey"));
        }
        Ok(())
    }

    /// CTR-MTX-27 (spec §7.2 TON row, §9): the router's `RelayCall`. The job's own checks (`relay_fee_job`) run before
    /// any getter; then the payment's wallet is the payer's of the master, the payment simulates like a plain pay, the
    /// relayed call must run on its target (`check_relayed_call`, final review I1), the lane attaches what the router
    /// asks for (`get_relay_value` on this very body: every hop priced from the config), and the fee must be worth that
    /// TON at the node's floor price (`min_ton_value`, spec §9).
    async fn build_relay_fee(&self, job: &Job, op: &Value, cell: &Arc<Cell>, m: &MetaOp) -> std::result::Result<Built, SimError> {
        let revert = |e: anyhow::Error| SimError::Revert(format!("{e:#}"));
        let transport = |e: anyhow::Error| SimError::Transport(format!("{e:#}"));
        let (router, mut rc) = relay_fee_job(&self.relay_fee, self.global_id, cell, op).map_err(revert)?;
        let now = crate::submit::now();
        if m.network != self.global_id {
            return Err(SimError::Revert("payload network does not match the chain".into()));
        }
        if m.valid_until <= now {
            return Err(SimError::Revert("signed payload expired".into()));
        }
        // No validity floor on the payment (owner ruling 2026-10-28, Q1: risk accepted): one that expires in transit
        // bounces at the relayer's cost.
        // The payer's wallet refuses it (E_TTL) after the router escrowed it: the relayer would pay the bounce (P1).
        if m.valid_until > now + LANE_TTL_S {
            return Err(SimError::Revert("the payment is valid further ahead than LANE_TTL".into()));
        }
        pay_forward_floor(m).map_err(revert)?; // the router prices the signed floor into get_relay_value
        let auth = parse_auth(op["signature"].as_str().unwrap_or_default()).map_err(revert)?;
        let (h, d) = self.wallet_code(&rc.master).await.map_err(transport)?
            .ok_or_else(|| SimError::Revert(format!("{} is not a jetton master", rc.master.raw())))?;
        if jetton_wallet_address(&m.from, &rc.master, &h, d).map_err(revert)? != m.contract {
            return Err(SimError::Revert("the payment's contract is not the payer's wallet of op.extra.master".into()));
        }
        self.simulate_signed(&m.contract, m, cell, &auth).await?;
        // ... and refuses more than it holds (E_BALANCE, P1); a payer that moves its tokens away after this check pays a
        // direct transfer each time. JettonWalletData { balance, owner, master, code }, flattened.
        let data = self.api.run_get(&m.contract, "get_wallet_data", vec![]).await.map_err(transport)?;
        let balance = data.first().map(stack_num).transpose().map_err(transport)?.unwrap_or(0);
        if balance < m.amount {
            return Err(SimError::Revert(format!("the payer's wallet holds {balance}, the payment is {}", m.amount)));
        }
        rc.pay_auth = auth_cell(&auth).map_err(revert)?;
        rc.pay_state_init = auth_state_init(&auth);
        rc.deadline = (now + RELAY_DEADLINE_S) as u32;
        self.check_relayed_call(&rc, &router, &m.from, now).await?;
        let body = rc.body().map_err(revert)?;
        let v = self.api.run_get(&router, "get_relay_value", vec![json!({"type": "cell", "value": b64encode(&boc_serialize(&body))})]).await.map_err(transport)?;
        let value = v.first().map(stack_num).transpose().map_err(transport)?.ok_or_else(|| SimError::Transport("get_relay_value: empty".into()))?;
        let value = self.attach.max(value);
        let price = self.relay_fee.min_ton_value.get(&rc.master).copied().unwrap_or(0);
        if m.amount.saturating_mul(price) < value {
            return Err(SimError::Revert(format!("fee {} × min_ton_value {price} is below the {value} nanoton the relay puts at risk", m.amount)));
        }
        // The lane tx expires before the RelayCall's deadline would (the router refuses a past deadline).
        Ok(Built { job_id: job.id, body: boc_serialize(&body), valid_until: m.valid_until.min(rc.deadline as u64), meta: built_meta(&router, value) })
    }

    /// A relay-fee job's lane tx: the router's transaction, then the escrow (`get_escrow_state`). Open: pending; past the
    /// `deadline` (funded), or owed after a bounced settlement (any time), this node sends `RelayRefund` itself (anyone
    /// may), again after `RELAY_REFUND_RETRY_S`. Closed: identified positively by the router's event for this
    /// `(payer, ref)`: `RelayFeePaid` = mined, `RelayFeeRefunded` = reverted (the payer was not charged); neither seen
    /// yet = pending, never "refunded" by absence.
    async fn escrow_status(&self, lane_tx: &Value, out: &Value, rc: &RelayCall) -> Result<TxStatus> {
        let Some(rt) = self.tx_by_in_msg(&api_hash(out.get("hash").unwrap_or(&Value::Null))?).await? else { return Ok(TxStatus::Pending) };
        if let Err(why) = compute_ok(&rt) {
            return Ok(TxStatus::Reverted { reason: format!("router: {why}") });
        }
        let router = Addr::parse(rt.get("account").and_then(Value::as_str).ok_or_else(|| anyhow!("tx.account"))?)?;
        let m = parse_metaop(&rc.pay_op)?;
        let key = escrow_key(&m.from, &m.pay_ref)?;
        let st = self.api.run_get(&router, "get_escrow_state", vec![json!({"type": "num", "value": hex0x(&key)})]).await?;
        let st = st.first().map(stack_num).transpose()?.unwrap_or(0);
        if st != 0 {
            let now = crate::submit::now();
            let due = (st >= 3 || (st == 2 && now >= rc.deadline as u64))
                && self.refunds.read().ok().and_then(|r| r.get(&key).copied()).is_none_or(|at| now >= at + RELAY_REFUND_RETRY_S);
            if due {
                match self.send_refund(lane_tx, &router, &m.from, &m.pay_ref).await {
                    Ok(()) => {
                        if let Ok(mut r) = self.refunds.write() {
                            r.insert(key, now);
                        }
                    }
                    Err(e) => tracing::warn!(chain = %self.key, "RelayRefund not sent; retry: {e:#}"),
                }
            }
            return Ok(TxStatus::Pending);
        }
        let lane = Addr::parse(lane_tx.get("account").and_then(Value::as_str).unwrap_or_default())?;
        Ok(match self.escrow_outcome(&router, &lane, &m.from, &m.pay_ref).await? {
            Some((true, height, tx_hash)) => TxStatus::Mined { height, tx_hash: Some(tx_hash) },
            Some((false, _, _)) => TxStatus::Reverted { reason: "relay fee refunded: the call failed, bounced or timed out (the payer was not charged)".into() },
            None => TxStatus::Pending,
        })
    }

    /// The router transaction that settled our relay of `(payer, r)`: `(released, mc height, tx hash)` from its
    /// `RelayFeePaid` / `RelayFeeRefunded` naming our lane. A release wins over a refund (a `(payer, ref)` is paid at most
    /// once: a refund of ours next to it is an earlier attempt whose payment never arrived). ponytail: the router's last
    /// 128 transactions; a busier router needs the indexer's view (T17).
    async fn escrow_outcome(&self, router: &Addr, lane: &Addr, payer: &Addr, r: &[u8; 32]) -> Result<Option<(bool, u64, String)>> {
        let v = self.api.get("transactions", &[("account", router.raw()), ("limit", "128".into()), ("sort", "desc".into())]).await?;
        let mut found: Option<(bool, u64, String)> = None;
        for tx in v.get("transactions").and_then(Value::as_array).into_iter().flatten() {
            if compute_ok(tx).is_err() {
                continue;
            }
            let msgs = tx.get("out_msgs").and_then(Value::as_array).cloned().unwrap_or_default();
            for c in msgs.iter().filter(|m| m.get("destination").is_none_or(Value::is_null)).filter_map(out_body) {
                if let Some(released) = settled_event(&c, lane, payer, r) {
                    if released || found.is_none() {
                        let h = hex0x(&api_hash(tx.get("hash").unwrap_or(&Value::Null))?);
                        found = Some((released, tx.get("mc_block_seqno").and_then(Value::as_u64).unwrap_or_default(), h));
                    }
                    if released {
                        return Ok(found);
                    }
                }
            }
        }
        Ok(found)
    }

    /// `RelayRefund { from, ref }` from the lane that sent the relay (the lane runner holds it until the job ends).
    async fn send_refund(&self, lane_tx: &Value, router: &Addr, from: &Addr, r: &[u8; 32]) -> Result<()> {
        let account = Addr::parse(lane_tx.get("account").and_then(Value::as_str).unwrap_or_default())?;
        let lane = self.w5.iter().position(|w| w.address().ok() == Some(account)).ok_or_else(|| anyhow!("the relay was not sent by one of our lanes"))?;
        let seqno = self.sequence(lane).await? as u32;
        let signer = self.signers.get(lane).ok_or_else(|| anyhow!("no lane {lane}"))?;
        let vu = (crate::submit::now() + 300) as u32;
        let v = self.api.run_get(router, "get_refund_value", vec![]).await?;
        let value = v.first().map(stack_num).transpose()?.ok_or_else(|| anyhow!("get_refund_value: empty"))?;
        let (raw, _) = w5_transfer(&self.w5[lane], signer, seqno, vu, router, value, relay_refund_body(from, r)?)?;
        self.api.post("message", json!({"boc": b64encode(&raw)})).await.map(|_| ())
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
        // authenticated through its transaction's `Executed` (`meta_payer`)
        TonEvent::Meta { .. } => None,
    }
}

/// The payer of a `PaymentMeta`: the `Executed` of the same transaction, same emitter (the payer's jetton wallet) and
/// master, authenticated like any `Executed` (the wallet derives from `(from, master)`). `PaymentMeta` has no `from`.
pub fn meta_payer(evs: &[(usize, Addr, TonEvent)], emitter: &Addr, master: &Addr, masters: &[(Addr, Option<WalletCode>)]) -> Option<Addr> {
    evs.iter().find_map(|(_, e, ev)| match ev {
        TonEvent::Executed { master: m, from, .. } if e == emitter && m == master => {
            authenticate(e, ev, masters).map(|_| *from)
        }
        _ => None,
    })
}

/// `(master, payer, payId)` ⇒ its `Waiting` meta: a `PaymentMeta` waits for its `PaymentSettled`, emitted by the payee's
/// wallet in a later transaction, maybe a later range. It is looked up, never taken, so a range that fails after the
/// join and is retried joins again (the triple happens once on chain: a second join is the same meta); it leaves by
/// expiry (`META_WAIT_BLOCKS`, also the end of a payment that never settled: a payee bounce) or, past `META_WAIT_MAX`,
/// those already joined first, then the oldest (logged). Persisted (`params.meta_journal`, `save_meta_wait`) so a
/// restart keeps it.
pub type MetaWait = HashMap<(Addr, Addr, [u8; 32]), Waiting>;

/// One waiting `PaymentMeta`: its bytes, the mc seqno it was seen at, and whether its payment was already seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Waiting {
    pub meta: Vec<u8>,
    pub seqno: u64,
    pub joined: bool,
}
/// One authenticated event of a transaction: `(log index, master, event, the meta its payment joined)`.
pub type JoinedEvent = (usize, Addr, TonEvent, Option<Vec<u8>>);
const META_WAIT_BLOCKS: u64 = 10_000;
const META_WAIT_MAX: usize = 4_096;

/// One transaction's normalized events (TON's join, T17 G): `Executed` and `Paid` as before; a `PaymentMeta` (payer
/// from the same transaction's `Executed`) waits in `wait`, and the `Paid` of the same `(master, from, pay_ref)` takes
/// its `meta`. Never by `pay_ref` alone; a `PaymentMeta` is never sent as a row (without its payment it proves nothing).
/// The flag: `wait` changed (persist it).
pub fn ton_tx_events(evs: Vec<(usize, Addr, TonEvent)>, masters: &[(Addr, Option<WalletCode>)], wait: &mut MetaWait, seqno: u64)
    -> (Vec<JoinedEvent>, bool)
{
    let n = wait.len();
    wait.retain(|_, w| w.seqno.saturating_add(META_WAIT_BLOCKS) >= seqno);
    let mut changed = wait.len() != n;
    for (_, emitter, ev) in &evs {
        if let TonEvent::Meta { master, pay_id, meta } = ev {
            if let Some(from) = meta_payer(&evs, emitter, master, masters) {
                // a re-read of the same transaction keeps the entry (and its `joined`) as it is
                if wait.get(&(*master, from, *pay_id)).is_none_or(|w| w.meta != *meta) {
                    wait.insert((*master, from, *pay_id), Waiting { meta: meta.clone(), seqno, joined: false });
                    changed = true;
                }
            }
        }
    }
    let mut out = Vec::new();
    for (i, emitter, ev) in &evs {
        let Some((master, ev)) = authenticate(emitter, ev, masters) else { continue };
        let meta = match &ev {
            TonEvent::Paid { from, pay_ref, .. } => wait.get_mut(&(master, *from, *pay_ref)).map(|w| {
                changed |= !w.joined;
                w.joined = true;
                w.meta.clone()
            }),
            _ => None,
        };
        out.push((*i, master, ev, meta));
    }
    // over the cap: entries whose payment was already seen leave first (only a re-read range would still need them),
    // then the oldest still waiting (its payment would reach the client without meta)
    while wait.len() > META_WAIT_MAX {
        let Some((k, joined)) = wait.iter().min_by_key(|(_, w)| (!w.joined, w.seqno)).map(|(k, w)| (*k, w.joined)) else { break };
        wait.remove(&k);
        changed = true;
        if joined {
            tracing::warn!(master = %k.0.raw(), from = %k.1.raw(), "PaymentMeta wait full: a joined entry is dropped (its payment already carried meta)");
        } else {
            tracing::warn!(master = %k.0.raw(), from = %k.1.raw(), "PaymentMeta wait full: a still-waiting entry is dropped (its payment will reach the client without meta)");
        }
    }
    (out, changed)
}

/// The persisted `MetaWait` (a missing file is an empty wait): `[{master, from, pay_id, meta, seqno}]`, hex / raw addresses.
pub fn load_meta_wait(path: &std::path::Path) -> Result<MetaWait> {
    let raw = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(MetaWait::new()),
        Err(e) => return Err(e).with_context(|| format!("meta journal {}", path.display())),
    };
    let rows: Vec<Value> = serde_json::from_slice(&raw).with_context(|| format!("meta journal {}", path.display()))?;
    rows.iter().map(|r| {
        let s = |k: &str| r[k].as_str().ok_or_else(|| anyhow!("meta journal: {k} missing"));
        let pay_id: [u8; 32] = alloy::hex::decode(s("pay_id")?.trim_start_matches("0x"))?.try_into().map_err(|_| anyhow!("pay_id is 32 bytes"))?;
        let seqno = r["seqno"].as_u64().ok_or_else(|| anyhow!("meta journal: seqno missing"))?;
        let w = Waiting { meta: alloy::hex::decode(s("meta")?.trim_start_matches("0x"))?, seqno, joined: r["joined"].as_bool().unwrap_or(false) };
        Ok(((Addr::parse(s("master")?)?, Addr::parse(s("from")?)?, pay_id), w))
    }).collect()
}

/// Writes `wait` to `path` atomically: a temporary file written in full and synced to disk, then renamed over the
/// journal (as the Sui lane journal), so a power loss leaves the old journal or the new one, never a truncated file;
/// the directory is synced after the rename, so the new journal survives a crash right after it (final review M13).
pub fn save_meta_wait(path: &std::path::Path, wait: &MetaWait) -> Result<()> {
    use std::io::Write;
    let rows: Vec<Value> = wait.iter().map(|((master, from, pay_id), w)| json!({"master": master.raw(),
        "from": from.raw(), "pay_id": hex0x(pay_id), "meta": hex0x(&w.meta), "seqno": w.seqno, "joined": w.joined})).collect();
    let tmp = path.with_extension("tmp");
    let ctx = || format!("meta journal {}", tmp.display());
    let mut f = std::fs::File::create(&tmp).with_context(ctx)?;
    f.write_all(&serde_json::to_vec(&rows)?).with_context(ctx)?;
    f.sync_all().with_context(ctx)?;
    std::fs::rename(&tmp, path).with_context(|| format!("meta journal {}", path.display()))?;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(std::path::Path::new("."));
    std::fs::File::open(dir).and_then(|d| d.sync_all()).with_context(|| format!("meta journal directory {}", dir.display()))
}

/// The forward TON floor a pay op signed (`MetaOp.extra`, review H2).
fn pay_forward_floor(m: &MetaOp) -> Result<u128> {
    if m.extra[..16] != [0; 16] {
        bail!("signed forward floor is not a TON amount");
    }
    Ok(u128::from_be_bytes(m.extra[16..].try_into().expect("16")))
}

fn auth_state_init(auth: &Auth) -> Option<Arc<Cell>> {
    match auth {
        Auth::TonConnect { state_init, .. } => state_init.clone(),
        Auth::Passkey { .. } => None,
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
        // A relay-fee payment's lane is spent by a refunded escrow too: its outcome is the escrow's (tx_status).
        let Some(op) = job.op.as_ref().filter(|o| o["op_kind"] == "pay" && o["kind"] != "relay_fee") else { return Ok(None) };
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
        if op["kind"] == "relay_fee" {
            return self.build_relay_fee(job, op, &cell, &m).await;
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
        let pay_meta = pay_params(&m, op, self.relay_fee.params.max_pay_meta_bytes).map_err(revert)?;
        if m.op == 1 && self.relay_fee.router == Some(m.to) {
            // CTR-MTX-27: never pay the router outside a relay (a transfer without a notification would stay there).
            return Err(SimError::Revert(format!("a plain pay to the relay-fee router {} is refused", m.to.raw())));
        }
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
            let next = self.simulate_signed(&contract, &m, &cell, &auth).await?;
            let state_init = auth_state_init(&auth);
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
                1 => pay_forward_floor(&m).map_err(revert)?,
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
        if let Some(rc) = out_body(out).and_then(|c| RelayCall::parse(&c).ok()) {
            return self.escrow_status(&tx, out, &rc).await;
        }
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
                    let evs = {
                        let mut wait = self.metas.lock().map_err(|_| anyhow!("meta wait poisoned"))?;
                        let (evs, changed) = ton_tx_events(evs, &masters, &mut wait, seqno);
                        if let (true, Some(f)) = (changed, &self.meta_journal) {
                            save_meta_wait(f, &wait)?; // a failed write fails the range, which is read again
                        }
                        evs
                    };
                    for (log_index, master, ev, meta) in evs {
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
                                if let Some(m) = meta {
                                    e["meta"] = json!(hex0x(&m));
                                }
                            }
                            TonEvent::Meta { .. } => continue,
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
    /// T17 (G): a `PaymentMeta` takes its payer from the same transaction's authenticated `Executed`, waits, and gives
    /// its `meta` to the later `PaymentSettled` of the same `(master, from, pay_ref)` (never by `pay_ref` alone; a
    /// 0-amount `Paid` of another payer joins nothing); it is never a row of its own; a meta cell with more than one
    /// ref is refused; a wait expires.
    #[test]
    fn ton_indexer_joins_payment_meta_by_payer() {
        let v = vectors();
        let code = cell(&v, "/jetton/wallet_code_boc");
        let (payer, master) = (Addr::parse(s(&v, "/metaop/from")).unwrap(), Addr::parse(s(&v, "/jetton/master")).unwrap());
        let wallet = Addr::parse(s(&v, "/jetton/payer_wallet")).unwrap();
        let masters = vec![(master, Some((code.hash(), code.depth())))];
        let payee = Addr { wc: 0, hash: [0x5e; 32] };
        let payee_wallet = jetton_wallet_address(&payee, &master, &code.hash(), code.depth()).unwrap();
        let two = Builder::new().bytes(&[1]).reference(snake(&[2]).unwrap()).reference(snake(&[3]).unwrap()).end().unwrap();
        let bad = Builder::new().uint(EV_META, 32).addr(Some(&master)).bytes(&[4; 32]).reference(two).end().unwrap();
        assert!(decode_event(&bad).is_err(), "a meta cell with two refs");
        let pid = [4u8; 32];
        let exe = TonEvent::Executed { master, from: payer, digest: [1; 32] };
        let pm = |m: Vec<u8>| TonEvent::Meta { master, pay_id: pid, meta: m };
        let mut wait = MetaWait::new();
        let forger = Addr { wc: 0, hash: [9; 32] };
        let (forged, changed) = ton_tx_events(vec![(0, forger, exe.clone()), (1, forger, pm(vec![0xff]))], &masters, &mut wait, 10);
        assert!(forged.is_empty() && wait.is_empty() && !changed, "a meta from a wallet that is not the payer's");
        let (a, changed) = ton_tx_events(vec![(0, wallet, exe.clone()), (1, wallet, pm(vec![0xab]))], &masters, &mut wait, 10);
        assert_eq!(a.iter().map(|e| matches!(e.2, TonEvent::Executed { .. })).collect::<Vec<_>>(), [true], "never a row");
        assert!(changed, "persist");
        let paid = |from: Addr, amount| TonEvent::Paid { from, to: payee, amount, pay_ref: pid };
        let payment = || vec![(0, payee_wallet, paid(Addr { wc: 0, hash: [0x77; 32] }, 0)), (1, payee_wallet, paid(payer, 100))];
        let (b, _) = ton_tx_events(payment(), &masters, &mut wait, 11);
        assert_eq!((b[0].3.clone(), b[1].3.clone()), (None, Some(vec![0xab])), "joined by (master, from, pay_ref)");
        assert!(wait.values().all(|w| w.joined), "marked joined");
        // fix 1: a range that failed after the join is read again: the payment still carries its meta
        let (again, changed) = ton_tx_events(payment(), &masters, &mut wait, 11);
        assert_eq!((again[1].3.clone(), changed), (Some(vec![0xab]), false), "looked up, never taken");
        ton_tx_events(vec![(0, wallet, exe.clone()), (1, wallet, pm(vec![0xab]))], &masters, &mut wait, 10);
        assert!(wait.values().all(|w| w.joined), "re-reading the meta's own transaction keeps it joined");
        // fix 1: a restart reloads the wait from the journal
        let f = std::env::temp_dir().join(format!("ton-meta-{}.json", std::process::id()));
        save_meta_wait(&f, &wait).unwrap();
        let mut reloaded = load_meta_wait(&f).unwrap();
        assert_eq!(reloaded, wait);
        let (after, _) = ton_tx_events(payment(), &masters, &mut reloaded, 12);
        assert_eq!(after[1].3, Some(vec![0xab]), "after a restart");
        let _ = std::fs::remove_file(&f);
        assert!(load_meta_wait(&f).unwrap().is_empty(), "no journal yet: an empty wait");
        let (_, changed) = ton_tx_events(vec![], &masters, &mut wait, 10 + META_WAIT_BLOCKS + 1);
        assert!(wait.is_empty() && changed, "a payment that never settled (payee bounce) stops waiting");
        // the cap (fix 2): an entry already joined leaves before any still waiting, then the oldest waiting one
        let id = |k: u64| { let mut b = [0u8; 32]; b[24..].copy_from_slice(&k.to_be_bytes()); b };
        for k in 0..META_WAIT_MAX as u64 + 1 {
            wait.insert((master, payer, id(k)), Waiting { meta: vec![], seqno: 20_000 + k, joined: k == 7 });
        }
        ton_tx_events(vec![], &masters, &mut wait, 20_000);
        assert_eq!(wait.len(), META_WAIT_MAX);
        assert!(!wait.contains_key(&(master, payer, id(7))) && wait.contains_key(&(master, payer, id(0))), "the joined one first");
        wait.insert((master, payer, id(10_000)), Waiting { meta: vec![], seqno: 30_000, joined: false });
        ton_tx_events(vec![], &masters, &mut wait, 20_000);
        assert!(!wait.contains_key(&(master, payer, id(0))), "then the oldest waiting");
    }

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
        /// `message` POSTs (the BOCs the adapter sent).
        posted: Vec<Value>,
        /// The getters run, in order (`runGetMethod` method names).
        ran: Vec<String>,
    }

    type Shared = Arc<std::sync::Mutex<Fake>>;

    async fn fake_api(f: Fake) -> String {
        fake_api_shared(f).await.0
    }

    async fn fake_api_shared(f: Fake) -> (String, Shared) {
        use axum::extract::{Path, Query, State};
        async fn h(State(s): State<Shared>, Path(path): Path<String>, Query(q): Query<HashMap<String, String>>, body: String) -> axum::Json<Value> {
            let mut f = s.lock().unwrap();
            axum::Json(match path.as_str() {
                "runGetMethod" => {
                    let b: Value = serde_json::from_str(&body).unwrap();
                    let method = b["method"].as_str().unwrap().to_string();
                    f.ran.push(method.clone());
                    // `<method>@<raw address>` answers for that contract only, before `<method>` for every contract
                    let at = format!("{method}@{}", b["address"].as_str().unwrap_or_default());
                    f.getters.get(&at).or_else(|| f.getters.get(&method)).cloned().unwrap_or(json!({"exit_code": 11, "stack": []}))
                }
                "transactionsByMessage" => json!({"transactions": f.by_msg.get(&q["msg_hash"]).into_iter().collect::<Vec<_>>()}),
                "transactions" => json!({"transactions": f.by_account}),
                "walletInformation" => json!({"seqno": 3}),
                "message" => {
                    f.posted.push(serde_json::from_str(&body).unwrap());
                    json!({})
                }
                _ => json!({}),
            })
        }
        let shared: Shared = Arc::new(std::sync::Mutex::new(f));
        let app = axum::Router::new().route("/api/v3/{path}", axum::routing::any(h)).with_state(shared.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, shared)
    }

    fn adapter(url: &str) -> TonAdapter {
        adapter_with(url, toml::Table::new(), vec![]).unwrap()
    }

    fn adapter_with(url: &str, params: toml::Table, tokens: Vec<crate::config::TokenCfg>) -> Result<TonAdapter> {
        let cfg = ChainCfg {
            family: "ton".into(),
            network: Some("-239".into()),
            evm_chain_number: 0,
            rpc_urls: vec![url.into()],
            signer_key_env: String::new(),
            private_key: None,
            lanes: vec![0],
            params,
            finality: crate::config::FinalityCfg { mode: "depth".into(), depth: 0, quorum: 1 },
            dex: None,
            poll_ms: 200,
            stuck_after_secs: 60,
            max_gas_per_tx: 0,
            max_fee_cap_gwei: 0,
            tokens,
            ..Default::default()
        };
        TonAdapter::new(&cfg, &[LocalSigner::new(Curve::Ed25519, &[0x11; 32]).unwrap()])
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
        // the `PaymentMeta` event decodes (T17): the vector's payment id and meta
        let Some(TonEvent::Meta { pay_id, meta: m, .. }) = decode_event(&cell(&v, "/events/pm_boc")).unwrap() else { panic!("pm_boc") };
        assert_eq!((pay_id, m), (id, meta.clone()));

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
        assert!(e.contains("above max_pay_meta_bytes 2048"), "{e}");
        let (job, m) = pay_job(big_id, pay_lane(&big_id), 0, 1, with("meta", json!(alloy::hex::encode(&big))));
        assert!(pay_params(&m, job.op.as_ref().unwrap(), 4096).is_ok(), "params.max_pay_meta_bytes raises it");
        let mut kindless = with("meta", json!("00"));
        kindless.as_object_mut().unwrap().remove("kind");
        assert!(refused(pay_job(id, pay_lane(&id), 0, 1, kindless).0).await.contains("no salt / meta"), "a kind-less pay with meta");
        let at_cap = vec![0x61u8; MAX_PAY_META_BYTES];
        let cap_id = meta_pay_id(&salt, &at_cap);
        let (job, m) = pay_job(cap_id, pay_lane(&cap_id), 0, 1, with("meta", json!(alloy::hex::encode(&at_cap))));
        assert_eq!(pay_params(&m, job.op.as_ref().unwrap(), MAX_PAY_META_BYTES).unwrap().unwrap().refs()[0].hash(), snake(&at_cap).unwrap().hash());
        // unknown kinds and a plain pay with params are refused, never sent as a plain pay
        for k in [json!("pay-meta"), json!("pay"), json!(""), json!(7), json!(true), json!({"k": 1}), json!(["pay_meta"])] {
            let e = refused(pay_job(id, pay_lane(&id), 0, 1, with("kind", k.clone())).0).await;
            assert!(e.contains("unknown op.kind"), "{k}: {e}");
        }
        let e = refused(pay_job(id, pay_lane(&id), 0, 1, json!({"extra": {"params": s(&v, "/pay_meta/params_boc")}})).0).await;
        assert!(e.contains("plain pay carries no params"), "{e}");
    }

    // ---------------------------------------------------------------- CTR-MTX-27 (spec §7.2 TON row, §9)

    const ROUTER: Addr = Addr { wc: 0, hash: [0x5e; 32] };
    const MASTER: Addr = Addr { wc: 0, hash: [0x33; 32] };
    const ROUTER_RAW: &str = "0:5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";

    fn policy() -> RelayFeePolicy {
        RelayFeePolicy { router: Some(ROUTER), tokens: vec![MASTER], params: crate::config::RelayParams { min_amount: 5, ..Default::default() },
                         min_ton_value: HashMap::from([(MASTER, 100_000_000)]) }
    }

    fn relay_params(price: u64) -> toml::Table {
        let mut p = toml::Table::new();
        let mut t = toml::Table::new();
        t.insert("router".into(), ROUTER_RAW.into());
        t.insert("min_amount".into(), 5.into());
        t.insert("min_ton_value".into(), toml::Value::Table(toml::Table::from_iter([(MASTER.raw(), toml::Value::Integer(price as i64))])));
        p.insert("relay_fee".into(), toml::Value::Table(t));
        p
    }

    fn wallet_code(v: &Value) -> Arc<Cell> {
        cell(v, "/jetton/wallet_code_boc")
    }

    /// The payer: the W5R1 wallet of key `[1; 32]`; it also owns the targets.
    fn payer() -> (LocalSigner, W5) {
        let key = LocalSigner::new(Curve::Ed25519, &[1; 32]).unwrap();
        let w5 = W5::new(key.public_key().try_into().unwrap(), -239).unwrap();
        (key, w5)
    }

    /// A target of `code` owned by the payer (data `owner master …`, the owner first as Tact lays it out), at the
    /// address its StateInit derives.
    fn target_of(code: Arc<Cell>) -> (Arc<Cell>, Arc<Cell>, Addr) {
        let data = Builder::new().addr(Some(&payer().1.address().unwrap())).addr(Some(&MASTER)).uint(0x77, 8).end().unwrap();
        let si = Builder::new().uint(0b00110, 5).reference(code.clone()).reference(data.clone()).end().unwrap();
        (code, data, Addr::of_state_init(&si))
    }

    /// The target: a served code (the jetton wallet's).
    fn target_init() -> (Arc<Cell>, Arc<Cell>, Addr) {
        target_of(wallet_code(&vectors()))
    }

    fn metaop_cell(m: &MetaOp) -> Arc<Cell> {
        Builder::new().bytes(b"scaas.metaop.v1").int(m.network as i64, 32).uint(m.op as u128, 8).uint(m.amount, 128)
            .uint(m.nonce as u128, 64).uint(m.valid_until as u128, 64).addr(Some(&m.contract))
            .reference(Builder::new().addr(Some(&m.from)).addr(Some(&m.to)).addr(m.relayer.as_ref()).end().unwrap())
            .reference(Builder::new().bytes(&m.pay_ref).bytes(&m.lane).bytes(&m.extra).end().unwrap())
            .end().unwrap()
    }

    /// A served call on target `t` as its owner (the payer) would send it: a TON Connect-signed `SignedOp` (signed by
    /// `key`, the payer's StateInit attached) whose MetaOp is a set_key dropping the passkey (`extra` 0) until `f` edits it.
    fn signed_call_at(t: &Addr, key: &[u8; 32], f: impl Fn(&mut MetaOp)) -> Arc<Cell> {
        let owner = payer().1.address().unwrap();
        let mut m = MetaOp { network: -239, op: 5, amount: 0, nonce: 0, valid_until: crate::submit::now() + 3600, contract: *t, from: owner,
            to: owner, relayer: None, pay_ref: [0; 32], lane: [7; 32], extra: [0; 32], digest: [0; 32] };
        f(&mut m);
        let op = metaop_cell(&m);
        let ts = 1_800_000_000u64;
        let sig = LocalSigner::new(Curve::Ed25519, key).unwrap().sign(&envelope_hash(&owner, ts, "pay.example", &op).unwrap()).unwrap();
        let auth = Auth::TonConnect { signature: sig.try_into().unwrap(), timestamp: ts, domain: "pay.example".into(), state_init: None };
        signed_op_body(&op, &auth_cell(&auth).unwrap(), None, Some(payer().1.state_init().unwrap()), &EXECUTOR, 0, [0; 32]).unwrap()
    }

    /// The payer's executor as the fake router's `get_executor` names it (the call's `responseDestination`).
    const EXECUTOR: Addr = Addr { wc: 0, hash: [0xec; 32] };

    /// `call` with its `SignedOp` tail or auth replaced (the MetaOp and its signature unchanged).
    fn resign(call: &Arc<Cell>, params: Option<Arc<Cell>>, auth: Option<Arc<Cell>>, response: Option<Addr>, forward: Option<u128>) -> Arc<Cell> {
        let (op, a, p, si, r, f) = parse_signed_op(call).unwrap();
        signed_op_body(&op, &auth.unwrap_or(a), params.or(p), si, &response.unwrap_or(r), forward.unwrap_or(f), [0; 32]).unwrap()
    }

    /// The Mandate target: a code other than the jetton wallet's, owned by the payer.
    fn mandate_init() -> (Arc<Cell>, Arc<Cell>, Addr) {
        target_of(Builder::new().uint(0x3a4d, 16).end().unwrap())
    }

    /// The getters of a relay-fee build: the master's wallet code, unused lanes, no bound key, the router's price,
    /// executor and code set (`get_codes`: the wallet's, `mandate_init`'s), a live Mandate of the payer's key.
    fn relay_getters() -> HashMap<String, Value> {
        let code = wallet_code(&vectors());
        let n = |v: &str| json!({"type": "num", "value": v});
        let exec = Builder::new().addr(Some(&EXECUTOR)).end().unwrap();
        HashMap::from([
            ("get_jetton_data".to_string(), json!({"exit_code": 0, "stack": [num(0), num(0), num(0), num(0),
                json!({"type": "cell", "value": b64encode(&boc_serialize(&code))})]})),
            ("get_lane_nonce".into(), num(0)), ("get_owner_pubkey".into(), num(0)), ("get_relay_value".into(), num(306_666_673)),
            ("get_executor".into(), json!({"exit_code": 0, "stack": [{"type": "slice", "value": b64encode(&boc_serialize(&exec))}]})),
            ("get_codes".into(), json!({"exit_code": 0, "stack": [n(&hex0x(&code.hash())), n(&hex0x(&mandate_init().0.hash()))]})),
            ("get_state".into(), mandate_state(false)),
            ("get_wallet_data".into(), num(1_000_000)),
        ])
    }

    /// `get_state` of a Mandate whose owner key is the payer's (`MandateState`, flattened).
    fn mandate_state(revoked: bool) -> Value {
        let n = |v: &str| json!({"type": "num", "value": v});
        json!({"exit_code": 0, "stack": [n(if revoked { "-0x1" } else { "0x0" }), n("0x0"), n("0x0"), n("0x0"), n("0x0"), n("0x0"),
            n("0x0"), n("0x0"), n(&hex0x(&payer().1.pubkey)), n("0x0")]})
    }

    fn target() -> Addr {
        target_init().2
    }

    /// A served call: a `SignedOp` whose MetaOp is `op` (5 = set_key) with `relayer`.
    fn served_call(op: u8, relayer: Option<&Addr>) -> Arc<Cell> {
        let a = Addr { wc: 0, hash: [0x61; 32] };
        let m = Builder::new().bytes(b"scaas.metaop.v1").int(-239, 32).uint(op as u128, 8).uint(0, 128).uint(0, 64).uint(1 << 40, 64)
            .addr(Some(&target())).reference(Builder::new().addr(Some(&a)).addr(Some(&a)).addr(relayer).end().unwrap())
            .reference(Builder::new().bytes(&[0; 32]).bytes(&[1; 32]).bytes(&[0; 32]).end().unwrap()).end().unwrap();
        signed_op_body(&m, &Builder::new().uint(0, 8).end().unwrap(), None, None, &a, 0, [0; 32]).unwrap()
    }

    /// A relay-fee job: the payer (W5R1 of key `[1; 32]`) pays `amount` from its wallet of `MASTER`, bound to
    /// (target, call, salt); `f` edits the MetaOp fields before signing.
    fn relay_job_with(amount: u128, call: Arc<Cell>, f: impl Fn(&mut MetaOp)) -> (Value, MetaOp, Arc<Cell>, [u8; 32]) {
        relay_job_at(amount, target_init(), call, f)
    }

    /// `relay_job_with` on the target `(code, data, address)`.
    fn relay_job_at(amount: u128, tgt: (Arc<Cell>, Arc<Cell>, Addr), call: Arc<Cell>, f: impl Fn(&mut MetaOp)) -> (Value, MetaOp, Arc<Cell>, [u8; 32]) {
        let v = vectors();
        let code = wallet_code(&v);
        let (key, w5) = payer();
        let from = w5.address().unwrap();
        let salt = [0x5a; 32];
        let (tcode, tdata, t) = tgt;
        let r = relay_ref(-239, &t, &call, &salt);
        let mut m = MetaOp {
            network: -239, op: 1, amount, nonce: 0, valid_until: crate::submit::now() + 3600,
            contract: jetton_wallet_address(&from, &MASTER, &code.hash(), code.depth()).unwrap(), from, to: ROUTER,
            relayer: Some(ROUTER), pay_ref: r, lane: pay_lane(&r), extra: [0; 32], digest: [0; 32],
        };
        f(&mut m);
        let op = metaop_cell(&m);
        let ts = 1_800_000_000u64;
        let sig = key.sign(&envelope_hash(&from, ts, "pay.example", &op).unwrap()).unwrap();
        let signature = json!({"kind": "ton_connect", "signature": b64encode(&sig), "timestamp": ts, "domain": "pay.example",
                               "state_init": b64encode(&boc_serialize(&w5.state_init().unwrap()))});
        let hx = |c: &Arc<Cell>| alloy::hex::encode(boc_serialize(c));
        let o = json!({"kind": "relay_fee", "contract": ROUTER.raw(), "op_kind": "pay", "payload": hx(&op),
            "signature": signature.to_string(), "digest": hex0x(&op.hash()),
            "extra": {"target": t.raw(), "target_code": hx(&tcode), "target_data": hx(&tdata), "call": hx(&call),
                      "salt": alloy::hex::encode(salt), "master": MASTER.raw()}});
        (o, parse_metaop(&op).unwrap(), op, r)
    }

    fn relay_job(amount: u128, f: impl Fn(&mut MetaOp)) -> (Value, MetaOp, Arc<Cell>, [u8; 32]) {
        relay_job_with(amount, served_call(5, None), f)
    }

    fn job_of(o: &Value) -> Job {
        serde_json::from_value(json!({"id": 1, "kind": "signed_op", "op": o})).unwrap()
    }

    fn relay_call_of(m: &MetaOp, op: Arc<Cell>, deadline: u32) -> RelayCall {
        let (target_code, target_data, target) = target_init();
        RelayCall { target, target_code, target_data, call: served_call(5, None), salt: [0x5a; 32], pay_wallet: m.contract, pay_op: op,
            pay_auth: Builder::new().end().unwrap(), pay_state_init: None, master: MASTER, deadline }
    }

    /// Rule 2: the router's `ref`, escrow key and message bodies, byte for byte the Tact contract's (@ton/core vectors).
    #[test]
    fn ton_relay_fee_vectors() {
        let v = vectors();
        let rf = &v["relay_fee"];
        let a = |k: &str| Addr::parse(rf[k].as_str().unwrap()).unwrap();
        let salt: [u8; 32] = hexv(&rf["salt"]).try_into().unwrap();
        let call = cell(&v, "/relay_fee/call_boc");
        let r = relay_ref(-239, &a("target"), &call, &salt);
        assert_eq!(hex0x(&r), rf["ref"].as_str().unwrap());
        assert_eq!(hex0x(&escrow_key(&a("from"), &r).unwrap()), rf["escrow_key"].as_str().unwrap());
        let body = cell(&v, "/relay_fee/relay_call_boc");
        let rc = RelayCall::parse(&body).unwrap();
        assert_eq!((rc.target, rc.salt, rc.deadline, rc.call.hash()), (a("target"), salt, 1_800_000_600, call.hash()));
        assert_eq!(rc.target_code.parser().uint(16).unwrap(), 0xc0de);
        assert_eq!(hex0x(&rc.body().unwrap().hash()), rf["relay_call_hash"].as_str().unwrap(), "our RelayCall layout = Tact's");
        assert_eq!(parse_metaop(&rc.pay_op).unwrap().pay_ref, r);
        assert_eq!(alloy::hex::encode(boc_serialize(&relay_refund_body(&a("from"), &r).unwrap())), rf["relay_refund_boc"].as_str().unwrap());
        // every ref of the call counts: a change two levels down moves the ref
        let other = Builder::new().uint(0x5b0a1d01, 32).reference(Builder::new().reference(Builder::new().uint(9, 8).end().unwrap()).end().unwrap())
            .reference(Builder::new().uint(2, 8).end().unwrap()).end().unwrap();
        assert_ne!(relay_ref(-239, &a("target"), &other, &salt), r);
    }

    /// Rule 8: every check runs before any getter (an unreachable API), each with its reason; a plain pay to the router
    /// and a non-string `op.kind` are refused.
    #[tokio::test]
    async fn ton_relay_fee_job_checks_ref() {
        let (o, _, cell0, r) = relay_job(25, |_| {});
        let (router, rc) = relay_fee_job(&policy(), -239, &cell0, &o).unwrap();
        assert_eq!((router, rc.target, rc.master, rc.salt), (ROUTER, target(), MASTER, [0x5a; 32]));
        let err = |o: &Value, p: &RelayFeePolicy| {
            let c = boc_parse(&alloy::hex::decode(o["payload"].as_str().unwrap()).unwrap()).unwrap();
            relay_fee_job(p, -239, &c, o).unwrap_err().to_string()
        };
        assert_eq!(err(&o, &RelayFeePolicy { router: None, ..policy() }), "params.relay_fee.router is not set");
        assert_eq!(err(&o, &RelayFeePolicy { router: Some(target()), ..policy() }), "op.contract is not params.relay_fee.router");
        assert_eq!(err(&o, &RelayFeePolicy { tokens: vec![], ..policy() }), format!("token {} is not registered on this chain", MASTER.raw()));
        assert_eq!(err(&o, &RelayFeePolicy { min_ton_value: HashMap::new(), ..policy() }),
                   format!("params.relay_fee.min_ton_value has no price for token {}", MASTER.raw()));
        assert_eq!(err(&relay_job(4, |_| {}).0, &policy()), "fee 4 is below relay_fee.min_amount 5");
        const BOUND: &str = "the payment is not bound to this call (ref, payLane(ref), nonce 0, relayer = to = router)";
        assert_eq!(err(&relay_job(25, |m| m.lane = [1; 32]).0, &policy()), BOUND);
        assert_eq!(err(&relay_job(25, |m| m.nonce = 1).0, &policy()), BOUND);
        assert_eq!(err(&relay_job(25, |m| m.relayer = None).0, &policy()), BOUND);
        assert_eq!(err(&relay_job(25, |m| m.to = MASTER).0, &policy()), BOUND);
        assert_eq!(err(&relay_job(25, |m| m.op = 2).0, &policy()), "the relay-fee payment is not a pay op");
        // the call: a served fee-less entry, never a pay, never bound to the router (R18)
        const SERVED: &str = "op.extra.call is not a served fee-less entry (a SignedOp revoke / set_key not bound to the router)";
        assert_eq!(err(&relay_job_with(25, served_call(1, None), |_| {}).0, &policy()), SERVED);
        assert_eq!(err(&relay_job_with(25, served_call(5, Some(&ROUTER)), |_| {}).0, &policy()), SERVED);
        assert_eq!(err(&relay_job_with(25, Builder::new().uint(1, 32).end().unwrap(), |_| {}).0, &policy()), SERVED);
        assert!(relay_fee_job(&policy(), -239, &relay_job_with(25, served_call(4, None), |_| {}).2, &relay_job_with(25, served_call(4, None), |_| {}).0).is_ok());
        let with = |k: &str, val: Value| {
            let mut x = o.clone();
            x["extra"][k] = val;
            x
        };
        assert_eq!(err(&with("salt", json!("5b".repeat(32))), &policy()), BOUND, "a different salt");
        assert_eq!(err(&with("target", json!(MASTER.raw())), &policy()), "op.extra.target_code / target_data do not derive op.extra.target");
        assert_eq!(err(&with("target_data", json!(alloy::hex::encode(boc_serialize(&Builder::new().end().unwrap())))), &policy()),
                   "op.extra.target_code / target_data do not derive op.extra.target");
        assert_eq!(err(&with("target_code", json!("zz")), &policy()), "op.extra.target_code");
        assert!(err(&with("salt", json!("5a")), &policy()).contains("32 bytes"));
        assert_eq!(err(&with("call", json!("zz")), &policy()), "op.extra.call");
        assert_eq!(err(&with("call", json!("b5ee")), &policy()), "op.extra.call");
        assert!(err(&with("master", json!("nope")), &policy()).contains("op.extra.master"));
        let mut bad_ref = o.clone();
        bad_ref["ref"] = json!(hex0x(&[0; 32]));
        assert_eq!(err(&bad_ref, &policy()), "op.ref != relay_ref(target, call, salt)");
        let mut good_ref = o.clone();
        good_ref["ref"] = json!(hex0x(&r));
        assert!(relay_fee_job(&policy(), -239, &cell0, &good_ref).is_ok());

        // through `build` on an adapter whose API is unreachable: refused before any getter
        let tok = vec![crate::config::TokenCfg { address: MASTER.raw(), decimals: 9 }];
        let dead = adapter_with("http://127.0.0.1:9", relay_params(100_000_000), tok).unwrap();
        let refused = |o: Value| {
            let dead = &dead;
            async move {
                match dead.build(&job_of(&o), 0).await {
                    Err(SimError::Revert(e)) => e,
                    other => panic!("{other:?}"),
                }
            }
        };
        assert!(refused(relay_job(4, |_| {}).0).await.contains("below relay_fee.min_amount"));
        assert!(refused(relay_job(25, |m| m.lane = [1; 32]).0).await.contains("not bound"));
        assert!(refused(relay_job(25, |m| m.valid_until = 1).0).await.contains("expired"));
        // the router-bound payment sent as a plain pay is refused (only the router may submit it), so is a non-string kind
        let (plain, _) = pay_job([3; 32], [4; 32], 0, 1, json!({}));
        let mut to_router = plain.op.clone().unwrap();
        let mut plain_to_router = o.clone();
        plain_to_router.as_object_mut().unwrap().remove("kind");
        plain_to_router["contract"] = json!(parse_metaop(&cell0).unwrap().contract.raw());
        assert!(refused(plain_to_router).await.contains("bound to another relayer"));
        to_router["kind"] = json!(7);
        assert!(refused(to_router).await.contains("unknown op.kind 7"));
    }

    /// The plain pay to the router (relayer open, to = router) is refused before any getter (rule 4: never pay the router).
    #[tokio::test]
    async fn ton_plain_pay_to_router_refused() {
        let mut params = toml::Table::new();
        params.insert("relay_fee".into(), toml::Value::Table(toml::toml! { router = "0:0202020202020202020202020202020202020202020202020202020202020202" }));
        let dead = adapter_with("http://127.0.0.1:9", params, vec![]).unwrap();
        let (job, _) = pay_job([3; 32], [4; 32], 0, 1, json!({})); // pay_job pays 0:0202…02
        match dead.build(&job, 0).await {
            Err(SimError::Revert(e)) => assert!(e.contains("plain pay to the relay-fee router"), "{e}"),
            other => panic!("{other:?}"),
        }
    }

    /// Rule 8: a configured but unparsable `params.relay_fee.router` / `min_amount` / `min_ton_value` / token fails at
    /// startup.
    #[test]
    fn ton_relay_fee_policy_config() {
        let cfg = |t: toml::Table, tokens: Vec<&str>| {
            let mut p = toml::Table::new();
            p.insert("relay_fee".into(), toml::Value::Table(t));
            adapter_with("http://127.0.0.1:9", p, tokens.into_iter().map(|a| crate::config::TokenCfg { address: a.into(), decimals: 9 }).collect())
        };
        assert!(adapter("http://127.0.0.1:9").relay_fee.router.is_none(), "no relay_fee: relay-fee jobs refused");
        let ok = adapter_with("http://127.0.0.1:9", relay_params(7), vec![crate::config::TokenCfg { address: MASTER.raw(), decimals: 9 }]).unwrap();
        assert_eq!((ok.relay_fee.router, ok.relay_fee.params.min_amount, ok.relay_fee.tokens.clone()), (Some(ROUTER), 5, vec![MASTER]));
        assert_eq!(ok.relay_fee.min_ton_value.get(&MASTER), Some(&7));
        for (t, what) in [(toml::toml! { router = "0:zz" }, "router"), (toml::toml! { router = 7 }, "router"),
                          (toml::toml! { min_amount = "9" }, "min_amount"), (toml::toml! { min_amount = -1 }, "min_amount"),
                          (toml::toml! { min_ton_value = 5 }, "min_ton_value"), (toml::toml! { min_ton_value = { nope = 5 } }, "min_ton_value"),
                          (toml::toml! { min_ton_value = { "0:5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e" = -5 } }, "min_ton_value")] {
            let e = cfg(t, vec![]).err().map(|e| format!("{e:#}")).unwrap_or_default();
            assert!(e.contains(&format!("params.relay_fee.{what}")), "{what}: {e}");
        }
        let e = cfg(toml::Table::new(), vec!["wasm1nope"]).err().map(|e| format!("{e:#}")).unwrap_or_default();
        assert!(e.contains("tokens: wasm1nope"), "{e}");
    }

    fn paid_event(r: &[u8; 32], payer: &Addr, payee: &Addr) -> Arc<Cell> {
        Builder::new().uint(EV_RELAY_FEE_PAID, 32).bytes(r).addr(Some(&target())).addr(Some(&MASTER))
            .reference(Builder::new().addr(Some(payer)).addr(Some(payee)).coins(25).end().unwrap()).end().unwrap()
    }

    fn refunded_event(r: &[u8; 32], payer: &Addr, relayer: &Addr, amount: u128) -> Arc<Cell> {
        Builder::new().uint(EV_RELAY_FEE_REFUNDED, 32).bytes(r).addr(Some(payer)).addr(Some(relayer)).coins(amount).end().unwrap()
    }

    /// The router's event layouts, byte for byte the Tact contract's (@ton/core vectors).
    #[test]
    fn ton_relay_fee_event_vectors() {
        let v = vectors();
        let rf = &v["relay_fee"];
        let a = |k: &str| Addr::parse(rf[k].as_str().unwrap()).unwrap();
        let r: [u8; 32] = hexv(&rf["ref"]).try_into().unwrap();
        let paid = cell(&v, "/relay_fee/paid_boc");
        let refunded = cell(&v, "/relay_fee/refunded_boc");
        assert_eq!(paid.hash(), paid_event_at(&r, &a("target"), &a("token"), &a("from"), &a("relayer")).hash());
        assert_eq!(settled_event(&paid, &a("relayer"), &a("from"), &r), Some(true));
        assert_eq!(settled_event(&refunded, &a("relayer"), &a("from"), &r), Some(false));
        assert_eq!(settled_event(&paid, &a("from"), &a("from"), &r), None, "another payee");
        assert_eq!(settled_event(&refunded, &a("from"), &a("from"), &r), None, "another relayer");
    }

    fn paid_event_at(r: &[u8; 32], target: &Addr, token: &Addr, payer: &Addr, payee: &Addr) -> Arc<Cell> {
        Builder::new().uint(EV_RELAY_FEE_PAID, 32).bytes(r).addr(Some(target)).addr(Some(token))
            .reference(Builder::new().addr(Some(payer)).addr(Some(payee)).coins(25).end().unwrap()).end().unwrap()
    }

    /// §9: the relay-fee job builds the router's `RelayCall` (deadline inside RELAY_TIMEOUT, the TON the router prices
    /// on that body, a fee worth it at `min_ton_value`), then the escrow is tracked: pending while open, and once closed
    /// identified positively (`RelayFeePaid` = mined, `RelayFeeRefunded` = reverted of this payer and ref; neither seen =
    /// still pending, never "refunded" by absence).
    #[tokio::test]
    async fn ton_relay_fee_job_tracks_escrow() {
        let call = signed_call_at(&target(), &[1; 32], |_| {});
        let (o, m, _, r) = relay_job_with(25, call.clone(), |_| {});
        let mut getters = relay_getters();
        getters.insert("get_escrow_state".into(), num(2));
        let (url, shared) = fake_api_shared(Fake { getters, ..Default::default() }).await;
        let tok = || vec![crate::config::TokenCfg { address: MASTER.raw(), decimals: 9 }];
        // the fee must be worth the TON the relay puts at risk: 25 units × 12,266,666 < 306,666,673
        let cheap = adapter_with(&url, relay_params(12_266_666), tok()).unwrap();
        match cheap.build(&job_of(&o), 0).await {
            Err(SimError::Revert(e)) => assert!(e.contains("below the 306666673 nanoton"), "{e}"),
            other => panic!("{other:?}"),
        }
        let a = adapter_with(&url, relay_params(12_266_667), tok()).unwrap();
        let now = crate::submit::now();
        let b = a.build(&job_of(&o), 0).await.unwrap();
        let rc = RelayCall::parse(&boc_parse(&b.body).unwrap()).unwrap();
        assert_eq!((rc.target, rc.master, rc.pay_wallet, rc.salt), (target(), MASTER, m.contract, [0x5a; 32]));
        assert_eq!((rc.target_code.hash(), rc.call.hash()), (target_init().0.hash(), call.hash()));
        assert_eq!(rc.pay_op.hash(), m.digest);
        assert!(rc.pay_state_init.is_some(), "the payer's StateInit binds its key on first use");
        assert!((now + RELAY_DEADLINE_S..=now + RELAY_DEADLINE_S + 5).contains(&(rc.deadline as u64)) && RELAY_DEADLINE_S < 3600);
        assert_eq!((b.meta["to"].as_str().unwrap(), b.meta["value"].as_str().unwrap()), (ROUTER.raw().as_str(), "306666673"));
        assert!(b.valid_until <= rc.deadline as u64);

        // the lane tx carries the RelayCall to the router; the router's tx ran
        let me = a.lane_wallet(0).unwrap().address().unwrap();
        let (lane_tx, h1) = ([0x0au8; 32], [0x01u8; 32]);
        let ok = json!({"compute_ph": {"success": true, "exit_code": 0}});
        let lane = json!({"account": me.raw(), "description": ok, "out_msgs": [
            {"hash": b64encode(&h1), "destination": ROUTER.raw(), "bounce": true, "message_content": {"body": b64encode(&b.body)}}]});
        let router_tx = |d: Value| json!({"account": ROUTER.raw(), "description": d, "out_msgs": []});
        let at = |k: &[u8; 32]| alloy::hex::encode(k);
        let id = hex0x(&lane_tx);
        shared.lock().unwrap().by_msg.insert(at(&lane_tx), lane.clone());
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Pending, "router tx not seen yet");
        shared.lock().unwrap().by_msg.insert(at(&h1), router_tx(json!({"aborted": true, "compute_ph": {"success": false, "exit_code": 742}})));
        assert!(matches!(a.tx_status(&id).await.unwrap(), TxStatus::Reverted { reason } if reason.contains("742")), "the router refused it");
        shared.lock().unwrap().by_msg.insert(at(&h1), router_tx(ok.clone()));
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Pending, "escrow open (funded, the call is out)");
        assert!(shared.lock().unwrap().posted.is_empty(), "no refund before the deadline");
        // closed, but no event of OUR relay of this (payer, ref) seen yet: another payer's, another ref's, another
        // relayer's release, a griefer's copied RelayCall refunded with amount 0 to itself: still pending
        shared.lock().unwrap().getters.insert("get_escrow_state".into(), num(0));
        let ev = |c: &Arc<Cell>, h: u8, seq: u64| json!({"hash": b64encode(&[h; 32]), "description": ok, "mc_block_seqno": seq,
            "out_msgs": [{"destination": null, "message_content": {"body": b64encode(&boc_serialize(c))}}]});
        let griefer = Addr { wc: 0, hash: [0x6e; 32] };
        shared.lock().unwrap().by_account = vec![ev(&refunded_event(&r, &m.from, &griefer, 0), 0x0a, 11), ev(&paid_event(&r, &MASTER, &me), 0x0d, 10),
            ev(&refunded_event(&[9; 32], &m.from, &me, 25), 0x0e, 9), ev(&paid_event(&r, &m.from, &griefer), 0x0b, 8)];
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Pending, "never refunded by absence, never another relayer's outcome");
        // ours refunded, positively
        shared.lock().unwrap().by_account.push(ev(&refunded_event(&r, &m.from, &me, 25), 0x0f, 7));
        let refunded = a.tx_status(&id).await.unwrap();
        assert!(matches!(&refunded, TxStatus::Reverted { reason } if reason.contains("refunded")), "{refunded:?}");
        // ours released: a release wins over a refund of ours (an earlier attempt), whatever the order
        shared.lock().unwrap().by_account = vec![ev(&refunded_event(&r, &m.from, &me, 0), 0x0f, 8), ev(&paid_event(&r, &m.from, &me), 0x0c, 7)];
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Mined { height: 7, tx_hash: Some(hex0x(&[0x0c; 32])) });
        // a relay-fee job is never "consumed" by its spent pay lane (a refunded escrow spends it too)
        assert_eq!(a.op_consumed(&job_of(&o)).await.unwrap(), None);
    }

    async fn try_relay(a: &TonAdapter, tgt: (Arc<Cell>, Arc<Cell>, Addr), call: Arc<Cell>) -> std::result::Result<Built, SimError> {
        a.build(&job_of(&relay_job_at(25, tgt, call, |_| {}).0), 0).await
    }

    /// The relay is refused for `why` by the call check, before the router is asked to price it (`get_relay_value`,
    /// the step before the lane sends).
    async fn refused_before_send(a: &TonAdapter, f: &Shared, tgt: (Arc<Cell>, Arc<Cell>, Addr), call: Arc<Cell>, why: &str) {
        let e = job_refused_before_send(a, f, &relay_job_at(25, tgt, call, |_| {}).0, why).await;
        assert!(e.starts_with("RELAY_CALL_REFUSED"), "{why}: {e}");
    }

    /// The relay-fee job `o` is refused for `why` before the router is asked to price it; the reason.
    async fn job_refused_before_send(a: &TonAdapter, f: &Shared, o: &Value, why: &str) -> String {
        f.lock().unwrap().ran.clear();
        let e = match a.build(&job_of(o), 0).await {
            Err(SimError::Revert(e)) => e,
            other => panic!("{why}: {other:?}"),
        };
        assert!(e.contains(why), "{why}: {e}");
        let ran = f.lock().unwrap().ran.clone();
        assert!(!ran.iter().any(|m| m == "get_relay_value"), "{why}: priced for sending after the refusal: {ran:?}");
        e
    }

    /// P1 (fix-wave re-review): the payment leg is checked like the wallet runs it, so it cannot bounce at the payer's
    /// wallet after the router escrowed it: valid at most LANE_TTL ahead (E_TTL), within the wallet's balance (E_BALANCE).
    #[tokio::test]
    async fn ton_relay_fee_refuses_failing_payment_before_send() {
        let (url, sh) = fake_api_shared(Fake { getters: relay_getters(), ..Default::default() }).await;
        let a = adapter_with(&url, relay_params(12_266_667), vec![crate::config::TokenCfg { address: MASTER.raw(), decimals: 9 }]).unwrap();
        let call = || signed_call_at(&target(), &[1; 32], |_| {});
        let (o, m, _, _) = relay_job_with(25, call(), |_| {});
        assert!(a.build(&job_of(&o), 0).await.is_ok(), "a payment within the balance and LANE_TTL");
        let far = relay_job_with(25, call(), |m| m.valid_until = crate::submit::now() + LANE_TTL_S + 600).0;
        job_refused_before_send(&a, &sh, &far, "LANE_TTL").await;
        // q1: a balance equal to the amount pays
        sh.lock().unwrap().getters.insert(format!("get_wallet_data@{}", m.contract.raw()), num(25));
        assert!(a.build(&job_of(&o), 0).await.is_ok(), "balance == amount");
        sh.lock().unwrap().getters.insert(format!("get_wallet_data@{}", m.contract.raw()), num(24));
        job_refused_before_send(&a, &sh, &o, "holds 24, the payment is 25").await;
    }

    /// I1 (final review; fix round 1: F1, F2, m1, m4): the relayed call is checked on its target before anything is sent,
    /// so the relayer never pays the bounce of a call bound to fail. Every check has a case that fails without it.
    #[tokio::test]
    async fn ton_relay_fee_refuses_failing_call_before_send() {
        let (url, sh) = fake_api_shared(Fake { getters: relay_getters(), ..Default::default() }).await;
        let a = adapter_with(&url, relay_params(12_266_667), vec![crate::config::TokenCfg { address: MASTER.raw(), decimals: 9 }]).unwrap();
        let (w, t) = (target_init(), target());
        let ok = |r: std::result::Result<Built, SimError>, what: &str| assert!(r.is_ok(), "{what}: {r:?}");
        let call = |f: &dyn Fn(&mut MetaOp)| signed_call_at(&t, &[1; 32], f);
        let other = Addr { wc: 0, hash: [0x99; 32] };
        // a passkey record: pubkey:264 rpIdHash:256 ^origin (jetton.tact set_key)
        let record = Builder::new().bytes(&[2; 33]).bytes(&[3; 32]).reference(Builder::new().bytes(b"https://x").end().unwrap()).end().unwrap();
        let junk = Builder::new().uint(1, 8).end().unwrap();
        let passkey = auth_cell(&Auth::Passkey { r: [1; 32], s: [2; 32], authenticator_data: vec![0; 37],
            client_data_json: format!("{CDJ_PREFIX}{}\",\"origin\":\"https://x\"}}", "A".repeat(43)) }).unwrap();

        ok(try_relay(&a, w.clone(), call(&|_| {})).await, "the owner's own set_key (drop the passkey)");
        ok(try_relay(&a, w.clone(), resign(&call(&|m| m.extra = record.hash()), Some(record.clone()), None, None, None)).await, "set_key of a record");
        // the envelope
        refused_before_send(&a, &sh, w.clone(), call(&|m| m.contract = other), "contract, network or from").await;
        refused_before_send(&a, &sh, w.clone(), call(&|m| m.network = -3), "contract, network or from").await;
        refused_before_send(&a, &sh, w.clone(), call(&|m| m.from = other), "contract, network or from").await;
        refused_before_send(&a, &sh, w.clone(), call(&|m| m.valid_until = crate::submit::now() + 60), "deadline").await;
        refused_before_send(&a, &sh, w.clone(), call(&|m| m.relayer = Some(other)), "relayer other than its executor").await;
        refused_before_send(&a, &sh, w.clone(), resign(&call(&|_| {}), None, None, Some(other), None), "not the payer's executor").await;
        refused_before_send(&a, &sh, w.clone(), served_call(5, None), "").await;
        // the jetton wallet
        refused_before_send(&a, &sh, w.clone(), signed_call_at(&t, &[3; 32], |_| {}), "signature does not verify").await;
        refused_before_send(&a, &sh, w.clone(), call(&|m| m.valid_until = crate::submit::now() + LANE_TTL_S + 600), "LANE_TTL").await;
        refused_before_send(&a, &sh, w.clone(), resign(&call(&|m| m.op = 4), None, Some(passkey.clone()), None, None), "passkey").await;
        refused_before_send(&a, &sh, w.clone(), resign(&call(&|_| {}), None, Some(passkey.clone()), None, None), "passkey").await;
        refused_before_send(&a, &sh, w.clone(), call(&|m| m.extra = [9; 32]), "set_key").await;
        refused_before_send(&a, &sh, w.clone(), resign(&call(&|m| m.extra = [9; 32]), Some(record.clone()), None, None, None), "set_key").await;
        refused_before_send(&a, &sh, w.clone(), resign(&call(&|m| m.extra = junk.hash()), Some(junk.clone()), None, None, None), "set_key").await;
        // a revoke of an order already out (the lane is at n + 1) forwards its cancel
        sh.lock().unwrap().getters.insert(format!("get_lane_nonce@{}", t.raw()), num(1));
        refused_before_send(&a, &sh, w.clone(), call(&|m| m.op = 4), "CANCEL_TON").await;
        ok(try_relay(&a, w.clone(), resign(&call(&|m| m.op = 4), None, None, None, Some(CANCEL_TON))).await, "a cancel with CANCEL_TON");
        sh.lock().unwrap().getters.remove(&format!("get_lane_nonce@{}", t.raw()));
        // a code that is neither the wallet's nor the Mandate's: refused for good, never retried
        let unknown = target_of(Builder::new().uint(0xbad, 16).end().unwrap());
        refused_before_send(&a, &sh, unknown.clone(), signed_call_at(&unknown.2, &[1; 32], |m| m.op = 4), "unknown target code").await;
        // the Mandate: an owner revoke, TON Connect, at its lane nonce, by the owner key, of a live Mandate
        let md = mandate_init();
        let revoke = |key: &[u8; 32]| signed_call_at(&md.2, key, |m| m.op = 4);
        ok(try_relay(&a, md.clone(), revoke(&[1; 32])).await, "the owner's revoke");
        refused_before_send(&a, &sh, md.clone(), revoke(&[3; 32]), "ownerPubkey").await;
        refused_before_send(&a, &sh, md.clone(), signed_call_at(&md.2, &[1; 32], |_| {}), "only the owner's revoke").await;
        refused_before_send(&a, &sh, md.clone(), resign(&revoke(&[1; 32]), None, Some(passkey.clone()), None, None), "TON Connect").await;
        sh.lock().unwrap().getters.insert(format!("get_lane_nonce@{}", md.2.raw()), num(1));
        refused_before_send(&a, &sh, md.clone(), revoke(&[1; 32]), "Mandate lane nonce is 1").await;
        sh.lock().unwrap().getters.remove(&format!("get_lane_nonce@{}", md.2.raw()));
        sh.lock().unwrap().getters.insert("get_state".into(), mandate_state(true));
        refused_before_send(&a, &sh, md.clone(), revoke(&[1; 32]), "already revoked").await;
    }

    /// §9: past the deadline with the escrow funded, or at any time when a settlement is owed (its transfer bounced),
    /// the node sends `RelayRefund { from, ref }` from the relay's lane with the router's `get_refund_value`, once per
    /// retry window.
    #[tokio::test]
    async fn ton_relay_fee_refunds_after_deadline() {
        let (_, m, op, r) = relay_job(25, |_| {});
        let getters = HashMap::from([("get_escrow_state".into(), num(2)), ("get_refund_value".into(), num(41_000_000))]);
        let (url, shared) = fake_api_shared(Fake { getters, ..Default::default() }).await;
        let a = adapter(&url);
        let rc = relay_call_of(&m, op, (crate::submit::now() - 1) as u32);
        let me = a.lane_wallet(0).unwrap().address().unwrap();
        let (lane_tx, h1) = ([0x0au8; 32], [0x01u8; 32]);
        let ok = json!({"compute_ph": {"success": true, "exit_code": 0}});
        let carry = |rc: &RelayCall| json!({"account": me.raw(), "description": ok, "out_msgs": [
            {"hash": b64encode(&h1), "destination": ROUTER.raw(), "bounce": true, "message_content": {"body": b64encode(&boc_serialize(&rc.body().unwrap()))}}]});
        {
            let mut f = shared.lock().unwrap();
            f.by_msg.insert(alloy::hex::encode(lane_tx), carry(&rc));
            f.by_msg.insert(alloy::hex::encode(h1), json!({"account": ROUTER.raw(), "description": ok, "out_msgs": []}));
        }
        let id = hex0x(&lane_tx);
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Pending);
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Pending);
        let posted = shared.lock().unwrap().posted.clone();
        assert_eq!(posted.len(), 1, "one RelayRefund per retry window");
        // the lane's external message carries RelayRefund { from: payer, ref } with the router's refund value
        let ext = boc_parse(&b64decode(posted[0]["boc"].as_str().unwrap()).unwrap()).unwrap();
        fn find(c: &Arc<Cell>, h: &[u8; 32]) -> bool {
            c.hash() == *h || c.refs().iter().any(|x| find(x, h))
        }
        assert!(find(&ext, &relay_refund_body(&m.from, &r).unwrap().hash()));
        let relaxed = internal_message(&ROUTER, 41_000_000, relay_refund_body(&m.from, &r).unwrap()).unwrap();
        assert!(find(&ext, &relaxed.hash()), "sent with get_refund_value");
        // the retry window passed: sent again
        a.refunds.write().unwrap().insert(escrow_key(&m.from, &r).unwrap(), crate::submit::now() - RELAY_REFUND_RETRY_S);
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Pending);
        assert_eq!(shared.lock().unwrap().posted.len(), 2);
        // before the deadline nothing is sent while funded…
        let early = RelayCall { deadline: (crate::submit::now() + 60) as u32, ..rc };
        shared.lock().unwrap().by_msg.insert(alloy::hex::encode(lane_tx), carry(&early));
        a.refunds.write().unwrap().clear();
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Pending);
        assert_eq!(shared.lock().unwrap().posted.len(), 2);
        // …but an owed settlement (state 3 / 4) is sent again at once
        shared.lock().unwrap().getters.insert("get_escrow_state".into(), num(3));
        assert_eq!(a.tx_status(&id).await.unwrap(), TxStatus::Pending);
        assert_eq!(shared.lock().unwrap().posted.len(), 3);
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
                let _ = pay_params(&m, &o, MAX_PAY_META_BYTES);
                let id = meta_pay_id(salt.as_bytes(), &meta);
                m.pay_ref = id;
                m.lane = pay_lane(&id);
                let _ = pay_params(&m, &o, MAX_PAY_META_BYTES);
            }

            /// Rule 8: the relay-fee job and the RelayCall parser on untrusted input: no panic.
            #[test]
            fn relay_fee_job_never_panics(extra in "\\PC{0,160}", at in 0usize..4000, byte in any::<u8>(), cut in 0usize..64,
                                          body in proptest::collection::vec(any::<u8>(), 0..300)) {
                let (o, _, c, _) = relay_job(25, |_| {});
                let mut x = o.clone();
                x["extra"] = serde_json::from_str(&extra).unwrap_or(json!({"target": extra, "call": extra, "salt": extra, "master": extra}));
                let _ = relay_fee_job(&policy(), -239, &c, &x);
                let mut raw = serde_json::to_vec(&o).unwrap();
                let i = at % raw.len();
                raw[i] = byte;
                if let Ok(v) = serde_json::from_slice::<Value>(&raw) {
                    if let Some(c) = v["payload"].as_str().and_then(|p| alloy::hex::decode(p).ok()).and_then(|b| boc_parse(&b).ok()) {
                        let _ = relay_fee_job(&policy(), -239, &c, &v);
                    }
                    let _ = pay_params(&parse_metaop(&c).unwrap(), &v, MAX_PAY_META_BYTES);
                }
                if let Ok(c) = boc_parse(&body) {
                    let _ = RelayCall::parse(&c);
                }
                let v = vectors();
                let b = alloy::hex::decode(v["relay_fee"]["relay_call_boc"].as_str().unwrap()).unwrap();
                let _ = boc_parse(&b[..b.len().saturating_sub(cut)]).map(|c| RelayCall::parse(&c));
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
