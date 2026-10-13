//! DEX order book (NODE-DEX-01, NODE-DEX-15): role-free `TradeOrder`s settled by `SCaaSDex.mtxSettle`
//! (contracts/dex.md), one book per market, price-time priority, partial fills, IOC, fill-or-kill (`minFill = amount`).
//! An incoming order that crosses is the taker of ONE settlement against the resting orders it crosses (its makers);
//! every order fills at least `max(minFill, ceil(amount / 2))` per settlement unless the fill closes it, exactly as the
//! token (`TradeLib.record`) and the DEX (`settleOne`) check. PURE (no I/O, tested bit for bit); RPC, the client store
//! and the gateway are in `dex::venue`.
pub mod venue;

use std::collections::HashMap;

use alloy::primitives::{keccak256, Address, Bytes, B256, U256, U512};
use alloy::sol_types::{Eip712Domain, SolStruct, SolValue};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

pub use crate::abi::{CancelOrder, DexOrder, ISCaaSDex, InvalidateNonces, Leg, Settlement, TradeOrder};
use crate::metatx::{addr, uint};

pub const FLAG_IOC: u8 = 1;
/// Path B (escrow + refund): not built by this venue, refused at intake.
pub const FLAG_ESCROW: u8 = 2;
/// Read only on the exchange path (CTR-DEX-23); a book order may carry it.
pub const FLAG_LISTED_POOLS: u8 = 4;
/// `tokenKind`: 1 = SCaaS (the token checks the order), 2 = outside (a `DexOrder`, pulled through the `DexPuller`).
pub const KIND_SCAAS: u8 = 1;
pub const KIND_OUTSIDE: u8 = 2;
/// Whole-book cap of resting orders: a valid order is almost free for its signer (gasless).
pub const MAX_RESTING: usize = 10_000;
pub const MAX_OPEN_PER_MAKER: usize = 50;
pub const MIN_TTL_SECS: u64 = 5;
pub const MAX_TTL_SECS: u64 = 30 * 86_400;
/// `TradeLib.MAX_FEE_PPM`: an order signs at most 1 % DEX fee.
const MAX_FEE_PPM: u64 = 10_000;

/// The salted EIP-712 domain of a SCaaS contract: `(name, "1", chainId, contract, chain_uid)`.
pub fn domain(name: &str, chain_id: u64, contract: Address, chain_uid: B256) -> Eip712Domain {
    Eip712Domain::new(
        Some(name.to_string().into()),
        Some("1".into()),
        Some(U256::from(chain_id)),
        Some(contract),
        Some(chain_uid),
    )
}

/// A SCaaS sell token's order hash: the `TradeOrder` in the token's own domain (`tradeOrderDigest`).
pub fn trade_order_hash(token_domain: &Eip712Domain, o: &TradeOrder) -> B256 {
    o.eip712_signing_hash(token_domain)
}

/// An outside sell token's order hash: `DexOrder(sellToken, order)` in the DEX's domain (`dexOrderDigest`).
pub fn dex_order_hash(dex_domain: &Eip712Domain, sell: Address, o: &TradeOrder) -> B256 {
    DexOrder { sellToken: sell, order: o.clone() }.eip712_signing_hash(dex_domain)
}

pub fn cancel_digest(d: &Eip712Domain, h: B256) -> B256 {
    CancelOrder { orderHash: h }.eip712_signing_hash(d)
}

pub fn invalidate_digest(d: &Eip712Domain, from: Address, batch: U256, min: U256) -> B256 {
    InvalidateNonces { from, batch, minNonce: min }.eip712_signing_hash(d)
}

// ---------------------------------------------------------------------------------- wire

/// `TradeOrder` on the wire (decimal strings, camelCase), as the gateway takes it and the client stores it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WireOrder {
    pub from: String,
    pub receive_token: String,
    pub amount: String,
    pub receive_amount: String,
    pub min_fill: String,
    pub fee: String,
    pub relayer: String,
    pub dex: String,
    pub destination: String,
    pub flags: u8,
    pub batch: String,
    pub nonce: String,
    pub valid_until: String,
}

impl WireOrder {
    pub fn to_sol(&self) -> Result<TradeOrder> {
        Ok(TradeOrder {
            from: addr(&self.from)?,
            receiveToken: addr(&self.receive_token)?,
            amount: uint(&self.amount)?,
            receiveAmount: uint(&self.receive_amount)?,
            minFill: uint(&self.min_fill)?,
            fee: uint(&self.fee)?,
            relayer: addr(&self.relayer)?,
            dex: addr(&self.dex)?,
            destination: addr(&self.destination)?,
            flags: self.flags,
            batch: uint(&self.batch)?,
            nonce: uint(&self.nonce)?,
            validUntil: uint(&self.valid_until)?,
        })
    }

    pub fn from_sol(o: &TradeOrder) -> Self {
        let a = |x: Address| format!("{x:#x}");
        Self {
            from: a(o.from),
            receive_token: a(o.receiveToken),
            amount: o.amount.to_string(),
            receive_amount: o.receiveAmount.to_string(),
            min_fill: o.minFill.to_string(),
            fee: o.fee.to_string(),
            relayer: a(o.relayer),
            dex: a(o.dex),
            destination: a(o.destination),
            flags: o.flags,
            batch: o.batch.to_string(),
            nonce: o.nonce.to_string(),
            valid_until: o.validUntil.to_string(),
        }
    }
}

pub fn hex_bytes(s: &str) -> Result<Bytes> {
    Ok(alloy::hex::decode(s.strip_prefix("0x").ok_or_else(|| anyhow!("not 0x-hex"))?)?.into())
}

pub fn hex_of(b: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(b))
}

// ---------------------------------------------------------------------------------- markets

/// A market as the client configures it (`dex_markets`): venue policy only. The DEX itself holds the listing
/// (`marketListed`) and each token's kind; the fee is each order's signed rate (NODE-DEX-15).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct MarketCfg {
    pub id: i64,
    pub base: Address,
    pub quote: Address,
    pub base_decimals: u8,
    pub quote_decimals: u8,
    /// An order whose signed `fee` is below the rate of the role it would play is not matched in that role.
    #[serde(default)]
    pub maker_fee_ppm: u32,
    #[serde(default)]
    pub taker_fee_ppm: u32,
    #[serde(default = "zero")]
    pub min_base_amount: String,
}

fn zero() -> String {
    "0".into()
}

pub fn pair(a: Address, b: Address) -> (Address, Address) {
    if a < b { (a, b) } else { (b, a) }
}

// ---------------------------------------------------------------------------------- book

/// One order in the book. `remaining` is in the sell token, net of every settlement planned and not yet failed.
#[derive(Debug, Clone, PartialEq)]
pub struct Resting {
    pub hash: B256,
    pub sell: Address,
    pub order: TradeOrder,
    pub sig: Bytes,
    pub remaining: U256,
    pub seq: u64,
}

/// The row the client stores (`blockchain.dex.order`): enough to rebuild the book in order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Row {
    pub order_hash: String,
    pub sell_token: String,
    pub order: WireOrder,
    pub signature: String,
    pub remaining: String,
    pub seq: u64,
}

impl Row {
    pub fn of(r: &Resting) -> Self {
        Self {
            order_hash: format!("{:#x}", r.hash),
            sell_token: format!("{:#x}", r.sell),
            order: WireOrder::from_sol(&r.order),
            signature: hex_of(&r.sig),
            remaining: r.remaining.to_string(),
            seq: r.seq,
        }
    }

    pub fn resting(&self) -> Result<Resting> {
        Ok(Resting {
            hash: self.order_hash.parse()?,
            sell: addr(&self.sell_token)?,
            order: self.order.to_sol()?,
            sig: hex_bytes(&self.signature)?,
            remaining: uint(&self.remaining)?,
            seq: self.seq,
        })
    }
}

/// One settlement on its way to the chain: the taker (as it was before) sells `taker_fill` (= Σ makers' receive) and
/// receives Σ maker sell fills. `tag` is `Settlement.ref` on chain and the trade's key in the client.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedSettlement {
    pub tag: B256,
    pub market_id: i64,
    pub taker: Resting,
    pub taker_fill: U256,
    /// `(maker as it was, its sell fill x, what it receives y = ceil(x · receiveAmount / amount))`.
    pub makers: Vec<(Resting, U256, U256)>,
}

impl PlannedSettlement {
    pub fn to_settlement(&self) -> Settlement {
        // shape 0: the book holds `TradeOrder`s only (UA intake waits for UA F5, C5b-11)
        let leg = |r: &Resting, fill: U256| Leg {
            sellToken: r.sell, shape: 0, order: r.order.abi_encode().into(), sig: r.sig.clone(), fill,
        };
        Settlement {
            r#ref: self.tag,
            taker: leg(&self.taker, self.taker_fill),
            makers: self.makers.iter().map(|(m, x, _)| leg(m, *x)).collect(),
        }
    }

    /// What the taker receives: the makers' sell fills.
    pub fn taker_receives(&self) -> U256 {
        self.makers.iter().map(|(_, x, _)| *x).sum()
    }

    pub fn valid_until(&self) -> U256 {
        self.makers.iter().map(|(m, _, _)| m.order.validUntil).chain([self.taker.order.validUntil]).min().unwrap_or_default()
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct Placement {
    pub settlement: Option<PlannedSettlement>,
    /// The remainder in the book (GTC, not crossing).
    pub rested: Option<Resting>,
    /// The remainder cancelled: IOC, or a remainder that would rest crossed (it cannot meet a crossing order's
    /// minimum fill, so it would sit there locked).
    pub dropped: U256,
    /// Makers taken off the book as dust (NODE-DEX-05): they cannot receive one unit for their remainder.
    pub dust: Vec<Resting>,
    /// Time priority given to this order, rested or not.
    pub seq: u64,
}

#[derive(Debug, Clone)]
struct MarketBook {
    cfg: MarketCfg,
    /// Orders selling base, best first.
    asks: Vec<Resting>,
    /// Orders selling quote, best first.
    bids: Vec<Resting>,
}

impl MarketBook {
    fn side_mut(&mut self, sell: Address) -> &mut Vec<Resting> {
        if sell == self.cfg.base { &mut self.asks } else { &mut self.bids }
    }
}

/// `a` offers the opposite side more per unit received than `b` (`a.amount / a.receiveAmount` larger), by
/// cross-multiplication (amounts at intake `< 2^128`, so no U512 overflow).
fn better(a: &TradeOrder, b: &TradeOrder) -> bool {
    mul(a.amount, b.receiveAmount) > mul(b.amount, a.receiveAmount)
}

fn mul(a: U256, b: U256) -> U512 {
    U512::from(a) * U512::from(b)
}

fn crosses(rest: &TradeOrder, inc: &TradeOrder) -> bool {
    mul(rest.receiveAmount, inc.receiveAmount) <= mul(inc.amount, rest.amount)
}

fn div_ceil(a: U512, b: U512) -> U512 {
    (a + b - U512::from(1u8)) / b
}

fn to256(v: U512) -> U256 {
    U256::from_limbs_slice(&v.as_limbs()[..4])
}

/// The effective minimum sell fill per settlement: `max(minFill, ceil(amount / 2))` (`TradeLib.record`).
pub fn min_fill(o: &TradeOrder) -> U256 {
    o.minFill.max(o.amount - o.amount / U256::from(2u8))
}

/// What a maker receives for selling `x` at its own price: `ceil(x · receiveAmount / amount)` (`SCaaSDex._makerCalc`).
pub fn maker_receives(o: &TradeOrder, x: U256) -> U256 {
    to256(div_ceil(mul(x, o.receiveAmount), U512::from(o.amount)))
}

/// One maker against the taker for `x` (maker sells) and `y` (taker sells) at the maker's price, exactly as the
/// token and the DEX check it: in the remainders, `y` is the maker's receive, both price limits hold.
pub fn limits_ok(maker: &Resting, taker: &Resting, x: U256, y: U256) -> bool {
    let (m, t) = (&maker.order, &taker.order);
    !x.is_zero()
        && !y.is_zero()
        && x <= maker.remaining
        && y <= taker.remaining
        && y == maker_receives(m, x)
        && mul(y, m.amount) >= mul(x, m.receiveAmount)
        && mul(x, t.amount) >= mul(y, t.receiveAmount)
}

/// The whole settlement as the chain checks it (a mirror for tests and the venue's last guard): every maker leg in
/// limits and at least its minimum unless it closes, the taker's fill = Σ makers' receive and at least its minimum
/// unless it closes, no self-trade, no duplicate maker, makers on the taker's opposite side.
pub fn settlement_ok(s: &PlannedSettlement) -> bool {
    let t = &s.taker;
    let mut seen = Vec::new();
    let legs_ok = s.makers.iter().all(|(m, x, y)| {
        let fresh = !seen.contains(&m.hash);
        seen.push(m.hash);
        fresh
            && m.order.from != t.order.from
            && m.sell == t.order.receiveToken
            && m.order.receiveToken == t.sell
            && limits_ok(m, t, *x, *y)
            && (*x >= min_fill(&m.order) || *x == m.remaining)
    });
    let sum: U256 = s.makers.iter().map(|(_, _, y)| *y).sum();
    legs_ok
        && !s.makers.is_empty()
        && s.taker_fill == sum
        && sum <= t.remaining
        && (sum >= min_fill(&t.order) || sum == t.remaining)
        && mul(s.taker_receives(), t.order.amount) >= mul(sum, t.order.receiveAmount)
}

/// A unique tag per settlement. The orders and fills alone are not enough: a failed settlement handed back to the
/// book re-matches exactly as before, and the client treats a repeated tag as a replay. Per-process salt + counter.
fn tag(taker: &Resting, salt: u64, n: u64) -> B256 {
    let mut b = Vec::with_capacity(80);
    b.extend_from_slice(taker.hash.as_slice());
    b.extend_from_slice(&taker.remaining.to_be_bytes::<32>());
    b.extend_from_slice(&salt.to_be_bytes());
    b.extend_from_slice(&n.to_be_bytes());
    keccak256(b)
}

fn random_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    std::collections::hash_map::RandomState::new().build_hasher().finish()
}

#[derive(Debug, Clone, Default)]
pub struct Book {
    markets: HashMap<(Address, Address), MarketBook>,
    next_seq: u64,
    salt: u64,
    made: u64,
    /// Per order hash: sell fills planned and not yet final (mined `LegSettled`) or failed. The chain's closing clause
    /// is `sellFill == amount − pulled` with `pulled` as mined, so a remainder closes only while this is 0.
    pending: HashMap<B256, U256>,
}

impl Book {
    pub fn new(markets: Vec<MarketCfg>) -> Self {
        let markets = markets
            .into_iter()
            .map(|cfg| (pair(cfg.base, cfg.quote), MarketBook { cfg, asks: vec![], bids: vec![] }))
            .collect();
        Self { markets, next_seq: 1, salt: random_u64(), made: 0, pending: HashMap::new() }
    }

    /// What of `h` is planned and not yet final or failed.
    pub fn pending_of(&self, h: B256) -> U256 {
        self.pending.get(&h).copied().unwrap_or_default()
    }

    /// `amount` of `h` planned earlier is now final on chain or failed: no longer pending.
    pub fn settled(&mut self, h: B256, amount: U256) {
        if let Some(p) = self.pending.get_mut(&h) {
            *p = p.saturating_sub(amount);
            if p.is_zero() {
                self.pending.remove(&h);
            }
        }
    }

    /// Rebuild from the client's rows: inserted by increasing `seq`, so equal prices keep their time order.
    pub fn load(markets: Vec<MarketCfg>, rows: &[Row]) -> Result<Self> {
        let mut book = Self::new(markets);
        let mut rs = rows.iter().map(Row::resting).collect::<Result<Vec<_>>>()?;
        rs.sort_by_key(|r| r.seq);
        for r in rs {
            book.next_seq = book.next_seq.max(r.seq + 1);
            if book.market_of(r.sell, r.order.receiveToken).is_some() {
                book.insert(r);
            }
        }
        Ok(book)
    }

    pub fn rows(&self) -> Vec<Row> {
        let mut out: Vec<Row> = self.all().map(Row::of).collect();
        out.sort_by_key(|r| r.seq);
        out
    }

    pub fn markets(&self) -> impl Iterator<Item = &MarketCfg> {
        self.markets.values().map(|m| &m.cfg)
    }

    pub fn market_of(&self, sell: Address, receive: Address) -> Option<&MarketCfg> {
        self.markets.get(&pair(sell, receive)).map(|m| &m.cfg)
    }

    pub fn market_by_id(&self, id: i64) -> Option<&MarketCfg> {
        self.markets().find(|m| m.id == id)
    }

    fn all(&self) -> impl Iterator<Item = &Resting> {
        self.markets.values().flat_map(|m| m.asks.iter().chain(m.bids.iter()))
    }

    pub fn len(&self) -> usize {
        self.all().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, h: B256) -> Option<&Resting> {
        self.all().find(|r| r.hash == h)
    }

    pub fn open_of(&self, from: Address) -> Vec<&Resting> {
        let mut v: Vec<&Resting> = self.all().filter(|r| r.order.from == from).collect();
        v.sort_by_key(|r| r.seq);
        v
    }

    /// Σ of `sell` the open orders of `from` can still pull (NODE-DEX-07; the fee is on the received side).
    pub fn committed(&self, from: Address, sell: Address) -> U256 {
        self.all().filter(|r| r.order.from == from && r.sell == sell).map(|r| r.remaining).sum()
    }

    /// Insert by (best price, `seq`). The same hash already there ⇒ add `remaining` (a failed fill handed back).
    fn insert(&mut self, r: Resting) {
        let Some(mb) = self.markets.get_mut(&pair(r.sell, r.order.receiveToken)) else { return };
        let side = mb.side_mut(r.sell);
        if let Some(e) = side.iter_mut().find(|e| e.hash == r.hash) {
            e.remaining = (e.remaining + r.remaining).min(e.order.amount);
            return;
        }
        let at = side
            .iter()
            .position(|e| better(&r.order, &e.order) || (!better(&e.order, &r.order) && r.seq < e.seq))
            .unwrap_or(side.len());
        side.insert(at, r);
    }

    pub fn remove(&mut self, h: B256) -> Option<Resting> {
        for mb in self.markets.values_mut() {
            for side in [&mut mb.asks, &mut mb.bids] {
                if let Some(i) = side.iter().position(|r| r.hash == h) {
                    return Some(side.remove(i));
                }
            }
        }
        None
    }

    /// Hand `fill` back to an order after its settlement failed on chain, keeping its `seq`. Through the matcher, not
    /// straight in: when both sides come back, a straight insert would leave a crossed book. IOC never rests, so it is
    /// never handed back.
    pub fn restore(&mut self, r: Resting, fill: U256) -> Placement {
        if r.order.flags & FLAG_IOC != 0 {
            return Placement { dropped: fill, seq: r.seq, ..Default::default() };
        }
        let current = self.remove(r.hash).map(|x| x.remaining).unwrap_or_default();
        let remaining = (current + fill).min(r.order.amount);
        self.matching(Resting { remaining, ..r })
    }

    /// Drop expired orders; returns their hashes.
    pub fn purge(&mut self, now: u64) -> Vec<B256> {
        let mut gone = vec![];
        for mb in self.markets.values_mut() {
            for side in [&mut mb.asks, &mut mb.bids] {
                side.retain(|r| {
                    let live = r.order.validUntil >= U256::from(now);
                    if !live {
                        gone.push(r.hash);
                    }
                    live
                });
            }
        }
        gone
    }

    /// Drop the orders an `InvalidateNonces(from, batch, min)` closed: `from`'s orders on that lane with `nonce < min`,
    /// selling one of `sells` (the token's own orders, or every outside token for the DEX's lane).
    pub fn drop_below(&mut self, from: Address, batch: U256, min: U256, sells: &dyn Fn(Address) -> bool) -> Vec<Resting> {
        let hs: Vec<B256> = self
            .all()
            .filter(|r| r.order.from == from && r.order.batch == batch && r.order.nonce < min && sells(r.sell))
            .map(|r| r.hash)
            .collect();
        hs.iter().filter_map(|h| self.remove(*h)).collect()
    }

    /// Pure intake checks (NODE-DEX-15, intake section). `remaining` = `amount − pulled` on chain, `fundable` = the
    /// balance (outside token: `min(balance, allowance to the puller)`). The book is unchanged.
    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        &self,
        hash: B256,
        sell: Address,
        o: &TradeOrder,
        remaining: U256,
        fundable: U256,
        relayer: Address,
        dex: Address,
        now: u64,
    ) -> Result<()> {
        let cap = U256::from(1u8) << 128;
        if o.amount.is_zero() || o.receiveAmount.is_zero() || o.amount >= cap || o.receiveAmount >= cap {
            bail!("amounts must be in (0, 2^128)");
        }
        if o.validUntil <= U256::from(now + MIN_TTL_SECS) || o.validUntil > U256::from(now + MAX_TTL_SECS) {
            bail!("validUntil must be within ({MIN_TTL_SECS} s, {MAX_TTL_SECS} s] from now");
        }
        if o.flags & !(FLAG_IOC | FLAG_LISTED_POOLS) != 0 {
            bail!("unknown flags, or ESCROW (Path B is not served by this venue)");
        }
        if o.minFill > o.amount {
            bail!("minFill above amount");
        }
        // NODE-DEX-16: only the DEX this venue runs; home-bound (RS5-9): only this relayer settles a book order.
        if o.dex != dex {
            bail!("DEX_NOT_LISTED: order.dex must be {dex:#x}");
        }
        if o.relayer != relayer {
            bail!("order.relayer must be this relayer {relayer:#x}");
        }
        if o.from == sell || o.dex == sell {
            bail!("an order cannot sell its own signer or the DEX");
        }
        let Some(m) = self.market_of(sell, o.receiveToken) else { bail!("no market for this pair") };
        if sell == o.receiveToken {
            bail!("sell and receive token are the same");
        }
        if o.fee > U256::from(MAX_FEE_PPM) {
            bail!("fee above 1 %");
        }
        // A fee below a role's rate is never selected in that role (NODE-DEX-15): an IOC order only takes; a GTC order
        // rests and makes, and takes when it crosses on arrival.
        let rests = o.flags & FLAG_IOC == 0;
        let (maker_ok, taker_ok) = (o.fee >= U256::from(m.maker_fee_ppm), o.fee >= U256::from(m.taker_fee_ppm));
        let fee_ok = if rests { maker_ok && (taker_ok || !self.would_cross(sell, o)) } else { taker_ok };
        if !fee_ok {
            bail!("FEE_TOO_LOW: the signed fee is below the market's rate for the role this order would play");
        }
        let min = uint(&m.min_base_amount)?;
        let base_amt = if sell == m.base { o.amount } else { o.receiveAmount };
        if base_amt < min {
            bail!("below the market minimum {min}");
        }
        if remaining.is_zero() {
            bail!("order is closed on chain");
        }
        if self.get(hash).is_some() {
            bail!("duplicate order");
        }
        if self.open_of(o.from).len() >= MAX_OPEN_PER_MAKER {
            bail!("too many open orders for this signer");
        }
        if rests && self.len() >= MAX_RESTING {
            bail!("order book full");
        }
        // Committed balance (NODE-DEX-07): every open order of the signer pulls from the same balance.
        let need = self.committed(o.from, sell) + remaining;
        if need > fundable {
            bail!("balance {fundable} below what open orders commit ({need})");
        }
        Ok(())
    }

    /// An order of another signer on the opposite side crosses `o` (it would take on arrival).
    fn would_cross(&self, sell: Address, o: &TradeOrder) -> bool {
        self.markets.get(&pair(sell, o.receiveToken)).is_some_and(|mb| {
            let opposite = if sell == mb.cfg.base { &mb.bids } else { &mb.asks };
            opposite.iter().any(|r| r.order.from != o.from && crosses(&r.order, o))
        })
    }

    /// Match `taker` (hash and on-chain `remaining` known) into the book. Changes the book: resting makers shrink or
    /// leave, a GTC remainder rests. Call it on a COPY to try first.
    pub fn place(&mut self, hash: B256, sell: Address, order: TradeOrder, sig: Bytes, remaining: U256) -> Placement {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.matching(Resting { hash, sell, order, sig, remaining, seq })
    }

    fn matching(&mut self, mut t: Resting) -> Placement {
        let mut out = Placement { seq: t.seq, ..Default::default() };
        let Some(mb) = self.markets.get_mut(&pair(t.sell, t.order.receiveToken)) else {
            out.dropped = t.remaining;
            return out;
        };
        let pending = &self.pending;
        let unmined = |h: B256| pending.get(&h).is_some_and(|p| !p.is_zero());
        let (market_id, maker_ppm, taker_ppm) = (mb.cfg.id, mb.cfg.maker_fee_ppm, mb.cfg.taker_fee_ppm);
        let base = mb.cfg.base;
        let opposite = if t.sell == base { &mut mb.bids } else { &mut mb.asks };
        let mut makers: Vec<(Resting, U256, U256)> = vec![];
        let mut taken = U256::ZERO;
        let can_take = t.order.fee >= U256::from(taker_ppm);
        if can_take {
            for r in opposite.iter() {
                if !crosses(&r.order, &t.order) {
                    break; // sorted by price: only worse from here
                }
                // self-trade (the DEX refuses it) or a signed fee under the maker rate: never this maker
                if r.order.from == t.order.from || r.order.fee < U256::from(maker_ppm) {
                    continue;
                }
                if maker_receives(&r.order, r.remaining).is_zero() || mul(r.remaining, r.order.receiveAmount) < U512::from(r.order.amount) {
                    out.dust.push(r.clone()); // NODE-DEX-05: cannot receive one unit for its whole remainder
                    continue;
                }
                let left = t.remaining - taken;
                let x = r.remaining.min(to256(mul(left, r.order.amount) / U512::from(r.order.receiveAmount)));
                if x.is_zero() {
                    break; // the taker's rest buys less than one unit here
                }
                let y = maker_receives(&r.order, x);
                // the maker's minimum per settlement, unless this fill closes it ON CHAIN (nothing of it still
                // unmined: `amount − pulled` counts only mined fills); a deeper maker may still fit
                if x < min_fill(&r.order) && (x < r.remaining || unmined(r.hash)) {
                    continue;
                }
                if !limits_ok(r, &Resting { remaining: left, ..t.clone() }, x, y) {
                    break; // rounding at tiny amounts: never a leg the contract would refuse
                }
                makers.push((r.clone(), x, y));
                taken += y;
                if x < r.remaining {
                    break; // the taker is used up at this maker's price
                }
            }
        }
        for d in &out.dust {
            if let Some(i) = opposite.iter().position(|r| r.hash == d.hash) {
                opposite.remove(i);
            }
        }
        let settles =
            !makers.is_empty() && (taken >= min_fill(&t.order) || (taken == t.remaining && !unmined(t.hash)));
        if settles {
            for (m, x, _) in &makers {
                *self.pending.entry(m.hash).or_default() += *x;
                if let Some(i) = opposite.iter().position(|r| r.hash == m.hash) {
                    opposite[i].remaining -= *x;
                    if opposite[i].remaining.is_zero() {
                        opposite.remove(i);
                    }
                }
            }
            *self.pending.entry(t.hash).or_default() += taken;
            self.made += 1;
            out.settlement = Some(PlannedSettlement {
                tag: tag(&t, self.salt, self.made),
                market_id,
                taker: t.clone(),
                taker_fill: taken,
                makers,
            });
            t.remaining -= taken;
        }
        if t.remaining.is_zero() {
            return out;
        }
        // A remainder that still crosses could not meet a crossing order's minimum fill: it would sit there locked, so
        // it is cancelled. One that may not take (a fee under the taker rate, only on a hand-back) rests.
        let crossed = can_take && opposite.iter().any(|r| r.order.from != t.order.from && crosses(&r.order, &t.order));
        if t.order.flags & FLAG_IOC != 0 || crossed {
            out.dropped = t.remaining;
            return out;
        }
        out.rested = Some(t.clone());
        self.insert(t);
        out
    }

    /// Aggregated levels `(bids, asks)`, each `(decimal price quote/base, base amount)`.
    pub fn depth(&self, market_id: i64, levels: usize) -> Option<(Vec<Level>, Vec<Level>)> {
        let mb = self.markets.values().find(|m| m.cfg.id == market_id)?;
        let cfg = &mb.cfg;
        let agg = |side: &[Resting], is_ask: bool| -> Vec<Level> {
            let mut out: Vec<Level> = vec![];
            for r in side {
                let (base_amt, quote_amt) = if is_ask {
                    (r.order.amount, r.order.receiveAmount)
                } else {
                    (r.order.receiveAmount, r.order.amount)
                };
                let price = price_str(quote_amt, base_amt, cfg.base_decimals, cfg.quote_decimals);
                let base_rem = if is_ask {
                    r.remaining
                } else {
                    to256(mul(r.remaining, r.order.receiveAmount) / U512::from(r.order.amount))
                };
                if let Some(l) = out.last_mut().filter(|l| l.price == price) {
                    l.base_amount += base_rem;
                    l.orders += 1;
                } else if out.len() == levels {
                    break;
                } else {
                    out.push(Level { price, base_amount: base_rem, orders: 1 });
                }
            }
            out
        };
        Some((agg(&mb.bids, false), agg(&mb.asks, true)))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Level {
    pub price: String,
    pub base_amount: U256,
    pub orders: u32,
}

/// `quote/base` in display units, 18 decimals (review D16): never a raw integer division.
pub fn price_str(quote: U256, base: U256, base_dec: u8, quote_dec: u8) -> String {
    if base.is_zero() {
        return "0".into();
    }
    let ten = U512::from(10u8);
    let num = U512::from(quote) * ten.pow(U512::from(18u32 + u32::from(base_dec)));
    let den = U512::from(base) * ten.pow(U512::from(quote_dec));
    let v = (num / den).to_string();
    let v = format!("{v:0>19}");
    let (int, frac) = v.split_at(v.len() - 18);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() { int.to_string() } else { format!("{int}.{frac}") }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::sol_types::{SolCall, SolValue};
    use std::str::FromStr;

    const BASE: Address = Address::repeat_byte(0xaa);
    const QUOTE: Address = Address::repeat_byte(0xbb);
    const RELAYER: Address = Address::repeat_byte(0xee);
    const DEX: Address = Address::repeat_byte(0xd0);
    const NOW: u64 = 1_800_000_000;

    fn market() -> MarketCfg {
        MarketCfg { id: 1, base: BASE, quote: QUOTE, base_decimals: 18, quote_decimals: 6, maker_fee_ppm: 0,
                    taker_fee_ppm: 0, min_base_amount: "0".into() }
    }

    fn o(from: u8, receive: Address, amount: u64, receive_amount: u64, nonce: u64) -> TradeOrder {
        TradeOrder {
            from: Address::repeat_byte(from),
            receiveToken: receive,
            amount: U256::from(amount),
            receiveAmount: U256::from(receive_amount),
            minFill: U256::ZERO,
            fee: U256::ZERO,
            relayer: RELAYER,
            dex: DEX,
            destination: Address::ZERO,
            flags: 0,
            batch: U256::from(1),
            nonce: U256::from(nonce),
            validUntil: U256::from(NOW + 300),
        }
    }

    fn hash_of(o: &TradeOrder) -> B256 {
        keccak256(format!("{o:?}"))
    }

    fn sell_of(o: &TradeOrder) -> Address {
        if o.receiveToken == QUOTE { BASE } else { QUOTE }
    }

    fn put(book: &mut Book, o: TradeOrder) -> Placement {
        let rem = o.amount;
        book.place(hash_of(&o), sell_of(&o), o, Bytes::new(), rem)
    }

    /// Sells `base` base for at least `quote` quote.
    fn ask(from: u8, base: u64, quote: u64, nonce: u64) -> TradeOrder {
        o(from, QUOTE, base, quote, nonce)
    }

    /// Sells `quote` quote for at least `base` base.
    fn bid(from: u8, quote: u64, base: u64, nonce: u64) -> TradeOrder {
        o(from, BASE, quote, base, nonce)
    }

    fn makers(p: &Placement) -> Vec<(Address, U256, U256)> {
        p.settlement.as_ref().map_or(vec![], |s| s.makers.iter().map(|(m, x, y)| (m.order.from, *x, *y)).collect())
    }

    fn word(k: &serde_json::Value, f: &str) -> String {
        k[f].as_str().unwrap().to_string()
    }

    /// Byte-identical with forge (`DexKat.t.sol`, `TradeKat.t.sol`): the `DexOrder` hash in the DEX's salted domain,
    /// the SCaaS taker's `TradeOrder` hash in its token's domain, the DEX cancel and invalidate digests, and the
    /// `mtxSettle` / `mtxCancelOrders` / `mtxInvalidateNonces` calldata the venue sends.
    #[test]
    fn kat_hashes_and_calldata_match_forge() {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm/test/vectors/dex_order_kat.json");
        let k: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let a = |f: &str| Address::from_str(&word(&k, f)).unwrap();
        let uid = B256::from_str(&word(&k, "salt")).unwrap();
        let maker = TradeOrder::abi_decode(&hex_bytes(&word(&k, "maker_order_abi")).unwrap()).unwrap();
        let taker = TradeOrder::abi_decode(&hex_bytes(&word(&k, "taker_order_abi")).unwrap()).unwrap();
        let dd = domain("SCaaS Dex", 7622, a("dex"), uid);
        let hm = dex_order_hash(&dd, a("outside_token"), &maker);
        assert_eq!(format!("{hm:#x}"), word(&k, "dex_order_hash"));
        let td = domain("SCaaS MetaToken", 7622, a("token"), uid);
        assert_eq!(format!("{:#x}", trade_order_hash(&td, &taker)), word(&k, "taker_order_hash"));
        assert_eq!(format!("{:#x}", cancel_digest(&dd, hm)), word(&k, "cancel_digest"));
        assert_eq!(format!("{:#x}", invalidate_digest(&dd, maker.from, U256::from(1), U256::from(5))),
            word(&k, "invalidate_digest"));
        // the calldata: decode forge's, re-encode it here, byte for byte
        let settle = hex_bytes(&word(&k, "settle_calldata")).unwrap();
        let c = ISCaaSDex::mtxSettleCall::abi_decode(&settle).unwrap();
        assert_eq!((c.s[0].makers[0].shape, c.s[0].taker.shape), (0, 0));
        assert_eq!(TradeOrder::abi_decode(&c.s[0].makers[0].order).unwrap(), maker);
        assert_eq!(TradeOrder::abi_decode(&c.s[0].taker.order).unwrap(), taker);
        assert_eq!(ISCaaSDex::mtxSettleCall { s: c.s.clone() }.abi_encode(), settle.to_vec());
        let cancel = hex_bytes(&word(&k, "cancel_orders_calldata")).unwrap();
        let c = ISCaaSDex::mtxCancelOrdersCall::abi_decode(&cancel).unwrap();
        assert_eq!((c.orders[0].sellToken, &c.orders[0].order), (a("outside_token"), &maker));
        assert_eq!(ISCaaSDex::mtxCancelOrdersCall { orders: c.orders, sigs: c.sigs }.abi_encode(), cancel.to_vec());
        let inv = hex_bytes(&word(&k, "invalidate_calldata")).unwrap();
        let c = ISCaaSDex::mtxInvalidateNoncesCall::abi_decode(&inv).unwrap();
        assert_eq!((c.from, c.batch, c.newMin), (maker.from, U256::from(1), U256::from(5)));
        // the token-side order hash and cancel of trade_kat.json
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm/test/vectors/trade_kat.json");
        let k: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let o = TradeOrder::abi_decode(&hex_bytes(&word(&k, "order_abi")).unwrap()).unwrap();
        let td = domain("SCaaS MetaToken", 7622, Address::from_str(&word(&k, "verifying_contract")).unwrap(),
            B256::from_str(&word(&k, "salt")).unwrap());
        let h = trade_order_hash(&td, &o);
        assert_eq!(format!("{h:#x}"), word(&k, "order_hash"));
        assert_eq!(format!("{:#x}", cancel_digest(&td, h)), word(&k, "cancel_digest"));
        assert_eq!(format!("{:#x}", invalidate_digest(&td, o.from, U256::from(7), U256::from(43))), word(&k, "invalidate_digest"));
    }

    #[test]
    fn wire_round_trips_and_rejects_garbage() {
        let x = ask(1, 100, 200, 1);
        assert_eq!(WireOrder::from_sol(&x).to_sol().unwrap(), x);
        let mut w = WireOrder::from_sol(&x);
        w.amount = "01".into();
        assert!(w.to_sol().is_err());
        let mut v = serde_json::to_value(WireOrder::from_sol(&x)).unwrap();
        v["maker"] = serde_json::json!("0x00");
        assert!(serde_json::from_value::<WireOrder>(v).is_err(), "the built DEX's fields are refused");
    }

    #[test]
    fn price_time_priority_best_price_then_earliest() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 10, 30, 1)); // 3.0
        put(&mut b, ask(2, 10, 20, 1)); // 2.0 best
        put(&mut b, ask(3, 10, 20, 2)); // 2.0, later
        let p = put(&mut b, bid(9, 60, 30, 1)); // buys up to 30 base at <= 2.0 → fills 2 and 3 only
        let who: Vec<Address> = makers(&p).iter().map(|m| m.0).collect();
        assert_eq!(who, vec![Address::repeat_byte(2), Address::repeat_byte(3)], "one settlement, two makers");
        assert!(settlement_ok(p.settlement.as_ref().unwrap()));
        assert_eq!(p.settlement.as_ref().unwrap().taker_fill, U256::from(40));
        // 20 quote left, still crossing nothing at <= 2.0: rests
        assert_eq!(p.rested.expect("bid remainder rests").remaining, U256::from(20));
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn a_partial_fill_runs_at_the_makers_price_and_keeps_the_maker_resting() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 100, 200, 1));
        let p = put(&mut b, bid(2, 120, 48, 1)); // pays up to 2.5; 120 quote buys 60 base at 2.0
        assert_eq!(makers(&p), vec![(Address::repeat_byte(1), U256::from(60), U256::from(120))]);
        assert!(settlement_ok(p.settlement.as_ref().unwrap()));
        assert_eq!(b.open_of(Address::repeat_byte(1))[0].remaining, U256::from(40));
        assert!(p.rested.is_none());
    }

    /// NODE-DEX-15: every order fills at least `max(minFill, ceil(amount / 2))` per settlement unless it closes.
    #[test]
    fn the_minimum_fill_binds_makers_and_takers() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 100, 200, 1)); // min 50 base
        // a bid that can take only 20 base cannot partially fill a 100 ask: no settlement, and its remainder would
        // rest crossed, so it is cancelled
        let p = put(&mut b, bid(2, 40, 20, 1));
        assert!(p.settlement.is_none());
        assert_eq!((p.dropped, p.rested.is_none()), (U256::from(40), true));
        assert_eq!(b.open_of(Address::repeat_byte(1))[0].remaining, U256::from(100));
        // a taker whose crossing makers give less than its own minimum: nothing settles, it rests (GTC)
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 10, 20, 1));
        let p = put(&mut b, bid(3, 200, 100, 1)); // min 100 quote; the ask fills only 20 quote
        assert!(p.settlement.is_none());
        assert!(p.dropped == U256::from(200), "crossing remainder never rests");
        // the same taker with a deeper maker: one settlement of two makers reaches its minimum
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 10, 20, 1));
        put(&mut b, ask(4, 50, 100, 1));
        let p = put(&mut b, bid(3, 200, 100, 1));
        assert_eq!(makers(&p).len(), 2);
        assert_eq!(p.settlement.as_ref().unwrap().taker_fill, U256::from(120));
        assert!(settlement_ok(p.settlement.as_ref().unwrap()));
    }

    #[test]
    fn a_maker_too_large_for_the_taker_is_skipped_for_a_deeper_one() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 100, 200, 1)); // best price, min 50
        put(&mut b, ask(2, 10, 21, 1));   // worse price, closes whole
        let p = put(&mut b, bid(3, 25, 10, 1)); // pays up to 2.5, buys ~10 base
        assert_eq!(makers(&p), vec![(Address::repeat_byte(2), U256::from(10), U256::from(21))]);
        assert!(settlement_ok(p.settlement.as_ref().unwrap()));
    }

    #[test]
    fn non_crossing_orders_rest_on_both_sides() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 10, 30, 1));
        let p = put(&mut b, bid(2, 20, 10, 1));
        assert!(p.settlement.is_none());
        let (bids, asks) = b.depth(1, 10).unwrap();
        assert_eq!((bids.len(), asks.len()), (1, 1));
    }

    #[test]
    fn ioc_remainder_is_dropped_not_rested() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 30, 60, 1));
        let mut x = bid(2, 100, 50, 1);
        x.flags = FLAG_IOC;
        let p = put(&mut b, x);
        assert_eq!(makers(&p).len(), 1);
        assert_eq!(p.dropped, U256::from(40));
        assert!(p.rested.is_none());
        assert!(b.is_empty());
    }

    #[test]
    fn fill_or_kill_aggregates_makers_or_settles_nothing() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 10, 20, 1));
        put(&mut b, ask(3, 20, 40, 1));
        let mut x = bid(2, 60, 30, 1);
        x.minFill = x.amount; // FOK
        let p = put(&mut b, x);
        assert_eq!(makers(&p).len(), 2, "one atomic settlement may aggregate makers");
        assert_eq!(p.settlement.as_ref().unwrap().taker_fill, U256::from(60));
        let mut y = bid(4, 1_000, 500, 1);
        y.minFill = y.amount;
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 10, 20, 1));
        let p = put(&mut b, y);
        assert!(p.settlement.is_none());
        assert_eq!(p.dropped, U256::from(1_000), "a FOK remainder that crosses never rests");
    }

    #[test]
    fn self_trade_and_cheap_makers_are_skipped() {
        let mut m = market();
        m.maker_fee_ppm = 1_000;
        let mut b = Book::new(vec![m]);
        let mut cheap = ask(5, 10, 20, 1);
        cheap.fee = U256::from(999);
        let mut own = ask(1, 10, 20, 1);
        own.fee = U256::from(1_000);
        let mut fair = ask(2, 10, 20, 1);
        fair.fee = U256::from(1_000);
        b.insert(Resting { hash: hash_of(&cheap), sell: BASE, order: cheap, sig: Bytes::new(), remaining: U256::from(10), seq: 1 });
        put(&mut b, own);
        put(&mut b, fair);
        let p = put(&mut b, bid(1, 20, 10, 2));
        assert_eq!(makers(&p), vec![(Address::repeat_byte(2), U256::from(10), U256::from(20))]);
    }

    #[test]
    fn dust_makers_leave_the_book() {
        let mut b = Book::new(vec![market()]);
        // 1 base left of an order pricing 1 base at 1/3 quote: it can never receive one unit
        let dust = ask(1, 3, 1, 1);
        b.insert(Resting { hash: hash_of(&dust), sell: BASE, order: dust, sig: Bytes::new(), remaining: U256::from(1), seq: 1 });
        put(&mut b, ask(2, 10, 20, 1));
        let p = put(&mut b, bid(3, 20, 10, 1));
        assert_eq!(p.dust.len(), 1);
        assert_eq!(makers(&p), vec![(Address::repeat_byte(2), U256::from(10), U256::from(20))]);
        assert!(b.is_empty());
    }

    #[test]
    fn limits_and_the_settlement_mirror_the_contract_including_rounding() {
        // maker 3 base for 10 quote (3.33); the taker sells 10 quote for 3 base (same price)
        let m = Resting { hash: B256::ZERO, sell: BASE, order: ask(1, 3, 10, 1), sig: Bytes::new(), remaining: U256::from(3), seq: 1 };
        let t = Resting { hash: B256::repeat_byte(1), sell: QUOTE, order: bid(2, 10, 3, 1), sig: Bytes::new(), remaining: U256::from(10), seq: 2 };
        assert!(limits_ok(&m, &t, U256::from(3), U256::from(10)));
        // 1 base costs ceil(10/3) = 4 quote: 4/1 > 10/3 breaks the taker's limit
        assert!(!limits_ok(&m, &t, U256::from(1), U256::from(4)));
        assert!(!limits_ok(&m, &t, U256::from(4), U256::from(14)), "overfill");
        assert!(!limits_ok(&m, &t, U256::from(3), U256::from(9)), "y is the maker's ceiling receive, not less");
        // a taker that would pay more than the maker's ceiling: within both price limits, yet the DEX computes the
        // maker's receive itself (FillMismatch), so the leg is refused here too
        let rich = Resting { order: bid(2, 12, 3, 1), remaining: U256::from(12), ..t.clone() };
        assert!(limits_ok(&m, &rich, U256::from(3), U256::from(10)));
        assert!(!limits_ok(&m, &rich, U256::from(3), U256::from(11)));
        let s = |makers: Vec<(Resting, U256, U256)>, fill: u64| PlannedSettlement {
            tag: B256::ZERO, market_id: 1, taker: t.clone(), taker_fill: U256::from(fill), makers };
        assert!(settlement_ok(&s(vec![(m.clone(), U256::from(3), U256::from(10))], 10)));
        assert!(!settlement_ok(&s(vec![(m.clone(), U256::from(3), U256::from(10))], 9)), "FillMismatch");
        assert!(!settlement_ok(&s(vec![], 0)), "NoMakers");
        // DuplicateOrder: each leg alone is within every limit (2 ≥ ceil(4/2), receive ceil(2·8/4) = 4, both prices
        // hold, Σ = the taker's whole remainder); only the repeated hash refuses it
        let dm = Resting { order: ask(1, 4, 8, 1), remaining: U256::from(4), ..m.clone() };
        let dt = Resting { order: bid(2, 8, 4, 1), remaining: U256::from(8), ..t.clone() };
        let ds = |makers: Vec<(Resting, U256, U256)>| PlannedSettlement {
            tag: B256::ZERO, market_id: 1, taker: dt.clone(), taker_fill: U256::from(8), makers };
        let leg = (dm.clone(), U256::from(2), U256::from(4));
        let other = (Resting { hash: B256::repeat_byte(9), ..dm.clone() }, U256::from(2), U256::from(4));
        assert!(settlement_ok(&ds(vec![leg.clone(), other])), "two distinct makers settle");
        assert!(!settlement_ok(&ds(vec![leg.clone(), leg.clone()])), "DuplicateOrder");
        let wrong_token = (Resting { hash: B256::repeat_byte(9), sell: QUOTE, ..dm.clone() }, U256::from(2), U256::from(4));
        assert!(!settlement_ok(&ds(vec![leg.clone(), wrong_token])), "TokenMismatch");
        // the taker's minimum: 4 of 8 quote is ceil(8/2); one leg of a taker whose minFill is 8 is below it
        let fok = PlannedSettlement { taker: Resting { order: TradeOrder { minFill: U256::from(8), ..dt.order.clone() }, ..dt.clone() },
            taker_fill: U256::from(4), ..ds(vec![leg.clone()]) };
        assert!(settlement_ok(&PlannedSettlement { taker_fill: U256::from(4), ..ds(vec![leg.clone()]) }));
        assert!(!settlement_ok(&fok), "below the taker's minimum");
        // the maker's receive is the CEILING (a floor would silently stop matching non-multiples)
        assert_eq!(maker_receives(&m.order, U256::from(1)), U256::from(4), "ceil(1 · 10 / 3)");
        assert_eq!(maker_receives(&m.order, U256::from(3)), U256::from(10));
        // the 50 % floor rounds up for odd amounts (`amount − amount/2`, as `TradeLib.record`)
        assert_eq!(min_fill(&ask(1, 101, 202, 1)), U256::from(51));
        assert_eq!(min_fill(&TradeOrder { minFill: U256::from(70), ..ask(1, 101, 202, 1) }), U256::from(70));
        let mut me = m.clone();
        me.order.from = t.order.from;
        assert!(!settlement_ok(&s(vec![(me, U256::from(3), U256::from(10))], 10)), "SelfTrade");
        let mut big = m.clone();
        big.order = ask(1, 30, 100, 1);
        big.remaining = U256::from(30);
        assert!(!settlement_ok(&s(vec![(big, U256::from(3), U256::from(10))], 10)), "maker below its minimum");
    }

    #[test]
    fn rows_round_trip_rebuilds_the_same_book() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 10, 30, 1));
        put(&mut b, ask(2, 10, 20, 1));
        put(&mut b, ask(3, 10, 20, 2));
        put(&mut b, bid(4, 10, 10, 1));
        put(&mut b, bid(5, 40, 20, 1)); // fills asks 2 and 3
        let rows = b.rows();
        let json = serde_json::to_string(&rows).unwrap();
        let back: Vec<Row> = serde_json::from_str(&json).unwrap();
        let mut c = Book::load(vec![market()], &back).unwrap();
        assert_eq!(c.rows(), rows);
        assert_eq!(c.depth(1, 10), b.depth(1, 10));
        let strip = |p: Placement| makers(&p);
        let pb = put(&mut b, bid(6, 30, 10, 1));
        let pc = put(&mut c, bid(6, 30, 10, 1));
        assert_eq!(strip(pb), strip(pc));
    }

    #[test]
    fn restore_returns_a_failed_fill_and_never_revives_ioc() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 10, 20, 1));
        let p = put(&mut b, bid(2, 20, 10, 1));
        assert!(b.is_empty());
        let s = p.settlement.unwrap();
        let (m, x, _) = s.makers[0].clone();
        assert!(b.restore(m.clone(), x).settlement.is_none());
        assert_eq!(b.open_of(Address::repeat_byte(1))[0].remaining, U256::from(10));
        assert_eq!(b.open_of(Address::repeat_byte(1))[0].seq, m.seq, "time priority kept");
        let mut ioc = s.taker.clone();
        ioc.order.flags = FLAG_IOC;
        let p = b.restore(ioc, s.taker_fill);
        assert!(p.settlement.is_none(), "an IOC hand-back never takes the resting maker again");
        assert_eq!(p.dropped, s.taker_fill);
        assert!(b.open_of(Address::repeat_byte(2)).is_empty());
        assert_eq!(b.open_of(Address::repeat_byte(1))[0].remaining, U256::from(10), "the maker still rests whole");
    }

    #[test]
    fn restoring_both_sides_rematches_instead_of_leaving_a_crossed_book() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 10, 20, 1));
        let s = put(&mut b, bid(2, 20, 10, 1)).settlement.unwrap();
        let (m, x, _) = s.makers[0].clone();
        assert!(b.restore(m, x).settlement.is_none());
        let again = b.restore(s.taker.clone(), s.taker_fill).settlement.expect("the two healthy sides trade again");
        assert_eq!((again.taker_fill, again.makers[0].1), (s.taker_fill, s.makers[0].1));
        assert_ne!(again.tag, s.tag, "a re-match is a new trade, not a replay");
        assert!(b.is_empty());
    }

    #[test]
    fn admit_enforces_the_intake_rules() {
        let mut b = Book::new(vec![market()]);
        let good = ask(1, 100, 200, 1);
        let ok = |b: &Book, x: &TradeOrder, fundable: u64| {
            b.admit(hash_of(x), sell_of(x), x, x.amount, U256::from(fundable), RELAYER, DEX, NOW)
        };
        ok(&b, &good, 100).unwrap();
        // committed balance: the same 100 cannot back two orders (review D6)
        put(&mut b, good.clone());
        assert!(ok(&b, &ask(1, 100, 200, 2), 150).is_err());
        ok(&b, &ask(1, 50, 100, 2), 150).unwrap();
        let bad = |f: &dyn Fn(&mut TradeOrder)| {
            let mut x = ask(1, 1, 2, 3);
            f(&mut x);
            ok(&b, &x, 1_000).is_err()
        };
        assert!(bad(&|x| x.relayer = Address::ZERO), "RS5-9: home-bound");
        assert!(bad(&|x| x.dex = Address::repeat_byte(0xd1)), "NODE-DEX-16");
        assert!(bad(&|x| x.validUntil = U256::from(NOW + 2)), "too short");
        assert!(bad(&|x| x.validUntil = U256::from(NOW + MAX_TTL_SECS + 1)), "too long");
        assert!(bad(&|x| x.amount = U256::from(1u8) << 128), "2^128");
        assert!(bad(&|x| x.flags = FLAG_ESCROW | FLAG_IOC), "Path B not served");
        assert!(bad(&|x| x.flags = 8), "unknown flag");
        assert!(bad(&|x| x.minFill = U256::from(2)), "minFill above amount");
        assert!(bad(&|x| x.fee = U256::from(10_001)), "fee above 1 %");
        assert!(bad(&|x| x.receiveToken = Address::repeat_byte(0xcc)), "no market");
        assert!(!bad(&|x| x.flags = FLAG_LISTED_POOLS), "LISTED_POOLS is fine on the book");
        assert!(ok(&b, &good, 1_000).is_err(), "duplicate");
        for n in 10..(10 + MAX_OPEN_PER_MAKER as u64) {
            put(&mut b, ask(7, 1, 2, n));
        }
        assert!(ok(&b, &ask(7, 1, 2, 999), 1_000).is_err(), "per-signer cap");
        // minimum size on the base side, both directions (review D22)
        let mut m = market();
        m.min_base_amount = "10".into();
        let b2 = Book::new(vec![m]);
        assert!(b2.admit(B256::ZERO, BASE, &ask(1, 5, 10, 1), U256::from(5), U256::from(99), RELAYER, DEX, NOW).is_err());
        assert!(b2.admit(B256::ZERO, QUOTE, &bid(1, 50, 5, 1), U256::from(50), U256::from(99), RELAYER, DEX, NOW).is_err());
        b2.admit(B256::ZERO, QUOTE, &bid(1, 50, 10, 1), U256::from(50), U256::from(99), RELAYER, DEX, NOW).unwrap();
        assert!(b2.admit(B256::ZERO, QUOTE, &bid(1, 50, 10, 1), U256::ZERO, U256::from(99), RELAYER, DEX, NOW).is_err(), "closed");
    }

    #[test]
    fn fee_rates_by_role_at_intake() {
        let mut m = market();
        (m.maker_fee_ppm, m.taker_fee_ppm) = (1_000, 2_000);
        let mut b = Book::new(vec![m]);
        let ok = |b: &Book, x: &TradeOrder| b.admit(hash_of(x), sell_of(x), x, x.amount, U256::from(1_000), RELAYER, DEX, NOW);
        let with = |fee: u64, flags: u8| {
            let mut x = ask(1, 100, 200, 1);
            (x.fee, x.flags) = (U256::from(fee), flags);
            x
        };
        assert!(ok(&b, &with(999, 0)).is_err(), "a GTC order below the maker rate never fills");
        ok(&b, &with(1_000, 0)).unwrap();
        assert!(ok(&b, &with(1_999, FLAG_IOC)).is_err(), "IOC only takes");
        ok(&b, &with(2_000, FLAG_IOC)).unwrap();
        let mut cross = bid(9, 200, 100, 1);
        cross.fee = U256::from(2_000);
        put(&mut b, cross);
        assert!(ok(&b, &with(1_000, 0)).is_err(), "a GTC order that takes on arrival pays the taker rate");
        ok(&b, &with(2_000, 0)).unwrap();
    }

    /// A handed-back order that may not take (fee under the taker rate) rests even when crossing; makers first
    /// restores the original roles (the venue's sync order).
    #[test]
    fn a_hand_back_below_the_taker_rate_rests() {
        let mut m = market();
        (m.maker_fee_ppm, m.taker_fee_ppm) = (1_000, 2_000);
        let mut b = Book::new(vec![m]);
        let mut x = ask(1, 10, 20, 1);
        x.fee = U256::from(1_000);
        let mut y = bid(2, 20, 10, 1);
        y.fee = U256::from(2_000);
        let mk = |o: &TradeOrder| Resting { hash: hash_of(o), sell: sell_of(o), order: o.clone(), sig: Bytes::new(), remaining: o.amount, seq: 1 };
        assert!(b.restore(mk(&y), y.amount).rested.is_some());
        let p = b.restore(mk(&x), x.amount);
        assert!(p.settlement.is_none() && p.rested.is_some(), "the cheap ask may not take: it rests crossed");
        let mut c = Book::new(vec![b.markets().next().unwrap().clone()]);
        assert!(c.restore(mk(&x), x.amount).rested.is_some());
        assert!(c.restore(mk(&y), y.amount).settlement.is_some(), "makers first: the bid takes again");
    }

    #[test]
    fn purge_and_drop_below() {
        let mut b = Book::new(vec![market()]);
        let mut x = ask(1, 10, 20, 1);
        x.validUntil = U256::from(NOW + 10);
        put(&mut b, x);
        put(&mut b, ask(2, 10, 20, 5));
        put(&mut b, ask(2, 10, 20, 9));
        let mut other_lane = ask(2, 10, 20, 2);
        other_lane.batch = U256::from(2);
        put(&mut b, other_lane);
        assert_eq!(b.purge(NOW + 11).len(), 1);
        let all = |_: Address| true;
        assert_eq!(b.drop_below(Address::repeat_byte(2), U256::from(1), U256::from(6), &all).len(), 1, "lane 1 only");
        assert!(b.drop_below(Address::repeat_byte(2), U256::from(1), U256::from(9), &all).is_empty(),
            "nonce == minNonce is still valid");
        assert_eq!(b.drop_below(Address::repeat_byte(2), U256::from(1), U256::from(99), &|s| s == QUOTE).len(), 0,
            "another sell token's lane");
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn price_is_scaled_by_decimals() {
        // 2 000 quote (6 dec) for 1 base (18 dec)
        assert_eq!(price_str(U256::from(2_000_000_000u64), U256::from(10u64).pow(U256::from(18)), 18, 6), "2000");
        assert_eq!(price_str(U256::from(1u8), U256::from(3u8), 0, 0), "0.333333333333333333");
    }

    #[test]
    fn a_planned_settlement_encodes_as_the_dex_reads_it() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 10, 20, 1));
        let s = put(&mut b, bid(2, 20, 10, 1)).settlement.unwrap();
        let st = s.to_settlement();
        assert_eq!((st.r#ref, st.taker.sellToken, st.taker.fill), (s.tag, QUOTE, U256::from(20)));
        assert_eq!((st.makers[0].sellToken, st.makers[0].fill), (BASE, U256::from(10)));
        assert_eq!((st.taker.shape, st.makers[0].shape), (0, 0), "shape 0: abi.encode(TradeOrder)");
        assert_eq!(st.taker.order.len(), 13 * 32);
        assert_eq!(TradeOrder::abi_decode(&st.makers[0].order).unwrap(), s.makers[0].0.order);
        assert_eq!(&ISCaaSDex::mtxSettleCall { s: vec![st] }.abi_encode()[..4], &[0x04, 0x03, 0xb1, 0x3c]);
    }

    /// Review T3 I1 (the reviewer's PoC `poc_second_fill_of_an_unmined_remainder`): a remainder whose first settlement
    /// is not mined yet does not close on chain (`amount − pulled` counts mined fills only), so it is never planned as
    /// closing until that fill is final or failed — for a maker and for a re-placed taker.
    #[test]
    fn poc_second_fill_of_an_unmined_remainder() {
        let mut b = Book::new(vec![market()]);
        let a = ask(1, 100, 200, 1); // min 50 base
        let ah = hash_of(&a);
        put(&mut b, a.clone());
        let p1 = put(&mut b, bid(2, 120, 60, 1));
        assert_eq!(makers(&p1)[0].1, U256::from(60));
        assert_eq!(b.pending_of(ah), U256::from(60));
        assert_eq!(b.pending_of(hash_of(&bid(2, 120, 60, 1))), U256::from(120), "the taker's fill is pending too");
        let p2 = put(&mut b, bid(3, 80, 40, 1));
        assert!(p2.settlement.is_none(), "40 != 100 − 0 and 40 < 50 on chain: BelowMinFill, so never planned");
        assert_eq!(b.get(ah).unwrap().remaining, U256::from(40), "the honest maker stays");
        b.settled(ah, U256::from(60)); // the watcher's LegSettled
        let s3 = put(&mut b, bid(4, 80, 40, 1)).settlement.expect("the remainder now closes on chain");
        assert_eq!(s3.makers[0].1, a.amount - U256::from(60));
        assert!(settlement_ok(&s3));
        assert_eq!(b.pending_of(ah), U256::from(40));
        b.settled(ah, U256::from(40));
        assert_eq!(b.pending_of(ah), U256::ZERO);
        // a taker: the order re-placed with its remainder while its first fill is unmined
        let mut b = Book::new(vec![market()]);
        put(&mut b, a.clone());
        put(&mut b, bid(2, 120, 60, 1));
        let rest = b.remove(ah).unwrap();
        put(&mut b, bid(5, 80, 40, 1));
        assert!(b.place(ah, BASE, a.clone(), Bytes::new(), rest.remaining).settlement.is_none());
        b.settled(ah, U256::from(60));
        assert!(b.place(ah, BASE, a, Bytes::new(), rest.remaining).settlement.is_some());
    }
}
