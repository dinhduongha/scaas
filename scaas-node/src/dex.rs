//! DEX sổ lệnh (R35, `2026-10-03-dex-design.md` §3): kiểu lệnh EIP-712 của `SCaaSDexV1`, sổ theo
//! thị trường với ưu tiên giá-thời gian, khớp một phần / IOC / FOK, chặn spam. Phần này THUẦN (không
//! I/O, test được từng bit); RPC, Odoo, gateway nằm ở `dex::venue`.
pub mod venue;

use std::collections::HashMap;

use alloy::primitives::{keccak256, Address, Bytes, B256, U256, U512};
use alloy::sol;
use alloy::sol_types::{Eip712Domain, SolStruct};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

use crate::metatx::{addr, uint};

sol! {
    /// Phải khớp TỪNG KÝ TỰ với `SCaaSDexV1.ORDER_TYPEHASH` (khoá bằng `dex_kat.json`).
    #[derive(Debug, PartialEq, Eq)]
    struct Order {
        address maker; address taker; address sellToken; address buyToken;
        uint256 sellAmount; uint256 buyAmount; uint256 nonce; uint256 expiry;
        uint32 maxFeePpm; uint8 flags; address relayer; uint8 feeMode; uint256 fee;
        address feeToken; address feeRecipient;
    }

    struct CancelOrder { bytes32 orderHash; }
    struct InvalidateNonces { address maker; uint256 minNonce; }

    #[derive(Debug)]
    struct Match {
        bytes32 tag; Order maker; bytes makerSig; Order taker; bytes takerSig;
        uint256 makerFill; uint256 takerFill;
    }

    #[derive(Debug)]
    struct CancelReq { Order order; bytes sig; }

    #[derive(Debug)]
    struct Market { bool listed; bool feeOn; uint32 makerFeePpm; uint32 takerFeePpm; address feeRecipient; }

    #[derive(Debug)]
    struct Fill {
        address sellToken; uint256 sold; address buyToken; uint256 received; uint256 dexFee;
        address dexFeeRecipient; address relayerFeeToken; uint256 relayerFee; address relayerFeeRecipient;
        uint256 filledTotal;
    }

    #[derive(Debug)]
    interface ISCaaSDex {
        function settle(Match[] ms) external returns (bool[] ok);
        function cancel(CancelReq[] reqs) external;
        function invalidateNonces(address maker, uint256 newMin, bytes sig) external;
        function checkOrder(Order o, bytes sig) external view
            returns (bytes32 h, uint8 status, uint256 remaining, uint256 fundable, uint256 feeFundable);
        function markets(bytes32 key) external view
            returns (bool listed, bool feeOn, uint32 makerFeePpm, uint32 takerFeePpm, address feeRecipient);
        function marketKey(address a, address b) external pure returns (bytes32);
        function minNonce(address maker) external view returns (uint256);
        event OrderFilled(bytes32 indexed tag, bytes32 indexed orderHash, address indexed owner, Fill fill);
        event Matched(bytes32 indexed tag, bytes32 indexed makerHash, bytes32 indexed takerHash);
        event MatchFailed(bytes32 indexed tag, bytes reason);
        event OrderCancelled(bytes32 indexed orderHash, address indexed maker);
        event NoncesInvalidated(address indexed maker, uint256 minNonce);
        error NothingSettled();
        error Overfill(bytes32 orderHash, uint256 filledBefore, uint256 fill, uint256 sellAmount);
        error PriceLimit(bytes32 orderHash);
        error BadSignature(bytes32 orderHash);
        error OrderExpired(bytes32 orderHash);
        error NonceInvalidated(bytes32 orderHash);
        error FillOrKill(bytes32 orderHash);
        error FeeAboveSigned(bytes32 orderHash);
        error NonceNotIncreasing();
        error MarketNotListed();
    }
}

pub const FLAG_FOK: u8 = 1;
pub const FLAG_IOC: u8 = 2;
/// `checkOrder` status `ST_OK`.
pub const ST_OK: u8 = 0;
/// Trần lệnh nghỉ toàn sổ — lệnh hợp lệ gần như miễn phí với người đặt (gasless).
pub const MAX_RESTING: usize = 10_000;
pub const MAX_OPEN_PER_MAKER: usize = 50;
pub const MIN_TTL_SECS: u64 = 5;
pub const MAX_TTL_SECS: u64 = 30 * 86_400;
const PPM: u64 = 1_000_000;
const MAX_FEE_PPM: u64 = 10_000;

pub fn domain(chain_id: u64, dex: Address) -> Eip712Domain {
    Eip712Domain::new(
        Some("SCaaS Dex".into()),
        Some("1".into()),
        Some(U256::from(chain_id)),
        Some(dex),
        None,
    )
}

pub fn order_hash(d: &Eip712Domain, o: &Order) -> B256 {
    o.eip712_signing_hash(d)
}

pub fn cancel_digest(d: &Eip712Domain, h: B256) -> B256 {
    CancelOrder { orderHash: h }.eip712_signing_hash(d)
}

pub fn invalidate_digest(d: &Eip712Domain, maker: Address, min: U256) -> B256 {
    InvalidateNonces { maker, minNonce: min }.eip712_signing_hash(d)
}

// ---------------------------------------------------------------------------------- wire

/// Định dạng dây (chuỗi thập phân, như `WireMetaTx`): gateway nhận, Odoo lưu.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WireOrder {
    pub maker: String,
    pub taker: String,
    pub sell_token: String,
    pub buy_token: String,
    pub sell_amount: String,
    pub buy_amount: String,
    pub nonce: String,
    pub expiry: String,
    pub max_fee_ppm: u32,
    pub flags: u8,
    pub relayer: String,
    pub fee_mode: u8,
    pub fee: String,
    pub fee_token: String,
    pub fee_recipient: String,
}

impl WireOrder {
    pub fn to_sol(&self) -> Result<Order> {
        Ok(Order {
            maker: addr(&self.maker)?,
            taker: addr(&self.taker)?,
            sellToken: addr(&self.sell_token)?,
            buyToken: addr(&self.buy_token)?,
            sellAmount: uint(&self.sell_amount)?,
            buyAmount: uint(&self.buy_amount)?,
            nonce: uint(&self.nonce)?,
            expiry: uint(&self.expiry)?,
            maxFeePpm: self.max_fee_ppm,
            flags: self.flags,
            relayer: addr(&self.relayer)?,
            feeMode: self.fee_mode,
            fee: uint(&self.fee)?,
            feeToken: addr(&self.fee_token)?,
            feeRecipient: addr(&self.fee_recipient)?,
        })
    }

    pub fn from_sol(o: &Order) -> Self {
        let a = |x: Address| format!("{x:#x}");
        Self {
            maker: a(o.maker),
            taker: a(o.taker),
            sell_token: a(o.sellToken),
            buy_token: a(o.buyToken),
            sell_amount: o.sellAmount.to_string(),
            buy_amount: o.buyAmount.to_string(),
            nonce: o.nonce.to_string(),
            expiry: o.expiry.to_string(),
            max_fee_ppm: o.maxFeePpm,
            flags: o.flags,
            relayer: a(o.relayer),
            fee_mode: o.feeMode,
            fee: o.fee.to_string(),
            fee_token: a(o.feeToken),
            fee_recipient: a(o.feeRecipient),
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

/// Thị trường do Odoo cấu hình (`dex_markets`); node đối chiếu với `markets(key)` on-chain.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct MarketCfg {
    pub id: i64,
    pub base: Address,
    pub quote: Address,
    pub base_decimals: u8,
    pub quote_decimals: u8,
    pub fee_on: bool,
    pub maker_fee_ppm: u32,
    pub taker_fee_ppm: u32,
    pub fee_recipient: Address,
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

/// Một lệnh trong sổ. `remaining` tính theo `sellToken`, đã trừ mọi cặp đang chờ settle.
#[derive(Debug, Clone, PartialEq)]
pub struct Resting {
    pub hash: B256,
    pub order: Order,
    pub sig: Bytes,
    pub remaining: U256,
    pub seq: u64,
}

impl Resting {
    fn filled(&self) -> U256 {
        self.order.sellAmount - self.remaining
    }
}

/// Hàng lưu ở Odoo (`blockchain.dex.order`): đủ để dựng lại sổ đúng thứ tự.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Row {
    pub order_hash: String,
    pub order: WireOrder,
    pub signature: String,
    pub remaining: String,
    pub seq: u64,
}

impl Row {
    pub fn of(r: &Resting) -> Self {
        Self {
            order_hash: format!("{:#x}", r.hash),
            order: WireOrder::from_sol(&r.order),
            signature: hex_of(&r.sig),
            remaining: r.remaining.to_string(),
            seq: r.seq,
        }
    }

    pub fn resting(&self) -> Result<Resting> {
        Ok(Resting {
            hash: self.order_hash.parse()?,
            order: self.order.to_sol()?,
            sig: hex_bytes(&self.signature)?,
            remaining: uint(&self.remaining)?,
            seq: self.seq,
        })
    }
}

/// Một cặp khớp chờ lên chain. `tag` là `Match.ref` on-chain — khoá trade ở Odoo.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedFill {
    pub tag: B256,
    pub market_id: i64,
    pub maker: Resting,
    pub taker: Resting,
    pub maker_fill: U256,
    pub taker_fill: U256,
}

impl PlannedFill {
    pub fn to_match(&self) -> Match {
        Match {
            tag: self.tag,
            maker: self.maker.order.clone(),
            makerSig: self.maker.sig.clone(),
            taker: self.taker.order.clone(),
            takerSig: self.taker.sig.clone(),
            makerFill: self.maker_fill,
            takerFill: self.taker_fill,
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct Placement {
    pub fills: Vec<PlannedFill>,
    /// Phần còn lại vào sổ (GTC).
    pub rested: Option<Resting>,
    /// Phần còn lại bị bỏ (IOC/FOK) — không bao giờ nghỉ.
    pub dropped: U256,
    /// `seq` (ưu tiên thời gian) cấp cho lệnh này, nghỉ hay không.
    pub seq: u64,
}

#[derive(Debug, Clone)]
struct MarketBook {
    cfg: MarketCfg,
    /// Lệnh bán base, tốt nhất trước.
    asks: Vec<Resting>,
    /// Lệnh bán quote, tốt nhất trước.
    bids: Vec<Resting>,
}

impl MarketBook {
    fn side_mut(&mut self, sell_token: Address) -> &mut Vec<Resting> {
        if sell_token == self.cfg.base { &mut self.asks } else { &mut self.bids }
    }
}

/// `a` chào giá tốt hơn `b` cho phía đối diện: đưa nhiều hơn trên mỗi đơn vị nhận
/// (`a.sell/a.buy > b.sell/b.buy`), nhân chéo — lượng ở cửa `< 2^128` nên không tràn U512.
fn better(a: &Order, b: &Order) -> bool {
    mul(a.sellAmount, b.buyAmount) > mul(b.sellAmount, a.buyAmount)
}

fn mul(a: U256, b: U256) -> U512 {
    U512::from(a) * U512::from(b)
}

fn crosses(rest: &Order, inc: &Order) -> bool {
    mul(rest.buyAmount, inc.buyAmount) <= mul(inc.sellAmount, rest.sellAmount)
}

/// Bản sao đúng điều kiện của `SCaaSDexV1._checkMatch` + `_accept` cho lượng và giá: book không
/// bao giờ phát một cặp contract sẽ từ chối (review D2).
pub fn limits_ok(maker: &Resting, taker: &Resting, x: U256, y: U256) -> bool {
    let (m, t) = (&maker.order, &taker.order);
    let side_ok = |r: &Resting, fill: U256| {
        let fok = r.order.flags & FLAG_FOK != 0;
        fill <= r.remaining && (!fok || (r.filled().is_zero() && fill == r.order.sellAmount))
    };
    !x.is_zero()
        && !y.is_zero()
        && side_ok(maker, x)
        && side_ok(taker, y)
        && mul(y, m.sellAmount) >= mul(x, m.buyAmount)
        && mul(x, t.sellAmount) >= mul(y, t.buyAmount)
}

fn div_ceil(a: U512, b: U512) -> U512 {
    (a + b - U512::from(1u8)) / b
}

fn to256(v: U512) -> U256 {
    U256::from_limbs_slice(&v.as_limbs()[..4])
}

/// Phí relayer của `o` cho lượng `sold` — đúng như `SCaaSDexV1._relayerFee`. `(token, amount)`.
pub fn relayer_fee(o: &Order, sold: U256) -> (Address, U256) {
    let token = if o.feeToken == Address::ZERO { o.sellToken } else { o.feeToken };
    match o.feeMode {
        1 => (token, sold * o.fee / U256::from(PPM)),
        2 if !o.sellAmount.is_zero() => (token, to256(mul(o.fee, sold) / U512::from(o.sellAmount))),
        _ => (token, U256::ZERO),
    }
}

/// Tag duy nhất cho một cặp. Hai lệnh + lượng đã khớp KHÔNG đủ: một cặp fail rồi được trả về sổ
/// khớp lại đúng như cũ, và Odoo coi tag trùng là phát lại. Muối ngẫu nhiên mỗi tiến trình + bộ đếm.
fn tag(maker: &Resting, taker: &Resting, salt: u64, n: u64) -> B256 {
    let mut b = Vec::with_capacity(112);
    b.extend_from_slice(maker.hash.as_slice());
    b.extend_from_slice(taker.hash.as_slice());
    b.extend_from_slice(&maker.filled().to_be_bytes::<32>());
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
    fills_made: u64,
}

impl Book {
    pub fn new(markets: Vec<MarketCfg>) -> Self {
        let markets = markets
            .into_iter()
            .map(|cfg| (pair(cfg.base, cfg.quote), MarketBook { cfg, asks: vec![], bids: vec![] }))
            .collect();
        Self { markets, next_seq: 1, salt: random_u64(), fills_made: 0 }
    }

    /// Dựng lại từ hàng Odoo: chèn theo `seq` tăng nên cùng giá vẫn giữ thứ tự thời gian.
    pub fn load(markets: Vec<MarketCfg>, rows: &[Row]) -> Result<Self> {
        let mut book = Self::new(markets);
        let mut rs = rows.iter().map(Row::resting).collect::<Result<Vec<_>>>()?;
        rs.sort_by_key(|r| r.seq);
        for r in rs {
            book.next_seq = book.next_seq.max(r.seq + 1);
            if book.market(&r.order).is_some() {
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

    pub fn market(&self, o: &Order) -> Option<&MarketCfg> {
        self.markets.get(&pair(o.sellToken, o.buyToken)).map(|m| &m.cfg)
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

    pub fn open_of(&self, maker: Address) -> Vec<&Resting> {
        let mut v: Vec<&Resting> = self.all().filter(|r| r.order.maker == maker).collect();
        v.sort_by_key(|r| r.seq);
        v
    }

    /// Σ lượng `token` mà các lệnh mở của `maker` có thể kéo: phần bán còn lại + phí relayer còn lại.
    pub fn committed(&self, maker: Address, token: Address) -> U256 {
        self.all().filter(|r| r.order.maker == maker).fold(U256::ZERO, |acc, r| {
            let mut c = acc;
            if r.order.sellToken == token {
                c += r.remaining;
            }
            let (ft, fee) = relayer_fee(&r.order, r.remaining);
            if ft == token {
                c += fee;
            }
            c
        })
    }

    /// Chèn theo (giá tốt nhất, `seq`). Lệnh cùng hash đã có ⇒ cộng `remaining` (trả lại phần
    /// của một cặp fail).
    fn insert(&mut self, r: Resting) {
        let Some(mb) = self.markets.get_mut(&pair(r.order.sellToken, r.order.buyToken)) else { return };
        let side = mb.side_mut(r.order.sellToken);
        if let Some(e) = side.iter_mut().find(|e| e.hash == r.hash) {
            e.remaining = (e.remaining + r.remaining).min(e.order.sellAmount);
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

    /// Trả `fill` về một lệnh sau khi cặp của nó fail on-chain (§2 bước 3), giữ `seq` cũ. Đi lại
    /// qua matcher, không chèn thẳng: nếu cả hai bên cùng được trả thì chèn thẳng để lại một sổ
    /// chéo (bid >= ask nằm yên). IOC/FOK không bao giờ nghỉ nên không bao giờ được trả (review D5).
    pub fn restore(&mut self, r: Resting, fill: U256) -> Placement {
        if r.order.flags & (FLAG_IOC | FLAG_FOK) != 0 {
            return Placement { dropped: fill, seq: r.seq, ..Default::default() };
        }
        let current = self.remove(r.hash).map(|x| x.remaining).unwrap_or_default();
        let remaining = (current + fill).min(r.order.sellAmount);
        self.matching(Resting { remaining, ..r })
    }

    /// Bỏ lệnh hết hạn; trả hash đã bỏ.
    pub fn purge(&mut self, now: u64) -> Vec<B256> {
        let mut gone = vec![];
        for mb in self.markets.values_mut() {
            for side in [&mut mb.asks, &mut mb.bids] {
                side.retain(|r| {
                    let live = r.order.expiry >= U256::from(now);
                    if !live {
                        gone.push(r.hash);
                    }
                    live
                });
            }
        }
        gone
    }

    /// Bỏ mọi lệnh của `maker` có `nonce < min` (huỷ-hết on-chain).
    pub fn drop_below(&mut self, maker: Address, min: U256) -> Vec<B256> {
        let hs: Vec<B256> =
            self.all().filter(|r| r.order.maker == maker && r.order.nonce < min).map(|r| r.hash).collect();
        for h in &hs {
            self.remove(*h);
        }
        hs
    }

    /// Kiểm cửa thuần (§3.4). `remaining` = phần còn lại on-chain; `fundable`/`fee_fundable` từ
    /// `checkOrder`. Không đổi sổ.
    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        &self,
        hash: B256,
        o: &Order,
        remaining: U256,
        fundable: U256,
        fee_fundable: U256,
        relayer: Address,
        now: u64,
    ) -> Result<()> {
        let cap = U256::from(1u8) << 128;
        if o.sellAmount.is_zero() || o.buyAmount.is_zero() || o.sellAmount >= cap || o.buyAmount >= cap {
            bail!("amounts must be in (0, 2^128)");
        }
        if o.expiry <= U256::from(now + MIN_TTL_SECS) || o.expiry > U256::from(now + MAX_TTL_SECS) {
            bail!("expiry must be within ({MIN_TTL_SECS} s, {MAX_TTL_SECS} s] from now");
        }
        if o.flags > FLAG_IOC || o.flags == FLAG_FOK | FLAG_IOC {
            bail!("unknown or conflicting flags");
        }
        // RS5-9: chỉ relayer này settle được lệnh trong sổ (chống MEV, chống settle lại phần đã huỷ).
        if o.relayer != relayer {
            bail!("order.relayer must be this relayer {relayer:#x}");
        }
        if o.feeMode > 2 || (o.feeMode == 1 && U256::from(MAX_FEE_PPM) < o.fee) {
            bail!("bad relayer fee");
        }
        // Lệnh riêng tư hay trần phí dưới phí thị trường nằm trong sổ sẽ làm mọi cặp khớp với nó fail
        // (review I2): sổ công khai chỉ nhận lệnh khớp được với bất kỳ ai, ở cả vai maker lẫn taker.
        if o.taker != Address::ZERO {
            bail!("order.taker must be zero on the public book");
        }
        let Some(m) = self.market(o) else { bail!("no market for this pair") };
        if m.fee_on && o.maxFeePpm < m.maker_fee_ppm.max(m.taker_fee_ppm) {
            bail!("maxFeePpm below the market fee");
        }
        let min = uint(&m.min_base_amount)?;
        let base_amt = if o.sellToken == m.base { o.sellAmount } else { o.buyAmount };
        if base_amt < min {
            bail!("below the market minimum {min}");
        }
        if remaining.is_zero() {
            bail!("order is closed on-chain");
        }
        if self.get(hash).is_some() {
            bail!("duplicate order");
        }
        if self.open_of(o.maker).len() >= MAX_OPEN_PER_MAKER {
            bail!("too many open orders for this maker");
        }
        let rests = o.flags & (FLAG_IOC | FLAG_FOK) == 0;
        if rests && self.len() >= MAX_RESTING {
            bail!("order book full");
        }
        // Cam kết cộng dồn (review D6): mọi lệnh mở của maker kéo cùng một số dư.
        let (ft, fee) = relayer_fee(o, remaining);
        let need_sell = self.committed(o.maker, o.sellToken) + remaining + if ft == o.sellToken { fee } else { U256::ZERO };
        if need_sell > fundable {
            bail!("balance/allowance {fundable} below what open orders commit ({need_sell})");
        }
        if ft != o.sellToken && !fee.is_zero() && self.committed(o.maker, ft) + fee > fee_fundable {
            bail!("relayer-fee token balance/allowance too low");
        }
        Ok(())
    }

    /// Khớp `taker` (hash + `remaining` đã biết) vào sổ (§3.3). Đổi sổ: lệnh nghỉ giảm/biến mất,
    /// phần còn lại GTC vào sổ. Gọi trên BẢN SAO khi cần thử trước.
    pub fn place(&mut self, hash: B256, order: Order, sig: Bytes, remaining: U256) -> Placement {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.matching(Resting { hash, order, sig, remaining, seq })
    }

    fn matching(&mut self, mut t: Resting) -> Placement {
        let mut out = Placement { seq: t.seq, ..Default::default() };
        let Some(mb) = self.markets.get_mut(&pair(t.order.sellToken, t.order.buyToken)) else {
            out.dropped = t.remaining;
            return out;
        };
        let market_id = mb.cfg.id;
        let opposite = if t.order.sellToken == mb.cfg.base { &mut mb.bids } else { &mut mb.asks };
        let fok = t.order.flags & FLAG_FOK != 0;
        // Phí thị trường có thể tăng sau khi lệnh vào sổ: không phát cặp contract sẽ `FeeAboveSigned`.
        let (fee_on, maker_ppm, taker_ppm) = (mb.cfg.fee_on, mb.cfg.maker_fee_ppm, mb.cfg.taker_fee_ppm);
        let taker_fee_ok = !fee_on || t.order.maxFeePpm >= taker_ppm;
        let mut i = 0;
        while taker_fee_ok && i < opposite.len() && !t.remaining.is_zero() {
            let r = &opposite[i];
            if !crosses(&r.order, &t.order) {
                break; // sắp theo giá: sau đây chỉ tệ hơn
            }
            if r.order.maker == t.order.maker || (fee_on && r.order.maxFeePpm < maker_ppm) {
                i += 1; // self-trade prevention (review D21) / trần phí đã ký dưới phí maker
                continue;
            }
            let (rs, rb) = (U512::from(r.order.sellAmount), U512::from(r.order.buyAmount));
            let (x, y) = if fok {
                // FOK: taker giao trọn `y = sellAmount` trong MỘT cặp (RS5-4).
                let y = t.remaining;
                (to256(U512::from(y) * rs / rb), y)
            } else {
                let x = r.remaining.min(to256(U512::from(t.remaining) * rs / rb));
                (x, to256(div_ceil(U512::from(x) * rb, rs)))
            };
            if !limits_ok(r, &t, x, y) {
                if fok {
                    i += 1; // lệnh nghỉ này không lấp trọn được; thử lệnh sau
                    continue;
                }
                break; // phần lẻ do làm tròn: nghỉ lại, không phát cặp contract sẽ từ chối
            }
            self.fills_made += 1;
            let fill = PlannedFill {
                tag: tag(r, &t, self.salt, self.fills_made),
                market_id,
                maker: r.clone(),
                taker: t.clone(),
                maker_fill: x,
                taker_fill: y,
            };
            out.fills.push(fill);
            t.remaining -= y;
            let r = &mut opposite[i];
            r.remaining -= x;
            if r.remaining.is_zero() {
                opposite.remove(i);
            } else {
                i += 1;
            }
            if fok {
                break;
            }
        }
        if t.remaining.is_zero() {
            return out;
        }
        if t.order.flags & (FLAG_IOC | FLAG_FOK) != 0 {
            out.dropped = t.remaining;
            return out;
        }
        out.rested = Some(t.clone());
        self.insert(t);
        out
    }

    /// Mức giá gộp: `(bids, asks)`, mỗi mức `(giá thập phân, lượng base)`.
    pub fn depth(&self, market_id: i64, levels: usize) -> Option<(Vec<Level>, Vec<Level>)> {
        let mb = self.markets.values().find(|m| m.cfg.id == market_id)?;
        let cfg = &mb.cfg;
        let agg = |side: &[Resting], is_ask: bool| -> Vec<Level> {
            let mut out: Vec<Level> = vec![];
            for r in side {
                let (base_amt, quote_amt) = if is_ask {
                    (r.order.sellAmount, r.order.buyAmount)
                } else {
                    (r.order.buyAmount, r.order.sellAmount)
                };
                let price = price_str(quote_amt, base_amt, cfg.base_decimals, cfg.quote_decimals);
                let base_rem = if is_ask {
                    r.remaining
                } else {
                    to256(mul(r.remaining, r.order.buyAmount) / U512::from(r.order.sellAmount))
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

/// `quote/base` theo đơn vị hiển thị, 18 chữ số lẻ (review D16): không bao giờ chia nguyên thô.
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
    use std::str::FromStr;

    const BASE: Address = Address::repeat_byte(0xaa);
    const QUOTE: Address = Address::repeat_byte(0xbb);
    const RELAYER: Address = Address::repeat_byte(0xee);
    const NOW: u64 = 1_800_000_000;

    fn market() -> MarketCfg {
        MarketCfg {
            id: 1,
            base: BASE,
            quote: QUOTE,
            base_decimals: 18,
            quote_decimals: 6,
            fee_on: false,
            maker_fee_ppm: 0,
            taker_fee_ppm: 0,
            fee_recipient: Address::ZERO,
            min_base_amount: "0".into(),
        }
    }

    fn o(maker: u8, sell: Address, sell_amt: u64, buy: Address, buy_amt: u64, nonce: u64) -> Order {
        Order {
            maker: Address::repeat_byte(maker),
            taker: Address::ZERO,
            sellToken: sell,
            buyToken: buy,
            sellAmount: U256::from(sell_amt),
            buyAmount: U256::from(buy_amt),
            nonce: U256::from(nonce),
            expiry: U256::from(NOW + 300),
            maxFeePpm: 0,
            flags: 0,
            relayer: RELAYER,
            feeMode: 0,
            fee: U256::ZERO,
            feeToken: Address::ZERO,
            feeRecipient: Address::ZERO,
        }
    }

    fn hash_of(o: &Order) -> B256 {
        keccak256(format!("{o:?}"))
    }

    fn put(book: &mut Book, o: Order) -> Placement {
        let h = hash_of(&o);
        let rem = o.sellAmount;
        book.place(h, o, Bytes::new(), rem)
    }

    fn ask(maker: u8, base: u64, quote: u64, nonce: u64) -> Order {
        o(maker, BASE, base, QUOTE, quote, nonce)
    }

    fn bid(maker: u8, quote: u64, base: u64, nonce: u64) -> Order {
        o(maker, QUOTE, quote, BASE, base, nonce)
    }

    #[test]
    fn kat_hashes_match_forge() {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm/test/vectors/dex_kat.json");
        let k: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let s = |f: &str| k[f].as_str().unwrap().to_string();
        let a = |f: &str| Address::from_str(&s(f)).unwrap();
        let u = |f: &str| U256::from_str(&s(f)).unwrap();
        let order = Order {
            maker: a("maker"),
            taker: Address::ZERO,
            sellToken: a("sell_token"),
            buyToken: a("buy_token"),
            sellAmount: u("sell_amount"),
            buyAmount: u("buy_amount"),
            nonce: u("nonce"),
            expiry: u("expiry"),
            maxFeePpm: s("max_fee_ppm").parse().unwrap(),
            flags: s("flags").parse().unwrap(),
            relayer: a("relayer"),
            feeMode: s("fee_mode").parse().unwrap(),
            fee: u("fee"),
            feeToken: Address::ZERO,
            feeRecipient: Address::ZERO,
        };
        let d = domain(s("chain_id").parse().unwrap(), a("dex"));
        let h = order_hash(&d, &order);
        assert_eq!(format!("{h:#x}"), s("order_hash").to_lowercase());
        assert_eq!(format!("{:#x}", cancel_digest(&d, h)), s("cancel_digest").to_lowercase());
        assert_eq!(
            format!("{:#x}", invalidate_digest(&d, order.maker, U256::from(42))),
            s("invalidate_digest").to_lowercase()
        );
    }

    #[test]
    fn wire_round_trips_and_rejects_garbage() {
        let x = ask(1, 100, 200, 1);
        assert_eq!(WireOrder::from_sol(&x).to_sol().unwrap(), x);
        let mut w = WireOrder::from_sol(&x);
        w.sell_amount = "01".into();
        assert!(w.to_sol().is_err());
    }

    #[test]
    fn price_time_priority_best_price_then_earliest() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 10, 30, 1)); // 3.0
        put(&mut b, ask(2, 10, 20, 1)); // 2.0 best
        put(&mut b, ask(3, 10, 20, 2)); // 2.0, later
        let p = put(&mut b, bid(9, 60, 30, 1)); // buys up to 30 base at <= 2.0 → fills 2 and 3 only
        let makers: Vec<Address> = p.fills.iter().map(|f| f.maker.order.maker).collect();
        assert_eq!(makers, vec![Address::repeat_byte(2), Address::repeat_byte(3)]);
        let rest = p.rested.expect("bid remainder rests");
        assert_eq!(rest.remaining, U256::from(20)); // 60 - 40 quote left
        assert_eq!(b.len(), 2); // ask@3.0 and the bid remainder
    }

    #[test]
    fn partial_fill_executes_at_the_makers_price_and_keeps_the_maker_resting() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 100, 200, 1));
        let p = put(&mut b, bid(2, 100, 40, 1)); // willing to pay 2.5
        assert_eq!(p.fills.len(), 1);
        let f = &p.fills[0];
        // 100 quote at maker price 2.0 buys 50 base; the maker has 100 → x = 50, y = 100
        assert_eq!((f.maker_fill, f.taker_fill), (U256::from(50), U256::from(100)));
        assert!(limits_ok(&f.maker, &f.taker, f.maker_fill, f.taker_fill));
        let left = b.open_of(Address::repeat_byte(1));
        assert_eq!(left[0].remaining, U256::from(50));
        assert!(p.rested.is_none());
    }

    #[test]
    fn non_crossing_orders_rest_on_both_sides() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 10, 30, 1));
        let p = put(&mut b, bid(2, 20, 10, 1));
        assert!(p.fills.is_empty());
        let (bids, asks) = b.depth(1, 10).unwrap();
        assert_eq!((bids.len(), asks.len()), (1, 1));
    }

    #[test]
    fn ioc_remainder_is_dropped_not_rested() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 10, 20, 1));
        let mut x = bid(2, 100, 50, 1);
        x.flags = FLAG_IOC;
        let p = put(&mut b, x);
        assert_eq!(p.fills.len(), 1);
        assert_eq!(p.dropped, U256::from(80));
        assert!(p.rested.is_none());
        assert!(b.is_empty());
    }

    #[test]
    fn fok_fills_whole_against_one_maker_or_nothing() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 10, 20, 1)); // too small for the FOK
        put(&mut b, ask(3, 100, 200, 1));
        let mut x = bid(2, 60, 30, 1);
        x.flags = FLAG_FOK;
        let p = put(&mut b, x.clone());
        assert_eq!(p.fills.len(), 1, "skips the small maker, fills whole against one");
        assert_eq!(p.fills[0].maker.order.maker, Address::repeat_byte(3));
        assert_eq!(p.fills[0].taker_fill, U256::from(60));
        let mut y = bid(4, 1_000, 500, 1);
        y.flags = FLAG_FOK;
        let p = put(&mut b, y);
        assert!(p.fills.is_empty());
        assert_eq!(p.dropped, U256::from(1_000));
    }

    #[test]
    fn self_trade_is_skipped() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 10, 20, 1));
        put(&mut b, ask(2, 10, 20, 1));
        let p = put(&mut b, bid(1, 20, 10, 2));
        assert_eq!(p.fills.len(), 1);
        assert_eq!(p.fills[0].maker.order.maker, Address::repeat_byte(2));
    }

    #[test]
    fn limits_mirror_the_contract_including_rounding() {
        // maker 3 base for 10 quote (3.33); taker sells 10 quote for 3 base (same price)
        let m = Resting { hash: B256::ZERO, order: ask(1, 3, 10, 1), sig: Bytes::new(), remaining: U256::from(3), seq: 1 };
        let t = Resting { hash: B256::ZERO, order: bid(2, 10, 3, 1), sig: Bytes::new(), remaining: U256::from(10), seq: 2 };
        assert!(limits_ok(&m, &t, U256::from(3), U256::from(10)));
        // 1 base would cost ceil(10/3) = 4 quote: 4/1 > 10/3 breaks the taker's limit
        assert!(!limits_ok(&m, &t, U256::from(1), U256::from(4)));
        assert!(!limits_ok(&m, &t, U256::from(4), U256::from(14)), "overfill");
    }

    #[test]
    fn rows_round_trip_rebuilds_the_same_book() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 10, 30, 1));
        put(&mut b, ask(2, 10, 20, 1));
        put(&mut b, ask(3, 10, 20, 2));
        put(&mut b, bid(4, 10, 10, 1));
        put(&mut b, bid(5, 100, 40, 1)); // partially fills ask 2 & 3
        let rows = b.rows();
        let json = serde_json::to_string(&rows).unwrap();
        let back: Vec<Row> = serde_json::from_str(&json).unwrap();
        let mut c = Book::load(vec![market()], &back).unwrap();
        assert_eq!(c.rows(), rows);
        assert_eq!(c.depth(1, 10), b.depth(1, 10));
        // the restarted book matches exactly like the original
        let strip = |p: Placement| p.fills.into_iter().map(|f| (f.maker, f.taker, f.maker_fill, f.taker_fill)).collect::<Vec<_>>();
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
        let f = &p.fills[0];
        assert!(b.restore(f.maker.clone(), f.maker_fill).fills.is_empty());
        assert_eq!(b.open_of(Address::repeat_byte(1))[0].remaining, U256::from(10));
        assert_eq!(b.open_of(Address::repeat_byte(1))[0].seq, f.maker.seq, "time priority kept");
        let mut ioc = f.taker.clone();
        ioc.order.flags = FLAG_IOC;
        b.restore(ioc, f.taker_fill);
        assert!(b.open_of(Address::repeat_byte(2)).is_empty());
    }

    #[test]
    fn restoring_both_sides_rematches_instead_of_leaving_a_crossed_book() {
        let mut b = Book::new(vec![market()]);
        put(&mut b, ask(1, 10, 20, 1));
        let p = put(&mut b, bid(2, 20, 10, 1));
        let f = p.fills[0].clone();
        assert!(b.restore(f.maker.clone(), f.maker_fill).fills.is_empty());
        let again = b.restore(f.taker.clone(), f.taker_fill);
        assert_eq!(again.fills.len(), 1, "the two healthy sides trade again");
        assert_eq!((again.fills[0].maker_fill, again.fills[0].taker_fill), (f.maker_fill, f.taker_fill));
        assert_ne!(again.fills[0].tag, f.tag, "a re-match is a new trade, not a replay");
        assert!(b.is_empty());
    }

    #[test]
    fn admit_enforces_spam_caps() {
        let mut b = Book::new(vec![market()]);
        let good = ask(1, 100, 200, 1);
        let ok = |b: &Book, x: &Order, fundable: u64| {
            b.admit(hash_of(x), x, x.sellAmount, U256::from(fundable), U256::ZERO, RELAYER, NOW)
        };
        ok(&b, &good, 100).unwrap();
        // committed balance: the same 100 cannot back two orders (review D6)
        put(&mut b, good.clone());
        assert!(ok(&b, &ask(1, 100, 200, 2), 150).is_err());
        ok(&b, &ask(1, 50, 100, 2), 150).unwrap();
        let mut x = ask(1, 1, 2, 3);
        x.relayer = Address::ZERO;
        assert!(ok(&b, &x, 1_000).is_err(), "RS5-9");
        let mut x = ask(1, 1, 2, 3);
        x.expiry = U256::from(NOW + 2);
        assert!(ok(&b, &x, 1_000).is_err(), "expiry too short");
        x.expiry = U256::from(NOW + MAX_TTL_SECS + 1);
        assert!(ok(&b, &x, 1_000).is_err(), "expiry too long");
        let mut x = ask(1, 1, 2, 3);
        x.sellAmount = U256::from(1u8) << 128;
        assert!(ok(&b, &x, 1_000).is_err(), "2^128");
        let mut x = ask(1, 1, 2, 3);
        x.flags = FLAG_FOK | FLAG_IOC;
        assert!(ok(&b, &x, 1_000).is_err());
        assert!(ok(&b, &o(1, BASE, 1, Address::repeat_byte(0xcc), 1, 9), 1_000).is_err(), "no market");
        assert!(ok(&b, &good, 1_000).is_err(), "duplicate");
        for n in 10..(10 + MAX_OPEN_PER_MAKER as u64) {
            put(&mut b, ask(7, 1, 2, n));
        }
        assert!(ok(&b, &ask(7, 1, 2, 999), 1_000).is_err(), "per-maker cap");
        // minimum size on the base side, both directions (review D22)
        let mut m = market();
        m.min_base_amount = "10".into();
        let b2 = Book::new(vec![m]);
        assert!(b2.admit(B256::ZERO, &ask(1, 5, 10, 1), U256::from(5), U256::from(99), U256::ZERO, RELAYER, NOW).is_err());
        assert!(b2.admit(B256::ZERO, &bid(1, 50, 5, 1), U256::from(50), U256::from(99), U256::ZERO, RELAYER, NOW).is_err());
        b2.admit(B256::ZERO, &bid(1, 50, 10, 1), U256::from(50), U256::from(99), U256::ZERO, RELAYER, NOW).unwrap();
    }

    #[test]
    fn poison_orders_never_block_the_book() {
        // review I2: a private order or a fee cap below the market fee would fail every pair it joins
        let mut m = market();
        (m.fee_on, m.maker_fee_ppm, m.taker_fee_ppm) = (true, 1_000, 2_000);
        let mut b = Book::new(vec![m]);
        let ok = |b: &Book, x: &Order| b.admit(hash_of(x), x, x.sellAmount, U256::from(1_000), U256::ZERO, RELAYER, NOW);
        let mut x = ask(1, 100, 200, 1);
        x.maxFeePpm = 1_999;
        assert!(ok(&b, &x).is_err(), "cap below the taker fee");
        x.maxFeePpm = 2_000;
        ok(&b, &x).unwrap();
        x.taker = Address::repeat_byte(9);
        assert!(ok(&b, &x).is_err(), "private order");
        // a resting order whose cap fell under a raised fee is skipped, the next one trades
        let mut cheap = ask(1, 100, 100, 2);
        cheap.maxFeePpm = 500;
        put(&mut b, cheap);
        let mut fair = ask(2, 100, 200, 3);
        fair.maxFeePpm = 2_000;
        put(&mut b, fair.clone());
        let mut t = bid(3, 200, 100, 4);
        t.maxFeePpm = 2_000;
        let p = put(&mut b, t.clone());
        assert_eq!(p.fills.len(), 1);
        assert_eq!(p.fills[0].maker.hash, hash_of(&fair));
        // a taker whose cap is under the taker fee never matches
        let mut low = bid(4, 200, 100, 5);
        low.maxFeePpm = 1_000;
        assert!(put(&mut b, low).fills.is_empty());
    }

    #[test]
    fn admit_counts_the_relayer_fee_on_top() {
        let b = Book::new(vec![market()]);
        let mut x = ask(1, 100, 200, 1);
        x.feeMode = 1;
        x.fee = U256::from(10_000); // 1 %
        assert!(b.admit(B256::ZERO, &x, x.sellAmount, U256::from(100), U256::ZERO, RELAYER, NOW).is_err());
        b.admit(B256::ZERO, &x, x.sellAmount, U256::from(101), U256::ZERO, RELAYER, NOW).unwrap();
        assert_eq!(relayer_fee(&x, U256::from(40)), (BASE, U256::ZERO)); // 40 * 1% floors to 0
        x.feeMode = 2;
        x.fee = U256::from(3);
        x.feeToken = Address::repeat_byte(0xf0);
        assert_eq!(relayer_fee(&x, U256::from(40)).1, U256::from(1)); // 3*40/100 floors
    }

    #[test]
    fn purge_and_drop_below() {
        let mut b = Book::new(vec![market()]);
        let mut x = ask(1, 10, 20, 1);
        x.expiry = U256::from(NOW + 10);
        put(&mut b, x);
        put(&mut b, ask(2, 10, 20, 5));
        put(&mut b, ask(2, 10, 20, 9));
        assert_eq!(b.purge(NOW + 11).len(), 1);
        assert_eq!(b.drop_below(Address::repeat_byte(2), U256::from(6)).len(), 1);
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn price_is_scaled_by_decimals() {
        // 2 000 quote (6 dec) for 1 base (18 dec)
        assert_eq!(price_str(U256::from(2_000_000_000u64), U256::from(10u64).pow(U256::from(18)), 18, 6), "2000");
        assert_eq!(price_str(U256::from(1u8), U256::from(3u8), 0, 0), "0.333333333333333333");
    }
}
