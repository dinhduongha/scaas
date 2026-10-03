//! DEX venue: phần I/O quanh `Book` (design §2–§3). Một venue mỗi chain, người ghi DUY NHẤT của sổ.
//!
//! - Lưu bền ở Odoo qua `/json/2` (RS5-2): mỗi thay đổi sổ là MỘT `dex_book_commit` (lệnh + trade +
//!   relay job `call`), thành công mới thay sổ trong bộ nhớ; lỗi ⇒ nạp lại sổ từ Odoo (review D20).
//! - Settle đi qua outbox Odoo như mọi job khác: `submit` claim, journal `signed`, thay thế, lấp nonce.
//! - Watcher event final có cursor riêng (RS5-8): DEX lỗi không chặn chốt thanh toán.
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, Log, TransactionRequest};
use alloy::signers::Signature;
use alloy::sol_types::{Eip712Domain, SolCall, SolError, SolEvent, SolInterface};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tracing::{info, warn};

use super::{
    cancel_digest, domain, hex_bytes, hex_of, invalidate_digest, order_hash, pair, Book, CancelReq, IOrderBookDex,
    MarketCfg, Order, PlannedFill, Resting, Row, WireOrder, FLAG_FOK, FLAG_IOC, ST_OK, relayer_fee,
};
use crate::chain::{classify, Chain, SimError};
use crate::finality::{next_range, quorum_ok, safe_head, Mode};
use crate::odoo::Odoo;
use crate::submit::now;

/// Lần thử lại khi simulate loại lệnh nghỉ hỏng (design §2 bước 2).
const MAX_ROUNDS: usize = 3;
const RECENT_TRADES: usize = 200;
/// Huỷ on-chain tốn gas relayer: mỗi maker tối đa chừng này mỗi giờ (review D14).
const ONCHAIN_CANCELS_PER_HOUR: usize = 20;
const CANCEL_BATCH: usize = 50;
const MAX_LOG_SPAN: u64 = 1000;

/// Lỗi trả cho client: `Bad` = 400 (lỗi của lệnh), `Unavailable` = 503 (RPC/Odoo).
#[derive(Debug)]
pub enum VenueError {
    Bad(String),
    Unavailable(String),
}

impl std::fmt::Display for VenueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VenueError::Bad(s) | VenueError::Unavailable(s) => f.write_str(s),
        }
    }
}

fn bad(e: impl std::fmt::Display) -> VenueError {
    VenueError::Bad(e.to_string())
}

fn down(e: impl std::fmt::Display) -> VenueError {
    VenueError::Unavailable(e.to_string())
}

#[derive(Debug, Clone, Serialize)]
pub struct TradeView {
    pub market_id: i64,
    pub tag: String,
    pub price: String,
    pub base_amount: String,
    pub taker_side: &'static str,
    pub at: u64,
}

#[derive(Debug, Serialize)]
pub struct PlaceReply {
    pub order_hash: String,
    pub status: &'static str,
    pub fills: Vec<Value>,
    pub remaining: String,
}

#[derive(Debug, Deserialize)]
struct MarketsReply {
    dex: Address,
    markets: Vec<MarketCfg>,
}

#[derive(Debug, Deserialize)]
struct LoadReply {
    rows: Vec<Row>,
}

#[derive(Debug, Deserialize)]
struct FailedTrade {
    tag: String,
    /// None: lệnh đã đóng ở Odoo (huỷ/hết hạn/invalid) — không bao giờ trả về sổ (review I3).
    maker: Option<Row>,
    taker: Option<Row>,
    maker_fill: String,
    taker_fill: String,
}

#[derive(Debug, Deserialize)]
struct SyncReply {
    failed: Vec<FailedTrade>,
}

#[derive(Debug, Deserialize)]
struct CursorReply {
    indexed_block: u64,
}

/// Một thay đổi sổ, ghi vào Odoo trong MỘT transaction (`dex_book_commit`).
#[derive(Debug, Default, Serialize)]
pub struct Commit {
    pub orders: Vec<Value>,
    pub trades: Vec<Value>,
    pub jobs: Vec<Value>,
    pub acks: Vec<String>,
}

impl Commit {
    fn is_empty(&self) -> bool {
        self.orders.is_empty() && self.trades.is_empty() && self.jobs.is_empty() && self.acks.is_empty()
    }

    fn order(&mut self, market_id: i64, r: &Resting, state: &str) {
        let row = Row::of(r);
        self.orders.push(json!({
            "market_id": market_id, "order_hash": row.order_hash, "order": row.order,
            "signature": row.signature, "remaining": row.remaining, "seq": row.seq, "state": state,
        }));
    }
}

fn state_of(r: &Resting) -> &'static str {
    if r.remaining.is_zero() {
        "filled"
    } else if r.remaining < r.order.sellAmount {
        "partial"
    } else {
        "open"
    }
}

pub struct Venue {
    pub chain: Arc<Chain>,
    relay: Odoo,
    indexer: Option<Odoo>,
    pub dex: Address,
    domain: Eip712Domain,
    book: Mutex<Book>,
    trades: std::sync::Mutex<VecDeque<TradeView>>,
    cancels: std::sync::Mutex<CancelQueue>,
}

#[derive(Default)]
struct CancelQueue {
    // ponytail: hàng đợi trong bộ nhớ — node chết trước khi flush thì lệnh đã gỡ khỏi sổ (và Odoo ghi
    // `cancelled`) nhưng chưa đóng on-chain; vì RS5-9 chỉ relayer này settle được nó nên an toàn.
    // Muốn bền: lưu chữ ký huỷ vào `blockchain.dex.order` và flush từ Odoo.
    pending: Vec<(i64, CancelReq)>,
    recent: HashMap<Address, Vec<u64>>,
}

impl CancelQueue {
    /// Có được huỷ on-chain lần nữa trong giờ này không (và ghi nhận nếu có).
    fn allow(&mut self, maker: Address, at: u64) -> bool {
        let v = self.recent.entry(maker).or_default();
        v.retain(|t| at < t + 3600);
        if v.len() >= ONCHAIN_CANCELS_PER_HOUR {
            return false;
        }
        v.push(at);
        true
    }
}

impl Venue {
    /// Nạp thị trường + sổ từ Odoo, đối chiếu thị trường với chain (design §3.1).
    pub async fn start(chain: Arc<Chain>, relay: Odoo, indexer: Option<Odoo>, dex: Address) -> Result<Arc<Self>> {
        let n = chain.number;
        let mr: MarketsReply = relay
            .call("blockchain.dex.market", "dex_markets", json!({"evm_chain_number": n}))
            .await
            .context("dex_markets")?;
        if mr.dex != dex {
            bail!("chain {n}: Odoo DEX {:#x} != node config {dex:#x}", mr.dex);
        }
        let mut markets = vec![];
        for m in mr.markets {
            match onchain_matches(&chain, dex, &m).await {
                Ok(true) => markets.push(m),
                Ok(false) => warn!(chain = n, market = m.id, "on-chain market differs from Odoo; not served"),
                Err(e) => warn!(chain = n, market = m.id, "market check: {e:#}; not served"),
            }
        }
        let load: LoadReply = relay
            .call("blockchain.dex.order", "dex_book_load", json!({"evm_chain_number": n}))
            .await
            .context("dex_book_load")?;
        let book = Book::load(markets, &load.rows)?;
        info!(chain = n, orders = book.len(), "dex book loaded");
        Ok(Arc::new(Self {
            domain: domain(n, dex),
            chain,
            relay,
            indexer,
            dex,
            book: Mutex::new(book),
            trades: Default::default(),
            cancels: Default::default(),
        }))
    }

    pub fn relayer(&self) -> Address {
        self.chain.address()
    }

    pub fn hash(&self, o: &Order) -> B256 {
        order_hash(&self.domain, o)
    }

    // ------------------------------------------------------------------------------ chain reads

    async fn call(&self, data: Vec<u8>) -> std::result::Result<Bytes, SimError> {
        let tx = TransactionRequest::default().from(self.relayer()).to(self.dex).input(data.into());
        self.chain.primary().call(tx).await.map_err(|e| classify(&e))
    }

    async fn check(&self, o: &Order, sig: &Bytes) -> Result<IOrderBookDex::checkOrderReturn> {
        let out = self
            .call(IOrderBookDex::checkOrderCall { o: o.clone(), sig: sig.clone() }.abi_encode())
            .await
            .map_err(|e| anyhow!("checkOrder: {e}"))?;
        Ok(IOrderBookDex::checkOrderCall::abi_decode_returns(&out)?)
    }

    /// Simulate `settle`: `Ok(vec ok-per-match)`; mọi cặp fail ⇒ `NothingSettled` ⇒ toàn `false`.
    async fn simulate(&self, fills: &[PlannedFill]) -> std::result::Result<Vec<bool>, SimError> {
        let ms = fills.iter().map(PlannedFill::to_match).collect();
        match self.call(IOrderBookDex::settleCall { ms }.abi_encode()).await {
            Ok(out) => IOrderBookDex::settleCall::abi_decode_returns(&out)
                .map_err(|e| SimError::Revert(format!("decode: {e}"))),
            Err(SimError::Revert(r))
                if r.contains(&alloy::hex::encode(<IOrderBookDex::NothingSettled as SolError>::SELECTOR)) =>
            {
                Ok(vec![false; fills.len()])
            }
            Err(e) => Err(e),
        }
    }

    /// Chữ ký EOA (khôi phục cục bộ) hoặc ERC-1271 (gọi `isValidSignature` của ví hợp đồng).
    async fn valid_sig(&self, signer: Address, digest: B256, sig: &Bytes) -> bool {
        if sig.len() == 65 {
            if let Ok(s) = Signature::try_from(sig.as_ref()) {
                // High-s: contract `tryRecover` từ chối ⇒ `cancel` bỏ qua im lặng (review I4).
                if s.normalize_s().is_some() {
                    return false;
                }
                if s.recover_address_from_prehash(&digest).ok() == Some(signer) {
                    return true;
                }
            }
        }
        alloy::sol! {
            function isValidSignature(bytes32 hash, bytes signature) external view returns (bytes4);
        }
        let data = isValidSignatureCall { hash: digest, signature: sig.clone() }.abi_encode();
        let tx = TransactionRequest::default().to(signer).input(data.into());
        match self.chain.primary().call(tx).await {
            Ok(out) => out.len() >= 4 && out[..4] == [0x16, 0x26, 0xba, 0x7e],
            Err(_) => false,
        }
    }

    // ------------------------------------------------------------------------------ intake

    pub async fn place(&self, wire: &WireOrder, signature: &str) -> std::result::Result<PlaceReply, VenueError> {
        let o = wire.to_sol().map_err(bad)?;
        let sig = sig_bytes(signature)?;
        let h = self.hash(&o);
        let c = self.check(&o, &sig).await.map_err(down)?;
        if c.h != h {
            // KAT lệch giữa node và contract: không bao giờ nhận lệnh mà chain băm khác.
            return Err(down(format!("order hash mismatch: node {h:#x}, chain {:#x}", c.h)));
        }
        if c.status != ST_OK {
            return Err(bad(format!("order refused on-chain: {}", status_name(c.status))));
        }
        let mut book = self.book.lock().await;
        book.purge(now());
        book.admit(h, &o, c.remaining, c.fundable, c.feeFundable, self.relayer(), now()).map_err(bad)?;

        let mut commit = Commit::default();
        let mut dropped_makers: Vec<B256> = vec![];
        let mut trial;
        let mut placed;
        let mut round = 0;
        loop {
            trial = book.clone();
            for d in &dropped_makers {
                trial.remove(*d);
            }
            placed = trial.place(h, o.clone(), sig.clone(), c.remaining);
            if placed.fills.is_empty() {
                break;
            }
            let ok = self.simulate(&placed.fills).await.map_err(|e| match e {
                SimError::Revert(r) => bad(format!("settlement simulation: {r}")),
                SimError::Transport(r) => down(format!("rpc: {r}")),
            })?;
            let failed: Vec<&PlannedFill> = placed.fills.iter().zip(&ok).filter(|(_, ok)| !**ok).map(|(f, _)| f).collect();
            if failed.is_empty() {
                break;
            }
            round += 1;
            for f in failed {
                let m = &f.maker;
                let healthy = match self.check(&m.order, &m.sig).await {
                    Ok(mc) => funded(&m.order, m.remaining, &mc),
                    Err(e) => return Err(down(e)),
                };
                if healthy {
                    // Lệnh nghỉ còn tốt mà cặp vẫn fail ⇒ lỗi nằm ở lệnh mới.
                    return Err(bad("settlement simulation refused this order"));
                }
                if let Some(mk) = book.market(&m.order) {
                    commit.order(mk.id, m, "invalid");
                }
                dropped_makers.push(m.hash);
            }
            if round >= MAX_ROUNDS {
                return Err(down("order book unstable; retry"));
            }
        }

        let market_id = book.market(&o).map(|m| m.id).ok_or_else(|| bad("no market"))?;
        self.add_fills(&mut commit, &trial, &placed.fills);
        let filled_here: U256 = placed.fills.iter().map(|f| f.taker_fill).sum();
        let taker_after = Resting {
            hash: h,
            order: o.clone(),
            sig: sig.clone(),
            remaining: c.remaining - filled_here,
            seq: placed.seq,
        };
        let taker_state = match (&placed.rested, placed.dropped.is_zero()) {
            (Some(_), _) => state_of(&taker_after),
            (None, true) => "filled",
            (None, false) => "cancelled", // IOC/FOK: phần còn lại huỷ, không nghỉ
        };
        commit.order(market_id, &taker_after, taker_state);
        self.commit_or_reload(&mut book, trial, commit).await?;
        drop(book);

        let fills: Vec<Value> = placed
            .fills
            .iter()
            .map(|f| {
                json!({"tag": format!("{:#x}", f.tag), "maker_hash": format!("{:#x}", f.maker.hash),
                       "maker_fill": f.maker_fill.to_string(), "taker_fill": f.taker_fill.to_string()})
            })
            .collect();
        self.remember(&placed.fills, &o);
        let status = match (placed.rested.is_some(), placed.fills.is_empty(), placed.dropped.is_zero()) {
            (true, true, _) => "resting",
            (true, false, _) => "partial",
            (false, _, true) => "filled",
            (false, _, false) => "cancelled",
        };
        Ok(PlaceReply {
            order_hash: format!("{h:#x}"),
            status,
            fills,
            remaining: placed.rested.map(|r| r.remaining).unwrap_or_default().to_string(),
        })
    }

    /// Lệnh maker sau khớp + trade + MỘT job `settle` cho cả lô (nguyên tử từng cặp on-chain).
    fn add_fills(&self, commit: &mut Commit, after: &Book, fills: &[PlannedFill]) {
        let Some(first) = fills.first() else { return };
        for f in fills {
            let mk = after.get(f.maker.hash).cloned().unwrap_or_else(|| Resting { remaining: U256::ZERO, ..f.maker.clone() });
            commit.order(f.market_id, &mk, state_of(&mk));
            commit.trades.push(json!({
                "tag": format!("{:#x}", f.tag), "market_id": f.market_id,
                "maker_hash": format!("{:#x}", f.maker.hash), "taker_hash": format!("{:#x}", f.taker.hash),
                "maker_fill": f.maker_fill.to_string(), "taker_fill": f.taker_fill.to_string(),
            }));
        }
        commit.jobs.push(self.settle_job(first.market_id, fills));
    }

    fn settle_job(&self, market_id: i64, fills: &[PlannedFill]) -> Value {
        let ms = fills.iter().map(PlannedFill::to_match).collect();
        let valid_until = fills
            .iter()
            .flat_map(|f| [f.maker.order.expiry, f.taker.order.expiry])
            .min()
            .unwrap_or_default();
        json!({
            "kind": "settle", "market_id": market_id, "target": format!("{:#x}", self.dex),
            "calldata": hex_of(&IOrderBookDex::settleCall { ms }.abi_encode()),
            "valid_until": valid_until.to_string(),
            "tags": fills.iter().map(|f| format!("{:#x}", f.tag)).collect::<Vec<_>>(),
        })
    }

    async fn commit_or_reload(
        &self,
        book: &mut Book,
        next: Book,
        commit: Commit,
    ) -> std::result::Result<(), VenueError> {
        if commit.is_empty() {
            *book = next;
            return Ok(());
        }
        let mut body = serde_json::to_value(&commit).map_err(down)?;
        body["evm_chain_number"] = json!(self.chain.number);
        match self.relay.call::<Value>("blockchain.dex.order", "dex_book_commit", body).await {
            Ok(_) => {
                *book = next;
                Ok(())
            }
            Err(e) => {
                // Timeout có thể là "Odoo đã commit": không đoán, nạp lại sự thật (review D20).
                warn!(chain = self.chain.number, "dex_book_commit: {e:#}; reloading the book from Odoo");
                if let Err(e2) = self.reload(book).await {
                    warn!(chain = self.chain.number, "reload: {e2:#}");
                }
                Err(down(format!("order book store unavailable: {e}")))
            }
        }
    }

    async fn reload(&self, book: &mut Book) -> Result<()> {
        let load: LoadReply =
            self.relay.call("blockchain.dex.order", "dex_book_load", json!({"evm_chain_number": self.chain.number})).await?;
        *book = Book::load(book.markets().cloned().collect(), &load.rows)?;
        Ok(())
    }

    fn remember(&self, fills: &[PlannedFill], taker: &Order) {
        let Ok(mut t) = self.trades.lock() else { return };
        for f in fills {
            let book_market = f.market_id;
            let maker = &f.maker.order;
            let taker_buys_base = taker.buyToken == maker.sellToken;
            // maker sells X: if X is base the trade price is takerFill/makerFill (quote per base)
            let (quote, base) = if taker_buys_base { (f.taker_fill, f.maker_fill) } else { (f.maker_fill, f.taker_fill) };
            t.push_front(TradeView {
                market_id: book_market,
                tag: format!("{:#x}", f.tag),
                price: format!("{quote}/{base}"),
                base_amount: base.to_string(),
                taker_side: if taker_buys_base { "buy" } else { "sell" },
                at: now(),
            });
            t.truncate(RECENT_TRADES);
        }
    }

    // ------------------------------------------------------------------------------ cancel

    /// Huỷ một lệnh bằng chữ ký `CancelOrder(orderHash)`: gỡ khỏi sổ NGAY + xếp huỷ on-chain.
    pub async fn cancel(&self, h: B256, signature: &str) -> std::result::Result<(), VenueError> {
        let sig = sig_bytes(signature)?;
        let mut book = self.book.lock().await;
        let r = book.get(h).cloned().ok_or_else(|| bad("order is not in the book"))?;
        if !self.valid_sig(r.order.maker, cancel_digest(&self.domain, h), &sig).await {
            return Err(bad("bad cancel signature"));
        }
        let market_id = book.market(&r.order).map(|m| m.id).unwrap_or_default();
        let mut next = book.clone();
        next.remove(h);
        let mut commit = Commit::default();
        commit.order(market_id, &r, "cancelled");
        self.commit_or_reload(&mut book, next, commit).await?;
        if let Ok(mut q) = self.cancels.lock() {
            if q.allow(r.order.maker, now()) {
                q.pending.push((market_id, CancelReq { order: r.order, sig }));
            }
        }
        Ok(())
    }

    /// Huỷ-hết: `InvalidateNonces(maker, minNonce)`. Chỉ khi maker còn ≥ 1 lệnh mở (chặn spam gas).
    pub async fn cancel_all(&self, maker: Address, min: U256, signature: &str) -> std::result::Result<usize, VenueError> {
        let sig = sig_bytes(signature)?;
        let mut book = self.book.lock().await;
        let open = book.open_of(maker);
        let Some(first) = open.first() else { return Err(bad("maker has no open orders")) };
        let market_id = book.market(&first.order).map(|m| m.id).unwrap_or_default();
        if !self.valid_sig(maker, invalidate_digest(&self.domain, maker, min), &sig).await {
            return Err(bad("bad invalidate signature"));
        }
        let call = IOrderBookDex::invalidateNoncesCall { maker, newMin: min, sig: sig.clone() }.abi_encode();
        if let Err(e) = self.call(call.clone()).await {
            return Err(bad(format!("invalidateNonces refused: {e}")));
        }
        let mut next = book.clone();
        let mut commit = Commit::default();
        for r in book.open_of(maker).into_iter().filter(|r| r.order.nonce < min) {
            commit.order(book.market(&r.order).map(|m| m.id).unwrap_or_default(), r, "cancelled");
        }
        let n = next.drop_below(maker, min).len();
        let allowed = self.cancels.lock().map(|mut q| q.allow(maker, now())).unwrap_or(false);
        if allowed {
            commit.jobs.push(json!({
                "kind": "invalidate", "market_id": market_id, "target": format!("{:#x}", self.dex),
                "calldata": hex_of(&call), "valid_until": (now() + 86_400).to_string(), "tags": [],
            }));
        }
        self.commit_or_reload(&mut book, next, commit).await?;
        Ok(n)
    }

    // ------------------------------------------------------------------------------ loops

    /// Trade fail ⇒ trả lại sổ; huỷ chờ ⇒ một tx `cancel`; hết hạn ⇒ bỏ khỏi bộ nhớ.
    pub async fn sync_once(&self) -> Result<()> {
        let sr: SyncReply =
            self.relay.call("blockchain.dex.trade", "dex_sync", json!({"evm_chain_number": self.chain.number})).await?;
        let mut book = self.book.lock().await;
        book.purge(now());
        let mut commit = Commit::default();
        // Khớp lại; cặp không simulate được ⇒ hai bên của nó không được trả về trong vòng này
        // (vẫn ack): không bao giờ kẹt cả chain vì một lệnh hỏng (review I3).
        // ponytail: bỏ cả bên khoẻ của cặp hỏng; đo trước khi tách từng bên.
        let mut skip: Vec<B256> = vec![];
        let (mut next, mut fills, mut touched);
        let (mut round, mut give_up) = (0, false);
        loop {
            next = book.clone();
            fills = Vec::<PlannedFill>::new();
            touched = Vec::<(i64, Resting)>::new();
            for ft in &sr.failed {
                for (row, fill) in [(&ft.maker, &ft.maker_fill), (&ft.taker, &ft.taker_fill)] {
                    let Some(row) = row else { continue };
                    let r = row.resting()?;
                    let fill = crate::metatx::uint(fill)?;
                    if give_up
                        || skip.contains(&r.hash)
                        || r.order.flags & (FLAG_IOC | FLAG_FOK) != 0
                        || r.order.expiry < U256::from(now())
                    {
                        continue;
                    }
                    let in_book = next.get(r.hash).map(|x| x.remaining).unwrap_or_default();
                    let c = self.check(&r.order, &r.sig).await?;
                    let add = fill.min(c.remaining.saturating_sub(in_book));
                    let Some(market_id) = next.market(&r.order).map(|m| m.id) else { continue };
                    if add.is_zero() || !funded(&r.order, in_book + add, &c) {
                        continue;
                    }
                    // Đi lại qua matcher: hai bên cùng khoẻ thì khớp lại, không để sổ chéo.
                    fills.extend(next.restore(r.clone(), add).fills);
                    touched.push((market_id, r));
                }
            }
            if fills.is_empty() {
                break;
            }
            let ok = self.simulate(&fills).await.map_err(|e| anyhow!("re-match simulation: {e}"))?;
            let bad: Vec<B256> =
                fills.iter().zip(&ok).filter(|(_, ok)| !**ok).flat_map(|(f, _)| [f.maker.hash, f.taker.hash]).collect();
            if bad.is_empty() {
                break;
            }
            warn!(chain = self.chain.number, n = bad.len() / 2, "re-matched fills do not simulate; not restoring them");
            skip.extend(bad);
            round += 1;
            give_up = round >= MAX_ROUNDS; // vòng cuối không trả gì về: ack, không kẹt
        }
        commit.acks.extend(sr.failed.iter().map(|ft| ft.tag.clone()));
        self.add_fills(&mut commit, &next, &fills);
        let pending: Vec<(i64, CancelReq)> =
            self.cancels.lock().map(|mut q| std::mem::take(&mut q.pending)).unwrap_or_default();
        for chunk in pending.chunks(CANCEL_BATCH) {
            let reqs: Vec<CancelReq> = chunk.iter().map(|(_, r)| r.clone()).collect();
            let valid_until = reqs.iter().map(|r| r.order.expiry).max().unwrap_or_default();
            commit.jobs.push(json!({
                "kind": "cancel", "market_id": chunk[0].0, "target": format!("{:#x}", self.dex),
                "calldata": hex_of(&IOrderBookDex::cancelCall { reqs }.abi_encode()),
                "valid_until": valid_until.to_string(), "tags": [],
            }));
        }
        let res = self.commit_or_reload(&mut book, next, commit).await;
        if res.is_err() && !pending.is_empty() {
            // Không mất huỷ on-chain khi Odoo lỗi; gửi trùng thì `origin_key` + `cancel` no-op chặn.
            if let Ok(mut q) = self.cancels.lock() {
                q.pending.extend(pending);
            }
        }
        res.map_err(|e| anyhow!("{e}"))
    }

    /// Một vòng watcher: log DEX trong vùng final ⇒ `dex_fill_ingest` ⇒ gỡ lệnh bị đóng on-chain.
    /// `true` = đã tiến.
    pub async fn watch_once(&self) -> Result<bool> {
        let Some(idx) = &self.indexer else { return Ok(false) };
        let nc = idx.node_config(self.chain.number, None).await?;
        let cur: CursorReply =
            idx.call("blockchain.dex.trade", "dex_cursor", json!({"evm_chain_number": self.chain.number})).await?;
        let mode = if nc.finality_mode == "tag" { Mode::Tag } else { Mode::Depth(nc.finality_depth) };
        let latest = self.chain.primary().get_block_number().await?;
        let finalized = if mode == Mode::Tag { self.chain.finalized_number().await? } else { None };
        let Some(safe) = safe_head(&mode, latest, finalized) else { return Ok(false) };
        let Some((from, to)) = next_range(cur.indexed_block, safe, MAX_LOG_SPAN) else { return Ok(false) };
        let Some(hash) = Chain::block_hash(self.chain.primary(), to).await else { return Ok(false) };
        let mut others = vec![];
        for p in self.chain.others() {
            others.push(Chain::block_hash(p, to).await);
        }
        if !quorum_ok(hash, &others, nc.finality_quorum) {
            return Ok(false);
        }
        let f = Filter::new().from_block(from).to_block(to).address(self.dex);
        let logs = self.chain.primary().get_logs(&f).await?;
        let events: Vec<Value> = logs.iter().filter_map(encode_event).collect();
        let _: Value = idx
            .call(
                "blockchain.dex.trade",
                "dex_fill_ingest",
                json!({"evm_chain_number": self.chain.number, "from_block": from, "to_block": to,
                       "to_block_hash": format!("{hash:#x}"), "events": events}),
            )
            .await?;
        // Odoo đã đánh dấu lệnh đóng; sổ trong bộ nhớ theo sau (review D13).
        let mut book = self.book.lock().await;
        for e in &events {
            match e["event"].as_str() {
                Some("OrderCancelled") => {
                    if let Ok(h) = e["order_hash"].as_str().unwrap_or_default().parse::<B256>() {
                        book.remove(h);
                    }
                }
                Some("NoncesInvalidated") => {
                    if let (Ok(m), Ok(n)) = (
                        e["maker"].as_str().unwrap_or_default().parse::<Address>(),
                        crate::metatx::uint(e["min_nonce"].as_str().unwrap_or_default()),
                    ) {
                        book.drop_below(m, n);
                    }
                }
                _ => {}
            }
        }
        Ok(true)
    }

    pub async fn run_loops(self: Arc<Self>, poll: Duration) {
        loop {
            if let Err(e) = self.sync_once().await {
                warn!(chain = self.chain.number, "dex sync: {e:#}");
            }
            loop {
                match self.watch_once().await {
                    Ok(true) => continue,
                    Ok(false) => break,
                    Err(e) => {
                        warn!(chain = self.chain.number, "dex watcher: {e:#}");
                        break;
                    }
                }
            }
            tokio::time::sleep(poll).await;
        }
    }

    // ------------------------------------------------------------------------------ reads

    pub async fn markets(&self) -> Vec<MarketCfg> {
        self.book.lock().await.markets().cloned().collect()
    }

    pub async fn depth(&self, market_id: i64, levels: usize) -> Option<Value> {
        let (bids, asks) = self.book.lock().await.depth(market_id, levels)?;
        Some(json!({"market_id": market_id, "bids": bids, "asks": asks}))
    }

    pub fn trades(&self, market_id: i64) -> Vec<TradeView> {
        self.trades
            .lock()
            .map(|t| t.iter().filter(|x| x.market_id == market_id).cloned().collect())
            .unwrap_or_default()
    }

    pub async fn ticker(&self, market_id: i64) -> Option<Value> {
        let (bids, asks) = self.book.lock().await.depth(market_id, 1)?;
        let trades = self.trades(market_id);
        let volume: U256 = trades.iter().filter_map(|t| t.base_amount.parse::<U256>().ok()).sum();
        Some(json!({
            "market_id": market_id,
            "best_bid": bids.first().map(|l| l.price.clone()),
            "best_ask": asks.first().map(|l| l.price.clone()),
            "last": trades.first().map(|t| t.price.clone()),
            "recent_base_volume": volume.to_string(),
        }))
    }

    pub async fn orders_of(&self, maker: Address) -> Vec<Value> {
        let book = self.book.lock().await;
        book.open_of(maker)
            .into_iter()
            .map(|r| {
                json!({"order_hash": format!("{:#x}", r.hash), "order": WireOrder::from_sol(&r.order),
                       "remaining": r.remaining.to_string(), "state": state_of(r)})
            })
            .collect()
    }

    /// Test/vận hành: hàng sổ hiện tại.
    pub async fn rows(&self) -> Vec<Row> {
        self.book.lock().await.rows()
    }
}

fn sig_bytes(s: &str) -> std::result::Result<Bytes, VenueError> {
    let b = hex_bytes(s).map_err(|_| bad("signature is not 0x-hex"))?;
    if b.len() < 64 || b.len() > 4096 {
        return Err(bad("signature length"));
    }
    Ok(b)
}

fn status_name(s: u8) -> &'static str {
    ["ok", "bad flags", "expired", "nonce invalidated", "bad signature", "closed", "market not listed", "bad fee"]
        .get(usize::from(s))
        .copied()
        .unwrap_or("unknown")
}

/// Thị trường Odoo khớp on-chain (niêm yết, cờ phí, ppm, người nhận phí).
async fn onchain_matches(chain: &Chain, dex: Address, m: &MarketCfg) -> Result<bool> {
    let (a, b) = pair(m.base, m.quote);
    let key_call = IOrderBookDex::marketKeyCall { a, b }.abi_encode();
    let tx = TransactionRequest::default().to(dex).input(key_call.into());
    let key = B256::from_slice(&chain.primary().call(tx).await?[..32]);
    let tx = TransactionRequest::default().to(dex).input(IOrderBookDex::marketsCall { key }.abi_encode().into());
    let out = chain.primary().call(tx).await?;
    let r = IOrderBookDex::marketsCall::abi_decode_returns(&out)?;
    let fees_ok = if r.feeOn {
        m.fee_on && r.makerFeePpm == m.maker_fee_ppm && r.takerFeePpm == m.taker_fee_ppm && r.feeRecipient == m.fee_recipient
    } else {
        !m.fee_on
    };
    Ok(r.listed && fees_ok)
}

/// Tên lỗi DEX đọc được (cho `MatchFailed.reason` ở Odoo); không nhận ra ⇒ bộ giải mã chung.
pub fn revert_name(data: &[u8]) -> String {
    match IOrderBookDex::IOrderBookDexErrors::abi_decode(data) {
        Ok(e) => format!("{e:?}"),
        Err(_) => crate::abi::decode_revert(data),
    }
}

/// Lệnh nghỉ còn settle được `remaining`: OK on-chain và đủ số dư/allowance kể cả phí relayer
/// (review I2/I3: thiếu 1 wei phí cũng làm mọi cặp với nó fail).
fn funded(o: &Order, remaining: U256, c: &IOrderBookDex::checkOrderReturn) -> bool {
    let (ft, fee) = relayer_fee(o, remaining);
    let own = if ft == o.sellToken { fee } else { U256::ZERO };
    c.status == ST_OK && c.fundable >= remaining + own && (ft == o.sellToken || c.feeFundable >= fee)
}

/// Log DEX ⇒ JSON đúng khoá `dex_fill_ingest` đọc. None = không phải event ta theo dõi / log pending.
pub fn encode_event(log: &Log) -> Option<Value> {
    let mut v = json!({
        "contract": format!("{:#x}", log.address()),
        "block_number": log.block_number?,
        "block_hash": format!("{:#x}", log.block_hash?),
        "tx_hash": format!("{:#x}", log.transaction_hash?),
        "log_index": log.log_index?,
    });
    let topic0 = *log.topic0()?;
    let a = |x: Address| format!("{x:#x}");
    if topic0 == IOrderBookDex::OrderFilled::SIGNATURE_HASH {
        let e = log.log_decode::<IOrderBookDex::OrderFilled>().ok()?.inner.data;
        let f = e.fill;
        v["event"] = json!("OrderFilled");
        v["tag"] = json!(format!("{:#x}", e.tag));
        v["order_hash"] = json!(format!("{:#x}", e.orderHash));
        v["owner"] = json!(a(e.owner));
        v["sell_token"] = json!(a(f.sellToken));
        v["sold"] = json!(f.sold.to_string());
        v["buy_token"] = json!(a(f.buyToken));
        v["received"] = json!(f.received.to_string());
        v["dex_fee"] = json!(f.dexFee.to_string());
        v["dex_fee_recipient"] = json!(a(f.dexFeeRecipient));
        v["relayer_fee_token"] = json!(a(f.relayerFeeToken));
        v["relayer_fee"] = json!(f.relayerFee.to_string());
        v["relayer_fee_recipient"] = json!(a(f.relayerFeeRecipient));
        v["filled_total"] = json!(f.filledTotal.to_string());
    } else if topic0 == IOrderBookDex::Matched::SIGNATURE_HASH {
        let e = log.log_decode::<IOrderBookDex::Matched>().ok()?.inner.data;
        v["event"] = json!("Matched");
        v["tag"] = json!(format!("{:#x}", e.tag));
        v["maker_hash"] = json!(format!("{:#x}", e.makerHash));
        v["taker_hash"] = json!(format!("{:#x}", e.takerHash));
    } else if topic0 == IOrderBookDex::MatchFailed::SIGNATURE_HASH {
        let e = log.log_decode::<IOrderBookDex::MatchFailed>().ok()?.inner.data;
        v["event"] = json!("MatchFailed");
        v["tag"] = json!(format!("{:#x}", e.tag));
        v["reason"] = json!(revert_name(&e.reason));
    } else if topic0 == IOrderBookDex::OrderCancelled::SIGNATURE_HASH {
        let e = log.log_decode::<IOrderBookDex::OrderCancelled>().ok()?.inner.data;
        v["event"] = json!("OrderCancelled");
        v["order_hash"] = json!(format!("{:#x}", e.orderHash));
        v["maker"] = json!(a(e.maker));
    } else if topic0 == IOrderBookDex::NoncesInvalidated::SIGNATURE_HASH {
        let e = log.log_decode::<IOrderBookDex::NoncesInvalidated>().ok()?.inner.data;
        v["event"] = json!("NoncesInvalidated");
        v["maker"] = json!(a(e.maker));
        v["min_nonce"] = json!(e.minNonce.to_string());
    } else {
        return None;
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::LogData;

    #[test]
    fn funded_counts_the_relayer_fee_in_either_token() {
        let c = |status, fundable: u64, fee: u64| IOrderBookDex::checkOrderReturn {
            h: B256::ZERO,
            status,
            remaining: U256::from(100),
            fundable: U256::from(fundable),
            feeFundable: U256::from(fee),
        };
        let mut o = Order {
            maker: Address::ZERO,
            taker: Address::ZERO,
            sellToken: Address::repeat_byte(1),
            buyToken: Address::repeat_byte(3),
            sellAmount: U256::from(100),
            buyAmount: U256::from(100),
            nonce: U256::ZERO,
            expiry: U256::ZERO,
            maxFeePpm: 0,
            flags: 0,
            relayer: Address::ZERO,
            feeMode: 0,
            fee: U256::ZERO,
            feeToken: Address::ZERO,
            feeRecipient: Address::ZERO,
        };
        o.feeMode = 2; // FIXED 5, paid in the sell token
        o.fee = U256::from(5);
        assert!(funded(&o, U256::from(100), &c(ST_OK, 105, 0)));
        assert!(!funded(&o, U256::from(100), &c(ST_OK, 104, 0)), "1 wei short of the fee");
        assert!(!funded(&o, U256::from(100), &c(ST_OK + 1, 1_000, 0)));
        o.feeToken = Address::repeat_byte(2); // separate fee token
        assert!(funded(&o, U256::from(100), &c(ST_OK, 100, 5)));
        assert!(!funded(&o, U256::from(100), &c(ST_OK, 100, 4)));
    }

    fn log_of(data: LogData) -> Log {
        Log {
            inner: alloy::primitives::Log { address: Address::repeat_byte(9), data },
            block_hash: Some(B256::repeat_byte(0xb)),
            block_number: Some(5),
            transaction_hash: Some(B256::repeat_byte(0xe)),
            log_index: Some(2),
            ..Default::default()
        }
    }

    #[test]
    fn order_filled_is_encoded_for_odoo() {
        let ev = IOrderBookDex::OrderFilled {
            tag: B256::repeat_byte(1),
            orderHash: B256::repeat_byte(2),
            owner: Address::repeat_byte(3),
            fill: super::super::Fill {
                sellToken: Address::repeat_byte(4),
                sold: U256::from(100),
                buyToken: Address::repeat_byte(5),
                received: U256::from(199),
                dexFee: U256::from(1),
                dexFeeRecipient: Address::repeat_byte(6),
                relayerFeeToken: Address::ZERO,
                relayerFee: U256::ZERO,
                relayerFeeRecipient: Address::ZERO,
                filledTotal: U256::from(100),
            },
        };
        let v = encode_event(&log_of(ev.encode_log_data())).unwrap();
        assert_eq!(v["event"], "OrderFilled");
        assert_eq!(v["received"], "199");
        assert_eq!(v["dex_fee"], "1");
        assert_eq!(v["owner"], format!("{:#x}", Address::repeat_byte(3)));
    }

    #[test]
    fn cancel_and_invalidate_are_encoded() {
        let ev = IOrderBookDex::OrderCancelled { orderHash: B256::repeat_byte(7), maker: Address::repeat_byte(8) };
        let v = encode_event(&log_of(ev.encode_log_data())).unwrap();
        assert_eq!(v["event"], "OrderCancelled");
        let ev = IOrderBookDex::NoncesInvalidated { maker: Address::repeat_byte(8), minNonce: U256::from(9) };
        let v = encode_event(&log_of(ev.encode_log_data())).unwrap();
        assert_eq!(v["min_nonce"], "9");
        let ev = IOrderBookDex::MatchFailed { tag: B256::ZERO, reason: Bytes::from_static(&[1, 2, 3]) };
        let v = encode_event(&log_of(ev.encode_log_data())).unwrap();
        assert!(v["reason"].as_str().unwrap().starts_with("revert 0x"));
    }

    #[test]
    fn cancel_rate_limit_is_per_maker_and_per_hour() {
        let mut q = CancelQueue::default();
        let m = Address::repeat_byte(1);
        for _ in 0..ONCHAIN_CANCELS_PER_HOUR {
            assert!(q.allow(m, 1000));
        }
        assert!(!q.allow(m, 1000));
        assert!(q.allow(Address::repeat_byte(2), 1000));
        assert!(q.allow(m, 1000 + 3600));
    }
}
