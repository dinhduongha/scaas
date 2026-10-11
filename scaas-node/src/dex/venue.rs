//! DEX venue: the I/O around `Book` (NODE-DEX-01, -15, -16). One venue per chain and DEX, the book's ONLY writer.
//!
//! - Persisted in the client over `/json/2` (RS5-2): every book change is ONE `dex_book_commit` (orders + trades +
//!   jobs); only success replaces the book in memory; a failure reloads the book from the client (review D20).
//! - Settlements go through the client outbox like every job: `mtxSettle` and the DEX-side cancels as `call` jobs to
//!   the DEX, the token-side cancels as `metatx` jobs naming their `entry` (job-api.md, order and wrap entries).
//! - Intake reads the order's state where it lives (NODE-DEX-15, dex.md §10): a SCaaS sell token keeps a
//!   `TradeOrder`'s fill state and cancels (`tradeOrderDigest`, `pulled`, `minNonce`, `balanceOf`), the DEX keeps an
//!   outside token's `DexOrder` (`dexOrderDigest`, `pulled`, `minNonce`, and `allowance(from, puller)`).
//! - The final-event watcher has its own cursor (RS5-8): a DEX failure never blocks payment finality.
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, Log, TransactionRequest};
use alloy::signers::Signature;
use alloy::sol_types::{SolCall, SolEvent};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tracing::{info, warn};

use super::{
    hex_bytes, hex_of, pair, Book, DexOrder, ISCaaSDex, MarketCfg, PlannedSettlement, Resting, Row,
    TradeOrder, WireOrder, FLAG_IOC, KIND_OUTSIDE, KIND_SCAAS,
};
use crate::abi::IToken;
use crate::chain::{classify, Chain, SimError};
use crate::finality::{next_range, quorum_ok, safe_head, Mode};
use crate::odoo::Odoo;
use crate::submit::now;

/// Rounds of "drop the maker at fault and match again" before giving up (NODE-DEX-02).
const MAX_ROUNDS: usize = 3;
const RECENT_TRADES: usize = 200;
/// On-chain cancels cost relayer gas: at most this many per signer per hour (review D14).
const ONCHAIN_CANCELS_PER_HOUR: usize = 20;
const CANCEL_BATCH: usize = 50;
const MAX_LOG_SPAN: u64 = 1000;
/// Cancels and invalidations never expire on chain; the job carrying one is given a day.
const CANCEL_JOB_SECS: u64 = 86_400;

/// Error for the client: `Bad` = 400 (the order's fault), `Unavailable` = 503 (RPC or client store).
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

/// One leg of a failed trade; `row` None = the order is closed in the client (cancelled/expired/invalid): never
/// handed back (review I3).
#[derive(Debug, Deserialize)]
struct FailedLeg {
    row: Option<Row>,
    fill: String,
}

#[derive(Debug, Deserialize)]
struct FailedTrade {
    tag: String,
    taker: FailedLeg,
    makers: Vec<FailedLeg>,
}

#[derive(Debug, Deserialize)]
struct SyncReply {
    failed: Vec<FailedTrade>,
}

#[derive(Debug, Deserialize)]
struct CursorReply {
    indexed_block: u64,
}

/// One book change, written to the client in ONE transaction (`dex_book_commit`).
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
            "market_id": market_id, "order_hash": row.order_hash, "sell_token": row.sell_token, "order": row.order,
            "signature": row.signature, "remaining": row.remaining, "seq": row.seq, "state": state,
        }));
    }
}

fn state_of(r: &Resting) -> &'static str {
    if r.remaining.is_zero() {
        "filled"
    } else if r.remaining < r.order.amount {
        "partial"
    } else {
        "open"
    }
}

/// An on-chain cancel waiting for the next sync: `(market, sell token, its kind, order, CancelOrder signature)`.
type PendingCancel = (i64, Address, u8, TradeOrder, Bytes);

#[derive(Default)]
struct CancelQueue {
    // ponytail: in memory — a node that dies before the flush has the order out of the book (the client records
    // `cancelled`) but not closed on chain; with RS5-9 only this relayer can settle it, so it is safe. Durable: keep
    // the cancel signature on the client's order row and flush from there.
    pending: Vec<PendingCancel>,
    recent: HashMap<Address, Vec<u64>>,
}

impl CancelQueue {
    /// May `from` cancel on chain once more this hour (and record it if so).
    fn allow(&mut self, from: Address, at: u64) -> bool {
        let v = self.recent.entry(from).or_default();
        v.retain(|t| at < t + 3600);
        if v.len() >= ONCHAIN_CANCELS_PER_HOUR {
            return false;
        }
        v.push(at);
        true
    }
}

/// An order's state on chain: what is left to fill and what the signer can still deliver.
struct OnChain {
    remaining: U256,
    fundable: U256,
}

pub struct Venue {
    pub chain: Arc<Chain>,
    relay: Odoo,
    indexer: Option<Odoo>,
    pub dex: Address,
    puller: Address,
    /// `tokenKind` per token, from the DEX's listing (never from the order or the client).
    kinds: HashMap<Address, u8>,
    book: Mutex<Book>,
    trades: std::sync::Mutex<VecDeque<TradeView>>,
    cancels: std::sync::Mutex<CancelQueue>,
}

impl Venue {
    /// Load the markets and the book from the client; serve only markets the DEX lists with both tokens classified.
    pub async fn start(chain: Arc<Chain>, relay: Odoo, indexer: Option<Odoo>, dex: Address) -> Result<Arc<Self>> {
        let n = chain.number;
        let mr: MarketsReply = relay
            .call("blockchain.dex.market", "dex_markets", json!({"evm_chain_number": n}))
            .await
            .context("dex_markets")?;
        if mr.dex != dex {
            bail!("chain {n}: client DEX {:#x} != node config {dex:#x}", mr.dex);
        }
        let puller = view(&chain, dex, ISCaaSDex::pullerCall {}).await.context("puller()")?;
        let mut markets = vec![];
        let mut kinds = HashMap::new();
        for m in mr.markets {
            match onchain_market(&chain, dex, &m).await {
                Ok(Some((kb, kq))) => {
                    kinds.insert(m.base, kb);
                    kinds.insert(m.quote, kq);
                    markets.push(m);
                }
                Ok(None) => warn!(chain = n, market = m.id, "market not listed on the DEX; not served"),
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
            chain,
            relay,
            indexer,
            dex,
            puller,
            kinds,
            book: Mutex::new(book),
            trades: Default::default(),
            cancels: Default::default(),
        }))
    }

    pub fn relayer(&self) -> Address {
        self.chain.address()
    }

    fn kind(&self, token: Address) -> u8 {
        self.kinds.get(&token).copied().unwrap_or_default()
    }

    // ------------------------------------------------------------------------------ chain reads

    async fn call(&self, from: Address, to: Address, data: Vec<u8>) -> std::result::Result<Bytes, SimError> {
        let tx = TransactionRequest::default().from(from).to(to).input(data.into());
        self.chain.primary().call(tx).await.map_err(|e| classify(&e))
    }

    /// The order's hash where it is checked: the sell token (`TradeOrder`) or the DEX (`DexOrder`).
    async fn order_hash(&self, sell: Address, o: &TradeOrder) -> Result<B256> {
        match self.kind(sell) {
            KIND_SCAAS => view(&self.chain, sell, IToken::tradeOrderDigestCall { o: o.clone() }).await,
            KIND_OUTSIDE => view(&self.chain, self.dex, ISCaaSDex::dexOrderDigestCall { sellToken: sell, o: o.clone() }).await,
            _ => bail!("TOKEN_NOT_SERVED: {sell:#x} is not a side of a listed market"),
        }
    }

    /// `amount − pulled` (0 when the lane's `minNonce` passed the order) and the signer's deliverable balance.
    async fn on_chain(&self, sell: Address, h: B256, o: &TradeOrder) -> Result<OnChain> {
        let outside = self.kind(sell) == KIND_OUTSIDE;
        let state = if outside { self.dex } else { sell };
        let (pulled, min) = if outside {
            (view(&self.chain, state, ISCaaSDex::pulledCall { orderHash: h }).await?,
             view(&self.chain, state, ISCaaSDex::minNonceCall { from: o.from, batch: o.batch }).await?)
        } else {
            (view(&self.chain, state, IToken::pulledCall { orderHash: h }).await?,
             view(&self.chain, state, IToken::minNonceCall { from: o.from, batch: o.batch }).await?)
        };
        let remaining = if o.nonce < min { U256::ZERO } else { o.amount.saturating_sub(pulled) };
        let mut fundable = view(&self.chain, sell, IToken::balanceOfCall { who: o.from }).await?;
        if outside {
            fundable = fundable.min(view(&self.chain, sell, IToken::allowanceCall { owner: o.from, spender: self.puller }).await?);
        }
        Ok(OnChain { remaining, fundable })
    }

    /// A resting order can still settle `r.remaining`: open on chain for that much, funded, signature valid.
    async fn healthy(&self, r: &Resting) -> Result<bool> {
        let c = self.on_chain(r.sell, r.hash, &r.order).await?;
        Ok(c.remaining >= r.remaining && c.fundable >= r.remaining && self.valid_sig(r.order.from, r.hash, &r.sig).await)
    }

    /// Simulate `mtxSettle` from the lane: `Ok(ok per settlement)`; all failed ⇒ `NothingSettled` ⇒ all `false`. A
    /// whole-call `SigCheckGasStarved` (CTR-DEX-08) is split and each settlement simulated alone, never retried whole
    /// with more gas: a party's hook-token destination can forge that selector (P2b-2 H5).
    async fn simulate(&self, ps: &[PlannedSettlement]) -> std::result::Result<Vec<bool>, SimError> {
        let s: Vec<_> = ps.iter().map(PlannedSettlement::to_settlement).collect();
        match self.call(self.relayer(), self.dex, ISCaaSDex::mtxSettleCall { s: s.clone() }.abi_encode()).await {
            Ok(out) => {
                ISCaaSDex::mtxSettleCall::abi_decode_returns(&out).map_err(|e| SimError::Revert(format!("decode: {e}")))
            }
            Err(SimError::Revert(r)) if r.starts_with("NothingSettled") => Ok(vec![false; ps.len()]),
            Err(SimError::Revert(r)) if r.starts_with("SigCheckGasStarved") && ps.len() > 1 => {
                let mut ok = vec![];
                for p in ps {
                    ok.push(Box::pin(self.simulate(std::slice::from_ref(p))).await?.first().copied().unwrap_or(false));
                }
                Ok(ok)
            }
            Err(SimError::Revert(r)) if r.starts_with("SigCheckGasStarved") => Ok(vec![false]),
            Err(e) => Err(e),
        }
    }

    /// The order a failed settlement blames: its revert data from `settleOne(s, lane)` called as the DEX names an
    /// order hash (token and DEX errors carry it, NODE-DEX-15); `None` when it names none of them.
    async fn fault(&self, p: &PlannedSettlement) -> Option<B256> {
        let data = ISCaaSDex::settleOneCall { s: p.to_settlement(), submitter: self.relayer() }.abi_encode();
        let tx = TransactionRequest::default().from(self.dex).to(self.dex).input(data.into());
        let err = self.chain.primary().call(tx).await.err()?;
        let raw = err.as_error_resp()?.as_revert_data()?;
        let hashes: Vec<B256> = p.makers.iter().map(|(m, _, _)| m.hash).chain([p.taker.hash]).collect();
        raw.get(4..)?.chunks_exact(32).map(B256::from_slice).find(|w| hashes.contains(w))
    }

    /// EOA signature (recovered here, low-s as the contract requires) or ERC-1271 (`isValidSignature`).
    async fn valid_sig(&self, signer: Address, digest: B256, sig: &Bytes) -> bool {
        if sig.len() == 65 {
            if let Ok(s) = Signature::try_from(sig.as_ref()) {
                // High-s: `ECDSA.tryRecover` refuses it (review I4). A contract wallet still goes the ERC-1271 way.
                if s.normalize_s().is_none() && s.recover_address_from_prehash(&digest).ok() == Some(signer) {
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

    /// `POST /v1/dex/orders {chain, sellToken, order, signature}`: the order is a `TradeOrder` for a SCaaS sell token
    /// and a `DexOrder` for an outside one, by the DEX's listing.
    pub async fn place(&self, sell: Address, wire: &WireOrder, signature: &str) -> std::result::Result<PlaceReply, VenueError> {
        let o = wire.to_sol().map_err(bad)?;
        let sig = sig_bytes(signature)?;
        if self.kind(sell) == 0 {
            return Err(bad(format!("TOKEN_NOT_SERVED: {sell:#x} is not a side of a listed market")));
        }
        let h = self.order_hash(sell, &o).await.map_err(down)?;
        if !self.valid_sig(o.from, h, &sig).await {
            return Err(bad("bad order signature"));
        }
        let c = self.on_chain(sell, h, &o).await.map_err(down)?;
        let mut book = self.book.lock().await;
        book.purge(now());
        book.admit(h, sell, &o, c.remaining, c.fundable, self.relayer(), self.dex, now()).map_err(bad)?;

        let mut commit = Commit::default();
        let mut dropped_makers: Vec<B256> = vec![];
        let (mut trial, mut placed);
        let mut round = 0;
        loop {
            trial = book.clone();
            for d in &dropped_makers {
                trial.remove(*d);
            }
            placed = trial.place(h, sell, o.clone(), sig.clone(), c.remaining);
            let Some(s) = &placed.settlement else { break };
            let ok = self.simulate(std::slice::from_ref(s)).await.map_err(|e| match e {
                SimError::Revert(r) => bad(format!("settlement simulation: {r}")),
                SimError::Transport(r) => down(format!("rpc: {r}")),
            })?;
            if ok.first() == Some(&true) {
                break;
            }
            // NODE-DEX-02: blame by evidence. An order hash in the revert names the order at fault; otherwise each
            // maker's state is read, and a maker that can no longer settle is the one dropped.
            let at_fault = match self.fault(s).await {
                Some(f) if f == h => return Err(bad("settlement simulation refused this order")),
                Some(f) => vec![f],
                None => {
                    let mut v = vec![];
                    for (m, _, _) in &s.makers {
                        if !self.healthy(m).await.map_err(down)? {
                            v.push(m.hash);
                        }
                    }
                    v
                }
            };
            if at_fault.is_empty() {
                return Err(bad("settlement simulation refused this order"));
            }
            for f in at_fault {
                if let Some((m, _, _)) = s.makers.iter().find(|(m, _, _)| m.hash == f) {
                    commit.order(s.market_id, m, "invalid");
                }
                dropped_makers.push(f);
            }
            round += 1;
            if round >= MAX_ROUNDS {
                return Err(down("order book unstable; retry"));
            }
        }

        let (market_id, base) =
            book.market_of(sell, o.receiveToken).map(|m| (m.id, m.base)).ok_or_else(|| bad("no market"))?;
        for d in &placed.dust {
            commit.order(market_id, &Resting { remaining: U256::ZERO, ..d.clone() }, "filled");
        }
        let settlement: Vec<PlannedSettlement> = placed.settlement.iter().cloned().collect();
        self.add_settlements(&mut commit, &trial, &settlement);
        let filled_here = placed.settlement.as_ref().map(|s| s.taker_fill).unwrap_or_default();
        let taker_after = Resting { hash: h, sell, order: o.clone(), sig: sig.clone(), remaining: c.remaining - filled_here, seq: placed.seq };
        let taker_state = match (&placed.rested, placed.dropped.is_zero()) {
            (Some(_), _) => state_of(&taker_after),
            (None, true) => "filled",
            (None, false) => "cancelled", // IOC, or a remainder that would rest crossed
        };
        commit.order(market_id, &taker_after, taker_state);
        self.commit_or_reload(&mut book, trial, commit).await?;
        drop(book);

        let fills: Vec<Value> = placed
            .settlement
            .iter()
            .flat_map(|s| s.makers.iter().map(move |(m, x, y)| {
                json!({"tag": format!("{:#x}", s.tag), "maker_hash": format!("{:#x}", m.hash),
                       "maker_fill": x.to_string(), "taker_fill": y.to_string()})
            }))
            .collect();
        self.remember(&settlement, base);
        let status = match (placed.rested.is_some(), placed.settlement.is_none(), placed.dropped.is_zero()) {
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

    /// The makers after matching, one trade per settlement, and one `mtxSettle` job per market.
    fn add_settlements(&self, commit: &mut Commit, after: &Book, ss: &[PlannedSettlement]) {
        for s in ss {
            for (m, _, _) in &s.makers {
                let now_m = after.get(m.hash).cloned().unwrap_or_else(|| Resting { remaining: U256::ZERO, ..m.clone() });
                commit.order(s.market_id, &now_m, state_of(&now_m));
            }
            commit.trades.push(json!({
                "tag": format!("{:#x}", s.tag), "market_id": s.market_id,
                "taker_hash": format!("{:#x}", s.taker.hash), "taker_fill": s.taker_fill.to_string(),
                "makers": s.makers.iter().map(|(m, x, _)| json!({"hash": format!("{:#x}", m.hash), "fill": x.to_string()}))
                    .collect::<Vec<_>>(),
            }));
        }
        commit.jobs.extend(settle_jobs(self.dex, ss));
    }

    async fn commit_or_reload(&self, book: &mut Book, next: Book, commit: Commit) -> std::result::Result<(), VenueError> {
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
                // A timeout may be "the client committed": never guess, reload the truth (review D20).
                warn!(chain = self.chain.number, "dex_book_commit: {e:#}; reloading the book from the client");
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

    fn remember(&self, ss: &[PlannedSettlement], base: Address) {
        let Ok(mut t) = self.trades.lock() else { return };
        for s in ss {
            t.push_front(trade_view(s, base, now()));
            t.truncate(RECENT_TRADES);
        }
    }

    // ------------------------------------------------------------------------------ cancel

    /// Cancel one order with a `CancelOrder(orderHash)` signature (the sell token's domain, or the DEX's for an
    /// outside token): out of the book NOW, then closed on chain at the next sync.
    pub async fn cancel(&self, h: B256, signature: &str) -> std::result::Result<(), VenueError> {
        let sig = sig_bytes(signature)?;
        let mut book = self.book.lock().await;
        let r = book.get(h).cloned().ok_or_else(|| bad("order is not in the book"))?;
        let kind = self.kind(r.sell);
        let digest = match kind {
            KIND_SCAAS => view(&self.chain, r.sell, IToken::cancelOrderDigestCall { orderHash: h }).await,
            _ => view(&self.chain, self.dex, ISCaaSDex::cancelOrderDigestCall { orderHash: h }).await,
        }
        .map_err(down)?;
        if !self.valid_sig(r.order.from, digest, &sig).await {
            return Err(bad("bad cancel signature"));
        }
        let market_id = book.market_of(r.sell, r.order.receiveToken).map(|m| m.id).unwrap_or_default();
        let mut next = book.clone();
        next.remove(h);
        let mut commit = Commit::default();
        commit.order(market_id, &r, "cancelled");
        self.commit_or_reload(&mut book, next, commit).await?;
        if let Ok(mut q) = self.cancels.lock() {
            if q.allow(r.order.from, now()) {
                q.pending.push((market_id, r.sell, kind, r.order, sig));
            }
        }
        Ok(())
    }

    /// Cancel-all of a lane: `InvalidateNonces(from, batch, minNonce)` in the sell token's domain (its SCaaS orders)
    /// or the DEX's (every outside-token order). Only while the signer has an open order there (gas spam).
    pub async fn cancel_all(&self, sell: Address, from: Address, batch: U256, min: U256, signature: &str)
        -> std::result::Result<usize, VenueError>
    {
        let sig = sig_bytes(signature)?;
        let kind = self.kind(sell);
        let outside = kind == KIND_OUTSIDE;
        let in_scope = |s: Address| if outside { self.kind(s) == KIND_OUTSIDE } else { s == sell };
        let mut book = self.book.lock().await;
        let open: Vec<Resting> = book.open_of(from).into_iter().filter(|r| r.order.batch == batch && in_scope(r.sell)).cloned().collect();
        let Some(first) = open.first() else { return Err(bad("no open order of this signer on that lane")) };
        let market_id = book.market_of(first.sell, first.order.receiveToken).map(|m| m.id).unwrap_or_default();
        let (target, digest, call) = if outside {
            (self.dex, view(&self.chain, self.dex, ISCaaSDex::invalidateNoncesDigestCall { from, batch, newMin: min }).await,
             ISCaaSDex::mtxInvalidateNoncesCall { from, batch, newMin: min, sig: sig.clone() }.abi_encode())
        } else {
            (sell, view(&self.chain, sell, IToken::invalidateNoncesDigestCall { from, batch, newMin: min }).await,
             IToken::mtxInvalidateNoncesCall { from, batch, newMin: min, sig: sig.clone() }.abi_encode())
        };
        if !self.valid_sig(from, digest.map_err(down)?, &sig).await {
            return Err(bad("bad invalidate signature"));
        }
        // already at or past `min` on chain (MinNonceNotIncreasing): the orders are closed, no job needed
        let job_needed = match self.call(self.relayer(), target, call.clone()).await {
            Ok(_) => true,
            Err(SimError::Revert(r)) if r.starts_with("MinNonceNotIncreasing(") => false,
            Err(e) => return Err(bad(format!("mtxInvalidateNonces refused: {e}"))),
        };
        let mut next = book.clone();
        let gone = next.drop_below(from, batch, min, &in_scope);
        let mut commit = Commit::default();
        for r in &gone {
            commit.order(book.market_of(r.sell, r.order.receiveToken).map(|m| m.id).unwrap_or_default(), r, "cancelled");
        }
        let allowed = self.cancels.lock().map(|mut q| q.allow(from, now())).unwrap_or(false);
        if job_needed && allowed {
            let valid_until = (now() + CANCEL_JOB_SECS).to_string();
            commit.jobs.push(if outside {
                json!({"kind": "invalidate", "market_id": market_id, "target": format!("{:#x}", self.dex),
                       "calldata": hex_of(&call), "valid_until": valid_until, "tags": []})
            } else {
                json!({"kind": "metatx", "entry": "mtxInvalidateNonces", "market_id": market_id,
                       "token": format!("{sell:#x}"), "from": format!("{from:#x}"), "batch": batch.to_string(),
                       "newMin": min.to_string(), "signature": hex_of(&sig), "validUntil": valid_until})
            });
        }
        self.commit_or_reload(&mut book, next, commit).await?;
        Ok(gone.len())
    }

    // ------------------------------------------------------------------------------ loops

    /// Failed trades back to the book; pending cancels to the chain; expired orders out of memory.
    pub async fn sync_once(&self) -> Result<()> {
        let sr: SyncReply =
            self.relay.call("blockchain.dex.trade", "dex_sync", json!({"evm_chain_number": self.chain.number})).await?;
        let mut book = self.book.lock().await;
        book.purge(now());
        let mut commit = Commit::default();
        // Match again; a settlement that does not simulate leaves its orders out of this round (still acked): one bad
        // order never jams the chain (review I3). ponytail: drops the healthy legs of a bad settlement too; split
        // per leg if that ever costs real fills.
        let mut skip: Vec<B256> = vec![];
        let (mut next, mut settlements, mut touched);
        let (mut round, mut give_up) = (0, false);
        loop {
            next = book.clone();
            settlements = Vec::<PlannedSettlement>::new();
            touched = Vec::<(i64, Resting)>::new();
            for ft in &sr.failed {
                // makers first: each goes back as it rested, then the taker takes again in its original role
                for leg in ft.makers.iter().chain(std::iter::once(&ft.taker)) {
                    let Some(row) = &leg.row else { continue };
                    let r = row.resting()?;
                    let fill = crate::metatx::uint(&leg.fill)?;
                    if give_up || skip.contains(&r.hash) || r.order.flags & FLAG_IOC != 0 || r.order.validUntil < U256::from(now()) {
                        continue;
                    }
                    let Some(market_id) = next.market_of(r.sell, r.order.receiveToken).map(|m| m.id) else { continue };
                    let in_book = next.get(r.hash).map(|x| x.remaining).unwrap_or_default();
                    let c = self.on_chain(r.sell, r.hash, &r.order).await?;
                    let add = fill.min(c.remaining.saturating_sub(in_book));
                    if add.is_zero() || c.fundable < in_book + add {
                        continue;
                    }
                    // Through the matcher: two healthy sides trade again, never a crossed book.
                    settlements.extend(next.restore(r.clone(), add).settlement);
                    touched.push((market_id, r));
                }
            }
            if settlements.is_empty() {
                break;
            }
            let ok = self.simulate(&settlements).await.map_err(|e| anyhow!("re-match simulation: {e}"))?;
            let failed: Vec<B256> = settlements
                .iter()
                .zip(&ok)
                .filter(|(_, ok)| !**ok)
                .flat_map(|(s, _)| s.makers.iter().map(|(m, _, _)| m.hash).chain([s.taker.hash]))
                .collect();
            if failed.is_empty() {
                break;
            }
            warn!(chain = self.chain.number, n = failed.len(), "re-matched settlements do not simulate; not restoring them");
            skip.extend(failed);
            round += 1;
            give_up = round >= MAX_ROUNDS; // the last round hands nothing back: ack, never jam
        }
        commit.acks.extend(sr.failed.iter().map(|ft| ft.tag.clone()));
        self.add_settlements(&mut commit, &next, &settlements);
        // Every order handed back (re-matched or not) is written to the client, or a restart loses it.
        for (market_id, r) in &touched {
            let now_r = next.get(r.hash).cloned().unwrap_or_else(|| Resting { remaining: U256::ZERO, ..r.clone() });
            commit.order(*market_id, &now_r, state_of(&now_r));
        }
        let pending: Vec<PendingCancel> = self.cancels.lock().map(|mut q| std::mem::take(&mut q.pending)).unwrap_or_default();
        commit.jobs.extend(cancel_jobs(self.dex, &pending));
        let res = self.commit_or_reload(&mut book, next, commit).await;
        if res.is_err() && !pending.is_empty() {
            // Never lose an on-chain cancel when the client store fails; a duplicate is a no-op on chain.
            if let Ok(mut q) = self.cancels.lock() {
                q.pending.extend(pending);
            }
        }
        res.map_err(|e| anyhow!("{e}"))
    }

    /// One watcher round: the DEX's and the market tokens' logs in the final range ⇒ `dex_fill_ingest` ⇒ orders
    /// closed on chain leave the book. `true` = progressed.
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
        let mut contracts: Vec<Address> = self.kinds.keys().copied().collect();
        contracts.push(self.dex);
        let f = Filter::new().from_block(from).to_block(to).address(contracts).event_signature(vec![
            ISCaaSDex::LegSettled::SIGNATURE_HASH,
            ISCaaSDex::MatchFailed::SIGNATURE_HASH,
            ISCaaSDex::OrderCancelled::SIGNATURE_HASH,
            ISCaaSDex::NoncesInvalidated::SIGNATURE_HASH,
        ]);
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
        // The client closed the orders; the book in memory follows (review D13).
        let mut book = self.book.lock().await;
        for e in &events {
            let addr_of = |k: &str| e[k].as_str().unwrap_or_default().parse::<Address>();
            match e["event"].as_str() {
                Some("OrderCancelled") => {
                    if let Ok(h) = e["order_hash"].as_str().unwrap_or_default().parse::<B256>() {
                        book.remove(h);
                    }
                }
                Some("NoncesInvalidated") => {
                    if let (Ok(c), Ok(from), Ok(batch), Ok(min)) = (
                        addr_of("contract"),
                        addr_of("from"),
                        crate::metatx::uint(e["batch"].as_str().unwrap_or_default()),
                        crate::metatx::uint(e["min_nonce"].as_str().unwrap_or_default()),
                    ) {
                        let dex_lane = c == self.dex;
                        book.drop_below(from, batch, min, &|s| if dex_lane { self.kind(s) == KIND_OUTSIDE } else { s == c });
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

    pub async fn orders_of(&self, from: Address) -> Vec<Value> {
        let book = self.book.lock().await;
        book.open_of(from)
            .into_iter()
            .map(|r| {
                json!({"order_hash": format!("{:#x}", r.hash), "sell_token": format!("{:#x}", r.sell),
                       "order": WireOrder::from_sol(&r.order), "remaining": r.remaining.to_string(), "state": state_of(r)})
            })
            .collect()
    }

    /// Tests and operations: the book's rows now.
    pub async fn rows(&self) -> Vec<Row> {
        self.book.lock().await.rows()
    }
}

async fn view<C: SolCall>(chain: &Chain, to: Address, call: C) -> Result<C::Return> {
    let tx = TransactionRequest::default().to(to).input(call.abi_encode().into());
    Ok(C::abi_decode_returns(&chain.primary().call(tx).await?)?)
}

/// The market as the DEX lists it: `Some((kind of base, kind of quote))` when listed and both classified.
async fn onchain_market(chain: &Chain, dex: Address, m: &MarketCfg) -> Result<Option<(u8, u8)>> {
    let (a, b) = pair(m.base, m.quote);
    if !view(chain, dex, ISCaaSDex::marketListedCall { a, b }).await? {
        return Ok(None);
    }
    let kb = view(chain, dex, ISCaaSDex::tokenKindCall { token: m.base }).await?;
    let kq = view(chain, dex, ISCaaSDex::tokenKindCall { token: m.quote }).await?;
    Ok((kb != 0 && kq != 0).then_some((kb, kq)))
}

/// One line on the tape: quote/base price, base amount, the taker's side. The side is read from the market's base:
/// the makers sell exactly what the taker buys.
fn trade_view(s: &PlannedSettlement, base: Address, at: u64) -> TradeView {
    let taker_buys_base = s.taker.order.receiveToken == base;
    let (quote, base_amt) =
        if taker_buys_base { (s.taker_fill, s.taker_receives()) } else { (s.taker_receives(), s.taker_fill) };
    TradeView {
        market_id: s.market_id,
        tag: format!("{:#x}", s.tag),
        price: format!("{quote}/{base_amt}"),
        base_amount: base_amt.to_string(),
        taker_side: if taker_buys_base { "buy" } else { "sell" },
        at,
    }
}

/// By market id, keeping the order inside each market (stable sort).
fn by_market<T: Clone>(items: &[T], market: impl Fn(&T) -> i64) -> Vec<Vec<T>> {
    let mut v = items.to_vec();
    v.sort_by_key(&market);
    v.chunk_by(|a, b| market(a) == market(b)).map(<[T]>::to_vec).collect()
}

/// One `mtxSettle` job per market: the client attaches a job to its market's company (review agy F3).
fn settle_jobs(dex: Address, ss: &[PlannedSettlement]) -> Vec<Value> {
    by_market(ss, |s| s.market_id)
        .into_iter()
        .map(|ss| {
            let s = ss.iter().map(PlannedSettlement::to_settlement).collect();
            let valid_until = ss.iter().map(PlannedSettlement::valid_until).min().unwrap_or_default();
            json!({
                "kind": "settle", "market_id": ss[0].market_id, "target": format!("{dex:#x}"),
                "calldata": hex_of(&ISCaaSDex::mtxSettleCall { s }.abi_encode()),
                "valid_until": valid_until.to_string(),
                "tags": ss.iter().map(|s| format!("{:#x}", s.tag)).collect::<Vec<_>>(),
            })
        })
        .collect()
}

/// SCaaS-token orders: one `mtxCancelOrder` entry job each, on the sell token. Outside-token orders: one
/// `mtxCancelOrders` call on the DEX per market, at most `CANCEL_BATCH` orders.
fn cancel_jobs(dex: Address, pending: &[PendingCancel]) -> Vec<Value> {
    let valid_until = (now() + CANCEL_JOB_SECS).to_string();
    let mut jobs: Vec<Value> = pending
        .iter()
        .filter(|p| p.2 == KIND_SCAAS)
        .map(|(m, sell, _, o, sig)| {
            json!({"kind": "metatx", "entry": "mtxCancelOrder", "market_id": m, "token": format!("{sell:#x}"),
                   "order": WireOrder::from_sol(o), "signature": hex_of(sig), "validUntil": valid_until})
        })
        .collect();
    let outside: Vec<PendingCancel> = pending.iter().filter(|p| p.2 != KIND_SCAAS).cloned().collect();
    for m in by_market(&outside, |p| p.0) {
        for chunk in m.chunks(CANCEL_BATCH) {
            let orders = chunk.iter().map(|(_, s, _, o, _)| DexOrder { sellToken: *s, order: o.clone() }).collect();
            let sigs = chunk.iter().map(|p| p.4.clone()).collect();
            jobs.push(json!({
                "kind": "cancel", "market_id": chunk[0].0, "target": format!("{dex:#x}"),
                "calldata": hex_of(&ISCaaSDex::mtxCancelOrdersCall { orders, sigs }.abi_encode()),
                "valid_until": valid_until, "tags": [],
            }));
        }
    }
    jobs
}

fn sig_bytes(s: &str) -> std::result::Result<Bytes, VenueError> {
    let b = hex_bytes(s).map_err(|_| bad("signature is not 0x-hex"))?;
    if b.len() < 64 || b.len() > 4096 {
        return Err(bad("signature length"));
    }
    Ok(b)
}

/// Readable DEX error (for `MatchFailed.reason` in the client); an EMPTY reason is the settlement's self-call
/// running out of gas, never an order's fault (P2b-2: success is not monotonic in gas).
pub fn revert_name(data: &[u8]) -> String {
    if data.is_empty() {
        return "out_of_gas".into();
    }
    crate::abi::decode_revert(data)
}

/// A DEX or token log ⇒ JSON with the keys `dex_fill_ingest` reads. None = not ours, or a pending log.
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
    if topic0 == ISCaaSDex::LegSettled::SIGNATURE_HASH {
        let e = log.log_decode::<ISCaaSDex::LegSettled>().ok()?.inner.data;
        v["event"] = json!("LegSettled");
        v["tag"] = json!(format!("{:#x}", e.r#ref));
        v["order_hash"] = json!(format!("{:#x}", e.orderHash));
        v["from"] = json!(a(e.from));
        v["destination"] = json!(a(e.destination));
        v["sold"] = json!(e.sold.to_string());
        v["received"] = json!(e.received.to_string());
        v["dex_fee"] = json!(e.dexFee.to_string());
        v["refund"] = json!(e.refund.to_string());
        v["relayer_share"] = json!(e.relayerShare.to_string());
        v["treasury_share"] = json!(e.treasuryShare.to_string());
    } else if topic0 == ISCaaSDex::MatchFailed::SIGNATURE_HASH {
        let e = log.log_decode::<ISCaaSDex::MatchFailed>().ok()?.inner.data;
        v["event"] = json!("MatchFailed");
        v["tag"] = json!(format!("{:#x}", e.r#ref));
        v["reason"] = json!(revert_name(&e.reason));
    } else if topic0 == ISCaaSDex::OrderCancelled::SIGNATURE_HASH {
        let e = log.log_decode::<ISCaaSDex::OrderCancelled>().ok()?.inner.data;
        v["event"] = json!("OrderCancelled");
        v["order_hash"] = json!(format!("{:#x}", e.orderHash));
        v["from"] = json!(a(e.from));
    } else if topic0 == ISCaaSDex::NoncesInvalidated::SIGNATURE_HASH {
        let e = log.log_decode::<ISCaaSDex::NoncesInvalidated>().ok()?.inner.data;
        v["event"] = json!("NoncesInvalidated");
        v["from"] = json!(a(e.from));
        v["batch"] = json!(e.batch.to_string());
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
    use alloy::sol_types::SolError;

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
    fn leg_settled_is_encoded_for_the_client() {
        let ev = ISCaaSDex::LegSettled {
            r#ref: B256::repeat_byte(1),
            orderHash: B256::repeat_byte(2),
            from: Address::repeat_byte(3),
            destination: Address::repeat_byte(4),
            sold: U256::from(100),
            received: U256::from(199),
            dexFee: U256::from(1),
            refund: U256::ZERO,
            relayerShare: U256::ZERO,
            treasuryShare: U256::from(1),
        };
        let v = encode_event(&log_of(ev.encode_log_data())).unwrap();
        assert_eq!((v["event"].as_str(), v["received"].as_str(), v["dex_fee"].as_str()), (Some("LegSettled"), Some("199"), Some("1")));
        assert_eq!(v["tag"], format!("{:#x}", B256::repeat_byte(1)));
        assert_eq!(v["from"], format!("{:#x}", Address::repeat_byte(3)));
    }

    #[test]
    fn cancels_invalidations_and_failures_are_encoded() {
        let ev = ISCaaSDex::OrderCancelled { orderHash: B256::repeat_byte(7), from: Address::repeat_byte(8) };
        assert_eq!(encode_event(&log_of(ev.encode_log_data())).unwrap()["event"], "OrderCancelled");
        let ev = ISCaaSDex::NoncesInvalidated { from: Address::repeat_byte(8), batch: U256::from(2), minNonce: U256::from(9) };
        let v = encode_event(&log_of(ev.encode_log_data())).unwrap();
        assert_eq!((v["batch"].as_str(), v["min_nonce"].as_str()), (Some("2"), Some("9")));
        let ev = ISCaaSDex::MatchFailed { r#ref: B256::ZERO, reason: Bytes::from_static(&[1, 2, 3]) };
        assert!(encode_event(&log_of(ev.encode_log_data())).unwrap()["reason"].as_str().unwrap().starts_with("revert 0x"));
        // P2b-2: an empty reason is out of gas inside the settlement, never an order's fault
        let ev = ISCaaSDex::MatchFailed { r#ref: B256::ZERO, reason: Bytes::new() };
        assert_eq!(encode_event(&log_of(ev.encode_log_data())).unwrap()["reason"], "out_of_gas");
        let reason = IToken::BelowMinFill { orderHash: B256::repeat_byte(5) }.abi_encode();
        assert!(revert_name(&reason).starts_with("BelowMinFill"));
    }

    #[test]
    fn cancel_rate_limit_is_per_signer_and_per_hour() {
        let mut q = CancelQueue::default();
        let m = Address::repeat_byte(1);
        for _ in 0..ONCHAIN_CANCELS_PER_HOUR {
            assert!(q.allow(m, 1000));
        }
        assert!(!q.allow(m, 1000));
        assert!(q.allow(Address::repeat_byte(2), 1000));
        assert!(q.allow(m, 1000 + 3600));
    }

    const BASE: Address = Address::repeat_byte(0xaa);
    const QUOTE: Address = Address::repeat_byte(0xbb);

    fn rest(from: u8, sell: Address, receive: Address) -> Resting {
        let order = TradeOrder {
            from: Address::repeat_byte(from),
            receiveToken: receive,
            amount: U256::from(1000),
            receiveAmount: U256::from(1000),
            minFill: U256::ZERO,
            fee: U256::ZERO,
            relayer: Address::ZERO,
            dex: Address::ZERO,
            destination: Address::ZERO,
            flags: 0,
            batch: U256::ZERO,
            nonce: U256::ZERO,
            validUntil: U256::from(from),
        };
        Resting { hash: B256::repeat_byte(from), sell, order, sig: Bytes::new(), remaining: U256::from(1000), seq: 0 }
    }

    fn settlement(market_id: i64, tag: u8, maker: Resting, taker: Resting, x: u64, y: u64) -> PlannedSettlement {
        PlannedSettlement { tag: B256::repeat_byte(tag), market_id, taker, taker_fill: U256::from(y),
                            makers: vec![(maker, U256::from(x), U256::from(y))] }
    }

    #[test]
    fn trade_tape_reads_side_and_price_from_the_market_base() {
        // the taker buys base: the maker sells 10 base for 20 quote ⇒ 20/10, base 10, "buy"
        let buy = settlement(1, 1, rest(1, BASE, QUOTE), rest(2, QUOTE, BASE), 10, 20);
        let t = trade_view(&buy, BASE, 7);
        assert_eq!((t.price.as_str(), t.base_amount.as_str(), t.taker_side), ("20/10", "10", "buy"));
        // the taker sells base: the maker (a bid) sells 20 quote, the taker gives 10 base ⇒ same price, "sell"
        let sell = settlement(1, 2, rest(1, QUOTE, BASE), rest(2, BASE, QUOTE), 20, 10);
        let t = trade_view(&sell, BASE, 7);
        assert_eq!((t.price.as_str(), t.base_amount.as_str(), t.taker_side), ("20/10", "10", "sell"));
    }

    #[test]
    fn settle_jobs_are_one_per_market_and_cancels_go_where_the_order_lives() {
        let dex = Address::repeat_byte(0xd);
        let ss = [
            settlement(1, 1, rest(1, BASE, QUOTE), rest(2, QUOTE, BASE), 10, 20),
            settlement(2, 2, rest(3, BASE, QUOTE), rest(4, QUOTE, BASE), 10, 20),
            settlement(1, 3, rest(5, BASE, QUOTE), rest(6, QUOTE, BASE), 10, 20),
        ];
        let jobs = settle_jobs(dex, &ss);
        let seen: Vec<(i64, usize)> =
            jobs.iter().map(|j| (j["market_id"].as_i64().unwrap(), j["tags"].as_array().unwrap().len())).collect();
        assert_eq!(seen, vec![(1, 2), (2, 1)]);
        assert_eq!(jobs[0]["valid_until"], "1", "the earliest leg's deadline");
        let c = |m: i64, from: u8, kind: u8| (m, BASE, kind, rest(from, BASE, QUOTE).order, Bytes::from_static(&[1]));
        let jobs = cancel_jobs(dex, &[c(1, 1, KIND_SCAAS), c(2, 2, KIND_OUTSIDE), c(1, 3, KIND_OUTSIDE)]);
        let kinds: Vec<(&str, i64)> = jobs.iter().map(|j| (j["kind"].as_str().unwrap(), j["market_id"].as_i64().unwrap())).collect();
        assert_eq!(kinds, vec![("metatx", 1), ("cancel", 1), ("cancel", 2)]);
        assert_eq!((jobs[0]["entry"].as_str(), jobs[0]["token"].as_str()), (Some("mtxCancelOrder"), Some(&*format!("{BASE:#x}"))));
        assert_eq!(jobs[1]["target"], format!("{dex:#x}"));
    }
}
