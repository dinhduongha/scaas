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

use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
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
    hex_bytes, hex_of, pair, Book, DexOrder, ISCaaSDex, MarketCfg, Placement, PlannedSettlement, Resting, Row,
    TradeOrder, WireOrder, FLAG_IOC, KIND_OUTSIDE, KIND_SCAAS,
};
use crate::abi::{IToken, TradeFill};
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
/// `SigCheck.ERC1271_GAS` and `SCaaSDex.SMART_KEY_1271_GAS` (CTR-DEX-08, CTR-ACC-05).
const ERC1271_GAS: u64 = 50_000;
const SMART_KEY_1271_GAS: u64 = 400_000;
const MAGIC_1271: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];
const PPM: u64 = 1_000_000;

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
    /// EIP-1167 runtime codehash of this chain's `SmartKeyAccount` clones (the DEX's `SMART_KEY_ACCOUNT_IMPL`): the one
    /// ERC-1271 signer given 400 k gas (CTR-DEX-08). `None` = no implementation on this chain.
    clone_codehash: Option<B256>,
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
        let ska = view(&chain, dex, ISCaaSDex::SMART_KEY_ACCOUNT_IMPLCall {}).await.context("SMART_KEY_ACCOUNT_IMPL()")?;
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
        let me = Arc::new(Self {
            chain,
            relay,
            indexer,
            dex,
            puller,
            kinds,
            clone_codehash: clone_codehash(ska),
            book: Mutex::new(book),
            trades: Default::default(),
            cancels: Default::default(),
        });
        me.load_pending(&mut *me.book.lock().await).await.context("pending fills")?;
        Ok(me)
    }

    /// The unmined part of each partly filled order, from the chain: `amount − pulled` there minus the book's
    /// `remaining` (review T3 I1). After a restart or reload an unmined remainder is still never planned as closing.
    async fn load_pending(&self, book: &mut Book) -> Result<()> {
        let partial: Vec<Resting> = book.all().filter(|r| r.remaining < r.order.amount).cloned().collect();
        for r in partial {
            let c = self.on_chain(r.sell, r.hash, &r.order).await?;
            let p = c.remaining.saturating_sub(r.remaining);
            if !p.is_zero() {
                book.pending.insert(r.hash, p);
            }
        }
        Ok(())
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

    /// Where an order of `sell` is checked: the SCaaS sell token itself, or the DEX for an outside token.
    fn verifier(&self, sell: Address) -> Address {
        if self.kind(sell) == KIND_OUTSIDE { self.dex } else { sell }
    }

    /// A resting order can still settle `r.remaining`: open on chain for that much, funded, signature valid.
    async fn healthy(&self, r: &Resting) -> Result<bool> {
        let c = self.on_chain(r.sell, r.hash, &r.order).await?;
        Ok(c.remaining >= r.remaining
            && c.fundable >= r.remaining
            && self.valid_sig(self.verifier(r.sell), r.order.from, r.hash, &r.sig).await?)
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

    /// Every order a failed settlement names: the order hashes in the revert data of `settleOne(s, lane)` called as
    /// the DEX (token and DEX errors carry one, NODE-DEX-15); empty when it names none of them.
    async fn fault(&self, p: &PlannedSettlement) -> Vec<B256> {
        let data = ISCaaSDex::settleOneCall { s: p.to_settlement(), submitter: self.relayer() }.abi_encode();
        let tx = TransactionRequest::default().from(self.dex).to(self.dex).input(data.into());
        let Err(err) = self.chain.primary().call(tx).await else { return vec![] };
        let Some(raw) = err.as_error_resp().and_then(|r| r.as_revert_data()) else { return vec![] };
        let legs: Vec<B256> = p.makers.iter().map(|(m, _, _)| m.hash).chain([p.taker.hash]).collect();
        let mut named: Vec<B256> = vec![];
        for w in raw.get(4..).unwrap_or_default().chunks_exact(32).map(B256::from_slice) {
            if legs.contains(&w) && !named.contains(&w) {
                named.push(w);
            }
        }
        named
    }

    /// Evidence when a failed settlement names no order (a SCaaS token reports a bad signature as
    /// `MetaTxBadSignature()`, no hash): each SCaaS leg's own `mtxTrade(o, sig, fill)`, called alone as the DEX calls it.
    /// A leg whose own pull reverts is at fault. Outside legs name their hash themselves (`BadSignature(h)`, `TradeLib`).
    /// Review T3 C1, N8: no leg is blamed without this evidence.
    async fn leg_faults(&self, p: &PlannedSettlement) -> std::result::Result<Vec<B256>, VenueError> {
        let fee = |recv: U256, o: &TradeOrder| (recv * o.fee + U256::from(PPM - 1)) / U256::from(PPM);
        let legs = p.makers.iter().map(|(m, x, y)| (m, *x, *y)).chain([(&p.taker, p.taker_fill, p.taker_receives())]);
        let mut out = vec![];
        for (r, sold, recv) in legs {
            if self.kind(r.sell) != KIND_SCAAS {
                continue;
            }
            let f = TradeFill { sellFill: sold, receiveFill: recv, dexFee: fee(recv, &r.order), submitter: self.relayer() };
            let data = IToken::mtxTradeCall { o: r.order.clone(), sig: r.sig.clone(), f }.abi_encode();
            match self.call(self.dex, r.sell, data).await {
                Ok(_) => {}
                Err(SimError::Revert(_)) => out.push(r.hash),
                Err(SimError::Transport(e)) => return Err(down(format!("rpc: {e}"))),
            }
        }
        Ok(out)
    }

    /// `SigCheck.isValid` exactly as `verifier` (the order's token, or the DEX) runs it (CTR-MTX-25, review T3 C1): no
    /// code or an EIP-7702 designator ⇒ ECDSA only; a contract ⇒ ERC-1271 called from `verifier` with the cap by
    /// codehash as the callee's gas, accepted only as exactly 32 bytes equal to the magic word. `Err` = the RPC, never
    /// a verdict.
    async fn valid_sig(&self, verifier: Address, signer: Address, digest: B256, sig: &Bytes) -> Result<bool> {
        let code = self.chain.primary().get_code_at(signer).await?;
        if !is_contract(&code) {
            return Ok(ecdsa_ok(signer, digest, sig));
        }
        alloy::sol! {
            function isValidSignature(bytes32 hash, bytes signature) external view returns (bytes4);
        }
        let data = isValidSignatureCall { hash: digest, signature: sig.clone() }.abi_encode();
        // the callee of a top-level call gets `gas − intrinsic`: exactly the cap `staticcall` gives it
        let gas = sig_cap(&code, self.clone_codehash) + intrinsic(&data);
        let tx = TransactionRequest::default().from(verifier).to(signer).input(data.into()).gas_limit(gas);
        match self.chain.primary().call(tx).await {
            Ok(out) => Ok(magic_ok(&out)),
            // the EVM's answer (a revert, out of gas inside the cap) is `false`, as a failed `staticcall` is
            Err(e) if e.as_error_resp().is_some_and(|r| {
                let m = r.message.to_ascii_lowercase();
                r.as_revert_data().is_some() || m.contains("revert") || m.contains("execution") || m.contains("gas")
            }) => Ok(false),
            Err(e) => Err(e.into()),
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
        if !self.valid_sig(self.verifier(sell), o.from, h, &sig).await.map_err(down)? {
            return Err(bad("bad order signature"));
        }
        let c = self.on_chain(sell, h, &o).await.map_err(down)?;
        let mut book = self.book.lock().await;
        book.purge(now());
        // an order handed in again while a fill of it is unmined: that fill is not on chain yet (never over-credit)
        let rem = c.remaining.saturating_sub(book.pending_of(h));
        book.admit(h, sell, &o, rem, c.fundable, self.relayer(), self.dex, now()).map_err(bad)?;

        let mut commit = Commit::default();
        let mut dropped: Vec<B256> = vec![];
        let matched: std::result::Result<(Book, Placement), VenueError> = async {
            let mut round = 0;
            loop {
                let mut trial = book.clone();
                for d in &dropped {
                    trial.remove(*d);
                }
                let placed = trial.place(h, sell, o.clone(), sig.clone(), rem);
                let Some(s) = placed.settlement.clone() else { break Ok((trial, placed)) };
                let ok = self.simulate(std::slice::from_ref(&s)).await.map_err(|e| match e {
                    SimError::Revert(r) => bad(format!("settlement simulation: {r}")),
                    SimError::Transport(r) => down(format!("rpc: {r}")),
                })?;
                if ok.first() == Some(&true) {
                    break Ok((trial, placed));
                }
                // NODE-DEX-02, N8: blame by evidence only. Every order hash the revert names, and every maker of the
                // settlement whose state or signature can no longer settle; failing both, each leg's own pull.
                let mut at_fault = self.fault(&s).await;
                if at_fault.contains(&h) {
                    return Err(bad("settlement simulation refused this order"));
                }
                for (m, _, _) in &s.makers {
                    if !at_fault.contains(&m.hash) && !self.healthy(m).await.map_err(down)? {
                        at_fault.push(m.hash);
                    }
                }
                if at_fault.is_empty() {
                    at_fault = self.leg_faults(&s).await?;
                    if at_fault.contains(&h) {
                        return Err(bad("settlement simulation refused this order"));
                    }
                }
                if at_fault.is_empty() {
                    // no evidence against anyone: never the taker's 400 (NODE-DEX-02)
                    return Err(down("settlement simulation failed with no evidence against an order; retry"));
                }
                for f in at_fault {
                    if let Some((m, _, _)) = s.makers.iter().find(|(m, _, _)| m.hash == f) {
                        commit.order(s.market_id, m, "invalid");
                    }
                    dropped.push(f);
                }
                round += 1;
                if round >= MAX_ROUNDS {
                    return Err(down("order book unstable; retry"));
                }
            }
        }
        .await;
        let (trial, placed) = match matched {
            Ok(x) => x,
            Err(e) => {
                // review T3 I2: the evidence is kept — the makers found at fault leave the book and the client first
                if !commit.is_empty() {
                    let mut next = book.clone();
                    for d in &dropped {
                        next.remove(*d);
                    }
                    self.commit_or_reload(&mut book, next, commit).await?;
                }
                return Err(e);
            }
        };

        let (market_id, base) =
            book.market_of(sell, o.receiveToken).map(|m| (m.id, m.base)).ok_or_else(|| bad("no market"))?;
        for d in &placed.dust {
            commit.order(market_id, &Resting { remaining: U256::ZERO, ..d.clone() }, "filled");
        }
        let settlement: Vec<PlannedSettlement> = placed.settlement.iter().cloned().collect();
        self.add_settlements(&mut commit, &trial, &settlement);
        let filled_here = placed.settlement.as_ref().map(|s| s.taker_fill).unwrap_or_default();
        let taker_after = Resting { hash: h, sell, order: o.clone(), sig: sig.clone(), remaining: rem - filled_here, seq: placed.seq };
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
        self.load_pending(book).await
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
        if !self.valid_sig(self.verifier(r.sell), r.order.from, digest, &sig).await.map_err(down)? {
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
        if !self.valid_sig(target, from, digest.map_err(down)?, &sig).await.map_err(down)? {
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
                    next.settled(r.hash, fill); // a failed fill is never mined: no longer pending
                    if give_up || skip.contains(&r.hash) || r.order.flags & FLAG_IOC != 0 || r.order.validUntil < U256::from(now()) {
                        continue;
                    }
                    let Some(market_id) = next.market_of(r.sell, r.order.receiveToken).map(|m| m.id) else { continue };
                    let in_book = next.get(r.hash).map(|x| x.remaining).unwrap_or_default();
                    let c = self.on_chain(r.sell, r.hash, &r.order).await?;
                    let add = restorable(fill, c.remaining, in_book, next.pending_of(r.hash));
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
                // a planned fill is final on chain: no longer pending (review T3 I1)
                Some("LegSettled") => {
                    if let (Ok(h), Ok(sold)) = (e["order_hash"].as_str().unwrap_or_default().parse::<B256>(),
                                                 crate::metatx::uint(e["sold"].as_str().unwrap_or_default())) {
                        book.settled(h, sold);
                    }
                }
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

/// What a failed fill may hand back: at most `fill`, and never more than the chain still has open for the order
/// (`amount − pulled`) after what rests in the book and what other planned fills still pull (review T3 I1).
fn restorable(fill: U256, on_chain: U256, in_book: U256, pending: U256) -> U256 {
    fill.min(on_chain.saturating_sub(in_book.saturating_add(pending)))
}

/// `SigCheck.isContract`: code, and not an EIP-7702 designator (`0xef0100 ‖ address`, whose key still signs).
fn is_contract(code: &[u8]) -> bool {
    let designator = code.len() == 23 && code.starts_with(&[0xef, 0x01, 0x00]);
    !code.is_empty() && !designator
}

/// The ERC-1271 cap (CTR-DEX-08): 400 k for this chain's `SmartKeyAccount` clone, by codehash; 50 k for any other.
fn sig_cap(code: &[u8], clone_codehash: Option<B256>) -> u64 {
    if clone_codehash == Some(keccak256(code)) { SMART_KEY_1271_GAS } else { ERC1271_GAS }
}

/// `SigCheck`'s ERC-1271 verdict: exactly 32 bytes of returndata, equal to `isValidSignature.selector ‖ 0²⁸`.
fn magic_ok(out: &[u8]) -> bool {
    out.len() == 32 && out[..4] == MAGIC_1271 && out[4..].iter().all(|b| *b == 0)
}

/// `ECDSA.tryRecover` (OpenZeppelin): 65 bytes, `v` 27 or 28, low-s (review I4), recovering exactly `signer`.
fn ecdsa_ok(signer: Address, digest: B256, sig: &[u8]) -> bool {
    sig.len() == 65
        && matches!(sig[64], 27 | 28)
        && Signature::try_from(sig)
            .is_ok_and(|s| s.normalize_s().is_none() && s.recover_address_from_prehash(&digest).ok() == Some(signer))
}

/// Intrinsic gas of a call carrying `data`: 21 000 + 4 per zero byte + 16 per other byte. ponytail: no EIP-7623
/// floor; it binds only when calldata gas exceeds the call's execution, never next to a ≥ 50 k cap.
fn intrinsic(data: &[u8]) -> u64 {
    21_000 + data.iter().map(|b| if *b == 0 { 4 } else { 16 }).sum::<u64>()
}

/// `SCaaSDex._SMART_KEY_CLONE_CODEHASH`: keccak of the EIP-1167 runtime of a clone of `implementation` (0 = none).
fn clone_codehash(implementation: Address) -> Option<B256> {
    (implementation != Address::ZERO).then(|| keccak256(clone_code(implementation)))
}

fn clone_code(implementation: Address) -> Vec<u8> {
    use alloy::primitives::hex;
    [&hex!("363d3d373d3d3d363d73")[..], implementation.as_slice(), &hex!("5af43d82803e903d91602b57fd5bf3")].concat()
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

    // ------------------------------------------------------------------ the venue on a fake chain (review T3 C1, I2)

    use std::collections::HashSet;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use alloy::sol_types::SolValue;

    const DEX: Address = Address::repeat_byte(0xd0);

    /// A chain where each leg's fate is scripted by its order hash (`keccak(abi(order))`, as the fake token's
    /// `tradeOrderDigest` answers). `mtxSettle` fails a settlement holding any failing leg; `settleOne` reverts as the
    /// first failing leg would; `mtxTrade` alone fails only for a bad signature.
    #[derive(Default)]
    struct World {
        codes: HashMap<Address, Bytes>,
        /// `isValidSignature` returndata per contract signer.
        answers: HashMap<Address, Bytes>,
        /// The token reports `MetaTxBadSignature()` (no hash) for the leg, in a settlement and alone.
        bad_sig: HashSet<B256>,
        /// In a settlement only: `MetaTxBadSignature()`, yet its own `mtxTrade` passes (no evidence anywhere).
        silent: HashSet<B256>,
        /// The leg's revert names it: `BelowMinFill(h)`.
        named: HashSet<B256>,
        /// `balanceOf` = 0.
        unfunded: HashSet<Address>,
        /// `(from, to, gas)` of every `isValidSignature` call.
        sig_calls: Vec<(Address, Address, u64)>,
        /// `isValidSignature` of this signer answers this JSON-RPC error instead.
        sig_errors: HashMap<Address, Value>,
        /// In a settlement the leg reverts with words that are no order hash (`MetaTxInsufficientForFee(1, 0)`), and its
        /// own `mtxTrade` reverts too.
        wordy: HashSet<B256>,
        /// Tokens without `mtxTrade` (an outside token): every `mtxTrade` on them reverts.
        no_trade: HashSet<Address>,
        /// `eth_getLogs` answers these (the watcher's final range is blocks 6..=10).
        logs: Vec<Value>,
    }
    type W = Arc<std::sync::Mutex<World>>;

    fn oh(o: &TradeOrder) -> B256 {
        keccak256(o.abi_encode())
    }

    async fn fake_chain(w: World) -> (String, W) {
        use axum::extract::State;
        use axum::Json;
        async fn h(State(s): State<W>, Json(r): Json<Value>) -> Json<Value> {
            let mut w = s.lock().unwrap();
            let p = &r["params"];
            let hexs = |b: &[u8]| json!(format!("0x{}", alloy::hex::encode(b)));
            let revert = |e: Vec<u8>| Err(json!({"code": 3, "message": "execution reverted", "data": format!("0x{}", alloy::hex::encode(e))}));
            let out: std::result::Result<Value, Value> = match r["method"].as_str().unwrap() {
                "eth_getCode" => {
                    let a: Address = p[0].as_str().unwrap().parse().unwrap();
                    Ok(hexs(w.codes.get(&a).map(|c| c.as_ref()).unwrap_or_default()))
                }
                "eth_blockNumber" => Ok(json!("0xa")),
                "eth_getBlockByNumber" => {
                    Ok(serde_json::from_str::<Value>(include_str!("../../tests/vectors/hedera_testnet.json")).unwrap()["block"].clone())
                }
                "eth_getLogs" => Ok(Value::Array(w.logs.clone())),
                "eth_call" => {
                    let input = alloy::hex::decode(&p[0]["input"].as_str().or(p[0]["data"].as_str()).unwrap()[2..]).unwrap();
                    let to: Address = p[0]["to"].as_str().unwrap().parse().unwrap();
                    let from: Address = p[0]["from"].as_str().map_or(Address::ZERO, |f| f.parse().unwrap());
                    let sel: [u8; 4] = input[..4].try_into().unwrap();
                    let word = |v: U256| hexs(&v.abi_encode());
                    let fails = |w: &World, sell: Address, o: &TradeOrder| -> Option<Vec<u8>> {
                        let h = if sell == BASE || sell == QUOTE { oh(o) } else { B256::ZERO };
                        if w.named.contains(&h) {
                            Some(IToken::BelowMinFill { orderHash: h }.abi_encode())
                        } else if w.bad_sig.contains(&h) || w.silent.contains(&h) {
                            Some(IToken::MetaTxBadSignature {}.abi_encode())
                        } else if w.wordy.contains(&h) || w.unfunded.contains(&o.from) {
                            Some(IToken::MetaTxInsufficientForFee { needed: U256::from(1), available: U256::ZERO }.abi_encode())
                        } else {
                            None
                        }
                    };
                    let legs = |s: &crate::abi::Settlement| -> Vec<(Address, TradeOrder)> {
                        std::iter::once((s.taker.sellToken, s.taker.o.clone()))
                            .chain(s.makers.iter().map(|m| (m.sellToken, m.o.clone()))).collect()
                    };
                    if sel == IToken::tradeOrderDigestCall::SELECTOR {
                        Ok(hexs(oh(&IToken::tradeOrderDigestCall::abi_decode(&input).unwrap().o).as_slice()))
                    } else if sel == IToken::pulledCall::SELECTOR || sel == IToken::minNonceCall::SELECTOR {
                        Ok(word(U256::ZERO))
                    } else if sel == IToken::balanceOfCall::SELECTOR {
                        let who = IToken::balanceOfCall::abi_decode(&input).unwrap().who;
                        Ok(word(if w.unfunded.contains(&who) { U256::ZERO } else { U256::from(10u64).pow(U256::from(30)) }))
                    } else if sel == MAGIC_1271 {
                        let gas = u64::from_str_radix(&p[0]["gas"].as_str().unwrap()[2..], 16).unwrap();
                        w.sig_calls.push((from, to, gas));
                        match w.sig_errors.get(&to) {
                            Some(e) => Err(e.clone()),
                            None => Ok(hexs(w.answers.get(&to).map(|b| b.as_ref()).unwrap_or_default())),
                        }
                    } else if sel == ISCaaSDex::mtxSettleCall::SELECTOR {
                        let c = ISCaaSDex::mtxSettleCall::abi_decode(&input).unwrap();
                        let ok: Vec<bool> = c.s.iter().map(|s| legs(s).iter().all(|(t, o)| fails(&w, *t, o).is_none())).collect();
                        if ok.iter().any(|x| *x) { Ok(hexs(&ok.abi_encode())) } else { revert(ISCaaSDex::NothingSettled {}.abi_encode()) }
                    } else if sel == ISCaaSDex::settleOneCall::SELECTOR {
                        assert_eq!((from, to), (DEX, DEX));
                        let c = ISCaaSDex::settleOneCall::abi_decode(&input).unwrap();
                        match legs(&c.s).iter().find_map(|(t, o)| fails(&w, *t, o)) {
                            Some(e) => revert(e),
                            None => Ok(hexs(&[])),
                        }
                    } else if sel == IToken::mtxTradeCall::SELECTOR {
                        assert_eq!(from, DEX, "a leg is probed as the DEX pulls it");
                        let h = oh(&IToken::mtxTradeCall::abi_decode(&input).unwrap().o);
                        if w.bad_sig.contains(&h) || w.wordy.contains(&h) || w.no_trade.contains(&to) {
                            revert(IToken::MetaTxBadSignature {}.abi_encode())
                        } else {
                            Ok(hexs(&[]))
                        }
                    } else {
                        panic!("unexpected eth_call {}", alloy::hex::encode(sel))
                    }
                }
                m => panic!("unexpected {m}"),
            };
            Json(match out {
                Ok(v) => json!({"jsonrpc": "2.0", "id": r["id"], "result": v}),
                Err(e) => json!({"jsonrpc": "2.0", "id": r["id"], "error": e}),
            })
        }
        let s: W = Arc::new(std::sync::Mutex::new(w));
        let app = axum::Router::new().route("/", axum::routing::post(h)).with_state(s.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, s)
    }

    fn market() -> MarketCfg {
        MarketCfg { id: 1, base: BASE, quote: QUOTE, base_decimals: 0, quote_decimals: 0, maker_fee_ppm: 0,
                    taker_fee_ppm: 0, min_base_amount: "0".into() }
    }

    fn relayer_key() -> PrivateKeySigner {
        PrivateKeySigner::from_bytes(&B256::repeat_byte(0x42)).unwrap()
    }

    fn order(from: Address, receive: Address, amount: u64, receive_amount: u64, nonce: u64) -> TradeOrder {
        TradeOrder {
            from, receiveToken: receive, amount: U256::from(amount), receiveAmount: U256::from(receive_amount),
            minFill: U256::ZERO, fee: U256::ZERO, relayer: relayer_key().address(), dex: DEX, destination: Address::ZERO,
            flags: 0, batch: U256::from(1), nonce: U256::from(nonce), validUntil: U256::from(now() + 300),
        }
    }

    fn sig_of(k: &PrivateKeySigner, h: B256) -> Bytes {
        Bytes::from(k.sign_hash_sync(&h).unwrap().as_bytes().to_vec())
    }

    /// A venue on the fake chain whose book holds `makers` (asks, best first by price as inserted).
    async fn venue(w: World, makers: Vec<(TradeOrder, Bytes)>) -> (Venue, W) {
        let (url, world) = fake_chain(w).await;
        let cfg = crate::config::ChainCfg { family: "evm".into(), evm_chain_number: 31337, rpc_urls: vec![url],
                                            chain_uid: Some(B256::repeat_byte(0x24)), ..Default::default() };
        let chain = Arc::new(Chain::with_signer(&cfg, relayer_key()).unwrap());
        let (relay, _) = crate::adapter::tests::fake_odoo(Default::default()).await;
        let mut book = Book::new(vec![market()]);
        for (i, (o, sig)) in makers.into_iter().enumerate() {
            book.insert(Resting { hash: oh(&o), sell: BASE, remaining: o.amount, order: o, sig, seq: i as u64 + 1 });
        }
        book.next_seq = 100;
        let v = Venue { chain, relay, indexer: None, dex: DEX, puller: Address::repeat_byte(0x9),
            kinds: [(BASE, KIND_SCAAS), (QUOTE, KIND_SCAAS)].into_iter().collect(), clone_codehash: None,
            book: Mutex::new(book), trades: Default::default(), cancels: Default::default() };
        (v, world)
    }

    async fn take(v: &Venue, k: &PrivateKeySigner, quote: u64, base: u64, nonce: u64) -> std::result::Result<PlaceReply, VenueError> {
        let o = order(k.address(), BASE, quote, base, nonce);
        v.place(QUOTE, &WireOrder::from_sol(&o), &hex_of(&sig_of(k, oh(&o)))).await
    }

    fn in_book(rows: &[Row], o: &TradeOrder) -> bool {
        rows.iter().any(|r| r.order_hash == format!("{:#x}", oh(o)))
    }

    /// Review T3 C1: an ERC-1271 maker at the best price whose wallet answers anything but exactly the 32-byte magic
    /// word fails its leg; the venue's check is `SigCheck`'s, so it is found unhealthy and dropped, and the taker fills
    /// at the next maker. The taker is an EIP-7702 delegated EOA: its key signs, it is never asked ERC-1271.
    #[tokio::test]
    async fn a_hostile_1271_maker_at_the_best_price_never_blocks_a_taker() {
        let taker = PrivateKeySigner::random();
        let honest = PrivateKeySigner::random();
        let hostile = Address::repeat_byte(0x71);
        let mut designator = vec![0xef, 0x01, 0x00];
        designator.extend_from_slice(Address::repeat_byte(0x55).as_slice());
        let magic_then_one = [MAGIC_1271.to_vec(), vec![0; 28], U256::from(1).to_be_bytes::<32>().to_vec()].concat();
        for answer in [MAGIC_1271.to_vec(), magic_then_one] {
            let bad_ask = order(hostile, QUOTE, 10, 20, 1);
            let good_ask = order(honest.address(), QUOTE, 10, 22, 1);
            let mut w = World::default();
            w.codes.insert(hostile, Bytes::from_static(&[0x60, 0x01]));
            w.codes.insert(taker.address(), Bytes::from(designator.clone()));
            w.answers.insert(hostile, Bytes::from(answer.clone()));
            w.bad_sig.insert(oh(&bad_ask));
            let makers = vec![(bad_ask.clone(), Bytes::from_static(&[0xab; 65])), (good_ask.clone(), sig_of(&honest, oh(&good_ask)))];
            let (v, world) = venue(w, makers).await;
            let r = take(&v, &taker, 22, 10, 1).await.unwrap_or_else(|e| panic!("{} bytes: {e}", answer.len()));
            assert_eq!((r.status, r.fills[0]["maker_hash"].as_str().unwrap()), ("filled", &*format!("{:#x}", oh(&good_ask))));
            assert!(!in_book(&v.rows().await, &bad_ask), "the hostile maker left the book");
            let calls = world.lock().unwrap().sig_calls.clone();
            let data = {
                alloy::sol! { function isValidSignature(bytes32 hash, bytes signature) external view returns (bytes4); }
                isValidSignatureCall { hash: oh(&bad_ask), signature: Bytes::from_static(&[0xab; 65]) }.abi_encode()
            };
            assert_eq!(calls, vec![(BASE, hostile, ERC1271_GAS + intrinsic(&data))], "from the token, with the 50 k cap");
        }
    }

    /// N8: a leg whose revert names no order and whose state and signature read healthy is found by its own pull
    /// (`mtxTrade` as the DEX calls it); with no evidence at all the taker gets 503, never a 400.
    #[tokio::test]
    async fn a_failing_leg_is_found_by_its_own_pull_and_no_evidence_is_never_the_takers_fault() {
        let taker = PrivateKeySigner::random();
        let (sly, honest) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let sly_ask = order(sly.address(), QUOTE, 10, 20, 1);
        let good_ask = order(honest.address(), QUOTE, 10, 22, 1);
        let makers = vec![(sly_ask.clone(), sig_of(&sly, oh(&sly_ask))), (good_ask.clone(), sig_of(&honest, oh(&good_ask)))];
        let mut w = World::default();
        w.bad_sig.insert(oh(&sly_ask));
        let (v, _) = venue(w, makers.clone()).await;
        assert_eq!(take(&v, &taker, 22, 10, 1).await.unwrap().status, "filled");
        assert!(!in_book(&v.rows().await, &sly_ask));
        let mut w = World::default();
        w.silent.insert(oh(&sly_ask));
        let (v, _) = venue(w, makers).await;
        assert!(matches!(take(&v, &taker, 22, 10, 1).await, Err(VenueError::Unavailable(_))));
        assert!(in_book(&v.rows().await, &sly_ask), "nobody is dropped without evidence");
    }

    /// Review T3 I2: every maker named or unhealthy in a round leaves at once, and the round limit keeps what it found.
    #[tokio::test]
    async fn three_bad_makers_at_the_top_never_cause_an_endless_503() {
        let taker = PrivateKeySigner::random();
        let keys: Vec<PrivateKeySigner> = (0..4).map(|_| PrivateKeySigner::random()).collect();
        let asks: Vec<TradeOrder> = [(10, 20), (10, 21), (10, 22), (40, 92)].iter().zip(&keys)
            .map(|((b, q), k)| order(k.address(), QUOTE, *b, *q, 1)).collect();
        let makers: Vec<(TradeOrder, Bytes)> = asks.iter().zip(&keys).map(|(o, k)| (o.clone(), sig_of(k, oh(o)))).collect();
        // (a) each named by its own revert, one per settlement, state healthy: the third round gives up with 503,
        //     yet all three are gone for the next taker
        let mut w = World::default();
        w.named.extend(asks[..3].iter().map(oh));
        let (v, _) = venue(w, makers.clone()).await;
        assert!(matches!(take(&v, &taker, 23, 10, 1).await, Err(VenueError::Unavailable(_))));
        let rows = v.rows().await;
        assert!(asks[..3].iter().all(|o| !in_book(&rows, o)) && in_book(&rows, &asks[3]), "the drops are committed");
        assert_eq!(take(&v, &taker, 69, 30, 2).await.unwrap().status, "filled");
        // (b) one settlement over all three: the revert names the first, the other two read unfunded — all leave in
        //     the same round and the taker fills at once
        let mut w = World::default();
        w.named.extend(asks[..3].iter().map(oh));
        w.unfunded.extend(keys[..3].iter().map(|k| k.address()));
        let (v, _) = venue(w, makers).await;
        let r = take(&v, &taker, 69, 30, 1).await.unwrap();
        assert_eq!((r.status, r.fills[0]["maker_hash"].as_str().unwrap()), ("filled", &*format!("{:#x}", oh(&asks[3]))));
    }

    #[test]
    fn the_signature_rules_are_sigcheck_s() {
        let k = PrivateKeySigner::random();
        let d = B256::repeat_byte(7);
        let sig = sig_of(&k, d);
        assert!(ecdsa_ok(k.address(), d, &sig));
        let mut v01 = sig.to_vec();
        v01[64] -= 27;
        assert!(!ecdsa_ok(k.address(), d, &v01), "v must be 27 or 28 (ecrecover)");
        assert!(!ecdsa_ok(k.address(), d, &sig[..64]), "65 bytes only");
        assert!(!ecdsa_ok(Address::repeat_byte(1), d, &sig));
        // the high-s twin recovers the same signer; `ECDSA.tryRecover` refuses it
        let n = U256::from_str_radix("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16).unwrap();
        let mut high = sig.to_vec();
        high[32..64].copy_from_slice(&(n - U256::from_be_slice(&sig[32..64])).to_be_bytes::<32>());
        high[64] = if high[64] == 27 { 28 } else { 27 };
        assert_eq!(Signature::try_from(&high[..]).unwrap().recover_address_from_prehash(&d).unwrap(), k.address());
        assert!(!ecdsa_ok(k.address(), d, &high), "high-s");
        let mut designator = vec![0xef, 0x01, 0x00];
        designator.extend_from_slice(&[0x55; 20]);
        assert!(!is_contract(&designator), "an EIP-7702 EOA signs with its key");
        assert!(is_contract(&designator[..22]) && is_contract(&[0xef, 0x01, 0x01, 0, 0]) && !is_contract(&[]));
        let mut ok = MAGIC_1271.to_vec();
        ok.extend_from_slice(&[0; 28]);
        assert!(magic_ok(&ok));
        assert!(!magic_ok(&MAGIC_1271), "4 bytes");
        assert!(!magic_ok(&[ok.clone(), vec![0; 32]].concat()), "64 bytes");
        let mut dirty = ok.clone();
        dirty[31] = 1;
        assert!(!magic_ok(&dirty), "the whole word");
        let implementation = Address::repeat_byte(0x5a);
        let clone = clone_code(implementation);
        assert_eq!(clone.len(), 45);
        assert_eq!(sig_cap(&clone, clone_codehash(implementation)), SMART_KEY_1271_GAS);
        assert_eq!(sig_cap(&clone_code(Address::repeat_byte(0x5b)), clone_codehash(implementation)), ERC1271_GAS);
        assert_eq!(sig_cap(&clone, None), ERC1271_GAS);
        assert_eq!(clone_codehash(Address::ZERO), None);
        assert_eq!(intrinsic(&[0, 1, 0]), 21_000 + 4 + 16 + 4);
    }

    /// Review T3 I1 at the I/O edges: a reload counts the unmined part of a partly filled order as pending (from the
    /// chain's `amount − pulled`), and a failed trade releases its pending fill before the order is handed back.
    #[tokio::test]
    async fn pending_fills_are_loaded_from_chain_and_released_by_a_failed_trade() {
        let (maker, taker) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let ask = order(maker.address(), QUOTE, 100, 200, 1); // min 50 base
        let (v, _) = venue(World::default(), vec![(ask.clone(), sig_of(&maker, oh(&ask)))]).await;
        let r = take(&v, &taker, 120, 60, 1).await.unwrap();
        assert_eq!(r.status, "filled");
        assert_eq!(v.book.lock().await.pending_of(oh(&ask)), U256::from(60));
        // a reload (or restart) reads the chain: pulled is still 0, so 60 of the 40-left order is unmined
        let mut reloaded = Book::load(vec![market()], &v.rows().await).unwrap();
        v.load_pending(&mut reloaded).await.unwrap();
        assert_eq!(reloaded.pending_of(oh(&ask)), U256::from(60));
        // the order handed in again (out of the book, e.g. cancelled here only) is credited only what is not pending
        let rest = v.book.lock().await.remove(oh(&ask)).unwrap();
        let again = v.place(BASE, &WireOrder::from_sol(&ask), &hex_of(&rest.sig)).await.unwrap();
        assert_eq!((again.status, again.remaining.as_str()), ("resting", "40"));
        // the settlement dies: the client reports it failed; the maker gets its 60 back (nothing pending any more)
        let row = Row::of(&Resting { hash: oh(&ask), sell: BASE, order: ask.clone(), sig: sig_of(&maker, oh(&ask)),
                                     remaining: U256::from(100), seq: 1 });
        let tag = r.fills[0]["tag"].clone();
        let (relay, _) = crate::adapter::tests::fake_odoo(crate::adapter::tests::Fake {
            dex_sync: json!({"failed": [{"tag": tag, "taker": {"row": null, "fill": "120"},
                                          "makers": [{"row": row, "fill": "60"}]}]}),
            ..Default::default()
        }).await;
        let v = Venue { relay, ..v };
        v.sync_once().await.unwrap();
        let book = v.book.lock().await;
        assert_eq!((book.get(oh(&ask)).unwrap().remaining, book.pending_of(oh(&ask))), (U256::from(100), U256::ZERO));
    }

    /// Review T3 I1 at the watcher: a mined `LegSettled` releases the order's pending fill, so its remainder (below the
    /// minimum fill) closes at once, with no restart or reload.
    #[tokio::test]
    async fn a_mined_leg_releases_its_pending_fill() {
        let (maker, taker) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let ask = order(maker.address(), QUOTE, 100, 200, 1); // min 50 base
        let (v, world) = venue(World::default(), vec![(ask.clone(), sig_of(&maker, oh(&ask)))]).await;
        assert_eq!(take(&v, &taker, 120, 60, 1).await.unwrap().status, "filled");
        assert_eq!(v.book.lock().await.pending_of(oh(&ask)), U256::from(60));
        let ev = ISCaaSDex::LegSettled { r#ref: B256::repeat_byte(1), orderHash: oh(&ask), from: maker.address(),
            destination: maker.address(), sold: U256::from(60), received: U256::from(120), dexFee: U256::ZERO,
            refund: U256::ZERO, relayerShare: U256::ZERO, treasuryShare: U256::ZERO };
        world.lock().unwrap().logs.push(serde_json::to_value(log_of(ev.encode_log_data())).unwrap());
        let (idx, _) = crate::adapter::tests::fake_odoo(crate::adapter::tests::Fake { tokens: json!([]), ..Default::default() }).await;
        let v = Venue { indexer: Some(idx), ..v };
        assert!(v.watch_once().await.unwrap());
        assert_eq!(v.book.lock().await.pending_of(oh(&ask)), U256::ZERO);
        let r = take(&v, &PrivateKeySigner::random(), 80, 40, 1).await.unwrap();
        assert_eq!((r.status, r.fills[0]["maker_hash"].as_str().unwrap()), ("filled", &*format!("{:#x}", oh(&ask))));
    }

    /// Review T3 C1 at the RPC edge: a reverting (or starved) ERC-1271 wallet is `false`, as a failed `staticcall` is;
    /// an RPC failure is no verdict (503 at intake, a resting maker is never dropped for it).
    #[tokio::test]
    async fn a_reverting_wallet_is_invalid_and_an_rpc_failure_is_no_verdict() {
        let wallet = Address::repeat_byte(0x71);
        let mut w = World::default();
        w.codes.insert(wallet, Bytes::from_static(&[0x60, 0x01]));
        let (v, world) = venue(w, vec![]).await;
        let (d, sig) = (B256::repeat_byte(1), Bytes::from_static(&[0xab; 65]));
        for e in [json!({"code": 3, "message": "execution reverted", "data": "0x"}), json!({"code": -32000, "message": "out of gas"})] {
            world.lock().unwrap().sig_errors.insert(wallet, e.clone());
            assert!(!v.valid_sig(BASE, wallet, d, &sig).await.unwrap(), "{e}");
        }
        world.lock().unwrap().sig_errors.insert(wallet, json!({"code": -32603, "message": "upstream unavailable"}));
        assert!(v.valid_sig(BASE, wallet, d, &sig).await.is_err());
    }

    /// Outside legs are never probed through `mtxTrade` (an outside token has none: an honest maker would revert there
    /// and be blamed); they are blamed only on their own evidence, the hash their revert names (N8).
    #[tokio::test]
    async fn outside_legs_are_blamed_only_on_their_own_evidence() {
        let (maker, taker) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let (ask, bid) = (order(maker.address(), QUOTE, 10, 20, 1), order(taker.address(), BASE, 20, 10, 1));
        let leg = |o: &TradeOrder, sell: Address, k: &PrivateKeySigner| Resting { hash: oh(o), sell, order: o.clone(),
            sig: sig_of(k, oh(o)), remaining: o.amount, seq: 1 };
        let s = PlannedSettlement { tag: B256::repeat_byte(1), market_id: 1, taker: leg(&bid, QUOTE, &taker),
            taker_fill: U256::from(20), makers: vec![(leg(&ask, BASE, &maker), U256::from(10), U256::from(20))] };
        let mut w = World::default();
        w.no_trade.insert(BASE);
        let (v, world) = venue(w, vec![]).await;
        let v = Venue { kinds: [(BASE, KIND_OUTSIDE), (QUOTE, KIND_SCAAS)].into_iter().collect(), ..v };
        assert_eq!(v.leg_faults(&s).await.unwrap(), Vec::<B256>::new(), "the outside maker is never probed");
        world.lock().unwrap().named.insert(oh(&ask));
        assert_eq!(v.fault(&s).await, vec![oh(&ask)], "its own revert names it");
    }

    /// A revert whose words name no leg (an amount, a zero) names nobody: the makers' health and each SCaaS leg's own
    /// pull decide, and the taker fills at the next maker instead of a 503 loop.
    #[tokio::test]
    async fn revert_words_that_name_no_leg_are_no_names() {
        let taker = PrivateKeySigner::random();
        let (sly, honest) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let sly_ask = order(sly.address(), QUOTE, 10, 20, 1);
        let good_ask = order(honest.address(), QUOTE, 10, 22, 1);
        let makers = vec![(sly_ask.clone(), sig_of(&sly, oh(&sly_ask))), (good_ask.clone(), sig_of(&honest, oh(&good_ask)))];
        let mut w = World::default();
        w.wordy.insert(oh(&sly_ask));
        let (v, _) = venue(w, makers).await;
        let r = take(&v, &taker, 22, 10, 1).await.unwrap();
        assert_eq!((r.status, r.fills[0]["maker_hash"].as_str().unwrap()), ("filled", &*format!("{:#x}", oh(&good_ask))));
        assert!(!in_book(&v.rows().await, &sly_ask));
    }

    /// A failed fill hands back no more than the chain still has open after the book and the other planned fills.
    #[test]
    fn restores_never_over_credit() {
        let u = U256::from;
        assert_eq!(restorable(u(60), u(100), u(0), u(0)), u(60));
        assert_eq!(restorable(u(60), u(100), u(40), u(0)), u(60));
        assert_eq!(restorable(u(60), u(100), u(40), u(20)), u(40), "another fill of 20 still pulls");
        assert_eq!(restorable(u(60), u(50), u(40), u(20)), u(0));
    }
}
