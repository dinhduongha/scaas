//! DEX venue: the I/O around `Book` (NODE-DEX-01, -15, -16). One venue per chain and DEX, the book's ONLY writer.
//!
//! - Persisted in the client over `/json/2` (RS5-2): every book change is ONE `dex_book_commit` (orders + trades +
//!   jobs); only success replaces the book in memory; a failure reloads the book from the client (review D20).
//! - Settlements go through the client outbox like every job: `mtxSettle` and the DEX-side cancels as `call` jobs to
//!   the DEX, the token-side cancel and invalidation as `ua_metatx` jobs naming their `entry` (job-api.md, CTR-MTX-30).
//! - Intake reads the order's state where it lives (NODE-DEX-15, dex.md §10): a SCaaS sell token keeps a
//!   `UATradeOrder`'s fill state and cancels (`tradeOrderDigest`, `pulled`, `minNonce` by id, `balanceOf` or a derived
//!   id's `balanceOfUA`), the DEX keeps an outside token's `DexOrder` (`dexOrderDigest`, `pulled`, `minNonce`, and
//!   `allowance(from, puller)`).
//! - A shape-1 order is authorized as the token's `authorize` does (ua-mtx-merge T17, R12): a native id by its own key
//!   (`SigCheck`, `keyData` and `members` empty, R17), a derived id by the registry's `requireAuthorized` under `trade`.
//! - The final-event watcher has its own cursor (RS5-8): a DEX failure never blocks payment finality.
use std::collections::{HashMap, HashSet, VecDeque};
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
    auth_of, hex_of, order_of, pair, trade_of, ua_sig_json, Auth, Book, DexOrder, ISCaaSDex, MarketCfg, Placement,
    PlannedSettlement, Resting, Row, UATradeOrder, WireOrder, FLAG_IOC, KIND_OUTSIDE, KIND_SCAAS, PURPOSE_TRADE,
};
use crate::abi::{IComplianceRegistry, IERC165, IMtxIds, IRegulatedToken, IToken, IUALedger, IUARegistry, TradeFill};
use crate::metatx::native;
use crate::chain::{classify, is_contract, Chain, SimError};
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
            "signature": row.signature, "auth": row.auth, "remaining": row.remaining, "seq": row.seq, "state": state,
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

/// An on-chain cancel waiting for the next sync: `(market, the order as it rested with the CANCEL's signature in `auth`, the
/// sell token's contract kind)`; the shape says where it goes.
type PendingCancel = (i64, Resting, &'static str);

#[derive(Default)]
struct CancelQueue {
    // ponytail: in memory — a node that dies before the flush has the order out of the book (the client records
    // `cancelled`) but not closed on chain; with RS5-9 only this relayer can settle it, so it is safe. Durable: keep
    // the cancel signature on the client's order row and flush from there.
    pending: Vec<PendingCancel>,
    recent: HashMap<B256, Vec<u64>>,
}

impl CancelQueue {
    /// May `from` cancel on chain once more this hour (and record it if so).
    fn allow(&mut self, from: B256, at: u64) -> bool {
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
    /// The regulated legs (kinds 8-13: ERC-165 at start) and the `pausedUntil` last seen of each (regulated-kinds spec §7,
    /// NODE-DEX-11): a market with a regulated leg halts while it is in the future.
    regulated: std::sync::Mutex<HashMap<Address, u64>>,
    /// Round 3s (spec 2026-11-10-token-lists.md §9, Fable R-7, P2-1): the regulated legs whose live list refuses the DEX or its
    /// puller ([`venue_halts`], computed at start and on each list event naming one or `FeatureEnabled(8 | 9)`): their markets halt.
    list_halted: std::sync::Mutex<HashSet<Address>>,
    /// The chain's `compliance_registry`, its code hash checked when the chain was loaded (fail closed); `None`: a regulated
    /// leg with a list on is refused `REGISTRY_NOT_CONFIGURED`.
    registry: Option<Address>,
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
        // fail closed: a configured registry whose code is not the pinned one stops the venue
        let me_registry = chain.compliance_registry().await.context("compliance_registry")?;
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
            regulated: Default::default(),
            list_halted: Default::default(),
            registry: me_registry,
        });
        me.load_pending(&mut *me.book.lock().await).await.context("pending fills")?;
        me.load_regulated().await.context("regulated legs")?;
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

    /// A SCaaS token's kind for a job's typed digest, from its EIP-712 domain (`eip712Domain()`, immutable). Unreadable is an
    /// error, never `token`: a seller's cancel under the wrong domain dies `BAD_SIGNATURE` on the lane.
    async fn contract_of(&self, token: Address) -> std::result::Result<&'static str, VenueError> {
        Ok(match view(&self.chain, token, IToken::eip712DomainCall {}).await.map_err(down)?.name.as_str() {
            "SCaaS ZetherToken" => "zether",
            "SCaaS PqzToken" => "pqz",
            _ => "token",
        })
    }

    fn kind(&self, token: Address) -> u8 {
        self.kinds.get(&token).copied().unwrap_or_default()
    }

    // ------------------------------------------------------------------------------ regulated legs (NODE-DEX-11)

    /// The SCaaS legs that answer `type(IRegulatedToken).interfaceId` (M-10), each with its `pausedUntil`; for each, the venue's
    /// own eligibility, alerted by name, never assumed: the registry admin attests the DEX and its puller `ELIGIBLE_CONTRACT`
    /// (an operator step, owner 2026-11-06); until then intake refuses `VENUE_NOT_ELIGIBLE` on a listed leg.
    async fn load_regulated(&self) -> Result<()> {
        for (&t, _) in self.kinds.iter().filter(|(_, k)| **k == KIND_SCAAS) {
            let call = IERC165::supportsInterfaceCall { id: crate::abi::regulated_interface_id().into() };
            let regulated = match self.chain.call_view(t, call).await {
                Ok(yes) => yes,
                Err(SimError::Revert(_)) => false,
                Err(SimError::Transport(e)) => bail!("supportsInterface of {t:#x}: {e}"),
            };
            if !regulated {
                continue;
            }
            let c = view(&self.chain, t, IRegulatedToken::regulatedConfigCall {}).await?;
            self.set_paused(t, c.pausedUntil);
            // Fable P2-1 (c): the list halt from live reads at start too, never only from events seen since
            self.set_list_halt(t, self.venue_halted(t, c.controls).await?);
            self.alert_eligibility(t, &c).await;
        }
        Ok(())
    }

    /// The venue's own eligibility on regulated leg `t`, alerted by name (`VENUE_NOT_ELIGIBLE`), never assumed: at start and on
    /// the leg's `FeatureEnabled(KYC)` (spec 2026-11-10-token-lists.md §9, Fable P3-2).
    async fn alert_eligibility(&self, t: Address, c: &IRegulatedToken::RegulatedConfig) {
        for (who, name) in [(self.dex, "venue"), (self.puller, "puller")] {
            match self.leg_receivable(t, c, who.into_word(), now()).await {
                Ok((true, ..)) => {}
                Ok((false, reason, _)) => warn!(chain = self.chain.number, token = %t, %who, reason, alert = "VENUE_NOT_ELIGIBLE",
                    "the {name} is not eligible on a regulated leg: the registry admin attests [venue, venue.puller()] as \
                     ELIGIBLE_CONTRACT (8, validUntil 2^64-1); until then orders on it are refused"),
                Err(e) => warn!(chain = self.chain.number, token = %t, %who, alert = "VENUE_NOT_ELIGIBLE", "{name}: {e}"),
            }
        }
    }

    /// Fable P2-1: leg `t`'s list halt, computed from its live `controls` and the DEX's and the puller's live flags
    /// ([`venue_halts`]), never toggled by one event; both lists off, no read. A transport error is an error (fail closed).
    async fn venue_halted(&self, t: Address, controls: u8) -> Result<bool> {
        if controls & (C_ALLOW | C_DENY) == 0 {
            return Ok(false);
        }
        let flags = |v: Address| view(&self.chain, t, IRegulatedToken::listFlagsOfCall { account: v.into_word() });
        let (d, p) = (flags(self.dex).await.context("LIST_UNREAD: listFlagsOf(DEX)")?,
            flags(self.puller).await.context("LIST_UNREAD: listFlagsOf(puller)")?);
        Ok(venue_halts(controls, d, p))
    }

    fn set_paused(&self, token: Address, until: u64) {
        if let Ok(mut m) = self.regulated.lock() {
            m.insert(token, until);
        }
    }

    /// `Some(pausedUntil)` while a regulated `token` is paused at `at` (a market with it halts); reopens at `pausedUntil`.
    fn halted(&self, token: Address, at: u64) -> Option<u64> {
        if self.list_halted.lock().is_ok_and(|h| h.contains(&token)) {
            return Some(u64::MAX); // round 3s: until the reverse list event
        }
        self.regulated.lock().ok()?.get(&token).copied().filter(|u| *u > at)
    }

    fn set_list_halt(&self, token: Address, on: bool) {
        if let Ok(mut h) = self.list_halted.lock() {
            if on {
                h.insert(token);
            } else {
                h.remove(&token);
            }
        }
    }

    /// Round 3s (spec 2026-11-10-token-lists.md §4.2, §9): `L(who)` on a regulated leg, read live: under `ALLOWLIST` not
    /// `ALLOWED` `NOT_ALLOWED`, under `DENYLIST` `DENIED`; both lists off, no read.
    async fn leg_listed(&self, token: Address, c: &IRegulatedToken::RegulatedConfig, who: B256) -> std::result::Result<(), VenueError> {
        if c.controls & (C_ALLOW | C_DENY) == 0 {
            return Ok(());
        }
        let f = view(&self.chain, token, IRegulatedToken::listFlagsOfCall { account: who }).await.map_err(down)?;
        if !list_admits(c.controls, f) {
            let name = if c.controls & C_ALLOW != 0 && f & 1 == 0 { "NOT_ALLOWED" } else { "DENIED" };
            return Err(bad(format!("{name}: {who:#x} on {token:#x}")));
        }
        Ok(())
    }

    fn is_regulated(&self, token: Address) -> bool {
        self.regulated.lock().is_ok_and(|m| m.contains_key(&token))
    }

    /// `R(who)` on a regulated leg as its `canReceive` answers it under `KYC` (`scaas_ua::regulated::can_receive` over the
    /// registry's `complianceOf` and `kycProviderEnabled`, both masks; round 3s), with the row's `validUntil`; `KYC` off:
    /// `(true, 0, u64::MAX)`.
    /// The leg's registry must be the configured one: `REGISTRY_NOT_CONFIGURED`, `REGISTRY_MISMATCH` otherwise.
    async fn leg_receivable(&self, token: Address, c: &IRegulatedToken::RegulatedConfig, who: B256, at: u64)
        -> std::result::Result<(bool, u8, u64), VenueError>
    {
        if c.controls & C_KYC == 0 {
            return Ok((true, 0, u64::MAX));
        }
        let (req, den) = (Some(c.requiredFlags), Some(c.deniedFlags));
        let reg = match self.registry {
            None => return Err(bad(format!("REGISTRY_NOT_CONFIGURED: {token:#x} reads registry {:#x}; set compliance_registry", c.complianceRegistry))),
            Some(r) if r != c.complianceRegistry => {
                return Err(bad(format!("REGISTRY_MISMATCH: {token:#x} reads registry {:#x}, not compliance_registry {r:#x}", c.complianceRegistry)))
            }
            Some(r) => r,
        };
        let a = view(&self.chain, reg, IComplianceRegistry::complianceOfCall { account: who }).await.map_err(down)?;
        let on = view(&self.chain, reg, IComplianceRegistry::kycProviderEnabledCall { id: a.providerId }).await.map_err(down)?;
        let att = scaas_ua::regulated::Attestation { flags: a.flags, valid_until: a.validUntil, attester_enabled: on };
        let (ok, reason) = scaas_ua::regulated::can_receive(req, den, &att, at);
        Ok((ok, reason, a.validUntil))
    }

    /// NODE-DEX-11's intake pre-check of an order on each regulated leg, read live (the token is the arbiter regardless):
    /// `PAUSED` (and the market halts), the seller `FROZEN` on the token it sells, the venue `VENUE_NOT_ELIGIBLE`, the receiver
    /// `NOT_ELIGIBLE` on the token it buys, an order outliving its receiver's attestation `ATTESTATION_SHORTER`.
    async fn precheck(&self, sell: Address, o: &UATradeOrder) -> std::result::Result<(), VenueError> {
        let at = now();
        for t in [sell, o.receiveToken] {
            if !self.is_regulated(t) {
                continue;
            }
            let c = view(&self.chain, t, IRegulatedToken::regulatedConfigCall {}).await.map_err(down)?;
            self.set_paused(t, c.pausedUntil);
            if c.pausedUntil > at {
                return Err(bad(format!("PAUSED: {t:#x} until {}", c.pausedUntil)));
            }
            if t == sell && view(&self.chain, t, IRegulatedToken::isFrozenCall { account: o.from }).await.map_err(down)? {
                return Err(bad(format!("FROZEN: {:#x} on {t:#x}", o.from)));
            }
            // round 3s: the lists, both parties (the seller on the leg it sells, the venue and its puller on every leg, the
            // receiver on the leg it buys)
            if t == sell {
                self.leg_listed(t, &c, o.from).await?;
            }
            for v in [self.dex, self.puller] {
                self.leg_listed(t, &c, v.into_word()).await?;
            }
            if t == o.receiveToken {
                self.leg_listed(t, &c, if o.destination.is_zero() { o.from } else { o.destination }).await?;
            }
            // the venue receives every leg of a regulated token: pulled in, then paid out
            if let (false, reason, _) = self.leg_receivable(t, &c, self.dex.into_word(), at).await? {
                return Err(bad(format!("VENUE_NOT_ELIGIBLE: the DEX {:#x} on {t:#x}, reason {reason}: the registry admin attests \
                    [venue, venue.puller()] as ELIGIBLE_CONTRACT", self.dex)));
            }
            if t == o.receiveToken {
                let who = if o.destination.is_zero() { o.from } else { o.destination };
                let (ok, reason, until) = self.leg_receivable(t, &c, who, at).await?;
                if !ok {
                    return Err(bad(format!("NOT_ELIGIBLE: {who:#x} on {t:#x}, reason {reason}")));
                }
                if o.validUntil > U256::from(until) {
                    return Err(bad(format!("ATTESTATION_SHORTER: the order runs to {}, {who:#x}'s attestation to {until}", o.validUntil)));
                }
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------------------ chain reads

    async fn call(&self, from: Address, to: Address, data: Vec<u8>) -> std::result::Result<Bytes, SimError> {
        let tx = TransactionRequest::default().from(from).to(to).input(data.into());
        self.chain.primary().call(tx).await.map_err(|e| classify(&e))
    }

    /// The order's hash where it is checked: the sell token (`UATradeOrder`) or the DEX (`DexOrder`).
    async fn order_hash(&self, sell: Address, o: &UATradeOrder) -> Result<B256> {
        match self.kind(sell) {
            KIND_SCAAS => view(&self.chain, sell, IToken::tradeOrderDigestCall { o: o.clone() }).await,
            KIND_OUTSIDE => view(&self.chain, self.dex, ISCaaSDex::dexOrderDigestCall { sellToken: sell, o: trade_of(o) }).await,
            _ => bail!("TOKEN_NOT_SERVED: {sell:#x} is not a side of a listed market"),
        }
    }

    /// `amount − pulled` (0 when the lane's `minNonce` passed the order) and the signer's deliverable balance: an address's
    /// `balanceOf` (and, for an outside token, its allowance to the puller), a derived id's `balanceOfUA` on the token.
    async fn on_chain(&self, sell: Address, h: B256, o: &UATradeOrder) -> Result<OnChain> {
        let (pulled, min) = if self.kind(sell) == KIND_OUTSIDE {
            let from = Address::from_word(o.from);
            (view(&self.chain, self.dex, ISCaaSDex::pulledCall { orderHash: h }).await?,
             view(&self.chain, self.dex, ISCaaSDex::minNonceCall { from, batch: o.batch }).await?)
        } else {
            (view(&self.chain, sell, IToken::pulledCall { orderHash: h }).await?,
             view(&self.chain, sell, IToken::minNonceCall { from: o.from, batch: o.batch }).await?)
        };
        let remaining = if o.nonce < min { U256::ZERO } else { o.amount.saturating_sub(pulled) };
        let fundable = match native(&o.from) {
            None => view(&self.chain, sell, IUALedger::balanceOfUACall { ua: o.from }).await?,
            Some(who) if self.kind(sell) == KIND_OUTSIDE => view(&self.chain, sell, IToken::balanceOfCall { who }).await?
                .min(view(&self.chain, sell, IToken::allowanceCall { owner: who, spender: self.puller }).await?),
            Some(who) => view(&self.chain, sell, IToken::balanceOfCall { who }).await?,
        };
        Ok(OnChain { remaining, fundable })
    }

    /// The signer of `from` authorized `digest` as the contract that holds the order checks it: a shape-0 signature on the DEX
    /// (`SigCheck`, CTR-UA-24); a shape-1 `UASig` as the token's `authorize` under the purpose `trade` — a native id by its own key
    /// with `keyData` and `members` empty (R17), a derived one by the token's registry (`requireAuthorized`; none = refused,
    /// `UALedgerOff`). `Err` = the RPC, never a verdict.
    async fn authorized(&self, sell: Address, from: B256, digest: B256, auth: &Auth) -> Result<bool> {
        let a = match auth {
            Auth::Sig(sig) => return self.valid_sig(self.dex, Address::from_word(from), digest, sig).await,
            Auth::Ua(a) => a,
        };
        if let Some(signer) = native(&from) {
            let r17 = a.keyData.is_empty() && a.members.is_empty();
            return Ok(r17 && signer != Address::ZERO && self.valid_sig(sell, signer, digest, &a.signature).await?);
        }
        let registry = view(&self.chain, sell, IUALedger::registryCall {}).await?;
        if registry == Address::ZERO {
            return Ok(false);
        }
        let call = IUARegistry::requireAuthorizedCall { ua: from, purposeTag: PURPOSE_TRADE, digest, auth: a.clone() };
        match self.call(sell, registry, call.abi_encode()).await {
            Ok(_) => Ok(true),
            Err(SimError::Revert(_)) => Ok(false),
            Err(SimError::Transport(e)) => Err(anyhow!("rpc: {e}")),
        }
    }

    /// A resting order can still settle `r.remaining`: open on chain for that much, funded, signature valid.
    async fn healthy(&self, r: &Resting) -> Result<bool> {
        let c = self.on_chain(r.sell, r.hash, &r.order).await?;
        Ok(c.remaining >= r.remaining
            && c.fundable >= r.remaining
            && self.authorized(r.sell, r.order.from, r.hash, &r.auth).await?)
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
        for w in raw.get(4..).unwrap_or_default().as_chunks::<32>().0.iter().copied().map(B256::from) {
            if legs.contains(&w) && !named.contains(&w) {
                named.push(w);
            }
        }
        named
    }

    /// Evidence when a failed settlement names no order (a SCaaS token reports a bad signature as
    /// `MetaTxBadSignature()`, no hash): each SCaaS leg's own `mtxTrade(o, auth, fill)`, called alone as the DEX calls it.
    /// A leg whose own pull reverts is at fault. Outside legs name their hash themselves (`BadSignature(h)`, `TradeLib`).
    /// Review T3 C1, N8: no leg is blamed without this evidence.
    async fn leg_faults(&self, p: &PlannedSettlement) -> std::result::Result<Vec<B256>, VenueError> {
        let fee = |recv: U256, o: &UATradeOrder| (recv * o.fee + U256::from(PPM - 1)) / U256::from(PPM);
        let legs = p.makers.iter().map(|(m, x, y)| (m, *x, *y)).chain([(&p.taker, p.taker_fill, p.taker_receives())]);
        let mut out = vec![];
        for (r, sold, recv) in legs {
            if self.kind(r.sell) != KIND_SCAAS {
                continue;
            }
            let Auth::Ua(auth) = &r.auth else {
                out.push(r.hash); // a SCaaS leg in shape 0: `LegShapeUnknown(0)` on chain
                continue;
            };
            let f = TradeFill { sellFill: sold, receiveFill: recv, dexFee: fee(recv, &r.order), submitter: self.relayer() };
            let data = IToken::mtxTradeCall { o: r.order.clone(), auth: auth.clone(), f }.abi_encode();
            let tx = TransactionRequest::default().from(self.dex).to(r.sell).input(data.into());
            match self.chain.primary().call(tx).await {
                Ok(_) => {}
                Err(e) => {
                    // F-16: a pause is no leg's fault; the market halts until it ends, nobody is blamed
                    let paused = e.as_error_resp().and_then(|x| x.as_revert_data()).filter(|_| self.is_regulated(r.sell))
                        .and_then(|raw| <IRegulatedToken::TokenPaused as alloy::sol_types::SolError>::abi_decode(&raw).ok());
                    if let Some(p) = paused {
                        self.set_paused(r.sell, p.until);
                        return Err(bad(format!("PAUSED: {:#x} until {}", r.sell, p.until)));
                    }
                    match classify(&e) {
                        SimError::Revert(_) => out.push(r.hash),
                        SimError::Transport(e) => return Err(down(format!("rpc: {e}"))),
                    }
                }
            }
        }
        Ok(out)
    }

    /// `SigCheck.isValid` exactly as `verifier` (the order's token, or the DEX) runs it (CTR-MTX-25, review T3 C1; CTR-UA-24
    /// on every path, owner ruling 2026-10-30, D1): no code or an EIP-7702 designator (an EOA) ⇒ ECDSA by its own key
    /// only, the delegate is never asked; a contract ⇒ ERC-1271 called from `verifier` with the cap by codehash as the
    /// callee's gas, accepted only as exactly 32 bytes equal to the magic word. `Err` = the RPC, never a verdict.
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

    /// `POST /v1/dex/orders {chain, sellToken, order, auth | signature}`, by the DEX's listing (CTR-DEX-26): a SCaaS sell
    /// token's order is a `UATradeOrder` (`from`, `destination` ids) with `auth` (a `UASig`), an outside token's a `TradeOrder`
    /// (signed as a `DexOrder`) with `signature`; the other form is refused by name.
    pub async fn place(&self, sell: Address, wire: &WireOrder, signature: Option<&str>, auth: Option<&Value>)
        -> std::result::Result<PlaceReply, VenueError>
    {
        let kind = self.kind(sell);
        let sig = auth_of(kind, signature, auth).map_err(bad)?;
        let o = order_of(kind, wire).map_err(bad)?;
        let h = self.order_hash(sell, &o).await.map_err(down)?;
        if !self.authorized(sell, o.from, h, &sig).await.map_err(down)? {
            return Err(bad("bad order signature"));
        }
        self.precheck(sell, &o).await?;
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
        let taker_after = Resting { hash: h, sell, order: o.clone(), auth: sig.clone(), remaining: rem - filled_here, seq: placed.seq };
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

    /// Cancel one order with its cancel signed in its own form: `CancelUAOrder` with `auth` in the sell token's domain (a SCaaS
    /// order), `CancelDexOrder` with `signature` in the DEX's (an outside one); out of the book NOW, closed on chain at the
    /// next sync.
    pub async fn cancel(&self, h: B256, signature: Option<&str>, auth: Option<&Value>) -> std::result::Result<(), VenueError> {
        let mut book = self.book.lock().await;
        let r = book.get(h).cloned().ok_or_else(|| bad("order is not in the book"))?;
        let kind = self.kind(r.sell);
        let sig = auth_of(kind, signature, auth).map_err(bad)?;
        let digest = match kind {
            KIND_SCAAS => view(&self.chain, r.sell, IToken::cancelOrderDigestCall { o: r.order.clone() }).await,
            _ => view(&self.chain, self.dex, ISCaaSDex::cancelDexOrderDigestCall { sellToken: r.sell, o: trade_of(&r.order) }).await,
        }
        .map_err(down)?;
        if !self.authorized(r.sell, r.order.from, digest, &sig).await.map_err(down)? {
            return Err(bad("bad cancel signature"));
        }
        // before the book moves: an order off the book with no way to close it on chain is the failure to avoid
        let contract = if kind == KIND_SCAAS { self.contract_of(r.sell).await? } else { "dex" };
        let market_id = book.market_of(r.sell, r.order.receiveToken).map(|m| m.id).unwrap_or_default();
        let mut next = book.clone();
        next.remove(h);
        let mut commit = Commit::default();
        commit.order(market_id, &r, "cancelled");
        self.commit_or_reload(&mut book, next, commit).await?;
        if let Ok(mut q) = self.cancels.lock() {
            if q.allow(r.order.from, now()) {
                q.pending.push((market_id, Resting { auth: sig, ..r }, contract));
            }
        }
        Ok(())
    }

    /// Cancel-all of a lane: `UAInvalidateNonces(from, batch, minNonce)` with `auth` in the sell token's domain (its SCaaS
    /// orders; `from` an id) or `InvalidateNonces` with `signature` in the DEX's (every outside-token order; `from` an
    /// address). Only while the signer has an open order there (gas spam).
    pub async fn cancel_all(&self, sell: Address, from: &str, batch: U256, min: U256, signature: Option<&str>, auth: Option<&Value>)
        -> std::result::Result<usize, VenueError>
    {
        let kind = self.kind(sell);
        let sig = auth_of(kind, signature, auth).map_err(bad)?;
        let outside = kind == KIND_OUTSIDE;
        let id = if outside { crate::metatx::addr(from).map(|a| a.into_word()) } else { crate::metatx::b32(from) }.map_err(bad)?;
        let in_scope = |s: Address| if outside { self.kind(s) == KIND_OUTSIDE } else { s == sell };
        let mut book = self.book.lock().await;
        let open: Vec<Resting> = book.open_of(id).into_iter().filter(|r| r.order.batch == batch && in_scope(r.sell)).cloned().collect();
        let Some(first) = open.first() else { return Err(bad("no open order of this signer on that lane")) };
        let market_id = book.market_of(first.sell, first.order.receiveToken).map(|m| m.id).unwrap_or_default();
        let (target, digest, call) = match &sig {
            Auth::Sig(s) => {
                let from = Address::from_word(id);
                (self.dex, view(&self.chain, self.dex, ISCaaSDex::invalidateNoncesDigestCall { from, batch, newMin: min }).await,
                 ISCaaSDex::mtxInvalidateNoncesCall { from, batch, newMin: min, sig: s.clone() }.abi_encode())
            }
            Auth::Ua(a) => (sell, view(&self.chain, sell, IToken::invalidateNoncesDigestCall { from: id, batch, newMin: min }).await,
                IMtxIds::mtxInvalidateNoncesCall { from: id, batch, newMin: min, auth: a.clone() }.abi_encode()),
        };
        if !self.authorized(sell, id, digest.map_err(down)?, &sig).await.map_err(down)? {
            return Err(bad("bad invalidate signature"));
        }
        // already at or past `min` on chain (MinNonceNotIncreasing): the orders are closed, no job needed
        let job_needed = match self.call(self.relayer(), target, call.clone()).await {
            Ok(_) => true,
            Err(SimError::Revert(r)) if r.starts_with("MinNonceNotIncreasing(") => false,
            Err(e) => return Err(bad(format!("mtxInvalidateNonces refused: {e}"))),
        };
        let contract = if outside { "dex" } else { self.contract_of(sell).await? };
        let mut next = book.clone();
        let gone = next.drop_below(id, batch, min, &in_scope);
        let mut commit = Commit::default();
        for r in &gone {
            commit.order(book.market_of(r.sell, r.order.receiveToken).map(|m| m.id).unwrap_or_default(), r, "cancelled");
        }
        let allowed = self.cancels.lock().map(|mut q| q.allow(id, now())).unwrap_or(false);
        if job_needed && allowed {
            let valid_until = (now() + CANCEL_JOB_SECS).to_string();
            commit.jobs.push(invalidate_job(market_id, contract, target, id, batch, min, &sig, &valid_until));
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
        // a failed trade on a halted market (a regulated leg paused) waits, unacked, until the market reopens
        let at = now();
        let open = |ft: &&FailedTrade| !ft.makers.iter().chain(std::iter::once(&ft.taker)).filter_map(|l| l.row.as_ref()?.resting().ok())
            .any(|r| self.halted(r.sell, at).is_some() || self.halted(r.order.receiveToken, at).is_some());
        let failed: Vec<&FailedTrade> = sr.failed.iter().filter(open).collect();
        let (mut next, mut settlements, mut touched);
        let (mut round, mut give_up) = (0, false);
        loop {
            next = book.clone();
            settlements = Vec::<PlannedSettlement>::new();
            touched = Vec::<(i64, Resting)>::new();
            for ft in &failed {
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
        commit.acks.extend(failed.iter().map(|ft| ft.tag.clone()));
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

    /// C6-3: the encoded events of `logs` whose emitter may say them. A SCaaS token's order events (`UAOrderCancelled`,
    /// `UANoncesInvalidated`, R18) from a SCaaS token only (`apply_events` keeps it to the orders it sells); every other
    /// (leg, failure, an outside order's cancel and invalidation) from the DEX only. A listed outside token is not a
    /// source of any of them.
    fn accepted(&self, logs: &[alloy::rpc::types::Log]) -> Vec<Value> {
        logs.iter()
            .filter(|l| {
                let (a, Some(t)) = (l.address(), l.topic0()) else { return false };
                if *t == IToken::UAOrderCancelled::SIGNATURE_HASH || *t == IToken::UANoncesInvalidated::SIGNATURE_HASH {
                    self.kind(a) == KIND_SCAAS
                } else if REGULATED_TOPICS.contains(t) {
                    self.is_regulated(a)
                } else {
                    a == self.dex
                }
            })
            .filter_map(encode_event)
            .collect()
    }

    /// Apply accepted events to the in-memory book; the orders an `AccountFrozen` dropped, for the client store.
    fn apply_events(&self, book: &mut Book, events: &[Value]) -> Vec<Resting> {
        let mut frozen_out = vec![];
        for e in events {
            let addr_of = |k: &str| e[k].as_str().unwrap_or_default().parse::<Address>();
            match e["event"].as_str() {
                // a planned fill is final on chain: no longer pending (review T3 I1)
                Some("LegSettled" | "UALegSettled") => {
                    if let (Ok(h), Ok(sold)) = (e["order_hash"].as_str().unwrap_or_default().parse::<B256>(),
                                                 crate::metatx::uint(e["sold"].as_str().unwrap_or_default())) {
                        book.settled(h, sold);
                    }
                }
                Some("OrderCancelled") => {
                    // C6-3: the DEX cancels outside tokens' orders, a SCaaS token (`UAOrderCancelled`) only the orders it sells
                    let c = addr_of("contract").unwrap_or_default();
                    if let Ok(h) = e["order_hash"].as_str().unwrap_or_default().parse::<B256>() {
                        if book.get(h).is_some_and(|r| if c == self.dex { self.kind(r.sell) == KIND_OUTSIDE } else { r.sell == c }) {
                            book.remove(h);
                        }
                    }
                }
                // regulated-kinds spec §7, NODE-DEX-11: the market halts while a leg is paused and reopens on `Unpaused` or at
                // `pausedUntil`; a frozen account cannot send, so its orders selling that token leave the book
                Some("Paused") => self.set_paused(addr_of("contract").unwrap_or_default(), e["until"].as_u64().unwrap_or(u64::MAX)),
                Some("Unpaused") => self.set_paused(addr_of("contract").unwrap_or_default(), 0),
                Some("AccountFrozen") => {
                    let (t, a) = (addr_of("contract").unwrap_or_default(), e["account"].as_str().unwrap_or_default().parse::<B256>());
                    if let Ok(a) = a {
                        let gone: Vec<B256> = book.all().filter(|r| r.sell == t && r.order.from == a).map(|r| r.hash).collect();
                        frozen_out.extend(gone.into_iter().filter_map(|h| book.remove(h)));
                    }
                }
                Some("NoncesInvalidated") => {
                    // the DEX's `from` is an address, a SCaaS token's (`UANoncesInvalidated`) an id: the book keys both as ids
                    let f = e["from"].as_str().unwrap_or_default();
                    let from = crate::metatx::b32(f).or_else(|_| crate::metatx::addr(f).map(|a| a.into_word()));
                    if let (Ok(c), Ok(from), Ok(batch), Ok(min)) = (
                        addr_of("contract"),
                        from,
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
        frozen_out
    }

    /// Round 3s (spec §9; NODE-DEX-11; Fable P2-1, P2-2, P3-1, P3-2): what the lists' events of one round do, read live BEFORE the
    /// cursor moves and before the book lock: one `regulatedConfig` per leg; a leg whose event names the DEX or its puller, or
    /// `FeatureEnabled(8 | 9)`, gets its halt recomputed ([`Venue::venue_halted`]); an account a list event refuses, and on
    /// `FeatureEnabled(8 | 9)` every maker and receiver of the leg's orders, is dropped only if its live flag refuses it;
    /// `FeatureEnabled(28)` reruns the venue's eligibility alert. A transport error fails the round: the range is read again.
    async fn read_lists(&self, events: &[Value]) -> Result<ListPlan> {
        let venue = [self.dex.into_word(), self.puller.into_word()];
        let mut legs: std::collections::BTreeMap<Address, Vec<&Value>> = Default::default();
        for e in events.iter().filter(|e| matches!(e["event"].as_str(), Some("AllowedSet" | "DeniedSet" | "FeatureEnabled"))) {
            if let Ok(t) = e["contract"].as_str().unwrap_or_default().parse::<Address>() {
                legs.entry(t).or_default().push(e);
            }
        }
        let mut plan = ListPlan::default();
        for (t, evs) in legs {
            let c = view(&self.chain, t, IRegulatedToken::regulatedConfigCall {}).await
                .with_context(|| format!("LIST_UNREAD: regulatedConfig of {t:#x}"))?;
            let (mut halt, mut recheck, mut who) = (false, false, std::collections::BTreeSet::new());
            for e in evs {
                match list_effect(e, c.controls, venue) {
                    ListEffect::Drop(a) => _ = who.insert(a),
                    ListEffect::Venue => halt = true,
                    ListEffect::Recheck => (halt, recheck) = (true, true),
                    ListEffect::Kyc => self.alert_eligibility(t, &c).await,
                    ListEffect::None => {}
                }
            }
            if halt {
                plan.halts.push((t, self.venue_halted(t, c.controls).await?));
            }
            if recheck {
                // the accounts under a short lock, their flags read after it (Fable P2-2: no RPC under the book)
                let book = self.book.lock().await;
                who.extend(book.all().filter(|r| r.sell == t).map(|r| r.order.from)
                    .chain(book.all().filter(|r| r.order.receiveToken == t).map(receiver_of)));
            }
            for a in who {
                let f = view(&self.chain, t, IRegulatedToken::listFlagsOfCall { account: a }).await
                    .with_context(|| format!("LIST_UNREAD: listFlagsOf({a:#x}) on {t:#x}"))?;
                if !list_admits(c.controls, f) {
                    plan.drops.push((t, a));
                }
            }
        }
        Ok(plan)
    }

    /// Apply a round's [`ListPlan`] under the book lock: the halts, then the refused accounts' orders of that leg, both sides,
    /// leave the book (for the client store, as an `AccountFrozen`'s).
    fn apply_lists(&self, book: &mut Book, plan: &ListPlan) -> Vec<Resting> {
        for &(t, on) in &plan.halts {
            self.set_list_halt(t, on);
        }
        let mut out = vec![];
        for &(t, a) in &plan.drops {
            let gone: Vec<B256> = book.all().filter(|r| (r.sell == t && r.order.from == a)
                || (r.order.receiveToken == t && receiver_of(r) == a)).map(|r| r.hash).collect();
            out.extend(gone.into_iter().filter_map(|h| book.remove(h)));
        }
        out
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
            ISCaaSDex::UALegSettled::SIGNATURE_HASH,
            ISCaaSDex::MatchFailed::SIGNATURE_HASH,
            ISCaaSDex::OrderCancelled::SIGNATURE_HASH,
            ISCaaSDex::NoncesInvalidated::SIGNATURE_HASH,
            IToken::UAOrderCancelled::SIGNATURE_HASH,
            IToken::UANoncesInvalidated::SIGNATURE_HASH,
            IRegulatedToken::Paused::SIGNATURE_HASH,
            IRegulatedToken::Unpaused::SIGNATURE_HASH,
            IRegulatedToken::AccountFrozen::SIGNATURE_HASH,
            IRegulatedToken::AllowedSet::SIGNATURE_HASH,
            IRegulatedToken::DeniedSet::SIGNATURE_HASH,
            crate::abi::IGovernance::FeatureEnabled::SIGNATURE_HASH,
        ]);
        let logs = self.chain.primary().get_logs(&f).await?;
        let events = self.accepted(&logs);
        // Fable P2-2: the lists read before the cursor moves and before the book lock; unreadable, the round fails and is retried
        let lists = self.read_lists(&events).await?;
        // the regulated legs' events are the venue's own (the halt, the frozen makers): the client gets the orders' states
        let fills: Vec<&Value> = events.iter().filter(|e| !matches!(e["event"].as_str(),
            Some("Paused" | "Unpaused" | "AccountFrozen" | "AllowedSet" | "DeniedSet" | "FeatureEnabled"))).collect();
        let _: Value = idx
            .call(
                "blockchain.dex.trade",
                "dex_fill_ingest",
                json!({"evm_chain_number": self.chain.number, "from_block": from, "to_block": to,
                       "to_block_hash": format!("{hash:#x}"), "events": fills}),
            )
            .await?;
        // The client closed the orders; the book in memory follows (review D13).
        let mut book = self.book.lock().await;
        let mut frozen = self.apply_events(&mut book, &events);
        frozen.extend(self.apply_lists(&mut book, &lists));
        if !frozen.is_empty() {
            let mut commit = Commit::default();
            for r in &frozen {
                if let Some(m) = book.market_of(r.sell, r.order.receiveToken).map(|m| m.id) {
                    commit.order(m, r, "invalid");
                }
            }
            let next = book.clone();
            self.commit_or_reload(&mut book, next, commit).await.map_err(|e| anyhow!("{e}"))?;
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
        let book = self.book.lock().await;
        let (bids, asks) = book.depth(market_id, levels)?;
        let (mb, ma) = book.depth_min_fill(market_id, levels)?;
        Some(json!({"market_id": market_id, "bids": bids, "asks": asks, "min_fill": {"bids": mb, "asks": ma}}))
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

    /// `from` is an id: an address's orders of both shapes are under its zero-padded id.
    pub async fn orders_of(&self, from: B256) -> Vec<Value> {
        let book = self.book.lock().await;
        book.open_of(from)
            .into_iter()
            .map(|r| {
                json!({"order_hash": format!("{:#x}", r.hash), "sell_token": format!("{:#x}", r.sell),
                       "order": r.wire(), "remaining": r.remaining.to_string(), "state": state_of(r)})
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

/// A `mtxInvalidateNonces` job (job-api.md, R43): a token's on ids (`UAInvalidateNonces`, `auth`, a `ua_metatx` job), the
/// DEX's on an address (`InvalidateNonces`, `signature`, a `metatx` job).
#[allow(clippy::too_many_arguments)]
fn invalidate_job(market_id: i64, contract: &str, target: Address, id: B256, batch: U256, min: U256, sig: &Auth, valid_until: &str) -> Value {
    let mut op = json!({"entry": "mtxInvalidateNonces", "contract": contract, "token": format!("{target:#x}"), "validUntil": valid_until,
                        "args": {"batch": batch.to_string(), "minNonce": min.to_string()}});
    let kind = match sig {
        Auth::Ua(a) => {
            (op["args"]["from"], op["auth"]) = (json!(format!("{id:#x}")), ua_sig_json(a));
            "ua_metatx"
        }
        Auth::Sig(s) => {
            (op["args"]["from"], op["signature"]) = (json!(format!("{:#x}", Address::from_word(id))), json!(hex_of(s)));
            "metatx"
        }
    };
    json!({"kind": kind, "market_id": market_id, "op": op})
}

/// A plain DEX entry as its named op: the job carries fields, never bytes; a table row is what `abi_encode` just wrote.
fn dex_op(dex: Address, data: &[u8], valid_until: &str) -> Value {
    crate::typed::call_op("dex", dex, data, valid_until).expect("a DEX table row")
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
                "op": dex_op(dex, &ISCaaSDex::mtxSettleCall { s }.abi_encode(), &valid_until.to_string()),
                "valid_until": valid_until.to_string(),
                "tags": ss.iter().map(|s| format!("{:#x}", s.tag)).collect::<Vec<_>>(),
            })
        })
        .collect()
}

/// SCaaS-token orders (shape 1): one `mtxCancelOrder` entry job each on the sell token, `CancelUAOrder` with its `auth`, a
/// `ua_metatx` job (R43). Outside-token orders (shape 0): one `mtxCancelOrders` call on the DEX per market, at most
/// `CANCEL_BATCH` orders.
fn cancel_jobs(dex: Address, pending: &[PendingCancel]) -> Vec<Value> {
    let valid_until = (now() + CANCEL_JOB_SECS).to_string();
    let mut jobs: Vec<Value> = vec![];
    let mut outside: Vec<(i64, Address, UATradeOrder, Bytes)> = vec![];
    for (m, r, contract) in pending {
        match &r.auth {
            Auth::Ua(a) => jobs.push(json!({"kind": "ua_metatx", "market_id": m, "op": {"entry": "mtxCancelOrder",
                "struct": "CancelUAOrder", "contract": contract, "token": format!("{:#x}", r.sell),
                "args": {"order": WireOrder::from_ua(&r.order)}, "auth": ua_sig_json(a), "validUntil": valid_until}})),
            Auth::Sig(s) => outside.push((*m, r.sell, r.order.clone(), s.clone())),
        }
    }
    for m in by_market(&outside, |p| p.0) {
        for chunk in m.chunks(CANCEL_BATCH) {
            let orders = chunk.iter().map(|(_, s, o, _)| DexOrder { sellToken: *s, order: trade_of(o) }).collect();
            let sigs = chunk.iter().map(|p| p.3.clone()).collect();
            jobs.push(json!({
                "kind": "cancel", "market_id": chunk[0].0, "target": format!("{dex:#x}"),
                "op": dex_op(dex, &ISCaaSDex::mtxCancelOrdersCall { orders, sigs }.abi_encode(), &valid_until),
                "valid_until": valid_until, "tags": [],
            }));
        }
    }
    jobs
}

/// Readable DEX error (for `MatchFailed.reason` in the client); an EMPTY reason is the settlement's self-call
/// running out of gas (or an interaction's, wrapped in `InteractionFailed`), never an order's fault (P2b-2: success is not monotonic in gas).
pub fn revert_name(data: &[u8]) -> String {
    if crate::guard::reason_is_out_of_gas(data) {
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
    } else if topic0 == ISCaaSDex::UALegSettled::SIGNATURE_HASH {
        // a shape-1 leg (CTR-DEX-26): `from` / `destination` are ids (32-byte hex)
        let e = log.log_decode::<ISCaaSDex::UALegSettled>().ok()?.inner.data;
        v["event"] = json!("UALegSettled");
        v["tag"] = json!(format!("{:#x}", e.r#ref));
        v["order_hash"] = json!(format!("{:#x}", e.orderHash));
        v["from"] = json!(format!("{:#x}", e.from));
        v["destination"] = json!(format!("{:#x}", e.destination));
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
    } else if topic0 == IToken::UAOrderCancelled::SIGNATURE_HASH {
        // a SCaaS order's cancel (R18), under the name the client knows; `from` is the id (32-byte hex), as the indexer
        // sends a UA event (decisions.md, node-ua-jobs (9))
        let e = log.log_decode::<IToken::UAOrderCancelled>().ok()?.inner.data;
        v["event"] = json!("OrderCancelled");
        v["order_hash"] = json!(format!("{:#x}", e.orderHash));
        v["from"] = json!(format!("{:#x}", e.from));
    } else if topic0 == ISCaaSDex::NoncesInvalidated::SIGNATURE_HASH {
        let e = log.log_decode::<ISCaaSDex::NoncesInvalidated>().ok()?.inner.data;
        v["event"] = json!("NoncesInvalidated");
        v["from"] = json!(a(e.from));
        v["batch"] = json!(e.batch.to_string());
        v["min_nonce"] = json!(e.minNonce.to_string());
    } else if topic0 == IToken::UANoncesInvalidated::SIGNATURE_HASH {
        // a SCaaS token's lane floor (R18), as `OrderCancelled` above: `NoncesInvalidated` with the id
        let e = log.log_decode::<IToken::UANoncesInvalidated>().ok()?.inner.data;
        v["event"] = json!("NoncesInvalidated");
        v["from"] = json!(format!("{:#x}", e.from));
        v["batch"] = json!(e.batch.to_string());
        v["min_nonce"] = json!(e.minNonce.to_string());
    } else if topic0 == IRegulatedToken::Paused::SIGNATURE_HASH {
        let e = log.log_decode::<IRegulatedToken::Paused>().ok()?.inner.data;
        v["event"] = json!("Paused");
        v["until"] = json!(e.until);
    } else if topic0 == IRegulatedToken::Unpaused::SIGNATURE_HASH {
        log.log_decode::<IRegulatedToken::Unpaused>().ok()?;
        v["event"] = json!("Unpaused");
    } else if topic0 == IRegulatedToken::AccountFrozen::SIGNATURE_HASH {
        let e = log.log_decode::<IRegulatedToken::AccountFrozen>().ok()?.inner.data;
        v["event"] = json!("AccountFrozen");
        v["account"] = json!(format!("{:#x}", e.account));
        v["until"] = json!(e.until);
    } else if topic0 == IRegulatedToken::AllowedSet::SIGNATURE_HASH {
        let e = log.log_decode::<IRegulatedToken::AllowedSet>().ok()?.inner.data;
        (v["event"], v["account"], v["on"]) = (json!("AllowedSet"), json!(format!("{:#x}", e.account)), json!(e.on));
    } else if topic0 == IRegulatedToken::DeniedSet::SIGNATURE_HASH {
        let e = log.log_decode::<IRegulatedToken::DeniedSet>().ok()?.inner.data;
        (v["event"], v["account"], v["on"]) = (json!("DeniedSet"), json!(format!("{:#x}", e.account)), json!(e.on));
    } else if topic0 == crate::abi::IGovernance::FeatureEnabled::SIGNATURE_HASH {
        let e = log.log_decode::<crate::abi::IGovernance::FeatureEnabled>().ok()?.inner.data;
        (v["event"], v["bit"]) = (json!("FeatureEnabled"), json!(e.bit));
    } else {
        return None;
    }
    Some(v)
}

/// The regulated legs' events the venue reads (NODE-DEX-11), from a regulated token only; round 3s (spec §9, Fable P2-1): the
/// lists' edits and `FeatureEnabled`.
const REGULATED_TOPICS: [B256; 6] = [IRegulatedToken::Paused::SIGNATURE_HASH, IRegulatedToken::Unpaused::SIGNATURE_HASH,
    IRegulatedToken::AccountFrozen::SIGNATURE_HASH, IRegulatedToken::AllowedSet::SIGNATURE_HASH,
    IRegulatedToken::DeniedSet::SIGNATURE_HASH, crate::abi::IGovernance::FeatureEnabled::SIGNATURE_HASH];

/// `RegulatedLib`'s `controls`: the lists (bits 8, 9) and `KYC` (bit 28 in byte bit 6), round 3s.
const C_ALLOW: u8 = 1 << 3;
const C_DENY: u8 = 1 << 4;
const C_KYC: u8 = 1 << 6;

/// `L` (spec §4.2) on a `listFlagsOf` byte under `controls`: off the allow list or on the deny list is refused.
fn list_admits(controls: u8, flags: u8) -> bool {
    !(controls & C_ALLOW != 0 && flags & 1 == 0) && !(controls & C_DENY != 0 && flags & 2 != 0)
}

/// Fable P2-1: a leg's markets halt while its live list refuses the DEX or its puller (`L`, spec §4.2, on both).
fn venue_halts(controls: u8, dex: u8, puller: u8) -> bool {
    !list_admits(controls, dex) || !list_admits(controls, puller)
}

/// The account an order pays out to: its `destination`, else its maker.
fn receiver_of(r: &Resting) -> B256 {
    if r.order.destination.is_zero() { r.order.from } else { r.order.destination }
}

/// Fable P2-2: a round's list reads, made before the cursor moves and before the book lock ([`Venue::read_lists`]).
#[derive(Debug, Default, PartialEq, Eq)]
struct ListPlan {
    /// Each leg's halt, recomputed from live reads.
    halts: Vec<(Address, bool)>,
    /// (leg, account): the account's live flag refuses it; its orders on that leg leave the book.
    drops: Vec<(Address, B256)>,
}

/// Round 3s (spec §9, Fable P2-1, P3-1, P3-2, R-1, R-7): what one list event asks of its leg, against the leg's live
/// `controls`: `Drop(account)` (a refusing edit of an account while its list is on: the account's live flag is read, its orders
/// leave if it refuses), `Venue` (the DEX or its puller named: the leg's halt is recomputed), `Recheck` (`FeatureEnabled(8 | 9)`:
/// the halt and every maker and receiver of the leg read again), `Kyc` (`FeatureEnabled(28)`: the venue's eligibility alert
/// reruns), or nothing (a dormant list, a relaxing edit of another account, another bit).
#[derive(Debug, PartialEq, Eq)]
enum ListEffect {
    Drop(B256),
    Venue,
    Recheck,
    Kyc,
    None,
}

fn list_effect(e: &Value, controls: u8, venue: [B256; 2]) -> ListEffect {
    let (ev, on) = (e["event"].as_str().unwrap_or_default(), e["on"].as_bool().unwrap_or(false));
    if ev == "FeatureEnabled" {
        return match e["bit"].as_u64() {
            Some(8 | 9) => ListEffect::Recheck,
            Some(28) => ListEffect::Kyc,
            _ => ListEffect::None,
        };
    }
    let bit = match ev { "DeniedSet" => C_DENY, "AllowedSet" => C_ALLOW, _ => return ListEffect::None };
    let Ok(a) = e["account"].as_str().unwrap_or_default().parse::<B256>() else { return ListEffect::None };
    if venue.contains(&a) {
        return ListEffect::Venue; // recomputed from both flags, whatever this one event says (P2-1)
    }
    if controls & bit == 0 {
        return ListEffect::None; // R-1: a dormant list changes nothing on chain, nothing here
    }
    if (ev == "DeniedSet") == on { ListEffect::Drop(a) } else { ListEffect::None } // DeniedSet(on) or AllowedSet(off)
}

#[cfg(test)]
mod tests {
    /// Round 3s (spec 2026-11-10-token-lists.md §9, test (13); Fable P2-1, R-1, R-7; M32, M34): a list edit drops a refused
    /// account's orders only while its bit is on (a dormant list drops nothing), the reverse edit drops nothing; an edit
    /// naming the DEX or its puller halts the leg's markets and the reverse reopens them; `FeatureEnabled(8 | 9)` re-reads.
    #[test]
    fn list_effects_follow_the_live_bit() {
        use super::{list_admits, list_effect, ListEffect, C_ALLOW, C_DENY};
        use alloy::primitives::B256;
        use serde_json::json;
        let (a, dex, puller) = (B256::repeat_byte(0xa1), B256::repeat_byte(0xd1), B256::repeat_byte(0xd2));
        let ev = |name: &str, who: B256, on: bool| json!({"event": name, "account": format!("{who:#x}"), "on": on});
        let v = [dex, puller];
        assert_eq!(list_effect(&ev("DeniedSet", a, true), C_DENY, v), ListEffect::Drop(a));
        assert_eq!(list_effect(&ev("DeniedSet", a, true), C_ALLOW, v), ListEffect::None, "R-1: the deny list dormant");
        assert_eq!(list_effect(&ev("DeniedSet", a, false), C_DENY, v), ListEffect::None, "a relaxing edit");
        assert_eq!(list_effect(&ev("AllowedSet", a, false), C_ALLOW, v), ListEffect::Drop(a));
        assert_eq!(list_effect(&ev("AllowedSet", a, false), C_DENY, v), ListEffect::None, "R-1: the allow list dormant");
        assert_eq!(list_effect(&ev("AllowedSet", a, true), C_ALLOW, v), ListEffect::None);
        // Fable P2-1: an event naming the venue's contracts never sets the halt itself; it is recomputed from both live flags
        for who in v {
            for (name, on, controls) in [("DeniedSet", true, C_DENY), ("DeniedSet", false, C_DENY), ("AllowedSet", true, C_ALLOW),
                ("AllowedSet", false, C_ALLOW), ("DeniedSet", true, C_ALLOW)] {
                assert_eq!(list_effect(&ev(name, who, on), controls, v), ListEffect::Venue, "R-7: {name}({on})");
            }
        }
        assert_eq!(list_effect(&json!({"event": "FeatureEnabled", "bit": 9}), 0, v), ListEffect::Recheck);
        assert_eq!(list_effect(&json!({"event": "FeatureEnabled", "bit": 8}), 0, v), ListEffect::Recheck);
        assert_eq!(list_effect(&json!({"event": "FeatureEnabled", "bit": 28}), 0, v), ListEffect::Kyc, "Fable P3-2");
        assert_eq!(list_effect(&json!({"event": "FeatureEnabled", "bit": 27}), 0, v), ListEffect::None);
        // the halt: either contract refused halts the leg (P2-1 (b): never the last one read)
        use super::venue_halts;
        assert!(!venue_halts(C_DENY, 0, 0) && venue_halts(C_DENY, 2, 0) && venue_halts(C_DENY, 0, 2));
        assert!(!venue_halts(C_ALLOW | C_DENY, 1, 1) && venue_halts(C_ALLOW | C_DENY, 3, 1) && venue_halts(C_ALLOW, 1, 0));
        assert!(list_admits(0, 0) && list_admits(C_ALLOW, 1) && !list_admits(C_ALLOW, 0) && !list_admits(C_DENY, 2));
        assert!(list_admits(C_DENY, 1) && !list_admits(C_ALLOW | C_DENY, 3));
    }

    /// T5 minor: an interaction out of gas inside a batch plan is `InteractionFailed(i, target, "")`, read as out_of_gas.
    #[test]
    fn a_wrapped_empty_interaction_revert_is_out_of_gas() {
        let e = |r: &[u8]| ISCaaSDex::InteractionFailed { index: alloy::primitives::U256::from(2), target: Address::repeat_byte(7), reason: r.to_vec().into() }.abi_encode();
        assert_eq!(revert_name(&[]), "out_of_gas");
        assert_eq!(revert_name(&e(&[])), "out_of_gas");
        assert!(revert_name(&e(&[1, 2])).starts_with("InteractionFailed"));
    }
    use super::*;
    use alloy::primitives::LogData;
    use alloy::sol_types::SolError;
    use crate::abi::UASig;

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

    /// CTR-DEX-26: a shape-1 leg's event carries ids; the client reads the same keys as `LegSettled`.
    #[test]
    fn ua_leg_settled_is_encoded_with_ids() {
        let ev = ISCaaSDex::UALegSettled {
            r#ref: B256::repeat_byte(1),
            orderHash: B256::repeat_byte(2),
            from: B256::repeat_byte(3),
            destination: B256::repeat_byte(4),
            sold: U256::from(100),
            received: U256::from(199),
            dexFee: U256::from(1),
            refund: U256::from(5),
            relayerShare: U256::ZERO,
            treasuryShare: U256::from(1),
        };
        let v = encode_event(&log_of(ev.encode_log_data())).unwrap();
        assert_eq!((v["event"].as_str(), v["sold"].as_str(), v["refund"].as_str()), (Some("UALegSettled"), Some("100"), Some("5")));
        assert_eq!(v["order_hash"], format!("{:#x}", B256::repeat_byte(2)));
        assert_eq!(v["from"], format!("{:#x}", B256::repeat_byte(3)));
        assert_eq!(v["destination"], format!("{:#x}", B256::repeat_byte(4)));
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
        // a SCaaS token's order events (R18) under the names the client knows, `from` the id
        let ev = IToken::UAOrderCancelled { orderHash: B256::repeat_byte(7), from: B256::repeat_byte(8) };
        let v = encode_event(&log_of(ev.encode_log_data())).unwrap();
        assert_eq!((v["event"].as_str(), v["from"].clone()), (Some("OrderCancelled"), json!(format!("{:#x}", B256::repeat_byte(8)))));
        let ev = IToken::UANoncesInvalidated { from: B256::repeat_byte(8), batch: U256::from(2), minNonce: U256::from(9) };
        let v = encode_event(&log_of(ev.encode_log_data())).unwrap();
        assert_eq!((v["event"].as_str(), v["from"].clone()), (Some("NoncesInvalidated"), json!(format!("{:#x}", B256::repeat_byte(8)))));
    }

    #[test]
    fn cancel_rate_limit_is_per_signer_and_per_hour() {
        let mut q = CancelQueue::default();
        let m = B256::repeat_byte(1);
        for _ in 0..ONCHAIN_CANCELS_PER_HOUR {
            assert!(q.allow(m, 1000));
        }
        assert!(!q.allow(m, 1000));
        assert!(q.allow(B256::repeat_byte(2), 1000));
        assert!(q.allow(m, 1000 + 3600));
    }

    const BASE: Address = Address::repeat_byte(0xaa);
    const QUOTE: Address = Address::repeat_byte(0xbb);

    fn rest(from: u8, sell: Address, receive: Address) -> Resting {
        let order = UATradeOrder {
            from: Address::repeat_byte(from).into_word(),
            receiveToken: receive,
            amount: U256::from(1000),
            receiveAmount: U256::from(1000),
            minFill: U256::ZERO,
            fee: U256::ZERO,
            relayer: Address::ZERO,
            dex: Address::ZERO,
            destination: B256::ZERO,
            flags: 0,
            batch: U256::ZERO,
            nonce: U256::ZERO,
            validUntil: U256::from(from),
        };
        Resting { hash: B256::repeat_byte(from), sell, order, auth: Auth::Ua(ua(Bytes::new())), remaining: U256::from(1000), seq: 0 }
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
        // the shape says where a cancel goes: a SCaaS order (shape 1) to its token as `CancelUAOrder` on a `ua_metatx` job, an
        // outside one (shape 0) to the DEX's `mtxCancelOrders`
        let sig = Bytes::from(vec![0x11; 65]);
        let c = |m: i64, from: u8, auth: Auth| (m, Resting { auth, ..rest(from, BASE, QUOTE) }, "token");
        let jobs = cancel_jobs(dex, &[c(1, 1, Auth::Ua(ua(sig.clone()))), c(2, 2, Auth::Sig(sig.clone())), c(1, 3, Auth::Sig(sig.clone()))]);
        let kinds: Vec<(&str, i64)> = jobs.iter().map(|j| (j["kind"].as_str().unwrap(), j["market_id"].as_i64().unwrap())).collect();
        assert_eq!(kinds, vec![("ua_metatx", 1), ("cancel", 1), ("cancel", 2)]);
        let op = &jobs[0]["op"];
        assert_eq!((op["entry"].as_str(), op["struct"].as_str(), op["token"].as_str()),
            (Some("mtxCancelOrder"), Some("CancelUAOrder"), Some(&*format!("{BASE:#x}"))));
        assert_eq!((op["args"]["order"]["from"].clone(), op["auth"]["signature"].clone()),
            (json!(format!("{:#x}", Address::repeat_byte(1).into_word())), json!(hex_of(&sig))));
        assert!(op.get("signature").is_none(), "no address form");
        assert_eq!(jobs[1]["target"], format!("{dex:#x}"));
        for j in &jobs {
            assert!(j.get("calldata").is_none(), "named fields, never hex");
            let (_, ua) = crate::submit::work_of_op(None, &j["op"], None).unwrap_or_else(|e| panic!("{j}: {e:#}"));
            assert_eq!(ua, j["kind"] == "ua_metatx", "R43: the job kind of the entry, {j}");
        }
    }

    // ------------------------------------------------------------------ the venue on a fake chain (review T3 C1, I2)

    use std::collections::HashSet;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use alloy::sol_types::SolValue;

    const DEX: Address = Address::repeat_byte(0xd0);

    /// A chain where each leg's fate is scripted by its order hash (`keccak(abi(order))` of the `UATradeOrder`, as the fake
    /// token's `tradeOrderDigest` answers; a shape-0 leg's `TradeOrder` has the same words). `mtxSettle` fails a settlement holding any failing leg; `settleOne` reverts as the
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
        /// The token's `eip712Domain().name`; `None`: it does not answer.
        domain: Option<&'static str>,
        /// `(from, to, gas)` of every `isValidSignature` call.
        sig_calls: Vec<(Address, Address, u64)>,
        /// `isValidSignature` of this signer answers this JSON-RPC error instead.
        sig_errors: HashMap<Address, Value>,
        /// In a settlement the leg reverts with words that are no order hash (`MetaTxInsufficientForFee(1, 0)`), and its
        /// own `mtxTrade` reverts too.
        wordy: HashSet<B256>,
        /// Tokens without `mtxTrade` (an outside token): every `mtxTrade` on them reverts.
        no_trade: HashSet<Address>,
        /// `eth_getLogs` answers these whose `topic0` the filter asks for (the watcher's final range is blocks 6..=10).
        logs: Vec<Value>,
        /// The tokens' `registry()` (0 = none).
        registry: Address,
        /// The digests the registry's `requireAuthorized` accepts (any other reverts `UAUnauthorized`).
        authorized: HashSet<B256>,
        /// A regulated token's `regulatedConfig()` (`complianceRegistry` = `REG_REGISTRY`): `(controls, requiredFlags,
        /// deniedFlags, pausedUntil)`.
        reg: HashMap<Address, (u8, u64, u64, u64)>,
        /// `isFrozen` on every regulated token.
        frozen: HashSet<B256>,
        /// Round 3s: `listFlagsOf` on every regulated token (absent: 0).
        lists: HashMap<B256, u8>,
        /// `REG_REGISTRY.complianceOf`: `(flags, validUntil)`, provider 0 (the admin, enabled); absent: `(0, 0)`.
        attest: HashMap<B256, (u64, u64)>,
        /// The leg on this token reverts `TokenPaused(until)`, in a settlement and in its own `mtxTrade` (a pause that lands after
        /// the intake read).
        trade_paused: HashMap<Address, u64>,
        /// Fable P2-2: `regulatedConfig` and `listFlagsOf` answer a transport error (an RPC blip).
        lists_down: bool,
    }
    const REG_REGISTRY: Address = Address::repeat_byte(0xc0);
    type W = Arc<std::sync::Mutex<World>>;

    fn oh(o: &UATradeOrder) -> B256 {
        keccak256(o.abi_encode())
    }

    /// A native id's `UASig`: its signature only (R17).
    fn ua(signature: Bytes) -> UASig {
        UASig { keyData: Bytes::new(), signature, members: vec![] }
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
                "eth_getLogs" => {
                    let asked = p[0]["topics"][0].clone();
                    let asked = asked.as_array().cloned().unwrap_or_else(|| vec![asked]);
                    Ok(Value::Array(w.logs.iter().filter(|l| asked.contains(&l["topics"][0])).cloned().collect()))
                }
                "eth_call" => {
                    let input = alloy::hex::decode(&p[0]["input"].as_str().or(p[0]["data"].as_str()).unwrap()[2..]).unwrap();
                    let to: Address = p[0]["to"].as_str().unwrap().parse().unwrap();
                    let from: Address = p[0]["from"].as_str().map_or(Address::ZERO, |f| f.parse().unwrap());
                    let sel: [u8; 4] = input[..4].try_into().unwrap();
                    let word = |v: U256| hexs(&v.abi_encode());
                    let fails = |w: &World, sell: Address, o: &UATradeOrder| -> Option<Vec<u8>> {
                        let h = if sell == BASE || sell == QUOTE { oh(o) } else { B256::ZERO };
                        if let Some(until) = w.trade_paused.get(&sell) {
                            Some(IRegulatedToken::TokenPaused { until: *until }.abi_encode())
                        } else if w.named.contains(&h) {
                            Some(IToken::BelowMinFill { orderHash: h }.abi_encode())
                        } else if w.bad_sig.contains(&h) || w.silent.contains(&h) {
                            Some(IToken::MetaTxBadSignature {}.abi_encode())
                        } else if w.wordy.contains(&h) || w.unfunded.contains(&Address::from_word(o.from)) {
                            Some(IToken::MetaTxInsufficientForFee { needed: U256::from(1), available: U256::ZERO }.abi_encode())
                        } else {
                            None
                        }
                    };
                    let legs = |s: &crate::abi::Settlement| -> Vec<(Address, UATradeOrder)> {
                        std::iter::once(&s.taker).chain(&s.makers).map(|l| {
                            assert!(l.shape <= 1);
                            (l.sellToken, if l.shape == 1 { l.uaOrder.clone() } else { super::super::canon(&l.order) })
                        }).collect()
                    };
                    if sel == IToken::tradeOrderDigestCall::SELECTOR {
                        Ok(hexs(oh(&IToken::tradeOrderDigestCall::abi_decode(&input).unwrap().o).as_slice()))
                    } else if sel == IToken::pulledCall::SELECTOR || sel == IToken::minNonceCall::SELECTOR
                        || sel == ISCaaSDex::minNonceCall::SELECTOR {
                        Ok(word(U256::ZERO))
                    } else if sel == IToken::balanceOfCall::SELECTOR {
                        let who = IToken::balanceOfCall::abi_decode(&input).unwrap().who;
                        Ok(word(if w.unfunded.contains(&who) { U256::ZERO } else { U256::from(10u64).pow(U256::from(30)) }))
                    } else if sel == IUALedger::balanceOfUACall::SELECTOR || sel == IToken::allowanceCall::SELECTOR {
                        Ok(word(U256::from(10u64).pow(U256::from(30))))
                    } else if sel == IUALedger::registryCall::SELECTOR {
                        Ok(hexs(&w.registry.abi_encode()))
                    } else if sel == IUARegistry::requireAuthorizedCall::SELECTOR {
                        let c = IUARegistry::requireAuthorizedCall::abi_decode(&input).unwrap();
                        assert!((from == BASE || from == QUOTE) && c.purposeTag == PURPOSE_TRADE, "asked as the token, under trade");
                        if w.authorized.contains(&c.digest) { Ok(hexs(&[])) } else { revert(IUALedger::UAUnauthorized { ua: c.ua }.abi_encode()) }
                    } else if sel == IToken::invalidateNoncesDigestCall::SELECTOR {
                        let c = IToken::invalidateNoncesDigestCall::abi_decode(&input).unwrap();
                        Ok(hexs(keccak256((c.from, c.batch, c.newMin).abi_encode()).as_slice()))
                    } else if sel == IMtxIds::mtxInvalidateNoncesCall::SELECTOR {
                        Ok(hexs(&[]))
                    } else if sel == IToken::cancelOrderDigestCall::SELECTOR {
                        Ok(word(U256::from_be_bytes(oh(&IToken::cancelOrderDigestCall::abi_decode(&input).unwrap().o).0)))
                    } else if sel == IToken::eip712DomainCall::SELECTOR {
                        match w.domain {
                            Some(name) => Ok(hexs(&IToken::eip712DomainCall::abi_encode_returns(&IToken::eip712DomainReturn {
                                fields: alloy::primitives::FixedBytes([0x1f]), name: name.into(), version: "1".into(), chainId: U256::from(7622),
                                verifyingContract: to, salt: B256::ZERO, extensions: vec![] }))),
                            None => revert(vec![]),
                        }
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
                        if let Some(until) = w.trade_paused.get(&to) {
                            revert(IRegulatedToken::TokenPaused { until: *until }.abi_encode())
                        } else if w.bad_sig.contains(&h) || w.wordy.contains(&h) || w.no_trade.contains(&to) {
                            revert(IToken::MetaTxBadSignature {}.abi_encode())
                        } else {
                            Ok(hexs(&[]))
                        }
                    } else if sel == IERC165::supportsInterfaceCall::SELECTOR {
                        Ok(hexs(&w.reg.contains_key(&to).abi_encode()))
                    } else if w.lists_down && (sel == IRegulatedToken::regulatedConfigCall::SELECTOR
                        || sel == IRegulatedToken::listFlagsOfCall::SELECTOR) {
                        Err(json!({"code": -32603, "message": "upstream unavailable"}))
                    } else if sel == IRegulatedToken::regulatedConfigCall::SELECTOR {
                        let (controls, required, denied, paused) = w.reg[&to];
                        Ok(hexs(&IRegulatedToken::regulatedConfigCall::abi_encode_returns(&IRegulatedToken::RegulatedConfig {
                            complianceRegistry: REG_REGISTRY, controls, requiredFlags: required, deniedFlags: denied, termsHash: B256::ZERO,
                            pausedUntil: paused, pauseCooldownUntil: 0 })))
                    } else if sel == IRegulatedToken::listFlagsOfCall::SELECTOR {
                        assert!(w.reg.contains_key(&to));
                        let a = IRegulatedToken::listFlagsOfCall::abi_decode(&input).unwrap().account;
                        Ok(hexs(&U256::from(w.lists.get(&a).copied().unwrap_or_default()).abi_encode()))
                    } else if sel == IRegulatedToken::isFrozenCall::SELECTOR {
                        assert!(w.reg.contains_key(&to));
                        let a = IRegulatedToken::isFrozenCall::abi_decode(&input).unwrap().account;
                        Ok(hexs(&w.frozen.contains(&a).abi_encode()))
                    } else if sel == IComplianceRegistry::complianceOfCall::SELECTOR {
                        assert_eq!(to, REG_REGISTRY);
                        let a = IComplianceRegistry::complianceOfCall::abi_decode(&input).unwrap().account;
                        let (f, v) = w.attest.get(&a).copied().unwrap_or_default();
                        Ok(hexs(&(f, v, 0u32).abi_encode()))
                    } else if sel == IComplianceRegistry::kycProviderEnabledCall::SELECTOR {
                        Ok(hexs(&true.abi_encode()))
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

    fn order(from: Address, receive: Address, amount: u64, receive_amount: u64, nonce: u64) -> UATradeOrder {
        UATradeOrder {
            from: from.into_word(), receiveToken: receive, amount: U256::from(amount), receiveAmount: U256::from(receive_amount),
            minFill: U256::ZERO, fee: U256::ZERO, relayer: relayer_key().address(), dex: DEX, destination: B256::ZERO,
            flags: 0, batch: U256::from(1), nonce: U256::from(nonce), validUntil: U256::from(now() + 300),
        }
    }

    fn sig_of(k: &PrivateKeySigner, h: B256) -> Bytes {
        Bytes::from(k.sign_hash_sync(&h).unwrap().as_bytes().to_vec())
    }

    /// A venue on the fake chain whose book holds `makers` (asks, best first by price as inserted).
    async fn venue(w: World, makers: Vec<(UATradeOrder, Bytes)>) -> (Venue, W) {
        let (url, world) = fake_chain(w).await;
        let cfg = crate::config::ChainCfg { family: "evm".into(), evm_chain_number: 31337, rpc_urls: vec![url],
                                            chain_uid: Some(B256::repeat_byte(0x24)), ..Default::default() };
        let chain = Arc::new(Chain::with_signer(&cfg, relayer_key()).unwrap());
        let (relay, _) = crate::adapter::tests::fake_odoo(Default::default()).await;
        let mut book = Book::new(vec![market()]);
        for (i, (o, sig)) in makers.into_iter().enumerate() {
            book.insert(Resting { hash: oh(&o), sell: BASE, remaining: o.amount, order: o, auth: Auth::Ua(ua(sig)), seq: i as u64 + 1 });
        }
        book.next_seq = 100;
        let v = Venue { chain, relay, indexer: None, dex: DEX, puller: Address::repeat_byte(0x9),
            kinds: [(BASE, KIND_SCAAS), (QUOTE, KIND_SCAAS)].into_iter().collect(), clone_codehash: None,
            book: Mutex::new(book), trades: Default::default(), cancels: Default::default(), regulated: Default::default(),
            list_halted: Default::default(),
            registry: None };
        (v, world)
    }

    async fn take(v: &Venue, k: &PrivateKeySigner, quote: u64, base: u64, nonce: u64) -> std::result::Result<PlaceReply, VenueError> {
        let o = order(k.address(), BASE, quote, base, nonce);
        v.place(QUOTE, &WireOrder::from_ua(&o), None, Some(&ua_sig_json(&ua(sig_of(k, oh(&o)))))).await
    }

    fn in_book(rows: &[Row], o: &UATradeOrder) -> bool {
        rows.iter().any(|r| r.order_hash == format!("{:#x}", oh(o)))
    }

    fn log_at(addr: Address, data: LogData) -> Log {
        let mut l = log_of(data);
        l.inner.address = addr;
        l
    }

    /// A venue whose BASE is a regulated leg (`controls`, `required`, `denied`, open), on the configured registry.
    async fn regulated_venue(mut w: World, controls: u8, required: u64, denied: u64, makers: Vec<(UATradeOrder, Bytes)>) -> (Venue, W) {
        w.reg.insert(BASE, (controls, required, denied, 0));
        let (mut v, world) = venue(w, makers).await;
        v.registry = Some(REG_REGISTRY);
        v.set_paused(BASE, 0);
        (v, world)
    }

    /// Regulated-kinds spec §7 (F-16): a market with a regulated leg halts on `Paused` — intake refuses `PAUSED`, nothing is
    /// matched or simulated, the resting maker stays — and reopens on `Unpaused`, or at `pausedUntil` with no event at all.
    #[tokio::test]
    async fn market_halts_on_paused_and_reopens() {
        let (m, t) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let ask = order(m.address(), QUOTE, 10, 30, 1);
        let (v, w) = regulated_venue(World::default(), 0, 0, 0, vec![(ask.clone(), sig_of(&m, oh(&ask)))]).await;
        let until = now() + 3_600;
        w.lock().unwrap().reg.get_mut(&BASE).unwrap().3 = until;
        let paused = log_at(BASE, IRegulatedToken::Paused { r#ref: B256::repeat_byte(1), until }.encode_log_data());
        let events = v.accepted(&[paused]);
        assert_eq!(events.len(), 1, "a regulated leg's Paused is read");
        v.apply_events(&mut *v.book.lock().await, &events);
        assert_eq!(v.halted(BASE, now()), Some(until));
        let err = take(&v, &t, 30, 10, 1).await.unwrap_err();
        assert!(matches!(&err, VenueError::Bad(e) if e.starts_with("PAUSED")), "{err}");
        assert!(in_book(&v.rows().await, &ask), "the maker rests through the pause");
        // a failed trade on the halted market waits, unacked, until the market reopens
        let row = Row::of(&Resting { hash: oh(&ask), sell: BASE, order: ask.clone(), auth: Auth::Ua(ua(sig_of(&m, oh(&ask)))),
            remaining: ask.amount, seq: 1 });
        let (relay, store) = crate::adapter::tests::fake_odoo(crate::adapter::tests::Fake {
            dex_sync: json!({"failed": [{"tag": "0x01", "taker": {"row": null, "fill": "30"}, "makers": [{"row": row, "fill": "10"}]}]}),
            ..Default::default()
        }).await;
        let v = Venue { relay, ..v };
        v.sync_once().await.unwrap();
        assert!(store.lock().unwrap().commits.iter().all(|c| c["acks"].as_array().is_none_or(|a| a.is_empty())), "not acked while halted");
        // reopens on Unpaused
        w.lock().unwrap().reg.get_mut(&BASE).unwrap().3 = now();
        let unpaused = log_at(BASE, IRegulatedToken::Unpaused { r#ref: B256::repeat_byte(1) }.encode_log_data());
        v.apply_events(&mut *v.book.lock().await, &v.accepted(&[unpaused]));
        assert_eq!(v.halted(BASE, now()), None);
        assert_eq!(take(&v, &t, 30, 10, 2).await.unwrap().status, "filled");
        // and at pausedUntil, passively
        v.set_paused(BASE, now() + 10);
        assert!(v.halted(BASE, now()).is_some() && v.halted(BASE, now() + 10).is_none());
    }

    /// F-16: a settlement that reverts `TokenPaused` (a pause that landed after the intake read) is never the maker's fault:
    /// no order is marked invalid or dropped, the market halts until the revert's `until`, and the taker is refused `PAUSED`.
    #[tokio::test]
    async fn token_paused_not_grief_scored() {
        let (m, t) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let ask = order(m.address(), QUOTE, 10, 30, 1);
        let until = now() + 600;
        let w = World { trade_paused: [(BASE, until)].into_iter().collect(), ..Default::default() };
        let (v, _) = regulated_venue(w, 0, 0, 0, vec![(ask.clone(), sig_of(&m, oh(&ask)))]).await;
        let err = take(&v, &t, 30, 10, 1).await.unwrap_err();
        assert!(matches!(&err, VenueError::Bad(e) if e.starts_with("PAUSED")), "{err}");
        assert!(in_book(&v.rows().await, &ask), "the maker is not blamed");
        assert_eq!(v.halted(BASE, now()), Some(until), "the market halts until the revert's until");
    }

    /// NODE-DEX-11's intake pre-check on a regulated leg, each refusal by name, nothing matched: the seller frozen on the token it
    /// sells; the receiver not eligible on the token it buys (`canReceive`'s reason); an order outliving its receiver's
    /// attestation; the venue itself not attested (never assumed: an operator step of the registry admin, owner 2026-11-06);
    /// a list on with no `compliance_registry` configured. An eligible pair trades.
    #[tokio::test]
    async fn regulated_leg_precheck_refuses_by_name() {
        let (m, t) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let (kyc, eligible, max) = (1u64, 8u64, u64::MAX);
        let ask = order(m.address(), QUOTE, 10, 30, 1);
        let attest = |who: &[(Address, u64, u64)]| who.iter().map(|(a, f, v)| (a.into_word(), (*f, *v))).collect::<HashMap<_, _>>();
        let ok_world = || World { attest: attest(&[(DEX, eligible, max), (t.address(), kyc, max)]), ..Default::default() };
        let refused = |r: std::result::Result<PlaceReply, VenueError>| match r {
            Err(VenueError::Bad(e)) => e,
            other => panic!("{:?}", other.map(|p| p.status)),
        };
        // the taker sells QUOTE (plain) and buys BASE (regulated, round 3s: KYC = controls bit 6, KYC required)
        let (v, _) = regulated_venue(World { attest: attest(&[(DEX, eligible, max)]), ..ok_world() }, 64, kyc, 0, vec![(ask.clone(), sig_of(&m, oh(&ask)))]).await;
        let e = refused(take(&v, &t, 30, 10, 1).await);
        assert!(e.starts_with("NOT_ELIGIBLE") && e.contains("reason 1"), "{e}");
        let (v, _) = regulated_venue(World { attest: attest(&[(DEX, eligible, max), (t.address(), kyc, now() + 60)]), ..ok_world() }, 64, kyc, 0,
            vec![(ask.clone(), sig_of(&m, oh(&ask)))]).await;
        assert!(refused(take(&v, &t, 30, 10, 1).await).starts_with("ATTESTATION_SHORTER"));
        let (v, _) = regulated_venue(World { attest: attest(&[(t.address(), kyc, max)]), ..ok_world() }, 64, kyc, 0,
            vec![(ask.clone(), sig_of(&m, oh(&ask)))]).await;
        assert!(refused(take(&v, &t, 30, 10, 1).await).starts_with("VENUE_NOT_ELIGIBLE"));
        let (mut v, _) = regulated_venue(ok_world(), 64, kyc, 0, vec![(ask.clone(), sig_of(&m, oh(&ask)))]).await;
        v.registry = None;
        assert!(refused(take(&v, &t, 30, 10, 1).await).starts_with("REGISTRY_NOT_CONFIGURED"));
        // a frozen seller of the regulated leg: the taker selling BASE
        let bid = order(m.address(), BASE, 30, 10, 1);
        let (v, _) = regulated_venue(World { frozen: [t.address().into_word()].into_iter().collect(), ..ok_world() }, 0, 0, 0, vec![]).await;
        v.book.lock().await.insert(Resting { hash: oh(&bid), sell: QUOTE, remaining: bid.amount, order: bid.clone(), auth: Auth::Ua(ua(sig_of(&m, oh(&bid)))), seq: 1 });
        let sell_base = order(t.address(), QUOTE, 10, 30, 1);
        let e = refused(v.place(BASE, &WireOrder::from_ua(&sell_base), None, Some(&ua_sig_json(&ua(sig_of(&t, oh(&sell_base)))))).await);
        assert!(e.starts_with("FROZEN"), "{e}");
        // eligible: trades
        let (v, _) = regulated_venue(ok_world(), 64, kyc, 0, vec![(ask.clone(), sig_of(&m, oh(&ask)))]).await;
        assert_eq!(take(&v, &t, 30, 10, 1).await.unwrap().status, "filled");
        // round 3s (spec 2026-11-10-token-lists.md §9): the lists, both parties, no registry: the receiver denied on the
        // leg it buys (DENYLIST = 16), the DEX not on the allow list (ALLOWLIST = 8), each refused by name; listed, it trades
        let (v, _) = regulated_venue(World { lists: [(t.address().into_word(), 2)].into_iter().collect(), ..ok_world() }, 16, 0, 0,
            vec![(ask.clone(), sig_of(&m, oh(&ask)))]).await;
        let e = refused(take(&v, &t, 30, 10, 1).await);
        assert!(e.starts_with("DENIED") && e.contains(&format!("{:#x}", t.address().into_word())), "{e}");
        let (v, _) = regulated_venue(World { lists: [(t.address().into_word(), 1)].into_iter().collect(), ..ok_world() }, 8, 0, 0,
            vec![(ask.clone(), sig_of(&m, oh(&ask)))]).await;
        let e = refused(take(&v, &t, 30, 10, 1).await);
        assert!(e.starts_with("NOT_ALLOWED") && e.contains(&format!("{:#x}", DEX.into_word())), "{e}");
        let all = [t.address(), DEX, v.puller].iter().map(|a| (a.into_word(), 1u8)).collect();
        let (v, _) = regulated_venue(World { lists: all, ..ok_world() }, 8, 0, 0, vec![(ask.clone(), sig_of(&m, oh(&ask)))]).await;
        assert_eq!(take(&v, &t, 30, 10, 1).await.unwrap().status, "filled");
    }

    /// Fable P2-1, P2-2, P3-1 (spec 2026-11-10-token-lists.md §9): the list halt is computed from live reads, never toggled by one
    /// event: (a) with both lists on, `AllowedSet(dex, true)` keeps the halt while the DEX is still denied; (b) the puller
    /// relaxed keeps it while the DEX is refused; it reopens once both are admitted; (c) a restart reads it. A refusing edit of
    /// a maker drops its orders only if its live flag refuses it (undone at the next block: it stays).
    #[tokio::test]
    async fn list_halt_is_computed_from_live_reads() {
        let m = PrivateKeySigner::random();
        let ask = order(m.address(), QUOTE, 10, 30, 1);
        let (dex, a) = (DEX.into_word(), m.address().into_word());
        let both = C_ALLOW | C_DENY;
        let w = World { lists: [(dex, 3), (Address::repeat_byte(0x9).into_word(), 1)].into_iter().collect(), ..Default::default() };
        let (v, world) = regulated_venue(w, both, 0, 0, vec![(ask.clone(), sig_of(&m, oh(&ask)))]).await;
        let v = &v;
        let list = |name: &str, who: B256, on: bool| {
            let d = if name == "AllowedSet" { IRegulatedToken::AllowedSet { account: who, by: B256::ZERO, on }.encode_log_data() }
                    else { IRegulatedToken::DeniedSet { account: who, by: B256::ZERO, on }.encode_log_data() };
            v.accepted(&[log_at(BASE, d)])
        };
        let round = |events: Vec<Value>| async move {
            let plan = v.read_lists(&events).await.unwrap();
            v.apply_lists(&mut *v.book.lock().await, &plan);
        };
        // (c) at start
        v.load_regulated().await.unwrap();
        assert_eq!(v.halted(BASE, now()), Some(u64::MAX), "a restart while the DEX is denied keeps the halt");
        // (a) the allow edit of a denied DEX
        round(list("AllowedSet", dex, true)).await;
        assert_eq!(v.halted(BASE, now()), Some(u64::MAX), "(a) still denied");
        // (b) the puller relaxed, the DEX still refused
        round(list("DeniedSet", Address::repeat_byte(0x9).into_word(), false)).await;
        assert_eq!(v.halted(BASE, now()), Some(u64::MAX), "(b) the DEX still refused");
        world.lock().unwrap().lists.insert(dex, 1);
        round(list("DeniedSet", dex, false)).await;
        assert_eq!(v.halted(BASE, now()), None, "both admitted: reopens");
        // P3-1: a maker's refusing edit undone by the live state stays; refused live, it leaves
        world.lock().unwrap().lists.insert(a, 1);
        round(list("DeniedSet", a, true)).await;
        assert!(in_book(&v.rows().await, &ask), "the live flag admits it");
        world.lock().unwrap().lists.insert(a, 3);
        round(list("DeniedSet", a, true)).await;
        assert!(!in_book(&v.rows().await, &ask), "the live flag refuses it");
    }

    /// Fable P2-2: a list event whose leg cannot be read fails the watcher round BEFORE the client ingests the range (the cursor
    /// does not move; the same range is read again), never skipped; read, the round goes through.
    #[tokio::test]
    async fn an_unreadable_list_fails_the_round_before_the_cursor() {
        let m = PrivateKeySigner::random();
        let ask = order(m.address(), QUOTE, 10, 30, 1);
        let (v, world) = regulated_venue(World { lists_down: true, ..Default::default() }, C_DENY, 0, 0,
            vec![(ask.clone(), sig_of(&m, oh(&ask)))]).await;
        let ev = IRegulatedToken::DeniedSet { account: m.address().into_word(), by: B256::ZERO, on: true }.encode_log_data();
        world.lock().unwrap().logs.push(serde_json::to_value(log_at(BASE, ev)).unwrap());
        let (idx, o) = crate::adapter::tests::fake_odoo(crate::adapter::tests::Fake { tokens: json!([]), ..Default::default() }).await;
        let v = Venue { indexer: Some(idx), ..v };
        let e = v.watch_once().await.unwrap_err();
        assert!(format!("{e:#}").contains("LIST_UNREAD"), "{e:#}");
        assert_eq!(o.lock().unwrap().ingests, 1, "dex_cursor only: dex_fill_ingest never ran");
        assert!(in_book(&v.rows().await, &ask));
        world.lock().unwrap().lists_down = false;
        world.lock().unwrap().lists.insert(m.address().into_word(), 2);
        assert!(v.watch_once().await.unwrap());
        assert_eq!(o.lock().unwrap().ingests, 3, "the same range, ingested once read");
        assert!(!in_book(&v.rows().await, &ask), "the denied maker left");
    }

    /// Spec §7: an `AccountFrozen` of a regulated leg drops that account's orders selling it (a frozen account cannot send);
    /// its orders buying it stay (credits are never refused for a freeze), and another token's event drops nothing.
    #[tokio::test]
    async fn account_frozen_drops_the_makers_orders() {
        let m = PrivateKeySigner::random();
        let ask = order(m.address(), QUOTE, 10, 30, 1);
        let (v, _) = regulated_venue(World::default(), 0, 0, 0, vec![(ask.clone(), sig_of(&m, oh(&ask)))]).await;
        let bid = order(m.address(), BASE, 30, 10, 2);
        v.book.lock().await.insert(Resting { hash: oh(&bid), sell: QUOTE, remaining: bid.amount, order: bid.clone(), auth: Auth::Ua(ua(sig_of(&m, oh(&bid)))), seq: 9 });
        let frozen = |token: Address| log_at(token, IRegulatedToken::AccountFrozen { account: m.address().into_word(), r#ref: B256::repeat_byte(1),
            recordId: B256::ZERO, until: now() + 60 }.encode_log_data());
        v.apply_events(&mut *v.book.lock().await, &v.accepted(&[frozen(QUOTE)]));
        assert!(in_book(&v.rows().await, &ask), "QUOTE is no regulated leg: not its event");
        v.apply_events(&mut *v.book.lock().await, &v.accepted(&[frozen(BASE)]));
        let rows = v.rows().await;
        assert!(!in_book(&rows, &ask) && in_book(&rows, &bid), "the order selling BASE leaves, the one buying it stays");
    }

    #[tokio::test]
    async fn ticker_ignores_the_min_fill_bucket() {
        let (m1, m2) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let normal = order(m1.address(), QUOTE, 10, 30, 1);
        let big = UATradeOrder { minFill: U256::from(5), ..order(m2.address(), QUOTE, 10, 20, 1) }; // better price, in the bucket
        let (v, _) = venue(World::default(), vec![(normal.clone(), sig_of(&m1, oh(&normal))), (big.clone(), sig_of(&m2, oh(&big)))]).await;
        assert_eq!(v.ticker(1).await.unwrap()["best_ask"], "3");
        let d = v.depth(1, 5).await.unwrap();
        assert_eq!(d["asks"].as_array().unwrap().len(), 1);
        assert_eq!(d["min_fill"]["asks"][0]["price"], "2");
        assert!(d["min_fill"]["bids"].as_array().unwrap().is_empty());
    }

    /// C6-3: the watcher takes leg events and an outside order's cancel and invalidation only from the DEX, a SCaaS order's
    /// (`UAOrderCancelled`, `UANoncesInvalidated`, R18) only from a SCaaS token, and that token only for the orders it sells; a
    /// hostile listed outside token's forged logs change nothing.
    #[tokio::test]
    async fn the_watcher_checks_who_emitted_the_log() {
        let evil = Address::repeat_byte(0xee);
        let maker = PrivateKeySigner::random();
        let ask = order(maker.address(), QUOTE, 10, 20, 1);
        let h = oh(&ask);
        let (v, _) = venue(World::default(), vec![(ask.clone(), sig_of(&maker, h))]).await;
        let v = Venue { kinds: [(BASE, KIND_SCAAS), (QUOTE, KIND_SCAAS), (evil, KIND_OUTSIDE)].into_iter().collect(), ..v };
        let leg = |sold: u64| ISCaaSDex::UALegSettled { r#ref: B256::ZERO, orderHash: h, from: ask.from,
            destination: ask.from, sold: U256::from(sold), received: U256::ZERO, dexFee: U256::ZERO,
            refund: U256::ZERO, relayerShare: U256::ZERO, treasuryShare: U256::ZERO }.encode_log_data();
        let cancel = ISCaaSDex::OrderCancelled { orderHash: h, from: maker.address() }.encode_log_data();
        let inv = ISCaaSDex::NoncesInvalidated { from: maker.address(), batch: U256::from(1), minNonce: U256::from(9) }.encode_log_data();
        let ua_cancel = IToken::UAOrderCancelled { orderHash: h, from: ask.from }.encode_log_data();
        let ua_inv = IToken::UANoncesInvalidated { from: ask.from, batch: U256::from(1), minNonce: U256::from(9) }.encode_log_data();
        // forged: an outside token (listed, in `kinds`) and a stranger
        for who in [evil, Address::repeat_byte(0xdd)] {
            for d in [leg(1), cancel.clone(), inv.clone(), ua_cancel.clone(), ua_inv.clone()] {
                assert!(v.accepted(&[log_at(who, d)]).is_empty(), "{who}");
            }
        }
        // a SCaaS token is no source of a leg event nor of the DEX's address events (no token emits them since T6, R18); the
        // DEX is no source of a token's order events
        for d in [leg(1), cancel.clone(), inv.clone()] {
            assert!(v.accepted(&[log_at(BASE, d)]).is_empty());
        }
        for d in [ua_cancel.clone(), ua_inv.clone()] {
            assert!(v.accepted(&[log_at(DEX, d)]).is_empty());
        }
        for (who, d) in [(DEX, leg(1)), (DEX, cancel.clone()), (DEX, inv.clone()), (BASE, ua_cancel.clone()), (BASE, ua_inv.clone())] {
            assert_eq!(v.accepted(&[log_at(who, d)]).len(), 1);
        }
        // the order sells BASE: only BASE (its token) cancels it; QUOTE (another SCaaS token) cannot, nor can the DEX (it
        // holds outside tokens' orders only)
        let mut book = v.book.lock().await;
        v.apply_events(&mut book, &v.accepted(&[log_at(QUOTE, ua_cancel.clone()), log_at(DEX, cancel.clone()), log_at(QUOTE, ua_inv.clone()),
            log_at(DEX, inv.clone())]));
        assert!(book.get(h).is_some(), "neither QUOTE nor the DEX holds it");
        let mut other = book.clone();
        v.apply_events(&mut book, &v.accepted(&[log_at(BASE, ua_cancel)]));
        assert!(book.get(h).is_none(), "BASE sells it: UAOrderCancelled");
        v.apply_events(&mut other, &v.accepted(&[log_at(BASE, ua_inv)]));
        assert!(other.get(h).is_none(), "BASE sells it: UANoncesInvalidated, its id's lane");
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
        let asks: Vec<UATradeOrder> = [(10, 20), (10, 21), (10, 22), (40, 92)].iter().zip(&keys)
            .map(|((b, q), k)| order(k.address(), QUOTE, *b, *q, 1)).collect();
        let makers: Vec<(UATradeOrder, Bytes)> = asks.iter().zip(&keys).map(|(o, k)| (o.clone(), sig_of(k, oh(o)))).collect();
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
        let Auth::Ua(auth) = &rest.auth else { panic!("a SCaaS order") };
        let again = v.place(BASE, &WireOrder::from_ua(&ask), None, Some(&ua_sig_json(auth))).await.unwrap();
        assert_eq!((again.status, again.remaining.as_str()), ("resting", "40"));
        // the settlement dies: the client reports it failed; the maker gets its 60 back (nothing pending any more)
        let row = Row::of(&Resting { hash: oh(&ask), sell: BASE, order: ask.clone(), auth: Auth::Ua(ua(sig_of(&maker, oh(&ask)))),
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

    /// Review T3 I1 at the watcher, a SCaaS leg (CTR-DEX-26, R18): its mined `UALegSettled` (never `LegSettled`, an outside
    /// leg's) releases the order's pending fill, so its remainder (below the minimum fill) closes at once, with no restart or
    /// reload; the watcher asks the chain for it.
    #[tokio::test]
    async fn watcher_settles_on_ua_leg_settled() {
        let (maker, taker) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let ask = order(maker.address(), QUOTE, 100, 200, 1); // min 50 base
        let (v, world) = venue(World::default(), vec![(ask.clone(), sig_of(&maker, oh(&ask)))]).await;
        assert_eq!(take(&v, &taker, 120, 60, 1).await.unwrap().status, "filled");
        assert_eq!(v.book.lock().await.pending_of(oh(&ask)), U256::from(60));
        let ev = ISCaaSDex::UALegSettled { r#ref: B256::repeat_byte(1), orderHash: oh(&ask), from: ask.from,
            destination: ask.from, sold: U256::from(60), received: U256::from(120), dexFee: U256::ZERO,
            refund: U256::ZERO, relayerShare: U256::ZERO, treasuryShare: U256::ZERO };
        world.lock().unwrap().logs.push(serde_json::to_value(log_at(DEX, ev.encode_log_data())).unwrap());
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

    /// CTR-UA-24 on the venue too (owner ruling 2026-10-30, D1, superseding 2026-10-28): an EIP-7702 maker signs with
    /// its base key only; its delegate's ERC-1271 is never called, so a yes from it is invalid.
    #[tokio::test]
    async fn a_7702_maker_signs_with_its_key_only() {
        let maker = PrivateKeySigner::random();
        let mut designator = vec![0xef, 0x01, 0x00];
        designator.extend_from_slice(Address::repeat_byte(0x55).as_slice());
        let mut w = World::default();
        w.codes.insert(maker.address(), Bytes::from(designator));
        let (v, world) = venue(w, vec![]).await;
        let d = B256::repeat_byte(1);
        let own = Bytes::from(maker.sign_hash_sync(&d).unwrap().as_bytes().to_vec());
        assert!(v.valid_sig(BASE, maker.address(), d, &own).await.unwrap(), "the base key");
        assert!(world.lock().unwrap().sig_calls.is_empty(), "the base key needs no ERC-1271 call");
        let other = Bytes::from_static(&[0xab; 65]);
        assert!(!v.valid_sig(BASE, maker.address(), d, &other).await.unwrap(), "no answer from the delegate");
        // a sweeper delegate that says yes to anything is never asked (owner ruling 2026-10-30, D1)
        world.lock().unwrap().answers.insert(maker.address(), Bytes::from([MAGIC_1271.to_vec(), vec![0; 28]].concat()));
        assert!(!v.valid_sig(BASE, maker.address(), d, &other).await.unwrap(), "the delegate's ERC-1271 refused");
        assert!(world.lock().unwrap().sig_calls.is_empty(), "the delegate is never called");
    }

    /// Outside legs are never probed through `mtxTrade` (an outside token has none: an honest maker would revert there
    /// and be blamed); they are blamed only on their own evidence, the hash their revert names (N8).
    #[tokio::test]
    async fn outside_legs_are_blamed_only_on_their_own_evidence() {
        let (maker, taker) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let (ask, bid) = (order(maker.address(), QUOTE, 10, 20, 1), order(taker.address(), BASE, 20, 10, 1));
        let leg = |o: &UATradeOrder, sell: Address, k: &PrivateKeySigner| Resting { hash: oh(o), sell, order: o.clone(),
            auth: if sell == BASE { Auth::Sig(sig_of(k, oh(o))) } else { Auth::Ua(ua(sig_of(k, oh(o)))) }, remaining: o.amount, seq: 1 };
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

    /// `contract_of` is read before the book moves: an unreadable kind leaves the order where it is, and each kind reaches the job.
    #[tokio::test]
    async fn a_cancel_needs_the_token_kind_and_keeps_the_book_without_it() {
        let maker = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x61)).unwrap();
        let ask = order(maker.address(), QUOTE, 100, 200, 1);
        let sig = sig_of(&maker, oh(&ask));
        let made = || vec![(ask.clone(), sig.clone())];
        // the fake's cancelOrderDigest is the order hash, so `sig` is a valid cancel signature
        let (v, _) = venue(World::default(), made()).await;
        let auth = ua_sig_json(&ua(sig.clone()));
        assert!(v.cancel(oh(&ask), Some(&hex_of(&sig)), None).await.unwrap_err().to_string().starts_with("LEG_SHAPE"),
            "a SCaaS order's cancel is CancelUAOrder in auth");
        let e = v.cancel(oh(&ask), None, Some(&auth)).await.unwrap_err();
        assert!(matches!(e, VenueError::Unavailable(_)), "an unreadable kind is unavailable, never a guess");
        assert!(in_book(&v.rows().await, &ask), "the order stays: nothing would close it on chain");
        assert!(v.cancels.lock().unwrap().pending.is_empty());
        for (name, want) in [("SCaaS MetaToken", "token"), ("SCaaS ZetherToken", "zether"), ("SCaaS PqzToken", "pqz")] {
            let (v, _) = venue(World { domain: Some(name), ..Default::default() }, made()).await;
            v.cancel(oh(&ask), None, Some(&auth)).await.unwrap();
            assert!(!in_book(&v.rows().await, &ask));
            let q = v.cancels.lock().unwrap().pending.clone();
            let jobs = cancel_jobs(DEX, &q);
            assert_eq!(jobs[0]["op"]["contract"], want, "{name}");
        }
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

    /// ua-mtx-merge T17 (spec §3.4, R12): an EOA's `UATradeOrder` (its address zero-padded, its key's signature alone in
    /// `auth`) rests and takes; the settle job carries both SCaaS legs in shape 1 with their `UASig`s. The shape-0 form, a
    /// native `auth` with `keyData` (R17) and another key's signature are refused, nothing written.
    #[tokio::test]
    async fn book_takes_a_ua_trade_order_from_an_eoa() {
        let (maker, taker) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let ask = order(maker.address(), QUOTE, 10, 20, 1);
        let (v, _) = venue(World::default(), vec![(ask.clone(), sig_of(&maker, oh(&ask)))]).await;
        let (relay, store) = crate::adapter::tests::fake_odoo(Default::default()).await;
        let v = Venue { relay, ..v };
        let bid = order(taker.address(), BASE, 20, 10, 1);
        let sig = sig_of(&taker, oh(&bid));
        let w = WireOrder::from_ua(&bid);
        let refused = |e: VenueError| e.to_string();
        assert!(refused(v.place(QUOTE, &w, Some(&hex_of(&sig)), None).await.unwrap_err()).starts_with("LEG_SHAPE"), "shape 0");
        let addr_form = WireOrder::from_sol(&super::super::trade_of(&bid));
        assert!(refused(v.place(QUOTE, &addr_form, None, Some(&ua_sig_json(&ua(sig.clone())))).await.unwrap_err()).contains("not a bytes32"));
        let r17 = UASig { keyData: Bytes::from_static(&[1]), ..ua(sig.clone()) };
        assert_eq!(refused(v.place(QUOTE, &w, None, Some(&ua_sig_json(&r17))).await.unwrap_err()), "bad order signature", "R17");
        let other = ua(sig_of(&maker, oh(&bid)));
        assert_eq!(refused(v.place(QUOTE, &w, None, Some(&ua_sig_json(&other))).await.unwrap_err()), "bad order signature");
        assert!(store.lock().unwrap().commits.is_empty(), "nothing written on a refusal");
        let r = v.place(QUOTE, &w, None, Some(&ua_sig_json(&ua(sig.clone())))).await.unwrap();
        assert_eq!((r.status, r.fills[0]["maker_hash"].as_str().unwrap()), ("filled", &*format!("{:#x}", oh(&ask))));
        let commit = store.lock().unwrap().commits[0].clone();
        let job = commit["jobs"].as_array().unwrap().iter().find(|j| j["kind"] == "settle").unwrap().clone();
        let (w8, _) = crate::submit::work_of_op(None, &job["op"], None).unwrap();
        let c = ISCaaSDex::mtxSettleCall::abi_decode(&w8.data).unwrap();
        assert_eq!((c.s[0].taker.shape, c.s[0].makers[0].shape), (1, 1));
        assert_eq!((&c.s[0].taker.uaOrder, &c.s[0].taker.auth), (&bid, &ua(sig)));
        assert_eq!(c.s[0].makers[0].uaOrder, ask);
        // the rows the client stores carry the order as it came in: ids, and `auth` instead of `signature`
        let taker_row = commit["orders"].as_array().unwrap().iter().find(|o| o["order_hash"] == json!(format!("{:#x}", oh(&bid)))).unwrap().clone();
        assert_eq!((taker_row["order"]["from"].clone(), taker_row["signature"].clone()), (json!(format!("{:#x}", bid.from)), json!("")));
        assert_eq!(super::super::ua_sig(&taker_row["auth"]).unwrap(), c.s[0].taker.auth);
        assert_eq!(v.orders_of(ask.from).await.len(), 0, "the maker filled");
    }

    /// Cancel-all of a SCaaS lane (R12, R38): `UAInvalidateNonces` on the id, its `auth` checked as the token does, the lane's
    /// orders out of the book, and one `ua_metatx` job of the token's `mtxInvalidateNonces(bytes32, …, UASig)`; the shape-0
    /// form (an address `from`, or a `signature`) refused by name.
    #[tokio::test]
    async fn cancel_all_signs_the_ua_invalidate() {
        let maker = PrivateKeySigner::random();
        let (a1, a2) = (order(maker.address(), QUOTE, 10, 30, 1), order(maker.address(), QUOTE, 10, 40, 7));
        let made = vec![(a1.clone(), sig_of(&maker, oh(&a1))), (a2.clone(), sig_of(&maker, oh(&a2)))];
        let (v, _) = venue(World { domain: Some("SCaaS MetaToken"), ..Default::default() }, made).await;
        let (relay, store) = crate::adapter::tests::fake_odoo(Default::default()).await;
        let v = Venue { relay, ..v };
        let id = format!("{:#x}", a1.from);
        let digest = keccak256((a1.from, U256::from(1), U256::from(5)).abi_encode());
        let auth = ua_sig_json(&ua(sig_of(&maker, digest)));
        let err = |e: VenueError| e.to_string();
        let sig = hex_of(&sig_of(&maker, digest));
        assert!(err(v.cancel_all(BASE, &id, U256::from(1), U256::from(5), Some(&sig), None).await.unwrap_err()).starts_with("LEG_SHAPE"));
        let addr = format!("{:#x}", maker.address());
        assert!(err(v.cancel_all(BASE, &addr, U256::from(1), U256::from(5), None, Some(&auth)).await.unwrap_err()).contains("not a bytes32"));
        let wrong = ua_sig_json(&ua(sig_of(&maker, B256::repeat_byte(9))));
        assert_eq!(err(v.cancel_all(BASE, &id, U256::from(1), U256::from(5), None, Some(&wrong)).await.unwrap_err()), "bad invalidate signature");
        assert_eq!(v.cancel_all(BASE, &id, U256::from(1), U256::from(5), None, Some(&auth)).await.unwrap(), 1, "nonce 1 < 5; nonce 7 stays");
        let rows = v.rows().await;
        assert!(!in_book(&rows, &a1) && in_book(&rows, &a2));
        let jobs = store.lock().unwrap().commits[0]["jobs"].clone();
        assert_eq!(jobs.as_array().unwrap().len(), 1);
        assert_eq!((jobs[0]["kind"].as_str(), jobs[0]["op"]["args"]["from"].as_str()), (Some("ua_metatx"), Some(&*id)));
        assert!(jobs[0]["op"].get("signature").is_none());
        let (w8, is_ua) = crate::submit::work_of_op(None, &jobs[0]["op"], None).unwrap();
        assert!(is_ua);
        assert_eq!(w8.data[..4], crate::guard::SEL_TOKEN_INVALIDATE_NONCES);
        let c = IMtxIds::mtxInvalidateNoncesCall::abi_decode(&w8.data).unwrap();
        assert_eq!((c.from, c.batch, c.newMin, c.auth), (a1.from, U256::from(1), U256::from(5), ua(sig_of(&maker, digest))));
    }

    /// A derived seller (an id outside the native space) is authorized by the sell token's registry under `trade`, as the
    /// token's `authorize` does: a registry that refuses, or none (`registry() == 0`, `UALedgerOff` on chain), is a bad
    /// signature; its balance is its `balanceOfUA`.
    #[tokio::test]
    async fn a_derived_seller_is_authorized_by_its_registry() {
        let from = B256::repeat_byte(0xa7);
        let ask = UATradeOrder { from, ..order(Address::ZERO, QUOTE, 10, 20, 1) };
        let auth = ua_sig_json(&UASig { keyData: Bytes::from_static(&[1, 2]), signature: Bytes::from_static(&[3; 64]), members: vec![] });
        for (registry, ok, want) in [(Address::ZERO, true, false), (Address::repeat_byte(0x5c), false, false), (Address::repeat_byte(0x5c), true, true)] {
            let mut w = World { registry, ..Default::default() };
            if ok {
                w.authorized.insert(oh(&ask));
            }
            let (v, _) = venue(w, vec![]).await;
            let r = v.place(BASE, &WireOrder::from_ua(&ask), None, Some(&auth)).await;
            assert_eq!(r.is_ok(), want, "{registry} {ok}: {:?}", r.err().map(|e| e.to_string()));
        }
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
