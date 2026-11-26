// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Bitcoin reads (SDK plan T36's read part; decisions CLI-SDK-32's Change of 2026-11-21, Q-D4 both): Esplora REST for an address's
//! UTXOs, history, a transaction's status and the fee estimates; Bitcoin Core JSON-RPC for the cross-checks
//! ([`cross_check`]: Esplora's tip hash at its height equals Core's, and every UTXO to spend is unspent in Core with the same
//! value and script, else [`BitcoinCrossCheck`] by name). Two endpoint lists, each with its own credentials (Core's
//! `authorization` header is the app's own `EndpointAuth::Header`). The network identity of both is the block-0 hash; Esplora's
//! head is its tip height. Every answer is bounded (16 MiB, depth 64 by the family client; a text answer 80 bytes; at most
//! [`UTXO_MAX`] UTXOs, [`PAGE_MAX`] history entries); amounts are satoshis as `u64` up to 21·10^14. The address is the caller's
//! (`ua-rs`'s segwit form, CLI-SGN-52), refused unless it is 14 to 90 lower-case bech32 characters. No key, no signing
//! (CLI-RPC-01). UNAUDITED.
use crate::family::{Client, FamilyError};
use crate::pool::{BlockChoice, Probe};
use crate::{EndpointFailure, FailureKind};
use serde_json::{json, Value};
use web_time::Instant;

/// The most UTXOs one address answer may hold.
pub const UTXO_MAX: usize = 1000;
/// The most entries one history page may hold (Esplora sends 50 unconfirmed and 25 confirmed at most).
pub const PAGE_MAX: usize = 100;
/// 21 million BTC in satoshis.
pub const MAX_SATS: u64 = 2_100_000_000_000_000;
const TEXT_MAX: usize = 80;

/// One unspent output of an address, as Esplora sends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    /// the block height when confirmed
    pub height: Option<u64>,
}

/// One transaction of an address's history: its id and its block height when confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    pub txid: String,
    pub height: Option<u64>,
}

/// An output as Core's `gettxout` sends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script: String,
    /// Core's `confirmations`: 0 for an output only in its mempool
    pub confirmations: u64,
}

/// A disagreement between Esplora and Core, or an output Core says is spent: nothing built on it is signed.
#[derive(Debug, Clone, PartialEq)]
pub enum BitcoinCrossCheck {
    /// Core's block hash at Esplora's tip height is another one (or Core has none)
    Tip { height: u64 },
    /// Core has no unspent output at `txid:vout` (spent, or never seen)
    Spent { txid: String, vout: u32 },
    /// Core's value or script of the output differs from Esplora's value or the address's script
    Output { txid: String, vout: u32 },
    /// an endpoint's failure while checking
    Endpoint(FamilyError),
}

impl std::fmt::Display for BitcoinCrossCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tip { height } => write!(f, "BitcoinCrossCheck: tip at {height}"),
            Self::Spent { txid, vout } => write!(f, "BitcoinCrossCheck: {txid}:{vout} spent"),
            Self::Output { txid, vout } => write!(f, "BitcoinCrossCheck: {txid}:{vout} differs"),
            Self::Endpoint(e) => write!(f, "BitcoinCrossCheck: {e}"),
        }
    }
}

impl std::error::Error for BitcoinCrossCheck {}

/// The Esplora endpoints of one Bitcoin network, named by its block-0 hash.
pub struct Esplora {
    pub client: Client,
    genesis: String,
}

impl Esplora {
    pub fn new(client: Client, genesis: &str) -> Self {
        Self {
            client,
            genesis: genesis.to_ascii_lowercase(),
        }
    }

    /// Endpoint `i`'s tip: its height and its block hash at that height.
    pub async fn tip(&self, i: usize) -> Result<(u64, String), FamilyError> {
        crate::family::admit_first(&self.client, self, i).await?;
        let h = self.height(i).await?;
        Ok((h, self.hash_at(i, h).await?))
    }

    /// The unspent outputs of `address` on endpoint `i` (`/address/{a}/utxo`).
    pub async fn utxos(&self, i: usize, address: &str) -> Result<Vec<Utxo>, FamilyError> {
        crate::family::admit_first(&self.client, self, i).await?;
        let v = self
            .json(i, &format!("/address/{}/utxo", addr(address)?))
            .await?;
        let a = list(i, &v, UTXO_MAX)?;
        let out = a
            .iter()
            .map(|u| {
                Ok(Utxo {
                    txid: txid(i, &u["txid"])?,
                    vout: u["vout"]
                        .as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or_else(|| malformed(i, "a vout that is not a u32"))?,
                    value: sats(i, &u["value"])?,
                    height: height(i, &u["status"])?,
                })
            })
            .collect::<Result<Vec<Utxo>, FamilyError>>()?;
        // one outpoint once: a caller that sums the values would count a repeated one twice (T26 B2-12)
        let mut seen = std::collections::HashSet::new();
        if !out.iter().all(|u| seen.insert((u.txid.as_str(), u.vout))) {
            return Err(malformed(i, "a repeated outpoint"));
        }
        Ok(out)
    }

    /// One page of `address`'s history on endpoint `i`, newest first: the first page (`/address/{a}/txs`), or the confirmed
    /// ones after `after` (`/address/{a}/txs/chain/{after}`).
    pub async fn history(
        &self,
        i: usize,
        address: &str,
        after: Option<&str>,
    ) -> Result<Vec<HistoryEntry>, FamilyError> {
        crate::family::admit_first(&self.client, self, i).await?;
        let a = addr(address)?;
        let path = match after {
            Some(t) => format!("/address/{a}/txs/chain/{}", txid(i, &json!(t))?),
            None => format!("/address/{a}/txs"),
        };
        let v = self.json(i, &path).await?;
        list(i, &v, PAGE_MAX)?
            .iter()
            .map(|t| {
                Ok(HistoryEntry {
                    txid: txid(i, &t["txid"])?,
                    height: height(i, &t["status"])?,
                })
            })
            .collect()
    }

    /// A transaction's block height on endpoint `i` (`/tx/{id}/status`), `None` while unconfirmed.
    pub async fn tx_height(&self, i: usize, id: &str) -> Result<Option<u64>, FamilyError> {
        crate::family::admit_first(&self.client, self, i).await?;
        let v = self
            .json(i, &format!("/tx/{}/status", txid(i, &json!(id))?))
            .await?;
        height(i, &v)
    }

    /// The fee estimates of endpoint `i` (`/fee-estimates`): each confirmation target (1 to 1008 blocks) with its rate in
    /// millisatoshis per virtual byte (Esplora sends sat/vB with three decimals), at most 10^9 (a million sat/vB); sorted by target.
    pub async fn fee_estimates(&self, i: usize) -> Result<Vec<(u16, u64)>, FamilyError> {
        crate::family::admit_first(&self.client, self, i).await?;
        let v = self.json(i, "/fee-estimates").await?;
        let o = v
            .as_object()
            .filter(|o| o.len() <= 64)
            .ok_or_else(|| malformed(i, "fee estimates that are not a small object"))?;
        let mut out = o
            .iter()
            .map(|(k, r)| {
                let t = k.parse::<u16>().ok().filter(|t| (1..=1008).contains(t));
                let m = r
                    .as_f64()
                    .filter(|r| r.is_finite() && *r >= 0.0 && *r <= 1e6)
                    .map(|r| (r * 1000.0).round() as u64);
                t.zip(m)
                    .ok_or_else(|| malformed(i, "a fee estimate out of form"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        out.sort_unstable();
        Ok(out)
    }

    async fn height(&self, i: usize) -> Result<u64, FamilyError> {
        self.text(i, "/blocks/tip/height")
            .await?
            .parse()
            .map_err(|_| malformed(i, "a tip height that is not a number"))
    }

    async fn hash_at(&self, i: usize, h: u64) -> Result<String, FamilyError> {
        let t = self.text(i, &format!("/block-height/{h}")).await?;
        is_hash(&t)
            .then(|| t.to_ascii_lowercase())
            .ok_or_else(|| malformed(i, "a block hash that is not 32 bytes"))
    }

    async fn text(&self, i: usize, path: &str) -> Result<String, FamilyError> {
        let (status, b) = self
            .client
            .raw_at(i, reqwest::Method::GET, path, None, "text/plain", TEXT_MAX)
            .await?;
        if !(200..300).contains(&status) {
            return Err(FamilyError::Status {
                status,
                message: crate::error::endpoint_text(&String::from_utf8_lossy(&b)),
            });
        }
        String::from_utf8(b)
            .map(|s| s.trim().to_string())
            .map_err(|_| malformed(i, "a text answer that is not UTF-8"))
    }

    async fn json(&self, i: usize, path: &str) -> Result<Value, FamilyError> {
        self.client.get_at(i, path).await
    }
}

impl Probe for Esplora {
    type Hash = String;
    /// `/block-height/0` against the configured block-0 hash.
    async fn same_chain(&self, i: usize, _: Option<Instant>) -> Result<bool, EndpointFailure> {
        self.hash_at(i, 0)
            .await
            .map(|g| g == self.genesis)
            .map_err(|e| unread(i, e))
    }
    /// `/blocks/tip/height`.
    async fn head(&self, i: usize, _: Option<Instant>) -> Result<u64, EndpointFailure> {
        self.height(i).await.map_err(|e| unread(i, e))
    }
    async fn named(
        &self,
        i: usize,
        _: BlockChoice,
        d: Option<Instant>,
    ) -> Result<u64, EndpointFailure> {
        self.head(i, d).await
    }
    async fn header(
        &self,
        i: usize,
        n: u64,
        _: Option<Instant>,
    ) -> Result<String, EndpointFailure> {
        self.hash_at(i, n).await.map_err(|e| unread(i, e))
    }
}

/// The Bitcoin Core JSON-RPC endpoints of one network, named by its block-0 hash.
pub struct Core {
    pub client: Client,
    genesis: String,
}

impl Core {
    pub fn new(client: Client, genesis: &str) -> Self {
        Self {
            client,
            genesis: genesis.to_ascii_lowercase(),
        }
    }

    /// Endpoint `i`'s block hash at height `h` (`getblockhash`), `None` above its tip (error -8).
    pub async fn block_hash(&self, i: usize, h: u64) -> Result<Option<String>, FamilyError> {
        crate::family::admit_first(&self.client, self, i).await?;
        self.hash_unchecked(i, h).await
    }

    async fn hash_unchecked(&self, i: usize, h: u64) -> Result<Option<String>, FamilyError> {
        match self.client.rpc_at(i, "getblockhash", json!([h])).await {
            Ok(v) => v
                .as_str()
                .filter(|t| is_hash(t))
                .map(|t| Some(t.to_ascii_lowercase()))
                .ok_or_else(|| malformed(i, "a block hash that is not 32 bytes")),
            Err(FamilyError::Rpc { error, .. }) if error["code"] == -8 => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The unspent output `txid:vout` on endpoint `i` (`gettxout`, the mempool's spends counted), `None` when Core has none.
    pub async fn txout(&self, i: usize, id: &str, vout: u32) -> Result<Option<TxOut>, FamilyError> {
        crate::family::admit_first(&self.client, self, i).await?;
        let v = self
            .client
            .rpc_at(
                i,
                "gettxout",
                json!([
                    txid(i, &json!(id)).map_err(|_| FamilyError::Argument("a txid out of form"))?,
                    vout,
                    true
                ]),
            )
            .await?;
        if v.is_null() {
            return Ok(None);
        }
        let value = v["value"]
            .as_f64()
            .filter(|b| b.is_finite() && *b >= 0.0 && *b <= 21e6)
            .map(|b| (b * 1e8).round() as u64)
            .ok_or_else(|| malformed(i, "a gettxout value out of form"))?;
        let script = v["scriptPubKey"]["hex"]
            .as_str()
            .filter(|s| {
                s.len() <= 2 * 10_000
                    && s.len().is_multiple_of(2)
                    && s.bytes().all(|b| b.is_ascii_hexdigit())
            })
            .ok_or_else(|| malformed(i, "a gettxout script out of form"))?
            .to_ascii_lowercase();
        let confirmations = v["confirmations"]
            .as_u64()
            .ok_or_else(|| malformed(i, "a gettxout without its confirmations"))?;
        Ok(Some(TxOut {
            value,
            script,
            confirmations,
        }))
    }
}

impl Probe for Core {
    type Hash = String;
    /// `getblockhash 0` against the configured block-0 hash.
    async fn same_chain(&self, i: usize, _: Option<Instant>) -> Result<bool, EndpointFailure> {
        match self.hash_unchecked(i, 0).await.map_err(|e| unread(i, e))? {
            Some(g) => Ok(g == self.genesis),
            None => Err(EndpointFailure::new(
                i,
                FailureKind::IdentityUnread,
                "no block 0",
            )),
        }
    }
    /// `getblockcount`.
    async fn head(&self, i: usize, _: Option<Instant>) -> Result<u64, EndpointFailure> {
        self.client
            .rpc_at(i, "getblockcount", json!([]))
            .await
            .map_err(|e| unread(i, e))?
            .as_u64()
            .ok_or_else(|| {
                EndpointFailure::new(
                    i,
                    FailureKind::AnswerMalformed,
                    "a block count that is not a number",
                )
            })
    }
    async fn named(
        &self,
        i: usize,
        _: BlockChoice,
        d: Option<Instant>,
    ) -> Result<u64, EndpointFailure> {
        self.head(i, d).await
    }
    async fn header(
        &self,
        i: usize,
        n: u64,
        _: Option<Instant>,
    ) -> Result<String, EndpointFailure> {
        self.hash_unchecked(i, n)
            .await
            .map_err(|e| unread(i, e))?
            .ok_or_else(|| {
                EndpointFailure::new(i, FailureKind::AnswerMalformed, "no block at that height")
            })
    }
}

/// `BitcoinCrossCheck` on Core's endpoint `i`: Esplora's `tip` (height, hash) is Core's block at that height, and every UTXO of
/// `utxos` is unspent in Core with the same value and the address's `script` (lower-case hex).
pub async fn cross_check(
    core: &Core,
    i: usize,
    tip: &(u64, String),
    utxos: &[Utxo],
    script: &str,
) -> Result<(), BitcoinCrossCheck> {
    let (h, hash) = tip;
    let at = core
        .block_hash(i, *h)
        .await
        .map_err(BitcoinCrossCheck::Endpoint)?;
    if at.as_deref() != Some(hash.as_str()) {
        return Err(BitcoinCrossCheck::Tip { height: *h });
    }
    for u in utxos {
        let (txid, vout) = (u.txid.clone(), u.vout);
        match core
            .txout(i, &u.txid, u.vout)
            .await
            .map_err(BitcoinCrossCheck::Endpoint)?
        {
            None => return Err(BitcoinCrossCheck::Spent { txid, vout }),
            // a UTXO Esplora calls confirmed must be confirmed in Core too, not only in its mempool (T26 B2-12)
            Some(o)
                if o.value != u.value
                    || o.script != script.to_ascii_lowercase()
                    || (u.height.is_some() && o.confirmations == 0) =>
            {
                return Err(BitcoinCrossCheck::Output { txid, vout })
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// The address as a path segment: 14 to 90 lower-case bech32 characters (the segwit forms `ua-rs` prints), else the caller's
/// `FamilyError::Argument` before any request.
fn addr(a: &str) -> Result<&str, FamilyError> {
    let ok = (14..=90).contains(&a.len())
        && a.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if ok {
        Ok(a)
    } else {
        Err(FamilyError::Argument("an address out of form"))
    }
}

fn list(i: usize, v: &Value, max: usize) -> Result<&Vec<Value>, FamilyError> {
    v.as_array()
        .filter(|a| a.len() <= max)
        .ok_or_else(|| malformed(i, "a list that is not an array within its bound"))
}

fn txid(i: usize, v: &Value) -> Result<String, FamilyError> {
    v.as_str()
        .filter(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| malformed(i, "a txid that is not 32 bytes of hex"))
}

fn sats(i: usize, v: &Value) -> Result<u64, FamilyError> {
    v.as_u64()
        .filter(|s| *s <= MAX_SATS)
        .ok_or_else(|| malformed(i, "a value that is not satoshis"))
}

/// A `status` object's height: `Some` when `confirmed` is true (its `block_height` a number), `None` when false.
fn height(i: usize, s: &Value) -> Result<Option<u64>, FamilyError> {
    match s["confirmed"].as_bool() {
        Some(true) => s["block_height"]
            .as_u64()
            .map(Some)
            .ok_or_else(|| malformed(i, "a confirmed status without a height")),
        Some(false) => Ok(None),
        None => Err(malformed(i, "a status without confirmed")),
    }
}

fn is_hash(h: &str) -> bool {
    h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())
}

fn malformed(i: usize, why: &str) -> FamilyError {
    FamilyError::Failure(EndpointFailure::new(i, FailureKind::AnswerMalformed, why))
}

fn unread(i: usize, e: FamilyError) -> EndpointFailure {
    match e {
        FamilyError::Failure(f) => f,
        e => EndpointFailure::new(i, FailureKind::Transport, &e.to_string()),
    }
}
