// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `dex` (spec §10; plan T17): the venue's reads through the gateway list, failed over (`NodeClient`'s DEX calls, the answers
//! the gateway's named-field JSON as text); the trade order (`UATradeOrder` in a SCaaS sell token's domain, or an outside token's
//! `DexOrder` in the DEX's) signed under `Expect::TradeOrder` and placed by `POST /v1/dex/orders`; the cancel of every lane's
//! orders (`UAInvalidateNonces` / `InvalidateNonces`) by `POST /v1/dex/cancel-all`; the token-side rows `UAWrapOrder`,
//! `CancelUAOrder`, `CancelUAWrapOrder` and the DEX's `CancelDexOrder` as operations of spec §13 (`Op::quote`, `Op::submit`);
//! the liquidity order (`liquidity_order_typed_data`) signed under `Expect::LiquidityOrder`. A DEX not on the chain profile's
//! list (NET-ALL-24) is `DexNotListed` before anything is read or signed (CLI-SGN-35), as is a wrapped token off its wrapper
//! list. A token's form is its DEX factory's catalogue (`versionOf(token).version != 0`: SCaaS), never the request's
//! (NODE-DEX-15). An order's life (open, filled, cancelled) is the venue's, read through `orders`. UNAUDITED.
use crate::op::{
    addr20, domain_name, evm, field, flatten, head, hex, key_opened, sim, unhex, KeyRef, Op,
    Prepared, ReviewField, Source,
};
use crate::wallet::ops::{draft, id32, id_of, ids, kind_of};
use crate::wallet::tokens::{selector, word};
use crate::{Sdk, SdkError};
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, U256};
use scaas_rpc::evm::EvmPool;
use scaas_rpc::node::{NodeClient, NodeOutcome};
use scaas_ua::wallet::{
    liquidity_order_typed_data, scaas_typed_data, Expect, Invalidate, TypedData,
};
use serde_json::{json, Map, Value};
use std::sync::Arc;

const ZERO20: &str = "0x0000000000000000000000000000000000000000";
const ZERO32: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

/// The DEX module.
pub struct Dex {
    sdk: Arc<Sdk>,
}

impl Sdk {
    /// The DEX module (spec §10).
    pub fn dex(self: &Arc<Self>) -> Arc<Dex> {
        Arc::new(Dex { sdk: self.clone() })
    }
}

/// A trade order (`TradeOrder`'s named fields, CTR-DEX-15): sold `amount` of `sell_token` for at least `receive_amount` of
/// `receive_token`, each settlement at least `min_fill` unless it closes the order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TradeOrder {
    pub signer: KeyRef,
    pub chain: String,
    pub sell_token: String,
    /// a DEX of the profile's list (CLI-SGN-35)
    pub dex: String,
    pub receive_token: String,
    pub amount: String,
    pub receive_amount: String,
    pub min_fill: String,
    /// the DEX fee rate the order accepts on what it receives, in millionths (at most 10,000)
    pub fee: String,
    pub relayer: String,
    /// `None`: 0 (the signer receives)
    pub destination: Option<String>,
    /// 1 IOC, 2 ESCROW (with IOC, SCaaS sell tokens only), 4 reserved by the venue
    pub flags: u8,
    /// the order lane, decimal (not an envelope's lane)
    pub batch: String,
    /// `None`: the lane's floor (`minNonce(from, batch)` on the sell token, or on the DEX for an outside token) read now
    pub nonce: Option<String>,
    /// unix seconds on the chain's clock
    pub valid_until: u64,
}

/// An order as it was signed: a `TradeOrder`'s 13 named fields, `from` and `destination` 32-byte ids for a SCaaS sell token's
/// `UATradeOrder`, addresses for an outside token's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderTerms {
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

/// The cancel of one order (`CancelUAOrder` on its SCaaS sell token, `CancelDexOrder` on the DEX for an outside token's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelOrder {
    pub signer: KeyRef,
    pub chain: String,
    pub sell_token: String,
    pub order: OrderTerms,
}

/// A wrap order (`UAWrapOrder`, CTR-TOK wrap orders): `amount` of the SCaaS token `token` wrapped into `wrapped_token`, at least
/// `min_minted` minted; fills whole (`min_fill` = `amount`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapOrder {
    pub signer: KeyRef,
    pub chain: String,
    /// the underlying: the order's domain
    pub token: String,
    /// a wrapper of the profile's list
    pub wrapped_token: String,
    pub amount: String,
    pub min_minted: String,
    pub min_fill: String,
    pub fee: String,
    pub relayer: String,
    pub destination: Option<String>,
    pub flags: u8,
    pub batch: String,
    /// `None`: the lane's floor on the underlying
    pub nonce: Option<String>,
    pub valid_until: u64,
}

/// A wrap order as it was signed (`UAWrapOrder`'s named fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapOrderTerms {
    pub from: String,
    pub wrapped_token: String,
    pub amount: String,
    pub min_minted: String,
    pub min_fill: String,
    pub fee: String,
    pub relayer: String,
    pub destination: String,
    pub flags: u8,
    pub batch: String,
    pub nonce: String,
    pub valid_until: String,
}

/// The cancel of one wrap order (`CancelUAWrapOrder` on the underlying `token`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelWrapOrder {
    pub signer: KeyRef,
    pub chain: String,
    pub token: String,
    pub order: WrapOrderTerms,
}

/// The cancel of every order of one lane below `min_nonce` (`POST /v1/dex/cancel-all`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelAll {
    pub signer: KeyRef,
    pub chain: String,
    pub sell_token: String,
    /// the DEX whose factory names the sell token's form; on the profile's list
    pub dex: String,
    pub batch: String,
    /// `None`: the lane's floor read now plus one (every order signed at the floor)
    pub min_nonce: Option<String>,
}

/// A token and an amount of a liquidity order's plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidityToken {
    pub token: String,
    pub amount: String,
}

/// A liquidity order (`LiquidityOrder`, CTR-DEX-30; dex-liquidity spec §4.2), signed in its DEX's domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidityOrder {
    pub signer: KeyRef,
    pub chain: String,
    /// a DEX of the profile's list with its liquidity mark
    pub dex: String,
    pub inputs: Vec<LiquidityToken>,
    pub outputs: Vec<LiquidityToken>,
    pub position_manager: Option<String>,
    pub position_reader: Option<String>,
    pub position_in: String,
    /// `0x` + 64 hex; `None`: no position received
    pub position_pool: Option<String>,
    pub tick_lower: i32,
    pub tick_upper: i32,
    pub min_liquidity: String,
    /// a 32-byte id; `None`: the signer
    pub recipient: Option<String>,
    pub fee: String,
    pub relayer: String,
    pub flags: u8,
    pub batch: String,
    /// the order's nonce (the planner's; no lane is read)
    pub nonce: String,
    pub valid_until: u64,
    /// tokens the plan counts beside its inputs and outputs (at most eight)
    pub extra_tokens: Vec<String>,
    /// a partial withdraw or fee collect (it must receive the position back)
    pub partial: bool,
}

/// An order prepared (a trade order or a liquidity order): opaque, holding nothing signed.
pub struct PreparedOrder {
    id: String,
    chain: String,
    review: Vec<ReviewField>,
    signer: KeyRef,
    td: TypedData,
    expect: Expect,
    /// the venue's body without its signature (`{chain, sellToken, order}`); `None`: a liquidity order
    body: Option<Value>,
    ua: bool,
}

impl std::fmt::Debug for PreparedOrder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedOrder")
            .field("id", &self.id)
            .finish()
    }
}

impl PreparedOrder {
    /// The order's hash (its typed digest): the venue's `orderHash`.
    pub fn id(&self) -> String {
        self.id.clone()
    }
    pub fn chain(&self) -> String {
        self.chain.clone()
    }
    /// Every signed field (`minFill` among them, as signed) and the DEX and tokens with their marks.
    pub fn review(&self) -> Vec<ReviewField> {
        self.review.clone()
    }
    pub fn signer(&self) -> KeyRef {
        self.signer.clone()
    }
}

/// A signed order: its hash, the order as signed (named-field JSON) and its signature (a `UASig` JSON for a 32-byte `from`,
/// else `0x` hex).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedOrder {
    pub order_hash: String,
    pub order: String,
    pub signature: String,
}

/// The listed DEX `dex` of `chain` (`DexNotListed`).
fn listed(sdk: &Sdk, chain: &str, dex: &[u8; 20]) -> Result<crate::ListedDex, SdkError> {
    let (p, _, _) = evm(sdk, chain)?;
    p.dexes
        .iter()
        .find(|d| addr20(&d.address.to_ascii_lowercase()).is_ok_and(|a| a == *dex))
        .cloned()
        .ok_or(SdkError::DexNotListed)
}

fn addrs(list: &[String]) -> Result<Vec<[u8; 20]>, SdkError> {
    list.iter()
        .map(|a| addr20(&a.to_ascii_lowercase()))
        .collect()
}

async fn call(pool: &EvmPool, to: [u8; 20], data: Vec<u8>) -> Result<Vec<u8>, SdkError> {
    let tx = alloy::rpc::types::TransactionRequest::default()
        .with_to(Address::from(to))
        .with_input(Bytes::from(data));
    Ok(pool.call_tx(tx).await.map_err(sim)?.to_vec())
}

fn padded(b: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    let at = 32usize.saturating_sub(b.len());
    if let Some(t) = w.get_mut(at..) {
        t.copy_from_slice(b.get(..32 - at).unwrap_or_default());
    }
    w
}

/// Whether `token` is a SCaaS token on `dex`'s factory (NODE-DEX-15: `versionOf(token).version != 0` on its `factory()`).
async fn scaas_token(pool: &EvmPool, dex: [u8; 20], token: [u8; 20]) -> Result<bool, SdkError> {
    let f = call(pool, dex, selector("factory()")).await?;
    let factory: [u8; 20] = word(&f, 0)?
        .get(12..)
        .and_then(|a| a.try_into().ok())
        .ok_or(SdkError::Argument)?;
    let mut data = selector("versionOf(address)");
    data.extend_from_slice(&padded(&token));
    let v = call(pool, factory, data).await?;
    Ok(word(&v, 1)?.iter().any(|b| *b != 0))
}

/// The order lane's floor: `minNonce(bytes32, uint256)` on a SCaaS token, `minNonce(address, uint256)` on a DEX.
async fn floor(
    pool: &EvmPool,
    contract: [u8; 20],
    from: &[u8],
    batch: &str,
) -> Result<U256, SdkError> {
    let sig = if from.len() == 32 {
        "minNonce(bytes32,uint256)"
    } else {
        "minNonce(address,uint256)"
    };
    let batch = U256::from_str_radix(batch, 10).map_err(|_| SdkError::Argument)?;
    let mut data = selector(sig);
    data.extend_from_slice(&padded(from));
    data.extend_from_slice(&batch.to_be_bytes::<32>());
    let w = call(pool, contract, data).await?;
    Ok(U256::from_be_slice(word(&w, 0)?))
}

/// The gateway list of `chain` and its chain id (`SubmitPathNone` without one).
fn gateways(sdk: &Sdk, chain: &str) -> Result<(NodeClient, u64), SdkError> {
    let c = sdk
        .chains
        .iter()
        .find(|c| c.profile.key == chain)
        .ok_or(SdkError::ChainUnknown)?;
    let (Some(list), Some(id)) = (c.gateways.clone(), c.profile.chain_id) else {
        return Err(SdkError::SubmitPathNone);
    };
    Ok((NodeClient::new(list)?, id))
}

/// A venue read.
enum Read {
    Markets,
    Depth(i64, Option<usize>),
    Trades(i64),
    Ticker(i64),
    Orders(String),
}

/// `body` posted by `route` to the first gateway that answers (a refusal is final). A gateway is used only once its own
/// `GET /v1/gateway` names the profile's `chain_uid` for the chain (NODE-GW-05); one that names another is not used, and
/// with none left that is `ProfileMismatch`.
async fn post(sdk: &Sdk, chain: &str, route: &str, body: &Value) -> Result<(), SdkError> {
    let (node, id) = gateways(sdk, chain)?;
    let (profile, _, _) = evm(sdk, chain)?;
    let (mut last, mut mismatch) = (None, false);
    for i in 0..node.list().len() {
        match node.gateway_at(i).await {
            Ok(v) if announces(&v, id, &profile.chain_uid) => {}
            Ok(_) => {
                mismatch = true;
                continue;
            }
            Err(scaas_rpc::RpcError::EndpointAllFailed { last: f, .. }) => {
                last = f;
                continue;
            }
            Err(e) => return Err(SdkError::Rpc(e)),
        }
        let o = match route {
            "orders" => node.dex_place_at(i, body).await?,
            _ => node.dex_cancel_all_at(i, body).await?,
        };
        match o {
            NodeOutcome::Queued { .. } => return Ok(()),
            NodeOutcome::Refused(e) => return Err(SdkError::Rpc(e)),
            NodeOutcome::Unreachable(f) => last = Some(f),
        }
    }
    if mismatch {
        return Err(SdkError::ProfileMismatch);
    }
    Err(SdkError::Rpc(scaas_rpc::RpcError::EndpointAllFailed {
        last,
        failover_revert: None,
    }))
}

/// Whether a gateway's `GET /v1/gateway` lists chain `id` with `chain_uid`.
fn announces(v: &Value, id: u64, chain_uid: &str) -> bool {
    v.get("chains").and_then(Value::as_array).is_some_and(|cs| {
        cs.iter().any(|x| {
            x.get("chain").and_then(Value::as_u64) == Some(id)
                && x.get("chain_uid")
                    .and_then(Value::as_str)
                    .is_some_and(|u| u.eq_ignore_ascii_case(chain_uid))
        })
    })
}

/// The tokens and the DEX an order touches, each with its mark (`listed <symbol>` or `unlisted`).
fn marks(sdk: &Sdk, chain: &str, dex: &[u8; 20], tokens: &[[u8; 20]]) -> Vec<ReviewField> {
    let profile = sdk.evm(chain).map(|(p, _, _)| p).ok();
    let mut out = vec![field("dex", &hex(dex), "listed", Source::Derived)];
    for t in tokens {
        let a = hex(t);
        let display = profile
            .as_ref()
            .and_then(|p| p.tokens.iter().find(|l| l.address.eq_ignore_ascii_case(&a)))
            .map_or("unlisted".to_string(), |l| format!("listed {}", l.symbol));
        out.push(field("token", &a, &display, Source::Derived));
    }
    out
}

fn canonical(td: &TypedData) -> Result<Value, SdkError> {
    td.to_value()
        .get("message")
        .cloned()
        .ok_or(SdkError::Internal)
}

/// The signer's signature in an order's form: a `UASig` for a 32-byte `from`, else the bytes.
fn signature_json(ua: bool, s: &scaas_ua::ua_portable::UASig) -> Value {
    if ua {
        json!({"keyData": hex(&s.key_data), "signature": hex(&s.signature), "members": []})
    } else {
        json!(hex(&s.signature))
    }
}

impl Dex {
    async fn read(&self, chain: String, r: Read) -> Result<String, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let (node, id) = gateways(&sdk, &chain)?;
                let v = match r {
                    Read::Markets => node.dex_markets(id).await?,
                    Read::Depth(m, l) => node.dex_depth(id, m, l).await?,
                    Read::Trades(m) => node.dex_trades(id, m).await?,
                    Read::Ticker(m) => node.dex_ticker(id, m).await?,
                    Read::Orders(maker) => node.dex_orders(id, &maker).await?,
                };
                serde_json::to_string(&v).map_err(|_| SdkError::Internal)
            })
            .await
    }

    /// The venue's markets and fees (`GET /v1/dex/markets`), failed over across the gateway list: the gateway's JSON.
    pub async fn markets(&self, chain: String) -> Result<String, SdkError> {
        self.read(chain, Read::Markets).await
    }
    /// A market's price levels (`GET /v1/dex/depth`, `levels` at most 200).
    pub async fn depth(
        &self,
        chain: String,
        market: i64,
        levels: Option<u32>,
    ) -> Result<String, SdkError> {
        let l = levels.map(|l| l.min(200) as usize);
        self.read(chain, Read::Depth(market, l)).await
    }
    /// A market's recent fills (`GET /v1/dex/trades`).
    pub async fn trades(&self, chain: String, market: i64) -> Result<String, SdkError> {
        self.read(chain, Read::Trades(market)).await
    }
    /// A market's last price, best bid and ask, volume (`GET /v1/dex/ticker`).
    pub async fn ticker(&self, chain: String, market: i64) -> Result<String, SdkError> {
        self.read(chain, Read::Ticker(market)).await
    }
    /// The open orders of `maker` (an id or an address, `GET /v1/dex/orders`): an order's life is the venue's.
    pub async fn orders(&self, chain: String, maker: String) -> Result<String, SdkError> {
        self.read(chain, Read::Orders(maker)).await
    }

    /// Prepares a trade order (CLI-SGN-35): `DexNotListed` for a DEX off the profile's list, before any read; the sell token's
    /// form from the DEX's factory (a SCaaS token: a `UATradeOrder` in its domain, `from` the signer's id; an outside token: a
    /// `DexOrder` in the DEX's, `from` an EVM key's address); the review lists every signed field, `minFill` as signed.
    pub async fn prepare_trade_order(
        &self,
        req: TradeOrder,
    ) -> Result<Arc<PreparedOrder>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let dex = addr20(&req.dex.to_ascii_lowercase())?;
                listed(&sdk, &req.chain, &dex)?;
                let sell = addr20(&req.sell_token.to_ascii_lowercase())?;
                let receive = addr20(&req.receive_token.to_ascii_lowercase())?;
                let (profile, chain_id, pool) = evm(&sdk, &req.chain)?;
                let ua = scaas_token(&pool, dex, sell).await?;
                drop(key_opened(&sdk, &req.signer).await?);
                let from = id_of(&sdk, &req.signer, if ua { "bytes32" } else { "address" }).await?;
                let from_b = unhex(&from)?;
                let nonce = match &req.nonce {
                    Some(n) => n.clone(),
                    None => floor(&pool, if ua { sell } else { dex }, &from_b, &req.batch)
                        .await?
                        .to_string(),
                };
                let zero = if ua { ZERO32 } else { ZERO20 };
                let destination = req.destination.clone().unwrap_or_else(|| zero.into());
                let order = json!({
                    "from": from, "receiveToken": hex(&receive), "amount": req.amount,
                    "receiveAmount": req.receive_amount, "minFill": req.min_fill, "fee": req.fee,
                    "relayer": req.relayer.to_ascii_lowercase(), "dex": hex(&dex),
                    "destination": destination.to_ascii_lowercase(), "flags": req.flags,
                    "batch": req.batch, "nonce": nonce, "validUntil": req.valid_until.to_string(),
                });
                let (_, uid) = ids(&sdk, &req.chain)?;
                let (td, wire) = if ua {
                    let kind = kind_of(&sdk, &req.chain, "CancelUAOrder", sell).await?;
                    let td = scaas_typed_data(
                        "UATradeOrder",
                        Some(domain_name(kind)?),
                        &sell,
                        chain_id,
                        &uid,
                        &order,
                    )?;
                    let m = canonical(&td)?;
                    (td, m)
                } else {
                    kind_of(&sdk, &req.chain, "CancelDexOrder", dex).await?;
                    let td = scaas_typed_data(
                        "DexOrder",
                        Some(domain_name("dex")?),
                        &dex,
                        chain_id,
                        &uid,
                        &json!({"sellToken": hex(&sell), "order": order}),
                    )?;
                    let m = canonical(&td)?
                        .get("order")
                        .cloned()
                        .ok_or(SdkError::Internal)?;
                    (td, m)
                };
                let (_, now) = head(&pool).await?;
                let expect = Expect::TradeOrder {
                    account: from_b,
                    chain_id,
                    chain_uid: uid,
                    order: order.clone(),
                    sell_token: sell,
                    outside: !ua,
                    dexes: addrs(
                        &profile
                            .dexes
                            .iter()
                            .map(|d| d.address.clone())
                            .collect::<Vec<_>>(),
                    )?,
                    ua,
                    now,
                    max_window: sdk.window(&req.chain),
                };
                let mut review = vec![];
                flatten("", &wire, &mut review);
                review.extend(marks(&sdk, &req.chain, &dex, &[sell, receive]));
                Ok(Arc::new(PreparedOrder {
                    id: hex(&td.digest()?),
                    chain: req.chain.clone(),
                    review,
                    signer: req.signer,
                    td,
                    expect,
                    body: Some(json!({"chain": chain_id, "sellToken": hex(&sell), "order": wire})),
                    ua,
                }))
            })
            .await
    }

    /// Signs a prepared order under its check (the user confirmed its review): its hash, the order and the signature.
    pub async fn sign_order(&self, order: Arc<PreparedOrder>) -> Result<SignedOrder, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let k = key_opened(&sdk, &order.signer).await?;
                let s = crate::op::submit::sign_one(&sdk, &k, &order.td, &order.expect).await?;
                let o = match &order.body {
                    Some(b) => b.get("order").cloned().ok_or(SdkError::Internal)?,
                    None => canonical(&order.td)?,
                };
                Ok(SignedOrder {
                    order_hash: order.id.clone(),
                    order: o.to_string(),
                    signature: signature_json(order.ua, &s).to_string(),
                })
            })
            .await
    }

    /// Signs a prepared trade order and places it (`POST /v1/dex/orders`) at the first gateway that answers, every gateway's
    /// `chain_uid` checked first (`ProfileMismatch`); a refusal is final (`Rpc` with the node's code). Returns the order hash.
    /// A liquidity order is not placed here (`Argument`): its job is the planner's.
    pub async fn place(&self, order: Arc<PreparedOrder>) -> Result<String, SdkError> {
        let Some(body) = order.body.clone() else {
            return Err(SdkError::Argument);
        };
        let signed = self.sign_order(order.clone()).await?;
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let mut b = body;
                let o = b.as_object_mut().ok_or(SdkError::Internal)?;
                let sig: Value =
                    serde_json::from_str(&signed.signature).map_err(|_| SdkError::Internal)?;
                o.insert(if order.ua { "auth" } else { "signature" }.into(), sig);
                post(&sdk, &order.chain, "orders", &b).await?;
                Ok(signed.order_hash)
            })
            .await
    }

    /// Cancels every order of one lane with a nonce below `min_nonce` (`POST /v1/dex/cancel-all`): `UAInvalidateNonces` in a
    /// SCaaS sell token's domain or `InvalidateNonces` in the DEX's, signed under `Expect::Cancel`. Returns the signed digest.
    pub async fn cancel_all(&self, req: CancelAll) -> Result<String, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let dex = addr20(&req.dex.to_ascii_lowercase())?;
                listed(&sdk, &req.chain, &dex)?;
                let sell = addr20(&req.sell_token.to_ascii_lowercase())?;
                let (_, chain_id, pool) = evm(&sdk, &req.chain)?;
                let ua = scaas_token(&pool, dex, sell).await?;
                let from = id_of(&sdk, &req.signer, if ua { "bytes32" } else { "address" }).await?;
                let from_b = unhex(&from)?;
                let contract = if ua { sell } else { dex };
                let min_nonce = match &req.min_nonce {
                    Some(n) => n.clone(),
                    None => (floor(&pool, contract, &from_b, &req.batch).await? + U256::from(1))
                        .to_string(),
                };
                let (name, kind) = if ua {
                    (
                        "UAInvalidateNonces",
                        kind_of(&sdk, &req.chain, "UAInvalidateNonces", sell).await?,
                    )
                } else {
                    (
                        "InvalidateNonces",
                        kind_of(&sdk, &req.chain, "InvalidateNonces", dex).await?,
                    )
                };
                let (_, uid) = ids(&sdk, &req.chain)?;
                let m = json!({"from": from, "batch": req.batch, "minNonce": min_nonce});
                let td = scaas_typed_data(
                    name,
                    Some(domain_name(kind)?),
                    &contract,
                    chain_id,
                    &uid,
                    &m,
                )?;
                let expect = Expect::Cancel {
                    account: from_b,
                    chain_id,
                    chain_uid: uid,
                    contract,
                    order: None,
                    invalidate: Some(Invalidate {
                        batch: req.batch.clone(),
                        min_nonce: min_nonce.clone(),
                    }),
                    ua,
                };
                let k = key_opened(&sdk, &req.signer).await?;
                let s = crate::op::submit::sign_one(&sdk, &k, &td, &expect).await?;
                let mut body = json!({"chain": chain_id, "sellToken": hex(&sell), "from": from,
                    "batch": req.batch, "minNonce": min_nonce});
                if let Some(o) = body.as_object_mut() {
                    o.insert(
                        if ua { "auth" } else { "signature" }.into(),
                        signature_json(ua, &s),
                    );
                }
                post(&sdk, &req.chain, "cancel-all", &body).await?;
                Ok(hex(&td.digest()?))
            })
            .await
    }

    /// Prepares the cancel of one order (an operation of spec §13): a 32-byte `from` is a SCaaS sell token's `UATradeOrder`,
    /// cancelled by `CancelUAOrder` on that token whatever its DEX (a cancel only protects the signer, NODE-DEX-16); an
    /// address `from` an outside token's order, cancelled by `CancelDexOrder` on its DEX, which must be on the profile's list.
    /// The signer must be the order's `from` (`Argument`).
    pub async fn prepare_cancel_order(&self, req: CancelOrder) -> Result<Arc<Prepared>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let o = &req.order;
                let from_b = unhex(&o.from.to_ascii_lowercase())?;
                let ua = match from_b.len() {
                    32 => true,
                    20 => false,
                    _ => return Err(SdkError::Argument),
                };
                let sell = addr20(&req.sell_token.to_ascii_lowercase())?;
                let dex = addr20(&o.dex.to_ascii_lowercase())?;
                if !ua {
                    listed(&sdk, &req.chain, &dex)?;
                }
                let me = id_of(&sdk, &req.signer, if ua { "bytes32" } else { "address" }).await?;
                if unhex(&me)? != from_b {
                    return Err(SdkError::Argument);
                }
                let terms = json!({
                    "from": o.from.to_ascii_lowercase(), "receiveToken": o.receive_token.to_ascii_lowercase(),
                    "amount": o.amount, "receiveAmount": o.receive_amount, "minFill": o.min_fill, "fee": o.fee,
                    "relayer": o.relayer.to_ascii_lowercase(), "dex": hex(&dex),
                    "destination": o.destination.to_ascii_lowercase(), "flags": o.flags, "batch": o.batch,
                    "nonce": o.nonce, "validUntil": o.valid_until,
                });
                let (name, contract, order) = if ua {
                    ("CancelUAOrder", sell, terms)
                } else {
                    ("CancelDexOrder", dex, json!({"sellToken": hex(&sell), "order": terms}))
                };
                cancel_op(&sdk, req.chain, req.signer, name, contract, order, from_b, ua).await
            })
            .await
    }

    /// Prepares the cancel of one wrap order (`CancelUAWrapOrder` on the underlying `token`, an operation of spec §13).
    pub async fn prepare_cancel_wrap_order(
        &self,
        req: CancelWrapOrder,
    ) -> Result<Arc<Prepared>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let o = &req.order;
                let from_b = id32(&o.from)?.to_vec();
                let me = id_of(&sdk, &req.signer, "bytes32").await?;
                if unhex(&me)? != from_b {
                    return Err(SdkError::Argument);
                }
                let token = addr20(&req.token.to_ascii_lowercase())?;
                let order = json!({
                    "from": o.from.to_ascii_lowercase(), "wrappedToken": o.wrapped_token.to_ascii_lowercase(),
                    "amount": o.amount, "minMinted": o.min_minted, "minFill": o.min_fill, "fee": o.fee,
                    "relayer": o.relayer.to_ascii_lowercase(), "destination": o.destination.to_ascii_lowercase(),
                    "flags": o.flags, "batch": o.batch, "nonce": o.nonce, "validUntil": o.valid_until,
                });
                cancel_op(&sdk, req.chain, req.signer, "CancelUAWrapOrder", token, order, from_b, true)
                    .await
            })
            .await
    }

    /// Prepares a wrap order (`UAWrapOrder`, an operation of spec §13): signed in the underlying's domain under
    /// `Expect::WrapOrder`, sent to the wrapper's `mtxWrapOrder`; `DexNotListed` for a wrapper off the profile's list.
    pub async fn prepare_wrap_order(&self, req: WrapOrder) -> Result<Arc<Prepared>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let (profile, chain_id, pool) = evm(&sdk, &req.chain)?;
                let wrapper = addr20(&req.wrapped_token.to_ascii_lowercase())?;
                let wrappers = addrs(&profile.wrappers)?;
                if !wrappers.contains(&wrapper) {
                    return Err(SdkError::DexNotListed);
                }
                let token = addr20(&req.token.to_ascii_lowercase())?;
                let kind = kind_of(&sdk, &req.chain, "UAWrapOrder", token).await?;
                let from = id_of(&sdk, &req.signer, "bytes32").await?;
                let from_b = unhex(&from)?;
                let nonce = match &req.nonce {
                    Some(n) => n.clone(),
                    None => floor(&pool, token, &from_b, &req.batch).await?.to_string(),
                };
                let mut m = Map::new();
                for (k, v) in [
                    ("from", json!(from)),
                    ("wrappedToken", json!(hex(&wrapper))),
                    ("amount", json!(req.amount)),
                    ("minMinted", json!(req.min_minted)),
                    ("minFill", json!(req.min_fill)),
                    ("fee", json!(req.fee)),
                    ("relayer", json!(req.relayer.to_ascii_lowercase())),
                    (
                        "destination",
                        json!(req
                            .destination
                            .clone()
                            .unwrap_or_else(|| ZERO32.into())
                            .to_ascii_lowercase()),
                    ),
                    ("flags", json!(req.flags)),
                    ("batch", json!(req.batch)),
                    ("nonce", json!(nonce)),
                    ("validUntil", json!(req.valid_until.to_string())),
                ] {
                    m.insert(k.into(), v);
                }
                let (_, uid) = ids(&sdk, &req.chain)?;
                let max_window = sdk.window(&req.chain);
                let order = Value::Object(m.clone());
                let mut d = draft(req.chain, "UAWrapOrder", kind, token, m, req.signer);
                d.target = Some(wrapper);
                d.extra = json!({"underlying": hex(&token)});
                d.touched.push(wrapper);
                d.expect = Some(Box::new(move |now, _| {
                    Ok(Expect::WrapOrder {
                        account: from_b.clone(),
                        chain_id,
                        chain_uid: uid,
                        order: order.clone(),
                        sell_token: token,
                        wrappers: wrappers.clone(),
                        now,
                        max_window,
                    })
                }));
                Op::prepare(&sdk, d).await
            })
            .await
    }

    /// Prepares a liquidity order (`LiquidityOrder` in its DEX's domain, `liquidity_order_typed_data`): `DexNotListed` for a
    /// DEX off the profile's list or without its liquidity mark; the plan tokens' forms from the DEX's factory; checked under
    /// `Expect::LiquidityOrder` when signed (`sign_order`). Its `mtxLiquidity` job is the planner's (not placed here).
    pub async fn prepare_liquidity_order(
        &self,
        req: LiquidityOrder,
    ) -> Result<Arc<PreparedOrder>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let dex = addr20(&req.dex.to_ascii_lowercase())?;
                let entry = listed(&sdk, &req.chain, &dex)?;
                if !entry.liquidity {
                    return Err(SdkError::DexNotListed);
                }
                let (profile, chain_id, pool) = evm(&sdk, &req.chain)?;
                let from = id_of(&sdk, &req.signer, "bytes32").await?;
                let account = id32(&from)?;
                let plan = |l: &[LiquidityToken]| -> Result<Vec<Value>, SdkError> {
                    l.iter()
                        .map(|t| {
                            Ok(json!({"token": hex(&addr20(&t.token.to_ascii_lowercase())?), "amount": t.amount}))
                        })
                        .collect()
                };
                let a = |o: &Option<String>| o.clone().unwrap_or_else(|| ZERO20.into()).to_ascii_lowercase();
                let order = json!({
                    "from": from, "inputs": plan(&req.inputs)?, "outputs": plan(&req.outputs)?,
                    "positionManager": a(&req.position_manager), "positionReader": a(&req.position_reader),
                    "positionIn": req.position_in,
                    "positionPool": req.position_pool.clone().unwrap_or_else(|| ZERO32.into()).to_ascii_lowercase(),
                    "tickLower": req.tick_lower, "tickUpper": req.tick_upper, "minLiquidity": req.min_liquidity,
                    "recipient": req.recipient.clone().unwrap_or_else(|| ZERO32.into()).to_ascii_lowercase(),
                    "fee": req.fee, "relayer": req.relayer.to_ascii_lowercase(), "flags": req.flags,
                    "batch": req.batch, "nonce": req.nonce, "validUntil": req.valid_until.to_string(),
                });
                let (_, uid) = ids(&sdk, &req.chain)?;
                let td = liquidity_order_typed_data(&dex, chain_id, &uid, &order)?;
                let mut scaas_tokens = vec![];
                let mut tokens = vec![];
                for t in req.inputs.iter().chain(&req.outputs) {
                    let t = addr20(&t.token.to_ascii_lowercase())?;
                    if scaas_token(&pool, dex, t).await? {
                        scaas_tokens.push(t);
                    }
                    tokens.push(t);
                }
                let mut readers: Vec<([u8; 20], Vec<[u8; 20]>)> = vec![];
                for r in &entry.position_readers {
                    let (m, x) = (addr20(&r.manager.to_ascii_lowercase())?, addr20(&r.reader.to_ascii_lowercase())?);
                    match readers.iter_mut().find(|(k, _)| *k == m) {
                        Some((_, v)) => v.push(x),
                        None => readers.push((m, vec![x])),
                    }
                }
                let (_, now) = head(&pool).await?;
                let expect = Expect::LiquidityOrder {
                    account,
                    chain_id,
                    chain_uid: uid,
                    order: order.clone(),
                    dexes: addrs(&profile.dexes.iter().map(|d| d.address.clone()).collect::<Vec<_>>())?,
                    liquidity_dexes: addrs(
                        &profile
                            .dexes
                            .iter()
                            .filter(|d| d.liquidity)
                            .map(|d| d.address.clone())
                            .collect::<Vec<_>>(),
                    )?,
                    readers,
                    scaas_tokens,
                    extra_tokens: addrs(&req.extra_tokens)?,
                    partial: req.partial,
                    now,
                    max_window: sdk.window(&req.chain),
                };
                let mut review = vec![];
                flatten("", &canonical(&td)?, &mut review);
                review.extend(marks(&sdk, &req.chain, &dex, &tokens));
                Ok(Arc::new(PreparedOrder {
                    id: hex(&td.digest()?),
                    chain: req.chain.clone(),
                    review,
                    signer: req.signer,
                    td,
                    expect,
                    body: None,
                    ua: true,
                }))
            })
            .await
    }
}

/// A cancel's operation: `name` on `contract` with `{order}`, under `Expect::Cancel` of the stored order.
#[allow(clippy::too_many_arguments)]
async fn cancel_op(
    sdk: &Arc<Sdk>,
    chain: String,
    signer: KeyRef,
    name: &'static str,
    contract: [u8; 20],
    order: Value,
    account: Vec<u8>,
    ua: bool,
) -> Result<Arc<Prepared>, SdkError> {
    let kind = kind_of(sdk, &chain, name, contract).await?;
    let (chain_id, uid) = ids(sdk, &chain)?;
    let mut m = Map::new();
    m.insert("order".into(), order.clone());
    let mut d = draft(chain, name, kind, contract, m, signer);
    d.expect = Some(Box::new(move |_, _| {
        Ok(Expect::Cancel {
            account: account.clone(),
            chain_id,
            chain_uid: uid,
            contract,
            order: Some(order.clone()),
            invalidate: None,
            ua,
        })
    }));
    Op::prepare(sdk, d).await
}
