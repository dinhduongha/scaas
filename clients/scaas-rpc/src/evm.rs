// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The EVM reader (spec §5.2): `EvmPool`, alloy providers per endpoint on the crate's bounded transport ([`BoundedRpc`],
//! CLI-RPC-07: never `connect_reqwest`, which reads an answer whole), identity per endpoint (CLI-RPC-03), failover reads
//! (CLI-RPC-04) and the first-endpoint reads that never fail over (F4). Lifted from the node's `chain.rs` with its rules; the node's
//! lane keys, sends and typed contract reads stay in the node.

use crate::endpoint::{NodeList, Purpose};
use crate::error::{endpoint_text, EndpointFailure, FailureKind, RpcError};
use crate::http::{BoundedRpc, Http, ANSWER_MAX};
/// The pinned-read types the SDK names with `EvmPool` (spec §13), the hash an EVM block hash.
pub use crate::pool::{Agreed, BlockChoice, ReadAt};
use crate::pool::{Answer, Pool, Probe, ReadError};
use alloy::eips::BlockNumberOrTag;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, B256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::client::ClientBuilder;
use alloy::rpc::types::{Filter, Log, TransactionRequest};
use alloy::transports::TransportError;
use std::future::Future;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, OnceLock};
use web_time::Instant;

/// A simulation or a read failed because the contract reverted (final for this state) or because of the transport (transient).
/// Merging the two would kill a job for one flaky RPC answer (the node's review P7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimError {
    Revert(String),
    Transport(String),
}

impl std::fmt::Display for SimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SimError::Revert(s) => write!(f, "revert: {s}"),
            SimError::Transport(s) => write!(f, "transport: {s}"),
        }
    }
}

/// `SigCheck.isContract`: code, and not an EIP-7702 designator (`0xef0100 ‖ address`: an EOA, ECDSA by its own key only).
pub fn is_contract(code: &[u8]) -> bool {
    let designator = code.len() == 23 && code.starts_with(&[0xef, 0x01, 0x00]);
    !code.is_empty() && !designator
}

/// A revert's data as text when the caller has no ABI for it: `Error(string)`'s reason, `Panic(uint256)`'s code, else the hex.
pub fn default_decode(data: &[u8]) -> String {
    use alloy::sol_types::SolValue;
    match data.get(..4) {
        Some([0x08, 0xc3, 0x79, 0xa0]) => {
            String::abi_decode(&data[4..]).unwrap_or_else(|_| alloy::hex::encode_prefixed(data))
        }
        Some([0x4e, 0x48, 0x7b, 0x71]) => alloy::primitives::U256::abi_decode(&data[4..])
            .map(|c| format!("Panic({c:#x})"))
            .unwrap_or_else(|_| alloy::hex::encode_prefixed(data)),
        _ => alloy::hex::encode_prefixed(data),
    }
}

/// [`classify_with`] with [`default_decode`].
pub fn classify(e: &TransportError) -> SimError {
    classify_with(e, default_decode)
}

/// A revert first (its data decoded by `decode`); a JSON-RPC error that says "revert", or "execution" without being a node's own
/// limit, is the EVM's answer too; anything else is the transport's (the node's recheck 2 P3-8, recheck 3 R3-6).
pub fn classify_with(e: &TransportError, decode: fn(&[u8]) -> String) -> SimError {
    match e.as_error_resp() {
        Some(resp) => match resp.as_revert_data() {
            // T13 S4 (CLI-RPC-11): the endpoint's text, capped and cleaned, a decoded reason too
            Some(data) => SimError::Revert(endpoint_text(&decode(&data))),
            None if resp.message.contains("revert") => {
                SimError::Revert(endpoint_text(&resp.message))
            }
            None if resp.message.contains("execution") && !node_limit(&resp.message) => {
                SimError::Revert(endpoint_text(&resp.message))
            }
            None => SimError::Transport(endpoint_text(&resp.message)),
        },
        None => SimError::Transport(e.to_string()),
    }
}

/// The revert's data as bytes, when the error answer carries it (CLI-RPC-12 Q5: the verifier keeps it as bytes).
pub fn revert_data(e: &TransportError) -> Option<Bytes> {
    e.as_error_resp().and_then(|r| r.as_revert_data())
}

/// A node's own limit on one call, not the EVM's answer: geth's `execution aborted (timeout = 5s)` (`--rpc.evmtimeout`).
/// Nethermind 2.2.0 answers its own timeout with `<method> request was canceled due to enabled timeout.` (from its
/// `Nethermind.JsonRpc.dll`, not seen in a run): neither "revert" nor "execution", so [`classify`] reads it as transport already.
/// A timed-out `eth_estimateGas` may answer `err: Cancellation Requested (supplied gas <n>)` (from the DLLs): transport too.
/// Erigon's and Reth's are not verified: one containing "execution" would read as a revert.
fn node_limit(m: &str) -> bool {
    m.starts_with("execution aborted (timeout = ") && m.ends_with(')')
}

/// [`classify`] for a simulation without a gas field: "out of gas" / "gas required exceeds allowance" there is the call needing
/// more than 2^24 regular gas (EIP-7825 under EIP-8037) or more than the RPC's gas cap: no gas limit makes it fit, so it is the
/// job's answer, not the network's (Nethermind 2.2.0 answers exactly these two for an endless loop).
pub fn classify_sim(e: &TransportError) -> SimError {
    classify_sim_with(e, default_decode)
}

pub fn classify_sim_with(e: &TransportError, decode: fn(&[u8]) -> String) -> SimError {
    match classify_with(e, decode) {
        SimError::Transport(m)
            if m.contains("out of gas") || m.contains("gas required exceeds allowance") =>
        {
            SimError::Revert(format!(
                "over the 2^24 regular gas of a transaction or the RPC gas cap: {m}"
            ))
        }
        x => x,
    }
}

/// The smallest `eth_getLogs` span [`EvmPool::logs_back`] asks before it gives an endpoint up (R-6), and at most this many spans
/// per window (recheck 2 P3-3): a window is read in at most about 25 requests.
pub const LOG_SPAN_MIN: u64 = 10;
pub const LOG_WINDOW_SPANS: u64 = 20;

/// The `latest` header's gas facts ([`EvmPool::block_gas`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockGas {
    pub limit: u64,
    /// EIP-7928's `blockAccessListHash` is in the header: the Amsterdam two-dimensional gas model applies.
    pub amsterdam: bool,
}

/// What several pools of one chain share: the highest block seen from the first endpoint, the total of failover answers.
#[derive(Clone, Default)]
pub struct Shared {
    pub head: Arc<AtomicU64>,
    pub failover: Arc<AtomicU64>,
}

/// One endpoint list of one EVM chain.
pub struct EvmPool {
    number: u64,
    list: Arc<NodeList>,
    pool: Pool,
    http: Http,
    /// each request bounded by the list's `timeout_ms` (reads, log spans, the first-endpoint reads)
    providers: Vec<DynProvider>,
    /// the same endpoints, each request bounded by `slow_timeout_ms`: the simulation only
    simulators: Vec<DynProvider>,
    pinned_uid: Option<B256>,
    uid: Arc<OnceLock<B256>>,
    decode: fn(&[u8]) -> String,
}

fn is_local(url: &url::Url) -> bool {
    matches!(
        url.host_str(),
        Some("localhost") | Some("127.0.0.1") | Some("[::1]")
    )
}

impl EvmPool {
    /// The pool of `list` for chain `chain_id`; `chain_uid` (block 0's hash) is required by `strict_majority` and by a read that
    /// feeds a decryption (`Argument` otherwise).
    pub fn connect(
        list: NodeList,
        chain_id: u64,
        chain_uid: Option<B256>,
    ) -> Result<Self, RpcError> {
        if list.policy == crate::Policy::StrictMajority && chain_uid.is_none() {
            return Err(RpcError::argument(
                "strict_majority needs a pinned chain_uid",
            ));
        }
        let (http, slow) = (
            Http::new(list.timeout_ms)?,
            Http::new(list.slow_timeout_ms)?,
        );
        let list = Arc::new(list);
        let pool = Pool::new(&list, chain_uid.is_some());
        let set = |h: &Http| {
            (0..list.len())
                .map(|i| Self::provider(h, &list, i, None))
                .collect::<Vec<_>>()
        };
        let (providers, simulators) = (set(&http), set(&slow));
        Ok(Self {
            number: chain_id,
            list,
            pool,
            http,
            providers,
            simulators,
            pinned_uid: chain_uid,
            uid: Default::default(),
            decode: default_decode,
        })
    }

    /// With the head and the failover total shared per `[[chains]]` table (feature `node-internal`: the node's pools of one chain).
    /// Every endpoint, the first included, is identity-checked as in [`EvmPool::connect`] (T13 point 6).
    #[cfg(feature = "node-internal")]
    pub fn with_shared(mut self, shared: Shared) -> Self {
        self.pool = Pool::shared(
            &self.list,
            self.pinned_uid.is_some(),
            shared.head,
            shared.failover,
        );
        self
    }

    /// With reverts decoded by `decode` (feature `node-internal`: the node's ABI).
    #[cfg(feature = "node-internal")]
    pub fn with_decode(mut self, decode: fn(&[u8]) -> String) -> Self {
        self.decode = decode;
        self
    }

    fn provider(
        h: &Http,
        list: &Arc<NodeList>,
        i: usize,
        deadline: Option<Instant>,
    ) -> DynProvider {
        let t = BoundedRpc::new(h.clone(), list.clone(), i, ANSWER_MAX, deadline);
        let client = ClientBuilder::default().transport(t, is_local(list.endpoints()[i].url()));
        ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect_client(client)
            .erased()
    }

    /// Endpoint `i`'s provider, its requests bounded by `deadline` too when given.
    pub(crate) fn at(&self, i: usize, deadline: Option<Instant>) -> DynProvider {
        match deadline {
            None => self.providers[i].clone(),
            Some(_) => Self::provider(&self.http, &self.list, i, deadline),
        }
    }

    /// The configured chain number.
    pub fn number(&self) -> u64 {
        self.number
    }
    pub fn list(&self) -> &NodeList {
        &self.list
    }
    pub fn pool(&self) -> &Pool {
        &self.pool
    }
    /// The `chain_uid` cell (feature `node-internal`: the node's `Chain` keeps it).
    #[cfg(feature = "node-internal")]
    pub fn uid_cell(&self) -> Arc<OnceLock<B256>> {
        self.uid.clone()
    }

    /// Endpoint `i`'s provider, its requests bounded by `deadline` too when given (feature `node-internal`: a server that runs
    /// its own read rule over the list, the PQZ verifier's per-index reads, F10).
    #[cfg(feature = "node-internal")]
    pub fn endpoint(&self, i: usize, deadline: Option<Instant>) -> DynProvider {
        self.at(i, deadline)
    }

    /// Endpoint 0's provider (feature `node-internal`: the node's lane and indexer reads).
    #[cfg(feature = "node-internal")]
    pub fn primary(&self) -> &DynProvider {
        &self.providers[0]
    }
    /// The providers after endpoint 0 (feature `node-internal`: the indexers' quorum).
    #[cfg(feature = "node-internal")]
    pub fn others(&self) -> &[DynProvider] {
        &self.providers[1..]
    }

    /// A block of this chain from the first endpoint (a lane's receipt, a polled head): failover endpoints below it answer no read.
    pub fn saw_block(&self, n: u64) {
        self.pool.saw_block(n)
    }
    /// The highest block seen ([`EvmPool::saw_block`]).
    pub fn seen_head(&self) -> u64 {
        self.pool.seen_head()
    }
    /// How many reads a failover endpoint answered (a value, never a verdict): a refusal read while this moved is no verdict.
    pub fn failover_answers(&self) -> u64 {
        self.pool.failover_answers()
    }

    /// The node's failover read (feature `node-internal`): one endpoint answers `f` whole (CLI-RPC-04).
    #[cfg(feature = "node-internal")]
    pub async fn raw_read<T, F, Fut>(&self, f: F) -> Result<T, SimError>
    where
        F: Fn(DynProvider) -> Fut,
        Fut: Future<Output = Result<T, SimError>>,
    {
        self.read_within(false, f).await.map(|(t, _)| t)
    }

    /// [`EvmPool::raw_read`] with the index of the endpoint that answered: a caller that reads a refusal out of an `Ok` takes it
    /// from the first endpoint only.
    #[cfg(feature = "node-internal")]
    pub async fn raw_read_at<T, F, Fut>(&self, f: F) -> Result<(T, usize), SimError>
    where
        F: Fn(DynProvider) -> Fut,
        Fut: Future<Output = Result<T, SimError>>,
    {
        self.read_within(false, f).await
    }

    /// The failover read over [`crate::pool::Pool::failover`]; `simulate`: `f` gets the endpoint's simulation client.
    pub(crate) async fn read_within<T, F, Fut>(
        &self,
        simulate: bool,
        f: F,
    ) -> Result<(T, usize), SimError>
    where
        F: Fn(DynProvider) -> Fut,
        Fut: Future<Output = Result<T, SimError>>,
    {
        let r = self
            .pool
            .failover(self, Purpose::Plain, |i| {
                let fut = f(if simulate {
                    self.simulators[i].clone()
                } else {
                    self.providers[i].clone()
                });
                async move {
                    fut.await.map_err(|e| match e {
                        SimError::Revert(reason) => ReadError::Revert {
                            data: vec![],
                            reason,
                        },
                        SimError::Transport(s) => {
                            ReadError::Failure(EndpointFailure::new(i, FailureKind::Transport, &s))
                        }
                    })
                }
            })
            .await;
        match r {
            Ok(Answer { value, endpoint }) => Ok((value, endpoint)),
            Err(e) => Err(self.sim_error(e)),
        }
    }

    /// An `RpcError` of a failover read as the node's `SimError`: the first endpoint's revert, else the last failure's text.
    pub(crate) fn sim_error(&self, e: RpcError) -> SimError {
        match e {
            RpcError::Revert { reason, .. } => SimError::Revert(reason),
            RpcError::EndpointAllFailed { last: Some(l), .. } => {
                SimError::Transport(self.failure_text(&l))
            }
            e => SimError::Transport(e.to_string()),
        }
    }

    fn failure_text(&self, l: &EndpointFailure) -> String {
        match l.kind {
            FailureKind::WrongChain => {
                format!("endpoint {} is not chain {}", l.endpoint, self.number)
            }
            FailureKind::BehindHead => format!("endpoint {} {}", l.endpoint, l.text()),
            FailureKind::ChainIdentityUnreadable => {
                format!("ChainIdentityUnreadable: {}", l.text())
            }
            _ => l.text().to_string(),
        }
    }

    /// One `eth_call` (with `from` and `gas` when given), classified.
    pub async fn call_tx(&self, tx: TransactionRequest) -> Result<Bytes, SimError> {
        let d = self.decode;
        self.read_within(false, |p| {
            let tx = tx.clone();
            async move { p.call(tx).await.map_err(|e| classify_with(&e, d)) }
        })
        .await
        .map(|(b, _)| b)
    }

    /// `eth_call` then `eth_estimateGas` from `from`: the gas limit the transaction needs, regular + state (EIP-8037); no gas
    /// field, so both run at the RPC's gas cap. Each request under `slow_timeout_ms`. The caller caps the gas it accepts.
    pub async fn simulate_from(
        &self,
        from: Address,
        to: Address,
        data: Bytes,
    ) -> Result<u64, SimError> {
        let tx = TransactionRequest::default()
            .with_from(from)
            .with_to(to)
            .with_input(data);
        let d = self.decode;
        self.read_within(true, |p| {
            let tx = tx.clone();
            async move {
                p.call(tx.clone())
                    .await
                    .map_err(|e| classify_sim_with(&e, d))?;
                p.estimate_gas(tx)
                    .await
                    .map_err(|e| classify_sim_with(&e, d))
            }
        })
        .await
        .map(|(g, _)| g)
    }

    /// The `latest` header's gas facts, from the raw header (any RPC's block shape).
    pub async fn block_gas(&self) -> Result<BlockGas, SimError> {
        let (b, _): (serde_json::Value, usize) = self
            .read_within(false, |p| async move {
                p.raw_request("eth_getBlockByNumber".into(), ("latest", false))
                    .await
                    .map_err(|e| SimError::Transport(e.to_string()))
            })
            .await?;
        let g = b["gasLimit"].as_str().ok_or_else(|| {
            SimError::Transport(format!(
                "chain {}: latest block without gasLimit",
                self.number
            ))
        })?;
        let limit = u64::from_str_radix(g.trim_start_matches("0x"), 16)
            .map_err(|e| SimError::Transport(format!("gasLimit: {e}")))?;
        Ok(BlockGas {
            limit,
            amsterdam: b.get("blockAccessListHash").is_some(),
        })
    }

    /// This chain's `chain_uid`: block 0's hash, which must equal the pinned one when set (a pruned RPC without block 0 trusts
    /// the pin). Kept once read; an error is not kept.
    pub async fn uid(&self) -> Result<B256, RpcError> {
        if let Some(u) = self.uid.get() {
            return Ok(*u);
        }
        let d = self.decode;
        let genesis = self
            .read_within(false, |p| async move {
                p.get_block_by_number(BlockNumberOrTag::Number(0))
                    .await
                    .map_err(|e| classify_with(&e, d))
            })
            .await
            .map_err(|e| RpcError::EndpointAllFailed {
                last: Some(EndpointFailure::new(
                    0,
                    FailureKind::Transport,
                    &format!("chain {}: block 0: {e}", self.number),
                )),
                failover_revert: None,
            })?;
        let (genesis, at) = (genesis.0.map(|b| b.header.hash), genesis.1);
        let u = match (self.pinned_uid, genesis) {
            (Some(p), Some(g)) if p != g => {
                return Err(RpcError::argument(&format!(
                    "chain {}: RPC block 0 {g:#x} is not chain_uid {p:#x}",
                    self.number
                )))
            }
            (None, Some(g)) | (Some(g), Some(_)) => g,
            // T13 S16: no block 0: the pin only when the answering endpoint matched its checkpoint (identity)
            (Some(p), None) if self.list.endpoints()[at].checkpoint().is_some() => p,
            (Some(_), None) => {
                return Err(RpcError::EndpointAllFailed {
                    last: Some(EndpointFailure::new(
                        at,
                        FailureKind::ChainIdentityUnreadable,
                        &format!(
                            "chain {}: endpoint {at} serves no block 0 and names no checkpoint",
                            self.number
                        ),
                    )),
                    failover_revert: None,
                })
            }
            (None, None) => {
                return Err(RpcError::argument(&format!(
                    "chain {}: the RPC gives no block 0 hash; set chain_uid",
                    self.number
                )))
            }
        };
        Ok(*self.uid.get_or_init(|| u))
    }

    /// `who`'s runtime code, through the failover read.
    pub async fn code(&self, who: Address) -> Result<Bytes, SimError> {
        let d = self.decode;
        self.read_within(false, |p| async move {
            p.get_code_at(who).await.map_err(|e| classify_with(&e, d))
        })
        .await
        .map(|(c, _)| c)
    }

    /// `who` is a contract signer: [`is_contract`] of its code (an EIP-7702 designator is an EOA).
    pub async fn is_contract_at(&self, who: Address) -> Result<bool, SimError> {
        Ok(is_contract(&self.code(who).await?))
    }

    /// Endpoint `p`'s block `n` hash (`None`: unread or absent).
    pub async fn block_hash_on(p: &DynProvider, n: u64) -> Option<B256> {
        p.get_block_by_number(BlockNumberOrTag::Number(n))
            .await
            .ok()
            .flatten()
            .map(|b| b.header.hash)
    }

    /// The logs of `address` with `topic0` in the last `lookback` blocks.
    pub async fn logs_since(
        &self,
        address: Address,
        topic0: B256,
        lookback: u64,
    ) -> Result<Vec<Log>, SimError> {
        self.logs_back(
            Filter::new().address(address).event_signature(topic0),
            lookback,
        )
        .await
    }

    /// The logs of `filter` in the last `lookback` blocks, the head and the logs from one endpoint. An RPC that caps the
    /// `eth_getLogs` range refuses the whole window, so a span it refuses (an error answer) is asked again in tenths, down to
    /// [`LOG_SPAN_MIN`] blocks or a [`LOG_WINDOW_SPANS`]th of the window, whichever is larger; an endpoint that refuses the floor
    /// fails the read over. A transport error never shrinks a span; after an answer the span grows back (doubles), staying
    /// below half of a span refused. Each span is one request under `timeout_ms`. The first endpoint's head raises the head seen.
    pub async fn logs_back(&self, filter: Filter, lookback: u64) -> Result<Vec<Log>, SimError> {
        let d = self.decode;
        let (out, at) = self
            .read_within(false, |p| {
                let filter = filter.clone();
                async move {
                    let latest = p
                        .get_block_number()
                        .await
                        .map_err(|e| classify_with(&e, d))?;
                    let start = latest.saturating_sub(lookback);
                    let whole = latest - start + 1;
                    let floor = LOG_SPAN_MIN.max(whole.div_ceil(LOG_WINDOW_SPANS));
                    let (mut from, mut span, mut refused, mut out) =
                        (start, whole, u64::MAX, vec![]);
                    while from <= latest {
                        let to = latest.min(from.saturating_add(span - 1));
                        match p
                            .get_logs(&filter.clone().from_block(from).to_block(to))
                            .await
                        {
                            Ok(l) => {
                                out.extend(l);
                                from = to + 1;
                                span = span.saturating_mul(2).min(refused / 2).max(span);
                            }
                            Err(e) if e.as_error_resp().is_some() && span > floor => {
                                tracing::debug!(span, "eth_getLogs span refused; a tenth of it");
                                refused = refused.min(span);
                                span = (span / 10).max(floor);
                            }
                            // never a revert: a log read has no contract answer
                            Err(e) => return Err(SimError::Transport(e.to_string())),
                        }
                    }
                    Ok((latest, out))
                }
            })
            .await?;
        if at == 0 {
            self.saw_block(out.0);
        }
        Ok(out.1)
    }

    // ------------------------------------------------------------ the SDK's head reads (failover; strict majority: plan T6)

    /// A receipt, failed over: a value, never terminal (`tx_state` decides, CLI-RPC-09).
    pub async fn receipt(
        &self,
        id: B256,
    ) -> Result<Option<alloy::rpc::types::TransactionReceipt>, RpcError> {
        self.failover_read(Purpose::Plain, |p| async move {
            p.get_transaction_receipt(id).await
        })
        .await
    }

    /// A failover read of one provider call, classified (a revert keeps its data as bytes).
    pub(crate) async fn failover_read<T, F, Fut>(
        &self,
        purpose: Purpose,
        f: F,
    ) -> Result<T, RpcError>
    where
        F: Fn(DynProvider) -> Fut,
        Fut: Future<Output = Result<T, TransportError>>,
    {
        let d = self.decode;
        self.pool
            .failover(self, purpose, |i| {
                let fut = f(self.providers[i].clone());
                async move { fut.await.map_err(|e| read_error(i, &e, d)) }
            })
            .await
            .map(|a| a.value)
    }

    // ------------------------------------------------------------ first-endpoint reads (F4): endpoint 0 only, never failover

    /// Endpoint 0 may be asked (T13 S3: a dropped endpoint 0 answers no first-endpoint read either).
    async fn first(&self) -> Result<(), RpcError> {
        self.pool
            .admit(self, 0, None)
            .await
            .map_err(|f| RpcError::EndpointAllFailed {
                last: Some(f),
                failover_revert: None,
            })
    }

    /// The pending nonce of `who` from endpoint 0 (the lane's own).
    pub async fn first_pending_nonce(&self, who: Address) -> Result<u64, RpcError> {
        self.first().await?;
        self.providers[0]
            .get_transaction_count(who)
            .pending()
            .await
            .map_err(|e| first_err(&e))
    }
    /// The committed (`latest`) nonce of `who` from endpoint 0.
    pub async fn first_nonce_at(&self, who: Address) -> Result<u64, RpcError> {
        self.first().await?;
        self.providers[0]
            .get_transaction_count(who)
            .latest()
            .await
            .map_err(|e| first_err(&e))
    }
    /// EIP-1559 fees from endpoint 0: (max fee, at least 1; priority fee).
    pub async fn first_fees(&self) -> Result<(u128, u128), RpcError> {
        self.first().await?;
        let est = self.providers[0]
            .estimate_eip1559_fees()
            .await
            .map_err(|e| first_err(&e))?;
        Ok((est.max_fee_per_gas.max(1), est.max_priority_fee_per_gas))
    }
    /// A receipt from endpoint 0.
    pub async fn first_receipt(
        &self,
        hash: B256,
    ) -> Result<Option<alloy::rpc::types::TransactionReceipt>, RpcError> {
        self.first().await?;
        self.providers[0]
            .get_transaction_receipt(hash)
            .await
            .map_err(|e| first_err(&e))
    }
    /// The gas limit and max fee per gas of transaction `hash` as sent, from endpoint 0; `None` if it does not know it (the fee:
    /// if it gives none, e.g. a legacy transaction).
    pub async fn first_tx_fees(&self, hash: B256) -> Result<Option<(u64, Option<u128>)>, RpcError> {
        self.first().await?;
        let t: serde_json::Value = self.providers[0]
            .raw_request("eth_getTransactionByHash".into(), (hash,))
            .await
            .map_err(|e| first_err(&e))?;
        let hex = |k: &str| {
            t[k].as_str()
                .map(|g| u128::from_str_radix(g.trim_start_matches("0x"), 16))
        };
        let bad = |_| RpcError::argument("a transaction field that is not a number");
        let Some(gas) = hex("gas") else {
            return Ok(None);
        };
        let gas =
            u64::try_from(gas.map_err(bad)?).map_err(|_| RpcError::argument("a gas above u64"))?;
        Ok(Some((gas, hex("maxFeePerGas").transpose().map_err(bad)?)))
    }
    /// The `finalized` block's number from endpoint 0 (`None`: unread or none).
    pub async fn first_finalized_number(&self) -> Option<u64> {
        self.first().await.ok()?;
        self.providers[0]
            .get_block_by_number(BlockNumberOrTag::Finalized)
            .await
            .ok()
            .flatten()
            .map(|b| b.header.number)
    }
}

/// One endpoint's transport error as the pool reads it: a revert (its data as bytes, its text by `decode`) or a failure.
pub(crate) fn read_error(i: usize, e: &TransportError, decode: fn(&[u8]) -> String) -> ReadError {
    match classify_with(e, decode) {
        SimError::Revert(reason) => ReadError::Revert {
            data: revert_data(e).map(|b| b.to_vec()).unwrap_or_default(),
            reason,
        },
        SimError::Transport(_) => ReadError::Failure(transport(i, e)),
    }
}

/// EIP-1559 fee data: the max fee per gas (at least 1) and the priority fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fees {
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

/// A first-endpoint read's failure: endpoint 0's, never failed over.
fn first_err(e: &TransportError) -> RpcError {
    RpcError::EndpointAllFailed {
        last: Some(EndpointFailure::new(
            0,
            FailureKind::Transport,
            &e.to_string(),
        )),
        failover_revert: None,
    }
}

fn transport(i: usize, e: &TransportError) -> EndpointFailure {
    EndpointFailure::new(i, FailureKind::Transport, &e.to_string())
}

impl Probe for EvmPool {
    type Hash = B256;

    /// Endpoint `i`'s `eth_chainId` is the chain's and its block 0 hash is the chain's (the pinned `chain_uid`, else the one
    /// [`EvmPool::uid`] read, else the first endpoint's block 0).
    async fn same_chain(
        &self,
        i: usize,
        deadline: Option<Instant>,
    ) -> Result<bool, EndpointFailure> {
        let p = self.at(i, deadline);
        let unread = |what: &str| {
            EndpointFailure::new(
                i,
                FailureKind::IdentityUnread,
                &format!("endpoint {i}: {what} unreadable; not used"),
            )
        };
        let id = p.get_chain_id().await.map_err(|_| unread("chain id"))?;
        if id != self.number {
            return Ok(false);
        }
        let want = match self.pinned_uid.or(self.uid.get().copied()) {
            Some(u) => u,
            None => Self::block_hash_on(&self.at(0, deadline), 0)
                .await
                .ok_or_else(|| unread("the first endpoint's block 0"))?,
        };
        match p.get_block_by_number(BlockNumberOrTag::Number(0)).await {
            Err(_) => Err(unread("block 0")),
            Ok(Some(b)) => Ok(b.header.hash == want),
            // T13 S16: no block 0: this chain only by the checkpoint its entry names, never by the pin alone
            Ok(None) => match self.list.endpoints()[i].checkpoint() {
                Some(c) => Ok(self.header(i, c.number, deadline).await? == B256::from(c.hash)),
                None => Err(EndpointFailure::new(
                    i,
                    FailureKind::ChainIdentityUnreadable,
                    &format!("endpoint {i} serves no block 0 and names no checkpoint"),
                )),
            },
        }
    }

    async fn head(&self, i: usize, deadline: Option<Instant>) -> Result<u64, EndpointFailure> {
        self.at(i, deadline)
            .get_block_number()
            .await
            .map_err(|e| transport(i, &e))
    }

    async fn named(
        &self,
        i: usize,
        choice: BlockChoice,
        deadline: Option<Instant>,
    ) -> Result<u64, EndpointFailure> {
        let p = self.at(i, deadline);
        match choice {
            BlockChoice::Latest => p.get_block_number().await.map_err(|e| transport(i, &e)),
            BlockChoice::Depth(d) => Ok(p
                .get_block_number()
                .await
                .map_err(|e| transport(i, &e))?
                .saturating_sub(d)),
            BlockChoice::Finalized => p
                .get_block_by_number(BlockNumberOrTag::Finalized)
                .await
                .map_err(|e| transport(i, &e))?
                .map(|b| b.header.number)
                .ok_or_else(|| {
                    EndpointFailure::new(i, FailureKind::Transport, "no finalized block")
                }),
        }
    }

    async fn header(
        &self,
        i: usize,
        number: u64,
        deadline: Option<Instant>,
    ) -> Result<B256, EndpointFailure> {
        let b = self
            .at(i, deadline)
            .get_block_by_number(BlockNumberOrTag::Number(number))
            .await
            .map_err(|e| transport(i, &e))?
            .ok_or_else(|| {
                EndpointFailure::new(i, FailureKind::Transport, &format!("no block {number}"))
            })?;
        if b.header.number != number {
            return Err(EndpointFailure::new(
                i,
                FailureKind::AnswerMalformed,
                &format!("asked block {number}, answered {}", b.header.number),
            ));
        }
        Ok(b.header.hash)
    }
}

// ---------------------------------------------------------------- plan T6: pinned reads and strict majority (CLI-RPC-05)

/// The most blocks one [`EvmPool::logs_range`] covers (F23): a caller pages a longer history itself.
pub const LOG_RANGE_MAX: u64 = 10_000;

/// A log as an agreed read compares it (spec §4.4; an honest client's extra fields are not compared, I1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogAt {
    pub block_hash: Option<B256>,
    pub tx_hash: Option<B256>,
    pub log_index: Option<u64>,
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
}

impl From<&Log> for LogAt {
    fn from(l: &Log) -> Self {
        Self {
            block_hash: l.block_hash,
            tx_hash: l.transaction_hash,
            log_index: l.log_index,
            address: l.address(),
            topics: l.topics().to_vec(),
            data: l.data().data.clone(),
        }
    }
}

/// A receipt as compared: counted only when its block hash is the endpoint's header hash at its number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptAt {
    pub block_hash: B256,
    pub block_number: u64,
    pub status: bool,
    pub gas_used: u64,
    pub logs: Vec<LogAt>,
}

/// A transaction by hash as compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxAt {
    pub block_hash: Option<B256>,
    pub block_number: Option<u64>,
    pub from: Address,
    pub nonce: u64,
}

/// Every request of a pinned read names its block by hash (EIP-1898, `requireCanonical`).
pub fn pinned(at: &ReadAt<B256>) -> alloy::eips::BlockId {
    alloy::eips::BlockId::Hash(alloy::eips::RpcBlockHash {
        block_hash: at.hash,
        require_canonical: Some(true),
    })
}

impl EvmPool {
    /// A read pinned to one block, by the list's policy (spec §4.4): under `strict_majority` the agreed read; under `failover`
    /// one endpoint names its block for `choice`, reads its header there, runs `f` pinned to that hash, and reads the header
    /// again (a moved hash is that endpoint's failure, `BlockChanged`).
    pub async fn read_at_block<T, F, Fut>(
        &self,
        choice: BlockChoice,
        purpose: Purpose,
        f: F,
    ) -> Result<Agreed<T, B256>, RpcError>
    where
        T: Clone + PartialEq,
        F: Fn(ReadAt<B256>) -> Fut,
        Fut: Future<Output = Result<T, ReadError>>,
    {
        if self.pool.policy() == crate::Policy::StrictMajority {
            return self.pool.agree(self, choice, purpose, f).await;
        }
        let f = &f;
        let a = self
            .pool
            .failover(self, purpose, |i| async move {
                let number = self.named(i, choice, None).await?;
                let hash = self.header(i, number, None).await?;
                let v = f(ReadAt {
                    endpoint: i,
                    number,
                    hash,
                    deadline: None,
                })
                .await?;
                if self.header(i, number, None).await? != hash {
                    return Err(ReadError::Failure(EndpointFailure::new(
                        i,
                        FailureKind::BlockChanged,
                        &format!("block {number} changed"),
                    )));
                }
                Ok((v, number, hash))
            })
            .await?;
        let (value, number, hash) = a.value;
        Ok(Agreed {
            value,
            number,
            hash,
            members: vec![a.endpoint],
            highest_named: number,
        })
    }

    /// `eth_call` at the read's block (by hash).
    pub async fn call_at(
        &self,
        at: &ReadAt<B256>,
        to: Address,
        data: Bytes,
    ) -> Result<Bytes, ReadError> {
        let tx = TransactionRequest::default().with_to(to).with_input(data);
        self.at(at.endpoint, at.deadline)
            .call(tx)
            .block(pinned(at))
            .await
            .map_err(|e| read_error(at.endpoint, &e, self.decode))
    }
    /// `eth_getStorageAt` at the read's block.
    pub async fn storage_at(
        &self,
        at: &ReadAt<B256>,
        who: Address,
        slot: alloy::primitives::U256,
    ) -> Result<alloy::primitives::U256, ReadError> {
        self.at(at.endpoint, at.deadline)
            .get_storage_at(who, slot)
            .block_id(pinned(at))
            .await
            .map_err(|e| read_error(at.endpoint, &e, self.decode))
    }
    /// `eth_getCode` at the read's block.
    pub async fn code_at(&self, at: &ReadAt<B256>, who: Address) -> Result<Bytes, ReadError> {
        self.at(at.endpoint, at.deadline)
            .get_code_at(who)
            .block_id(pinned(at))
            .await
            .map_err(|e| read_error(at.endpoint, &e, self.decode))
    }
    /// `eth_getBalance` at the read's block.
    pub async fn balance_at(
        &self,
        at: &ReadAt<B256>,
        who: Address,
    ) -> Result<alloy::primitives::U256, ReadError> {
        self.at(at.endpoint, at.deadline)
            .get_balance(who)
            .block_id(pinned(at))
            .await
            .map_err(|e| read_error(at.endpoint, &e, self.decode))
    }
    /// The committed nonce of `who` at the read's block.
    pub async fn nonce_at_block(&self, at: &ReadAt<B256>, who: Address) -> Result<u64, ReadError> {
        self.at(at.endpoint, at.deadline)
            .get_transaction_count(who)
            .block_id(pinned(at))
            .await
            .map_err(|e| read_error(at.endpoint, &e, self.decode))
    }
    /// A transaction by hash, from the read's endpoint (`None`: unknown to it).
    pub async fn tx_by_hash_at(
        &self,
        at: &ReadAt<B256>,
        id: B256,
    ) -> Result<Option<TxAt>, ReadError> {
        use alloy::consensus::Transaction as _;
        let t = self
            .at(at.endpoint, at.deadline)
            .get_transaction_by_hash(id)
            .await
            .map_err(|e| read_error(at.endpoint, &e, self.decode))?;
        Ok(t.map(|t| TxAt {
            block_hash: t.block_hash,
            block_number: t.block_number,
            from: t.inner.signer(),
            nonce: t.nonce(),
        }))
    }
    /// A receipt as of the read's block: counted only when its block is at or below it and its block hash is this endpoint's
    /// header hash at its number (else `None`).
    pub async fn receipt_at(
        &self,
        at: &ReadAt<B256>,
        id: B256,
    ) -> Result<Option<ReceiptAt>, ReadError> {
        Ok(self
            .checked_receipt(at.endpoint, id, at.deadline)
            .await?
            .filter(|r| r.block_number <= at.number))
    }

    /// A receipt whose block hash is the endpoint's header hash at its number (`None` otherwise or unknown).
    pub(crate) async fn checked_receipt(
        &self,
        i: usize,
        id: B256,
        deadline: Option<Instant>,
    ) -> Result<Option<ReceiptAt>, ReadError> {
        let p = self.at(i, deadline);
        let Some(r) = p
            .get_transaction_receipt(id)
            .await
            .map_err(|e| read_error(i, &e, self.decode))?
        else {
            return Ok(None);
        };
        let (Some(hash), Some(number)) = (r.block_hash, r.block_number) else {
            return Ok(None);
        };
        if self.header(i, number, deadline).await? != hash {
            return Ok(None);
        }
        Ok(Some(ReceiptAt {
            block_hash: hash,
            block_number: number,
            status: r.status(),
            gas_used: r.gas_used,
            logs: r.logs().iter().map(LogAt::from).collect(),
        }))
    }

    /// The logs of `filter` over blocks `[from, to]`, both required, at most [`LOG_RANGE_MAX`] blocks (`Argument` otherwise;
    /// F23), compared whole under `strict_majority`; an endpoint whose head is below `to` does not answer.
    pub async fn logs_range(
        &self,
        from: u64,
        to: u64,
        filter: Filter,
        purpose: Purpose,
    ) -> Result<Agreed<Vec<LogAt>, B256>, RpcError> {
        if to < from || to - from >= LOG_RANGE_MAX {
            return Err(RpcError::argument(&format!(
                "a log range is [from, to] with at most {LOG_RANGE_MAX} blocks"
            )));
        }
        let filter = &filter;
        self.read_at_block(BlockChoice::Latest, purpose, |at| async move {
            if at.number < to {
                return Err(ReadError::Failure(EndpointFailure::new(
                    at.endpoint,
                    FailureKind::BehindHead,
                    &format!("at block {}, below {to}", at.number),
                )));
            }
            let logs = self
                .at(at.endpoint, at.deadline)
                .get_logs(&filter.clone().from_block(from).to_block(to))
                .await
                .map_err(|e| ReadError::Failure(transport(at.endpoint, &e)))?;
            Ok(logs.iter().map(LogAt::from).collect())
        })
        .await
    }

    /// The head, failed over.
    pub async fn head(&self) -> Result<u64, RpcError> {
        self.failover_read(
            Purpose::Plain,
            |p| async move { p.get_block_number().await },
        )
        .await
    }
    /// The `finalized` block's number, failed over (`None`: the chain has none).
    pub async fn finalized(&self) -> Result<Option<u64>, RpcError> {
        self.failover_read(Purpose::Plain, |p| async move {
            p.get_block_by_number(BlockNumberOrTag::Finalized).await
        })
        .await
        .map(|b| b.map(|b| b.header.number))
    }
    /// Block `n`'s hash, failed over.
    pub async fn block_hash(&self, n: u64) -> Result<Option<B256>, RpcError> {
        self.failover_read(Purpose::Plain, |p| async move {
            p.get_block_by_number(BlockNumberOrTag::Number(n)).await
        })
        .await
        .map(|b| b.map(|b| b.header.hash))
    }
    /// The chain's `chain_uid` ([`EvmPool::uid`]).
    pub async fn chain_uid(&self) -> Result<B256, RpcError> {
        self.uid().await
    }

    /// The nonce of a new transaction from `who`: under `failover` its pending nonce failed over; under `strict_majority` the
    /// agreed committed nonce at the default block (the caller adds its own count of what it sent since; F14).
    pub async fn pending_nonce(&self, who: Address, purpose: Purpose) -> Result<u64, RpcError> {
        if self.pool.policy() == crate::Policy::StrictMajority {
            return self
                .read_at_block(BlockChoice::default(), purpose, |at| async move {
                    self.nonce_at_block(&at, who).await
                })
                .await
                .map(|a| a.value);
        }
        self.failover_read(purpose, |p| async move {
            p.get_transaction_count(who).pending().await
        })
        .await
    }

    /// EIP-1559 fee data: under `failover` failed over (the caller caps fee and gas from its own configuration); under
    /// `strict_majority` the `need`-th highest of the endpoints' values for each field (a minority moves it neither way; F14).
    pub async fn fees(&self, purpose: Purpose) -> Result<Fees, RpcError> {
        if self.pool.policy() != crate::Policy::StrictMajority {
            let f = self
                .failover_read(purpose, |p| async move { p.estimate_eip1559_fees().await })
                .await?;
            return Ok(Fees {
                max_fee_per_gas: f.max_fee_per_gas.max(1),
                max_priority_fee_per_gas: f.max_priority_fee_per_gas,
            });
        }
        let order = self.pool.usable(purpose)?;
        let n = self.list.len();
        let need = n / 2 + 1;
        let deadline = Some(self.pool.deadline());
        let got = futures::future::join_all(order.iter().map(|&i| async move {
            self.pool.admit(self, i, deadline).await?;
            self.at(i, deadline)
                .estimate_eip1559_fees()
                .await
                .map_err(|e| transport(i, &e))
        }))
        .await;
        let (mut max, mut prio, mut failures) = (vec![], vec![], vec![]);
        for g in got {
            match g {
                Ok(f) => {
                    max.push(f.max_fee_per_gas);
                    prio.push(f.max_priority_fee_per_gas);
                }
                Err(e) => failures.push(e),
            }
        }
        if max.len() < need {
            return Err(RpcError::EndpointNoMajority {
                n,
                need,
                largest: max.len(),
                failures,
            });
        }
        max.sort_unstable_by(|a, b| b.cmp(a));
        prio.sort_unstable_by(|a, b| b.cmp(a));
        Ok(Fees {
            max_fee_per_gas: max[need - 1].max(1),
            max_priority_fee_per_gas: prio[need - 1],
        })
    }
}

// ---------------------------------------------------------------- plan T7: the same signed bytes to several endpoints, state

/// The "already known" answers of the clients, each meaning the endpoint holds this very transaction (CLI-RPC-08, F24):
/// - geth (and its forks): `already known` (`core/txpool`, `ErrAlreadyKnown`);
/// - Nethermind 2.2.0: `already known` (`Nethermind.TxPool.dll`, `AcceptTxResult.AlreadyKnown`, read from the local
///   `nethermind/nethermind:2.2.0` image);
/// - anvil (foundry 1.8.5): `transaction already imported` (its pool's `AlreadyImported`, seen in `tests/anvil.rs`).
pub const ALREADY_KNOWN: [&str; 2] = ["already known", "transaction already imported"];

pub use crate::endpoint::Fanout;

/// One endpoint's answer to a send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// it holds the transaction (its hash answered, or "already known")
    Accepted,
    /// a well-formed rejection, its reason capped and redacted ("nonce too low", "another transaction id", …)
    Refused { reason: String },
    /// transport, timeout, HTTP error, malformed answer
    Unreachable { failure: EndpointFailure },
}

/// The merge of a send (CLI-RPC-08): never a final verdict on the transaction ([`EvmPool::tx_state`] decides).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastOutcome {
    Sent {
        id: B256,
        accepted: Vec<usize>,
        others: Vec<(usize, SendOutcome)>,
    },
    Rejected {
        id: B256,
        outcomes: Vec<(usize, SendOutcome)>,
    },
}

impl BroadcastOutcome {
    /// `BroadcastRejected` for `Rejected` (the app's code 20), else `None`.
    pub fn code(&self) -> Option<&'static str> {
        matches!(self, BroadcastOutcome::Rejected { .. }).then_some("BroadcastRejected")
    }
    pub fn id(&self) -> B256 {
        match self {
            BroadcastOutcome::Sent { id, .. } | BroadcastOutcome::Rejected { id, .. } => *id,
        }
    }
}

/// A type-3 (blob) transaction in its network form (`0x03 ‖ rlp([tx_payload_body, blobs, commitments, proofs])`): its first
/// list item is itself a list, where the canonical form's is the chain id.
fn blob_network_form(raw: &[u8]) -> bool {
    if raw.first() != Some(&0x03) {
        return false;
    }
    let body = &raw[1..];
    // the outer list's header: one byte (a short list), or one plus its length's bytes
    let skip = match body.first() {
        Some(0xc0..=0xf7) => Some(1),
        Some(b @ 0xf8..=0xff) => Some(1 + (*b as usize - 0xf7)),
        _ => None,
    };
    matches!(skip.and_then(|k| body.get(k)), Some(0xc0..=0xff))
}

/// A transaction's state (CLI-RPC-09): terminal only from a decisive read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxState {
    /// a receipt at or below the final block, its block hash the endpoint's header hash at its number (terminal)
    Final {
        number: u64,
        hash: B256,
        success: bool,
    },
    /// the sender's nonce at the final block above the transaction's, the transaction and its receipt unknown, in one decisive
    /// read (terminal; never re-sent automatically); under `strict_majority` only from an agreed read at the finalized block
    Replaced { by_nonce: u64, basis: Basis },
    /// a receipt above the final block, or from a read that is not decisive
    Included {
        number: u64,
        hash: B256,
        success: bool,
        endpoint: usize,
    },
    /// none of the above (also `Replaced`'s facts from an endpoint that is not decisive)
    Pending { endpoint: Option<usize> },
}

impl TxState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, TxState::Final { .. } | TxState::Replaced { .. })
    }
}

/// What a `Replaced` or `FailedForGood` rests on (T13 S7, owner 2026-11-17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// agreed by a strict majority at the finalized block
    Majority,
    /// endpoint 0 alone (`failover`)
    OneEndpoint,
}

impl std::fmt::Display for Basis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Basis::Majority => "agreed by a majority at the finalized block",
            Basis::OneEndpoint => "rests on one endpoint (endpoint 0, failover)",
        })
    }
}

impl std::fmt::Display for TxState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxState::Final {
                number, success, ..
            } => write!(f, "final at block {number}, success {success}"),
            TxState::Replaced { by_nonce, basis } => {
                write!(f, "replaced: the sender's nonce is {by_nonce}; {basis}")
            }
            TxState::Included {
                number, endpoint, ..
            } => {
                write!(
                    f,
                    "included at block {number} (endpoint {endpoint}), not final"
                )
            }
            TxState::Pending { .. } => f.write_str("pending"),
        }
    }
}

impl std::fmt::Display for OpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpState::Landed => f.write_str("landed"),
            OpState::FailedForGood { basis } => write!(f, "failed for good; {basis}"),
            OpState::Pending => f.write_str("pending"),
        }
    }
}

/// The facts of one read for [`EvmPool::tx_state`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct TxFacts {
    receipt: Option<ReceiptAt>,
    nonce: u64,
    known: bool,
}

/// A relayed operation's state (CLI-RPC-09): terminal only on chain facts at the final block from a decisive read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpState {
    /// its executed event at or below the final block
    Landed,
    /// the subject's operation nonce spent at the final block without its executed event, or its deadline below the final
    /// block's timestamp while the nonce is unspent; under `strict_majority` only from an agreed read at the finalized block
    FailedForGood {
        basis: Basis,
    },
    Pending,
}

/// What a relayed operation's state reads: the nonce view (`call` to `contract`, decoded to the nonce now), the executed
/// event's filter, the operation's nonce and its `validUntil`.
#[derive(Debug, Clone)]
pub struct OpQuery {
    pub contract: Address,
    pub nonce_call: Bytes,
    pub nonce: alloy::primitives::U256,
    pub executed: Filter,
    pub from_block: u64,
    pub valid_until: u64,
}

impl EvmPool {
    /// CLI-RPC-08: the same `raw` bytes to the first endpoint or to all, concurrently; the id is `keccak256(raw)`, computed before
    /// any request (a blob transaction in its network form is refused by name, `Argument`). `Sent` when one endpoint accepted,
    /// else `Rejected`; neither is final.
    pub async fn broadcast(
        &self,
        raw: &[u8],
        fanout: Fanout,
    ) -> Result<BroadcastOutcome, RpcError> {
        if blob_network_form(raw) {
            return Err(RpcError::argument(
                "a blob transaction in its network form: send its canonical form",
            ));
        }
        let id = alloy::primitives::keccak256(raw);
        let hex = alloy::hex::encode_prefixed(raw);
        let to: Vec<usize> = match fanout {
            Fanout::First => vec![0],
            Fanout::All => (0..self.list.len()).collect(),
        };
        let outcomes = futures::future::join_all(to.iter().map(|&i| {
            let hex = hex.clone();
            async move {
                if let Err(failure) = self.pool.admit(self, i, None).await {
                    return (i, SendOutcome::Unreachable { failure });
                }
                let a = self
                    .http
                    .json_rpc(
                        &self.list,
                        i,
                        "eth_sendRawTransaction",
                        serde_json::json!([hex]),
                        1 << 20,
                        None,
                    )
                    .await;
                (
                    i,
                    match a {
                        Err(failure) => SendOutcome::Unreachable { failure },
                        Ok(Ok(v)) => match v.as_str().and_then(|s| s.parse::<B256>().ok()) {
                            Some(h) if h == id => SendOutcome::Accepted,
                            _ => SendOutcome::Refused {
                                reason: "another transaction id".into(),
                            },
                        },
                        Ok(Err(e))
                            if ALREADY_KNOWN
                                .iter()
                                .any(|k| e.message.to_lowercase().contains(k)) =>
                        {
                            SendOutcome::Accepted
                        }
                        Ok(Err(e)) => SendOutcome::Refused {
                            reason: endpoint_text(&e.message),
                        },
                    },
                )
            }
        }))
        .await;
        let accepted: Vec<usize> = outcomes
            .iter()
            .filter(|(_, o)| *o == SendOutcome::Accepted)
            .map(|(i, _)| *i)
            .collect();
        Ok(if accepted.is_empty() {
            BroadcastOutcome::Rejected { id, outcomes }
        } else {
            BroadcastOutcome::Sent {
                id,
                accepted,
                others: outcomes
                    .into_iter()
                    .filter(|(_, o)| *o != SendOutcome::Accepted)
                    .collect(),
            }
        })
    }

    /// CLI-RPC-09: `id` sent by `from` with `nonce`, read at the final block `f` (`choice`'s). Terminal only from a decisive read:
    /// agreed under `strict_majority`, or answered by endpoint 0 when it is not `discovered` under `failover`.
    pub async fn tx_state(
        &self,
        id: B256,
        from: Address,
        nonce: u64,
        choice: BlockChoice,
    ) -> Result<TxState, RpcError> {
        let a = self.tx_facts(id, from, choice).await?;
        let strict = self.pool.policy() == crate::Policy::StrictMajority;
        let decisive =
            strict || (a.members == [0] && self.pool.class(0) != crate::Class::Discovered);
        let endpoint = a.members[0];
        let replaced = |t: &TxFacts| t.receipt.is_none() && t.nonce > nonce && !t.known;
        Ok(match a.value.receipt {
            Some(r) if decisive && r.block_number <= a.number => TxState::Final {
                number: r.block_number,
                hash: r.block_hash,
                success: r.status,
            },
            Some(r) => TxState::Included {
                number: r.block_number,
                hash: r.block_hash,
                success: r.status,
                endpoint,
            },
            None if decisive && replaced(&a.value) && !strict => TxState::Replaced {
                by_nonce: a.value.nonce,
                basis: Basis::OneEndpoint,
            },
            // T13 S7 (owner 2026-11-17): under strict_majority, Replaced only from an agreed read at the finalized block
            None if decisive && replaced(&a.value) => {
                let f = match choice {
                    BlockChoice::Finalized => a.value,
                    _ => self.tx_facts(id, from, BlockChoice::Finalized).await?.value,
                };
                if replaced(&f) {
                    TxState::Replaced {
                        by_nonce: f.nonce,
                        basis: Basis::Majority,
                    }
                } else {
                    TxState::Pending {
                        endpoint: Some(endpoint),
                    }
                }
            }
            None => TxState::Pending {
                endpoint: Some(endpoint),
            },
        })
    }

    /// The facts [`EvmPool::tx_state`] reads at `choice`'s block.
    async fn tx_facts(
        &self,
        id: B256,
        from: Address,
        choice: BlockChoice,
    ) -> Result<Agreed<TxFacts, B256>, RpcError> {
        self.read_at_block(choice, Purpose::Plain, |at| async move {
            let receipt = self.checked_receipt(at.endpoint, id, at.deadline).await?;
            let now = self.nonce_at_block(&at, from).await?;
            let known = self
                .at(at.endpoint, at.deadline)
                .get_transaction_by_hash(id)
                .await
                .map_err(|e| read_error(at.endpoint, &e, self.decode))?
                .is_some();
            Ok(TxFacts {
                receipt,
                nonce: now,
                known,
            })
        })
        .await
    }

    /// CLI-RPC-09 for a relayed operation: at the final block `f`, by one decisive read, its executed event in `[from_block, f]`,
    /// its nonce view, and `f`'s timestamp.
    pub async fn op_state(&self, q: &OpQuery, choice: BlockChoice) -> Result<OpState, RpcError> {
        let a = self.op_facts(q, choice).await?;
        let strict = self.pool.policy() == crate::Policy::StrictMajority;
        let decisive =
            strict || (a.members == [0] && self.pool.class(0) != crate::Class::Discovered);
        let failed =
            |(executed, spent, ts): (bool, bool, u64)| !executed && (spent || q.valid_until < ts);
        Ok(match a.value {
            _ if !decisive => OpState::Pending,
            (true, _, _) => OpState::Landed,
            v if failed(v) && !strict => OpState::FailedForGood {
                basis: Basis::OneEndpoint,
            },
            // T13 S7 (owner 2026-11-17): under strict_majority, FailedForGood only from an agreed read at the finalized block
            v if failed(v) => {
                let f = match choice {
                    BlockChoice::Finalized => v,
                    _ => self.op_facts(q, BlockChoice::Finalized).await?.value,
                };
                if failed(f) {
                    OpState::FailedForGood {
                        basis: Basis::Majority,
                    }
                } else {
                    OpState::Pending
                }
            }
            _ => OpState::Pending,
        })
    }

    /// The facts [`EvmPool::op_state`] reads at `choice`'s block: executed, nonce spent, the block's timestamp.
    async fn op_facts(
        &self,
        q: &OpQuery,
        choice: BlockChoice,
    ) -> Result<Agreed<(bool, bool, u64), B256>, RpcError> {
        self.read_at_block(choice, Purpose::Plain, |at| async move {
            let p = self.at(at.endpoint, at.deadline);
            let executed = !p
                .get_logs(
                    &q.executed
                        .clone()
                        .from_block(q.from_block)
                        .to_block(at.number),
                )
                .await
                .map_err(|e| ReadError::Failure(transport(at.endpoint, &e)))?
                .is_empty();
            let word = self.call_at(&at, q.contract, q.nonce_call.clone()).await?;
            let now =
                alloy::primitives::U256::try_from_be_slice(word.get(..32).unwrap_or_default())
                    .ok_or_else(|| {
                        ReadError::Failure(EndpointFailure::new(
                            at.endpoint,
                            FailureKind::AnswerMalformed,
                            "a nonce view of no word",
                        ))
                    })?;
            let ts = p
                .get_block_by_hash(at.hash)
                .await
                .map_err(|e| ReadError::Failure(transport(at.endpoint, &e)))?
                .ok_or_else(|| {
                    ReadError::Failure(EndpointFailure::new(
                        at.endpoint,
                        FailureKind::Transport,
                        "no final block",
                    ))
                })?
                .header
                .timestamp;
            Ok((executed, now > q.nonce, ts))
        })
        .await
    }
}
