//! Kết nối RPC + ký vỏ tx. Khoá chỉ đi qua `EthereumWallet` dựng từ một signer (ruling R15):
//! bản này là `PrivateKeySigner` từ biến môi trường; thay bằng custody broker không đổi nơi gọi.
use alloy::eips::eip2718::Encodable2718;
use alloy::eips::BlockNumberOrTag;
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::{Filter, TransactionRequest};
use alloy::sol_types::{SolCall, SolEvent};
use alloy::signers::local::PrivateKeySigner;
use alloy::transports::TransportError;
use anyhow::{anyhow, Result};

use crate::abi::{decode_revert, IMtxIds, IToken, IUALedger};
use crate::submit::MetaRef;
use crate::config::ChainCfg;

/// Simulation fail vì hợp đồng revert (vĩnh viễn với state này) hay vì đường truyền (tạm thời).
/// Gộp hai cái làm một là giết job của khách vì một lần RPC chập chờn (review plan P7).
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

/// Fable E N-8: an endpoint URL (an RPC's, a verifier's: an internal host, a key in a path) never reaches a job's error or a
/// gateway reply: each `scheme://…` up to a blank, a quote or a bracket becomes `<url>` (never ending at `,` or `;`: a key after
/// one in a path or query is part of the URL; Fable recheck R-7).
pub fn redact_urls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = ["http://", "https://", "ws://", "wss://"].iter().filter_map(|p| rest.find(p)).min() {
        out.push_str(&rest[..i]);
        out.push_str("<url>");
        let tail = &rest[i..];
        rest = &tail[tail.find(|c: char| c.is_whitespace() || "()<>\"'".contains(c)).unwrap_or(tail.len())..];
    }
    out.push_str(rest);
    out
}

pub fn classify(e: &TransportError) -> SimError {
    match e.as_error_resp() {
        Some(resp) => match resp.as_revert_data() {
            Some(data) => SimError::Revert(decode_revert(&data)),
            // Node trả lỗi JSON-RPC có nghĩa (execution reverted không data, out of gas…):
            // đó là câu trả lời của EVM, không phải mạng.
            // Fable recheck 2 P3-8, recheck 3 R3-6: a revert first; then a node's own limit, matched by its exact phrase, is the
            // endpoint's answer, not the EVM's
            None if resp.message.contains("revert") => SimError::Revert(resp.message.to_string()),
            None if resp.message.contains("execution") && !node_limit(&resp.message) => SimError::Revert(resp.message.to_string()),
            None => SimError::Transport(resp.message.to_string()),
        },
        None => SimError::Transport(e.to_string()),
    }
}

/// A node's own limit on one call, not the EVM's answer: geth's `execution aborted (timeout = 5s)` (`--rpc.evmtimeout`).
fn node_limit(m: &str) -> bool {
    m.starts_with("execution aborted (timeout = ") && m.ends_with(')')
}

/// [`classify`] for a simulation without a gas field: "out of gas" / "gas required exceeds allowance" there is the
/// call needing more than 2^24 regular gas (EIP-7825 under EIP-8037: execution gets at most 2^24 at any gas limit) or
/// more than the RPC's gas cap — no gas limit makes it fit, so it is the job's answer, not the network's. Nethermind
/// 2.2.0 answers exactly these two messages for an endless loop (`pqz-core/nethermind/runs/2026-10-22-genesis-200m-throwaway.txt`).
pub fn classify_sim(e: &TransportError) -> SimError {
    match classify(e) {
        SimError::Transport(m) if m.contains("out of gas") || m.contains("gas required exceeds allowance") => {
            SimError::Revert(format!("over the 2^24 regular gas of a transaction or the RPC gas cap: {m}"))
        }
        x => x,
    }
}

/// The smallest `eth_getLogs` span [`Chain::logs_back`] asks before it gives an endpoint up (R-6), and at most this many spans per
/// window (Fable recheck 2 P3-3): a window is read in at most about 25 requests, a smaller cap gives the endpoint up.
const LOG_SPAN_MIN: u64 = 10;
const LOG_WINDOW_SPANS: u64 = 20;

/// The `latest` header's gas facts ([`Chain::block_gas`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockGas {
    pub limit: u64,
    /// EIP-7928's `blockAccessListHash` is in the header: the Amsterdam two-dimensional gas model applies.
    pub amsterdam: bool,
}

pub struct Chain {
    pub number: u64,
    providers: Vec<DynProvider>,
    wallet: EthereumWallet,
    address: Address,
    /// `chain_uid` from the config, checked against the RPC's block 0 (NODE-GW-07).
    pinned_uid: Option<B256>,
    uid: tokio::sync::OnceCell<B256>,
    /// `compliance_registry` and its pinned code hash (regulated-kinds spec §5, F-11).
    compliance: Option<(Address, B256)>,
    /// Fable recheck 2 P2-1, recheck 3 R3-1, R3-2: the highest block this chain has seen from its first endpoint, one value
    /// shared by every `Chain` of the same `[[chains]]` table (`ChainCfg::head`), raised by [`Chain::saw_block`] only; a
    /// failover endpoint below it answers no read.
    head: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Fable recheck 2 P3-5, recheck 3 R3-3: per endpoint, its `eth_chainId` is `number` and its block 0 is this chain's (checked
    /// once, at a failover endpoint's first use); `false`: another network, dropped from every read.
    chain_ok: Vec<std::sync::OnceLock<bool>>,
    /// Fable recheck 3 R3-4: one read's time on one endpoint, and a simulation's (`rpc_timeout_ms`, `rpc_simulate_timeout_ms`).
    read_timeout: std::time::Duration,
    simulate_timeout: std::time::Duration,
}

impl Chain {
    /// Một `Chain` mỗi lane (R62): cùng RPC, khoá khác nhau.
    pub fn connect_lanes(cfg: &ChainCfg, signers: &[crate::signer::LocalSigner]) -> Result<Vec<Self>> {
        signers.iter().map(|s| Self::with_signer(cfg, s.evm()?)).collect()
    }

    pub fn with_signer(cfg: &ChainCfg, signer: PrivateKeySigner) -> Result<Self> {
        let address = signer.address();
        let (read_timeout, simulate_timeout) =
            (std::time::Duration::from_millis(cfg.rpc_timeout_ms), std::time::Duration::from_millis(cfg.rpc_simulate_timeout_ms));
        let providers = cfg
            .rpc_urls
            .iter()
            // Fable recheck 2 P3-4: a request timeout, so an endpoint that accepts and never answers fails a read over; each read
            // is bounded by its own limit ([`Chain::read_within`]), this one bounds every other request (sends, receipts, scans)
            .map(|u| Ok(ProviderBuilder::new().disable_recommended_fillers()
                .connect_reqwest(reqwest::Client::builder().timeout(read_timeout.max(simulate_timeout)).build()?, u.parse()?).erased()))
            .collect::<Result<Vec<_>>>()?;
        if providers.is_empty() {
            return Err(anyhow!("chain {}: no rpc_urls", cfg.evm_chain_number));
        }
        Ok(Self {
            number: cfg.evm_chain_number,
            providers,
            wallet: EthereumWallet::from(signer),
            address,
            pinned_uid: cfg.chain_uid,
            uid: Default::default(),
            compliance: cfg.compliance_registry.zip(cfg.compliance_registry_codehash),
            head: cfg.head.clone(),
            chain_ok: cfg.rpc_urls.iter().map(|_| Default::default()).collect(),
            read_timeout,
            simulate_timeout,
        })
    }

    pub fn primary(&self) -> &DynProvider {
        &self.providers[0]
    }

    pub fn others(&self) -> &[DynProvider] {
        &self.providers[1..]
    }

    pub fn address(&self) -> Address {
        self.address
    }

    /// ARCH-POS-15, failover (the default; the strict-majority option is deferred to `scaas-rpc`): one read, answered completely
    /// by one endpoint, `rpc_urls` in the order given, never mixing answers of two endpoints. A transport error (the endpoint
    /// down, an error answer that is no revert) moves the whole read to the next endpoint; a revert is the contract's answer and
    /// is final only from the first endpoint: a failover endpoint's revert is a transport error (Fable recheck 3 R3-1), so no
    /// revert of an endpoint other than the first makes a job `dead` or an order `invalid` (the venue's evidence read out of an
    /// answer takes the first endpoint's only, [`Chain::read_at`]). A failover endpoint answers at all only when it is this chain
    /// (its id and block 0, R3-3) and its head is at or above the highest block this chain has seen from its first endpoint
    /// ([`Chain::saw_block`]; Fable recheck 2 P2-1; its own head never raises it, R3-2). Each endpoint gets `rpc_timeout_ms`
    /// (R3-4). The lane's own sends, nonces, fees and receipts stay on the first endpoint, and the indexers keep their quorum
    /// over all of them.
    pub async fn read<T, F, Fut>(&self, f: F) -> std::result::Result<T, SimError>
    where
        F: Fn(DynProvider) -> Fut,
        Fut: std::future::Future<Output = std::result::Result<T, SimError>>,
    {
        self.read_at(f).await.map(|(t, _)| t)
    }

    /// [`Chain::read`], with the index of the endpoint that answered: a caller that reads a refusal out of an `Ok` (the venue's
    /// evidence, an ERC-1271 `false`) takes it from the first endpoint only.
    pub async fn read_at<T, F, Fut>(&self, f: F) -> std::result::Result<(T, usize), SimError>
    where
        F: Fn(DynProvider) -> Fut,
        Fut: std::future::Future<Output = std::result::Result<T, SimError>>,
    {
        self.read_within(self.read_timeout, f).await
    }

    /// [`Chain::read_at`] with `limit` per endpoint (R3-4: a simulation's is larger).
    async fn read_within<T, F, Fut>(&self, limit: std::time::Duration, f: F) -> std::result::Result<(T, usize), SimError>
    where
        F: Fn(DynProvider) -> Fut,
        Fut: std::future::Future<Output = std::result::Result<T, SimError>>,
    {
        use std::sync::atomic::Ordering::Relaxed;
        let mut last = String::new();
        for (i, p) in self.providers.iter().enumerate() {
            let fresh = async {
                if i == 0 {
                    return Ok(());
                }
                match self.same_chain(i, p).await {
                    Ok(true) => {}
                    Ok(false) => return Err(SimError::Transport(format!("endpoint {i} is not chain {}", self.number))),
                    Err(e) => return Err(SimError::Transport(e)),
                }
                match p.get_block_number().await {
                    Ok(n) if n >= self.head.load(Relaxed) => Ok(()),
                    Ok(n) => Err(SimError::Transport(format!("endpoint {i} at block {n}, behind {}", self.head.load(Relaxed)))),
                    Err(e) => Err(classify(&e)),
                }
            };
            let answer = tokio::time::timeout(limit, async {
                fresh.await.map_err(|e| (false, e))?;
                f(p.clone()).await.map_err(|e| (true, e))
            }).await.unwrap_or_else(|_| Err((true, SimError::Transport(format!("endpoint {i}: no answer within {} ms", limit.as_millis())))));
            match answer {
                Err((false, e)) => {
                    let e = e.to_string();
                    tracing::warn!(chain = self.number, endpoint = i, error = %redact_urls(&e), "chain read: endpoint not used; next");
                    last = e;
                }
                Err((_, SimError::Transport(e))) => {
                    tracing::warn!(chain = self.number, endpoint = i, error = %redact_urls(&e), "chain read failed; next endpoint");
                    last = e;
                }
                Err((_, SimError::Revert(e))) if i > 0 => {
                    tracing::warn!(chain = self.number, endpoint = i, "chain read: a failover endpoint's revert is no verdict; next");
                    last = format!("endpoint {i} reverted (a failover endpoint decides nothing): {e}");
                }
                Err((_, e)) => return Err(e),
                Ok(t) => return Ok((t, i)),
            }
        }
        Err(SimError::Transport(last))
    }

    /// Endpoint `i` is this chain: its `eth_chainId` is `number` and its block 0 hash is the chain's (the pinned `chain_uid`, else
    /// the one [`Chain::uid`] read, else the first endpoint's block 0): read once and kept; another network is dropped with one
    /// log line (Fable recheck 2 P3-5, recheck 3 R3-3: a reset or forked network keeps its id). `Err`: unreadable, not kept,
    /// asked again next time.
    async fn same_chain(&self, i: usize, p: &DynProvider) -> std::result::Result<bool, String> {
        if let Some(ok) = self.chain_ok[i].get() {
            return Ok(*ok);
        }
        let unread = |what: &str| format!("endpoint {i}: {what} unreadable; not used");
        let id = p.get_chain_id().await.map_err(|_| unread("chain id"))?;
        let ok = id == self.number && {
            let want = match self.pinned_uid.or(self.uid.get().copied()) {
                Some(u) => u,
                None => Self::block_hash(self.primary(), 0).await.ok_or_else(|| unread("the first endpoint's block 0"))?,
            };
            Self::block_hash(p, 0).await.ok_or_else(|| unread("block 0"))? == want
        };
        if !ok {
            tracing::warn!(chain = self.number, endpoint = i, got = id, "rpc_urls endpoint is another network (chain id or block 0); dropped");
        }
        Ok(*self.chain_ok[i].get_or_init(|| ok))
    }

    /// A block of this chain from its first endpoint (a lane's receipt, a polled head): failover endpoints below it answer no
    /// read. Never fed by a failover endpoint's own answer (R3-2): nothing lowers it, so one wrong number would refuse every
    /// honest failover until a restart.
    pub fn saw_block(&self, n: u64) {
        self.head.fetch_max(n, std::sync::atomic::Ordering::Relaxed);
    }

    /// The highest block seen ([`Chain::saw_block`]).
    pub fn seen_head(&self) -> u64 {
        self.head.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// [`Chain::read`] of one `eth_call` from `from` (with `gas` when given), classified by [`classify`].
    pub async fn call_tx(&self, tx: TransactionRequest) -> std::result::Result<Bytes, SimError> {
        self.read(|p| {
            let tx = tx.clone();
            async move { p.call(tx).await.map_err(|e| classify(&e)) }
        })
        .await
    }

    /// `eth_call` + `eth_estimateGas` từ địa chỉ relayer.
    pub async fn simulate(&self, to: Address, data: Bytes) -> std::result::Result<u64, SimError> {
        self.simulate_from(self.address, to, data).await
    }

    /// Mô phỏng với `from` tuỳ ý (gateway mô phỏng chân DEX bằng địa chỉ DEX). The estimate is the gas limit the
    /// transaction needs, regular + state (EIP-8037); no gas field, so both calls run at the RPC's gas cap.
    pub async fn simulate_from(&self, from: Address, to: Address, data: Bytes) -> std::result::Result<u64, SimError> {
        let tx = TransactionRequest::default().with_from(from).with_to(to).with_input(data);
        self.read_within(self.simulate_timeout, |p| {
            let tx = tx.clone();
            async move {
                p.call(tx.clone()).await.map_err(|e| classify_sim(&e))?;
                p.estimate_gas(tx).await.map_err(|e| classify_sim(&e))
            }
        })
        .await
        .map(|(g, _)| g)
    }

    /// The `latest` header's gas facts: its `gasLimit` (EIP-8037 includes a transaction only when its gas limit fits
    /// it) and whether the chain runs Amsterdam — the header carries EIP-7928's `blockAccessListHash` (as
    /// `pqz-core/nethermind/chain/e2e.py` decides it). Read from the raw header, so any RPC's block shape works.
    pub async fn block_gas(&self) -> Result<BlockGas> {
        let b: serde_json::Value = self.read(|p| async move {
            p.raw_request("eth_getBlockByNumber".into(), ("latest", false)).await.map_err(|e| SimError::Transport(e.to_string()))
        }).await.map_err(|e| anyhow!("{e}"))?;
        let g = b["gasLimit"].as_str().ok_or_else(|| anyhow!("chain {}: latest block without gasLimit", self.number))?;
        Ok(BlockGas { limit: u64::from_str_radix(g.trim_start_matches("0x"), 16)?, amsterdam: b.get("blockAccessListHash").is_some() })
    }

    /// The gas limit and max fee per gas of the transaction `hash` as it was sent (`eth_getTransactionByHash`); `None`
    /// if the RPC does not know it (the fee: if it gives none, e.g. a legacy transaction).
    pub async fn tx_fees(&self, hash: B256) -> Result<Option<(u64, Option<u128>)>> {
        let t: serde_json::Value = self.primary().raw_request("eth_getTransactionByHash".into(), (hash,)).await?;
        let hex = |k: &str| t[k].as_str().map(|g| u128::from_str_radix(g.trim_start_matches("0x"), 16));
        let Some(gas) = hex("gas") else { return Ok(None) };
        Ok(Some((u64::try_from(gas?)?, hex("maxFeePerGas").transpose()?)))
    }

    /// This chain's `chain_uid`: the RPC's block 0 hash, which must equal the configured `chain_uid` when one is set
    /// (a pruned RPC without block 0 trusts the configured one). Read once; an error is not remembered.
    pub async fn uid(&self) -> Result<B256> {
        self.uid
            .get_or_try_init(|| async {
                // an RPC error is not "no block 0": nothing is cached, the next call asks again (review T4 m3)
                let genesis = self.read(|p| async move { p.get_block_by_number(BlockNumberOrTag::Number(0)).await.map_err(|e| classify(&e)) })
                    .await.map_err(|e| anyhow!("chain {}: block 0: {e}", self.number))?.map(|b| b.header.hash);
                match (self.pinned_uid, genesis) {
                    (Some(p), Some(g)) if p != g => Err(anyhow!("chain {}: RPC block 0 {g:#x} is not chain_uid {p:#x}", self.number)),
                    (Some(p), _) | (None, Some(p)) => Ok(p),
                    (None, None) => Err(anyhow!("chain {}: the RPC gives no block 0 hash; set chain_uid", self.number)),
                }
            })
            .await
            .copied()
    }

    /// The configured `compliance_registry` once its runtime code hashes to the pinned `compliance_registry_codehash`
    /// (regulated-kinds spec §5: one canonical code, no proxy); `Ok(None)` when none is configured. Another code, no code, or
    /// an unreadable one is an error: the caller does not start (fail closed).
    pub async fn compliance_registry(&self) -> Result<Option<Address>> {
        let Some((a, pin)) = self.compliance else { return Ok(None) };
        let code = self.code_at(a).await.map_err(|e| anyhow!("chain {}: compliance_registry code: {e}", self.number))?;
        let got = alloy::primitives::keccak256(&code);
        if code.is_empty() || got != pin {
            return Err(anyhow!("chain {}: compliance_registry {a:#x} code hash {got:#x} is not compliance_registry_codehash {pin:#x}",
                self.number));
        }
        Ok(Some(a))
    }

    /// A view call; a revert is the contract's answer (`SimError::Revert`), anything else the transport's.
    pub async fn call_view<C: SolCall>(&self, to: Address, call: C) -> std::result::Result<C::Return, SimError> {
        let out = self.call_tx(TransactionRequest::default().with_to(to).with_input(call.abi_encode())).await?;
        C::abi_decode_returns(&out).map_err(|e| SimError::Revert(format!("decode: {e}")))
    }

    /// `eth_call` of calldata built by ABI type (group 3f: a PQZ token's statement views, `crate::pqz`).
    pub async fn call_raw(&self, to: Address, data: Bytes) -> std::result::Result<Bytes, SimError> {
        self.call_tx(TransactionRequest::default().with_to(to).with_input(data)).await
    }

    /// `eth_call` from the lane with exactly `gas` (sizing `mtxSettle`, `guard::settle_gas`).
    pub async fn call_with_gas(&self, to: Address, data: Bytes, gas: u64) -> std::result::Result<Bytes, SimError> {
        self.call_tx(TransactionRequest::default().with_from(self.address).with_to(to).with_input(data).with_gas_limit(gas)).await
    }

    /// `who` is a contract signer (ERC-1271, `guard::erc1271_floor`): `is_contract` of its code, so an EIP-7702
    /// designator (an EOA, ECDSA only) is not.
    pub async fn is_contract_at(&self, who: Address) -> Result<bool> {
        Ok(is_contract(&self.code_at(who).await.map_err(|e| anyhow!("{e}"))?))
    }

    /// `who`'s runtime code, through [`Chain::read`].
    pub async fn code_at(&self, who: Address) -> std::result::Result<Bytes, SimError> {
        self.read(|p| async move { p.get_code_at(who).await.map_err(|e| classify(&e)) }).await
    }

    pub async fn fees(&self) -> Result<(u128, u128)> {
        let est = self.primary().estimate_eip1559_fees().await?;
        Ok((est.max_fee_per_gas.max(1), est.max_priority_fee_per_gas))
    }

    pub async fn pending_nonce(&self) -> Result<u64> {
        Ok(self.primary().get_transaction_count(self.address).pending().await?)
    }

    /// Số tx của lane ĐÃ vào khối (`latest`), khác `pending_nonce`: nonce vỏ `n` đã bị dùng ⇔ `nonce_at() > n` (R80).
    pub async fn nonce_at(&self) -> Result<u64> {
        Ok(self.primary().get_transaction_count(self.address).latest().await?)
    }

    async fn view<C: SolCall>(&self, to: Address, call: C) -> Result<C::Return> {
        self.call_view(to, call).await.map_err(|e| anyhow!("{e}"))
    }

    /// The subject's next nonce on its lane (R80), by the contract's kind (ua-mtx-merge plan T14): `mtxNonce(bytes32 id, batch)`
    /// on a token, the router and a mandate wallet (one nonce map on ids, CTR-UA-26: an address envelope's `from` padded),
    /// `mtxNonce(address, batch)` on `SmartKeyAccount`.
    pub async fn subject_nonce(&self, m: &MetaRef) -> Result<U256> {
        if m.addr_nonce {
            return self.view(m.token, IToken::mtxNonceCall { from: Address::from_word(m.from), batch: m.batch }).await;
        }
        self.view(m.token, IMtxIds::mtxNonceCall { from: m.from, batch: m.batch }).await
    }

    /// `MetaTransactionExecuted` (a UA subject: `UAMetaTransactionExecuted`) of `(from, batch, nonce)` trong `lookback`
    /// khối gần nhất ⇒ `(digest, relayer)` (§8.5). Both events index `from`, `relayer`, `batch` alike.
    pub async fn meta_executed(&self, m: &MetaRef, lookback: u64) -> Result<Option<(B256, Address)>> {
        let filter = Filter::new().address(m.token).event_signature(executed_events(m)).topic1(m.from).topic3(B256::from(m.batch));
        for log in self.logs_back(filter, lookback).await? {
            let e = match log.topic0() == Some(&IUALedger::UAMetaTransactionExecuted::SIGNATURE_HASH) {
                true => log.log_decode::<IUALedger::UAMetaTransactionExecuted>().ok().map(|l| (l.inner.data.nonce, l.inner.data.digest, l.inner.data.relayer)),
                false => log.log_decode::<IToken::MetaTransactionExecuted>().ok().map(|l| (l.inner.data.nonce, l.inner.data.digest, l.inner.data.relayer)),
            };
            if let Some((_, digest, relayer)) = e.filter(|e| e.0 == m.nonce) {
                return Ok(Some((digest, relayer)));
            }
        }
        Ok(None)
    }

    /// The byte length of `a`'s code (a PQZ key's SSTORE2 pointer: its key length plus the STOP byte).
    pub async fn code_len(&self, a: Address) -> std::result::Result<usize, SimError> {
        self.code_at(a).await.map(|c| c.len())
    }

    /// Group 3g (spec §7.3): a `UAPqzKeyCurrent` of one of `uas` on `registry` in the last `lookback` blocks.
    pub async fn pqz_key_current_since(&self, registry: Address, uas: &[B256], lookback: u64) -> Result<bool> {
        let filter = Filter::new()
            .address(registry)
            .event_signature(crate::abi::IUARegistry::UAPqzKeyCurrent::SIGNATURE_HASH)
            .topic1(uas.to_vec());
        Ok(!self.logs_back(filter, lookback).await?.is_empty())
    }

    /// Round 3t (CTR-PQZ-36, spec §10): the logs `topic0` of `address` in the last `lookback` blocks (a token's `VerifierFeeSet`).
    pub async fn logs_since(&self, address: Address, topic0: B256, lookback: u64) -> Result<Vec<alloy::rpc::types::Log>> {
        self.logs_back(Filter::new().address(address).event_signature(topic0), lookback).await
    }

    /// The logs of `filter` in the last `lookback` blocks, the head and the logs from one endpoint ([`Chain::read`]). Fable recheck
    /// R-6: an RPC that caps the `eth_getLogs` range refuses the whole window, so a span it refuses (an error answer) is asked
    /// again in tenths, down to a floor: [`LOG_SPAN_MIN`] blocks or a [`LOG_WINDOW_SPANS`]th of the window, whichever is larger;
    /// an endpoint that refuses the floor fails the read over. Fable recheck 2 P3-3: a transport error never shrinks a span, it
    /// fails the read over at once; after an answer the span grows back (doubles), staying below half of a span refused.
    async fn logs_back(&self, filter: Filter, lookback: u64) -> Result<Vec<alloy::rpc::types::Log>> {
        let (out, at) = self.read_at(|p| {
            let filter = filter.clone();
            async move {
                let latest = p.get_block_number().await.map_err(|e| classify(&e))?;
                let start = latest.saturating_sub(lookback);
                let whole = latest - start + 1;
                let floor = LOG_SPAN_MIN.max(whole.div_ceil(LOG_WINDOW_SPANS));
                let (mut from, mut span, mut refused, mut out) = (start, whole, u64::MAX, vec![]);
                while from <= latest {
                    let to = latest.min(from.saturating_add(span - 1));
                    match p.get_logs(&filter.clone().from_block(from).to_block(to)).await {
                        Ok(l) => {
                            out.extend(l);
                            from = to + 1;
                            span = span.saturating_mul(2).min(refused / 2).max(span);
                        }
                        Err(e) if e.as_error_resp().is_some() && span > floor => {
                            tracing::debug!(span, error = %redact_urls(&e.to_string()), "eth_getLogs span refused; a tenth of it");
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
        .await
        .map_err(|e| anyhow!("{e}"))?;
        if at == 0 {
            self.saw_block(out.0); // R3-2: the first endpoint's head only
        }
        Ok(out.1)
    }

    /// Ký EIP-1559; trả bytes thô và hash — hash biết TRƯỚC khi gửi (journal, review F5).
    pub async fn sign(&self, nonce: u64, to: Address, data: Bytes, gas: u64, fees: (u128, u128)) -> Result<(Bytes, B256)> {
        let tx = TransactionRequest::default()
            .with_from(self.address)
            .with_to(to)
            .with_input(data)
            .with_nonce(nonce)
            .with_chain_id(self.number)
            .with_gas_limit(gas)
            .with_max_fee_per_gas(fees.0)
            .with_max_priority_fee_per_gas(fees.1.min(fees.0));
        let env = tx.build(&self.wallet).await.map_err(|e| anyhow!("sign: {e}"))?;
        let hash = *env.tx_hash();
        Ok((Bytes::from(env.encoded_2718()), hash))
    }

    pub async fn send_raw(&self, raw: &Bytes) -> Result<()> {
        let _pending = self.primary().send_raw_transaction(raw).await?;
        Ok(())
    }

    pub async fn finalized_number(&self) -> Result<Option<u64>> {
        Ok(self
            .primary()
            .get_block_by_number(BlockNumberOrTag::Finalized)
            .await
            .ok()
            .flatten()
            .map(|b| b.header.number))
    }

    pub async fn block_hash(p: &DynProvider, n: u64) -> Option<B256> {
        p.get_block_by_number(BlockNumberOrTag::Number(n)).await.ok().flatten().map(|b| b.header.hash)
    }
}

/// The executions that spend `m`'s nonce: a native id's lane is spent by a merged entry (`UAMetaTransactionExecuted`, R18) or
/// an address one (a wrap, `executeMetaTransaction`: `MetaTransactionExecuted`) alike, one nonce map; a derived UA's by the
/// UA event only.
pub fn executed_events(m: &MetaRef) -> Vec<B256> {
    let (ua, mtx) = (IUALedger::UAMetaTransactionExecuted::SIGNATURE_HASH, IToken::MetaTransactionExecuted::SIGNATURE_HASH);
    match crate::metatx::native(&m.from) {
        Some(_) => vec![ua, mtx],
        None => vec![ua],
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// An RPC whose block 0 is the recorded Hedera testnet block (any block will do: only its hash is read).
    async fn rpc() -> (String, B256) {
        let block: Value = serde_json::from_str::<Value>(include_str!("../tests/vectors/hedera_testnet.json")).unwrap()["block"].clone();
        let hash = block["hash"].as_str().unwrap().parse().unwrap();
        let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
            let block = block.clone();
            async move { axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": block})) }
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, hash)
    }

    fn chain(url: &str, pin: Option<B256>) -> Chain {
        let cfg = ChainCfg { evm_chain_number: 296, rpc_urls: vec![url.into()], chain_uid: pin, ..Default::default() };
        Chain::with_signer(&cfg, PrivateKeySigner::random()).unwrap()
    }

    /// A fake RPC answering each request with `f(request)` (a `result` or an `error` member), counting the requests.
    pub(crate) async fn fake_rpc(f: fn(&Value) -> Value) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        fake_rpc_on(f, 296, genesis()).await
    }

    /// The block 0 hash of the fake chain 296 ([`chain_of`] pins it).
    fn genesis() -> B256 {
        B256::repeat_byte(0x60)
    }

    /// [`fake_rpc`] answering `eth_chainId` with `id` (P3-5) and block 0 with hash `zero` (R3-3); neither is counted.
    async fn fake_rpc_on(f: fn(&Value) -> Value, id: u64, zero: B256) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let n: std::sync::Arc<std::sync::atomic::AtomicUsize> = Default::default();
        let n2 = n.clone();
        let mut block: Value = serde_json::from_str::<Value>(include_str!("../tests/vectors/hedera_testnet.json")).unwrap()["block"].clone();
        block["hash"] = json!(format!("{zero:#x}"));
        let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
            let mut a = if r["method"] == "eth_chainId" {
                json!({"result": format!("{id:#x}")})
            } else if r["method"] == "eth_getBlockByNumber" && r["params"][0] == "0x0" {
                json!({"result": block.clone()})
            } else {
                n2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                f(&r)
            };
            async move {
                a["jsonrpc"] = json!("2.0");
                a["id"] = r["id"].clone();
                axum::Json(a)
            }
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, n)
    }

    fn chain_of(urls: &[&str]) -> Chain {
        Chain::with_signer(&cfg_of(urls), PrivateKeySigner::random()).unwrap()
    }

    fn cfg_of(urls: &[&str]) -> ChainCfg {
        ChainCfg { evm_chain_number: 296, rpc_urls: urls.iter().map(|u| u.to_string()).collect(), chain_uid: Some(genesis()),
            ..Default::default() }
    }

    /// ARCH-POS-15 (failover): a chain read moves to the next `rpc_urls` endpoint on a transport error (the endpoint down, an
    /// error answer that is no revert) and never on a revert, the contract's answer; one endpoint answers a whole read (the
    /// head and the logs of a window alike). Positive control: the good endpoint alone answers.
    #[tokio::test]
    async fn chain_reads_fail_over_on_transport_errors_never_on_a_revert() {
        use std::sync::atomic::Ordering::SeqCst;
        let (good, good_n) = fake_rpc(|r| match r["method"].as_str() {
            Some("eth_blockNumber") => json!({"result": "0x64"}),
            Some("eth_getLogs") => json!({"result": []}),
            _ => json!({"result": format!("0x{:064x}", 5)}),
        }).await;
        let (busy, busy_n) = fake_rpc(|_| json!({"error": {"code": -32000, "message": "header not found"}})).await;
        let (rev, rev_n) = fake_rpc(|_| json!({"error": {"code": 3, "message": "execution reverted", "data": "0xdeadbeef"}})).await;
        let five = Bytes::from(U256::from(5).to_be_bytes::<32>().to_vec());
        let call = |c: Chain| async move { c.call_raw(Address::ZERO, Bytes::new()).await };
        assert_eq!(call(chain_of(&[&good])).await.unwrap(), five, "control");
        assert_eq!(call(chain_of(&["http://127.0.0.1:9", &good])).await.unwrap(), five, "the first endpoint down");
        assert_eq!(call(chain_of(&[&busy, &good])).await.unwrap(), five, "an error answer that is no revert");
        assert_eq!(busy_n.load(SeqCst), 1);
        let before = good_n.load(SeqCst);
        assert!(matches!(call(chain_of(&[&rev, &good])).await, Err(SimError::Revert(_))), "a revert is final");
        assert_eq!((rev_n.load(SeqCst), good_n.load(SeqCst)), (1, before), "the next endpoint is never asked after a revert");
        assert!(matches!(call(chain_of(&["http://127.0.0.1:9", &busy])).await, Err(SimError::Transport(_))), "all down");
        // Fable recheck 2 P2-1: a failover endpoint behind the highest block seen answers nothing; recheck 3 R3-1: a failover
        // endpoint's revert decides nothing even at the head or with no head seen yet (a fresh `Chain`); its value is used
        let (stale, stale_n) = fake_rpc(|r| match r["method"].as_str() {
            Some("eth_blockNumber") => json!({"result": "0x10"}),
            _ => json!({"error": {"code": 3, "message": "execution reverted", "data": "0xdeadbeef"}}),
        }).await;
        let (level, _) = fake_rpc(|r| match r["method"].as_str() {
            Some("eth_blockNumber") => json!({"result": "0x10"}),
            _ => json!({"result": format!("0x{:064x}", 5)}),
        }).await;
        let fresh = chain_of(&["http://127.0.0.1:9", &stale]);
        assert_eq!(fresh.head.load(SeqCst), 0);
        assert!(matches!(call(fresh).await, Err(SimError::Transport(e)) if e.contains("decides nothing")), "head 0: requeue");
        let at_head = chain_of(&["http://127.0.0.1:9", &stale]);
        at_head.saw_block(0x10);
        assert!(matches!(call(at_head).await, Err(SimError::Transport(e)) if e.contains("decides nothing")), "at the head too");
        assert!(matches!(call(chain_of(&[&stale])).await, Err(SimError::Revert(_))), "control: the first endpoint's revert is final");
        // the head is shared by every `Chain` of one table: a lane's receipt refuses a stale endpoint to the venue's object
        let cfg = cfg_of(&["http://127.0.0.1:9", &level]);
        let (lane, venue) = (Chain::with_signer(&cfg, PrivateKeySigner::random()).unwrap(), Chain::with_signer(&cfg, PrivateKeySigner::random()).unwrap());
        assert_eq!(venue.call_raw(Address::ZERO, Bytes::new()).await.unwrap(), five, "control: at the head, its answer is used");
        assert_eq!(venue.head.load(SeqCst), 0, "R3-2: a failover endpoint's own head raises nothing");
        lane.saw_block(0x11);
        let before = stale_n.load(SeqCst);
        assert!(matches!(venue.call_raw(Address::ZERO, Bytes::new()).await, Err(SimError::Transport(e)) if e.contains("behind 17")));
        let behind = chain_of(&["http://127.0.0.1:9", &stale]);
        behind.saw_block(0x11);
        assert!(matches!(call(behind).await, Err(SimError::Transport(e)) if e.contains("behind")), "stale: requeue, never final");
        assert_eq!(stale_n.load(SeqCst) - before, 1, "only its head was read");
        let (headless, _) = fake_rpc(|r| match r["method"].as_str() {
            Some("eth_blockNumber") => json!({"error": {"code": -32000, "message": "header not found"}}),
            _ => json!({"error": {"code": 3, "message": "execution reverted", "data": "0xdeadbeef"}}),
        }).await;
        assert!(matches!(call(chain_of(&["http://127.0.0.1:9", &headless])).await, Err(SimError::Transport(_))),
            "a failover endpoint whose head is unread answers nothing");
        // Fable recheck 2 P3-5, recheck 3 R3-3: a failover endpoint on another chain id, or on the same id with another block 0
        // (a reset or forked network), answers nothing, checked once; the control is `level` above
        let answer = |r: &Value| match r["method"].as_str() {
            Some("eth_blockNumber") => json!({"result": "0x64"}),
            _ => json!({"result": format!("0x{:064x}", 5)}),
        };
        for (id, zero) in [(1, genesis()), (296, B256::repeat_byte(0x61))] {
            let (other, other_n) = fake_rpc_on(answer, id, zero).await;
            let c = chain_of(&["http://127.0.0.1:9", &other]);
            for _ in 0..2 {
                assert!(matches!(c.call_raw(Address::ZERO, Bytes::new()).await, Err(SimError::Transport(e)) if e.contains("not chain 296")));
            }
            assert_eq!(other_n.load(SeqCst), 0, "nothing but its chain id and block 0 was asked");
            assert_eq!(c.chain_ok[1].get(), Some(&false), "dropped, once");
        }
        // with no pinned chain_uid, block 0 is the first endpoint's; unread there: the failover endpoint is not used
        let (same, _) = fake_rpc(answer).await;
        let c = Chain::with_signer(&ChainCfg { chain_uid: None, ..cfg_of(&["http://127.0.0.1:9", &same]) }, PrivateKeySigner::random()).unwrap();
        assert!(matches!(c.call_raw(Address::ZERO, Bytes::new()).await, Err(SimError::Transport(e)) if e.contains("unreadable")));
        assert_eq!(c.chain_ok[1].get(), None, "not kept");
        let (first, _) = fake_rpc(|_| json!({"error": {"code": -32000, "message": "busy"}})).await;
        let c = Chain::with_signer(&ChainCfg { chain_uid: None, ..cfg_of(&[&first, &same]) }, PrivateKeySigner::random()).unwrap();
        assert_eq!(c.call_raw(Address::ZERO, Bytes::new()).await.unwrap(), five, "the first endpoint's block 0 matches");
        // an unread chain id is no answer: the endpoint is not used, and it is asked again next time
        let app = axum::Router::new().route("/", axum::routing::post(|axum::Json(r): axum::Json<Value>| async move {
            axum::Json(match r["method"].as_str() {
                Some("eth_chainId") => json!({"jsonrpc": "2.0", "id": r["id"], "error": {"code": -32000, "message": "busy"}}),
                Some("eth_blockNumber") => json!({"jsonrpc": "2.0", "id": r["id"], "result": "0x64"}),
                _ => json!({"jsonrpc": "2.0", "id": r["id"], "result": format!("0x{:064x}", 5)}),
            })
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mute = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let c = chain_of(&["http://127.0.0.1:9", &mute]);
        assert!(matches!(c.call_raw(Address::ZERO, Bytes::new()).await, Err(SimError::Transport(e)) if e.contains("chain id unreadable")),
            "unread chain id: not used");
        assert_eq!(c.chain_ok[1].get(), None, "not kept");
        // a window of logs: the busy endpoint refuses the head, the good one answers the head and the logs
        let c = chain_of(&[&busy, &good]);
        let before = good_n.load(SeqCst);
        assert!(c.logs_since(Address::ZERO, B256::ZERO, 10).await.unwrap().is_empty());
        assert_eq!(good_n.load(SeqCst) - before, 3, "its head check, eth_blockNumber and eth_getLogs, all on the good endpoint");
        assert_eq!(c.head.load(SeqCst), 0, "R3-2: a failover endpoint's head in a log read raises nothing");
        let c = chain_of(&[&good]);
        c.logs_since(Address::ZERO, B256::ZERO, 10).await.unwrap();
        assert_eq!(c.head.load(SeqCst), 0x64, "control: the first endpoint's head does");
        assert_eq!(c.subject_nonce(&MetaRef { token: Address::ZERO, from: B256::ZERO, batch: U256::ZERO, nonce: U256::ZERO,
            digest: None, ua: true, addr_nonce: false }).await.unwrap(), U256::from(5), "the subject nonce view fails over too");
    }

    /// An RPC at head 12,288 whose `eth_getLogs` caps the range at `cap(request)` blocks and answers one log per accepted request,
    /// its `blockNumber` the request's `fromBlock` and its `logIndex` the span's length.
    fn capped_logs(r: &Value, cap: u64) -> Value {
        let n = |v: &Value| u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        match r["method"].as_str() {
            Some("eth_blockNumber") => json!({"result": "0x3000"}),
            Some("eth_getLogs") => {
                let (from, to) = (n(&r["params"][0]["fromBlock"]), n(&r["params"][0]["toBlock"]));
                if to - from + 1 > cap {
                    return json!({"error": {"code": -32005, "message": format!("query exceeds max block range {cap}")}});
                }
                json!({"result": [{"address": format!("{:#x}", Address::ZERO), "topics": [], "data": "0x",
                    "blockNumber": format!("{from:#x}"), "blockHash": format!("{:#x}", B256::repeat_byte(9)),
                    "transactionHash": format!("{:#x}", B256::repeat_byte(8)), "transactionIndex": "0x0",
                    "logIndex": format!("{:#x}", to - from + 1), "removed": false}]})
            }
            _ => json!({"error": {"code": -32601, "message": "no such method"}}),
        }
    }

    /// Fable recheck R-6: a log window an RPC refuses whole (it caps the `eth_getLogs` range) is read in tenths, contiguous and
    /// complete; an endpoint that refuses even `LOG_SPAN_MIN` blocks fails the read over. Control: an uncapped RPC answers the
    /// window in one request.
    #[tokio::test]
    async fn a_log_window_is_chunked_for_an_rpc_that_caps_the_range() {
        let spans = |logs: Vec<alloy::rpc::types::Log>| logs.iter().map(|l| (l.block_number.unwrap(), l.log_index.unwrap())).collect::<Vec<_>>();
        let (open, _) = fake_rpc(|r| capped_logs(r, u64::MAX)).await;
        let (capped, _) = fake_rpc(|r| capped_logs(r, 1_000)).await;
        let (stingy, _) = fake_rpc(|r| capped_logs(r, 5)).await;
        let head = 0x3000u64;
        let read = |url: String| async move { chain_of(&[&url]).logs_since(Address::ZERO, B256::ZERO, 10_000).await };
        assert_eq!(spans(read(open).await.unwrap()), vec![(head - 10_000, 10_001)], "control: one request");
        let got = spans(read(capped).await.unwrap());
        let mut at = head - 10_000;
        for (from, len) in &got {
            assert_eq!(*from, at, "contiguous: {got:?}");
            assert!(*len <= 1_000, "within the cap: {got:?}");
            at += len;
        }
        assert_eq!(at, head + 1, "up to the head: {got:?}");
        assert!(got.len() <= 12, "the span grows back to the cap: {got:?}");
        // the span grows back after a shrink below the cap: a 3,000-block cap is read in fewer, larger spans than its first tenth
        let (wide, _) = fake_rpc(|r| capped_logs(r, 3_000)).await;
        let got = spans(read(wide).await.unwrap());
        assert_eq!(got.iter().map(|x| x.1).sum::<u64>(), 10_001, "{got:?}");
        assert!(got.len() <= 8 && got.iter().any(|x| x.1 > 1_000), "grows back: {got:?}");
        assert!(read(stingy.clone()).await.is_err(), "a cap below LOG_SPAN_MIN gives the endpoint up");
        assert!(chain_of(&[&stingy]).logs_since(Address::ZERO, B256::ZERO, 50).await.is_err(),
            "a 51-block window: a tenth is 5, floored at LOG_SPAN_MIN, still refused");
        let (capped2, _) = fake_rpc(|r| capped_logs(r, 1_000)).await;
        assert!(!chain_of(&[&stingy, &capped2]).logs_since(Address::ZERO, B256::ZERO, 10_000).await.unwrap().is_empty(),
            "and the read fails over to the next endpoint");
        // Fable recheck 2 P3-3: a cap below a twentieth of the window gives the endpoint up within a few requests
        let (tight, tight_n) = fake_rpc(|r| capped_logs(r, 400)).await;
        assert!(read(tight).await.is_err());
        assert!(tight_n.load(std::sync::atomic::Ordering::SeqCst) <= 5, "head, 10,001, 1,000, 501: given up");
        // a transport error (HTTP 500) never shrinks the span: one log request, then the next endpoint
        let n: std::sync::Arc<std::sync::atomic::AtomicUsize> = Default::default();
        let n2 = n.clone();
        let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
            let n2 = n2.clone();
            async move {
                if r["method"] == "eth_getLogs" {
                    n2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({})));
                }
                (axum::http::StatusCode::OK, axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": "0x3000"})))
            }
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let down = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let (capped3, _) = fake_rpc(|r| capped_logs(r, u64::MAX)).await;
        assert_eq!(chain_of(&[&down, &capped3]).logs_since(Address::ZERO, B256::ZERO, 10_000).await.unwrap().len(), 1);
        assert_eq!(n.load(std::sync::atomic::Ordering::SeqCst), 1, "one request, then the next endpoint");
    }

    /// Fable recheck 2 P3-4: an endpoint that accepts and never answers fails the read over after `rpc_timeout_ms`; the block gas
    /// limit (every job's cap) fails over too. Control: the good endpoint alone. Recheck 3 R3-4: a simulation gets
    /// `rpc_simulate_timeout_ms`: an answer slower than a read's limit is a simulation's (the control: the same call as a read
    /// times out).
    #[tokio::test]
    async fn a_hung_endpoint_and_the_block_gas_read_fail_over() {
        let hung = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hung_url = format!("http://{}", hung.local_addr().unwrap());
        tokio::spawn(async move {
            let mut held = vec![];
            while let Ok((c, _)) = hung.accept().await {
                held.push(c); // accepted, never answered
            }
        });
        let (good, _) = fake_rpc(|r| match r["method"].as_str() {
            Some("eth_blockNumber") => json!({"result": "0x64"}),
            Some("eth_getBlockByNumber") => json!({"result": {"gasLimit": "0x1c9c380"}}),
            _ => json!({"result": format!("0x{:064x}", 5)}),
        }).await;
        assert_eq!(chain_of(&[&good]).block_gas().await.unwrap().limit, 30_000_000, "control");
        let quick = |urls: &[&str], read: u64, simulate: u64| Chain::with_signer(&ChainCfg { rpc_timeout_ms: read,
            rpc_simulate_timeout_ms: simulate, ..cfg_of(urls) }, PrivateKeySigner::random()).unwrap();
        let two = quick(&[&hung_url, &good], 500, 500);
        let got = tokio::time::timeout(std::time::Duration::from_secs(20), two.call_raw(Address::ZERO, Bytes::new())).await;
        assert_eq!(got.expect("one timeout, then the next endpoint").unwrap().len(), 32);
        let app = axum::Router::new().route("/", axum::routing::post(|axum::Json(r): axum::Json<Value>| async move {
            tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
            axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": if r["method"] == "eth_estimateGas" { json!("0x5208") }
                else { json!("0x") }}))
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let slow = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let c = quick(&[&slow], 300, 10_000);
        assert_eq!(c.simulate(Address::ZERO, Bytes::new()).await.unwrap(), 21_000, "a simulation within its own limit");
        // a fresh client: no pooled connection the server may have closed meanwhile (a quick transport error of another kind)
        let got = quick(&[&slow], 300, 10_000).call_raw(Address::ZERO, Bytes::new()).await;
        assert!(matches!(&got, Err(SimError::Transport(e)) if e.contains("within 300 ms")), "control: a read of the same speed times \
            out: {got:?}");
        let (busy, _) = fake_rpc(|_| json!({"error": {"code": -32000, "message": "header not found"}})).await;
        assert_eq!(chain_of(&[&busy, &good]).block_gas().await.unwrap().limit, 30_000_000, "the gas cap's read fails over");
    }

    /// Fable recheck 2 P3-8: an error answer saying execution was aborted by the node's own timeout is a transport error (it fails
    /// over); an EVM revert or an execution error without data stays a revert (the controls).
    /// Recheck 3 R3-6: matched by the exact phrase, after a revert: a revert reason that says "timeout" stays a revert.
    #[tokio::test]
    async fn an_aborted_execution_is_transport() {
        let (aborted, _) = fake_rpc(|_| json!({"error": {"code": -32000, "message": "execution aborted (timeout = 5s)"}})).await;
        let (exec, _) = fake_rpc(|_| json!({"error": {"code": -32000, "message": "VM execution error."}})).await;
        let (rev, _) = fake_rpc(|_| json!({"error": {"code": 3, "message": "execution reverted"}})).await;
        let (reason, _) = fake_rpc(|_| json!({"error": {"code": 3, "message": "execution reverted: timeout elapsed"}})).await;
        let (other, _) = fake_rpc(|_| json!({"error": {"code": -32000, "message": "execution timeout aborted"}})).await;
        let call = |u: String| async move { chain_of(&[&u]).call_raw(Address::ZERO, Bytes::new()).await };
        assert!(matches!(call(aborted).await, Err(SimError::Transport(_))));
        assert!(matches!(call(exec).await, Err(SimError::Revert(_))), "control: an execution error");
        assert!(matches!(call(rev).await, Err(SimError::Revert(_))), "control: a revert");
        assert!(matches!(call(reason).await, Err(SimError::Revert(_))), "a revert whose reason names a timeout");
        assert!(matches!(call(other).await, Err(SimError::Revert(_))), "not the node's phrase: the EVM's");
    }

    /// NODE-GW-07: the chain's `chain_uid` is its block 0 hash; a configured one that differs refuses the chain.
    #[tokio::test]
    async fn chain_uid_is_block_zero_and_a_wrong_pin_is_refused() {
        let (url, genesis) = rpc().await;
        assert_eq!(chain(&url, None).uid().await.unwrap(), genesis);
        assert_eq!(chain(&url, Some(genesis)).uid().await.unwrap(), genesis);
        assert!(chain(&url, Some(B256::repeat_byte(1))).uid().await.is_err());
        // a pruned RPC (no block 0) trusts the pin, and without one there is no chain_uid
        let app = axum::Router::new().route("/", axum::routing::post(|axum::Json(r): axum::Json<Value>| async move {
            axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": null}))
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pruned = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        assert_eq!(chain(&pruned, Some(B256::repeat_byte(1))).uid().await.unwrap(), B256::repeat_byte(1));
        assert!(chain(&pruned, None).uid().await.is_err());
        // review T4 m3: an unreachable RPC is not a pruned one — no pin is trusted, nothing is cached, it asks again
        let c = chain("http://127.0.0.1:9", Some(genesis));
        assert!(c.uid().await.is_err() && c.uid().await.is_err());
        assert!(c.uid.get().is_none());
    }

    /// Regulated-kinds spec §5, §7: the configured registry is used only while its code hashes to the pin; another code, none, or
    /// an unreachable RPC is an error (the venue does not start); none configured is `None`.
    #[tokio::test]
    async fn compliance_registry_code_hash_fails_closed() {
        let code = vec![0x60u8, 0x00, 0x60, 0x00, 0xf3];
        let c2 = code.clone();
        let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
            let c2 = c2.clone();
            async move {
                let at = r["params"][0].as_str().unwrap_or_default().to_lowercase();
                let code = if at == format!("{:#x}", Address::repeat_byte(0xc0)) { c2 } else { vec![] };
                axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": format!("0x{}", alloy::hex::encode(code))}))
            }
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let with = |url: &str, a: Option<Address>, h: Option<B256>| {
            let cfg = ChainCfg { evm_chain_number: 296, rpc_urls: vec![url.into()], compliance_registry: a, compliance_registry_codehash: h,
                ..Default::default() };
            Chain::with_signer(&cfg, PrivateKeySigner::random()).unwrap()
        };
        let (reg, pin) = (Address::repeat_byte(0xc0), alloy::primitives::keccak256(&code));
        assert_eq!(with(&url, Some(reg), Some(pin)).compliance_registry().await.unwrap(), Some(reg));
        assert_eq!(with(&url, None, None).compliance_registry().await.unwrap(), None);
        let e = with(&url, Some(reg), Some(B256::repeat_byte(1))).compliance_registry().await.unwrap_err().to_string();
        assert!(e.contains("is not compliance_registry_codehash"), "{e}");
        assert!(with(&url, Some(Address::repeat_byte(0xc1)), Some(alloy::primitives::keccak256([]))).compliance_registry().await.is_err(),
            "no code is never the pin, even the empty code's hash");
        assert!(with("http://127.0.0.1:9", Some(reg), Some(pin)).compliance_registry().await.is_err());
    }

    /// An RPC answering every `eth_call` with 5 and keeping each call's input.
    async fn nonce_rpc() -> (String, std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
        let seen: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Default::default();
        let s2 = seen.clone();
        let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
            let s2 = s2.clone();
            async move {
                let input = r["params"][0]["input"].as_str().or(r["params"][0]["data"].as_str()).unwrap_or("0x").to_string();
                s2.lock().unwrap().push(alloy::hex::decode(&input[2..]).unwrap());
                axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": format!("0x{:064x}", 5)}))
            }
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, seen)
    }

    /// The view R80 reads for vector row `name` on `kind`: `(selector, the id word)` of the one `eth_call` made, and its answer.
    async fn nonce_view_of(name: &str, kind: &str) -> ([u8; 4], B256, U256) {
        let v = crate::typed::testkit::vectors();
        let mut op = crate::typed::testkit::op_of(name, kind, &v).unwrap_or_else(|| panic!("{name}"));
        if name == "UAPayUnderMandate" {
            op["envelope"]["batch"] = json!(crate::typed::mandate_pay_lane(&crate::typed::testkit::hex(&op["args"]["entryRef"])).to_string());
            op["envelope"]["nonce"] = json!("0");
        }
        let m = crate::submit::work_of_op(Some(1), &op, None).unwrap().0.meta.unwrap_or_else(|| panic!("{name}: no lane"));
        let (url, seen) = nonce_rpc().await;
        let n = chain(&url, None).subject_nonce(&m).await.unwrap();
        let call = seen.lock().unwrap().pop().unwrap();
        assert!(seen.lock().unwrap().is_empty(), "one read");
        assert_eq!(call[36..68], m.batch.to_be_bytes::<32>(), "{name}: the lane");
        (call[..4].try_into().unwrap(), B256::from_slice(&call[4..36]), n)
    }

    fn cast(s: &str) -> [u8; 4] {
        alloy::primitives::keccak256(s)[..4].try_into().unwrap()
    }

    /// Plan T14, R80 by kind: the subject's nonce through `mtxNonce(bytes32 id, batch)` on a token (a merged row and an address
    /// wrap alike: one nonce map, and the token has no address view left), the router and the mandate wallet; through
    /// `mtxNonce(address, batch)` on `SmartKeyAccount`. The id is the envelope's `from`, padded for an address envelope.
    #[tokio::test]
    async fn nonce_view_by_kind() {
        let key: Address = crate::typed::testkit::vectors()["key"]["address"].as_str().unwrap().parse().unwrap();
        let ids = cast("mtxNonce(bytes32,uint256)");
        for (name, kind) in [("UAUnwrap", "token"), ("Wrap", "token"), ("UAShield", "zether"), ("UAPrepareAcc", "pqz"),
            ("UAGrantRole", "gov_router"), ("UACancelNonce", "token")] {
            assert_eq!(nonce_view_of(name, kind).await, (ids, key.into_word(), U256::from(5)), "{name} on {kind}");
        }
        assert_eq!(nonce_view_of("AddKey", "account").await, (cast("mtxNonce(address,uint256)"), key.into_word(), U256::from(5)));
        assert_eq!(nonce_view_of("CancelNonce", "account").await.0, cast("mtxNonce(address,uint256)"));
    }

    /// Q6: the mandate wallet is on `UAMetaTxBase`: its nonce view is `mtxNonce(bytes32)`, the delegate's payment lane too.
    #[tokio::test]
    async fn wallet_nonce_view_is_bytes32() {
        for name in ["UASetPayee", "UAExecute", "UAPayUnderMandate", "UACancelNonce"] {
            assert_eq!(nonce_view_of(name, "wallet").await.0, cast("mtxNonce(bytes32,uint256)"), "{name}");
        }
    }

    /// Fix 1 (review minor 5), ua-mtx-merge: a native id's lane is one nonce map for the merged entries (`UA…` event, R18) and
    /// the address ones left (a wrap: `MetaTransactionExecuted`), so its classification reads both executions, whichever
    /// job spent it; a derived UA's only the UA one.
    #[test]
    fn a_native_ua_subject_is_classified_on_both_paths() {
        let m = |from: B256, ua: bool| MetaRef { token: Address::ZERO, from, batch: U256::ZERO, nonce: U256::ZERO, digest: None, ua, addr_nonce: false };
        let (ua_ev, mtx_ev) = (IUALedger::UAMetaTransactionExecuted::SIGNATURE_HASH, IToken::MetaTransactionExecuted::SIGNATURE_HASH);
        let native = Address::repeat_byte(1).into_word();
        assert_eq!(executed_events(&m(native, true)), vec![ua_ev, mtx_ev]);
        assert_eq!(executed_events(&m(B256::repeat_byte(1), true)), vec![ua_ev]);
        assert_eq!(executed_events(&m(native, false)), vec![ua_ev, mtx_ev], "an address job's lane too");
    }
}
