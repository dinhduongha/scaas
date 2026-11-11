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
            None if resp.message.contains("revert") || resp.message.contains("execution") => {
                SimError::Revert(resp.message.to_string())
            }
            None => SimError::Transport(resp.message.to_string()),
        },
        None => SimError::Transport(e.to_string()),
    }
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

/// The smallest `eth_getLogs` span [`Chain::logs_back`] asks before it gives an endpoint up (R-6).
const LOG_SPAN_MIN: u64 = 10;

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
    /// Fable recheck 2 P2-1: the highest block this chain has seen (a receipt's, an endpoint's head); a failover endpoint below it
    /// answers no read.
    head: std::sync::atomic::AtomicU64,
}

impl Chain {
    /// Một `Chain` mỗi lane (R62): cùng RPC, khoá khác nhau.
    pub fn connect_lanes(cfg: &ChainCfg, signers: &[crate::signer::LocalSigner]) -> Result<Vec<Self>> {
        signers.iter().map(|s| Self::with_signer(cfg, s.evm()?)).collect()
    }

    pub fn with_signer(cfg: &ChainCfg, signer: PrivateKeySigner) -> Result<Self> {
        let address = signer.address();
        let providers = cfg
            .rpc_urls
            .iter()
            .map(|u| Ok(ProviderBuilder::new().disable_recommended_fillers().connect_http(u.parse()?).erased()))
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
            head: Default::default(),
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
    /// is final. A failover endpoint (not the first) answers only when its head is at or above the highest block this chain has
    /// seen ([`Chain::saw_block`]; Fable recheck 2 P2-1): a stale one could revert a job that lands at the head, so it is a
    /// transport error. The lane's own sends, nonces, fees and receipts stay on the first endpoint, and the indexers keep their
    /// quorum over all of them.
    pub async fn read<T, F, Fut>(&self, f: F) -> std::result::Result<T, SimError>
    where
        F: Fn(DynProvider) -> Fut,
        Fut: std::future::Future<Output = std::result::Result<T, SimError>>,
    {
        use std::sync::atomic::Ordering::Relaxed;
        let mut last = String::new();
        for (i, p) in self.providers.iter().enumerate() {
            let fresh = match i {
                0 => Ok(()),
                _ => match p.get_block_number().await {
                    Ok(n) if n >= self.head.load(Relaxed) => {
                        self.saw_block(n);
                        Ok(())
                    }
                    Ok(n) => Err(SimError::Transport(format!("endpoint {i} at block {n}, behind {}", self.head.load(Relaxed)))),
                    Err(e) => Err(classify(&e)),
                },
            };
            if let Err(e) = fresh {
                let e = e.to_string();
                tracing::warn!(chain = self.number, endpoint = i, error = %redact_urls(&e), "chain read: endpoint not used; next");
                last = e;
                continue;
            }
            match f(p.clone()).await {
                Err(SimError::Transport(e)) => {
                    tracing::warn!(chain = self.number, endpoint = i, error = %redact_urls(&e), "chain read failed; next endpoint");
                    last = e;
                }
                r => return r,
            }
        }
        Err(SimError::Transport(last))
    }

    /// A block this chain has seen (a receipt's, an endpoint's head): failover endpoints below it answer no read.
    pub fn saw_block(&self, n: u64) {
        self.head.fetch_max(n, std::sync::atomic::Ordering::Relaxed);
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
        self.read(|p| {
            let tx = tx.clone();
            async move {
                p.call(tx.clone()).await.map_err(|e| classify_sim(&e))?;
                p.estimate_gas(tx).await.map_err(|e| classify_sim(&e))
            }
        })
        .await
    }

    /// The `latest` header's gas facts: its `gasLimit` (EIP-8037 includes a transaction only when its gas limit fits
    /// it) and whether the chain runs Amsterdam — the header carries EIP-7928's `blockAccessListHash` (as
    /// `pqz-core/nethermind/chain/e2e.py` decides it). Read from the raw header, so any RPC's block shape works.
    pub async fn block_gas(&self) -> Result<BlockGas> {
        let b: serde_json::Value =
            self.primary().raw_request("eth_getBlockByNumber".into(), ("latest", false)).await?;
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
    /// R-6: an RPC that caps the `eth_getLogs` range refuses the whole window, so a refused span is asked again in tenths, down
    /// to [`LOG_SPAN_MIN`] blocks; an endpoint that refuses that too fails the read over.
    async fn logs_back(&self, filter: Filter, lookback: u64) -> Result<Vec<alloy::rpc::types::Log>> {
        self.read(|p| {
            let filter = filter.clone();
            async move {
                let latest = p.get_block_number().await.map_err(|e| classify(&e))?;
                self.saw_block(latest);
                let (mut from, mut span, mut out) = (latest.saturating_sub(lookback), lookback.saturating_add(1), vec![]);
                while from <= latest {
                    let to = latest.min(from.saturating_add(span - 1));
                    match p.get_logs(&filter.clone().from_block(from).to_block(to)).await {
                        Ok(l) => {
                            out.extend(l);
                            from = to + 1;
                        }
                        Err(e) if span > LOG_SPAN_MIN => {
                            tracing::debug!(span, error = %redact_urls(&e.to_string()), "eth_getLogs span refused; a tenth of it");
                            span = (span / 10).max(LOG_SPAN_MIN);
                        }
                        Err(e) => return Err(classify(&e)),
                    }
                }
                Ok(out)
            }
        })
        .await
        .map_err(|e| anyhow!("{e}"))
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
mod tests {
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
    async fn fake_rpc(f: fn(&Value) -> Value) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let n: std::sync::Arc<std::sync::atomic::AtomicUsize> = Default::default();
        let n2 = n.clone();
        let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
            n2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut a = f(&r);
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
        let cfg = ChainCfg { evm_chain_number: 296, rpc_urls: urls.iter().map(|u| u.to_string()).collect(), ..Default::default() };
        Chain::with_signer(&cfg, PrivateKeySigner::random()).unwrap()
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
        // Fable recheck 2 P2-1: a failover endpoint behind the highest block seen answers nothing (its revert could kill a job that
        // lands at the head); at or above it, its revert is final (the control)
        let (stale, stale_n) = fake_rpc(|r| match r["method"].as_str() {
            Some("eth_blockNumber") => json!({"result": "0x10"}),
            _ => json!({"error": {"code": 3, "message": "execution reverted", "data": "0xdeadbeef"}}),
        }).await;
        let behind = chain_of(&["http://127.0.0.1:9", &stale]);
        behind.saw_block(0x11);
        assert!(matches!(call(behind).await, Err(SimError::Transport(e)) if e.contains("behind")), "stale: requeue, never final");
        assert_eq!(stale_n.load(SeqCst), 1, "only its head was read");
        let level = chain_of(&["http://127.0.0.1:9", &stale]);
        level.saw_block(0x10);
        assert!(matches!(call(level).await, Err(SimError::Revert(_))), "control: at the head, its revert is the contract's");
        let (headless, _) = fake_rpc(|r| match r["method"].as_str() {
            Some("eth_blockNumber") => json!({"error": {"code": -32000, "message": "header not found"}}),
            _ => json!({"error": {"code": 3, "message": "execution reverted", "data": "0xdeadbeef"}}),
        }).await;
        assert!(matches!(call(chain_of(&["http://127.0.0.1:9", &headless])).await, Err(SimError::Transport(_))),
            "a failover endpoint whose head is unread answers nothing");
        // a window of logs: the busy endpoint refuses the head, the good one answers the head and the logs
        let c = chain_of(&[&busy, &good]);
        let before = good_n.load(SeqCst);
        assert!(c.logs_since(Address::ZERO, B256::ZERO, 10).await.unwrap().is_empty());
        assert_eq!(good_n.load(SeqCst) - before, 3, "its head check, eth_blockNumber and eth_getLogs, all on the good endpoint");
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
        let want: Vec<(u64, u64)> = (0..11).map(|i| (head - 10_000 + i * 1_000, if i < 10 { 1_000 } else { 1 })).collect();
        assert_eq!(got, want, "contiguous 1,000-block spans up to the head");
        assert!(read(stingy.clone()).await.is_err(), "a cap below LOG_SPAN_MIN gives the endpoint up");
        assert!(chain_of(&[&stingy]).logs_since(Address::ZERO, B256::ZERO, 50).await.is_err(),
            "a 51-block window: a tenth is 5, floored at LOG_SPAN_MIN, still refused");
        let (capped2, _) = fake_rpc(|r| capped_logs(r, 1_000)).await;
        assert_eq!(chain_of(&[&stingy, &capped2]).logs_since(Address::ZERO, B256::ZERO, 10_000).await.unwrap().len(), 11,
            "and the read fails over to the next endpoint");
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
