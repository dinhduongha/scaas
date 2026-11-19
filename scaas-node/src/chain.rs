//! Kết nối RPC + ký vỏ tx. Khoá chỉ đi qua `EthereumWallet` dựng từ một signer (ruling R15):
//! bản này là `PrivateKeySigner` từ biến môi trường; thay bằng custody broker không đổi nơi gọi.
//! The chain reads go through `scaas_rpc::evm::EvmPool` (CLI-RPC-01, plan T5): the endpoint list, failover, identity, the
//! bounded transport; this file keeps the lane key, signing and sending, and the reads over the node's own types.
use alloy::eips::eip2718::Encodable2718;
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::{Filter, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::{SolCall, SolEvent};
use alloy::transports::TransportError;
use anyhow::{anyhow, Result};
use scaas_rpc::evm::EvmPool;

use crate::abi::{decode_revert, IMtxIds, IToken, IUALedger};
use crate::config::ChainCfg;
use crate::submit::MetaRef;

pub use scaas_rpc::endpoint::redact_urls;
pub use scaas_rpc::evm::{is_contract, BlockGas, SimError};

/// The crate's classifier with the node's revert decoder (`abi::decode_revert`).
pub fn classify(e: &TransportError) -> SimError {
    scaas_rpc::evm::classify_with(e, decode_revert)
}

/// [`classify`] for a simulation without a gas field (the crate's rule, the node's decoder).
pub fn classify_sim(e: &TransportError) -> SimError {
    scaas_rpc::evm::classify_sim_with(e, decode_revert)
}

pub struct Chain {
    pub number: u64,
    pool: EvmPool,
    wallet: EthereumWallet,
    address: Address,
    /// `compliance_registry` and its pinned code hash (regulated-kinds spec §5, F-11).
    compliance: Option<(Address, B256)>,
    /// The table's highest block seen from its first endpoint (`ChainCfg::head`), the pool's own.
    #[cfg_attr(not(test), allow(dead_code))]
    head: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// The pool's identity cells, per endpoint (`false`: another network, dropped from every read).
    #[cfg_attr(not(test), allow(dead_code))]
    chain_ok: std::sync::Arc<Vec<std::sync::OnceLock<bool>>>,
    /// The pool's `chain_uid` once read.
    #[cfg_attr(not(test), allow(dead_code))]
    uid: std::sync::Arc<std::sync::OnceLock<B256>>,
}

impl Chain {
    /// Một `Chain` mỗi lane (R62): cùng RPC, khoá khác nhau.
    pub fn connect_lanes(
        cfg: &ChainCfg,
        signers: &[crate::signer::LocalSigner],
    ) -> Result<Vec<Self>> {
        signers
            .iter()
            .map(|s| Self::with_signer(cfg, s.evm()?))
            .collect()
    }

    pub fn with_signer(cfg: &ChainCfg, signer: PrivateKeySigner) -> Result<Self> {
        let address = signer.address();
        if cfg.rpc_urls.is_empty() {
            return Err(anyhow!("chain {}: no rpc_urls", cfg.evm_chain_number));
        }
        let endpoints = cfg
            .rpc_urls
            .iter()
            .map(|u| scaas_rpc::Endpoint::named(u))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("chain {}: rpc_urls: {e}", cfg.evm_chain_number))?;
        // each request bounded by rpc_timeout_ms, a simulation's by rpc_simulate_timeout_ms (recheck 2 P3-4, recheck 4 R4-3)
        let list = scaas_rpc::NodeList::new(
            endpoints,
            scaas_rpc::Policy::Failover,
            cfg.rpc_timeout_ms,
            cfg.rpc_simulate_timeout_ms,
            scaas_rpc::endpoint::READ_TIMEOUT_MS,
        )
        .map_err(|e| anyhow!("chain {}: rpc_urls: {e}", cfg.evm_chain_number))?;
        let shared = scaas_rpc::evm::Shared {
            head: cfg.head.clone(),
            failover: cfg.failover.clone(),
        };
        // scaas-rpc T13 point 6: endpoint 0 is identity-checked on its reads too, as every other endpoint
        let pool = EvmPool::connect(list, cfg.evm_chain_number, cfg.chain_uid)
            .map_err(|e| anyhow!("chain {}: {e}", cfg.evm_chain_number))?
            .with_shared(shared)
            .with_decode(decode_revert);
        Ok(Self {
            number: cfg.evm_chain_number,
            chain_ok: pool.pool().identity_cells(),
            uid: pool.uid_cell(),
            pool,
            wallet: EthereumWallet::from(signer),
            address,
            compliance: cfg
                .compliance_registry
                .zip(cfg.compliance_registry_codehash),
            head: cfg.head.clone(),
        })
    }

    /// The chain's endpoint pool (scaas-rpc), for a family's first-endpoint reads (Hedera's Relay, plan T14).
    pub fn pool(&self) -> &EvmPool {
        &self.pool
    }

    pub fn primary(&self) -> &DynProvider {
        self.pool.primary()
    }

    pub fn others(&self) -> &[DynProvider] {
        self.pool.others()
    }

    pub fn address(&self) -> Address {
        self.address
    }

    /// ARCH-POS-15, failover (CLI-RPC-04, `scaas_rpc::pool::Pool::failover`): one read, answered completely by one endpoint,
    /// `rpc_urls` in the order given, never mixing answers of two endpoints. A transport error moves the whole read to the next
    /// endpoint; a revert is final only from the first endpoint (a failover endpoint's revert is a transport error, recheck 3
    /// R3-1). A failover endpoint answers only when it is this chain (R3-3) and its head is at or above the highest block seen
    /// from the first endpoint ([`Chain::saw_block`], recheck 2 P2-1). The lane's own sends, nonces, fees and receipts stay on
    /// the first endpoint, and the indexers keep their quorum over all of them.
    pub async fn read<T, F, Fut>(&self, f: F) -> std::result::Result<T, SimError>
    where
        F: Fn(DynProvider) -> Fut,
        Fut: std::future::Future<Output = std::result::Result<T, SimError>>,
    {
        self.pool.raw_read(f).await
    }

    /// [`Chain::read`], with the index of the endpoint that answered: a caller that reads a refusal out of an `Ok` (the venue's
    /// evidence, an ERC-1271 `false`) takes it from the first endpoint only.
    pub async fn read_at<T, F, Fut>(&self, f: F) -> std::result::Result<(T, usize), SimError>
    where
        F: Fn(DynProvider) -> Fut,
        Fut: std::future::Future<Output = std::result::Result<T, SimError>>,
    {
        self.pool.raw_read_at(f).await
    }

    /// A block of this chain from its first endpoint (a lane's receipt, a polled head): failover endpoints below it answer no
    /// read. Never fed by a failover endpoint's own answer (R3-2).
    pub fn saw_block(&self, n: u64) {
        self.pool.saw_block(n)
    }

    /// Recheck 4 R4-1: how many reads a failover endpoint answered (a value, never a verdict): a refusal or a blame read while
    /// this moved is no verdict: the lane requeues the job, the venue answers 503.
    pub fn failover_answers(&self) -> u64 {
        self.pool.failover_answers()
    }

    /// The highest block seen ([`Chain::saw_block`]).
    pub fn seen_head(&self) -> u64 {
        self.pool.seen_head()
    }

    /// [`Chain::read`] of one `eth_call` from `from` (with `gas` when given), classified by [`classify`].
    pub async fn call_tx(&self, tx: TransactionRequest) -> std::result::Result<Bytes, SimError> {
        self.pool.call_tx(tx).await
    }

    /// `eth_call` + `eth_estimateGas` từ địa chỉ relayer.
    pub async fn simulate(&self, to: Address, data: Bytes) -> std::result::Result<u64, SimError> {
        self.simulate_from(self.address, to, data).await
    }

    /// Mô phỏng với `from` tuỳ ý (gateway mô phỏng chân DEX bằng địa chỉ DEX). The estimate is the gas limit the
    /// transaction needs, regular + state (EIP-8037); no gas field, so both calls run at the RPC's gas cap.
    pub async fn simulate_from(
        &self,
        from: Address,
        to: Address,
        data: Bytes,
    ) -> std::result::Result<u64, SimError> {
        self.pool.simulate_from(from, to, data).await
    }

    /// The `latest` header's gas facts (`gasLimit`, Amsterdam by EIP-7928's `blockAccessListHash`), failed over.
    pub async fn block_gas(&self) -> Result<BlockGas> {
        self.pool.block_gas().await.map_err(|e| anyhow!("{e}"))
    }

    /// The gas limit and max fee per gas of the transaction `hash` as it was sent (`eth_getTransactionByHash`, the first
    /// endpoint); `None` if the RPC does not know it (the fee: if it gives none, e.g. a legacy transaction).
    pub async fn tx_fees(&self, hash: B256) -> Result<Option<(u64, Option<u128>)>> {
        self.pool
            .first_tx_fees(hash)
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    /// This chain's `chain_uid`: the RPC's block 0 hash, which must equal the configured `chain_uid` when one is set; a pruned
    /// RPC without block 0 is refused (`ChainIdentityUnreadable`, scaas-rpc T13 S16). Read once; an error is not remembered.
    pub async fn uid(&self) -> Result<B256> {
        self.pool.uid().await.map_err(|e| anyhow!("{e}"))
    }

    /// The configured `compliance_registry` once its runtime code hashes to the pinned `compliance_registry_codehash`
    /// (regulated-kinds spec §5: one canonical code, no proxy); `Ok(None)` when none is configured. Another code, no code, or
    /// an unreadable one is an error: the caller does not start (fail closed).
    pub async fn compliance_registry(&self) -> Result<Option<Address>> {
        let Some((a, pin)) = self.compliance else {
            return Ok(None);
        };
        let code = self
            .code_at(a)
            .await
            .map_err(|e| anyhow!("chain {}: compliance_registry code: {e}", self.number))?;
        let got = alloy::primitives::keccak256(&code);
        if code.is_empty() || got != pin {
            return Err(anyhow!("chain {}: compliance_registry {a:#x} code hash {got:#x} is not compliance_registry_codehash {pin:#x}",
                self.number));
        }
        Ok(Some(a))
    }

    /// A view call; a revert is the contract's answer (`SimError::Revert`), anything else the transport's.
    pub async fn call_view<C: SolCall>(
        &self,
        to: Address,
        call: C,
    ) -> std::result::Result<C::Return, SimError> {
        let out = self
            .call_tx(
                TransactionRequest::default()
                    .with_to(to)
                    .with_input(call.abi_encode()),
            )
            .await?;
        C::abi_decode_returns(&out).map_err(|e| SimError::Revert(format!("decode: {e}")))
    }

    /// `eth_call` of calldata built by ABI type (group 3f: a PQZ token's statement views, `crate::pqz`).
    pub async fn call_raw(&self, to: Address, data: Bytes) -> std::result::Result<Bytes, SimError> {
        self.call_tx(TransactionRequest::default().with_to(to).with_input(data))
            .await
    }

    /// `eth_call` from the lane with exactly `gas` (sizing `mtxSettle`, `guard::settle_gas`).
    pub async fn call_with_gas(
        &self,
        to: Address,
        data: Bytes,
        gas: u64,
    ) -> std::result::Result<Bytes, SimError> {
        self.call_tx(
            TransactionRequest::default()
                .with_from(self.address)
                .with_to(to)
                .with_input(data)
                .with_gas_limit(gas),
        )
        .await
    }

    /// `who` is a contract signer (ERC-1271, `guard::erc1271_floor`): `is_contract` of its code, so an EIP-7702
    /// designator (an EOA, ECDSA only) is not.
    pub async fn is_contract_at(&self, who: Address) -> Result<bool> {
        self.pool
            .is_contract_at(who)
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    /// `who`'s runtime code, through [`Chain::read`].
    pub async fn code_at(&self, who: Address) -> std::result::Result<Bytes, SimError> {
        self.pool.code(who).await
    }

    /// The lane's EIP-1559 fees, from the first endpoint only (F4).
    pub async fn fees(&self) -> Result<(u128, u128)> {
        self.pool.first_fees().await.map_err(|e| anyhow!("{e}"))
    }

    /// The lane's pending nonce, from the first endpoint only (F4).
    pub async fn pending_nonce(&self) -> Result<u64> {
        self.pool
            .first_pending_nonce(self.address)
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    /// Số tx của lane ĐÃ vào khối (`latest`), khác `pending_nonce`: nonce vỏ `n` đã bị dùng ⇔ `nonce_at() > n` (R80).
    pub async fn nonce_at(&self) -> Result<u64> {
        self.pool
            .first_nonce_at(self.address)
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    async fn view<C: SolCall>(&self, to: Address, call: C) -> Result<C::Return> {
        self.call_view(to, call).await.map_err(|e| anyhow!("{e}"))
    }

    /// The subject's next nonce on its lane (R80), by the contract's kind (ua-mtx-merge plan T14): `mtxNonce(bytes32 id, batch)`
    /// on a token, the router and a mandate wallet (one nonce map on ids, CTR-UA-26: an address envelope's `from` padded),
    /// `mtxNonce(address, batch)` on `SmartKeyAccount`.
    pub async fn subject_nonce(&self, m: &MetaRef) -> Result<U256> {
        if m.addr_nonce {
            return self
                .view(
                    m.token,
                    IToken::mtxNonceCall {
                        from: Address::from_word(m.from),
                        batch: m.batch,
                    },
                )
                .await;
        }
        self.view(
            m.token,
            IMtxIds::mtxNonceCall {
                from: m.from,
                batch: m.batch,
            },
        )
        .await
    }

    /// R80: `m`'s subject nonce is spent (`mtxNonce > nonce`). Fable recheck 7 R7-1: a "not spent" read while a failover endpoint
    /// answered is no verdict (it may be a block behind another relayer's landing): `Err`, which every caller treats as unread;
    /// a "spent" stands (a nonce only grows).
    pub async fn nonce_spent(&self, m: &MetaRef) -> Result<bool> {
        let mark = self.failover_answers();
        let spent = self.subject_nonce(m).await? > m.nonce;
        if !spent && self.failover_answers() != mark {
            return Err(anyhow!("FAILOVER_ANSWER: mtxNonce read on a failover endpoint (the first endpoint did not answer); read again"));
        }
        Ok(spent)
    }

    /// `MetaTransactionExecuted` (a UA subject: `UAMetaTransactionExecuted`) of `(from, batch, nonce)` trong `lookback`
    /// khối gần nhất ⇒ `(digest, relayer)` (§8.5). Both events index `from`, `relayer`, `batch` alike.
    pub async fn meta_executed(
        &self,
        m: &MetaRef,
        lookback: u64,
    ) -> Result<Option<(B256, Address)>> {
        let filter = Filter::new()
            .address(m.token)
            .event_signature(executed_events(m))
            .topic1(m.from)
            .topic3(B256::from(m.batch));
        for log in self.logs_back(filter, lookback).await? {
            let e =
                match log.topic0() == Some(&IUALedger::UAMetaTransactionExecuted::SIGNATURE_HASH) {
                    true => log
                        .log_decode::<IUALedger::UAMetaTransactionExecuted>()
                        .ok()
                        .map(|l| {
                            (
                                l.inner.data.nonce,
                                l.inner.data.digest,
                                l.inner.data.relayer,
                            )
                        }),
                    false => log
                        .log_decode::<IToken::MetaTransactionExecuted>()
                        .ok()
                        .map(|l| {
                            (
                                l.inner.data.nonce,
                                l.inner.data.digest,
                                l.inner.data.relayer,
                            )
                        }),
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

    /// Group 3g (spec §7.3): a `UAPqzKeyCurrent` of one of `uas` on `registry` in the last `lookback` blocks; the three-key model
    /// (CTR-UA-43): or a `UAPqzScopedKeyCurrent` (a class-2 / class-3 token's keys), of any scope (evidence, not proof).
    pub async fn pqz_key_current_since(
        &self,
        registry: Address,
        uas: &[B256],
        lookback: u64,
    ) -> Result<bool> {
        let filter = Filter::new()
            .address(registry)
            .event_signature(vec![
                crate::abi::IUARegistry::UAPqzKeyCurrent::SIGNATURE_HASH,
                crate::abi::IUARegistry::UAPqzScopedKeyCurrent::SIGNATURE_HASH,
            ])
            .topic1(uas.to_vec());
        Ok(!self.logs_back(filter, lookback).await?.is_empty())
    }

    /// Round 3t (CTR-PQZ-36, spec §10): the logs `topic0` of `address` in the last `lookback` blocks (a token's `VerifierFeeSet`).
    pub async fn logs_since(
        &self,
        address: Address,
        topic0: B256,
        lookback: u64,
    ) -> Result<Vec<alloy::rpc::types::Log>> {
        self.pool
            .logs_since(address, topic0, lookback)
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    /// The logs of `filter` in the last `lookback` blocks, one endpoint answering the head and the logs (the crate's
    /// `EvmPool::logs_back`: spans in tenths for an RPC that caps the range, R-6, recheck 2 P3-3).
    async fn logs_back(
        &self,
        filter: Filter,
        lookback: u64,
    ) -> Result<Vec<alloy::rpc::types::Log>> {
        self.pool
            .logs_back(filter, lookback)
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    /// Ký EIP-1559; trả bytes thô và hash — hash biết TRƯỚC khi gửi (journal, review F5).
    pub async fn sign(
        &self,
        nonce: u64,
        to: Address,
        data: Bytes,
        gas: u64,
        fees: (u128, u128),
    ) -> Result<(Bytes, B256)> {
        let tx = TransactionRequest::default()
            .with_from(self.address)
            .with_to(to)
            .with_input(data)
            .with_nonce(nonce)
            .with_chain_id(self.number)
            .with_gas_limit(gas)
            .with_max_fee_per_gas(fees.0)
            .with_max_priority_fee_per_gas(fees.1.min(fees.0));
        let env = tx
            .build(&self.wallet)
            .await
            .map_err(|e| anyhow!("sign: {e}"))?;
        let hash = *env.tx_hash();
        Ok((Bytes::from(env.encoded_2718()), hash))
    }

    pub async fn send_raw(&self, raw: &Bytes) -> Result<()> {
        let _pending = self.primary().send_raw_transaction(raw).await?;
        Ok(())
    }

    /// The `finalized` block's number, from the first endpoint only (F4).
    pub async fn finalized_number(&self) -> Result<Option<u64>> {
        Ok(self.pool.first_finalized_number().await)
    }

    pub async fn block_hash(p: &DynProvider, n: u64) -> Option<B256> {
        EvmPool::block_hash_on(p, n).await
    }
}

/// The executions that spend `m`'s nonce: a native id's lane is spent by a merged entry (`UAMetaTransactionExecuted`, R18) or
/// an address one (a wrap, `executeMetaTransaction`: `MetaTransactionExecuted`) alike, one nonce map; a derived UA's by the
/// UA event only.
pub fn executed_events(m: &MetaRef) -> Vec<B256> {
    let (ua, mtx) = (
        IUALedger::UAMetaTransactionExecuted::SIGNATURE_HASH,
        IToken::MetaTransactionExecuted::SIGNATURE_HASH,
    );
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
        let block: Value =
            serde_json::from_str::<Value>(include_str!("../tests/vectors/hedera_testnet.json"))
                .unwrap()["block"]
                .clone();
        let hash = block["hash"].as_str().unwrap().parse().unwrap();
        let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
            let block = block.clone();
            // scaas-rpc T13 point 6 (fixture correction): `eth_chainId` is chain 296's, every other request block 0
            let result = if r["method"] == "eth_chainId" { json!("0x128") } else { block };
            async move { axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": result})) }
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, hash)
    }

    /// Chain 296's answer to `eth_chainId` and to block 0 (the recorded Hedera testnet block, hash [`genesis`]), else none.
    fn identity_answer(r: &Value) -> Option<Value> {
        let result = if r["method"] == "eth_chainId" {
            json!("0x128")
        } else if r["method"] == "eth_getBlockByNumber" && r["params"][0] == "0x0" {
            let mut b =
                serde_json::from_str::<Value>(include_str!("../tests/vectors/hedera_testnet.json"))
                    .unwrap()["block"]
                    .clone();
            b["hash"] = json!(format!("{:#x}", genesis()));
            b
        } else {
            return None;
        };
        Some(json!({"jsonrpc": "2.0", "id": r["id"], "result": result}))
    }

    fn chain(url: &str, pin: Option<B256>) -> Chain {
        let cfg = ChainCfg {
            evm_chain_number: 296,
            rpc_urls: vec![url.into()],
            chain_uid: pin,
            ..Default::default()
        };
        Chain::with_signer(&cfg, PrivateKeySigner::random()).unwrap()
    }

    /// A fake RPC answering each request with `f(request)` (a `result` or an `error` member), counting the requests.
    pub(crate) async fn fake_rpc(
        f: fn(&Value) -> Value,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        fake_rpc_on(f, 296, genesis()).await
    }

    /// The block 0 hash of the fake chain 296 ([`chain_of`] pins it).
    fn genesis() -> B256 {
        B256::repeat_byte(0x60)
    }

    /// [`fake_rpc`] answering `eth_chainId` with `id` (P3-5) and block 0 with hash `zero` (R3-3); neither is counted.
    async fn fake_rpc_on(
        f: fn(&Value) -> Value,
        id: u64,
        zero: B256,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let n: std::sync::Arc<std::sync::atomic::AtomicUsize> = Default::default();
        let n2 = n.clone();
        let mut block: Value =
            serde_json::from_str::<Value>(include_str!("../tests/vectors/hedera_testnet.json"))
                .unwrap()["block"]
                .clone();
        block["hash"] = json!(format!("{zero:#x}"));
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
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
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, n)
    }

    fn chain_of(urls: &[&str]) -> Chain {
        Chain::with_signer(&cfg_of(urls), PrivateKeySigner::random()).unwrap()
    }

    fn cfg_of(urls: &[&str]) -> ChainCfg {
        ChainCfg {
            evm_chain_number: 296,
            rpc_urls: urls.iter().map(|u| u.to_string()).collect(),
            chain_uid: Some(genesis()),
            ..Default::default()
        }
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
        })
        .await;
        let (busy, busy_n) =
            fake_rpc(|_| json!({"error": {"code": -32000, "message": "header not found"}})).await;
        let (rev, rev_n) = fake_rpc(|_| json!({"error": {"code": 3, "message": "execution reverted", "data": "0xdeadbeef"}})).await;
        let five = Bytes::from(U256::from(5).to_be_bytes::<32>().to_vec());
        let call = |c: Chain| async move { c.call_raw(Address::ZERO, Bytes::new()).await };
        assert_eq!(call(chain_of(&[&good])).await.unwrap(), five, "control");
        assert_eq!(
            call(chain_of(&["http://127.0.0.1:9", &good]))
                .await
                .unwrap(),
            five,
            "the first endpoint down"
        );
        assert_eq!(
            call(chain_of(&[&busy, &good])).await.unwrap(),
            five,
            "an error answer that is no revert"
        );
        assert_eq!(busy_n.load(SeqCst), 1);
        let before = good_n.load(SeqCst);
        assert!(
            matches!(
                call(chain_of(&[&rev, &good])).await,
                Err(SimError::Revert(_))
            ),
            "a revert is final"
        );
        assert_eq!(
            (rev_n.load(SeqCst), good_n.load(SeqCst)),
            (1, before),
            "the next endpoint is never asked after a revert"
        );
        assert!(
            matches!(
                call(chain_of(&["http://127.0.0.1:9", &busy])).await,
                Err(SimError::Transport(_))
            ),
            "all down"
        );
        // Fable recheck 2 P2-1: a failover endpoint behind the highest block seen answers nothing; recheck 3 R3-1: a failover
        // endpoint's revert decides nothing even at the head or with no head seen yet (a fresh `Chain`); its value is used
        let (stale, stale_n) = fake_rpc(|r| match r["method"].as_str() {
            Some("eth_blockNumber") => json!({"result": "0x10"}),
            _ => {
                json!({"error": {"code": 3, "message": "execution reverted", "data": "0xdeadbeef"}})
            }
        })
        .await;
        let (level, _) = fake_rpc(|r| match r["method"].as_str() {
            Some("eth_blockNumber") => json!({"result": "0x10"}),
            _ => json!({"result": format!("0x{:064x}", 5)}),
        })
        .await;
        let fresh = chain_of(&["http://127.0.0.1:9", &stale]);
        assert_eq!(fresh.head.load(SeqCst), 0);
        assert!(
            matches!(call(fresh).await, Err(SimError::Transport(e)) if e.contains("decides nothing")),
            "head 0: requeue"
        );
        let at_head = chain_of(&["http://127.0.0.1:9", &stale]);
        at_head.saw_block(0x10);
        assert!(
            matches!(call(at_head).await, Err(SimError::Transport(e)) if e.contains("decides nothing")),
            "at the head too"
        );
        assert!(
            matches!(call(chain_of(&[&stale])).await, Err(SimError::Revert(_))),
            "control: the first endpoint's revert is final"
        );
        // the head is shared by every `Chain` of one table: a lane's receipt refuses a stale endpoint to the venue's object
        let cfg = cfg_of(&["http://127.0.0.1:9", &level]);
        let (lane, venue) = (
            Chain::with_signer(&cfg, PrivateKeySigner::random()).unwrap(),
            Chain::with_signer(&cfg, PrivateKeySigner::random()).unwrap(),
        );
        assert_eq!(
            venue.call_raw(Address::ZERO, Bytes::new()).await.unwrap(),
            five,
            "control: at the head, its answer is used"
        );
        assert_eq!(
            (venue.failover_answers(), lane.failover_answers()),
            (1, 0),
            "R4-1: a failover answer is counted, per Chain"
        );
        assert_eq!(
            cfg.failover.load(SeqCst),
            1,
            "R5-5: and per table, for health"
        );
        let first = chain_of(&[&level]);
        first.call_raw(Address::ZERO, Bytes::new()).await.unwrap();
        assert_eq!(
            first.failover_answers(),
            0,
            "control: the first endpoint's answer is not"
        );
        assert_eq!(
            venue.head.load(SeqCst),
            0,
            "R3-2: a failover endpoint's own head raises nothing"
        );
        lane.saw_block(0x11);
        let before = stale_n.load(SeqCst);
        assert!(
            matches!(venue.call_raw(Address::ZERO, Bytes::new()).await, Err(SimError::Transport(e)) if e.contains("behind 17"))
        );
        let behind = chain_of(&["http://127.0.0.1:9", &stale]);
        behind.saw_block(0x11);
        assert!(
            matches!(call(behind).await, Err(SimError::Transport(e)) if e.contains("behind")),
            "stale: requeue, never final"
        );
        assert_eq!(stale_n.load(SeqCst) - before, 1, "only its head was read");
        let (headless, _) = fake_rpc(|r| match r["method"].as_str() {
            Some("eth_blockNumber") => {
                json!({"error": {"code": -32000, "message": "header not found"}})
            }
            _ => {
                json!({"error": {"code": 3, "message": "execution reverted", "data": "0xdeadbeef"}})
            }
        })
        .await;
        assert!(
            matches!(
                call(chain_of(&["http://127.0.0.1:9", &headless])).await,
                Err(SimError::Transport(_))
            ),
            "a failover endpoint whose head is unread answers nothing"
        );
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
                assert!(
                    matches!(c.call_raw(Address::ZERO, Bytes::new()).await, Err(SimError::Transport(e)) if e.contains("not chain 296"))
                );
            }
            assert_eq!(
                other_n.load(SeqCst),
                0,
                "nothing but its chain id and block 0 was asked"
            );
            assert_eq!(c.chain_ok[1].get(), Some(&false), "dropped, once");
        }
        // with no pinned chain_uid, block 0 is the first endpoint's; unread there: the failover endpoint is not used
        let (same, _) = fake_rpc(answer).await;
        let c = Chain::with_signer(
            &ChainCfg {
                chain_uid: None,
                ..cfg_of(&["http://127.0.0.1:9", &same])
            },
            PrivateKeySigner::random(),
        )
        .unwrap();
        assert!(
            matches!(c.call_raw(Address::ZERO, Bytes::new()).await, Err(SimError::Transport(e)) if e.contains("unreadable"))
        );
        assert_eq!(c.chain_ok[1].get(), None, "not kept");
        let (first, _) = fake_rpc(|_| json!({"error": {"code": -32000, "message": "busy"}})).await;
        let c = Chain::with_signer(
            &ChainCfg {
                chain_uid: None,
                ..cfg_of(&[&first, &same])
            },
            PrivateKeySigner::random(),
        )
        .unwrap();
        assert_eq!(
            c.call_raw(Address::ZERO, Bytes::new()).await.unwrap(),
            five,
            "the first endpoint's block 0 matches"
        );
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
        assert!(
            matches!(c.call_raw(Address::ZERO, Bytes::new()).await, Err(SimError::Transport(e)) if e.contains("chain id unreadable")),
            "unread chain id: not used"
        );
        assert_eq!(c.chain_ok[1].get(), None, "not kept");
        // a window of logs: the busy endpoint refuses the head, the good one answers the head and the logs
        let c = chain_of(&[&busy, &good]);
        let before = good_n.load(SeqCst);
        assert!(c
            .logs_since(Address::ZERO, B256::ZERO, 10)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            good_n.load(SeqCst) - before,
            3,
            "its head check, eth_blockNumber and eth_getLogs, all on the good endpoint"
        );
        assert_eq!(
            c.head.load(SeqCst),
            0,
            "R3-2: a failover endpoint's head in a log read raises nothing"
        );
        let c = chain_of(&[&good]);
        c.logs_since(Address::ZERO, B256::ZERO, 10).await.unwrap();
        assert_eq!(
            c.head.load(SeqCst),
            0x64,
            "control: the first endpoint's head does"
        );
        assert_eq!(
            c.subject_nonce(&MetaRef {
                token: Address::ZERO,
                from: B256::ZERO,
                batch: U256::ZERO,
                nonce: U256::ZERO,
                digest: None,
                ua: true,
                addr_nonce: false
            })
            .await
            .unwrap(),
            U256::from(5),
            "the subject nonce view fails over too"
        );
    }

    /// Fable recheck 7 R7-1: "not spent" read on a failover endpoint (the first down) is no verdict (`Err`, read again); "spent"
    /// there stands. Control: "not spent" from the first endpoint is `Ok(false)`.
    #[tokio::test]
    async fn an_unspent_nonce_on_a_failover_answer_is_unread() {
        let m = MetaRef {
            token: Address::ZERO,
            from: B256::ZERO,
            batch: U256::ZERO,
            nonce: U256::from(3),
            digest: None,
            ua: true,
            addr_nonce: false,
        };
        let at = |n: u64| -> fn(&Value) -> Value {
            match n {
                3 => |r| match r["method"].as_str() {
                    Some("eth_blockNumber") => json!({"result": "0x10"}),
                    _ => json!({"result": format!("0x{:064x}", 3)}),
                },
                _ => |r| match r["method"].as_str() {
                    Some("eth_blockNumber") => json!({"result": "0x10"}),
                    _ => json!({"result": format!("0x{:064x}", 4)}),
                },
            }
        };
        let (unspent, _) = fake_rpc(at(3)).await;
        let (spent, _) = fake_rpc(at(4)).await;
        assert!(
            !chain_of(&[&unspent]).nonce_spent(&m).await.unwrap(),
            "control: the first endpoint's answer"
        );
        let e = chain_of(&["http://127.0.0.1:9", &unspent])
            .nonce_spent(&m)
            .await
            .unwrap_err();
        assert!(e.to_string().starts_with("FAILOVER_ANSWER"), "{e:#}");
        assert!(
            chain_of(&["http://127.0.0.1:9", &spent])
                .nonce_spent(&m)
                .await
                .unwrap(),
            "spent on a failover endpoint stands"
        );
    }

    /// An RPC at head 12,288 whose `eth_getLogs` caps the range at `cap(request)` blocks and answers one log per accepted request,
    /// its `blockNumber` the request's `fromBlock` and its `logIndex` the span's length.
    fn capped_logs(r: &Value, cap: u64) -> Value {
        let n = |v: &Value| {
            u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
        };
        // scaas-rpc T13 point 6 (fixture correction): chain 296's identity
        if let Some(a) = identity_answer(r) {
            return a;
        }
        match r["method"].as_str() {
            Some("eth_blockNumber") => json!({"result": "0x3000"}),
            Some("eth_getLogs") => {
                let (from, to) = (
                    n(&r["params"][0]["fromBlock"]),
                    n(&r["params"][0]["toBlock"]),
                );
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

    /// Fable recheck 4 R4-3: each request of a log window has its own `rpc_timeout_ms`, not the window: an RPC that caps the range
    /// and answers each span in 400 ms reads a 10,001-block window (several spans, over a second in all) under a 1 s limit;
    /// control: a span slower than the limit fails the window over.
    #[tokio::test]
    async fn each_log_span_has_its_own_timeout() {
        async fn serve(delay: u64) -> String {
            let app = axum::Router::new().route(
                "/",
                axum::routing::post(move |axum::Json(r): axum::Json<Value>| async move {
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    let mut a = capped_logs(&r, 2_000);
                    a["jsonrpc"] = json!("2.0");
                    a["id"] = r["id"].clone();
                    axum::Json(a)
                }),
            );
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", l.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
            url
        }
        let c = |url: &str| {
            Chain::with_signer(
                &ChainCfg {
                    rpc_timeout_ms: 1_000,
                    ..cfg_of(&[url])
                },
                PrivateKeySigner::random(),
            )
            .unwrap()
        };
        let t = std::time::Instant::now();
        let logs = c(&serve(400).await)
            .logs_since(Address::ZERO, B256::ZERO, 10_000)
            .await
            .unwrap();
        assert!(
            logs.len() >= 3 && t.elapsed() > std::time::Duration::from_millis(1_200),
            "{} spans in {:?}",
            logs.len(),
            t.elapsed()
        );
        assert!(
            c(&serve(2_500).await)
                .logs_since(Address::ZERO, B256::ZERO, 10_000)
                .await
                .is_err(),
            "control: one slow request"
        );
    }

    /// Fable recheck R-6: a log window an RPC refuses whole (it caps the `eth_getLogs` range) is read in tenths, contiguous and
    /// complete; an endpoint that refuses even `LOG_SPAN_MIN` blocks fails the read over. Control: an uncapped RPC answers the
    /// window in one request.
    #[tokio::test]
    async fn a_log_window_is_chunked_for_an_rpc_that_caps_the_range() {
        let spans = |logs: Vec<alloy::rpc::types::Log>| {
            logs.iter()
                .map(|l| (l.block_number.unwrap(), l.log_index.unwrap()))
                .collect::<Vec<_>>()
        };
        let (open, _) = fake_rpc(|r| capped_logs(r, u64::MAX)).await;
        let (capped, _) = fake_rpc(|r| capped_logs(r, 1_000)).await;
        let (stingy, _) = fake_rpc(|r| capped_logs(r, 5)).await;
        let head = 0x3000u64;
        let read = |url: String| async move {
            chain_of(&[&url])
                .logs_since(Address::ZERO, B256::ZERO, 10_000)
                .await
        };
        assert_eq!(
            spans(read(open).await.unwrap()),
            vec![(head - 10_000, 10_001)],
            "control: one request"
        );
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
        assert!(
            got.len() <= 8 && got.iter().any(|x| x.1 > 1_000),
            "grows back: {got:?}"
        );
        assert!(
            read(stingy.clone()).await.is_err(),
            "a cap below LOG_SPAN_MIN gives the endpoint up"
        );
        assert!(
            chain_of(&[&stingy])
                .logs_since(Address::ZERO, B256::ZERO, 50)
                .await
                .is_err(),
            "a 51-block window: a tenth is 5, floored at LOG_SPAN_MIN, still refused"
        );
        let (capped2, _) = fake_rpc(|r| capped_logs(r, 1_000)).await;
        assert!(
            !chain_of(&[&stingy, &capped2])
                .logs_since(Address::ZERO, B256::ZERO, 10_000)
                .await
                .unwrap()
                .is_empty(),
            "and the read fails over to the next endpoint"
        );
        // Fable recheck 2 P3-3: a cap below a twentieth of the window gives the endpoint up within a few requests
        let (tight, tight_n) = fake_rpc(|r| capped_logs(r, 400)).await;
        assert!(read(tight).await.is_err());
        assert!(
            tight_n.load(std::sync::atomic::Ordering::SeqCst) <= 5,
            "head, 10,001, 1,000, 501: given up"
        );
        // a transport error (HTTP 500) never shrinks the span: one log request, then the next endpoint
        let n: std::sync::Arc<std::sync::atomic::AtomicUsize> = Default::default();
        let n2 = n.clone();
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
                let n2 = n2.clone();
                async move {
                    // scaas-rpc T13 point 6 (fixture correction): chain 296's identity
                    if let Some(a) = identity_answer(&r) {
                        return (axum::http::StatusCode::OK, axum::Json(a));
                    }
                    if r["method"] == "eth_getLogs" {
                        n2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        return (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            axum::Json(json!({})),
                        );
                    }
                    (
                        axum::http::StatusCode::OK,
                        axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": "0x3000"})),
                    )
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let down = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let (capped3, _) = fake_rpc(|r| capped_logs(r, u64::MAX)).await;
        assert_eq!(
            chain_of(&[&down, &capped3])
                .logs_since(Address::ZERO, B256::ZERO, 10_000)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            n.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "one request, then the next endpoint"
        );
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
        })
        .await;
        assert_eq!(
            chain_of(&[&good]).block_gas().await.unwrap().limit,
            30_000_000,
            "control"
        );
        let quick = |urls: &[&str], read: u64, simulate: u64| {
            Chain::with_signer(
                &ChainCfg {
                    rpc_timeout_ms: read,
                    rpc_simulate_timeout_ms: simulate,
                    ..cfg_of(urls)
                },
                PrivateKeySigner::random(),
            )
            .unwrap()
        };
        let two = quick(&[&hung_url, &good], 500, 500);
        let got = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            two.call_raw(Address::ZERO, Bytes::new()),
        )
        .await;
        assert_eq!(
            got.expect("one timeout, then the next endpoint")
                .unwrap()
                .len(),
            32
        );
        let app = axum::Router::new().route("/", axum::routing::post(|axum::Json(r): axum::Json<Value>| async move {
            // scaas-rpc T13 point 6 (fixture correction): chain 296's identity, answered at once
            if let Some(a) = identity_answer(&r) {
                return axum::Json(a);
            }
            tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
            axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": if r["method"] == "eth_estimateGas" { json!("0x5208") }
                else { json!("0x") }}))
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let slow = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let c = quick(&[&slow], 300, 10_000);
        assert_eq!(
            c.simulate(Address::ZERO, Bytes::new()).await.unwrap(),
            21_000,
            "a simulation within its own limit"
        );
        // a fresh client: no pooled connection the server may have closed meanwhile
        let t = std::time::Instant::now();
        let got = quick(&[&slow], 300, 10_000)
            .call_raw(Address::ZERO, Bytes::new())
            .await;
        assert!(
            matches!(&got, Err(SimError::Transport(_)))
                && t.elapsed() < std::time::Duration::from_millis(1_400),
            "control: a read of the same speed times out: {got:?} after {:?}",
            t.elapsed()
        );
        let (busy, _) =
            fake_rpc(|_| json!({"error": {"code": -32000, "message": "header not found"}})).await;
        assert_eq!(
            chain_of(&[&busy, &good]).block_gas().await.unwrap().limit,
            30_000_000,
            "the gas cap's read fails over"
        );
    }

    /// Fable recheck 2 P3-8: an error answer saying execution was aborted by the node's own timeout is a transport error (it fails
    /// over); an EVM revert or an execution error without data stays a revert (the controls).
    /// Recheck 3 R3-6: matched by the exact phrase, after a revert: a revert reason that says "timeout" stays a revert.
    #[tokio::test]
    async fn an_aborted_execution_is_transport() {
        let (aborted, _) = fake_rpc(
            |_| json!({"error": {"code": -32000, "message": "execution aborted (timeout = 5s)"}}),
        )
        .await;
        let (exec, _) =
            fake_rpc(|_| json!({"error": {"code": -32000, "message": "VM execution error."}}))
                .await;
        let (rev, _) =
            fake_rpc(|_| json!({"error": {"code": 3, "message": "execution reverted"}})).await;
        let (reason, _) = fake_rpc(
            |_| json!({"error": {"code": 3, "message": "execution reverted: timeout elapsed"}}),
        )
        .await;
        let (other, _) = fake_rpc(
            |_| json!({"error": {"code": -32000, "message": "execution timeout aborted"}}),
        )
        .await;
        // Fable recheck 4 R4-5: Nethermind 2.2.0's own timeout (its text; the code is not read), transport as it stands
        let (nethermind, _) = fake_rpc(|_| json!({"error": {"code": -32000, "message": "eth_call request was canceled due to enabled timeout."}})).await;
        let call =
            |u: String| async move { chain_of(&[&u]).call_raw(Address::ZERO, Bytes::new()).await };
        assert!(matches!(call(aborted).await, Err(SimError::Transport(_))));
        assert!(
            matches!(call(exec).await, Err(SimError::Revert(_))),
            "control: an execution error"
        );
        assert!(
            matches!(call(rev).await, Err(SimError::Revert(_))),
            "control: a revert"
        );
        assert!(
            matches!(call(reason).await, Err(SimError::Revert(_))),
            "a revert whose reason names a timeout"
        );
        assert!(
            matches!(call(other).await, Err(SimError::Revert(_))),
            "not the node's phrase: the EVM's"
        );
        assert!(
            matches!(call(nethermind).await, Err(SimError::Transport(_))),
            "Nethermind's own timeout"
        );
        // recheck 5 R5-6: the estimate's frame around the EVM's cancellation (from the DLLs), transport for a simulation too
        let (cancelled, _) = fake_rpc(|_| json!({"error": {"code": -32000, "message": "err: Cancellation Requested (supplied gas 100000000)"}})).await;
        assert!(
            matches!(call(cancelled.clone()).await, Err(SimError::Transport(_))),
            "the estimate's cancellation"
        );
        let c = chain_of(&[&cancelled]);
        assert!(
            matches!(
                c.simulate(Address::ZERO, Bytes::new()).await,
                Err(SimError::Transport(_))
            ),
            "the same through classify_sim"
        );
    }

    /// NODE-GW-07: the chain's `chain_uid` is its block 0 hash; a configured one that differs refuses the chain.
    #[tokio::test]
    async fn chain_uid_is_block_zero_and_a_wrong_pin_is_refused() {
        let (url, genesis) = rpc().await;
        assert_eq!(chain(&url, None).uid().await.unwrap(), genesis);
        assert_eq!(chain(&url, Some(genesis)).uid().await.unwrap(), genesis);
        assert!(chain(&url, Some(B256::repeat_byte(1))).uid().await.is_err());
        // scaas-rpc T13 S16 (coordinator's call): a pruned RPC (no block 0) is never trusted on the pin alone, and without one
        // there is no chain_uid either
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(|axum::Json(r): axum::Json<Value>| async move {
                // scaas-rpc T13 point 6 (fixture correction): chain 296's `eth_chainId`, no block
                let result = if r["method"] == "eth_chainId" {
                    json!("0x128")
                } else {
                    Value::Null
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": result}))
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pruned = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let e = chain(&pruned, Some(B256::repeat_byte(1)))
            .uid()
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("ChainIdentityUnreadable"), "{e}");
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
                // scaas-rpc T13 point 6 (fixture correction): chain 296's `eth_chainId` and a block 0
                if let Some(a) = identity_answer(&r) {
                    return axum::Json(a);
                }
                let at = r["params"][0].as_str().unwrap_or_default().to_lowercase();
                let code = if at == format!("{:#x}", Address::repeat_byte(0xc0)) { c2 } else { vec![] };
                axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": format!("0x{}", alloy::hex::encode(code))}))
            }
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let with = |url: &str, a: Option<Address>, h: Option<B256>| {
            let cfg = ChainCfg {
                evm_chain_number: 296,
                rpc_urls: vec![url.into()],
                compliance_registry: a,
                compliance_registry_codehash: h,
                ..Default::default()
            };
            Chain::with_signer(&cfg, PrivateKeySigner::random()).unwrap()
        };
        let (reg, pin) = (
            Address::repeat_byte(0xc0),
            alloy::primitives::keccak256(&code),
        );
        assert_eq!(
            with(&url, Some(reg), Some(pin))
                .compliance_registry()
                .await
                .unwrap(),
            Some(reg)
        );
        assert_eq!(
            with(&url, None, None).compliance_registry().await.unwrap(),
            None
        );
        let e = with(&url, Some(reg), Some(B256::repeat_byte(1)))
            .compliance_registry()
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("is not compliance_registry_codehash"), "{e}");
        assert!(
            with(
                &url,
                Some(Address::repeat_byte(0xc1)),
                Some(alloy::primitives::keccak256([]))
            )
            .compliance_registry()
            .await
            .is_err(),
            "no code is never the pin, even the empty code's hash"
        );
        assert!(with("http://127.0.0.1:9", Some(reg), Some(pin))
            .compliance_registry()
            .await
            .is_err());
    }

    /// An RPC answering every `eth_call` with 5 and keeping each call's input.
    async fn nonce_rpc() -> (String, std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
        let seen: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Default::default();
        let s2 = seen.clone();
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
                let s2 = s2.clone();
                async move {
                    // scaas-rpc T13 point 6 (fixture correction): chain 296's `eth_chainId` and a block 0, not kept
                    if let Some(a) = identity_answer(&r) {
                        return axum::Json(a);
                    }
                    let input = r["params"][0]["input"]
                        .as_str()
                        .or(r["params"][0]["data"].as_str())
                        .unwrap_or("0x")
                        .to_string();
                    s2.lock()
                        .unwrap()
                        .push(alloy::hex::decode(&input[2..]).unwrap());
                    axum::Json(
                        json!({"jsonrpc": "2.0", "id": r["id"], "result": format!("0x{:064x}", 5)}),
                    )
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, seen)
    }

    /// The view R80 reads for vector row `name` on `kind`: `(selector, the id word)` of the one `eth_call` made, and its answer.
    async fn nonce_view_of(name: &str, kind: &str) -> ([u8; 4], B256, U256) {
        let v = crate::typed::testkit::vectors();
        let mut op =
            crate::typed::testkit::op_of(name, kind, &v).unwrap_or_else(|| panic!("{name}"));
        if name == "UAPayUnderMandate" {
            op["envelope"]["batch"] = json!(crate::typed::mandate_pay_lane(
                &crate::typed::testkit::hex(&op["args"]["entryRef"])
            )
            .to_string());
            op["envelope"]["nonce"] = json!("0");
        }
        let m = crate::submit::work_of_op(Some(1), &op, None)
            .unwrap()
            .0
            .meta
            .unwrap_or_else(|| panic!("{name}: no lane"));
        let (url, seen) = nonce_rpc().await;
        let n = chain(&url, None).subject_nonce(&m).await.unwrap();
        let call = seen.lock().unwrap().pop().unwrap();
        assert!(seen.lock().unwrap().is_empty(), "one read");
        assert_eq!(
            call[36..68],
            m.batch.to_be_bytes::<32>(),
            "{name}: the lane"
        );
        (
            call[..4].try_into().unwrap(),
            B256::from_slice(&call[4..36]),
            n,
        )
    }

    fn cast(s: &str) -> [u8; 4] {
        alloy::primitives::keccak256(s)[..4].try_into().unwrap()
    }

    /// Plan T14, R80 by kind: the subject's nonce through `mtxNonce(bytes32 id, batch)` on a token (a merged row and an address
    /// wrap alike: one nonce map, and the token has no address view left), the router and the mandate wallet; through
    /// `mtxNonce(address, batch)` on `SmartKeyAccount`. The id is the envelope's `from`, padded for an address envelope.
    #[tokio::test]
    async fn nonce_view_by_kind() {
        let key: Address = crate::typed::testkit::vectors()["key"]["address"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let ids = cast("mtxNonce(bytes32,uint256)");
        for (name, kind) in [
            ("UAUnwrap", "token"),
            ("Wrap", "token"),
            ("UAShield", "zether"),
            ("UAPrepareAcc", "pqz"),
            ("UAGrantRole", "gov_router"),
            ("UACancelNonce", "token"),
        ] {
            assert_eq!(
                nonce_view_of(name, kind).await,
                (ids, key.into_word(), U256::from(5)),
                "{name} on {kind}"
            );
        }
        assert_eq!(
            nonce_view_of("AddKey", "account").await,
            (
                cast("mtxNonce(address,uint256)"),
                key.into_word(),
                U256::from(5)
            )
        );
        assert_eq!(
            nonce_view_of("CancelNonce", "account").await.0,
            cast("mtxNonce(address,uint256)")
        );
    }

    /// Q6: the mandate wallet is on `UAMetaTxBase`: its nonce view is `mtxNonce(bytes32)`, the delegate's payment lane too.
    #[tokio::test]
    async fn wallet_nonce_view_is_bytes32() {
        for name in [
            "UASetPayee",
            "UAExecute",
            "UAPayUnderMandate",
            "UACancelNonce",
        ] {
            assert_eq!(
                nonce_view_of(name, "wallet").await.0,
                cast("mtxNonce(bytes32,uint256)"),
                "{name}"
            );
        }
    }

    /// Fix 1 (review minor 5), ua-mtx-merge: a native id's lane is one nonce map for the merged entries (`UA…` event, R18) and
    /// the address ones left (a wrap: `MetaTransactionExecuted`), so its classification reads both executions, whichever
    /// job spent it; a derived UA's only the UA one.
    #[test]
    fn a_native_ua_subject_is_classified_on_both_paths() {
        let m = |from: B256, ua: bool| MetaRef {
            token: Address::ZERO,
            from,
            batch: U256::ZERO,
            nonce: U256::ZERO,
            digest: None,
            ua,
            addr_nonce: false,
        };
        let (ua_ev, mtx_ev) = (
            IUALedger::UAMetaTransactionExecuted::SIGNATURE_HASH,
            IToken::MetaTransactionExecuted::SIGNATURE_HASH,
        );
        let native = Address::repeat_byte(1).into_word();
        assert_eq!(executed_events(&m(native, true)), vec![ua_ev, mtx_ev]);
        assert_eq!(executed_events(&m(B256::repeat_byte(1), true)), vec![ua_ev]);
        assert_eq!(
            executed_events(&m(native, false)),
            vec![ua_ev, mtx_ev],
            "an address job's lane too"
        );
    }

    /// scaas-rpc F4 (plan T5): the lane's nonce, fee, receipt, landed-fee and final-number reads stay on the first endpoint: with
    /// it hung, each is an error (or none) and endpoint 1 is never asked. Control: a view fails over to endpoint 1.
    #[tokio::test]
    async fn the_lane_reads_stay_on_the_first_endpoint() {
        use std::sync::atomic::Ordering::SeqCst;
        let hung = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hung_url = format!("http://{}", hung.local_addr().unwrap());
        tokio::spawn(async move {
            let mut held = vec![];
            while let Ok((c, _)) = hung.accept().await {
                held.push(c);
            }
        });
        let (good, good_n) = fake_rpc(|r| match r["method"].as_str() {
            Some("eth_blockNumber") => json!({"result": "0x10"}),
            Some("eth_getTransactionCount") => json!({"result": "0x7"}),
            Some("eth_getTransactionReceipt") | Some("eth_getTransactionByHash") => {
                json!({"result": null})
            }
            _ => json!({"result": format!("0x{:064x}", 5)}),
        })
        .await;
        let c = Chain::with_signer(
            &ChainCfg {
                rpc_timeout_ms: 300,
                ..cfg_of(&[&hung_url, &good])
            },
            PrivateKeySigner::random(),
        )
        .unwrap();
        assert!(c.pending_nonce().await.is_err());
        assert!(c.nonce_at().await.is_err());
        assert!(c.fees().await.is_err());
        assert!(c
            .primary()
            .get_transaction_receipt(B256::ZERO)
            .await
            .is_err());
        assert!(c.tx_fees(B256::ZERO).await.is_err());
        assert_eq!(c.finalized_number().await.unwrap(), None);
        assert_eq!(good_n.load(SeqCst), 0, "endpoint 1 is never asked");
        assert_eq!(
            c.call_raw(Address::ZERO, Bytes::new()).await.unwrap().len(),
            32,
            "control: a view fails over"
        );
    }

    /// scaas-rpc T13 point 6: endpoint 0 is identity-checked on its reads: of another chain, it is dropped (never asked), a view
    /// fails over to endpoint 1, and the lane's first-endpoint reads fail. Control: endpoint 0 of chain 296 answers itself.
    #[tokio::test]
    async fn an_endpoint_0_of_another_chain_is_dropped() {
        use std::sync::atomic::Ordering::SeqCst;
        let f: fn(&Value) -> Value = |r| match r["method"].as_str() {
            Some("eth_getTransactionCount") => json!({"result": "0x7"}),
            _ => json!({"result": format!("0x{:064x}", 5)}),
        };
        let (other, other_n) = fake_rpc_on(f, 1, genesis()).await;
        let (good, _) = fake_rpc(f).await;
        let c = chain_of(&[&other, &good]);
        assert_eq!(
            c.call_raw(Address::ZERO, Bytes::new()).await.unwrap().len(),
            32,
            "the view fails over"
        );
        assert!(
            c.pending_nonce().await.is_err(),
            "a lane read stays on endpoint 0, dropped"
        );
        assert_eq!(other_n.load(SeqCst), 0, "endpoint 0 is never asked");
        assert_eq!(c.chain_ok[0].get(), Some(&false));
        let (same, same_n) = fake_rpc_on(f, 296, genesis()).await;
        let c = chain_of(&[&same, &good]);
        assert_eq!(c.pending_nonce().await.unwrap(), 7, "control");
        assert_eq!(same_n.load(SeqCst), 1);
    }
}
