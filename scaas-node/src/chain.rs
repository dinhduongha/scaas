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

use crate::abi::{decode_revert, IToken};
use crate::metatx::Mtx;
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

    /// `eth_call` + `eth_estimateGas` từ địa chỉ relayer.
    pub async fn simulate(&self, to: Address, data: Bytes) -> std::result::Result<u64, SimError> {
        self.simulate_from(self.address, to, data).await
    }

    /// Mô phỏng với `from` tuỳ ý (gateway mô phỏng chân DEX bằng địa chỉ DEX). The estimate is the gas limit the
    /// transaction needs, regular + state (EIP-8037); no gas field, so both calls run at the RPC's gas cap.
    pub async fn simulate_from(&self, from: Address, to: Address, data: Bytes) -> std::result::Result<u64, SimError> {
        let tx = TransactionRequest::default().with_from(from).with_to(to).with_input(data);
        self.primary().call(tx.clone()).await.map_err(|e| classify_sim(&e))?;
        self.primary().estimate_gas(tx).await.map_err(|e| classify_sim(&e))
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

    /// The gas limit of the transaction `hash` as it was sent (`eth_getTransactionByHash`); `None` if the RPC does not
    /// know it.
    pub async fn tx_gas(&self, hash: B256) -> Result<Option<u64>> {
        let t: serde_json::Value = self.primary().raw_request("eth_getTransactionByHash".into(), (hash,)).await?;
        t["gas"].as_str().map(|g| Ok(u64::from_str_radix(g.trim_start_matches("0x"), 16)?)).transpose()
    }

    /// This chain's `chain_uid`: the RPC's block 0 hash, which must equal the configured `chain_uid` when one is set
    /// (a pruned RPC without block 0 trusts the configured one). Read once; an error is not remembered.
    pub async fn uid(&self) -> Result<B256> {
        self.uid
            .get_or_try_init(|| async {
                // an RPC error is not "no block 0": nothing is cached, the next call asks again (review T4 m3)
                let genesis = self.primary().get_block_by_number(BlockNumberOrTag::Number(0)).await
                    .map_err(|e| anyhow!("chain {}: block 0: {e}", self.number))?.map(|b| b.header.hash);
                match (self.pinned_uid, genesis) {
                    (Some(p), Some(g)) if p != g => Err(anyhow!("chain {}: RPC block 0 {g:#x} is not chain_uid {p:#x}", self.number)),
                    (Some(p), _) | (None, Some(p)) => Ok(p),
                    (None, None) => Err(anyhow!("chain {}: the RPC gives no block 0 hash; set chain_uid", self.number)),
                }
            })
            .await
            .copied()
    }

    /// A view call; a revert is the contract's answer (`SimError::Revert`), anything else the transport's.
    pub async fn call_view<C: SolCall>(&self, to: Address, call: C) -> std::result::Result<C::Return, SimError> {
        let tx = TransactionRequest::default().with_to(to).with_input(call.abi_encode());
        let out = self.primary().call(tx).await.map_err(|e| classify(&e))?;
        C::abi_decode_returns(&out).map_err(|e| SimError::Revert(format!("decode: {e}")))
    }

    /// `eth_call` from the lane with exactly `gas` (sizing `mtxSettle`, `guard::settle_gas`).
    pub async fn call_with_gas(&self, to: Address, data: Bytes, gas: u64) -> std::result::Result<Bytes, SimError> {
        let tx = TransactionRequest::default().with_from(self.address).with_to(to).with_input(data).with_gas_limit(gas);
        self.primary().call(tx).await.map_err(|e| classify(&e))
    }

    /// `who` has code (a contract signer: ERC-1271, `guard::ERC1271_FLOOR`).
    pub async fn has_code(&self, who: Address) -> Result<bool> {
        Ok(!self.primary().get_code_at(who).await?.is_empty())
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
        let tx = TransactionRequest::default().with_to(to).with_input(call.abi_encode());
        Ok(C::abi_decode_returns(&self.primary().call(tx).await?)?)
    }

    /// `mtxNonce(from, batch)`: the subject's next nonce on that lane, shared by both structs (R80, CTR-MTX-15).
    pub async fn mtx_nonce(&self, token: Address, from: Address, batch: U256) -> Result<U256> {
        self.view(token, IToken::mtxNonceCall { from, batch }).await
    }

    /// `mtxDigest(m)` / `mtxTransferDigest(t)`: exactly the digest the contract emits in `MetaTransactionExecuted` (R78).
    pub async fn mtx_digest(&self, token: Address, m: Mtx) -> std::result::Result<B256, SimError> {
        match m {
            Mtx::Call(m) => self.call_view(token, IToken::mtxDigestCall { m }).await,
            Mtx::Transfer(t) => self.call_view(token, IToken::mtxTransferDigestCall { t }).await,
        }
    }

    /// `MetaTransactionExecuted` của `(from, batch, nonce)` trong `lookback` khối gần nhất ⇒ `(digest, relayer)` (§8.5).
    pub async fn meta_executed(&self, token: Address, from: Address, batch: U256, nonce: U256, lookback: u64) -> Result<Option<(B256, Address)>> {
        let latest = self.primary().get_block_number().await?;
        let filter = Filter::new()
            .address(token)
            .event_signature(IToken::MetaTransactionExecuted::SIGNATURE_HASH)
            .topic1(from.into_word())
            .topic3(B256::from(batch))
            .from_block(latest.saturating_sub(lookback))
            .to_block(latest);
        for log in self.primary().get_logs(&filter).await? {
            let Ok(e) = log.log_decode::<IToken::MetaTransactionExecuted>().map(|l| l.inner.data) else { continue };
            if e.nonce == nonce {
                return Ok(Some((e.digest, e.relayer)));
            }
        }
        Ok(None)
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
}
