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

use crate::abi::{decode_revert, IToken, IUALedger};
use crate::metatx::{Mtx, UaMtx};
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

    /// `who` is a contract signer (ERC-1271, `guard::erc1271_floor`): `is_contract` of its code, so an EIP-7702
    /// designator (an EOA, ECDSA only) is not.
    pub async fn is_contract_at(&self, who: Address) -> Result<bool> {
        Ok(is_contract(&self.primary().get_code_at(who).await?))
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

    /// The subject's next nonce on its lane (R80): `mtxNonce(from, batch)`, shared by both structs (CTR-MTX-15), or
    /// for a `ua_metatx` job `uaNonce(id, batch)` (the one nonce map, CTR-UA-26).
    pub async fn subject_nonce(&self, m: &MetaRef) -> Result<U256> {
        if m.ua {
            return self.view(m.token, IUALedger::uaNonceCall { ua: m.from, batch: m.batch }).await;
        }
        self.view(m.token, IToken::mtxNonceCall { from: Address::from_word(m.from), batch: m.batch }).await
    }

    /// `mtxDigest(m)` / `mtxTransferDigest(t)`: exactly the digest the contract emits in `MetaTransactionExecuted` (R78).
    pub async fn mtx_digest(&self, token: Address, m: Mtx) -> std::result::Result<B256, SimError> {
        match m {
            Mtx::Call(m) => self.call_view(token, IToken::mtxDigestCall { m }).await,
            Mtx::Transfer(t) => self.call_view(token, IToken::mtxTransferDigestCall { t }).await,
        }
    }

    /// `uaDigest(m)` / `uaTransferDigest(t)`: the digest of `UAMetaTransactionExecuted`.
    pub async fn ua_digest(&self, token: Address, m: UaMtx) -> std::result::Result<B256, SimError> {
        match m {
            UaMtx::Call(m) => self.call_view(token, IUALedger::uaDigestCall { m }).await,
            UaMtx::Transfer(t) => self.call_view(token, IUALedger::uaTransferDigestCall { t }).await,
        }
    }

    /// The token's digest of a relayed `mtxExecute*` / `mtxPayMeta` or `uaExecute*` / `uaPayMeta` calldata; `None` for
    /// any other call.
    pub async fn digest_of(&self, token: Address, data: &[u8]) -> Option<std::result::Result<B256, SimError>> {
        if let Some((m, _)) = Mtx::from_calldata(data) {
            return Some(self.mtx_digest(token, m).await);
        }
        Some(self.ua_digest(token, UaMtx::from_calldata(data)?.0).await)
    }

/// `MetaTransactionExecuted` (a UA subject: `UAMetaTransactionExecuted`) of `(from, batch, nonce)` trong `lookback`
    /// khối gần nhất ⇒ `(digest, relayer)` (§8.5). Both events index `from`, `relayer`, `batch` alike.
    pub async fn meta_executed(&self, m: &MetaRef, lookback: u64) -> Result<Option<(B256, Address)>> {
        let latest = self.primary().get_block_number().await?;
        let filter = Filter::new()
            .address(m.token)
            .event_signature(executed_events(m))
            .topic1(m.from)
            .topic3(B256::from(m.batch))
            .from_block(latest.saturating_sub(lookback))
            .to_block(latest);
        for log in self.primary().get_logs(&filter).await? {
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

/// The executions that spend `m`'s nonce: the address path's, the UA ledger's, or both for a native-id UA (one nonce
/// map, `uaNonce(pad(a), b) == mtxNonce(a, b)`).
pub fn executed_events(m: &MetaRef) -> Vec<B256> {
    let (ua, mtx) = (IUALedger::UAMetaTransactionExecuted::SIGNATURE_HASH, IToken::MetaTransactionExecuted::SIGNATURE_HASH);
    match (m.ua, crate::metatx::native(&m.from).is_some()) {
        (true, true) => vec![ua, mtx],
        (true, false) => vec![ua],
        (false, _) => vec![mtx],
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

    /// Fix 1 (review minor 5): a native-id UA job shares its nonce map with the address path, so its classification
    /// reads both executions; a derived UA's only the UA one; an address job only the address one.
    #[test]
    fn a_native_ua_subject_is_classified_on_both_paths() {
        let m = |from: B256, ua: bool| MetaRef { token: Address::ZERO, from, batch: U256::ZERO, nonce: U256::ZERO, digest: None, ua };
        let (ua_ev, mtx_ev) = (IUALedger::UAMetaTransactionExecuted::SIGNATURE_HASH, IToken::MetaTransactionExecuted::SIGNATURE_HASH);
        let native = Address::repeat_byte(1).into_word();
        assert_eq!(executed_events(&m(native, true)), vec![ua_ev, mtx_ev]);
        assert_eq!(executed_events(&m(B256::repeat_byte(1), true)), vec![ua_ev]);
        assert_eq!(executed_events(&m(native, false)), vec![mtx_ev]);
    }
}
