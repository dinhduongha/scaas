//! Hedera HSCS qua Hedera JSON-RPC Relay (R63). Contract là Solidity (`HederaMetaToken`), tx là tx Ethereum
//! ký ECDSA từ lane (alias EVM, `m/44'/3030'/0'/0/i`), nên phần lớn đi nhờ `EvmAdapter`. Riêng Hedera:
//!
//! - **R6-1**: không mempool — tx vào đồng thuận trong vài giây hoặc bị từ chối; nonce tương lai có thể tới
//!   đồng thuận trước nonce trước nó (qua node khác) ⇒ `WRONG_NONCE`. Vì vậy Hedera chạy dưới `lane_runner`
//!   (một tx bay mỗi lane, nonce đã commit đọc trước mỗi job), không qua `submit.rs` (pipeline + thay thế).
//! - Receipt đọc thô: receipt của Relay mang `revertReason` (mã Hedera như `WRONG_NONCE`, hoặc dữ liệu revert
//!   ABI) — báo nguyên văn cho Odoo; chưa có ở mirror node ⇒ `Unknown` (runner chờ tới hạn payload).
//! - Lane phải là tài khoản Hedera đã tồn tại và có HBAR (review S22): lane số dư 0 ⇒ job về hàng đợi.
//! - Danh sách token lọc event: `params.tokens` (event của contract lạ không bao giờ gửi Odoo).
use std::sync::{Arc, RwLock};

use alloy::primitives::{Address, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use serde_json::Value;

use super::evm::EvmAdapter;
use crate::abi::decode_revert;
use crate::adapter::{Built, ChainAdapter, Family, Head, Lane, Signed, TxStatus};
use crate::chain::{Chain, SimError};
use crate::config::ChainCfg;
use crate::odoo::Job;
use crate::signer::LocalSigner;

/// 295 mainnet, 296 testnet, 297 previewnet, 298 localnet (hedera-local-node / solo).
pub const CHAIN_IDS: [u64; 4] = [295, 296, 297, 298];

pub struct HederaAdapter {
    inner: EvmAdapter,
    rpc: DynProvider,
    lane_addrs: Vec<Address>,
}

impl HederaAdapter {
    pub fn new(cfg: &ChainCfg, chains: Vec<Chain>, tokens: Arc<RwLock<Vec<Address>>>) -> Result<Self> {
        if cfg.family != "hedera" || !CHAIN_IDS.contains(&cfg.evm_chain_number) {
            bail!("chain {}: Hedera needs family=hedera and evm_chain_number 295..298", cfg.chain_key());
        }
        let url = cfg.rpc_urls.first().ok_or_else(|| anyhow!("chain {}: no rpc_urls", cfg.chain_key()))?;
        let rpc = ProviderBuilder::new().disable_recommended_fillers().connect_http(url.parse()?).erased();
        let lane_addrs = chains.iter().map(Chain::address).collect();
        Ok(Self { inner: EvmAdapter::new(cfg, chains, tokens)?, rpc, lane_addrs })
    }

    /// Từ config: một `Chain` mỗi lane (khoá secp256k1 coin 3030), token từ `params.tokens`.
    pub fn from_cfg(cfg: &ChainCfg, signers: &[LocalSigner]) -> Result<Self> {
        Self::new(cfg, Chain::connect_lanes(cfg, signers)?, Arc::new(RwLock::new(param_tokens(cfg)?)))
    }
}

/// `params.tokens = ["0x…", …]` — địa chỉ token `HederaMetaToken` mà indexer theo dõi.
pub fn param_tokens(cfg: &ChainCfg) -> Result<Vec<Address>> {
    let Some(v) = cfg.params.get("tokens") else { return Ok(vec![]) };
    v.as_array()
        .ok_or_else(|| anyhow!("params.tokens must be an array"))?
        .iter()
        .map(|t| t.as_str().ok_or_else(|| anyhow!("params.tokens: not a string"))?.parse::<Address>().map_err(Into::into))
        .collect()
}

/// Receipt thô của Relay → trạng thái. `None` = chưa có (mirror node chưa nhập). Không panic với dữ liệu lạ.
pub fn decode_receipt(rc: &Value) -> Option<TxStatus> {
    if rc.is_null() {
        return None;
    }
    let height = rc.get("blockNumber").and_then(Value::as_str).and_then(hex_u64);
    match (rc.get("status").and_then(Value::as_str).and_then(hex_u64), height) {
        (Some(1), Some(height)) => Some(TxStatus::Mined { height }),
        (Some(0), _) => Some(TxStatus::Reverted { reason: revert_reason(rc.get("revertReason")) }),
        _ => None, // receipt dở dang: coi như chưa có
    }
}

/// `revertReason` của Relay: dữ liệu revert ABI (lỗi của contract) hoặc mã Hedera ASCII hex (`WRONG_NONCE`…).
pub fn revert_reason(v: Option<&Value>) -> String {
    let Some(s) = v.and_then(Value::as_str) else { return "execution reverted".into() };
    let Ok(bytes) = alloy::hex::decode(s.strip_prefix("0x").unwrap_or(s)) else { return s.chars().take(200).collect() };
    if bytes.is_empty() {
        return "execution reverted".into();
    }
    if bytes.iter().all(|b| b.is_ascii_uppercase() || *b == b'_' || b.is_ascii_digit()) {
        return String::from_utf8_lossy(&bytes).into_owned();
    }
    decode_revert(&bytes)
}

fn hex_u64(s: &str) -> Option<u64> {
    u64::from_str_radix(s.strip_prefix("0x")?, 16).ok()
}

#[async_trait]
impl ChainAdapter for HederaAdapter {
    fn family(&self) -> Family {
        Family::Hedera
    }

    fn chain_key(&self) -> &str {
        self.inner.chain_key()
    }

    fn lanes(&self) -> &[Lane] {
        self.inner.lanes()
    }

    async fn build(&self, job: &Job, lane: usize) -> std::result::Result<Built, SimError> {
        let addr = *self.lane_addrs.get(lane).ok_or_else(|| SimError::Transport(format!("no lane {lane}")))?;
        let bal = self.rpc.get_balance(addr).await.map_err(|e| SimError::Transport(e.to_string()))?;
        if bal == U256::ZERO {
            return Err(SimError::Transport(format!("lane {addr:#x} is not a funded Hedera account")));
        }
        self.inner.build(job, lane).await
    }

    async fn sign(&self, built: Built, lane: usize, sequence: u64) -> Result<Signed> {
        self.inner.sign(built, lane, sequence).await
    }

    async fn submit(&self, signed: &Signed) -> Result<()> {
        self.inner.submit(signed).await
    }

    async fn tx_status(&self, tx_id: &str) -> Result<TxStatus> {
        let rc: Value = self.rpc.raw_request("eth_getTransactionReceipt".into(), (tx_id,)).await?;
        if let Some(st) = decode_receipt(&rc) {
            return Ok(st);
        }
        let tx: Value = self.rpc.raw_request("eth_getTransactionByHash".into(), (tx_id,)).await?;
        Ok(if tx.is_null() { TxStatus::Unknown } else { TxStatus::Pending })
    }

    async fn sequence(&self, lane: usize) -> Result<u64> {
        self.inner.sequence(lane).await
    }

    async fn final_head(&self) -> Result<Option<Head>> {
        self.inner.final_head().await
    }

    async fn block_hash(&self, height: u64) -> Result<String> {
        self.inner.block_hash(height).await
    }

    async fn events(&self, from: u64, to: u64) -> Result<Vec<Value>> {
        self.inner.events(from, to).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::B256;
    use alloy::rpc::types::{Block, Log, TransactionReceipt};
    use proptest::prelude::*;
    use serde_json::json;

    const RELAY: &str = include_str!("../../tests/vectors/hedera_testnet.json");
    const KAT: &str = include_str!("../../../smartcontracts/test/vectors/hedera_kat.json");

    fn relay() -> Value {
        serde_json::from_str(RELAY).unwrap()
    }

    /// Dữ liệu THẬT của Relay testnet (ghi 2026-10-03) phải đi qua đúng các kiểu alloy mà `EvmAdapter` dùng —
    /// nếu không, `final_head`/`events` im lặng không bao giờ báo gì.
    #[test]
    fn recorded_relay_responses_parse_with_alloy_types() {
        let v = relay();
        let b: Block = serde_json::from_value(v["block"].clone()).expect("block");
        assert_eq!(format!("{:#x}", b.header.hash), v["block"]["hash"].as_str().unwrap());
        assert_eq!(b.header.number, hex_u64(v["block"]["number"].as_str().unwrap()).unwrap());
        let rc: TransactionReceipt = serde_json::from_value(v["receipt"].clone()).expect("receipt");
        assert!(rc.status());
        let logs: Vec<Log> = serde_json::from_value(v["logs"].clone()).expect("logs");
        assert!(!logs.is_empty());
        assert!(logs.iter().all(|l| l.block_hash.is_some() && l.log_index.is_some()));
    }

    #[test]
    fn recorded_receipt_decodes() {
        let v = relay();
        let h = hex_u64(v["receipt"]["blockNumber"].as_str().unwrap()).unwrap();
        assert_eq!(decode_receipt(&v["receipt"]), Some(TxStatus::Mined { height: h }));
        assert_eq!(decode_receipt(&v["receipt_unknown"]["result"]), None);
    }

    #[test]
    fn hedera_revert_reasons() {
        let mut rc = relay()["receipt"].clone();
        rc["status"] = json!("0x0");
        rc["revertReason"] = json!("0x57524f4e475f4e4f4e4345"); // "WRONG_NONCE"
        assert_eq!(decode_receipt(&rc), Some(TxStatus::Reverted { reason: "WRONG_NONCE".into() }));
        rc["revertReason"] = json!("0x0bdf5a6b"); // MetaTxBadSignature()
        assert_eq!(decode_receipt(&rc), Some(TxStatus::Reverted { reason: "MetaTxBadSignature(MetaTxBadSignature)".into() }));
        rc.as_object_mut().unwrap().remove("revertReason");
        assert_eq!(decode_receipt(&rc), Some(TxStatus::Reverted { reason: "execution reverted".into() }));
    }

    /// Cùng vector với forge (`HederaKat.t.sol`) và Odoo (`test_hedera.py`): digest EIP-712 và chữ ký ed25519
    /// thật của tài khoản 0.0.1234567 trên đúng 32 byte đó (phép HIP-632 kiểm).
    #[test]
    fn kat_digest_and_ed25519_signature() {
        use crate::metatx::{digest, Domain, WireMetaTx};
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let k: Value = serde_json::from_str(KAT).unwrap();
        let s = |f: &str| k[f].as_str().unwrap().to_string();
        let wire: WireMetaTx = serde_json::from_value(json!({
            "from": s("from"), "to": s("to"), "value": s("value"), "data": s("data"), "batch": s("batch"),
            "nonce": s("nonce"), "validUntil": s("valid_until"), "mode": s("mode").parse::<u32>().unwrap(),
            "relayer": s("relayer"), "fee": "0", "feeRecipient": format!("{:#x}", Address::ZERO)}))
        .unwrap();
        let m = wire.to_sol().unwrap();
        let d = Domain {
            name: "Bamboo MetaToken".into(),
            version: "1".into(),
            chain_id: k["chain_id"].as_u64().unwrap(),
            verifying_contract: s("verifying_contract").parse().unwrap(),
        };
        let dg = digest(&d, &m);
        assert_eq!(dg, s("digest").parse::<B256>().unwrap());
        let pk: [u8; 32] = alloy::hex::decode(&s("ed25519_public_key")[2..]).unwrap().try_into().unwrap();
        let sig: [u8; 64] = alloy::hex::decode(&s("ed25519_signature")[2..]).unwrap().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        vk.verify(dg.as_slice(), &Signature::from_bytes(&sig)).expect("ed25519 over the digest");
        // Hedera account 0.0.1234567 ⇒ long-zero `from`.
        assert_eq!(m.from, Address::left_padding_from(&1_234_567u64.to_be_bytes()));
    }

    #[test]
    fn params_tokens() {
        let mut cfg: ChainCfg = toml::from_str(
            "family = \"hedera\"\nevm_chain_number = 296\nrpc_urls = [\"http://127.0.0.1:7546\"]\n",
        )
        .unwrap();
        assert!(param_tokens(&cfg).unwrap().is_empty());
        cfg.params.insert("tokens".into(), toml::Value::Array(vec![toml::Value::String(format!("{:#x}", Address::repeat_byte(7)))]));
        assert_eq!(param_tokens(&cfg).unwrap(), vec![Address::repeat_byte(7)]);
        cfg.params.insert("tokens".into(), toml::Value::String("0x1".into()));
        assert!(param_tokens(&cfg).is_err());
    }

    #[test]
    fn refuses_non_hedera_chain_ids() {
        let cfg: ChainCfg = toml::from_str(
            "family = \"hedera\"\nevm_chain_number = 1\nrpc_urls = [\"http://127.0.0.1:7546\"]\n",
        )
        .unwrap();
        let s = crate::signer::LocalSigner::new(crate::signer::Curve::Secp256k1, &[7u8; 32]).unwrap();
        assert!(HederaAdapter::from_cfg(&cfg, &[s]).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

        #[test]
        fn receipt_decoder_never_panics(status in ".{0,12}", block in ".{0,20}", reason in ".{0,90}",
                                         hexreason in "0x[0-9a-fA-F]{0,200}") {
            let _ = decode_receipt(&json!({"status": status, "blockNumber": block, "revertReason": reason}));
            let _ = decode_receipt(&json!({"status": "0x0", "revertReason": hexreason}));
            let _ = decode_receipt(&json!({"status": 1, "blockNumber": null}));
            let _ = decode_receipt(&json!([status]));
        }

        #[test]
        fn mined_only_with_status_one_and_a_height(n in any::<u64>()) {
            let rc = json!({"status": "0x1", "blockNumber": format!("0x{n:x}")});
            prop_assert_eq!(decode_receipt(&rc), Some(TxStatus::Mined { height: n }));
            let rc = json!({"status": "0x2", "blockNumber": format!("0x{n:x}")});
            prop_assert_eq!(decode_receipt(&rc), None);
        }
    }
}
