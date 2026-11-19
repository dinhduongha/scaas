// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Hedera through its JSON-RPC Relay (spec §5.3, plan T14): the EVM transport and pool ([`EvmPool`]), plus the Relay's reads the
//! EVM types do not carry. Its receipt carries `revertReason` (a Hedera status such as `WRONG_NONCE` in ASCII hex, or ABI revert
//! data), so the receipt is read raw; the caller keeps the Hedera status classes. Every read here is the first endpoint's (F3).
use crate::evm::{first_err, EvmPool};
use crate::RpcError;
use alloy::primitives::B256;
use alloy::providers::Provider;
use serde_json::Value;

impl EvmPool {
    /// The Relay's receipt of `hash` as sent (`null`: none yet), from endpoint 0.
    pub async fn first_relay_receipt(&self, hash: B256) -> Result<Value, RpcError> {
        self.first_provider()
            .await?
            .raw_request("eth_getTransactionReceipt".into(), (hash,))
            .await
            .map_err(|e| first_err(&e))
    }

    /// Whether endpoint 0 knows transaction `hash`.
    pub async fn first_tx_known(&self, hash: B256) -> Result<bool, RpcError> {
        let tx: Value = self
            .first_provider()
            .await?
            .raw_request("eth_getTransactionByHash".into(), (hash,))
            .await
            .map_err(|e| first_err(&e))?;
        Ok(!tx.is_null())
    }

    /// `eth_gasPrice` from endpoint 0 (Hedera's gas price is fixed by its fee schedule).
    pub async fn first_gas_price(&self) -> Result<u128, RpcError> {
        self.first_provider()
            .await?
            .get_gas_price()
            .await
            .map_err(|e| first_err(&e))
    }
}
