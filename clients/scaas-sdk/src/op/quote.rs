// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Submission paths and the quote (spec §13.3, CLI-SDK-09): the user reviews the payer, gas limit, maximum fee per gas and
//! maximum cost beside the operation's own fee; above the profile's caps (from the SDK's configuration, never the answering
//! endpoint) `FeeAboveCap`; a gas limit above the chain's per-transaction cap or block limit `GasAboveTxCap`; a payer that is an
//! EIP-7702 designator `PayerDelegated`.
use super::prepared::{envelope, Prepared};
use super::{evm, key, sim, KeyRef, Op};
use crate::{Sdk, SdkError};
use alloy::primitives::{Address, Bytes, U256};
use scaas_rpc::Purpose;
use std::sync::Arc;

/// How an operation reaches the chain (spec §13.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitPath {
    /// a gateway when the profile has one and the entry is one a gateway takes (door A), else a self-relay by `payer` when
    /// given, else `SubmitPathNone`
    Auto { payer: Option<KeyRef> },
    /// the profile's gateways, the same body to each
    Gateway,
    /// an EIP-1559 transaction from the holder's own native EVM key, which pays the gas
    SelfRelay { payer: KeyRef },
}

/// A quote the user confirms (spec §13.3); `submit` takes exactly it. Amounts are decimal strings of wei.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitQuote {
    /// `Gateway` or `SelfRelay`, never `Auto`
    pub path: SubmitPath,
    /// the payer's address (a self-relay): linked on chain to the subject
    pub payer: Option<String>,
    pub gas_limit: u64,
    pub max_fee_per_gas: String,
    pub max_priority_fee_per_gas: String,
    pub max_cost: String,
    /// the operation's own fee to its relayer, as signed
    pub fee_to_relayer: String,
    /// the gateways the body goes to, by index in the profile's list
    pub gateways: Vec<u32>,
    /// the payer's transaction nonce
    pub tx_nonce: u64,
    /// a self-relay's EIP-2718 type: 2 where the chain's head has a base fee, else 0 (owner 2026-11-18, ruling 3)
    pub tx_type: u8,
}

/// A gateway takes it (NODE-GW-03 door A: a registered token's `mtx*` entries on `POST /v1/op`).
pub(crate) fn door_a(p: &Prepared) -> bool {
    matches!(p.t.kind, "token" | "zether" | "pqz")
}

fn cap(s: &str) -> Result<U256, SdkError> {
    U256::from_str_radix(s, 10).map_err(|_| SdkError::Argument)
}

/// The caps of the SDK's configuration over a self-relay's numbers (`FeeAboveCap`).
pub(crate) fn check_caps(sdk: &Sdk, gas: u64, max_fee: u128) -> Result<U256, SdkError> {
    let l = &sdk.limits;
    let cost = U256::from(gas)
        .checked_mul(U256::from(max_fee))
        .ok_or(SdkError::FeeAboveCap)?;
    if gas > l.max_gas || U256::from(max_fee) > cap(&l.max_fee_per_gas)? || cost > cap(&l.max_cost)?
    {
        return Err(SdkError::FeeAboveCap);
    }
    Ok(cost)
}

/// An EIP-7702 designator: `0xef0100 ‖ address`.
pub(crate) fn delegated(code: &[u8]) -> bool {
    code.len() == 23 && code.starts_with(&[0xef, 0x01, 0x00])
}

/// The native EVM payer's address (`Argument` for any other key).
pub(crate) fn payer_address(sdk: &Sdk, payer: &KeyRef) -> Result<Address, SdkError> {
    let KeyRef::Native { network, .. } = payer else {
        return Err(SdkError::Argument);
    };
    if network != "evm" {
        return Err(SdkError::Argument);
    }
    let super::Key::Native(_, k) = key(sdk, payer)? else {
        return Err(SdkError::Argument);
    };
    k.address()
        .and_then(|a| a.parse().ok())
        .ok_or(SdkError::Argument)
}

/// A self-relay's quote for `to` and `data` from `payer`: the code check, the gas, the chain's caps, the fees and the SDK's
/// caps, the payer's nonce. The gas of a relayed operation (owner 2026-11-18, ruling 1: a quote never makes a signature;
/// owner 2026-11-19, ruling B) is the gas table's figure for its key ([`super::gas`]), `pinned`; without one `GasUnquoted`.
/// A native send's gas is its own estimate.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn self_relay(
    sdk: &Sdk,
    chain: &str,
    payer: &KeyRef,
    to: Address,
    value: U256,
    data: Bytes,
    fee_to_relayer: String,
    relayed: bool,
    pinned: Option<u64>,
) -> Result<SubmitQuote, SdkError> {
    let (profile, _, pool) = evm(sdk, chain)?;
    let from = payer_address(sdk, payer)?;
    // a delegated direct caller of a relayed entry reverts `CallerDelegated` after spending the gas; a native send from a
    // delegated EOA is the EOA's own transaction
    if relayed && delegated(&pool.code(from).await.map_err(sim)?) {
        return Err(SdkError::PayerDelegated);
    }
    let gas = if let Some(g) = pinned {
        g
    } else if relayed {
        return Err(SdkError::GasUnquoted);
    } else if data.is_empty() && pool.code(to).await.map_err(sim)?.is_empty() {
        21_000 // a plain transfer to an account without code
    } else {
        // the estimate with the value sent (T13b ruling 5): a payable path's cost, a non-payable target's revert
        pool.simulate_value(from, to, value, data)
            .await
            .map_err(sim)?
    };
    let block = pool.block_gas().await.map_err(sim)?;
    if profile.tx_gas_cap.is_some_and(|c| gas > c) || gas > block.limit {
        return Err(SdkError::GasAboveTxCap);
    }
    let fees = pool.fees(Purpose::Plain).await?;
    let cost = check_caps(sdk, gas, fees.max_fee_per_gas)?;
    // the endpoints' nonce (under `strict_majority` the agreed committed one), never below what this session signed since
    // (closing review P3; rpc F14): two self-relays from one payer before the first lands take two nonces
    let floor = sdk
        .sent_nonces
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&(chain.to_string(), format!("{from:#x}")))
        .copied()
        .unwrap_or(0);
    let tx_nonce = pool.pending_nonce(from, Purpose::Plain).await?.max(floor);
    Ok(SubmitQuote {
        path: SubmitPath::SelfRelay {
            payer: payer.clone(),
        },
        payer: Some(format!("{from:#x}")),
        gas_limit: gas,
        max_fee_per_gas: fees.max_fee_per_gas.to_string(),
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas.to_string(),
        max_cost: cost.to_string(),
        fee_to_relayer,
        gateways: vec![],
        tx_nonce,
        tx_type: if block.base_fee.is_some() { 2 } else { 0 },
    })
}

/// Every gateway of `chain` announces the profile's `chain_uid` for its chain id (`GET /v1/gateway`; NODE-GW-05), else
/// `ProfileMismatch` and none is used (spec §8; a gateway that announces none is refused too).
pub(crate) async fn check_gateways(sdk: &Sdk, chain: &str) -> Result<(), SdkError> {
    let c = sdk
        .chains
        .iter()
        .find(|c| c.profile.key == chain)
        .ok_or(SdkError::ChainUnknown)?;
    let (Some(list), Some(id)) = (c.gateways.clone(), c.profile.chain_id) else {
        return Err(SdkError::SubmitPathNone);
    };
    let client = scaas_rpc::node::NodeClient::new(list)?;
    for i in 0..client.list().len() {
        let v = client.gateway_at(i).await?;
        let ok = v
            .get("chains")
            .and_then(|c| c.as_array())
            .is_some_and(|cs| {
                cs.iter().any(|x| {
                    x.get("chain").and_then(|n| n.as_u64()) == Some(id)
                        && x.get("chain_uid")
                            .and_then(|u| u.as_str())
                            .is_some_and(|u| u.eq_ignore_ascii_case(&c.profile.chain_uid))
                })
            });
        if !ok {
            return Err(SdkError::ProfileMismatch);
        }
    }
    Ok(())
}

impl Op {
    /// The quote of `prepared` on `path` (spec §13.3). `PreparedUnknown`, `PreparedStale` (expired or its lane nonce moved),
    /// `SubmitPathNone`, `PayerDelegated`, `GasUnquoted` (no gas row for the operation's key), `GasAboveTxCap`, `FeeAboveCap`.
    pub async fn quote(
        &self,
        prepared: Arc<Prepared>,
        path: SubmitPath,
    ) -> Result<SubmitQuote, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                Op::known(&sdk, &prepared)?;
                super::submit::fresh(&sdk, &prepared).await?;
                // the amount the relayer takes (a PERCENT envelope's computed fee, never its rate: P2-4)
                let fee = match envelope(&prepared.t.message) {
                    Some(_) => scaas_ua::wallet::fee_due(prepared.t.name, &prepared.t.message)?,
                    None => "0".to_string(),
                };
                let gateways = sdk
                    .chains
                    .iter()
                    .find(|c| c.profile.key == prepared.chain())
                    .and_then(|c| c.gateways.as_ref())
                    .map_or(0, |g| g.len());
                let gateway = || SubmitQuote {
                    path: SubmitPath::Gateway,
                    payer: None,
                    gas_limit: 0,
                    max_fee_per_gas: "0".into(),
                    max_priority_fee_per_gas: "0".into(),
                    max_cost: "0".into(),
                    fee_to_relayer: fee.clone(),
                    gateways: (0..gateways as u32).collect(),
                    tx_nonce: 0,
                    tx_type: 0,
                };
                let payer = match path {
                    SubmitPath::Gateway | SubmitPath::Auto { .. }
                        if gateways > 0 && door_a(&prepared) =>
                    {
                        check_gateways(&sdk, &prepared.chain()).await?;
                        return Ok(gateway());
                    }
                    SubmitPath::Gateway => return Err(SdkError::SubmitPathNone),
                    SubmitPath::Auto { payer: None } => return Err(SdkError::SubmitPathNone),
                    SubmitPath::Auto { payer: Some(p) } | SubmitPath::SelfRelay { payer: p } => p,
                };
                // no signature here (ruling 1): the gas table's figure for the operation's key (ruling B)
                let unsigned = super::submit::unsigned(&prepared)?;
                let signer = match prepared.signer() {
                    KeyRef::Ua { kind, .. } => kind,
                    KeyRef::Native { .. } | KeyRef::Imported { .. } => super::gas::NATIVE_EVM,
                };
                let fresh = prepared
                    .t
                    .lane
                    .as_ref()
                    .is_some_and(|(_, _, n)| n.is_zero());
                let (profile, _, _) = evm(&sdk, &prepared.chain())?;
                let pinned = super::gas::quoted(
                    &profile.gas,
                    &prepared.entry(),
                    prepared.t.kind,
                    signer,
                    fresh,
                    unsigned.calldata.len(),
                );
                self_relay(
                    &sdk,
                    &prepared.chain(),
                    &payer,
                    Address::from(prepared.t.contract),
                    U256::ZERO,
                    Bytes::from(unsigned.calldata),
                    fee,
                    true,
                    pinned,
                )
                .await
            })
            .await
    }
}
