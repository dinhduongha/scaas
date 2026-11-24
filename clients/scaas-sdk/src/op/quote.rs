// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Submission paths and the quote (spec §13.3, CLI-SDK-09): the user reviews the payer, gas limit, maximum fee per gas and
//! maximum cost beside the operation's own fee; above the profile's caps (from the SDK's configuration, never the answering
//! endpoint) `FeeAboveCap`; a gas limit above the chain's per-transaction cap or block limit `GasAboveTxCap`; a payer that is an
//! EIP-7702 designator `PayerDelegated`.
use super::gas::{Figure, GasFrom, GasSources};
use super::prepared::{envelope, Prepared};
use super::{evm, key, sim, KeyRef, Op};
use crate::{Sdk, SdkError};
use alloy::primitives::{address, Address, Bytes, U256};
use scaas_rpc::evm::EvmPool;
use scaas_rpc::pool::{BlockChoice, ReadError};
use scaas_rpc::{EndpointFailure, FailureKind, Purpose};
use std::sync::Arc;

/// The OP Stack `GasPriceOracle` predeploy and its `getL1Fee(bytes)` (plan T38).
const GAS_PRICE_ORACLE: Address = address!("420000000000000000000000000000000000000f");
const GET_L1_FEE: [u8; 4] = [0x49, 0x94, 0x8e, 0x0e];
/// Arbitrum's `NodeInterface` (`0x…C8`) and its `gasEstimateL1Component(address,bool,bytes)` (T26 B2-1).
const NODE_INTERFACE: Address = address!("00000000000000000000000000000000000000c8");
const GAS_ESTIMATE_L1: [u8; 4] = [0x77, 0xd4, 0x88, 0xa2];

/// The `msig` kind: an `msig` signer's verify row (spec §13.3).
const MSIG: u16 = 0x0120;

/// How an operation reaches the chain (spec §13.3).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct SubmitQuote {
    /// `Gateway` or `SelfRelay`, never `Auto`
    pub path: SubmitPath,
    /// the payer's address (a self-relay): linked on chain to the subject
    pub payer: Option<String>,
    /// the self-relay transaction's gas limit (`gas`); 0 on the gateway path, where the holder sends no transaction
    pub gas_limit: u64,
    /// the bound of `gas_limit`'s regular part, with the margin (EIP-8037; controller call, owner auto-run 2026-11-19): the part
    /// held to the profile's `tx_gas_cap` (EIP-7825 caps the regular gas only), the whole `gas_limit` where the split is not
    /// known (a native send's estimate, an app's figure); 0 on the gateway path
    pub regular_gas: u64,
    /// what the operation costs in gas, with the margin, on every path (owner 2026-11-19): on a relayed path for the user and
    /// the app only, to choose the token fee; it is not sent to the gateway. `None`: unquoted (no figure anywhere)
    pub gas: Option<u64>,
    /// where `gas` came from, its base part and its verify part each (owner 2026-11-19, part 3b): the chain's measured rows,
    /// a module table, the reference table; the app's figure or a native send's estimate for both
    pub gas_from: Option<GasSources>,
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

/// A gateway takes it (NODE-GW-03 door A: a registered token's `mtx*` entries on `POST /v1/op`; a PQZ debit fits the job
/// submission's body cap, NODE-GW-08, P-T16-8).
pub(crate) fn door_a(p: &Prepared) -> bool {
    matches!(p.t.kind, "token" | "zether" | "pqz")
}

fn cap(s: &str) -> Result<U256, SdkError> {
    U256::from_str_radix(s, 10).map_err(|_| SdkError::Argument)
}

/// The caps of the SDK's configuration over a self-relay's numbers (`FeeAboveCap`).
pub(crate) fn check_caps(sdk: &Sdk, gas: u64, max_fee: u128) -> Result<U256, SdkError> {
    check_cost(sdk, gas, max_fee, U256::ZERO)
}

/// [`check_caps`] of a cost that adds the chain's L1 data fee `l1` (plan T38): `gas × max_fee + l1`.
pub(crate) fn check_cost(sdk: &Sdk, gas: u64, max_fee: u128, l1: U256) -> Result<U256, SdkError> {
    let l = &sdk.limits;
    let cost = U256::from(gas)
        .checked_mul(U256::from(max_fee))
        .and_then(|c| c.checked_add(l1))
        .ok_or(SdkError::FeeAboveCap)?;
    if gas > l.max_gas || U256::from(max_fee) > cap(&l.max_fee_per_gas)? || cost > cap(&l.max_cost)?
    {
        return Err(SdkError::FeeAboveCap);
    }
    Ok(cost)
}

/// The L1 data fee of the unsigned transaction `unsigned` on `profile`'s chain (plan T38, spec §27.3): on `L1Fee::OpStack`
/// `GasPriceOracle.getL1Fee(unsigned)` read at one block, pinned by hash, its answer exactly one `uint256` (else the endpoint's
/// `AnswerMalformed`); 0 and no read without the profile's field.
pub(crate) async fn l1_fee(
    profile: &crate::ChainProfile,
    pool: &EvmPool,
    unsigned: &[u8],
) -> Result<U256, SdkError> {
    if profile.l1_fee != Some(crate::L1Fee::OpStack) {
        return Ok(U256::ZERO);
    }
    // getL1Fee(bytes): the selector, the offset 32, the length, the bytes padded to a word
    let mut data = GET_L1_FEE.to_vec();
    data.extend_from_slice(&U256::from(32).to_be_bytes::<32>());
    data.extend_from_slice(&U256::from(unsigned.len()).to_be_bytes::<32>());
    data.extend_from_slice(unsigned);
    data.resize(data.len() + (32 - unsigned.len() % 32) % 32, 0);
    let data = Bytes::from(data);
    let a = pool
        .read_at_block(BlockChoice::Latest, Purpose::Plain, |at| {
            let data = data.clone();
            async move {
                let r = pool.call_at(&at, GAS_PRICE_ORACLE, data).await?;
                let w: [u8; 32] = r.as_ref().try_into().map_err(|_| {
                    ReadError::Failure(EndpointFailure::new(
                        at.endpoint,
                        FailureKind::AnswerMalformed,
                        "getL1Fee's answer is no uint256",
                    ))
                })?;
                Ok(U256::from_be_bytes(w))
            }
        })
        .await?;
    Ok(a.value)
}

/// The L1 component of a transaction to `to` with calldata `data` on an `InEstimate` chain (T26 B2-1): Arbitrum's
/// `NodeInterface.gasEstimateL1Component(to, false, data)` (`0x…C8`, answered by `eth_call` only) read at one block, pinned by
/// hash, its first word a `uint64` (else the endpoint's `AnswerMalformed`).
pub(crate) async fn l1_gas(pool: &EvmPool, to: Address, data: &[u8]) -> Result<u64, SdkError> {
    // gasEstimateL1Component(address,bool,bytes): to, false, the offset 96, the length, the bytes padded to a word
    let mut call = GAS_ESTIMATE_L1.to_vec();
    call.extend_from_slice(&[0u8; 12]);
    call.extend_from_slice(to.as_slice());
    call.extend_from_slice(&[0u8; 32]);
    call.extend_from_slice(&U256::from(96).to_be_bytes::<32>());
    call.extend_from_slice(&U256::from(data.len()).to_be_bytes::<32>());
    call.extend_from_slice(data);
    call.resize(call.len() + (32 - data.len() % 32) % 32, 0);
    let call = Bytes::from(call);
    let a = pool
        .read_at_block(BlockChoice::Latest, Purpose::Plain, |at| {
            let call = call.clone();
            async move {
                let r = pool.call_at(&at, NODE_INTERFACE, call).await?;
                r.get(..32)
                    .filter(|w| r.len() == 96 && w.iter().take(24).all(|b| *b == 0))
                    .and_then(|w| w.get(24..))
                    .and_then(|w| <[u8; 8]>::try_from(w).ok())
                    .map(u64::from_be_bytes)
                    .ok_or_else(|| {
                        ReadError::Failure(EndpointFailure::new(
                            at.endpoint,
                            FailureKind::AnswerMalformed,
                            "gasEstimateL1Component's answer is no (uint64, uint256, uint256)",
                        ))
                    })
            }
        })
        .await?;
    Ok(a.value)
}

/// `q` with the L1 cost of its transaction to `to` with `value` and `data` by the profile's model (plan T38; T26 B2-1):
/// `InEstimate` sets the gas limit to `gas` plus [`l1_gas`] with the margin (a native send's estimate holds it already) and
/// holds it to the chain's caps; `Linea` raises the fees to `linea_estimateGas`'s; then `max_cost` is `gas_limit × max fee`
/// + [`l1_fee`] of the unsigned transaction (`OpStack`), within the SDK's caps (`FeeAboveCap` counts it).
pub(crate) async fn with_l1(
    sdk: &Sdk,
    chain: &str,
    q: &mut SubmitQuote,
    to: Address,
    value: U256,
    data: &[u8],
) -> Result<(), SdkError> {
    let (profile, chain_id, pool) = evm(sdk, chain)?;
    let estimated = q
        .gas_from
        .as_ref()
        .is_some_and(|f| f.base == GasFrom::Estimate);
    match profile.l1_fee {
        Some(crate::L1Fee::InEstimate) if !estimated => {
            let own = q.gas.unwrap_or(q.gas_limit).min(q.gas_limit);
            let l1 = l1_gas(&pool, to, data).await?;
            q.gas_limit = own.saturating_add(super::gas::with_margin(l1));
            let block = pool.block_gas().await.map_err(sim)?;
            above_caps(&profile, q.regular_gas, q.gas_limit, block.limit)?;
        }
        Some(crate::L1Fee::Linea) => {
            let from: Address = q
                .payer
                .as_deref()
                .and_then(|a| a.parse().ok())
                .ok_or(SdkError::Argument)?;
            let l = pool
                .linea_fees(from, to, value, Bytes::from(data.to_vec()), Purpose::Plain)
                .await?;
            let up = |a: &str, b: u128| a.parse::<u128>().map(|a| a.max(b).to_string());
            q.max_fee_per_gas =
                up(&q.max_fee_per_gas, l.max_fee_per_gas).map_err(|_| SdkError::Argument)?;
            q.max_priority_fee_per_gas =
                up(&q.max_priority_fee_per_gas, l.max_priority_fee_per_gas)
                    .map_err(|_| SdkError::Argument)?;
        }
        _ => {}
    }
    let fee = q
        .max_fee_per_gas
        .parse::<u128>()
        .map_err(|_| SdkError::Argument)?;
    let unsigned =
        super::submit::evm_tx(chain_id, q, to.into_array(), value, data.to_vec())?.unsigned()?;
    let l1 = l1_fee(&profile, &pool, &unsigned).await?;
    q.max_cost = check_cost(sdk, q.gas_limit, fee, l1)?.to_string();
    Ok(())
}

/// An EIP-7702 designator: `0xef0100 ‖ address`.
pub(crate) fn delegated(code: &[u8]) -> bool {
    code.len() == 23 && code.starts_with(&[0xef, 0x01, 0x00])
}

/// The native EVM payer's address: an `evm` key, or Hedera's `hedera_ecdsa` (its EVM side, the JSON-RPC Relay: T41.evm,
/// controller call CLI-SDK-33 (49)); `Argument` for any other key (`hedera_ed25519` included: HAPI is T41.hedera's).
pub(crate) fn payer_address(sdk: &Sdk, payer: &KeyRef) -> Result<Address, SdkError> {
    let KeyRef::Native { network, .. } = payer else {
        return Err(SdkError::Argument);
    };
    if network != "evm" && network != "hedera_ecdsa" {
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
/// owner 2026-11-19, ruling B and the gas-table rulings) is the figure of the lookup ([`super::gas`]), `pinned`, with its
/// source; without one `GasUnquoted`. A native send's gas is its own estimate.
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
    pinned: Option<super::gas::Figure>,
) -> Result<SubmitQuote, SdkError> {
    let (profile, _, pool) = evm(sdk, chain)?;
    let from = payer_address(sdk, payer)?;
    // a delegated direct caller of a relayed entry reverts `CallerDelegated` after spending the gas; a native send from a
    // delegated EOA is the EOA's own transaction
    if relayed && delegated(&pool.code(from).await.map_err(sim)?) {
        return Err(SdkError::PayerDelegated);
    }
    let Figure {
        gas,
        regular,
        from: gas_from,
    } = if let Some(g) = pinned {
        g
    } else if relayed {
        return Err(SdkError::GasUnquoted);
    } else {
        // the estimate with the value sent (T13b ruling 5): a payable path's cost, a non-payable target's revert; a plain
        // transfer too (T26 B2-1: no figure in code; a chain whose estimate carries more, an L1 part or an account's creation)
        let g = pool
            .simulate_value(from, to, value, data.clone())
            .await
            .map_err(sim)?;
        Figure::whole(g, GasSources::both(GasFrom::Estimate))
    };
    let block = pool.block_gas().await.map_err(sim)?;
    above_caps(&profile, regular, gas, block.limit)?;
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
    let mut q = SubmitQuote {
        path: SubmitPath::SelfRelay {
            payer: payer.clone(),
        },
        payer: Some(format!("{from:#x}")),
        gas_limit: gas,
        regular_gas: regular,
        gas: Some(gas),
        gas_from: Some(gas_from),
        max_fee_per_gas: fees.max_fee_per_gas.to_string(),
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas.to_string(),
        max_cost: cost.to_string(),
        fee_to_relayer,
        gateways: vec![],
        tx_nonce,
        tx_type: if block.base_fee.is_some() { 2 } else { 0 },
    };
    // plan T38: the chain's L1 data fee over the unsigned transaction (none without the profile's field)
    with_l1(sdk, chain, &mut q, to, value, &data).await?;
    Ok(q)
}

/// EIP-8037 under EIP-7825 (controller call, owner auto-run 2026-11-19): a transaction's regular gas `regular` above the
/// profile's per-transaction cap, or its gas limit `gas` (regular + state) above the chain's block gas limit `block`, is
/// `GasAboveTxCap`. A gas limit above the cap is otherwise accepted: under EIP-8037 the cap holds the regular gas only.
pub(crate) fn above_caps(
    profile: &crate::ChainProfile,
    regular: u64,
    gas: u64,
    block: u64,
) -> Result<(), SdkError> {
    if profile.tx_gas_cap.is_some_and(|c| regular > c) || gas > block {
        return Err(SdkError::GasAboveTxCap);
    }
    Ok(())
}

/// The signer kind of `p`'s quote: a UA key's kind, else the native EVM key (the reference signer).
pub(crate) async fn signer_kind(sdk: &Sdk, p: &Prepared) -> Result<u16, SdkError> {
    Ok(match p.signer() {
        KeyRef::Ua { kind, .. } => kind,
        KeyRef::BlsMulti { .. } => scaas_ua::bls_multi::KIND,
        KeyRef::Native { .. } | KeyRef::Imported { .. } => super::gas::NATIVE_EVM,
        KeyRef::Msig { .. } => MSIG,
        // an imported operation's signer, as its blob names it (spec §27.5 (c))
        KeyRef::Signed { .. } => {
            p.t.signed
                .as_ref()
                .map(|(_, k)| *k)
                .ok_or(SdkError::Internal)?
        }
        KeyRef::Key { .. } => match super::key_opened(sdk, &p.signer()).await? {
            super::Key::External(row, _) => row.kind,
            _ => return Err(SdkError::Internal),
        },
    })
}

/// The amount an operation's relayer takes (a PERCENT envelope's computed fee, never its rate: P2-4); "0" without an envelope.
pub(crate) fn fee_of(name: &str, message: &serde_json::Value) -> Result<String, SdkError> {
    Ok(match envelope(message) {
        Some(_) => scaas_ua::wallet::fee_due(name, message)?,
        None => "0".to_string(),
    })
}

/// The gas figure of an operation's key `(entry, domain kind, signer kind, fresh lane)` on `profile`'s tables, with what it
/// reads of the operation (`extra`, `message`: ruling B, rulings 1-4, I1, PR A review finding 4) and its relayer `fee`, its
/// unsigned calldata `unsigned` bytes ([`super::gas::quoted`]); shared by the quote and a gateway row's self-relay `resend`
/// (PR A review, finding 2).
#[allow(clippy::too_many_arguments)]
pub(crate) fn figure(
    sdk: &Sdk,
    profile: &crate::ChainProfile,
    key: (&str, &str, u16, bool),
    extra: &serde_json::Value,
    message: &serde_json::Value,
    fee: &str,
    app: Option<u64>,
    unsigned: usize,
    members: Option<u64>,
) -> Result<Option<Figure>, SdkError> {
    let op = super::gas::OpGas {
        len: &|input| super::gas::input_len(extra, message, input),
        // I1: the count a per-item part names; a group signer's n (bls-multi plan Task 17: `members`, from its key data)
        count: &|item| match (item, members) {
            ("members", Some(n)) => Some(n),
            _ => super::gas::item_count(extra, message, item),
        },
        // ruling 1: the record saved (`PayMeta.save`)
        saves: extra
            .get("meta")
            .is_some_and(|m| scaas_ua::wallet::entries::pay_meta_of(m).is_ok_and(|m| m.save)),
        // ruling 3: a fee > 0 (the amount the relayer takes)
        fee: fee.bytes().any(|b| b != b'0'),
        // ruling 4: the second signature attached
        attached: super::gas::attached_kind(extra, message),
        // PR A review, finding 4: a third party's derived holder debited
        holder: super::gas::holder_derived(key.0, message),
        // CTR-UA-65: the verify rows of the registry the operation's contract binds (the profile's)
        registry: profile.registry.as_deref(),
    };
    super::gas::quoted(
        &profile.gas,
        &profile.gas_opt_in,
        &sdk.gas_tables,
        app,
        key,
        unsigned,
        &op,
    )
}

/// A self-relay quote `q` of an operation on `chain` by a signer of kind `signer`, whose unsigned calldata is `unsigned` bytes,
/// once signed into the calldata `signed` to `to` (owner 2026-11-19, G3 at `submit`, Q5 at a gateway operation's self-relay
/// `resend`, from the row's stored signed calldata): its gas recomputed from the real signature's length, never below `q`'s
/// (`q` itself when nothing grew); above `Limits::max_gas` `SignedGasAboveCap`, above the profile's per-transaction cap or the
/// chain's block gas limit `GasAboveTxCap` (PR A review, finding 3: as `self_relay` checks it), a cost above the caps
/// `FeeAboveCap`. `own`: the operation's own figure where the caller recomputed it (a gateway row's `resend`, PR A review
/// finding 2): the larger of it and `q`'s is the base, so a quote of another entry, kind or lane state never lowers it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn signed_quote(
    sdk: &Sdk,
    chain: &str,
    signer: u16,
    unsigned: usize,
    q: &SubmitQuote,
    to: Address,
    signed: &[u8],
    own: Option<Figure>,
) -> Result<SubmitQuote, SdkError> {
    let calldata = signed;
    let signed = calldata.len();
    let c = sdk
        .chains
        .iter()
        .find(|c| c.profile.key == chain)
        .ok_or(SdkError::ChainUnknown)?;
    // M17 (review 2026-11-20): the caller's quote never lowers the regular bound either: a quote naming no regular part (0)
    // is read as whole, and the operation's own bound (`own`) is the floor
    let q_regular = match q.regular_gas {
        0 => q.gas_limit,
        r => r,
    };
    let own_regular = own.as_ref().map_or(0, |f| f.regular);
    let (base, base_regular, gas_from) = match own {
        Some(f) if f.gas > q.gas_limit => (f.gas, f.regular.max(q_regular), Some(f.from)),
        // the quote's own figure (`gas`): its gas limit less an L1 component (`InEstimate`), which `with_l1` adds again
        _ => (
            q.gas.unwrap_or(q.gas_limit).min(q.gas_limit),
            q_regular.max(own_regular),
            q.gas_from.clone(),
        ),
    };
    let base_regular = base_regular.min(base);
    let counted = super::gas::counted_bytes(
        &c.profile.gas,
        &c.profile.gas_opt_in,
        &sdk.gas_tables,
        signer,
        c.profile.registry.as_deref(),
        gas_from.as_ref(),
        unsigned,
    );
    let per_byte = super::gas::tx_gas(&c.profile.gas, &c.profile.gas_opt_in, &sdk.gas_tables)
        .ok_or(SdkError::GasUnquoted)?
        .per_byte;
    let gas = super::gas::signed_gas(base, counted, signed, per_byte);
    if gas > sdk.limits.max_gas {
        return Err(SdkError::SignedGasAboveCap);
    }
    // the signature's growth is calldata: regular gas
    let regular = base_regular.saturating_add(gas.saturating_sub(base));
    // the caps held whether or not anything grew (M17)
    let (_, _, pool) = evm(sdk, chain)?;
    let block = pool.block_gas().await.map_err(sim)?;
    above_caps(&c.profile, regular, gas, block.limit)?;
    // an L1 data fee is of the signed calldata (plan T38): read again even when the gas did not move
    if gas == q.gas_limit && regular == q.regular_gas && c.profile.l1_fee.is_none() {
        return Ok(q.clone());
    }
    let mut out = SubmitQuote {
        gas_limit: gas,
        regular_gas: regular,
        gas: Some(gas),
        gas_from,
        ..q.clone()
    };
    with_l1(sdk, chain, &mut out, to, U256::ZERO, calldata).await?;
    Ok(out)
}

pub(crate) use crate::wallet::families::{check_gateways, kept_gateways};

impl Op {
    /// The quote of `prepared` on `path` (spec §13.3). `PreparedUnknown`, `PreparedStale` (expired or its lane nonce moved),
    /// `SubmitPathNone`, `PayerDelegated`, `GasUnquoted` (a self-relay with no gas figure for the operation's key; a gateway
    /// quote reports `gas: None` instead), `GasCountUnknown` (a row of the operation's key grows with a count the SDK cannot
    /// read from it, on every path; owner 2026-11-19, I1), `GasAboveTxCap`, `FeeAboveCap`.
    pub async fn quote(
        &self,
        prepared: Arc<Prepared>,
        path: SubmitPath,
    ) -> Result<SubmitQuote, SdkError> {
        self.quote_inner(prepared, path, None).await
    }

    /// [`Op::quote`] with the app's own gas figure for the operation (execution gas, one total for base and verify), used only
    /// when the tables lack its base or its verify row (owner 2026-11-19); the quote names it `App` for both. For
    /// `mtxExecute` (owner 2026-11-19, ruling 5) the figure is instead its inner call's, added to the wallet's rows (never a
    /// total; without the rows the operation is unquoted, and `quote` without a figure leaves it unquoted: a self-relay is
    /// `GasUnquoted`, a relayed quote reports `gas: None`). A figure above `Limits::max_gas` is `FeeAboveCap`.
    pub async fn quote_with_gas(
        &self,
        prepared: Arc<Prepared>,
        path: SubmitPath,
        gas: u64,
    ) -> Result<SubmitQuote, SdkError> {
        if gas > self.sdk.limits.max_gas {
            return Err(SdkError::FeeAboveCap);
        }
        self.quote_inner(prepared, path, Some(gas)).await
    }

    async fn quote_inner(
        &self,
        prepared: Arc<Prepared>,
        path: SubmitPath,
        app: Option<u64>,
    ) -> Result<SubmitQuote, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                Op::known(&sdk, &prepared)?;
                super::submit::fresh(&sdk, &prepared).await?;
                // the amount the relayer takes (a PERCENT envelope's computed fee, never its rate: P2-4)
                let fee = fee_of(prepared.t.name, &prepared.t.message)?;
                let chain = sdk
                    .chains
                    .iter()
                    .find(|c| c.profile.key == prepared.chain())
                    .ok_or(SdkError::ChainUnknown)?;
                let gateways = chain.gateways.as_ref().map_or(0, |g| g.len());
                // no signature here (ruling 1): the gas figure of the operation's key (ruling B, the gas-table rulings), on
                // every path
                let unsigned = super::submit::unsigned(&prepared)?;
                let signer = signer_kind(&sdk, &prepared).await?;
                let fresh = prepared
                    .t
                    .lane
                    .as_ref()
                    .is_some_and(|(_, _, n)| n.is_zero());
                let entry = prepared.entry();
                // a group signer's n (plan Task 17): `members`, read from its key data
                let members = super::bls_multi::members(&prepared.signer());
                let figure = figure(
                    &sdk,
                    &chain.profile,
                    (&entry, prepared.t.kind, signer, fresh),
                    &prepared.t.extra,
                    &prepared.t.message,
                    &fee,
                    app,
                    unsigned.calldata.len(),
                    members,
                )?;
                let gateway = || SubmitQuote {
                    path: SubmitPath::Gateway,
                    payer: None,
                    gas_limit: 0,
                    regular_gas: 0,
                    gas: figure.as_ref().map(|f| f.gas),
                    gas_from: figure.as_ref().map(|f| f.from.clone()),
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
                        let kept = check_gateways(&sdk, &prepared.chain()).await?;
                        return Ok(SubmitQuote {
                            gateways: kept,
                            ..gateway()
                        });
                    }
                    SubmitPath::Gateway => return Err(SdkError::SubmitPathNone),
                    SubmitPath::Auto { payer: None } => return Err(SdkError::SubmitPathNone),
                    SubmitPath::Auto { payer: Some(p) } | SubmitPath::SelfRelay { payer: p } => p,
                };
                self_relay(
                    &sdk,
                    &prepared.chain(),
                    &payer,
                    Address::from(prepared.t.entry_contract()),
                    U256::ZERO,
                    Bytes::from(unsigned.calldata),
                    fee,
                    true,
                    figure,
                )
                .await
            })
            .await
    }
}
