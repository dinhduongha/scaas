// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Submission paths and the quote (spec §13.3, CLI-SDK-09): the user reviews the payer, gas limit, maximum fee per gas and
//! maximum cost beside the operation's own fee; above the profile's caps (from the SDK's configuration, never the answering
//! endpoint) `FeeAboveCap`; a gas limit above the chain's per-transaction cap or block limit `GasAboveTxCap`; a payer that is an
//! EIP-7702 designator `PayerDelegated`.
use super::gas::{Figure, GasFrom, GasSources};
use super::prepared::{envelope, Prepared};
use super::{evm, key, sim, KeyRef, Op};
use crate::{Sdk, SdkError};
use alloy::primitives::{Address, Bytes, U256};
use scaas_rpc::Purpose;
use std::sync::Arc;

/// The `msig` kind: an `msig` signer's verify row (spec §13.3).
const MSIG: u16 = 0x0120;

/// How an operation reaches the chain (spec §13.3).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
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
    } else if data.is_empty() && pool.code(to).await.map_err(sim)?.is_empty() {
        Figure::whole(21_000, GasSources::both(GasFrom::Estimate)) // a plain transfer to an account without code
    } else {
        // the estimate with the value sent (T13b ruling 5): a payable path's cost, a non-payable target's revert
        let g = pool
            .simulate_value(from, to, value, data)
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
    Ok(SubmitQuote {
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
    })
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
/// once signed into `signed` calldata bytes (owner 2026-11-19, G3 at `submit`, Q5 at a gateway operation's self-relay
/// `resend`, from the row's stored signed calldata): its gas recomputed from the real signature's length, never below `q`'s
/// (`q` itself when nothing grew); above `Limits::max_gas` `SignedGasAboveCap`, above the profile's per-transaction cap or the
/// chain's block gas limit `GasAboveTxCap` (PR A review, finding 3: as `self_relay` checks it), a cost above the caps
/// `FeeAboveCap`. `own`: the operation's own figure where the caller recomputed it (a gateway row's `resend`, PR A review
/// finding 2): the larger of it and `q`'s is the base, so a quote of another entry, kind or lane state never lowers it.
pub(crate) async fn signed_quote(
    sdk: &Sdk,
    chain: &str,
    signer: u16,
    unsigned: usize,
    q: &SubmitQuote,
    signed: usize,
    own: Option<Figure>,
) -> Result<SubmitQuote, SdkError> {
    let c = sdk
        .chains
        .iter()
        .find(|c| c.profile.key == chain)
        .ok_or(SdkError::ChainUnknown)?;
    let (base, base_regular, gas_from) = match own {
        Some(f) if f.gas > q.gas_limit => (f.gas, f.regular, Some(f.from)),
        _ => (q.gas_limit, q.regular_gas, q.gas_from.clone()),
    };
    let counted = super::gas::counted_bytes(
        &c.profile.gas,
        &c.profile.gas_opt_in,
        &sdk.gas_tables,
        signer,
        gas_from.as_ref(),
        unsigned,
    );
    let gas = super::gas::signed_gas(base, counted, signed);
    if gas == q.gas_limit {
        return Ok(q.clone());
    }
    if gas > sdk.limits.max_gas {
        return Err(SdkError::SignedGasAboveCap);
    }
    let (_, _, pool) = evm(sdk, chain)?;
    let block = pool.block_gas().await.map_err(sim)?;
    // the signature's growth is calldata: regular gas
    let regular = base_regular.saturating_add(gas.saturating_sub(base));
    above_caps(&c.profile, regular, gas, block.limit)?;
    let fee = q
        .max_fee_per_gas
        .parse::<u128>()
        .map_err(|_| SdkError::Argument)?;
    let cost = check_caps(sdk, gas, fee)?;
    Ok(SubmitQuote {
        gas_limit: gas,
        regular_gas: regular,
        gas: Some(gas),
        gas_from,
        max_cost: cost.to_string(),
        ..q.clone()
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
                        check_gateways(&sdk, &prepared.chain()).await?;
                        return Ok(gateway());
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
