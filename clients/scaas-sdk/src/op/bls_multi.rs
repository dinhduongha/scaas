// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `bls12381-multi` (`0x0121`) in the SDK (spec 2026-11-19-bls12381-multi §5.4, §8.4; plan Task 17). A group is a signer
//! [`KeyRef::BlsMulti`]: one member key of an open seed and the group's key data `d`; its operations are prepared as any
//! other (`from` the group's UA). Each member signs its partial of the prepared operation under the operation's check
//! ([`Op::bls_multi_part`]; a member on another device prepares the same request, the same named fields and `validUntil`,
//! and gets the same digest); the coordinator checks each partial on receipt ([`Op::bls_multi_part_ok`], naming a bad one),
//! then [`Op::submit_bls_multi`] aggregates (minimal unless the caller asks for surplus, N6), dropping invalid partials, and
//! submits with the `UASig` by name (`{signature, signers}`; the 160-byte object only in the calldata). Registration: each
//! member's PoP part ([`Op::bls_multi_pop_part`]), the quote as a function of n ([`Op::quote_register_bls_multi`]), and
//! `registerBlsMulti` by a self-relay ([`Op::register_bls_multi`]). The chain's check is the only authority; the SDK's checks
//! are availability. UNAUDITED.
use super::prepared::Prepared;
use super::quote::{self_relay, SubmitPath, SubmitQuote};
use super::{evm, hex, key, sim, unhex, Key, KeyRef, Op};
use crate::SdkError;
use alloy::primitives::{Address, Bytes, U256};
use scaas_rpc::evm::BroadcastOutcome;
use scaas_rpc::Fanout;
use scaas_ua::bls_multi;
use serde_json::{json, Value};
use std::sync::Arc;

alloy::sol! {
    struct KemKey { uint8 scheme; bytes mlkemEk; bytes32 x25519; }
    struct UAAttrs { bytes pqzKey; bytes32 pqzPopHash; KemKey kem; bytes32 kemPkHash; }
    struct BlsMultiMember { bytes key; uint16 weight; }
    struct BlsMultiKey { bytes aggKey; uint16 threshold; BlsMultiMember[] members; }
    function registerBlsMulti(BlsMultiKey key, UAAttrs attrs, bytes pop, bytes pqzPop) external returns (bytes32);
}

/// A member's part (spec §5.4, §4): its index in the group's key data and its partial `σ_i` (or PoP part `π_i`), 128 bytes,
/// `0x` hex.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct BlsMultiPart {
    pub index: u8,
    pub signature: String,
}

/// The group key data of a [`KeyRef::BlsMulti`], valid `0x0121` key data (`Argument` otherwise, or for another key).
pub(crate) fn key_data(r: &KeyRef) -> Result<Vec<u8>, SdkError> {
    let KeyRef::BlsMulti { key_data, .. } = r else {
        return Err(SdkError::Argument);
    };
    let d = unhex(key_data)?;
    bls_multi::parse(&d).map_err(|_| SdkError::Argument)?;
    Ok(d)
}

/// The member count n of a [`KeyRef::BlsMulti`] signer (`members`, the gas rows' count); `None` for any other key.
pub(crate) fn members(r: &KeyRef) -> Option<u64> {
    let d = key_data(r).ok()?;
    bls_multi::parse(&d).ok().map(|k| k.members.len() as u64)
}

/// The group's UA, `keccak256(TAG(0x0121) ‖ d)`.
pub(crate) fn ua(r: &KeyRef) -> Result<[u8; 32], SdkError> {
    Ok(bls_multi::ua_of(&key_data(r)?))
}

/// The member key of `member` (a [`KeyRef::BlsMulti`] of the group `d`) and its index in `d` (`Argument` when `d` does not
/// list it or the key data differ).
fn member(
    sdk: &crate::Sdk,
    member: &KeyRef,
    d: &[u8],
) -> Result<(scaas_ua::wallet::UaKey, u8), SdkError> {
    if key_data(member)? != d {
        return Err(SdkError::Argument);
    }
    let Key::Ua(_, k) = key(sdk, member)? else {
        return Err(SdkError::Argument);
    };
    let i = bls_multi::parse(d)
        .map_err(|_| SdkError::Argument)?
        .members
        .iter()
        .position(|m| m.0[..] == k.key_data()[..])
        .ok_or(SdkError::Argument)?;
    Ok((k, i as u8))
}

fn part_bytes(p: &BlsMultiPart) -> Result<(u8, [u8; 128]), SdkError> {
    Ok((
        p.index,
        unhex(&p.signature)?
            .try_into()
            .map_err(|_| SdkError::Argument)?,
    ))
}

/// Whether `part` is member `part.index`'s valid part of the group `d` on `message` (`pop`: the PoP part over `popMsg`).
fn part_ok(d: &[u8], message: &[u8; 32], pop: bool, part: &BlsMultiPart) -> bool {
    let Ok((i, s)) = part_bytes(part) else {
        return false;
    };
    bls_multi::parse(d).is_ok_and(|k| {
        k.members
            .get(i as usize)
            .is_some_and(|m| bls_multi::part_ok(d, &m.0, message, pop, &s))
    })
}

/// The `UASig` objects of a built job `op` whose `signature` is `abi` (the 160-byte `σ ‖ bitmap`), each replaced by its named
/// form `{signature: σ, signers}` (spec §5.1, NODE: a 160-byte hex is `HEX_ARGS_REFUSED`); the count replaced.
fn name_sig(v: &mut Value, abi: &str, named: &Value) -> usize {
    match v {
        Value::Object(o) => {
            if o.get("signature").and_then(Value::as_str) == Some(abi)
                && o.contains_key("keyData")
                && o.contains_key("members")
            {
                *v = named.clone();
                return 1;
            }
            o.values_mut().map(|x| name_sig(x, abi, named)).sum()
        }
        Value::Array(a) => a.iter_mut().map(|x| name_sig(x, abi, named)).sum(),
        _ => 0,
    }
}

/// `p`'s entry built with the group's aggregate of `parts` (spec §5.4: each partial checked, an invalid one dropped, a minimal
/// set unless `surplus`): the calldata's `UASig` `{"", σ ‖ bitmap, []}` (a stored kind), the job `op`'s by name. Refused:
/// `BlsMultiBelowThreshold` (the valid partials' weight below `t`), `Argument` (a duplicate index or one at or above n, a
/// part that is not 128 bytes, an entry whose signature is not a `UASig`).
pub(crate) fn sign(
    p: &Prepared,
    parts: &[BlsMultiPart],
    surplus: bool,
) -> Result<scaas_ua::wallet::entries::Built, SdkError> {
    // an owner statement (`ownerSig`, `pqzAuth`) is signed by one key before the entry: a group has no such path (M15,
    // review 2026-11-20; as `sign_msig`)
    if p.t.owner.is_some() {
        return Err(SdkError::Argument);
    }
    let d = key_data(&p.signer())?;
    let ua_msg = scaas_ua::wallet::scaas_bls_multi_message(&p.t.td)?;
    let parts = parts
        .iter()
        .map(part_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    let agg = bls_multi::aggregate(&d, &ua_msg, &parts, surplus).map_err(|e| match e {
        bls_multi::Error::BelowThreshold | bls_multi::Error::BadPartial { .. } => {
            SdkError::BlsMultiBelowThreshold
        }
        _ => SdkError::Argument,
    })?;
    let abi = hex(&agg.to_abi());
    let sig = super::submit::sig_json(p, &[], &agg.to_abi())?;
    if sig.get("members").is_none() {
        return Err(SdkError::Argument); // a group signs only an entry that takes a `UASig`
    }
    let mut b = super::submit::build(p, &sig, &p.t.extra)?;
    let named = json!({"signature": hex(&agg.signature), "signers": agg.signers});
    if let Some(op) = b.op.as_mut() {
        if name_sig(op, &abi, &named) == 0 {
            return Err(SdkError::Internal); // never the 160-byte object to a node
        }
    }
    Ok(b)
}

/// `registerBlsMulti(key, UAAttrs(), pop, "")` of the group `d` (spec §2: the key data by name).
pub(crate) fn register_calldata(d: &[u8], pop: &[u8]) -> Result<Vec<u8>, SdkError> {
    use alloy::sol_types::SolCall;
    let k = bls_multi::parse(d).map_err(|_| SdkError::Argument)?;
    let key = BlsMultiKey {
        aggKey: d.get(..256).ok_or(SdkError::Argument)?.to_vec().into(),
        threshold: k.threshold,
        members: k
            .members
            .iter()
            .map(|m| BlsMultiMember {
                key: m.0.to_vec().into(),
                weight: m.1,
            })
            .collect(),
    };
    Ok(registerBlsMultiCall {
        key,
        attrs: UAAttrs {
            pqzKey: Bytes::new(),
            pqzPopHash: Default::default(),
            kem: KemKey {
                scheme: 0,
                mlkemEk: Bytes::new(),
                x25519: Default::default(),
            },
            kemPkHash: Default::default(),
        },
        pop: pop.to_vec().into(),
        pqzPop: Bytes::new(),
    }
    .abi_encode())
}

fn registry(sdk: &crate::Sdk, chain: &str) -> Result<Address, SdkError> {
    let (profile, _, _) = evm(sdk, chain)?;
    profile
        .registry
        .as_deref()
        .and_then(|a| a.parse().ok())
        .ok_or(SdkError::Argument)
}

impl Op {
    /// Member `member`'s partial of `prepared` (whose signer is the group, [`KeyRef::BlsMulti`] of the same key data), signed
    /// under the operation's check (`scaas-ua` `sign_scaas_bls_multi`). `PreparedUnknown`, `PreparedStale`, `PolicyRefused`,
    /// `Argument` (another group, a key the group does not list), `WalletLocked`.
    pub async fn bls_multi_part(
        &self,
        prepared: Arc<Prepared>,
        member: KeyRef,
    ) -> Result<BlsMultiPart, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                Op::known(&sdk, &prepared)?;
                super::submit::fresh(&sdk, &prepared).await?;
                let d = key_data(&prepared.signer())?;
                let (k, index) = self::member(&sdk, &member, &d)?;
                let s = scaas_ua::wallet::sign_scaas_bls_multi(
                    &k,
                    &d,
                    &prepared.t.td,
                    prepared.t.expect.clone(),
                )?;
                Ok(BlsMultiPart {
                    index,
                    signature: hex(&s),
                })
            })
            .await
    }

    /// Whether `part` is a valid partial of `prepared`'s group on it: what the coordinator checks on receipt, naming a bad
    /// partial by its index (spec §5.4). `false` too when `prepared`'s signer is not a group.
    pub fn bls_multi_part_ok(&self, prepared: &Prepared, part: &BlsMultiPart) -> bool {
        let (Ok(d), Ok(m)) = (
            key_data(&prepared.signer()),
            scaas_ua::wallet::scaas_bls_multi_message(&prepared.t.td),
        ) else {
            return false;
        };
        part_ok(&d, &m, false, part)
    }

    /// [`Op::submit`] of a group's operation: the aggregate of `parts` (each checked, an invalid one dropped; a minimal set
    /// unless `surplus`, N6) in place of one key's signature, the job's `UASig` by name. `BlsMultiBelowThreshold` when the
    /// valid partials do not reach `t`; otherwise as [`Op::submit`].
    pub async fn submit_bls_multi(
        &self,
        prepared: Arc<Prepared>,
        quote: SubmitQuote,
        parts: Vec<BlsMultiPart>,
        surplus: bool,
    ) -> Result<String, SdkError> {
        self.submit_with(
            prepared,
            quote,
            super::submit::Signing::BlsMulti(parts, surplus),
        )
        .await
    }

    /// Member `member`'s PoP part for its group's registration (spec §4: over `popMsg` derived from the key data, N5).
    /// `Argument` (not a group key, a key the group does not list), `WalletLocked`.
    pub fn bls_multi_pop_part(&self, member: KeyRef) -> Result<BlsMultiPart, SdkError> {
        let d = key_data(&member)?;
        let (k, index) = self::member(&self.sdk, &member, &d)?;
        Ok(BlsMultiPart {
            index,
            signature: hex(&k.sign_bls_multi_pop(&d)?),
        })
    }

    /// Whether `part` is member `part.index`'s valid PoP part for the group `key_data` (`0x` hex).
    pub fn bls_multi_pop_part_ok(&self, key_data: &str, part: &BlsMultiPart) -> bool {
        let Ok(d) = unhex(key_data) else { return false };
        let Ok(pm) = bls_multi::pop_message(&d) else {
            return false;
        };
        part_ok(&d, &pm, true, part)
    }

    /// The self-relay quote of `registerBlsMulti` of the group `key_data` (`0x` hex) on `chain` by `payer` (spec §8.4): the
    /// registration's base row `gas + per_item × n` ([`super::gas::registry_gas`]: regular and state gas, no verify part;
    /// its regular bound held to the per-transaction cap, EIP-8037)
    /// with the intrinsic cost and the calldata, quoted as [`super::gas::registry_gas`] quotes a registry write (a fixed-cost
    /// row: no margin, owner 2026-11-20): the cost by n before the members' parts exist. The row is gas
    /// used; the PoP check's gas pre-check asks the verifier's whole `POP_GAS` up front, so a small group's transaction needs
    /// more gas than it uses: [`Op::register_bls_multi`] raises the limit to the simulation's. `GasUnquoted` without a row, `Argument` for invalid key data or
    /// a profile without a registry; then as [`Op::quote`]'s self-relay.
    pub async fn quote_register_bls_multi(
        &self,
        chain: String,
        key_data: String,
        payer: KeyRef,
    ) -> Result<SubmitQuote, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let d = unhex(&key_data)?;
                let n = bls_multi::parse(&d)
                    .map_err(|_| SdkError::Argument)?
                    .members
                    .len();
                let to = registry(&sdk, &chain)?;
                let cd = register_calldata(&d, &[0u8; 128])?; // the PoP's length, not its value
                let c = sdk
                    .chains
                    .iter()
                    .find(|c| c.profile.key == chain)
                    .ok_or(SdkError::ChainUnknown)?;
                let figure = super::gas::registry_gas(
                    &c.profile.gas,
                    &c.profile.gas_opt_in,
                    &sdk.gas_tables,
                    &[("registerBlsMulti".into(), "account".into())],
                    n as u64,
                    &[],
                    cd.len(),
                )?
                .ok_or(SdkError::GasUnquoted)?;
                self_relay(
                    &sdk,
                    &chain,
                    &payer,
                    to,
                    U256::ZERO,
                    Bytes::from(cd),
                    "0".into(),
                    true,
                    Some(figure),
                )
                .await
            })
            .await
    }

    /// `registerBlsMulti` of the group `key_data` (`0x` hex) on `chain` by the self-relay `quote`
    /// ([`Op::quote_register_bls_multi`]): the PoP aggregated from every member's part (`RegistrationPopInvalid` for a bad or
    /// missing one; [`Op::bls_multi_pop_part_ok`] names it), the calldata simulated from the payer (a revert sends nothing),
    /// its gas the quote's or, where more, the simulation's with the margin (G3's rule: above `Limits::max_gas`
    /// `SignedGasAboveCap`, above the chain's per-transaction cap `GasAboveTxCap`, a cost above the caps `FeeAboveCap`), then
    /// sent; returns the transaction's id. A registration is not an operation row: it holds no lane, and a repeat lands
    /// the identical record or reverts (CTR-UA-07). `SubmitPathNone` for another path; the quote's caps as [`Op::submit`].
    pub async fn register_bls_multi(
        &self,
        chain: String,
        key_data: String,
        parts: Vec<BlsMultiPart>,
        quote: SubmitQuote,
    ) -> Result<String, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let SubmitPath::SelfRelay { payer } = &quote.path else {
                    return Err(SdkError::SubmitPathNone);
                };
                let fee = quote
                    .max_fee_per_gas
                    .parse::<u128>()
                    .map_err(|_| SdkError::Argument)?;
                super::quote::check_caps(&sdk, quote.gas_limit, fee)?;
                let d = unhex(&key_data)?;
                let parts = parts
                    .iter()
                    .map(part_bytes)
                    .collect::<Result<Vec<_>, _>>()?;
                let pop = bls_multi::aggregate_pop(&d, &parts)
                    .map_err(|_| SdkError::RegistrationPopInvalid)?;
                let to = registry(&sdk, &chain)?;
                let cd = register_calldata(&d, &pop)?;
                let (_, chain_id, pool) = evm(&sdk, &chain)?;
                let from = super::quote::payer_address(&sdk, payer)?;
                let est = pool
                    .simulate_from(from, to, Bytes::from(cd.clone()))
                    .await
                    .map_err(sim)?;
                // G3's rule (owner 2026-11-19) on the real calldata: the gas the simulation needs, with the margin, where it
                // exceeds the quote's (the PoP check's gas pre-check, the verifier's whole `POP_GAS`, needs more than a small
                // group uses), within the caps
                let gas = quote.gas_limit.max(super::gas::with_margin(est));
                if gas > sdk.limits.max_gas {
                    return Err(SdkError::SignedGasAboveCap);
                }
                // the raise is the gas the PoP check asks up front: regular gas
                let regular = quote.regular_gas.saturating_add(gas - quote.gas_limit);
                let (profile, _, _) = evm(&sdk, &chain)?;
                let block = pool.block_gas().await.map_err(sim)?;
                super::quote::above_caps(&profile, regular, gas, block.limit)?;
                let cost = super::quote::check_caps(&sdk, gas, fee)?;
                let quote = SubmitQuote {
                    gas_limit: gas,
                    regular_gas: regular,
                    gas: Some(gas),
                    max_cost: cost.to_string(),
                    ..quote.clone()
                };
                let (raw, id) =
                    super::submit::sign_tx(&sdk, chain_id, &quote, to.into(), U256::ZERO, cd)?;
                match pool.broadcast(&raw, Fanout::All).await? {
                    BroadcastOutcome::Sent { .. } => Ok(id),
                    BroadcastOutcome::Rejected { .. } => {
                        Err(SdkError::Rpc(scaas_rpc::RpcError::EndpointAllFailed {
                            last: None,
                            failover_revert: None,
                        }))
                    }
                }
            })
            .await
    }
}
