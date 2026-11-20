// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Registration (spec §7 "Registration"; plan T13): a UA key's registry write built by `scaas-ua` (`registration_args`, the
//! PoP by `sign_ua` under `pop` v2, role Pop, CLI-UAL-17; the calldata by `entries::registry_call`), self-relayed by the
//! user's payer while the gateway's `POST /v1/ua/register` is not served (§13.3). Owner 2026-11-20: a registration carrying a
//! `pqzPop` is quoted in one transaction first; when its whole gas is above half the chain's block gas limit (read from the
//! node), its regular gas above the per-transaction cap, its whole above `Limits::max_gas`, or its estimate fails, it goes in
//! two steps, the registration without `pqzPop`, then `storePqzPop` (F22's restart-safe flow); each step held to the same
//! (`GasAboveTxCap`, `GasAboveBlockShare`, `FeeAboveCap`), nothing kept or sent otherwise, and [`RegistryWrite::registration_gas`]
//! states the transactions, each step's gas and the total. A KEM key in its hash-commit form is filled by `setKemKey(ua, 0, kem, UASig())`.
//! An ML-DSA key on a registry that caches expanded keys (`cacheExpandedKey(kind, pk, 0)` simulates; with the precompile the
//! registry refuses it) first gets each part `expandedKeyOf(ua)` shows missing (CTR-UA-23 MD-3; owner 2026-11-19, T1).
//! A registry write is an opaque [`RegistryWrite`] kept in the SDK's table, quoted and submitted like a native send (sign →
//! write ahead → simulate → send). Its gas (controller call, owner auto-run 2026-11-19): where the gas table has its form's rows
//! ([`GasShape`]: `register` by the UA's kind, plus a KEM key's and a PQZ key's (with or without its proof) additions,
//! `registerWebAuthn`, `storePqzPop`, `setKemKey`, `cacheExpandedKey`, `registerMsig` / `acceptMembership` / `updateMsig` by
//! `members` plus each signing slot's verify row), the regular bound is the table's and the gas limit max(the node's estimate,
//! the table's); without them the estimate, whole, held to the cap (a successful estimate is never read as proof that the
//! regular gas fits: anvil and a node that does not enforce the cap pass anything); it lands **by its record** (`isRegistered`, `pqzPopOf(…)` non-empty:
//! the proof stored, proven or not, as on a chain with no PoP verifier (owner 2026-11-19, S2), `kemKeyAt(…)`), whoever sent
//! it: a registration is portable, its PoP binds no caller (CTR-UA-07). UNAUDITED.
use super::Account;
use crate::op::gas::{Figure, GasFrom, GasSources};
use crate::op::quote::{check_caps, payer_address, self_relay};
use crate::op::state::{self, Row};
use crate::op::submit::{detach, send, sign_tx};
use crate::op::{
    evm, field, hex, key, sim, unhex, Key, KeyRef, ReviewField, Source, SubmitPath, SubmitQuote,
};
use crate::{Sdk, SdkError};
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, U256};
use alloy::rpc::types::TransactionRequest;
use scaas_rpc::evm::EvmPool;
use scaas_ua::wallet::entries::registry_call;
use serde_json::{json, Value};
use std::sync::{Arc, PoisonError};

/// What a registration carries besides the key (spec §7): the PQZ key with its `R_REG` proof, the KEM key (version 0).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegisterAttrs {
    pub pqz_key: bool,
    pub kem: bool,
}

/// `prepare_register`: the UA key `key` (a seed's `KeyRef::Ua`) registered on `chain`, its writes self-relayed by `payer` (a
/// native `evm` key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Register {
    pub key: KeyRef,
    pub chain: String,
    pub attrs: RegisterAttrs,
    pub payer: KeyRef,
}

/// The record that shows a registry write landed (read at the profile's final block).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Landed {
    /// `isRegistered(ua)`
    Registered,
    /// `pqzPopOf(ua, v)` non-empty: the proof stored, proven by a verifier or not (owner 2026-11-19, S2)
    PqzPop(u64),
    /// `kemKeyAt(ua, v).kem.scheme != 0`
    Kem(u64),
    /// `msigStateOf(ua).accepted` has bit `i`: the slot accepted (CTR-UA-37; enabled or not)
    Accepted(u16),
    /// `msigStateOf(ua).version >= v` and `keccak256(msigOf(ua))` the update's structure hash: the `msig` at or past update `v`
    /// on this registry with this update's structure (CTR-UA-44; whoever sent it, as a registration; M3, owner 2026-11-19: a
    /// competing update of the same version by another quorum is not this one)
    MsigUpdate(u64, [u8; 32]),
    /// `expandedKeyOf(ua)[p] != 0`: part `p` of an ML-DSA key's expanded-key cache stored (CTR-UA-23 MD-3, MD-4)
    Cached(u64),
}

impl Landed {
    fn name(self) -> String {
        match self {
            Landed::Registered => "registered".into(),
            Landed::PqzPop(v) => format!("pqzPop:{v}"),
            Landed::Kem(v) => format!("kem:{v}"),
            Landed::Accepted(i) => format!("accepted:{i}"),
            Landed::MsigUpdate(v, h) => format!("msigUpdate:{v}:{}", crate::op::hex(&h)),
            Landed::Cached(p) => format!("cached:{p}"),
        }
    }
    pub(crate) fn parse(s: &str) -> Option<Landed> {
        match s.split_once(':') {
            None if s == "registered" => Some(Landed::Registered),
            Some(("pqzPop", v)) => v.parse().ok().map(Landed::PqzPop),
            Some(("kem", v)) => v.parse().ok().map(Landed::Kem),
            Some(("accepted", i)) => i.parse().ok().map(Landed::Accepted),
            Some(("msigUpdate", r)) => {
                let (v, h) = r.split_once(':')?;
                let h: [u8; 32] = crate::op::unhex(h).ok()?.try_into().ok()?;
                v.parse().ok().map(|v| Landed::MsigUpdate(v, h))
            }
            Some(("cached", p)) => p.parse().ok().map(Landed::Cached),
            _ => None,
        }
    }
}

/// One step of a registration carrying its PQZ key's proof as quoted at prepare (owner 2026-11-20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepGas {
    /// `register` (or `registerWebAuthn`, `registerMsig`), with or without the proof, or `storePqzPop`
    pub entry: String,
    /// the step's gas limit: max(the node's estimate, the gas table's figure), the table's with the intrinsic cost, the
    /// calldata and the margin; `None` where neither is known yet (a later step is not estimated before the one before it
    /// landed)
    pub gas: Option<u64>,
    /// the bound of its regular part (EIP-8037): the table's; the estimate, whole, where the table has no row
    pub regular_gas: Option<u64>,
}

/// A registration carrying its PQZ key's proof as the SDK quoted it at prepare (owner 2026-11-20): one transaction, or two
/// (`register` without the proof, then `storePqzPop`, F22's restart-safe flow) when the one transaction's gas is above half
/// the chain's block gas limit or its regular gas above the per-transaction cap; each step's gas and the total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationGas {
    /// 1 or 2
    pub transactions: u32,
    /// the steps prepared, in the order they land (after a restart between the two, the second alone)
    pub steps: Vec<StepGas>,
    /// the steps' gas added; `None` when a step's is not known
    pub total_gas: Option<u64>,
}

/// What a registry write's gas rows read (controller call, owner auto-run 2026-11-19; spec §13.3): its base rows `(entry,
/// kind)`, added, at a fresh lane; the `members` count the counted ones read; the signing slots whose verify rows it adds (an
/// `msig`'s PoP, update or acceptance slots, by verify-row signer: an EOA member the native reference, 0).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GasShape {
    pub rows: Vec<(String, String)>,
    pub members: u64,
    pub signers: Vec<u16>,
}

/// A registry write as the user reviews it (spec §7, §13.1): opaque, kept in the SDK's table; it holds public data only
/// (the PoP binds no caller). `submit_registry_write` sends exactly its calldata to the profile's registry.
pub struct RegistryWrite {
    id: String,
    chain: String,
    entry: String,
    ua: [u8; 32],
    review: Vec<ReviewField>,
    payer: KeyRef,
    pub(crate) calldata: Vec<u8>,
    pub(crate) landed: Landed,
    pub(crate) shape: GasShape,
    registration: Option<RegistrationGas>,
}

impl std::fmt::Debug for RegistryWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryWrite")
            .field("id", &self.id)
            .field("entry", &self.entry)
            .finish()
    }
}

#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
impl RegistryWrite {
    pub fn id(&self) -> String {
        self.id.clone()
    }
    pub fn chain(&self) -> String {
        self.chain.clone()
    }
    /// The registry function: `register`, `registerWebAuthn`, …, `storePqzPop`, `setKemKey`, `cacheExpandedKey`, `registerMsig`,
    /// `acceptMembership`, `updateMsig`.
    pub fn entry(&self) -> String {
        self.entry.clone()
    }
    /// The UA it registers (`0x` + 64 hex).
    pub fn ua(&self) -> String {
        hex(&self.ua)
    }
    pub fn review(&self) -> Vec<ReviewField> {
        self.review.clone()
    }
    /// The calldata the payer's transaction carries to the registry (`0x` hex; public data).
    pub fn calldata(&self) -> String {
        hex(&self.calldata)
    }
    /// The payer whose transaction sends it (linked on chain to the UA's registration).
    pub fn payer(&self) -> KeyRef {
        self.payer.clone()
    }
    /// A registration carrying its PQZ key's proof (`register` and its `storePqzPop`): one transaction or two, each step's gas
    /// and the total as quoted at prepare (owner 2026-11-20); `None` for any other write.
    pub fn registration_gas(&self) -> Option<RegistrationGas> {
        self.registration.clone()
    }
}

/// A registration as the registry holds it (`registration_of`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistrationState {
    pub registered: bool,
    /// the hash commit of the KEM key (`attrs.kemPkHash`, `0x` + 64 hex; all zero: none)
    pub kem_pk_hash: String,
    /// the KEM key of version 0 is stored (a commit filled, or the full key given at `register`)
    pub kem_stored: bool,
    /// the PQZ key of version 0 has its proof stored (`pqzPopOf`; owner 2026-11-19, S2)
    pub pqz_pop_stored: bool,
    /// and a PoP verifier checked it (`pqzKeyAt(…).proven`; false on a chain with none)
    pub pqz_proven: bool,
}

pub(crate) fn registry_of(sdk: &Sdk, chain: &str) -> Result<Address, SdkError> {
    let (profile, _, _) = evm(sdk, chain)?;
    profile
        .registry
        .as_deref()
        .and_then(|r| r.parse().ok())
        .ok_or(SdkError::Argument)
}

fn selector(sig: &str) -> Vec<u8> {
    scaas_ua::keccak256(sig.as_bytes())
        .get(..4)
        .unwrap_or_default()
        .to_vec()
}

fn word_u64(v: u64) -> [u8; 32] {
    U256::from(v).to_be_bytes::<32>()
}

/// The view call of `landed` on `ua`.
pub(crate) fn record_call(landed: Landed, ua: &[u8; 32]) -> Bytes {
    let mut d = match landed {
        Landed::Registered => selector("isRegistered(bytes32)"),
        Landed::PqzPop(_) => selector("pqzPopOf(bytes32,uint64)"),
        Landed::Kem(_) => selector("kemKeyAt(bytes32,uint64)"),
        Landed::Accepted(_) | Landed::MsigUpdate(..) => selector("msigStateOf(bytes32)"),
        Landed::Cached(_) => selector("expandedKeyOf(bytes32)"),
    };
    d.extend_from_slice(ua);
    match landed {
        Landed::PqzPop(v) | Landed::Kem(v) => d.extend_from_slice(&word_u64(v)),
        Landed::Registered | Landed::Accepted(_) | Landed::MsigUpdate(..) | Landed::Cached(_) => {}
    }
    Bytes::from(d)
}

/// The second view of `landed` on `ua`, read when the first holds (M3: `msigOf(ua)`, the current structure).
pub(crate) fn record_call2(landed: Landed, ua: &[u8; 32]) -> Option<Bytes> {
    let Landed::MsigUpdate(..) = landed else {
        return None;
    };
    let mut d = selector("msigOf(bytes32)");
    d.extend_from_slice(ua);
    Some(Bytes::from(d))
}

/// The second view's answer: the current structure (`msigOf`), its key data's keccak256 the update's; `None` for another shape.
pub(crate) fn record_holds2(landed: Landed, out: &[u8]) -> Option<bool> {
    let Landed::MsigUpdate(_, h) = landed else {
        return Some(true);
    };
    super::msig::decode_structure(out).map(|kd| scaas_ua::keccak256(&kd) == h)
}

fn word(out: &[u8], i: usize) -> Option<U256> {
    // F24 / M5: `i` may come from an RPC answer
    let at = i.checked_mul(32)?;
    out.get(at..at.checked_add(32)?).map(U256::from_be_slice)
}

/// The record's answer: present or not; `None` for an answer of another shape.
pub(crate) fn record_holds(landed: Landed, out: &[u8]) -> Option<bool> {
    match landed {
        // one ABI `bool`, exactly 0 or 1
        Landed::Registered => match (out.len(), word(out, 0)?) {
            (32, w) if w <= U256::from(1) => Some(w == U256::from(1)),
            _ => None,
        },
        // `bytes`: its offset, then its length; stored when not empty
        Landed::PqzPop(_) => {
            let off = usize::try_from(word(out, 0)?).ok()?;
            let len = usize::try_from(word(out, off / 32)?).ok()?;
            // F24: offsets from an RPC answer, added checked
            let end = off.checked_add(32)?.checked_add(len)?;
            (off % 32 == 0 && out.len() >= end).then_some(len > 0)
        }
        // `(KemKey kem, bytes sig)`: the tuple's offset, then its first word the scheme
        Landed::Kem(_) => {
            let off = usize::try_from(word(out, 0)?).ok()?;
            Some(!out.get(off..off.checked_add(32)?)?.iter().all(|b| *b == 0))
        }
        // `(uint64 version, uint256 enabled, uint256 accepted)`
        Landed::Accepted(i) => (out.len() == 96)
            .then(|| i < 256 && word(out, 2).is_some_and(|w| w.bit(usize::from(i)))),
        Landed::MsigUpdate(v, _) => match (out.len(), word(out, 0)?) {
            (96, w) if w <= U256::from(u64::MAX) => Some(w >= U256::from(v)),
            _ => None,
        },
        // `address[3]`: part `p`'s pointer
        Landed::Cached(p) => (out.len() == 96)
            .then(|| word(out, usize::try_from(p).unwrap_or(3)).is_some_and(|w| !w.is_zero())),
    }
}

pub(crate) async fn read_record(
    pool: &EvmPool,
    registry: Address,
    landed: Landed,
    ua: &[u8; 32],
) -> Result<bool, SdkError> {
    let tx = TransactionRequest::default()
        .with_to(registry)
        .with_input(record_call(landed, ua));
    let out = pool.call_tx(tx).await.map_err(sim)?;
    let bad = || {
        SdkError::Rpc(scaas_rpc::RpcError::EndpointAllFailed {
            last: None,
            failover_revert: None,
        })
    };
    if !record_holds(landed, &out).ok_or_else(bad)? {
        return Ok(false);
    }
    let Some(c2) = record_call2(landed, ua) else {
        return Ok(true);
    };
    let out = pool
        .call_tx(
            TransactionRequest::default()
                .with_to(registry)
                .with_input(c2),
        )
        .await
        .map_err(sim)?;
    record_holds2(landed, &out).ok_or_else(bad)
}

/// `pqzKeyAt(ua, 0).proven`: a PoP verifier checked version 0's proof.
async fn pqz_proven(pool: &EvmPool, registry: Address, ua: &[u8; 32]) -> Result<bool, SdkError> {
    let mut d = selector("pqzKeyAt(bytes32,uint64)");
    d.extend_from_slice(ua);
    d.extend_from_slice(&word_u64(0));
    let tx = TransactionRequest::default()
        .with_to(registry)
        .with_input(Bytes::from(d));
    let out = pool.call_tx(tx).await.map_err(sim)?;
    // `(address ptr, bytes32 pqzPopHash, bool proven)`
    word(&out, 2)
        .filter(|w| *w <= U256::from(1))
        .map(|w| w == U256::from(1))
        .ok_or(SdkError::Rpc(scaas_rpc::RpcError::EndpointAllFailed {
            last: None,
            failover_revert: None,
        }))
}

/// `pqzKeyAt(ua, 0).pqzPopHash`: the hash of the proof the registration committed to (`storePqzPop` takes only that proof).
async fn pqz_pop_hash(
    pool: &EvmPool,
    registry: Address,
    ua: &[u8; 32],
) -> Result<[u8; 32], SdkError> {
    let mut d = selector("pqzKeyAt(bytes32,uint64)");
    d.extend_from_slice(ua);
    d.extend_from_slice(&word_u64(0));
    let tx = TransactionRequest::default()
        .with_to(registry)
        .with_input(Bytes::from(d));
    let out = pool.call_tx(tx).await.map_err(sim)?;
    // `(address ptr, bytes32 pqzPopHash, bool proven)`
    out.get(32..64)
        .and_then(|w| w.try_into().ok())
        .ok_or(SdkError::Rpc(scaas_rpc::RpcError::EndpointAllFailed {
            last: None,
            failover_revert: None,
        }))
}

/// `registrationOf(ua)`'s `attrs.kemPkHash` (zero for an unregistered UA).
async fn kem_pk_hash(
    pool: &EvmPool,
    registry: Address,
    ua: &[u8; 32],
) -> Result<[u8; 32], SdkError> {
    let mut d = selector("registrationOf(bytes32)");
    d.extend_from_slice(ua);
    let tx = TransactionRequest::default()
        .with_to(registry)
        .with_input(Bytes::from(d));
    let out = pool.call_tx(tx).await.map_err(sim)?;
    let bad = || {
        SdkError::Rpc(scaas_rpc::RpcError::EndpointAllFailed {
            last: None,
            failover_revert: None,
        })
    };
    // `(uint16 kind, bytes keyData, UAAttrs attrs, bytes pop, bytes pqzPop)`: `attrs` by its offset, `kemPkHash` its fourth word
    let off = word(&out, 2)
        .and_then(|w| usize::try_from(w).ok())
        .ok_or_else(bad)?;
    let at = off.checked_add(96).ok_or_else(bad)?;
    out.get(at..at.checked_add(32).ok_or_else(bad)?)
        .and_then(|w| w.try_into().ok())
        .ok_or_else(bad)
}

/// A verify row's signer of an `msig` slot of kind `kind`: an EOA member the native reference (0), any other its kind (a kind
/// without a row leaves the write without a figure).
pub(crate) fn slot_signer(kind: u16) -> u16 {
    match kind {
        1 => crate::op::gas::NATIVE_EVM,
        k => k,
    }
}

/// The rows a registry write's arguments name (controller call, owner auto-run 2026-11-19): the form's base row, then a KEM
/// key's addition (full or committed) and a PQZ key's (`pqz-pop` with its proof, `pqz-key` without), an `msig` structure's
/// `members` and its `pop` slots' signers. `acceptMembership` and `updateMsig` take their count and signers from the
/// registry's structure ([`keep_with`]).
pub(crate) fn shape_of(entry: &str, args: &Value) -> GasShape {
    let mut g = GasShape::default();
    let ua = |k: u64| format!("ua-{k:#06x}");
    let base = match entry {
        "register" | "cacheExpandedKey" => args.get("kind").and_then(Value::as_u64).map(ua),
        "registerWebAuthn" => Some(ua(0x0100)),
        "registerMsig" | "acceptMembership" | "updateMsig" => Some("msig".into()),
        "storePqzPop" => Some("pqz".into()),
        "setKemKey" => Some("kem".into()),
        _ => None,
    };
    let Some(base) = base else { return g };
    g.rows.push((entry.into(), base));
    let set = |v: Option<&Value>| {
        v.and_then(Value::as_str)
            .is_some_and(|h| h.trim_start_matches("0x").bytes().any(|b| b != b'0'))
    };
    if let (true, Some(a)) = (entry.starts_with("register"), args.get("attrs")) {
        let kem = a
            .pointer("/kem/scheme")
            .and_then(Value::as_u64)
            .is_some_and(|k| k != 0);
        if kem || set(a.get("kemPkHash")) {
            g.rows.push(("register".into(), "kem".into()));
        }
        if a.get("pqzKey")
            .and_then(Value::as_str)
            .is_some_and(|k| k != "0x")
        {
            let pop = args
                .get("pqzPop")
                .and_then(Value::as_str)
                .is_some_and(|p| p != "0x");
            let kind = if pop { "pqz-pop" } else { "pqz-key" };
            g.rows.push(("register".into(), kind.into()));
        }
    }
    if entry == "registerMsig" {
        let members = args.pointer("/structure/members").and_then(Value::as_array);
        g.members = members.map_or(0, |m| m.len() as u64);
        let kind = |i: u64| {
            members?
                .get(usize::try_from(i).ok()?)?
                .get("kind")?
                .as_u64()
        };
        for slot in args
            .get("pop")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let k = slot.get("index").and_then(Value::as_u64).and_then(kind);
            // a slot whose kind cannot be read: a signer without a row (no figure)
            g.signers.push(
                k.and_then(|k| u16::try_from(k).ok())
                    .map_or(u16::MAX, slot_signer),
            );
        }
    }
    g
}

/// The gas table's figure of `shape` on `chain` for `len` bytes of calldata (with the intrinsic cost and the margin); `None`
/// without every row.
fn table_figure(
    sdk: &Sdk,
    chain: &str,
    shape: &GasShape,
    len: usize,
) -> Result<Option<Figure>, SdkError> {
    let c = sdk
        .chains
        .iter()
        .find(|c| c.profile.key == chain)
        .ok_or(SdkError::ChainUnknown)?;
    Ok(crate::op::gas::registry_gas(
        &c.profile.gas,
        &c.profile.gas_opt_in,
        &sdk.gas_tables,
        &shape.rows,
        shape.members,
        &shape.signers,
    )?
    .map(|(g, r, from)| crate::op::gas::with_calldata(g, r, len, from)))
}

/// What a registration step is held to (owner 2026-11-20): its regular gas to the profile's per-transaction cap, its whole to
/// half the block gas limit (the node's latest block, the read the quote does) and to `Limits::max_gas`.
struct Caps {
    tx: Option<u64>,
    half: u64,
    max: u64,
}

impl Caps {
    async fn of(sdk: &Sdk, chain: &str, pool: &EvmPool) -> Result<Caps, SdkError> {
        let (profile, _, _) = evm(sdk, chain)?;
        let block = pool.block_gas().await.map_err(sim)?;
        Ok(Caps {
            tx: profile.tx_gas_cap,
            half: block.limit / 2,
            max: sdk.limits.max_gas,
        })
    }

    /// The step's refusal, `None` where it fits (a figure not known yet is not held).
    fn refusal(&self, s: &StepGas) -> Option<SdkError> {
        if s.regular_gas.zip(self.tx).is_some_and(|(r, c)| r > c) {
            return Some(SdkError::GasAboveTxCap);
        }
        if s.gas.is_some_and(|g| g > self.half) {
            return Some(SdkError::GasAboveBlockShare);
        }
        s.gas
            .is_some_and(|g| g > self.max)
            .then_some(SdkError::FeeAboveCap)
    }
}

/// A step's gas (owner 2026-11-20): the table's figure of `entry` with `args`, and with `estimate` the node's (`None` when the
/// estimate fails); the gas the larger, the regular bound the table's, else the estimate, whole.
#[allow(clippy::too_many_arguments)]
async fn step(
    sdk: &Sdk,
    chain: &str,
    pool: &EvmPool,
    from: Address,
    registry: Address,
    entry: &str,
    args: &Value,
    estimate: bool,
) -> Result<Option<StepGas>, SdkError> {
    let cd = registry_call(entry, args)?;
    let table = table_figure(sdk, chain, &shape_of(entry, args), cd.len())?;
    let est = match estimate {
        false => None,
        true => match pool.simulate_from(from, registry, Bytes::from(cd)).await {
            Ok(g) => Some(g),
            Err(_) => return Ok(None),
        },
    };
    Ok(Some(StepGas {
        entry: entry.into(),
        gas: est.max(table.as_ref().map(|t| t.gas)),
        regular_gas: table.map(|t| t.regular).or(est),
    }))
}

fn flatten(prefix: &str, v: &Value, out: &mut Vec<ReviewField>) {
    match v {
        Value::Object(o) => {
            for (k, x) in o {
                flatten(&format!("{prefix}.{k}"), x, out);
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                flatten(&format!("{prefix}[{i}]"), x, out);
            }
        }
        Value::String(s) => out.push(field(prefix, s, s, Source::Signed)),
        other => {
            let s = other.to_string();
            out.push(field(prefix, &s, &s, Source::Signed));
        }
    }
}

/// One write kept in the table, its gas rows read from its arguments ([`shape_of`]).
pub(crate) fn keep(
    sdk: &Sdk,
    chain: &str,
    entry: &str,
    ua: [u8; 32],
    args: &Value,
    payer: &KeyRef,
    landed: Landed,
) -> Result<Arc<RegistryWrite>, SdkError> {
    let shape = shape_of(entry, args);
    keep_with(sdk, chain, entry, ua, args, payer, landed, shape, None)
}

/// [`keep`] with its gas rows `shape` and, for a registration carrying its proof, the plan it was quoted in.
#[allow(clippy::too_many_arguments)]
pub(crate) fn keep_with(
    sdk: &Sdk,
    chain: &str,
    entry: &str,
    ua: [u8; 32],
    args: &Value,
    payer: &KeyRef,
    landed: Landed,
    shape: GasShape,
    registration: Option<RegistrationGas>,
) -> Result<Arc<RegistryWrite>, SdkError> {
    let registry = registry_of(sdk, chain)?;
    let calldata = registry_call(entry, args)?;
    let mut review = vec![
        field("entry", entry, entry, Source::Derived),
        field("ua", &hex(&ua), &hex(&ua), Source::Derived),
        field(
            "registry",
            &format!("{registry:#x}"),
            &format!("{registry:#x}"),
            Source::Derived,
        ),
    ];
    flatten("args", args, &mut review);
    let w = Arc::new(RegistryWrite {
        id: crate::vault::uuid4()?,
        chain: chain.into(),
        entry: entry.into(),
        ua,
        review,
        payer: payer.clone(),
        calldata,
        landed,
        shape,
        registration,
    });
    sdk.registry_writes
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(w.id.clone(), w.clone());
    Ok(w)
}

/// The writes of a registration with its arguments `args` (named fields, `entry` among them, as `scaas-ua`'s
/// `registration_args_json` gives them) and `kem_fill` (the `setKemKey` of a hash-committed KEM key): skipped when `ua` is
/// registered already (its KEM fill added when the commit is unfilled, its `storePqzPop` when a split's second part never
/// landed); in two steps when it carries a `pqzPop` and does not fit one transaction (module doc). `GasAboveTxCap`,
/// `GasAboveBlockShare`, `FeeAboveCap`: a step that alone does not fit.
pub(crate) async fn writes(
    sdk: &Arc<Sdk>,
    chain: &str,
    payer: &KeyRef,
    ua: [u8; 32],
    args: &Value,
    kem_fill: Option<&Value>,
) -> Result<Vec<Arc<RegistryWrite>>, SdkError> {
    let (_, _, pool) = evm(sdk, chain)?;
    let registry = registry_of(sdk, chain)?;
    let entry = args
        .get("entry")
        .and_then(Value::as_str)
        .ok_or(SdkError::Argument)?
        .to_string();
    let from = payer_address(sdk, payer)?;
    let mut out = Vec::new();
    let registered = read_record(&pool, registry, Landed::Registered, &ua).await?;
    if !registered {
        // an ML-DSA key on a registry that caches its expanded key (no precompile: `cacheExpandedKey` of part 0 simulates;
        // with a precompile it reverts `UAKeyCache`): each part not stored yet, before the registration (CTR-UA-23 MD-3)
        let mut cache_pending = false;
        let kind = args
            .get("kind")
            .and_then(Value::as_u64)
            .and_then(|k| u16::try_from(k).ok());
        let parts = kind.map_or(0, scaas_ua::mldsa_cache::parts);
        if entry == "register" && parts > 0 {
            let kind = kind.ok_or(SdkError::Argument)?;
            let pk = unhex(
                args.get("keyData")
                    .and_then(Value::as_str)
                    .ok_or(SdkError::Argument)?,
            )?;
            let probe =
                scaas_ua::mldsa_cache::part_call(kind, &pk, 0).map_err(|_| SdkError::Argument)?;
            if pool
                .simulate_from(from, registry, Bytes::from(probe))
                .await
                .is_ok()
            {
                for p in 0..parts {
                    if !read_record(&pool, registry, Landed::Cached(p), &ua).await? {
                        let a = json!({"kind": kind, "pk": hex(&pk), "part": p});
                        out.push(keep(
                            sdk,
                            chain,
                            "cacheExpandedKey",
                            ua,
                            &a,
                            payer,
                            Landed::Cached(p),
                        )?);
                        cache_pending = true;
                    }
                }
            }
        }
        let pqz_pop = args.get("pqzPop").and_then(Value::as_str).unwrap_or("0x");
        // owner 2026-11-20: the one transaction first; with the cache pending it cannot be estimated yet
        // (`UAKeyNotCached`): two steps, each quoted after the one before it landed
        let caps = Caps::of(sdk, chain, &pool).await?;
        let one = match pqz_pop != "0x" && !cache_pending {
            true => step(sdk, chain, &pool, from, registry, &entry, args, true).await?,
            false => None,
        };
        if pqz_pop == "0x" {
            out.push(keep(
                sdk,
                chain,
                &entry,
                ua,
                args,
                payer,
                Landed::Registered,
            )?);
        } else if let Some(s) = one.filter(|s| caps.refusal(s).is_none()) {
            let plan = RegistrationGas {
                transactions: 1,
                total_gas: s.gas,
                steps: vec![s],
            };
            let shape = shape_of(&entry, args);
            out.push(keep_with(
                sdk,
                chain,
                &entry,
                ua,
                args,
                payer,
                Landed::Registered,
                shape,
                Some(plan),
            )?);
        } else {
            let mut first = args.clone();
            first
                .as_object_mut()
                .ok_or(SdkError::Argument)?
                .insert("pqzPop".into(), json!("0x"));
            let store = json!({"ua": hex(&ua), "version": 0, "pqzPop": pqz_pop});
            // a first step the node cannot estimate (it reverts) is not sent
            let s1 = step(
                sdk,
                chain,
                &pool,
                from,
                registry,
                &entry,
                &first,
                !cache_pending,
            )
            .await?
            .ok_or(SdkError::GasAboveTxCap)?;
            let s2 = step(
                sdk,
                chain,
                &pool,
                from,
                registry,
                "storePqzPop",
                &store,
                false,
            )
            .await?
            .ok_or(SdkError::Internal)?;
            if let Some(e) = caps.refusal(&s1).or_else(|| caps.refusal(&s2)) {
                return Err(e);
            }
            let plan = RegistrationGas {
                transactions: 2,
                total_gas: s1.gas.zip(s2.gas).map(|(a, b)| a.saturating_add(b)),
                steps: vec![s1, s2],
            };
            let shape = shape_of(&entry, &first);
            out.push(keep_with(
                sdk,
                chain,
                &entry,
                ua,
                &first,
                payer,
                Landed::Registered,
                shape,
                Some(plan.clone()),
            )?);
            let shape = shape_of("storePqzPop", &store);
            out.push(keep_with(
                sdk,
                chain,
                "storePqzPop",
                ua,
                &store,
                payer,
                Landed::PqzPop(0),
                shape,
                Some(plan),
            )?);
            // the second part's proof outlives this process (M1)
            crate::op::state::keep_pop(sdk, &hex(&ua), Some(pqz_pop)).await?;
        }
    }
    // F22, M1 (reviews 2026-11-20): a split whose first part landed and whose `storePqzPop` did not (the app closed between
    // the two parts, a lost handle, a failed submit): the second part again, with the proof the registration committed to
    // (`pqzKeyAt(ua, 0).pqzPopHash`): the one kept at the split, or this call's when it hashes the same (a sponsor's blob);
    // a proof proved again hashes otherwise (hedged), so none matching is `RegistrationPopInvalid`
    let pqz_pop = args.get("pqzPop").and_then(Value::as_str).unwrap_or("0x");
    let uah = hex(&ua);
    if registered && pqz_pop != "0x" {
        if read_record(&pool, registry, Landed::PqzPop(0), &ua).await? {
            crate::op::state::keep_pop(sdk, &uah, None).await?;
        } else {
            let want = pqz_pop_hash(&pool, registry, &ua).await?;
            let kept = crate::op::state::kept_pop(sdk, &uah).await?;
            let pop = [Some(pqz_pop.to_string()), kept]
                .into_iter()
                .flatten()
                .find(|p| unhex(p).is_ok_and(|b| scaas_ua::keccak256(&b) == want))
                .ok_or(SdkError::RegistrationPopInvalid)?;
            let store = json!({"ua": uah, "version": 0, "pqzPop": pop});
            // the second of two steps (owner 2026-11-20), held as at the split: estimated now the registration landed (the
            // table's alone where the node cannot)
            let est = step(
                sdk,
                chain,
                &pool,
                from,
                registry,
                "storePqzPop",
                &store,
                true,
            )
            .await?;
            let s2 = match est {
                Some(s) => s,
                None => step(
                    sdk,
                    chain,
                    &pool,
                    from,
                    registry,
                    "storePqzPop",
                    &store,
                    false,
                )
                .await?
                .ok_or(SdkError::Internal)?,
            };
            if let Some(e) = Caps::of(sdk, chain, &pool).await?.refusal(&s2) {
                return Err(e);
            }
            let plan = RegistrationGas {
                transactions: 2,
                total_gas: s2.gas,
                steps: vec![s2],
            };
            let shape = shape_of("storePqzPop", &store);
            out.push(keep_with(
                sdk,
                chain,
                "storePqzPop",
                ua,
                &store,
                payer,
                Landed::PqzPop(0),
                shape,
                Some(plan),
            )?);
        }
    }
    if let Some(fill) = kem_fill {
        let filled = registered && read_record(&pool, registry, Landed::Kem(0), &ua).await?;
        if !filled {
            out.push(keep(
                sdk,
                chain,
                "setKemKey",
                ua,
                fill,
                payer,
                Landed::Kem(0),
            )?);
        }
    }
    Ok(out)
}

/// `submit_registry_write`'s re-check of what it takes: one of this SDK's writes (`PreparedUnknown`).
fn known(sdk: &Sdk, w: &Arc<RegistryWrite>) -> Result<(), SdkError> {
    match sdk
        .registry_writes
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&w.id)
    {
        Some(x) if Arc::ptr_eq(x, w) => Ok(()),
        _ => Err(SdkError::PreparedUnknown),
    }
}

/// Takes `w` out of the table (one submit: a second, concurrent or later, is `PreparedUnknown`).
fn take(sdk: &Sdk, w: &Arc<RegistryWrite>) -> Result<(), SdkError> {
    let mut t = sdk
        .registry_writes
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    match t.get(&w.id) {
        Some(x) if Arc::ptr_eq(x, w) => {
            t.remove(&w.id);
            Ok(())
        }
        _ => Err(SdkError::PreparedUnknown),
    }
}

/// A seed key's registration by `scaas-ua` (`registration_args_json`; the PoP by `sign_ua` under `pop` v2, the Zether UA's by
/// its facade): the UA and `{args, kemFill, …}`.
pub(crate) fn build(
    sdk: &Sdk,
    key_ref: &KeyRef,
    attrs: RegisterAttrs,
) -> Result<([u8; 32], Value), SdkError> {
    let (mut pqz_key, mut pqz_pop) = (vec![], vec![]);
    let (kind, key_data, ua, pop, kem_pk) = match key(sdk, key_ref)? {
        Key::Ua(_, k) => {
            let ua = k.ua().ok_or(SdkError::Argument)?;
            let kem_pk = if attrs.kem {
                k.kem_key(0)?.kem_pk()
            } else {
                vec![]
            };
            if attrs.pqz_key {
                // a kind that holds no PQZ key is refused before anything is proved
                if !scaas_ua::is_pqz_holder(k.kind()) {
                    return Err(SdkError::Argument);
                }
                (pqz_key, pqz_pop) = pqz_attr(sdk, key_ref, k.kind(), &ua, &kem_pk)?;
            }
            let hp = scaas_ua::holder_pop_message(
                k.kind(),
                &ua,
                &k.key_data(),
                Some(&pqz_key),
                Some(&pqz_pop),
                None,
                Some(&kem_pk),
            )
            .map_err(|_| SdkError::Argument)?;
            let pop = k.sign_ua(
                &scaas_ua::ua_portable::pop_v2_tag(),
                &hp.registration_digest,
            )?;
            (k.kind(), k.key_data(), ua, pop, kem_pk)
        }
        #[cfg(feature = "zether")]
        Key::Zether(_, z) => {
            if attrs.kem || attrs.pqz_key {
                return Err(SdkError::Argument); // a Zether UA holds no KEM key
            }
            let (y, pop) = z.pop()?;
            (crate::confidential::ZETHER_KIND, y, z.ua(), pop, vec![])
        }
        Key::Native(..) | Key::External(..) => return Err(SdkError::Argument),
    };
    Ok((
        ua,
        args_of(kind, &key_data, &pqz_key, &pqz_pop, &kem_pk, &pop)?,
    ))
}

/// `scaas-ua`'s registration of these parts (`registration_args_json`): `{args, kemFill, …}`.
fn args_of(
    kind: u16,
    key_data: &[u8],
    pqz_key: &[u8],
    pqz_pop: &[u8],
    kem_pk: &[u8],
    pop: &[u8],
) -> Result<Value, SdkError> {
    let pop_hash = match pqz_pop.is_empty() {
        true => "0x".to_string(),
        false => hex(&scaas_ua::keccak256(pqz_pop)),
    };
    let input = json!({
        "kind": kind, "keyData": hex(key_data), "pqzKey": hex(pqz_key), "pqzPopHash": pop_hash, "pqzPop": hex(pqz_pop),
        "kemPk": hex(kem_pk), "pop": hex(pop),
    });
    serde_json::from_str(
        &scaas_ua::json::registration_args_json(&input.to_string())
            .map_err(|_| SdkError::Argument)?,
    )
    .map_err(|_| SdkError::Internal)
}

/// [`build`] for every key a registration takes (owner 2026-11-19, T2): a stored key row (a passkey's `registerWebAuthn`, a
/// secure element's `p256` `register`) signs its PoP through the `Authenticator` (`external::answer`, then `scaas-ua`'s
/// `ua_sig` over an `ExternalKey` returning that answer, which `scaas-ua` verifies); neither holds a KEM or PQZ key
/// (`Argument`).
pub(crate) async fn build_key(
    sdk: &Sdk,
    key_ref: &KeyRef,
    attrs: RegisterAttrs,
) -> Result<([u8; 32], Value), SdkError> {
    if !matches!(key_ref, KeyRef::Key { .. }) {
        return build(sdk, key_ref, attrs);
    }
    if attrs.kem || attrs.pqz_key {
        return Err(SdkError::Argument);
    }
    let Key::External(row, _) = crate::op::key_opened(sdk, key_ref).await? else {
        return Err(SdkError::Internal);
    };
    let hp = scaas_ua::holder_pop_message(row.kind, &row.ua, &row.key_data, None, None, None, None)
        .map_err(|_| SdkError::Argument)?;
    let tag = scaas_ua::ua_portable::pop_v2_tag();
    let answer = crate::op::external::answer(sdk, &row, &tag, &hp.registration_digest).await?;
    let device = scaas_ua::wallet::ExternalKey::new(row.key_ref(), move |_| Ok(answer.clone()));
    let pop = scaas_ua::wallet::ua_sig(&device, None, &tag, &hp.registration_digest)?.signature;
    Ok((
        row.ua,
        args_of(row.kind, &row.key_data, &[], &[], &[], &pop)?,
    ))
}

/// The PQZ key attribute of a seed's UA key (spec §7): the PQZ key of the same wallet account and index
/// (`Wallet::pqz_key`, version 0) and its `R_REG` proof by `scaas-ua`'s `proveRegister` over `pqz_reg_message(kind, ua, pk,
/// kem)`, under this build's PQZL `proofSystemId` (`pqz_set`, the set the build carries; the registry's PoP verifier takes
/// PQZL). `(pqzKey, pqzPop)`. `FeatureMissing` without feature `pqz`.
#[cfg(feature = "pqz")]
fn pqz_attr(
    sdk: &Sdk,
    key_ref: &KeyRef,
    kind: u16,
    ua: &[u8; 32],
    kem_pk: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), SdkError> {
    let KeyRef::Ua {
        seed,
        account,
        index,
        ..
    } = key_ref
    else {
        return Err(SdkError::Argument);
    };
    let pk = sdk.open_seed(seed)?.wallet.pqz_key(*account, *index)?;
    let mut req = serde_json::Map::new();
    req.insert(
        "proofSystemId".into(),
        json!(hex(&scaas_ua::facade::pqz::pqz_set().pqzl_id)),
    );
    req.insert("kind".into(), json!(kind));
    req.insert("ua".into(), json!(hex(ua)));
    if !kem_pk.is_empty() {
        req.insert("kemPk".into(), json!(hex(kem_pk)));
    }
    let req = Value::Object(req);
    let a: Value = serde_json::from_str(&pk.call("proveRegister", req.to_string().as_bytes())?)
        .map_err(|_| SdkError::Internal)?;
    let proof = unhex(
        a.get("proof")
            .and_then(Value::as_str)
            .ok_or(SdkError::Internal)?,
    )?;
    Ok((pk.pk(), proof))
}

#[cfg(not(feature = "pqz"))]
fn pqz_attr(
    _: &Sdk,
    _: &KeyRef,
    _: u16,
    _: &[u8; 32],
    _: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), SdkError> {
    Err(SdkError::FeatureMissing)
}

/// `ReceiverUnregistered` (spec §7.1): `to` a derived UA (not a native id: its top 12 bytes not all zero) that the profile's
/// registry does not hold, or on a profile naming no registry (fail closed: owner 2026-11-19, R3); a native id passes.
pub(crate) async fn receiver_registered(
    sdk: &Sdk,
    chain: &str,
    to: &[u8; 32],
) -> Result<(), SdkError> {
    if to.get(..12).is_some_and(|h| h.iter().all(|b| *b == 0)) {
        return Ok(());
    }
    let (profile, _, pool) = evm(sdk, chain)?;
    let Some(registry) = profile.registry.as_deref() else {
        return Err(SdkError::ReceiverUnregistered);
    };
    let registry: Address = registry.parse().map_err(|_| SdkError::Argument)?;
    match read_record(&pool, registry, Landed::Registered, to).await? {
        true => Ok(()),
        false => Err(SdkError::ReceiverUnregistered),
    }
}

impl Account {
    /// Prepares the registration of `req.key` (spec §7): the arguments and the PoP by `scaas-ua`, then the writes (the
    /// registration, `storePqzPop` when split, `setKemKey` for a hash-committed KEM key), in the order they must land; an
    /// already registered UA gives only what it misses. `WalletLocked`; `Argument` (a key other than a seed's UA key, a KEM
    /// key on a kind that holds none, a profile without a registry); `FeatureMissing` (`attrs.pqz_key` without feature
    /// `pqz`; a PQZ key on a kind that holds none is `Argument`); `GasAboveTxCap`.
    pub async fn prepare_register(
        &self,
        req: Register,
    ) -> Result<Vec<Arc<RegistryWrite>>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let (ua, r) = build_key(&sdk, &req.key, req.attrs).await?;
                let args = r.get("args").ok_or(SdkError::Internal)?;
                let fill = r.get("kemFill").filter(|f| !f.is_null());
                writes(&sdk, &req.chain, &req.payer, ua, args, fill).await
            })
            .await
    }

    /// The quote of `write` by its payer (spec §13.3): its gas (controller call, owner auto-run 2026-11-19: where the gas table
    /// has the write's rows, the regular bound the table's and the gas limit max(the estimate of its calldata, the table's);
    /// else the estimate, whole), the chain's and the SDK's caps (a registration step also half the block gas limit, owner
    /// 2026-11-20), the payer's nonce. Quote a later step only after the one before it landed (its estimate reverts before).
    /// `PreparedUnknown`, `GasAboveTxCap`, `GasAboveBlockShare`, `GasCountUnknown` (an `msig` above the counts measured),
    /// `FeeAboveCap`.
    pub async fn quote_registry_write(
        &self,
        write: Arc<RegistryWrite>,
    ) -> Result<SubmitQuote, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                known(&sdk, &write)?;
                let registry = registry_of(&sdk, &write.chain)?;
                let (_, _, pool) = evm(&sdk, &write.chain)?;
                let from = payer_address(&sdk, &write.payer)?;
                let est = pool
                    .simulate_from(from, registry, Bytes::from(write.calldata.clone()))
                    .await
                    .map_err(sim)?;
                let len = write.calldata.len();
                let fig = match table_figure(&sdk, &write.chain, &write.shape, len)? {
                    Some(t) => Figure {
                        gas: t.gas.max(est),
                        regular: t.regular,
                        from: t.from,
                    },
                    None => Figure::whole(est, GasSources::both(GasFrom::Estimate)),
                };
                if write.registration.is_some() {
                    let s = StepGas {
                        entry: write.entry.clone(),
                        gas: Some(fig.gas),
                        regular_gas: Some(fig.regular),
                    };
                    if let Some(e) = Caps::of(&sdk, &write.chain, &pool).await?.refusal(&s) {
                        return Err(e);
                    }
                }
                self_relay(
                    &sdk,
                    &write.chain,
                    &write.payer,
                    registry,
                    U256::ZERO,
                    Bytes::from(write.calldata.clone()),
                    "0".into(),
                    false,
                    Some(fig),
                )
                .await
            })
            .await
    }

    /// Signs the payer's transaction carrying exactly `write`, writes the operation's row, returns its id; the send runs on
    /// and reports as `Event::OpState`; `Op::state` follows it to `Landed` by the record. `PreparedUnknown` (a write not of
    /// this SDK, or submitted already), `Argument` (a quote of another payer), `FeeAboveCap`; a failed signing of the payer's
    /// transaction (`WalletLocked`, …) leaves the write in the table, submittable again.
    pub async fn submit_registry_write(
        &self,
        write: Arc<RegistryWrite>,
        quote: SubmitQuote,
    ) -> Result<String, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                known(&sdk, &write)?;
                let fee = quote
                    .max_fee_per_gas
                    .parse::<u128>()
                    .map_err(|_| SdkError::Argument)?;
                check_caps(&sdk, quote.gas_limit, fee)?;
                if !matches!(&quote.path, SubmitPath::SelfRelay { payer } if *payer == write.payer)
                {
                    return Err(SdkError::Argument);
                }
                let (profile, chain_id, pool) = evm(&sdk, &write.chain)?;
                let registry = registry_of(&sdk, &write.chain)?;
                let from_block = crate::op::final_number(&pool, &profile).await?;
                // one submit of a write: taken out of the table before it is signed, put back when the signing fails (owner
                // 2026-11-19, R4: as `Op::submit`)
                take(&sdk, &write)?;
                let (raw, id) = match sign_tx(
                    &sdk,
                    chain_id,
                    &quote,
                    registry.into_array(),
                    U256::ZERO,
                    write.calldata.clone(),
                ) {
                    Ok(x) => x,
                    Err(e) => {
                        sdk.registry_writes
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .entry(write.id.clone())
                            .or_insert_with(|| write.clone());
                        return Err(e);
                    }
                };
                let row = Row {
                    op: crate::vault::uuid4()?,
                    chain: write.chain.clone(),
                    entry: write.entry.clone(),
                    name: write.entry.clone(),
                    kind: "registry".into(),
                    contract: format!("{registry:#x}"),
                    from: hex(&write.ua),
                    batch: write.landed.name(),
                    nonce: String::new(),
                    valid_until: u64::MAX,
                    digest: id.clone(),
                    op_json: Value::Null,
                    calldata: hex(&write.calldata),
                    raw: Some(hex(&raw)),
                    tx_id: Some(id),
                    tx_nonce: Some(quote.tx_nonce),
                    path: "self".into(),
                    payer: Some(format!("{:#x}", payer_address(&sdk, &write.payer)?)),
                    members: None,
                    from_block,
                    state: "signed".into(),
                    detail: "Signed".into(),
                    landed: None,
                    relayer_bound: false,
                    gas_limit: Some(quote.gas_limit),
                    signer_kind: None,
                    unsigned_len: None,
                    ended_at: None,
                    fact: None,
                    message: Value::Null,
                    extra: Value::Null,
                };
                state::put(&sdk, &row).await?;
                let (s2, op) = (sdk.clone(), row.op.clone());
                detach(&sdk, async move { send(&s2, row).await });
                Ok(op)
            })
            .await
    }

    /// The registration of `ua` (`0x` + 64 hex) on `chain` as the registry holds it now.
    pub async fn registration_of(
        &self,
        chain: String,
        ua: String,
    ) -> Result<RegistrationState, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let ua: [u8; 32] = unhex(&ua)?.try_into().map_err(|_| SdkError::Argument)?;
                let (_, _, pool) = evm(&sdk, &chain)?;
                let registry = registry_of(&sdk, &chain)?;
                let registered = read_record(&pool, registry, Landed::Registered, &ua).await?;
                if !registered {
                    return Ok(RegistrationState {
                        kem_pk_hash: hex(&[0; 32]),
                        ..Default::default()
                    });
                }
                Ok(RegistrationState {
                    registered,
                    kem_pk_hash: hex(&kem_pk_hash(&pool, registry, &ua).await?),
                    kem_stored: read_record(&pool, registry, Landed::Kem(0), &ua).await?,
                    pqz_pop_stored: read_record(&pool, registry, Landed::PqzPop(0), &ua).await?,
                    pqz_proven: pqz_proven(&pool, registry, &ua).await?,
                })
            })
            .await
    }

    /// The KEM repair (CTR-UA-07, `scaas-ua` `kem_repair`): after a registration in the hash-commit form, or one landed by
    /// someone else in that form, the `setKemKey(ua, 0, kem, UASig())` that stores `key`'s KEM key (version 0) when the commit
    /// is unfilled; `None` when nothing is to repair (no commit, or filled). `WalletLocked`; `Argument` as `prepare_register`.
    pub async fn prepare_kem_repair(
        &self,
        key: KeyRef,
        chain: String,
        payer: KeyRef,
    ) -> Result<Option<Arc<RegistryWrite>>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let Key::Ua(_, k) = crate::op::key(&sdk, &key)? else {
                    return Err(SdkError::Argument);
                };
                let ua = k.ua().ok_or(SdkError::Argument)?;
                let kem_pk = k.kem_key(0)?.kem_pk();
                let (_, _, pool) = evm(&sdk, &chain)?;
                let registry = registry_of(&sdk, &chain)?;
                if !read_record(&pool, registry, Landed::Registered, &ua).await? {
                    return Ok(None);
                }
                let hash = kem_pk_hash(&pool, registry, &ua).await?;
                let stored = if read_record(&pool, registry, Landed::Kem(0), &ua).await? {
                    // any non-empty stored key: `kem_repair` only asks whether one is stored
                    scaas_ua::ua_portable::KemKey {
                        scheme: 1,
                        ..Default::default()
                    }
                } else {
                    scaas_ua::ua_portable::KemKey::default()
                };
                let Some(fix) = scaas_ua::ua_portable::kem_repair(&ua, &hash, &stored, &kem_pk)
                    .map_err(|_| SdkError::Argument)?
                else {
                    return Ok(None);
                };
                // the fill carries no signature: the PoP signed the same `UAKemRecord` (CTR-UA-07)
                let args = json!({
                    "ua": hex(&fix.ua), "version": fix.version,
                    "kem": {"scheme": fix.kem.scheme, "mlkemEk": hex(&fix.kem.mlkem_ek), "x25519": hex(&fix.kem.x25519)},
                    "sig": {"keyData": "0x", "signature": "0x", "members": []},
                });
                Ok(Some(keep(&sdk, &chain, "setKemKey", ua, &args, &payer, Landed::Kem(0))?))
            })
            .await
    }
}

#[cfg(test)]
#[path = "register_tests.rs"]
mod tests;
