// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `msig` (spec §7 "msig"; plan T13; CTR-UA-09, CTR-UA-37, CTR-UA-38, CTR-UA-44): the structure, its state on the profile's
//! registry, the three registry writes (`registerMsig`, `acceptMembership`, `updateMsig`) as [`RegistryWrite`]s landed by the
//! record (`isRegistered`; `msigStateOf(ua).accepted` bit `i`; `msigStateOf(ua).version` at or past the update's), and signing
//! as an `msig` (`KeyRef::Msig`). `scaas-ua`'s lookups are synchronous, so every record a signature needs is read first: the
//! `msig`'s first structure (`registrationOf(ua).keyData`, the id for ever), its current one (`msigOf`) and its state
//! (`msigStateOf`), the same for each `msig` member of the current structure; then `scaas-ua` builds the signature
//! (`msig_sig_current`, `membership_sig_current`), refusing a set not minimal at either level (`UAPoP`) or a disabled slot.
//! The SDK refuses before anything is signed a slot (or an inner leaf) that is not enabled and accepted on this registry
//! (CTR-UA-37: an `msig` names no signer until then; `MsigSlotInactive`, M2). A native member signs an operation as `UAAuth`
//! under the registry's domain, gen 1 only (`predecessor() == 0`; a gen-2 registry `Argument`), and a `registerMsig` PoP as the
//! registration's typed data (`scaas-ua` `registration_typed_data`, M1).
//!
//! Members on different devices (M1, owner 2026-11-19): [`crate::op::Op::member_sign`] signs one slot of a prepared operation
//! (its check first) and returns that slot's `MemberSig`; the device that submits names it as `MsigSlot::Signed` beside its own
//! slots, each signed apart (`msig_slot_sig_current`) and combined by `msig_combine` (index order, minimal). A passkey or
//! secure-element row signs a slot through the external flow (M5): a dry run that only refuses, then the device asked for
//! `uaMessage(kind, member, memberDigest(msig, uaMessage(msig, purpose, digest)))`, then `scaas-ua` verifies its answer.
//! UNAUDITED.
use super::register::{
    keep_with, registry_of, slot_signer, writes, GasShape, Landed, RegistryWrite,
};
use super::Account;
use crate::op::{evm, hex, key_opened, sim, unhex, Key, KeyRef, MsigSlot};
use crate::{Sdk, SdkError};
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, U256};
use alloy::rpc::types::TransactionRequest;
use scaas_rpc::evm::EvmPool;
use scaas_ua::ua_portable::{
    msig_update_digest, plan_msig_update, MsigMember, MsigStructure, MsigUpdateState, UASig,
};
use scaas_ua::ua_portable::{InnerSig, MemberSig};
use scaas_ua::wallet::{
    membership_sig_current, msig_combine, msig_sig_current, msig_slot_sig_current,
    msig_update_typed_data, registration_typed_data, scaas_purpose, sign_scaas, Expect,
    ExternalKey, Slot, TypedData,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const MSIG: u16 = 0x0120;

/// One member of an `msig` structure (CTR-UA-09): its kind, its id (`0x` + 64 hex), its weight.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct MsigMemberArgs {
    pub kind: u16,
    pub id: String,
    pub weight: u16,
}

/// An `msig` structure: the threshold and the members, in slot order.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct MsigStructureArgs {
    pub threshold: u16,
    pub members: Vec<MsigMemberArgs>,
}

impl MsigStructureArgs {
    fn typed(&self) -> Result<MsigStructure, SdkError> {
        let members = self
            .members
            .iter()
            .map(|m| {
                Ok(MsigMember {
                    kind: m.kind,
                    id: id32(&m.id)?,
                    weight: m.weight,
                })
            })
            .collect::<Result<Vec<_>, SdkError>>()?;
        Ok(MsigStructure {
            threshold: self.threshold,
            members,
        })
    }

    fn of(s: &MsigStructure) -> Self {
        MsigStructureArgs {
            threshold: s.threshold,
            members: s
                .members
                .iter()
                .map(|m| MsigMemberArgs {
                    kind: m.kind,
                    id: hex(&m.id),
                    weight: m.weight,
                })
                .collect(),
        }
    }

    /// The UA of this structure registered as a new `msig` (`keccak256(TAG(msig) ‖ keyData)`, CTR-UA-44 MM-1).
    pub fn ua(&self) -> Result<String, SdkError> {
        let kd = self.typed()?.key_data();
        Ok(hex(&scaas_ua::derive_ua(MSIG, &kd, false).map_err(ua_err)?))
    }
}

/// `msig_structure(members, threshold)` (spec §7): the members sorted by id (CTR-UA-09: strictly), the threshold at least 1 and
/// at most the total weight, every weight at least 1; `Argument` otherwise (one id twice included). The registry checks the
/// rest (kinds, registered members, the bound).
pub fn msig_structure(
    mut members: Vec<MsigMemberArgs>,
    threshold: u16,
) -> Result<MsigStructureArgs, SdkError> {
    for m in &mut members {
        m.id = hex(&id32(&m.id)?);
    }
    members.sort_by(|a, b| a.id.cmp(&b.id));
    let total: u32 = members.iter().map(|m| u32::from(m.weight)).sum();
    if threshold == 0
        || u32::from(threshold) > total
        || members.iter().any(|m| m.weight == 0)
        || members
            .windows(2)
            .any(|w| w.first().map(|m| &m.id) == w.get(1).map(|m| &m.id))
    {
        return Err(SdkError::Argument);
    }
    Ok(MsigStructureArgs { threshold, members })
}

/// One slot of an `msig` as the registry holds it now.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct MsigSlotState {
    pub kind: u16,
    pub id: String,
    pub weight: u16,
    pub enabled: bool,
    /// accepted (CTR-UA-37; never cleared, whether enabled or not)
    pub accepted: bool,
    /// `memberSigHashOf(ua, i)` (`0x` + 64 hex; zero for a slot not accepted): what a copy to another registry checks
    pub sig_hash: String,
}

/// An `msig` on the profile's registry (`msig_state`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct MsigState {
    pub ua: String,
    /// the structure the id derives from (`registrationOf`)
    pub first: MsigStructureArgs,
    /// the current threshold (`msigOf`)
    pub threshold: u16,
    /// the current slots, disabled ones included
    pub slots: Vec<MsigSlotState>,
    /// `msigStateOf`'s update counter (0: never updated here)
    pub version: u64,
    /// the weight of the slots enabled and accepted
    pub active_weight: u32,
    /// that weight reaches the threshold: until then the `msig` authorizes nothing (CTR-UA-37)
    pub active: bool,
}

/// `prepare_msig_register`: the `msig` `structure` registered on `chain` (`registerMsig`), its `pop` signed by `slots` (a
/// minimal set, CTR-UA-07; none: an empty `pop`, a classical-dominant `msig`'s), sent by `payer`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct MsigRegister {
    pub chain: String,
    pub structure: MsigStructureArgs,
    pub slots: Vec<MsigSlot>,
    pub payer: KeyRef,
}

/// `accept_membership` (CTR-UA-37): slot `slot` of the `msig` `ua` accepts on `chain`, sent by `payer`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct AcceptMembership {
    pub chain: String,
    pub ua: String,
    pub slot: MsigSlot,
    pub payer: KeyRef,
}

/// `update_msig` (CTR-UA-44): the `msig` `ua` on `chain`'s registry becomes `structure` (every slot, the stored ones unchanged,
/// new members appended), `enabled` the slots that count, valid to block `valid_until_block`; signed by `slots` of the
/// **stored** structure, sent by `payer`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct UpdateMsig {
    pub chain: String,
    pub ua: String,
    pub structure: MsigStructureArgs,
    pub enabled: Vec<u16>,
    pub valid_until_block: u64,
    pub slots: Vec<MsigSlot>,
    pub payer: KeyRef,
    /// the caller's facts for `plan_msig_update` (M4, owner 2026-11-19): a token names this `msig` as its PQZ verifier; the UA is
    /// in use on a family with no `msig` update yet. Whether it holds a PQZ key is read (`pqzKeyAt(ua, 0)`).
    pub verifier: bool,
    pub family_without_update: bool,
}

/// A prepared update: its write and `scaas-ua`'s warnings (`plan_msig_update`, none a refusal), in their `Debug` form.
#[derive(Debug)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", serde(deny_unknown_fields))]
pub struct MsigUpdatePlan {
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::handle"))]
    pub write: Arc<RegistryWrite>,
    pub warnings: Vec<String>,
}

/// One `msig` as read from the registry.
#[derive(Debug, Clone)]
struct View {
    first: Vec<u8>,
    current: Vec<u8>,
    version: u64,
    enabled: [u8; 32],
    accepted: [u8; 32],
}

impl View {
    fn active(&self, i: u16) -> bool {
        bit(&self.enabled, i) && bit(&self.accepted, i)
    }
}

fn bit(w: &[u8; 32], i: u16) -> bool {
    let i = usize::from(i);
    i < 256 && w.get(31 - i / 8).is_some_and(|b| b >> (i % 8) & 1 == 1)
}

fn id32(s: &str) -> Result<[u8; 32], SdkError> {
    unhex(&s.to_ascii_lowercase())?
        .try_into()
        .map_err(|_| SdkError::Argument)
}

fn bad() -> SdkError {
    SdkError::Rpc(scaas_rpc::RpcError::EndpointAllFailed {
        last: None,
        failover_revert: None,
    })
}

fn word(out: &[u8], at: usize) -> Option<U256> {
    out.get(at..at.checked_add(32)?).map(U256::from_be_slice)
}

fn small(out: &[u8], at: usize, max: u64) -> Option<usize> {
    word(out, at)
        .filter(|w| *w <= U256::from(max))
        .and_then(|w| usize::try_from(w).ok())
}

async fn call(
    pool: &EvmPool,
    registry: Address,
    sig: &str,
    args: &[[u8; 32]],
) -> Result<Vec<u8>, SdkError> {
    let mut d = scaas_ua::keccak256(sig.as_bytes())
        .get(..4)
        .unwrap_or_default()
        .to_vec();
    for a in args {
        d.extend_from_slice(a);
    }
    let tx = TransactionRequest::default()
        .with_to(registry)
        .with_input(Bytes::from(d));
    pool.call_tx(tx).await.map(|b| b.to_vec()).map_err(sim)
}

/// `registrationOf(ua).keyData`, at most 256 slots' bytes.
fn decode_key_data(out: &[u8]) -> Option<Vec<u8>> {
    let off = small(out, 32, 1 << 20)?;
    let len = small(out, off, 4 + 36 * 256)?;
    out.get(off + 32..off + 32 + len).map(<[u8]>::to_vec)
}

/// `msigOf(ua)`: `(uint16 threshold, (uint16 kind, bytes32 id, uint16 weight)[] members)`, at most 256 members, as key data.
pub(crate) fn decode_structure(out: &[u8]) -> Option<Vec<u8>> {
    let base = small(out, 0, 1 << 20)?;
    let threshold = u16::try_from(small(out, base, u64::from(u16::MAX))?).ok()?;
    let list = base.checked_add(small(out, base + 32, 1 << 20)?)?;
    let n = small(out, list, 256)?;
    let members = (0..n)
        .map(|i| {
            let at = list + 32 + 96 * i;
            Some(MsigMember {
                kind: u16::try_from(small(out, at, u64::from(u16::MAX))?).ok()?,
                id: out.get(at + 32..at + 64)?.try_into().ok()?,
                weight: u16::try_from(small(out, at + 64, u64::from(u16::MAX))?).ok()?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(MsigStructure { threshold, members }.key_data())
}

/// The `msig` `ua` on `registry`: `Argument` when it holds no `msig` of that id.
async fn view(pool: &EvmPool, registry: Address, ua: &[u8; 32]) -> Result<View, SdkError> {
    let first = decode_key_data(&call(pool, registry, "registrationOf(bytes32)", &[*ua]).await?)
        .ok_or_else(bad)?;
    if scaas_ua::derive_ua(MSIG, &first, false).ok() != Some(*ua) {
        return Err(SdkError::Argument);
    }
    let current = decode_structure(&call(pool, registry, "msigOf(bytes32)", &[*ua]).await?)
        .ok_or_else(bad)?;
    let st = call(pool, registry, "msigStateOf(bytes32)", &[*ua]).await?;
    let w = |i: usize| -> Result<[u8; 32], SdkError> {
        st.get(32 * i..32 * i + 32)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(bad)
    };
    if st.len() != 96 {
        return Err(bad());
    }
    Ok(View {
        version: u64::try_from(U256::from_be_bytes(w(0)?)).map_err(|_| bad())?,
        enabled: w(1)?,
        accepted: w(2)?,
        first,
        current,
    })
}

/// The views of `ids` and of each `msig` member of their current structures (two levels).
async fn views(
    pool: &EvmPool,
    registry: Address,
    ids: &[[u8; 32]],
) -> Result<HashMap<[u8; 32], View>, SdkError> {
    let mut out = HashMap::new();
    for id in ids {
        let v = view(pool, registry, id).await?;
        for m in structure(&v.current)?.members {
            if m.kind == MSIG && !out.contains_key(&m.id) {
                out.insert(m.id, view(pool, registry, &m.id).await?);
            }
        }
        out.insert(*id, v);
    }
    Ok(out)
}

/// The keys of `slots` in their order (a slot's key, then an `msig` slot's leaves); a key that is an `msig` itself `Argument`.
/// A slot signed elsewhere (`Signed`) has none.
async fn open(sdk: &Sdk, slots: &[MsigSlot]) -> Result<Vec<Key>, SdkError> {
    let mut keys = vec![];
    for s in slots {
        let refs: Vec<&KeyRef> = match s {
            MsigSlot::Member { key, .. } => vec![key],
            MsigSlot::Msig { members, .. } => members.iter().map(|l| &l.key).collect(),
            MsigSlot::Signed { .. } => vec![],
        };
        for r in refs {
            // a slot's key is a single key: never an `msig` nor a `bls12381-multi` group (M16; a group slot PLANNED)
            if matches!(r, KeyRef::Msig { .. } | KeyRef::BlsMulti { .. }) {
                return Err(SdkError::Argument);
            }
            keys.push(key_opened(sdk, r).await?);
        }
    }
    Ok(keys)
}

/// `scaas-ua`'s slots over the opened `keys` (as [`open`] ordered them).
fn ua_slots<'a>(slots: &[MsigSlot], keys: &'a [Key]) -> Result<Vec<Slot<'a>>, SdkError> {
    let mut it = keys.iter();
    let mut next = || it.next().map(Key::signer).ok_or(SdkError::Internal);
    slots
        .iter()
        .map(|s| {
            Ok(match s {
                MsigSlot::Member { index, .. } => Slot::Member {
                    index: *index,
                    key: next()?,
                },
                MsigSlot::Msig { index, members } => Slot::Msig {
                    index: *index,
                    members: members
                        .iter()
                        .map(|l| Ok((l.index, next()?)))
                        .collect::<Result<_, SdkError>>()?,
                },
                MsigSlot::Signed { .. } => return Err(SdkError::Argument),
            })
        })
        .collect()
}

/// Each `msig` slot's leaves enabled and accepted in that inner `msig`, `structure` the outer's (CTR-UA-37: an inner names
/// no signer until then). `Argument` before anything is signed.
fn leaves_active(
    views: &HashMap<[u8; 32], View>,
    structure: &MsigStructure,
    slots: &[MsigSlot],
) -> Result<(), SdkError> {
    for s in slots {
        if let MsigSlot::Msig { index, members } = s {
            let id = structure
                .members
                .get(usize::from(*index))
                .ok_or(SdkError::Argument)?
                .id;
            let v = views.get(&id).ok_or(SdkError::Argument)?;
            if members.iter().any(|l| !v.active(l.index)) {
                return Err(SdkError::MsigSlotInactive);
            }
        }
    }
    Ok(())
}

/// Every slot enabled and accepted in `v` (the outer `msig`), and every leaf in its inner one: `MsigSlotInactive` otherwise
/// (M2).
fn slots_active(
    views: &HashMap<[u8; 32], View>,
    v: &View,
    slots: &[MsigSlot],
) -> Result<(), SdkError> {
    for s in slots {
        if !v.active(s.index()) {
            return Err(SdkError::MsigSlotInactive);
        }
    }
    leaves_active(views, &structure(&v.current)?, slots)
}

fn ua_err(e: scaas_ua::UAError) -> SdkError {
    SdkError::Ua(e.into())
}

fn structure(kd: &[u8]) -> Result<MsigStructure, SdkError> {
    MsigStructure::from_key_data(kd).map_err(ua_err)
}

/// The registry's domain for a native member's `UAAuth` (gen 1 only: `predecessor() == 0`).
pub(crate) async fn domain(
    sdk: &Sdk,
    chain: &str,
    pool: &EvmPool,
    registry: Address,
) -> Result<scaas_ua::Domain, SdkError> {
    let (profile, chain_id, _) = evm(sdk, chain)?;
    let pred = call(pool, registry, "predecessor()", &[]).await?;
    if word(&pred, 0) != Some(U256::ZERO) {
        return Err(SdkError::Argument);
    }
    Ok(scaas_ua::Domain {
        generation: 1,
        chain_id,
        registry: registry.into_array(),
        chain_uid: id32(&profile.chain_uid)?,
    })
}

/// A `MemberSig` from its JSON (`{index, members: [{index, sig}], sig}`, `0x` hex), as [`members_json`] writes one: bounded
/// (64 KiB, 256 inner signatures), else `Argument`.
fn member_of(s: &str) -> Result<MemberSig, SdkError> {
    if s.len() > 64 << 10 {
        return Err(SdkError::Argument);
    }
    let v: Value = serde_json::from_str(s).map_err(|_| SdkError::Argument)?;
    let index = |v: &Value| -> Result<u16, SdkError> {
        let n = match v.get("index") {
            Some(Value::Number(n)) => n.as_u64(),
            Some(Value::String(s)) => s.parse().ok(),
            _ => None,
        };
        n.and_then(|n| u16::try_from(n).ok())
            .ok_or(SdkError::Argument)
    };
    let sig = |v: &Value| {
        v.get("sig")
            .and_then(Value::as_str)
            .ok_or(SdkError::Argument)
            .and_then(unhex)
    };
    let inner = v
        .get("members")
        .and_then(Value::as_array)
        .ok_or(SdkError::Argument)?;
    if inner.len() > 256 {
        return Err(SdkError::Argument);
    }
    Ok(MemberSig {
        index: index(&v)?,
        members: inner
            .iter()
            .map(|m| {
                Ok(InnerSig {
                    index: index(m)?,
                    sig: sig(m)?,
                })
            })
            .collect::<Result<_, SdkError>>()?,
        sig: sig(&v)?,
    })
}

/// F1 (review 2026-11-20): a slot signed on another device names what it signed (`ua`, `purpose`, `digest`, as
/// [`crate::op::Op::member_sign`] writes them); the submitting device combines it only over its own prepared operation:
/// `PreparedStale` when it names another (that device prepared another nonce or `validUntil`, or the JSON is of another
/// operation), `Argument` when it names none. The signatures themselves stay the registry's to check (PLANNED: a
/// `scaas-ua` verifier of a `MemberSig`).
fn bound_to(
    member: &str,
    ua: &[u8; 32],
    purpose: &[u8; 32],
    digest: &[u8; 32],
) -> Result<(), SdkError> {
    let v: Value = serde_json::from_str(member).map_err(|_| SdkError::Argument)?;
    let got = |k: &str| -> Result<[u8; 32], SdkError> {
        id32(v.get(k).and_then(Value::as_str).ok_or(SdkError::Argument)?)
    };
    if got("ua")? != *ua || got("purpose")? != *purpose || got("digest")? != *digest {
        return Err(SdkError::PreparedStale);
    }
    Ok(())
}

/// One local slot's `MemberSig` (M1) over `uaMessage(msig, purpose, digest)`; a passkey or secure-element member through the
/// external flow (M5: a dry run that only refuses, then the device, then `scaas-ua` verifies its answer).
#[allow(clippy::too_many_arguments)]
async fn slot_sig(
    sdk: &Sdk,
    views: &HashMap<[u8; 32], View>,
    first: &[u8],
    ua: &[u8; 32],
    s: &MsigSlot,
    purpose: &[u8; 32],
    digest: &[u8; 32],
    d: Option<&scaas_ua::Domain>,
    record: Option<&TypedData>,
) -> Result<MemberSig, SdkError> {
    let keys = open(sdk, std::slice::from_ref(s)).await?;
    let current = |id: [u8; 32]| views.get(&id).map(|v| (v.current.clone(), v.enabled));
    let inner = |id: [u8; 32]| views.get(&id).map(|v| v.first.clone());
    if let (MsigSlot::Member { index, .. }, Some(Key::External(row, _))) = (s, keys.first()) {
        let asked = AtomicBool::new(false);
        let refuse = ExternalKey::new(row.key_ref(), |_| {
            asked.store(true, Ordering::SeqCst);
            Err(scaas_ua::wallet::Error::ExternalSignature)
        });
        let slot = Slot::Member {
            index: *index,
            key: &refuse,
        };
        let dry = msig_slot_sig_current(first, &current, &inner, purpose, digest, d, record, &slot);
        if !asked.load(Ordering::SeqCst) {
            return Err(dry.err().map_or(SdkError::Internal, SdkError::from));
        }
        let md = scaas_ua::member_digest(
            ua,
            &scaas_ua::ua_message(MSIG, purpose, digest).map_err(ua_err)?,
        );
        let tag = scaas_ua::purpose_tag("member").map_err(ua_err)?;
        let answer = crate::op::external::answer(sdk, row, &tag, &md).await?;
        let device = ExternalKey::new(row.key_ref(), move |_| Ok(answer.clone()));
        let slot = Slot::Member {
            index: *index,
            key: &device,
        };
        return Ok(msig_slot_sig_current(
            first, &current, &inner, purpose, digest, d, record, &slot,
        )?);
    }
    let slots = ua_slots(std::slice::from_ref(s), &keys)?;
    Ok(msig_slot_sig_current(
        first,
        &current,
        &inner,
        purpose,
        digest,
        d,
        record,
        slots.first().ok_or(SdkError::Internal)?,
    )?)
}

/// The `UASig` of the `msig` `ua` over `uaMessage(msig, purpose, digest)` by `slots` (module doc); `record` what a native
/// member signs in a portable purpose. Local key slots only: one `scaas-ua` call over the set; with a slot signed elsewhere or
/// a stored key row: each slot apart, then `msig_combine`.
async fn uasig(
    sdk: &Sdk,
    chain: &str,
    ua: &[u8; 32],
    slots: &[MsigSlot],
    purpose: &[u8; 32],
    digest: &[u8; 32],
) -> Result<UASig, SdkError> {
    let (_, _, pool) = evm(sdk, chain)?;
    let registry = registry_of(sdk, chain)?;
    let views = views(&pool, registry, &[*ua]).await?;
    let v = views.get(ua).ok_or(SdkError::Internal)?;
    slots_active(&views, v, slots)?;
    let keys = open(sdk, slots).await?;
    let native = keys.iter().any(|k| matches!(k, Key::Native(..)));
    let d = match native {
        true => Some(domain(sdk, chain, &pool, registry).await?),
        false => None,
    };
    let current = |id: [u8; 32]| views.get(&id).map(|v| (v.current.clone(), v.enabled));
    let inner = |id: [u8; 32]| views.get(&id).map(|v| v.first.clone());
    let apart = slots.iter().any(|s| matches!(s, MsigSlot::Signed { .. }))
        || keys.iter().any(|k| matches!(k, Key::External(..)));
    if !apart {
        return Ok(msig_sig_current(
            &v.first,
            &current,
            &inner,
            purpose,
            digest,
            d.as_ref(),
            None,
            &ua_slots(slots, &keys)?,
        )?);
    }
    drop(keys);
    let mut members = Vec::with_capacity(slots.len());
    for s in slots {
        members.push(match s {
            MsigSlot::Signed { index, member } => {
                let m = member_of(member)?;
                if m.index != *index {
                    return Err(SdkError::Argument);
                }
                bound_to(member, ua, purpose, digest)?;
                m
            }
            _ => {
                slot_sig(
                    sdk,
                    &views,
                    &v.first,
                    ua,
                    s,
                    purpose,
                    digest,
                    d.as_ref(),
                    None,
                )
                .await?
            }
        });
    }
    Ok(msig_combine(&v.first, &current, &members)?)
}

/// F2 (controller call 2026-11-22, CLI-PQV-15; PqVault's dedicated path): the `UAAuth` domain a signature of `of` is checked in
/// on the line ending at `registry`, of any generation. A record a predecessor holds (`holderOf`, when `registry` has a
/// predecessor) is checked by its holder, in the holder's domain (`requireAuthorized` hands it there, CTR-UA-60 §4); `of`
/// none (a native signer), a native id, or a record `registry` holds, in `registry`'s own. The generation is the registry's `generation()`: its domain's
/// version.
#[cfg(feature = "app-core")]
pub(crate) async fn line_domain(
    sdk: &Sdk,
    chain: &str,
    pool: &EvmPool,
    registry: Address,
    of: Option<[u8; 32]>,
) -> Result<scaas_ua::Domain, SdkError> {
    let (profile, chain_id, _) = evm(sdk, chain)?;
    let mut at = registry;
    if let Some(of) = of.filter(|x| !scaas_ua::in_native_space(x)) {
        let pred = call(pool, registry, "predecessor()", &[]).await?;
        if word(&pred, 0).ok_or(SdkError::Argument)? != U256::ZERO {
            let h = call(pool, registry, "holderOf(bytes32)", &[of]).await?;
            let w = word(&h, 0).ok_or(SdkError::Argument)?;
            let holder = Address::from_word(alloy::primitives::B256::from(w));
            if holder != Address::ZERO {
                at = holder;
            }
        }
    }
    let g = call(pool, at, "generation()", &[]).await?;
    let generation = small(&g, 0, 16)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n >= 1)
        .ok_or(SdkError::Argument)?;
    Ok(scaas_ua::Domain {
        generation,
        chain_id,
        registry: at.into_array(),
        chain_uid: id32(&profile.chain_uid)?,
    })
}

/// An app record's `UASig` by the `msig` `ua` (PqVault's dedicated path, owner 2026-11-22): the records read as [`uasig`]
/// reads them, the slots checked enabled and accepted, their keys opened (local keys only: a slot signed elsewhere or a
/// stored key row `Argument`), the registry generation's domain when a member is native; `sign` builds the `UASig`.
#[cfg(feature = "app-core")]
pub(crate) async fn app_msig(
    sdk: &Sdk,
    chain: &str,
    ua: &[u8; 32],
    slots: &[MsigSlot],
    sign: impl FnOnce(
        &[u8],
        &scaas_ua::ua_portable::Current,
        &scaas_ua::ua_portable::Inner,
        Option<&scaas_ua::Domain>,
        &[Slot],
    ) -> scaas_ua::wallet::Result<UASig>,
) -> Result<UASig, SdkError> {
    if slots.is_empty() || slots.iter().any(|s| matches!(s, MsigSlot::Signed { .. })) {
        return Err(SdkError::Argument);
    }
    let (_, _, pool) = evm(sdk, chain)?;
    let registry = registry_of(sdk, chain)?;
    let views = views(&pool, registry, &[*ua]).await?;
    let v = views.get(ua).ok_or(SdkError::Internal)?;
    slots_active(&views, v, slots)?;
    let keys = open(sdk, slots).await?;
    if keys.iter().any(|k| matches!(k, Key::External(..))) {
        return Err(SdkError::Argument);
    }
    // F2: the domain of the generation that holds the `msig` (its native members sign there)
    let d = match keys.iter().any(|k| matches!(k, Key::Native(..))) {
        true => Some(line_domain(sdk, chain, &pool, registry, Some(*ua)).await?),
        false => None,
    };
    let current = |id: [u8; 32]| views.get(&id).map(|v| (v.current.clone(), v.enabled));
    let inner = |id: [u8; 32]| views.get(&id).map(|v| v.first.clone());
    Ok(sign(
        &v.first,
        &current,
        &inner,
        d.as_ref(),
        &ua_slots(slots, &keys)?,
    )?)
}

/// An operation's `UASig` by the `msig` `ua` (`KeyRef::Msig`, spec §13.4): the entry's check first (`sign_scaas` through a
/// key that only refuses: `PolicyRefused` before any member key signs), then [`uasig`] under the entry's purpose.
pub(crate) async fn sign_typed(
    sdk: &Sdk,
    chain: &str,
    ua: &str,
    slots: &[MsigSlot],
    td: &TypedData,
    expect: &Expect,
) -> Result<UASig, SdkError> {
    let ua = id32(ua)?;
    check_first(sdk, slots, td, expect).await?;
    uasig(sdk, chain, &ua, slots, &scaas_purpose(td)?, &td.digest()?).await
}

/// The entry's check through the first local slot's key, a key that only refuses: `PolicyRefused` (or the typed data's own
/// error) before any member key signs; `Argument` when no slot is local.
async fn check_first(
    sdk: &Sdk,
    slots: &[MsigSlot],
    td: &TypedData,
    expect: &Expect,
) -> Result<(), SdkError> {
    let probe = slots
        .iter()
        .find_map(|s| match s {
            MsigSlot::Member { key, .. } => Some(key),
            MsigSlot::Msig { members, .. } => members.first().map(|l| &l.key),
            MsigSlot::Signed { .. } => None,
        })
        .ok_or(SdkError::Argument)?;
    let k = key_opened(sdk, probe).await?;
    let asked = AtomicBool::new(false);
    let refuse = ExternalKey::new(k.signer().key_ref(), |_| {
        asked.store(true, Ordering::SeqCst);
        Err(scaas_ua::wallet::Error::ExternalSignature)
    });
    let dry = sign_scaas(&refuse, td, expect.clone());
    if !asked.load(Ordering::SeqCst) {
        return Err(dry.err().map_or(SdkError::Internal, SdkError::from));
    }
    Ok(())
}

impl crate::op::Op {
    /// One member's signature of a prepared operation signed by an `msig` (M1, owner 2026-11-19: members on different
    /// devices): `prepared`'s signer is `KeyRef::Msig` with exactly one local slot; the entry's check runs first, then that slot
    /// signs (its keys enabled and accepted, `MsigSlotInactive` otherwise). The `MemberSig` JSON the submitting device names as
    /// `MsigSlot::Signed`. Nothing is sent. `PreparedUnknown`, `PolicyRefused`, `Argument` (another signer, several slots).
    pub async fn member_sign(
        &self,
        prepared: Arc<crate::op::Prepared>,
    ) -> Result<String, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                crate::op::Op::known(&sdk, &prepared)?;
                let KeyRef::Msig { ua, slots } = prepared.signer() else {
                    return Err(SdkError::Argument);
                };
                let [slot] = slots.as_slice() else {
                    return Err(SdkError::Argument);
                };
                if matches!(slot, MsigSlot::Signed { .. }) {
                    return Err(SdkError::Argument);
                }
                let (td, expect) = (&prepared.t.td, &prepared.t.expect);
                check_first(&sdk, &slots, td, expect).await?;
                let ua = id32(&ua)?;
                let chain = prepared.chain();
                let (_, _, pool) = evm(&sdk, &chain)?;
                let registry = registry_of(&sdk, &chain)?;
                let views = views(&pool, registry, &[ua]).await?;
                let v = views.get(&ua).ok_or(SdkError::Internal)?;
                slots_active(&views, v, &slots)?;
                let d = match has_native(&sdk, slot).await? {
                    true => Some(domain(&sdk, &chain, &pool, registry).await?),
                    false => None,
                };
                let (purpose, digest) = (scaas_purpose(td)?, td.digest()?);
                let m = slot_sig(
                    &sdk,
                    &views,
                    &v.first,
                    &ua,
                    slot,
                    &purpose,
                    &digest,
                    d.as_ref(),
                    None,
                )
                .await?;
                let j = members_json(&UASig {
                    members: vec![m],
                    ..Default::default()
                })?;
                let mut j = j.get(0).cloned().ok_or(SdkError::Internal)?;
                // what it signed, for the submitting device's check (F1)
                let o = j.as_object_mut().ok_or(SdkError::Internal)?;
                o.insert("ua".into(), Value::from(hex(&ua)));
                o.insert("purpose".into(), Value::from(hex(&purpose)));
                o.insert("digest".into(), Value::from(hex(&digest)));
                serde_json::to_string(&j).map_err(|_| SdkError::Internal)
            })
            .await
    }
}

/// Whether `slot` holds a native member, by its opened keys as `uasig` decides (F7: an imported EVM key is a native member too).
async fn has_native(sdk: &Sdk, slot: &MsigSlot) -> Result<bool, SdkError> {
    Ok(open(sdk, std::slice::from_ref(slot))
        .await?
        .iter()
        .any(|k| matches!(k, Key::Native(..))))
}

/// `MemberSig[]` as the registry calls take them.
fn members_json(s: &UASig) -> Result<Value, SdkError> {
    let v: Value =
        serde_json::from_str(&scaas_ua::json::uasig_json(s)).map_err(|_| SdkError::Internal)?;
    v.get("members").cloned().ok_or(SdkError::Internal)
}

impl Account {
    /// The `msig` `ua` (`0x` + 64 hex) on `chain`'s registry: its first and current structures, each slot enabled and accepted
    /// apart, its update counter, whether it can authorize (CTR-UA-37). `Argument`: no `msig` of that id there.
    pub async fn msig_state(&self, chain: String, ua: String) -> Result<MsigState, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let id = id32(&ua)?;
                let (_, _, pool) = evm(&sdk, &chain)?;
                let registry = registry_of(&sdk, &chain)?;
                let v = view(&pool, registry, &id).await?;
                let current = structure(&v.current)?;
                let mut slots = vec![];
                let mut active_weight = 0u32;
                for (i, m) in current.members.iter().enumerate() {
                    let i = u16::try_from(i).map_err(|_| SdkError::Internal)?;
                    let accepted = bit(&v.accepted, i);
                    let sig_hash = match accepted {
                        true => {
                            let out = call(
                                &pool,
                                registry,
                                "memberSigHashOf(bytes32,uint256)",
                                &[id, U256::from(i).to_be_bytes()],
                            )
                            .await?;
                            out.get(..32)
                                .map(hex)
                                .filter(|_| out.len() == 32)
                                .ok_or_else(bad)?
                        }
                        false => hex(&[0; 32]),
                    };
                    if v.active(i) {
                        active_weight += u32::from(m.weight);
                    }
                    slots.push(MsigSlotState {
                        kind: m.kind,
                        id: hex(&m.id),
                        weight: m.weight,
                        enabled: bit(&v.enabled, i),
                        accepted,
                        sig_hash,
                    });
                }
                Ok(MsigState {
                    ua: hex(&id),
                    first: MsigStructureArgs::of(&structure(&v.first)?),
                    threshold: current.threshold,
                    slots,
                    version: v.version,
                    active: active_weight >= u32::from(current.threshold),
                    active_weight,
                })
            })
            .await
    }

    /// `registerMsig` of `req.structure` (spec §7): its `pop` by `req.slots` over the registration digest (`pop` v2; a native
    /// member's slot is not built here: `Argument`), the arguments by `scaas-ua` (`registration_args`), skipped when the UA is
    /// registered. An `msig` member must be registered first (its structures are read).
    pub async fn prepare_msig_register(
        &self,
        req: MsigRegister,
    ) -> Result<Vec<Arc<RegistryWrite>>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let s = req.structure.typed()?;
                let kd = s.key_data();
                let ua = scaas_ua::derive_ua(MSIG, &kd, false).map_err(ua_err)?;
                let (_, _, pool) = evm(&sdk, &req.chain)?;
                let registry = registry_of(&sdk, &req.chain)?;
                let inners: Vec<[u8; 32]> = s.members.iter().filter(|m| m.kind == MSIG).map(|m| m.id).collect();
                let views = views(&pool, registry, &inners).await?;
                let pop = match req.slots.is_empty() {
                    true => json!([]),
                    false => {
                        leaves_active(&views, &s, &req.slots)?;
                        let hp = scaas_ua::holder_pop_message(MSIG, &ua, &kd, None, None, None, None)
                            .map_err(|_| SdkError::Argument)?;
                        let keys = open(&sdk, &req.slots).await?;
                        let current = |id: [u8; 32]| views.get(&id).map(|v| (v.current.clone(), v.enabled));
                        let inner = |id: [u8; 32]| views.get(&id).map(|v| v.first.clone());
                        // a native member signs the registration's typed data itself (M1)
                        let record = registration_typed_data(&ua, MSIG, &hp.pqz_key_hash, &hp.pqz_pop_hash)?;
                        let sig = msig_sig_current(
                            &kd,
                            &current,
                            &inner,
                            &scaas_ua::ua_portable::pop_v2_tag(),
                            &hp.registration_digest,
                            None,
                            Some(&record),
                            &ua_slots(&req.slots, &keys)?,
                        )?;
                        members_json(&sig)?
                    }
                };
                let inner: serde_json::Map<String, Value> =
                    views.iter().map(|(id, v)| (hex(id), json!(hex(&v.first)))).collect();
                let input = json!({"kind": MSIG, "keyData": hex(&kd), "pqzKey": "0x", "pqzPopHash": "0x", "pqzPop": "0x",
                    "kemPk": "0x", "pop": pop, "inner": inner});
                let r: Value = serde_json::from_str(
                    &scaas_ua::json::registration_args_json(&input.to_string()).map_err(|_| SdkError::Argument)?,
                )
                .map_err(|_| SdkError::Internal)?;
                let args = r.get("args").ok_or(SdkError::Internal)?;
                writes(&sdk, &req.chain, &req.payer, ua, args, None).await
            })
            .await
    }

    /// `acceptMembership(ua, memberSig)` of `req.slot` (CTR-UA-37), signed over typed `UAMembership{ua, member}` by
    /// `scaas-ua` (`membership_sig_current`, the current structure: an appended slot accepts too); landed when the slot's
    /// accepted bit is set. `None`: the slot accepted already.
    pub async fn prepare_accept_membership(
        &self,
        req: AcceptMembership,
    ) -> Result<Option<Arc<RegistryWrite>>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let ua = id32(&req.ua)?;
                let (_, _, pool) = evm(&sdk, &req.chain)?;
                let registry = registry_of(&sdk, &req.chain)?;
                let views = views(&pool, registry, &[ua]).await?;
                let v = views.get(&ua).ok_or(SdkError::Internal)?;
                let index = req.slot.index();
                if bit(&v.accepted, index) {
                    return Ok(None);
                }
                // the slot itself accepts now; an inner `msig`'s leaves must count there
                let slots = [req.slot.clone()];
                let cur = structure(&v.current)?;
                leaves_active(&views, &cur, &slots)?;
                // its gas rows (controller call, owner auto-run 2026-11-19): by the current structure's members, the slot's
                // verify row
                let shape = GasShape {
                    rows: vec![("acceptMembership".into(), "msig".into())],
                    members: cur.members.len() as u64,
                    signers: vec![cur
                        .members
                        .get(usize::from(index))
                        .map_or(u16::MAX, |m| slot_signer(m.kind))],
                };
                let keys = open(&sdk, &slots).await?;
                let current = |id: [u8; 32]| views.get(&id).map(|v| (v.current.clone(), v.enabled));
                let inner = |id: [u8; 32]| views.get(&id).map(|v| v.first.clone());
                let s = ua_slots(&slots, &keys)?;
                let m = membership_sig_current(
                    &v.first,
                    &current,
                    &inner,
                    s.first().ok_or(SdkError::Internal)?,
                )?;
                let ms = members_json(&UASig {
                    members: vec![m],
                    ..Default::default()
                })?;
                let args =
                    json!({"ua": hex(&ua), "memberSig": ms.get(0).ok_or(SdkError::Internal)?});
                Ok(Some(
                    keep_with(
                        &sdk,
                        &req.chain,
                        "acceptMembership",
                        ua,
                        &args,
                        &req.payer,
                        Landed::Accepted(index),
                        shape,
                        None,
                    )
                    .await?,
                ))
            })
            .await
    }

    /// `updateMsig` (CTR-UA-44): the stored structure, version and bits read from the registry, the update planned by
    /// `scaas-ua` (`plan_msig_update`: version = stored + 1, the target's own refusals, `Ua(KeyData)`; its warnings returned),
    /// signed by `req.slots` of the stored structure (enabled and accepted, minimal) over typed `UAMsigUpdate` for this one
    /// registry and chain; landed when the registry's version reaches it.
    pub async fn prepare_update_msig(&self, req: UpdateMsig) -> Result<MsigUpdatePlan, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let ua = id32(&req.ua)?;
                let (profile, _, pool) = evm(&sdk, &req.chain)?;
                let registry = registry_of(&sdk, &req.chain)?;
                let views = views(&pool, registry, &[ua]).await?;
                let v = views.get(&ua).ok_or(SdkError::Internal)?;
                slots_active(&views, v, &req.slots)?;
                let mut enabled = [0u8; 32];
                for i in &req.enabled {
                    let i = usize::from(*i);
                    let b = enabled.get_mut(31usize.checked_sub(i / 8).ok_or(SdkError::Argument)?);
                    *b.ok_or(SdkError::Argument)? |= 1 << (i % 8);
                }
                // M4: whether the `msig` holds a PQZ key, read (`pqzKeyAt(ua, 0)`: a key at version 0 once any is set); the
                // verifier and family facts are the caller's
                let key = call(&pool, registry, "pqzKeyAt(bytes32,uint64)", &[ua, [0; 32]]).await?;
                let state = MsigUpdateState {
                    current: structure(&v.current)?,
                    version: v.version,
                    enabled: v.enabled,
                    accepted: v.accepted,
                    holds_pqz_key: word(&key, 0).ok_or_else(bad)? != U256::ZERO,
                    verifier: req.verifier,
                    family_without_update: req.family_without_update,
                };
                let chain_uid = id32(&profile.chain_uid)?;
                let (u, warnings) = plan_msig_update(
                    &state,
                    &ua,
                    &chain_uid,
                    &registry.into_array(),
                    &req.structure.typed()?,
                    &enabled,
                    req.valid_until_block,
                    false,
                )
                .map_err(ua_err)?;
                let keys = open(&sdk, &req.slots).await?;
                let current = |id: [u8; 32]| views.get(&id).map(|v| (v.current.clone(), v.enabled));
                let inner = |id: [u8; 32]| views.get(&id).map(|v| v.first.clone());
                let record = msig_update_typed_data(&u)?;
                let sig = msig_sig_current(
                    &v.first,
                    &current,
                    &inner,
                    &scaas_ua::purpose_tag("msig-update").map_err(ua_err)?,
                    &msig_update_digest(&u),
                    None,
                    Some(&record),
                    &ua_slots(&req.slots, &keys)?,
                )?;
                let s = MsigStructureArgs::of(&u.structure);
                let members: Vec<Value> = s
                    .members
                    .iter()
                    .map(|m| json!({"kind": m.kind, "id": m.id, "weight": m.weight}))
                    .collect();
                let input = json!({"ua": hex(&ua), "chainUid": hex(&chain_uid), "registry": format!("{registry:#x}"),
                    "version": u.version, "threshold": s.threshold, "members": members,
                    "enabled": U256::from_be_bytes(u.enabled).to_string(), "validUntilBlock": u.valid_until_block,
                    "sigs": members_json(&sig)?});
                let out: Value = serde_json::from_str(
                    &scaas_ua::json::msig_update_json(&input.to_string()).map_err(|_| SdkError::Argument)?,
                )
                .map_err(|_| SdkError::Internal)?;
                let args = out.get("args").ok_or(SdkError::Internal)?;
                // M3: landed when the registry's version reached it and its current structure is this update's
                let hash = scaas_ua::keccak256(&u.structure.key_data());
                // its gas rows (controller call, owner auto-run 2026-11-19): by the new structure's members, each signing slot of
                // the stored one by its verify row
                let shape = GasShape {
                    rows: vec![("updateMsig".into(), "msig".into())],
                    members: u.structure.members.len() as u64,
                    signers: sig
                        .members
                        .iter()
                        .map(|m| {
                            state.current.members.get(usize::from(m.index)).map_or(u16::MAX, |x| slot_signer(x.kind))
                        })
                        .collect(),
                };
                let landed = Landed::MsigUpdate(u.version, hash);
                let write = keep_with(&sdk, &req.chain, "updateMsig", ua, args, &req.payer, landed, shape, None).await?;
                Ok(MsigUpdatePlan {
                    write,
                    warnings: warnings.iter().map(|w| format!("{w:?}")).collect(),
                })
            })
            .await
    }
}

#[cfg(test)]
#[path = "msig_tests.rs"]
mod tests;
