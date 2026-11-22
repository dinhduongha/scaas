// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The `UASig` builder (spec §5.2, §9.4; T3d) over `&dyn Signer` handles: a single key's `UASig{keyData, signature, []}`
//! ([`ua_sig`]), an `msig`'s `UASig{"", "", members}` from the member slots the caller names ([`msig_sig`]), and one slot's
//! acceptance `MemberSig` (CTR-UA-37, [`membership_sig`]). Every `msig` set is minimal at both levels and strictly increasing
//! (CTR-UA-07; the registry stores and copies only that form, `UARegistryLib._msig`), else `UAPoP`, the registry's verdict, before
//! anything is signed; a minimal set also passes `requireAuthorized`'s stop at the threshold. A derived member signs
//! `uaMessage(kind, member, memberDigest(msig, ua_msg))`, an `msig` member's leaves `memberDigest` of the inner id over
//! `uaMessage(msig, member, md)` (`ua_portable::inner_digest`), as clientkeys `msigMemberSigs`. T4: a native key (`evm-eoa`, an EVM
//! key) signs typed data (CTR-UA-07, CTR-UA-24, TS-D4): as a `UASig` of its own (R17: `{"", signature, []}`) `UAAuth(id, purpose,
//! digest)` under the registry's domain; as an `msig` member, at either level, the record's typed data itself in the portable
//! purposes (`pop` v2, `kem`, `pqz-key`, `membership`), else `UAAuth(id, member, md)` of its level's member digest. UNAUDITED.
use super::eip712::{self, TypedData};
use super::sign::{app_request, check_purpose, member_request, ua_request};
use super::signer::{KeyRef, SignRequest, Signer};
use super::{bounded, Error, Network, Result};
use crate::ua_portable::{
    app_purpose, is_portable_purpose, membership_digest, msig_slots_minimal, msig_update_digest,
    portable_record_purposes, slot_enabled, Current, Inner, InnerSig, MemberSig, MsigMember,
    MsigStructure, MsigUpdate, UASig, PORTABLE_DOMAIN_SEPARATOR,
};
use crate::{derive_ua, keccak256, member_digest, purpose_tag, ua_message, Domain, UAError};
use serde_json::Value;

const MSIG: u16 = 0x0120;
const EVM_EOA: u16 = 0x0001;

/// One slot of an `msig` signature, named by the caller.
pub enum Slot<'a> {
    /// The derived member at `index` signs with `key`.
    Member { index: u16, key: &'a dyn Signer },
    /// The `msig` member at `index` signs by its own slots `(index, key)`, one level down.
    Msig {
        index: u16,
        members: Vec<(u16, &'a dyn Signer)>,
    },
}

impl Slot<'_> {
    fn index(&self) -> u16 {
        match self {
            Slot::Member { index, .. } | Slot::Msig { index, .. } => *index,
        }
    }
}

/// The kinds whose key the registry stores (`UAStore.vkLength` ≠ 0): their `UASig` carries no key data (CTR-UA-17).
fn stored(kind: u16) -> bool {
    matches!(kind, 0x0110..=0x0113 | 0x0130..=0x0135 | 0x0141)
}

/// The native id (`evm-eoa`, CTR-UA-03) of an EVM key: its address left-padded to 32 bytes; any other key `None`.
pub(super) fn native_id(r: &KeyRef) -> Option<[u8; 32]> {
    let KeyRef::Native {
        network: Network::Evm,
        public_key,
        ..
    } = r
    else {
        return None;
    };
    let pk = k256::PublicKey::from_sec1_bytes(public_key).ok()?;
    let point = k256::elliptic_curve::sec1::ToSec1Point::to_sec1_point(&pk, false);
    let mut id = [0u8; 32];
    id.get_mut(12..)?
        .copy_from_slice(keccak256(point.as_bytes().get(1..)?).get(12..)?);
    Some(id)
}

/// The `UASig` of a single UA key over `uaMessage(kind, purpose, digest)`, `purpose` a tag of `PURPOSES` or `pop` v2, the role
/// from the purpose: `keyData` the key's key data, empty for a stored kind and for `member` and the portable purposes
/// (`UARegistry._derived`, `UARegistryLib._portableOk`); no members. A native EVM key (R17): `{"", signature, []}`, the signature
/// over `UAAuth(id, purpose, digest)` under `domain` (`requireAuthorized`; `Argument` with no domain, or for a portable purpose:
/// a native id has no portable record). `domain` is read only for a native key. A key claiming the `msig` kind (an `msig` has no
/// key: [`msig_sig`]) or another native key: `Argument`.
pub fn ua_sig(
    key: &dyn Signer,
    domain: Option<&Domain>,
    purpose: &[u8; 32],
    digest: &[u8; 32],
) -> Result<UASig> {
    let r = key.key_ref();
    if let KeyRef::Native { .. } = r {
        check_purpose(purpose)?;
        let id = native_id(&r).ok_or(Error::Argument)?;
        if is_portable_purpose(purpose) || portable_record_purposes().contains(purpose) {
            return Err(Error::Argument);
        }
        let td = eip712::ua_auth(domain.ok_or(Error::Argument)?, &id, purpose, digest)?;
        let signature = key.sign_request(&eip712::request(&td)?)?;
        return Ok(UASig {
            key_data: vec![],
            signature,
            members: vec![],
        });
    }
    let KeyRef::Ua { kind, key_data } = r else {
        return Err(Error::Argument);
    };
    if kind == MSIG {
        return Err(Error::Argument);
    }
    let signature = super::webauthn::answer(key, &ua_request(kind, purpose, digest)?)?;
    let bare = stored(kind)
        || is_portable_purpose(purpose)
        || portable_record_purposes().contains(purpose)
        || *purpose == purpose_tag("member")?;
    Ok(UASig {
        key_data: if bare { vec![] } else { key_data },
        signature,
        members: vec![],
    })
}

/// CTR-UA-46: the `UASig` of a single UA key over app `app_id`'s portable record (`requirePortableApp`): `signature` over
/// `uaMessage(kind, app_purpose(app_id), digest)`, role `Pop`, no key data, no members. A native key, or a key claiming the `msig`
/// kind: `Argument` (a native id has no portable record; an `msig` signs by [`msig_sig_app`]).
pub fn ua_sig_app(key: &dyn Signer, app_id: &[u8; 32], digest: &[u8; 32]) -> Result<UASig> {
    let KeyRef::Ua { kind, .. } = key.key_ref() else {
        return Err(Error::Argument);
    };
    if kind == MSIG {
        return Err(Error::Argument);
    }
    let signature = super::webauthn::answer(key, &app_request(kind, app_id, digest)?)?;
    Ok(UASig {
        key_data: vec![],
        signature,
        members: vec![],
    })
}

/// CTR-UA-46: [`msig_sig_current`] over app `app_id`'s portable record `record`, purpose `app_purpose(app_id)`, digest
/// `record.digest()`: derived members over `memberDigest` under `member`, a native member (at either level) over `record` itself.
/// `record`'s domain is an app's portable domain, exactly `name, version, salt` with `salt = app_id` (rule (c)), else `Argument`
/// before anything is signed.
pub fn msig_sig_app(
    key_data: &[u8],
    current: &Current,
    inner: &Inner,
    app_id: &[u8; 32],
    record: &TypedData,
    slots: &[Slot],
) -> Result<UASig> {
    let purpose = app_purpose(app_id)?;
    let v = record.to_value();
    let d = v
        .get("domain")
        .and_then(Value::as_object)
        .ok_or(Error::Argument)?;
    let mut keys: Vec<&str> = d.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let salt = d.get("salt").and_then(Value::as_str);
    if keys != ["name", "salt", "version"]
        || !salt.is_some_and(|s| s.eq_ignore_ascii_case(&eip712::to_hex(app_id)))
    {
        return Err(Error::Argument);
    }
    msig_build(
        key_data,
        current,
        inner,
        &purpose,
        &record.digest()?,
        slots,
        || Ok(Native::Record(record)),
    )
}

/// The `UASig` of the `msig` `key_data` over `uaMessage(msig, purpose, digest)`: no key data, no signature, `members` the slots in
/// the caller's order. `inner` gives an `msig` member's key data by its id. A native member (an EVM key, at either level) signs, in
/// a portable purpose, `record` itself: the record's typed data, whose digest is `digest` and whose domain the portable one; in
/// any other purpose `UAAuth(id, member, md)` under `domain`. `record` and `domain` are read only for a native slot. `UAPoP`: a
/// set not minimal or not strictly increasing, at either level; `MemberUnknown`: an `msig` member `inner` does not give (or that
/// holds an `msig`); `Argument`: a slot's form not its member's, a key that is not its member, a native slot without what it signs
/// (or `record` another digest's). Nothing is signed unless every slot passes.
pub fn msig_sig(
    key_data: &[u8],
    inner: &Inner,
    purpose: &[u8; 32],
    digest: &[u8; 32],
    domain: Option<&Domain>,
    record: Option<&TypedData>,
    slots: &[Slot],
) -> Result<UASig> {
    msig_sig_current(
        key_data,
        &|_| None,
        inner,
        purpose,
        digest,
        domain,
        record,
        slots,
    )
}

/// [`msig_sig`] of an `msig` that `updateMsig` changed (CTR-UA-44, T21 L01): `key_data` its first structure (the id, for ever),
/// `current` the target registry's `msigOf(id)` (every slot, disabled ones included) and `msigStateOf` `enabled` word, for the
/// record and for its `msig` members (`None`: never updated there, the first structure authorizes). Slot indexes, weights,
/// threshold and minimality are the current structure's; every member digest binds the id; a disabled slot, at either level,
/// is `Argument` before anything is signed. `inner` gives an `msig` member's first structure.
#[allow(clippy::too_many_arguments)]
pub fn msig_sig_current(
    key_data: &[u8],
    current: &Current,
    inner: &Inner,
    purpose: &[u8; 32],
    digest: &[u8; 32],
    domain: Option<&Domain>,
    record: Option<&TypedData>,
    slots: &[Slot],
) -> Result<UASig> {
    check_purpose(purpose)?;
    msig_members_current(
        key_data, current, inner, purpose, digest, domain, record, slots,
    )
}

/// The typed `UAMsigUpdate` of an update (CTR-UA-44, the portable domain; clientkeys `msigUpdateMessage().typedData`): the `record`
/// a native member signs for [`msig_sig_current`] under `msig-update`, whose digest is [`msig_update_digest`].
pub fn msig_update_typed_data(u: &MsigUpdate) -> Result<TypedData> {
    use serde_json::json;
    let f = |n: &str, t: &str| json!({"name": n, "type": t});
    let members: Vec<Value> = u
        .structure
        .members
        .iter()
        .map(|m| json!({"kind": m.kind, "id": eip712::to_hex(&m.id), "weight": m.weight}))
        .collect();
    let td = TypedData::from_value(json!({
        "types": {
            "UAMsigUpdate": [f("ua", "bytes32"), f("chainUid", "bytes32"), f("registry", "address"), f("version", "uint64"),
                f("threshold", "uint16"), f("members", "UAMsigMember[]"), f("enabled", "uint256"), f("validUntilBlock", "uint64")],
            "UAMsigMember": [f("kind", "uint16"), f("id", "bytes32"), f("weight", "uint16")],
        },
        "primaryType": "UAMsigUpdate",
        "domain": {"name": crate::ua_portable::PORTABLE_DOMAIN_NAME, "version": crate::ua_portable::PORTABLE_DOMAIN_VERSION},
        "message": {"ua": eip712::to_hex(&u.ua), "chainUid": eip712::to_hex(&u.chain_uid), "registry": eip712::to_hex(&u.registry),
            "version": u.version, "threshold": u.structure.threshold, "members": members, "enabled": eip712::to_hex(&u.enabled),
            "validUntilBlock": u.valid_until_block},
    }))?;
    if td.digest()? != msig_update_digest(u) {
        return Err(Error::Argument);
    }
    Ok(td)
}

/// The typed `UARegistration{record, pqzPopHash}` of a registration without a KEM record (the portable domain; M1, owner
/// 2026-11-19): the `record` a native `msig` member signs for a `registerMsig` PoP under `pop` v2 ([`msig_slot_sig_current`]),
/// whose digest is `ua_portable::registration_digest` with the zero KEM record. An `msig` never holds a KEM key (CTR-UA-32).
pub fn registration_typed_data(
    ua: &[u8; 32],
    kind: u16,
    pqz_key_hash: &[u8; 32],
    pqz_pop_hash: &[u8; 32],
) -> Result<TypedData> {
    use serde_json::json;
    let f = |n: &str, t: &str| json!({"name": n, "type": t});
    let z = eip712::to_hex(&[0u8; 32]);
    let td = TypedData::from_value(json!({
        "types": {
            "UARegistration": [f("record", "UAPortableRecord"), f("pqzPopHash", "bytes32")],
            "UAPortableRecord": [f("ua", "bytes32"), f("kind", "uint16"), f("pqzKeyHash", "bytes32"), f("kem", "UAKemRecord")],
            "UAKemRecord": [f("ua", "bytes32"), f("version", "uint64"), f("scheme", "uint8"), f("kemPkHash", "bytes32")],
        },
        "primaryType": "UARegistration",
        "domain": {"name": crate::ua_portable::PORTABLE_DOMAIN_NAME, "version": crate::ua_portable::PORTABLE_DOMAIN_VERSION},
        "message": {"record": {"ua": eip712::to_hex(ua), "kind": kind, "pqzKeyHash": eip712::to_hex(pqz_key_hash),
            "kem": {"ua": eip712::to_hex(ua), "version": 0, "scheme": 0, "kemPkHash": z}},
            "pqzPopHash": eip712::to_hex(pqz_pop_hash)},
    }))?;
    let kem = crate::ua_portable::kem_record_hash(ua, 0, &[])?;
    if td.digest()?
        != crate::ua_portable::registration_digest(ua, kind, pqz_key_hash, &kem, pqz_pop_hash)
    {
        return Err(Error::Argument);
    }
    Ok(td)
}

/// [`msig_sig`] past its purpose check: the sealed container's sender (`seal`, MD-10: the off-chain seal purpose, no native member)
/// calls it directly.
pub(super) fn msig_members(
    key_data: &[u8],
    inner: &Inner,
    purpose: &[u8; 32],
    digest: &[u8; 32],
    domain: Option<&Domain>,
    record: Option<&TypedData>,
    slots: &[Slot],
) -> Result<UASig> {
    msig_members_current(
        key_data,
        &|_| None,
        inner,
        purpose,
        digest,
        domain,
        record,
        slots,
    )
}

/// The structure that authorizes the `msig` `id` whose first structure is `first` (CTR-UA-44) and its `enabled` word (`None`:
/// never updated, every slot).
fn now(id: &[u8; 32], first: &[u8], current: &Current) -> (Vec<u8>, Option<[u8; 32]>) {
    current(*id).map_or_else(|| (first.to_vec(), None), |(c, en)| (c, Some(en)))
}
fn on(enabled: &Option<[u8; 32]>, index: u16) -> bool {
    enabled.as_ref().is_none_or(|en| slot_enabled(en, index))
}

/// The purposes whose native members sign the record's typed digest itself, not `UAAuth` (T21 L02): the portable purposes
/// (`is_portable_purpose`: `pop` v2, `kem`, `pqz-key`, `membership`), the portable record purposes (`pqz-scoped-key`) and
/// `msig-update`, whose native members the contract checks over the update digest (`UARegistryAuxLib.updateMsig`,
/// `UARegistryCoreLib._memberOk`; accounts.md CTR-UA-44). `is_portable_purpose` itself stays the contract's `requirePortable` set.
fn native_signs_record(purpose: &[u8; 32]) -> Result<bool> {
    Ok(is_portable_purpose(purpose)
        || portable_record_purposes().contains(purpose)
        || *purpose == purpose_tag("msig-update")?)
}

/// What a native member signs in `purpose` over `digest`: the portable `record` itself (its digest `digest`), else `UAAuth`
/// under `domain`.
fn native_of<'a>(
    purpose: &[u8; 32],
    digest: &[u8; 32],
    domain: Option<&'a Domain>,
    record: Option<&'a TypedData>,
) -> Result<Native<'a>> {
    if native_signs_record(purpose)? {
        let r = record.ok_or(Error::Argument)?;
        if r.domain_separator()? != PORTABLE_DOMAIN_SEPARATOR || r.digest()? != *digest {
            return Err(Error::Argument);
        }
        Ok(Native::Record(r))
    } else {
        Ok(Native::Auth(domain.ok_or(Error::Argument)?))
    }
}

#[allow(clippy::too_many_arguments)]
fn msig_members_current(
    first: &[u8],
    current: &Current,
    inner: &Inner,
    purpose: &[u8; 32],
    digest: &[u8; 32],
    domain: Option<&Domain>,
    record: Option<&TypedData>,
    slots: &[Slot],
) -> Result<UASig> {
    msig_build(first, current, inner, purpose, digest, slots, || {
        native_of(purpose, digest, domain, record)
    })
}

/// One slot's `MemberSig` of the `msig` whose first structure is `first` over `uaMessage(msig, purpose, digest)` (M1, owner
/// 2026-11-19: members on different devices): as [`msig_sig_current`] for that slot alone, the set's minimality left to
/// [`msig_combine`]. A disabled slot (at either level) is `Argument`; an `msig` slot's own leaves must be minimal (`UAPoP`).
#[allow(clippy::too_many_arguments)]
pub fn msig_slot_sig_current(
    first: &[u8],
    current: &Current,
    inner: &Inner,
    purpose: &[u8; 32],
    digest: &[u8; 32],
    domain: Option<&Domain>,
    record: Option<&TypedData>,
    slot: &Slot,
) -> Result<MemberSig> {
    check_purpose(purpose)?;
    let ua = derive_ua(MSIG, first, false)?;
    let (key_data, enabled) = now(&ua, first, current);
    if !on(&enabled, slot.index()) {
        return Err(Error::Argument);
    }
    let structure = MsigStructure::from_key_data(&key_data)?;
    let p = plan(&structure, slot, inner, current)?;
    let native = if p.has_native() {
        native_of(purpose, digest, domain, record)?
    } else {
        Native::None
    };
    sign(&p, &ua, &ua_message(MSIG, purpose, digest)?, &native)
}

/// The `msig`'s `UASig` from its slots' `MemberSig`s, signed apart ([`msig_slot_sig_current`]), in any order: put in index
/// order; a repeated or disabled slot is `Argument`, a set not minimal for the current structure `UAPoP` (CTR-UA-07). The
/// signatures are the registry's to check.
pub fn msig_combine(first: &[u8], current: &Current, members: &[MemberSig]) -> Result<UASig> {
    let ua = derive_ua(MSIG, first, false)?;
    let (key_data, enabled) = now(&ua, first, current);
    let mut members = members.to_vec();
    members.sort_by_key(|m| m.index);
    let indexes: Vec<u16> = members.iter().map(|m| m.index).collect();
    if indexes.windows(2).any(|w| w.first() == w.get(1))
        || !indexes.iter().all(|i| on(&enabled, *i))
    {
        return Err(Error::Argument);
    }
    if !msig_slots_minimal(&key_data, &indexes)? {
        return Err(Error::Ua(UAError::Pop));
    }
    Ok(UASig {
        key_data: vec![],
        signature: vec![],
        members,
    })
}

/// The members of an `msig` signature, `native` asked only when a slot holds a native member: what that member signs.
fn msig_build<'a>(
    first: &[u8],
    current: &Current,
    inner: &Inner,
    purpose: &[u8; 32],
    digest: &[u8; 32],
    slots: &[Slot],
    native: impl FnOnce() -> Result<Native<'a>>,
) -> Result<UASig> {
    let ua = derive_ua(MSIG, first, false)?;
    let (key_data, enabled) = now(&ua, first, current);
    let indexes: Vec<u16> = slots.iter().map(Slot::index).collect();
    if !indexes.iter().all(|i| on(&enabled, *i)) {
        return Err(Error::Argument); // a disabled slot signs nothing
    }
    if !msig_slots_minimal(&key_data, &indexes)? {
        return Err(Error::Ua(UAError::Pop));
    }
    let structure = MsigStructure::from_key_data(&key_data)?;
    let plans = slots
        .iter()
        .map(|s| plan(&structure, s, inner, current))
        .collect::<Result<Vec<_>>>()?;
    let native = if plans.iter().any(Plan::has_native) {
        native()?
    } else {
        Native::None
    };
    let msg = ua_message(MSIG, purpose, digest)?;
    let members = plans
        .iter()
        .map(|p| sign(p, &ua, &msg, &native))
        .collect::<Result<Vec<_>>>()?;
    Ok(UASig {
        key_data: vec![],
        signature: vec![],
        members,
    })
}

/// The `MemberSig` of `acceptMembership(ua, ·)` for one slot of the `msig` `key_data` (CTR-UA-37): over typed
/// `UAMembership{ua, member}` ([`membership_digest`]) under `membership`, as an `msig` slot of that purpose; an `msig` member by a
/// minimal list of its own slots. One slot, no threshold. A slot past the members: `Argument`; else as [`msig_sig`].
pub fn membership_sig(key_data: &[u8], inner: &Inner, slot: &Slot) -> Result<MemberSig> {
    membership_sig_current(key_data, &|_| None, inner, slot)
}

/// [`membership_sig`] of an updated `msig` (CTR-UA-44, T21 L01): `key_data` the first structure (the id the record binds),
/// `current` as [`msig_sig_current`]; the slot one of the current structure, enabled or not (an appended slot accepts before it
/// counts, MM-2); an `msig` member's leaves enabled slots of its current structure.
pub fn membership_sig_current(
    key_data: &[u8],
    current: &Current,
    inner: &Inner,
    slot: &Slot,
) -> Result<MemberSig> {
    let ua = derive_ua(MSIG, key_data, false)?;
    let structure = MsigStructure::from_key_data(&now(&ua, key_data, current).0)?;
    let p = plan(&structure, slot, inner, current)?;
    let record = eip712::membership(&ua, &p.member.id)?;
    let msg = ua_message(
        MSIG,
        &purpose_tag("membership")?,
        &membership_digest(&ua, &p.member.id),
    )?;
    sign(&p, &ua, &msg, &Native::Record(&record))
}

/// What a native leaf signs in this call.
enum Native<'a> {
    /// The portable record's typed data (its digest checked).
    Record(&'a TypedData),
    /// `UAAuth(id, member, md)` under the registry's domain.
    Auth(&'a Domain),
    None,
}

/// A slot checked against its member.
struct Plan<'a> {
    index: u16,
    member: MsigMember,
    signers: Signers<'a>,
}
enum Signers<'a> {
    Key(&'a dyn Signer),
    /// An `msig` member's leaves `(index, member, key)`, its own list minimal.
    Leaves(Vec<(u16, MsigMember, &'a dyn Signer)>),
}
impl Plan<'_> {
    fn has_native(&self) -> bool {
        match &self.signers {
            Signers::Key(_) => self.member.kind == EVM_EOA,
            Signers::Leaves(l) => l.iter().any(|(_, m, _)| m.kind == EVM_EOA),
        }
    }
}

fn plan<'a>(
    structure: &MsigStructure,
    slot: &Slot<'a>,
    inner: &Inner,
    current: &Current,
) -> Result<Plan<'a>> {
    let index = slot.index();
    let member = *structure
        .members
        .get(usize::from(index))
        .ok_or(Error::Argument)?;
    match slot {
        Slot::Member { key, .. } => {
            if member.kind == MSIG {
                return Err(Error::Argument);
            }
            is_member(*key, &member)?;
            Ok(Plan {
                index,
                member,
                signers: Signers::Key(*key),
            })
        }
        Slot::Msig { members, .. } => {
            if member.kind != MSIG {
                return Err(Error::Argument);
            }
            let first = inner(member.id).ok_or(UAError::MemberUnknown)?;
            if derive_ua(MSIG, &first, false).ok() != Some(member.id) {
                return Err(Error::Ua(UAError::MemberUnknown));
            }
            let (d, enabled) = now(&member.id, &first, current);
            let all = MsigStructure::from_key_data(&d)?.members;
            if all
                .iter()
                .chain(&MsigStructure::from_key_data(&first)?.members)
                .any(|m| m.kind == MSIG)
            {
                return Err(Error::Ua(UAError::MemberUnknown)); // two levels only (CTR-UA-38)
            }
            if !members.iter().all(|(j, _)| on(&enabled, *j)) {
                return Err(Error::Argument); // a disabled slot signs nothing
            }
            if !msig_slots_minimal(&d, &members.iter().map(|(j, _)| *j).collect::<Vec<_>>())? {
                return Err(Error::Ua(UAError::Pop));
            }
            let leaves = members
                .iter()
                .map(|(j, key)| {
                    let m = *all.get(usize::from(*j)).ok_or(Error::Argument)?;
                    is_member(*key, &m)?;
                    Ok((*j, m, *key))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Plan {
                index,
                member,
                signers: Signers::Leaves(leaves),
            })
        }
    }
}

/// `key` is the member `m`: a derived member by its kind and its id (clientkeys `memberSlots`), an `evm-eoa` member by its id; no
/// other native kind signs here (a contract member answers ERC-1271).
fn is_member(key: &dyn Signer, m: &MsigMember) -> Result<()> {
    let r = key.key_ref();
    let ok = match &r {
        KeyRef::Ua { kind, key_data } => {
            *kind == m.kind && derive_ua(*kind, key_data, false).ok() == Some(m.id)
        }
        KeyRef::Native { .. } => m.kind == EVM_EOA && native_id(&r) == Some(m.id),
    };
    if ok {
        Ok(())
    } else {
        Err(Error::Argument)
    }
}

/// The slot's `MemberSig` in the `msig` `ua` over its `ua_msg` `msg`.
fn sign(p: &Plan, ua: &[u8; 32], msg: &[u8; 32], native: &Native) -> Result<MemberSig> {
    // a leaf of the structure `structure` (`m` its member) over that level's message `level_msg`
    let leaf = |key: &dyn Signer, m: &MsigMember, structure: &[u8; 32], level_msg: &[u8; 32]| {
        let req = if m.kind == EVM_EOA {
            match native {
                Native::Record(r) => eip712::request(r)?,
                Native::Auth(d) => {
                    let md = member_digest(structure, level_msg);
                    eip712::request(&eip712::ua_auth(d, &m.id, &purpose_tag("member")?, &md)?)?
                }
                Native::None => return Err(Error::Argument),
            }
        } else {
            member_request(m.kind, structure, level_msg)?
        };
        if matches!(req, SignRequest::Eip712 { .. }) != (m.kind == EVM_EOA) {
            return Err(Error::Argument);
        }
        super::webauthn::answer(key, &req)
    };
    match &p.signers {
        Signers::Key(key) => Ok(MemberSig {
            index: p.index,
            members: vec![],
            sig: leaf(*key, &p.member, ua, msg)?,
        }),
        Signers::Leaves(leaves) => {
            // the inner `msig` signs, under `member`, its slot's message `uaMessage(msig, member, memberDigest(ua, msg))`
            let inner_msg = ua_message(MSIG, &purpose_tag("member")?, &member_digest(ua, msg))?;
            let members = leaves
                .iter()
                .map(|(j, m, key)| {
                    Ok(InnerSig {
                        index: *j,
                        sig: leaf(*key, m, &p.member.id, &inner_msg)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(MemberSig {
                index: p.index,
                members,
                sig: vec![],
            })
        }
    }
}

/// The largest `UaSigRequest` JSON and its depth (`{msig: {slots: [{members: [{…}]}]}}` is 6; spec §9.3's rule, T12).
const REQUEST_JSON: usize = 64 << 10;
const REQUEST_DEPTH: usize = 6;
/// An `msig` has at most 16 members (CTR-UA-09).
const SLOTS_MAX: usize = 16;

/// The `UASig` builder as one JSON call (spec §9.2: ua-c `scaas_ua_uasig`, the `registration_args` convention: named fields, `0x`
/// hex): the request names its signing keys by their position in a list of handles the caller passes beside it, so no key
/// crosses as JSON. `{purpose, digest, domain?, key}` builds [`ua_sig`] of `keys[key]`; `{purpose, digest, domain?, msig: {keyData,
/// inner?, current?, slots: [{index, key} | {index, members: [{index, key}]}]}}` builds [`msig_sig_current`] (no `record`: a native
/// member in a purpose whose natives sign the record is `Argument`); `current` `[{ua, keyData, enabled}]` the structures that
/// authorize now (CTR-UA-44; none: never updated), `keyData` stays the first structure. `domain` is `{generation, chainId,
/// registry, chainUid}`, read only for a native key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UaSigRequest {
    purpose: [u8; 32],
    digest: [u8; 32],
    domain: Option<(u32, u64, [u8; 20], [u8; 32])>,
    by: By,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum By {
    Key(usize),
    Msig {
        key_data: Vec<u8>,
        inner: Vec<([u8; 32], Vec<u8>)>,
        current: Vec<([u8; 32], Vec<u8>, [u8; 32])>,
        slots: Vec<(u16, SlotBy)>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum SlotBy {
    Key(usize),
    Members(Vec<(u16, usize)>),
}

impl UaSigRequest {
    /// The request (64 KiB, JSON depth 6, at most 16 slots and 16 members a slot): `Argument` for anything else, an unknown key
    /// included. The key positions are checked by [`UaSigRequest::sign`].
    pub fn from_json(json: &[u8]) -> Result<UaSigRequest> {
        let v = bounded::json(json, REQUEST_JSON, REQUEST_DEPTH)?;
        parse_request(&v).ok_or(Error::Argument)
    }

    /// The `UASig`, each key `keys[i]` of the request (`Argument` for a position past the list); errors as [`ua_sig`] /
    /// [`msig_sig`].
    pub fn sign(&self, keys: &[&dyn Signer]) -> Result<UASig> {
        let key = |i: &usize| keys.get(*i).copied().ok_or(Error::Argument);
        let domain = self
            .domain
            .map(|(generation, chain_id, registry, chain_uid)| Domain {
                generation,
                chain_id,
                registry,
                chain_uid,
            });
        match &self.by {
            By::Key(i) => ua_sig(key(i)?, domain.as_ref(), &self.purpose, &self.digest),
            By::Msig {
                key_data,
                inner,
                current,
                slots,
            } => {
                let slots = slots
                    .iter()
                    .map(|(index, s)| match s {
                        SlotBy::Key(i) => Ok(Slot::Member {
                            index: *index,
                            key: key(i)?,
                        }),
                        SlotBy::Members(l) => Ok(Slot::Msig {
                            index: *index,
                            members: l
                                .iter()
                                .map(|(j, i)| Ok((*j, key(i)?)))
                                .collect::<Result<_>>()?,
                        }),
                    })
                    .collect::<Result<Vec<_>>>()?;
                let lookup = crate::json::lookup(inner);
                let now = |id: [u8; 32]| {
                    current
                        .iter()
                        .find(|(x, ..)| *x == id)
                        .map(|(_, d, en)| (d.clone(), *en))
                };
                msig_sig_current(
                    key_data,
                    &now,
                    &lookup,
                    &self.purpose,
                    &self.digest,
                    domain.as_ref(),
                    None,
                    &slots,
                )
            }
        }
    }
}

fn parse_request(v: &Value) -> Option<UaSigRequest> {
    let only = |v: &Value, keys: &[&str]| {
        v.as_object()
            .filter(|o| o.keys().all(|k| keys.contains(&k.as_str())))
            .cloned()
    };
    let h = |v: &Value| eip712::from_hex(v.as_str()?);
    let h32 = |v: &Value| <[u8; 32]>::try_from(h(v)?).ok();
    let u16_of = |v: &Value| u16::try_from(v.as_u64()?).ok();
    let pos = |v: &Value| usize::try_from(v.as_u64()?).ok();
    let o = only(v, &["purpose", "digest", "domain", "key", "msig"])?;
    let domain = match o.get("domain") {
        None => None,
        Some(d) => {
            let d = only(d, &["generation", "chainId", "registry", "chainUid"])?;
            let registry = <[u8; 20]>::try_from(h(d.get("registry")?)?).ok()?;
            Some((
                u32::try_from(d.get("generation")?.as_u64()?).ok()?,
                d.get("chainId")?.as_u64()?,
                registry,
                h32(d.get("chainUid")?)?,
            ))
        }
    };
    let by = match (o.get("key"), o.get("msig")) {
        (Some(k), None) => By::Key(pos(k)?),
        (None, Some(m)) => {
            let m = only(m, &["keyData", "inner", "current", "slots"])?;
            let inner = match m.get("inner") {
                None => vec![],
                Some(i) => crate::json::inners_in(i).ok()?,
            };
            let slot = |s: &Value| {
                let s = only(s, &["index", "key", "members"])?;
                let index = u16_of(s.get("index")?)?;
                match (s.get("key"), s.get("members")) {
                    (Some(k), None) => Some((index, SlotBy::Key(pos(k)?))),
                    (None, Some(l)) => {
                        let l = l.as_array().filter(|l| l.len() <= SLOTS_MAX)?;
                        let member = |x: &Value| {
                            let x = only(x, &["index", "key"])?;
                            Some((u16_of(x.get("index")?)?, pos(x.get("key")?)?))
                        };
                        Some((
                            index,
                            SlotBy::Members(l.iter().map(member).collect::<Option<_>>()?),
                        ))
                    }
                    _ => None,
                }
            };
            // CTR-UA-44: `current: [{ua, keyData, enabled}]`, the record's and its `msig` members' structures now (optional)
            let now = |c: &Value| {
                let c = only(c, &["ua", "keyData", "enabled"])?;
                Some((
                    h32(c.get("ua")?)?,
                    h(c.get("keyData")?)?,
                    h32(c.get("enabled")?)?,
                ))
            };
            let current = match m.get("current") {
                None => vec![],
                Some(c) => c
                    .as_array()
                    .filter(|l| l.len() <= SLOTS_MAX + 1)?
                    .iter()
                    .map(now)
                    .collect::<Option<_>>()?,
            };
            let slots = m
                .get("slots")?
                .as_array()
                .filter(|l| l.len() <= SLOTS_MAX)?;
            By::Msig {
                key_data: h(m.get("keyData")?)?,
                inner,
                current,
                slots: slots.iter().map(slot).collect::<Option<_>>()?,
            }
        }
        _ => return None,
    };
    Some(UaSigRequest {
        purpose: h32(o.get("purpose")?)?,
        digest: h32(o.get("digest")?)?,
        domain,
        by,
    })
}

/// An app record's path (scaas-sdk spec §12.2, §12.4): (A) portable under `appPurpose(app_id)` (`requirePortableApp`), or (B)
/// chain-bound under the app's own `purpose` (`requireAuthorized`).
#[cfg(feature = "app-core")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppPath {
    Portable { app_id: [u8; 32] },
    ChainBound { purpose: [u8; 32] },
}

/// Whether `purpose` is a SCaaS purpose: a `UAKinds` constant (`APP_PURPOSE_NS` included, the generated list), a SCaaS app's
/// `appPurpose(appId)` (the generated `SCAAS_APP_IDS`: PqVault's `P_V`, signed only by [`super::pqvault`], owner 2026-11-22),
/// one this crate signs (`PURPOSES`, the portable records' tags), or the seal purpose.
#[cfg(feature = "app-core")]
pub fn is_scaas_purpose(purpose: &[u8; 32]) -> bool {
    super::app_refusals::SCAAS_PURPOSES
        .iter()
        .any(|(_, s)| keccak256(s.as_bytes()) == *purpose)
        || super::app_refusals::SCAAS_APP_IDS
            .iter()
            .any(|(_, s)| app_purpose(&keccak256(s.as_bytes())).ok() == Some(*purpose))
        || check_purpose(purpose).is_ok()
        || *purpose == crate::seal_purpose_tag()
}

/// The typed digest of an app record on `path` once its domain and purpose pass (scaas-sdk spec §12.4): a domain named as a
/// SCaaS contract's (`AppDomainRefused`); path A: `app_id` ≠ 0 and not a SCaaS app's (`AppPurposeRefused`: PqVault's signs by
/// [`super::pqvault`] only), a domain of exactly `name, version, salt` (`AppDomainRefused`) with `salt == app_id`
/// (`AppSaltMismatch`); path B: an app purpose (`AppPurposeRefused`) and a domain with a `chainId` and a
/// `verifyingContract` (`AppDomainRefused`; their values are the caller's to check against its profile).
#[cfg(feature = "app-core")]
pub fn app_record_digest(path: &AppPath, typed: &TypedData) -> Result<[u8; 32]> {
    let v = typed.to_value();
    let d = v
        .get("domain")
        .and_then(Value::as_object)
        .ok_or(Error::AppDomainRefused)?;
    let name = d.get("name").and_then(Value::as_str).unwrap_or_default();
    if super::app_refusals::SCAAS_DOMAIN_NAMES.contains(&name) {
        return Err(Error::AppDomainRefused);
    }
    match path {
        AppPath::Portable { app_id } => {
            if *app_id == [0; 32] {
                return Err(Error::Argument);
            }
            if is_scaas_purpose(&app_purpose(app_id)?) {
                return Err(Error::AppPurposeRefused);
            }
            let mut keys: Vec<&str> = d.keys().map(String::as_str).collect();
            keys.sort_unstable();
            if keys != ["name", "salt", "version"] {
                return Err(Error::AppDomainRefused);
            }
            let salt = d.get("salt").and_then(Value::as_str);
            if !salt.is_some_and(|s| s.eq_ignore_ascii_case(&eip712::to_hex(app_id))) {
                return Err(Error::AppSaltMismatch);
            }
        }
        AppPath::ChainBound { purpose } => {
            if is_scaas_purpose(purpose) {
                return Err(Error::AppPurposeRefused);
            }
            if !(d.contains_key("chainId") && d.contains_key("verifyingContract")) {
                return Err(Error::AppDomainRefused);
            }
        }
    }
    typed.digest()
}

/// The `UASig` of a single key over an app record (scaas-sdk spec §12.4; typed data only, never a digest): path A by
/// [`ua_sig_app`] (a native key: `Argument`, it has no portable record); path B a UA key over `uaMessage(kind, purpose,
/// digest)` (its key data unless a stored kind), a native EVM key over `UAAuth(id, purpose, digest)` under `registry` (the
/// registry generation's domain; `Argument` without it). A key claiming the `msig` kind: `Argument` (an `msig` signs by
/// [`msig_sig_app`] or [`msig_sig`]).
#[cfg(feature = "app-core")]
pub fn sign_app_record(
    key: &dyn Signer,
    registry: Option<&Domain>,
    path: &AppPath,
    typed: &TypedData,
) -> Result<UASig> {
    sign_app_digest(key, registry, path, &app_record_digest(path, typed)?)
}

/// [`sign_app_record`] after its refusals: the record's typed digest `digest` on `path` (also [`super::pqvault::sign`]'s).
#[cfg(feature = "app-core")]
pub(super) fn sign_app_digest(
    key: &dyn Signer,
    registry: Option<&Domain>,
    path: &AppPath,
    digest: &[u8; 32],
) -> Result<UASig> {
    let digest = *digest;
    let purpose = match path {
        AppPath::Portable { app_id } => return ua_sig_app(key, app_id, &digest),
        AppPath::ChainBound { purpose } => purpose,
    };
    let r = key.key_ref();
    if let KeyRef::Native { .. } = r {
        let id = native_id(&r).ok_or(Error::Argument)?;
        let td = eip712::ua_auth(registry.ok_or(Error::Argument)?, &id, purpose, &digest)?;
        let signature = key.sign_request(&eip712::request(&td)?)?;
        return Ok(UASig {
            key_data: vec![],
            signature,
            members: vec![],
        });
    }
    let KeyRef::Ua { kind, key_data } = r else {
        return Err(Error::Argument);
    };
    if kind == MSIG {
        return Err(Error::Argument);
    }
    let signature = super::webauthn::answer(
        key,
        &super::sign::app_chain_request(kind, purpose, &digest)?,
    )?;
    Ok(UASig {
        key_data: if stored(kind) { vec![] } else { key_data },
        signature,
        members: vec![],
    })
}

/// What [`verify_app_record`] reads of the target registry, at one block: `members` each registered id's `(kind, keyData)`
/// (`registrationOf`; checked against the id here), `current` an `msig`'s `msigOf` and `enabled` word, `accepted` its accepted
/// bits, `domain` the registry generation's `UAAuth` domain (a native signer's; `None` where none was read).
#[cfg(feature = "app-core")]
pub struct AppRecordState<'a> {
    pub members: &'a crate::ua_portable::Members<'a>,
    pub current: &'a Current<'a>,
    pub accepted: &'a crate::ua_portable::Accepted<'a>,
    pub domain: Option<&'a Domain>,
}

/// Whether `sig` is `ua`'s signature of the app record `typed` on `path`, as the registry judges it on `state` (scaas-sdk spec
/// §12.2, review r2 R7): path A as `requirePortableApp` (a registered UA only; an `msig` down to its members, minimal, its native
/// members over the record's typed digest), path B as `requireAuthorized` (a native id over `UAAuth(ua, purpose, digest)` in
/// `state.domain`; an `msig` down to its members, its native members over `UAAuth(id, member, md)`; a single key with its key
/// data against the id, a stored kind's from its record). A refused record, an unknown UA or a part nothing here can check
/// (an `evm-eoa` id with code, a native kind other than `evm-eoa`): `false`.
#[cfg(feature = "app-core")]
pub fn verify_app_record(
    ua: &[u8; 32],
    path: &AppPath,
    typed: &TypedData,
    sig: &UASig,
    state: &AppRecordState,
) -> bool {
    app_record_digest(path, typed).is_ok_and(|d| verify_app_digest(ua, path, &d, sig, state))
}

/// [`verify_app_record`] after its refusals: `sig` over the record's typed digest `digest` on `path` (also
/// [`super::pqvault::verify`]'s).
#[cfg(feature = "app-core")]
pub(super) fn verify_app_digest(
    ua: &[u8; 32],
    path: &AppPath,
    digest: &[u8; 32],
    sig: &UASig,
    state: &AppRecordState,
) -> bool {
    let digest = *digest;
    let purpose = match path {
        AppPath::Portable { app_id } => match app_purpose(app_id) {
            Ok(p) => p,
            Err(_) => return false,
        },
        AppPath::ChainBound { purpose } => *purpose,
    };
    if crate::in_native_space(ua) {
        // a native id has no portable record; on path B it signs `UAAuth` itself (an EOA: its own key, never a delegate)
        let (AppPath::ChainBound { .. }, Some(d)) = (path, state.domain) else {
            return false;
        };
        let Some(addr) = ua.get(12..).and_then(|a| <[u8; 20]>::try_from(a).ok()) else {
            return false;
        };
        return sig.key_data.is_empty()
            && sig.members.is_empty()
            && crate::verify::native_ecdsa(
                &addr,
                &crate::ua_auth_digest(d, ua, &purpose, &digest),
                &sig.signature,
            );
    }
    let Some((kind, key_data)) = (state.members)(*ua) else {
        return false;
    };
    let accepted = Some(state.accepted);
    if let AppPath::Portable { .. } = path {
        return crate::ua_portable::check_portable_current(
            kind,
            &key_data,
            ua,
            &purpose,
            &digest,
            sig,
            state.members,
            state.current,
            accepted,
        )
        .is_ok();
    }
    if kind == MSIG {
        let Some(d) = state.domain else {
            return false;
        };
        return sig.key_data.is_empty()
            && sig.signature.is_empty()
            && crate::ua_portable::check_authorization_current(
                &key_data,
                ua,
                &purpose,
                &digest,
                &sig.members,
                d,
                state.members,
                state.current,
                accepted,
            )
            .is_ok();
    }
    // `UARegistry._derived`: a stored kind's key from its record, `keyData` empty; any other kind's key data hashing to the id
    let key = match (stored(kind), sig.key_data.is_empty()) {
        (true, true) => key_data,
        (false, false) => sig.key_data.clone(),
        _ => return false,
    };
    if derive_ua(kind, &key, false).ok() != Some(*ua) || !sig.members.is_empty() {
        return false;
    }
    match ua_message(kind, &purpose, &digest) {
        Ok(m) => crate::verify::verify(kind, &key, &m, &sig.signature, false, false),
        Err(_) => false,
    }
}

/// Whether a single UA key's `signature` (kind `kind`, key data `key_data` read from the UA's record and checked against its id
/// by the caller) signs the app record `typed` on `path` (scaas-sdk spec §12.2, review r2 R7): path A with the kind's PoP check
/// (`requirePortableApp`), path B with its authorization check (`requireAuthorized`). A refused record or an `msig` kind is
/// `false` (an `msig` is checked member by member).
#[cfg(feature = "app-core")]
pub fn verify_app_record_key(
    kind: u16,
    key_data: &[u8],
    path: &AppPath,
    typed: &TypedData,
    signature: &[u8],
) -> bool {
    let Ok(digest) = app_record_digest(path, typed) else {
        return false;
    };
    let (purpose, pop) = match path {
        AppPath::Portable { app_id } => match crate::ua_portable::app_purpose(app_id) {
            Ok(p) => (p, true),
            Err(_) => return false,
        },
        AppPath::ChainBound { purpose } => (*purpose, false),
    };
    if kind == MSIG {
        return false;
    }
    match ua_message(kind, &purpose, &digest) {
        Ok(m) => crate::verify::verify(kind, key_data, &m, signature, pop, false),
        Err(_) => false,
    }
}
