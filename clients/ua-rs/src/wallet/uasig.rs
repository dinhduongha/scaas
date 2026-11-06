// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The `UASig` builder (spec §5.2, §9.4; T3d) over `&dyn Signer` handles: a single key's `UASig{keyData, signature, []}`
//! ([`ua_sig`]), an `msig`'s `UASig{"", "", members}` from the member slots the caller names ([`msig_sig`]), and one slot's
//! acceptance `MemberSig` (CTR-UA-37, [`membership_sig`]). Every `msig` set is minimal at both levels and strictly increasing
//! (CTR-UA-07; the registry stores and copies only that form, `UARegistryLib._msig`), else `UAPoP`, the registry's verdict, before
//! anything is signed; a minimal set also passes `requireAuthorized`'s stop at the threshold. A derived member signs
//! `uaMessage(kind, member, memberDigest(msig, ua_msg))`, an `msig` member's leaves `memberDigest` of the inner id over
//! `uaMessage(msig, member, md)` (`ua8::inner_digest`), as clientkeys `msigMemberSigs`. T4: a native key (`evm-eoa`, an EVM
//! key) signs typed data (CTR-UA-07, CTR-UA-24, TS-D4): as a `UASig` of its own (R17: `{"", signature, []}`) `UAAuth(id, purpose,
//! digest)` under the registry's domain; as an `msig` member, at either level, the record's typed data itself in the portable
//! purposes (`pop` v2, `kem`, `pqz-key`, `membership`), else `UAAuth(id, member, md)` of its level's member digest. UNAUDITED.
use super::eip712::{self, TypedData};
use super::sign::{check_purpose, member_request, ua_request};
use super::signer::{KeyRef, SignRequest, Signer};
use super::{Error, Network, Result};
use crate::ua8::{
    is_portable_purpose, membership_digest, msig_slots_minimal, Inner, InnerSig, MemberSig, MsigMember, MsigStructure, UASig,
    PORTABLE_DOMAIN_SEPARATOR,
};
use crate::{derive_ua, keccak256, member_digest, purpose_tag, ua_message, Domain, UAError};

const MSIG: u16 = 0x0120;
const EVM_EOA: u16 = 0x0001;

/// One slot of an `msig` signature, named by the caller.
pub enum Slot<'a> {
    /// The derived member at `index` signs with `key`.
    Member { index: u16, key: &'a dyn Signer },
    /// The `msig` member at `index` signs by its own slots `(index, key)`, one level down.
    Msig { index: u16, members: Vec<(u16, &'a dyn Signer)> },
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
fn native_id(r: &KeyRef) -> Option<[u8; 32]> {
    let KeyRef::Native { network: Network::Evm, public_key, .. } = r else { return None };
    let pk = k256::PublicKey::from_sec1_bytes(public_key).ok()?;
    let point = k256::elliptic_curve::sec1::ToSec1Point::to_sec1_point(&pk, false);
    let mut id = [0u8; 32];
    id.get_mut(12..)?.copy_from_slice(keccak256(point.as_bytes().get(1..)?).get(12..)?);
    Some(id)
}

/// The `UASig` of a single UA key over `uaMessage(kind, purpose, digest)`, `purpose` a tag of `PURPOSES` or `pop` v2, the role
/// from the purpose: `keyData` the key's key data, empty for a stored kind and for `member` and the portable purposes
/// (`UARegistry._derived`, `UARegistryLib._portableOk`); no members. A native EVM key (R17): `{"", signature, []}`, the signature
/// over `UAAuth(id, purpose, digest)` under `domain` (`requireAuthorized`; `Argument` with no domain, or for a portable purpose:
/// a native id has no portable record). `domain` is read only for a native key. A key claiming the `msig` kind (an `msig` has no
/// key: [`msig_sig`]) or another native key: `Argument`.
pub fn ua_sig(key: &dyn Signer, domain: Option<&Domain>, purpose: &[u8; 32], digest: &[u8; 32]) -> Result<UASig> {
    let r = key.key_ref();
    if let KeyRef::Native { .. } = r {
        check_purpose(purpose)?;
        let id = native_id(&r).ok_or(Error::Argument)?;
        if is_portable_purpose(purpose) {
            return Err(Error::Argument);
        }
        let td = eip712::ua_auth(domain.ok_or(Error::Argument)?, &id, purpose, digest)?;
        let signature = key.sign_request(&eip712::request(&td)?)?;
        return Ok(UASig { key_data: vec![], signature, members: vec![] });
    }
    let KeyRef::Ua { kind, key_data } = r else { return Err(Error::Argument) };
    if kind == MSIG {
        return Err(Error::Argument);
    }
    let signature = key.sign_request(&ua_request(kind, purpose, digest)?)?;
    let bare = stored(kind) || is_portable_purpose(purpose) || *purpose == purpose_tag("member")?;
    Ok(UASig { key_data: if bare { vec![] } else { key_data }, signature, members: vec![] })
}

/// The `UASig` of the `msig` `key_data` over `uaMessage(msig, purpose, digest)`: no key data, no signature, `members` the slots in
/// the caller's order. `inner` gives an `msig` member's key data by its id. A native member (an EVM key, at either level) signs, in
/// a portable purpose, `record` itself: the record's typed data, whose digest is `digest` and whose domain the portable one; in
/// any other purpose `UAAuth(id, member, md)` under `domain`. `record` and `domain` are read only for a native slot. `UAPoP`: a
/// set not minimal or not strictly increasing, at either level; `MemberUnknown`: an `msig` member `inner` does not give (or that
/// holds an `msig`); `Argument`: a slot's form not its member's, a key that is not its member, a native slot without what it signs
/// (or `record` another digest's). Nothing is signed unless every slot passes.
pub fn msig_sig(
    key_data: &[u8], inner: &Inner, purpose: &[u8; 32], digest: &[u8; 32], domain: Option<&Domain>, record: Option<&TypedData>,
    slots: &[Slot],
) -> Result<UASig> {
    check_purpose(purpose)?;
    msig_members(key_data, inner, purpose, digest, domain, record, slots)
}

/// [`msig_sig`] past its purpose check: the sealed container's sender (`seal`, MD-10: the off-chain seal purpose, no native member)
/// calls it directly.
pub(super) fn msig_members(
    key_data: &[u8], inner: &Inner, purpose: &[u8; 32], digest: &[u8; 32], domain: Option<&Domain>, record: Option<&TypedData>,
    slots: &[Slot],
) -> Result<UASig> {
    let ua = derive_ua(MSIG, key_data, false)?;
    if !msig_slots_minimal(key_data, &slots.iter().map(Slot::index).collect::<Vec<_>>())? {
        return Err(Error::Ua(UAError::Pop));
    }
    let structure = MsigStructure::from_key_data(key_data)?;
    let plans = slots.iter().map(|s| plan(&structure, s, inner)).collect::<Result<Vec<_>>>()?;
    let native = if plans.iter().any(Plan::has_native) {
        if is_portable_purpose(purpose) {
            let r = record.ok_or(Error::Argument)?;
            if r.domain_separator()? != PORTABLE_DOMAIN_SEPARATOR || r.digest()? != *digest {
                return Err(Error::Argument);
            }
            Native::Record(r)
        } else {
            Native::Auth(domain.ok_or(Error::Argument)?)
        }
    } else {
        Native::None
    };
    let msg = ua_message(MSIG, purpose, digest)?;
    let members = plans.iter().map(|p| sign(p, &ua, &msg, &native)).collect::<Result<Vec<_>>>()?;
    Ok(UASig { key_data: vec![], signature: vec![], members })
}

/// The `MemberSig` of `acceptMembership(ua, ·)` for one slot of the `msig` `key_data` (CTR-UA-37): over typed
/// `UAMembership{ua, member}` ([`membership_digest`]) under `membership`, as an `msig` slot of that purpose; an `msig` member by a
/// minimal list of its own slots. One slot, no threshold. A slot past the members: `Argument`; else as [`msig_sig`].
pub fn membership_sig(key_data: &[u8], inner: &Inner, slot: &Slot) -> Result<MemberSig> {
    let ua = derive_ua(MSIG, key_data, false)?;
    let structure = MsigStructure::from_key_data(key_data)?;
    let p = plan(&structure, slot, inner)?;
    let record = eip712::membership(&ua, &p.member.id)?;
    let msg = ua_message(MSIG, &purpose_tag("membership")?, &membership_digest(&ua, &p.member.id))?;
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

fn plan<'a>(structure: &MsigStructure, slot: &Slot<'a>, inner: &Inner) -> Result<Plan<'a>> {
    let index = slot.index();
    let member = *structure.members.get(usize::from(index)).ok_or(Error::Argument)?;
    match slot {
        Slot::Member { key, .. } => {
            if member.kind == MSIG {
                return Err(Error::Argument);
            }
            is_member(*key, &member)?;
            Ok(Plan { index, member, signers: Signers::Key(*key) })
        }
        Slot::Msig { members, .. } => {
            if member.kind != MSIG {
                return Err(Error::Argument);
            }
            let d = inner(member.id).ok_or(UAError::MemberUnknown)?;
            if derive_ua(MSIG, &d, false).ok() != Some(member.id) {
                return Err(Error::Ua(UAError::MemberUnknown));
            }
            let all = MsigStructure::from_key_data(&d)?.members;
            if all.iter().any(|m| m.kind == MSIG) {
                return Err(Error::Ua(UAError::MemberUnknown)); // two levels only (CTR-UA-38)
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
            Ok(Plan { index, member, signers: Signers::Leaves(leaves) })
        }
    }
}

/// `key` is the member `m`: a derived member by its kind and its id (clientkeys `memberSlots`), an `evm-eoa` member by its id; no
/// other native kind signs here (a contract member answers ERC-1271).
fn is_member(key: &dyn Signer, m: &MsigMember) -> Result<()> {
    let r = key.key_ref();
    let ok = match &r {
        KeyRef::Ua { kind, key_data } => *kind == m.kind && derive_ua(*kind, key_data, false).ok() == Some(m.id),
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
        key.sign_request(&req)
    };
    match &p.signers {
        Signers::Key(key) => Ok(MemberSig { index: p.index, members: vec![], sig: leaf(*key, &p.member, ua, msg)? }),
        Signers::Leaves(leaves) => {
            // the inner `msig` signs, under `member`, its slot's message `uaMessage(msig, member, memberDigest(ua, msg))`
            let inner_msg = ua_message(MSIG, &purpose_tag("member")?, &member_digest(ua, msg))?;
            let members = leaves
                .iter()
                .map(|(j, m, key)| Ok(InnerSig { index: *j, sig: leaf(*key, m, &p.member.id, &inner_msg)? }))
                .collect::<Result<Vec<_>>>()?;
            Ok(MemberSig { index: p.index, members, sig: vec![] })
        }
    }
}
