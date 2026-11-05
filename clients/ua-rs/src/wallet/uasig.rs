// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The `UASig` builder (spec §5.2, §9.4; T3d) over `&dyn Signer` handles: a single key's `UASig{keyData, signature, []}`
//! ([`ua_sig`]), an `msig`'s `UASig{"", "", members}` from the member slots the caller names ([`msig_sig`]), and one slot's
//! acceptance `MemberSig` (CTR-UA-37, [`membership_sig`]). Every `msig` set is minimal at both levels and strictly increasing
//! (CTR-UA-07; the registry stores and copies only that form, `UARegistryLib._msig`), else `UAPoP`, the registry's verdict, before
//! anything is signed; a minimal set also passes `requireAuthorized`'s stop at the threshold. A derived member signs
//! `uaMessage(kind, member, memberDigest(msig, ua_msg))`, an `msig` member's leaves `memberDigest` of the inner id over
//! `uaMessage(msig, member, md)` (`ua8::inner_digest`), as clientkeys `msigMemberSigs`. A native key or member signs typed data:
//! T4 (`Argument` here). UNAUDITED.
use super::sign::{check_purpose, member_request, ua_request};
use super::signer::{KeyRef, Signer};
use super::{Error, Result};
use crate::ua8::{is_portable_purpose, membership_digest, msig_slots_minimal, Inner, InnerSig, MemberSig, MsigMember, MsigStructure, UASig};
use crate::{derive_ua, member_digest, purpose_tag, ua_message, UAError};

const MSIG: u16 = 0x0120;

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

/// The `UASig` of a single UA key over `uaMessage(kind, purpose, digest)`, `purpose` a tag of `PURPOSES` or `pop` v2, the role
/// from the purpose: `keyData` the key's key data, empty for a stored kind and for `member` and the portable purposes
/// (`UARegistry._derived`, `UARegistryLib._portableOk`); no members. A native key (its typed signature, T4) or a key claiming the
/// `msig` kind (an `msig` has no key: [`msig_sig`]): `Argument`.
pub fn ua_sig(key: &dyn Signer, purpose: &[u8; 32], digest: &[u8; 32]) -> Result<UASig> {
    let KeyRef::Ua { kind, key_data } = key.key_ref() else { return Err(Error::Argument) };
    if kind == MSIG {
        return Err(Error::Argument);
    }
    let signature = key.sign_request(&ua_request(kind, purpose, digest)?)?;
    let bare = stored(kind) || is_portable_purpose(purpose) || *purpose == purpose_tag("member")?;
    Ok(UASig { key_data: if bare { vec![] } else { key_data }, signature, members: vec![] })
}

/// The `UASig` of the `msig` `key_data` over `uaMessage(msig, purpose, digest)`: no key data, no signature, `members` the slots in
/// the caller's order. `inner` gives an `msig` member's key data by its id. `UAPoP`: a set not minimal or not strictly increasing,
/// at either level; `MemberUnknown`: an `msig` member `inner` does not give (or that holds an `msig`); `Argument`: a slot's form
/// not its member's, a key that is not its member. Nothing is signed unless every slot passes.
pub fn msig_sig(key_data: &[u8], inner: &Inner, purpose: &[u8; 32], digest: &[u8; 32], slots: &[Slot]) -> Result<UASig> {
    check_purpose(purpose)?;
    let ua = derive_ua(MSIG, key_data, false)?;
    if !msig_slots_minimal(key_data, &slots.iter().map(Slot::index).collect::<Vec<_>>())? {
        return Err(Error::Ua(UAError::Pop));
    }
    let structure = MsigStructure::from_key_data(key_data)?;
    let plans = slots.iter().map(|s| plan(&structure, s, inner)).collect::<Result<Vec<_>>>()?;
    let msg = ua_message(MSIG, purpose, digest)?;
    let members = plans.iter().map(|p| sign(p, &ua, &msg)).collect::<Result<Vec<_>>>()?;
    Ok(UASig { key_data: vec![], signature: vec![], members })
}

/// The `MemberSig` of `acceptMembership(ua, ·)` for one slot of the `msig` `key_data` (CTR-UA-37): over typed
/// `UAMembership{ua, member}` ([`membership_digest`]) under `membership`, as an `msig` slot of that purpose; an `msig` member by a
/// minimal list of its own slots. One slot, no threshold. A slot past the members: `Argument`; else as [`msig_sig`].
pub fn membership_sig(key_data: &[u8], inner: &Inner, slot: &Slot) -> Result<MemberSig> {
    let ua = derive_ua(MSIG, key_data, false)?;
    let structure = MsigStructure::from_key_data(key_data)?;
    let p = plan(&structure, slot, inner)?;
    let msg = ua_message(MSIG, &purpose_tag("membership")?, &membership_digest(&ua, &p.member.id))?;
    sign(&p, &ua, &msg)
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

/// `key` is the derived member `m`: its kind and its id (clientkeys `memberSlots`); a native member signs typed data (T4).
fn is_member(key: &dyn Signer, m: &MsigMember) -> Result<()> {
    match key.key_ref() {
        KeyRef::Ua { kind, key_data } if kind == m.kind && derive_ua(kind, &key_data, false).ok() == Some(m.id) => Ok(()),
        _ => Err(Error::Argument),
    }
}

/// The slot's `MemberSig` in the `msig` `ua` over its `ua_msg` `msg`.
fn sign(p: &Plan, ua: &[u8; 32], msg: &[u8; 32]) -> Result<MemberSig> {
    let leaf = |key: &dyn Signer, kind: u16, structure: &[u8; 32], m: &[u8; 32]| {
        key.sign_request(&member_request(kind, structure, m)?)
    };
    match &p.signers {
        Signers::Key(key) => Ok(MemberSig { index: p.index, members: vec![], sig: leaf(*key, p.member.kind, ua, msg)? }),
        Signers::Leaves(leaves) => {
            // the inner `msig` signs, under `member`, its slot's message `uaMessage(msig, member, memberDigest(ua, msg))`
            let inner_msg = ua_message(MSIG, &purpose_tag("member")?, &member_digest(ua, msg))?;
            let members = leaves
                .iter()
                .map(|(j, m, key)| Ok(InnerSig { index: *j, sig: leaf(*key, m.kind, &p.member.id, &inner_msg)? }))
                .collect::<Result<Vec<_>>>()?;
            Ok(MemberSig { index: p.index, members, sig: vec![] })
        }
    }
}
