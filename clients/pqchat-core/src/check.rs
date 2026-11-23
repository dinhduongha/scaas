// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The checks of every record read (CLI-PQC-07): a record that fails is dropped silently, counted on the device per reason,
//! and nothing sent depends on it. The control-plane checks here are pure functions of what the trusted reads gave; the
//! message checks run in [`crate::message`] in the order of CLI-PQC-07, each before the next can be reached.
pub use crate::drops::DropReason;
use crate::model::Epoch;

/// Strictly ascending (by the lower-case hex the reads give; equal length, so byte order).
pub fn strictly_sorted<'a>(v: impl IntoIterator<Item = &'a str>) -> bool {
    let v: Vec<&str> = v.into_iter().collect();
    v.windows(2).all(|w| matches!(w, [a, b] if a < b))
}

/// `PqGroupBase.KEYS_PER_UA_MAX` (owner (M) 2026-11-23, CTR-CHAT-24): the KEM keys one UA may hold in one epoch.
pub const KEYS_PER_UA_MAX: usize = 8;

/// Members strictly sorted by `(ua, keyId)`, at most [`KEYS_PER_UA_MAX`] keys per UA (CTR-CHAT-24).
pub fn members_sorted(e: &Epoch) -> bool {
    let ordered = e
        .members
        .windows(2)
        .all(|w| matches!(w, [a, b] if (a.ua.as_str(), a.key_id) < (b.ua.as_str(), b.key_id)));
    ordered
        && distinct(e)
            .iter()
            .all(|u| e.members.iter().filter(|m| &m.ua == *u).count() <= KEYS_PER_UA_MAX)
}

/// The distinct UAs of `e`'s members, in order: every rule but the wraps reads members per UA (CTR-CHAT-24).
pub fn distinct(e: &Epoch) -> Vec<&String> {
    let mut v: Vec<&String> = e.members.iter().map(|m| &m.ua).collect();
    v.dedup();
    v
}

/// The list shapes of a session or an epoch record (CTR-CHAT-06, UA-7 §4.2; CTR-CHAT-24): members strictly sorted by
/// `(ua, keyId)`, admins strictly sorted, one wrap hash per entry; a session's creator (epoch 0's author) in both.
pub fn shapes(e: &Epoch) -> Result<(), DropReason> {
    if e.members.is_empty()
        || !members_sorted(e)
        || !strictly_sorted(e.admins.iter().map(String::as_str))
        || e.wrap_hashes.len() != e.members.len()
    {
        return Err(DropReason::Control);
    }
    if e.epoch == 0 && !(e.has_member(&e.author) && e.admins.contains(&e.author)) {
        return Err(DropReason::Control);
    }
    Ok(())
}

/// A child against its verified parent (CTR-CHAT-08, CTR-CHAT-09, CTR-CHAT-20): its number the parent's plus one; a plain
/// rekey (the parent's members and admins minus those who left) by a member of the parent who neither left nor was removed;
/// anything else by an admin of the parent who was not removed; no removed UA kept.
pub fn child(
    child: &Epoch,
    parent: &Epoch,
    left: &[String],
    removed: &[String],
) -> Result<(), DropReason> {
    shapes(child)?;
    if child.session_id != parent.session_id
        || child.parent != parent.id
        || child.epoch != parent.epoch + 1
    {
        return Err(DropReason::Control);
    }
    let kept = |u: &String| !left.contains(u);
    // per UA (CTR-CHAT-24): a member's keys may change in a plain rekey
    let plain = distinct(child)
        .into_iter()
        .eq(distinct(parent).into_iter().filter(|u| kept(u)))
        && child
            .admins
            .iter()
            .eq(parent.admins.iter().filter(|u| kept(u)));
    let a = &child.author;
    let rights = if plain {
        parent.has_member(a) && !left.contains(a)
    } else {
        parent.admins.contains(a)
    };
    let keeps_removed = removed
        .iter()
        .any(|r| r == a || child.has_member(r) || child.admins.contains(r));
    if !rights || keeps_removed {
        return Err(DropReason::Control);
    }
    Ok(())
}

/// A wrap read from state against the signed record's hash, before it enters a decapsulation (CLI-PQC-07).
pub fn wrap_hash(read: &str, signed: &str) -> Result<(), DropReason> {
    if read.eq_ignore_ascii_case(signed) {
        Ok(())
    } else {
        Err(DropReason::WrapHash)
    }
}
