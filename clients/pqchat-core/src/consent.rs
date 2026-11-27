// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Pending until accepted (CLI-PQC-08, UA-7 P12): a session found in state is pending on this device until its user accepts
//! it. Before that the crate reads it from contract state only, opens its own wrap and `sealedInfo` only when the user looks
//! at it ([`PqChat::preview`]), hands its room to the transport to hold the invite, and makes no store read, no Matrix join,
//! no subscription, no receipt and no write; declining writes nothing. Acceptance is local and the store is a cache: on a
//! fresh device the user is asked again (spec §13 O6 (a), open with the owner), and a session the UA left is declined (K11).
use crate::matrix::room_of;
use crate::message::OpenEpoch;
use crate::model::{at, h};
use crate::reads::SessionRef;
use crate::session::{Me, StoreEntry};
use crate::{DropReason, Items, PqChat, PqChatError};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;

/// A session's consent on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Consent {
    Pending,
    Accepted,
    Declined,
}

/// A session this device knows: where it lives and its consent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Known {
    pub s: SessionRef,
    pub consent: Consent,
}

/// What the user sees of a pending session before accepting it: from its latest epoch, opened locally.
#[derive(Clone)]
pub struct Preview {
    pub creator: String,
    pub epoch: String,
    pub members: Vec<String>,
    pub admins: Vec<String>,
    /// the epoch's `sealedInfo` JSON (its name and topic), only as the SDK's handle (owner 2026-11-22, spec §11)
    pub info: Arc<scaas_sdk::SecretBytes>,
    /// the chain stores a send writes (each costs gas per message, CLI-PQC-06)
    pub chain_stores: usize,
    /// the session lists a Matrix room (its invite held until acceptance)
    pub matrix: bool,
}

/// What [`PqChat::open_session`] did after acceptance.
#[derive(Clone)]
pub struct Opened {
    pub epoch: Arc<OpenEpoch>,
    pub room: crate::matrix::RoomUse,
    /// messages shown from the chain stores and the room's history
    pub shown: usize,
}

const KNOWN: &str = "sessions";

fn drop_err(d: DropReason) -> PqChatError {
    match d {
        DropReason::Member => PqChatError::NotMember,
        DropReason::Unlisted => PqChatError::InstanceUnlisted,
        _ => PqChatError::SessionUnknown,
    }
}

impl PqChat {
    /// Every session this device knows, by id.
    pub fn known(&self) -> Result<BTreeMap<String, Known>, PqChatError> {
        Ok(Items(&*self.store).get(KNOWN)?.unwrap_or_default())
    }

    /// `session`'s consent on this device (`None`: never seen here).
    pub fn consent(&self, session: &str) -> Result<Option<Consent>, PqChatError> {
        Ok(self
            .known()?
            .get(&session.to_ascii_lowercase())
            .map(|k| k.consent))
    }

    /// `s` recorded with `consent` (`force`: replacing the one held; else only when none is).
    pub(crate) fn set_consent(
        &self,
        s: &SessionRef,
        consent: Consent,
        force: bool,
    ) -> Result<Consent, PqChatError> {
        let sid = s.session_id.to_ascii_lowercase();
        let mut out = consent;
        Items(&*self.store).update::<BTreeMap<String, Known>, _>(KNOWN, |m| {
            let mut m = m.unwrap_or_default();
            match m.get(&sid) {
                Some(k) if !force => out = k.consent,
                _ => {
                    let mut s = s.clone();
                    s.session_id.clone_from(&sid);
                    m.insert(sid.clone(), Known { s, consent });
                }
            }
            Ok(m)
        })?;
        Ok(out)
    }

    pub(crate) fn is_accepted(&self, session: &str) -> Result<bool, PqChatError> {
        Ok(self.consent(session)? == Some(Consent::Accepted))
    }

    /// `SessionPending` unless the user accepted `session` on this device.
    pub(crate) fn require_accepted(&self, session: &str) -> Result<(), PqChatError> {
        if self.is_accepted(session)? {
            Ok(())
        } else {
            Err(PqChatError::SessionPending)
        }
    }

    /// The user's acceptance of `s` on this device, with the chain-store spend consent (local; the reads follow in
    /// [`PqChat::open_session`]).
    pub fn accept(&self, s: &SessionRef, chain_spend: bool) -> Result<(), PqChatError> {
        self.set_consent(s, Consent::Accepted, true)?;
        self.consent_chain_spend(&s.session_id, chain_spend)
    }

    /// The user declines `s`: recorded on this device, nothing written, nothing sent.
    pub fn decline(&self, s: &SessionRef) -> Result<(), PqChatError> {
        self.set_consent(s, Consent::Declined, true)?;
        Ok(())
    }

    /// The latest epoch of `s` at home (`latestEpoch`, a trusted read at the final block).
    pub(crate) async fn latest_epoch(&self, s: &SessionRef) -> Result<String, PqChatError> {
        let v = self
            .net
            .read(
                &s.chain,
                &s.home,
                "IPqChat.latestEpoch",
                json!({ "sessionId": s.session_id }),
            )
            .await?;
        h(at(&v, "epochId"))
    }

    /// A pending session as the user looks at it: its latest epoch at home opened locally for `me` (the own wrap, then
    /// `sealedInfo`), its room handed to the transport to hold the invite unanswered (`MatrixRoom` when the transport refuses
    /// it). No store read, no join, no write.
    pub async fn preview(&self, s: &SessionRef, me: &Me) -> Result<Preview, PqChatError> {
        let latest = self.latest_epoch(s).await?;
        let ep = self
            .open_epoch(s, &latest, &me.key, &me.ua.to_ascii_lowercase(), None)
            .await
            .map_err(drop_err)?;
        let handle = self.info(&ep)?;
        let info = crate::stores::read_info(&handle)?;
        if let (Some(room), Some(t)) = (room_of(&info.stores), self.matrix()) {
            // a room the transport refuses to hold (scaas-matrix: one the account already uses as a Matrix room) is not
            // this session's: the preview fails closed
            // a room the account is already joined to (the user's own session on a fresh device) needs no hold
            if !t.joined(room).await? {
                t.hold_invite(room, true).await?;
            }
        }
        let creator = match ep.epoch.epoch {
            0 => ep.epoch.author.clone(),
            _ => {
                self.signed_record_at(&s.chain, &s.home, &s.session_id, &s.session_id)
                    .await
                    .map_err(drop_err)?
                    .ok_or(PqChatError::SessionUnknown)?
                    .author
            }
        };
        Ok(Preview {
            creator,
            epoch: ep.epoch.id.clone(),
            members: crate::check::distinct(&ep.epoch)
                .into_iter()
                .cloned()
                .collect(),
            admins: ep.epoch.admins.clone(),
            info: handle,
            chain_stores: info
                .stores
                .iter()
                .filter(|e| matches!(e, StoreEntry::Chain { .. }))
                .count(),
            matrix: room_of(&info.stores).is_some(),
        })
    }

    /// An accepted session put to use on this device: its latest epoch at home opened for `me` and in use, the stores it
    /// lists confirmed (accepting them), its room joined (an attached client) and the latest messages read from its chain
    /// stores (`storedRange`) and the room's history.
    pub async fn open_session(&self, s: &SessionRef, me: &Me) -> Result<Opened, PqChatError> {
        self.require_accepted(&s.session_id)?;
        let latest = self.latest_epoch(s).await?;
        let ep = self
            .open_epoch(s, &latest, &me.key, &me.ua.to_ascii_lowercase(), None)
            .await
            .map_err(drop_err)?;
        let ep = self.use_epoch(s, ep).await?;
        self.confirm_stores(&ep)?;
        let info = self.info_of(&ep)?;
        let mut shown = 0;
        for e in info
            .stores
            .iter()
            .filter(|e| matches!(e, StoreEntry::Chain { .. }))
        {
            shown += self.read_chain_store(&ep, e).await?;
        }
        let mut room = crate::matrix::RoomUse::None;
        if self.matrix().is_some() {
            room = self.join_room(&ep).await?;
            if let (crate::matrix::RoomUse::Bound, Some(r)) = (room, room_of(&info.stores)) {
                shown += self.read_room(r).await?;
            }
        }
        Ok(Opened {
            epoch: ep,
            room,
            shown,
        })
    }
}
