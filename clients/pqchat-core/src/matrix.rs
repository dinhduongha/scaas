// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The Matrix store (CLI-PQC-05, spec §6): the app's live Matrix client behind [`MatrixTransport`], the event of an envelope
//! (UA-7 P15: type `net.scaas.pqchat.v1`, content `{"v": 1, "hint": <base64>, "env": <base64>}`, base64 of RFC 4648 §4 with
//! padding, the `matrixEvent` row's form, and only that form read back), and the binding of rooms and Matrix ids (§6.2,
//! Fable K8). A room counts for a session only if this client created it for that session or joined it through that
//! session's acceptance, a room the account had joined before only once its members check against the epoch (state-only
//! recovery: a fresh device), one session per room (the first bound keeps it); a
//! Matrix id counts for a UA only when that UA asserted it (its signed contact card, UA-7 §14 O7, or an envelope signed by that
//! UA received from that sender); invites
//! and removals go only to ids bound so, by the epoch's author's client, once the epoch is complete at home; no Matrix power
//! level is a PqChat right. The room id lives only in `sealedInfo` and this device's store (D10). The codec is a transport
//! encoding; the envelope's bytes are opened and decoded in `ua-rs` (K4).
use crate::drops::DropReason;
use crate::message::{Incoming, OpenEpoch};
use crate::model::at;
use crate::reads::SessionRef;
use crate::session::{Me, StoreEntry};
use crate::{Event, Items, PqChat, PqChatError};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use scaas_sdk::app_core::AppUaSig;
use scaas_sdk::pqchat_records::PqChatCard;
use serde_json::{json, Value};

// The transport trait, its error and value types and the conformance test live in `pqchat-transport` (CLI-MTX-01), so that
// `scaas-matrix` implements the trait without this crate and this crate pulls no Matrix crate; re-exported at their old paths.
pub use pqchat_transport::{
    conformance, HistoryPage, MatrixTransport, RoomEvent, Seen, TransportError, Witness, EVENT_MAX,
    EVENT_TYPE,
};

/// History pages read back at most per room and call (the rest: the server's retention, or the next call).
pub const HISTORY_PAGES: usize = 64;
/// Events of one history read processed at most.
pub const HISTORY_MAX: usize = 4096;
/// Matrix ids kept per UA.
pub const MXIDS_MAX: usize = 8;
/// Events kept per room while the seed is locked; past it the room is read again from its history at unlock.
pub const LOCKED_MAX: usize = 64;
/// Bound rooms listed for [`PqChat::tell_bound_rooms`], at most.
pub const BOUND_MAX: usize = 4096;
const BOUND_INDEX: &str = "mroom-index";

/// The content of the event carrying `env` under `hint`.
pub fn event(hint: &[u8], env: &[u8]) -> Value {
    json!({ "v": 1, "hint": STANDARD.encode(hint), "env": STANDARD.encode(env) })
}

/// A received event's content (its JSON bytes): the hint and the envelope, or `decode` for an event over [`EVENT_MAX`], not
/// one flat object of exactly `v`, `hint`, `env`, a `v` other than 1, a base64 form other than the padded standard one, a
/// hint other than 8 bytes, an empty envelope.
pub fn parse(content: &[u8]) -> Result<([u8; 8], Vec<u8>), DropReason> {
    if content.len() > EVENT_MAX {
        return Err(DropReason::Decode);
    }
    // a flat object: three string or number members; a nested value is refused before any depth is reached
    let v: serde_json::Map<String, Value> =
        serde_json::from_slice(content).map_err(|_| DropReason::Decode)?;
    if v.len() != 3 || v.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(DropReason::Decode);
    }
    let field = |k: &str| v.get(k).and_then(Value::as_str).ok_or(DropReason::Decode);
    let (h, e) = (field("hint")?, field("env")?);
    let hint = STANDARD.decode(h).map_err(|_| DropReason::Decode)?;
    let env = STANDARD.decode(e).map_err(|_| DropReason::Decode)?;
    // the one canonical form: encoding the bytes again gives the text read
    if STANDARD.encode(&hint) != h || STANDARD.encode(&env) != e || env.is_empty() {
        return Err(DropReason::Decode);
    }
    Ok((hint.try_into().map_err(|_| DropReason::Decode)?, env))
}

/// A room as this device's store knows it: the session it serves (`None`: created here, no session yet) and whether this
/// client created it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoomBind {
    pub session: Option<String>,
    pub created: bool,
}

/// Why a session's room is not used (shown with the session; the room id is not in it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RoomRefusal {
    /// the account had joined the room before this client bound it to the session
    JoinedBefore,
    /// another session holds the room
    OtherSession,
}

/// What [`PqChat::join_room`] did with an epoch's Matrix room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomUse {
    /// the epoch lists no Matrix room
    None,
    /// the room serves the session (joined now or before through it)
    Bound,
    /// the user has not confirmed it: neither joined nor read
    Unconfirmed,
    Refused(RoomRefusal),
}

/// What became of a Matrix event handed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatrixIn {
    /// a room no accepted session binds: not ours, nothing counted
    Ignored,
    /// kept while the seed is locked (CLI-PQC-10)
    Kept,
    /// the room's session's outcome
    Read(Incoming),
}

/// What [`PqChat::sync_room`] did: UAs only (no Matrix id).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoomSync {
    pub invited: Vec<String>,
    pub removed: Vec<String>,
    /// UAs whose claimed Matrix id is not bound to them (`MatrixIdUnbound`): neither invited nor removed, shown as unconfirmed
    pub unbound: Vec<String>,
    /// the first failure of the transport, by its code (the chain is not touched)
    pub failed: Option<&'static str>,
}

fn room_key(room: &str) -> String {
    format!("mroom/{room}")
}

/// The events of one room kept while the seed was locked, in their order, and whether more came than were kept.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct Kept {
    events: Vec<RoomEvent>,
    overflow: bool,
}

const KEPT_ROOMS: &str = "locked-rooms";

fn kept_key(room: &str) -> String {
    format!("locked/{room}")
}

fn mxid_key(ua: &str) -> String {
    format!("mxid/{}", ua.to_ascii_lowercase())
}

/// The Matrix room an epoch's list names.
pub(crate) fn room_of(stores: &[StoreEntry]) -> Option<&str> {
    stores.iter().find_map(|s| match s {
        StoreEntry::Matrix { room } => Some(room.as_str()),
        _ => None,
    })
}

impl PqChat {
    fn transport(&self) -> Result<std::sync::Arc<dyn MatrixTransport>, PqChatError> {
        self.matrix().ok_or(PqChatError::MatrixDetached)
    }

    pub(crate) fn room_bind(&self, room: &str) -> Result<Option<RoomBind>, PqChatError> {
        Items(&*self.store).get(&room_key(room))
    }

    /// The session `room` serves on this device, if any.
    pub fn room_session(&self, room: &str) -> Result<Option<String>, PqChatError> {
        Ok(self.room_bind(room)?.and_then(|b| b.session))
    }

    /// A new room for a session this client is about to create (no Matrix encryption): bound to the session by
    /// [`PqChat::create`] when its list names it.
    pub async fn create_room(&self) -> Result<String, PqChatError> {
        let room = self.transport()?.create_room().await?;
        Items(&*self.store).update::<RoomBind, _>(&room_key(&room), |b| match b {
            None => Ok(RoomBind {
                session: None,
                created: true,
            }),
            Some(_) => Err(PqChatError::MatrixRoom),
        })?;
        Ok(room)
    }

    /// `room` bound to `session` as the session's creator: only a room this client created and no session holds
    /// (`MatrixRoom`).
    pub(crate) fn bind_created(&self, room: &str, session: &str) -> Result<(), PqChatError> {
        let sid = session.to_ascii_lowercase();
        Items(&*self.store).update::<RoomBind, _>(&room_key(room), |b| match b {
            Some(b) if b.created && b.session.as_deref().is_none_or(|s| s == sid) => Ok(RoomBind {
                session: Some(sid.clone()),
                created: true,
            }),
            _ => Err(PqChatError::MatrixRoom),
        })?;
        self.index_bound(room)
    }

    /// The Matrix ids `ua` asserted (each by its contact card or an envelope signed by `ua` received from that sender), at
    /// most [`MXIDS_MAX`].
    pub fn matrix_ids_of(&self, ua: &str) -> Result<Vec<String>, PqChatError> {
        Ok(Items(&*self.store).get(&mxid_key(ua))?.unwrap_or_default())
    }

    /// `sender` asserted by `ua` (the oldest dropped past [`MXIDS_MAX`]: an id relayed by another sender cannot crowd out
    /// the UA's own for good, it only adds one).
    fn bind_mxid(&self, ua: &str, sender: &str) -> Result<(), PqChatError> {
        Items(&*self.store).update::<Vec<String>, _>(&mxid_key(ua), |m| {
            let mut m = m.unwrap_or_default();
            if !m.iter().any(|x| x == sender) {
                m.push(sender.to_string());
            }
            while m.len() > MXIDS_MAX {
                m.remove(0);
            }
            Ok(m)
        })?;
        Ok(())
    }

    /// A contact card the user received out of band (UA-7 §14 O7): checked by the SDK for its own UA (V1 on `chain`'s
    /// registry at the final block, a trusted read); its Matrix id then counts for that UA (CLI-PQC-05) beside those its
    /// envelopes bound. `CardRefused` when it does not count; `false` for a card without a Matrix id (nothing bound).
    pub async fn add_card(
        &self,
        chain: &str,
        card: &PqChatCard,
        sig: &AppUaSig,
    ) -> Result<bool, PqChatError> {
        self.conf(chain)?;
        let ok = self
            .app
            .verify_pqchat_card(chain.into(), card.ua.clone(), card.clone(), sig.clone())
            .await?;
        if !ok {
            return Err(PqChatError::CardRefused);
        }
        if card.matrix_id.is_empty() {
            return Ok(false);
        }
        self.bind_mxid(&card.ua, &card.matrix_id)?;
        Ok(true)
    }

    /// `ua`'s Matrix id as `claimed` (an epoch's `sealedInfo` map, the author's claim) when `ua` asserted it.
    fn bound_id(&self, ua: &str, claimed: Option<&String>) -> Result<Option<String>, PqChatError> {
        let held = self.matrix_ids_of(ua)?;
        Ok(claimed.filter(|c| held.contains(c)).cloned())
    }

    /// The Matrix room of `ep`'s list put to use for its session (an accepted one): neither joined nor read while the user
    /// has not confirmed it; refused (shown with the reason, `RoomNotUsed`) when another session holds it, or when the
    /// account had joined it before this client bound it and one of its members does not check against `ep` (a fresh
    /// device's room: every id it holds, joined or invited, is the account's own or one `ep`'s `sealedInfo` maps to a member
    /// of `ep`); else joined (an invite held answered) and bound. Every `Bound` answer is told to the attached transport
    /// ([`MatrixTransport::bound`]), so a fresh device or a new Matrix login treats the room as this session's.
    pub async fn join_room(&self, ep: &OpenEpoch) -> Result<RoomUse, PqChatError> {
        self.require_accepted(&ep.epoch.session_id)?;
        let sid = ep.epoch.session_id.to_ascii_lowercase();
        let info = self.info_of(ep)?;
        let Some(room) = room_of(&info.stores) else {
            return Ok(RoomUse::None);
        };
        let entry = StoreEntry::Matrix { room: room.into() };
        if !self.prefs(&sid)?.confirmed.contains(&entry) {
            return Ok(RoomUse::Unconfirmed);
        }
        let refuse = |r: RoomRefusal| {
            self.event(Event::RoomNotUsed {
                session: sid.clone(),
                reason: r,
            });
            Ok(RoomUse::Refused(r))
        };
        match self.room_bind(room)? {
            Some(RoomBind {
                session: Some(s), ..
            }) if s == sid => return self.told_bound(room).await,
            Some(RoomBind {
                session: Some(_), ..
            }) => return refuse(RoomRefusal::OtherSession),
            // created here and not given to a session yet: this one's
            Some(RoomBind { created: true, .. }) => {
                self.bind_created(room, &sid)?;
                return self.told_bound(room).await;
            }
            _ => {}
        }
        let t = self.transport()?;
        if t.joined(room).await? {
            let me = t.user_id();
            let known: Vec<&String> = info
                .matrix
                .iter()
                .filter(|(ua, _)| ep.epoch.has_member(ua))
                .map(|(_, id)| id)
                .collect();
            let members = t.members(room).await?;
            if !members.iter().all(|m| *m == me || known.contains(&m)) {
                return refuse(RoomRefusal::JoinedBefore);
            }
            Items(&*self.store).update::<RoomBind, _>(&room_key(room), |_| {
                Ok(RoomBind {
                    session: Some(sid.clone()),
                    created: false,
                })
            })?;
        } else {
            t.join(room).await?;
            // the binding written before anything else can fail, so a failure below never leaves a joined room unbound
            Items(&*self.store).update::<RoomBind, _>(&room_key(room), |_| {
                Ok(RoomBind {
                    session: Some(sid.clone()),
                    created: false,
                })
            })?;
            // the invite is no longer held (the bound room is the session's from here; a failed release changes nothing)
            let _ = t.hold_invite(room, false).await;
        }
        self.index_bound(room)?;
        t.bound(room).await?;
        Ok(RoomUse::Bound)
    }

    /// `room` added to the list of bound rooms (at most [`BOUND_MAX`], the oldest dropped), read by
    /// [`PqChat::tell_bound_rooms`].
    fn index_bound(&self, room: &str) -> Result<(), PqChatError> {
        Items(&*self.store).update::<Vec<String>, _>(BOUND_INDEX, |v| {
            let mut v = v.unwrap_or_default();
            if !v.iter().any(|r| r == room) {
                v.push(room.to_string());
            }
            while v.len() > BOUND_MAX {
                v.remove(0);
            }
            Ok(v)
        })?;
        Ok(())
    }

    /// Every room this device binds to an accepted session told to the attached transport ([`MatrixTransport::bound`]), so
    /// a Matrix client that knows none of them (a fresh device, a new Matrix login, a profile without a store key) treats
    /// them as PqChat rooms before any session is opened. The app calls it after [`PqChat::attach_matrix`]. How many.
    pub async fn tell_bound_rooms(&self) -> Result<usize, PqChatError> {
        let t = self.transport()?;
        let rooms: Vec<String> = Items(&*self.store).get(BOUND_INDEX)?.unwrap_or_default();
        let mut n = 0;
        for room in rooms {
            if let Some(s) = self.room_session(&room)? {
                if self.is_accepted(&s)? {
                    t.bound(&room).await?;
                    n += 1;
                }
            }
        }
        Ok(n)
    }

    /// `Bound`, told to the transport when one is attached (none attached: nothing to tell).
    async fn told_bound(&self, room: &str) -> Result<RoomUse, PqChatError> {
        if let Some(t) = self.matrix() {
            t.bound(room).await?;
        }
        Ok(RoomUse::Bound)
    }

    /// A `net.scaas.pqchat.v1` event of `room` handed in by the app's client: kept while the seed is locked (CLI-PQC-10);
    /// ignored when no accepted session binds the room; else parsed with bounds (`decode`) and read as its session's
    /// (CLI-PQC-07). A message that passed every check binds its sender's Matrix id to the record's sender UA.
    pub async fn matrix_event(&self, room: &str, ev: RoomEvent) -> Result<MatrixIn, PqChatError> {
        if self.keep_locked(room, &ev)? {
            return Ok(MatrixIn::Kept);
        }
        let Some(sid) = self.room_session(room)? else {
            return Ok(MatrixIn::Ignored);
        };
        if !self.is_accepted(&sid)? {
            return Ok(MatrixIn::Ignored);
        }
        let (hint, env) = match parse(&ev.content) {
            Ok(x) => x,
            Err(d) => {
                self.drops.add(&sid, d);
                return Ok(MatrixIn::Read(Incoming::Dropped(d)));
            }
        };
        let (r, sender) = self.incoming_from(&sid, &hint, env).await?;
        if let Some(ua) = sender {
            self.bind_mxid(&ua, &ev.sender)?;
        }
        Ok(MatrixIn::Read(r))
    }

    /// `room`'s history read back (to its first event, the server's retention limit, or [`HISTORY_PAGES`] pages), its events
    /// processed oldest first as [`PqChat::matrix_event`] (an id seen is a duplicate); how many were shown.
    pub async fn read_room(&self, room: &str) -> Result<usize, PqChatError> {
        let sid = self.room_session(room)?.ok_or(PqChatError::MatrixRoom)?;
        self.require_accepted(&sid)?;
        let t = self.transport()?;
        let mut pages = vec![];
        let mut before = None;
        let mut n = 0;
        for _ in 0..HISTORY_PAGES {
            let p = t.history(room, before).await?;
            n += p.events.len();
            before = p.before;
            pages.push(p.events);
            if before.is_none() || n >= HISTORY_MAX {
                break;
            }
        }
        let mut shown = 0;
        for ev in pages.into_iter().rev().flatten().take(HISTORY_MAX) {
            if let MatrixIn::Read(Incoming::Shown(_)) = self.matrix_event(room, ev).await? {
                shown += 1;
            }
        }
        Ok(shown)
    }

    /// The room's membership after `ep`, by `me`'s client when `me` authored it, once it is complete at home (`epochComplete`,
    /// a trusted read; `EpochIncomplete` before): the Matrix ids its `sealedInfo` maps to members new since `parent` (every
    /// other member for a session record) invited, those of the parent's members it drops removed when its author is an
    /// admin of the parent by the home's record (never by a Matrix power level), the admins' ids given the level that
    /// invites and removes; only ids bound to their UA (`unbound` otherwise). A transport failure stops there, reported.
    pub async fn sync_room(
        &self,
        s: &SessionRef,
        ep: &OpenEpoch,
        parent: Option<&OpenEpoch>,
        me: &Me,
    ) -> Result<RoomSync, PqChatError> {
        let sid = ep.epoch.session_id.to_ascii_lowercase();
        self.require_accepted(&sid)?;
        let ua = me.ua.to_ascii_lowercase();
        let mut out = RoomSync::default();
        if ep.epoch.author != ua {
            return Ok(out);
        }
        let info = self.info_of(ep)?;
        let Some(room) = room_of(&info.stores) else {
            return Ok(out);
        };
        if self.room_session(room)?.as_deref() != Some(sid.as_str()) {
            return Err(PqChatError::MatrixRoom);
        }
        let done = self
            .net
            .read(
                &s.chain,
                &s.home,
                "IPqChat.epochComplete",
                json!({ "epochId": ep.epoch.id }),
            )
            .await?;
        if at(&done, "0") != true {
            return Err(PqChatError::EpochIncomplete);
        }
        let t = self.transport()?;
        let was = |u: &str| parent.is_some_and(|p| p.epoch.has_member(u));
        let mut calls: Vec<(u8, String, String)> = vec![];
        for m in ep
            .epoch
            .members
            .iter()
            .filter(|m| m.ua != ua && !was(&m.ua))
        {
            match self.bound_id(&m.ua, info.matrix.get(&m.ua))? {
                Some(id) => calls.push((0, m.ua.clone(), id)),
                None => out.unbound.push(m.ua.clone()),
            }
        }
        if let Some(p) = parent {
            let admin = p.epoch.admins.contains(&ua);
            let pinfo = self.info_of(p)?;
            for m in p
                .epoch
                .members
                .iter()
                .filter(|m| m.ua != ua && !ep.epoch.has_member(&m.ua))
            {
                if !admin {
                    continue;
                }
                match self.bound_id(&m.ua, pinfo.matrix.get(&m.ua))? {
                    Some(id) => calls.push((1, m.ua.clone(), id)),
                    None => out.unbound.push(m.ua.clone()),
                }
            }
        }
        for a in ep.epoch.admins.iter().filter(|a| **a != ua) {
            if let Some(id) = self.bound_id(a, info.matrix.get(a))? {
                calls.push((2, a.clone(), id));
            }
        }
        for (op, u, id) in calls {
            let r = match op {
                0 => t.invite(room, &id).await,
                1 => t.remove(room, &id).await,
                _ => t.set_admin(room, &id, true).await,
            };
            if let Err(e) = r {
                out.failed = Some(e.code());
                return Ok(out);
            }
            match op {
                0 => out.invited.push(u),
                1 => out.removed.push(u),
                _ => {}
            }
        }
        Ok(out)
    }
}

impl PqChat {
    /// While the seed is locked: `ev` kept in the store, every one, up to [`LOCKED_MAX`] per room, past it the room marked
    /// to be read again from its history (CLI-PQC-10). Nothing is read, sent or answered. `false` when the seed is open.
    fn keep_locked(&self, room: &str, ev: &RoomEvent) -> Result<bool, PqChatError> {
        if !self.is_locked() {
            return Ok(false);
        }
        Items(&*self.store).update::<Vec<String>, _>(KEPT_ROOMS, |r| {
            let mut r = r.unwrap_or_default();
            if !r.iter().any(|x| x == room) {
                r.push(room.to_string());
            }
            Ok(r)
        })?;
        Items(&*self.store).update::<Kept, _>(&kept_key(room), |k| {
            let mut k = k.unwrap_or_default();
            if k.events.len() < LOCKED_MAX {
                k.events.push(ev.clone());
            } else {
                k.overflow = true;
            }
            Ok(k)
        })?;
        Ok(true)
    }

    /// How many events are kept for `room` while locked, and whether its bound was passed.
    pub fn kept(&self, room: &str) -> Result<(usize, bool), PqChatError> {
        let k: Kept = Items(&*self.store)
            .get(&kept_key(room))?
            .unwrap_or_default();
        Ok((k.events.len(), k.overflow))
    }

    /// The events kept while locked, processed in their order (rooms in the order first kept); a room whose bound was
    /// passed read again from its history; each room's items emptied once processed. How many were shown.
    pub(crate) async fn process_kept(&self) -> Result<usize, PqChatError> {
        let rooms: Vec<String> = Items(&*self.store).get(KEPT_ROOMS)?.unwrap_or_default();
        let mut shown = 0;
        for room in rooms {
            let k: Kept = Items(&*self.store)
                .get(&kept_key(&room))?
                .unwrap_or_default();
            for ev in k.events {
                if let MatrixIn::Read(Incoming::Shown(_)) = self.matrix_event(&room, ev).await? {
                    shown += 1;
                }
            }
            let bound = self.room_session(&room)?;
            if k.overflow && bound.is_some_and(|s| self.is_accepted(&s).unwrap_or(false)) {
                shown += self.read_room(&room).await?;
            }
            Items(&*self.store).update::<Kept, _>(&kept_key(&room), |_| Ok(Kept::default()))?;
            Items(&*self.store).update::<Vec<String>, _>(KEPT_ROOMS, |r| {
                Ok(r.unwrap_or_default()
                    .into_iter()
                    .filter(|x| *x != room)
                    .collect())
            })?;
        }
        Ok(shown)
    }
}
