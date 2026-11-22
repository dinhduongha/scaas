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
use crate::drops::Drop;
use crate::message::{Incoming, OpenEpoch};
use crate::model::at;
use crate::reads::SessionRef;
use crate::session::{Me, StoreEntry};
use crate::{Event, Items, PqChat, PqChatError};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use scaas_sdk::app_core::AppUaSig;
use scaas_sdk::pqchat_records::PqChatCard;
use serde_json::{json, Value};

/// One `net.scaas.pqchat.v1` event of a room as the transport hands it: its sender's Matrix id and its content's JSON bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoomEvent {
    pub sender: String,
    pub content: Vec<u8>,
}

/// A page of a room's `net.scaas.pqchat.v1` history, oldest first, and the token of the page before it (`None`: the room's
/// first event or the server's retention limit reached).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryPage {
    pub events: Vec<RoomEvent>,
    pub before: Option<String>,
}

/// The app's Matrix client as the crate uses it (spec §6.1). **In a room the crate has bound, an implementation sends no
/// Matrix read receipt, read marker, typing notice or presence update, and joins only on the crate's call** (UA-7 P15, D10:
/// a receipt of an event shown would be a signal that depends on a decryption); [`conformance`] holds an implementation to
/// it. Errors carry no room id or Matrix id (`MatrixRoom` for a room that cannot be created, joined or written).
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait MatrixTransport: Send + Sync {
    /// The account's own Matrix id.
    fn user_id(&self) -> String;
    /// A new private room **without Matrix encryption** (CLI-PQC-05); its id.
    async fn create_room(&self) -> Result<String, PqChatError>;
    /// Whether the account is joined to `room` now.
    async fn joined(&self, room: &str) -> Result<bool, PqChatError>;
    /// The Matrix ids `room` holds now, joined or invited (a room the account is joined to).
    async fn members(&self, room: &str) -> Result<Vec<String>, PqChatError>;
    /// Joins `room` (an invite held by [`MatrixTransport::hold_invite`] is answered by this call only).
    async fn join(&self, room: &str) -> Result<(), PqChatError>;
    async fn invite(&self, room: &str, user: &str) -> Result<(), PqChatError>;
    async fn remove(&self, room: &str, user: &str) -> Result<(), PqChatError>;
    /// `user` given (or no longer given) the power level that invites and removes; it grants no PqChat right.
    async fn set_admin(&self, room: &str, user: &str, admin: bool) -> Result<(), PqChatError>;
    /// Sends one [`EVENT_TYPE`] event with `content` (an [`event`]) in `room`.
    async fn send_event(&self, room: &str, content: Value) -> Result<(), PqChatError>;
    /// The page of `room`'s [`EVENT_TYPE`] events before `before` (`None`: the latest).
    async fn history(&self, room: &str, before: Option<String>)
        -> Result<HistoryPage, PqChatError>;
    /// An invite to `room` held unanswered (`hold`), or no longer held: a pending session's room (CLI-PQC-08, §13 O5 (c)).
    async fn hold_invite(&self, room: &str, hold: bool);
}

/// The event type.
pub const EVENT_TYPE: &str = "net.scaas.pqchat.v1";
/// An event's content above this is dropped (`decode`): a homeserver's event bound.
pub const EVENT_MAX: usize = 65_536;
/// History pages read back at most per room and call (the rest: the server's retention, or the next call).
pub const HISTORY_PAGES: usize = 64;
/// Events of one history read processed at most.
pub const HISTORY_MAX: usize = 4096;
/// Matrix ids kept per UA.
pub const MXIDS_MAX: usize = 8;
/// Events kept per room while the seed is locked; past it the room is read again from its history at unlock.
pub const LOCKED_MAX: usize = 64;

/// The content of the event carrying `env` under `hint`.
pub fn event(hint: &[u8], env: &[u8]) -> Value {
    json!({ "v": 1, "hint": STANDARD.encode(hint), "env": STANDARD.encode(env) })
}

/// A received event's content (its JSON bytes): the hint and the envelope, or `decode` for an event over [`EVENT_MAX`], not
/// one flat object of exactly `v`, `hint`, `env`, a `v` other than 1, a base64 form other than the padded standard one, a
/// hint other than 8 bytes, an empty envelope.
pub fn parse(content: &[u8]) -> Result<([u8; 8], Vec<u8>), Drop> {
    if content.len() > EVENT_MAX {
        return Err(Drop::Decode);
    }
    // a flat object: three string or number members; a nested value is refused before any depth is reached
    let v: serde_json::Map<String, Value> =
        serde_json::from_slice(content).map_err(|_| Drop::Decode)?;
    if v.len() != 3 || v.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(Drop::Decode);
    }
    let field = |k: &str| v.get(k).and_then(Value::as_str).ok_or(Drop::Decode);
    let (h, e) = (field("hint")?, field("env")?);
    let hint = STANDARD.decode(h).map_err(|_| Drop::Decode)?;
    let env = STANDARD.decode(e).map_err(|_| Drop::Decode)?;
    // the one canonical form: encoding the bytes again gives the text read
    if STANDARD.encode(&hint) != h || STANDARD.encode(&env) != e || env.is_empty() {
        return Err(Drop::Decode);
    }
    Ok((hint.try_into().map_err(|_| Drop::Decode)?, env))
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
        Ok(())
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
    /// of `ep`); else joined (an invite held answered) and bound.
    pub async fn join_room(&self, ep: &OpenEpoch) -> Result<RoomUse, PqChatError> {
        self.require_accepted(&ep.epoch.session_id)?;
        let sid = ep.epoch.session_id.to_ascii_lowercase();
        let info = self.info(ep)?;
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
            }) if s == sid => return Ok(RoomUse::Bound),
            Some(RoomBind {
                session: Some(_), ..
            }) => return refuse(RoomRefusal::OtherSession),
            // created here and not given to a session yet: this one's
            Some(RoomBind { created: true, .. }) => {
                self.bind_created(room, &sid)?;
                return Ok(RoomUse::Bound);
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
        } else {
            t.join(room).await?;
            t.hold_invite(room, false).await;
        }
        Items(&*self.store).update::<RoomBind, _>(&room_key(room), |_| {
            Ok(RoomBind {
                session: Some(sid.clone()),
                created: false,
            })
        })?;
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
        let info = self.info(ep)?;
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
            let pinfo = self.info(p)?;
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

/// What a homeserver holds of an account's ephemeral and membership signals in one room, as another party sees them: the
/// conformance test's witness (spec §6.1, K9).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Seen {
    pub receipts: u64,
    pub read_markers: u64,
    pub typing: u64,
    /// presence updates the account sent (not per room)
    pub presence: u64,
    pub joined: bool,
    pub encrypted: bool,
    /// [`EVENT_TYPE`] events in the room
    pub events: u64,
}

/// The homeserver's side of [`conformance`]: another account on the same server, and what the server holds.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Witness: Send + Sync {
    /// `user`'s signals in `room`, as the server holds them.
    async fn seen(&self, room: &str, user: &str) -> Result<Seen, PqChatError>;
    /// A room the other account creates and invites `user` to; its id.
    async fn invite_me(&self, user: &str) -> Result<String, PqChatError>;
    /// One [`EVENT_TYPE`] event with `content` sent by the other account in `room`.
    async fn post(&self, room: &str, content: Value) -> Result<(), PqChatError>;
}

/// The conformance test of a [`MatrixTransport`] (CLI-PQC-05, K9), run against the fake, the e2e's implementation and
/// `app-matrix`'s in its own repository: a room it creates is not encrypted and holds the event sent; an invite held is not
/// answered until [`MatrixTransport::join`]; after sending, reading history and receiving in both rooms, the server holds no
/// read receipt, read marker, typing notice or presence update of the account. The first failure by name.
pub async fn conformance(t: &dyn MatrixTransport, w: &dyn Witness) -> Result<(), &'static str> {
    let me = t.user_id();
    let room = t.create_room().await.map_err(|_| "create_room")?;
    let s = w.seen(&room, &me).await.map_err(|_| "witness")?;
    if s.encrypted {
        return Err("encrypted");
    }
    if !s.joined {
        return Err("creator not joined");
    }
    let ev = event(&[1; 8], &[2; 33]);
    t.send_event(&room, ev.clone())
        .await
        .map_err(|_| "send_event")?;
    let h = t.history(&room, None).await.map_err(|_| "history")?;
    let mine = |p: &HistoryPage| {
        p.events
            .iter()
            .any(|e| e.sender == me && parse(&e.content).is_ok())
    };
    if !mine(&h) {
        return Err("history without the event sent");
    }
    let other = w.invite_me(&me).await.map_err(|_| "witness")?;
    t.hold_invite(&other, true).await;
    w.post(&other, ev).await.map_err(|_| "witness")?;
    if w.seen(&other, &me).await.map_err(|_| "witness")?.joined {
        return Err("joined without the crate's call");
    }
    t.join(&other).await.map_err(|_| "join")?;
    if !w.seen(&other, &me).await.map_err(|_| "witness")?.joined {
        return Err("join not done");
    }
    let h = t.history(&other, None).await.map_err(|_| "history")?;
    if h.events.is_empty() {
        return Err("history of the joined room empty");
    }
    for r in [&room, &other] {
        let s = w.seen(r, &me).await.map_err(|_| "witness")?;
        if s.receipts > 0 {
            return Err("read receipt");
        }
        if s.read_markers > 0 {
            return Err("read marker");
        }
        if s.typing > 0 {
            return Err("typing notice");
        }
        if s.presence > 0 {
            return Err("presence");
        }
    }
    Ok(())
}
