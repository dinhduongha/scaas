// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! PqChat's Matrix transport (CLI-PQC-05, CLI-MTX-01): the trait `pqchat-core` sends and reads its `net.scaas.pqchat.v1`
//! events through, and the conformance test every implementation passes. It is a crate of its own so that `scaas-matrix`
//! implements the trait without depending on `pqchat-core` (and so on the SDK), and `pqchat-core` uses it without a Matrix
//! crate. `pqchat-core` re-exports every item at `pqchat_core::matrix`; the event's codec stays there.
#![forbid(unsafe_code)]
use async_trait::async_trait;
use serde_json::{json, Value};

/// The event type.
pub const EVENT_TYPE: &str = "net.scaas.pqchat.v1";
/// An event's content above this is dropped, by the transport and by `pqchat-core`'s `parse`: a homeserver's event bound.
pub const EVENT_MAX: usize = 65_536;

/// A transport call that failed. It carries no room id or Matrix id; `pqchat-core` reads it as `MatrixRoom` (a room that
/// cannot be created, joined or written).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportError;

impl TransportError {
    /// The code `pqchat-core` reports it by.
    pub fn code(&self) -> &'static str {
        "MatrixRoom"
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for TransportError {}

/// One `net.scaas.pqchat.v1` event of a room as the transport hands it: its sender's Matrix id and its content's JSON bytes
/// (at most [`EVENT_MAX`]). Its `Debug` shows neither.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoomEvent {
    pub sender: String,
    pub content: Vec<u8>,
}

impl std::fmt::Debug for RoomEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RoomEvent {{ content: {} bytes }}", self.content.len())
    }
}

/// A page of a room's `net.scaas.pqchat.v1` history, oldest first, and the token of the page before it (`None`: the room's
/// first event or the server's retention limit reached).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryPage {
    pub events: Vec<RoomEvent>,
    pub before: Option<String>,
}

/// The app's Matrix client as `pqchat-core` uses it (its spec §6.1). **In a room the crate has bound, an implementation sends
/// no Matrix read receipt, read marker, typing notice or presence update, and joins only on the crate's call** (UA-7 P15, D10:
/// a receipt of an event shown would be a signal that depends on a decryption); [`conformance`] holds an implementation to
/// it. Errors carry no room id or Matrix id.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait MatrixTransport: Send + Sync {
    /// The account's own Matrix id.
    fn user_id(&self) -> String;
    /// A new private room **without Matrix encryption** (CLI-PQC-05); its id.
    async fn create_room(&self) -> Result<String, TransportError>;
    /// Whether the account is joined to `room` now.
    async fn joined(&self, room: &str) -> Result<bool, TransportError>;
    /// The Matrix ids `room` holds now, joined or invited (a room the account is joined to).
    async fn members(&self, room: &str) -> Result<Vec<String>, TransportError>;
    /// Joins `room` (an invite held by [`MatrixTransport::hold_invite`] is answered by this call only).
    async fn join(&self, room: &str) -> Result<(), TransportError>;
    async fn invite(&self, room: &str, user: &str) -> Result<(), TransportError>;
    async fn remove(&self, room: &str, user: &str) -> Result<(), TransportError>;
    /// `user` given (or no longer given) the power level that invites and removes; it grants no PqChat right.
    async fn set_admin(&self, room: &str, user: &str, admin: bool) -> Result<(), TransportError>;
    /// Sends one [`EVENT_TYPE`] event with `content` in `room`.
    async fn send_event(&self, room: &str, content: Value) -> Result<(), TransportError>;
    /// The page of `room`'s [`EVENT_TYPE`] events before `before` (`None`: the latest).
    async fn history(
        &self,
        room: &str,
        before: Option<String>,
    ) -> Result<HistoryPage, TransportError>;
    /// An invite to `room` held unanswered (`hold`), or no longer held: a pending session's room (CLI-PQC-08). An
    /// implementation may refuse to hold a room the account already uses for something else (`scaas-matrix`: a room the
    /// homeserver says the account is joined to, or no answer from it); the caller then treats the room as not usable.
    /// `pqchat-core` holds only a room the account is not joined to. `scaas-matrix` releases a hold on `hold == false` and
    /// when the account joins the room from elsewhere.
    async fn hold_invite(&self, room: &str, hold: bool) -> Result<(), TransportError>;
    /// `room` serves a session the crate has bound (CLI-PQC-05): from now on the implementation treats it as such (no Matrix
    /// receipt, read marker, typing notice or presence; its events go to the crate). Called on every use of a bound room, so a
    /// fresh device or a new Matrix login learns the binding the crate's store holds. Nothing to do by default.
    async fn bound(&self, _room: &str) -> Result<(), TransportError> {
        Ok(())
    }
}

/// What a homeserver holds of an account's ephemeral and membership signals in one room, as another party sees them: the
/// conformance test's witness (`pqchat-core` spec §6.1, K9).
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
    /// The other account's Matrix id.
    fn user_id(&self) -> String;
    /// `user`'s signals in `room`, as the server holds them.
    async fn seen(&self, room: &str, user: &str) -> Result<Seen, TransportError>;
    /// A room the other account creates and invites `user` to; its id.
    async fn invite_me(&self, user: &str) -> Result<String, TransportError>;
    /// One [`EVENT_TYPE`] event with `content` sent by the other account in `room`.
    async fn post(&self, room: &str, content: Value) -> Result<(), TransportError>;
}

/// The conformance test of a [`MatrixTransport`] (CLI-PQC-05, K9), run against `pqchat-core`'s fake, its e2e's client and
/// `scaas-matrix`: a room it creates is not encrypted, is joined, and holds the event sent as sent; an invite to it shows in
/// its members; an invite held is not answered until [`MatrixTransport::join`], after which its members hold both accounts;
/// after sending, reading history and receiving in both rooms, the server holds no read receipt, read marker, typing notice
/// or presence update of the account. The first failure by name.
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
    if !t.joined(&room).await.map_err(|_| "joined")? {
        return Err("joined");
    }
    let other_id = w.user_id();
    // an envelope event's form (`pqchat-core`'s codec): hint [1; 8], env [2; 33], base64 with padding
    let ev = json!({"v": 1, "hint": "AQEBAQEBAQE=", "env": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC"});
    t.send_event(&room, ev.clone())
        .await
        .map_err(|_| "send_event")?;
    let h = t.history(&room, None).await.map_err(|_| "history")?;
    let mine = |p: &HistoryPage| {
        p.events.iter().any(|e| {
            e.sender == me && serde_json::from_slice::<Value>(&e.content).ok().as_ref() == Some(&ev)
        })
    };
    if !mine(&h) {
        return Err("history without the event sent");
    }
    t.invite(&room, &other_id).await.map_err(|_| "invite")?;
    if !t
        .members(&room)
        .await
        .map_err(|_| "members")?
        .contains(&other_id)
    {
        return Err("members without the invited");
    }
    let other = w.invite_me(&me).await.map_err(|_| "witness")?;
    t.hold_invite(&other, true)
        .await
        .map_err(|_| "hold_invite")?;
    w.post(&other, ev).await.map_err(|_| "witness")?;
    if w.seen(&other, &me).await.map_err(|_| "witness")?.joined {
        return Err("joined without the crate's call");
    }
    t.join(&other).await.map_err(|_| "join")?;
    if !w.seen(&other, &me).await.map_err(|_| "witness")?.joined {
        return Err("join not done");
    }
    let m = t.members(&other).await.map_err(|_| "members")?;
    if !m.contains(&me) || !m.contains(&other_id) {
        return Err("members");
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
