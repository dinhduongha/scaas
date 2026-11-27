// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! A recording fake of the app's Matrix client (spec §6.1) over an in-memory homeserver: rooms with their members, invites,
//! encryption flag and `net.scaas.pqchat.v1` events; every call of each client recorded; the server's view of each account's
//! receipts, read markers, typing and presence for the conformance test's witness. Local only, nothing leaves the process.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
use async_trait::async_trait;
use pqchat_core::matrix::TransportError;
use pqchat_core::matrix::{HistoryPage, MatrixTransport, RoomEvent, Seen, Witness, EVENT_TYPE};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// A history page's size.
pub const PAGE: usize = 8;

#[derive(Default)]
pub struct RoomState {
    pub creator: String,
    pub encrypted: bool,
    pub members: BTreeSet<String>,
    pub invited: BTreeSet<String>,
    pub admins: BTreeSet<String>,
    /// (sender, type, content)
    pub events: Vec<(String, String, Value)>,
    /// (user, kind): `m.receipt`, `m.fully_read`, `m.typing`
    pub ephemeral: Vec<(String, String)>,
}

#[derive(Default)]
pub struct Server {
    pub rooms: Mutex<BTreeMap<String, RoomState>>,
    pub presence: Mutex<Vec<String>>,
    next: AtomicU64,
}

impl Server {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn room_id(&self) -> String {
        format!("!r{}:fake.local", self.next.fetch_add(1, Ordering::SeqCst))
    }
    /// A room `creator` made itself (an ordinary one: Matrix-encrypted when `encrypted`), `members` joined.
    pub fn ordinary(&self, creator: &str, members: &[&str], encrypted: bool) -> String {
        let id = self.room_id();
        let mut r = RoomState {
            creator: creator.into(),
            encrypted,
            ..Default::default()
        };
        r.members.insert(creator.into());
        r.members.extend(members.iter().map(|m| m.to_string()));
        self.rooms.lock().unwrap().insert(id.clone(), r);
        id
    }
    /// `user` put into `room` directly (a test's setup).
    pub fn add_member(&self, room: &str, user: &str) {
        self.rooms
            .lock()
            .unwrap()
            .get_mut(room)
            .unwrap()
            .members
            .insert(user.into());
    }
    /// An event `sender` posted in `room`.
    pub fn post_as(&self, room: &str, sender: &str, content: Value) {
        self.rooms
            .lock()
            .unwrap()
            .get_mut(room)
            .unwrap()
            .events
            .push((sender.into(), EVENT_TYPE.into(), content));
    }
    pub fn is_member(&self, room: &str, user: &str) -> bool {
        self.rooms
            .lock()
            .unwrap()
            .get(room)
            .is_some_and(|r| r.members.contains(user))
    }
    pub fn is_invited(&self, room: &str, user: &str) -> bool {
        self.rooms
            .lock()
            .unwrap()
            .get(room)
            .is_some_and(|r| r.invited.contains(user))
    }
    /// The events of `room` as the transport hands them.
    pub fn events_of(&self, room: &str) -> Vec<RoomEvent> {
        self.rooms.lock().unwrap()[room]
            .events
            .iter()
            .filter(|(_, t, _)| t == EVENT_TYPE)
            .map(|(s, _, c)| RoomEvent {
                sender: s.clone(),
                content: c.to_string().into_bytes(),
            })
            .collect()
    }
}

/// One account's client on the fake server: every call recorded by name.
pub struct Client {
    pub server: Arc<Server>,
    pub user: String,
    pub calls: Mutex<Vec<(String, String)>>,
    pub held: Mutex<BTreeSet<String>>,
    /// `send_event` fails (`MatrixRoom`): a transport failure for that store only
    pub fail_send: AtomicBool,
}

impl Client {
    pub fn new(server: &Arc<Server>, user: &str) -> Arc<Self> {
        Arc::new(Client {
            server: server.clone(),
            user: user.into(),
            calls: Mutex::new(vec![]),
            held: Mutex::new(BTreeSet::new()),
            fail_send: AtomicBool::new(false),
        })
    }
    fn rec(&self, call: &str, room: &str) {
        self.calls.lock().unwrap().push((call.into(), room.into()));
    }
    /// The calls named `call`, their rooms.
    pub fn calls_of(&self, call: &str) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(c, _)| c == call)
            .map(|(_, r)| r.clone())
            .collect()
    }
    /// Every call but `user_id`, `joined`, `members` and `hold_invite` (the network calls that answer or act).
    pub fn acting(&self) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(c, _)| !matches!(c.as_str(), "joined" | "members" | "hold_invite" | "bound"))
            .count()
    }
}

fn no_room() -> TransportError {
    TransportError
}

#[async_trait]
impl MatrixTransport for Client {
    fn user_id(&self) -> String {
        self.user.clone()
    }
    async fn create_room(&self) -> Result<String, TransportError> {
        let id = self.server.room_id();
        self.rec("create_room", &id);
        let mut r = RoomState {
            creator: self.user.clone(),
            encrypted: false,
            ..Default::default()
        };
        r.members.insert(self.user.clone());
        self.server.rooms.lock().unwrap().insert(id.clone(), r);
        Ok(id)
    }
    async fn joined(&self, room: &str) -> Result<bool, TransportError> {
        self.rec("joined", room);
        Ok(self.server.is_member(room, &self.user))
    }
    async fn members(&self, room: &str) -> Result<Vec<String>, TransportError> {
        self.rec("members", room);
        let rooms = self.server.rooms.lock().unwrap();
        let r = rooms.get(room).ok_or_else(no_room)?;
        Ok(r.members.iter().chain(&r.invited).cloned().collect())
    }
    async fn join(&self, room: &str) -> Result<(), TransportError> {
        self.rec("join", room);
        let mut rooms = self.server.rooms.lock().unwrap();
        let r = rooms.get_mut(room).ok_or_else(no_room)?;
        if !r.invited.remove(&self.user) && !r.members.contains(&self.user) {
            return Err(no_room());
        }
        r.members.insert(self.user.clone());
        Ok(())
    }
    async fn invite(&self, room: &str, user: &str) -> Result<(), TransportError> {
        self.rec("invite", room);
        let mut rooms = self.server.rooms.lock().unwrap();
        let r = rooms.get_mut(room).ok_or_else(no_room)?;
        r.invited.insert(user.into());
        Ok(())
    }
    async fn remove(&self, room: &str, user: &str) -> Result<(), TransportError> {
        self.rec("remove", room);
        let mut rooms = self.server.rooms.lock().unwrap();
        let r = rooms.get_mut(room).ok_or_else(no_room)?;
        r.members.remove(user);
        r.invited.remove(user);
        Ok(())
    }
    async fn set_admin(&self, room: &str, user: &str, admin: bool) -> Result<(), TransportError> {
        self.rec("set_admin", room);
        let mut rooms = self.server.rooms.lock().unwrap();
        let r = rooms.get_mut(room).ok_or_else(no_room)?;
        if admin {
            r.admins.insert(user.into());
        } else {
            r.admins.remove(user);
        }
        Ok(())
    }
    async fn send_event(&self, room: &str, content: Value) -> Result<(), TransportError> {
        self.rec("send_event", room);
        if self.fail_send.load(Ordering::SeqCst) {
            return Err(no_room());
        }
        let mut rooms = self.server.rooms.lock().unwrap();
        let r = rooms.get_mut(room).ok_or_else(no_room)?;
        if !r.members.contains(&self.user) {
            return Err(no_room());
        }
        r.events
            .push((self.user.clone(), EVENT_TYPE.into(), content));
        Ok(())
    }
    async fn history(
        &self,
        room: &str,
        before: Option<String>,
    ) -> Result<HistoryPage, TransportError> {
        self.rec("history", room);
        let mut rooms = self.server.rooms.lock().unwrap();
        let r = rooms.get_mut(room).ok_or_else(no_room)?;
        if !r.members.contains(&self.user) {
            return Err(no_room());
        }
        let all: Vec<RoomEvent> = r
            .events
            .iter()
            .filter(|(_, t, _)| t == EVENT_TYPE)
            .map(|(s, _, c)| RoomEvent {
                sender: s.clone(),
                content: c.to_string().into_bytes(),
            })
            .collect();
        let end = before.map_or(all.len(), |b| b.parse::<usize>().unwrap().min(all.len()));
        let start = end.saturating_sub(PAGE);
        // no receipt, read marker, typing or presence (CLI-PQC-05)
        Ok(HistoryPage {
            events: all[start..end].to_vec(),
            before: (start > 0).then(|| start.to_string()),
        })
    }
    async fn hold_invite(&self, room: &str, hold: bool) -> Result<(), TransportError> {
        self.rec("hold_invite", room);
        let mut h = self.held.lock().unwrap();
        if hold {
            h.insert(room.into());
        } else {
            h.remove(room);
        }
        Ok(())
    }
    async fn bound(&self, room: &str) -> Result<(), TransportError> {
        self.rec("bound", room);
        Ok(())
    }
}

/// The witness: another account (`@witness:fake.local`) on the same server.
pub struct ServerWitness(pub Arc<Server>);

pub const WITNESS: &str = "@witness:fake.local";

#[async_trait]
impl Witness for ServerWitness {
    fn user_id(&self) -> String {
        WITNESS.into()
    }
    async fn seen(&self, room: &str, user: &str) -> Result<Seen, TransportError> {
        let rooms = self.0.rooms.lock().unwrap();
        let r = rooms.get(room).ok_or_else(no_room)?;
        let count = |k: &str| {
            r.ephemeral
                .iter()
                .filter(|(u, x)| u == user && x == k)
                .count() as u64
        };
        Ok(Seen {
            receipts: count("m.receipt"),
            read_markers: count("m.fully_read"),
            typing: count("m.typing"),
            presence: self
                .0
                .presence
                .lock()
                .unwrap()
                .iter()
                .filter(|u| *u == user)
                .count() as u64,
            joined: r.members.contains(user),
            encrypted: r.encrypted,
            events: r.events.iter().filter(|(_, t, _)| t == EVENT_TYPE).count() as u64,
        })
    }
    async fn invite_me(&self, user: &str) -> Result<String, TransportError> {
        let id = self.0.ordinary(WITNESS, &[], false);
        self.0
            .rooms
            .lock()
            .unwrap()
            .get_mut(&id)
            .unwrap()
            .invited
            .insert(user.into());
        Ok(id)
    }
    async fn post(&self, room: &str, content: Value) -> Result<(), TransportError> {
        self.0.post_as(room, WITNESS, content);
        Ok(())
    }
}
