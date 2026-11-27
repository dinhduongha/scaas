// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T8's conformance (CLI-PQC-05, K9): `pqchat_core::matrix::conformance` over the fake transport and its server's
//! witness (the e2e's implementation runs it in T11, `scaas-matrix` in its own e2e): the fake conforms; a transport that sends a
//! read receipt, a read marker, a typing notice or a presence update in a bound room, joins on an invite by itself, creates
//! an encrypted room, sends another content than asked or lists no invited member fails, each by its own name, beside the
//! conforming control.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;

use async_trait::async_trait;
use common::matrix::{Client, Server, ServerWitness};
use pqchat_core::matrix::{conformance, HistoryPage, MatrixTransport, TransportError};
use serde_json::Value;
use std::sync::Arc;

const ME: &str = "@alice:fake.local";

/// The fake with one fault: what it does on top of the conforming client.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    Receipt,
    ReadMarker,
    Typing,
    Presence,
    AutoJoin,
    Encrypted,
    /// sends another content than asked
    Rewrite,
    /// lists joined members only, not the invited
    NoInvited,
}

struct Leaky {
    inner: Arc<Client>,
    fault: Fault,
}

impl Leaky {
    fn signal(&self, room: &str, kind: &str) {
        let mut rooms = self.inner.server.rooms.lock().unwrap();
        if let Some(r) = rooms.get_mut(room) {
            r.ephemeral.push((ME.into(), kind.into()));
        }
    }
}

#[async_trait]
impl MatrixTransport for Leaky {
    fn user_id(&self) -> String {
        self.inner.user_id()
    }
    async fn create_room(&self) -> Result<String, TransportError> {
        let r = self.inner.create_room().await?;
        if self.fault == Fault::Encrypted {
            self.inner
                .server
                .rooms
                .lock()
                .unwrap()
                .get_mut(&r)
                .unwrap()
                .encrypted = true;
        }
        Ok(r)
    }
    async fn joined(&self, room: &str) -> Result<bool, TransportError> {
        self.inner.joined(room).await
    }
    async fn members(&self, room: &str) -> Result<Vec<String>, TransportError> {
        let m = self.inner.members(room).await?;
        if self.fault != Fault::NoInvited {
            return Ok(m);
        }
        let rooms = self.inner.server.rooms.lock().unwrap();
        let invited = &rooms.get(room).unwrap().invited;
        Ok(m.into_iter().filter(|u| !invited.contains(u)).collect())
    }
    async fn join(&self, room: &str) -> Result<(), TransportError> {
        self.inner.join(room).await
    }
    async fn invite(&self, room: &str, user: &str) -> Result<(), TransportError> {
        self.inner.invite(room, user).await
    }
    async fn remove(&self, room: &str, user: &str) -> Result<(), TransportError> {
        self.inner.remove(room, user).await
    }
    async fn set_admin(&self, room: &str, user: &str, admin: bool) -> Result<(), TransportError> {
        self.inner.set_admin(room, user, admin).await
    }
    async fn send_event(&self, room: &str, content: Value) -> Result<(), TransportError> {
        let content = match self.fault {
            Fault::Rewrite => serde_json::json!({"v": 1, "hint": "AAAAAAAAAAA=", "env": "AA=="}),
            _ => content,
        };
        self.inner.send_event(room, content).await?;
        if self.fault == Fault::Typing {
            self.signal(room, "m.typing");
        }
        Ok(())
    }
    async fn history(
        &self,
        room: &str,
        before: Option<String>,
    ) -> Result<HistoryPage, TransportError> {
        let p = self.inner.history(room, before).await?;
        match self.fault {
            Fault::Receipt => self.signal(room, "m.receipt"),
            Fault::ReadMarker => self.signal(room, "m.fully_read"),
            Fault::Presence => self.inner.server.presence.lock().unwrap().push(ME.into()),
            _ => {}
        }
        Ok(p)
    }
    async fn bound(&self, room: &str) -> Result<(), TransportError> {
        self.inner.bound(room).await
    }
    async fn hold_invite(&self, room: &str, hold: bool) -> Result<(), TransportError> {
        self.inner.hold_invite(room, hold).await?;
        if self.fault == Fault::AutoJoin {
            let _ = self.inner.join(room).await;
        }
        Ok(())
    }
}

/// The fake conforms (the control of every negative below).
#[tokio::test]
async fn fake_conforms() {
    let server = Server::new();
    let c = Client::new(&server, ME);
    assert_eq!(
        conformance(&*c, &ServerWitness(server.clone())).await,
        Ok(())
    );
    // it created one room without Matrix encryption and joined the other only on the call
    assert_eq!(c.calls_of("create_room").len(), 1);
    assert_eq!(c.calls_of("join").len(), 1);
    // the event `conformance` sends is the codec's form of hint [1; 8], env [2; 33] (its literal pinned to `event`)
    let rooms = server.rooms.lock().unwrap();
    let sent: Vec<&Value> = rooms
        .values()
        .flat_map(|r| r.events.iter())
        .filter(|(s, _, _)| s == ME)
        .map(|(_, _, c)| c)
        .collect();
    assert_eq!(sent.len(), 1);
    assert_eq!(*sent[0], pqchat_core::matrix::event(&[1; 8], &[2; 33]));
}

/// Each fault fails by its own name.
#[tokio::test]
async fn faults_fail_by_name() {
    for (fault, name) in [
        (Fault::Receipt, "read receipt"),
        (Fault::ReadMarker, "read marker"),
        (Fault::Typing, "typing notice"),
        (Fault::Presence, "presence"),
        (Fault::AutoJoin, "joined without the crate's call"),
        (Fault::Encrypted, "encrypted"),
        (Fault::Rewrite, "history without the event sent"),
        (Fault::NoInvited, "members without the invited"),
    ] {
        let server = Server::new();
        let t = Leaky {
            inner: Client::new(&server, ME),
            fault,
        };
        assert_eq!(
            conformance(&t, &ServerWitness(server.clone())).await,
            Err(name)
        );
    }
}
