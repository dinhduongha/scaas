// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The crate's rules as plain values, testable without a server: the privacy settings and their defaults (CLI-MTX-05), the
//! room kinds and their filter (CLI-MTX-06), the homeserver URL rule (CLI-MTX-04) and the bounded decode of the crate's own
//! records (CLI-MTX-09).
use crate::MatrixError;
use matrix_sdk::ruma::RoomId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;
use url::{Host, Url};

/// The privacy settings of one profile, kept in its encrypted store. Every default is off (CLI-PQC-19 G2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// read receipts as `m.read` (public) instead of `m.read.private`
    pub public_receipts: bool,
    /// typing notices sent at all
    pub typing: bool,
}

/// Which kind a room is (CLI-PQC-19 G1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoomKind {
    /// an ordinary Matrix room, classical end-to-end encryption at most
    Matrix,
    /// a room that carries a PqChat session's envelopes: never shown or used as a Matrix room
    PqChat,
}

/// The room list a caller asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomFilter {
    Matrix,
    PqChat,
}

/// The receipt type a read position goes out as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Receipt {
    Private,
    Public,
}

/// A room id's length at most (the Matrix spec's bound).
pub const ROOM_ID_MAX: usize = 255;
/// PqChat rooms marked at most per profile.
pub const MARKS_MAX: usize = 4096;
/// The session record's bound.
pub const SESSION_MAX: usize = 8 * 1024;
/// The settings record's bound.
pub const SETTINGS_MAX: usize = 4 * 1024;
/// The marks record's bound (4,096 room ids of at most 255 bytes, with JSON's quotes, commas and frame).
pub const MARKS_RECORD_MAX: usize = MARKS_MAX * (ROOM_ID_MAX + 3) + 64;
/// A text to send, at most (a Matrix event is at most 65,536 bytes).
pub const TEXT_MAX: usize = 60_000;
/// Events of a page, at most.
pub const PAGE_MAX: u32 = 100;

/// The rooms of a profile marked PqChat: created, joined or used by the transport for a bound session, or an invite it holds
/// unanswered (CLI-PQC-08). A mark is kept after a leave. Only a room id (at most 255 bytes) is marked.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marks {
    pqchat: BTreeSet<String>,
}

impl Marks {
    pub fn kind(&self, room: &str) -> RoomKind {
        if self.pqchat.contains(room) {
            RoomKind::PqChat
        } else {
            RoomKind::Matrix
        }
    }

    /// `room` marked PqChat; `MatrixArgument` for a string that is not a room id or past [`MARKS_MAX`].
    pub fn mark(&mut self, room: &str) -> Result<(), MatrixError> {
        // matrix-sdk turns on ruma's arbitrary-length ids: the spec's 255 bytes checked here
        if room.len() > ROOM_ID_MAX || RoomId::parse(room).is_err() {
            return Err(MatrixError::MatrixArgument);
        }
        if !self.pqchat.contains(room) && self.pqchat.len() >= MARKS_MAX {
            return Err(MatrixError::MatrixArgument);
        }
        self.pqchat.insert(room.to_string());
        Ok(())
    }

    /// An invite held (`hold`) marks the room PqChat, unless the account is joined to it as a Matrix room (`joined_matrix`:
    /// joined and not marked): a session someone else describes cannot take over a room the user already uses
    /// (`MatrixRoomKind`). Released, a room stays as it is.
    pub fn hold(&mut self, room: &str, hold: bool, joined_matrix: bool) -> Result<(), MatrixError> {
        if !hold {
            return Ok(());
        }
        if joined_matrix && self.kind(room) == RoomKind::Matrix {
            return Err(MatrixError::MatrixRoomKind);
        }
        self.mark(room)
    }

    /// Whether a room belongs in the list `filter` asks for.
    pub fn shows(&self, filter: RoomFilter, room: &str) -> bool {
        match filter {
            RoomFilter::Matrix => self.kind(room) == RoomKind::Matrix,
            RoomFilter::PqChat => self.kind(room) == RoomKind::PqChat,
        }
    }
}

/// A front-end's Matrix action in a room (send text, accept the invite): refused in a PqChat room.
pub fn matrix_action(kind: RoomKind) -> Result<(), MatrixError> {
    match kind {
        RoomKind::Matrix => Ok(()),
        RoomKind::PqChat => Err(MatrixError::MatrixRoomKind),
    }
}

/// The receipt a read position goes out as: private unless the user turned public receipts on; none in a PqChat room.
pub fn receipt(s: &Settings, kind: RoomKind) -> Result<Receipt, MatrixError> {
    matrix_action(kind)?;
    Ok(if s.public_receipts {
        Receipt::Public
    } else {
        Receipt::Private
    })
}

/// Whether a typing notice goes out: only when the user turned typing on; never in a PqChat room.
pub fn typing(s: &Settings, kind: RoomKind) -> Result<bool, MatrixError> {
    matrix_action(kind)?;
    Ok(s.typing)
}

/// A homeserver URL: `https`, or `http` to a loopback IP literal only (the local test server); else `EndpointScheme`.
pub fn homeserver(url: &str) -> Result<Url, MatrixError> {
    let u = Url::parse(url).map_err(|_| MatrixError::EndpointScheme)?;
    let loopback = match u.host() {
        Some(Host::Ipv4(a)) => IpAddr::V4(a).is_loopback(),
        Some(Host::Ipv6(a)) => IpAddr::V6(a).is_loopback(),
        _ => false,
    };
    match u.scheme() {
        "https" => Ok(u),
        "http" if loopback => Ok(u),
        _ => Err(MatrixError::EndpointScheme),
    }
}

/// One of the crate's own records, bounded by length before it is decoded (`MatrixStore` past `max` or malformed).
pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], max: usize) -> Result<T, MatrixError> {
    if bytes.len() > max {
        return Err(MatrixError::MatrixStore);
    }
    serde_json::from_slice(bytes).map_err(|_| MatrixError::MatrixStore)
}

/// A pusher's URL: `https` only (the push gateway receives the event ids).
pub fn pusher_url(url: &str) -> Result<(), MatrixError> {
    match Url::parse(url) {
        Ok(u) if u.scheme() == "https" => Ok(()),
        _ => Err(MatrixError::MatrixArgument),
    }
}

/// A text to send: at most [`TEXT_MAX`] bytes.
pub fn text(t: &str) -> Result<(), MatrixError> {
    if t.len() > TEXT_MAX {
        return Err(MatrixError::MatrixArgument);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_private() {
        let s = Settings::default();
        assert_eq!(receipt(&s, RoomKind::Matrix), Ok(Receipt::Private));
        assert_eq!(typing(&s, RoomKind::Matrix), Ok(false));
        // the opt-ins, one at a time
        let p = Settings {
            public_receipts: true,
            ..s
        };
        assert_eq!(receipt(&p, RoomKind::Matrix), Ok(Receipt::Public));
        assert_eq!(typing(&p, RoomKind::Matrix), Ok(false));
        let t = Settings { typing: true, ..s };
        assert_eq!(typing(&t, RoomKind::Matrix), Ok(true));
        assert_eq!(receipt(&t, RoomKind::Matrix), Ok(Receipt::Private));
    }

    #[test]
    fn nothing_ephemeral_in_a_pqchat_room_whatever_the_settings() {
        let all = Settings {
            public_receipts: true,
            typing: true,
        };
        for s in [Settings::default(), all] {
            assert_eq!(
                receipt(&s, RoomKind::PqChat),
                Err(MatrixError::MatrixRoomKind)
            );
            assert_eq!(
                typing(&s, RoomKind::PqChat),
                Err(MatrixError::MatrixRoomKind)
            );
        }
        assert_eq!(
            matrix_action(RoomKind::PqChat),
            Err(MatrixError::MatrixRoomKind)
        );
        assert_eq!(matrix_action(RoomKind::Matrix), Ok(()));
    }

    #[test]
    fn kinds_never_mix() {
        let mut m = Marks::default();
        m.mark("!p:x").unwrap();
        m.hold("!h:x", true, false).unwrap();
        for r in ["!p:x", "!h:x"] {
            assert_eq!(m.kind(r), RoomKind::PqChat);
            assert!(!m.shows(RoomFilter::Matrix, r), "{r}");
            assert!(m.shows(RoomFilter::PqChat, r), "{r}");
        }
        // the control: an unmarked room is Matrix
        assert_eq!(m.kind("!m:x"), RoomKind::Matrix);
        assert!(m.shows(RoomFilter::Matrix, "!m:x"));
        assert!(!m.shows(RoomFilter::PqChat, "!m:x"));
        // a released invite stays PqChat
        m.hold("!h:x", false, false).unwrap();
        assert_eq!(m.kind("!h:x"), RoomKind::PqChat);
    }

    #[test]
    fn a_held_invite_cannot_take_a_joined_matrix_room() {
        let mut m = Marks::default();
        assert_eq!(
            m.hold("!dm:x", true, true),
            Err(MatrixError::MatrixRoomKind)
        );
        assert_eq!(m.kind("!dm:x"), RoomKind::Matrix);
        // the controls: not joined, it is held; joined and marked already (a bound room), it stays
        m.hold("!inv:x", true, false).unwrap();
        assert_eq!(m.kind("!inv:x"), RoomKind::PqChat);
        assert_eq!(m.hold("!inv:x", true, true), Ok(()));
        // only a room id is marked
        for bad in [
            "",
            "not a room",
            "@user:x",
            &format!("!{}:x", "a".repeat(260)),
        ] {
            assert_eq!(m.mark(bad), Err(MatrixError::MatrixArgument), "{bad}");
            assert_eq!(m.kind(bad), RoomKind::Matrix);
        }
    }

    #[test]
    fn marks_are_bounded() {
        let mut m = Marks::default();
        for i in 0..MARKS_MAX {
            m.mark(&format!("!{i}:x")).unwrap();
        }
        assert_eq!(m.mark("!one-more:x"), Err(MatrixError::MatrixArgument));
        // the bound record holds the longest room ids
        let mut l = Marks::default();
        for i in 0..MARKS_MAX {
            let id = format!("!{i}:{}", "h".repeat(250 - i.to_string().len()));
            l.mark(&id).unwrap();
        }
        assert!(serde_json::to_vec(&l).unwrap().len() <= MARKS_RECORD_MAX);
        // marking a room already marked is not a new one
        assert_eq!(m.mark("!0:x"), Ok(()));
        let full = serde_json::to_vec(&m).unwrap();
        assert!(full.len() <= MARKS_RECORD_MAX, "{}", full.len());
    }

    #[test]
    fn homeserver_https_or_loopback_ip() {
        for ok in [
            "https://matrix.example",
            "http://127.0.0.1:8008",
            "http://127.9.9.9",
            "http://[::1]:8008",
        ] {
            assert!(homeserver(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://localhost:8008",
            "http://10.0.0.1",
            "http://matrix.example",
            "ftp://127.0.0.1",
            "nonsense",
        ] {
            assert_eq!(homeserver(bad), Err(MatrixError::EndpointScheme), "{bad}");
        }
    }

    #[test]
    fn own_records_bounded_before_decoding() {
        let s = serde_json::to_vec(&Settings::default()).unwrap();
        assert_eq!(
            decode::<Settings>(&s, SETTINGS_MAX),
            Ok(Settings::default())
        );
        let mut big = s.clone();
        big.resize(SETTINGS_MAX + 1, b' ');
        assert_eq!(
            decode::<Settings>(&big, SETTINGS_MAX),
            Err(MatrixError::MatrixStore)
        );
        assert_eq!(text(&"a".repeat(TEXT_MAX)), Ok(()));
        assert_eq!(
            text(&"a".repeat(TEXT_MAX + 1)),
            Err(MatrixError::MatrixArgument)
        );
        assert_eq!(
            pusher_url("https://push.example/_matrix/push/v1/notify"),
            Ok(())
        );
        for bad in ["http://push.example/x", "push.example", "ftp://x"] {
            assert_eq!(pusher_url(bad), Err(MatrixError::MatrixArgument), "{bad}");
        }
    }
}
