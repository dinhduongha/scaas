// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `MatrixTransport` over the profile's one client (CLI-MTX-10): each call one client-server request through the same
//! `matrix_sdk::Client` (its login and token), independent of the sync loop's view; it fails once the client is closed.
//! The rooms it creates, joins, holds, or uses for a bound session are marked PqChat (CLI-MTX-06). It sends nothing
//! ephemeral and answers no invite by itself.
use crate::Inner;
use async_trait::async_trait;
use matrix_sdk::ruma::api::client::membership::{
    get_member_events, invite_user, join_room_by_id, joined_rooms, kick_user,
};
use matrix_sdk::ruma::api::client::message::{get_message_events, send_message_event};
use matrix_sdk::ruma::api::client::room::create_room::v3::RoomPreset;
use matrix_sdk::ruma::api::client::room::{create_room, Visibility};
use matrix_sdk::ruma::api::client::state::{get_state_event_for_key, send_state_event};
use matrix_sdk::ruma::events::room::member::MembershipState;
use matrix_sdk::ruma::events::{MessageLikeEventType, StateEventType};
use matrix_sdk::ruma::serde::Raw;
use matrix_sdk::ruma::{OwnedRoomId, OwnedUserId, TransactionId, UInt};
use pqchat_transport::{
    HistoryPage, MatrixTransport, RoomEvent, TransportError, EVENT_MAX, EVENT_TYPE,
};
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::Value;
use std::sync::Arc;

/// Events of one history page asked for.
const HISTORY_PAGE: u32 = 100;

pub(crate) struct Transport(pub(crate) Arc<Inner>);

const E: TransportError = TransportError;

fn room_id(room: &str) -> Result<OwnedRoomId, TransportError> {
    OwnedRoomId::try_from(room).map_err(|_| E)
}

fn user_id(user: &str) -> Result<OwnedUserId, TransportError> {
    OwnedUserId::try_from(user).map_err(|_| E)
}

/// A `net.scaas.pqchat.v1` event's sender and content bytes as the server sent them (`None`: another type, or its content
/// above [`EVENT_MAX`]).
pub(crate) fn pqchat_event(raw: &RawValue) -> Option<RoomEvent> {
    #[derive(Deserialize)]
    struct Min<'a> {
        #[serde(rename = "type")]
        ty: String,
        sender: String,
        #[serde(borrow)]
        content: &'a RawValue,
    }
    let m: Min<'_> = serde_json::from_str(raw.get()).ok()?;
    let c = m.content.get();
    if m.ty != EVENT_TYPE || c.len() > EVENT_MAX {
        return None;
    }
    Some(RoomEvent {
        sender: m.sender,
        content: c.as_bytes().to_vec(),
    })
}

/// One request through the profile's client; any failure, a closed client included, is the transport's error (no room id
/// or Matrix id in it).
macro_rules! send {
    ($s:expr, $r:expr) => {
        $s.0.client().map_err(|_| E)?.send($r).await.map_err(|_| E)
    };
}

impl Transport {
    async fn mark(&self, room: &str) -> Result<(), TransportError> {
        self.0.mark(room).await.map_err(|_| E)
    }
}

#[async_trait]
impl MatrixTransport for Transport {
    fn user_id(&self) -> String {
        self.0
            .client()
            .ok()
            .and_then(|c| c.user_id().map(|u| u.to_string()))
            .unwrap_or_default()
    }

    async fn create_room(&self) -> Result<String, TransportError> {
        let mut r = create_room::v3::Request::new();
        r.preset = Some(RoomPreset::PrivateChat);
        r.visibility = Visibility::Private;
        let id = send!(self, r)?.room_id;
        self.mark(id.as_str()).await?;
        // a homeserver that encrypts new rooms by itself gives a room a fresh device cannot read from the seed: refused
        // (CLI-PQC-05)
        let enc = self
            .0
            .client()
            .map_err(|_| E)?
            .send(get_state_event_for_key::v3::Request::new(
                id.clone(),
                StateEventType::RoomEncryption,
                String::new(),
            ))
            .await;
        if enc.is_ok() {
            return Err(E);
        }
        Ok(id.to_string())
    }

    async fn joined(&self, room: &str) -> Result<bool, TransportError> {
        let r = send!(self, joined_rooms::v3::Request::new())?;
        Ok(r.joined_rooms.iter().any(|x| x.as_str() == room))
    }

    async fn members(&self, room: &str) -> Result<Vec<String>, TransportError> {
        #[derive(Deserialize)]
        struct M {
            state_key: String,
            content: C,
        }
        #[derive(Deserialize)]
        struct C {
            membership: String,
        }
        let mut rq = get_member_events::v3::Request::new(room_id(room)?);
        rq.not_membership = Some(MembershipState::Leave);
        let r = send!(self, rq)?;
        Ok(r.chunk
            .iter()
            .filter_map(|e| serde_json::from_str::<M>(e.json().get()).ok())
            .filter(|m| matches!(m.content.membership.as_str(), "join" | "invite"))
            .map(|m| m.state_key)
            .collect())
    }

    async fn join(&self, room: &str) -> Result<(), TransportError> {
        self.mark(room).await?;
        send!(self, join_room_by_id::v3::Request::new(room_id(room)?))?;
        Ok(())
    }

    async fn invite(&self, room: &str, user: &str) -> Result<(), TransportError> {
        self.mark(room).await?;
        let to = invite_user::v3::InviteUserId::new(user_id(user)?);
        send!(
            self,
            invite_user::v3::Request::new(room_id(room)?, to.into())
        )?;
        Ok(())
    }

    async fn remove(&self, room: &str, user: &str) -> Result<(), TransportError> {
        self.mark(room).await?;
        send!(
            self,
            kick_user::v3::Request::new(room_id(room)?, user_id(user)?)
        )?;
        Ok(())
    }

    async fn set_admin(&self, room: &str, user: &str, admin: bool) -> Result<(), TransportError> {
        self.mark(room).await?;
        let id = room_id(room)?;
        let got = send!(
            self,
            get_state_event_for_key::v3::Request::new(
                id.clone(),
                StateEventType::RoomPowerLevels,
                String::new(),
            )
        )?;
        let mut pl: Value = serde_json::from_str(got.event_or_content.get()).map_err(|_| E)?;
        let obj = pl.as_object_mut().ok_or(E)?;
        let users = obj
            .entry("users")
            .or_insert_with(|| Value::Object(Default::default()))
            .as_object_mut()
            .ok_or(E)?;
        if admin {
            users.insert(user.to_string(), Value::from(50));
        } else {
            users.remove(user);
        }
        let body = Raw::from_json(serde_json::value::to_raw_value(&pl).map_err(|_| E)?);
        send!(
            self,
            send_state_event::v3::Request::new_raw(
                id,
                StateEventType::RoomPowerLevels,
                String::new(),
                body
            )
        )?;
        Ok(())
    }

    async fn send_event(&self, room: &str, content: Value) -> Result<(), TransportError> {
        self.mark(room).await?;
        let body = Raw::from_json(serde_json::value::to_raw_value(&content).map_err(|_| E)?);
        send!(
            self,
            send_message_event::v3::Request::new_raw(
                room_id(room)?,
                TransactionId::new(),
                MessageLikeEventType::from(EVENT_TYPE),
                body,
            )
        )?;
        Ok(())
    }

    async fn history(
        &self,
        room: &str,
        before: Option<String>,
    ) -> Result<HistoryPage, TransportError> {
        self.mark(room).await?;
        let mut r = get_message_events::v3::Request::backward(room_id(room)?);
        r.from = before.clone();
        r.limit = UInt::from(HISTORY_PAGE);
        r.filter.types = Some(vec![EVENT_TYPE.to_string()]);
        let res = send!(self, r)?;
        let mut events: Vec<RoomEvent> = res
            .chunk
            .iter()
            .filter_map(|e| pqchat_event(e.json()))
            .collect();
        events.reverse();
        // a filtered page may be empty with more before it: the paging goes on while the token moves
        let before = res.end.filter(|e| Some(e) != before.as_ref());
        Ok(HistoryPage { events, before })
    }

    async fn hold_invite(&self, room: &str, hold: bool) -> Result<(), TransportError> {
        // recorded only: the crate never answers an invite by itself; a joined Matrix room is refused
        self.0.hold(room, hold).await.map_err(|_| E)
    }

    async fn bound(&self, room: &str) -> Result<(), TransportError> {
        self.mark(room).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(v: Value) -> Box<RawValue> {
        serde_json::value::to_raw_value(&v).unwrap()
    }

    #[test]
    fn pqchat_events_only_and_bounded() {
        let ev = |ty: &str, c: Value| {
            raw(serde_json::json!({"type": ty, "sender": "@a:x", "content": c}))
        };
        let ok = pqchat_event(&ev(EVENT_TYPE, serde_json::json!({"v": 1}))).unwrap();
        assert_eq!(
            (ok.sender.as_str(), ok.content.as_slice()),
            ("@a:x", br#"{"v":1}"#.as_slice())
        );
        assert!(pqchat_event(&ev("m.room.message", serde_json::json!({"v": 1}))).is_none());
        // `{"p":"…"}` is 8 bytes of frame around the string
        let at = |n: usize| serde_json::json!({"p": "a".repeat(n - 8)});
        assert!(pqchat_event(&ev(EVENT_TYPE, at(EVENT_MAX))).is_some());
        assert!(pqchat_event(&ev(EVENT_TYPE, at(EVENT_MAX + 1))).is_none());
    }
}
