// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The Matrix event of an envelope (UA-7 P15, CLI-PQC-05): type `net.scaas.pqchat.v1`, content `{"v": 1, "hint": <base64>,
//! "env": <base64>}`, base64 of RFC 4648 §4 with padding, the `matrixEvent` row's form, and only that form read back. The
//! codec is a transport encoding; the envelope's bytes are opened and decoded in `ua-rs` (K4).
use crate::drops::Drop;
use crate::PqChatError;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};

/// The app's Matrix client as the crate uses it (spec §6.1; plan T8 adds rooms, invites, history and the conformance test).
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait MatrixTransport: Send + Sync {
    /// Sends one [`EVENT_TYPE`] event with `content` (an [`event`]) in `room`.
    async fn send_event(&self, room: &str, content: Value) -> Result<(), PqChatError>;
}

/// The event type.
pub const EVENT_TYPE: &str = "net.scaas.pqchat.v1";
/// An event's content above this is dropped (`decode`): a homeserver's event bound.
pub const EVENT_MAX: usize = 65_536;

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
