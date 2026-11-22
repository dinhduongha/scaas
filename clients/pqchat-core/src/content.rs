// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Message contents (UA-7 §6.4.1, P49; CLI-PQC-02's types in scope: `text`, `edit`, `redact`, `react`, `receipt`, `typing`).
//! The crate builds and reads JSON values only: the SDK canonicalises, pads and seals a content (S5) and checks a received
//! one canonical (K4); here only P49's fields and bounds. A field the reader does not know is ignored; a type it does not know
//! or does not act on in this round (`file`, the call types), or a content that breaks a bound or a field's type, is shown as
//! unsupported and never acted on.
use crate::PqChatError;
use serde_json::{json, Map, Value};

/// A `text` or `edit` body's bound in bytes (a longer text goes as a `file`).
pub const BODY_MAX: usize = 16_000;
/// `ts` and every integer: at most 2^53 − 1.
pub const INT_MAX: u64 = (1 << 53) - 1;

/// A content of a type in scope, or [`Content::Unsupported`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// `media_type` `text/plain` (absent) or `text/markdown`
    Text {
        media_type: Option<String>,
        body: String,
    },
    /// a new body of the `text` `target` (its sender's only)
    Edit {
        target: String,
        media_type: Option<String>,
        body: String,
    },
    /// hides `target` (its sender's only); the bytes stay in every store
    Redact {
        target: String,
        reason: Option<String>,
    },
    React {
        target: String,
        reaction: String,
    },
    /// read up to `target`
    Receipt {
        target: String,
    },
    Typing {
        on: bool,
    },
    /// an unknown type, a type out of this round's scope, or a content out of P49's bounds: shown so, never acted on
    Unsupported,
}

/// A received content: its value, and the common fields `ts` and `onBehalfOf` (display only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub content: Content,
    pub ts: Option<u64>,
    pub on_behalf_of: Option<String>,
}

type Obj = Map<String, Value>;

/// A string member of `o` of `lo..=hi` bytes; `Ok(None)` when absent, `Err` for another type or length.
fn text(o: &Obj, k: &str, lo: usize, hi: usize) -> Result<Option<String>, ()> {
    match o.get(k) {
        None => Ok(None),
        Some(Value::String(s)) if (lo..=hi).contains(&s.len()) => Ok(Some(s.clone())),
        Some(_) => Err(()),
    }
}

fn need(o: &Obj, k: &str, lo: usize, hi: usize) -> Result<String, ()> {
    text(o, k, lo, hi)?.ok_or(())
}

/// A 32-byte id: lower-case `0x` hex.
fn id_ok(s: &str) -> bool {
    s.len() == 66
        && s.starts_with("0x")
        && s.bytes()
            .skip(2)
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn id(o: &Obj, k: &str) -> Result<String, ()> {
    let s = need(o, k, 66, 66)?;
    id_ok(&s).then_some(s).ok_or(())
}

/// `text/plain` (absent) or `text/markdown`.
fn media(o: &Obj) -> Result<Option<String>, ()> {
    match text(o, "mediaType", 1, 64)? {
        None => Ok(None),
        Some(m) if m == "text/plain" || m == "text/markdown" => Ok(Some(m)),
        Some(_) => Err(()),
    }
}

impl Content {
    /// The content of a received value (the SDK's canonical JSON): P49's form and bounds, else `Unsupported`.
    pub fn parse(bytes: &[u8]) -> Parsed {
        let unsupported = Parsed {
            content: Content::Unsupported,
            ts: None,
            on_behalf_of: None,
        };
        match serde_json::from_slice::<Value>(bytes) {
            Ok(Value::Object(o)) => Self::of(&o).unwrap_or(unsupported),
            _ => unsupported,
        }
    }

    fn of(o: &Obj) -> Result<Parsed, ()> {
        let ty = need(o, "type", 1, 32)?;
        if !ty.bytes().all(|b| b.is_ascii_alphabetic()) {
            return Err(());
        }
        let ts = match o.get("ts") {
            None => None,
            Some(v) => Some(v.as_u64().filter(|t| *t <= INT_MAX).ok_or(())?),
        };
        let on_behalf_of = match o.get("onBehalfOf") {
            None => None,
            Some(_) => Some(id(o, "onBehalfOf")?),
        };
        let content = match ty.as_str() {
            "text" => Content::Text {
                media_type: media(o)?,
                body: need(o, "body", 1, BODY_MAX)?,
            },
            "edit" => Content::Edit {
                target: id(o, "target")?,
                media_type: media(o)?,
                body: need(o, "body", 1, BODY_MAX)?,
            },
            "redact" => Content::Redact {
                target: id(o, "target")?,
                reason: text(o, "reason", 0, 512)?,
            },
            "react" => Content::React {
                target: id(o, "target")?,
                reaction: need(o, "reaction", 1, 64)?,
            },
            "receipt" => Content::Receipt {
                target: id(o, "target")?,
            },
            "typing" => Content::Typing {
                on: o.get("on").and_then(Value::as_bool).ok_or(())?,
            },
            _ => Content::Unsupported,
        };
        Ok(Parsed {
            content,
            ts,
            on_behalf_of,
        })
    }

    /// The content's `type`.
    pub fn kind(&self) -> &'static str {
        match self {
            Content::Text { .. } => "text",
            Content::Edit { .. } => "edit",
            Content::Redact { .. } => "redact",
            Content::React { .. } => "react",
            Content::Receipt { .. } => "receipt",
            Content::Typing { .. } => "typing",
            Content::Unsupported => "unsupported",
        }
    }

    /// The value to send, with the sender's clock `ts` (milliseconds, display only): a body above [`BODY_MAX`]
    /// `ContentTooLarge`; anything else out of P49's bounds, or `Unsupported`, `ContentInvalid`. The SDK canonicalises it.
    pub fn value(&self, ts: Option<u64>) -> Result<Value, PqChatError> {
        let mut v = match self {
            Content::Text { media_type, body } => {
                json!({"type": "text", "mediaType": media_type, "body": body})
            }
            Content::Edit {
                target,
                media_type,
                body,
            } => json!({"type": "edit", "target": target, "mediaType": media_type, "body": body}),
            Content::Redact { target, reason } => {
                json!({"type": "redact", "target": target, "reason": reason})
            }
            Content::React { target, reaction } => {
                json!({"type": "react", "target": target, "reaction": reaction})
            }
            Content::Receipt { target } => json!({"type": "receipt", "target": target}),
            Content::Typing { on } => json!({"type": "typing", "on": on}),
            Content::Unsupported => return Err(PqChatError::ContentInvalid),
        };
        if let Content::Text { body, .. } | Content::Edit { body, .. } = self {
            if body.len() > BODY_MAX {
                return Err(PqChatError::ContentTooLarge);
            }
        }
        let o = v.as_object_mut().ok_or(PqChatError::Internal)?;
        o.retain(|_, x| !x.is_null());
        if let Some(t) = ts {
            o.insert("ts".into(), t.into());
        }
        // what is sent reads back as itself
        match Self::of(o) {
            Ok(p) if p.content == *self && p.ts == ts => Ok(v),
            _ => Err(PqChatError::ContentInvalid),
        }
    }

    /// Whether the content acts on its `target` (`edit`, `redact`, `react`, `receipt`).
    pub fn target(&self) -> Option<&str> {
        match self {
            Content::Edit { target, .. }
            | Content::Redact { target, .. }
            | Content::React { target, .. }
            | Content::Receipt { target } => Some(target),
            _ => None,
        }
    }
}
