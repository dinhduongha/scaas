// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The drop reasons of CLI-PQC-07 and their per-session counts: a record that fails a check is no error; it is counted on
//! the device only, never written, never sent.
use std::collections::BTreeMap;
use std::sync::Mutex;

/// Why a record read was dropped (CLI-PQC-07's reasons; `control` for a control-plane record that breaks the epoch rule, the
/// author's rights or the list shapes, which only a forged answer can show since the contract refuses it).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum Drop {
    Envelope,
    Decode,
    Signature,
    Member,
    Counter,
    Duplicate,
    Replica,
    Unlisted,
    WrapHash,
    Content,
    TooFar,
    Control,
}

impl Drop {
    pub const ALL: [Drop; 12] = [
        Drop::Envelope,
        Drop::Decode,
        Drop::Signature,
        Drop::Member,
        Drop::Counter,
        Drop::Duplicate,
        Drop::Replica,
        Drop::Unlisted,
        Drop::WrapHash,
        Drop::Content,
        Drop::TooFar,
        Drop::Control,
    ];
    /// The reason's name as CLI-PQC-07 writes it.
    pub fn name(self) -> &'static str {
        match self {
            Drop::Envelope => "envelope",
            Drop::Decode => "decode",
            Drop::Signature => "signature",
            Drop::Member => "member",
            Drop::Counter => "counter",
            Drop::Duplicate => "duplicate",
            Drop::Replica => "replica",
            Drop::Unlisted => "unlisted",
            Drop::WrapHash => "wrap-hash",
            Drop::Content => "content",
            Drop::TooFar => "too-far",
            Drop::Control => "control",
        }
    }
}

/// Drops counted per session and reason, on the device only (never written, never sent).
#[derive(Default)]
pub struct DropCounts(Mutex<BTreeMap<(String, Drop), u64>>);

impl DropCounts {
    pub fn add(&self, session: &str, d: Drop) {
        tracing::debug!(reason = d.name(), "dropped");
        let mut m = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *m.entry((session.to_string(), d)).or_default() += 1;
    }
    /// The counts of `session` by reason.
    pub fn of(&self, session: &str) -> BTreeMap<Drop, u64> {
        let m = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        m.iter()
            .filter(|((s, _), _)| s == session)
            .map(|((_, d), n)| (*d, *n))
            .collect()
    }
}
