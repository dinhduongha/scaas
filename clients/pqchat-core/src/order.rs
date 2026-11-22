// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Conversation order (UA-7 P19, P49): a message names the heads its sender has seen as `parents`, at most 8, strictly
//! sorted; a reader orders by `parents`, then the content's `ts`, then `messageId`. An `edit` or `redact` counts only from its
//! target's sender UA; a reference to a message not seen yet waits for it (the timeline is computed over every message held).
use crate::content::Content;
use crate::PqChatError;
use scaas_sdk::SecretBytes;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

/// At most this many parents (UA-7 §4.2).
pub const PARENTS_MAX: usize = 8;
/// Messages held per session in memory (the oldest dropped; plaintext is never written to the store, spec §7).
pub const TIMELINE_MAX: usize = 4096;

/// `heads` as a message's `parents`: lower case, sorted, de-duplicated; above [`PARENTS_MAX`] the newest (the last given) kept.
pub fn parents(heads: &[String]) -> Result<Vec<String>, PqChatError> {
    let mut v: Vec<String> = heads.iter().map(|h| h.to_ascii_lowercase()).collect();
    if v.iter().any(|h| h.len() != 66 || !h.starts_with("0x")) {
        return Err(PqChatError::ContentInvalid);
    }
    if v.len() > PARENTS_MAX {
        v.drain(..v.len() - PARENTS_MAX);
    }
    v.sort();
    v.dedup();
    Ok(v)
}

/// A message that passed every check (or an own one sent), as the timeline holds it: what the crate acts on (its type,
/// target, `ts`), and the content itself only as the SDK's handle (Rust-only, plan T12).
#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
#[derive(Clone)]
pub struct Shown {
    pub id: String,
    pub epoch: String,
    pub sender: String,
    pub device: String,
    pub counter: u64,
    pub parents: Vec<String>,
    pub ts: Option<u64>,
    /// the `msig` seat the sender writes for, only when the sender is its leaf in the epoch (`via`)
    pub on_behalf_of: Option<String>,
    /// [`Content::kind`]
    pub kind: &'static str,
    /// [`Content::target`]
    pub target: Option<String>,
    /// the canonical JSON content
    pub content: Arc<SecretBytes>,
}

/// The display order of `msgs`: a message after its parents that are held, then by `ts` (an absent `ts` sorts as 0, a
/// controller call), then by `messageId`.
#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
pub fn display_order(msgs: &[Shown]) -> Vec<&Shown> {
    let at: HashMap<&str, usize> = msgs
        .iter()
        .enumerate()
        .map(|(i, m)| (m.id.as_str(), i))
        .collect();
    let mut waits = vec![0usize; msgs.len()];
    let mut children: Vec<Vec<usize>> = vec![vec![]; msgs.len()];
    for (i, m) in msgs.iter().enumerate() {
        for p in &m.parents {
            if let Some(&j) = at.get(p.as_str()) {
                if let (Some(w), Some(c)) = (waits.get_mut(i), children.get_mut(j)) {
                    *w += 1;
                    c.push(i);
                }
            }
        }
    }
    let key = |i: usize| msgs.get(i).map(|m| (m.ts.unwrap_or(0), m.id.as_str(), i));
    let mut ready: BTreeSet<(u64, &str, usize)> = (0..msgs.len())
        .filter(|i| waits.get(*i) == Some(&0))
        .filter_map(key)
        .collect();
    let mut out = Vec::with_capacity(msgs.len());
    while let Some((_, _, i)) = ready.pop_first() {
        out.extend(msgs.get(i));
        for &c in children.get(i).into_iter().flatten() {
            if let Some(w) = waits.get_mut(c) {
                *w -= 1;
                if *w == 0 {
                    ready.extend(key(c));
                }
            }
        }
    }
    out
}

/// A message as the user sees it: a `text` (its newest own edit applied) or an unsupported one, with its reactions. Its
/// content only as the SDK's `SecretBytes` handle, read through the SDK's copy calls (owner 2026-11-22, spec §11).
#[derive(Clone)]
pub struct Message {
    pub id: String,
    pub sender: String,
    pub ts: Option<u64>,
    pub on_behalf_of: Option<String>,
    /// a `text`; else shown as unsupported, never acted on
    pub supported: bool,
    pub edited: bool,
    /// the canonical JSON content: the `text`'s, or its newest own `edit`'s when `edited`
    pub content: Arc<SecretBytes>,
    /// one per reaction value, in the values' order
    pub reactions: Vec<Reaction>,
}

/// A reaction value on a message and how many UAs gave it.
#[derive(Clone)]
pub struct Reaction {
    /// the canonical JSON content of one `react` giving it
    pub content: Arc<SecretBytes>,
    pub count: u64,
}

/// A message's reactions: value → (the UAs giving it, one `react`'s content).
type Givers<'a> = BTreeMap<String, (BTreeSet<&'a str>, &'a Arc<SecretBytes>)>;

/// `react`'s value, read where the crate acts on it (one reaction per UA and value).
fn reaction(m: &Shown) -> Option<String> {
    match m.content.with(Content::parse).content {
        Content::React { reaction, .. } => Some(reaction),
        _ => None,
    }
}

/// A session's messages held on this device, and its heads (the messages no held message names as a parent).
#[derive(Default)]
pub(crate) struct Timeline {
    msgs: Vec<Shown>,
    heads: Vec<String>,
}

impl Timeline {
    pub(crate) fn add(&mut self, m: Shown) {
        self.heads.retain(|h| !m.parents.contains(h));
        self.heads.push(m.id.clone());
        if self.heads.len() > PARENTS_MAX {
            self.heads.remove(0);
        }
        self.msgs.push(m);
        if self.msgs.len() > TIMELINE_MAX {
            self.msgs.remove(0);
        }
    }

    pub(crate) fn heads(&self) -> &[String] {
        &self.heads
    }

    /// The messages in display order with the actions applied: an `edit` of a `text` and a `redact` of any message count
    /// only from the target's sender UA (P49), the newest edit in display order shown; one reaction per (UA, target,
    /// reaction), none from a redacted `react`; `receipt` and `typing` are no messages.
    pub(crate) fn view(&self) -> Vec<Message> {
        let order = display_order(&self.msgs);
        let by_id: HashMap<&str, &Shown> = order.iter().map(|m| (m.id.as_str(), *m)).collect();
        let own = |a: &Shown| {
            a.target
                .as_deref()
                .and_then(|t| by_id.get(t))
                .filter(|t| t.sender == a.sender)
                .copied()
        };
        let redacted: BTreeSet<&str> = order
            .iter()
            .filter(|a| a.kind == "redact")
            .filter_map(|a| own(a))
            .map(|t| t.id.as_str())
            .collect();
        let mut edits: HashMap<&str, &Arc<SecretBytes>> = HashMap::new();
        let mut reacts: HashMap<&str, Givers> = HashMap::new();
        for a in &order {
            if redacted.contains(a.id.as_str()) {
                continue;
            }
            match (a.kind, a.target.as_deref()) {
                ("edit", _) => {
                    if let Some(t) = own(a).filter(|t| t.kind == "text") {
                        edits.insert(t.id.as_str(), &a.content);
                    }
                }
                ("react", Some(target)) => {
                    if let Some(r) = reaction(a) {
                        let v = reacts.entry(target).or_default();
                        let e = v.entry(r).or_insert_with(|| (BTreeSet::new(), &a.content));
                        e.0.insert(a.sender.as_str());
                    }
                }
                _ => {}
            }
        }
        order
            .iter()
            .filter(|m| matches!(m.kind, "text" | "unsupported"))
            .filter(|m| !redacted.contains(m.id.as_str()))
            .map(|m| {
                let reactions = reacts
                    .get(m.id.as_str())
                    .into_iter()
                    .flatten()
                    .map(|(_, (uas, c))| Reaction {
                        content: Arc::clone(c),
                        count: uas.len() as u64,
                    })
                    .collect();
                let edit = edits.get(m.id.as_str());
                Message {
                    id: m.id.clone(),
                    sender: m.sender.clone(),
                    ts: m.ts,
                    on_behalf_of: m.on_behalf_of.clone(),
                    supported: m.kind == "text",
                    edited: edit.is_some(),
                    content: Arc::clone(edit.copied().unwrap_or(&m.content)),
                    reactions,
                }
            })
            .collect()
    }
}
