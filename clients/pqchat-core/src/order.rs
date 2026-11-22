// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Conversation order (UA-7 P19, P49): a message names the heads its sender has seen as `parents`, at most 8, strictly
//! sorted; a reader orders by `parents`, then the content's `ts`, then `messageId`. An `edit` or `redact` counts only from its
//! target's sender UA; a reference to a message not seen yet waits for it (the timeline is computed over every message held).
use crate::content::Content;
use crate::PqChatError;
use std::collections::{BTreeMap, BTreeSet, HashMap};

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

/// A message that passed every check (or an own one sent), as the timeline holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    pub id: String,
    pub epoch: String,
    pub sender: String,
    pub device: String,
    pub counter: u64,
    pub parents: Vec<String>,
    pub ts: Option<u64>,
    pub content: Content,
    /// the `msig` seat the sender writes for, only when the sender is its leaf in the epoch (`via`)
    pub on_behalf_of: Option<String>,
}

/// The display order of `msgs`: a message after its parents that are held, then by `ts` (an absent `ts` sorts as 0, a
/// controller call), then by `messageId`.
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

/// A message as the user sees it: a `text` (its newest own edit applied) or an unsupported one, with its reactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: String,
    pub sender: String,
    pub ts: Option<u64>,
    pub content: Content,
    pub on_behalf_of: Option<String>,
    pub edited: bool,
    /// reaction → how many UAs
    pub reactions: BTreeMap<String, usize>,
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
            a.content
                .target()
                .and_then(|t| by_id.get(t))
                .filter(|t| t.sender == a.sender)
                .copied()
        };
        let redacted: BTreeSet<&str> = order
            .iter()
            .filter(|a| matches!(a.content, Content::Redact { .. }))
            .filter_map(|a| own(a))
            .map(|t| t.id.as_str())
            .collect();
        let mut edits: HashMap<&str, Content> = HashMap::new();
        let mut reacts: HashMap<&str, BTreeSet<(&str, &str)>> = HashMap::new();
        for a in &order {
            if redacted.contains(a.id.as_str()) {
                continue;
            }
            match &a.content {
                Content::Edit {
                    media_type, body, ..
                } => {
                    if let Some(t) = own(a).filter(|t| matches!(t.content, Content::Text { .. })) {
                        let body = body.clone();
                        let media_type = media_type.clone();
                        edits.insert(t.id.as_str(), Content::Text { media_type, body });
                    }
                }
                Content::React { target, reaction } => {
                    reacts
                        .entry(target.as_str())
                        .or_default()
                        .insert((a.sender.as_str(), reaction.as_str()));
                }
                _ => {}
            }
        }
        order
            .iter()
            .filter(|m| matches!(m.content, Content::Text { .. } | Content::Unsupported))
            .filter(|m| !redacted.contains(m.id.as_str()))
            .map(|m| {
                let mut reactions = BTreeMap::new();
                for (_, r) in reacts.get(m.id.as_str()).into_iter().flatten() {
                    *reactions.entry(r.to_string()).or_insert(0) += 1;
                }
                let edit = edits.get(m.id.as_str());
                Message {
                    id: m.id.clone(),
                    sender: m.sender.clone(),
                    ts: m.ts,
                    content: edit.cloned().unwrap_or_else(|| m.content.clone()),
                    on_behalf_of: m.on_behalf_of.clone(),
                    edited: edit.is_some(),
                    reactions,
                }
            })
            .collect()
    }
}
