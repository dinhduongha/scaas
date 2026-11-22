// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! A received message (CLI-PQC-07, CLI-PQC-14): the checks in their order, each reached only after the ones before it pass:
//! the envelope opens (`envelope`), its record decodes within bounds (`decode`), its portable signature verifies against the
//! sender's registry record (`signature`), the sender is a member of the epoch as its home orders it (`member`), its
//! `messageId` is new (`duplicate`), its counter is fresh in its scope (`counter`); only then is its chain walked, at most
//! 2^20 steps from the nearest held position (`too-far`), and its content opened, unpadded and checked canonical in `ua-rs`
//! (`content`). A failure is a drop reason: no error, no write, no network call that depends on it.
use crate::check::Drop;
use crate::model::at;
use crate::model::{bytes, h, list, num, Epoch};
use crate::{Items, PqChat};
use scaas_sdk::app_core::AppKey;
use scaas_sdk::pqchat_records::PqChatMessage;
use scaas_sdk::SecretBytes;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

/// CLI-PQC-14's walk bound.
pub const WALK_MAX: u64 = 1 << 20;
/// Chain positions held per session; the least recently used is dropped.
pub const POSITIONS_MAX: usize = 64;
/// Counters remembered per received scope `(epoch, sender, device)`.
pub const SEEN_MAX: usize = 1024;
/// Message ids remembered per session for the dedupe.
pub const IDS_MAX: usize = 4096;

/// An epoch the user can read: its record at home and its key handle (unwrapped or drawn), on the home chain's profile.
pub struct OpenEpoch {
    pub chain: String,
    pub epoch: Epoch,
    pub k: Arc<AppKey>,
}

/// A message that passed every check.
pub struct Received {
    pub message_id: String,
    pub record: PqChatMessage,
    /// the canonical JSON content
    pub content: SecretBytes,
}

/// The held chain positions and seen ids, in memory only (handles die at the lock; derived again).
#[derive(Default)]
pub struct Chains {
    /// (session, epoch, sender, device) → (counter, position), in use order
    pos: HashMap<String, VecDeque<(String, u64, Arc<AppKey>)>>,
    ids: HashMap<String, VecDeque<String>>,
}

impl Chains {
    /// The nearest held position at or below `counter` of the scope, and its counter.
    fn nearest(&mut self, session: &str, scope: &str, counter: u64) -> Option<(u64, Arc<AppKey>)> {
        let q = self.pos.get_mut(session)?;
        let i = q.iter().position(|(s, c, _)| s == scope && *c <= counter)?;
        let e = q.remove(i)?;
        let out = (e.1, e.2.clone());
        q.push_back(e);
        Some(out)
    }
    fn hold(&mut self, session: &str, scope: &str, counter: u64, p: Arc<AppKey>) {
        let q = self.pos.entry(session.to_string()).or_default();
        q.retain(|(s, _, _)| s != scope);
        q.push_back((scope.to_string(), counter, p));
        while q.len() > POSITIONS_MAX {
            q.pop_front();
        }
    }
    /// How many positions `session` holds.
    pub fn held(&self, session: &str) -> usize {
        self.pos.get(session).map_or(0, VecDeque::len)
    }
    fn seen_id(&self, session: &str, id: &str) -> bool {
        self.ids
            .get(session)
            .is_some_and(|q| q.iter().any(|x| x == id))
    }
    fn add_id(&mut self, session: &str, id: String) {
        let q = self.ids.entry(session.to_string()).or_default();
        q.push_back(id);
        while q.len() > IDS_MAX {
            q.pop_front();
        }
    }
    /// Every handle released (the seed's lock).
    pub fn clear(&mut self) {
        self.pos.clear();
    }
}

/// The record as V1 reads it, its fields by name (no byte format: the SDK builds the typed data).
pub fn record_json(r: &PqChatMessage) -> String {
    serde_json::json!({"sessionId": r.session_id, "epochId": r.epoch_id, "sender": r.sender, "device": r.device,
        "counter": r.counter, "parents": r.parents, "ciphertext": crate::model::hex(&r.ciphertext)})
    .to_string()
}

fn seen_key(epoch: &str, sender: &str, device: &str) -> String {
    format!("seen/{epoch}/{sender}/{device}")
}

impl PqChat {
    /// An envelope of `ep` read from a store: the checked message, or the reason it was dropped (counted).
    pub async fn receive(&self, ep: &OpenEpoch, env: Vec<u8>) -> Result<Received, Drop> {
        let r = self.receive_inner(ep, env).await;
        if let Err(d) = &r {
            self.drops.add(&ep.epoch.session_id, *d);
        }
        r
    }

    async fn receive_inner(&self, ep: &OpenEpoch, env: Vec<u8>) -> Result<Received, Drop> {
        let (sid, eid) = (&ep.epoch.session_id, &ep.epoch.id);
        let inner = self
            .app
            .pqchat_open_envelope(ep.k.clone(), sid.clone(), eid.clone(), env)
            .map_err(|e| {
                if e.code() == "Aead" {
                    Drop::Envelope
                } else {
                    Drop::Decode
                }
            })?;
        let r = inner.record;
        if r.session_id.to_ascii_lowercase() != *sid || r.epoch_id.to_ascii_lowercase() != *eid {
            return Err(Drop::Envelope);
        }
        let ok = self
            .app
            .verify_pqchat_record(
                ep.chain.clone(),
                r.sender.clone(),
                "PqChatMessage".into(),
                record_json(&r),
                inner.sig,
            )
            .await
            .unwrap_or(false);
        if !ok {
            return Err(Drop::Signature);
        }
        self.accept_record(ep, r).await
    }

    /// A message posted at `instance` (`messageAt(sessionId, index)`, a trusted read): its signature bytes are not in state
    /// (CTR-CHAT-05), so it counts on the contract's check, only from a listed instance, with the sender's membership checked
    /// again at the home (`ep`, read there), then the checks after the signature (K12).
    pub async fn posted(
        &self,
        instance: &str,
        index: u64,
        ep: &OpenEpoch,
    ) -> Result<Received, Drop> {
        let sid = ep.epoch.session_id.clone();
        let r = self.posted_inner(instance, index, ep).await;
        if let Err(d) = &r {
            self.drops.add(&sid, *d);
        }
        r
    }

    async fn posted_inner(
        &self,
        instance: &str,
        index: u64,
        ep: &OpenEpoch,
    ) -> Result<Received, Drop> {
        if !self
            .listed(&ep.chain, instance)
            .await
            .map_err(|_| Drop::Unlisted)?
        {
            return Err(Drop::Unlisted);
        }
        let a = serde_json::json!({ "sessionId": ep.epoch.session_id, "index": index.to_string() });
        let v = self
            .net
            .read(&ep.chain, instance, "IPqChat.messageAt", a)
            .await
            .map_err(|_| Drop::Decode)?;
        let m = &at(&v, "m");
        let d = |_| Drop::Decode;
        let r = PqChatMessage {
            session_id: h(at(m, "sessionId")).map_err(d)?,
            epoch_id: h(at(m, "epochId")).map_err(d)?,
            sender: h(at(m, "sender")).map_err(d)?,
            device: h(at(m, "device")).map_err(d)?,
            counter: num(at(m, "counter")).map_err(d)?,
            parents: list(at(m, "parents")).map_err(d)?,
            ciphertext: bytes(at(m, "ciphertext")).map_err(d)?,
        };
        if r.session_id != ep.epoch.session_id || r.epoch_id != ep.epoch.id {
            return Err(Drop::Control);
        }
        self.accept_record(ep, r).await
    }

    /// The checks after the signature (or, for a `messageAt` record, after the contract's): member at home, dedupe,
    /// counter, walk, content.
    pub(crate) async fn accept_record(
        &self,
        ep: &OpenEpoch,
        r: PqChatMessage,
    ) -> Result<Received, Drop> {
        let sid = &ep.epoch.session_id;
        let sender = r.sender.to_ascii_lowercase();
        let device = r.device.to_ascii_lowercase();
        if !ep.epoch.has_member(&sender) {
            return Err(Drop::Member);
        }
        let id = self
            .app
            .pqchat_message_id(r.clone())
            .map_err(|_| Drop::Decode)?;
        if self.chains().seen_id(sid, &id) {
            return Err(Drop::Duplicate);
        }
        let key = seen_key(&ep.epoch.id, &sender, &device);
        let seen: Vec<u64> = Items(&*self.store)
            .get(&key)
            .map_err(|_| Drop::Counter)?
            .unwrap_or_default();
        if seen.contains(&r.counter)
            || (seen.len() >= SEEN_MAX && seen.first().is_some_and(|m| r.counter <= *m))
        {
            return Err(Drop::Counter);
        }
        let pos = self.position(ep, &sender, &device, r.counter)?;
        let content = self
            .app
            .pqchat_open_message(pos, r.clone())
            .map_err(|_| Drop::Content)?;
        // counted only once it opened: a record that fails later spends nothing of the scope
        let c = r.counter;
        Items(&*self.store)
            .update::<Vec<u64>, _>(&key, |v| {
                let mut v = v.unwrap_or_default();
                if let Err(i) = v.binary_search(&c) {
                    v.insert(i, c);
                }
                while v.len() > SEEN_MAX {
                    v.remove(0);
                }
                Ok(v)
            })
            .map_err(|_| Drop::Counter)?;
        self.chains().add_id(sid, id.clone());
        Ok(Received {
            message_id: id,
            record: r,
            content,
        })
    }

    /// The position of `(sender, device)`'s chain at `counter`: from the nearest held one at or below it, else from `ck_0`,
    /// in one `advance` of at most [`WALK_MAX`] steps (`too-far` beyond).
    fn position(
        &self,
        ep: &OpenEpoch,
        sender: &str,
        device: &str,
        counter: u64,
    ) -> Result<Arc<AppKey>, Drop> {
        let sid = &ep.epoch.session_id;
        let scope = format!("{}/{sender}/{device}", ep.epoch.id);
        let near = self.chains().nearest(sid, &scope, counter);
        let (from, p) = match near {
            Some(x) => x,
            None => {
                let p = self
                    .app
                    .pqchat_chain(
                        ep.k.clone(),
                        sid.clone(),
                        ep.epoch.id.clone(),
                        sender.into(),
                        device.into(),
                    )
                    .map_err(|_| Drop::Content)?;
                (0, p)
            }
        };
        let n = counter - from;
        if n > WALK_MAX {
            return Err(Drop::TooFar);
        }
        let at = if n == 0 {
            p
        } else {
            self.app.pqchat_advance(p, n).map_err(|_| Drop::TooFar)?
        };
        self.chains().hold(sid, &scope, counter, at.clone());
        Ok(at)
    }

    fn chains(&self) -> std::sync::MutexGuard<'_, Chains> {
        self.chains
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
