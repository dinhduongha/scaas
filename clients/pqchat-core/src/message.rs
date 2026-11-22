// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! A received message (CLI-PQC-07, CLI-PQC-14): the checks in their order, each reached only after the ones before it pass:
//! the envelope opens (`envelope`), its record decodes within bounds (`decode`), its portable signature verifies against the
//! sender's registry record (`signature`), the sender is a member of the epoch as its home orders it (`member`), its
//! `messageId` is new (`duplicate`), its counter is fresh in its scope (`counter`); only then is its chain walked, at most
//! 2^20 steps from the nearest held position (`too-far`), and its content opened, unpadded and checked canonical in `ua-rs`
//! (`content`). A failure is a drop reason: no error, no write, no network call that depends on it.
use crate::check::DropReason;
use crate::content::Content;
use crate::model::at;
use crate::model::{bytes, h, list, num, Epoch, ZERO32};
use crate::order::{self, Shown};
use crate::reads::SessionRef;
use crate::session::Me;
use crate::{Items, PqChat, PqChatError};
use scaas_sdk::app_core::AppKey;
use scaas_sdk::pqchat_keys::{PqMessageHeader, PqSealedMessage};
use scaas_sdk::pqchat_records::PqChatMessage;
use scaas_sdk::SecretBytes;
use serde_json::{json, Value};
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
/// Envelopes of an epoch not open yet kept per session (the oldest dropped; read again from the stores).
pub const PENDING_MAX: usize = 64;
/// The 1,024-B bucket: a `postMessage` above it only with the user's cost confirmation (UA-7 §6.5).
pub const POST_BUCKET: usize = 1024;
/// AES-256-GCM-SIV's tag: a ciphertext is its padded plaintext's bucket and this (UA-7 §6.4).
pub const TAG: usize = 16;
/// Epochs followed at home in one send before it gives up (`EpochNotFinal`).
pub const EPOCH_STEPS: usize = 64;

/// An epoch the user can read: its record at home and its key handle (unwrapped or drawn), on the home chain's profile.
#[derive(Clone)]
pub struct OpenEpoch {
    pub chain: String,
    pub epoch: Epoch,
    #[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
    pub k: Arc<AppKey>,
}

/// A message that passed every check.
pub struct Received {
    pub message_id: String,
    pub record: PqChatMessage,
    /// the canonical JSON content, only as the SDK's handle (owner 2026-11-22, spec §11)
    pub content: Arc<SecretBytes>,
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
    pub async fn receive(&self, ep: &OpenEpoch, env: Vec<u8>) -> Result<Received, DropReason> {
        let r = self.receive_inner(ep, env).await;
        if let Err(d) = &r {
            self.drops.add(&ep.epoch.session_id, *d);
        }
        r
    }

    async fn receive_inner(&self, ep: &OpenEpoch, env: Vec<u8>) -> Result<Received, DropReason> {
        let (sid, eid) = (&ep.epoch.session_id, &ep.epoch.id);
        let inner = self
            .app
            .pqchat_open_envelope(ep.k.clone(), sid.clone(), eid.clone(), env)
            .map_err(|e| {
                if e.code() == "Aead" {
                    DropReason::Envelope
                } else {
                    DropReason::Decode
                }
            })?;
        let r = inner.record;
        if r.session_id.to_ascii_lowercase() != *sid || r.epoch_id.to_ascii_lowercase() != *eid {
            return Err(DropReason::Envelope);
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
            return Err(DropReason::Signature);
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
    ) -> Result<Received, DropReason> {
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
    ) -> Result<Received, DropReason> {
        if !self
            .listed(&ep.chain, instance)
            .await
            .map_err(|_| DropReason::Unlisted)?
        {
            return Err(DropReason::Unlisted);
        }
        let a = serde_json::json!({ "sessionId": ep.epoch.session_id, "index": index.to_string() });
        let v = self
            .net
            .read(&ep.chain, instance, "IPqChat.messageAt", a)
            .await
            .map_err(|_| DropReason::Decode)?;
        let m = &at(&v, "m");
        let d = |_| DropReason::Decode;
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
            return Err(DropReason::Control);
        }
        self.accept_record(ep, r).await
    }

    /// The checks after the signature (or, for a `messageAt` record, after the contract's): member at home, dedupe,
    /// counter, walk, content.
    pub(crate) async fn accept_record(
        &self,
        ep: &OpenEpoch,
        r: PqChatMessage,
    ) -> Result<Received, DropReason> {
        let sid = &ep.epoch.session_id;
        let sender = r.sender.to_ascii_lowercase();
        let device = r.device.to_ascii_lowercase();
        if !ep.epoch.has_member(&sender) {
            return Err(DropReason::Member);
        }
        let id = self
            .app
            .pqchat_message_id(r.clone())
            .map_err(|_| DropReason::Decode)?;
        if self.chains().seen_id(sid, &id) {
            return Err(DropReason::Duplicate);
        }
        let key = seen_key(&ep.epoch.id, &sender, &device);
        let seen: Vec<u64> = Items(&*self.store)
            .get(&key)
            .map_err(|_| DropReason::Counter)?
            .unwrap_or_default();
        if seen.contains(&r.counter)
            || (seen.len() >= SEEN_MAX && seen.first().is_some_and(|m| r.counter <= *m))
        {
            return Err(DropReason::Counter);
        }
        let pos = self.position(ep, &sender, &device, r.counter)?;
        let content = Arc::new(
            self.app
                .pqchat_open_message(pos, r.clone())
                .map_err(|_| DropReason::Content)?,
        );
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
            .map_err(|_| DropReason::Counter)?;
        self.chains().add_id(sid, id.clone());
        let p = content.with(Content::parse);
        self.show(ep, &r, &id, p, content.clone());
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
    ) -> Result<Arc<AppKey>, DropReason> {
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
                    .map_err(|_| DropReason::Content)?;
                (0, p)
            }
        };
        let n = counter - from;
        if n > WALK_MAX {
            return Err(DropReason::TooFar);
        }
        let at = if n == 0 {
            p
        } else {
            self.app
                .pqchat_advance(p, n)
                .map_err(|_| DropReason::TooFar)?
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

/// A message sealed and signed for every store of its epoch (S5): the bytes each store takes are the same.
pub struct Outgoing {
    pub epoch: Arc<OpenEpoch>,
    pub sealed: PqSealedMessage,
}

impl Outgoing {
    /// The padded plaintext's bucket: the ciphertext less its tag.
    pub fn bucket(&self) -> usize {
        self.sealed.record.ciphertext.len().saturating_sub(TAG)
    }

    /// `postMessage`'s arguments by name: the envelope's own record and signature (their ABI encoding is the SDK's `inner`,
    /// the envelope's inner bytes), so the message has one `messageId` on every store. Rust-only (a JSON value).
    #[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
    pub fn post_args(&self) -> Value {
        let r = &self.sealed.record;
        json!({"m": {"sessionId": r.session_id, "epochId": r.epoch_id, "sender": r.sender, "device": r.device,
            "counter": r.counter.to_string(), "parents": r.parents, "ciphertext": crate::model::hex(&r.ciphertext)},
            "sig": crate::session::sig_json(&self.sealed.sig)})
    }
}

/// What became of an envelope handed in from a store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    Shown(String),
    /// kept until its epoch is open (bounded)
    Buffered,
    Dropped(DropReason),
}

/// An epoch in use and its hint.
type Hinted = (Vec<u8>, Arc<OpenEpoch>);

/// The epochs in use on this device (in memory: handles die at the lock), per session, with their hints.
#[derive(Default)]
pub(crate) struct InUse(HashMap<String, Vec<Hinted>>);

fn pending_key(session: &str) -> String {
    format!("pending/{session}")
}

impl PqChat {
    /// How many chain positions `session` holds (CLI-PQC-14's bound: [`POSITIONS_MAX`]).
    pub fn held_positions(&self, session: &str) -> usize {
        self.chains().held(&session.to_ascii_lowercase())
    }

    /// The seed was locked (or the app starts with it locked): every chain position and epoch key handle released;
    /// positions are derived again, lazily, when a message needs one after the epochs are open again; Matrix events kept
    /// until [`PqChat::resume`] (CLI-PQC-10).
    pub fn locked(&self) {
        self.set_locked(true);
        self.chains().clear();
        self.in_use().0.clear();
    }

    fn in_use(&self) -> std::sync::MutexGuard<'_, InUse> {
        self.in_use
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn timelines(&self) -> std::sync::MutexGuard<'_, HashMap<String, order::Timeline>> {
        self.timelines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// `session`'s messages in display order (UA-7 P19, P49).
    pub fn timeline(&self, session: &str) -> Vec<order::Message> {
        self.timelines()
            .get(&session.to_ascii_lowercase())
            .map(order::Timeline::view)
            .unwrap_or_default()
    }

    pub(crate) fn show(
        &self,
        ep: &OpenEpoch,
        r: &PqChatMessage,
        id: &str,
        p: crate::content::Parsed,
        content: Arc<SecretBytes>,
    ) {
        let sender = r.sender.to_ascii_lowercase();
        // display only, and only from a leaf of that seat in the epoch
        let on_behalf_of = p.on_behalf_of.filter(|seat| {
            *seat != ZERO32
                && ep
                    .epoch
                    .members
                    .iter()
                    .any(|m| m.ua == sender && m.via == *seat)
        });
        let m = Shown {
            id: id.to_string(),
            epoch: ep.epoch.id.clone(),
            sender,
            device: r.device.to_ascii_lowercase(),
            counter: r.counter,
            parents: r.parents.iter().map(|x| x.to_ascii_lowercase()).collect(),
            ts: p.ts,
            on_behalf_of,
            kind: p.content.kind(),
            target: p.content.target().map(str::to_string),
            content,
        };
        self.timelines()
            .entry(ep.epoch.session_id.clone())
            .or_default()
            .add(m);
    }

    /// `ep` of `s` in use on this device: its envelopes read from now on, those kept for it read now; when it is a complete
    /// child of an epoch in use, sends under the parent are held until the home's final block shows it (CLI-PQC-07); a
    /// rekey naming a store the user has not confirmed is told (`StoresChanged`, CLI-PQC-06).
    pub async fn use_epoch(
        &self,
        s: &SessionRef,
        ep: OpenEpoch,
    ) -> Result<Arc<OpenEpoch>, PqChatError> {
        let hint = self.app.pqchat_hint(ep.k.clone())?;
        let sid = ep.epoch.session_id.clone();
        let ep = Arc::new(ep);
        let parent = {
            let mut u = self.in_use();
            let v = u.0.entry(sid.clone()).or_default();
            v.retain(|(_, e)| e.epoch.id != ep.epoch.id);
            v.push((hint.clone(), ep.clone()));
            v.iter()
                .find(|(_, e)| e.epoch.id == ep.epoch.parent)
                .map(|(_, e)| e.epoch.admins.clone())
        };
        self.stores_changed(&ep, parent.as_deref());
        if parent.is_some() && ep.epoch.epoch > 0 {
            let c = self
                .net
                .read(
                    &s.chain,
                    &s.home,
                    "IPqChat.epochComplete",
                    json!({ "epochId": ep.epoch.id }),
                )
                .await?;
            if at(&c, "0") == true {
                self.saw_child(&ep.epoch.parent, &ep.epoch.id);
            }
        }
        let mut kept = vec![];
        let key = pending_key(&sid);
        let ours = |h: &String| *h == crate::model::hex(&hint);
        let waiting: Option<Vec<(String, String)>> = Items(&*self.store).get(&key)?;
        if waiting.is_some_and(|v| v.iter().any(|(h, _)| ours(h))) {
            Items(&*self.store).update::<Vec<(String, String)>, _>(&key, |v| {
                let (mine, rest): (Vec<_>, Vec<_>) = v
                    .unwrap_or_default()
                    .into_iter()
                    .partition(|(h, _)| ours(h));
                kept = mine;
                Ok(rest)
            })?;
        }
        for (_, env) in kept {
            if let Ok(env) = crate::model::unhex(&env) {
                let _ = self.receive(&ep, env).await;
            }
        }
        Ok(ep)
    }

    /// An envelope under `hint` handed in from a store of `session`: read under its epoch, or kept (at most
    /// [`PENDING_MAX`] per session, the oldest dropped) until that epoch is in use.
    pub async fn incoming(
        &self,
        session: &str,
        hint: &[u8],
        env: Vec<u8>,
    ) -> Result<Incoming, PqChatError> {
        Ok(self.incoming_from(session, hint, env).await?.0)
    }

    /// [`PqChat::incoming`], with the sender UA of a message shown.
    pub(crate) async fn incoming_from(
        &self,
        session: &str,
        hint: &[u8],
        env: Vec<u8>,
    ) -> Result<(Incoming, Option<String>), PqChatError> {
        let sid = session.to_ascii_lowercase();
        if hint.len() != 8 {
            self.drops.add(&sid, DropReason::Decode);
            return Ok((Incoming::Dropped(DropReason::Decode), None));
        }
        let ep = self.in_use().0.get(&sid).and_then(|v| {
            v.iter()
                .find(|(h, _)| h.as_slice() == hint)
                .map(|(_, e)| e.clone())
        });
        if let Some(ep) = ep {
            return Ok(match self.receive(&ep, env).await {
                Ok(r) => (
                    Incoming::Shown(r.message_id),
                    Some(r.record.sender.to_ascii_lowercase()),
                ),
                Err(d) => (Incoming::Dropped(d), None),
            });
        }
        let item = (crate::model::hex(hint), crate::model::hex(&env));
        Items(&*self.store).update::<Vec<(String, String)>, _>(&pending_key(&sid), |v| {
            let mut v = v.unwrap_or_default();
            v.push(item.clone());
            while v.len() > PENDING_MAX {
                v.remove(0);
            }
            Ok(v)
        })?;
        Ok((Incoming::Buffered, None))
    }

    /// How many envelopes `session` keeps for epochs not in use.
    pub fn pending(&self, session: &str) -> Result<usize, PqChatError> {
        Ok(Items(&*self.store)
            .get::<Vec<(String, String)>>(&pending_key(&session.to_ascii_lowercase()))?
            .map_or(0, |v| v.len()))
    }

    /// The epoch a send of `s` goes under: the latest in use, followed at home to its final child (opened for `me`, then in
    /// use); `EpochNotFinal` while a complete child seen is not final; `NotMember` when `me` is no member of it.
    pub(crate) async fn send_under(
        &self,
        s: &SessionRef,
        me: &Me,
    ) -> Result<Arc<OpenEpoch>, PqChatError> {
        let sid = s.session_id.to_ascii_lowercase();
        let latest = |u: &InUse| {
            u.0.get(&sid)
                .and_then(|v| v.iter().max_by_key(|(_, e)| e.epoch.epoch))
                .map(|(_, e)| e.clone())
        };
        let in_use = |id: &str| {
            self.in_use().0.get(&sid).and_then(|v| {
                v.iter()
                    .find(|(_, e)| e.epoch.id == id)
                    .map(|(_, e)| e.clone())
            })
        };
        let mut ep = latest(&self.in_use()).ok_or(PqChatError::SessionUnknown)?;
        // a child seen and not final yet: its parent's final state at home decides
        let parent = self
            .unfinal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|(_, c)| **c == ep.epoch.id)
            .map(|(p, _)| p.clone());
        if let Some(p) = parent.and_then(|p| in_use(&p)) {
            ep = p;
        }
        for _ in 0..EPOCH_STEPS {
            let id = self.send_epoch(s, &ep.epoch.id).await?;
            if id == ep.epoch.id {
                return Ok(ep);
            }
            ep = match in_use(&id) {
                Some(e) => e,
                None => {
                    let open = self
                        .open_epoch(s, &id, &me.key, &me.ua, None)
                        .await
                        .map_err(|d| match d {
                            DropReason::Member => PqChatError::NotMember,
                            _ => PqChatError::Internal,
                        })?;
                    self.use_epoch(s, open).await?
                }
            };
        }
        Err(PqChatError::EpochNotFinal)
    }

    /// The own chain's position at `counter`: from the nearest held one at or below it, else from `ck_0`, in steps of at
    /// most [`WALK_MAX`].
    fn own_position(
        &self,
        ep: &OpenEpoch,
        ua: &str,
        device: &str,
        counter: u64,
    ) -> Result<Arc<AppKey>, PqChatError> {
        let sid = &ep.epoch.session_id;
        let scope = format!("{}/{ua}/{device}", ep.epoch.id);
        let near = self.chains().nearest(sid, &scope, counter);
        let (mut at, mut p) = match near {
            Some(x) => x,
            None => (
                0,
                self.app.pqchat_chain(
                    ep.k.clone(),
                    sid.clone(),
                    ep.epoch.id.clone(),
                    ua.into(),
                    device.into(),
                )?,
            ),
        };
        while at < counter {
            let n = (counter - at).min(WALK_MAX);
            p = self.app.pqchat_advance(p, n)?;
            at += n;
        }
        self.chains().hold(sid, &scope, counter, p.clone());
        Ok(p)
    }

    /// `content` sealed and signed for every store of `s` by `me` (S5, no per-message prompt): under the epoch
    /// [`PqChat::send_under`] gives, at the own chain's next counter, **taken before the seal**, its `parents` the session's
    /// heads; shown at once, its id seen (its copy from a store is a duplicate).
    pub async fn seal(
        &self,
        s: &SessionRef,
        me: &Me,
        content: &Content,
        ts: Option<u64>,
    ) -> Result<Outgoing, PqChatError> {
        crate::session::seed_of(&me.key)?;
        let v = content.value(ts)?;
        let ep = self.send_under(s, me).await?;
        let out = self.seal_under(&ep, me, &v).await?;
        self.mine(&out, &v);
        Ok(out)
    }

    /// An own message sent: shown, its id seen (its copy from a store is a duplicate).
    pub(crate) fn mine(&self, out: &Outgoing, v: &Value) {
        let sealed = &out.sealed;
        self.chains()
            .add_id(&out.epoch.epoch.session_id, sealed.message_id.clone());
        let v = v.to_string();
        let Ok(h) = SecretBytes::new(v.len()) else {
            return;
        };
        h.with_mut(|b| b.copy_from_slice(v.as_bytes()));
        let p = Content::parse(v.as_bytes());
        self.show(
            &out.epoch,
            &sealed.record,
            &sealed.message_id,
            p,
            Arc::new(h),
        );
    }

    pub(crate) async fn seal_under(
        &self,
        ep: &Arc<OpenEpoch>,
        me: &Me,
        v: &Value,
    ) -> Result<Outgoing, PqChatError> {
        let ua = me.ua.to_ascii_lowercase();
        let sid = ep.epoch.session_id.clone();
        if !ep.epoch.has_member(&ua) {
            return Err(PqChatError::NotMember);
        }
        let device = self.device()?;
        let counter = self.take_counter(&ep.epoch.id, &device)?;
        let heads = self
            .timelines()
            .get(&sid)
            .map(|t| t.heads().to_vec())
            .unwrap_or_default();
        let parents = order::parents(&heads)?;
        let pos = self.own_position(ep, &ua, &device, counter)?;
        let sealed = self
            .app
            .pqchat_seal_message(
                me.key.clone(),
                ep.k.clone(),
                pos,
                PqMessageHeader {
                    session_id: sid.clone(),
                    epoch_id: ep.epoch.id.clone(),
                    device,
                    counter,
                    parents,
                },
                v.to_string(),
            )
            .await?;
        if sealed.record.sender.to_ascii_lowercase() != ua {
            return Err(PqChatError::Internal);
        }
        Ok(Outgoing {
            epoch: ep.clone(),
            sealed,
        })
    }
}
