// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! A session's stores (CLI-PQC-06; UA-7 P27, P29, P49, §6.5): one send builds one signed record and one envelope and delivers
//! the same bytes to every store of the epoch's list that its type may use (`typing` to the Matrix room only, none without
//! one); a list naming a kind this build does not implement refuses the send before anything is signed (`StoreUnsupported`);
//! chain-store gas is spent only under the session's consent (`ChainCostUnconfirmed`), `receipt` off by default while a chain
//! store is listed; `postMessage` only on the user's choice, above the 1,024-B bucket only with the cost confirmation
//! (`ContentTooLarge`); a store the user has not confirmed is neither written nor read (`StoreUnconfirmed`), and a rekey that
//! brings one is told (`StoresChanged`, by an admin or not).
use crate::content::Content;
use crate::file::{FileToSend, FileUpload};
use crate::message::{OpenEpoch, POST_BUCKET};
use crate::reads::SessionRef;
use crate::session::{check_stores, Info, Me, StoreEntry};
use crate::{Event, Items, PqChat, PqChatError};
use scaas_sdk::op::KeyRef;
use scaas_sdk::SecretBytes;
use std::sync::Arc;

/// The user's choices for a session on this device (spec §7): the stores confirmed, the chain-store spend consent, receipts.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Prefs {
    pub confirmed: Vec<StoreEntry>,
    pub chain_spend: bool,
    /// `None`: on unless a chain store is listed
    pub receipts: Option<bool>,
}

/// How one message goes on chain: the payer of its chain writes, and the user's choices for it.
#[derive(Debug, Clone)]
pub struct SendOpts {
    pub payer: KeyRef,
    /// `postMessage` at the home instance as well (D2)
    pub post: bool,
    /// the user confirmed the cost of a `postMessage` above the 1,024-B bucket
    pub post_cost_confirmed: bool,
}

/// One store's outcome of a send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// the SDK operation's id (a chain write) or empty (a Matrix event sent)
    Sent(String),
    /// this store only; the code
    Failed(&'static str),
    /// a store of the list the user has not confirmed: not written
    Unconfirmed,
}

/// What a send did: the message's id (none when nothing was sent), each store's outcome, the `postMessage`'s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendReport {
    pub message_id: Option<String>,
    /// each store by its index in the epoch's list (the list itself is `sealedInfo` plaintext, read through
    /// [`PqChat::info`])
    pub stores: Vec<(u32, Delivery)>,
    pub post: Option<Delivery>,
}

/// What a send carries: a content, or a file the SDK seals first (`file`).
#[derive(Clone, Copy)]
pub(crate) enum Body<'a> {
    Content(&'a Content),
    File(&'a FileToSend),
}

/// A `sealedInfo` handle read by its named fields.
pub(crate) fn read_info(h: &SecretBytes) -> Result<Info, PqChatError> {
    h.with(|b| serde_json::from_slice(b))
        .map_err(|_| PqChatError::Internal)
}

fn prefs_key(session: &str) -> String {
    format!("prefs/{}", session.to_ascii_lowercase())
}

fn is_chain(e: &StoreEntry) -> bool {
    matches!(e, StoreEntry::Chain { .. })
}

fn is_matrix(e: &StoreEntry) -> bool {
    matches!(e, StoreEntry::Matrix { .. })
}

impl PqChat {
    /// The user's choices for `session` on this device (its confirmed stores are `sealedInfo` plaintext: crate-only).
    pub(crate) fn prefs(&self, session: &str) -> Result<Prefs, PqChatError> {
        Ok(Items(&*self.store)
            .get(&prefs_key(session))?
            .unwrap_or_default())
    }

    fn set_prefs(&self, session: &str, f: impl Fn(&mut Prefs)) -> Result<(), PqChatError> {
        Items(&*self.store).update::<Prefs, _>(&prefs_key(session), |p| {
            let mut p = p.unwrap_or_default();
            f(&mut p);
            Ok(p)
        })?;
        Ok(())
    }

    /// The user's per-session consent to chain-store gas (asked with the figure per message at creation or acceptance).
    pub fn consent_chain_spend(&self, session: &str, yes: bool) -> Result<(), PqChatError> {
        self.set_prefs(session, |p| p.chain_spend = yes)
    }

    /// The user's choice of read receipts for `session`.
    pub fn set_receipts(&self, session: &str, on: bool) -> Result<(), PqChatError> {
        self.set_prefs(session, |p| p.receipts = Some(on))
    }

    /// Every store `ep`'s list names, confirmed by the user: written to and read from from now on.
    pub fn confirm_stores(&self, ep: &OpenEpoch) -> Result<(), PqChatError> {
        let stores = self.info_of(ep)?.stores;
        self.set_prefs(&ep.epoch.session_id, |p| {
            for s in &stores {
                if !p.confirmed.contains(s) {
                    p.confirmed.push(s.clone());
                }
            }
        })
    }

    /// `ep`'s `sealedInfo` opened (K5), its JSON only as the SDK's handle (owner 2026-11-22, spec §11); a tree epoch's
    /// ([`PqChat::tree_open`]) is the info in force there from the replay (`TreeInfoMissing` when the device holds none).
    pub fn info(&self, ep: &OpenEpoch) -> Result<Arc<SecretBytes>, PqChatError> {
        if let Some(i) = self.tree_epoch(&ep.epoch.id) {
            return i.ok_or(PqChatError::TreeInfoMissing);
        }
        Ok(Arc::new(self.app.pqchat_open_info(
            ep.k.clone(),
            ep.epoch.session_id.clone(),
            ep.epoch.id.clone(),
            ep.epoch.sealed_info.clone(),
        )?))
    }

    /// `ep`'s `sealedInfo` read by its named fields, where the crate acts on it.
    pub(crate) fn info_of(&self, ep: &OpenEpoch) -> Result<Info, PqChatError> {
        read_info(&*self.info(ep)?)
    }

    /// The chain stores of `info` on a test chain the app serves (its profile key `…-testnet`): warned about, since a test
    /// chain can be retired with its data (UA-7 P27).
    pub fn test_chain_stores(&self, info: &Info) -> Vec<StoreEntry> {
        info.stores
            .iter()
            .filter(|e| match e {
                StoreEntry::Chain { chain_uid, .. } => self.conf.chains.iter().any(|c| {
                    c.chain_uid.eq_ignore_ascii_case(chain_uid) && c.chain.ends_with("-testnet")
                }),
                _ => false,
            })
            .cloned()
            .collect()
    }

    /// A rekey's list naming a store the user has not confirmed: `StoresChanged`, with whether its author is an admin of the
    /// parent (`parent_admins`; the epoch's own when the parent is not in use). Nothing for a session the user has confirmed
    /// nothing of yet.
    pub(crate) fn stores_changed(&self, ep: &OpenEpoch, parent_admins: Option<&[String]>) {
        if ep.epoch.epoch == 0 {
            return;
        }
        let (Ok(info), Ok(p)) = (self.info_of(ep), self.prefs(&ep.epoch.session_id)) else {
            return;
        };
        if p.confirmed.is_empty() || info.stores.iter().all(|s| p.confirmed.contains(s)) {
            return;
        }
        let admins = parent_admins.unwrap_or(&ep.epoch.admins);
        self.event(Event::StoresChanged {
            session: ep.epoch.session_id.clone(),
            author: ep.epoch.author.clone(),
            by_admin: admins.contains(&ep.epoch.author),
        });
    }

    /// The content whose JSON `content` holds ([`Content::from_json`]: the bindings send a content only as this handle, owner
    /// 2026-11-23) sent by `me` to every store of `s`'s current epoch its type may use, the same bytes to each (CLI-PQC-06).
    /// Refused before anything is signed: a store list out of UA-7 §4.2's rules (`StoreListInvalid`) or naming a kind not
    /// implemented (`StoreUnsupported`), every store it would use unconfirmed (`StoreUnconfirmed`), a Matrix room without an
    /// attached client (`MatrixDetached`), chain writes without the session's spend consent (`ChainCostUnconfirmed`). A
    /// `postMessage` above the 1,024-B bucket without `post_cost_confirmed`: `ContentTooLarge`, nothing sent (the counter
    /// skipped). A `typing` with no room listed and a `receipt` while receipts are off send nothing.
    pub async fn send(
        &self,
        s: &SessionRef,
        me: &Me,
        content: Arc<SecretBytes>,
        ts: Option<u64>,
        o: &SendOpts,
    ) -> Result<SendReport, PqChatError> {
        let c = content.with(Content::from_json)?;
        self.send_content(s, me, &c, ts, o).await
    }

    /// [`PqChat::send`] of a content built in Rust (Rust-only: the bindings send only a handle).
    #[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
    pub async fn send_content(
        &self,
        s: &SessionRef,
        me: &Me,
        content: &Content,
        ts: Option<u64>,
        o: &SendOpts,
    ) -> Result<SendReport, PqChatError> {
        Ok(self
            .send_with(s, me, Body::Content(content), ts, o)
            .await?
            .0)
    }

    /// [`PqChat::send`] of a content, or of a file sealed by the SDK just before the message ([`PqChat::send_file`]).
    pub(crate) async fn send_with(
        &self,
        s: &SessionRef,
        me: &Me,
        body: Body<'_>,
        ts: Option<u64>,
        o: &SendOpts,
    ) -> Result<(SendReport, Option<FileUpload>), PqChatError> {
        crate::session::seed_of(&me.key)?;
        self.require_accepted(&s.session_id)?;
        match body {
            // a `file` only through `send_file`, which enters its key
            Body::Content(Content::File { .. }) => return Err(PqChatError::ContentInvalid),
            Body::Content(c) => drop(c.value(ts)?),
            Body::File(f) => f.check(ts)?,
        }
        let content = match body {
            Body::Content(c) => Some(c),
            Body::File(_) => None,
        };
        let ep = self.send_under(s, me).await?;
        let prefs = self.prefs(&ep.epoch.session_id)?;
        // R11: a tree session sends no automatic receipt, whatever its store list: only the user's own choice turns them on
        if matches!(content, Some(Content::Receipt { .. }))
            && self.tree_epoch(&ep.epoch.id).is_some()
            && prefs.receipts != Some(true)
        {
            return Ok((
                SendReport {
                    message_id: None,
                    stores: vec![],
                    post: None,
                },
                None,
            ));
        }
        let info = self.info_of(&ep)?;
        check_stores(&info)?;
        let mut report = SendReport {
            message_id: None,
            stores: vec![],
            post: None,
        };
        let typing = matches!(content, Some(Content::Typing { .. }));
        let chain_listed = info.stores.iter().any(is_chain);
        if matches!(content, Some(Content::Receipt { .. }))
            && !prefs.receipts.unwrap_or(!chain_listed)
        {
            return Ok((report, None));
        }
        // (index in the list, store, confirmed) in the list's order
        let mut plan = vec![];
        for (i, e) in (0u32..).zip(&info.stores) {
            // `typing`: the room only (P49)
            if !e.holds_messages() || (typing && !is_matrix(e)) {
                continue;
            }
            plan.push((i, e.clone(), prefs.confirmed.contains(e)));
        }
        let targets: Vec<&StoreEntry> = plan.iter().filter(|p| p.2).map(|p| &p.1).collect();
        let post = o.post && !typing;
        if targets.is_empty() && !post {
            return if plan.is_empty() {
                Ok((report, None))
            } else {
                Err(PqChatError::StoreUnconfirmed)
            };
        }
        if targets.iter().any(|e| is_matrix(e)) && self.matrix().is_none() {
            return Err(PqChatError::MatrixDetached);
        }
        if (post || targets.iter().any(|e| is_chain(e))) && !prefs.chain_spend {
            return Err(PqChatError::ChainCostUnconfirmed);
        }
        let (v, key, upload) = match body {
            Body::Content(c) => (c.value(ts)?, None, None),
            Body::File(f) => {
                let (v, key, up) = self.seal_file_for(me, f, ts)?;
                (v, Some(key), Some(up))
            }
        };
        let out = self.seal_under(&ep, me, &v, key.clone()).await;
        if let Some(k) = key {
            let _ = self.app.destroy(k);
        }
        let out = out?;
        if post && out.bucket() > POST_BUCKET && !o.post_cost_confirmed {
            return Err(PqChatError::ContentTooLarge);
        }
        self.mine(&out, &v);
        for (i, e, confirmed) in plan {
            let d = if !confirmed {
                Delivery::Unconfirmed
            } else {
                match self.deliver(&e, &out, &o.payer).await {
                    Ok(id) => Delivery::Sent(id),
                    Err(x) => Delivery::Failed(x.code()),
                }
            };
            report.stores.push((i, d));
        }
        if post {
            report.post = Some(match self.post_message(s, &out, &o.payer).await {
                Ok(id) => Delivery::Sent(id),
                Err(x) => Delivery::Failed(x.code()),
            });
        }
        report.message_id = Some(out.sealed.message_id.clone());
        Ok((report, upload))
    }

    /// One store's copy of `out`: a Matrix event `{v, hint, env}` to the room, or `storeMessage(1, hint, env)`.
    async fn deliver(
        &self,
        e: &StoreEntry,
        out: &crate::message::Outgoing,
        payer: &KeyRef,
    ) -> Result<String, PqChatError> {
        match e {
            StoreEntry::Matrix { room } => {
                // only the room bound to this session (CLI-PQC-05)
                if self.room_session(room)?.as_deref() != Some(out.epoch.epoch.session_id.as_str())
                {
                    return Err(PqChatError::MatrixRoom);
                }
                let m = self.matrix().ok_or(PqChatError::MatrixDetached)?;
                m.send_event(
                    room,
                    crate::matrix::event(&out.sealed.hint, &out.sealed.env),
                )
                .await?;
                Ok(String::new())
            }
            StoreEntry::Chain { .. } => self.store_message(e, out, payer).await,
            _ => Err(PqChatError::StoreUnsupported),
        }
    }
}
