// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Public topics (topics spec P33–P46, CTR-CHAT-15 to CTR-CHAT-18): create (with `openReplies` true, D19), update, writers,
//! post, reply, edit, vote, each signed by the SDK's `prepare_pqchat_topic*` entries and their `sign()` (S6) from named fields and prepared as the
//! SDK's operation (W1); a record that replaces a value is built at `seq == stored + 1` and an edit at `versionCount + 1`,
//! both read from the instance's state. Rights are the contract's: the crate checks none of its own and the quote (a
//! simulation) refuses what the contract refuses. Every list is paged from state. A `ref` is shown unverified until
//! [`PqChat::resolve_ref`] reads its chain: the factory lists its instance, the referenced entry's topic names that instance
//! as its home (Fable P3-4), and `contentHash` is zero; a pinned `contentHash` stays unverified (`HashUnchecked`): the views
//! now give each version's nonce (CTR-CHAT-31), the digest check itself is not built here yet. An `msig` author:
//! `MsigAuthorPlanned`.
//! Nothing here is encrypted; bodies are public, untrusted Markdown (rendered by the front-end, P46).
use crate::model::{self, at, ZERO32};
use crate::session::{seed_of, sig_json, Me};
use crate::{PqChat, PqChatError};
use scaas_sdk::app_core::AppCall;
use scaas_sdk::op::KeyRef;
use scaas_sdk::pqchat_records::{
    PqChatSigned, PqEntryRef, PqTopic, PqTopicEdit, PqTopicEntry, PqTopicUpdate, PqTopicVote,
    PqTopicWriter,
};
use serde_json::{json, Value};

/// The media type the crate writes (RFC 7763, CommonMark).
pub const MARKDOWN: &str = "text/markdown";
/// The most ids one page asks for.
pub const PAGE_MAX: u64 = 64;
const ZERO20: &str = "0x0000000000000000000000000000000000000000";

/// Where a topic write goes: the SDK profile's chain and the `PqChat` instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct At {
    pub chain: String,
    pub instance: String,
}

/// A signed, prepared topic write: the record's id (a topic's or an entry's; `None` for the others) and the operation.
pub struct TopicWrite {
    pub id: Option<String>,
    pub call: AppCall,
}

/// A vote's value (P40): up, down, or withdrawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vote {
    Up,
    Down,
    Withdraw,
}

impl Vote {
    fn value(self) -> i8 {
        match self {
            Vote::Up => 1,
            Vote::Down => -1,
            Vote::Withdraw => 0,
        }
    }
}

/// A topic as `topicOf` returns it (its latest name, `about` and `openReplies`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topic {
    pub id: String,
    pub admin: String,
    pub home_chain: String,
    pub home_chat_contract: String,
    pub name: String,
    pub about: Vec<u8>,
    pub open_replies: bool,
    pub seq: u64,
}

/// Why a `ref` is not shown as verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefFault {
    /// its `chainUid` is no chain the app serves
    ChainNotServed,
    /// that chain's factory does not list its instance as `PqChat`
    Unlisted,
    /// the entry or its topic could not be read there
    Unreadable,
    /// the entry's topic names another instance as its home (Fable P3-4)
    OtherHome,
    /// `contentHash` is pinned and cannot be rebuilt from state
    HashUnchecked,
}

/// A `ref`'s standing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefState {
    /// not read yet: shown as unverified
    Unresolved,
    Verified,
    Unverified(RefFault),
}

/// An entry as `entryOf` returns it: the original's place and its latest version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: String,
    pub topic_id: String,
    pub author: String,
    /// zero for a post
    pub parent_id: String,
    pub depth: u64,
    /// `None` for no reference
    pub entry_ref: Option<PqEntryRef>,
    /// [`RefState::Unresolved`] with a reference, until [`PqChat::resolve_ref`]
    pub ref_state: Option<RefState>,
    pub media_type: String,
    pub body: Vec<u8>,
    pub version_count: u64,
    /// the block time the original landed (CTR-CHAT-29)
    pub posted_at: u64,
    /// the latest edit's block time, 0 before one (CTR-CHAT-29)
    pub edited_at: u64,
    /// the latest version's nonce (CTR-CHAT-31)
    pub nonce: u64,
}

/// A version as `versionAt` returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub media_type: String,
    pub body: Vec<u8>,
    /// this version's nonce (CTR-CHAT-31)
    pub nonce: u64,
    /// the original's block time (CTR-CHAT-29)
    pub posted_at: u64,
    /// this version's block time, 0 for version 1 (CTR-CHAT-29)
    pub edited_at: u64,
}

/// One page of a list: at most the asked count of ids and the list's length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub ids: Vec<String>,
    pub total: u64,
}

/// A topic list of P42.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum List {
    Topics,
    TopicsByAdmin(String),
    Writers(String),
    Posts(String),
    Replies(String),
    ByAuthor(String),
}

fn bad() -> PqChatError {
    PqChatError::Internal
}

fn ref_json(r: &PqEntryRef) -> Value {
    json!({"chainUid": r.chain_uid, "pqchat": r.pqchat, "entryId": r.entry_id, "contentHash": r.content_hash})
}

fn no_ref() -> PqEntryRef {
    PqEntryRef {
        chain_uid: ZERO32.into(),
        pqchat: ZERO20.into(),
        entry_id: ZERO32.into(),
        content_hash: ZERO32.into(),
    }
}

impl PqChat {
    async fn topic_write(
        &self,
        on: &At,
        item: &'static str,
        name: &str,
        record: Value,
        signed: PqChatSigned,
        payer: &KeyRef,
    ) -> Result<TopicWrite, PqChatError> {
        let a = json!({ name: record, "sig": sig_json(&signed.sig) });
        let call = self
            .net
            .prepare(&on.chain, &on.instance, item, a, payer)
            .await?;
        Ok(TopicWrite {
            id: signed.id,
            call,
        })
    }

    /// A new topic of `me` at `at` (P41), `openReplies` true (D19), its home this instance.
    pub async fn create_topic(
        &self,
        on: &At,
        me: &Me,
        nonce: u64,
        name: &str,
        about: &[u8],
        payer: &KeyRef,
    ) -> Result<TopicWrite, PqChatError> {
        seed_of(&me.key)?;
        self.require_listed(&on.chain, &on.instance).await?;
        let c = self.conf(&on.chain)?;
        let (admin, home) = (me.ua.to_ascii_lowercase(), on.instance.to_ascii_lowercase());
        let t = PqTopic {
            admin: admin.clone(),
            nonce,
            home_chain: c.chain_uid.to_ascii_lowercase(),
            home_chat_contract: home.clone(),
            name: name.into(),
            about: about.to_vec(),
            open_replies: true,
        };
        let r = json!({"admin": admin, "nonce": nonce.to_string(), "homeChain": t.home_chain,
            "homeChatContract": home, "name": name, "about": model::hex(about), "openReplies": true});
        let signed = self
            .app
            .prepare_pqchat_topic(me.key.clone(), t)
            .await?
            .sign()
            .await?;
        self.topic_write(on, "IPqChat.createTopic", "t", r, signed, payer)
            .await
    }

    /// The topic's admin's update (P41) at the stored `seq + 1`.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_topic(
        &self,
        on: &At,
        topic_id: &str,
        me: &Me,
        name: &str,
        about: &[u8],
        open_replies: bool,
        payer: &KeyRef,
    ) -> Result<TopicWrite, PqChatError> {
        seed_of(&me.key)?;
        let seq = self.topic(on, topic_id).await?.seq + 1;
        let tid = topic_id.to_ascii_lowercase();
        let u = PqTopicUpdate {
            topic_id: tid.clone(),
            seq,
            name: name.into(),
            about: about.to_vec(),
            open_replies,
        };
        let r = json!({"topicId": tid, "seq": seq.to_string(), "name": name, "about": model::hex(about),
            "openReplies": open_replies});
        let signed = self
            .app
            .prepare_pqchat_topic_update(me.key.clone(), u)
            .await?
            .sign()
            .await?;
        self.topic_write(on, "IPqChat.updateTopic", "u", r, signed, payer)
            .await
    }

    /// The topic's admin grants or revokes `writer` (P41) at the stored `seq + 1` of `(topic, writer)`.
    pub async fn set_writer(
        &self,
        on: &At,
        topic_id: &str,
        me: &Me,
        writer: &str,
        granted: bool,
        payer: &KeyRef,
    ) -> Result<TopicWrite, PqChatError> {
        seed_of(&me.key)?;
        let (tid, wr) = (topic_id.to_ascii_lowercase(), writer.to_ascii_lowercase());
        let v = self
            .net
            .read(
                &on.chain,
                &on.instance,
                "IPqChat.writerOf",
                json!({"topicId": tid, "ua": wr}),
            )
            .await?;
        let seq = model::num(at(&v, "seq"))? + 1;
        let w = PqTopicWriter {
            topic_id: tid.clone(),
            writer: wr.clone(),
            granted,
            seq,
        };
        let r = json!({"topicId": tid, "writer": wr, "granted": granted, "seq": seq.to_string()});
        let signed = self
            .app
            .prepare_pqchat_topic_writer(me.key.clone(), w)
            .await?
            .sign()
            .await?;
        self.topic_write(on, "IPqChat.setTopicWriter", "w", r, signed, payer)
            .await
    }

    /// A post (`parent` `None`) or a reply to `parent` in `topic_id` (P41), Markdown, with an optional `ref` (stored as
    /// given, never checked by the contract).
    #[allow(clippy::too_many_arguments)]
    pub async fn post(
        &self,
        on: &At,
        topic_id: &str,
        me: &Me,
        nonce: u64,
        parent: Option<String>,
        entry_ref: Option<PqEntryRef>,
        body: &[u8],
        payer: &KeyRef,
    ) -> Result<TopicWrite, PqChatError> {
        seed_of(&me.key)?;
        let (tid, author) = (topic_id.to_ascii_lowercase(), me.ua.to_ascii_lowercase());
        let parent_id = parent
            .as_deref()
            .map_or(ZERO32.to_string(), str::to_ascii_lowercase);
        let er = entry_ref.unwrap_or_else(no_ref);
        let r = json!({"topicId": tid, "author": author, "nonce": nonce.to_string(), "parentId": parent_id,
            "ref": ref_json(&er), "mediaType": MARKDOWN, "body": model::hex(body)});
        let e = PqTopicEntry {
            topic_id: tid,
            author,
            nonce,
            parent_id,
            entry_ref: er,
            media_type: MARKDOWN.into(),
            body: body.to_vec(),
        };
        let signed = self
            .app
            .prepare_pqchat_topic_entry(me.key.clone(), e)
            .await?
            .sign()
            .await?;
        self.topic_write(on, "IPqChat.postEntry", "e", r, signed, payer)
            .await
    }

    /// A new version of `entry_id` (P38) at the stored `versionCount + 1`; the author's only (the contract's rule).
    pub async fn edit(
        &self,
        on: &At,
        entry_id: &str,
        me: &Me,
        nonce: u64,
        body: &[u8],
        payer: &KeyRef,
    ) -> Result<TopicWrite, PqChatError> {
        seed_of(&me.key)?;
        let version = self.entry(on, entry_id).await?.version_count + 1;
        let version = u32::try_from(version).map_err(|_| bad())?;
        let (eid, author) = (entry_id.to_ascii_lowercase(), me.ua.to_ascii_lowercase());
        let r = json!({"entryId": eid, "author": author, "nonce": nonce.to_string(), "version": version.to_string(),
            "mediaType": MARKDOWN, "body": model::hex(body)});
        let d = PqTopicEdit {
            entry_id: eid,
            author,
            nonce,
            version,
            media_type: MARKDOWN.into(),
            body: body.to_vec(),
        };
        let signed = self
            .app
            .prepare_pqchat_topic_edit(me.key.clone(), d)
            .await?
            .sign()
            .await?;
        self.topic_write(on, "IPqChat.editEntry", "e", r, signed, payer)
            .await
    }

    /// `me`'s vote on `entry_id` (P40) at the stored `seq + 1` of `(entry, me)`.
    pub async fn vote(
        &self,
        on: &At,
        entry_id: &str,
        me: &Me,
        vote: Vote,
        payer: &KeyRef,
    ) -> Result<TopicWrite, PqChatError> {
        seed_of(&me.key)?;
        let (eid, voter) = (entry_id.to_ascii_lowercase(), me.ua.to_ascii_lowercase());
        let seq = self.vote_of(on, &eid, &voter).await?.1 + 1;
        let r = json!({"entryId": eid, "voter": voter, "value": vote.value().to_string(), "seq": seq.to_string()});
        let v = PqTopicVote {
            entry_id: eid,
            voter,
            value: vote.value(),
            seq,
        };
        let signed = self
            .app
            .prepare_pqchat_topic_vote(me.key.clone(), v)
            .await?
            .sign()
            .await?;
        self.topic_write(on, "IPqChat.voteEntry", "v", r, signed, payer)
            .await
    }

    /// `topicOf(topic_id)` at `at`.
    pub async fn topic(&self, on: &At, topic_id: &str) -> Result<Topic, PqChatError> {
        let tid = topic_id.to_ascii_lowercase();
        let v = self
            .net
            .read(
                &on.chain,
                &on.instance,
                "IPqChat.topicOf",
                json!({ "topicId": tid }),
            )
            .await?;
        let t = &at(&v, "t");
        Ok(Topic {
            id: tid,
            admin: model::h(at(t, "admin"))?,
            home_chain: model::h(at(t, "homeChain"))?,
            home_chat_contract: model::h(at(t, "homeChatContract"))?,
            name: at(t, "name").as_str().ok_or_else(bad)?.into(),
            about: model::bytes(at(t, "about"))?,
            open_replies: at(t, "openReplies").as_bool().ok_or_else(bad)?,
            seq: model::num(at(&v, "seq"))?,
        })
    }

    /// `entryOf(entry_id)` at `at`: a `ref` unresolved.
    pub async fn entry(&self, on: &At, entry_id: &str) -> Result<Entry, PqChatError> {
        let eid = entry_id.to_ascii_lowercase();
        let v = self
            .net
            .read(
                &on.chain,
                &on.instance,
                "IPqChat.entryOf",
                json!({ "entryId": eid }),
            )
            .await?;
        let e = &at(&v, "0");
        let r = &at(e, "ref");
        let er = PqEntryRef {
            chain_uid: model::h(at(r, "chainUid"))?,
            pqchat: model::h(at(r, "pqchat"))?,
            entry_id: model::h(at(r, "entryId"))?,
            content_hash: model::h(at(r, "contentHash"))?,
        };
        let entry_ref = (er != no_ref()).then_some(er);
        Ok(Entry {
            id: eid,
            topic_id: model::h(at(e, "topicId"))?,
            author: model::h(at(e, "author"))?,
            parent_id: model::h(at(e, "parentId"))?,
            depth: model::num(at(e, "depth"))?,
            ref_state: entry_ref.as_ref().map(|_| RefState::Unresolved),
            entry_ref,
            media_type: at(e, "mediaType").as_str().ok_or_else(bad)?.into(),
            body: model::bytes(at(e, "body"))?,
            version_count: model::num(at(e, "versionCount"))?,
            posted_at: model::num(at(e, "postedAt"))?,
            edited_at: model::num(at(e, "editedAt"))?,
            nonce: model::num(at(e, "nonce"))?,
        })
    }

    /// Version `version` of `entry_id` (1 the original): its media type, body, nonce and times.
    pub async fn version_at(
        &self,
        on: &At,
        entry_id: &str,
        version: u64,
    ) -> Result<Version, PqChatError> {
        let v = self
            .net
            .read(
                &on.chain,
                &on.instance,
                "IPqChat.versionAt",
                json!({"entryId": entry_id.to_ascii_lowercase(), "version": version.to_string()}),
            )
            .await?;
        Ok(Version {
            media_type: at(&v, "mediaType").as_str().ok_or_else(bad)?.into(),
            body: model::bytes(at(&v, "body"))?,
            nonce: model::num(at(&v, "nonce"))?,
            posted_at: model::num(at(&v, "postedAt"))?,
            edited_at: model::num(at(&v, "editedAt"))?,
        })
    }

    /// `scoreOf(entry_id)`: `(up, down)`, never a combined score.
    pub async fn score(&self, on: &At, entry_id: &str) -> Result<(u64, u64), PqChatError> {
        let v = self
            .net
            .read(
                &on.chain,
                &on.instance,
                "IPqChat.scoreOf",
                json!({ "entryId": entry_id.to_ascii_lowercase() }),
            )
            .await?;
        Ok((model::num(at(&v, "up"))?, model::num(at(&v, "down"))?))
    }

    /// `voteOf(entry_id, ua)`: the value and its `seq`.
    pub async fn vote_of(
        &self,
        on: &At,
        entry_id: &str,
        ua: &str,
    ) -> Result<(i8, u64), PqChatError> {
        let v = self
            .net
            .read(
                &on.chain,
                &on.instance,
                "IPqChat.voteOf",
                json!({"entryId": entry_id.to_ascii_lowercase(), "ua": ua.to_ascii_lowercase()}),
            )
            .await?;
        let value = at(&v, "value")
            .as_str()
            .and_then(|s| s.parse::<i8>().ok())
            .ok_or_else(bad)?;
        Ok((value, model::num(at(&v, "seq"))?))
    }

    /// A page of `list` at `at`: at most `count` (≤ [`PAGE_MAX`]) ids from `start`, and the list's length; an answer with
    /// more ids than asked is refused.
    pub async fn page(
        &self,
        on: &At,
        list: &List,
        start: u64,
        count: u64,
    ) -> Result<Page, PqChatError> {
        let count = count.min(PAGE_MAX);
        let (s, n) = (start.to_string(), count.to_string());
        let (item, args) = match list {
            List::Topics => ("IPqChat.topics", json!({"start": s, "count": n})),
            List::TopicsByAdmin(a) => (
                "IPqChat.topicsByAdmin",
                json!({"admin_": a.to_ascii_lowercase(), "start": s, "count": n}),
            ),
            List::Writers(t) => (
                "IPqChat.writersOf",
                json!({"topicId": t.to_ascii_lowercase(), "start": s, "count": n}),
            ),
            List::Posts(t) => (
                "IPqChat.posts",
                json!({"topicId": t.to_ascii_lowercase(), "start": s, "count": n}),
            ),
            List::Replies(p) => (
                "IPqChat.replies",
                json!({"parentId": p.to_ascii_lowercase(), "start": s, "count": n}),
            ),
            List::ByAuthor(a) => (
                "IPqChat.byAuthor",
                json!({"author": a.to_ascii_lowercase(), "start": s, "count": n}),
            ),
        };
        let v = self.net.read(&on.chain, &on.instance, item, args).await?;
        let ids = model::list(at(&v, "ids"))?;
        if ids.len() as u64 > count {
            return Err(bad());
        }
        Ok(Page {
            ids,
            total: model::num(at(&v, "total"))?,
        })
    }

    /// The standing of `r` (P35) on its own chain: that chain served, its factory listing the instance, the referenced
    /// entry's topic naming that instance as its home, `contentHash` zero. Reads only; nothing is written or sent.
    pub async fn resolve_ref(&self, r: &PqEntryRef) -> RefState {
        match self.resolve(r).await {
            Ok(()) => RefState::Verified,
            Err(f) => RefState::Unverified(f),
        }
    }

    async fn resolve(&self, r: &PqEntryRef) -> Result<(), RefFault> {
        let uid = r.chain_uid.to_ascii_lowercase();
        let chain = self
            .conf
            .chains
            .iter()
            .find(|c| c.chain_uid.to_ascii_lowercase() == uid)
            .ok_or(RefFault::ChainNotServed)?
            .chain
            .clone();
        let on = At {
            chain,
            instance: r.pqchat.to_ascii_lowercase(),
        };
        if !self
            .listed(&on.chain, &on.instance)
            .await
            .map_err(|_| RefFault::Unreadable)?
        {
            return Err(RefFault::Unlisted);
        }
        let e = self
            .entry(&on, &r.entry_id)
            .await
            .map_err(|_| RefFault::Unreadable)?;
        let t = self
            .topic(&on, &e.topic_id)
            .await
            .map_err(|_| RefFault::Unreadable)?;
        if t.home_chain != uid || t.home_chat_contract != on.instance {
            return Err(RefFault::OtherHome);
        }
        if !r.content_hash.eq_ignore_ascii_case(ZERO32) {
            return Err(RefFault::HashUnchecked);
        }
        Ok(())
    }
}
