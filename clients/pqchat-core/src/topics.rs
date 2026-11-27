// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Public topics (topics spec P33–P46, CTR-CHAT-15 to CTR-CHAT-18): create (with `openReplies` true, D19), update, writers,
//! post, reply, edit, vote, each built from named fields by the SDK's `prepare_pqchat_topic*` entries for the user's review and
//! signed only on the confirm (CLI-SDK-36, [`crate::confirm`]); relayed by the chain's gateways by default, fee 0, or the
//! payer's own transaction (CLI-PQC-18 F3, [`Path`]). A record that replaces a value is built at `seq == stored + 1` and an
//! edit at `versionCount + 1`, both read from the instance's state. Rights are the contract's: the crate checks none of its
//! own and the simulation refuses what the contract refuses. Every list is paged from state, newest first by
//! [`PqChat::page_newest`] (G7), its rows read by `entryRows` and ranked over a window of 256 ids by [`rank`] (F6), each
//! folded at the user's threshold, never dropped. A `ref` is shown unverified until [`PqChat::resolve_ref`] reads its chain:
//! the factory lists its instance, the referenced entry's topic names that instance as its home (Fable P3-4), and a pinned
//! `contentHash` is the typed digest of one of its versions rebuilt from state by the SDK (G5, CTR-CHAT-31). An `msig`
//! author: `MsigAuthorPlanned`.
//! Nothing here is encrypted; bodies are public, untrusted Markdown (rendered by the front-end, P46).
use crate::confirm::{Path, Prepared, RecordWrite};
use crate::model::{self, at, ZERO32};
use crate::net::Unsigned;
use crate::session::{seed_of, Me};
use crate::{PqChat, PqChatError};
use scaas_sdk::pqchat_records::{
    PqChatPrepared, PqEntryRef, PqTopic, PqTopicEdit, PqTopicEntry, PqTopicUpdate, PqTopicVote,
    PqTopicWriter,
};
use serde_json::{json, Value};

/// The most versions of a referenced entry [`PqChat::resolve_ref`] reads to find a pinned `contentHash`, newest first.
pub const REF_VERSIONS_MAX: u64 = 64;
/// The ids a window sort scores (CLI-PQC-18 F6): the newest 256 of a list (Top, Controversial), the first 256 replies of a
/// parent (Best).
pub const WINDOW: u64 = 256;
/// The fold's default (F6): an entry whose `down − up` is 5 or more is folded, never dropped; the user's setting replaces it.
pub const FOLD_DEFAULT: u64 = 5;
/// The most ids one `entryRows` call takes (`PqChat.ENTRY_ROWS_MAX`, CTR-CHAT-30).
pub const ROWS_MAX: usize = 64;

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

/// A topic write built for the review, unsigned (CLI-SDK-36): [`PqChat::confirm`] signs it into a
/// [`crate::confirm::SignedWrite`], [`PqChat::dispatch`] sends it by its path.
pub type TopicWrite = Prepared<RecordWrite>;

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
    /// `contentHash` is pinned and none of the newest [`REF_VERSIONS_MAX`] versions read is it: an older version may be
    HashUnchecked,
    /// `contentHash` is pinned and no version of the entry is it (every version read, CTR-CHAT-31)
    HashMismatch,
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

/// One feed row as `entryRows` gives it (CTR-CHAT-30): an entry without its body, its votes, the viewer's vote and its direct
/// reply count; `folded` by the caller's threshold (F6: shown as "hidden by your filter", never dropped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRow {
    pub id: String,
    pub topic_id: String,
    pub author: String,
    pub parent_id: String,
    pub depth: u64,
    pub entry_ref: Option<PqEntryRef>,
    pub media_type: String,
    pub sig_hash: String,
    pub version_count: u64,
    pub posted_at: u64,
    pub edited_at: u64,
    pub nonce: u64,
    pub body_length: u64,
    pub up: u128,
    pub down: u128,
    /// the viewer's vote: 1, -1 or 0
    pub vote: i8,
    /// direct replies only (the contract keeps no total of a thread)
    pub replies: u64,
    pub folded: bool,
}

/// A window sort (CLI-PQC-18 F6), each deterministic: the same rows give the same order on every client, ties by the lower
/// list index. New and Old are no window: [`PqChat::page_newest`] and [`PqChat::page`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rank {
    /// `up − down`, highest first, over the newest [`WINDOW`] ids
    Top,
    /// Reddit's controversy `(up + down)^(min / max)`, 0 when either is 0, highest first, over the newest [`WINDOW`] ids
    Controversial,
    /// the Wilson score's lower bound of `up / (up + down)` at z = 1.2816, highest first, over the first [`WINDOW`] ids
    Best,
}

/// A window ranked: its rows with their list index, in order; the snapshot's total and whether the window covered the whole
/// list (else the front-end says "scored among the latest 256", or the first 256 for Best).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ranked {
    pub rows: Vec<(u64, EntryRow)>,
    pub total: u64,
    pub whole: bool,
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
    /// `record` (the argument `name` of `item`) prepared for `me`'s signature on the user's confirm: its review, and on the
    /// payer's path the SDK's quote of the call before the signature; nothing signed (CLI-SDK-36).
    #[allow(clippy::too_many_arguments)]
    async fn topic_write(
        &self,
        on: &At,
        me: &Me,
        item: &'static str,
        name: &'static str,
        record: Value,
        prepared: PqChatPrepared,
        path: &Path,
    ) -> Result<TopicWrite, PqChatError> {
        let quote = match path {
            Path::Relayed => None,
            Path::Payer(p) => Some(
                self.quote_unsigned(on, item, json!({ name: record }), p, &me.key)
                    .await?,
            ),
        };
        Ok(Prepared {
            review: prepared.review.clone(),
            unsigned: Unsigned::Record(prepared),
            quote,
            then: RecordWrite {
                at: on.clone(),
                item,
                name,
                record,
                path: path.clone(),
            },
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
        path: &Path,
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
        let prepared = self.app.prepare_pqchat_topic(me.key.clone(), t).await?;
        self.topic_write(on, me, "IPqChat.createTopic", "t", r, prepared, path)
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
        path: &Path,
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
        let prepared = self
            .app
            .prepare_pqchat_topic_update(me.key.clone(), u)
            .await?;
        self.topic_write(on, me, "IPqChat.updateTopic", "u", r, prepared, path)
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
        path: &Path,
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
        let prepared = self
            .app
            .prepare_pqchat_topic_writer(me.key.clone(), w)
            .await?;
        self.topic_write(on, me, "IPqChat.setTopicWriter", "w", r, prepared, path)
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
        path: &Path,
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
        let prepared = self
            .app
            .prepare_pqchat_topic_entry(me.key.clone(), e)
            .await?;
        self.topic_write(on, me, "IPqChat.postEntry", "e", r, prepared, path)
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
        path: &Path,
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
        let prepared = self
            .app
            .prepare_pqchat_topic_edit(me.key.clone(), d)
            .await?;
        self.topic_write(on, me, "IPqChat.editEntry", "e", r, prepared, path)
            .await
    }

    /// `me`'s vote on `entry_id` (P40) at the stored `seq + 1` of `(entry, me)`.
    pub async fn vote(
        &self,
        on: &At,
        entry_id: &str,
        me: &Me,
        vote: Vote,
        path: &Path,
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
        let prepared = self
            .app
            .prepare_pqchat_topic_vote(me.key.clone(), v)
            .await?;
        self.topic_write(on, me, "IPqChat.voteEntry", "v", r, prepared, path)
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
        if r.content_hash.eq_ignore_ascii_case(ZERO32) {
            return Ok(());
        }
        // G5 (CTR-CHAT-31): the version the hash pins, rebuilt from state, newest first
        let want = r.content_hash.to_ascii_lowercase();
        let first = e.version_count.saturating_sub(REF_VERSIONS_MAX - 1).max(1);
        for v in (first..=e.version_count).rev() {
            let x = self
                .version_at(&on, &e.id, v)
                .await
                .map_err(|_| RefFault::Unreadable)?;
            if self
                .content_hash(&e, v, x)
                .map_err(|_| RefFault::Unreadable)?
                == want
            {
                return Ok(());
            }
        }
        Err(match first {
            1 => RefFault::HashMismatch,
            _ => RefFault::HashUnchecked,
        })
    }

    /// The `contentHash` a `ref` pins for version `version` of `entry_id` at `on` (G5): the version's typed digest rebuilt
    /// from state by the SDK (its `PqTopicEntry` for 1, its `PqTopicEdit` after).
    pub async fn content_hash_at(
        &self,
        on: &At,
        entry_id: &str,
        version: u64,
    ) -> Result<String, PqChatError> {
        let e = self.entry(on, entry_id).await?;
        let x = self.version_at(on, &e.id, version).await?;
        self.content_hash(&e, version, x)
    }

    /// The typed digest of version `v` of `e` (its `PqTopicEntry` for 1, its `PqTopicEdit` after), by the SDK.
    fn content_hash(&self, e: &Entry, v: u64, x: Version) -> Result<String, PqChatError> {
        let h = match v {
            1 => self.app.pqchat_entry_hash(PqTopicEntry {
                topic_id: e.topic_id.clone(),
                author: e.author.clone(),
                nonce: x.nonce,
                parent_id: e.parent_id.clone(),
                entry_ref: e.entry_ref.clone().unwrap_or_else(no_ref),
                media_type: x.media_type,
                body: x.body,
            })?,
            _ => self.app.pqchat_edit_hash(PqTopicEdit {
                entry_id: e.id.clone(),
                author: e.author.clone(),
                nonce: x.nonce,
                version: u32::try_from(v).map_err(|_| bad())?,
                media_type: x.media_type,
                body: x.body,
            })?,
        };
        Ok(h.to_ascii_lowercase())
    }

    /// The newest page of `list` before `before` (G7): at most `count` (≤ [`PAGE_MAX`]) ids below index `before`, newest first,
    /// and the list's length. Against a snapshot total a new post never shifts a page.
    pub async fn page_newest(
        &self,
        on: &At,
        list: &List,
        before: u64,
        count: u64,
    ) -> Result<Page, PqChatError> {
        let start = before.saturating_sub(count.min(PAGE_MAX));
        let mut p = self.page(on, list, start, before - start).await?;
        p.ids.reverse();
        Ok(p)
    }

    /// `entryRows(ids, viewer)` (CTR-CHAT-30) in calls of at most [`ROWS_MAX`] ids: one row per id in the order given, each
    /// folded when its `down − up` reaches `fold_at` (the user's setting; `None`: nothing folds). An answer with another number
    /// of rows is refused.
    pub async fn entry_rows(
        &self,
        on: &At,
        ids: &[String],
        viewer: &str,
        fold_at: Option<u64>,
    ) -> Result<Vec<EntryRow>, PqChatError> {
        let mut out = Vec::with_capacity(ids.len());
        for chunk in ids.chunks(ROWS_MAX) {
            let v = self
                .net
                .read(
                    &on.chain,
                    &on.instance,
                    "IPqChat.entryRows",
                    json!({"entryIds": chunk, "viewer": viewer.to_ascii_lowercase()}),
                )
                .await?;
            let rows = at(&v, "rows").as_array().ok_or_else(bad)?;
            if rows.len() != chunk.len() {
                return Err(bad());
            }
            for (id, r) in chunk.iter().zip(rows) {
                out.push(row_of(id, r, fold_at)?);
            }
        }
        Ok(out)
    }

    /// `list` ranked by `sort` over its window against the snapshot total `snapshot` (F6): the window's ids read by pages, each
    /// id once (a repeat is dropped), their rows by `entryRows` folded at `fold_at`, then [`rank`].
    pub async fn ranked(
        &self,
        on: &At,
        list: &List,
        sort: Rank,
        snapshot: u64,
        viewer: &str,
        fold_at: Option<u64>,
    ) -> Result<Ranked, PqChatError> {
        let (start, end) = match sort {
            Rank::Best => (0, snapshot.min(WINDOW)),
            Rank::Top | Rank::Controversial => (snapshot.saturating_sub(WINDOW), snapshot),
        };
        let mut ids: Vec<(u64, String)> = vec![];
        let mut i = start;
        while i < end {
            let p = self.page(on, list, i, (end - i).min(PAGE_MAX)).await?;
            if p.ids.is_empty() {
                break;
            }
            for id in p.ids {
                if !ids.iter().any(|(_, x)| *x == id) {
                    ids.push((i, id));
                }
                i += 1;
            }
        }
        let names: Vec<String> = ids.iter().map(|(_, x)| x.clone()).collect();
        let rows = self.entry_rows(on, &names, viewer, fold_at).await?;
        let mut rows: Vec<(u64, EntryRow)> = ids.into_iter().map(|(i, _)| i).zip(rows).collect();
        rank(&mut rows, sort);
        Ok(Ranked {
            rows,
            total: snapshot,
            whole: start == 0 && end == snapshot,
        })
    }
}

fn row_of(id: &str, r: &Value, fold_at: Option<u64>) -> Result<EntryRow, PqChatError> {
    let f = &at(r, "ref");
    let er = PqEntryRef {
        chain_uid: model::h(at(f, "chainUid"))?,
        pqchat: model::h(at(f, "pqchat"))?,
        entry_id: model::h(at(f, "entryId"))?,
        content_hash: model::h(at(f, "contentHash"))?,
    };
    let (up, down) = (big(at(r, "up"))?, big(at(r, "down"))?);
    let vote = at(r, "vote")
        .as_str()
        .and_then(|s| s.parse::<i8>().ok())
        .filter(|v| (-1..=1).contains(v))
        .ok_or_else(bad)?;
    Ok(EntryRow {
        id: id.to_ascii_lowercase(),
        topic_id: model::h(at(r, "topicId"))?,
        author: model::h(at(r, "author"))?,
        parent_id: model::h(at(r, "parentId"))?,
        depth: model::num(at(r, "depth"))?,
        entry_ref: (er != no_ref()).then_some(er),
        media_type: at(r, "mediaType").as_str().ok_or_else(bad)?.into(),
        sig_hash: model::h(at(r, "sigHash"))?,
        version_count: model::num(at(r, "versionCount"))?,
        posted_at: model::num(at(r, "postedAt"))?,
        edited_at: model::num(at(r, "editedAt"))?,
        nonce: model::num(at(r, "nonce"))?,
        body_length: model::num(at(r, "bodyLength"))?,
        up,
        down,
        vote,
        replies: model::num(at(r, "replies"))?,
        folded: fold_at.is_some_and(|t| down >= up.saturating_add(u128::from(t))),
    })
}

/// A `uint128` as the SDK's named JSON gives it (a decimal string).
fn big(v: &Value) -> Result<u128, PqChatError> {
    v.as_str().and_then(|s| s.parse().ok()).ok_or_else(bad)
}

/// `rows` (each with its list index) in `sort`'s order, highest first, ties by the lower index (F6). Integer arithmetic only
/// but Best's: `+ − × ÷ √` on `f64`, correctly rounded under IEEE 754 on every target, so every client orders alike.
pub fn rank(rows: &mut [(u64, EntryRow)], sort: Rank) {
    match sort {
        Rank::Top => rows.sort_by(|a, b| net(&b.1).cmp(&net(&a.1)).then(a.0.cmp(&b.0))),
        Rank::Controversial => rows.sort_by(|a, b| {
            controversy(&b.1)
                .cmp(&controversy(&a.1))
                .then(a.0.cmp(&b.0))
        }),
        Rank::Best => {
            rows.sort_by(|a, b| wilson(&b.1).total_cmp(&wilson(&a.1)).then(a.0.cmp(&b.0)))
        }
    }
}

/// `up − down` as an ordered pair: the sign (up ≥ down), then the magnitude, larger better when positive.
fn net(r: &EntryRow) -> (bool, i128) {
    match r.up >= r.down {
        true => (true, i128::try_from(r.up - r.down).unwrap_or(i128::MAX)),
        false => (false, -i128::try_from(r.down - r.up).unwrap_or(i128::MAX)),
    }
}

/// `(up + down)^(min / max)` as `log2` in Q32 fixed point: `min · log2(up + down) / max`, 0 when either is 0.
fn controversy(r: &EntryRow) -> u128 {
    let (lo, hi) = (r.up.min(r.down), r.up.max(r.down));
    if lo == 0 {
        return 0;
    }
    // ponytail: past 2^64 votes both sides lose their low bits alike (deterministic, the order kept to 2^-64)
    let shift = (128 - hi.leading_zeros()).saturating_sub(64);
    let l = log2_q32(r.up.saturating_add(r.down));
    l * (lo >> shift) / (hi >> shift)
}

/// `log2(n)` in Q32 (n ≥ 1), by repeated squaring of the mantissa: integer operations only.
fn log2_q32(n: u128) -> u128 {
    let ip = u128::from(127 - n.leading_zeros());
    let one: u128 = 1 << 63;
    let mut m = if ip >= 63 {
        n >> (ip - 63)
    } else {
        n << (63 - ip)
    };
    let mut frac = 0u128;
    for i in (0..32).rev() {
        m = (m * m) >> 63;
        if m >= 2 * one {
            m >>= 1;
            frac |= 1 << i;
        }
    }
    (ip << 32) | frac
}

/// The Wilson score interval's lower bound of `up / (up + down)` at z = 1.2816 (Reddit's `confidence`); 0 without votes.
fn wilson(r: &EntryRow) -> f64 {
    // the sum in f64: no saturation at the top of `u128`
    let (n, z) = (r.up as f64 + r.down as f64, 1.2816_f64);
    if n == 0.0 {
        return 0.0;
    }
    let p = r.up as f64 / n;
    let z2 = z * z;
    (p + z2 / (2.0 * n) - z * ((p * (1.0 - p) + z2 / (4.0 * n)) / n).sqrt()) / (1.0 + z2 / n)
}
