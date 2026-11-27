// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! PqChat's tree mode (`groupMode = 1`; CLI-PQC-17; spec 2026-11-23-pqchat-treekem §8, §10, §11, §15; plan T6a, T6b): the home's
//! views read through the port by `scaas-ua`'s names ([`PqChat::tree_view`]) and the registry's records through the SDK, the
//! creation in one transaction with one wrap per member key (owner 2026-11-25), a commit built and signed by `scaas-ua` and
//! sent in C37's order, the exits, and the replay from state alone with its checkpoint (the pin) kept in the store. The
//! state machine is here; every secret, record byte and tree rule is `scaas-ua`'s, every read and write the SDK's. A tree
//! session sends no receipt (R11) and nothing on its own after a failed open (C22). UNAUDITED.
use crate::model::{self, at};
use crate::reads::SessionRef;
use crate::session::Me;
use crate::{PqChat, PqChatError};
use scaas_sdk::app_core::{AppCall, AppCore, AppKey};
use scaas_sdk::op::KeyRef;
use scaas_sdk::pqchat_tree::{
    self as pt, PqCommitShape, PqTreeChanges, PqTreeCommitSigned, PqTreeGas, PqTreeLanded,
    PqTreeLeave, PqTreeNext, PqTreeReads, PqTreeRemove, PqTreeReplay, PqTreeStep,
};
use scaas_sdk::SdkError;
use serde_json::{json, Value};
use std::sync::Arc;

/// The most read-and-call rounds one tree call takes (each round reads every view the call missed).
// ponytail: a fixed bound; a session whose walk needs more rounds fails closed (`TreeReads`), raise it with a reason
const ROUNDS_MAX: usize = 4096;
/// The most times one tree call reads its views again after the head moved under it (D-18, C-8 of the T4-T9 review): an
/// endpoint whose `treeOf` keeps changing fails closed (`TreeReads`) instead of holding the call for every round.
const MOVED_MAX: usize = 3;
/// A page of `treeLeaves` (C36) and of `treeNodes` / `epochsOf` (`TREE_RANGE_MAX`).
const LEAF_PAGE: u64 = 64;
const RANGE_PAGE: u64 = 256;

/// The home's views a tree session reads (CLI-PQC-13: every one feeds a decryption or chooses a key or a recipient).
pub const TREE_READS: &[&str] = &[
    "IPqChat.epochCount",
    "IPqChat.epochSig",
    "IPqChat.epochsOf",
    "IPqChat.leaveAt",
    "IPqChat.leaveCount",
    "IPqChat.leaveSig",
    "IPqChat.removalAt",
    "IPqChat.removalCount",
    "IPqChat.removalSig",
    "IPqChat.sessionOf",
    "IPqChat.sessionSig",
    "IPqChat.wrapAt",
    "IPqChatTreeViews.commitOf",
    "IPqChatTreeViews.goneKeyOf",
    "IPqChatTreeViews.goneOf",
    "IPqChatTreeViews.goneOwnKeyOf",
    "IPqChatTreeViews.pathCtAt",
    "IPqChatTreeViews.pathKeys",
    "IPqChatTreeViews.pathListOf",
    "IPqChatTreeViews.treeLeaves",
    "IPqChatTreeViews.treeNodeKey",
    "IPqChatTreeViews.treeNodes",
    "IPqChatTreeViews.treeOf",
    "IPqChat.epochComplete",
    "IPqChat.sigStore",
    "IUARegistry.kemKeyAt",
    "IUARegistry.kemKeyOf",
    "IUARegistry.msigAt",
    "IUARegistry.msigStateOf",
    "IUARegistry.registrationOf",
];

/// A tree session to create: the creator and a few members (each at the KEM version it holds now), the admins, the info
/// (`sealedInfo`), the payer of the one transaction. More members come by commits of Adds (owner 2026-11-25).
pub struct CreateTree {
    pub me: Me,
    pub chain: String,
    pub home: String,
    pub nonce: u64,
    pub admins: Vec<String>,
    pub members: Vec<String>,
    pub info: crate::session::Info,
    pub payer: KeyRef,
    /// the session's `pathRefreshBound` (the path-less delta §3.1, R18): `None` the client default 20, 0 never forced
    pub path_refresh_bound: Option<u32>,
}

/// A created tree session: its ids, `K_0`'s handle and the prepared `createSession` with every wrap (one transaction).
pub struct TreeCreated {
    pub session_id: String,
    pub tree_id: String,
    #[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
    pub k: Arc<AppKey>,
    pub call: AppCall,
}

/// A commit to make (spec §8): Removes and Adds by leaf (`TreeRemove`, `TreeAdd` named JSON), the admins after it, and a
/// changed info (`None`: the info in force if the device holds it, else the marker).
#[derive(Clone)]
pub struct TreeCommit {
    pub me: Me,
    pub key_id: u64,
    pub removes: Vec<Value>,
    pub adds: Vec<Value>,
    pub admins: Vec<String>,
    pub info: Option<String>,
    /// the admin reviewed `info` as a new info after a gap (codex-r3-7): required when the device holds no info in force
    pub info_reviewed: bool,
    pub payer: KeyRef,
    /// "add and refresh" (the path-less delta §6.5): an Adds-only change built as a path commit; otherwise it goes
    /// path-less whenever the conditions of C46 hold
    pub refresh: bool,
}

/// A tree session as this device follows it: the replay's epochs and warnings, and whether the device can send.
pub struct TreeState {
    pub replay: Arc<PqTreeReplay>,
    /// the session (lowercase), and every epoch id at the replay by number (`epochsOf`)
    pub session_id: String,
    pub ids: Vec<String>,
    /// the head's number
    pub head: u64,
    /// no UA that is not gone holds a live leaf (C38): nothing more is written
    pub closed: bool,
    /// the head was not confirmed by a strict majority of at least 3 named endpoints (C26, CLI-PQC-17): a device with no
    /// verified tree keeps no pin then; the app shows the head "unconfirmed"
    pub unconfirmed: bool,
    /// the store's pin was a twin: a strict majority served the walk's record at its number, and it replaced the pin (C26,
    /// fable-r3-3); the app shows the event
    pub pin_replaced: bool,
}

/// A commit built and signed (spec §8), its plan, and whether a strict majority of at least 3 named endpoints confirmed the
/// head it was built on (R13; spec §11: an Add's review says so when it was not).
pub struct TreeBuilt {
    pub signed: PqTreeCommitSigned,
    pub plan: pt::PqTreePlan,
    pub head_confirmed: bool,
    /// the Adds left for the next commits when the request was split (owner 2026-11-27), in order; empty otherwise
    pub adds_left: Vec<Value>,
    /// the commit's review as signed (`scaas-ua`'s lines), and for a path commit the leaves under review (the path-less
    /// delta §6.2, F-3: listed, never removed by this client on its own)
    pub review: Vec<(String, String)>,
}

/// The commits a commit request becomes (owner 2026-11-27, [`PqChat::tree_commit_plan`]): the most Adds one commit takes
/// within the cap less the margin (`None` without rows, for a kind they do not name, or without Adds), the Adds of each commit
/// in order, and each commit's plan (its transactions with their gas).
pub struct TreeSplit {
    pub adds_per_commit: Option<u64>,
    pub batches: Vec<u64>,
    pub plans: Vec<pt::PqTreePlan>,
    /// a path-less build's other price (the path-less delta §6.5, §9): the same Adds as "add and refresh", a path commit,
    /// its plans; `None` for a path commit
    pub refresh: Option<Vec<pt::PqTreePlan>>,
    /// a path-less build's deferred cost (§6.4, D-10): the ciphertexts the next path commit carries for the leaves added
    /// without one, and what they ask ([`deferred_line`]); `None` for a path commit or without rows
    pub deferred: Option<(u64, pt::PqGas)>,
}

/// The review's line of a deferred cost (the path-less delta §6.4): "the next refresh carries about m ciphertexts, about
/// x M asked".
pub fn deferred_line(m: u64, g: pt::PqGas) -> String {
    format!(
        "the next refresh carries about {m} ciphertext{}, about {:.1} M asked",
        if m == 1 { "" } else { "s" },
        g.asked() as f64 / 1e6
    )
}

/// What a strict-majority read of `treeOf` said about the one a call read (R13, C26).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fresh {
    /// at least 3 named endpoints, and their majority serves the same `treeOf`, whole
    Confirmed,
    /// at least 3 named endpoints, and no majority serves it
    Disagrees,
    /// fewer than 3 named endpoints (or a port without the agreed read)
    Unavailable,
}

fn sdk(e: SdkError) -> PqChatError {
    PqChatError::from(e)
}

/// `f(args)` of a view name `f(a,b)`.
fn parse(name: &str) -> Result<(&str, Vec<&str>), PqChatError> {
    let (f, rest) = name.split_once('(').ok_or(PqChatError::Internal)?;
    let args = rest.strip_suffix(')').ok_or(PqChatError::Internal)?;
    Ok((
        f,
        if args.is_empty() {
            vec![]
        } else {
            args.split(',').collect()
        },
    ))
}

fn arg<'a>(a: &[&'a str], i: usize) -> Result<&'a str, PqChatError> {
    a.get(i).copied().ok_or(PqChatError::Internal)
}

/// The store key of a tree creation's signed record and wraps, kept until epoch 0 completes (codex-r3-5).
fn create_key(session_id: &str) -> String {
    format!("tree/create/{}", session_id.to_ascii_lowercase())
}

/// C10: Adds plus Removes per commit, and the leaves a head may owe (`scaas-ua`'s `TREE_CHANGES_MAX`).
const TREE_CHANGES_MAX: usize = 20;

/// C3: the tree mode is proposed from this many member keys where several members commit; a hint, never enforced.
pub const TREE_HINT_KEYS: usize = 7;

/// C3's size hint: whether to propose a tree session for `keys` member keys of which `committers` commit.
pub fn tree_advised(keys: usize, committers: usize) -> bool {
    keys >= TREE_HINT_KEYS && committers >= 2
}

/// The store key of this device's own path commit staged on a head (the path-less delta §6.5, F-5 by the owner's ruling of
/// 2026-11-27): `{epochId, parent}`; it holds back a path-less Add only while its parent is the head.
fn staged_key(session_id: &str) -> String {
    format!("tree/staged/{}", session_id.to_ascii_lowercase())
}

/// The store key of this device's path-less `try` counter on a head (C47): `{parent, next}`.
fn tries_key(session_id: &str) -> String {
    format!("tree/tries/{}", session_id.to_ascii_lowercase())
}

/// The store key of a tree session's checkpoint (C26), by its `treeId` (C16).
fn pin_key(tree_id: &str) -> String {
    format!("tree/pin/{}", tree_id.to_ascii_lowercase())
}

/// The store key of the head number a strict majority last confirmed (R2-D-3 of the T4-T9 re-check), by `treeId`.
fn confirmed_key(tree_id: &str) -> String {
    format!("tree/confirmed/{}", tree_id.to_ascii_lowercase())
}

impl PqChat {
    /// A view of `s`'s home by `scaas-ua`'s name, read through the port (trusted) and put in `reads` in the views' shape: a
    /// record with its kept signature (`sessionOf`, `commitOf`, `leaveAt`, `removalAt`), a page view whole (every page of
    /// `treeLeaves`, `treeNodes`, `epochsOf`), the others as the contract answers. Epochs by number through `epochsOf`.
    pub(crate) async fn tree_view(
        &self,
        s: &SessionRef,
        reads: &mut PqTreeReads,
        name: &str,
    ) -> Result<(), PqChatError> {
        let (f, a) = parse(name)?;
        let sid = s.session_id.to_ascii_lowercase();
        let v = match f {
            "sessionOf" => {
                let r = self
                    .home_read(s, "IPqChat.sessionOf", json!({ "sessionId": sid }))
                    .await?;
                let g = self
                    .home_read(s, "IPqChat.sessionSig", json!({ "sessionId": sid }))
                    .await?;
                json!({"record": at(&r, "s"), "sig": at(&g, "sig")})
            }
            "treeOf" => {
                self.home_read(s, "IPqChatTreeViews.treeOf", json!({ "sessionId": sid }))
                    .await?
            }
            "treeLeaves" => {
                let used = self.tree_of(s, reads, "used").await?;
                self.pages(
                    s,
                    "IPqChatTreeViews.treeLeaves",
                    used,
                    LEAF_PAGE,
                    "first",
                    "count",
                )
                .await?
            }
            "treeNodes" => {
                let leaves = self.tree_of(s, reads, "leaves").await?;
                let width = (2 * leaves).saturating_sub(1);
                self.pages(
                    s,
                    "IPqChatTreeViews.treeNodes",
                    width,
                    RANGE_PAGE,
                    "first",
                    "count",
                )
                .await?
            }
            "treeNodeKey" => {
                let r = self
                    .home_read(
                        s,
                        "IPqChatTreeViews.treeNodeKey",
                        json!({"sessionId": sid, "node": arg(&a, 0)?}),
                    )
                    .await?;
                at(&r, "0").clone()
            }
            "epochsOf" => {
                let n = model::num(at(
                    &self
                        .home_read(s, "IPqChat.epochCount", json!({ "sessionId": sid }))
                        .await?,
                    "0",
                ))?;
                self.pages(s, "IPqChat.epochsOf", n, RANGE_PAGE, "offset", "limit")
                    .await?
            }
            "commitOf" => {
                let id = self.epoch_at(s, reads, arg(&a, 0)?).await?;
                let r = self
                    .home_read(s, "IPqChatTreeViews.commitOf", json!({ "epochId": id }))
                    .await?;
                let g = self
                    .home_read(s, "IPqChat.epochSig", json!({ "epochId": id }))
                    .await?;
                json!({"record": at(&r, "c"), "sig": at(&g, "sig")})
            }
            "pathListOf" => {
                let id = self.epoch_at(s, reads, arg(&a, 0)?).await?;
                self.home_read(s, "IPqChatTreeViews.pathListOf", json!({ "epochId": id }))
                    .await?
            }
            "pathCtAt" => {
                let id = self.epoch_at(s, reads, arg(&a, 0)?).await?;
                let r = self
                    .home_read(
                        s,
                        "IPqChatTreeViews.pathCtAt",
                        json!({"epochId": id, "i": arg(&a, 1)?}),
                    )
                    .await?;
                at(&r, "0").clone()
            }
            "wrapAt" => {
                let id = self.epoch_at(s, reads, arg(&a, 0)?).await?;
                let r = self
                    .home_read(
                        s,
                        "IPqChat.wrapAt",
                        json!({"epochId": id, "i": arg(&a, 1)?}),
                    )
                    .await?;
                at(&r, "0").clone()
            }
            "goneOf" => {
                self.home_read(
                    s,
                    "IPqChatTreeViews.goneOf",
                    json!({"sessionId": sid, "ua": arg(&a, 0)?}),
                )
                .await?
            }
            "goneKeyOf" => {
                self.home_read(
                    s,
                    "IPqChatTreeViews.goneKeyOf",
                    json!({"sessionId": sid, "kemHash": arg(&a, 0)?}),
                )
                .await?
            }
            "goneOwnKeyOf" => {
                self.home_read(
                    s,
                    "IPqChatTreeViews.goneOwnKeyOf",
                    json!({"sessionId": sid, "ua": arg(&a, 0)?, "kemHash": arg(&a, 1)?}),
                )
                .await?
            }
            "leaveCount" | "removalCount" => {
                let id = self.epoch_at(s, reads, arg(&a, 0)?).await?;
                let item = if f == "leaveCount" {
                    "IPqChat.leaveCount"
                } else {
                    "IPqChat.removalCount"
                };
                at(
                    &self.home_read(s, item, json!({ "epochId": id })).await?,
                    "0",
                )
                .clone()
            }
            "leaveAt" | "removalAt" => {
                let id = self.epoch_at(s, reads, arg(&a, 0)?).await?;
                let args = json!({"epochId": id, "index": arg(&a, 1)?});
                let (rec, sig, k) = if f == "leaveAt" {
                    ("IPqChat.leaveAt", "IPqChat.leaveSig", "l")
                } else {
                    ("IPqChat.removalAt", "IPqChat.removalSig", "r")
                };
                let r = self.home_read(s, rec, args.clone()).await?;
                let g = self.home_read(s, sig, args).await?;
                json!({"record": at(&r, k), "sig": at(&g, "sig")})
            }
            _ => return Err(PqChatError::Internal),
        };
        reads.views.insert(name.to_string(), v);
        Ok(())
    }

    /// One trusted read of `s`'s home.
    async fn home_read(
        &self,
        s: &SessionRef,
        item: &'static str,
        args: Value,
    ) -> Result<Value, PqChatError> {
        self.net.read(&s.chain, &s.home, item, args).await
    }

    /// `treeOf`'s field `k` (the view read first when missing).
    async fn tree_of(
        &self,
        s: &SessionRef,
        reads: &mut PqTreeReads,
        k: &str,
    ) -> Result<u64, PqChatError> {
        if !reads.views.contains_key("treeOf()") {
            Box::pin(self.tree_view(s, reads, "treeOf()")).await?;
        }
        model::num(at(reads.views.get("treeOf()").unwrap_or(&Value::Null), k))
    }

    /// Epoch `n`'s id: `epochsOf` at `n` (the view read first when missing).
    async fn epoch_at(
        &self,
        s: &SessionRef,
        reads: &mut PqTreeReads,
        n: &str,
    ) -> Result<String, PqChatError> {
        if !reads.views.contains_key("epochsOf()") {
            Box::pin(self.tree_view(s, reads, "epochsOf()")).await?;
        }
        let i: usize = n.parse().map_err(|_| PqChatError::Internal)?;
        reads
            .views
            .get("epochsOf()")
            .and_then(Value::as_array)
            .and_then(|v| v.get(i))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or(PqChatError::Internal)
    }

    /// A page view read whole: `total` entries in pages of `page`.
    async fn pages(
        &self,
        s: &SessionRef,
        item: &'static str,
        total: u64,
        page: u64,
        first: &str,
        count: &str,
    ) -> Result<Value, PqChatError> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < total {
            let mut args = serde_json::Map::new();
            args.insert("sessionId".into(), json!(s.session_id.to_ascii_lowercase()));
            args.insert(first.into(), json!(i.to_string()));
            args.insert(count.into(), json!(page.min(total - i).to_string()));
            let args = Value::Object(args);
            let r = self.home_read(s, item, args).await?;
            let got = at(&r, "0").as_array().cloned().unwrap_or_default();
            if got.is_empty() {
                return Err(PqChatError::Internal);
            }
            i += got.len() as u64;
            out.extend(got);
        }
        Ok(Value::Array(out))
    }

    /// `f` over `reads` until it misses no read: each missing home view through the port, each registry record through the
    /// SDK, at most [`ROUNDS_MAX`] rounds; the epochs' records and exits scheduled from public data from epoch `start` (the
    /// walk's first: the pin's when it starts there, C-8). fable-r3-9: the views are one state of the home: before each call
    /// after a read, `treeOf` read again is the one read first, else every read is dropped and made again (the head moved
    /// while they were read), at most [`MOVED_MAX`] times; so `f` never runs on a mixed snapshot, and a call that consumes
    /// its input (a resumed replay moves the node keys it holds, D-6) is never made and then thrown away.
    pub(crate) async fn tree_run<T>(
        &self,
        s: &SessionRef,
        reads: &mut PqTreeReads,
        start: u64,
        mut f: impl FnMut(&PqTreeReads) -> Result<PqTreeStep<T>, SdkError>,
    ) -> Result<T, PqChatError> {
        let mut prefetched = false;
        let mut fresh = true;
        let mut moved = 0;
        for _ in 0..ROUNDS_MAX {
            // the reads every walk makes per epoch, scheduled from public data (the epoch list and the exit counts) once the
            // list is known, so a long session takes a few rounds, not one per view
            if !prefetched && reads.views.contains_key("epochsOf()") {
                prefetched = true;
                self.tree_prefetch(s, reads, start).await?;
                fresh = false;
            }
            if !fresh {
                fresh = true;
                if let Some(first) = reads.views.get("treeOf()").cloned() {
                    let again = self
                        .home_read(
                            s,
                            "IPqChatTreeViews.treeOf",
                            json!({ "sessionId": s.session_id.to_ascii_lowercase() }),
                        )
                        .await?;
                    if !same_head(&first, &again) {
                        moved += 1;
                        if moved > MOVED_MAX {
                            return Err(PqChatError::TreeReads);
                        }
                        *reads = PqTreeReads::default();
                        reads.views.insert("treeOf()".into(), again);
                        prefetched = false;
                        continue;
                    }
                }
            }
            match f(reads).map_err(sdk)? {
                PqTreeStep::Done(v) => return Ok(v),
                PqTreeStep::Need(names) => {
                    for n in &names {
                        match pt::registry_name(n) {
                            Some((f, ua, k)) => {
                                self.registry_view(s, reads, f, &model::hex(&ua), k, n)
                                    .await?
                            }
                            None => self.tree_view(s, reads, n).await?,
                        }
                    }
                    fresh = false;
                }
            }
        }
        Err(PqChatError::TreeReads)
    }

    /// Every epoch's record and exit counts from epoch `start`, then each exit, as one walk reads them (public data only,
    /// C22).
    async fn tree_prefetch(
        &self,
        s: &SessionRef,
        reads: &mut PqTreeReads,
        start: u64,
    ) -> Result<(), PqChatError> {
        let n = reads
            .views
            .get("epochsOf()")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        for e in (start as usize).min(n)..n {
            let mut names = vec![format!("leaveCount({e})"), format!("removalCount({e})")];
            if e > 0 {
                names.push(format!("commitOf({e})"));
            }
            for name in names {
                if !reads.views.contains_key(&name) {
                    self.tree_view(s, reads, &name).await?;
                }
            }
            for (count, at_) in [("leaveCount", "leaveAt"), ("removalCount", "removalAt")] {
                let k = reads
                    .views
                    .get(&format!("{count}({e})"))
                    .and_then(|v| model::num(v).ok())
                    .unwrap_or(0);
                for i in 0..k {
                    let name = format!("{at_}({e},{i})");
                    if !reads.views.contains_key(&name) {
                        self.tree_view(s, reads, &name).await?;
                    }
                }
            }
        }
        Ok(())
    }

    /// R13, C26: `treeOf` read by a strict majority of the chain's named endpoints at the final block compared with `seen`,
    /// whole (the head, the tree hash, `owed`: an exit the endpoint hides changes `owed`, D-3).
    async fn majority_tree(&self, s: &SessionRef, seen: &Value) -> Fresh {
        let args = json!({ "sessionId": s.session_id.to_ascii_lowercase() });
        match self
            .net
            .read_majority(&s.chain, &s.home, "IPqChatTreeViews.treeOf", args)
            .await
        {
            Ok((v, named)) if named >= 3 && v == *seen => Fresh::Confirmed,
            Ok((_, named)) if named >= 3 => Fresh::Disagrees,
            Ok(_) => Fresh::Unavailable,
            Err(e) if matches!(e.code(), "AgreementNeedsThree" | "TreeInfoUnconfirmed") => {
                Fresh::Unavailable
            }
            Err(_) => Fresh::Disagrees,
        }
    }

    /// A registry record a tree call missed, read through the port at the chain's registry (trusted) and put in `reads` by
    /// the SDK's converters: a KEM key with its kept signature, a UA's registration, an `msig`'s accepted slots and its
    /// structure at a version (codex-1, CTR-UA-74).
    async fn registry_view(
        &self,
        s: &SessionRef,
        reads: &mut PqTreeReads,
        f: &str,
        ua: &str,
        k: u64,
        name: &str,
    ) -> Result<(), PqChatError> {
        let reg = self.conf(&s.chain)?.registry.clone();
        let rd = |item: &'static str, args: Value| self.net.read(&s.chain, &reg, item, args);
        match f {
            "kemKeyAt" => {
                let v = rd(
                    "IUARegistry.kemKeyAt",
                    json!({"ua": ua, "version": k.to_string()}),
                )
                .await?;
                reads.put_kem_key_at(name, &v).map_err(sdk)
            }
            "registrationOf" => {
                let v = rd("IUARegistry.registrationOf", json!({ "ua": ua })).await?;
                reads.put_registration(ua, &v).map_err(sdk)
            }
            "msigStateOf" => {
                let v = rd("IUARegistry.msigStateOf", json!({ "ua": ua })).await?;
                reads.put_msig_state(ua, &v).map_err(sdk)
            }
            _ => {
                let v = rd(
                    "IUARegistry.msigAt",
                    json!({"ua": ua, "version": k.to_string()}),
                )
                .await?;
                reads.put_msig_at(ua, k, &v).map_err(sdk)
            }
        }
    }

    /// A tree session created small (owner 2026-11-25): the creator and a few members, each member key wrapped, the session
    /// record and **every wrap in one transaction** (`wraps.length == members.length`). The member count is capped by the
    /// chain's limits from the chain's gas rows ([`pt::create_cap`]) and confirmed by the quote; over it `TreeTooLarge`, nothing
    /// signed. More members come by commits of Adds with their Welcome wraps. A `none` home is refused (C1, `TreeHomeNone`).
    pub async fn create_tree(&self, r: CreateTree) -> Result<TreeCreated, PqChatError> {
        let me = r.me.ua.to_ascii_lowercase();
        crate::session::check_stores(&r.info)?;
        self.require_listed(&r.chain, &r.home).await?;
        // C-12: only a home whose setting is not `sstore2` (or moved from it, C27) is `TreeHomeNone`; a read that failed is not
        match self.sig_store(&r.chain, &r.home).await {
            Ok(crate::signed::SIG_SSTORE2) => {}
            Ok(_) | Err(crate::drops::DropReason::Control) => {
                return Err(PqChatError::TreeHomeNone)
            }
            Err(_) => return Err(PqChatError::Internal),
        }
        let mut uas: Vec<String> = r.members.iter().map(|m| m.to_ascii_lowercase()).collect();
        if !uas.contains(&me) {
            uas.push(me.clone());
        }
        let mut admins: Vec<String> = r.admins.iter().map(|m| m.to_ascii_lowercase()).collect();
        if !admins.contains(&me) {
            admins.push(me.clone());
        }
        admins.sort();
        admins.dedup();
        let mut members = Vec::new();
        for (ua, via) in self.expand(&r.chain, &uas).await? {
            let (v, _) = self.kem_version(&r.chain, &ua).await?;
            members.push(json!({"ua": ua, "keyId": v, "via": via}));
        }
        let c = self.conf(&r.chain)?.clone();
        let kind = self.signer_kind(&r.me)?;
        if let Some(g) = c.tree_gas.as_deref() {
            let g: PqTreeGas = serde_json::from_str(g).map_err(|_| PqChatError::Internal)?;
            // C-7: a kind the rows do not name is held to the quote alone, as without rows
            if g.kinds.contains_key(&kind) {
                let l = self.app.pqchat_tree_limits(&r.chain).await.map_err(sdk)?;
                if members.len() as u64 > pt::create_cap(&g, l, &kind, admins.len() as u64) {
                    return Err(PqChatError::TreeTooLarge);
                }
            }
        }
        let mut session = json!({"creator": me, "nonce": r.nonce, "homeChain": c.chain_uid,
            "homeChatContract": r.home.to_ascii_lowercase(), "admins": admins, "members": members, "groupMode": 1});
        if let (Some(b), Some(o)) = (r.path_refresh_bound, session.as_object_mut()) {
            o.insert("pathRefreshBound".into(), json!(b));
        }
        let info = serde_json::to_string(&r.info).map_err(|_| PqChatError::Internal)?;
        let sref = SessionRef {
            chain: r.chain.clone(),
            home: r.home.to_ascii_lowercase(),
            session_id: String::new(),
        };
        let mut reads = PqTreeReads::default();
        let key = r.me.key.clone();
        let g = self
            .tree_run(&sref, &mut reads, 0, |rd| {
                self.app
                    .pqchat_tree_genesis(key.clone(), session.clone(), rd, info.clone())
            })
            .await?;
        let signed = self
            .app
            .prepare_pqchat_tree_session(r.me.key.clone(), g.record.clone())
            .await
            .map_err(sdk)?
            .sign()
            .await
            .map_err(sdk)?;
        let sig = crate::session::sig_json(&signed.sig);
        let args = json!({"s": strings(&g.record), "wraps": strings(&json!(g.wraps)), "sig": sig});
        // codex-r3-5: the signed record and every wrap kept before anything leaves, until the session is complete at home;
        // C-12: a call that cannot be prepared (over the cap, or refused) drops what it kept, nothing has left the device
        let kept = create_key(&g.session_id);
        crate::store::Items(&*self.store).update::<Value, _>(&kept, |_| Ok(args.clone()))?;
        let call = match self
            .net
            .prepare(
                &r.chain,
                &sref.home,
                "IPqChat.createSession",
                args,
                &r.payer,
            )
            .await
        {
            Ok(c) => c,
            Err(e) => {
                crate::store::Items(&*self.store).update::<Value, _>(&kept, |_| Ok(Value::Null))?;
                return Err(match e.code() {
                    "GasAboveTxCap" => PqChatError::TreeTooLarge,
                    _ => e,
                });
            }
        };
        self.set_consent(
            &SessionRef {
                session_id: g.session_id.clone(),
                ..sref
            },
            crate::consent::Consent::Accepted,
            true,
        )?;
        Ok(TreeCreated {
            session_id: g.session_id,
            tree_id: g.tree_id,
            k: g.k,
            call,
        })
    }

    /// A tree creation after a restart (codex-r3-5): complete at home, its kept record dropped and `None`; else the kept
    /// `createSession` prepared again (the same signed record and wraps); with no kept record on an incomplete creation
    /// `TreeCreationIncomplete`: nothing is sent, the app offers a new session.
    pub async fn tree_resume_create(
        &self,
        s: &SessionRef,
        payer: &KeyRef,
    ) -> Result<Option<AppCall>, PqChatError> {
        let sid = s.session_id.to_ascii_lowercase();
        let done = self
            .home_read(s, "IPqChat.epochComplete", json!({ "epochId": sid }))
            .await?;
        let key = create_key(&sid);
        if at(&done, "0") == true {
            crate::store::Items(&*self.store).update::<Value, _>(&key, |_| Ok(Value::Null))?;
            return Ok(None);
        }
        let kept: Option<Value> = crate::store::Items(&*self.store).get(&key)?;
        let args = kept
            .filter(|v| !v.is_null())
            .ok_or(PqChatError::TreeCreationIncomplete)?;
        Ok(Some(
            self.net
                .prepare(&s.chain, &s.home, "IPqChat.createSession", args, payer)
                .await?,
        ))
    }

    /// The signer kind's name in the gas rows (`scaas-ua`'s kind names, [`pt::signer_name`]: `mldsa65` for 0x0131, `mldsa87`
    /// for 0x0134; B-5 = C-7 of the T4-T9 review: one naming for the SDK and the crate).
    fn signer_kind(&self, me: &Me) -> Result<String, PqChatError> {
        match &me.key {
            KeyRef::Ua { kind, .. } => Ok(pt::signer_name(*kind)
                .map(str::to_string)
                .unwrap_or_else(|| format!("{kind:#06x}"))),
            _ => Err(PqChatError::MsigAuthorPlanned),
        }
    }

    /// The device's replay of `s` (spec §10) by `me`'s key `key_id`: resumed from `from`, the device's previous replay (only
    /// the epochs after its pin), else walked from the cold tree with the store's pin compared; every read scheduled from
    /// public data; `K` handles for every followed epoch the walk opens (R2-C-1 of the T4-T9 re-check: a restart keeps the
    /// history below the pin readable). C26 (the T4-T9 review's D-2, C-5, D-5): a pin the store holds moves to the verified
    /// head on success, never down: a `from` whose pin is below the store's is refused (`TreeCheckpoint`, R2-C-2), and a
    /// `from` an earlier resume consumed too (`TreePeriod`); `from`'s node keys move into the new state only after the pin is
    /// stored (a store error returns it, `from` whole: R2-D-5). A device with no pin writes its first one only when a strict
    /// majority of at least 3 named endpoints serves the head it walked to; the state is `unconfirmed` until such a read of
    /// its head agreed (R2-D-3), and nothing is pinned before; a conflict at the pinned number (the store's, or `from`'s on a
    /// resume: R2-C-6) is settled by the majority's record there (the pin replaced, `pin_replaced`; a resume then walks from
    /// the cold tree), else `TreeConflict` ("conflicting head"). Neither the reads nor the pin depend on any opening
    /// (ARCH-POS-13). A key in no period of the session: `NotMember`.
    pub async fn tree_state(
        &self,
        s: &SessionRef,
        me: &Me,
        key_id: u64,
        from: Option<&PqTreeReplay>,
    ) -> Result<TreeState, PqChatError> {
        let key = me.key.clone();
        self.tree_state_by(s, from, |app, rd, pin, resume| match (from, resume) {
            (Some(f), true) => app.pqchat_tree_resume(key.clone(), key_id, rd, pin, f, 0),
            _ => app.pqchat_tree_replay(key.clone(), key_id, rd, pin, 0),
        })
        .await
    }

    /// Test-only (feature `vectors`): [`PqChat::tree_state`] of a vector device's KEM key (`kemSeed`), `K` in `seed`'s arena.
    #[cfg(feature = "vectors")]
    pub async fn tree_state_vectors(
        &self,
        s: &SessionRef,
        seed: &str,
        kem_seed: &[u8],
        ua: &str,
        key_id: u64,
        from: Option<&PqTreeReplay>,
    ) -> Result<TreeState, PqChatError> {
        self.tree_state_by(s, from, |app, rd, pin, resume| {
            let from = from.filter(|_| resume);
            app.pqchat_tree_vectors_replay(seed, kem_seed, ua, key_id, rd, pin, from, 0)
        })
        .await
    }

    /// `f(app, reads, pin, resume)`: the replay, resumed from `from` when `resume`, else from the cold tree against `pin`.
    async fn tree_state_by(
        &self,
        s: &SessionRef,
        from: Option<&PqTreeReplay>,
        mut f: impl FnMut(
            &AppCore,
            &PqTreeReads,
            Option<&Value>,
            bool,
        ) -> Result<PqTreeStep<Option<Arc<PqTreeReplay>>>, SdkError>,
    ) -> Result<TreeState, PqChatError> {
        let epoch_of = |p: Option<&Value>| p.and_then(|p| p.get("epoch")).and_then(Value::as_u64);
        let mut reads = PqTreeReads::default();
        self.tree_view(s, &mut reads, "treeOf()").await?;
        let t = reads.views.get("treeOf()").cloned().unwrap_or_default();
        let tree_id = model::h(at(&t, "treeId"))?;
        let items = crate::store::Items(&*self.store);
        let mut pin: Option<Value> = items
            .get::<Value>(&pin_key(&tree_id))?
            .filter(|p| !p.is_null());
        let app = self.app.clone();
        let mut resume = from.is_some();
        let mut replaced = false;
        let r = loop {
            let start = if resume {
                epoch_of(from.map(|f| &f.pin))
            } else {
                None
            };
            let run = self
                .tree_run(s, &mut reads, start.unwrap_or(0), |rd| {
                    f(&app, rd, pin.as_ref(), resume)
                })
                .await;
            match run {
                Err(e) if e.code() == "TreeConflict" && !replaced => {
                    // C26: settled by the majority's record at the pinned number (the store's, or the resumed replay's),
                    // else "conflicting head"
                    let at_pin = if resume {
                        from.map(|f| &f.pin)
                    } else {
                        pin.as_ref()
                    };
                    let twin = match at_pin {
                        Some(p) => self.pin_is_twin(s, &reads, p).await,
                        None => false,
                    };
                    if !twin {
                        return Err(e);
                    }
                    if !resume || pin.as_ref() == at_pin {
                        items.update::<Value, _>(&pin_key(&tree_id), |_| Ok(Value::Null))?;
                        items.update::<Value, _>(&confirmed_key(&tree_id), |_| Ok(Value::Null))?;
                        pin = None;
                    }
                    (resume, replaced) = (false, true);
                    reads = PqTreeReads::default();
                    self.tree_view(s, &mut reads, "treeOf()").await?;
                }
                r => break r?.ok_or(PqChatError::NotMember)?,
            }
        };
        let ids: Vec<String> = reads
            .views
            .get("epochsOf()")
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_ascii_lowercase()))
                    .collect()
            })
            .unwrap_or_default();
        let head = ids.len().saturating_sub(1) as u64;
        // ARCH-POS-13: the majority read is made until a majority confirmed the head (R2-D-3), public facts only
        let confirmed: Option<u64> = items
            .get::<Value>(&confirmed_key(&tree_id))?
            .and_then(|v| v.as_u64());
        let asked = confirmed.is_none_or(|c| head > c);
        let seen = reads.views.get("treeOf()").cloned().unwrap_or_default();
        let unconfirmed = asked && self.majority_tree(s, &seen).await != Fresh::Confirmed;
        // the confirmation first: a pin write that fails after it leaves a confirmed head, which a later poll pins
        if asked && !unconfirmed {
            items.update::<Value, _>(&confirmed_key(&tree_id), |_| Ok(json!(head)))?;
        }
        if pin.is_some() || !unconfirmed {
            items.update::<Value, _>(&pin_key(&tree_id), |_| Ok(r.pin.clone()))?;
        }
        // every step that can fail is behind: `from`'s node keys move into the new state (D-5, U-a)
        if let (Some(f), true) = (from, resume) {
            r.adopt(f);
        }
        Ok(TreeState {
            closed: closed_of(&r.pin),
            session_id: s.session_id.to_ascii_lowercase(),
            ids,
            replay: r,
            head,
            unconfirmed,
            pin_replaced: replaced,
        })
    }

    /// C26: whether a strict majority of at least 3 named endpoints serves, at the pinned number, the id and the record the
    /// walk read there (then the pin is the twin: it goes); anything else keeps it.
    async fn pin_is_twin(&self, s: &SessionRef, reads: &PqTreeReads, pin: &Value) -> bool {
        let Some(n) = pin.get("epoch").and_then(Value::as_u64).filter(|n| *n > 0) else {
            return false;
        };
        let served_id = reads
            .views
            .get("epochsOf()")
            .and_then(Value::as_array)
            .and_then(|v| v.get(n as usize))
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase);
        let served = reads
            .views
            .get(&format!("commitOf({n})"))
            .map(|v| v["record"].clone());
        let (Some(id), Some(served)) = (served_id, served) else {
            return false;
        };
        let sid = s.session_id.to_ascii_lowercase();
        let ids = self
            .net
            .read_majority(
                &s.chain,
                &s.home,
                "IPqChat.epochsOf",
                json!({"sessionId": sid, "offset": n.to_string(), "limit": "1"}),
            )
            .await;
        let Ok((v, named)) = ids else { return false };
        if named < 3
            || at(&v, "0")
                .get(0)
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase)
                != Some(id.clone())
        {
            return false;
        }
        match self
            .net
            .read_majority(
                &s.chain,
                &s.home,
                "IPqChatTreeViews.commitOf",
                json!({ "epochId": id }),
            )
            .await
        {
            Ok((v, named)) => named >= 3 && *at(&v, "c") == served,
            Err(_) => false,
        }
    }

    /// Epoch `epoch_id` of a followed tree session opened for messages (the mode branch at "obtain `K`", CLI-PQC-17): its
    /// `K` from the replay (`followed` only; else `EpochIncomplete`, nothing sent), its members the roster's UAs, its author
    /// and admins its record's, its parent the epoch before it. The crate keeps it as a tree epoch (C-3, D-7, D-8 of the T4-T9 review): its info is the info in
    /// force there from the replay (none held, or held flagged: `TreeInfoMissing` when the app sends), a send under it that
    /// meets a later epoch at home asks for a replay (`EpochTaken`), and no receipt leaves it unless the user turned them on
    /// (R11). A state of another session: `SessionUnknown`.
    pub fn tree_open(
        &self,
        s: &SessionRef,
        st: &TreeState,
        epoch_id: &str,
    ) -> Result<crate::message::OpenEpoch, PqChatError> {
        let id = epoch_id.to_ascii_lowercase();
        if st.session_id != s.session_id.to_ascii_lowercase() {
            return Err(PqChatError::SessionUnknown);
        }
        let e = st
            .replay
            .epochs
            .iter()
            .find(|e| e.epoch_id == id)
            .ok_or(PqChatError::SessionUnknown)?;
        let k = match (&e.k, e.state.as_str()) {
            (Some(k), "followed") => k.clone(),
            _ => return Err(PqChatError::EpochIncomplete),
        };
        let mut members: Vec<model::Member> = Vec::new();
        for (ua, key_id) in st
            .replay
            .rosters
            .get(&e.epoch)
            .into_iter()
            .flatten()
            .flatten()
        {
            if !members.iter().any(|m| m.ua == *ua) {
                members.push(model::Member {
                    ua: ua.clone(),
                    key_id: *key_id,
                    via: model::ZERO32.into(),
                });
            }
        }
        members.sort_by(|a, b| a.ua.cmp(&b.ua));
        let info = match (&e.in_force, e.flagged) {
            (Some(i), false) => Some(Arc::new(
                scaas_sdk::SecretBytes::from_zeroizing(zeroize::Zeroizing::new(
                    i.as_bytes().to_vec(),
                ))
                .map_err(|_| PqChatError::Internal)?,
            )),
            _ => None,
        };
        self.tree_epochs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id.clone(), info);
        let parent = match e.epoch {
            0 => model::ZERO32.to_string(),
            n => st
                .ids
                .get(n as usize - 1)
                .cloned()
                .ok_or(PqChatError::Internal)?,
        };
        Ok(crate::message::OpenEpoch {
            chain: s.chain.clone(),
            epoch: model::Epoch {
                id,
                session_id: s.session_id.to_ascii_lowercase(),
                // R2-C-3 of the T4-T9 re-check: the room's sync and `StoresChanged` act on the record's author and admins
                author: e.author.to_ascii_lowercase(),
                nonce: 0,
                epoch: e.epoch,
                parent,
                admins: e.admins.iter().map(|a| a.to_ascii_lowercase()).collect(),
                members,
                wrap_hashes: vec![],
                sealed_info: vec![],
                sig_hash: String::new(),
            },
            k,
        })
    }

    /// Whether `epoch_id` was opened by [`PqChat::tree_open`], and the info in force there it holds.
    pub(crate) fn tree_epoch(&self, epoch_id: &str) -> Option<Option<Arc<scaas_sdk::SecretBytes>>> {
        self.tree_epochs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(epoch_id)
            .cloned()
    }

    /// A commit by `c.me` on the head of `st` (spec §8): built and signed by `scaas-ua` on the tree the forward walk verified
    /// from the store's pin, then planned in C37's order on the chain's limits. Refused before anything is built: a head that
    /// moved since `st` (`TreeStale`, C33: the info `st` holds is the one in force at its head only; D-10); a changed info
    /// without a strict majority of at least 3 named endpoints serving the `treeOf` it reads, whole (`TreeInfoUnconfirmed`,
    /// R13; C-2 = D-1, D-3); an Add whose majority serves another state (the same name), or, with fewer than 3 named
    /// endpoints, built with `head_confirmed` false for its review (spec §11). Adds over one commit (owner 2026-11-27,
    /// [`PqChat::tree_commit_plan`]): this commit holds the first batch (with the Removes, admins and info), the rest is
    /// `adds_left` for the next commit on the head this one makes, in order. A commit that cannot hold even one Add, or a
    /// required piece that does not fit, refuses the operation (`TreeTooLarge`), nothing signed.
    pub async fn tree_commit(
        &self,
        s: &SessionRef,
        st: &TreeState,
        c: TreeCommit,
        leaf: u32,
    ) -> Result<TreeBuilt, PqChatError> {
        let (mut prepared, mut head_confirmed) = self.tree_built(s, st, &c, &c.adds, leaf).await?;
        let mut split = self
            .tree_split(s, &c.me, &shape_of(&prepared.record))
            .await?;
        let first = split.batches.first().copied().unwrap_or(0) as usize;
        let (head, left) = c.adds.split_at(first.min(c.adds.len()));
        if split.batches.len() > 1 {
            (prepared, head_confirmed) = self.tree_built(s, st, &c, head, leaf).await?;
            split = self
                .tree_split(s, &c.me, &shape_of(&prepared.record))
                .await?;
        }
        let plan = split.plans.first().cloned().unwrap_or_else(one_tx);
        let mut review = prepared.review.clone();
        let pathless = prepared.record.get("pathless") == Some(&json!(true));
        if !pathless && !st.replay.review.is_empty() {
            let l: Vec<String> = st.replay.review.iter().map(u32::to_string).collect();
            review.push((
                "leavesUnderReview".into(),
                format!("leaves under review (a warning or an author that did not hold the epoch names them): {}", l.join(", ")),
            ));
        }
        let signed = prepared.sign().map_err(sdk)?;
        if pathless {
            // C47: the next path-less build on this head takes the next `try`
            let parent = signed
                .record
                .get("parentEpochId")
                .cloned()
                .unwrap_or_default();
            let next = self.next_try(st)?.saturating_add(1);
            crate::store::Items(&*self.store)
                .update::<Value, _>(&tries_key(&st.session_id), |_| {
                    Ok(json!({"parent": parent, "next": next}))
                })?;
        }
        // F-5 (owner 2026-11-27): this device's own path commit sent in several transactions holds its path-less Adds back
        // while it is staged on this head
        if signed.record.get("pathless") == Some(&json!(false)) && plan.txs.len() > 1 {
            let parent = signed
                .record
                .get("parentEpochId")
                .cloned()
                .unwrap_or_default();
            let v = json!({"epochId": signed.epoch_id, "parent": parent});
            crate::store::Items(&*self.store)
                .update::<Value, _>(&staged_key(&st.session_id), |_| Ok(v.clone()))?;
        }
        Ok(TreeBuilt {
            signed,
            plan,
            head_confirmed,
            adds_left: left.to_vec(),
            review,
        })
    }

    /// Before anything is signed (owner 2026-11-27): the commits a request becomes, built on the head of `st` as
    /// [`PqChat::tree_commit`] builds it (nothing signed or sent): the most Adds one commit takes within the chain's cap less
    /// the SDK's margin ([`pt::adds_per_commit`]: what the app suggests, "at most N Adds per transaction"), the Adds of each
    /// commit in their order, and each commit's plan, its transactions with their gas (the first from the built commit, the
    /// others on its shape with their Adds), for the app to show their count and fees. Each commit is an ordinary one (C37,
    /// its own epoch); the app makes them one after the other and stops at the first refusal, the epochs landed before it
    /// kept. The same refusals as `tree_commit`.
    pub async fn tree_commit_plan(
        &self,
        s: &SessionRef,
        st: &TreeState,
        c: &TreeCommit,
        leaf: u32,
    ) -> Result<TreeSplit, PqChatError> {
        let (prepared, _) = self.tree_built(s, st, c, &c.adds, leaf).await?;
        let shape = shape_of(&prepared.record);
        let mut split = self.tree_split(s, &c.me, &shape).await?;
        if prepared.record.get("pathless") == Some(&json!(true)) {
            // the path-less delta §6.5, §9: the quote names both prices, this one and "add and refresh"'s
            let refresh = TreeCommit {
                refresh: true,
                ..c.clone()
            };
            let (path, _) = self.tree_built(s, st, &refresh, &c.adds, leaf).await?;
            split.refresh = Some(
                self.tree_split(s, &c.me, &shape_of(&path.record))
                    .await?
                    .plans,
            );
            split.deferred = self.tree_deferred(s, st, shape.adds)?;
        }
        Ok(split)
    }

    /// The deferred cost on the head of `st` with `adds` more path-less leaves (the path-less delta §6.4, D-10): about one
    /// ciphertext per leaf added since the last path commit, from the chain's rows; `None` without rows. The admins' warning
    /// shows it with `adds` 0.
    // ponytail: `sincePath` plus the Adds only, a lower bound; the warm nodes the Adds blanked (up to d - 2 more, §9) are
    // not counted until the walk exposes them
    pub fn tree_deferred(
        &self,
        s: &SessionRef,
        st: &TreeState,
        adds: u64,
    ) -> Result<Option<(u64, pt::PqGas)>, PqChatError> {
        let Some(g) = self.conf(&s.chain)?.tree_gas.as_deref() else {
            return Ok(None);
        };
        let g: PqTreeGas = serde_json::from_str(g).map_err(|_| PqChatError::Internal)?;
        let m = u64::from(st.replay.since_path) + adds;
        Ok(Some((m, pt::deferred_cost(&g, m))))
    }

    /// The split of a built commit's shape on the chain's rows (one commit, one transaction, without rows or for a kind
    /// the rows do not name, C-7).
    async fn tree_split(
        &self,
        s: &SessionRef,
        me: &Me,
        shape: &PqCommitShape,
    ) -> Result<TreeSplit, PqChatError> {
        let one = || TreeSplit {
            adds_per_commit: None,
            batches: vec![shape.adds],
            plans: vec![one_tx()],
            refresh: None,
            deferred: None,
        };
        let Some(g) = self.conf(&s.chain)?.tree_gas.as_deref() else {
            return Ok(one());
        };
        let g: PqTreeGas = serde_json::from_str(g).map_err(|_| PqChatError::Internal)?;
        let l = self.app.pqchat_tree_limits(&s.chain).await.map_err(sdk)?;
        let kind = self.signer_kind(me)?;
        // C-7: a kind the rows do not name is held to the quote alone, as without rows
        let unnamed = |r: &pt::PqTreeRefused| r.what == pt::NO_KIND_ROW;
        let (per, batches) = match (
            pt::adds_per_commit(&g, l, &kind, shape),
            pt::split_adds(&g, l, &kind, shape),
        ) {
            (Ok(per), Ok(b)) if b.len() > 1 => (Some(per), b),
            (Ok(per), _) => ((shape.adds > 0).then_some(per), vec![shape.adds]),
            (Err(r), _) if unnamed(&r) => return Ok(one()),
            (Err(_), _) => return Err(PqChatError::TreeTooLarge),
        };
        let mut plans = Vec::new();
        for (k, n) in batches.iter().enumerate() {
            let sh = if k == 0 && batches.len() == 1 {
                *shape
            } else {
                PqCommitShape {
                    adds: *n,
                    changes: if k == 0 {
                        shape.changes - shape.adds
                    } else {
                        0
                    } + n,
                    ..*shape
                }
            };
            let limits = if batches.len() > 1 {
                pt::margined(l)
            } else {
                l
            };
            match pt::plan_commit(&g, limits, &kind, &sh) {
                Ok(p) => plans.push(p),
                Err(r) if unnamed(&r) => return Ok(one()),
                Err(_) => return Err(PqChatError::TreeTooLarge),
            }
        }
        Ok(TreeSplit {
            refresh: None,
            deferred: None,
            adds_per_commit: per,
            batches,
            plans,
        })
    }

    /// `c` with the Adds `adds` built (not signed) on the head of `st`, and whether a strict majority confirmed that head.
    async fn tree_built(
        &self,
        s: &SessionRef,
        st: &TreeState,
        c: &TreeCommit,
        adds: &[Value],
        leaf: u32,
    ) -> Result<(pt::PqTreeCommit, bool), PqChatError> {
        // C33: the device seals the info in force when it holds it, else the marker; a new info after a gap (the device
        // holds none in force) is the admin's reviewed action only (codex-r3-7), never sealed by itself
        let info = match (&c.info, st.replay.info_to_seal.as_ref()) {
            (Some(_), None) if !c.info_reviewed => return Err(PqChatError::TreeInfoReview),
            (Some(i), _) => Some(i.clone()),
            (None, held) => held.cloned(),
        };
        let changed = c.info.is_some() && c.info.as_ref() != st.replay.info_to_seal.as_ref();
        let mut reads = PqTreeReads::default();
        self.tree_view(s, &mut reads, "treeOf()").await?;
        let seen = reads.views.get("treeOf()").cloned().unwrap_or_default();
        if st.ids.last().map(String::as_str) != model::h(at(&seen, "headEpochId")).ok().as_deref() {
            return Err(PqChatError::TreeStale);
        }
        let head_confirmed = if changed || !adds.is_empty() {
            match self.majority_tree(s, &seen).await {
                Fresh::Confirmed => true,
                Fresh::Unavailable if !changed => false,
                _ => return Err(PqChatError::TreeInfoUnconfirmed),
            }
        } else {
            false
        };
        let tree_id = model::h(at(&seen, "treeId"))?;
        let pin: Option<Value> = crate::store::Items(&*self.store)
            .get::<Value>(&pin_key(&tree_id))?
            .filter(|p| !p.is_null());
        let start = pin
            .as_ref()
            .and_then(|p| p.get("epoch"))
            .and_then(Value::as_u64);
        let ch = PqTreeChanges {
            removes: c.removes.clone(),
            adds: adds.to_vec(),
            admins: c.admins.iter().map(|a| a.to_ascii_lowercase()).collect(),
            info,
        };
        let key = c.me.key.clone();
        let pathless = !c.refresh && self.pathless_form(st, c, adds, &seen)?.is_ok();
        let try_ = self.next_try(st)?;
        let prepared = self
            .tree_run(s, &mut reads, start.unwrap_or(0), |rd| {
                if pathless {
                    self.app.pqchat_tree_prepare_pathless(
                        key.clone(),
                        c.key_id,
                        leaf,
                        rd,
                        pin.as_ref(),
                        &st.replay,
                        &ch.adds,
                        ch.info.clone(),
                        try_,
                    )
                } else {
                    self.app.pqchat_tree_prepare_commit(
                        key.clone(),
                        c.key_id,
                        leaf,
                        rd,
                        pin.as_ref(),
                        ch.clone(),
                    )
                }
            })
            .await?;
        // the walk built on the state read and confirmed first: a head that moved during the build is stale
        if reads.views.get("treeOf()") != Some(&seen) {
            return Err(PqChatError::TreeStale);
        }
        Ok((prepared, head_confirmed))
    }

    /// The `try` (C47) of this device's next path-less Add on the head of `st`: one more than the last it signed on that
    /// head, 0 on a new head.
    fn next_try(&self, st: &TreeState) -> Result<u32, PqChatError> {
        let t: Option<Value> = crate::store::Items(&*self.store).get(&tries_key(&st.session_id))?;
        let head = st.ids.last().map(|x| x.to_ascii_lowercase());
        Ok(match t {
            Some(t)
                if t.get("parent")
                    .and_then(Value::as_str)
                    .map(str::to_ascii_lowercase)
                    == head =>
            {
                t.get("next")
                    .and_then(Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok())
                    .unwrap_or(u32::MAX)
            }
            _ => 0,
        })
    }

    /// The path-less delta §6.5 (C46; F-5 by the owner's ruling of 2026-11-27): whether `c` with the Adds `adds` goes
    /// path-less on the head of `st` (`seen` its `treeOf`): Adds only, the head's admin list, the device holding the head's
    /// epoch, nothing owed, no head admin gone, room under the bound and no path commit of this device's own staged on the
    /// head; else the reason the path form is built.
    pub fn pathless_form(
        &self,
        st: &TreeState,
        c: &TreeCommit,
        adds: &[Value],
        seen: &Value,
    ) -> Result<Result<(), &'static str>, PqChatError> {
        let r = &st.replay;
        let head_admins: Vec<String> = r
            .epochs
            .last()
            .map(|e| e.admins.iter().map(|a| a.to_ascii_lowercase()).collect())
            .unwrap_or_default();
        let mut mine: Vec<String> = c.admins.iter().map(|a| a.to_ascii_lowercase()).collect();
        mine.sort();
        // the pin's register before the head's exits, and the exits applied at the head: every UA gone there
        let list = |k: &str| {
            r.pin
                .get(k)
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        };
        let gone: Vec<String> = list("gone")
            .into_iter()
            .chain(list("exits"))
            .filter_map(|g| {
                g.get(0)
                    .and_then(Value::as_str)
                    .map(str::to_ascii_lowercase)
            })
            .collect();
        let staged: Option<Value> =
            crate::store::Items(&*self.store).get(&staged_key(&st.session_id))?;
        let head = st.ids.last().map(|x| x.to_ascii_lowercase());
        let check = pt::PqPathlessCheck {
            holds_head: r.holds_head,
            // the SDK's named JSON: a number as a decimal string; anything else counts as owed (the path form)
            owed: at(seen, "owed")
                .as_str()
                .and_then(|x| x.parse::<u32>().ok())
                .or_else(|| {
                    at(seen, "owed")
                        .as_u64()
                        .and_then(|x| u32::try_from(x).ok())
                })
                .unwrap_or(u32::MAX),
            gone_admin: head_admins.iter().any(|a| gone.contains(a)),
            admins_changed: mine != head_admins,
            removes: !c.removes.is_empty(),
            since_path: r.since_path,
            bound: r.path_bound,
            adds: u32::try_from(adds.len()).unwrap_or(u32::MAX),
            own_path_commit_staged: staged
                .as_ref()
                .and_then(|v| v.get("parent").and_then(Value::as_str))
                .map(str::to_ascii_lowercase)
                == head,
            tries_left: self.next_try(st)? < pt::ADD_NONCE_TRIES,
        };
        Ok(check.form())
    }

    /// The next transaction of a signed commit on the state now (C37): prepared, or `None` once the epoch is complete at
    /// the final block (C-1 = B-4 = D-9 of the T4-T9 review: a record another sender stored alone is not complete, the
    /// pieces go through their entries). What is landed is read at the latest block and what is final at the final block
    /// (D-14): a piece landed and not final is waited for (`EpochNotFinal`), never sent twice once it landed; a piece sent and
    /// not landed yet is prepared again by a second call (the app waits for its send before it asks again, R2-C-6). The order broken so that the
    /// piece left cannot pay the completion: `TreeVoid` (rebuild with a new nonce), nothing more sent.
    pub async fn tree_next(
        &self,
        s: &SessionRef,
        c: &PqTreeCommitSigned,
        plan: &pt::PqTreePlan,
        payer: &KeyRef,
    ) -> Result<Option<AppCall>, PqChatError> {
        let shape = shape_of(&c.record);
        let fin = self.tree_landed(s, c, false).await?;
        let landed = if fin.complete {
            fin.clone()
        } else {
            self.tree_landed(s, c, true).await?
        };
        let g: PqTreeGas = match self.conf(&s.chain)?.tree_gas.as_deref() {
            Some(g) => serde_json::from_str(g).map_err(|_| PqChatError::Internal)?,
            None => PqTreeGas::default(),
        };
        let l = self.app.pqchat_tree_limits(&s.chain).await.map_err(sdk)?;
        let tx = match pt::next_send(&g, l, plan, &shape, &landed, &fin) {
            PqTreeNext::Done => return Ok(None),
            PqTreeNext::Wait => return Err(PqChatError::EpochNotFinal),
            PqTreeNext::Void(_) => return Err(PqChatError::TreeVoid),
            PqTreeNext::Send(t) => t,
        };
        let whole = plan.txs.len() == 1 && !landed.record;
        let (item, args) = piece_args(c, &tx, whole)?;
        Ok(Some(
            self.net
                .prepare(&s.chain, &s.home, item, args, payer)
                .await?,
        ))
    }

    /// What of `c` is in state at the home: at the final block, or at the latest one (`latest`, D-14); whether its epoch is
    /// complete. A `commitOf` that reverts (the record not stored: the first endpoint's revert, or `PqChatUnknown()` kept by
    /// a failover whose endpoints all reverted, R2-C-4 of the T4-T9 re-check) is "not landed"; a read that fails keeps its
    /// error (C-11, D-18).
    async fn tree_landed(
        &self,
        s: &SessionRef,
        c: &PqTreeCommitSigned,
        latest: bool,
    ) -> Result<PqTreeLanded, PqChatError> {
        let eid = &c.epoch_id;
        let shape = shape_of(&c.record);
        let read = |item: &'static str, args: Value| async move {
            if latest {
                self.net.read_latest(&s.chain, &s.home, item, args).await
            } else {
                self.net.read(&s.chain, &s.home, item, args).await
            }
        };
        let mut l = PqTreeLanded {
            cts: vec![false; shape.cts as usize],
            wraps: vec![false; shape.adds as usize],
            ..Default::default()
        };
        let done = read("IPqChat.epochComplete", json!({ "epochId": eid })).await?;
        l.complete = at(&done, "0") == true;
        l.record = match read("IPqChatTreeViews.commitOf", json!({ "epochId": eid })).await {
            Ok(_) => true,
            Err(PqChatError::Sdk(e)) if pt::record_unknown(&e) => false,
            Err(e) => return Err(e),
        };
        if !l.record {
            return Ok(l);
        }
        let list = read("IPqChatTreeViews.pathListOf", json!({ "epochId": eid })).await?;
        l.list = at(&list, "ctTargets")
            .as_array()
            .is_some_and(|v| !v.is_empty());
        let keys = read("IPqChatTreeViews.pathKeys", json!({ "epochId": eid })).await?;
        l.keys = at(&keys, "0").as_array().is_some_and(|v| !v.is_empty());
        for (i, x) in l.cts.iter_mut().enumerate() {
            let r = read(
                "IPqChatTreeViews.pathCtAt",
                json!({"epochId": eid, "i": i.to_string()}),
            )
            .await?;
            *x = at(at(&r, "0"), "mlkemCt")
                .as_str()
                .is_some_and(|h| h.len() > 2);
        }
        for (i, x) in l.wraps.iter_mut().enumerate() {
            let r = read(
                "IPqChat.wrapAt",
                json!({"epochId": eid, "i": i.to_string()}),
            )
            .await?;
            *x = at(at(&r, "0"), "mlkemCt")
                .as_str()
                .is_some_and(|h| h.len() > 2);
        }
        Ok(l)
    }

    /// The named epoch's number and the head's, refused before anything is signed when the exit is past the lag (C9, D2-4,
    /// `ExitLag`; C-10 of the T4-T9 review): the named epoch among the last [`crate::signed::EXIT_LAG_MAX`] + 1 of `epochsOf`.
    async fn exit_epoch(&self, s: &SessionRef, epoch_id: &str) -> Result<u64, PqChatError> {
        let sid = s.session_id.to_ascii_lowercase();
        let n = model::num(at(
            &self
                .home_read(s, "IPqChat.epochCount", json!({ "sessionId": sid }))
                .await?,
            "0",
        ))?;
        let lag = crate::signed::EXIT_LAG_MAX;
        let first = n.saturating_sub(lag + 1);
        let page = self
            .home_read(
                s,
                "IPqChat.epochsOf",
                json!({"sessionId": sid, "offset": first.to_string(), "limit": (n - first).to_string()}),
            )
            .await?;
        let want = epoch_id.to_ascii_lowercase();
        at(&page, "0")
            .as_array()
            .and_then(|v| {
                v.iter()
                    .position(|x| x.as_str().map(str::to_ascii_lowercase) == Some(want.clone()))
            })
            .map(|i| first + i as u64)
            .ok_or(PqChatError::ExitLag)
    }

    /// `treeLeave` of `me` from `s` naming `epoch_id` (the head or an ancestor within the lag, else `ExitLag` before anything
    /// is signed; C9), prepared and signed; its review says the UA cannot come back (R14). The prepared call.
    pub async fn tree_leave(
        &self,
        s: &SessionRef,
        me: &Me,
        epoch_id: &str,
        nonce: u64,
        payer: &KeyRef,
    ) -> Result<AppCall, PqChatError> {
        self.exit_epoch(s, epoch_id).await?;
        let tree_id = self.tree_id(s).await?;
        let p = self
            .app
            .prepare_pqchat_tree_leave(
                me.key.clone(),
                PqTreeLeave {
                    session_id: s.session_id.clone(),
                    tree_id,
                    epoch_id: epoch_id.into(),
                    nonce,
                },
            )
            .map_err(sdk)?;
        let sig = crate::session::sig_json(&p.sign().map_err(sdk)?);
        let args = json!({"l": strings(&p.record), "sig": sig});
        self.net
            .prepare(&s.chain, &s.home, "IPqChat.treeLeave", args, payer)
            .await
    }

    /// `treeRemove` of `members` from `s` by the admin `me` naming `epoch_id` (within the lag, else `ExitLag`; its
    /// `nextEpoch` the named epoch's number plus one; the members sorted, each once, at most `TREE_CHANGES_MAX`, else
    /// `MembersInvalid`; C9), prepared and signed (R14 in its review).
    pub async fn tree_remove(
        &self,
        s: &SessionRef,
        me: &Me,
        epoch_id: &str,
        members: Vec<String>,
        nonce: u64,
        payer: &KeyRef,
    ) -> Result<AppCall, PqChatError> {
        let mut members: Vec<String> = members.iter().map(|m| m.to_ascii_lowercase()).collect();
        members.sort();
        members.dedup();
        if members.is_empty() || members.len() > TREE_CHANGES_MAX {
            return Err(PqChatError::MembersInvalid);
        }
        let named = self.exit_epoch(s, epoch_id).await?;
        let tree_id = self.tree_id(s).await?;
        let p = self
            .app
            .prepare_pqchat_tree_remove(
                me.key.clone(),
                PqTreeRemove {
                    session_id: s.session_id.clone(),
                    tree_id,
                    epoch_id: epoch_id.into(),
                    next_epoch: named + 1,
                    members,
                    nonce,
                },
            )
            .map_err(sdk)?;
        let sig = crate::session::sig_json(&p.sign().map_err(sdk)?);
        let args = json!({"r": strings(&p.record), "sig": sig});
        self.net
            .prepare(&s.chain, &s.home, "IPqChat.treeRemove", args, payer)
            .await
    }

    async fn tree_id(&self, s: &SessionRef) -> Result<String, PqChatError> {
        let t = self
            .home_read(
                s,
                "IPqChatTreeViews.treeOf",
                json!({ "sessionId": s.session_id.to_ascii_lowercase() }),
            )
            .await?;
        model::h(at(&t, "treeId"))
    }
}

/// The KEM versions the Add warning's lookup scans per candidate (spec §15, codex-r3-9): 0 to the highest when the highest
/// is at most this many.
pub const KEM_SCAN_MAX: u64 = 64;

/// The Add warning's answer (owner R16, spec §15): the candidate UAs whose registry keys hold the added key's `kemHash`, each
/// at a version, how many candidates were looked at, and those whose versions were not all scanned (above
/// [`KEM_SCAN_MAX`]: 0, the highest and the versions the session's leaves name). Empty `held_by` is "not found among
/// `checked`" with what was not covered, never "held by nobody".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddCheck {
    pub held_by: Vec<(String, u64)>,
    pub checked: usize,
    /// candidates with versions left out of the scan: `(ua, highest)`
    pub not_covered: Vec<(String, u64)>,
}

impl PqChat {
    /// Before an Add of `ua`'s key `kem_hash` (owner R16): every other candidate (the session's UAs, the contacts, index hints)
    /// at each KEM version from 0 to its highest when that is at most [`KEM_SCAN_MAX`] (D-15 of the T4-T9 review: "at
    /// most"), else at 0, the highest and each version `leaf_versions` names for it (the session's leaves); each positive the
    /// registry's `kemKeyAt` hashing to `kem_hash`. A candidate whose `version` cannot be read is not counted as checked. The
    /// app shows "this key is also held by UA …" for each, or "not found among N" with what was not covered.
    pub async fn tree_add_check(
        &self,
        chain: &str,
        ua: &str,
        kem_hash: &str,
        candidates: &[String],
        leaf_versions: &[(String, u64)],
    ) -> Result<AddCheck, PqChatError> {
        let (ua, want) = (ua.to_ascii_lowercase(), kem_hash.to_ascii_lowercase());
        let mut cands: Vec<String> = candidates
            .iter()
            .map(|c| c.to_ascii_lowercase())
            .filter(|c| *c != ua)
            .collect();
        cands.sort();
        cands.dedup();
        let reg = self.conf(chain)?.registry.clone();
        let mut out = AddCheck {
            held_by: vec![],
            checked: 0,
            not_covered: vec![],
        };
        for c in &cands {
            let v = self
                .net
                .read(chain, &reg, "IUARegistry.kemKeyOf", json!({ "ua": c }))
                .await?;
            let Ok(high) = model::num(at(&v, "version")) else {
                continue;
            };
            let versions: Vec<u64> = if high <= KEM_SCAN_MAX {
                (0..=high).collect()
            } else {
                let mut v: Vec<u64> = leaf_versions
                    .iter()
                    .filter(|(u, k)| u.eq_ignore_ascii_case(c) && *k <= high)
                    .map(|(_, k)| *k)
                    .chain([0, high])
                    .collect();
                v.sort_unstable();
                v.dedup();
                out.not_covered.push((c.clone(), high));
                v
            };
            let names: Vec<String> = versions
                .iter()
                .map(|k| format!("kemKeyAt({c},{k})"))
                .collect();
            let mut reads = PqTreeReads::default();
            for (k, n) in versions.iter().zip(&names) {
                let v = self
                    .net
                    .read(
                        chain,
                        &reg,
                        "IUARegistry.kemKeyAt",
                        json!({"ua": c, "version": k.to_string()}),
                    )
                    .await?;
                reads.put_kem_key_at(n, &v).map_err(sdk)?;
            }
            for (k, n) in versions.iter().zip(&names) {
                let pk = reads
                    .views
                    .get(n)
                    .and_then(|x| x.get("kemPk"))
                    .and_then(Value::as_str)
                    .unwrap_or("0x");
                if pk.len() > 2 && pt::kem_hash(pk).as_deref() == Some(want.as_str()) {
                    out.held_by.push((c.clone(), *k));
                }
            }
            out.checked += 1;
        }
        Ok(out)
    }
}

/// Two `treeOf` answers of one state: equal whole (the head, the tree hash and `owed`, which an exit moves; D-18).
fn same_head(a: &Value, b: &Value) -> bool {
    a == b
}

/// C38 (C-6 of the T4-T9 review): a session is closed when no leaf of the pinned head's tree belongs to a UA that is not
/// gone (the tree's `goneUa`, the register's `gone`, the head's exits): its last members left or were removed by exits,
/// which blank no leaf.
fn closed_of(pin: &Value) -> bool {
    let list = |v: &Value| v.as_array().cloned().unwrap_or_default();
    let first = |x: &Value| x.get(0).cloned().unwrap_or_default();
    let tree = at(pin, "tree");
    let mut gone: Vec<String> = list(at(tree, "goneUa"))
        .into_iter()
        .chain(list(at(pin, "gone")).iter().map(first))
        .chain(list(at(pin, "exits")).iter().map(first))
        .filter_map(|x| x.as_str().map(str::to_ascii_lowercase))
        .collect();
    gone.sort();
    list(at(tree, "nodes"))
        .iter()
        .step_by(2)
        .filter_map(|n| n.get("ua").and_then(Value::as_str))
        .all(|ua| gone.binary_search(&ua.to_ascii_lowercase()).is_ok())
}

/// The one-transaction plan (no rows, or a kind the rows do not name): the whole commit, held to the quote.
fn one_tx() -> pt::PqTreePlan {
    pt::PqTreePlan {
        txs: vec![pt::PqTreeTx {
            entry: "commit",
            first: 0,
            count: 0,
            gas: Default::default(),
        }],
        completion: Default::default(),
        dearest_last: Default::default(),
    }
}

/// Integers as decimal strings (the port's named arguments).
fn strings(v: &Value) -> Value {
    match v {
        Value::Number(n) => json!(n.to_string()),
        Value::Array(a) => Value::Array(a.iter().map(strings).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), strings(x))).collect()),
        x => x.clone(),
    }
}

/// The planner's shape of a commit record.
fn shape_of(rec: &Value) -> PqCommitShape {
    let n = |k: &str| {
        rec.get(k)
            .and_then(Value::as_array)
            .map_or(0, |a| a.len() as u64)
    };
    PqCommitShape {
        changes: n("removes") + n("adds"),
        admins: n("admins"),
        info: rec
            .get("sealedInfo")
            .and_then(Value::as_str)
            .map_or(0, |h| (h.len().saturating_sub(2) / 2) as u64),
        cts: rec.get("ctCount").and_then(Value::as_u64).unwrap_or(0),
        keys: n("nodeKeyHashes"),
        adds: n("adds"),
    }
}

/// A planned transaction's entry and named arguments from the signed commit: the whole commit when the plan is one
/// transaction, else the record alone or one piece.
fn piece_args(
    c: &PqTreeCommitSigned,
    t: &pt::PqTreeTx,
    whole: bool,
) -> Result<(&'static str, Value), PqChatError> {
    let sig = crate::session::sig_json(&c.sig);
    let keys: Vec<String> = c.node_keys.iter().map(|k| model::hex(k)).collect();
    let range = |v: &[Value]| -> Result<Vec<Value>, PqChatError> {
        let (a, b) = (t.first as usize, (t.first + t.count.max(1)) as usize);
        v.get(a..b).map(|s| s.to_vec()).ok_or(PqChatError::Internal)
    };
    Ok(match t.entry {
        "commit" if whole => (
            "IPqChat.commit",
            json!({"c": strings(&c.record), "ctTargets": strings(&json!(c.ct_targets)), "ctHashes": c.ct_hashes,
                "nodeKeys": keys, "cts": c.cts, "wraps": strings(&json!(c.wraps)), "sig": sig}),
        ),
        "commit" => (
            "IPqChat.commit",
            json!({"c": strings(&c.record), "ctTargets": [], "ctHashes": [], "nodeKeys": [], "cts": [], "wraps": [], "sig": sig}),
        ),
        "addPathList" => (
            "IPqChat.addPathList",
            json!({"epochId": c.epoch_id, "ctTargets": strings(&json!(c.ct_targets)), "ctHashes": c.ct_hashes}),
        ),
        "addPathKeys" => (
            "IPqChat.addPathKeys",
            json!({"epochId": c.epoch_id, "nodeKeys": keys}),
        ),
        "addPath" => (
            "IPqChat.addPath",
            json!({"epochId": c.epoch_id, "firstCt": t.first.to_string(), "cts": range(&c.cts)?}),
        ),
        _ => (
            "IPqChat.addWraps",
            json!({"epochId": c.epoch_id, "first": t.first.to_string(), "wraps": strings(&json!(range(&c.wraps)?))}),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_names_parse() {
        assert_eq!(parse("commitOf(3)").ok(), Some(("commitOf", vec!["3"])));
        assert_eq!(parse("treeOf()").ok(), Some(("treeOf", vec![])));
        assert_eq!(
            parse("goneOwnKeyOf(0xab,0xcd)").ok(),
            Some(("goneOwnKeyOf", vec!["0xab", "0xcd"]))
        );
        assert!(parse("treeOf").is_err());
        assert_eq!(pin_key("0xAB"), "tree/pin/0xab");
    }

    /// C38 (C-6 of the T4-T9 review): closed when every leaf's UA is gone, by the tree, the register or the head's exits;
    /// a leaf of a UA that stays keeps it open.
    #[test]
    fn a_session_closed_by_exits() {
        let (a, b) = ("0xaa", "0xbb");
        let pin = |exits: Value, gone: Value| {
            json!({"tree": {"goneUa": [], "nodes": [{"ua": a}, {"keyHash": "0x01"}, {"ua": b}, null]},
                "gone": gone, "exits": exits})
        };
        assert!(closed_of(&pin(json!([[a, 1]]), json!([[b, 2, 3]]))));
        assert!(closed_of(&pin(json!([[a, 1], [b, 2]]), json!([]))));
        assert!(!closed_of(&pin(json!([[a, 1]]), json!([]))));
        assert!(!closed_of(&pin(json!([]), json!([]))));
    }

    /// Every view the tree mode reads is marked trusted (CLI-PQC-13) in the crate's one table.
    #[test]
    fn tree_reads_are_trusted() {
        for item in TREE_READS {
            assert_eq!(
                crate::net::trust(item).ok(),
                Some(crate::net::Trust::Trusted),
                "{item}"
            );
        }
    }
}
