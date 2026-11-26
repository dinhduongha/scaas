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
}

/// A tree session as this device follows it: the replay's epochs and warnings, and whether the device can send.
pub struct TreeState {
    pub replay: Arc<PqTreeReplay>,
    /// the head's number
    pub head: u64,
    /// no UA that is not gone holds a live leaf (C38): nothing more is written
    pub closed: bool,
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

/// C3: the tree mode is proposed from this many member keys where several members commit; a hint, never enforced.
pub const TREE_HINT_KEYS: usize = 7;

/// C3's size hint: whether to propose a tree session for `keys` member keys of which `committers` commit.
pub fn tree_advised(keys: usize, committers: usize) -> bool {
    keys >= TREE_HINT_KEYS && committers >= 2
}

/// The store key of a tree session's checkpoint (C26), by its `treeId` (C16).
fn pin_key(tree_id: &str) -> String {
    format!("tree/pin/{}", tree_id.to_ascii_lowercase())
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
    /// SDK, at most [`ROUNDS_MAX`] rounds.
    pub(crate) async fn tree_run<T>(
        &self,
        s: &SessionRef,
        reads: &mut PqTreeReads,
        mut f: impl FnMut(&PqTreeReads) -> Result<PqTreeStep<T>, SdkError>,
    ) -> Result<T, PqChatError> {
        let mut prefetched = false;
        for _ in 0..ROUNDS_MAX {
            // the reads every walk makes per epoch, scheduled from public data (the epoch list and the exit counts) once the
            // list is known, so a long session takes a few rounds, not one per view
            if !prefetched && reads.views.contains_key("epochsOf()") {
                prefetched = true;
                self.tree_prefetch(s, reads).await?;
            }
            match f(reads).map_err(sdk)? {
                PqTreeStep::Done(v) => {
                    // fable-r3-9: the snapshot is one state of the home: the tree read again at the end is the one read first,
                    // else every view is read again (the head moved while the pages were read)
                    let Some(first) = reads.views.get("treeOf()").cloned() else {
                        return Ok(v);
                    };
                    let again = self
                        .home_read(
                            s,
                            "IPqChatTreeViews.treeOf",
                            json!({ "sessionId": s.session_id.to_ascii_lowercase() }),
                        )
                        .await?;
                    if same_head(&first, &again) {
                        return Ok(v);
                    }
                    reads.views.clear();
                }
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
                }
            }
        }
        Err(PqChatError::TreeReads)
    }

    /// Every epoch's record and exit counts, then each exit, as one walk reads them (public data only, C22).
    async fn tree_prefetch(
        &self,
        s: &SessionRef,
        reads: &mut PqTreeReads,
    ) -> Result<(), PqChatError> {
        let n = reads
            .views
            .get("epochsOf()")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        for e in 0..n {
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
        if self.sig_store(&r.chain, &r.home).await != Ok(crate::signed::SIG_SSTORE2) {
            return Err(PqChatError::TreeHomeNone);
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
        if let Some(g) = c.tree_gas.as_deref() {
            let g: PqTreeGas = serde_json::from_str(g).map_err(|_| PqChatError::Internal)?;
            let l = self.app.pqchat_tree_limits(&r.chain).await.map_err(sdk)?;
            let cap = pt::create_cap(&g, l, &self.signer_kind(&r.me)?, admins.len() as u64, 0);
            if members.len() as u64 > cap {
                return Err(PqChatError::TreeTooLarge);
            }
        }
        let session = json!({"creator": me, "nonce": r.nonce, "homeChain": c.chain_uid,
            "homeChatContract": r.home.to_ascii_lowercase(), "admins": admins, "members": members, "groupMode": 1});
        let info = serde_json::to_string(&r.info).map_err(|_| PqChatError::Internal)?;
        let sref = SessionRef {
            chain: r.chain.clone(),
            home: r.home.to_ascii_lowercase(),
            session_id: String::new(),
        };
        let mut reads = PqTreeReads::default();
        let key = r.me.key.clone();
        let g = self
            .tree_run(&sref, &mut reads, |rd| {
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
        // codex-r3-5: the signed record and every wrap kept before anything leaves, until the session is complete at home
        crate::store::Items(&*self.store)
            .update::<Value, _>(&create_key(&g.session_id), |_| Ok(args.clone()))?;
        let call = self
            .net
            .prepare(
                &r.chain,
                &sref.home,
                "IPqChat.createSession",
                args,
                &r.payer,
            )
            .await
            .map_err(|e| match e.code() {
                "GasAboveTxCap" => PqChatError::TreeTooLarge,
                _ => e,
            })?;
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

    /// The signer kind name of the gas rows' `verify` (`mldsa65` for the wallet's PQ default, by the key's kind).
    fn signer_kind(&self, me: &Me) -> Result<String, PqChatError> {
        match &me.key {
            KeyRef::Ua { kind, .. } => Ok(match *kind {
                0x0132 => "mldsa87".into(),
                0x0131 => "mldsa65".into(),
                k => format!("{k:#06x}"),
            }),
            _ => Err(PqChatError::MsigAuthorPlanned),
        }
    }

    /// The device's replay of `s` (spec §10) by `me`'s key `key_id`: from the store's pin (resumed when the device holds its
    /// previous replay, else walked from the cold tree with the pin compared), every read scheduled from public data; the pin
    /// moves to the head only on success. A key in no period of the session: `NotMember`.
    pub async fn tree_state(
        &self,
        s: &SessionRef,
        me: &Me,
        key_id: u64,
        from: Option<&PqTreeReplay>,
    ) -> Result<TreeState, PqChatError> {
        let key = me.key.clone();
        self.tree_state_by(s, |app, rd, pin| match from {
            Some(f) => app.pqchat_tree_resume(key.clone(), key_id, rd, f, 0),
            None => app.pqchat_tree_replay(key.clone(), key_id, rd, pin, 0),
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
    ) -> Result<TreeState, PqChatError> {
        self.tree_state_by(s, |app, rd, pin| {
            app.pqchat_tree_vectors_replay(seed, kem_seed, ua, key_id, rd, pin, 0)
        })
        .await
    }

    async fn tree_state_by(
        &self,
        s: &SessionRef,
        mut f: impl FnMut(
            &AppCore,
            &PqTreeReads,
            Option<&Value>,
        ) -> Result<PqTreeStep<Option<Arc<PqTreeReplay>>>, SdkError>,
    ) -> Result<TreeState, PqChatError> {
        let mut reads = PqTreeReads::default();
        self.tree_view(s, &mut reads, "treeOf()").await?;
        let t = reads.views.get("treeOf()").cloned().unwrap_or_default();
        let tree_id = model::h(at(&t, "treeId"))?;
        let pin: Option<Value> = crate::store::Items(&*self.store).get(&pin_key(&tree_id))?;
        let app = self.app.clone();
        let r = self
            .tree_run(s, &mut reads, |rd| f(&app, rd, pin.as_ref()))
            .await?
            .ok_or(PqChatError::NotMember)?;
        let ids: Vec<String> = reads
            .views
            .get("epochsOf()")
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let head = ids.len().saturating_sub(1) as u64;
        // R13: a changed info is taken only once a strict majority of at least 3 named endpoints confirms the head it was
        // read at; fewer, or a majority that disagrees, refuses it by name and the pin does not move
        let pinned = pin
            .as_ref()
            .and_then(|p| p.get("epoch"))
            .and_then(Value::as_u64);
        // ARCH-POS-13: the majority read is made whenever the replay reached an epoch after the pin, whatever any epoch's info
        // opened to, so the reads never depend on a decryption; its answer counts only for a changed info
        let new_epochs: Vec<_> = r
            .epochs
            .iter()
            .filter(|e| pinned.is_none_or(|p| e.epoch > p))
            .collect();
        if !new_epochs.is_empty() {
            let args = json!({ "sessionId": s.session_id.to_ascii_lowercase() });
            let agreed = self
                .net
                .read_majority(&s.chain, &s.home, "IPqChatTreeViews.treeOf", args)
                .await
                .ok()
                .filter(|(_, named)| *named >= 3)
                .and_then(|(v, _)| model::h(at(&v, "headEpochId")).ok())
                .is_some_and(|h| Some(h) == ids.last().map(|x| x.to_ascii_lowercase()));
            if !agreed
                && new_epochs
                    .iter()
                    .any(|e| e.info.as_deref() == Some("changed"))
            {
                return Err(PqChatError::TreeInfoUnconfirmed);
            }
        }
        crate::store::Items(&*self.store)
            .update::<Value, _>(&pin_key(&tree_id), |_| Ok(r.pin.clone()))?;
        // C38: closed when no leaf the walk reached at the head is held (every UA left or removed)
        let closed = r
            .rosters
            .get(&head)
            .is_some_and(|v| v.iter().all(Option::is_none));
        Ok(TreeState {
            replay: r,
            head,
            closed,
        })
    }

    /// Epoch `epoch_id` of a followed tree session opened for messages (the mode branch at "obtain `K`", CLI-PQC-17): its
    /// `K` from the replay (`followed` only; else `EpochIncomplete`, nothing sent), its members the roster's UAs.
    pub fn tree_open(
        &self,
        s: &SessionRef,
        st: &TreeState,
        epoch_id: &str,
    ) -> Result<crate::message::OpenEpoch, PqChatError> {
        let id = epoch_id.to_ascii_lowercase();
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
        Ok(crate::message::OpenEpoch {
            chain: s.chain.clone(),
            epoch: model::Epoch {
                id,
                session_id: s.session_id.to_ascii_lowercase(),
                author: String::new(),
                nonce: 0,
                epoch: e.epoch,
                parent: model::ZERO32.into(),
                admins: vec![],
                members,
                wrap_hashes: vec![],
                sealed_info: vec![],
                sig_hash: String::new(),
            },
            k,
        })
    }

    /// A commit by `c.me` on the head of `s` (spec §8): built and signed by `scaas-ua` on the tree the forward walk verified
    /// from the store's pin, then planned in C37's order on the chain's limits; the first transaction prepared. A required
    /// piece that does not fit refuses the operation (`TreeTooLarge`), nothing signed.
    pub async fn tree_commit(
        &self,
        s: &SessionRef,
        st: &TreeState,
        c: TreeCommit,
        leaf: u32,
    ) -> Result<(PqTreeCommitSigned, pt::PqTreePlan), PqChatError> {
        // C33: the device seals the info in force when it holds it, else the marker; a new info after a gap (the device
        // holds none in force) is the admin's reviewed action only (codex-r3-7), never sealed by itself
        let info = match (&c.info, st.replay.info_to_seal.as_ref()) {
            (Some(_), None) if !c.info_reviewed => return Err(PqChatError::TreeInfoReview),
            (Some(i), _) => Some(i.clone()),
            (None, held) => held.cloned(),
        };
        let mut reads = PqTreeReads::default();
        self.tree_view(s, &mut reads, "treeOf()").await?;
        let tree_id = model::h(at(
            reads.views.get("treeOf()").unwrap_or(&Value::Null),
            "treeId",
        ))?;
        let pin: Option<Value> = crate::store::Items(&*self.store).get(&pin_key(&tree_id))?;
        let ch = PqTreeChanges {
            removes: c.removes.clone(),
            adds: c.adds.clone(),
            admins: c.admins.iter().map(|a| a.to_ascii_lowercase()).collect(),
            info,
        };
        let key = c.me.key.clone();
        let prepared = self
            .tree_run(s, &mut reads, |rd| {
                self.app.pqchat_tree_prepare_commit(
                    key.clone(),
                    c.key_id,
                    leaf,
                    rd,
                    pin.as_ref(),
                    ch.clone(),
                )
            })
            .await?;
        let shape = shape_of(&prepared.record);
        let plan = match self.conf(&s.chain)?.tree_gas.as_deref() {
            Some(g) => {
                let g: PqTreeGas = serde_json::from_str(g).map_err(|_| PqChatError::Internal)?;
                let l = self.app.pqchat_tree_limits(&s.chain).await.map_err(sdk)?;
                pt::plan_commit(&g, l, &self.signer_kind(&c.me)?, &shape)
                    .map_err(|_| PqChatError::TreeTooLarge)?
            }
            None => pt::PqTreePlan {
                txs: vec![pt::PqTreeTx {
                    entry: "commit",
                    first: 0,
                    count: 0,
                    gas: Default::default(),
                }],
                completion: Default::default(),
                dearest_last: Default::default(),
            },
        };
        let signed = prepared.sign().map_err(sdk)?;
        Ok((signed, plan))
    }

    /// The next transaction of a signed commit on the state now (C37; the record-already-stored fallback): prepared, or
    /// `None` when complete. The order broken so that the piece left cannot pay the completion: `TreeVoid` (rebuild with a
    /// new nonce), nothing more sent.
    pub async fn tree_next(
        &self,
        s: &SessionRef,
        c: &PqTreeCommitSigned,
        plan: &pt::PqTreePlan,
        payer: &KeyRef,
    ) -> Result<Option<AppCall>, PqChatError> {
        let shape = shape_of(&c.record);
        let landed = self.tree_landed(s, c).await?;
        let g: PqTreeGas = match self.conf(&s.chain)?.tree_gas.as_deref() {
            Some(g) => serde_json::from_str(g).map_err(|_| PqChatError::Internal)?,
            None => PqTreeGas::default(),
        };
        let l = self.app.pqchat_tree_limits(&s.chain).await.map_err(sdk)?;
        // the port reads at the final block: what it shows landed is final
        let tx = match pt::next_send(&g, l, plan, &shape, &landed, &landed) {
            PqTreeNext::Done => return Ok(None),
            PqTreeNext::Wait => return Err(PqChatError::EpochNotFinal),
            PqTreeNext::Void(_) => return Err(PqChatError::TreeVoid),
            PqTreeNext::Send(t) => t,
        };
        let (item, args) = piece_args(c, &tx, plan.txs.len() == 1)?;
        Ok(Some(
            self.net
                .prepare(&s.chain, &s.home, item, args, payer)
                .await?,
        ))
    }

    /// What of `c` is in state at the home (trusted reads at the final block).
    async fn tree_landed(
        &self,
        s: &SessionRef,
        c: &PqTreeCommitSigned,
    ) -> Result<PqTreeLanded, PqChatError> {
        let eid = &c.epoch_id;
        let shape = shape_of(&c.record);
        let mut l = PqTreeLanded {
            cts: vec![false; shape.cts as usize],
            wraps: vec![false; shape.adds as usize],
            ..Default::default()
        };
        l.record = self
            .home_read(s, "IPqChatTreeViews.commitOf", json!({ "epochId": eid }))
            .await
            .is_ok();
        if !l.record {
            return Ok(l);
        }
        let list = self
            .home_read(s, "IPqChatTreeViews.pathListOf", json!({ "epochId": eid }))
            .await?;
        l.list = at(&list, "ctTargets")
            .as_array()
            .is_some_and(|v| !v.is_empty());
        let keys = self
            .home_read(s, "IPqChatTreeViews.pathKeys", json!({ "epochId": eid }))
            .await?;
        l.keys = at(&keys, "0").as_array().is_some_and(|v| !v.is_empty());
        for (i, x) in l.cts.iter_mut().enumerate() {
            let r = self
                .home_read(
                    s,
                    "IPqChatTreeViews.pathCtAt",
                    json!({"epochId": eid, "i": i.to_string()}),
                )
                .await?;
            *x = at(at(&r, "0"), "mlkemCt")
                .as_str()
                .is_some_and(|h| h.len() > 2);
        }
        for (i, x) in l.wraps.iter_mut().enumerate() {
            let r = self
                .home_read(
                    s,
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

    /// `treeLeave` of `me` from `s` naming `epoch_id` (the head or an ancestor within the lag; C9), prepared and signed; its
    /// review says the UA cannot come back (R14). The prepared call.
    pub async fn tree_leave(
        &self,
        s: &SessionRef,
        me: &Me,
        epoch_id: &str,
        nonce: u64,
        payer: &KeyRef,
    ) -> Result<AppCall, PqChatError> {
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

    /// `treeRemove` of `members` from `s` by the admin `me` naming `epoch_id` (C9), prepared and signed (R14 in its review).
    #[allow(clippy::too_many_arguments)]
    pub async fn tree_remove(
        &self,
        s: &SessionRef,
        me: &Me,
        epoch_id: &str,
        next_epoch: u64,
        members: Vec<String>,
        nonce: u64,
        payer: &KeyRef,
    ) -> Result<AppCall, PqChatError> {
        let tree_id = self.tree_id(s).await?;
        let mut members: Vec<String> = members.iter().map(|m| m.to_ascii_lowercase()).collect();
        members.sort();
        let p = self
            .app
            .prepare_pqchat_tree_remove(
                me.key.clone(),
                PqTreeRemove {
                    session_id: s.session_id.clone(),
                    tree_id,
                    epoch_id: epoch_id.into(),
                    next_epoch,
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

/// The KEM versions the Add warning's lookup scans per candidate (spec §15, codex-r3-9): 0 to the highest up to this many.
pub const KEM_SCAN_MAX: u64 = 64;

/// The Add warning's answer (owner R16, spec §15): the candidate UAs whose registry keys hold the added key's `kemHash`, each
/// at a version, and how many candidates were looked at. Empty `held_by` is "not found among `checked`", never "held by
/// nobody".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddCheck {
    pub held_by: Vec<(String, u64)>,
    pub checked: usize,
}

impl PqChat {
    /// Before an Add of `ua`'s key `kem_hash` (owner R16): every other candidate (the session's UAs, the contacts, index hints)
    /// at each KEM version from 0 to its highest (at most [`KEM_SCAN_MAX`]; above it 0 and the highest), each positive the
    /// registry's `kemKeyAt` hashing to `kem_hash`. The app shows "this key is also held by UA …" for each.
    pub async fn tree_add_check(
        &self,
        chain: &str,
        ua: &str,
        kem_hash: &str,
        candidates: &[String],
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
        };
        for c in &cands {
            let v = self
                .net
                .read(chain, &reg, "IUARegistry.kemKeyOf", json!({ "ua": c }))
                .await?;
            let high = model::num(at(&v, "version")).unwrap_or(0);
            let versions: Vec<u64> = if high < KEM_SCAN_MAX {
                (0..=high).collect()
            } else {
                vec![0, high]
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

/// Two `treeOf` answers of one state: the same head and tree hash.
fn same_head(a: &Value, b: &Value) -> bool {
    at(a, "headEpochId") == at(b, "headEpochId") && at(a, "treeHash") == at(b, "treeHash")
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
