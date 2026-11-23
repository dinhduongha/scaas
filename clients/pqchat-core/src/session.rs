// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Sessions and epochs (spec §4 rows Session, Epoch, Remove / leave, Wraps / KEM, `msig`; CTR-CHAT-06 to CTR-CHAT-10,
//! CTR-CHAT-20): what to build and from which reads. The creator is in `members` and `admins`, both strictly sorted; a fresh
//! `K` per epoch (drawn, never the parent's); `msig` seats expanded into their accepted leaves (two levels, `via` the seat);
//! each member wrapped at the highest KEM version seen (trusted reads), a member without a usable key skipped and named; the
//! `sealedInfo` sealed and the record signed by the SDK's PqChat entries from named fields; the wraps sent in as many chunks as
//! the SDK's quote accepts. Every write is the SDK's prepared operation: the app shows its review, submits it, follows it.
use crate::message::OpenEpoch;
use crate::model::{self, at, Epoch, Member, ZERO32};
use crate::reads::SessionRef;
use crate::{Event, PqChat, PqChatError};
use scaas_sdk::app_core::{AppCall, AppKey, AppUaSig};
use scaas_sdk::op::KeyRef;
use scaas_sdk::pqchat_keys::{PqEpochNew, PqSessionNew};
use scaas_sdk::pqchat_records::{PqChatLeave, PqChatRemove, PqChatSigned, PqMemberKey, PqWrap};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The registry's `msig` kind (CTR-UA-37).
pub const MSIG: u64 = 0x0120;

/// An account as the crate acts for it: the SDK key and its UA (the app's account list gives both).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Me {
    pub key: KeyRef,
    pub ua: String,
}

/// One store of a session's list (UA-7 P27, §4.2), as `sealedInfo` names it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum StoreEntry {
    Matrix {
        room: String,
    },
    #[serde(rename_all = "camelCase")]
    Chain {
        chain_id: String,
        chain_uid: String,
        contract: String,
    },
    #[serde(rename_all = "camelCase")]
    Chainstore {
        chain_id: String,
        chain_uid: String,
        contract: String,
    },
    Hcs {
        topic: String,
    },
    #[serde(rename_all = "camelCase")]
    Waku {
        content_topic: String,
    },
    Libp2p,
}

impl StoreEntry {
    /// A store that holds messages (`libp2p` signals calls only).
    pub fn holds_messages(&self) -> bool {
        !matches!(self, StoreEntry::Libp2p)
    }
    /// A store this build reads and writes (CLI-PQC-02: Matrix and `PqChat` chain stores).
    pub fn implemented(&self) -> bool {
        matches!(self, StoreEntry::Matrix { .. } | StoreEntry::Chain { .. })
    }
}

/// An epoch's `sealedInfo` (UA-7 §4.2).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Info {
    pub stores: Vec<StoreEntry>,
    pub name: String,
    pub topic: String,
    /// UA → Matrix user id; present only with a Matrix store
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub matrix: BTreeMap<String, String>,
}

/// UA-7 §4.2's list rules (`StoreListInvalid`): at least one message store; at most one Matrix, HCS, Waku and `libp2p`
/// entry; chain entries distinct; the Matrix map only with a Matrix store. Then every kind implemented (`StoreUnsupported`).
pub fn check_stores(i: &Info) -> Result<(), PqChatError> {
    let count = |f: fn(&StoreEntry) -> bool| i.stores.iter().filter(|s| f(s)).count();
    let matrix = count(|s| matches!(s, StoreEntry::Matrix { .. }));
    let one_each = [
        matrix,
        count(|s| matches!(s, StoreEntry::Hcs { .. })),
        count(|s| matches!(s, StoreEntry::Waku { .. })),
        count(|s| matches!(s, StoreEntry::Libp2p)),
    ];
    let mut chains: Vec<&StoreEntry> = i
        .stores
        .iter()
        .filter(|s| matches!(s, StoreEntry::Chain { .. } | StoreEntry::Chainstore { .. }))
        .collect();
    let n = chains.len();
    chains.sort();
    chains.dedup();
    if count(StoreEntry::holds_messages) == 0
        || one_each.iter().any(|c| *c > 1)
        || chains.len() != n
        || (!i.matrix.is_empty() && matrix == 0)
    {
        return Err(PqChatError::StoreListInvalid);
    }
    if !i.stores.iter().all(StoreEntry::implemented) {
        return Err(PqChatError::StoreUnsupported);
    }
    Ok(())
}

/// A session to create (CTR-CHAT-06): the home, the members and admins (the creator added to both), the store list.
#[derive(Debug, Clone)]
pub struct CreateSession {
    pub me: Me,
    pub chain: String,
    pub home: String,
    pub nonce: u64,
    /// UAs or `msig` seats
    pub members: Vec<String>,
    pub admins: Vec<String>,
    pub info: Info,
    pub payer: KeyRef,
}

/// A new epoch after an open parent (CTR-CHAT-08, CTR-CHAT-09): members (UAs or seats) and admins; those who left the parent
/// or were removed from it are dropped.
#[derive(Debug, Clone)]
pub struct Rekey {
    pub me: Me,
    pub nonce: u64,
    pub members: Vec<String>,
    pub admins: Vec<String>,
    pub info: Info,
    pub payer: KeyRef,
}

/// A listed UA left out of the record, named for the user: its seat (`via`, zero for a direct member) and the code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub ua: String,
    pub via: String,
    pub code: &'static str,
}

/// A signed session or epoch ready to send: its record, key, wraps, the first write (`createSession` or `rekey`) with the wraps
/// that fit, and the UAs skipped; the rest of the wraps go by [`PqChat::next_wraps`] once that write has landed.
pub struct Built {
    pub session_id: String,
    pub epoch_id: String,
    pub epoch: Epoch,
    #[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
    pub k: Arc<AppKey>,
    pub wraps: Vec<PqWrap>,
    pub signed: PqChatSigned,
    pub call: AppCall,
    /// how many wraps the writes prepared so far carry
    pub sent: usize,
    pub skipped: Vec<Skipped>,
}

/// Lower case, strictly sorted after adding `add`; a duplicate in `v` is `MembersInvalid`.
fn sorted(v: &[String], add: Option<&str>) -> Result<Vec<String>, PqChatError> {
    let mut v: Vec<String> = v.iter().map(|s| s.to_ascii_lowercase()).collect();
    v.sort();
    if !crate::check::strictly_sorted(v.iter().map(String::as_str)) {
        return Err(PqChatError::MembersInvalid);
    }
    if let Some(a) = add {
        if let Err(i) = v.binary_search_by(|x| x.as_str().cmp(a)) {
            v.insert(i, a.to_string());
        }
    }
    Ok(v)
}

fn field<'a>(s: &'a PqChatSigned, name: &str) -> Result<&'a str, PqChatError> {
    s.review
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.value.as_str())
        .ok_or(PqChatError::Internal)
}

pub(crate) fn sig_json(s: &AppUaSig) -> Value {
    let inner = |m: &scaas_sdk::app_core::AppMemberSig| -> Vec<Value> {
        m.members
            .iter()
            .map(|x| json!({"index": x.index.to_string(), "sig": model::hex(&x.sig)}))
            .collect()
    };
    json!({"keyData": model::hex(&s.key_data), "signature": model::hex(&s.signature),
        "members": s.members.iter().map(|m| json!({"index": m.index.to_string(), "sig": model::hex(&m.sig),
            "members": inner(m)})).collect::<Vec<_>>()})
}

fn wrap_json(w: &PqWrap) -> Value {
    json!({"member": w.member, "keyId": w.key_id.to_string(), "mlkemCt": model::hex(&w.mlkem_ct),
        "x25519Eph": w.x25519_eph, "sealedKey": model::hex(&w.sealed_key)})
}

fn members_json(m: &[PqMemberKey]) -> Vec<Value> {
    m.iter()
        .map(|k| json!({"ua": k.ua, "keyId": k.key_id.to_string(), "via": k.via}))
        .collect()
}

fn as_members(m: &[PqMemberKey]) -> Vec<Member> {
    m.iter()
        .map(|k| Member {
            ua: k.ua.clone(),
            key_id: k.key_id,
            via: k.via.clone(),
        })
        .collect()
}

/// The seed of a single UA key; an `msig` author is out of this round (CLI-PQC-02).
pub(crate) fn seed_of(k: &KeyRef) -> Result<&str, PqChatError> {
    match k {
        KeyRef::Ua { seed, .. } => Ok(seed),
        KeyRef::Msig { .. } => Err(PqChatError::MsigAuthorPlanned),
        _ => Err(PqChatError::NotMember),
    }
}

/// The members and wraps of a record being built.
struct Wrapped {
    keys: Vec<PqMemberKey>,
    wraps: Vec<PqWrap>,
    skipped: Vec<Skipped>,
}

impl PqChat {
    /// `ua`'s `msig` slots accepted now (`msigOf`, `memberAccepted`, trusted reads), `(kind, id)` each; `None` for a UA that
    /// is no `msig` (threshold 0).
    async fn accepted_slots(
        &self,
        chain: &str,
        ua: &str,
    ) -> Result<Option<Vec<(u64, String)>>, PqChatError> {
        let reg = &self.conf(chain)?.registry;
        let v = self
            .net
            .read(chain, reg, "IUARegistry.msigOf", json!({ "ua": ua }))
            .await?;
        let st = at(&v, "0");
        if model::num(at(st, "threshold"))? == 0 {
            return Ok(None);
        }
        let slots = at(st, "members").as_array().ok_or(PqChatError::Internal)?;
        let mut out = vec![];
        for (i, m) in slots.iter().enumerate() {
            let a = self
                .net
                .read(
                    chain,
                    reg,
                    "IUARegistry.memberAccepted",
                    json!({ "ua": ua, "index": i.to_string() }),
                )
                .await?;
            if at(&a, "0") == true {
                out.push((model::num(at(m, "kind"))?, model::h(at(m, "id"))?));
            }
        }
        Ok(Some(out))
    }

    /// The leaves of `uas` (P13, CTR-UA-38): a UA as itself (`via` zero); an `msig` seat as its accepted slots, an accepted
    /// `msig` slot as its own accepted leaves (two levels), each with `via` = the seat; a deeper level is no leaf. A leaf named
    /// twice keeps its first `via` (direct members first). `MembersInvalid` for a seat with no leaf.
    async fn expand(
        &self,
        chain: &str,
        uas: &[String],
    ) -> Result<Vec<(String, String)>, PqChatError> {
        let mut direct = vec![];
        let mut seated = vec![];
        for ua in uas {
            let Some(slots) = self.accepted_slots(chain, ua).await? else {
                direct.push((ua.clone(), ZERO32.to_string()));
                continue;
            };
            let mut leaves = vec![];
            for (kind, id) in slots {
                if kind != MSIG {
                    leaves.push(id);
                    continue;
                }
                for (k2, id2) in self.accepted_slots(chain, &id).await?.unwrap_or_default() {
                    if k2 != MSIG {
                        leaves.push(id2);
                    }
                }
            }
            if leaves.is_empty() {
                return Err(PqChatError::MembersInvalid);
            }
            seated.extend(leaves.into_iter().map(|l| (l, ua.clone())));
        }
        let mut out: Vec<(String, String)> = vec![];
        for (ua, via) in direct.into_iter().chain(seated) {
            if !out.iter().any(|(u, _)| *u == ua) {
                out.push((ua, via));
            }
        }
        out.sort();
        Ok(out)
    }

    /// The highest KEM version of `ua` (a trusted read, kept in the store); a raised one is an event, never a rekey.
    async fn member_kem(&self, chain: &str, session: &str, ua: &str) -> Result<u64, PqChatError> {
        let (v, raised) = self.kem_version(chain, ua).await?;
        if raised {
            self.event(Event::KemVersionRaised {
                session: session.to_string(),
                member: ua.to_string(),
            });
        }
        Ok(v)
    }

    /// `members` expanded and `k` wrapped to each leaf at its highest KEM version; a leaf without a usable key
    /// (`KemKeyMissing`) or whose key P14 refuses (`KemKeyInvalid`) skipped and named; a seat left with no leaf
    /// `MembersInvalid`; every other error stops.
    async fn wrap_members(
        &self,
        chain: &str,
        k: &Arc<AppKey>,
        session_id: &str,
        epoch_id: &str,
        members: &[String],
    ) -> Result<Wrapped, PqChatError> {
        let mut w = Wrapped {
            keys: vec![],
            wraps: vec![],
            skipped: vec![],
        };
        for (ua, via) in self.expand(chain, members).await? {
            let wrap = match self.member_kem(chain, session_id, &ua).await {
                Ok(v) => self
                    .app
                    .pqchat_wrap(
                        chain.into(),
                        k.clone(),
                        session_id.into(),
                        epoch_id.into(),
                        ua.clone(),
                        v,
                    )
                    .await
                    .map_err(PqChatError::from)
                    .map(|x| (v, x)),
                Err(e) => Err(e),
            };
            match wrap {
                Ok((v, x)) => {
                    w.keys.push(PqMemberKey {
                        ua: ua.clone(),
                        key_id: v,
                        via: via.clone(),
                    });
                    w.wraps.push(x);
                }
                Err(e @ (PqChatError::KemKeyMissing | PqChatError::KemKeyInvalid)) => {
                    w.skipped.push(Skipped {
                        ua,
                        via,
                        code: e.code(),
                    })
                }
                Err(e) => return Err(e),
            }
        }
        let kept = |s: &str| w.keys.iter().any(|m| m.via == s);
        if w.skipped.iter().any(|s| s.via != ZERO32 && !kept(&s.via)) {
            return Err(PqChatError::MembersInvalid);
        }
        Ok(w)
    }

    /// Builds and signs a session (S1) and prepares `createSession` with as many wraps as the quote accepts.
    pub async fn create(&self, r: CreateSession) -> Result<Built, PqChatError> {
        let seed = seed_of(&r.me.key)?;
        let me = r.me.ua.to_ascii_lowercase();
        let members = sorted(&r.members, Some(&me))?;
        let admins = sorted(&r.admins, Some(&me))?;
        check_stores(&r.info)?;
        self.require_listed(&r.chain, &r.home).await?;
        if self.conf.require_signed_records
            && self.sig_store(&r.chain, &r.home).await != Ok(crate::signed::SIG_SSTORE2)
        {
            return Err(PqChatError::HomeUnsigned);
        }
        let c = self.conf(&r.chain)?.clone();
        let sid = self.app.pqchat_session_id(me.clone(), r.nonce)?;
        // only a room this client created for the session, bound to it before anything is signed (CLI-PQC-05)
        if let Some(room) = crate::matrix::room_of(&r.info.stores) {
            self.bind_created(room, &sid)?;
        }
        // the creator's own session: accepted on this device
        self.set_consent(
            &SessionRef {
                chain: r.chain.clone(),
                home: r.home.to_ascii_lowercase(),
                session_id: sid.clone(),
            },
            crate::consent::Consent::Accepted,
            true,
        )?;
        let k = self.app.pqchat_epoch_key(seed)?;
        let w = self
            .wrap_members(&r.chain, &k, &sid, &sid, &members)
            .await?;
        if let Some(s) = w.skipped.iter().find(|s| s.ua == me) {
            return Err(match s.code {
                "KemKeyMissing" => PqChatError::KemKeyMissing,
                _ => PqChatError::KemKeyInvalid,
            });
        }
        if w.keys.len() < 2 || !w.keys.iter().any(|m| m.ua == me) {
            return Err(PqChatError::MembersInvalid);
        }
        let info_json = serde_json::to_string(&r.info).map_err(|_| PqChatError::Internal)?;
        let signed = self
            .app
            .pqchat_sign_session(
                r.me.key.clone(),
                k.clone(),
                PqSessionNew {
                    nonce: r.nonce,
                    home_chain: c.chain_uid.clone(),
                    home_chat_contract: r.home.to_ascii_lowercase(),
                    admins: admins.clone(),
                    members: w.keys.clone(),
                    wraps: w.wraps.clone(),
                    info_json,
                },
            )
            .await?;
        if field(&signed, "message.creator")? != me || signed.id.as_deref() != Some(sid.as_str()) {
            return Err(PqChatError::Internal);
        }
        let sealed = model::unhex(field(&signed, "message.sealedInfo")?)?;
        let s = json!({"creator": me, "nonce": r.nonce.to_string(), "homeChain": c.chain_uid,
            "homeChatContract": r.home.to_ascii_lowercase(), "admins": admins, "members": members_json(&w.keys),
            "wrapHashes": signed.wrap_hashes, "sealedInfo": model::hex(&sealed)});
        let epoch = Epoch {
            id: sid.clone(),
            session_id: sid.clone(),
            author: me,
            nonce: r.nonce,
            epoch: 0,
            parent: ZERO32.into(),
            admins,
            members: as_members(&w.keys),
            wrap_hashes: signed.wrap_hashes.clone(),
            sealed_info: sealed,
            sig_hash: String::new(),
        };
        let sig = sig_json(&signed.sig);
        let wraps = w.wraps;
        let (call, sent) = self
            .fit(&r.chain, &r.home, &r.payer, wraps.len(), "IPqChat.createSession", |n| {
                json!({"s": s, "wraps": wraps.iter().take(n).map(wrap_json).collect::<Vec<_>>(), "sig": sig})
            })
            .await?;
        Ok(Built {
            session_id: sid.clone(),
            epoch_id: sid,
            epoch,
            k,
            wraps,
            signed,
            call,
            sent,
            skipped: w.skipped,
        })
    }

    /// A new epoch of `s` after the open `parent` (S2): `epoch = parent + 1`, a fresh `K`, the members expanded and wrapped
    /// at their highest versions, those who left or were removed dropped. A plain rekey (the parent's members and admins
    /// minus those who left) by a member of the parent; anything else by an admin of it (`NotAdmin`). The author must not
    /// have left nor been removed (`NotMember`); the home's slot must be free (`EpochTaken`: rebuild on the winner,
    /// [`PqChat::child_of`]).
    pub async fn rekey(
        &self,
        s: &SessionRef,
        parent: &OpenEpoch,
        r: Rekey,
    ) -> Result<Built, PqChatError> {
        let seed = seed_of(&r.me.key)?;
        let p = &parent.epoch;
        let ua = r.me.ua.to_ascii_lowercase();
        let left = self.flags(s, p, "IPqChat.leftIn").await?;
        let removed = self.flags(s, p, "IPqChat.removedIn").await?;
        let out = |u: &String| left.contains(u) || removed.contains(u);
        if out(&ua) || !(p.has_member(&ua) || p.admins.contains(&ua)) {
            return Err(PqChatError::NotMember);
        }
        let members: Vec<String> = sorted(&r.members, None)?
            .into_iter()
            .filter(|u| !out(u))
            .collect();
        let admins: Vec<String> = sorted(&r.admins, None)?
            .into_iter()
            .filter(|u| !out(u))
            .collect();
        check_stores(&r.info)?;
        if self.child_of(s, &p.id).await?.is_some() {
            return Err(PqChatError::EpochTaken);
        }
        let eid = self
            .app
            .pqchat_epoch_id(s.session_id.clone(), ua.clone(), r.nonce)?;
        let k = self.app.pqchat_epoch_key(seed)?;
        let w = self
            .wrap_members(&s.chain, &k, &s.session_id, &eid, &members)
            .await?;
        if w.keys.is_empty() {
            return Err(PqChatError::MembersInvalid);
        }
        let kept = |u: &&String| !left.contains(u);
        let plain = w
            .keys
            .iter()
            .map(|m| &m.ua)
            .eq(p.members.iter().map(|m| &m.ua).filter(kept))
            && admins.iter().eq(p.admins.iter().filter(kept));
        if plain && !p.has_member(&ua) {
            return Err(PqChatError::NotMember);
        }
        if !plain && !p.admins.contains(&ua) {
            return Err(PqChatError::NotAdmin);
        }
        let number = p.epoch + 1;
        let info_json = serde_json::to_string(&r.info).map_err(|_| PqChatError::Internal)?;
        let signed = self
            .app
            .pqchat_sign_epoch(
                r.me.key.clone(),
                k.clone(),
                PqEpochNew {
                    session_id: s.session_id.clone(),
                    nonce: r.nonce,
                    epoch: number,
                    parent_epoch_id: p.id.clone(),
                    admins: admins.clone(),
                    members: w.keys.clone(),
                    wraps: w.wraps.clone(),
                    info_json,
                },
            )
            .await?;
        if field(&signed, "message.author")? != ua || signed.id.as_deref() != Some(eid.as_str()) {
            return Err(PqChatError::Internal);
        }
        let sealed = model::unhex(field(&signed, "message.sealedInfo")?)?;
        let e = json!({"sessionId": s.session_id, "author": ua, "nonce": r.nonce.to_string(), "epoch": number.to_string(),
            "parentEpochId": p.id, "admins": admins, "members": members_json(&w.keys), "wrapHashes": signed.wrap_hashes,
            "sealedInfo": model::hex(&sealed)});
        let epoch = Epoch {
            id: eid.clone(),
            session_id: s.session_id.clone(),
            author: ua,
            nonce: r.nonce,
            epoch: number,
            parent: p.id.clone(),
            admins,
            members: as_members(&w.keys),
            wrap_hashes: signed.wrap_hashes.clone(),
            sealed_info: sealed,
            sig_hash: String::new(),
        };
        let sig = sig_json(&signed.sig);
        let wraps = w.wraps;
        let (call, sent) = self
            .fit(&s.chain, &s.home, &r.payer, wraps.len(), "IPqChat.rekey", |n| {
                json!({"e": e, "wraps": wraps.iter().take(n).map(wrap_json).collect::<Vec<_>>(), "sig": sig})
            })
            .await?;
        Ok(Built {
            session_id: s.session_id.clone(),
            epoch_id: eid,
            epoch,
            k,
            wraps,
            signed,
            call,
            sent,
            skipped: w.skipped,
        })
    }

    /// The members and admins of `e` flagged by `item` (`leftIn` or `removedIn`, trusted reads at home).
    async fn flags(
        &self,
        s: &SessionRef,
        e: &Epoch,
        item: &'static str,
    ) -> Result<Vec<String>, PqChatError> {
        let mut out = vec![];
        for m in e.members.iter().map(|m| &m.ua).chain(e.admins.iter()) {
            let v = self
                .net
                .read(
                    &s.chain,
                    &s.home,
                    item,
                    json!({"epochId": e.id, "member": m}),
                )
                .await?;
            if at(&v, "0") == true && !out.contains(m) {
                out.push(m.clone());
            }
        }
        Ok(out)
    }

    /// The child holding `parent`'s slot at home (`childOf`, a trusted read at the final block, R3); `None` while free.
    pub async fn child_of(
        &self,
        s: &SessionRef,
        parent: &str,
    ) -> Result<Option<String>, PqChatError> {
        let v = self
            .net
            .read(
                &s.chain,
                &s.home,
                "IPqChat.childOf",
                json!({"parentEpochId": parent}),
            )
            .await?;
        let c = model::h(at(&v, "0"))?;
        Ok((c != ZERO32).then_some(c))
    }

    /// The next `addWraps` of `b` once its earlier writes landed (`None` when every wrap is in): as many as the quote
    /// accepts. `EpochTaken` when another child of the parent holds the home's slot.
    pub async fn next_wraps(
        &self,
        s: &SessionRef,
        b: &mut Built,
        payer: &KeyRef,
    ) -> Result<Option<AppCall>, PqChatError> {
        if b.sent >= b.wraps.len() {
            return Ok(None);
        }
        if b.epoch.epoch > 0
            && self
                .child_of(s, &b.epoch.parent)
                .await?
                .is_some_and(|c| c != b.epoch_id)
        {
            return Err(PqChatError::EpochTaken);
        }
        let first = b.sent;
        let (eid, wraps) = (&b.epoch_id, &b.wraps);
        let (call, n) = self
            .fit(
                &s.chain,
                &s.home,
                payer,
                wraps.len() - first,
                "IPqChat.addWraps",
                |n| {
                    json!({"epochId": eid, "first": first.to_string(),
                    "wraps": wraps.iter().skip(first).take(n).map(wrap_json).collect::<Vec<_>>()})
                },
            )
            .await?;
        b.sent += n;
        Ok(Some(call))
    }

    /// The write `item` with the most of `n` wraps whose quote the SDK accepts, found by bisection: a quote refused as a
    /// transaction that does not fit (`GasAboveTxCap`: regular gas above the profile's cap or the whole above the block's
    /// limit; `Revert`: the simulation out of gas, which the SDK's endpoint layer gives as a revert without data) bounds it from
    /// above, an accepted one from below; when not even one wrap fits, that refusal. No limit of ours assumed (UA-7 P11).
    async fn fit<F: Fn(usize) -> Value>(
        &self,
        chain: &str,
        home: &str,
        payer: &KeyRef,
        n: usize,
        item: &'static str,
        args: F,
    ) -> Result<(AppCall, usize), PqChatError> {
        let (mut lo, mut hi) = (0, n + 1);
        let (mut best, mut refused) = (None, None);
        let mut take = n;
        loop {
            match self.net.prepare(chain, home, item, args(take), payer).await {
                Ok(c) => {
                    lo = take;
                    best = Some((c, take));
                }
                Err(e) if matches!(e.code(), "GasAboveTxCap" | "Revert") => {
                    hi = take;
                    refused = Some(e);
                }
                Err(e) => return Err(e),
            }
            if hi - lo <= 1 {
                break;
            }
            take = (lo + hi) / 2;
        }
        best.ok_or(refused.unwrap_or(PqChatError::Internal))
    }

    /// An admin's `remove` of `members` from `e` before its next epoch (P48, S3): signed, prepared.
    pub async fn remove(
        &self,
        s: &SessionRef,
        e: &Epoch,
        me: &Me,
        nonce: u64,
        members: &[String],
        payer: &KeyRef,
    ) -> Result<AppCall, PqChatError> {
        seed_of(&me.key)?;
        let ua = me.ua.to_ascii_lowercase();
        if !e.admins.contains(&ua) {
            return Err(PqChatError::NotAdmin);
        }
        let m = sorted(members, None)?;
        if m.is_empty() || m.iter().any(|u| !(e.has_member(u) || e.admins.contains(u))) {
            return Err(PqChatError::MembersInvalid);
        }
        let r = PqChatRemove {
            session_id: s.session_id.clone(),
            epoch_id: e.id.clone(),
            next_epoch: e.epoch + 1,
            members: m.clone(),
            admin: ua.clone(),
            nonce,
        };
        let signed = self.app.sign_pqchat_remove(me.key.clone(), r).await?;
        let a = json!({"r": {"sessionId": s.session_id, "epochId": e.id, "nextEpoch": (e.epoch + 1).to_string(),
            "members": m, "admin": ua, "nonce": nonce.to_string()}, "sig": sig_json(&signed.sig)});
        self.net
            .prepare(&s.chain, &s.home, "IPqChat.remove", a, payer)
            .await
    }

    /// The account's `leave` of `e` (CTR-CHAT-10, S3): signed, prepared.
    pub async fn leave(
        &self,
        s: &SessionRef,
        e: &Epoch,
        me: &Me,
        nonce: u64,
        payer: &KeyRef,
    ) -> Result<AppCall, PqChatError> {
        seed_of(&me.key)?;
        let ua = me.ua.to_ascii_lowercase();
        if !e.has_member(&ua) {
            return Err(PqChatError::NotMember);
        }
        let l = PqChatLeave {
            session_id: s.session_id.clone(),
            epoch_id: e.id.clone(),
            member: ua.clone(),
            nonce,
        };
        let signed = self.app.sign_pqchat_leave(me.key.clone(), l).await?;
        let a = json!({"l": {"sessionId": s.session_id, "epochId": e.id, "member": ua, "nonce": nonce.to_string()},
            "sig": sig_json(&signed.sig)});
        self.net
            .prepare(&s.chain, &s.home, "IPqChat.leave", a, payer)
            .await
    }

    /// The members of `e` whose KEM version rose above the highest seen (trusted reads): each an event
    /// (`KemVersionRaised`); the rekey is a write the user confirms, never started here. A member without a usable key now
    /// is not listed (the next build names it).
    pub async fn kem_changes(&self, s: &SessionRef, e: &Epoch) -> Result<Vec<String>, PqChatError> {
        let mut out = vec![];
        for m in &e.members {
            match self.kem_version(&s.chain, &m.ua).await {
                Ok((_, true)) => {
                    self.event(Event::KemVersionRaised {
                        session: s.session_id.to_ascii_lowercase(),
                        member: m.ua.clone(),
                    });
                    out.push(m.ua.clone());
                }
                Ok(_) | Err(PqChatError::KemKeyMissing) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// A complete child of `parent` seen before its finality (its first sight: an own rekey landed, a record under it read
    /// from a store): sends under `parent` are held from now until the home's final block shows it (CLI-PQC-07).
    pub fn saw_child(&self, parent: &str, child: &str) {
        self.unfinal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(parent.to_ascii_lowercase(), child.to_ascii_lowercase());
    }

    /// The epoch a send of `s` goes under, from `epoch`: its child once the home's final block holds it in the slot
    /// (`childOf`, R3); `EpochNotFinal` while a child was seen and is not final yet; else `epoch`.
    pub async fn send_epoch(&self, s: &SessionRef, epoch: &str) -> Result<String, PqChatError> {
        let epoch = epoch.to_ascii_lowercase();
        if let Some(c) = self.child_of(s, &epoch).await? {
            self.unfinal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&epoch);
            return Ok(c);
        }
        let seen = self
            .unfinal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&epoch)
            .cloned();
        match seen {
            Some(_) => Err(PqChatError::EpochNotFinal),
            None => Ok(epoch),
        }
    }
}

impl Epoch {
    /// The seats and direct members of `self` to list again at the next epoch, so each seat is expanded anew (P13: at every
    /// epoch): the members with `via` zero, then each seat once.
    pub fn seats(&self) -> Vec<String> {
        let mut v: Vec<String> = vec![];
        for m in &self.members {
            let x = if m.via == ZERO32 { &m.ua } else { &m.via };
            if !v.contains(x) {
                v.push(x.clone());
            }
        }
        v
    }
}
