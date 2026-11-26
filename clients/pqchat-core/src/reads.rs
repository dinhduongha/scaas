// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Trusted reads, instances and replicas (CLI-PQC-07, CLI-PQC-13): the factory's listing, the control-plane records at an
//! instance, a replica against its home, the highest KEM version seen per UA, and an own wrap opened only after its hash check.
use crate::check::{self, DropReason};
use crate::model::at;
use crate::model::{self, Epoch};
use crate::signed::Kept;
use crate::signed::EXIT_LAG_MAX;
use crate::{Items, PqChat, PqChatError};
use scaas_sdk::app_core::{msig_versions_up, AppKey, AppUaSig};
use scaas_sdk::op::KeyRef;
use scaas_sdk::pqchat_records::PqWrap;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;

/// `IUARegistry.checkedOf`'s `kem` value of a UA without a usable KEM key.
pub const KEM_NONE: u64 = 0;

impl PqChat {
    /// Whether `chain`'s factory lists `contract` as class 3 (`PqChat`) with version ≠ 0 (a trusted read).
    pub async fn listed(&self, chain: &str, contract: &str) -> Result<bool, PqChatError> {
        let c = self.conf(chain)?;
        let v = self
            .net
            .read(
                chain,
                &c.factory,
                "IOpenFactory.infoOf",
                json!({ "c": contract }),
            )
            .await?;
        let i = &at(&v, "0");
        let same = model::h(at(i, "addr")).is_ok_and(|a| a == contract.to_ascii_lowercase());
        Ok(same && model::num(at(i, "contractClass"))? == 3 && model::num(at(i, "version"))? != 0)
    }

    /// [`PqChat::listed`] for the user's own action: `InstanceUnlisted` otherwise.
    pub async fn require_listed(&self, chain: &str, contract: &str) -> Result<(), PqChatError> {
        if self.listed(chain, contract).await? {
            Ok(())
        } else {
            Err(PqChatError::InstanceUnlisted)
        }
    }

    /// The session record (`epoch_id` = `session_id`) or epoch record stored at `contract`, `None` when absent.
    pub async fn record_at(
        &self,
        chain: &str,
        contract: &str,
        session_id: &str,
        epoch_id: &str,
    ) -> Result<Option<Epoch>, PqChatError> {
        if epoch_id.eq_ignore_ascii_case(session_id) {
            let v = self
                .net
                .read(
                    chain,
                    contract,
                    "IPqChat.sessionOf",
                    json!({ "sessionId": session_id }),
                )
                .await?;
            Epoch::from_session(session_id, &v)
        } else {
            let v = self
                .net
                .read(
                    chain,
                    contract,
                    "IPqChat.epochOf",
                    json!({ "epochId": epoch_id }),
                )
                .await?;
            Epoch::from_epoch(epoch_id, &v)
        }
    }

    /// A record read at a replica counts only when it equals the home's record and `sigHash` under the same id (P32).
    pub fn replica(home: &Epoch, rep: &Epoch) -> Result<(), DropReason> {
        if home == rep {
            Ok(())
        } else {
            Err(DropReason::Replica)
        }
    }

    /// A-1 (CTR-UA-74, CTR-CHAT-20): [`Self::replica`] when both instances keep signatures (`home_sig`, `rep_sig`): the record
    /// equal under the same id and the two kept signatures equal with their `msig` version tags stripped
    /// ([`AppUaSig::without_tags`]), since a copy carries the tag of the replica registry's current version and so another
    /// `sigHash`; the signed content and every other signature byte the home's. Either kept signature absent: [`Self::replica`].
    #[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
    pub fn replica_kept(
        home: &Epoch,
        home_sig: Option<&AppUaSig>,
        rep: &Epoch,
        rep_sig: Option<&AppUaSig>,
    ) -> Result<(), DropReason> {
        let (Some(a), Some(b)) = (home_sig, rep_sig) else {
            return Self::replica(home, rep);
        };
        let unhashed = |e: &Epoch| Epoch {
            sig_hash: String::new(),
            ..e.clone()
        };
        if unhashed(home) == unhashed(rep) && a.without_tags() == b.without_tags() {
            Ok(())
        } else {
            Err(DropReason::Replica)
        }
    }

    /// The KEM version `ua` holds now (`kemKeyOf`, trusted), held to the highest seen and kept in the store: a lower one
    /// `KemVersionLowered`; a member without a usable key (`checkedOf.kem` `NONE`, or none) `KemKeyMissing`. The answer and
    /// whether it raised the highest seen.
    pub async fn kem_version(&self, chain: &str, ua: &str) -> Result<(u64, bool), PqChatError> {
        let c = self.conf(chain)?;
        let ck = self
            .net
            .read(
                chain,
                &c.registry,
                "IUARegistry.checkedOf",
                json!({ "ua": ua }),
            )
            .await?;
        if model::num(at(&ck, "kem"))? == KEM_NONE {
            return Err(PqChatError::KemKeyMissing);
        }
        let v = self
            .net
            .read(
                chain,
                &c.registry,
                "IUARegistry.kemKeyOf",
                json!({ "ua": ua }),
            )
            .await?;
        let version = model::num(at(&v, "version"))?;
        // an all-zero key is no key (a version may be 0: the registration's own)
        if model::num(at(at(&v, "kem"), "scheme"))? == 0 {
            return Err(PqChatError::KemKeyMissing);
        }
        let key = format!("kem/{chain}/{}", ua.to_ascii_lowercase());
        let mut raised = false;
        let kept = Items(&*self.store).update::<u64, _>(&key, |high| {
            raised = high.is_some_and(|h| version > h);
            if high.is_some_and(|h| version < h) {
                return Err(PqChatError::KemVersionLowered);
            }
            Ok(version)
        })?;
        Ok((kept, raised))
    }

    /// The account's own wrap of `e` at `contract`, read from state (trusted), checked against the signed record's
    /// `wrapHashes[i]` before it enters a decapsulation (`wrap-hash`), then opened by the account's KEM key: the epoch key.
    /// `member` when the account is not a member; `envelope` when no own wrap opens (shown, never answered). A member with
    /// several keys (CTR-CHAT-24) has one wrap per key: each is tried in order, the first that opens is used (a device key
    /// this account does not hold is skipped).
    #[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
    pub async fn open_own_wrap(
        &self,
        chain: &str,
        contract: &str,
        e: &Epoch,
        account: &KeyRef,
        me: &str,
    ) -> Result<Arc<AppKey>, DropReason> {
        let mine: Vec<usize> = e
            .members
            .iter()
            .enumerate()
            .filter_map(|(i, m)| (m.ua == me).then_some(i))
            .collect();
        if mine.is_empty() {
            return Err(DropReason::Member);
        }
        let mut last = DropReason::Envelope;
        for i in mine {
            match self.open_wrap_at(chain, contract, e, account, i).await {
                Ok(k) => return Ok(k),
                Err(d) => last = d,
            }
        }
        Err(last)
    }

    /// [`PqChat::open_own_wrap`]'s wrap `i`.
    async fn open_wrap_at(
        &self,
        chain: &str,
        contract: &str,
        e: &Epoch,
        account: &KeyRef,
        i: usize,
    ) -> Result<Arc<AppKey>, DropReason> {
        let v = self
            .net
            .read(
                chain,
                contract,
                "IPqChat.wrapAt",
                json!({ "epochId": e.id, "i": i.to_string() }),
            )
            .await
            .map_err(|_| DropReason::Decode)?;
        let w = &at(&v, "0");
        let wrap = PqWrap {
            member: model::h(at(w, "member")).map_err(|_| DropReason::Decode)?,
            key_id: model::num(at(w, "keyId")).map_err(|_| DropReason::Decode)?,
            mlkem_ct: model::bytes(at(w, "mlkemCt")).map_err(|_| DropReason::Decode)?,
            x25519_eph: model::h(at(w, "x25519Eph")).map_err(|_| DropReason::Decode)?,
            sealed_key: model::bytes(at(w, "sealedKey")).map_err(|_| DropReason::Decode)?,
        };
        let read = self
            .app
            .pqchat_wrap_hash(wrap.clone())
            .map_err(|_| DropReason::Decode)?;
        let signed = e.wrap_hashes.get(i).ok_or(DropReason::WrapHash)?;
        check::wrap_hash(&read, signed)?;
        self.unwraps
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.app
            .pqchat_unwrap(account.clone(), e.session_id.clone(), e.id.clone(), wrap)
            .map_err(|_| DropReason::Envelope)
    }
}

/// Where a session lives: the SDK profile of its home chain and its home instance (fixed for its life, UA-7 §4.2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionRef {
    pub chain: String,
    pub home: String,
    pub session_id: String,
}

impl PqChat {
    /// The epoch `epoch_id` of `s` opened for `account` (UA `me`): the home instance listed (`unlisted`), the record read at
    /// home and checked (`control`: the shapes, and a child against its parent with the parent's leaves and removals; on an
    /// `sstore2` instance each with its kept signature, `signature`, CLI-PQC-15; a `none` one `unsigned` when required), equal at `replica` when one is named (`replica`), the own wrap checked and opened. Membership
    /// is the home's record, never a replica's.
    pub async fn open_epoch(
        &self,
        s: &SessionRef,
        epoch_id: &str,
        account: &KeyRef,
        me: &str,
        replica: Option<String>,
    ) -> Result<crate::message::OpenEpoch, DropReason> {
        let r = self
            .open_epoch_inner(s, epoch_id, account, me, replica.as_deref())
            .await;
        if let Err(d) = &r {
            self.drops.add(&s.session_id.to_ascii_lowercase(), *d);
        }
        r
    }

    async fn open_epoch_inner(
        &self,
        s: &SessionRef,
        epoch_id: &str,
        account: &KeyRef,
        me: &str,
        replica: Option<&str>,
    ) -> Result<crate::message::OpenEpoch, DropReason> {
        let (home, home_kept) = self.checked_at(s, &s.home, epoch_id, true).await?;
        if let Some(rep) = replica {
            // E-5, D2-2: the replica's record counts only when it equals the home's, judged above (membership is the home's,
            // CTR-CHAT-14); a replica keeps an exit under the epoch it names, so its parent's exits are not read there. A-1: the
            // kept signatures compared without their `msig` version tags
            let (r, rep_kept) = self.checked_at(s, rep, epoch_id, false).await?;
            Self::replica_kept(
                &home,
                home_kept.as_ref().map(|k| &k.sig),
                &r,
                rep_kept.as_ref().map(|k| &k.sig),
            )?;
        }
        let k = self
            .open_own_wrap(&s.chain, &s.home, &home, account, me)
            .await?;
        Ok(crate::message::OpenEpoch {
            chain: s.chain.clone(),
            epoch: home,
            k,
        })
    }

    /// The record `epoch_id` of `s` at `contract`, listed and checked; with `judge`, against its parent at the same instance: on
    /// a `none` instance the one link on the contract's flags; on an `sstore2` one by [`Self::walk`].
    async fn checked_at(
        &self,
        s: &SessionRef,
        contract: &str,
        epoch_id: &str,
        judge: bool,
    ) -> Result<(Epoch, Option<Kept>), DropReason> {
        if !self
            .listed(&s.chain, contract)
            .await
            .map_err(|_| DropReason::Unlisted)?
        {
            return Err(DropReason::Unlisted);
        }
        // CLI-PQC-15: on an `sstore2` instance each record counts only with its author's kept signature; a `none` one is
        // refused under `require_signed_records`
        let (e, k) = self.read_at(s, contract, epoch_id).await?;
        if e.session_id != s.session_id.to_ascii_lowercase() {
            return Err(DropReason::Control);
        }
        check::shapes(&e)?;
        if !judge {
            return Ok((e, k));
        }
        if let Some(k) = k {
            return self.walk(s, contract, e, k).await;
        }
        if e.epoch == 0 {
            return Ok((e, None));
        }
        let (p, _) = self.read_at(s, contract, &e.parent).await?;
        let (left, removed) = self.left_and_removed(&s.chain, contract, &p).await?;
        check::child(&e, &p, &left, &removed)?;
        Ok((e, None))
    }

    async fn read_at(
        &self,
        s: &SessionRef,
        contract: &str,
        id: &str,
    ) -> Result<(Epoch, Option<Kept>), DropReason> {
        self.record_kept_at(&s.chain, contract, &s.session_id, id)
            .await?
            .ok_or(DropReason::Control)
    }

    /// U-1, D2-1 (an `sstore2` instance): `e` and its ancestors down to the signed session record, or to an epoch this device
    /// verified before at this instance, each record bound to its id and each link judged by [`check::child`] with the exits its
    /// parent keeps, named among the parent's verified ancestors. So an endpoint cannot serve a parent of its choosing: every
    /// right comes from the session's creator down. The verified epochs are remembered (id → number, parent and the record's
    /// hash), so a device walks each epoch once; a remembered id read again counts only as the same record (C-1: an author may
    /// sign another record under the same id), else `control`. Each parent read is numbered one below its child (C-2), so a
    /// record naming itself or a later one ends the walk. CTR-UA-74 step 6 (C-3): along the session, oldest first, no `msig`
    /// signs an epoch with a version below the highest one the session's verified records named (kept with the epochs), the
    /// exits kept under an epoch judged order-free against the versions after it; one below is `control`. ponytail: one
    /// store item per session, one entry per epoch; prune when histories grow large.
    async fn walk(
        &self,
        s: &SessionRef,
        contract: &str,
        e: Epoch,
        k: Kept,
    ) -> Result<(Epoch, Option<Kept>), DropReason> {
        let key = format!(
            "verified/{}/{}/{}",
            s.chain,
            contract.to_ascii_lowercase(),
            s.session_id.to_ascii_lowercase()
        );
        let items = Items(&*self.store);
        let mut w: Walked = items
            .get(&key)
            .map_err(|_| DropReason::Control)?
            .unwrap_or_default();
        let mut chain = vec![(e, k)];
        // whether the last record of `chain` is one remembered (the walk's stop)
        let mut stop = false;
        while let Some((cur, _)) = chain.last() {
            if let Some((_, _, h)) = w.epochs.get(&cur.id) {
                if *h != record_hash(cur)? {
                    return Err(DropReason::Control);
                }
                stop = true;
                break;
            }
            if cur.epoch == 0 {
                break;
            }
            let (p, pk) = self.read_at(s, contract, &cur.parent).await?;
            check::shapes(&p)?;
            if p.epoch.checked_add(1) != Some(cur.epoch) {
                return Err(DropReason::Control);
            }
            chain.push((p, pk.ok_or(DropReason::Control)?));
        }
        // the ids by number down from `e`: the records read, then the remembered ones by their parent links
        let mut ids: Vec<String> = chain.iter().map(|x| x.0.id.clone()).collect();
        let mut x = ids.last().cloned().unwrap_or_default();
        while ids.len() < chain.len() + EXIT_LAG_MAX as usize {
            match w.epochs.get(&x) {
                Some((n, parent, _)) if *n > 0 => {
                    ids.push(parent.clone());
                    x = parent.clone();
                }
                _ => break,
            }
        }
        // per link `i` (child `i`, parent `i + 1`) the versions of the exits kept under the parent
        let mut exits = Vec::new();
        for (i, pair) in chain.windows(2).enumerate() {
            let [(c, _), (p, _)] = pair else { continue };
            let names = ids
                .iter()
                .skip(i + 1)
                .take(EXIT_LAG_MAX as usize + 1)
                .cloned()
                .collect();
            let (left, removed, v) = self.exits_of(&s.chain, contract, p, Some(names)).await?;
            check::child(c, p, &left, &removed)?;
            exits.push(v);
        }
        // step 6, oldest first: each new record, then the exits kept under it before its child
        for i in (0..chain.len()).rev() {
            let (_, k) = chain.get(i).ok_or(DropReason::Control)?;
            let remembered = stop && i + 1 == chain.len();
            if !remembered && !msig_versions_up(&mut w.msig, &k.versions) {
                return Err(DropReason::Control);
            }
            if let Some(under) = i.checked_sub(1).and_then(|j| exits.get(j)) {
                let floor = w.msig.clone();
                for v in under {
                    let mut f = floor.clone();
                    if !msig_versions_up(&mut f, v) {
                        return Err(DropReason::Control);
                    }
                    for (m, n) in f {
                        let e = w.msig.entry(m).or_insert(0);
                        *e = (*e).max(n);
                    }
                }
            }
        }
        for (c, _) in &chain {
            w.epochs
                .insert(c.id.clone(), (c.epoch, c.parent.clone(), record_hash(c)?));
        }
        items
            .update::<Walked, _>(&key, |old| {
                let mut m = old.unwrap_or_default();
                m.epochs.extend(w.epochs.clone());
                for (u, v) in &w.msig {
                    let e = m.msig.entry(u.clone()).or_insert(0);
                    *e = (*e).max(*v);
                }
                Ok(m)
            })
            .map_err(|_| DropReason::Control)?;
        let (e, k) = chain.into_iter().next().ok_or(DropReason::Control)?;
        Ok((e, Some(k)))
    }
}

/// The walk's memory of one session at one instance: per verified epoch id its number, parent and record hash
/// ([`record_hash`], C-1); per `msig` the highest structure version the session's verified records named (CTR-UA-74 step 6, C-3).
#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
struct Walked {
    epochs: BTreeMap<String, (u64, String, String)>,
    msig: BTreeMap<String, u64>,
}

/// SHA-256 of the record as read (its named fields and `sigHash`, in the struct's fixed order): what a remembered id binds.
fn record_hash(e: &Epoch) -> Result<String, DropReason> {
    use sha2::Digest as _;
    let b = serde_json::to_vec(e).map_err(|_| DropReason::Control)?;
    Ok(sha2::Sha256::digest(&b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect())
}
