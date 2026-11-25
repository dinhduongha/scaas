// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Signed control-plane records (CLI-PQC-15, owner 2026-11-23 on the spec's O11; CTR-CHAT-23): an instance's signature-storage
//! setting, read under trusted reads and pinned per instance on the device; on an `sstore2` instance every control-plane record
//! the crate uses (session, epoch, the parent's leaves and removals, a posted message) counts only when its author's `UASig`,
//! read from state, verifies over the typed digest the SDK rebuilds from the record's named fields (V1); on a `none` instance
//! the record counts on the contract's check as before, or is refused under `require_signed_records`.
use crate::model::{self, at, Epoch};
use crate::{DropReason, Items, PqChat};
use scaas_sdk::app_core::{AppInnerSig, AppMemberSig, AppUaSig, MsigVersion};
use serde_json::{json, Value};

/// `IPqChat.sigStore()`'s values (PQZ's numbering): `none` keeps each record's `sigHash` only.
pub const SIG_NONE: u64 = 0;
/// `sstore2` keeps each control-plane record's and posted message's signature in state (the default of every new instance).
pub const SIG_SSTORE2: u64 = 2;
/// The most epochs a leave or removal names below the head it is applied at (C9, CTR-CHAT-20, Change 2026-11-24).
pub const EXIT_LAG_MAX: u64 = 16;
/// `PqChat.REMOVE_MAX` (P48): the UAs one removal names at most.
pub const REMOVE_MAX: usize = 16;

/// A `UASig` as the SDK's named JSON gives a view's tuple (`keyData`, `signature`, `members` with `index`, `members`, `sig`).
pub fn ua_sig(v: &Value) -> Result<AppUaSig, DropReason> {
    let d = |_| DropReason::Decode;
    let u16_of = |x: &Value| -> Result<u16, DropReason> {
        u16::try_from(model::num(x).map_err(d)?).map_err(|_| DropReason::Decode)
    };
    let arr = |x: &Value| x.as_array().cloned().ok_or(DropReason::Decode);
    let members = arr(at(v, "members"))?
        .iter()
        .map(|m| {
            Ok(AppMemberSig {
                index: u16_of(at(m, "index"))?,
                members: arr(at(m, "members"))?
                    .iter()
                    .map(|i| {
                        Ok(AppInnerSig {
                            index: u16_of(at(i, "index"))?,
                            sig: model::bytes(at(i, "sig")).map_err(d)?,
                        })
                    })
                    .collect::<Result<_, DropReason>>()?,
                sig: model::bytes(at(m, "sig")).map_err(d)?,
            })
        })
        .collect::<Result<_, DropReason>>()?;
    Ok(AppUaSig {
        key_data: model::bytes(at(v, "keyData")).map_err(d)?,
        signature: model::bytes(at(v, "signature")).map_err(d)?,
        members,
    })
}

/// A record's kept signature as read, verified, and every `(msig, version)` it names (CTR-UA-74 step 6: what the walk holds a
/// session's order by).
#[derive(Debug, Clone)]
pub(crate) struct Kept {
    pub sig: AppUaSig,
    pub versions: Vec<MsigVersion>,
}

/// A view's one output: by its name `sig`, else unnamed (`"0"`).
fn sig_out(v: &Value) -> &Value {
    match v.get("sig") {
        Some(s) => s,
        None => at(v, "0"),
    }
}

impl PqChat {
    /// `contract`'s signature-storage setting (`sigStore()`, a trusted read), pinned in the store on its first answer: the
    /// setting is fixed for the instance's life, so a later different answer is a forged one (`control`), and an endpoint cannot
    /// report `none` for an `sstore2` instance seen before. A value neither 0 nor 2: `control`.
    pub async fn sig_store(&self, chain: &str, contract: &str) -> Result<u64, DropReason> {
        let v = self
            .net
            .read(chain, contract, "IPqChat.sigStore", json!({}))
            .await
            .map_err(|_| DropReason::Decode)?;
        let got = model::num(at(&v, "0")).map_err(|_| DropReason::Decode)?;
        if got != SIG_NONE && got != SIG_SSTORE2 {
            return Err(DropReason::Control);
        }
        let key = format!("sigstore/{chain}/{}", contract.to_ascii_lowercase());
        Items(&*self.store)
            .update::<u64, _>(&key, |seen| match seen {
                Some(s) if s != got => Err(crate::PqChatError::Internal),
                _ => Ok(got),
            })
            .map_err(|_| DropReason::Control)
    }

    /// Whether `contract`'s records are verified by their kept signatures (`sstore2`: true; `none`: false), or refused
    /// (`unsigned`: a `none` instance under `require_signed_records`).
    pub async fn verifies(&self, chain: &str, contract: &str) -> Result<bool, DropReason> {
        match self.sig_store(chain, contract).await? {
            SIG_SSTORE2 => Ok(true),
            _ if self.conf.require_signed_records => Err(DropReason::Unsigned),
            _ => Ok(false),
        }
    }

    /// The record `rec` (the struct `name`'s fields by name, as the view gave them) counts only when `ua`'s signature read by
    /// the view `sig.0` with the arguments `sig.1` verifies over its typed digest (V1, the signer's registry record a trusted
    /// read); else `signature`.
    pub async fn verify_kept(
        &self,
        chain: &str,
        contract: &str,
        ua: &str,
        name: &str,
        rec: &Value,
        read: (&'static str, Value),
    ) -> Result<(), DropReason> {
        self.kept_sig(chain, contract, ua, name, rec, read)
            .await
            .map(|_| ())
    }

    /// [`Self::verify_kept`] with the signature read and the versions it names ([`Kept`]).
    pub(crate) async fn kept_sig(
        &self,
        chain: &str,
        contract: &str,
        ua: &str,
        name: &str,
        rec: &Value,
        (item, args): (&'static str, Value),
    ) -> Result<Kept, DropReason> {
        let v = self
            .net
            .read(chain, contract, item, args)
            .await
            .map_err(|_| DropReason::Signature)?;
        let sig = ua_sig(sig_out(&v))?;
        let versions = self
            .app
            .verify_pqchat_record_versions(
                chain.into(),
                ua.into(),
                name.into(),
                rec.to_string(),
                sig.clone(),
            )
            .await
            .ok()
            .flatten()
            .ok_or(DropReason::Signature)?;
        Ok(Kept { sig, versions })
    }

    /// The session or epoch record `epoch_id` at `contract` with its signature verified and its id recomputed from its fields (an
    /// `sstore2` instance), or as stored (`none`, unless refused): the record a client uses, of the session asked (`control`).
    /// `None` when it is not stored.
    pub async fn signed_record_at(
        &self,
        chain: &str,
        contract: &str,
        session_id: &str,
        epoch_id: &str,
    ) -> Result<Option<Epoch>, DropReason> {
        Ok(self
            .record_kept_at(chain, contract, session_id, epoch_id)
            .await?
            .map(|x| x.0))
    }

    /// [`Self::signed_record_at`] with its kept signature ([`Kept`]; `None` on a `none` instance).
    pub(crate) async fn record_kept_at(
        &self,
        chain: &str,
        contract: &str,
        session_id: &str,
        epoch_id: &str,
    ) -> Result<Option<(Epoch, Option<Kept>)>, DropReason> {
        let verify = self.verifies(chain, contract).await?;
        let session = epoch_id.eq_ignore_ascii_case(session_id);
        let (item, args) = if session {
            ("IPqChat.sessionOf", json!({ "sessionId": session_id }))
        } else {
            ("IPqChat.epochOf", json!({ "epochId": epoch_id }))
        };
        let v = self
            .net
            .read(chain, contract, item, args.clone())
            .await
            .map_err(|_| DropReason::Decode)?;
        let e = if session {
            Epoch::from_session(session_id, &v)
        } else {
            Epoch::from_epoch(epoch_id, &v)
        }
        .map_err(|_| DropReason::Decode)?;
        let Some(e) = e else { return Ok(None) };
        if !session && e.session_id != session_id.to_ascii_lowercase() {
            return Err(DropReason::Control);
        }
        if verify {
            // E-4, D2-1, B2-4: the record is the one its id names (UA-7 §4.3), never one an endpoint put under another id
            let id = if session {
                self.app.pqchat_session_id(e.author.clone(), e.nonce)
            } else {
                self.app
                    .pqchat_epoch_id(e.session_id.clone(), e.author.clone(), e.nonce)
            };
            if !id.is_ok_and(|x| x.eq_ignore_ascii_case(epoch_id)) {
                return Err(DropReason::Control);
            }
            let (name, rec, sig_item) = if session {
                ("PqChatSession", at(&v, "s"), "IPqChat.sessionSig")
            } else {
                ("PqChatEpoch", at(&v, "e"), "IPqChat.epochSig")
            };
            let k = self
                .kept_sig(chain, contract, &e.author, name, rec, (sig_item, args))
                .await?;
            return Ok(Some((e, Some(k))));
        }
        Ok(Some((e, None)))
    }

    /// `p`'s id and those of its ancestors at most [`EXIT_LAG_MAX`] above it, each by [`Self::signed_record_at`] (its id
    /// recomputed, its signature verified) and the next one's parent of `p`'s session, its number one below (D2-1, B2-4): what an
    /// exit kept under `p` may name (CTR-CHAT-20, CTR-CHAT-10: at home a leave or removal names the head or such an ancestor
    /// and is kept under the head it is applied at; C9, Change 2026-11-24). By number below `p`: `out[k]` is `p.epoch - k`.
    pub async fn ancestors(
        &self,
        chain: &str,
        contract: &str,
        p: &Epoch,
    ) -> Result<Vec<String>, DropReason> {
        let mut out = vec![p.id.clone()];
        let mut cur = p.clone();
        while cur.epoch > 0 && (out.len() as u64) <= EXIT_LAG_MAX {
            let e = self
                .signed_record_at(chain, contract, &p.session_id, &cur.parent)
                .await?
                .ok_or(DropReason::Control)?;
            if e.epoch + 1 != cur.epoch {
                return Err(DropReason::Control);
            }
            out.push(e.id.clone());
            cur = e;
        }
        Ok(out)
    }

    /// The members of `p` that left it and those a removal took out of it, on an `sstore2` instance from the `leave` and
    /// `remove` records kept under `p`, each counted only when its signer's signature verifies and it is one the contract
    /// could have accepted at `p` (CLI-PQC-15, E-4): of `p`'s session, naming `p` or an ancestor of it within
    /// [`EXIT_LAG_MAX`] ([`Self::ancestors`]), a leave by a member of `p`; a removal by an admin of `p` of 1 to 16 UAs strictly
    /// sorted, each a member or an admin of `p`, `nextEpoch` the named number plus one. A record that is not one is not
    /// counted; on a `none` instance from the flags (`leftIn`, `removedIn`) as the contract set them.
    pub async fn left_and_removed(
        &self,
        chain: &str,
        contract: &str,
        p: &Epoch,
    ) -> Result<(Vec<String>, Vec<String>), DropReason> {
        let (left, removed, _) = self.exits_of(chain, contract, p, None).await?;
        Ok((left, removed))
    }

    /// [`Self::left_and_removed`] with `p`'s [`Self::ancestors`] when the caller holds them (the walk, `reads.rs`), and per exit
    /// counted the `(msig, version)`s its signature names (CTR-UA-74 step 6; none on a `none` instance).
    pub(crate) async fn exits_of(
        &self,
        chain: &str,
        contract: &str,
        p: &Epoch,
        names: Option<Vec<String>>,
    ) -> Result<(Vec<String>, Vec<String>, Vec<Vec<MsigVersion>>), DropReason> {
        let (mut left, mut removed, mut versions) = (vec![], vec![], vec![]);
        let d = |_| DropReason::Decode;
        if !self.verifies(chain, contract).await? {
            for m in p
                .members
                .iter()
                .map(|m| m.ua.clone())
                .chain(p.admins.iter().cloned())
            {
                let a = json!({ "epochId": p.id, "member": m });
                let l = self
                    .net
                    .read(chain, contract, "IPqChat.leftIn", a.clone())
                    .await
                    .map_err(d)?;
                let r = self
                    .net
                    .read(chain, contract, "IPqChat.removedIn", a)
                    .await
                    .map_err(d)?;
                if at(&l, "0") == true {
                    left.push(m.clone());
                }
                if at(&r, "0") == true {
                    removed.push(m);
                }
            }
            return Ok((left, removed, versions));
        }
        // B2-4: each record newly flags a UA of `p` (the contract refuses a repeat), so no more than its UAs
        let most = (crate::check::distinct(p).len() + p.admins.len()) as u64;
        let count = |item: &'static str| async move {
            let v = self
                .net
                .read(chain, contract, item, json!({ "epochId": p.id }))
                .await
                .map_err(d)?;
            let n = model::num(at(&v, "0")).map_err(d)?;
            if n > most {
                return Err(DropReason::Control);
            }
            Ok(n)
        };
        // the ancestors are read only when a record names another epoch than `p`; the named epoch's number, else `None`
        let mut names = names;
        let mut named = async |r: &Value| -> Result<Option<u64>, DropReason> {
            let (Ok(sid), Ok(eid)) = (model::h(at(r, "sessionId")), model::h(at(r, "epochId")))
            else {
                return Ok(None);
            };
            if sid != p.session_id {
                return Ok(None);
            }
            if eid == p.id {
                return Ok(Some(p.epoch));
            }
            if names.is_none() {
                names = Some(self.ancestors(chain, contract, p).await?);
            }
            let k = names
                .as_ref()
                .and_then(|n| n.iter().position(|x| *x == eid));
            // C-2: a name below epoch 0 is no epoch of the session
            k.map(|k| p.epoch.checked_sub(k as u64).ok_or(DropReason::Control))
                .transpose()
        };
        for i in 0..count("IPqChat.leaveCount").await? {
            let a = json!({ "epochId": p.id, "index": i.to_string() });
            let v = self
                .net
                .read(chain, contract, "IPqChat.leaveAt", a.clone())
                .await
                .map_err(d)?;
            let l = at(&v, "l");
            let member = model::h(at(l, "member")).map_err(d)?;
            if named(l).await?.is_some() && p.has_member(&member) {
                let k = self
                    .kept_sig(
                        chain,
                        contract,
                        &member,
                        "PqChatLeave",
                        l,
                        ("IPqChat.leaveSig", a),
                    )
                    .await?;
                versions.push(k.versions);
                left.push(member);
            }
        }
        for i in 0..count("IPqChat.removalCount").await? {
            let a = json!({ "epochId": p.id, "index": i.to_string() });
            let v = self
                .net
                .read(chain, contract, "IPqChat.removalAt", a.clone())
                .await
                .map_err(d)?;
            let r = at(&v, "r");
            let admin = model::h(at(r, "admin")).map_err(d)?;
            let members = model::list(at(r, "members")).map_err(d)?;
            let next = model::num(at(r, "nextEpoch")).map_err(d)?;
            let ok = (1..=REMOVE_MAX).contains(&members.len())
                && crate::check::strictly_sorted(members.iter().map(String::as_str))
                && p.admins.contains(&admin)
                && members
                    .iter()
                    .all(|m| p.has_member(m) || p.admins.contains(m));
            if ok
                && named(r)
                    .await?
                    .is_some_and(|n| n.checked_add(1) == Some(next))
            {
                let k = self
                    .kept_sig(
                        chain,
                        contract,
                        &admin,
                        "PqChatRemove",
                        r,
                        ("IPqChat.removalSig", a),
                    )
                    .await?;
                versions.push(k.versions);
                removed.extend(members);
            }
        }
        Ok((left, removed, versions))
    }
}
