// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Signed control-plane records (CLI-PQC-15, owner 2026-11-23 on the spec's O11; CTR-CHAT-23): an instance's signature-storage
//! setting, read under trusted reads and pinned per instance on the device; on an `sstore2` instance every control-plane record
//! the crate uses (session, epoch, the parent's leaves and removals, a posted message) counts only when its author's `UASig`,
//! read from state, verifies over the typed digest the SDK rebuilds from the record's named fields (V1); on a `none` instance
//! the record counts on the contract's check as before, or is refused under `require_signed_records`.
use crate::model::{self, at, Epoch};
use crate::{DropReason, Items, PqChat};
use scaas_sdk::app_core::{AppInnerSig, AppMemberSig, AppUaSig};
use serde_json::{json, Value};

/// `IPqChat.sigStore()`'s values (PQZ's numbering): `none` keeps each record's `sigHash` only.
pub const SIG_NONE: u64 = 0;
/// `sstore2` keeps each control-plane record's and posted message's signature in state (the default of every new instance).
pub const SIG_SSTORE2: u64 = 2;

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
        (item, args): (&'static str, Value),
    ) -> Result<(), DropReason> {
        let v = self
            .net
            .read(chain, contract, item, args)
            .await
            .map_err(|_| DropReason::Signature)?;
        let sig = ua_sig(sig_out(&v))?;
        let ok = self
            .app
            .verify_pqchat_record(chain.into(), ua.into(), name.into(), rec.to_string(), sig)
            .await
            .unwrap_or(false);
        if ok {
            Ok(())
        } else {
            Err(DropReason::Signature)
        }
    }

    /// The session or epoch record `epoch_id` at `contract` with its signature verified (an `sstore2` instance) or as stored
    /// (`none`, unless refused): the record a client uses. `None` when it is not stored.
    pub async fn signed_record_at(
        &self,
        chain: &str,
        contract: &str,
        session_id: &str,
        epoch_id: &str,
    ) -> Result<Option<Epoch>, DropReason> {
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
        if verify {
            let (name, rec, sig_item) = if session {
                ("PqChatSession", at(&v, "s"), "IPqChat.sessionSig")
            } else {
                ("PqChatEpoch", at(&v, "e"), "IPqChat.epochSig")
            };
            self.verify_kept(chain, contract, &e.author, name, rec, (sig_item, args))
                .await?;
        }
        Ok(Some(e))
    }

    /// The members of `p` that left it and those a removal took out of it, on an `sstore2` instance from its kept `leave` and
    /// `remove` records, each counted only when its signer's signature verifies and it names `p` (an endpoint cannot make a
    /// non-admin's membership change look plain by reporting a leave nobody signed); on a `none` instance from the flags
    /// (`leftIn`, `removedIn`) as the contract set them.
    pub async fn left_and_removed(
        &self,
        chain: &str,
        contract: &str,
        p: &Epoch,
    ) -> Result<(Vec<String>, Vec<String>), DropReason> {
        let (mut left, mut removed) = (vec![], vec![]);
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
            return Ok((left, removed));
        }
        let count = |item: &'static str| async move {
            let v = self
                .net
                .read(chain, contract, item, json!({ "epochId": p.id }))
                .await
                .map_err(d)?;
            model::num(at(&v, "0")).map_err(d)
        };
        let mine = |r: &Value| {
            model::h(at(r, "sessionId")).is_ok_and(|x| x == p.session_id)
                && model::h(at(r, "epochId")).is_ok_and(|x| x == p.id)
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
            if mine(l) {
                self.verify_kept(
                    chain,
                    contract,
                    &member,
                    "PqChatLeave",
                    l,
                    ("IPqChat.leaveSig", a),
                )
                .await?;
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
            if mine(r) {
                self.verify_kept(
                    chain,
                    contract,
                    &admin,
                    "PqChatRemove",
                    r,
                    ("IPqChat.removalSig", a),
                )
                .await?;
                removed.extend(model::list(at(r, "members")).map_err(d)?);
            }
        }
        Ok((left, removed))
    }
}
