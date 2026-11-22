// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Trusted reads, instances and replicas (CLI-PQC-07, CLI-PQC-13): the factory's listing, the control-plane records at an
//! instance, a replica against its home, the highest KEM version seen per UA, and an own wrap opened only after its hash check.
use crate::check::{self, Drop};
use crate::model::at;
use crate::model::{self, Epoch};
use crate::{Items, PqChat, PqChatError};
use scaas_sdk::app_core::AppKey;
use scaas_sdk::op::KeyRef;
use scaas_sdk::pqchat_records::PqWrap;
use serde_json::json;
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
    pub fn replica(home: &Epoch, rep: &Epoch) -> Result<(), Drop> {
        if home == rep {
            Ok(())
        } else {
            Err(Drop::Replica)
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
        Items(&*self.store).update::<u64, _>(&key, |high| {
            raised = high.is_some_and(|h| version > h);
            if high.is_some_and(|h| version < h) {
                return Err(PqChatError::KemVersionLowered);
            }
            Ok(version)
        })?;
        Ok((version, raised))
    }

    /// The account's own wrap of `e` at `contract`, read from state (trusted), checked against the signed record's
    /// `wrapHashes[i]` before it enters a decapsulation (`wrap-hash`), then opened by the account's KEM key: the epoch key.
    /// `member` when the account is not a member; `envelope` when the wrap does not open (shown, never answered).
    pub async fn open_own_wrap(
        &self,
        chain: &str,
        contract: &str,
        e: &Epoch,
        account: &KeyRef,
        me: &str,
    ) -> Result<Arc<AppKey>, Drop> {
        let i = e.index_of(me).ok_or(Drop::Member)?;
        let v = self
            .net
            .read(
                chain,
                contract,
                "IPqChat.wrapAt",
                json!({ "epochId": e.id, "i": i.to_string() }),
            )
            .await
            .map_err(|_| Drop::Decode)?;
        let w = &at(&v, "0");
        let wrap = PqWrap {
            member: model::h(at(w, "member")).map_err(|_| Drop::Decode)?,
            key_id: model::num(at(w, "keyId")).map_err(|_| Drop::Decode)?,
            mlkem_ct: model::bytes(at(w, "mlkemCt")).map_err(|_| Drop::Decode)?,
            x25519_eph: model::h(at(w, "x25519Eph")).map_err(|_| Drop::Decode)?,
            sealed_key: model::bytes(at(w, "sealedKey")).map_err(|_| Drop::Decode)?,
        };
        let read = self
            .app
            .pqchat_wrap_hash(wrap.clone())
            .map_err(|_| Drop::Decode)?;
        let signed = e.wrap_hashes.get(i).ok_or(Drop::WrapHash)?;
        check::wrap_hash(&read, signed)?;
        self.unwraps
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.app
            .pqchat_unwrap(account.clone(), e.session_id.clone(), e.id.clone(), wrap)
            .map_err(|_| Drop::Envelope)
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
    /// home and checked as far as state allows (`control`: the shapes, and a child against its parent with the parent's
    /// leaves and removals), equal at `replica` when one is named (`replica`), the own wrap checked and opened. Membership
    /// is the home's record, never a replica's.
    pub async fn open_epoch(
        &self,
        s: &SessionRef,
        epoch_id: &str,
        account: &KeyRef,
        me: &str,
        replica: Option<&str>,
    ) -> Result<crate::message::OpenEpoch, Drop> {
        let r = self
            .open_epoch_inner(s, epoch_id, account, me, replica)
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
    ) -> Result<crate::message::OpenEpoch, Drop> {
        let home = self.checked_at(s, &s.home, epoch_id).await?;
        if let Some(rep) = replica {
            let r = self.checked_at(s, rep, epoch_id).await?;
            Self::replica(&home, &r)?;
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

    /// The record `epoch_id` of `s` at `contract`, listed and checked (its parent read at the same instance).
    async fn checked_at(
        &self,
        s: &SessionRef,
        contract: &str,
        epoch_id: &str,
    ) -> Result<Epoch, Drop> {
        if !self
            .listed(&s.chain, contract)
            .await
            .map_err(|_| Drop::Unlisted)?
        {
            return Err(Drop::Unlisted);
        }
        let read = |id: String| async move {
            self.record_at(&s.chain, contract, &s.session_id, &id)
                .await
                .map_err(|_| Drop::Decode)?
                .ok_or(Drop::Control)
        };
        let e = read(epoch_id.to_string()).await?;
        if e.session_id != s.session_id.to_ascii_lowercase() {
            return Err(Drop::Control);
        }
        check::shapes(&e)?;
        if e.epoch > 0 {
            let p = read(e.parent.clone()).await?;
            let (mut left, mut removed) = (vec![], vec![]);
            for m in p
                .members
                .iter()
                .map(|m| m.ua.clone())
                .chain(p.admins.iter().cloned())
            {
                let a = json!({ "epochId": p.id, "member": m });
                let l = self
                    .net
                    .read(&s.chain, contract, "IPqChat.leftIn", a.clone())
                    .await
                    .map_err(|_| Drop::Decode)?;
                let r = self
                    .net
                    .read(&s.chain, contract, "IPqChat.removedIn", a)
                    .await
                    .map_err(|_| Drop::Decode)?;
                if at(&l, "0") == true {
                    left.push(m.clone());
                }
                if at(&r, "0") == true {
                    removed.push(m);
                }
            }
            check::child(&e, &p, &left, &removed)?;
        }
        Ok(e)
    }
}
