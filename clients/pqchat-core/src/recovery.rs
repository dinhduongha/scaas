// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Recovery from contract state alone (CLI-PQC-09, CTR-CHAT-14): on each chain the app serves, the factory's index pages the
//! `PqChat` instances (class 3, version ≠ 0, trusted reads); each listed instance's `sessionCount` / `sessionsOf` (plain
//! discovery reads, paged) give the account's session ids, de-duplicated; a session is shown only when its home is listed and
//! reachable, holds the equal record and has `epochCount > 0` (K25), its latest epoch read at home (`latestEpoch`, trusted,
//! at the final block). No event is read and no own wrap of a pending session is opened. And after the seed's unlock
//! ([`PqChat::resume`]): every accepted session's latest epoch opened again, the events kept while locked processed in order,
//! a room whose bound was passed read again from its history (CLI-PQC-10).
use crate::consent::{Consent, Known};
use crate::model::{at, h, list, num, ZERO32};
use crate::reads::SessionRef;
use crate::session::Me;
use crate::{Event, PqChat, PqChatError};
use serde_json::json;
use std::collections::BTreeSet;
use std::sync::Arc;

/// The factory index's page.
pub const INSTANCES_PAGE: u64 = 64;
/// `sessionsOf`'s page.
pub const SESSIONS_PAGE: u64 = 64;
/// Instances read per chain at most.
pub const INSTANCES_MAX: u64 = 4096;
/// Sessions read per instance at most.
pub const SESSIONS_MAX: u64 = 65_536;

/// A session found in state, as the app lists it.
#[derive(Clone)]
pub struct SessionSummary {
    pub s: SessionRef,
    pub latest: String,
    pub epochs: u64,
    pub consent: Consent,
    /// the latest epoch's `sealedInfo` JSON (its name), opened for an accepted session only, as the SDK's handle
    pub info: Option<Arc<scaas_sdk::SecretBytes>>,
}

impl PqChat {
    /// The `PqChat` instances `chain`'s factory lists (class 3, version ≠ 0), from its index.
    pub async fn instances(&self, chain: &str) -> Result<Vec<String>, PqChatError> {
        let c = self.conf(chain)?.clone();
        let mut out = vec![];
        let mut from = 0;
        while from < INSTANCES_MAX {
            let v = self
                .net
                .read(
                    chain,
                    &c.factory,
                    "IOpenFactory.contractsPage",
                    json!({"contractClass": "3", "from": from.to_string(), "n": INSTANCES_PAGE.to_string()}),
                )
                .await?;
            let page = at(&v, "page").as_array().ok_or(PqChatError::Internal)?;
            if page.len() as u64 > INSTANCES_PAGE {
                return Err(PqChatError::Internal);
            }
            for i in page {
                if num(at(i, "contractClass"))? == u64::from(crate::CLASS)
                    && num(at(i, "version"))? != 0
                {
                    out.push(h(at(i, "addr"))?);
                }
            }
            from += page.len() as u64;
            if page.is_empty() || from >= num(at(&v, "total"))? {
                break;
            }
        }
        Ok(out)
    }

    /// The account's sessions on every chain the app serves, found from state (progress: `RecoveryProgress` per instance).
    /// Each new one is recorded pending on this device, or declined when the account left it; the user's consent of a known
    /// one is kept.
    pub async fn sessions(&self, me: &Me) -> Result<Vec<SessionSummary>, PqChatError> {
        let ua = me.ua.to_ascii_lowercase();
        let mut seen = BTreeSet::new();
        let mut out = vec![];
        for c in self.conf.chains.clone() {
            let inst = self.instances(&c.chain).await?;
            for (n, i) in inst.iter().enumerate() {
                let count = self
                    .net
                    .read(&c.chain, i, "IPqChat.sessionCount", json!({ "ua": ua }))
                    .await?;
                let count = num(at(&count, "0"))?.min(SESSIONS_MAX);
                let mut off = 0;
                while off < count {
                    let a = json!({"ua": ua, "offset": off.to_string(), "limit": SESSIONS_PAGE.to_string()});
                    let v = self.net.read(&c.chain, i, "IPqChat.sessionsOf", a).await?;
                    let ids = list(at(&v, "0"))?;
                    if ids.is_empty() || ids.len() as u64 > SESSIONS_PAGE {
                        break;
                    }
                    off += ids.len() as u64;
                    for sid in ids {
                        if !seen.insert(sid.clone()) {
                            continue;
                        }
                        if let Some(s) = self.found(&c.chain, i, &sid, me).await? {
                            out.push(s);
                        }
                    }
                }
                self.event(Event::RecoveryProgress {
                    chain: c.chain.clone(),
                    instances_done: n as u64 + 1,
                    instances: inst.len() as u64,
                    found: out.len() as u64,
                });
            }
        }
        Ok(out)
    }

    /// The session `sid` read at `instance` on `chain`: shown when its home is listed, reachable and holds the equal record
    /// with `epochCount > 0`.
    async fn found(
        &self,
        chain: &str,
        instance: &str,
        sid: &str,
        me: &Me,
    ) -> Result<Option<SessionSummary>, PqChatError> {
        let v = self
            .net
            .read(
                chain,
                instance,
                "IPqChat.sessionOf",
                json!({ "sessionId": sid }),
            )
            .await?;
        let rec = at(&v, "s");
        if h(at(rec, "creator"))? == ZERO32 {
            return Ok(None);
        }
        let (home_uid, home) = (h(at(rec, "homeChain"))?, h(at(rec, "homeChatContract"))?);
        let Some(hc) = self
            .conf
            .chains
            .iter()
            .find(|c| c.chain_uid.eq_ignore_ascii_case(&home_uid))
        else {
            return Ok(None);
        };
        let home_chain = hc.chain.clone();
        if !self.listed(&home_chain, &home).await? {
            return Ok(None);
        }
        let s = SessionRef {
            chain: home_chain,
            home: home.clone(),
            session_id: sid.to_ascii_lowercase(),
        };
        // CLI-PQC-15: the home's record with its kept signature verified (`sstore2`), else not shown
        let Ok(at_home) = self.signed_record_at(&s.chain, &home, sid, sid).await else {
            return Ok(None);
        };
        let here = crate::model::Epoch::from_session(sid, &v)?;
        let (Some(at_home), Some(here)) = (at_home, here) else {
            return Ok(None);
        };
        if Self::replica(&at_home, &here).is_err() {
            return Ok(None);
        }
        let n = self
            .net
            .read(
                &s.chain,
                &home,
                "IPqChat.epochCount",
                json!({ "sessionId": sid }),
            )
            .await?;
        let epochs = num(at(&n, "0"))?;
        if epochs == 0 {
            return Ok(None);
        }
        let latest = self.latest_epoch(&s).await?;
        let ua = me.ua.to_ascii_lowercase();
        let Ok(latest_rec) = self.signed_record_at(&s.chain, &home, sid, &latest).await else {
            return Ok(None);
        };
        let left = match latest_rec {
            Some(e) if e.has_member(&ua) => {
                let l = self
                    .net
                    .read(
                        &s.chain,
                        &home,
                        "IPqChat.leftIn",
                        json!({"epochId": latest, "member": ua}),
                    )
                    .await?;
                at(&l, "0") == true
            }
            // left or removed before the latest epoch
            _ => true,
        };
        let consent = if left {
            self.set_consent(&s, Consent::Declined, true)?
        } else {
            self.set_consent(&s, Consent::Pending, false)?
        };
        let info = if consent == Consent::Accepted {
            match self.open_epoch(&s, &latest, &me.key, &ua, None).await {
                Ok(ep) => self.info(&ep).ok(),
                Err(_) => None,
            }
        } else {
            None
        };
        Ok(Some(SessionSummary {
            s,
            latest,
            epochs,
            consent,
            info,
        }))
    }

    /// After the seed's unlock (CLI-PQC-10): the crate takes envelopes again; every accepted session's latest epoch is
    /// opened for `me` and put to use (a session that does not open is skipped, counted by its reason), then the events
    /// kept while locked are processed in their order, those of rooms no accepted session binds dropped, and each room whose
    /// bound was passed is read again from its history. How many messages were shown.
    pub async fn resume(&self, me: &Me) -> Result<usize, PqChatError> {
        self.set_locked(false);
        let ua = me.ua.to_ascii_lowercase();
        let known: Vec<Known> = self.known()?.into_values().collect();
        for k in known.iter().filter(|k| k.consent == Consent::Accepted) {
            let Ok(latest) = self.latest_epoch(&k.s).await else {
                continue;
            };
            if let Ok(ep) = self.open_epoch(&k.s, &latest, &me.key, &ua, None).await {
                self.use_epoch(&k.s, ep).await?;
            }
        }
        self.process_kept().await
    }
}
