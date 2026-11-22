// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The `PqChat` chain stores (UA-7 P29, P16, CTR-CHAT-05): `storeMessage(1, hint, env)` writes an envelope under the epoch's
//! hint; a reader pages `storedRange(hint, offset, 16)` (trusted reads) from its kept position, each payload decoded by the SDK
//! (V2, bounded) and checked as any message (CLI-PQC-07): anyone may write under a known hint, so a stranger's or an empty
//! envelope is dropped and paged past. `postMessage` posts the envelope's own record and signature at the home instance.
use crate::message::{OpenEpoch, Outgoing};
use crate::model::{at, bytes, hex};
use crate::reads::SessionRef;
use crate::session::StoreEntry;
use crate::{ChainConf, Drop, Items, PqChat, PqChatError};
use scaas_sdk::op::KeyRef;
use serde_json::json;

/// `storedRange`'s page (the contract's `STORED_RANGE_MAX`).
pub const PAGE: usize = 16;

impl PqChat {
    /// The chain store `e` as this app serves it: its chain and instance, listed by that chain's factory (a trusted read).
    async fn chain_store(&self, e: &StoreEntry) -> Result<(ChainConf, String), PqChatError> {
        let StoreEntry::Chain {
            chain_uid,
            contract,
            ..
        } = e
        else {
            return Err(PqChatError::StoreUnsupported);
        };
        let c = self
            .conf
            .chains
            .iter()
            .find(|c| c.chain_uid.eq_ignore_ascii_case(chain_uid))
            .ok_or(PqChatError::InstanceUnlisted)?
            .clone();
        let contract = contract.to_ascii_lowercase();
        self.require_listed(&c.chain, &contract).await?;
        Ok((c, contract))
    }

    /// `out` written to the chain store `e` (`storeMessage`, prepared and submitted under the session's spend consent): the
    /// SDK operation's id.
    pub(crate) async fn store_message(
        &self,
        e: &StoreEntry,
        out: &Outgoing,
        payer: &KeyRef,
    ) -> Result<String, PqChatError> {
        let (c, contract) = self.chain_store(e).await?;
        let a = json!({"v": "1", "hint": hex(&out.sealed.hint), "env": hex(&out.sealed.env)});
        let call = self
            .net
            .prepare(&c.chain, &contract, "IPqChat.storeMessage", a, payer)
            .await?;
        self.net.submit(call).await
    }

    /// `out` posted at `s`'s home instance (`postMessage`: the envelope's record and signature, one `messageId`).
    pub(crate) async fn post_message(
        &self,
        s: &SessionRef,
        out: &Outgoing,
        payer: &KeyRef,
    ) -> Result<String, PqChatError> {
        let call = self
            .net
            .prepare(
                &s.chain,
                &s.home,
                "IPqChat.postMessage",
                out.post_args(),
                payer,
            )
            .await?;
        self.net.submit(call).await
    }

    /// The envelopes of `ep` stored in the chain store `e` since the last read: paged by `storedRange`, [`PAGE`] at a time,
    /// from the kept position to an empty or short page; each checked (CLI-PQC-07), a payload that does not decode or names
    /// another hint dropped (`decode`). How many were shown. Only a store of `ep`'s list the user confirmed
    /// (`StoreUnconfirmed`).
    pub async fn read_chain_store(
        &self,
        ep: &OpenEpoch,
        e: &StoreEntry,
    ) -> Result<usize, PqChatError> {
        let sid = ep.epoch.session_id.clone();
        self.require_accepted(&sid)?;
        if !self.info(ep)?.stores.contains(e) || !self.prefs(&sid)?.confirmed.contains(e) {
            return Err(PqChatError::StoreUnconfirmed);
        }
        let (c, contract) = self.chain_store(e).await?;
        let hint = self.app.pqchat_hint(ep.k.clone())?;
        let key = format!(
            "read/{}/{contract}/{}",
            c.chain_uid.to_ascii_lowercase(),
            hex(&hint)
        );
        let mut offset: u64 = Items(&*self.store).get(&key)?.unwrap_or(0);
        let mut shown = 0;
        loop {
            let a = json!({"hint": hex(&hint), "offset": offset.to_string(), "limit": PAGE.to_string()});
            let v = self
                .net
                .read(&c.chain, &contract, "IPqChat.storedRange", a)
                .await?;
            let page = at(&v, "0").as_array().ok_or(PqChatError::Internal)?;
            if page.len() > PAGE {
                return Err(PqChatError::Internal);
            }
            for p in page {
                let env = bytes(p)
                    .ok()
                    .and_then(|b| self.app.pqchat_decode_payload(b).ok())
                    .filter(|pl| pl.hint == hint);
                match env {
                    Some(pl) => shown += usize::from(self.receive(ep, pl.env).await.is_ok()),
                    None => self.drops.add(&sid, Drop::Decode),
                }
            }
            offset += page.len() as u64;
            Items(&*self.store).update::<u64, _>(&key, |_| Ok(offset))?;
            if page.len() < PAGE {
                return Ok(shown);
            }
        }
    }
}
