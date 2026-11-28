// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The `PqChat` chain stores (UA-7 P29, P16, CTR-CHAT-05): `storeMessage(1, hint, env)` writes an envelope under the epoch's
//! hint; a reader pages `storedRange(hint, offset, 16)` (trusted reads) from its kept position, each payload decoded by the SDK
//! (V2, bounded) and checked as any message (CLI-PQC-07): anyone may write under a known hint, so a stranger's or an empty
//! envelope is dropped and paged past. `postMessage` posts the envelope's own record and signature at the home instance.
//! A `chainstore` entry (a `PqChatStore`, CTR-CHAT-22: `PqChat`'s store selectors, event and error; owner 2026-11-28) takes the
//! same path at the store's own address, after its own identity check (CLI-PQC-02): no factory lists it.
use crate::message::{OpenEpoch, Outgoing};
use crate::model::{at, bytes, hex};
use crate::reads::SessionRef;
use crate::session::StoreEntry;
use crate::{ChainConf, DropReason, Items, PqChat, PqChatError};
use scaas_sdk::op::KeyRef;
use serde_json::json;

/// `storedRange`'s page (the contract's `STORED_RANGE_MAX`).
pub const PAGE: usize = 16;

/// `type(IPqChatStore).interfaceId`: `storeMessage`, `storedCount`, `storedAt` and `storedRange`'s selectors XORed (the forge
/// pin `PqChatStore.t.sol` `test_erc165`).
pub const IPQCHATSTORE_ID: &str = "0xf33ad180";

impl PqChat {
    /// The chain store `e` as this app serves it: its chain and contract. A `chain` entry's instance is listed by that chain's
    /// factory (a trusted read); a `chainstore` entry resolves only to a served chain whose `chain_uid` and chain id it names
    /// (C-Chain and Fuji share `chain_uid`), its contract a `PqChatStore` ([`PqChat::is_chat_store`]). `InstanceUnlisted`
    /// otherwise, nothing read there.
    async fn chain_store(&self, e: &StoreEntry) -> Result<(ChainConf, String), PqChatError> {
        let (chain_uid, contract, chainstore) = match e {
            StoreEntry::Chain {
                chain_uid,
                contract,
                ..
            } => (chain_uid, contract, None),
            StoreEntry::Chainstore {
                chain_id,
                chain_uid,
                contract,
            } => (chain_uid, contract, Some(chain_id)),
            _ => return Err(PqChatError::StoreUnsupported),
        };
        // a `chainstore` entry's chain id in decimal, as the served chain states it
        let id_of = |c: &ChainConf, id: &String| c.chain_id.is_some_and(|i| i.to_string() == *id);
        let c = self
            .conf
            .chains
            .iter()
            .find(|c| {
                c.chain_uid.eq_ignore_ascii_case(chain_uid)
                    && chainstore.is_none_or(|id| id_of(c, id))
            })
            .ok_or(PqChatError::InstanceUnlisted)?
            .clone();
        let contract = contract.to_ascii_lowercase();
        let known = match chainstore {
            None => self.listed(&c.chain, &contract).await?,
            Some(_) => self.is_chat_store(&c, &contract).await?,
        };
        if !known {
            return Err(PqChatError::InstanceUnlisted);
        }
        Ok((c, contract))
    }

    /// Whether `contract` on `c` is a `PqChatStore`: its runtime code hash equals the one `c`'s release data pins (spec
    /// 2026-11-21 §5.5 C4; none pinned: no store) and it answers `supportsInterface(IPqChatStore)` true, both trusted reads.
    /// An address without code has the empty code's hash.
    pub(crate) async fn is_chat_store(
        &self,
        c: &ChainConf,
        contract: &str,
    ) -> Result<bool, PqChatError> {
        let Some(pin) = c.chainstore_code_hash.as_deref() else {
            return Ok(false);
        };
        let code = self.net.code_hash(&c.chain, contract).await?;
        if !code.eq_ignore_ascii_case(pin) {
            return Ok(false);
        }
        let v = self
            .net
            .read(
                &c.chain,
                contract,
                "PqChatStore.supportsInterface",
                json!({ "id": IPQCHATSTORE_ID }),
            )
            .await?;
        Ok(at(&v, "0").as_bool() == Some(true))
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
        if !self.info_of(ep)?.stores.contains(e) || !self.prefs(&sid)?.confirmed.contains(e) {
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
                    None => self.drops.add(&sid, DropReason::Decode),
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
