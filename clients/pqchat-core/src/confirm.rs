// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Sign after confirm (CLI-SDK-36, owner 2026-11-27): every write but a message is built for the user's review and returned
//! as a [`Prepared`], unsigned: the record's fields as the SDK will sign them and, for the payer's own transaction, the SDK's
//! quote of its call before the signature (`quote_app_call`). [`PqChat::confirm`] makes the one signing call, on the user's
//! confirm only; a `Prepared` dropped signed nothing. A message keeps CLI-PQC-04's form: the send is its confirm. After the
//! confirm, a paid call is sent on that confirm only when its fresh quote is within the reviewed one
//! ([`Confirmed::within_review`], the rule of CLI-PQV-18); otherwise the front-end shows the fresh quote and asks again.
//! A relayed topic write (CLI-PQC-18 F3) costs its author nothing: nothing to compare. UNAUDITED.
use crate::net::{Signature, Unsigned};
use crate::topics::At;
use crate::{PqChat, PqChatError};
use async_trait::async_trait;
use scaas_sdk::app_core::{AppCall, AppQuote};
use scaas_sdk::op::{KeyRef, ReviewField};
use serde_json::{json, Value};

/// A write built for the user's review and not signed (CLI-SDK-36). It holds no key: the record's fields, its ciphertexts
/// and key handles only. Read-only: what [`PqChat::confirm`] signs is what the review showed.
pub struct Prepared<W> {
    pub(crate) unsigned: Unsigned,
    pub(crate) review: Vec<ReviewField>,
    pub(crate) quote: Option<AppQuote>,
    pub(crate) then: W,
}

impl<W> Prepared<W> {
    /// The record as it will be signed: the SDK's review of every field (and its notices: an exit's lag, a tree commit's
    /// lines and the leaves under review).
    pub fn review(&self) -> &[ReviewField] {
        &self.review
    }
    /// The SDK's quote of the payer's call before the signature (its review with the signature empty, the payer's gas from
    /// the gas rows, `quote` none when unquoted); `None` for a relayed write and for a tree commit, whose cost is its plan.
    pub fn quote(&self) -> Option<&AppQuote> {
        self.quote.as_ref()
    }
    /// The write's own facts for the review (the UAs skipped, a tree commit's plan, …).
    pub fn facts(&self) -> &W {
        &self.then
    }
}

/// A write signed on the user's confirm: what it became, and the quote the user reviewed.
pub struct Confirmed<O> {
    pub out: O,
    pub reviewed: Option<AppQuote>,
}

impl<O> Confirmed<O> {
    /// CLI-PQV-18's rule for `fresh`, the call of this write prepared after the confirm: it may be sent on the confirm already
    /// given only when its payer is the reviewed one and its `max_cost` at most the reviewed `max_cost`. `false` without a
    /// reviewed quote (relayed, a tree commit, unquoted) or when a figure does not parse: the front-end then shows `fresh`
    /// and sends only on a second confirm.
    pub fn within_review(&self, fresh: &AppCall) -> bool {
        let Some(r) = self.reviewed.as_ref().and_then(|q| q.quote.as_ref()) else {
            return false;
        };
        let f = &fresh.quote.quote;
        let cost = |q: &scaas_sdk::op::SubmitQuote| q.max_cost.parse::<u128>().ok();
        f.payer.is_some()
            && f.payer == r.payer
            && matches!((cost(f), cost(r)), (Some(a), Some(b)) if a <= b)
    }
}

/// What a confirm does around its one signature, per write kind (crate-internal; the kinds are this crate's).
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Then: Send + Sync {
    type Out;
    /// Before the signature (a room bound to the session, CLI-PQC-05); nothing by default.
    async fn before(&self, _chat: &PqChat) -> Result<(), PqChatError> {
        Ok(())
    }
    /// After it: the write's output from the signature.
    async fn then(self, chat: &PqChat, s: Signature) -> Result<Self::Out, PqChatError>;
}

impl PqChat {
    /// Signs `p` on the user's confirm of its review (CLI-SDK-36): the write's checks before the signature, the one signing
    /// call ([`crate::net::Net::sign`]), then the write's output. Nothing is signed before this call.
    pub async fn confirm<W: Then>(&self, p: Prepared<W>) -> Result<Confirmed<W::Out>, PqChatError> {
        p.then.before(self).await?;
        let s = self.net.sign(p.unsigned).await?;
        let out = p.then.then(self, s).await?;
        Ok(Confirmed {
            out,
            reviewed: p.quote,
        })
    }

    /// The SDK's quote of `item` at `on` before the signature: `args` with the record's `UASig` empty.
    pub(crate) async fn quote_unsigned(
        &self,
        on: &At,
        item: &'static str,
        mut args: Value,
        payer: &KeyRef,
        signer: &KeyRef,
    ) -> Result<AppQuote, PqChatError> {
        if let Some(o) = args.as_object_mut() {
            o.insert(
                "sig".into(),
                json!({"keyData": "0x", "signature": "0x", "members": []}),
            );
        }
        self.net
            .quote(&on.chain, &on.instance, item, args, payer, signer)
            .await
    }

    /// A signed write sent by the path it was prepared for: relayed by the chain's gateways (whether one queued it) or the
    /// payer's call prepared and simulated (the front-end sends it, [`Confirmed::within_review`] first).
    pub async fn dispatch(&self, w: &SignedWrite) -> Result<Sent, PqChatError> {
        match &w.path {
            Path::Relayed => Ok(Sent::Relayed {
                queued: self
                    .net
                    .relay(&w.at.chain, &w.at.instance, w.item, w.args.clone())
                    .await?,
            }),
            Path::Payer(p) => Ok(Sent::Call(Box::new(
                self.net
                    .prepare(&w.at.chain, &w.at.instance, w.item, w.args.clone(), p)
                    .await?,
            ))),
        }
    }

    /// `w` sent by the payer's own transaction instead of the gateways (a relay no gateway queued): its call prepared.
    pub async fn dispatch_paid(
        &self,
        w: &SignedWrite,
        payer: &KeyRef,
    ) -> Result<AppCall, PqChatError> {
        self.net
            .prepare(&w.at.chain, &w.at.instance, w.item, w.args.clone(), payer)
            .await
    }
}

/// How a write reaches the chain: relayed by the chain's gateways, fee 0 (the default of a topic write, CLI-PQC-18 F3), or
/// the payer's own transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Path {
    Relayed,
    Payer(KeyRef),
}

/// What [`PqChat::dispatch`] did.
pub enum Sent {
    /// relayed: whether a gateway queued it (`false`: none did; the same bytes may go again, or by
    /// [`PqChat::dispatch_paid`])
    Relayed { queued: bool },
    /// the payer's call, prepared and simulated
    Call(Box<AppCall>),
}

/// A record signed on the confirm and its call's named arguments: sent by [`PqChat::dispatch`] (again too, the same bytes).
#[derive(Debug, Clone)]
pub struct SignedWrite {
    /// the record's id (a topic's or an entry's), `None` for a record without one
    pub id: Option<String>,
    pub at: At,
    pub path: Path,
    pub(crate) item: &'static str,
    pub(crate) args: Value,
}

impl SignedWrite {
    /// The entry it calls (`IPqChat.postEntry`, …).
    pub fn item(&self) -> &'static str {
        self.item
    }
}

/// A record write: the record under its argument name, signed, then the call's arguments (no network after the signature).
pub struct RecordWrite {
    pub(crate) at: At,
    pub(crate) item: &'static str,
    pub(crate) name: &'static str,
    pub(crate) record: Value,
    pub(crate) path: Path,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Then for RecordWrite {
    type Out = SignedWrite;
    async fn then(self, _chat: &PqChat, s: Signature) -> Result<SignedWrite, PqChatError> {
        let (id, sig) = match s {
            Signature::Record(s) => (s.id, s.sig),
            Signature::Exit(sig) => (None, sig),
            Signature::Commit(_) => return Err(PqChatError::Internal),
        };
        Ok(SignedWrite {
            id,
            at: self.at,
            path: self.path,
            item: self.item,
            args: json!({ self.name: self.record, "sig": crate::session::sig_json(&sig) }),
        })
    }
}

/// A tree review's `(name, value)` lines as review fields.
pub(crate) fn lines(review: &[(String, String)]) -> Vec<ReviewField> {
    review
        .iter()
        .map(|(n, v)| ReviewField {
            name: n.clone(),
            value: v.clone(),
            display: v.clone(),
            source: scaas_sdk::op::Source::Derived,
        })
        .collect()
}
