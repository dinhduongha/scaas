// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The chain port (spec §5 R1–R3, W1): every read and write the crate makes, by the contract item's name. Each read's trust
//! mark is in [`READS`], once (CLI-PQC-13): a read of a session's state at an instance, of a registry key or membership, or of
//! the factory's listing feeds a decryption or chooses a key, a recipient or an epoch, so it is made under
//! `Purpose::FeedsDecryption`; the discovery and topic views choose nothing. The gate `pqc-reads` holds every call site to the
//! table. [`SdkNet`] is the port over the SDK (`read_app` at the profile's final block, `prepare_app_call`, the wallet's send);
//! the tests put recording fakes in its place.
use crate::PqChatError;
use async_trait::async_trait;
use scaas_sdk::app_core::{AppCall, AppCore, AppQuote, AppUaSig};
use scaas_sdk::op::KeyRef;
use scaas_sdk::pqchat_records::{PqChatPrepared, PqChatSigned};
use scaas_sdk::pqchat_tree::{PqTreeCommit, PqTreeCommitSigned, PqTreeExit};
use scaas_sdk::Sdk;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

/// A read's mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// `Purpose::FeedsDecryption` (CLI-RPC-06): never a discovered endpoint alone
    Trusted,
    /// `Purpose::Plain`: a read that chooses nothing
    Plain,
}

use Trust::{Plain, Trusted};

/// Every read of the crate and its mark, by ABI item (`Contract.function` of [`abi.json`](abi.json)).
pub const READS: &[(&str, Trust)] = &[
    ("IOpenFactory.contractsPage", Trusted),
    ("IOpenFactory.infoOf", Trusted),
    ("IPqChat.byAuthor", Plain),
    ("IPqChat.childOf", Trusted),
    ("IPqChat.entryOf", Plain),
    ("IPqChat.entryRows", Plain),
    ("IPqChat.epochComplete", Trusted),
    ("IPqChat.epochCount", Trusted),
    ("IPqChat.epochOf", Trusted),
    ("IPqChat.epochSig", Trusted),
    ("IPqChat.epochsOf", Trusted),
    ("IPqChat.latestEpoch", Trusted),
    ("IPqChat.leaveAt", Trusted),
    ("IPqChat.leaveCount", Trusted),
    ("IPqChat.leaveSig", Trusted),
    ("IPqChat.leftIn", Trusted),
    ("IPqChat.messageAt", Trusted),
    ("IPqChat.messageCount", Trusted),
    ("IPqChat.messageSig", Trusted),
    ("IPqChat.posts", Plain),
    ("IPqChat.removalAt", Trusted),
    ("IPqChat.removalCount", Trusted),
    ("IPqChat.removalSig", Trusted),
    ("IPqChat.removedIn", Trusted),
    ("IPqChat.replies", Plain),
    ("IPqChat.scoreOf", Plain),
    ("IPqChat.sessionCount", Plain),
    ("IPqChat.sessionOf", Trusted),
    ("IPqChat.sessionSig", Trusted),
    ("IPqChat.sessionsOf", Plain),
    ("IPqChat.sigStore", Trusted),
    ("IPqChat.storedCount", Trusted),
    ("IPqChat.storedRange", Trusted),
    ("IPqChat.topicOf", Plain),
    ("IPqChat.topics", Plain),
    ("IPqChat.topicsByAdmin", Plain),
    ("IPqChat.versionAt", Plain),
    ("IPqChat.voteOf", Plain),
    ("IPqChat.wrapAt", Trusted),
    ("IPqChat.writerOf", Plain),
    ("IPqChat.writersOf", Plain),
    ("IPqChatTreeViews.commitOf", Trusted),
    ("IPqChatTreeViews.goneKeyOf", Trusted),
    ("IPqChatTreeViews.goneOf", Trusted),
    ("IPqChatTreeViews.goneOwnKeyOf", Trusted),
    ("IPqChatTreeViews.pathCtAt", Trusted),
    ("IPqChatTreeViews.pathKeys", Trusted),
    ("IPqChatTreeViews.pathListOf", Trusted),
    ("IPqChatTreeViews.treeLeaves", Trusted),
    ("IPqChatTreeViews.treeNodeKey", Trusted),
    ("IPqChatTreeViews.treeNodes", Trusted),
    ("IPqChatTreeViews.treeOf", Trusted),
    ("IUARegistry.checkedOf", Trusted),
    ("IUARegistry.kemKeyAt", Trusted),
    ("IUARegistry.kemKeyOf", Trusted),
    ("IUARegistry.memberAccepted", Trusted),
    ("IUARegistry.msigAt", Trusted),
    ("IUARegistry.msigOf", Trusted),
    ("IUARegistry.msigStateOf", Trusted),
    ("IUARegistry.registrationOf", Trusted),
];

/// Every write of the crate, by ABI item.
pub const WRITES: &[&str] = &[
    "IPqChat.addPath",
    "IPqChat.addPathKeys",
    "IPqChat.addPathList",
    "IPqChat.addWraps",
    "IPqChat.commit",
    "IPqChat.createSession",
    "IPqChat.createTopic",
    "IPqChat.editEntry",
    "IPqChat.leave",
    "IPqChat.postEntry",
    "IPqChat.postMessage",
    "IPqChat.rekey",
    "IPqChat.remove",
    "IPqChat.setTopicWriter",
    "IPqChat.storeMessage",
    "IPqChat.treeLeave",
    "IPqChat.treeRemove",
    "IPqChat.updateTopic",
    "IPqChat.voteEntry",
];

/// The writes relayed by the chain's gateways by default (CLI-PQC-18 F3): the six topic records; the others are the payer's own
/// transactions.
pub const RELAYED: &[&str] = &[
    "IPqChat.createTopic",
    "IPqChat.editEntry",
    "IPqChat.postEntry",
    "IPqChat.setTopicWriter",
    "IPqChat.updateTopic",
    "IPqChat.voteEntry",
];

/// The mark of `item`; an item outside the table is `Internal` (no read without a mark).
pub fn trust(item: &str) -> Result<Trust, PqChatError> {
    READS
        .iter()
        .find(|(i, _)| *i == item)
        .map(|(_, t)| *t)
        .ok_or(PqChatError::Internal)
}

/// The JSON ABI item named `item` (generated by `runs/gen_abi.py` from forge's build).
pub fn abi(item: &str) -> Result<&'static str, PqChatError> {
    static ITEMS: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    let m = ITEMS.get_or_init(|| {
        let v: BTreeMap<String, Value> =
            serde_json::from_str(include_str!("abi.json")).unwrap_or_default();
        v.into_iter().map(|(k, x)| (k, x.to_string())).collect()
    });
    m.get(item).map(String::as_str).ok_or(PqChatError::Internal)
}

/// What a confirm signs (CLI-SDK-36): one of the SDK's PqChat records prepared for its signature, signed once by
/// [`Net::sign`], only on the user's confirm ([`crate::confirm`]).
pub enum Unsigned {
    /// a session, epoch, leave, removal or topic record, or a tree session's genesis (`prepare_pqchat_*`)
    Record(PqChatPrepared),
    /// a tree commit, path or path-less (`pqchat_tree_prepare_commit`, `pqchat_tree_prepare_pathless`)
    Commit(Box<PqTreeCommit>),
    /// a tree exit (`prepare_pqchat_tree_leave`, `prepare_pqchat_tree_remove`)
    Exit(PqTreeExit),
}

/// The signature [`Net::sign`] made, of the kind it was given.
pub enum Signature {
    Record(PqChatSigned),
    Commit(PqTreeCommitSigned),
    Exit(AppUaSig),
}

/// Signs `u` now: the SDK's one signing call of that record.
pub async fn sign_now(u: Unsigned) -> Result<Signature, PqChatError> {
    Ok(match u {
        Unsigned::Record(p) => Signature::Record(p.sign().await?),
        Unsigned::Commit(c) => Signature::Commit(c.sign()?),
        Unsigned::Exit(e) => Signature::Exit(e.sign()?),
    })
}

/// The crate's chain port.
// on wasm32 the SDK's futures are not `Send` (the page's one thread), as the SDK's own async traits
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Net: Send + Sync {
    /// The view `item` of `contract` on `chain` with `args` (its parameters by name), at the final block, by its own mark;
    /// the outputs by name (the SDK's named JSON).
    async fn read(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<Value, PqChatError>;
    /// [`Net::read`] at the latest block instead of the final one (C37, D-14 of the TreeKEM T4-T9 review: what a sender
    /// already landed); a port without it reads at the final block.
    async fn read_latest(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<Value, PqChatError> {
        self.read(chain, contract, item, args).await
    }
    /// The write `item` of `contract` on `chain`, paid by `payer`: quoted and reviewed (the SDK's operation model, W1).
    async fn prepare(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
        payer: &KeyRef,
    ) -> Result<AppCall, PqChatError>;
    /// Sends exactly a prepared write; the SDK operation's id.
    async fn submit(&self, call: AppCall) -> Result<String, PqChatError>;
    /// The quote of the write `item` before its record is signed (CLI-SDK-36, the SDK's `quote_app_call`): `args` with the
    /// record's `UASig` empty, paid by `payer`, signed later by `signer`. A port without one answers it unquoted.
    async fn quote(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
        payer: &KeyRef,
        signer: &KeyRef,
    ) -> Result<AppQuote, PqChatError> {
        let _ = (chain, contract, item, args, payer, signer);
        Ok(AppQuote {
            review: vec![],
            quote: None,
        })
    }
    /// The one signing call of a confirmed write (CLI-SDK-36); the tests count it.
    async fn sign(&self, u: Unsigned) -> Result<Signature, PqChatError> {
        sign_now(u).await
    }
    /// A signed topic write relayed by the chain's gateways, fee 0 (CLI-PQC-18 F3; the SDK's `relay_app_call`): whether a
    /// gateway queued it. A port without gateways answers `RelayUnavailable`.
    async fn relay(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<bool, PqChatError> {
        let _ = (chain, contract, item, args);
        Err(PqChatError::RelayUnavailable)
    }
    /// R13 (CLI-PQC-17): the view `item` read by a strict majority of the chain's **named** endpoints at the final block
    /// (CLI-RPC-05 over the named ones only: discovered and default endpoints do not count), with how many named endpoints the
    /// chain lists. A port without an agreed read answers `TreeInfoUnconfirmed`.
    async fn read_majority(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<(Value, usize), PqChatError> {
        let _ = (chain, contract, item, args);
        Err(PqChatError::TreeInfoUnconfirmed)
    }
}

/// [`Net`] over the SDK.
pub struct SdkNet {
    pub sdk: Arc<Sdk>,
    pub app: Arc<AppCore>,
}

/// CLI-PQC-16 (`PqChatConfig.agreed_reads`): [`SdkNet`] with every trusted `IPqChat` and `IPqChatTreeViews` read (the control
/// plane at an instance) an agreed read, the SDK's `read_app_agreed`; every other read and every write as [`SdkNet`]'s.
pub struct AgreedNet(pub SdkNet);

/// Whether [`AgreedNet`] reads `item` agreed: a trusted read of an instance (CLI-PQC-16), its tree views included.
pub fn agreed_item(item: &str) -> bool {
    (item.starts_with("IPqChat.") || item.starts_with("IPqChatTreeViews."))
        && matches!(trust(item), Ok(Trusted))
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Net for SdkNet {
    async fn read(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<Value, PqChatError> {
        let trusted = trust(item)? == Trusted;
        let (c, k, e, a) = (
            chain.into(),
            contract.into(),
            abi(item)?.into(),
            args.to_string(),
        );
        let out = if trusted {
            self.app.read_app(c, k, e, a).await?
        } else {
            self.app.read_app_plain(c, k, e, a).await?
        };
        serde_json::from_str(&out).map_err(|_| PqChatError::Internal)
    }

    async fn prepare(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
        payer: &KeyRef,
    ) -> Result<AppCall, PqChatError> {
        if !WRITES.contains(&item) {
            return Err(PqChatError::Internal);
        }
        Ok(self
            .app
            .prepare_app_call(
                chain.into(),
                contract.into(),
                abi(item)?.into(),
                args.to_string(),
                payer.clone(),
            )
            .await?)
    }

    async fn submit(&self, call: AppCall) -> Result<String, PqChatError> {
        Ok(self.sdk.wallet().submit_native_send(call.quote).await?)
    }

    async fn quote(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
        payer: &KeyRef,
        signer: &KeyRef,
    ) -> Result<AppQuote, PqChatError> {
        if !WRITES.contains(&item) {
            return Err(PqChatError::Internal);
        }
        Ok(self
            .app
            .quote_app_call(
                chain.into(),
                contract.into(),
                abi(item)?.into(),
                args.to_string(),
                payer.clone(),
                signer.clone(),
            )
            .await?)
    }

    async fn relay(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<bool, PqChatError> {
        if !RELAYED.contains(&item) {
            return Err(PqChatError::Internal);
        }
        // a chain without gateways: the relay is unavailable by the crate's name (the payer's transaction is the option)
        self.app
            .relay_app_call(
                chain.into(),
                "pqchat".into(),
                contract.into(),
                abi(item)?.into(),
                args.to_string(),
            )
            .await
            .map_err(|e| match e.code() {
                "SubmitPathNone" => PqChatError::RelayUnavailable,
                _ => e.into(),
            })
    }

    async fn read_latest(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<Value, PqChatError> {
        trust(item)?;
        let out = self
            .app
            .read_app_latest(
                chain.into(),
                contract.into(),
                abi(item)?.into(),
                args.to_string(),
            )
            .await?;
        serde_json::from_str(&out).map_err(|_| PqChatError::Internal)
    }

    async fn read_majority(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<(Value, usize), PqChatError> {
        trust(item)?;
        let named = self.app.named_endpoints(chain)?;
        let out = self
            .app
            .read_app_agreed_named(
                chain.into(),
                contract.into(),
                abi(item)?.into(),
                args.to_string(),
            )
            .await?;
        Ok((
            serde_json::from_str(&out).map_err(|_| PqChatError::Internal)?,
            named,
        ))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Net for AgreedNet {
    async fn read(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<Value, PqChatError> {
        if !agreed_item(item) {
            return self.0.read(chain, contract, item, args).await;
        }
        let out = self
            .0
            .app
            .read_app_agreed(
                chain.into(),
                contract.into(),
                abi(item)?.into(),
                args.to_string(),
            )
            .await?;
        serde_json::from_str(&out).map_err(|_| PqChatError::Internal)
    }

    async fn prepare(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
        payer: &KeyRef,
    ) -> Result<AppCall, PqChatError> {
        self.0.prepare(chain, contract, item, args, payer).await
    }

    async fn submit(&self, call: AppCall) -> Result<String, PqChatError> {
        self.0.submit(call).await
    }

    async fn quote(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
        payer: &KeyRef,
        signer: &KeyRef,
    ) -> Result<AppQuote, PqChatError> {
        self.0
            .quote(chain, contract, item, args, payer, signer)
            .await
    }

    async fn relay(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<bool, PqChatError> {
        self.0.relay(chain, contract, item, args).await
    }

    async fn read_latest(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<Value, PqChatError> {
        self.0.read_latest(chain, contract, item, args).await
    }

    async fn read_majority(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<(Value, usize), PqChatError> {
        self.0.read_majority(chain, contract, item, args).await
    }
}
