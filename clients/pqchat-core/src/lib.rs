// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `pqchat-core`: PqChat's client core above `scaas-sdk` (CLI-PQC-01, docs/clients/pqchat-core.md; spec
//! docs/superpowers/specs/2026-11-17-pqchat-core.md). It owns the state machine (what to build, when, from which reads, and what
//! to show); every key operation, signature and chain read goes through the SDK, every Matrix call through the transport trait
//! the app implements. No cryptography, no signed or encrypted byte format, no key byte (CLI-PQC-03). UNAUDITED.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

pub mod drops;
pub mod error;
pub mod matrix;
pub mod order;
pub mod store;

pub use drops::{Drop, DropCounts};
pub use error::PqChatError;
pub use store::{Item, Items, MemoryStore, PqChatStore, StoreFault};

use scaas_sdk::app_core::{AppCore, AppDesc};
use scaas_sdk::Sdk;
use std::sync::Arc;

/// PqChat's label prefix (CLI-PQC-03): the one the crate declares to the SDK.
pub const LABELS: &str = "scaas/pqchat/v1/";
/// `PqChat`'s factory class (CTR-CHAT-02).
pub const CLASS: u16 = 3;

/// The crate's SDK scope: PqChat's label prefix and class 3, no app purpose (its records are signed by the SDK's PqChat
/// entries under `PURPOSE_PQCHAT`, CLI-PQC-04).
pub fn scope(sdk: &Arc<Sdk>) -> Result<Arc<AppCore>, PqChatError> {
    Ok(AppCore::new(
        sdk.clone(),
        AppDesc {
            app_id: None,
            name: "PqChat".into(),
            class: Some(CLASS),
            labels: vec![LABELS.into()],
        },
    )?)
}
