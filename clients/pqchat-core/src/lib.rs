// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `pqchat-core`: PqChat's client core above `scaas-sdk` (CLI-PQC-01, docs/clients/pqchat-core.md; spec
//! docs/superpowers/specs/2026-11-17-pqchat-core.md). It owns the state machine (what to build, when, from which reads, and what
//! to show); every key operation, signature and chain read goes through the SDK, every Matrix call through the transport trait
//! the app implements. No cryptography, no signed or encrypted byte format, no key byte (CLI-PQC-03). UNAUDITED.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

pub mod error;
pub mod store;

pub use error::PqChatError;
pub use store::{Item, Items, MemoryStore, PqChatStore, StoreFault};
