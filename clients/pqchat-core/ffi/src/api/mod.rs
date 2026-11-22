// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The check's FRB surface (plan T12): `flutter_rust_bridge_codegen` scans this module and `pqchat-core` itself
//! (`rust_input: crate::api,pqchat-core`), as the SDK's generator scans the SDK. `PqChat` is opened here over the SDK and a
//! memory store: the storage interface and the Matrix transport are Rust-only (spec §11), set up by the app's Rust code.
use flutter_rust_bridge::frb;
pub use pqchat_core::{PqChat, PqChatConfig, PqChatError};
use scaas_sdk::Sdk;
use std::sync::Arc;

/// `PqChat` over `sdk` with a memory store (the reference library's; an app passes its own store in Rust).
#[frb(sync)]
pub fn pqchat_open(sdk: Arc<Sdk>, conf: PqChatConfig) -> Result<Arc<PqChat>, PqChatError> {
    PqChat::new(sdk, Arc::new(pqchat_core::MemoryStore::new()), conf)
}

/// The error's code.
#[frb(sync)]
pub fn pqchat_error_code(e: &PqChatError) -> String {
    e.code().to_string()
}
