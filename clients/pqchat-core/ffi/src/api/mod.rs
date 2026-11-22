// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The check's FRB surface (plan T12): `flutter_rust_bridge_codegen` scans this module and `pqchat-core` itself
//! (`rust_input: crate::api,pqchat-core`), as the SDK's generator scans the SDK. `PqChat` is opened here over the SDK and a
//! memory store: the storage interface and the Matrix transport are Rust-only (spec §11), set up by the app's Rust code.
use flutter_rust_bridge::frb;
pub use pqchat_core::{PqChat, PqChatConfig, PqChatError};
// the types of `pqchat-core`'s public API that are not its own: named here, where the generated glue looks them up
pub use pqchat_core::matrix::RoomUse;
pub use scaas_sdk::app_core::{AppCall, AppCore};
pub use scaas_sdk::op::KeyRef;
pub use scaas_sdk::pqchat_keys::PqSealedMessage;
pub use scaas_sdk::pqchat_records::{PqChatMessage, PqChatSigned, PqEntryRef, PqWrap};
pub use scaas_sdk::{Sdk, SecretBytes};
pub use std::collections::BTreeMap;
use std::sync::Arc;

/// `PqChat` over `sdk` with a memory store (the reference library's; an app passes its own store in Rust).
#[frb(sync)]
pub fn pqchat_open(sdk: Arc<Sdk>, conf: PqChatConfig) -> Result<Arc<PqChat>, PqChatError> {
    PqChat::new(sdk, Arc::new(pqchat_core::MemoryStore::new()), conf)
}

/// A secret's id for the C copy calls (`scaas_sdk_secret_read`): the only way a decrypted content's bytes leave.
#[frb(sync)]
pub fn secret_id(s: &Arc<SecretBytes>) -> u64 {
    s.id()
}

/// A secret's length in bytes.
#[frb(sync)]
pub fn secret_len(s: &Arc<SecretBytes>) -> u32 {
    u32::try_from(s.len()).unwrap_or(u32::MAX)
}

/// The error's code.
#[frb(sync)]
pub fn pqchat_error_code(e: &PqChatError) -> String {
    e.code().to_string()
}
