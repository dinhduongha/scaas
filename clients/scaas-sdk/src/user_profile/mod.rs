// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `user_profile` (feature `user-profile`; spec docs/superpowers/specs/2026-11-27-user-profiles.md, rules CLI-UPR-01 to
//! CLI-UPR-28 of docs/clients/scaas-sdk.md §12): many protected local profiles in the SDK layer. Every KDF, AEAD and MAC runs in
//! `scaas-ua`'s profile arena (`ProfileKeys`); this module holds handles and public bytes. Built so far (plan UP5): the sealed
//! store core of one open profile ([`Core`]), its `SecureStore` face ([`PartStore`]), the manifests and the anchor. UNAUDITED.
pub mod anchor;
pub mod store;

pub use anchor::{Anchor, Head, Verdict};
pub use store::{Core, CoreOpen, Manifest, PartStore, ProfilePart, WriteGuard};

use crate::vault::StoreError;
use async_trait::async_trait;

/// The app's keychain (spec §11): small items only (at most 2,560 bytes), named by the SDK (`scaas.profile.<id>.<what>`): the
/// anchors, the `protected` marker, the unlock key.
#[async_trait]
pub trait ProfileKeychain: Send + Sync {
    async fn get(&self, name: String) -> Result<Option<Vec<u8>>, StoreError>;
    async fn put(&self, name: String, bytes: Vec<u8>) -> Result<(), StoreError>;
    async fn delete(&self, name: String) -> Result<(), StoreError>;
}

/// The keychain item `what` of profile `id`: `scaas.profile.<id>.<what>` (spec §5, §7.1, §7.2).
pub(crate) fn keychain_name(id: &str, what: &str) -> String {
    format!("scaas.profile.{id}.{what}")
}
