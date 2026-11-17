// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! scaas-sdk T3 spike probe: one item per shape of the SDK's binding surface (spec §16.1), each in a sync control form and the
//! async form the SDK needs. Which of them uniffi-bindgen-cpp generates is the spike's question.
uniffi::setup_scaffolding!();

#[derive(Debug, uniffi::Error)]
pub enum ProbeError {
    Internal,
    Unexpected,
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ProbeError::Internal => "Internal",
            ProbeError::Unexpected => "Unexpected",
        })
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for ProbeError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        ProbeError::Unexpected
    }
}

#[derive(uniffi::Record)]
pub struct SeedInfo {
    pub id: String,
    pub label: String,
    pub words: u32,
}

/// Control: a sync function returning a record list.
#[uniffi::export]
pub fn seeds() -> Vec<SeedInfo> {
    vec![SeedInfo { id: "0b9c2f0e-5d0e-4a51-9d3b-6a1f6f6f2a10".into(), label: "Main".into(), words: 24 }]
}

/// Control: a sync function that panics (UniFFI catches it).
#[uniffi::export]
pub fn panics() -> Result<u32, ProbeError> {
    let v: Vec<u32> = vec![];
    #[allow(clippy::indexing_slicing)]
    Ok(v[1])
}

#[cfg(feature = "async-fn")]
/// The SDK's shape: an async function (spec §14: every exported call async, spawned on the SDK's runtime).
#[uniffi::export]
pub async fn ping_async(n: u32) -> u32 {
    n + 1
}

/// Control: a sync foreign-implemented interface.
#[uniffi::export(with_foreign)]
pub trait SyncStore: Send + Sync {
    fn get(&self, name: String) -> Result<Option<Vec<u8>>, ProbeError>;
}

#[cfg(feature = "async-callback")]
/// The SDK's shape: an async foreign-implemented interface (`SecureStore`, `Authenticator`, spec §6.9, §6.10).
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait AsyncStore: Send + Sync {
    async fn get(&self, name: String) -> Result<Option<Vec<u8>>, ProbeError>;
}

/// Control: a sync call through the sync interface.
#[uniffi::export]
pub fn read_sync(store: std::sync::Arc<dyn SyncStore>, name: String) -> Result<u32, ProbeError> {
    Ok(store.get(name)?.map_or(0, |b| b.len() as u32))
}

#[cfg(all(feature = "async-fn", feature = "async-callback"))]
/// The SDK's shape: an async call through the async interface.
#[uniffi::export]
pub async fn read_async(store: std::sync::Arc<dyn AsyncStore>, name: String) -> Result<u32, ProbeError> {
    Ok(store.get(name).await?.map_or(0, |b| b.len() as u32))
}
