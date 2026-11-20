// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The reference library's test hook (plan T20b-T20h; feature `uniffi`): a panic inside an exported call, run as the SDK's own
//! calls run, so each binding's smoke test sees it arrive as `Internal` (spec §16.1). Here only, never in the SDK's surface.
use scaas_sdk::binding::Sdk;
use scaas_sdk::SdkError;
use std::sync::Arc;

/// Panics inside a call on the SDK's runtime: `Internal`.
#[cfg(not(feature = "sync-api"))]
#[uniffi::export]
pub async fn panic_in_call(sdk: Arc<Sdk>) -> Result<(), SdkError> {
    sdk.run(async { panic!("the test hook's panic") }).await
}

/// Panics inside a `*_blocking` call: `Internal`.
#[cfg(feature = "sync-api")]
#[uniffi::export]
pub fn panic_in_call_blocking(sdk: Arc<Sdk>) -> Result<(), SdkError> {
    sdk.run_blocking(None, async { panic!("the test hook's panic") })
}
