// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Tests only (T26 A-5): the SDK prepares an app record and signs it apart; a test that checks a signature, not the review,
//! signs what it prepared through this one helper, after asserting the review is there.
#![allow(dead_code)]

use scaas_sdk::app_core::{AppCore, AppPath, AppSigned};
use scaas_sdk::op::KeyRef;
use scaas_sdk::SdkError;
use std::sync::Arc;

#[allow(async_fn_in_trait)]
pub trait SignPrepared {
    async fn sign_app_record(
        &self,
        account: KeyRef,
        path: AppPath,
        typed: String,
    ) -> Result<AppSigned, SdkError>;
    async fn sign_pqvault_record(
        &self,
        account: KeyRef,
        path: AppPath,
        records: Option<String>,
        typed: String,
    ) -> Result<AppSigned, SdkError>;
}

impl SignPrepared for Arc<AppCore> {
    async fn sign_app_record(
        &self,
        account: KeyRef,
        path: AppPath,
        typed: String,
    ) -> Result<AppSigned, SdkError> {
        let p = self.prepare_app_record(account, path, typed).await?;
        assert!(!p.review.is_empty());
        p.sign().await
    }
    async fn sign_pqvault_record(
        &self,
        account: KeyRef,
        path: AppPath,
        records: Option<String>,
        typed: String,
    ) -> Result<AppSigned, SdkError> {
        let p = self
            .prepare_pqvault_record(account, path, records, typed)
            .await?;
        assert!(!p.review.is_empty());
        p.sign().await
    }
}
