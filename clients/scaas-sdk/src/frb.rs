// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The one adapter for Dart (spec §16.1, feature `frb`): FRB 2 carries closures that return futures (`DartFnFuture`), not
//! foreign trait objects, so the Dart side gives each platform interface as a record of async closures and this module wraps
//! them into [`SecureStore`] and [`Authenticator`]. A closure answers every failure as a value (a Dart exception is caught on
//! the Dart side and answered `Unexpected`), so no foreign exception reaches Rust as a panic.

use crate::platform::{
    Assertion, AssertionRequest, AuthError, Authenticator, KeyPolicy, PasskeyCreated, SePublic,
};
use crate::vault::{SecureStore, StoreError, StoreLock, StorePolicy, StoredItem};
use async_trait::async_trait;
use scaas_ua::wallet::SecretBytes;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// A foreign future (FRB's `DartFnFuture<T>` is this type).
pub type Fut<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;
type F<A, T> = Box<dyn Fn(A) -> Fut<T> + Send + Sync>;

/// `SecureStore` as closures; `lock` answers a token that `unlock` releases (called when the lock drops). `get` takes the item's
/// name and the reason shown at a presence check; `put_if` the name, the expected `rev`, the bytes and the item's policy.
pub struct ClosureStore {
    pub get: F<(String, String), Result<Option<StoredItem>, StoreError>>,
    pub put_if: F<(String, Option<u64>, Vec<u8>, StorePolicy), Result<(), StoreError>>,
    pub delete: F<String, Result<(), StoreError>>,
    pub lock: F<String, Result<u64, StoreError>>,
    pub unlock: Arc<dyn Fn(u64) -> Fut<()> + Send + Sync>,
}

struct Release(u64, Arc<dyn Fn(u64) -> Fut<()> + Send + Sync>);

impl Drop for Release {
    fn drop(&mut self) {
        // review T26 C-7: the release runs to its end on a thread of its own: never a task a runtime's shutdown drops, and
        // where no runtime runs too
        crate::vault::store::release_on_own_thread((self.1)(self.0));
    }
}

#[async_trait]
impl SecureStore for ClosureStore {
    async fn get(&self, name: String, reason: String) -> Result<Option<StoredItem>, StoreError> {
        (self.get)((name, reason)).await
    }
    async fn put_if(
        &self,
        name: String,
        prev: Option<u64>,
        bytes: Vec<u8>,
        policy: StorePolicy,
    ) -> Result<(), StoreError> {
        (self.put_if)((name, prev, bytes, policy)).await
    }
    async fn delete(&self, name: String) -> Result<(), StoreError> {
        (self.delete)(name).await
    }
    async fn lock(&self, name: String) -> Result<Arc<StoreLock>, StoreError> {
        let token = (self.lock)(name).await?;
        Ok(StoreLock::new(Box::new(Release(
            token,
            self.unlock.clone(),
        ))))
    }
}

/// `Authenticator` as closures; the secret outputs are written by the Dart side through the copy calls into the
/// `SecretBytes` whose id it is given.
pub struct ClosureAuthenticator {
    pub create_passkey: F<(String, String, Vec<Vec<u8>>), Result<PasskeyCreated, AuthError>>,
    pub get_assertion: F<(AssertionRequest, u64), Result<Assertion, AuthError>>,
    pub platform_secret:
        F<(String, Vec<u8>, String, Option<KeyPolicy>, u64), Result<(), AuthError>>,
    pub p256_generate: F<KeyPolicy, Result<SePublic, AuthError>>,
    pub p256_sign: F<(String, Vec<u8>, String), Result<Vec<u8>, AuthError>>,
}

#[async_trait]
impl Authenticator for ClosureAuthenticator {
    async fn create_passkey(
        &self,
        rp: String,
        user: String,
        exclude: Vec<Vec<u8>>,
    ) -> Result<PasskeyCreated, AuthError> {
        (self.create_passkey)((rp, user, exclude)).await
    }
    async fn get_assertion(
        &self,
        req: AssertionRequest,
        prf_out: Arc<SecretBytes>,
    ) -> Result<Assertion, AuthError> {
        (self.get_assertion)((req, prf_out.id())).await
    }
    async fn platform_secret(
        &self,
        h: String,
        salt: Vec<u8>,
        reason: String,
        policy: Option<KeyPolicy>,
        out: Arc<SecretBytes>,
    ) -> Result<(), AuthError> {
        (self.platform_secret)((h, salt, reason, policy, out.id())).await
    }
    async fn p256_generate(&self, policy: KeyPolicy) -> Result<SePublic, AuthError> {
        (self.p256_generate)(policy).await
    }
    async fn p256_sign(
        &self,
        h: String,
        msg: Vec<u8>,
        reason: String,
    ) -> Result<Vec<u8>, AuthError> {
        (self.p256_sign)((h, msg, reason)).await
    }
}
