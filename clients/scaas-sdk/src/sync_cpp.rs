// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The sync surface (spec §16.1 (a′); plan T20b; feature `sync-api`): the runner of the `*_blocking` twins that
//! `crate::binding`'s `surface!` declares, the cancel token, and the sync platform interfaces (run on a blocking thread).
//! UNAUDITED.
use crate::binding::{self, BindingConfig};
use crate::platform::{
    Assertion, AssertionRequest, AuthError, Authenticator, KeyPolicy, PasskeyCreated, SePublic,
};
use crate::vault::{SecureStore, StoreError, StoreLock, StorePolicy, StoredItem};
use crate::SdkError;
use async_trait::async_trait;
use scaas_ua::wallet::SecretBytes;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

/// A cancel token (spec §16.1): cancelled from another thread, the call returns `Cancelled` at once and its work goes on on
/// the SDK's runtime, the effect of a dropped future (spec §13.4).
#[derive(uniffi::Object, Default)]
pub struct CancelToken {
    flag: AtomicBool,
    notify: Notify,
}

#[uniffi::export]
impl CancelToken {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(CancelToken::default())
    }
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

impl CancelToken {
    async fn cancelled(&self) {
        loop {
            let n = self.notify.notified();
            tokio::pin!(n);
            n.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            n.await;
        }
    }
}

/// Runs `f` on the SDK's runtime and blocks the foreign thread for its result (`Internal` on a runtime thread: a twin never
/// blocks one). As the async call (`Sdk::spawn`): a panic is `Internal`; a cancelled token returns `Cancelled` at once and `f`
/// goes on on the runtime, the effect of a dropped future (spec §13.4).
pub(crate) fn block<T: Send + 'static>(
    sdk: &Arc<crate::Sdk>,
    cancel: Option<Arc<CancelToken>>,
    f: impl Future<Output = Result<T, SdkError>> + Send + 'static,
) -> Result<T, SdkError> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(SdkError::Internal);
    }
    let h = sdk.rt.as_ref().ok_or(SdkError::Internal)?.handle.clone();
    h.block_on(async move {
        match cancel {
            Some(c) => tokio::select! {
                biased;
                () = c.cancelled() => Err(SdkError::Cancelled),
                r = sdk.spawn(f) => r,
            },
            None => sdk.spawn(f).await,
        }
    })
}

/// The app's store (spec §6.9) as a sync foreign interface, called by the SDK on a blocking thread. `remove` is the store's
/// `delete` (a C++ keyword).
#[uniffi::export(with_foreign)]
pub trait SyncStore: Send + Sync {
    fn get(&self, name: String, reason: String) -> Result<Option<StoredItem>, StoreError>;
    fn put_if(
        &self,
        name: String,
        prev_rev: Option<u64>,
        bytes: Vec<u8>,
        policy: StorePolicy,
    ) -> Result<(), StoreError>;
    fn remove(&self, name: String) -> Result<(), StoreError>;
    fn lock(&self, name: String) -> Result<u64, StoreError>;
    fn unlock(&self, token: u64);
}

/// The app's authenticator (spec §6.10) as a sync foreign interface, called on a blocking thread; secret outputs through the
/// copy calls into the secret whose id it is given.
#[uniffi::export(with_foreign)]
pub trait SyncAuthenticator: Send + Sync {
    fn create_passkey(
        &self,
        rp_id: String,
        user_name: String,
        exclude: Vec<Vec<u8>>,
    ) -> Result<PasskeyCreated, AuthError>;
    fn get_assertion(&self, req: AssertionRequest, prf_out: u64) -> Result<Assertion, AuthError>;
    fn platform_secret(
        &self,
        handle: String,
        salt: Vec<u8>,
        reason: String,
        policy: Option<KeyPolicy>,
        out: u64,
    ) -> Result<(), AuthError>;
    fn p256_generate(&self, policy: KeyPolicy) -> Result<SePublic, AuthError>;
    fn p256_sign(
        &self,
        handle: String,
        ua_msg: Vec<u8>,
        reason: String,
    ) -> Result<Vec<u8>, AuthError>;
}

/// `f` on a blocking thread; a `JoinError` (a panic) is `e`.
async fn off<T: Send + 'static, E: Send + 'static>(
    e: E,
    f: impl FnOnce() -> Result<T, E> + Send + 'static,
) -> Result<T, E> {
    tokio::task::spawn_blocking(f).await.unwrap_or(Err(e))
}

struct StoreAdapter(Arc<dyn SyncStore>);

struct Release(u64, Arc<dyn SyncStore>);

impl Drop for Release {
    fn drop(&mut self) {
        let (token, store) = (self.0, self.1.clone());
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            h.spawn_blocking(move || store.unlock(token));
        }
    }
}

#[async_trait]
impl SecureStore for StoreAdapter {
    async fn get(&self, name: String, reason: String) -> Result<Option<StoredItem>, StoreError> {
        let s = self.0.clone();
        off(StoreError::Unexpected, move || s.get(name, reason)).await
    }
    async fn put_if(
        &self,
        name: String,
        prev_rev: Option<u64>,
        bytes: Vec<u8>,
        policy: StorePolicy,
    ) -> Result<(), StoreError> {
        let s = self.0.clone();
        off(StoreError::Unexpected, move || {
            s.put_if(name, prev_rev, bytes, policy)
        })
        .await
    }
    async fn delete(&self, name: String) -> Result<(), StoreError> {
        let s = self.0.clone();
        off(StoreError::Unexpected, move || s.remove(name)).await
    }
    async fn lock(&self, name: String) -> Result<Arc<StoreLock>, StoreError> {
        let s = self.0.clone();
        let token = off(StoreError::Unexpected, move || s.lock(name)).await?;
        Ok(StoreLock::new(Box::new(Release(token, self.0.clone()))))
    }
}

struct AuthAdapter(Arc<dyn SyncAuthenticator>);

#[async_trait]
impl Authenticator for AuthAdapter {
    async fn create_passkey(
        &self,
        rp_id: String,
        user_name: String,
        exclude: Vec<Vec<u8>>,
    ) -> Result<PasskeyCreated, AuthError> {
        let a = self.0.clone();
        off(AuthError::Unexpected, move || {
            a.create_passkey(rp_id, user_name, exclude)
        })
        .await
    }
    async fn get_assertion(
        &self,
        req: AssertionRequest,
        prf_out: Arc<SecretBytes>,
    ) -> Result<Assertion, AuthError> {
        let (a, id) = (self.0.clone(), prf_out.id());
        off(AuthError::Unexpected, move || a.get_assertion(req, id)).await
    }
    async fn platform_secret(
        &self,
        handle: String,
        salt: Vec<u8>,
        reason: String,
        policy: Option<KeyPolicy>,
        out: Arc<SecretBytes>,
    ) -> Result<(), AuthError> {
        let (a, id) = (self.0.clone(), out.id());
        off(AuthError::Unexpected, move || {
            a.platform_secret(handle, salt, reason, policy, id)
        })
        .await
    }
    async fn p256_generate(&self, policy: KeyPolicy) -> Result<SePublic, AuthError> {
        let a = self.0.clone();
        off(AuthError::Unexpected, move || a.p256_generate(policy)).await
    }
    async fn p256_sign(
        &self,
        handle: String,
        ua_msg: Vec<u8>,
        reason: String,
    ) -> Result<Vec<u8>, AuthError> {
        let a = self.0.clone();
        off(AuthError::Unexpected, move || {
            a.p256_sign(handle, ua_msg, reason)
        })
        .await
    }
}

/// Opens the SDK (spec §4) over the app's sync store and authenticator; blocks the calling thread (never a UI thread).
#[uniffi::export]
pub fn open_blocking(
    config: BindingConfig,
    store: Arc<dyn SyncStore>,
    authenticator: Option<Arc<dyn SyncAuthenticator>>,
) -> Result<Arc<binding::Sdk>, SdkError> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(SdkError::Internal);
    }
    let auth = authenticator.map(|a| Arc::new(AuthAdapter(a)) as Arc<dyn Authenticator>);
    let config = config.sdk_config(Arc::new(StoreAdapter(store)), auth);
    // the opening's keystore read needs a runtime before the SDK's own exists: a current-thread one for that call
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| SdkError::Internal)?;
    let sdk = rt.block_on(crate::Sdk::open(config))?;
    Ok(binding::Sdk::new(sdk))
}
