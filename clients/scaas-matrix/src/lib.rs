// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `scaas-matrix` (CLI-PQC-20, CLI-MTX-01..12): one matrix-rust-sdk client per open user profile. It logs in by password,
//! restores the session from the profile's store key, syncs, lists rooms by kind, reads and sends Matrix messages with
//! Matrix's own end-to-end encryption (classical), verifies devices by SAS, keeps CLI-PQC-19's privacy defaults and
//! implements PqChat's `MatrixTransport` over the same client. It signs nothing of SCaaS and holds no seed. UNAUDITED.
//!
//! Layout of a profile's Matrix directory: `lock` (the OS lock of the open client, CLI-MTX-02) and `store/` (matrix-sdk's
//! SQLite stores, every one encrypted by the caller's key, CLI-MTX-03); the session, settings and PqChat marks are records
//! in the encrypted state store (CLI-MTX-04).
pub mod policy;
mod transport;

use matrix_sdk::authentication::matrix::MatrixSession;
use matrix_sdk::config::{RequestConfig, SyncSettings};
use matrix_sdk::deserialized_responses::{
    TimelineEvent, TimelineEventKind, VerificationLevel, VerificationState,
};
use matrix_sdk::encryption::verification::{SasVerification, Verification, VerificationRequest};
use matrix_sdk::encryption::{BackupDownloadStrategy, EncryptionSettings};
use matrix_sdk::room::MessagesOptions;
use matrix_sdk::ruma::api::client::filter::{FilterDefinition, LazyLoadOptions};
use matrix_sdk::ruma::api::client::push::{
    delete_pushrule, set_pushrule, PusherIds, PusherInit, PusherKind, RuleKind,
};
use matrix_sdk::ruma::api::client::receipt::create_receipt::v3::ReceiptType;
use matrix_sdk::ruma::api::client::sync::sync_events;
use matrix_sdk::ruma::api::error::ErrorKind;
use matrix_sdk::ruma::events::key::verification::request::ToDeviceKeyVerificationRequestEvent;
use matrix_sdk::ruma::events::receipt::ReceiptThread;
use matrix_sdk::ruma::events::room::message::RoomMessageEventContent;
use matrix_sdk::ruma::presence::PresenceState;
use matrix_sdk::ruma::push::{
    Action, EventMatchConditionData, HttpPusherData, NewConditionalPushRule, NewPushRule,
    PushCondition, PushFormat,
};
use matrix_sdk::ruma::{EventId, OwnedServerName, RoomId, UInt, UserId};
use matrix_sdk::{Client, RoomState, SqliteStateStore, SqliteStoreConfig, StateStore};
use matrix_sdk_base::crypto::CollectStrategy;
use policy::Marks;
pub use policy::{RoomFilter, RoomKind, Settings};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

pub use pqchat_transport::{MatrixTransport, RoomEvent, EVENT_TYPE};

/// The crate's errors (CLI-MTX-12): a name each, nothing secret and no identifier in any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixError {
    EndpointScheme,
    MatrixLogin,
    MatrixSession,
    MatrixStore,
    MatrixVerification,
    MatrixSend,
    MatrixRoom,
    MatrixRoomKind,
    MatrixProfileBusy,
    MatrixPushHidden,
    Argument,
    Internal,
}

impl MatrixError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::EndpointScheme => "EndpointScheme",
            Self::MatrixLogin => "MatrixLogin",
            Self::MatrixSession => "MatrixSession",
            Self::MatrixStore => "MatrixStore",
            Self::MatrixVerification => "MatrixVerification",
            Self::MatrixSend => "MatrixSend",
            Self::MatrixRoom => "MatrixRoom",
            Self::MatrixRoomKind => "MatrixRoomKind",
            Self::MatrixProfileBusy => "MatrixProfileBusy",
            Self::MatrixPushHidden => "MatrixPushHidden",
            Self::Argument => "Argument",
            Self::Internal => "Internal",
        }
    }
}

impl std::fmt::Display for MatrixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for MatrixError {}

type R<T> = Result<T, MatrixError>;

/// The profile's Matrix store key (CLI-MTX-03, CLI-UPR-29): 32 bytes from the profile's sealed item, wiped on drop, never
/// printed. The crate hands it to matrix-sdk's stores at open and keeps no copy of its own.
pub struct StoreKey(Zeroizing<[u8; 32]>);

impl StoreKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        StoreKey(Zeroizing::new(bytes))
    }
}

impl std::fmt::Debug for StoreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoreKey(..)")
    }
}

/// How a profile's client opens.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// a hidden profile (CLI-UPR-08): no pusher, no push rule (CLI-MTX-08)
    pub hidden: bool,
}

/// A device's trust as the front-end shows it (contract §11.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    Verified,
    Unverified,
    /// the user's identity changed since it was verified: a warning
    Changed,
    Unknown,
}

/// A room of the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomRow {
    pub room_id: String,
    pub name: String,
    pub invited: bool,
    pub encrypted: bool,
    pub direct: bool,
    pub unread: u64,
    pub kind: RoomKind,
}

/// What a timeline item is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemKind {
    Text(String),
    Notice(String),
    /// an encrypted event this device cannot open: shown, never dropped
    Undecryptable,
    /// a `net.scaas.pqchat.v1` event in a Matrix room (contract §11.2)
    PqChatNeedsScaasBuild,
    Other,
}

/// One timeline item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineItem {
    pub event_id: String,
    pub sender: String,
    pub sender_device: Option<String>,
    pub ts: u64,
    pub kind: ItemKind,
    pub verification: Trust,
}

/// A page of a room's timeline, newest last, and the token of the page before it.
#[derive(Debug, Clone, Default)]
pub struct Page {
    pub items: Vec<TimelineItem>,
    pub before: Option<String>,
}

/// A verification flow: the other user and the flow id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    pub user: String,
    pub flow_id: String,
}

/// A verification flow's step (view-model contract §11.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Requested,
    Ready,
    SasStarted,
    SasEmoji,
    Verified,
    Mismatch,
    Cancelled,
    TimedOut,
}

/// The recovery state (matrix-sdk's).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    Unknown,
    Enabled,
    Disabled,
    Incomplete,
}

/// An HTTP pusher's fields; its format is always `event_id_only` (CLI-MTX-08).
#[derive(Debug, Clone)]
pub struct HttpPusher {
    pub app_id: String,
    pub pushkey: String,
    pub url: String,
    pub app_display_name: String,
    pub device_display_name: String,
    pub lang: String,
}

/// What the sync loop and the event handlers report (CLI-MTX-09: a bounded queue).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Update {
    RoomsChanged,
    Timeline {
        room: String,
        item: TimelineItem,
    },
    /// a `net.scaas.pqchat.v1` event of a PqChat room, for `pqchat-core`'s `matrix_event`
    PqChatEvent {
        room: String,
        event: RoomEvent,
    },
    VerificationRequest {
        flow: Flow,
        device: String,
    },
    SessionInvalid,
    /// the queue was full and updates were dropped: read the rooms again
    Lagged,
}

/// The update queue's bound.
pub const UPDATES_MAX: usize = 1024;
/// The timeline events per room a sync asks for.
const SYNC_TIMELINE: u32 = 20;
const SESSION_KEY: &[u8] = b"scaas-matrix/session/v1";
const SETTINGS_KEY: &[u8] = b"scaas-matrix/settings/v1";
const MARKS_KEY: &[u8] = b"scaas-matrix/marks/v1";
const PQCHAT_RULE: &str = "net.scaas.pqchat.v1";

#[derive(Serialize, Deserialize)]
struct SessionRecord {
    homeserver: String,
    session: MatrixSession,
}

/// The state the client and its transport share.
pub(crate) struct Inner {
    pub(crate) client: Client,
    hidden: bool,
    settings: Mutex<Settings>,
    marks: Mutex<Marks>,
    tx: mpsc::Sender<Update>,
    lagged: AtomicBool,
}

impl Inner {
    fn push(&self, u: Update) {
        if self.tx.try_send(u).is_err() {
            self.lagged.store(true, Ordering::SeqCst);
        }
    }

    /// The room's kind; a poisoned lock reads every room as PqChat (nothing ephemeral is sent then).
    pub(crate) fn kind(&self, room: &str) -> RoomKind {
        self.marks
            .lock()
            .map(|m| m.kind(room))
            .unwrap_or(RoomKind::PqChat)
    }

    async fn put<T: Serialize>(&self, key: &[u8], v: &T) -> R<()> {
        let b = serde_json::to_vec(v).map_err(|_| MatrixError::Internal)?;
        self.client
            .state_store()
            .set_custom_value(key, b)
            .await
            .map(|_| ())
            .map_err(|_| MatrixError::MatrixStore)
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, key: &[u8], max: usize) -> R<Option<T>> {
        match self.client.state_store().get_custom_value(key).await {
            Ok(Some(b)) => policy::decode(&b, max).map(Some),
            Ok(None) => Ok(None),
            Err(_) => Err(MatrixError::MatrixStore),
        }
    }

    /// `room` marked PqChat (`hold`: its invite held, or released), the marks written.
    pub(crate) async fn mark(&self, room: &str, hold: Option<bool>) -> R<()> {
        let m = {
            let mut m = self.marks.lock().map_err(|_| MatrixError::Internal)?;
            match hold {
                Some(h) => m.hold(room, h)?,
                None => m.mark(room)?,
            }
            m.clone()
        };
        self.put(MARKS_KEY, &m).await
    }
}

/// One profile's Matrix client (CLI-MTX-02). Dropping it without [`MatrixClient::close`] also stops the sync loop and frees
/// the lock.
pub struct MatrixClient {
    inner: Arc<Inner>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Update>>,
    sync: Mutex<Option<tokio::task::JoinHandle<()>>>,
    dir: PathBuf,
    _lock: File,
}

impl Drop for MatrixClient {
    fn drop(&mut self) {
        if let Ok(mut s) = self.sync.lock() {
            if let Some(h) = s.take() {
                h.abort();
            }
        }
    }
}

/// The profile directory locked for this client: `MatrixProfileBusy` while another holds it.
fn lock(dir: &Path) -> R<File> {
    std::fs::create_dir_all(dir).map_err(|_| MatrixError::MatrixStore)?;
    let f = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("lock"))
        .map_err(|_| MatrixError::MatrixStore)?;
    f.try_lock().map_err(|e| match e {
        std::fs::TryLockError::WouldBlock => MatrixError::MatrixProfileBusy,
        std::fs::TryLockError::Error(_) => MatrixError::MatrixStore,
    })?;
    Ok(f)
}

fn store_dir(dir: &Path) -> PathBuf {
    dir.join("store")
}

/// ring as the process's rustls provider, unless one is installed already (matrix-sdk's reqwest has none of its own).
fn provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// The sync settings: presence offline on every sync (CLI-MTX-05), a short timeline and lazy-loaded members (CLI-MTX-09).
pub fn sync_settings(timeout: Duration) -> SyncSettings {
    let mut f = FilterDefinition::default();
    f.room.timeline.limit = Some(UInt::from(SYNC_TIMELINE));
    f.room.state.lazy_load_options = LazyLoadOptions::Enabled {
        include_redundant_members: false,
    };
    SyncSettings::new()
        .timeout(timeout)
        .set_presence(PresenceState::Offline)
        .filter(sync_events::v3::Filter::FilterDefinition(f))
}

enum Server<'a> {
    Url(url::Url),
    Name(&'a str),
}

fn server(homeserver: &str) -> R<Server<'_>> {
    if homeserver.contains("://") {
        Ok(Server::Url(policy::homeserver(homeserver)?))
    } else {
        Ok(Server::Name(homeserver))
    }
}

async fn build(dir: &Path, key: Option<&StoreKey>, hs: Server<'_>) -> R<Client> {
    provider();
    let mut b = Client::builder()
        .with_encryption_settings(EncryptionSettings {
            auto_enable_cross_signing: true,
            backup_download_strategy: BackupDownloadStrategy::Manual,
            auto_enable_backups: false,
        })
        .with_room_key_recipient_strategy(CollectStrategy::IdentityBasedStrategy)
        .request_config(RequestConfig::new().timeout(Duration::from_secs(90)));
    b = match hs {
        Server::Url(u) => b.homeserver_url(u),
        Server::Name(n) => {
            let n = OwnedServerName::try_from(n).map_err(|_| MatrixError::Argument)?;
            b.server_name(&n)
        }
    };
    if let Some(k) = key {
        b = b.sqlite_store_with_config_and_cache_path(
            SqliteStoreConfig::new(store_dir(dir)).key(Some(&k.0[..])),
            None::<PathBuf>,
        );
    }
    let c = b.build().await.map_err(|e| match e {
        matrix_sdk::ClientBuildError::SqliteStore(_) => MatrixError::MatrixStore,
        _ => MatrixError::MatrixLogin,
    })?;
    // a discovered homeserver obeys the same rule as a given one
    policy::homeserver(c.homeserver().as_str())?;
    Ok(c)
}

impl MatrixClient {
    async fn wrap(dir: &Path, lock: File, client: Client, opts: Options) -> R<MatrixClient> {
        let (tx, rx) = mpsc::channel(UPDATES_MAX);
        let inner = Arc::new(Inner {
            client,
            hidden: opts.hidden,
            settings: Mutex::new(Settings::default()),
            marks: Mutex::new(Marks::default()),
            tx,
            lagged: AtomicBool::new(false),
        });
        if let Some(s) = inner
            .get::<Settings>(SETTINGS_KEY, policy::SETTINGS_MAX)
            .await?
        {
            *inner.settings.lock().map_err(|_| MatrixError::Internal)? = s;
        }
        if let Some(m) = inner
            .get::<Marks>(MARKS_KEY, policy::MARKS_RECORD_MAX)
            .await?
        {
            *inner.marks.lock().map_err(|_| MatrixError::Internal)? = m;
        }
        let w = Arc::downgrade(&inner);
        inner
            .client
            .add_event_handler(move |ev: ToDeviceKeyVerificationRequestEvent| {
                let w = w.clone();
                async move {
                    if let Some(i) = w.upgrade() {
                        i.push(Update::VerificationRequest {
                            flow: Flow {
                                user: ev.sender.to_string(),
                                flow_id: ev.content.transaction_id.to_string(),
                            },
                            device: ev.content.from_device.to_string(),
                        });
                    }
                }
            });
        Ok(MatrixClient {
            inner,
            rx: tokio::sync::Mutex::new(rx),
            sync: Mutex::new(None),
            dir: dir.to_path_buf(),
            _lock: lock,
        })
    }

    /// A password login on the profile's Matrix directory `dir` (CLI-MTX-04): the session written into the encrypted store
    /// when `key` is given (none: memory stores, nothing persisted). `homeserver`: an `https` URL (or `http` to a loopback IP
    /// literal), or a server name for `.well-known` discovery. The password is not kept.
    #[allow(clippy::too_many_arguments)]
    pub async fn login_password(
        dir: &Path,
        key: Option<StoreKey>,
        opts: Options,
        homeserver: &str,
        user: &str,
        password: &str,
        device_name: &str,
    ) -> R<MatrixClient> {
        let hs = server(homeserver)?;
        let l = lock(dir)?;
        let persist = key.is_some();
        let client = build(dir, key.as_ref(), hs).await?;
        drop(key);
        client
            .matrix_auth()
            .login_username(user, password)
            .initial_device_display_name(device_name)
            .send()
            .await
            .map_err(|_| MatrixError::MatrixLogin)?;
        let session = client
            .matrix_auth()
            .session()
            .ok_or(MatrixError::MatrixLogin)?;
        let rec = SessionRecord {
            homeserver: client.homeserver().to_string(),
            session,
        };
        let c = Self::wrap(dir, l, client, opts).await?;
        if persist {
            c.inner.put(SESSION_KEY, &rec).await?;
        }
        c.inner
            .client
            .encryption()
            .wait_for_e2ee_initialization_tasks()
            .await;
        Ok(c)
    }

    /// The profile's session restored from its encrypted store (`MatrixStore`: wrong key or no store; `MatrixSession`: no
    /// session in it).
    pub async fn restore(dir: &Path, key: StoreKey, opts: Options) -> R<MatrixClient> {
        let l = lock(dir)?;
        if !store_dir(dir).exists() {
            return Err(MatrixError::MatrixStore);
        }
        let rec: SessionRecord = {
            let s = SqliteStateStore::open_with_key(store_dir(dir), Some(&key.0[..]))
                .await
                .map_err(|_| MatrixError::MatrixStore)?;
            let b = s
                .get_custom_value(SESSION_KEY)
                .await
                .map_err(|_| MatrixError::MatrixStore)?
                .ok_or(MatrixError::MatrixSession)?;
            policy::decode(&b, policy::SESSION_MAX)?
        };
        let hs = policy::homeserver(&rec.homeserver)?;
        let client = build(dir, Some(&key), Server::Url(hs)).await?;
        drop(key);
        client
            .restore_session(rec.session)
            .await
            .map_err(|_| MatrixError::MatrixSession)?;
        Self::wrap(dir, l, client, opts).await
    }

    /// Stops the sync loop and drops the client and its stores; the profile directory's lock is free when it returns.
    pub async fn close(self) {
        let h = self.sync.lock().ok().and_then(|mut s| s.take());
        if let Some(h) = h {
            h.abort();
            let _ = h.await;
        }
        drop(self);
    }

    /// Invalidates the token on the server, closes the client and deletes the directory's stores.
    pub async fn logout(self) -> R<()> {
        let r = self
            .inner
            .client
            .logout()
            .await
            .map_err(|_| MatrixError::MatrixSession);
        let dir = self.dir.clone();
        self.close().await;
        if store_dir(&dir).exists() {
            std::fs::remove_dir_all(store_dir(&dir)).map_err(|_| MatrixError::MatrixStore)?;
        }
        r
    }

    pub fn user_id(&self) -> Option<String> {
        self.inner.client.user_id().map(|u| u.to_string())
    }

    pub fn device_id(&self) -> Option<String> {
        self.inner.client.device_id().map(|d| d.to_string())
    }

    /// The next update (`None` once the client is gone); `Lagged` first when updates were dropped.
    pub async fn next_update(&self) -> Option<Update> {
        if self.inner.lagged.swap(false, Ordering::SeqCst) {
            return Some(Update::Lagged);
        }
        self.rx.lock().await.recv().await
    }

    /// One sync (presence offline), its rooms' events turned into updates.
    pub async fn sync_once(&self, timeout: Duration) -> R<()> {
        sync_round(&self.inner, timeout).await
    }

    /// The sync loop, in a task of the caller's runtime until [`MatrixClient::close`] or an invalid session.
    pub fn start_sync(&self) {
        let i = self.inner.clone();
        let h = tokio::spawn(async move {
            let mut wait = 1;
            loop {
                match sync_round(&i, Duration::from_secs(30)).await {
                    Ok(()) => wait = 1,
                    Err(MatrixError::MatrixSession) => return,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_secs(wait)).await;
                        wait = (wait * 2).min(30);
                    }
                }
            }
        });
        if let Ok(mut s) = self.sync.lock() {
            if let Some(old) = s.replace(h) {
                old.abort();
            }
        }
    }

    fn room(&self, room: &str) -> R<matrix_sdk::Room> {
        let id = RoomId::parse(room).map_err(|_| MatrixError::Argument)?;
        self.inner
            .client
            .get_room(&id)
            .ok_or(MatrixError::MatrixRoom)
    }

    /// The kind of a room (CLI-MTX-06).
    pub fn kind(&self, room: &str) -> RoomKind {
        self.inner.kind(room)
    }

    /// The rooms of one kind (CLI-MTX-06), joined or invited.
    pub async fn rooms(&self, filter: RoomFilter) -> Vec<RoomRow> {
        let marks = self
            .inner
            .marks
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default();
        let mut out = vec![];
        for r in self.inner.client.rooms() {
            let invited = match r.state() {
                RoomState::Joined => false,
                RoomState::Invited => true,
                _ => continue,
            };
            let id = r.room_id().to_string();
            if !marks.shows(filter, &id) {
                continue;
            }
            out.push(RoomRow {
                name: r
                    .display_name()
                    .await
                    .map(|n| n.to_string())
                    .unwrap_or_default(),
                invited,
                encrypted: r.encryption_state().is_encrypted(),
                direct: r.is_direct().await.unwrap_or(false),
                unread: r.unread_notification_counts().notification_count,
                kind: marks.kind(&id),
                room_id: id,
            });
        }
        out
    }

    /// A direct room with `user`, encrypted from its first event (CLI-MTX-07); its id.
    pub async fn create_direct(&self, user: &str) -> R<String> {
        let u = UserId::parse(user).map_err(|_| MatrixError::Argument)?;
        let r = self
            .inner
            .client
            .create_dm(&u)
            .await
            .map_err(|_| MatrixError::MatrixRoom)?;
        Ok(r.room_id().to_string())
    }

    /// A Matrix invite accepted (refused for a PqChat room's held invite).
    pub async fn accept_invite(&self, room: &str) -> R<()> {
        policy::matrix_action(self.inner.kind(room))?;
        self.room(room)?
            .join()
            .await
            .map_err(|_| MatrixError::MatrixRoom)
    }

    /// A Matrix invite declined, or a Matrix room left (refused for a PqChat room: `pqchat-core`'s to answer).
    pub async fn leave(&self, room: &str) -> R<()> {
        policy::matrix_action(self.inner.kind(room))?;
        self.room(room)?
            .leave()
            .await
            .map_err(|_| MatrixError::MatrixRoom)
    }

    /// A page of a Matrix room's timeline before `before`, at most `limit` (at most 100) events, newest last.
    pub async fn messages(&self, room: &str, before: Option<String>, limit: u32) -> R<Page> {
        policy::matrix_action(self.inner.kind(room))?;
        let r = self.room(room)?;
        let mut o = MessagesOptions::backward().from(before.as_deref());
        o.limit = UInt::from(limit.clamp(1, policy::PAGE_MAX));
        let m = r.messages(o).await.map_err(|_| MatrixError::MatrixRoom)?;
        let mut items: Vec<TimelineItem> = m.chunk.iter().filter_map(item).collect();
        items.reverse();
        Ok(Page {
            items,
            before: m.end,
        })
    }

    /// A text sent in a Matrix room (encrypted where the room is); its event id.
    pub async fn send_text(&self, room: &str, text: &str) -> R<String> {
        policy::matrix_action(self.inner.kind(room))?;
        policy::text(text)?;
        let r = self.room(room)?;
        let res = r
            .send(RoomMessageEventContent::text_plain(text))
            .await
            .map_err(|_| MatrixError::MatrixSend)?;
        Ok(res.response.event_id.to_string())
    }

    pub fn settings(&self) -> Settings {
        self.inner.settings.lock().map(|s| *s).unwrap_or_default()
    }

    async fn set(&self, f: impl FnOnce(&mut Settings)) -> R<()> {
        let s = {
            let mut s = self
                .inner
                .settings
                .lock()
                .map_err(|_| MatrixError::Internal)?;
            f(&mut s);
            *s
        };
        self.inner.put(SETTINGS_KEY, &s).await
    }

    /// Public read receipts on or off (off by default).
    pub async fn set_public_receipts(&self, on: bool) -> R<()> {
        self.set(|s| s.public_receipts = on).await
    }

    /// Typing notices on or off (off by default).
    pub async fn set_typing(&self, on: bool) -> R<()> {
        self.set(|s| s.typing = on).await
    }

    /// The read position at `event` in a Matrix room: `m.read.private` unless public receipts are on (CLI-MTX-05).
    pub async fn mark_read(&self, room: &str, event: &str) -> R<()> {
        let rt = match policy::receipt(&self.settings(), self.inner.kind(room))? {
            policy::Receipt::Private => ReceiptType::ReadPrivate,
            policy::Receipt::Public => ReceiptType::Read,
        };
        let e = EventId::parse(event).map_err(|_| MatrixError::Argument)?;
        self.room(room)?
            .send_single_receipt(rt, ReceiptThread::Unthreaded, e)
            .await
            .map_err(|_| MatrixError::MatrixSend)
    }

    /// A typing notice in a Matrix room, only when typing is on; whether one was sent.
    pub async fn typing(&self, room: &str, on: bool) -> R<bool> {
        if !policy::typing(&self.settings(), self.inner.kind(room))? {
            return Ok(false);
        }
        self.room(room)?
            .typing_notice(on)
            .await
            .map_err(|_| MatrixError::MatrixSend)?;
        Ok(true)
    }

    /// The PqChat transport over this client (CLI-MTX-10).
    pub fn transport(&self) -> Arc<dyn MatrixTransport> {
        Arc::new(transport::Transport(self.inner.clone()))
    }

    // ---- verification (CLI-MTX-07)

    /// A verification request to `device` of `user` (another user's, or this account's own).
    pub async fn request_verification(&self, user: &str, device: &str) -> R<Flow> {
        let v = MatrixError::MatrixVerification;
        let u = UserId::parse(user).map_err(|_| MatrixError::Argument)?;
        let d = self
            .inner
            .client
            .encryption()
            .get_device(&u, device.into())
            .await
            .map_err(|_| v)?
            .ok_or(v)?;
        let r = d.request_verification().await.map_err(|_| v)?;
        Ok(Flow {
            user: user.to_string(),
            flow_id: r.flow_id().to_string(),
        })
    }

    async fn sas(&self, f: &Flow) -> R<Option<SasVerification>> {
        let u = UserId::parse(&f.user).map_err(|_| MatrixError::Argument)?;
        Ok(
            match self
                .inner
                .client
                .encryption()
                .get_verification(&u, &f.flow_id)
                .await
            {
                Some(Verification::SasV1(s)) => Some(s),
                _ => None,
            },
        )
    }

    async fn request(&self, f: &Flow) -> R<VerificationRequest> {
        let u = UserId::parse(&f.user).map_err(|_| MatrixError::Argument)?;
        self.inner
            .client
            .encryption()
            .get_verification_request(&u, &f.flow_id)
            .await
            .ok_or(MatrixError::MatrixVerification)
    }

    /// Accepts the other side's request, or the SAS it started.
    pub async fn accept(&self, f: &Flow) -> R<()> {
        let v = MatrixError::MatrixVerification;
        if let Some(s) = self.sas(f).await? {
            return s.accept().await.map_err(|_| v);
        }
        self.request(f).await?.accept().await.map_err(|_| v)
    }

    /// Starts SAS on a ready request.
    pub async fn start_sas(&self, f: &Flow) -> R<()> {
        let v = MatrixError::MatrixVerification;
        self.request(f)
            .await?
            .start_sas()
            .await
            .map_err(|_| v)?
            .ok_or(v)?;
        Ok(())
    }

    /// The seven emoji to compare, once both sides have them: `(symbol, description)`.
    pub async fn sas_emoji(&self, f: &Flow) -> R<Option<Vec<(String, String)>>> {
        Ok(self.sas(f).await?.and_then(|s| s.emoji()).map(|e| {
            e.iter()
                .map(|x| (x.symbol.to_string(), x.description.to_string()))
                .collect()
        }))
    }

    /// The emoji matched.
    pub async fn confirm(&self, f: &Flow) -> R<()> {
        let v = MatrixError::MatrixVerification;
        self.sas(f).await?.ok_or(v)?.confirm().await.map_err(|_| v)
    }

    /// The emoji did not match: the flow cancelled as a mismatch.
    pub async fn mismatch(&self, f: &Flow) -> R<()> {
        let v = MatrixError::MatrixVerification;
        self.sas(f).await?.ok_or(v)?.mismatch().await.map_err(|_| v)
    }

    pub async fn cancel(&self, f: &Flow) -> R<()> {
        let v = MatrixError::MatrixVerification;
        if let Some(s) = self.sas(f).await? {
            return s.cancel().await.map_err(|_| v);
        }
        self.request(f).await?.cancel().await.map_err(|_| v)
    }

    /// Where a flow stands; `MatrixVerification` for a flow this client does not hold (never seen, or dropped by matrix-sdk
    /// after it ended: the device's trust is then the outcome).
    pub async fn step(&self, f: &Flow) -> R<Step> {
        let ended = |code: Option<String>| match code.as_deref() {
            Some("m.mismatched_sas") | Some("m.key_mismatch") => Step::Mismatch,
            Some("m.timeout") => Step::TimedOut,
            _ => Step::Cancelled,
        };
        if let Some(s) = self.sas(f).await? {
            return Ok(if s.is_done() {
                Step::Verified
            } else if s.is_cancelled() {
                ended(s.cancel_info().map(|c| c.cancel_code().to_string()))
            } else if s.can_be_presented() {
                Step::SasEmoji
            } else {
                Step::SasStarted
            });
        }
        let r = self.request(f).await?;
        Ok(if r.is_done() {
            Step::Verified
        } else if r.is_cancelled() {
            ended(r.cancel_info().map(|c| c.cancel_code().to_string()))
        } else if r.is_ready() {
            Step::Ready
        } else {
            Step::Requested
        })
    }

    /// A device's trust: verified, unverified, or changed since its user was verified.
    pub async fn device_trust(&self, user: &str, device: &str) -> R<Trust> {
        let u = UserId::parse(user).map_err(|_| MatrixError::Argument)?;
        let e = self.inner.client.encryption();
        let Some(d) = e
            .get_device(&u, device.into())
            .await
            .map_err(|_| MatrixError::Internal)?
        else {
            return Ok(Trust::Unknown);
        };
        if d.is_verified() {
            return Ok(Trust::Verified);
        }
        let changed =
            matches!(e.get_user_identity(&u).await, Ok(Some(i)) if i.has_verification_violation());
        Ok(if changed {
            Trust::Changed
        } else {
            Trust::Unverified
        })
    }

    // ---- recovery and key backup (CLI-MTX-07)

    /// The secret storage made; the recovery key returned once (the crate keeps no copy). Key backup stays as it is.
    pub async fn setup_recovery(&self) -> R<Zeroizing<String>> {
        let s = self
            .inner
            .client
            .encryption()
            .secret_storage()
            .create_secret_store()
            .await
            .map_err(|_| MatrixError::MatrixStore)?;
        s.export_secrets()
            .await
            .map_err(|_| MatrixError::MatrixStore)?;
        Ok(Zeroizing::new(s.secret_storage_key()))
    }

    /// The secret storage opened on this device with the recovery key.
    pub async fn recover(&self, key: &str) -> R<()> {
        self.inner
            .client
            .encryption()
            .recovery()
            .recover(key)
            .await
            .map_err(|_| MatrixError::MatrixVerification)
    }

    pub fn recovery_state(&self) -> Recovery {
        use matrix_sdk::encryption::recovery::RecoveryState as S;
        match self.inner.client.encryption().recovery().state() {
            S::Enabled => Recovery::Enabled,
            S::Disabled => Recovery::Disabled,
            S::Incomplete => Recovery::Incomplete,
            _ => Recovery::Unknown,
        }
    }

    /// Server-side key backup on (created) or off (deleted); off until the user turns it on.
    pub async fn set_key_backup(&self, on: bool) -> R<()> {
        let b = self.inner.client.encryption().backups();
        if on {
            b.create().await
        } else {
            b.disable_and_delete().await
        }
        .map_err(|_| MatrixError::MatrixStore)
    }

    /// Whether the server holds a key backup of the account.
    pub async fn key_backup(&self) -> R<bool> {
        self.inner
            .client
            .encryption()
            .backups()
            .fetch_exists_on_server()
            .await
            .map_err(|_| MatrixError::Internal)
    }

    // ---- push (CLI-MTX-08)

    /// An HTTP pusher registered, format `event_id_only`; refused for a hidden profile.
    pub async fn register_pusher(&self, p: HttpPusher) -> R<()> {
        if self.inner.hidden {
            return Err(MatrixError::MatrixPushHidden);
        }
        let mut data = HttpPusherData::new(p.url);
        data.format = Some(PushFormat::EventIdOnly);
        let pusher = PusherInit {
            ids: PusherIds::new(p.pushkey, p.app_id),
            kind: PusherKind::Http(data),
            app_display_name: p.app_display_name,
            device_display_name: p.device_display_name,
            profile_tag: None,
            lang: p.lang,
        };
        self.inner
            .client
            .pusher()
            .set(pusher.into(), false)
            .await
            .map_err(|_| MatrixError::MatrixSend)
    }

    pub async fn remove_pusher(&self, app_id: &str, pushkey: &str) -> R<()> {
        self.inner
            .client
            .pusher()
            .delete(PusherIds::new(pushkey.into(), app_id.into()))
            .await
            .map_err(|_| MatrixError::MatrixSend)
    }

    /// The push rule for `net.scaas.pqchat.v1` added (the user's opt-in) or removed; refused for a hidden profile.
    pub async fn set_pqchat_push(&self, on: bool) -> R<()> {
        if self.inner.hidden {
            return Err(MatrixError::MatrixPushHidden);
        }
        let c = &self.inner.client;
        let r = if on {
            let cond = PushCondition::EventMatch(EventMatchConditionData::new(
                "type".into(),
                EVENT_TYPE.into(),
            ));
            let rule =
                NewConditionalPushRule::new(PQCHAT_RULE.into(), vec![cond], vec![Action::Notify]);
            c.send(set_pushrule::v3::Request::new(NewPushRule::Override(rule)))
                .await
                .map(|_| ())
        } else {
            c.send(delete_pushrule::v3::Request::new(
                RuleKind::Override,
                PQCHAT_RULE.into(),
            ))
            .await
            .map(|_| ())
        };
        r.map_err(|_| MatrixError::MatrixSend)
    }
}

/// An item of a timeline event (`None`: a state or other event the list does not show).
fn item(ev: &TimelineEvent) -> Option<TimelineItem> {
    #[derive(Deserialize)]
    struct Min {
        #[serde(rename = "type")]
        ty: String,
        sender: String,
        event_id: String,
        #[serde(default)]
        origin_server_ts: u64,
        #[serde(default)]
        state_key: Option<serde::de::IgnoredAny>,
        #[serde(default)]
        content: serde_json::Value,
    }
    let m: Min = serde_json::from_str(ev.raw().json().get()).ok()?;
    if m.state_key.is_some() {
        return None;
    }
    let body = || {
        m.content
            .get("body")
            .and_then(|b| b.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let kind = match (&ev.kind, m.ty.as_str()) {
        (TimelineEventKind::UnableToDecrypt { .. }, _) | (_, "m.room.encrypted") => {
            ItemKind::Undecryptable
        }
        (_, EVENT_TYPE) => ItemKind::PqChatNeedsScaasBuild,
        (_, "m.room.message") => match m.content.get("msgtype").and_then(|t| t.as_str()) {
            Some("m.text") => ItemKind::Text(body()),
            Some("m.notice") => ItemKind::Notice(body()),
            _ => ItemKind::Other,
        },
        _ => return None,
    };
    let info = ev.encryption_info();
    let verification = match info.map(|i| &i.verification_state) {
        Some(VerificationState::Verified) => Trust::Verified,
        Some(VerificationState::Unverified(VerificationLevel::VerificationViolation)) => {
            Trust::Changed
        }
        Some(VerificationState::Unverified(_)) => Trust::Unverified,
        None => Trust::Unknown,
    };
    Some(TimelineItem {
        event_id: m.event_id,
        sender: m.sender,
        sender_device: info
            .and_then(|i| i.sender_device.as_ref())
            .map(|d| d.to_string()),
        ts: m.origin_server_ts,
        kind,
        verification,
    })
}

async fn sync_round(i: &Inner, timeout: Duration) -> R<()> {
    let res = match i.client.sync_once(sync_settings(timeout)).await {
        Ok(r) => r,
        Err(e) => {
            if matches!(
                e.client_api_error_kind(),
                Some(ErrorKind::UnknownToken { .. })
            ) {
                i.push(Update::SessionInvalid);
                return Err(MatrixError::MatrixSession);
            }
            return Err(MatrixError::Internal);
        }
    };
    let mut changed = !res.rooms.invited.is_empty() || !res.rooms.left.is_empty();
    for (room, up) in &res.rooms.joined {
        let id = room.to_string();
        let kind = i.kind(&id);
        changed |= !up.timeline.events.is_empty();
        for ev in &up.timeline.events {
            match kind {
                RoomKind::PqChat => {
                    if let Some(event) = transport::pqchat_event(ev.raw().json()) {
                        i.push(Update::PqChatEvent {
                            room: id.clone(),
                            event,
                        });
                    }
                }
                RoomKind::Matrix => {
                    if let Some(item) = item(ev) {
                        i.push(Update::Timeline {
                            room: id.clone(),
                            item,
                        });
                    }
                }
            }
        }
    }
    if changed {
        i.push(Update::RoomsChanged);
    }
    Ok(())
}
