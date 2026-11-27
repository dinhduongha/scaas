// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `scaas-matrix` (CLI-PQC-20, CLI-MTX-01..12): one matrix-rust-sdk client per open user profile. It logs in by password,
//! restores the session from the profile's store key, syncs, lists rooms by kind, reads and sends Matrix messages with
//! Matrix's own end-to-end encryption (classical), verifies devices by SAS, keeps CLI-PQC-19's privacy defaults and
//! implements PqChat's `MatrixTransport` over the same client. It signs nothing of SCaaS and holds no seed. UNAUDITED.
//!
//! Layout of a profile's Matrix directory (mode 0700): `lock` (the OS lock of the open client, CLI-MTX-02) and `store/`
//! (matrix-sdk's SQLite stores, every one encrypted by the caller's key, CLI-MTX-03). The crate's own records (session,
//! settings, PqChat marks) are sealed by a record cipher of the crate before they reach the state store (CLI-MTX-04): the
//! store encrypts only the values matrix-sdk writes itself.
#![forbid(unsafe_code)]
pub mod policy;
mod transport;

use matrix_sdk::authentication::matrix::MatrixSession;
use matrix_sdk::config::{RequestConfig, SyncSettings};
use matrix_sdk::deserialized_responses::{
    TimelineEvent, TimelineEventKind, VerificationLevel, VerificationState,
};
use matrix_sdk::encryption::verification::{
    AcceptSettings, SasState, SasVerification, Verification, VerificationRequest,
};
use matrix_sdk::encryption::{
    BackupDownloadStrategy, CrossSigningResetAuthType, EncryptionSettings, OlmError,
};
use matrix_sdk::room::MessagesOptions;
use matrix_sdk::ruma::api::client::filter::{FilterDefinition, LazyLoadOptions};
use matrix_sdk::ruma::api::client::push::{
    delete_pushrule, set_pushrule, PusherIds, PusherInit, PusherKind, RuleKind,
};
use matrix_sdk::ruma::api::client::receipt::create_receipt::v3::ReceiptType;
use matrix_sdk::ruma::api::client::sync::sync_events;
use matrix_sdk::ruma::api::client::uiaa::{
    AuthData, MatrixUserIdentifier, Password, UserIdentifier,
};
use matrix_sdk::ruma::api::error::ErrorKind;
use matrix_sdk::ruma::events::key::verification::request::ToDeviceKeyVerificationRequestEvent;
use matrix_sdk::ruma::events::key::verification::ShortAuthenticationString;
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
use matrix_sdk_store_encryption::{EncryptedValueBase64, StoreCipher};
use policy::Marks;
pub use policy::{RoomFilter, RoomKind, Settings};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, VecDeque};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::sync::{mpsc, Notify};
use zeroize::{Zeroize, Zeroizing};

pub use pqchat_transport::{MatrixTransport, RoomEvent, EVENT_MAX, EVENT_TYPE};

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
    /// an encrypted send refused because this device is not verified (cross-signing missing on it, or the account's
    /// identity not trusted here) or a verified user changed identity (CLI-MTX-07)
    MatrixDeviceUnverified,
    MatrixArgument,
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
            Self::MatrixDeviceUnverified => "MatrixDeviceUnverified",
            Self::MatrixArgument => "MatrixArgument",
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

/// A lock that a panic elsewhere left poisoned still answers: one reading of the data everywhere (A-15).
fn lk<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The profile's Matrix store key (CLI-MTX-03, CLI-UPR-29): 32 bytes from the profile's sealed item, wiped on drop, never
/// printed. The crate hands it to matrix-sdk's stores and to its record cipher at open and keeps no copy of its own.
pub struct StoreKey(Zeroizing<[u8; 32]>);

impl StoreKey {
    /// The key copied out of `bytes`, which is wiped.
    pub fn from_bytes(bytes: &mut [u8; 32]) -> Self {
        let k = StoreKey(Zeroizing::new(*bytes));
        bytes.zeroize();
        k
    }
}

impl std::fmt::Debug for StoreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoreKey(..)")
    }
}

/// How a profile's client opens (no default: the caller says whether the profile is hidden).
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// a hidden profile (CLI-UPR-08): no pusher, no PqChat push rule (CLI-MTX-08)
    pub hidden: bool,
}

/// A password login's fields (named: the password never in another field's place).
pub struct Login<'a> {
    /// an `https` URL (or `http` to a loopback IP literal), or a server name for `.well-known` discovery
    pub homeserver: &'a str,
    pub user: &'a str,
    pub password: &'a str,
    /// the device's display name, visible to the homeserver and to every user who lists the account's devices
    pub device_name: &'a str,
}

/// A device's trust, or an event's, as the front-end shows it (contract §11.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    Verified,
    Unverified,
    /// the user's identity changed since it was verified: a warning
    Changed,
    /// an event that came in the clear in an encrypted room (the homeserver or a client put it there): a warning
    Unencrypted,
    /// an event of a room without encryption
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
    /// the time of the room's latest event matrix-sdk knows, in ms since the epoch
    pub last_ts: Option<u64>,
    pub room_kind: RoomKind,
}

/// What a timeline item is.
#[derive(Clone, PartialEq, Eq)]
pub enum ItemKind {
    Text(String),
    Notice(String),
    /// an encrypted event this device cannot open: shown, never dropped
    Undecryptable,
    /// a `net.scaas.pqchat.v1` event in a Matrix room (contract §11.2)
    PqChatNeedsScaasBuild,
    Other,
}

impl std::fmt::Debug for ItemKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text(b) => write!(f, "Text({} bytes)", b.len()),
            Self::Notice(b) => write!(f, "Notice({} bytes)", b.len()),
            Self::Undecryptable => f.write_str("Undecryptable"),
            Self::PqChatNeedsScaasBuild => f.write_str("PqChatNeedsScaasBuild"),
            Self::Other => f.write_str("Other"),
        }
    }
}

/// One timeline item. Its `Debug` shows no body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineItem {
    pub event_id: String,
    pub sender: String,
    pub sender_device: Option<String>,
    pub ts: u64,
    pub kind: ItemKind,
    /// the event came encrypted (decrypted here or not)
    pub encrypted: bool,
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

/// A verification flow's step (view-model contract §11.4: `requested`, `accepted` = `Ready`, `sasEmoji`, `confirm` =
/// `Confirmed`, then `verified`, `mismatch`, `cancelled`, `timedOut`; `SasStarted` before both sides hold the emoji).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Requested,
    Ready,
    SasStarted,
    SasEmoji,
    /// this side confirmed; waiting for the other
    Confirmed,
    Verified,
    Mismatch,
    Cancelled,
    TimedOut,
}

impl Step {
    fn ended(&self) -> bool {
        matches!(
            self,
            Step::Verified | Step::Mismatch | Step::Cancelled | Step::TimedOut
        )
    }
}

/// The recovery state (matrix-sdk's).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    Unknown,
    Enabled,
    Disabled,
    Incomplete,
}

/// An HTTP pusher's fields; its URL is `https` and its format always `event_id_only` (CLI-MTX-08). Its `Debug` hides the
/// push key.
#[derive(Clone)]
pub struct HttpPusher {
    pub app_id: String,
    pub pushkey: String,
    pub url: String,
    pub app_display_name: String,
    pub device_display_name: String,
    pub lang: String,
}

impl std::fmt::Debug for HttpPusher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpPusher")
            .field("app_id", &self.app_id)
            .finish_non_exhaustive()
    }
}

/// What the sync loop reports (CLI-MTX-09: a bounded queue; the signals that must not be lost are kept beside it).
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
    /// PqChat rooms whose events were not all delivered (a full queue or a limited sync): `pqchat-core`'s `read_room` reads
    /// each again
    PqChatGap {
        rooms: Vec<String>,
    },
    /// a Matrix room whose sync skipped events (a limited timeline): page it back with `messages`
    Gap {
        room: String,
    },
    VerificationRequest {
        flow: Flow,
        device: String,
    },
    /// a tracked verification flow moved
    Verification {
        flow: Flow,
        step: Step,
    },
    /// five sync rounds in a row failed (the homeserver unreachable or refusing); the loop keeps trying
    SyncFailing,
    SessionInvalid,
    /// the queue was full and Matrix updates were dropped: read the rooms again
    Lagged,
}

/// The update queue's bound.
pub const UPDATES_MAX: usize = 1024;
/// Verification flows whose last step is kept.
const FLOWS_MAX: usize = 64;
/// The timeline events per room a sync asks for.
const SYNC_TIMELINE: u32 = 20;
/// Failed sync rounds before `SyncFailing`.
const SYNC_FAILS: u32 = 5;
const SESSION_KEY: &str = "scaas-matrix/session/v1";
const SETTINGS_KEY: &str = "scaas-matrix/settings/v1";
const MARKS_KEY: &str = "scaas-matrix/marks/v1";
/// The record cipher, exported under the store key (matrix-sdk-store-encryption's key wrap).
const CIPHER_KEY: &str = "scaas-matrix/cipher/v1";
const PQCHAT_RULE: &str = "net.scaas.pqchat.v1";
/// A sealed record's bound for a plaintext bound `max`: base64 (4/3) and the JSON frame.
fn sealed_max(max: usize) -> usize {
    max / 3 * 4 + 1024
}

#[derive(Serialize, Deserialize)]
struct SessionRecord {
    homeserver: String,
    session: MatrixSession,
}

/// A record as sealed: its name inside, so a record moved under another name does not open (`MatrixStore`).
#[derive(Serialize, Deserialize)]
struct Named<T> {
    name: String,
    value: T,
}

fn seal<T: Serialize>(c: &StoreCipher, name: &str, v: &T, max: usize) -> R<Vec<u8>> {
    let plain = Zeroizing::new(
        serde_json::to_vec(&Named {
            name: name.to_string(),
            value: v,
        })
        .map_err(|_| MatrixError::Internal)?,
    );
    if plain.len() > max {
        return Err(MatrixError::MatrixArgument);
    }
    let sealed = c
        .encrypt_value_base64_data(plain.to_vec())
        .map_err(|_| MatrixError::Internal)?;
    serde_json::to_vec(&sealed).map_err(|_| MatrixError::Internal)
}

fn unseal<T: serde::de::DeserializeOwned>(
    c: &StoreCipher,
    name: &str,
    b: &[u8],
    max: usize,
) -> R<T> {
    if b.len() > sealed_max(max) {
        return Err(MatrixError::MatrixStore);
    }
    let e: EncryptedValueBase64 =
        serde_json::from_slice(b).map_err(|_| MatrixError::MatrixStore)?;
    let plain = Zeroizing::new(
        c.decrypt_value_base64_data(e)
            .map_err(|_| MatrixError::MatrixStore)?,
    );
    let n: Named<T> = policy::decode(&plain, max)?;
    if n.name != name {
        return Err(MatrixError::MatrixStore);
    }
    Ok(n.value)
}

/// The record cipher of a state store: imported under the key when the store holds one, else made and stored.
async fn record_cipher<S: StateStore + ?Sized>(s: &S, key: &StoreKey) -> R<StoreCipher> {
    match s
        .get_custom_value(CIPHER_KEY.as_bytes())
        .await
        .map_err(|_| MatrixError::MatrixStore)?
    {
        Some(b) => {
            StoreCipher::import_with_key(&key.0[..], &b).map_err(|_| MatrixError::MatrixStore)
        }
        None => {
            let c = StoreCipher::new().map_err(|_| MatrixError::Internal)?;
            let b = c
                .export_with_key(&key.0[..])
                .map_err(|_| MatrixError::Internal)?;
            s.set_custom_value(CIPHER_KEY.as_bytes(), b)
                .await
                .map_err(|_| MatrixError::MatrixStore)?;
            Ok(c)
        }
    }
}

/// The state the client and its transport share. `close` takes the client, the lock and the update sender out: every
/// later call, the transport's too, fails (`MatrixSession`, CLI-MTX-02).
pub(crate) struct Inner {
    client: Mutex<Option<Client>>,
    lock: Mutex<Option<File>>,
    cipher: StoreCipher,
    hidden: bool,
    /// the records persist (a store key was given)
    persist: bool,
    settings: Mutex<Settings>,
    marks: Mutex<Marks>,
    /// one record write at a time, memory replaced only after it (A-8)
    write: tokio::sync::Mutex<()>,
    tx: Mutex<Option<mpsc::Sender<Update>>>,
    wake: Notify,
    lagged: AtomicBool,
    session_invalid: AtomicBool,
    pq_gaps: Mutex<BTreeSet<String>>,
    flows: Mutex<VecDeque<(Flow, Step)>>,
    syncing: AtomicBool,
    fails: AtomicU32,
}

impl Inner {
    pub(crate) fn client(&self) -> R<Client> {
        lk(&self.client).clone().ok_or(MatrixError::MatrixSession)
    }

    fn push(&self, u: Update) {
        let full = match &*lk(&self.tx) {
            Some(tx) => tx.try_send(u.clone()).is_err(),
            None => return,
        };
        if full {
            match u {
                Update::PqChatEvent { room, .. } => {
                    lk(&self.pq_gaps).insert(room);
                }
                _ => self.lagged.store(true, Ordering::SeqCst),
            }
            self.wake.notify_one();
        }
    }

    fn gap(&self, room: &str) {
        lk(&self.pq_gaps).insert(room.to_string());
        self.wake.notify_one();
    }

    pub(crate) fn kind(&self, room: &str) -> RoomKind {
        lk(&self.marks).kind(room)
    }

    async fn put<T: Serialize>(&self, name: &str, v: &T, max: usize) -> R<()> {
        let b = seal(&self.cipher, name, v, max)?;
        if !self.persist {
            return Ok(());
        }
        self.client()?
            .state_store()
            .set_custom_value(name.as_bytes(), b)
            .await
            .map(|_| ())
            .map_err(|_| MatrixError::MatrixStore)
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, name: &str, max: usize) -> R<Option<T>> {
        match self
            .client()?
            .state_store()
            .get_custom_value(name.as_bytes())
            .await
        {
            Ok(Some(b)) => unseal(&self.cipher, name, &b, max).map(Some),
            Ok(None) => Ok(None),
            Err(_) => Err(MatrixError::MatrixStore),
        }
    }

    /// The marks changed by `f` (a copy), written, then made current: nothing written when nothing changed (CLI-MTX-06).
    pub(crate) async fn marks_update(&self, f: impl FnOnce(&mut Marks) -> R<()>) -> R<()> {
        let _w = self.write.lock().await;
        let mut m = lk(&self.marks).clone();
        f(&mut m)?;
        if m == *lk(&self.marks) {
            return Ok(());
        }
        self.put(MARKS_KEY, &m, policy::MARKS_RECORD_MAX).await?;
        *lk(&self.marks) = m;
        Ok(())
    }

    /// `room` marked PqChat (a room the crate creates, joins or uses as bound).
    pub(crate) async fn mark(&self, room: &str) -> R<()> {
        // the common case (a bound room used again) takes no write lock and copies nothing
        if lk(&self.marks).marked(room) {
            return Ok(());
        }
        self.marks_update(|m| m.mark(room)).await
    }

    /// An invite to `room` held (or released): refused for a room the account is joined to as a Matrix room (CLI-MTX-06).
    /// "Joined" is the homeserver's answer, not the local view a fresh login or a late sync may lack; no answer, no hold.
    pub(crate) async fn hold(&self, room: &str, hold: bool) -> R<()> {
        let joined = if hold && !lk(&self.marks).marked(room) {
            use matrix_sdk::ruma::api::client::membership::joined_rooms;
            self.client()?
                .send(joined_rooms::v3::Request::new())
                .await
                .map_err(|_| MatrixError::MatrixRoom)?
                .joined_rooms
                .iter()
                .any(|r| r.as_str() == room)
        } else {
            false
        };
        self.marks_update(|m| m.hold(room, hold, joined)).await
    }

    /// The last step of `flow`, kept (64 flows at most); whether it moved.
    fn track(&self, flow: &Flow, step: Step) -> bool {
        let mut fl = lk(&self.flows);
        if let Some(e) = fl.iter_mut().find(|(f, _)| f == flow) {
            let moved = e.1 != step;
            e.1 = step;
            return moved;
        }
        if fl.len() >= FLOWS_MAX {
            fl.pop_front();
        }
        fl.push_back((flow.clone(), step));
        true
    }

    fn last_step(&self, flow: &Flow) -> Option<Step> {
        lk(&self.flows)
            .iter()
            .find(|(f, _)| f == flow)
            .map(|(_, s)| *s)
    }
}

/// One profile's Matrix client (CLI-MTX-02). Dropping it without [`MatrixClient::close`] also stops the sync loop; the
/// client, its stores and the lock go when the last transport handle goes too.
pub struct MatrixClient {
    inner: Arc<Inner>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Update>>,
    sync: Mutex<Option<tokio::task::JoinHandle<()>>>,
    dir: PathBuf,
}

impl Drop for MatrixClient {
    fn drop(&mut self) {
        if let Some(h) = lk(&self.sync).take() {
            h.abort();
        }
    }
}

/// The profile directory (mode 0700 on unix) locked for this client: `MatrixProfileBusy` while another holds it.
fn lock(dir: &Path) -> R<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|_| MatrixError::MatrixStore)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir).map_err(|_| MatrixError::MatrixStore)?;
    let mut o = File::options();
    o.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let f = o
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

/// The HTTP client matrix-sdk runs on: no decompression (an answer is at most what the link carries before the timeouts,
/// CLI-MTX-09), connect and read timeouts.
fn http() -> R<matrix_sdk::reqwest::Client> {
    matrix_sdk::reqwest::Client::builder()
        .no_gzip()
        .connect_timeout(Duration::from_secs(20))
        .read_timeout(Duration::from_secs(60))
        .build()
        .map_err(|_| MatrixError::Internal)
}

async fn build(dir: &Path, key: Option<&StoreKey>, hs: &Server<'_>) -> R<Client> {
    provider();
    let mut b = Client::builder()
        .http_client(http()?)
        .respect_login_well_known(false)
        .with_encryption_settings(EncryptionSettings {
            auto_enable_cross_signing: true,
            // a room key is fetched from the backup only once its key is known here (the user's `recover`)
            backup_download_strategy: BackupDownloadStrategy::AfterDecryptionFailure,
            auto_enable_backups: false,
        })
        .with_room_key_recipient_strategy(CollectStrategy::IdentityBasedStrategy)
        .request_config(
            RequestConfig::new()
                .timeout(Duration::from_secs(90))
                .disable_retry(),
        );
    b = match hs {
        Server::Url(u) => b.homeserver_url(u.clone()),
        Server::Name(n) => {
            let n = OwnedServerName::try_from(*n).map_err(|_| MatrixError::MatrixArgument)?;
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
    // a discovered homeserver is `https` (no loopback exception for what a server name points to)
    match hs {
        Server::Name(_) if c.homeserver().scheme() != "https" => {
            return Err(MatrixError::EndpointScheme)
        }
        _ => policy::homeserver(c.homeserver().as_str())?,
    };
    Ok(c)
}

/// An encrypted send's refusal by the room-key share strategy, by its name (F-2).
fn send_error(e: matrix_sdk::Error) -> MatrixError {
    match e {
        matrix_sdk::Error::OlmError(o)
            if matches!(*o, OlmError::SessionRecipientCollectionError(_)) =>
        {
            MatrixError::MatrixDeviceUnverified
        }
        _ => MatrixError::MatrixSend,
    }
}

impl MatrixClient {
    async fn wrap(
        dir: &Path,
        lock: File,
        client: Client,
        cipher: StoreCipher,
        persist: bool,
        opts: Options,
    ) -> R<MatrixClient> {
        let (tx, rx) = mpsc::channel(UPDATES_MAX);
        let inner = Arc::new(Inner {
            client: Mutex::new(Some(client)),
            lock: Mutex::new(Some(lock)),
            cipher,
            hidden: opts.hidden,
            persist,
            settings: Mutex::new(Settings::default()),
            marks: Mutex::new(Marks::default()),
            write: tokio::sync::Mutex::new(()),
            tx: Mutex::new(Some(tx)),
            wake: Notify::new(),
            lagged: AtomicBool::new(false),
            session_invalid: AtomicBool::new(false),
            pq_gaps: Mutex::new(BTreeSet::new()),
            flows: Mutex::new(VecDeque::new()),
            syncing: AtomicBool::new(false),
            fails: AtomicU32::new(0),
        });
        if let Some(s) = inner
            .get::<Settings>(SETTINGS_KEY, policy::SETTINGS_MAX)
            .await?
        {
            *lk(&inner.settings) = s;
        }
        if let Some(m) = inner
            .get::<Marks>(MARKS_KEY, policy::MARKS_RECORD_MAX)
            .await?
        {
            *lk(&inner.marks) = m;
        }
        let w = Arc::downgrade(&inner);
        inner
            .client()?
            .add_event_handler(move |ev: ToDeviceKeyVerificationRequestEvent| {
                let w = w.clone();
                async move {
                    if let Some(i) = w.upgrade() {
                        let flow = Flow {
                            user: ev.sender.to_string(),
                            flow_id: ev.content.transaction_id.to_string(),
                        };
                        i.track(&flow, Step::Requested);
                        i.push(Update::VerificationRequest {
                            flow,
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
        })
    }

    /// A password login on the profile's Matrix directory `dir` (CLI-MTX-04): the session sealed into the encrypted store
    /// when `key` is given (none: memory stores, nothing persisted). A directory that holds a store already is refused
    /// (`MatrixSession`: restore it, or [`MatrixClient::wipe`] it first). A failure after the server accepted the login logs
    /// that device out again and wipes what was written. The password is not kept.
    pub async fn login_password(
        dir: &Path,
        key: Option<StoreKey>,
        opts: Options,
        login: Login<'_>,
    ) -> R<MatrixClient> {
        let hs = server(login.homeserver)?;
        let l = lock(dir)?;
        if store_dir(dir).exists() {
            return Err(MatrixError::MatrixSession);
        }
        let client = build(dir, key.as_ref(), &hs).await;
        let client = match client {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_dir_all(store_dir(dir));
                return Err(e);
            }
        };
        let r = Self::login_on(dir, l, client, key, opts, &login).await;
        if r.is_err() {
            // under the lock again (a refused wipe leaves the store to whoever holds the directory now)
            let _ = Self::wipe(dir);
        }
        r
    }

    async fn login_on(
        dir: &Path,
        l: File,
        client: Client,
        key: Option<StoreKey>,
        opts: Options,
        login: &Login<'_>,
    ) -> R<MatrixClient> {
        client
            .matrix_auth()
            .login_username(login.user, login.password)
            .initial_device_display_name(login.device_name)
            .send()
            .await
            .map_err(|_| MatrixError::MatrixLogin)?;
        let undo = |c: Client| async move {
            let _ = tokio::time::timeout(Duration::from_secs(30), c.logout()).await;
        };
        // the login answer cannot move the client (`respect_login_well_known(false)`); checked again all the same
        if policy::homeserver(client.homeserver().as_str()).is_err() {
            undo(client).await;
            return Err(MatrixError::EndpointScheme);
        }
        let Some(session) = client.matrix_auth().session() else {
            undo(client).await;
            return Err(MatrixError::MatrixLogin);
        };
        let rec = SessionRecord {
            homeserver: client.homeserver().to_string(),
            session,
        };
        let made = match &key {
            Some(k) => record_cipher(client.state_store(), k)
                .await
                .map(|c| (c, true)),
            None => StoreCipher::new()
                .map(|c| (c, false))
                .map_err(|_| MatrixError::Internal),
        };
        let (cipher, persist) = match made {
            Ok(x) => x,
            Err(e) => {
                undo(client).await;
                return Err(e);
            }
        };
        drop(key);
        let c = match Self::wrap(dir, l, client.clone(), cipher, persist, opts).await {
            Ok(c) => c,
            Err(e) => {
                undo(client).await;
                return Err(e);
            }
        };
        if let Err(e) = c.inner.put(SESSION_KEY, &rec, policy::SESSION_MAX).await {
            c.close().await;
            undo(client).await;
            return Err(e);
        }
        client
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
        let (rec, cipher): (SessionRecord, StoreCipher) = {
            let s = SqliteStateStore::open_with_key(store_dir(dir), Some(&key.0[..]))
                .await
                .map_err(|_| MatrixError::MatrixStore)?;
            let Some(cb) = s
                .get_custom_value(CIPHER_KEY.as_bytes())
                .await
                .map_err(|_| MatrixError::MatrixStore)?
            else {
                return Err(MatrixError::MatrixSession);
            };
            let cipher = StoreCipher::import_with_key(&key.0[..], &cb)
                .map_err(|_| MatrixError::MatrixStore)?;
            let b = s
                .get_custom_value(SESSION_KEY.as_bytes())
                .await
                .map_err(|_| MatrixError::MatrixStore)?
                .ok_or(MatrixError::MatrixSession)?;
            (
                unseal(&cipher, SESSION_KEY, &b, policy::SESSION_MAX)?,
                cipher,
            )
        };
        let hs = policy::homeserver(&rec.homeserver)?;
        let client = build(dir, Some(&key), &Server::Url(hs)).await?;
        drop(key);
        client
            .restore_session(rec.session)
            .await
            .map_err(|_| MatrixError::MatrixSession)?;
        Self::wrap(dir, l, client, cipher, true, opts).await
    }

    /// The profile directory's stores deleted, under its lock (`MatrixProfileBusy` while a client holds it): a fresh start
    /// after an invalid session or a damaged store.
    pub fn wipe(dir: &Path) -> R<()> {
        let _l = lock(dir)?;
        if store_dir(dir).exists() {
            std::fs::remove_dir_all(store_dir(dir)).map_err(|_| MatrixError::MatrixStore)?;
        }
        Ok(())
    }

    /// Stops the sync loop, ends the update queue and drops the client and its stores, the transport's handle included
    /// (every later call fails `MatrixSession`); the profile directory's lock is free when it returns.
    pub async fn close(&self) {
        let h = lk(&self.sync).take();
        if let Some(h) = h {
            h.abort();
            let _ = h.await;
        }
        let client = lk(&self.inner.client).take();
        lk(&self.inner.tx).take();
        self.inner.wake.notify_waiters();
        drop(client);
        lk(&self.inner.lock).take();
    }

    /// The token invalidated on the server (at most 30 s), the client closed and the directory's stores deleted under the
    /// directory's lock, whatever the server answered. `Ok(true)`: the server invalidated the token; `Ok(false)`: it could
    /// not be reached or refused, and the token may still be valid there; `Err`: a closed client (`MatrixSession`, nothing
    /// deleted), another client holds the directory now (`MatrixProfileBusy`), or the stores could not be deleted.
    pub async fn logout(&self) -> R<bool> {
        let c = self.inner.client()?;
        let at_server = matches!(
            tokio::time::timeout(Duration::from_secs(30), c.logout()).await,
            Ok(Ok(_))
        );
        drop(c);
        self.close().await;
        Self::wipe(&self.dir)?;
        Ok(at_server)
    }

    pub fn user_id(&self) -> Option<String> {
        self.inner.client().ok()?.user_id().map(|u| u.to_string())
    }

    pub fn device_id(&self) -> Option<String> {
        self.inner.client().ok()?.device_id().map(|d| d.to_string())
    }

    pub fn homeserver(&self) -> Option<String> {
        Some(self.inner.client().ok()?.homeserver().to_string())
    }

    /// The next update (`None` once the client is closed): an invalid session first, then PqChat gaps, then `Lagged`, then
    /// the queue.
    pub async fn next_update(&self) -> Option<Update> {
        loop {
            if self.inner.session_invalid.swap(false, Ordering::SeqCst) {
                return Some(Update::SessionInvalid);
            }
            let gaps = std::mem::take(&mut *lk(&self.inner.pq_gaps));
            if !gaps.is_empty() {
                return Some(Update::PqChatGap {
                    rooms: gaps.into_iter().collect(),
                });
            }
            if self.inner.lagged.swap(false, Ordering::SeqCst) {
                return Some(Update::Lagged);
            }
            let mut rx = self.rx.lock().await;
            tokio::select! {
                u = rx.recv() => return u,
                _ = self.inner.wake.notified() => {
                    if lk(&self.inner.client).is_none() {
                        return None;
                    }
                }
            }
        }
    }

    /// One sync (presence offline), its rooms' events turned into updates; refused while the loop runs (`MatrixArgument`).
    pub async fn sync_once(&self, timeout: Duration) -> R<()> {
        if self.inner.syncing.load(Ordering::SeqCst) {
            return Err(MatrixError::MatrixArgument);
        }
        sync_round(&self.inner, timeout).await
    }

    /// The sync loop, in a task of the caller's runtime until [`MatrixClient::close`] or an invalid session; at least 1 s
    /// between rounds.
    pub fn start_sync(&self) {
        let i = self.inner.clone();
        i.syncing.store(true, Ordering::SeqCst);
        let h = tokio::spawn(async move {
            let mut wait = 1;
            loop {
                let t = tokio::time::Instant::now();
                match sync_round(&i, Duration::from_secs(30)).await {
                    Ok(()) => {
                        wait = 1;
                        tokio::time::sleep_until(t + Duration::from_secs(1)).await;
                    }
                    Err(MatrixError::MatrixSession) => break,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_secs(wait)).await;
                        wait = (wait * 2).min(30);
                    }
                }
            }
            i.syncing.store(false, Ordering::SeqCst);
        });
        if let Some(old) = lk(&self.sync).replace(h) {
            old.abort();
        }
    }

    fn room(&self, room: &str) -> R<matrix_sdk::Room> {
        let id = RoomId::parse(room).map_err(|_| MatrixError::MatrixArgument)?;
        self.inner
            .client()?
            .get_room(&id)
            .ok_or(MatrixError::MatrixRoom)
    }

    /// The kind of a room (CLI-MTX-06).
    pub fn kind(&self, room: &str) -> RoomKind {
        self.inner.kind(room)
    }

    /// The rooms of one kind (CLI-MTX-06), joined or invited.
    pub async fn rooms(&self, filter: RoomFilter) -> Vec<RoomRow> {
        let Ok(c) = self.inner.client() else {
            return vec![];
        };
        let marks = lk(&self.inner.marks).clone();
        let mut out = vec![];
        for r in c.rooms() {
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
                last_ts: r.latest_event_timestamp().map(|t| u64::from(t.0)),
                room_kind: marks.kind(&id),
                room_id: id,
            });
        }
        out
    }

    /// A direct room with `user`, encrypted from its first event (CLI-MTX-07); its id.
    pub async fn create_direct(&self, user: &str) -> R<String> {
        let u = UserId::parse(user).map_err(|_| MatrixError::MatrixArgument)?;
        let r = self
            .inner
            .client()?
            .create_dm(&u)
            .await
            .map_err(|_| MatrixError::MatrixRoom)?;
        Ok(r.room_id().to_string())
    }

    /// A Matrix invite accepted (refused for a PqChat room: `pqchat-core` joins it).
    pub async fn accept_invite(&self, room: &str) -> R<()> {
        policy::matrix_action(self.inner.kind(room))?;
        self.room(room)?
            .join()
            .await
            .map_err(|_| MatrixError::MatrixRoom)
    }

    /// An invite declined or a room left, of either kind (a membership change carries no content and no ephemeral signal;
    /// a PqChat room's mark stays).
    pub async fn leave(&self, room: &str) -> R<()> {
        self.room(room)?
            .leave()
            .await
            .map_err(|_| MatrixError::MatrixRoom)
    }

    /// A page of a Matrix room's timeline before `before`, at most `limit` (at most 100) events, newest last.
    pub async fn messages(&self, room: &str, before: Option<String>, limit: u32) -> R<Page> {
        policy::matrix_action(self.inner.kind(room))?;
        let r = self.room(room)?;
        let enc = r.encryption_state().is_encrypted();
        let mut o = MessagesOptions::backward().from(before.as_deref());
        o.limit = UInt::from(limit.clamp(1, policy::PAGE_MAX));
        let m = r.messages(o).await.map_err(|_| MatrixError::MatrixRoom)?;
        let mut items: Vec<TimelineItem> = m.chunk.iter().filter_map(|e| item(e, enc)).collect();
        items.reverse();
        Ok(Page {
            items,
            before: m.end,
        })
    }

    /// A text sent in a Matrix room (encrypted where the room is); its event id. `MatrixDeviceUnverified` when the room-key
    /// share strategy refuses (this device not verified, or a verified user changed identity).
    pub async fn send_text(&self, room: &str, text: &str) -> R<String> {
        policy::matrix_action(self.inner.kind(room))?;
        policy::text(text)?;
        let r = self.room(room)?;
        let res = r
            .send(RoomMessageEventContent::text_plain(text))
            .await
            .map_err(send_error)?;
        Ok(res.response.event_id.to_string())
    }

    pub fn settings(&self) -> Settings {
        *lk(&self.inner.settings)
    }

    async fn set(&self, f: impl FnOnce(&mut Settings)) -> R<()> {
        let _w = self.inner.write.lock().await;
        let mut s = *lk(&self.inner.settings);
        f(&mut s);
        self.inner
            .put(SETTINGS_KEY, &s, policy::SETTINGS_MAX)
            .await?;
        *lk(&self.inner.settings) = s;
        Ok(())
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
        let e = EventId::parse(event).map_err(|_| MatrixError::MatrixArgument)?;
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

    /// The PqChat transport over this client (CLI-MTX-10); it fails once the client is closed.
    pub fn transport(&self) -> Arc<dyn MatrixTransport> {
        Arc::new(transport::Transport(self.inner.clone()))
    }

    // ---- verification (CLI-MTX-07)

    /// A verification request to `device` of `user` (another user's, or this account's own).
    pub async fn request_verification(&self, user: &str, device: &str) -> R<Flow> {
        let v = MatrixError::MatrixVerification;
        let u = UserId::parse(user).map_err(|_| MatrixError::MatrixArgument)?;
        let d = self
            .inner
            .client()?
            .encryption()
            .get_device(&u, device.into())
            .await
            .map_err(|_| v)?
            .ok_or(v)?;
        let r = d.request_verification().await.map_err(|_| v)?;
        let flow = Flow {
            user: user.to_string(),
            flow_id: r.flow_id().to_string(),
        };
        self.inner.track(&flow, Step::Requested);
        Ok(flow)
    }

    /// Accepts the other side's request, or the SAS it started (emoji only: a decimal-only SAS cannot be shown).
    pub async fn accept(&self, f: &Flow) -> R<()> {
        let v = MatrixError::MatrixVerification;
        if let Some(s) = sas_of(&self.inner, f).await? {
            return s
                .accept_with_settings(AcceptSettings::with_allowed_methods(vec![
                    ShortAuthenticationString::Emoji,
                ]))
                .await
                .map_err(|_| v);
        }
        request_of(&self.inner, f)
            .await?
            .ok_or(v)?
            .accept()
            .await
            .map_err(|_| v)
    }

    /// Starts SAS on a ready request.
    pub async fn start_sas(&self, f: &Flow) -> R<()> {
        let v = MatrixError::MatrixVerification;
        request_of(&self.inner, f)
            .await?
            .ok_or(v)?
            .start_sas()
            .await
            .map_err(|_| v)?
            .ok_or(v)?;
        Ok(())
    }

    /// The seven emoji to compare, once both sides have them: `(symbol, description)`.
    pub async fn sas_emoji(&self, f: &Flow) -> R<Option<Vec<(String, String)>>> {
        Ok(sas_of(&self.inner, f)
            .await?
            .and_then(|s| s.emoji())
            .map(|e| {
                e.iter()
                    .map(|x| (x.symbol.to_string(), x.description.to_string()))
                    .collect()
            }))
    }

    /// The emoji matched.
    pub async fn confirm(&self, f: &Flow) -> R<()> {
        let v = MatrixError::MatrixVerification;
        sas_of(&self.inner, f)
            .await?
            .ok_or(v)?
            .confirm()
            .await
            .map_err(|_| v)
    }

    /// The emoji did not match: the flow cancelled as a mismatch.
    pub async fn mismatch(&self, f: &Flow) -> R<()> {
        let v = MatrixError::MatrixVerification;
        sas_of(&self.inner, f)
            .await?
            .ok_or(v)?
            .mismatch()
            .await
            .map_err(|_| v)
    }

    pub async fn cancel(&self, f: &Flow) -> R<()> {
        let v = MatrixError::MatrixVerification;
        if let Some(s) = sas_of(&self.inner, f).await? {
            return s.cancel().await.map_err(|_| v);
        }
        request_of(&self.inner, f)
            .await?
            .ok_or(v)?
            .cancel()
            .await
            .map_err(|_| v)
    }

    /// Where a flow stands; a flow matrix-sdk no longer holds answers its last step seen here (`MatrixVerification` only for
    /// a flow never seen by this client).
    pub async fn step(&self, f: &Flow) -> R<Step> {
        step_of(&self.inner, f).await
    }

    /// A device's trust: verified, unverified, or changed since its user was verified.
    pub async fn device_trust(&self, user: &str, device: &str) -> R<Trust> {
        let u = UserId::parse(user).map_err(|_| MatrixError::MatrixArgument)?;
        let c = self.inner.client()?;
        let e = c.encryption();
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

    /// Whether this device may send encrypted: the account's identity is known here and trusted (what the room-key share
    /// strategy asks, CLI-MTX-07).
    pub async fn device_verified(&self) -> R<bool> {
        let c = self.inner.client()?;
        let me = c.user_id().ok_or(MatrixError::MatrixSession)?.to_owned();
        Ok(matches!(c.encryption().get_user_identity(&me).await, Ok(Some(i)) if i.is_verified()))
    }

    /// A new cryptographic identity for the account, on the caller's call: this device becomes its only verified device
    /// and every other user sees the identity changed (`Trust::Changed`). The homeserver may ask for the password.
    pub async fn reset_identity(&self, password: &str) -> R<()> {
        let c = self.inner.client()?;
        let v = MatrixError::MatrixVerification;
        let Some(h) = c
            .encryption()
            .recovery()
            .reset_identity()
            .await
            .map_err(|_| v)?
        else {
            return Ok(());
        };
        let auth = match h.auth_type() {
            CrossSigningResetAuthType::Uiaa(info) => {
                let user = c.user_id().ok_or(MatrixError::MatrixSession)?.to_string();
                let mut p = Password::new(
                    UserIdentifier::Matrix(MatrixUserIdentifier::new(user)),
                    password.to_string(),
                );
                p.session = info.session.clone();
                Some(AuthData::Password(p))
            }
            CrossSigningResetAuthType::OAuth(_) => return Err(MatrixError::MatrixLogin),
        };
        h.reset(auth).await.map_err(|_| v)
    }

    // ---- recovery and key backup (CLI-MTX-07)

    /// The secret storage made with this device's secrets; the recovery key returned once (the crate keeps no copy). Refused
    /// (`MatrixVerification`) when the account has secret storage already (`recover` it) or this device lacks the
    /// cross-signing keys (verify it, or `reset_identity`).
    pub async fn setup_recovery(&self) -> R<Zeroizing<String>> {
        let c = self.inner.client()?;
        let e = c.encryption();
        let s = MatrixError::MatrixSend;
        if e.secret_storage().is_enabled().await.map_err(|_| s)? {
            return Err(MatrixError::MatrixVerification);
        }
        if !e
            .cross_signing_status()
            .await
            .is_some_and(|x| x.is_complete())
        {
            return Err(MatrixError::MatrixVerification);
        }
        let store = e
            .secret_storage()
            .create_secret_store()
            .await
            .map_err(|_| s)?;
        Ok(Zeroizing::new(store.secret_storage_key()))
    }

    /// The secret storage opened on this device with the recovery key (its cross-signing keys and, when backed up, the
    /// backup key: room keys are then fetched from the backup as needed).
    pub async fn recover(&self, key: &str) -> R<()> {
        self.inner
            .client()?
            .encryption()
            .recovery()
            .recover(key)
            .await
            .map_err(|_| MatrixError::MatrixVerification)
    }

    pub fn recovery_state(&self) -> Recovery {
        use matrix_sdk::encryption::recovery::RecoveryState as S;
        let Ok(c) = self.inner.client() else {
            return Recovery::Unknown;
        };
        match c.encryption().recovery().state() {
            S::Enabled => Recovery::Enabled,
            S::Disabled => Recovery::Disabled,
            S::Incomplete => Recovery::Incomplete,
            _ => Recovery::Unknown,
        }
    }

    /// Server-side key backup on or off, off until the user turns it on. On: refused when the account has a backup already
    /// (`MatrixVerification`: `recover` to use it); the new backup's key goes into the secret storage when there is one.
    /// Off: the server's backup deleted.
    pub async fn set_key_backup(&self, on: bool) -> R<()> {
        let c = self.inner.client()?;
        let e = c.encryption();
        if on {
            if e.backups()
                .fetch_exists_on_server()
                .await
                .map_err(|_| MatrixError::MatrixSend)?
            {
                return Err(MatrixError::MatrixVerification);
            }
            e.recovery()
                .enable_backup()
                .await
                .map_err(|_| MatrixError::MatrixSend)
        } else {
            e.backups()
                .disable_and_delete()
                .await
                .map_err(|_| MatrixError::MatrixSend)
        }
    }

    /// Whether the server holds a key backup of the account.
    pub async fn key_backup(&self) -> R<bool> {
        self.inner
            .client()?
            .encryption()
            .backups()
            .fetch_exists_on_server()
            .await
            .map_err(|_| MatrixError::MatrixSend)
    }

    // ---- push (CLI-MTX-08)

    /// An HTTP pusher registered (`https` URL), format `event_id_only`; refused for a hidden profile.
    pub async fn register_pusher(&self, p: HttpPusher) -> R<()> {
        if self.inner.hidden {
            return Err(MatrixError::MatrixPushHidden);
        }
        policy::pusher_url(&p.url)?;
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
            .client()?
            .pusher()
            .set(pusher.into(), false)
            .await
            .map_err(|_| MatrixError::MatrixSend)
    }

    /// A pusher removed (allowed in a hidden profile too).
    pub async fn remove_pusher(&self, app_id: &str, pushkey: &str) -> R<()> {
        self.inner
            .client()?
            .pusher()
            .delete(PusherIds::new(pushkey.into(), app_id.into()))
            .await
            .map_err(|_| MatrixError::MatrixSend)
    }

    /// The push rule for `net.scaas.pqchat.v1` added (the user's opt-in; refused for a hidden profile) or removed (allowed
    /// in a hidden profile).
    pub async fn set_pqchat_push(&self, on: bool) -> R<()> {
        if on && self.inner.hidden {
            return Err(MatrixError::MatrixPushHidden);
        }
        let c = self.inner.client()?;
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

async fn sas_of(i: &Inner, f: &Flow) -> R<Option<SasVerification>> {
    let u = UserId::parse(&f.user).map_err(|_| MatrixError::MatrixArgument)?;
    Ok(
        match i
            .client()?
            .encryption()
            .get_verification(&u, &f.flow_id)
            .await
        {
            Some(Verification::SasV1(s)) => Some(s),
            _ => None,
        },
    )
}

async fn request_of(i: &Inner, f: &Flow) -> R<Option<VerificationRequest>> {
    let u = UserId::parse(&f.user).map_err(|_| MatrixError::MatrixArgument)?;
    Ok(i.client()?
        .encryption()
        .get_verification_request(&u, &f.flow_id)
        .await)
}

/// A cancel code's step: a mismatched SAS, key or commitment is a mismatch (the mark of an attack on the SAS).
fn ended(code: Option<String>) -> Step {
    match code.as_deref() {
        Some("m.mismatched_sas" | "m.key_mismatch" | "m.mismatched_commitment") => Step::Mismatch,
        Some("m.timeout") => Step::TimedOut,
        _ => Step::Cancelled,
    }
}

async fn step_of(i: &Inner, f: &Flow) -> R<Step> {
    let s = if let Some(s) = sas_of(i, f).await? {
        if s.is_done() {
            Step::Verified
        } else if s.is_cancelled() {
            ended(s.cancel_info().map(|c| c.cancel_code().to_string()))
        } else if matches!(s.state(), SasState::Confirmed) {
            Step::Confirmed
        } else if s.emoji().is_some() {
            Step::SasEmoji
        } else {
            Step::SasStarted
        }
    } else if let Some(r) = request_of(i, f).await? {
        if r.is_done() {
            Step::Verified
        } else if r.is_cancelled() {
            ended(r.cancel_info().map(|c| c.cancel_code().to_string()))
        } else if r.is_ready() {
            Step::Ready
        } else {
            Step::Requested
        }
    } else {
        return i.last_step(f).ok_or(MatrixError::MatrixVerification);
    };
    i.track(f, s);
    Ok(s)
}

/// An item of a timeline event of a room (`encrypted_room`: the room has encryption on); `None`: a state or other event
/// the list does not show.
fn item(ev: &TimelineEvent, encrypted_room: bool) -> Option<TimelineItem> {
    #[derive(Deserialize)]
    struct Min {
        #[serde(rename = "type")]
        ty: String,
        sender: String,
        event_id: String,
        #[serde(default)]
        origin_server_ts: serde_json::Value,
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
    let came_encrypted = matches!(
        ev.kind,
        TimelineEventKind::Decrypted(_) | TimelineEventKind::UnableToDecrypt { .. }
    );
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
        None if encrypted_room && !came_encrypted => Trust::Unencrypted,
        None => Trust::Unknown,
    };
    Some(TimelineItem {
        event_id: m.event_id,
        sender: m.sender,
        sender_device: info
            .and_then(|i| i.sender_device.as_ref())
            .map(|d| d.to_string()),
        ts: m.origin_server_ts.as_u64().unwrap_or(0),
        kind,
        encrypted: came_encrypted,
        verification,
    })
}

async fn sync_round(i: &Inner, timeout: Duration) -> R<()> {
    let c = i.client()?;
    let res = match c.sync_once(sync_settings(timeout)).await {
        Ok(r) => {
            i.fails.store(0, Ordering::SeqCst);
            r
        }
        Err(e) => {
            if matches!(
                e.client_api_error_kind(),
                Some(ErrorKind::UnknownToken { .. })
            ) {
                i.session_invalid.store(true, Ordering::SeqCst);
                i.wake.notify_one();
                return Err(MatrixError::MatrixSession);
            }
            if i.fails.fetch_add(1, Ordering::SeqCst) + 1 == SYNC_FAILS {
                i.push(Update::SyncFailing);
            }
            return Err(MatrixError::Internal);
        }
    };
    let mut changed = !res.rooms.invited.is_empty() || !res.rooms.left.is_empty();
    // a held invite the account joined (from another client): a Matrix room again (J-1)
    let held_joined: Vec<String> = {
        let m = lk(&i.marks);
        res.rooms
            .joined
            .keys()
            .map(|r| r.to_string())
            .filter(|r| !m.marked(r) && m.kind(r) == RoomKind::PqChat)
            .collect()
    };
    for r in held_joined {
        let _ = i
            .marks_update(|m| {
                m.release_joined(&r);
                Ok(())
            })
            .await;
    }
    for (room, up) in &res.rooms.joined {
        let id = room.to_string();
        let kind = i.kind(&id);
        // a joined room in the answer moved: events, state, or its counts
        changed = true;
        let enc = c
            .get_room(room)
            .is_some_and(|r| r.encryption_state().is_encrypted());
        if up.timeline.limited {
            match kind {
                RoomKind::PqChat => i.gap(&id),
                RoomKind::Matrix => i.push(Update::Gap { room: id.clone() }),
            }
        }
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
                    if let Some(item) = item(ev, enc) {
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
    // the tracked flows that moved
    let flows: Vec<Flow> = lk(&i.flows)
        .iter()
        .filter(|(_, s)| !s.ended())
        .map(|(f, _)| f.clone())
        .collect();
    for f in flows {
        let before = i.last_step(&f);
        if let Ok(step) = step_of(i, &f).await {
            if before != Some(step) {
                i.push(Update::Verification { flow: f, step });
            }
        }
    }
    Ok(())
}

/// Test support (feature `testing`, tests only): a session record sealed into a profile directory's store as
/// `login_password` writes it, so the offline tests open a profile without a homeserver.
#[cfg(feature = "testing")]
pub mod testing {
    use super::*;

    pub async fn seed_session(
        dir: &Path,
        key: &mut [u8; 32],
        homeserver: &str,
        user_id: &str,
        device_id: &str,
        access_token: &str,
    ) -> R<()> {
        let key = StoreKey::from_bytes(key);
        let s = SqliteStateStore::open_with_key(store_dir(dir), Some(&key.0[..]))
            .await
            .map_err(|_| MatrixError::MatrixStore)?;
        let c = record_cipher(&s, &key).await?;
        let session: MatrixSession = serde_json::from_value(serde_json::json!({
            "user_id": user_id, "device_id": device_id, "access_token": access_token,
        }))
        .map_err(|_| MatrixError::MatrixArgument)?;
        let rec = SessionRecord {
            homeserver: homeserver.to_string(),
            session,
        };
        let b = seal(&c, SESSION_KEY, &rec, policy::SESSION_MAX)?;
        s.set_custom_value(SESSION_KEY.as_bytes(), b)
            .await
            .map_err(|_| MatrixError::MatrixStore)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use matrix_sdk::deserialized_responses::TimelineEvent;
    use matrix_sdk::ruma::serde::Raw;

    fn plain(v: serde_json::Value) -> TimelineEvent {
        TimelineEvent::from_plaintext(Raw::from_json(serde_json::value::to_raw_value(&v).unwrap()))
    }

    fn msg(ty: &str, content: serde_json::Value, ts: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"type": ty, "sender": "@a:x", "event_id": "$e", "origin_server_ts": ts, "content": content})
    }

    #[test]
    fn items_by_kind() {
        let text = plain(msg(
            "m.room.message",
            serde_json::json!({"msgtype": "m.text", "body": "hi"}),
            5.into(),
        ));
        let i = item(&text, false).unwrap();
        assert_eq!(
            (i.kind, i.encrypted, i.verification, i.ts),
            (ItemKind::Text("hi".into()), false, Trust::Unknown, 5)
        );
        // a cleartext message in an encrypted room is flagged, not shown as an ordinary one
        assert_eq!(item(&text, true).unwrap().verification, Trust::Unencrypted);
        let pq = plain(msg(EVENT_TYPE, serde_json::json!({"v": 1}), 1.into()));
        assert_eq!(
            item(&pq, false).unwrap().kind,
            ItemKind::PqChatNeedsScaasBuild
        );
        let enc = plain(msg(
            "m.room.encrypted",
            serde_json::json!({"algorithm": "m.megolm.v1.aes-sha2"}),
            1.into(),
        ));
        assert_eq!(item(&enc, true).unwrap().kind, ItemKind::Undecryptable);
        // an odd timestamp does not drop the event
        let odd = plain(msg(
            "m.room.message",
            serde_json::json!({"msgtype": "m.text", "body": "x"}),
            (-3).into(),
        ));
        assert_eq!(item(&odd, false).unwrap().ts, 0);
        // a state event is not an item
        let mut st = msg("m.room.name", serde_json::json!({"name": "n"}), 1.into());
        st["state_key"] = "".into();
        assert!(item(&plain(st), false).is_none());
        // Debug shows no body
        assert!(!format!("{:?}", item(&text, false).unwrap()).contains("hi"));
    }

    #[test]
    fn records_sealed_and_named() {
        let c = StoreCipher::new().unwrap();
        let s = Settings {
            public_receipts: true,
            typing: false,
        };
        let b = seal(&c, SETTINGS_KEY, &s, policy::SETTINGS_MAX).unwrap();
        assert!(!String::from_utf8_lossy(&b).contains("public_receipts"));
        assert_eq!(
            unseal::<Settings>(&c, SETTINGS_KEY, &b, policy::SETTINGS_MAX).unwrap(),
            s
        );
        // under another name, or another cipher, it does not open
        assert_eq!(
            unseal::<Settings>(&c, MARKS_KEY, &b, policy::SETTINGS_MAX).err(),
            Some(MatrixError::MatrixStore)
        );
        let other = StoreCipher::new().unwrap();
        assert_eq!(
            unseal::<Settings>(&other, SETTINGS_KEY, &b, policy::SETTINGS_MAX).err(),
            Some(MatrixError::MatrixStore)
        );
        // a record above its bound is not written, nor read
        assert_eq!(
            seal(
                &c,
                SETTINGS_KEY,
                &"x".repeat(policy::SETTINGS_MAX),
                policy::SETTINGS_MAX
            )
            .err(),
            Some(MatrixError::MatrixArgument)
        );
        assert_eq!(
            unseal::<Settings>(
                &c,
                SETTINGS_KEY,
                &vec![b' '; sealed_max(policy::SETTINGS_MAX) + 1],
                policy::SETTINGS_MAX
            )
            .err(),
            Some(MatrixError::MatrixStore)
        );
    }

    #[tokio::test]
    async fn the_record_cipher_opens_only_under_its_store_key() {
        let s = matrix_sdk::MemoryStore::new();
        let a = record_cipher(&s, &StoreKey::from_bytes(&mut [1; 32]))
            .await
            .unwrap();
        let b = seal(&a, SETTINGS_KEY, &Settings::default(), policy::SETTINGS_MAX).unwrap();
        // the same key finds the same cipher
        let again = record_cipher(&s, &StoreKey::from_bytes(&mut [1; 32]))
            .await
            .unwrap();
        assert_eq!(
            unseal::<Settings>(&again, SETTINGS_KEY, &b, policy::SETTINGS_MAX).unwrap(),
            Settings::default()
        );
        // another key opens nothing, and does not replace the stored cipher
        assert_eq!(
            record_cipher(&s, &StoreKey::from_bytes(&mut [2; 32]))
                .await
                .err(),
            Some(MatrixError::MatrixStore)
        );
        let still = record_cipher(&s, &StoreKey::from_bytes(&mut [1; 32]))
            .await
            .unwrap();
        assert!(unseal::<Settings>(&still, SETTINGS_KEY, &b, policy::SETTINGS_MAX).is_ok());
    }

    #[test]
    fn verification_endings() {
        for c in [
            "m.mismatched_sas",
            "m.key_mismatch",
            "m.mismatched_commitment",
        ] {
            assert_eq!(ended(Some(c.into())), Step::Mismatch, "{c}");
        }
        assert_eq!(ended(Some("m.timeout".into())), Step::TimedOut);
        assert_eq!(ended(Some("m.user".into())), Step::Cancelled);
        assert_eq!(ended(None), Step::Cancelled);
    }

    #[test]
    fn store_key_wipes_the_callers_copy() {
        let mut b = [7u8; 32];
        let k = StoreKey::from_bytes(&mut b);
        assert_eq!(b, [0u8; 32]);
        assert_eq!(*k.0, [7u8; 32]);
        assert_eq!(format!("{k:?}"), "StoreKey(..)");
    }
}
