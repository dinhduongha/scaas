//! Backend SQLite (A1.2): một kết nối, WAL, `synchronous = FULL`, transaction `BEGIN IMMEDIATE` (mọi writer xếp
//! hàng trên khoá ghi của file); owner lock = `flock` trên `<db>.lock` (thay `locking_mode = EXCLUSIVE`).
use std::fs::File;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Sqlite, Transaction};

use super::*;

const LIVE_SQL: &str = "('queued', 'leased', 'signed', 'broadcast')";
const RESERVED: [&str; 3] = ["~gateway", "~mesh", "~dex"];

pub struct SqliteStore {
    pub(crate) pool: SqlitePool,
    id: Identity,
    /// Giữ `flock` suốt đời process; thả = mất quyền chủ.
    _lock: File,
    #[cfg(test)]
    commit_unknown: std::sync::atomic::AtomicBool,
}

fn hex16() -> String {
    alloy::hex::encode(rand::random::<[u8; 16]>())
}

impl SqliteStore {
    pub async fn open(url: &str, owner: &str) -> Result<Self> {
        if url.contains(":memory:") || url.contains("mode=memory") {
            return Err(StoreError::Invalid("an in-memory store has no owner lock".into()));
        }
        let opts = SqliteConnectOptions::from_str(url)?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let mut lock_path = opts.get_filename().as_os_str().to_owned();
        lock_path.push(".lock");
        let lock = File::options().read(true).write(true).create(true).truncate(false).open(&lock_path)
            .map_err(|e| StoreError::Invalid(format!("{}: {e}", lock_path.to_string_lossy())))?;
        lock.try_lock().map_err(|e| StoreError::Owned(format!("{}: {e}", lock_path.to_string_lossy())))?;
        let pool = SqlitePoolOptions::new().max_connections(1).connect_with(opts).await?;
        sqlx::migrate!("migrations/sqlite").run(&pool).await?;
        let now = now_ms();
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query("INSERT INTO meta (name, value) VALUES ('store_id', ?) ON CONFLICT (name) DO NOTHING")
            .bind(hex16()).execute(&mut *tx).await?;
        let incarnation = hex16();
        let epoch: i64 = sqlx::query_scalar(
            "UPDATE store_owner SET epoch = epoch + 1, incarnation = ?, owner = ?, since = ? WHERE id = 1 RETURNING epoch")
            .bind(&incarnation).bind(owner).bind(now).fetch_one(&mut *tx).await?;
        let store_id: String = sqlx::query_scalar("SELECT value FROM meta WHERE name = 'store_id'")
            .fetch_one(&mut *tx).await?;
        let restore: String = sqlx::query_scalar("SELECT value FROM meta WHERE name = 'restore_epoch'")
            .fetch_one(&mut *tx).await?;
        for ns in RESERVED {
            sqlx::query("INSERT INTO namespace (name, state, created_at, updated_at) VALUES (?, 'active', ?, ?) \
                         ON CONFLICT (name) DO NOTHING")
                .bind(ns).bind(now).bind(now).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        let restore_epoch = restore.parse().map_err(|_| StoreError::Invalid(format!("meta restore_epoch {restore}")))?;
        Ok(Self {
            pool,
            id: Identity { store_id, incarnation, epoch, restore_epoch },
            _lock: lock,
            #[cfg(test)]
            commit_unknown: Default::default(),
        })
    }

    #[cfg(test)]
    pub(crate) fn drop_lock_for_test(&self) {
        self._lock.unlock().unwrap();
    }

    /// Lần commit kế tiếp của `transition` thành công nhưng báo `Unknown` (mất kết nối sau COMMIT).
    #[cfg(test)]
    pub(crate) fn inject_commit_unknown(&self) {
        self.commit_unknown.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    async fn begin(&self) -> Result<Transaction<'static, Sqlite>> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let epoch: i64 = sqlx::query_scalar("SELECT epoch FROM store_owner WHERE id = 1").fetch_one(&mut *tx).await?;
        if epoch != self.id.epoch {
            return Err(StoreError::NotOwner);
        }
        Ok(tx)
    }

    async fn transition_tx(&self, uid: i64, from: State, to: State, f: &Fields, now: i64) -> Result<Transition> {
        let mut tx = self.begin().await?;
        let row: Option<(String, Option<String>, bool, Option<String>)> =
            sqlx::query_as("SELECT state, tx_hash, hold, lane_hint FROM job WHERE uid = ?")
                .bind(uid).fetch_optional(&mut *tx).await?;
        let (state, tx_hash, hold, hint) = row.ok_or(StoreError::NotFound)?;
        let state = State::try_from(state).map_err(StoreError::Invalid)?;
        let moved = Transition::Moved { state, tx_hash };
        if late_noop(from, to) || state != from {
            return Ok(moved);
        }
        let lane = if to == Leased { f.lane_label.as_deref() } else { None };
        if to == Leased && (hold || hint.is_some_and(|h| Some(h.as_str()) != lane)) {
            return Ok(moved);
        }
        let n = sqlx::query(
            "UPDATE job SET state = ?1, updated_at = ?2,
               lane_label  = CASE WHEN ?1 = 'queued' THEN NULL ELSE COALESCE(?3, lane_label) END,
               claim_block = CASE WHEN ?1 = 'queued' THEN NULL ELSE COALESCE(?4, claim_block) END,
               outer_nonce = CASE WHEN ?1 = 'queued' THEN NULL ELSE COALESCE(?5, outer_nonce) END,
               tx_hash     = CASE WHEN ?1 = 'queued' THEN NULL ELSE COALESCE(?6, tx_hash) END,
               last_error  = COALESCE(?7, last_error),
               attempt_count = attempt_count + (CASE WHEN ?1 = 'leased' THEN 1 ELSE 0 END)
             WHERE uid = ?8 AND state = ?9")
            .bind(to.as_str()).bind(now).bind(lane).bind(if to == Leased { f.claim_block } else { None })
            .bind(f.outer_nonce).bind(&f.tx_hash).bind(&f.error).bind(uid).bind(from.as_str())
            .execute(&mut *tx).await?.rows_affected();
        if n == 0 {
            return Ok(moved);
        }
        if let (Some(nonce), false) = (f.outer_nonce, to == Queued) {
            let n = sqlx::query("UPDATE lane SET journal_max = MAX(COALESCE(journal_max, ?1), ?1) \
                                 WHERE (chain_key, label) = (SELECT chain_key, lane_label FROM job WHERE uid = ?2)")
                .bind(nonce).bind(uid).execute(&mut *tx).await?.rows_affected();
            if n == 0 {
                return Err(StoreError::Invalid(format!("job {uid}: its lane is not in the store")));
            }
        }
        let seq = event(&mut tx, uid, f.error.as_deref(), now).await?;
        tx.commit().await?;
        #[cfg(test)]
        if self.commit_unknown.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(StoreError::Db(sqlx::Error::PoolClosed));
        }
        Ok(Transition::Ok { seq })
    }

    async fn accept_once(&self, j: &NewJob, now: i64) -> Result<Option<Accept>> {
        let mut tx = self.begin().await?;
        let max: i64 = sqlx::query_scalar("SELECT max_live_jobs FROM namespace WHERE name = ?")
            .bind(&j.namespace).fetch_optional(&mut *tx).await?
            .ok_or_else(|| StoreError::Invalid(format!("unknown namespace {}", j.namespace)))?;
        let rows: Vec<JobRow> = sqlx::query_as(
            "SELECT * FROM job WHERE namespace = ? AND origin_scope = ? AND origin_producer = ? AND origin_key = ? \
             ORDER BY generation DESC")
            .bind(&j.namespace).bind(&j.origin.scope).bind(&j.origin.producer).bind(&j.origin.key)
            .fetch_all(&mut *tx).await?;
        if let Some(r) = rows.iter().find(|r| r.generation == j.origin.generation) {
            let same = r.kind == "tombstone" || r.payload_hash.as_deref() == Some(&j.payload_hash[..]);
            return Ok(Some(if same { Accept::Existing(r.clone()) } else { Accept::IdempotencyMismatch { uid: r.uid } }));
        }
        if let Some(r) = rows.iter().find(|r| r.generation < j.origin.generation && r.state.is_live()) {
            return Ok(Some(Accept::PreviousGenerationLive { uid: r.uid }));
        }
        let live: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM job WHERE namespace = ? AND state IN {LIVE_SQL}"))
            .bind(&j.namespace).fetch_one(&mut *tx).await?;
        if live >= max {
            return Ok(Some(Accept::Quota));
        }
        let uid = next(&mut tx, "job").await?;
        let ins = sqlx::query(
            "INSERT INTO job (uid, namespace, origin_scope, origin_producer, origin_key, generation, client_ref, chain_key, \
               kind, digest, payload, payload_hash, valid_until, lane_hint, bus_scope, private_window_secs, state, \
               created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)")
            .bind(uid).bind(&j.namespace).bind(&j.origin.scope).bind(&j.origin.producer).bind(&j.origin.key)
            .bind(j.origin.generation).bind(&j.client_ref).bind(&j.chain_key).bind(&j.kind)
            .bind(j.digest.map(|d| d.to_vec())).bind(&j.payload).bind(&j.payload_hash[..]).bind(j.valid_until)
            .bind(&j.lane_hint).bind(&j.bus_scope).bind(j.private_window_secs).bind(now).bind(now)
            .execute(&mut *tx).await;
        if let Err(e) = ins {
            return match unique_constraint(&e) {
                Some("job_live_digest") => Ok(Some(Accept::DuplicateDigest)),
                Some(_) => Ok(None), // job_origin: a concurrent insert won, re-run the SELECT
                None => Err(e.into()),
            };
        }
        event(&mut tx, uid, None, now).await?;
        let row = job_row(&mut tx, uid).await?;
        tx.commit().await?;
        Ok(Some(Accept::Created(row)))
    }

    async fn cancel_in(&self, tx: &mut Transaction<'static, Sqlite>, uid: i64, now: i64) -> Result<Cancel> {
        let Some(row) = sqlx::query_as::<_, JobRow>("SELECT * FROM job WHERE uid = ?").bind(uid)
            .fetch_optional(&mut **tx).await? else { return Ok(Cancel::NotFound) };
        Ok(match (row.state, row.published_at) {
            (Cancelled, _) => Cancel::Cancelled(row),
            (Queued | Leased, None) => {
                sqlx::query("UPDATE job SET state = 'cancelled', last_error = 'cancelled', updated_at = ? WHERE uid = ?")
                    .bind(now).bind(uid).execute(&mut **tx).await?;
                event(tx, uid, Some("cancelled"), now).await?;
                Cancel::Cancelled(job_row(tx, uid).await?)
            }
            (Queued, Some(_)) => {
                sqlx::query("UPDATE job SET hold = 1, updated_at = ? WHERE uid = ?").bind(now).bind(uid)
                    .execute(&mut **tx).await?;
                Cancel::TooLate { state: Queued, published: true }
            }
            (state, published) => Cancel::TooLate { state, published: published.is_some() },
        })
    }
}

/// SQLite báo danh sách cột, không báo tên constraint: ánh xạ ngược về tên trong DDL (A1.3).
pub(crate) fn unique_constraint(e: &sqlx::Error) -> Option<&'static str> {
    let db = e.as_database_error()?;
    if db.kind() != sqlx::error::ErrorKind::UniqueViolation {
        return None;
    }
    let m = db.message();
    if m.contains("job_live_digest") || m.ends_with("job.chain_key, job.digest") {
        Some("job_live_digest")
    } else if m.ends_with("job.namespace, job.origin_scope, job.origin_producer, job.origin_key, job.generation") {
        Some("job_origin")
    } else {
        None
    }
}

async fn next(tx: &mut SqliteConnection, counter: &str) -> Result<i64> {
    Ok(sqlx::query_scalar("UPDATE seq_counter SET value = value + 1 WHERE name = ? RETURNING value")
        .bind(counter).fetch_one(tx).await?)
}

/// `job_event` = snapshot của dòng sau chuyển trạng thái; cùng transaction cập nhật `job.last_seq`.
async fn event(tx: &mut SqliteConnection, uid: i64, error: Option<&str>, now: i64) -> Result<i64> {
    let seq = next(&mut *tx, "job_event").await?;
    sqlx::query("INSERT INTO job_event (seq, job_uid, namespace, state, tx_hash, outer_nonce, signer, error, at) \
                 SELECT ?1, uid, namespace, state, tx_hash, outer_nonce, lane_label, ?3, ?4 FROM job WHERE uid = ?2")
        .bind(seq).bind(uid).bind(error).bind(now).execute(&mut *tx).await?;
    sqlx::query("UPDATE job SET last_seq = ? WHERE uid = ?").bind(seq).bind(uid).execute(&mut *tx).await?;
    Ok(seq)
}

async fn job_row(tx: &mut SqliteConnection, uid: i64) -> Result<JobRow> {
    Ok(sqlx::query_as("SELECT * FROM job WHERE uid = ?").bind(uid).fetch_one(tx).await?)
}

async fn audit_in(tx: &mut SqliteConnection, e: &AuditEntry, now: i64) -> Result<AuditRow> {
    let prev: Vec<u8> = sqlx::query_scalar("SELECT row_hash FROM audit_log ORDER BY seq DESC LIMIT 1")
        .fetch_optional(&mut *tx).await?.unwrap_or_else(|| vec![0; 32]);
    let seq = next(&mut *tx, "audit").await?;
    let hash = audit_hash(&prev, seq, now, e);
    sqlx::query("INSERT INTO audit_log (seq, at, actor_kind, iss, sub, roles, method, route, target, before, after, \
                 result, request_id, prev_hash, row_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(seq).bind(now).bind(&e.actor_kind).bind(&e.iss).bind(&e.sub).bind(&e.roles).bind(&e.method)
        .bind(&e.route).bind(&e.target).bind(&e.before).bind(&e.after).bind(e.result).bind(&e.request_id)
        .bind(&prev).bind(&hash[..]).execute(&mut *tx).await?;
    Ok(sqlx::query_as("SELECT * FROM audit_log WHERE seq = ?").bind(seq).fetch_one(tx).await?)
}

fn boot_audit(target: String, after: &impl Serialize) -> AuditEntry {
    AuditEntry {
        actor_kind: "bootstrap".into(),
        method: "BOOTSTRAP".into(),
        route: "node.toml".into(),
        target: Some(target),
        after: serde_json::to_string(after).ok(),
        request_id: "bootstrap".into(),
        ..Default::default()
    }
}

#[async_trait]
impl Backend for SqliteStore {
    fn identity(&self) -> &Identity {
        &self.id
    }

    async fn head_seq(&self, counter: &str) -> Result<i64> {
        Ok(sqlx::query_scalar("SELECT value FROM seq_counter WHERE name = ?").bind(counter).fetch_one(&self.pool).await?)
    }

    async fn accept(&self, job: &NewJob, now_ms: i64) -> Result<Accept> {
        for _ in 0..3 {
            if let Some(a) = self.accept_once(job, now_ms).await? {
                return Ok(a);
            }
        }
        Err(StoreError::Invalid("accept: the origin race did not settle in 3 tries".into()))
    }

    async fn transition(&self, uid: i64, from: State, to: State, f: &Fields, now_ms: i64) -> Result<Transition> {
        if !allowed(from, to) && !late_noop(from, to) {
            return Err(StoreError::Illegal { from, to });
        }
        if to == Leased && f.lane_label.is_none() {
            return Err(StoreError::Invalid("a lease names its lane".into()));
        }
        if to == Signed && (f.outer_nonce.is_none() || f.tx_hash.is_none()) {
            return Err(StoreError::Invalid("signed needs outer_nonce and tx_hash".into()));
        }
        match self.transition_tx(uid, from, to, f, now_ms).await {
            Err(StoreError::Db(e)) => Ok(Transition::Unknown(e.to_string())),
            other => other,
        }
    }

    async fn cancel(&self, uid: i64, now_ms: i64) -> Result<Cancel> {
        let mut tx = self.begin().await?;
        let c = self.cancel_in(&mut tx, uid, now_ms).await?;
        tx.commit().await?;
        Ok(c)
    }

    async fn cancel_by_origin(&self, namespace: &str, o: &Origin, valid_until: i64, now_ms: i64) -> Result<Cancel> {
        let mut tx = self.begin().await?;
        let uid: Option<i64> = sqlx::query_scalar(
            "SELECT uid FROM job WHERE namespace = ? AND origin_scope = ? AND origin_producer = ? AND origin_key = ? \
             AND generation = ?")
            .bind(namespace).bind(&o.scope).bind(&o.producer).bind(&o.key).bind(o.generation)
            .fetch_optional(&mut *tx).await?;
        let c = match uid {
            Some(uid) => self.cancel_in(&mut tx, uid, now_ms).await?,
            None => {
                let uid = next(&mut tx, "job").await?;
                sqlx::query("INSERT INTO job (uid, namespace, origin_scope, origin_producer, origin_key, generation, \
                               chain_key, kind, valid_until, state, last_error, created_at, updated_at) \
                             VALUES (?, ?, ?, ?, ?, ?, '', 'tombstone', ?, 'cancelled', 'cancelled', ?, ?)")
                    .bind(uid).bind(namespace).bind(&o.scope).bind(&o.producer).bind(&o.key).bind(o.generation)
                    .bind(valid_until).bind(now_ms).bind(now_ms).execute(&mut *tx).await?;
                event(&mut tx, uid, Some("cancelled"), now_ms).await?;
                Cancel::Cancelled(job_row(&mut tx, uid).await?)
            }
        };
        tx.commit().await?;
        Ok(c)
    }

    async fn publish(&self, uid: i64, now_ms: i64) -> Result<bool> {
        let mut tx = self.begin().await?;
        let n = sqlx::query("UPDATE job SET published_at = ?1, updated_at = ?1 \
                             WHERE uid = ?2 AND state = 'queued' AND published_at IS NULL")
            .bind(now_ms).bind(uid).execute(&mut *tx).await?.rows_affected();
        tx.commit().await?;
        Ok(n > 0)
    }

    async fn job(&self, uid: i64) -> Result<Option<JobRow>> {
        Ok(sqlx::query_as("SELECT * FROM job WHERE uid = ?").bind(uid).fetch_optional(&self.pool).await?)
    }

    async fn job_events(&self, after: i64, limit: i64) -> Result<Vec<JobEvent>> {
        Ok(sqlx::query_as("SELECT * FROM job_event WHERE seq > ? ORDER BY seq LIMIT ?")
            .bind(after).bind(limit).fetch_all(&self.pool).await?)
    }

    async fn journal_max(&self, chain_key: &str, lane: &str) -> Result<Option<i64>> {
        let v: Option<Option<i64>> = sqlx::query_scalar("SELECT journal_max FROM lane WHERE chain_key = ? AND label = ?")
            .bind(chain_key).bind(lane).fetch_optional(&self.pool).await?;
        Ok(v.flatten())
    }

    async fn bump_journal_max(&self, chain_key: &str, lane: &str, nonce: i64) -> Result<()> {
        let mut tx = self.begin().await?;
        let n = sqlx::query("UPDATE lane SET journal_max = MAX(COALESCE(journal_max, ?1), ?1) \
                             WHERE chain_key = ?2 AND label = ?3")
            .bind(nonce).bind(chain_key).bind(lane).execute(&mut *tx).await?.rows_affected();
        if n == 0 {
            return Err(StoreError::Invalid(format!("lane {chain_key}/{lane} is not in the store")));
        }
        tx.commit().await?;
        Ok(())
    }

    async fn purge(&self, now_ms: i64, job_retention_secs: i64, feed_retention_secs: i64) -> Result<u64> {
        let mut tx = self.begin().await?;
        let n = sqlx::query(&format!(
            "DELETE FROM job WHERE state NOT IN {LIVE_SQL} AND updated_at < ? AND valid_until < ?"))
            .bind(now_ms - job_retention_secs * 1000).bind(now_ms / 1000 - 86_400)
            .execute(&mut *tx).await?.rows_affected();
        let feed = now_ms - feed_retention_secs * 1000;
        sqlx::query("DELETE FROM job_event WHERE at < ?").bind(feed).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM feed_item WHERE at < ?").bind(feed).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(n)
    }

    async fn append_audit(&self, entry: &AuditEntry, now_ms: i64) -> Result<AuditRow> {
        let mut tx = self.begin().await?;
        let row = audit_in(&mut tx, entry, now_ms).await?;
        tx.commit().await?;
        Ok(row)
    }

    async fn audit_log(&self) -> Result<Vec<AuditRow>> {
        Ok(sqlx::query_as("SELECT * FROM audit_log ORDER BY seq").fetch_all(&self.pool).await?)
    }

    async fn mark_restored(&self, entry: &AuditEntry, now_ms: i64) -> Result<i64> {
        let mut tx = self.begin().await?;
        let v: String = sqlx::query_scalar(
            "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE name = 'restore_epoch' RETURNING value")
            .fetch_one(&mut *tx).await?;
        let n: i64 = v.parse().map_err(|_| StoreError::Invalid(format!("meta restore_epoch {v}")))?;
        let e = AuditEntry { before: Some(format!("{{\"restore_epoch\":{}}}", n - 1)),
                             after: Some(format!("{{\"restore_epoch\":{n}}}")), ..entry.clone() };
        audit_in(&mut tx, &e, now_ms).await?;
        tx.commit().await?;
        Ok(n)
    }

    async fn load_config(&self) -> Result<ConfigSet> {
        let p = &self.pool;
        let mut namespaces: Vec<NamespaceRow> = sqlx::query_as::<_, (String, String, bool, i64)>(
            "SELECT name, state, allow_call, max_live_jobs FROM namespace ORDER BY name")
            .fetch_all(p).await?.into_iter()
            .map(|(name, state, allow_call, max_live_jobs)| NamespaceRow { name, state, allow_call, max_live_jobs, chains: vec![] })
            .collect();
        let grants: Vec<(String, String)> = sqlx::query_as(
            "SELECT namespace, chain_key FROM namespace_chain ORDER BY namespace, chain_key").fetch_all(p).await?;
        for (ns, chain) in grants {
            if let Some(n) = namespaces.iter_mut().find(|n| n.name == ns) {
                n.chains.push(chain);
            }
        }
        Ok(ConfigSet {
            chains: sqlx::query_as("SELECT * FROM chain ORDER BY chain_key").fetch_all(p).await?,
            tokens: sqlx::query_as("SELECT * FROM token ORDER BY chain_key, address").fetch_all(p).await?,
            lanes: sqlx::query_as("SELECT * FROM lane ORDER BY chain_key, label").fetch_all(p).await?,
            namespaces,
            peers: sqlx::query_as("SELECT * FROM mesh_peer ORDER BY name").fetch_all(p).await?,
            policy: sqlx::query_as("SELECT * FROM mesh_policy ORDER BY chain_key, contract, selector").fetch_all(p).await?,
        })
    }

    async fn import(&self, set: &ConfigSet, now_ms: i64) -> Result<()> {
        let mut tx = self.begin().await?;
        let now = now_ms;
        for c in &set.chains {
            sqlx::query("INSERT INTO chain (chain_key, family, state, profile, finality_mode, finality_depth, \
                           finality_quorum, fee_recipient, poll_ms, stuck_after_secs, max_gas_per_tx, max_fee_cap_gwei, \
                           max_index_lag, breaker, dex, gossip, exclusive_ms, updated_at) \
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
                .bind(&c.chain_key).bind(&c.family).bind(&c.state).bind(&c.profile).bind(&c.finality_mode)
                .bind(c.finality_depth).bind(c.finality_quorum).bind(&c.fee_recipient).bind(c.poll_ms)
                .bind(c.stuck_after_secs).bind(c.max_gas_per_tx).bind(c.max_fee_cap_gwei).bind(c.max_index_lag)
                .bind(&c.breaker).bind(&c.dex).bind(c.gossip).bind(c.exclusive_ms).bind(now)
                .execute(&mut *tx).await?;
            audit_in(&mut tx, &boot_audit(c.label(), c), now).await?;
        }
        for t in &set.tokens {
            sqlx::query("INSERT INTO token (chain_key, address, decimals, active) VALUES (?, ?, ?, ?)")
                .bind(&t.chain_key).bind(&t.address).bind(t.decimals).bind(t.active).execute(&mut *tx).await?;
            audit_in(&mut tx, &boot_audit(t.label(), t), now).await?;
        }
        for l in &set.lanes {
            sqlx::query("INSERT INTO lane (chain_key, label, account_index) VALUES (?, ?, ?)")
                .bind(&l.chain_key).bind(&l.label).bind(l.account_index).execute(&mut *tx).await?;
            audit_in(&mut tx, &boot_audit(l.label(), l), now).await?;
        }
        for n in &set.namespaces {
            sqlx::query("INSERT INTO namespace (name, state, allow_call, max_live_jobs, created_at, updated_at) \
                         VALUES (?, ?, ?, ?, ?, ?)")
                .bind(&n.name).bind(&n.state).bind(n.allow_call).bind(n.max_live_jobs).bind(now).bind(now)
                .execute(&mut *tx).await?;
            for c in &n.chains {
                sqlx::query("INSERT INTO namespace_chain (namespace, chain_key) VALUES (?, ?)")
                    .bind(&n.name).bind(c).execute(&mut *tx).await?;
            }
            audit_in(&mut tx, &boot_audit(n.label(), n), now).await?;
        }
        for p in &set.peers {
            sqlx::query("INSERT INTO mesh_peer (name, url, spki_sha256, class, chains, updated_at) VALUES (?, ?, ?, ?, ?, ?)")
                .bind(&p.name).bind(&p.url).bind(&p.spki_sha256).bind(&p.class).bind(&p.chains).bind(now)
                .execute(&mut *tx).await?;
            audit_in(&mut tx, &boot_audit(p.label(), p), now).await?;
        }
        for p in &set.policy {
            sqlx::query("INSERT INTO mesh_policy (chain_key, contract, selector, support, submit, pool_visibility, \
                           min_fee, fee_recipient_allow, gossip, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
                .bind(&p.chain_key).bind(&p.contract).bind(&p.selector).bind(&p.support).bind(p.submit)
                .bind(&p.pool_visibility).bind(&p.min_fee).bind(&p.fee_recipient_allow).bind(p.gossip).bind(now)
                .execute(&mut *tx).await?;
            audit_in(&mut tx, &boot_audit(p.label(), p), now).await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
