//! Bộ test hợp đồng của store (NI §16.1, A1.4). P1: SQLite trong process. P1b chạy lại cùng các ca trên
//! PostgreSQL/MySQL (docker, `--ignored`).
use super::sqlite::SqliteStore;
use super::*;

const LANE: &str = "0x00000000000000000000000000000000000000aa";
const CHAIN: &str = "evm:9000";

/// A store directory of its own, removed on drop (review F15). `url` names a file that does not exist yet.
struct Tmp {
    dir: std::path::PathBuf,
    url: String,
}

impl Tmp {
    fn db(&self) -> std::path::PathBuf {
        self.dir.join("node.db")
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn tmp() -> Tmp {
    let dir = std::env::temp_dir().join(format!("scaas-store-{}-{:016x}", std::process::id(), rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite://{}", dir.join("node.db").display());
    Tmp { dir, url }
}

fn chain(key: &str) -> ChainRow {
    ChainRow {
        chain_key: key.into(),
        family: "evm".into(),
        state: "active".into(),
        profile: "private".into(),
        finality_mode: "depth".into(),
        finality_depth: 1,
        finality_quorum: 1,
        fee_recipient: None,
        poll_ms: 1000,
        stuck_after_secs: 60,
        max_gas_per_tx: 3_000_000,
        max_fee_cap_gwei: 500,
        max_index_lag: 100,
        breaker: "{}".into(),
        dex: None,
        gossip: false,
        exclusive_ms: 7000,
    }
}

fn base_set() -> ConfigSet {
    ConfigSet {
        chains: vec![chain(CHAIN), chain("evm:100")],
        tokens: vec![TokenRow { chain_key: CHAIN.into(), address: "0xAB".into(), decimals: 6, active: true }],
        lanes: vec![
            LaneRow { chain_key: CHAIN.into(), label: LANE.into(), account_index: 0, journal_max: None },
            LaneRow { chain_key: CHAIN.into(), label: "0xBB".into(), account_index: 1, journal_max: None },
        ],
        namespaces: vec![NamespaceRow { name: "odoo".into(), state: "active".into(), allow_call: true,
                                        max_live_jobs: 10_000, chains: vec![CHAIN.into()] }],
        peers: vec![],
        policy: vec![],
    }
}

async fn open_seeded(url: &str) -> SqliteStore {
    let s = SqliteStore::create(url, "test").await.unwrap();
    bootstrap(&s, &base_set(), 1).await.unwrap();
    s
}

fn new_job(key: &str, digest: u8) -> NewJob {
    NewJob {
        namespace: "odoo".into(),
        origin: Origin { scope: "db:1".into(), producer: "blockchain.payment.request".into(), key: key.into(), generation: 0 },
        client_ref: Some(format!("odoo:{key}")),
        chain_key: CHAIN.into(),
        kind: "metatx".into(),
        digest: Some([digest; 32]),
        payload: br#"{"token":"0x"}"#.to_vec(),
        payload_hash: [digest; 32],
        valid_until: 4_000_000_000,
        lane_hint: None,
        bus_scope: "restricted".into(),
        private_window_secs: 120,
    }
}

async fn created(s: &dyn Backend, j: &NewJob) -> JobRow {
    match s.accept(j, 10).await.unwrap() {
        Accept::Created(r) => r,
        other => panic!("expected Created, got {other:?}"),
    }
}

fn lease(lane: &str) -> Fields {
    Fields { lane_label: Some(lane.into()), claim_block: Some(7), ..Default::default() }
}

fn signed(nonce: i64, hash: &str) -> Fields {
    Fields { outer_nonce: Some(nonce), tx_hash: Some(hash.into()), ..Default::default() }
}

async fn leased_job(s: &dyn Backend, key: &str, digest: u8) -> JobRow {
    let j = created(s, &new_job(key, digest)).await;
    assert!(matches!(s.transition(j.uid, Queued, Leased, &lease(LANE), 11).await.unwrap(), Transition::Ok { .. }));
    j
}

// ------------------------------------------------------------------ identity, owner lock, fencing

#[tokio::test]
async fn migrations_create_identity_and_counters() {
    let t = tmp();
    let url = t.url.clone();
    let s = SqliteStore::create(&url, "test").await.unwrap();
    let id = s.identity().clone();
    assert_eq!(id.store_id.len(), 32);
    assert!(id.store_id.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(id.incarnation.len(), 32);
    assert_eq!(id.epoch, 1);
    assert_eq!(id.restore_epoch, 0);
    for c in ["job", "job_event", "feed_item", "audit", "intent"] {
        assert_eq!(s.head_seq(c).await.unwrap(), 0, "{c}");
    }
    let v: String = sqlx::query_scalar("SELECT value FROM meta WHERE name = 'schema_version'")
        .fetch_one(&s.pool).await.unwrap();
    assert_eq!(v, "2");
    // reserved namespaces exist (R90)
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM namespace WHERE name IN ('~gateway', '~mesh', '~dex')")
        .fetch_one(&s.pool).await.unwrap();
    assert_eq!(n, 3);
}

#[tokio::test]
async fn reopen_keeps_seq_and_store_id() {
    let t = tmp();
    let url = t.url.clone();
    let s = open_seeded(&url).await;
    let first = created(&s, &new_job("a", 1)).await;
    let id1 = s.identity().clone();
    let head1 = s.head_seq("job_event").await.unwrap();
    drop(s);
    let s = SqliteStore::open(&url, "test").await.unwrap();
    let id2 = s.identity().clone();
    assert_eq!(id2.store_id, id1.store_id);
    assert_ne!(id2.incarnation, id1.incarnation, "a new incarnation at every open");
    assert_eq!(id2.epoch, id1.epoch + 1);
    assert_eq!(s.head_seq("job_event").await.unwrap(), head1);
    let second = created(&s, &new_job("b", 2)).await;
    assert_eq!(second.uid, first.uid + 1);
    assert_eq!(second.last_seq, Some(head1 + 1));
}

#[tokio::test]
async fn second_owner_is_refused() {
    let t = tmp();
    let url = t.url.clone();
    let _a = SqliteStore::create(&url, "a").await.unwrap();
    match SqliteStore::open(&url, "b").await {
        Err(StoreError::Owned(_)) => {}
        other => panic!("expected Owned, got {:?}", other.map(|_| ())),
    }
    assert!(open(&url, "b").await.is_err(), "through the dispatcher too");
}

#[tokio::test]
async fn stale_owner_cannot_journal() {
    let t = tmp();
    let url = t.url.clone();
    let a = open_seeded(&url).await;
    let j = leased_job(&a, "a", 1).await;
    a.drop_lock_for_test(); // the lock is lost without A noticing
    let b = SqliteStore::open(&url, "b").await.unwrap();
    assert_eq!(b.identity().epoch, a.identity().epoch + 1);
    assert!(matches!(a.transition(j.uid, Leased, Signed, &signed(5, "0x01"), 12).await, Err(StoreError::NotOwner)));
    assert!(matches!(a.accept(&new_job("b", 2), 12).await, Err(StoreError::NotOwner)));
    assert!(matches!(a.cancel(j.uid, 12).await, Err(StoreError::NotOwner)));
    assert!(matches!(a.append_audit(&audit("x"), 12).await, Err(StoreError::NotOwner)));
    assert!(matches!(a.bump_journal_max(CHAIN, LANE, 9).await, Err(StoreError::NotOwner)));
    let q = created(&b, &new_job("q", 3)).await;
    assert!(matches!(a.publish(q.uid, 12).await, Err(StoreError::NotOwner)));
    assert!(matches!(a.purge(i64::MAX / 2, 0, 0).await, Err(StoreError::NotOwner)));
    let mut more = base_set();
    more.chains.push(chain("evm:7"));
    assert!(matches!(bootstrap(&a, &more, 12).await, Err(StoreError::NotOwner)), "import");
    assert!(matches!(a.cancel_by_origin("odoo", &new_job("z", 4).origin, 4_000_000_000, 12).await, Err(StoreError::NotOwner)));
    assert!(matches!(a.mark_restored(&audit("r"), 12).await, Err(StoreError::NotOwner)));
    assert!(matches!(a.check_owner().await, Err(StoreError::NotOwner)), "the cheap A1.1 check sees it too");
    b.check_owner().await.unwrap();
    assert_eq!(b.job(q.uid).await.unwrap().unwrap().published_at, None);
    assert_eq!(b.identity().restore_epoch, 0);
    assert!(b.load_config().await.unwrap().chains.iter().all(|c| c.chain_key != "evm:7"));
    assert_eq!(b.job(j.uid).await.unwrap().unwrap().state, Leased, "nothing journaled by the stale owner");
    assert_eq!(b.journal_max(CHAIN, LANE).await.unwrap(), None);
    assert!(matches!(b.transition(j.uid, Leased, Signed, &signed(5, "0x01"), 12).await.unwrap(), Transition::Ok { .. }));
}

#[tokio::test]
async fn a_missing_store_is_never_created_implicitly() {
    let t = tmp();
    match SqliteStore::open(&t.url, "t").await {
        Err(StoreError::Invalid(m)) => assert!(m.contains("store init"), "{m}"),
        other => panic!("expected Invalid, got {:?}", other.map(|_| ())),
    }
    assert!(!t.db().exists(), "a typo'd or unmounted path creates nothing");
    let s = SqliteStore::create(&t.url, "t").await.unwrap();
    drop(s);
    assert!(SqliteStore::create(&t.url, "t").await.is_err(), "init never reuses an existing store");
    SqliteStore::open(&t.url, "t").await.unwrap();
}

#[tokio::test]
async fn the_store_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let t = tmp();
    let s = open_seeded(&t.url).await;
    created(&s, &new_job("a", 1)).await;
    let mode = |suffix: &str| {
        let p = format!("{}{suffix}", t.db().display());
        std::fs::metadata(&p).map(|m| m.permissions().mode() & 0o777).unwrap_or_else(|e| panic!("{p}: {e}"))
    };
    for suffix in ["", "-wal", "-shm", ".lock"] {
        assert_eq!(mode(suffix), 0o600, "node.db{suffix}");
    }
}

#[tokio::test]
async fn a_symlinked_path_is_the_same_store() {
    let t = tmp();
    let _a = SqliteStore::create(&t.url, "a").await.unwrap();
    std::os::unix::fs::symlink(t.db(), t.dir.join("link.db")).unwrap();
    let link = format!("sqlite://{}", t.dir.join("link.db").display());
    match SqliteStore::open(&link, "b").await {
        Err(StoreError::Owned(_)) => {}
        other => panic!("expected Owned through the symlink, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn a_replaced_lock_file_is_lost_ownership() {
    let t = tmp();
    let a = SqliteStore::create(&t.url, "a").await.unwrap();
    a.check_owner().await.unwrap();
    std::fs::remove_file(format!("{}.lock", t.db().display())).unwrap();
    assert!(matches!(a.check_owner().await, Err(StoreError::Owned(_))), "a second process could lock a new file");
}

#[tokio::test]
async fn janitor_exits_when_fenced_out() {
    let t = tmp();
    let a = Arc::new(open_seeded(&t.url).await);
    a.drop_lock_for_test();
    let _b = SqliteStore::open(&t.url, "b").await.unwrap();
    let ms = Duration::from_millis(10);
    let r = tokio::time::timeout(Duration::from_secs(5), janitor(a.clone() as Store, ms, ms, 1, 1)).await
        .expect("the janitor returns instead of warning forever");
    assert!(matches!(r, Err(StoreError::NotOwner)), "{r:?}");
}

#[tokio::test]
async fn memory_and_unknown_urls_are_refused() {
    assert!(SqliteStore::open("sqlite::memory:", "t").await.is_err(), "no owner lock without a file");
    assert!(open("postgres://x/y", "t").await.is_err(), "P1b");
}

// ------------------------------------------------------------------ state machine

#[test]
fn state_machine_matches_the_vector_file() {
    let v: serde_json::Value = serde_json::from_str(include_str!("../../tests/api/transitions.json")).unwrap();
    let names = |x: &serde_json::Value| -> Vec<String> {
        x.as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect()
    };
    assert_eq!(names(&v["states"]), State::ALL.map(|s| s.as_str().to_string()).to_vec());
    assert_eq!(names(&v["live"]), State::LIVE.map(|s| s.as_str().to_string()).to_vec());
    for from in State::ALL {
        for to in State::ALL {
            let file = v["transitions"].get(from.as_str()).map(|t| names(t).contains(&to.as_str().to_string()));
            assert_eq!(allowed(from, to), file.unwrap_or(false), "{} -> {}", from.as_str(), to.as_str());
            let late = v["late_noop"].get(from.as_str()).map(|t| names(t).contains(&to.as_str().to_string()));
            assert_eq!(late_noop(from, to), late.unwrap_or(false), "late {} -> {}", from.as_str(), to.as_str());
        }
    }
}

#[tokio::test]
async fn illegal_transitions_are_refused_and_late_noop_writes_nothing() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    let j = created(&s, &new_job("a", 1)).await;
    assert!(matches!(s.transition(j.uid, Queued, Signed, &signed(1, "0x01"), 11).await,
                     Err(StoreError::Illegal { from: Queued, to: Signed })));
    assert!(matches!(s.transition(j.uid, Dead, Queued, &Fields::default(), 11).await, Err(StoreError::Illegal { .. })));
    assert!(matches!(s.transition(999, Queued, Leased, &lease(LANE), 11).await, Err(StoreError::NotFound)));
    s.transition(j.uid, Queued, Leased, &lease(LANE), 11).await.unwrap();
    s.transition(j.uid, Leased, Consumed, &Fields { error: Some("landed elsewhere".into()), ..Default::default() }, 12)
        .await.unwrap();
    let head = s.head_seq("job_event").await.unwrap();
    for to in [Mined, Reverted, Consumed] {
        assert_eq!(s.transition(j.uid, Consumed, to, &Fields::default(), 13).await.unwrap(),
                   Transition::Moved { state: Consumed, tx_hash: None }, "LATE_NOOP");
    }
    assert_eq!(s.head_seq("job_event").await.unwrap(), head, "late no-ops are not stored");
}

#[tokio::test]
async fn only_cancel_reaches_cancelled() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    let j = created(&s, &new_job("a", 1)).await;
    assert!(s.publish(j.uid, 11).await.unwrap());
    assert!(matches!(s.transition(j.uid, Queued, Cancelled, &Fields::default(), 12).await,
                     Err(StoreError::Illegal { from: Queued, to: Cancelled })), "R98: published ⇒ hold + TOO_LATE");
    assert_eq!(s.job(j.uid).await.unwrap().unwrap().state, Queued);
    let k = leased_job(&s, "b", 2).await;
    assert!(matches!(s.transition(k.uid, Leased, Cancelled, &Fields::default(), 12).await, Err(StoreError::Illegal { .. })));
    assert!(allowed(Queued, Cancelled) && allowed(Leased, Cancelled), "the pairs stay in the table (transitions.json)");
}

#[tokio::test]
async fn journal_fields_only_on_their_transitions() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    let j = leased_job(&s, "a", 1).await;
    let nonce = Fields { outer_nonce: Some(99), ..Default::default() };
    let hash = Fields { tx_hash: Some("0x99".into()), ..Default::default() };
    for (to, f) in [(Dead, &nonce), (Consumed, &nonce), (Dead, &hash), (Queued, &hash)] {
        assert!(matches!(s.transition(j.uid, Leased, to, f, 12).await, Err(StoreError::Invalid(_))), "{to:?} {f:?}");
    }
    let other_lane = Fields { lane_label: Some("0xBB".into()), ..signed(1, "0x01") };
    assert!(matches!(s.transition(j.uid, Leased, Signed, &other_lane, 12).await, Err(StoreError::Invalid(_))),
            "signed by a lane that did not lease it");
    assert_eq!((s.job(j.uid).await.unwrap().unwrap().state, s.journal_max(CHAIN, LANE).await.unwrap()), (Leased, None));
    let own_lane = Fields { lane_label: Some(LANE.into()), ..signed(1, "0x01") };
    assert!(matches!(s.transition(j.uid, Leased, Signed, &own_lane, 12).await.unwrap(), Transition::Ok { .. }));
    assert!(matches!(s.transition(j.uid, Signed, Broadcast, &nonce, 13).await, Err(StoreError::Invalid(_))));
    s.transition(j.uid, Signed, Broadcast, &Fields::default(), 13).await.unwrap();
    assert!(matches!(s.transition(j.uid, Broadcast, Broadcast, &Fields { outer_nonce: Some(99), ..signed(99, "0x02") }, 14)
                     .await, Err(StoreError::Invalid(_))), "a replacement keeps its nonce");
    assert!(matches!(s.transition(j.uid, Broadcast, Broadcast, &Fields { tx_hash: Some("0x02".into()), ..Default::default() }, 14)
                     .await.unwrap(), Transition::Ok { .. }));
    assert_eq!(s.journal_max(CHAIN, LANE).await.unwrap(), Some(1), "never raised by a stray nonce");
}

#[tokio::test]
async fn every_transition_writes_one_event_atomically() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    let j = created(&s, &new_job("a", 1)).await;
    let ladder = [
        (Queued, Leased, lease(LANE)),
        (Leased, Signed, signed(4, "0x0a")),
        (Signed, Broadcast, Fields::default()),
        (Broadcast, Broadcast, Fields { tx_hash: Some("0x0b".into()), ..Default::default() }),
        (Broadcast, Mined, Fields::default()),
        (Mined, Reverted, Fields::default()),
    ];
    let mut seen = vec![j.last_seq.unwrap()];
    for (from, to, f) in ladder {
        let Transition::Ok { seq } = s.transition(j.uid, from, to, &f, 20).await.unwrap() else { panic!("{from:?}") };
        let row = s.job(j.uid).await.unwrap().unwrap();
        assert_eq!(row.state, to);
        assert_eq!(row.last_seq, Some(seq));
        seen.push(seq);
    }
    let ev = s.job_events(0, 100).await.unwrap();
    assert_eq!(ev.iter().map(|e| e.seq).collect::<Vec<_>>(), seen);
    assert_eq!(ev.iter().map(|e| e.state.as_str()).collect::<Vec<_>>(),
               ["queued", "leased", "signed", "broadcast", "broadcast", "mined", "reverted"]);
    assert_eq!(ev[2].outer_nonce, Some(4));
    assert_eq!(ev[2].signer.as_deref(), Some(LANE));
    assert_eq!(ev[4].tx_hash.as_deref(), Some("0x0b"), "replacement hash");
    let row = s.job(j.uid).await.unwrap().unwrap();
    assert_eq!(row.attempt_count, 1);
    assert_eq!(row.claim_block, Some(7));
    // a CAS that misses writes nothing
    let head = s.head_seq("job_event").await.unwrap();
    assert!(matches!(s.transition(j.uid, Mined, Reverted, &Fields::default(), 21).await.unwrap(), Transition::Moved { .. }));
    assert_eq!(s.head_seq("job_event").await.unwrap(), head);
}

#[tokio::test]
async fn requeue_clears_the_journal_fields_but_not_journal_max() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    let j = leased_job(&s, "a", 1).await;
    s.transition(j.uid, Leased, Signed, &signed(8, "0x08"), 12).await.unwrap();
    s.transition(j.uid, Signed, Queued, &Fields { error: Some("dropped".into()), ..Default::default() }, 13).await.unwrap();
    let row = s.job(j.uid).await.unwrap().unwrap();
    assert_eq!((row.lane_label, row.outer_nonce, row.tx_hash, row.claim_block), (None, None, None, None));
    assert_eq!(row.last_error.as_deref(), Some("dropped"));
    assert_eq!(s.journal_max(CHAIN, LANE).await.unwrap(), Some(8));
}

// ------------------------------------------------------------------ tri-state transition (§9.1)

#[tokio::test]
async fn transition_tri_state() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    // Moved after a cancel: the lane must drop the work and keep its nonce.
    let j = leased_job(&s, "a", 1).await;
    assert!(matches!(s.cancel(j.uid, 12).await.unwrap(), Cancel::Cancelled(_)));
    assert_eq!(s.transition(j.uid, Leased, Signed, &signed(3, "0x03"), 13).await.unwrap(),
               Transition::Moved { state: Cancelled, tx_hash: None });
    assert_eq!(s.journal_max(CHAIN, LANE).await.unwrap(), None, "a refused journal never bumps journal_max");
    // Moved{signed, own hash} on an idempotent retry.
    let j = leased_job(&s, "b", 2).await;
    assert!(matches!(s.transition(j.uid, Leased, Signed, &signed(3, "0x03"), 13).await.unwrap(), Transition::Ok { .. }));
    assert_eq!(s.transition(j.uid, Leased, Signed, &signed(3, "0x03"), 14).await.unwrap(),
               Transition::Moved { state: Signed, tx_hash: Some("0x03".into()) });
    // Commit outcome unknown: the row is re-read, it is ours, the retry says so.
    let j = leased_job(&s, "c", 3).await;
    s.inject_commit_unknown();
    assert!(matches!(s.transition(j.uid, Leased, Signed, &signed(4, "0x04"), 15).await.unwrap(), Transition::Unknown(_)));
    let row = s.job(j.uid).await.unwrap().unwrap();
    assert_eq!((row.state, row.tx_hash.as_deref()), (Signed, Some("0x04")));
    assert_eq!(s.transition(j.uid, Leased, Signed, &signed(4, "0x04"), 16).await.unwrap(),
               Transition::Moved { state: Signed, tx_hash: Some("0x04".into()) });
}

#[tokio::test]
async fn signed_requires_nonce_hash_and_a_known_lane() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    let j = leased_job(&s, "a", 1).await;
    assert!(matches!(s.transition(j.uid, Leased, Signed, &Fields::default(), 12).await, Err(StoreError::Invalid(_))));
    let k = created(&s, &new_job("b", 2)).await;
    assert!(matches!(s.transition(k.uid, Queued, Leased, &lease("0xNOTALANE"), 12).await, Err(StoreError::Invalid(_))),
            "an unknown lane is refused at lease time, not at signed");
    assert_eq!(s.job(k.uid).await.unwrap().unwrap().state, Queued, "rolled back");
}

// ------------------------------------------------------------------ journal_max, nonces, bytes

#[tokio::test]
async fn journal_max_is_monotonic_with_out_of_order_writes() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    let a = leased_job(&s, "a", 1).await;
    let b = leased_job(&s, "b", 2).await;
    s.transition(a.uid, Leased, Signed, &signed(5, "0x05"), 12).await.unwrap();
    s.transition(b.uid, Leased, Signed, &signed(3, "0x03"), 13).await.unwrap();
    assert_eq!(s.journal_max(CHAIN, LANE).await.unwrap(), Some(5));
    s.bump_journal_max(CHAIN, LANE, 4).await.unwrap();
    assert_eq!(s.journal_max(CHAIN, LANE).await.unwrap(), Some(5));
    s.bump_journal_max(CHAIN, LANE, 9).await.unwrap();
    assert_eq!(s.journal_max(CHAIN, LANE).await.unwrap(), Some(9));
    assert_eq!(s.journal_max(CHAIN, "0xBB").await.unwrap(), None, "per lane");
    assert!(s.bump_journal_max(CHAIN, "0xNOPE", 1).await.is_err(), "unknown lane");
}

#[tokio::test]
async fn nonces_are_i64() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    let stellar = (5_000_000i64 << 32) + 7; // ledger << 32
    let j = leased_job(&s, "a", 1).await;
    s.transition(j.uid, Leased, Signed, &signed(stellar, "h1"), 12).await.unwrap();
    assert_eq!(s.job(j.uid).await.unwrap().unwrap().outer_nonce, Some(stellar));
    s.bump_journal_max(CHAIN, LANE, i64::MAX).await.unwrap();
    assert_eq!(s.journal_max(CHAIN, LANE).await.unwrap(), Some(i64::MAX));
}

#[tokio::test]
async fn keys_compare_byte_exact() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    let mut set = base_set();
    set.tokens.push(TokenRow { chain_key: CHAIN.into(), address: "0xab".into(), decimals: 6, active: true });
    set.lanes.push(LaneRow { chain_key: CHAIN.into(), label: "0xbb".into(), account_index: 2, journal_max: None });
    let r = bootstrap(&s, &set, 2).await.unwrap();
    assert_eq!(r.imported, ["token:evm:9000/0xab", "lane:evm:9000/0xbb"], "'0xAB' != '0xab'");
    // origin keys: hex and base58 are case-sensitive
    let a = created(&s, &new_job("3mJr7AoUXx2Wqd", 1)).await;
    let b = created(&s, &new_job("3MJR7AOUXX2WQD", 2)).await;
    assert_ne!(a.uid, b.uid);
    s.bump_journal_max(CHAIN, "0xbb", 3).await.unwrap();
    assert_eq!(s.journal_max(CHAIN, "0xBB").await.unwrap(), None);
}

// ------------------------------------------------------------------ accept: idempotency, digest, quota

#[tokio::test]
async fn idempotency_key_and_payload_hash() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    let j = new_job("k", 1);
    let first = created(&s, &j).await;
    let head = s.head_seq("job_event").await.unwrap();
    assert_eq!(s.accept(&j, 11).await.unwrap(), Accept::Existing(first.clone()), "same key + same hash");
    assert_eq!(s.head_seq("job_event").await.unwrap(), head, "a retry writes nothing");
    let mut other = j.clone();
    other.payload_hash = [9; 32];
    assert_eq!(s.accept(&other, 11).await.unwrap(), Accept::IdempotencyMismatch { uid: first.uid });
    // a requeue (generation + 1) while generation 0 is live
    let mut g1 = j.clone();
    g1.origin.generation = 1;
    assert_eq!(s.accept(&g1, 11).await.unwrap(), Accept::PreviousGenerationLive { uid: first.uid });
    s.transition(first.uid, Queued, Dead, &Fields { error: Some("expired".into()), ..Default::default() }, 12)
        .await.unwrap();
    let second = created(&s, &g1).await;
    assert_ne!(second.uid, first.uid);
    // other scope or namespace = other key
    let mut scope = j.clone();
    scope.origin.scope = "db:2".into();
    scope.digest = Some([3; 32]);
    created(&s, &scope).await;
}

#[tokio::test]
async fn accept_refuses_expired_payloads_and_stale_generations() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    let mut j = new_job("x", 1);
    j.valid_until = 100;
    assert_eq!(s.accept(&j, 100_000).await.unwrap(), Accept::Expired, "valid_until is unix s, now is ms");
    assert_eq!(s.head_seq("job").await.unwrap(), 0, "nothing written");
    let row = match s.accept(&j, 99_999).await.unwrap() { Accept::Created(r) => r, other => panic!("{other:?}") };
    assert_eq!(s.accept(&j, 200_000).await.unwrap(), Accept::Existing(row), "a retry of a stored job still answers");
    let mut g1 = new_job("y", 2);
    g1.origin.generation = 1;
    let r1 = created(&s, &g1).await;
    s.transition(r1.uid, Queued, Dead, &Fields::default(), 12).await.unwrap();
    let g0 = new_job("y", 3);
    assert_eq!(s.accept(&g0, 13).await.unwrap(), Accept::Superseded { uid: r1.uid }, "generation 0 after 1");
}

#[tokio::test]
async fn digest_and_payload_hash_follow_the_kind() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    for (kind, digest) in [("metatx", None), ("signed_op", None), ("call", Some([5; 32]))] {
        let mut j = new_job(kind, 5);
        j.kind = kind.into();
        j.digest = digest;
        assert!(s.accept(&j, 11).await.is_err(), "{kind} with digest {digest:?}");
    }
    assert_eq!(s.head_seq("job").await.unwrap(), 0, "rolled back");
    let raw = |kind: &str, hash: &str| format!(
        "INSERT INTO job (uid, namespace, origin_scope, origin_producer, origin_key, chain_key, kind, digest, payload, \
         payload_hash, valid_until, state, created_at, updated_at) VALUES (900, 'odoo', 's', 'p', 'k', '', '{kind}', NULL, \
         {}, {hash}, 1, 'cancelled', 1, 1)", if kind == "tombstone" { "NULL" } else { "x'00'" });
    assert!(sqlx::query(&raw("call", "NULL")).execute(&s.pool).await.is_err(), "call without payload_hash");
    assert!(sqlx::query(&raw("tombstone", "zeroblob(32)")).execute(&s.pool).await.is_err(), "tombstone with one");
    sqlx::query(&raw("tombstone", "NULL")).execute(&s.pool).await.unwrap();
}

#[tokio::test]
async fn cancel_by_origin_without_a_job_writes_a_tombstone() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    let j = new_job("t", 1);
    let Cancel::Cancelled(t) = s.cancel_by_origin("odoo", &j.origin, 4_000_000_000, 10).await.unwrap() else { panic!() };
    assert_eq!((t.kind.as_str(), t.state, t.payload.clone()), ("tombstone", Cancelled, None));
    // a late push of that key: created = false, state = cancelled
    assert_eq!(s.accept(&j, 11).await.unwrap(), Accept::Existing(t.clone()));
    // cancel by origin of an existing job = cancel by uid
    let k = created(&s, &new_job("u", 2)).await;
    let Cancel::Cancelled(c) = s.cancel_by_origin("odoo", &new_job("u", 2).origin, 4_000_000_000, 12).await.unwrap()
        else { panic!() };
    assert_eq!((c.uid, c.state), (k.uid, Cancelled));
    assert!(matches!(s.cancel_by_origin("odoo", &new_job("u", 2).origin, 4_000_000_000, 13).await.unwrap(),
                     Cancel::Cancelled(_)), "idempotent");
}

#[tokio::test]
async fn live_digest_is_unique_per_chain() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    let a = created(&s, &new_job("a", 1)).await;
    let mut squat = new_job("b", 1); // other origin, same digest
    squat.payload_hash = [2; 32];
    assert_eq!(s.accept(&squat, 11).await.unwrap(), Accept::DuplicateDigest);
    let mut other_ns = squat.clone();
    other_ns.namespace = "~gateway".into();
    assert_eq!(s.accept(&other_ns, 11).await.unwrap(), Accept::DuplicateDigest, "across namespaces");
    let mut other_chain = squat.clone();
    other_chain.chain_key = "evm:100".into();
    created(&s, &other_chain).await;
    s.transition(a.uid, Queued, Dead, &Fields::default(), 12).await.unwrap();
    created(&s, &new_job("e", 1)).await; // a terminal row no longer holds the digest
    let mut call = new_job("c", 0);
    call.digest = None;
    call.kind = "call".into();
    created(&s, &call).await;
    let mut call2 = new_job("d", 0);
    call2.digest = None;
    call2.kind = "call".into();
    created(&s, &call2).await; // NULL digests never collide
}

#[tokio::test]
async fn unique_violations_are_classified_by_constraint_name() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    let j = created(&s, &new_job("a", 1)).await;
    let dup = |uid: i64, key: &str, digest: Vec<u8>| {
        sqlx::query("INSERT INTO job (uid, namespace, origin_scope, origin_producer, origin_key, generation, chain_key, \
                     kind, digest, payload, payload_hash, valid_until, state, created_at, updated_at) \
                     VALUES (?, 'odoo', 'db:1', 'blockchain.payment.request', ?, 0, 'evm:9000', 'metatx', ?, x'00', \
                     zeroblob(32), 1, 'queued', 1, 1)")
            .bind(uid).bind(key.to_string()).bind(digest)
    };
    let e = dup(100, "a", vec![7; 32]).execute(&s.pool).await.unwrap_err();
    assert_eq!(sqlite::unique_constraint(&e), Some("job_origin"));
    let e = dup(101, "z", j.digest.clone().unwrap()).execute(&s.pool).await.unwrap_err();
    assert_eq!(sqlite::unique_constraint(&e), Some("job_live_digest"));
    let e = dup(j.uid, "y", vec![8; 32]).execute(&s.pool).await.unwrap_err();
    assert_eq!(sqlite::unique_constraint(&e), None, "primary key is not a classified constraint");
}

#[tokio::test]
async fn quota_counts_live_jobs_of_the_namespace() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    let mut set = base_set();
    set.namespaces = vec![NamespaceRow { name: "tiny".into(), state: "active".into(), allow_call: false,
                                         max_live_jobs: 1, chains: vec![CHAIN.into()] }];
    bootstrap(&s, &set, 2).await.unwrap();
    let mut a = new_job("a", 1);
    a.namespace = "tiny".into();
    let row = created(&s, &a).await;
    let mut b = new_job("b", 2);
    b.namespace = "tiny".into();
    assert_eq!(s.accept(&b, 11).await.unwrap(), Accept::Quota);
    s.transition(row.uid, Queued, Dead, &Fields::default(), 12).await.unwrap();
    created(&s, &b).await;
    let mut c = new_job("c", 3);
    c.namespace = "nobody".into();
    assert!(matches!(s.accept(&c, 11).await, Err(StoreError::Invalid(_))), "unknown namespace");
}

// ------------------------------------------------------------------ lease, cancel, publication (R98)

#[tokio::test]
async fn lease_respects_hold_and_lane_hint() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    let mut j = new_job("a", 1);
    j.lane_hint = Some("0xBB".into());
    let row = created(&s, &j).await;
    assert_eq!(s.transition(row.uid, Queued, Leased, &lease(LANE), 11).await.unwrap(),
               Transition::Moved { state: Queued, tx_hash: None }, "pinned to another lane (R102)");
    assert!(matches!(s.transition(row.uid, Queued, Leased, &lease("0xBB"), 11).await.unwrap(), Transition::Ok { .. }));
    assert!(matches!(s.transition(row.uid, Queued, Leased, &Fields::default(), 11).await, Err(StoreError::Invalid(_))),
            "a lease names its lane");
}

#[tokio::test]
async fn cancel_of_a_published_job_holds_it_and_is_too_late() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    let j = created(&s, &new_job("a", 1)).await;
    assert!(s.publish(j.uid, 11).await.unwrap());
    assert_eq!(s.cancel(j.uid, 12).await.unwrap(), Cancel::TooLate { state: Queued, published: true });
    let row = s.job(j.uid).await.unwrap().unwrap();
    assert!(row.hold && row.published_at == Some(11) && row.state == Queued);
    assert_eq!(s.transition(j.uid, Queued, Leased, &lease(LANE), 13).await.unwrap(),
               Transition::Moved { state: Queued, tx_hash: None }, "never leased by us");
    // signed jobs cannot be cancelled; unknown uid
    let k = leased_job(&s, "b", 2).await;
    s.transition(k.uid, Leased, Signed, &signed(1, "0x01"), 12).await.unwrap();
    assert_eq!(s.cancel(k.uid, 13).await.unwrap(), Cancel::TooLate { state: Signed, published: false });
    assert!(!s.publish(k.uid, 13).await.unwrap(), "only queued jobs are published");
    assert_eq!(s.cancel(999, 13).await.unwrap(), Cancel::NotFound);
}

#[tokio::test]
async fn lease_and_cancel_race_has_one_winner() {
    for _ in 0..20 {
        let t = tmp();
        let s: Store = Arc::new(open_seeded(&t.url).await);
        let j = created(s.as_ref(), &new_job("a", 1)).await;
        let (s1, s2) = (s.clone(), s.clone());
        let lease_t = tokio::spawn(async move { s1.transition(j.uid, Queued, Leased, &lease(LANE), 11).await.unwrap() });
        let cancel_t = tokio::spawn(async move { s2.cancel(j.uid, 11).await.unwrap() });
        let (l, c) = (lease_t.await.unwrap(), cancel_t.await.unwrap());
        assert!(matches!(c, Cancel::Cancelled(_)), "never published: cancel wins from queued or leased");
        let journal = s.transition(j.uid, Leased, Signed, &signed(1, "0x01"), 12).await.unwrap();
        assert_eq!(journal, Transition::Moved { state: Cancelled, tx_hash: None }, "lease was {l:?}");
        assert_eq!(s.job(j.uid).await.unwrap().unwrap().state, Cancelled);
    }
}

// ------------------------------------------------------------------ janitor

#[tokio::test]
async fn purge_never_deletes_an_unexpired_origin() {
    let t = tmp();
    let s = open_seeded(&t.url).await;
    let day = 86_400_000i64;
    let mut old = new_job("old", 1);
    old.valid_until = 1_000; // long expired
    let a = created(&s, &old).await;
    let b = created(&s, &new_job("live", 2)).await; // valid_until far in the future
    let c = created(&s, &{ let mut x = new_job("queued", 3); x.valid_until = 1_000; x }).await;
    for uid in [a.uid, b.uid] {
        s.transition(uid, Queued, Dead, &Fields::default(), 20).await.unwrap();
    }
    let now = 40 * day;
    let head = s.head_seq("job_event").await.unwrap();
    assert_eq!(s.purge(now, 30 * 86_400, 7 * 86_400).await.unwrap(), 1);
    assert!(s.job(a.uid).await.unwrap().is_none(), "terminal + old + expired");
    assert!(s.job(b.uid).await.unwrap().is_some(), "its payload has not expired: the key stays taken");
    assert!(s.job(c.uid).await.unwrap().is_some(), "live rows are never purged");
    assert!(s.job_events(0, 100).await.unwrap().is_empty(), "feed rows older than feed retention");
    assert_eq!(s.accept(&new_job("live", 2), now).await.unwrap(), Accept::Existing(s.job(b.uid).await.unwrap().unwrap()));
    assert_eq!(s.accept(&old, now).await.unwrap(), Accept::Expired, "a purged origin is never re-accepted");
    // R93: the purge floor tells "cursor expired" from "nothing new"
    assert_eq!(s.purge_floor("job_event").await.unwrap(), head, "every event up to the head was purged");
    assert_eq!(s.purge_floor("feed_item").await.unwrap(), 0);
    assert!(matches!(s.accept(&new_job("later", 4), now).await.unwrap(), Accept::Created(_)));
    s.purge(now, 30 * 86_400, 7 * 86_400).await.unwrap();
    assert_eq!(s.purge_floor("job_event").await.unwrap(), head, "a newer row is not purged; the floor never falls");
}

// ------------------------------------------------------------------ audit chain (R110)

fn audit(target: &str) -> AuditEntry {
    AuditEntry {
        actor_kind: "user".into(),
        sub: Some("alice".into()),
        roles: "admin".into(),
        method: "PATCH".into(),
        route: "/v1/admin/chains/{key}".into(),
        target: Some(target.into()),
        before: Some(r#"{"state":"active"}"#.into()),
        after: Some(r#"{"state":"paused"}"#.into()),
        result: 200,
        request_id: "r1".into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn audit_rows_form_a_hash_chain() {
    let t = tmp();
    let s = SqliteStore::create(&t.url, "t").await.unwrap();
    let r1 = s.append_audit(&audit("evm:1"), 1).await.unwrap();
    let r2 = s.append_audit(&audit("evm:2"), 2).await.unwrap();
    assert_eq!(r1.prev_hash, vec![0; 32]);
    assert_eq!(r2.prev_hash, r1.row_hash);
    let rows = s.audit_log().await.unwrap();
    assert_eq!(verify_audit(&rows), Ok(r2.row_hash.clone().try_into().unwrap()));
    sqlx::query("UPDATE audit_log SET after = '{\"state\":\"active\"}' WHERE seq = ?").bind(r1.seq)
        .execute(&s.pool).await.unwrap();
    assert_eq!(verify_audit(&s.audit_log().await.unwrap()), Err(r1.seq), "a rewrite breaks the chain");
}

#[tokio::test]
async fn a_deleted_middle_audit_row_breaks_the_chain() {
    let t = tmp();
    let s = SqliteStore::create(&t.url, "t").await.unwrap();
    let _r1 = s.append_audit(&audit("evm:1"), 1).await.unwrap();
    let r2 = s.append_audit(&audit("evm:2"), 2).await.unwrap();
    let r3 = s.append_audit(&audit("evm:3"), 3).await.unwrap();
    sqlx::query("DELETE FROM audit_log WHERE seq = ?").bind(r2.seq).execute(&s.pool).await.unwrap();
    assert_eq!(verify_audit(&s.audit_log().await.unwrap()), Err(r3.seq));
}

#[tokio::test]
async fn store_restored_bumps_restore_epoch_and_is_audited() {
    let t = tmp();
    let url = t.url.clone();
    let s = SqliteStore::create(&url, "cli:1000").await.unwrap();
    let e = AuditEntry { actor_kind: "cli".into(), sub: Some("1000".into()), method: "CLI".into(),
                         route: "store restored".into(), result: 0, request_id: "cli".into(), ..Default::default() };
    assert_eq!(s.mark_restored(&e, 5).await.unwrap(), 1);
    drop(s);
    let s = SqliteStore::open(&url, "node").await.unwrap();
    assert_eq!(s.identity().restore_epoch, 1);
    assert_eq!(s.identity().epoch, 6, "the fencing epoch jumps to max(epoch + 1, now_ms = 5), then + 1 at open");
    let log = s.audit_log().await.unwrap();
    assert_eq!((log[0].actor_kind.as_str(), log[0].route.as_str()), ("cli", "store restored"));
}

// ------------------------------------------------------------------ configuration authority (R95)

#[tokio::test]
async fn bootstrap_imports_absent_entries_and_reports_drift() {
    let t = tmp();
    let s = SqliteStore::create(&t.url, "t").await.unwrap();
    let r = bootstrap(&s, &base_set(), 1).await.unwrap();
    assert_eq!(r.imported.len(), 6);
    assert!(r.drift.is_empty());
    let audits = s.audit_log().await.unwrap();
    assert_eq!(audits.len(), 6, "one bootstrap audit row per imported entry");
    assert!(audits.iter().all(|a| a.actor_kind == "bootstrap"));
    let loaded = s.load_config().await.unwrap();
    let mut want = base_set();
    want.namespaces.extend(["~dex", "~gateway", "~mesh"].map(|n| NamespaceRow {
        name: n.into(), state: "active".into(), allow_call: false, max_live_jobs: 10_000, chains: vec![] }));
    want.namespaces.sort_by(|a, b| a.name.cmp(&b.name));
    want.chains.sort_by(|a, b| a.chain_key.cmp(&b.chain_key));
    assert_eq!(loaded, want, "load_config orders by key");

    // an admin change (state) is kept; a toml change is drift, not an overwrite
    sqlx::query("UPDATE chain SET state = 'paused' WHERE chain_key = ?").bind(CHAIN).execute(&s.pool).await.unwrap();
    let mut toml = base_set();
    toml.tokens[0].decimals = 18;
    toml.chains[0].poll_ms = 500;
    toml.lanes[1].account_index = 7;
    let r = bootstrap(&s, &toml, 2).await.unwrap();
    assert!(r.imported.is_empty());
    assert_eq!(r.drift, ["chain:evm:9000", "token:evm:9000/0xAB", "lane:evm:9000/0xBB"]);
    let loaded = s.load_config().await.unwrap();
    assert_eq!(loaded.chains.iter().find(|c| c.chain_key == CHAIN).unwrap().state, "paused");
    assert_eq!(loaded.tokens[0].decimals, 6);
    // the same toml again is neither drift nor import
    let r = bootstrap(&s, &base_set(), 3).await.unwrap();
    assert_eq!(r, BootReport::default());
}

#[tokio::test]
async fn bootstrap_imports_mesh_peers_and_policy() {
    let t = tmp();
    let s = SqliteStore::create(&t.url, "t").await.unwrap();
    let mut set = base_set();
    set.peers = vec![PeerRow { name: "partner-a".into(), url: "https://a.example.net:8550".into(),
                               spki_sha256: "9f".repeat(32), class: "private".into(), chains: "evm:100".into() }];
    set.policy = vec![PolicyRow { chain_key: "evm:100".into(), contract: "0xC0".into(), selector: "*".into(),
                                  support: "full".into(), submit: true, pool_visibility: "open".into(),
                                  min_fee: "0".into(), fee_recipient_allow: "any".into(), gossip: false }];
    bootstrap(&s, &set, 1).await.unwrap();
    let loaded = s.load_config().await.unwrap();
    assert_eq!((loaded.peers, loaded.policy), (set.peers, set.policy));
    let mut bad = base_set();
    bad.chains = vec![];
    bad.tokens = vec![];
    bad.lanes = vec![];
    bad.namespaces = vec![];
    bad.policy = vec![PolicyRow { chain_key: "evm:1".into(), contract: "*".into(), selector: "*".into(),
                                  support: "full".into(), submit: true, pool_visibility: "open".into(),
                                  min_fee: "0".into(), fee_recipient_allow: "any".into(), gossip: false }];
    assert!(bootstrap(&s, &bad, 2).await.is_err(), "contract '*' with submit is refused by the store (R86)");
    // foreign keys (review F11)
    let orphan = |f: &dyn Fn(&mut ConfigSet)| {
        let mut x = ConfigSet::default();
        f(&mut x);
        x
    };
    let token = orphan(&|x| x.tokens.push(TokenRow { chain_key: "evm:404".into(), address: "0x01".into(), decimals: 6, active: true }));
    let lane = orphan(&|x| x.lanes.push(LaneRow { chain_key: "evm:404".into(), label: "0x01".into(), account_index: 0, journal_max: None }));
    for set in [token, lane] {
        assert!(bootstrap(&s, &set, 3).await.is_err(), "a row of an unknown chain: {set:?}");
    }
    assert!(sqlx::query("INSERT INTO api_key (key_id, namespace, scopes, state, created_by, created_at) \
                         VALUES ('k1', 'nobody', 'read', 'active', 't', 1)").execute(&s.pool).await.is_err());
}
