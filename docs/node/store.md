# Node store

The store is the node's only durable state: jobs and their journal, feeds, chain index ranges, configuration, key
metadata, credentials, audit log, DEX book, mesh and gossip tables. It runs on SQLite, PostgreSQL or MySQL; the
backend is storage only. Status: SQLite store, owner lock, fencing, counters, CAS and audit chain **BUILT**; the job
source, PostgreSQL/MySQL and the tables marked below **SPECIFIED**.

## One store

<a id="one-store"></a><a id="NODE-STO-04"></a>**NODE-STO-04** — **One store, always on**, opened by every node (not
only when the mesh is on); backend per [NODE-STO-06](#NODE-STO-06). It holds jobs, job events, index ranges, config,
key metadata, audit, DEX book and the mesh tables. **One owner process per store**, enforced by a backend-native owner
lock **and a fencing epoch** checked in every journal transaction ([backends](#backends)). There is no distributed
nonce manager, no relay pool, no Redis and no Lua: one process owns a store, so a lane's next nonce is a value inside
that process, recovered at cold start from the store ([submit-lanes.md#nonce-plan](submit-lanes.md#nonce-plan)). The
journal is local, so journal-before-broadcast needs no network hop; one writer gives commit-ordered `seq`. A lost
store loses jobs; recovery is operator-confirmed ([NODE-ADM-07](admin-auth.md#NODE-ADM-07),
[runbooks.md#backup-dr](runbooks.md#backup-dr)).

## Backends

<a id="backends"></a><a id="NODE-STO-06"></a>**NODE-STO-06** — **The node store runs on SQLite, PostgreSQL or MySQL;
the backend is storage only.** One `[store] url` (`sqlite:///var/lib/scaas/node.db`, `postgres://…`, `mysql://…`;
toml/env only) selects it; every backend carries the same logical schema ([schema](#schema)) and the same semantics
as [NODE-STO-04](#NODE-STO-04). Multi-node HA on a shared database is **not** in scope
([README.md#limitations](README.md#limitations)).

### Single owner and fencing

- Owner lock, backend-native, on a **dedicated** connection: SQLite `flock` on `<db>.lock`; PostgreSQL
  `pg_try_advisory_lock(k)` with `k` = the first 8 bytes of `store_id` as `int8` (no 32-bit `hashtext`); MySQL
  `GET_LOCK('scaas-node:<store_id>', 0)`. Not obtained ⇒ refuse to start.
- **Fencing epoch**: after taking the lock, `UPDATE store_owner SET epoch = epoch + 1, incarnation = ?, owner = ?,
  since = ?` and remember `mine = epoch`. **Every** journal-bearing transaction (any job CAS, feed insert, audit
  insert) starts with `SELECT epoch FROM store_owner WHERE id = 1 FOR UPDATE` (PG/MySQL; SQLite: inside
  `BEGIN IMMEDIATE`) and aborts with `NOT_OWNER` when `epoch ≠ mine`. A process that lost its lock without noticing
  can therefore not journal, and so cannot broadcast (journal-before-broadcast). The host CLI
  ([NODE-ADM-05](admin-auth.md#NODE-ADM-05)) is the one non-owner writer: it touches only credential tables and
  `audit_log` (taking the same `store_owner` row lock to serialize the audit chain, without comparing the epoch) and
  never a job or feed row.
- The lock connection is pinged every ≤ 2 s; a failed ping stops leasing and submission at once, re-takes the lock
  (new epoch) before resuming, and replays `plan()` from the store.
- PostgreSQL: refuse to start when the server answers `SHOW pool_mode` (PgBouncer) or when `pg_backend_pid()` of the
  lock connection changes between two pings. A connection pooler must not sit between the node and its database.
  <!-- example:odoo -->The reference ERP stack runs PgBouncer (`/home/dockers/odoo19/pgbouncer`) for its own database;
  it must not sit in front of the node store.<!-- /example -->

### Transactions and outcomes

- SQLite: `max_connections = 1` (the single connection of [NODE-STO-04](#NODE-STO-04)), WAL, `synchronous = FULL`,
  `foreign_keys = ON`, transactions opened with `begin_with("BEGIN IMMEDIATE")`; the owner `flock` replaces
  `locking_mode = EXCLUSIVE`.
- PostgreSQL: `REPEATABLE READ` + the fencing `SELECT … FOR UPDATE` row (all writers serialize on it; volume is low);
  MySQL: `REPEATABLE READ` + `SELECT … FOR UPDATE`. Serialization failure / deadlock (`40001`, `40P01`, MySQL 1213)
  ⇒ retry the whole transaction (≤ 3), never skip it.
- **Commit outcome unknown** (connection lost after `COMMIT` was sent): the caller gets `Unknown`; it reconnects and
  re-reads the row before any further action ([submit-lanes.md#journal](submit-lanes.md#journal)). The idempotent
  journal CAS makes the retry safe.

### Per-backend schema rules (normative)

| Logical | SQLite | PostgreSQL | MySQL 8 |
|---|---|---|---|
| key / hash / address / origin text (every PK, UNIQUE, join or compare column) | `TEXT` (binary collation is the default) | `TEXT COLLATE "C"` | `VARBINARY(n)` or `VARCHAR(n) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin` with explicit `n` (PK/UNIQUE need a length: `origin_key` 256, `origin_scope`/`producer` 128, `namespace` 40, `chain_key` 80, addresses 128, `tx_hash` 132) |
| digests, payload hashes, order hashes | `BLOB` (32) | `bytea` | `BINARY(32)` |
| payload / body / JSON metadata | `BLOB`/`TEXT` | `bytea`/`text` | `LONGBLOB`/`LONGTEXT` |
| nonces, heights, seq, uid, timestamps (ms) | `INTEGER` | `BIGINT` | `BIGINT` |
| uint256 amounts | decimal `TEXT`, never ordered or aggregated | same | same |
| `seq`/`uid` | `seq_counter` row incremented in the same transaction (no `AUTOINCREMENT`/`SERIAL`/`AUTO_INCREMENT`), so cursor semantics are identical everywhere | same | same |
| `job_live_digest` | partial UNIQUE index | partial UNIQUE index | generated column `live_digest BINARY(32) AS (IF(state IN ('queued','leased','signed','broadcast'), digest, NULL)) STORED` + `UNIQUE (chain_key, live_digest)` |
| `CHECK` | enforced | enforced | enforced (8.0.16+); minimum version 8.0.16 |
| unique-violation classification | the column list of `UNIQUE constraint failed: job.chain_key, job.digest` (SQLite reports columns, never the constraint or index name), mapped back to the DDL name by the backend; a classifier test pins the mapping, since a future unique index ending in the same columns would be misread | `constraint_name` of the error | index name in error 1062 |

Every query compares bytes; the contract suite asserts `'0xAB' != '0xab'` and base58 case on every backend.
Migrations: `sqlx::migrate!` with `migrations/{sqlite,postgres,mysql}/`; a DDL-equivalence test introspects the three
schemas and compares tables, columns (logical types), unique and check constraints.

### Driver, secrets, tests

- `sqlx` with features `store-sqlite` (default), `store-postgres`, `store-mysql`; `rusqlite` is not used.
- A database URL with a password is toml/env-only, never stored in config tables nor returned by the admin API.
- Store contract suite on all three (SQLite in-process; PostgreSQL and MySQL in docker, `--ignored`), including lock
  loss, fencing, serialization retry, commit-outcome-unknown injection and the byte-exact checks.
- Order of delivery: the backend trait + SQLite first; PostgreSQL then MySQL, each green on the contract suite before
  the next.

## Durability

<a id="durability"></a>A claim needs no `FOR UPDATE SKIP LOCKED`: that was required only while several processes
competed over one shared table. One process owns one store (owner lock + fencing epoch); its lanes compete through the
store and the claim CAS `queued → leased` returns 0 rows to the loser ([NODE-JOB-06](job-api.md#NODE-JOB-06)). A
client never claims: it pushes (idempotent) and applies (ordered, idempotent).

**Same lane keys in two stores** is forbidden and detected on sequence families (EVM, Hedera, Cosmos, Aptos, Soroban,
TON; Sui and Solana have no lane nonce): at lane start, `nonce_at(latest) > journal_max + 1 + tracked` ⇒ the lane
does not lease, `/readyz` reason `lane <label> used outside this store`, metric `scaas_lane_foreign_nonce_total`. A
manual wallet send also trips it — the right default ([submit-lanes.md#lane-keys](submit-lanes.md#lane-keys),
[runbooks.md#incidents](runbooks.md#incidents) RB-04).

## Schema

<a id="schema"></a>Logical schema in SQLite dialect; the per-backend rules above apply. Migrations: `sqlx::migrate!`,
one directory per backend, `meta.schema_version = '2'`; every implementing change ships one numbered migration per
backend directory (`schema_version` + 1). Every key/hash/address column compares **byte-exact** on every backend.
Nonces are `BIGINT` (i64); adapters refuse values > `i64::MAX` (every family fits: EVM nonce, Cosmos/Aptos sequence,
Stellar `ledger << 32`, TON u32).

```sql
-- tenants and credentials (NODE-JOB-03, NODE-JOB-05)
CREATE TABLE namespace (
  name          TEXT PRIMARY KEY,                                 -- [a-z0-9-]{3,40} or reserved '~…' (checked in code)
  state         TEXT NOT NULL CHECK (state IN ('active', 'suspended')),
  allow_call    INTEGER NOT NULL DEFAULT 0,                       -- NODE-JOB-09
  max_live_jobs INTEGER NOT NULL DEFAULT 10000,
  all_tokens    INTEGER NOT NULL DEFAULT 0,                       -- NODE-JOB-12; 1 only by admin, audited
  max_tombstones INTEGER NOT NULL DEFAULT 1000,                   -- NODE-JOB-11
  created_at    INTEGER NOT NULL, updated_at INTEGER NOT NULL);   -- updated_at bumped by every authority change (NODE-JOB-14)
CREATE TABLE namespace_chain (namespace TEXT NOT NULL, chain_key TEXT NOT NULL, PRIMARY KEY (namespace, chain_key));
CREATE TABLE namespace_token (namespace TEXT NOT NULL, chain_key TEXT NOT NULL, token TEXT NOT NULL,
  PRIMARY KEY (namespace, chain_key, token));                     -- client-pushed; empty = no tokens (NODE-JOB-12)
CREATE TABLE api_key (
  key_id      TEXT PRIMARY KEY,                                   -- 'k_' + 16 hex
  namespace   TEXT NOT NULL,
  scopes      TEXT NOT NULL CHECK (scopes IN ('submit', 'read', 'submit read')),
  generation  INTEGER NOT NULL DEFAULT 0,                         -- rotate = +1 (old secret dies)
  state       TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
  label TEXT, expires_at INTEGER, last_used_at INTEGER,           -- last_used_at flushed from memory every 60 s
  created_by  TEXT NOT NULL, created_at INTEGER NOT NULL);        -- no secret column (NODE-JOB-05)
CREATE TABLE watch (namespace TEXT NOT NULL, chain_key TEXT NOT NULL, token TEXT NOT NULL, address TEXT NOT NULL,
  PRIMARY KEY (namespace, chain_key, token, address));            -- receiving wallets (drift A/C)

-- configuration (NODE-STO-03); secrets and dial targets are NOT here (exception: mesh_peer.url)
CREATE TABLE chain (
  chain_key TEXT PRIMARY KEY, family TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active', 'paused', 'halted')),
  profile TEXT NOT NULL DEFAULT 'private' CHECK (profile IN ('public', 'private')),   -- NODE-MESH-06
  finality_mode TEXT NOT NULL, finality_depth INTEGER NOT NULL, finality_quorum INTEGER NOT NULL,
  fee_recipient TEXT, poll_ms INTEGER NOT NULL, stuck_after_secs INTEGER NOT NULL,
  max_gas_per_tx INTEGER NOT NULL, max_fee_cap_gwei INTEGER NOT NULL, max_index_lag INTEGER NOT NULL,
  breaker TEXT NOT NULL,                                          -- BreakerCfg as JSON text (small metadata)
  dex TEXT, updated_at INTEGER NOT NULL,
  max_valid_for_secs INTEGER NOT NULL DEFAULT 3600,               -- job accept step 5, /v1/gateway, mesh accept
  max_inflight INTEGER NOT NULL DEFAULT 16,                       -- per-lane in-flight depth (NODE-LANE-24, PLANNED)
  ua_registry TEXT, ua_registry_gen INTEGER,                      -- NULL = no UA routes
  chain_uid TEXT,          -- '0x' + 64 hex, ≠ 0; EVM/Hedera genesis block hash, else the family's network id or a
                           -- profile constant; required when ua_registry is set, and (SPECIFIED) on every EVM/Hedera
                           -- chain: the salt of every SCaaS EIP-712 domain (NODE-GW-07, NET-ALL-24)
  max_attempts INTEGER NOT NULL DEFAULT 5,                        -- NODE-LANE-14: attempt_count > it ⇒ dead ATTEMPTS_EXHAUSTED
  max_value_out TEXT NOT NULL DEFAULT '0',                        -- NODE-LANE-17, smallest native unit; TON profile 50000000
  max_deposit_per_job TEXT NOT NULL DEFAULT '0',                  -- NODE-LANE-18 (c)
  grief_cost_cap TEXT,                                            -- NODE-LANE-15; NULL = count only
  gossip INTEGER NOT NULL DEFAULT 0,                              -- gossip.md; a private profile forces 0
  exclusive_ms INTEGER NOT NULL DEFAULT 7000);                    -- NODE-GSP-10
CREATE TABLE token (chain_key TEXT NOT NULL, address TEXT NOT NULL, decimals INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,                              -- 0 = intake paused on every door, indexing continues
  kind TEXT NOT NULL DEFAULT 'meta' CHECK (kind IN ('meta', 'zether', 'meta_none', 'meta_single', 'meta_multi',
    'pqz')),                                                      -- built versionOf().kind 0–4; flags 5–8: features                                                      -- PqzToken (ops.md#pqz)
  features TEXT NOT NULL DEFAULT '',                              -- space-separated: 'receiver_fee', 'ua' (v3: registry() ≠ 0)
  PRIMARY KEY (chain_key, address));
  -- planned: token.reg_cache TEXT (controls, roles, compliance registry of regulated tokens) and the snapshot
  -- builder's table (indexer-feeds.md#snapshots)
CREATE TABLE lane (chain_key TEXT NOT NULL, label TEXT NOT NULL, account_index INTEGER NOT NULL,
  journal_max BIGINT,                                             -- monotonic: max(journal_max, n) in the SAME
  PRIMARY KEY (chain_key, label));                                -- transaction as leased→signed (and legacy signed)
CREATE TABLE chain_contract (chain_key TEXT NOT NULL, address TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('tender', 'sponsorship_pool', 'account_factory', 'dex', 'role_holder')),
  PRIMARY KEY (chain_key, address));                              -- registered non-token contracts (call table, job-api.md);
                                                                  -- kind 'dex' rows = the chain profile's DEX list (NET-ALL-24)

-- jobs (NODE-JOB-02, NODE-JOB-04)
CREATE TABLE job (
  uid             BIGINT PRIMARY KEY,                             -- from counter row 'job'
  namespace       TEXT NOT NULL,
  origin_scope    TEXT NOT NULL, origin_producer TEXT NOT NULL, origin_key TEXT NOT NULL,
  generation      INTEGER NOT NULL DEFAULT 0,
  client_ref      TEXT,                                           -- echoed, e.g. 'erp:<outbox row id>'
  chain_key       TEXT NOT NULL,                                  -- tombstones too: the granted chain of the cancel
  kind            TEXT NOT NULL CHECK (kind IN ('metatx', 'call', 'signed_op', 'tombstone', 'ua_metatx',
                                                'pqz_call')),
  digest          BLOB,                                           -- node-computed; NULL for call/pqz_call/tombstone
  payload         BLOB,                                           -- NULL only for kind = 'tombstone'
  payload_hash    BLOB,                                           -- JCS SHA-256; NULL only for tombstone
  -- CHECK ((digest IS NULL) = (kind IN ('call', 'pqz_call', 'tombstone'))): job_live_digest skips NULL, so a
  -- digest-bearing kind without its digest would bypass durable G2. CHECK ((payload_hash IS NULL) = (kind = 'tombstone')).
  -- ua_metatx is digest-bearing: digest = uaDigest. pqz_call is a direct call like call: digest NULL, call_hash set.
  valid_until     BIGINT NOT NULL,
  lane_hint       TEXT,                                           -- NODE-JOB-08
  bus_scope       TEXT NOT NULL DEFAULT 'restricted' CHECK (bus_scope IN ('restricted', 'open', 'public')),
                  -- open "exposes … to admitted peers" (partners); public: also the open mesh
  private_window_secs INTEGER NOT NULL DEFAULT 120,
  published_at    BIGINT,                                         -- set when offered on the bus (NODE-JOB-07, NODE-MESH-15)
  hold            INTEGER NOT NULL DEFAULT 0,                     -- 1 = never lease (cancelled after publication)
  state           TEXT NOT NULL CHECK (state IN ('queued', 'leased', 'signed', 'broadcast', 'mined',
                                                 'reverted', 'dead', 'consumed', 'cancelled')),
  lane_label      TEXT, outer_nonce BIGINT, tx_hash TEXT, claim_block BIGINT,
  attempt_count   INTEGER NOT NULL DEFAULT 0, last_error TEXT, last_seq BIGINT,
  trace_id        TEXT,                                           -- 32 hex from W3C traceparent, else generated
  call_hash       BLOB,                                           -- kind = call/pqz_call: keccak256(target ‖ calldata)
  sponsor_policy_id BIGINT,                                       -- NULL = booked to the namespace (sponsorship.md)
  sponsor_reserved TEXT,                                          -- amount reserved at accept (released/booked exactly)
  sponsor_day     TEXT,                                           -- 'd:YYYY-MM-DD' of the reservation; cost books to this day
  sponsor_hour    TEXT,                                           -- 'YYYY-MM-DDTHH' of the reservation; its counts are released here
  sponsor_fallback TEXT,                                          -- policy name when matched but exhausted with on_exhausted = unsponsored
  gas_used        BIGINT, gas_price TEXT,                         -- effective price, smallest native unit per gas
  cost_native     TEXT,                                           -- every job at mined/reverted, smallest native unit
  created_at      BIGINT NOT NULL, updated_at BIGINT NOT NULL,
  CONSTRAINT job_origin UNIQUE (namespace, origin_scope, origin_producer, origin_key, generation));
CREATE INDEX job_sched   ON job (chain_key, state, uid);
CREATE INDEX job_journal ON job (chain_key, lane_label, outer_nonce);
CREATE UNIQUE INDEX job_live_digest ON job (chain_key, digest)
  WHERE digest IS NOT NULL AND state IN ('queued', 'leased', 'signed', 'broadcast');   -- durable G2 (MySQL: emulation)
CREATE UNIQUE INDEX job_live_call ON job (namespace, chain_key, call_hash)              -- per namespace (NODE-JOB-13)
  WHERE call_hash IS NOT NULL AND state IN ('queued', 'leased', 'signed', 'broadcast');   -- ⇒ 409 DUPLICATE_CALL {uid}

CREATE TABLE job_event (                                          -- the jobs feed (NODE-IDX-04)
  seq BIGINT PRIMARY KEY, job_uid BIGINT NOT NULL, namespace TEXT NOT NULL,
  state TEXT NOT NULL, tx_hash TEXT, outer_nonce BIGINT, signer TEXT, error TEXT, at BIGINT NOT NULL);
CREATE INDEX job_event_ns ON job_event (namespace, seq);

-- the outer transaction (NODE-LANE-12) and adapter journals (NODE-LANE-19)
CREATE TABLE outer_tx (chain_key TEXT NOT NULL, lane_label TEXT NOT NULL, outer_nonce BIGINT NOT NULL,
  tx_hash TEXT NOT NULL,                                 -- latest sent; replacements update it (each logged in job_event)
  state TEXT NOT NULL CHECK (state IN ('signed', 'broadcast', 'mined', 'reverted', 'dropped')),  -- dropped: nonce
                                                         -- gap-filled or never landed, items requeued by plan()
  items INTEGER NOT NULL,                                -- 1, or the batch size; items = job rows journaled with this triple
  gas_used BIGINT, gas_price TEXT, cost_native TEXT,     -- raw, before the batch split onto the items
  fee_native TEXT, value_out TEXT, deposits TEXT,        -- NODE-LANE-13 TxCost, failures included
  billed_retry INTEGER NOT NULL DEFAULT 0,               -- NODE-LANE-14: 1 after the one billed requeue
  signed_bytes BLOB, object_refs TEXT,                   -- NODE-LANE-19 (Sui coins + versions; Solana nonce value),
                                                         -- kept until terminal
  created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL,
  PRIMARY KEY (chain_key, lane_label, outer_nonce));
CREATE TABLE subject_grief (chain_key TEXT NOT NULL, subject TEXT NOT NULL, day TEXT NOT NULL,  -- NODE-LANE-15, 'YYYY-MM-DD'
  billed_failures INTEGER NOT NULL DEFAULT 0, cost TEXT NOT NULL DEFAULT '0', last_at BIGINT NOT NULL,
  PRIMARY KEY (chain_key, subject, day));                                         -- rows kept 30 d

-- index + events feed (NODE-IDX-04, NODE-IDX-05)
CREATE TABLE chain_index (chain_key TEXT PRIMARY KEY, indexed_block BIGINT NOT NULL, indexed_hash TEXT);
CREATE TABLE feed_item (
  seq BIGINT PRIMARY KEY, chain_key TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('range', 'balances', 'dex_range', 'dex_order', 'dex_trade')),
  namespace TEXT,                                                 -- NULL = chain-wide (filtered at serve time)
  from_block BIGINT, to_block BIGINT, body BLOB NOT NULL, at BIGINT NOT NULL);
CREATE INDEX feed_chain ON feed_item (chain_key, seq);

-- store identity and ownership
CREATE TABLE meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);   -- schema_version, store_id, restore_epoch, <table>_floor
CREATE TABLE store_owner (id INTEGER PRIMARY KEY CHECK (id = 1), epoch BIGINT NOT NULL,
  incarnation TEXT NOT NULL, owner TEXT NOT NULL, since BIGINT NOT NULL);
CREATE TABLE seq_counter (name TEXT PRIMARY KEY, value BIGINT NOT NULL);
  -- 'job', 'job_event', 'feed_item', 'audit', 'deny_subject', 'sponsor_policy'

-- admin credentials (NODE-ADM-02, NODE-ADM-04); roles = space-separated subset of 'viewer operator admin key_custodian'
CREATE TABLE admin_user (
  name TEXT PRIMARY KEY,                                          -- [a-z0-9._-]{3,64}
  password_hash TEXT NOT NULL,                                    -- Argon2id PHC string ($argon2id$v=19$m=19456,t=2,p=1$…)
  roles TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN ('active', 'disabled')),
  session_epoch INTEGER NOT NULL DEFAULT 0,                       -- +1 on logout-all, password change, disable, role change
  failed_logins INTEGER NOT NULL DEFAULT 0, locked_until BIGINT,
  created_by TEXT NOT NULL, created_at BIGINT NOT NULL, last_login_at BIGINT);

-- admin audit (NODE-ADM-07)
CREATE TABLE audit_log (seq BIGINT PRIMARY KEY, at BIGINT NOT NULL,
  actor_kind TEXT NOT NULL CHECK (actor_kind IN ('user', 'oidc', 'cli', 'bootstrap')),
  iss TEXT, sub TEXT, roles TEXT NOT NULL, method TEXT NOT NULL, route TEXT NOT NULL, target TEXT,
  before TEXT, after TEXT, result INTEGER NOT NULL, request_id TEXT NOT NULL,
  prev_hash BLOB NOT NULL, row_hash BLOB NOT NULL);               -- row_hash = sha256(prev_hash ‖ canonical row)

-- subject denylist (NODE-OPS-14)
CREATE TABLE deny_subject (
  id            BIGINT PRIMARY KEY,                -- counter row 'deny_subject'
  chain_key     TEXT NOT NULL,                     -- a chain key or '*'
  address       TEXT NOT NULL,                     -- family canonical form (addresses.canonical)
  order_ref     TEXT NOT NULL,                     -- the order's own reference
  document_hash BLOB NOT NULL,                     -- SHA-256 of the order document (kept by the operator, not the node)
  state         TEXT NOT NULL CHECK (state IN ('active', 'lifted')),
  valid_until   BIGINT,                            -- NULL = until lifted; past ⇒ no longer matches
  created_by TEXT NOT NULL, created_at BIGINT NOT NULL, lifted_by TEXT, lifted_at BIGINT, lift_ref TEXT);
CREATE INDEX deny_subject_addr ON deny_subject (address, chain_key);            -- lifted/expired rows kept 400 d

-- integrity and FinOps (ops.md, runbooks.md)
CREATE TABLE breaker_latch (chain_key TEXT NOT NULL, breaker TEXT NOT NULL, opened_at BIGINT NOT NULL,
  reason TEXT NOT NULL, PRIMARY KEY (chain_key, breaker));                      -- re-read at start; cleared only by breaker/reset
CREATE TABLE lane_adopted (chain_key TEXT NOT NULL, lane_label TEXT NOT NULL, nonce BIGINT NOT NULL,
  tx_hash TEXT, adopted_at BIGINT NOT NULL, PRIMARY KEY (chain_key, lane_label, nonce));   -- deleted once latest passes
CREATE TABLE usage_day (
  day            TEXT NOT NULL,                  -- 'YYYY-MM-DD', UTC
  chain_key      TEXT NOT NULL,
  namespace      TEXT NOT NULL,                  -- incl. '~gateway', '~mesh', '~dex', '~lane'
  token          TEXT NOT NULL,                  -- contract of metatx/signed_op, call target, or '' for '~lane'
  sponsor_policy TEXT NOT NULL DEFAULT '',       -- sponsor policy name, '' = none
  jobs_mined BIGINT NOT NULL DEFAULT 0, jobs_reverted BIGINT NOT NULL DEFAULT 0,
  jobs_consumed BIGINT NOT NULL DEFAULT 0, jobs_expired BIGINT NOT NULL DEFAULT 0,
  gas_used       BIGINT NOT NULL DEFAULT 0,
  cost_native    TEXT NOT NULL DEFAULT '0',      -- decimal; summed in code, never in SQL
  fee_earned     TEXT NOT NULL DEFAULT '0',      -- decimal, token base units
  PRIMARY KEY (day, chain_key, namespace, token, sponsor_policy));   -- upserted in the terminal-transition
                                                                     -- transaction; purged after 400 d

-- gas sponsorship (sponsorship.md)
CREATE TABLE sponsor_policy (
  id              BIGINT PRIMARY KEY,                 -- from counter row 'sponsor_policy'
  name            TEXT NOT NULL UNIQUE,               -- [a-z0-9._-]{3,64}
  state           TEXT NOT NULL CHECK (state IN ('active', 'paused')),
  priority        INTEGER NOT NULL DEFAULT 100,       -- lower first; ties by id
  namespace       TEXT NOT NULL,                      -- a namespace, '~gateway', '~mesh', or '*'
  chain_key       TEXT NOT NULL,
  job_kind        TEXT NOT NULL CHECK (job_kind IN ('metatx', 'signed_op', 'call', '*')),
  contract        TEXT NOT NULL,                      -- token (metatx/signed_op: token_of) or call target; canonical, or '*'
  selector        TEXT NOT NULL,                      -- EVM '0x'+8 hex | '0x' (transfer) | '*'; non-EVM 'pay' | '*'
  receiver        TEXT,                               -- canonical m.to / op payee; NULL = any (metatx/signed_op only)
  min_value       TEXT NOT NULL DEFAULT '0',          -- uint256 decimal, token base units; must be '0' when contract = '*'
  account         TEXT NOT NULL,                      -- opaque booking label (cost centre / sponsor contract id); no personal data
  max_cost_per_tx TEXT NOT NULL,                      -- smallest native unit; reservation and per-tx cap
  budget_per_day  TEXT NOT NULL,                      -- smallest native unit, UTC day
  max_tx_per_hour INTEGER NOT NULL, max_tx_per_payer_hour INTEGER NOT NULL,   -- 0 = no per-payer cap
  on_exhausted    TEXT NOT NULL CHECK (on_exhausted IN ('reject', 'unsponsored')),
  min_valid_secs  INTEGER NOT NULL DEFAULT 120,       -- sponsored only if valid_until ≥ now + this
  valid_from BIGINT, valid_to BIGINT, created_by TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL);
CREATE INDEX sponsor_policy_match ON sponsor_policy (chain_key, state, priority, id);
CREATE TABLE sponsor_usage (                          -- buckets: day (cost), hour (tx), payer-hour (tx)
  policy_id BIGINT NOT NULL, bucket TEXT NOT NULL,    -- 'd:2026-10-06' | 'h:2026-10-06T14' | 'p:<payer>:2026-10-06T14'
  tx_count BIGINT NOT NULL DEFAULT 0,                 -- jobs admitted in the hour (counted at accept; −1 on a pre-broadcast end)
  cost_spent TEXT NOT NULL DEFAULT '0',               -- measured (decimal, arbitrary precision in code)
  cost_reserved TEXT NOT NULL DEFAULT '0',            -- Σ job.sponsor_reserved of live jobs of this day
  PRIMARY KEY (policy_id, bucket));                   -- hour/payer buckets pruned after 48 h, day buckets after 400 d
```

Per-backend notes: new address/name/bucket columns are byte-exact keys (MySQL lengths: addresses, `contract`,
`receiver`, `token` 128; `name`, `sponsor_policy` 64; `bucket` 160; `day` 10; `breaker` 40; `order_ref`, `lift_ref`
256); `call_hash`, `document_hash` = `BLOB`/`bytea`/`BINARY(32)`; amounts are decimal text, never ordered or
aggregated in SQL; MySQL emulates `job_live_call` as `job_live_digest` (generated `live_call_hash` + `UNIQUE
(namespace, chain_key, live_call_hash)`); SQLite's column list `job.namespace, job.chain_key, job.call_hash` maps to
`DUPLICATE_CALL` (classifier test). Upserts of `usage_day`/`sponsor_usage` lock their rows (`INSERT … ON CONFLICT DO
NOTHING`, `SELECT … FOR UPDATE`; SQLite: the single writer); restart recomputes `sponsor_usage.cost_reserved` from
live jobs; `tx_count` is transactional and is not recomputed.

Store identity: `restore_epoch` (in `meta`) is incremented by the CLI `scaas-node store restored --config node.toml`,
mandatory after any restore; the same audited transaction **sets every chain `paused`** and runs the retention purge
([NODE-RUN-02](runbooks.md#NODE-RUN-02)), so nothing is leased before clients reconcile. `incarnation` is a random
16-byte hex written at every open. `store init` creates the store once (file mode 0600; refuses an existing one) and
the reserved namespaces `~gateway`, `~mesh`, `~dex` with `all_tokens = 1`; a missing store refuses to start, so an
unmounted volume or a typo'd url never becomes a fresh store with a new `store_id`.

The job state machine is in [job-api.md#states](job-api.md#states); DEX tables in
[dex-venue.md#book-store](dex-venue.md#book-store).

<a id="NODE-STO-09"></a>**NODE-STO-09** (open; default applied) — Names chosen where the design sources gave none
stand as written here: `chain.max_valid_for_secs`, `token.features` value `ua`, `token.reg_cache`, the `/readyz`
body ([ops.md#health](ops.md#health)), the client-side event-cursor reset action of the integration guide.

### Mesh tables

<a id="mesh-tables"></a>The mesh intent rows live in the same store; every local submission is a `job` row
([NODE-JOB-02](job-api.md#NODE-JOB-02)) and an `intent` row references it by `job_uid` instead of carrying its own
journal (`lane_label`, `outer_nonce`, `tx_hash` are read from the job). Counter row `intent` gives `seq` (the
`bus_seq` served to peers) in commit order.

```sql
CREATE TABLE intent (
  seq            BIGINT  PRIMARY KEY,                                    -- bus_seq, from counter row 'intent'
  intent_id      BLOB    NOT NULL UNIQUE CHECK (length(intent_id) = 32),
  chain_key      TEXT    NOT NULL,
  family         TEXT    NOT NULL,
  contract       TEXT    NOT NULL,
  selector       TEXT    NOT NULL,
  subject        TEXT    NOT NULL,                                       -- decoded from the payload (mesh.md#intent-id)
  lane           TEXT    NOT NULL,                                       -- EVM batch (decimal) / op lane (hex)
  subject_nonce  TEXT    NOT NULL,                                       -- decimal
  valid_until    BIGINT  NOT NULL,                                       -- unix s
  visibility     INTEGER NOT NULL CHECK (visibility IN (0, 1, 2)),       -- open, private, none (never served)
  source         TEXT    NOT NULL CHECK (source IN ('gateway', 'job', 'peer', 'gossip')),
  source_peer    BLOB,                                                   -- peer_id when source = 'peer' / 'gossip'
  job_uid        BIGINT,                                                 -- the job row that submits it, if any
  hop_count      INTEGER NOT NULL,
  exclusive_until BIGINT,                                                -- NULL = none or clamped away
  exclusive_self INTEGER NOT NULL DEFAULT 0,
  may_submit     INTEGER NOT NULL DEFAULT 0,                             -- local policy said submit (mesh.md#acceptance)
  state          TEXT    NOT NULL CHECK (state IN ('pooled', 'submittable', 'submitting', 'broadcast',
                         'landed', 'consumed', 'failed', 'expired')),    -- submitting..landed derived from the job
  consumed_kind  TEXT    CHECK (consumed_kind IN ('landed_elsewhere', 'superseded', 'unknown')),
  from_block     BIGINT,                                                 -- chain head when received (getLogs start)
  envelope       BLOB    NOT NULL,                                       -- JSON as created/received
  received_at    BIGINT  NOT NULL,                                       -- unix ms
  updated_at     BIGINT  NOT NULL,                                       -- unix ms
  last_error     TEXT
);
CREATE INDEX intent_serve   ON intent (seq) WHERE state NOT IN ('landed', 'consumed', 'failed', 'expired');
CREATE INDEX intent_sched   ON intent (state, exclusive_until);
CREATE INDEX intent_valid   ON intent (valid_until);

CREATE TABLE peer_cursor (peer_id BLOB PRIMARY KEY, store_id TEXT NOT NULL, cursor BIGINT NOT NULL,
                          updated_at BIGINT NOT NULL);
CREATE TABLE tombstone (intent_id BLOB NOT NULL, body_hash BLOB NOT NULL, expires_at BIGINT NOT NULL,
                        PRIMARY KEY (intent_id, body_hash));
CREATE TABLE mesh_peer (id BIGINT PRIMARY KEY, name TEXT NOT NULL, url TEXT, multiaddr TEXT,
  spki_sha256 TEXT NOT NULL UNIQUE,                     -- 64 lowercase hex
  class TEXT NOT NULL CHECK (class IN ('open', 'private')), chains TEXT NOT NULL,   -- private: required, non-empty
  state TEXT NOT NULL CHECK (state IN ('draft', 'active', 'suspended')),
  allow_private INTEGER NOT NULL DEFAULT 0);            -- SSRF guard opt-in (admin-auth.md#mesh-peer-url)
CREATE TABLE mesh_policy (id BIGINT PRIMARY KEY, chain_key TEXT NOT NULL, contract TEXT NOT NULL,
  selector TEXT NOT NULL, support TEXT NOT NULL CHECK (support IN ('none', 'forward_only', 'full')),
  submit INTEGER NOT NULL DEFAULT 0, pool_visibility TEXT NOT NULL CHECK (pool_visibility IN ('open', 'private', 'none')),
  min_fee TEXT NOT NULL DEFAULT '0', fee_recipient_allow TEXT NOT NULL DEFAULT 'any',
  gossip INTEGER NOT NULL DEFAULT 0,                    -- door-A intents on this row are published on gossip
  UNIQUE (chain_key, contract, selector));
```

First-draft state names (`POOLED`, `FORWARDING`, `SUBMITTABLE`, `SIMULATED`, `LANDED_ELSEWHERE`, `REJECTED`) map to
the lowercase states below (`forwarding` and `simulated` were dropped). Transitions are single `UPDATE … WHERE
intent_id = ? AND state = ?` statements (CAS); a zero row count means
someone else moved it.

| From | Event | To | Who |
|---|---|---|---|
| — | accepted, `!may_submit` or waiting for another's `exclusive` | `pooled` | accept |
| — | accepted, may submit now | `submittable` | accept |
| `pooled` | `exclusive` expired + jitter, `may_submit` | `submittable` | scheduler |
| `submittable` | in-flight digest set admits it, the job row is inserted in `~mesh` | `submitting` | scheduler |
| `submitting` | job insert refused (`DUPLICATE_DIGEST`), breaker open, transient RPC/simulate error | `submittable` | scheduler / outcome sink |
| `submitting` | job journaled (lane, outer nonce, tx hash) and sent | `broadcast` | submit |
| `submitting` | `valid_until` passed before send | `expired` | submit |
| `submitting`, `broadcast` | simulation revert or reverted receipt **with** consumption | `consumed` (+ kind) | submit |
| `submitting` | simulation revert **without** consumption, gas over cap, `metaTxDigest` mismatch | `failed` | submit |
| `broadcast` | receipt success | `landed` | submit |
| `broadcast` | reverted receipt **without** consumption | `failed` | submit |
| `broadcast` | outer nonce gap-filled after `valid_until` | `expired` | submit ([NODE-LANE-04](submit-lanes.md#NODE-LANE-04)) |
| `pooled`, `submittable` | `valid_until < now − clock_skew_secs` | `expired` | janitor |
| `pooled` (`source = job`) | our own job path landed / consumed it | `landed` / `consumed` | job outcome sink (by digest) |
| any non-terminal | the subject nonce is seen consumed while scheduling | `consumed` | scheduler |

A row that ends `failed` is **deleted** (not kept for retention), so a later honest copy of the same `intent_id`
from another source can still be ingested (a bad re-originated copy cannot censor the intent). In its place a
**tombstone** is kept until `valid_until + clock_skew_secs`. L1 skips an envelope whose `(intent_id, body_hash)` is
tombstoned (no re-simulation every poll while it sits in a peer's overlap window); a copy with a different
`body_hash` — the honest one — is still evaluated. The janitor deletes expired tombstones. Rejected intents (L0–L3)
are never written and not cached: an honest copy that arrives later is always evaluated.

Retention (janitor, every 60 s):

1. `pooled`/`submittable` with `valid_until < now − clock_skew_secs` ⇒ `expired`.
2. `submitting` rows older than 60 s with no `tx_hash` on their job ⇒ `submittable` (lost hand-off). `broadcast` rows
   are left to the submit path (it owns the outer nonce).
3. `DELETE` terminal rows with `updated_at < now − retention_secs` (24 h).
4. Row count ≥ `max_rows` ⇒ new ingests fail with `STORE_FULL` (metric), nothing is evicted (gossip rows have their
   own cap, [gossip.md#numbers](gossip.md#numbers)).

`peer_cursor` rows of peers no longer in the table are deleted at the next config refresh.

### Gossip tables

```sql
CREATE TABLE gossip_announce (peer_id BLOB PRIMARY KEY, version BIGINT NOT NULL, expires_at BIGINT NOT NULL,
  body TEXT NOT NULL, received_at BIGINT NOT NULL);
CREATE TABLE gossip_lane (chain_key TEXT NOT NULL, address TEXT NOT NULL, peer_id BLOB NOT NULL,
  PRIMARY KEY (chain_key, address, peer_id));                       -- from announces with a valid PoP only
CREATE TABLE gossip_peer_stat (peer_id BLOB NOT NULL, day BIGINT NOT NULL, assigned BIGINT NOT NULL DEFAULT 0,
  landed BIGINT NOT NULL DEFAULT 0, missed BIGINT NOT NULL DEFAULT 0, violations BIGINT NOT NULL DEFAULT 0,
  false_hints BIGINT NOT NULL DEFAULT 0, invalid BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (peer_id, day));
CREATE TABLE gossip_trusted (peer_id BLOB PRIMARY KEY, label TEXT NOT NULL, assign INTEGER NOT NULL DEFAULT 1,
  dex INTEGER NOT NULL DEFAULT 0 CHECK (dex IN (-1, 0, 1)));        -- DEX home: 1 pre-trusted, 0 automatic, -1 blocked
CREATE TABLE dex_home_credit (home BLOB NOT NULL, chain_key TEXT NOT NULL, tx_hash TEXT NOT NULL,
  ref BLOB NOT NULL, maker TEXT NOT NULL, taker TEXT NOT NULL, block BIGINT NOT NULL, at BIGINT NOT NULL,
  PRIMARY KEY (chain_key, tx_hash, ref));                           -- credited settles, pruned after the window
CREATE TABLE dex_home_state (home BLOB PRIMARY KEY, trusted_at BIGINT, demoted_until BIGINT, reason TEXT);
CREATE TABLE gossip_ban (peer_id BLOB PRIMARY KEY, until_ms BIGINT, reason TEXT NOT NULL, actor TEXT NOT NULL,
  created_at BIGINT NOT NULL);                                      -- until_ms NULL = until lifted
CREATE TABLE dex_replica (order_hash BLOB PRIMARY KEY, chain_key TEXT NOT NULL, dex TEXT NOT NULL,
  base TEXT NOT NULL, quote TEXT NOT NULL,
  home BLOB NOT NULL,                                               -- bound: the home; unbound: the winning claimant
  bound INTEGER NOT NULL CHECK (bound IN (0, 1)), relayer TEXT NOT NULL, maker TEXT NOT NULL,
  claim_rank BLOB, claim_until BIGINT, first_seen_ms BIGINT NOT NULL,                  -- unbound only
  side TEXT NOT NULL CHECK (side IN ('ask', 'bid')), sell_amount TEXT NOT NULL, buy_amount TEXT NOT NULL,
  home_seq BIGINT NOT NULL, home_filled TEXT NOT NULL, home_closed INTEGER NOT NULL DEFAULT 0,
  chain_filled TEXT NOT NULL DEFAULT '0', chain_closed INTEGER NOT NULL DEFAULT 0, expiry BIGINT NOT NULL,
  checked_ok INTEGER NOT NULL DEFAULT 0,                            -- unbound: our checkOrder passed
  body TEXT NOT NULL, updated_at BIGINT NOT NULL);
CREATE INDEX dex_replica_book ON dex_replica (chain_key, dex, base, quote, home_closed, chain_closed, side);
```

Portable per the backend rules (`BIGINT`/`TEXT`, no backend types); `gossip_peer_stat` rows older than 8 days and
expired announces/bans are deleted by the janitor. `dex_market` gains `gossip INTEGER NOT NULL DEFAULT 0` and
`unbound INTEGER NOT NULL DEFAULT 0` ([dex-venue.md#gossip](dex-venue.md#gossip)).

## Chain state

<a id="chain-state"></a><a id="chain-states"></a><a id="NODE-STO-02"></a>**NODE-STO-02** — Chain `state ∈ active|paused|halted`. **`paused` blocks sending only**: no new lease, the gateway refuses new intake for the chain, but
the indexer and the event feed continue and signed transactions keep being tracked, so a customer who has paid is
still booked. **`halted`** also stops indexing (chain fault or reorg that needs a human). A chain not yet enabled
stays out of the store (enablement: [runbooks.md#production-gates](runbooks.md#production-gates)). A client may keep
its own pause switch as a push gate; the stricter of the two wins.

<a id="NODE-STO-05"></a>**NODE-STO-05** — **Finality, pause and the index cursor are node state**: finality mode,
depth and quorum, the chain state and `chain_index` live in the node store; client copies of them are never node
inputs ([NODE-IDX-02](indexer-feeds.md#NODE-IDX-02)).

<a id="NODE-STO-08"></a>**NODE-STO-08** (open; default applied) — A paused chain **accepts** jobs on the job API and
holds them `queued` until it is resumed; a `halted` chain refuses intake (`409 CHAIN_HALTED`).

## Configuration authority

<a id="config-authority"></a><a id="NODE-STO-03"></a>**NODE-STO-03** — **Config authority = the node store.**
`node.toml` bootstraps: entries absent from the store are imported; present ones are not overwritten (drift warning
+ gauge `scaas_config_toml_drift`). **Toml-only** (never in the store, never through the admin API): lane
keys/mnemonic, `rpc_urls`, `[store] url`, `master_key`, OIDC issuers, binds (incl. `metrics_bind`), CORS origin
lists, `[app]`, `[log]`, `[api.admin_auth]` modes and session parameters, `[identity]`, `[transport]`, `[gossip]`
listen/external/bootstrap/direct addresses. RPC endpoints are therefore only in node configuration: clients never call
an RPC, provider URLs often embed keys, and two places holding one list would be two truths. **Hot (≤ 2 s)**: chain
state, tokens (incl. `active`, `features`), `fee_recipient`, breaker, `max_valid_for_secs`, `max_attempts`,
`max_value_out`, `max_deposit_per_job`, `grief_cost_cap`, policy, peers, namespaces, keys, watch lists, namespace
token subsets, DEX markets, deny list, sponsor policies, chain contracts, per-chain/per-policy/per-market `gossip`
switches, `exclusive_ms`, `gossip_trusted`, bans. **Restart**: lane index list, finality, family params,
`ua_registry`, `chain_uid`. **Token subsets per namespace are client state** (`PUT /v1/tokens/{chain}`), intersected
with the node registry; empty = no tokens ([NODE-JOB-12](job-api.md#NODE-JOB-12)). **Exception: `mesh_peer.url`**
(mesh dial targets) **is editable through the admin API**: `admin` role only, audited, behind the SSRF guard of
[admin-auth.md#mesh-peer-url](admin-auth.md#mesh-peer-url).

Start: load toml → open store (it must exist: a new node runs `scaas-node store init` once; a missing file refuses to
start; migrate, take owner lock on the canonical path, bump fencing epoch, new incarnation) → **import** toml entries
absent from the store (`[[chains]]` + tokens + lanes, `[[mesh.peers]]`, `[[mesh.policy]]`, `[[namespaces]]`,
`[[sponsorship.policies]]`; `all_tokens` only from an explicit toml key) → build runtime. Differing toml values set
`scaas_config_toml_drift` and a warning. Until the runtime reads a value from the store, every consumer still reads
toml, so the warning says toml is used for now and the store value takes effect when the runtime reads the store.
`rpc_urls`, keys, `params`, `coin_type`, `[store] url` always come from toml.

Runtime snapshot: `tokio::sync::watch::Sender<Arc<ConfigSnapshot>>`, rebuilt after every admin commit (and every 30 s
as a guard). Its readers: gateway tokens, family token filters, indexer tokens and finality, drift pairs, breaker,
chain state, mesh peers/policy, the deny set, sponsor policies, `chain_contract` rows, token `kind`/`features`/`active`
(every door).

Transitional (BUILT): the legacy pull path reads the token list and chain parameters from the client's `node_config`
call; the store snapshot replaces it chain by chain ([job-api.md#legacy-pull](job-api.md#legacy-pull)).

## Config validation

<a id="config-validation"></a>`Config::validate` and the admin API refuse, besides the listener rules of
[README.md#listeners](README.md#listeners):

<a id="NODE-STO-01"></a>**NODE-STO-01** — On a family that prunes lane state after expiry (TON, Aptos, Solana, Sui), a chain
must have `max_valid_for_secs ≤ LANE_HORIZON` — `max_valid_for_secs ≤ H` with `H = LANE_HORIZON = 30 d`, so that
`validUntil ≤ t_first_issue + H` holds (the pay-lane issuance horizon H,
[CTR-MTX-04](../contracts/metatx.md#CTR-MTX-04)); the node refuses `max_valid_for_secs > LANE_HORIZON`, because pay-once then no longer
holds ([NET-ALL-01](../networks/README.md#NET-ALL-01)). The constants are pinned equal in tests (TON `LANE_TTL`,
Aptos/Solana `PRUNE_DELAY_S`, Sui `LANE_HORIZON_S`, node `LANE_TTL_S`, the issuer's `LANE_HORIZON_S`).

<a id="NODE-STO-10"></a>**NODE-STO-10** — `max_gas_per_tx` keeps its default of 3 000 000; registering a confidential
token (classical Zether or post-quantum Zether) on a chain whose `max_gas_per_tx` is below that token kind's per-chain
minimum (≥ 4 200 000 on classical Zether chains, measured transfer 3 360 000, [contracts/zether.md#gas-measured](../contracts/zether.md#gas-measured);
16 000 000 on the post-quantum Zether chain, [contracts/pq-zether.md#verifier](../contracts/pq-zether.md#verifier)) is accepted with a warning
and a `422`-free admin response field `warnings`, so the operator raises the cap before the first transfer.

Also refused: an upgradeable program on a chain being activated ([NODE-STO-07](#NODE-STO-07)); the same public key in
two families ([NODE-LANE-20](submit-lanes.md#NODE-LANE-20)); `gateway_cors_origins` with gateway auth `bearer` or
`hmac` ([NODE-GW-04](gateway.md#NODE-GW-04)); a private profile with `gossip = 1` or a policy `pool_visibility =
open`; `submit` on `contract = "*"`; a mesh peer of class `private` without chains; `ua_registry` without `chain_uid`;
(SPECIFIED) an EVM or Hedera chain without `chain_uid`, a `chain_uid` already used by another chain row, and a
`chain_contract` row of kind `dex` whose `chainUid()` differs ([NODE-GW-07](gateway.md#NODE-GW-07)).

## Immutable programs

<a id="immutable-programs"></a><a id="NODE-STO-07"></a>**NODE-STO-07** — **Sui, Aptos and Solana programs are
immutable at deploy** ([CTR-GEN-02](../contracts/README.md#CTR-GEN-02)); the node verifies it. Sui
`package::make_immutable` on the `UpgradeCap`, Solana upgrade authority `None` (after `initialize`), Aptos
`upgrade_policy = immutable`; the family deploy scripts set and verify it. The node reads it at chain activation and
at start (Sui: the configured `UpgradeCap` id no longer exists; Solana: ProgramData `upgrade_authority_address` is
`None`; Aptos: `PackageRegistry` policy = immutable) and holds an upgradeable chain `halted` with
`PROGRAM_UPGRADEABLE`.

## Config file

<a id="config-file"></a>`node.toml` holds the bootstrap rows, secrets (as references: `{ env = … }`, `{ file = … }`,
`{ keystore = …, passphrase_env = … }`) and dial targets. Example (other sections:
[admin-auth.md#credentials](admin-auth.md#credentials), [submit-lanes.md#lane-keys](submit-lanes.md#lane-keys),
[gossip.md#architecture](gossip.md#architecture)):

```toml
[store]
url = "sqlite:///var/lib/scaas/node.db"         # or postgres://… / mysql://… (password via env)

[modules]
submit = true
indexer = true
gateway = true                                  # gateway_bind default 127.0.0.1:8547, behind a reverse proxy
mesh = true                                     # default false
gateway_bind = "127.0.0.1:8547"
admin_bind = "127.0.0.1:9108"
metrics_bind = ""

[[chains]]
family = "evm"
evm_chain_number = 7622
rpc_urls = ["http://rpc-a:8545", "http://rpc-b:8545"]   # ≥ finality.quorum independent endpoints
finality = { mode = "depth", depth = 1, quorum = 1 }    # 'depth' | 'tag' | 'instant'
dex = "0x…"                                     # SCaaSDex, optional
poll_ms = 1000
stuck_after_secs = 60                           # replace at the same nonce, fee ×1.25
max_gas_per_tx = 3000000                        # structural breaker
max_fee_cap_gwei = 500                          # fee ceiling for replacements
max_inflight = 16                               # per-lane in-flight depth, tunable default (NODE-LANE-24)
profile = "public"                              # chain_profile; default "private" (NODE-MESH-06)
fee_recipient = "0x…"                           # optional, EVM/Hedera. Cold wallet: normalization target, published
                                                # in /v1/mesh/policy, used by fee_recipient_allow = "self_or_zero".
                                                # Never a lane key. Unset ⇒ normalization writes 0 (fee to the lane).
tokens = ["0x…"]                                # bootstrap token rows (NODE-MESH-13)
lanes = [0, 1]                                  # account indexes (submit-lanes.md#lane-keys)

[mesh]
bind = "0.0.0.0:8550"                           # mTLS only; there is no plaintext mode
cert = "/etc/scaas/mesh.crt"                    # self-signed X.509 (PEM) holding the [identity] key
poll_ms = 1000
max_hops = 4
cursor_overlap = 200
publish_lag_ms = 500
exclusive_ms = 10000                            # receiver clamp (NODE-MESH-10)
post_exclusive_jitter_ms = 2000
max_valid_for_secs = 3600
page_max = 200
page_max_bytes = 1048576
retention_secs = 86400
max_rows = 200000
peer_rps = 10                                   # requests/s a peer may make to us (token bucket, burst = 2 × rps)
peer_intents_per_sec = 50                       # new intents/s we ingest from one peer
max_conns = 64                                  # concurrent inbound TLS connections
handshake_timeout_ms = 5000
max_conn_age_secs = 300
clock_skew_secs = 30

[[mesh.peers]]                                  # bootstrap rows; the admin API manages them afterwards
name = "partner-a"
url = "https://a.example.net:8550"
spki_sha256 = "9f…64 hex"
class = "open"                                  # open | private
chains = ["evm:100"]                            # private peers: chains they may receive (required, non-empty).
                                                # open peers: optional filter; empty = every public chain.

[[mesh.policy]]
chain = "evm:100"
contract = "0x…"                                # canonical address of the family (token_of), or "*" (never "*" with submit = true)
selector = "*"                                  # EVM: "0x" + 8 hex, "0x" (empty data) or "*"; other families: "pay" or "*"
support = "full"                                # none | forward_only | full
submit = true
pool_visibility = "open"                        # open | private | none
min_fee = "0"                                   # uint256 decimal, smallest token unit, compared with the EFFECTIVE fee
fee_recipient_allow = "any"                     # any | self_or_zero — only meaningful when the intent binds feeRecipient
```

Validation: `modules.mesh = true` ⇒ `[mesh]` required; a `[[chains]]` entry needs a key only if `modules.submit`; a
`profile = "private"` chain refuses `pool_visibility = "open"` and `gossip = 1`; `submit = true` with `contract =
"*"` is refused. Peer key generation (no new crate needed; also printed by `scaas-node mesh-id --config node.toml`):

```bash
openssl genpkey -algorithm ed25519 -out node.key
openssl req -new -x509 -key node.key -out mesh.crt -days 3650 -subj "/CN=scaas-node"
# peer_id = SPKI pin to give to partners:
openssl x509 -in mesh.crt -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -r
```

Transitional (BUILT): a legacy client section (client URL, database, two service API key env names) configures
the pull path; a client's `node_config` call supplies tokens and finality there. The final release refuses
that section ([NODE-JOB-10](job-api.md#NODE-JOB-10)).
