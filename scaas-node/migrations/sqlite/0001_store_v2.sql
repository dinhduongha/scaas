-- Node store v2, SQLite dialect (NI spec §4, A1 §A1.3, gossip amendment §8.4).
-- STRICT tables: a BLOB column never silently holds TEXT, so every key/hash compares byte-exact (A1).
-- No AUTOINCREMENT anywhere: seq/uid come from seq_counter in the same transaction (A1.3).
-- FOREIGN KEYs only where cheap and always true (PRAGMA foreign_keys = ON per connection); none on job.chain_key
-- (a tombstone carries '').

-- store identity and ownership (R88, R93, R110, R111)
-- schema_version, store_id, restore_epoch, <feed>_floor = highest purged seq (R93: cursor < floor ⇒ 410)
CREATE TABLE meta (name TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE store_owner (id INTEGER PRIMARY KEY CHECK (id = 1), epoch INTEGER NOT NULL,
  incarnation TEXT NOT NULL, owner TEXT NOT NULL, since INTEGER NOT NULL) STRICT;
CREATE TABLE seq_counter (name TEXT PRIMARY KEY, value INTEGER NOT NULL) STRICT;
INSERT INTO meta (name, value) VALUES ('schema_version', '2'), ('restore_epoch', '0'), ('job_event_floor', '0'),
  ('feed_item_floor', '0');
INSERT INTO store_owner (id, epoch, incarnation, owner, since) VALUES (1, 0, '', '', 0);
INSERT INTO seq_counter (name, value) VALUES ('job', 0), ('job_event', 0), ('feed_item', 0), ('audit', 0), ('intent', 0);

-- tenants and credentials (R90, R92)
CREATE TABLE namespace (
  name          TEXT PRIMARY KEY,
  state         TEXT NOT NULL CHECK (state IN ('active', 'suspended')),
  allow_call    INTEGER NOT NULL DEFAULT 0,
  max_live_jobs INTEGER NOT NULL DEFAULT 10000,
  created_at    INTEGER NOT NULL, updated_at INTEGER NOT NULL) STRICT;
CREATE TABLE namespace_chain (namespace TEXT NOT NULL REFERENCES namespace (name), chain_key TEXT NOT NULL,
  PRIMARY KEY (namespace, chain_key)) STRICT;
CREATE TABLE namespace_token (namespace TEXT NOT NULL REFERENCES namespace (name), chain_key TEXT NOT NULL,
  token TEXT NOT NULL, PRIMARY KEY (namespace, chain_key, token)) STRICT;
CREATE TABLE api_key (
  key_id      TEXT PRIMARY KEY,
  namespace   TEXT NOT NULL REFERENCES namespace (name),
  scopes      TEXT NOT NULL CHECK (scopes IN ('submit', 'read', 'submit read')),
  generation  INTEGER NOT NULL DEFAULT 0,
  state       TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
  label TEXT, expires_at INTEGER, last_used_at INTEGER,
  created_by  TEXT NOT NULL, created_at INTEGER NOT NULL) STRICT;
CREATE TABLE watch (namespace TEXT NOT NULL REFERENCES namespace (name), chain_key TEXT NOT NULL, token TEXT NOT NULL, address TEXT NOT NULL,
  PRIMARY KEY (namespace, chain_key, token, address)) STRICT;

-- configuration (R95); secrets and dial targets are NOT here
CREATE TABLE chain (
  chain_key TEXT PRIMARY KEY, family TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active', 'paused', 'halted')),
  profile TEXT NOT NULL DEFAULT 'private' CHECK (profile IN ('public', 'private')),
  finality_mode TEXT NOT NULL, finality_depth INTEGER NOT NULL, finality_quorum INTEGER NOT NULL,
  fee_recipient TEXT, poll_ms INTEGER NOT NULL, stuck_after_secs INTEGER NOT NULL,
  max_gas_per_tx INTEGER NOT NULL, max_fee_cap_gwei INTEGER NOT NULL, max_index_lag INTEGER NOT NULL,
  breaker TEXT NOT NULL,
  dex TEXT,
  gossip INTEGER NOT NULL DEFAULT 0 CHECK (gossip = 0 OR profile = 'public'),      -- gossip §8.4: private ⇒ 0
  exclusive_ms INTEGER NOT NULL DEFAULT 7000,
  updated_at INTEGER NOT NULL) STRICT;
CREATE TABLE token (chain_key TEXT NOT NULL REFERENCES chain (chain_key), address TEXT NOT NULL, decimals INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (chain_key, address)) STRICT;
CREATE TABLE lane (chain_key TEXT NOT NULL REFERENCES chain (chain_key), label TEXT NOT NULL, account_index INTEGER NOT NULL,
  journal_max INTEGER,                                            -- monotonic, bumped in the journal transaction
  PRIMARY KEY (chain_key, label)) STRICT;
-- mesh peers and policy (R99: node store tables; MESH R79 superseded). chains = space-separated chain keys.
CREATE TABLE mesh_peer (
  name TEXT PRIMARY KEY, url TEXT NOT NULL, spki_sha256 TEXT NOT NULL UNIQUE,
  class TEXT NOT NULL CHECK (class IN ('open', 'private')),
  chains TEXT NOT NULL DEFAULT '', updated_at INTEGER NOT NULL) STRICT;
CREATE TABLE mesh_policy (
  chain_key TEXT NOT NULL, contract TEXT NOT NULL, selector TEXT NOT NULL,
  support TEXT NOT NULL CHECK (support IN ('none', 'forward_only', 'full')),
  submit INTEGER NOT NULL DEFAULT 0,
  pool_visibility TEXT NOT NULL CHECK (pool_visibility IN ('open', 'private', 'none')),
  min_fee TEXT NOT NULL DEFAULT '0',
  fee_recipient_allow TEXT NOT NULL DEFAULT 'any' CHECK (fee_recipient_allow IN ('any', 'self_or_zero')),
  gossip INTEGER NOT NULL DEFAULT 0,                              -- gossip §8.4
  updated_at INTEGER NOT NULL,
  CHECK (NOT (contract = '*' AND submit = 1)),                    -- MESH R86
  PRIMARY KEY (chain_key, contract, selector)) STRICT;

-- jobs (R89, R91)
CREATE TABLE job (
  uid             INTEGER PRIMARY KEY,
  namespace       TEXT NOT NULL REFERENCES namespace (name),
  origin_scope    TEXT NOT NULL, origin_producer TEXT NOT NULL, origin_key TEXT NOT NULL,
  generation      INTEGER NOT NULL DEFAULT 0,
  client_ref      TEXT,
  chain_key       TEXT NOT NULL,
  kind            TEXT NOT NULL CHECK (kind IN ('metatx', 'call', 'signed_op', 'tombstone')),
  -- G2 is durable only if every digest-bearing kind carries its digest (job_live_digest skips NULL)
  digest          BLOB CHECK (digest IS NULL OR length(digest) = 32)
                  CHECK ((digest IS NULL) = (kind IN ('call', 'tombstone'))),
  payload         BLOB CHECK ((payload IS NULL) = (kind = 'tombstone')),
  payload_hash    BLOB CHECK (payload_hash IS NULL OR length(payload_hash) = 32)
                  CHECK ((payload_hash IS NULL) = (kind = 'tombstone')),
  valid_until     INTEGER NOT NULL,
  lane_hint       TEXT,
  bus_scope       TEXT NOT NULL DEFAULT 'restricted' CHECK (bus_scope IN ('restricted', 'open', 'public')),
  private_window_secs INTEGER NOT NULL DEFAULT 120,
  published_at    INTEGER,
  hold            INTEGER NOT NULL DEFAULT 0,
  state           TEXT NOT NULL CHECK (state IN ('queued', 'leased', 'signed', 'broadcast', 'mined',
                                                 'reverted', 'dead', 'consumed', 'cancelled')),
  lane_label      TEXT, outer_nonce INTEGER, tx_hash TEXT, claim_block INTEGER,
  attempt_count   INTEGER NOT NULL DEFAULT 0, last_error TEXT, last_seq INTEGER,
  created_at      INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  CONSTRAINT job_origin UNIQUE (namespace, origin_scope, origin_producer, origin_key, generation)) STRICT;
CREATE INDEX job_sched   ON job (chain_key, state, uid);
CREATE INDEX job_journal ON job (chain_key, lane_label, outer_nonce);
CREATE UNIQUE INDEX job_live_digest ON job (chain_key, digest)
  WHERE digest IS NOT NULL AND state IN ('queued', 'leased', 'signed', 'broadcast');

CREATE TABLE job_event (
  seq INTEGER PRIMARY KEY, job_uid INTEGER NOT NULL, namespace TEXT NOT NULL,
  state TEXT NOT NULL, tx_hash TEXT, outer_nonce INTEGER, signer TEXT, error TEXT, at INTEGER NOT NULL) STRICT;
CREATE INDEX job_event_ns ON job_event (namespace, seq);

-- index + events feed (R93, R94)
CREATE TABLE chain_index (chain_key TEXT PRIMARY KEY, indexed_block INTEGER NOT NULL, indexed_hash TEXT) STRICT;
CREATE TABLE feed_item (
  seq INTEGER PRIMARY KEY, chain_key TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('range', 'balances', 'dex_range', 'dex_order', 'dex_trade')),
  namespace TEXT,
  from_block INTEGER, to_block INTEGER, body BLOB NOT NULL, at INTEGER NOT NULL) STRICT;
CREATE INDEX feed_chain ON feed_item (chain_key, seq);

-- admin credentials (R106, R107)
CREATE TABLE admin_user (
  name TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  roles TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN ('active', 'disabled')),
  session_epoch INTEGER NOT NULL DEFAULT 0,
  failed_logins INTEGER NOT NULL DEFAULT 0, locked_until INTEGER,
  created_by TEXT NOT NULL, created_at INTEGER NOT NULL, last_login_at INTEGER) STRICT;

-- admin audit (R110): row_hash = sha256(prev_hash ‖ canonical row), see store::audit_hash
CREATE TABLE audit_log (seq INTEGER PRIMARY KEY, at INTEGER NOT NULL,
  actor_kind TEXT NOT NULL CHECK (actor_kind IN ('user', 'oidc', 'cli', 'bootstrap')),
  iss TEXT, sub TEXT,                                             -- user: sub = name; oidc: iss + sub; cli: sub = uid
  roles TEXT NOT NULL, method TEXT NOT NULL, route TEXT NOT NULL, target TEXT,
  before TEXT, after TEXT, result INTEGER NOT NULL, request_id TEXT NOT NULL,
  prev_hash BLOB NOT NULL CHECK (length(prev_hash) = 32), row_hash BLOB NOT NULL CHECK (length(row_hash) = 32)) STRICT;

-- mesh (MESH §6 as amended by R89 / NI §13.1 and gossip §8.4): journal columns live on the job
CREATE TABLE intent (
  seq            INTEGER PRIMARY KEY,                             -- bus_seq, from seq_counter 'intent'
  intent_id      BLOB    NOT NULL UNIQUE CHECK (length(intent_id) = 32),
  chain_key      TEXT    NOT NULL,
  family         TEXT    NOT NULL,
  contract       TEXT    NOT NULL,
  selector       TEXT    NOT NULL,
  subject        TEXT    NOT NULL,
  lane           TEXT    NOT NULL,
  subject_nonce  TEXT    NOT NULL,
  valid_until    INTEGER NOT NULL,
  visibility     INTEGER NOT NULL CHECK (visibility IN (0, 1, 2)),
  source         TEXT    NOT NULL CHECK (source IN ('gateway', 'job', 'peer', 'gossip')),
  source_peer    BLOB,
  job_uid        INTEGER,
  hop_count      INTEGER NOT NULL,
  exclusive_until INTEGER,
  exclusive_self INTEGER NOT NULL DEFAULT 0,
  may_submit     INTEGER NOT NULL DEFAULT 0,
  state          TEXT    NOT NULL CHECK (state IN ('pooled', 'submittable', 'submitting', 'broadcast',
                         'landed', 'consumed', 'failed', 'expired')),
  consumed_kind  TEXT    CHECK (consumed_kind IN ('landed_elsewhere', 'superseded', 'unknown')),
  from_block     INTEGER,
  envelope       BLOB    NOT NULL,
  received_at    INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL,
  last_error     TEXT) STRICT;
CREATE INDEX intent_serve ON intent (seq) WHERE state NOT IN ('landed', 'consumed', 'failed', 'expired');
CREATE INDEX intent_sched ON intent (state, exclusive_until);
CREATE INDEX intent_valid ON intent (valid_until);
CREATE TABLE peer_cursor (peer_id BLOB PRIMARY KEY, store_id TEXT NOT NULL, cursor INTEGER NOT NULL,
  updated_at INTEGER NOT NULL) STRICT;
CREATE TABLE tombstone (intent_id BLOB NOT NULL, body_hash BLOB NOT NULL, expires_at INTEGER NOT NULL,
  PRIMARY KEY (intent_id, body_hash)) STRICT;

-- gossip (amendment §8.4)
CREATE TABLE gossip_announce (peer_id BLOB PRIMARY KEY, version INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  body TEXT NOT NULL, received_at INTEGER NOT NULL) STRICT;
CREATE TABLE gossip_lane (chain_key TEXT NOT NULL, address TEXT NOT NULL, peer_id BLOB NOT NULL,
  PRIMARY KEY (chain_key, address, peer_id)) STRICT;
CREATE TABLE gossip_peer_stat (peer_id BLOB NOT NULL, day INTEGER NOT NULL, assigned INTEGER NOT NULL DEFAULT 0,
  landed INTEGER NOT NULL DEFAULT 0, missed INTEGER NOT NULL DEFAULT 0, violations INTEGER NOT NULL DEFAULT 0,
  false_hints INTEGER NOT NULL DEFAULT 0, invalid INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (peer_id, day)) STRICT;
CREATE TABLE gossip_trusted (peer_id BLOB PRIMARY KEY, label TEXT NOT NULL, assign INTEGER NOT NULL DEFAULT 1,
  dex INTEGER NOT NULL DEFAULT 0 CHECK (dex IN (-1, 0, 1))) STRICT;
CREATE TABLE dex_home_credit (home BLOB NOT NULL, chain_key TEXT NOT NULL, tx_hash TEXT NOT NULL,
  ref BLOB NOT NULL, maker TEXT NOT NULL, taker TEXT NOT NULL, block INTEGER NOT NULL, at INTEGER NOT NULL,
  PRIMARY KEY (chain_key, tx_hash, ref)) STRICT;
CREATE TABLE dex_home_state (home BLOB PRIMARY KEY, trusted_at INTEGER, demoted_until INTEGER, reason TEXT) STRICT;
CREATE TABLE gossip_ban (peer_id BLOB PRIMARY KEY, until_ms INTEGER, reason TEXT NOT NULL, actor TEXT NOT NULL,
  created_at INTEGER NOT NULL) STRICT;
CREATE TABLE dex_replica (order_hash BLOB PRIMARY KEY, chain_key TEXT NOT NULL, dex TEXT NOT NULL,
  base TEXT NOT NULL, quote TEXT NOT NULL,
  home BLOB NOT NULL,
  bound INTEGER NOT NULL CHECK (bound IN (0, 1)), relayer TEXT NOT NULL, maker TEXT NOT NULL,
  claim_rank BLOB, claim_until INTEGER, first_seen_ms INTEGER NOT NULL,
  side TEXT NOT NULL CHECK (side IN ('ask', 'bid')), sell_amount TEXT NOT NULL, buy_amount TEXT NOT NULL,
  home_seq INTEGER NOT NULL, home_filled TEXT NOT NULL, home_closed INTEGER NOT NULL DEFAULT 0,
  chain_filled TEXT NOT NULL DEFAULT '0', chain_closed INTEGER NOT NULL DEFAULT 0, expiry INTEGER NOT NULL,
  checked_ok INTEGER NOT NULL DEFAULT 0,
  body TEXT NOT NULL, updated_at INTEGER NOT NULL) STRICT;
CREATE INDEX dex_replica_book ON dex_replica (chain_key, dex, base, quote, home_closed, chain_closed, side);
