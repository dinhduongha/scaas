# P1 "node store v2 on SQLite" code review

Merge `416dd24` (`60cfa9d`, `9c804d9`), `scaas-node/`. This was a read-only review: no build and no test run.
Spec: NI rev 3.2 §4, §8, §9, R88–R95, R110, A1 rev 2 / R111, §16.1, §17 P1. Also the MESH §6 and gossip §8.4 tables.

## Verdict: FIX

None of this is a BLOCK. In P1 the store is not on any path that moves money yet: submit, indexer and gateway still
run on the legacy Odoo path. The core parts are sound:
- owner lock plus fencing
- seq counters taken in the same transaction
- the tri-state CAS
- the partial UNIQUE index
- the audit chain
- the pragmas

F1–F4, though, are safety holes in the store contract that P3 will build on. Fix them before P3 starts, preferably
as a small P1 follow-up so the contract suite pins them.

---

## Findings (ranked)

### F1 — HIGH: `transition()` can cancel a published job, which bypasses R98

`src/store/mod.rs:125-126` (TRANSITIONS has `Queued→Cancelled` and `Leased→Cancelled`) and
`src/store/sqlite.rs:288-302, 95-140`.

**Problem.** `transition(uid, Queued, Cancelled, …)` is a legal pair, and `transition_tx` never looks at
`published_at`. R98's rule ("published ⇒ hold + TOO_LATE, never cancelled") is only enforced in `cancel_in`. A P3 or
P4 caller that cancels through `transition` (expiry janitor, admin kill, API handler) marks a published job
`cancelled`. Odoo then sees `dead`/`cancelled` and lets the payer re-sign, while a peer may still land the original.
That is a double payment.

**Fix.** Make `cancel()` / `cancel_by_origin()` the only way into `Cancelled`. In `transition()`, return
`Err(Illegal)` when `to == Cancelled`. Keep the pair in `TRANSITIONS` so it still matches `transitions.json`.
Another option is to add `AND published_at IS NULL` to the CAS when `to = 'cancelled'`. Test: publish, then
`transition(Queued→Cancelled)` must not reach `cancelled`.

### F2 — HIGH: mesh policy keys are not canonical, so a deny row can be bypassed silently

`src/config.rs:690` (`contract: p.contract.clone()`), `src/config.rs:613` (selector hex accepts uppercase), and
`src/mesh/accept.rs:119-122` (`lookup` compares byte-exact).

**Problem.** The mesh compares against lowercase forms:
- `digest.rs:155-156` requires `env.contract` to be lowercase `{:#x}`.
- `hex0x` writes selectors in lowercase.

Toml accepts `contract = "0xAbC…"` (an EIP-55 checksummed address pasted from an explorer) or
`selector = "0xA9059CBB"`, and imports it as-is. That row can never match. A specific `support = "none"` row then
falls through to a permissive `(*, *)` row, so the deny is silently bypassed. A specific `submit = true` row is also
silently dead. Tokens were normalised (`config.rs:665`) but policy was not.

**Fix.** In `validate_store_sections`, require `contract == "*"` or the family's canonical form. For EVM and Hedera,
parse it as `Address` and either refuse anything that differs from `{:#x}`, or normalise in `boot_set` the way
tokens are. Require selector hex to be lowercase (or lowercase it). Add a test: `"0xAbC…"` either becomes lowercase
or is refused.

### F3 — HIGH: `job.digest` can be NULL on digest-bearing kinds, so durable G2 can be bypassed

`migrations/sqlite/0001_store_v2.sql:80`.

**Problem.** `job_live_digest` only covers rows `WHERE digest IS NOT NULL`. Nothing stops a `metatx` or `signed_op`
row with `digest = NULL`. A caller bug in P2/P3 (gateway door A, mesh scheduler, DEX settle) would then insert live
duplicates that the durable G2 index never sees. G2 is the double-broadcast guard. Spec §4: "NULL for
call/tombstone".

**Fix.** Make the invariant part of the schema, since nothing is deployed and 0001 can still be edited:
`CHECK ((digest IS NULL) = (kind IN ('call', 'tombstone')))`. Also add
`CHECK ((payload_hash IS NULL) = (kind = 'tombstone'))`.

### F4 — MEDIUM-HIGH: `accept` never checks `valid_until`, so the purge safety argument does not hold in the store

`src/store/sqlite.rs:142-186` and `:371-382`.

**Problem.** §4 says "a purged origin key can never be re-accepted because its payload is expired". The janitor
deletes terminal rows once `valid_until < now − 1 d`. After that, a stale or replayed push of the same key passes the
SELECT, because the row is gone, and gets `Created`. The store never refuses an expired `valid_until`. For `call`
jobs (digest NULL) nothing else dedups them.

There is a related gap: `accept` refuses a *lower* generation that is still live, but it happily creates generation
`g` when generation `g+1` already exists (for example after `g` was purged).

**Fix.** In `accept_once`, refuse `j.valid_until * 1000 <= now` with a new `Accept::Expired` (422). Optionally also
return `PreviousGenerationLive`/`Superseded` when a row with `generation > g` exists. Both checks are cheap and run
inside the same transaction.

### F5 — MEDIUM: a mis-mounted or typo'd `[store] url` silently creates a fresh store

`src/store/sqlite.rs:35` (`create_if_missing(true)`).

**Problem.** If the docker volume is missing or the path is wrong, the node starts on a brand-new, empty store. That
means a new `store_id`, no `journal_max`, no live-digest rows and no audit chain. In P3 and later this loses the
journal and G2 state. In a container without its volume it happens on every restart. Odoo halts on the `store_id`
change (R110), but the node itself keeps going.

**Fix.** Default to `create_if_missing(false)`. Create the store only through an explicit `scaas-node store init`,
or a `[store] create = true` that the operator removes after the first start. Refuse to start when the file is
missing, with the message "store not found; run `store init` for a new node".

### F6 — MEDIUM: `outer_nonce` and `tx_hash` are accepted on any transition and bump `journal_max`

`src/store/sqlite.rs:110-132` (the bind at `:120`).

**Problem.**
- `COALESCE(?5, outer_nonce)` and the `journal_max` bump run for every `to ≠ Queued`. A caller that passes a nonce
  on `Leased→Dead`, `Leased→Consumed` or `Broadcast→Broadcast` overwrites the journaled nonce. If the nonce is larger
  than the real one, it raises `journal_max` above what was ever signed. `plan()` then opens a nonce gap and the lane
  stalls.
- `Signed` does not check that the signing lane is the leased lane.

**Fix.**
- Accept `outer_nonce` only for `to == Signed` and return `Invalid` otherwise.
- Accept `tx_hash` only for `Signed` and `Broadcast` (replacement).
- For `Signed`, if `fields.lane_label` is `Some`, require it to equal `job.lane_label`.
- Validate the lane at lease time too: `Queued→Leased` should fail when `(chain_key, lane_label)` is not in `lane`.
  Today that is only discovered at `Signed`, as the test at `tests.rs:293` shows.

### F7 — MEDIUM: `NotOwner` is not fatal and lock health is not checked

`src/store/mod.rs:613-622`; A1.1 "a failed ping stops leasing…".

**Problem.**
- Once fenced out, the janitor logs `warn` every 60 s forever, and the legacy Odoo paths keep running in a process
  that no longer owns its store.
- The lock path comes from the URL string (`sqlite.rs:40-41`). Opening the same DB through a symlink (`link.db` and
  `node.db`) gives two lock files, so two owners. Fencing stops the stale one from journaling, but nothing notices
  that it has been fenced out.

**Fix.**
- `janitor` should return `Err` on `StoreError::NotOwner`. `main` already turns a finished task into an error, so the
  process exits.
- Canonicalize the DB path before forming `<db>.lock`: create it first, then `std::fs::canonicalize`.
- Optional cheap check every ≤ 2 s from A1.1: compare `SELECT epoch FROM store_owner` with `mine`, and check that the
  lock file inode still matches.

### F8 — MEDIUM (P2 prerequisite): purge leaves no low-water mark for `410 CURSOR_EXPIRED`

`src/store/sqlite.rs:377-379`.

**Problem.** After `DELETE FROM job_event/feed_item WHERE at < …`, the API cannot tell "cursor expired" from
"nothing new". The test at `tests.rs:520` shows the table can end up empty while `head_seq > 0`.

**Fix.** In the same purge transaction, write `meta('job_event_floor')` and `meta('feed_item_floor')` as the max
purged seq. R93 then returns 410 when `cursor < floor`.

### F9 — LOW-MEDIUM: Hedera and other non-EVM token addresses are not canonical

`src/config.rs:665-668`.

**Problem.** Only `0x…` values that `Address` parses are normalised. Odoo's `addresses.canonical` turns Hedera
`0.0.N` into `0x` + 20-byte long-zero, and lowercases and zero-pads Sui/Aptos. Toml `0.0.N` is stored raw, so the
R95 client-pushed token subsets (`namespace_token`, intersected with the registry) never match Odoo's form.

Also, a mixed-case EVM address with a bad EIP-55 checksum is accepted, while Odoo's `parse_address` refuses it.

**Fix.** Port `canonical(family, value)` from `dms_blockchain/lib/addresses.py` (one function, shared KAT vectors),
use it in `boot_set` and validation, and refuse a bad checksum.

### F10 — LOW: the drift warning is wrong in P1

`src/main.rs:132` says "the store wins (R95)", but every runtime consumer still reads `cfg` (toml) until the
ConfigSnapshot is wired up (P3/P4). An operator who edits finality in toml after the first start is told the store
wins. In P1 the toml actually wins, and after P3 their edit will silently vanish.

**Fix.** Until consumers read the store, say "node.toml differs from the store; the store value takes effect when
runtime reads the store (P3); toml is used for now". Also add the `toml_drift` gauge from §8.

### F11 — LOW: `foreign_keys = ON` but there are no FOREIGN KEYs

`sqlite.rs:38` and the DDL.

The pragma does nothing. Either declare FKs where they are cheap and true, or drop the pragma claim:
- `namespace_chain → namespace`
- `token → chain`
- `lane → chain`
- `api_key → namespace`
- `job.namespace → namespace`

Do not put an FK on `job.chain_key`, because of the tombstone's `''`.

### F12 — LOW: default `[api] bind` equals the default `gateway_bind`

`config.rs:61` uses `default_bind()` = `127.0.0.1:8547`, which is the same as `gateway_bind` (`config.rs:202`). The
spec §3 table repeats the clash. `node.example.toml:17` hides it by setting 8546.

**Fix.** Use a distinct default (8548), and validate `api.bind != modules.gateway_bind` when both run. P2 will hit
this otherwise.

### F13 — LOW: missing fencing tests

`stale_owner_cannot_journal` (`tests.rs:151`) does not cover these fenced writes: `publish`, `purge`, `import`
(bootstrap), `cancel_by_origin`, `mark_restored`. Add one-line asserts for each.

There are also no tests for:
- F1 (published job plus `transition→Cancelled`)
- a deleted middle audit row in `verify_audit`
- a symlinked path (F7)

### F14 — LOW: integer casts can overflow

- `main.rs:141` and `sqlite.rs:375-377` compute `job_retention_secs as i64 * 1000`. A huge toml value wraps, or
  panics in debug.
- `config.rs:442-453` casts `u64` to `i64` for `max_gas_per_tx` and similar.

**Fix.** Bound them in `validate`, for example retention ≤ 10 y, or use `i64::try_from` and `checked_mul`.

### F15 — LOW: housekeeping

- The DB file is created with umask mode (0644). `node.example.toml:13` says 0600, and the store will hold Argon2
  hashes from P2. Set 0600 on create (and on `-wal`/`-shm` via umask).
- The tests leak a temp dir per case (`tests.rs:9-13`). Use `tempfile`, or remove the dir in a guard.
- `verify_audit` loads the whole log at every start (`main.rs:134`). That is fine now; it is already covered by the
  spec's ponytail note on retention.
- The `transitions.json` copy in `dms_blockchain/tests/data/` and the CI `cmp` do not exist yet (§4). Track them for
  P5.
- `store_owner.epoch` rewinds together with a restore, so a pre-restore stale process could share an epoch with the
  post-restore owner. Not reachable if the runbook is followed (node stopped). Optional hardening: `mark_restored`
  sets `epoch = max(epoch + 1, now_ms)`.

---

## Properties checked and found correct

- **Owner lock.** `flock` is taken before connect and migrate (`sqlite.rs:42-46`). The kernel releases it on crash
  or exit, and `File` is CLOEXEC. A second open in another process, or the same one, gets `Owned`. Pool reconnects
  (idle and lifetime) do not drop the lock, because it lives on a separate `File`. That is the right reason to prefer
  it over `locking_mode = EXCLUSIVE`.
- **Fencing.** Every write method goes through `begin()`, which runs `BEGIN IMMEDIATE` and then compares the epoch,
  so the epoch cannot change mid-transaction: transition, accept, cancel, cancel_by_origin, publish, bump, purge,
  audit, mark_restored, import. `NotOwner` is not folded into `Unknown`. Reads are unfenced, which is fine because a
  stale owner cannot journal and so cannot broadcast.
- **Tri-state.** `Moved` is returned before any write. A CAS miss writes nothing (tested). The `Signed` retry returns
  `Moved{Signed, hash}` for the caller to compare. That is equivalent to the spec's
  `OR (state='signed' AND tx_hash=?)`, provided P3 callers compare the hash. Any `Db` error becomes `Unknown`, which
  is conservative and also covers BUSY before commit.
- **Seq counters.** They are incremented in the same transaction as the row and rolled back with it (including the
  accept unique-violation path). With one writer, commit order equals seq order. Reopen keeps them (tested). There
  is no AUTOINCREMENT.
- **`journal_max`.** It is updated with `MAX(COALESCE(j, n), n)` in the journal transaction and in the fenced
  `bump_journal_max`. Writers are serialized (IMMEDIATE plus pool = 1), so it is monotonic. A requeue keeps it.
- **Live-digest index.** The partial index matches the spec. No transition goes from terminal back to live, so
  re-entry never collides.
- **Constraint classifier.** The column lists `job.chain_key, job.digest` and `…, job.generation` are unambiguous,
  and the PK gives `None` (tested). It cannot misclassify with the current DDL. A future unique index ending in the
  same columns would, so keep the classifier test as the guard.
- **Pragmas.** WAL, `synchronous = FULL`, `busy_timeout` 5 s, STRICT on every table, `max_connections(1)`, all as
  A1.2. Bundled SQLite supports RETURNING and STRICT.
- **R95 secrets.** No `rpc_urls`, keys, `master_key`, identity key or store url reach the store. Lane labels are
  public addresses. Bootstrap audit `after` is a non-secret row. Spec ambiguity to raise with the owner (not a P1
  bug): `mesh_peer.url` is a dial target in an admin-editable table, which conflicts with R95's "dial targets
  toml-only / no admin-API SSRF". Either keep peer url toml-only, or put the T1 SSRF checks on the P2 admin route.
- **EVM lowercase.** Lane labels (`address_hex`), `fee_recipient`, `dex` and EVM tokens all use lowercase `{:#x}`,
  consistent with the gateway, mesh digest, indexer and Odoo `parse_address`. The exceptions are policy (F2) and
  non-EVM families (F9).
- **unwrap/expect outside tests.** Only `default_from_empty_table`'s `expect`, which is sound because every field has
  a serde default and the defaults tests exercise it.

## Implementer's listed deviations

| Deviation | Opinion |
|---|---|
| Store requires `[store]` (no default url) | **Agree.** A default path makes F5 worse. Pair it with F5 (no implicit create). Note in the upgrade notes that every existing `node.toml` needs the section, and that two nodes on one host need two urls. |
| `[odoo]` is `Option`, but required for the legacy roles | **Agree.** It matches R104 and is checked in both `validate` (`config.rs:542`) and `legacy()`. |
| `modes = ["oidc"]` refused until P2b | **Agree.** It fails closed, as §3 requires (no issuer ⇒ refuse). |
| Tombstone `chain_key = ''` | **Agree.** Cancel-by-origin carries no chain, and `NOT NULL` keeps indexes simple. P2 must render it as `chain_key: null` in snapshots and feed items, and FKs (F11) must skip `job.chain_key`. |
| Audit actor as `actor_kind` + `iss` + `sub` instead of an `actor` string | **Agree.** It is the spec's own §4 DDL. The R110 strings (`user:<name>`, `oidc:<iss>\|<sub>`, `cli:<uid>`) are a rendering of those columns. Keep `bootstrap` as its own kind. |
| A broken audit chain only logs at start | **Agree.** The spec asks only for logging plus the head metric. Refusing to start would let anyone with DB write access stop the node, without protecting anything. Add `scaas_audit_chain_ok` / `scaas_audit_head_info` in P2b, and a `/readyz` reason. New rows chain on, so the break stays pinned at its seq. |
| `bus_scope` includes `public` | **Agree.** Gossip §8.4 / R99 amends NI §4. |
