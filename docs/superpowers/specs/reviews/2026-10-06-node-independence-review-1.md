# Adversarial review 1: node-independence spec (R87–R111)

Spec: `scaas/docs/superpowers/specs/2026-10-06-node-independence-design.md`, rev 1 + Amendment A1.
Code checked: `scaas/bamboo-node/src/{submit,adapter,odoo,gateway,gwauth,indexer,drift,admin,config,main,nonce}.rs`;
`dms_blockchain/models/{blockchain_relay_job,blockchain_chain,blockchain_chain_event,blockchain_subject_account}.py`;
`dms_blockchain_payment/models/blockchain_autopay.py`; `dms_blockchain_dex/models/{dex_order,dex_trade,relay_job}.py`.
Read-only: nothing built, nothing modified.

## Verdict: FIX-THEN-GO

The direction holds, and most file:line claims are accurate (§6 below). The weak points are the **push protocol
edges** (a rollback after the node accepted, cancel, restore), the **A1 network-DB semantics** (commit outcome unknown,
lock is not a fence, MySQL collation, nonce encoding) and **trusting client-supplied fields** now that the API is
multi-tenant. Every fix is a spec edit. P3/P5 must not start until C1 and H1–H9 are resolved in the text.

---

## Critical

### C1. A rollback after the node accepted leaves the node holding a job that Odoo treats as unsent. The kill switch then fails, and the job's states are lost (§10.3, §10.4, §10.5)

**Problem.** §10.3 says it outright: "If the cron transaction rolls back after the node accepted, the next run gets
`created: false` and the same `uid`." Until that next run, the Odoo row is `push_state='local'`, and every local
decision assumes `local` means "the node doesn't have it":

1. `_node_cancel` (`push_state == 'local'` ⇒ "today's local `dead`") is what `_cancel_unsent`
   (`blockchain_autopay.py:80-99`) calls. The policy is killed, the run's request is expired and its transaction is
   cancelled, but the node still has the job `queued` and will sign it. Today's veto ("node cannot journal `signed`
   for a `dead` job", §1.1) is gone, so **a payment goes out after the kill switch reported it stopped**.
2. When the next push does happen, `_apply_push_result` stores `node_job_uid`. The node may already have emitted
   `leased/signed/broadcast` for that uid, and `_apply_node_event` dropped them (`if not job ... return`). Those items
   are now behind the cursor. The `overlap = 200` only helps if the re-push lands within 200 seqs. After that, the
   next item (`broadcast`/`mined`) hits `_apply_report` from `queued`. `TRANSITIONS` has no `queued` key
   (`blockchain_relay_job.py:20-25`), so it raises `UserError`, which is treated as poison and skipped. The job stays
   `queued` in Odoo forever. A `call` job (revokeWithSig, deploy, mandate pay) has no indexed event to rescue it via
   `_mark_final`, and RS4-6 dependents (`blockchain_subject_account.py:451-455`) never unblock.
3. A node-side `dead` (expiry, bad payload) for an unknown uid is dropped. `_cron_expire` skips `sent` jobs (§10.5),
   so a job that was re-pushed late never fails and never calls `_fail_dependents`.

**Fix.**
- **Adopt by origin.** Feed items already carry `origin` and `client_ref`. `_apply_node_event` looks up
  `(node, uid)`. If that misses, it looks up `(company from scope, producer, key)` with
  `generation == push_generation`, adopts the uid and sets `push_state='sent'`. It applies states as a
  **snapshot**: Odoo `queued` + item `signed` means apply the implied `nonce_leased` first. A
  `node_feed_transitions` table extends `TRANSITIONS` with `queued → {nonce_leased, dead, consumed, signed}` for
  feed use only.
- **The accept result carries the job's current `state` and `last_seq`.** On `created: false`,
  `_apply_push_result` applies that snapshot instead of assuming `queued`.
- **Cancel by origin.** Add `POST /v1/jobs/cancel {origin}`. It cancels a live job, or writes a `cancelled`
  **tombstone** under the idempotency tuple, so a later push of that key returns `created:false, state:cancelled`.
  `_node_cancel` on a `push` chain always goes to the node, except for a row that provably was never sent. Record
  `push_attempted` in its own committed cursor before the HTTP call. Only `push_attempted = False` may be killed
  locally.

---

## High

### H1. Cancel says `cancelled` for a job that was already published on the mesh bus (§2 R98, §13.1 R73)

**Problem.** Under amended R73 the node publishes `bus_scope=open` jobs that are still `queued` after
`private_window_secs`. Peers then hold the signed intent. A cancel `queued → cancelled` succeeds on our store, and Odoo
expires the request and cancels the transaction. A peer can still land the intent, and it does: MESH R74 says "after
`until` any admitted peer may submit". R98's guarantee ("one wins") only covers our own lanes.

**Fix.** A job that has been published reports `409 TOO_LATE` with `published: true` (or a distinct `PUBLISHED`)
and is cancelled locally only, so we don't lease it. Odoo treats that like `signed` ("already released, cannot be
recalled") and keeps the request open until it is `final` or expired. Add `published_at` to `job`. Test the case in
§16.4.

### H2. A store restore (same `store_id`, older contents) goes undetected and silently drops feed items (§2 R110, §5.3)

**Problem.** R110 only fires when `store_id` *changes*. A file or PG/MySQL point-in-time restore keeps `store_id`
and rewinds `seq`. New `job_event`/`feed_item` rows reuse seq values ≤ Odoo's cursor, and Odoo skips them twice:
first with `seq > cursor`, then with `item['seq'] <= job.node_event_seq`. Jobs that were signed after the backup no
longer exist on the node, but Odoo has them `sent`, so they hang. If Odoo re-pushes them, the node re-signs them.
G1 keeps the funds safe, but the gas is lost and the states are wrong.

**Fix.** Every page and `/v1/info` returns `head_seq` for both feeds. In Odoo, `head_seq < stored cursor` triggers
the same halt as a `store_id` change (`needs_attention`). In the node, `store_id` becomes `store_id` + `incarnation`:
a random value written at every open, and also at `bamboo-node store restored` (a CLI command the runbook makes
mandatory after a restore). Odoo treats an incarnation change with a lower head as a store change. Document that a
restore requires the R110 operator step.

### H3. The journal transition is binary (ok/false). That is wrong in two ways that matter for money (§9.1 row "report → transition", A1 "Transactions")

**Problem (a): CAS miss vs I/O error.** The spec keeps "returns `false` on CAS miss or I/O error exactly where
`report()` returned `false`". In the EVM `Submitter`, `false` on `signed` means `self.retry.push_back((w, guard))`
(`submit.rs:311-314`). `drain_retry` → `send` re-simulates, re-signs and CAS-misses again, forever
(`submit.rs:386-392`). Meanwhile it holds the G2 digest guard, so no other path can take that digest. With R98 a
cancel `leased → cancelled` is a normal event, not an edge case. The same loop exists today with the Odoo veto, but
it becomes common now.

**Problem (b): commit outcome unknown (PG/MySQL).** A connection drop after `COMMIT` was sent leaves the
`leased → signed` row committed while the node sees an error. The node then retries: same nonce (`self.next` not
bumped, `submit.rs:315`), new fees, so a new hash. The CAS misses (the row is already `signed`) and the node loops as
in (a). The next job takes nonce N too and journals it. Now two jobs are journaled at N, and one is "signed" with
bytes that were never sent. After a restart `plan()` tracks a phantom. "A serialization failure retries the step,
never skips it" (A1) does not cover this case.

**Fix.** `transition()` returns `Ok | Moved(current_state, current_tx_hash) | Unknown(err)`.
- `Moved` ⇒ drop the work and release the guard. If the current state is `signed` with **our** hash (an idempotent
  retry), proceed to `send_raw`.
- `Unknown` ⇒ reconnect and re-read the row before deciding. The journal CAS is
  `WHERE uid=? AND (state='leased' OR (state='signed' AND tx_hash=?))`.
- Non-EVM `step_once` (`adapter.rs:419-423`) uses the same tri-state, so a cancel does not cost a 60 s backoff.
- Add both cases to the store contract suite on all three backends.

### H4. The PG/MySQL owner lock does not fence anything (A1 "Single owner")

**Problem.** "The session, not a TTL, is the fence" is not true. `pg_try_advisory_lock` and `GET_LOCK` live on a
*dedicated* connection, while journal writes go through other pool connections. When the lock session drops, the
server releases the lock straight away. The node only notices on its next use of that connection (TCP keepalive,
minutes). In that window a second process can take the lock, both write, and both broadcast with in-memory
nonce counters. PgBouncer in transaction mode makes session advisory locks meaningless. This stack runs PgBouncer
(`/home/dockers/odoo19/pgbouncer`; Odoo needs `session`, but the node could be pointed through it by mistake).

**Fix.**
- Add a **fencing epoch**: `store_owner(epoch BIGINT)`, incremented when the lock is taken. Every journal transaction
  runs `UPDATE store_owner SET epoch = epoch WHERE epoch = :mine` (or a `SELECT … FOR UPDATE` check) and aborts on 0
  rows. A stale owner then cannot journal, and therefore cannot broadcast (journal-before-broadcast).
- Poll the lock connection every ≤ 2 s.
- Refuse to start when `SHOW pool_mode` answers (PgBouncer) or when `pg_backend_pid()` changes between two calls on
  the lock connection.
- Use `hashtextextended` (64-bit), or derive the int8 from the `store_id` bytes, instead of the 32-bit internal
  `hashtext`.

### H5. MySQL's default collation is case-insensitive, and the schema keys are `TEXT` (A1 "Schema portability")

**Problem.** `utf8mb4_0900_ai_ci` compares `'0xAB' = '0xab'` and ignores accents. That corrupts:
- idempotency (`origin_key`, R91): a different payload under a case-variant key gives `IDEMPOTENCY_MISMATCH`, or the
  wrong existing job is returned;
- base58 Solana tx ids and addresses (case-sensitive, `blockchain_chain.py:208-210`);
- Soroban strkeys;
- `namespace` uniqueness.

Separately, MySQL cannot index or primary-key a `TEXT` column without a prefix length, so §4 does not even create on
MySQL. `GLOB` (SQLite), `AUTOINCREMENT` (SQLite) and partial indexes (SQLite/PG) are not portable either, and MySQL
`INSERT … ON DUPLICATE KEY`/`IGNORE` cannot target one unique index. A `job_live_digest` conflict would be read as an
idempotency hit.

**Fix.**
- Declare the DDL per backend with `VARBINARY`/`utf8mb4_bin` (MySQL) and `COLLATE "C"`-equivalent semantics for every
  key or hash column. Prefer `BLOB`/`bytea`/`VARBINARY` for hashes and digests.
- The contract suite asserts `'0xAB' != '0xab'` on all backends.
- Accept is `SELECT … FOR UPDATE` by the idempotency tuple, then `INSERT`. Unique violations are classified by
  constraint name per backend, and deadlocks (1213/40001) are retried.

### H6. Nonces "as decimal TEXT beyond 2^63, as the journal already does" is wrong, and it breaks `max()` (A1, §9.1)

**Problem.** The journal does not do that. Odoo's `outer_nonce` is `int8` (`blockchain_relay_job.py:34-36, 70`), and
the node uses `u64`. If any backend stores `outer_nonce` as TEXT, `max(outer_nonce)` becomes lexicographic
(`'9' > '10'`). `journal_max` then goes backwards and `plan()` reuses a nonce (`nonce.rs:23-33`). Separately,
`journal_max = max(journal_floor, max(job.outer_nonce))` depends on job rows the janitor purges after 30 d (§4).

**Fix.**
- `outer_nonce BIGINT` everywhere. Refuse values > i64::MAX at the adapter boundary: every family fits (EVM nonce,
  Cosmos/Aptos sequence, Stellar `ledger<<32` is itself i64, TON u32).
- Keep a monotonic **`lane.journal_max`** column, updated `= max(journal_max, n)` in the *same* transaction as
  `leased → signed`. `plan()` reads that column, never an aggregate over purgeable rows.
- The transitional legacy path bumps it on every successful legacy `relay_report('signed')`. That makes `journal_floor`
  exact instead of "the last `node_config` read" (see M7).

### H7. The client-supplied `digest` drives durable G2 and the in-memory set. Cross-tenant squatting and G2 bypass follow (§2 R89, §5.2 accept checks)

**Problem.** `job_digest()` reads `job.digest` / `op.digest` straight from the payload (`submit.rs:93-96`;
`odoo.rs:96`). On a multi-tenant API (R90), namespace B can push jobs with garbage payloads whose `digest` equals A's
pending intents (visible on the mesh, the gateway or the mempool). A then gets `409 DUPLICATE_DIGEST`, and Odoo keeps
it `local` (§10.3). B can repeat this with fresh origin keys. A wrong digest in the other direction defeats durable
G2: two live jobs for one intent produce double outer txs. G1 still protects the funds, but each one costs gas.

**Fix.** At accept, the node **derives** the digest (intent_id, MESH §4.4) from the decoded payload, using the S3
pure library with vectors. A client `digest` that differs ⇒ `422 BAD_PAYLOAD`. Move S3 before P2 in §17.
`job.digest` is always node-computed.

### H8. `IDEMPOTENCY_MISMATCH` is treated as a permanent `dead`, and "canonical JSON" is undefined (§5.2 step 7-8, §10.3)

**Problem.** A mismatch means "the node already holds a job under this key". It may be live, signed or broadcast.
Marking the Odoo row `dead`/`failed` and calling `_fail_dependents()` contradicts reality. A later `mined` from the
feed then hits `dead → mined`, which is not in `TRANSITIONS`, so it is skipped as poison.

The likely trigger is benign. A module upgrade changes `_payload()`: a new key, `extra_json` ordering, int vs str.
Then a re-push after a rollback (C1) hashes differently. The spec never says what "canonical" means, or whether the
hash is over the raw bytes or the parsed value.

**Fix.**
- `payload_hash` = SHA-256 of **RFC 8785 (JCS)** over the parsed `payload` object, computed by the node, with a
  shared KAT in `tests/api/`.
- `IDEMPOTENCY_MISMATCH` (and `PREVIOUS_GENERATION_LIVE`, which is currently unhandled in `_apply_push_result`) ⇒
  the row stays `sent`-pending with `needs_attention`. Odoo fetches `GET /v1/jobs/{uid}`, and the 409 body must carry
  that `uid`. Never mark it `dead` locally.

### H9. Token registry divergence (node `token` table vs Odoo `token_ids`) stalls payment booking (§2 R95, §6, §10.4)

**Problem.** Tokens become node config managed through the admin API. A namespace's token subset is "empty = every
registered token". `_ingest_range` reuses `_decode`, which raises `UserError("Event from an unregistered contract")`
(`blockchain_chain_event.py:110-112`). One token added on the node but not in Odoo is enough: every range carrying
its events raises, and §10.4 has no poison rule for ranges. The result is a stall, or, if the range is skipped, a gap
and then `needs_attention`. The reverse case (a token in Odoo but missing on the node) is silent: it is never indexed
and its payments never reach `final`.

**Fix.**
- `_ingest_range` **drops** events from contracts that are not Odoo tokens, with a counter and a log line. It does
  not raise.
- The sync cron pushes Odoo's active token list as the namespace token subset (`PUT /v1/watch` already exists; add
  `PUT /v1/tokens/{chain}` scoped to the namespace, intersected with the node's registry).
- `action_switch_to_push` precondition: Odoo's active tokens ⊆ `GET /v1/info` tokens for the chain.

### H10. A copy of the Odoo database pushes real jobs to the production node (§10.1, §14 T3)

**Problem.** This risk is new with the inversion. Today a staging copy of a production database is inert, because
the node only pulls from the database it is configured for. After inversion, a pg_dump/restore copy keeps
`database.uuid` and `ir.config_parameter` `dms_blockchain.node_secret.<id>`. Its crons (autopay with custodial
keys, deploy jobs) will **push to the prod node with the prod key**. New origin keys create new jobs, which are
signed and executed on chain.

**Fix.**
- Add `dms_blockchain/data/neutralize.sql` (Odoo 19 supports it; see `addons/mail/data/neutralize.sql`). It deletes
  `dms_blockchain.node_secret.%` and sets every chain to `pull`.
- `blockchain.node` stores the `database.uuid` and the `web.base.url` it was configured under. Push refuses when
  either changed (`needs_attention`).
- §14 gets a new row, T18.

---

## Medium

### M1. Cancel during a node outage weakens the kill switch (§2 R98, §10.5)

`cancel_requested` waits for the next sync. When the node comes back, its lanes lease immediately, so a killed
autopay run can be signed before the retry arrives. Today the veto is immediate. The window is bounded by
`valid_until` (`MAX_SIGNING_WINDOW = 300`, `blockchain_autopay.py:12`). **Fix:** document the window in R98's
"cost". The sync cron retries `cancel_requested` **first** (step 0, not step 4). Optional: a node
`lease_hold_after_start_secs` (default 15) for namespaces with `submit` keys.

### M2. The push cron holds `FOR UPDATE` row locks across HTTP (§10.3)

The cron can make up to 4 batches × 30 s per route while holding locks on up to 200 jobs. `_cancel_unsent`, payment
flows and `_fail_dependents` block on those rows, then hit REPEATABLE READ serialization failures. **Fix:** one
batch per transaction (lock ≤ 50, POST, apply, commit). The SQL lock re-checks
`chain_state='queued' AND push_state='local'`, as `relay_claim` does (`blockchain_relay_job.py:130-132`). The
pseudo-code `groupby(...)[:50]` is also invalid (unsorted input, slicing an iterator).

### M3. Long-poll in an Odoo cron ties up a cron worker. Events have no base schedule (§10.4, R101)

`wait=10` per node per page, re-triggered every 10 s, keeps one of the default 2 cron threads busy permanently,
starving the mail queue, autopay and expiry. It buys nothing: latency is already bounded by the 10 s re-trigger.
Re-triggering "only if a pushed job is non-terminal" also starves the **events** feed when no job is live
(payer-submitted txs, Transfers for drift A). **Fix:** Odoo uses `wait=0`. The sync cron gets a fixed interval
(e.g. 1 min) plus the `_trigger` re-trigger. Keep `wait` for other clients.

### M4. `blockchain.node` server-only fields are only `readonly` (§10.1)

`group_blockchain_manager` has write access (§10.8), so it can RPC-write `store_id`, `jobs_cursor`,
`events_cursor` and `needs_attention`. That clears the R110 halt, or skips feed items. **Fix:** the same
`SERVER_ONLY` create-force / write-strip-unless-`su` as `blockchain_relay_job.py:79-86`, plus
`action_acknowledge_store_change()` (group system, audited in chatter) as the only way to accept a new `store_id`.
Also, `jobs_cursor = fields.Integer  # int8` contradicts itself: use `BigInteger`.

### M5. Feed application: missing late no-ops, duplicated side effects (§10.4 `_apply_node_event`)

- A `mined`/`broadcast` that arrives after `final` (events applied first, or 410 recovery) raises `UserError`. Each one
  writes a `last_error` to a successful job. Add `final: {*}` to a feed-side `LATE_NOOP`.
- The explicit `dead` branch (`{...dead/failed...}`) duplicates and risks missing `_apply_report`'s
  metatx/signed_op `failed` writes (`blockchain_relay_job.py:226-231`). Route it through the same table as C1's
  `node_feed_transitions` and let `_apply_report` own the side effects.

### M6. DEX mirrors need a seq guard (§12.2)

Overlap re-delivers older `dex_order` items. `_upsert` regresses `remaining_sell`, or raises on a terminal order
(`dex_order.py:116-121`). Neither the spec nor the code defines poison handling for `dex_*` items. **Fix:** a
server-only `node_seq` on `blockchain.dex.order/trade`; skip `item.seq <= node_seq`; terminal re-delivery is a no-op.
(`_book_fees` is already idempotent via `move_ids`, `dex_trade.py:207`.)

### M7. Transitional nonce continuity rests on a stale `journal_floor` (§9.2, §11.2 precondition 3, R104)

The floor is "imported from every legacy `node_config` it reads". Legacy jobs signed after the last read have higher
nonces. Today `Submitter::start` fails closed when Odoo is unreachable (`submit.rs:148-150` `?`). The spec must keep
that while any legacy job may be live on the lane. "Union if available" would reuse nonces. **Fix:** H6's
`lane.journal_max` is bumped on every legacy `signed` report. Start refuses (it does not degrade) when the legacy
journal is unreachable and the chain has ever been `pull`.

### M8. A company without a route silently stalls on a `push` chain (§10.3, §11.2 precondition 1)

The precondition only covers companies with non-terminal jobs at switch time. A company that creates its first job
later stays `local` with `last_error` until expiry. **Fix:** `blockchain.relay.job.create` raises `UserError` for a
push chain with no route for the company. The precondition also covers every company with an approved
receiving or paying wallet on the chain.

### M9. Changing a lane through the admin API orphans live jobs (§7.3 `PUT …/lanes`)

Removing an account index whose lane has `leased/signed/broadcast` rows leaves them untracked after the restart.
They also keep holding `job_live_digest`. **Fix:** `409` when the lane has live rows; the operator drains first.

### M10. A1 contradicts the base spec in several places

- §4 uses `AUTOINCREMENT` for `seq`/`uid`, while A1 says "explicit counter row".
- §4 has "forward-only `user_version`", while A1 has `sqlx::migrate!`.
- R88 (`locking_mode = EXCLUSIVE`, one connection) conflicts with a sqlx pool: >1 connection gets `SQLITE_BUSY` forever.
- `BEGIN IMMEDIATE` needs sqlx `begin_with`.

**Fix:** one normative schema table per backend (types, collations, the partial-index emulation, the counter row) and
`max_connections = 1` for SQLite. A1 §"Tests" adds a DDL-equivalence test.

### M11. OIDC validation details (§7.1)

- `role_claim = "scope"` for interactive users grants the role to **every** user the public app is allowed to request
  that scope for. Scopes are client permissions, not user roles. Allow `scope` mapping only for tokens without a user
  (`client_credentials`: `sub == client_id`, or a configured `machine_only = true`).
- Lifetime cap only "when `iat` is present": a token without `iat` bypasses it. Require `iat`.
- The JWKS cache key must be `(iss, kid)`, not `kid`. If a JWK carries `alg`, it must equal the header `alg`.
- Refuse a config where `audience ∈ client_ids` (ID-token substitution). Optionally require `typ = at+jwt`
  (RFC 9068) per issuer.
- reqwest follows up to 10 redirects by default. Discovery/JWKS clients must set `redirect::Policy::none()`.
  `jwks_uri` host equality is exact, including scheme and port.

### M12. Stream sequencing (§17, A1)

P2b (OIDC) sits before P3, but nothing in P3–P6 needs it: bootstrap works over the socket (R108). A1 folds three
backends into P1, the first stream, with the first sqlx build × 3 drivers under the OOM cap. **Fix:** S3 → P1
(SQLite) → P2 → P3 → P4 → P5 → P6 → P2b → P1b (PG, MySQL contract suite) → cutover on those backends.
This changes the order only; the owner rulings stand.

---

## Low

- **L1 Break-glass (§7.2).** `umask` is process-wide and racy in a multi-threaded tokio runtime. Bind, then `chmod
  0600`, inside a `0700` directory owned by the service user. Also check the `SO_PEERCRED` uid ∈ {service uid, 0}.
  File mode alone shouldn't be the only control.
- **L2 Audit integrity (§7.5).** Anyone with store access can rewrite it. Add a `prev_hash` chain
  (`sha256(prev ‖ row)`) and export the head to logs/metrics. That is a few lines.
- **L3 Revoked keys come back after a restore.** Secrets are derivable, so restoring a backup that predates a revoke
  re-enables the key. Doc: rotate `master_key` or re-revoke after a restore (ties into H2's incarnation).
- **L4.** `api_key.last_used_at` is written on every request, which means a store write per GET. Keep it in memory
  and flush every 60 s.
- **L5 §9.4 heuristic.** Applies only to sequence families (EVM, Cosmos, Aptos, Soroban, TON). Solana and Sui have no
  lane nonce. Say so.
- **L6 `gwauth.rs:23`.** `MAX_BODY = 64 KiB` while the job API allows 1 MiB. Parameterise per listener.
- **L7 §10.8.** Managers have create ACL on `blockchain.node`, but required `url`/`key_id` are `groups=base.group_system`,
  so a manager create always fails. Make the ACL match the intent.
- **L8 §11.2.** State whether the store indexer runs for `pull` chains in the transitional binary. If not, its cursor
  is stale at the switch. The straddle rule makes that harmless, but the e2e should cover it.
- **L9 Watch latency (§10.4 step 3).** A newly approved receiving wallet reaches the node ≥ 1 sync later. Transfers in
  that gap are not indexed, so drift A shows false negatives. Doc, or push the watch list in the same run as the
  approval (`_trigger`).
- **L10.** `plan()` matches the literal `"nonce_leased"` (`nonce.rs:28`), while the store uses `leased`. Map the
  string at the `store.inflight` boundary.

---

## Over-engineering for v1 (ponytail)

- Long-poll for Odoo (M3): drop it on the Odoo side.
- `namespace_token` as an independent admin-managed subset: keep it only as Odoo-pushed state (H9). Otherwise YAGNI
  until a second tenant exists.
- Multi-issuer OIDC is cheap and fine. Per-issuer `client_ids`/`azp` are fine too.
- `cursor_overlap` on a single commit-ordered writer is a harmless belt. Don't add more machinery around it.
- Three DB backends: owner ruling. Sequence them late (M12), not first.

---

## Claims verified against code (accurate unless noted)

`odoo.rs:91-108` Job (`id` at :92), `:190-206` poll/claim/report; `submit.rs:146-190` start, `:244-261` report,
`:308-316` journal-before-send (retry at :313), `:540-568` poll_outbox, `:571-583` run loop; `adapter.rs:151-159`,
`:232-248` recover_lane, `:263-341` follow, `:396-410`, `:419-423` journal, `:443-458` index_step (M1 at :450-453);
`gateway.rs:129-137`, `:179-188`; `gwauth.rs:5-8, 25-26, 74-117`, nonce cache `:108-116`; `indexer.rs:81-82,
106-117` (finality :113); `drift.rs:30-50`; `admin.rs:125-153`; `config.rs:11-19, 29-34, 51-52`; `main.rs:103,117,
131-167, 139-153, 181-186`; `nonce.rs:23-33`. Odoo: `blockchain_relay_job.py:20-29, 79-86, 99-101, 105-138,
160-187, 189-204, 206-247, 249-261, 263-291`; `blockchain_chain.py:13-25, 163-197, 189-196, 215-219, 223-254`;
`blockchain_chain_event.py:20-27, 78-103, 86-88, 106-137`; `blockchain_autopay.py:80-99, 101-113`;
`blockchain_subject_account.py:451-460`; `dex_order.py:65-104, 106-141, 144-152`; `dex_trade.py:203`;
`dms_blockchain_dex/models/relay_job.py:10-16`; `blockchain_security.xml:61`.

**Inaccurate or misleading:**
- A1 "uint64 as decimal text, as the journal already does": false (H6).
- R102 cites `main.rs:181-186` as evidence that bound jobs go to any lane. Those lines are the DEX single-lane `bail!`,
  i.e. the workaround, not the bug.
- §10.1's `jobs_cursor` comment says int8, but the type is int4 (M4).
- Today gateway door-A work is **not** journaled (`job_id: None`, `gateway.rs:149`; `submit.rs:309` only journals
  `Some(id)`). The spec's move to `~gateway` jobs fixes this and should say so as a safety gain.
