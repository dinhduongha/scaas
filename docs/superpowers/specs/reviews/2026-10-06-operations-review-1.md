# Review 1 — Operations spec C (rev 1.1, R230–R247)

Reviewer: adversarial design review, read-only. Inputs: `2026-10-06-operations-design.md` rev 1.1; NI rev 3.3 (§2, §4,
§5, §7.3, §9, §10.4–10.5, §14, §15, A1); MESH §12; gossip §13 routes; TSS R195/§C.4 and sponsorship routes; TW2 §10.2;
AS §3.3–3.5; code `admin.rs`, `breaker.rs`, `nonce.rs`, `submit.rs:146-190`, `main.rs:40-62`, `store/sqlite.rs:84-125,
449-477`; Odoo producers of `call` jobs; `MandateWallet.sol`. Owner rulings (OA numbers, internal SLOs, operator
independence, operator-chosen denylist) not re-litigated.

## Verdict: **FIX-THEN-GO**

The structure is sound and most runbook commands exist. Four procedure/alert defects must be fixed in the spec before
OP1/OP5/OP6 start: a restore lets the node execute jobs that were cancelled after the backup point (H1); `lane
accept-nonce` can lower `journal_max` and leaves the nonces it adopts unmonitored (H2); several P1 alerts can never
fire (H3); and two latches the spec calls "manual" are lost on restart (H4). Each fix is a few lines of spec. Nothing
needs redesign.

Verified OK (no finding): `store restored` already moves the fencing epoch past any pre-restore owner
(`sqlite.rs:475` `MAX(epoch + 1, now_ms)`), so a zombie can't share an epoch with the post-restore owner. CLI
`addresses`, `store init|restored`, `key create|revoke`, `admin disable` exist or are specified (R108). The gossip
routes (A2 §13) and sponsorship routes (TSS) used by RB-14/RB-17 exist. The denylist never auto-cancels signed or held
jobs, which matches R245. Existing names and labels in `admin.rs` (`scaas_breaker_open{chain,lane,breaker}`,
`scaas_relayer_balance{chain,lane}`, `scaas_indexer_lag_blocks{chain}`) match §4.2.

---

## High

### H1 — Restore starts leasing before anyone reconciles: post-backup cancels, denylist entries and delistings are undone (§2 R240, §11.2, §11.3, RB-08)

**Problem.** The R240 sequence is: stop → restore → `store restored` → re-revoke → **start** → accept-nonce → clients
acknowledge. A restored store holds as `queued` (hold = 0) every job that a client cancelled or killed after the
backup point. Once started, the node leases those jobs after `lease_hold_after_start_secs` (15 s). The client can't
re-cancel them in that window, because R110 has halted it (`needs_attention`) until a human acknowledges. Also,
`action_acknowledge_store_change` (NI §10.1) only marks Odoo's *non-terminal* jobs for re-push. It sends no cancel for
jobs that Odoo holds as `dead`/cancelled but that the node has as `queued`. `max_valid_for_secs = 3600` (MESH R82) is
longer than the 30-min RTO (§11.1), so a payment the customer stopped (for example autopay "kill switch",
`blockchain_autopay.py:80-99`) can execute after the restore. Odoo's `FEED_LATE_NOOP` for `dead` then hides the
`mined`, so money moves while the ERP books nothing.

The same gap applies to security configuration changed after the backup point. §11.2 says "audit log events ⇒
re-apply", but §11.3 has no such step before `systemctl start`. Examples:
- a denylist entry added under a regulator order (R246) is served again;
- a token removed in RB-12 because of a malicious upgrade is relayed again;
- a chain halted in RB-06 resumes;
- a reverted `fee_recipient` (RB-10) returns.

**Evidence.** NI R98 (15 s hold, "cancels retried first" assumes a live client); NI §10.1
`action_acknowledge_store_change` "marks this node's non-terminal pushed jobs `push_state = 'local'`"; ops §11.3 runs
`systemctl start` right after re-revoke.

**Fix.**
1. `store restored` also sets every `chain.state` to `paused`, in the same transaction and audited. Paused chains still
   accept, index and track; they don't lease (R53).
2. Add step 3b to §11.3: re-apply the security-relevant mutations newer than the backup point from the off-host audit
   events (deny add/lift, token delete, chain state, fee_recipient, namespace suspend, peer bans) through the admin
   API while the chains are paused.
3. Client acknowledgement (NI §10.1, P5) must also POST `cancel {origin}` for every job the client holds as
   dead/cancelled whose node snapshot is live. Only after that does the node operator resume each chain.
4. Add "chains resumed by NO after EA ack" to the RACI row "Store restore".

### H2 — `lane accept-nonce` can break `journal_max` monotonicity, and the nonces it adopts are invisible (§2 R241, RB-04 step 3, §3.1 head-stuck, RB-03)

**Problems.**
- (a) R241 says it "sets `lane.journal_max` to `pending − 1`". If an operator runs it on a lane that is not foreign
  (journal ahead of the chain after drops, which is normal), this *lowers* `journal_max`. That violates the NI §4 rule
  "monotonic: max(journal_max, n)". The journaled nonces in `[pending, journal_max]` are then neither gap-filled nor
  tracked: `plan()` requeues their jobs and re-uses the nonces while the old signed txs may still sit at one endpoint.
- (b) "reads … from every RPC (quorum must agree)" is ambiguous. If a quorum agrees on a lower `pending` than a
  minority endpoint that still holds a lost-period tx, the node signs over that nonce and creates a conflicting tx.
- (c) The nonces it adopts in `[latest, pending)` have no journal row. `scaas_lane_head_stuck_seconds` is defined
  over "the lowest unmined **journaled** nonce" (§4.3), so it reads 0 while an underpriced adopted tx blocks the lane.
  The node can't bump that tx either (it has no bytes). It is gap-filled only "at the next cold start if dropped", and
  a tx that is underpriced but not dropped is never handled. ScaasLaneHeadStuck/Hard stay silent; only W3B burn
  eventually fires, routed to RB-03, which has no step for this case.
- (d) RB-04 step 3 "explained by a restore … and no other user of the key" gives the operator no evidence to decide.
- (e) R241 covers sequence families only. §11.2 has no restore procedure for Sui (gas-object versions in the restored
  journal; RB-03 step 4 "re-sends the journaled bytes" against stale versions risks owned-object equivocation, which
  locks the gas coin until the epoch ends) or Solana (durable-nonce value).

**Fix.**
- Refuse unless `pending − 1 > lane.journal_max`.
- Read `latest` and `pending` from **all** endpoints, require every endpoint to answer, and use the maximum `pending`.
- Define `pending` per family (it equals the committed sequence on Cosmos, Aptos, Soroban and TON).
- Print every adopted nonce `[journal_max+1, pending)` with its tx hash, its `to`, and whether its meta-tx digest
  matches a job in the restored store. An unmatched nonce is a second user, so RB-04 step 2 applies.
- Redefine head-stuck as "seconds since `nonce_at(latest)` last advanced while `latest ≤ journal_max`". This covers
  both journaled and adopted nonces.
- Add an RB-03 step for the adopted-head case: a journaled, bumped gap-filler at that nonce.
- Add one line for Sui/Solana: re-read gas objects / the nonce account at start, never re-send journaled bytes after
  `store restored`.

### H3 — P1 alerts on conditions detected at start (or exported lazily) can never fire (§5.1 `ScaasLaneForeignNonce`, `ScaasAuditChainBroken`, `ScaasFinalityMismatch`, `ScaasFencingLost`)

**Problem.** NI §9.4 detects a foreign nonce **at lane start**, and R242(b) verifies the audit chain **at start**. Both
are exported as counters. If the renderer creates a label set only when the counter is first incremented (natural for
`{chain,lane}`), Prometheus first sees the series at value 1. `increase()`/`rate()` need two samples, so they return 0
and the alert never fires. The common case for both conditions is a restart, which resets the counter, so the most
important occurrence is the one that is lost. `ScaasLaneForeignNonce` is the alert that RB-08/H2 depend on. Today only
`ScaasNotReady` (5 min, generic) would catch it, and an audit break doesn't affect readiness at all.

**Evidence.** §4.3 types; NI §15 `scaas_lane_foreign_nonce_total` counter `{chain,lane}`; `admin.rs` renders families
only from the readings present.

**Fix.**
- Export *states* as latched gauges and alert on `== 1`, as already done for `scaas_watch_code_hash_changed`:
  `scaas_lane_foreign_nonce{chain,lane}`, `scaas_audit_chain_ok` (0/1), `scaas_indexer_finality_violated{chain}`.
- Add a renderer rule: every counter is emitted at 0 for every configured label set from process start. Extend the
  golden test to check it.
- Add `readyz` reason `audit chain broken`.

### H4 — The two "manual reset" latches are in memory and are lost on restart (§2 R233 `revert_streak`, R242(a) indexer hold)

**Problem.**
- R233 makes `revert_streak` a breaker with "manual reset". Breakers are in memory and reset at start (`breaker.rs`
  header: "trong bộ nhớ (đặt lại khi khởi động)"). Any restart (RB-01 roll back, OOM, restart loop, deploy) silently
  reopens a chain that is under a P1 defect investigation.
- R242(a) "that chain's indexer holds **in memory**". After a restart the indexer resumes from a `chain_index` whose
  hash a quorum has just rejected, and writes ranges of the new fork on top of the stale base for up to 600 s before
  the next recheck. Clients book those ranges. This is the damage R242 exists to stop.

**Fix.**
- Run the R242(a) hash recheck once at indexer start, before the first range is written. That is one header read and
  restores the hold deterministically.
- Persist the `revert_streak` latch in the store (a `breaker_latch` row or a field in the `chain.breaker` JSON) and
  clear it only through `breaker/reset` (audited).

---

## Medium

### M1 — RB-12 step 2 (`DELETE …/tokens/$TOKEN`) silently removes that token's events from the feed for good (§10 RB-12)

**Problem.** Removing a token from the registry also removes it from the indexer filter. NI §16.1 says "unregistered
contract dropped and counted", and Odoo §10.4(b) drops non-token events too. Payments to the ERP for that token stop
arriving. Re-registering doesn't backfill, because the cursor is per chain. The runbook presents the step as a
reversible intake stop.

**Fix.** Specify a token intake pause: `token.active = 0` refuses intake on every door and keeps indexing. NI already
has the column; it needs a route, for example `PATCH …/tokens/{addr} {active}`. RB-12 should use the pause. If a
delete is ever used, re-registration needs `index reset` to the delete block.

### M2 — Node-wide `/readyz` turns per-chain P2 conditions into P1 pages (§5.1 `ScaasNotReady`, §3.1)

**Problem.** `/readyz` is red when any chain has an `rpc:` error, index lag or (during transition) an `odoo:` error
(`admin.rs:90-103`). RB-05 classes RPC divergence as P2, but 5 minutes of a single chain's quorum loss on a 16-chain
node pages P1 through `ScaasNotReady`. A chain halted on purpose in RB-06 probably stays red for its whole incident.

**Fix.** Page P1 only on node-scope reasons (store not open, not owner, every chain failing). Export
`scaas_chain_ready{chain}` (0/1 with a reason-free label set) and alert per chain at the severity its runbook already
gives. Exclude `paused`/`halted` chains.

### M3 — Off-host Prometheus (R231) can't scrape the default node, and exposing it publishes the admin API (§2 R231, §4.1)

**Problem.** `/metrics`, `/readyz` and `/healthz` are served on `admin_bind` (default `127.0.0.1:9108`, NI §3; T14
"admin bind loopback/VPN by default"). An off-host Prometheus and blackbox exporter can't reach loopback. Binding
`admin_bind` wider exposes `/v1/admin/login` and every admin route to the monitoring network. It also serves the
metrics without authentication, and those metrics carry tenant namespace names, lane and token addresses, and
balances.

**Fix.** Add `[modules] metrics_bind` that serves only `/metrics`, `/readyz` and `/healthz`. An alternative is a
documented reverse proxy with mTLS or a bearer and a path allowlist. State which choice the `scaas/ops` bundle assumes.

### M4 — The R244 caps don't give the stated "≤ ~5 000 series, 1 MiB" (§2 R244, §4.1, §12)

**Evidence (at the caps: 16 chains, 32 namespaces, 64 tokens per chain, 8 legs, 14 roles):**

| Series family | Labels | Series |
|---|---|---|
| `scaas_watch_code_hash_changed` | chain × token × role | 14 336 |
| `scaas_wrapper_leg_backing_ratio` + `scaas_wrapper_leg_reserve_share` | chain × token × leg, × 2 | 16 384 |
| `scaas_relay_jobs` | chain × namespace × 9 states | 4 608 |
| `scaas_job_terminal_total` | chain × namespace × outcome | 3 072 |
| token cost + fee counters | chain × token, × 2 | 2 048 |
| `scaas_job_stage_seconds` | histogram | 1 632 |
| **Total** | | **≈ 42 000 series, before the HTTP histogram** |

That is roughly 4–5 MiB per scrape. Separately:
- `scaas_audit_head_info{hash}` (NI) creates a new series on every admin mutation (churn).
- `scaas_oidc_*{issuer}` uses a URL as a label, which R230 forbids.

**Fix.**
- Emit leg and role series only for legs and roles that exist.
- Collapse the code-hash gauge to `{chain,token}` (the role is in `GET …/watch`).
- Drop `namespace` from `scaas_job_terminal_total` (cost and accept counters keep it).
- Replace `hash` with an `_info`-free `scaas_audit_head_seq` gauge and log the hash.
- Use an issuer index as the label.
- Then restate the bound from the real formula.

### M5 — The indexer-progress SLO and `ScaasIndexerStalled` (P1, 300 s) are wrong for `finalized`/`l1_batch` chains (§3.1, §5.1)

**Problem.** The final head of Celo (`tag` until `l1_batch`, §3.2 row) moves when L1 Ethereum finalizes, about once
per epoch (≈ 384 s). Empty ranges are written only when the final head moves. So "≤ 60 s for 99 % of minutes" can
never be met, and `time() - last_progress > 300` pages P1 about once per epoch.

**Fix.** Add a per-chain `scaas:indexer_stall_seconds` recording rule, like `scaas:slo_target_seconds`, with default
max(300, 2 × the expected final-head step), and set the §3.1 target per chain class.

### M6 — Forced-transfer silences can't be scoped to one token, and the issuer doesn't own the Alertmanager (§4.3, RB-13 step 2)

**Problem.** `scaas_watch_events_total{chain,event}` has no `token` label. A silence "for `ScaasForcedTransfer` on
that token" therefore mutes every regulated token on the chain, which removes the "unplanned forced transfer must
page" control for the other tokens. R231/R247 also put Alertmanager with the node operator, not the issuer.

**Fix.** Add a `token` label. It is bounded by the 64-per-chain cap, and series are created lazily, so only tokens
with events have them. Change RB-13 step 2 so that NO creates the silence at IS's written request.

### M7 — The denylist is checked at intake only, so jobs requeued from `signed` bypass it; lift and DEX effects are unstated (§4.5)

**Problem.**
- A job that is `signed`/`broadcast` when the entry is added correctly "continues". If its tx drops, `plan()` /
  stuck-expiry moves it `signed → queued` (NI §4 transition table) and it is re-leased and re-signed for the listed
  party. Intake never sees it again.
- Lifting an entry doesn't restore held or dead jobs. This should be stated.
- For the DEX: a settle job of a listed maker or taker that goes `dead` after a match must take the trade to `failed`
  (the `dex_sync` failed path). Otherwise the venue keeps a matched trade without a live job.

**Fix.**
- Check the in-memory set at lease time too (one lookup). A listed job goes `dead`, or `hold = 1` if published.
- Add a line: lift doesn't revive jobs; clients re-push with a new generation.
- Add a line on the DEX trade outcome.
- Optionally state the operator's choice for refunds/exits whose only listed party is the *source* (TSS
  withdrawals, tender refunds), since a refund to a non-listed payer then needs self-submission.

### M8 — PII rules conflict with the audit mirror, backups and evidence copies (§2 R237, §7, §10.0, §11.1; TSS R195/§C.4)

**Problems.**
- (a) R237 mirrors every `audit_log` row with `before`/`after`. `POST /v1/admin/deny` logs the listed address, which
  contradicts R237's "never subject addresses" and §4.5's "never the address". Fee-recipient and token changes are
  fine; deny rows aren't.
- (b) §11.1: "a 35 d backup holds ≤ 30 d of jobs" confuses content age with copy lifetime. A daily off-site copy kept
  35 d keeps payloads (payer, payee, amounts) for up to about 65 d. TSS §C.4 step 5 promises "node payloads age out
  within 30 d". A restore of an old backup also resurrects purged rows until the purge task runs.
- (c) §10.0 evidence writes a full unencrypted store copy to `/var/lib/scaas-evidence/` with no retention.
- (d) "A pipeline that cannot enforce retention must receive `text` at `warn` only" drops the `info`-level audit
  events that R240 needs for re-revoke.

**Fix.**
- Audit mirror: replace address fields with `deny_id` / SHA-256.
- Either cap off-site backup retention or amend TSS §C.4 step 5 to "≤ `job_retention_secs` + backup retention", and
  run the purge before serving after `store restored`.
- Evidence directory: encrypted, mode 0700, deleted at incident close (≤ 30 d).
- Emit audit events at `warn`, or require a separate sink for them.

### M9 — With R239 separation in place, the RACI "Admin user lifecycle: KC A/R" can't be done through the API (§9.1, §9.2; NI R107)

**Problem.** R107: creating a user needs `key_custodian`, roles granted must be ⊆ the caller's roles, and creating an
`admin` user needs `admin` + `key_custodian`. R239 makes KC and `admin` different people, so KC can create only users
with KC's own roles, and NO can't create users at all. In production, operator/admin users can be created only
through the host CLI (R108), which is NO's host access.

Also, R239's reason calls KC "C (second person)" on `fee_recipient` two-person control, but nothing enforces it.

**Fix.** RACI row: "operator/admin users: NO R via host CLI, KC A (approves) and I". KC creates KC/viewer users via
the API. State that the `fee_recipient` second person is procedural (an audited change verified against
`ScaasFeeRecipientChanged`), not technical.

### M10 — SQLite backup and capacity figures are internally inconsistent (§11.1, §12, §4.3 `scaas_store_rows`)

**Problems.**
- (a) `.backup` every 5 min kept 7 d is 2 016 full copies. At §12's own 1.8 GB that is about 3.6 TB.
- (b) §12's store-size row uses 24 000 jobs/day, while the rated load is 860 000/day: about 2.1 GB/day, roughly 65 GB
  at 30 d of `job` rows. That makes (a) and the 30-min RTO implausible at the rated load.
- (c) `scaas_store_rows` every 60 s runs `COUNT(*)` on tables of tens of millions of rows. It runs on the single
  SQLite connection (A1.2 `max_connections = 1`), so it blocks journal transactions and breaks the 50 ms p99 journal
  SLO every minute.
- (d) The sqlite3 CLI `.backup` steps through the online-backup API and restarts when another connection writes. On a
  large store under continuous writes it may not finish.
- PG "≈ the same per node" holds only at LAN RTT. With every transaction serialized on the fencing row and about 6
  statements per transaction, a 5 ms RTT gives about 5 jobs/s.

**Fix.**
- Keep the last 12–24 five-minute copies plus a daily copy.
- Restate size and RTO at the rated load, or lower the rating.
- Derive row counts from `seq_counter` minus the purge floors (or incremental counters), not `COUNT(*)`.
- Use `VACUUM INTO` (one consistent statement) or Litestream snapshots for periodic copies.
- State the RTT assumption (≤ 1 ms) for the PG/MySQL rating.

### M11 — The §11.2 claim "subjects' nonces prevent double execution (G1)" doesn't cover `call` jobs (§11.2, R241)

**Problem.** `call` jobs carry no node digest (NI §4 `digest NULL for call`), so they have no G2, and they have no
subject nonce. After a restore, a `call` job signed and mined after the backup point is `queued` again and is
re-signed. Today's producers are protected by their target contracts:
- `MandateWallet.payUnderMandate` checks `refUsed[entryRef]`;
- subject-account `deploy` is idempotent;
- DEX settle consumes order fills.

That protection is a property of the targets, not of the node.

**Fix.** Make "target enforces its own replay protection" a stated precondition of granting `allow_call` (NI R103),
and say so in §11.2. Together with H1 (paused after restore) this closes the gap.

---

## Low

- **L1 Watched event names (§4.3).** `RateChangeExecuted` doesn't exist; TW2 §10.2 emits `RateChanged`.
  `ImplementationRegistered`/`ImplementationDeprecated` aren't in TW2 §10.2. Missing: AS `ControlsDisabled`
  (irreversible), `AccountUnfrozen`; TW2 `MinterRenounced`, `MetaNonceCancelled`. Fix the list rather than rely on
  "normaliser wins".
- **L2 PromQL hygiene (§5.1).**
  - `sum(scaas_gossip_peers) == 0` and `sum(increase(scaas_admin_login_total…))` have no `by (instance)`, so one
    isolated node is masked among several.
  - The W3B volume gate counts `dead_before_sign`/`cancelled`, which the ratio excludes.
  - Add `absent(up{job="scaas-node"})`. `up == 0` misses a target that dropped out of service discovery.
  - Backup and drill alerts never fire when the textfile series is absent (never ran; a drill on a scratch host
    writes its file there). Seed the files on the production host or add `absent()` rules.
  - `ScaasStoreDiskCritical` assumes `/var/lib/scaas` is a separate mount.
  - `ScaasNamespaceBudget90` runs a 30 d raw `increase` at every evaluation. Use a 1 h recording rule plus
    `sum_over_time`, evaluated hourly.
  - `scaas_wrapper_leg_reserve_share > 0.80` fires forever on a Multi that is concentrated by design. Make the
    threshold per token.
- **L3 R234 stage map.** Keying the map by `tx_hash` loses jobs whose hash changes on a bump. Draining "when the
  indexer writes the range" by tx match never drains `call` txs with no watched event, so the 50 000 cap fills. Key
  by job uid and drain by `mined_block ≤ to_block`. A late `mined → reverted` counts the job twice in
  `scaas_job_terminal_total`.
- **L4 Snapshot staleness.** `admin.rs` `refresh` probes chains one after another (3 s timeout, 2 probes each). At
  the 16-chain cap a refresh can take about 96 s, which reaches the file's own ponytail ceiling. Parallelize in OP1
  and export `scaas_snapshot_age_seconds`.
- **L5 Runbook request bodies.**
  - RB-02 `PATCH {"breaker": {"gas_budget_per_hour": …}}` writes into a JSON blob (`chain.breaker`). Specify a merge,
    otherwise it drops `min_relayer_balance`, which removes the floor.
  - RB-12 `DELETE …/tokens/$TOKEN` doesn't match NI's collection route `DELETE /v1/admin/chains/{key}/tokens`.
  - §4.2 says `scaas_submit_bump_skipped_consumed_total` has `{chain,lane}`, but `admin.rs` renders it without
    labels. Note this as OP1 work.
- **L6 Over-engineering for v1 (R247 makes all of this advisory).**
  - Code-hash pins with EIP-1967 slot reads, `watch_pin` and the re-pin route (OP3) could be an external script in
    `scaas/ops` reading `GET …/tokens`, with no node code or table.
  - Nine dashboards could be three (Overview, Submit/Chains, Store/DR).
  - Composition-drift series and rule could wait.
  - Eight DR drills could be four for v1 (restore, accept_nonce, dead_man, key_recovery).
  - Keep watched events, backing ratio, `usage_day` and the denylist.
