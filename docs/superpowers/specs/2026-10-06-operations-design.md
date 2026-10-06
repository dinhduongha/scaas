# Operations: SLOs, telemetry, FinOps, RACI, incident response and disaster recovery (component spec C)

Status: draft rev 1, 2026-10-06. Component spec **C**. Short name **OPS**. Code at `scaas` `main` 5f1d327 (node store
P1 built; job API, admin API, mesh bus, gossip SPECIFIED). **Nothing in this spec is built** except the metrics marked
BUILT in §4.2.
Rulings: **R230–R245** (§2). R150–R172 belong to the app spec, R180–R199 to spec B (TSS), R200–R216 to spec A (AS).
Owner ruling of 2026-10-06 folded in: **the spec proposes default numbers with reasons; every number is owner to
approve.** Market-neutral: no jurisdiction-specific law; amounts in neutral units; "reporting currency" means the
deployment's own.

**OA** marks a default number proposed by this spec (reason next to it); **owner to approve**. Changing an OA number
never changes a ruling's reasoning.

Amends (status changes only; text in those files is not rewritten here):

| Short | File | How |
|---|---|---|
| SCaaS | `docs/SCaaS.md` | §13.1 W3B-01…06, trace contract; §13.2 unit cost; §13.3–§13.5: PLANNED → SPECIFIED, link here. §13 tables stay as the summary; this spec is the normative detail |
| NI | `specs/2026-10-06-node-independence-design.md` rev 3.3 | §15 metrics extended (§4.3); `job` gains `trace_id` (R236); `usage_day` and `watch_pin` tables (R238, R235); CLI `lane accept-nonce` (R241); admin routes `…/tokens/{addr}/pins`, `…/watch`, `/v1/admin/usage` (§4.4) |
| MESH, A2 | relayer-mesh rev 3, gossip amendment rev 2.1 | metric `scaas_mesh_propagation_seconds` added; names of MESH §12 and A2 §13.3 unchanged |
| TSS | tender-sponsorship-shredding rev 1.1 | job cost columns (§B1.2) are written for **every** job, not only sponsored ones (R238) |
| TW2, AS | token wrappers v2 rev 1.2, asset suite rev 1 | "node/ERP should alert" items (TW2 §6.6, §8.4; AS §3.10, §9.1) become the node ops watch (R235) |

---

## 1. Scope and conventions

### 1.1 In scope

SLIs/SLOs per component with error budgets; exact metric names and labels; alert rules, severities, routing;
dashboards; trace scope; structured logs and their personal-data rules; FinOps measurement and the monthly report;
RACI for every operational action; incident runbooks with commands; backup/restore with RPO/RTO per store backend;
DR drills; capacity limits for the reference hardware class.

### 1.2 Non-goals

- High availability for one `(company, chain)` (R97, NI §18.3 stays deferred). DR here is restore, not failover.
- Automatic lane refill from a treasury (SCaaS §13.2 "auto-refill" stays PLANNED; runway alerts replace it in v1).
- A price oracle in the node (TSS R189 unchanged). FinOps conversion uses an operator-supplied price file.
- Contractual SLAs with service credits (open question §14 q2). The targets here are internal objectives.
- Telemetry from the app (`scaas/app`). The app sends nothing; W3B-05 is a release benchmark (R233).

### 1.3 Severities (R232)

| Sev | Meaning | Routing | Acknowledge within (OA) | Why |
|---|---|---|---|---|
| **P1** | Integrity at risk (journal, nonce, feed, audit, reserve) or service stops within the hour | page 24/7, on-call of the accountable role (§9) | 15 min | SCaaS §13.4 starts the clock at T+0; 15 min matches the research P1 reaction window (§12.11: loss = cap rate × 15 min) |
| **P2** | Degraded or a security-relevant change that must be verified the same day | page in business hours, ticket otherwise | 4 h | one working half-day; nothing on this list loses data while waiting |
| **P3** | Trend, budget or hygiene | ticket | next business day | |

---

## 2. Rulings

Format: **ruling — reason — cost if wrong.**

- **R230** **Metrics = Prometheus text on the admin `/metrics`, rendered by the existing hand-written renderer
  (`admin.rs` `render`); no metrics crate.** Prefix `scaas_`; base units (seconds, bytes, smallest native unit);
  counters `_total`; histograms rendered by the same code with fixed buckets. Labels only from the §4.1 allowlist:
  never a subject address, payer, amount, `tx_hash`, job uid, `entry_ref`, open-mesh peer, URL or IP; RPC endpoints
  by index (`"0"`, `"1"`…), because `rpc_urls` may embed provider API keys. — R51 already hand-writes the format
  (golden test); a histogram is ~30 lines; one dependency less on a box with an OOM rule. — If wrong: a crate swap
  keeps every name.
- **R231** **SLOs, alerts and dashboards are evaluated outside the node**: Prometheus recording rules + Alertmanager
  on infrastructure that is neither the node's host nor the ERP's, plus an external dead-man's switch fed by an
  always-firing `Watchdog`. The node exports raw series only. Rule file, Alertmanager example and dashboards live in
  `scaas/ops/` and are the normative copy of §5. — Research §12.11: monitoring on the monitored host is switched off
  by whoever owns that host; absence of signal must page. — If wrong: one more host per deployment.
- **R232** **Three severities** (§1.3); P1 = exactly the `scaas-p1` group of §5.1; everything else P2/P3. — Pages
  that do not mean "integrity or outage" train people to ignore pages. — If wrong: an alert moves one group.
- **R233** **W3B as the node can measure it.** Each job counts once at its terminal transition in
  `scaas_job_terminal_total{chain,namespace,outcome}`, `outcome ∈ mined, consumed, reverted, expired_after_sign,
  dead_before_sign, cancelled`. **W3B-01** = (`mined` + `consumed`) ÷ (`mined` + `consumed` + `reverted` +
  `expired_after_sign`): `consumed` is good (landed elsewhere, or the subject chose another intent), the last two
  outcomes never reached a lane. **W3B-02**: each reverted receipt of ours is `race` (R80 read shows the subject
  nonce consumed) or `other`; target `other` = 0, each one a P2; **≥ 3 `other` in 15 min on a chain (OA: three rules
  out one bad payload; 15 min = one reaction window) opens a new chain-level breaker `revert_streak`** (new work only,
  N9 unchanged, manual reset). **W3B-05** is a release benchmark (prover time on reference devices + verifier gas
  tests): the app sends no telemetry. **W3B-06** is a monthly report figure (§8). — SCaaS §13.1 counts "finalized";
  the node knows `mined` at once and finality only via its feed; a mined job that never finalizes is a finality
  violation, caught by R242. — If wrong: W3B-01 over-reports by the (paged, ~0) violation rate.
- **R234** **Job timing = `scaas_job_stage_seconds{chain,stage}`**, `stage ∈ queue` (accepted → first `leased`),
  `sign` (`leased` → `signed`), `include` (first broadcast → `mined`), `finalize` (`mined` → final range written),
  `broadcast_final` (= W3B-04), `e2e` (accepted → final). The last three use a bounded in-memory map `tx_hash →
  (accepted_at, broadcast_at, mined_at)` drained when the indexer writes the range; lost on restart (samples lost,
  never wrong). — No new `job` index for a metric. — If wrong: a restart drops ≤ one finality window of samples.
  `// ponytail: in-memory finalize map (cap 50 000 OA); persist only if restarts make W3B-04 blind.`
- **R235** **Ops watch in the node** for registered tokens on EVM and Hedera: (a) **code-hash pins** of the token,
  each underlying, `rateAdmin`, `guardian`, `issuer`, `compliance`, `registry`, including EIP-1967 implementation
  and beacon slots; (b) **leg backing** (`underlying.balanceOf(token) ÷ reserve_i`) and **Multi composition**; (c)
  **watched events** from the final feed (§4.3). Pins are taken at token registration and changed only by an audited
  admin re-pin; a mismatch latches until then. Poll every 300 s (OA: ~20 reads per token per 5 min, far below
  provider quotas; a TW2 drain is one block, so polling only shortens the reaction) at the final head. Non-EVM
  upgrade signals (Solana upgrade authority, Aptos package upgrades, Sui `UpgradeCap`) are PLANNED. — TW2 §6.6/§8.4
  and AS §9.1 ask the "node/ERP" to alert; only the node has the RPC, the registry and `~gateway`/`~mesh` tokens. —
  If wrong: a few RPC reads every 5 min.
- **R236** **Traces: no OpenTelemetry SDK in the v1 binary.** Gateway and job API accept a W3C `traceparent` (the
  `POST /v1/jobs` header applies to every item); the trace id (32 hex) is stored as `job.trace_id` (absent ⇒
  generated) and carried by every lifecycle log line and jobs-feed item. Span names are fixed now (§6). OTLP export =
  cargo feature `otel`, default off, stream OP7 (PLANNED). — OpenTelemetry + OTLP + `tonic` would be the node's
  heaviest dependency set (OOM rule); `job_event` already is a durable per-job trace. — If wrong: correlation by
  `trace_id` in logs until OP7.
- **R237** **Logs = JSON lines in production** (`[log] format = "json" | "text"`, default `text`; any deployment
  holding value runs `json`), fields §7. Never logged: payloads, signatures, subject addresses (`from`, `to`, payer,
  payee, maker), amounts, salts, openings, secrets, tokens, HMAC headers, passwords, RPC URLs. Allowed: lane and
  contract addresses, `tx_hash`, digests, job uid, `entry_ref` (random, R9/R198), `namespace`, `trace_id`; source IPs
  only in auth-failure and rate-limit lines. **Retention ≤ 30 d (OA, = `job_retention_secs`)** at every sink, so no
  copy outlives the store (R195; TSS §C.4 step 5). **Every `audit_log` row is mirrored as a log event** (`event =
  "audit"`, `***` for secrets) so a lost store's last audit entries survive off-host (R240). — R195. — If wrong: an
  auditor gets a 30-day log window; long-term evidence is the audit table and the chain.
- **R238** **FinOps measurement**: the TSS cost columns (`gas_used`, `gas_price`, `cost_native`) are filled for every
  job at `mined`/`reverted` and for gap-fillers; the same transaction upserts a durable daily rollup **`usage_day`**
  (§8.2; 400 d OA = a fiscal year plus a month). Cost/fee counters (§4.3) feed alerts and dashboards. Conversion to
  the reporting currency happens only in the report, with an operator-supplied price file; the node fetches no
  prices. **Budget alarms are Prometheus rules; enforcement stays with R55 `gas_budget`, TSS sponsor budgets and
  `max_live_jobs`.** — Jobs are purged after 30 d, Prometheus retention is short, and `~gateway`/`~mesh` costs are
  booked by no client. — If wrong: one small upsert per terminal job.
- **R239** **RACI roles** (§9.1): node operator, key_custodian, issuer, compliance, guardian, rateAdmin, ERP admin,
  owner/SCaaS team. In production `key_custodian` and `admin` are **different people**; guardian, rateAdmin, issuer
  and compliance are **different keys** (recommended, not enforced: R107 allows one person on a dev box; AS
  `rolesSeparated()` discloses the on-chain case). — Two-person control between "mint credentials" and "change fee
  recipient" is the cheapest defence against T14; AS A1–A3 rely on separation. — If wrong: the risk is disclosed.
- **R240** **Restore is one fixed sequence** (§11.3): stop, evidence, restore, integrity check, `store restored`,
  re-revoke from the off-host audit events (R237) **or** rotate `master_key`, start, `lane accept-nonce` for lanes
  flagged foreign, clients acknowledge. RPO/RTO per backend §11.1. — R110 halts the client; this makes the node side
  deterministic. — If wrong: a skipped step is caught by the next (foreign-nonce refusal, client halt).
- **R241** **New CLI `scaas-node lane accept-nonce --chain <key> --lane <label> --confirm <n> --config node.toml`**
  (sequence families; node stopped; owner lock, epoch + 1): reads `nonce_at(latest)` and `nonce_at(pending)` from
  every RPC (quorum must agree), prints them with `journal_max`, requires `--confirm` = `pending − 1`, sets
  `lane.journal_max` to it, audited. Unjournaled nonces in `[latest, pending)` are then tracked while in the mempool
  and gap-filled at the next cold start if dropped. — After a restore the chain is ahead of the journal by design;
  NI §9.4 refuses such a lane (correct) and the only other way out is a new lane. — If wrong: an operator adopts a
  nonce advanced by a second store; RB-04 makes "no second user of the key" an explicit check.
- **R242** **Integrity rechecks**: (a) every 600 s (OA: inside the 30-min P1 window, one header read per chain) the
  indexer re-reads the hash at `chain_index.indexed_block` from ≥ `quorum` endpoints; a quorum answering a different
  hash ⇒ `scaas_indexer_final_mismatch_total + 1`, that chain's indexer holds in memory, `/readyz` reason `finality
  violated at <block>`. (b) The audit hash chain is verified from the first row at start and every 24 h (OA); a break
  ⇒ `scaas_audit_verify_failures_total + 1`. No automatic state change or feed rewind. (c) Recovery: CLI `scaas-node
  index reset --chain <key> --to <block> --confirm <block>` (node stopped, owner lock, audited) moves `chain_index`
  back; clients reset their own event cursor for that chain to the same block, else the straddle rule (integration
  §4.3) drops the re-delivered events. — A violation is a human-judgement event (which ranges, which bookings);
  holding the indexer stops the damage without a schema change. — If wrong: ≤ 10 min of extra ranges to reconcile.
- **R243** **DR drills are scheduled, timed and exported** (§11.4): each run writes
  `scaas_dr_drill_last_success_timestamp_seconds{drill}` and `scaas_dr_drill_cadence_seconds{drill}` to the
  node_exporter textfile collector; older than 1.5 × cadence ⇒ P3. — Research §12.11: an untested restore is not a
  restore. — If wrong: one textfile per drill.
- **R244** **Capacity rating** for the reference hardware class (§12) and **label caps**: ≤ 16 chains, ≤ 8 lanes per
  chain, ≤ 32 namespaces, ≤ 64 registered tokens per chain (OA: `/metrics` stays under ~5 000 series and 1 MiB per
  15 s scrape); `Config::validate` and the admin routes refuse more (`422 LIMIT`). — An unbounded label is an outage
  of the monitoring, found at 3 a.m. — If wrong: the caps are constants.
- **R245** **Incident command** = the accountable role of the failing component (§9.2): node operator for node,
  store, chain and lane; issuer (with compliance for regulated tokens) for tokens; owner/SCaaS team for release
  defects. Evidence first (§10.0); never auto-cancel held or signed jobs (a broadcast tx can still land); never
  rewind silently; customer communication from prepared templates. — Research §12.10; SCaaS §13.4 timing kept. — If
  wrong: escalation path in §9.2.

---

## 3. SLIs and SLOs

### 3.1 Component SLOs

Window: 30 days rolling unless stated. "Budget" = allowed bad fraction of the window.

| Component | SLI (series, §4) | Target (OA) | Reason | Budget / 30 d |
|---|---|---|---|---|
| Gateway acceptance | p99 of `scaas_http_request_seconds{listener="gateway",route="/v1/metatx"}`; availability = non-5xx share | p99 ≤ 300 ms; ≥ 99.9 % | accept does no RPC (one store transaction + R54 auth); a wallet waits on it | 43 min |
| Job API acceptance | p99 of `…{listener="api",route="/v1/jobs",method="POST"}` (≤ 50 items); availability | p99 ≤ 1 s; ≥ 99.9 % | 50 JCS hashes + one transaction; the ERP cron holds a worker meanwhile | 43 min |
| Queueing | p95 of `scaas_job_stage_seconds{stage="queue"}` while no breaker/pause | ≤ 5 s | poll 1 s × a few rounds; the 15 s hold after a restart counts, a 1 h p95 absorbs one restart | — |
| Submit → mined | p95 of `stage="include"` per chain (table §3.2) | §3.2 | a few blocks per family | — |
| W3B-01 success | R233 ratio | ≥ 99.5 % | SCaaS §13.1 | 0.5 % of jobs |
| W3B-02 zero revert | `scaas_submit_reverted_total{class="other"}` | 0 | SCaaS §13.1; any occurrence P2, streak ⇒ breaker | 0 |
| Revert incl. races | all reverts ÷ broadcasts, 7 d | ≤ 0.5 % | research guard §06.3.2 | — |
| Consumed rate, private profile | `consumed` ÷ signed-terminal, 1 d | ≤ 1 % | on `restricted` scope only the subject can race us; more means a second relayer or a client re-signing | — |
| W3B-03 gas budget | breaker `gas_budget` open minutes | ≤ 100 % (warn 90 %) | R55 (BUILT) | — |
| Indexer progress | `time() − scaas_indexer_last_progress_timestamp_seconds` | ≤ 60 s for 99 % of minutes | ranges are written even when empty (R94), so silence means stalled | 7 h 12 min |
| Indexer lag | `scaas_indexer_lag_blocks` | ≤ `max_index_lag` (100) | R51 readiness | — |
| Finality lag | `time() − scaas_final_head_block_time_seconds` | ≤ hard finality + 60 s (§3.2) | SCaaS §13.1 W3B-04 rule applied to the head | — |
| W3B-04 | p95 of `stage="broadcast_final"` | §3.2 | SCaaS §13.1 | — |
| Feed to clients | `scaas_feed_last_poll_seconds` per namespace while it has live jobs | ≤ 180 s for 99 % | Odoo polls every 60 s, every ~10 s while live (R101); 3 missed polls is a stall | 7 h 12 min |
| Mesh propagation | p95 of `scaas_mesh_propagation_seconds` per carrier | gossip ≤ 1 s, bus ≤ 3 s | must be ≪ the 7 s exclusivity window (R121); bus is pull-based | — |
| Gossip health | `scaas_gossip_mesh_peers{topic_kind="intent"}` per chain | ≥ `mesh_n_low` (4) for 99 % | A2 §7 parameter; below it gossipsub grafts and delivery suffers | 7 h 12 min |
| Store | p99 of `scaas_store_tx_seconds{kind="journal"}`; `scaas_store_fencing_lost_total`; `scaas_store_commit_unknown_total` | ≤ 50 ms; 0; 0 | NVMe fsync ≈ 1–2 ms, PG/MySQL one RTT; journal latency is in every send | — |
| Backups | `time() − scaas_backup_last_success_timestamp_seconds` | ≤ 3 × interval (§11.1) | RPO is the interval; three misses is a broken job | — |
| Admin API / app | blackbox `probe_success` of `/readyz` and the app `/` + `/config.json` | ≥ 99.5 % | an operator console, not a payment path | 3 h 36 min |

### 3.2 Latency targets per family and profile (all OA)

`include` = first broadcast → mined (p95). `broadcast_final` = W3B-04 (p95) = hard finality + 60 s for depth/tag
families, `include` + 30 s for instant families (one indexer poll plus a range write).

| Chain class | Block / finality | `include` p95 | `broadcast_final` p95 | Reason |
|---|---|---|---|---|
| EVM private (9000, Clique, 1 signer) | ~5 s, depth 1 | 15 s | 15 s | SCaaS §13.1 value; 3 blocks |
| EVM public (Gnosis) | 5 s, `finalized` ~160–240 s | 30 s | 300 s | 6 blocks; 240 s + 60 s |
| EVM L2 (Celo, `tag` until `l1_batch`) | 1 s, L1 finality ~13–20 min | 10 s | 1 260 s | 20 min + 60 s |
| Hedera | 3–5 s record files, instant | 15 s | 45 s | 3 record files |
| Cosmos | ~6 s, instant | 20 s | 50 s | 3 blocks |
| Soroban (Stellar, Pi) | ~5–6 s ledgers, instant | 20 s | 50 s | 3 ledgers |
| Sui | ~0.5 s checkpoints, instant | 5 s | 35 s | |
| Aptos | ~1 s, instant | 5 s | 35 s | |
| TON | ~5 s masterchain, depth 0, message chains | 60 s | 90 s | jetton transfers span several messages |
| Solana | 0.4 s slots, `finalized` ~12.8 s | 10 s | 75 s | confirmed + 60 s margin over finalized |

A chain stays `draft` until 7 days of measurements exist (SCaaS §6.6 O4); the measured p95 + 20 % then replaces the
OA row for that chain.

### 3.3 Error-budget policy (OA)

- Burn-rate alerts (multi-window, Google SRE workbook): **fast** 14.4× over 1 h and 5 min ⇒ P1; **slow** 6× over
  6 h and 30 min ⇒ P2; **trend** 1× over 3 d ⇒ P3. Minimum volume 20 jobs in the long window, so one failure on an
  idle chain does not page.
- Budget exhausted for a node: only fixes ship to that node until it recovers (config changes that reduce risk —
  pause, breaker, lane retirement — are always allowed).
- One incident consuming > 25 % of a budget ⇒ written post-mortem (T+24 h) with a regression test.

---

## 4. Metrics

### 4.1 Rules

- **Label allowlist (R230):** `chain` (chain key), `family`, `profile`, `lane` (lane label: address or `pk:` key),
  `namespace` (incl. `~gateway`, `~mesh`, `~dex`), `token` (registered token address only), `leg` (0–7), `role`,
  `state`, `outcome`, `result`, `class`, `stage`, `kind`, `breaker`, `listener`, `route` (templated: `/v1/jobs/{uid}`),
  `method`, `code_class` (`2xx`…`5xx`), `endpoint` (RPC index), `feed`, `table`, `backend`, `carrier`, `topic_kind`,
  `event`, `policy` (sponsor policy name), `drill`, `peer` (admitted bus peer names only, bounded by the peer table),
  plus the labels already fixed by NI §15, MESH §12, A2 §13.3, TSS §B1.6 and the app spec §13.2.
- **Caps** R244. Amount values are float64 of the smallest unit (precision loss above 2^53 is irrelevant for
  aggregates; exact accounting is `usage_day`, §8).
- **Histogram buckets** (seconds): `scaas_job_stage_seconds` 0.5, 1, 2, 5, 10, 20, 30, 60, 120, 300, 600, 1200,
  1800, 3600; request and store histograms 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5;
  propagation 0.05, 0.1, 0.25, 0.5, 1, 2, 3, 5, 7, 10.
- Gauges are refreshed with the 10 s snapshot (`admin.rs` `REFRESH`); counters and histograms are atomics read at
  render time. Scrape interval 15 s (OA).

### 4.2 Existing (BUILT, `admin.rs`, `submit.rs`)

| Metric | Type | Labels | Note |
|---|---|---|---|
| `scaas_relay_jobs` | gauge | `chain`, `state` | from Odoo `relay_stats` today; from the store with `namespace` after P3 (NI §15) |
| `scaas_payment_requests_attention`, `scaas_drift_alerts` | gauge | `chain` | legacy (R104); leave the node (NI §9.1); the ERP alerts on its own queues |
| `scaas_indexer_lag_blocks` | gauge | `chain` | final head − indexed block |
| `scaas_relayer_balance` | gauge | `chain`, `lane` | smallest gas-coin unit |
| `scaas_breaker_open` | gauge | `chain`, `lane`, `breaker` | `base_fee_spike`, `gas_budget`, `balance_floor`; `revert_streak` added (R233), reported on every lane of the chain |
| `scaas_submit_bump_skipped_consumed_total` | counter | — (`chain`, `lane` per MESH §12) | R80 |
| `scaas_config_toml_drift` | gauge | — | R95 |

Specified elsewhere, names unchanged: NI §15 (job API, feeds, store owner, admin, audit, OIDC, fee recipient,
foreign nonce), MESH §12 (`scaas_mesh_*`, `scaas_submit_inflight_dup_total`), A2 §13.3 (`scaas_gossip_*`,
`scaas_tls_handshake_failures_total`, `scaas_bus_requests_total`), TSS §B1.6 (`scaas_sponsor_*`), app §13.2
(`scaas_app_requests_total`). NI's `scaas_feed_last_poll_seconds` is defined here as **seconds since the last poll**
at render time.

### 4.3 New (this spec, SPECIFIED)

| Metric | Type | Labels | Source / meaning |
|---|---|---|---|
| `scaas_build_info` | gauge (=1) | `version`, `commit` | binary |
| `scaas_process_start_time_seconds`, `scaas_process_resident_memory_bytes` | gauge | — | restart detection; `/proc/self/statm` |
| `scaas_chain_info` | gauge (=1) | `chain`, `family`, `profile` | config |
| `scaas_chain_state` | gauge (0/1) | `chain`, `state` (`active`, `paused`, `halted`) | store |
| `scaas_job_terminal_total` | counter | `chain`, `namespace`, `outcome` | R233 |
| `scaas_job_stage_seconds` | histogram | `chain`, `stage` | R234 |
| `scaas_simulation_total` | counter | `chain`, `result` (`ok`, `revert_consumed`, `revert_dead`, `transient`, `gas_cap`) | SCaaS §6.5 outcomes |
| `scaas_submit_broadcast_total` | counter | `chain`, `lane` | first broadcasts only |
| `scaas_submit_replacements_total` | counter | `chain`, `kind` (`bump`, `gapfill`, `resend`) | §6.3 |
| `scaas_submit_fee_cap_reached_total` | counter | `chain`, `lane` | replacement wanted, cap reached |
| `scaas_submit_reverted_total` | counter | `chain`, `class` (`race`, `other`) | R233 |
| `scaas_lane_inflight` | gauge | `chain`, `lane` | `signed` + `broadcast` rows |
| `scaas_lane_head_stuck_seconds` | gauge | `chain`, `lane` | now − first broadcast of the lowest unmined journaled nonce; 0 when none |
| `scaas_lane_cost_native_total` | counter | `chain`, `lane` | measured fee paid (R238) |
| `scaas_relayer_balance_floor` | gauge | `chain`, `lane` | `min_relayer_balance` (runway maths) |
| `scaas_rpc_requests_total` | counter | `chain`, `endpoint`, `result` (`ok`, `error`, `timeout`) | adapter |
| `scaas_rpc_head_lag_blocks` | gauge | `chain`, `endpoint` | max head − this endpoint's head |
| `scaas_rpc_quorum_disagreement_total` | counter | `chain` | ≥ 2 hashes at the candidate final head |
| `scaas_indexer_last_progress_timestamp_seconds` | gauge | `chain` | unix time of the last committed range |
| `scaas_final_head_block_time_seconds` | gauge | `chain` | chain timestamp of the final head, where the family exposes one |
| `scaas_indexer_final_mismatch_total`, `scaas_audit_verify_failures_total` | counter | `chain` / — | R242 (a), (b) |
| `scaas_http_request_seconds` | histogram | `listener` (`gateway`, `api`, `admin`), `route`, `method`, `code_class` | all listeners |
| `scaas_store_info` (=1), `scaas_store_restore_epoch` | gauge | `backend`, `store_id`, `schema_version` / — | store identity; `meta.restore_epoch` |
| `scaas_store_tx_seconds` | histogram | `kind` (`journal`, `transition`, `accept`, `feed`, `audit`, `purge`) | store |
| `scaas_store_tx_retries_total` | counter | `reason` (`serialization`, `deadlock`, `busy`) | A1.2 |
| `scaas_store_commit_unknown_total`, `scaas_store_lock_ping_failures_total` | counter | — | A1.2, A1.1 |
| `scaas_store_size_bytes` | gauge | — | SQLite file + WAL; PG `pg_database_size`; MySQL `information_schema` sum; every 60 s |
| `scaas_store_rows` | gauge | `table` (`job`, `job_event`, `feed_item`, `audit_log`, `intent`, `usage_day`) | every 60 s |
| `scaas_mesh_propagation_seconds` | histogram | `chain`, `carrier` (`gossip`, `bus_https`, `bus_quic`) | receive time − `hub.published_at`, clamped at 0 |
| `scaas_watch_events_total` | counter | `chain`, `event` | R235 (c), list below |
| `scaas_watch_code_hash_changed` | gauge (0/1, latched) | `chain`, `token`, `role` | R235 (a); `role ∈ token, underlying_0…7, rate_admin, guardian, issuer, compliance, registry` |
| `scaas_wrapper_leg_backing_ratio` | gauge | `chain`, `token`, `leg` | R235 (b); tier 2 = leg 0 |
| `scaas_wrapper_leg_reserve_share` | gauge | `chain`, `token`, `leg` | Multi only; `reserve_i × num_i/den_i ÷ Σ` |
| `scaas_gas_cost_native_total` | counter | `chain`, `namespace` | R238 |
| `scaas_token_gas_cost_native_total` | counter | `chain`, `token` | R238; `token = "call"` for call targets that are not tokens |
| `scaas_fee_earned_total` | counter | `chain`, `token` | fee of our mined meta-txs whose resolved recipient is a lane or the chain's `fee_recipient`, token base units |

Watched events (`event` label): `OrderRecorded`, `OrderRevoked`, `ForcedTransfer`, `AccountFrozen`, `Paused`,
`Unpaused`, `AttesterSet`, `RoleRenounced`, `WrapDisabled`, `GuardianRenounced`, `RateChangeProposed`,
`RateChangeExecuted`, `RateChangeCancelled`, `RateAdminRenounced`, `ImplementationRegistered`,
`ImplementationDeprecated` — only for registered tokens and the configured factories (exact event names as in
TW2 §10.2 and AS §3.3; the normaliser's names win if they differ).

External (not the node): `scaas_backup_last_success_timestamp_seconds{backend}`,
`scaas_backup_interval_seconds{backend}`, `scaas_dr_drill_last_success_timestamp_seconds{drill}`,
`scaas_dr_drill_cadence_seconds{drill}` written by the
backup and drill scripts to the node_exporter textfile directory; blackbox `probe_success`; node_exporter host
metrics.

### 4.4 Admin and store additions

| Item | Detail |
|---|---|
| `job.trace_id TEXT NULL` | R236; 32 hex; echoed in jobs-feed items |
| `watch_pin (chain_key, token, role, address, code_hash, slots TEXT, pinned_at, pinned_by, PRIMARY KEY (chain_key, token, role))` | R235; `slots` = JSON list of storage slots read for proxies (default EIP-1967 implementation `0x3608…2bbc` and beacon `0xa3f0…3d50`; an older proxy's slot is added by the admin) |
| `usage_day` | §8.2 |
| `GET /v1/admin/chains/{key}/watch` | viewer: pins, current hashes, backing ratios, shares |
| `PUT /v1/admin/chains/{key}/tokens/{address}/pins` `{roles?: [...], slots?: [...]}` | admin; re-reads and re-pins (clears the latch), before/after audited |
| `GET /v1/admin/usage?from=&to=&chain=&namespace=` | viewer; `usage_day` rows, no conversion |
| `scaas-node report usage --from YYYY-MM-DD --to YYYY-MM-DD [--prices prices.csv] [--format csv|json]` | CLI, read-only (no owner lock); §8.3 |
| `scaas-node lane accept-nonce …` | R241 |
| `scaas-node index reset --chain <key> --to <block> --confirm <block>` | R242 (c); node stopped |

---

## 5. Alerts, routing, dashboards

### 5.1 Rule file (`scaas/ops/prometheus/scaas-rules.yml`, normative)

Every alert carries `severity` and `runbook` (anchor in §10). Thresholds are OA with the reason in §3 or the rule's
comment.

```yaml
groups:
- name: scaas-recording
  rules:
  - record: scaas:w3b01_errors:ratio_rate5m  # same expression for 30m, 1h, 6h, 3d (rename the window)
    expr: |
      sum by (chain) (rate(scaas_job_terminal_total{outcome=~"reverted|expired_after_sign"}[5m]))
      / clamp_min(sum by (chain) (rate(scaas_job_terminal_total{outcome=~"mined|consumed|reverted|expired_after_sign"}[5m])), 1e-9)
  - {record: scaas:slo_target_seconds, expr: 'vector(300)', labels: {chain: "evm:100", slo: w3b04}}  # one rule per chain and slo (w3b04, include), values §3.2
  - {record: scaas:finops_budget_native_30d, expr: 'vector(5e17)', labels: {namespace: odoo-prod, chain: "evm:100"}}  # one rule per (namespace, chain) with an approved budget
- name: scaas-p1
  rules:
  - {alert: ScaasNodeDown, expr: 'up{job="scaas-node"} == 0', for: 2m, labels: {severity: P1, runbook: rb-01-node-down-or-not-ready}}
  - {alert: ScaasNotReady, expr: 'probe_success{job="scaas-readyz"} == 0', for: 5m, labels: {severity: P1, runbook: rb-01-node-down-or-not-ready}}
  - {alert: ScaasLaneForeignNonce, expr: 'increase(scaas_lane_foreign_nonce_total[10m]) > 0', labels: {severity: P1, runbook: rb-04-foreign-nonce}}
  - {alert: ScaasFencingLost, expr: 'increase(scaas_store_fencing_lost_total[5m]) > 0', labels: {severity: P1, runbook: rb-07-store-owner-loss}}
  - {alert: ScaasLaneHeadStuckHard, expr: 'scaas_lane_head_stuck_seconds > 900', labels: {severity: P1, runbook: rb-03-stuck-lane}}  # 15 min: SRS §5.4 mempool limit; bumps run every 60 s before
  - {alert: ScaasChainNoLaneAvailable, expr: 'min by (chain) (max by (chain, lane) (scaas_breaker_open)) == 1', for: 5m, labels: {severity: P1, runbook: rb-02-breaker-open}}
  - alert: ScaasLaneRunwayCritical
    expr: |
      (scaas_relayer_balance - on (chain, lane) scaas_relayer_balance_floor)
        / on (chain, lane) clamp_min(rate(scaas_lane_cost_native_total[1h]), 1e-30) < 3600
    for: 5m
    labels: {severity: P1, runbook: rb-14-runway}
  - {alert: ScaasFinalityMismatch, expr: 'increase(scaas_indexer_final_mismatch_total[1h]) > 0', labels: {severity: P1, runbook: rb-06-chain-halt-or-finality-violation}}
  - {alert: ScaasRpcDivergenceSustained, expr: 'increase(scaas_rpc_quorum_disagreement_total[30m]) > 10', labels: {severity: P1, runbook: rb-05-rpc-divergence}}
  - alert: ScaasIndexerStalled
    expr: |
      (time() - scaas_indexer_last_progress_timestamp_seconds > 300)
        unless on (chain) (scaas_chain_state{state="halted"} == 1)
    labels: {severity: P1, runbook: rb-06-chain-halt-or-finality-violation}
  - {alert: ScaasRevertStreak, expr: 'max by (chain) (scaas_breaker_open{breaker="revert_streak"}) == 1', labels: {severity: P1, runbook: rb-16-simulation-gap-revert}}
  - {alert: ScaasWrapperBackingShortfall, expr: 'scaas_wrapper_leg_backing_ratio < 1', labels: {severity: P1, runbook: rb-11-wrapper-shortfall-or-depeg}}
  - {alert: ScaasWatchedCodeHashChanged, expr: 'scaas_watch_code_hash_changed == 1', labels: {severity: P1, runbook: rb-12-code-hash-change}}
  - {alert: ScaasForcedTransfer, expr: 'increase(scaas_watch_events_total{event="ForcedTransfer"}[10m]) > 0', labels: {severity: P1, runbook: rb-13-regulator-order}}  # silence it before a planned execution (RB-13)
  - {alert: ScaasAuditChainBroken, expr: 'increase(scaas_audit_verify_failures_total[1d]) > 0', labels: {severity: P1, runbook: rb-10-compromised-admin}}
  - alert: ScaasW3B01FastBurn
    expr: |
      scaas:w3b01_errors:ratio_rate1h > (14.4 * 0.005) and scaas:w3b01_errors:ratio_rate5m > (14.4 * 0.005)
        and sum by (chain) (increase(scaas_job_terminal_total[1h])) >= 20
    labels: {severity: P1, runbook: rb-03-stuck-lane}
  - {alert: ScaasBackupVeryStale, expr: 'time() - scaas_backup_last_success_timestamp_seconds > 12 * scaas_backup_interval_seconds', labels: {severity: P1, runbook: rb-08-restore}}
  - {alert: ScaasStoreDiskCritical, expr: 'node_filesystem_avail_bytes{mountpoint="/var/lib/scaas"} / node_filesystem_size_bytes{mountpoint="/var/lib/scaas"} < 0.10', labels: {severity: P1, runbook: rb-01-node-down-or-not-ready}}
  - {alert: Watchdog, expr: 'vector(1)', labels: {severity: none}}  # always firing; routed to the external dead-man's switch
- name: scaas-p2
  rules:
  - {alert: ScaasLaneHeadStuck, expr: 'scaas_lane_head_stuck_seconds > 300', labels: {severity: P2, runbook: rb-03-stuck-lane}}
  - {alert: ScaasFeeCapReached, expr: 'increase(scaas_submit_fee_cap_reached_total[15m]) > 0', labels: {severity: P2, runbook: rb-03-stuck-lane}}
  - alert: ScaasLaneRunwayLow
    expr: |
      (scaas_relayer_balance - on (chain, lane) scaas_relayer_balance_floor)
        / on (chain, lane) clamp_min(rate(scaas_lane_cost_native_total[6h]), 1e-30) < 4 * 3600
    for: 15m
    labels: {severity: P2, runbook: rb-14-runway}
  - {alert: ScaasBreakerOpen, expr: 'scaas_breaker_open == 1', for: 10m, labels: {severity: P2, runbook: rb-02-breaker-open}}
  - {alert: ScaasSimulationGapRevert, expr: 'increase(scaas_submit_reverted_total{class="other"}[15m]) > 0', labels: {severity: P2, runbook: rb-16-simulation-gap-revert}}
  - {alert: ScaasRpcDivergence, expr: 'increase(scaas_rpc_quorum_disagreement_total[15m]) > 0', labels: {severity: P2, runbook: rb-05-rpc-divergence}}
  - alert: ScaasW3B01SlowBurn
    expr: |
      scaas:w3b01_errors:ratio_rate6h > (6 * 0.005) and scaas:w3b01_errors:ratio_rate30m > (6 * 0.005)
        and sum by (chain) (increase(scaas_job_terminal_total[6h])) >= 20
    labels: {severity: P2, runbook: rb-03-stuck-lane}
  - alert: ScaasFinalityLatencySLO
    expr: |
      histogram_quantile(0.95, sum by (chain, le) (rate(scaas_job_stage_seconds_bucket{stage="broadcast_final"}[1h])))
        > on (chain) scaas:slo_target_seconds{slo="w3b04"}
    for: 30m
    labels: {severity: P2, runbook: rb-06-chain-halt-or-finality-violation}
  - alert: ScaasFeedClientStalled
    expr: |
      scaas_feed_last_poll_seconds > 600
        and on (namespace) (sum by (namespace) (scaas_relay_jobs{state=~"queued|leased|signed|broadcast"}) > 0)
    labels: {severity: P2, runbook: rb-15-feed-client-stalled}
  - {alert: ScaasStoreCommitUnknown, expr: 'increase(scaas_store_commit_unknown_total[1h]) > 0', labels: {severity: P2, runbook: rb-07-store-owner-loss}}
  - {alert: ScaasBackupStale, expr: 'time() - scaas_backup_last_success_timestamp_seconds > 3 * scaas_backup_interval_seconds', labels: {severity: P2, runbook: rb-08-restore}}
  - {alert: ScaasStoreDiskLow, expr: 'node_filesystem_avail_bytes{mountpoint="/var/lib/scaas"} / node_filesystem_size_bytes{mountpoint="/var/lib/scaas"} < 0.20', labels: {severity: P2, runbook: rb-01-node-down-or-not-ready}}
  - {alert: ScaasRestartLoop, expr: 'changes(scaas_process_start_time_seconds[1h]) > 3', labels: {severity: P2, runbook: rb-01-node-down-or-not-ready}}
  - {alert: ScaasWatchedEvent, expr: 'increase(scaas_watch_events_total{event!="ForcedTransfer"}[10m]) > 0', labels: {severity: P2, runbook: rb-13-regulator-order}}
  - {alert: ScaasFeeRecipientChanged, expr: 'increase(scaas_fee_recipient_changed_total[10m]) > 0', labels: {severity: P2, runbook: rb-10-compromised-admin}}
  - {alert: ScaasAdminLoginFailures, expr: 'sum(increase(scaas_admin_login_total{result=~"bad|locked"}[10m])) > 20', labels: {severity: P2, runbook: rb-10-compromised-admin}}
  - {alert: ScaasSponsorBudgetExhausted, expr: 'scaas_sponsor_budget_remaining_ratio == 0', labels: {severity: P2, runbook: rb-14-runway}}
  - {alert: ScaasGossipIsolated, expr: 'sum(scaas_gossip_peers) == 0', for: 10m, labels: {severity: P2, runbook: rb-17-gossip-degraded}}
- name: scaas-p3
  rules:
  - alert: ScaasRevertRateGuard
    expr: |
      sum by (chain) (increase(scaas_submit_reverted_total[7d]))
        / clamp_min(sum by (chain) (increase(scaas_submit_broadcast_total[7d])), 1) > 0.005
    labels: {severity: P3, runbook: rb-16-simulation-gap-revert}
  - alert: ScaasConsumedOnPrivate
    expr: |
      sum by (chain) (increase(scaas_job_terminal_total{outcome="consumed"}[1d]))
        / clamp_min(sum by (chain) (increase(scaas_job_terminal_total{outcome=~"mined|consumed|reverted|expired_after_sign"}[1d])), 1) > 0.01
        and on (chain) scaas_chain_info{profile="private"}
    labels: {severity: P3, runbook: rb-04-foreign-nonce}
  - {alert: ScaasMultiCompositionDrift, expr: 'abs(delta(scaas_wrapper_leg_reserve_share[24h])) > 0.20 or scaas_wrapper_leg_reserve_share > 0.80', labels: {severity: P3, runbook: rb-11-wrapper-shortfall-or-depeg}}  # 20 pp a day or one leg above 80 %: TW2 §8.4 drain signature
  - {alert: ScaasSponsorBudgetLow, expr: 'scaas_sponsor_budget_remaining_ratio < 0.20', labels: {severity: P3, runbook: rb-14-runway}}  # SRS §5.4: 20 % of the safe limit
  - {alert: ScaasNamespaceBudget90, expr: 'sum by (namespace, chain) (increase(scaas_gas_cost_native_total[30d])) > on (namespace, chain) (0.9 * scaas:finops_budget_native_30d)', labels: {severity: P3, runbook: rb-14-runway}}
  - {alert: ScaasStoreSlow, expr: 'histogram_quantile(0.99, sum by (le) (rate(scaas_store_tx_seconds_bucket{kind="journal"}[15m]))) > 0.05', for: 15m, labels: {severity: P3, runbook: rb-07-store-owner-loss}}
  - alert: ScaasRpcEndpointErrors
    expr: |
      sum by (chain, endpoint) (rate(scaas_rpc_requests_total{result!="ok"}[10m]))
        / clamp_min(sum by (chain, endpoint) (rate(scaas_rpc_requests_total[10m])), 1e-9) > 0.2
    for: 10m
    labels: {severity: P3, runbook: rb-05-rpc-divergence}
  - {alert: ScaasGossipThinMesh, expr: 'min by (chain) (scaas_gossip_mesh_peers{topic_kind="intent"}) < 4', for: 15m, labels: {severity: P3, runbook: rb-17-gossip-degraded}}
  - {alert: ScaasMeshPropagationSlow, expr: 'histogram_quantile(0.95, sum by (carrier, le) (rate(scaas_mesh_propagation_seconds_bucket[30m]))) > 3', for: 30m, labels: {severity: P3, runbook: rb-17-gossip-degraded}}
  - {alert: ScaasW3B01Trend, expr: 'scaas:w3b01_errors:ratio_rate3d > 0.005', labels: {severity: P3, runbook: rb-03-stuck-lane}}
  - {alert: ScaasMemoryHigh, expr: 'scaas_process_resident_memory_bytes > 512 * 1024 ^ 2', for: 30m, labels: {severity: P3, runbook: rb-01-node-down-or-not-ready}}  # 2× the §12 budget
  - {alert: ScaasConfigDrift, expr: 'scaas_config_toml_drift > 0', labels: {severity: P3, runbook: rb-01-node-down-or-not-ready}}
  - {alert: ScaasAppAvailability, expr: 'avg_over_time(probe_success{job="scaas-app"}[30d]) < 0.995', labels: {severity: P3, runbook: rb-01-node-down-or-not-ready}}
  - {alert: ScaasDrillOverdue, expr: 'time() - scaas_dr_drill_last_success_timestamp_seconds > 1.5 * scaas_dr_drill_cadence_seconds', labels: {severity: P3, runbook: rb-08-restore}}  # cadences §11.4
```

Prometheus retention ≥ 35 d (OA: the 30 d budget windows plus margin); long-term FinOps comes from `usage_day`, not
Prometheus.

### 5.2 Routing (`scaas/ops/alertmanager.example.yml`)

Route by `severity` and by owner: alerts `ScaasForcedTransfer`, `ScaasWatchedEvent`, `ScaasWrapperBackingShortfall`,
`ScaasWatchedCodeHashChanged`, `ScaasMultiCompositionDrift` go to the **issuer** (and compliance for regulated
tokens) in addition to the node operator; `ScaasNamespaceBudget90`, `ScaasSponsorBudget*` to the finance owner of
the namespace/sponsor account; `ScaasFeedClientStalled` to the ERP admin; everything else to the node operator.
`Watchdog` goes to the external dead-man's switch (expected every ≤ 5 min OA). Group by `chain`; repeat P1 every
30 min until acknowledged.

### 5.3 Dashboards (`scaas/ops/grafana/*.json`)

| # | Dashboard | Panels |
|---|---|---|
| 1 | Overview | SLO table with remaining error budget per §3.1 row; firing alerts; chains by state; build info; restarts |
| 2 | Submit and lanes | stage latencies p50/p95/p99 per chain; terminal outcomes; simulation results; replacements; inflight and head-stuck per lane; breakers; balances and runway |
| 3 | Chains, RPC, finality | final head age; indexer lag and progress; RPC errors/head lag per endpoint; quorum disagreements; final mismatches |
| 4 | Clients and feeds | per namespace: job API requests/codes, accepts by result, feed poll age, client cursor vs head, live jobs |
| 5 | Store and DR | journal latency, retries, commit unknown, fencing epoch, size and rows, backup age, drill age, restore epoch |
| 6 | Mesh and gossip | bus peers up/last pull, served, rate-limited; gossip peers by carrier, mesh size per topic, accept/ignore/reject, propagation, hints, assignment outcomes |
| 7 | FinOps | cost per namespace/token/lane (native), fees earned, sponsor spend vs budget, namespace budget burn, W3B-03 |
| 8 | Tokens and watchers | backing ratio per leg, Multi composition, watched events timeline, code-hash pins |
| 9 | Security and admin | logins by result, OIDC rejections, admin mutations by route/actor kind, CLI actions, fee-recipient changes, audit head, TLS handshake failures |

The app's metrics screen (app R171) and `metricsDashboardUrl` link to dashboard 1.

---

## 6. Traces (R236)

Span model (names are normative; v1 emits them as log events with `span` and `trace_id`; OP7 exports them):

| Span | Starts / ends | Attributes (SCaaS §13.1 trace contract) |
|---|---|---|
| `scaas.job` | accept → terminal (or final) | `job_uid`, `namespace`, `chain_key`, `kind`, `origin.producer`, `entry_ref` (if any), `mode`, `batch`, `nonce` (subject), `bus_scope` |
| `scaas.job.accept` | request → committed | `result`, `error_code` |
| `scaas.job.simulate` | per attempt | `result`, `gas_estimate`, `error_code` |
| `scaas.job.sign` | lease → journal commit | `lane`, `outer_nonce`, `tx_hash` |
| `scaas.job.broadcast` | each send/replacement | `tx_hash`, `kind` (`first`, `bump`, `resend`), `max_fee`, `priority_fee` |
| `scaas.job.include` | first broadcast → receipt | `gas_used`, `effective_gas_price`, `cost_native`, `block_number`, `outcome` |
| `scaas.job.finalize` | receipt → final range | `finality_depth` (mode/depth/quorum), `to_block` |

No payload, subject address or amount (R237). An ERP `traceparent` joins its outbox → push trace to the node's spans.
Traces never cross nodes (envelopes carry no trace field; a peer's landing shows as `consumed`).

---

## 7. Logs (R237)

One JSON object per line on stdout (journald/container runtime ships it). Fields:

| Field | When | Note |
|---|---|---|
| `ts` (RFC 3339, ms, UTC), `level`, `target`, `msg` | always | `tracing-subscriber` with feature `json` (the crate is already a dependency) |
| `store_id`, `incarnation` | always (span fields) | correlate restarts and restores |
| `chain`, `lane`, `namespace`, `job_uid`, `trace_id`, `span` | job and lane work | |
| `state_from`, `state_to`, `outer_nonce`, `tx_hash`, `digest`, `error_code`, `attempt` | transitions | `error_code` is the decoded custom error or node code |
| `listener`, `route`, `method`, `status`, `dur_ms`, `request_id`, `key_id` | requests | `key_id` is the public id, never the secret; no headers |
| `event = "audit"` + `actor_kind`, `actor`, `roles`, `route`, `target`, `result`, `before`, `after`, `row_hash` | every audit row | `***` for secret fields (NI §7.5) |
| `source_ip` | auth failures, rate limits only | personal data: same 30 d retention |
| `peer_id` | mesh/gossip lines | node identity, not a person |

Levels: `error` = needs a human; `warn` = degraded (breaker warn at 90 %, balance within 20 % of the floor); `info` =
transitions and audit; `debug` off in production. Rate limit: identical `warn` lines ≤ 1/10 s per (target, chain)
(OA). Retention ≤ 30 d at every sink; erasure requests need no node action (TSS §C.4 step 5) because nothing outlives
the store. A log pipeline that cannot enforce retention must receive `text` format at `warn` only.

---

## 8. FinOps (R238)

### 8.1 Measurement

| What | Where | Unit |
|---|---|---|
| Cost per job | `job.cost_native` (+ `gas_used`, `gas_price`) at `mined`/`reverted`; gap-fillers charged to the expired job (outcome `expired_after_sign`) or, without a job (after `accept-nonce`), to namespace `~lane` | smallest native unit (TSS §B1.2 per family) |
| Cost per namespace / token / lane | counters §4.3 | same |
| Fees earned | `scaas_fee_earned_total`, `usage_day.fee_earned` | token base units |
| Sponsored cost | TSS `sponsor_usage` and `scaas_sponsor_*` | native |
| Lane balance and floor | `scaas_relayer_balance`, `scaas_relayer_balance_floor` | native |

### 8.2 `usage_day` (store, all backends; A1 type rules)

```sql
CREATE TABLE usage_day (
  day            TEXT NOT NULL,                  -- 'YYYY-MM-DD', UTC
  chain_key      TEXT NOT NULL,
  namespace      TEXT NOT NULL,                  -- incl. '~gateway', '~mesh', '~dex', '~lane'
  token          TEXT NOT NULL,                  -- contract of metatx/signed_op, call target, or '' for '~lane'
  sponsor_policy TEXT NOT NULL DEFAULT '',       -- TSS policy name, '' = none
  jobs_mined BIGINT NOT NULL DEFAULT 0, jobs_reverted BIGINT NOT NULL DEFAULT 0,
  jobs_consumed BIGINT NOT NULL DEFAULT 0, jobs_expired BIGINT NOT NULL DEFAULT 0,
  gas_used       BIGINT NOT NULL DEFAULT 0,
  cost_native    TEXT NOT NULL DEFAULT '0',      -- decimal; summed in code, never in SQL (A1.3)
  fee_earned     TEXT NOT NULL DEFAULT '0',      -- decimal, token base units
  PRIMARY KEY (day, chain_key, namespace, token, sponsor_policy));
```

Upserted (read, add in code, write) inside the terminal-transition transaction; purged after 400 d (OA) by the
existing purge task. A lost-race (`consumed`) after broadcast is booked with its measured cost (TSS §B1.3).

### 8.3 Monthly report

`scaas-node report usage --from 2026-10-01 --to 2026-11-01 --prices prices.csv --format csv`, or the admin route
without conversion. `prices.csv`: `date,chain_key,asset,price,currency,source` (`asset` = `native` or a token
address); a missing price leaves the converted cells empty and lists the gap, never interpolates.

| Field | Source |
|---|---|
| period, `store_id`, node version | report run |
| per chain: family, profile | config |
| per (chain, namespace, token, sponsor policy): jobs by outcome, `gas_used`, `cost_native` | `usage_day` |
| native price used and its source; `cost_reporting` | price file |
| `fee_earned` (token units), token price, `fees_reporting` | `usage_day`, price file |
| **relayer margin / W3B-06** = `fees_reporting − cost_reporting` per chain (may be negative, SCaaS §6.9) | computed |
| cost per mined job, per consumed job | computed |
| sponsor utilisation: Σ spent ÷ Σ daily budget, days at budget, rejects by reason | `sponsor_usage`, `scaas_sponsor_jobs_total` |
| **W3B-03** = max hourly spend ÷ `gas_budget_per_hour` per lane; breaker-open minutes | Prometheus (`scaas_breaker_open`), lane cost |
| refills and fixed costs (infrastructure, RPC plans, audits) | operator inputs (treasury records), not the node |
| break-even estimate (SCaaS §6.9 formula) with this month's numbers | computed |

Per-business-document allocation (`entryRef` → invoice) stays with the client from the jobs-feed cost fields (TSS
§B1.4); the node report is the operator's view, including doors no client books.

### 8.4 Budget alarms

| Budget | Owner (§9) | Alarm (§5.1) | Enforcement |
|---|---|---|---|
| Lane gas per hour (`gas_budget_per_hour`) | finance owner of the node operator | `ScaasBreakerOpen` (`gas_budget`) | R55 breaker (BUILT) |
| Lane float / runway | node operator | `ScaasLaneRunwayLow` (< 4 h, P2), `…Critical` (< 1 h, P1) | `balance_floor` breaker |
| Sponsor daily budget | sponsor account owner | `ScaasSponsorBudgetLow` (< 20 %), `…Exhausted` | TSS R190 |
| Namespace monthly cost | finance owner of the tenant | `ScaasNamespaceBudget90` against `scaas:finops_budget_native_30d` | none (report + `max_live_jobs` quota) |

---

## 9. RACI (R239)

### 9.1 Roles

| Role | Who | Holds | Cannot |
|---|---|---|---|
| **Node operator** (NO) | the organisation running `scaas-node` and its on-call | host, `node.toml`, lane keystore passphrase, admin roles `viewer`/`operator`/`admin` | mint client credentials (needs `key_custodian`) |
| **key_custodian** (KC) | named person(s) in the operator organisation, not the `admin` holder in production | `key_custodian` role; `master_key` and lane-mnemonic secret custody (Shamir shares or KMS) | change chain config (unless also `admin`) |
| **Issuer** (IS) | token creator / asset issuer | on-chain `issuer` of `*_REG` tokens; chooses guardian and rateAdmin; holder disclosures | move funds without a compliance record (AS A1) |
| **Compliance** (CO) | issuer's compliance function | on-chain `compliance` (records orders); client-side `compliance_officer` (erasure, TSS §C.4) | execute orders (AS A2) |
| **Guardian** (GU) | issuer's on-call key | Multi `disableWrap` only (TW2 R136) | re-enable, mint, move funds |
| **rateAdmin** (RA) | a multisig/timelock contract (TW2 R135) | propose/cancel/execute rate, renounce | act within `rateDelay`, exceed `maxRateStepBps` |
| **ERP admin** (EA) | system administrator of the client ERP | API key entry, push/sync crons, `action_switch_to_push`, `action_acknowledge_store_change`, DB neutralisation | node configuration (R109) |
| **Owner / SCaaS team** (OW) | product owner and SCaaS engineering | releases, specs, default parameters, factory registrar multisig (O2), audits (O1) | operate a customer's node or keys |

Organisational functions of SCaaS §13.3 (security, legal, finance) sit inside these roles: the node operator's and
issuer's security and finance owners act as A where marked.

### 9.2 Matrix

R responsible · A accountable · C consulted · I informed · — not involved.

| Operation | NO | KC | IS | CO | GU | RA | EA | OW |
|---|---|---|---|---|---|---|---|---|
| Lane key rotation (drain, `PUT …/lanes`, refund to treasury) | A/R | R (new key) | — | — | — | — | I | C |
| `master_key` rotation (revokes all API keys and sessions) | A | R | — | — | — | — | R (new keys) | I |
| Client API key create/rotate/revoke | C | A/R | — | — | — | — | R (enters it) | — |
| Admin user lifecycle | C | A/R | — | — | — | — | — | — |
| Node identity key rotation (new `peer_id`, partners re-pin) | A/R | R | — | — | — | — | — | I |
| Chain pause / resume (`state paused`) | A/R | — | I | — | — | — | I | I |
| Chain halt (`state halted`) | A/R | — | I | I | — | — | I | C |
| Breaker reset, fee-cap raise | A/R | — | — | — | — | — | — | — |
| Gas budget / breaker parameters | R | — | — | — | — | — | I | C |
| Regulated token pause / unpause | I | — | A/R | C | — | — | I | — |
| `disableWrap` on a Multi leg | I | — | A | — | R | — | I | I |
| Rate change propose / execute / cancel | I | — | A | C | — | R | I | — |
| `renounceRateAdmin` / `renounceGuardian` | — | — | A | C | R (own role) | R (own role) | — | — |
| Token registration on a node / code-hash re-pin | A/R | — | C | — | — | — | I | — |
| `fee_recipient` change | A/R | C (second person) | — | — | — | — | — | — |
| Sponsorship policy and budget | R | — | C | — | — | — | C | — |
| Chain enablement `draft → active` (O4) | R | — | — | — | — | — | I | A |
| Mesh peer admission, URL change | A/R | — | — | — | — | — | — | I |
| Gossip ban / trust | A/R | — | — | — | — | — | — | I |
| Cutover per chain (`action_switch_to_push`) | C (preconditions §11.2 NI) | — | — | — | — | — | A/R | C |
| Cutover rollback (`pull`) | C | — | — | — | — | — | A/R | C |
| Store restore (node side) | A/R | R (re-revoke / rotate) | I | — | — | — | I | C |
| Restore acknowledgement and re-push (client) | C | — | — | — | — | — | A/R | — |
| Regulator order on a regulated token | I | — | R (freeze, execute) | A/R (record) | — | — | I | — |
| Regulator order on a permissionless token | R (stop relaying, §14 q1) | — | I | A | — | — | C | C |
| Erasure request (client data) | I | — | — | A/R | — | — | R | — |
| Incident: node / store / chain / lane | A/R (commander) | C | I | — | — | — | I | C |
| Incident: token (backing, depeg, code hash, forced transfer) | R (watch, evidence) | — | A (commander) | R | R | C | I | C |
| Incident: software defect in a release | R | — | I | — | — | — | I | A |
| Post-mortem | R | C | C | C | — | — | C | A (defects) / C |
| Release upgrade of the node | A/R | — | — | — | — | — | I | C |
| DR drill | A/R | R (shares, keys) | — | — | — | — | R (ack drill) | I |
| Alert rules and dashboards (`scaas/ops/`) | R (thresholds per deployment) | — | — | — | — | — | — | A (defaults) |

Human approval stays mandatory where SCaaS §13.3 says so (land gate, confidentiality horizon, budgets, factory
implementations, controlled-token interventions).

---

## 10. Incident runbooks

### 10.0 Common

Evidence first (T+1 min, SCaaS §13.4), before any change:

```bash
CFG=/etc/scaas/node.toml; NODE=http://127.0.0.1:9108; E=/var/lib/scaas-evidence/$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$E" && curl -fsS $NODE/metrics > "$E/metrics.txt"; curl -sS $NODE/readyz > "$E/readyz.json"
journalctl -u scaas-node --since -2h -o cat > "$E/node.log"        # or the container's log
sqlite3 /var/lib/scaas/node.db ".backup '$E/node.db'"              # PG: pg_dump -Fc; MySQL: mysqldump --single-transaction
```

Admin session (password never in argv) and helper used below:

```bash
read -rs PW; T=$(jq -n --arg n "$ADMIN" --arg p "$PW" '{name:$n,password:$p}' \
  | curl -fsS -X POST $NODE/v1/admin/login -H 'Content-Type: application/json' -d @- | jq -r .token); unset PW
adm() { m=$1 p=$2; shift 2; curl -fsS -X "$m" "$NODE$p" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' "$@"; }
```

Request bodies not fixed by NI §7.3 are fixed here: chain state `{"state": "active|paused|halted", "reason": "…"}`;
breaker reset `{"lane": "<label>|*", "breaker": "<name>|*"}`; chain patch fields as NI §7.3. Every call is audited.

#### RB-01 node down or not ready
1. `curl -sS $NODE/readyz | jq .reasons` — the reason names the runbook: `rpc:` ⇒ RB-05; `indexer lag` ⇒ RB-06;
   `store` / `not owner` ⇒ RB-07; `lane … used outside this store` ⇒ RB-04; `issuer failed closed` ⇒ OIDC (fix the
   IdP or `modes`).
2. Process down: `systemctl status scaas-node`; refuses to start with "store missing" ⇒ the volume is not mounted —
   **never** run `store init` on a production host to "fix" it (that creates an empty store; R110 halts every client).
3. Disk low: grow the volume, never delete store files (purge only removes terminal rows past retention). Restart
   loop or memory: evidence, roll back to the previous release (OW informed), open a defect.

#### RB-02 breaker open
1. `adm GET /v1/admin/chains/$C/lanes | jq '.[] | {lane, balance, breaker}'`.
2. `balance_floor` ⇒ RB-14 (it closes itself after funding). `gas_budget` ⇒ wait for the next UTC hour, or the
   finance owner approves a new value: `adm PATCH /v1/admin/chains/$C -d '{"breaker": {"gas_budget_per_hour": "…"}}'`.
   `base_fee_spike` ⇒ wait; reset only if the spike is understood: `adm POST /v1/admin/chains/$C/breaker/reset -d
   '{"lane":"*","breaker":"base_fee_spike"}'`. `revert_streak` ⇒ RB-16 first, then reset.
3. All lanes open (P1): work is held, nothing is lost; tell clients via the status page if > 30 min.

#### RB-03 stuck lane
Symptom: `scaas_lane_head_stuck_seconds` high, `ScaasFeeCapReached`, W3B-01 burn.

1. `adm GET /v1/admin/jobs?chain=$C&state=broadcast` — lowest `outer_nonce` per lane is the head.
2. EVM at the cap: raise for this chain (hot): `adm PATCH /v1/admin/chains/$C -d '{"max_fee_cap_gwei": 1000}'`
   (finance informed), or wait for fees to fall. **Never** abandon the nonce (N3) or re-sign the intent (N5).
3. Nonce gap (head nonce has no tx in any mempool: `eth_getTransactionByHash` returns null on every endpoint):
   restart the node — cold start `plan()` gap-fills journaled nonces not in the mempool and requeues their jobs.
4. Generic lane (non-EVM, one tx in flight): check the family explorer for the journaled hash; Sui re-sends the
   journaled bytes on start; Solana durable nonce account must be readable.
5. Lane unrecoverable (key issue): retire it: `adm PUT /v1/admin/chains/$C/lanes -d '{"lanes":[…without it…]}'`
   (`409 LANE_BUSY` until its rows are terminal), restart, drain its balance to treasury.

#### RB-04 foreign nonce
Symptom: `ScaasLaneForeignNonce`, `/readyz` "lane … used outside this store". The lane refuses to lease (correct).

1. Who else signs with this key? Another `scaas-node` on a copied `node.toml`/mnemonic, a restored old store, a
   manual wallet send. Check: `scaas-node addresses --config $CFG` on every host that holds the mnemonic; partner
   reports; the chain explorer for txs from the lane after `journal_max`.
2. Second node or unknown sender ⇒ treat the mnemonic as **exposed**: KC creates a new mnemonic, NO moves every
   lane (RB-03 step 5) and drains old lanes to treasury; incident (security) declared.
3. Explained by a restore of this store (RB-08) and no other user of the key ⇒ `systemctl stop scaas-node; scaas-node
   lane accept-nonce --chain $C --lane $L --config $CFG --confirm <pending−1>; systemctl start scaas-node` (R241).
4. `ScaasConsumedOnPrivate` (P3) is the soft version: someone else is landing our subjects' intents on a private
   chain; find the relayer from `MetaTransactionExecuted.relayer` in the feed.

#### RB-05 RPC divergence
1. `curl -fsS $NODE/metrics | grep -E 'scaas_rpc_(head_lag|requests)'` — which `endpoint` index lags, errors or
   disagrees.
2. Compare the block hash at the disputed height on every endpoint and one independent explorer.
3. Lying or forked endpoint: remove it from `rpc_urls` in `node.toml` (toml-only, R95), keep `len ≥ quorum`
   (otherwise the node refuses to start: add a replacement first), restart. Sustained divergence with a correct
   endpoint set ⇒ RB-06 (the chain itself forked).
4. The indexer holds while the quorum disagrees (N8): nothing is booked; submission continues.

#### RB-06 chain halt or finality violation
Chain halt (network stalled, `ScaasIndexerStalled` with `final_head` age rising on every endpoint):

1. Confirm on the network's status channel and two explorers.
2. `adm PUT /v1/admin/chains/$C/state -d '{"state":"paused","reason":"network halt"}'` — stops leasing, keeps
   indexing and tracking; jobs stay queued and expire by `valid_until` (clients re-issue). Do not bump or cancel
   broadcast txs (they wait in the mempool). Resume with `"active"` after 5 min of steady head growth (OA).

Finality violation (`ScaasFinalityMismatch`, `/readyz` "finality violated at <block>"):

1. Evidence; `adm PUT /v1/admin/chains/$C/state -d '{"state":"halted","reason":"finality violation"}'` (also stops
   indexing).
2. Determine the first differing final block with the quorum; list the ranges after it from `GET /v1/events`
   (client side) — every event at or after that block is suspect.
3. Inform every ERP admin of a namespace granted the chain (I in §9.2) with the block range; clients reverse or
   re-verify bookings manually. **No automatic rewind** (R242). Odoo: affected payments go to `needs_attention`.
4. Re-index from the last agreed block only after OW review: stop the node, `scaas-node index reset --chain $C --to
   <block> --confirm <block> --config $CFG` (R242 c; `store restored` is **not** used, the store is intact), start.
   Every client resets its event cursor for the chain to `<block>` before syncing again (Odoo: a system-group action
   on `blockchain.chain`, delivered with NI P5); dedup by `(chain_key, tx_hash, log_index)` absorbs the rest.

#### RB-07 store owner loss
Symptom: `ScaasFencingLost`, `NOT_OWNER` (503), `ScaasStoreCommitUnknown`.

1. The node stops leasing/journaling on its own and re-takes the lock with a new epoch (A1.1); if it cannot, a second
   process holds it. Find it: SQLite `fuser -v /var/lib/scaas/node.db.lock`; PostgreSQL `SELECT pid, application_name,
   client_addr FROM pg_stat_activity WHERE pid IN (SELECT pid FROM pg_locks WHERE locktype = 'advisory')`; MySQL
   `SELECT IS_USED_LOCK('scaas-node:<store_id>')`.
2. Stop the intruder (a second unit, a test container with the production `[store] url`), then let the node
   re-take the lock; `scaas_store_owner_epoch` increases by one.
3. PostgreSQL behind PgBouncer is refused by design (A1.1) — route the node directly to the server.
4. Repeated commit-unknown: database or network fault; the node's re-read-before-act rule keeps it safe; fix the
   transport.

#### RB-08 restore
Use only when the store is lost or corrupt (not for a bad config change). Sequence R240, commands §11.3. Clients halt
automatically (R110); ERP admins acknowledge after the node operator confirms the restore time and `restore_epoch`.

#### RB-09 compromised API key
1. `scaas-node key revoke $KEY_ID --config $CFG` (or `adm DELETE /v1/admin/keys/$KEY_ID`, KC) — hot, ≤ 2 s.
2. Scope: `adm GET "/v1/admin/audit?since=…"`, logs filtered on `key_id`; `adm GET "/v1/admin/jobs?namespace=$NS"`.
   An API key cannot forge subject signatures; it can push jobs of its namespace (and `call` jobs if `allow_call`),
   cancel unpublished jobs, read the namespace feeds (pseudonymous payment data: legal assesses notification).
3. Cancel unwanted queued jobs: `adm POST /v1/admin/jobs/$UID/cancel` (operator). Signed jobs run to completion.
4. KC issues a new key (`scaas-node key create --namespace $NS --scopes "submit read"`), EA enters it.
5. If the client server is compromised: suspend the namespace until cleaned:
   `adm PATCH /v1/admin/namespaces/$NS -d '{"state":"suspended"}'`.

#### RB-10 compromised admin
1. Disable the account from the host: `scaas-node admin disable $NAME --config $CFG` (bumps `session_epoch`; all its
   sessions die). OIDC: disable the subject at the IdP; if the IdP is suspect remove the issuer from
   `[api.admin_auth]` and restart (`modes = ["builtin"]`).
2. Review `adm GET "/v1/admin/audit?since=<last trusted>"` for: `fee_recipient`, tokens, lanes, mesh peers and URLs,
   policy, sponsorship policies, namespaces (`allow_call`, grants), users and keys. Revert each change through the
   same routes (audited as the reverting user).
3. Audit chain broken (`ScaasAuditChainBroken`) ⇒ the store was edited outside the node: treat the host as
   compromised: preserve evidence, rotate `master_key` (KC), rotate lane keys (RB-03 step 5), restore from a backup
   older than the break if config was altered (RB-08), declare a security incident.
4. Rotating `master_key` revokes every client API key and every session at once: EA re-enters new keys.

#### RB-11 wrapper shortfall or depeg
Shortfall (`scaas_wrapper_leg_backing_ratio < 1`): a leg's `balanceOf < reserve` (blacklist burn, negative rebase,
confiscation, or a bug).

1. Evidence: `adm GET /v1/admin/chains/$C/watch` (pins, ratios, shares); confirm `legOf(u)` and
   `underlying.balanceOf(token)` on two endpoints.
2. Issuer (commander) informs holders; the app shows per-leg backing before a wrap (TW2 §8.4). Wrap into other legs
   is **not** stopped by the contract (owner decision L3): the issuer asks integrators to pause intake; the guardian
   may `disableWrap` the affected leg (stops inflow of that asset only).
3. Permissionless token: no admin can fix it; migration to a new token is the remedy (SCaaS §13.6).

Depeg on a Multi leg (composition drift, external price signal):

1. Guardian submits `disableWrap(u, reason)` **privately** (private relay or builder bundle, TW2 §8.4), not through
   the public mempool and not through an open-mesh job (`bus_scope = restricted`).
2. Exits stay open by design; communicate expected composition movement; no re-enable exists (a new token if the leg
   must return).
3. Adjustable-rate Multi: RA must not execute a pending decrease while a leg is disabled
   (`RateDecreaseWithDisabledLeg` blocks it anyway); cancel pending changes during the incident.

#### RB-12 code-hash change
1. `adm GET /v1/admin/chains/$C/watch` shows the role and the new hash/implementation.
2. Underlying upgraded (e.g. a stablecoin proxy): issuer reviews the new implementation's behaviour (freeze,
   fee-on-transfer, rebase); until reviewed, the node operator may stop relaying jobs for the affected token:
   `adm DELETE /v1/admin/chains/$C/tokens/$TOKEN` (stops intake of every op on that token, unwraps included —
   use only when the risk outweighs blocking exits; the contract itself stays open to direct calls).
3. Role contract changed (rateAdmin/issuer/compliance Safe upgraded, guardian is a contract): verify with the role
   owner; re-pin when accepted: `adm PUT /v1/admin/chains/$C/tokens/$TOKEN/pins -d '{}'`.
4. Token or registry code itself changed: impossible for EIP-1167 clones of immutable implementations ⇒ wrong
   address registered or RPC lying ⇒ RB-05.

#### RB-13 regulator order
Regulated token (`*_REG`, AS §3.5):

1. Legal validates the order (scope, jurisdiction, beneficiary). CO records it: `recordOrder(orderId, docHash,
   subject, beneficiary, maxAmount)` from the compliance multisig (a Safe transaction, optionally submitted as a
   node `call` job by the issuer's ERP namespace).
2. Before execution, IS creates an Alertmanager silence for `ScaasForcedTransfer` on that token for the planned
   window (an unplanned forced transfer must page).
3. IS: `freeze(subject, ref)`, then `forceTransfer(recordId, amount)` ≤ `maxAmount`; `unfreeze` when the order says
   so; CO `revokeOrder` stops further execution.
4. `OrderRecorded` without a matching internal record (P2 `ScaasWatchedEvent`) ⇒ compliance key compromise (AS A2):
   CO revokes the record, rotates the multisig signer, IS refuses execution.

Permissionless token: no on-chain power exists by design (SCaaS §4.5). The operator can only stop relaying: suspend
the namespace concerned, unregister the token, or (if adopted, §14 q1) deny the subject address; legal answers the
order with that limit stated.

#### RB-14 runway
1. `scaas-node addresses --config $CFG` lists lane addresses; fund from treasury to the float target (~50 tx,
   SCaaS §13.2); the `balance_floor` breaker closes on the next 15 s sample.
2. Runway falling while volume is flat ⇒ fee regime changed (base-fee spike, L1 data fee on rollups): finance
   reviews budget; consider raising `gas_budget_per_hour` only with approval.
3. Sponsor budget exhausted: the policy behaves per `on_exhausted`; the sponsor owner raises the budget (`adm PATCH
   /v1/admin/sponsorship/policies/$ID`, admin) or accepts rejects.

#### RB-15 feed client stalled
1. Node side: `scaas_job_api_requests_total{namespace=$NS}` — no requests ⇒ client stopped; `401` ⇒ key revoked or
   clock skew (> 300 s, NTP); `410 CURSOR_EXPIRED` ⇒ client recovery (integration §4.3).
2. Odoo: crons `cron_node_push`/`cron_node_sync` active, `blockchain.node.needs_attention` (store change ⇒
   acknowledge after RB-08 confirmation), last error on the node form.

#### RB-16 simulation-gap revert
1. `adm GET "/v1/admin/jobs?chain=$C&state=reverted"`; logs by `job_uid` (`span=scaas.job.simulate` vs `include`).
2. Classify: state changed between simulation and inclusion (front-run balance move, attestation expiry, pause) ⇒
   expected drift, document; simulation ran against a different block/endpoint than inclusion ⇒ RPC issue (RB-05);
   decoded error the simulation should have seen ⇒ defect (OW): keep `revert_streak` open, pause the chain if needed.
3. Reset after explanation: `adm POST /v1/admin/chains/$C/breaker/reset -d '{"lane":"*","breaker":"revert_streak"}'`.

#### RB-17 gossip degraded
1. `adm GET /v1/admin/gossip` (mesh size per topic), `adm GET /v1/admin/gossip/peers` (scores, carriers).
2. Zero peers: bootstrap multiaddrs (toml), UDP 4001 / TCP 4001 reachability, `scaas_tls_handshake_failures_total`
   (PQ-only QUIC vs classical peers, A2 R114).
3. Thin mesh with healthy peers: graylisting from our own rejects (version skew, A2 E2) — upgrade or check clock.

---

## 11. Backup, restore, DR

### 11.1 RPO / RTO per backend (OA)

RPO here is "after loss of the store's disk"; on the same disk every committed journal transaction is durable
(SQLite `synchronous = FULL`; PG/MySQL durable commit, NI §9.2). RTO = start of restore → `/readyz` green.

| Backend | Continuous protection | Periodic | RPO | RTO | Reason |
|---|---|---|---|---|---|
| SQLite | Litestream (WAL shipping to an S3-compatible bucket, `sync-interval: 1s`) | `sqlite3 node.db ".backup …"` every 5 min to a second disk, kept 7 d; daily copy off-site, kept 35 d | ≤ 10 s with Litestream; ≤ 5 min without | 30 min | `.backup` uses SQLite's online backup API (safe while the node runs; the owner lock is on `<db>.lock`, not the file); Litestream is an external process, no node dependency |
| PostgreSQL | WAL archiving (`archive_mode = on`, `archive_timeout = 60`) with pgBackRest or `pg_basebackup` + `archive_command` | base backup daily, kept 35 d | ≤ 60 s (0 with a synchronous standby) | 30 min | PITR to any second, but per cluster: give the store its own cluster; the advisory lock is not restored state |
| MySQL 8 | binlog (`binlog_format = ROW`, `sync_binlog = 1`) streamed off-host (`mysqlbinlog --read-from-remote-server --raw --stop-never`) | daily physical backup (XtraBackup) or `mysqldump --single-transaction`, kept 35 d | ≤ 60 s | 45 min | binlog replay is slower than PG WAL replay |

| Component | RPO | RTO | Mechanism |
|---|---|---|---|
| Lane state | — | minutes | cold start `plan()`; after restore `lane accept-nonce` (R241) |
| `master_key` | must never be lost | 15 min | secret store / Shamir 2-of-3 (OA) held by KC; loss ⇒ every API key and session re-issued |
| Lane mnemonic | must never be lost | 30 min | Shamir 2-of-3 (OA) or KMS-native backup (SCaaS §13.5); loss ⇒ lane gas lost, new lanes |
| Node identity key | — | 30 min | secret store; loss ⇒ new `peer_id`; bus partners re-pin SPKI |
| `node.toml` | per change | 15 min | version control without secrets (secrets are references, R20) |
| Logs (off-host) | stream | — | ≤ 30 d retention (R237); needed for post-backup audit replay |
| Private chain | 0 | 60 min | validator snapshots every 6 h + archive node (SCaaS §13.5) |

Backup scripts write `scaas_backup_last_success_timestamp_seconds{backend}` and `scaas_backup_interval_seconds` to the
textfile collector. Backups are encrypted at rest (NI T5: payloads hold payer, payee, amounts) and inherit the 30 d
data limit only for job content older than the store's own retention — a 35 d backup holds ≤ 30 d of jobs.

### 11.2 What a restore loses and how it is recovered

| Lost after the backup point | Recovered by |
|---|---|
| Jobs accepted after the backup | client re-push after acknowledgement (idempotent; R91) |
| Journal entries (`signed`) after the backup | the chain: their txs land or drop; `lane accept-nonce` adopts the nonces; subjects' nonces prevent double execution (G1) |
| Feed items after the backup | indexer re-delivers from the restored `chain_index` (ranges idempotent) |
| Credential revocations, role changes after the backup | off-host audit log events (R237) ⇒ re-revoke; if logs are incomplete ⇒ rotate `master_key` (T19) |
| Config changes after the backup | audit log events ⇒ re-apply |
| Sponsor reservations | recomputed from live jobs at start (TSS §B1.7) |

### 11.3 Restore commands

```bash
systemctl stop scaas-node
# 0. evidence: keep the broken store, do not overwrite it
mv /var/lib/scaas/node.db /var/lib/scaas/node.db.broken-$(date -u +%s) 2>/dev/null
# 1a. SQLite (Litestream)
litestream restore -o /var/lib/scaas/node.db s3://<bucket>/scaas/node.db
# 1b. SQLite (periodic copy)
cp /backup/scaas/node-<ts>.db /var/lib/scaas/node.db
sqlite3 /var/lib/scaas/node.db 'PRAGMA integrity_check'        # must print "ok"
chown scaas:scaas /var/lib/scaas/node.db && chmod 0600 /var/lib/scaas/node.db
# 1c. PostgreSQL (into an empty cluster): pgbackrest --stanza=scaas --type=time --target='<UTC time>' restore
# 1d. MySQL: restore the base backup, then
#     mysqlbinlog --start-position=<from backup> --stop-datetime='<UTC time>' binlog.0* | mysql scaas
# 2. mark the restore (mandatory; bumps restore_epoch, audited)
scaas-node store restored --config /etc/scaas/node.toml
# 3. re-revoke from off-host audit events newer than the backup point
#    (event=audit, route=keys revoke / admin disable / users roles); otherwise rotate master_key
scaas-node key revoke <key_id> --config /etc/scaas/node.toml
scaas-node admin disable <name> --config /etc/scaas/node.toml
systemctl start scaas-node
curl -sS http://127.0.0.1:9108/readyz | jq .reasons            # lanes "used outside this store" ⇒ RB-04 step 3
```

Then ERP admins acknowledge (`action_acknowledge_store_change`) and re-push (integration §16.3).

### 11.4 DR drills (R243, cadences OA)

| Drill (`drill` label) | Cadence | Pass criterion |
|---|---|---|
| `restore_<backend>` — restore the latest backup to a scratch host, `store restored`, start against a testnet | quarterly per backend in use | RTO met; `/readyz` green; Odoo halts and acknowledges on the test database |
| `lane_accept_nonce` — restore an older backup of a testnet store, adopt nonces, land a new job | quarterly | no lane stuck after 10 min |
| `indexer_kill` — stop the indexer task (or block RPC egress) without notice | quarterly | `ScaasIndexerStalled` pages within 6 min |
| `rpc_lie` — point one endpoint at a forked devnet | quarterly | divergence alert, no range written from the liar |
| `dead_man` — stop Prometheus | quarterly | external switch alerts within 10 min |
| `key_recovery` — reconstruct `master_key` and the lane mnemonic from shares on an offline host | semi-annually | both reconstruct; shareholders reachable |
| `guardian_testnet` — `disableWrap` on a testnet Multi via a private submission | annually per issuer with a Multi token | executed within 15 min of the call |
| `cutover_rehearsal` — NI §11.2 on testnet before each production chain cutover | per cutover | preconditions verified, rollback exercised |

Each run writes its timestamp; a failed drill is a P3 with an owner and a date.

---

## 12. Capacity (R244)

Reference hardware class **H1**: one host, 8 vCPU, 24 GiB RAM, NVMe SSD, shared with an ERP stack and its database
(the development host class). All figures are OA estimates to be **measured** in stream OP1 (a load test that runs
alone, OOM rule) and replaced by measured values.

| Resource | Budget / limit | Reason |
|---|---|---|
| Node RSS | ≤ 256 MiB without gossip; + 64 MiB with gossip at 50 peers (A2 R126) | leaves the ERP its memory; alert at 2× (P3) |
| Node CPU | < 1 core sustained at the rated load | signing (k256 ≈ 0.1 ms), JCS + SHA-256, JSON; gossip < 5 % of one core at 200 msg/s (R126) |
| Store journal transactions (SQLite, `synchronous = FULL`) | ≤ ~300/s (fsync ≈ 1–3 ms on NVMe, one connection) | each job ≈ 5–7 transactions over its life |
| **Rated sustained load per node** | **10 jobs/s** (≈ 860 000/day), alert at 70 % | ⅕ of the store ceiling, headroom for bursts and indexer writes |
| PG/MySQL store | ≈ the same per node (network RTT replaces fsync; one owner, serialized on the fencing row) | A1.2 |
| Store size | ≈ 2.5 KB per job across `job`, `job_event`, `feed_item` ⇒ ~60 MB/day at 24 000 jobs/day, ~1.8 GB at 30 d retention; `usage_day` negligible | research §06.10.2 order of magnitude; disk alerts at 80 %/90 % |
| EVM lane | ≤ 16 txs in flight per lane (typical client per-account pending-slot limit) ⇒ Gnosis ≈ 3 tx/s per lane; private 9000 bound by block gas | the mempool, not the node, is the limit |
| Generic lanes (one tx in flight) | ≈ 1 ÷ `include` latency: Sui ~2/s, Aptos ~1/s, Solana ~1/s, Hedera ~0.3/s, Cosmos and Soroban ~0.15/s, TON ~0.1/s per lane | lanes needed = target rate ÷ per-lane rate (≤ 8 lanes per chain, R244) |
| Job API | 20 POST rps (burst 40) and 10 GET rps per key; batches ≤ 50; feed pages ≤ 500 items / 1 MiB; ≤ 4 long-polls per key | NI §5.4 |
| Gateway | `MAX_INFLIGHT` 64; body 64 KiB | NI §3 |
| Namespaces / chains / lanes / tokens | ≤ 32 / ≤ 16 / ≤ 8 per chain / ≤ 64 per chain | R244 label caps |
| `/metrics` | ≤ ~5 000 series, ≤ 1 MiB | scrape 15 s |

Above the rated load: a second node on **different chains** (R97), not a bigger store.

---

## 13. Streams

| # | Stream | Content | Depends on | Status |
|---|---|---|---|---|
| OP1 | Metrics core | renderer histograms; §4.3 submit/lane/RPC/indexer/store/HTTP/process/chain series; `revert_streak` breaker; finalize map; load test on H1 | NI P3, P4 | **SPECIFIED** |
| OP2 | Logs and trace ids | `[log] format`, JSON fields, `traceparent` on gateway/job API, `job.trace_id`, audit mirror events, warn rate limit | NI P2 | **SPECIFIED** |
| OP3 | Ops watch | `watch_pin`, code-hash and slot reads, wrapper backing/composition, watched events, admin `…/watch` and `…/pins` | NI P4, TW2 T7, AS AS7 | **SPECIFIED** |
| OP4 | FinOps | cost columns for every job, `usage_day`, cost/fee counters, `report usage` CLI, `/v1/admin/usage` | NI P3, TSS SP1 | **SPECIFIED** |
| OP5 | Integrity and DR tooling | `lane accept-nonce`, `index reset` (+ the Odoo cursor-reset action), final-hash recheck, audit-chain verification, backup scripts per backend, restore runbook rehearsal | NI P3/P4; PG/MySQL parts after P1b | **SPECIFIED** (SQLite parts before the first production cutover, P6) |
| OP6 | Ops bundle | `scaas/ops/prometheus/scaas-rules.yml` (§5.1), Alertmanager example, nine Grafana dashboards, promtool rule tests | OP1 | **SPECIFIED** |
| OP7 | OTLP export | cargo feature `otel`, spans of §6 | OP2 | PLANNED |

Order: OP2 (small, any time after P2) → OP1 with P3/P4 → OP5 SQLite part and OP6 before P6 cutover → OP4 with SP1
→ OP3 after TW2 T7 → OP5 PG/MySQL with P1b → OP7. Heavy builds and the OP1 load test run one at a time.

Tests: renderer golden tests extended per new family (as `metrics_text_format_golden`); promtool `test rules` with
synthetic series for every alert of §5.1; `revert_streak` boundary (2 vs 3 in 15 min, `race` excluded);
`usage_day` upsert under concurrent terminal transitions and decimal sums; `accept-nonce` refuses without quorum
agreement or with a wrong `--confirm`; final-hash recheck on a forked devnet; audit verification detects a single
edited row; log redaction test (no payload/address/amount/secret field in any line of an e2e run, grep-based).

---

## 14. Open questions (owner)

1. **Subject denylist for permissionless tokens.** A regulator may order an operator to stop relaying for an
   address. Today the only levers are namespace suspension and token unregistration (both coarse). Add an
   admin-managed `deny_subject (chain_key, address, ref, until)` checked at accept on every door, or keep the coarse
   levers and state the limit?
2. **SLA.** Stay internal objectives (this spec), or turn some rows of §3.1 into a contractual SLA with credits for
   managed deployments (which then needs SCaaS-side monitoring of customer nodes)?
3. **Who hosts monitoring for customer-run nodes**: the customer (telemetry never leaves its infrastructure) or the
   SCaaS team as a managed service (R231 needs an off-host Prometheus either way; §9.2 marks NO as accountable and
   would change to OW for managed nodes)?
