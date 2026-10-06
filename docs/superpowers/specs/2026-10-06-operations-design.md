# Operations: SLOs, telemetry, FinOps, RACI, incident response and disaster recovery (component spec C)

Status: draft rev 1.2, 2026-10-06. Rev 1.1 folded in the owner's answers (denylist, internal SLOs, customer-run
monitoring, operator independence); rev 1.2 folds in independent review 1 (FIX-THEN-GO, H1–H4, M1–M11, L1–L6;
disposition §15). Component spec **C**. Short name **OPS**. Code at `scaas` `main` 5f1d327 (node store P1 built; job
API, admin API, mesh bus, gossip SPECIFIED). **Nothing in this spec is built** except the metrics marked BUILT (§4.2).
Rulings: **R230–R247** (§2). R150–R172 belong to the app spec, R180–R199 to spec B (TSS), R200–R216 to spec A (AS).
Owner ruling of 2026-10-06: **the spec proposes default numbers with reasons; every number is owner to approve.**
Owner, rev 1.1: **"SCaaS means the smart contracts themselves are the API services that run the business
services."** The node is infrastructure anyone can run to reach those contract services (submit, index, relay), not
the product; **how a node operates — its policies — is up to whoever runs it** (R247). Everything here is a
recommendation to node operators, never a network-wide rule. Market-neutral: no jurisdiction-specific law; amounts in
neutral units; "reporting currency" means the deployment's own.

**OA** marks a default number proposed by this spec (reason next to it); **owner to approve**. Changing an OA number
never changes a ruling's reasoning.

Amends (listed; text in those files is not rewritten here):

| Short | File | How |
|---|---|---|
| SCaaS | `docs/SCaaS.md` | §13.1 W3B-01…06, trace contract; §13.2 unit cost; §13.3–§13.5: PLANNED → SPECIFIED, link here; §13 tables stay the summary |
| NI | `specs/2026-10-06-node-independence-design.md` rev 3.3 | `deny_subject` + intake and lease checks (R246, §4.5); `store restored` also pauses every chain and runs the purge (R240); client acknowledgement also cancels jobs the client holds dead (§10.1, R240); `[modules] metrics_bind` (R230); `PATCH …/tokens/{addr} {active}` (§4.4); `breaker_latch`, `lane_adopted`, `usage_day` tables; `job.trace_id`; CLIs `lane accept-nonce`, `index reset`; R103 precondition for `allow_call` (§11.2); `scaas_audit_head_info{hash}` → `scaas_audit_head_seq`, OIDC `issuer` label → issuer index; foreign nonce also as a latched gauge (§4.3) |
| MESH, A2 | relayer-mesh rev 3, gossip amendment rev 2.1 | `scaas_mesh_propagation_seconds` added; other names unchanged |
| TSS | tender-sponsorship-shredding rev 1.2 | cost columns (§B1.2) written for **every** job (R238); §C.4 step 5 reads "within `job_retention_secs` + backup retention" (R237) |
| TW2, AS | token wrappers v2 rev 1.2, asset suite rev 1.1 | "node/ERP should alert" items become the ops watch (R235) |

---

## 1. Scope and conventions

### 1.1 In scope

SLIs/SLOs per component with error budgets; metric names and labels; alert rules, severities, routing; dashboards;
trace scope; structured logs and their personal-data rules; FinOps measurement and the monthly report; RACI; incident
runbooks with commands; backup/restore with RPO/RTO per store backend; DR drills; capacity limits.

### 1.2 Non-goals

- High availability for one `(company, chain)` (R97, NI §18.3 stays deferred). DR here is restore, not failover.
- Automatic lane refill from a treasury (SCaaS §13.2 "auto-refill" stays PLANNED; runway alerts replace it in v1).
- A price oracle in the node (TSS R189 unchanged). FinOps conversion uses an operator-supplied price file.
- Contractual SLAs or service credits (owner, rev 1.1): every target is an internal objective of whoever runs a node.
- Telemetry from the app (`scaas/app`). The app sends nothing; W3B-05 is a release benchmark (R233).
- Multi composition-drift series (TW2 §8.4): deferred (review L6); leg backing (R235) covers the loss case.

### 1.3 Severities (R232; recommended, each operator routes its own)

| Sev | Meaning | Routing | Acknowledge within (OA) | Why |
|---|---|---|---|---|
| **P1** | Integrity at risk (journal, nonce, feed, audit, reserve) or service stops within the hour | page 24/7, on-call of the accountable role (§9) | 15 min | SCaaS §13.4 starts the clock at T+0; research §12.11 reaction window (loss = cap rate × 15 min) |
| **P2** | Degraded, or a security-relevant change to verify the same day | page in business hours, ticket otherwise | 4 h | one working half-day; nothing here loses data while waiting |
| **P3** | Trend, budget or hygiene | ticket | next business day | |

---

## 2. Rulings

Format: **ruling — reason — cost if wrong.**

- **R230** **Metrics = Prometheus text rendered by the existing hand-written renderer (`admin.rs` `render`); no
  metrics crate.** Prefix `scaas_`; base units (seconds, bytes, smallest native unit); counters `_total`; histograms
  with fixed buckets. Labels only from the §4.1 allowlist: never a subject address, payer, amount, `tx_hash`, job uid,
  `entry_ref`, open-mesh peer, URL or IP; RPC endpoints and OIDC issuers by index, because URLs may embed provider
  keys. **Every counter and latched gauge is emitted at 0 for every configured label set from process start** (so
  `increase()` sees the first event, review H3). New **`[modules] metrics_bind`** (default `""` = served on
  `admin_bind` as today) serves only `/metrics`, `/readyz`, `/healthz`; the `scaas/ops` bundle assumes it, bound to
  a private monitoring network or behind an mTLS proxy. Exposing `admin_bind` to monitoring is never recommended;
  metrics name tenants, lanes, tokens and balances and are internal data. — R51 already hand-writes the format
  (golden test); one dependency less on a box with an OOM rule. — If wrong: a crate swap keeps every name.
- **R231** **SLOs, alerts and dashboards are evaluated outside the node, by whoever runs it** (owner: customer-run
  nodes are monitored by the customer): Prometheus + Alertmanager on infrastructure that is neither the node's host
  nor the ERP's, plus an external dead-man's switch fed by an always-firing `Watchdog`. The node exports raw series
  only. SCaaS ships the rule file, Alertmanager example, dashboards and watch scripts in `scaas/ops/` as the
  recommended copy of §5; operators adopt, change or replace them. — Research §12.11: monitoring on the monitored
  host is switched off by whoever owns that host. — If wrong: one more host per deployment.
- **R232** **Three severities** (§1.3); P1 = exactly the `scaas-p1` group of §5.1. — Pages that do not mean
  "integrity or outage" train people to ignore pages. — If wrong: an alert moves one group.
- **R233** **W3B as the node can measure it.** Each job counts once, at its first terminal transition, in
  `scaas_job_terminal_total{chain,outcome}`, `outcome ∈ mined, consumed, reverted, expired_after_sign,
  dead_before_sign, cancelled`; a late `mined → reverted` adds `scaas_job_late_revert_total{chain}` instead of a
  second count. **W3B-01** = (`mined` + `consumed`) ÷ (`mined` + `consumed` + `reverted` + `expired_after_sign`):
  `consumed` is good (landed elsewhere, or the subject chose another intent). **W3B-02**: each reverted receipt of
  ours is `race` (R80 read shows the subject nonce consumed) or `other`; target `other` = 0, each one a P2; **≥ 3
  `other` in 15 min on a chain (OA: three rules out one bad payload; 15 min = one reaction window) opens a
  chain-level breaker `revert_streak`**, persisted in `breaker_latch (chain_key, breaker, opened_at, reason)` in the
  transaction that records the third revert, re-read at start, cleared only by `breaker/reset` (audited). It stops
  new work only (N9). **W3B-05** is a release benchmark (prover time on reference devices + verifier gas tests).
  **W3B-06** is a monthly report figure (§8). — SCaaS §13.1 counts "finalized"; the node knows `mined` at once; a
  mined job that never finalizes is a finality violation (R242). — If wrong: W3B-01 over-reports by the paged, ~0
  violation rate.
- **R234** **Job timing = `scaas_job_stage_seconds{chain,stage}`**, `stage ∈ queue` (accepted → first `leased`),
  `sign` (`leased` → `signed`), `include` (first broadcast → `mined`), `finalize` (`mined` → final range covering the
  mined block), `broadcast_final` (= W3B-04), `e2e`. The last three use a bounded in-memory map keyed by **job uid**
  (`accepted_at, broadcast_at, mined_at, mined_block`), drained when the indexer writes a range with `to_block ≥
  mined_block` (works for `call` txs and bumped hashes); lost on restart (samples lost, never wrong). — No new `job`
  index for a metric. — If wrong: a restart drops ≤ one finality window of samples. `// ponytail: in-memory finalize
  map (cap 50 000 OA); persist only if restarts make W3B-04 blind.`
- **R235** **Ops watch** for registered EVM/Hedera tokens: (a) **in the node**: leg backing
  (`underlying.balanceOf(token) ÷ reserve_i`, only for legs that exist) polled every 300 s (OA: ~10 reads per token
  per 5 min; a TW2 drain is one block, so polling only shortens the reaction) at the final head, and **watched
  events** from the final feed (§4.3, label `token`); (b) **outside the node** (review L6): code-hash pins — token,
  underlyings, `rateAdmin`, `guardian`, `issuer`, `compliance`, `registry`, EIP-1967 implementation and beacon
  slots — by the `scaas/ops/watch-code-hash` script, which reads the token list (admin API with an OIDC machine
  token, R109, or a static file), keeps its pins in its own state file, latches
  `scaas_watch_code_hash_changed{chain,token}` in a textfile until `--repin`. Non-EVM upgrade signals (Solana upgrade
  authority, Aptos package upgrades, Sui `UpgradeCap`) PLANNED. — Backing needs the node's registry and final head;
  code hashes need nothing from the node, so they stay out of it. — If wrong: a few RPC reads every 5 min.
- **R236** **Traces: no OpenTelemetry SDK in the v1 binary.** Gateway and job API accept a W3C `traceparent` (the
  `POST /v1/jobs` header applies to every item); the trace id (32 hex) is stored as `job.trace_id` (absent ⇒
  generated) and carried by lifecycle log lines and jobs-feed items. Span names fixed now (§6); OTLP export = cargo
  feature `otel`, default off, stream OP7 (PLANNED). — OpenTelemetry + OTLP + `tonic` would be the node's heaviest
  dependency set (OOM rule); `job_event` already is a durable per-job trace. — If wrong: correlation via logs until OP7.
- **R237** **Logs = JSON lines in production** (`[log] format = "json" | "text"`, default `text`; any deployment
  holding value runs `json`), fields §7. Never logged: payloads, signatures, subject addresses (`from`, `to`, payer,
  payee, maker, denylisted parties), amounts, salts, openings, secrets, tokens, HMAC headers, passwords, RPC URLs.
  Allowed: lane and contract addresses, `tx_hash`, digests, job uid, `entry_ref` (random, R9/R198), `namespace`,
  `trace_id`, `deny_id`; source IPs only in auth-failure and rate-limit lines. **Every `audit_log` row is mirrored as
  a `warn`-level log event** (`event = "audit"`; secrets and deny addresses as `***`) so a lost store's last audit
  entries survive off-host (R240) and survive a `warn`-only sink. **Retention ≤ 30 d (OA, = `job_retention_secs`)**
  at every log sink; **backups and evidence copies ≤ 7 d (OA)**, so a node-held copy of pseudonymous job data
  lives ≤ 37 d (TSS §C.4 step 5 amended accordingly). — R195. — If wrong: an auditor gets a 30-day log window;
  long-term evidence is the audit table and the chain.
- **R238** **FinOps measurement**: the TSS cost columns (`gas_used`, `gas_price`, `cost_native`) are filled for every
  job at `mined`/`reverted` and for gap-fillers; the same transaction upserts a durable daily rollup **`usage_day`**
  (§8.2; 400 d OA = a fiscal year plus a month). Conversion to the reporting currency happens only in the report,
  with an operator-supplied price file. **Budget alarms are Prometheus rules; enforcement stays with R55
  `gas_budget`, TSS sponsor budgets and `max_live_jobs`.** — Jobs are purged after 30 d, Prometheus retention is
  short, and `~gateway`/`~mesh` costs are booked by no client. — If wrong: one small upsert per terminal job.
- **R239** **RACI roles** (§9.1): node operator, key_custodian, issuer, compliance, guardian, rateAdmin, ERP admin,
  owner/SCaaS team. Recommended in production: `key_custodian` and `admin` are **different people**; guardian,
  rateAdmin, issuer and compliance are **different keys**. Not enforced (R107 allows one person on a dev box). Under
  R107 a KC-only user can grant only its own roles, so `operator`/`admin` users are created with the host CLI (R108)
  by NO with KC's approval; the second person on `fee_recipient` changes is procedural (the audited change is checked
  against `ScaasFeeRecipientChanged`). — Two-person control between "mint credentials" and "change fee recipient" is
  the cheapest defence against T14. — If wrong: the risk is disclosed.
- **R240** **Restore is one fixed sequence and starts paused** (§11.3): stop → evidence → restore → integrity check →
  `store restored` (bumps `restore_epoch`, **sets every chain `paused`**, runs the retention purge, audited) →
  `lane accept-nonce` for every sequence-family lane (refuses where nothing is to adopt) → start (paused chains
  accept, index and track, never lease) → re-apply, through the admin API, every security-relevant mutation newer
  than the backup point from the off-host audit events (key revokes, admin disables, deny add/lift, token
  `active`/removal, chain state, `fee_recipient`, namespace suspension, peer bans) **or** rotate `master_key` → each
  ERP admin acknowledges; the acknowledgement also posts `cancel {origin}` for every job the client holds as
  dead/cancelled whose node snapshot is live (NI §10.1 addition) → NO resumes each chain after every namespace
  granted it has acknowledged. — A restored store holds as `queued` jobs that were cancelled after the backup point,
  and `max_valid_for_secs` (3 600 s) outlives the RTO; leasing before the client reconciles would execute stopped
  payments (review H1). — If wrong: one manual resume per chain.
- **R241** **CLI `scaas-node lane accept-nonce --chain <key> --lane <label> --confirm <n> --config node.toml`**
  (sequence families; node stopped; owner lock, epoch + 1). Reads `nonce_at(latest)` and `nonce_at(pending)` from
  **every** configured endpoint (all must answer) and uses the **maximum** `pending` (on Cosmos, Aptos, Soroban and
  TON `pending` = the committed sequence). **Refuses unless `pending − 1 > lane.journal_max`** (monotonicity, NI §4).
  Prints every nonce in `[journal_max + 1, pending)` with its tx hash, `to`, and whether its meta-tx digest matches a
  job of the restored store; requires `--confirm` = `pending − 1`; sets `lane.journal_max` and inserts one
  `lane_adopted (chain_key, lane_label, nonce, tx_hash, adopted_at)` row per adopted nonce, audited. The lane tracks
  adopted nonces like journaled ones: a stuck adopted head is replaced by a 0-value self-send at that nonce, bumped
  ×1.25 over the observed fee (the lost intents were re-pushed by clients and stay protected by subject nonces);
  rows are deleted once `latest` passes them. Sui and Solana have no lane nonce: after `store restored` the lane
  re-reads its gas objects (and waits until none is locked by a pending certificate) or its durable-nonce account
  at start and never re-sends journaled bytes from the restored store. — After a restore the chain is ahead of the
  journal by design; NI §9.4 refuses such a lane, and the only other way out is a new lane. — If wrong: an operator
  adopts a nonce advanced by a second user; the unmatched-digest listing makes that visible (RB-04).
- **R242** **Integrity rechecks**: (a) at indexer start, before the first range, and every 600 s (OA: inside the
  30-min P1 window, one header read per chain) the indexer re-reads the hash at `chain_index.indexed_block` from ≥
  `quorum` endpoints; a quorum answering a different hash ⇒ the chain's indexer holds,
  `scaas_indexer_finality_violated{chain} = 1`, `/readyz` reason `finality violated at <block>`; the start-time check
  re-derives the hold after any restart. (b) The audit hash chain is verified from the first row at start and every
  24 h (OA); a break ⇒ `scaas_audit_chain_ok = 0`, `/readyz` reason `audit chain broken`. No automatic state change
  or feed rewind. (c) Recovery: CLI `scaas-node index reset --chain <key> --to <block> --confirm <block>` (node
  stopped, owner lock, audited); clients reset their own event cursor for that chain to the same block, else the
  straddle rule (integration §4.3) drops the re-delivered events. — A violation is a human-judgement event; holding
  the indexer stops the damage without a schema change. — If wrong: ≤ 10 min of extra ranges to reconcile.
- **R243** **DR drills are scheduled, timed and exported** (§11.4): each run writes
  `scaas_dr_drill_last_success_timestamp_seconds{drill}` and `scaas_dr_drill_cadence_seconds{drill}` to the
  textfile collector of the **production** node host (seeded with 0 at install, so a drill never run alerts); older
  than 1.5 × cadence ⇒ P3. — Research §12.11: an untested restore is not a restore. — If wrong: one file per drill.
- **R244** **Capacity rating** (§12) and **label caps**: ≤ 16 chains, ≤ 8 lanes per chain, ≤ 32 namespaces, ≤ 64
  registered tokens per chain, ≤ 256 watched wrapper legs per node (OA: `/metrics` ≤ ~13 000 series / ~1.5 MiB at
  the caps, ~2 500 series typical; formula §12); `Config::validate` and the admin routes refuse more (`422 LIMIT`). —
  An unbounded label is an outage of the monitoring, found at 3 a.m. — If wrong: the caps are constants.
- **R245** **Incident command** = the accountable role of the failing component (§9.2): node operator for node,
  store, chain and lane; issuer (with compliance for regulated tokens) for tokens; owner/SCaaS team for release
  defects. Evidence first (§10.0); never auto-cancel held or signed jobs (a broadcast tx can still land); never
  rewind silently; communication from prepared templates. — Research §12.10; SCaaS §13.4 timing kept. — If wrong:
  escalation path in §9.2.
- **R246** (owner) **Subject denylist — the operator's choice.** An admin-managed list (§4.5): the node refuses to
  relay or serve jobs whose subject, payer or recipient is listed, **at intake and again at lease**; each entry
  carries the order reference and the SHA-256 of the order document; every change is audited. It has **no on-chain
  effect**: the listed party can still use the contract through other operators or by self-submission; this node
  just won't serve. Mesh intents with a listed party are Ignored (local policy, never a peer fault) and not forwarded.
  — An order binds the operator it is addressed to; that operator needs a precise, evidenced, reversible lever
  instead of suspending a namespace or pausing a token. — If wrong: the list is empty by default; one set lookup.
- **R247** (owner) **Operators are independent; this spec is a set of recommendations.** Anyone can run `scaas-node`
  (it doubles as a relayer). Each operator sets its own acceptance, fee, sponsorship, denylist, gossip and peer
  policy, and its own SLOs, alerting and monitoring; nothing in §3, §5, §11 or §12 binds another operator or the
  network. Protocol guarantees — contract rules, subject signatures, nonces, expiry — hold on chain whatever any
  operator does; a refusing or slow operator costs liveness only, countered by other operators or self-submission
  (SCaaS §1.2). The `scaas/ops` bundle and every OA default are recommendations, not obligations; SLOs are internal
  objectives, with no SLA or credits. — Owner: "SCaaS means the smart contracts themselves are the API services that
  run the business services." — If wrong: nothing on chain changes.

---

## 3. SLIs and SLOs

### 3.1 Component SLOs

Recommended internal objectives for whoever runs a node (R247); no SLA. Window: 30 days rolling unless stated.
"Budget" = allowed bad fraction of the window.

| Component | SLI (series, §4) | Target (OA) | Reason | Budget / 30 d |
|---|---|---|---|---|
| Gateway acceptance | p99 of `scaas_http_request_seconds{listener="gateway",route="/v1/metatx"}`; non-5xx share | p99 ≤ 300 ms; ≥ 99.9 % | accept does no RPC (one store transaction + R54 auth) | 43 min |
| Job API acceptance | p99 of `…{listener="api",route="/v1/jobs",method="POST"}` (≤ 50 items); non-5xx share | p99 ≤ 1 s; ≥ 99.9 % | 50 JCS hashes + one transaction; an ERP cron worker waits | 43 min |
| Queueing | p95 of `scaas_job_stage_seconds{stage="queue"}` while no breaker/pause | ≤ 5 s | poll 1 s × a few rounds; a 1 h p95 absorbs one 15 s restart hold | — |
| Submit → mined | p95 of `stage="include"` per chain | §3.2 | a few blocks per family | — |
| W3B-01 success | R233 ratio | ≥ 99.5 % | SCaaS §13.1 | 0.5 % of jobs |
| W3B-02 zero revert | `scaas_submit_reverted_total{class="other"}` | 0 | SCaaS §13.1; each P2, streak ⇒ breaker | 0 |
| Revert incl. races | all reverts ÷ broadcasts, 7 d | ≤ 0.5 % | research guard §06.3.2 | — |
| Consumed rate, private profile | `consumed` ÷ signed-terminal, 1 d | ≤ 1 % | on `restricted` scope only the subject can race us | — |
| W3B-03 gas budget | breaker `gas_budget` open minutes | ≤ 100 % (warn 90 %) | R55 (BUILT) | — |
| Indexer progress | `time() − scaas_indexer_last_progress_timestamp_seconds` | ≤ `scaas:indexer_stall_seconds` per chain (§5.1): 60 s on depth/instant chains, 2 × the final-head step on `tag` chains (Celo ≈ 800 s) | empty ranges are written whenever the final head moves (R94) | 7 h 12 min |
| Indexer lag | `scaas_indexer_lag_blocks` | ≤ `max_index_lag` (100) | R51 readiness | — |
| Finality lag | `time() − scaas_final_head_block_time_seconds` | ≤ hard finality + 60 s (§3.2) | W3B-04 rule applied to the head | — |
| W3B-04 | p95 of `stage="broadcast_final"` | §3.2 | SCaaS §13.1 | — |
| Feed to clients | `scaas_feed_last_poll_seconds` per namespace with live jobs | ≤ 180 s for 99 % | Odoo polls every 60 s, ~10 s while live (R101) | 7 h 12 min |
| Mesh propagation | p95 of `scaas_mesh_propagation_seconds` | gossip ≤ 1 s, bus ≤ 3 s | ≪ the 7 s exclusivity window (R121) | — |
| Gossip health | `scaas_gossip_mesh_peers{topic_kind="intent"}` per chain | ≥ `mesh_n_low` (4) for 99 % | A2 §7 | 7 h 12 min |
| Store | p99 of `scaas_store_tx_seconds{kind="journal"}`; fencing lost; commit unknown | ≤ 50 ms; 0; 0 | NVMe fsync ≈ 1–2 ms, PG/MySQL one RTT (≤ 1 ms LAN, §12) | — |
| Backups | `time() − scaas_backup_last_success_timestamp_seconds` | ≤ 3 × interval (§11.1) | RPO is the interval | — |
| Node and app | `scaas_node_ready`; blackbox `probe_success` of the app `/` + `/config.json` | ≥ 99.5 % | an operator console, not a payment path | 3 h 36 min |

### 3.2 Latency targets per family and profile (all OA)

`include` = first broadcast → mined (p95). `broadcast_final` (p95) = hard finality + 60 s for depth/tag families,
`include` + 30 s for instant families (one indexer poll plus a range write).

| Chain class | Block / finality | `include` | `broadcast_final` | Reason |
|---|---|---|---|---|
| EVM private (9000, Clique, 1 signer) | ~5 s, depth 1 | 15 s | 15 s | SCaaS §13.1 value; 3 blocks |
| EVM public (Gnosis) | 5 s, `finalized` ~160–240 s | 30 s | 300 s | 6 blocks; 240 s + 60 s |
| EVM L2 (Celo, `tag` until `l1_batch`) | 1 s, L1 finality ~13–20 min | 10 s | 1 260 s | 20 min + 60 s |
| Hedera | 3–5 s record files, instant | 15 s | 45 s | 3 record files |
| Cosmos / Soroban (Stellar, Pi) | ~5–6 s, instant | 20 s | 50 s | 3 blocks/ledgers |
| Sui / Aptos | ~0.5–1 s, instant | 5 s | 35 s | |
| TON | ~5 s masterchain, message chains | 60 s | 90 s | jetton transfers span several messages |
| Solana | 0.4 s slots, `finalized` ~12.8 s | 10 s | 75 s | confirmed + 60 s margin |

A chain stays `draft` until 7 days of measurements exist (SCaaS §6.6 O4); the measured p95 + 20 % then replaces the
OA row for that chain.

### 3.3 Error-budget policy (OA)

- Burn-rate alerts (multi-window, Google SRE workbook): **fast** 14.4× over 1 h and 5 min ⇒ P1; **slow** 6× over 6 h
  and 30 min ⇒ P2; **trend** 1× over 3 d ⇒ P3. Minimum volume: 20 signed-terminal jobs in the long window.
- Budget exhausted: only fixes ship to that node until it recovers (risk-reducing changes — pause, breaker, lane
  retirement — always allowed). One incident consuming > 25 % of a budget ⇒ post-mortem with a regression test.

---

## 4. Metrics

### 4.1 Rules

- **Label allowlist (R230):** `chain`, `family`, `profile`, `lane` (lane label), `namespace` (incl. `~gateway`,
  `~mesh`, `~dex`), `token` (registered token address), `leg` (existing legs only), `state`, `outcome`, `result`,
  `class`, `stage`, `kind`, `breaker`, `listener`, `route` (templated), `method`, `code_class`, `endpoint` (RPC
  index), `issuer` (OIDC issuer index), `feed`, `table`, `backend`, `carrier`, `topic_kind`, `event`, `door`,
  `action`, `policy` (sponsor policy name), `drill`, `peer` (admitted bus peers only), plus labels fixed by NI §15,
  MESH §12, A2 §13.3, TSS §B1.6, app §13.2. No label whose value set grows with traffic.
- **Pre-emission (H3):** counters and latched gauges exist at 0 for every configured chain, lane, namespace, endpoint
  and enum value from process start; the golden test asserts it. Label sets created by traffic (`token` on watched
  events, `route`) are the only lazy ones and are never used in `increase()`-on-first-event alerts.
- Amounts are float64 of the smallest unit (aggregates only; exact accounting is `usage_day`, §8).
- **Buckets** (seconds): job stages 0.5, 1, 2, 5, 10, 20, 30, 60, 120, 300, 600, 1200, 1800, 3600; request/store
  0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5; propagation 0.05, 0.1, 0.25, 0.5, 1, 2, 3, 5, 7, 10.
- Gauges come from the 10 s snapshot; chain probes run in parallel (OP1; today sequential, `admin.rs` ponytail) and
  `scaas_snapshot_age_seconds` exposes staleness. Counters/histograms are atomics read at render. Scrape 15 s (OA).

### 4.2 Existing (BUILT, `admin.rs`, `submit.rs`)

| Metric | Type | Labels | Note |
|---|---|---|---|
| `scaas_relay_jobs` | gauge | `chain`, `state` | from Odoo `relay_stats` today; from the store with `namespace` after P3 (NI §15) |
| `scaas_payment_requests_attention`, `scaas_drift_alerts` | gauge | `chain` | legacy (R104); leave the node (NI §9.1) |
| `scaas_indexer_lag_blocks` | gauge | `chain` | final head − indexed block |
| `scaas_relayer_balance` | gauge | `chain`, `lane` | smallest gas-coin unit |
| `scaas_breaker_open` | gauge | `chain`, `lane`, `breaker` | + `revert_streak` (R233), reported on every lane of the chain |
| `scaas_submit_bump_skipped_consumed_total` | counter | none today; `chain`, `lane` added in OP1 (MESH §12) | R80 |
| `scaas_config_toml_drift` | gauge | — | R95 |

Specified elsewhere: NI §15 (job API, feeds, store owner, admin, audit, OIDC, fee recipient, foreign nonce), MESH §12,
A2 §13.3, TSS §B1.6, app §13.2. Changed here: NI's `scaas_audit_head_info{hash}` (one new series per mutation) →
`scaas_audit_head_seq` gauge, hash logged; `scaas_oidc_*{issuer}` uses the issuer index; `scaas_feed_last_poll_seconds`
= seconds since the last poll at render time.

### 4.3 New (this spec, SPECIFIED)

| Metric | Type | Labels | Source / meaning |
|---|---|---|---|
| `scaas_build_info` (=1); `scaas_process_start_time_seconds`, `scaas_process_resident_memory_bytes`; `scaas_snapshot_age_seconds` | gauge | `version`, `commit` / — | binary, `/proc/self/statm`, snapshot |
| `scaas_node_ready` | gauge 0/1 | — | node-scope readiness: store open and owned, audit chain ok, ≥ 1 chain ready (M2) |
| `scaas_chain_ready` | gauge 0/1 | `chain` | that chain's `/readyz` reasons are empty |
| `scaas_chain_info` (=1), `scaas_chain_state` (0/1) | gauge | `chain`, `family`, `profile` / `chain`, `state` | config, store |
| `scaas_job_terminal_total`, `scaas_job_late_revert_total` | counter | `chain`, `outcome` / `chain` | R233 |
| `scaas_job_stage_seconds` | histogram | `chain`, `stage` | R234 |
| `scaas_simulation_total` | counter | `chain`, `result` (`ok`, `revert_consumed`, `revert_dead`, `transient`, `gas_cap`) | SCaaS §6.5 |
| `scaas_submit_broadcast_total`, `scaas_submit_fee_cap_reached_total` | counter | `chain`, `lane` | first broadcasts; replacement wanted at the cap |
| `scaas_submit_replacements_total` | counter | `chain`, `kind` (`bump`, `gapfill`, `resend`) | §6.3 |
| `scaas_submit_reverted_total` | counter | `chain`, `class` (`race`, `other`) | R233 |
| `scaas_lane_inflight` | gauge | `chain`, `lane` | `signed` + `broadcast` rows + adopted nonces |
| `scaas_lane_head_stuck_seconds` | gauge | `chain`, `lane` | seconds since `nonce_at(latest)` last advanced while `latest ≤ journal_max`; 0 otherwise (covers adopted nonces, H2) |
| `scaas_lane_foreign_nonce` | gauge 0/1, latched until the lane leases again | `chain`, `lane` | NI §9.4 state (the NI counter stays) |
| `scaas_lane_cost_native_total` | counter | `chain`, `lane` | measured fee paid (R238) |
| `scaas_relayer_balance_floor` | gauge | `chain`, `lane` | `min_relayer_balance` |
| `scaas_rpc_requests_total` | counter | `chain`, `endpoint`, `result` (`ok`, `error`, `timeout`) | adapter |
| `scaas_rpc_head_lag_blocks` | gauge | `chain`, `endpoint` | max head − this endpoint's head |
| `scaas_rpc_quorum_disagreement_total` | counter | `chain` | ≥ 2 hashes at the candidate final head |
| `scaas_indexer_last_progress_timestamp_seconds`, `scaas_final_head_block_time_seconds` | gauge | `chain` | last committed range; chain timestamp of the final head |
| `scaas_indexer_finality_violated` | gauge 0/1 | `chain` | R242 (a) |
| `scaas_audit_chain_ok` | gauge 0/1 | — | R242 (b) |
| `scaas_http_request_seconds` | histogram | `listener`, `route`, `method`, `code_class` | all listeners |
| `scaas_store_info` (=1), `scaas_store_restore_epoch` | gauge | `backend`, `store_id`, `schema_version` / — | store identity |
| `scaas_store_tx_seconds` | histogram | `kind` (`journal`, `transition`, `accept`, `feed`, `audit`, `purge`) | store |
| `scaas_store_tx_retries_total` | counter | `reason` (`serialization`, `deadlock`, `busy`) | A1.2 |
| `scaas_store_commit_unknown_total`, `scaas_store_lock_ping_failures_total` | counter | — | A1.2, A1.1 |
| `scaas_store_size_bytes` | gauge | — | file size (SQLite + WAL) / `pg_database_size` / `information_schema`, every 60 s |
| `scaas_store_rows` | gauge | `table` (`job`, `job_event`, `feed_item`, `audit_log`, `intent`) | `seq_counter` value − purge floor (no `COUNT(*)`, M10) |
| `scaas_mesh_propagation_seconds` | histogram | `chain`, `carrier` (`gossip`, `bus_https`, `bus_quic`) | receive − `hub.published_at`, clamped at 0 |
| `scaas_watch_events_total` | counter | `chain`, `token`, `event` | R235; lazy per token |
| `scaas_wrapper_leg_backing_ratio` | gauge | `chain`, `token`, `leg` | R235; tier 2 = leg 0 |
| `scaas_gas_cost_native_total` | counter | `chain`, `namespace` | R238 |
| `scaas_token_gas_cost_native_total`, `scaas_fee_earned_total` | counter | `chain`, `token` | R238; `token = "call"` for non-token call targets; fees in token base units |
| `scaas_deny_entries`; `scaas_deny_refused_total`; `scaas_deny_changes_total` | gauge; counter; counter | `chain`; `chain`, `door`; `action` | §4.5 |

Watched events (`event`): AS `OrderRecorded`, `OrderRevoked`, `ForcedTransfer`, `AccountFrozen`, `AccountUnfrozen`,
`Paused`, `Unpaused`, `ControlsDisabled`, `RoleRenounced`, `AttesterSet`; TW2 `WrapDisabled`, `GuardianRenounced`,
`MinterRenounced`, `RateChangeProposed`, `RateChanged`, `RateChangeCancelled`, `RateAdminRenounced`; factory
`ImplementationRegistered`, `ImplementationDeprecated` (`IOpenFactoryV2.sol`). Only registered tokens and configured
factories.

External: `scaas_backup_last_success_timestamp_seconds{backend}`, `scaas_backup_interval_seconds{backend}`,
`scaas_dr_drill_*{drill}` (R243), `scaas_watch_code_hash_changed{chain,token}` (R235 b) from textfiles; blackbox
`probe_success`; node_exporter.

### 4.4 Admin and store additions

| Item | Detail |
|---|---|
| `job.trace_id TEXT NULL` | R236; 32 hex; echoed in jobs-feed items |
| `breaker_latch`, `lane_adopted`, `usage_day` | R233, R241, §8.2 |
| `PATCH /v1/admin/chains/{key}/tokens/{address}` `{active: bool}` | admin; `token.active = 0` refuses intake of every op on the token on every door, **keeps indexing** (M1); audited |
| `PATCH /v1/admin/chains/{key}` with `breaker` | JSON merge patch (RFC 7396) on the `breaker` object: absent keys keep their value (L5) |
| `GET /v1/admin/chains/{key}/watch` | viewer: backing ratios per leg, last watched events |
| `GET /v1/admin/usage?from=&to=&chain=&namespace=` | viewer; `usage_day` rows, no conversion |
| `scaas-node report usage --from YYYY-MM-DD --to YYYY-MM-DD [--prices prices.csv] [--format csv\|json]` | CLI, read-only; §8.3 |
| `scaas-node lane accept-nonce …`, `scaas-node index reset …` | R241, R242 (c); node stopped |

### 4.5 Subject denylist (R246, operator's choice)

```sql
CREATE TABLE deny_subject (
  id            BIGINT PRIMARY KEY,                -- counter row 'deny_subject'
  chain_key     TEXT NOT NULL,                     -- a chain key or '*'
  address       TEXT NOT NULL,                     -- family canonical form (addresses.canonical)
  order_ref     TEXT NOT NULL,                     -- the order's own reference
  document_hash BLOB NOT NULL,                     -- SHA-256 of the order document (kept by the operator, not the node)
  state         TEXT NOT NULL CHECK (state IN ('active', 'lifted')),
  valid_until   BIGINT,                            -- NULL = until lifted; past ⇒ no longer matches
  created_by TEXT NOT NULL, created_at BIGINT NOT NULL, lifted_by TEXT, lifted_at BIGINT, lift_ref TEXT);
CREATE INDEX deny_subject_addr ON deny_subject (address, chain_key);
```

- **Parties** checked at intake on every door (job API, gateway, mesh, DEX, `/v1/ops`) **and at lease** (a job
  requeued from `signed` after a dropped tx is re-checked, M7): meta-tx `m.from`, `m.to`; family op signer and payee;
  DEX maker (taker at match); `call` jobs: target and the addresses decoded for known selectors. Intake match ⇒
  `403 SUBJECT_DENIED` (no order detail); mesh ⇒ Ignore, not forwarded; lease match ⇒ `dead` (`SUBJECT_DENIED`), or
  `hold = 1` if published.
- **On add:** never-published `queued`/`leased` jobs ⇒ `dead`; published ones ⇒ `hold = 1`; `signed`/`broadcast`
  continue (the signed tx can land anyway, N3). DEX: the maker's resting orders are dropped (cancel item on the
  feed); a settle job that goes `dead` takes its trade to `failed` through the existing failed-settle path. The
  events feed is not filtered (clients need chain facts for their books).
- **On lift:** nothing is revived; clients re-push with `generation + 1` (R91).
- **Exits** (refunds, withdrawals) whose only listed party is the source: refused like any other match (the
  operator's choice; the beneficiary can self-submit).
- **Routes:** `GET /v1/admin/deny[?address=]` (operator); `POST /v1/admin/deny` `{chain_key, address, order_ref,
  document_sha256, valid_until?}` and `POST /v1/admin/deny/{id}/lift {lift_ref}` (admin); audited (R110; the log
  mirror writes `***` for the address, R237); hot ≤ 2 s (in-memory set). Lifted/expired rows kept 400 d (OA).
- Metrics carry no address; refusal logs carry `deny_id` and the job/intent id.

---

## 5. Alerts, routing, dashboards

### 5.1 Rule file (`scaas/ops/prometheus/scaas-rules.yml`, recommended)

Every alert carries `severity` and `runbook` (anchor in §10). `$STORE_MOUNT` is the filesystem holding the store
(set per deployment).

```yaml
groups:
- name: scaas-recording
  rules:
  - record: scaas:w3b01_errors:ratio_rate5m  # same expression for 30m, 1h, 6h, 3d (rename the window)
    expr: |
      sum by (chain) (rate(scaas_job_terminal_total{outcome=~"reverted|expired_after_sign"}[5m]))
      / clamp_min(sum by (chain) (rate(scaas_job_terminal_total{outcome=~"mined|consumed|reverted|expired_after_sign"}[5m])), 1e-9)
  - {record: scaas:signed_terminal:increase1h, expr: 'sum by (chain) (increase(scaas_job_terminal_total{outcome=~"mined|consumed|reverted|expired_after_sign"}[1h]))'}  # also 6h
  - {record: scaas:slo_target_seconds, expr: 'vector(300)', labels: {chain: "evm:100", slo: w3b04}}  # one rule per chain and slo, §3.2
  - {record: scaas:indexer_stall_seconds, expr: 'vector(300)', labels: {chain: "evm:100"}}  # per chain: max(300, 2 × final-head step), Celo 800
  - {record: scaas:finops_budget_native_30d, expr: 'vector(5e17)', labels: {namespace: odoo-prod, chain: "evm:100"}}  # per approved (namespace, chain) budget
- name: scaas-finops-hourly
  interval: 1h
  rules:
  - {record: scaas:gas_cost_native:increase1h, expr: 'sum by (namespace, chain) (increase(scaas_gas_cost_native_total[1h]))'}
- name: scaas-p1
  rules:
  - {alert: ScaasNodeDown, expr: 'up{job="scaas-node"} == 0', for: 2m, labels: {severity: P1, runbook: rb-01-node-down-or-not-ready}}
  - {alert: ScaasNodeAbsent, expr: 'absent(up{job="scaas-node"})', for: 5m, labels: {severity: P1, runbook: rb-01-node-down-or-not-ready}}
  - {alert: ScaasNodeNotReady, expr: 'scaas_node_ready == 0', for: 5m, labels: {severity: P1, runbook: rb-01-node-down-or-not-ready}}
  - {alert: ScaasLaneForeignNonce, expr: 'scaas_lane_foreign_nonce == 1', labels: {severity: P1, runbook: rb-04-foreign-nonce}}
  - {alert: ScaasFencingLost, expr: 'increase(scaas_store_fencing_lost_total[5m]) > 0', labels: {severity: P1, runbook: rb-07-store-owner-loss}}
  - {alert: ScaasLaneHeadStuckHard, expr: 'scaas_lane_head_stuck_seconds > 900', labels: {severity: P1, runbook: rb-03-stuck-lane}}  # 15 min: SRS §5.4; bumps every 60 s before
  - {alert: ScaasChainNoLaneAvailable, expr: 'min by (chain) (max by (chain, lane) (scaas_breaker_open)) == 1', for: 5m, labels: {severity: P1, runbook: rb-02-breaker-open}}
  - alert: ScaasLaneRunwayCritical
    expr: |
      (scaas_relayer_balance - on (chain, lane) scaas_relayer_balance_floor)
        / on (chain, lane) clamp_min(rate(scaas_lane_cost_native_total[1h]), 1e-30) < 3600
    for: 5m
    labels: {severity: P1, runbook: rb-14-runway}
  - {alert: ScaasFinalityViolated, expr: 'scaas_indexer_finality_violated == 1', labels: {severity: P1, runbook: rb-06-chain-halt-or-finality-violation}}
  - {alert: ScaasRpcDivergenceSustained, expr: 'increase(scaas_rpc_quorum_disagreement_total[30m]) > 10', labels: {severity: P1, runbook: rb-05-rpc-divergence}}
  - alert: ScaasIndexerStalled
    expr: |
      (time() - scaas_indexer_last_progress_timestamp_seconds > on (chain) scaas:indexer_stall_seconds)
        unless on (chain) (scaas_chain_state{state="halted"} == 1)
    labels: {severity: P1, runbook: rb-06-chain-halt-or-finality-violation}
  - {alert: ScaasRevertStreak, expr: 'max by (chain) (scaas_breaker_open{breaker="revert_streak"}) == 1', labels: {severity: P1, runbook: rb-16-simulation-gap-revert}}
  - {alert: ScaasWrapperBackingShortfall, expr: 'scaas_wrapper_leg_backing_ratio < 1', labels: {severity: P1, runbook: rb-11-wrapper-shortfall-or-depeg}}
  - {alert: ScaasWatchedCodeHashChanged, expr: 'scaas_watch_code_hash_changed == 1', labels: {severity: P1, runbook: rb-12-code-hash-change}}
  - {alert: ScaasForcedTransfer, expr: 'increase(scaas_watch_events_total{event="ForcedTransfer"}[10m]) > 0', labels: {severity: P1, runbook: rb-13-regulator-order}}  # per token; silenced per token for a planned execution
  - {alert: ScaasAuditChainBroken, expr: 'scaas_audit_chain_ok == 0', labels: {severity: P1, runbook: rb-10-compromised-admin}}
  - alert: ScaasW3B01FastBurn
    expr: |
      scaas:w3b01_errors:ratio_rate1h > (14.4 * 0.005) and scaas:w3b01_errors:ratio_rate5m > (14.4 * 0.005)
        and scaas:signed_terminal:increase1h >= 20
    labels: {severity: P1, runbook: rb-03-stuck-lane}
  - {alert: ScaasBackupVeryStale, expr: 'time() - scaas_backup_last_success_timestamp_seconds > 12 * scaas_backup_interval_seconds', labels: {severity: P1, runbook: rb-08-restore}}
  - {alert: ScaasStoreDiskCritical, expr: 'node_filesystem_avail_bytes{mountpoint="$STORE_MOUNT"} / node_filesystem_size_bytes{mountpoint="$STORE_MOUNT"} < 0.10', labels: {severity: P1, runbook: rb-01-node-down-or-not-ready}}
  - {alert: Watchdog, expr: 'vector(1)', labels: {severity: none}}  # always firing; routed to the external dead-man's switch
- name: scaas-p2
  rules:
  - {alert: ScaasChainNotReady, expr: '(scaas_chain_ready == 0) unless on (chain) (scaas_chain_state{state=~"paused|halted"} == 1)', for: 10m, labels: {severity: P2, runbook: rb-01-node-down-or-not-ready}}
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
        and scaas:signed_terminal:increase6h >= 20
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
  - {alert: ScaasBackupMetricAbsent, expr: 'absent(scaas_backup_last_success_timestamp_seconds)', for: 1h, labels: {severity: P2, runbook: rb-08-restore}}
  - {alert: ScaasStoreDiskLow, expr: 'node_filesystem_avail_bytes{mountpoint="$STORE_MOUNT"} / node_filesystem_size_bytes{mountpoint="$STORE_MOUNT"} < 0.20', labels: {severity: P2, runbook: rb-01-node-down-or-not-ready}}
  - {alert: ScaasRestartLoop, expr: 'changes(scaas_process_start_time_seconds[1h]) > 3', labels: {severity: P2, runbook: rb-01-node-down-or-not-ready}}
  - {alert: ScaasWatchedEvent, expr: 'increase(scaas_watch_events_total{event!="ForcedTransfer"}[10m]) > 0', labels: {severity: P2, runbook: rb-13-regulator-order}}
  - {alert: ScaasFeeRecipientChanged, expr: 'increase(scaas_fee_recipient_changed_total[10m]) > 0', labels: {severity: P2, runbook: rb-10-compromised-admin}}
  - {alert: ScaasAdminLoginFailures, expr: 'sum by (instance) (increase(scaas_admin_login_total{result=~"bad|locked"}[10m])) > 20', labels: {severity: P2, runbook: rb-10-compromised-admin}}
  - {alert: ScaasSponsorBudgetExhausted, expr: 'scaas_sponsor_budget_remaining_ratio == 0', labels: {severity: P2, runbook: rb-14-runway}}
  - {alert: ScaasDenylistChanged, expr: 'increase(scaas_deny_changes_total{action!="expire"}[10m]) > 0', labels: {severity: P2, runbook: rb-13-regulator-order}}
  - {alert: ScaasGossipIsolated, expr: 'sum by (instance) (scaas_gossip_peers) == 0', for: 10m, labels: {severity: P2, runbook: rb-17-gossip-degraded}}
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
  - {alert: ScaasSponsorBudgetLow, expr: 'scaas_sponsor_budget_remaining_ratio < 0.20', labels: {severity: P3, runbook: rb-14-runway}}  # SRS §5.4: 20 %
  - {alert: ScaasNamespaceBudget90, expr: 'sum_over_time(scaas:gas_cost_native:increase1h[30d]) > on (namespace, chain) (0.9 * scaas:finops_budget_native_30d)', labels: {severity: P3, runbook: rb-14-runway}}
  - {alert: ScaasStoreSlow, expr: 'histogram_quantile(0.99, sum by (le) (rate(scaas_store_tx_seconds_bucket{kind="journal"}[15m]))) > 0.05', for: 15m, labels: {severity: P3, runbook: rb-07-store-owner-loss}}
  - alert: ScaasRpcEndpointErrors
    expr: |
      sum by (chain, endpoint) (rate(scaas_rpc_requests_total{result!="ok"}[10m]))
        / clamp_min(sum by (chain, endpoint) (rate(scaas_rpc_requests_total[10m])), 1e-9) > 0.2
    for: 10m
    labels: {severity: P3, runbook: rb-05-rpc-divergence}
  - {alert: ScaasGossipThinMesh, expr: 'min by (instance, chain) (scaas_gossip_mesh_peers{topic_kind="intent"}) < 4', for: 15m, labels: {severity: P3, runbook: rb-17-gossip-degraded}}
  - {alert: ScaasMeshPropagationSlow, expr: 'histogram_quantile(0.95, sum by (carrier, le) (rate(scaas_mesh_propagation_seconds_bucket[30m]))) > 3', for: 30m, labels: {severity: P3, runbook: rb-17-gossip-degraded}}
  - {alert: ScaasW3B01Trend, expr: 'scaas:w3b01_errors:ratio_rate3d > 0.005', labels: {severity: P3, runbook: rb-03-stuck-lane}}
  - {alert: ScaasMemoryHigh, expr: 'scaas_process_resident_memory_bytes > 512 * 1024 ^ 2', for: 30m, labels: {severity: P3, runbook: rb-01-node-down-or-not-ready}}  # 2× the §12 budget
  - {alert: ScaasSnapshotStale, expr: 'scaas_snapshot_age_seconds > 60', for: 10m, labels: {severity: P3, runbook: rb-01-node-down-or-not-ready}}
  - {alert: ScaasConfigDrift, expr: 'scaas_config_toml_drift > 0', labels: {severity: P3, runbook: rb-01-node-down-or-not-ready}}
  - {alert: ScaasAppAvailability, expr: 'avg_over_time(probe_success{job="scaas-app"}[30d]) < 0.995', labels: {severity: P3, runbook: rb-01-node-down-or-not-ready}}
  - {alert: ScaasDrillOverdue, expr: 'time() - scaas_dr_drill_last_success_timestamp_seconds > 1.5 * scaas_dr_drill_cadence_seconds', labels: {severity: P3, runbook: rb-08-restore}}  # seeded 0 at install
```

Prometheus retention ≥ 35 d (OA: the 30 d budget windows plus margin); long-term FinOps is `usage_day`.

### 5.2 Routing (`scaas/ops/alertmanager.example.yml`)

Token alerts (`ScaasForcedTransfer`, `ScaasWatchedEvent`, `ScaasWrapperBackingShortfall`,
`ScaasWatchedCodeHashChanged`) go to the **issuer** (and compliance for regulated tokens) as well as the node
operator; `ScaasNamespaceBudget90`, `ScaasSponsorBudget*` to the finance owner of the namespace/sponsor account;
`ScaasFeedClientStalled` to the ERP admin; everything else to the node operator, who owns the Alertmanager (R231).
`Watchdog` goes to the external dead-man's switch (expected every ≤ 5 min OA). Group by `chain`; repeat P1 every
30 min until acknowledged.

### 5.3 Dashboards (`scaas/ops/grafana/*.json`, three, review L6)

| Dashboard | Panels |
|---|---|
| Overview | SLO table with remaining error budget; firing alerts; chains by state and readiness; build info, restarts, snapshot age; FinOps cost per namespace/token, fees, sponsor spend vs budget; backing ratios and watched events |
| Submit and chains | stage latencies per chain; terminal outcomes; simulation results; replacements; inflight, head-stuck, breakers, balances and runway per lane; final head age, indexer lag/progress; RPC errors, head lag, disagreements; job API and feed poll age per namespace; mesh/gossip peers, propagation |
| Store, DR and security | journal latency, retries, commit unknown, fencing epoch, size and rows, backup and drill age, restore epoch; logins, OIDC rejections, admin mutations, CLI actions, fee-recipient and denylist changes, audit chain |

The app's metrics screen (app R171) and `metricsDashboardUrl` link to Overview.

---

## 6. Traces (R236)

Span model (names normative; v1 emits them as log events with `span` and `trace_id`; OP7 exports them):

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
| `ts` (RFC 3339, ms, UTC), `level`, `target`, `msg` | always | `tracing-subscriber` feature `json` (crate already a dependency) |
| `store_id`, `incarnation` | always (span fields) | correlate restarts and restores |
| `chain`, `lane`, `namespace`, `job_uid`, `trace_id`, `span` | job and lane work | |
| `state_from`, `state_to`, `outer_nonce`, `tx_hash`, `digest`, `error_code`, `attempt` | transitions | `error_code` = decoded custom error or node code |
| `listener`, `route`, `method`, `status`, `dur_ms`, `request_id`, `key_id` | requests | `key_id` is the public id; no headers |
| `event = "audit"` + `actor_kind`, `actor`, `roles`, `route`, `target`, `result`, `before`, `after`, `row_hash` | every audit row, at `warn` | `***` for secrets and deny addresses (`deny_id` kept) |
| `source_ip` | auth failures, rate limits only | personal data: same 30 d retention |
| `peer_id`, `deny_id` | mesh/gossip lines; denylist refusals | not persons |

Levels: `error` = needs a human; `warn` = degraded and audit events; `info` = transitions; `debug` off in production.
Identical non-audit `warn` lines ≤ 1/10 s per (target, chain) (OA). Retention ≤ 30 d at every sink; erasure requests
need no node action (TSS §C.4 step 5) because no node-held copy outlives job retention + backup retention.

---

## 8. FinOps (R238)

### 8.1 Measurement

| What | Where | Unit |
|---|---|---|
| Cost per job | `job.cost_native` (+ `gas_used`, `gas_price`) at `mined`/`reverted`; gap-fillers charged to the expired job (`expired_after_sign`), or for adopted nonces (R241) to namespace `~lane` | smallest native unit (TSS §B1.2 per family) |
| Cost per namespace / token / lane; fees earned | counters §4.3; `usage_day` | native; token base units |
| Sponsored cost | TSS `sponsor_usage`, `scaas_sponsor_*` | native |
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

Upserted (read, add in code, write) inside the terminal-transition transaction; purged after 400 d (OA). A lost race
(`consumed`) after broadcast is booked with its measured cost (TSS §B1.3).

### 8.3 Monthly report

`scaas-node report usage --from 2026-10-01 --to 2026-11-01 --prices prices.csv --format csv`, or the admin route
without conversion. `prices.csv`: `date,chain_key,asset,price,currency,source` (`asset` = `native` or a token
address); a missing price leaves the converted cells empty and lists the gap, never interpolates.

| Field | Source |
|---|---|
| period, `store_id`, node version; per chain family, profile | report run, config |
| per (chain, namespace, token, sponsor policy): jobs by outcome, `gas_used`, `cost_native` | `usage_day` |
| native and token prices with source; `cost_reporting`, `fees_reporting` | price file |
| **relayer margin / W3B-06** = `fees_reporting − cost_reporting` per chain (may be negative, SCaaS §6.9) | computed |
| cost per mined job, per consumed job | computed |
| sponsor utilisation: Σ spent ÷ Σ daily budget, days at budget, rejects by reason | `sponsor_usage`, `scaas_sponsor_jobs_total` |
| **W3B-03** = max hourly spend ÷ `gas_budget_per_hour` per lane; breaker-open minutes | Prometheus, lane cost |
| refills and fixed costs (infrastructure, RPC plans, audits); break-even (SCaaS §6.9) | operator inputs; computed |

Per-business-document allocation stays with the client from the jobs-feed cost fields (TSS §B1.4); the node report is
the operator's view, including doors no client books.

### 8.4 Budget alarms

| Budget | Owner (§9) | Alarm (§5.1) | Enforcement |
|---|---|---|---|
| Lane gas per hour (`gas_budget_per_hour`) | node operator's finance owner | `ScaasBreakerOpen` (`gas_budget`) | R55 breaker (BUILT) |
| Lane float / runway | node operator | `ScaasLaneRunwayLow` (< 4 h), `…Critical` (< 1 h) | `balance_floor` breaker |
| Sponsor daily budget | sponsor account owner | `ScaasSponsorBudgetLow` (< 20 %), `…Exhausted` | TSS R190 |
| Namespace monthly cost | tenant's finance owner | `ScaasNamespaceBudget90` | none (report + `max_live_jobs`) |

---

## 9. RACI (R239)

SCaaS means the smart contracts themselves are the API services that run the business services; the node is
infrastructure anyone can run to reach them. **Operating, monitoring and paging a node is accountable to whoever runs
that node** (customer, partner, third party, or the SCaaS team for its own nodes); the SCaaS team ships contracts,
software and the recommended `scaas/ops` bundle (R231, R247).

### 9.1 Roles

| Role | Who | Holds | Cannot |
|---|---|---|---|
| **Node operator** (NO) | whoever runs `scaas-node` (independent; sets its node's policies) and its on-call | host, `node.toml`, lane keystore passphrase, admin roles `viewer`/`operator`/`admin`, host CLI | mint client credentials through the API (needs `key_custodian`) |
| **key_custodian** (KC) | named person(s) in the operator organisation, not the `admin` holder in production | `key_custodian` role; `master_key` and lane-mnemonic custody (Shamir shares or KMS) | change chain config (unless also `admin`) |
| **Issuer** (IS) | token creator / asset issuer | on-chain `issuer` of `*_REG` tokens; chooses guardian and rateAdmin; holder disclosures | move funds without a compliance record (AS A1) |
| **Compliance** (CO) | issuer's compliance function | on-chain `compliance`; client-side `compliance_officer` (erasure, TSS §C.4) | execute orders (AS A2) |
| **Guardian** (GU) | issuer's on-call key | Multi `disableWrap` only (TW2 R136) | re-enable, mint, move funds |
| **rateAdmin** (RA) | a multisig/timelock contract (TW2 R135) | propose/cancel/execute rate, renounce | act within `rateDelay`, exceed `maxRateStepBps` |
| **ERP admin** (EA) | system administrator of the client ERP | API key entry, push/sync crons, `action_switch_to_push`, `action_acknowledge_store_change`, DB neutralisation | node configuration (R109) |
| **Owner / SCaaS team** (OW) | product owner and SCaaS engineering | contracts, releases, specs, recommended defaults, `scaas/ops`, factory registrar multisig (O2), audits (O1) | operate, monitor or set policy for another operator's node; hold its keys |

Organisational functions of SCaaS §13.3 (security, legal, finance) sit inside these roles.

### 9.2 Matrix

R responsible · A accountable · C consulted · I informed · — not involved.

| Operation | NO | KC | IS | CO | GU | RA | EA | OW |
|---|---|---|---|---|---|---|---|---|
| Lane key rotation (drain, `PUT …/lanes`, refund to treasury) | A/R | R (new key) | — | — | — | — | I | C |
| `master_key` rotation (revokes all API keys and sessions) | A | R | — | — | — | — | R (new keys) | I |
| Client API key create/rotate/revoke | C | A/R | — | — | — | — | R (enters it) | — |
| `operator`/`admin` users (host CLI, R108) | R | A (approves) | — | — | — | — | — | — |
| `key_custodian`/`viewer` users (API) | I | A/R | — | — | — | — | — | — |
| Node identity key rotation (new `peer_id`, partners re-pin) | A/R | R | — | — | — | — | — | I |
| Chain pause / resume; chain halt | A/R | — | I | I (halt) | — | — | I | C (halt) |
| Breaker reset, fee-cap raise, gas budget / breaker parameters | A/R | — | — | — | — | — | I | C |
| Regulated token pause / unpause | I | — | A/R | C | — | — | I | — |
| `disableWrap` on a Multi leg | I | — | A | — | R | — | I | I |
| Rate change propose / execute / cancel | I | — | A | C | — | R | I | — |
| `renounceRateAdmin` / `renounceGuardian` | — | — | A | C | R (own role) | R (own role) | — | — |
| Token registration / intake pause (`active`) on a node | A/R | — | C | — | — | — | I | — |
| `fee_recipient` change | A/R | C (second person, procedural) | — | — | — | — | — | — |
| Node policies (acceptance, fees, sponsorship, gossip, peers, mesh peer URLs) | A/R | — | C (own tokens) | — | — | — | C | — |
| Chain enablement `draft → active` on a node (O4 evidence) | A/R | — | — | — | — | — | I | C (publishes evidence) |
| Cutover per chain (`action_switch_to_push`) / rollback | C (NI §11.2 preconditions) | — | — | — | — | — | A/R | C |
| Store restore (node side, chains start paused) | A/R | R (re-revoke / rotate) | I | — | — | — | I | C |
| Restore acknowledgement, cancels and re-push (client) | C | — | — | — | — | — | A/R | — |
| Chains resumed after restore (after every EA ack) | A/R | — | — | — | — | — | C | — |
| Regulator order on a regulated token | I | — | R (freeze, execute) | A/R (record) | — | — | I | — |
| Regulator order on a permissionless token / denylist add or lift (R246) | A/R (order addressed to it) | — | I | C | — | — | I | I |
| Erasure request (client data) | I | — | — | A/R | — | — | R | — |
| Incident: node / store / chain / lane | A/R (commander) | C | I | — | — | — | I | C |
| Incident: token (backing, depeg, code hash, forced transfer) | R (watch, evidence) | — | A (commander) | R | R | C | I | C |
| Incident: software defect in a release | A/R (own node: roll back) | — | I | — | — | — | I | A/R (fix, release) |
| Post-mortem | R | C | C | C | — | — | C | A (defects) / C |
| Release upgrade of the node; DR drill | A/R | R (drill: shares, keys) | — | — | — | — | R (drill ack) | C / I |
| Monitoring, alert routing and paging of a node | A/R | — | — | — | — | — | I | — |
| Recommended rules, dashboards, scripts (`scaas/ops/`) | C (adopts or changes) | — | — | — | — | — | — | A/R |

Human approval stays mandatory where SCaaS §13.3 says so (land gate, confidentiality horizon, budgets, factory
implementations, controlled-token interventions).

---

## 10. Incident runbooks

### 10.0 Common

Evidence first (T+1 min, SCaaS §13.4), before any change. The evidence directory is mode 0700 on an encrypted volume
and deleted when the incident closes (≤ 30 d, R237):

```bash
CFG=/etc/scaas/node.toml; NODE=http://127.0.0.1:9108; E=/var/lib/scaas-evidence/$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 0700 "$E" && curl -fsS $NODE/metrics > "$E/metrics.txt"; curl -sS $NODE/readyz > "$E/readyz.json"
journalctl -u scaas-node --since -2h -o cat > "$E/node.log"        # or the container's log
sqlite3 /var/lib/scaas/node.db "VACUUM INTO '$E/node.db'"          # PG: pg_dump -Fc; MySQL: mysqldump --single-transaction
```

Admin session (password never in argv) and helper used below:

```bash
read -rs PW; T=$(jq -n --arg n "$ADMIN" --arg p "$PW" '{name:$n,password:$p}' \
  | curl -fsS -X POST $NODE/v1/admin/login -H 'Content-Type: application/json' -d @- | jq -r .token); unset PW
adm() { m=$1 p=$2; shift 2; curl -fsS -X "$m" "$NODE$p" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' "$@"; }
```

Request bodies not fixed by NI §7.3 are fixed here: chain state `{"state": "active|paused|halted", "reason": "…"}`;
breaker reset `{"lane": "<label>|*", "breaker": "<name>|*"}`; chain patch as NI §7.3 with `breaker` merged (§4.4).

#### RB-01 node down or not ready
1. `curl -sS $NODE/readyz | jq .reasons` — `rpc:` ⇒ RB-05; `indexer lag`/`finality violated` ⇒ RB-06; `store` /
   `not owner` ⇒ RB-07; `lane … used outside this store` ⇒ RB-04; `audit chain broken` ⇒ RB-10; `issuer failed
   closed` ⇒ OIDC (fix the IdP or `modes`). A single chain not ready is P2 (`ScaasChainNotReady`), not a node page.
2. Process down: `systemctl status scaas-node`; "store missing" ⇒ the volume is not mounted — **never** run `store
   init` on a production host (it creates an empty store; R110 halts every client).
3. Disk low: grow the volume, never delete store files. Restart loop or memory: evidence, roll back to the previous
   release (OW informed), open a defect.

#### RB-02 breaker open
1. `adm GET /v1/admin/chains/$C/lanes | jq '.[] | {lane, balance, breaker}'`.
2. `balance_floor` ⇒ RB-14 (closes after funding). `gas_budget` ⇒ wait for the next UTC hour, or the finance owner
   approves: `adm PATCH /v1/admin/chains/$C -d '{"breaker": {"gas_budget_per_hour": "…"}}'` (merge patch).
   `base_fee_spike` ⇒ wait; reset only if understood: `adm POST /v1/admin/chains/$C/breaker/reset -d
   '{"lane":"*","breaker":"base_fee_spike"}'`. `revert_streak` ⇒ RB-16 first (it survives restarts).
3. All lanes open (P1): work is held, nothing is lost; tell clients via the status page if > 30 min.

#### RB-03 stuck lane
Symptom: `scaas_lane_head_stuck_seconds` high, `ScaasFeeCapReached`, W3B-01 burn.
1. `adm GET /v1/admin/jobs?chain=$C&state=broadcast` — lowest `outer_nonce` per lane; compare with `nonce_at(latest)`.
2. EVM at the cap: raise for this chain (hot): `adm PATCH /v1/admin/chains/$C -d '{"max_fee_cap_gwei": 1000}'`
   (finance informed), or wait. **Never** abandon the nonce (N3) or re-sign the intent (N5).
3. Nonce gap (head nonce has no tx on any endpoint): restart — cold start `plan()` gap-fills journaled nonces not in
   the mempool and requeues their jobs.
4. Head is an **adopted** nonce (R241, no job row): the lane replaces it with a 0-value self-send at that nonce,
   bumped like any journaled tx; check `scaas_submit_replacements_total{kind="gapfill"}`. Not replaced ⇒ defect (OW).
5. Generic lane (one tx in flight): check the family explorer for the journaled hash; Solana durable nonce account
   readable; Sui gas objects not locked.
6. Lane unrecoverable: `adm PUT /v1/admin/chains/$C/lanes -d '{"lanes":[…without it…]}'` (`409 LANE_BUSY` until its
   rows are terminal), restart, drain its balance to treasury.

#### RB-04 foreign nonce
Symptom: `ScaasLaneForeignNonce`, `/readyz` "lane … used outside this store". The lane refuses to lease (correct).
1. Who else signs with this key? A second `scaas-node` on a copied mnemonic, a restored old store, a manual wallet
   send. `scaas-node addresses --config $CFG` on every host holding the mnemonic; explorer txs after `journal_max`.
2. Second user or unknown sender ⇒ the mnemonic is **exposed**: KC creates a new one, NO moves every lane (RB-03
   step 6) and drains old lanes; security incident.
3. Only after a restore of this store (RB-08), with node stopped: `scaas-node lane accept-nonce --chain $C --lane $L
   --config $CFG` without `--confirm` prints the adopted nonces; **any nonce whose digest matches no job of the
   restored store and no tx we sent ⇒ step 2**. Otherwise rerun with `--confirm <pending−1>` (R241).
4. `ScaasConsumedOnPrivate` (P3) is the soft version: find the relayer from `MetaTransactionExecuted.relayer`.

#### RB-05 RPC divergence
1. `curl -fsS $NODE/metrics | grep -E 'scaas_rpc_(head_lag|requests)'` — which `endpoint` lags, errors or disagrees.
2. Compare the block hash at the disputed height on every endpoint and one independent explorer.
3. Lying or forked endpoint: remove it from `rpc_urls` (toml-only, R95), keep `len ≥ quorum` (add a replacement
   first), restart. Divergence with a correct endpoint set ⇒ RB-06.
4. The indexer holds while the quorum disagrees (N8): nothing is booked; submission continues.

#### RB-06 chain halt or finality violation
Chain halt (network stalled, `ScaasIndexerStalled`, final-head age rising on every endpoint):
1. Confirm on the network's status channel and two explorers.
2. `adm PUT /v1/admin/chains/$C/state -d '{"state":"paused","reason":"network halt"}'` — stops leasing, keeps
   indexing and tracking; jobs expire by `valid_until`. Do not bump or cancel broadcast txs. Resume with `"active"`
   after 5 min of steady head growth (OA).

Finality violation (`ScaasFinalityViolated`, `/readyz` "finality violated at <block>"; the hold survives restarts):
1. Evidence; `adm PUT /v1/admin/chains/$C/state -d '{"state":"halted","reason":"finality violation"}'`.
2. Find the first differing final block with the quorum; every event at or after it is suspect.
3. Inform every ERP admin of a namespace granted the chain; clients reverse or re-verify bookings manually. **No
   automatic rewind** (R242).
4. After OW review: stop the node, `scaas-node index reset --chain $C --to <block> --confirm <block> --config $CFG`
   (not `store restored`), start. Every client resets its event cursor for the chain to `<block>` first (Odoo: a
   system-group action on `blockchain.chain`, with NI P5); dedup by `(chain_key, tx_hash, log_index)` absorbs the rest.

#### RB-07 store owner loss
Symptom: `ScaasFencingLost`, `NOT_OWNER` (503), `ScaasStoreCommitUnknown`.
1. The node stops leasing/journaling and re-takes the lock with a new epoch (A1.1); if it cannot, another process
   holds it: SQLite `fuser -v /var/lib/scaas/node.db.lock`; PostgreSQL `SELECT pid, application_name, client_addr FROM
   pg_stat_activity WHERE pid IN (SELECT pid FROM pg_locks WHERE locktype = 'advisory')`; MySQL
   `SELECT IS_USED_LOCK('scaas-node:<store_id>')`.
2. Stop the intruder (a second unit, a test container with the production `[store] url`); the node re-takes the
   lock; `scaas_store_owner_epoch` increases. PgBouncer in front of PostgreSQL is refused by design (A1.1).
3. Repeated commit-unknown: database or network fault; re-read-before-act keeps it safe; fix the transport.

#### RB-08 restore
Only when the store is lost or corrupt (not for a bad config change). Sequence R240, commands §11.3. Clients halt
(R110); chains stay paused until their ERP admins have acknowledged.

#### RB-09 compromised API key
1. `scaas-node key revoke $KEY_ID --config $CFG` (or `adm DELETE /v1/admin/keys/$KEY_ID`, KC) — hot, ≤ 2 s.
2. Scope: `adm GET "/v1/admin/audit?since=…"`, logs by `key_id`, `adm GET "/v1/admin/jobs?namespace=$NS"`. A key
   cannot forge subject signatures; it can push jobs of its namespace (`call` jobs if `allow_call`), cancel
   unpublished jobs, read the namespace feeds (pseudonymous payment data: legal assesses notification).
3. Cancel unwanted queued jobs: `adm POST /v1/admin/jobs/$UID/cancel`. Signed jobs run to completion.
4. KC issues a new key (`scaas-node key create --namespace $NS --scopes "submit read"`), EA enters it. Client server
   compromised ⇒ `adm PATCH /v1/admin/namespaces/$NS -d '{"state":"suspended"}'` until cleaned.

#### RB-10 compromised admin
1. `scaas-node admin disable $NAME --config $CFG` (bumps `session_epoch`). OIDC: disable the subject at the IdP; if
   the IdP is suspect remove the issuer from `[api.admin_auth]` and restart.
2. Review `adm GET "/v1/admin/audit?since=<last trusted>"`: `fee_recipient`, tokens, lanes, mesh peers and URLs,
   policy, sponsorship, namespaces, denylist, users, keys. Revert each change through the same routes.
3. `ScaasAuditChainBroken` ⇒ the store was edited outside the node: host compromised: evidence, rotate `master_key`,
   rotate lane keys, restore from a backup older than the break if config was altered (RB-08), security incident.
4. Rotating `master_key` revokes every client API key and session at once: EA re-enters new keys.

#### RB-11 wrapper shortfall or depeg
Shortfall (`scaas_wrapper_leg_backing_ratio < 1`: blacklist burn, negative rebase, confiscation, bug):
1. Evidence: `adm GET /v1/admin/chains/$C/watch`; confirm `legOf(u)` and `underlying.balanceOf(token)` on two
   endpoints.
2. Issuer (commander) informs holders; the app shows per-leg backing before a wrap (TW2 §8.4). Wrap into other legs is
   **not** stopped by the contract (owner decision L3): the issuer asks integrators to pause intake; the guardian may
   `disableWrap` the leg. Permissionless token: migration to a new token is the remedy (SCaaS §13.6).

Depeg on a Multi leg (external price signal):
1. Guardian submits `disableWrap(u, reason)` **privately** (private relay or builder bundle), never through the public
   mempool or an open-mesh job.
2. Exits stay open; no re-enable exists (a new token if the leg must return). RA cancels pending rate changes during
   the incident (`RateDecreaseWithDisabledLeg` blocks decreases anyway).

#### RB-12 code-hash change
1. The `watch-code-hash` script's state file names the role, old and new hash/implementation.
2. Underlying upgraded: the issuer reviews the new behaviour (freeze, fee-on-transfer, rebase). Until reviewed, NO may
   pause intake for the token: `adm PATCH /v1/admin/chains/$C/tokens/$TOKEN -d '{"active": false}'` — every op
   refused (unwraps included: use when the risk outweighs blocking exits), **indexing continues**. Never `DELETE` the
   token for this: that drops its events from the feed for good (re-registration needs `index reset`).
3. Role contract changed (Safe upgraded, guardian contract): verify with the role owner; accept with
   `watch-code-hash --repin --chain $C --token $TOKEN`.
4. Token or registry code changed: impossible for EIP-1167 clones ⇒ wrong address or lying RPC ⇒ RB-05.

#### RB-13 regulator order
Regulated token (`*_REG`, AS §3.5):
1. Legal validates the order. CO records it: `recordOrder(orderId, docHash, subject, beneficiary, maxAmount)` from the
   compliance multisig (optionally submitted as a `call` job by the issuer's ERP namespace).
2. IS asks NO in writing for a silence of `ScaasForcedTransfer` with matchers `chain` **and `token`** for the planned
   window; NO creates it (the other tokens keep paging).
3. IS: `freeze(subject, ref)`, then `forceTransfer(recordId, amount)` ≤ `maxAmount`; `unfreeze` when the order says
   so; CO `revokeOrder` stops further execution.
4. `OrderRecorded` without a matching internal record (`ScaasWatchedEvent`) ⇒ compliance key compromise (AS A2): CO
   revokes the record, rotates the multisig signer, IS refuses execution.

Permissionless token: no on-chain power exists (SCaaS §4.5); the order binds the operator it is addressed to. After
its legal validates the order, the operator lists the party (R246):
`adm POST /v1/admin/deny -d '{"chain_key":"*","address":"0x…","order_ref":"…","document_sha256":"<64 hex>"}'`; lift
with `adm POST /v1/admin/deny/$ID/lift -d '{"lift_ref":"…"}'`. Other operators and self-submission still reach the
contract; legal answers with that limit stated. `ScaasDenylistChanged` is checked against the order register.

#### RB-14 runway
1. `scaas-node addresses --config $CFG`; fund from treasury to the float target (~50 tx, SCaaS §13.2); the
   `balance_floor` breaker closes on the next 15 s sample.
2. Runway falling at flat volume ⇒ fee regime changed (base-fee spike, rollup L1 data fee): finance reviews budget.
3. Sponsor budget exhausted: the policy follows `on_exhausted`; the sponsor owner raises it (`adm PATCH
   /v1/admin/sponsorship/policies/$ID`) or accepts rejects.

#### RB-15 feed client stalled
1. `scaas_job_api_requests_total{namespace=$NS}` — none ⇒ client stopped; `401` ⇒ key revoked or clock skew (> 300 s,
   NTP); `410 CURSOR_EXPIRED` ⇒ client recovery (integration §4.3).
2. Odoo: crons `cron_node_push`/`cron_node_sync` active, `blockchain.node.needs_attention` (store change ⇒
   acknowledge after RB-08 confirmation), last error on the node form.

#### RB-16 simulation-gap revert
1. `adm GET "/v1/admin/jobs?chain=$C&state=reverted"`; logs by `job_uid` (`span=scaas.job.simulate` vs `include`).
2. State changed between simulation and inclusion (front-run, attestation expiry, pause) ⇒ expected drift, document;
   simulation on a different block/endpoint ⇒ RB-05; an error simulation should have seen ⇒ defect (OW): keep
   `revert_streak` open, pause the chain if needed.
3. Reset after explanation: `adm POST /v1/admin/chains/$C/breaker/reset -d '{"lane":"*","breaker":"revert_streak"}'`.

#### RB-17 gossip degraded
1. `adm GET /v1/admin/gossip` (mesh size per topic), `adm GET /v1/admin/gossip/peers` (scores, carriers).
2. Zero peers: bootstrap multiaddrs (toml), UDP/TCP 4001 reachability, `scaas_tls_handshake_failures_total` (PQ-only
   QUIC vs classical peers, A2 R114). Thin mesh with healthy peers: graylisting from our own rejects (version skew, A2
   E2) — upgrade or check the clock.

---

## 11. Backup, restore, DR

### 11.1 RPO / RTO per backend (OA)

RPO = after loss of the store's disk (on the same disk every committed journal transaction is durable, NI §9.2).
RTO = start of restore → `/readyz` green, for a store ≤ 20 GB (§12). Backups and copies are encrypted and kept ≤ 7 d
(R237).

| Backend | Continuous | Periodic | RPO | RTO | Reason |
|---|---|---|---|---|---|
| SQLite | Litestream (WAL shipping to an S3-compatible bucket, `sync-interval: 1s`) | `VACUUM INTO` every 5 min to a second disk, last 24 kept; one daily copy off-site | ≤ 10 s with Litestream; ≤ 5 min without | 30 min | `VACUUM INTO` is one consistent statement (the CLI `.backup` restarts under concurrent writes); the owner lock is on `<db>.lock`; Litestream is external |
| PostgreSQL | WAL archiving (`archive_mode = on`, `archive_timeout = 60`), pgBackRest or `pg_basebackup` + `archive_command` | daily base backup | ≤ 60 s (0 with a synchronous standby) | 30 min | PITR is per cluster: give the store its own cluster |
| MySQL 8 | binlog (`ROW`, `sync_binlog = 1`) streamed off-host (`mysqlbinlog --read-from-remote-server --raw --stop-never`) | daily XtraBackup or `mysqldump --single-transaction` | ≤ 60 s | 45 min | binlog replay is slower than WAL replay |

| Component | RPO | RTO | Mechanism |
|---|---|---|---|
| Lane state | — | minutes | cold start `plan()`; after restore `lane accept-nonce` (R241) |
| `master_key`, lane mnemonic | must never be lost | 15 / 30 min | secret store or KMS; Shamir 2-of-3 (OA) held by KC; loss ⇒ re-issue every API key and session / new lanes, lane gas lost |
| Node identity key | — | 30 min | secret store; loss ⇒ new `peer_id`; bus partners re-pin SPKI |
| `node.toml` | per change | 15 min | version control without secrets (secrets are references, R20) |
| Logs (off-host) | stream | — | ≤ 30 d (R237); needed for the post-backup audit replay |
| Private chain | 0 | 60 min | validator snapshots every 6 h + archive node (SCaaS §13.5) |

Backup scripts write `scaas_backup_last_success_timestamp_seconds{backend}` and `scaas_backup_interval_seconds` to
the textfile collector (seeded with 0 at install).

### 11.2 What a restore loses and how it is recovered

| Lost after the backup point | Recovered by |
|---|---|
| Jobs accepted after the backup | client re-push after acknowledgement (idempotent; R91) |
| Cancels and client-side kills after the backup | chains start paused; the client acknowledgement re-sends `cancel {origin}` for jobs it holds dead (R240) |
| Journal entries (`signed`) after the backup | the chain: txs land or drop; `lane accept-nonce` adopts the nonces; **meta-tx and op jobs** are protected by subject nonces (G1); **`call` jobs** have no node digest and no subject nonce — a target qualifies for `allow_call` (R103) only if it enforces its own replay protection (`MandateWallet` `refUsed[entryRef]`, idempotent account deploy, DEX fills consumed), and paused chains give the client time to cancel |
| Feed items after the backup | indexer re-delivers from the restored `chain_index` (ranges idempotent) |
| Credential, denylist, token, chain-state, fee-recipient, namespace and peer changes after the backup | re-applied from the off-host audit events before resume (R240); incomplete logs ⇒ rotate `master_key` (T19) |
| Purged rows resurrected by an old backup | `store restored` runs the retention purge before the node serves |
| Sponsor reservations | recomputed from live jobs at start (TSS §B1.7) |

### 11.3 Restore commands

```bash
systemctl stop scaas-node
mv /var/lib/scaas/node.db /var/lib/scaas/node.db.broken-$(date -u +%s) 2>/dev/null   # evidence, never overwritten
litestream restore -o /var/lib/scaas/node.db s3://<bucket>/scaas/node.db             # or: cp <copy> node.db
sqlite3 /var/lib/scaas/node.db 'PRAGMA integrity_check'                              # must print "ok"
chown scaas:scaas /var/lib/scaas/node.db && chmod 0600 /var/lib/scaas/node.db
# PostgreSQL (into the store's own empty cluster): pgbackrest --stanza=scaas --type=time --target='<UTC>' restore
# MySQL: base backup, then mysqlbinlog --start-position=<from backup> --stop-datetime='<UTC>' binlog.0* | mysql scaas
scaas-node store restored --config $CFG               # restore_epoch + 1, every chain paused, purge; audited
for L in $(scaas-node addresses --config $CFG --chain $C --labels); do      # per sequence-family chain
  scaas-node lane accept-nonce --chain $C --lane $L --config $CFG; done     # review listing (RB-04 step 3), then --confirm
scaas-node key revoke <key_id> --config $CFG; scaas-node admin disable <name> --config $CFG   # from audit events
systemctl start scaas-node                            # paused: accepts, indexes, tracks; never leases
# re-apply post-backup deny / token active / fee_recipient / namespace / peer-ban changes through adm (R240)
# after every ERP admin of a namespace granted chain $C acknowledged (and sent its cancels):
adm PUT /v1/admin/chains/$C/state -d '{"state":"active","reason":"restore acknowledged"}'
```

`scaas-node addresses --labels` prints lane labels per chain (OP5 adds the flag). ERP admins acknowledge
(`action_acknowledge_store_change`) and re-push (integration §16.3).

### 11.4 DR drills (R243, cadences OA; review L6: four in v1)

| Drill (`drill` label) | Cadence | Pass criterion |
|---|---|---|
| `restore_<backend>` — latest backup to a scratch host, `store restored`, start paused against a testnet, acknowledge, resume | quarterly per backend in use | RTO met; no job leased before the acknowledgement; `/readyz` green |
| `lane_accept_nonce` — restore an older testnet backup, adopt nonces, land a new job | quarterly | listing shows every adopted nonce; no lane stuck after 10 min |
| `dead_man` — stop Prometheus | quarterly | external switch alerts within 10 min |
| `key_recovery` — reconstruct `master_key` and the lane mnemonic from shares offline | semi-annually | both reconstruct; shareholders reachable |

Optional when the risk applies: indexer kill (stall alert), lying RPC (divergence, no range written), guardian
`disableWrap` on a testnet Multi, cutover rehearsal (NI §11.2, per production cutover). A failed drill is a P3 with
an owner and a date.

---

## 12. Capacity (R244)

Reference hardware class **H1**: one host, 8 vCPU, 24 GiB RAM, NVMe SSD, shared with an ERP stack and its database.
All figures are OA estimates to be **measured** in stream OP1 (a load test run alone, OOM rule).

| Resource | Budget / limit | Reason |
|---|---|---|
| Node RSS | ≤ 256 MiB without gossip; + 64 MiB with gossip at 50 peers (A2 R126) | leaves the ERP its memory; alert at 2× |
| Node CPU | < 1 core sustained at the rated load | k256 signing ≈ 0.1 ms, JCS + SHA-256, JSON; gossip < 5 % of a core (R126) |
| Store journal transactions (SQLite, `synchronous = FULL`) | ≤ ~300/s (fsync ≈ 1–3 ms, one connection) | each job ≈ 5–7 transactions over its life |
| **Rated throughput per node** | **10 jobs/s** for hours (alert at 70 %) | ⅕ of the store ceiling |
| **Rated daily volume** | ≈ 270 000 jobs/day at 30 d retention (store ≈ 20 GB at ≈ 2.5 KB per job across `job`, `job_event`, `feed_item`) | keeps §11.1 RTO and backup sizes; above it, lower `job_retention_secs` (≥ `valid_until` + 1 d, NI §4) or accept a longer RTO |
| PG/MySQL store | ≈ SQLite figures **at ≤ 1 ms RTT**; ≈ 5 jobs/s at 5 ms (≈ 6 statements per transaction, serialized on the fencing row) | A1.2 |
| EVM lane | ≤ 16 txs in flight (typical per-account pending-slot limit) ⇒ Gnosis ≈ 3 tx/s per lane | the mempool is the limit |
| Generic lanes (one tx in flight) | ≈ 1 ÷ `include`: Sui ~2/s, Aptos ~1/s, Solana ~1/s, Hedera ~0.3/s, Cosmos/Soroban ~0.15/s, TON ~0.1/s per lane | lanes = target rate ÷ per-lane rate (≤ 8) |
| Job API / gateway | 20 POST rps (burst 40), 10 GET rps per key; batch ≤ 50; pages ≤ 500 / 1 MiB; ≤ 4 long-polls per key / `MAX_INFLIGHT` 64, body 64 KiB | NI §5.4, §3 |
| Label caps | ≤ 16 chains, ≤ 8 lanes per chain, ≤ 32 namespaces, ≤ 64 tokens per chain, ≤ 256 watched wrapper legs | R244 |
| `/metrics` | series ≈ C·(9N + 6 + 102 + 14L + 4E + 2T) + C·N + W + ~1 500 (HTTP, admin, mesh, store) ⇒ ≈ 13 000 at the caps (C 16, N 32, L 8, E 4, T 64, W 256), ≈ 2 500 typical (C 4, N 4, L 4, E 2, T 8) | `scaas_relay_jobs` (9N per chain) dominates; scrape 15 s |

Above the rated load: a second node on **different chains** (R97), not a bigger store.

---

## 13. Streams

| # | Stream | Content | Depends on | Status |
|---|---|---|---|---|
| OP1 | Metrics core | histograms, pre-emission, §4.3 series, `metrics_bind`, parallel probes, `revert_streak` + `breaker_latch`, finalize map, load test on H1 | NI P3, P4 | **SPECIFIED** |
| OP2 | Logs and trace ids | `[log] format`, JSON fields, `traceparent`, `job.trace_id`, audit mirror at `warn`, rate limit | NI P2 | **SPECIFIED** |
| OP3 | Ops watch | leg backing, watched events with `token`, `…/watch`; `scaas/ops/watch-code-hash` script | NI P4, TW2 T7, AS AS7 | **SPECIFIED** |
| OP4 | FinOps | cost columns for every job, `usage_day`, counters, `report usage`, `/v1/admin/usage` | NI P3, TSS SP1 | **SPECIFIED** |
| OP5 | Integrity and DR tooling | `store restored` pause + purge, `lane accept-nonce` + `lane_adopted`, `index reset` (+ Odoo cursor reset and acknowledgement cancels, NI P5), start-time and periodic final-hash recheck, audit verification, `token.active` route, backup scripts | NI P3/P4; PG/MySQL after P1b | **SPECIFIED** (SQLite parts before P6) |
| OP6 | Ops bundle | `scaas/ops` rules (§5.1), Alertmanager example, three dashboards, promtool tests | OP1 | **SPECIFIED** |
| OP7 | OTLP export | cargo feature `otel`, spans of §6 | OP2 | PLANNED |
| OP8 | Subject denylist | `deny_subject`, intake and lease checks per door, routes, metrics, add-time hold/dead, DEX failed path | NI P2/P3 | **SPECIFIED** |

Order: OP2 → OP1 with P3/P4 → OP5 SQLite part and OP6 before P6 cutover → OP8 with P3 → OP4 with SP1 → OP3 after TW2
T7 → OP5 PG/MySQL with P1b → OP7. Heavy builds and the OP1 load test run one at a time.

Tests: golden renderer tests (new families, pre-emitted zeros); promtool `test rules` for every alert, including a
foreign nonce and an audit break present at process start; `revert_streak` boundary (2 vs 3 in 15 min, `race`
excluded) and survival across restart; `usage_day` concurrent upserts and decimal sums; `accept-nonce` refuses when
`pending − 1 ≤ journal_max`, when an endpoint is missing, or with a wrong `--confirm`, and lists an unmatched digest;
adopted head replaced by a gap-filler; restore drill: a job cancelled after the backup point is never leased;
start-time final-hash recheck on a forked devnet; audit verification detects one edited row; denylist per party
position and door, lease-time re-check after `signed → queued`, `*` vs chain entries, expiry, no address in logs,
labels or the audit mirror; log redaction (no payload/address/amount/secret in an e2e run, grep-based).

---

## 14. Open questions (owner)

None open. Owner answers (rev 1.1): q1 subject denylist **yes**, at node intake, operator's choice (R246); q2 SLOs
stay **internal objectives**, no SLA or credits (R247); q3 customer-run nodes are **monitored by the customer**,
SCaaS ships the `scaas/ops` bundle (R231, §9).

---

## 15. Review disposition (review 1, FIX-THEN-GO)

| # | Finding | Disposition |
|---|---|---|
| H1 | Restore leases jobs cancelled after the backup; post-backup security changes undone | applied: chains start paused, re-apply step, acknowledgement cancels, resume after ack (R240, §11.2–11.3, RACI) |
| H2 | `accept-nonce` can lower `journal_max`; adopted nonces unmonitored; Sui/Solana | applied: refusal rule, all endpoints + max pending, listing with digest match, `lane_adopted` + gap-filler replacement, head-stuck redefined, Sui/Solana rule (R241, RB-03/04) |
| H3 | Start-time conditions never fire as counters | applied: latched gauges, pre-emission rule, `readyz` reason (R230, R242, §4.1) |
| H4 | `revert_streak` and the finality hold lost on restart | applied: `breaker_latch`, start-time recheck (R233, R242) |
| M1 | Token `DELETE` drops events | applied: `active` intake pause route; RB-12 forbids delete |
| M2 | Node-wide readiness pages per-chain issues | applied: `scaas_node_ready` P1, `scaas_chain_ready` P2 |
| M3 | Off-host scrape vs loopback admin bind | applied: `metrics_bind` (R230) |
| M4 | Series bound wrong | applied: existing legs only, code hash per token (and outside the node), no `namespace` on terminal outcomes, `audit_head_seq`, issuer index, honest bound (§12) |
| M5 | Indexer stall wrong on `tag` chains | applied: `scaas:indexer_stall_seconds` per chain |
| M6 | Forced-transfer silence too wide | applied: `token` label; NO creates the silence at IS's written request |
| M7 | Denylist bypass on requeue; lift and DEX unstated | applied: lease check, lift and DEX lines, exits line (§4.5) |
| M8 | PII: audit mirror, backup age, evidence, warn-only sinks | applied: `***` for deny addresses, backups ≤ 7 d + TSS amendment, purge on restore, evidence rules, audit at `warn` (R237) |
| M9 | User creation under R107 | applied: CLI for operator/admin users, procedural second person (R239, RACI) |
| M10 | Backup and capacity figures | applied: last 24 copies, `VACUUM INTO`, rated daily volume, rows from counters, RTT assumption (§11.1, §12) |
| M11 | `call` jobs after restore | applied: R103 precondition stated (§11.2) |
| L1 | Event names | applied, except: `ImplementationRegistered`/`Deprecated` exist in `IOpenFactoryV2.sol` (kept); `MetaNonceCancelled` is a subject's own action already handled by R80, not an ops event (not added) |
| L2 | PromQL hygiene | applied: `by (instance)`, signed-terminal volume gate, `absent()` rules, seeded textfiles, `$STORE_MOUNT`, hourly budget rule; composition rule removed with L6 |
| L3 | Stage map key and late reverts | applied (R233, R234) |
| L4 | Snapshot staleness | applied: parallel probes in OP1, `scaas_snapshot_age_seconds` |
| L5 | Request bodies and labels | applied: merge patch, token route, OP1 labels for `bump_skipped` |
| L6 | Over-engineering | applied: code-hash watch moved to a `scaas/ops` script, three dashboards, four drills, composition drift deferred; kept watched events, backing ratio, `usage_day`, denylist |
