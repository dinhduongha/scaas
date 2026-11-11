# Operations: SLOs, metrics, alerts, traces, logs, FinOps, capacity

How a node is observed and measured. Everything here is a **recommendation to node operators**
([NODE-OPS-15](#NODE-OPS-15)); default numbers are proposed with their reasons and approved as defaults
([NODE-OPS-16](#NODE-OPS-16)). Market-neutral: amounts in neutral units; "reporting currency" means the deployment's
own. Status: the metrics marked BUILT exist; everything else **SPECIFIED**. Incident runbooks, RACI and DR are in
[runbooks.md](runbooks.md).

**Contents**

1. [Scope](#1-scope)
   - 1.1 [Severities](#11-severities)
2. [SLOs](#2-slos)
3. [Health](#health)
4. [Metrics](#metrics)
5. [Ops watch](#5-ops-watch)
6. [Integrity](#6-integrity)
7. [Denylist](#denylist)
8. [Alerts](#alerts)
9. [Traces](#9-traces)
10. [Logs](#logs)
11. [FinOps](#finops)
12. [Capacity](#capacity)
13. [Post-quantum Zether chains](#13-post-quantum-zether-chains)
14. [Operator notes, branch `ua-mtx-merge`](#operator-notes)

## 1. Scope

<a id="scope"></a><a id="NODE-OPS-15"></a>**NODE-OPS-15** — **Operators are independent; operations rules are
recommendations.** The smart contracts themselves are the API services that run the business; the node is
infrastructure anyone can run to reach them (submit, index, relay). Each operator sets its own acceptance, fee,
sponsorship, denylist, gossip and peer policy, and its own SLOs, alerting and monitoring (relayer abuse control is the
operator's business); nothing here binds another operator or the network. Protocol guarantees — contract rules, subject
signatures, nonces, expiry — hold on chain whatever any operator does; a refusing or slow operator costs liveness only,
countered by other operators or self-submission. The `scaas/ops` bundle and every default are recommendations, not
obligations; SLOs are internal objectives, with no SLA or credits. The one on-chain cap a relayer may want for abuse is
a sponsor budget ([sponsorship.md#budgets](sponsorship.md#budgets)).

In scope: SLIs/SLOs per component with error budgets; metric names and labels; alert rules, severities, routing;
dashboards; trace scope; structured logs and their personal-data rules; FinOps measurement and the monthly report;
capacity limits. Non-goals:

- High availability for one (company, chain) ([README.md#limitations](README.md#limitations)). DR is restore, not
  failover.
- Automatic lane refill from a treasury ("auto-refill", PLANNED); runway alerts replace it in v1.
- A price oracle in the node. FinOps conversion uses an operator-supplied price file.
- Contractual SLAs or service credits: every target is an internal objective of whoever runs a node.
- Telemetry from the console app. The app sends nothing; W3B-05 is a release benchmark.
- Multi-leg composition-drift series; leg backing ([NODE-OPS-08](#NODE-OPS-08)) covers the loss case.

### 1.1 Severities

<a id="severities"></a><a id="NODE-OPS-05"></a>**NODE-OPS-05** — **Three severities**; P1 = exactly the `scaas-p1`
group of the rule file ([alerts](#alerts)). Pages that do not mean "integrity or outage" train people to ignore pages.

| Sev | Meaning | Routing | Acknowledge within | Why |
|---|---|---|---|---|
| **P1** | Integrity at risk (journal, nonce, feed, audit, reserve) or service stops within the hour | page 24/7, on-call of the accountable role ([runbooks.md#raci](runbooks.md#raci)) | 15 min | the incident clock starts at T+0; loss in a reaction window = cap rate × 15 min |
| **P2** | Degraded, or a security-relevant change to verify the same day | page in business hours, ticket otherwise | 4 h | one working half-day; nothing here loses data while waiting |
| **P3** | Trend, budget or hygiene | ticket | next business day | |

## 2. SLOs

<a id="slos"></a><a id="NODE-OPS-04"></a>**NODE-OPS-04** — **SLOs, alerts and dashboards are evaluated outside the
node, by whoever runs it**: Prometheus + Alertmanager on infrastructure that is neither the node's host nor the ERP's,
plus an external dead-man's switch fed by an always-firing `Watchdog`. The node exports raw series only. The
recommended rule file, Alertmanager example, dashboards and watch scripts ship in `scaas/ops/`; operators adopt, change
or replace them. (Monitoring on the monitored host is switched off by whoever owns that host.) Customer-run nodes are
monitored by the customer.

<a id="NODE-OPS-16"></a>**NODE-OPS-16** — **The default numbers below are approved as defaults.** Each is an
operator-tunable recommendation; changing one never changes a ruling's reasoning.

Telemetry targets W3B-01 … W3B-06:

| Id | Indicator | Definition | Target | On breach | Status |
|---|---|---|---|---|---|
| W3B-01 | Meta-tx success rate | intents finalized (incl. `landed_elsewhere`) ÷ intents broadcast, 30 d | ≥ 99.5 % | fail over RPC, check lane balances, page operator | metric inputs **BUILT** (`scaas_relay_jobs{state}`); SLO **SPECIFIED** |
| W3B-02 | Simulation zero-revert | broadcast transactions that reverted for a reason simulation would have caught ÷ broadcast; lost races (`consumed`) excluded | **0.00 %** (any occurrence is an incident); guard: revert rate ≤ 0.5 % per 7 d including races | stop the chain's new work (breaker), investigate contract/simulation drift | gate **BUILT**; metric **SPECIFIED** |
| W3B-03 | Gas budget adherence | gas spent ÷ approved budget per lane and window | ≤ 100 % (warn 90 %) | breaker `gas_budget` stops new work; notify finance owner | **BUILT** |
| W3B-04 | Finality latency | broadcast → final range delivered, p95 | ≤ chain hard finality + 60 s (Gnosis ≤ 240 s + 60 s; SCaaS testnet ≤ 15 s) | alert; check RPC quorum and indexer lag | lag gauge **BUILT** (`scaas_indexer_lag_blocks`); histogram **SPECIFIED** |
| W3B-05 | Zether proof latency | client proof time + on-chain verification | to be set after measurement on target devices | optimize prover/verifier | **SPECIFIED** as a release benchmark |
| W3B-06 | Relayer fee spread | fees earned − gas paid, per chain per month | may be negative (fee = 0 B2B) | monthly OPEX review | **SPECIFIED** ([finops](#finops)) |

Additional operational SLOs: jobs final without manual intervention ≥ 99.5 %/month; outer-nonce gap age = 0 for 99.9 %
of the time; signed-but-orphaned transactions = 0.

<a id="NODE-OPS-06"></a>**NODE-OPS-06** — **W3B as the node measures it.** Each job counts once, at its first terminal
transition, in `scaas_job_terminal_total{chain,outcome}`, `outcome ∈ mined, consumed, reverted, expired_after_sign,
dead_before_sign, cancelled`; a late `mined → reverted` adds `scaas_job_late_revert_total{chain}` instead of a second
count. **W3B-01** = (`mined` + `consumed`) ÷ (`mined` + `consumed` + `reverted` + `expired_after_sign`): `consumed` is
good (landed elsewhere, or the subject chose another intent). **W3B-02**: each reverted receipt of ours is `race`
(the consumption read shows the subject nonce consumed) or `other`; target `other` = 0, each one a P2; **≥ 3 `other`
in 15 min on a chain (three rules out one bad payload; 15 min = one reaction window) opens a chain-level breaker
`revert_streak`**, persisted in `breaker_latch (chain_key, breaker, opened_at, reason)` in the transaction that
records the third revert, re-read at start, cleared only by `breaker/reset` (audited). It stops new work only
(NODE-GEN-09). **W3B-05** is a release benchmark (prover time on reference devices + verifier gas tests). **W3B-06**
is a monthly report figure. The node knows `mined` at once; a mined job that never finalizes is a finality violation
([NODE-OPS-12](#NODE-OPS-12)); W3B-01 over-reports by the paged, ~0 violation rate.

Component SLOs (recommended internal objectives; window 30 days rolling unless stated; "budget" = allowed bad fraction
of the window):

| Component | SLI (series) | Target | Reason | Budget / 30 d |
|---|---|---|---|---|
| Gateway acceptance | p99 of `scaas_http_request_seconds{listener="gateway",route="/v1/metatx"}`; non-5xx share | p99 ≤ 300 ms; ≥ 99.9 % | accept does no RPC (one store transaction + auth) | 43 min |
| Job API acceptance | p99 of `…{listener="api",route="/v1/jobs",method="POST"}` (≤ 50 items); non-5xx share | p99 ≤ 1 s; ≥ 99.9 % | 50 JCS hashes + one transaction; an ERP cron worker waits | 43 min |
| Queueing | p95 of `scaas_job_stage_seconds{stage="queue"}` while no breaker/pause | ≤ 5 s | poll 1 s × a few rounds; a 1 h p95 absorbs one 15 s restart hold | — |
| Submit → mined | p95 of `stage="include"` per chain | latency table below | a few blocks per family | — |
| W3B-01 success | [NODE-OPS-06](#NODE-OPS-06) ratio | ≥ 99.5 % | W3B table | 0.5 % of jobs |
| W3B-02 zero revert | `scaas_submit_reverted_total{class="other"}` | 0 | each P2, streak ⇒ breaker | 0 |
| Revert incl. races | all reverts ÷ broadcasts, 7 d | ≤ 0.5 % | guard | — |
| Consumed rate, private profile | `consumed` ÷ signed-terminal, 1 d | ≤ 1 % | on `restricted` scope only the subject can race us | — |
| W3B-03 gas budget | breaker `gas_budget` open minutes | ≤ 100 % (warn 90 %) | breaker (BUILT) | — |
| Indexer progress | `time() − scaas_indexer_last_progress_timestamp_seconds` | ≤ `scaas:indexer_stall_seconds` per chain: 60 s on depth/instant chains, 2 × the final-head step on `tag` chains (Celo ≈ 800 s) | empty ranges are written whenever the final head moves | 7 h 12 min |
| Indexer lag | `scaas_indexer_lag_blocks` | ≤ `max_index_lag` (100) | readiness | — |
| Finality lag | `time() − scaas_final_head_block_time_seconds` | ≤ hard finality + 60 s | W3B-04 rule applied to the head | — |
| W3B-04 | p95 of `stage="broadcast_final"` | latency table below | W3B table | — |
| Feed to clients | `scaas_feed_last_poll_seconds` per namespace with live jobs | ≤ 180 s for 99 % | ERP clients poll every 60 s, ~10 s while live | 7 h 12 min |
| Mesh propagation | p95 of `scaas_mesh_propagation_seconds` | gossip ≤ 1 s, bus ≤ 3 s | ≪ the 7 s exclusivity window | — |
| Gossip health | `scaas_gossip_mesh_peers{topic_kind="intent"}` per chain | ≥ `mesh_n_low` (4) for 99 % | gossip numbers | 7 h 12 min |
| Store | p99 of `scaas_store_tx_seconds{kind="journal"}`; fencing lost; commit unknown | ≤ 50 ms; 0; 0 | NVMe fsync ≈ 1–2 ms, PG/MySQL one RTT (≤ 1 ms LAN) | — |
| Backups | `time() − scaas_backup_last_success_timestamp_seconds` | ≤ 3 × interval | RPO is the interval | — |
| Node and app | `scaas_node_ready`; blackbox `probe_success` of the app `/` + `/config.json` | ≥ 99.5 % | an operator console, not a payment path | 3 h 36 min |

Latency targets per family and profile: `include` = first broadcast → mined (p95). `broadcast_final` (p95) = hard
finality + 60 s for depth/tag families, `include` + 30 s for instant families (one indexer poll plus a range write).

| Chain class | Block / finality | `include` | `broadcast_final` | Reason |
|---|---|---|---|---|
| EVM private (SCaaS testnet, formerly 9000; Clique, 1 signer) | ~5 s, depth 1 | 15 s | 15 s | 3 blocks |
| EVM public (Gnosis) | 5 s, `finalized` ~160–240 s | 30 s | 300 s | 6 blocks; 240 s + 60 s |
| EVM L2 (Celo, `tag` until `l1_batch`) | 1 s, L1 finality ~13–20 min | 10 s | 1 260 s | 20 min + 60 s |
| Hedera | 3–5 s record files, instant | 15 s | 45 s | 3 record files |
| Cosmos / Soroban (Stellar, Pi) | ~5–6 s, instant | 20 s | 50 s | 3 blocks/ledgers |
| Sui / Aptos | ~0.5–1 s, instant | 5 s | 35 s | |
| GRAM | ~5 s masterchain, message chains | 60 s | 90 s | jetton transfers span several messages |
| Solana | 0.4 s slots, `finalized` ~12.8 s | 10 s | 75 s | confirmed + 60 s margin |

A chain stays out of `active` until 7 days of measurements exist ([runbooks.md#production-gates](runbooks.md#production-gates));
the measured p95 + 20 % then replaces the default row for that chain.

Error-budget policy:

- Burn-rate alerts (multi-window): **fast** 14.4× over 1 h and 5 min ⇒ P1; **slow** 6× over 6 h and 30 min ⇒ P2;
  **trend** 1× over 3 d ⇒ P3. Minimum volume: 20 signed-terminal jobs in the long window.
- Budget exhausted: only fixes ship to that node until it recovers (risk-reducing changes — pause, breaker, lane
  retirement — always allowed). One incident consuming > 25 % of a budget ⇒ post-mortem with a regression test.

## <a id="health"></a>3. Health

<a id="health"></a><a id="admin-listener"></a><a id="NODE-OPS-01"></a>**NODE-OPS-01** — **`/readyz` and `/metrics` are
served on the admin port**, separate from the public gateway (`[modules] admin_bind`, default `127.0.0.1:9108`; or the
optional `metrics_bind`, [NODE-OPS-03](#NODE-OPS-03)). The node has `/readyz` even without a gateway.

- `GET /healthz` — the process is alive.
- `GET /readyz` — answered at once from a **cached state** that a background task refreshes every 10 s; `200` only
  when node-scope ready (store open and owned, audit chain ok, ≥ 1 chain ready = `scaas_node_ready`); body `{"ready",
  "reasons": [...], "chains": {"<key>": {"ready", "reasons"}}}` (= `scaas_chain_ready`). A chain is ready when ≥
  `finality.quorum` RPCs answer within 3 s, indexer lag `head_final − indexed ≤ max_index_lag` (configured per chain),
  and its other reasons are empty; otherwise `503` with the JSON reasons. Reasons: store not open or not owner; final
  head missing; index lag; lane used outside the store; issuer failed closed; RPC endpoints disagree on a range's event
  set; `finality violated at <block>`; `chain_uid mismatch`; chain held for an upgradeable program
  (`PROGRAM_UPGRADEABLE`); `audit chain broken`; no gossip peer for 5 min (informational, not fatal for submission).
- `GET /metrics` — Prometheus text, hand-written (no crate). Job counts come from the store (`scaas_relay_jobs`);
  client-side counts (attention, drift alerts) leave the node.

Transitional (BUILT): readiness reads job counts from the legacy client (`relay_stats`), and `/readyz` also requires
the client to answer.

## <a id="metrics"></a>4. Metrics

<a id="metrics"></a><a id="NODE-OPS-03"></a>**NODE-OPS-03** — **Metrics = Prometheus text rendered by the existing
hand-written renderer (`admin.rs` `render`); no metrics crate.** Prefix `scaas_`; base units (seconds, bytes, smallest
native unit); counters `_total`; histograms with fixed buckets. Labels only from the allowlist below: never a subject
address, payer, amount, `tx_hash`, job uid, `entry_ref`, open-mesh peer, URL or IP; RPC endpoints and OIDC issuers by
index, because URLs may embed provider keys. **Every counter and latched gauge is emitted at 0 for every configured
label set from process start** (so `increase()` sees the first event). **`[modules] metrics_bind`** (default `""` =
served on `admin_bind`) serves only `/metrics`, `/readyz`, `/healthz`; the `scaas/ops` bundle assumes it, bound to a
private monitoring network or behind an mTLS proxy. Exposing `admin_bind` to monitoring is never recommended; metrics
name tenants, lanes, tokens and balances and are internal data. One dependency less on a small box; a crate swap would
keep every name.

Rules:

- **Label allowlist:** `chain`, `family`, `profile`, `lane` (lane label), `namespace` (incl. `~gateway`, `~mesh`,
  `~dex`), `token` (registered token address), `leg` (existing legs only), `state`, `outcome`, `result`, `class`,
  `stage`, `kind`, `breaker`, `listener`, `route` (templated), `method`, `code_class`, `endpoint` (RPC index), `issuer`
  (OIDC issuer index), `feed`, `table`, `backend`, `carrier`, `topic_kind`, `event`, `door`, `action`, `policy`
  (sponsor policy name), `drill`, `peer` (admitted bus peers only), plus the labels fixed in the tables below. No label
  whose value set grows with traffic.
- **Pre-emission:** counters and latched gauges exist at 0 for every configured chain, lane, namespace, endpoint and
  enum value from process start; the golden test asserts it. Label sets created by traffic (`token` on watched events,
  `route`) are the only lazy ones and are never used in `increase()`-on-first-event alerts.
- Amounts are float64 of the smallest unit (aggregates only; exact accounting is `usage_day`).
- **Buckets** (seconds): job stages 0.5, 1, 2, 5, 10, 20, 30, 60, 120, 300, 600, 1200, 1800, 3600; request/store
  0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5; propagation 0.05, 0.1, 0.25, 0.5, 1, 2, 3, 5, 7,
  10.
- Gauges come from the 10 s snapshot; chain probes run in parallel (today sequential, `admin.rs` ponytail) and
  `scaas_snapshot_age_seconds` exposes staleness. Counters/histograms are atomics read at render. Scrape 15 s.

Existing (BUILT, `admin.rs` `render()`, `submit.rs`; first-release forms `scaas_relay_jobs{chain,state}`,
`scaas_payment_requests_attention{chain}`, `scaas_indexer_lag_blocks{chain}`, `scaas_breaker_open{chain,breaker}`,
`scaas_drift_alerts{chain}`; mesh counters come from a `MeshStats` snapshot of atomics):

| Metric | Type | Labels | Note |
|---|---|---|---|
| `scaas_relay_jobs` | gauge | `chain`, `state` (incl. `dead`) | from the legacy client today; from the store with `namespace` once jobs run from the store |
| `scaas_payment_requests_attention`, `scaas_drift_alerts` | gauge | `chain` | legacy; leave the node |
| `scaas_indexer_lag_blocks` | gauge | `chain` | final head − indexed block |
| `scaas_relayer_balance` | gauge | `chain`, `lane` | smallest gas-coin unit; the account that pays, so on a chain with `fee_bump_lane` every lane reports the fee account |
| `scaas_breaker_open` | gauge | `chain`, `lane`, `breaker` | + `revert_streak`, reported on every lane of the chain |
| `scaas_fee_unread_total` | counter | `chain`, `lane` | landed transactions (mined or reverted) whose fee `tx_fee` could not read, so the gas budget missed that fee; each is also a warning in the log naming the job. BUILT (ua8-soroban B9a) |
| `scaas_submit_bump_skipped_consumed_total` | counter | none today; `chain`, `lane` added with the metrics core | consumption check |
| `scaas_config_toml_drift` | gauge | — | [NODE-STO-03](store.md#NODE-STO-03) |

Job API, feeds, store, admin, audit, OIDC (SPECIFIED):

| Metric | Type | Labels |
|---|---|---|
| `scaas_job_api_requests_total` | counter | `route`, `code`, `namespace` |
| `scaas_job_accept_total` | counter | `chain`, `namespace`, `result` |
| `scaas_job_transition_total` | counter | `chain`, `result` (`ok`, `moved`, `unknown`) |
| `scaas_feed_client_cursor`, `scaas_feed_last_poll_seconds` | gauge | `namespace`, `feed` (`scaas_feed_last_poll_seconds` = seconds since the last poll at render time) |
| `scaas_feed_head` | gauge | `feed` |
| `scaas_index_cursor` | gauge | `chain` |
| `scaas_store_owner_epoch`, `scaas_store_fencing_lost_total` | gauge / counter | — |
| `scaas_admin_mutations_total` | counter | `route`, `actor_kind`, `result` |
| `scaas_admin_cli_total` | counter | `action` |
| `scaas_admin_login_total` | counter | `result` (`ok`, `bad`, `locked`) |
| `scaas_audit_head_seq` | gauge | — (one series; the head hash is logged, not a label; replaces `scaas_audit_head_info{hash}`) |
| `scaas_oidc_rejections_total` (with the jwks counter: `scaas_oidc_*{issuer}`) | counter | `issuer` (index), `reason` |
| `scaas_oidc_jwks_refresh_total` | counter | `issuer`, `result` |
| `scaas_fee_recipient_changed_total` | counter | `chain` |
| `scaas_lane_foreign_nonce_total`; `scaas_lane_foreign_nonce` (0/1, latched until the lane leases) | counter; gauge | `chain`, `lane` |
| `scaas_finality_quorum` | gauge | `chain` (single-provider trust visible) |
| `scaas_grief_*` | counter/gauge | `namespace`, `chain` (aggregate only, [NODE-LANE-15](submit-lanes.md#NODE-LANE-15)) |
| `scaas_app_requests_total` | counter | `path_class` |
| `scaas_sponsor_jobs_total`, `scaas_sponsor_cost_spent`, `scaas_sponsor_budget_remaining_ratio`, `scaas_sponsor_reserved` | counter, gauges | `policy`, `chain`, `result` ([sponsorship.md#metrics](sponsorship.md#metrics); no payer label) |
| `scaas_deny_entries`; `scaas_deny_refused_total`; `scaas_deny_changes_total` | gauge; counters | `chain`; `chain`, `door`; `action` ([denylist](#denylist)) |

Node, chains, jobs, lanes, RPC, store (SPECIFIED):

| Metric | Type | Labels | Source / meaning |
|---|---|---|---|
| `scaas_build_info` (=1); `scaas_process_start_time_seconds`, `scaas_process_resident_memory_bytes`; `scaas_snapshot_age_seconds` | gauge | `version`, `commit` / — | binary, `/proc/self/statm`, snapshot |
| `scaas_node_ready` | gauge 0/1 | — | node-scope readiness: store open and owned, audit chain ok, ≥ 1 chain ready |
| `scaas_chain_ready` | gauge 0/1 | `chain` | that chain's `/readyz` reasons are empty |
| `scaas_chain_info` (=1), `scaas_chain_state` (0/1) | gauge | `chain`, `family`, `profile` / `chain`, `state` | config, store |
| `scaas_job_terminal_total`, `scaas_job_late_revert_total` | counter | `chain`, `outcome` / `chain` | [NODE-OPS-06](#NODE-OPS-06) |
| `scaas_job_stage_seconds` | histogram | `chain`, `stage` | [NODE-OPS-07](#NODE-OPS-07) |
| `scaas_simulation_total` | counter | `chain`, `result` (`ok`, `revert_consumed`, `revert_dead`, `transient`, `gas_cap`) | [NODE-LANE-23](submit-lanes.md#NODE-LANE-23) |
| `scaas_submit_broadcast_total`, `scaas_submit_fee_cap_reached_total` | counter | `chain`, `lane` | first broadcasts; replacement wanted at the cap |
| `scaas_submit_replacements_total` | counter | `chain`, `kind` (`bump`, `gapfill`, `resend`) | [submit-lanes.md#nonce-plan](submit-lanes.md#nonce-plan) |
| `scaas_submit_reverted_total` | counter | `chain`, `class` (`race`, `other`) | [NODE-OPS-06](#NODE-OPS-06) |
| `scaas_lane_inflight` | gauge | `chain`, `lane` | `signed` + `broadcast` rows + adopted nonces |
| `scaas_lane_head_stuck_seconds` | gauge | `chain`, `lane` | seconds since `nonce_at(latest)` last advanced while `latest ≤ journal_max`; 0 otherwise (covers adopted nonces) |
| `scaas_lane_foreign_nonce` | gauge 0/1, latched until the lane leases again | `chain`, `lane` | foreign-nonce state ([store.md#durability](store.md#durability); the counter stays) |
| `scaas_lane_cost_native_total` | counter | `chain`, `lane` | measured fee paid ([NODE-OPS-11](#NODE-OPS-11)) |
| `scaas_relayer_balance_floor` | gauge | `chain`, `lane` | `min_relayer_balance` |
| `scaas_rpc_requests_total` | counter | `chain`, `endpoint`, `result` (`ok`, `error`, `timeout`) | adapter |
| `scaas_rpc_head_lag_blocks` | gauge | `chain`, `endpoint` | max head − this endpoint's head |
| `scaas_rpc_quorum_disagreement_total` | counter | `chain` | ≥ 2 hashes at the candidate final head |
| `scaas_indexer_last_progress_timestamp_seconds`, `scaas_final_head_block_time_seconds` | gauge | `chain` | last committed range; chain timestamp of the final head |
| `scaas_indexer_finality_violated` | gauge 0/1 | `chain` | [NODE-OPS-12](#NODE-OPS-12) (a) |
| `scaas_audit_chain_ok` | gauge 0/1 | — | [NODE-OPS-12](#NODE-OPS-12) (b) |
| `scaas_http_request_seconds` | histogram | `listener`, `route`, `method`, `code_class` | all listeners |
| `scaas_store_info` (=1), `scaas_store_restore_epoch` | gauge | `backend`, `store_id`, `schema_version` / — | store identity |
| `scaas_store_tx_seconds` | histogram | `kind` (`journal`, `transition`, `accept`, `feed`, `audit`, `purge`) | store |
| `scaas_store_tx_retries_total` | counter | `reason` (`serialization`, `deadlock`, `busy`) | store backends |
| `scaas_store_commit_unknown_total`, `scaas_store_lock_ping_failures_total` | counter | — | store backends |
| `scaas_store_size_bytes` | gauge | — | file size (SQLite + WAL) / `pg_database_size` / `information_schema`, every 60 s |
| `scaas_store_rows` | gauge | `table` (`job`, `job_event`, `feed_item`, `audit_log`, `intent`) | `seq_counter` value − purge floor (no `COUNT(*)`) |
| `scaas_mesh_propagation_seconds` | histogram | `chain`, `carrier` (`gossip`, `bus_https`, `bus_quic`) | receive − `hub.published_at`, clamped at 0 |
| `scaas_watch_events_total` | counter | `chain`, `token`, `event` | [NODE-OPS-08](#NODE-OPS-08); lazy per token |
| `scaas_wrapper_leg_backing_ratio` | gauge | `chain`, `token`, `leg` | [NODE-OPS-08](#NODE-OPS-08); tier 2 = leg 0 |
| `scaas_gas_cost_native_total` | counter | `chain`, `namespace` | [NODE-OPS-11](#NODE-OPS-11) |
| `scaas_token_gas_cost_native_total`, `scaas_fee_earned_total` | counter | `chain`, `token` | `token = "call"` for non-token call targets; fees in token base units |

Watched events (`event`): asset suite `OrderRecorded`, `OrderRevoked`, `ForcedTransfer`, `AccountFrozen`,
`AccountUnfrozen`, `Paused`, `Unpaused`, `FeatureDisabled`, `RoleGranted`, `RoleRevoked`, `AttesterSet`; token wrappers
`WrapDisabled`, `GuardianRenounced`, `MinterRenounced`, `RateChangeProposed`, `RateChanged`, `RateChangeCancelled`,
`RateAdminRenounced`; factory `EnvPublished`, `ImplementationDeployed`, `TokenImplementationDeprecated`, `TokenKindEnabled` (`IOpenFactory.sol`, plan 5g-Z2). Only
registered tokens and configured factories. (`MetaNonceCancelled` is a subject's own action, handled by the
consumption check; not an ops event.)

External: `scaas_backup_last_success_timestamp_seconds{backend}`, `scaas_backup_interval_seconds{backend}`,
`scaas_dr_drill_*{drill}` ([NODE-RUN-04](runbooks.md#NODE-RUN-04)), `scaas_watch_code_hash_changed{chain,token}`
([NODE-OPS-08](#NODE-OPS-08) (b)) from textfiles; blackbox `probe_success`; node_exporter.

Mesh (bus) metrics:

| Metric | Type | Labels |
|---|---|---|
| `scaas_mesh_ingest_total` | counter | `chain`, `source` (gateway\|job\|peer\|gossip), `result` (accepted\|duplicate\|`<CODE>`) |
| `scaas_mesh_store_rows` | gauge | `state` |
| `scaas_mesh_peer_up` | gauge | `peer` (name) — last pull succeeded |
| `scaas_mesh_peer_last_pull_seconds` | gauge | `peer` |
| `scaas_mesh_peer_cursor_resets_total` | counter | `peer` (store_id changed) |
| `scaas_mesh_served_total` | counter | `peer`, `route` |
| `scaas_mesh_rate_limited_total` | counter | `peer`, `direction` (in\|out) |
| `scaas_mesh_outcome_total` | counter | `chain`, `outcome` (landed\|landed_elsewhere\|superseded\|consumed_unknown\|failed\|expired) |
| `scaas_mesh_exclusive_violations_total` | counter | `peer` |
| `scaas_mesh_private_from_open_total` | counter | `peer` |
| `scaas_submit_bump_skipped_consumed_total` | counter | `chain`, `lane` (also for job-API work) |
| `scaas_submit_inflight_dup_total` | counter | `chain` (a path found the digest already in flight, G2) |

These are the only mesh counters (no client-side copy). `/readyz` adds a reason when `[mesh]` is on and the store is
not open.

<a id="NODE-OPS-02"></a>**NODE-OPS-02** — **Gossip metrics** (prefix `scaas_`; per-peer details stay in the admin API,
no per-peer metric labels on the open mesh: unbounded cardinality):

| Metric | Type | Labels |
|---|---|---|
| `scaas_gossip_peers` | gauge | `carrier` (quic, tcp), `direction` |
| `scaas_gossip_mesh_peers` | gauge | `topic_kind` (intent, hint, dex, announce), `chain` |
| `scaas_gossip_messages_total` | counter | `topic_kind`, `chain`, `result` (accept, ignore, reject), `code` |
| `scaas_gossip_published_total` | counter | `topic_kind`, `chain` |
| `scaas_gossip_validation_seconds` | histogram | `topic_kind`, `stage` |
| `scaas_gossip_rpc_checks_total` | counter | `chain`, `result` (fresh, stale, skipped, error) |
| `scaas_gossip_score` | histogram | — (distribution, no per-peer label) |
| `scaas_gossip_graylisted`, `scaas_gossip_banned` | gauge | — |
| `scaas_gossip_hints_total` | counter | `chain`, `result` (consumed, not_yet, false, ignored) |
| `scaas_gossip_sync_total` | counter | `kind`, `direction`, `result` |
| `scaas_gossip_dex_replica_orders` | gauge | `chain`, `market` |
| `scaas_gossip_dex_head_mismatch_total` | counter | `chain`, `market` |
| `scaas_gossip_dex_unbound_total` | counter | `chain`, `result` (claimed, lost_claim, settled, lost_race, cancel_pending) |
| `scaas_gossip_validation_queue` | gauge | — |
| `scaas_gossip_assign_total` | counter | `chain`, `result` (assigned, landed, missed) |
| `scaas_gossip_shared_lane_total` | counter | — |
| `scaas_tls_handshake_failures_total` | counter | `listener`, `reason` |
| `scaas_bus_requests_total` | counter | `carrier` (https, quic), `op`, `code` |

<a id="NODE-OPS-07"></a>**NODE-OPS-07** — **Job timing = `scaas_job_stage_seconds{chain,stage}`**, `stage ∈ queue`
(accepted → first `leased`), `sign` (`leased` → `signed`), `include` (first broadcast → `mined`), `finalize` (`mined`
→ final range covering the mined block), `broadcast_final` (= W3B-04), `e2e`. The last three use a bounded in-memory
map keyed by **job uid** (`accepted_at, broadcast_at, mined_at, mined_block`), drained when the indexer writes a range
with `to_block ≥ mined_block` (works for `call` txs and bumped hashes); lost on restart (samples lost, never wrong). No
new `job` index for a metric; a restart drops ≤ one finality window of samples. `// ponytail: in-memory finalize map
(cap 50 000); persist only if restarts make W3B-04 blind.`

## 5. Ops watch

<a id="ops-watch"></a><a id="NODE-OPS-08"></a>**NODE-OPS-08** — **Ops watch for registered EVM/Hedera tokens**: (a)
**in the node**: leg backing (`underlying.balanceOf(token) ÷ reserve_i`, only for legs that exist) polled every 300 s
(~10 reads per token per 5 min; a wrapper drain is one block, so polling only shortens the reaction) at the final
head, and **watched events** from the final feed (label `token`); (b) **outside the node**: code-hash pins — token,
underlyings, `rateAdmin`, `guardian`, `issuer`, `compliance`, `registry`, EIP-1967 implementation and beacon slots — by
the `scaas/ops/watch-code-hash` script, which reads the token list (admin API with an OIDC machine token, or a static
file), keeps its pins in its own state file, latches `scaas_watch_code_hash_changed{chain,token}` in a textfile until
`--repin`. Non-EVM upgrade signals (Solana upgrade authority, Aptos package upgrades, Sui `UpgradeCap`) PLANNED.
Backing needs the node's registry and final head; code hashes need nothing from the node, so they stay out of it. Admin
view: `GET /v1/admin/chains/{key}/watch` (backing ratios per leg, last watched events).

<a id="regulated-legs"></a>**Regulated legs** (BUILT, ua-mtx-merge T35; [NODE-DEX-11](dex-venue.md#NODE-DEX-11),
[CTR-AS-16](../contracts/asset-suite.md#CTR-AS-16)). A chain whose DEX lists a regulated token (kinds 8–13) with `ALLOWLIST`
or `DENYLIST` on sets `compliance_registry` and `compliance_registry_codehash` (the deployments JSON's keys of the same names);
the venue checks the code hash when it loads and does not start on another code. **Operator step, not the deploy's (owner
2026-11-06):** after `createDex`, the registry admin (a contract or an `msig`) signs `attest([venue, venue.puller()], [8, 8],
[2^64−1, 2^64−1])` (`ELIGIBLE_CONTRACT`); the node signs nothing and holds no role. Until the rows exist the venue logs
`alert = "VENUE_NOT_ELIGIBLE"` per leg at load and refuses orders on the leg by that name. The indexer's regulated alerts
(`OrderRecorded`, `RelaxProposed`, `AccountFrozen`, `Paused`) are `warn` lines with `alert = <event>` and `alert: true` rows
of the feed ([indexer-feeds.md](indexer-feeds.md)); no metric yet.

## 6. Integrity

<a id="integrity"></a><a id="NODE-OPS-12"></a>**NODE-OPS-12** — **Integrity rechecks**: (a) at indexer start, before
the first range, and every 600 s (inside the 30-min P1 window, one header read per chain) the indexer re-reads the hash
at `chain_index.indexed_block` from ≥ `quorum` endpoints; a quorum answering a different hash ⇒ the chain's indexer
holds, `scaas_indexer_finality_violated{chain} = 1`, `/readyz` reason `finality violated at <block>`; the start-time
check re-derives the hold after any restart. (b) The audit hash chain is verified from the first row at start and every
24 h; a break ⇒ `scaas_audit_chain_ok = 0`, `/readyz` reason `audit chain broken`. No automatic state change or feed
rewind. (c) Recovery: CLI `scaas-node index reset --chain <key> --to <block> --confirm <block>` (node stopped, owner
lock, audited); clients reset their own event cursor for that chain to the same block, else the straddle rule drops the
re-delivered events. A violation is a human-judgement event; holding the indexer stops the damage without a schema
change; ≤ 10 min of extra ranges to reconcile.

## <a id="denylist"></a>7. Denylist

<a id="denylist"></a><a id="NODE-OPS-14"></a>**NODE-OPS-14** — **Subject denylist — the operator's choice.** An
admin-managed list: the node refuses to relay or serve jobs whose subject, payer or recipient is listed, **at intake and
again at lease**; each entry carries the order reference and the SHA-256 of the order document; every change is
audited. It has **no on-chain effect**: the listed party can still use the contract through other operators or by
self-submission; this node just won't serve. Mesh intents with a listed party are Ignored (local policy, never a peer
fault) and not forwarded. An order binds the operator it is addressed to; that operator needs a precise, evidenced,
reversible lever instead of suspending a namespace or pausing a token. Empty by default; one set lookup. Table
`deny_subject` in [store.md#schema](store.md#schema).

- **Parties** checked at intake on every door (job API, gateway, mesh, DEX, `/v1/ops`) **and at lease** (a job
  requeued from `signed` after a dropped tx is re-checked): meta-tx `m.from`, `m.to`; family op signer and payee; DEX
  maker (taker at match); `call` jobs: target and the addresses decoded for known selectors. Intake match ⇒
  `403 SUBJECT_DENIED` (no order detail); mesh ⇒ Ignore, not forwarded; lease match ⇒ `dead` (`SUBJECT_DENIED`), or
  `hold = 1` if published.
- **On add:** never-published `queued`/`leased` jobs ⇒ `dead`; published ones ⇒ `hold = 1`; `signed`/`broadcast`
  continue (the signed tx can land anyway). DEX: the maker's resting orders are dropped (cancel item on the feed); a
  settle job that goes `dead` takes its trade to `failed` through the existing failed-settle path. The events feed is
  not filtered (clients need chain facts for their books).
- **On lift:** nothing is revived; clients re-push with `generation + 1`.
- **Exits** (refunds, withdrawals) whose only listed party is the source: refused like any other match (the operator's
  choice; the beneficiary can self-submit).
- **Routes:** `GET /v1/admin/deny[?address=]` (operator); `POST /v1/admin/deny` `{chain_key, address, order_ref,
  document_sha256, valid_until?}` and `POST /v1/admin/deny/{id}/lift {lift_ref}` (admin); audited (the log mirror
  writes `***` for the address); hot ≤ 2 s (in-memory set). Lifted/expired rows kept 400 d.
- Metrics carry no address; refusal logs carry `deny_id` and the job/intent id.

## <a id="alerts"></a>8. Alerts

<a id="alerts"></a>Rule file `scaas/ops/prometheus/scaas-rules.yml` (recommended). Every alert carries `severity` and
`runbook` (anchor in [runbooks.md#incidents](runbooks.md#incidents)). `$STORE_MOUNT` is the filesystem holding the
store and `$FEE_BUMP_CHAINS` a regex of the chains that set `params.fee_bump_lane`, empty when none (both set per deployment).

```yaml
groups:
- name: scaas-recording
  rules:
  - record: scaas:w3b01_errors:ratio_rate5m  # same expression for 30m, 1h, 6h, 3d (rename the window)
    expr: |
      sum by (chain) (rate(scaas_job_terminal_total{outcome=~"reverted|expired_after_sign"}[5m]))
      / clamp_min(sum by (chain) (rate(scaas_job_terminal_total{outcome=~"mined|consumed|reverted|expired_after_sign"}[5m])), 1e-9)
  - {record: scaas:signed_terminal:increase1h, expr: 'sum by (chain) (increase(scaas_job_terminal_total{outcome=~"mined|consumed|reverted|expired_after_sign"}[1h]))'}  # also 6h
  - {record: scaas:slo_target_seconds, expr: 'vector(300)', labels: {chain: "evm:100", slo: w3b04}}  # one rule per chain and slo
  - {record: scaas:indexer_stall_seconds, expr: 'vector(300)', labels: {chain: "evm:100"}}  # per chain: max(300, 2 × final-head step), Celo 800
  - {record: scaas:finops_budget_native_30d, expr: 'vector(5e17)', labels: {namespace: acme-erp, chain: "evm:100"}}  # per approved (namespace, chain) budget
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
  - {alert: ScaasLaneHeadStuckHard, expr: 'scaas_lane_head_stuck_seconds > 900', labels: {severity: P1, runbook: rb-03-stuck-lane}}  # 15 min; bumps every 60 s before
  - {alert: ScaasChainNoLaneAvailable, expr: 'min by (chain) (max by (chain, lane) (scaas_breaker_open)) == 1', for: 5m, labels: {severity: P1, runbook: rb-02-breaker-open}}
  - alert: ScaasLaneRunwayCritical
    expr: |
      (scaas_relayer_balance{chain!~"$FEE_BUMP_CHAINS"} - on (chain, lane) scaas_relayer_balance_floor)
        / on (chain, lane) clamp_min(rate(scaas_lane_cost_native_total[1h]), 1e-30) < 3600
    for: 5m
    labels: {severity: P1, runbook: rb-14-runway}
  # $FEE_BUMP_CHAINS, chains with `fee_bump_lane`: every lane reports the one fee account, whose runway is over all its lanes' burn
  - alert: ScaasFeeAccountRunwayCritical
    expr: |
      (max by (chain) (scaas_relayer_balance{chain=~"$FEE_BUMP_CHAINS"}) - max by (chain) (scaas_relayer_balance_floor))
        / on (chain) clamp_min(sum by (chain) (rate(scaas_lane_cost_native_total[1h])), 1e-30) < 3600
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
  - {alert: ScaasFeeUnread, expr: 'increase(scaas_fee_unread_total[15m]) > 0', labels: {severity: P2, runbook: rb-02-breaker-open}}
  - alert: ScaasLaneRunwayLow
    expr: |
      (scaas_relayer_balance{chain!~"$FEE_BUMP_CHAINS"} - on (chain, lane) scaas_relayer_balance_floor)
        / on (chain, lane) clamp_min(rate(scaas_lane_cost_native_total[6h]), 1e-30) < 4 * 3600
    for: 15m
    labels: {severity: P2, runbook: rb-14-runway}
  - alert: ScaasFeeAccountRunwayLow
    expr: |
      (max by (chain) (scaas_relayer_balance{chain=~"$FEE_BUMP_CHAINS"}) - max by (chain) (scaas_relayer_balance_floor))
        / on (chain) clamp_min(sum by (chain) (rate(scaas_lane_cost_native_total[6h])), 1e-30) < 4 * 3600
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
  - {alert: ScaasSponsorBudgetLow, expr: 'scaas_sponsor_budget_remaining_ratio < 0.20', labels: {severity: P3, runbook: rb-14-runway}}  # 20 %
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
  - {alert: ScaasMemoryHigh, expr: 'scaas_process_resident_memory_bytes > 512 * 1024 ^ 2', for: 30m, labels: {severity: P3, runbook: rb-01-node-down-or-not-ready}}  # 2× the capacity budget
  - {alert: ScaasSnapshotStale, expr: 'scaas_snapshot_age_seconds > 60', for: 10m, labels: {severity: P3, runbook: rb-01-node-down-or-not-ready}}
  - {alert: ScaasConfigDrift, expr: 'scaas_config_toml_drift > 0', labels: {severity: P3, runbook: rb-01-node-down-or-not-ready}}
  - {alert: ScaasAppAvailability, expr: 'avg_over_time(probe_success{job="scaas-app"}[30d]) < 0.995', labels: {severity: P3, runbook: rb-01-node-down-or-not-ready}}
  - {alert: ScaasDrillOverdue, expr: 'time() - scaas_dr_drill_last_success_timestamp_seconds > 1.5 * scaas_dr_drill_cadence_seconds', labels: {severity: P3, runbook: rb-08-restore}}  # seeded 0 at install
```

Prometheus retention ≥ 35 d (the 30 d budget windows plus margin); long-term FinOps is `usage_day`.

Routing (`scaas/ops/alertmanager.example.yml`): token alerts (`ScaasForcedTransfer`, `ScaasWatchedEvent`,
`ScaasWrapperBackingShortfall`, `ScaasWatchedCodeHashChanged`) go to the **issuer** (and compliance for regulated
tokens) as well as the node operator; `ScaasNamespaceBudget90`, `ScaasSponsorBudget*` to the finance owner of the
namespace/sponsor account; `ScaasFeedClientStalled` to the ERP admin; everything else to the node operator, who owns the
Alertmanager. `Watchdog` goes to the external dead-man's switch (expected every ≤ 5 min). Group by `chain`; repeat P1
every 30 min until acknowledged.

Dashboards (`scaas/ops/grafana/*.json`, three):

| Dashboard | Panels |
|---|---|
| Overview | SLO table with remaining error budget; firing alerts; chains by state and readiness; build info, restarts, snapshot age; FinOps cost per namespace/token, fees, sponsor spend vs budget; backing ratios and watched events |
| Submit and chains | stage latencies per chain; terminal outcomes; simulation results; replacements; inflight, head-stuck, breakers, balances and runway per lane; final head age, indexer lag/progress; RPC errors, head lag, disagreements; job API and feed poll age per namespace; mesh/gossip peers, propagation |
| Store, DR and security | journal latency, retries, commit unknown, fencing epoch, size and rows, backup and drill age, restore epoch; logins, OIDC rejections, admin mutations, CLI actions, fee-recipient and denylist changes, audit chain |

The console app's metrics screen and its `metricsDashboardUrl` link to Overview. Tests: golden renderer tests (new
families, pre-emitted zeros); promtool `test rules` for every alert, including a foreign nonce and an audit break present
at process start; `revert_streak` boundary (2 vs 3 in 15 min, `race` excluded) and survival across restart; the
capacity load test runs alone.

## 9. Traces

<a id="traces"></a><a id="NODE-OPS-09"></a>**NODE-OPS-09** — **Traces: no OpenTelemetry SDK in the v1 binary.**
Gateway and job API accept a W3C `traceparent` (the `POST /v1/jobs` header applies to every item); the trace id (32
hex) is stored as `job.trace_id` (`job.trace_id TEXT NULL`, 32 hex; absent ⇒ generated) and carried by lifecycle log lines and jobs-feed items. Span
names are fixed now; OTLP export = cargo feature `otel`, default off (PLANNED). OpenTelemetry + OTLP + `tonic` would be
the node's heaviest dependency set; `job_event` already is a durable per-job trace. Until export exists, correlation is
via logs.

Span model (names normative; v1 emits them as log events with `span` and `trace_id`):

| Span | Starts / ends | Attributes |
|---|---|---|
| `scaas.job` | accept → terminal (or final) | `job_uid`, `namespace`, `chain_key`, `kind`, `origin.producer`, `entry_ref` (if any), `mode`, `batch`, `nonce` (subject), `bus_scope` |
| `scaas.job.accept` | request → committed | `result`, `error_code` |
| `scaas.job.simulate` | per attempt | `result`, `gas_estimate`, `error_code` |
| `scaas.job.sign` | lease → journal commit | `lane`, `outer_nonce`, `tx_hash` |
| `scaas.job.broadcast` | each send/replacement | `tx_hash`, `kind` (`first`, `bump`, `resend`), `max_fee`, `priority_fee` |
| `scaas.job.include` | first broadcast → receipt | `gas_used`, `effective_gas_price`, `cost_native`, `block_number`, `outcome` |
| `scaas.job.finalize` | receipt → final range | `finality_depth` (mode/depth/quorum), `to_block` |

Trace contract: every submission span carries `chain_key`, `lane` (address), `tx_hash`, `gas_used`,
`effective_gas_price`, `entry_ref`, `mode`, `batch`/`nonce`, `finality_depth`, `job_uid`, `namespace`. No payload,
subject address or amount ([logs](#logs)). An ERP `traceparent` joins its outbox → push trace to the node's spans.
Traces never cross nodes (envelopes carry no trace field; a peer's landing shows as `consumed`).

## <a id="logs"></a>10. Logs

<a id="logs"></a><a id="NODE-OPS-10"></a>**NODE-OPS-10** — **Logs = JSON lines in production** (`[log] format = "json"
| "text"`, default `text`; any deployment holding value runs `json`). Never logged: payloads, signatures, subject
addresses (`from`, `to`, payer, payee, maker, denylisted parties), amounts, salts, openings, secrets, tokens, HMAC
headers, passwords, RPC URLs. Allowed: lane and contract addresses, `tx_hash`, digests, job uid, `entry_ref` (random),
`namespace`, `trace_id`, `deny_id`; source IPs only in auth-failure and rate-limit lines. **Every `audit_log` row is
mirrored as a `warn`-level log event** (`event = "audit"`; secrets and deny addresses as `***`) so a lost store's last
audit entries survive off-host ([NODE-RUN-02](runbooks.md#NODE-RUN-02)) and survive a `warn`-only sink. **Retention
≤ 30 d (= `job_retention_secs`)** at every log sink; **backups and evidence copies ≤ 7 d**, so a node-held copy of
pseudonymous job data lives ≤ 37 d (the erasure procedure of [INT-ERP-24](../integration.md#INT-ERP-24) relies on it).
An auditor gets a 30-day log window; long-term evidence is the audit table and the chain.

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
Identical non-audit `warn` lines ≤ 1/10 s per (target, chain). Erasure requests need no node action because no
node-held copy outlives job retention + backup retention. Simulation failures and decoded reasons are logged with the
job (the incident log of an operator is its log sink). Log redaction is tested (no payload/address/amount/secret in an
e2e run, grep-based).

## <a id="finops"></a>11. FinOps

<a id="finops"></a><a id="NODE-OPS-11"></a>**NODE-OPS-11** — **FinOps measurement**: the cost columns (`gas_used`,
`gas_price`, `cost_native`) are filled for every job at `mined`/`reverted` and for gap-fillers; the same transaction
upserts a durable daily rollup **`usage_day`** ([store.md#schema](store.md#schema); 400 d = a fiscal year plus a
month). Conversion to the reporting currency happens only in the report, with an operator-supplied price file.
**Budget alarms are Prometheus rules; enforcement stays with the `gas_budget` breaker
([NODE-LANE-05](submit-lanes.md#NODE-LANE-05)), sponsor budgets ([NODE-SPN-02](sponsorship.md#NODE-SPN-02)) and
`max_live_jobs`.** Jobs are purged after 30 d, Prometheus retention is short, and `~gateway`/`~mesh` costs are booked by
no client, so the rollup is needed; cost: one small upsert per terminal job.

**Soroban spend limits are mandatory** ([NET-SOR-14](../networks/soroban.md#NET-SOR-14); controller call under the owner's
ruling of 2026-11-01, owner may override; **BUILT**, ua8-soroban B9a). A `soroban` chain with `modules.submit` on does not
start unless `[chains.breaker]` sets both `gas_budget_per_hour` and `min_relayer_balance` above 0 and `params` sets
`max_resource_fee_per_job` above 0 ([NET-SOR-29](../networks/soroban.md#NET-SOR-29), owner 2026-11-02; stroops; the error names
the chain). Why a refusal and not a default: a job is free to the client and its fee is the lane's, the amount is a money
decision for the operator's finance owner, and a default would be an XLM figure nobody chose on a family that also serves
Pi. An indexer-only node (`modules.submit` off) has no lane to limit and needs neither. `node.example.toml` sets 100 XLM an
hour, a 10 XLM floor and a 12 XLM cap per job on both Soroban chains as a starting point, not as a recommendation. A lane lands at
most 720 transactions an hour, each at most that cap: the failures measured cost 0.04 to 0.07 XLM, about 50 XLM an hour at that rate, under
the budget, so set it lower to stop failing jobs inside the hour. The floor compares the account that pays, under a fee bump the fee account alone (owner ruling 2026-11-01). `call`
jobs and a plain `signed_op` that is no token payment stop at `breaker.call_budget_pct` of the budget (default 50, owner decisions
2026-11-01 and 2026-11-02) and everything else runs to all of it, free `ua_metatx` jobs included, so those can stop a payment until the
window ends. `ua_metatx` on a mandate needs `params.mandate_wasm_hashes` (unset, none runs) and names a registered token. A landed failure counts against
the budget (`FAILED` Soroban transactions are billed): the breaker opens at the budget and no later job is claimed, while a
job in flight is still followed to its report. When `tx_fee` cannot read a landed transaction's fee, the budget misses it:
that is a warning in the log and `scaas_fee_unread_total{chain,lane}`, never a guessed fee, and `ScaasFeeUnread` alerts on an increase.

Measurement:

| What | Where | Unit |
|---|---|---|
| Cost per job | `job.cost_native` (+ `gas_used`, `gas_price`) at `mined`/`reverted`; gap-fillers charged to the expired job (`expired_after_sign`), or for adopted nonces to namespace `~lane` | smallest native unit ([sponsorship.md#budgets](sponsorship.md#budgets) per family) |
| Cost per namespace / token / lane; fees earned | counters above; `usage_day` | native; token base units |
| Sponsored cost | `sponsor_usage`, `scaas_sponsor_*` | native |
| Lane balance and floor | `scaas_relayer_balance`, `scaas_relayer_balance_floor` | native |

`usage_day` is upserted (read, add in code, write) inside the terminal-transition transaction; purged after 400 d. A
lost race (`consumed`) after broadcast is booked with its measured cost.

Monthly report: `scaas-node report usage --from 2026-10-01 --to 2026-11-01 --prices prices.csv --format csv`, or the
admin route `GET /v1/admin/usage` without conversion. `prices.csv`: `date,chain_key,asset,price,currency,source`
(`asset` = `native` or a token address); a missing price leaves the converted cells empty and lists the gap, never
interpolates.

| Field | Source |
|---|---|
| period, `store_id`, node version; per chain family, profile | report run, config |
| per (chain, namespace, token, sponsor policy): jobs by outcome, `gas_used`, `cost_native` | `usage_day` |
| native and token prices with source; `cost_reporting`, `fees_reporting` | price file |
| **relayer margin / W3B-06** = `fees_reporting − cost_reporting` per chain (may be negative, [mesh.md#rewards](mesh.md#rewards)) | computed |
| cost per mined job, per consumed job | computed |
| sponsor utilisation: Σ spent ÷ Σ daily budget, days at budget, rejects by reason | `sponsor_usage`, `scaas_sponsor_jobs_total` |
| **W3B-03** = max hourly spend ÷ `gas_budget_per_hour` per lane; breaker-open minutes | Prometheus, lane cost |
| refills and fixed costs (infrastructure, RPC plans, audits); break-even | operator inputs; computed |

Per-business-document allocation stays with the client from the jobs-feed cost fields: gas of every finalized job is
converted to the deployment's reporting currency at the transaction time and allocated to the business document
(`entryRef` → invoice/order); the node report is the operator's view, including doors no client books.

Budget alarms:

| Budget | Owner | Alarm | Enforcement |
|---|---|---|---|
| Lane gas per hour (`gas_budget_per_hour`) | node operator's finance owner | `ScaasBreakerOpen` (`gas_budget`) | breaker (BUILT) |
| Lane float / runway | node operator | `ScaasLaneRunwayLow` (< 4 h), `…Critical` (< 1 h); `ScaasFeeAccountRunwayLow`, `…Critical` on a chain with `fee_bump_lane` | `balance_floor` breaker |
| Sponsor daily budget | sponsor account owner | `ScaasSponsorBudgetLow` (< 20 %), `…Exhausted` | sponsor budgets |
| Namespace monthly cost | tenant's finance owner | `ScaasNamespaceBudget90` | none (report + `max_live_jobs`) |

Other FinOps facts: per namespace `max_live_jobs`; sponsorship budgets per policy row (day budget and hour / payer-hour
counts taken at accept and released if the job ends before broadcast; `min_valid_secs` default 120; a policy caps a
tenant's spend only with `on_exhausted = reject` — `unsponsored` on a client namespace books to the namespace, is marked
`sponsor_fallback` on the jobs feed and needs an audited `fallback_to_namespace`). **Float:** each lane holds gas float
for ~50 transactions; refill from treasury when below 30 % of target; the `balance_floor` breaker stops a lane at the
floor. Auto-refill is PLANNED; today an operator refills. **Indicative fixed costs** (an estimate, not re-estimated for
all families): infrastructure ≈ $480–830 per month in year 1; minimum configuration ≈ $620 per month; a third-party audit
of all contract families is the largest one-off cost ([runbooks.md#production-gates](runbooks.md#production-gates)).
**Break-even** of independent relayers: [mesh.md#rewards](mesh.md#rewards).

## <a id="capacity"></a>12. Capacity

<a id="capacity"></a><a id="NODE-OPS-13"></a>**NODE-OPS-13** — **Capacity rating and label caps**: ≤ 16 chains, ≤ 8
lanes per chain, ≤ 32 namespaces, ≤ 64 registered tokens per chain, ≤ 256 watched wrapper legs per node (`/metrics` ≤
~13 000 series / ~1.5 MiB at the caps, ~2 500 series typical; formula below); `Config::validate` and the admin routes
refuse more (`422 LIMIT`). An unbounded label is an outage of the monitoring, found at 3 a.m.; the caps are constants.

Reference hardware class **H1**: one host, 8 vCPU, 24 GiB RAM, NVMe SSD, shared with an ERP stack and its database. All
figures are estimates to be **measured** by a load test run alone.

| Resource | Budget / limit | Reason |
|---|---|---|
| Node RSS | ≤ 256 MiB without gossip; + 64 MiB with gossip at 50 peers ([NODE-GSP-14](gossip.md#NODE-GSP-14)) | leaves the ERP its memory; alert at 2× |
| Node CPU | < 1 core sustained at the rated load | k256 signing ≈ 0.1 ms, JCS + SHA-256, JSON; gossip < 5 % of a core |
| Store journal transactions (SQLite, `synchronous = FULL`) | ≤ ~300/s (fsync ≈ 1–3 ms, one connection) | each job ≈ 5–7 transactions over its life |
| **Rated throughput per node** | **10 jobs/s** for hours (alert at 70 %) | ⅕ of the store ceiling |
| **Rated daily volume** | ≈ 270 000 jobs/day at 30 d retention (store ≈ 20 GB at ≈ 2.5 KB per job across `job`, `job_event`, `feed_item`) | keeps the restore RTO and backup sizes; above it, lower `job_retention_secs` (≥ `valid_until` + 1 d) or accept a longer RTO |
| PG/MySQL store | ≈ SQLite figures **at ≤ 1 ms RTT**; ≈ 5 jobs/s at 5 ms (≈ 6 statements per transaction, serialized on the fencing row) | store backends |
| EVM lane | ≤ 16 txs in flight (typical per-account pending-slot limit) ⇒ Gnosis ≈ 3 tx/s per lane | the mempool is the limit |
| Generic lanes (one tx in flight) | ≈ 1 ÷ `include`: Sui ~2/s, Aptos ~1/s, Solana ~1/s, Hedera ~0.3/s, Cosmos/Soroban ~0.15/s, GRAM ~0.1/s per lane | lanes = target rate ÷ per-lane rate (≤ 8) |
| Job API / gateway | 20 POST rps (burst 40), 10 GET rps per key; batch ≤ 50; pages ≤ 500 / 1 MiB; ≤ 4 long-polls per key / `MAX_INFLIGHT` 64, body 64 KiB | [job-api.md#errors](job-api.md#errors) |
| Label caps | ≤ 16 chains, ≤ 8 lanes per chain, ≤ 32 namespaces, ≤ 64 tokens per chain, ≤ 256 watched wrapper legs | [NODE-OPS-13](#NODE-OPS-13) |
| `/metrics` | series ≈ C·(9N + 6 + 102 + 14L + 4E + 2T) + C·N + W + ~1 500 (HTTP, admin, mesh, store) ⇒ ≈ 13 000 at the caps (C 16, N 32, L 8, E 4, T 64, W 256), ≈ 2 500 typical (C 4, N 4, L 4, E 2, T 8) | `scaas_relay_jobs` (9N per chain) dominates; scrape 15 s |

Above the rated load: a second node on **different chains**, not a bigger store.

**Lane gas cap for post-quantum signers.** A lane's `max_gas_per_tx` defaults to 3,000,000 (`config.rs`), enough for classical
signers only. Each SCaaS input of a job verifies its signer's signature once, at the kind's verify cap
([CTR-DEX-26](../contracts/dex.md#CTR-DEX-26): `mldsa65` 5,950,000), so a lane that serves PQ signers needs a higher cap: an
`mldsa65`-signed liquidity order with two SCaaS inputs measured 12,143,505 regular gas, plus 979,200 EIP-8037 state gas
(`smartcontracts/evm/runs/2026-11-10-ua-mtx-liquidity/summary.txt`). Set the cap to at least the largest job the lane accepts
(regular + state gas under Amsterdam; regular stays ≤ 2^24, [submit-lanes.md#amsterdam-gas](submit-lanes.md#amsterdam-gas)).
Below it the node refuses the job before it sends anything: `LIQUIDITY_TOO_LARGE` for a liquidity plan
([NODE-DEX-19](dex-venue.md#NODE-DEX-19)), a gas refusal for any other job. `node.example.toml` carries the same note.

## 13. Post-quantum Zether chains

<a id="pqz"></a>Operator recommendations for a chain that runs post-quantum Zether tokens
([contracts/pq-zero-knowledge.md](../contracts/pq-zero-knowledge.md)):

- Chain profile flag `pqz = { genesis_hash = "0x…", registry = "0x…", tokens = ["0x…"] }`; a start-up probe
  `has_pqz_precompile` (genesis hash first; SPECIFIED, not built: the node has no such probe today) — on a chain that fails it
  the node refuses the jobs of its `PRECOMPILE` PQZ tokens only. An `OFFCHAIN` token
  ([CTR-PQZ-27](../contracts/pq-zero-knowledge.md#CTR-PQZ-27)) never calls the precompile and its jobs are never refused for a
  missing one (owner O1, 2026-11-06); BUILT: the node never reads the precompile for an `OFFCHAIN` job
  (`offchain_job_not_refused_without_precompile`). The node checks RPC genesis hash
  `==` profile `genesis_hash` `==` `registry.chainUid()` `==` each token's `chainUid` and refuses a mismatch (the node
  chain binding, [gateway.md#chain-binding](gateway.md#chain-binding)): the chain id 7622 (formerly 9000) alone does not identify our
  chain.
- Job kinds ([job-api.md#post-v1jobs](job-api.md#post-v1jobs)): envelope ops use the **existing** `metatx` (v1) and
  `ua_metatx` (v3) jobs, with the node-computed digest over the token's domain, idempotency and lanes unchanged; the
  token row has `kind = pqz`. Job kind `pqz_call` is for **direct open calls** only: `{chain, contract, selector ∈
  {mtxConfidentialTransfer, mtxUnshield, mtxRollOver}, calldata}` (direct `mtxShield` moves the caller's public units into the pool and `mtxWrapShield` pulls the caller's underlying, so neither is a node
  job; `mtxRollOver` is also an allowlisted envelope op (a relayed `metatx` job, outer fee may be 0, owner 2026-10-20); with the multi-recipient transfer, P6-ANON, `mtxConfidentialTransfer*` is op 7 with M ≥ 1 recipients and the single-recipient
  `mtxConfidentialTransferSingle*` (op 1) joins the set, each with its `Compact` variant; `NoBundle` is retired on PQZ and on Zether (review C0-3)). For all: the contract must be a configured PQZ token; pre-simulation by `eth_estimateGas` on a
  **follower**, never the signer (fails ⇒ job rejected, no gas spent; op 7 is pre-simulated the same way); `max_gas_per_tx = 64_000_000` on the SCaaS testnet (Amsterdam,
  2026-10-22: the cap is on regular + state gas; op 1 needs ≈ 41.7–43.4 M with ≈ 32.8 M of EIP-8037 state gas, Task 7b,
  +20 % ≈ 52 M; 16,000,000 before Amsterdam; the default 3,000,000 already rejects classical Zether transfers at 3.36 M;
  regular gas stays ≤ 2^24 and the block gas limit is read from the chain, [submit-lanes.md#amsterdam-gas](submit-lanes.md#amsterdam-gas)); never batched (`PqzToken` has no
  `mtxBatch`). Gateway body limit 1 MiB on job submissions to the `pqz` chain profile only (a v3 transfer job is ≈ 170
  KB as hex; the gateway's global limit stays 64 KiB). **Checked for op 7 (P6-ANON S9, 2026-10-16) — all unchanged**, against the largest
  call of each id within 16 M gas [estimate: measured proof sizes, precompile gas scaled from the live op 1 rows,
  `pqz-core/pqzl/params/anon/s9_limits.py`]: PQZL M = 8 + 16 inline credits 383,108 B of calldata, ≈ 14.6 M gas; PQZH M = 4
  + 10 inline 440,356 B, ≈ 15.9 M (floor-bound; 11 inline need 16.4 M, over this cap, under EIP-7825's 16,777,216). As
  hex the largest job is ≈ 0.88 MB (≈ 0.92 MB at 11 inline), under 1 MiB (1.19×). No inline credit: PQZL M = 8 ≈ 10.4
  M, PQZH M = 4 ≈ 10.7 M; ≥ 5 such calls per 80 M block. *Under Amsterdam (SCaaS testnet since 2026-10-21) these
  figures are history: a transaction carries at most 261,909 calldata bytes (EIP-7976 floor 15,000 + 64 per byte ≤
  2^24, regular gas), so the 383 KB / 440 KB calls above cannot be sent at all and the node refuses them before
  simulating; every op that stores an SSTORE2 blob adds ≈ 25.6–31.8 M of state gas
  ([gas impact](../../pqz-core/nethermind/runs/2026-10-21-glamsterdam-gas-impact.md)).*
- Optional rollover keeper: per configured PQZ token, when an account has ≥ 16 unrolled credits **older than
  `KEEPER_AGE = 24` blocks** (2 min) and the chain is idle, submit `mtxRollOver` of those old credits only, with
  ciphertexts from logs (anyone may; it is harmless). A proof in flight chose `p ≥` every credit older than its own
  state read, so the keeper never pushes `rolled` more than 16 past it. Clients prove at `p = pendingCount` and, on
  `InlineTooFar`, refresh state and re-prove once. *Since plan 5h (docs sync 2026-10-20) the contract enforces `ROLL_AGE = 5`
  blocks per rolled entry and `mtxRollOver(ua, n)` (`n ≤ ROLL_MAX`, the set's: 96 / 80 / 64 / 32 at `n2048-kmax1024` / `n2304-kmax4096` / `n2560-kmax16384` / `n2816-kmax65536`, plan 5h Task 8d part 2b) reads the entries from state, with no ciphertexts from logs
  and no 16-credit batch; the keeper policy and its numbers above are to be updated in the node task that follows part A
  ([CTR-PQZ-08](../contracts/pq-zero-knowledge.md#CTR-PQZ-08)).*
- **P6i, multi-recipient transfer (op 7, P6-ANON; SPECIFIED):**
  - Indexer: normalizes `ConfidentialTransferMulti(entryRef, fromUA, beneficiary, fee, sendCounter, recipients, mode, blob)` (M = `recipients.length`) and its M per-leg
    `Credited(ua, index, entryRef)` (`ConfidentialTransfer` + one `Credited` for op 1, as today). Leg j's credit ciphertext is
    `u_{⌊j/4⌋} ‖ v_j` sliced from `out` (`out = u_0 … u_{G−1} ‖ v_0 … v_{M−1} ‖ v_f ‖ [v_{a,0} … v_{a,M−1}]`,
    `G = ⌈M/4⌉`); legs are matched by log order (P6g emits the `Credited`s in leg order), and the indexer checks
    `keccak256` of the matched UAs (32-byte words in leg order) `== recipientsHash` and each
    `keccak256(u_{g(j)} ‖ v_j)` against the pending slot it rebuilds; a mismatch is an integrity alert
    ([NODE-OPS-12](#NODE-OPS-12)), never a silent skip. Decoy legs (`Enc(0)`) are indistinguishable and indexed like
    real ones.
  - Keeper: the age-gated rule above, unchanged, over **every** credit including decoy ones (it cannot tell them
    apart): same `KEEPER_AGE = 24`, ≥ 16 old credits, idle chain, funded from the same lane budget as other roll-overs.
    Load: a transfer with M legs adds M credits, so up to M later roll-over shares (≈ 0.55 M gas per credit, ≈ 8.9 M
    per 16): PQZL M = 8 ≈ 4.4 M of keeper gas per transfer, PQZH M = 4 ≈ 2.2 M [estimate]; series
    `scaas_gas_cost_native_total{namespace}` ([NODE-OPS-11](#NODE-OPS-11)) carries it.
  - `pqz_call` pre-simulates op 7 on the follower like op 1 (above); the limits above already cover the largest op 7
    call of each id.
- **The PQZ node** (P6f, [chain integration](../contracts/pq-zero-knowledge.md#chain-integration)): image
  `scaas/nethermind-pqz:1.39.0-pqz1`; `config.json` `TxPool.MaxTxSize` 1,048,576 at P6f, 2,097,152 (2 MiB) on both SCaaS testnet nodes since 2026-10-31 ([NET-EVM-10](../networks/evm.md#NET-EVM-10)) (a PQZH transfer is 345,221 B with
  framing; the largest op 7 transaction within 16 M gas ≈ 440 KB, 2.38× under it, S9; the follower proxy's
  `client_max_body_size` 2 MiB takes its hex raw transaction, ≈ 0.88 MB) and `Blocks.TargetBlockGasLimit` 80,000,000 (Clique moves the limit ≈ 0.1 % per block: 16.78 M → 80 M in
  ≈ 1,600 blocks ≈ 2.2 h; 200,000,000 since the Amsterdam reset of 2026-10-21, and the genesis `gasLimit` 200 M
  (`0xbebc200`, `chain/patch-chainspec.py --testnet-reset`) since the reset of 2026-10-22, so no ramp; a relayer never assumes
  this limit: it reads the block gas limit from the chain); the chainspec carries `engine.Pqz`. Health after any start: the log line `PQZ-START`
  (library SHA-256 = the image label `scaas.pqz.ffi.sha256`, self-test hash `d6c01fbc…6f68d` (images `2.2.0-pqz5` / `2.2.0-pqz6` / `2.2.0-pqz7`, set `n2304-kmax4096`; `23d7a1db…c97c0` on `2.2.0-pqz4`, `ed910a2c…d205` before), the schedules, the
  addresses), no `PQZ-REFUSE`. A node fault (D4: arena, worker) logs `PQZ-NODE-FAULT` and **exits with code 120**: the
  block in progress is never sealed, nothing is marked invalid, and a restart re-processes it; `PQZ-INPUT-PANIC` is an
  input-caused panic answered `…00` (should never appear). `pqz-core/nethermind/chain/watch.sh <container> <rpc>
  [since]` prints the head (height, age, `gasLimit`), the container state and last exit code and counts those tags; run
  it from cron or by hand. Since 2026-10-31 every SCaaS testnet service runs `restart: unless-stopped` (owner ruling, NET-EVM-10): Docker
  restarts the node after exit 120; a fault caused by a pooled transaction can loop (the RPC node gossips it again), so
  `watch.sh` prints `restarts=` and warns when it is not 0, and the operator stops the sealer and drops the transaction. Clients price transactions at least `baseFee + 1` ([evm.md](../networks/evm.md#private-chain)).
- The node never holds a PQZ secret or an ML-DSA key of a user (as for classical Zether: "the node never needs the
  confidential key"); it holds no envelope key either — envelopes arrive signed — nor a PQZ verifier key: it carries or fetches
  verdicts and never signs one ([NODE-JOB-22](job-api.md#NODE-JOB-22)).
- Indexer: `MetaTransactionExecuted`, `UAMetaTransactionExecuted`, `Transfer` and `UATransfer` of a PQZ token are
  normalized like any meta token's, beside the `Pqz*` events.
- Not on the mesh, exactly as classical Zether: the bus never exports a `metatx` or `ua_metatx` intent naming a PQZ
  token, and the SCaaS testnet is private anyway.

- <a id="pqz-verifier"></a>**The PQZ verifier (off-chain) is a separately operated trust role, never this node** (group 3f;
  node side **BUILT**, T47 `75ddccc4`…`062133b6`; the reference service `scaas-pqz-verifier` **BUILT**, T48 `06e11d23`,
  `5d4a2780`; [CTR-PQZ-27…30](../contracts/pq-zero-knowledge.md#pqz-verifier-mode)). A token in `OFFCHAIN` mode names a verifier UA
  whose signature makes its proofs valid; whoever holds that key can approve a false proof up to the token's maximum loss. It is
  its own process, operator, key custody and resource limits (`scaas-pqz-verifier` is its own crate and binary, never linked into
  `scaas-node`; anyone may run another that keeps this contract). It **decrypts nothing**: it verifies public statements and proofs
  and reads chain state, holds no PQZ secret and no ciphertext of anyone ([ARCH-POS-13](../decisions.md#ARCH-POS-13)); its keystore
  is named in its own config, never a lane key; a k-of-n `msig` of derived keys held by separate parties is recommended (who
  collects the member signatures of one verdict is not specified yet). **UNAUDITED.**

```toml
[pqz_verifier]
endpoints = ["https://pqz-verifier.example.org"]   # asked in order; URLs only, no secret
refuse_shield_when_unserved = false                # opt-in
# timeout_ms = 5000            # one endpoint's whole request; one that does not answer rests 10 s (submit-lanes.md)
# max_response_bytes = 262144  # read in chunks, a longer answer is no answer
# valid_margin_secs = 30       # a verdict expiring sooner is re-fetched
```

  - **Request** `POST <endpoint>/v1/pqz-verdict`, JSON, named fields only: `{token, chainId (a number), op: {entry, args, binding,
    amount?, recipient?, unwrap?}, statement, proof, pqzVerifierEpoch}`; `op.args` the entry's argument struct (uints up to 64 bits
    as numbers, wider ones decimal strings, bytes hex), `amount` / `recipient` for `mtxUnshield`, `unwrap` for
    `mtxUnshieldUnwrap`, `binding` the envelope binding the token gave; `statement` and `proof` hex as the node rebuilt them.
    `op.args` repeats the ciphertext parts the statement carries, so the body is up to about twice the statement plus the proof.
  - **Answer**: a 2xx JSON `{pqzVerdict: {…}, pqzVerdictSig: {keyData, signature, members}}`; the node reads only
    `pqzVerdict.pqzVerifierEpoch`, `pqzVerdict.validUntil` and the signature, and rebuilds the rest. A non-2xx (a named refusal), a
    body above `max_response_bytes`, a timeout, a decode failure or a `UASig` past the bound is no answer.
  - **The verifier's own duties** (T48): release address → set; the statement's length one of the set's `STMT_*`, its word 32 the
    set's PQZL id; `pqz-ffi`'s `pqz_precompile`; the statement rebuilt from the token's state and compared; every key named passes
    [CTR-PQZ-30](../contracts/pq-zero-knowledge.md#CTR-PQZ-30)'s checks; signs only a valid proof, `validUntil` short (minutes),
    the token's current epoch, every signature logged with `token`, `statementHash`, `proofHash`; a refusal is a named JSON error,
    never a signature; a bounded queue, concurrency and per-client rate limits. Group 3t
    ([CTR-PQZ-36](../contracts/pq-zero-knowledge.md#CTR-PQZ-36); BUILT, `tests/service.rs` `refuses_stale_fee_word`): after the
    view call and before the byte compare, the request's statement word 256 must equal the view's (one source), else
    `FEE_WORD_MISMATCH` with its three terms (`confidentialFee()`, `pqzVerifyConfig().verifierFee`, `M·d`); the fee is the token's,
    not the service's policy. A fee change between the config read and the view call gives `STATEMENT_MISMATCH` or
    `FEE_WORD_MISMATCH`, never a wrong signature (the verdict binds the statement's hash).
  - **The reference service's configuration and refusals** (`scaas-pqz-verifier`, Fable C-1…C-6 on branch
    `ua-mtx-fix-verifier`; [pqz-verifier.example.toml](../../scaas-pqz-verifier/pqz-verifier.example.toml), names and paths
    only, no secret): `rpc_urls` (one or more, asked in order; one request's reads from one node at one block, the next node
    only when one does not answer within 10 s or answers an error that is not a revert,
    [ARCH-POS-15](../decisions.md#ARCH-POS-15) by failover; **every endpoint must be a node the verifier's operator trusts,
    until the strict-majority option exists (`scaas-rpc`)**, owner ruling 2026-11-11 ([decisions.md](../decisions.md)
    CTR-PQZ-29 Change): the option is deferred to the shared `scaas-rpc` crate (TODO 8b), the block is pinned by number not
    hash (R-6, deferred with it), and a lying RPC could pass a key check (§6, CTR-PQZ-30: the key record, its stored `pqzPop` bytes, `keyOwner`) that `OFFCHAIN` tokens trust the verifier for), `chain_id` (required; every endpoint must answer it at start or
    the service does not start), `chain_uid`, `registry` and `registry_generation` (1 or 2; at start the registry's
    `chainUid()` and `generation()` on every endpoint must equal them): the one chain and registry it serves, and the only inputs of the `UAAuth` digest it signs (never a hash read from the
    chain). New refusals: `FOREIGN_REGISTRY` and `FOREIGN_CHAIN_UID` (the token's code names another registry or `chainUid`),
    `BODY_TIMEOUT` (408: the body not read within 15 s; read before a queue place is taken), `KEY_RECORD_FULL` (503: the
    in-memory key ownership record holds 2^18 keys; a restart empties it).
  - **Paid on the token** (group 3t): an `OFFCHAIN` token with `verifierFee ≠ 0` pays the verifier UA `verifierFee ·
    shieldScale` per debit from `SHIELD_POOL`: a native verifier's ERC-20 balance, a derived one's UA-ledger balance (its first
    payout creates the slot); the verifier spends it with its own key, as any holder. An operator's price floor is not specified. Open (owner): the request body limit (built
    1,244,672 B against the spec formula's 722,688 B), how JSON depth is counted, whether the key-ownership record persists across
    restarts.
  - **Served**, for the shield switch: some endpoint answers 2xx to the probe `POST <endpoint>/v1/pqz-verdict/probe {token,
    chainId}` (a fixed probe statement; the reference service answers it only for an `OFFCHAIN` token naming it); one probe per
    shield job. The check before a verifier transfer is proposed asks the proposed `next` with `proposal: true`, answered while
    the token still names another verifier or none. With
    `refuse_shield_when_unserved = true`, shield and wrap-shield jobs (`UAShield`, `WrapShield` on a PQZ token) into an `OFFCHAIN`
    token whose verifier is revoked (`pqzVerifyConfig().verifier == 0`) or that no endpoint serves (none configured counts as
    unserved) are refused `PQZ_VERIFIER_UNREACHABLE`, for every consumer; a probe that does not get through while none serves
    is `PQZ_VERIFIER_PROBE_UNREAD`, back in the queue.
- **`OFFCHAIN` token health** (BUILT, T47; the token view SPECIFIED): per `OFFCHAIN` token the indexer keeps
  `pqz_last_verdict_at`, the epoch, the revoked state and (group 3t) `pqz_verifier_fee` ([indexer-feeds.md](indexer-feeds.md#pqz-verifier-rows)). Alerts:
  `PqzVerifierProposed` (with `eta`), `PqzVerifierRevoked` and `VerifierFeeProposed` (with `eta`) are feed rows with `alert: true`;
  no metric yet. **Operator note** (group 3t): a `ConfidentialTransfer*.fee` is the whole fee word, `txFee + verifierFee + M·d`.

## <a id="operator-notes"></a>14. Operator notes, branch `ua-mtx-merge`

Status: each row names its own status. One note per job-shape or config change of the round (AGENTS.md: a consumer on an old shape
must be told, never left to go `dead` silently); an old shape is refused by name. Nothing is live with value: every chain is test
only. **UNAUDITED.**

| Change | Who acts | What to do |
|---|---|---|
| The `ua*` / `mtx*` merge (BUILT, [CTR-MTX-30](../contracts/metatx.md#CTR-MTX-30)): one signed entry per operation, `mtx<Op>` on ids with `UASig`; the address token forms and the `ua<Op>` names are gone. A token transfer or payment is a `ua_metatx` job (`{op}` with `auth`, or `{token, struct: "transfer", m, auth}`); a `metatx` job's `MetaTransfer` is refused `OP_KIND_MISMATCH` by name ([job-api.md](job-api.md#named-entries)) | EVM job producers, clients | build the merged entries; ids as `bytes32` (a native address zero-padded); an old shape is refused by name, never silently `dead` |
| The gateway's token doors: `/v1/op` takes the merged entries with `auth`, `/v1/ua-metatx` a `UAMetaTransfer`, `/v1/metatx` refuses a token or a mandate wallet by name (BUILT, [gateway.md](gateway.md#routes)) | wallets, partners on door A | move to `/v1/op` or `/v1/ua-metatx` |
| The DEX: a SCaaS token's order is a `UATradeOrder` (shape 1) signed in `auth`, an outside token's a `TradeOrder` (shape 0); the cancels are `CancelUAOrder` / `CancelUAWrapOrder` on a token (BUILT, [CTR-DEX-26](../contracts/dex.md#CTR-DEX-26)); the other form is `LEG_SHAPE` | DEX clients, the public DEX API | sign the shape of the sell token's kind |
| The mesh's EVM token body is `evm.ua_meta_tx` + `auth` under `scaas-intent/1.3`, for a native `from` (BUILT, [NODE-MESH-18](mesh.md#NODE-MESH-18)); a derived `from` is `DERIVED_FROM_UNSUPPORTED` | mesh peers | upgrade the node; a 1.2-only peer ignores the 1.3 envelopes |
| A derived signer of a cancel (`mtxCancelNonce`) signs the named purpose of every named operation (MD-5) | wallets, `clientkeys` / `ua-rs` | re-sign old cancel signatures |
| The mandate wallets take the merged form: owner and delegate ids, the named entries as `ua_metatx` jobs, the flat builders and `mtxExecuteAsOwner(Raw)` gone (MD-11; new CREATE2 addresses, [mandates.md](../contracts/mandates.md#mandatewallet)) | wallet owners, deployers | redeploy; move the jobs to the named entries |
| Every PQZ proof-carrying entry ends with `PqzSignedVerdict pqzVerdict` (BUILT, T45): new selectors on kinds 4, 5, 12, 13, direct and signed | clients building PQZ calldata, node operators | update `clientkeys` / `ua-rs` and the node together; the token refuses the old selectors |
| PQZ jobs gain `args.pqz_verdict: {pqzVerifierEpoch, validUntil, auth}` (BUILT, [NODE-JOB-22](job-api.md#NODE-JOB-22)) | PQZ job producers | `OFFCHAIN` token: send it, or let the node fetch it; `PRECOMPILE` token: leave it out (`PQZ_VERDICT_NOT_EXPECTED`) |
| `ConfidentialConfig` gained `pqzVerifyMode`, `pqzVerifierUA`, `pqzVerifierFixed` (group 3f) and `proofStore` (group 3h); the `TokenConfig` encoding moved for every kind (BUILT) | token creators, the wizard | every kind sends the fields; non-PQZ kinds leave them 0 / false (`ConfigFieldForOtherKind(4)`); a PQZ creation states the mode and, for `OFFCHAIN`, the verifier and fixed or transferable, after showing the maximum loss |
| `[pqz_verifier] endpoints`, `refuse_shield_when_unserved` (BUILT, [above](#pqz-verifier)) | node operators | configure endpoints for the `OFFCHAIN` tokens served; the node signs nothing and holds no verifier key |
| The PQZ verifier (off-chain) is a separate trust role (BUILT, T48) | whoever a token names as verifier | run `scaas-pqz-verifier` (or another implementation of its contract) apart from the node, its key in its own keystore |
| Alerts `PqzVerifierProposed`, `PqzVerifierRevoked`; per-token `pqz_last_verdict_at` (BUILT) | operators, wallets | watch a proposal before its `eta`; a revocation freezes the token's confidential balances until a new verifier is set |
| The verdict-less `verifyTransferAmount` reverts `PqzVerdictRequired()` on an `OFFCHAIN` token (BUILT, T45) | ERP reconciliation | use the verdict form, or `pqz-ffi` on `disclosureStatement` |
| `GovernanceRouter` gained `mtxPqzSetVerifier`, `mtxPqzCancelVerifier`, `mtxPqzRevokeVerifier` (3f) and `mtxSetProofStore` (3h) (BUILT); its CREATE2 address moved | deployers, node call tables | redeploy the router; the new address in the deployments JSON |
| PQZ gas pins moved: every `PRECOMPILE` debit carries the empty verdict (480 B, at most +30,720 gas at the EIP-7976 floor); at `n2048-kmax1024` a PQZH op 7 commit-reveal M = 4 without the auditor paid by an `mldsa65` UA no longer fits (M ≤ 3) | relayers quoting PQZ jobs | re-read the figures; the node reads gas from the chain |
| PQZ debit jobs name `ownTag` (`bytes32` hex) in `args` (BUILT, T63 `39fa296c`); the old shape is `BAD_PAYLOAD: args.args.ownTag: missing` | PQZ job producers | send `ownTag` ([job-api.md](job-api.md#pqz-owntag)); probe a token's release with `proofStore()` (answers from 3h) |
| A LOG token can hold a large debit under `PROOF_STORE_OVER_LANE_CAP` (BUILT, [NODE-JOB-24](submit-lanes.md#NODE-JOB-24)) until the issuer sets NONE or the job's `validUntil` passes | PQZ job producers, issuers | read the status; it is queued, never `dead` early |
| PQZ debits, rollovers and prepares name `keyVersion`; the registry's `setPqzKey` / `storePqzPop` take a version (BUILT, T55, [NODE-JOB-23](job-api.md#NODE-JOB-23)) | PQZ job producers, wallets | rotate a key on an operator change or a share holder leaving; in-flight credits to a rotating UA are refused by name (`PQZ_KEY_ROTATION_PENDING`, `PQZ_KEY_ROTATED`) and re-proved; a 60 M chain at `n2816-kmax65536` cannot rotate (spec KV-2) |
| A new contract kind `service` (BUILT, T79, [NODE-JOB-25](job-api.md#NODE-JOB-25)): `[[chains.services]] address, entries = [{entry, op_type}]` after every key of its `[[chains]]` table (`node.example.toml`); the lane stops on `SERVICE_ENTRIES_MISMATCH`; new `params.max_service_op_bytes` (default 2,048) | node operators, service payers | jobs `{kind: "ua_metatx", op: {entry, contract: "service", token: <service>, args: {op, pullToken, t, auth}}}`; in `t`, `mode` may be a JSON number, every other `uint` a decimal string; new refusals `SERVICE_ENTRIES_MISMATCH`, `SERVICE_PULL_SHAPE` (code 1–4 or `fee nonce`), `SERVICE_TOKEN_MISMATCH`; the gateway takes no service job |
| `meta.payNo` is a `0x` + 64-hex `bytes32` (absent = 0, none), no longer text (BUILT, plan T83 `ba280ade`): a text `payNo` is `BAD_PAYLOAD: meta.payNo: not 0x-hex`, a short one `not bytes32`; `PAY_NO_TOO_LONG` is gone. New `meta.save` (JSON bool, absent = false; with `payNo` 0 `PAY_META_SHAPE`; inside the commitment, so a differing `save` is `PAY_META_MISMATCH`); `max_pay_meta_bytes` (default 2,048) counts `body` only | pay job producers, ERPs | send `payNo` as `bytes32` (recommended a right-aligned UUIDv7, `clientkeys` `payNoFromUuid`); read the records with `paymentCount(payNo)` / `paymentsOf(payNo, offset, limit)` by `eth_call` (no node API) |
| `PaymentMeta(bytes32 indexed payId, bytes32 indexed payNo, bool save, uint16 schema, bytes body)` (topic 0 changed); the indexer's `PaymentSettled` row carries `pay_no` as 0x-hex 32 bytes (was text; all zero = none) and a new `meta_save` (BUILT) | feed consumers | change a text `pay_no` column or decode the hex |
| Pay selectors changed with the `PayMeta` tuple: `mtxPay`, `mtxPayReceiverFee`, `payWithFee`, `payWithFeeToUA`, `mtxPayWithTax`, `payWithTax`, `MandateWallet.payUnderMandate`, `mtxPayUnderMandate` (BUILT) | anyone hand-building calldata | build from named fields; the old tuple reaches no function |
| A taxed pay is the named entry `mtxPayWithTax` on kinds 8–13 (BUILT, T40, T42, [CTR-AS-18](../contracts/asset-suite.md#CTR-AS-18)); a PERCENT payment in flight across a rate change reverts `TaxMismatch(expected, got)`, refused at the simulation by name (a node pre-check from `taxConfig()` is SPECIFIED) | ERPs, issuers | ERPs use AMOUNT; issuers announce a rate change and drain PERCENT queues across its `eta`; the client re-signs a refused job |
| `UARelayFee` gained `batch` and `nonce` (new typehash, BUILT T38 `e273978e`, [CTR-MTX-27](../contracts/metatx.md#CTR-MTX-27)): a relay-fee job names `args.batch`, `args.nonce` on the payer's own lane; an old-typehash signature is refused; the router's CREATE2 address moved | relay-fee job producers, deployers | sign the new struct (a lane may be dedicated to relay fees); redeploy the router, the new address in the deployments JSON |
| Pay lanes are free (BUILT T37 `3740b85e`, [CTR-MTX-31](../contracts/metatx.md#CTR-MTX-31)): the node no longer checks `batch == payLane(entryRef)`, nonce 0 on a pay; one `entryRef` may be paid several times | ERPs, reconcilers | add the amounts of one key; keep `payLane` only as an own convention |
| An `msig` registered with a KEM key is refused `UAKemHolder` (BUILT, T66a, [CTR-UA-32](../contracts/accounts.md#CTR-UA-32)) | clients on the old builders | register the `msig` without a KEM key; senders seal to each accepted member's own key |
| A factory creator is a 32-byte UA id (canonical; a native id still in its 20-byte form) in a feed, job field or export (PLANNED: the node decodes no `TokenCreated` / `DexCreated` today, so no node shape moves) | feed consumers | read creators as `bytes32` ids ([CTR-TOK-27](../contracts/token-wrappers.md#CTR-TOK-27)) |
| The regulated kinds 8–13 and `ComplianceRegistry` (BUILT, T24–T36, [asset-suite §2](../contracts/asset-suite.md#2-regulated-controls)); `TokenConfig` gained field 6 `reg` for every kind (a plain kind sends it zero, else `ConfigFieldForOtherKind(6)`); the plain kinds refuse bits 5–10, 21, 22 with `FeatureInvalidForKind` | token creators, the wizard, deployers | encode `reg` on every kind; deploy the regulated releases and the registry with the release set (deployments JSON `compliance_registry`, `compliance_registry_codehash`) |
| The `GovernanceRouter` gained the eight control ops `mtxFreeze`, `mtxUnfreeze`, `mtxForceTransfer`, `mtxPause`, `mtxUnpause`, `mtxRecordOrder`, `mtxRevokeOrder`, `mtxOperatorTransfer` (BUILT, T32); the token has no `mtx` twin | issuers, compliance holders, node call tables | relay a holder's control as a router job (`gov_router`), fee 0; a contract holder signs by ERC-1271, an `msig` holder through the registry |
| Regulated refusals by name at the node and the venue (`Frozen`, `TokenPaused`, `NotEligible`, `FeeRecipientFrozen`, `RegistryUnavailable`, `RegistryGasStarved`), regulated legs and alerts (BUILT, T35, [regulated legs](#regulated-legs)) | node operators, venues, wallets | set the registry keys for a venue; watch the alerts; use the runbook below |

**Regulated kinds: emergency runbook** (regulated-kinds spec §3.6, F-06, M-06; [CTR-GOV-09](../decisions.md#ctr-gov-09--delayed-relaxing-and-record-later-with-the-asset-suite),
[CTR-AS-21](../contracts/asset-suite.md#CTR-AS-21)): who stops what at once, who only after `grantDelay` (≤ 30 d).

| Threat | At once | After `grantDelay` |
|---|---|---|
| Compromised issuer (bits 5–7) | its harm is bounded: ≤ 30 d per issuer-only freeze (≤ 60 d per episode), ≤ 7 d pause, then cooldowns; `unfreeze` and `unpause` by another issuer root | owner `revokeRole(5/6/7)` or `disableFeature`, confirmed by the proposer |
| Compromised `FORCE` holder | compliance `revokeOrder` of each live record; or owner `revokeRole(10, ·)` of every compliance root; or `disableFeature(RECORD)`; each stops `FORCE` | owner `revokeRole(6)` |
| Compromised compliance (bit 10) | owner `revokeRole(10, holder)` (not delayed); `FORCE` still needs a frozen subject and the issuer | — |
| Registry hostile, unavailable or gas-starving | admin `disableFeature(28)` (`KYC`, group 3s) when not locked: two calls with `grantDelay`; `enableFeature(28)` again, at once, once the registry is trusted; a locked bit has no recovery, as disclosed | — |
| Compromised list holder (bits 8, 9, group 3s, [CTR-AS-31](../contracts/asset-suite.md#CTR-AS-31)) | it denies or unlists any account at once; the bits are never switched off, so relief is a holder's list edit | admin `revokeRole(8 / 9)`, at once (not delayed); a second holder granted ahead avoids the `grantDelay` of a new grant |
| Before `enableFeature(8)` (an allow list) | list, `ALLOWED`, every party first: the holders, the DEX and its `puller()`, `RelayFeeRouter`, the tax recipient and every fee recipient, wrappers holding the token, the clones and escrows; check the issuer seat (or a granted lister) holds bit 8 (`ListHolderMissing` otherwise). A contract holding a denied or unlisted party's units cannot pay it out until a holder edits the list; a payout to several recipients reverts as a whole when one is blocked | — |
| Owner proposes a relaxation | `RelaxProposed` is public for `grantDelay`; the node alerts | the proposer confirms in the window |

Alerts: the indexer marks `alert` on `OrderRecorded`, `RelaxProposed`, `AccountFrozen` and `Paused` (BUILT, T35,
`scaas-node/src/indexer.rs` `ALERTS`); an alert on `FeatureDisabled` is SPECIFIED.
