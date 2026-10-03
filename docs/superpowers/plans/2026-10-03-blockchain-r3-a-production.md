# Round 3 / A — Production blockers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use `- [ ]`.

**Goal:** close GA §2.1 blockers #1,#3,#4,#7,#8 and GA §2.2 #4,#6,#7, §2.3 #12,#13,#14.
**Architecture:** Odoo side in `dms_blockchain` / `dms_blockchain_payment` / bridge; node side in `bamboo-node` (new `admin.rs`, `breaker.rs`, gateway auth); CI workflow.
**Spec:** `docs/superpowers/specs/2026-10-03-blockchain-round3-design.md` §A (rulings R50–R57).

## Global Constraints
- Odoo tests only via `scripts/chain-odoo-test.sh` (DB `dms_test_chain`, port 8920), never two at once.
- No new Python dependency (`cryptography` ships with Odoo). Node: only `proptest` (dev), `hmac`/`sha2` (already transitive via alloy? else add).
- Cron bodies in model methods; `models.Constraint`; RPC entry points public, logic private.

## Review Focus
1. `env:` custody reachable on a non-dev chain via an existing approved wallet ⇒ must refuse at sign time, not only at approval.
2. `paused` chain still ingests events (customers who paid are recorded).
3. Gateway with `none` auth on a non-loopback bind ⇒ refuse to start.
4. Breaker open ⇒ already-signed txs keep being tracked/replaced.
5. Drift: a Transfer that belongs to a `PaymentSettled` tx is NOT reported as unmatched.

### Task A1: custody `env:` dev-only, OpenSSL signing (R50)
Files: `dms_blockchain/lib/custody.py`, `models/blockchain_chain.py` (`is_dev_chain`), `models/blockchain_paying_wallet.py`, tests `tests/test_custody.py`.
- [x] Tests: without `dms_blockchain.allow_dev_custody` ⇒ `custody.address('env:X')` raises; with flag but wallet on non-dev chain ⇒ approve and `_sign_digest` raise; with both ⇒ signature recovers to address, s ≤ n/2; adapter signs via `cryptography` (assert the pure-Python `sign` is not called — patch it to raise).
- [x] Impl: `custody.register` unchanged; `EnvAdapter` registered lazily by `custody.dev_adapter(env)` check; `_sign_digest` passes chain dev flag.
- [x] Commit `feat(blockchain): env custody is dev-only and signs through OpenSSL`.

### Task A2: pause stops submission only (R53)
Files: `models/blockchain_chain.py` (state `halted`, `_for_indexing`, `_for_submission`), `blockchain_relay_job.relay_poll`, `blockchain_chain_event.chain_event_ingest`; node `submit.rs` treats a refused poll as idle.
- [x] Tests: paused ⇒ `relay_poll` == [], `node_config` OK, ingest OK; halted ⇒ ingest refused; draft ⇒ all refused.
- [x] Commit `feat(blockchain): pausing a chain stops submission, not indexing`.

### Task A3: seams + platform company (R57, GA 2.3 #13/#14)
Files: `dms_blockchain/models/blockchain_receiving_wallet.py`, bridge `dms_portal_api.py`, `sale_order.py`, tests.
- [x] Tests: provider lookup/offered/start/staff note all use `_dms_chain_receiving_company` (patch it to another company ⇒ every path follows); platform company reads new param, falls back to old param and main company.
- [x] Commit `refactor(blockchain): one receiving-company seam, "platform company" naming`.

### Task A4: journal per (company, token) (R56)
Files: `dms_blockchain/models/blockchain_token.py` (`journal_id` company_dependent), `dms_blockchain_payment/models/payment_transaction.py` (`_create_payment` journal override + method line ensured), views, tests.
- [x] Tests: token journal set ⇒ `account.payment.journal_id` == token journal, invoice reconciled; unset ⇒ provider journal.
- [x] Commit `feat(blockchain): payments post to the token's journal of the receiving company`.

### Task A5: drift A + C (R56)
Files: node `indexer.rs` (Transfer logs to receiving wallets), `odoo.rs` (`balance_report`), new `drift.rs` (hourly balanceOf at final height); Odoo `blockchain_chain_event` (`unmatched_inbound`), new `blockchain_balance_snapshot.py`, `node_config` gains `receiving_addresses`, tests.
- [x] Tests (Odoo): Transfer in same tx as PaymentSettled ⇒ matched; lone Transfer ⇒ unmatched + attention; balance report equal to GL ⇒ `ok`, different ⇒ `mismatch` + activity.
- [x] Tests (node): Transfer decoding filters by `to ∈ receiving`; drift loop posts at final height.
- [x] Commit `feat(blockchain): drift checks — unmatched inbound transfers and balance vs GL`.

### Task A6: admin server /healthz /readyz /metrics (R51)
Files: node `admin.rs`, `config.rs` (`admin_bind`, `max_index_lag`), `main.rs`; Odoo `blockchain_chain.relay_stats`.
- [x] Tests: readiness false when an RPC fails / Odoo fails / lag > bound (unit with fakes); metrics text format golden; Odoo `relay_stats` counts by state + attention, service-only.
- [x] Commit `feat(node): admin port with readiness and Prometheus metrics`.

### Task A7: gateway auth + proptest (R54)
Files: node `gateway.rs`, `config.rs`, dev-dep `proptest`.
- [x] Tests: bearer ok/wrong/missing; hmac ok/stale/wrong; `none` + `0.0.0.0` bind ⇒ config error; proptest: arbitrary JSON bodies never panic `WireMetaTx::to_sol`/handlers' parsers.
- [x] Commit `feat(node): gateway authentication and fuzzed decoders`.

### Task A8: circuit breakers (R55)
Files: node `breaker.rs`, `submit.rs` (check before taking new work), `config.rs`.
- [x] Tests: spike ratio trips/clears; hourly budget 90 % warn / 100 % trip / window roll; balance floor per lane; tripped breaker still lets `track()` run.
- [x] Commit `feat(node): gas circuit breakers`.

### Task A9: CI (R52)
Files: `.github/workflows/blockchain-ci.yml`.
- [x] Validate YAML parses; job steps mirror local commands.
- [x] Commit `ci(blockchain): forge, cargo and Odoo blockchain suites`.

## Ghi chú triển khai (S1, round 3)
- A5: chỉ `Transfer` KHÔNG cùng tx với `PaymentSettled` mới được lưu (cùng khối ⇒ cùng lô ingest); `balance_report`
  chỉ nhận đúng `height == indexed_block` (khác ⇒ `stale`, node đọc lại sau 20 s); activity chỉ khi lệch **hai lần
  liên tiếp** (`is_persistent`) vì `account.payment` sinh sau `_set_done` qua post-processing.
- A6+A8 và A5 nằm chung một commit (main.rs/config.rs đan xen); A9 commit riêng.
- R55 "< 20 % sàn": hiểu là số dư < 120 % sàn ⇒ cảnh báo (R1-1).
