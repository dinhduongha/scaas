# `scaas-matrix`: the Matrix client crate — build plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status (2026-11-27):** plan, not executed when written. Spec: [`2026-11-27-scaas-matrix.md`](../specs/2026-11-27-scaas-matrix.md).
Rules: [clients/scaas-matrix.md](../../clients/scaas-matrix.md) CLI-MTX-01 to CLI-MTX-12; owner rulings CLI-PQC-19, CLI-PQC-20,
CLI-UPR-29. UNAUDITED.

**Branch** `scaas-matrix` from `dev` at `d0b3f7f34`, worktree `.claude/worktrees/scaas-matrix`. Commits `scaas-matrix T<n>: <what>`,
staged by explicit path with `git commit --only -- <paths>`, the session's attribution lines, no `Signed-off-by`. **No push, no
merge.**

**Goal:** `clients/pqchat-transport` holds the transport trait and its conformance, `pqchat-core` re-exports it unchanged for its
callers; `clients/scaas-matrix` logs in, restores, syncs, lists rooms by kind, reads and sends E2EE messages, verifies devices by SAS,
keeps CLI-PQC-19's defaults and implements the trait; an e2e against Synapse in Docker proves it, and the policy code's mutants are
each killed by a named test.

## Global constraints

- AGENTS.md in full. `cargo` through `scripts/capped`, foreground, `CARGO_INCREMENTAL=0`, `-j 2`, never inside `timeout`; MemAvailable
  at least 4 GB before a heavy step; no background shell left. Docker with `--memory 1g --cpus 1`, one Synapse at a time, removed by
  the test's `Drop`. Never the live testnet.
- TDD: each task's test first, run red **for the stated reason** (the red line goes into the commit body), then the code, then green.
- Network only for `cargo fetch` of the new dependency tree; every later run `--offline --locked`.
- Gate scope per task: the crate's own `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo deny check`, `cargo audit`;
  `pqchat-core`'s full `cargo test --locked` and clippy for T0 (its trait moves); `python3 scripts/docs_check.py check` for docs.

## Tasks

### T0 — `clients/pqchat-transport`, `pqchat-core` re-exports

- [ ] New crate with `MatrixTransport`, `TransportError` (code `MatrixRoom`), `RoomEvent`, `HistoryPage`, `EVENT_TYPE`, `Seen`,
  `Witness`, `conformance`; deps `serde`, `serde_json`, `async-trait`; its own unit test: a minimal in-memory transport conforms and a
  receipt-sending one fails by name.
- [ ] `pqchat-core/src/matrix.rs`: those items removed and re-exported (`pub use pqchat_transport::...`); `From<TransportError> for
  PqChatError` (`MatrixRoom`); the test transports (`tests/common/matrix.rs`, `tests/stores.rs`, `tests/matrix_conformance.rs`,
  `tests/e2e/matrix.rs`) return `TransportError`. `conformance`'s "event sent" check compares content as sent.
- [ ] `pqchat-core/tests/e2e/matrix.rs`: imports only from `pqchat_transport` (so `scaas-matrix`'s e2e includes it by `#[path]`);
  the image pinned by digest; presence counted as `/presence/` requests plus `/sync` requests without `set_presence=offline`
  (unchanged for its HTTP client, which never syncs). Red: `pqchat-core` does not compile against the moved trait until the impls
  change. Green: `pqchat-core` `cargo test --locked`, clippy, wasm32 check, `tests/deps.rs`.

### T1 — `clients/scaas-matrix` skeleton and its dependency rules

- [ ] `Cargo.toml` (matrix-sdk `=0.19.1`, `default-features = false`, `e2e-encryption`, `sqlite`, `bundled-sqlite`; rustls `ring`),
  `Cargo.lock` committed, `deny.toml`, `.cargo/audit.toml`, `tests/deps.rs` (no `scaas-sdk`, `pqchat-core`, `scaas-ua`, `scaas-rpc` in
  the normal graph; `matrix-sdk` present; positive control: each forbidden name in an added line is seen). `cargo deny check` and
  `cargo audit` green or each exception named with its reason. Record the tree size.

### T2 — Profiles, store key, session (CLI-MTX-02 to CLI-MTX-04)

- [ ] `StoreKey` (no `Debug` of bytes, `Zeroizing`), the directory lock, `open` / `close`, the session record in the encrypted state
  store, `restore`, the URL rule. Offline tests: a second open refused `MatrixProfileBusy`, open again after `close`; the key's bytes,
  hex and base64 in no file of the directory after a record is written and the client closed (positive control: a planted copy is
  found); a wrong key `MatrixStore`; no record `MatrixSession`; `http://localhost` and `http://10.0.0.1` refused, `http://127.0.0.1`
  and `https://` accepted.

### T3 — Policy: privacy defaults and room kinds (CLI-MTX-05, CLI-MTX-06)

- [ ] `src/policy.rs`: the settings with their defaults, the receipt type, typing, the kind filter, the refusals in a PqChat room, the
  mark set with its bound; persisted in the encrypted store. Unit tests per rule and its opt-in.

### T4 — Login, sync, rooms, timeline, send (e2e)

- [ ] `login_password`, `sync_once` / `start_sync` with presence offline, `rooms(filter)`, `create_direct`, invites, `messages`,
  `send_text`, the update queue. E2E steps: two users, a direct encrypted room, a message read decrypted by the other, a session
  restored from the key on a fresh client.

### T5 — Verification, cross-signing, recovery, backup (e2e)

- [ ] SAS flow both sides to `verified`, `device_trust`; cross-signing bootstrapped at first login; backup off by default (the server
  holds no backup version); `setup_recovery` returns a key once.

### T6 — Push (e2e)

- [ ] No pusher and no PqChat rule by default (server read); `set_pusher` always `event_id_only`, refused hidden; `set_pqchat_push`.

### T7 — The `MatrixTransport` implementation and the privacy witness (e2e)

- [ ] `transport()`; `conformance` passes against Synapse; the witness proves no receipt, read marker, typing or presence of either
  user after the whole run, beside a positive control (a raw client that sends each one is counted).

### T8 — CI, format, test features

- [ ] A `scaas-matrix` job in `.github/workflows/ci.yml` (tests, clippy, deny, audit; e2e stays local), started by
  `.github/ci_changes.py` on `clients/scaas-matrix/`, `clients/pqchat-transport/` or `clients/pqchat-core/`; `pqchat-transport` added
  to the `pqchat-core` job's inputs; `scripts/format.sh` covers both crates; `scripts/check_test_features.py` lists their manifests.

### T9 — Mutants and the closing record

- [ ] `clients/scaas-matrix/runs/2026-11-27-scaas-matrix-mutants.py` through `scripts/mutant_guard.py`: the defaults (public
  receipts, typing on, presence online), the kind filter (a PqChat room listed as Matrix), a refusal removed, the lock dropped, the key
  written beside the store, the loopback rule widened; each killed by a named test; record `…-mutants.txt`. The summary
  `runs/2026-11-27-scaas-matrix-summary.txt` (`step | commit | rc | counts`).
